import std/unittest

import stackable_hooks/platform/linux_raw_syscalls

suite "linux raw syscall primitives":
  test "platform support is explicit":
    when defined(linux) and defined(amd64):
      check linuxRawSyscallSupported() == lrsOk
    elif defined(linux):
      check linuxRawSyscallSupported() == lrsUnsupportedArchitecture
      check rawSyscall6(0, 0, 0, 0, 0, 0, 0) == -38
    else:
      check linuxRawSyscallSupported() == lrsUnsupportedPlatform
      check rawSyscall6(0, 0, 0, 0, 0, 0, 0) == -38

  test "byte scanner detects syscall opcodes and filters embedded immediates":
    let bytes = [
      byte 0x90,
      byte 0x0f, byte 0x05, byte 0xc3,
      byte 0xc7, byte 0x04, byte 0x24, byte 0x00,
      byte 0x0f, byte 0x05, byte 0x00,
      byte 0x0f, byte 0x05, byte 0x48]
    let sites = scanLinuxX8664SyscallBytes(bytes, baseAddress = 0x1000'u)
    check sites.len == 2
    check sites[0].offset == 1
    check sites[0].address == 0x1001'u
    check sites[0].nextByte == byte 0xc3
    check sites[1].offset == 11
    check sites[1].address == 0x100b'u
    check sites[1].nextByte == byte 0x48

    var visited: seq[int]
    visitLinuxX8664SyscallBytes(bytes, proc(site: LinuxSyscallSite): bool =
      visited.add site.offset
      true
    )
    check visited == @[1, 11]

  test "byte scanner rejects 0f 05 inside a call/jmp rel32 displacement":
    # `e8 0f 05 fa ff` is `call rel32` whose displacement embeds `0f 05`.
    # A naive scan would mistake it for a `syscall` at offset 1 and patch an
    # INT3 over the branch displacement -> deterministic SIGILL. The
    # preceding-0xe8/0xe9 guard must reject it. A genuine `0f 05` elsewhere in
    # the same slice is still detected.
    let callBytes = [
      byte 0x90,
      byte 0xe8, byte 0x0f, byte 0x05, byte 0xfa, byte 0xff, # call rel32
      byte 0xe9, byte 0x0f, byte 0x05, byte 0x11, byte 0x22, # jmp rel32
      byte 0x0f, byte 0x05, byte 0xc3]                       # real syscall
    check not looksLikeLinuxX8664Syscall(callBytes, 2)  # inside call
    check not looksLikeLinuxX8664Syscall(callBytes, 7)  # inside jmp
    check looksLikeLinuxX8664Syscall(callBytes, 11)     # real syscall
    let callSites = scanLinuxX8664SyscallBytes(callBytes, baseAddress = 0x2000'u)
    check callSites.len == 1
    check callSites[0].offset == 11
    check callSites[0].address == 0x200b'u

  test "maps parser exposes executable mappings without policy filtering":
    let line = "7f0000001000-7f0000002000 r-xp 00000000 00:00 0 /tmp/libx.so"
    let parsed = parseLinuxMapsLine(line)
    check parsed.ok
    check parsed.mapping.start == 0x7f0000001000'u
    check parsed.mapping.stop == 0x7f0000002000'u
    check parsed.mapping.readable
    check not parsed.mapping.writable
    check parsed.mapping.executable
    check parsed.mapping.privateMapping
    check parsed.mapping.path == "/tmp/libx.so"

  test "enumerating executable mappings reports support diagnostics":
    let enumerated = enumerateLinuxExecutableMappings()
    when defined(linux) and defined(amd64):
      check enumerated.diagnostic == lrsOk
      check enumerated.mappings.len > 0
      var foundExecutable = false
      for mapping in enumerated.mappings:
        if mapping.readable and mapping.executable:
          foundExecutable = true
      check foundExecutable
    elif defined(linux):
      check enumerated.diagnostic == lrsUnsupportedArchitecture
      check enumerated.mappings.len == 0
    else:
      check enumerated.diagnostic == lrsUnsupportedPlatform
      check enumerated.mappings.len == 0

  test "default symbol resolution is explicit":
    when defined(linux) and defined(amd64):
      check resolveDefaultSymbol(cstring("syscall")) != nil
      check resolveDefaultSymbol(cstring("__stackable_missing_symbol")) == nil
    else:
      check resolveDefaultSymbol(cstring("syscall")) == nil

  test "atomic instruction classifier accepts bounded LOCK, XCHG, and fence fixtures":
    when defined(linux) and defined(amd64):
      let lockAdd = classifyLinuxX8664AtomicWindow([
        byte 0xf0, byte 0x01, byte 0x18, byte 0x90])
      check lockAdd.diagnostic == lrsOk
      check lockAdd.kind == laikLockRmw
      check lockAdd.length == 3
      check lockAdd.lockPrefixed
      check lockAdd.memoryOperand
      check lockAdd.modrmOffset == 2
      check lockAdd.opcodeOffset == 1
      check lockAdd.opcode0 == byte 0x01

      let lockCmpxchg = classifyLinuxX8664AtomicWindow([
        byte 0xf0, byte 0x48, byte 0x0f, byte 0xb1, byte 0x10])
      check lockCmpxchg.diagnostic == lrsOk
      check lockCmpxchg.kind == laikLockRmw
      check lockCmpxchg.length == 5
      check lockCmpxchg.opcode0 == byte 0x0f
      check lockCmpxchg.opcode1 == byte 0xb1

      let xchgMem = classifyLinuxX8664AtomicWindow([
        byte 0x87, byte 0x03, byte 0x90])
      check xchgMem.diagnostic == lrsOk
      check xchgMem.kind == laikXchgMem
      check xchgMem.length == 2
      check not xchgMem.lockPrefixed
      check xchgMem.memoryOperand

      let mfence = classifyLinuxX8664AtomicWindow([
        byte 0x0f, byte 0xae, byte 0xf0])
      check mfence.diagnostic == lrsOk
      check mfence.kind == laikMfence
      check mfence.length == 3

      let sfence = classifyLinuxX8664AtomicWindow([
        byte 0x0f, byte 0xae, byte 0xf8])
      check sfence.diagnostic == lrsOk
      check sfence.kind == laikSfence

      let lfence = classifyLinuxX8664AtomicWindow([
        byte 0x0f, byte 0xae, byte 0xe8])
      check lfence.diagnostic == lrsOk
      check lfence.kind == laikLfence
    else:
      check classifyLinuxX8664AtomicWindow([byte 0xf0]).diagnostic != lrsOk

  test "atomic instruction classifier rejects ambiguous or non-memory fixtures":
    let truncated = classifyLinuxX8664AtomicWindow([byte 0xf0, byte 0x01])
    when defined(linux) and defined(amd64):
      check truncated.diagnostic == lrsUnsupportedInstruction
      let registerOnly = classifyLinuxX8664AtomicWindow([
        byte 0xf0, byte 0x01, byte 0xc0])
      check registerOnly.diagnostic == lrsUnsupportedInstruction
      let unlockedAdd = classifyLinuxX8664AtomicWindow([
        byte 0x01, byte 0x18])
      check unlockedAdd.diagnostic == lrsUnsupportedInstruction
      let xchgRegister = classifyLinuxX8664AtomicWindow([
        byte 0x87, byte 0xc0])
      check xchgRegister.diagnostic == lrsUnsupportedInstruction
      let lockMfence = classifyLinuxX8664AtomicWindow([
        byte 0xf0, byte 0x0f, byte 0xae, byte 0xf0])
      check lockMfence.diagnostic == lrsUnsupportedInstruction
      let prefixedMfence = classifyLinuxX8664AtomicWindow([
        byte 0x66, byte 0x0f, byte 0xae, byte 0xf0])
      check prefixedMfence.diagnostic == lrsUnsupportedInstruction
    else:
      check truncated.diagnostic != lrsOk

  test "atomic patch strategy selection chooses rel32 jmp or INT3 fallback":
    when defined(linux) and defined(amd64):
      let jmp = selectLinuxAtomicPatchStrategy(
        0x10000000'u, 0x10001000'u, 5)
      check jmp.diagnostic == lrsOk
      check jmp.strategy == lapsJmpRel32
      check jmp.patchSize == 5
      check jmp.rel32Displacement == int64(0x10001000'i64 - 0x10000005'i64)

      let short = selectLinuxAtomicPatchStrategy(
        0x10000000'u, 0x10001000'u, 3)
      check short.diagnostic == lrsOk
      check short.strategy == lapsInt3
      check short.patchSize == 1

      let far = selectLinuxAtomicPatchStrategy(
        0x10000000'u, 0x9000000000'u, 8)
      check far.diagnostic == lrsOk
      check far.strategy == lapsInt3
      check far.patchSize == 1

      let invalid = selectLinuxAtomicPatchStrategy(0'u, 0x1000'u, 5)
      check invalid.diagnostic == lrsInvalidArgument
    else:
      check selectLinuxAtomicPatchStrategy(1'u, 2'u, 5).diagnostic != lrsOk

  test "JIT executable range registry merges, subtracts, and deregisters ranges":
    var registry: LinuxJitRangeRegistry
    check addLinuxJitExecutableRange(registry, 100'u, 200'u)
    check addLinuxJitExecutableRange(registry, 250'u, 300'u)
    check registry.ranges == @[
      LinuxJitExecutableRange(start: 100'u, stop: 200'u),
      LinuxJitExecutableRange(start: 250'u, stop: 300'u)]
    check addLinuxJitExecutableRange(registry, 180'u, 260'u)
    check registry.ranges == @[LinuxJitExecutableRange(start: 100'u, stop: 300'u)]
    check containsLinuxJitExecutableRange(registry, 120'u, 290'u)
    check not containsLinuxJitExecutableRange(registry, 90'u, 120'u)

    let missing = untrackedLinuxJitExecutableRanges(registry, 50'u, 350'u)
    check missing == @[
      LinuxJitExecutableRange(start: 50'u, stop: 100'u),
      LinuxJitExecutableRange(start: 300'u, stop: 350'u)]

    removeLinuxJitExecutableRange(registry, 140'u, 180'u)
    check registry.ranges == @[
      LinuxJitExecutableRange(start: 100'u, stop: 140'u),
      LinuxJitExecutableRange(start: 180'u, stop: 300'u)]
    removeLinuxJitExecutableRange(registry, 90'u, 150'u)
    check registry.ranges == @[LinuxJitExecutableRange(start: 180'u, stop: 300'u)]
    check not addLinuxJitExecutableRange(registry, 9'u, 9'u)

  test "clone continuation classifier is policy-extensible":
    when defined(linux) and defined(amd64):
      check isLinuxX8664DefaultCloneContinuationSyscall(linuxX8664SysClone)
      check isLinuxX8664DefaultCloneContinuationSyscall(linuxX8664SysFork)
      check isLinuxX8664DefaultCloneContinuationSyscall(linuxX8664SysVfork)
      check isLinuxX8664DefaultCloneContinuationSyscall(linuxX8664SysClone3)
      check not isLinuxX8664DefaultCloneContinuationSyscall(39)
    else:
      check not isLinuxX8664DefaultCloneContinuationSyscall(linuxX8664SysClone)
      check not isLinuxX8664DefaultCloneContinuationSyscall(linuxX8664SysFork)
      check not isLinuxX8664DefaultCloneContinuationSyscall(linuxX8664SysVfork)
      check not isLinuxX8664DefaultCloneContinuationSyscall(linuxX8664SysClone3)
    check isLinuxX8664CloneContinuationSyscall(39, [39])
    check not isLinuxX8664CloneContinuationSyscall(39, [1, 2, 3])

  test "INT3 resume-RIP helper describes Linux x86_64 trap shape":
    check computeLinuxX8664Int3ResumeRip(0'u) == 0'u
    check computeLinuxX8664Int3ResumeRip(0x401001'u) == 0x401002'u

  test "clone continuation state is computed from synthetic registers":
    var regs = LinuxX8664SyscallRegisters(
      syscallNumber: linuxX8664SysClone,
      trapRip: 0x7011'u,
      syscallAddress: 0x7010'u,
      resumeRip: 0x7012'u)
    let computed = computeLinuxX8664CloneContinuation(regs, parentResult = 12345)
    when defined(linux) and defined(amd64):
      check computed.diagnostic == lrsOk
      check computed.state.cloneLike
      check computed.state.syscallNumber == linuxX8664SysClone
      check computed.state.syscallAddress == 0x7010'u
      check computed.state.trapRip == 0x7011'u
      check computed.state.resumeRip == 0x7012'u
      check computed.state.parentResult == 12345
      check computed.state.parentResumeRip == 0x7012'u
      check computed.state.childResult == 0
      check computed.state.childResumeRip == 0x7012'u
    elif defined(linux):
      check computed.diagnostic == lrsUnsupportedArchitecture
    else:
      check computed.diagnostic == lrsUnsupportedPlatform

    when defined(linux) and defined(amd64):
      regs.syscallNumber = 39
      let nonClone = computeLinuxX8664CloneContinuation(
        regs, parentResult = 99, cloneLike = false)
      check nonClone.diagnostic == lrsOk
      check not nonClone.state.cloneLike
      check nonClone.state.parentResult == 99

when defined(linux) and defined(amd64):
  {.compile: "fixtures/linux_raw_syscalls_c_abi_smoke.c".}
  {.emit: """
#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <elf.h>

void *stackable_test_alloc_patch_target(void) {
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  unsigned char *p = (unsigned char *)mmap(NULL, (size_t)page_size,
      PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return NULL;
  /* mov $7,%eax; ret; nop padding for the 14-byte jump patch window. */
  unsigned char code[16] = {
    0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90
  };
  memcpy(p, code, sizeof(code));
  return p;
}

void *stackable_test_alloc_original_trampoline_target(void) {
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  unsigned char *p = (unsigned char *)mmap(NULL, (size_t)page_size,
      PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return NULL;
  /* mov $7,%eax; add $5,%eax; push %rbp; pop %rbp; nop*4; ret */
  unsigned char code[16] = {
    0xb8, 0x07, 0x00, 0x00, 0x00,
    0x83, 0xc0, 0x05,
    0x55, 0x5d,
    0x90, 0x90, 0x90, 0x90,
    0xc3, 0x90
  };
  memcpy(p, code, sizeof(code));
  return p;
}

void *stackable_test_alloc_rip_relative_target(void) {
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  unsigned char *p = (unsigned char *)mmap(NULL, (size_t)page_size,
      PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return NULL;
  /* mov 0(%rip),%rax; nop padding. This must be rejected, not guessed. */
  unsigned char code[16] = {
    0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xc3, 0x90
  };
  memcpy(p, code, sizeof(code));
  return p;
}

void *stackable_test_alloc_syscall_scan_buffer(void) {
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  unsigned char *p = (unsigned char *)mmap(NULL, (size_t)page_size,
      PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return NULL;
  unsigned char code[16] = {
    0x90, 0x0f, 0x05, 0xc3,
    0xc7, 0x04, 0x24, 0x00, 0x0f, 0x05, 0x00,
    0x0f, 0x05, 0xc3, 0x90, 0x90
  };
  memcpy(p, code, sizeof(code));
  return p;
}

void *stackable_test_alloc_vdso_fixture(int value) {
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  unsigned char *p = (unsigned char *)mmap(NULL, (size_t)page_size,
      PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return NULL;
  memset(p, 0, (size_t)page_size);

  Elf64_Ehdr *eh = (Elf64_Ehdr *)p;
  eh->e_ident[EI_MAG0] = ELFMAG0;
  eh->e_ident[EI_MAG1] = ELFMAG1;
  eh->e_ident[EI_MAG2] = ELFMAG2;
  eh->e_ident[EI_MAG3] = ELFMAG3;
  eh->e_ident[EI_CLASS] = ELFCLASS64;
  eh->e_ident[EI_DATA] = ELFDATA2LSB;
  eh->e_ident[EI_VERSION] = EV_CURRENT;
  eh->e_type = ET_DYN;
  eh->e_machine = EM_X86_64;
  eh->e_version = EV_CURRENT;
  eh->e_phoff = sizeof(Elf64_Ehdr);
  eh->e_ehsize = sizeof(Elf64_Ehdr);
  eh->e_phentsize = sizeof(Elf64_Phdr);
  eh->e_phnum = 2;

  Elf64_Phdr *ph = (Elf64_Phdr *)(p + eh->e_phoff);
  ph[0].p_type = PT_LOAD;
  ph[0].p_offset = 0;
  ph[0].p_vaddr = 0;
  ph[0].p_memsz = (Elf64_Xword)page_size;
  ph[0].p_filesz = (Elf64_Xword)page_size;
  ph[0].p_flags = PF_R | PF_X;
  ph[0].p_align = (Elf64_Xword)page_size;
  ph[1].p_type = PT_DYNAMIC;
  ph[1].p_offset = 0x100;
  ph[1].p_vaddr = 0x100;
  ph[1].p_filesz = 5 * sizeof(Elf64_Dyn);
  ph[1].p_memsz = 5 * sizeof(Elf64_Dyn);
  ph[1].p_flags = PF_R;
  ph[1].p_align = 8;

  Elf64_Dyn *dyn = (Elf64_Dyn *)(p + 0x100);
  dyn[0].d_tag = DT_SYMTAB; dyn[0].d_un.d_ptr = 0x180;
  dyn[1].d_tag = DT_STRTAB; dyn[1].d_un.d_ptr = 0x220;
  dyn[2].d_tag = DT_SYMENT; dyn[2].d_un.d_val = sizeof(Elf64_Sym);
  dyn[3].d_tag = DT_STRSZ;  dyn[3].d_un.d_val = 32;
  dyn[4].d_tag = DT_NULL;

  Elf64_Sym *sym = (Elf64_Sym *)(p + 0x180);
  memset(sym, 0, 2 * sizeof(Elf64_Sym));
  sym[1].st_name = 1;
  sym[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
  sym[1].st_shndx = 1;
  sym[1].st_value = 0x300;
  sym[1].st_size = 16;

  char *str = (char *)(p + 0x220);
  str[0] = '\0';
  memcpy(str + 1, "__vdso_fixture", sizeof("__vdso_fixture"));

  unsigned char code[16] = {
    0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90
  };
  code[1] = (unsigned char)(value & 0xff);
  code[2] = (unsigned char)((value >> 8) & 0xff);
  code[3] = (unsigned char)((value >> 16) & 0xff);
  code[4] = (unsigned char)((value >> 24) & 0xff);
  memcpy(p + 0x300, code, sizeof(code));
  return p;
}

void *stackable_test_alloc_vdso_fixture_bad_symbol(void) {
  unsigned char *p = (unsigned char *)stackable_test_alloc_vdso_fixture(11);
  if (p == NULL) return NULL;
  Elf64_Sym *sym = (Elf64_Sym *)(p + 0x180);
  sym[1].st_value = 0x5000;
  return p;
}

int stackable_test_replacement_value(void) {
  return 42;
}
""".}

  proc allocPatchTarget(): pointer
    {.importc: "stackable_test_alloc_patch_target", cdecl.}
  proc allocOriginalTrampolineTarget(): pointer
    {.importc: "stackable_test_alloc_original_trampoline_target", cdecl.}
  proc allocRipRelativeTarget(): pointer
    {.importc: "stackable_test_alloc_rip_relative_target", cdecl.}
  proc replacementValue(): cint
    {.importc: "stackable_test_replacement_value", cdecl.}
  proc allocSyscallScanBuffer(): pointer
    {.importc: "stackable_test_alloc_syscall_scan_buffer", cdecl.}
  proc allocVdsoFixture(value: cint): pointer
    {.importc: "stackable_test_alloc_vdso_fixture", cdecl.}
  proc allocVdsoFixtureBadSymbol(): pointer
    {.importc: "stackable_test_alloc_vdso_fixture_bad_symbol", cdecl.}
  proc cAbiLinkSmoke(): cint
    {.importc: "stackable_test_c_abi_link_smoke", cdecl.}
  proc ucontextHelpersSmoke(): cint
    {.importc: "stackable_test_ucontext_helpers_smoke", cdecl.}
  proc replayGetpid(): clong
    {.importc: "stackable_test_replay_getpid", cdecl.}
  proc sigtrapInstallUninstallSmoke(): cint
    {.importc: "stackable_test_sigtrap_install_uninstall_smoke", cdecl.}
  proc liveInt3GetpidContinuation(): clong
    {.importc: "stackable_test_live_int3_getpid_continuation", cdecl.}
  proc fixedPageInt3PatchSmoke(): cint
    {.importc: "stackable_test_fixed_page_int3_patch_smoke", cdecl.}

  type TestFn = proc(): cint {.cdecl.}

  suite "linux raw syscall live patch":
    test "INT3 callsite table keeps sorted lookup and trap-RIP lookup":
      var table: LinuxInt3CallsiteTable
      check addLinuxInt3Callsite(table, 0x3000'u)
      check addLinuxInt3Callsite(table, 0x1000'u)
      check addLinuxInt3Callsite(table, 0x2000'u, patched = true)
      check not addLinuxInt3Callsite(table, 0x2000'u)
      check table.sites.len == 3
      check table.sites[0].address == 0x1000'u
      check table.sites[1].address == 0x2000'u
      check table.sites[1].patched
      check table.sites[2].address == 0x3000'u
      check findLinuxInt3Callsite(table, 0x1000'u) == 0
      check findLinuxInt3Callsite(table, 0x2000'u) == 1
      check findLinuxInt3Callsite(table, 0x4000'u) == -1
      check findLinuxInt3CallsiteForTrapRip(table, 0x2001'u) == 1
      check findLinuxInt3CallsiteForTrapRip(table, 0'u) == -1

    test "absolute jump patch changes and restores a controlled executable buffer":
      let target = allocPatchTarget()
      check target != nil
      let fn = cast[TestFn](target)
      check fn() == 7

      let tx = installAbsoluteJumpPatchTransaction(
        target, cast[pointer](replacementValue), captureRestoreBytes = true)
      check tx.diagnostic == lrsOk
      check tx.stage == lpsComplete
      check tx.patchLive
      check tx.restoreBytesCaptured
      check tx.handle.diagnostic == lrsOk
      check tx.handle.active
      check tx.handle.patchSize == linuxAbsoluteJumpPatchSize
      check fn() == 42

      var handle = tx.handle
      check restoreAbsoluteJumpPatch(handle) == lrsOk
      check not handle.active
      check fn() == 7

    test "original-call trampoline preserves controlled original behavior after patch":
      let target = allocOriginalTrampolineTarget()
      check target != nil
      let fn = cast[TestFn](target)
      check fn() == 12

      let measured = measureOriginalCallTrampoline(target)
      check measured.diagnostic == lrsOk
      check measured.target == target
      check measured.entry == nil
      check measured.copiedLen == linuxAbsoluteJumpPatchSize
      check measured.minPatchLen == linuxAbsoluteJumpPatchSize
      check measured.unsupportedOffset == -1

      let original = buildOriginalCallTrampoline(target)
      check original.diagnostic == lrsOk
      check original.entry != nil
      check original.copiedLen == linuxAbsoluteJumpPatchSize
      let originalFn = cast[TestFn](original.entry)
      check originalFn() == 12

      let tx = installAbsoluteJumpPatchTransaction(
        target, cast[pointer](replacementValue), captureRestoreBytes = true)
      check tx.diagnostic == lrsOk
      check fn() == 42
      check originalFn() == 12

      var handle = tx.handle
      check restoreAbsoluteJumpPatch(handle) == lrsOk
      check fn() == 12

    test "original-call trampoline rejects RIP-relative prologue":
      let target = allocRipRelativeTarget()
      check target != nil
      let measured = measureOriginalCallTrampoline(target)
      check measured.diagnostic == lrsUnsupportedInstruction
      check measured.entry == nil
      check measured.copiedLen == 0
      check measured.unsupportedOffset == 0

      let built = buildOriginalCallTrampoline(target)
      check built.diagnostic == lrsUnsupportedInstruction
      check built.entry == nil
      check built.unsupportedOffset == 0

    test "transaction reports invalid target at validation stage":
      let tx = installAbsoluteJumpPatchTransaction(nil, cast[pointer](replacementValue))
      check tx.diagnostic == lrsInvalidArgument
      check tx.stage == lpsValidateTarget
      check not tx.patchLive
      check not tx.handle.active
      check not tx.restoreBytesCaptured

    test "transaction reports pre-patch mprotect failure before reading target bytes":
      let tx = installAbsoluteJumpPatchTransaction(
        cast[pointer](0x1), cast[pointer](replacementValue))
      check tx.diagnostic == lrsPrePatchMprotectFailed
      check tx.stage == lpsPrePatchMprotect
      check tx.osErrno != 0
      check not tx.patchLive
      check not tx.restoreBytesCaptured

    test "transaction can skip restore-byte capture":
      let target = allocPatchTarget()
      check target != nil
      let fn = cast[TestFn](target)
      check fn() == 7

      let tx = installAbsoluteJumpPatchTransaction(
        target, cast[pointer](replacementValue), captureRestoreBytes = false)
      check tx.diagnostic == lrsOk
      check tx.patchLive
      check not tx.restoreBytesCaptured
      check fn() == 42

    test "transaction reports already-patched targets without recapturing bytes":
      let target = allocPatchTarget()
      check target != nil
      let first = installAbsoluteJumpPatchTransaction(
        target, cast[pointer](replacementValue), captureRestoreBytes = true)
      check first.diagnostic == lrsOk

      let second = installAbsoluteJumpPatchTransaction(
        target, cast[pointer](replacementValue), captureRestoreBytes = true)
      check second.diagnostic == lrsAlreadyPatched
      check second.stage == lpsValidateTarget
      check not second.patchLive
      check not second.restoreBytesCaptured

      var handle = first.handle
      check restoreAbsoluteJumpPatch(handle) == lrsOk

    test "resolver chains are consumer controlled":
      let libc = openLibraryNoLoad(cstring("libc.so.6"))
      let chain = if libc != nil:
        @[handleSymbolResolver(libc), defaultSymbolResolver()]
      else:
        @[defaultSymbolResolver()]
      check resolveSymbolChain(cstring("syscall"), chain) != nil
      check resolveSymbolChain(cstring("__stackable_missing_symbol"), chain) == nil

    test "live vDSO image discovery exposes structured diagnostics":
      let image = locateLinuxVdsoImage()
      check image.diagnostic in {lrsOk, lrsVdsoNotFound, lrsVdsoNotElf,
                                 lrsVdsoNoDynamic, lrsVdsoNoSymbolTable}
      if image.diagnostic == lrsOk:
        check image.base != nil
        check image.length > 0
        check image.symbolTable != nil
        check image.stringTable != nil
        let missing = resolveLinuxVdsoSymbol(
          image, cstring("__stackable_missing_vdso_symbol"))
        check missing.diagnostic == lrsVdsoSymbolNotFound

        for name in ["__vdso_clock_gettime", "__vdso_gettimeofday",
                     "__vdso_time", "__vdso_getcpu", "__vdso_clock_getres"]:
          let sym = resolveLinuxVdsoSymbol(image, cstring(name))
          if sym.diagnostic == lrsOk:
            check sym.address != nil
            check sym.name == name
          else:
            check sym.diagnostic == lrsVdsoSymbolNotFound

    test "controlled vDSO-shaped ELF fixture resolves symbols deterministically":
      let fixture = allocVdsoFixture(31)
      check fixture != nil
      let image = parseLinuxVdsoImageAt(fixture)
      check image.diagnostic == lrsOk
      check image.base == fixture
      check image.length >= 4096
      check image.symbolCount >= 2
      let sym = resolveLinuxVdsoSymbol(image, cstring("__vdso_fixture"))
      check sym.diagnostic == lrsOk
      check sym.address == cast[pointer](cast[uint](fixture) + 0x300'u)
      check sym.size == 16
      let missing = resolveLinuxVdsoSymbol(image, cstring("__vdso_absent"))
      check missing.diagnostic == lrsVdsoSymbolNotFound

    test "controlled vDSO fixture rejects out-of-image symbol values":
      let fixture = allocVdsoFixtureBadSymbol()
      check fixture != nil
      let image = parseLinuxVdsoImageAt(fixture)
      check image.diagnostic == lrsOk
      let sym = resolveLinuxVdsoSymbol(image, cstring("__vdso_fixture"))
      check sym.diagnostic == lrsVdsoSymbolNotFound

    test "controlled vDSO symbol direct patch transaction does not touch live vDSO":
      let fixture = allocVdsoFixture(31)
      check fixture != nil
      let image = parseLinuxVdsoImageAt(fixture)
      check image.diagnostic == lrsOk
      let sym = resolveLinuxVdsoSymbol(image, cstring("__vdso_fixture"))
      check sym.diagnostic == lrsOk
      let fn = cast[TestFn](sym.address)
      check fn() == 31

      let tx = installLinuxVdsoSymbolPatchTransaction(
        image, cstring("__vdso_fixture"), cast[pointer](replacementValue))
      check tx.diagnostic == lrsOk
      check tx.path == lvppDirect
      check tx.patchLive
      check not tx.overlayUsed
      check tx.symbol.address == sym.address
      check fn() == 42

    test "controlled vDSO overlay patch transaction uses disposable mapping only":
      let fixture = allocVdsoFixture(23)
      check fixture != nil
      let image = parseLinuxVdsoImageAt(fixture)
      check image.diagnostic == lrsOk
      let sym = resolveLinuxVdsoSymbol(image, cstring("__vdso_fixture"))
      check sym.diagnostic == lrsOk
      let fn = cast[TestFn](sym.address)
      check fn() == 23

      let tx = installLinuxVdsoOverlayPatchTransaction(
        fixture, image.length, sym.address, cast[pointer](replacementValue))
      check tx.diagnostic == lrsOk
      check tx.path == lvppOverlay
      check tx.overlayUsed
      check tx.patchLive
      check fn() == 42

    test "duplicate patch book is optional and executable segment validation is reusable":
      clearLinuxPatchBook()
      check not linuxPatchBookContains(cast[pointer](replacementValue))
      check recordLinuxPatchBookTarget(cast[pointer](replacementValue)) == 0
      check linuxPatchBookContains(cast[pointer](replacementValue))
      check recordLinuxPatchBookTarget(cast[pointer](replacementValue)) == 1
      check addrInLinuxExecutableSegment(cast[pointer](replacementValue))

      let anon = allocPatchTarget()
      check anon != nil
      check not addrInLinuxExecutableSegment(anon)

    test "near trampoline allocation returns writable rel32-reachable memory":
      let allocation = allocateLinuxNearTrampoline(cast[pointer](replacementValue), 64)
      check allocation.diagnostic == lrsOk
      check allocation.address != nil
      check allocation.length >= 64
      check allocation.withinRel32
      let bytes = cast[ptr UncheckedArray[byte]](allocation.address)
      bytes[0] = byte 0xc3
      check bytes[0] == byte 0xc3
      let decision = selectLinuxAtomicPatchStrategy(
        cast[pointer](replacementValue), allocation.address, 5)
      check decision.diagnostic == lrsOk
      check decision.strategy == lapsJmpRel32
      check freeLinuxNearTrampoline(allocation) == lrsOk

    test "C ABI symbols compile and link from a C translation unit":
      check cAbiLinkSmoke() == 0

    test "INT3 patch and restore only touch selected controlled syscall bytes":
      let buf = allocSyscallScanBuffer()
      check buf != nil
      let bytes = cast[ptr UncheckedArray[byte]](buf)
      check bytes[1] == linuxSyscallOpcode0
      check bytes[2] == linuxSyscallOpcode1

      let site = cast[pointer](cast[uint](buf) + 1'u)
      let tx = installInt3SyscallPatchTransaction(site)
      check tx.diagnostic == lrsOk
      check tx.stage == lpsComplete
      check tx.patchLive
      check tx.restoreByteCaptured
      check tx.handle.active
      check tx.handle.originalFirstByte == linuxSyscallOpcode0
      check tx.handle.secondByte == linuxSyscallOpcode1
      check bytes[1] == linuxInt3Opcode
      check bytes[2] == linuxSyscallOpcode1

      let second = installInt3SyscallPatchTransaction(site)
      check second.diagnostic == lrsAlreadyPatched
      check not second.patchLive
      check not second.restoreByteCaptured

      var handle = tx.handle
      check restoreInt3SyscallPatch(handle) == lrsOk
      check not handle.active
      check bytes[1] == linuxSyscallOpcode0
      check bytes[2] == linuxSyscallOpcode1

    test "INT3 patch has a no-libc fixed-page-size ABI variant":
      let buf = allocSyscallScanBuffer()
      check buf != nil
      let bytes = cast[ptr UncheckedArray[byte]](buf)
      let site = cast[pointer](cast[uint](buf) + 1'u)
      let tx = installInt3SyscallPatchTransaction(site, 4096'u)
      check tx.diagnostic == lrsOk
      check tx.patchLive
      check tx.restoreByteCaptured
      check bytes[1] == linuxInt3Opcode
      var handle = tx.handle
      check restoreInt3SyscallPatch(handle) == lrsOk
      check bytes[1] == linuxSyscallOpcode0
      check fixedPageInt3PatchSmoke() == 0

    test "INT3 patch rejects non-syscall controlled bytes":
      let target = allocPatchTarget()
      check target != nil
      let tx = installInt3SyscallPatchTransaction(target)
      check tx.diagnostic == lrsNotSyscallSite
      check not tx.patchLive
      check not tx.restoreByteCaptured

    test "ucontext register helpers and raw register replay are exported through C ABI":
      check ucontextHelpersSmoke() == 0
      check replayGetpid() > 0
      check staticRawSyscall6(39, 0, 0, 0, 0, 0, 0) > 0
      check rtSigreturnRestorerAddress() != nil
      check cloneContinuationTrampolineAddress() != nil

    test "SIGTRAP install/uninstall substrate restores process handler without raising trap":
      check sigtrapInstallUninstallSmoke() == 0

    test "live INT3 handler replays raw syscall and advances saved RIP":
      check liveInt3GetpidContinuation() > 0

    test "memory scanner describes callsites in a controlled executable buffer":
      let buf = allocSyscallScanBuffer()
      check buf != nil
      var offsets: seq[int]
      visitLinuxX8664SyscallMemory(buf, 16, proc(site: LinuxSyscallSite): bool =
        offsets.add site.offset
        true
      )
      check offsets == @[1, 11]

      let mapping = LinuxExecutableMapping(
        start: cast[uint](buf),
        stop: cast[uint](buf) + 16'u,
        readable: true,
        executable: true)
      var mappingOffsets: seq[int]
      visitLinuxExecutableMappingSyscalls(mapping, proc(site: LinuxSyscallSite): bool =
        mappingOffsets.add site.offset
        true
      )
      check mappingOffsets == @[1, 11]
