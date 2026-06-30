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

when defined(linux) and defined(amd64):
  {.compile: "fixtures/linux_raw_syscalls_c_abi_smoke.c".}
  {.emit: """
#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

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
