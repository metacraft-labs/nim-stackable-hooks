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
  proc replacementValue(): cint
    {.importc: "stackable_test_replacement_value", cdecl.}
  proc allocSyscallScanBuffer(): pointer
    {.importc: "stackable_test_alloc_syscall_scan_buffer", cdecl.}

  type TestFn = proc(): cint {.cdecl.}

  suite "linux raw syscall live patch":
    test "absolute jump patch changes and restores a controlled executable buffer":
      let target = allocPatchTarget()
      check target != nil
      let fn = cast[TestFn](target)
      check fn() == 7

      var handle = installAbsoluteJumpPatch(target, cast[pointer](replacementValue))
      check handle.diagnostic == lrsOk
      check handle.active
      check handle.patchSize == linuxAbsoluteJumpPatchSize
      check fn() == 42

      check restoreAbsoluteJumpPatch(handle) == lrsOk
      check not handle.active
      check fn() == 7

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
