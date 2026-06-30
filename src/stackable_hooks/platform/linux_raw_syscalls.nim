## Linux raw-syscall helper primitives.
##
## This module contains reusable, non-opinionated pieces extracted from the
## MCR monkey-patching design:
##
## - raw syscall forwarding for framework internals;
## - x86_64 absolute-jump body patching for explicit wrapper addresses;
## - byte and mapping scanners for Linux x86_64 `syscall` (`0f 05`) sites.
##
## It deliberately does not know about MCR events, replay, io-mon records,
## stage0 installation, clone attribution, or consumer lifecycle policy.

import std/strutils

type
  LinuxRawSyscallDiagnostic* = enum
    lrsOk = "ok"
    lrsUnsupportedPlatform = "unsupported-platform"
    lrsUnsupportedArchitecture = "unsupported-architecture"
    lrsInvalidArgument = "invalid-argument"
    lrsSymbolNotFound = "symbol-not-found"
    lrsAlreadyPatched = "already-patched"
    lrsMprotectFailed = "mprotect-failed"
    lrsPatchWriteFailed = "patch-write-failed"
    lrsRestoreFailed = "restore-failed"

  LinuxPatchHandle* = object
    ## Opaque-enough patch record for consumers that need diagnostics or later
    ## restore. `originalBytes` stores the overwritten 14-byte x86_64 absolute
    ## jump window. This is not an original-call trampoline; consumers that need
    ## forwarding should build a policy-specific trampoline after instruction
    ## decoding in a later milestone.
    target*: pointer
    replacement*: pointer
    patchSize*: int
    originalBytes*: array[14, byte]
    active*: bool
    diagnostic*: LinuxRawSyscallDiagnostic
    osErrno*: cint

  LinuxSyscallSite* = object
    address*: uint
    offset*: int
    nextByte*: byte

  LinuxExecutableMapping* = object
    start*: uint
    stop*: uint
    readable*: bool
    writable*: bool
    executable*: bool
    privateMapping*: bool
    path*: string

const
  linuxSyscallOpcode0* = byte 0x0f
  linuxSyscallOpcode1* = byte 0x05
  linuxInt3Opcode* = byte 0xcc
  linuxAbsoluteJumpPatchSize* = 14

proc linuxRawSyscallSupported*(): LinuxRawSyscallDiagnostic =
  when defined(linux):
    when defined(amd64):
      lrsOk
    else:
      lrsUnsupportedArchitecture
  else:
    lrsUnsupportedPlatform

when defined(linux) and defined(amd64):
  {.emit: """
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

long stackable_linux_raw_syscall6(long nr, long a1, long a2, long a3,
                                  long a4, long a5, long a6) {
  long ret;
  register long r10 __asm__("r10") = a4;
  register long r8  __asm__("r8")  = a5;
  register long r9  __asm__("r9")  = a6;
  __asm__ volatile (
    "syscall"
    : "=a"(ret)
    : "0"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
    : "rcx", "r11", "memory"
  );
  return ret;
}

void *stackable_linux_resolve_default_symbol(char *name) {
  if (name == NULL || name[0] == '\0') return NULL;
  return dlsym(RTLD_DEFAULT, name);
}

static long stackable_linux_raw_mprotect(uintptr_t addr, size_t len, int prot) {
  return stackable_linux_raw_syscall6((long)SYS_mprotect, (long)addr,
                                      (long)len, (long)prot, 0, 0, 0);
}

int stackable_linux_patch_absolute_jump(void *target, void *replacement,
                                        unsigned char *saved14,
                                        int *out_errno) {
  if (out_errno) *out_errno = 0;
  if (target == NULL || replacement == NULL || saved14 == NULL) return 3;

  unsigned char *p = (unsigned char *)target;
  if (p[0] == 0xff && p[1] == 0x25 && p[2] == 0x00 && p[3] == 0x00 &&
      p[4] == 0x00 && p[5] == 0x00) {
    return 4;
  }

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  uintptr_t page_mask = (uintptr_t)(page_size - 1);
  uintptr_t target_addr = (uintptr_t)target;
  uintptr_t start = target_addr & ~page_mask;
  uintptr_t end = (target_addr + 14 + page_mask) & ~page_mask;
  size_t span = (size_t)(end - start);

  long mp1 = stackable_linux_raw_mprotect(start, span,
                                          PROT_READ | PROT_WRITE | PROT_EXEC);
  if (mp1 < 0) {
    if (out_errno) *out_errno = (int)(-mp1);
    return 5;
  }

  memcpy(saved14, p, 14);
  p[0] = 0xff; p[1] = 0x25;
  p[2] = 0x00; p[3] = 0x00; p[4] = 0x00; p[5] = 0x00;
  uint64_t addr = (uint64_t)(uintptr_t)replacement;
  memcpy(p + 6, &addr, sizeof(addr));

  long mp2 = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
  if (mp2 < 0) {
    if (out_errno) *out_errno = (int)(-mp2);
    return 0;
  }
  return 0;
}

int stackable_linux_restore_absolute_jump(void *target,
                                          unsigned char *saved14,
                                          int *out_errno) {
  if (out_errno) *out_errno = 0;
  if (target == NULL || saved14 == NULL) return 3;

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  uintptr_t page_mask = (uintptr_t)(page_size - 1);
  uintptr_t target_addr = (uintptr_t)target;
  uintptr_t start = target_addr & ~page_mask;
  uintptr_t end = (target_addr + 14 + page_mask) & ~page_mask;
  size_t span = (size_t)(end - start);

  long mp1 = stackable_linux_raw_mprotect(start, span,
                                          PROT_READ | PROT_WRITE | PROT_EXEC);
  if (mp1 < 0) {
    if (out_errno) *out_errno = (int)(-mp1);
    return 7;
  }
  memcpy(target, saved14, 14);
  long mp2 = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
  if (mp2 < 0) {
    if (out_errno) *out_errno = (int)(-mp2);
    return 7;
  }
  return 0;
}
""".}

  proc cRawSyscall6(nr, a1, a2, a3, a4, a5, a6: clong): clong
    {.importc: "stackable_linux_raw_syscall6", cdecl.}
  proc cResolveDefaultSymbol(name: cstring): pointer
    {.importc: "stackable_linux_resolve_default_symbol", cdecl.}
  proc cPatchAbsoluteJump(target, replacement: pointer;
                          saved14: ptr byte; outErrno: ptr cint): cint
    {.importc: "stackable_linux_patch_absolute_jump", cdecl.}
  proc cRestoreAbsoluteJump(target: pointer; saved14: ptr byte;
                            outErrno: ptr cint): cint
    {.importc: "stackable_linux_restore_absolute_jump", cdecl.}

proc rawSyscall6*(nr, a1, a2, a3, a4, a5, a6: int): int =
  ## Issue a Linux x86_64 raw syscall using the kernel calling convention.
  ## Unsupported platforms return `-38` (`ENOSYS`) instead of silently
  ## pretending success.
  when defined(linux) and defined(amd64):
    int(cRawSyscall6(clong(nr), clong(a1), clong(a2), clong(a3), clong(a4),
                     clong(a5), clong(a6)))
  else:
    -38

proc resolveDefaultSymbol*(name: cstring): pointer =
  ## Resolve an exported process symbol with `dlsym(RTLD_DEFAULT, name)`.
  ## This is intentionally only resolution; consumers decide whether the symbol
  ## belongs to libc, vDSO, or another interpose target set.
  if linuxRawSyscallSupported() != lrsOk or name == nil:
    return nil
  when defined(linux) and defined(amd64):
    cResolveDefaultSymbol(name)
  else:
    nil

proc installAbsoluteJumpPatch*(target, replacement: pointer): LinuxPatchHandle =
  ## Patch `target` with `jmp qword ptr [rip+0]; .quad replacement`.
  ## This primitive assumes the caller has already proven installation timing
  ## safety. It does not suspend threads and does not attach consumer policy.
  result.target = target
  result.replacement = replacement
  result.patchSize = linuxAbsoluteJumpPatchSize
  result.diagnostic = linuxRawSyscallSupported()
  if result.diagnostic != lrsOk:
    return
  when defined(linux) and defined(amd64):
    var saved: array[14, byte]
    var osErr: cint
    let rc = cPatchAbsoluteJump(target, replacement, addr saved[0], addr osErr)
    result.osErrno = osErr
    result.originalBytes = saved
    case rc
    of 0:
      result.active = true
      result.diagnostic = lrsOk
    of 3:
      result.diagnostic = lrsInvalidArgument
    of 4:
      result.diagnostic = lrsAlreadyPatched
    of 5:
      result.diagnostic = lrsMprotectFailed
    else:
      result.diagnostic = lrsPatchWriteFailed

proc installNamedAbsoluteJumpPatch*(symbolName: cstring;
                                    replacement: pointer): LinuxPatchHandle =
  ## Resolve `symbolName` in the current process and install an absolute jump.
  ## This supports exported libc/syscall-wrapper style consumers without
  ## hard-wiring the framework to any particular symbol list.
  result.patchSize = linuxAbsoluteJumpPatchSize
  result.replacement = replacement
  result.diagnostic = linuxRawSyscallSupported()
  if result.diagnostic != lrsOk:
    return
  let target = resolveDefaultSymbol(symbolName)
  if target == nil:
    result.diagnostic = lrsSymbolNotFound
    return
  result = installAbsoluteJumpPatch(target, replacement)

proc restoreAbsoluteJumpPatch*(handle: var LinuxPatchHandle): LinuxRawSyscallDiagnostic =
  ## Restore bytes saved by `installAbsoluteJumpPatch`.
  if handle.diagnostic != lrsOk:
    return handle.diagnostic
  if not handle.active:
    return lrsInvalidArgument
  when defined(linux) and defined(amd64):
    var osErr: cint
    let rc = cRestoreAbsoluteJump(handle.target, unsafeAddr handle.originalBytes[0],
                                  addr osErr)
    handle.osErrno = osErr
    if rc == 0:
      handle.active = false
      lrsOk
    else:
      lrsRestoreFailed
  else:
    linuxRawSyscallSupported()

proc looksLikeLinuxX8664Syscall*(bytes: openArray[byte]; offset: int): bool =
  ## Conservative byte-level syscall-site predicate. This follows MCR's current
  ## false-positive guard: a `0f 05` followed by `00` is likely an embedded
  ## immediate in generated code, not an instruction boundary.
  if offset < 0 or offset + 2 >= bytes.len:
    return false
  bytes[offset] == linuxSyscallOpcode0 and
    bytes[offset + 1] == linuxSyscallOpcode1 and
    bytes[offset + 2] != byte 0x00

proc scanLinuxX8664SyscallBytes*(bytes: openArray[byte];
                                 baseAddress: uint = 0): seq[LinuxSyscallSite] =
  ## Scan a controlled byte slice for Linux x86_64 raw syscall opcodes.
  if bytes.len < 3:
    return @[]
  var i = 0
  while i + 2 < bytes.len:
    if looksLikeLinuxX8664Syscall(bytes, i):
      result.add LinuxSyscallSite(
        address: baseAddress + uint(i),
        offset: i,
        nextByte: bytes[i + 2])
      inc i, 2
    else:
      inc i

proc visitLinuxX8664SyscallBytes*(bytes: openArray[byte];
                                  visitor: proc(site: LinuxSyscallSite): bool
                                    {.closure, raises: [].};
                                  baseAddress: uint = 0) {.raises: [].} =
  ## Callback-style scanner surface for consumers that want to classify, patch,
  ## or reject sites without first allocating a result sequence. Returning
  ## `false` from `visitor` stops the scan.
  if bytes.len < 3 or visitor == nil:
    return
  var i = 0
  while i + 2 < bytes.len:
    if looksLikeLinuxX8664Syscall(bytes, i):
      let keepGoing = visitor LinuxSyscallSite(
        address: baseAddress + uint(i),
        offset: i,
        nextByte: bytes[i + 2])
      if not keepGoing:
        return
      inc i, 2
    else:
      inc i

proc visitLinuxX8664SyscallMemory*(start: pointer; length: int;
                                   visitor: proc(site: LinuxSyscallSite): bool
                                     {.closure, raises: [].}) {.raises: [].} =
  ## Scan an already-readable memory range for raw syscall callsites. The
  ## caller owns mapping selection and exclusion policy.
  if start == nil or length < 3 or visitor == nil:
    return
  when defined(linux) and defined(amd64):
    let p = cast[ptr UncheckedArray[byte]](start)
    let base = cast[uint](start)
    var i = 0
    while i + 2 < length:
      if p[i] == linuxSyscallOpcode0 and p[i + 1] == linuxSyscallOpcode1 and
          p[i + 2] != byte 0x00:
        let keepGoing = visitor LinuxSyscallSite(
          address: base + uint(i),
          offset: i,
          nextByte: p[i + 2])
        if not keepGoing:
          return
        inc i, 2
      else:
        inc i

proc visitLinuxExecutableMappingSyscalls*(mapping: LinuxExecutableMapping;
                                          visitor: proc(site: LinuxSyscallSite): bool
                                            {.closure, raises: [].}) {.raises: [].} =
  ## Scan one readable executable mapping selected by the consumer. Kernel
  ## pseudo-mappings, self-mappings, and size limits are caller policy.
  if linuxRawSyscallSupported() != lrsOk:
    return
  if not (mapping.readable and mapping.executable):
    return
  if mapping.stop <= mapping.start:
    return
  let length = int(mapping.stop - mapping.start)
  visitLinuxX8664SyscallMemory(cast[pointer](mapping.start), length, visitor)

proc parseLinuxMapsLine*(line: string): tuple[ok: bool, mapping: LinuxExecutableMapping] =
  ## Parse one `/proc/self/maps` line. Exposed for deterministic tests and for
  ## consumers that want to apply their own mapping filters before scanning.
  let parts = line.splitWhitespace(maxsplit = 5)
  if parts.len < 5:
    return (false, LinuxExecutableMapping())
  let dash = parts[0].find('-')
  if dash <= 0:
    return (false, LinuxExecutableMapping())
  try:
    result.mapping.start = parseHexInt(parts[0][0 ..< dash]).uint
    result.mapping.stop = parseHexInt(parts[0][dash + 1 .. ^1]).uint
  except ValueError:
    return (false, LinuxExecutableMapping())
  if parts[1].len < 4:
    return (false, LinuxExecutableMapping())
  result.mapping.readable = parts[1][0] == 'r'
  result.mapping.writable = parts[1][1] == 'w'
  result.mapping.executable = parts[1][2] == 'x'
  result.mapping.privateMapping = parts[1][3] == 'p'
  result.mapping.path = if parts.len >= 6: parts[5] else: ""
  result.ok = true

proc enumerateLinuxExecutableMappings*(): tuple[diagnostic: LinuxRawSyscallDiagnostic,
                                                mappings: seq[LinuxExecutableMapping]] =
  ## Enumerate readable executable mappings from `/proc/self/maps`.
  ## Kernel pseudo-mappings such as `[vdso]` are returned to the caller, not
  ## silently filtered, so consumer policy can decide whether to scan or skip.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return (support, @[])
  when defined(linux):
    for line in lines("/proc/self/maps"):
      let parsed = parseLinuxMapsLine(line)
      if parsed.ok and parsed.mapping.readable and parsed.mapping.executable:
        result.mappings.add parsed.mapping
    result.diagnostic = lrsOk
  else:
    result = (support, @[])
