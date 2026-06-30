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
    lrsPrePatchMprotectFailed = "pre-patch-mprotect-failed"
    lrsPatchWriteFailed = "patch-write-failed"
    lrsPostPatchMprotectBackFailed = "post-patch-mprotect-back-failed"
    lrsRestoreFailed = "restore-failed"

  LinuxPatchStage* = enum
    lpsNone = "none"
    lpsValidateTarget = "validate-target"
    lpsPrePatchMprotect = "pre-patch-mprotect"
    lpsWritePatch = "write-patch"
    lpsPostPatchMprotectBack = "post-patch-mprotect-back"
    lpsComplete = "complete"

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

  LinuxPatchTransaction* = object
    ## Stage-aware patch result for consumers that need to distinguish fatal
    ## pre-patch failures from post-patch hardening failures after the jump is
    ## already live. This carries no lifecycle or policy decisions.
    handle*: LinuxPatchHandle
    stage*: LinuxPatchStage
    diagnostic*: LinuxRawSyscallDiagnostic
    osErrno*: cint
    patchLive*: bool
    restoreBytesCaptured*: bool

  LinuxSymbolResolverKind* = enum
    lsrDefault = "rtld-default"
    lsrHandle = "handle"

  LinuxSymbolResolver* = object
    ## One symbol lookup step. `lsrDefault` maps to `RTLD_DEFAULT`; `lsrHandle`
    ## uses an opened handle supplied by the consumer.
    kind*: LinuxSymbolResolverKind
    handle*: pointer

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

type CStackableLinuxPatchResult {.importc: "struct stackable_linux_patch_result",
                                  bycopy.} = object
  diagnostic {.importc: "diagnostic".}: cint
  stage {.importc: "stage".}: cint
  osErrno {.importc: "os_errno".}: cint
  patchLive {.importc: "patch_live".}: cint
  restoreCaptured {.importc: "restore_captured".}: cint
  target {.importc: "target".}: culong
  replacement {.importc: "replacement".}: culong
  patchSize {.importc: "patch_size".}: culong
  original {.importc: "original".}: array[14, byte]

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
#include <link.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#ifndef STACKABLE_LINUX_RTLD_NOLOAD
#define STACKABLE_LINUX_RTLD_NOLOAD RTLD_NOLOAD
#endif

enum {
  STACKABLE_LINUX_PATCH_OK = 0,
  STACKABLE_LINUX_PATCH_UNSUPPORTED_PLATFORM = 1,
  STACKABLE_LINUX_PATCH_UNSUPPORTED_ARCHITECTURE = 2,
  STACKABLE_LINUX_PATCH_INVALID_ARGUMENT = 3,
  STACKABLE_LINUX_PATCH_SYMBOL_NOT_FOUND = 4,
  STACKABLE_LINUX_PATCH_ALREADY_PATCHED = 5,
  STACKABLE_LINUX_PATCH_MPROTECT_FAILED = 6,
  STACKABLE_LINUX_PATCH_PRE_MPROTECT_FAILED = 7,
  STACKABLE_LINUX_PATCH_WRITE_FAILED = 8,
  STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED = 9,
  STACKABLE_LINUX_PATCH_RESTORE_FAILED = 10
};

enum {
  STACKABLE_LINUX_PATCH_STAGE_NONE = 0,
  STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET = 1,
  STACKABLE_LINUX_PATCH_STAGE_PRE_MPROTECT = 2,
  STACKABLE_LINUX_PATCH_STAGE_WRITE_PATCH = 3,
  STACKABLE_LINUX_PATCH_STAGE_POST_MPROTECT_BACK = 4,
  STACKABLE_LINUX_PATCH_STAGE_COMPLETE = 5
};

struct stackable_linux_patch_result {
  int diagnostic;
  int stage;
  int os_errno;
  int patch_live;
  int restore_captured;
  unsigned long target;
  unsigned long replacement;
  unsigned long patch_size;
  unsigned char original[14];
};

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

void *stackable_linux_open_library_noload(char *soname) {
  if (soname == NULL || soname[0] == '\0') return NULL;
  return dlopen(soname, RTLD_NOW | STACKABLE_LINUX_RTLD_NOLOAD);
}

void *stackable_linux_resolve_symbol_in_handle(void *handle, char *name) {
  if (name == NULL || name[0] == '\0') return NULL;
  return dlsym(handle == NULL ? RTLD_DEFAULT : handle, name);
}

static long stackable_linux_raw_mprotect(uintptr_t addr, size_t len, int prot) {
  return stackable_linux_raw_syscall6((long)SYS_mprotect, (long)addr,
                                      (long)len, (long)prot, 0, 0, 0);
}

static void stackable_linux_init_patch_result(
    struct stackable_linux_patch_result *out, void *target, void *replacement,
    int capture_restore) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->diagnostic = STACKABLE_LINUX_PATCH_OK;
  out->stage = STACKABLE_LINUX_PATCH_STAGE_NONE;
  out->target = (unsigned long)(uintptr_t)target;
  out->replacement = (unsigned long)(uintptr_t)replacement;
  out->patch_size = 14;
  out->restore_captured = 0;
}

int stackable_linux_patch_absolute_jump_tx(
    void *target, void *replacement, int capture_restore,
    struct stackable_linux_patch_result *out) {
  stackable_linux_init_patch_result(out, target, replacement, capture_restore);
  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET;
  if (target == NULL || replacement == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  uintptr_t page_mask = (uintptr_t)(page_size - 1);
  uintptr_t target_addr = (uintptr_t)target;
  uintptr_t start = target_addr & ~page_mask;
  uintptr_t end = (target_addr + 14 + page_mask) & ~page_mask;
  size_t span = (size_t)(end - start);

  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_PRE_MPROTECT;
  long mp1 = stackable_linux_raw_mprotect(start, span,
                                          PROT_READ | PROT_WRITE | PROT_EXEC);
  if (mp1 < 0) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_PRE_MPROTECT_FAILED;
      out->os_errno = (int)(-mp1);
    }
    return STACKABLE_LINUX_PATCH_PRE_MPROTECT_FAILED;
  }

  unsigned char *p = (unsigned char *)target;
  if (p[0] == 0xff && p[1] == 0x25 && p[2] == 0x00 && p[3] == 0x00 &&
      p[4] == 0x00 && p[5] == 0x00) {
    long mp_restore = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
    if (out) {
      out->stage = STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET;
      out->diagnostic = STACKABLE_LINUX_PATCH_ALREADY_PATCHED;
      if (mp_restore < 0) out->os_errno = (int)(-mp_restore);
    }
    return STACKABLE_LINUX_PATCH_ALREADY_PATCHED;
  }

  if (out && capture_restore) {
    memcpy(out->original, p, 14);
    out->restore_captured = 1;
  }

  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_WRITE_PATCH;
  p[0] = 0xff; p[1] = 0x25;
  p[2] = 0x00; p[3] = 0x00; p[4] = 0x00; p[5] = 0x00;
  uint64_t addr = (uint64_t)(uintptr_t)replacement;
  memcpy(p + 6, &addr, sizeof(addr));
  if (out) out->patch_live = 1;

  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_POST_MPROTECT_BACK;
  long mp2 = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
  if (mp2 < 0) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED;
      out->os_errno = (int)(-mp2);
    }
    return STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED;
  }

  if (out) {
    out->stage = STACKABLE_LINUX_PATCH_STAGE_COMPLETE;
    out->diagnostic = STACKABLE_LINUX_PATCH_OK;
  }
  return STACKABLE_LINUX_PATCH_OK;
}

int stackable_linux_patch_absolute_jump(void *target, void *replacement,
                                        unsigned char *saved14,
                                        int *out_errno) {
  if (out_errno) *out_errno = 0;
  if (saved14 == NULL) return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  struct stackable_linux_patch_result tx;
  int rc = stackable_linux_patch_absolute_jump_tx(target, replacement, 1, &tx);
  if (out_errno) *out_errno = tx.os_errno;
  if (rc == STACKABLE_LINUX_PATCH_OK ||
      rc == STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED) {
    memcpy(saved14, tx.original, 14);
    return 0;
  }
  return rc;
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

typedef struct {
  unsigned long anchor;
  int found_in_text;
} stackable_linux_phdr_query;

static int stackable_linux_phdr_cb(struct dl_phdr_info *info, size_t size,
                                   void *data) {
  (void)size;
  stackable_linux_phdr_query *q = (stackable_linux_phdr_query *)data;
  for (int i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
    if (ph->p_type != PT_LOAD) continue;
    if ((ph->p_flags & PF_X) == 0) continue;
    unsigned long seg_start = info->dlpi_addr + ph->p_vaddr;
    unsigned long seg_end = seg_start + ph->p_memsz;
    if (q->anchor >= seg_start && q->anchor < seg_end) {
      q->found_in_text = 1;
      return 1;
    }
  }
  return 0;
}

int stackable_linux_addr_in_executable_segment(unsigned long addr) {
  if (addr == 0) return 0;
  stackable_linux_phdr_query q;
  q.anchor = addr;
  q.found_in_text = 0;
  dl_iterate_phdr(stackable_linux_phdr_cb, &q);
  return q.found_in_text;
}

#define STACKABLE_LINUX_PATCH_REGISTRY_CAP 256
static unsigned long stackable_linux_patch_registry[STACKABLE_LINUX_PATCH_REGISTRY_CAP];
static int stackable_linux_patch_registry_count = 0;

void stackable_linux_patch_registry_reset(void) {
  stackable_linux_patch_registry_count = 0;
  memset(stackable_linux_patch_registry, 0, sizeof(stackable_linux_patch_registry));
}

int stackable_linux_patch_registry_contains(unsigned long addr) {
  for (int i = 0; i < stackable_linux_patch_registry_count; i++) {
    if (stackable_linux_patch_registry[i] == addr) return 1;
  }
  return 0;
}

int stackable_linux_patch_registry_record(unsigned long addr) {
  if (addr == 0) return 0;
  if (stackable_linux_patch_registry_contains(addr)) return 1;
  if (stackable_linux_patch_registry_count >= STACKABLE_LINUX_PATCH_REGISTRY_CAP) {
    return -1;
  }
  stackable_linux_patch_registry[stackable_linux_patch_registry_count++] = addr;
  return 0;
}
""".}

  proc cRawSyscall6(nr, a1, a2, a3, a4, a5, a6: clong): clong
    {.importc: "stackable_linux_raw_syscall6", cdecl.}
  proc cResolveDefaultSymbol(name: cstring): pointer
    {.importc: "stackable_linux_resolve_default_symbol", cdecl.}
  proc cOpenLibraryNoLoad(soname: cstring): pointer
    {.importc: "stackable_linux_open_library_noload", cdecl.}
  proc cResolveSymbolInHandle(handle: pointer; name: cstring): pointer
    {.importc: "stackable_linux_resolve_symbol_in_handle", cdecl.}
  proc cPatchAbsoluteJumpTx(target, replacement: pointer; captureRestore: cint;
                            outResult: ptr CStackableLinuxPatchResult): cint
    {.importc: "stackable_linux_patch_absolute_jump_tx", cdecl.}
  proc cRestoreAbsoluteJump(target: pointer; saved14: ptr byte;
                            outErrno: ptr cint): cint
    {.importc: "stackable_linux_restore_absolute_jump", cdecl.}
  proc cAddrInExecutableSegment(address: culong): cint
    {.importc: "stackable_linux_addr_in_executable_segment", cdecl.}
  proc cPatchRegistryReset()
    {.importc: "stackable_linux_patch_registry_reset", cdecl.}
  proc cPatchRegistryContains(address: culong): cint
    {.importc: "stackable_linux_patch_registry_contains", cdecl.}
  proc cPatchRegistryRecord(address: culong): cint
    {.importc: "stackable_linux_patch_registry_record", cdecl.}

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

proc openLibraryNoLoad*(soname: cstring): pointer =
  ## Open an already-loaded library without loading a new copy. Consumers choose
  ## which SONAMEs matter; this helper just exposes the reusable `dlopen`
  ## building block needed for resolver chains.
  if linuxRawSyscallSupported() != lrsOk or soname == nil:
    return nil
  when defined(linux) and defined(amd64):
    cOpenLibraryNoLoad(soname)
  else:
    nil

proc resolveSymbolInHandle*(handle: pointer; name: cstring): pointer =
  ## Resolve `name` through an explicit handle. A nil handle maps to
  ## `RTLD_DEFAULT`, matching `dlsym`'s conventional resolver sentinel.
  if linuxRawSyscallSupported() != lrsOk or name == nil:
    return nil
  when defined(linux) and defined(amd64):
    cResolveSymbolInHandle(handle, name)
  else:
    nil

proc defaultSymbolResolver*(): LinuxSymbolResolver =
  LinuxSymbolResolver(kind: lsrDefault)

proc handleSymbolResolver*(handle: pointer): LinuxSymbolResolver =
  LinuxSymbolResolver(kind: lsrHandle, handle: handle)

proc resolveSymbolChain*(name: cstring;
                         resolvers: openArray[LinuxSymbolResolver]): pointer =
  ## Resolve `name` by trying consumer-supplied resolver steps in order. This is
  ## enough to express policies such as RTLD_DEFAULT, then an opened libc
  ## RTLD_NOLOAD handle, without hard-wiring that policy into the framework.
  if name == nil:
    return nil
  for resolver in resolvers:
    let resolved =
      case resolver.kind
      of lsrDefault:
        resolveDefaultSymbol(name)
      of lsrHandle:
        resolveSymbolInHandle(resolver.handle, name)
    if resolved != nil:
      return resolved
  nil

proc toDiagnostic(rc: cint): LinuxRawSyscallDiagnostic {.used.} =
  case int(rc)
  of 0: lrsOk
  of 1: lrsUnsupportedPlatform
  of 2: lrsUnsupportedArchitecture
  of 3: lrsInvalidArgument
  of 4: lrsSymbolNotFound
  of 5: lrsAlreadyPatched
  of 6: lrsMprotectFailed
  of 7: lrsPrePatchMprotectFailed
  of 8: lrsPatchWriteFailed
  of 9: lrsPostPatchMprotectBackFailed
  of 10: lrsRestoreFailed
  else: lrsPatchWriteFailed

proc toPatchStage(stage: cint): LinuxPatchStage {.used.} =
  case int(stage)
  of 0: lpsNone
  of 1: lpsValidateTarget
  of 2: lpsPrePatchMprotect
  of 3: lpsWritePatch
  of 4: lpsPostPatchMprotectBack
  of 5: lpsComplete
  else: lpsNone

proc fromCTransaction(cres: CStackableLinuxPatchResult): LinuxPatchTransaction {.used.} =
  when defined(linux) and defined(amd64):
    result.handle.target = cast[pointer](cres.target)
    result.handle.replacement = cast[pointer](cres.replacement)
    result.handle.patchSize = int(cres.patchSize)
    result.handle.originalBytes = cres.original
    result.handle.active = cres.patchLive != 0
    result.handle.diagnostic = toDiagnostic(cres.diagnostic)
    result.handle.osErrno = cres.osErrno
    result.stage = toPatchStage(cres.stage)
    result.diagnostic = toDiagnostic(cres.diagnostic)
    result.osErrno = cres.osErrno
    result.patchLive = cres.patchLive != 0
    result.restoreBytesCaptured = cres.restoreCaptured != 0
  else:
    discard

proc installAbsoluteJumpPatchTransaction*(target, replacement: pointer;
                                          captureRestoreBytes = true): LinuxPatchTransaction =
  ## Install a 14-byte absolute jump and return stage-aware diagnostics. If the
  ## post-patch mprotect-back step fails, `patchLive` is true and the diagnostic
  ## records that security hardening failed after the patch was installed.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    result.handle.diagnostic = support
    return
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxPatchResult
    discard cPatchAbsoluteJumpTx(target, replacement,
                                 if captureRestoreBytes: 1 else: 0,
                                 addr cres)
    result = fromCTransaction(cres)
  else:
    result.diagnostic = support
    result.handle.diagnostic = support

proc installAbsoluteJumpPatch*(target, replacement: pointer): LinuxPatchHandle =
  ## Patch `target` with `jmp qword ptr [rip+0]; .quad replacement`.
  ## This primitive assumes the caller has already proven installation timing
  ## safety. It does not suspend threads and does not attach consumer policy.
  let tx = installAbsoluteJumpPatchTransaction(target, replacement)
  result = tx.handle
  if tx.diagnostic == lrsPostPatchMprotectBackFailed and tx.patchLive:
    result.diagnostic = lrsOk

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

proc addrInLinuxExecutableSegment*(address: pointer): bool =
  ## Return true when `address` falls inside any loaded executable PT_LOAD
  ## segment. Consumers decide whether "any executable segment" is sufficient
  ## or whether they need a stricter libc/vDSO/self-exclusion policy.
  if linuxRawSyscallSupported() != lrsOk or address == nil:
    return false
  when defined(linux) and defined(amd64):
    cAddrInExecutableSegment(cast[culong](address)) != 0
  else:
    false

proc clearLinuxPatchBook*() =
  ## Reset the optional in-process duplicate-target helper.
  when defined(linux) and defined(amd64):
    cPatchRegistryReset()

proc linuxPatchBookContains*(address: pointer): bool =
  ## Check whether a consumer previously recorded this target address in the
  ## optional duplicate-target helper.
  if address == nil:
    return false
  when defined(linux) and defined(amd64):
    cPatchRegistryContains(cast[culong](address)) != 0
  else:
    false

proc recordLinuxPatchBookTarget*(address: pointer): cint =
  ## Record an address in the optional duplicate-target helper. Returns 0 for a
  ## new address, 1 for duplicate, and -1 when the fixed helper table is full.
  if address == nil:
    return cint(-1)
  when defined(linux) and defined(amd64):
    cPatchRegistryRecord(cast[culong](address))
  else:
    cint(-1)

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
