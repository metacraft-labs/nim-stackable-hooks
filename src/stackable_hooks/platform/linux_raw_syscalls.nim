## Linux raw-syscall helper primitives.
##
## This module contains reusable, non-opinionated pieces extracted from the
## MCR monkey-patching design:
##
## - raw syscall forwarding for framework internals;
## - x86_64 absolute-jump body patching for explicit wrapper addresses;
## - conservative x86_64 original-call trampoline construction for wrapper
##   prologues that can be copied without relocation;
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
    lrsUnsupportedInstruction = "unsupported-instruction"
    lrsTrampolineAllocFailed = "trampoline-alloc-failed"
    lrsTrampolineBuildFailed = "trampoline-build-failed"
    lrsNotSyscallSite = "not-syscall-site"
    lrsTrapInstallFailed = "trap-install-failed"
    lrsTrapChainUnavailable = "trap-chain-unavailable"

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
    ## forwarding should use `buildOriginalCallTrampoline` before patching.
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

  LinuxOriginalTrampoline* = object
    ## Restore-free original-call trampoline for a body-patched Linux x86_64
    ## wrapper. The trampoline contains an instruction-aware copy of the first
    ## `copiedLen` bytes from `target`, followed by the same 14-byte absolute
    ## jump form back to `target + copiedLen`.
    target*: pointer
    entry*: pointer
    copiedLen*: int
    minPatchLen*: int
    diagnostic*: LinuxRawSyscallDiagnostic
    osErrno*: cint
    unsupportedOffset*: int

  LinuxInt3Callsite* = object
    ## One raw `0f 05` callsite selected by a consumer for INT3 handling.
    ## `address` points at byte 0 of the syscall instruction, not the saved
    ## SIGTRAP RIP. Consumers own mapping/self-exclusion policy.
    address*: uint
    originalFirstByte*: byte
    patched*: bool

  LinuxInt3CallsiteTable* = object
    ## Sorted table for signal-handler lookup. INT3 reports saved RIP as
    ## `callsite + 1`, so use `findLinuxInt3CallsiteForTrapRip` in handlers.
    sites*: seq[LinuxInt3Callsite]

  LinuxInt3PatchHandle* = object
    target*: pointer
    originalFirstByte*: byte
    secondByte*: byte
    active*: bool
    diagnostic*: LinuxRawSyscallDiagnostic
    osErrno*: cint

  LinuxInt3PatchTransaction* = object
    handle*: LinuxInt3PatchHandle
    stage*: LinuxPatchStage
    diagnostic*: LinuxRawSyscallDiagnostic
    osErrno*: cint
    patchLive*: bool
    restoreByteCaptured*: bool

  LinuxX8664SyscallRegisters* = object
    ## Policy-free view of the Linux x86_64 syscall ABI captured from a
    ## SIGTRAP `ucontext_t` at an INT3-patched raw syscall site.
    syscallNumber*: int
    args*: array[6, int]
    result*: int
    trapRip*: uint
    syscallAddress*: uint
    resumeRip*: uint

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

type CStackableLinuxTrampolineResult {.importc: "struct stackable_linux_trampoline_result",
                                       bycopy.} = object
  diagnostic {.importc: "diagnostic".}: cint
  osErrno {.importc: "os_errno".}: cint
  target {.importc: "target".}: culong
  entry {.importc: "entry".}: culong
  copiedLen {.importc: "copied_len".}: culong
  minPatchLen {.importc: "min_patch_len".}: culong
  unsupportedOffset {.importc: "unsupported_offset".}: clong

type CStackableLinuxInt3PatchResult {.importc: "struct stackable_linux_int3_patch_result",
                                      bycopy.} = object
  diagnostic {.importc: "diagnostic".}: cint
  stage {.importc: "stage".}: cint
  osErrno {.importc: "os_errno".}: cint
  patchLive {.importc: "patch_live".}: cint
  restoreCaptured {.importc: "restore_captured".}: cint
  target {.importc: "target".}: culong
  originalFirstByte {.importc: "original_first_byte".}: byte
  secondByte {.importc: "second_byte".}: byte

type CStackableLinuxSyscallRegs {.importc: "struct stackable_linux_syscall_regs",
                                  bycopy.} = object
  nr {.importc: "nr".}: clong
  args {.importc: "args".}: array[6, clong]
  result {.importc: "result".}: clong
  trapRip {.importc: "trap_rip".}: culong
  syscallAddress {.importc: "syscall_address".}: culong
  resumeRip {.importc: "resume_rip".}: culong

const
  linuxSyscallOpcode0* = byte 0x0f
  linuxSyscallOpcode1* = byte 0x05
  linuxInt3Opcode* = byte 0xcc
  linuxAbsoluteJumpPatchSize* = 14
  linuxTrampolineJumpBackSize* = linuxAbsoluteJumpPatchSize

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
#include <signal.h>
#include <ucontext.h>

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
  STACKABLE_LINUX_PATCH_RESTORE_FAILED = 10,
  STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION = 11,
  STACKABLE_LINUX_PATCH_TRAMPOLINE_ALLOC_FAILED = 12,
  STACKABLE_LINUX_PATCH_TRAMPOLINE_BUILD_FAILED = 13,
  STACKABLE_LINUX_PATCH_NOT_SYSCALL_SITE = 14,
  STACKABLE_LINUX_PATCH_TRAP_INSTALL_FAILED = 15,
  STACKABLE_LINUX_PATCH_TRAP_CHAIN_UNAVAILABLE = 16
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

struct stackable_linux_trampoline_result {
  int diagnostic;
  int os_errno;
  unsigned long target;
  unsigned long entry;
  unsigned long copied_len;
  unsigned long min_patch_len;
  long unsupported_offset;
};

struct stackable_linux_int3_patch_result {
  int diagnostic;
  int stage;
  int os_errno;
  int patch_live;
  int restore_captured;
  unsigned long target;
  unsigned char original_first_byte;
  unsigned char second_byte;
};

struct stackable_linux_syscall_regs {
  long nr;
  long args[6];
  long result;
  unsigned long trap_rip;
  unsigned long syscall_address;
  unsigned long resume_rip;
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

static long stackable_linux_raw_mmap(void *addr, size_t len, int prot,
                                     int flags, int fd, long offset) {
  return stackable_linux_raw_syscall6((long)SYS_mmap, (long)addr, (long)len,
                                      (long)prot, (long)flags, (long)fd,
                                      offset);
}

static void stackable_linux_write_abs_jump(unsigned char *p, void *target) {
  p[0] = 0xff; p[1] = 0x25;
  p[2] = 0x00; p[3] = 0x00; p[4] = 0x00; p[5] = 0x00;
  uint64_t addr = (uint64_t)(uintptr_t)target;
  memcpy(p + 6, &addr, sizeof(addr));
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
  stackable_linux_write_abs_jump(p, replacement);
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

static void stackable_linux_init_int3_result(
    struct stackable_linux_int3_patch_result *out, void *target) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->diagnostic = STACKABLE_LINUX_PATCH_OK;
  out->stage = STACKABLE_LINUX_PATCH_STAGE_NONE;
  out->target = (unsigned long)(uintptr_t)target;
}

int stackable_linux_patch_int3_syscall_tx(
    void *target, struct stackable_linux_int3_patch_result *out) {
  stackable_linux_init_int3_result(out, target);
  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET;
  if (target == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  uintptr_t page_mask = (uintptr_t)(page_size - 1);
  uintptr_t target_addr = (uintptr_t)target;
  uintptr_t start = target_addr & ~page_mask;
  uintptr_t end = (target_addr + 2 + page_mask) & ~page_mask;
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
  if (p[0] == 0xcc && p[1] == 0x05) {
    long mp_restore = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
    if (out) {
      out->stage = STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET;
      out->diagnostic = STACKABLE_LINUX_PATCH_ALREADY_PATCHED;
      if (mp_restore < 0) out->os_errno = (int)(-mp_restore);
    }
    return STACKABLE_LINUX_PATCH_ALREADY_PATCHED;
  }
  if (p[0] != 0x0f || p[1] != 0x05) {
    long mp_restore = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
    if (out) {
      out->stage = STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET;
      out->diagnostic = STACKABLE_LINUX_PATCH_NOT_SYSCALL_SITE;
      if (mp_restore < 0) out->os_errno = (int)(-mp_restore);
    }
    return STACKABLE_LINUX_PATCH_NOT_SYSCALL_SITE;
  }

  if (out) {
    out->original_first_byte = p[0];
    out->second_byte = p[1];
    out->restore_captured = 1;
  }

  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_WRITE_PATCH;
  *(volatile unsigned char *)p = 0xcc;
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

int stackable_linux_restore_int3_syscall(
    void *target, unsigned char original_first_byte, int *out_errno) {
  if (out_errno) *out_errno = 0;
  if (target == NULL) return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  uintptr_t page_mask = (uintptr_t)(page_size - 1);
  uintptr_t target_addr = (uintptr_t)target;
  uintptr_t start = target_addr & ~page_mask;
  uintptr_t end = (target_addr + 2 + page_mask) & ~page_mask;
  size_t span = (size_t)(end - start);

  long mp1 = stackable_linux_raw_mprotect(start, span,
                                          PROT_READ | PROT_WRITE | PROT_EXEC);
  if (mp1 < 0) {
    if (out_errno) *out_errno = (int)(-mp1);
    return STACKABLE_LINUX_PATCH_PRE_MPROTECT_FAILED;
  }

  unsigned char *p = (unsigned char *)target;
  if (p[0] != 0xcc || p[1] != 0x05) {
    long mp_restore = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
    if (out_errno && mp_restore < 0) *out_errno = (int)(-mp_restore);
    return STACKABLE_LINUX_PATCH_NOT_SYSCALL_SITE;
  }
  p[0] = original_first_byte;

  long mp2 = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
  if (mp2 < 0) {
    if (out_errno) *out_errno = (int)(-mp2);
    return STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED;
  }
  return STACKABLE_LINUX_PATCH_OK;
}

static int stackable_linux_decode_one_x86_64(const unsigned char *p,
                                             size_t max_len,
                                             size_t *out_len) {
  if (p == NULL || out_len == NULL || max_len == 0) {
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  size_t i = 0;
  int has_operand_prefix = 0;
  int has_rex = 0;
  unsigned char rex = 0;

  for (;;) {
    if (i >= max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    unsigned char b = p[i];
    if (b == 0x66 || b == 0x67 || b == 0xf2 || b == 0xf3) {
      has_operand_prefix = 1;
      i++;
      continue;
    }
    if (b >= 0x40 && b <= 0x4f) {
      has_rex = 1;
      rex = b;
      i++;
      continue;
    }
    break;
  }

  if (i >= max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  unsigned char op = p[i++];

  if (op == 0x90 || op == 0xc9) {
    *out_len = i;
    return STACKABLE_LINUX_PATCH_OK;
  }
  if ((op >= 0x50 && op <= 0x5f) || op == 0x9c || op == 0x9d) {
    *out_len = i;
    return STACKABLE_LINUX_PATCH_OK;
  }
  if (op == 0xcc ||
      op == 0xc3 || op == 0xcb || op == 0xc2 || op == 0xca ||
      op == 0xe8 || op == 0xe9 || op == 0xeb ||
      (op >= 0x70 && op <= 0x7f)) {
    return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  }

  if (op >= 0xb8 && op <= 0xbf) {
    size_t imm = (has_rex && (rex & 0x08)) ? 8 : (has_operand_prefix ? 2 : 4);
    if (i + imm > max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    *out_len = i + imm;
    return STACKABLE_LINUX_PATCH_OK;
  }

  if (op == 0x0f) {
    if (i >= max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    unsigned char op2 = p[i++];
    if (op2 == 0x05 || op2 == 0x34 || op2 == 0x35 ||
        (op2 >= 0x80 && op2 <= 0x8f)) {
      return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    }
    return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  }

  int needs_modrm = 0;
  size_t imm_len = 0;
  switch (op) {
    case 0x01: case 0x03: case 0x09: case 0x0b:
    case 0x21: case 0x23: case 0x29: case 0x2b:
    case 0x31: case 0x33: case 0x39: case 0x3b:
    case 0x63: case 0x85: case 0x87: case 0x89:
    case 0x8b: case 0x8d: case 0x8f:
      needs_modrm = 1;
      break;
    case 0x80:
      needs_modrm = 1; imm_len = 1; break;
    case 0x81:
      needs_modrm = 1; imm_len = 4; break;
    case 0x83:
      needs_modrm = 1; imm_len = 1; break;
    case 0xc7:
      needs_modrm = 1; imm_len = 4; break;
    case 0x68:
      imm_len = 4; break;
    case 0x6a:
      imm_len = 1; break;
    case 0xa1: case 0xa3:
      return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    default:
      return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  }

  if (needs_modrm) {
    if (i >= max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    unsigned char modrm = p[i++];
    unsigned char mod = (modrm >> 6) & 0x3;
    unsigned char rm = modrm & 0x7;
    if (mod != 3 && rm == 5) {
      return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    }
    if (mod != 3 && rm == 4) {
      if (i >= max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
      unsigned char sib = p[i++];
      unsigned char base = sib & 0x7;
      if (mod == 0 && base == 5) {
        if (i + 4 > max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
        i += 4;
      }
    }
    if (mod == 1) {
      if (i + 1 > max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
      i += 1;
    } else if (mod == 2) {
      if (i + 4 > max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
      i += 4;
    }
  }

  if (i + imm_len > max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  *out_len = i + imm_len;
  return STACKABLE_LINUX_PATCH_OK;
}

static int stackable_linux_measure_relocatable_prefix(
    void *target, size_t min_len, size_t max_scan, size_t *out_len,
    long *unsupported_offset) {
  if (out_len) *out_len = 0;
  if (unsupported_offset) *unsupported_offset = -1;
  if (target == NULL || min_len == 0 || out_len == NULL) {
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  if (max_scan < min_len) max_scan = min_len;

  const unsigned char *p = (const unsigned char *)target;
  size_t copied = 0;
  while (copied < min_len) {
    size_t insn_len = 0;
    int rc = stackable_linux_decode_one_x86_64(p + copied,
                                               max_scan - copied,
                                               &insn_len);
    if (rc != STACKABLE_LINUX_PATCH_OK) {
      if (unsupported_offset) *unsupported_offset = (long)copied;
      return rc;
    }
    if (insn_len == 0 || copied + insn_len > max_scan) {
      if (unsupported_offset) *unsupported_offset = (long)copied;
      return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    }
    copied += insn_len;
  }
  *out_len = copied;
  return STACKABLE_LINUX_PATCH_OK;
}

static void stackable_linux_init_trampoline_result(
    struct stackable_linux_trampoline_result *out, void *target,
    size_t min_patch_len) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->diagnostic = STACKABLE_LINUX_PATCH_OK;
  out->target = (unsigned long)(uintptr_t)target;
  out->min_patch_len = (unsigned long)min_patch_len;
  out->unsupported_offset = -1;
}

int stackable_linux_measure_original_trampoline(void *target,
                                                unsigned long min_patch_len,
                                                unsigned long max_scan,
                                                struct stackable_linux_trampoline_result *out) {
  if (min_patch_len == 0) min_patch_len = 14;
  if (max_scan == 0) max_scan = 64;
  stackable_linux_init_trampoline_result(out, target, (size_t)min_patch_len);
  if (target == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  size_t copied = 0;
  long unsupported = -1;
  int rc = stackable_linux_measure_relocatable_prefix(
      target, (size_t)min_patch_len, (size_t)max_scan, &copied, &unsupported);
  if (out) {
    out->diagnostic = rc;
    out->copied_len = (unsigned long)copied;
    out->unsupported_offset = unsupported;
  }
  return rc;
}

int stackable_linux_build_original_trampoline(void *target,
                                              unsigned long min_patch_len,
                                              unsigned long max_scan,
                                              struct stackable_linux_trampoline_result *out) {
  if (min_patch_len == 0) min_patch_len = 14;
  if (max_scan == 0) max_scan = 64;
  stackable_linux_init_trampoline_result(out, target, (size_t)min_patch_len);
  if (target == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  size_t copied = 0;
  long unsupported = -1;
  int rc = stackable_linux_measure_relocatable_prefix(
      target, (size_t)min_patch_len, (size_t)max_scan, &copied, &unsupported);
  if (rc != STACKABLE_LINUX_PATCH_OK) {
    if (out) {
      out->diagnostic = rc;
      out->unsupported_offset = unsupported;
    }
    return rc;
  }

  size_t total = copied + 14;
  long mapped = stackable_linux_raw_mmap(NULL, total, PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapped < 0) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_TRAMPOLINE_ALLOC_FAILED;
      out->os_errno = (int)(-mapped);
    }
    return STACKABLE_LINUX_PATCH_TRAMPOLINE_ALLOC_FAILED;
  }

  unsigned char *tramp = (unsigned char *)(uintptr_t)mapped;
  memcpy(tramp, target, copied);
  stackable_linux_write_abs_jump(tramp + copied,
      (void *)((uintptr_t)target + copied));

  long protect_rc = stackable_linux_raw_mprotect((uintptr_t)tramp, total,
                                                 PROT_READ | PROT_EXEC);
  if (protect_rc < 0) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_TRAMPOLINE_BUILD_FAILED;
      out->os_errno = (int)(-protect_rc);
    }
    return STACKABLE_LINUX_PATCH_TRAMPOLINE_BUILD_FAILED;
  }

  if (out) {
    out->diagnostic = STACKABLE_LINUX_PATCH_OK;
    out->entry = (unsigned long)(uintptr_t)tramp;
    out->copied_len = (unsigned long)copied;
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

static int stackable_linux_copy_ucontext_regs(
    void *ucontext_ptr, struct stackable_linux_syscall_regs *out) {
  if (ucontext_ptr == NULL || out == NULL) {
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  ucontext_t *uc = (ucontext_t *)ucontext_ptr;
  out->nr = (long)uc->uc_mcontext.gregs[REG_RAX];
  out->args[0] = (long)uc->uc_mcontext.gregs[REG_RDI];
  out->args[1] = (long)uc->uc_mcontext.gregs[REG_RSI];
  out->args[2] = (long)uc->uc_mcontext.gregs[REG_RDX];
  out->args[3] = (long)uc->uc_mcontext.gregs[REG_R10];
  out->args[4] = (long)uc->uc_mcontext.gregs[REG_R8];
  out->args[5] = (long)uc->uc_mcontext.gregs[REG_R9];
  out->result = (long)uc->uc_mcontext.gregs[REG_RAX];
  out->trap_rip = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
  out->syscall_address = out->trap_rip == 0 ? 0 : out->trap_rip - 1;
  out->resume_rip = out->trap_rip + 1;
  return STACKABLE_LINUX_PATCH_OK;
}

int stackable_linux_capture_syscall_regs_from_ucontext(
    void *ucontext_ptr, struct stackable_linux_syscall_regs *out) {
  return stackable_linux_copy_ucontext_regs(ucontext_ptr, out);
}

int stackable_linux_write_syscall_result_to_ucontext(
    void *ucontext_ptr, long result, unsigned long resume_rip) {
  if (ucontext_ptr == NULL) return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  ucontext_t *uc = (ucontext_t *)ucontext_ptr;
  uc->uc_mcontext.gregs[REG_RAX] = (greg_t)result;
  if (resume_rip != 0) {
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)resume_rip;
  }
  return STACKABLE_LINUX_PATCH_OK;
}

long stackable_linux_replay_syscall_regs(
    const struct stackable_linux_syscall_regs *regs) {
  if (regs == NULL) return -22;
  return stackable_linux_raw_syscall6(regs->nr, regs->args[0], regs->args[1],
                                      regs->args[2], regs->args[3],
                                      regs->args[4], regs->args[5]);
}

static struct sigaction stackable_linux_old_sigtrap_action;
static int stackable_linux_sigtrap_installed = 0;

int stackable_linux_install_sigtrap_handler(void *handler, int extra_flags) {
  if (handler == NULL) return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  if (stackable_linux_sigtrap_installed) return STACKABLE_LINUX_PATCH_ALREADY_PATCHED;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = (void (*)(int, siginfo_t *, void *))handler;
  sa.sa_flags = SA_SIGINFO | extra_flags;
  if (sigaction(SIGTRAP, &sa, &stackable_linux_old_sigtrap_action) != 0) {
    return STACKABLE_LINUX_PATCH_TRAP_INSTALL_FAILED;
  }
  stackable_linux_sigtrap_installed = 1;
  return STACKABLE_LINUX_PATCH_OK;
}

int stackable_linux_uninstall_sigtrap_handler(void) {
  if (!stackable_linux_sigtrap_installed) {
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  if (sigaction(SIGTRAP, &stackable_linux_old_sigtrap_action, NULL) != 0) {
    return STACKABLE_LINUX_PATCH_TRAP_INSTALL_FAILED;
  }
  stackable_linux_sigtrap_installed = 0;
  return STACKABLE_LINUX_PATCH_OK;
}

int stackable_linux_chain_sigtrap(int signum, void *siginfo_ptr,
                                  void *ucontext_ptr) {
  if (!stackable_linux_sigtrap_installed) {
    return STACKABLE_LINUX_PATCH_TRAP_CHAIN_UNAVAILABLE;
  }
  if (stackable_linux_old_sigtrap_action.sa_flags & SA_SIGINFO) {
    if (stackable_linux_old_sigtrap_action.sa_sigaction == NULL) {
      return STACKABLE_LINUX_PATCH_TRAP_CHAIN_UNAVAILABLE;
    }
    stackable_linux_old_sigtrap_action.sa_sigaction(
        signum, (siginfo_t *)siginfo_ptr, ucontext_ptr);
    return STACKABLE_LINUX_PATCH_OK;
  }
  if (stackable_linux_old_sigtrap_action.sa_handler == SIG_DFL ||
      stackable_linux_old_sigtrap_action.sa_handler == SIG_IGN ||
      stackable_linux_old_sigtrap_action.sa_handler == NULL) {
    return STACKABLE_LINUX_PATCH_TRAP_CHAIN_UNAVAILABLE;
  }
  stackable_linux_old_sigtrap_action.sa_handler(signum);
  return STACKABLE_LINUX_PATCH_OK;
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
  proc cMeasureOriginalTrampoline(target: pointer; minPatchLen, maxScan: culong;
                                  outResult: ptr CStackableLinuxTrampolineResult): cint
    {.importc: "stackable_linux_measure_original_trampoline", cdecl.}
  proc cBuildOriginalTrampoline(target: pointer; minPatchLen, maxScan: culong;
                                outResult: ptr CStackableLinuxTrampolineResult): cint
    {.importc: "stackable_linux_build_original_trampoline", cdecl.}
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
  proc cPatchInt3SyscallTx(target: pointer;
                           outResult: ptr CStackableLinuxInt3PatchResult): cint
    {.importc: "stackable_linux_patch_int3_syscall_tx", cdecl.}
  proc cRestoreInt3Syscall(target: pointer; originalFirstByte: byte;
                           outErrno: ptr cint): cint
    {.importc: "stackable_linux_restore_int3_syscall", cdecl.}
  proc cCaptureSyscallRegsFromUcontext(ucontext: pointer;
                                       outRegs: ptr CStackableLinuxSyscallRegs): cint
    {.importc: "stackable_linux_capture_syscall_regs_from_ucontext", cdecl.}
  proc cWriteSyscallResultToUcontext(ucontext: pointer; result: clong;
                                     resumeRip: culong): cint
    {.importc: "stackable_linux_write_syscall_result_to_ucontext", cdecl.}
  proc cReplaySyscallRegs(regs: ptr CStackableLinuxSyscallRegs): clong
    {.importc: "stackable_linux_replay_syscall_regs", cdecl.}
  proc cInstallSigtrapHandler(handler: pointer; extraFlags: cint): cint
    {.importc: "stackable_linux_install_sigtrap_handler", cdecl.}
  proc cUninstallSigtrapHandler(): cint
    {.importc: "stackable_linux_uninstall_sigtrap_handler", cdecl.}
  proc cChainSigtrap(signum: cint; siginfo: pointer; ucontext: pointer): cint
    {.importc: "stackable_linux_chain_sigtrap", cdecl.}

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
  of 11: lrsUnsupportedInstruction
  of 12: lrsTrampolineAllocFailed
  of 13: lrsTrampolineBuildFailed
  of 14: lrsNotSyscallSite
  of 15: lrsTrapInstallFailed
  of 16: lrsTrapChainUnavailable
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

proc fromCTrampoline(cres: CStackableLinuxTrampolineResult): LinuxOriginalTrampoline {.used.} =
  when defined(linux) and defined(amd64):
    result.target = cast[pointer](cres.target)
    result.entry = cast[pointer](cres.entry)
    result.copiedLen = int(cres.copiedLen)
    result.minPatchLen = int(cres.minPatchLen)
    result.diagnostic = toDiagnostic(cres.diagnostic)
    result.osErrno = cres.osErrno
    result.unsupportedOffset = int(cres.unsupportedOffset)
  else:
    discard

proc fromCInt3Transaction(cres: CStackableLinuxInt3PatchResult): LinuxInt3PatchTransaction {.used.} =
  when defined(linux) and defined(amd64):
    result.handle.target = cast[pointer](cres.target)
    result.handle.originalFirstByte = cres.originalFirstByte
    result.handle.secondByte = cres.secondByte
    result.handle.active = cres.patchLive != 0
    result.handle.diagnostic = toDiagnostic(cres.diagnostic)
    result.handle.osErrno = cres.osErrno
    result.stage = toPatchStage(cres.stage)
    result.diagnostic = toDiagnostic(cres.diagnostic)
    result.osErrno = cres.osErrno
    result.patchLive = cres.patchLive != 0
    result.restoreByteCaptured = cres.restoreCaptured != 0
  else:
    discard

proc fromCSyscallRegs(cres: CStackableLinuxSyscallRegs): LinuxX8664SyscallRegisters {.used.} =
  when defined(linux) and defined(amd64):
    result.syscallNumber = int(cres.nr)
    for i in 0 ..< 6:
      result.args[i] = int(cres.args[i])
    result.result = int(cres.result)
    result.trapRip = uint(cres.trapRip)
    result.syscallAddress = uint(cres.syscallAddress)
    result.resumeRip = uint(cres.resumeRip)
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

proc measureOriginalCallTrampoline*(target: pointer;
                                    minPatchLen = linuxAbsoluteJumpPatchSize;
                                    maxScan = 64): LinuxOriginalTrampoline =
  ## Decode a target wrapper prologue until at least `minPatchLen` bytes can be
  ## copied into an original-call trampoline. This is validation only: no memory
  ## is allocated and unsupported prologues are rejected with
  ## `lrsUnsupportedInstruction`.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    return
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxTrampolineResult
    discard cMeasureOriginalTrampoline(target, culong(minPatchLen), culong(maxScan),
                                       addr cres)
    result = fromCTrampoline(cres)
  else:
    result.diagnostic = support

proc buildOriginalCallTrampoline*(target: pointer;
                                  minPatchLen = linuxAbsoluteJumpPatchSize;
                                  maxScan = 64): LinuxOriginalTrampoline =
  ## Allocate an executable original-call trampoline for a Linux x86_64 wrapper
  ## body patch. The copied prefix is instruction-aware and conservative:
  ## unsupported control-flow instructions, `syscall`, absolute moffs
  ## instructions, and RIP-relative memory operands are rejected rather than
  ## relocated incorrectly. Successful trampolines append a 14-byte absolute
  ## jump back to `target + copiedLen`.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    return
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxTrampolineResult
    discard cBuildOriginalTrampoline(target, culong(minPatchLen), culong(maxScan),
                                     addr cres)
    result = fromCTrampoline(cres)
  else:
    result.diagnostic = support

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

proc addLinuxInt3Callsite*(table: var LinuxInt3CallsiteTable;
                           address: uint;
                           originalFirstByte: byte = linuxSyscallOpcode0;
                           patched = false): bool =
  ## Insert one callsite while preserving sort order. Returns false for a
  ## duplicate address. No mapping selection or patch policy is implied.
  var lo = 0
  var hi = table.sites.len
  while lo < hi:
    let mid = lo + ((hi - lo) shr 1)
    if table.sites[mid].address < address:
      lo = mid + 1
    else:
      hi = mid
  if lo < table.sites.len and table.sites[lo].address == address:
    return false
  table.sites.insert LinuxInt3Callsite(
    address: address,
    originalFirstByte: originalFirstByte,
    patched: patched), lo
  true

proc findLinuxInt3Callsite*(table: LinuxInt3CallsiteTable;
                            address: uint): int =
  ## Return the sorted-table index for `address`, or `-1`.
  var lo = 0
  var hi = table.sites.len
  while lo < hi:
    let mid = lo + ((hi - lo) shr 1)
    if table.sites[mid].address == address:
      return mid
    if table.sites[mid].address < address:
      lo = mid + 1
    else:
      hi = mid
  -1

proc findLinuxInt3CallsiteForTrapRip*(table: LinuxInt3CallsiteTable;
                                      trapRip: uint): int =
  ## Lookup using the saved RIP from an x86_64 Linux INT3 SIGTRAP. The CPU
  ## reports RIP after the 1-byte INT3, so the original callsite is `RIP - 1`.
  if trapRip == 0:
    return -1
  findLinuxInt3Callsite(table, trapRip - 1)

proc installInt3SyscallPatchTransaction*(target: pointer): LinuxInt3PatchTransaction =
  ## Replace byte 0 of a selected Linux x86_64 raw syscall (`0f 05`) with
  ## `INT3` and capture the restore byte. This does not install a handler and
  ## does not decide which mappings should be patched.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    result.handle.diagnostic = support
    return
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxInt3PatchResult
    discard cPatchInt3SyscallTx(target, addr cres)
    result = fromCInt3Transaction(cres)
  else:
    result.diagnostic = support
    result.handle.diagnostic = support

proc restoreInt3SyscallPatch*(handle: var LinuxInt3PatchHandle): LinuxRawSyscallDiagnostic =
  ## Restore the first byte overwritten by `installInt3SyscallPatchTransaction`.
  if handle.diagnostic != lrsOk:
    return handle.diagnostic
  if not handle.active:
    return lrsInvalidArgument
  when defined(linux) and defined(amd64):
    var osErr: cint
    let rc = cRestoreInt3Syscall(handle.target, handle.originalFirstByte, addr osErr)
    handle.osErrno = osErr
    if rc == 0:
      handle.active = false
      lrsOk
    else:
      toDiagnostic(rc)
  else:
    linuxRawSyscallSupported()

proc captureLinuxX8664SyscallRegisters*(ucontext: pointer):
    tuple[diagnostic: LinuxRawSyscallDiagnostic,
          regs: LinuxX8664SyscallRegisters] =
  ## Capture Linux x86_64 syscall ABI registers from a SIGTRAP `ucontext_t`.
  ## This is policy-free: it does not classify syscalls or special-case clone.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return (support, LinuxX8664SyscallRegisters())
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxSyscallRegs
    let rc = cCaptureSyscallRegsFromUcontext(ucontext, addr cres)
    (toDiagnostic(rc), fromCSyscallRegs(cres))
  else:
    (support, LinuxX8664SyscallRegisters())

proc writeLinuxX8664SyscallResult*(ucontext: pointer; resultValue: int;
                                   resumeRip: uint): LinuxRawSyscallDiagnostic =
  ## Write a syscall result to RAX and optionally advance saved RIP. For INT3
  ## raw syscall continuation, use the `resumeRip` produced by
  ## `captureLinuxX8664SyscallRegisters`.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return support
  when defined(linux) and defined(amd64):
    toDiagnostic(cWriteSyscallResultToUcontext(
      ucontext, clong(resultValue), culong(resumeRip)))
  else:
    support

proc replayLinuxX8664SyscallRegisters*(regs: LinuxX8664SyscallRegisters): int =
  ## Re-issue the captured syscall with the Linux x86_64 raw syscall ABI.
  ## Consumers remain responsible for deciding whether a particular syscall is
  ## safe to replay this way.
  if linuxRawSyscallSupported() != lrsOk:
    return -38
  when defined(linux) and defined(amd64):
    var cregs: CStackableLinuxSyscallRegs
    cregs.nr = clong(regs.syscallNumber)
    for i in 0 ..< 6:
      cregs.args[i] = clong(regs.args[i])
    cregs.result = clong(regs.result)
    cregs.trapRip = culong(regs.trapRip)
    cregs.syscallAddress = culong(regs.syscallAddress)
    cregs.resumeRip = culong(regs.resumeRip)
    int(cReplaySyscallRegs(addr cregs))
  else:
    -38

proc installLinuxSigtrapHandler*(handler: pointer; extraFlags: cint = 0):
    LinuxRawSyscallDiagnostic =
  ## Install a process SIGTRAP SA_SIGINFO handler and save the previous action
  ## for explicit chaining/restoration. This is the low-level substrate only;
  ## consumers own dispatch policy, reentrancy, and handler body.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return support
  when defined(linux) and defined(amd64):
    toDiagnostic(cInstallSigtrapHandler(handler, extraFlags))
  else:
    support

proc uninstallLinuxSigtrapHandler*(): LinuxRawSyscallDiagnostic =
  ## Restore the previous SIGTRAP action saved by `installLinuxSigtrapHandler`.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return support
  when defined(linux) and defined(amd64):
    toDiagnostic(cUninstallSigtrapHandler())
  else:
    support

proc chainLinuxSigtrap*(signum: cint; siginfo: pointer; ucontext: pointer):
    LinuxRawSyscallDiagnostic =
  ## Invoke the SIGTRAP action that was active before
  ## `installLinuxSigtrapHandler`, when one is chainable.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return support
  when defined(linux) and defined(amd64):
    toDiagnostic(cChainSigtrap(signum, siginfo, ucontext))
  else:
    support

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
