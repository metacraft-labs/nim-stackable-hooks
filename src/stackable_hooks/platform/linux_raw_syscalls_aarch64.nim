## Linux AArch64 (A64) raw-syscall / body-patch primitives
## ========================================================
##
## The aarch64 sibling of `linux_raw_syscalls.nim`'s x86_64 body-patch subset:
## an absolute-jump body-patcher, a fixed-width (4-byte) instruction decoder,
## and a PC-relative branch relocator, for statically-linked / static-pie / Go
## targets that issue raw `svc #0` syscalls.
##
## Substitutions vs the x86_64 primitives:
##   - Syscall instruction:  `0f 05`  ->  `svc #0` (`0xd4000001`).
##   - Absolute jump (`ff 25 <abs64>`, 14 B)  ->
##       `ldr x16, #8` (`0x58000050`); `br x16` (`0xd61f0200`); `.quad target`
##       = 16 bytes, 4-byte aligned.
##   - Variable-length decode  ->  fixed 4-byte decode; the "relocatable prefix"
##     is measured in whole 4-byte instructions.
##   - rel32/rel8 branch relocation  ->  A64 `b`/`bl` (imm26, +/-128 MB),
##     `b.cond`/`cbz`/`cbnz` (imm19, +/-1 MB), `tbz`/`tbnz` (imm14, +/-32 KB).
##   - Non-relocatable, refused so a window never spans them: `svc`/`brk`/`hlt`,
##     `ret`/`br`/`blr`/`eret`, and the PC-relative address forms
##     `adr`/`adrp`/`ldr (literal)` (mirroring `macos_bodypatch.nim`'s
##     `prologue_relocatable` refusal).
##   - I-cache: A64 is not coherent I/D like x86, so every code write is followed
##     by `__builtin___clear_cache`.
##
## The C body below is the source of truth for the vendored copy shipped in
## downstream consumers; keep the two in sync.

import std/os

# Make the shared header findable from this module's own directory, regardless
# of the consumer's build flags (self-contained include path).
{.passC: "-I" & currentSourcePath().parentDir().}

const a64Header = "linux_raw_syscalls_aarch64.h"

type LinuxAarch64PatchDiagnostic* = enum
  la64Ok = 0
  la64UnsupportedPlatform = 1
  la64UnsupportedArchitecture = 2

proc linuxAarch64PatchSupported*(): LinuxAarch64PatchDiagnostic =
  ## Whether the A64 body-patch primitives are available on this build target.
  when defined(linux):
    when defined(arm64): la64Ok
    else: la64UnsupportedArchitecture
  else:
    la64UnsupportedPlatform

# Bound to the shared header `linux_raw_syscalls_aarch64.h`, so the same struct
# definition is visible in this module and every consumer translation unit.
type CStackableLinuxAarch64PatchResult* {.importc: "struct stackable_linux_patch_result",
                                          header: a64Header, bycopy.} = object
  diagnostic* {.importc: "diagnostic".}: cint
  stage* {.importc: "stage".}: cint
  osErrno* {.importc: "os_errno".}: cint
  patchLive* {.importc: "patch_live".}: cint
  restoreCaptured* {.importc: "restore_captured".}: cint
  target* {.importc: "target".}: culong
  replacement* {.importc: "replacement".}: culong
  patchSize* {.importc: "patch_size".}: culong
  original* {.importc: "original".}: array[16, byte]

type CStackableLinuxAarch64TrampolineResult* {.importc: "struct stackable_linux_trampoline_result",
                                               header: a64Header, bycopy.} = object
  diagnostic* {.importc: "diagnostic".}: cint
  osErrno* {.importc: "os_errno".}: cint
  target* {.importc: "target".}: culong
  entry* {.importc: "entry".}: culong
  copiedLen* {.importc: "copied_len".}: culong
  minPatchLen* {.importc: "min_patch_len".}: culong
  unsupportedOffset* {.importc: "unsupported_offset".}: clong

when defined(linux) and defined(arm64):
  {.emit: """
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "linux_raw_syscalls_aarch64.h"

enum {
  STACKABLE_LINUX_PATCH_OK = 0,
  STACKABLE_LINUX_PATCH_INVALID_ARGUMENT = 3,
  STACKABLE_LINUX_PATCH_ALREADY_PATCHED = 5,
  STACKABLE_LINUX_PATCH_PRE_MPROTECT_FAILED = 7,
  STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED = 9,
  STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION = 11,
  STACKABLE_LINUX_PATCH_TRAMPOLINE_ALLOC_FAILED = 12,
  STACKABLE_LINUX_PATCH_TRAMPOLINE_BUILD_FAILED = 13
};

enum {
  STACKABLE_LINUX_PATCH_STAGE_NONE = 0,
  STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET = 1,
  STACKABLE_LINUX_PATCH_STAGE_PRE_MPROTECT = 2,
  STACKABLE_LINUX_PATCH_STAGE_WRITE_PATCH = 3,
  STACKABLE_LINUX_PATCH_STAGE_POST_MPROTECT_BACK = 4,
  STACKABLE_LINUX_PATCH_STAGE_COMPLETE = 5
};

#define STACKABLE_AARCH64_PATCH_SIZE 16

long stackable_linux_aarch64_raw_syscall6(long nr, long a1, long a2, long a3,
                                          long a4, long a5, long a6) {
  register long x8 __asm__("x8") = nr;
  register long x0 __asm__("x0") = a1;
  register long x1 __asm__("x1") = a2;
  register long x2 __asm__("x2") = a3;
  register long x3 __asm__("x3") = a4;
  register long x4 __asm__("x4") = a5;
  register long x5 __asm__("x5") = a6;
  __asm__ volatile("svc #0"
                   : "+r"(x0)
                   : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                   : "memory", "cc");
  return x0;
}

static long stackable_linux_aarch64_raw_mprotect(uintptr_t addr, size_t len,
                                                 int prot) {
  return stackable_linux_aarch64_raw_syscall6((long)SYS_mprotect, (long)addr,
                                              (long)len, (long)prot, 0, 0, 0);
}

static long stackable_linux_aarch64_raw_mmap(void *addr, size_t len, int prot,
                                             int flags, int fd, long offset) {
  return stackable_linux_aarch64_raw_syscall6((long)SYS_mmap, (long)addr,
                                              (long)len, (long)prot,
                                              (long)flags, (long)fd, offset);
}

static uint32_t stackable_a64_read_insn(const unsigned char *p) {
  uint32_t v; memcpy(&v, p, 4); return v;
}
static void stackable_a64_write_insn(unsigned char *p, uint32_t v) {
  memcpy(p, &v, 4);
}

static void stackable_linux_aarch64_write_abs_jump(unsigned char *p, void *target) {
  stackable_a64_write_insn(p + 0, 0x58000050u); /* ldr x16, #8 */
  stackable_a64_write_insn(p + 4, 0xd61f0200u); /* br  x16     */
  uint64_t addr = (uint64_t)(uintptr_t)target;
  memcpy(p + 8, &addr, sizeof(addr));
}

static int stackable_a64_is_barrier(uint32_t insn) {
  if ((insn & 0xFF000000u) == 0xD4000000u) return 1; /* svc/brk/hlt/... */
  if ((insn & 0xFE000000u) == 0xD6000000u) return 1; /* br/blr/ret/eret */
  return 0;
}
static int stackable_a64_is_pcrel_addr(uint32_t insn) {
  if ((insn & 0x9F000000u) == 0x90000000u) return 1; /* adrp          */
  if ((insn & 0x9F000000u) == 0x10000000u) return 1; /* adr           */
  if ((insn & 0x3B000000u) == 0x18000000u) return 1; /* ldr (literal) */
  return 0;
}
static int stackable_a64_branch_kind(uint32_t insn) {
  if ((insn & 0xFC000000u) == 0x14000000u) return 1; /* b   imm26 */
  if ((insn & 0xFC000000u) == 0x94000000u) return 2; /* bl  imm26 */
  if ((insn & 0xFF000010u) == 0x54000000u) return 3; /* b.cond imm19 */
  if ((insn & 0x7E000000u) == 0x34000000u) return 4; /* cbz/cbnz imm19 */
  if ((insn & 0x7E000000u) == 0x36000000u) return 5; /* tbz/tbnz imm14 */
  return 0;
}

static int stackable_linux_aarch64_decode_one(const unsigned char *p,
                                              size_t max_len, size_t *out_len) {
  if (p == NULL || out_len == NULL || max_len < 4)
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  uint32_t insn = stackable_a64_read_insn(p);
  if (stackable_a64_is_barrier(insn) || stackable_a64_is_pcrel_addr(insn))
    return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  *out_len = 4;
  return STACKABLE_LINUX_PATCH_OK;
}

static int stackable_linux_aarch64_measure_relocatable_prefix(
    void *target, size_t min_len, size_t max_scan, size_t *out_len,
    long *unsupported_offset) {
  if (out_len) *out_len = 0;
  if (unsupported_offset) *unsupported_offset = -1;
  if (target == NULL || min_len == 0 || out_len == NULL)
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  if (max_scan < min_len) max_scan = min_len;
  const unsigned char *p = (const unsigned char *)target;
  size_t copied = 0;
  while (copied < min_len) {
    size_t insn_len = 0;
    int rc = stackable_linux_aarch64_decode_one(p + copied, max_scan - copied, &insn_len);
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

static int stackable_a64_fits_signed(int64_t v, unsigned bits) {
  int64_t lim = (int64_t)1 << (bits - 1);
  return v >= -lim && v <= (lim - 1);
}

int stackable_linux_aarch64_relocate_window(unsigned char *tramp,
                                            uintptr_t orig_addr,
                                            uintptr_t tramp_addr, size_t copied) {
  int64_t delta_insns = ((int64_t)orig_addr - (int64_t)tramp_addr) / 4;
  size_t off = 0;
  while (off + 4 <= copied) {
    uint32_t insn = stackable_a64_read_insn(tramp + off);
    int kind = stackable_a64_branch_kind(insn);
    if (kind == 1 || kind == 2) {
      int64_t imm = (int64_t)(insn & 0x03FFFFFFu);
      if (imm & 0x02000000) imm |= ~(int64_t)0x03FFFFFF;
      int64_t nd = imm + delta_insns;
      if (!stackable_a64_fits_signed(nd, 26)) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
      insn = (insn & 0xFC000000u) | ((uint32_t)nd & 0x03FFFFFFu);
      stackable_a64_write_insn(tramp + off, insn);
    } else if (kind == 3 || kind == 4) {
      int64_t imm = (int64_t)((insn >> 5) & 0x7FFFFu);
      if (imm & 0x40000) imm |= ~(int64_t)0x7FFFF;
      int64_t nd = imm + delta_insns;
      if (!stackable_a64_fits_signed(nd, 19)) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
      insn = (insn & ~(0x7FFFFu << 5)) | (((uint32_t)nd & 0x7FFFFu) << 5);
      stackable_a64_write_insn(tramp + off, insn);
    } else if (kind == 5) {
      int64_t imm = (int64_t)((insn >> 5) & 0x3FFFu);
      if (imm & 0x2000) imm |= ~(int64_t)0x3FFF;
      int64_t nd = imm + delta_insns;
      if (!stackable_a64_fits_signed(nd, 14)) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
      insn = (insn & ~(0x3FFFu << 5)) | (((uint32_t)nd & 0x3FFFu) << 5);
      stackable_a64_write_insn(tramp + off, insn);
    }
    off += 4;
  }
  return STACKABLE_LINUX_PATCH_OK;
}

static void stackable_linux_aarch64_init_patch_result(
    struct stackable_linux_patch_result *out, void *target, void *replacement,
    int capture_restore) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->diagnostic = STACKABLE_LINUX_PATCH_OK;
  out->stage = STACKABLE_LINUX_PATCH_STAGE_NONE;
  out->target = (unsigned long)(uintptr_t)target;
  out->replacement = (unsigned long)(uintptr_t)replacement;
  out->patch_size = STACKABLE_AARCH64_PATCH_SIZE;
  out->restore_captured = 0;
  (void)capture_restore;
}

int stackable_linux_aarch64_patch_absolute_jump_tx(
    void *target, void *replacement, int capture_restore,
    struct stackable_linux_patch_result *out) {
  stackable_linux_aarch64_init_patch_result(out, target, replacement, capture_restore);
  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET;
  if (target == NULL || replacement == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  if (((uintptr_t)target & 0x3u) != 0) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  uintptr_t page_mask = (uintptr_t)(page_size - 1);
  uintptr_t target_addr = (uintptr_t)target;
  uintptr_t start = target_addr & ~page_mask;
  uintptr_t end = (target_addr + STACKABLE_AARCH64_PATCH_SIZE + page_mask) & ~page_mask;
  size_t span = (size_t)(end - start);

  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_PRE_MPROTECT;
  long mp1 = stackable_linux_aarch64_raw_mprotect(start, span, PROT_READ | PROT_WRITE | PROT_EXEC);
  if (mp1 < 0) {
    if (out) { out->diagnostic = STACKABLE_LINUX_PATCH_PRE_MPROTECT_FAILED; out->os_errno = (int)(-mp1); }
    return STACKABLE_LINUX_PATCH_PRE_MPROTECT_FAILED;
  }
  unsigned char *p = (unsigned char *)target;
  if (stackable_a64_read_insn(p) == 0x58000050u && stackable_a64_read_insn(p + 4) == 0xd61f0200u) {
    long mp_restore = stackable_linux_aarch64_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
    if (out) {
      out->stage = STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET;
      out->diagnostic = STACKABLE_LINUX_PATCH_ALREADY_PATCHED;
      if (mp_restore < 0) out->os_errno = (int)(-mp_restore);
    }
    return STACKABLE_LINUX_PATCH_ALREADY_PATCHED;
  }
  if (out && capture_restore) {
    memcpy(out->original, p, STACKABLE_AARCH64_PATCH_SIZE);
    out->restore_captured = 1;
  }
  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_WRITE_PATCH;
  stackable_linux_aarch64_write_abs_jump(p, replacement);
  __builtin___clear_cache((char *)p, (char *)p + STACKABLE_AARCH64_PATCH_SIZE);
  if (out) out->patch_live = 1;

  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_POST_MPROTECT_BACK;
  long mp2 = stackable_linux_aarch64_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
  if (mp2 < 0) {
    if (out) { out->diagnostic = STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED; out->os_errno = (int)(-mp2); }
    return STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED;
  }
  if (out) { out->stage = STACKABLE_LINUX_PATCH_STAGE_COMPLETE; out->diagnostic = STACKABLE_LINUX_PATCH_OK; }
  return STACKABLE_LINUX_PATCH_OK;
}

static void stackable_linux_aarch64_init_trampoline_result(
    struct stackable_linux_trampoline_result *out, void *target, size_t min_patch_len) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->diagnostic = STACKABLE_LINUX_PATCH_OK;
  out->target = (unsigned long)(uintptr_t)target;
  out->min_patch_len = (unsigned long)min_patch_len;
  out->unsupported_offset = -1;
}

int stackable_linux_aarch64_measure_original_trampoline(
    void *target, unsigned long min_patch_len, unsigned long max_scan,
    struct stackable_linux_trampoline_result *out) {
  if (min_patch_len == 0) min_patch_len = STACKABLE_AARCH64_PATCH_SIZE;
  if (max_scan == 0) max_scan = 64;
  stackable_linux_aarch64_init_trampoline_result(out, target, (size_t)min_patch_len);
  if (target == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  size_t copied = 0; long unsupported = -1;
  int rc = stackable_linux_aarch64_measure_relocatable_prefix(
      target, (size_t)min_patch_len, (size_t)max_scan, &copied, &unsupported);
  if (out) { out->diagnostic = rc; out->copied_len = (unsigned long)copied; out->unsupported_offset = unsupported; }
  return rc;
}

int stackable_linux_aarch64_build_original_trampoline(
    void *target, unsigned long min_patch_len, unsigned long max_scan,
    struct stackable_linux_trampoline_result *out) {
  if (min_patch_len == 0) min_patch_len = STACKABLE_AARCH64_PATCH_SIZE;
  if (max_scan == 0) max_scan = 64;
  stackable_linux_aarch64_init_trampoline_result(out, target, (size_t)min_patch_len);
  if (target == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  size_t copied = 0; long unsupported = -1;
  int rc = stackable_linux_aarch64_measure_relocatable_prefix(
      target, (size_t)min_patch_len, (size_t)max_scan, &copied, &unsupported);
  if (rc != STACKABLE_LINUX_PATCH_OK) {
    if (out) { out->diagnostic = rc; out->unsupported_offset = unsupported; }
    return rc;
  }
  size_t total = copied + STACKABLE_AARCH64_PATCH_SIZE;
  long mapped = stackable_linux_aarch64_raw_mmap(NULL, total, PROT_READ | PROT_WRITE,
                                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapped < 0) {
    if (out) { out->diagnostic = STACKABLE_LINUX_PATCH_TRAMPOLINE_ALLOC_FAILED; out->os_errno = (int)(-mapped); }
    return STACKABLE_LINUX_PATCH_TRAMPOLINE_ALLOC_FAILED;
  }
  unsigned char *tramp = (unsigned char *)(uintptr_t)mapped;
  memcpy(tramp, target, copied);
  {
    int reloc_rc = stackable_linux_aarch64_relocate_window(tramp, (uintptr_t)target, (uintptr_t)tramp, copied);
    if (reloc_rc != STACKABLE_LINUX_PATCH_OK) {
      (void)stackable_linux_aarch64_raw_syscall6((long)SYS_munmap, (long)(uintptr_t)tramp, (long)total, 0, 0, 0, 0);
      if (out) out->diagnostic = reloc_rc;
      return reloc_rc;
    }
  }
  stackable_linux_aarch64_write_abs_jump(tramp + copied, (void *)((uintptr_t)target + copied));
  long protect_rc = stackable_linux_aarch64_raw_mprotect((uintptr_t)tramp, total, PROT_READ | PROT_EXEC);
  if (protect_rc < 0) {
    if (out) { out->diagnostic = STACKABLE_LINUX_PATCH_TRAMPOLINE_BUILD_FAILED; out->os_errno = (int)(-protect_rc); }
    return STACKABLE_LINUX_PATCH_TRAMPOLINE_BUILD_FAILED;
  }
  __builtin___clear_cache((char *)tramp, (char *)tramp + total);
  if (out) { out->diagnostic = STACKABLE_LINUX_PATCH_OK; out->entry = (unsigned long)(uintptr_t)tramp; out->copied_len = (unsigned long)copied; }
  return STACKABLE_LINUX_PATCH_OK;
}
""".}

  proc cAarch64PatchAbsoluteJumpTx(target, replacement: pointer; captureRestore: cint;
                                   outResult: ptr CStackableLinuxAarch64PatchResult): cint
    {.importc: "stackable_linux_aarch64_patch_absolute_jump_tx", header: a64Header, cdecl.}
  proc cAarch64MeasureOriginalTrampoline(target: pointer; minPatchLen, maxScan: culong;
                                         outResult: ptr CStackableLinuxAarch64TrampolineResult): cint
    {.importc: "stackable_linux_aarch64_measure_original_trampoline", header: a64Header, cdecl.}
  proc cAarch64BuildOriginalTrampoline(target: pointer; minPatchLen, maxScan: culong;
                                       outResult: ptr CStackableLinuxAarch64TrampolineResult): cint
    {.importc: "stackable_linux_aarch64_build_original_trampoline", header: a64Header, cdecl.}
  proc cAarch64RelocateWindow(tramp: ptr byte; origAddr, trampAddr: culong;
                              copied: culong): cint
    {.importc: "stackable_linux_aarch64_relocate_window", header: a64Header, cdecl.}

proc linuxAarch64PatchAbsoluteJump*(target, replacement: pointer;
    captureRestore: bool; res: var CStackableLinuxAarch64PatchResult): cint =
  ## Body-patch `target` with a 16-byte `ldr x16,#8; br x16; .quad replacement`
  ## absolute jump. Returns 0 on success, `STACKABLE_LINUX_PATCH_*` otherwise.
  ## On unsupported targets returns `-38` (`ENOSYS`).
  when defined(linux) and defined(arm64):
    cAarch64PatchAbsoluteJumpTx(target, replacement, cint(captureRestore), addr res)
  else:
    -38

proc linuxAarch64MeasureTrampoline*(target: pointer; minPatchLen, maxScan: culong;
    res: var CStackableLinuxAarch64TrampolineResult): cint =
  ## Measure how many whole 4-byte instructions of `target`'s prologue must be
  ## relocated for a 16-byte patch. Refuses `svc`/`ret`/`br`/`adr`/`adrp`/`ldr`
  ## (literal). Returns 0 on success; `-38` on unsupported targets.
  when defined(linux) and defined(arm64):
    cAarch64MeasureOriginalTrampoline(target, minPatchLen, maxScan, addr res)
  else:
    -38

proc linuxAarch64BuildTrampoline*(target: pointer; minPatchLen, maxScan: culong;
    res: var CStackableLinuxAarch64TrampolineResult): cint =
  ## Build an original-instruction trampoline (branches rebased) that re-issues
  ## `target`'s overwritten prologue then jumps back past the patch. The entry
  ## point is `res.entry`. Returns 0 on success; `-38` on unsupported targets.
  when defined(linux) and defined(arm64):
    cAarch64BuildOriginalTrampoline(target, minPatchLen, maxScan, addr res)
  else:
    -38

proc linuxAarch64RelocateWindow*(tramp: ptr byte; origAddr, trampAddr: culong;
    copied: culong): cint =
  ## Rebase every relocatable A64 branch in the `copied` bytes at `tramp` (copied
  ## from `origAddr`, now at `trampAddr`) so it reaches the same absolute target.
  ## Exposed for unit-testing the relocation arithmetic. `-38` if unsupported.
  when defined(linux) and defined(arm64):
    cAarch64RelocateWindow(tramp, origAddr, trampAddr, copied)
  else:
    -38
