/*
 * ct_inline_hook/a64_relocate.h
 *
 * AArch64 instruction relocation and branch encoding for the Windows on Arm64
 * inline-hook backend.
 *
 * Contract: reprobuild-pm spec/Monitor-Hook-Shim.md, "Windows on Arm64 install
 * backend" (approved by Zahary Karadjov, 2026-11-16). The ARM64 install writes
 * ONE instruction at the target -- `B <forwarding stub>` -- so exactly one
 * original instruction is displaced into the trampoline. This module turns
 * that instruction into code that behaves identically at a different address.
 *
 * Instruction encodings follow the Arm Architecture Reference Manual for
 * A-profile (DDI 0487), section C6 "A64 Base Instruction Descriptions":
 *   https://developer.arm.com/documentation/ddi0487/latest
 *
 * Pure encoding: no OS calls, so the module builds and is tested on any host.
 */
#ifndef CT_INLINE_HOOK_A64_RELOCATE_H
#define CT_INLINE_HOOK_A64_RELOCATE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Reach of an unconditional B/BL immediate: +/-128 MB. */
#define CT_A64_B_REACH ((int64_t)128 * 1024 * 1024)

/* Most words ct_a64_relocate writes for one displaced instruction, including
 * the closing branch back to the original code and an 8-byte-aligned
 * literal pool. Callers size their buffers with this. */
#define CT_A64_RELOCATED_MAX_WORDS 16

/* 1 when a `B` placed at `from` can reach `to`. */
int ct_a64_b_reaches(uintptr_t from, uintptr_t to);

/* Encode `B to` placed at `from`. Returns 0 and writes *out, or -1 when out
 * of reach or when either address is not 4-byte aligned. */
int ct_a64_encode_b(uintptr_t from, uintptr_t to, uint32_t *out);

/* Whether `insn` is an unconditional `B` (not BL), and if so its target. */
int ct_a64_decode_b(uint32_t insn, uintptr_t pc, uintptr_t *target);

/* Emit the absolute forwarding stub `LDR X16, #8 ; BR X16 ; .quad dest` into
 * out[0..3]. X16 (IP0) is a scratch register at any function entry
 * (AAPCS64 §6.4.1; Windows ARM64 ABI keeps x16/x17 volatile), so clobbering
 * it before the target function body runs is sound. */
void ct_a64_emit_abs_jump(uint32_t out[4], uintptr_t dest);

/* Relocate the single instruction `insn`, which ran at `old_pc`, so that it
 * behaves identically when executed at `new_pc`, followed by a branch to
 * `resume` (the original `old_pc + 4`). Writes at most
 * CT_A64_RELOCATED_MAX_WORDS words to `out` and returns how many, or a
 * negative value:
 *   -1  invalid argument (misaligned address, NULL, too small a buffer)
 *   -2  the instruction cannot be relocated (a PC-relative form this module
 *       does not rewrite); the caller must not hook the target
 *   -3  `resume` is out of direct-branch reach of the relocated code
 *
 * PC-relative forms rewritten: B, BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, ADR, ADRP,
 * and the LDR-literal family (LDR W/X/S/D/Q, LDRSW, PRFM). Every other
 * instruction is position-independent and is copied verbatim. */
int ct_a64_relocate(uint32_t insn, uintptr_t old_pc, uintptr_t new_pc,
                    uintptr_t resume, uint32_t *out, size_t out_words);

#ifdef __cplusplus
}
#endif

#endif /* CT_INLINE_HOOK_A64_RELOCATE_H */
