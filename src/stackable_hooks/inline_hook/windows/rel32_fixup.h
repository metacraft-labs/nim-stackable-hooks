/*
 * ct_inline_hook/rel32_fixup.h
 *
 * x86-64 rel32 / RIP-relative displacement fixup (M50.1).
 *
 * Sits on top of ct_inline_hook/length_decoder.c (M50.0).  When an
 * inline-hook installer copies the first N bytes of a target prologue
 * into a trampoline allocated at a different address, any
 * displacement-bearing instruction in the copied region must have its
 * disp32 rewritten so the trampoline copy reaches the *same absolute
 * target* the original would have.
 *
 * Displacement-bearing instructions detected and fixed up:
 *
 *   E8 disp32        CALL rel32          (1+4 bytes)
 *   E9 disp32        JMP rel32           (1+4 bytes)
 *   0F 8x disp32     Jcc rel32           (2+4 bytes; x = 0..F)
 *   FF 25 disp32     JMP [rip+disp32]    (1+1+4 = 6 bytes, RIP-relative
 *                                         indirect via ModRM mod=00,
 *                                         reg=4, rm=5)
 *   FF 15 disp32     CALL [rip+disp32]   (1+1+4 = 6 bytes, ModRM
 *                                         mod=00, reg=2, rm=5)
 *
 *   Any other instruction whose ModRM encodes the RIP-relative form
 *   (mod=00, rm=101, no SIB).  Per Intel SDM Vol 2 §2.2.1.6 this is
 *   the only way to encode a RIP-relative effective address in 64-bit
 *   mode.  Examples that the corpus exercises:
 *     MOV r, [rip+disp32]    8B /r           (opcode + ModRM + disp32)
 *     LEA r, [rip+disp32]    8D /r
 *     MOV [rip+disp32], r    89 /r
 *     CMP [rip+disp32], imm  81 /7 ... imm   (also carries an immediate)
 *
 * For each detected disp32 the new displacement is:
 *
 *     new_disp = old_disp + (orig_addr - tramp_addr)
 *
 * which is equivalent to Detours' AdjustTarget formula
 * (nNewOffset = nOldOffset - (pbDst - pbSrc)) — disasm.cpp §AdjustTarget
 * around line 535-536.  Verified by the parity test.
 *
 * When the rewritten displacement overflows INT32 (the trampoline is
 * more than ±2 GB from the target the original disp reached), we
 * allocate a small thunk near the trampoline and redirect the
 * displacement to it:
 *
 *   - rel32 (E8/E9/Jcc): 14-byte thunk `FF 25 00 00 00 00 ; .quad <abs>`
 *     The trampoline's rel32 now points to the thunk; the thunk does
 *     an indirect JMP to the original absolute target.
 *
 *   - RIP-rel indirect (FF 25 / FF 15): 8-byte memory slot containing
 *     the absolute slot address.  The trampoline's disp32 now points
 *     to the slot; the indirect dispatch dereferences the slot and
 *     gets the same address it would have via the original disp32.
 *
 *   - RIP-rel data references (MOV/LEA/CMP [rip+disp32], …): if the
 *     displacement overflows we currently return failure.  Callers
 *     fall back to int3 patching or refuse the hook; a dedicated
 *     data-shadow allocator is left for a follow-on milestone.
 *
 * Quality bar (per MCR-Windows-Inline-Hooking.milestones.org §Quality
 * bars #1, #6): no silent truncation, no guessed displacements; the
 * test corpus is at least as wide as Detours' CopyInstruction rel32 +
 * RIP-relative path (parity test).
 */

#ifndef CT_INLINE_HOOK_REL32_FIXUP_H
#define CT_INLINE_HOOK_REL32_FIXUP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Thunk arena -------------------------------------------------- */

/* A 64 KB scratch arena reserved within ±2 GB of a near address.
 *
 * The arena is intentionally minimal in M50.1 — it is per-installation
 * and not shared across hooks.  M50.2 replaces it with a per-page
 * allocator shared with the trampoline allocator.  Keeping the
 * interface stable lets M50.2 swap implementations without touching
 * rel32_fixup.c. */
typedef struct ct_thunk_arena ct_thunk_arena_t;

/* Arena size: 64 KB.  Big enough for hundreds of 14-byte thunks even
 * if every instruction in a 16-byte prologue needed one. */
#define CT_THUNK_ARENA_BYTES (64u * 1024u)

/* Initialise an arena.  `near_addr` is the address the arena should
 * sit within ±2 GB of (typically the trampoline address).  Returns 0
 * on success, <0 on failure (no allocation in the ±2 GB window).
 *
 * The arena is allocated PAGE_EXECUTE_READWRITE so it can also hold
 * code thunks (the rel32 case).  Non-code thunks (the indirect data
 * slot) are happy in any executable+writable allocation.
 *
 * On non-Windows builds this returns -1; rel32_fixup is currently a
 * Windows-only module (see length_decoder.c §VEX/EVEX rejection for
 * the same scoping). */
int ct_thunk_arena_init(ct_thunk_arena_t *arena, uintptr_t near_addr);

/* Release an arena.  Idempotent; safe to call on a zero-initialised
 * arena. */
void ct_thunk_arena_destroy(ct_thunk_arena_t *arena);

/* Arena layout is published only so callers can stack-allocate it.
 * The fields are not part of the stable API and may change in M50.2. */
struct ct_thunk_arena {
    uint8_t  *base;     /* arena start, or NULL if uninitialised */
    size_t    used;     /* bytes consumed from `base` */
    size_t    capacity; /* always CT_THUNK_ARENA_BYTES when initialised */
};

/* ---- Prologue rel32 fixup ----------------------------------------- */

/* Walk `tramp_bytes[0..prologue_len)` (which the caller has already
 * filled with a memcpy of the original prologue bytes), find every
 * displacement-bearing instruction, and rewrite its disp32 so the
 * instruction at `tramp_addr` reaches the same absolute target that
 * `orig_bytes` at `orig_addr` would have reached.
 *
 *   orig_bytes      original prologue bytes (unmodified).  Length-
 *                   decoded to find instruction boundaries.
 *   prologue_len    number of bytes to fix up.  Must match the
 *                   span the caller copied into tramp_bytes.
 *   tramp_bytes     destination buffer (pre-filled).  Modified in
 *                   place.  Must have at least prologue_len writable
 *                   bytes.
 *   orig_addr       runtime address of orig_bytes[0].
 *   tramp_addr      runtime address of tramp_bytes[0].
 *   arena           thunk arena, initialised via
 *                   ct_thunk_arena_init().  Must sit within ±2 GB of
 *                   tramp_addr.
 *
 * Returns 0 on success, <0 on failure.  Failure modes:
 *   -1  length decoder rejected an instruction.
 *   -2  unsupported displacement instruction (RIP-relative ModRM in
 *       a non-FF /4/2 opcode whose new disp32 overflows ±2 GB).
 *   -3  thunk allocation failed (arena exhausted or uninitialised).
 *   -4  internal: instruction shape doesn't match what length
 *       decoder reported (this is a bug; surface it).
 */
int ct_rel32_fixup_prologue(const uint8_t *orig_bytes,
                            size_t prologue_len,
                            uint8_t *tramp_bytes,
                            uintptr_t orig_addr,
                            uintptr_t tramp_addr,
                            ct_thunk_arena_t *arena);

#ifdef __cplusplus
}
#endif

#endif /* CT_INLINE_HOOK_REL32_FIXUP_H */
