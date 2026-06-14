/*
 * ct_inline_hook/length_decoder.h
 *
 * x86-64 instruction length decoder (M50.0).
 *
 * Used by the Windows inline-hook backend to walk forward enough
 * instruction boundaries to cover an N-byte prologue overwrite (default
 * 5 bytes for `JMP rel32`, 14 bytes for `JMP [rip+0]; .quad target`).
 *
 * The decoder is *length-only*: it returns how many bytes the instruction
 * at `code` consumes, without producing any semantic decode (no operand
 * extraction, no flags inspection). This keeps the tables small and the
 * fast path predictable for the prologue-copy use case.
 *
 * Tables are derived from Intel SDM Vol 2 Appendix A (Opcode Maps).
 * See length_decoder.c for citations on each table entry.
 *
 * Returns 0 (NOT a guessed length) when the opcode is outside the
 * supported subset. Callers must treat 0 as a fallback signal --
 * typically falling back to int3 patching or refusing to install the
 * hook on that target. Returning a guessed length is a correctness bug:
 * the trampoline would copy a wrong number of bytes and either crash on
 * resume or, worse, execute past the intended boundary.
 */

#ifndef CT_INLINE_HOOK_LENGTH_DECODER_H
#define CT_INLINE_HOOK_LENGTH_DECODER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum legal x86-64 instruction length per Intel SDM Vol 2 §2.3.11.
 * Decoder caps reads at this number even if max_len is larger. */
#define CT_ILD_MAX_INSN_LEN 15

/*
 * ct_ild_decode -- return the byte length of the instruction at `code`.
 *
 *   code     pointer to the first byte of a candidate instruction.
 *   max_len  upper bound on bytes available at `code`. The decoder
 *            will never read past this; if a complete instruction does
 *            not fit, it returns 0.
 *
 * Return value:
 *   1..15    decoded length in bytes.
 *   0        opcode outside the supported subset OR not enough bytes
 *            available OR encoding rejected as illegal (the caller
 *            must treat both equivalently as "fall back to int3").
 */
int ct_ild_decode(const unsigned char *code, size_t max_len);

/*
 * ct_ild_decode_to_cover -- walk forward instruction-by-instruction at
 * `code` until at least `target_bytes` bytes are covered, return the
 * total covered count.
 *
 *   code          pointer to the first byte of the prologue.
 *   target_bytes  minimum number of bytes the caller needs to
 *                 overwrite atomically (typically 5 or 14).
 *   max_len       upper bound on bytes available at `code`.
 *
 * Return value:
 *   >= target_bytes  total bytes spanned by complete instructions.
 *   0                a decode failed before reaching target_bytes
 *                    (caller falls back to int3 patching).
 */
int ct_ild_decode_to_cover(const unsigned char *code, size_t target_bytes,
                           size_t max_len);

#ifdef __cplusplus
}
#endif

#endif /* CT_INLINE_HOOK_LENGTH_DECODER_H */
