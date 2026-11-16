/*
 * ct_inline_hook/a64_relocate.c -- see a64_relocate.h for the contract.
 *
 * Encodings: Arm Architecture Reference Manual for A-profile (DDI 0487),
 * C6.2 (B, BL, B.cond, CBZ, CBNZ, TBZ, TBNZ, ADR, ADRP, LDR (literal),
 * LDRSW (literal), PRFM (literal), LDR (immediate), BR, BLR, NOP) and C7.2
 * (LDR (literal, SIMD&FP), LDR (immediate, SIMD&FP)):
 *   https://developer.arm.com/documentation/ddi0487/latest
 */
#include "a64_relocate.h"

#include <string.h>

#define A64_NOP       0xD503201Fu
#define A64_BR_X16    0xD61F0200u
#define A64_BLR_X16   0xD63F0200u
#define A64_X16       16u

static int64_t sext(uint64_t value, unsigned bits)
{
    const uint64_t sign = (uint64_t)1 << (bits - 1);
    value &= (sign << 1) - 1;
    return (int64_t)((value ^ sign) - sign);
}

int ct_a64_b_reaches(uintptr_t from, uintptr_t to)
{
    const int64_t d = (int64_t)to - (int64_t)from;
    return ((from | to) & 3u) == 0 && d >= -CT_A64_B_REACH && d < CT_A64_B_REACH;
}

int ct_a64_encode_b(uintptr_t from, uintptr_t to, uint32_t *out)
{
    if (out == NULL || !ct_a64_b_reaches(from, to)) return -1;
    const int64_t words = ((int64_t)to - (int64_t)from) / 4;
    *out = 0x14000000u | ((uint32_t)words & 0x03FFFFFFu);
    return 0;
}

int ct_a64_decode_b(uint32_t insn, uintptr_t pc, uintptr_t *target)
{
    if ((insn & 0xFC000000u) != 0x14000000u) return 0;
    if (target != NULL)
        *target = (uintptr_t)((int64_t)pc + sext(insn & 0x03FFFFFFu, 26) * 4);
    return 1;
}

void ct_a64_emit_abs_jump(uint32_t out[4], uintptr_t dest)
{
    out[0] = 0x58000040u | A64_X16;          /* LDR X16, #8 */
    out[1] = A64_BR_X16;                      /* BR X16 */
    out[2] = (uint32_t)((uint64_t)dest & 0xFFFFFFFFu);
    out[3] = (uint32_t)((uint64_t)dest >> 32);
}

/* ---- A two-pass emitter: code words, then an aligned literal pool ------- */

#define MAX_CODE 10
#define MAX_LITS 3

typedef struct {
    uint32_t code[MAX_CODE];
    size_t   ncode;
    uint64_t lits[MAX_LITS];
    size_t   nlits;
    /* For each code word: -1, or the literal it loads (an LDR-literal whose
     * imm19 is filled in once the pool's position is known). */
    int      lit_of[MAX_CODE];
    /* For each code word: 0, or 1 when it is a `B` to `branch_to[i]` whose
     * imm26 is filled in at layout. */
    int      is_b[MAX_CODE];
    uintptr_t branch_to[MAX_CODE];
    int      overflow;
} emitter_t;

static void emit(emitter_t *e, uint32_t word)
{
    if (e->ncode >= MAX_CODE) { e->overflow = 1; return; }
    e->lit_of[e->ncode] = -1;
    e->is_b[e->ncode] = 0;
    e->code[e->ncode++] = word;
}

/* LDR <Rt-form> from a pool literal holding `value`. `opc_bits` is the
 * instruction with imm19 = 0 (e.g. 0x58000000 | Rt for LDR Xt). */
static void emit_ldr_literal(emitter_t *e, uint32_t opc_bits, uint64_t value)
{
    if (e->nlits >= MAX_LITS || e->ncode >= MAX_CODE) { e->overflow = 1; return; }
    e->lits[e->nlits] = value;
    emit(e, opc_bits);
    e->lit_of[e->ncode - 1] = (int)e->nlits;
    e->nlits++;
}

static void emit_b(emitter_t *e, uintptr_t to)
{
    emit(e, 0x14000000u);
    if (e->overflow) return;
    e->is_b[e->ncode - 1] = 1;
    e->branch_to[e->ncode - 1] = to;
}

/* Jump to `dest`: a direct B when it will reach (decided at layout), else
 * the X16 absolute form. The choice must be made now, because it changes the
 * code size; `pc` is where this jump will sit. */
static void emit_jump(emitter_t *e, uintptr_t pc, uintptr_t dest)
{
    if (ct_a64_b_reaches(pc, dest)) {
        emit_b(e, dest);
    } else {
        emit_ldr_literal(e, 0x58000000u | A64_X16, (uint64_t)dest);
        emit(e, A64_BR_X16);
    }
}

/* Lay out code at `base`, then the pool 8-byte aligned after it. Returns the
 * number of words written, or a negative error. */
static int layout(emitter_t *e, uintptr_t base, uint32_t *out, size_t out_words)
{
    if (e->overflow) return -1;
    size_t pool_word = e->ncode;
    if (e->nlits > 0 && ((base + pool_word * 4) & 7u) != 0) pool_word++;
    const size_t total = pool_word + e->nlits * 2;
    if (total > out_words) return -1;
    for (size_t i = 0; i < e->ncode; i++) {
        uint32_t word = e->code[i];
        const uintptr_t pc = base + i * 4;
        if (e->lit_of[i] >= 0) {
            const uintptr_t lit = base + (pool_word + (size_t)e->lit_of[i] * 2) * 4;
            const int64_t imm19 = ((int64_t)lit - (int64_t)pc) / 4;
            if (imm19 < -(1 << 18) || imm19 >= (1 << 18)) return -1;
            word |= ((uint32_t)imm19 & 0x7FFFFu) << 5;
        } else if (e->is_b[i]) {
            if (ct_a64_encode_b(pc, e->branch_to[i], &word) != 0) return -3;
        }
        out[i] = word;
    }
    if (pool_word > e->ncode) out[e->ncode] = A64_NOP;
    for (size_t j = 0; j < e->nlits; j++) {
        out[pool_word + j * 2] = (uint32_t)(e->lits[j] & 0xFFFFFFFFu);
        out[pool_word + j * 2 + 1] = (uint32_t)(e->lits[j] >> 32);
    }
    return (int)total;
}

int ct_a64_relocate(uint32_t insn, uintptr_t old_pc, uintptr_t new_pc,
                    uintptr_t resume, uint32_t *out, size_t out_words)
{
    if (out == NULL || ((old_pc | new_pc | resume) & 3u) != 0) return -1;
    emitter_t e;
    memset(&e, 0, sizeof(e));
#define PC_AT(i) (new_pc + (uintptr_t)(i) * 4)

    /* B imm26: an unconditional transfer; nothing follows it. */
    if ((insn & 0xFC000000u) == 0x14000000u) {
        const uintptr_t dest = (uintptr_t)((int64_t)old_pc + sext(insn & 0x03FFFFFFu, 26) * 4);
        emit_jump(&e, PC_AT(0), dest);
        return layout(&e, new_pc, out, out_words);
    }
    /* BL imm26: call, then continue at `resume`. */
    if ((insn & 0xFC000000u) == 0x94000000u) {
        const uintptr_t dest = (uintptr_t)((int64_t)old_pc + sext(insn & 0x03FFFFFFu, 26) * 4);
        if (ct_a64_b_reaches(PC_AT(0), dest)) {
            emit_b(&e, dest);   /* encoded as B by layout(), made a BL below */
        } else {
            emit_ldr_literal(&e, 0x58000000u | A64_X16, (uint64_t)dest);
            emit(&e, A64_BLR_X16);
        }
        emit_b(&e, resume);
        const int n = layout(&e, new_pc, out, out_words);
        if (n > 0 && ct_a64_b_reaches(PC_AT(0), dest) &&
            (out[0] & 0xFC000000u) == 0x14000000u)
            out[0] |= 0x80000000u;              /* B -> BL: set op bit 31 */
        return n;
    }

    /* Conditional branches. `field_shift`/`field_bits` locate the offset;
     * the instruction is re-emitted branching +8 (to the taken path at
     * word 2), word 1 resumes, words 2.. jump to the original target. */
    {
        unsigned shift = 0, bits = 0;
        if ((insn & 0xFF000000u) == 0x54000000u) {          /* B.cond, BC.cond */
            shift = 5; bits = 19;
        } else if ((insn & 0x7E000000u) == 0x34000000u) {   /* CBZ, CBNZ */
            shift = 5; bits = 19;
        } else if ((insn & 0x7E000000u) == 0x36000000u) {   /* TBZ, TBNZ */
            shift = 5; bits = 14;
        }
        if (bits != 0) {
            const uint32_t mask = ((1u << bits) - 1u) << shift;
            const uintptr_t dest = (uintptr_t)((int64_t)old_pc +
                sext((insn & mask) >> shift, bits) * 4);
            emit(&e, (insn & ~mask) | (2u << shift));     /* to word 2 */
            emit_b(&e, resume);                            /* not taken */
            emit_jump(&e, PC_AT(2), dest);                 /* taken */
            return layout(&e, new_pc, out, out_words);
        }
    }

    /* ADR / ADRP Xd: load the address they would have computed. */
    if ((insn & 0x1F000000u) == 0x10000000u) {
        const uint32_t rd = insn & 0x1Fu;
        const uint64_t immlo = (insn >> 29) & 3u;
        const uint64_t immhi = (insn >> 5) & 0x7FFFFu;
        const int64_t imm = sext((immhi << 2) | immlo, 21);
        uint64_t value;
        if (insn & 0x80000000u) {   /* ADRP */
            value = (uint64_t)(((int64_t)old_pc & ~(int64_t)0xFFF) + imm * 4096);
        } else {                     /* ADR */
            value = (uint64_t)((int64_t)old_pc + imm);
        }
        if (rd == 31) {
            /* XZR destination: architecturally a no-op. */
            emit(&e, A64_NOP);
        } else {
            emit_ldr_literal(&e, 0x58000000u | rd, value);
        }
        emit_b(&e, resume);
        return layout(&e, new_pc, out, out_words);
    }

    /* Load-literal family (opc in bits 31:30, V in bit 26, 011x00 in 29:24). */
    if ((insn & 0x3B000000u) == 0x18000000u) {
        const uint32_t rt = insn & 0x1Fu;
        const uint64_t addr = (uint64_t)((int64_t)old_pc +
            sext((insn >> 5) & 0x7FFFFu, 19) * 4);
        const uint32_t opc = insn >> 30;
        const int simd = (insn >> 26) & 1;
        uint32_t load;   /* the [X16] form, unsigned offset 0 */
        if (!simd) {
            switch (opc) {
            case 0: load = 0xB9400000u; break;   /* LDR Wt */
            case 1: load = 0xF9400000u; break;   /* LDR Xt */
            case 2: load = 0xB9800000u; break;   /* LDRSW Xt */
            default:                              /* PRFM: a hint */
                emit(&e, A64_NOP);
                emit_b(&e, resume);
                return layout(&e, new_pc, out, out_words);
            }
        } else {
            switch (opc) {
            case 0: load = 0xBD400000u; break;   /* LDR St */
            case 1: load = 0xFD400000u; break;   /* LDR Dt */
            case 2: load = 0x3DC00000u; break;   /* LDR Qt */
            default: return -2;                   /* unallocated */
            }
        }
        emit_ldr_literal(&e, 0x58000000u | A64_X16, addr);
        emit(&e, load | (A64_X16 << 5) | rt);
        emit_b(&e, resume);
        return layout(&e, new_pc, out, out_words);
    }

    /* Everything else is position-independent. */
    emit(&e, insn);
    emit_b(&e, resume);
    return layout(&e, new_pc, out, out_words);
#undef PC_AT
}
