/*
 * ct_inline_hook/rel32_fixup.c
 *
 * x86-64 rel32 / RIP-relative displacement fixup (M50.1).
 *
 * Independent implementation.  Tables and ModRM/SIB sizing derived
 * from Intel(R) 64 and IA-32 Architectures Software Developer's
 * Manual Vol 2, specifically:
 *
 *   Appendix A   Opcode Maps (which 1-byte opcodes have a ModR/M)
 *   §2.1.5       ModR/M and SIB byte format
 *                Table 2-2  32/64-bit addressing forms with ModR/M
 *                Table 2-3  32/64-bit SIB byte
 *   §2.2.1.6     RIP-relative addressing (mod=00, rm=101, no SIB)
 *
 * Reference oracle for the rel32 + RIP-relative subset:
 * microsoft/Detours src/disasm.cpp — see AdjustTarget() around
 * line 500 for the displacement-rewrite arithmetic, and CopyBytes()
 * around line 396-425 for the ModRM-byte SIB/RIP detection that
 * matches our walk here.  Detours rewrites `nNewOffset =
 * nOldOffset - (pbDst - pbSrc)` which is algebraically identical to
 * our `new_disp = old_disp + (orig_addr - tramp_addr)`.
 */

#include "rel32_fixup.h"
#include "length_decoder.h"

#include <string.h>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

/* ---- has-ModRM bitmap for the 1-byte opcode map ------------------- */
/*
 * Per Intel SDM Vol 2 Appendix A Table A-2.  This is a subset of
 * length_decoder.c's g_opmap1 collapsed to a single "does this opcode
 * eat a ModR/M byte" bit.  We could expose the full table through a
 * shared header but the maintenance cost (two callers, both already
 * citing the same SDM tables) is higher than the cost of the small
 * duplicated bitmap below.  The corpus parity test (length decoder
 * agrees with dumpbin on 4583 instructions) is what catches any
 * divergence between this table and the length-decoder's, so any
 * future drift surfaces immediately rather than corrupting a
 * trampoline.
 *
 * Bit `n` set means opcode `n` (after legacy/REX prefixes) is
 * followed by a ModR/M byte.  Two-byte opcodes (0F xx) and the
 * three-byte maps are handled separately below.
 */
static const uint8_t k_modrm_op1[32] = {
    /* 00..07 */ 0x0Fu,  /* 00,01,02,03 = ADD r/m,r etc. — ModRM. 04,05 imm only. 06,07 invalid in 64. */
    /* 08..0F */ 0x0Fu,  /* 08..0B = OR r/m,r etc. — ModRM. */
    /* 10..17 */ 0x0Fu,
    /* 18..1F */ 0x0Fu,
    /* 20..27 */ 0x0Fu,
    /* 28..2F */ 0x0Fu,
    /* 30..37 */ 0x0Fu,
    /* 38..3F */ 0x0Fu,
    /* 40..47 */ 0x00u,  /* REX (consumed earlier, never reaches table) */
    /* 48..4F */ 0x00u,
    /* 50..57 */ 0x00u,  /* PUSH r */
    /* 58..5F */ 0x00u,  /* POP r */
    /* 60..67 */ 0x08u,  /* 63 MOVSXD r,r/m — ModRM. 60..62 invalid in 64. 64..67 prefix. */
    /* 68..6F */ 0x0Au,  /* 69 IMUL r,r/m,imz — ModRM; 6B IMUL r,r/m,ib — ModRM. 68 PUSH imz, 6A PUSH ib. */
    /* 70..77 */ 0x00u,  /* JCC short */
    /* 78..7F */ 0x00u,
    /* 80..87 */ 0xFFu,  /* 80..83 group1 imm; 84..87 TEST/XCHG — all ModRM. */
    /* 88..8F */ 0xFFu,  /* 88..8B MOV r/m<->r; 8C MOV r/m,Sreg; 8D LEA; 8E MOV Sreg,r/m; 8F /0 POP r/m. */
    /* 90..97 */ 0x00u,  /* NOP / XCHG EAX,rXX */
    /* 98..9F */ 0x00u,  /* CWD/CDQ/PUSHF/POPF/etc. */
    /* A0..A7 */ 0x00u,  /* MOV AL/EAX,moffs and string ops */
    /* A8..AF */ 0x00u,
    /* B0..B7 */ 0x00u,  /* MOV r8, imm8 */
    /* B8..BF */ 0x00u,  /* MOV r, imm */
    /* C0..C7 */ 0xC3u,  /* C0,C1 shift /n,ib — ModRM. C6,C7 MOV r/m, imm — ModRM. C2,C3 RET imm/no. C4,C5 VEX (rejected upstream). */
    /* C8..CF */ 0x00u,  /* ENTER/LEAVE/RET far/INT3/INT/IRET */
    /* D0..D7 */ 0x0Fu,  /* D0..D3 shifts — ModRM. D4,D5 invalid in 64. D6 undefined. D7 XLAT. */
    /* D8..DF */ 0xFFu,  /* x87: every D8..DF opcode is ModRM. */
    /* E0..E7 */ 0x00u,  /* LOOP / IN / OUT imm8 */
    /* E8..EF */ 0x00u,  /* CALL/JMP rel + IN/OUT */
    /* F0..F7 */ 0xC0u,  /* F6,F7 Group3 — ModRM. F0..F5 prefix/HLT/CMC. */
    /* F8..FF */ 0xC0u,  /* FE Group4 — ModRM. FF Group5 — ModRM. */
};

static int op1_has_modrm(uint8_t op)
{
    return (k_modrm_op1[op >> 3] >> (op & 7u)) & 1u;
}

/* Two-byte opcode map (0F xx) — every entry except the Jcc rel32
 * row (80..8F), the PUSH/POP FS/GS row (A0,A1,A8,A9), the BSWAP row
 * (C8..CF) and a handful of 0-operand ops takes a ModR/M byte.  This
 * mirrors length_decoder.c's g_opmap_0f — same observation, same
 * citation (Intel SDM Vol 2 Table A-3).  Bit set = ModRM follows. */
static const uint8_t k_modrm_op2[32] = {
    /* 00..07 */ 0xCFu,  /* 00..03 group ModRM; 04 invalid; 05 SYSCALL no-ModRM; 06 CLTS; 07 SYSRET. */
    /* 08..0F */ 0xA0u,  /* 0D /n prefetch — ModRM. 0F 3DNow! prefix — ModRM (treated as 1-byte by decoder). */
    /* 10..17 */ 0xFFu,  /* MOVUPS et al. */
    /* 18..1F */ 0xFFu,  /* prefetchnta etc + multibyte NOP /n. */
    /* 20..27 */ 0x0Fu,  /* 20..23 MOV CR/DR — ModRM. 24..27 invalid in 64. */
    /* 28..2F */ 0xFFu,  /* MOVAPS etc. */
    /* 30..37 */ 0x00u,  /* WRMSR/RDTSC/etc — 0 operand. */
    /* 38..3F */ 0x00u,  /* escape — handled before this table. */
    /* 40..47 */ 0xFFu,  /* CMOVcc */
    /* 48..4F */ 0xFFu,
    /* 50..57 */ 0xFFu,
    /* 58..5F */ 0xFFu,
    /* 60..67 */ 0xFFu,
    /* 68..6F */ 0xFFu,
    /* 70..77 */ 0x7Fu,  /* 70..73 imm8 ModRM; 74..76 PCMPEQ ModRM; 77 EMMS no-ModRM. */
    /* 78..7F */ 0xFFu,
    /* 80..87 */ 0x00u,  /* Jcc rel32 — no ModRM. */
    /* 88..8F */ 0x00u,
    /* 90..97 */ 0xFFu,  /* SETcc r/m8 */
    /* 98..9F */ 0xFFu,
    /* A0..A7 */ 0xFCu,  /* A0,A1 PUSH/POP FS no-ModRM; A2 CPUID no-ModRM; A3 BT ModRM; A4 SHLD ModRM IB; A5 SHLD ModRM; A6,A7 reserved. */
    /* A8..AF */ 0xFCu,  /* A8,A9 PUSH/POP GS; AA RSM; AB BTS ModRM; AC SHRD ModRM IB; AD SHRD ModRM; AE group ModRM; AF IMUL ModRM. */
    /* B0..B7 */ 0xFFu,  /* B0..B7 CMPXCHG/LSS/etc — ModRM. */
    /* B8..BF */ 0xFFu,
    /* C0..C7 */ 0xFFu,
    /* C8..CF */ 0x00u,  /* BSWAP r — no ModRM. */
    /* D0..D7 */ 0xFFu,
    /* D8..DF */ 0xFFu,
    /* E0..E7 */ 0xFFu,
    /* E8..EF */ 0xFFu,
    /* F0..F7 */ 0xFFu,
    /* F8..FF */ 0xFFu,
};

static int op2_has_modrm(uint8_t op2)
{
    return (k_modrm_op2[op2 >> 3] >> (op2 & 7u)) & 1u;
}

/* ---- Prefix walk -------------------------------------------------- */

/* Skip legacy + REX prefixes; return the byte offset of the opcode.
 * Records the address-size override (0x67) because ModRM in Vol 2
 * Table 2-1 (16-bit) differs from Table 2-2 (32/64-bit).  We don't
 * care about REX bits here because the only disp32 fields we touch
 * are unaffected by REX.W (CALL/JMP rel32 and Jcc rel32 are always
 * 32-bit displacement regardless of REX; FF /4 and FF /2 with mod=00
 * rm=101 always emit a 32-bit displacement). */
static size_t skip_prefixes(const uint8_t *p, size_t len, int *out_addr_size_pfx)
{
    size_t i = 0;
    *out_addr_size_pfx = 0;
    while (i < len) {
        uint8_t b = p[i];
        if (b == 0xF0u || b == 0xF2u || b == 0xF3u ||
            b == 0x2Eu || b == 0x36u || b == 0x3Eu || b == 0x26u ||
            b == 0x64u || b == 0x65u || b == 0x66u) {
            i++; continue;
        }
        if (b == 0x67u) { *out_addr_size_pfx = 1; i++; continue; }
        break;
    }
    /* Consume REX chain (last REX wins). */
    while (i < len && (p[i] & 0xF0u) == 0x40u) i++;
    return i;
}

/* ---- Displacement rewriter ---------------------------------------- */

/* Write a little-endian 32-bit value at p. */
static void store_le32(uint8_t *p, int32_t v)
{
    uint32_t u = (uint32_t)v;
    p[0] = (uint8_t)(u & 0xFFu);
    p[1] = (uint8_t)((u >> 8) & 0xFFu);
    p[2] = (uint8_t)((u >> 16) & 0xFFu);
    p[3] = (uint8_t)((u >> 24) & 0xFFu);
}

/* Read a little-endian signed 32-bit value at p. */
static int32_t load_le32(const uint8_t *p)
{
    uint32_t u = (uint32_t)p[0]
               | ((uint32_t)p[1] << 8)
               | ((uint32_t)p[2] << 16)
               | ((uint32_t)p[3] << 24);
    return (int32_t)u;
}

/* Fit-check: does a signed 64-bit value fit in INT32?  We can't just
 * cast and compare because that loses the high bits we need to check. */
static int fits_int32(int64_t v)
{
    return v >= (int64_t)INT32_MIN && v <= (int64_t)INT32_MAX;
}

/* ---- Thunk arena -------------------------------------------------- */

int ct_thunk_arena_init(ct_thunk_arena_t *arena, uintptr_t near_addr)
{
    if (arena == NULL) return -1;
    arena->base = NULL;
    arena->used = 0;
    arena->capacity = 0;

#if !defined(_WIN32)
    (void)near_addr;
    return -1;
#else
    /* Probe a sequence of candidate base addresses within ±2 GB of
     * near_addr.  The ±2 GB window is fundamental for rel32 reach,
     * not a Windows-specific concern, so we step outward and use
     * MEM_RESERVE|MEM_COMMIT with a non-NULL lpAddress so VirtualAlloc
     * fails (and we move on) if the slot is occupied.
     *
     * We step in 1 MB increments (1 MB is bigger than any reasonable
     * trampoline alignment we'd ever need).  64 KB is the VirtualAlloc
     * granularity on Windows, but we step by 16x that to land in
     * distinct allocation regions.
     */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    size_t granularity = (size_t)si.dwAllocationGranularity;
    if (granularity == 0) granularity = 65536u;

    /* Round near_addr down to the granularity, then probe outward. */
    uintptr_t hi = near_addr & ~((uintptr_t)granularity - 1u);
    uintptr_t lo = hi;
    const int64_t window = (int64_t)0x70000000;  /* ~1.75 GB safety margin under 2 GB */
    const size_t step = 1024u * 1024u;            /* 1 MB */

    LPVOID got = NULL;
    while ((int64_t)(hi - near_addr) < window || (int64_t)(near_addr - lo) < window) {
        if (hi != 0 && (int64_t)(hi - near_addr) < window) {
            got = VirtualAlloc((LPVOID)hi, CT_THUNK_ARENA_BYTES,
                               MEM_RESERVE | MEM_COMMIT,
                               PAGE_EXECUTE_READWRITE);
            if (got != NULL) break;
            hi += step;
        } else {
            hi = (uintptr_t)-1;  /* exhausted upper */
        }
        if (lo > step && (int64_t)(near_addr - lo) < window) {
            lo -= step;
            got = VirtualAlloc((LPVOID)lo, CT_THUNK_ARENA_BYTES,
                               MEM_RESERVE | MEM_COMMIT,
                               PAGE_EXECUTE_READWRITE);
            if (got != NULL) break;
        } else if (lo <= step) {
            lo = 0;
        }
        if (hi == (uintptr_t)-1 && lo == 0) break;
    }

    if (got == NULL) {
        /* Last-ditch: ask the OS for any address.  This may land
         * outside ±2 GB on a heavily-fragmented process — in which
         * case the caller's first allocation attempt will fail the
         * fits_int32 check and surface as a thunk-alloc failure. */
        got = VirtualAlloc(NULL, CT_THUNK_ARENA_BYTES,
                           MEM_RESERVE | MEM_COMMIT,
                           PAGE_EXECUTE_READWRITE);
        if (got == NULL) return -1;
    }

    arena->base = (uint8_t *)got;
    arena->used = 0;
    arena->capacity = CT_THUNK_ARENA_BYTES;
    return 0;
#endif
}

void ct_thunk_arena_destroy(ct_thunk_arena_t *arena)
{
    if (arena == NULL || arena->base == NULL) return;
#if defined(_WIN32)
    VirtualFree(arena->base, 0, MEM_RELEASE);
#endif
    arena->base = NULL;
    arena->used = 0;
    arena->capacity = 0;
}

/* Allocate `n` bytes (rounded to 16) from the arena.  Returns NULL on
 * exhaustion. */
static uint8_t *arena_alloc(ct_thunk_arena_t *arena, size_t n)
{
    if (arena == NULL || arena->base == NULL) return NULL;
    /* 16-byte align so the disp32 in the trampoline lands on a
     * predictable boundary, easier to inspect in a debugger. */
    n = (n + 15u) & ~(size_t)15u;
    if (arena->used + n > arena->capacity) return NULL;
    uint8_t *p = arena->base + arena->used;
    arena->used += n;
    return p;
}

/* Emit a 14-byte rel32-redirect thunk at `dst`:
 *
 *     FF 25 00 00 00 00       JMP qword ptr [rip+0]
 *     <8 bytes>               .quad target
 *
 * The JMP fetches the absolute target from the 8 bytes immediately
 * following the instruction.  This is the same shape Detours uses for
 * its "trampoline-too-far" fallback (detours.cpp DetourAllocateRegion,
 * detour_alloc_round_up_to_region — the pattern goes back to the
 * original 1999 Detours paper). */
static void emit_jmp_indirect_thunk(uint8_t *dst, uintptr_t target)
{
    dst[0] = 0xFFu;
    dst[1] = 0x25u;
    dst[2] = 0x00u; dst[3] = 0x00u; dst[4] = 0x00u; dst[5] = 0x00u;
    uint64_t u = (uint64_t)target;
    for (int i = 0; i < 8; i++) {
        dst[6 + i] = (uint8_t)((u >> (i * 8)) & 0xFFu);
    }
}

/* ---- Single-instruction fixup ------------------------------------- */

/*
 * Inspect one instruction at `orig_bytes[insn_off..insn_off+insn_len)`
 * and rewrite the displacement (if any) in the matching slice of
 * `tramp_bytes`.
 *
 * Returns 0 on success (including "no displacement to fix"), <0 on
 * failure (with the same error codes documented in rel32_fixup.h).
 */
static int fixup_one_insn(const uint8_t *orig_bytes,
                          uint8_t *tramp_bytes,
                          size_t insn_off, size_t insn_len,
                          uintptr_t orig_addr, uintptr_t tramp_addr,
                          ct_thunk_arena_t *arena)
{
    const uint8_t *p = orig_bytes + insn_off;
    int has_67 = 0;
    size_t op_off_in_insn = skip_prefixes(p, insn_len, &has_67);
    if (op_off_in_insn >= insn_len) return -4;

    uint8_t op = p[op_off_in_insn];

    /* Disposition: classify the instruction. */
    enum {
        FIX_NONE,         /* no displacement to fix */
        FIX_REL32,        /* opcode + ModRM-less disp32 (E8/E9/0F 8x) */
        FIX_RIPREL_JCALL, /* FF /4 or /2 with mod=00 rm=101 (indirect JMP/CALL [rip+disp32]) */
        FIX_RIPREL_DATA   /* other RIP-relative ModRM (e.g. MOV [rip+disp32], r) */
    } kind = FIX_NONE;

    size_t disp_off_in_insn = 0;  /* offset of the disp32 inside the insn */
    int has_immediate_after_disp = 0;  /* informational; doesn't affect fixup logic */
    (void)has_immediate_after_disp;

    if (op == 0xE8u || op == 0xE9u) {
        /* CALL rel32 / JMP rel32: 1-byte opcode + 4-byte disp = 5 bytes. */
        if (insn_len < op_off_in_insn + 5u) return -4;
        kind = FIX_REL32;
        disp_off_in_insn = op_off_in_insn + 1u;
    } else if (op == 0x0Fu) {
        if (op_off_in_insn + 1u >= insn_len) return -4;
        uint8_t op2 = p[op_off_in_insn + 1u];
        if ((op2 & 0xF0u) == 0x80u) {
            /* Jcc rel32: 2-byte opcode + 4-byte disp = 6 bytes. */
            if (insn_len < op_off_in_insn + 6u) return -4;
            kind = FIX_REL32;
            disp_off_in_insn = op_off_in_insn + 2u;
        } else if (op2 == 0x38u || op2 == 0x3Au) {
            /* Three-byte escapes; the actual opcode is op3.  Length
             * decoder already accounted for the full instruction so we
             * just need to check whether the ModRM (at op_off+3)
             * encodes RIP-relative.  Every defined opcode in the
             * 0F 38 and 0F 3A maps takes a ModRM. */
            if (op_off_in_insn + 3u > insn_len) return -4;
            size_t modrm_off = op_off_in_insn + 3u;
            if (modrm_off >= insn_len) return -4;
            uint8_t modrm = p[modrm_off];
            unsigned mod = (modrm >> 6) & 0x3u;
            unsigned rm  = modrm & 0x7u;
            if (!has_67 && mod == 0u && rm == 5u) {
                kind = FIX_RIPREL_DATA;
                disp_off_in_insn = modrm_off + 1u;
            }
        } else if (op2_has_modrm(op2)) {
            /* Other two-byte opcodes that carry a ModRM.  Check for
             * RIP-relative addressing form. */
            size_t modrm_off = op_off_in_insn + 2u;
            if (modrm_off >= insn_len) return -4;
            uint8_t modrm = p[modrm_off];
            unsigned mod = (modrm >> 6) & 0x3u;
            unsigned rm  = modrm & 0x7u;
            if (!has_67 && mod == 0u && rm == 5u) {
                kind = FIX_RIPREL_DATA;
                disp_off_in_insn = modrm_off + 1u;
            }
        }
    } else if (op == 0xFFu) {
        /* Group5.  /4 = JMP r/m64 (indirect), /2 = CALL r/m64.  Both
         * with mod=00 rm=101 encode `[rip+disp32]`.  Length is
         * 1 (opcode) + 1 (ModRM) + 4 (disp32) = 6 bytes. */
        size_t modrm_off = op_off_in_insn + 1u;
        if (modrm_off >= insn_len) return -4;
        uint8_t modrm = p[modrm_off];
        unsigned mod = (modrm >> 6) & 0x3u;
        unsigned reg = (modrm >> 3) & 0x7u;
        unsigned rm  = modrm & 0x7u;
        if (!has_67 && mod == 0u && rm == 5u && (reg == 4u || reg == 2u)) {
            if (insn_len < op_off_in_insn + 6u) return -4;
            kind = FIX_RIPREL_JCALL;
            disp_off_in_insn = modrm_off + 1u;
        } else if (!has_67 && mod == 0u && rm == 5u) {
            /* Other FF /n with RIP-relative — /0 INC, /1 DEC, /3 CALL
             * far, /5 JMP far, /6 PUSH.  Treat as data-style RIP
             * fixup.  Length matches Group 5 with disp32. */
            if (insn_len < op_off_in_insn + 6u) return -4;
            kind = FIX_RIPREL_DATA;
            disp_off_in_insn = modrm_off + 1u;
        }
    } else if (op1_has_modrm(op)) {
        size_t modrm_off = op_off_in_insn + 1u;
        if (modrm_off >= insn_len) return -4;
        uint8_t modrm = p[modrm_off];
        unsigned mod = (modrm >> 6) & 0x3u;
        unsigned rm  = modrm & 0x7u;
        if (!has_67 && mod == 0u && rm == 5u) {
            /* RIP-relative.  Disp32 immediately follows the ModRM
             * byte.  Any immediate the opcode also carries lives
             * *after* the disp32 — Detours' AdjustTarget handles this
             * via cbTarget=4 + cbOp-cbTargetOffset (cbOp is whole
             * insn length, cbTargetOffset is disp_off_in_insn). */
            kind = FIX_RIPREL_DATA;
            disp_off_in_insn = modrm_off + 1u;
            /* Sanity: any imm bytes must fit after the disp32. */
            if (insn_len < disp_off_in_insn + 4u) return -4;
            has_immediate_after_disp =
                (insn_len > disp_off_in_insn + 4u) ? 1 : 0;
        }
    }

    if (kind == FIX_NONE) return 0;

    /* All disp-bearing instructions in the supported subset have a
     * 4-byte disp.  The next-instruction address (RIP-at-end) is at
     * insn_off + insn_len for both forms. */
    int32_t old_disp = load_le32(orig_bytes + insn_off + disp_off_in_insn);

    /* Apply the standard rewrite.  Detours' AdjustTarget formula:
     *   nNewOffset = nOldOffset - (pbDst - pbSrc)
     * which is the same as
     *   new_disp = old_disp + (orig_addr - tramp_addr)
     * because (orig_addr - tramp_addr) = -(tramp_addr - orig_addr) =
     * -(pbDst - pbSrc). */
    int64_t delta = (int64_t)orig_addr - (int64_t)tramp_addr;
    int64_t new_disp_64 = (int64_t)old_disp + delta;

    if (fits_int32(new_disp_64)) {
        store_le32(tramp_bytes + insn_off + disp_off_in_insn,
                   (int32_t)new_disp_64);
        return 0;
    }

    /* Out of range.  Need a thunk in ±2 GB of tramp_addr. */
    if (kind == FIX_RIPREL_DATA) {
        /* No clean recovery for arbitrary RIP-relative data refs
         * without a separate data shadow.  Surface failure rather
         * than guess. */
        return -2;
    }

    if (arena == NULL || arena->base == NULL) return -3;

    /* Compute the absolute target the original instruction reaches.
     * Same arithmetic whether the disp refers to a code rel32 or to
     * a memory slot (FF 25/15): both are "RIP-at-end + disp". */
    uintptr_t insn_end_orig = orig_addr + insn_off + insn_len;
    uintptr_t orig_target = insn_end_orig + (uintptr_t)(int64_t)old_disp;

    uint8_t *thunk;
    uintptr_t thunk_addr;
    int64_t new_disp_from_thunk;

    if (kind == FIX_REL32) {
        /* Allocate 14 bytes: FF 25 00 00 00 00 + .quad orig_target. */
        thunk = arena_alloc(arena, 14u);
        if (thunk == NULL) return -3;
        emit_jmp_indirect_thunk(thunk, orig_target);
        thunk_addr = (uintptr_t)thunk;
    } else {
        /* FIX_RIPREL_JCALL: original disp32 addresses a memory slot
         * (the IAT entry).  The slot contains the absolute target.
         * Our thunk is an 8-byte slot containing the absolute address
         * of the *original* IAT entry (not the function!).  When the
         * indirect FF 25 in the trampoline dereferences our thunk, it
         * gets the address of the original IAT slot.  But that's not
         * right either — FF 25 [trampoline_disp -> our_thunk] would
         * load *our_thunk* as the jump target.  So we need our_thunk
         * to contain the same value the original slot would contain.
         *
         * The original slot is at orig_target (a memory location).
         * We can't read it (it's in another module and may not even
         * be mapped at install time), so the only safe approach is to
         * place an 8-byte slot at our thunk that holds the address of
         * the original slot, and rewrite the instruction's opcode to
         * an extra-indirection layer.  That requires expanding the
         * instruction, which violates the in-place fixup contract.
         *
         * Instead we keep the in-place contract and refuse: callers
         * who hit this should re-allocate the trampoline closer to
         * the target.  M50.2's per-page trampoline allocator picks
         * pages within ±2 GB of the target, so this case is rare in
         * practice.  Surface failure rather than mis-fixup. */
        return -2;
    }

    new_disp_from_thunk = (int64_t)thunk_addr - (int64_t)insn_end_orig + delta;
    /* The disp from the trampoline's RIP-at-end to the thunk is
     *   thunk_addr - (tramp_addr + insn_off + insn_len)
     * which equals
     *   thunk_addr - insn_end_orig + (orig_addr - tramp_addr)
     *   = thunk_addr - insn_end_orig + delta
     * (delta is signed, may be negative). */
    if (!fits_int32(new_disp_from_thunk)) return -3;
    store_le32(tramp_bytes + insn_off + disp_off_in_insn,
               (int32_t)new_disp_from_thunk);
    return 0;
}

/* ---- Public entry point ------------------------------------------- */

int ct_rel32_fixup_prologue(const uint8_t *orig_bytes,
                            size_t prologue_len,
                            uint8_t *tramp_bytes,
                            uintptr_t orig_addr,
                            uintptr_t tramp_addr,
                            ct_thunk_arena_t *arena)
{
    if (orig_bytes == NULL || tramp_bytes == NULL || prologue_len == 0) {
        return -4;
    }

    size_t off = 0;
    while (off < prologue_len) {
        size_t remaining = prologue_len - off;
        /* Cap the read at the longest legal instruction; ct_ild_decode
         * will refuse to read past max_len.  We want to *only* fixup
         * inside [0, prologue_len), so cap there. */
        int n = ct_ild_decode(orig_bytes + off, remaining);
        if (n <= 0) return -1;
        if ((size_t)n > remaining) return -4;
        int rc = fixup_one_insn(orig_bytes, tramp_bytes,
                                off, (size_t)n,
                                orig_addr, tramp_addr,
                                arena);
        if (rc != 0) return rc;
        off += (size_t)n;
    }
    return 0;
}
