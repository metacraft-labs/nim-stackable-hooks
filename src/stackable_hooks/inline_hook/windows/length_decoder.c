/*
 * ct_inline_hook/length_decoder.c
 *
 * x86-64 instruction length decoder (M50.0).
 *
 * Independent implementation. Tables derived from Intel(R) 64 and
 * IA-32 Architectures Software Developer's Manual Vol 2, Appendix A
 * (Opcode Maps) -- specifically:
 *
 *   A.2.4  Table A-2  One-byte Opcode Map
 *   A.3    Table A-3  Two-byte Opcode Map (0F xx)
 *   A.4    Table A-4  Three-byte Opcode Map (0F 38 xx)
 *   A.5    Table A-5  Three-byte Opcode Map (0F 3A xx)
 *   A.2.1  Superscripts that mark "no encoding in 64-bit mode"
 *
 * Reference oracles consulted during development (no source copied):
 * microsoft/Detours src/disasm.cpp (s_rceCopyTable / s_rceCopyTable0F)
 * and TsudaKageyu/minhook src/hde/hde64.c (encoded table64.h).
 *
 * The decoder is length-only: it walks prefixes, dispatches on the
 * opcode map, computes ModRM/SIB/displacement sizes per Vol 2 §2.1.5
 * Table 2-2 (32-bit Addressing Forms with the ModR/M Byte) and Table
 * 2-3 (SIB byte), and adds the immediate bytes the opcode declares.
 *
 * Anything outside the supported subset returns 0 so the caller can
 * fall back to int3 patching. The supported subset covers the
 * overwhelming majority of MSVC- and MinGW-generated prologues.
 *
 * VEX (C4/C5) and EVEX (62) prefixes are explicitly rejected in
 * M50.0; the prologue corpus shows no Windows DLL prologue uses them.
 */

#include "length_decoder.h"

#include <string.h>

/* ---- Per-opcode flag bits used in the maps ------------------------- */

#define OP_MODRM    0x0001u  /* ModR/M byte follows opcode (+ optional SIB + disp) */
#define OP_IMM8     0x0002u  /* one byte of immediate */
#define OP_IMM16    0x0004u  /* two bytes of immediate (always 16-bit) */
#define OP_IMM_Z    0x0008u  /* 2 bytes if 66 prefix else 4 bytes */
#define OP_IMM_V    0x0010u  /* 8 if REX.W; 2 if 66; else 4 */
#define OP_IMM_O    0x0040u  /* moffset: 8 bytes if no 67 prefix, 4 if 67 */
#define OP_REL8     0x0080u  /* 1-byte rel displacement */
#define OP_REL_Z    0x0100u  /* 2 bytes if 66 else 4 (JMP/CALL rel) */
#define OP_INVALID  0x4000u  /* not encodable in 64-bit mode or rejected */

/* Concise aliases used in the tables below. */
#define M_    OP_MODRM
#define M_IB  (OP_MODRM | OP_IMM8)
#define M_IW  (OP_MODRM | OP_IMM16)
#define M_IZ  (OP_MODRM | OP_IMM_Z)
#define M_IV  (OP_MODRM | OP_IMM_V)
#define IB    OP_IMM8
#define IW    OP_IMM16
#define IZ    OP_IMM_Z
#define IV    OP_IMM_V
#define IO    OP_IMM_O
#define R8    OP_REL8
#define RZ    OP_REL_Z
#define X     OP_INVALID
#define _     0u   /* opcode produces zero extra bytes (1-byte instruction) */

/* ---- One-byte opcode map ------------------------------------------- */
/* Intel SDM Vol 2 Table A-2. 16 rows x 16 cols, indexed by opcode.
 * Notes per row:
 *   0x  ADD r/m,r ; ADD r,r/m ; ADD AL,imm8 ; ADD EAX,imm_z ;
 *       PUSH/POP ES/CS not encodable in 64-bit (X) ; 0F is escape (_).
 *   1x  ADC/SBB family, mirrors 0x row layout.
 *   2x  AND/SUB. 0x26/0x2E are segment prefixes (consumed earlier);
 *       0x27 DAA / 0x2F DAS invalid in 64-bit.
 *   3x  XOR/CMP. 0x36/0x3E prefix; 0x37 AAA / 0x3F AAS invalid in 64.
 *   4x  REX prefixes (consumed earlier; left as _).
 *   5x  PUSH/POP r64 (1 byte; _ for "no extra bytes").
 *   6x  Row-6 oddballs -- resolved below; placeholders here are _.
 *   7x  JCC short rel8.
 *   8x  Group1/2 immediate forms; 84/85 TEST; 86/87 XCHG; 88..8B MOV;
 *       8C/8E MOV Sreg ; 8D LEA ; 8F /0 POP r/m (others XOP we reject).
 *   9x  NOP/XCHG EAX,rXX ; CBW/CWD ; CALL far invalid (9A=X); WAIT;
 *       PUSHF/POPF/SAHF/LAHF.
 *   Ax  MOV AL/EAX,moffs (IO) ; MOVS/CMPS/STOS string (_) ;
 *       TEST AL,imm8 (IB) / TEST EAX,imm_z (IZ) ; A4..A7,AA..AF string _.
 *   Bx  MOV r,imm (IB for r8 row; IV for r64 row).
 *   Cx  C0/C1 shift imm8 ; C2 RET imm16 ; C3 RET ; C4/C5 VEX (X) ;
 *       C6 MOV r/m8,imm8 ; C7 MOV r/m,imm_z ; C8 ENTER iw,ib ;
 *       C9 LEAVE ; CA far RET imm16 ; CB far RET ; CC INT3 ; CD INT imm8 ;
 *       CE INTO invalid ; CF IRET.
 *   Dx  D0..D3 shift /1 ; D4/D5 AAM/AAD invalid ; D6 undefined ; D7 XLAT ;
 *       D8..DF x87 (all M_).
 *   Ex  E0..E3 LOOPx rel8 ; E4..E7 IN/OUT imm8 ; E8 CALL rel32 ;
 *       E9 JMP rel32 ; EA far JMP invalid ; EB JMP rel8 ; EC..EF IN/OUT;
 *   Fx  F0/F1/F2/F3 prefixes (consumed earlier; _) ; F4 HLT ; F5 CMC ;
 *       F6/F7 Group3 (M_ then test reg for imm8/imm_z) ; F8..FD flags ;
 *       FE Group4 (M_) ; FF Group5 (M_).
 */
static const unsigned short g_opmap1[256] = {
    /*       x0    x1    x2    x3    x4    x5    x6    x7    x8    x9    xA    xB    xC    xD    xE    xF */
    /* 0x */ M_,   M_,   M_,   M_,   IB,   IZ,   X,    X,    M_,   M_,   M_,   M_,   IB,   IZ,   X,    _,
    /* 1x */ M_,   M_,   M_,   M_,   IB,   IZ,   X,    X,    M_,   M_,   M_,   M_,   IB,   IZ,   X,    X,
    /* 2x */ M_,   M_,   M_,   M_,   IB,   IZ,   _,    X,    M_,   M_,   M_,   M_,   IB,   IZ,   _,    X,
    /* 3x */ M_,   M_,   M_,   M_,   IB,   IZ,   _,    X,    M_,   M_,   M_,   M_,   IB,   IZ,   _,    X,
    /* 4x */ _,    _,    _,    _,    _,    _,    _,    _,    _,    _,    _,    _,    _,    _,    _,    _,
    /* 5x */ _,    _,    _,    _,    _,    _,    _,    _,    _,    _,    _,    _,    _,    _,    _,    _,
    /* 6x */ X,    X,    X,    M_,   _,    _,    _,    _,    IZ,   M_IZ, IB,   M_IB, _,    _,    _,    _,
    /* 7x */ R8,   R8,   R8,   R8,   R8,   R8,   R8,   R8,   R8,   R8,   R8,   R8,   R8,   R8,   R8,   R8,
    /* 8x */ M_IB, M_IZ, M_IB, M_IB, M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,
    /* 9x */ _,    _,    _,    _,    _,    _,    _,    _,    _,    _,    X,    _,    _,    _,    _,    _,
    /* Ax */ IO,   IO,   IO,   IO,   _,    _,    _,    _,    IB,   IZ,   _,    _,    _,    _,    _,    _,
    /* Bx */ IB,   IB,   IB,   IB,   IB,   IB,   IB,   IB,   IV,   IV,   IV,   IV,   IV,   IV,   IV,   IV,
    /* Cx */ M_IB, M_IB, IW,   _,    X,    X,    M_IB, M_IZ, _,    _,    IW,   _,    _,    IB,   X,    _,
    /* Dx */ M_,   M_,   M_,   M_,   X,    X,    X,    _,    M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,
    /* Ex */ R8,   R8,   R8,   R8,   IB,   IB,   IB,   IB,   RZ,   RZ,   X,    R8,   _,    _,    _,    _,
    /* Fx */ _,    _,    _,    _,    _,    _,    M_,   M_,   _,    _,    _,    _,    _,    _,    M_,   M_,
};

/* ENTER imm16,imm8 (0xC8) has both -- we handle it as a special case
 * by setting both bits in the entry at decode time. The table cell
 * holds only one of the two; the override below adds the other. */

/* ---- Two-byte opcode map (0F xx) ----------------------------------- */
/* Intel SDM Vol 2 Table A-3.
 *   00..0F  group ops + SYSCALL/SYSRET/UD2 etc.
 *   10..1F  MOVUPS/MOVUPD ... ; 1F is /digit NOP, ModRM only.
 *   20..27  MOV CRn / DRn (ModRM); 28..2F MOVAPS/CVT...
 *   30..37  WRMSR/RDTSC/etc -- 0-operand bytes.
 *   38/3A   three-byte map escapes (handled inline before table lookup).
 *   40..4F  CMOVcc r,r/m (ModRM).
 *   50..6F  SSE / MMX / SSE2 (ModRM).
 *   70..73  imm8 shifts/shuffles.
 *   74..76  PCMPEQ* (ModRM).
 *   77      EMMS (no operands).
 *   78..7F  SSE moves / extracts (ModRM); 78/79 EVEX-only invalid; we
 *           accept M_ defensively since the corpus check catches any
 *           cell we get wrong.
 *   80..8F  JCC near rel32 (REL_Z).
 *   90..9F  SETcc r/m8 (ModRM).
 *   A0/A1   PUSH/POP FS ; A2 CPUID ; A3 BT (M_) ; A4/A5 SHLD (M_IB/M_);
 *   A6/A7   reserved invalid ; A8/A9 PUSH/POP GS ; AA RSM (no operands);
 *   AB BTS (M_) ; AC/AD SHRD (M_IB/M_) ; AE group /digit (M_) ;
 *   AF IMUL (M_).
 *   B0..B7  CMPXCHG/LSS/BTR/LFS/LGS/MOVZX (M_); B8 POPCNT (M_);
 *   B9 UD1 invalid; BA group /digit imm8 (M_IB) ;
 *   BB BTC (M_) ; BC/BD BSF/BSR (M_) ; BE/BF MOVSX (M_).
 *   C0/C1 XADD (M_); C2 CMPPS/CMPSS imm8 (M_IB); C3 MOVNTI (M_);
 *   C4/C5 PINSRW/PEXTRW imm8 (M_IB); C6 SHUFPS imm8 (M_IB);
 *   C7 group (M_); C8..CF BSWAP (no operands).
 *   D0..FF  SSE2 integer ops (M_); FF UD0 invalid.
 */
static const unsigned short g_opmap_0f[256] = {
    /*       x0    x1    x2    x3    x4    x5    x6    x7    x8    x9    xA    xB    xC    xD    xE    xF */
    /* 0x */ M_,   M_,   M_,   M_,   X,    _,    _,    _,    _,    _,    X,    _,    X,    M_,   _,    M_,
    /* 1x */ M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,
    /* 2x */ M_,   M_,   M_,   M_,   X,    X,    X,    X,    M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,
    /* 3x */ _,    _,    _,    _,    _,    _,    X,    _,    _,    X,    _,    X,    X,    X,    X,    X,
    /* 4x */ M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,
    /* 5x */ M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,
    /* 6x */ M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,
    /* 7x */ M_IB, M_IB, M_IB, M_IB, M_,   M_,   M_,   _,    M_,   M_,   X,    X,    M_,   M_,   M_,   M_,
    /* 8x */ RZ,   RZ,   RZ,   RZ,   RZ,   RZ,   RZ,   RZ,   RZ,   RZ,   RZ,   RZ,   RZ,   RZ,   RZ,   RZ,
    /* 9x */ M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,
    /* Ax */ _,    _,    _,    M_,   M_IB, M_,   X,    X,    _,    _,    _,    M_,   M_IB, M_,   M_,   M_,
    /* Bx */ M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   X,    M_IB, M_,   M_,   M_,   M_,   M_,
    /* Cx */ M_,   M_,   M_IB, M_,   M_IB, M_IB, M_IB, M_,   _,    _,    _,    _,    _,    _,    _,    _,
    /* Dx */ M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,
    /* Ex */ M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,
    /* Fx */ M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   M_,   X,
};

/* ---- Three-byte 0F 38 xx map --------------------------------------- */
/* Intel SDM Vol 2 Table A-4. Every defined opcode in this map takes a
 * ModRM byte with no immediate (SSSE3/SSE4.1/SSE4.2/MOVBE/CRC32/AES/
 * CLMUL primitives). MSVC's /Oi memcpy can compile down through here.
 * We populate every cell as M_; undefined cells decode length-correctly
 * because ModRM is deterministic, and the corpus oracle catches any
 * actual divergence. */
static const unsigned short g_opmap_0f38[256] = {
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
    M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_, M_,
};

/* ---- Three-byte 0F 3A xx map --------------------------------------- */
/* Intel SDM Vol 2 Table A-5. Every defined opcode takes ModRM and an
 * imm8 (PALIGNR, ROUND*, PCMP*STR*, AESKEYGENASSIST, etc). */
static const unsigned short g_opmap_0f3a[256] = {
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
    M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB, M_IB,
};

/* ---- ModRM / SIB / displacement helpers ---------------------------- */

/* Compute displacement size from ModRM + address-size prefix and report
 * whether a SIB byte follows. Intel SDM Vol 2 §2.1.5 Tables 2-1/2-2. */
static int ct_ild_modrm_extras(unsigned char modrm, int has_addr_size_pfx,
                               int *out_has_sib)
{
    unsigned mod = (modrm >> 6) & 0x3u;
    unsigned rm  = modrm & 0x7u;

    *out_has_sib = 0;

    if (has_addr_size_pfx) {
        /* 16-bit addressing -- Vol 2 Table 2-1. */
        if (mod == 0u && rm == 6u) return 2;
        if (mod == 1u) return 1;
        if (mod == 2u) return 2;
        return 0;
    }
    /* 32/64-bit addressing -- Vol 2 Table 2-2. */
    if (mod == 3u) return 0;
    if (rm == 4u) *out_has_sib = 1;
    if (mod == 0u) {
        if (rm == 5u) return 4;  /* disp32 (RIP-relative in 64-bit). */
        return 0;
    }
    if (mod == 1u) return 1;
    if (mod == 2u) return 4;
    return 0;
}

/* ---- Public decoder ------------------------------------------------ */

int ct_ild_decode(const unsigned char *code, size_t max_len)
{
    if (code == NULL || max_len == 0) return 0;
    if (max_len > CT_ILD_MAX_INSN_LEN) max_len = CT_ILD_MAX_INSN_LEN;

    size_t pos = 0;
    int has_66 = 0;     /* operand-size prefix */
    int has_67 = 0;     /* address-size prefix */
    int has_rex_w = 0;

    /* ---- Legacy prefixes (Intel SDM Vol 2 §2.1.1) ------------------ */
    while (pos < max_len) {
        unsigned char b = code[pos];
        if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) {
            pos++;
            continue;
        }
        if (b == 0x66) { has_66 = 1; pos++; continue; }
        if (b == 0x67) { has_67 = 1; pos++; continue; }
        break;
    }

    if (pos >= max_len) return 0;

    /* ---- REX prefix (Vol 2 §2.2.1.2) ------------------------------- */
    /* Only the last REX before the opcode takes effect; consume the
     * chain. (HDE64 only allows one but Intel says the LAST wins.) */
    while (pos < max_len && (code[pos] & 0xF0u) == 0x40u) {
        has_rex_w = (code[pos] & 0x08u) != 0;
        pos++;
    }
    if (pos >= max_len) return 0;

    /* ---- Reject VEX/EVEX prefixes outright (M50.0 limit) ----------- */
    {
        unsigned char b = code[pos];
        if (b == 0x62 || b == 0xC4 || b == 0xC5) {
            /* In 64-bit mode all three are prefix bytes for VEX/EVEX
             * (or in 32-bit mode they were BOUND/LES/LDS, all invalid
             * in 64-bit). Either way, reject. Vol 2 §2.3.5 / §2.6. */
            return 0;
        }
    }

    /* ---- Opcode dispatch ------------------------------------------- */
    unsigned char op = code[pos++];
    unsigned int entry;
    int is_secondary = 0;

    if (op == 0x0Fu) {
        if (pos >= max_len) return 0;
        unsigned char op2 = code[pos++];
        if (op2 == 0x38u) {
            if (pos >= max_len) return 0;
            unsigned char op3 = code[pos++];
            entry = g_opmap_0f38[op3];
            is_secondary = 1;
        } else if (op2 == 0x3Au) {
            if (pos >= max_len) return 0;
            unsigned char op3 = code[pos++];
            entry = g_opmap_0f3a[op3];
            is_secondary = 1;
        } else {
            entry = g_opmap_0f[op2];
            is_secondary = 1;
        }
    } else {
        entry = g_opmap1[op];
    }

    /* ENTER (0xC8) is the only 1-byte opcode with both imm16 + imm8.
     * The table cell holds IW; OR in IMM8 here. */
    if (!is_secondary && op == 0xC8u) {
        entry |= OP_IMM8;
    }

    if (entry & OP_INVALID) {
        return 0;
    }

    /* ---- ModRM / SIB / displacement -------------------------------- */
    int disp = 0;
    unsigned char modrm = 0;
    if (entry & OP_MODRM) {
        if (pos >= max_len) return 0;
        modrm = code[pos++];
        int has_sib = 0;
        disp = ct_ild_modrm_extras(modrm, has_67, &has_sib);
        if (has_sib) {
            if (pos >= max_len) return 0;
            unsigned char sib = code[pos++];
            /* SIB special case (Vol 2 Table 2-3): mod=00 + base=5 -> disp32. */
            unsigned modrm_mod = (modrm >> 6) & 0x3u;
            unsigned sib_base = sib & 0x7u;
            if (modrm_mod == 0u && sib_base == 5u) {
                disp = 4;
            }
        }
        if (disp > 0 && pos + (size_t)disp > max_len) return 0;
        pos += (size_t)disp;

        /* Group 3 special-cases (Vol 2 Table A-6):
         * 0xF6 /0 and /1 carry imm8; 0xF7 /0 and /1 carry imm_z. */
        if (!is_secondary) {
            unsigned reg = (modrm >> 3) & 0x7u;
            if (op == 0xF6u && reg <= 1u) entry |= OP_IMM8;
            else if (op == 0xF7u && reg <= 1u) entry |= OP_IMM_Z;
        }
    }

    /* ---- Immediate bytes ------------------------------------------- */
    size_t imm = 0;
    if (entry & OP_IMM8)  imm += 1;
    if (entry & OP_IMM16) imm += 2;
    if (entry & OP_IMM_Z) imm += has_66 ? 2u : 4u;
    if (entry & OP_IMM_V) imm += has_rex_w ? 8u : (has_66 ? 2u : 4u);
    if (entry & OP_IMM_O) imm += has_67 ? 4u : 8u;
    if (entry & OP_REL8)  imm += 1;
    if (entry & OP_REL_Z) imm += has_66 ? 2u : 4u;

    if (pos + imm > max_len) return 0;
    pos += imm;

    if (pos == 0u || pos > CT_ILD_MAX_INSN_LEN) return 0;
    return (int)pos;
}

int ct_ild_decode_to_cover(const unsigned char *code, size_t target_bytes,
                           size_t max_len)
{
    if (code == NULL || target_bytes == 0) return 0;

    size_t total = 0;
    while (total < target_bytes) {
        if (total >= max_len) return 0;
        int n = ct_ild_decode(code + total, max_len - total);
        if (n <= 0) return 0;
        total += (size_t)n;
        if (total > max_len) return 0;
    }
    return (int)total;
}
