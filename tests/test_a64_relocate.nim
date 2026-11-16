## The AArch64 relocation behind the Windows on Arm64 inline hook
## (reprobuild-pm spec/Monitor-Hook-Shim.md, "Windows on Arm64 install
## backend"). The module is pure encoding, so this test runs on every host:
## each case relocates one instruction between two fixed addresses and
## compares the exact words. The expected words were disassembled with
## `llvm-mc --disassemble -triple=aarch64` (LLVM 21.1.8) when the cases were
## written, and the comment on each row is that disassembly.
##
## No mocks: the C module under test is compiled into this binary.

import std/[strutils, unittest]

const inlineDir = currentSourcePath().rsplit({'/', '\\'}, 1)[0] &
  "/../src/stackable_hooks/inline_hook/windows"
{.passC: "-I" & inlineDir.}
{.compile: inlineDir & "/a64_relocate.c".}

const MaxWords = 16

proc ctA64Relocate(insn: uint32; oldPc, newPc, resume: uint; output: ptr uint32;
                   outWords: csize_t): cint
  {.importc: "ct_a64_relocate", cdecl.}
proc ctA64EncodeB(source, dest: uint; output: ptr uint32): cint
  {.importc: "ct_a64_encode_b", cdecl.}
proc ctA64DecodeB(insn: uint32; pc: uint; dest: ptr uint): cint
  {.importc: "ct_a64_decode_b", cdecl.}

const
  oldPc = 0x1_8001_0000'u
  nearPc = 0x1_8002_0000'u
  farPc = 0x7FF6_0000_0000'u

proc relocate(insn: uint32; oldAt, newAt: uint): seq[uint32] =
  var buf: array[MaxWords, uint32]
  let n = ctA64Relocate(insn, oldAt, newAt, oldAt + 4, addr buf[0], MaxWords)
  if n < 0: return @[uint32(n)]
  buf[0 ..< n]

suite "AArch64 single-instruction relocation":
  test "a position-independent instruction is copied, then branches back":
    # stp x29, x30, [sp, #-16]! ; b oldPc+4
    check relocate(0xA9BF7BFD'u32, oldPc, nearPc) == @[0xA9BF7BFD'u32, 0x17FFC000'u32]

  test "B in reach is rebased; out of reach becomes an absolute X16 jump":
    # b oldPc+0x100
    check relocate(0x14000040'u32, oldPc, nearPc) == @[0x17FFC040'u32]
    # ldr x16, #8 ; br x16 ; .quad oldPc+0x100
    check relocate(0x14000040'u32, oldPc, farPc) ==
      @[0x58000050'u32, 0xD61F0200'u32, 0x80010100'u32, 0x00000001'u32]

  test "BL keeps its link and resumes after the call":
    # bl oldPc+0x100 ; b oldPc+4
    check relocate(0x94000040'u32, oldPc, nearPc) == @[0x97FFC040'u32, 0x17FFC000'u32]
    # Target out of reach of the copy, resume in reach:
    # ldr x16, #16 ; blr x16 ; b oldPc+4 ; nop ; .quad dest
    let base = 0x1_8000_0000'u
    let bl = 0x94000000'u32 or uint32((127 * 1024 * 1024) div 4)
    check relocate(bl, base, base - 0x20_0000) == @[0x58000090'u32,
      0xD63F0200'u32, 0x1407FFFF'u32, 0xD503201F'u32, 0x87F00000'u32,
      0x00000001'u32]

  test "conditional branches split into taken and not-taken paths":
    # b.eq +8 ; b oldPc+4 ; b oldPc+0x20
    check relocate(0x54000100'u32, oldPc, nearPc) ==
      @[0x54000040'u32, 0x17FFC000'u32, 0x17FFC006'u32]
    # tbnz w2, #5, +8 ; b oldPc+4 ; b oldPc+0x20
    check relocate(0x37280102'u32, oldPc, nearPc) ==
      @[0x37280042'u32, 0x17FFC000'u32, 0x17FFC006'u32]

  test "ADR and ADRP load the address they would have computed":
    # adrp x16, page+1 -> ldr x16, #8 ; b oldPc+4 ; .quad 0x180011000
    check relocate(0xB0000010'u32, oldPc, nearPc) ==
      @[0x58000050'u32, 0x17FFC000'u32, 0x80011000'u32, 0x00000001'u32]
    # adr x1, +0x10 -> ldr x1, #8 ; b oldPc+4 ; .quad 0x180010010
    check relocate(0x10000081'u32, oldPc, nearPc) ==
      @[0x58000041'u32, 0x17FFC000'u32, 0x80010010'u32, 0x00000001'u32]

  test "the load-literal family loads through X16 from the original address":
    # ldr x2, =lit -> ldr x16, #16 ; ldr x2, [x16] ; b oldPc+4 ; nop ; .quad
    check relocate(0x58000202'u32, oldPc, nearPc) == @[0x58000090'u32,
      0xF9400202'u32, 0x17FFBFFF'u32, 0xD503201F'u32, 0x80010040'u32,
      0x00000001'u32]
    # ldr q3, =lit -> ldr x16, #16 ; ldr q3, [x16] ; ...
    check relocate(0x9C000203'u32, oldPc, nearPc) == @[0x58000090'u32,
      0x3DC00203'u32, 0x17FFBFFF'u32, 0xD503201F'u32, 0x80010040'u32,
      0x00000001'u32]

  test "refusals are distinct":
    # An unallocated SIMD load-literal opc cannot be relocated.
    check relocate(0xDC000000'u32, oldPc, nearPc) == @[uint32(cint(-2))]
    # A misaligned address is an invalid argument.
    var buf: array[MaxWords, uint32]
    check ctA64Relocate(0xD503201F'u32, oldPc + 2, nearPc, oldPc + 4,
                        addr buf[0], MaxWords) == -1
    # A copy whose branch back cannot reach is refused, not emitted.
    check relocate(0x94000040'u32, oldPc, farPc) == @[uint32(cint(-3))]

suite "AArch64 B encoding":
  test "B reaches +/-128 MB and no further":
    var word: uint32
    check ctA64EncodeB(oldPc, oldPc + 0x7FF_FFFC, addr word) == 0
    check word == 0x15FFFFFF'u32
    check ctA64EncodeB(oldPc, oldPc - 0x800_0000, addr word) == 0
    check word == 0x16000000'u32
    check ctA64EncodeB(oldPc, oldPc + 0x800_0000, addr word) == -1
    check ctA64EncodeB(oldPc, oldPc + 2, addr word) == -1

  test "decode is the inverse of encode":
    var word: uint32
    var dest: uint
    check ctA64EncodeB(nearPc, oldPc, addr word) == 0
    check ctA64DecodeB(word, nearPc, addr dest) == 1
    check dest == oldPc
    check ctA64DecodeB(0x94000040'u32, nearPc, addr dest) == 0   # BL is not B
