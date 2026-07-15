## Executes the AArch64 body-patch + trampoline primitives on real hardware.
## Runs only on linux/arm64; a no-op assertion elsewhere so the suite is
## portable.

when defined(linux) and defined(arm64):
  import std/unittest
  import posix
  import stackable_hooks/platform/linux_raw_syscalls_aarch64

  proc movzW0(imm: uint32): uint32 = 0x52800000'u32 or (imm shl 5)
  const Ret = 0xD65F03C0'u32

  proc rwxPage(): ptr UncheckedArray[byte] =
    let p = mmap(nil, 4096, PROT_READ or PROT_WRITE or PROT_EXEC,
                 MAP_PRIVATE or MAP_ANONYMOUS, -1, 0)
    doAssert p != MAP_FAILED
    cast[ptr UncheckedArray[byte]](p)

  proc wi(base: ptr UncheckedArray[byte]; off: int; insn: uint32) =
    copyMem(addr base[off], unsafeAddr insn, 4)

  proc clearCache(base: ptr UncheckedArray[byte]; len: int) =
    proc builtinClearCache(a, b: pointer) {.importc: "__builtin___clear_cache", nodecl.}
    builtinClearCache(addr base[0], addr base[len])

  suite "linux aarch64 body-patch primitives":
    test "supported on this build target":
      check linuxAarch64PatchSupported() == la64Ok

    test "absolute-jump patch routes a function to a hook":
      let code = rwxPage()
      wi(code, 0, movzW0(7)); wi(code, 4, Ret)
      wi(code, 64, movzW0(42)); wi(code, 68, Ret)
      clearCache(code, 128)
      type Fn = proc (): cint {.cdecl.}
      let target = cast[Fn](addr code[0])
      let hook = cast[Fn](addr code[64])
      check target() == 7
      check hook() == 42
      var pr: CStackableLinuxAarch64PatchResult
      check linuxAarch64PatchAbsoluteJump(addr code[0], addr code[64], true, pr) == 0
      check pr.patchSize == 16
      check target() == 42

    test "trampoline relocates a `b` to its absolute target":
      let code = rwxPage()
      wi(code, 0, 0x14000000'u32 or 6'u32) # b +24
      wi(code, 4, movzW0(99)); wi(code, 8, movzW0(98)); wi(code, 12, movzW0(97))
      wi(code, 16, movzW0(11)); wi(code, 20, Ret)
      wi(code, 24, movzW0(42)); wi(code, 28, Ret)
      clearCache(code, 64)
      var tr: CStackableLinuxAarch64TrampolineResult
      check linuxAarch64MeasureTrampoline(addr code[0], 16, 64, tr) == 0
      check tr.copiedLen == 16
      check linuxAarch64BuildTrampoline(addr code[0], 16, 64, tr) == 0
      type Fn = proc (): cint {.cdecl.}
      let tramp = cast[Fn](cast[pointer](tr.entry))
      check tramp() == 42

    test "measure refuses an svc site":
      let code = rwxPage()
      wi(code, 0, 0xD2801BA8'u32) # mov x8,#221
      wi(code, 4, 0xD4000001'u32) # svc #0
      clearCache(code, 8)
      var tr: CStackableLinuxAarch64TrampolineResult
      check linuxAarch64MeasureTrampoline(addr code[0], 16, 64, tr) == 11
else:
  static:
    doAssert not (defined(linux) and defined(arm64))
