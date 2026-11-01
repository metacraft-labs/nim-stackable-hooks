## Exercises the 32-bit ARM (armhf) raw-syscall substrate.
##
## The byte-level `svc #0` site scanner is pure Nim and is checked on every
## host. The body-patch / `svc`->UDF patch primitives run their live
## assertions only on linux/arm (real ARM hardware or an armhf container);
## elsewhere the file self-gates to a static assertion so it compiles and runs
## in the portable suite, exactly as the aarch64 sibling does.

import std/unittest
import stackable_hooks/platform/linux_raw_syscalls

suite "linux armhf svc-site scanner (portable byte checks)":
  test "recognizes a word-aligned ARM svc #0":
    # ARM `svc #0` == 0xef000000, little-endian bytes 00 00 00 ef.
    let bytes = @[0x00'u8, 0x00, 0x00, 0xef]
    check looksLikeLinuxArmSvcSite(bytes, 0)

  test "rejects a misaligned ARM svc and non-svc words":
    let svc = @[0x00'u8, 0x00, 0x00, 0xef]
    check not looksLikeLinuxArmSvcSite(svc, 1)   # not word-aligned
    let notSvc = @[0x1e'u8, 0xff, 0x2f, 0xe1]    # bx lr, not svc
    check not looksLikeLinuxArmSvcSite(notSvc, 0)
    let tooShort = @[0x00'u8, 0x00, 0x00]
    check not looksLikeLinuxArmSvcSite(tooShort, 0)

  test "scans a buffer of interleaved svc and non-svc words":
    # bx lr | svc #0 | mov r0,#7 | svc #0
    let buf = @[
      0x1e'u8, 0xff, 0x2f, 0xe1,
      0x00, 0x00, 0x00, 0xef,
      0x07, 0x00, 0xa0, 0xe3,
      0x00, 0x00, 0x00, 0xef]
    let sites = scanLinuxArmSvcBytes(buf, 0x1000'u)
    check sites.len == 2
    check sites[0].address == 0x1004'u
    check sites[1].address == 0x100c'u

when defined(linux) and defined(arm):
  import posix

  proc rwxPage(): ptr UncheckedArray[byte] =
    let p = mmap(nil, 4096, PROT_READ or PROT_WRITE or PROT_EXEC,
                 MAP_PRIVATE or MAP_ANONYMOUS, -1, 0)
    doAssert p != MAP_FAILED
    cast[ptr UncheckedArray[byte]](p)

  proc wi(base: ptr UncheckedArray[byte]; off: int; insn: uint32) =
    copyMem(addr base[off], unsafeAddr insn, 4)

  proc wh(base: ptr UncheckedArray[byte]; off: int; insn: uint16) =
    copyMem(addr base[off], unsafeAddr insn, 2)

  proc rw(base: ptr UncheckedArray[byte]; off: int): uint32 =
    copyMem(addr result, addr base[off], 4)

  proc rh(base: ptr UncheckedArray[byte]; off: int): uint16 =
    copyMem(addr result, addr base[off], 2)

  proc clearCache(base: ptr UncheckedArray[byte]; len: int) =
    proc builtinClearCache(a, b: pointer) {.importc: "__builtin___clear_cache", nodecl.}
    builtinClearCache(addr base[0], addr base[len])

  # A `{.cdecl.}` signal handler cannot capture a Nim closure, so the recorded
  # site travels through a module-level global.
  var armTrapSite: uint = 0
  proc armTrapHandler(sig: cint; info: pointer; uctx: pointer) {.cdecl.} =
    let (diag, regs) = captureLinuxX8664SyscallRegisters(uctx)
    if diag == lrsOk and regs.syscallAddress == armTrapSite:
      let r = replayLinuxX8664SyscallRegisters(regs)
      discard writeLinuxX8664SyscallResult(uctx, r, regs.resumeRip)
    else:
      discard chainLinuxSigtrap(sig, info, uctx)

  suite "linux armhf body-patch + svc-trap primitives (live on ARM)":
    test "supported on this build target":
      check linuxRawSyscallSupported() == lrsOk

    test "absolute-jump body patch routes an ARM function to a hook":
      let code = rwxPage()
      # target: mov r0,#7 ; bx lr     (returns 7)
      wi(code, 0, 0xe3a00007'u32); wi(code, 4, 0xe12fff1e'u32)
      # hook:   mov r0,#42 ; bx lr    (returns 42)
      wi(code, 64, 0xe3a0002a'u32); wi(code, 68, 0xe12fff1e'u32)
      clearCache(code, 128)
      type Fn = proc (): cint {.cdecl.}
      let target = cast[Fn](addr code[0])
      let hook = cast[Fn](addr code[64])
      check target() == 7
      check hook() == 42
      let tx = installAbsoluteJumpPatchTransaction(addr code[0], addr code[64],
        captureRestoreBytes = true)
      check tx.diagnostic == lrsOk
      check tx.handle.patchSize == 8
      # ldr pc,[pc,#-4] then the hook address as the embedded word.
      check rw(code, 0) == 0xe51ff004'u32
      check target() == 42

    test "ARM svc #0 patches to UDF and restores":
      let code = rwxPage()
      wi(code, 0, 0xef000000'u32)   # svc #0 (ARM)
      clearCache(code, 4)
      let tx = installInt3SyscallPatchTransaction(cast[pointer](addr code[0]))
      check tx.diagnostic == lrsOk
      check tx.patchLive
      check rw(code, 0) == 0xe7f000f0'u32   # ARM udf #0
      var h = tx.handle
      check restoreInt3SyscallPatch(h) == lrsOk
      check rw(code, 0) == 0xef000000'u32   # svc #0 restored

    test "Thumb svc #0 patches to a 2-byte UDF and restores":
      let code = rwxPage()
      wh(code, 0, 0xdf00'u16)       # svc #0 (Thumb)
      wh(code, 2, 0x4770'u16)       # bx lr (filler so the word read is defined)
      clearCache(code, 4)
      let tx = installInt3SyscallPatchTransaction(cast[pointer](addr code[0]))
      check tx.diagnostic == lrsOk
      check tx.patchLive
      check rh(code, 0) == 0xde00'u16       # Thumb udf #0, width preserved
      check rh(code, 2) == 0x4770'u16       # untouched: only 2 bytes changed
      var h = tx.handle
      check restoreInt3SyscallPatch(h) == lrsOk
      check rh(code, 0) == 0xdf00'u16

    test "a non-svc target is refused, not patched":
      let code = rwxPage()
      wi(code, 0, 0xe12fff1e'u32)   # bx lr
      clearCache(code, 4)
      let tx = installInt3SyscallPatchTransaction(cast[pointer](addr code[0]))
      check tx.diagnostic == lrsNotSyscallSite
      check not tx.patchLive
      check rw(code, 0) == 0xe12fff1e'u32

    test "a live svc trap replays through the SIGILL handler":
      # End-to-end: write `svc #0 ; bx lr` as a nr=getpid function, patch the
      # svc to UDF, install the real inline handler, record the site, call it,
      # and confirm the handler replayed the syscall (r0 = our pid) and resumed
      # at `bx lr`. This is the mechanism io-mon's inline trap relies on.
      # r7 is callee-saved under AAPCS (and the frame pointer in Thumb code),
      # so the stub preserves it: a stub that clobbered it crashed the
      # optimised (gcc -O3) test driver on rpi2 with SIGSEGV after the call.
      let code = rwxPage()
      wi(code, 0, 0xe52d7004'u32)   # push {r7}
      wi(code, 4, 0xe3a07014'u32)   # mov r7, #20   (SYS_getpid on arm)
      wi(code, 8, 0xef000000'u32)   # svc #0
      wi(code, 12, 0xe49d7004'u32)  # pop {r7}
      wi(code, 16, 0xe12fff1e'u32)  # bx lr
      clearCache(code, 20)
      type Fn = proc (): cint {.cdecl.}
      let fn = cast[Fn](addr code[0])
      check fn() == cint(getpid())            # baseline, before patching
      armTrapSite = cast[uint](addr code[8])
      let tx = installInt3SyscallPatchTransaction(cast[pointer](armTrapSite))
      check tx.diagnostic == lrsOk
      check installLinuxSigtrapHandler(cast[pointer](armTrapHandler)) == lrsOk
      # A wrong resume width would re-execute the trap forever (or run off into
      # the next word); the alarm turns that into a prompt SIGALRM failure
      # instead of a hang the runner can only report as a timeout.
      discard alarm(5)
      check fn() == cint(getpid())            # trapped, replayed, resumed
      discard alarm(0)
      check uninstallLinuxSigtrapHandler() == lrsOk
else:
  static:
    doAssert not (defined(linux) and defined(arm))
