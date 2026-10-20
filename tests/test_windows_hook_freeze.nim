## Real Windows thread-freeze regression for the inline-hook backend.
## The C fixture documents its handle tracking, snapshot filtering and the
## three injected Toolhelp/OpenThread faults; every other outcome, including
## refused suspensions and real thread exits, comes from the kernel.
## A supervised child bounds a stuck freeze.
when defined(windows) and (defined(amd64) or defined(i386)):
  import std/[os, osproc, streams, strutils, unittest]
  # Compile-time paths name host files even during a --os:windows check.
  const testDir = currentSourcePath().replace("\\", "/").rsplit("/", 1)[0]
  const backend = testDir & "/../src/stackable_hooks/inline_hook/windows"
  {.passC: "-I" & backend & " -D_CRT_SECURE_NO_WARNINGS".}
  {.compile: testDir & "/fixtures/windows_hook_freeze.c".}
  {.compile: backend & "/length_decoder.c".}
  {.compile: backend & "/rel32_fixup.c".}
  proc runProbe(): cint
    {.importc: "ct_test_windows_hook_freeze", cdecl.}

  if paramCount() == 1 and paramStr(1) == "--probe":
    quit(int(runProbe()))

  suite "Windows hook thread freeze":
    test "patching needs every live peer frozen; failures resume and close":
      let child = startProcess(getAppFilename(), args = @["--probe"],
        options = {poStdErrToStdOut})
      try:
        let code = child.waitForExit(120_000)
        if code == -1:
          child.kill()
          discard child.waitForExit()
        let output = child.outputStream.readAll()
        checkpoint(output)
        check code == 0
        check "FAIL" notin output
        check "all freeze checks passed" in output
      finally:
        child.close()
else:
  static: doAssert not defined(windows) or defined(arm64)
