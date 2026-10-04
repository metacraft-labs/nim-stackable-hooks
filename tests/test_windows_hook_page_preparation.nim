## Real Windows kernel/code/thread test, with transparent API-call counting.
## The C fixture documents why it counts actual protection calls; none are
## mocked. A supervised child bounds a stuck freeze or patch operation.
when defined(windows) and (defined(amd64) or defined(i386)):
  import std/[os, osproc, streams, strutils, unittest]
  # Compile-time paths name host files even during a --os:windows check.
  const testDir = currentSourcePath().replace("\\", "/").rsplit("/", 1)[0]
  const backend = testDir & "/../src/stackable_hooks/inline_hook/windows"
  {.passC: "-I" & backend & " -D_CRT_SECURE_NO_WARNINGS".}
  {.compile: testDir & "/fixtures/windows_hook_page_preparation.c".}
  {.compile: backend & "/length_decoder.c".}
  {.compile: backend & "/rel32_fixup.c".}
  proc runProbe(): cint
    {.importc: "ct_test_windows_hook_page_preparation", cdecl.}

  if paramCount() == 1 and paramStr(1) == "--probe":
    quit(int(runProbe()))

  suite "Windows hook page preparation":
    test "shared and crossing pages prepare once, with real hooks and peers":
      let child = startProcess(getAppFilename(), args = @["--probe"],
        options = {poStdErrToStdOut})
      try:
        let code = child.waitForExit(30_000)
        if code == -1:
          child.kill()
          discard child.waitForExit()
        let output = child.outputStream.readAll()
        checkpoint(output)
        check code == 0
        check "real target, trampoline, peer and protection checks passed" in output
      finally:
        child.close()
else:
  static: doAssert not defined(windows) or defined(arm64)
