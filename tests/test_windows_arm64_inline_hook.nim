## The Windows on Arm64 inline-hook backend, live (reprobuild-pm
## spec/Monitor-Hook-Shim.md, "Windows on Arm64 install backend").
##
## The C fixture writes real ARM64 functions into executable pages -- one per
## PC-relative first-instruction form the backend relocates -- and hooks them,
## and the real kernel32 GetCurrentProcessId, through the production backend,
## including a transaction committed while peer threads run the targets and
## the noreturn record-then-continue variant. No mocks. A supervised child
## bounds a wedged freeze, as in test_windows_hook_freeze.
when defined(windows) and defined(arm64):
  import std/[os, osproc, streams, strutils, unittest]
  const testDir = currentSourcePath().replace("\\", "/").rsplit("/", 1)[0]
  const backend = testDir & "/../src/stackable_hooks/inline_hook/windows"
  {.passC: "-I" & backend & " -D_CRT_SECURE_NO_WARNINGS".}
  {.compile: testDir & "/fixtures/windows_arm64_inline_hook.c".}
  {.compile: backend & "/a64_relocate.c".}
  proc runProbe(): cint
    {.importc: "ct_test_windows_arm64_inline_hook", cdecl.}

  if paramCount() == 1 and paramStr(1) == "--probe":
    quit(int(runProbe()))

  suite "Windows on Arm64 inline hooks":
    test "every relocated form, a system function, a transaction and noreturn":
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
        check "all arm64 inline hook checks passed" in output
      finally:
        child.close()
else:
  # Off Windows ARM64 the backend's relocation is still covered by
  # test_a64_relocate, which runs everywhere.
  static: doAssert not (defined(windows) and defined(arm64))
