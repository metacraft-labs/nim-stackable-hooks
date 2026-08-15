import std/[os, osproc, strutils, tempfiles, unittest]

import stackable_hooks/windows_injector

const ProbeArg = "--msys-fork-probe"

proc runForkProbe(): int =
  let shell = findExe("sh")
  if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
    return 77
  let systemRoot = getEnv("SystemRoot", r"C:\Windows")
  let systemDll = systemRoot / "System32" / "kernel32.dll"
  let capturePath = getTempDir() / "stackable-hooks-msys-fork-probe.log"
  let injection = runWithMonitorShim(
    @[shell, "-c", "/usr/bin/true; echo stackable-hooks-msys-fork-ok"],
    systemDll,
    captureStdio = true,
    captureStdioPath = capturePath)
  if injection.exitCode != 0:
    return 2
  if not injection.monitoringSkipped:
    return 3
  if windowsForkRuntimeForExecutable(shell) notin injection.skipReason:
    return 4
  0

if paramCount() == 1 and paramStr(1) == ProbeArg:
  quit(runForkProbe())

suite "Windows injector fork-runtime handling":
  test "detects adjacent MSYS2 and Cygwin runtimes":
    let fixture = createTempDir("stackable-hooks-", "-fork-runtime")
    defer: removeDir(fixture)
    let executable = fixture / "sh.exe"
    writeFile(executable, "fixture")

    writeFile(fixture / "msys-2.0.dll", "fixture")
    check windowsForkRuntimeForExecutable(executable) == "msys-2.0.dll"
    check windowsForkRuntimeForExecutable(fixture / "sh") == "msys-2.0.dll"

    removeFile(fixture / "msys-2.0.dll")
    writeFile(fixture / "cygwin1.dll", "fixture")
    check windowsForkRuntimeForExecutable(executable) == "cygwin1.dll"

    removeFile(fixture / "cygwin1.dll")
    check windowsForkRuntimeForExecutable(executable).len == 0

  test "MSYS2 compound command completes without pre-main injection":
    let shell = findExe("sh")
    if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
      checkpoint("MSYS2/Cygwin shell is not installed; integration probe skipped")
    else:
      let probe = startProcess(getAppFilename(), args = @[ProbeArg],
        options = {poUsePath, poParentStreams})
      var exitCode = -1
      for _ in 0 ..< 200:
        exitCode = peekExitCode(probe)
        if exitCode != -1:
          break
        sleep(50)
      if exitCode == -1:
        terminate(probe)
        discard waitForExit(probe, 5000)
      close(probe)
      check exitCode == 0
