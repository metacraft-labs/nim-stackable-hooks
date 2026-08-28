import std/[os, osproc, strtabs, strutils, tempfiles, unittest]

import stackable_hooks/windows_injector

const ProbeArg = "--msys-fork-probe"
const ArgvProbeArg = "--argv-fidelity-probe"
const EnvProbeArg = "--explicit-env-probe"
const EnvProbeName = "STACKABLE_HOOKS_EXPLICIT_ENV_PROBE"
const EnvProbeValue = "child-only-value"
const ArgvProbeValues = [
  "",
  "space arg",
  r"C:\path with space\zlib",
  "format=%s\\n",
  "caret=^left^right",
  "quote=\"value\"",
  "trailing path\\",
]

proc systemDllPath(): string =
  getEnv("SystemRoot", r"C:\Windows") / "System32" / "kernel32.dll"

proc runArgvFidelityProbe(): int =
  let received = commandLineParams()
  if received.len != ArgvProbeValues.len + 1:
    return 10
  for i, expected in ArgvProbeValues:
    if received[i + 1] != expected:
      return 20 + i
  0

proc runExplicitEnvProbe(): int =
  if getEnv(EnvProbeName) != EnvProbeValue:
    return 30
  0

proc runForkProbe(): int =
  let shell = findExe("sh")
  if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
    return 77
  let capturePath = getTempDir() / "stackable-hooks-msys-fork-probe.log"
  let injection = runWithMonitorShim(
    @[shell, "-c", "/usr/bin/true; echo stackable-hooks-msys-fork-ok"],
    systemDllPath(),
    captureStdio = true,
    captureStdioPath = capturePath)
  if injection.exitCode != 0:
    return 2
  if injection.rootPid == 0:
    return 5
  if not injection.monitoringSkipped:
    return 3
  if windowsForkRuntimeForExecutable(shell) notin injection.skipReason:
    return 4
  0

if paramCount() == 1 and paramStr(1) == ProbeArg:
  quit(runForkProbe())
if paramCount() > 0 and paramStr(1) == ArgvProbeArg:
  quit(runArgvFidelityProbe())
if paramCount() == 1 and paramStr(1) == EnvProbeArg:
  quit(runExplicitEnvProbe())

suite "Windows injector fork-runtime handling":
  test "CreateProcess command lines preserve every argument byte":
    var argv = @[getAppFilename(), ArgvProbeArg]
    argv.add(ArgvProbeValues)
    let injection = runWithMonitorShim(argv, systemDllPath())
    check injection.exitCode == 0
    check injection.rootPid != 0
    check not injection.monitoringSkipped

  test "CreateProcess passes an explicit child environment":
    let childEnv = newStringTable(modeCaseInsensitive)
    for name, value in envPairs():
      childEnv[name] = value
    childEnv[EnvProbeName] = EnvProbeValue

    let injection = runWithMonitorShim(
      @[getAppFilename(), EnvProbeArg], systemDllPath(), env = childEnv)
    check injection.exitCode == 0
    check injection.rootPid != 0
    check not injection.monitoringSkipped

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
