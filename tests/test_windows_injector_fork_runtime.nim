import std/[os, osproc, strtabs, strutils, tempfiles, unittest]

import stackable_hooks/windows_injector

const ProbeArg = "--msys-fork-probe"
const UnparkedProbeArg = "--msys-fork-probe-unparked"
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

proc runForkProbe(parkTimeoutMs: uint32): int =
  ## Run an MSYS2/Cygwin compound command (a `fork()` and an `exec`) under the
  ## injector and report what happened, as an exit code, from a process that
  ## is nobody else's test runner.
  ##
  ## `parkTimeoutMs = 0` disables the entry-point park and demands the OLD
  ## behaviour: the child carries a fork runtime, cannot be parked, and is
  ## therefore left uninjected with a `skipReason` that names the runtime.
  ## That arm is what keeps the parked arm below from passing vacuously.
  let shell = findExe("sh")
  if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
    return 77
  let capturePath = getTempDir() / "stackable-hooks-msys-fork-probe.log"
  let injection = runWithMonitorShim(
    @[shell, "-c", "/usr/bin/true; echo stackable-hooks-msys-fork-ok"],
    systemDllPath(),
    captureStdio = true,
    captureStdioPath = capturePath,
    parkTimeoutMs = parkTimeoutMs)
  # THE SHELL MUST COMPLETE either way. This is the assertion the whole file
  # exists for: a Cygwin shell that is touched by a pre-main remote thread
  # wedges at its first `fork()` and never reaches its second command.
  if injection.exitCode != 0:
    return 2
  if injection.rootPid == 0:
    return 5
  if parkTimeoutMs == 0:
    # Unparked: refused, and the refusal says why.
    if not injection.monitoringSkipped:
      return 3
    if windowsForkRuntimeForExecutable(shell) notin injection.skipReason:
      return 4
  else:
    # Parked: injected, and NOT reported as skipped -- a consumer may grade
    # this subtree on the records the child actually produced.
    if injection.monitoringSkipped:
      return 6
    if injection.skipReason.len != 0:
      return 7
  0

if paramCount() == 1 and paramStr(1) == ProbeArg:
  quit(runForkProbe(5000'u32))
if paramCount() == 1 and paramStr(1) == UnparkedProbeArg:
  quit(runForkProbe(0'u32))
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

  proc runProbeArm(arg: string): int =
    ## Drive one arm of `runForkProbe` in its own process and return its exit
    ## code, or -1 if it never finished (which is what a wedged Cygwin child
    ## looks like from here).
    let probe = startProcess(getAppFilename(), args = @[arg],
      options = {poUsePath, poParentStreams})
    result = -1
    for _ in 0 ..< 200:
      result = peekExitCode(probe)
      if result != -1:
        break
      sleep(50)
    if result == -1:
      terminate(probe)
      discard waitForExit(probe, 5000)
    close(probe)

  test "an unparked MSYS2 root is refused, and says which runtime":
    let shell = findExe("sh")
    if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
      checkpoint("MSYS2/Cygwin shell is not installed; integration probe skipped")
    else:
      # `parkTimeoutMs = 0`. Without the park a pre-main remote thread would
      # wedge this shell at its first `fork()`, so the injector refuses and
      # reports the refusal instead of attempting it.
      check runProbeArm(UnparkedProbeArg) == 0

  test "a parked MSYS2 root is injected and the compound command completes":
    let shell = findExe("sh")
    if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
      checkpoint("MSYS2/Cygwin shell is not installed; integration probe skipped")
    else:
      # The park runs the child's loader ON ITS MAIN THREAD before any remote
      # thread exists, which is what makes a Cygwin root attachable at all.
      # The shell still runs its `fork()` and its `exec` to completion --
      # that half of the assertion is unchanged from when this test only
      # covered the refusal.
      check runProbeArm(ProbeArg) == 0
