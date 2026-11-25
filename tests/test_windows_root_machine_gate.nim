## The root injector's machine gate, live: real children of each machine a
## Windows host can start, injected (or not) through ``runWithMonitorShim``.
##
## reprobuild-pm issue 2026-11-20: an x64 engine on a Windows on Arm host
## started a native ARM64 action root, called ``CreateRemoteThread`` with its
## x64 ``LoadLibraryW`` address, got err=6, and failed the action. The
## contract (reprobuild-pm spec/Monitor-Hook-Shim.md, "Windows on Arm64
## install backend", "Machine gate") is that the engine never injects a shim
## of the wrong machine: such a root is resumed uninjected, runs to its own
## exit code, and is reported through ``monitoringSkipped``. A root of the
## caller's own machine is injected and initialised; on a native ARM64 host
## that exercises the ARM64 entry park and both borrowed calls (the load and
## ``repro_runtime_init``) through the production path.
##
## What each build checks depends on the host, because the children it can
## start do:
##
## =================  ===================  ===================================
## test binary        host                 children
## =================  ===================  ===================================
## arm64              Windows on Arm       System32 cmd (ARM64): injected;
##                                         SysWOW64 cmd (x86): refused
## amd64 (emulated)   Windows on Arm       a pure ARM64 image: refused --
##                                         the issue's case; System32 cmd
##                                         (ARM64X, runs as x64): refused
## amd64              x64 Windows          System32 cmd (x64): injected
## =================  ===================  ===================================
##
## The pure ARM64 child of the x64 build is the ARM64 build of this same
## test, named by ``STACKABLE_HOOKS_NATIVE_ARM64_CHILD`` and run with
## ``--exit-with <n>`` (scripts/windows-arm64-native-tests.ps1 sets both up).
## System32's cmd.exe cannot play that part: it is an ARM64X image, and an x64
## parent starts it as an x64-mode process (measured, run 45595100361).
##
## The decision itself is unit-tested on every host by
## ``test_windows_machine``. No mocks: real processes, a real DLL built from
## ``tests/fixtures/root_gate_shim.nim``, and its records read back from disk.
when defined(windows) and (defined(amd64) or defined(arm64)):
  import std/[os, strtabs, strutils, unittest]
  import stackable_hooks/windows_injector
  import ./fixtures/machine_gate_support

  # Child mode: exit with the given code and touch nothing else. The x64
  # build of this test and of test_windows_child_machine_gate use the ARM64
  # build, run this way, as their pure ARM64 child.
  if paramCount() == 2 and paramStr(1) == ExitWithArg:
    quit(parseInt(paramStr(2)))

  let system32Cmd = system32Cmd()
  let sysWow64Cmd = sysWow64Cmd()
  let workDir = getTempDir() / ("stackable-hooks-root-gate-" & hostCPU &
    "-" & $getCurrentProcessId())
  createDir(workDir)
  let shimPath = workDir / "root_gate_shim.dll"

  proc runRoot(exe: string; exitCode: int; mark: string):
      WindowsInjectionResult =
    var env = newStringTable(modeCaseInsensitive)
    for k, v in envPairs():
      env[k] = v
    env[MarkVar] = mark
    removeFile(mark)
    runWithMonitorShim(childArgs(exe, exitCode), shimPath, env = env)

  let nativeArm64Child = nativeArm64Child()
  let setupError = buildShim(workDir, shimPath)
  let native = hostNativeMachine()

  suite "Windows root injector: machine gate":
    test "the fixture shim is of this process's machine":
      checkpoint(setupError)
      check setupError.len == 0
      check peFileMachine(shimPath) == hostImageMachine()

    test "a root of this process's machine is injected and initialised":
      checkpoint(setupError)
      require setupError.len == 0
      if native != hostImageMachine():
        # An emulated x64 process on Windows on Arm: System32's cmd.exe is
        # ARM64, so the next test covers it. There is no x64 cmd.exe to
        # start here.
        checkpoint("host " & toHex(native) & " is not this process's machine")
        skip()
      else:
        let mark = workDir / "same-machine.log"
        let r = runRoot(system32Cmd, 7, mark)
        checkpoint("skipReason: " & r.skipReason)
        check r.exitCode == 7
        check not r.monitoringSkipped
        check r.skipReason.len == 0
        let lines = records(mark)
        checkpoint("records: " & lines.join(" | "))
        check lines == @["ATTACH pid=" & $r.rootPid, "INIT pid=" & $r.rootPid]

    test "issue 2026-11-20: a native ARM64 root of an x64 engine runs uninjected":
      checkpoint(setupError)
      require setupError.len == 0
      if not (native == ImageFileMachineArm64 and
          hostImageMachine() == ImageFileMachineAmd64):
        checkpoint("needs an x64 build on Windows on Arm")
        skip()
      else:
        checkpoint(NativeArm64ChildVar & "=" & nativeArm64Child)
        require nativeArm64Child.len > 0
        require peFileMachine(nativeArm64Child) == ImageFileMachineArm64
        let mark = workDir / "arm64-root-of-x64.log"
        let r = runRoot(nativeArm64Child, 7, mark)
        checkpoint("skipReason: " & r.skipReason)
        check r.exitCode == 7
        check r.monitoringSkipped
        check "inject=unsupported-process-machine:AA64" in r.skipReason
        check records(mark).len == 0

    test "a hybrid ARM64X root of an x64 engine runs uninjected":
      checkpoint(setupError)
      require setupError.len == 0
      if not (native == ImageFileMachineArm64 and
          hostImageMachine() == ImageFileMachineAmd64):
        checkpoint("needs an x64 build on Windows on Arm")
        skip()
      else:
        # System32's cmd.exe is ARM64X; started by this x64 process it runs
        # in x64 mode. Before the image-file check, the gate took it for an
        # x64 child: the park timed out and CreateRemoteThread failed with
        # err=5 (run 45595100361).
        require peFileMachine(system32Cmd) == ImageFileMachineArm64
        let mark = workDir / "hybrid-root-of-x64.log"
        let r = runRoot(system32Cmd, 7, mark)
        checkpoint("skipReason: " & r.skipReason)
        check r.exitCode == 7
        check r.monitoringSkipped
        check "inject=unsupported-process-machine:8664" in r.skipReason
        check "hybrid" in r.skipReason
        check records(mark).len == 0

    test "an x86 root of a native ARM64 engine runs uninjected":
      checkpoint(setupError)
      require setupError.len == 0
      if hostImageMachine() != ImageFileMachineArm64:
        checkpoint("needs a native ARM64 build")
        skip()
      else:
        let mark = workDir / "x86-root-of-arm64.log"
        let r = runRoot(sysWow64Cmd, 9, mark)
        checkpoint("skipReason: " & r.skipReason)
        check r.exitCode == 9
        check r.monitoringSkipped
        check "inject=unsupported-process-machine:014C" in r.skipReason
        check records(mark).len == 0

    test "the park refuses a child of another machine as unsupported":
      # Its own module doc promises `epsUnsupported` for a machine mismatch;
      # it used to report `epsSetupFailed`, which documents a remote-thread
      # load as a sound fallback -- the exact fallback that failed with
      # err=6.
      if native == ImageFileMachineArm64 and
          hostImageMachine() == ImageFileMachineAmd64:
        # The x64 build's foreign child is the ARM64 build of this test; its
        # absence is a broken lane, not a host without one.
        checkpoint(NativeArm64ChildVar & " is not set")
        require nativeArm64Child.len > 0
      let foreign =
        if hostImageMachine() == ImageFileMachineArm64: sysWow64Cmd
        elif native == ImageFileMachineArm64: nativeArm64Child
        else: ""
      if foreign.len == 0:
        checkpoint("an x64 host starts no child of a foreign machine " &
          "except WOW64 ones, which the park handles itself")
        skip()
      else:
        let pi = spawnSuspended(foreign, 5)
        defer:
          discard CloseHandle(pi.hThread)
          discard CloseHandle(pi.hProcess)
        let park = parkChildAtEntryPoint(pi.hProcess, pi.hThread, false,
          60_000'u32)
        check park.status == epsUnsupported
        check resumeAndExitCode(pi) == 5
else:
  static: doAssert not (defined(windows) and (defined(amd64) or
    defined(arm64)))
