## Grandchild propagation's machine gate, live: a monitored process's shim
## sees each CreateProcessW in its spawn hook and calls
## ``propagation_windows.injectShimIntoChildReport`` on the suspended child
## (io-mon's ``injectSpawnedChild``). This test makes exactly that call, as
## the shim would, on real children of each machine.
##
## Contract: reprobuild-pm spec/Monitor-Hook-Shim.md, "Windows on Arm64
## install backend", "Machine gate". A child no shim of this process can
## serve -- including an ARM64X image that an x64 parent starts in x64 mode,
## such as System32's cmd.exe on Windows on Arm -- is left exactly as
## CreateProcessW created it: nothing is loaded into it and it runs to its own
## exit code once the caller resumes it. A child of this process's machine is
## injected and initialised.
##
## The root launcher's counterpart is ``test_windows_root_machine_gate``;
## children and helpers are shared through
## ``tests/fixtures/machine_gate_support.nim``. No mocks.
when defined(windows) and (defined(amd64) or defined(arm64)):
  import std/[os, strutils, unittest]
  import stackable_hooks/propagation_windows
  import stackable_hooks/windows_machine
  import ./fixtures/machine_gate_support

  let workDir = getTempDir() / ("stackable-hooks-child-gate-" & hostCPU &
    "-" & $getCurrentProcessId())
  createDir(workDir)
  let shimPath = workDir / "root_gate_shim.dll"
  let setupError = buildShim(workDir, shimPath)
  let native = hostNativeMachine()

  proc injectChild(exe: string; exitCode: int; mark: string):
      tuple[report: InjectionReport; exitCode: int; records: seq[string]] =
    ## Spawn `exe` suspended, inject it as the spawn hook does, resume it.
    removeFile(mark)
    putEnv(MarkVar, mark)
    let pi = spawnSuspended(exe, exitCode)
    defer:
      discard CloseHandle(pi.hThread)
      discard CloseHandle(pi.hProcess)
    result.report = injectShimIntoChildReport(pi.hProcess, shimPath,
      "repro_runtime_init", defaultInjectionConfig(), pi.hThread)
    checkpoint("outcome " & $result.report.outcome)
    if result.report.outcome == ioChildTerminated:
      result.exitCode = -2
    else:
      result.exitCode = resumeAndExitCode(pi)
    result.records = records(mark)

  suite "Windows grandchild propagation: machine gate":
    test "a child of this process's machine is injected and initialised":
      checkpoint(setupError)
      require setupError.len == 0
      if native != hostImageMachine():
        checkpoint("an x64 process on Windows on Arm has no x64 cmd.exe")
        skip()
      else:
        let r = injectChild(system32Cmd(), 7, workDir / "same.log")
        checkpoint("records: " & $r.records)
        check r.report.outcome == ioInjected
        check r.exitCode == 7
        # Loaded, and only loaded: `injectShimIntoChildReport` resolves the
        # init export in the module that contains IT, because in production
        # that is the shim propagating itself. Here the caller is this test
        # executable, which exports no `repro_runtime_init`, so no init is
        # dispatched (measured: run 45619632806). The init of a real shim's
        # grandchild is io-mon's spawn path and is tested there.
        check r.records.len == 1
        check r.records.len == 1 and r.records[0].startsWith("ATTACH")

    test "a hybrid ARM64X grandchild of an x64 shim is left alone":
      checkpoint(setupError)
      require setupError.len == 0
      if not (native == ImageFileMachineArm64 and
          hostImageMachine() == ImageFileMachineAmd64):
        checkpoint("needs an x64 build on Windows on Arm")
        skip()
      else:
        let r = injectChild(system32Cmd(), 7, workDir / "hybrid.log")
        check r.report.outcome == ioUnsupportedMachine
        check "inject=unsupported-process-machine:8664" in
          gateReason(r.report.machineGate)
        check r.report.machineGate.image == ImageFileMachineArm64
        check r.exitCode == 7
        check r.records.len == 0

    test "a pure ARM64 grandchild of an x64 shim is left alone":
      checkpoint(setupError)
      require setupError.len == 0
      if not (native == ImageFileMachineArm64 and
          hostImageMachine() == ImageFileMachineAmd64):
        checkpoint("needs an x64 build on Windows on Arm")
        skip()
      else:
        checkpoint(NativeArm64ChildVar & "=" & nativeArm64Child())
        require nativeArm64Child().len > 0
        let r = injectChild(nativeArm64Child(), 7, workDir / "arm64.log")
        check r.report.outcome == ioUnsupportedMachine
        check "inject=unsupported-process-machine:AA64" in
          gateReason(r.report.machineGate)
        check r.exitCode == 7
        check r.records.len == 0

    test "an x86 grandchild of a native ARM64 shim is left alone":
      checkpoint(setupError)
      require setupError.len == 0
      if hostImageMachine() != ImageFileMachineArm64:
        checkpoint("needs a native ARM64 build")
        skip()
      else:
        let r = injectChild(sysWow64Cmd(), 9, workDir / "x86.log")
        check r.report.outcome == ioUnsupportedMachine
        check "inject=unsupported-process-machine:014C" in
          gateReason(r.report.machineGate)
        check r.exitCode == 9
        check r.records.len == 0
else:
  static: doAssert not (defined(windows) and (defined(amd64) or
    defined(arm64)))
