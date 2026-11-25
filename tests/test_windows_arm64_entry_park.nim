## The entry park and the borrowed call on native Windows ARM64
## (reprobuild-pm spec/Monitor-Hook-Shim.md, "Windows on Arm64 install
## backend": "The park writes `B .` at the child's entry point and reads and
## restores CONTEXT_ARM64").
##
## A real native ARM64 child (`cmd.exe /c exit 7`, which Windows on Arm ships
## as an ARM64 image) is created suspended, parked at its entry point, made to
## run `GetCurrentProcessId` on its own main thread through the borrowed-call
## stub, released and resumed. The borrowed call must return the child's pid,
## and the child must then run its own program to its own exit code -- the
## proof that the parked context was handed back intact. No mocks.
when defined(windows) and defined(arm64):
  import std/[unittest, winlean]
  import stackable_hooks/windows_entry_park

  const
    createSuspended = 0x0000_0004'i32
    createNoWindow = 0x0800_0000'i32
    waitObject0 = 0'i32

  proc GetModuleHandleW(name: WideCString): Handle
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetProcAddress(h: Handle; name: cstring): pointer
    {.importc, stdcall, dynlib: "kernel32".}

  suite "Windows ARM64 entry park":
    test "park, borrow GetCurrentProcessId, release, and run to exit":
      var si: STARTUPINFO
      si.cb = int32(sizeof(si))
      var pi: PROCESS_INFORMATION
      var cmd = newWideCString("cmd.exe /d /c exit 7")
      check createProcessW(nil, cmd, nil, nil, 0, createSuspended or
        createNoWindow, nil, nil, si, pi) != 0
      defer:
        discard closeHandle(pi.hThread)
        discard closeHandle(pi.hProcess)

      var park = parkChildAtEntryPoint(cast[pointer](pi.hProcess),
        cast[pointer](pi.hThread), false, 60_000'u32)
      check park.status == epsParked
      if park.status == epsParked:
        let kernel32 = GetModuleHandleW(newWideCString("kernel32.dll"))
        let fn = GetProcAddress(kernel32, "GetCurrentProcessId")
        check fn != nil
        let call = borrowParkedThread(park, cast[pointer](pi.hThread), false,
          fn, nil, 60_000'u32)
        checkpoint("borrow status " & $call.status & ", ret " & $call.ret)
        check call.status == bcsReturned
        check call.ret == uint64(pi.dwProcessId)
        check park.status == epsParked
        check releaseEntryPark(park)
      discard resumeThread(pi.hThread)
      check waitForSingleObject(pi.hProcess, 60_000) == waitObject0
      var code: int32
      check getExitCodeProcess(pi.hProcess, code) != 0
      check code == 7

    test "an emulated x86 child is refused before any byte is changed":
      # The park writes this host's own machine code; an x86 image would
      # receive ARM64 bytes. `epsUnsupported` leaves the child untouched.
      let x64 = r"C:\Windows\SysWOW64\cmd.exe"   # x86 on every Windows on Arm
      var si: STARTUPINFO
      si.cb = int32(sizeof(si))
      var pi: PROCESS_INFORMATION
      var cmd = newWideCString(x64 & " /d /c exit 9")
      check createProcessW(nil, cmd, nil, nil, 0, createSuspended or
        createNoWindow, nil, nil, si, pi) != 0
      if pi.hProcess != 0:
        defer:
          discard closeHandle(pi.hThread)
          discard closeHandle(pi.hProcess)
        let park = parkChildAtEntryPoint(cast[pointer](pi.hProcess),
          cast[pointer](pi.hThread), false, 60_000'u32)
        check park.status == epsUnsupported
        discard resumeThread(pi.hThread)
        check waitForSingleObject(pi.hProcess, 60_000) == waitObject0
        var code: int32
        check getExitCodeProcess(pi.hProcess, code) != 0
        check code == 9
else:
  static: doAssert not (defined(windows) and defined(arm64))
