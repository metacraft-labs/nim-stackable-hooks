## A SLOW child must never be treated as a hung one, and a thread whose
## context is lent out must never be resumed BY THE LIBRARY -- the library
## reports the timeout and the CALLER applies a policy through the building
## blocks (keep waiting / terminate / detach).
##
## THE DEFECT, AND THE REDESIGN
## ----------------------------
## Injection borrows the child's parked main thread to call ``LoadLibraryW``
## and then the shim's init (``windows_entry_park.borrowParkedThread``). The
## borrow used to have a 5 s deadline whose expiry suspended the thread
## MID-CALL and returned ``false``; every caller then restored the entry bytes
## and resumed it, so the child finished the borrowed call and returned into
## its real entry point on a borrowed stack, and crashed. The first fix had the
## library TERMINATE such a child. The owner's decision (2026-10-13) makes that
## a building block the tool chooses, not a rigid library act: the borrow now
## returns ``bcsTimedOut`` with a ``TimedOutBorrow`` and leaves the thread
## suspended, lent out; the caller picks keep-waiting, terminate or detach. See
## ``docs/windows-borrowed-call-deadline.md``.
##
## WHAT IS ASSERTED
## ----------------
## The slow path is forced DETERMINISTICALLY and for real. The borrowed
## function is ``kernel32!Sleep`` itself, called ON THE CHILD'S MAIN THREAD
## with the delay as its argument, or a real ``LoadLibraryW`` of
## ``tests/fixtures/slow_load_lib.nim`` whose ``DllMain`` sleeps. Each runs
## against this same executable in an early child mode that exits 42.
##
## * TIMED OUT, NOT TERMINATED. A borrow past a short hard deadline returns
##   ``bcsTimedOut`` with ``usesStub`` set, the park is ``epsLentOut``, and the
##   child is ALIVE and suspended -- the library terminated nothing.
## * TERMINATE. ``terminateBorrowedChild`` kills it with
##   ``InjectionAbandonedExitCode``; a subsequent ``releaseEntryPark`` +
##   ``ResumeThread`` (what every caller does) never revives it and the
##   child's own exit code 42 is never seen.
## * KEEP WAITING. A ``Sleep`` that outlives the first deadline but is given
##   more time via ``keepWaitingForBorrow`` completes; the child then runs its
##   own ``main`` to 42 on the stack the loader gave it.
## * THE HARD RULE. With no building block applied, the reflexive
##   ``releaseEntryPark`` + ``ResumeThread`` leaves the lent-out child FROZEN
##   (never its own exit code), because of the extra suspend and the neutered
##   release.
## * THE INJECT LAYER. ``injectShimIntoChild`` waits for a slow shim load
##   (``ioInjected``) and, with the default terminate policy, kills a wedged
##   one (``ioChildTerminated``). ``autoPropagateCreateProcessW`` turns that
##   into a FAILED ``CreateProcessW`` (``FALSE``, ``ERROR_TIMEOUT``, zeroed
##   ``PROCESS_INFORMATION``).
##
## MOCKS, AND WHY THIS ONE IS JUSTIFIED
## -----------------------------------
## One: the ``CreateProcessW`` hook chain's ``original`` is a test callback
## that calls the REAL ``kernel32!CreateProcessW``. Hooking the test process's
## own ``kernel32`` would instrument the test runner, so the chain's tail is
## supplied directly instead, exactly as a shim's installer supplies it. Every
## process, park, borrow, deadline and termination in this file is real.
##
## RUN LANE
## --------
## Windows x64 only (the borrow is x64-only). The cross-target lane
## compile-checks it from Linux and macOS.

when defined(windows) and defined(amd64):

  import std/[os, osproc, unittest]

  import stackable_hooks/hook_registry
  import stackable_hooks/propagation
  import stackable_hooks/propagation_windows

  type
    HANDLE = pointer
    DWORD = uint32
    WORD = uint16
    BOOL = int32
    LPWSTR = ptr uint16
    LPCWSTR = ptr uint16

    STARTUPINFOW {.bycopy.} = object
      cb: DWORD
      lpReserved: LPWSTR
      lpDesktop: LPWSTR
      lpTitle: LPWSTR
      dwX: DWORD
      dwY: DWORD
      dwXSize: DWORD
      dwYSize: DWORD
      dwXCountChars: DWORD
      dwYCountChars: DWORD
      dwFillAttribute: DWORD
      dwFlags: DWORD
      wShowWindow: WORD
      cbReserved2: WORD
      lpReserved2: ptr byte
      hStdInput: HANDLE
      hStdOutput: HANDLE
      hStdError: HANDLE

    PROCESS_INFORMATION {.bycopy.} = object
      hProcess: HANDLE
      hThread: HANDLE
      dwProcessId: DWORD
      dwThreadId: DWORD

  const
    CREATE_SUSPENDED = 0x00000004'u32
    CREATE_NO_WINDOW = 0x08000000'u32
    WAIT_OBJECT_0 = 0x0'u32
    StillActive = 259'u32
    ChildExitCode = 42'u32
    SlowLoadEnvVar = "STACKABLE_HOOKS_SLOW_LOAD_MS"
    # Past the OLD deadline (5 s), well inside the new hard one: the case
    # the defect turned into a corrupted child.
    SlowButAliveMs = 7_000'u32
    # Far past the short hard deadline the poisoning cases use, so the only
    # way out of the borrowed call is the deadline.
    WedgedMs = 120_000'u32
    ShortHardDeadlineMs = 1_500'u32
    ChildRunBudgetMs = 60_000'u32

  if paramCount() == 1 and paramStr(1) == "--slow-call-child":
    quit(int(ChildExitCode))

  proc CreateProcessW(lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
                      lpProcessAttributes: pointer,
                      lpThreadAttributes: pointer,
                      bInheritHandles: BOOL, dwCreationFlags: DWORD,
                      lpEnvironment: pointer, lpCurrentDirectory: LPCWSTR,
                      lpStartupInfo: pointer,
                      lpProcessInformation: ptr PROCESS_INFORMATION): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc OpenProcess(access: DWORD, inherit: BOOL, pid: DWORD): HANDLE
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetModuleHandleW(name: LPCWSTR): HANDLE
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetProcAddress(m: HANDLE, name: cstring): pointer
    {.importc, stdcall, dynlib: "kernel32".}
  proc ResumeThread(hThread: HANDLE): DWORD
    {.importc, stdcall, dynlib: "kernel32".}
  proc WaitForSingleObject(hHandle: HANDLE, ms: DWORD): DWORD
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetExitCodeProcess(hProcess: HANDLE, code: ptr DWORD): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc TerminateProcess(hProcess: HANDLE, code: DWORD): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc CloseHandle(hObject: HANDLE): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetLastError(): DWORD
    {.importc, stdcall, dynlib: "kernel32".}

  proc toWide(s: string): seq[uint16] =
    result.setLen(s.len + 1)
    for i, c in s:
      result[i] = uint16(c)
    result[s.len] = 0'u16

  proc childCommandLine(): string =
    "\"" & getAppFilename() & "\" --slow-call-child"

  proc spawnSuspended(): PROCESS_INFORMATION =
    var cmdW = toWide(childCommandLine())
    var si: STARTUPINFOW
    si.cb = DWORD(sizeof(si))
    if CreateProcessW(nil, cast[LPWSTR](addr cmdW[0]), nil, nil, BOOL(0),
        CREATE_SUSPENDED or CREATE_NO_WINDOW, nil, nil, addr si,
        addr result) == 0:
      raise newException(OSError,
        "CreateProcessW failed (err=" & $GetLastError() & ")")

  proc kernel32Proc(name: cstring): pointer =
    var k32 = toWide("kernel32.dll")
    let kernel32 = GetModuleHandleW(cast[LPCWSTR](addr k32[0]))
    doAssert kernel32 != nil
    result = GetProcAddress(kernel32, name)
    doAssert result != nil

  proc exitCodeNow(hProcess: HANDLE): DWORD =
    ## ``StillActive`` while the process runs.
    if GetExitCodeProcess(hProcess, addr result) == 0:
      result = 0xFFFF_FFFF'u32

  proc waitExitCode(hProcess: HANDLE; ms: DWORD): DWORD =
    if WaitForSingleObject(hProcess, ms) != WAIT_OBJECT_0:
      return StillActive
    exitCodeNow(hProcess)

  proc reap(pi: PROCESS_INFORMATION) =
    ## Never leave a child behind, whatever the assertions said.
    if pi.hProcess != nil:
      if exitCodeNow(pi.hProcess) == StillActive:
        discard TerminateProcess(pi.hProcess, 1)
        discard WaitForSingleObject(pi.hProcess, 10_000)
      discard CloseHandle(pi.hProcess)
    if pi.hThread != nil:
      discard CloseHandle(pi.hThread)

  proc buildFixtureDll(src, outPath: string) =
    let root = currentSourcePath.parentDir.parentDir
    let args = @["c", "--hints:off", "--app:lib", "--threads:on",
                 "--mm:orc", "--path:" & (root / "src"),
                 "--out:" & outPath, src]
    let p = startProcess(findExe("nim"), args = args,
      options = {poUsePath, poParentStreams})
    let rc = waitForExit(p)
    close(p)
    doAssert rc == 0, "building fixture " & src & " failed with " & $rc
    doAssert fileExists(outPath), "fixture " & outPath & " was not produced"

  # -------------------------------------------------------------------
  # autoPropagateCreateProcessW harness
  # -------------------------------------------------------------------

  var gRegistry = initHookRegistry()
  var gLastChildPid: DWORD = 0
  # Global, not a local: the propagation registry is a process-lifetime
  # linked list and keeps the pointer after the test case returns.
  var gSlowNode: PropagationNode
  # A SEPARATE node for the btpDetach case, so it cannot collide with the
  # poisoned-child test's node on the process-lifetime propagation list.
  var gDetachNode: PropagationNode

  proc realCreateProcessWTail(ctx: var HookContext) {.raises: [].} =
    ## The chain's ``original``: the real CreateProcessW. The mock this file
    ## justifies in its header. It records the pid so the test can find the
    ## child after the hook has closed and zeroed the handles.
    let pi = cast[ptr PROCESS_INFORMATION](ctx.args[9])
    let r = CreateProcessW(cast[LPCWSTR](ctx.args[0]),
      cast[LPWSTR](ctx.args[1]), nil, nil, BOOL(ctx.args[4]),
      DWORD(ctx.args[5]), cast[pointer](ctx.args[6]),
      cast[LPCWSTR](ctx.args[7]), cast[pointer](ctx.args[8]), pi)
    ctx.result = uint64(uint32(r))
    if r != 0:
      gLastChildPid = pi[].dwProcessId

  suite "Windows borrowed call: a slow child is waited for, never corrupted":
    let workDir = getTempDir() / "stackable-hooks-park-slow"
    createDir(workDir)
    let slowDll = workDir / "slow_load_lib.dll"
    buildFixtureDll(currentSourcePath.parentDir / "fixtures" /
      "slow_load_lib.nim", slowDll)
    let sleepFn = kernel32Proc("Sleep")

    test "a borrowed call slower than the old 5 s deadline completes":
      putEnv(SlowLoadEnvVar, "0")
      var pi = spawnSuspended()
      defer: reap(pi)
      var park = parkChildAtEntryPoint(pi.hProcess, pi.hThread, false,
        DefaultInjectDeadlineMs)
      require park.status == epsParked
      let call = borrowParkedThread(park, pi.hThread, false, sleepFn,
        cast[pointer](uint(SlowButAliveMs)), DefaultInjectDeadlineMs)
      checkpoint("status=" & $call.status & " elapsedMs=" & $call.elapsedMs)
      check call.status == bcsReturned
      check call.elapsedMs >= uint64(SlowInjectionNoticeMs)
      check park.status == epsParked
      releaseEntryPark(park)
      discard ResumeThread(pi.hThread)
      # The child's own main ran to its own exit code on the stack the
      # loader gave it.
      check waitExitCode(pi.hProcess, ChildRunBudgetMs) == ChildExitCode

    test "a borrowed call past the hard deadline is reported, not terminated":
      ## Obligation 1. The library returns a timed-out borrow and leaves the
      ## child ALIVE and suspended, its context lent out. It terminates
      ## nothing. FALSIFYING MUTATION: in `windows_entry_park.borrowParkedThread`
      ## have the `pwDeadline` arm call `terminateBorrowedChild` (restore the
      ## old poison) -- the child is then dead and `childAlive` is false, so
      ## the `StillActive` assertion fails.
      putEnv(SlowLoadEnvVar, "0")
      var pi = spawnSuspended()
      defer: reap(pi)
      var park = parkChildAtEntryPoint(pi.hProcess, pi.hThread, false,
        DefaultInjectDeadlineMs)
      require park.status == epsParked
      var call = borrowParkedThread(park, pi.hThread, false, sleepFn,
        cast[pointer](uint(WedgedMs)), ShortHardDeadlineMs)
      checkpoint("status=" & $call.status & " elapsedMs=" & $call.elapsedMs)
      check call.status == bcsTimedOut
      check call.timedOut.usesStub
      check park.status == epsLentOut
      check call.elapsedMs < uint64(WedgedMs)
      # Nothing was terminated: the child is still running.
      check waitExitCode(pi.hProcess, 0) == StillActive
      # Clean up through the handle so `reap` has nothing to do.
      terminateBorrowedChild(call.timedOut)

    test "terminate: the child dies with the sentinel and never revives":
      ## Obligation 2. FALSIFYING MUTATION: make `terminateBorrowedChild`
      ## terminate with `0` instead of `InjectionAbandonedExitCode` -- the
      ## sentinel assertion fails. Or make it a no-op -- the child is then
      ## resumed by the reflexive sequence and runs to 42.
      putEnv(SlowLoadEnvVar, "0")
      var pi = spawnSuspended()
      defer: reap(pi)
      var park = parkChildAtEntryPoint(pi.hProcess, pi.hThread, false,
        DefaultInjectDeadlineMs)
      require park.status == epsParked
      var call = borrowParkedThread(park, pi.hThread, false, sleepFn,
        cast[pointer](uint(WedgedMs)), ShortHardDeadlineMs)
      require call.status == bcsTimedOut
      terminateBorrowedChild(call.timedOut)
      check park.status == epsAbandoned
      # Already dead, with the sentinel, before any caller resumes.
      check waitExitCode(pi.hProcess, 0) == InjectionAbandonedExitCode
      # Exactly what every caller does next. Before the redesign this is the
      # arm that resumed a thread mid-call.
      releaseEntryPark(park)
      discard ResumeThread(pi.hThread)
      let code = waitExitCode(pi.hProcess, ChildRunBudgetMs)
      check code == InjectionAbandonedExitCode
      check code != ChildExitCode

    test "keep waiting: a slow call given more time completes and runs main":
      ## Obligation 3. A `Sleep` that outlives a short deadline but is given
      ## more time via `keepWaitingForBorrow` returns, and the child then runs
      ## its own `main` to 42 on the loader's stack. FALSIFYING MUTATION: make
      ## `keepWaitingForBorrow` skip `resumeFully` -- the call never progresses
      ## and it times out again, so `bcsReturned` never arrives; or make it
      ## skip the `SetThreadContext(saved)` restore -- the child returns on a
      ## clobbered context and does not reach exit 42.
      putEnv(SlowLoadEnvVar, "0")
      var pi = spawnSuspended()
      defer: reap(pi)
      var park = parkChildAtEntryPoint(pi.hProcess, pi.hThread, false,
        DefaultInjectDeadlineMs)
      require park.status == epsParked
      var call = borrowParkedThread(park, pi.hThread, false, sleepFn,
        cast[pointer](uint(SlowButAliveMs)), ShortHardDeadlineMs)
      require call.status == bcsTimedOut
      check park.status == epsLentOut
      let resumed = keepWaitingForBorrow(call.timedOut, ChildRunBudgetMs)
      checkpoint("resumed status=" & $resumed.status &
        " elapsedMs=" & $resumed.elapsedMs)
      check resumed.status == bcsReturned
      check resumed.elapsedMs >= uint64(SlowInjectionNoticeMs)
      check park.status == epsParked
      releaseEntryPark(park)
      discard ResumeThread(pi.hThread)
      check waitExitCode(pi.hProcess, ChildRunBudgetMs) == ChildExitCode

    test "the hard rule: a lent-out child cannot be resumed by release+resume":
      ## Obligation 5 (behavioural). With NO building block applied, the
      ## reflexive caller sequence -- `releaseEntryPark` then `ResumeThread` --
      ## must leave the lent-out child FROZEN, never running its own code. The
      ## extra suspend and the neutered release are what make this structural.
      ## FALSIFYING MUTATION: drop the extra `SuspendThread` in
      ## `windows_entry_park.lendOut`, or let `releaseEntryPark` strip the
      ## bytes on `epsLentOut` -- the child then resumes and runs to 42.
      putEnv(SlowLoadEnvVar, "0")
      var pi = spawnSuspended()
      defer: reap(pi)
      var park = parkChildAtEntryPoint(pi.hProcess, pi.hThread, false,
        DefaultInjectDeadlineMs)
      require park.status == epsParked
      var call = borrowParkedThread(park, pi.hThread, false, sleepFn,
        cast[pointer](uint(WedgedMs)), ShortHardDeadlineMs)
      require call.status == bcsTimedOut
      # The reflexive sequence, applied with no policy chosen.
      releaseEntryPark(park)
      discard ResumeThread(pi.hThread)
      # Still frozen: its own exit code is never observed within a budget far
      # longer than a healthy child needs to reach `main`.
      check waitExitCode(pi.hProcess, 3_000'u32) == StillActive
      # Only a building block can end it.
      terminateBorrowedChild(call.timedOut)
      check waitExitCode(pi.hProcess, ChildRunBudgetMs) ==
        InjectionAbandonedExitCode

    test "injectShimIntoChild: a slow shim load is waited for":
      putEnv(SlowLoadEnvVar, $SlowButAliveMs)
      defer: putEnv(SlowLoadEnvVar, "0")
      var pi = spawnSuspended()
      defer: reap(pi)
      let report = injectShimIntoChildReport(pi.hProcess, slowDll, "",
        defaultInjectionConfig(), pi.hThread)
      checkpoint("outcome=" & $report.outcome & " waitedMs=" &
        $report.waitedMs)
      check report.outcome == ioInjected
      check report.waitedMs >= uint64(SlowInjectionNoticeMs)
      discard ResumeThread(pi.hThread)
      check waitExitCode(pi.hProcess, ChildRunBudgetMs) == ChildExitCode

    test "injectShimIntoChild: a wedged shim load terminates the child":
      putEnv(SlowLoadEnvVar, $WedgedMs)
      defer: putEnv(SlowLoadEnvVar, "0")
      var pi = spawnSuspended()
      defer: reap(pi)
      var cfg = defaultInjectionConfig()
      cfg.parkTimeoutMs = ShortHardDeadlineMs
      let report = injectShimIntoChildReport(pi.hProcess, slowDll, "", cfg,
        pi.hThread)
      checkpoint("outcome=" & $report.outcome & " waitedMs=" &
        $report.waitedMs)
      check report.outcome == ioChildTerminated
      check report.waitedMs < uint64(WedgedMs)
      check waitExitCode(pi.hProcess, 0) == InjectionAbandonedExitCode
      # The caller's resume, as io-mon's spawn hook does it in a `finally`.
      discard ResumeThread(pi.hThread)
      let code = waitExitCode(pi.hProcess, ChildRunBudgetMs)
      check code == InjectionAbandonedExitCode
      check code != ChildExitCode

    test "autoPropagateCreateProcessW fails the spawn of a poisoned child":
      putEnv(SlowLoadEnvVar, $WedgedMs)
      defer: putEnv(SlowLoadEnvVar, "0")
      gSlowNode.libraryPath = slowDll
      gSlowNode.initSymbol = ""
      registerPropagationNode(addr gSlowNode)
      enableAutoPropagation(addr gSlowNode)
      defer: disableAutoPropagation(addr gSlowNode)
      let savedCfg = propagationInjectionConfig()
      var cfg = savedCfg
      cfg.parkTimeoutMs = ShortHardDeadlineMs
      setPropagationInjectionConfig(cfg)
      defer: setPropagationInjectionConfig(savedCfg)

      gRegistry.setOriginal("CreateProcessW", realCreateProcessWTail)
      gRegistry.registerHook("CreateProcessW", 100,
        autoPropagateCreateProcessW)
      var cmdW = toWide(childCommandLine())
      var si: STARTUPINFOW
      si.cb = DWORD(sizeof(si))
      var pi: PROCESS_INFORMATION
      var ctx = HookContext(args: newSeq[uint64](10))
      ctx.args[1] = cast[uint64](addr cmdW[0])
      ctx.args[5] = uint64(CREATE_NO_WINDOW)
      ctx.args[8] = cast[uint64](addr si)
      ctx.args[9] = cast[uint64](addr pi)
      gLastChildPid = 0
      gRegistry.dispatch("CreateProcessW", ctx)
      let err = GetLastError()
      checkpoint("result=" & $ctx.result & " lastError=" & $err &
        " childPid=" & $gLastChildPid)
      require gLastChildPid != 0
      check (ctx.result and 0xFFFF_FFFF'u64) == 0
      check err == ERROR_TIMEOUT
      check pi.hProcess == nil
      check pi.hThread == nil
      check pi.dwProcessId == 0
      # The child really existed and really died of the deadline, not of
      # its own accord.
      const SYNCHRONIZE = 0x00100000'u32
      const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000'u32
      let h = OpenProcess(SYNCHRONIZE or PROCESS_QUERY_LIMITED_INFORMATION,
        BOOL(0), gLastChildPid)
      if h != nil:
        # Still openable only while something holds it; if so it must be
        # dead with the sentinel.
        check waitExitCode(h, ChildRunBudgetMs) == InjectionAbandonedExitCode
        discard CloseHandle(h)

    test "injectShimIntoChild: btpDetach lets a timed-out child run uninstrumented":
      ## The DETACH policy at the injection level. The borrowed LoadLibraryW
      ## of the slow fixture outlives a short deadline, so the caller's
      ## btpDetach policy restores the entry bytes and lets the call finish:
      ## the child reaches its own `main` (exit 42) UNINSTRUMENTED, with the
      ## loss surfaced as `ioChildDetached` -- the outcome io-mon's spawn
      ## record annotates as `inject=`. FALSIFYING MUTATION: make
      ## `applyBorrowTimeout`'s btpDetach arm terminate instead -- the child
      ## then dies (exit != 42) and the outcome is `ioChildTerminated`.
      putEnv(SlowLoadEnvVar, $SlowButAliveMs)
      defer: putEnv(SlowLoadEnvVar, "0")
      var pi = spawnSuspended()
      defer: reap(pi)
      var cfg = defaultInjectionConfig()
      cfg.parkTimeoutMs = ShortHardDeadlineMs
      cfg.onBorrowTimeout = btpDetach
      let report = injectShimIntoChildReport(pi.hProcess, slowDll, "", cfg,
        pi.hThread)
      checkpoint("outcome=" & $report.outcome & " waitedMs=" &
        $report.waitedMs)
      check report.outcome == ioChildDetached
      # Detach already resumed the child; a reflexive resume is a harmless
      # no-op. The child finishes the slow load on its own and runs to 42.
      discard ResumeThread(pi.hThread)
      check waitExitCode(pi.hProcess, ChildRunBudgetMs) == ChildExitCode

    test "autoPropagateCreateProcessW: btpDetach succeeds and the child runs":
      ## Correction 3: the observable outcome of btpDetach under
      ## auto-propagation. CreateProcess must SUCCEED (the child exists and
      ## runs), `PROCESS_INFORMATION` is left intact (not zeroed), and the
      ## child reaches its own exit code with no injector present. The loss is
      ## not silent: a consumer driving injection sees `ioChildDetached`.
      ## FALSIFYING MUTATION: make `autoPropagateCreateProcessW`'s
      ## `ioChildDetached` arm call `failSpawnForTerminatedChild` (treat it
      ## like terminate) -- `ctx.result` becomes 0 and `pi` is zeroed, so the
      ## success assertions fail.
      putEnv(SlowLoadEnvVar, $SlowButAliveMs)
      defer: putEnv(SlowLoadEnvVar, "0")
      # A FRESH hook registry and a SEPARATE propagation node, so neither the
      # hook chain nor the propagation list carries a duplicate from the
      # poisoned-child test above -- a duplicate would inject twice and the
      # second injection (into the now-detached, running child) would mask the
      # `ioChildDetached` this case must observe.
      gSlowNode.libraryPath = ""
      disableAutoPropagation(addr gSlowNode)
      var reg = initHookRegistry()
      gDetachNode.libraryPath = slowDll
      gDetachNode.initSymbol = ""
      registerPropagationNode(addr gDetachNode)
      enableAutoPropagation(addr gDetachNode)
      defer: disableAutoPropagation(addr gDetachNode)
      let savedCfg = propagationInjectionConfig()
      var cfg = savedCfg
      cfg.parkTimeoutMs = ShortHardDeadlineMs
      cfg.onBorrowTimeout = btpDetach
      setPropagationInjectionConfig(cfg)
      defer: setPropagationInjectionConfig(savedCfg)

      reg.setOriginal("CreateProcessW", realCreateProcessWTail)
      reg.registerHook("CreateProcessW", 100,
        autoPropagateCreateProcessW)
      var cmdW = toWide(childCommandLine())
      var si: STARTUPINFOW
      si.cb = DWORD(sizeof(si))
      var pi: PROCESS_INFORMATION
      var ctx = HookContext(args: newSeq[uint64](10))
      ctx.args[1] = cast[uint64](addr cmdW[0])
      ctx.args[5] = uint64(CREATE_NO_WINDOW)
      ctx.args[8] = cast[uint64](addr si)
      ctx.args[9] = cast[uint64](addr pi)
      gLastChildPid = 0
      reg.dispatch("CreateProcessW", ctx)
      checkpoint("result=" & $ctx.result & " childPid=" & $gLastChildPid)
      require gLastChildPid != 0
      # The spawn SUCCEEDED and the caller's handles are intact.
      check (ctx.result and 0xFFFF_FFFF'u64) != 0
      check pi.hProcess != nil
      check pi.dwProcessId == gLastChildPid
      # The detached child ran its own `main` to its own exit code,
      # uninstrumented, with no injector present.
      check waitExitCode(pi.hProcess, ChildRunBudgetMs) == ChildExitCode

else:
  static:
    doAssert not (defined(windows) and defined(amd64))
