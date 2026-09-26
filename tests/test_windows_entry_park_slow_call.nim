## A SLOW child must never be treated as a hung one, and a thread whose
## context is lent out must never be resumed.
##
## THE DEFECT
## ----------
## Injection borrows the child's parked main thread to call ``LoadLibraryW``
## and then the shim's init (``windows_entry_park.callOnParkedThread``). The
## borrow used to have a 5 s deadline. When a call missed it, the thread was
## suspended MID-CALL and ``false`` came back; every caller then restored the
## entry bytes and resumed the thread. The child finished the borrowed call and
## returned into its real entry point on the borrowed stack, with hooks
## possibly half-installed, and crashed. On an I/O-starved Windows build host
## this is exactly what happened to gcc: the spawn records said
## ``inject=ioInitFailed``, and the same compiles died with "SIGSEGV: Illegal
## storage access". See ``docs/windows-borrowed-call-deadline.md``.
##
## WHAT IS ASSERTED
## ----------------
## The slow path is forced DETERMINISTICALLY and for real. Nothing here
## fakes a delay inside the framework:
##
## * the borrowed function is ``kernel32!Sleep`` itself, called ON THE
##   CHILD'S MAIN THREAD with the delay as its argument; or
## * the borrowed ``LoadLibraryW`` loads ``tests/fixtures/slow_load_lib.nim``,
##   a real DLL whose ``DllMain`` sleeps for as long as the child's
##   environment says.
##
## Each is run both ways round against a real ``cmd.exe /c exit 42`` child:
##
## * SLOWER THAN THE OLD 5 s DEADLINE, WITHIN THE HARD ONE. The injection
##   must succeed, and the child must then run its own ``main`` to its own
##   exit code, 42. A corrupted hand-back of the thread cannot produce 42:
##   ``cmd`` would fault on the borrowed stack first.
## * SLOWER THAN A SHORT HARD DEADLINE. The borrow must report the child
##   POISONED, and the child must already be dead with
##   ``InjectionAbandonedExitCode``. The test then does what every caller
##   does, ``releaseEntryPark`` followed by ``ResumeThread``, and asserts
##   that the child's own exit code 42 is NEVER observed. Before the fix,
##   this is the arm that resumed a thread mid-call.
##
## ``autoPropagateCreateProcessW`` is driven the same way, end to end, and
## must turn the poisoned child into a FAILED ``CreateProcessW``
## (``FALSE``, ``ERROR_TIMEOUT``, zeroed ``PROCESS_INFORMATION``).
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

  proc comSpec(): string =
    result = getEnv("ComSpec")
    if result.len == 0:
      result = getEnv("SystemRoot", r"C:\Windows") / "System32" / "cmd.exe"

  proc childCommandLine(): string =
    "\"" & comSpec() & "\" /c exit " & $ChildExitCode

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

    test "a borrowed call past the hard deadline poisons, never resumes":
      putEnv(SlowLoadEnvVar, "0")
      var pi = spawnSuspended()
      defer: reap(pi)
      var park = parkChildAtEntryPoint(pi.hProcess, pi.hThread, false,
        DefaultInjectDeadlineMs)
      require park.status == epsParked
      let call = borrowParkedThread(park, pi.hThread, false, sleepFn,
        cast[pointer](uint(WedgedMs)), ShortHardDeadlineMs)
      checkpoint("status=" & $call.status & " elapsedMs=" & $call.elapsedMs)
      check call.status == bcsPoisoned
      check park.status == epsAbandoned
      check call.elapsedMs < uint64(WedgedMs)
      # Already dead, with the sentinel, before any caller acts.
      check waitExitCode(pi.hProcess, 0) == InjectionAbandonedExitCode
      # Exactly what every caller does next. Before the fix this resumed a
      # thread that was mid-call.
      releaseEntryPark(park)
      discard ResumeThread(pi.hThread)
      let code = waitExitCode(pi.hProcess, ChildRunBudgetMs)
      check code == InjectionAbandonedExitCode
      check code != ChildExitCode

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

else:
  static:
    doAssert not (defined(windows) and defined(amd64))
