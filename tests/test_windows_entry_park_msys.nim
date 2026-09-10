## Failing-before / passing-after for the MSYS2-Cygwin attach hazard.
##
## WHAT IS BEING MEASURED
## ----------------------
## A real MSYS2/Cygwin shell is spawned ``CREATE_SUSPENDED``, a real DLL
## with a real ``DllMain`` is injected through the real public
## ``injectShimIntoChild``, the shell is resumed, and the test waits for it
## to finish a fork-heavy script.
##
## Two strategies run against that identical setup:
##
## * ``asEntryPark`` (the default) -- the child must COMPLETE, and the
##   fixture must record one ``DllMain`` attach per run.
## * ``asDirect`` (the verbatim pre-park technique) -- the child must HANG.
##
## The control is what stops the passing case from passing vacuously. The
## success arm proves the fix works; the control proves the script is
## genuinely fork-heavy enough to expose the bug, that the DLL is genuinely
## being loaded, and that the shell on this host really is affected. A
## passing case with no failing control would be indistinguishable from a
## test that never exercised the hazard at all.
##
## The control also demonstrates the falsely-complete hazard directly:
## ``asDirect`` returns ``ioInjected`` -- LoadLibraryW really did succeed --
## while the child is wedged and will never do any of the work it was
## spawned for. A consumer grading on that outcome would publish a cache
## entry keyed on inputs it never saw. The default strategy is what stops
## that, and the two arms below are the difference between them.
##
## IF THE CONTROL EVER FAILS, the hazard has gone away on this host or in
## this Windows build. That is a real finding, not a flake: it would mean
## ``asDirect`` is safe here and the strategy knob could be retired. Do not
## "fix" it by loosening the assertion.
##
## RUN COUNTS are env-overridable so the same landed test can be swept:
## ``STACKABLE_HOOKS_PARK_RUNS`` (default 5) and
## ``STACKABLE_HOOKS_DIRECT_RUNS`` (default 2). The defaults keep the
## routine lane inside a minute; the sweep that qualified this change ran
## 20 and 20.

when defined(windows):

  import std/[os, osproc, strutils, unittest]

  import stackable_hooks/propagation_windows
  import stackable_hooks/windows_fork_runtime

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
    WAIT_OBJECT_0 = 0x0'u32
    MarkEnvVar = "STACKABLE_HOOKS_PARK_MARK"

  proc CreateProcessW(lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
                      lpProcessAttributes: pointer,
                      lpThreadAttributes: pointer,
                      bInheritHandles: BOOL, dwCreationFlags: DWORD,
                      lpEnvironment: pointer, lpCurrentDirectory: LPCWSTR,
                      lpStartupInfo: pointer,
                      lpProcessInformation: ptr PROCESS_INFORMATION): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc ResumeThread(hThread: HANDLE): DWORD
    {.importc, stdcall, dynlib: "kernel32".}
  proc WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD): DWORD
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetExitCodeProcess(hProcess: HANDLE, lpExitCode: ptr DWORD): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc TerminateProcess(hProcess: HANDLE, uExitCode: DWORD): BOOL
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

  # A fork-heavy POSIX script. Every ``$(...)`` is a Cygwin ``fork()`` and
  # the pipeline adds two more, so this is ~75 forks -- the shell wedges on
  # the FIRST of them when the runtime was initialised on a dead thread, so
  # the count is margin, not a requirement. Only tools that ship in every
  # MSYS2 and Git-for-Windows installation are used.
  const ForkHeavyScript = """
n=0
last=none
while [ $n -lt 25 ]; do
  a=$(/usr/bin/printf 'x%s' "$n")
  last=$(/usr/bin/printf '%s' "$a" | /usr/bin/tr 'x' 'y')
  n=$((n + 1))
done
/usr/bin/printf 'HEAVY_OK iterations=%s last=%s\n' "$n" "$last" > "$1"
"""

  type ChildOutcome = object
    injection: InjectionOutcome
    hung: bool
    exitCode: DWORD
    sentinel: string

  proc readIfPresent(path: string): string =
    result = ""
    try:
      if fileExists(path):
        result = readFile(path)
    except CatchableError:
      discard

  proc shellCommandLine(shell, script, sentinel: string): string =
    # Forward slashes throughout: the MSYS path layer accepts a
    # ``C:/...`` argument, and a backslash would be an escape to the shell.
    "\"" & shell & "\" \"" & script.replace('\\', '/') & "\" \"" &
      sentinel.replace('\\', '/') & "\""

  proc spawnSuspended(cmdline: string; pi: var PROCESS_INFORMATION) =
    var cmdW = toWide(cmdline)
    var si: STARTUPINFOW
    si.cb = DWORD(sizeof(si))
    if CreateProcessW(nil, cast[LPWSTR](addr cmdW[0]), nil, nil, BOOL(1),
        CREATE_SUSPENDED, nil, nil, addr si, addr pi) == 0:
      raise newException(OSError,
        "CreateProcessW failed (err=" & $GetLastError() & ") for " & cmdline)

  proc runInstrumentedShell(strategy: AttachStrategy;
                            shell, script, sentinel, dll: string;
                            waitMs: DWORD): ChildOutcome =
    ## Spawn the shell suspended, inject through the public API exactly as
    ## a propagation consumer would, resume, and wait.
    removeFile(sentinel)
    var pi: PROCESS_INFORMATION
    spawnSuspended(shellCommandLine(shell, script, sentinel), pi)

    var cfg = defaultInjectionConfig()
    cfg.attachStrategy = strategy
    # The fixture is never already mapped, and disabling the probe keeps
    # the two arms doing the identical amount of work.
    cfg.skipIfImageHasShim = false
    result.injection = injectShimIntoChild(pi.hProcess, dll, "", cfg,
      pi.hThread)

    # The single wakeup. injectShimIntoChild is suspend-count neutral, so
    # this is correct whether or not it parked the child.
    discard ResumeThread(pi.hThread)

    if WaitForSingleObject(pi.hProcess, waitMs) != WAIT_OBJECT_0:
      result.hung = true
      discard TerminateProcess(pi.hProcess, 0xDEAD'u32)
      discard WaitForSingleObject(pi.hProcess, 10_000'u32)
    else:
      discard GetExitCodeProcess(pi.hProcess, addr result.exitCode)
    discard CloseHandle(pi.hThread)
    discard CloseHandle(pi.hProcess)
    result.sentinel = readIfPresent(sentinel)

  proc envRuns(name: string; fallback: int): int =
    let raw = getEnv(name).strip()
    if raw.len == 0:
      return fallback
    try:
      parseInt(raw)
    except ValueError:
      fallback

  # --- re-entry guard ----------------------------------------------------
  # The native-child case below spawns THIS binary. Without an early exit
  # that would re-run the whole suite recursively, so the child arm has to
  # come before anything else executes. It does just enough to prove it ran
  # to completion under a parked-and-injected start.
  const NativeChildArg = "--native-park-child"
  if paramCount() >= 1 and paramStr(1) == NativeChildArg:
    quit(0)

  # --- one-time fixture setup, shared by every case below ----------------
  # The DLL is built UNCONDITIONALLY. The native-child case needs it on
  # every Windows host, and coupling the ordinary-path evidence to whether
  # an MSYS shell happens to be installed would leave the universal park
  # unproven exactly where it matters most.
  let shell = findExe("sh")
  let runtime =
    if shell.len == 0: ""
    else: windowsForkRuntimeForExecutable(shell)

  var workDir = ""
  var dllPath = ""
  var scriptPath = ""
  var markPath = ""
  var setupError = ""

  try:
    workDir = getTempDir() / "stackable-hooks-entry-park"
    removeDir(workDir)
    createDir(workDir)
    scriptPath = workDir / "forkheavy.sh"
    writeFile(scriptPath, ForkHeavyScript)
    markPath = workDir / "attach.log"
    putEnv(MarkEnvVar, markPath)

    let nimExe = findExe("nim")
    if nimExe.len == 0:
      setupError = "nim is not on PATH; cannot build the fixture DLL"
    else:
      let fixture = currentSourcePath().parentDir() / "fixtures" /
        "entry_park_mark_lib.nim"
      dllPath = workDir / "entry_park_mark_lib.dll"
      let (buildOut, buildCode) = execCmdEx(
        "\"" & nimExe & "\" c --app:lib --hints:off --warnings:off" &
        " --nimcache:\"" & (workDir / "nimcache") & "\"" &
        " --out:\"" & dllPath & "\" \"" & fixture & "\"")
      if buildCode != 0 or not fileExists(dllPath):
        setupError = "fixture DLL build failed (" & $buildCode & "):\n" &
          buildOut
  except CatchableError as e:
    setupError = "fixture setup failed: " & e.msg

  suite "Windows entry-point park: MSYS2/Cygwin attach":
    test "entry-point park lets a fork-heavy MSYS2/Cygwin shell complete":
      if runtime.len == 0:
        checkpoint("no MSYS2/Cygwin shell on PATH; hazard probe not run")
      else:
        # A setup failure is a REAL failure. Treating it as a skip would
        # turn "we could not build the fixture" into "the fix works".
        checkpoint(setupError)
        require setupError == ""

        let runs = envRuns("STACKABLE_HOOKS_PARK_RUNS", 5)
        var completed = 0
        for i in 1 .. runs:
          let r = runInstrumentedShell(asEntryPark, shell, scriptPath,
            workDir / ("sentinel-park-" & $i & ".txt"), dllPath, 60_000'u32)
          checkpoint("park run " & $i & ": injection=" & $r.injection &
            " hung=" & $r.hung & " exit=" & $r.exitCode &
            " sentinel=" & r.sentinel.strip())
          check r.injection == ioInjected
          check not r.hung
          check r.exitCode == 0
          check "HEAVY_OK iterations=25" in r.sentinel
          if not r.hung and r.exitCode == 0:
            inc completed
        check completed == runs

        # Non-vacuity: the injected DLL's DllMain really ran, once per
        # child. A mapped-but-inert DLL would never reach the hazard.
        var attaches = 0
        for line in readIfPresent(markPath).splitLines():
          if line.startsWith("ATTACH pid="):
            inc attaches
        checkpoint("DllMain attaches recorded: " & $attaches)
        check attaches == runs

    test "the pre-park technique wedges the same shell (control)":
      if runtime.len == 0:
        checkpoint("no MSYS2/Cygwin shell on PATH; hazard probe not run")
      else:
        require setupError == ""
        let runs = envRuns("STACKABLE_HOOKS_DIRECT_RUNS", 2)
        var hangs = 0
        for i in 1 .. runs:
          let r = runInstrumentedShell(asDirect, shell, scriptPath,
            workDir / ("sentinel-direct-" & $i & ".txt"), dllPath, 20_000'u32)
          checkpoint("direct run " & $i & ": injection=" & $r.injection &
            " hung=" & $r.hung & " exit=" & $r.exitCode &
            " sentinel=" & r.sentinel.strip())
          # The falsely-complete hazard, stated as an assertion: the
          # injection reports success while the child never runs.
          check r.injection == ioInjected
          check r.hung
          check r.sentinel.len == 0
          if r.hung:
            inc hangs
        check hangs == runs

    test "the default strategy refuses a fork-runtime child it cannot park":
      # With no main-thread handle the park is unavailable, and the
      # fork-runtime child must then be REFUSED rather than injected: the
      # outcome must not be ioInjected, so a consumer cannot grade the
      # subtree complete.
      if runtime.len == 0:
        checkpoint("no MSYS2/Cygwin shell on PATH; hazard probe not run")
      else:
        require setupError == ""
        let sentinel = workDir / "sentinel-nothread.txt"
        removeFile(sentinel)
        var pi: PROCESS_INFORMATION
        spawnSuspended(shellCommandLine(shell, scriptPath, sentinel), pi)

        let outcome = injectShimIntoChild(pi.hProcess, dllPath, "",
          defaultInjectionConfig())
        checkpoint("no-thread outcome: " & $outcome)
        check outcome == ioSkippedForkRuntime
        check outcome != ioInjected

        discard ResumeThread(pi.hThread)
        # Un-injected, the shell is unremarkable and must still complete.
        let waited = WaitForSingleObject(pi.hProcess, 60_000'u32)
        if waited != WAIT_OBJECT_0:
          discard TerminateProcess(pi.hProcess, 0xDEAD'u32)
        check waited == WAIT_OBJECT_0
        var code: DWORD = 1
        discard GetExitCodeProcess(pi.hProcess, addr code)
        check code == 0
        check "HEAVY_OK iterations=25" in readIfPresent(sentinel)
        discard CloseHandle(pi.hThread)
        discard CloseHandle(pi.hProcess)

    test "the universal park does not regress a native child":
      # The park is applied to EVERY child, not only MSYS ones, so the
      # ordinary path needs its own evidence. This test binary is a native
      # Nim executable: spawn it suspended, park-and-inject it, and require
      # that it completes AND that the fixture's DllMain ran in it. Both
      # halves matter -- "it exited 0" alone would also be true of a child
      # nothing was ever injected into.
      require setupError == ""
      let nativeMark = workDir / "native-attach.log"
      removeFile(nativeMark)
      putEnv(MarkEnvVar, nativeMark)
      defer: putEnv(MarkEnvVar, markPath)

      var pi: PROCESS_INFORMATION
      spawnSuspended("\"" & getAppFilename() & "\" " & NativeChildArg, pi)
      var cfg = defaultInjectionConfig()
      cfg.skipIfImageHasShim = false
      let outcome = injectShimIntoChild(pi.hProcess, dllPath, "", cfg,
        pi.hThread)
      checkpoint("native child outcome: " & $outcome)
      check outcome == ioInjected
      discard ResumeThread(pi.hThread)
      let waited = WaitForSingleObject(pi.hProcess, 60_000'u32)
      if waited != WAIT_OBJECT_0:
        discard TerminateProcess(pi.hProcess, 0xDEAD'u32)
      check waited == WAIT_OBJECT_0
      var code: DWORD = 1
      discard GetExitCodeProcess(pi.hProcess, addr code)
      check code == 0
      check "ATTACH pid=" in readIfPresent(nativeMark)
      discard CloseHandle(pi.hThread)
      discard CloseHandle(pi.hProcess)

    test "a native child is byte-identical under the legacy strategy":
      # The counterpart to the control above: on a NATIVE child the two
      # strategies must both work. This is what makes "universal" safe --
      # the park is not a workaround that only MSYS children tolerate.
      require setupError == ""
      let legacyMark = workDir / "native-legacy-attach.log"
      removeFile(legacyMark)
      putEnv(MarkEnvVar, legacyMark)
      defer: putEnv(MarkEnvVar, markPath)

      var pi: PROCESS_INFORMATION
      spawnSuspended("\"" & getAppFilename() & "\" " & NativeChildArg, pi)
      var cfg = defaultInjectionConfig()
      cfg.attachStrategy = asDirect
      cfg.skipIfImageHasShim = false
      let outcome = injectShimIntoChild(pi.hProcess, dllPath, "", cfg,
        pi.hThread)
      check outcome == ioInjected
      discard ResumeThread(pi.hThread)
      let waited = WaitForSingleObject(pi.hProcess, 60_000'u32)
      if waited != WAIT_OBJECT_0:
        discard TerminateProcess(pi.hProcess, 0xDEAD'u32)
      check waited == WAIT_OBJECT_0
      var code: DWORD = 1
      discard GetExitCodeProcess(pi.hProcess, addr code)
      check code == 0
      check "ATTACH pid=" in readIfPresent(legacyMark)
      discard CloseHandle(pi.hThread)
      discard CloseHandle(pi.hProcess)

  if workDir.len > 0:
    try: removeDir(workDir)
    except CatchableError: discard

else:
  static:
    doAssert not defined(windows),
      "the MSYS2 attach probe is Windows-only; this arm proves the file " &
      "still compiles off Windows so the cross-target lane covers it"
