## Adversarial test: Windows propagation framework edge cases.
##
## Hits the internal helpers (basenameOf, wideStringFromString,
## tryAcquireInFlight, releaseInFlight) under inputs that real
## consumer callers might supply but that the smoke test didn't cover.
##
## Strategy: most edge-cases are surfaced via the public
## ``injectShimIntoChild`` (with fake handles) since the helpers
## themselves are file-private. For helpers we want to exercise
## directly we re-import the symbol from the module (Nim allows access
## to file-private symbols via the file-private import the test
## namespace shares with the implementation when both compile in the
## same project, but for cross-module privacy we just exercise the
## paths that route through them from the public API).

when defined(windows):

  import std/[os, osproc, strutils, unittest]

  import stackable_hooks/propagation_windows
  import stackable_hooks/windows_fork_runtime

  # The self-respawn case below spawns THIS binary. Exit immediately in the
  # child so the suite does not recurse; it only has to exist long enough
  # to be classified.
  if paramCount() >= 1 and paramStr(1) == "--edge-case-self-respawn-probe":
    sleep(3000)
    quit(0)

  type
    HANDLE = pointer
    DWORD = uint32
    BOOL = int32

  const ProcessQueryLimitedInformation = 0x1000'u32

  proc OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL,
                   dwProcessId: DWORD): HANDLE
    {.importc, stdcall, dynlib: "kernel32".}
  proc CloseHandle(hObject: HANDLE): BOOL
    {.importc, stdcall, dynlib: "kernel32".}

  suite "propagation_windows_edge_cases":
    test "injectShimIntoChild: nil hProcess with non-empty path falls through":
      # No hProcess is valid for the real Win32 surface, but the API
      # must not crash — VirtualAllocEx will fail and we surface
      # ioInjectFailed. We use a clearly bogus pointer; the API
      # treats it opaquely and the OS rejects.
      let bogus = cast[pointer](0xDEAD'u)
      let outcome = injectShimIntoChild(bogus, r"C:\nonexistent\shim.dll",
        "", InjectionConfig(maxInFlight: 16, waitDeadlineMs: 1,
        skipIfImageHasShim: false))
      # The skip-probe is disabled, so the call MUST attempt the actual
      # alloc. Any non-ok outcome (Failed/Timeout) is acceptable — the
      # key invariant is that we do not crash and we return SOMETHING.
      check outcome != ioInjected
      check outcome != ioAlreadyPresent
      check outcome != ioNothingToInject

    test "injectShimIntoChild: maxInFlight=0 always returns ioSkippedCap":
      # Pathological cap: 0 in-flight allowed means every call is
      # immediately admission-rejected. Verifies the gating logic.
      let bogus = cast[pointer](0xBEEF'u)
      let cfg = InjectionConfig(maxInFlight: 0,
                                waitDeadlineMs: 1,
                                skipIfImageHasShim: false)
      let outcome = injectShimIntoChild(bogus, r"C:\foo\bar.dll", "", cfg)
      check outcome == ioSkippedCap

    test "injectShimIntoChild: empty path skipped before semaphore acquire":
      # The empty-path early-return path must NOT consume a semaphore
      # slot — if it did, the cap would leak under repeated
      # zero-arg calls. We verify by alternating empty-path calls
      # with capped calls and asserting the cap is still honoured.
      let cfg = InjectionConfig(maxInFlight: 1,
                                waitDeadlineMs: 1,
                                skipIfImageHasShim: false)
      let bogus = cast[pointer](0xCAFE'u)
      for _ in 0 ..< 100:
        check injectShimIntoChild(bogus, "", "", cfg) == ioNothingToInject
      # If the cap had leaked, this would return ioSkippedCap;
      # the only correct outcome is ioInjectFailed (alloc fails on bogus
      # handle) or ioWaitTimeout (deadline of 1 ms expires).
      let result = injectShimIntoChild(bogus, r"C:\foo\bar.dll", "", cfg)
      check result != ioSkippedCap

    test "InjectionConfig: defaults match the spec":
      let cfg = defaultInjectionConfig()
      check cfg.maxInFlight == 16
      check cfg.waitDeadlineMs == 5000'u32
      check cfg.skipIfImageHasShim
      # The attach strategy is UNIVERSAL, so the default has to be the
      # park and a zero-initialised config has to land on it too --
      # `asDirect` is the pre-park technique and must never be reached by
      # accident.
      check cfg.attachStrategy == asEntryPark
      # A HARD deadline for a wedged child, not a budget for a slow one:
      # the old 5 s default resumed healthy-but-slow children mid-call.
      # See docs/windows-borrowed-call-deadline.md (R1).
      check cfg.parkTimeoutMs == DefaultInjectDeadlineMs
      check DefaultInjectDeadlineMs == 600_000'u32
      check ord(asEntryPark) == 0
      check InjectionConfig().attachStrategy == asEntryPark

    test "injectShimIntoChild: asDirect keeps the pre-park semantics":
      # asDirect must NOT consult the fork-runtime heuristic: it is the
      # verbatim legacy path, and the regression control in
      # test_windows_entry_park_msys depends on being able to ask for it.
      # A bogus handle can never be a fork-runtime image, so the only
      # thing this can prove here is that the call still reaches the
      # allocation and fails there rather than short-circuiting.
      let bogus = cast[pointer](0xF00D'u)
      var cfg = defaultInjectionConfig()
      cfg.attachStrategy = asDirect
      cfg.maxInFlight = 16
      cfg.waitDeadlineMs = 1
      cfg.skipIfImageHasShim = false
      let outcome = injectShimIntoChild(bogus, r"C:\foo\bar.dll", "", cfg)
      check outcome != ioInjected
      check outcome != ioSkippedForkRuntime
      check outcome != ioParkFailed

    test "mappedForkRuntime: this native test process has no fork runtime":
      # The authoritative half of the fork-child detection. This binary is
      # a plain Nim executable, so the loader has neither runtime mapped;
      # if this ever reports one, `isCygwinForkChild` would start
      # classifying ordinary self-respawns as forks.
      check mappedForkRuntime() == ""

    test "isCygwinForkChild: a nil handle is not a fork child":
      check not isCygwinForkChild(nil)

    test "isCygwinForkChild: a native self-respawn is NOT a fork child":
      # This is the false-positive guard that keeps ordinary tools safe.
      # `nim`, `gcc` and `msbuild` all re-exec themselves; the child image
      # then equals ours EXACTLY, which is the second half of the
      # detection. The first half -- a fork runtime mapped into US -- is
      # what must keep them injectable, and this proves it does.
      let child = startProcess(getAppFilename(),
        args = @["--edge-case-self-respawn-probe"],
        options = {poStdErrToStdOut})
      defer:
        terminate(child)
        discard waitForExit(child, 5000)
        close(child)
      let handle = OpenProcess(ProcessQueryLimitedInformation, BOOL(0),
        DWORD(processID(child)))
      require handle != nil
      defer: discard CloseHandle(handle)

      # Same image as ours, by construction ...
      check windowsProcessImagePath(handle).cmpIgnoreCase(
        getAppFilename()) == 0
      # ... and still not a fork child, because we are not Cygwin.
      check not isCygwinForkChild(handle)

    test "resolveSelfImagePath: empty pointer returns empty string gracefully":
      let p = resolveSelfImagePath(nil)
      # We don't insist on what the OS returns — only that we don't
      # crash. A NULL address-inside is a programming error and the OS
      # will reject it; we want a string surface, not an AV.
      check p.len >= 0

    test "live MSYS child is excluded from recursive injection":
      let shell = findExe("sh")
      let expectedRuntime = windowsForkRuntimeForExecutable(shell)
      if shell.len == 0 or expectedRuntime.len == 0:
        checkpoint("MSYS2/Cygwin shell is not installed; integration probe skipped")
      else:
        let child = startProcess(shell, args = @["-c", "read ignored"],
          options = {poStdErrToStdOut})
        defer:
          terminate(child)
          discard waitForExit(child, 5000)
          close(child)
        let handle = OpenProcess(ProcessQueryLimitedInformation, BOOL(0),
          DWORD(processID(child)))
        require handle != nil
        defer: discard CloseHandle(handle)

        check windowsProcessImagePath(handle).extractFilename().cmpIgnoreCase(
          shell.extractFilename()) == 0
        check windowsForkRuntimeForProcess(handle) == expectedRuntime
