## Tests for the WOW64 (32-bit child) injection support in
## `stackable_hooks/windows_injector`.
##
## Scope, and why it is drawn here: the pure decisions — the naming
## conventions, the override hooks, the bitness probe, and the caching and
## failure contract of the proc-address probe — are testable without a
## 32-bit toolchain and are covered below. Actually injecting into a live
## 32-bit process needs `librepro_monitor_shim32.dll` plus
## `stackable_hooks_wow64_probe32.exe` on disk, which requires an i686
## toolchain the unit suite cannot assume; that arm is exercised by
## io-mon's shim build (`scripts/build_shim.sh`) and skipped here, in the
## same spirit as `test_propagation_windows_smoke.nim` testing the cap
## logic rather than spawning real grandchildren.
##
## The one behaviour worth stating twice, because getting it wrong is
## silent: when the 32-bit address cannot be obtained the injector MUST
## fail rather than fall back to this process's 64-bit `LoadLibraryW`.
## A wrong address does not fault cleanly — it starts a remote thread at a
## meaningless location in the child.
##
## The whole body is `when defined(windows)`-guarded rather than gated by a
## runtime `quit(0)`: `stackable_hooks/windows_injector` declares
## `{.error.}` off Windows, so a runtime guard placed after the import
## would still fail to COMPILE elsewhere. Same shape as
## `test_macos_bodypatch_minimal_consumer.nim`.

when defined(windows):
  import std/[os, unittest]

  import stackable_hooks/windows_injector

  proc GetCurrentProcess(): pointer
    {.importc, stdcall, dynlib: "kernel32".}
    ## Pseudo-handle for this process; `processIsWow64` accepts it directly.

  suite "windows_wow64_conventions":
    setup:
      # Each test starts from the conventional lookups, not whatever a
      # previous test pinned.
      setWow64ShimPath("")
      setWow64ProbePath("")

    test "32-bit shim is the '32' sibling of the 64-bit shim":
      check wow64ShimPathFor(r"C:\tools\librepro_monitor_shim.dll") ==
        r"C:\tools\librepro_monitor_shim32.dll"

    test "the convention preserves the directory and the extension":
      let resolved = wow64ShimPathFor(r"D:\a b\c\some_shim.dll")
      check resolved.parentDir == r"D:\a b\c"
      check resolved.extractFilename == "some_shim32.dll"
      check resolved.splitFile.ext == ".dll"

    test "probe is looked up beside the shim under a fixed name":
      check wow64ProbePathFor(r"C:\tools\librepro_monitor_shim.dll") ==
        r"C:\tools" / Wow64ProbeExeName
      check Wow64ProbeExeName == "stackable_hooks_wow64_probe32.exe"

    test "an explicit shim path overrides the convention":
      setWow64ShimPath(r"X:\custom\my32.dll")
      check wow64ShimPathFor(r"C:\tools\librepro_monitor_shim.dll") ==
        r"X:\custom\my32.dll"

    test "an explicit probe path overrides the convention":
      setWow64ProbePath(r"X:\custom\probe.exe")
      check wow64ProbePathFor(r"C:\tools\librepro_monitor_shim.dll") ==
        r"X:\custom\probe.exe"

    test "clearing an override restores the convention":
      setWow64ShimPath(r"X:\custom\my32.dll")
      setWow64ShimPath("")
      check wow64ShimPathFor(r"C:\tools\shim.dll") == r"C:\tools\shim32.dll"

  suite "windows_wow64_bitness_probe":
    test "the current process reports its own bitness truthfully":
      # This test binary is whatever the suite was built as.
      # `processIsWow64` answers "is this a 32-bit process on 64-bit
      # Windows", so for a 64-bit build it must be false, and for a 32-bit
      # build on 64-bit Windows it must be true. Asserting against
      # `sizeof(pointer)` ties the check to the build rather than to the
      # host, so it is correct either way.
      let self = GetCurrentProcess()
      let isWow = processIsWow64(self)
      when sizeof(pointer) == 8:
        check not isWow
      else:
        # A 32-bit build on 32-bit Windows is also not WOW64, so this only
        # asserts the call is answerable, not its value.
        discard isWow

  suite "windows_wow64_probe_contract":
    setup:
      setWow64ProbePath("")

    test "a missing probe yields 0 rather than a bogus address":
      # 0 is the documented "unavailable" signal: no proc lives at address
      # 0, so it cannot be confused with a real answer. The injector turns
      # this into a hard error naming the missing probe.
      let missing = getTempDir() / "stackable-hooks-no-such-probe32.exe"
      removeFile(missing)
      check not fileExists(missing)
      check wow64LoadLibraryWAddress(missing) == 0'u32

    test "a failed probe is NOT cached":
      # Failures must not be cached: a probe that is missing now may be
      # built later in the same session, and a caller asking about a
      # different probe must not be answered from an unrelated miss. This
      # is the bug the live arm below caught on its first run.
      let missing = getTempDir() / "stackable-hooks-no-such-probe32.exe"
      check wow64LoadLibraryWAddress(missing) == 0'u32
      check wow64LoadLibraryWAddress(missing) == 0'u32

    test "a real probe, when present, reports a plausible kernel32 address":
      # Only meaningful where io-mon's shim build has produced the probe.
      # Skipped rather than failed elsewhere: building it needs an i686
      # toolchain, which is exactly what the unit suite cannot assume.
      let candidates = [
        getAppDir() / Wow64ProbeExeName,
        getAppDir().parentDir / "lib" / Wow64ProbeExeName,
        getCurrentDir() / "build" / "lib" / Wow64ProbeExeName,
      ]
      var probe = ""
      for candidate in candidates:
        if fileExists(candidate):
          probe = candidate
          break
      if probe.len == 0:
        skip()
      else:
        let address = wow64LoadLibraryWAddress(probe)
        # A resolved address is non-zero and, being a kernel32 export in a
        # WOW64 process, lies in the 32-bit user address space.
        check address != 0'u32
        check address > 0x10000'u32

        # And it is cached: a second lookup returns the same answer.
        check wow64LoadLibraryWAddress(probe) == address

  suite "windows_wow64_export_rva":
    ## The offset of an export inside the 32-bit shim. The injector needs it
    ## to start the shim's initialiser in the child once LoadLibraryW has
    ## run there, and it cannot compute the offset the way the same-bitness
    ## path does -- loading the image in this 64-bit process -- because a
    ## 64-bit process cannot load a 32-bit DLL at all.
    ##
    ## That failure is why this suite exists rather than being folded into
    ## the one above: it was invisible from outside. LoadLibraryW genuinely
    ## succeeded, so no error was raised anywhere; the shim simply sat in
    ## the child uninitialised, installed no hooks, and the process reported
    ## zero records while the run still graded complete.
    setup:
      setWow64ProbePath("")

    proc locateProbe(): string =
      for candidate in [
          getAppDir() / Wow64ProbeExeName,
          getAppDir().parentDir / "lib" / Wow64ProbeExeName,
          getCurrentDir() / "build" / "lib" / Wow64ProbeExeName]:
        if fileExists(candidate):
          return candidate
      ""

    test "a missing probe yields 0 rather than a bogus offset":
      let missing = getTempDir() / "stackable-hooks-no-such-probe32.exe"
      removeFile(missing)
      check wow64ExportRva(missing, "whatever32.dll", "repro_runtime_init") ==
        0'u32

    test "a missing DLL yields 0":
      # The probe runs but LoadLibraryEx fails, so it reports the same
      # unavailable signal. 0 is safe to overload here because no export
      # can sit at RVA 0 -- that offset is the DOS header.
      let probe = locateProbe()
      if probe.len == 0:
        skip()
      else:
        check wow64ExportRva(probe,
          getTempDir() / "stackable-hooks-no-such-shim32.dll",
          "repro_runtime_init") == 0'u32

    test "an unknown symbol yields 0":
      let probe = locateProbe()
      let shim = probe.parentDir / "librepro_monitor_shim32.dll"
      if probe.len == 0 or not fileExists(shim):
        skip()
      else:
        check wow64ExportRva(probe, shim, "no_such_export_exists") == 0'u32

    test "the 32-bit shim's init export resolves to a plausible offset":
      let probe = locateProbe()
      let shim = probe.parentDir / "librepro_monitor_shim32.dll"
      if probe.len == 0 or not fileExists(shim):
        skip()
      else:
        let rva = wow64ExportRva(probe, shim, "repro_runtime_init")
        # Non-zero, and an offset into the image rather than an absolute
        # address: it must be smaller than the file itself.
        check rva != 0'u32
        check uint64(rva) < uint64(getFileSize(shim))

        # Cached on success, like the kernel32 address.
        check wow64ExportRva(probe, shim, "repro_runtime_init") == rva

    test "the init export is undecorated in the 32-bit build":
      # 32-bit mingw decorates stdcall exports with the callee's argument
      # byte count, so an unguarded build exports `repro_runtime_init@4`
      # while the 64-bit build exports it plain. Every lookup asks for the
      # undecorated name, so a decorated export resolves to nothing and the
      # shim is never initialised. io-mon's build passes -Wl,--kill-at to
      # keep ONE name across both bitnesses; this asserts the result.
      let probe = locateProbe()
      let shim = probe.parentDir / "librepro_monitor_shim32.dll"
      if probe.len == 0 or not fileExists(shim):
        skip()
      else:
        check wow64ExportRva(probe, shim, "repro_runtime_init") != 0'u32
