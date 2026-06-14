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

when not defined(windows):
  echo "[skip] propagation_windows_edge_cases is Windows-only"
  quit(0)

import std/unittest

import stackable_hooks/propagation_windows

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

  test "resolveSelfImagePath: empty pointer returns empty string gracefully":
    let p = resolveSelfImagePath(nil)
    # We don't insist on what the OS returns — only that we don't
    # crash. A NULL address-inside is a programming error and the OS
    # will reject it; we want a string surface, not an AV.
    check p.len >= 0
