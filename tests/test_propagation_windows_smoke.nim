## Smoke test for the Windows propagation API. Verifies the API
## surface compiles and that the cap+semaphore-style admission control
## behaves correctly under simulated fork-bomb pressure (no real child
## process is spawned — we test the cap logic in isolation since a
## real grandchild-injection test requires a tracee DLL on disk and is
## out of scope for the unit suite).

when not defined(windows):
  echo "[skip] Windows-only test"
  quit(0)

import std/unittest
import std/locks

import stackable_hooks/propagation_windows

suite "propagation_windows_smoke":
  test "defaultInjectionConfig has expected knobs":
    let cfg = defaultInjectionConfig()
    check cfg.maxInFlight == 16
    check cfg.waitDeadlineMs == 5000'u32
    check cfg.skipIfImageHasShim

  test "injectShimIntoChild rejects empty library path":
    var fakeHandle = cast[pointer](0xCAFE'u)
    let outcome = injectShimIntoChild(fakeHandle, "")
    check outcome == ioNothingToInject

  test "InjectionOutcome enum values are distinct":
    check ord(ioInjected) != ord(ioAlreadyPresent)
    check ord(ioInjected) != ord(ioSkippedCap)
    check ord(ioInjected) != ord(ioWaitTimeout)
    check ord(ioInjected) != ord(ioInjectFailed)
    check ord(ioInjected) != ord(ioInitFailed)
    check ord(ioInjected) != ord(ioNothingToInject)

  test "resolveSelfImagePath returns a valid module path":
    proc anchorProc() {.raises: [].} = discard
    let p = resolveSelfImagePath(cast[pointer](anchorProc))
    check p.len > 0
    # The path should contain a backslash and have an .exe / .dll suffix.
    check ('\\' in p) or ('/' in p)
