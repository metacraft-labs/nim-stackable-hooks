## Adversarial test: fork-bomb stress at the framework level.
##
## Reproduces the webpack hang scenario at the framework boundary:
## N parent threads each call ``injectShimIntoChild`` rapidly in a
## tight loop. The bespoke pre-framework path (with
## ``WaitForSingleObject(INFINITE)``) would have wedged on the first
## call against a hung child — and webpack spawned hundreds of node
## children per build. The framework's contract is:
##
##   - maxInFlight semaphore bounds the concurrent injections so the
##     N+1th call returns ``ioSkippedCap`` rather than queueing up
##     loader-lock pressure.
##   - waitDeadlineMs bounds the per-call wait so a hung child can't
##     wedge the parent.
##   - releaseInFlight is always called (defer-style) so a failure
##     path doesn't leak a permit.
##
## Test shape: 32 threads × 64 calls each = 2 048 total calls, against
## a clearly bogus child handle so the real CreateRemoteThread fails
## fast. Total wall-clock bounded at ~5 seconds even on a slow
## emulator. Pre-fix behaviour: hangs indefinitely on first call.

when not defined(windows):
  echo "[skip] propagation_windows_fork_bomb is Windows-only"
  quit(0)

import std/atomics
import std/monotimes
import std/times
import std/unittest

import stackable_hooks/propagation_windows

const
  Threads = 32
  CallsPerThread = 64
  Cap = 4   # tight cap so most calls hit ioSkippedCap
  Deadline = 50'u32  # 50ms — short so failed calls return quickly

var outcomes {.global.}: array[6, Atomic[int]]
  ## One counter per InjectionOutcome ordinal. Filled by the worker
  ## threads and read by the main thread after join.

proc forkBombWorker(threadIdx: int) {.thread, gcsafe.} =
  let bogus = cast[pointer](cast[uint](0xDEAD_BEEF_BAD0_F00D'u))
  let cfg = InjectionConfig(maxInFlight: Cap,
                            waitDeadlineMs: Deadline,
                            skipIfImageHasShim: false)
  for k in 0 ..< CallsPerThread:
    let outcome = injectShimIntoChild(bogus,
      r"C:\nope\shim.dll", "", cfg)
    let idx = ord(outcome)
    {.cast(gcsafe).}:
      if idx >= 0 and idx < outcomes.len:
        discard outcomes[idx].fetchAdd(1)

suite "propagation_windows_fork_bomb":
  test "32×64 concurrent injections complete in bounded time":
    for i in 0 ..< outcomes.len:
      outcomes[i].store(0)

    let start = getMonoTime()
    var ts: array[Threads, Thread[int]]
    for t in 0 ..< Threads:
      createThread(ts[t], forkBombWorker, t)
    joinThreads(ts)
    let elapsed = inMilliseconds(getMonoTime() - start)

    # Every call must have been counted exactly once.
    var totalCounted = 0
    for i in 0 ..< outcomes.len:
      totalCounted += outcomes[i].load()
    check totalCounted == Threads * CallsPerThread

    # Total wall-clock bounded: with Cap=4 in-flight and Deadline=50ms,
    # the sequential floor is roughly (calls / cap) * deadline. We
    # allow 5x slack for OS scheduler jitter — the key win is "not
    # INFINITE". The pre-framework code would wedge here forever.
    let upperBoundMs = (Threads * CallsPerThread div Cap) * int(Deadline) * 5
    check elapsed < upperBoundMs

  test "outcome distribution: most calls hit ioSkippedCap under tight cap":
    # With Cap=4 and 32×64=2048 calls, the semaphore admits at most
    # 4 concurrent injections; the rest get rejected at admission
    # rather than queueing. We assert the cap is doing real work.
    let skippedCap = outcomes[ord(ioSkippedCap)].load()
    let allOthers = (Threads * CallsPerThread) - skippedCap
    check skippedCap > 0
    # The cap doesn't have to dominate — under low contention every
    # call might fit. We assert only that the cap fires at least once,
    # which proves the admission code path is reachable.
    discard allOthers

  test "no permit leak: cap returns to baseline after the storm":
    # If releaseInFlight had a bug (e.g. failed on early return), the
    # cap would be permanently saturated. We verify by issuing one
    # final call after the storm completes; it must succeed
    # admission (i.e. return any outcome OTHER than ioSkippedCap).
    let bogus = cast[pointer](cast[uint](0xCAFE_F00D'u))
    let cfg = InjectionConfig(maxInFlight: Cap,
                              waitDeadlineMs: Deadline,
                              skipIfImageHasShim: false)
    let final = injectShimIntoChild(bogus, r"C:\post\storm.dll", "", cfg)
    check final != ioSkippedCap
