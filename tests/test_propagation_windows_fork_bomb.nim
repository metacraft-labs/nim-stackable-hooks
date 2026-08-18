## Adversarial test: process-spawn stress at the framework level.
##
## Reproduces the webpack hang scenario at the framework boundary:
## N parent threads each call ``injectShimIntoChild`` rapidly in a
## tight loop. The bespoke pre-framework path (with
## ``WaitForSingleObject(INFINITE)``) would have wedged on the first
## call against a hung child. The framework's contract is:
##
##   - maxInFlight bounds concurrent injections so excess calls return
##     ``ioSkippedCap`` instead of adding loader-lock pressure.
##   - waitDeadlineMs bounds each wait so a hung child cannot wedge the
##     parent.
##   - releaseInFlight always runs so a failure does not leak a permit.
##
## Test shape: 32 threads x 64 calls each = 2,048 total calls, against
## a bogus child handle so CreateRemoteThread fails fast. Total wall
## clock time remains bounded even on a slow emulator.

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
  Cap = 4
  Deadline = 50'u32

var outcomes {.global.}: array[InjectionOutcome, Atomic[int]]
  ## One counter per InjectionOutcome. Worker threads write the
  ## counters and the main thread reads them after join.

proc injectionWorker(threadIdx: int) {.thread, gcsafe.} =
  discard threadIdx
  let bogus = cast[pointer](cast[uint](0xDEAD_BEEF_BAD0_F00D'u))
  let cfg = InjectionConfig(maxInFlight: Cap,
                            waitDeadlineMs: Deadline,
                            skipIfImageHasShim: false)
  for k in 0 ..< CallsPerThread:
    discard k
    let outcome = injectShimIntoChild(bogus,
      r"C:\nope\shim.dll", "", cfg)
    {.cast(gcsafe).}:
      discard outcomes[outcome].fetchAdd(1)

suite "propagation_windows_fork_bomb":
  test "32x64 concurrent injections complete in bounded time":
    for outcome in InjectionOutcome:
      outcomes[outcome].store(0)

    let start = getMonoTime()
    var threads: array[Threads, Thread[int]]
    for threadIndex in 0 ..< Threads:
      createThread(threads[threadIndex], injectionWorker, threadIndex)
    joinThreads(threads)
    let elapsed = inMilliseconds(getMonoTime() - start)

    var totalCounted = 0
    for outcome in InjectionOutcome:
      totalCounted += outcomes[outcome].load()
    check totalCounted == Threads * CallsPerThread

    # A nonempty library path and a bogus handle cannot produce a
    # successful or no-op outcome. ioSkippedCap is valid under
    # contention, but thread scheduling is not required to produce it.
    check outcomes[ioInjected].load() == 0
    check outcomes[ioAlreadyPresent].load() == 0
    check outcomes[ioNothingToInject].load() == 0

    # With Cap concurrent waits and Deadline per wait, this generous
    # upper bound catches unbounded waits while tolerating slow hosts.
    let upperBoundMs =
      (Threads * CallsPerThread div Cap) * int(Deadline) * 5
    check elapsed < upperBoundMs

  test "no permit leaks after concurrent failures":
    let bogus = cast[pointer](cast[uint](0xCAFE_F00D'u))
    let cfg = InjectionConfig(maxInFlight: Cap,
                              waitDeadlineMs: Deadline,
                              skipIfImageHasShim: false)
    let final = injectShimIntoChild(bogus, r"C:\post\storm.dll", "", cfg)
    check final != ioSkippedCap
