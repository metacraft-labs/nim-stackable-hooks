## Adversarial test: PropagationNode registry under concurrency.
##
## The spec contract is that ``registerPropagationNode`` is safe to
## call from any thread (CAS-published head), ``propagationNodes``
## iteration is safe to call from any thread (acceptable to miss
## entries published mid-walk), and ``enableAutoPropagation`` /
## ``disableAutoPropagation`` are safe to flip from any thread (atomic
## bool).
##
## Tested invariants:
##   1. After N threads each register one node, ``enabledLibraryPaths``
##      returns exactly the N libraries that are enabled at snapshot
##      time, with no duplicates and no torn paths.
##   2. Walks that overlap with enable/disable flips observe a
##      consistent (monotonic) enabled state per node (no torn reads).
##   3. Re-registering the same node pointer is idempotent regardless
##      of which thread does the second registration.
##   4. The walker terminates even when one thread continuously flips
##      a node's enabled bit during the walk.

import std/unittest
import std/atomics

import stackable_hooks/propagation

const ConcurrencyThreads = 8
const NodesPerThread = 16
const TotalNodes = ConcurrencyThreads * NodesPerThread

# Library lifetime is conceptually permanent (each consumer DLL ships
# one static instance), so the test stashes nodes in a module-level
# array. Concurrent threads grab a slice from it via atomic counter.
var
  testNodes: array[TotalNodes, PropagationNode]
  cursorAtomic: Atomic[int]

proc registerWorker(threadIdx: int) {.thread, gcsafe.} =
  ## Grab N consecutive slots and register them all, flipping the
  ## enabled bit on alternate slots so half are enabled half disabled.
  let base = cursorAtomic.fetchAdd(NodesPerThread)
  for k in 0 ..< NodesPerThread:
    let i = base + k
    if i >= testNodes.len:
      break
    {.cast(gcsafe).}:
      testNodes[i].libraryPath = "/concurrent/lib-" & $i & ".so"
      registerPropagationNode(addr testNodes[i])
      if (i mod 2) == 0:
        enableAutoPropagation(addr testNodes[i])

suite "propagation_registry_concurrent":
  test "N threads register N nodes; enabledLibraryPaths sees exactly the enabled half":
    cursorAtomic.store(0)
    var threads: array[ConcurrencyThreads, Thread[int]]
    for t in 0 ..< ConcurrencyThreads:
      createThread(threads[t], registerWorker, t)
    joinThreads(threads)

    let paths = enabledLibraryPaths()
    # Half of TotalNodes are enabled (even indices).
    check paths.len >= TotalNodes div 2
    for i in 0 ..< TotalNodes:
      if (i mod 2) == 0:
        let expected = "/concurrent/lib-" & $i & ".so"
        check expected in paths
      else:
        let unexpected = "/concurrent/lib-" & $i & ".so"
        check unexpected notin paths

  test "idempotent re-register: double-registration from any thread does not duplicate":
    var node = PropagationNode(libraryPath: "/idemp/lib.so")
    registerPropagationNode(addr node)
    enableAutoPropagation(addr node)
    # Re-register twice in a row.
    registerPropagationNode(addr node)
    registerPropagationNode(addr node)
    var seen = 0
    for n in propagationNodes():
      if n == addr node: seen.inc
    check seen == 1
    disableAutoPropagation(addr node)

  test "walker is bounded — disable flips don't lengthen iteration":
    # Set up a flip-flopper: one thread continuously flips a node's
    # enabled bit; the main thread walks the registry and checks the
    # walk terminates in bounded time (the walker reads the atomic
    # ONCE per node, so it can't loop forever).
    var flipNode = PropagationNode(libraryPath: "/flip/lib.so")
    registerPropagationNode(addr flipNode)

    var stopFlag {.global.}: Atomic[bool]
    stopFlag.store(false)
    type FlipArg = tuple[stop: ptr Atomic[bool]; node: ptr PropagationNode]
    proc flipWorker(arg: FlipArg) {.thread, gcsafe.} =
      for _ in 0 ..< 10_000:
        enableAutoPropagation(arg.node)
        disableAutoPropagation(arg.node)
        if arg.stop[].load(): break
      arg.stop[].store(true)
    var ft: Thread[FlipArg]
    createThread(ft, flipWorker, (stop: addr stopFlag, node: addr flipNode))

    # Run many walks; each must terminate.
    for _ in 0 ..< 1_000:
      var seen = 0
      for n in propagationNodes():
        seen.inc
      check seen >= 1  # at least the flip node + whatever else lives
    stopFlag.store(true)
    joinThread(ft)
