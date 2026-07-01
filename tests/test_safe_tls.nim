## Verifies the pthread-backed hostile-context-safe thread-local:
##   * distinct keys are independent,
##   * a value set on one thread is invisible to another (per-thread isolation).
## (The malloc-safety-from-inside-libmalloc property is validated end-to-end in
## the consuming shim's suite — see io-mon's mmap-reentrancy regression — since it
## needs a real interpose hook reached from inside the allocator.)

import std/unittest
import stackable_hooks/safe_tls

# Module-level state so thread procs (which cannot capture locals) can use it.
var gTls = stackableSafeTlsCreate()
var gResults: array[4, uint]

proc worker(i: int) {.thread.} =
  doAssert gTls.get == 0'u          # this thread has never set it
  gTls.set(uint(100 + i))
  gResults[i] = gTls.get

suite "safe_tls (pthread-backed hostile-context-safe TLS)":
  test "distinct keys are independent on one thread":
    let a = stackableSafeTlsCreate()
    let b = stackableSafeTlsCreate()
    check a.isValid and b.isValid
    check a.get == 0'u and b.get == 0'u          # zero until first set
    a.set(11)
    b.set(22)
    check a.get == 11'u
    check b.get == 22'u
    a.set(33)
    check a.get == 33'u
    check b.get == 22'u                            # b untouched

  when compileOption("threads"):
    test "values are isolated per thread":
      gTls.set(1000)                               # main thread's value
      var threads: array[4, Thread[int]]
      for i in 0 ..< 4:
        createThread(threads[i], worker, i)
      joinThreads(threads)
      for i in 0 ..< 4:
        check gResults[i] == uint(100 + i)
      check gTls.get == 1000'u                      # main thread unchanged
