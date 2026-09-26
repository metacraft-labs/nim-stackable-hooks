# Deadlines on a borrowed parked thread (Windows)

Status: implemented. This note is the specification for how
`windows_entry_park` and its callers treat a slow child. The code docstrings
point back here.

## Background

`injectShimIntoChild` and `runWithMonitorShim` inject the shim by *borrowing*
the child's parked main thread (`windows_entry_park.callOnParkedThread`). They
save its `CONTEXT`, point `RIP` at `LoadLibraryW` (and later at the shim's init
export), resume the thread, and wait for it to return to the `EB FE` at the
image entry point. When it returns they restore the saved `CONTEXT`, so the
thread is back exactly as the park left it.

While a borrowed call runs, the thread's context is **lent out**. Its `RSP`
points below the parked frame, its volatile registers belong to the callee, and
the shim's hooks may be half-installed. The only safe exits from that state are:

1. the call returns to the self-jump and the saved context is restored, or
2. the child is dead.

## The defect

Both the park and the borrowed call had a fixed 5 s deadline
(`parkTimeoutMs = 5000`). When a borrowed call missed it, the thread was
suspended mid-call and `false` was returned. The caller then restored the entry
bytes (`releaseEntryPark`) and resumed the thread. The child finished the
borrowed call and `ret`urned into its real entry point, on the borrowed stack
(`RSP` 8 bytes off the Win64 entry alignment, volatile registers clobbered),
with hooks possibly half-armed. Then it crashed.

A deadline is not proof of a hang. On an I/O-starved host (4 KB writes taking
minutes), `LoadLibraryW` of the shim plus `repro_runtime_init` can take longer
than 5 s in a perfectly healthy child. The recovery path turned that slow child
into a corrupted one. The failure was reported as `ioInitFailed` or
`ioInjectFailed`, which looks like a harmless monitoring miss, not a corruption.

## Rules

R1. **A slow child is not a hung child.** While the borrowed call runs and the
    child process is alive, the wait continues. The deadline is a last resort
    for a genuinely wedged child, not a performance budget. The default
    (`DefaultInjectDeadlineMs`) is 10 minutes, and `INFINITE` (`0xFFFFFFFF`)
    means "wait as long as the child lives".

R2. **A thread whose context is lent out is never resumed.** If the hard
    deadline expires mid-call, or the saved context cannot be restored after a
    call, the child is *poisoned*. `windows_entry_park` itself then:
    - suspends the thread a second time, so a caller's unconditional
      `ResumeThread` still leaves it suspended, and
    - terminates the child with `InjectionAbandonedExitCode`
      (`0xC00000B5`, `STATUS_IO_TIMEOUT`) and waits for it to die.

    The callers do not have to get this right for the child to be safe.

R3. **The spawn fails cleanly and visibly.** A poisoned child is reported as
    its own outcome (`bcsPoisoned` from the borrow, `ioChildTerminated` from
    `injectShimIntoChild`), never folded into `ioInjectFailed` or
    `ioInitFailed`. A `CreateProcess` hook that sees it must fail the
    `CreateProcess` call. It returns `FALSE`, sets the last error to
    `ERROR_TIMEOUT` (1460), closes the handles, and zeroes
    `PROCESS_INFORMATION`, so the caller sees a spawn that failed rather than
    a child that later dies. `runWithMonitorShim` raises, as it already did.

R4. **Every other failure stays sound.** If a borrow fails before the thread
    ran (bad arguments, `SetThreadContext` failed, `ResumeThread` failed and
    the context was restored), the child is intact. It is reported as a failed
    injection, exactly as before, and the child runs unmonitored. A call that
    returned but whose result could not be read also leaves the child intact,
    provided the saved context was restored.

R5. **The park itself uses the same deadline.** A park that misses its
    deadline was already safe: the thread is suspended before it reaches user
    code, and the entry bytes are restored under the suspension, so the child
    runs unmonitored (`ioParkFailed`). Only the deadline value changes, so a
    slow loader is no longer mistaken for a wedged one.

R6. **Slowness is observable.** `injectShimIntoChildReport` returns the time
    spent waiting on the child. A consumer can annotate its records when that
    time exceeds `SlowInjectionNoticeMs` (5 s), which is the old deadline.
    Nothing is written to the child's or the parent's stdio, because a
    monitored build's stderr is part of its observable output.

## Test obligations

- A borrowed call that is slower than the old 5 s deadline (a real
  `kernel32!Sleep` in a real child) completes, and the child then runs its own
  `main` to its own exit code.
- A borrowed call that outlives a short hard deadline yields `bcsPoisoned`.
  The child is dead with `InjectionAbandonedExitCode`. A subsequent
  `releaseEntryPark` + `ResumeThread`, which is exactly what every caller
  does, does not bring it back, and the child's own exit code is never
  observed.
- The same two cases through `injectShimIntoChild`, using a real fixture DLL
  whose load really sleeps: `ioInjected` with a normal child, and
  `ioChildTerminated` with a dead child.
- `autoPropagateCreateProcessW` fails the `CreateProcessW` call with
  `ERROR_TIMEOUT` for a poisoned child.
