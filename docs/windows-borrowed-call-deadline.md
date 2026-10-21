# Deadlines on a borrowed parked thread (Windows)

Status: implemented. This note is the specification for how
`windows_entry_park` treats a borrowed call that misses its deadline, and for
how its callers turn that into a policy. The code docstrings point back here.

## Background

`injectShimIntoChild` and `runWithMonitorShim` inject the shim by _borrowing_
the child's parked main thread (`windows_entry_park.borrowParkedThread`). They
save its `CONTEXT`, point `RIP` at a small **call stub** written into the
child, resume the thread, and wait for it to return to the `EB FE` at the image
entry point. The stub is

```
    sub rsp, 20h          ; callee home space, keeps the Win64 alignment
    mov rax, <fn>
    call rax              ; a REAL call: balances the CET shadow stack
    mov rsp, <parked RSP> ; the stub restores the parked stack itself
    mov rcx, <parked RCX> ; ...and the entry point's one argument
    mov r11, <entry>
    jmp r11               ; land on the EB FE at the real entry point
```

When the thread comes back to the entry point's self-jump, `RAX` holds `fn`'s
result and the saved `CONTEXT` is put back, so the thread ends up suspended
exactly as the park left it.

While a borrowed call runs, the thread's context is **lent out**. Its `RSP`
points below the parked frame, its volatile registers belong to the callee, and
the shim's hooks may be half-installed. The only safe exits from that state are:

1. the call returns to the self-jump and the saved context is restored;
2. the call is **detached** (below), which uses the stub's own tail to carry
   the thread into the child's real entry point; or
3. the child is dead.

## The defect, and the earlier over-correction

Both the park and the borrowed call once had a fixed 5 s deadline. When a
borrowed call missed it, the thread was suspended mid-call and `false` was
returned; every caller then restored the entry bytes and resumed the thread.
The child finished the borrowed call and `ret`urned into its real entry point
on the borrowed stack, with hooks possibly half-armed, and crashed. A deadline
is not proof of a hang: on an I/O-starved host a healthy `LoadLibraryW` plus
`repro_runtime_init` can take minutes. The recovery turned a slow child into a
corrupted one.

The first correction made the library itself _terminate_ a child whose borrow
missed a hard deadline (`bcsPoisoned`: a second suspend, then
`TerminateProcess`). That is sound, but it is **policy**, and policy does not
belong in the library. Terminating is reasonable for the tool that uses
stackable-hooks; it is not a rigid behaviour every consumer must accept.

## The design: building blocks, tool decides

**The library reports and leaves policy to the caller.** A borrowed call that
misses its deadline returns `bcsTimedOut` and keeps the thread **suspended with
its context still lent out**. `windows_entry_park` terminates nothing and
resumes nothing on its own.

`bcsTimedOut` carries a `TimedOutBorrow` handle. The handle is the ONLY thing
that can act on a lent-out thread, and it offers exactly three building blocks:

- **keep waiting** — `keepWaitingForBorrow(b, additionalMs)`: resume the
  lent-out thread and wait up to `additionalMs` more for the call to return.
  Returns a fresh `BorrowedCall`, which may be `bcsReturned` (the slow call
  finished; the saved context is handed back and the thread is parked again,
  exactly as a prompt return would leave it), `bcsTimedOut` again (a new
  handle), or `bcsChildExited`.
- **terminate** — `terminateBorrowedChild(b, exitCode = InjectionAbandonedExitCode)`:
  the pre-existing behaviour, now a call the tool makes. It leaves the extra
  suspend in place, `TerminateProcess`es the child with the sentinel exit code,
  waits for it, and sets the park to `epsAbandoned`.
- **detach** — `detachBorrowedChild(b)`: let the call finish on its own and get
  the child back safely with **no injector present**. Defined precisely below.
  Allowed ONLY with the stub.

### No borrowing entry point carries a silent terminating default

"Building blocks; tool decides" applies to every library entry point that
borrows, not only to `injectShimIntoChild`. None of them terminates on its own
authority; each either takes the policy from its caller or hands the
`TimedOutBorrow` back:

- **`injectShimIntoChild`** takes `InjectionConfig.onBorrowTimeout`.
- **`runWithMonitorShim`** takes an `onBorrowTimeout` parameter. Its only
  default (`btpTerminate`) exists for source-compatibility, and **every io-mon
  call site names the policy explicitly** so no choice is made silently; the
  policy is applied to both its borrows (the `LoadLibraryW` and the
  `repro_runtime_init`).
- **`callOnParkedThread`** (the boolean convenience) takes a **required**
  `onTimeout: BorrowTimeoutPolicy` — no default at all — because a bool cannot
  describe a lent-out thread, and the caller, not the library, must say what to
  do with one.
- **`borrowParkedThread`** returns the `TimedOutBorrow` itself, leaving the
  policy entirely to the caller.

### Keep waiting at the policy level

`BorrowTimeoutPolicy` has only `btpTerminate` and `btpDetach` — the two
**terminal** choices. "Keep waiting" is deliberately not a policy value here,
for two reasons:

- At an entry point (`injectShimIntoChild`, `runWithMonitorShim`,
  `callOnParkedThread`) the wait is bounded by the deadline the caller already
  passes (`parkTimeoutMs` / `deadlineMs`), and R1 allows `InfiniteDeadline`
  ("wait as long as the child lives"). So "keep waiting longer" at this level is
  simply a larger deadline; a redundant `btpKeepWaiting` would only duplicate
  it, and bounding the *number* of extensions is the same thing as bounding the
  total time, which the deadline already does.
- For a caller that borrows directly and wants to react to a timeout by
  extending, `keepWaitingForBorrow(b, additionalMs)` is the building block —
  it can be called repeatedly, each time with its own bound, until the call
  returns, the child exits, or the caller switches to terminate/detach.

### The hard rule (the library's only one)

`windows_entry_park` never resumes, and never gives a caller a way to resume, a
lent-out context **without the stub**. This is structural, not documentary:

- The moment a borrow times out, the library adds one **extra suspend** to the
  thread. A caller's reflexive `ResumeThread` (every caller has one) therefore
  leaves the thread still suspended, and `releaseEntryPark` becomes a no-op for
  a lent-out park (its status is `epsLentOut`, not `epsParked`, so it will not
  strip the `EB FE`). So the ordinary caller sequence cannot run a lent-out
  thread.
- The only proc that resumes a lent-out thread **into the child's own code** is
  `detachBorrowedChild`, and detach is implemented on the stub's tail, which
  restores `RSP`/`RCX` by itself. `keepWaitingForBorrow` resumes the thread
  only to run the rest of the borrowed call back to the controlled self-jump,
  never into the child's program.
- `TimedOutBorrow`'s fields are module-private, so a caller can neither forge
  one nor read the thread handle out of it; there is no `resume` entry point.
  `detachBorrowedChild` additionally refuses (returns `doRefusedNoStub`) if its
  handle carries no stub pointer.

### Is there a borrow without the stub? (`usesStub`)

**No — today every production borrow uses the stub.** `borrowParkedThread`'s
only arrangement is the CET stub (`sub rsp,20h; … call rax; mov rsp,…; mov
rcx,…; jmp entry`), so every `TimedOutBorrow` it produces on amd64 has
`usesStub == true`. On any other arrangement — WOW64, ARM64, a 32-bit host
looking at a 64-bit child — `borrowParkedThread` returns `bcsNotRun` and lends
nothing out, so no `TimedOutBorrow` exists at all. There is therefore no
present path that reaches a lent-out thread whose `RSP`/`RCX` the stub did not
restore.

`usesStub`, `doRefusedNoStub` and the compile-time refusal test are a **guard
for the invariant, not dead weight**:

- If a future change ever adds a non-stub borrow (e.g. a WOW64 32-bit frame
  with `Wow64SetThreadContext`), its handle would carry `usesStub == false`,
  and `detachBorrowedChild` would **refuse** (`doRefusedNoStub`) rather than
  resume a thread whose stack pointer nothing restores — turning a silent
  corruption into a visible refusal the author must handle.
- The compile-time test (`not compiles(zero.hThread)`, `not
  compiles(resumeLentOut(park))`) protects the *structure*: it fails if someone
  makes the handle's fields public or adds a `resume`-style proc, which are the
  two ways the "no resume without the stub" invariant could be broken by
  accident.

So the refusal is reachable only by constructing a handle that today's borrow
never makes; it exists so the invariant stays true by construction if that
ever changes.

### Detach, precisely

`detachBorrowedChild(b)` does, under the suspension and in this order:

1. **Restore the entry bytes.** The two original bytes are written back over
   the `EB FE` self-jump at the image entry point, the page protection is
   restored and the instruction cache is flushed. After this the entry point
   holds the child's real first instruction again, not the self-jump.
2. **Release the thread.** The extra suspend and the deadline suspend are both
   removed (`ResumeThread` until the suspend count reaches zero), so the thread
   runs on. It finishes `fn` on its lent-out stack, then the stub's tail
   executes: `mov rsp, <parked RSP>` puts the loader's stack pointer back,
   `mov rcx, <parked RCX>` restores the entry argument, and `jmp <entry>` lands
   on the entry point — which, because of step 1, now runs the child's real
   code. No `ret` into the entry point is involved, so the CET shadow stack is
   never consulted there; the `call fn`/`ret` inside the borrow already
   balanced it.
3. **Leak the stub page.** A live thread may still be executing the stub, so
   its one page is not freed; it is reclaimed when the child exits. The saved
   parked context is discarded on purpose: there is no parked thread to hand
   back any more — the child is running its own program.

The park is left `epsDetached`: `releaseEntryPark` is a no-op on it (the bytes
are already restored) and the caller owes no resume (the thread is already
running). Detach's whole point is that the child reaches its real entry point
**whether or not the injector is still alive** — nothing the injector does
afterwards is required, so a dead or absent injector cannot strand the child on
the self-jump. See the stranding note under "Relation to the stranding record".

## Rules (unchanged where not noted)

R1. **A slow child is not a hung child.** While a borrowed call runs and the
child is alive, the wait continues. The deadline is a last resort for a
genuinely wedged child, not a performance budget. `DefaultInjectDeadlineMs` is
10 minutes; `InfiniteDeadline` (`0xFFFFFFFF`) means "wait as long as the child
lives".

R2. **A thread whose context is lent out is never resumed by the library.**
The library suspends it once more on a timeout and hands back a
`TimedOutBorrow`; it is the caller's chosen building block, not
`windows_entry_park`, that terminates, detaches or keeps waiting. The hard rule
above is what makes "never resumed without the stub" structural.

R3. **(io-mon policy, no longer library behaviour.)** io-mon's default policy
for a timed-out borrow is **terminate**, giving the old observable behaviour: a
poisoned child reported as `ioChildTerminated`, and a `CreateProcess` hook that
sees it fails the call — `FALSE`, last error `ERROR_TIMEOUT` (1460), handles
closed, `PROCESS_INFORMATION` zeroed. `runWithMonitorShim` terminates and
raises. The policy lives in the consumer; see
`InjectionConfig.onBorrowTimeout`.

R4. **Every other failure stays sound.** A borrow that fails before the thread
ran (bad arguments, `SetThreadContext` failed, a `ResumeThread` that failed
with the context restored) leaves the child intact and is reported as a failed
injection; the child runs unmonitored. A call that returned but whose result
could not be read (`bcsNoResult`) also leaves the child intact.

R5. **The park itself uses the same deadline.** A park that misses its deadline
is safe — the thread is suspended before it reaches user code and the entry
bytes are restored under the suspension — so the child runs unmonitored
(`ioParkFailed`). Only the deadline value changed.

R6. **Slowness is observable.** `injectShimIntoChildReport` returns the time
spent waiting on the child. A consumer annotates a wait longer than
`SlowInjectionNoticeMs` (5 s). Nothing is written to the child's or parent's
stdio.

## API

`windows_entry_park` (the building blocks):

- `type BorrowedCallStatus = enum bcsNotRun, bcsReturned, bcsNoResult,
  bcsChildExited, bcsTimedOut`
- `type BorrowedCall = object` — `status`, `ret`, `elapsedMs`, and `timedOut`
  (a `TimedOutBorrow`, meaningful only on `bcsTimedOut`).
- `type TimedOutBorrow = object` — opaque; public read-only `elapsedMs` and
  `usesStub`. Its only operations are the three building blocks.
- `type DetachOutcome = enum doDetached, doChildExited, doRefusedNoStub,
  doFailed`
- `proc borrowParkedThread(park, hThread, childIsWow64, fn, arg, deadlineMs):
  BorrowedCall`
- `proc keepWaitingForBorrow(b: var TimedOutBorrow; additionalMs): BorrowedCall`
- `proc terminateBorrowedChild(b: var TimedOutBorrow;
  exitCode = InjectionAbandonedExitCode)`
- `proc detachBorrowedChild(b: var TimedOutBorrow): DetachOutcome`
- `type BorrowTimeoutPolicy = enum btpTerminate, btpDetach` (lives here, in the
  building-block layer, and is re-exported by `windows_injector` and
  `propagation_windows`).
- `proc callOnParkedThread(park, hThread, childIsWow64, fn, arg, timeoutMs,
  onTimeout: BorrowTimeoutPolicy; ret): bool` — the boolean convenience. `true`
  only on `bcsReturned`. `onTimeout` has **no default**: on `bcsTimedOut` it
  applies that building block (`btpTerminate` → `epsAbandoned`, child dead;
  `btpDetach` → `epsDetached`, child running uninstrumented) and returns
  `false`. A caller that wants to keep waiting, or to inspect the handle, uses
  `borrowParkedThread`.
- `EntryParkStatus` gains `epsLentOut` (a borrow timed out; awaiting a policy)
  and `epsDetached` (detach ran; the child continues its own program);
  `epsAbandoned` keeps its meaning (terminated).

`windows_injector`:

- `runWithMonitorShim(...; onBorrowTimeout: BorrowTimeoutPolicy = btpTerminate)`
  — default for source compatibility only; io-mon names it at every call site.
  `btpTerminate` terminates and raises (unchanged contract); `btpDetach` detaches
  and reports the loss through `WindowsInjectionResult.monitoringSkipped` /
  `skipReason` instead of raising.

`propagation_windows` (applies a policy while the park is alive, because a
lent-out handle cannot outlive the frame that owns the park):

- `InjectionConfig.onBorrowTimeout: BorrowTimeoutPolicy` (default `btpTerminate`)
- `InjectionOutcome` keeps `ioChildTerminated` (policy terminate) and gains
  `ioChildDetached` (policy detach: the child runs on, uninstrumented, with the
  shim load or init abandoned and no injector present).

### `btpDetach` under `autoPropagateCreateProcessW`

A consumer that sets `onBorrowTimeout = btpDetach` and uses the built-in
auto-propagation hook gets this exact, defined behaviour when a borrow times
out:

- **`CreateProcess` SUCCEEDS.** Detach restored the entry bytes and resumed the
  child, which is alive and running its real entry point. Failing the spawn
  would be a lie and would orphan a live process, so `ctx.result` stays
  non-zero and `PROCESS_INFORMATION` is left intact (it is **not** zeroed, the
  way a terminated child's is).
- **The child runs UNINSTRUMENTED, and the loss is not silent.** The hook
  stops propagating at the first detached node (the park is spent and the child
  is running; injecting a further node would race a live thread down the legacy
  remote-thread path — the wedge the park exists to avoid). The child carries no
  hooks and emits no monitoring records, exactly as any uninjected child does.
  The signal a consumer reads is `injectShimIntoChild`'s `ioChildDetached`
  outcome; io-mon's own spawn path annotates its record `inject=ioChildDetached`
  (R6), so the incomplete subtree is visible in the merged evidence rather than
  mistaken for a complete one. **A silent monitoring loss never happens:** a
  child is either injected, reported terminated, or reported detached.
- **Exactly one wakeup.** Detach already resumed the child, so the hook does
  NOT resume again (that would be a redundant no-op); the "resume iff we forced
  the suspension" contract holds.

io-mon does not use `btpDetach` (its policy is `btpTerminate`), so in io-mon
this path does not arise; it is defined and tested for consumers that choose it.

## Test obligations

1. A timed-out borrow returns `bcsTimedOut`; the child is alive and suspended
   with its context lent out; nothing was terminated.
2. Terminate: the child dies with `InjectionAbandonedExitCode`; a later
   `releaseEntryPark` + `ResumeThread` does not revive it and its own exit code
   is never observed.
3. Keep waiting: a call that outlives the first deadline but is given more time
   completes, and the child runs its own `main` to its own exit code.
4. Detach with the stub, on a genuine CETCOMPAT AMD64 child: the injector
   abandons the borrow (or exits) and the child still finishes the call and runs
   its own `main` to its own exit code.
5. Detach is refused when the stub is not in use, and no API path resumes a
   lent-out context without the stub (the reflexive `releaseEntryPark` +
   `ResumeThread` leaves the child frozen, not running; only detach continues
   it).
6. io-mon's default policy gives the old end-to-end behaviour: `ioChildTerminated`
   and `CreateProcessW` failing with `ERROR_TIMEOUT`.
7. `injectShimIntoChild` with `btpDetach`: a timed-out shim load is detached,
   the outcome is `ioChildDetached`, and the child runs its own `main` to its
   own exit code uninstrumented.
8. `autoPropagateCreateProcessW` with `btpDetach`: `CreateProcess` SUCCEEDS,
   `PROCESS_INFORMATION` is intact, and the detached child runs its own `main`
   to its own exit code (the loss being observable as `ioChildDetached`).

## Relation to the stranding record

`issues/.../windows-entry-park-strands-a-spinning-child-when-the-injector-dies`
(moved to reprobuild-pm) records a child left spinning on the `EB FE` for an
hour after the injector died mid-**park** — before any borrow. That case is not
a borrowed-call timeout, so this redesign neither fixes nor worsens it; its
owner is the job-object assignment in `runWithMonitorShim` (`job`), which kills
the tree when the injector's handle closes. What this redesign does add is that
**detach** never leaves a child on the self-jump: it restores the entry bytes
before releasing the thread, so a tool that chooses detach as its timeout policy
gets a child that runs its own code rather than one that spins. Terminate,
likewise, never resumes a half-injected thread.
