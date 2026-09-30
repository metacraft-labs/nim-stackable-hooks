# Windows ARM-host compiler startup stalls in the hook transaction

Status: open. Hooks `8f4d806`, io-mon `5e71adf`, RunQuota `8cf662c`.

## Observed

[Failure-only trace](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36695470313)
at shared actions `62594e4` completes 98 of 100 monitored compilations.
An assembler child and a GCC child both expire inside the borrowed shim-init
call. Both have loaded the shim and report initialization phase 22, immediately
before `ct_inline_hook_commit_transaction`. Their stopped instruction pointer
is `ntdll+0x176784`; reason 2 identifies the unchanged borrowed-call deadline.
The entry still contains its `EB FE` park. No test stage executes.

The retained DLL and bounded stack scan contain executable-address candidates
in the trampoline/relocation and suspension implementation, plus kernel32,
ntdll and the x64 emulator. These are not unwound frames and do not establish
which API is blocked. The transaction takes the registry lock, enumerates and
suspends other threads, allocates trampolines and patches target instructions.
Add volatile checkpoints around those individual operations before selecting
a repair. No timeout increase, bypass of injection, or missing-compiler
explanation is supported by these failures.

The balanced context-observation comparison at shared `4b21d61`, run
`36693214051`, also fails an assembler startup at the same ntdll offset.
That separate API-contract repair does not eliminate this failure.

## Expected

The [Windows inline-hook contract](../docs/contributors/platform-primitives.md)
requires patch writes to remain protected by thread suspension. The
[borrowed-call deadline rules](../docs/windows-borrowed-call-deadline.md)
require termination of a child whose initialization cannot safely return.
Keep both contracts. A repair must complete real monitored compiler startup
and retain hook semantics, thread-local state, slow-call and poison controls.
Use the full monitored graph for final validation, with the existing limits.

Fetched dev `8f4d806` and agents `e995df7`; dev is already an ancestor.
Searched current issues and their complete history for transaction, suspension
and deadlock reports. The existing running-context and lock-readiness issues
cover distinct defects; neither has been shown to cause this stalled commit.

## Protection-call checkpoint at `5c332cc`

Finer diagnostic [36706329422](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36706329422)
at shared actions `5c332cc55f8ad8222ad0a49c8e3ca2e72319405f` completes
99 of 100 monitored compilations against hooks `8f4d806` and io-mon
`5e71adf`. The assembler for `t_observation_extension_write_path` expires
with borrowed-call reason 2 and `init-phase=130`: immediately before the
first `VirtualProtect(..., PAGE_EXECUTE_READWRITE, ...)` in `write_patch`.
Checkpoint 131, immediately after that call, is not reached. The transaction
has already suspended its other threads. The main instruction pointer is
again `ntdll+0x176784`, and the child entry remains `EB FE`. The report's
executable-address scan still is not an unwound stack and does not identify
a lock owner. No missing compiler or timeout adjustment explains this result.

This narrows the stopped operation; it does not yet prove which suspended
thread or lock prevents completion. Compare real protection/cache-flush
calls with active and suspended protection workers on native Windows x64
and the ARM host before choosing a repair. Keep protected patch writes,
cache coherency, complete capture, and the existing poison/deadline rules.
Microsoft's [SuspendThread contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread)
warns of deadlock when a suspended thread owns a synchronization object.
Refreshed dev `8f4d806` and agents `71f2aae` before extending this record.

## Real protection controls and next observation

Standalone [36718424230](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36718424230)
at shared actions `fdd7a68fa5f7ed5c2aa53eb2678073b05ea643e8` completes all
16 cases on native x64 and all 16 on the ARM host. Each case executes 512
rounds. The active-worker control, writable protection under suspension,
cache flushing under suspension and writes to an already writable code page
all finish. No timeout or nonzero exit is recorded in either results file.
This does not reproduce the installer stall: it freezes only the four known
protection workers and changes private executable pages, while the installer
freezes every other process thread and patches executable image pages.

Full graph [36720335981](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36720335981)
at shared actions `25c6ec20fbd1dd1bb17f663e7650931985767242` retains all
100 compile actions and captures the exact patch target, frozen peer thread
ids and contexts, and runtime stack unwind results only after the existing
fatal deadline. Nearest exports are explicitly labeled as approximate; the
older executable-address scan remains distinct from unwound frames. It
prints no raw stack contents. Exact-source transforms and Windows x64 C
compilation/link pass locally against hooks `8f4d806` and io-mon `5e71adf`.
The real ARM-host run is pending. No production patching change is selected.

Refreshed dev `8f4d806` and agents `4fe105e` before extending this record.
