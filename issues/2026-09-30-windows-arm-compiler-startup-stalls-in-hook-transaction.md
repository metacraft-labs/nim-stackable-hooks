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
