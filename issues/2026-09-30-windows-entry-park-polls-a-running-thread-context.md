# Windows entry parking polls a running thread's context

Status: open. Source inspected at `8f4d806`; the same code is in `72f5782`,
used by the release bootstrap.

## Observed

`parkChildAtEntryPoint` and `waitForParkedIp` call `instructionPointer` while
the child is running, then suspend only if that first sample equals the
self-jump address. They confirm again under suspension before accepting the
park. That confirmation protects a successful result, but the decision to
suspend still relies on a context whose validity the API does not guarantee.

This was found while investigating RunQuota `8cf662c` ARM-host x64 compiler
startup failures: control `36644657089` at shared actions `a7c9c3f` fails one
of 100 compilations with error 1460, even at two outer build actions. The
control does not establish that this polling pattern caused the failure.
Shared diagnostic `36682315614` at `000c15c` adds register and module evidence
only on paths that already abandon a borrowed call; it preserves deadlines.

## Expected

[Borrowed-call deadline rules R2/R5](../docs/windows-borrowed-call-deadline.md)
require a proven stopped state and safe handling of a call that did not return.
Microsoft's [GetThreadContext contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)
requires suspension before obtaining a valid context. Proposed: sample under
a balanced suspension, resume when the instruction pointer has not reached
the park, and preserve the existing hard deadline and poison behavior. Measure
real fork-heavy compiler work and all suspension/slow-call regression tests
on x64 and ARM hosts before selecting a repair for the release bootstrap.

Fetched dev `8f4d806` and searched current docs and all issue history for
running contexts and polling. This is the repository's first `issues/` record;
no earlier issue was found. No implementation change is included here.
