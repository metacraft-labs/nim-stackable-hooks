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

## Validation of the proposed suspension control

Shared `f841035`, run `36691629213`, tests the disposable `72f5782` source
with balanced suspension on x64 and ARM hosts. Windows x64 job `109809949852`
passes the real slow-call, termination and failed-spawn assertions. Its
thread-local-state fixture then fails: the borrowed child exits 5, meaning its
TLS offset differs from a fresh thread's offset. The remote-thread negative
control still rejects the incorrect loading thread. No compiler graph ran in
that job, and the change is not selected for production.

Follow-up `36693214051` at shared `4b21d61` compares that same TLS fixture
against the original parking source on the same toolchain before attributing
the failure to this change. It retains failed regression status while also
collecting the complete monitored compiler graph. The earlier `f04af34` run
stopped before assertions because its diagnostic child used an invalid Nim
module filename; it supplies no behavioral evidence.

## TLS fixture and full-graph results

The separate TLS control `36698212669` at shared `c114b4a` fails the original
and balanced parking variants on both hosts. The actual GCC-built DLL uses
emulated TLS, so the fixture's assumed native TEB-relative offset is invalid.
Hooks `db9e21a` replaces that assumption with real per-thread state and address
checks and adds a deliberately shared probe as a negative control. Shared
`febe28c`, run `36699038944`, passes all three cases for both parking variants
on both hosts: 12 passing cases, including both negative controls. This fixes
the fixture without changing production parking or any deadline.

The longer balanced control `36693214051` at shared `4b21d61` completes its
x64 job `109815014368` with all 100 compilations passing. Two of the 98 test
programs fail: `t_observation_socket_write_path` sees one dropped row where it
expects at least two, and `t_stats_table_publication` does not observe the key
within ten seconds. The remaining test graph records 93 successful, 95 cached,
two failed and eight blocked actions. Its ARM-host job is still running as of
2026-09-30 10:05 UTC. These failures do not establish a regression caused by
balanced parking; the same complete graph has no original-parking comparison
in this run. The change remains diagnostic only.
