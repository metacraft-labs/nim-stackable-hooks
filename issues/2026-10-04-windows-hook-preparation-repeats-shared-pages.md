# Windows hook preparation repeats shared pages

Status: in progress. Runtime baseline: `3b99d26fd969a48698cf75fc90a8657010c81eec`.

## Observed

Gosti `6129ea8` fails its unchanged five-request concurrency deadline under the
Windows ARM x64-emulation monitor. Phase run `37170164155` locates most delay
in hook installation and removal. Its ordinary debug image takes about 0.4
seconds to install and 0.2 seconds to remove hooks in the measured processes.
The same test binaries pass directly. The owning Gosti issue is
`issues/2026-10-03-shared-test-catalog-exposes-windows-portability-gaps.md`.

At hooks `3b99d26`, the preparation loop transitions each queued install range
to writable and back, even when several ranges share the same memory page.
Diagnostic `37173255901` at shared tooling `db22d0c` records 256 protection
calls during installation and another 128 during removal for 64 hooks.
Its API timing totals are invalid: that profiler used the public clock while
the clock's own hook was being installed. The run was cancelled; its retained
call counts and the earlier external phase measurements are distinct evidence.

## Candidate and qualification

The candidate prepares each intersected memory page once per transaction.
Windows protection changes operate on whole pages. Later transactions prepare
again. Actual patch writes, suspension, protection restoration, rollback and
instruction-cache flushing remain unchanged. This is a proposed performance
repair; call-count reduction alone does not prove Gosti meets its deadline.

The real Windows fixture places 33 functions across three target pages,
including an instruction crossing a page boundary. It requires actual target
and trampoline results, a resumed peer's calls, restored code and protections,
one suspension round and 72 real protection calls per install transaction.
It repeats the whole install/uninstall sequence. The original implementation
should fail the call-count control while passing the functional checks.
At candidate `10ed82a`, native comparison `37176379522` (shared `84ef14e`)
passes x64 and x86 executables on both Windows x64 and Windows ARM hosts.
Both transactions make 72 protection calls with the candidate and 132 with
baseline `b197281`. The baseline returns the designated count failure only
after all functional checks pass. Real loaded PE and host identities are
retained with source and binary hashes. The complete macOS suite, including
cross-target semantic checks, also passes at `10ed82a` (70 cases).
The regression is included in the ordinary Windows injection job as well as
the shared corpus. Gosti comparison `37176479700` is pending; it must pass its
original monitored deadline and full CI before this release blocker closes.

This serves the original-protection requirements in the existing
[startup-stall record](2026-09-30-windows-arm-compiler-startup-stalls-in-hook-transaction.md)
and the approved release follow-up's LOCAL-4 requirement to preserve timing
and correctness gates. The cross-page write-restoration and partial-freeze
issues are separate; this candidate does not claim to repair them.
