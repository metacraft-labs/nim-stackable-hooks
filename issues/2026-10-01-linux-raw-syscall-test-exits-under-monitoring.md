# Linux raw-syscall fixture exits while an outer monitor owns SIGTRAP

Status: open. Observed in stackable-hooks `65720d2`, io-mon `4b2bb39` from the POSIX bootstrap flake lock.

## Observed

Run `36787321087`, Linux x64 job `110131791725`, reports exit 127 from
`stackable_hooks.test_execute.test_linux_raw_syscalls`. The last completed
case is `ucontext register helpers and raw register replay are exported
through C ABI`. The next case installs and restores a process SIGTRAP
handler. Standard output has 35 passing cases; stderr is empty.
The native Nix test job at `5cadd95` passes. `repro.nim` already documents
this longstanding difference, including the three cases never reached
under monitoring; the issue now has its own searchable record.

## Expected

[Platform primitives](../docs/contributors/platform-primitives.md) defines
SIGTRAP/INT3 interception and restoration. The existing fixture requires its
own handler to be installed and the previous handler to be restored. Both
the host corpus and the monitored corpus should execute every registered
case. No spec authorizes silently skipping this case or pretending its
observations were complete. Determine whether handler chaining or fixture
isolation is required before selecting a repair.

## Evidence and next observation

Artifact `/tmp/hooks-657-linux-failure/repro/build-failure-report.json`
contains the complete failed-action output and exit status. Fetched dev
`8f4d806` and agents `0738aa9`, searched current issues and full issue history
for SIGTRAP, raw-syscall exit 127 and monitor interactions; the existing
recipe comment is the prior record. Observe the exact failing operation and
process handler state with the same pinned monitor. Preserve the native
control, assertions and complete test inventory.

## Fixture assumption and repair plan

The C fixture `stackable_test_sigtrap_install_uninstall_smoke` calls
`stackable_linux_chain_sigtrap(SIGTRAP, NULL, NULL)` and expects
`TRAP_CHAIN_UNAVAILABLE`. That expectation requires an absent prior handler.
The monitor installs one, so the fixture instead forwards null signal data
to an unrelated live handler. This source-level finding explains why the
native control and monitored run exercise different code paths; a paired
runtime control is still required to establish the resulting repair.

Give the fixture explicit prior dispositions: test `SIG_DFL` and `SIG_IGN`
for the unavailable result, and a real installed `SA_SIGINFO` fixture handler
for successful forwarding of exact signal/context pointers. Verify the
previous handler is restored after each uninstall, then restore the ambient
handler on every exit path. Retain duplicate-install rejection, all existing
live INT3 tests and automatic monitoring. This changes only fixture setup
and strengthens chaining/restoration assertions; it does not change the
shipping handler implementation or omit the outer monitor.

## The lifecycle fix passes; the next live INT3 case fails

At `f3a9dc1`, Linux Reprobuild job `110142647589` in run `36790688346`
now prints the lifecycle fixture's passing assertion and reaches 36 passing
cases. It exits 127 in the following live INT3/replay case; stderr remains
empty. The runtime compiler dependency fix also passes the full cross-target
case. Native Linux and macOS suites pass at the same source.

The POSIX bootstrap is Reprobuild `c14b1e6` with its flake-pinned io-mon
`4b2bb39` and hooks `72f5782`; the Windows-only `repro-io-mon-pin` input
must not be reported as the Linux dependency. The source log confirms the
`4b2bb39` download. Log: `/tmp/hooks-f3-linux-repro.log`.

Next bounded control: keep that exact native/monitored test and trace signal
syscalls. Its handler replays through a raw-syscall function that the outer
monitor may itself intercept. Compare the original fixture, allowing nested
SIGTRAP with `SA_NODEFER`, and allowing nesting while treating successfully
chained foreign traps as handled. Retain exact one-hit/getpid assertions and
failure accounting for unhandled signals. These are diagnostic fixture
variants, not a selected production change. Observe native success and the
monitor's real signal sequence before choosing a repair; do not suppress the
monitor or mark incomplete evidence cacheable.

The first control `36792965005` at tooling `c8aa902` compiles the original
fixture but stops before execution: Nix returns `strace`'s manual and binary
outputs, and the harness incorrectly combines them into one path. It supplies
no signal comparison. Tooling `2d5a582` explicitly selects `strace.out` and
checks the executable before running. A Nix dry run confirms exactly one
output, `/nix/store/r1mzfs885is8zv9z769wf216dyi313cn-strace-7.0`.
Corrected run `36795427990` is active, with all fixture variants and the
same monitor pins retained. First-run artifacts: `/tmp/hooks-linux-signal-c8a`.
