# Monitored Windows injection stress exits before its first assertion

|             |                                                  |
| ----------- | ------------------------------------------------ |
| Status      | open                                             |
| Recorded    | 2026-10-01                                       |
| Observed in | nim-stackable-hooks `9fcaf89`                    |
| Area        | Windows propagation stress under the io-mon shim |

## Observed

Windows ARM job `110157488712` in run `36795362092` compiles the complete
26-program corpus, then reports 51 successful actions and one failed action.
`test_propagation_windows_fork_bomb` prints its suite heading and exits with
reported status `2147483647`, before either assertion group reports a result.
There is no retained exception code, stack or hook-initialization phase.
The code alone does not identify a Windows exception or a page-protection
stall. Windows x64 passes the complete monitored and native workflow at the
same commit; the earlier paired native corpus also passes this test on ARM.

The fixture runs 32 real threads making 64 injection calls each against
invalid process handles, followed by a permit-recovery assertion. It creates
no actual child processes. Its default test name should not be interpreted
as evidence that thousands of child processes were launched.

## Expected

The public module contract in
[`propagation_windows.nim`](../src/stackable_hooks/propagation_windows.nim)
bounds concurrent injection attempts and their waits, and requires permits to
be released after failures. The existing real invalid-handle stress must
finish with counted failure outcomes and an available permit afterward.
These OS error inputs are not mocked API implementations.

## Next observation

Repeat the unchanged fixture with the same compiler and exact monitor source
pins, natively and through the production `runWithMonitorShim` function on
both Windows hosts. Record the native DWORD exit status before any CLI exit
conversion, exact binary hashes, captured output and complete monitor
fragments. Preserve all 32 threads, 2,048 calls, deadlines and assertions.
A nonzero status remains failure. This supplemental control cannot replace
full ordinary CI; candidate `4371fae` is still running that matrix.

Evidence: `/tmp/hooks-9fc-arm-repro.log` and
`/tmp/hooks-9fc-arm-evidence/repro/build-failure-report.json`.
Fetched dev `8f4d806` and agents `1bee6b7`; searched current issues and their
full history for fork-bomb and numeric-exit reports before filing. The
compiler-startup issue covers a different observed phase and is not assigned
this failure without evidence.

## Source-inspected first-call race

At `4371fae`, `ensureInFlightLock` checks the ordinary Boolean
`inFlightLockInit`, initializes the global critical section, then sets the
Boolean. Two first callers can both observe false and initialize the same
object; one can reset it while another is using it. This is a definite source
race, but the ordinary exit report does not establish that it caused this
particular failure. It is separate from the C hook registry's early-ready
publication issue.

Microsoft's [initialization contract](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsection)
forbids reinitializing a live critical section. Its
[DLL initialization guidance](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)
permits creation and initialization of synchronization objects during module
initialization. This repository already initializes `wow64StateLock` at
module scope in `windows_injector.nim`.

Initialize the propagation permit lock once at module initialization, before
injection callers can enter. Remove the racy lazy Boolean and both redundant
first-call checks. Preserve the same lock-protected cap/count operations and
all injection behavior. Strengthen the existing stress fixture with a start
gate that releases workers after all threads have been created; keep all 32
threads, 2,048 attempts, assertions and time bounds. Compare the original and
repaired source on real Windows hosts before selecting it. The unchanged raw
status control at tooling `6b2415e`, run `36801009503`, remains independent.

## Candidate and controls

Candidate `43b1835`, above `4371fae`, initializes the permit lock at module
load and adds the worker start gate. Windows Nim source checking and full
Windows x64 cross-compilation/linking of the stress fixture pass, using Nim
2.2.4 and Zig 0.13.0. Logs: `/tmp/hooks-injection-lock-windows-check.log` and
`/tmp/hooks-injection-lock-build.log`. Ordinary native `36801305772` and
Reprobuild `36801308347` runs are active; the native Windows injection job
already passes at this SHA.

Paired tooling `bf169cf`, run `36801505047`, compiles both permit-lock
implementations against the same strengthened fixture and exact monitor. It
records twelve native and twelve monitored stress repetitions per variant,
plus real DWORD-exit controls. Original failures are retained; any repaired
failure fails the run. The unchanged-fixture raw-status control
`36801009503` continues separately. Both drivers compile/link for Windows
x64 locally; workflow and Python syntax checks pass. No runtime result is
claimed until those Windows controls complete.

## Raw-status results and diagnostic capture repair

At tooling `6b2415e`, Windows x64 job `110175120165` in run `36801009503`
preserves the real `0xC0000005` exit in both native and monitored controls.
All twelve monitored repetitions of the unchanged `4371fae` fixture exit
zero and retain both passing assertion groups. All twelve native children
also exit zero, but their logs contain only the suite heading. Those native
results do not establish complete assertion-output coverage.

The native driver calls `Stream.readAll` before waiting. Nim's implementation
stops after a short pipe read, so it loses later output chunks. This is a
capture defect in the diagnostic driver. Tooling `5336c54` drains explicit
reads until pipe EOF and adds a real child that writes two separately
flushed lines 100 milliseconds apart, then exits 17. Both capture modes
must retain both lines and the exit code, in addition to the high-bit exit
control. Windows x64 cross-compilation/linking and Python/workflow syntax
checks pass at this tooling commit.

Corrected raw run `36802560298` and paired run `36802560317` retain the
same source pins and stress assertions. The prior paired run `36801505047`
uses the same incomplete native capture and cannot establish complete native
assertion output. Its raw statuses and monitored output remain evidence.
The corrected raw and paired drivers run 28 and 56 cases per host,
respectively. Evidence for the first raw x64 run is under
`/tmp/hooks-raw-stress-6b2-x64`.

The complete native matrix `36801305772` passes all seven jobs at helper
`43b1835`. Its complete Reprobuild matrix remains active. These observations
still do not establish the lazy permit lock as the cause of the original
ARM-host numeric-exit failure.

### Complete baseline and corrected x64 pair

Baseline `4371fae` now passes every job in native `36797913117` and
Reprobuild `36797913098`, including monitored build/test and both native
cross-checks on the Windows ARM host. The earlier numeric-exit failure is
intermittent across these ordinary runs, not established as repaired.

Corrected paired run `36802560317` at tooling `5336c54` passes all 56 x64
cases: twelve native and twelve monitored stress repetitions for each lock
variant, plus each mode's split-output and high-bit exit controls. Both lock
variants use the same `43b1835` start-gated fixture. All expected statuses
and assertion output are retained; no timeout occurs. This confirms
compatibility and complete diagnostic capture, not original-fail/repaired-pass
causality. Source pins and complete evidence are retained in
`/tmp/hooks-lock-pair-533-x64`. ARM results remain pending.

### ARM original wait and repaired monitored repetitions

The earlier paired run `36801505047` at tooling `bf169cf` now completes
on ARM. With the same `43b1835` start-gated fixture, the original `4371fae`
lock passes three monitored stress repetitions, then hangs in repetition
four. The target retains only its suite heading; no root result is written.
The outer 1,500-second bound expires and the driver and target are terminated.
The initialized-lock variant subsequently passes all twelve monitored
repetitions, each with zero root status and both assertion groups retained.
Both variants' high-bit exit controls pass in both modes.

This is an observed original-timeout/repaired-pass comparison on the ARM
host. It does not establish a stack location for the timeout or explain the
earlier numeric exit. Both native variants return zero in all twelve stress
repetitions, but `bf169cf`'s already-recorded output-capture defect loses
their assertion lines, so native assertion coverage is not claimed from
that driver. The corrected `5336c54` ARM pair remains active. Evidence:
`/tmp/hooks-lock-pair-bf1-arm`, especially `original-monitored-4` and the
twelve `initialized-monitored-*` stress directories.

Complete `43b1835` Reprobuild CI now passes both Linux jobs, macOS and
Windows x64. The ARM job passes monitored build and test, then native build;
its final native test cross-check remains active. Native CI already passes
all seven jobs at this same source commit.
