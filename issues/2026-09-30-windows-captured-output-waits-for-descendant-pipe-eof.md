# Windows captured output waits for descendant pipe EOF after root exit

| | |
| --- | --- |
| Status | open; real-process regression being prepared |
| Recorded | 2026-09-30 |
| Observed in | nim-stackable-hooks at `8f4d806ce1ae58e6b4292fed92944171eff4f7a2` |
| Area | `runWithMonitorShim`, captured stdout/stderr |

## Observed

Source inspection at `8f4d806` finds a blocking `ReadFile` loop after
`WaitForSingleObject(pi.hProcess, ...)` reports root exit. The final loop reads
until EOF without first checking available bytes. A descendant may still own
an inherited writer. In that case root exit does not imply pipe EOF, and the
read can wait for the descendant. This is a source-level defect hypothesis;
a real child/grandchild reproduction is required before claiming a runtime fix.
The earlier polling drain can also postpone checking root exit indefinitely
if a writer continuously replenishes the pipe.

## Expected

The public `runWithMonitorShim` contract says "Returns when the child process
exits." With capture enabled, preserve bytes buffered at root exit and its
actual exit code, then return without waiting for surviving descendants to
close inherited stdout/stderr handles. Draining each availability snapshot
must be bounded so a concurrent producer cannot starve the root-exit check.

## Evidence

Inspect the capture branch in `src/stackable_hooks/windows_injector.nim`,
especially its final drain after exit. The planned real-process regression
has a root write more than one capture buffer, spawn a descendant retaining
its stdout writer, and exit with code 17 while that descendant remains alive.
The original and corrected implementations must be compared on both Windows
hosts. No fake pipe or process objects are needed.

Fetched dev `8f4d806` and agents `cf1d6a7`; searched current issues/docs and
issue history for final drains, descendant stdout and inherited pipe EOF.
No existing issue records this capture-path defect.

## Related

The ARM hook-initialization stall is separately recorded in
`2026-09-30-windows-arm-compiler-startup-stalls-in-hook-transaction.md`.
This capture hypothesis does not explain its phase-130 traces and is not yet
attributed as the cause of any RunQuota timeout.

## Real reproduction and repair

Control `36763019382` at tooling `f68d8cc` compares real processes on Windows
x64 and the ARM host. Original hooks `8f4d806` fails the specific descendant-EOF
assertion twice per host: root exit is 17 and `descendant-exited=true`.
The repair at `b7a1cdd` passes twice per host, preserves all stdout/stderr bytes,
returns 17 and reports `descendant-exited=false`. Each fixture bounds its
surviving child and releases it during cleanup; no process or pipe mocks are used.

At `b7a1cdd`, `just build`, lane registration and all 102 declared cross-target
compilation checks pass. The regression compiles/links for Windows x64 and
passes the ARM64 source check. Isolated PR 12 at `def2464` has the same runtime
sources and tests; it also carries the previously validated TLS fixture repair.
The ordinary Windows injection suite passes there. Mainline promotion is
pending ordinary CI, whose Windows Reprobuild lane currently fails with the
unprovisioned compiler rather than reaching tests.

Evidence: `/tmp/windows-injector-capture-f68-x64` and
`/tmp/windows-injector-capture-f68-arm`.
PR: <https://github.com/metacraft-labs/nim-stackable-hooks/pull/12>.
