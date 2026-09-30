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
