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
