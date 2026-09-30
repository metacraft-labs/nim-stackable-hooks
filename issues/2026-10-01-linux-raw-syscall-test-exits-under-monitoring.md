# Linux raw-syscall fixture exits while an outer monitor owns SIGTRAP

Status: open. Observed in stackable-hooks `65720d2`, io-mon `5e71adf`.

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
