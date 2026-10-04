# Windows hook freeze can report success with unfrozen threads

| | |
| --- | --- |
| Status | open |
| Recorded | 2026-10-04 |
| Observed in | nim-stackable-hooks `fcac217396872eede718a57f49f91fecab41c4ac` |
| Area | `inline_hook/windows/install_windows.c`, `suspend_other_threads` |

## Observed

Source inspection finds three paths that return zero without establishing the
stopped-thread set required by the default patching entry points:

- A failed `Thread32First` falls through to success.
- After `CT_FROZEN_MAX` entries, further matching threads are silently skipped.
- Failed `OpenThread` and `SuspendThread` calls are skipped without distinguishing
  a thread that has exited from a live thread that could not be suspended.

The transaction and individual install/uninstall callers interpret zero as a
completed freeze and proceed to write executable bytes. This is code-path
evidence, not a reproduced partial-patch crash. It was found while examining
Gosti's Windows ARM monitored process latency; no latency cause is inferred.

## Expected

[Platform primitives, Windows inline hooks](../docs/contributors/platform-primitives.md)
states that default install/uninstall entry points suspend other threads around
patch writes. The implementation also cites MCR-Windows-Inline-Hooking's
thread-safety requirement. Inability to establish that condition must return a
failure before any patch bytes change, with already suspended threads resumed
and every acquired handle closed. Confirmed thread exit is a separate case.

## Evidence

Inspect `suspend_other_threads` and its four callers at the revision above.
Refreshed `agents` before filing. Searched current issues and deleted issue
history for `suspend_other_threads` and `CT_FROZEN_MAX`; no existing record
covered these success paths. The existing compiler-startup stall issue concerns
protection changes after suspension and remains separate.

Any repair needs real Windows thread/handle controls, bounded capacity and
failure controls, plus the existing transaction and concurrent-hook tests.
macOS compilation alone cannot qualify the suspension behavior.
