# Windows hook registry publishes readiness before initializing its lock

Status: open. Source inspected at fetched dev `8f4d806`; also present in
release bootstrap `72f5782`. No runtime reproduction is claimed.

## Observed

`ensure_cs_initialised` in `src/stackable_hooks/inline_hook/windows/install_windows.c`
changes `g_hooks_cs_initialised` from zero to one before calling
`InitializeCriticalSection`. A concurrent caller that sees one immediately
returns from the helper and calls `EnterCriticalSection`. If the winning
thread is paused after the flag update, the other caller uses an uninitialized
critical section. The comment says to wait for initialization, but the branch
does not wait and there is no distinct ready state.

## Expected

The backend header identifies
[MCR Windows Inline Hooking / Thread safety](https://github.com/metacraft-labs/codetracer-specs/blob/latest/Recording-Backends/Multi-Core-Recorder/MCR-Windows-Inline-Hooking.md)
as its normative contract. Serialization of patch operations must itself be
safe to enter concurrently. Microsoft's
[critical-section initialization contract](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsection)
requires initialization before any thread uses the object.

Use an actual once-initialization protocol, and verify simultaneous first
callers against the real Windows backend. A ready flag must represent completed
initialization. Preserve the installation transaction and thread-freeze rules.

This gap was found while investigating the RunQuota ARM-host compiler startup
stall. The failure-only trace does not yet establish a relationship: it stops
inside shim initialization, but does not identify which initialization stage
is blocked. Do not label this the cause of that stall without evidence.

Fetched dev `8f4d806`, already included in this branch, and searched all current
and deleted issue history for critical-section, once-initialization and readiness
races. No matching issue was found.
