# Changelog

## Unreleased

### Added

- **Windows entry-point park** (`stackable_hooks/windows_entry_park`) — a
  new attach primitive that parks a `CREATE_SUSPENDED` child's MAIN thread
  at its image entry point (patch `EB FE`, resume, poll `GetThreadContext`
  until the instruction pointer reaches the entry, suspend) so the Windows
  loader initialises the process on that thread instead of on an injected
  remote thread. The park is suspend-count neutral: the caller's own
  `ResumeThread` is still the single wakeup.
- `InjectionConfig.attachStrategy` (`asEntryPark` / `asDirect`) and
  `InjectionConfig.parkTimeoutMs`. `asEntryPark` is the default and is
  applied to **every** Windows child, not only MSYS2/Cygwin ones.
- `injectShimIntoChild` takes an optional trailing `hThread` (the child's
  main thread). Existing three- and four-argument callers compile unchanged
  and keep their exact previous behaviour.
- `propagation_windows.mappedForkRuntime` and `isCygwinForkChild` — the
  fork-child detection. `mappedForkRuntime` asks the loader what is
  actually mapped into THIS process rather than asking the filesystem what
  sits next to an image.
- Three new `InjectionOutcome` values, all deliberately distinct from
  `ioInjected` so a consumer cannot grade a skipped subtree as complete:
  `ioSkippedForkChild`, `ioSkippedForkRuntime`, `ioParkFailed`.
- `tests/test_windows_entry_park_msys.nim` — the failing-before /
  passing-after pair, asserted through the public API on a real
  MSYS2/Cygwin shell and on a native child.
- `research/msys-attach-2026-09/` — the probes and measurements behind the
  diagnosis, including the two plausible alternatives that do not work.

### Fixed

- An MSYS2/Cygwin child can now be attached to. Previously a
  `CreateRemoteThread` into a never-run `CREATE_SUSPENDED` child made the
  loader run `LdrpInitializeProcess` — `msys-2.0.dll`'s
  `DLL_PROCESS_ATTACH` included — on that remote thread, which then exited;
  the shell wedged at its first `fork()` while `injectShimIntoChild` still
  reported `ioInjected`. This was **not** the `msys-2.0.dll` base-address
  collision class and rebasing does not address it; see the research
  directory for the measurement that separates them.
- `autoPropagateCreateProcessW` no longer skips every MSYS2/Cygwin child
  behind a filesystem heuristic. It parks and injects them, except when the
  CALLER asked for `CREATE_SUSPENDED` — a caller who did is entitled to a
  child that has executed nothing, which is exactly what Cygwin's own
  `fork()` relies on.
- `skipIfImageHasShim` is now meaningful: the probe runs against a child
  whose loader has finished, so `EnumProcessModulesEx` reports the real
  module list instead of the two or three entries a never-run process has.


## v0.1.0 — 2026-06-14

Initial release. Cross-platform stackable hooks framework for Nim,
extracted from `codetracer-native-recorder/ct_interpose/`
to clean up the entanglement between reprobuild (simpler monitor-only
shim) and ct_interpose (sophisticated MCR record/replay layer).

### Added

- **Hook registry** (`stackable_hooks/hook_registry`) — priority-ordered hook chains with `dispatch` / `callNext` / `callReal` semantics.
- **Reentrancy guard** (`stackable_hooks/reentrancy`) — per-thread depth counter backed by a C-side `TlsAlloc` slot (Windows) / `_Thread_local` with `initial-exec` model (POSIX), correct under the CLR-spawned-thread + `NULL TEB.TLSPointer` edge case (MW17). Includes the depth-trace ancestor name stack used by `CT_DEPTH_TRACE` diagnostics.
- **Propagation framework** (`stackable_hooks/propagation` + `propagation_windows`):
  - Per-library `PropagationNode` registry (CAS-published linked list).
  - `enableAutoPropagation` / `disableAutoPropagation` per library.
  - `injectionEnvVar` + `buildInjectionEnv` + `buildInjectionEnvFromRegistry` for `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` on POSIX.
  - macOS SIP-aware path rewriting + sandbox-tools copy helpers.
  - Windows `injectShimIntoChild` + `autoPropagateCreateProcessW` with four safety knobs (configurable via `InjectionConfig`):
    - `maxInFlight` — global semaphore on concurrent injections (default 16).
    - `waitDeadlineMs` — replace `WaitForSingleObject(INFINITE)` with a deadline (default 5 000 ms).
    - `skipIfImageHasShim` — `EnumProcessModulesEx` probe to skip injection when the child already has the shim mapped (default true).
    - Resume-before-init ordering — the consumer's init proc runs on a separate remote thread AFTER the main thread resumes, so a slow init doesn't block forward progress.
  - `resolveSelfImagePath` helper for consumer self-registration.
- **Windows IAT patcher** (`stackable_hooks/platform/windows_iat_patcher`) — PE Import Address Table walker + per-entry pointer swap.
- **Windows inline-hook primitive** (`stackable_hooks/inline_hook/windows_inline_hook` + `inline_hook/windows/*.c`) — Detours-style 5-byte JMP rel32 installer with prologue length decoding, RIP-relative rel32 fixup, thread-suspension transaction. Vendored from `codetracer-native-recorder/ct_inline_hook`.

### Migration

Consumers migrate via shim modules:

- `codetracer-native-recorder/ct_interpose/src/ct_interpose/{hook_registry,reentrancy,propagation}.nim` now re-export `stackable_hooks/*` so the ~30 MCR call sites compile unchanged.
- `reprobuild/libs/repro_monitor_*` libs swap `import ct_interpose/*` for `import stackable_hooks/*`. Build infrastructure (`config.nims`, `env.ps1`, `scripts/build_apps.sh`, `repro_test_support.ctInterposeSrcPath`) all follow.
- `reprobuild/libs/repro_monitor_shim/.../windows_interpose.nim`'s `snoopCreateProcessW`/`A` now route through the framework's safer `injectShimIntoChild` (the legacy in-file copy is retained for diagnostic comparability but no longer called).

### Specification

The normative spec for the public surface lives at
`codetracer-specs/Recording-Backends/Multi-Core-Recorder/MCR-Library-APIs.md`
§6 and
`codetracer-specs/Recording-Backends/Multi-Core-Recorder/MCR-OS-Interposition.status.org`
§M0.
