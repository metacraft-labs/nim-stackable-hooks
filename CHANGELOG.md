# Changelog

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
