# nim-stackable-hooks

Cross-platform stackable hooks framework for Nim. A Nim port of the
`crates/stackable-hooks/` Rust library from `agent-harbor`, providing:

- Priority-ordered hook chains with `callNext` / `callReal`.
- Per-thread reentrancy guards (Windows: `TlsAlloc`-backed slot reachable from CLR-spawned threads).
- Per-library auto-propagation to child processes:
  - Linux / FreeBSD: prepends the shim to `LD_PRELOAD` at `execve` / `posix_spawn` time.
  - macOS: prepends the shim to `DYLD_INSERT_LIBRARIES`, with SIP-aware sandbox-tools fallback for system binaries.
  - Windows: low-priority `CreateProcessW`/`A` hook that suspends the child, injects the shim via `CreateRemoteThread(LoadLibraryW)`, and runs the consumer's init entrypoint — gated by a global semaphore (`maxInFlight`) and per-call deadline (`waitDeadline`) so fork-bomb workloads (webpack, ninja) don't wedge the parent.
- Platform install backends: PE IAT patcher + Detours-style inline `JMP rel32` on Windows, `dlsym(RTLD_NEXT)` on Linux/FreeBSD, `__DATA,__interpose` + canonical-symbol registry on macOS.

The normative spec lives at
`codetracer-specs/Recording-Backends/Multi-Core-Recorder/MCR-Library-APIs.md` §6.

## Quick start

```nim
import stackable_hooks/hook_registry

var registry = initHookRegistry()

proc snoop(ctx: var HookContext) {.raises: [].} =
  # Inspect ctx.args / ctx.result, then forward through the chain.
  callNext(ctx)

registry.setOriginal("CreateFileW", originalCreateFileW)
registry.registerHook("CreateFileW", priority = 100, snoop)

var ctx = HookContext(args: @[...])
registry.dispatch("CreateFileW", ctx)
```

## Status

- [x] M0: skeleton + nimble + smoke tests
- [x] M1: framework files (registry, reentrancy, propagation env helpers, inline hook primitive, IAT patcher)
- [x] M2: cross-platform propagation framework (per-library `PropagationNode` registry + auto-propagation hooks on POSIX/Windows + safety knobs on the Windows injection path)
- [x] M3: consumer migration (codetracer-native-recorder's `ct_interpose` re-exports `stackable_hooks` instead of carrying these files itself)
- [x] M4: consumer migration (reprobuild's `repro_monitor_*` libs drop the `--path:..\codetracer-native-recorder\ct_interpose\src` overlay)
- [x] M5: v0.1.0 docs + nimble release

## License

MIT
