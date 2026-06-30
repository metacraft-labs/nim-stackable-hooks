# nim-stackable-hooks

Cross-platform stackable hooks framework for Nim. A Nim port of the
`crates/stackable-hooks/` Rust library from `agent-harbor`, providing:

- Priority-ordered hook chains with `callNext` / `callReal`.
- Per-thread reentrancy guards (Windows: `TlsAlloc`-backed slot reachable from CLR-spawned threads).
- Per-library auto-propagation to child processes:
  - Linux / FreeBSD: prepends the shim to `LD_PRELOAD` at `execve` / `posix_spawn` time.
  - macOS: prepends the shim to `DYLD_INSERT_LIBRARIES`, with SIP-aware sandbox-tools fallback for system binaries.
  - Windows: low-priority `CreateProcessW`/`A` hook that suspends the child, injects the shim via `CreateRemoteThread(LoadLibraryW)`, and runs the consumer's init entrypoint — gated by a global semaphore (`maxInFlight`) and per-call deadline (`waitDeadline`) so fork-bomb workloads (webpack, ninja) don't wedge the parent.
- Platform install backends and primitives: PE IAT patcher + Detours-style inline `JMP rel32` on Windows, `dlsym(RTLD_NEXT)` on Linux/FreeBSD, `__DATA,__interpose` + canonical-symbol registry on macOS, plus macOS `mach_vm_remap` body-patch and original-call trampoline helpers under `stackable_hooks/platform/macos_bodypatch`.

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

v0.1.0 — first release. See [CHANGELOG.md](./CHANGELOG.md) for what's
in the box.

## License

MIT
