# nim-stackable-hooks

Cross-platform stackable hooks framework for Nim. A Nim port of the
`crates/stackable-hooks/` Rust library from `agent-harbor`, providing:

- Priority-ordered hook chains with `callNext` / `callReal`.
- Per-thread reentrancy guards (Windows: `TlsAlloc`-backed slot reachable from CLR-spawned threads).
- Per-library auto-propagation to child processes:
  - Linux / FreeBSD: prepends the shim to `LD_PRELOAD` at `execve` / `posix_spawn` time.
  - macOS: prepends the shim to `DYLD_INSERT_LIBRARIES`, with SIP-aware sandbox-tools fallback for system binaries.
  - Windows: low-priority `CreateProcessW`/`A` hook that suspends the child, injects the shim via `CreateRemoteThread(LoadLibraryW)`, and runs the consumer's init entrypoint — gated by a global semaphore (`maxInFlight`) and per-call deadline (`waitDeadline`) so fork-bomb workloads (webpack, ninja) don't wedge the parent.
- Platform install backends and primitives: PE IAT patcher + Detours-style inline `JMP rel32` on Windows, `dlsym(RTLD_NEXT)` on Linux/FreeBSD, `__DATA,__interpose` + canonical-symbol registry on macOS, plus macOS `mach_vm_remap` body-patch/original-call helpers under `stackable_hooks/platform/macos_bodypatch` and Linux x86_64 raw-syscall helpers under `stackable_hooks/platform/linux_raw_syscalls`.

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

## Linux Raw-Syscall Primitives

`stackable_hooks/platform/linux_raw_syscalls` exposes low-level Linux x86_64
helpers for consumers that need to close direct syscall bypasses:

- `rawSyscall6` for internal forwarding without calling libc wrappers.
- `resolveDefaultSymbol`, `openLibraryNoLoad`, `resolveSymbolInHandle`, and
  `resolveSymbolChain` for consumer-controlled symbol resolver chains such as
  `RTLD_DEFAULT` followed by a caller-opened libc handle.
- `installAbsoluteJumpPatchTransaction`, `installAbsoluteJumpPatch`,
  `installNamedAbsoluteJumpPatch`, and `restoreAbsoluteJumpPatch` for explicit
  wrapper/body-patch installation with structured diagnostics.
- `addrInLinuxExecutableSegment`, `clearLinuxPatchBook`,
  `linuxPatchBookContains`, and `recordLinuxPatchBookTarget` as optional
  reusable validation and duplicate-target bookkeeping helpers.
- `scanLinuxX8664SyscallBytes`, `visitLinuxX8664SyscallBytes`,
  `visitLinuxX8664SyscallMemory`, `visitLinuxExecutableMappingSyscalls`,
  `parseLinuxMapsLine`, and `enumerateLinuxExecutableMappings` for finding and
  describing raw `0f 05` callsites.

`rawSyscall6` returns the kernel result directly; failed syscalls are negative
errno values and do not set libc `errno`. The absolute-jump patch handle stores
the overwritten bytes for restore, but the Linux helper surface does not yet
provide an instruction-decoded original-call trampoline. Patch/restore
temporarily changes the affected page span to `RWX` and restores it to `RX`;
consumers that patch non-wrapper or writable executable pages need their own
permission policy.

`installAbsoluteJumpPatchTransaction` exposes the lower-level install contract
needed by C translation units and behavior-preserving migrations: it
distinguishes validation failure, fatal pre-patch `mprotect` failure, patch
write failure, and post-patch `mprotect`-back failure after the jump is already
live. The same C ABI is exported under neutral `stackable_linux_*` symbols.

These APIs are intentionally policy-free. MCR keeps record/replay semantics,
stage0 composition, event ABI, and clone attribution. io-mon keeps monitor
classification, completeness policy, and fail-open/fail-closed decisions.

## License

MIT
