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
- `measureOriginalCallTrampoline` and `buildOriginalCallTrampoline` for
  conservative Linux x86_64 original-call trampolines: the helper decodes
  enough whole instructions to cover the patch window, copies the relocated
  prefix into trampoline memory, appends a 14-byte absolute jump back to
  `target + copiedLen`, then makes the trampoline `RX`.
- `addrInLinuxExecutableSegment`, `clearLinuxPatchBook`,
  `linuxPatchBookContains`, and `recordLinuxPatchBookTarget` as optional
  reusable validation and duplicate-target bookkeeping helpers.
- `scanLinuxX8664SyscallBytes`, `visitLinuxX8664SyscallBytes`,
  `visitLinuxX8664SyscallMemory`, `visitLinuxExecutableMappingSyscalls`,
  `parseLinuxMapsLine`, and `enumerateLinuxExecutableMappings` for finding and
  describing raw `0f 05` callsites.
- `LinuxInt3CallsiteTable`, `addLinuxInt3Callsite`,
  `findLinuxInt3Callsite`, and `findLinuxInt3CallsiteForTrapRip` for sorted
  raw-syscall callsite lookup suitable for signal-handler dispatch.
- `installInt3SyscallPatchTransaction` and `restoreInt3SyscallPatch` for
  replacing byte 0 of a selected `0f 05` instruction with `INT3` and restoring
  the original byte.
- `captureLinuxX8664SyscallRegisters`, `writeLinuxX8664SyscallResult`, and
  `replayLinuxX8664SyscallRegisters` for policy-free Linux x86_64 `ucontext_t`
  register extraction, result/RIP writeback, and raw replay of the captured
  syscall ABI state.
- `isLinuxX8664DefaultCloneContinuationSyscall`,
  `isLinuxX8664CloneContinuationSyscall`,
  `computeLinuxX8664Int3ResumeRip`, and
  `computeLinuxX8664CloneContinuation` for policy-free clone/fork/vfork
  continuation-state calculation on top of the INT3 substrate. The helpers
  describe parent result/RIP writeback and child resume-RIP shape; consumers
  decide when clone-like handling applies.
- `staticRawSyscall6`, `rtSigreturnRestorerAddress`, and
  `cloneContinuationTrampolineAddress`, plus matching neutral
  `stackable_linux_*` C ABI symbols, for static-runtime/no-libc-oriented
  consumers that need raw syscall, signal-restorer, and clone-continuation
  building blocks without calling libc's `syscall(2)` wrapper.
- `installLinuxSigtrapHandler`, `chainLinuxSigtrap`, and
  `uninstallLinuxSigtrapHandler` as a low-level SIGTRAP install/chaining
  substrate. The install helper rejects double installation in the same
  process so uninstall can restore the saved predecessor predictably.

`rawSyscall6` returns the kernel result directly; failed syscalls are negative
errno values and do not set libc `errno`. Patch/restore temporarily changes the
affected page span to `RWX` and restores it to `RX`; consumers that patch
non-wrapper or writable executable pages need their own permission policy.

The original-call trampoline builder is intentionally conservative. It supports
simple non-control-flow x86_64 prologue instructions and rejects unsupported
instructions, `syscall`, calls, jumps, returns, absolute moffs forms, and
RIP-relative memory operands with `lrsUnsupportedInstruction` instead of
relocating them incorrectly. It does not yet provide a full disassembler,
RIP-relative relocation, or thread-suspension/install policy.

The INT3 raw-syscall helpers are also deliberately policy-free. They patch only
consumer-selected callsites, expose the x86_64 register continuation contract,
provide a signal chaining substrate, and expose default clone/fork/vfork
continuation mechanics. They do not record events, choose mapping scan policy,
decide which syscalls are mission-relevant, or own process lifecycle policy.
Handlers built on this substrate must explicitly dispatch known callsites and
chain or escalate unrelated SIGTRAPs; the helper returns
`lrsTrapChainUnavailable` when the saved predecessor cannot be invoked.

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
