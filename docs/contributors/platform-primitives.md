# Stackable Hooks — Platform-Specific Primitives

This document details the low-level, platform-specific primitives exposed by the library.

## Linux Preload Primitives

`stackable_hooks/platform/linux_preload` exposes the mechanics needed by traditional Linux `LD_PRELOAD` shims without taking over consumer policy:

- `resolveNextSymbol` performs `dlsym(RTLD_NEXT, name)` while suppressing nested preload hook dispatch on the current thread.
- `enterPreloadHook`, `exitPreloadHook`, `preloadHooksAllowed`, and `currentPreloadHookDepth` provide a small TLS reentrancy gate for exported preload wrapper functions.

Consumers still own the exported wrapper symbols, target symbol set, hook-body dispatch, event recording, and completeness policy.

## Linux Raw-Syscall Primitives

`stackable_hooks/platform/linux_raw_syscalls` exposes low-level Linux x86_64 helpers for consumers that need to close direct syscall bypasses:

- `rawSyscall6` for internal forwarding without calling libc wrappers. It returns the kernel result directly (failed syscalls are negative errno values).
- `resolveDefaultSymbol`, `openLibraryNoLoad`, `resolveSymbolInHandle`, and `resolveSymbolChain` for consumer-controlled symbol resolver chains.
- `installAbsoluteJumpPatchTransaction`, `installAbsoluteJumpPatch`, `installNamedAbsoluteJumpPatch`, and `restoreAbsoluteJumpPatch` for explicit wrapper/body-patch installation.
- `locateLinuxVdsoImage`, `parseLinuxVdsoImageAt`, `resolveLinuxVdsoSymbol`, `installLinuxVdsoSymbolPatchTransaction`, and `installLinuxVdsoOverlayPatchTransaction` for vDSO image discovery and Elf parsing/patching.
- `measureOriginalCallTrampoline` and `buildOriginalCallTrampoline` for building original-call trampolines on Linux x86_64.
- `addrInLinuxExecutableSegment`, `clearLinuxPatchBook`, `linuxPatchBookContains`, and `recordLinuxPatchBookTarget` for validation and duplicate-target bookkeeping.
- `scanLinuxX8664SyscallBytes`, `visitLinuxX8664SyscallBytes`, `visitLinuxX8664SyscallMemory`, `visitLinuxExecutableMappingSyscalls`, `parseLinuxMapsLine`, and `enumerateLinuxExecutableMappings` for finding raw `0f 05` callsites.
- `LinuxInt3CallsiteTable`, `addLinuxInt3Callsite`, `findLinuxInt3Callsite`, and `findLinuxInt3CallsiteForTrapRip` for signal-handler-based SIGTRAP dispatch.
- `installInt3SyscallPatchTransaction` and `restoreInt3SyscallPatch` for replacing byte 0 of `0f 05` with `INT3`.
- `captureLinuxX8664SyscallRegisters`, `writeLinuxX8664SyscallResult`, and `replayLinuxX8664SyscallRegisters` for register context extraction and replay.
- `isLinuxX8664DefaultCloneContinuationSyscall`, `isLinuxX8664CloneContinuationSyscall`, `computeLinuxX8664Int3ResumeRip`, and `computeLinuxX8664CloneContinuation` for clone/fork/vfork continuation calculation.
- `staticRawSyscall6`, `rtSigreturnRestorerAddress`, and `cloneContinuationTrampolineAddress` (plus matching neutral `stackable_linux_*` C ABI symbols) for static-runtime/no-libc consumers.
- `classifyLinuxX8664AtomicWindow`, `selectLinuxAtomicPatchStrategy`, `allocateLinuxNearTrampoline`, `freeLinuxNearTrampoline`, and `LinuxJitRangeRegistry` for bounded POSIX atomic/JIT patching.
- `installLinuxSigtrapHandler`, `chainLinuxSigtrap`, and `uninstallLinuxSigtrapHandler` for signal-handler installation/chaining.

## Windows Inline-Hook Primitives

`stackable_hooks/inline_hook/windows_inline_hook` exposes the Windows inline hook installer backed by `src/stackable_hooks/inline_hook/windows/`.

The default `inlineHookInstall`, `inlineHookInstallNoReturn`, and `inlineHookUninstall` entry points suspend other threads around patch writes.
The module also exposes unsafe no-suspend variants:

- `inlineHookInstallUnsafeNoSuspend`
- `inlineHookInstallNoReturnUnsafeNoSuspend`
- `inlineHookUninstallUnsafeNoSuspend`

These functions are mechanism-only helpers. The caller must ensure that no other thread can execute the target prologue while the bytes are being patched or restored.

## Windows Host-Side Injection Helper

`stackable_hooks/windows_injector` is an opt-in helper module providing host-side Windows process creation and DLL injection logic using the standard suspended creation + `CreateRemoteThread` + `LoadLibraryW` pattern.
It includes process handle-whitelisting via `STARTUPINFOEX` to prevent handle-leak deadlocks on parent-inherited resources.
