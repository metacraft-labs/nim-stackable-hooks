# nim-stackable-hooks

`nim-stackable-hooks` is a cross-platform stackable hooks framework for Nim, It provides high-performance interposition and hook orchestration primitives for macOS, Linux, FreeBSD, and Windows shims.

## Key Features

- **Priority-Ordered Hook Chains**: Register multiple hooks for a target function, with execution ordered by priority using `callNext` and `callReal`.
- **Per-Thread Reentrancy Guards**: Robust thread-local counters to detect and prevent infinite loops when hooks call other hooked functions.
- **Auto-Propagation to Child Processes**: Optional auto-propagation mechanics that ensure shims are loaded into child processes spawned by the host process:
  - **Linux / FreeBSD**: Pre-loads the shim library into `LD_PRELOAD`.
  - **macOS**: Pre-loads the shim library into `DYLD_INSERT_LIBRARIES` (with SIP-aware fallback helpers).
  - **Windows**: Suspends the child process, injects the shim DLL via `CreateRemoteThread` + `LoadLibraryW`, and resumes execution.

## Quick Start

```nim
import stackable_hooks/hook_registry

# Initialize the hooks registry
var registry = initHookRegistry()

# Define a hook body
proc snoop(ctx: var HookContext) {.raises: [].} =
  # Inspect ctx.args / ctx.result, and forward to the next hook in the chain
  echo "Intercepted call!"
  callNext(ctx)

# Register the hook on CreateFileW
registry.setOriginal("CreateFileW", originalCreateFileW)
registry.registerHook("CreateFileW", priority = 100, snoop)

# Dispatch calls through the hook chain
var ctx = HookContext(args: @[...])
registry.dispatch("CreateFileW", ctx)
```

## Developer & Contributor Documentation

If you want to contribute or understand the library's internals:

- [Architecture & Layout Guide](docs/contributors/architecture.md): Overview of components, directory layout, and how to run tests.
- [Platform Primitives Details](docs/contributors/platform-primitives.md): Technical details on the low-level platform hook insertion engines (Linux raw syscalls, macOS VM remapping/interposing, Windows Detours/IAT patching).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
