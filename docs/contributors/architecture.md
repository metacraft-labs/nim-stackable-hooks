# Stackable Hooks — Architecture

This document describes the high-level architecture and design of `nim-stackable-hooks`.

## Core Components

The framework consists of three main parts:

1. **Hook Registry** (`hook_registry.nim`): Manages priority-ordered hook chains and provides `callNext`/`callReal` dispatching.
2. **Reentrancy Guard** (`reentrancy.nim`): Prevents recursive hook loops on the same thread using a per-thread depth guard.
3. **Auto-Propagation** (`propagation.nim` and `propagation_windows.nim`): Handles propagating loaded shim DLLs/libraries to child processes spawned by the host.

## Codebase Layout

```
src/
├── stackable_hooks.nim                  # Public re-export
└── stackable_hooks/
    ├── hook_registry.nim                # Priority-ordered chain dispatch
    ├── reentrancy.nim                   # Per-thread depth guard
    ├── propagation.nim                  # POSIX env-var helpers + macOS SIP rewrite
    ├── propagation_windows.nim          # Windows CreateProcess hook + DLL injection
    ├── inline_hook/
    │   ├── windows_inline_hook.nim      # Nim wrapper over the C Detours-style patcher
    │   └── windows/
    │       ├── install_windows.c        # Detours-style inline JMP rel32 installer
    │       ├── length_decoder.c         # Prologue length decoding
    │       ├── rel32_fixup.c            # rel32 / RIP-relative displacement fixup
    │       └── *.h
    └── platform/
        ├── linux_backend.nim            # LD_PRELOAD + dlsym(RTLD_NEXT)
        ├── freebsd_backend.nim          # FreeBSD variant
        ├── macos_backend.nim            # DYLD_INSERT_LIBRARIES + interpose
        └── windows_iat_patcher.nim      # PE Import Address Table patcher
tests/
└── test_*.nim                           # Acceptance and unit tests
```

## Testing & Verification

The project uses `Justfile` and `nimble` to run tests:

- Run all tests: `just test` (or `nimble test`)
- Run individual tests:
  ```bash
  nim c -r tests/test_smoke.nim
  nim c -r tests/test_hook_registry_priority_order.nim
  nim c -r tests/test_reentrancy_guard_prevents_recursion.nim
  ```

## Consumer Integration

Consumers (such as `io-mon` or `CodeTracer`) import this package either via nimble or by mapping the path in their `config.nims`:

```nim
# consumer's config.nims
addPackagePath("STACKABLE_HOOKS_SRC", [
  ".." / "nim-stackable-hooks" / "src",
  "libs" / "vendor" / "nim-stackable-hooks" / "src",
], "stackable_hooks.nim")
```
