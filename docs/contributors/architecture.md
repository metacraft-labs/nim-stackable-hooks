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
    ├── safe_tls.nim                     # pthread-backed hostile-context-safe TLS
    ├── windows_env_block.nim            # lpEnvironment UTF-16 block encoding
    ├── windows_fork_runtime.nim         # Windows fork-runtime (MSYS/Cygwin) support
    ├── windows_injector.nim             # CreateProcessW + CreateRemoteThread injector
    ├── tools/
    │   ├── inject_helper.nim            # 64-bit injection helper executable
    │   └── wow64_proc_probe.nim         # 32-bit proc-address probe (--cpu:i386 only)
    ├── inline_hook/
    │   ├── windows_inline_hook.nim      # Nim wrapper over the C Detours-style patcher
    │   └── windows/
    │       ├── install_windows.c        # Detours-style inline JMP rel32 installer
    │       ├── length_decoder.c         # Prologue length decoding
    │       ├── rel32_fixup.c            # rel32 / RIP-relative displacement fixup
    │       └── *.h
    └── platform/
        ├── linux_preload.nim            # LD_PRELOAD + dlsym(RTLD_NEXT)
        ├── linux_raw_syscalls.nim       # x86-64 raw-syscall body patching
        ├── linux_raw_syscalls_aarch64.nim  # AArch64 body patch + trampolines
        ├── macos_bodypatch.nim          # DYLD_INSERT_LIBRARIES + body patch
        └── windows_iat_patcher.nim      # PE Import Address Table patcher
tests/
├── corpus.nim                           # THE test corpus + cross-target matrix
└── test_*.nim                           # Acceptance and unit tests
```

(This listing had gone stale — it named `linux_backend.nim`,
`freebsd_backend.nim` and `macos_backend.nim`, none of which exist, and
omitted the whole Windows injector tree. It is now checked against reality
by `tests/test_lane_registration.nim`, which fails if any `src/**/*.nim`
is absent from `tests/corpus.nim`.)

## Testing & Verification

Three runners execute this repo's tests:

| Runner | Entry point |
|---|---|
| `just test` | delegates to `nimble test` |
| `nimble test` | the `test` task in `stackable_hooks.nimble` |
| `repro test` | the edges `repro.nim` emits (`.github/workflows/ci-reprobuild.yml`) |

**All three read one list: `tests/corpus.nim`.** Each entry declares the
`nim` `(--os, --cpu)` targets its source compiles for, and that single list
decides both which tests this host builds and runs (`runsOnHost`) and which
targets the cross-target compile matrix checks. Add a test file, add it
there — `tests/test_lane_registration.nim` fails the build otherwise, and it
also fails if either lane grows a test path of its own.

- Run all tests: `just test` (or `nimble test`)
- Compile-check every platform arm from this host:
  `just check-cross-targets`
- Run individual tests:
  ```bash
  nim c -r tests/test_smoke.nim
  nim c -r tests/test_hook_registry_priority_order.nim
  nim c -r tests/test_reentrancy_guard_prevents_recursion.nim
  ```

Note that `just build` alone is not sufficient verification of the
Windows/macOS arms: `src/stackable_hooks.nim` imports the Windows tree only
`when defined(windows)`, so a bogus symbol in
`src/stackable_hooks/windows_injector.nim` does not redden a plain
`nim check` of the umbrella on Linux or macOS. `just build` therefore also
checks that file for both Windows CPUs, and the exhaustive matrix runs
inside the suite.

## Consumer Integration

Consumers (such as `io-mon` or `CodeTracer`) import this package either via nimble or by mapping the path in their `config.nims`:

```nim
# consumer's config.nims
addPackagePath("STACKABLE_HOOKS_SRC", [
  ".." / "nim-stackable-hooks" / "src",
  "libs" / "vendor" / "nim-stackable-hooks" / "src",
], "stackable_hooks.nim")
```
