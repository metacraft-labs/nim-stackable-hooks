# nim-stackable-hooks — development guide

Public cross-platform Nim hooks framework. Nim port of `agent-harbor`'s
`crates/stackable-hooks/` Rust library. Hosts the framework primitives
that any Nim consumer's interpose shim needs: hook registry with
priority dispatch, thread-local reentrancy guard, child-process
propagation (LD_PRELOAD on Linux, DYLD_INSERT_LIBRARIES on macOS,
CreateProcess+CreateRemoteThread on Windows), and the platform install
backends.

The normative spec lives at
`~/metacraft/codetracer-specs/Recording-Backends/Multi-Core-Recorder/MCR-Library-APIs.md`
§6 and
`~/metacraft/codetracer-specs/Recording-Backends/Multi-Core-Recorder/MCR-OS-Interposition.status.org`.

## What belongs here vs not

In scope:

- Cross-platform `HookRegistry` with priority-ordered dispatch + `callNext` / `callReal`.
- Per-thread `HookGuard` reentrancy counter (Windows: TlsAlloc-backed C-side accessor — see §MW17 rationale in `reentrancy.nim`).
- `PropagationNode` linked list + `enableAutoPropagation()` / `disableAutoPropagation()` per consumer DLL.
- Per-platform auto-propagation hooks (`execve` / `posix_spawn` on POSIX, `CreateProcessW` / `CreateProcessA` on Windows).
- macOS SIP-aware path rewriting + sandbox-tools copy helpers.
- Windows IAT patcher + inline-detour primitive (the C sources live under `src/stackable_hooks/inline_hook/windows/`).
- Stable install API any consumer's hook bodies can target without reaching into platform internals.

Out of scope (lives in the consumer's repo):

- Domain-specific hook bodies (codetracer's MCR syscall recorders, reprobuild's monitor-fragment writer).
- Recording / replay infrastructure.
- Stage0 PE bootstrap or DBI engine integration (codetracer-private).

## Layout

```
src/
├── stackable_hooks.nim                  # public re-export
└── stackable_hooks/
    ├── hook_registry.nim                # priority-ordered chain
    ├── reentrancy.nim                   # per-thread depth guard
    ├── propagation.nim                  # env-var helpers + SIP rewrite (POSIX)
    ├── propagation_windows.nim          # CreateProcess hook + injectShimIntoChild (Windows)
    ├── inline_hook/
    │   ├── windows_inline_hook.nim      # Nim wrapper over the C primitive
    │   └── windows/
    │       ├── install_windows.c        # Detours-style inline JMP rel32 installer
    │       ├── length_decoder.c         # prologue length decoding
    │       ├── rel32_fixup.c            # rel32 / RIP-rel fixup for the trampoline
    │       └── *.h
    └── platform/
        ├── linux_backend.nim            # LD_PRELOAD + dlsym(RTLD_NEXT)
        ├── freebsd_backend.nim          # FreeBSD variant
        ├── macos_backend.nim            # DYLD_INSERT_LIBRARIES + __DATA,__interpose
        └── windows_iat_patcher.nim      # PE Import Address Table patcher
tests/
└── test_*.nim                           # 11 acceptance tests from MCR-OS-Interposition §M0
```

## Building

```
nim c -r tests/test_smoke.nim
nim c -r tests/test_hook_registry_priority_order.nim
nim c -r tests/test_reentrancy_guard_prevents_recursion.nim
nimble test
```

## Consumer integration

Reprobuild and CodeTracer both consume this via `--path:<...>/nim-stackable-hooks/src` resolved either through their `config.nims` (env var fallback) or a workspace sibling lookup. The recommended consumer layout:

```nim
# consumer's config.nims
addPackagePath("STACKABLE_HOOKS_SRC", [
  ".." / "nim-stackable-hooks" / "src",
  "libs" / "vendor" / "nim-stackable-hooks" / "src",
], "stackable_hooks.nim")
```

After `nimble install stackable-hooks` lands, callers can rely on Nimble path resolution and drop the explicit path overlay.
