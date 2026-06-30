# M-FW-0 MCR Monkey-Patch Helper Inventory

Status: M-FW-0 inventory complete. This document is an implementation-status
artifact for the "Inventory and split MCR monkey-patch helpers" milestone. It
does not extract code. It records the boundary for later extraction work.

M-FW-2 update: the first Linux raw-syscall helper extraction now lives in
`src/stackable_hooks/platform/linux_raw_syscalls.nim`. It covers raw syscall
forwarding, explicit/named x86_64 absolute-jump body patching with restore
handles and diagnostics, `/proc/self/maps` executable mapping enumeration, and
byte/memory/mapping visitor scanners for Linux x86_64 `0f 05` callsites. It
does not migrate MCR, patch libc in tests, install a SIGTRAP substrate, or
implement io-mon monitor classification.

## Boundary

`nim-stackable-hooks` owns reusable, algorithmic helper primitives: page
permission changes, body/inline patch mechanics, trampoline construction,
executable mapping scans, signal/VEH dispatch substrate, raw/original forwarding
stubs, vDSO/symbol resolution, reentrancy state, and install diagnostics.

Consumers own composition and policy. MCR stage0 remains entirely
`codetracer-native-recorder` architecture. The same helper primitives may be
assembled by `nim-stackable-hooks` into a traditional interpose shim framework,
or by MCR into its stage0/recording paths. Event schemas, record/replay
semantics, target lists, lifecycle ordering, fail-open/fail-closed policy, and
process-injection strategy do not move into `nim-stackable-hooks`.

## Inventory

### Linux `syscall(2)` Wrapper Patching

Source files:

- `codetracer-native-recorder/ct_interpose/src/ct_interpose/recording/syscall_callsite_patch.nim`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/clone3_callsite_patch.c`

Framework-safe helper candidates:

- Resolve a patch target by symbol or explicit address. Implemented for
  `RTLD_DEFAULT` symbols in `linux_raw_syscalls`.
- Validate an x86_64 syscall-wrapper prologue before patching. Partially
  represented by duplicate absolute-jump detection; full instruction-aware
  prologue validation remains for later trampoline work.
- Change page permissions with raw syscalls so patch installation does not
  recurse through hooked libc wrappers. Implemented for the absolute-jump
  patch/restore primitive.
- Install an absolute or near jump at a wrapper entry point. Absolute
  RIP-indirect jump implemented; near-jump selection remains out of scope.
- Build and publish a trampoline/original-call handle. A restore handle with
  the overwritten 14-byte window is implemented; instruction-decoded
  original-call trampolines remain for later work.
- Provide a small raw syscall forwarding stub for framework internals.
  Implemented as `rawSyscall6`.
- Report structured install diagnostics per target. Implemented.
- Provide an optional single-thread/no-suspend primitive with explicit
  preconditions, but no stage0 policy.

MCR-owned adapters and policy:

- `ctRecordOsEvent`, `ctRecordOsOpenEvent`, replay decoders, and event typing.
- clone3 and pthread attribution payloads.
- stage0 state reconstruction and proof that no-suspend installation is safe.
- MCR-specific skip lists, recorder lifecycle ordering, and trace diagnostics.

Expected future consumers:

- io-mon: use wrapper patching to close libc `syscall(2)` bypasses in the Linux
  shim framework, then classify syscalls into monitor records in io-mon-owned
  callbacks.
- MCR: use the same primitives in recording and stage0 paths while retaining
  record/replay and stage0 composition locally.

### Program-Text Raw Syscall Scan and INT3 Trap

Source files:

- `codetracer-native-recorder/ct_interpose/src/ct_interpose/recording/program_syscall_scan.nim`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/static_shim/program_syscall_scan.c`

Framework-safe helper candidates:

- Enumerate readable executable mappings and let consumers exclude
  caller-provided mappings such as the shim's own code. Implemented as a
  policy-free maps enumerator.
- Scan instruction bytes for Linux x86_64 raw syscall opcodes. Implemented for
  controlled byte regions and selected readable memory mappings, including
  MCR's current immediate-operand false-positive guard.
- Patch selected callsites with INT3 or an alternate trap byte. Still pending;
  M-FW-2 extracted scanner/description surfaces only, not signal installation.
- Maintain a sorted callsite table for signal-handler lookup.
- Install and chain a SIGTRAP handler substrate.
- Reconstruct syscall arguments from ucontext and resume execution after the
  original syscall instruction.
- Dispatch to a consumer callback for byte- and mapping-scanned callsite
  descriptions. Register-state and continuation contracts remain pending with
  the SIGTRAP substrate.
- Emit structured scan/patch diagnostics per mapping and callsite.

MCR-owned adapters and policy:

- Mapping eligibility based on MCR recorder invariants.
- Event conversion to MCR OS/open events.
- Replay consumption and divergence checks.
- Static-shim bootstrap sequencing.
- Any policy deciding which raw syscalls are recordable, fatal, ignored, or
  replay-only.

Expected future consumers:

- io-mon: detect and route inline `0f 05` callsites in monitored programs to an
  io-mon syscall classifier, with fail-closed capability reporting when the
  scan or trap install is required but unavailable.
- MCR: reuse the scanner/trap substrate while retaining MCR event ABI and
  replay behavior.

### Linux vDSO Patching

Source files:

- `codetracer-native-recorder/ct_interpose/src/ct_interpose/recording/vdso_patch.nim`

Framework-safe helper candidates:

- Locate the vDSO image and exported vDSO symbols.
- Validate patchable vDSO wrapper prologues.
- Install body patches and per-symbol trampoline/original handles.
- Provide raw syscall fallbacks for helper internals.
- Record structured diagnostics for missing, skipped, and patched symbols.

MCR-owned adapters and policy:

- Time/getcpu event schemas.
- Record vs replay dispatch.
- MCR-specific determinism policy for clock sources.
- Target-symbol list decisions beyond a generic caller-provided list.

Expected future consumers:

- io-mon: use later if monitor completeness requires vDSO-adjacent coverage for
  time or identity reads, with io-mon-owned event classification.
- MCR: preserve existing deterministic time/getcpu recording using extracted
  low-level patch helpers.

### POSIX Atomic and JIT Callsite Patching

Source files:

- `codetracer-native-recorder/ct_interpose/src/ct_interpose/atomic_callsite_patch_posix.c`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/atomic_jit_patch_posix.c`

Framework-safe helper candidates:

- Decode and classify candidate instruction windows supplied by a consumer.
- Allocate per-image trampoline pages near patched code.
- Emit trampoline bodies for fixed-width patch strategies where architecture
  support is present.
- Choose between JMP-rel32 and INT3 fallback patch strategies based on range and
  safety checks.
- Patch/unpatch code pages with raw mprotect helpers.
- Install and chain SIGTRAP dispatch for patched callsites.
- Register executable JIT ranges after mprotect/mmap transitions.
- Provide deduplication and lifecycle bookkeeping for dynamically patched
  ranges.

MCR-owned adapters and policy:

- Atomic-event semantics, sync ids, memory-order interpretation, and replay.
- MCR's mprotect/mmap hook policy and JIT eligibility decisions.
- Internal recursion handling specific to `ctRecordAtomicEvent`.
- Any recorder diagnostics tied to MCR milestone IDs or event stream shape.

Expected future consumers:

- io-mon: no direct M-FW-2 dependency expected unless io-mon later needs generic
  executable-range patching for a monitor capability.
- MCR: keep atomic/JIT event semantics while sharing scanner, trampoline, and
  patch substrate where practical.

### Windows Inline and IAT Helpers

Source files:

- `codetracer-native-recorder/ct_inline_hook/`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/iat_patcher.nim`
- Already partly extracted in `nim-stackable-hooks/src/stackable_hooks/inline_hook/windows/`
- Already partly extracted in `nim-stackable-hooks/src/stackable_hooks/platform/windows_iat_patcher.nim`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/ntdll_detours_windows.nim`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/ldrloaddll_detour_windows.nim`

Framework-safe helper candidates:

- Keep the existing prologue decoder, rel32/RIP-relative fixup, trampoline
  allocator, inline install/uninstall API, transaction API, and IAT walker.
- Add explicit API shape for single-thread/no-suspend installation only as a
  primitive with documented preconditions.
- Preserve tracked IAT patch records and retroactive unpatch as generic
  mechanics where they are not tied to MCR event policy.
- Expose structured diagnostics for attempted, skipped, and successful patches.

MCR-owned adapters and policy:

- NT syscall target list and handler bodies.
- `ctRecordOsEvent` and replay behavior.
- stage0 install loop, stage0 readiness checks, and proof that no-suspend
  installation is safe.
- CLR-specific policy deciding when to retroactively unpatch IAT entries, beyond
  generic mechanics.
- Loader-detour sequencing and MCR diagnostics.

Expected future consumers:

- io-mon: use Windows framework hooks if/when io-mon gains Windows monitoring
  parity.
- MCR: continue composing inline/IAT primitives into NT-detour, loader-detour,
  and stage0 paths without moving stage0 itself into `nim-stackable-hooks`.

### io-mon macOS Bodypatch

Source files:

- `io-mon-hardening-work/src/io_mon/hooks/macos_bodypatch.nim`
- `io-mon-hardening-work/src/io_mon/shim/macos_interpose.nim`
- `nim-stackable-hooks/src/stackable_hooks/platform/macos_bodypatch.nim`

Framework-safe helper candidates:

- Resolve real libSystem symbols while excluding the shim image.
- Track idempotent bodypatch installs.
- Build arm64 branch stubs.
- Use `mach_vm_allocate`, `mach_vm_protect`, and `mach_vm_remap` to overwrite
  immutable shared-cache text via a fresh executable page.
- Detect simple non-relocatable prologues for trampoline safety.
- Build trampoline/original-call handles for functions that need to forward into
  the original wrapper body.
- Report structured per-symbol install diagnostics.

io-mon-owned adapters and policy:

- Monitor record emission, RMDF fragment writing, fd/path maps, canonical-path
  cache, environment propagation decisions, and completeness downgrades.
- Symbol list and hook-body semantics for filesystem, process, IPC,
  randomness, time, sysctl, dyld-image, and copy/link operations.
- Degradation policy for functions left interpose-only when trampoline
  construction is unsafe.

Expected future consumers:

- io-mon: current M-FW-1 consumer after extraction.
- MCR: potential future macOS consumer only if it needs the same bodypatch
  primitive; MCR-specific composition remains in MCR.

M-FW-1 implementation note:

- `nim-stackable-hooks/src/stackable_hooks/platform/macos_bodypatch.nim` now owns
  the reusable macOS bodypatch install, Mach-O symbol resolution with
  caller-supplied image exclusion, idempotent target tracking, and trampoline
  construction helpers. io-mon supplies the symbol list, hook bodies, debug
  toggles, diagnostics banner, and degradation policy.
- `nim-stackable-hooks/tests/test_macos_bodypatch_minimal_consumer.nim`
  exercises a standalone consumer that installs named plain and trampoline
  hooks through the public API. On non-macOS hosts it is intentionally a no-op;
  macOS-target `nim check --os:macosx --cpu:arm64` verifies the realistic
  consumer shape until live Darwin runtime coverage is available.

## Acceptance Checklist

- [x] Each required MCR monkey-patch helper family is listed with source files.
- [x] Linux `syscall(2)` wrapper patching includes
  `recording/syscall_callsite_patch.nim` and `clone3_callsite_patch.c`.
- [x] Program-text raw syscall scan/INT3 trapping includes
  `recording/program_syscall_scan.nim` and
  `static_shim/program_syscall_scan.c`.
- [x] Linux vDSO patching includes `recording/vdso_patch.nim`.
- [x] POSIX atomic/JIT callsite patching includes
  `atomic_callsite_patch_posix.c` and `atomic_jit_patch_posix.c`.
- [x] Windows inline/IAT coverage includes the already extracted helpers plus
  MCR no-suspend/single-thread stage0 uses in `ntdll_detours_windows.nim` and
  `ldrloaddll_detour_windows.nim`.
- [x] io-mon macOS bodypatch is recorded as a non-MCR source for M-FW-1.
- [x] The document separates algorithmic helper candidates from
  consumer-owned adapters, policy, record/replay, and stage0 composition.
- [x] Expected future consumers are named for every family.
- [x] The stage0 boundary is explicit: helper primitives may be shared, but
  stage0 architecture and composition stay MCR-owned.
- [x] No later milestone is marked complete by this document.

## Automated Checks

There is no obvious documentation-specific automated check or link checker in
`nim-stackable-hooks` today. The package's available lightweight automated check
is the Nimble test task, which runs the core Nim tests. M-FW-0 does not add
ignored or skipped tests because it does not change runtime code.
