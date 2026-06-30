# M-FW-3 MCR Migration Blockers

Status: blocked after implementation audit; independently reviewed and
accepted 2026-06-30. No MCR source was migrated in this pass because the
current `stackable_hooks/platform/linux_raw_syscalls` and Windows inline-hook
API surfaces are not yet sufficient to preserve MCR behavior.

M-FW-3A update 2026-06-30: the Linux patch transaction / C ABI / resolver
slice is implemented and independently reviewed in
`stackable_hooks/platform/linux_raw_syscalls`. This addresses the helper
contracts needed before migrating MCR's
`syscall_callsite_patch.nim` and the C translation unit
`clone3_callsite_patch.c`: stage-aware absolute-jump transactions,
post-patch-live diagnostics, neutral C ABI entry points, consumer-controlled
resolver chains, executable-segment validation, and optional duplicate-target
bookkeeping. M-FW-3 remains blocked on the other helper families listed below.

M-FW-3B update 2026-06-30: the Linux x86_64 original-call trampoline slice is
complete after independent review in
`stackable_hooks/platform/linux_raw_syscalls`. This adds conservative
instruction-aware prefix measurement and trampoline construction for wrapper
body patches: supported whole instructions are copied until the absolute-jump
patch window is covered, executable trampoline memory is allocated, and a
14-byte absolute jump back to `target + copiedLen` is appended. Unsupported
prologues are rejected with structured diagnostics. This is still an
algorithmic helper only; MCR source is not migrated by this slice.

M-FW-3C update 2026-06-30: the Linux x86_64 INT3 raw-syscall callsite
substrate is implemented and independently reviewed in
`stackable_hooks/platform/linux_raw_syscalls`. This adds sorted callsite-table
lookup, INT3 patch/restore transactions for selected `0f 05` sites, Linux
x86_64 `ucontext_t` syscall-register capture and result/RIP writeback, raw
syscall replay from captured register state, neutral C ABI entry points, and a
low-level SIGTRAP install/chain/uninstall substrate. The review added live
coverage for an INT3-patched `getpid` syscall stub continuing through replay
and RIP writeback. It remains policy-free: MCR event conversion, mapping
selection, clone/fork/vfork continuation, stage0/static-shim lifecycle,
unrelated-trap escalation policy, and no-libc signal restorer machinery are not
migrated by this slice.

This document is the M-FW-3 implementation artifact. It records why a narrow
partial migration would be misleading, which MCR modules depend on the missing
contracts, and which algorithmic APIs should be added before attempting the
migration again.

## Boundary

Stage0 remains entirely MCR-owned. The missing stackable-hooks pieces below are
algorithmic helpers only: patch transactions, forwarding/trampoline builders,
trap dispatch substrate, symbol/mapping resolvers, and install diagnostics.
MCR must continue to own record/replay policy, target symbol lists, clone3
attribution, stage0 lifecycle proofs, and event ABI.

## Audit Result

The current M-FW-2 Linux helper module provides:

- raw Linux x86_64 syscall forwarding;
- explicit/named 14-byte absolute jump patching;
- restore handles for the overwritten 14-byte window;
- `/proc/self/maps` executable mapping enumeration;
- byte, memory, and selected-mapping scanners for `0f 05` syscall opcodes;
- structured diagnostics for those primitives.

With M-FW-3A, the same module also provides:

- stage-aware patch transactions that distinguish validation, pre-patch
  `mprotect`, write, post-patch `mprotect`-back, and complete stages;
- neutral C ABI functions for transaction patching, resolver lookup,
  executable-segment validation, and optional duplicate-target bookkeeping;
- consumer-controlled resolver chains, including `RTLD_DEFAULT` and opened
  library handles such as `libc.so.6` with `RTLD_NOLOAD`.

Those helpers are useful but do not yet cover the behavior-preserving contracts
used by MCR. Replacing MCR internals with them now would either leave most
private copies in place or change observable behavior in the recorder.

## Blocking Gaps by Helper Family

### Linux `syscall(2)` Wrapper Patching

MCR modules:

- `codetracer-native-recorder/ct_interpose/src/ct_interpose/recording/syscall_callsite_patch.nim`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/clone3_callsite_patch.c`

Current MCR dependencies:

- `_ct_cp_apply_patch` is a C ABI used by both the generic libc `syscall(2)`
  installer and the clone3 extension.
- `_ct_cp_last_errno` and `_ct_cp_last_stage` distinguish fatal RWX
  `mprotect` failure from non-fatal `mprotect`-back failure after the patch is
  live.
- `_ct_cp_addr_in_executable_segment`, `_ct_cp_addr_already_patched`, and
  `_ct_cp_record_patched_addr` are part of MCR's validation and duplicate
  diagnostics.
- The trampoline calls MCR record/replay primitives and preserves MCR event
  stream shape for futex, open-family, read/write/data-returning syscalls, and
  clone3 safeguards.
- `ct_cp_install_libc_wrapper` has a libc-specific symbol resolver with a
  `libc.so.6` `RTLD_NOLOAD` fallback and per-wrapper counters.

Missing stackable-hooks APIs:

- wrapper-level counters and target-selection policy, which should stay in MCR
  but still need migration design once the low-level helpers are consumed;
- full behavior-preserving MCR migration to the new neutral transaction/C ABI
  helper names;

Addressed by M-FW-3A:

- a policy-free patch transaction API that reports stage-specific permission
  failures without imposing restore/uninstall semantics;
- a C ABI wrapper surface suitable for C translation units such as
  `clone3_callsite_patch.c`;
- executable-segment validation helpers independent of MCR diagnostics;
- duplicate-target bookkeeping as an optional helper, not as consumer policy;
- a symbol resolver that can be driven by a consumer-supplied lookup chain such
  as `RTLD_DEFAULT` then `libc.so.6` `RTLD_NOLOAD`.

Addressed by M-FW-3B:

- instruction-aware original-call trampoline construction for Linux x86_64
  wrapper body patches that can be safely copied without relocation;
- measure-only validation so consumers can reject unsupported prologues before
  allocating trampoline memory;
- neutral C ABI entry points for trampoline measurement/construction.

Still not addressed by M-FW-3B:

- RIP-relative relocation and a full instruction decoder;
- thread-suspension or install-timing policy;
- wrapper-level MCR counters and target-selection policy;
- actual MCR migration to call the neutral helpers.

Why migration now would change behavior:

The current stackable helper surface now covers the main Linux wrapper patch
transaction, resolver, C ABI, executable-segment, duplicate-book, and
original-call trampoline primitives. MCR migration is still blocked because the
consumer-owned wrapper policy and the remaining helper families below must be
handled without changing event stream shape or stage0 composition.

### Program-Text Raw Syscall Scan and INT3 Trap

MCR modules:

- `codetracer-native-recorder/ct_interpose/src/ct_interpose/recording/program_syscall_scan.nim`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/static_shim/program_syscall_scan.c`

Current MCR dependencies:

- two-phase executable mapping scan with self-mapping exclusion;
- callsite patching by replacing the first byte of `0f 05` with `INT3`;
- a SIGTRAP handler with previous-handler chaining;
- register extraction from `ucontext_t`;
- syscall argument reconstruction and result writeback into saved registers;
- special clone/fork/vfork continuation handling so child execution resumes at
  the user program's intended RIP rather than inside the recorder helper;
- static-shim raw syscall and no-libc signal-restorer machinery;
- MCR event conversion and replay policy.

Previously missing stackable-hooks APIs addressed by M-FW-3C:

- INT3 callsite patch/unpatch transactions;
- sorted callsite-table lookup helpers suitable for a signal handler;
- SIGTRAP install/chain/uninstall substrate;
- an architecture-specific register-state continuation contract;
- raw syscall replay from captured register state;

Previously missing stackable-hooks APIs addressed by M-FW-3D:

- default Linux x86_64 clone/fork/vfork/clone3 syscall-number classifiers with
  caller-extensible classification hooks;
- synthetic continuation-state helpers that compute parent result/RIP writeback
  and child resume-RIP semantics from captured INT3 register snapshots;
- neutral static-runtime-oriented C ABI symbols for raw syscall forwarding,
  `rt_sigreturn` restorer address exposure, and the low-level clone
  continuation trampoline used by consumers that cannot return through an
  ordinary C raw-syscall wrapper in the child.

Still missing after M-FW-3D:

- consumer-owned mapping/self-exclusion policy and MCR event conversion;
- static-shim lifecycle integration around raw `rt_sigaction` install policy;
- live migration of MCR's program syscall scanner to the new helper symbols.

Why migration now would change behavior:

M-FW-3D covers the generic trap installation, callsite table, register state,
raw replay substrate, clone-family continuation calculation, and exported
low-level static-runtime helper symbols. MCR migration is still not
behavior-preserving until the consumer-owned mapping/self-exclusion policy,
event conversion, raw `rt_sigaction` lifecycle, and existing static-shim
installation behavior are mapped explicitly and tested in MCR.

### Linux vDSO Patching

MCR module:

- `codetracer-native-recorder/ct_interpose/src/ct_interpose/recording/vdso_patch.nim`

Current MCR dependencies:

- vDSO image discovery from `AT_SYSINFO_EHDR`;
- ELF dynamic-section parsing for vDSO symbols;
- direct `mprotect` patching plus MAP_FIXED anonymous overlay fallback when
  hardened kernels reject RWX on the vDSO page;
- per-symbol trampoline bodies for time/getcpu APIs;
- record/replay dispatch and recursion guards.

Missing stackable-hooks APIs:

- policy-free vDSO image and symbol resolver;
- vDSO-specific patch transaction that supports direct patch and MAP_FIXED
  overlay fallback;
- per-symbol trampoline/original-call helper construction;
- structured vDSO diagnostics.

Why migration now would change behavior:

The current absolute-jump patch primitive does not implement the MAP_FIXED
overlay fallback that MCR relies on for hardened-kernel compatibility. Replacing
only the direct patch path would weaken existing vDSO coverage.

### POSIX Atomic and JIT Callsite Patching

MCR modules:

- `codetracer-native-recorder/ct_interpose/src/ct_interpose/atomic_callsite_patch_posix.c`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/atomic_jit_patch_posix.c`

Current MCR dependencies:

- instruction classification for LOCK/XCHG/fence sites;
- per-image near trampoline page allocation;
- JMP-rel32 vs INT3 fallback selection;
- register-preserving trampoline generation;
- SIGTRAP handler fallback for short instructions;
- JIT range registration/deregistration after `mmap`/`mprotect` transitions;
- MCR atomic event and replay semantics.

Missing stackable-hooks APIs:

- instruction-window classification helpers;
- near trampoline page allocator;
- architecture-specific trampoline emitter;
- patch strategy chooser for JMP-rel32 vs INT3;
- generic JIT executable-range registry;
- reusable trap dispatch substrate shared with raw syscall callsites.

Why migration now would change behavior:

The current stackable Linux API has no instruction decoder, trampoline emitter,
or INT3 fallback. MCR's atomic instrumentation depends on all three for event
ordering and for avoiding masked-SIGTRAP windows.

### Windows Inline and No-Suspend Hooks

MCR modules:

- `codetracer-native-recorder/ct_interpose/src/ct_interpose/ntdll_detours_windows.nim`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/ldrloaddll_detour_windows.nim`

Current MCR dependencies:

- normal suspending inline install;
- noreturn inline install;
- stage0-selected no-suspend install;
- stage0-selected noreturn no-suspend install;
- handler enter/leave reentrancy counters;
- MCR diagnostics around target resolution and install ordering.

Missing stackable-hooks APIs:

- exported no-suspend install primitive with an explicit single-thread/stage0
  precondition contract;
- exported noreturn no-suspend primitive;
- tests covering no-suspend behavior and parity with the MCR-vendored C
  sources.

Why migration now would change behavior:

`nim-stackable-hooks` currently exports normal and noreturn Windows inline
install wrappers, but not the no-suspend variants MCR selects when stage0 has
already established the required installation preconditions. Migrating only the
legacy path would split MCR's inline-hook source of truth and leave the stage0
path on private symbols.

## Required API Additions Before Reattempt

1. Map MCR's program syscall scanner to the new INT3/continuation/static-helper
   symbols without changing its mapping selection, event conversion, or signal
   lifecycle behavior.
2. Add vDSO ELF resolver and direct-or-overlay patch transaction helpers.
3. Add generic executable-range/JIT bookkeeping and near-trampoline allocation
   helpers for POSIX code patching.
4. Export and test Windows no-suspend and noreturn no-suspend inline install
   primitives with precondition documentation.

## M-FW-3 Status

M-FW-3 is blocked, not done. The current implementation pass intentionally
leaves MCR source unchanged rather than claiming a migration that would not
preserve MCR behavior or event stream shape.
