# M-FW-3 MCR Migration Blockers

Status: partial after the first parent M-FW-3 implementation pass on
2026-06-30. The original blocked audit was independently reviewed and accepted;
subsequent M-FW-3A..G helper slices closed the missing primitive gaps. The
first MCR migration pass moved the behavior-preserving Windows inline-hook
install surfaces onto `stackable_hooks/inline_hook/windows_inline_hook`, while
leaving MCR policy and stage0 composition in MCR. Linux syscall-wrapper,
program-text syscall-scan, vDSO, and POSIX atomic/JIT MCR migration remain
open.

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

M-FW-3 parent migration pass 1 update 2026-06-30: MCR's Windows inline-hook
users now consume the stackable helper module directly. The migrated files are:

- `codetracer-native-recorder/ct_interpose/src/ct_interpose/ntdll_detours_windows.nim`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/ldrloaddll_detour_windows.nim`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/getprocaddress_detour_windows.nim`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/gfx_capture_windows.nim`

This pass preserves the architecture boundary: MCR still owns stage0
discrimination, target resolution, install ordering, diagnostics, trampoline
consumers, and event bodies. `nim-stackable-hooks` supplies only the low-level
inline-hook helper and unsafe no-suspend primitive. The parent milestone is
still open because the Linux helper families below have not yet been migrated
in MCR.

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

Those helpers are useful and now cover enough primitive surface for targeted
MCR migrations. Windows inline-hook consumers have been migrated. The Linux
helper families below still need explicit MCR-side migration work to avoid
changing observable recorder behavior.

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

Previously missing stackable-hooks APIs addressed by M-FW-3E:

- policy-free vDSO image and symbol resolver;
- vDSO-specific patch transaction that supports direct patch and MAP_FIXED
  overlay fallback;
- structured vDSO diagnostics.

Still missing after M-FW-3E:

- MCR-owned per-symbol trampoline bodies for time/getcpu wrappers;
- MCR-owned target symbol list, record/replay dispatch, recursion guards, and
  install lifecycle;
- live MCR migration of `recording/vdso_patch.nim` to the helper APIs.

Why migration now would change behavior:

M-FW-3E covers image discovery from `AT_SYSINFO_EHDR`, bounded ELF
dynamic-section symbol resolution, direct vDSO symbol patching, explicit
page-aligned MAP_FIXED anonymous overlay fallback, and structured diagnostics.
MCR migration still requires mapping MCR's time/getcpu trampoline bodies,
event/replay semantics, recursion guard, target-list policy, and
constructor/status lifecycle onto those helpers without changing the event
stream or install behavior.

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

Previously missing stackable-hooks APIs addressed by M-FW-3F:

- bounded instruction-window classification helpers for LOCK-prefixed memory
  RMW instructions, implicit-lock memory XCHG, and MFENCE/SFENCE/LFENCE;
- caller-writable near trampoline allocation with rel32 reachability reporting;
- patch strategy chooser for JMP-rel32 vs INT3 based on instruction length and
  trampoline reachability;
- generic JIT executable-range registry with merge/subtract/deregister
  lifecycle bookkeeping;
- neutral C ABI symbols for classifier, strategy selection, and near
  allocation/freeing.

Still missing after M-FW-3F:

- MCR's register-saving atomic event trampoline emitter;
- full decoder/relocator parity for every instruction form MCR currently
  accepts in `atomic_common.c`;
- MCR atomic event, sync-id, replay, recursion-guard, and diagnostics policy;
- MCR integration with `mmap`/`mprotect` hooks and reverse-patching lifecycle.

Why migration now would change behavior:

M-FW-3F supplies the generic classification, near-allocation, strategy, and JIT
range bookkeeping pieces needed to remove the broad atomic/JIT helper blocker.
It intentionally does not emit MCR's recorder-aware trampolines or move atomic
event/replay policy into the shared library. A behavior-preserving MCR
migration still needs to wire these primitives into MCR-owned scanner,
trampoline, event, and lifecycle code.

### Windows Inline and No-Suspend Hooks

MCR modules:

- `codetracer-native-recorder/ct_interpose/src/ct_interpose/ntdll_detours_windows.nim`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/ldrloaddll_detour_windows.nim`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/getprocaddress_detour_windows.nim`
- `codetracer-native-recorder/ct_interpose/src/ct_interpose/gfx_capture_windows.nim`

Current MCR dependencies:

- normal suspending inline install;
- noreturn inline install;
- stage0-selected no-suspend install;
- stage0-selected noreturn no-suspend install;
- handler enter/leave reentrancy counters;
- MCR diagnostics around target resolution and install ordering.

Missing stackable-hooks APIs:

Previously missing stackable-hooks APIs addressed by M-FW-3G:

- exported no-suspend install primitive with an explicit caller-proved
  single-thread/non-racing precondition contract;
- exported noreturn no-suspend primitive with the same precondition;
- exported no-suspend uninstall primitive for symmetry with the vendored MCR
  helper surface;
- explicit rejection of active transactions for the unsafe no-suspend entry
  points, because transaction commit suspends threads by design;
- source-level and Windows-target API checks for the public Nim wrappers and
  underlying C symbols, plus Linux-host runtime checks that the non-Windows C
  stubs return unsupported instead of crashing.

Migrated in parent M-FW-3 pass 1:

- `ntdll_detours_windows.nim` imports the stackable wrapper for normal,
  unsafe no-suspend, noreturn, and unsafe no-suspend noreturn installs while
  keeping MCR's stage0 discriminator and diagnostics local.
- `ldrloaddll_detour_windows.nim` imports the stackable wrapper for normal and
  unsafe no-suspend installs plus handler enter/leave guards while keeping
  module-load policy local.
- `getprocaddress_detour_windows.nim` imports the stackable wrapper for normal
  and unsafe no-suspend installs plus handler-state checks while keeping the
  redirect policy local.
- `gfx_capture_windows.nim` no longer compiles the old local inline-hook C
  sources; it imports the stackable wrapper as the shared compile point while
  keeping graphics-capture policy local.

Remaining Windows risks:

- live Windows runtime validation still has to prove the stage0/single-thread
  no-suspend precondition at the migrated call sites;
- MCR diagnostics around target resolution, install ordering, and stage0
  transitions remain MCR-owned and must be reviewed against Windows traces.

## Required API Additions Before Reattempt

1. Map MCR's program syscall scanner to the new INT3/continuation/static-helper
   symbols without changing its mapping selection, event conversion, or signal
   lifecycle behavior.
2. Migrate MCR vDSO patching onto the helper APIs while preserving MCR-owned
   target lists, trampoline bodies, event/replay policy, and diagnostics.
3. Wire M-FW-3F's POSIX atomic/JIT helper slice into MCR-owned
   scanner/trampoline/event lifecycle code without changing MCR behavior.
4. Run independent review and live Windows validation for the parent M-FW-3
   Windows migration pass.

## M-FW-3 Status

M-FW-3 is partial, not done. The first parent migration pass moved the
behavior-preserving Windows inline-hook install users onto
`stackable_hooks/inline_hook/windows_inline_hook` while preserving MCR-owned
stage0 composition and diagnostics. Linux syscall-wrapper, program-text
syscall-scan, vDSO, and POSIX atomic/JIT migrations remain open.
