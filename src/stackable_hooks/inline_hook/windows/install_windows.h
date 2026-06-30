/*
 * ct_inline_hook/install_windows.h
 *
 * Windows inline-hook backend (M50.2).
 *
 * Sits on top of:
 *   - ct_inline_hook/length_decoder.{c,h}  (M50.0)  — prologue length
 *     decoding via ct_ild_decode_to_cover().
 *   - ct_inline_hook/rel32_fixup.{c,h}     (M50.1)  — rel32 + RIP-rel
 *     displacement fixup via ct_rel32_fixup_prologue().
 *
 * Public API mirrors the Linux callsite-patch shape:
 *
 *   int ct_inline_hook_install(void *target, void *hook, void **out_trampoline);
 *   int ct_inline_hook_uninstall(void *target);
 *
 * Implementation cites:
 *   MCR-Windows-Inline-Hooking.md §"Thread safety"   (normative)
 *   MCR-Windows-Inline-Hooking.md §"Hot-patch support" (normative)
 *   Detours src/detours.cpp DetourTransactionCommitEx (thread-suspend pattern)
 *   MinHook src/hook.c EnumerateThreads/Freeze/Unfreeze (toolhelp32 pattern)
 *
 * Re-entrancy: a __declspec(thread) initial-exec TLS slot mirrors the
 * Linux convention `_ct_ap_in_handler` (see
 * codetracer-native-recorder/ct_interpose/src/ct_interpose/atomic_callsite_patch.c).
 * Hook bodies bracket their recording work with
 *   CT_INLINE_HOOK_ENTER();
 *   ...record...
 *   CT_INLINE_HOOK_LEAVE();
 * Inside the guarded region a hook that ultimately re-enters a hooked
 * target observes ct_inline_hook_in_handler() == 1 and dispatches via
 * the trampoline (bypassing the hook) instead of looping.
 *
 * Transactions: ct_inline_hook_begin_transaction/commit/abort group
 * multiple installs/uninstalls into a single thread-suspend window
 * (Detours DetourTransactionBegin/Commit, MinHook MH_QueueEnableHook
 * + MH_ApplyQueued).  Use when atomic batching is required.
 */

#ifndef CT_INLINE_HOOK_INSTALL_WINDOWS_H
#define CT_INLINE_HOOK_INSTALL_WINDOWS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Public install/uninstall ------------------------------------- */

/* Install a 5-byte JMP rel32 detour at `target`, redirecting calls to
 * `hook`.  On success, `*out_trampoline` is set to a function pointer
 * that executes the original prologue and then jumps back to
 * `target + prologue_len`, so the hook body can call through to the
 * original behavior.
 *
 * Returns 0 on success, <0 on failure:
 *   -1  invalid argument (NULL pointer)
 *   -2  length decoder rejected the target prologue (caller must fall
 *       back to int3 patching or a different mechanism)
 *   -3  rel32 fixup failed (out-of-range disp32 with no thunk room)
 *   -4  VirtualAlloc / VirtualProtect / thread suspend failed
 *   -5  target already hooked (use uninstall first, or layer manually
 *       through trampolines)
 */
int ct_inline_hook_install(void *target, void *hook, void **out_trampoline);

/* Unsafe no-suspend install variant.
 *
 * Identical to ct_inline_hook_install except that it does NOT call
 * suspend_other_threads / resume_other_threads around the patch write.
 *
 * Contract: use this entry point only when the caller has independently
 * proved that no other thread can execute the target prologue while it is
 * being patched. This is a primitive for consumers with their own lifecycle
 * proof, not a generally thread-safe install API. Calling it in a
 * multithreaded context can race with instruction fetch from the modified
 * bytes and corrupt the process. This variant is intentionally not queued into
 * transactions, since transaction commit suspends threads by design.
 *
 * Same return-value semantics as ct_inline_hook_install. */
int ct_inline_hook_install_no_suspend(void *target, void *hook,
                                      void **out_trampoline);

/* Install a "record-then-continue" detour at `target` for a *noreturn*
 * (or noreturn-on-current-thread) NT syscall stub.  MW13
 * (MCR-Windows-CtMcr-Port.milestones.org).
 *
 * Unlike ct_inline_hook_install -- where the hook function is the
 * call target and is responsible for invoking the trampoline back to
 * the original code -- the noreturn variant inverts the relationship:
 *
 *   * The trampoline (the code the 5-byte JMP rel32 at `target`
 *     redirects to) is the only thing that runs on top of NTDLL's
 *     stack frame.
 *   * The trampoline saves the caller's volatile arg registers
 *     (RCX/RDX/R8/R9 on Win64), CALLs the supplied `record_callback`
 *     (which records the event), restores the caller's arg
 *     registers, runs the copied prologue with the original
 *     register/stack state, then JMPs to `target + prologue_len` so
 *     the SYSCALL fires exactly as if no hook were present.
 *   * No "hook function" with its own stack frame, prologue, and
 *     epilog ever sits between RtlExitUserThread and the SYSCALL.
 *
 * Why this matters:
 *
 *   For noreturn NT syscalls (NtTerminateThread of NtCurrentThread,
 *   NtRaiseHardError on a terminating fault, NtContinue), the kernel
 *   walks the user-mode stack frame at SYSCALL time to snapshot DR
 *   registers, exception records, and APC state for the thread-
 *   termination bookkeeping.  The pre-MW13 design routed the syscall
 *   through a Nim/C hook function whose ABI-required frame (push
 *   rbp, sub rsp, callee-saved register saves) added a frame that
 *   RtlExitUserThread had not set up -- which on the inject_dll-
 *   spawned init thread (BaseThreadInitThunk -> RtlExitUserThread
 *   is the only frame above) confused the kernel's unwinder and
 *   AVed with STATUS_ACCESS_VIOLATION inside the trampoline's JMP
 *   back to target+prologue_len ("trampoline epilog AV" in MW6
 *   Remaining item 2).
 *
 *   The noreturn-mode trampoline does not insert any frame: the
 *   stack at the SYSCALL site is byte-identical to what
 *   RtlExitUserThread had set up (the trampoline's `sub rsp, N /
 *   add rsp, N` window is entirely unwound before the JMP to the
 *   syscall).  The kernel's unwinder sees exactly the stack it
 *   would have seen without our hook.
 *
 * Calling convention for `record_callback`:
 *
 *   * Standard Win64 stdcall/fastcall (same as the original NT
 *     stub).  The trampoline calls it as:
 *
 *       record_callback(arg1, arg2);   // RCX = arg1, RDX = arg2
 *
 *     The hook author types `record_callback` as
 *     `void (__stdcall *)(void *arg1, int32_t arg2)` (or whatever
 *     the underlying NT stub's first two args are).
 *
 *   * The callback MUST return (no noreturn pragma).  After it
 *     returns, the trampoline restores RCX/RDX and jumps into the
 *     original syscall.
 *
 *   * The callback's return value is ignored.  RAX may be clobbered;
 *     the SYSCALL prologue sets RAX = syscall number before
 *     executing SYSCALL.
 *
 *   * The callback MUST NOT touch R8, R9 (the trampoline does not
 *     save them -- for NtTerminateThread these are unused; for any
 *     future client whose NT stub uses them, extend the trampoline
 *     to save R8/R9 too).
 *
 * `out_trampoline` is set to NULL on success (the caller has no use
 * for a trampoline pointer -- the noreturn-mode design does not
 * expose one).  The argument is kept for symmetry with
 * ct_inline_hook_install.  May be passed as NULL.
 *
 * Returns 0 on success, same negative error codes as
 * ct_inline_hook_install. */
int ct_inline_hook_install_noreturn(void *target, void *record_callback,
                                    void **out_trampoline);

/* Unsafe no-suspend variant of ct_inline_hook_install_noreturn.
 * See ct_inline_hook_install_no_suspend for the required caller-proved
 * single-thread/no-executing-prologue invariant. */
int ct_inline_hook_install_noreturn_no_suspend(void *target,
                                               void *record_callback,
                                               void **out_trampoline);

/* Uninstall the hook at `target`, restoring the original prologue
 * bytes.  Returns 0 on success, <0 on failure:
 *   -1  no hook registered at this target
 *   -4  VirtualProtect / thread suspend failed
 */
int ct_inline_hook_uninstall(void *target);

/* Unsafe no-suspend uninstall variant. See ct_inline_hook_install_no_suspend
 * for the required caller-proved single-thread/no-executing-prologue
 * invariant. This variant is intentionally not queued into transactions,
 * since transaction commit suspends threads by design. */
int ct_inline_hook_uninstall_no_suspend(void *target);

/* ---- Transactions (atomic batching) ------------------------------- */

/* Begin a transaction.  Subsequent ct_inline_hook_install /
 * ct_inline_hook_uninstall calls on the same thread are deferred and
 * committed together by ct_inline_hook_commit_transaction.  Nested
 * begin calls return -1.
 *
 * Note: when a transaction is active, the install/uninstall calls
 * return 0 if they were successfully queued; the queued operation may
 * still fail at commit time (returning a non-zero code from commit).
 *
 * Returns 0 on success, <0 if a transaction is already active. */
int ct_inline_hook_begin_transaction(void);

/* Commit a transaction.  Applies all queued installs/uninstalls inside
 * a single thread-suspend window.  Returns 0 on success, <0 if a queued
 * operation failed (the same error code that install/uninstall would
 * have returned outside a transaction).  On failure, the queue is
 * rolled back and no targets are modified. */
int ct_inline_hook_commit_transaction(void);

/* Abort the current transaction.  Drops all queued operations without
 * touching any targets.  Returns 0 on success, <0 if no transaction
 * is active. */
int ct_inline_hook_abort_transaction(void);

/* ---- Re-entrancy TLS guard ---------------------------------------- */

/* Returns non-zero if the current thread is inside a
 * CT_INLINE_HOOK_ENTER/LEAVE bracket.  Hook bodies that want to call
 * back into a hooked target without re-entering the hook should check
 * this and route to the trampoline directly when set. */
int ct_inline_hook_in_handler(void);

/* Enter / leave the guard.  Implemented as inline functions over the
 * TLS slot for predictable codegen (a single %gs:offset load on x64). */
void ct_inline_hook_enter(void);
void ct_inline_hook_leave(void);

/* Convenience macros for hook bodies. */
#define CT_INLINE_HOOK_ENTER() ct_inline_hook_enter()
#define CT_INLINE_HOOK_LEAVE() ct_inline_hook_leave()

/* ---- Debug introspection ------------------------------------------ */

/* Returns the install mode used for the most recent successful
 * ct_inline_hook_install call:
 *   0  CT_INSTALL_MODE_OVERWRITE  (5-byte JMP rel32 at target)
 *   1  CT_INSTALL_MODE_HOTPATCH   (hot-patch two-short-jump sequence)
 *  -1  no install has succeeded since process start
 * Used by tests; not a stable API surface. */
int ct_inline_hook_install_get_last_install_mode(void);

#define CT_INSTALL_MODE_OVERWRITE 0
#define CT_INSTALL_MODE_HOTPATCH  1

#ifdef __cplusplus
}
#endif

#endif /* CT_INLINE_HOOK_INSTALL_WINDOWS_H */
