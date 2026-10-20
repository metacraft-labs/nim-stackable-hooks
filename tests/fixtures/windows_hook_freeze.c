/* Thread-freeze regression for the Windows inline-hook backend.
 *
 * The backend must patch only after every other thread of the process is
 * suspended or has confirmably exited. Otherwise the default entry points
 * must return -4 before any patch byte changes, with the threads they had
 * suspended resumed and every handle closed.
 *
 * Everything runs against the real backend, real executable pages, real
 * peer threads and the real kernel. The wrappers below always call the
 * real Toolhelp32 / thread APIs. Why each one is there:
 *
 * - Handle tracking (CreateToolhelp32Snapshot, OpenThread, CloseHandle):
 *   records which handles the backend acquired and released, so a leak is
 *   a counted fact rather than an inference from GetProcessHandleCount.
 * - Snapshot filtering (Thread32First/Next): hides threads of this process
 *   that the test did not create -- loader and thread-pool workers -- so
 *   that CT_FROZEN_MAX = 2 is reached by exactly the peers below. No peer
 *   and no other process's entry is hidden.
 * - Fault injection, three cases only, each because the real kernel cannot
 *   be made to produce it deterministically from inside the process:
 *   Thread32First failing, Thread32Next failing mid-walk, and OpenThread
 *   denying access to a live thread (the owner of a thread can always
 *   reopen it, and SeDebugPrivilege may bypass a DACL). Each returns FALSE
 *   or NULL with ERROR_ACCESS_DENIED, as the kernel would.
 * - Real kernel outcomes, no injection: SuspendThread refused for a live
 *   thread at MAXIMUM_SUSPEND_COUNT, and threads that really exit between
 *   the snapshot and OpenThread (with the last handle closed, or with a
 *   handle still held so OpenThread succeeds on the terminated thread) or
 *   between OpenThread and SuspendThread. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PEER_MAX 3
typedef struct {
    HANDLE thread, go, done;
    DWORD tid;
    volatile LONG stop;
    int ended;  /* thread has terminated; `thread` may still hold it */
} peer_t;
static peer_t peers[PEER_MAX];
static DWORD main_tid;

enum { FAULT_NONE, FAULT_FIRST, FAULT_NEXT_AFTER_SUSPEND, FAULT_OPEN,
       EXIT_BEFORE_OPEN, EXIT_BEFORE_OPEN_HELD, EXIT_BEFORE_SUSPEND };
static int fault = FAULT_NONE;
static DWORD fault_tid;
static int backend_suspends;

#define TRACK_MAX 64
static HANDLE tracked[TRACK_MAX];
static int tracked_count;

static void track(HANDLE h)
{
    if (tracked_count < TRACK_MAX) tracked[tracked_count++] = h;
}

static void untrack(HANDLE h)
{
    for (int i = 0; i < tracked_count; i++)
        if (tracked[i] == h) { tracked[i] = tracked[--tracked_count]; return; }
}

static DWORD WINAPI peer_main(void *argument)
{
    peer_t *p = (peer_t *)argument;
    for (;;) {
        if (WaitForSingleObject(p->go, INFINITE) != WAIT_OBJECT_0) return 1;
        if (InterlockedCompareExchange(&p->stop, 0, 0)) return 0;
        SetEvent(p->done);
    }
}

static int start_peer(peer_t *p)
{
    memset(p, 0, sizeof(*p));
    p->go = CreateEventW(NULL, FALSE, FALSE, NULL);
    p->done = CreateEventW(NULL, FALSE, FALSE, NULL);
    p->thread = CreateThread(NULL, 0, peer_main, p, 0, &p->tid);
    return p->go && p->done && p->thread;
}

/* Terminate the peer's thread but keep the test's handle to it open. */
static void end_peer_thread(peer_t *p)
{
    InterlockedExchange(&p->stop, 1);
    SetEvent(p->go);
    WaitForSingleObject(p->thread, 5000);
    p->ended = 1;
}

static void stop_peer(peer_t *p)
{
    if (p->thread == NULL) return;
    if (!p->ended) end_peer_thread(p);
    CloseHandle(p->thread);
    CloseHandle(p->go);
    CloseHandle(p->done);
    p->thread = NULL;
}

static int peer_responds(peer_t *p)
{
    return SetEvent(p->go) && WaitForSingleObject(p->done, 5000) == WAIT_OBJECT_0;
}

static peer_t *peer_by_tid(DWORD tid)
{
    for (int i = 0; i < PEER_MAX; i++)
        if (peers[i].thread != NULL && peers[i].tid == tid) return &peers[i];
    return NULL;
}

static HANDLE WINAPI t_snapshot(DWORD flags, DWORD pid)
{
    HANDLE h = CreateToolhelp32Snapshot(flags, pid);
    if (h != INVALID_HANDLE_VALUE) track(h);
    return h;
}

/* Advance past threads of this process the test did not create. */
static BOOL filtered_walk(HANDLE snap, THREADENTRY32 *te, BOOL ok)
{
    const DWORD pid = GetCurrentProcessId();
    while (ok && te->dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD) &&
           te->th32OwnerProcessID == pid && te->th32ThreadID != main_tid &&
           peer_by_tid(te->th32ThreadID) == NULL) {
        te->dwSize = sizeof(*te);
        ok = Thread32Next(snap, te);
    }
    if (ok && fault == EXIT_BEFORE_OPEN && te->th32ThreadID == fault_tid) {
        /* The thread really exits, and its last handle is closed, after the
         * snapshot recorded it and before the backend opens it. */
        stop_peer(peer_by_tid(fault_tid));
        SetLastError(ERROR_SUCCESS);
    }
    if (ok && fault == EXIT_BEFORE_OPEN_HELD && te->th32ThreadID == fault_tid) {
        /* The thread really exits after the snapshot, but the test still
         * holds a handle, so the thread object and its TID survive and the
         * backend's OpenThread succeeds on a terminated thread. */
        end_peer_thread(peer_by_tid(fault_tid));
        SetLastError(ERROR_SUCCESS);
    }
    return ok;
}

static BOOL WINAPI t_thread_first(HANDLE snap, THREADENTRY32 *te)
{
    if (fault == FAULT_FIRST) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    return filtered_walk(snap, te, Thread32First(snap, te));
}

static BOOL WINAPI t_thread_next(HANDLE snap, THREADENTRY32 *te)
{
    if (fault == FAULT_NEXT_AFTER_SUSPEND && backend_suspends > 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return filtered_walk(snap, te, Thread32Next(snap, te));
}

static HANDLE WINAPI t_open_thread(DWORD access, BOOL inherit, DWORD tid)
{
    if (fault == FAULT_OPEN && tid == fault_tid) {
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    HANDLE h = OpenThread(access, inherit, tid);
    if (h != NULL) track(h);
    return h;
}

static DWORD WINAPI t_suspend_thread(HANDLE h)
{
    if (fault == EXIT_BEFORE_SUSPEND && GetThreadId(h) == fault_tid) {
        /* The backend's handle keeps the thread object alive; the thread
         * itself has really terminated before SuspendThread. */
        stop_peer(peer_by_tid(fault_tid));
    }
    DWORD previous = SuspendThread(h);
    if (previous != (DWORD)-1) backend_suspends++;
    return previous;
}

static BOOL WINAPI t_close_handle(HANDLE h)
{
    untrack(h);
    return CloseHandle(h);
}

#define CT_FROZEN_MAX 2
#define CreateToolhelp32Snapshot t_snapshot
#define Thread32First t_thread_first
#define Thread32Next t_thread_next
#define OpenThread t_open_thread
#define SuspendThread t_suspend_thread
#define CloseHandle t_close_handle
#include "../../src/stackable_hooks/inline_hook/windows/install_windows.c"
#undef CreateToolhelp32Snapshot
#undef Thread32First
#undef Thread32Next
#undef OpenThread
#undef SuspendThread
#undef CloseHandle

typedef int (*value_fn)(void);
static uint8_t *code_page;
static uint8_t *target, *replacement;
static uint8_t original[8];
static int failures;

static void emit_return(uint8_t *at, int value)
{
    uint32_t immediate = (uint32_t)value;
    at[0] = 0xb8;  /* mov eax, imm32 -- a five-byte overwritable prologue */
    memcpy(at + 1, &immediate, sizeof(immediate));
    at[5] = 0xc3;  /* ret */
}

static void arm(int kind, DWORD tid)
{
    fault = kind;
    fault_tid = tid;
    backend_suspends = 0;
}

static void report(const char *name, const char *problem)
{
    if (problem) { failures++; printf("FAIL %s: %s\n", name, problem); }
    else printf("PASS %s\n", name);
    fflush(stdout);
}

/* After a call: no backend handle outstanding, every live peer resumed
 * (suspend count back to zero) and running. */
static const char *aftermath(void)
{
    if (tracked_count != 0) return "handles acquired by the freeze were not closed";
    for (int i = 0; i < PEER_MAX; i++) {
        if (peers[i].thread == NULL || peers[i].ended) continue;
        DWORD previous = SuspendThread(peers[i].thread);
        ResumeThread(peers[i].thread);
        if (previous != 0) return "a peer thread was left suspended";
        if (!peer_responds(&peers[i])) return "a peer thread does not run";
    }
    return NULL;
}

static const char *expect_refused(int rc, const uint8_t *expected_bytes)
{
    if (rc != -4) return rc == 0 ? "reported success without freezing every live thread"
                                 : "returned an error other than -4";
    if (memcmp(target, expected_bytes, sizeof(original)) != 0)
        return "patch bytes changed although the freeze failed";
    return aftermath();
}

static int start_peers(int count)
{
    for (int i = 0; i < count; i++)
        if (!start_peer(&peers[i])) return 0;
    for (int i = 0; i < count; i++)
        if (!peer_responds(&peers[i])) return 0;
    return 1;
}

static void stop_peers(void)
{
    for (int i = 0; i < PEER_MAX; i++) stop_peer(&peers[i]);
}

/* Restore the target after a test that wrongly patched it, so one failure
 * does not cascade into the next scenario. Setup and reset use the
 * no-suspend variants: the peers never execute the target, and the
 * capacity scenario would refuse a freezing call. */
static void reset_target(void)
{
    arm(FAULT_NONE, 0);
    if (find_hook(target) != NULL) ct_inline_hook_uninstall_no_suspend(target);
}

static void each_caller_refuses(const char *scenario, int kind)
{
    char name[128];
    const char *problem;
    void *trampoline = NULL;

    snprintf(name, sizeof(name), "%s: ct_inline_hook_install", scenario);
    arm(kind, 0);
    problem = expect_refused(ct_inline_hook_install(target, replacement, &trampoline), original);
    report(name, problem); reset_target();

    /* ct_inline_hook_install_noreturn shares this freeze and its -4 path,
     * but it is not exercised here: at nim-stackable-hooks 88913f2 it
     * returns -4 on every call, frozen or not, because its entry stub is
     * 40 bytes against CT_NORETURN_STUB_BYTES 30 (reprobuild-pm issue
     * 2026-10-20-windows-noreturn-inline-hook-install-always-fails.md).
     * A -4 from it would pass this check without testing the freeze. */

    snprintf(name, sizeof(name), "%s: ct_inline_hook_commit_transaction", scenario);
    problem = NULL;
    arm(FAULT_NONE, 0);
    if (ct_inline_hook_begin_transaction() != 0 ||
        ct_inline_hook_install(target, replacement, &trampoline) != 0)
        problem = "could not queue the install";
    if (!problem) {
        arm(kind, 0);
        problem = expect_refused(ct_inline_hook_commit_transaction(), original);
    }
    if (!problem && ct_inline_hook_abort_transaction() == 0)
        problem = "the failed commit left its transaction active";
    report(name, problem); reset_target();

    snprintf(name, sizeof(name), "%s: ct_inline_hook_uninstall", scenario);
    problem = NULL;
    arm(FAULT_NONE, 0);
    uint8_t hooked[sizeof(original)];
    if (ct_inline_hook_install_no_suspend(target, replacement, &trampoline) != 0)
        problem = "could not install the hook to uninstall";
    if (!problem) {
        memcpy(hooked, target, sizeof(hooked));
        arm(kind, 0);
        problem = expect_refused(ct_inline_hook_uninstall(target), hooked);
    }
    if (!problem && ((value_fn)target)() != 1000)
        problem = "the hook stopped working after the refused uninstall";
    report(name, problem); reset_target();
}

/* peers[2] really exits during the freeze. `live` peers (1 or 2) stay up.
 * With two live peers CT_FROZEN_MAX is reached by them, so the exited one
 * must not count against capacity; EXIT_BEFORE_OPEN_HELD is the variant in
 * which the backend can still open the terminated thread and has to see
 * that it exited. With one, a slot is free, so the freeze reaches
 * SuspendThread for the exiting peer. */
static void install_succeeds_with_exit(const char *name, int kind, int live)
{
    const char *problem = NULL;
    void *trampoline = NULL;
    if (!start_peers(3)) { report(name, "could not start peers"); stop_peers(); return; }
    if (live == 1) stop_peer(&peers[1]);
    arm(kind, peers[2].tid);
    int rc = ct_inline_hook_install(target, replacement, &trampoline);
    arm(FAULT_NONE, 0);
    if (peers[2].thread != NULL && !peers[2].ended)
        problem = "the exiting peer was never reached";
    else if (rc != 0) problem = "a confirmed thread exit failed the freeze";
    else if (((value_fn)target)() != 1000 || ((value_fn)trampoline)() != 7)
        problem = "the hook or its trampoline does not work";
    else if ((problem = aftermath()) == NULL && ct_inline_hook_uninstall(target) != 0)
        problem = "could not uninstall";
    else if (!problem && memcmp(target, original, sizeof(original)) != 0)
        problem = "uninstall did not restore the target";
    report(name, problem);
    reset_target();
    stop_peers();
}

int ct_test_windows_hook_freeze(void)
{
    main_tid = GetCurrentThreadId();
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    code_page = (uint8_t *)VirtualAlloc(NULL, info.dwPageSize, MEM_RESERVE | MEM_COMMIT,
                                        PAGE_READWRITE);
    if (code_page == NULL) return 10;
    memset(code_page, 0xcc, info.dwPageSize);
    target = code_page + 64;
    replacement = code_page + 128;
    emit_return(target, 7);
    emit_return(replacement, 1000);
    memcpy(original, target, sizeof(original));
    DWORD old;
    if (!VirtualProtect(code_page, info.dwPageSize, PAGE_EXECUTE_READ, &old) ||
        !FlushInstructionCache(GetCurrentProcess(), code_page, info.dwPageSize))
        return 11;

    if (CT_FROZEN_MAX != 2)
        report("capacity override", "install_windows.c ignores the test's CT_FROZEN_MAX");

    /* Controls: with nothing injected every caller succeeds. */
    if (!start_peers(2)) return 12;
    {
        void *trampoline = NULL;
        arm(FAULT_NONE, 0);
        int rc = ct_inline_hook_install(target, replacement, &trampoline);
        const int install_suspends = backend_suspends;
        const char *problem = rc != 0 ? "install failed without any fault" :
            ((value_fn)target)() != 1000 ? "hook does not work" : aftermath();
        if (!problem && (ct_inline_hook_uninstall(target) != 0 ||
                         memcmp(target, original, sizeof(original)) != 0))
            problem = "uninstall did not restore the target";
        if (!problem && install_suspends != 2) problem = "the control did not suspend both peers";
        report("control: two live peers freeze and thaw", problem);
        reset_target();
    }

    each_caller_refuses("Thread32First fails", FAULT_FIRST);
    each_caller_refuses("Thread32Next fails after a suspension", FAULT_NEXT_AFTER_SUSPEND);

    /* OpenThread denied for each peer in turn, so one run has the other
     * peer already suspended when the denial comes. */
    int resumed_after_partial = 0;
    for (int i = 0; i < 2; i++) {
        void *trampoline = NULL;
        arm(FAULT_OPEN, peers[i].tid);
        int rc = ct_inline_hook_install(target, replacement, &trampoline);
        if (backend_suspends > 0) resumed_after_partial = 1;
        report(i == 0 ? "OpenThread denied for a live peer (first)"
                      : "OpenThread denied for a live peer (second)",
               expect_refused(rc, original));
        reset_target();
    }
    report("OpenThread denied after another peer was suspended",
           resumed_after_partial ? NULL : "no run suspended a peer before the denial");

    /* SuspendThread really refused: the peer is at MAXIMUM_SUSPEND_COUNT. */
    for (int i = 0; i < 2; i++) {
        void *trampoline = NULL;
        int held = 0;
        while (held < 200 && SuspendThread(peers[i].thread) != (DWORD)-1) held++;
        arm(FAULT_NONE, 0);
        int rc = ct_inline_hook_install(target, replacement, &trampoline);
        int code_unchanged = memcmp(target, original, sizeof(original)) == 0;
        reset_target();
        for (int k = 0; k < held; k++) ResumeThread(peers[i].thread);
        const char *problem = held == 200 ? "the kernel never refused SuspendThread" :
            rc != -4 ? (rc == 0 ? "reported success with a live peer not suspended"
                                : "returned an error other than -4") :
            !code_unchanged ? "patch bytes changed although the freeze failed" : aftermath();
        report(i == 0 ? "SuspendThread refused for a live peer (first)"
                      : "SuspendThread refused for a live peer (second)", problem);
    }
    stop_peers();

    /* More live peers than CT_FROZEN_MAX. */
    if (!start_peers(3)) return 13;
    each_caller_refuses("more live peers than CT_FROZEN_MAX", FAULT_NONE);
    stop_peers();

    /* Confirmed exits are not failures, even with CT_FROZEN_MAX peers
     * already suspended. */
    install_succeeds_with_exit("peer exits between snapshot and OpenThread, two live peers",
                               EXIT_BEFORE_OPEN, 2);
    install_succeeds_with_exit("peer exits between snapshot and OpenThread, handle held, "
                               "two live peers",
                               EXIT_BEFORE_OPEN_HELD, 2);
    install_succeeds_with_exit("peer exits between snapshot and OpenThread, one live peer",
                               EXIT_BEFORE_OPEN, 1);
    install_succeeds_with_exit("peer exits between OpenThread and SuspendThread",
                               EXIT_BEFORE_SUSPEND, 1);

    VirtualFree(code_page, 0, MEM_RELEASE);
    if (failures != 0) {
        printf("%d freeze check(s) failed\n", failures);
        return 1;
    }
    puts("all freeze checks passed");
    return 0;
}
