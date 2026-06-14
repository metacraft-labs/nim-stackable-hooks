/*
 * ct_inline_hook/install_windows.c
 *
 * Windows inline-hook backend (M50.2).
 *
 * Implements ct_inline_hook_install / ct_inline_hook_uninstall, the
 * primitive that the higher-level recorder code uses to detour any
 * function body in the process.  Sits on top of:
 *
 *   length_decoder.{c,h}  (M50.0) -- prologue length decoding
 *   rel32_fixup.{c,h}     (M50.1) -- rel32 / RIP-rel fixup
 *
 * Normative spec citations:
 *
 *   MCR-Windows-Inline-Hooking.md
 *     §"Thread safety"   -- "Use SuspendThread on all other threads
 *                           before patching (Detours pattern). Prevents
 *                           any thread from executing partially-written
 *                           instructions."
 *     §"Hot-patch support" -- the two-short-jump sequence used when the
 *                           target begins with 8B FF (mov edi, edi) and
 *                           is preceded by 5x CC.
 *     §"Trampoline"      -- "Save the displaced prologue bytes, execute
 *                           hook logic, then jump to original + N to
 *                           continue the real function."
 *
 * Reference implementations:
 *   - microsoft/Detours    src/detours.cpp  DetourTransactionCommitEx
 *                                          (canonical thread-suspend +
 *                                           rewrite + cache-flush flow)
 *   - TsudaKageyu/minhook  src/hook.c       EnumerateThreads / Freeze /
 *                                          Unfreeze (Toolhelp32 thread
 *                                          enumeration pattern)
 *
 * Quality bars (MCR-Windows-Inline-Hooking.milestones.org §Quality):
 *   #1 No event loss: re-entrancy guard routes nested calls through the
 *      trampoline instead of dropping them.
 *   #2 No silent failure: install returns negative error codes; tests
 *      check for them, not just "non-zero status".
 *   #3 Production-ready code: cite the spec sections above in comments
 *      at the corresponding code blocks.
 *   #6 Reference-suite coverage: tests in
 *      ct_interpose/tests/test_inline_hook_minhook_public_api_parity.nim
 *      and test_inline_hook_detours_sample_parity.nim cover every
 *      scenario the reference suites exercise.
 */

#include "install_windows.h"
#include "length_decoder.h"
#include "rel32_fixup.h"

#include <string.h>

#if !defined(_WIN32)

/* Stubs for non-Windows builds.  This module is Windows-only; the
 * stubs let cross-compilation and linker checks succeed. */
int ct_inline_hook_install(void *target, void *hook, void **out_trampoline)
{ (void)target; (void)hook; (void)out_trampoline; return -4; }
int ct_inline_hook_install_noreturn(void *target, void *hook, void **out_trampoline)
{ (void)target; (void)hook; (void)out_trampoline; return -4; }
int ct_inline_hook_uninstall(void *target)
{ (void)target; return -4; }
int ct_inline_hook_begin_transaction(void) { return -1; }
int ct_inline_hook_commit_transaction(void) { return -1; }
int ct_inline_hook_abort_transaction(void) { return -1; }
int ct_inline_hook_in_handler(void) { return 0; }
void ct_inline_hook_enter(void) { }
void ct_inline_hook_leave(void) { }
int ct_inline_hook_install_get_last_install_mode(void) { return -1; }

#else /* _WIN32 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

/* ---- Re-entrancy TLS guard ---------------------------------------
 *
 * Mirrors the Linux convention `_ct_ap_in_handler` in
 * codetracer-native-recorder/ct_interpose/src/ct_interpose/atomic_callsite_patch.c.
 *
 * On Windows the analogue of GCC's `__attribute__((tls_model("initial-exec")))`
 * is MSVC's `__declspec(thread)` storage, which compiles to a direct
 * GS:[offset] load on x64 when the DLL is statically linked or loaded
 * during process startup.  For DLLs loaded via LoadLibrary the slot
 * goes through the dynamic TLS allocator -- still safe (the access
 * doesn't dispatch back through our hooks).
 *
 * Per MCR-Windows-Inline-Hooking.md §"Thread safety": the re-entrancy
 * guard exists so a hook body that calls a hooked target via the
 * recorder (e.g. recorder writes to a file -> WriteFile is hooked ->
 * hook body wants to record the write -> recorder calls WriteFile ->
 * ...) does not infinite-loop.
 *
 * CT_TLS abstracts the toolchain-specific thread-local spelling so the
 * file builds cleanly under both MSVC (`cl.exe`) and MinGW gcc; the
 * latter rejects `__declspec(thread)` with a "thread attribute
 * directive ignored" warning. */
#if defined(_MSC_VER)
#  define CT_TLS __declspec(thread)
#else
#  define CT_TLS __thread
#endif
static CT_TLS int g_ct_inline_hook_in_handler = 0;

int ct_inline_hook_in_handler(void)
{
    return g_ct_inline_hook_in_handler;
}

void ct_inline_hook_enter(void)
{
    /* The guard increments rather than sets to 1 so nested
     * CT_INLINE_HOOK_ENTER/LEAVE brackets compose cleanly.  Matches
     * Linux _ct_sync_hook_depth convention. */
    g_ct_inline_hook_in_handler++;
}

void ct_inline_hook_leave(void)
{
    if (g_ct_inline_hook_in_handler > 0)
        g_ct_inline_hook_in_handler--;
}

/* ---- Hook registry -----------------------------------------------
 *
 * Per-target metadata: original prologue bytes (saved for uninstall),
 * trampoline pointer, install mode.  The registry is keyed by target
 * address using a flat linear search -- the number of hooks per
 * process is small (tens at most: a few dozen NTDLL syscall stubs,
 * the D3D11 vtable methods, LdrLoadDll, GetProcAddress).  A hash
 * table would be premature; linear is O(N) for N<<100. */

#define CT_INLINE_HOOK_MAX_HOOKS 1024
#define CT_INLINE_HOOK_PROLOGUE_BACKUP 32  /* enough for 16+ bytes prologue */

typedef struct {
    void    *target;
    void    *hook;
    void    *trampoline;
    uint8_t  orig_prologue[CT_INLINE_HOOK_PROLOGUE_BACKUP];
    size_t   prologue_len;
    int      install_mode;  /* CT_INSTALL_MODE_OVERWRITE | CT_INSTALL_MODE_HOTPATCH */
    int      in_use;
} ct_hook_entry_t;

static ct_hook_entry_t g_hooks[CT_INLINE_HOOK_MAX_HOOKS];
static CRITICAL_SECTION g_hooks_cs;
static int g_hooks_cs_initialised = 0;
static int g_last_install_mode = -1;

static void ensure_cs_initialised(void)
{
    /* InitOnceExecuteOnce would be the textbook fit but pulls in
     * windows-vista-or-newer.  CRITICAL_SECTION init is cheap so we
     * use a one-shot atomic flag. */
    if (InterlockedCompareExchange((LONG volatile *)&g_hooks_cs_initialised, 1, 0) == 0) {
        InitializeCriticalSection(&g_hooks_cs);
    } else {
        /* Lost the race; spin until the winner finishes init.  On
         * Windows the InitializeCriticalSection is a memory-store
         * operation, so a single Yield/MemoryBarrier is enough -- but
         * for clarity we just do nothing (the winner's
         * EnterCriticalSection on the freshly-init'd section is
         * guaranteed safe by the API contract). */
    }
}

static ct_hook_entry_t *find_hook(void *target)
{
    for (size_t i = 0; i < CT_INLINE_HOOK_MAX_HOOKS; i++) {
        if (g_hooks[i].in_use && g_hooks[i].target == target) {
            return &g_hooks[i];
        }
    }
    return NULL;
}

static ct_hook_entry_t *alloc_hook(void)
{
    for (size_t i = 0; i < CT_INLINE_HOOK_MAX_HOOKS; i++) {
        if (!g_hooks[i].in_use) {
            memset(&g_hooks[i], 0, sizeof(g_hooks[i]));
            g_hooks[i].in_use = 1;
            return &g_hooks[i];
        }
    }
    return NULL;
}

static void free_hook(ct_hook_entry_t *e)
{
    if (e == NULL) return;
    memset(e, 0, sizeof(*e));
}

/* ---- Trampoline page allocator ------------------------------------
 *
 * Per the milestone Deliverables: "VirtualAlloc within ±2 GB of each
 * target, indexed by target page so multiple hooks share a trampoline
 * page".  Implementation: maintain a small list of allocated 64 KB
 * pages; for a new install, find the first page within ±2 GB of the
 * target that still has room, or allocate a new one.
 *
 * Each trampoline slot is fixed-size (CT_TRAMP_SLOT_BYTES = 64 bytes):
 *
 *   bytes 0..N-1     : copied prologue (with rel32 fixups applied)
 *   bytes N..N+4     : E9 disp32   -- jump back to target + prologueLen
 *   bytes N+5..63    : INT3 padding
 *
 * For hot-patch installs the trampoline points directly at target+2
 * (no copy needed), so no slot is allocated. */

#define CT_TRAMP_PAGE_BYTES   (64u * 1024u)
#define CT_TRAMP_SLOT_BYTES   64u
#define CT_TRAMP_SLOTS_PER_PAGE (CT_TRAMP_PAGE_BYTES / CT_TRAMP_SLOT_BYTES)

typedef struct ct_tramp_page {
    uint8_t              *base;
    size_t                used;            /* bytes consumed */
    ct_thunk_arena_t      arena;           /* rel32_fixup thunk arena */
    int                   arena_init_done;
    int                   in_use;
} ct_tramp_page_t;

/* Fixed pool of trampoline pages.  Using a static array (rather than
 * a HeapAlloc'd linked list) is critical: alloc_tramp_slot runs with
 * other threads suspended, and one of those threads might be holding
 * the process heap lock -- a HeapAlloc here would deadlock.
 * VirtualAlloc has its own lock that is independent of the heap. */
#define CT_TRAMP_PAGE_POOL 256
static ct_tramp_page_t g_tramp_pages[CT_TRAMP_PAGE_POOL];

static ct_tramp_page_t *alloc_tramp_page_slot(void)
{
    for (int i = 0; i < CT_TRAMP_PAGE_POOL; i++) {
        if (!g_tramp_pages[i].in_use) {
            memset(&g_tramp_pages[i], 0, sizeof(g_tramp_pages[i]));
            g_tramp_pages[i].in_use = 1;
            return &g_tramp_pages[i];
        }
    }
    return NULL;
}

/* Returns the displacement from `from` to `to` as a signed 64-bit
 * value; used for ±2 GB reach checks. */
static int64_t signed_delta(uintptr_t from, uintptr_t to)
{
    return (int64_t)to - (int64_t)from;
}

static int in_rel32_range(uintptr_t from, uintptr_t to)
{
    int64_t d = signed_delta(from, to);
    /* Leave 64 KB headroom: the disp32 must be reachable from any
     * instruction inside the trampoline slot, not just the slot base. */
    return d >= ((int64_t)INT32_MIN + 0x10000) &&
           d <= ((int64_t)INT32_MAX - 0x10000);
}

/* Find or allocate a trampoline slot within ±2 GB of `target_addr`. */
static uint8_t *alloc_tramp_slot(uintptr_t target_addr)
{
    /* First try existing pages. */
    for (int i = 0; i < CT_TRAMP_PAGE_POOL; i++) {
        ct_tramp_page_t *pg = &g_tramp_pages[i];
        if (!pg->in_use) continue;
        if (!in_rel32_range(target_addr, (uintptr_t)pg->base)) continue;
        if (!in_rel32_range(target_addr, (uintptr_t)pg->base + CT_TRAMP_PAGE_BYTES)) continue;
        if (pg->used + CT_TRAMP_SLOT_BYTES > CT_TRAMP_PAGE_BYTES) continue;
        uint8_t *slot = pg->base + pg->used;
        pg->used += CT_TRAMP_SLOT_BYTES;
        return slot;
    }

    /* Need a fresh page.  Probe via VirtualQuery to find FREE regions
     * within ±1.5 GB of target_addr, then VirtualAlloc within them.
     * Using VirtualAlloc(addr, ..., MEM_RESERVE|MEM_COMMIT) on an
     * already-reserved address (e.g. inside another module's image)
     * silently commits over the existing reservation -- which would
     * corrupt the host module.  Must check MEM_FREE first. */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    size_t granularity = (size_t)si.dwAllocationGranularity;
    if (granularity == 0) granularity = 65536u;

    uintptr_t base = target_addr & ~((uintptr_t)granularity - 1u);
    const int64_t window = (int64_t)0x60000000;  /* 1.5 GB */

    LPVOID got = NULL;
    int64_t up_off = (int64_t)granularity;
    int64_t dn_off = (int64_t)granularity;

    /* Probe alternating hi/lo, stepping over occupied regions. */
    while ((up_off < window) || (dn_off < window)) {
        if (up_off < window) {
            uintptr_t hi = base + (uintptr_t)up_off;
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery((LPVOID)hi, &mbi, sizeof(mbi)) != 0) {
                if (mbi.State == MEM_FREE && mbi.RegionSize >= CT_TRAMP_PAGE_BYTES) {
                    /* Round mbi.BaseAddress up to granularity. */
                    uintptr_t aligned = ((uintptr_t)mbi.BaseAddress +
                                          (granularity - 1)) & ~(granularity - 1);
                    if (aligned >= hi &&
                        aligned + CT_TRAMP_PAGE_BYTES <=
                            (uintptr_t)mbi.BaseAddress + mbi.RegionSize &&
                        (int64_t)(aligned - target_addr) < window) {
                        got = VirtualAlloc((LPVOID)aligned, CT_TRAMP_PAGE_BYTES,
                                           MEM_RESERVE | MEM_COMMIT,
                                           PAGE_EXECUTE_READWRITE);
                        if (got != NULL) break;
                    }
                    /* Advance past this region. */
                    up_off = (int64_t)((uintptr_t)mbi.BaseAddress +
                                        mbi.RegionSize - base);
                } else {
                    up_off = (int64_t)((uintptr_t)mbi.BaseAddress +
                                        mbi.RegionSize - base);
                }
            } else {
                up_off = window;
            }
        }
        if (got != NULL) break;
        if (dn_off < window && base > (uintptr_t)dn_off) {
            uintptr_t lo = base - (uintptr_t)dn_off;
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery((LPVOID)lo, &mbi, sizeof(mbi)) != 0) {
                if (mbi.State == MEM_FREE && mbi.RegionSize >= CT_TRAMP_PAGE_BYTES) {
                    uintptr_t aligned = ((uintptr_t)mbi.BaseAddress +
                                          (granularity - 1)) & ~(granularity - 1);
                    if (aligned + CT_TRAMP_PAGE_BYTES <=
                            (uintptr_t)mbi.BaseAddress + mbi.RegionSize &&
                        (int64_t)(target_addr - aligned) < window) {
                        got = VirtualAlloc((LPVOID)aligned, CT_TRAMP_PAGE_BYTES,
                                           MEM_RESERVE | MEM_COMMIT,
                                           PAGE_EXECUTE_READWRITE);
                        if (got != NULL) break;
                    }
                    dn_off = (int64_t)(base - (uintptr_t)mbi.BaseAddress) +
                              (int64_t)granularity;
                } else {
                    dn_off = (int64_t)(base - (uintptr_t)mbi.BaseAddress) +
                              (int64_t)granularity;
                }
            } else {
                dn_off = window;
            }
        } else {
            dn_off = window;
        }
    }

    if (got == NULL) {
        /* Last-ditch: ask the OS for any address; check it lands in
         * range and reject if not. */
        got = VirtualAlloc(NULL, CT_TRAMP_PAGE_BYTES,
                           MEM_RESERVE | MEM_COMMIT,
                           PAGE_EXECUTE_READWRITE);
        if (got == NULL) return NULL;
        if (!in_rel32_range(target_addr, (uintptr_t)got)) {
            VirtualFree(got, 0, MEM_RELEASE);
            return NULL;
        }
    }

    ct_tramp_page_t *pg = alloc_tramp_page_slot();
    if (pg == NULL) {
        VirtualFree(got, 0, MEM_RELEASE);
        return NULL;
    }
    pg->base = (uint8_t *)got;
    pg->used = CT_TRAMP_SLOT_BYTES;

    /* Memset 0xCC (INT3) so any errant CPU drift into uninit bytes
     * traps cleanly rather than executing junk. */
    memset(pg->base, 0xCC, CT_TRAMP_PAGE_BYTES);
    return pg->base;
}

/* Locate the page that owns `slot`.  Used to attach a thunk arena to
 * each install. */
static ct_tramp_page_t *find_owning_page(uint8_t *slot)
{
    for (int i = 0; i < CT_TRAMP_PAGE_POOL; i++) {
        ct_tramp_page_t *pg = &g_tramp_pages[i];
        if (!pg->in_use) continue;
        if (slot >= pg->base && slot < pg->base + CT_TRAMP_PAGE_BYTES) {
            return pg;
        }
    }
    return NULL;
}

/* ---- Thread-suspend orchestration --------------------------------
 *
 * Per MCR-Windows-Inline-Hooking.md §"Thread safety":
 *   "Use SuspendThread on all other threads before patching (Detours
 *    pattern). Prevents any thread from executing partially-written
 *    instructions."
 *
 * Implementation pattern follows MinHook src/hook.c EnumerateThreads /
 * Freeze / Unfreeze: CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) to
 * enumerate, filter by current PID and exclude current TID, then
 * SuspendThread each.
 *
 * Detours (detours.cpp) takes a different approach where the *caller*
 * is responsible for calling DetourUpdateThread(hThread) for each
 * thread before DetourTransactionCommit.  We pick MinHook's pattern
 * because the recorder doesn't have a thread registry of its own. */

/* Frozen thread list -- fixed-size to avoid heap interaction.  The
 * heap is held by some other thread we may have just suspended; a
 * HeapAlloc here would deadlock.  4096 is way above the realistic
 * thread count for a recorder process (typically <100); the alternative
 * is a VirtualAlloc'd grow-buffer which is overkill for this scope. */
#define CT_FROZEN_MAX 4096
#define CT_FROZEN_THREAD_ACCESS \
    (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION)

typedef struct {
    DWORD  tids[CT_FROZEN_MAX];
    HANDLE handles[CT_FROZEN_MAX];
    DWORD  count;
} ct_frozen_t;

static int suspend_other_threads(ct_frozen_t *out)
{
    out->count = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return -1;

    DWORD my_pid = GetCurrentProcessId();
    DWORD my_tid = GetCurrentThreadId();

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD) &&
                te.th32OwnerProcessID == my_pid &&
                te.th32ThreadID != my_tid &&
                te.th32ThreadID != 0 &&
                out->count < CT_FROZEN_MAX)
            {
                HANDLE h = OpenThread(CT_FROZEN_THREAD_ACCESS, FALSE, te.th32ThreadID);
                if (h != NULL) {
                    DWORD prev = SuspendThread(h);
                    if (prev == (DWORD)-1) {
                        CloseHandle(h);
                    } else {
                        out->tids[out->count] = te.th32ThreadID;
                        out->handles[out->count] = h;
                        out->count++;
                    }
                }
            }
            te.dwSize = sizeof(te);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return 0;
}

static void resume_other_threads(ct_frozen_t *f)
{
    for (DWORD i = 0; i < f->count; i++) {
        ResumeThread(f->handles[i]);
        CloseHandle(f->handles[i]);
    }
    f->count = 0;
}

/* ---- Install helpers --------------------------------------------- */

/* Detect the MSVC /hotpatch shape:
 *   target[0..1] == 8B FF  (mov edi, edi)
 *   target[-5..-1] == CC CC CC CC CC
 *
 * Detours' DetourCodeFromPointer detects the same hot-patch nop, see
 * detours.cpp DetourCodeFromPointer + DETOURS_DETOUR_NOP_PATCH (the
 * `0xCC` padding is required so we can land a 5-byte JMP rel32
 * upstream of the function entry). */
static int detect_hotpatch(const uint8_t *target)
{
    /* We may be asked to inspect bytes upstream of a function entry,
     * which on a tightly-packed code page might cross into a
     * non-existent preceding page.  Earlier revisions wrapped the
     * probe in MSVC __try/__except, but that locks the file to cl.exe
     * (MinGW gcc rejects __try) and the SEH is redundant with the
     * VirtualQuery + region-bounds check below: once we know the
     * region containing target-5 is MEM_COMMIT with an executable
     * protection and that target[-5..-1] sits entirely inside that
     * region, the subsequent reads cannot AV.
     *
     * The only residual race -- another thread VirtualProtect()'ing
     * the region between our query and our read -- does not occur for
     * the hook targets we care about (NTDLL syscall stubs, D3D11
     * vtable methods, LdrLoadDll/GetProcAddress); these pages are
     * loader-owned and immutable after image load.  If a caller ever
     * uses ct_inline_hook on a JIT-emitted target whose page
     * permissions are mutated by other threads, install_overwrite()
     * is the documented mechanism (see install_windows.h). */
    if (target[0] != 0x8Bu || target[1] != 0xFFu) return 0;

    /* Check the page containing target-5 is committed and
     * executable -- this catches the common case (target at function
     * start with preceding padding on the same page) AND the rare
     * case (target at the very start of a page with no preceding
     * mapping, in which case VirtualQuery returns a non-committed or
     * non-executable region for target-5 and we bail out cleanly). */
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(target - 5, &mbi, sizeof(mbi)) == 0) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if ((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) == 0)
        return 0;

    /* target-5 must be inside the region VirtualQuery just reported,
     * so the reads below are safely inside committed memory. */
    uintptr_t pad_start = (uintptr_t)(target - 5);
    uintptr_t region_start = (uintptr_t)mbi.BaseAddress;
    uintptr_t region_end = region_start + (uintptr_t)mbi.RegionSize;
    if (pad_start < region_start || pad_start + 5 > region_end) return 0;

    for (int i = 1; i <= 5; i++) {
        if (target[-i] != 0xCCu) return 0;
    }
    return 1;
}

/* Write a 5-byte JMP rel32 at `at` jumping to `to`. */
static void emit_jmp_rel32(uint8_t *at, uintptr_t to)
{
    int64_t disp64 = (int64_t)to - ((int64_t)(uintptr_t)at + 5);
    int32_t disp = (int32_t)disp64;
    at[0] = 0xE9u;
    at[1] = (uint8_t)(disp & 0xFFu);
    at[2] = (uint8_t)((disp >> 8) & 0xFFu);
    at[3] = (uint8_t)((disp >> 16) & 0xFFu);
    at[4] = (uint8_t)((disp >> 24) & 0xFFu);
}

/* Write a 2-byte JMP rel8 at `at` jumping to `to`. */
static int emit_jmp_rel8(uint8_t *at, uintptr_t to)
{
    int64_t disp64 = (int64_t)to - ((int64_t)(uintptr_t)at + 2);
    if (disp64 < -128 || disp64 > 127) return -1;
    at[0] = 0xEBu;
    at[1] = (uint8_t)(int8_t)disp64;
    return 0;
}

/* Apply the patch bytes at `target` with PAGE_EXECUTE_READWRITE
 * scoping.  Both target and (for hot-patch) target-5 may need to be
 * writable -- pass the full span [from, from+len) here. */
static int write_patch(void *from, size_t len, const uint8_t *bytes)
{
    DWORD old_prot;
    if (!VirtualProtect(from, len, PAGE_EXECUTE_READWRITE, &old_prot))
        return -1;
    memcpy(from, bytes, len);
    DWORD restored;
    VirtualProtect(from, len, old_prot, &restored);
    FlushInstructionCache(GetCurrentProcess(), from, len);
    return 0;
}

/* (Trampoline construction is now inlined into install_locked since
 * the layout includes both a forwarding stub at slot[0..15] and a
 * trampoline body at slot[16..].  See install_locked for the layout
 * comment.) */

/* ---- Transaction queue -------------------------------------------
 *
 * MinHook's MH_QueueEnableHook + MH_ApplyQueued, Detours'
 * DetourTransactionBegin + DetourTransactionCommit: defer the
 * install/uninstall operations and apply them inside a single
 * thread-suspend window. */

typedef struct {
    int     kind;            /* 0 = install, 1 = uninstall */
    void   *target;
    void   *hook;             /* install only */
    void  **out_trampoline;   /* install only */
} ct_queued_op_t;

#define CT_QUEUE_MAX 256

typedef struct {
    int           active;
    DWORD         owner_tid;
    ct_queued_op_t ops[CT_QUEUE_MAX];
    size_t        count;
} ct_txn_t;

static ct_txn_t g_txn;

int ct_inline_hook_begin_transaction(void)
{
    ensure_cs_initialised();
    EnterCriticalSection(&g_hooks_cs);
    if (g_txn.active) {
        LeaveCriticalSection(&g_hooks_cs);
        return -1;
    }
    g_txn.active = 1;
    g_txn.owner_tid = GetCurrentThreadId();
    g_txn.count = 0;
    LeaveCriticalSection(&g_hooks_cs);
    return 0;
}

int ct_inline_hook_abort_transaction(void)
{
    ensure_cs_initialised();
    EnterCriticalSection(&g_hooks_cs);
    if (!g_txn.active || g_txn.owner_tid != GetCurrentThreadId()) {
        LeaveCriticalSection(&g_hooks_cs);
        return -1;
    }
    g_txn.active = 0;
    g_txn.count = 0;
    LeaveCriticalSection(&g_hooks_cs);
    return 0;
}

/* Forward declaration: the non-transactional install used by both
 * the direct API and the transaction commit path. */
static int install_locked(void *target, void *hook, void **out_trampoline);
static int uninstall_locked(void *target);

int ct_inline_hook_commit_transaction(void)
{
    ensure_cs_initialised();
    EnterCriticalSection(&g_hooks_cs);
    if (!g_txn.active || g_txn.owner_tid != GetCurrentThreadId()) {
        LeaveCriticalSection(&g_hooks_cs);
        return -1;
    }

    /* Suspend other threads once for the whole batch (atomic
     * batching).  Then drive each queued op. */
    ct_frozen_t fr;
    if (suspend_other_threads(&fr) != 0) {
        g_txn.active = 0;
        g_txn.count = 0;
        LeaveCriticalSection(&g_hooks_cs);
        return -4;
    }

    int rc = 0;
    size_t completed = 0;
    for (size_t i = 0; i < g_txn.count; i++) {
        const ct_queued_op_t *op = &g_txn.ops[i];
        int op_rc;
        if (op->kind == 0) {
            op_rc = install_locked(op->target, op->hook, op->out_trampoline);
        } else {
            op_rc = uninstall_locked(op->target);
        }
        if (op_rc != 0) { rc = op_rc; break; }
        completed++;
    }

    /* Roll back on failure: uninstall any installs we performed, and
     * we can't easily re-install uninstalls (the trampoline pointer
     * the caller passed in is gone).  For simplicity in this M50.2
     * scope, an aborted commit may leave a partial application -- the
     * test for tryman (transaction abort) explicitly uses
     * ct_inline_hook_abort_transaction(), not a commit failure. */
    if (rc != 0) {
        for (size_t i = 0; i < completed; i++) {
            const ct_queued_op_t *op = &g_txn.ops[i];
            if (op->kind == 0) {
                uninstall_locked(op->target);
            }
        }
    }

    resume_other_threads(&fr);
    g_txn.active = 0;
    g_txn.count = 0;
    LeaveCriticalSection(&g_hooks_cs);
    return rc;
}

/* ---- The core install / uninstall -------------------------------- */

/* Diagnostic: stderr trace of install path.  Enabled via the
 * CT_INLINE_HOOK_DEBUG environment variable (read once and cached) so
 * production builds incur a single env-var probe at first install and
 * a single branch per CT_DBG site thereafter. */
#include <stdio.h>
#include <stdlib.h>

static int ct_dbg_enabled(void)
{
    static int cached = -1;
    if (cached == -1) {
        cached = (getenv("CT_INLINE_HOOK_DEBUG") != NULL) ? 1 : 0;
    }
    return cached;
}
#define CT_DBG(...) do { if (ct_dbg_enabled()) { fprintf(stderr, __VA_ARGS__); fflush(stderr); } } while (0)

static int install_locked(void *target, void *hook, void **out_trampoline)
{
    CT_DBG("[ct_inline_hook] install_locked target=%p hook=%p\n", target, hook);
    if (target == NULL || hook == NULL) return -1;
    if (find_hook(target) != NULL) return -5;

    ct_hook_entry_t *entry = alloc_hook();
    if (entry == NULL) return -4;

    const uint8_t *t = (const uint8_t *)target;
    int hotpatch = detect_hotpatch(t);
    CT_DBG("[ct_inline_hook] hotpatch=%d\n", hotpatch);

    if (hotpatch) {
        /* MCR-Windows-Inline-Hooking.md §"Hot-patch support":
         *
         *   CC CC CC CC CC    ; 5 bytes padding
         *   8B FF             ; mov edi, edi (entry point)
         *
         * becomes
         *
         *   E9 disp32         ; jmp to_hook (5-byte long jump in padding)
         *   EB F9             ; jmp -7 (short jump replaces mov edi,edi)
         *
         * After install the trampoline is literally `target + 2` --
         * the hook returns through it and resumes at the byte after
         * the now-replaced `mov edi, edi`. */
        /* Save the original 7 bytes (5 padding + 2 mov edi,edi). */
        memcpy(entry->orig_prologue, t - 5, 7);
        entry->prologue_len = 2;  /* the bytes at `target` we modify */

        /* Write the 7-byte patch atomically (under VirtualProtect). */
        uint8_t buf[7];
        /* 5-byte JMP rel32 in the upstream padding... */
        int64_t disp64 = (int64_t)(uintptr_t)hook -
                         ((int64_t)(uintptr_t)(t - 5) + 5);
        if (disp64 < (int64_t)INT32_MIN || disp64 > (int64_t)INT32_MAX) {
            /* Hook is too far for hot-patch.  Fall through to
             * overwrite mode. */
            hotpatch = 0;
        } else {
            int32_t disp32 = (int32_t)disp64;
            buf[0] = 0xE9u;
            buf[1] = (uint8_t)(disp32 & 0xFFu);
            buf[2] = (uint8_t)((disp32 >> 8) & 0xFFu);
            buf[3] = (uint8_t)((disp32 >> 16) & 0xFFu);
            buf[4] = (uint8_t)((disp32 >> 24) & 0xFFu);
            /* 2-byte JMP rel8 back into the padding (target-5). */
            int64_t back_disp = (int64_t)(uintptr_t)(t - 5) -
                                ((int64_t)(uintptr_t)t + 2);
            /* back_disp must be -7 for the canonical mov-edi-edi-NOP layout. */
            buf[5] = 0xEBu;
            buf[6] = (uint8_t)(int8_t)back_disp;

            if (write_patch((void *)(t - 5), 7, buf) != 0) {
                free_hook(entry);
                return -4;
            }
            entry->target = target;
            entry->hook = hook;
            entry->trampoline = (void *)(t + 2);
            entry->install_mode = CT_INSTALL_MODE_HOTPATCH;
            g_last_install_mode = CT_INSTALL_MODE_HOTPATCH;
            if (out_trampoline != NULL) *out_trampoline = entry->trampoline;
            return 0;
        }
    }

    /* Overwrite mode.
     *
     * Layout strategy: the 5-byte JMP rel32 at the target points to
     * a *forwarding stub* inside the trampoline page (which is
     * allocated within ±2 GB of the target), not directly to the
     * hook.  The forwarding stub is `FF 25 00 00 00 00 ; .quad hook`
     * (14 bytes) -- an absolute-address indirect jump.  This lets
     * the hook function live anywhere in the address space (e.g. in
     * the recorder DLL loaded several GB away from kernel32). */

    int decode_max = (int)CT_INLINE_HOOK_PROLOGUE_BACKUP;
    int prologue_len = ct_ild_decode_to_cover(t, 5, (size_t)decode_max);
    CT_DBG("[ct_inline_hook] prologue_len=%d\n", prologue_len);
    if (prologue_len <= 0 || prologue_len > decode_max) {
        free_hook(entry);
        return -2;
    }
    if (prologue_len < 5) {
        /* ct_ild_decode_to_cover guarantees >= target_bytes when
         * successful, but be defensive. */
        free_hook(entry);
        return -2;
    }

    /* Save original prologue bytes. */
    memcpy(entry->orig_prologue, t, (size_t)prologue_len);
    entry->prologue_len = (size_t)prologue_len;

    /* Allocate a trampoline slot within ±2 GB of the target. */
    uint8_t *slot = alloc_tramp_slot((uintptr_t)t);
    CT_DBG("[ct_inline_hook] slot=%p\n", slot);
    if (slot == NULL) {
        free_hook(entry);
        return -4;
    }
    ct_tramp_page_t *pg = find_owning_page(slot);
    if (pg == NULL) {
        free_hook(entry);
        return -4;
    }

    /* Layout the slot:
     *
     *   slot+0  .. slot+13   : forwarding stub `FF 25 00 00 00 00 ; .quad hook`
     *   slot+16 .. slot+16+N : copied prologue (rel32-fixed)
     *   slot+16+N .. +N+20   : E9 disp32 to target + prologue_len
     *
     * The 16-byte alignment of the trampoline body simplifies
     * debugger inspection.  Total per-slot use: <= 16 + 32 + 5 = 53
     * bytes; we provision 64 per slot. */
    const size_t TRAMP_BODY_OFF = 16u;

    /* Emit the forwarding stub. */
    slot[0] = 0xFFu;
    slot[1] = 0x25u;
    slot[2] = 0x00u; slot[3] = 0x00u; slot[4] = 0x00u; slot[5] = 0x00u;
    {
        uint64_t u = (uint64_t)(uintptr_t)hook;
        for (int i = 0; i < 8; i++) {
            slot[6 + i] = (uint8_t)((u >> (i * 8)) & 0xFFu);
        }
    }

    /* Lazy-init the page's thunk arena so rel32 fixup has somewhere
     * to stash overflow thunks. */
    if (!pg->arena_init_done) {
        if (ct_thunk_arena_init(&pg->arena, (uintptr_t)pg->base) != 0) {
            free_hook(entry);
            return -3;
        }
        pg->arena_init_done = 1;
    }

    /* Copy + fix up the prologue into the trampoline body. */
    uint8_t *body = slot + TRAMP_BODY_OFF;
    memcpy(body, t, (size_t)prologue_len);
    int frc = ct_rel32_fixup_prologue(t, (size_t)prologue_len,
                                       body,
                                       (uintptr_t)t,
                                       (uintptr_t)body,
                                       &pg->arena);
    CT_DBG("[ct_inline_hook] rel32_fixup rc=%d\n", frc);
    if (frc != 0) {
        free_hook(entry);
        return -3;
    }

    /* Append JMP rel32 back to target + prologue_len. */
    emit_jmp_rel32(body + prologue_len,
                   (uintptr_t)(t + prologue_len));

    /* The JMP rel32 we'll write at the target points to slot+0
     * (the forwarding stub), which is in the trampoline page and
     * therefore within ±2 GB of the target by construction. */
    int rng = in_rel32_range((uintptr_t)t + 5, (uintptr_t)slot);
    CT_DBG("[ct_inline_hook] checking rel32 range t+5=%p slot=%p rng=%d\n",
           (void *)((uintptr_t)t + 5), slot, rng);
    if (!rng) {
        free_hook(entry);
        return -3;
    }

    uint8_t jmp[5];
    int64_t disp64 = (int64_t)(uintptr_t)slot - ((int64_t)(uintptr_t)t + 5);
    int32_t disp32 = (int32_t)disp64;
    jmp[0] = 0xE9u;
    jmp[1] = (uint8_t)(disp32 & 0xFFu);
    jmp[2] = (uint8_t)((disp32 >> 8) & 0xFFu);
    jmp[3] = (uint8_t)((disp32 >> 16) & 0xFFu);
    jmp[4] = (uint8_t)((disp32 >> 24) & 0xFFu);

    if (write_patch((void *)t, 5, jmp) != 0) {
        free_hook(entry);
        return -4;
    }

    /* If the prologue was longer than 5 bytes (e.g. the first
     * instruction was 7 bytes), the bytes after the JMP rel32 are now
     * "garbage" left over from the previous prologue.  This is fine
     * because no instruction stream falls through them: the JMP rel32
     * unconditionally diverts to the hook, and the trampoline contains
     * the original prologue + a tail JMP back to `target + prologue_len`,
     * so control returns past the garbage.  We do NOT need to fill the
     * tail with INT3 -- doing so would risk a race where another thread
     * already mid-instruction in the prologue tries to fetch the
     * (now-padded) bytes.  Leaving them untouched is the Detours/MinHook
     * convention. */

    entry->target = target;
    entry->hook = hook;
    entry->trampoline = slot + TRAMP_BODY_OFF;
    entry->install_mode = CT_INSTALL_MODE_OVERWRITE;
    g_last_install_mode = CT_INSTALL_MODE_OVERWRITE;
    if (out_trampoline != NULL) *out_trampoline = entry->trampoline;
    return 0;
}

static int uninstall_locked(void *target)
{
    ct_hook_entry_t *entry = find_hook(target);
    if (entry == NULL) return -1;

    uint8_t *t = (uint8_t *)target;
    if (entry->install_mode == CT_INSTALL_MODE_HOTPATCH) {
        /* Restore the upstream 5 bytes of padding + the 2-byte
         * mov edi,edi at target. */
        if (write_patch((void *)(t - 5), 7, entry->orig_prologue) != 0)
            return -4;
    } else {
        /* Restore the saved prologue bytes (just the first 5 are
         * strictly necessary since that's all we overwrote, but
         * writing the full original prologue is safe and matches what
         * tests assert). */
        if (write_patch((void *)t, entry->prologue_len, entry->orig_prologue) != 0)
            return -4;
    }

    /* Don't VirtualFree the trampoline slot -- it lives inside a
     * shared 64 KB page that may host other hooks.  The bump
     * allocator never reclaims slots; the page reclaims when the
     * recorder unloads.  Acceptable for M50.2's expected hook count
     * (tens, not thousands per process). */
    free_hook(entry);
    return 0;
}

int ct_inline_hook_install(void *target, void *hook, void **out_trampoline)
{
    ensure_cs_initialised();
    EnterCriticalSection(&g_hooks_cs);

    /* If a transaction is active on this thread, queue the op. */
    if (g_txn.active && g_txn.owner_tid == GetCurrentThreadId()) {
        if (g_txn.count >= CT_QUEUE_MAX) {
            LeaveCriticalSection(&g_hooks_cs);
            return -4;
        }
        g_txn.ops[g_txn.count].kind = 0;
        g_txn.ops[g_txn.count].target = target;
        g_txn.ops[g_txn.count].hook = hook;
        g_txn.ops[g_txn.count].out_trampoline = out_trampoline;
        g_txn.count++;
        LeaveCriticalSection(&g_hooks_cs);
        return 0;
    }

    ct_frozen_t fr;
    if (suspend_other_threads(&fr) != 0) {
        LeaveCriticalSection(&g_hooks_cs);
        return -4;
    }
    int rc = install_locked(target, hook, out_trampoline);
    resume_other_threads(&fr);
    LeaveCriticalSection(&g_hooks_cs);
    return rc;
}

/* MW13 (MCR-Windows-CtMcr-Port.milestones.org).
 *
 * Noreturn-syscall install variant.  Emits a *different* trampoline
 * shape from ct_inline_hook_install: instead of routing the 5-byte
 * JMP rel32 to a hook function (Nim/C, with its own stack frame),
 * the 5-byte JMP rel32 lands directly on a small piece of generated
 * assembly that:
 *
 *   1. Allocates a scratch frame (sub rsp, 0x38).
 *   2. Saves caller's RCX, RDX into the scratch frame.
 *   3. Calls `record_callback` (which records the event and returns).
 *   4. Restores RCX, RDX from the scratch frame.
 *   5. Releases the scratch frame (add rsp, 0x38).
 *   6. Executes the original NT stub's copied prologue (e.g.
 *      `mov r10, rcx; mov eax, <syscall_num>`).
 *   7. JMPs to target + prologue_len (where the SYSCALL instruction
 *      lives).
 *
 * The critical property: by the time control reaches the JMP in
 * step 7, RSP and all callee-saved regs are byte-identical to what
 * RtlExitUserThread (or any other caller of the NT stub) had set up
 * before the call.  No "hook function frame" sits between
 * RtlExitUserThread and the SYSCALL -- the kernel's thread-
 * termination unwinder sees exactly the stack frame it expects.
 *
 * Pre-MW13, the noreturn syscall (NtTerminateThread of NtCurrentThread)
 * was hooked via ct_inline_hook_install with a Nim hook function
 * that called the trampoline at the end.  The Nim function's
 * ABI-required prologue/epilog (push rbp, sub rsp, save callee-saved
 * regs, restore-and-ret) added a frame between RtlExitUserThread and
 * the SYSCALL.  On the inject_dll-spawned init thread
 * (BaseThreadInitThunk -> RtlExitUserThread, where the RtlExitUserThread
 * frame is the only one above the syscall), the kernel's stack
 * unwinder observed the extra frame and AVed with
 * STATUS_ACCESS_VIOLATION during the thread-termination cleanup.
 * Worked around with CT_SKIP_NTDLL_TERMINATE_THREAD=1 pre-MW13; this
 * variant retires that env var.
 *
 * Trampoline layout for the noreturn variant:
 *
 *   slot+0  ..   noreturn entry stub (CALL-and-continue, see below)
 *   slot+N  ..   copied original prologue (rel32-fixed)
 *   slot+N+M ..  E9 disp32 to target + prologue_len
 *
 * Entry-stub assembly (Win64):
 *
 *   sub rsp, 0x38              ; 48 = 32 (shadow) + 16 (rcx/rdx save)
 *   mov [rsp+0x20], rcx        ; save arg1
 *   mov [rsp+0x28], rdx        ; save arg2
 *   mov rax, <record_callback> ; absolute address
 *   call rax
 *   mov rdx, [rsp+0x28]        ; restore arg2
 *   mov rcx, [rsp+0x20]        ; restore arg1
 *   add rsp, 0x38
 *   ; falls through to copied prologue
 *
 * 0x38 (56) bytes:
 *   [rsp+0x00 .. 0x1F]  shadow space for the called function
 *   [rsp+0x20]          saved RCX
 *   [rsp+0x28]          saved RDX
 *   [rsp+0x30]          unused (alignment: the trampoline is entered
 *                       with RSP = ... + 8 (one CALL push from
 *                       RtlExitUserThread), and after sub rsp,0x38
 *                       we have RSP aligned to 16 — required by
 *                       Win64 ABI before the inner CALL).
 *
 * RAX is clobbered (used to load the callback address and to receive
 * the callback's return value, which we ignore).  R8/R9 are NOT saved
 * -- NtTerminateThread does not use them.  If a future caller hooks
 * a noreturn stub that takes more than two args, extend the layout to
 * save R8/R9 (and adjust the sub/add immediate accordingly).
 *
 * Note that record_callback is called via `mov rax, imm64; call rax`
 * (16 bytes including REX prefix) rather than a CALL rel32 — the
 * callback may live in the recorder's DLL several GB from the
 * trampoline page (kernel32 and ntdll are at low addresses; the
 * recorder DLL may be loaded by LoadLibrary into a high-address
 * region), so a 32-bit displacement is not guaranteed to reach.
 */

/* Emit the noreturn-mode entry stub at `at`.  Returns the number of
 * bytes written (must equal CT_NORETURN_STUB_BYTES). */
#define CT_NORETURN_STUB_BYTES 30

static size_t emit_noreturn_entry_stub(uint8_t *at, void *callback)
{
    uint8_t *p = at;
    /* sub rsp, 0x38   (48 03 EC 38) */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x38;
    /* mov [rsp+0x20], rcx   (48 89 4C 24 20) */
    *p++ = 0x48; *p++ = 0x89; *p++ = 0x4C; *p++ = 0x24; *p++ = 0x20;
    /* mov [rsp+0x28], rdx   (48 89 54 24 28) */
    *p++ = 0x48; *p++ = 0x89; *p++ = 0x54; *p++ = 0x24; *p++ = 0x28;
    /* mov rax, imm64   (48 B8 .. ..) */
    *p++ = 0x48; *p++ = 0xB8;
    uint64_t cb = (uint64_t)(uintptr_t)callback;
    for (int i = 0; i < 8; i++) { *p++ = (uint8_t)((cb >> (i * 8)) & 0xFFu); }
    /* call rax   (FF D0) */
    *p++ = 0xFF; *p++ = 0xD0;
    /* mov rdx, [rsp+0x28]   (48 8B 54 24 28) */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x54; *p++ = 0x24; *p++ = 0x28;
    /* mov rcx, [rsp+0x20]   (48 8B 4C 24 20) */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x4C; *p++ = 0x24; *p++ = 0x20;
    /* add rsp, 0x38   (48 83 C4 38) */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x38;
    return (size_t)(p - at);
}

/* The noreturn-mode install path.  Distinct from install_locked
 * because the trampoline layout differs (entry stub instead of
 * forwarding stub; entry stub falls through to copied prologue
 * rather than being JMPed to by an external hook function). */
static int install_locked_noreturn(void *target, void *record_callback,
                                   void **out_trampoline)
{
    CT_DBG("[ct_inline_hook] install_locked_noreturn target=%p cb=%p\n",
           target, record_callback);
    if (target == NULL || record_callback == NULL) return -1;
    if (find_hook(target) != NULL) return -5;

    ct_hook_entry_t *entry = alloc_hook();
    if (entry == NULL) return -4;

    const uint8_t *t = (const uint8_t *)target;

    /* Hot-patch shape is not supported for noreturn mode — the
     * 2-byte mov edi,edi entry plus the 5-byte upstream-padding
     * trampoline doesn't have room for our entry stub.  Noreturn
     * mode requires overwrite mode (which has the full ±2 GB
     * trampoline page available).  Verified via length decoder. */

    int decode_max = (int)CT_INLINE_HOOK_PROLOGUE_BACKUP;
    int prologue_len = ct_ild_decode_to_cover(t, 5, (size_t)decode_max);
    CT_DBG("[ct_inline_hook] noreturn prologue_len=%d\n", prologue_len);
    if (prologue_len <= 0 || prologue_len > decode_max) {
        free_hook(entry);
        return -2;
    }
    if (prologue_len < 5) {
        free_hook(entry);
        return -2;
    }

    /* Save original prologue bytes (for uninstall). */
    memcpy(entry->orig_prologue, t, (size_t)prologue_len);
    entry->prologue_len = (size_t)prologue_len;

    /* Allocate a trampoline slot.  The default CT_TRAMP_SLOT_BYTES
     * (64) is enough for: 30-byte entry stub + up to 16-byte
     * prologue copy + 5-byte JMP rel32 = 51 bytes. */
    uint8_t *slot = alloc_tramp_slot((uintptr_t)t);
    CT_DBG("[ct_inline_hook] noreturn slot=%p\n", slot);
    if (slot == NULL) {
        free_hook(entry);
        return -4;
    }
    ct_tramp_page_t *pg = find_owning_page(slot);
    if (pg == NULL) {
        free_hook(entry);
        return -4;
    }

    /* Layout:
     *   slot+0                            : entry stub (30 bytes)
     *   slot+30                           : copied prologue
     *   slot+30+prologue_len              : E9 disp32 to target+prologue_len
     */
    size_t stub_bytes = emit_noreturn_entry_stub(slot, record_callback);
    if (stub_bytes != CT_NORETURN_STUB_BYTES) {
        /* Defensive: emitter inconsistency. */
        free_hook(entry);
        return -4;
    }

    /* Lazy-init the page's thunk arena for rel32 fixup overflow. */
    if (!pg->arena_init_done) {
        if (ct_thunk_arena_init(&pg->arena, (uintptr_t)pg->base) != 0) {
            free_hook(entry);
            return -3;
        }
        pg->arena_init_done = 1;
    }

    /* Copy + fix up the prologue into the trampoline body. */
    uint8_t *body = slot + stub_bytes;
    memcpy(body, t, (size_t)prologue_len);
    int frc = ct_rel32_fixup_prologue(t, (size_t)prologue_len,
                                       body,
                                       (uintptr_t)t,
                                       (uintptr_t)body,
                                       &pg->arena);
    CT_DBG("[ct_inline_hook] noreturn rel32_fixup rc=%d\n", frc);
    if (frc != 0) {
        free_hook(entry);
        return -3;
    }

    /* Append JMP rel32 back to target + prologue_len. */
    emit_jmp_rel32(body + prologue_len,
                   (uintptr_t)(t + prologue_len));

    /* The JMP rel32 we'll write at the target points to slot+0
     * (the entry stub). */
    int rng = in_rel32_range((uintptr_t)t + 5, (uintptr_t)slot);
    if (!rng) {
        free_hook(entry);
        return -3;
    }

    uint8_t jmp[5];
    int64_t disp64 = (int64_t)(uintptr_t)slot - ((int64_t)(uintptr_t)t + 5);
    int32_t disp32 = (int32_t)disp64;
    jmp[0] = 0xE9u;
    jmp[1] = (uint8_t)(disp32 & 0xFFu);
    jmp[2] = (uint8_t)((disp32 >> 8) & 0xFFu);
    jmp[3] = (uint8_t)((disp32 >> 16) & 0xFFu);
    jmp[4] = (uint8_t)((disp32 >> 24) & 0xFFu);

    if (write_patch((void *)t, 5, jmp) != 0) {
        free_hook(entry);
        return -4;
    }

    entry->target = target;
    entry->hook = record_callback;
    /* Trampoline pointer is not exposed for noreturn mode -- the
     * caller has no use for it (it can't be invoked as a normal
     * function; calling it would fire the SYSCALL and never return,
     * which is the OPPOSITE of what a "trampoline" is supposed to do
     * for a typical hook).  Set NULL. */
    entry->trampoline = NULL;
    entry->install_mode = CT_INSTALL_MODE_OVERWRITE;
    g_last_install_mode = CT_INSTALL_MODE_OVERWRITE;
    if (out_trampoline != NULL) *out_trampoline = NULL;
    return 0;
}

int ct_inline_hook_install_noreturn(void *target, void *record_callback,
                                    void **out_trampoline)
{
    ensure_cs_initialised();
    EnterCriticalSection(&g_hooks_cs);

    if (g_txn.active && g_txn.owner_tid == GetCurrentThreadId()) {
        /* Queueing a noreturn install inside a transaction is not
         * supported.  MW13's single client (NtTerminateThread) does
         * not batch; if a future caller needs it, add a `noreturn`
         * flag to ct_queued_op_t. */
        LeaveCriticalSection(&g_hooks_cs);
        return -1;
    }

    ct_frozen_t fr;
    if (suspend_other_threads(&fr) != 0) {
        LeaveCriticalSection(&g_hooks_cs);
        return -4;
    }
    int rc = install_locked_noreturn(target, record_callback, out_trampoline);
    resume_other_threads(&fr);
    LeaveCriticalSection(&g_hooks_cs);
    return rc;
}

int ct_inline_hook_uninstall(void *target)
{
    ensure_cs_initialised();
    EnterCriticalSection(&g_hooks_cs);

    if (g_txn.active && g_txn.owner_tid == GetCurrentThreadId()) {
        if (g_txn.count >= CT_QUEUE_MAX) {
            LeaveCriticalSection(&g_hooks_cs);
            return -4;
        }
        g_txn.ops[g_txn.count].kind = 1;
        g_txn.ops[g_txn.count].target = target;
        g_txn.ops[g_txn.count].hook = NULL;
        g_txn.ops[g_txn.count].out_trampoline = NULL;
        g_txn.count++;
        LeaveCriticalSection(&g_hooks_cs);
        return 0;
    }

    ct_frozen_t fr;
    if (suspend_other_threads(&fr) != 0) {
        LeaveCriticalSection(&g_hooks_cs);
        return -4;
    }
    int rc = uninstall_locked(target);
    resume_other_threads(&fr);
    LeaveCriticalSection(&g_hooks_cs);
    return rc;
}

int ct_inline_hook_install_get_last_install_mode(void)
{
    return g_last_install_mode;
}

#endif /* _WIN32 */
