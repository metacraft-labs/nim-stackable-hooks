/*
 * Windows on Arm64 inline-hook fixture (reprobuild-pm spec/Monitor-Hook-Shim.md,
 * "Windows on Arm64 install backend").
 *
 * Everything here is real: functions are ARM64 machine code written into
 * executable pages (plus one real system function, GetCurrentProcessId), the
 * hooks are installed by the production backend compiled in below, and peer
 * threads really run the hooked code during a transaction. The only
 * synthetic part is the choice of first instruction of each function, which
 * is the point: one function per PC-relative form the backend relocates.
 *
 * Encodings: Arm Architecture Reference Manual A-profile (DDI 0487), C6.2.
 */
#if defined(_WIN32) && (defined(_M_ARM64) || defined(__aarch64__))

#include "../../src/stackable_hooks/inline_hook/windows/install_windows.c"

#include <stdio.h>

typedef long long (*fn0_t)(void);
typedef long long (*fn1_t)(long long);
typedef long long (*fn2_t)(long long, long long);

static int g_failures = 0;
#define CHECK(cond, ...) do { if (!(cond)) { g_failures++; printf("FAIL: " __VA_ARGS__); printf("\n"); } else { printf("ok: " __VA_ARGS__); printf("\n"); } } while (0)

/* One executable page per synthetic function, so each has its own literal
 * data and no function's patch can touch another's bytes. */
static uint32_t *make_function(const uint32_t *words, size_t count)
{
    uint32_t *page = (uint32_t *)VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT,
                                              PAGE_EXECUTE_READWRITE);
    if (page == NULL) return NULL;
    memcpy(page, words, count * 4);
    FlushInstructionCache(GetCurrentProcess(), page, 4096);
    return page;
}

#define RET         0xD65F03C0u
#define MOVZ_X0(v)  (0xD2800000u | ((uint32_t)(v) << 5))          /* movz x0, #v */
#define ADD_X0_X0_X1 0x8B010000u                                  /* add x0, x0, x1 */

/* ---- hook bodies ------------------------------------------------------ */
static fn0_t g_tramp0;
static volatile LONG g_hook_calls;
static long long hook_plus_1000(void)
{
    InterlockedIncrement(&g_hook_calls);
    return g_tramp0() + 1000;
}

/* Transaction hooks: commit writes each trampoline through the caller's
 * out pointer while every peer is still frozen, so a peer that reaches a
 * hook after the commit always finds its trampoline set. */
static fn0_t volatile g_tramp_a, g_tramp_b;
static long long hook_a(void) { return g_tramp_a() + 1000; }
static long long hook_b(void) { return g_tramp_b() + 1000; }

static fn1_t g_tramp1;
static long long hook1_plus_1000(long long a) { return g_tramp1(a) + 1000; }

typedef DWORD (WINAPI *pid_fn_t)(void);
static pid_fn_t g_pid_tramp;
static volatile LONG g_pid_calls;
static DWORD WINAPI hook_pid(void)
{
    InterlockedIncrement(&g_pid_calls);
    return g_pid_tramp();
}

static volatile LONG g_record_calls;
static volatile long long g_record_a, g_record_b;
static void record_callback(long long a, long long b)
{
    InterlockedIncrement(&g_record_calls);
    g_record_a = a;
    g_record_b = b;
}

/* Hook `fn`, call it through `call`, and require `expected + 1000`, a B patch
 * that decodes to the slot, and the original word restored on uninstall. */
static void check_relocated(const char *name, uint32_t *fn, fn0_t *tramp_slot,
                            long long expected)
{
    const uint32_t original = fn[0];
    void *tramp = NULL;
    int rc = ct_inline_hook_install(fn, (void *)hook_plus_1000, &tramp);
    CHECK(rc == 0, "%s: install rc=%d", name, rc);
    if (rc != 0) return;
    *tramp_slot = (fn0_t)tramp;
    uintptr_t dest = 0;
    CHECK(ct_a64_decode_b(fn[0], (uintptr_t)fn, &dest) == 1 &&
          dest - (uintptr_t)fn + CT_A64_B_REACH < 2 * (uintptr_t)CT_A64_B_REACH,
          "%s: the target begins with a B in reach (0x%08x)", name, fn[0]);
    long long hooked = ((fn0_t)fn)();
    CHECK(hooked == expected + 1000, "%s: hooked call returned %lld, want %lld",
          name, hooked, expected + 1000);
    CHECK(((fn0_t)tramp)() == expected, "%s: trampoline alone returns the original", name);
    rc = ct_inline_hook_uninstall(fn);
    CHECK(rc == 0 && fn[0] == original, "%s: uninstall restores 0x%08x (rc=%d)",
          name, original, rc);
    CHECK(((fn0_t)fn)() == expected, "%s: unhooked call returns the original", name);
}

static DWORD WINAPI peer_loop(LPVOID arg)
{
    fn0_t fn = (fn0_t)arg;
    for (int i = 0; i < 200000; i++) (void)fn();
    return 0;
}

int ct_test_windows_arm64_inline_hook(void)
{
    /* 1. Position-independent first instruction. */
    {
        const uint32_t w[] = { MOVZ_X0(7), RET };
        uint32_t *fn = make_function(w, 2);
        check_relocated("plain", fn, &g_tramp0, 7);
    }
    /* 2. LDR (literal): ldr x0, #8 ; ret ; .quad 42 */
    {
        const uint32_t w[] = { 0x58000040u, RET, 42u, 0u };
        uint32_t *fn = make_function(w, 4);
        check_relocated("ldr-literal", fn, &g_tramp0, 42);
    }
    /* 3. ADR: adr x0, #12 ; ldr x0, [x0] ; ret ; .quad 43 */
    {
        const uint32_t w[] = { 0x10000060u, 0xF9400000u, RET, 43u, 0u };
        uint32_t *fn = make_function(w, 5);
        check_relocated("adr", fn, &g_tramp0, 43);
    }
    /* 4. ADRP + ADD :lo12: + LDR: the shape of an import thunk. The data
     *    sits at page offset 0x800 of the function's own page. */
    {
        uint32_t w[0x210];
        memset(w, 0, sizeof(w));
        w[0] = 0x90000000u;                          /* adrp x0, #0 (own page) */
        w[1] = 0x91200000u;                          /* add x0, x0, #0x800 */
        w[2] = 0xF9400000u;                          /* ldr x0, [x0] */
        w[3] = RET;
        w[0x200] = 44u;                              /* page+0x800 */
        uint32_t *fn = make_function(w, 0x202);
        check_relocated("adrp", fn, &g_tramp0, 44);
    }
    /* 5. B as the first instruction (a tail-jump thunk): b #8 ; brk ; movz x0,#45 ; ret */
    {
        const uint32_t w[] = { 0x14000002u, 0xD4200000u, MOVZ_X0(45), RET };
        uint32_t *fn = make_function(w, 4);
        check_relocated("b", fn, &g_tramp0, 45);
    }
    /* 6. CBZ both ways: cbz x0, #12 ; movz x0,#1 ; ret ; movz x0,#2 ; ret */
    {
        const uint32_t w[] = { 0xB4000060u, MOVZ_X0(1), RET, MOVZ_X0(2), RET };
        uint32_t *fn = make_function(w, 5);
        const uint32_t original = fn[0];
        void *tramp = NULL;
        int rc = ct_inline_hook_install(fn, (void *)hook1_plus_1000, &tramp);
        CHECK(rc == 0, "cbz: install rc=%d", rc);
        if (rc == 0) {
            g_tramp1 = (fn1_t)tramp;
            CHECK(((fn1_t)fn)(0) == 1002, "cbz: taken path");
            CHECK(((fn1_t)fn)(5) == 1001, "cbz: not-taken path");
            CHECK(ct_inline_hook_uninstall(fn) == 0 && fn[0] == original, "cbz: uninstall");
        }
    }
    /* 7. A real system function, and a hook that runs while peers call it. */
    {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        void *target = (void *)GetProcAddress(k32, "GetCurrentProcessId");
        const DWORD pid = GetCurrentProcessId();
        int rc = ct_inline_hook_install(target, (void *)hook_pid, (void **)&g_pid_tramp);
        CHECK(rc == 0, "GetCurrentProcessId: install rc=%d", rc);
        if (rc == 0) {
            const DWORD seen = ((pid_fn_t)target)();
            CHECK(seen == pid && g_pid_calls >= 1,
                  "GetCurrentProcessId: hooked call returns the pid (calls=%ld)", g_pid_calls);
            CHECK(ct_inline_hook_uninstall(target) == 0, "GetCurrentProcessId: uninstall");
        }
    }
    /* 8. A transaction installing two hooks while two peers run the targets. */
    {
        const uint32_t wa[] = { MOVZ_X0(11), RET };
        const uint32_t wb[] = { MOVZ_X0(12), RET };
        uint32_t *fa = make_function(wa, 2), *fb = make_function(wb, 2);
        HANDLE peers[2] = {
            CreateThread(NULL, 0, peer_loop, fa, 0, NULL),
            CreateThread(NULL, 0, peer_loop, fb, 0, NULL),
        };
        const unsigned long rounds = ct_inline_hook_suspend_round_count();
        int b = ct_inline_hook_begin_transaction();
        int ia = ct_inline_hook_install(fa, (void *)hook_a, (void **)&g_tramp_a);
        int ib = ct_inline_hook_install(fb, (void *)hook_b, (void **)&g_tramp_b);
        int c = ct_inline_hook_commit_transaction();
        CHECK(b == 0 && ia == 0 && ib == 0 && c == 0,
              "transaction: begin=%d install=%d,%d commit=%d", b, ia, ib, c);
        CHECK(ct_inline_hook_suspend_round_count() == rounds + 1,
              "transaction: one freeze round for two hooks");
        WaitForMultipleObjects(2, peers, TRUE, INFINITE);
        CloseHandle(peers[0]); CloseHandle(peers[1]);
        CHECK(((fn0_t)fa)() == 1011, "transaction: first hook live");
        CHECK(((fn0_t)fb)() == 1012, "transaction: second hook live");
        CHECK(ct_inline_hook_uninstall(fa) == 0 && ct_inline_hook_uninstall(fb) == 0,
              "transaction: uninstall both");
    }
    /* 9. The noreturn variant records, then the original runs with its
     *    arguments intact: add x0, x0, x1 ; ret */
    {
        const uint32_t w[] = { ADD_X0_X0_X1, RET };
        uint32_t *fn = make_function(w, 2);
        void *tramp = (void *)1;
        int rc = ct_inline_hook_install_noreturn(fn, (void *)record_callback, &tramp);
        CHECK(rc == 0 && tramp == NULL, "noreturn: install rc=%d", rc);
        if (rc == 0) {
            const long long sum = ((fn2_t)fn)(30, 12);
            CHECK(sum == 42 && g_record_calls == 1 && g_record_a == 30 && g_record_b == 12,
                  "noreturn: recorded (%lld,%lld) and returned %lld",
                  g_record_a, g_record_b, sum);
            CHECK(ct_inline_hook_uninstall(fn) == 0 && fn[0] == ADD_X0_X0_X1,
                  "noreturn: uninstall");
        }
    }
    /* 10. Refusals: misaligned target, and a double install. */
    {
        const uint32_t w[] = { MOVZ_X0(1), RET };
        uint32_t *fn = make_function(w, 2);
        void *tramp = NULL;
        CHECK(ct_inline_hook_install((uint8_t *)fn + 2, (void *)hook_plus_1000, &tramp) == -1,
              "refusal: a misaligned target is an invalid argument");
        CHECK(ct_inline_hook_install(fn, (void *)hook_plus_1000, &tramp) == 0 &&
              ct_inline_hook_install(fn, (void *)hook_plus_1000, &tramp) == -5,
              "refusal: a second install on the same target");
        ct_inline_hook_uninstall(fn);
    }

    if (g_failures == 0) printf("all arm64 inline hook checks passed\n");
    fflush(stdout);
    return g_failures == 0 ? 0 : 1;
}

#endif
