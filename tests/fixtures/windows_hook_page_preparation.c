/* Real executable-page and peer-thread regression; no mocks. The counting
 * wrapper below always calls the real VirtualProtect with the original
 * arguments and preserves its result and LastError. Counting actual calls
 * makes repeated page preparation detectable without a timing threshold.
 * Targets, replacement bodies, trampolines, protection checks and thread
 * suspension all run against the actual Windows backend and kernel. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uintptr_t code_begin, code_end;
static unsigned long protection_calls;
static int count_protection;

static BOOL counted_protect(LPVOID address, SIZE_T size, DWORD protection,
                            PDWORD old_protection)
{
    BOOL result = VirtualProtect(address, size, protection, old_protection);
    DWORD error = GetLastError();
    if (count_protection && (uintptr_t)address >= code_begin &&
        (uintptr_t)address < code_end)
        protection_calls++;
    SetLastError(error);
    return result;
}

#define VirtualProtect counted_protect
#include "../../src/stackable_hooks/inline_hook/windows/install_windows.c"
#undef VirtualProtect

#define TARGET_COUNT 33
typedef int (*target_fn)(void);
typedef struct {
    HANDLE go, done;
    volatile LONG stop;
    volatile LONG failed;
    int expected_delta;
    target_fn targets[TARGET_COUNT];
} peer_state;

static DWORD WINAPI peer_calls_targets(void *argument)
{
    peer_state *state = (peer_state *)argument;
    for (;;) {
        if (WaitForSingleObject(state->go, INFINITE) != WAIT_OBJECT_0) return 1;
        if (InterlockedCompareExchange(&state->stop, 0, 0)) return 0;
        for (int i = 0; i < TARGET_COUNT; ++i)
            if (state->targets[i]() != i + state->expected_delta)
                InterlockedExchange(&state->failed, 1);
        if (!SetEvent(state->done)) return 2;
    }
}

static int check_peer(peer_state *state, int delta)
{
    state->expected_delta = delta;
    return SetEvent(state->go) &&
        WaitForSingleObject(state->done, 5000) == WAIT_OBJECT_0 && !state->failed;
}

static void emit_return(uint8_t *at, int value)
{
    /* x86/x64: mov eax, imm32; ret. Its five-byte first instruction is also
     * the overwritten prologue. One target straddles two executable pages. */
    uint32_t immediate = (uint32_t)value;
    at[0] = 0xb8;
    memcpy(at + 1, &immediate, sizeof(immediate));
    at[5] = 0xc3;
}

static int pages_restored(uint8_t *code, size_t page_size)
{
    for (size_t i = 0; i < 3; ++i) {
        MEMORY_BASIC_INFORMATION info;
        if (!VirtualQuery(code + i * page_size, &info, sizeof(info)) ||
            info.Protect != PAGE_EXECUTE_READ)
            return 0;
    }
    return 1;
}

int ct_test_windows_hook_page_preparation(void)
{
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);
    size_t page_size = system_info.dwPageSize;
    if (page_size < 1024) return 10;
    size_t size = page_size * 3;
    uint8_t *code = (uint8_t *)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT,
                                            PAGE_READWRITE);
    uint8_t *original = (uint8_t *)malloc(size);
    if (!code || !original) return 11;
    code_begin = (uintptr_t)code;
    code_end = code_begin + size;
    memset(code, 0xcc, size);
    peer_state state = {0};
    target_fn replacements[TARGET_COUNT];
    void *trampolines[TARGET_COUNT] = {0};
    for (int i = 0; i < TARGET_COUNT; ++i) {
        uint8_t *target = i == TARGET_COUNT - 1 ? code + 2 * page_size - 3 :
                          code + 64 + i * 16;
        uint8_t *replacement = code + page_size + 64 + i * 16;
        emit_return(target, i);
        emit_return(replacement, i + 1000);
        state.targets[i] = (target_fn)target;
        replacements[i] = (target_fn)replacement;
    }
    memcpy(original, code, size);
    DWORD old_protection;
    if (!VirtualProtect(code, size, PAGE_EXECUTE_READ, &old_protection) ||
        !FlushInstructionCache(GetCurrentProcess(), code, size)) return 12;
    state.go = CreateEventW(NULL, FALSE, FALSE, NULL);
    state.done = CreateEventW(NULL, FALSE, FALSE, NULL);
    HANDLE peer = CreateThread(NULL, 0, peer_calls_targets, &state, 0, NULL);
    if (!state.go || !state.done || !peer || !check_peer(&state, 0)) return 13;

    int redundant_preparation = 0;
    for (int round = 0; round < 2; ++round) {
        if (ct_inline_hook_begin_transaction() != 0) return 20;
        for (int i = 0; i < TARGET_COUNT; ++i)
            if (ct_inline_hook_install((void *)state.targets[i],
                    (void *)replacements[i], &trampolines[i]) != 0) return 21;
        protection_calls = 0;
        count_protection = 1;
        unsigned long rounds = ct_inline_hook_suspend_round_count();
        int installed = ct_inline_hook_commit_transaction();
        count_protection = 0;
        if (installed != 0) return 22;
        if (ct_inline_hook_suspend_round_count() != rounds + 1) return 23;
        if (!pages_restored(code, page_size) || !check_peer(&state, 1000)) return 24;
        for (int i = 0; i < TARGET_COUNT; ++i)
            if (!trampolines[i] || ((target_fn)trampolines[i])() != i) return 25;
        /* Three distinct target pages, each warmed once (two protection
         * calls), plus each hook's unchanged writable/restore write pair. */
        const unsigned long expected_calls = 3 * 2 + TARGET_COUNT * 2;
        printf("round=%d real-protection-calls=%lu expected=%lu\n",
                round, protection_calls, expected_calls);
        if (protection_calls != expected_calls) redundant_preparation = 1;
        if (ct_inline_hook_begin_transaction() != 0) return 26;
        for (int i = 0; i < TARGET_COUNT; ++i)
            if (ct_inline_hook_uninstall((void *)state.targets[i]) != 0) return 27;
        if (ct_inline_hook_commit_transaction() != 0) return 28;
        if (!pages_restored(code, page_size) || !check_peer(&state, 0) ||
            memcmp(code, original, size) != 0) return 29;
    }
    InterlockedExchange(&state.stop, 1);
    if (!SetEvent(state.go) || WaitForSingleObject(peer, 5000) != WAIT_OBJECT_0)
        return 30;
    CloseHandle(peer);
    CloseHandle(state.go);
    CloseHandle(state.done);
    VirtualFree(code, 0, MEM_RELEASE);
    free(original);
    puts("real target, trampoline, peer and protection checks passed");
    return redundant_preparation ? 71 : 0;
}

#ifdef CT_TEST_STANDALONE
int main(int argc, char **argv)
{
    typedef BOOL (WINAPI *machine_query)(HANDLE, USHORT *, USHORT *);
    machine_query query = (machine_query)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                                        "IsWow64Process2");
    USHORT process_machine = 0, native_machine = 0;
    if (argc != 2 || !query ||
        !query(GetCurrentProcess(), &process_machine, &native_machine)) return 80;
    USHORT expected_native = !strcmp(argv[1], "ARM64") ? 0xaa64 :
                              !strcmp(argv[1], "X64") ? 0x8664 : 0;
    uint8_t *image = (uint8_t *)GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)image;
    IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS *)(image + dos->e_lfanew);
    USHORT expected_pe = sizeof(void *) == 8 ? 0x8664 : 0x014c;
    printf("native-machine=%04x process-machine=%04x pe-machine=%04x\n",
            native_machine, process_machine, pe->FileHeader.Machine);
    if (!expected_native || native_machine != expected_native ||
        pe->FileHeader.Machine != expected_pe) return 81;
    return ct_test_windows_hook_page_preparation();
}
#endif
