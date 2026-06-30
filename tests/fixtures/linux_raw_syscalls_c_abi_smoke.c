#include <stdint.h>
#include <stddef.h>

struct stackable_linux_patch_result {
  int diagnostic;
  int stage;
  int os_errno;
  int patch_live;
  int restore_captured;
  unsigned long target;
  unsigned long replacement;
  unsigned long patch_size;
  unsigned char original[14];
};

struct stackable_linux_trampoline_result {
  int diagnostic;
  int os_errno;
  unsigned long target;
  unsigned long entry;
  unsigned long copied_len;
  unsigned long min_patch_len;
  long unsupported_offset;
};

extern int stackable_linux_patch_absolute_jump_tx(
    void *target, void *replacement, int capture_restore,
    struct stackable_linux_patch_result *out);
extern int stackable_linux_measure_original_trampoline(
    void *target, unsigned long min_patch_len, unsigned long max_scan,
    struct stackable_linux_trampoline_result *out);
extern int stackable_linux_build_original_trampoline(
    void *target, unsigned long min_patch_len, unsigned long max_scan,
    struct stackable_linux_trampoline_result *out);
extern void *stackable_linux_resolve_symbol_in_handle(void *handle, char *name);
extern int stackable_linux_addr_in_executable_segment(unsigned long addr);
extern void stackable_linux_patch_registry_reset(void);
extern int stackable_linux_patch_registry_contains(unsigned long addr);
extern int stackable_linux_patch_registry_record(unsigned long addr);

static int stackable_c_fixture_function(void) {
  return 17;
}

int stackable_test_c_abi_link_smoke(void) {
  struct stackable_linux_patch_result tx;
  struct stackable_linux_trampoline_result tramp;
  int rc = stackable_linux_patch_absolute_jump_tx(NULL, NULL, 1, &tx);
  if (rc != 3 || tx.diagnostic != 3 || tx.stage != 1) return -1;
  if (tx.patch_live != 0 || tx.restore_captured != 0) return -2;
  rc = stackable_linux_measure_original_trampoline(NULL, 14, 64, &tramp);
  if (rc != 3 || tramp.diagnostic != 3 || tramp.entry != 0) return -7;
  rc = stackable_linux_build_original_trampoline(NULL, 14, 64, &tramp);
  if (rc != 3 || tramp.diagnostic != 3 || tramp.entry != 0) return -8;
  stackable_linux_patch_registry_reset();
  if (stackable_linux_patch_registry_record(0x1234UL) != 0) return -3;
  if (stackable_linux_patch_registry_contains(0x1234UL) != 1) return -4;
  if (stackable_linux_addr_in_executable_segment(
      (unsigned long)(uintptr_t)&stackable_c_fixture_function) != 1) return -5;
  if (stackable_linux_resolve_symbol_in_handle(NULL, "syscall") == NULL) return -6;
  return 0;
}
