/* AArch64 (A64) body-patch + trampoline primitives — shared declarations.
 *
 * Struct layouts + prototypes for the functions defined in the `{.emit.}` block
 * of `linux_raw_syscalls_aarch64.nim`. Kept in a header so both this module and
 * any consumer translation unit see a single definition (avoids the
 * conflicting-types / opaque-struct problems of an emit-only definition).
 */
#ifndef STACKABLE_LINUX_RAW_SYSCALLS_AARCH64_H
#define STACKABLE_LINUX_RAW_SYSCALLS_AARCH64_H

struct stackable_linux_patch_result {
  int diagnostic;
  int stage;
  int os_errno;
  int patch_live;
  int restore_captured;
  unsigned long target;
  unsigned long replacement;
  unsigned long patch_size;
  unsigned char original[16];
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

int stackable_linux_aarch64_patch_absolute_jump_tx(
    void *target, void *replacement, int capture_restore,
    struct stackable_linux_patch_result *out);
int stackable_linux_aarch64_measure_original_trampoline(
    void *target, unsigned long min_patch_len, unsigned long max_scan,
    struct stackable_linux_trampoline_result *out);
int stackable_linux_aarch64_build_original_trampoline(
    void *target, unsigned long min_patch_len, unsigned long max_scan,
    struct stackable_linux_trampoline_result *out);
int stackable_linux_aarch64_relocate_window(unsigned char *tramp,
                                            unsigned long orig_addr,
                                            unsigned long tramp_addr,
                                            unsigned long copied);

#endif /* STACKABLE_LINUX_RAW_SYSCALLS_AARCH64_H */
