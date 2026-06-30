#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ucontext.h>

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

struct stackable_linux_int3_patch_result {
  int diagnostic;
  int stage;
  int os_errno;
  int patch_live;
  int restore_captured;
  unsigned long target;
  unsigned char original_first_byte;
  unsigned char second_byte;
};

struct stackable_linux_syscall_regs {
  long nr;
  long args[6];
  long result;
  unsigned long trap_rip;
  unsigned long syscall_address;
  unsigned long resume_rip;
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
extern int stackable_linux_patch_int3_syscall_tx(
    void *target, struct stackable_linux_int3_patch_result *out);
extern int stackable_linux_restore_int3_syscall(
    void *target, unsigned char original_first_byte, int *out_errno);
extern int stackable_linux_capture_syscall_regs_from_ucontext(
    void *ucontext_ptr, struct stackable_linux_syscall_regs *out);
extern int stackable_linux_write_syscall_result_to_ucontext(
    void *ucontext_ptr, long result, unsigned long resume_rip);
extern long stackable_linux_replay_syscall_regs(
    const struct stackable_linux_syscall_regs *regs);
extern int stackable_linux_install_sigtrap_handler(void *handler, int extra_flags);
extern int stackable_linux_uninstall_sigtrap_handler(void);
extern int stackable_linux_chain_sigtrap(int signum, void *siginfo_ptr,
                                         void *ucontext_ptr);

static int stackable_c_fixture_function(void) {
  return 17;
}

static void stackable_test_sigtrap_handler(int signo, siginfo_t *info, void *uctx) {
  (void)signo;
  (void)info;
  (void)uctx;
}

static void *stackable_live_int3_site;
static volatile sig_atomic_t stackable_live_int3_hits;
static volatile sig_atomic_t stackable_live_int3_failures;

static void stackable_live_int3_handler(int signo, siginfo_t *info, void *uctx) {
  (void)signo;
  (void)info;
  struct stackable_linux_syscall_regs regs;
  int rc = stackable_linux_capture_syscall_regs_from_ucontext(uctx, &regs);
  if (rc != 0 ||
      regs.syscall_address != (unsigned long)(uintptr_t)stackable_live_int3_site) {
    stackable_live_int3_failures++;
    (void)stackable_linux_chain_sigtrap(signo, info, uctx);
    return;
  }
  long result = stackable_linux_replay_syscall_regs(&regs);
  rc = stackable_linux_write_syscall_result_to_ucontext(
      uctx, result, regs.resume_rip);
  if (rc != 0) {
    stackable_live_int3_failures++;
    return;
  }
  stackable_live_int3_hits++;
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
  struct stackable_linux_int3_patch_result int3;
  rc = stackable_linux_patch_int3_syscall_tx(NULL, &int3);
  if (rc != 3 || int3.diagnostic != 3 || int3.patch_live != 0) return -9;
  stackable_linux_patch_registry_reset();
  if (stackable_linux_patch_registry_record(0x1234UL) != 0) return -3;
  if (stackable_linux_patch_registry_contains(0x1234UL) != 1) return -4;
  if (stackable_linux_addr_in_executable_segment(
      (unsigned long)(uintptr_t)&stackable_c_fixture_function) != 1) return -5;
  if (stackable_linux_resolve_symbol_in_handle(NULL, "syscall") == NULL) return -6;
  return 0;
}

int stackable_test_ucontext_helpers_smoke(void) {
  ucontext_t uc;
  memset(&uc, 0, sizeof(uc));
  uc.uc_mcontext.gregs[REG_RAX] = 39;
  uc.uc_mcontext.gregs[REG_RDI] = 11;
  uc.uc_mcontext.gregs[REG_RSI] = 22;
  uc.uc_mcontext.gregs[REG_RDX] = 33;
  uc.uc_mcontext.gregs[REG_R10] = 44;
  uc.uc_mcontext.gregs[REG_R8] = 55;
  uc.uc_mcontext.gregs[REG_R9] = 66;
  uc.uc_mcontext.gregs[REG_RIP] = 0x7011;

  struct stackable_linux_syscall_regs regs;
  int rc = stackable_linux_capture_syscall_regs_from_ucontext(&uc, &regs);
  if (rc != 0) return -1;
  if (regs.nr != 39 || regs.args[0] != 11 || regs.args[1] != 22 ||
      regs.args[2] != 33 || regs.args[3] != 44 || regs.args[4] != 55 ||
      regs.args[5] != 66) return -2;
  if (regs.trap_rip != 0x7011UL || regs.syscall_address != 0x7010UL ||
      regs.resume_rip != 0x7012UL) return -3;

  rc = stackable_linux_write_syscall_result_to_ucontext(
      &uc, 1234, regs.resume_rip);
  if (rc != 0) return -4;
  if (uc.uc_mcontext.gregs[REG_RAX] != 1234) return -5;
  if ((unsigned long)uc.uc_mcontext.gregs[REG_RIP] != 0x7012UL) return -6;

  if (stackable_linux_capture_syscall_regs_from_ucontext(NULL, &regs) != 3) {
    return -7;
  }
  return 0;
}

long stackable_test_replay_getpid(void) {
  struct stackable_linux_syscall_regs regs;
  memset(&regs, 0, sizeof(regs));
  regs.nr = 39;
  return stackable_linux_replay_syscall_regs(&regs);
}

int stackable_test_sigtrap_install_uninstall_smoke(void) {
  int rc = stackable_linux_install_sigtrap_handler(
      (void *)&stackable_test_sigtrap_handler, 0);
  if (rc != 0) return -1;
  rc = stackable_linux_install_sigtrap_handler(
      (void *)&stackable_test_sigtrap_handler, 0);
  if (rc != 5) {
    (void)stackable_linux_uninstall_sigtrap_handler();
    return -4;
  }
  rc = stackable_linux_chain_sigtrap(SIGTRAP, NULL, NULL);
  if (rc != 16) {
    (void)stackable_linux_uninstall_sigtrap_handler();
    return -2;
  }
  rc = stackable_linux_uninstall_sigtrap_handler();
  if (rc != 0) return -3;
  return 0;
}

long stackable_test_live_int3_getpid_continuation(void) {
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  unsigned char *p = (unsigned char *)mmap(NULL, (size_t)page_size,
      PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return -1001;

  unsigned char code[8] = {
    0xb8, 0x27, 0x00, 0x00, 0x00, /* mov $39,%eax */
    0x0f, 0x05,                   /* syscall */
    0xc3                          /* ret */
  };
  memcpy(p, code, sizeof(code));

  stackable_live_int3_site = p + 5;
  stackable_live_int3_hits = 0;
  stackable_live_int3_failures = 0;

  struct stackable_linux_int3_patch_result tx;
  int rc = stackable_linux_patch_int3_syscall_tx(stackable_live_int3_site, &tx);
  if (rc != 0 || tx.patch_live == 0 || tx.restore_captured == 0) {
    (void)munmap(p, (size_t)page_size);
    return -1002;
  }

  rc = stackable_linux_install_sigtrap_handler(
      (void *)&stackable_live_int3_handler, 0);
  if (rc != 0) {
    int ignored_errno = 0;
    (void)stackable_linux_restore_int3_syscall(
        stackable_live_int3_site, tx.original_first_byte, &ignored_errno);
    (void)munmap(p, (size_t)page_size);
    return -1003;
  }

  typedef long (*stackable_getpid_fn)(void);
  long got = ((stackable_getpid_fn)(void *)p)();
  long expected = (long)getpid();

  int ignored_errno = 0;
  int restore_rc = stackable_linux_restore_int3_syscall(
      stackable_live_int3_site, tx.original_first_byte, &ignored_errno);
  int uninstall_rc = stackable_linux_uninstall_sigtrap_handler();
  (void)munmap(p, (size_t)page_size);

  if (restore_rc != 0) return -1004;
  if (uninstall_rc != 0) return -1005;
  if (stackable_live_int3_failures != 0) return -1006;
  if (stackable_live_int3_hits != 1) return -1007;
  if (got != expected) return -1008;
  return got;
}
