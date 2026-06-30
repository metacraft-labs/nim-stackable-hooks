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

struct stackable_linux_clone_continuation {
  int clone_like;
  long nr;
  unsigned long syscall_address;
  unsigned long trap_rip;
  unsigned long resume_rip;
  long parent_result;
  unsigned long parent_resume_rip;
  long child_result;
  unsigned long child_resume_rip;
};

struct stackable_linux_vdso_image {
  int diagnostic;
  int os_errno;
  unsigned long base;
  unsigned long length;
  unsigned long load_max_address;
  unsigned long dynamic_address;
  unsigned long symbol_table;
  unsigned long string_table;
  unsigned long symbol_entry_size;
  unsigned long symbol_count;
  unsigned long string_table_size;
};

struct stackable_linux_vdso_symbol {
  int diagnostic;
  unsigned long address;
  unsigned long size;
  unsigned char info;
  unsigned char other;
  unsigned short section_index;
};

struct stackable_linux_vdso_patch_result {
  int diagnostic;
  int path;
  int direct_diagnostic;
  int overlay_diagnostic;
  int os_errno;
  int patch_live;
  int overlay_used;
  unsigned long image_base;
  unsigned long image_length;
  unsigned long symbol_address;
  unsigned long replacement;
  struct stackable_linux_patch_result direct;
};

struct stackable_linux_atomic_window {
  int diagnostic;
  int kind;
  unsigned long length;
  int lock_prefixed;
  int memory_operand;
  long modrm_offset;
  long opcode_offset;
  unsigned char opcode0;
  unsigned char opcode1;
};

struct stackable_linux_atomic_patch_decision {
  int diagnostic;
  int strategy;
  unsigned long target;
  unsigned long trampoline;
  unsigned long instruction_length;
  unsigned long patch_size;
  long long rel32_displacement;
};

struct stackable_linux_near_allocation {
  int diagnostic;
  int os_errno;
  unsigned long anchor;
  unsigned long address;
  unsigned long length;
  int within_rel32;
};

extern long stackable_linux_static_raw_syscall6(
    long nr, long a1, long a2, long a3, long a4, long a5, long a6);
extern void stackable_linux_rt_sigreturn_restorer(void);
extern long stackable_linux_clone_continuation_trampoline(
    long nr, long a0, long a1, long a2, long a3, long a4, long a5,
    void *resume_rip, long *user_gregs);
extern int stackable_linux_is_default_clone_continuation_syscall(long nr);
extern int stackable_linux_compute_clone_continuation(
    struct stackable_linux_syscall_regs *regs, long parent_result,
    int clone_like, struct stackable_linux_clone_continuation *out);
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
extern int stackable_linux_patch_int3_syscall_tx_fixed_page(
    void *target, unsigned long page_size,
    struct stackable_linux_int3_patch_result *out);
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
extern int stackable_linux_locate_vdso_image(
    struct stackable_linux_vdso_image *out);
extern int stackable_linux_parse_vdso_image_at(
    unsigned long base, struct stackable_linux_vdso_image *out);
extern int stackable_linux_resolve_vdso_symbol(
    struct stackable_linux_vdso_image *image, char *name,
    struct stackable_linux_vdso_symbol *out);
extern int stackable_linux_vdso_overlay_patch_tx(
    unsigned long image_base, unsigned long image_len,
    void *target, void *replacement,
    struct stackable_linux_vdso_patch_result *out);
extern int stackable_linux_vdso_patch_symbol_tx(
    struct stackable_linux_vdso_image *image, char *name,
    void *replacement, int allow_overlay,
    struct stackable_linux_vdso_patch_result *out);
extern int stackable_linux_classify_atomic_window(
    unsigned char *bytes, unsigned long len,
    struct stackable_linux_atomic_window *out);
extern int stackable_linux_select_atomic_patch_strategy(
    unsigned long target, unsigned long trampoline, unsigned long instruction_len,
    struct stackable_linux_atomic_patch_decision *out);
extern int stackable_linux_allocate_near_trampoline(
    unsigned long anchor, unsigned long length,
    struct stackable_linux_near_allocation *out);
extern int stackable_linux_free_near_trampoline(
    unsigned long address, unsigned long length);

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
  struct stackable_linux_clone_continuation continuation;
  struct stackable_linux_syscall_regs regs;
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
  if (stackable_linux_static_raw_syscall6(39, 0, 0, 0, 0, 0, 0) <= 0) return -10;
  if ((void *)&stackable_linux_rt_sigreturn_restorer == NULL) return -11;
  if ((void *)&stackable_linux_clone_continuation_trampoline == NULL) return -12;
  if (stackable_linux_clone_continuation_trampoline(
      39, 0, 0, 0, 0, 0, 0, NULL, NULL) <= 0) return -18;
  if (stackable_linux_is_default_clone_continuation_syscall(56) != 1) return -13;
  if (stackable_linux_is_default_clone_continuation_syscall(39) != 0) return -14;
  memset(&regs, 0, sizeof(regs));
  regs.nr = 56;
  regs.trap_rip = 0x5011UL;
  regs.syscall_address = 0x5010UL;
  regs.resume_rip = 0x5012UL;
  rc = stackable_linux_compute_clone_continuation(
      &regs, 777, 1, &continuation);
  if (rc != 0 || continuation.clone_like != 1 || continuation.nr != 56) return -15;
  if (continuation.parent_result != 777 || continuation.child_result != 0) return -16;
  if (continuation.parent_resume_rip != 0x5012UL ||
      continuation.child_resume_rip != 0x5012UL) return -17;
  struct stackable_linux_vdso_image image;
  struct stackable_linux_vdso_symbol sym;
  struct stackable_linux_vdso_patch_result vdso_patch;
  rc = stackable_linux_parse_vdso_image_at(0, &image);
  if (rc != 17 || image.diagnostic != 17) return -19;
  rc = stackable_linux_resolve_vdso_symbol(NULL, "__vdso_missing", &sym);
  if (rc != 3 || sym.diagnostic != 3) return -20;
  rc = stackable_linux_vdso_overlay_patch_tx(
      0, 0, NULL, (void *)&stackable_c_fixture_function, &vdso_patch);
  if (rc != 3 || vdso_patch.diagnostic != 3) return -21;
  rc = stackable_linux_vdso_patch_symbol_tx(
      NULL, "__vdso_missing", (void *)&stackable_c_fixture_function, 0,
      &vdso_patch);
  if (rc != 3 || vdso_patch.diagnostic != 3) return -22;

  unsigned char lock_add[4] = {0xf0, 0x01, 0x18, 0x90};
  struct stackable_linux_atomic_window atomic;
  rc = stackable_linux_classify_atomic_window(lock_add, sizeof(lock_add), &atomic);
  if (rc != 0 || atomic.kind != 1 || atomic.length != 3 ||
      atomic.lock_prefixed != 1 || atomic.memory_operand != 1) return -23;
  unsigned char mfence[3] = {0x0f, 0xae, 0xf0};
  rc = stackable_linux_classify_atomic_window(mfence, sizeof(mfence), &atomic);
  if (rc != 0 || atomic.kind != 3 || atomic.length != 3) return -24;

  struct stackable_linux_atomic_patch_decision decision;
  rc = stackable_linux_select_atomic_patch_strategy(
      0x10000000UL, 0x10001000UL, 5, &decision);
  if (rc != 0 || decision.strategy != 1 || decision.patch_size != 5) return -25;
  rc = stackable_linux_select_atomic_patch_strategy(
      0x10000000UL, 0x9000000000UL, 5, &decision);
  if (rc != 0 || decision.strategy != 2 || decision.patch_size != 1) return -26;

  struct stackable_linux_near_allocation near_alloc;
  rc = stackable_linux_allocate_near_trampoline(
      (unsigned long)(uintptr_t)&stackable_c_fixture_function, 64, &near_alloc);
  if (rc == 0) {
    if (near_alloc.address == 0 || near_alloc.length < 64 ||
        near_alloc.within_rel32 != 1) return -27;
    ((unsigned char *)(uintptr_t)near_alloc.address)[0] = 0xc3;
    if (((unsigned char *)(uintptr_t)near_alloc.address)[0] != 0xc3) return -28;
    if (stackable_linux_free_near_trampoline(
            near_alloc.address, near_alloc.length) != 0) return -30;
  } else if (rc != 12) {
    return -29;
  }
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

int stackable_test_fixed_page_int3_patch_smoke(void) {
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  unsigned char *p = (unsigned char *)mmap(NULL, (size_t)page_size,
      PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return -1;

  unsigned char code[3] = {0x0f, 0x05, 0xc3};
  memcpy(p, code, sizeof(code));

  struct stackable_linux_int3_patch_result tx;
  int rc = stackable_linux_patch_int3_syscall_tx_fixed_page(
      p, (unsigned long)page_size, &tx);
  if (rc != 0 || tx.patch_live == 0 || tx.restore_captured == 0 ||
      p[0] != 0xcc || p[1] != 0x05) {
    (void)munmap(p, (size_t)page_size);
    return -2;
  }

  int ignored_errno = 0;
  rc = stackable_linux_restore_int3_syscall(
      p, tx.original_first_byte, &ignored_errno);
  if (rc != 0 || p[0] != 0x0f || p[1] != 0x05) {
    (void)munmap(p, (size_t)page_size);
    return -3;
  }

  (void)munmap(p, (size_t)page_size);
  return 0;
}
