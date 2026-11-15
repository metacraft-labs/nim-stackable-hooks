## A CLONE_VM child created through `rawSyscall6` must not write into its
## creator's stack.
##
## The kernel starts a clone child with a new stack at the instruction after
## the system call, with the child's stack pointer but every other register --
## the frame pointer included -- still the creator's. So whatever the raw
## syscall entry does between `syscall` and its return runs twice in one
## address space, once with the creator's frame. A C body compiled without
## optimisation keeps its result in a frame slot (`mov %rax,-8(%rbp)`), and
## the child's store of its 0 lands in the CREATOR's stack. In a real process
## that slot is soon a return address of a later call, and the creator jumps
## to address 0. The entry is therefore one hand-written function in which
## nothing touches memory between `syscall` and `ret`.
##
## The failure depends on the optimisation level of the module that defines
## the entry (an optimised C body needed no frame), so this test forces -O0
## for every C file of its build, the library's included. A build that is
## optimised anyway is caught by the `__OPTIMIZE__` check below rather than
## passing vacuously.
##
## Determinism: the clone uses CLONE_VFORK as well as CLONE_VM, so the creator
## is suspended until the child exits. The child runs the entry's whole
## post-syscall path, then copies the creator's stack region the entry's frame
## occupies while the creator cannot yet have overwritten it. That region was
## painted with a canary first, so any word the child stored there shows up
## as a 0 (the child's return value). No timing, no retries.
##
## A positive control runs the same probe through a C copy of the old entry
## and requires the probe to see that store, so a probe that can no longer see
## the hazard fails instead of passing.
##
## Real kernel, real clone; no mocks. x86-64 Linux only: elsewhere the file
## compiles to a static assertion, as its siblings do.

when defined(linux) and defined(amd64):
  import std/unittest
  import stackable_hooks/platform/linux_raw_syscalls

  {.passC: "-O0".}

  {.emit: """
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#if defined(__OPTIMIZE__)
#error "test_linux_raw_syscall_clone_vm must be compiled at -O0 (see its header)"
#endif

extern long stackable_linux_raw_syscall6(long, long, long, long, long, long,
                                         long);
extern long stackable_linux_static_raw_syscall6(long, long, long, long, long,
                                                long, long);

/* The entry as it was before it became hand-written assembly. Kept only as
 * the positive control: the probe must see this body's post-syscall store. */
__attribute__((noinline, optimize("O0")))
static long shk_test_legacy_c_raw_syscall6(long nr, long a1, long a2, long a3,
                                           long a4, long a5, long a6) {
  long ret;
  register long r10 __asm__("r10") = a4;
  register long r8  __asm__("r8")  = a5;
  register long r9  __asm__("r9")  = a6;
  __asm__ volatile ("syscall"
                    : "=a"(ret)
                    : "0"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8),
                      "r"(r9)
                    : "rcx", "r11", "memory");
  return ret;
}

typedef long (*shk_test_entry_fn)(long, long, long, long, long, long, long);

#define SHK_TEST_CANARY 0x5afe5afe5afe5afeUL
#define SHK_TEST_PAINT_WORDS 256
#define SHK_TEST_STACK_SLOTS 64

static volatile unsigned long *shk_test_paint_lo;
static unsigned long shk_test_snapshot[SHK_TEST_PAINT_WORDS];
static volatile int shk_test_child_ran;
static char shk_test_child_stack[64 * 1024] __attribute__((aligned(16)));

/* Where the child's 'ret' lands: the top of its new stack holds this
 * address in every slot, so it is reached however many words the entry pops
 * first. The creator is suspended (CLONE_VFORK) and the region below its
 * stack pointer still holds what the entry's frame left there. */
__attribute__((noreturn, force_align_arg_pointer, noinline))
static void shk_test_child_entry(void) {
  for (int i = 0; i < SHK_TEST_PAINT_WORDS; i++)
    shk_test_snapshot[i] = shk_test_paint_lo[i];
  shk_test_child_ran = 1;
  stackable_linux_raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
  for (;;) {}
}

/* Paint the stack just below the caller's stack pointer, where the entry's
 * frame will be placed by the call that follows. */
__attribute__((noinline))
static void shk_test_paint_below(void) {
  volatile unsigned long region[SHK_TEST_PAINT_WORDS];
  for (int i = 0; i < SHK_TEST_PAINT_WORDS; i++) region[i] = SHK_TEST_CANARY;
  shk_test_paint_lo = region;
}

__attribute__((noinline))
static long shk_test_clone_through(shk_test_entry_fn entry) {
  void **top = (void **)(shk_test_child_stack + sizeof(shk_test_child_stack));
  void **sp = top - SHK_TEST_STACK_SLOTS;
  for (int i = 0; i < SHK_TEST_STACK_SLOTS; i++)
    sp[i] = (void *)shk_test_child_entry;
  shk_test_child_ran = 0;
  /* clone(2) on x86-64: flags, stack, parent_tid, child_tid, tls. The kernel
   * reads the last three only under CLONE_PARENT_SETTID, CLONE_CHILD_*TID
   * and CLONE_SETTLS, none of which is set, so they carry non-zero filler:
   * an entry that spills its arguments then leaves no 0 of its own. */
  shk_test_paint_below();
  return entry(SYS_clone, CLONE_VM | CLONE_VFORK | SIGCHLD, (long)sp,
               0x1111, 0x2222, 0x3333, 0x4444);
}

/* Returns the number of words of the creator's stack the child zeroed, or a
 * negative code: -1 the clone failed, -2 the child never reached its entry,
 * -3 waitpid failed or the child did not exit with status 0. */
static long shk_test_creator_words_zeroed_by_child(shk_test_entry_fn entry) {
  long pid = shk_test_clone_through(entry);
  if (pid <= 0) return -1;
  int status = 0;
  if (waitpid((pid_t)pid, &status, 0) != (pid_t)pid) return -3;
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return -3;
  if (!shk_test_child_ran) return -2;
  long zeroed = 0;
  for (int i = 0; i < SHK_TEST_PAINT_WORDS; i++)
    if (shk_test_snapshot[i] == 0) zeroed++;
  return zeroed;
}

long shk_test_zeroed_via_raw(void) {
  return shk_test_creator_words_zeroed_by_child(stackable_linux_raw_syscall6);
}
long shk_test_zeroed_via_static(void) {
  return shk_test_creator_words_zeroed_by_child(
      stackable_linux_static_raw_syscall6);
}
long shk_test_zeroed_via_legacy_c(void) {
  return shk_test_creator_words_zeroed_by_child(shk_test_legacy_c_raw_syscall6);
}

/* Bytes from the entry's 'syscall' (0f 05) to the next byte: 0xc3 ('ret') iff
 * nothing runs between them. -1 when no 'syscall' is found in the first 64
 * bytes. */
static int shk_test_byte_after_syscall(const unsigned char *p) {
  for (int i = 0; i + 2 < 64; i++)
    if (p[i] == 0x0f && p[i + 1] == 0x05) return p[i + 2];
  return -1;
}
int shk_test_raw_byte_after_syscall(void) {
  return shk_test_byte_after_syscall(
      (const unsigned char *)stackable_linux_raw_syscall6);
}
int shk_test_static_byte_after_syscall(void) {
  return shk_test_byte_after_syscall(
      (const unsigned char *)stackable_linux_static_raw_syscall6);
}
""".}

  proc zeroedViaRaw(): clong {.importc: "shk_test_zeroed_via_raw", cdecl.}
  proc zeroedViaStatic(): clong {.importc: "shk_test_zeroed_via_static", cdecl.}
  proc zeroedViaLegacyC(): clong {.importc: "shk_test_zeroed_via_legacy_c", cdecl.}
  proc rawByteAfterSyscall(): cint {.importc: "shk_test_raw_byte_after_syscall", cdecl.}
  proc staticByteAfterSyscall(): cint {.importc: "shk_test_static_byte_after_syscall", cdecl.}

  const Rounds = 200
    ## The probe is deterministic; the rounds only show that it stays so.

  suite "a CLONE_VM child does not write into its creator's stack":
    test "positive control: the probe sees a C entry's post-syscall store":
      for _ in 0 ..< Rounds:
        check zeroedViaLegacyC() >= 1

    test "rawSyscall6 leaves the creator's stack untouched":
      for _ in 0 ..< Rounds:
        check zeroedViaRaw() == 0

    test "staticRawSyscall6 leaves the creator's stack untouched":
      for _ in 0 ..< Rounds:
        check zeroedViaStatic() == 0

    test "both entries return straight after the syscall instruction":
      check rawByteAfterSyscall() == 0xc3
      check staticByteAfterSyscall() == 0xc3

    test "the Nim wrappers still forward an ordinary syscall":
      # getpid(2) through both bindings: the entry is the kernel ABI, unchanged.
      const SysGetpid = 39
      check rawSyscall6(SysGetpid, 0, 0, 0, 0, 0, 0) > 0
      check staticRawSyscall6(SysGetpid, 0, 0, 0, 0, 0, 0) ==
        rawSyscall6(SysGetpid, 0, 0, 0, 0, 0, 0)
else:
  static:
    doAssert not (defined(linux) and defined(amd64))
