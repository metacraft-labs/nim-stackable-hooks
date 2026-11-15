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
## The test makes two checks.
##
## 1. The static check, which always runs. For each entry it finds the
##    entry's `syscall` (`0f 05`) and requires the next instruction to be
##    `ret` (`c3`), so that nothing runs, and nothing touches memory, between
##    the two. A positive control applies the same reader to a C copy of the
##    old entry, compiled at -O0 in this file, and requires the opposite: the
##    old body's store of its result to its frame (`mov %rax,disp8(%rbp)`).
##    So a reader that can no longer see the hazard fails instead of passing.
##
##    The bytes are read from the test's executable FILE, not from memory.
##    The property belongs to the code the compiler and assembler produced,
##    and memory need not hold that code: `repro test` runs every test under
##    a syscall monitor, and that monitor rewrites each `syscall` instruction
##    it finds in a loaded image into a trap and emulates the call from its
##    signal handler. The file is mapped MAP_PRIVATE, so the rewrite never
##    reaches it. Each entry is located through the line of
##    `/proc/self/maps` whose range holds the entry's address: the file
##    offset is that line's offset plus the entry's distance from the start
##    of the range (proc(5)). That reads exactly the bytes the call jumps to,
##    needs no symbol table (the test binary may be stripped, and the
##    positive control is a `static` function), and needs no ELF parser.
##    The line must name the same inode as `/proc/self/exe`, which is the
##    file the bytes are then read from.
##
## 2. The behavioural check, which runs only when the code in memory is the
##    code in the file. It clones through each entry with
##    CLONE_VM|CLONE_VFORK, so the creator is suspended until the child
##    exits. The child runs the entry's whole post-syscall path, then copies
##    the creator's stack region the entry's frame occupies while the
##    creator cannot yet have overwritten it. That region was painted with a
##    canary first, so any word the child stored there shows up as a 0 (the
##    child's return value). No timing, no retries. The positive control
##    must see the old body's store here too.
##
##    Under the monitor this check does not apply: the instruction after the
##    clone is the monitor's trap, so the child continues in the monitor's
##    handler instead of the entry. The handler's own frame lands in the
##    painted region, and a vfork child that leaves through a rewritten
##    syscall while its creator is suspended is a known limit of the monitor
##    (it is killed by SIGTRAP), not a property of the entry. The signal used
##    is therefore the difference itself: the behavioural check runs when the
##    bytes of every entry, up to the instruction after its `syscall`, are
##    the same in memory as in the file, and otherwise prints why it did not
##    run and is reported as skipped. The static check carries the assertion
##    in either case.
##
## Real kernel, real clone, the test's own executable; no mocks. x86-64 Linux
## only: elsewhere the file compiles to a static assertion, as its siblings
## do. The ARM and AArch64 entries were checked by cross disassembly.

when defined(linux) and defined(amd64):
  import std/[os, unittest]
  import stackable_hooks/platform/linux_raw_syscalls

  {.passC: "-O0".}

  {.emit: """
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__OPTIMIZE__)
#error "test_linux_raw_syscall_clone_vm must be compiled at -O0 (see its header)"
#endif

extern long stackable_linux_raw_syscall6(long, long, long, long, long, long,
                                         long);
extern long stackable_linux_static_raw_syscall6(long, long, long, long, long,
                                                long, long);

/* The entry as it was before it became hand-written assembly. Kept only as
 * the positive control: both checks must see this body's post-syscall
 * store. */
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

/* The entries, by the index the Nim side passes: 0 the raw entry, 1 the
 * static entry, 2 the positive control. */
static shk_test_entry_fn shk_test_entry(int which) {
  switch (which) {
  case 0: return stackable_linux_raw_syscall6;
  case 1: return stackable_linux_static_raw_syscall6;
  case 2: return shk_test_legacy_c_raw_syscall6;
  default: return NULL;
  }
}

/* ---- Reading an entry's bytes from the executable file. ---- */

/* How far from an entry's start its 'syscall' is looked for. The
 * hand-written entry is 34 bytes; the old body at -O0 is under 100 with its
 * 'syscall' well inside the first 64. */
#define SHK_TEST_SCAN_BYTES 64
/* The bytes after the 'syscall' the checks look at: one instruction. */
#define SHK_TEST_AFTER_BYTES 4

/* Copies 'n' bytes of the executable file, from the place the code at 'fn'
 * was mapped from, into 'out'. Returns 0, or a negative code: -1 maps or the
 * executable could not be opened, -2 no line of /proc/self/maps holds 'fn'
 * through 'fn + n' as an executable mapping of the executable's inode, -3
 * the file could not be read there. */
static int shk_test_read_from_exe(const void *fn, unsigned char *out,
                                  size_t n) {
  uintptr_t want = (uintptr_t)fn;
  int exe = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  if (exe < 0) return -1;
  struct stat st;
  if (fstat(exe, &st) != 0) { close(exe); return -1; }
  FILE *maps = fopen("/proc/self/maps", "re");
  if (maps == NULL) { close(exe); return -1; }
  /* proc(5): "address perms offset dev inode pathname". */
  char line[4096];
  int rc = -2;
  while (fgets(line, sizeof line, maps) != NULL) {
    unsigned long start = 0, end = 0, offset = 0, inode = 0;
    char perms[8] = {0};
    if (sscanf(line, "%lx-%lx %7s %lx %*s %lu", &start, &end, perms, &offset,
               &inode) != 5)
      continue;
    if (want < start || want >= end) continue;
    if (want + n > end || perms[2] != 'x' || inode != (unsigned long)st.st_ino)
      break;
    ssize_t got = pread(exe, out, n, (off_t)(offset + (want - start)));
    rc = (got == (ssize_t)n) ? 0 : -3;
    break;
  }
  fclose(maps);
  close(exe);
  return rc;
}

/* Index of the first 'syscall' (0f 05) in 'p', or -1. */
static int shk_test_find_syscall(const unsigned char *p) {
  for (int i = 0; i + 1 < SHK_TEST_SCAN_BYTES; i++)
    if (p[i] == 0x0f && p[i + 1] == 0x05) return i;
  return -1;
}

/* Copies the SHK_TEST_AFTER_BYTES bytes that follow entry 'which''s
 * 'syscall', as the executable file holds them, into 'out'. Returns 0, a
 * code of shk_test_read_from_exe, -4 when no 'syscall' is in the scanned
 * bytes, or -5 for an unknown entry. */
int shk_test_file_bytes_after_syscall(int which, unsigned char *out) {
  shk_test_entry_fn fn = shk_test_entry(which);
  if (fn == NULL) return -5;
  unsigned char code[SHK_TEST_SCAN_BYTES + SHK_TEST_AFTER_BYTES];
  int rc = shk_test_read_from_exe((const void *)fn, code, sizeof code);
  if (rc != 0) return rc;
  int at = shk_test_find_syscall(code);
  if (at < 0) return -4;
  memcpy(out, code + at + 2, SHK_TEST_AFTER_BYTES);
  return 0;
}

/* 1 when the bytes of entry 'which' in memory, from its start through the
 * instruction after its 'syscall', are those the executable file holds; 0
 * when they differ (something rewrote the code at run time); or a negative
 * code of shk_test_file_bytes_after_syscall. Only the entry's own bytes are
 * compared: a rewritten 'syscall' in a neighbouring function is not this
 * entry's business. */
int shk_test_entry_runs_as_built(int which) {
  shk_test_entry_fn fn = shk_test_entry(which);
  if (fn == NULL) return -5;
  unsigned char code[SHK_TEST_SCAN_BYTES + SHK_TEST_AFTER_BYTES];
  int rc = shk_test_read_from_exe((const void *)fn, code, sizeof code);
  if (rc != 0) return rc;
  int at = shk_test_find_syscall(code);
  if (at < 0) return -4;
  return memcmp((const void *)fn, code, (size_t)at + 2 + SHK_TEST_AFTER_BYTES)
             == 0;
}

/* ---- The behavioural CLONE_VM probe. ---- */

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

/* Returns the number of words of the creator's stack the child zeroed when
 * it cloned through entry 'which', or a negative code: -1 the clone failed,
 * -2 the child never reached its entry, -3 waitpid failed or the child did
 * not exit with status 0, -5 an unknown entry. */
long shk_test_creator_words_zeroed_by_child(int which) {
  shk_test_entry_fn entry = shk_test_entry(which);
  if (entry == NULL) return -5;
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
""".}

  type Entry = enum
    ## The order is the C side's `shk_test_entry` index.
    eRaw = "stackable_linux_raw_syscall6"
    eStatic = "stackable_linux_static_raw_syscall6"
    eLegacyC = "the old C entry (positive control)"

  proc fileBytesAfterSyscall(which: cint; output: ptr array[4, uint8]): cint
    {.importc: "shk_test_file_bytes_after_syscall", cdecl.}
  proc entryRunsAsBuilt(which: cint): cint
    {.importc: "shk_test_entry_runs_as_built", cdecl.}
  proc creatorWordsZeroedByChild(which: cint): clong
    {.importc: "shk_test_creator_words_zeroed_by_child", cdecl.}

  proc afterSyscall(entry: Entry; bytes: var array[4, uint8]): cint =
    ## Reads the instruction bytes that follow `entry`'s `syscall` in the
    ## executable file into `bytes`; 0, or the C side's negative code (and
    ## `bytes` stays zero, which no check below accepts).
    fileBytesAfterSyscall(cint(ord(entry)), addr bytes)

  proc behaviourNotApplicableReason(): string =
    ## Empty when every entry's code in memory is the code in the file, so
    ## the behavioural check exercises the entries as built. Otherwise why it
    ## does not. A read failure is not a reason: it fails the static check.
    for entry in Entry:
      if entryRunsAsBuilt(cint(ord(entry))) == 0:
        return $entry & " differs in memory from the executable file, so " &
          "its syscall instruction was rewritten at run time (a syscall " &
          "monitor is active; LD_PRELOAD=" & getEnv("LD_PRELOAD") & "). A " &
          "clone through it continues in the monitor's handler, not in the " &
          "entry, so the clone would test the monitor."
    ""

  const Rounds = 200
    ## The probe is deterministic; the rounds only show that it stays so.

  suite "the raw syscall entries as built return straight after `syscall`":
    test "positive control: the old C entry stores to its frame after `syscall`":
      # `mov %rax, disp8(%rbp)`: REX.W, opcode 89 (store r64), ModRM with
      # mod 01 and r/m 101 (rbp + disp8), reg 000 (rax).
      var after: array[4, uint8]
      check afterSyscall(eLegacyC, after) == 0
      check after[0] == 0x48
      check after[1] == 0x89
      check after[2] == 0x45

    test "rawSyscall6's next instruction after `syscall` is `ret`":
      var after: array[4, uint8]
      check afterSyscall(eRaw, after) == 0
      check after[0] == 0xc3

    test "staticRawSyscall6's next instruction after `syscall` is `ret`":
      var after: array[4, uint8]
      check afterSyscall(eStatic, after) == 0
      check after[0] == 0xc3

    test "every entry's code can be compared with the executable file":
      for entry in Entry:
        check entryRunsAsBuilt(cint(ord(entry))) in [0.cint, 1.cint]

  let notApplicable = behaviourNotApplicableReason()
  if notApplicable.len > 0:
    echo "[test_linux_raw_syscall_clone_vm] the CLONE_VM behavioural check " &
      "does not apply here: " & notApplicable & " The static check " &
      "above carries the assertion."

  suite "a CLONE_VM child does not write into its creator's stack":
    setup:
      if notApplicable.len > 0:
        skip()

    test "positive control: the probe sees a C entry's post-syscall store":
      if notApplicable.len == 0:
        for _ in 0 ..< Rounds:
          check creatorWordsZeroedByChild(cint(ord(eLegacyC))) >= 1

    test "rawSyscall6 leaves the creator's stack untouched":
      if notApplicable.len == 0:
        for _ in 0 ..< Rounds:
          check creatorWordsZeroedByChild(cint(ord(eRaw))) == 0

    test "staticRawSyscall6 leaves the creator's stack untouched":
      if notApplicable.len == 0:
        for _ in 0 ..< Rounds:
          check creatorWordsZeroedByChild(cint(ord(eStatic))) == 0

  suite "the Nim wrappers":
    test "still forward an ordinary syscall":
      # getpid(2) through both bindings: the entry is the kernel ABI, unchanged.
      const SysGetpid = 39
      check rawSyscall6(SysGetpid, 0, 0, 0, 0, 0, 0) > 0
      check staticRawSyscall6(SysGetpid, 0, 0, 0, 0, 0, 0) ==
        rawSyscall6(SysGetpid, 0, 0, 0, 0, 0, 0)
else:
  static:
    doAssert not (defined(linux) and defined(amd64))
