## Linux raw-syscall helper primitives.
##
## This module contains reusable, non-opinionated pieces extracted from the
## MCR monkey-patching design:
##
## - raw syscall forwarding for framework internals;
## - x86_64 absolute-jump body patching for explicit wrapper addresses;
## - conservative x86_64 original-call trampoline construction for wrapper
##   prologues that can be copied without relocation;
## - byte and mapping scanners for Linux x86_64 `syscall` (`0f 05`) sites.
##
## It deliberately does not know about MCR events, replay, io-mon records,
## stage0 installation, clone attribution, or consumer lifecycle policy.

import std/strutils

type
  LinuxRawSyscallDiagnostic* = enum
    lrsOk = "ok"
    lrsUnsupportedPlatform = "unsupported-platform"
    lrsUnsupportedArchitecture = "unsupported-architecture"
    lrsInvalidArgument = "invalid-argument"
    lrsSymbolNotFound = "symbol-not-found"
    lrsAlreadyPatched = "already-patched"
    lrsMprotectFailed = "mprotect-failed"
    lrsPrePatchMprotectFailed = "pre-patch-mprotect-failed"
    lrsPatchWriteFailed = "patch-write-failed"
    lrsPostPatchMprotectBackFailed = "post-patch-mprotect-back-failed"
    lrsRestoreFailed = "restore-failed"
    lrsUnsupportedInstruction = "unsupported-instruction"
    lrsTrampolineAllocFailed = "trampoline-alloc-failed"
    lrsTrampolineBuildFailed = "trampoline-build-failed"
    lrsNotSyscallSite = "not-syscall-site"
    lrsTrapInstallFailed = "trap-install-failed"
    lrsTrapChainUnavailable = "trap-chain-unavailable"
    lrsVdsoNotFound = "vdso-not-found"
    lrsVdsoNotElf = "vdso-not-elf"
    lrsVdsoNoDynamic = "vdso-no-dynamic"
    lrsVdsoNoSymbolTable = "vdso-no-symbol-table"
    lrsVdsoSymbolNotFound = "vdso-symbol-not-found"
    lrsVdsoDirectPatchFailed = "vdso-direct-patch-failed"
    lrsVdsoOverlayFailed = "vdso-overlay-failed"

  LinuxPatchStage* = enum
    lpsNone = "none"
    lpsValidateTarget = "validate-target"
    lpsPrePatchMprotect = "pre-patch-mprotect"
    lpsWritePatch = "write-patch"
    lpsPostPatchMprotectBack = "post-patch-mprotect-back"
    lpsComplete = "complete"

  LinuxPatchHandle* = object
    ## Opaque-enough patch record for consumers that need diagnostics or later
    ## restore. `originalBytes` stores the overwritten 14-byte x86_64 absolute
    ## jump window. This is not an original-call trampoline; consumers that need
    ## forwarding should use `buildOriginalCallTrampoline` before patching.
    target*: pointer
    replacement*: pointer
    patchSize*: int
    originalBytes*: array[14, byte]
    active*: bool
    diagnostic*: LinuxRawSyscallDiagnostic
    osErrno*: cint

  LinuxPatchTransaction* = object
    ## Stage-aware patch result for consumers that need to distinguish fatal
    ## pre-patch failures from post-patch hardening failures after the jump is
    ## already live. This carries no lifecycle or policy decisions.
    handle*: LinuxPatchHandle
    stage*: LinuxPatchStage
    diagnostic*: LinuxRawSyscallDiagnostic
    osErrno*: cint
    patchLive*: bool
    restoreBytesCaptured*: bool

  LinuxOriginalTrampoline* = object
    ## Restore-free original-call trampoline for a body-patched Linux x86_64
    ## wrapper. The trampoline contains an instruction-aware copy of the first
    ## `copiedLen` bytes from `target`, followed by the same 14-byte absolute
    ## jump form back to `target + copiedLen`.
    target*: pointer
    entry*: pointer
    copiedLen*: int
    minPatchLen*: int
    diagnostic*: LinuxRawSyscallDiagnostic
    osErrno*: cint
    unsupportedOffset*: int

  LinuxInt3Callsite* = object
    ## One raw `0f 05` callsite selected by a consumer for INT3 handling.
    ## `address` points at byte 0 of the syscall instruction, not the saved
    ## SIGTRAP RIP. Consumers own mapping/self-exclusion policy.
    address*: uint
    originalFirstByte*: byte
    patched*: bool

  LinuxInt3CallsiteTable* = object
    ## Sorted table for signal-handler lookup. INT3 reports saved RIP as
    ## `callsite + 1`, so use `findLinuxInt3CallsiteForTrapRip` in handlers.
    sites*: seq[LinuxInt3Callsite]

  LinuxInt3PatchHandle* = object
    target*: pointer
    originalFirstByte*: byte
    secondByte*: byte
    active*: bool
    diagnostic*: LinuxRawSyscallDiagnostic
    osErrno*: cint

  LinuxInt3PatchTransaction* = object
    handle*: LinuxInt3PatchHandle
    stage*: LinuxPatchStage
    diagnostic*: LinuxRawSyscallDiagnostic
    osErrno*: cint
    patchLive*: bool
    restoreByteCaptured*: bool

  LinuxX8664SyscallRegisters* = object
    ## Policy-free view of the Linux x86_64 syscall ABI captured from a
    ## SIGTRAP `ucontext_t` at an INT3-patched raw syscall site.
    syscallNumber*: int
    args*: array[6, int]
    result*: int
    trapRip*: uint
    syscallAddress*: uint
    resumeRip*: uint

  LinuxX8664CloneContinuation* = object
    ## Policy-free continuation calculation for clone/fork/vfork-like raw
    ## syscalls trapped through INT3. Consumers decide whether a syscall number
    ## should use this path; the helper only describes parent/child register
    ## and RIP outcomes.
    cloneLike*: bool
    syscallNumber*: int
    syscallAddress*: uint
    trapRip*: uint
    resumeRip*: uint
    parentResult*: int
    parentResumeRip*: uint
    childResult*: int
    childResumeRip*: uint

  LinuxVdsoImage* = object
    ## Policy-free description of a parsed Linux x86_64 vDSO image. The image
    ## can be the live process vDSO or a controlled fixture with the same ELF
    ## dynamic-symbol shape.
    base*: pointer
    length*: int
    loadMaxAddress*: uint
    dynamicAddress*: pointer
    symbolTable*: pointer
    stringTable*: pointer
    symbolEntrySize*: int
    symbolCount*: int
    stringTableSize*: int
    diagnostic*: LinuxRawSyscallDiagnostic
    osErrno*: cint

  LinuxVdsoSymbol* = object
    name*: string
    address*: pointer
    size*: int
    info*: byte
    other*: byte
    sectionIndex*: int
    diagnostic*: LinuxRawSyscallDiagnostic

  LinuxVdsoPatchPath* = enum
    lvppNone = "none"
    lvppDirect = "direct"
    lvppOverlay = "overlay"

  LinuxVdsoPatchTransaction* = object
    ## vDSO-specific patch transaction. It resolves one caller-supplied symbol
    ## name inside one caller-supplied image and patches it to the caller's
    ## replacement. No target list, event policy, or replay behavior is implied.
    image*: LinuxVdsoImage
    symbol*: LinuxVdsoSymbol
    replacement*: pointer
    path*: LinuxVdsoPatchPath
    diagnostic*: LinuxRawSyscallDiagnostic
    directDiagnostic*: LinuxRawSyscallDiagnostic
    overlayDiagnostic*: LinuxRawSyscallDiagnostic
    osErrno*: cint
    patchLive*: bool
    overlayUsed*: bool
    direct*: LinuxPatchTransaction

  LinuxAtomicInstructionKind* = enum
    laikNone = "none"
    laikLockRmw = "lock-rmw"
    laikXchgMem = "xchg-mem"
    laikMfence = "mfence"
    laikSfence = "sfence"
    laikLfence = "lfence"

  LinuxAtomicPatchStrategy* = enum
    lapsNone = "none"
    lapsJmpRel32 = "jmp-rel32"
    lapsInt3 = "int3"

  LinuxAtomicInstructionWindow* = object
    ## Conservative policy-free classification of one x86_64 instruction
    ## window relevant to MCR's atomic instrumentation. This is intentionally
    ## not a full instruction decoder: unproven byte windows are rejected.
    diagnostic*: LinuxRawSyscallDiagnostic
    kind*: LinuxAtomicInstructionKind
    length*: int
    lockPrefixed*: bool
    memoryOperand*: bool
    modrmOffset*: int
    opcodeOffset*: int
    opcode0*: byte
    opcode1*: byte

  LinuxAtomicPatchDecision* = object
    ## Mechanism-only choice between a direct 5-byte JMP-rel32 patch and an
    ## INT3 fallback. No event, signal, or lifecycle policy is implied.
    diagnostic*: LinuxRawSyscallDiagnostic
    strategy*: LinuxAtomicPatchStrategy
    target*: uint
    trampoline*: uint
    instructionLength*: int
    patchSize*: int
    rel32Displacement*: int64

  LinuxNearTrampolineAllocation* = object
    diagnostic*: LinuxRawSyscallDiagnostic
    anchor*: uint
    address*: pointer
    length*: int
    withinRel32*: bool
    osErrno*: cint

  LinuxJitExecutableRange* = object
    start*: uint
    stop*: uint

  LinuxJitRangeRegistry* = object
    ## Sorted, merged half-open executable range registry for JIT mprotect
    ## tracking. It owns only dedup/lifecycle bookkeeping; consumers own scans
    ## and reverse-patching.
    ranges*: seq[LinuxJitExecutableRange]

  LinuxSymbolResolverKind* = enum
    lsrDefault = "rtld-default"
    lsrHandle = "handle"

  LinuxSymbolResolver* = object
    ## One symbol lookup step. `lsrDefault` maps to `RTLD_DEFAULT`; `lsrHandle`
    ## uses an opened handle supplied by the consumer.
    kind*: LinuxSymbolResolverKind
    handle*: pointer

  LinuxSyscallSite* = object
    address*: uint
    offset*: int
    nextByte*: byte

  LinuxExecutableMapping* = object
    start*: uint
    stop*: uint
    readable*: bool
    writable*: bool
    executable*: bool
    privateMapping*: bool
    path*: string

type CStackableLinuxPatchResult {.importc: "struct stackable_linux_patch_result",
                                  bycopy.} = object
  diagnostic {.importc: "diagnostic".}: cint
  stage {.importc: "stage".}: cint
  osErrno {.importc: "os_errno".}: cint
  patchLive {.importc: "patch_live".}: cint
  restoreCaptured {.importc: "restore_captured".}: cint
  target {.importc: "target".}: culong
  replacement {.importc: "replacement".}: culong
  patchSize {.importc: "patch_size".}: culong
  original {.importc: "original".}: array[14, byte]

type CStackableLinuxTrampolineResult {.importc: "struct stackable_linux_trampoline_result",
                                       bycopy.} = object
  diagnostic {.importc: "diagnostic".}: cint
  osErrno {.importc: "os_errno".}: cint
  target {.importc: "target".}: culong
  entry {.importc: "entry".}: culong
  copiedLen {.importc: "copied_len".}: culong
  minPatchLen {.importc: "min_patch_len".}: culong
  unsupportedOffset {.importc: "unsupported_offset".}: clong

type CStackableLinuxInt3PatchResult {.importc: "struct stackable_linux_int3_patch_result",
                                      bycopy.} = object
  diagnostic {.importc: "diagnostic".}: cint
  stage {.importc: "stage".}: cint
  osErrno {.importc: "os_errno".}: cint
  patchLive {.importc: "patch_live".}: cint
  restoreCaptured {.importc: "restore_captured".}: cint
  target {.importc: "target".}: culong
  originalFirstByte {.importc: "original_first_byte".}: byte
  secondByte {.importc: "second_byte".}: byte

type CStackableLinuxSyscallRegs {.importc: "struct stackable_linux_syscall_regs",
                                  bycopy.} = object
  nr {.importc: "nr".}: clong
  args {.importc: "args".}: array[6, clong]
  result {.importc: "result".}: clong
  trapRip {.importc: "trap_rip".}: culong
  syscallAddress {.importc: "syscall_address".}: culong
  resumeRip {.importc: "resume_rip".}: culong

type CStackableLinuxCloneContinuation {.importc: "struct stackable_linux_clone_continuation",
                                        bycopy.} = object
  cloneLike {.importc: "clone_like".}: cint
  nr {.importc: "nr".}: clong
  syscallAddress {.importc: "syscall_address".}: culong
  trapRip {.importc: "trap_rip".}: culong
  resumeRip {.importc: "resume_rip".}: culong
  parentResult {.importc: "parent_result".}: clong
  parentResumeRip {.importc: "parent_resume_rip".}: culong
  childResult {.importc: "child_result".}: clong
  childResumeRip {.importc: "child_resume_rip".}: culong

type CStackableLinuxVdsoImage {.importc: "struct stackable_linux_vdso_image",
                                bycopy.} = object
  diagnostic {.importc: "diagnostic".}: cint
  osErrno {.importc: "os_errno".}: cint
  base {.importc: "base".}: culong
  length {.importc: "length".}: culong
  loadMaxAddress {.importc: "load_max_address".}: culong
  dynamicAddress {.importc: "dynamic_address".}: culong
  symbolTable {.importc: "symbol_table".}: culong
  stringTable {.importc: "string_table".}: culong
  symbolEntrySize {.importc: "symbol_entry_size".}: culong
  symbolCount {.importc: "symbol_count".}: culong
  stringTableSize {.importc: "string_table_size".}: culong

type CStackableLinuxVdsoSymbol {.importc: "struct stackable_linux_vdso_symbol",
                                 bycopy.} = object
  diagnostic {.importc: "diagnostic".}: cint
  address {.importc: "address".}: culong
  size {.importc: "size".}: culong
  info {.importc: "info".}: byte
  other {.importc: "other".}: byte
  sectionIndex {.importc: "section_index".}: cushort

type CStackableLinuxVdsoPatchResult {.importc: "struct stackable_linux_vdso_patch_result",
                                      bycopy.} = object
  diagnostic {.importc: "diagnostic".}: cint
  path {.importc: "path".}: cint
  directDiagnostic {.importc: "direct_diagnostic".}: cint
  overlayDiagnostic {.importc: "overlay_diagnostic".}: cint
  osErrno {.importc: "os_errno".}: cint
  patchLive {.importc: "patch_live".}: cint
  overlayUsed {.importc: "overlay_used".}: cint
  imageBase {.importc: "image_base".}: culong
  imageLength {.importc: "image_length".}: culong
  symbolAddress {.importc: "symbol_address".}: culong
  replacement {.importc: "replacement".}: culong
  direct {.importc: "direct".}: CStackableLinuxPatchResult

type CStackableLinuxAtomicWindow {.importc: "struct stackable_linux_atomic_window",
                                   bycopy.} = object
  diagnostic {.importc: "diagnostic".}: cint
  kind {.importc: "kind".}: cint
  length {.importc: "length".}: culong
  lockPrefixed {.importc: "lock_prefixed".}: cint
  memoryOperand {.importc: "memory_operand".}: cint
  modrmOffset {.importc: "modrm_offset".}: clong
  opcodeOffset {.importc: "opcode_offset".}: clong
  opcode0 {.importc: "opcode0".}: byte
  opcode1 {.importc: "opcode1".}: byte

type CStackableLinuxAtomicPatchDecision {.importc: "struct stackable_linux_atomic_patch_decision",
                                          bycopy.} = object
  diagnostic {.importc: "diagnostic".}: cint
  strategy {.importc: "strategy".}: cint
  target {.importc: "target".}: culong
  trampoline {.importc: "trampoline".}: culong
  instructionLength {.importc: "instruction_length".}: culong
  patchSize {.importc: "patch_size".}: culong
  rel32Displacement {.importc: "rel32_displacement".}: clonglong

type CStackableLinuxNearAllocation {.importc: "struct stackable_linux_near_allocation",
                                     bycopy.} = object
  diagnostic {.importc: "diagnostic".}: cint
  osErrno {.importc: "os_errno".}: cint
  anchor {.importc: "anchor".}: culong
  address {.importc: "address".}: culong
  length {.importc: "length".}: culong
  withinRel32 {.importc: "within_rel32".}: cint

const
  linuxSyscallOpcode0* = byte 0x0f
  linuxSyscallOpcode1* = byte 0x05
  linuxInt3Opcode* = byte 0xcc
  linuxAbsoluteJumpPatchSize* = 14
  linuxTrampolineJumpBackSize* = linuxAbsoluteJumpPatchSize
  linuxX8664SysClone* = 56
  linuxX8664SysFork* = 57
  linuxX8664SysVfork* = 58
  linuxX8664SysClone3* = 435
  linuxX8664SysRtSigreturn* = 15

proc linuxRawSyscallSupported*(): LinuxRawSyscallDiagnostic =
  when defined(linux):
    when defined(amd64):
      lrsOk
    else:
      lrsUnsupportedArchitecture
  else:
    lrsUnsupportedPlatform

when defined(linux) and defined(amd64):
  {.emit: """
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <dlfcn.h>
#include <link.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/auxv.h>
#include <signal.h>
#include <ucontext.h>
#include <elf.h>
#include <stdlib.h>

#ifndef STACKABLE_LINUX_RTLD_NOLOAD
#define STACKABLE_LINUX_RTLD_NOLOAD RTLD_NOLOAD
#endif

enum {
  STACKABLE_LINUX_PATCH_OK = 0,
  STACKABLE_LINUX_PATCH_UNSUPPORTED_PLATFORM = 1,
  STACKABLE_LINUX_PATCH_UNSUPPORTED_ARCHITECTURE = 2,
  STACKABLE_LINUX_PATCH_INVALID_ARGUMENT = 3,
  STACKABLE_LINUX_PATCH_SYMBOL_NOT_FOUND = 4,
  STACKABLE_LINUX_PATCH_ALREADY_PATCHED = 5,
  STACKABLE_LINUX_PATCH_MPROTECT_FAILED = 6,
  STACKABLE_LINUX_PATCH_PRE_MPROTECT_FAILED = 7,
  STACKABLE_LINUX_PATCH_WRITE_FAILED = 8,
  STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED = 9,
  STACKABLE_LINUX_PATCH_RESTORE_FAILED = 10,
  STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION = 11,
  STACKABLE_LINUX_PATCH_TRAMPOLINE_ALLOC_FAILED = 12,
  STACKABLE_LINUX_PATCH_TRAMPOLINE_BUILD_FAILED = 13,
  STACKABLE_LINUX_PATCH_NOT_SYSCALL_SITE = 14,
  STACKABLE_LINUX_PATCH_TRAP_INSTALL_FAILED = 15,
  STACKABLE_LINUX_PATCH_TRAP_CHAIN_UNAVAILABLE = 16,
  STACKABLE_LINUX_PATCH_VDSO_NOT_FOUND = 17,
  STACKABLE_LINUX_PATCH_VDSO_NOT_ELF = 18,
  STACKABLE_LINUX_PATCH_VDSO_NO_DYNAMIC = 19,
  STACKABLE_LINUX_PATCH_VDSO_NO_SYMBOL_TABLE = 20,
  STACKABLE_LINUX_PATCH_VDSO_SYMBOL_NOT_FOUND = 21,
  STACKABLE_LINUX_PATCH_VDSO_DIRECT_PATCH_FAILED = 22,
  STACKABLE_LINUX_PATCH_VDSO_OVERLAY_FAILED = 23
};

enum {
  STACKABLE_LINUX_PATCH_STAGE_NONE = 0,
  STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET = 1,
  STACKABLE_LINUX_PATCH_STAGE_PRE_MPROTECT = 2,
  STACKABLE_LINUX_PATCH_STAGE_WRITE_PATCH = 3,
  STACKABLE_LINUX_PATCH_STAGE_POST_MPROTECT_BACK = 4,
  STACKABLE_LINUX_PATCH_STAGE_COMPLETE = 5
};

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

void stackable_linux_rt_sigreturn_restorer(void);
__asm__(
  ".text\n"
  ".globl stackable_linux_rt_sigreturn_restorer\n"
  ".type  stackable_linux_rt_sigreturn_restorer, @function\n"
  "stackable_linux_rt_sigreturn_restorer:\n"
  "    movq $15, %rax\n"
  "    syscall\n"
  ".size stackable_linux_rt_sigreturn_restorer, .-stackable_linux_rt_sigreturn_restorer\n"
);

long stackable_linux_raw_syscall6(long nr, long a1, long a2, long a3,
                                  long a4, long a5, long a6) {
  long ret;
  register long r10 __asm__("r10") = a4;
  register long r8  __asm__("r8")  = a5;
  register long r9  __asm__("r9")  = a6;
  __asm__ volatile (
    "syscall"
    : "=a"(ret)
    : "0"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
    : "rcx", "r11", "memory"
  );
  return ret;
}

long stackable_linux_static_raw_syscall6(long nr, long a1, long a2, long a3,
                                         long a4, long a5, long a6) {
  return stackable_linux_raw_syscall6(nr, a1, a2, a3, a4, a5, a6);
}

long stackable_linux_clone_continuation_trampoline(
    long nr, long a0, long a1, long a2, long a3, long a4, long a5,
    void *resume_rip, long *user_gregs);
__asm__(
  ".text\n"
  ".globl stackable_linux_clone_continuation_trampoline\n"
  ".type  stackable_linux_clone_continuation_trampoline, @function\n"
  "stackable_linux_clone_continuation_trampoline:\n"
  "    pushq %rbx\n"
  "    pushq %r12\n"
  "    pushq %r13\n"
  "    pushq %r14\n"
  "    pushq %r15\n"
  "    pushq %rbp\n"
  "    movq  %rdi, %rax\n"
  "    movq  %rsi, %rdi\n"
  "    movq  %rdx, %rsi\n"
  "    movq  %rcx, %rdx\n"
  "    movq  %r8,  %r10\n"
  "    movq  %r9,  %r8\n"
  "    movq  56(%rsp), %r9\n"
  "    movq  72(%rsp), %rcx\n"
  "    testq %rcx, %rcx\n"
  "    je    .Lstackable_clone_skip_restore\n"
  "    movq  32(%rcx), %r12\n"
  "    movq  40(%rcx), %r13\n"
  "    movq  48(%rcx), %r14\n"
  "    movq  56(%rcx), %r15\n"
  "    movq  80(%rcx), %rbp\n"
  ".Lstackable_clone_skip_restore:\n"
  "    movq  64(%rsp), %rbx\n"
  "    syscall\n"
  "    testq %rax, %rax\n"
  "    je    .Lstackable_clone_child\n"
  "    popq  %rbp\n"
  "    popq  %r15\n"
  "    popq  %r14\n"
  "    popq  %r13\n"
  "    popq  %r12\n"
  "    popq  %rbx\n"
  "    ret\n"
  ".Lstackable_clone_child:\n"
  "    jmp   *%rbx\n"
  ".size stackable_linux_clone_continuation_trampoline, .-stackable_linux_clone_continuation_trampoline\n"
);

int stackable_linux_is_default_clone_continuation_syscall(long nr) {
  return nr == 56 || nr == 57 || nr == 58 || nr == 435;
}

int stackable_linux_compute_clone_continuation(
    struct stackable_linux_syscall_regs *regs, long parent_result,
    int clone_like, struct stackable_linux_clone_continuation *out) {
  if (regs == NULL || out == NULL) return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  out->clone_like = clone_like ? 1 : 0;
  out->nr = regs->nr;
  out->syscall_address = regs->syscall_address;
  out->trap_rip = regs->trap_rip;
  out->resume_rip = regs->resume_rip;
  out->parent_result = parent_result;
  out->parent_resume_rip = regs->resume_rip;
  out->child_result = 0;
  out->child_resume_rip = regs->resume_rip;
  return STACKABLE_LINUX_PATCH_OK;
}

void *stackable_linux_resolve_default_symbol(char *name) {
  if (name == NULL || name[0] == '\0') return NULL;
  return dlsym(RTLD_DEFAULT, name);
}

void *stackable_linux_open_library_noload(char *soname) {
  if (soname == NULL || soname[0] == '\0') return NULL;
  return dlopen(soname, RTLD_NOW | STACKABLE_LINUX_RTLD_NOLOAD);
}

void *stackable_linux_resolve_symbol_in_handle(void *handle, char *name) {
  if (name == NULL || name[0] == '\0') return NULL;
  return dlsym(handle == NULL ? RTLD_DEFAULT : handle, name);
}

static long stackable_linux_raw_mprotect(uintptr_t addr, size_t len, int prot) {
  return stackable_linux_raw_syscall6((long)SYS_mprotect, (long)addr,
                                      (long)len, (long)prot, 0, 0, 0);
}

static long stackable_linux_raw_mmap(void *addr, size_t len, int prot,
                                     int flags, int fd, long offset) {
  return stackable_linux_raw_syscall6((long)SYS_mmap, (long)addr, (long)len,
                                      (long)prot, (long)flags, (long)fd,
                                      offset);
}

static long stackable_linux_raw_munmap(void *addr, size_t len) {
  return stackable_linux_raw_syscall6((long)SYS_munmap, (long)addr, (long)len,
                                      0, 0, 0, 0);
}

static void stackable_linux_write_abs_jump(unsigned char *p, void *target) {
  p[0] = 0xff; p[1] = 0x25;
  p[2] = 0x00; p[3] = 0x00; p[4] = 0x00; p[5] = 0x00;
  uint64_t addr = (uint64_t)(uintptr_t)target;
  memcpy(p + 6, &addr, sizeof(addr));
}

static void stackable_linux_init_patch_result(
    struct stackable_linux_patch_result *out, void *target, void *replacement,
    int capture_restore) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->diagnostic = STACKABLE_LINUX_PATCH_OK;
  out->stage = STACKABLE_LINUX_PATCH_STAGE_NONE;
  out->target = (unsigned long)(uintptr_t)target;
  out->replacement = (unsigned long)(uintptr_t)replacement;
  out->patch_size = 14;
  out->restore_captured = 0;
}

int stackable_linux_patch_absolute_jump_tx(
    void *target, void *replacement, int capture_restore,
    struct stackable_linux_patch_result *out) {
  stackable_linux_init_patch_result(out, target, replacement, capture_restore);
  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET;
  if (target == NULL || replacement == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  uintptr_t page_mask = (uintptr_t)(page_size - 1);
  uintptr_t target_addr = (uintptr_t)target;
  uintptr_t start = target_addr & ~page_mask;
  uintptr_t end = (target_addr + 14 + page_mask) & ~page_mask;
  size_t span = (size_t)(end - start);

  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_PRE_MPROTECT;
  long mp1 = stackable_linux_raw_mprotect(start, span,
                                          PROT_READ | PROT_WRITE | PROT_EXEC);
  if (mp1 < 0) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_PRE_MPROTECT_FAILED;
      out->os_errno = (int)(-mp1);
    }
    return STACKABLE_LINUX_PATCH_PRE_MPROTECT_FAILED;
  }

  unsigned char *p = (unsigned char *)target;
  if (p[0] == 0xff && p[1] == 0x25 && p[2] == 0x00 && p[3] == 0x00 &&
      p[4] == 0x00 && p[5] == 0x00) {
    long mp_restore = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
    if (out) {
      out->stage = STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET;
      out->diagnostic = STACKABLE_LINUX_PATCH_ALREADY_PATCHED;
      if (mp_restore < 0) out->os_errno = (int)(-mp_restore);
    }
    return STACKABLE_LINUX_PATCH_ALREADY_PATCHED;
  }

  if (out && capture_restore) {
    memcpy(out->original, p, 14);
    out->restore_captured = 1;
  }

  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_WRITE_PATCH;
  stackable_linux_write_abs_jump(p, replacement);
  if (out) out->patch_live = 1;

  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_POST_MPROTECT_BACK;
  long mp2 = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
  if (mp2 < 0) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED;
      out->os_errno = (int)(-mp2);
    }
    return STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED;
  }

  if (out) {
    out->stage = STACKABLE_LINUX_PATCH_STAGE_COMPLETE;
    out->diagnostic = STACKABLE_LINUX_PATCH_OK;
  }
  return STACKABLE_LINUX_PATCH_OK;
}

static void stackable_linux_init_int3_result(
    struct stackable_linux_int3_patch_result *out, void *target) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->diagnostic = STACKABLE_LINUX_PATCH_OK;
  out->stage = STACKABLE_LINUX_PATCH_STAGE_NONE;
  out->target = (unsigned long)(uintptr_t)target;
}

int stackable_linux_patch_int3_syscall_tx(
    void *target, struct stackable_linux_int3_patch_result *out) {
  stackable_linux_init_int3_result(out, target);
  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET;
  if (target == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  uintptr_t page_mask = (uintptr_t)(page_size - 1);
  uintptr_t target_addr = (uintptr_t)target;
  uintptr_t start = target_addr & ~page_mask;
  uintptr_t end = (target_addr + 2 + page_mask) & ~page_mask;
  size_t span = (size_t)(end - start);

  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_PRE_MPROTECT;
  long mp1 = stackable_linux_raw_mprotect(start, span,
                                          PROT_READ | PROT_WRITE | PROT_EXEC);
  if (mp1 < 0) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_PRE_MPROTECT_FAILED;
      out->os_errno = (int)(-mp1);
    }
    return STACKABLE_LINUX_PATCH_PRE_MPROTECT_FAILED;
  }

  unsigned char *p = (unsigned char *)target;
  if (p[0] == 0xcc && p[1] == 0x05) {
    long mp_restore = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
    if (out) {
      out->stage = STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET;
      out->diagnostic = STACKABLE_LINUX_PATCH_ALREADY_PATCHED;
      if (mp_restore < 0) out->os_errno = (int)(-mp_restore);
    }
    return STACKABLE_LINUX_PATCH_ALREADY_PATCHED;
  }
  if (p[0] != 0x0f || p[1] != 0x05) {
    long mp_restore = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
    if (out) {
      out->stage = STACKABLE_LINUX_PATCH_STAGE_VALIDATE_TARGET;
      out->diagnostic = STACKABLE_LINUX_PATCH_NOT_SYSCALL_SITE;
      if (mp_restore < 0) out->os_errno = (int)(-mp_restore);
    }
    return STACKABLE_LINUX_PATCH_NOT_SYSCALL_SITE;
  }

  if (out) {
    out->original_first_byte = p[0];
    out->second_byte = p[1];
    out->restore_captured = 1;
  }

  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_WRITE_PATCH;
  *(volatile unsigned char *)p = 0xcc;
  if (out) out->patch_live = 1;

  if (out) out->stage = STACKABLE_LINUX_PATCH_STAGE_POST_MPROTECT_BACK;
  long mp2 = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
  if (mp2 < 0) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED;
      out->os_errno = (int)(-mp2);
    }
    return STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED;
  }

  if (out) {
    out->stage = STACKABLE_LINUX_PATCH_STAGE_COMPLETE;
    out->diagnostic = STACKABLE_LINUX_PATCH_OK;
  }
  return STACKABLE_LINUX_PATCH_OK;
}

int stackable_linux_restore_int3_syscall(
    void *target, unsigned char original_first_byte, int *out_errno) {
  if (out_errno) *out_errno = 0;
  if (target == NULL) return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  uintptr_t page_mask = (uintptr_t)(page_size - 1);
  uintptr_t target_addr = (uintptr_t)target;
  uintptr_t start = target_addr & ~page_mask;
  uintptr_t end = (target_addr + 2 + page_mask) & ~page_mask;
  size_t span = (size_t)(end - start);

  long mp1 = stackable_linux_raw_mprotect(start, span,
                                          PROT_READ | PROT_WRITE | PROT_EXEC);
  if (mp1 < 0) {
    if (out_errno) *out_errno = (int)(-mp1);
    return STACKABLE_LINUX_PATCH_PRE_MPROTECT_FAILED;
  }

  unsigned char *p = (unsigned char *)target;
  if (p[0] != 0xcc || p[1] != 0x05) {
    long mp_restore = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
    if (out_errno && mp_restore < 0) *out_errno = (int)(-mp_restore);
    return STACKABLE_LINUX_PATCH_NOT_SYSCALL_SITE;
  }
  p[0] = original_first_byte;

  long mp2 = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
  if (mp2 < 0) {
    if (out_errno) *out_errno = (int)(-mp2);
    return STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED;
  }
  return STACKABLE_LINUX_PATCH_OK;
}

static int stackable_linux_decode_one_x86_64(const unsigned char *p,
                                             size_t max_len,
                                             size_t *out_len) {
  if (p == NULL || out_len == NULL || max_len == 0) {
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  size_t i = 0;
  int has_operand_prefix = 0;
  int has_rex = 0;
  unsigned char rex = 0;

  for (;;) {
    if (i >= max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    unsigned char b = p[i];
    if (b == 0x66 || b == 0x67 || b == 0xf2 || b == 0xf3) {
      has_operand_prefix = 1;
      i++;
      continue;
    }
    if (b >= 0x40 && b <= 0x4f) {
      has_rex = 1;
      rex = b;
      i++;
      continue;
    }
    break;
  }

  if (i >= max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  unsigned char op = p[i++];

  if (op == 0x90 || op == 0xc9) {
    *out_len = i;
    return STACKABLE_LINUX_PATCH_OK;
  }
  if ((op >= 0x50 && op <= 0x5f) || op == 0x9c || op == 0x9d) {
    *out_len = i;
    return STACKABLE_LINUX_PATCH_OK;
  }
  if (op == 0xcc ||
      op == 0xc3 || op == 0xcb || op == 0xc2 || op == 0xca ||
      op == 0xe8 || op == 0xe9 || op == 0xeb ||
      (op >= 0x70 && op <= 0x7f)) {
    return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  }

  if (op >= 0xb8 && op <= 0xbf) {
    size_t imm = (has_rex && (rex & 0x08)) ? 8 : (has_operand_prefix ? 2 : 4);
    if (i + imm > max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    *out_len = i + imm;
    return STACKABLE_LINUX_PATCH_OK;
  }

  if (op == 0x0f) {
    if (i >= max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    unsigned char op2 = p[i++];
    if (op2 == 0x05 || op2 == 0x34 || op2 == 0x35 ||
        (op2 >= 0x80 && op2 <= 0x8f)) {
      return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    }
    return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  }

  int needs_modrm = 0;
  size_t imm_len = 0;
  switch (op) {
    case 0x01: case 0x03: case 0x09: case 0x0b:
    case 0x21: case 0x23: case 0x29: case 0x2b:
    case 0x31: case 0x33: case 0x39: case 0x3b:
    case 0x63: case 0x85: case 0x87: case 0x89:
    case 0x8b: case 0x8d: case 0x8f:
      needs_modrm = 1;
      break;
    case 0x80:
      needs_modrm = 1; imm_len = 1; break;
    case 0x81:
      needs_modrm = 1; imm_len = 4; break;
    case 0x83:
      needs_modrm = 1; imm_len = 1; break;
    case 0xc7:
      needs_modrm = 1; imm_len = 4; break;
    case 0x68:
      imm_len = 4; break;
    case 0x6a:
      imm_len = 1; break;
    case 0xa1: case 0xa3:
      return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    default:
      return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  }

  if (needs_modrm) {
    if (i >= max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    unsigned char modrm = p[i++];
    unsigned char mod = (modrm >> 6) & 0x3;
    unsigned char rm = modrm & 0x7;
    if (mod != 3 && rm == 5) {
      return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    }
    if (mod != 3 && rm == 4) {
      if (i >= max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
      unsigned char sib = p[i++];
      unsigned char base = sib & 0x7;
      if (mod == 0 && base == 5) {
        if (i + 4 > max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
        i += 4;
      }
    }
    if (mod == 1) {
      if (i + 1 > max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
      i += 1;
    } else if (mod == 2) {
      if (i + 4 > max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
      i += 4;
    }
  }

  if (i + imm_len > max_len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  *out_len = i + imm_len;
  return STACKABLE_LINUX_PATCH_OK;
}

static int stackable_linux_measure_relocatable_prefix(
    void *target, size_t min_len, size_t max_scan, size_t *out_len,
    long *unsupported_offset) {
  if (out_len) *out_len = 0;
  if (unsupported_offset) *unsupported_offset = -1;
  if (target == NULL || min_len == 0 || out_len == NULL) {
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  if (max_scan < min_len) max_scan = min_len;

  const unsigned char *p = (const unsigned char *)target;
  size_t copied = 0;
  while (copied < min_len) {
    size_t insn_len = 0;
    int rc = stackable_linux_decode_one_x86_64(p + copied,
                                               max_scan - copied,
                                               &insn_len);
    if (rc != STACKABLE_LINUX_PATCH_OK) {
      if (unsupported_offset) *unsupported_offset = (long)copied;
      return rc;
    }
    if (insn_len == 0 || copied + insn_len > max_scan) {
      if (unsupported_offset) *unsupported_offset = (long)copied;
      return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    }
    copied += insn_len;
  }
  *out_len = copied;
  return STACKABLE_LINUX_PATCH_OK;
}

static void stackable_linux_init_trampoline_result(
    struct stackable_linux_trampoline_result *out, void *target,
    size_t min_patch_len) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->diagnostic = STACKABLE_LINUX_PATCH_OK;
  out->target = (unsigned long)(uintptr_t)target;
  out->min_patch_len = (unsigned long)min_patch_len;
  out->unsupported_offset = -1;
}

int stackable_linux_measure_original_trampoline(void *target,
                                                unsigned long min_patch_len,
                                                unsigned long max_scan,
                                                struct stackable_linux_trampoline_result *out) {
  if (min_patch_len == 0) min_patch_len = 14;
  if (max_scan == 0) max_scan = 64;
  stackable_linux_init_trampoline_result(out, target, (size_t)min_patch_len);
  if (target == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  size_t copied = 0;
  long unsupported = -1;
  int rc = stackable_linux_measure_relocatable_prefix(
      target, (size_t)min_patch_len, (size_t)max_scan, &copied, &unsupported);
  if (out) {
    out->diagnostic = rc;
    out->copied_len = (unsigned long)copied;
    out->unsupported_offset = unsupported;
  }
  return rc;
}

int stackable_linux_build_original_trampoline(void *target,
                                              unsigned long min_patch_len,
                                              unsigned long max_scan,
                                              struct stackable_linux_trampoline_result *out) {
  if (min_patch_len == 0) min_patch_len = 14;
  if (max_scan == 0) max_scan = 64;
  stackable_linux_init_trampoline_result(out, target, (size_t)min_patch_len);
  if (target == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  size_t copied = 0;
  long unsupported = -1;
  int rc = stackable_linux_measure_relocatable_prefix(
      target, (size_t)min_patch_len, (size_t)max_scan, &copied, &unsupported);
  if (rc != STACKABLE_LINUX_PATCH_OK) {
    if (out) {
      out->diagnostic = rc;
      out->unsupported_offset = unsupported;
    }
    return rc;
  }

  size_t total = copied + 14;
  long mapped = stackable_linux_raw_mmap(NULL, total, PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapped < 0) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_TRAMPOLINE_ALLOC_FAILED;
      out->os_errno = (int)(-mapped);
    }
    return STACKABLE_LINUX_PATCH_TRAMPOLINE_ALLOC_FAILED;
  }

  unsigned char *tramp = (unsigned char *)(uintptr_t)mapped;
  memcpy(tramp, target, copied);
  stackable_linux_write_abs_jump(tramp + copied,
      (void *)((uintptr_t)target + copied));

  long protect_rc = stackable_linux_raw_mprotect((uintptr_t)tramp, total,
                                                 PROT_READ | PROT_EXEC);
  if (protect_rc < 0) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_TRAMPOLINE_BUILD_FAILED;
      out->os_errno = (int)(-protect_rc);
    }
    return STACKABLE_LINUX_PATCH_TRAMPOLINE_BUILD_FAILED;
  }

  if (out) {
    out->diagnostic = STACKABLE_LINUX_PATCH_OK;
    out->entry = (unsigned long)(uintptr_t)tramp;
    out->copied_len = (unsigned long)copied;
  }
  return STACKABLE_LINUX_PATCH_OK;
}

int stackable_linux_patch_absolute_jump(void *target, void *replacement,
                                        unsigned char *saved14,
                                        int *out_errno) {
  if (out_errno) *out_errno = 0;
  if (saved14 == NULL) return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  struct stackable_linux_patch_result tx;
  int rc = stackable_linux_patch_absolute_jump_tx(target, replacement, 1, &tx);
  if (out_errno) *out_errno = tx.os_errno;
  if (rc == STACKABLE_LINUX_PATCH_OK ||
      rc == STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED) {
    memcpy(saved14, tx.original, 14);
    return 0;
  }
  return rc;
}

int stackable_linux_restore_absolute_jump(void *target,
                                          unsigned char *saved14,
                                          int *out_errno) {
  if (out_errno) *out_errno = 0;
  if (target == NULL || saved14 == NULL) return 3;

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  uintptr_t page_mask = (uintptr_t)(page_size - 1);
  uintptr_t target_addr = (uintptr_t)target;
  uintptr_t start = target_addr & ~page_mask;
  uintptr_t end = (target_addr + 14 + page_mask) & ~page_mask;
  size_t span = (size_t)(end - start);

  long mp1 = stackable_linux_raw_mprotect(start, span,
                                          PROT_READ | PROT_WRITE | PROT_EXEC);
  if (mp1 < 0) {
    if (out_errno) *out_errno = (int)(-mp1);
    return 7;
  }
  memcpy(target, saved14, 14);
  long mp2 = stackable_linux_raw_mprotect(start, span, PROT_READ | PROT_EXEC);
  if (mp2 < 0) {
    if (out_errno) *out_errno = (int)(-mp2);
    return 7;
  }
  return 0;
}

typedef struct {
  unsigned long anchor;
  int found_in_text;
} stackable_linux_phdr_query;

static int stackable_linux_phdr_cb(struct dl_phdr_info *info, size_t size,
                                   void *data) {
  (void)size;
  stackable_linux_phdr_query *q = (stackable_linux_phdr_query *)data;
  for (int i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
    if (ph->p_type != PT_LOAD) continue;
    if ((ph->p_flags & PF_X) == 0) continue;
    unsigned long seg_start = info->dlpi_addr + ph->p_vaddr;
    unsigned long seg_end = seg_start + ph->p_memsz;
    if (q->anchor >= seg_start && q->anchor < seg_end) {
      q->found_in_text = 1;
      return 1;
    }
  }
  return 0;
}

int stackable_linux_addr_in_executable_segment(unsigned long addr) {
  if (addr == 0) return 0;
  stackable_linux_phdr_query q;
  q.anchor = addr;
  q.found_in_text = 0;
  dl_iterate_phdr(stackable_linux_phdr_cb, &q);
  return q.found_in_text;
}

static void stackable_linux_init_vdso_image(
    struct stackable_linux_vdso_image *out) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->diagnostic = STACKABLE_LINUX_PATCH_OK;
}

static unsigned long stackable_linux_vdso_ptr_value(unsigned long raw,
                                                    unsigned long base,
                                                    unsigned long load_max) {
  if (raw < load_max || raw < base) return base + raw;
  return raw;
}

static int stackable_linux_range_contains(unsigned long base,
                                          unsigned long length,
                                          unsigned long addr,
                                          unsigned long size) {
  if (base == 0 || length == 0 || addr < base) return 0;
  unsigned long stop = base + length;
  if (stop <= base) return 0;
  unsigned long end = addr + size;
  if (end < addr) return 0;
  return end <= stop;
}

static int stackable_linux_vdso_offset_range(unsigned long offset,
                                             unsigned long size,
                                             unsigned long length) {
  if (length == 0 || offset > length) return 0;
  if (size > length - offset) return 0;
  return 1;
}

static int stackable_linux_parse_vdso_image(
    unsigned long base_addr, struct stackable_linux_vdso_image *out) {
  stackable_linux_init_vdso_image(out);
  if (base_addr == 0) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_NOT_FOUND;
    return STACKABLE_LINUX_PATCH_VDSO_NOT_FOUND;
  }
  if (out) out->base = base_addr;

  unsigned char *base = (unsigned char *)(uintptr_t)base_addr;
  Elf64_Ehdr ehdr;
  memcpy(&ehdr, base, sizeof(ehdr));
  if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
      ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
      ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
      ehdr.e_ident[EI_MAG3] != ELFMAG3 ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
      ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
      ehdr.e_machine != EM_X86_64 ||
      ehdr.e_phoff == 0 || ehdr.e_phnum == 0 ||
      ehdr.e_phnum > 64 ||
      ehdr.e_phentsize < sizeof(Elf64_Phdr) ||
      ehdr.e_phoff > 1024 * 1024 ||
      (unsigned long)ehdr.e_phnum >
          ((1024 * 1024UL - (unsigned long)ehdr.e_phoff) /
           (unsigned long)ehdr.e_phentsize)) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_NOT_ELF;
    return STACKABLE_LINUX_PATCH_VDSO_NOT_ELF;
  }

  unsigned long dyn_off = 0;
  unsigned long dyn_size = 0;
  unsigned long load_max = 0;
  for (int i = 0; i < ehdr.e_phnum; i++) {
    Elf64_Phdr phdr;
    memcpy(&phdr, base + ehdr.e_phoff + (size_t)i * ehdr.e_phentsize,
           sizeof(phdr));
    if (phdr.p_type == PT_DYNAMIC) {
      dyn_off = (unsigned long)phdr.p_offset;
      dyn_size = (unsigned long)phdr.p_filesz;
    }
    if (phdr.p_type == PT_LOAD) {
      unsigned long end = (unsigned long)phdr.p_vaddr +
                          (unsigned long)phdr.p_memsz;
      if (end < (unsigned long)phdr.p_vaddr || end > 1024 * 1024UL) {
        if (out) out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_NOT_ELF;
        return STACKABLE_LINUX_PATCH_VDSO_NOT_ELF;
      }
      if (end > load_max) load_max = end;
    }
  }
  if (load_max == 0 || load_max > 1024 * 1024UL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_NOT_ELF;
    return STACKABLE_LINUX_PATCH_VDSO_NOT_ELF;
  }
  if (base_addr + load_max <= base_addr) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_NOT_ELF;
    return STACKABLE_LINUX_PATCH_VDSO_NOT_ELF;
  }
  if (out) {
    out->load_max_address = load_max;
    out->length = load_max;
  }
  if (dyn_off == 0 || dyn_size == 0 ||
      !stackable_linux_vdso_offset_range(dyn_off, sizeof(Elf64_Dyn), load_max)) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_NO_DYNAMIC;
    return STACKABLE_LINUX_PATCH_VDSO_NO_DYNAMIC;
  }
  if (dyn_size > load_max - dyn_off) dyn_size = load_max - dyn_off;

  unsigned long symtab_v = 0, strtab_v = 0, syment = 0, strsz = 0, hash_v = 0;
  Elf64_Dyn *dynp = (Elf64_Dyn *)(base + dyn_off);
  unsigned long dyn_count = dyn_size / sizeof(Elf64_Dyn);
  for (unsigned long i = 0; i < dyn_count; i++) {
    Elf64_Dyn d;
    memcpy(&d, &dynp[i], sizeof(d));
    if (d.d_tag == DT_NULL) break;
    switch (d.d_tag) {
      case DT_SYMTAB: symtab_v = (unsigned long)d.d_un.d_ptr; break;
      case DT_STRTAB: strtab_v = (unsigned long)d.d_un.d_ptr; break;
      case DT_SYMENT: syment = (unsigned long)d.d_un.d_val; break;
      case DT_STRSZ: strsz = (unsigned long)d.d_un.d_val; break;
      case DT_HASH: hash_v = (unsigned long)d.d_un.d_ptr; break;
      default: break;
    }
  }
  if (symtab_v == 0 || strtab_v == 0 || syment < sizeof(Elf64_Sym) ||
      strsz == 0 || strsz > load_max) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_NO_SYMBOL_TABLE;
    return STACKABLE_LINUX_PATCH_VDSO_NO_SYMBOL_TABLE;
  }

  unsigned long symtab_p =
      stackable_linux_vdso_ptr_value(symtab_v, base_addr, load_max);
  unsigned long strtab_p =
      stackable_linux_vdso_ptr_value(strtab_v, base_addr, load_max);
  if (!stackable_linux_range_contains(base_addr, load_max, strtab_p, strsz) ||
      !stackable_linux_range_contains(base_addr, load_max, symtab_p,
                                      sizeof(Elf64_Sym))) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_NO_SYMBOL_TABLE;
    return STACKABLE_LINUX_PATCH_VDSO_NO_SYMBOL_TABLE;
  }

  unsigned long symcount = 256;
  if (hash_v != 0) {
    unsigned long hash_p =
        stackable_linux_vdso_ptr_value(hash_v, base_addr, load_max);
    if (stackable_linux_range_contains(base_addr, load_max, hash_p,
                                       2 * sizeof(uint32_t))) {
      uint32_t nchain = 0;
      memcpy(&nchain, (void *)(uintptr_t)(hash_p + sizeof(uint32_t)),
             sizeof(nchain));
      if (nchain > 0) symcount = nchain;
    }
  } else if (strtab_p > symtab_p && ((strtab_p - symtab_p) % syment) == 0) {
    symcount = (strtab_p - symtab_p) / syment;
  }
  unsigned long max_by_range = (base_addr + load_max - symtab_p) / syment;
  if (symcount > max_by_range) symcount = max_by_range;
  if (symcount == 0 || symcount > 4096) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_NO_SYMBOL_TABLE;
    return STACKABLE_LINUX_PATCH_VDSO_NO_SYMBOL_TABLE;
  }

  if (out) {
    out->diagnostic = STACKABLE_LINUX_PATCH_OK;
    out->dynamic_address = base_addr + dyn_off;
    out->symbol_table = symtab_p;
    out->string_table = strtab_p;
    out->symbol_entry_size = syment;
    out->symbol_count = symcount;
    out->string_table_size = strsz;
  }
  return STACKABLE_LINUX_PATCH_OK;
}

int stackable_linux_locate_vdso_image(struct stackable_linux_vdso_image *out) {
  stackable_linux_init_vdso_image(out);
  unsigned long base = (unsigned long)getauxval(AT_SYSINFO_EHDR);
  if (base == 0) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_NOT_FOUND;
    return STACKABLE_LINUX_PATCH_VDSO_NOT_FOUND;
  }
  return stackable_linux_parse_vdso_image(base, out);
}

int stackable_linux_parse_vdso_image_at(
    unsigned long base, struct stackable_linux_vdso_image *out) {
  return stackable_linux_parse_vdso_image(base, out);
}

int stackable_linux_resolve_vdso_symbol(
    struct stackable_linux_vdso_image *image, char *name,
    struct stackable_linux_vdso_symbol *out) {
  if (out) memset(out, 0, sizeof(*out));
  if (image == NULL || name == NULL || name[0] == '\0') {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  if (image->diagnostic != STACKABLE_LINUX_PATCH_OK ||
      image->base == 0 || image->symbol_table == 0 ||
      image->string_table == 0 || image->symbol_entry_size == 0 ||
      image->string_table_size == 0) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_NO_SYMBOL_TABLE;
    return STACKABLE_LINUX_PATCH_VDSO_NO_SYMBOL_TABLE;
  }

  size_t nlen = strlen(name);
  unsigned long symcount = image->symbol_count;
  if (symcount == 0 || symcount > 4096) symcount = 256;
  for (unsigned long i = 0; i < symcount; i++) {
    unsigned long sym_addr = image->symbol_table + i * image->symbol_entry_size;
    if (!stackable_linux_range_contains(image->base, image->length, sym_addr,
                                        sizeof(Elf64_Sym))) break;
    Elf64_Sym sym;
    memcpy(&sym, (void *)(uintptr_t)sym_addr, sizeof(sym));
    if (sym.st_name == 0 || sym.st_name >= image->string_table_size) continue;
    const char *sname = (const char *)(uintptr_t)(image->string_table + sym.st_name);
    size_t maxlen = image->string_table_size - sym.st_name;
    if (strnlen(sname, maxlen) >= maxlen) continue;
    if (strlen(sname) != nlen) continue;
    if (memcmp(sname, name, nlen) != 0) continue;
    unsigned long value = (unsigned long)sym.st_value;
    unsigned long addr = stackable_linux_vdso_ptr_value(
        value, image->base, image->load_max_address);
    if (!stackable_linux_range_contains(image->base, image->length, addr, 1))
      continue;
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_OK;
      out->address = addr;
      out->size = (unsigned long)sym.st_size;
      out->info = sym.st_info;
      out->other = sym.st_other;
      out->section_index = sym.st_shndx;
    }
    return STACKABLE_LINUX_PATCH_OK;
  }
  if (out) out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_SYMBOL_NOT_FOUND;
  return STACKABLE_LINUX_PATCH_VDSO_SYMBOL_NOT_FOUND;
}

static void stackable_linux_init_vdso_patch_result(
    struct stackable_linux_vdso_patch_result *out,
    struct stackable_linux_vdso_image *image,
    void *replacement) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->diagnostic = STACKABLE_LINUX_PATCH_OK;
  out->direct_diagnostic = STACKABLE_LINUX_PATCH_OK;
  out->overlay_diagnostic = STACKABLE_LINUX_PATCH_OK;
  out->image_base = image ? image->base : 0;
  out->image_length = image ? image->length : 0;
  out->replacement = (unsigned long)(uintptr_t)replacement;
}

int stackable_linux_vdso_overlay_patch_tx(
    unsigned long image_base, unsigned long image_len,
    void *target, void *replacement,
    struct stackable_linux_vdso_patch_result *out) {
  struct stackable_linux_vdso_image image;
  memset(&image, 0, sizeof(image));
  image.base = image_base;
  image.length = image_len;
  image.diagnostic = STACKABLE_LINUX_PATCH_OK;
  stackable_linux_init_vdso_patch_result(out, &image, replacement);
  if (out) out->path = 2;
  if (image_base == 0 || image_len == 0 || target == NULL || replacement == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  uintptr_t base = (uintptr_t)image_base;
  uintptr_t stop = base + (uintptr_t)image_len;
  uintptr_t t = (uintptr_t)target;
  if (stop <= base || t < base || t + 14 > stop) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  uintptr_t page_mask = (uintptr_t)(page_size - 1);
  if ((base & page_mask) != 0 || (stop & page_mask) != 0) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  uintptr_t aligned_base = base & ~page_mask;
  uintptr_t aligned_end = (stop + page_mask) & ~page_mask;
  size_t span = (size_t)(aligned_end - aligned_base);
  if (span == 0 || span > (size_t)(1024 * 1024)) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  unsigned char *snapshot = (unsigned char *)malloc(span);
  if (snapshot == NULL) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_OVERLAY_FAILED;
      out->overlay_diagnostic = STACKABLE_LINUX_PATCH_VDSO_OVERLAY_FAILED;
      out->os_errno = ENOMEM;
    }
    return STACKABLE_LINUX_PATCH_VDSO_OVERLAY_FAILED;
  }
  memcpy(snapshot, (void *)aligned_base, span);

  long mapped = stackable_linux_raw_mmap((void *)aligned_base, span,
      PROT_READ | PROT_WRITE | PROT_EXEC,
      MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapped < 0 || (uintptr_t)mapped != aligned_base) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_OVERLAY_FAILED;
      out->overlay_diagnostic = STACKABLE_LINUX_PATCH_VDSO_OVERLAY_FAILED;
      out->os_errno = mapped < 0 ? (int)(-mapped) : EINVAL;
    }
    free(snapshot);
    return STACKABLE_LINUX_PATCH_VDSO_OVERLAY_FAILED;
  }

  memcpy((void *)aligned_base, snapshot, span);
  free(snapshot);
  stackable_linux_write_abs_jump((unsigned char *)target, replacement);

  long protect_rc = stackable_linux_raw_mprotect(aligned_base, span,
                                                 PROT_READ | PROT_EXEC);
  if (protect_rc < 0 && out) {
    out->os_errno = (int)(-protect_rc);
  }
  if (out) {
    out->diagnostic = STACKABLE_LINUX_PATCH_OK;
    out->overlay_diagnostic = STACKABLE_LINUX_PATCH_OK;
    out->path = 2;
    out->patch_live = 1;
    out->overlay_used = 1;
    out->symbol_address = (unsigned long)(uintptr_t)target;
  }
  return STACKABLE_LINUX_PATCH_OK;
}

int stackable_linux_vdso_patch_symbol_tx(
    struct stackable_linux_vdso_image *image, char *name,
    void *replacement, int allow_overlay,
    struct stackable_linux_vdso_patch_result *out) {
  stackable_linux_init_vdso_patch_result(out, image, replacement);
  if (image == NULL || name == NULL || name[0] == '\0' || replacement == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  if (image->diagnostic != STACKABLE_LINUX_PATCH_OK) {
    if (out) out->diagnostic = image->diagnostic;
    return image->diagnostic;
  }

  struct stackable_linux_vdso_symbol sym;
  int rc = stackable_linux_resolve_vdso_symbol(image, name, &sym);
  if (rc != STACKABLE_LINUX_PATCH_OK) {
    if (out) out->diagnostic = rc;
    return rc;
  }
  if (out) out->symbol_address = sym.address;
  if (!stackable_linux_range_contains(image->base, image->length,
                                      sym.address, 14)) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }

  struct stackable_linux_patch_result direct;
  memset(&direct, 0, sizeof(direct));
  rc = stackable_linux_patch_absolute_jump_tx(
      (void *)(uintptr_t)sym.address, replacement, 1, &direct);
  if (out) {
    out->direct = direct;
    out->direct_diagnostic = direct.diagnostic;
  }
  if (rc == STACKABLE_LINUX_PATCH_OK ||
      (rc == STACKABLE_LINUX_PATCH_POST_MPROTECT_BACK_FAILED &&
       direct.patch_live)) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_OK;
      out->path = 1;
      out->patch_live = 1;
      out->os_errno = direct.os_errno;
    }
    return STACKABLE_LINUX_PATCH_OK;
  }

  if (!allow_overlay) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_DIRECT_PATCH_FAILED;
      out->os_errno = direct.os_errno;
      out->patch_live = direct.patch_live;
    }
    return STACKABLE_LINUX_PATCH_VDSO_DIRECT_PATCH_FAILED;
  }

  struct stackable_linux_vdso_patch_result overlay;
  memset(&overlay, 0, sizeof(overlay));
  rc = stackable_linux_vdso_overlay_patch_tx(
      image->base, image->length, (void *)(uintptr_t)sym.address,
      replacement, &overlay);
  if (out) {
    out->overlay_diagnostic = overlay.diagnostic;
    out->os_errno = overlay.os_errno;
    out->path = overlay.path;
    out->patch_live = overlay.patch_live;
    out->overlay_used = overlay.overlay_used;
  }
  if (rc == STACKABLE_LINUX_PATCH_OK) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_OK;
    return STACKABLE_LINUX_PATCH_OK;
  }
  if (out) out->diagnostic = STACKABLE_LINUX_PATCH_VDSO_OVERLAY_FAILED;
  return STACKABLE_LINUX_PATCH_VDSO_OVERLAY_FAILED;
}

#define STACKABLE_LINUX_PATCH_REGISTRY_CAP 256
static unsigned long stackable_linux_patch_registry[STACKABLE_LINUX_PATCH_REGISTRY_CAP];
static int stackable_linux_patch_registry_count = 0;

void stackable_linux_patch_registry_reset(void) {
  stackable_linux_patch_registry_count = 0;
  memset(stackable_linux_patch_registry, 0, sizeof(stackable_linux_patch_registry));
}

int stackable_linux_patch_registry_contains(unsigned long addr) {
  for (int i = 0; i < stackable_linux_patch_registry_count; i++) {
    if (stackable_linux_patch_registry[i] == addr) return 1;
  }
  return 0;
}

int stackable_linux_patch_registry_record(unsigned long addr) {
  if (addr == 0) return 0;
  if (stackable_linux_patch_registry_contains(addr)) return 1;
  if (stackable_linux_patch_registry_count >= STACKABLE_LINUX_PATCH_REGISTRY_CAP) {
    return -1;
  }
  stackable_linux_patch_registry[stackable_linux_patch_registry_count++] = addr;
  return 0;
}

static int stackable_linux_copy_ucontext_regs(
    void *ucontext_ptr, struct stackable_linux_syscall_regs *out) {
  if (ucontext_ptr == NULL || out == NULL) {
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  ucontext_t *uc = (ucontext_t *)ucontext_ptr;
  out->nr = (long)uc->uc_mcontext.gregs[REG_RAX];
  out->args[0] = (long)uc->uc_mcontext.gregs[REG_RDI];
  out->args[1] = (long)uc->uc_mcontext.gregs[REG_RSI];
  out->args[2] = (long)uc->uc_mcontext.gregs[REG_RDX];
  out->args[3] = (long)uc->uc_mcontext.gregs[REG_R10];
  out->args[4] = (long)uc->uc_mcontext.gregs[REG_R8];
  out->args[5] = (long)uc->uc_mcontext.gregs[REG_R9];
  out->result = (long)uc->uc_mcontext.gregs[REG_RAX];
  out->trap_rip = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
  out->syscall_address = out->trap_rip == 0 ? 0 : out->trap_rip - 1;
  out->resume_rip = out->trap_rip + 1;
  return STACKABLE_LINUX_PATCH_OK;
}

int stackable_linux_capture_syscall_regs_from_ucontext(
    void *ucontext_ptr, struct stackable_linux_syscall_regs *out) {
  return stackable_linux_copy_ucontext_regs(ucontext_ptr, out);
}

int stackable_linux_write_syscall_result_to_ucontext(
    void *ucontext_ptr, long result, unsigned long resume_rip) {
  if (ucontext_ptr == NULL) return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  ucontext_t *uc = (ucontext_t *)ucontext_ptr;
  uc->uc_mcontext.gregs[REG_RAX] = (greg_t)result;
  if (resume_rip != 0) {
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)resume_rip;
  }
  return STACKABLE_LINUX_PATCH_OK;
}

long stackable_linux_replay_syscall_regs(
    const struct stackable_linux_syscall_regs *regs) {
  if (regs == NULL) return -22;
  return stackable_linux_raw_syscall6(regs->nr, regs->args[0], regs->args[1],
                                      regs->args[2], regs->args[3],
                                      regs->args[4], regs->args[5]);
}

static struct sigaction stackable_linux_old_sigtrap_action;
static int stackable_linux_sigtrap_installed = 0;

int stackable_linux_install_sigtrap_handler(void *handler, int extra_flags) {
  if (handler == NULL) return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  if (stackable_linux_sigtrap_installed) return STACKABLE_LINUX_PATCH_ALREADY_PATCHED;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = (void (*)(int, siginfo_t *, void *))handler;
  sa.sa_flags = SA_SIGINFO | extra_flags;
  if (sigaction(SIGTRAP, &sa, &stackable_linux_old_sigtrap_action) != 0) {
    return STACKABLE_LINUX_PATCH_TRAP_INSTALL_FAILED;
  }
  stackable_linux_sigtrap_installed = 1;
  return STACKABLE_LINUX_PATCH_OK;
}

int stackable_linux_uninstall_sigtrap_handler(void) {
  if (!stackable_linux_sigtrap_installed) {
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  if (sigaction(SIGTRAP, &stackable_linux_old_sigtrap_action, NULL) != 0) {
    return STACKABLE_LINUX_PATCH_TRAP_INSTALL_FAILED;
  }
  stackable_linux_sigtrap_installed = 0;
  return STACKABLE_LINUX_PATCH_OK;
}

int stackable_linux_chain_sigtrap(int signum, void *siginfo_ptr,
                                  void *ucontext_ptr) {
  if (!stackable_linux_sigtrap_installed) {
    return STACKABLE_LINUX_PATCH_TRAP_CHAIN_UNAVAILABLE;
  }
  if (stackable_linux_old_sigtrap_action.sa_flags & SA_SIGINFO) {
    if (stackable_linux_old_sigtrap_action.sa_sigaction == NULL) {
      return STACKABLE_LINUX_PATCH_TRAP_CHAIN_UNAVAILABLE;
    }
    stackable_linux_old_sigtrap_action.sa_sigaction(
        signum, (siginfo_t *)siginfo_ptr, ucontext_ptr);
    return STACKABLE_LINUX_PATCH_OK;
  }
  if (stackable_linux_old_sigtrap_action.sa_handler == SIG_DFL ||
      stackable_linux_old_sigtrap_action.sa_handler == SIG_IGN ||
      stackable_linux_old_sigtrap_action.sa_handler == NULL) {
    return STACKABLE_LINUX_PATCH_TRAP_CHAIN_UNAVAILABLE;
  }
  stackable_linux_old_sigtrap_action.sa_handler(signum);
  return STACKABLE_LINUX_PATCH_OK;
}

enum {
  STACKABLE_LINUX_ATOMIC_NONE = 0,
  STACKABLE_LINUX_ATOMIC_LOCK_RMW = 1,
  STACKABLE_LINUX_ATOMIC_XCHG_MEM = 2,
  STACKABLE_LINUX_ATOMIC_MFENCE = 3,
  STACKABLE_LINUX_ATOMIC_SFENCE = 4,
  STACKABLE_LINUX_ATOMIC_LFENCE = 5
};

enum {
  STACKABLE_LINUX_ATOMIC_STRATEGY_NONE = 0,
  STACKABLE_LINUX_ATOMIC_STRATEGY_JMP_REL32 = 1,
  STACKABLE_LINUX_ATOMIC_STRATEGY_INT3 = 2
};

static void stackable_linux_init_atomic_window(
    struct stackable_linux_atomic_window *out) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->diagnostic = STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  out->modrm_offset = -1;
  out->opcode_offset = -1;
}

static int stackable_linux_atomic_read_modrm_tail(
    const unsigned char *bytes, size_t len, size_t *pos, unsigned char modrm,
    size_t imm_len) {
  unsigned char mod = (unsigned char)((modrm >> 6) & 0x3);
  unsigned char rm = (unsigned char)(modrm & 0x7);
  if (mod != 3 && rm == 4) {
    if (*pos >= len) return 0;
    unsigned char sib = bytes[(*pos)++];
    unsigned char base = (unsigned char)(sib & 0x7);
    if (mod == 0 && base == 5) {
      if (*pos + 4 > len) return 0;
      *pos += 4;
    }
  }
  if (mod == 1) {
    if (*pos + 1 > len) return 0;
    *pos += 1;
  } else if (mod == 2 || (mod == 0 && rm == 5)) {
    if (*pos + 4 > len) return 0;
    *pos += 4;
  }
  if (*pos + imm_len > len) return 0;
  *pos += imm_len;
  return 1;
}

static int stackable_linux_atomic_memory_modrm(unsigned char modrm) {
  return ((modrm >> 6) & 0x3) != 0x3;
}

static int stackable_linux_lockable_one_byte(unsigned char op,
                                             unsigned char modrm) {
  switch (op) {
    case 0x00: case 0x01: case 0x08: case 0x09:
    case 0x10: case 0x11: case 0x18: case 0x19:
    case 0x20: case 0x21: case 0x28: case 0x29:
    case 0x30: case 0x31:
      return 1;
    case 0x80: case 0x81: case 0x83:
      return ((modrm >> 3) & 0x7) != 0x7;
    case 0xf6: case 0xf7: {
      unsigned char reg = (unsigned char)((modrm >> 3) & 0x7);
      return reg == 2 || reg == 3;
    }
    case 0xfe: case 0xff: {
      unsigned char reg = (unsigned char)((modrm >> 3) & 0x7);
      return reg == 0 || reg == 1;
    }
    default:
      return 0;
  }
}

static int stackable_linux_lockable_two_byte(unsigned char op2,
                                             unsigned char modrm) {
  switch (op2) {
    case 0xab: case 0xb0: case 0xb1: case 0xb3:
    case 0xbb: case 0xc0: case 0xc1:
      return 1;
    case 0xba: {
      unsigned char reg = (unsigned char)((modrm >> 3) & 0x7);
      return reg >= 5 && reg <= 7;
    }
    default:
      return 0;
  }
}

int stackable_linux_classify_atomic_window(
    unsigned char *bytes, unsigned long len,
    struct stackable_linux_atomic_window *out) {
  stackable_linux_init_atomic_window(out);
  if (bytes == NULL || len == 0 || out == NULL) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  size_t i = 0;
  int saw_lock = 0;
  int saw_legacy_prefix = 0;
  for (;;) {
    if (i >= (size_t)len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    unsigned char b = bytes[i];
    if (b == 0xf0) { saw_lock = 1; i++; continue; }
    if (b == 0x66 || b == 0x67 || b == 0xf2 || b == 0xf3 ||
        b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e ||
        b == 0x64 || b == 0x65) {
      saw_legacy_prefix = 1;
      i++;
      continue;
    }
    break;
  }
  if (i < (size_t)len && bytes[i] >= 0x40 && bytes[i] <= 0x4f) i++;
  if (i >= (size_t)len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;

  size_t opcode_offset = i;
  unsigned char op = bytes[i++];
  if (op == 0x0f) {
    if (i >= (size_t)len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    unsigned char op2 = bytes[i++];
    if (op2 == 0xae) {
      if (i >= (size_t)len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
      unsigned char modrm = bytes[i++];
      if (!saw_lock && !saw_legacy_prefix && opcode_offset == 0 &&
          (modrm == 0xf0 || modrm == 0xf8 || modrm == 0xe8)) {
        out->diagnostic = STACKABLE_LINUX_PATCH_OK;
        out->kind = modrm == 0xf0 ? STACKABLE_LINUX_ATOMIC_MFENCE :
                    modrm == 0xf8 ? STACKABLE_LINUX_ATOMIC_SFENCE :
                                     STACKABLE_LINUX_ATOMIC_LFENCE;
        out->length = (unsigned long)i;
        out->lock_prefixed = saw_lock;
        out->memory_operand = 0;
        out->modrm_offset = (long)(i - 1);
        out->opcode_offset = (long)opcode_offset;
        out->opcode0 = op;
        out->opcode1 = op2;
        return STACKABLE_LINUX_PATCH_OK;
      }
      return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    }
    if (i >= (size_t)len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    size_t modrm_offset = i;
    unsigned char modrm = bytes[i++];
    size_t imm_len = op2 == 0xba ? 1 : 0;
    if (!stackable_linux_atomic_read_modrm_tail(bytes, (size_t)len, &i,
                                                modrm, imm_len)) {
      return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    }
    if (saw_lock && stackable_linux_atomic_memory_modrm(modrm) &&
        stackable_linux_lockable_two_byte(op2, modrm)) {
      out->diagnostic = STACKABLE_LINUX_PATCH_OK;
      out->kind = STACKABLE_LINUX_ATOMIC_LOCK_RMW;
      out->length = (unsigned long)i;
      out->lock_prefixed = 1;
      out->memory_operand = 1;
      out->modrm_offset = (long)modrm_offset;
      out->opcode_offset = (long)opcode_offset;
      out->opcode0 = op;
      out->opcode1 = op2;
      return STACKABLE_LINUX_PATCH_OK;
    }
    return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  }

  if (op == 0x86 || op == 0x87) {
    if (i >= (size_t)len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    size_t modrm_offset = i;
    unsigned char modrm = bytes[i++];
    if (!stackable_linux_atomic_read_modrm_tail(bytes, (size_t)len, &i,
                                                modrm, 0)) {
      return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
    }
    if (stackable_linux_atomic_memory_modrm(modrm)) {
      out->diagnostic = STACKABLE_LINUX_PATCH_OK;
      out->kind = STACKABLE_LINUX_ATOMIC_XCHG_MEM;
      out->length = (unsigned long)i;
      out->lock_prefixed = saw_lock;
      out->memory_operand = 1;
      out->modrm_offset = (long)modrm_offset;
      out->opcode_offset = (long)opcode_offset;
      out->opcode0 = op;
      return STACKABLE_LINUX_PATCH_OK;
    }
    return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  }

  if (!saw_lock) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  if (i >= (size_t)len) return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  size_t modrm_offset = i;
  unsigned char modrm = bytes[i++];
  size_t imm_len = 0;
  if (op == 0x80 || op == 0x83) imm_len = 1;
  else if (op == 0x81) imm_len = 4;
  else if (op == 0xf6) {
    unsigned char reg = (unsigned char)((modrm >> 3) & 0x7);
    if (reg == 0 || reg == 1) imm_len = 1;
  } else if (op == 0xf7) {
    unsigned char reg = (unsigned char)((modrm >> 3) & 0x7);
    if (reg == 0 || reg == 1) imm_len = 4;
  }
  if (!stackable_linux_atomic_read_modrm_tail(bytes, (size_t)len, &i,
                                              modrm, imm_len)) {
    return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
  }
  if (stackable_linux_atomic_memory_modrm(modrm) &&
      stackable_linux_lockable_one_byte(op, modrm)) {
    out->diagnostic = STACKABLE_LINUX_PATCH_OK;
    out->kind = STACKABLE_LINUX_ATOMIC_LOCK_RMW;
    out->length = (unsigned long)i;
    out->lock_prefixed = 1;
    out->memory_operand = 1;
    out->modrm_offset = (long)modrm_offset;
    out->opcode_offset = (long)opcode_offset;
    out->opcode0 = op;
    return STACKABLE_LINUX_PATCH_OK;
  }
  return STACKABLE_LINUX_PATCH_UNSUPPORTED_INSTRUCTION;
}

static int stackable_linux_rel32_reachable(uintptr_t site_after_patch,
                                           uintptr_t target,
                                           long long *out_disp) {
  long long disp = (long long)((int64_t)target - (int64_t)site_after_patch);
  if (out_disp) *out_disp = disp;
  return disp >= -2147483648LL && disp <= 2147483647LL;
}

int stackable_linux_select_atomic_patch_strategy(
    unsigned long target, unsigned long trampoline, unsigned long instruction_len,
    struct stackable_linux_atomic_patch_decision *out) {
  if (out) {
    memset(out, 0, sizeof(*out));
    out->target = target;
    out->trampoline = trampoline;
    out->instruction_length = instruction_len;
  }
  if (target == 0 || trampoline == 0 || instruction_len == 0) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  long long disp = 0;
  int reachable = stackable_linux_rel32_reachable(
      (uintptr_t)target + 5U, (uintptr_t)trampoline, &disp);
  if (instruction_len >= 5 && reachable) {
    if (out) {
      out->diagnostic = STACKABLE_LINUX_PATCH_OK;
      out->strategy = STACKABLE_LINUX_ATOMIC_STRATEGY_JMP_REL32;
      out->patch_size = 5;
      out->rel32_displacement = disp;
    }
    return STACKABLE_LINUX_PATCH_OK;
  }
  if (out) {
    out->diagnostic = STACKABLE_LINUX_PATCH_OK;
    out->strategy = STACKABLE_LINUX_ATOMIC_STRATEGY_INT3;
    out->patch_size = 1;
    out->rel32_displacement = disp;
  }
  return STACKABLE_LINUX_PATCH_OK;
}

int stackable_linux_allocate_near_trampoline(
    unsigned long anchor, unsigned long length,
    struct stackable_linux_near_allocation *out) {
  if (out) {
    memset(out, 0, sizeof(*out));
    out->anchor = anchor;
    out->length = length;
  }
  if (anchor == 0 || length == 0) {
    if (out) out->diagnostic = STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
    return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  }
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) page_size = 4096;
  uintptr_t page_mask = (uintptr_t)(page_size - 1);
  size_t span = (size_t)((length + (unsigned long)page_mask) & ~((unsigned long)page_mask));
  if (span == 0) span = (size_t)page_size;

  long mapped = stackable_linux_raw_mmap(NULL, span, PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapped >= 0) {
    long long disp = 0;
    if (stackable_linux_rel32_reachable(anchor + 5U, (uintptr_t)mapped, &disp)) {
      if (out) {
        out->diagnostic = STACKABLE_LINUX_PATCH_OK;
        out->address = (unsigned long)mapped;
        out->length = (unsigned long)span;
        out->within_rel32 = 1;
      }
      return STACKABLE_LINUX_PATCH_OK;
    }
    (void)stackable_linux_raw_munmap((void *)(uintptr_t)mapped, span);
  }

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
  uintptr_t base = ((uintptr_t)anchor) & ~page_mask;
  const uintptr_t step = (uintptr_t)page_size * 64U;
  const uintptr_t limit = 0x7fffffffUL;
  for (uintptr_t delta = step; delta < limit; delta += step) {
    for (int dir = -1; dir <= 1; dir += 2) {
      uintptr_t candidate = dir < 0 ? base - delta : base + delta;
      if (dir < 0 && candidate > base) continue;
      if (candidate + span <= candidate) continue;
      long m = stackable_linux_raw_mmap((void *)candidate, span,
          PROT_READ | PROT_WRITE,
          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
      if (m < 0) {
        if (out && out->os_errno == 0) out->os_errno = (int)(-m);
        continue;
      }
      if (out) {
        out->diagnostic = STACKABLE_LINUX_PATCH_OK;
        out->address = (unsigned long)m;
        out->length = (unsigned long)span;
        out->within_rel32 = stackable_linux_rel32_reachable(
            anchor + 5U, (uintptr_t)m, NULL);
      }
      return STACKABLE_LINUX_PATCH_OK;
    }
  }
  if (out) out->diagnostic = STACKABLE_LINUX_PATCH_TRAMPOLINE_ALLOC_FAILED;
  return STACKABLE_LINUX_PATCH_TRAMPOLINE_ALLOC_FAILED;
}

int stackable_linux_free_near_trampoline(unsigned long address,
                                         unsigned long length) {
  if (address == 0 || length == 0) return STACKABLE_LINUX_PATCH_INVALID_ARGUMENT;
  long rc = stackable_linux_raw_munmap((void *)(uintptr_t)address,
                                       (size_t)length);
  if (rc < 0) return STACKABLE_LINUX_PATCH_RESTORE_FAILED;
  return STACKABLE_LINUX_PATCH_OK;
}
""".}

  proc cRawSyscall6(nr, a1, a2, a3, a4, a5, a6: clong): clong
    {.importc: "stackable_linux_raw_syscall6", cdecl.}
  proc cStaticRawSyscall6(nr, a1, a2, a3, a4, a5, a6: clong): clong
    {.importc: "stackable_linux_static_raw_syscall6", cdecl.}
  proc cRtSigreturnRestorer()
    {.importc: "stackable_linux_rt_sigreturn_restorer", cdecl.}
  proc cCloneContinuationTrampoline(nr, a1, a2, a3, a4, a5, a6: clong;
                                    resumeRip: pointer; userGregs: ptr clong): clong
    {.importc: "stackable_linux_clone_continuation_trampoline", cdecl.}
  proc cIsDefaultCloneContinuationSyscall(nr: clong): cint
    {.importc: "stackable_linux_is_default_clone_continuation_syscall", cdecl.}
  proc cComputeCloneContinuation(regs: ptr CStackableLinuxSyscallRegs;
                                 parentResult: clong; cloneLike: cint;
                                 outState: ptr CStackableLinuxCloneContinuation): cint
    {.importc: "stackable_linux_compute_clone_continuation", cdecl.}
  proc cResolveDefaultSymbol(name: cstring): pointer
    {.importc: "stackable_linux_resolve_default_symbol", cdecl.}
  proc cOpenLibraryNoLoad(soname: cstring): pointer
    {.importc: "stackable_linux_open_library_noload", cdecl.}
  proc cResolveSymbolInHandle(handle: pointer; name: cstring): pointer
    {.importc: "stackable_linux_resolve_symbol_in_handle", cdecl.}
  proc cPatchAbsoluteJumpTx(target, replacement: pointer; captureRestore: cint;
                            outResult: ptr CStackableLinuxPatchResult): cint
    {.importc: "stackable_linux_patch_absolute_jump_tx", cdecl.}
  proc cMeasureOriginalTrampoline(target: pointer; minPatchLen, maxScan: culong;
                                  outResult: ptr CStackableLinuxTrampolineResult): cint
    {.importc: "stackable_linux_measure_original_trampoline", cdecl.}
  proc cBuildOriginalTrampoline(target: pointer; minPatchLen, maxScan: culong;
                                outResult: ptr CStackableLinuxTrampolineResult): cint
    {.importc: "stackable_linux_build_original_trampoline", cdecl.}
  proc cRestoreAbsoluteJump(target: pointer; saved14: ptr byte;
                            outErrno: ptr cint): cint
    {.importc: "stackable_linux_restore_absolute_jump", cdecl.}
  proc cAddrInExecutableSegment(address: culong): cint
    {.importc: "stackable_linux_addr_in_executable_segment", cdecl.}
  proc cPatchRegistryReset()
    {.importc: "stackable_linux_patch_registry_reset", cdecl.}
  proc cPatchRegistryContains(address: culong): cint
    {.importc: "stackable_linux_patch_registry_contains", cdecl.}
  proc cPatchRegistryRecord(address: culong): cint
    {.importc: "stackable_linux_patch_registry_record", cdecl.}
  proc cPatchInt3SyscallTx(target: pointer;
                           outResult: ptr CStackableLinuxInt3PatchResult): cint
    {.importc: "stackable_linux_patch_int3_syscall_tx", cdecl.}
  proc cRestoreInt3Syscall(target: pointer; originalFirstByte: byte;
                           outErrno: ptr cint): cint
    {.importc: "stackable_linux_restore_int3_syscall", cdecl.}
  proc cCaptureSyscallRegsFromUcontext(ucontext: pointer;
                                       outRegs: ptr CStackableLinuxSyscallRegs): cint
    {.importc: "stackable_linux_capture_syscall_regs_from_ucontext", cdecl.}
  proc cWriteSyscallResultToUcontext(ucontext: pointer; result: clong;
                                     resumeRip: culong): cint
    {.importc: "stackable_linux_write_syscall_result_to_ucontext", cdecl.}
  proc cReplaySyscallRegs(regs: ptr CStackableLinuxSyscallRegs): clong
    {.importc: "stackable_linux_replay_syscall_regs", cdecl.}
  proc cInstallSigtrapHandler(handler: pointer; extraFlags: cint): cint
    {.importc: "stackable_linux_install_sigtrap_handler", cdecl.}
  proc cUninstallSigtrapHandler(): cint
    {.importc: "stackable_linux_uninstall_sigtrap_handler", cdecl.}
  proc cChainSigtrap(signum: cint; siginfo: pointer; ucontext: pointer): cint
    {.importc: "stackable_linux_chain_sigtrap", cdecl.}
  proc cLocateVdsoImage(outImage: ptr CStackableLinuxVdsoImage): cint
    {.importc: "stackable_linux_locate_vdso_image", cdecl.}
  proc cParseVdsoImageAt(base: culong; outImage: ptr CStackableLinuxVdsoImage): cint
    {.importc: "stackable_linux_parse_vdso_image_at", cdecl.}
  proc cResolveVdsoSymbol(image: ptr CStackableLinuxVdsoImage; name: cstring;
                          outSymbol: ptr CStackableLinuxVdsoSymbol): cint
    {.importc: "stackable_linux_resolve_vdso_symbol", cdecl.}
  proc cVdsoOverlayPatchTx(imageBase, imageLen: culong; target, replacement: pointer;
                           outResult: ptr CStackableLinuxVdsoPatchResult): cint
    {.importc: "stackable_linux_vdso_overlay_patch_tx", cdecl.}
  proc cVdsoPatchSymbolTx(image: ptr CStackableLinuxVdsoImage; name: cstring;
                          replacement: pointer; allowOverlay: cint;
                          outResult: ptr CStackableLinuxVdsoPatchResult): cint
    {.importc: "stackable_linux_vdso_patch_symbol_tx", cdecl.}
  proc cClassifyAtomicWindow(bytes: ptr byte; length: culong;
                             outResult: ptr CStackableLinuxAtomicWindow): cint
    {.importc: "stackable_linux_classify_atomic_window", cdecl.}
  proc cSelectAtomicPatchStrategy(target, trampoline, instructionLen: culong;
                                  outResult: ptr CStackableLinuxAtomicPatchDecision): cint
    {.importc: "stackable_linux_select_atomic_patch_strategy", cdecl.}
  proc cAllocateNearTrampoline(anchor, length: culong;
                               outResult: ptr CStackableLinuxNearAllocation): cint
    {.importc: "stackable_linux_allocate_near_trampoline", cdecl.}
  proc cFreeNearTrampoline(address, length: culong): cint
    {.importc: "stackable_linux_free_near_trampoline", cdecl.}

proc rawSyscall6*(nr, a1, a2, a3, a4, a5, a6: int): int =
  ## Issue a Linux x86_64 raw syscall using the kernel calling convention.
  ## Unsupported platforms return `-38` (`ENOSYS`) instead of silently
  ## pretending success.
  when defined(linux) and defined(amd64):
    int(cRawSyscall6(clong(nr), clong(a1), clong(a2), clong(a3), clong(a4),
                     clong(a5), clong(a6)))
  else:
    -38

proc staticRawSyscall6*(nr, a1, a2, a3, a4, a5, a6: int): int =
  ## C ABI raw syscall entry intended for static-runtime/no-libc helper code.
  ## It has the same raw-kernel-result contract as `rawSyscall6`; the separate
  ## symbol lets C consumers avoid linking against libc's `syscall` wrapper.
  when defined(linux) and defined(amd64):
    int(cStaticRawSyscall6(clong(nr), clong(a1), clong(a2), clong(a3),
                           clong(a4), clong(a5), clong(a6)))
  else:
    -38

proc rtSigreturnRestorerAddress*(): pointer =
  ## Address of the x86_64 `rt_sigreturn` restorer stub exported for consumers
  ## that install signal handlers via raw `rt_sigaction`. Do not call it
  ## directly; it is only meaningful as a kernel signal-restorer address.
  when defined(linux) and defined(amd64):
    cast[pointer](cRtSigreturnRestorer)
  else:
    nil

proc cloneContinuationTrampolineAddress*(): pointer =
  ## Address of the low-level clone/fork/vfork continuation trampoline. It is
  ## exported for C/static-runtime consumers; normal Nim code should use the
  ## continuation-state helpers to decide when such a trampoline is required.
  when defined(linux) and defined(amd64):
    cast[pointer](cCloneContinuationTrampoline)
  else:
    nil

proc resolveDefaultSymbol*(name: cstring): pointer =
  ## Resolve an exported process symbol with `dlsym(RTLD_DEFAULT, name)`.
  ## This is intentionally only resolution; consumers decide whether the symbol
  ## belongs to libc, vDSO, or another interpose target set.
  if linuxRawSyscallSupported() != lrsOk or name == nil:
    return nil
  when defined(linux) and defined(amd64):
    cResolveDefaultSymbol(name)
  else:
    nil

proc openLibraryNoLoad*(soname: cstring): pointer =
  ## Open an already-loaded library without loading a new copy. Consumers choose
  ## which SONAMEs matter; this helper just exposes the reusable `dlopen`
  ## building block needed for resolver chains.
  if linuxRawSyscallSupported() != lrsOk or soname == nil:
    return nil
  when defined(linux) and defined(amd64):
    cOpenLibraryNoLoad(soname)
  else:
    nil

proc resolveSymbolInHandle*(handle: pointer; name: cstring): pointer =
  ## Resolve `name` through an explicit handle. A nil handle maps to
  ## `RTLD_DEFAULT`, matching `dlsym`'s conventional resolver sentinel.
  if linuxRawSyscallSupported() != lrsOk or name == nil:
    return nil
  when defined(linux) and defined(amd64):
    cResolveSymbolInHandle(handle, name)
  else:
    nil

proc defaultSymbolResolver*(): LinuxSymbolResolver =
  LinuxSymbolResolver(kind: lsrDefault)

proc handleSymbolResolver*(handle: pointer): LinuxSymbolResolver =
  LinuxSymbolResolver(kind: lsrHandle, handle: handle)

proc resolveSymbolChain*(name: cstring;
                         resolvers: openArray[LinuxSymbolResolver]): pointer =
  ## Resolve `name` by trying consumer-supplied resolver steps in order. This is
  ## enough to express policies such as RTLD_DEFAULT, then an opened libc
  ## RTLD_NOLOAD handle, without hard-wiring that policy into the framework.
  if name == nil:
    return nil
  for resolver in resolvers:
    let resolved =
      case resolver.kind
      of lsrDefault:
        resolveDefaultSymbol(name)
      of lsrHandle:
        resolveSymbolInHandle(resolver.handle, name)
    if resolved != nil:
      return resolved
  nil

proc toDiagnostic(rc: cint): LinuxRawSyscallDiagnostic {.used.} =
  case int(rc)
  of 0: lrsOk
  of 1: lrsUnsupportedPlatform
  of 2: lrsUnsupportedArchitecture
  of 3: lrsInvalidArgument
  of 4: lrsSymbolNotFound
  of 5: lrsAlreadyPatched
  of 6: lrsMprotectFailed
  of 7: lrsPrePatchMprotectFailed
  of 8: lrsPatchWriteFailed
  of 9: lrsPostPatchMprotectBackFailed
  of 10: lrsRestoreFailed
  of 11: lrsUnsupportedInstruction
  of 12: lrsTrampolineAllocFailed
  of 13: lrsTrampolineBuildFailed
  of 14: lrsNotSyscallSite
  of 15: lrsTrapInstallFailed
  of 16: lrsTrapChainUnavailable
  of 17: lrsVdsoNotFound
  of 18: lrsVdsoNotElf
  of 19: lrsVdsoNoDynamic
  of 20: lrsVdsoNoSymbolTable
  of 21: lrsVdsoSymbolNotFound
  of 22: lrsVdsoDirectPatchFailed
  of 23: lrsVdsoOverlayFailed
  else: lrsPatchWriteFailed

proc toPatchStage(stage: cint): LinuxPatchStage {.used.} =
  case int(stage)
  of 0: lpsNone
  of 1: lpsValidateTarget
  of 2: lpsPrePatchMprotect
  of 3: lpsWritePatch
  of 4: lpsPostPatchMprotectBack
  of 5: lpsComplete
  else: lpsNone

proc fromCTransaction(cres: CStackableLinuxPatchResult): LinuxPatchTransaction {.used.} =
  when defined(linux) and defined(amd64):
    result.handle.target = cast[pointer](cres.target)
    result.handle.replacement = cast[pointer](cres.replacement)
    result.handle.patchSize = int(cres.patchSize)
    result.handle.originalBytes = cres.original
    result.handle.active = cres.patchLive != 0
    result.handle.diagnostic = toDiagnostic(cres.diagnostic)
    result.handle.osErrno = cres.osErrno
    result.stage = toPatchStage(cres.stage)
    result.diagnostic = toDiagnostic(cres.diagnostic)
    result.osErrno = cres.osErrno
    result.patchLive = cres.patchLive != 0
    result.restoreBytesCaptured = cres.restoreCaptured != 0
  else:
    discard

proc fromCTrampoline(cres: CStackableLinuxTrampolineResult): LinuxOriginalTrampoline {.used.} =
  when defined(linux) and defined(amd64):
    result.target = cast[pointer](cres.target)
    result.entry = cast[pointer](cres.entry)
    result.copiedLen = int(cres.copiedLen)
    result.minPatchLen = int(cres.minPatchLen)
    result.diagnostic = toDiagnostic(cres.diagnostic)
    result.osErrno = cres.osErrno
    result.unsupportedOffset = int(cres.unsupportedOffset)
  else:
    discard

proc fromCInt3Transaction(cres: CStackableLinuxInt3PatchResult): LinuxInt3PatchTransaction {.used.} =
  when defined(linux) and defined(amd64):
    result.handle.target = cast[pointer](cres.target)
    result.handle.originalFirstByte = cres.originalFirstByte
    result.handle.secondByte = cres.secondByte
    result.handle.active = cres.patchLive != 0
    result.handle.diagnostic = toDiagnostic(cres.diagnostic)
    result.handle.osErrno = cres.osErrno
    result.stage = toPatchStage(cres.stage)
    result.diagnostic = toDiagnostic(cres.diagnostic)
    result.osErrno = cres.osErrno
    result.patchLive = cres.patchLive != 0
    result.restoreByteCaptured = cres.restoreCaptured != 0
  else:
    discard

proc fromCSyscallRegs(cres: CStackableLinuxSyscallRegs): LinuxX8664SyscallRegisters {.used.} =
  when defined(linux) and defined(amd64):
    result.syscallNumber = int(cres.nr)
    for i in 0 ..< 6:
      result.args[i] = int(cres.args[i])
    result.result = int(cres.result)
    result.trapRip = uint(cres.trapRip)
    result.syscallAddress = uint(cres.syscallAddress)
    result.resumeRip = uint(cres.resumeRip)
  else:
    discard

proc toCSyscallRegs(regs: LinuxX8664SyscallRegisters): CStackableLinuxSyscallRegs {.used.} =
  when defined(linux) and defined(amd64):
    result.nr = clong(regs.syscallNumber)
    for i in 0 ..< 6:
      result.args[i] = clong(regs.args[i])
    result.result = clong(regs.result)
    result.trapRip = culong(regs.trapRip)
    result.syscallAddress = culong(regs.syscallAddress)
    result.resumeRip = culong(regs.resumeRip)
  else:
    discard

proc fromCCloneContinuation(cres: CStackableLinuxCloneContinuation):
    LinuxX8664CloneContinuation {.used.} =
  when defined(linux) and defined(amd64):
    result.cloneLike = cres.cloneLike != 0
    result.syscallNumber = int(cres.nr)
    result.syscallAddress = uint(cres.syscallAddress)
    result.trapRip = uint(cres.trapRip)
    result.resumeRip = uint(cres.resumeRip)
    result.parentResult = int(cres.parentResult)
    result.parentResumeRip = uint(cres.parentResumeRip)
    result.childResult = int(cres.childResult)
    result.childResumeRip = uint(cres.childResumeRip)
  else:
    discard

proc fromCVdsoImage(cres: CStackableLinuxVdsoImage): LinuxVdsoImage {.used.} =
  when defined(linux) and defined(amd64):
    result.base = cast[pointer](cres.base)
    result.length = int(cres.length)
    result.loadMaxAddress = uint(cres.loadMaxAddress)
    result.dynamicAddress = cast[pointer](cres.dynamicAddress)
    result.symbolTable = cast[pointer](cres.symbolTable)
    result.stringTable = cast[pointer](cres.stringTable)
    result.symbolEntrySize = int(cres.symbolEntrySize)
    result.symbolCount = int(cres.symbolCount)
    result.stringTableSize = int(cres.stringTableSize)
    result.diagnostic = toDiagnostic(cres.diagnostic)
    result.osErrno = cres.osErrno
  else:
    discard

proc toCVdsoImage(image: LinuxVdsoImage): CStackableLinuxVdsoImage {.used.} =
  when defined(linux) and defined(amd64):
    result.diagnostic = cint(ord(image.diagnostic))
    result.osErrno = image.osErrno
    result.base = culong(cast[uint](image.base))
    result.length = culong(image.length)
    result.loadMaxAddress = culong(image.loadMaxAddress)
    result.dynamicAddress = culong(cast[uint](image.dynamicAddress))
    result.symbolTable = culong(cast[uint](image.symbolTable))
    result.stringTable = culong(cast[uint](image.stringTable))
    result.symbolEntrySize = culong(image.symbolEntrySize)
    result.symbolCount = culong(image.symbolCount)
    result.stringTableSize = culong(image.stringTableSize)
  else:
    discard

proc fromCVdsoSymbol(cres: CStackableLinuxVdsoSymbol;
                     name: cstring): LinuxVdsoSymbol {.used.} =
  when defined(linux) and defined(amd64):
    result.name = if name == nil: "" else: $name
    result.address = cast[pointer](cres.address)
    result.size = int(cres.size)
    result.info = cres.info
    result.other = cres.other
    result.sectionIndex = int(cres.sectionIndex)
    result.diagnostic = toDiagnostic(cres.diagnostic)
  else:
    discard

proc fromCVdsoPatch(cres: CStackableLinuxVdsoPatchResult;
                    image: LinuxVdsoImage;
                    name: cstring): LinuxVdsoPatchTransaction {.used.} =
  when defined(linux) and defined(amd64):
    result.image = image
    result.symbol = LinuxVdsoSymbol(
      name: if name == nil: "" else: $name,
      address: cast[pointer](cres.symbolAddress),
      diagnostic: if cres.symbolAddress == 0:
        toDiagnostic(cres.diagnostic)
      else:
        lrsOk)
    result.replacement = cast[pointer](cres.replacement)
    result.path =
      case int(cres.path)
      of 1: lvppDirect
      of 2: lvppOverlay
      else: lvppNone
    result.diagnostic = toDiagnostic(cres.diagnostic)
    result.directDiagnostic = toDiagnostic(cres.directDiagnostic)
    result.overlayDiagnostic = toDiagnostic(cres.overlayDiagnostic)
    result.osErrno = cres.osErrno
    result.patchLive = cres.patchLive != 0
    result.overlayUsed = cres.overlayUsed != 0
    result.direct = fromCTransaction(cres.direct)
  else:
    discard

proc toAtomicKind(kind: cint): LinuxAtomicInstructionKind {.used.} =
  case int(kind)
  of 1: laikLockRmw
  of 2: laikXchgMem
  of 3: laikMfence
  of 4: laikSfence
  of 5: laikLfence
  else: laikNone

proc toAtomicStrategy(strategy: cint): LinuxAtomicPatchStrategy {.used.} =
  case int(strategy)
  of 1: lapsJmpRel32
  of 2: lapsInt3
  else: lapsNone

proc fromCAtomicWindow(cres: CStackableLinuxAtomicWindow): LinuxAtomicInstructionWindow {.used.} =
  when defined(linux) and defined(amd64):
    result.diagnostic = toDiagnostic(cres.diagnostic)
    result.kind = toAtomicKind(cres.kind)
    result.length = int(cres.length)
    result.lockPrefixed = cres.lockPrefixed != 0
    result.memoryOperand = cres.memoryOperand != 0
    result.modrmOffset = int(cres.modrmOffset)
    result.opcodeOffset = int(cres.opcodeOffset)
    result.opcode0 = cres.opcode0
    result.opcode1 = cres.opcode1
  else:
    discard

proc fromCAtomicPatchDecision(cres: CStackableLinuxAtomicPatchDecision):
    LinuxAtomicPatchDecision {.used.} =
  when defined(linux) and defined(amd64):
    result.diagnostic = toDiagnostic(cres.diagnostic)
    result.strategy = toAtomicStrategy(cres.strategy)
    result.target = uint(cres.target)
    result.trampoline = uint(cres.trampoline)
    result.instructionLength = int(cres.instructionLength)
    result.patchSize = int(cres.patchSize)
    result.rel32Displacement = int64(cres.rel32Displacement)
  else:
    discard

proc fromCNearAllocation(cres: CStackableLinuxNearAllocation):
    LinuxNearTrampolineAllocation {.used.} =
  when defined(linux) and defined(amd64):
    result.diagnostic = toDiagnostic(cres.diagnostic)
    result.anchor = uint(cres.anchor)
    result.address = cast[pointer](cres.address)
    result.length = int(cres.length)
    result.withinRel32 = cres.withinRel32 != 0
    result.osErrno = cres.osErrno
  else:
    discard

proc installAbsoluteJumpPatchTransaction*(target, replacement: pointer;
                                          captureRestoreBytes = true): LinuxPatchTransaction =
  ## Install a 14-byte absolute jump and return stage-aware diagnostics. If the
  ## post-patch mprotect-back step fails, `patchLive` is true and the diagnostic
  ## records that security hardening failed after the patch was installed.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    result.handle.diagnostic = support
    return
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxPatchResult
    discard cPatchAbsoluteJumpTx(target, replacement,
                                 if captureRestoreBytes: 1 else: 0,
                                 addr cres)
    result = fromCTransaction(cres)
  else:
    result.diagnostic = support
    result.handle.diagnostic = support

proc locateLinuxVdsoImage*(): LinuxVdsoImage =
  ## Locate and parse the live Linux x86_64 vDSO image via AT_SYSINFO_EHDR.
  ## The returned image is only a description; no patching or target selection
  ## occurs here.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    return
  when defined(linux) and defined(amd64):
    var cimage: CStackableLinuxVdsoImage
    discard cLocateVdsoImage(addr cimage)
    result = fromCVdsoImage(cimage)
  else:
    result.diagnostic = support

proc parseLinuxVdsoImageAt*(base: pointer): LinuxVdsoImage =
  ## Parse a vDSO-shaped ELF64 image at `base`. Exposed for deterministic
  ## fixtures and for consumers that already found the image through another
  ## mechanism. The helper does not verify that the pointer is the process vDSO.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    return
  if base == nil:
    result.diagnostic = lrsVdsoNotFound
    return
  when defined(linux) and defined(amd64):
    var cimage: CStackableLinuxVdsoImage
    discard cParseVdsoImageAt(culong(cast[uint](base)), addr cimage)
    result = fromCVdsoImage(cimage)
  else:
    result.diagnostic = support

proc resolveLinuxVdsoSymbol*(image: LinuxVdsoImage;
                             name: cstring): LinuxVdsoSymbol =
  ## Resolve one caller-supplied exported symbol name from a parsed vDSO image.
  ## No MCR target list or trampoline policy is embedded in this lookup.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    result.name = if name == nil: "" else: $name
    return
  if name == nil:
    result.diagnostic = lrsInvalidArgument
    return
  when defined(linux) and defined(amd64):
    var cimage = toCVdsoImage(image)
    var csym: CStackableLinuxVdsoSymbol
    discard cResolveVdsoSymbol(addr cimage, name, addr csym)
    result = fromCVdsoSymbol(csym, name)
  else:
    result.diagnostic = support

proc installLinuxVdsoOverlayPatchTransaction*(imageBase: pointer;
                                              imageLength: int;
                                              target, replacement: pointer):
    LinuxVdsoPatchTransaction =
  ## Overlay-patch a caller-supplied vDSO-shaped image range with MAP_FIXED.
  ## This is explicit because MAP_FIXED replaces a mapping. Tests and consumers
  ## should use it only for a known vDSO range or a disposable controlled range.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    result.overlayDiagnostic = support
    return
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxVdsoPatchResult
    discard cVdsoOverlayPatchTx(culong(cast[uint](imageBase)),
                                culong(imageLength), target, replacement,
                                addr cres)
    result = fromCVdsoPatch(cres, LinuxVdsoImage(
      base: imageBase,
      length: imageLength,
      diagnostic: lrsOk), nil)
  else:
    result.diagnostic = support
    result.overlayDiagnostic = support

proc installLinuxVdsoSymbolPatchTransaction*(image: LinuxVdsoImage;
                                             name: cstring;
                                             replacement: pointer;
                                             allowOverlay = false):
    LinuxVdsoPatchTransaction =
  ## Resolve `name` in `image`, then patch the symbol to `replacement`.
  ## The direct path uses the ordinary absolute-jump transaction. If that
  ## fails and `allowOverlay` is true, the helper may replace the image range
  ## with a MAP_FIXED anonymous copy and patch that copy. Consumers must opt in
  ## to overlay because it is intentionally invasive.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    return
  when defined(linux) and defined(amd64):
    var cimage = toCVdsoImage(image)
    var cres: CStackableLinuxVdsoPatchResult
    discard cVdsoPatchSymbolTx(addr cimage, name, replacement,
                               if allowOverlay: 1 else: 0,
                               addr cres)
    result = fromCVdsoPatch(cres, image, name)
  else:
    result.diagnostic = support

proc classifyLinuxX8664AtomicWindow*(bytes: openArray[byte]):
    LinuxAtomicInstructionWindow =
  ## Conservatively classify one x86_64 instruction window relevant to atomic
  ## instrumentation: LOCK-prefixed memory RMW instructions, implicit-lock
  ## memory XCHG, and MFENCE/SFENCE/LFENCE. This is not a complete decoder;
  ## ambiguous or unsupported windows return `lrsUnsupportedInstruction`.
  let support = linuxRawSyscallSupported()
  result.modrmOffset = -1
  result.opcodeOffset = -1
  if support != lrsOk:
    result.diagnostic = support
    return
  if bytes.len == 0:
    result.diagnostic = lrsInvalidArgument
    return
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxAtomicWindow
    discard cClassifyAtomicWindow(unsafeAddr bytes[0], culong(bytes.len),
                                  addr cres)
    result = fromCAtomicWindow(cres)
  else:
    result.diagnostic = support

proc selectLinuxAtomicPatchStrategy*(target: uint;
                                     trampoline: uint;
                                     instructionLength: int):
    LinuxAtomicPatchDecision =
  ## Select the generic POSIX atomic callsite patch shape. A 5-byte JMP-rel32
  ## is selected only when the original instruction window can host it and the
  ## trampoline is reachable from `target + 5`; otherwise INT3 is selected.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    return
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxAtomicPatchDecision
    discard cSelectAtomicPatchStrategy(culong(target), culong(trampoline),
                                       culong(instructionLength), addr cres)
    result = fromCAtomicPatchDecision(cres)
  else:
    result.diagnostic = support

proc selectLinuxAtomicPatchStrategy*(target, trampoline: pointer;
                                     instructionLength: int):
    LinuxAtomicPatchDecision =
  selectLinuxAtomicPatchStrategy(cast[uint](target), cast[uint](trampoline),
                                 instructionLength)

proc allocateLinuxNearTrampoline*(anchor: pointer; length: int):
    LinuxNearTrampolineAllocation =
  ## Allocate a caller-writable mapping near `anchor` where feasible. The helper
  ## owns only allocation/proximity; the caller owns trampoline bytes,
  ## executable-permission hardening, event callbacks, and lifetime policy.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    return
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxNearAllocation
    discard cAllocateNearTrampoline(culong(cast[uint](anchor)), culong(length),
                                    addr cres)
    result = fromCNearAllocation(cres)
  else:
    result.diagnostic = support

proc freeLinuxNearTrampoline*(allocation: LinuxNearTrampolineAllocation):
    LinuxRawSyscallDiagnostic =
  ## Release a mapping returned by `allocateLinuxNearTrampoline`.
  if allocation.address == nil or allocation.length <= 0:
    return lrsInvalidArgument
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return support
  when defined(linux) and defined(amd64):
    toDiagnostic(cFreeNearTrampoline(culong(cast[uint](allocation.address)),
                                     culong(allocation.length)))
  else:
    support

proc addLinuxJitExecutableRange*(registry: var LinuxJitRangeRegistry;
                                 start, stop: uint): bool =
  ## Insert and merge one half-open executable range. Returns false only for an
  ## invalid or overflowed range. Adjacent ranges are merged to keep lifecycle
  ## bookkeeping compact.
  if start >= stop:
    return false
  var mergedStart = start
  var mergedStop = stop
  var first = registry.ranges.len
  var last = registry.ranges.len
  for i, r in registry.ranges:
    if r.stop < start:
      continue
    if r.start > stop:
      if last == registry.ranges.len:
        last = i
      break
    if first == registry.ranges.len:
      first = i
    last = i + 1
    if r.start < mergedStart:
      mergedStart = r.start
    if r.stop > mergedStop:
      mergedStop = r.stop
  if first == registry.ranges.len:
    var ins = 0
    while ins < registry.ranges.len and registry.ranges[ins].stop < start:
      inc ins
    registry.ranges.insert LinuxJitExecutableRange(start: start, stop: stop), ins
    return true
  registry.ranges[first] = LinuxJitExecutableRange(start: mergedStart,
                                                   stop: mergedStop)
  if last > first + 1:
    for _ in first + 1 ..< last:
      registry.ranges.delete(first + 1)
  true

proc removeLinuxJitExecutableRange*(registry: var LinuxJitRangeRegistry;
                                    start, stop: uint) =
  ## Remove `[start, stop)` from the registry, clipping or splitting tracked
  ## ranges. This mirrors mprotect-to-writable lifecycle bookkeeping; consumers
  ## still own reverse patching of any sites in the removed span.
  if start >= stop or registry.ranges.len == 0:
    return
  var i = 0
  while i < registry.ranges.len:
    let r = registry.ranges[i]
    if r.stop <= start:
      inc i
      continue
    if r.start >= stop:
      break
    if r.start >= start and r.stop <= stop:
      registry.ranges.delete(i)
      continue
    if r.start < start and r.stop > stop:
      registry.ranges[i].stop = start
      registry.ranges.insert LinuxJitExecutableRange(start: stop, stop: r.stop),
                             i + 1
      inc i, 2
      continue
    if r.start < start:
      registry.ranges[i].stop = start
      inc i
    else:
      registry.ranges[i].start = stop
      inc i

proc containsLinuxJitExecutableRange*(registry: LinuxJitRangeRegistry;
                                      start, stop: uint): bool =
  ## Return true when `[start, stop)` is fully covered by one tracked range.
  if start >= stop:
    return false
  for r in registry.ranges:
    if r.start <= start and r.stop >= stop:
      return true
    if r.start > start:
      return false
  false

proc untrackedLinuxJitExecutableRanges*(registry: LinuxJitRangeRegistry;
                                        start, stop: uint):
    seq[LinuxJitExecutableRange] =
  ## Return the sub-ranges of `[start, stop)` that are not yet tracked. This is
  ## the reusable dedup primitive needed before a consumer scans fresh JIT code.
  if start >= stop:
    return @[]
  var cursor = start
  for r in registry.ranges:
    if r.stop <= cursor:
      continue
    if r.start >= stop:
      break
    if r.start > cursor:
      result.add LinuxJitExecutableRange(start: cursor, stop: min(r.start, stop))
    if r.stop > cursor:
      cursor = r.stop
    if cursor >= stop:
      break
  if cursor < stop:
    result.add LinuxJitExecutableRange(start: cursor, stop: stop)

proc measureOriginalCallTrampoline*(target: pointer;
                                    minPatchLen = linuxAbsoluteJumpPatchSize;
                                    maxScan = 64): LinuxOriginalTrampoline =
  ## Decode a target wrapper prologue until at least `minPatchLen` bytes can be
  ## copied into an original-call trampoline. This is validation only: no memory
  ## is allocated and unsupported prologues are rejected with
  ## `lrsUnsupportedInstruction`.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    return
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxTrampolineResult
    discard cMeasureOriginalTrampoline(target, culong(minPatchLen), culong(maxScan),
                                       addr cres)
    result = fromCTrampoline(cres)
  else:
    result.diagnostic = support

proc buildOriginalCallTrampoline*(target: pointer;
                                  minPatchLen = linuxAbsoluteJumpPatchSize;
                                  maxScan = 64): LinuxOriginalTrampoline =
  ## Allocate an executable original-call trampoline for a Linux x86_64 wrapper
  ## body patch. The copied prefix is instruction-aware and conservative:
  ## unsupported control-flow instructions, `syscall`, absolute moffs
  ## instructions, and RIP-relative memory operands are rejected rather than
  ## relocated incorrectly. Successful trampolines append a 14-byte absolute
  ## jump back to `target + copiedLen`.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    return
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxTrampolineResult
    discard cBuildOriginalTrampoline(target, culong(minPatchLen), culong(maxScan),
                                     addr cres)
    result = fromCTrampoline(cres)
  else:
    result.diagnostic = support

proc installAbsoluteJumpPatch*(target, replacement: pointer): LinuxPatchHandle =
  ## Patch `target` with `jmp qword ptr [rip+0]; .quad replacement`.
  ## This primitive assumes the caller has already proven installation timing
  ## safety. It does not suspend threads and does not attach consumer policy.
  let tx = installAbsoluteJumpPatchTransaction(target, replacement)
  result = tx.handle
  if tx.diagnostic == lrsPostPatchMprotectBackFailed and tx.patchLive:
    result.diagnostic = lrsOk

proc installNamedAbsoluteJumpPatch*(symbolName: cstring;
                                    replacement: pointer): LinuxPatchHandle =
  ## Resolve `symbolName` in the current process and install an absolute jump.
  ## This supports exported libc/syscall-wrapper style consumers without
  ## hard-wiring the framework to any particular symbol list.
  result.patchSize = linuxAbsoluteJumpPatchSize
  result.replacement = replacement
  result.diagnostic = linuxRawSyscallSupported()
  if result.diagnostic != lrsOk:
    return
  let target = resolveDefaultSymbol(symbolName)
  if target == nil:
    result.diagnostic = lrsSymbolNotFound
    return
  result = installAbsoluteJumpPatch(target, replacement)

proc addrInLinuxExecutableSegment*(address: pointer): bool =
  ## Return true when `address` falls inside any loaded executable PT_LOAD
  ## segment. Consumers decide whether "any executable segment" is sufficient
  ## or whether they need a stricter libc/vDSO/self-exclusion policy.
  if linuxRawSyscallSupported() != lrsOk or address == nil:
    return false
  when defined(linux) and defined(amd64):
    cAddrInExecutableSegment(cast[culong](address)) != 0
  else:
    false

proc clearLinuxPatchBook*() =
  ## Reset the optional in-process duplicate-target helper.
  when defined(linux) and defined(amd64):
    cPatchRegistryReset()

proc linuxPatchBookContains*(address: pointer): bool =
  ## Check whether a consumer previously recorded this target address in the
  ## optional duplicate-target helper.
  if address == nil:
    return false
  when defined(linux) and defined(amd64):
    cPatchRegistryContains(cast[culong](address)) != 0
  else:
    false

proc recordLinuxPatchBookTarget*(address: pointer): cint =
  ## Record an address in the optional duplicate-target helper. Returns 0 for a
  ## new address, 1 for duplicate, and -1 when the fixed helper table is full.
  if address == nil:
    return cint(-1)
  when defined(linux) and defined(amd64):
    cPatchRegistryRecord(cast[culong](address))
  else:
    cint(-1)

proc restoreAbsoluteJumpPatch*(handle: var LinuxPatchHandle): LinuxRawSyscallDiagnostic =
  ## Restore bytes saved by `installAbsoluteJumpPatch`.
  if handle.diagnostic != lrsOk:
    return handle.diagnostic
  if not handle.active:
    return lrsInvalidArgument
  when defined(linux) and defined(amd64):
    var osErr: cint
    let rc = cRestoreAbsoluteJump(handle.target, unsafeAddr handle.originalBytes[0],
                                  addr osErr)
    handle.osErrno = osErr
    if rc == 0:
      handle.active = false
      lrsOk
    else:
      lrsRestoreFailed
  else:
    linuxRawSyscallSupported()

proc addLinuxInt3Callsite*(table: var LinuxInt3CallsiteTable;
                           address: uint;
                           originalFirstByte: byte = linuxSyscallOpcode0;
                           patched = false): bool =
  ## Insert one callsite while preserving sort order. Returns false for a
  ## duplicate address. No mapping selection or patch policy is implied.
  var lo = 0
  var hi = table.sites.len
  while lo < hi:
    let mid = lo + ((hi - lo) shr 1)
    if table.sites[mid].address < address:
      lo = mid + 1
    else:
      hi = mid
  if lo < table.sites.len and table.sites[lo].address == address:
    return false
  table.sites.insert LinuxInt3Callsite(
    address: address,
    originalFirstByte: originalFirstByte,
    patched: patched), lo
  true

proc findLinuxInt3Callsite*(table: LinuxInt3CallsiteTable;
                            address: uint): int =
  ## Return the sorted-table index for `address`, or `-1`.
  var lo = 0
  var hi = table.sites.len
  while lo < hi:
    let mid = lo + ((hi - lo) shr 1)
    if table.sites[mid].address == address:
      return mid
    if table.sites[mid].address < address:
      lo = mid + 1
    else:
      hi = mid
  -1

proc findLinuxInt3CallsiteForTrapRip*(table: LinuxInt3CallsiteTable;
                                      trapRip: uint): int =
  ## Lookup using the saved RIP from an x86_64 Linux INT3 SIGTRAP. The CPU
  ## reports RIP after the 1-byte INT3, so the original callsite is `RIP - 1`.
  if trapRip == 0:
    return -1
  findLinuxInt3Callsite(table, trapRip - 1)

proc installInt3SyscallPatchTransaction*(target: pointer): LinuxInt3PatchTransaction =
  ## Replace byte 0 of a selected Linux x86_64 raw syscall (`0f 05`) with
  ## `INT3` and capture the restore byte. This does not install a handler and
  ## does not decide which mappings should be patched.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    result.diagnostic = support
    result.handle.diagnostic = support
    return
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxInt3PatchResult
    discard cPatchInt3SyscallTx(target, addr cres)
    result = fromCInt3Transaction(cres)
  else:
    result.diagnostic = support
    result.handle.diagnostic = support

proc restoreInt3SyscallPatch*(handle: var LinuxInt3PatchHandle): LinuxRawSyscallDiagnostic =
  ## Restore the first byte overwritten by `installInt3SyscallPatchTransaction`.
  if handle.diagnostic != lrsOk:
    return handle.diagnostic
  if not handle.active:
    return lrsInvalidArgument
  when defined(linux) and defined(amd64):
    var osErr: cint
    let rc = cRestoreInt3Syscall(handle.target, handle.originalFirstByte, addr osErr)
    handle.osErrno = osErr
    if rc == 0:
      handle.active = false
      lrsOk
    else:
      toDiagnostic(rc)
  else:
    linuxRawSyscallSupported()

proc captureLinuxX8664SyscallRegisters*(ucontext: pointer):
    tuple[diagnostic: LinuxRawSyscallDiagnostic,
          regs: LinuxX8664SyscallRegisters] =
  ## Capture Linux x86_64 syscall ABI registers from a SIGTRAP `ucontext_t`.
  ## This is policy-free: it does not classify syscalls or special-case clone.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return (support, LinuxX8664SyscallRegisters())
  when defined(linux) and defined(amd64):
    var cres: CStackableLinuxSyscallRegs
    let rc = cCaptureSyscallRegsFromUcontext(ucontext, addr cres)
    (toDiagnostic(rc), fromCSyscallRegs(cres))
  else:
    (support, LinuxX8664SyscallRegisters())

proc writeLinuxX8664SyscallResult*(ucontext: pointer; resultValue: int;
                                   resumeRip: uint): LinuxRawSyscallDiagnostic =
  ## Write a syscall result to RAX and optionally advance saved RIP. For INT3
  ## raw syscall continuation, use the `resumeRip` produced by
  ## `captureLinuxX8664SyscallRegisters`.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return support
  when defined(linux) and defined(amd64):
    toDiagnostic(cWriteSyscallResultToUcontext(
      ucontext, clong(resultValue), culong(resumeRip)))
  else:
    support

proc replayLinuxX8664SyscallRegisters*(regs: LinuxX8664SyscallRegisters): int =
  ## Re-issue the captured syscall with the Linux x86_64 raw syscall ABI.
  ## Consumers remain responsible for deciding whether a particular syscall is
  ## safe to replay this way.
  if linuxRawSyscallSupported() != lrsOk:
    return -38
  when defined(linux) and defined(amd64):
    var cregs: CStackableLinuxSyscallRegs
    cregs.nr = clong(regs.syscallNumber)
    for i in 0 ..< 6:
      cregs.args[i] = clong(regs.args[i])
    cregs.result = clong(regs.result)
    cregs.trapRip = culong(regs.trapRip)
    cregs.syscallAddress = culong(regs.syscallAddress)
    cregs.resumeRip = culong(regs.resumeRip)
    int(cReplaySyscallRegs(addr cregs))
  else:
    -38

proc isLinuxX8664DefaultCloneContinuationSyscall*(syscallNumber: int): bool =
  ## Return true for the Linux x86_64 clone-family syscall numbers that cannot
  ## safely be replayed through an ordinary C raw-syscall wrapper when trapped
  ## from program text. This is only the default classifier; consumers may add
  ## narrower or broader policy on top.
  when defined(linux) and defined(amd64):
    cIsDefaultCloneContinuationSyscall(clong(syscallNumber)) != 0
  else:
    false

proc isLinuxX8664CloneContinuationSyscall*(syscallNumber: int;
                                           extraCloneLike: openArray[int]): bool =
  ## Classify with the framework default clone-family set plus
  ## caller-supplied numbers. The supplied list is a mechanism hook, not a
  ## policy decision by this module.
  if isLinuxX8664DefaultCloneContinuationSyscall(syscallNumber):
    return true
  for nr in extraCloneLike:
    if nr == syscallNumber:
      return true
  false

proc isLinuxX8664CloneContinuationSyscall*(syscallNumber: int): bool =
  isLinuxX8664DefaultCloneContinuationSyscall(syscallNumber)

proc computeLinuxX8664Int3ResumeRip*(trapRip: uint): uint =
  ## Linux x86_64 INT3 reports saved RIP after the one-byte INT3. For a
  ## patched `0f 05`, the original syscall starts at `trapRip - 1` and normal
  ## user-code continuation is `trapRip + 1`.
  if trapRip == 0:
    0
  else:
    trapRip + 1

proc computeLinuxX8664CloneContinuation*(regs: LinuxX8664SyscallRegisters;
                                         parentResult: int;
                                         cloneLike: bool):
    tuple[diagnostic: LinuxRawSyscallDiagnostic,
          state: LinuxX8664CloneContinuation] =
  ## Compute parent/child continuation facts for a clone/fork/vfork-like raw
  ## syscall trapped by INT3. This does not issue the syscall, record events, or
  ## decide whether the clone path should be used. Parent handling writes
  ## `parentResult` into RAX and resumes at `regs.resumeRip`; child handling
  ## must arrange RAX=0 and jump directly to the same user-code resume RIP.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return (support, LinuxX8664CloneContinuation())
  when defined(linux) and defined(amd64):
    var cregs = toCSyscallRegs(regs)
    var cstate: CStackableLinuxCloneContinuation
    let rc = cComputeCloneContinuation(addr cregs, clong(parentResult),
                                       if cloneLike: 1 else: 0, addr cstate)
    (toDiagnostic(rc), fromCCloneContinuation(cstate))
  else:
    (support, LinuxX8664CloneContinuation())

proc computeLinuxX8664CloneContinuation*(regs: LinuxX8664SyscallRegisters;
                                         parentResult: int):
    tuple[diagnostic: LinuxRawSyscallDiagnostic,
          state: LinuxX8664CloneContinuation] =
  ## Convenience overload using the default Linux x86_64 clone-family syscall
  ## classifier.
  computeLinuxX8664CloneContinuation(
    regs, parentResult,
    isLinuxX8664DefaultCloneContinuationSyscall(regs.syscallNumber))

proc installLinuxSigtrapHandler*(handler: pointer; extraFlags: cint = 0):
    LinuxRawSyscallDiagnostic =
  ## Install a process SIGTRAP SA_SIGINFO handler and save the previous action
  ## for explicit chaining/restoration. This is the low-level substrate only;
  ## consumers own dispatch policy, reentrancy, and handler body.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return support
  when defined(linux) and defined(amd64):
    toDiagnostic(cInstallSigtrapHandler(handler, extraFlags))
  else:
    support

proc uninstallLinuxSigtrapHandler*(): LinuxRawSyscallDiagnostic =
  ## Restore the previous SIGTRAP action saved by `installLinuxSigtrapHandler`.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return support
  when defined(linux) and defined(amd64):
    toDiagnostic(cUninstallSigtrapHandler())
  else:
    support

proc chainLinuxSigtrap*(signum: cint; siginfo: pointer; ucontext: pointer):
    LinuxRawSyscallDiagnostic =
  ## Invoke the SIGTRAP action that was active before
  ## `installLinuxSigtrapHandler`, when one is chainable.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return support
  when defined(linux) and defined(amd64):
    toDiagnostic(cChainSigtrap(signum, siginfo, ucontext))
  else:
    support

proc looksLikeLinuxX8664Syscall*(bytes: openArray[byte]; offset: int): bool =
  ## Conservative byte-level syscall-site predicate. This follows MCR's current
  ## false-positive guard: a `0f 05` followed by `00` is likely an embedded
  ## immediate in generated code, not an instruction boundary.
  if offset < 0 or offset + 2 >= bytes.len:
    return false
  bytes[offset] == linuxSyscallOpcode0 and
    bytes[offset + 1] == linuxSyscallOpcode1 and
    bytes[offset + 2] != byte 0x00

proc scanLinuxX8664SyscallBytes*(bytes: openArray[byte];
                                 baseAddress: uint = 0): seq[LinuxSyscallSite] =
  ## Scan a controlled byte slice for Linux x86_64 raw syscall opcodes.
  if bytes.len < 3:
    return @[]
  var i = 0
  while i + 2 < bytes.len:
    if looksLikeLinuxX8664Syscall(bytes, i):
      result.add LinuxSyscallSite(
        address: baseAddress + uint(i),
        offset: i,
        nextByte: bytes[i + 2])
      inc i, 2
    else:
      inc i

proc visitLinuxX8664SyscallBytes*(bytes: openArray[byte];
                                  visitor: proc(site: LinuxSyscallSite): bool
                                    {.closure, raises: [].};
                                  baseAddress: uint = 0) {.raises: [].} =
  ## Callback-style scanner surface for consumers that want to classify, patch,
  ## or reject sites without first allocating a result sequence. Returning
  ## `false` from `visitor` stops the scan.
  if bytes.len < 3 or visitor == nil:
    return
  var i = 0
  while i + 2 < bytes.len:
    if looksLikeLinuxX8664Syscall(bytes, i):
      let keepGoing = visitor LinuxSyscallSite(
        address: baseAddress + uint(i),
        offset: i,
        nextByte: bytes[i + 2])
      if not keepGoing:
        return
      inc i, 2
    else:
      inc i

proc visitLinuxX8664SyscallMemory*(start: pointer; length: int;
                                   visitor: proc(site: LinuxSyscallSite): bool
                                     {.closure, raises: [].}) {.raises: [].} =
  ## Scan an already-readable memory range for raw syscall callsites. The
  ## caller owns mapping selection and exclusion policy.
  if start == nil or length < 3 or visitor == nil:
    return
  when defined(linux) and defined(amd64):
    let p = cast[ptr UncheckedArray[byte]](start)
    let base = cast[uint](start)
    var i = 0
    while i + 2 < length:
      if p[i] == linuxSyscallOpcode0 and p[i + 1] == linuxSyscallOpcode1 and
          p[i + 2] != byte 0x00:
        let keepGoing = visitor LinuxSyscallSite(
          address: base + uint(i),
          offset: i,
          nextByte: p[i + 2])
        if not keepGoing:
          return
        inc i, 2
      else:
        inc i

proc visitLinuxExecutableMappingSyscalls*(mapping: LinuxExecutableMapping;
                                          visitor: proc(site: LinuxSyscallSite): bool
                                            {.closure, raises: [].}) {.raises: [].} =
  ## Scan one readable executable mapping selected by the consumer. Kernel
  ## pseudo-mappings, self-mappings, and size limits are caller policy.
  if linuxRawSyscallSupported() != lrsOk:
    return
  if not (mapping.readable and mapping.executable):
    return
  if mapping.stop <= mapping.start:
    return
  let length = int(mapping.stop - mapping.start)
  visitLinuxX8664SyscallMemory(cast[pointer](mapping.start), length, visitor)

proc parseLinuxMapsLine*(line: string): tuple[ok: bool, mapping: LinuxExecutableMapping] =
  ## Parse one `/proc/self/maps` line. Exposed for deterministic tests and for
  ## consumers that want to apply their own mapping filters before scanning.
  let parts = line.splitWhitespace(maxsplit = 5)
  if parts.len < 5:
    return (false, LinuxExecutableMapping())
  let dash = parts[0].find('-')
  if dash <= 0:
    return (false, LinuxExecutableMapping())
  try:
    result.mapping.start = parseHexInt(parts[0][0 ..< dash]).uint
    result.mapping.stop = parseHexInt(parts[0][dash + 1 .. ^1]).uint
  except ValueError:
    return (false, LinuxExecutableMapping())
  if parts[1].len < 4:
    return (false, LinuxExecutableMapping())
  result.mapping.readable = parts[1][0] == 'r'
  result.mapping.writable = parts[1][1] == 'w'
  result.mapping.executable = parts[1][2] == 'x'
  result.mapping.privateMapping = parts[1][3] == 'p'
  result.mapping.path = if parts.len >= 6: parts[5] else: ""
  result.ok = true

proc enumerateLinuxExecutableMappings*(): tuple[diagnostic: LinuxRawSyscallDiagnostic,
                                                mappings: seq[LinuxExecutableMapping]] =
  ## Enumerate readable executable mappings from `/proc/self/maps`.
  ## Kernel pseudo-mappings such as `[vdso]` are returned to the caller, not
  ## silently filtered, so consumer policy can decide whether to scan or skip.
  let support = linuxRawSyscallSupported()
  if support != lrsOk:
    return (support, @[])
  when defined(linux):
    for line in lines("/proc/self/maps"):
      let parsed = parseLinuxMapsLine(line)
      if parsed.ok and parsed.mapping.readable and parsed.mapping.executable:
        result.mappings.add parsed.mapping
    result.diagnostic = lrsOk
  else:
    result = (support, @[])
