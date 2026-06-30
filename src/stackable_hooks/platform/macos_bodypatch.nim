when not defined(macosx):
  {.error: "stackable_hooks/platform/macos_bodypatch is macOS-only".}

## macOS body-patch primitives
## ===========================
##
## Reusable, non-opinionated helpers for patching macOS function entry bodies.
## Consumers provide the target symbol names and hook function bodies; this
## module provides only the low-level install, resolution, trampoline, and
## diagnostic counter primitives.
##
## The install primitive replaces the code mapping at a target address with a
## fresh executable page whose prologue branches to the consumer hook. This uses
## the Dobby/substrate-style `mach_vm_remap(..., VM_FLAGS_OVERWRITE, ...)`
## technique, which works around hardened in-place W^X restrictions on signed
## shared-cache text. The emitted arm64 branch stub is:
##
##   ldr x16, #8
##   br  x16
##   .quad hook
##
## For functions that must call the original body after patching, this module
## can build a trampoline that copies the original 16-byte prologue and resumes
## at `target + 16`. The trampoline builder conservatively refuses prologues
## containing PC-relative AArch64 instructions.

{.emit: """
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/dyld.h>

#ifndef STACKABLE_BODYPATCH_MAX_TARGETS
#define STACKABLE_BODYPATCH_MAX_TARGETS 64
#endif

static int stackable_bodypatch_addr_in_image_substr(const void *addr,
                                                    const char *image_substr) {
  Dl_info info;
  if (addr == NULL || image_substr == NULL || image_substr[0] == '\0') return 0;
  if (dladdr(addr, &info) == 0) return 0;
  if (info.dli_fname == NULL) return 0;
  return strstr(info.dli_fname, image_substr) != NULL ? 1 : 0;
}

static void *stackable_bodypatch_resolve_macho_symbol(const char *name,
                                                      const char *exclude_substr) {
  if (name == NULL) return NULL;
  char mangled[128];
  size_t n = strlen(name);
  if (n + 2 > sizeof(mangled)) return NULL;
  mangled[0] = '_';
  memcpy(mangled + 1, name, n);
  mangled[n + 1] = '\0';

  uint32_t count = _dyld_image_count();
  for (uint32_t i = 0; i < count; i++) {
    const char *img = _dyld_get_image_name(i);
    if (exclude_substr != NULL && exclude_substr[0] != '\0' &&
        img != NULL && strstr(img, exclude_substr) != NULL) {
      continue;
    }

    const struct mach_header *header = _dyld_get_image_header(i);
    if (header == NULL) continue;
    NSSymbol sym = NSLookupSymbolInImage(header, mangled,
      NSLOOKUPSYMBOLINIMAGE_OPTION_BIND |
      NSLOOKUPSYMBOLINIMAGE_OPTION_RETURN_ON_ERROR);
    if (sym) {
      void *ptr = NSAddressOfSymbol(sym);
      if (ptr && !stackable_bodypatch_addr_in_image_substr(ptr, exclude_substr)) {
        return ptr;
      }
    }
  }
  return NULL;
}

static uintptr_t stackable_bodypatch_seen[STACKABLE_BODYPATCH_MAX_TARGETS];
static size_t stackable_bodypatch_seen_count = 0;

static int stackable_bodypatch_already(uintptr_t target) {
  for (size_t i = 0; i < stackable_bodypatch_seen_count; i++) {
    if (stackable_bodypatch_seen[i] == target) return 1;
  }
  return 0;
}

static void stackable_bodypatch_remember(uintptr_t target) {
  if (stackable_bodypatch_seen_count < STACKABLE_BODYPATCH_MAX_TARGETS) {
    stackable_bodypatch_seen[stackable_bodypatch_seen_count++] = target;
  }
}

int stackable_macos_bodypatch_install(void *target, void *hook) {
  if (target == NULL || hook == NULL) return 1;

  uintptr_t taddr = (uintptr_t)target;
  if (stackable_bodypatch_already(taddr)) return 0;

  const size_t patch_len = 16;
  long pg = sysconf(_SC_PAGESIZE);
  uintptr_t page_base = taddr & ~(uintptr_t)(pg - 1);
  uintptr_t offset = taddr - page_base;

  size_t copy_len = (size_t)pg;
  if (offset + patch_len > (size_t)pg) {
    copy_len = (size_t)pg * 2;
  }

  mach_vm_address_t new_page = 0;
  kern_return_t kr = mach_vm_allocate(mach_task_self(), &new_page,
                                      copy_len, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) return 3;

  memcpy((void *)new_page, (void *)page_base, copy_len);
  uint32_t *p = (uint32_t *)(new_page + offset);
  p[0] = 0x58000050u;
  p[1] = 0xd61f0200u;
  *(uint64_t *)&p[2] = (uint64_t)(uintptr_t)hook;

  kr = mach_vm_protect(mach_task_self(), new_page, copy_len, FALSE,
                       VM_PROT_READ | VM_PROT_EXECUTE);
  if (kr != KERN_SUCCESS) {
    mach_vm_deallocate(mach_task_self(), new_page, copy_len);
    return 4;
  }

  mach_vm_address_t dst = (mach_vm_address_t)page_base;
  vm_prot_t cur = 0, max = 0;
  kr = mach_vm_remap(mach_task_self(), &dst, copy_len, 0,
                     VM_FLAGS_OVERWRITE, mach_task_self(), new_page, FALSE,
                     &cur, &max, VM_INHERIT_COPY);
  if (kr != KERN_SUCCESS) {
    mach_vm_deallocate(mach_task_self(), new_page, copy_len);
    return 5;
  }

  sys_icache_invalidate(target, patch_len);
  stackable_bodypatch_remember(taddr);
  return 0;
}

void stackable_macos_bodypatch_install_named_excluding(const char *name,
                                                       void *hook,
                                                       const char *exclude_substr,
                                                       int *installed,
                                                       int *failed,
                                                       int *absent) {
  void *target = stackable_bodypatch_resolve_macho_symbol(name, exclude_substr);
  if (target == NULL) {
    if (absent) (*absent)++;
    return;
  }
  if (stackable_bodypatch_addr_in_image_substr(target, exclude_substr)) {
    if (failed) (*failed)++;
    return;
  }
  int rc = stackable_macos_bodypatch_install(target, hook);
  if (rc == 0) {
    if (installed) (*installed)++;
  } else {
    if (failed) (*failed)++;
  }
}

static int stackable_bodypatch_insn_is_pcrel(uint32_t insn) {
  if ((insn & 0x9F000000u) == 0x90000000u) return 1;
  if ((insn & 0x9F000000u) == 0x10000000u) return 1;
  if ((insn & 0xFC000000u) == 0x14000000u) return 1;
  if ((insn & 0xFC000000u) == 0x94000000u) return 1;
  if ((insn & 0xFF000010u) == 0x54000000u) return 1;
  if ((insn & 0x7E000000u) == 0x34000000u) return 1;
  if ((insn & 0x7E000000u) == 0x36000000u) return 1;
  if ((insn & 0x3B000000u) == 0x18000000u) return 1;
  return 0;
}

static int stackable_bodypatch_prologue_relocatable(const void *target) {
  const uint32_t *p = (const uint32_t *)target;
  for (int i = 0; i < 4; i++) {
    if (stackable_bodypatch_insn_is_pcrel(p[i])) return 0;
  }
  return 1;
}

void *stackable_macos_bodypatch_build_trampoline(void *target, int *err) {
  if (err) *err = 0;
  if (target == NULL) { if (err) *err = 1; return NULL; }

  if (!stackable_bodypatch_prologue_relocatable(target)) {
    if (err) *err = 2;
    return NULL;
  }

  const size_t tramp_words = 6;
  const size_t tramp_len = tramp_words * sizeof(uint32_t) + sizeof(uint64_t);

  mach_vm_address_t tramp = 0;
  kern_return_t kr = mach_vm_allocate(mach_task_self(), &tramp, tramp_len,
                                      VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) { if (err) *err = 3; return NULL; }

  uint32_t *t = (uint32_t *)tramp;
  const uint32_t *src = (const uint32_t *)target;
  t[0] = src[0];
  t[1] = src[1];
  t[2] = src[2];
  t[3] = src[3];
  t[4] = 0x58000050u;
  t[5] = 0xd61f0200u;
  *(uint64_t *)&t[6] = (uint64_t)(uintptr_t)target + 16u;

  kr = mach_vm_protect(mach_task_self(), tramp, tramp_len, FALSE,
                       VM_PROT_READ | VM_PROT_EXECUTE);
  if (kr != KERN_SUCCESS) {
    mach_vm_deallocate(mach_task_self(), tramp, tramp_len);
    if (err) *err = 4;
    return NULL;
  }

  sys_icache_invalidate((void *)tramp, tramp_len);
  return (void *)tramp;
}

void stackable_macos_bodypatch_install_named_tramp_excluding(const char *name,
                                                             void *hook,
                                                             const char *exclude_substr,
                                                             void **out_trampoline,
                                                             int *installed,
                                                             int *failed,
                                                             int *absent) {
  if (out_trampoline) *out_trampoline = NULL;
  void *target = stackable_bodypatch_resolve_macho_symbol(name, exclude_substr);
  if (target == NULL) {
    if (absent) (*absent)++;
    return;
  }
  if (stackable_bodypatch_addr_in_image_substr(target, exclude_substr)) {
    if (failed) (*failed)++;
    return;
  }

  int terr = 0;
  void *tramp = stackable_macos_bodypatch_build_trampoline(target, &terr);
  if (tramp == NULL) {
    if (failed) (*failed)++;
    return;
  }

  int rc = stackable_macos_bodypatch_install(target, hook);
  if (rc == 0) {
    if (out_trampoline) *out_trampoline = tramp;
    if (installed) (*installed)++;
  } else {
    if (failed) (*failed)++;
  }
}
""".}

proc stackableMacosBodypatchInstall*(target, hook: pointer): cint
    {.importc: "stackable_macos_bodypatch_install", cdecl.}
  ## Install one body patch. Returns 0 on success; nonzero on failure:
  ## 1 bad arguments, 3 allocation failure, 4 RX protect failure,
  ## 5 remap failure. Reinstalling the same target is idempotent.

proc stackableMacosBodypatchInstallNamedExcluding*(name: cstring; hook: pointer;
    excludeImageSubstring: cstring; installed, failed, absent: ptr cint)
    {.importc: "stackable_macos_bodypatch_install_named_excluding", cdecl.}
  ## Resolve `name` by walking Mach-O images, excluding any image whose path
  ## contains `excludeImageSubstring`, then install a body patch. Absent symbols
  ## increment `absent`; install failures increment `failed`; successful patches
  ## increment `installed`.

proc stackableMacosBodypatchBuildTrampoline*(target: pointer;
    err: ptr cint): pointer
    {.importc: "stackable_macos_bodypatch_build_trampoline", cdecl.}
  ## Build an original-call trampoline for `target` by copying its first 16 bytes
  ## and branching back to `target + 16`. Must be called before patching.
  ## Returns nil and writes `err = 2` when the prologue contains a PC-relative
  ## AArch64 instruction and is unsafe to relocate.

proc stackableMacosBodypatchInstallNamedTrampExcluding*(name: cstring;
    hook: pointer; excludeImageSubstring: cstring; outTrampoline: ptr pointer;
    installed, failed, absent: ptr cint)
    {.importc: "stackable_macos_bodypatch_install_named_tramp_excluding", cdecl.}
  ## Resolve `name`, build an original-call trampoline, then install the body
  ## patch. If resolution, trampoline construction, or patch installation fails,
  ## `outTrampoline` remains nil and the symbol is left unpatched.
