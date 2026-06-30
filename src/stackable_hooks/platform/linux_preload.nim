when not defined(linux):
  {.error: "stackable_hooks/platform/linux_preload is Linux-only".}

## Policy-free helper primitives for traditional Linux LD_PRELOAD shims.
##
## Consumers still own the exported interpose symbols, target list, hook bodies,
## and observation policy. This module only centralizes reusable mechanics that
## every preload shim otherwise reimplements: `RTLD_NEXT` lookup and a small
## thread-local reentrancy depth used to bypass hooks while resolving or
## forwarding.

{.emit: """
#define _GNU_SOURCE
#include <dlfcn.h>

static __thread int stackable_linux_preload_hook_depth = 0;

void *stackable_linux_preload_resolve_next(const char *name) {
  stackable_linux_preload_hook_depth++;
  void *result = dlsym(RTLD_NEXT, name);
  stackable_linux_preload_hook_depth--;
  return result;
}

int stackable_linux_preload_current_depth(void) {
  return stackable_linux_preload_hook_depth;
}

int stackable_linux_preload_hooks_allowed(void) {
  return stackable_linux_preload_hook_depth == 0;
}

void stackable_linux_preload_enter_hook(void) {
  stackable_linux_preload_hook_depth++;
}

void stackable_linux_preload_exit_hook(void) {
  if (stackable_linux_preload_hook_depth > 0) {
    stackable_linux_preload_hook_depth--;
  }
}
""".}

proc resolveNextSymbol*(name: cstring): pointer
  {.importc: "stackable_linux_preload_resolve_next", cdecl, raises: [].}
  ## Resolve a symbol using `dlsym(RTLD_NEXT, name)` while suppressing nested
  ## preload hooks on the current thread.

proc currentPreloadHookDepth*(): cint
  {.importc: "stackable_linux_preload_current_depth", cdecl, raises: [].}
  ## Return the current thread's preload-hook reentrancy depth.

proc preloadHooksAllowed*(): cint
  {.importc: "stackable_linux_preload_hooks_allowed", cdecl, raises: [].}
  ## Non-zero when a preload wrapper may dispatch into consumer hook bodies.

proc enterPreloadHook*()
  {.importc: "stackable_linux_preload_enter_hook", cdecl, raises: [].}
  ## Enter a consumer hook body or other hook-suppressed section.

proc exitPreloadHook*()
  {.importc: "stackable_linux_preload_exit_hook", cdecl, raises: [].}
  ## Leave a consumer hook body or other hook-suppressed section.
