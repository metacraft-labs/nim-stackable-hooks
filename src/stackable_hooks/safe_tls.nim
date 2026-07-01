## Hostile-context-safe thread-local storage for injected shims.
##
## An interpose / inline-hook shim runs its hooks in contexts where touching
## ORDINARY thread-local storage is unsafe:
##
##   * INSIDE libmalloc — libmalloc grows an arena via `mmap` while holding its
##     arena lock, so a hook on `mmap` runs with that lock held;
##   * from a signal handler;
##   * on a thread created BEFORE the shim's image was mapped (see
##     `reentrancy.nim` for the Windows .NET-CLR variant of this).
##
## The hazard (macOS, verified). A Nim `{.threadvar.}` or a C `__thread` /
## `_Thread_local` — with ANY `tls_model`, including `initial-exec` — is, in a
## dlopen'd / DYLD_INSERT_LIBRARIES image, a dyld **TLV**. The FIRST access on a
## given thread calls `tlv_get_addr -> tlv_allocate_and_initialize_for_key ->
## malloc`. Reached from inside libmalloc that re-enters the allocator under its
## own lock and corrupts the heap → SIGSEGV. Measured with a minimal `mmap`
## interpose hook: touching a `_Thread_local(initial-exec)` counter crashes
## `rustc` 6/6; the identical hook using the accessors below is safe 0/6.
##
## The safe primitive. `pthread_getspecific` / `pthread_setspecific` read and
## write a slot in the pthread struct's **inline**, thread-creation-time TSD
## array: no malloc, no lock, async-signal-safe. (Windows `TlsGetValue` /
## `TlsSetValue` over a `TlsAlloc` slot has the same inline-TEB property — see
## `reentrancy.nim`.) So a `pthread_key`-backed word is safe in every context
## above.
##
## Two rules for using this safely from a hostile context:
##   1. Create the key ONCE, at shim-constructor time, on the main thread
##      (`stackableSafeTlsCreate`), never lazily from a hook.
##   2. The accessors are plain C functions (`{.emit.}`) with thin Nim wrappers.
##      When the surrounding code path can run inside libmalloc, call the C
##      accessors (`stackable_safe_tls_get` / `_set`) directly from your C thunk,
##      or ensure the Nim wrapper is compiled magic-free (`{.raises: [].}`,
##      `--stackTrace:off`, and no `--exceptions:goto` error-flag on the path) —
##      otherwise ENTERING the Nim wrapper itself touches the `nimInErrorMode` /
##      `framePtr` threadvars and re-introduces the very TLV-malloc it avoids.
##      See `docs/compilation-settings.md`.
##
## The stored value is a single opaque machine word (`uint`): use it for a small
## re-entrancy depth, a boolean flag, or a cast pointer.

{.push raises: [].}

{.emit: """
#include <stddef.h>   /* size_t — pointer-sized on ILP32/LP64/LLP64, unlike `unsigned long` */

/* A hostile-context-safe per-thread word. The key is created ONCE at
 * construction (main thread); the get/set accessors read/write the calling
 * thread's INLINE TSD/TEB slot with no malloc, no lock — safe from inside
 * libmalloc and signal handlers. Windows: TlsAlloc + TlsGetValue/TlsSetValue
 * (inline TEB TlsSlots — see reentrancy.nim's MW17 note on why not
 * __declspec(thread)). POSIX: pthread_getspecific/setspecific (inline pthread
 * TSD array). NOTE: `size_t` is used throughout so a pointer-sized value is not
 * truncated on LLP64 (Win64), where `unsigned long` is 32-bit. */
#if defined(_WIN32)
#  include <windows.h>
static int stackable_safe_tls_create(size_t *out_key) {
  DWORD idx = TlsAlloc();
  if (idx == TLS_OUT_OF_INDEXES) return 1;
  *out_key = (size_t)idx;
  return 0;
}
static size_t stackable_safe_tls_get(size_t key) {
  return (size_t)(SIZE_T)TlsGetValue((DWORD)key);   /* NULL (0) until first set */
}
static void stackable_safe_tls_set(size_t key, size_t value) {
  (void)TlsSetValue((DWORD)key, (LPVOID)(SIZE_T)value);
}
#else
#  include <pthread.h>
static int stackable_safe_tls_create(size_t *out_key) {
  pthread_key_t k;
  int rc = pthread_key_create(&k, (void (*)(void *))0);
  if (rc != 0) return rc;
  *out_key = (size_t)k;
  return 0;
}
static size_t stackable_safe_tls_get(size_t key) {
  return (size_t)pthread_getspecific((pthread_key_t)key);
}
static void stackable_safe_tls_set(size_t key, size_t value) {
  (void)pthread_setspecific((pthread_key_t)key, (void *)value);
}
#endif
""".}

type
  SafeTls* = object
    ## A hostile-context-safe thread-local word, backed by a pthread key (POSIX)
    ## or a TlsAlloc slot (Windows). Value-typed and cheap to copy; the identity
    ## is the underlying key.
    key: csize_t

proc stackableSafeTlsCreateImpl(outKey: ptr csize_t): cint
  {.importc: "stackable_safe_tls_create", nodecl.}
proc stackableSafeTlsGetImpl(key: csize_t): csize_t
  {.importc: "stackable_safe_tls_get", nodecl.}
proc stackableSafeTlsSetImpl(key: csize_t; value: csize_t)
  {.importc: "stackable_safe_tls_set", nodecl.}

proc stackableSafeTlsCreate*(): SafeTls =
  ## Allocate a hostile-context-safe thread-local word. Call ONCE, from the shim
  ## constructor, on the main thread — NEVER lazily from a hook (key creation is
  ## not itself hostile-context-safe). Raises `OSError`-free: on the (effectively
  ## impossible for a shim: PTHREAD_KEYS_MAX / TLS_OUT_OF_INDEXES exhaustion)
  ## failure it returns a key of 0, which the accessors treat as an ordinary — if
  ## shared — slot; callers that need to detect this can check `isValid`.
  var k: csize_t = 0
  discard stackableSafeTlsCreateImpl(addr k)
  SafeTls(key: k)

proc isValid*(t: SafeTls): bool {.inline.} =
  ## False only if key creation failed (PTHREAD_KEYS_MAX / TLS_OUT_OF_INDEXES).
  ## Normally true.
  t.key != 0

proc get*(t: SafeTls): uint =
  ## Read this thread's word (0 until first `set` on the thread). Safe from a
  ## hostile context PROVIDED the caller reaches here without touching other
  ## thread-locals (see the module note on magic-free compilation).
  ##
  ## NOT `{.inline.}` on purpose: the C accessor it forwards to is `static`, so it
  ## must be CALLED from this module's translation unit rather than inlined into a
  ## caller's. A C thunk on a genuine hostile hot path (running inside libmalloc)
  ## should instead inline the two-line `pthread_getspecific` / `TlsGetValue`
  ## pattern directly (see the `{.emit.}` above) — the same primitive, no cross-TU
  ## call.
  uint(stackableSafeTlsGetImpl(t.key))

proc set*(t: SafeTls; value: uint) =
  ## Write this thread's word. Same hostile-context caveat as `get`.
  stackableSafeTlsSetImpl(t.key, csize_t(value))

{.pop.}
