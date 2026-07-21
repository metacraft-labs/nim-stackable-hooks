{.push raises: [].}

## Thread-local reentrancy guard for ct_interpose.
##
## When a hook function calls libc functions that are themselves hooked,
## the reentrancy guard prevents infinite recursion. Each hook entry
## increments the depth counter; `hooksAllowed()` returns false when
## depth > 0, causing the dispatcher to call the original function directly.
##
## *MW16 (MCR-Windows-CtMcr-Port, 2026-05-28) -- C-side __declspec(thread)
## migration.*  Pre-MW16 the depth counter was a Nim `{.threadvar.}: int`.
## On Windows that compiles to an FlsAlloc / FlsGet / FlsSet runtime slot
## (or, for `--threads:on` builds, a `TlsAlloc` slot whose value is read
## via TlsGetValue).  Either way, the storage lives outside the PE TLS
## directory of `ct_interpose.dll`.
##
## MW15's diagnostic localised a residual STATUS_ACCESS_VIOLATION on the
## .NET CLR record path to the *hook-entry transition* on CLR-spawned
## threads -- threads created via `NtCreateThreadEx` BEFORE the loader
## mapped `ct_interpose.dll`.  Such threads have a per-thread TLS array
## populated only with the TLS entries of the modules that were loaded
## when the thread was created; the dynamically-loaded `ct_interpose.dll`
## adds its entries to the *image* TLS Directory, but the loader patches
## the per-thread TLS array (via the `TlsExpansionSlots` mechanism the
## NT loader maintains on each TEB) only the next time that thread
## either enters a syscall via the loader-aware path or `LdrLoadDll`
## explicitly sweeps existing threads.  CLR-spawned threads that fire
## an inline-detoured NT syscall before the loader's expansion-slot
## fix-up have a TLS-array hole at the offset the Nim threadvar codegen
## reads -- the prologue AVs before the hook body's first statement.
##
## *The fix.*  Mirror the precedent already established in
## `recording/runtime_internal_lock.nim:50-92` (and used by
## `ct_inline_hook/install_windows.c`'s `g_ct_inline_hook_in_handler`):
## declare the depth counter as a C-side `static __declspec(thread) int`
## (Windows) or `static _Thread_local __attribute__((tls_model(
## "initial-exec"))) int` (POSIX).  The `__declspec(thread)` slot is
## allocated through the PE TLS Directory; on Windows the loader's
## `TlsExpansionSlots` machinery guarantees the slot is reachable from
## every thread alive at the time the DLL is mapped -- including
## CLR-spawned threads created before `ct_interpose.dll` was loaded --
## because `LdrLoadDll` walks the live thread list and patches each
## TEB's `ThreadLocalStoragePointer` to include the newly-loaded
## module's TLS index.  POSIX `__thread` has the same property without
## any loader gymnastics (the dynamic linker handles the GOT-relative
## TLS offset transparently on every thread).
##
## *API.*  Three C-callable accessors (`_ct_hook_depth_get` / `_set` /
## `_inc_and_get` / `_dec_and_get`) wrapped by Nim-side procs.  The
## existing call sites (`enterHook`, `exitHook`, `hooksAllowed`,
## `suppressHooksForCurrentThread`, `withReentrancy*`) keep their
## interface unchanged -- they now read/write the C-side slot instead
## of the Nim threadvar.  The legacy `hookDepth` symbol is preserved
## as a property-style template that delegates to the accessors, so
## `test_reentrancy.nim` (which uses `hookDepth == N` assertions
## directly) compiles unmodified.

when defined(windows) and defined(vcc) and
    defined(ctStackableHooksExternalTls):
  {.passC: "/DCT_STACKABLE_HOOKS_EXTERNAL_TLS".}

{.emit: """
/* MW17 (MCR-Windows-CtMcr-Port, 2026-05-28) -- per-thread hook
   reentrancy counter.

   *Storage model.*  On Windows, `TlsAlloc`-managed slot accessed via
   `TlsGetValue` / `TlsSetValue`.  On POSIX, `_Thread_local` with
   `initial-exec` model.

   *Why TlsAlloc and not __declspec(thread) on Windows (MW17 fix).*
   MW16 attempted `__declspec(thread)` on the (incorrect) premise that
   the Windows loader's `TlsExpansionSlots` machinery patches every
   alive thread's TLS array when a new DLL is mapped.  MW17 verified
   experimentally (in-process VEH at the AV site, capturing RIP +
   register state -- see ct_interpose/src/ct_interpose/mw17_veh.c)
   that this premise is FALSE for the .NET CLR's raw-NtCreateThreadEx
   thread set: those threads have TEB::ThreadLocalStoragePointer ==
   NULL on entry to any inline hook, and the MSVC-emitted
   `__declspec(thread)` accessor (`mov rdx, gs:[58h]; mov rcx,
   [rdx+rcx*8]; ...`) AVs at the second load with FaultAddress=0x8.
   Reproduced 5/5 with QPC alone armed at 82-83 events.

   TlsAlloc / TlsGetValue dispatches via the TEB's *inline*
   `TlsSlots[64]` array (TEB+0x1480 on x64), which is unconditionally
   present in every TEB (kernel-allocated at thread create).
   `TlsGetValue` returns NULL cleanly for any uninitialised slot on
   any thread -- no AV.  This is the architectural guarantee MW16
   wanted but mis-attributed to TlsExpansionSlots.

   *POSIX side (_Thread_local + initial-exec).*  Standard PT_TLS
   segment slot; the dynamic linker resolves the GOT-relative offset
   on every thread regardless of load order.  The `initial-exec` model
   is chosen so the read compiles to a single `%fs:offset` (x86_64
   Linux) or `tpidr_el0`-relative (aarch64) load with no
   `__tls_get_addr` call -- the hook hot path is too dense to afford
   a PLT round-trip.  POSIX does not have the Windows-loader issue
   (LD_PRELOAD'd libraries' TLS is in the PT_TLS segment which the
   dynamic linker handles uniformly per-thread). */
#if defined(_MSC_VER) && defined(CT_STACKABLE_HOOKS_EXTERNAL_TLS)
int _ct_hook_depth_get(void);
void _ct_hook_depth_set(int v);
int _ct_hook_depth_inc_and_get(void);
int _ct_hook_depth_dec_and_get(void);
void *_ct_hook_depth_outer_caller(void);
void _ct_depth_trace_push(char *name);
void _ct_depth_trace_pop(void);
int _ct_depth_trace_get_depth(void);
int _ct_depth_trace_snapshot(char *buf, int cap);
#elif defined(_MSC_VER)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <intrin.h>

static DWORD volatile g_ct_hook_depth_tls = TLS_OUT_OF_INDEXES;
static DWORD volatile g_ct_hook_outer_caller_tls = TLS_OUT_OF_INDEXES;

static DWORD _ct_hook_depth_ensure_index(void) {
  /* One-shot lazy allocation via CAS.  Safe to call from any thread,
     including the CLR-spawned threads that bypass the loader's per-
     thread TLS-array sweep -- TlsAlloc only touches process-global
     state (the bitmap of allocated slots), not per-thread state. */
  DWORD idx = g_ct_hook_depth_tls;
  if (idx != TLS_OUT_OF_INDEXES) return idx;
  DWORD fresh = TlsAlloc();
  if (fresh == TLS_OUT_OF_INDEXES) return TLS_OUT_OF_INDEXES;
  DWORD prev = (DWORD)InterlockedCompareExchange(
      (LONG volatile *)&g_ct_hook_depth_tls,
      (LONG)fresh, (LONG)TLS_OUT_OF_INDEXES);
  if (prev != TLS_OUT_OF_INDEXES) {
    /* Lost the race -- release our slot and use the winner's. */
    TlsFree(fresh);
    return prev;
  }
  return fresh;
}

static DWORD _ct_hook_outer_caller_ensure_index(void) {
  DWORD idx = g_ct_hook_outer_caller_tls;
  if (idx != TLS_OUT_OF_INDEXES) return idx;
  DWORD fresh = TlsAlloc();
  if (fresh == TLS_OUT_OF_INDEXES) return TLS_OUT_OF_INDEXES;
  DWORD prev = (DWORD)InterlockedCompareExchange(
      (LONG volatile *)&g_ct_hook_outer_caller_tls,
      (LONG)fresh, (LONG)TLS_OUT_OF_INDEXES);
  if (prev != TLS_OUT_OF_INDEXES) {
    TlsFree(fresh);
    return prev;
  }
  return fresh;
}

static void _ct_hook_outer_caller_set(void *caller) {
  DWORD idx = _ct_hook_outer_caller_ensure_index();
  if (idx != TLS_OUT_OF_INDEXES) TlsSetValue(idx, caller);
}

void *_ct_hook_depth_outer_caller(void) {
  DWORD idx = g_ct_hook_outer_caller_tls;
  return idx == TLS_OUT_OF_INDEXES ? NULL : TlsGetValue(idx);
}

int _ct_hook_depth_get(void) {
  DWORD idx = g_ct_hook_depth_tls;
  if (idx == TLS_OUT_OF_INDEXES) return 0;  /* never written = 0 */
  /* TlsGetValue can fail (returns NULL + sets LastError) -- treat
     "no value yet" as 0 either way. */
  return (int)(intptr_t)TlsGetValue(idx);
}

void _ct_hook_depth_set(int v) {
  DWORD idx = _ct_hook_depth_ensure_index();
  if (idx == TLS_OUT_OF_INDEXES) return;
  TlsSetValue(idx, (LPVOID)(intptr_t)v);
}

int _ct_hook_depth_inc_and_get(void) {
  DWORD idx = _ct_hook_depth_ensure_index();
  if (idx == TLS_OUT_OF_INDEXES) return 1;  /* defensive */
  int cur = (int)(intptr_t)TlsGetValue(idx);
  if (cur == 0) {
    _ct_hook_outer_caller_set(_ReturnAddress());
  }
  cur++;
  TlsSetValue(idx, (LPVOID)(intptr_t)cur);
  return cur;
}

int _ct_hook_depth_dec_and_get(void) {
  DWORD idx = _ct_hook_depth_ensure_index();
  if (idx == TLS_OUT_OF_INDEXES) return 0;
  int cur = (int)(intptr_t)TlsGetValue(idx);
  if (cur > 0) cur--;
  TlsSetValue(idx, (LPVOID)(intptr_t)cur);
  if (cur == 0) _ct_hook_outer_caller_set(NULL);
  return cur;
}
#else
static _Thread_local __attribute__((tls_model("initial-exec")))
    int _ct_hook_depth_storage = 0;

int _ct_hook_depth_get(void) {
  return _ct_hook_depth_storage;
}

void _ct_hook_depth_set(int v) {
  _ct_hook_depth_storage = v;
}

int _ct_hook_depth_inc_and_get(void) {
  _ct_hook_depth_storage++;
  return _ct_hook_depth_storage;
}

int _ct_hook_depth_dec_and_get(void) {
  if (_ct_hook_depth_storage > 0) {
    _ct_hook_depth_storage--;
  }
  return _ct_hook_depth_storage;
}

void *_ct_hook_depth_outer_caller(void) {
  return (void *)0;
}
#endif

/* ------------------------------------------------------------------
   Depth-trace ancestor stack (Multi-Core-Recorder.md §8.6.1).

   Per-thread stack of up to CT_DEPTH_ANCESTOR_CAP short hook-name
   pointers.  Pushed by ``enterHookN(name)`` from the recording
   bracket inside a hook body; popped by the matching ``exitHookN``.
   The stack is INDEPENDENT of ``_ct_hook_depth_get`` -- it tracks
   NAMES, not the gate counter -- so a hook body that uses the
   unnamed ``enterHook()`` / ``exitHook()`` continues to bump the
   depth counter and just leaves an anonymous slot in the name stack.

   Storage: per-thread struct embedded inline in the TLS slot via
   ``TlsAlloc`` on Windows + a small allocation -- avoided by
   stashing the depth + name array INSIDE multiple separate
   TLS slots so no heap allocator is touched on virgin CLR / D /
   loader-init threads.  Mirrors the MW17 architectural fix
   (TlsAlloc + TlsGetValue dispatched through TEB.TlsSlots[64]) so
   threads that bypass the loader-driven TLS-array sweep still
   reach a valid slot.

   To represent up to 16 names + a depth counter inside TLS slots
   only (no heap), we use 17 separate ``TlsAlloc``-managed slots:
   one for the depth counter, 16 for the name pointers.  Each
   ``TlsGetValue`` returns NULL cleanly for any uninitialised slot
   on any thread (no AV).  This is heap-allocator-free, which is
   the load-bearing safety property on virgin CLR / D loader-init
   threads where ``calloc`` AVs (`MCR-Bootstrap-Determinism.md`
   §3.3, and the MW18 root-cause notes on heap-corruption inside
   the OS heap manager's own critical section).

   Size cap CT_DEPTH_ANCESTOR_CAP=16 is chosen empirically: the
   deepest nesting observed in practice (the MW54 synthetic
   evThreadStart path) is 3-4 frames; cascade-debug fixtures
   stay below 8.  Pushes beyond the cap saturate (the deepest
   frames lose their name).  No allocation on the hot path. */
#define CT_DEPTH_ANCESTOR_CAP 16

#if defined(_MSC_VER) && defined(CT_STACKABLE_HOOKS_EXTERNAL_TLS)
/* Depth-trace accessors are supplied by the host's external TLS backend. */
#elif defined(_MSC_VER)
/* Slot 0: depth counter (stored as ``intptr_t`` masquerading as
   ``void*`` -- the TLS slot is a pointer slot but TlsSetValue
   accepts any uintptr_t-wide value).  Slots 1..CT_DEPTH_ANCESTOR_CAP:
   one ``char*`` per ancestor name. */
static DWORD volatile g_ct_depth_trace_tls[1 + CT_DEPTH_ANCESTOR_CAP] = {
  TLS_OUT_OF_INDEXES, TLS_OUT_OF_INDEXES, TLS_OUT_OF_INDEXES,
  TLS_OUT_OF_INDEXES, TLS_OUT_OF_INDEXES, TLS_OUT_OF_INDEXES,
  TLS_OUT_OF_INDEXES, TLS_OUT_OF_INDEXES, TLS_OUT_OF_INDEXES,
  TLS_OUT_OF_INDEXES, TLS_OUT_OF_INDEXES, TLS_OUT_OF_INDEXES,
  TLS_OUT_OF_INDEXES, TLS_OUT_OF_INDEXES, TLS_OUT_OF_INDEXES,
  TLS_OUT_OF_INDEXES, TLS_OUT_OF_INDEXES
};

static DWORD _ct_depth_trace_ensure_slot(int slotIdx) {
  /* Lazy-allocate the i'th TLS slot.  Safe to race -- CAS-publish. */
  DWORD idx = g_ct_depth_trace_tls[slotIdx];
  if (idx != TLS_OUT_OF_INDEXES) return idx;
  DWORD fresh = TlsAlloc();
  if (fresh == TLS_OUT_OF_INDEXES) return TLS_OUT_OF_INDEXES;
  DWORD prev = (DWORD)InterlockedCompareExchange(
      (LONG volatile *)&g_ct_depth_trace_tls[slotIdx],
      (LONG)fresh, (LONG)TLS_OUT_OF_INDEXES);
  if (prev != TLS_OUT_OF_INDEXES) {
    TlsFree(fresh);
    return prev;
  }
  return fresh;
}

static int _ct_depth_trace_read_depth(void) {
  DWORD idx = g_ct_depth_trace_tls[0];
  if (idx == TLS_OUT_OF_INDEXES) return 0;
  return (int)(intptr_t)TlsGetValue(idx);
}

static void _ct_depth_trace_write_depth(int v) {
  DWORD idx = _ct_depth_trace_ensure_slot(0);
  if (idx == TLS_OUT_OF_INDEXES) return;
  TlsSetValue(idx, (LPVOID)(intptr_t)v);
}

static char* _ct_depth_trace_read_name(int frame) {
  if (frame < 0 || frame >= CT_DEPTH_ANCESTOR_CAP) return (char*)0;
  DWORD idx = g_ct_depth_trace_tls[1 + frame];
  if (idx == TLS_OUT_OF_INDEXES) return (char*)0;
  return (char*)TlsGetValue(idx);
}

static void _ct_depth_trace_write_name(int frame, char* name) {
  if (frame < 0 || frame >= CT_DEPTH_ANCESTOR_CAP) return;
  DWORD idx = _ct_depth_trace_ensure_slot(1 + frame);
  if (idx == TLS_OUT_OF_INDEXES) return;
  TlsSetValue(idx, (LPVOID)name);
}
#else
/* POSIX: ``_Thread_local`` with the initial-exec model is reliable
   on every thread for the dynamic-linker-loaded ct_interpose.so;
   inline storage avoids any allocator dependency. */
static _Thread_local __attribute__((tls_model("initial-exec")))
    int _ct_depth_trace_depth_storage = 0;
static _Thread_local __attribute__((tls_model("initial-exec")))
    char* _ct_depth_trace_name_storage[CT_DEPTH_ANCESTOR_CAP] = {0};

static int _ct_depth_trace_read_depth(void) {
  return _ct_depth_trace_depth_storage;
}
static void _ct_depth_trace_write_depth(int v) {
  _ct_depth_trace_depth_storage = v;
}
static char* _ct_depth_trace_read_name(int frame) {
  if (frame < 0 || frame >= CT_DEPTH_ANCESTOR_CAP) return (char*)0;
  return _ct_depth_trace_name_storage[frame];
}
static void _ct_depth_trace_write_name(int frame, char* name) {
  if (frame < 0 || frame >= CT_DEPTH_ANCESTOR_CAP) return;
  _ct_depth_trace_name_storage[frame] = name;
}
#endif

#if !(defined(_MSC_VER) && defined(CT_STACKABLE_HOOKS_EXTERNAL_TLS))
void _ct_depth_trace_push(char* name) {
  /* The ``name`` slot is treated as read-only (we never mutate the
     pointed-to bytes), but we declare the parameter as ``char*`` to
     match Nim's ``cstring`` emission (``NCSTRING`` ≡ ``char*``) so
     MSVC does not raise C4028.  Logically equivalent to ``const
     char*`` for this code path. */
  int d = _ct_depth_trace_read_depth();
  if (d >= 0 && d < CT_DEPTH_ANCESTOR_CAP) {
    _ct_depth_trace_write_name(d, name);
  }
  if (d < 0x7FFFFFFF) {
    _ct_depth_trace_write_depth(d + 1);
  }
}

void _ct_depth_trace_pop(void) {
  int d = _ct_depth_trace_read_depth();
  if (d > 0) {
    d--;
    _ct_depth_trace_write_depth(d);
    if (d < CT_DEPTH_ANCESTOR_CAP) {
      _ct_depth_trace_write_name(d, (char*)0);
    }
  }
}

int _ct_depth_trace_get_depth(void) {
  return _ct_depth_trace_read_depth();
}

/* Snapshot the ancestor chain into ``buf`` as a NUL-terminated
   string of the form "outer>middle>inner".  Frames whose name
   slot is NULL render as "?".  Returns the number of bytes
   written (excluding the trailing NUL).  Truncates at ``cap-1``
   bytes; the result is always NUL-terminated when ``cap > 0``. */
int _ct_depth_trace_snapshot(char* buf, int cap) {
  if (buf == (char*)0 || cap <= 0) return 0;
  buf[0] = '\0';
  int pos = 0;
  int n = _ct_depth_trace_read_depth();
  if (n > CT_DEPTH_ANCESTOR_CAP) n = CT_DEPTH_ANCESTOR_CAP;
  for (int i = 0; i < n; i++) {
    if (i > 0 && pos < cap - 1) {
      buf[pos++] = '>';
    }
    char* name = _ct_depth_trace_read_name(i);
    if (name == (char*)0) {
      if (pos < cap - 1) buf[pos++] = '?';
    } else {
      while (*name != '\0' && pos < cap - 1) {
        buf[pos++] = *name++;
      }
    }
    if (pos >= cap - 1) break;
  }
  buf[pos] = '\0';
  return pos;
}
#endif
""".}

proc ctHookDepthGet*(): cint
    {.importc: "_ct_hook_depth_get", cdecl.}
  ## Read the calling thread's reentrancy depth counter.

proc ctHookDepthSet*(v: cint)
    {.importc: "_ct_hook_depth_set", cdecl.}
  ## Overwrite the calling thread's reentrancy depth counter.  Used
  ## by `suppressHooksForCurrentThread` to install a permanent
  ## "suppressed" state on the inject_dll init thread.

proc ctHookDepthIncAndGet*(): cint
    {.importc: "_ct_hook_depth_inc_and_get", cdecl.}
  ## Increment and return the new value.

proc ctHookDepthDecAndGet*(): cint
    {.importc: "_ct_hook_depth_dec_and_get", cdecl.}
  ## Decrement (saturating at 0) and return the new value.

template hookDepth*: int =
  ## Compatibility alias for the pre-MW16 Nim `{.threadvar.}: int`
  ## surface.  Reads route through the C-side __declspec(thread)
  ## accessor.  Existing call sites that use `hookDepth == 0`,
  ## `hookDepth > 0`, `$hookDepth`, etc. keep working unchanged.
  int(ctHookDepthGet())

template `hookDepth=`*(v: int) =
  ## Compatibility setter for the pre-MW16 Nim `{.threadvar.}: int`
  ## surface.  Writes route through the C-side accessor.
  ctHookDepthSet(cint(v))

when defined(windows):
  when defined(ctStackableHooksExternalTls) and defined(vcc):
    proc ctHookSuppressedGet(): cint
      {.importc: "_ct_hook_suppressed_get", cdecl.}
    proc ctHookSuppressedSet(v: cint)
      {.importc: "_ct_hook_suppressed_set", cdecl.}

    proc initReentrancyTls*() = discard

    proc hooksExplicitlySuppressedForCurrentThread*(): bool {.inline.} =
      ctHookSuppressedGet() != 0

    proc suppressHooksForCurrentThread*() =
      ctHookDepthSet(1)
      ctHookSuppressedSet(1)
  else:
    type DWORD = uint32

    const TlsOutOfIndexes = 0xFFFFFFFF'u32

    proc TlsAlloc(): DWORD
      {.importc, stdcall, dynlib: "kernel32".}
    proc TlsGetValue(dwTlsIndex: DWORD): pointer
      {.importc, stdcall, dynlib: "kernel32".}
    proc TlsSetValue(dwTlsIndex: DWORD, lpTlsValue: pointer): int32
      {.importc, stdcall, dynlib: "kernel32".}

    var gHookSuppressTlsIndex {.global.}: DWORD = TlsOutOfIndexes

    proc initReentrancyTls*() =
      if gHookSuppressTlsIndex == TlsOutOfIndexes:
        let idx = TlsAlloc()
        if idx != TlsOutOfIndexes:
          gHookSuppressTlsIndex = idx

    proc hooksExplicitlySuppressedForCurrentThread*(): bool {.inline.} =
      ## True after `suppressHooksForCurrentThread` permanently retires this
      ## thread from hook dispatch. Unlike hook depth, this remains true while
      ## Windows runs thread-teardown code after the recorded worker returns.
      gHookSuppressTlsIndex != TlsOutOfIndexes and
        TlsGetValue(gHookSuppressTlsIndex) != nil

    proc suppressHooksForCurrentThread*() =
      ctHookDepthSet(1)
      if gHookSuppressTlsIndex != TlsOutOfIndexes:
        discard TlsSetValue(gHookSuppressTlsIndex, cast[pointer](1))
else:
  proc initReentrancyTls*() = discard

  proc hooksExplicitlySuppressedForCurrentThread*(): bool {.inline.} =
    ## POSIX represents permanent suppression through hook depth alone.
    false

  proc suppressHooksForCurrentThread*() =
    ctHookDepthSet(1)

proc ctHooksExplicitlySuppressedForCurrentThread*(): cint
    {.exportc: "_ct_hooks_explicitly_suppressed_for_current_thread", cdecl.} =
  ## C instrumentation needs to distinguish temporary recorder recursion from
  ## the permanent post-entrypoint state of a retiring program thread.
  if hooksExplicitlySuppressedForCurrentThread(): 1.cint else: 0.cint

proc hooksAllowed*(): bool =
  ## Returns true when no hook is currently executing on this thread.
  ctHookDepthGet() == 0 and not hooksExplicitlySuppressedForCurrentThread()

proc currentHookDepth*(): int {.inline.} =
  ## MW39 (MCR-Windows-CtMcr-Port) -- public accessor for the per-thread
  ## hook reentrancy depth.  Used by the nested-hook detection diagnostic
  ## in ``ntdll_detours_windows.nim`` to decide whether the current hook
  ## invocation is nested inside an outer hook (depth > 0) so that the
  ## ``gXxxFiresNested`` counter and ``CT_NESTED_HOOK_TRACE`` log line
  ## can fire.  Same semantics as the existing ``hookDepth`` template
  ## (which reads the same C-side TLS slot) but exported as a named proc
  ## so other modules can ``import reentrancy`` and call it without
  ## relying on the legacy template form.
  int(ctHookDepthGet())

proc enterHook*() =
  ## Increment the reentrancy depth. Called on hook entry.
  discard ctHookDepthIncAndGet()

proc exitHook*() =
  ## Decrement the reentrancy depth. Called on hook exit.
  discard ctHookDepthDecAndGet()

# ── Depth-trace ancestor stack (Multi-Core-Recorder.md §8.6.1) ──
#
# These C-callable accessors maintain a per-thread "ancestor name
# stack" used by the ``CT_DEPTH_TRACE`` diagnostic surface to render
# hook-name chains like ``outer>middle>inner`` when an event is
# observed at ``currentHookDepth() > 0``.  The stack is INDEPENDENT
# of the ``hookDepth`` counter -- it carries NAMES, not the gate.
# Hook bodies that do not push a name via ``enterHookN`` leave an
# anonymous slot (``?``) in the chain at their depth level.

proc ctDepthTracePush*(name: cstring)
    {.importc: "_ct_depth_trace_push", cdecl.}
  ## Push ``name`` onto the per-thread ancestor name stack.  No-op
  ## (other than incrementing an internal depth counter for balance)
  ## when the cap is exceeded.

proc ctDepthTracePop*()
    {.importc: "_ct_depth_trace_pop", cdecl.}
  ## Pop the top entry from the per-thread ancestor name stack.
  ## Saturating at zero -- safe to call from a hook body whose
  ## matching push was elided.

proc ctDepthTraceGetDepth*(): cint
    {.importc: "_ct_depth_trace_get_depth", cdecl.}
  ## Current depth of the per-thread ancestor name stack.  Used by
  ## the diagnostic surface to detect anonymous slots (where
  ## ``ctDepthTraceGetDepth()`` exceeds the count of named pushes).

proc ctDepthTraceSnapshot*(buf: cstring, cap: cint): cint
    {.importc: "_ct_depth_trace_snapshot", cdecl.}
  ## Snapshot the current ancestor chain into ``buf`` as
  ## ``"outer>middle>inner"`` (anonymous frames render as ``?``).
  ## Returns the bytes written excluding the trailing NUL.

proc enterHookN*(name: cstring) =
  ## Named variant of ``enterHook``: bumps the reentrancy depth AND
  ## pushes ``name`` onto the ancestor stack.  Used in the recording
  ## brackets of NT detour bodies so the diagnostic surface can
  ## render ancestor chains.
  discard ctHookDepthIncAndGet()
  ctDepthTracePush(name)

proc exitHookN*(name: cstring) =
  ## Named variant of ``exitHook``: pops the ancestor stack AND
  ## decrements the reentrancy depth.  The ``name`` argument is
  ## accepted for symmetry with ``enterHookN`` (it is NOT checked
  ## against the popped value -- mismatches indicate the caller
  ## broke the LIFO discipline and the recording bracket is broken
  ## anyway).
  ctDepthTracePop()
  discard ctHookDepthDecAndGet()

proc withReentrancy*[T](body: proc(): T {.nimcall, raises: [].}): T =
  ## Temporarily decrements the hook depth by 1 so that callNext / callReal
  ## can dispatch through the hook chain even though we are already inside a
  ## hook. Restores the depth after the body returns.
  if ctHookDepthGet() == 0:
    result = body()
  else:
    discard ctHookDepthDecAndGet()
    result = body()
    discard ctHookDepthIncAndGet()

proc withReentrancyVoid*(body: proc() {.nimcall, raises: [].}) =
  ## Void version of withReentrancy for hooks that don't return a value.
  if ctHookDepthGet() == 0:
    body()
  else:
    discard ctHookDepthDecAndGet()
    body()
    discard ctHookDepthIncAndGet()

template withHookGuard*(body: untyped) =
  ## RAII-style guard: increments hookDepth on entry, decrements on exit.
  ## Use this in hook implementations to mark the "I'm in a hook" scope.
  enterHook()
  try:
    body
  finally:
    exitHook()

{.pop.}
