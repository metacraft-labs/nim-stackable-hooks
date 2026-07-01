# Compilation settings for a stackable-hooks shim

`nim-stackable-hooks` is used to build **injected shims** — libraries loaded into
an arbitrary host process via `DYLD_INSERT_LIBRARIES` (macOS), `LD_PRELOAD`
(Linux), or DLL injection (Windows) — whose hook functions run *inside* that host.

This document does **not** outlaw any Nim compilation setting. It explains the
hazards each one carries in the injected-shim environment so an adopter can choose
deliberately. The single organizing idea:

> A hook can run in a **hostile context** where touching thread-local storage,
> allocating, or entering nontrivial runtime machinery corrupts the host.

## The hostile contexts

1. **Inside libmalloc.** libmalloc grows an arena by calling `mmap` **while holding
   its arena lock**. So a hook on `mmap` (and `munmap`/`madvise`/`mremap`/…) runs
   with the allocator's lock held. Anything on that path that calls back into
   `malloc` deadlocks or corrupts the heap.
2. **Signal handlers.** Only async-signal-safe operations are legal.
3. **Threads created before the shim was mapped.** Their thread-local storage may
   not yet include the shim's slots. (The Windows .NET-CLR variant of this — raw
   `NtCreateThreadEx` threads with a `NULL ThreadLocalStoragePointer` — is
   documented in `src/stackable_hooks/reentrancy.nim`.)
4. **Foreign (non-Nim) threads generally.** The host's threads were not created by
   Nim's runtime; per-thread Nim state is initialized lazily on them.

## The load-bearing rule: thread-local first-touch can `malloc`

A Nim `{.threadvar.}`, or a C `__thread` / `_Thread_local` — with **any**
`tls_model`, including `initial-exec` — is, in a dlopen'd / inserted image:

- **macOS:** a dyld **TLV**. The *first* access on a given thread calls
  `tlv_get_addr → tlv_allocate_and_initialize_for_key → malloc`.
- **Windows:** an image-TLS-directory slot that the loader must patch into each
  live thread's TLS array; threads created outside the loader's view (CLR) can
  have a hole and **AV** at the access.

Reached from **inside libmalloc**, the macOS first-touch `malloc` re-enters the
allocator under its own lock → heap corruption → SIGSEGV. Measured with a minimal
`mmap` interpose hook: touching a `_Thread_local(initial-exec)` counter crashes
`rustc` **6/6**; the identical hook using `pthread_getspecific` is safe **0/6**;
no thread-local at all is safe.

**The safe primitive:** `pthread_getspecific`/`pthread_setspecific` (macOS/POSIX)
and `TlsGetValue`/`TlsSetValue` (Windows) read/write a slot in the thread's
**inline** TSD/TEB array — no malloc, no lock, async-signal-safe. Use
`stackable_hooks/safe_tls` (a `pthread_key`-backed word) when a hook that can run
in a hostile context needs per-thread state. Create the key once at constructor
time. `reentrancy.nim` uses the Windows `TlsAlloc` form of the same idea.

Note that `--tlsEmulation:on|off` does **not** save you on macOS: emulated TLS is a
function call that lazily `malloc`s, and native macOS TLS is a TLV that *also*
lazily `malloc`s. Both are unsafe from inside libmalloc.

## Per-setting hazards

| Setting | What it injects | Hazard in a hostile context |
|---|---|---|
| `--exceptions:goto` (default) | `nimErr_ = nimErrorFlag()` at proc entry; `nimErrorFlag()` reads the `nimInErrorMode` **threadvar** | Entering *any* such proc touches a threadvar → macOS TLV first-touch `malloc`. |
| `--exceptions:setjmp` | `setjmp`/`longjmp` frames | No error-flag threadvar, but `setjmp` buffers and unwinding are heavier; avoid raising across a hostile hook. |
| `--exceptions:quirky` | *nothing* — no error propagation | Removes the `nimInErrorMode` threadvar access. Appropriate for a shim that does not rely on exceptions; but raised exceptions are then silently unsound, so hot paths must be `{.raises: [].}` and error-free. |
| `--stackTrace:on` / `--lineTrace:on` | `framePtr` **threadvar** push/pop per proc | Same threadvar-first-touch hazard as above. A shim rarely needs Nim stack traces. |
| `--mm:orc` (default) | reference counting + cycle collector; allocations touch GC state | Allocating in a hostile context is unsafe (it calls `malloc`). A background collector adds threads. |
| `--mm:arc` | reference counting, no cycle collector | More C-like; still allocates. |
| `--mm:none` / `--os:standalone` | no GC; allocation forbidden | Safest, but the shim may not use `seq`/`string`/heap types on any path. |
| `--tlsEmulation:on/off` | emulated vs native TLS | Neither is safe from inside libmalloc on macOS (see above). |
| `-d:noSignalHandler` | *removes* Nim's SIGSEGV/… handlers | **Recommended on.** A shim must not install signal handlers — it would clobber the host's (e.g. rustc's stack-overflow handler). |
| `--threads:on` | thread-aware runtime + thread-locals | Required for per-thread correctness; interacts with all of the above. |
| `-d:danger` | disables checks + stack traces | Removes overflow/bounds checks (which call `raiseX`), but does **not** change `--exceptions`, so `nimErrorFlag` remains unless combined with `quirky`. |

## Guidance

- **Hooks that can run inside libmalloc** (mmap/munmap/madvise/mremap/…), **or from
  a signal handler**, must touch **no thread-local and must not allocate** on that
  path. Prefer to decide and forward in **C** (no Nim entry at all); if per-thread
  state is unavoidable there, use `stackable_hooks/safe_tls` (pthread), never a
  `{.threadvar.}` / `__thread`.
- **Shrink the threadvar surface** by compiling the shim as C-like as your feature
  set allows: at minimum `--stackTrace:off --lineTrace:off -d:noSignalHandler`; add
  `--exceptions:quirky` (or make hot procs `{.raises: [].}`) if you do not depend on
  Nim exceptions; consider `--mm:arc`. This does not by itself make a *specific*
  hostile hook safe — an application `{.threadvar.}` on that path is still unsafe —
  but it removes the compiler-injected threadvars from every other hook.
- **`nim-stackable-hooks` mandates none of this.** It provides the safe primitives
  (`safe_tls`, `reentrancy`) and this hazard map; the adopter picks the settings.

See each adopter's own policy doc for its concrete stance (e.g. io-mon's
`docs/shim-build-policy.md`).
