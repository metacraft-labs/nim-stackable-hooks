## Windows arm of the propagation framework.
##
## On Linux / macOS the child inherits LD_PRELOAD / DYLD_INSERT_LIBRARIES
## from the parent env so the dynamic linker loads our shim DLLs at
## startup. Windows has no such env-var equivalent; the framework
## instead suspends the new child on its initial thread, allocates a
## buffer in the child's address space, writes each enabled library's
## path into it, and ``CreateRemoteThread``-fires ``LoadLibraryW``
## followed by the library's registered init entrypoint. The main
## thread is then resumed (unless the parent already asked for
## ``CREATE_SUSPENDED``, in which case the framework leaves the
## suspension exactly as the parent requested).
##
## Reprobuild's pre-extraction ``snoopCreateProcessW`` + ad-hoc
## ``injectShimIntoChild`` lived inline at
## ``reprobuild/libs/repro_monitor_shim/src/repro_monitor_shim/windows_interpose.nim``
## and hard-coded an ``INFINITE`` wait on every cross-process thread.
## That works for short-lived workloads but compounds linearly when a
## node-heavy build (webpack, ninja, msbuild) fork-bombs through the
## hook, with loader-lock pressure scaling super-linearly because each
## child synchronously waits on its own init before its parent's hook
## returns. Adding four knobs lets the framework stay correct under
## those workloads:
##
##   * ``maxInFlight`` — a global semaphore on concurrent injections.
##     Fork-bomb workloads serialize past this cap instead of
##     overwhelming the cross-process thread scheduler. Default 16.
##   * ``waitDeadlineMs`` — replace ``INFINITE`` with a deadline. On
##     timeout the framework abandons the wait, leaves the child
##     uninstrumented, and returns ``ioWaitTimeout``. Default 5000ms.
##     Abandoning the wait means abandoning the remote thread's ARGUMENT
##     too: the child-side path buffer is deliberately leaked rather than
##     freed under a thread that may still be reading it. See the
##     cross-process lifetime note in ``injectShimIntoChild``.
##   * ``skipIfImageHasShim`` — query ``EnumProcessModulesEx`` for the
##     child's loaded modules and skip injection if the shim is
##     already mapped (e.g. via inherited handles or static linkage).
##   * resume-before-init ordering — the second ``CreateRemoteThread``
##     calling the consumer's init entrypoint is dispatched AFTER
##     the main thread resumes, so the child can make forward progress
##     while init runs concurrently rather than blocking until init
##     returns. Init takes the consumer's own internal lock; the OS
##     loader's per-DLL constructor has already completed by then so
##     loader-lock contention is bounded.
##
## MSYS2/CYGWIN CHILDREN
## ---------------------
## Two independent hazards, both propagation-framework concerns because
## ``injectShimIntoChild`` attaches to every Windows child it is handed.
##
## HAZARD 1 — the loader runs on the wrong thread. A ``CreateRemoteThread``
## into a never-run ``CREATE_SUSPENDED`` child makes the Windows loader
## initialise the whole process, ``msys-2.0.dll``'s ``DLL_PROCESS_ATTACH``
## included, on that remote thread, which then exits. The Cygwin runtime is
## left bound to a dead thread and the shell wedges at its first ``fork()``.
## ``stackable_hooks/windows_entry_park`` fixes this by parking the child's
## MAIN thread at its image entry point first; its docstring carries the
## measurements, including the two plausible alternatives that do not work.
## ``attachStrategy`` selects the technique and defaults to the park.
##
## HAZARD 2 — Cygwin's ``fork()`` is itself a ``CreateProcessW``, on OUR OWN
## IMAGE, so an instrumented shell hooks its own forks. ``isCygwinForkChild``
## identifies those, and they are refused WHEN THEY CANNOT BE PARKED. Every
## refusal returns an outcome that is NOT ``ioInjected``, so a consumer
## grading on the outcome keeps the subtree reported-incomplete rather than
## silently-complete.
##
## A FORK CHILD IS ATTACHABLE WHEN WE OWN THE SUSPENSION
## -----------------------------------------------------
## This module used to refuse every fork child outright, on two stated
## grounds. Both were measured on this host (Git-for-Windows 2.55.0.5's
## ``msys-2.0.dll``) and neither survived:
##
## 1. "The Cygwin runtime passes ``CREATE_SUSPENDED`` on every ``fork``,
##    ``exec`` and ``spawn``, so ``callerAskedSuspended`` is always true
##    there and the park is never sound."
##
##    IT DOES NOT. An instrumented ``bash`` forking, and the same ``bash``
##    ``exec``-ing ``grep``, were both observed entering the
##    ``CreateProcessW`` hook with ``CREATE_SUSPENDED`` CLEAR. This Cygwin
##    does not need the flag: the child runs immediately and synchronises
##    with its parent through the ``child_info`` block's own events. So the
##    consumer's spawn hook is free to add ``CREATE_SUSPENDED`` itself, and
##    when it does, IT owns the suspension and the park is sound by exactly
##    the same rule as for any other child.
##
## 2. "A fork child is the one case where the identical-address constraint
##    genuinely bites: the runtime replays the parent's address space into
##    it."
##
##    Not for OUR mapping. Cygwin's ``dll_list`` replay covers the DLLs the
##    runtime itself tracks; a shim mapped into the parent after that
##    snapshot is not among them and is simply absent from the child — which
##    is WHY a fork child arrives uninstrumented in the first place.
##    Injecting into the parked child adds a mapping the replay has no
##    opinion about.
##
## MEASURED, with the park applied to fork children: the research workload
## ``research/msys-attach-2026-09/heavy.sh`` (25 iterations of nested
## ``$(...)`` substitution, a pipeline and a subshell — the script that
## wedges 20/20 under a pre-park remote thread) ran 5/5 green under the
## monitor with 331 processes observed per run, including fork children,
## their ``exec``-ed children, and the second-generation forks those
## performed. The composability worry — a fork FROM a fork child — is the
## ordinary case in that workload, and it holds.
##
## SO THE CONDITION IS THE PARK, NOT THE KIND OF CHILD. ``hThread == nil``
## means the caller could not hand us the child's main thread, which means
## the caller does not own the suspension, which means the park is unsound —
## and only then is a fork child refused with ``ioSkippedForkChild``. A park
## that is attempted and fails still refuses: ``epsTimedOut`` means the
## child has RUN (``ioParkFailed``), and ``epsUnsupported`` /
## ``epsSetupFailed`` on a fork-runtime image means the legacy remote thread
## would wedge it (``ioSkippedForkRuntime``).
##
## WHAT IS STILL NOT ATTACHED, and why
## -----------------------------------
## A child whose caller genuinely asked for ``CREATE_SUSPENDED``. The park
## runs the child's loader, and such a caller is entitled to a child that
## has executed nothing, so the consumer's hook must not add a suspension of
## its own there and must pass ``hThread = nil``. On this Cygwin that case
## turns out to be the exception rather than the rule for MSYS spawns, but
## it is the case the refusals above exist for.
##
## NOT THE RESUME. An earlier design hooked ``kernel32!ResumeThread`` to
## attach in the window between the runtime finishing its writes and the
## child running. It was built and measured, and there is no such window:
## the runtime never suspends these children, so the hook never fires for
## one. (``msys-2.0.dll`` does import ``ResumeThread`` from ``KERNEL32`` and
## imports no resume entry point from ``ntdll`` — the hook point was right,
## the premise was not.) Hooking ``ResumeThread`` is also actively
## dangerous here: ``ct_inline_hook`` calls it to thaw the threads it froze
## to apply a patch, so the detour re-enters the shim with every other
## thread of the process suspended, and the first allocation deadlocks the
## process where it stands.

when not defined(windows):
  {.error: "stackable_hooks/propagation_windows is Windows-only".}

{.push raises: [].}

import std/[atomics, locks, strutils, widestrs]

import ./hook_registry
import ./propagation
import ./windows_entry_park
import ./windows_fork_runtime
import ./windows_injector

# Re-exported whole: a consumer that spawns its own suspended children
# needs the park primitive itself, not only the outcomes this module
# derives from it.
export windows_entry_park

# Re-exported so a shim's spawn hook can consult it through this module,
# which is the one it already imports for `injectShimIntoChild`.
export windows_injector.spawningHelperProcess

# ---------------------------------------------------------------------------
# Win32 typedefs and imports
# ---------------------------------------------------------------------------

type
  HANDLE = pointer
  DWORD = uint32
  BOOL = int32
  LPCWSTR = ptr uint16
  LPWSTR = ptr uint16
  LPVOID = pointer
  LPCVOID = pointer
  LPSECURITY_ATTRIBUTES = pointer
  SIZE_T = uint

  PROCESS_INFORMATION {.bycopy.} = object
    hProcess, hThread: HANDLE
    dwProcessId, dwThreadId: DWORD

const
  CREATE_SUSPENDED = 0x00000004'u32
  MEM_COMMIT = 0x00001000'u32
  MEM_RESERVE = 0x00002000'u32
  MEM_RELEASE = 0x00008000'u32
  PAGE_READWRITE = 0x04'u32
  WAIT_OBJECT_0 = 0x0'u32
  GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x00000004'u32
  GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 0x00000002'u32

proc GetLastError(): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc SetLastError(dwErrCode: DWORD)
  {.importc, stdcall, dynlib: "kernel32".}
proc GetModuleHandleW(lpModuleName: LPCWSTR): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc GetModuleHandleExW(dwFlags: DWORD, lpModuleName: LPCWSTR,
                        phModule: ptr HANDLE): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetModuleFileNameW(hModule: HANDLE, lpFilename: LPWSTR,
                        nSize: DWORD): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc IsWow64Process(hProcess: HANDLE, Wow64Process: ptr BOOL): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetProcAddress(hModule: HANDLE, lpProcName: cstring): pointer
  {.importc, stdcall, dynlib: "kernel32".}
proc GetModuleBaseNameW(hProcess: HANDLE, hModule: HANDLE,
                        lpBaseName: LPWSTR, nSize: DWORD): DWORD
  {.importc, stdcall, dynlib: "psapi".}
proc EnumProcessModulesEx(hProcess: HANDLE, lphModule: ptr pointer,
                          cb: DWORD, lpcbNeeded: ptr DWORD,
                          dwFilterFlag: DWORD): BOOL
  {.importc, stdcall, dynlib: "psapi".}
proc VirtualAllocEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
                    flAllocationType: DWORD, flProtect: DWORD): LPVOID
  {.importc, stdcall, dynlib: "kernel32".}
proc VirtualFreeEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
                   dwFreeType: DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: LPVOID,
                        lpBuffer: LPCVOID, nSize: SIZE_T,
                        lpNumberOfBytesWritten: ptr SIZE_T): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc CreateRemoteThread(hProcess: HANDLE,
                        lpThreadAttributes: LPSECURITY_ATTRIBUTES,
                        dwStackSize: SIZE_T, lpStartAddress: pointer,
                        lpParameter: LPVOID, dwCreationFlags: DWORD,
                        lpThreadId: ptr DWORD): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc ResumeThread(hThread: HANDLE): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc CloseHandle(hObject: HANDLE): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc QueryFullProcessImageNameW(hProcess: HANDLE, dwFlags: DWORD,
                                lpExeName: LPWSTR,
                                lpdwSize: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetCurrentProcess(): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}

proc windowsProcessImagePath*(hProcess: pointer): string =
  ## Resolve a child image after CreateProcessW has created it suspended.
  ## Querying the process avoids reparsing Windows command-line quoting.
  if hProcess == nil:
    return ""
  var pathBuffer: array[32768, uint16]
  var pathChars = DWORD(pathBuffer.len)
  if QueryFullProcessImageNameW(hProcess, 0'u32,
      cast[LPWSTR](addr pathBuffer[0]), addr pathChars) == 0:
    return ""
  `$`(cast[WideCString](addr pathBuffer[0]), int(pathChars))

proc windowsForkRuntimeForProcess*(hProcess: pointer): string =
  windowsForkRuntimeForImagePath(windowsProcessImagePath(hProcess))

# ---------------------------------------------------------------------------
# Configuration + outcome types
# ---------------------------------------------------------------------------

type
  AttachStrategy* = enum
    ## How ``injectShimIntoChild`` reaches a suspended child.
    asEntryPark
      ## Park the child's main thread at its image entry point, so the
      ## Windows loader initialises the process ON THAT THREAD, then
      ## inject. The default, and universal: it is applied to every child,
      ## not only MSYS2/Cygwin ones. The comment block in
      ## ``injectShimIntoChild`` records why universal was chosen over
      ## gating the park on fork-runtime detection.
    asDirect
      ## VERBATIM PRE-PARK BEHAVIOUR: ``CreateRemoteThread`` straight into a
      ## child that has never executed an instruction, with no fork-runtime
      ## refusal in front of it. On an MSYS2/Cygwin child this WEDGES the
      ## child at its first ``fork()`` while still returning ``ioInjected``
      ## — the exact falsely-complete outcome the default exists to
      ## prevent. It is kept for two reasons: a consumer that needs
      ## bit-identical legacy semantics can still ask for them, and the
      ## regression test needs to be able to demand the broken behaviour so
      ## the passing case cannot pass vacuously.
      ##
      ## Note this is a strategy, not a fallback. When ``asEntryPark`` is
      ## selected and the park is merely UNAVAILABLE (no main-thread
      ## handle, ARM64, a 32-bit host looking at a 64-bit child) the direct
      ## technique is still used for a native child — but a fork-runtime
      ## child is refused with ``ioSkippedForkRuntime`` instead.

  InjectionConfig* = object
    ## Tuning knobs for ``injectShimIntoChild``. See the module docstring
    ## for the rationale on each field.
    maxInFlight*: int
    waitDeadlineMs*: DWORD
    skipIfImageHasShim*: bool
    attachStrategy*: AttachStrategy
    parkTimeoutMs*: DWORD

  InjectionOutcome* = enum
    ioInjected, ioAlreadyPresent, ioSkippedCap,
    ioWaitTimeout, ioInjectFailed, ioInitFailed,
    ioNothingToInject,
    ioSkippedForkChild,
      ## The child is this process's own Cygwin/MSYS ``fork()`` child AND
      ## could not be parked, because the caller owns its suspension. A fork
      ## child we CAN park is injected like any other; see
      ## ``isCygwinForkChild`` and the module docstring.
    ioSkippedForkRuntime,
      ## The child uses an MSYS2/Cygwin fork runtime AND could not be
      ## parked, so injecting would wedge it at its first ``fork()``.
      ## Refused rather than attempted.
    ioParkFailed
      ## The entry-point park resumed the child and it never reached its
      ## entry point. The child has RUN, so a post-hoc injection would be
      ## the racy technique the park exists to replace. Refused.

proc defaultInjectionConfig*(): InjectionConfig =
  ## Defaults chosen for webpack-class fork-bomb workloads:
  ## - maxInFlight = 16: enough to keep the OS thread scheduler busy
  ##   without amplifying loader-lock pressure linearly with the
  ##   parent's fork rate.
  ## - waitDeadlineMs = 5000: covers a slow init under contention but
  ##   bounds the parent's hook return so a wedged child can't wedge
  ##   the entire build.
  ## - skipIfImageHasShim = true: the cheapest win is not injecting
  ##   when the shim is already present from inherited handles or
  ##   static linkage.
  ## - attachStrategy = asEntryPark: universal, see the type's docstring.
  ## - parkTimeoutMs = 5000: the park completes in 1-2 ms on a real image;
  ##   this is a safety net for a child that never reaches its entry
  ##   point at all, not a tuning parameter.
  InjectionConfig(maxInFlight: 16,
                  waitDeadlineMs: 5000,
                  skipIfImageHasShim: true,
                  attachStrategy: asEntryPark,
                  parkTimeoutMs: 5000)

# ---------------------------------------------------------------------------
# Concurrency cap (maxInFlight)
# ---------------------------------------------------------------------------

var
  inFlightLock {.global.}: Lock
  inFlightCount {.global.}: int
  inFlightLockInit {.global.} = false

proc ensureInFlightLock() =
  if not inFlightLockInit:
    initLock(inFlightLock)
    inFlightLockInit = true

proc tryAcquireInFlight(cap: int): bool =
  ## Cheap CAS-style admission control: hold the lock for the cap check
  ## only. The actual injection runs OUTSIDE the lock so concurrent
  ## injections proceed in parallel up to the cap.
  ensureInFlightLock()
  acquire(inFlightLock)
  defer: release(inFlightLock)
  if inFlightCount >= cap:
    return false
  inFlightCount.inc
  true

proc releaseInFlight() =
  ensureInFlightLock()
  acquire(inFlightLock)
  defer: release(inFlightLock)
  if inFlightCount > 0:
    inFlightCount.dec

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc wideStringFromString(s: string): seq[uint16] =
  ## UTF-8 → UTF-16LE for the Win32 wide path APIs. We don't go through
  ## ``MultiByteToWideChar`` because our paths are always ASCII (NT
  ## extended-path form with backslashes); a straight widen suffices.
  result.setLen(s.len + 1)
  for i, c in s:
    result[i] = uint16(c)
  result[s.len] = 0'u16

proc childHasModule(hProcess: HANDLE; basename: string): bool =
  ## Check whether the child has any loaded module whose basename
  ## (case-insensitive) matches ``basename``.
  var mods: array[1024, HANDLE]
  var cb: DWORD = 0
  if EnumProcessModulesEx(hProcess, cast[ptr pointer](addr mods[0]),
      DWORD(sizeof(mods)), addr cb, 0x3'u32) == 0:
    return false
  let n = int(cb) div sizeof(HANDLE)
  for i in 0 ..< min(n, mods.len):
    var nameBuf: array[1024, uint16]
    let nl = GetModuleBaseNameW(hProcess, mods[i],
      cast[LPWSTR](addr nameBuf[0]), DWORD(nameBuf.len))
    if nl == 0:
      continue
    var got = newString(int(nl))
    for j in 0 ..< int(nl):
      got[j] = char(nameBuf[j] and 0xFF)
    if cmpIgnoreCase(got, basename) == 0:
      return true
  false

proc basenameOf(path: string): string =
  let i = max(path.rfind('\\'), path.rfind('/'))
  if i < 0: path else: path.substr(i + 1)

proc mappedForkRuntime*(): string =
  ## Which MSYS2/Cygwin runtime, if any, is MAPPED INTO THIS PROCESS.
  ##
  ## Note the difference from ``windowsForkRuntimeForProcess``, which asks
  ## the FILESYSTEM whether a runtime sits next to an image. That is a
  ## heuristic — it cannot see a runtime resolved off ``PATH`` from another
  ## directory, and it answers for a runtime that is merely present rather
  ## than loaded. For OUR OWN process we do not have to guess: the loader
  ## already knows, and ``GetModuleHandleW`` reports it authoritatively.
  for runtime in ["msys-2.0.dll", "cygwin1.dll"]:
    var name = wideStringFromString(runtime)
    if GetModuleHandleW(cast[LPCWSTR](addr name[0])) != nil:
      return runtime
  ""

proc isCygwinForkChild*(hProcess: pointer): bool =
  ## True when ``hProcess`` is a re-exec of THIS process's own image issued
  ## from inside a mapped MSYS2/Cygwin runtime — i.e. a ``fork()`` child
  ## (or a self-``exec``/self-``spawn``, which take the same runtime path).
  ##
  ## Cygwin implements ``fork()`` as ``CreateProcessW`` on its own image
  ## followed by ``WriteProcessMemory`` of the parent's address space into
  ## the child. Two things follow. First, injecting into one is exactly the
  ## identical-address case the Cygwin hooking spec warns about, and unlike
  ## HAZARD 1 no thread trick makes it safe. Second, the child is entitled
  ## to have executed NOTHING when the runtime starts writing into it, so it
  ## must not be parked either. Refuse both.
  ##
  ## WHAT THIS DETECTION CAN SEE
  ## * Any fork issued by a process we ourselves instrumented — bash never
  ##   calls Win32 ``CreateProcessW`` directly, so a spawn we observe from
  ##   inside a mapped runtime came from the runtime.
  ## * It separates ``fork`` from ``spawn``: bash running ``nim.exe`` is a
  ##   DIFFERENT image and stays injectable, which is what keeps the trace
  ##   complete for the native subtree.
  ##
  ## WHAT IT CANNOT SEE
  ## * A fork whose child image resolves to a different path than ours —
  ##   a copy, a hardlink, or a bind-style junction of the same binary.
  ##   Both sides go through ``QueryFullProcessImageNameW`` so casing and
  ##   short names normalise, but content-identical files at two paths do
  ##   not.
  ## * A fork inside a Cygwin process we never instrumented: we never see
  ##   its ``CreateProcessW`` at all, so there is nothing to classify.
  ## * Whether a fork child ends up instrumented. The parent's address
  ##   space is copied verbatim, so our mapped pages and the IAT patches
  ##   pointing at them are present in the child — but with no loader entry
  ##   behind them, and Cygwin's own ``dll_list`` replay only covers DLLs
  ##   loaded through the runtime, which ours is not. This function makes
  ##   no claim either way, and the ``ioSkippedForkChild`` outcome is
  ##   deliberately not ``ioInjected`` so the subtree grades as incomplete.
  if hProcess == nil:
    return false
  # Cheap gate first: the overwhelmingly common case is a native parent,
  # and this costs two GetModuleHandleW calls with no allocation of the
  # 32K-wide path buffers below.
  if mappedForkRuntime().len == 0:
    return false
  let childImage = windowsProcessImagePath(hProcess)
  if childImage.len == 0:
    return false
  let selfImage = windowsProcessImagePath(GetCurrentProcess())
  if selfImage.len == 0:
    return false
  cmpIgnoreCase(childImage, selfImage) == 0

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

proc injectShimIntoChild*(hProcess: HANDLE;
                          libraryPath: string;
                          initSymbol: string = "";
                          cfg: InjectionConfig = defaultInjectionConfig();
                          hThread: HANDLE = nil):
    InjectionOutcome =
  ## Inject one library into the given child process. The caller is
  ## responsible for having spawned the child with ``CREATE_SUSPENDED``
  ## and for resuming its main thread once propagation completes.
  ##
  ## ``hThread`` is the child's MAIN thread, still carrying that
  ## ``CREATE_SUSPENDED`` count of one. Passing it enables the entry-point
  ## park (HAZARD 1 in the module docstring), which is what makes an
  ## MSYS2/Cygwin child attachable at all. It is a defaulted parameter so
  ## existing three-argument callers keep compiling and keep their exact
  ## previous behaviour.
  ##
  ## THE PARK IS SUSPEND-COUNT NEUTRAL. It resumes the thread, waits for it
  ## to reach the image entry point, and suspends it again, so on return
  ## the thread is suspended exactly once - precisely as it was passed in.
  ## The caller's own ``ResumeThread`` remains the single wakeup.
  ##
  ## DO NOT pass ``hThread`` when the CALLER of ``CreateProcessW`` asked
  ## for ``CREATE_SUSPENDED`` themselves. The park runs the child's loader,
  ## and such a caller is entitled to a child that has executed nothing.
  ## With ``hThread = nil`` this proc falls back to the legacy technique and
  ## refuses fork-runtime children outright.
  ##
  ## Passing it for a Cygwin ``fork()`` child is not only allowed but is the
  ## whole reason that subtree is observable: this Cygwin does NOT create
  ## fork children suspended, so the consumer's own forced
  ## ``CREATE_SUSPENDED`` is the only one there is. See the module
  ## docstring's measurement.
  ##
  ## Returns one of:
  ##   ``ioInjected``       — LoadLibraryW completed; init (if any) was
  ##                          dispatched on its own remote thread.
  ##   ``ioAlreadyPresent`` — child already has the library mapped;
  ##                          skipped per ``skipIfImageHasShim``.
  ##   ``ioSkippedCap``     — the global ``maxInFlight`` semaphore is
  ##                          saturated; the caller can decide whether
  ##                          to retry or proceed un-injected.
  ##   ``ioWaitTimeout``    — LoadLibraryW didn't complete within
  ##                          ``waitDeadlineMs``; child runs uninstrumented
  ##                          and the child-side path buffer is
  ##                          deliberately leaked (reclaimed when the child
  ##                          exits).
  ##   ``ioInjectFailed``   — VirtualAllocEx / WriteProcessMemory /
  ##                          CreateRemoteThread reported an error.
  ##   ``ioInitFailed``     — LoadLibraryW succeeded but the init
  ##                          remote thread couldn't be created.
  ##   ``ioSkippedForkChild``   — the child is this process's own Cygwin
  ##                          ``fork()`` child and no main thread was passed,
  ##                          so it could not be parked.
  ##   ``ioSkippedForkRuntime`` — the child carries an MSYS2/Cygwin fork
  ##                          runtime and could not be parked; injecting
  ##                          would wedge it, so nothing was attempted.
  ##   ``ioParkFailed``     — the park resumed the child and it never
  ##                          reached its entry point; the child has run,
  ##                          so injection was refused rather than raced.
  ##
  ## Only ``ioInjected`` and ``ioAlreadyPresent`` mean the child is
  ## instrumented. Every refusal above is deliberately a DIFFERENT value so
  ## a consumer cannot grade a skipped subtree as complete.
  if libraryPath.len == 0:
    return ioNothingToInject

  # Never inject into our own probe/helper. Those are spawned from inside
  # this very path, so injecting them recurses: the helper exists to inject
  # a 64-bit child, and injecting the helper needs a helper. They are also
  # not part of the traced program -- their I/O is infrastructure, not a
  # dependency of the action being recorded.
  if spawningHelperProcess():
    return ioNothingToInject

  # HAZARD 2. Cygwin's fork() is itself a CreateProcessW on our own image,
  # so an instrumented shell hooks its own forks.
  #
  # `hThread == nil` is the whole condition, and it is not really about
  # forking: it says the caller did not hand us the child's main thread, so
  # the caller does not own the child's suspension, so the child cannot be
  # parked, so the only technique left is the pre-loader remote thread --
  # which wedges a Cygwin child at its first fork(). Refuse.
  #
  # With a main thread in hand the child IS attachable, fork child or not.
  # The module docstring carries the measurement, and the two grounds on
  # which this used to be an unconditional refusal, neither of which held.
  if isCygwinForkChild(hProcess) and hThread == nil:
    return ioSkippedForkChild

  # A 32-bit child takes the 32-bit shim, so the already-present check has
  # to look for the shim that would actually be injected -- see
  # docs/windows-wow64-injection.md.
  var childIsWow64: BOOL = 0
  discard IsWow64Process(hProcess, addr childIsWow64)
  let effectiveLibrary =
    if childIsWow64 != 0: wow64ShimPathFor(libraryPath) else: libraryPath

  # ---------------------------------------------------------------------
  # HAZARD 1 -- the attach strategy. THIS IS UNIVERSAL, NOT GATED ON MSYS.
  #
  # The alternative was to park only children that look like they carry a
  # fork runtime. That was rejected: the gate would be
  # `windowsForkRuntimeForImagePath`, a FILESYSTEM heuristic asking whether
  # `msys-2.0.dll` happens to sit next to the image. It cannot see a
  # runtime resolved off PATH from another directory, and a gate that
  # answers "no" wrongly does not degrade -- it HANGS the child. Making
  # correctness depend on that heuristic being right is worse than not
  # depending on it at all.
  #
  # Universal is also less of a change than it looks. The legacy technique
  # ALREADY runs the child's entire loader before our shim maps -- that is
  # the whole diagnosis: `LdrpInitializeProcess` runs on the injected
  # remote thread. The park does not reorder anything relative to our shim;
  # it moves that same initialisation onto the thread the OS would have
  # used for an uninstrumented process. Every native child therefore ends
  # up CLOSER to its uninstrumented behaviour, not further from it.
  #
  # Composition with the other knobs:
  #  * `maxInFlight` deliberately does NOT cover the park. That cap exists
  #    to bound concurrent cross-process REMOTE THREADS; a park creates no
  #    remote thread. N concurrent parks are N children performing ordinary
  #    process startup, which is what an uninstrumented fork bomb does
  #    anyway.
  #  * `skipIfImageHasShim` gets strictly better: the probe below now runs
  #    against a child whose loader has FINISHED, so `EnumProcessModulesEx`
  #    reports the real module list instead of the two or three entries a
  #    never-run process has. A statically linked shim was previously
  #    invisible to it.
  #  * `waitDeadlineMs` and resume-before-init are untouched.
  #
  # NOT FOR A WOW64 CHILD. The park is only half of the technique; the
  # other half is borrowing the parked thread to map the shim, and
  # `callOnParkedThread` refuses a 32-bit child because a 32-bit frame and
  # `Wow64SetThreadContext` are unmeasured here. Parking one anyway would
  # produce exactly the combination that corrupts a child -- a
  # loader-initialised main thread plus a remote-thread load -- so a
  # 32-bit child keeps the legacy technique end to end and a 32-bit child
  # carrying a fork runtime is refused rather than wedged.
  var park = parkChildAtEntryPoint(hProcess, hThread, childIsWow64 != 0,
    (if cfg.attachStrategy == asEntryPark and childIsWow64 == 0:
       cfg.parkTimeoutMs
     else: 0'u32))
  defer: releaseEntryPark(park)

  if cfg.attachStrategy == asEntryPark:
    case park.status
    of epsParked:
      discard
    of epsTimedOut:
      # The child HAS RUN. Injecting now is the fixed-`Sleep` technique
      # that was measured to be a race (0 ms hangs, >=1 ms passes) rather
      # than a fix. Refuse, and let the consumer grade the subtree
      # incomplete.
      return ioParkFailed
    of epsUnsupported, epsSetupFailed:
      # The child has executed NOTHING and is exactly as CreateProcessW
      # left it, so the legacy pre-loader remote thread is still available
      # and is byte-for-byte what this proc did before the park existed --
      # correct for a native child, fatal for a fork-runtime one. The
      # filesystem heuristic is consulted HERE and nowhere else: it is not
      # load-bearing for a child we managed to park, and being wrong on
      # this path can only cost us an injection, never wedge a child.
      if windowsForkRuntimeForProcess(hProcess).len > 0:
        return ioSkippedForkRuntime

  when sizeof(pointer) == 4:
    # We are a 32-bit shim. A child that is NOT WOW64 on 64-bit Windows is a
    # 64-bit process, and none of what follows can reach it: our
    # VirtualAllocEx / WriteProcessMemory / CreateRemoteThread go through the
    # WOW64 thunk layer, which does not address a 64-bit address space, and
    # we cannot resolve the 64-bit kernel32's LoadLibraryW either.
    #
    # This is not a corner case. A 32-bit PATH trampoline (scoop's shims are
    # i386) is injected as a WOW64 child and then spawns the real 64-bit
    # tool; that grandchild is exactly this situation, and leaving it
    # uninjected makes the subtree an unknown-scope loss that disqualifies
    # the action from the cache.
    #
    # So hand the whole operation to a 64-bit helper, the mirror of what the
    # 32-bit probe does for a 64-bit injector.
    if childIsWow64 == 0 and hostIsWow64Capable():
      let shim64 = shim64PathFor(libraryPath)
      if cfg.skipIfImageHasShim and childHasModule(hProcess,
          basenameOf(shim64)):
        return ioAlreadyPresent
      return (if runInject64Helper(hProcess, shim64, initSymbol): ioInjected
              else: ioInjectFailed)

  if cfg.skipIfImageHasShim and
      childHasModule(hProcess, basenameOf(effectiveLibrary)):
    return ioAlreadyPresent

  if not tryAcquireInFlight(cfg.maxInFlight):
    return ioSkippedCap
  defer: releaseInFlight()

  var wpath = wideStringFromString(effectiveLibrary)
  let bufSize = SIZE_T(wpath.len * sizeof(uint16))
  let remoteBuf = VirtualAllocEx(hProcess, nil, bufSize,
    MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if remoteBuf == nil:
    return ioInjectFailed

  # ---------------------------------------------------------------------
  # CROSS-PROCESS LIFETIME — why there is no unconditional ``defer`` here.
  #
  # ``remoteBuf`` lives in the CHILD's address space and is handed to a
  # ``CreateRemoteThread`` running ``kernel32!LoadLibraryW``. That thread's
  # lifetime is NOT bounded by this stack frame, so the local ``defer``
  # idiom — "free on every exit path" — is wrong here BY CONSTRUCTION: it
  # is a lifetime rule for objects this frame owns, and this frame does
  # not own the remote read.
  #
  # The bug it caused: on the ``ioWaitTimeout`` path the deadline expired
  # while ``LoadLibraryW`` was still running, and the ``defer`` unmapped
  # the buffer under it. ntdll's AVX2 zero-scan over the path string
  # (``vpcmpeqb ymm1,ymm2,[rdx]``) then read a region that had gone
  # ``MEM_FREE``, and the child died with ``STATUS_ACCESS_VIOLATION``
  # (0xC0000005) — observed as compilers crashing mid-build on Windows.
  # Only GRANDchildren were ever hit, because the ROOT injector
  # (``windows_injector.nim``) waits ``INFINITE`` and therefore always has
  # proof the remote thread finished before it frees.
  #
  # The rule: free ONLY with PROOF the remote thread exited, i.e. only
  # after ``WaitForSingleObject`` returned ``WAIT_OBJECT_0``. Until the
  # remote thread exists, this frame is still the sole owner and freeing
  # is safe (the early-failure returns below); the instant the thread is
  # created ownership transfers to it, and it comes back only on
  # ``WAIT_OBJECT_0``.
  #
  # On timeout/failure we therefore DELIBERATELY LEAK the reservation.
  # The cost is bounded and self-healing: one 64 KB reservation in the
  # CHILD's address space, reclaimed in full when the child exits. Leaking
  # that is strictly better than unmapping memory a live remote thread is
  # mid-read.
  # ---------------------------------------------------------------------
  var remoteBufOwned = true
  defer:
    if remoteBufOwned:
      discard VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE)

  var written: SIZE_T = 0
  if WriteProcessMemory(hProcess, remoteBuf, addr wpath[0],
      bufSize, addr written) == 0:
    return ioInjectFailed

  # A WOW64 child's kernel32 is at a different base and this process
  # cannot resolve that address; the 32-bit probe reports it. Refuse
  # rather than fall back -- a wrong address starts a remote thread at a
  # meaningless location instead of failing cleanly.
  var loadLibraryW: pointer = nil
  if childIsWow64 != 0:
    let addr32 = wow64LoadLibraryWAddress(wow64ProbePathFor(libraryPath))
    if addr32 == 0:
      return ioInjectFailed
    loadLibraryW = cast[pointer](uint(addr32))
  else:
    var kernel32Name = wideStringFromString("kernel32.dll")
    let kernel32 = GetModuleHandleW(cast[LPCWSTR](addr kernel32Name[0]))
    if kernel32 == nil:
      return ioInjectFailed
    loadLibraryW = GetProcAddress(kernel32, "LoadLibraryW")
    if loadLibraryW == nil:
      return ioInjectFailed

  # WHO CALLS ``LoadLibraryW`` MATTERS AS MUCH AS THE CALL. A remote
  # thread runs the shim's module body and then exits, and a Nim
  # ``--threads:on`` shim keeps its allocator in a THREADVAR -- so every
  # process-global the module body allocated is owned by a region that dies
  # with that thread, and the first cross-thread free of one dereferences
  # it. Before the park the two threads' regions happened to coincide;
  # parked, they do not. The measurement and the fault are documented on
  # ``windows_entry_park.callOnParkedThread``; it borrows the parked main
  # thread so the child maps the shim itself.
  var borrowedLoad = false
  if park.status == epsParked and childIsWow64 == 0:
    var llModule: uint64 = 0
    # The buffer belongs to the child for the duration of the borrowed
    # call, exactly as it belongs to a remote thread on the legacy arm.
    remoteBufOwned = false
    if not callOnParkedThread(park, hThread, false, loadLibraryW,
        remoteBuf, cfg.parkTimeoutMs, llModule):
      # The child either died or never came back to the parked entry
      # point. Falling back to a remote thread here is NOT available: it
      # is the combination this branch exists to avoid.
      return ioInjectFailed
    # The call returned, so ``LoadLibraryW`` is done with the path string.
    remoteBufOwned = true
    if llModule == 0:
      return ioInjectFailed
    borrowedLoad = true
  else:
    let llThread = CreateRemoteThread(hProcess, nil, 0, loadLibraryW,
      remoteBuf, 0, nil)
    if llThread == nil:
      # No remote thread exists, so nothing can be reading the buffer:
      # ownership never left this frame and the deferred free is correct.
      return ioInjectFailed
    # Ownership transfers to the remote thread HERE, before the wait — a
    # thread that outlives the deadline must keep its argument.
    remoteBufOwned = false
    let wait = WaitForSingleObject(llThread, cfg.waitDeadlineMs)
    discard CloseHandle(llThread)
    if wait != WAIT_OBJECT_0:
      # Timed out (or the wait itself failed): the remote thread may still
      # be dereferencing ``remoteBuf``. Leak it on purpose — see the
      # cross-process lifetime note above.
      return ioWaitTimeout
    # WAIT_OBJECT_0 is the PROOF the remote thread exited; LoadLibraryW is
    # done with the path string, so ownership is ours again.
    remoteBufOwned = true

  # Init dispatch — only when the consumer asked for one.
  if initSymbol.len == 0:
    return ioInjected

  # Resolve the init symbol's RVA from our own image and dispatch it on
  # the child by translating to the child-side base. The walk of the
  # child's module list is the same EnumProcessModulesEx call as the
  # "skipIfImageHasShim" probe, just keyed on a different result —
  # we need the HMODULE of the now-loaded library.
  var ourMod: HANDLE = nil
  # GetModuleHandleExW with FROM_ADDRESS expects an address inside the
  # caller's module. We use ``cast[pointer](injectShimIntoChild)`` —
  # this proc lives in the same DLL the consumer is asking us to
  # propagate, so the module handle is correct.
  if GetModuleHandleExW(
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS or
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
      cast[LPCWSTR](cast[uint](injectShimIntoChild)),
      addr ourMod) == 0 or ourMod == nil:
    return ioInjected
  let ourInit = GetProcAddress(ourMod, initSymbol.cstring)
  if ourInit == nil:
    return ioInjected
  var rva = cast[uint](ourInit) - cast[uint](ourMod)

  # Our own module is only a valid stand-in for the child's when the two are
  # the same image. A 64-bit shim propagating into a WOW64 grandchild injects
  # `<name>32.dll`, a DIFFERENT binary whose exports sit at different
  # offsets, so this RVA would name an arbitrary address there. Ask the
  # 32-bit probe about the image actually being injected.
  #
  # A 32-bit shim propagating into a 32-bit child needs none of this: it IS
  # the image being injected, so the offset it computed above is already the
  # right one.
  when sizeof(pointer) == 8:
    if childIsWow64 != 0:
      let fromProbe = wow64ExportRva(wow64ProbePathFor(libraryPath),
        effectiveLibrary, initSymbol)
      if fromProbe == 0'u32:
        return ioInjectFailed
      rva = uint(fromProbe)

  # Find the child-side base for the same library basename.
  let wantBase = basenameOf(libraryPath)
  var mods: array[1024, HANDLE]
  var cb: DWORD = 0
  if EnumProcessModulesEx(hProcess, cast[ptr pointer](addr mods[0]),
      DWORD(sizeof(mods)), addr cb, 0x3'u32) == 0:
    return ioInjected
  let nMods = int(cb) div sizeof(HANDLE)
  var childBase: HANDLE = nil
  for i in 0 ..< min(nMods, mods.len):
    var nameBuf: array[1024, uint16]
    let nl = GetModuleBaseNameW(hProcess, mods[i],
      cast[LPWSTR](addr nameBuf[0]), DWORD(nameBuf.len))
    if nl == 0:
      continue
    var got = newString(int(nl))
    for j in 0 ..< int(nl):
      got[j] = char(nameBuf[j] and 0xFF)
    if cmpIgnoreCase(got, wantBase) == 0:
      childBase = mods[i]
      break
  if childBase == nil:
    return ioInjected

  let childInit = cast[pointer](cast[uint](childBase) + rva)
  if borrowedLoad:
    # Same thread that mapped the shim, for the same reason: init installs
    # the hooks and touches the shim's thread-locals, and the thread whose
    # locals have to be sound is the child's own.
    var initRet: uint64 = 0
    if not callOnParkedThread(park, hThread, false, childInit, nil,
        cfg.parkTimeoutMs, initRet):
      return ioInitFailed
    return ioInjected
  let initThread = CreateRemoteThread(hProcess, nil, 0, childInit,
    nil, 0, nil)
  if initThread == nil:
    return ioInitFailed
  # The init thread is passed ``nil`` as its parameter — it never touches
  # ``remoteBuf`` — and ``LoadLibraryW`` has provably returned by now, so
  # the deferred free is safe on both arms below.
  let initWait = WaitForSingleObject(initThread, cfg.waitDeadlineMs)
  discard CloseHandle(initThread)
  if initWait != WAIT_OBJECT_0:
    return ioWaitTimeout
  ioInjected

# ---------------------------------------------------------------------------
# Auto-propagation: CreateProcess hook body
# ---------------------------------------------------------------------------

proc autoPropagateCreateProcessW*(ctx: var HookContext) {.raises: [].} =
  ## Low-priority hook to register on ``CreateProcessW``. Forces
  ## ``CREATE_SUSPENDED`` into the child's flags, calls the chain, then
  ## walks the propagation registry to inject every enabled library
  ## before resuming the child.
  ##
  ## The caller's original ``CREATE_SUSPENDED`` is preserved: if they
  ## already wanted the child suspended, we DON'T touch the main
  ## thread when we're done (their own ``ResumeThread`` later will
  ## drive the wakeup).
  let callerFlags = DWORD(ctx.args[5])
  let callerAskedSuspended = (callerFlags and CREATE_SUSPENDED) != 0
  ctx.args[5] = uint64(callerFlags or CREATE_SUSPENDED)

  callNext(ctx)

  let savedLastError = GetLastError()
  let bResult = BOOL(ctx.result)
  let pi = cast[ptr PROCESS_INFORMATION](ctx.args[9])
  if bResult == 0 or pi == nil:
    SetLastError(savedLastError)
    return

  # A native launcher such as make.exe can spawn MSYS2/Cygwin workers, and
  # an instrumented shell calls CreateProcessW from inside its own fork().
  # Both hazards are handled INSIDE injectShimIntoChild now -- it parks the
  # child's main thread at the image entry point so the loader initialises
  # on that thread, and it refuses a fork child of this very process
  # outright. The blanket `windowsForkRuntimeForProcess(...) == 0` guard
  # that used to stand here is gone with them: it was a filesystem
  # heuristic standing in for a thread-scheduling problem, and it skipped
  # every MSYS child whether or not it was attachable.
  #
  # What we still decide here, because only this frame knows it, is whether
  # the park is SOUND. The park runs the child's loader. A caller who asked
  # for CREATE_SUSPENDED themselves is entitled to a child that has
  # executed nothing -- Cygwin's own fork() copies the parent's address
  # space into exactly such a child, and a debugger or another injector
  # expects the same. When they asked, we hand injectShimIntoChild a nil
  # thread handle, which pins it to the legacy technique and makes it
  # refuse fork-runtime children rather than wedge them. That is strictly
  # the behaviour this hook had before the park existed.
  let cfg = defaultInjectionConfig()
  let injectThread = if callerAskedSuspended: nil else: pi[].hThread
  for node in propagationNodes():
    if not node.enabled.load():
      continue
    if node.libraryPath.len == 0:
      continue
    discard injectShimIntoChild(pi[].hProcess, node.libraryPath,
      node.initSymbol, cfg, injectThread)

  # Still the single wakeup. injectShimIntoChild leaves the suspend count
  # exactly as it found it, park or no park, so this stays correct whether
  # zero, one or several nodes were injected.
  if not callerAskedSuspended:
    discard ResumeThread(pi[].hThread)
  SetLastError(savedLastError)

# ---------------------------------------------------------------------------
# Library self-registration helper
# ---------------------------------------------------------------------------

proc resolveSelfImagePath*(addressInside: pointer): string =
  ## Resolve the absolute path of the DLL/EXE containing
  ## ``addressInside``. Consumers call this from their init proc with
  ## a pointer to one of their own functions to populate the
  ## ``PropagationNode.libraryPath`` field.
  var h: HANDLE = nil
  if GetModuleHandleExW(
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS or
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
      cast[LPCWSTR](cast[uint](addressInside)),
      addr h) == 0 or h == nil:
    return ""
  var buf: array[1024, uint16]
  let n = GetModuleFileNameW(h, cast[LPWSTR](addr buf[0]), DWORD(buf.len))
  if n == 0:
    return ""
  result = newString(int(n))
  for i in 0 ..< int(n):
    result[i] = char(buf[i] and 0xFF)

{.pop.}
