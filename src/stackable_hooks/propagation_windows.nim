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

when not defined(windows):
  {.error: "stackable_hooks/propagation_windows is Windows-only".}

{.push raises: [].}

import std/[atomics, locks, strutils, widestrs]

import ./hook_registry
import ./propagation
import ./windows_fork_runtime
import ./windows_injector

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
  WAIT_TIMEOUT = 0x102'u32
  WAIT_FAILED = 0xFFFFFFFF'u32
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
  InjectionConfig* = object
    ## Tuning knobs for ``injectShimIntoChild``. See the module docstring
    ## for the rationale on each field.
    maxInFlight*: int
    waitDeadlineMs*: DWORD
    skipIfImageHasShim*: bool

  InjectionOutcome* = enum
    ioInjected, ioAlreadyPresent, ioSkippedCap,
    ioWaitTimeout, ioInjectFailed, ioInitFailed,
    ioNothingToInject

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
  InjectionConfig(maxInFlight: 16,
                  waitDeadlineMs: 5000,
                  skipIfImageHasShim: true)

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

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

proc injectShimIntoChild*(hProcess: HANDLE;
                          libraryPath: string;
                          initSymbol: string = "";
                          cfg: InjectionConfig = defaultInjectionConfig()):
    InjectionOutcome =
  ## Inject one library into the given child process. The caller is
  ## responsible for having spawned the child with ``CREATE_SUSPENDED``
  ## and for resuming its main thread once propagation completes.
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
  ##                          ``waitDeadlineMs``; child runs uninstrumented.
  ##   ``ioInjectFailed``   — VirtualAllocEx / WriteProcessMemory /
  ##                          CreateRemoteThread reported an error.
  ##   ``ioInitFailed``     — LoadLibraryW succeeded but the init
  ##                          remote thread couldn't be created.
  if libraryPath.len == 0:
    return ioNothingToInject

  # Never inject into our own probe/helper. Those are spawned from inside
  # this very path, so injecting them recurses: the helper exists to inject
  # a 64-bit child, and injecting the helper needs a helper. They are also
  # not part of the traced program -- their I/O is infrastructure, not a
  # dependency of the action being recorded.
  if spawningHelperProcess():
    return ioNothingToInject

  # A 32-bit child takes the 32-bit shim, so the already-present check has
  # to look for the shim that would actually be injected -- see
  # docs/windows-wow64-injection.md.
  var childIsWow64: BOOL = 0
  discard IsWow64Process(hProcess, addr childIsWow64)
  let effectiveLibrary =
    if childIsWow64 != 0: wow64ShimPathFor(libraryPath) else: libraryPath

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
  defer: discard VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE)

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

  let hThread = CreateRemoteThread(hProcess, nil, 0, loadLibraryW,
    remoteBuf, 0, nil)
  if hThread == nil:
    return ioInjectFailed
  let wait = WaitForSingleObject(hThread, cfg.waitDeadlineMs)
  discard CloseHandle(hThread)
  if wait == WAIT_TIMEOUT or wait == WAIT_FAILED:
    return ioWaitTimeout

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
  let initThread = CreateRemoteThread(hProcess, nil, 0, childInit,
    nil, 0, nil)
  if initThread == nil:
    return ioInitFailed
  let initWait = WaitForSingleObject(initThread, cfg.waitDeadlineMs)
  discard CloseHandle(initThread)
  if initWait == WAIT_TIMEOUT or initWait == WAIT_FAILED:
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

  # A native launcher such as make.exe can spawn MSYS2/Cygwin workers.
  # Injecting a remote thread before their fork runtime initializes wedges the
  # child. Leave that subtree uninstrumented; consumers conservatively mark the
  # unmatched process subtree incomplete.
  if windowsForkRuntimeForProcess(pi[].hProcess).len == 0:
    let cfg = defaultInjectionConfig()
    for node in propagationNodes():
      if not node.enabled.load():
        continue
      if node.libraryPath.len == 0:
        continue
      discard injectShimIntoChild(pi[].hProcess, node.libraryPath,
        node.initSymbol, cfg)

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
