when not defined(windows):
  {.error: "stackable_hooks/windows_injector is Windows-only".}

# Windows: CreateRemoteThread + LoadLibraryW injector used on Windows.
# macOS uses DYLD_INSERT_LIBRARIES which Windows lacks; the Windows
# substitute is the documented "spawn the target suspended, allocate a buffer
# in the remote address space, write the DLL path into it, then call
# LoadLibraryW via CreateRemoteThread" pattern. After LoadLibraryW returns,
# we optionally invoke an init entry point in the loaded DLL (also via
# CreateRemoteThread), then resume the original main thread.

import std/[locks, os, strtabs, strutils, tables]

import ./windows_env_block
import ./windows_fork_runtime

export windows_env_block
export windows_fork_runtime

proc toWideCStringSeq(s: string): seq[uint16] =
  result = newSeq[uint16](s.len + 1)
  for i, c in s:
    result[i] = uint16(ord(c))
  result[s.len] = 0

proc extendedPath(path: string): string =
  if path.len == 0 or path.startsWith("\\\\"):
    path
  else:
    var canonical = absolutePath(path).replace('/', '\\')
    while "\\\\" in canonical:
      canonical = canonical.replace("\\\\", "\\")
    "\\\\?\\" & canonical

proc quoteWindowsArg(s: string): string =
  if s.len > 0 and s.allCharsInSet(IdentChars + {'/', '-', ':', '.', '_', '\\'}):
    return s
  result = "\""
  var backslashes = 0
  for ch in s:
    if ch == '\\':
      inc(backslashes)
    elif ch == '"':
      # Backslashes before a quote are doubled; one more escapes the quote.
      for _ in 0 ..< (backslashes * 2 + 1):
        result.add('\\')
      backslashes = 0
      result.add('"')
    else:
      for _ in 0 ..< backslashes:
        result.add('\\')
      backslashes = 0
      result.add(ch)
  # Backslashes before the closing quote must be doubled so they are not
  # interpreted as escaping that quote by CommandLineToArgvW-compatible CRTs.
  for _ in 0 ..< (backslashes * 2):
    result.add('\\')
  result.add('"')

proc buildCommandLine(argv: openArray[string]): string =
  var parts: seq[string] = @[]
  for i, a in argv:
    parts.add(quoteWindowsArg(a))
  result = parts.join(" ")

{.push raises: [OSError].}

type
  HANDLE = pointer
  DWORD = uint32
  WORD = uint16
  BOOL = int32
  SIZE_T = uint
  LPVOID = pointer
  LPCVOID = pointer
  LPCWSTR = ptr uint16
  LPWSTR = ptr uint16
  LPSECURITY_ATTRIBUTES = pointer

  STARTUPINFOW {.bycopy.} = object
    cb: DWORD
    lpReserved: LPWSTR
    lpDesktop: LPWSTR
    lpTitle: LPWSTR
    dwX: DWORD
    dwY: DWORD
    dwXSize: DWORD
    dwYSize: DWORD
    dwXCountChars: DWORD
    dwYCountChars: DWORD
    dwFillAttribute: DWORD
    dwFlags: DWORD
    wShowWindow: WORD
    cbReserved2: WORD
    lpReserved2: ptr byte
    hStdInput: HANDLE
    hStdOutput: HANDLE
    hStdError: HANDLE

  PROCESS_INFORMATION {.bycopy.} = object
    hProcess: HANDLE
    hThread: HANDLE
    dwProcessId: DWORD
    dwThreadId: DWORD

const
  CREATE_SUSPENDED = 0x00000004'u32
  # CREATE_UNICODE_ENVIRONMENT lives in `stackable_hooks/windows_env_block`
  # (imported and re-exported above), next to the encoder that makes it
  # mandatory and to `lpEnvironmentArgs`, which decides it.
  STARTF_USESTDHANDLES = 0x00000100'u32
  MEM_COMMIT = 0x00001000'u32
  MEM_RESERVE = 0x00002000'u32
  MEM_RELEASE = 0x00008000'u32
  PAGE_READWRITE = 0x04'u32
  INFINITE = 0xFFFFFFFF'u32
  WAIT_OBJECT_0 = 0'u32
  HANDLE_FLAG_INHERIT = 0x00000001'u32
  STD_INPUT_HANDLE = 0xFFFFFFF6'u32
  STD_OUTPUT_HANDLE = 0xFFFFFFF5'u32
  STD_ERROR_HANDLE = 0xFFFFFFF4'u32

proc LoadLibraryWRaw(lpLibFileName: LPCWSTR): HANDLE
  {.importc: "LoadLibraryW", stdcall, dynlib: "kernel32".}
proc FreeLibraryRaw(hLibModule: HANDLE): BOOL
  {.importc: "FreeLibrary", stdcall, dynlib: "kernel32".}

proc EnumProcessModulesEx(hProcess: HANDLE, lphModule: ptr pointer,
                          cb: DWORD, lpcbNeeded: ptr DWORD,
                          dwFilterFlag: DWORD): BOOL
  {.importc, stdcall, dynlib: "psapi".}
proc GetModuleBaseNameW(hProcess: HANDLE, hModule: HANDLE,
                       lpBaseName: LPWSTR, nSize: DWORD): DWORD
  {.importc, stdcall, dynlib: "psapi".}

proc CreateProcessW(lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
                    lpProcessAttributes: LPSECURITY_ATTRIBUTES,
                    lpThreadAttributes: LPSECURITY_ATTRIBUTES,
                    bInheritHandles: BOOL, dwCreationFlags: DWORD,
                    lpEnvironment: LPVOID, lpCurrentDirectory: LPCWSTR,
                    lpStartupInfo: pointer,
                    lpProcessInformation: ptr PROCESS_INFORMATION): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc InitializeProcThreadAttributeList(lpAttributeList: pointer;
                                        dwAttributeCount: DWORD;
                                        dwFlags: DWORD;
                                        lpSize: ptr SIZE_T): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc UpdateProcThreadAttribute(lpAttributeList: pointer;
                                dwFlags: DWORD;
                                Attribute: DWORD;
                                lpValue: pointer;
                                cbSize: SIZE_T;
                                lpPreviousValue: pointer;
                                lpReturnSize: ptr SIZE_T): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc DeleteProcThreadAttributeList(lpAttributeList: pointer)
  {.importc, stdcall, dynlib: "kernel32".}

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

proc GetModuleHandleW(lpModuleName: LPCWSTR): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc GetProcAddress(hModule: HANDLE, lpProcName: cstring): pointer
  {.importc, stdcall, dynlib: "kernel32".}

proc WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc GetExitCodeThread(hThread: HANDLE, lpExitCode: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc ResumeThread(hThread: HANDLE): DWORD
  {.importc, stdcall, dynlib: "kernel32".}

proc GetLastError(): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc GetProcessId(hProcess: HANDLE): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc GetCurrentProcess(): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc CloseHandle(hObject: HANDLE): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetExitCodeProcess(hProcess: HANDLE, lpExitCode: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc TerminateProcess(hProcess: HANDLE, uExitCode: DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}

proc GetStdHandle(nStdHandle: DWORD): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc SetHandleInformation(hObject: HANDLE, dwMask: DWORD, dwFlags: DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetProcessHeap(): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc HeapAlloc(hHeap: HANDLE, dwFlags: DWORD, dwBytes: SIZE_T): pointer
  {.importc, stdcall, dynlib: "kernel32".}
proc HeapFree(hHeap: HANDLE, dwFlags: DWORD, lpMem: pointer): BOOL
  {.importc, stdcall, dynlib: "kernel32".}

proc CreatePipe(hReadPipe: ptr HANDLE, hWritePipe: ptr HANDLE,
                lpPipeAttributes: LPSECURITY_ATTRIBUTES, nSize: DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc ReadFile(hFile: HANDLE, lpBuffer: pointer, nNumberOfBytesToRead: DWORD,
              lpNumberOfBytesRead: ptr DWORD, lpOverlapped: pointer): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc PeekNamedPipe(hNamedPipe: HANDLE, lpBuffer: pointer, nBufferSize: DWORD,
                   lpBytesRead: ptr DWORD, lpTotalBytesAvail: ptr DWORD,
                   lpBytesLeftThisMessage: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}

type
  SECURITY_ATTRIBUTES {.bycopy.} = object
    nLength: DWORD
    lpSecurityDescriptor: pointer
    bInheritHandle: BOOL

  STARTUPINFOEXW {.bycopy.} = object
    StartupInfo: STARTUPINFOW
    lpAttributeList: pointer

const
  EXTENDED_STARTUPINFO_PRESENT = 0x00080000'u32
  PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002'u32

type
  WindowsInjectionResult* = object
    exitCode*: int
    monitoringSkipped*: bool
    skipReason*: string
    rootPid*: uint64
      ## OS pid of the process that was launched and injected. Consumers
      ## need it to check that the root child actually reported: a child
      ## that emits nothing is indistinguishable from one that was never
      ## hooked, and the only party who knows which pid SHOULD have
      ## appeared is the launcher. 0 when no process was started.

# ---------------------------------------------------------------------------
# WOW64 (32-bit child) support
#
# `runWithMonitorShim` resolves `LoadLibraryW` in its OWN kernel32 and passes
# that address to `CreateRemoteThread`. That holds only while injector and
# child share a bitness: a 64-bit process and a WOW64 process load different
# copies of kernel32 (System32 vs SysWOW64) at unrelated bases. A 64-bit
# injector also cannot resolve the 32-bit address itself — LoadLibraryW of
# SysWOW64\kernel32.dll fails on a machine-type mismatch.
#
# So the address is obtained from a 32-bit process instead: a tiny probe
# executable (src/stackable_hooks/tools/wow64_proc_probe.nim) resolves the
# proc in its own kernel32 and returns the pointer as its EXIT CODE — a
# DWORD is exactly wide enough, needs no framing, and cannot be truncated.
# The result is cached: kernel32's base is stable across WOW64 processes for
# the life of a boot session, so one spawn per session is enough.
#
# NAMING CONVENTION (relied upon rather than configured, so callers that
# already know the 64-bit shim path need to pass nothing extra):
#
#   <name>.dll                    the 64-bit shim
#   <name>32.dll                  the 32-bit shim, same directory
#   stackable_hooks_wow64_probe32.exe   the probe, same directory
#
# A caller that wants different locations can override both with
# `setWow64ShimPath` / `setWow64ProbePath` before the first injection.
# ---------------------------------------------------------------------------

proc IsWow64Process(hProcess: HANDLE, Wow64Process: ptr BOOL): BOOL
  {.importc, stdcall, dynlib: "kernel32".}

const
  Wow64ProbeExeName* = "stackable_hooks_wow64_probe32.exe"
    ## Convention: the 32-bit probe sits beside the shim it serves.

  Inject64HelperExeName* = "stackable_hooks_inject64.exe"
    ## Convention: the 64-bit injection helper sits beside the shim too.
    ##
    ## Needed for the mirror image of the WOW64 case. A 32-bit process can
    ## neither resolve the 64-bit kernel32 nor drive VirtualAllocEx /
    ## CreateRemoteThread against a 64-bit address space -- its calls go
    ## through the WOW64 thunk layer, which does not reach there. Where the
    ## probe answers a question for the other bitness, this helper performs
    ## the whole operation, because the operation itself cannot cross.

# The propagation path (`propagation_windows.injectShimIntoChild`) calls into
# this state from worker threads, so every access is taken under a lock and
# the accessors are `gcsafe`. The `cast(gcsafe)` is what the lock earns: the
# globals are GC'd (a string and a Table), and the compiler cannot see that
# the lock serialises them.

var
  wow64StateLock: Lock
  wow64ShimPathOverride = ""
  wow64ProbePathOverride = ""
  wow64ProcAddressCache: Table[string, uint32]
    ## Successful lookups only, keyed by "<probe><proc>".
    ##
    ## Successes are cached because the address is stable for the life of a
    ## boot session, so re-spawning the probe per injection would be waste.
    ## FAILURES are deliberately NOT cached: a probe that is missing now may
    ## be built later in the same session, and a caller asking about a
    ## different probe path must not be answered from an unrelated miss.

proc setWow64ShimPath*(path: string) {.gcsafe.} =
  ## Override the conventional `<name>32.dll` sibling lookup.
  {.cast(gcsafe).}:
    withLock wow64StateLock:
      wow64ShimPathOverride = path

proc setWow64ProbePath*(path: string) {.gcsafe.} =
  ## Override the conventional `stackable_hooks_wow64_probe32.exe` sibling.
  {.cast(gcsafe).}:
    withLock wow64StateLock:
      wow64ProbePathOverride = path

proc wow64ShimPathFor*(dllPath64: string): string {.raises: [], gcsafe.} =
  ## The 32-bit shim that pairs with `dllPath64`, by convention.
  {.cast(gcsafe).}:
    withLock wow64StateLock:
      if wow64ShimPathOverride.len > 0:
        return wow64ShimPathOverride
  let (dir, name, ext) = splitFile(dllPath64)
  dir / (name & "32" & ext)

proc wow64ProbePathFor*(dllPath64: string): string {.raises: [], gcsafe.} =
  ## The probe executable that pairs with `dllPath64`, by convention.
  {.cast(gcsafe).}:
    withLock wow64StateLock:
      if wow64ProbePathOverride.len > 0:
        return wow64ProbePathOverride
  dllPath64.parentDir / Wow64ProbeExeName

proc inject64HelperPathFor*(shimPath: string): string {.raises: [], gcsafe.} =
  ## The 64-bit injection helper paired with `shimPath`, by convention.
  ##
  ## `shimPath` may be either bitness -- a 32-bit shim's directory holds the
  ## helper just as a 64-bit one's does, since both shims are staged side by
  ## side by the build.
  shimPath.parentDir / Inject64HelperExeName

proc shim64PathFor*(shimPath32: string): string {.raises: [], gcsafe.} =
  ## The 64-bit shim paired with a 32-bit one: the inverse of
  ## `wow64ShimPathFor`, stripping the conventional `32` suffix.
  let (dir, name, ext) = splitFile(shimPath32)
  if name.endsWith("32"):
    dir / (name[0 ..< name.len - 2] & ext)
  else:
    shimPath32

proc processIsWow64*(hProcess: HANDLE): bool {.raises: [], gcsafe.} =
  ## True when `hProcess` is a 32-bit process on 64-bit Windows. On a 32-bit
  ## host every process reports false and the ordinary same-bitness path is
  ## already correct, so a false answer is always safe.
  # The winapi wrappers are declared under this module's
  # `{.push raises: [OSError].}`, so the call is wrapped to keep this proc
  # callable from the `{.raises: [].}` propagation path. A failed query is
  # reported as "not WOW64", which routes to the ordinary same-bitness path
  # -- correct on 32-bit hosts and the safe answer everywhere else.
  try:
    var isWow: BOOL = 0
    if IsWow64Process(hProcess, addr isWow) == 0:
      return false
    isWow != 0
  except OSError:
    false

var inHelperSpawn {.threadvar.}: int
  ## Depth of "this thread is currently spawning one of our own tool
  ## processes" (the WOW64 probe or the 64-bit injection helper).
  ##
  ## Those spawns go through `CreateProcessW`, which in a shimmed process is
  ## detoured -- so without this the spawn hook tries to inject the shim into
  ## the helper, and injecting into a 64-bit child is what called the helper
  ## in the first place. Measured: 129 helper processes before the guard.
  ##
  ## Thread-local and depth-counted because the spawn happens on the very
  ## thread that is inside the hook, and because a nested spawn (probe from
  ## inside a helper path) must not clear the flag early.
  ##
  ## Injecting the monitor into its own injection helper would be wrong even
  ## if it terminated: the helper is infrastructure, not part of the traced
  ## program, and its file I/O is not a dependency of the build action.

proc spawningHelperProcess*(): bool {.raises: [], gcsafe.} =
  ## True while this thread is spawning a probe/helper of our own.
  inHelperSpawn > 0

proc runProbeForExitCode(probeExe: string;
                         probeArgs: openArray[string]): uint32
                        {.raises: [], gcsafe.} =
  ## Spawn the 32-bit probe and return its exit code verbatim.
  inc inHelperSpawn
  defer: dec inHelperSpawn
  try:
    var si: STARTUPINFOW
    si.cb = DWORD(sizeof(STARTUPINFOW))
    var pi: PROCESS_INFORMATION
    var commandLine = buildCommandLine(@[probeExe] & @probeArgs)
    var commandLineW = toWideCStringSeq(commandLine)
    if CreateProcessW(nil, cast[LPWSTR](addr commandLineW[0]), nil, nil, 0,
        0, nil, nil, cast[ptr STARTUPINFOW](addr si), addr pi) == 0:
      return 0
    discard WaitForSingleObject(pi.hProcess, INFINITE)
    var exitCode: DWORD = 0
    discard GetExitCodeProcess(pi.hProcess, addr exitCode)
    discard CloseHandle(pi.hThread)
    discard CloseHandle(pi.hProcess)
    uint32(exitCode)
  except OSError, Exception:
    0'u32

proc wow64LoadLibraryWAddress*(probeExe: string): uint32 {.raises: [], gcsafe.} =
  ## Address of `LoadLibraryW` in a WOW64 process's kernel32, obtained once
  ## per session from the probe. Returns 0 when unavailable — the caller
  ## must treat that as "cannot inject into 32-bit children" and say so,
  ## rather than falling back to the 64-bit address, which would start a
  ## remote thread at a meaningless location.
  let cacheKey = probeExe & "" & "LoadLibraryW"
  # `getOrDefault` rather than `[]`: the module is under
  # `{.push raises: [OSError].}` and `[]` can raise KeyError. 0 is already
  # the "no answer" value, so the default coincides with the miss case.
  {.cast(gcsafe).}:
    withLock wow64StateLock:
      let cached = wow64ProcAddressCache.getOrDefault(cacheKey, 0'u32)
      if cached != 0'u32:
        return cached
  let probeExists =
    try: fileExists(extendedPath(probeExe))
    except CatchableError: false
  if not probeExists:
    return 0
  let resolved = runProbeForExitCode(probeExe, ["LoadLibraryW"])
  if resolved != 0:
    {.cast(gcsafe).}:
      withLock wow64StateLock:
        wow64ProcAddressCache[cacheKey] = resolved
  resolved

proc hostIsWow64Capable*(): bool {.raises: [], gcsafe.} =
  ## True when this 32-bit process is running under WOW64 -- i.e. the host is
  ## 64-bit, so a 64-bit child (and a 64-bit helper) is possible at all.
  ##
  ## On genuine 32-bit Windows every process is 32-bit, there is no other
  ## bitness to bridge to, and the ordinary in-process path is correct.
  try:
    processIsWow64(GetCurrentProcess())
  except OSError:
    false

proc runInject64Helper*(hProcess: HANDLE; shimPath64, initSymbol: string):
    bool {.raises: [], gcsafe.} =
  ## Inject `shimPath64` into a 64-bit `hProcess` by delegating to the 64-bit
  ## helper. Used only from a 32-bit shim, which cannot do this itself.
  ##
  ## The helper is addressed by pid rather than by handle: a handle is
  ## process-local, and duplicating one into a freshly spawned helper would
  ## need the helper's own handle first. The target is suspended by the
  ## caller for the duration, so the pid cannot be recycled underneath us.
  let helper = inject64HelperPathFor(shimPath64)
  let helperExists =
    try: fileExists(extendedPath(helper))
    except CatchableError: false
  if not helperExists:
    return false

  let shimExists =
    try: fileExists(extendedPath(shimPath64))
    except CatchableError: false
  if not shimExists:
    return false

  let pid =
    try: GetProcessId(hProcess)
    except OSError: 0'u32
  if pid == 0:
    return false

  let rc = runProbeForExitCode(helper, [$pid, shimPath64, initSymbol])
  # The helper reports 0 for success; every other value is a specific stage
  # failure documented in tools/inject_helper.nim.
  rc == 0

proc wow64ExportRva*(probeExe, dllPath32, procName: string): uint32
                    {.raises: [], gcsafe.} =
  ## Offset of `procName` from the base of the 32-bit `dllPath32`, obtained
  ## from the probe. Returns 0 when unavailable.
  ##
  ## The injector needs this to call the shim's initialiser in the child
  ## after LoadLibraryW has run there. For a same-bitness shim it computes
  ## the offset by loading the DLL in this process and subtracting the base;
  ## for a 32-bit shim it cannot, because a 64-bit process cannot load a
  ## 32-bit image at all. That failure used to be silent in the worst way:
  ## the shim WAS loaded in the child, so nothing errored, but its init was
  ## never called, so no hooks were installed and the process reported not a
  ## single record.
  ##
  ## Cached on success only, like the kernel32 address: a probe that is
  ## missing now may be built later in the same session, and the offset for
  ## one DLL must never be answered from another's entry.
  let cacheKey = probeExe & "\x1f" & dllPath32 & "\x1f" & procName
  {.cast(gcsafe).}:
    withLock wow64StateLock:
      let cached = wow64ProcAddressCache.getOrDefault(cacheKey, 0'u32)
      if cached != 0'u32:
        return cached
  let probeExists =
    try: fileExists(extendedPath(probeExe))
    except CatchableError: false
  if not probeExists:
    return 0
  let resolved = runProbeForExitCode(probeExe, [dllPath32, procName])
  if resolved != 0:
    {.cast(gcsafe).}:
      withLock wow64StateLock:
        wow64ProcAddressCache[cacheKey] = resolved
  resolved

proc runWithMonitorShim*(argv: openArray[string], dllPath: string,
    cwd = ""; captureStdio = false;
    captureStdioPath = ""; env: StringTableRef = nil): WindowsInjectionResult =
  ## Windows: Spawn `argv` in a CREATE_SUSPENDED state, inject the monitor
  ## shim DLL via CreateRemoteThread+LoadLibraryW, optionally invoke the
  ## shim's `repro_runtime_init` entry point, then resume the main thread.
  ## Returns when the child process exits.
  ##
  ## When ``captureStdio`` is true, the child's stdout+stderr (merged) are
  ## captured into a pipe owned by this proc and drained while waiting
  ## for the child to exit. This mirrors the reprobuild engine's
  ## ``osproc.startProcess`` default behaviour (pipe-captured stdio +
  ## pollCompletion drain) so integration tests at the fs-snoop level can
  ## reproduce wedges that only manifest under the build engine.
  ##
  ## ``env`` is the child's **complete** environment, and `nil` is NOT the
  ## same as an empty table:
  ##
  ## * `nil` (the default) means "inherit this process's environment". It is
  ##   compiled into `lpEnvironment = NULL`, which is byte-identical to what
  ##   this proc did before it took an `env` parameter — existing callers
  ##   see no change whatsoever.
  ## * an EMPTY but non-nil table means "give the child an EMPTY
  ##   environment". A different, deliberate outcome; it is never silently
  ##   treated as inheritance.
  ## * a populated table hands the child variables without `putEnv`-ing them
  ##   into the host, which is the only way to run several injected children
  ##   concurrently in one host process without them clobbering each other's
  ##   monitoring variables.
  ##
  ## That contract, and the creation flag that has to travel with the block,
  ## are decided by `windows_env_block.lpEnvironmentArgs`; encoding rules and
  ## their failure modes are in `stackable_hooks/windows_env_block`. Both live
  ## outside this Windows-gated module so they are unit-tested on the
  ## development host rather than merely compiled.
  if argv.len == 0:
    raise newException(OSError, "runWithMonitorShim: empty argv")
  let dllExists =
    try: fileExists(extendedPath(dllPath))
    except ValueError: false
  if not dllExists:
    raise newException(OSError, "shim DLL not found: " & dllPath)

  # NOTE (interaction with `env`): when `argv[0]` carries no directory
  # component, `windowsForkRuntimeForExecutable` falls back to `findExe`, which
  # searches THIS process's `PATH` — never `env`'s. A caller that hands the
  # child a `PATH` different from the host's can therefore have the MSYS/Cygwin
  # check look at a different image than the one that ends up running. Pass an
  # absolute `argv[0]` (or a `cwd`-relative one) when the two PATHs disagree.
  let forkRuntime =
    try: windowsForkRuntimeForExecutable(argv[0], cwd)
    except ValueError: ""
  let skipInjection = forkRuntime.len > 0
  if skipInjection:
    result.monitoringSkipped = true
    result.skipReason = "target uses " & forkRuntime &
      ", whose fork emulation is incompatible with pre-main remote threads"

  let commandLine = buildCommandLine(argv)
  var cmdLineW = toWideCStringSeq(commandLine)
  var cwdW: seq[uint16] = @[]
  if cwd.len > 0:
    cwdW = toWideCStringSeq(cwd)

  # A non-nil `env` becomes an explicit UTF-16 lpEnvironment block; a nil one
  # leaves `lpEnvironment` NULL so the child inherits our block, exactly as
  # before this parameter existed. The creation-flag bit and the pointer are
  # one decision, not two — a block passed without CREATE_UNICODE_ENVIRONMENT
  # is re-read as ANSI and the child comes up with a garbage environment — so
  # `lpEnvironmentArgs` returns both together, keyed on `env == nil` rather
  # than on the size of the encoded block. See its docstring: keying on the
  # block would let an "empty child environment" degrade into "inherit the
  # parent's" if the encoder ever stopped emitting a terminator-only block.
  var envArgs: tuple[extraFlags: uint32; blk: seq[uint16]]
  try:
    envArgs = lpEnvironmentArgs(env)
  except ValueError as e:
    raise newException(OSError,
      "runWithMonitorShim: invalid child environment: " & e.msg)
  var envBlockW = envArgs.blk
  let creationFlags =
    CREATE_SUSPENDED or EXTENDED_STARTUPINFO_PRESENT or envArgs.extraFlags

  # Pipe for captured stdio mode (anonymous pipe; merged stdout+stderr).
  var stdoutReadPipe: HANDLE = nil
  var stdoutWritePipe: HANDLE = nil
  if captureStdio:
    var sa: SECURITY_ATTRIBUTES
    sa.nLength = DWORD(sizeof(sa))
    sa.bInheritHandle = BOOL(1)
    sa.lpSecurityDescriptor = nil
    if CreatePipe(addr stdoutReadPipe, addr stdoutWritePipe,
                  cast[LPSECURITY_ATTRIBUTES](addr sa), 0'u32) == 0:
      raise newException(OSError,
        "CreatePipe failed (err=" & $GetLastError() & ")")
    # The READ end stays with us; mark it non-inheritable so the child
    # doesn't accidentally inherit a copy of the read handle.
    discard SetHandleInformation(stdoutReadPipe, HANDLE_FLAG_INHERIT, 0'u32)

  # Use STARTUPINFOEX with a PROC_THREAD_ATTRIBUTE_HANDLE_LIST so we
  # ONLY pass stdin/stdout/stderr to the child instead of every
  # inheritable handle in our process. When fs-snoop is spawned from
  # the reprobuild engine, the engine's process holds many other
  # inheritable handles (named pipes for daemon/runquota, cache
  # files, etc.) that would otherwise pollute the child's handle
  # table — bash's Git-Bash fork emulation, in particular, has been
  # observed to wedge on those inherited handles (no node spawn from
  # the action's webpack invocation). Explicit whitelisting is the
  # canonical Windows fix.
  var siex: STARTUPINFOEXW
  siex.StartupInfo.cb = DWORD(sizeof(siex))
  siex.StartupInfo.dwFlags = STARTF_USESTDHANDLES
  if captureStdio:
    siex.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE)
    siex.StartupInfo.hStdOutput = stdoutWritePipe
    siex.StartupInfo.hStdError = stdoutWritePipe
  else:
    siex.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE)
    siex.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE)
    siex.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE)
  discard SetHandleInformation(siex.StartupInfo.hStdInput,
                                HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
  if not captureStdio:
    discard SetHandleInformation(siex.StartupInfo.hStdOutput,
                                  HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
    discard SetHandleInformation(siex.StartupInfo.hStdError,
                                  HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
  # Build the attribute list with exactly stdin/stdout/stderr.
  var attrListSize: SIZE_T = 0
  discard InitializeProcThreadAttributeList(nil, 1'u32, 0'u32,
                                             addr attrListSize)
  let processHeap = GetProcessHeap()
  let attrList = HeapAlloc(processHeap, 0'u32, attrListSize)
  if attrList == nil:
    if stdoutWritePipe != nil:
      discard CloseHandle(stdoutWritePipe); stdoutWritePipe = nil
    if stdoutReadPipe != nil:
      discard CloseHandle(stdoutReadPipe); stdoutReadPipe = nil
    raise newException(OSError, "HeapAlloc for attr list failed")
  if InitializeProcThreadAttributeList(attrList, 1'u32, 0'u32,
                                        addr attrListSize) == 0:
    discard HeapFree(processHeap, 0'u32, attrList)
    if stdoutWritePipe != nil:
      discard CloseHandle(stdoutWritePipe); stdoutWritePipe = nil
    if stdoutReadPipe != nil:
      discard CloseHandle(stdoutReadPipe); stdoutReadPipe = nil
    raise newException(OSError,
      "InitializeProcThreadAttributeList failed (err=" &
        $GetLastError() & ")")
  siex.lpAttributeList = attrList
  # The HANDLE_LIST attribute value is an array of HANDLEs. Skip any
  # nil/INVALID handles — passing one to UpdateProcThreadAttribute
  # produces ERROR_INVALID_PARAMETER (err=87) from the subsequent
  # CreateProcessW. GetStdHandle returns nil for missing standard
  # streams (common when launched from a service-style context).
  var handleVec: seq[HANDLE] = @[]
  for h in [siex.StartupInfo.hStdInput,
             siex.StartupInfo.hStdOutput,
             siex.StartupInfo.hStdError]:
    if h != nil and cast[int](h) != -1 and h notin handleVec:
      handleVec.add(h)
  if handleVec.len == 0:
    DeleteProcThreadAttributeList(attrList)
    discard HeapFree(processHeap, 0'u32, attrList)
    if stdoutWritePipe != nil:
      discard CloseHandle(stdoutWritePipe); stdoutWritePipe = nil
    if stdoutReadPipe != nil:
      discard CloseHandle(stdoutReadPipe); stdoutReadPipe = nil
    raise newException(OSError,
      "no valid stdio handle to pass to child")
  if UpdateProcThreadAttribute(attrList, 0'u32,
                                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                unsafeAddr handleVec[0],
                                SIZE_T(handleVec.len * sizeof(HANDLE)),
                                nil, nil) == 0:
    DeleteProcThreadAttributeList(attrList)
    discard HeapFree(processHeap, 0'u32, attrList)
    if stdoutWritePipe != nil:
      discard CloseHandle(stdoutWritePipe); stdoutWritePipe = nil
    if stdoutReadPipe != nil:
      discard CloseHandle(stdoutReadPipe); stdoutReadPipe = nil
    raise newException(OSError,
      "UpdateProcThreadAttribute failed (err=" & $GetLastError() & ")")

  var pi: PROCESS_INFORMATION

  let ok = CreateProcessW(nil,
    cast[LPWSTR](addr cmdLineW[0]),
    nil, nil, BOOL(1),
    creationFlags,
    # Keyed on the caller's intent, not on the encoded size, so it cannot
    # disagree with the CREATE_UNICODE_ENVIRONMENT bit above.
    # `lpEnvironmentArgs` guarantees `blk` is non-empty whenever `env != nil`,
    # so `addr envBlockW[0]` is in bounds on this arm.
    (if env != nil: cast[LPVOID](addr envBlockW[0]) else: nil),
    if cwdW.len > 0: cast[LPCWSTR](addr cwdW[0]) else: nil,
    cast[pointer](addr siex), addr pi)
  if ok == 0:
    DeleteProcThreadAttributeList(attrList)
    discard HeapFree(processHeap, 0'u32, attrList)
    if stdoutWritePipe != nil:
      discard CloseHandle(stdoutWritePipe); stdoutWritePipe = nil
    if stdoutReadPipe != nil:
      discard CloseHandle(stdoutReadPipe); stdoutReadPipe = nil
    raise newException(OSError,
      "CreateProcessW failed (err=" & $GetLastError() & "): " & commandLine)
  result.rootPid = uint64(pi.dwProcessId)

  template safeClose(h: HANDLE) =
    if h != nil:
      discard CloseHandle(h)

  try:
    # 0. Pick the shim matching the CHILD's bitness. A 32-bit child cannot
    #    load the 64-bit shim (LoadLibraryW returns NULL on a machine-type
    #    mismatch), and its kernel32 is at a different base, so both the
    #    DLL and the LoadLibraryW address have to be switched together.
    let childIsWow64 = processIsWow64(pi.hProcess)
    let effectiveDllPath =
      if childIsWow64: wow64ShimPathFor(dllPath) else: dllPath
    if childIsWow64:
      let shim32Exists =
        try: fileExists(extendedPath(effectiveDllPath))
        except ValueError: false
      if not shim32Exists:
        raise newException(OSError,
          "child is a 32-bit (WOW64) process but the 32-bit shim is missing: " &
          effectiveDllPath & " — build it with `nim c --cpu:i386` and place " &
          "it beside the 64-bit shim, or call setWow64ShimPath")

    # 1. Allocate a buffer in the child for the wide DLL path.
    var dllPathW = toWideCStringSeq(effectiveDllPath)
    let bufSize = SIZE_T(dllPathW.len * sizeof(uint16))
    let remoteBuf = VirtualAllocEx(pi.hProcess, nil, bufSize,
      MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if remoteBuf == nil:
      raise newException(OSError,
        "VirtualAllocEx failed (err=" & $GetLastError() & ")")

    # 2. Write the DLL path into the buffer.
    var written: SIZE_T = 0
    if WriteProcessMemory(pi.hProcess, remoteBuf, addr dllPathW[0],
        bufSize, addr written) == 0:
      discard VirtualFreeEx(pi.hProcess, remoteBuf, 0, MEM_RELEASE)
      raise newException(OSError,
        "WriteProcessMemory failed (err=" & $GetLastError() & ")")

    # 3. Resolve LoadLibraryW as the CHILD sees it.
    #
    #    Same bitness: our own kernel32 is loaded at the same base in the
    #    child, so GetProcAddress here is the child's address too.
    #
    #    WOW64 child: it is NOT. The child uses SysWOW64\kernel32.dll at an
    #    unrelated base, and this process cannot resolve that address
    #    itself. The 32-bit probe reports it via its exit code; see the
    #    WOW64 section above.
    var loadLibraryW: pointer = nil
    if childIsWow64:
      let probeExe = wow64ProbePathFor(dllPath)
      let addr32 = wow64LoadLibraryWAddress(probeExe)
      if addr32 == 0:
        discard VirtualFreeEx(pi.hProcess, remoteBuf, 0, MEM_RELEASE)
        raise newException(OSError,
          "cannot resolve LoadLibraryW for the 32-bit child: the WOW64 probe " &
          "at " & probeExe & " is missing or reported no address. Build it " &
          "with `nim c --cpu:i386 src/stackable_hooks/tools/" &
          "wow64_proc_probe.nim`, or call setWow64ProbePath. Refusing to " &
          "use this process's 64-bit LoadLibraryW address, which would " &
          "start a remote thread at a meaningless location in the child.")
      loadLibraryW = cast[pointer](uint(addr32))
    else:
      var kernel32Name = toWideCStringSeq("kernel32.dll")
      let kernel32 = GetModuleHandleW(cast[LPCWSTR](addr kernel32Name[0]))
      if kernel32 == nil:
        discard VirtualFreeEx(pi.hProcess, remoteBuf, 0, MEM_RELEASE)
        raise newException(OSError,
          "GetModuleHandleW(kernel32) returned NULL")
      loadLibraryW = GetProcAddress(kernel32, "LoadLibraryW")
      if loadLibraryW == nil:
        discard VirtualFreeEx(pi.hProcess, remoteBuf, 0, MEM_RELEASE)
        raise newException(OSError,
          "GetProcAddress(LoadLibraryW) returned NULL")

    # 4. MSYS2/Cygwin fork emulation cannot tolerate a remote thread before
    # the runtime initializes. Resume those targets without injection and let
    # the caller mark the observation incomplete and noncacheable.
    var llExit: DWORD = 1
    if not skipInjection:
      let llThread = CreateRemoteThread(pi.hProcess, nil, 0,
        loadLibraryW, remoteBuf, 0, nil)
      if llThread == nil:
        discard VirtualFreeEx(pi.hProcess, remoteBuf, 0, MEM_RELEASE)
        raise newException(OSError,
          "CreateRemoteThread(LoadLibraryW) failed (err=" & $GetLastError() & ")")

      discard WaitForSingleObject(llThread, INFINITE)
      llExit = 0
      discard GetExitCodeThread(llThread, addr llExit)
      discard CloseHandle(llThread)
    discard VirtualFreeEx(pi.hProcess, remoteBuf, 0, MEM_RELEASE)

    if llExit == 0:
      # Report enough to tell the three causes apart without a rebuild: a
      # missing transitive dependency of the shim, a machine-type mismatch
      # (the historical failure — a 64-bit shim against a 32-bit child), and
      # a shim whose DllMain failed. The bare "check that the DLL and its
      # dependencies are present" wording that used to stand here named none
      # of them and sent readers hunting.
      raise newException(OSError,
        "LoadLibraryW in child returned NULL (err=" & $GetLastError() & "): " &
        "the shim DLL did not load. shim=" & effectiveDllPath &
        " child=" & (if childIsWow64: "32-bit (WOW64)" else: "64-bit") &
        ". Causes, in order of likelihood: a transitive dependency of the " &
        "shim is not resolvable from the child's DLL search path (check " &
        "with `objdump -p <shim>`; the shim should link the compiler " &
        "runtime statically); the shim's machine type does not match the " &
        "child; or the shim's DllMain returned FALSE.")

    # 5. Resolve repro_runtime_init in the child's copy of the shim DLL.
    #    GetExitCodeThread truncates the 64-bit HMODULE returned by
    #    LoadLibraryW to 32 bits, so we cannot use the thread exit code as
    #    the child-side HMODULE. Instead we enumerate the child's module
    #    list, find the entry whose basename matches our shim DLL, and use
    #    its 64-bit base address. Because our DLL was just LoadLibraryW'd
    #    into the child, the basename of the path we sent into the child
    #    is what the loader will report.
    var foundShim: HANDLE = nil
    let wantBaseName = block:
      let (_, tail) = splitPath(effectiveDllPath)
      tail
    var childMods: array[1024, HANDLE]
    var modCb: DWORD = 0
    if not skipInjection and
        EnumProcessModulesEx(pi.hProcess, cast[ptr pointer](addr childMods[0]),
        DWORD(sizeof(childMods)), addr modCb, 0x3'u32) != 0:
      let modCount = int(modCb) div sizeof(HANDLE)
      for i in 0 ..< min(modCount, 1024):
        var nameBuf: array[1024, uint16]
        let nameLen = GetModuleBaseNameW(pi.hProcess, childMods[i],
          cast[LPWSTR](addr nameBuf[0]), DWORD(nameBuf.len))
        if nameLen == 0:
          continue
        # Convert UTF-16 basename to a plain ASCII string for comparison.
        var got = ""
        for j in 0 ..< int(nameLen):
          got.add(chr(int(nameBuf[j]) and 0xFF))
        if cmpIgnoreCase(got, wantBaseName) == 0:
          foundShim = childMods[i]
          break

    if foundShim != nil:
      # The init proc in the child sits at (child's module base + the RVA of
      # the export). Only the RVA has to be discovered, and how depends on
      # whether this process can load the image at all.
      #
      # Same bitness: load it here and subtract the base. GetProcAddress
      # returns an address within our own mapping, and both processes mapped
      # the same image, so the offset transfers.
      #
      # WOW64: a 64-bit process cannot LoadLibraryW a 32-bit DLL -- the load
      # fails on the machine-type check. That used to end the sequence here
      # with no error and no init: the shim was in the child, loaded and
      # inert, hooks never installed, not one record emitted, while
      # LoadLibraryW had plainly succeeded so nothing looked wrong. Ask the
      # 32-bit probe for the offset instead; an RVA is bitness-agnostic once
      # something that CAN read the image reports it.
      var rva: uint = 0
      var parentShim: HANDLE = nil
      if childIsWow64:
        let fromProbe = wow64ExportRva(wow64ProbePathFor(dllPath),
          effectiveDllPath, "repro_runtime_init")
        if fromProbe != 0'u32:
          rva = uint(fromProbe)
      else:
        var parentDllPathW = toWideCStringSeq(effectiveDllPath)
        parentShim = LoadLibraryWRaw(cast[LPCWSTR](addr parentDllPathW[0]))
        if parentShim != nil:
          let parentInit = GetProcAddress(parentShim, "repro_runtime_init")
          if parentInit != nil:
            rva = cast[uint](parentInit) - cast[uint](parentShim)

      if rva != 0:
        let childInit = cast[pointer](cast[uint](foundShim) + rva)
        let initThread = CreateRemoteThread(pi.hProcess, nil, 0,
          childInit, nil, 0, nil)
        if initThread != nil:
          discard WaitForSingleObject(initThread, INFINITE)
          discard CloseHandle(initThread)
      if parentShim != nil:
        discard FreeLibraryRaw(parentShim)

    # 6. Resume the suspended main thread.
    discard ResumeThread(pi.hThread)

    # 7. Wait for the child to exit. In capture mode we close our write
    # end first so the read returns EOF when the child closes its end,
    # then drain in a poll loop alongside the WaitForSingleObject.
    if captureStdio:
      # Close the parent-side write end. The child still holds its
      # inheritable copy so PeekNamedPipe / ReadFile on our read end
      # will keep returning data until the child closes everything.
      if stdoutWritePipe != nil:
        discard CloseHandle(stdoutWritePipe)
        stdoutWritePipe = nil
      var captureBuf: array[8192, char]
      var captureOut: File
      let writeToFile = captureStdioPath.len > 0
      if writeToFile:
        try:
          captureOut = open(captureStdioPath, fmWrite)
        except IOError, OSError:
          captureOut = nil
      while true:
        # Drain everything PeekNamedPipe reports as available, then
        # check process exit. WaitForSingleObject with 50ms timeout
        # caps the drain latency so we don't spin.
        while true:
          var avail: DWORD = 0
          if PeekNamedPipe(stdoutReadPipe, nil, 0, nil, addr avail, nil) == 0:
            break
          if avail == 0:
            break
          var got: DWORD = 0
          if ReadFile(stdoutReadPipe, addr captureBuf[0],
                      DWORD(captureBuf.len), addr got, nil) == 0:
            break
          if got == 0:
            break
          if writeToFile and captureOut != nil:
            try:
              discard captureOut.writeBuffer(addr captureBuf[0], int(got))
              captureOut.flushFile()
            except IOError:
              discard
          # If no path was specified we just discard — the goal in
          # tests is to mimic the engine's "drain to /dev/null" path
          # (engine keeps the bytes in memory but tests rarely need
          # them).
        let waitStatus = WaitForSingleObject(pi.hProcess, 50'u32)
        if waitStatus == WAIT_OBJECT_0:
          break
      # Final drain after exit — anything in the buffer that wasn't
      # consumed during the 50ms slice.
      while true:
        var got: DWORD = 0
        if ReadFile(stdoutReadPipe, addr captureBuf[0],
                    DWORD(captureBuf.len), addr got, nil) == 0:
          break
        if got == 0:
          break
        if writeToFile and captureOut != nil:
          try:
            discard captureOut.writeBuffer(addr captureBuf[0], int(got))
            captureOut.flushFile()
          except IOError:
            discard
      if writeToFile and captureOut != nil:
        try: captureOut.close()
        except IOError: discard
      if stdoutReadPipe != nil:
        discard CloseHandle(stdoutReadPipe)
        stdoutReadPipe = nil
    else:
      discard WaitForSingleObject(pi.hProcess, INFINITE)
    var exit: DWORD = 0
    discard GetExitCodeProcess(pi.hProcess, addr exit)
    result.exitCode = int(exit)
  except OSError as e:
    discard TerminateProcess(pi.hProcess, 1'u32)
    safeClose(pi.hThread)
    safeClose(pi.hProcess)
    if stdoutWritePipe != nil:
      discard CloseHandle(stdoutWritePipe)
      stdoutWritePipe = nil
    if stdoutReadPipe != nil:
      discard CloseHandle(stdoutReadPipe)
      stdoutReadPipe = nil
    DeleteProcThreadAttributeList(attrList)
    discard HeapFree(processHeap, 0'u32, attrList)
    raise e
  safeClose(pi.hThread)
  safeClose(pi.hProcess)
  if stdoutWritePipe != nil:
    discard CloseHandle(stdoutWritePipe)
  if stdoutReadPipe != nil:
    discard CloseHandle(stdoutReadPipe)
  DeleteProcThreadAttributeList(attrList)
  discard HeapFree(processHeap, 0'u32, attrList)

{.pop.}

initLock(wow64StateLock)
