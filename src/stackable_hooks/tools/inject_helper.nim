## 64-bit injection helper for 32-bit (WOW64) injectors.
##
## ## Why this exists
##
## `windows_injector` and `propagation_windows` inject by writing the shim's
## path into the child and starting a remote thread at `LoadLibraryW`. That
## works in either direction *except* one: a WOW64 process injecting into a
## 64-bit process.
##
## A WOW64 process cannot resolve the 64-bit `kernel32`'s `LoadLibraryW` (its
## own `kernel32` is the SysWOW64 one, at an unrelated base), and its
## `VirtualAllocEx` / `WriteProcessMemory` / `CreateRemoteThread` calls go
## through the WOW64 thunk layer, which does not address a 64-bit target's
## address space. There is no in-process route; the usual workarounds are
## "Heaven's Gate"-style far-jumps into 64-bit mode, which are undocumented,
## version-fragile and defeated by CFG.
##
## This is the same problem the WOW64 probe solves in the other direction,
## and it takes the same shape of answer: **ask a process of the right
## bitness**. The probe reports an address; this helper performs the whole
## injection, because unlike an address, the operation itself cannot cross
## the boundary.
##
## The chain it exists for is not exotic. A 64-bit build spawns a tool
## through a 32-bit PATH trampoline (scoop's shims are i386), that trampoline
## is injected as a WOW64 child, and it then spawns the real 64-bit tool --
## which the 32-bit shim inside it cannot inject. Without this helper that
## grandchild runs unmonitored, and an unmonitored subtree is an
## unknown-scope loss that disqualifies the whole action from the cache.
##
## ## Contract
##
##   stackable_hooks_inject64.exe <pid> <dll-path> [init-symbol]
##
##   * Exit 0 -- the DLL was loaded in the target and, if `init-symbol` was
##     given and found, its initialiser was run there.
##   * Non-zero -- a specific failure stage (see `ExitCode` below), so the
##     caller can report *why* rather than a bare "inject failed".
##
## The target is expected to be suspended (or at least alive) for the
## duration; the caller creates it with CREATE_SUSPENDED and resumes it only
## after this helper returns, exactly as it would for an in-process
## injection.

when not defined(windows):
  {.error: "stackable_hooks/tools/inject_helper is Windows-only".}

when sizeof(pointer) != 8:
  {.error: "inject_helper MUST be compiled 64-bit: its whole purpose is to " &
           "perform an injection that a 32-bit process cannot, so a 32-bit " &
           "build would reproduce the limitation it exists to work around".}

import std/[os, strutils]

type
  HANDLE = pointer
  DWORD = uint32
  SIZE_T = uint
  LPCWSTR = ptr uint16

const
  PROCESS_CREATE_THREAD = 0x0002'u32
  PROCESS_QUERY_INFORMATION = 0x0400'u32
  PROCESS_VM_OPERATION = 0x0008'u32
  PROCESS_VM_WRITE = 0x0020'u32
  PROCESS_VM_READ = 0x0010'u32
  MEM_COMMIT = 0x1000'u32
  MEM_RESERVE = 0x2000'u32
  MEM_RELEASE = 0x8000'u32
  PAGE_READWRITE = 0x04'u32
  INFINITE = 0xFFFFFFFF'u32

type
  ExitCode = enum
    ecOk = 0
    ecBadArgs = 1
    ecOpenProcess = 2
    ecAlloc = 3
    ecWrite = 4
    ecResolveLoadLibrary = 5
    ecRemoteThread = 6
    ecLoadLibraryReturnedNull = 7
    ecEnumModules = 8

proc OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: int32,
                 dwProcessId: DWORD): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc CloseHandle(h: HANDLE): int32
  {.importc, stdcall, dynlib: "kernel32".}
proc VirtualAllocEx(hProcess: HANDLE, lpAddress: pointer, dwSize: SIZE_T,
                    flAllocationType: DWORD, flProtect: DWORD): pointer
  {.importc, stdcall, dynlib: "kernel32".}
proc VirtualFreeEx(hProcess: HANDLE, lpAddress: pointer, dwSize: SIZE_T,
                   dwFreeType: DWORD): int32
  {.importc, stdcall, dynlib: "kernel32".}
proc WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: pointer,
                        lpBuffer: pointer, nSize: SIZE_T,
                        lpNumberOfBytesWritten: ptr SIZE_T): int32
  {.importc, stdcall, dynlib: "kernel32".}
proc CreateRemoteThread(hProcess: HANDLE, lpThreadAttributes: pointer,
                        dwStackSize: SIZE_T, lpStartAddress: pointer,
                        lpParameter: pointer, dwCreationFlags: DWORD,
                        lpThreadId: ptr DWORD): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc WaitForSingleObject(h: HANDLE, ms: DWORD): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc GetExitCodeThread(h: HANDLE, exitCode: ptr DWORD): int32
  {.importc, stdcall, dynlib: "kernel32".}
proc GetModuleHandleW(lpModuleName: LPCWSTR): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc GetProcAddress(hModule: HANDLE, lpProcName: cstring): pointer
  {.importc, stdcall, dynlib: "kernel32".}
proc LoadLibraryW(lpLibFileName: LPCWSTR): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc FreeLibrary(h: HANDLE): int32
  {.importc, stdcall, dynlib: "kernel32".}
proc EnumProcessModulesEx(hProcess: HANDLE, lphModule: ptr pointer, cb: DWORD,
                          lpcbNeeded: ptr DWORD, dwFilterFlag: DWORD): int32
  {.importc, stdcall, dynlib: "psapi".}
proc GetModuleBaseNameW(hProcess: HANDLE, hModule: HANDLE, lpBaseName: ptr uint16,
                        nSize: DWORD): DWORD
  {.importc, stdcall, dynlib: "psapi".}

proc toWide(s: string): seq[uint16] =
  result = newSeq[uint16](s.len + 1)
  for i, c in s:
    result[i] = uint16(ord(c))
  result[s.len] = 0

proc baseNameOf(path: string): string =
  let idx = max(path.rfind('\\'), path.rfind('/'))
  if idx < 0: path else: path[idx + 1 .. ^1]

proc childModuleBase(hProcess: HANDLE, wanted: string): HANDLE =
  ## The child's load address for `wanted`, found by basename. The DLL was
  ## just loaded there by us, so the loader reports the same basename we sent.
  var mods: array[1024, HANDLE]
  var needed: DWORD = 0
  # 0x3 = LIST_MODULES_ALL: a 64-bit target from a 64-bit caller needs no
  # filtering, but being explicit keeps the call identical to the injector's.
  if EnumProcessModulesEx(hProcess, cast[ptr pointer](addr mods[0]),
      DWORD(sizeof(mods)), addr needed, 0x3'u32) == 0:
    return nil
  let count = min(int(needed) div sizeof(HANDLE), mods.len)
  for i in 0 ..< count:
    var nameBuf: array[512, uint16]
    let n = GetModuleBaseNameW(hProcess, mods[i], addr nameBuf[0],
      DWORD(nameBuf.len))
    if n == 0:
      continue
    var got = newStringOfCap(int(n))
    for j in 0 ..< int(n):
      got.add(chr(int(nameBuf[j]) and 0xFF))
    if cmpIgnoreCase(got, wanted) == 0:
      return mods[i]
  nil

proc runInitInChild(hProcess: HANDLE, dllPath, initSymbol: string): bool =
  ## Start `initSymbol` in the child at (child base + local RVA). Both this
  ## process and the child are 64-bit and mapped the same image, so the
  ## offset computed here transfers -- the very property the 32-bit caller
  ## could not rely on.
  if initSymbol.len == 0:
    return true
  var pathW = toWide(dllPath)
  let localMod = LoadLibraryW(cast[LPCWSTR](addr pathW[0]))
  if localMod == nil:
    return false
  defer: discard FreeLibrary(localMod)
  let localInit = GetProcAddress(localMod, initSymbol.cstring)
  if localInit == nil:
    return false
  let rva = cast[uint](localInit) - cast[uint](localMod)
  let childBase = childModuleBase(hProcess, baseNameOf(dllPath))
  if childBase == nil:
    return false
  let thread = CreateRemoteThread(hProcess, nil, 0,
    cast[pointer](cast[uint](childBase) + rva), nil, 0, nil)
  if thread == nil:
    return false
  discard WaitForSingleObject(thread, INFINITE)
  discard CloseHandle(thread)
  true

proc main() =
  if paramCount() < 2:
    quit(ord(ecBadArgs))
  var pid: int
  try:
    pid = parseInt(paramStr(1))
  except ValueError:
    quit(ord(ecBadArgs))
  let dllPath = paramStr(2)
  let initSymbol = if paramCount() >= 3: paramStr(3) else: ""

  let access = PROCESS_CREATE_THREAD or PROCESS_QUERY_INFORMATION or
    PROCESS_VM_OPERATION or PROCESS_VM_WRITE or PROCESS_VM_READ
  let hProcess = OpenProcess(access, 0, DWORD(pid))
  if hProcess == nil:
    quit(ord(ecOpenProcess))
  defer: discard CloseHandle(hProcess)

  var pathW = toWide(dllPath)
  let byteLen = SIZE_T(pathW.len * sizeof(uint16))
  let remote = VirtualAllocEx(hProcess, nil, byteLen,
    MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if remote == nil:
    quit(ord(ecAlloc))

  var written: SIZE_T = 0
  if WriteProcessMemory(hProcess, remote, addr pathW[0], byteLen,
      addr written) == 0:
    discard VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE)
    quit(ord(ecWrite))

  # This process and the target share a bitness, so our own kernel32 is at
  # the same base in the target and GetProcAddress here is its address there.
  var k32Name = toWide("kernel32.dll")
  let kernel32 = GetModuleHandleW(cast[LPCWSTR](addr k32Name[0]))
  let loadLibrary = if kernel32 == nil: nil
                    else: GetProcAddress(kernel32, "LoadLibraryW")
  if loadLibrary == nil:
    discard VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE)
    quit(ord(ecResolveLoadLibrary))

  let thread = CreateRemoteThread(hProcess, nil, 0, loadLibrary, remote, 0, nil)
  if thread == nil:
    discard VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE)
    quit(ord(ecRemoteThread))
  discard WaitForSingleObject(thread, INFINITE)
  var loadResult: DWORD = 0
  discard GetExitCodeThread(thread, addr loadResult)
  discard CloseHandle(thread)
  discard VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE)

  # GetExitCodeThread truncates the returned HMODULE to 32 bits, so it is
  # only usable as a zero / non-zero answer; the module base comes from the
  # module walk instead.
  if loadResult == 0:
    quit(ord(ecLoadLibraryReturnedNull))

  if not runInitInChild(hProcess, dllPath, initSymbol):
    quit(ord(ecEnumModules))

  quit(ord(ecOk))

main()
