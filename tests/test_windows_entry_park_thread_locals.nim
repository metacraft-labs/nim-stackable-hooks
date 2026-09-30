## Real injected-DLL regression for borrowed-thread initialization. No mocks.
##
## The main thread must load the DLL, retain the probe initialized by its
## module body, keep its state separate from a fresh OS thread, and safely
## rehash a container allocated at module initialization. These properties
## apply to both native TLS and GCC's emulated TLS; a TEB-relative offset does
## not describe GCC's storage.
##
## Two real negative controls prevent a vacuous pass. Loading on a remote
## thread must reject the initializing thread's identity. A DLL compiled with
## a shared probe must reject state isolation specifically (child exit 5).
## Missing injection, a hung child, or missing exports fails every arm.

when defined(windows) and (defined(i386) or defined(amd64)):

  import std/[os, osproc, unittest]

  import stackable_hooks/windows_entry_park

  type
    HANDLE = pointer
    DWORD = uint32
    WORD = uint16
    BOOL = int32
    LPWSTR = ptr uint16
    LPCWSTR = ptr uint16

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
    WAIT_OBJECT_0 = 0x0'u32
    MEM_COMMIT = 0x00001000'u32
    MEM_RESERVE = 0x00002000'u32
    MEM_RELEASE = 0x00008000'u32
    PAGE_READWRITE = 0x04'u32
    LibEnvVar = "STACKABLE_HOOKS_TLS_LIB"
    MarkEnvVar = "STACKABLE_HOOKS_TLS_MARK"

  proc CreateProcessW(lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
                      lpProcessAttributes: pointer,
                      lpThreadAttributes: pointer,
                      bInheritHandles: BOOL, dwCreationFlags: DWORD,
                      lpEnvironment: pointer, lpCurrentDirectory: LPCWSTR,
                      lpStartupInfo: pointer,
                      lpProcessInformation: ptr PROCESS_INFORMATION): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc VirtualAllocEx(hProcess: HANDLE, address: pointer, size: uint,
                      allocType: DWORD, protect: DWORD): pointer
    {.importc, stdcall, dynlib: "kernel32".}
  proc VirtualFreeEx(hProcess: HANDLE, address: pointer, size: uint,
                     freeType: DWORD): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc WriteProcessMemory(hProcess: HANDLE, base: pointer, buf: pointer,
                          size: uint, written: ptr uint): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc CreateRemoteThread(hProcess: HANDLE, sa: pointer, stack: uint,
                          start: pointer, param: pointer, flags: DWORD,
                          tid: ptr DWORD): HANDLE
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetModuleHandleW(name: LPCWSTR): HANDLE
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetProcAddress(m: HANDLE, name: cstring): pointer
    {.importc, stdcall, dynlib: "kernel32".}
  proc IsWow64Process(hProcess: HANDLE, res: ptr BOOL): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc ResumeThread(hThread: HANDLE): DWORD
    {.importc, stdcall, dynlib: "kernel32".}
  proc WaitForSingleObject(hHandle: HANDLE, ms: DWORD): DWORD
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetExitCodeProcess(hProcess: HANDLE, code: ptr DWORD): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc TerminateProcess(hProcess: HANDLE, code: DWORD): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc CloseHandle(hObject: HANDLE): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetLastError(): DWORD
    {.importc, stdcall, dynlib: "kernel32".}

  proc toWide(s: string): seq[uint16] =
    result.setLen(s.len + 1)
    for i, c in s:
      result[i] = uint16(c)
    result[s.len] = 0'u16

  type
    LoadTechnique = enum
      ltBorrowedThread   ## the parked main thread calls LoadLibraryW
      ltRemoteThread     ## CreateRemoteThread calls it (the defect)

    ChildOutcome = object
      parked: bool
      loaded: bool
      hung: bool
      exitCode: DWORD
      marked: bool

  proc buildFixture(src, outPath: string; asLib: bool; sharedProbe = false) =
    let root = currentSourcePath.parentDir.parentDir
    var args = @["c", "--hints:off", "--threads:on", "--mm:orc",
                 "--path:" & (root / "src"), "--out:" & outPath]
    if asLib:
      args.add "--app:lib"
    if sharedProbe:
      args.add "-d:parkTlsSharedProbe"
    args.add src
    let p = startProcess(findExe("nim"), args = args,
      options = {poUsePath, poParentStreams})
    let rc = waitForExit(p)
    close(p)
    doAssert rc == 0, "building fixture " & src & " failed with " & $rc
    doAssert fileExists(outPath), "fixture " & outPath & " was not produced"

  proc loadLibraryWAddress(): pointer =
    var k32 = toWide("kernel32.dll")
    let kernel32 = GetModuleHandleW(cast[LPCWSTR](addr k32[0]))
    doAssert kernel32 != nil
    result = GetProcAddress(kernel32, "LoadLibraryW")
    doAssert result != nil

  proc runChild(technique: LoadTechnique; childExe, dll, mark: string;
                waitMs: DWORD): ChildOutcome =
    ## Spawn the fixture suspended, park it, inject the fixture DLL the way
    ## `technique` asks for, release the park, resume, and wait.
    removeFile(mark)
    putEnv(LibEnvVar, dll)
    putEnv(MarkEnvVar, mark)

    var cmdW = toWide("\"" & childExe & "\"")
    var si: STARTUPINFOW
    si.cb = DWORD(sizeof(si))
    var pi: PROCESS_INFORMATION
    if CreateProcessW(nil, cast[LPWSTR](addr cmdW[0]), nil, nil, BOOL(1),
        CREATE_SUSPENDED, nil, nil, addr si, addr pi) == 0:
      raise newException(OSError,
        "CreateProcessW failed (err=" & $GetLastError() & ")")

    var wow64: BOOL = 0
    discard IsWow64Process(pi.hProcess, addr wow64)

    var park = parkChildAtEntryPoint(pi.hProcess, pi.hThread, wow64 != 0,
      10_000'u32)
    result.parked = park.status == epsParked

    if result.parked:
      var dllW = toWide(dll)
      let bufSize = uint(dllW.len * sizeof(uint16))
      let remoteBuf = VirtualAllocEx(pi.hProcess, nil, bufSize,
        MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
      doAssert remoteBuf != nil
      var wrote: uint = 0
      doAssert WriteProcessMemory(pi.hProcess, remoteBuf, addr dllW[0],
        bufSize, addr wrote) != 0
      let loadLibraryW = loadLibraryWAddress()

      case technique
      of ltBorrowedThread:
        var module: uint64 = 0
        result.loaded = callOnParkedThread(park, pi.hThread, wow64 != 0,
          loadLibraryW, remoteBuf, 10_000'u32, module) and module != 0
      of ltRemoteThread:
        let t = CreateRemoteThread(pi.hProcess, nil, 0, loadLibraryW,
          remoteBuf, 0, nil)
        if t != nil:
          discard WaitForSingleObject(t, 10_000'u32)
          discard CloseHandle(t)
          result.loaded = true
      discard VirtualFreeEx(pi.hProcess, remoteBuf, 0, MEM_RELEASE)

    releaseEntryPark(park)
    discard ResumeThread(pi.hThread)

    if WaitForSingleObject(pi.hProcess, waitMs) != WAIT_OBJECT_0:
      result.hung = true
      discard TerminateProcess(pi.hProcess, 0xDEAD'u32)
      discard WaitForSingleObject(pi.hProcess, 10_000'u32)
    else:
      discard GetExitCodeProcess(pi.hProcess, addr result.exitCode)
    discard CloseHandle(pi.hThread)
    discard CloseHandle(pi.hProcess)
    result.marked = fileExists(mark)

  suite "Windows entry park: the child's own thread must map the shim":
    let workDir = getTempDir() / "stackable-hooks-park-tls"
    createDir(workDir)
    let fixtures = currentSourcePath.parentDir / "fixtures"
    let dll = workDir / "park_tls_lib.dll"
    let sharedDll = workDir / "park_tls_shared.dll"
    let childExe = workDir / "park_tls_child.exe"
    let mark = workDir / "loaded.mark"

    buildFixture(fixtures / "park_tls_lib.nim", dll, asLib = true)
    buildFixture(fixtures / "park_tls_child.nim", childExe, asLib = false)
    buildFixture(fixtures / "park_tls_lib.nim", sharedDll, asLib = true,
      sharedProbe = true)

    test "a borrowed parked thread leaves the child's thread-locals sound":
      let outcome = runChild(ltBorrowedThread, childExe, dll, mark, 60_000'u32)
      check outcome.parked
      check outcome.loaded
      check outcome.marked
      check not outcome.hung
      checkpoint("child exit code: " & $outcome.exitCode)
      check outcome.exitCode == 0

    test "a remote-thread load into the same parked child does not":
      ## The control. Same park, same DLL, same fixture -- only the thread
      ## that calls LoadLibraryW differs.
      let outcome = runChild(ltRemoteThread, childExe, dll, mark, 60_000'u32)
      check outcome.parked
      check outcome.loaded
      # The DLL really did map: a control that failed for want of an
      # injection would prove nothing about thread-local storage.
      check outcome.marked
      check not outcome.hung
      checkpoint("control child exit code: " & $outcome.exitCode &
        " (4 = the DLL initialised on a thread that is not this one; " &
        "5 = thread-local state is not isolated; " &
        "1 / 0xC0000005 = it faulted)")
      check outcome.exitCode != 0

    test "a deliberately shared probe fails the isolation check":
      let outcome = runChild(ltBorrowedThread, childExe, sharedDll, mark,
        60_000'u32)
      check outcome.parked
      check outcome.loaded
      check outcome.marked
      check not outcome.hung
      checkpoint("shared-probe child exit code: " & $outcome.exitCode)
      check outcome.exitCode == 5
