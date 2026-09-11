## Failing-before / passing-after for the SECOND hazard the entry-point
## park creates, and the reason `windows_entry_park.callOnParkedThread`
## exists.
##
## WHAT IS BEING MEASURED
## ----------------------
## The park's purpose is that the child's MAIN thread runs the Windows
## loader before anything is injected, so an MSYS2/Cygwin runtime is not
## left bound to a thread that immediately exits. The injection itself then
## still went in on a ``CreateRemoteThread`` -- and that thread runs the
## shim's DLL entry point, its module body, and its init export, and then
## EXITS.
##
## Which matters because of where a Nim ``--threads:on`` runtime keeps its
## heap. The allocator is a ``MemRegion`` THREADVAR: it lives in the
## thread's TLS block, the OS releases that block when the thread exits,
## and every allocated chunk carries a pointer back to the region that owns
## it. Anything the module body allocates -- every process-global table the
## shim keeps -- is therefore owned by the injecting thread's region, and
## the first free of it from any other thread dereferences a region that
## thread took with it. That free is silent for as long as the released
## block stays committed, and an access violation the moment it does not.
##
## Before the park this never bit, because the injecting thread ran the
## whole loader and the child's main thread had not started: the two ended
## up with regions that compared equal. The park separates them, and the
## defect became a SIGSEGV that reproduced 44 environment variables in,
## every run.
##
## THE TWO ARMS, against one identical fixture
## -------------------------------------------
## * BORROWED (the fix) -- the parked main thread is made to call
##   ``LoadLibraryW`` itself through ``callOnParkedThread``. The child must
##   exit 0.
## * REMOTE (the control, and the verbatim shape of the defect) -- the same
##   parked child, loaded with ``CreateRemoteThread``. The child must NOT
##   exit 0.
##
## The control is what stops the passing arm from passing vacuously: both
## arms park the same child, inject the same DLL, and run the same fixture,
## and the ONLY difference is which thread calls ``LoadLibraryW``. Without
## it, a fixture that never exercised thread-local storage at all would
## look identical to a fix.
##
## WHAT THE FIXTURE ASSERTS, and why it is not "does it crash"
## -----------------------------------------------------------
## The fault this fix was found through is a USE-AFTER-FREE, and a
## use-after-free is only sometimes a crash. The measured case was a Nim
## ``Table`` allocated in the shim's module body and rehashed -- freed --
## from the child's main thread: the allocator dereferenced the owning
## ``MemRegion``, a threadvar in the TLS block of the thread that had run
## the module body and then exited. With the injected DLL's layout that
## released block was uncommitted and it was a deterministic access
## violation at the 44th distinct environment variable; in a smaller
## process the same free lands on memory that is still mapped and corrupts
## it silently. A control that asserted "it crashes" would therefore be a
## flake generator, and it was: an early version of this fixture passed its
## own control because the freed block happened to stay committed.
##
## So ``tests/fixtures/park_tls_child.nim`` asserts the PROPERTY the fix
## establishes rather than one of its symptoms, and reports a distinct exit
## code per check:
##
##   * 4 -- the DLL's module initialisation must have run ON THIS THREAD.
##     That is exactly what the borrow buys: the globals the module body
##     allocates are owned by the region of the thread that outlives the
##     whole process, so no later free of them crosses a thread that can
##     disappear. A remote-thread load fails this deterministically,
##     whatever the heap happens to look like.
##   * 5 -- the DLL's threadvar must sit at the SAME offset from this
##     module's TLS block here as on a thread created after the injection.
##     A link-time constant, so this reads directly whether this thread's
##     ``_tls_index`` slot points at this module's block.
##   * 6 -- the container allocated at module init must survive being grown
##     from here: the exact allocation pattern that faulted.
##
## Exit code 3 means the DLL was not mapped at all. The test treats that as
## a failure on BOTH arms, because a control that failed for want of an
## injection would prove nothing.
##
## IF THE CONTROL EVER PASSES, a remote-thread load has started running the
## injected module's initialisation on the child's main thread, which would
## mean the borrow could be retired. That is a real finding, not a flake.
## Do not "fix" it by loosening the assertion.

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

  proc buildFixture(src, outPath: string; asLib: bool) =
    let root = currentSourcePath.parentDir.parentDir
    var args = @["c", "--hints:off", "--threads:on", "--mm:orc",
                 "--path:" & (root / "src"), "--out:" & outPath]
    if asLib:
      args.add "--app:lib"
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
    let childExe = workDir / "park_tls_child.exe"
    let mark = workDir / "loaded.mark"

    buildFixture(fixtures / "park_tls_lib.nim", dll, asLib = true)
    buildFixture(fixtures / "park_tls_child.nim", childExe, asLib = false)

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
      checkpoint("control child exit code: " & $outcome.exitCode &
        " (4 = the DLL initialised on a thread that is not this one; " &
        "5 = its threadvar is not in this thread's TLS block; " &
        "1 / 0xC0000005 = it faulted)")
      check outcome.exitCode != 0
