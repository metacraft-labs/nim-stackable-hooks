## Failing-before / passing-after for a borrowed call into a child that runs
## with a hardware SHADOW STACK (Intel CET / "Hardware-enforced Stack
## Protection").
##
## WHAT BROKE
## ----------
## ``windows_entry_park.callOnParkedThread`` used to arrange the borrowed
## call by WRITING a return address -- the parked entry point -- onto the
## child's ordinary stack and pointing ``RIP`` at the callee. Nothing ever
## executed a ``call``, so the shadow stack never received a matching entry.
## On a host with user-mode shadow stacks, any image linked ``/CETCOMPAT``
## runs with them enforced, and the callee's ``ret`` then pops a shadow-stack
## entry that does not match the ordinary one: ``#CP``, delivered as
## ``STATUS_STACK_BUFFER_OVERRUN`` (0xC0000409) with fast-fail subcode 0x39,
## ``FAST_FAIL_CONTROL_INVALID_RETURN_ADDRESS``.
##
## That is how it was found. io-mon's shim injects every child of a monitored
## build edge through this proc; reprobuild runs a long ``nim c`` through
## ``pwsh`` (to get past ``cmd.exe``'s 8191-character limit); ``pwsh.exe`` is
## a ``/CETCOMPAT`` .NET apphost; so the shim's ``LoadLibraryW`` returned into
## a shadow-stack violation and ``pwsh`` died before it ever started ``nim``.
## Measured under ``cdb -o``: ``KERNELBASE!LoadLibraryExW+0x11a`` (its
## ``ret``), returning to ``apphost!__scrt_common_main_seh+0x183``.
##
## THE FIXTURE
## -----------
## A declared GCC/LLVM toolchain builds the repository's AMD64 C child and
## links it with LLD's supported CET compatibility option. The fixture reads
## the PE machine and real extended DLL-characteristics debug record before
## spawning it, instead of assuming System32's curl has an AMD64 view on ARM.
## Its main thread is parked, borrowed twice, released and resumed; the real
## entry point then calls ExitProcess(0) without network or CRT dependencies.
## GetCurrentProcessId must return the child's PID, proving each borrowed call
## ran inside that child and returned through its genuine CALL/RET path.
##
## WHERE THIS DISCRIMINATES. Only where the fixture actually runs with a
## shadow stack, which needs CET-capable hardware and an OS that enables it
## for ``/CETCOMPAT`` images. The test reads the child's
## ``ProcessUserShadowStackPolicy`` and reports it with a checkpoint; on a
## host where the policy is off, the cases still have to pass, but they
## cannot tell the two arrangements apart. On this repository's Windows
## development host (2026-10-05) the policy is ON and the unfixed proc fails
## every case below with the child dead of 0xC0000409.

when defined(windows) and defined(amd64):

  import std/[os, osproc, strutils, tempfiles, unittest]

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

    STARTUPINFOEXW {.bycopy.} = object
      StartupInfo: STARTUPINFOW
      lpAttributeList: pointer

    PROCESS_INFORMATION {.bycopy.} = object
      hProcess: HANDLE
      hThread: HANDLE
      dwProcessId: DWORD
      dwThreadId: DWORD

  const
    CREATE_SUSPENDED = 0x00000004'u32
    CREATE_NO_WINDOW = 0x08000000'u32
    WAIT_OBJECT_0 = 0x0'u32
    StillActive = 259'u32
    # PROCESS_MITIGATION_POLICY::ProcessUserShadowStackPolicy, and bit 0
    # (EnableUserShadowStack) of PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY.
    ProcessUserShadowStackPolicy = 15'i32
    EnableUserShadowStack = 0x1'u32

  proc CreateProcessW(lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
                      lpProcessAttributes: pointer,
                      lpThreadAttributes: pointer,
                      bInheritHandles: BOOL, dwCreationFlags: DWORD,
                      lpEnvironment: pointer, lpCurrentDirectory: LPCWSTR,
                      lpStartupInfo: pointer,
                      lpProcessInformation: ptr PROCESS_INFORMATION): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetCurrentProcess(): HANDLE
    {.importc, stdcall, dynlib: "kernel32".}
  proc IsWow64Process2(process: HANDLE; processMachine, nativeMachine: ptr WORD): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc InitializeProcThreadAttributeList(attributes: pointer; count, flags: DWORD;
                                        size: ptr uint): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc UpdateProcThreadAttribute(attributes: pointer; flags: DWORD;
                                attribute: uint; value: pointer; size: uint;
                                previous: pointer; returnedSize: ptr uint): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc DeleteProcThreadAttributeList(attributes: pointer)
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetProcessMitigationPolicy(hProcess: HANDLE; policy: int32;
                                  buffer: pointer; length: uint): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetModuleHandleW(name: LPCWSTR): HANDLE
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetProcAddress(m: HANDLE, name: cstring): pointer
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
  proc VirtualAllocEx(hProcess: HANDLE; address: pointer; size: uint;
                      allocType: DWORD; protect: DWORD): pointer
    {.importc, stdcall, dynlib: "kernel32".}
  proc WriteProcessMemory(hProcess: HANDLE; base: pointer; buffer: pointer;
                          size: uint; written: ptr uint): BOOL
    {.importc, stdcall, dynlib: "kernel32".}

  proc toWide(s: string): seq[uint16] =
    result.setLen(s.len + 1)
    for i, c in s:
      result[i] = uint16(c)
    result[s.len] = 0'u16

  proc kernel32Export(name: string): pointer =
    var k32 = toWide("kernel32.dll")
    let kernel32 = GetModuleHandleW(cast[LPCWSTR](addr k32[0]))
    doAssert kernel32 != nil
    result = GetProcAddress(kernel32, name.cstring)
    doAssert result != nil, "kernel32!" & name & " not found"

  type
    Outcome = object
      shadowStack: bool       ## the child runs with a user shadow stack
      parked: bool
      calls: seq[bool]        ## each borrowed call came back
      answers: seq[uint64]    ## and what it returned
      pid: DWORD
      hung: bool
      exitCode: DWORD

  proc peWord(data: string; offset: int): uint16 =
    doAssert offset >= 0 and offset + 2 <= data.len
    uint16(ord(data[offset])) or (uint16(ord(data[offset + 1])) shl 8)

  proc peDword(data: string; offset: int): uint32 =
    uint32(peWord(data, offset)) or (uint32(peWord(data, offset + 2)) shl 16)

  proc requireAmd64CetImage(path: string) =
    let data = readFile(path)
    doAssert data.len >= 64 and data[0 .. 1] == "MZ"
    let pe = int(peDword(data, 0x3c))
    doAssert pe >= 0 and pe + 24 <= data.len
    doAssert data[pe .. pe + 3] == "PE\0\0"
    doAssert peWord(data, pe + 4) == 0x8664, "CET child must be AMD64"
    let optional = pe + 24
    doAssert peWord(data, optional) == 0x20b, "CET child must be PE32+"
    let optionalSize = int(peWord(data, pe + 20))
    doAssert optionalSize >= 112 + 7 * 8 and optional + optionalSize <= data.len
    let sections = optional + optionalSize
    doAssert sections + int(peWord(data, pe + 6)) * 40 <= data.len
    proc fileOffset(rva: uint32): int =
      for index in 0 ..< int(peWord(data, pe + 6)):
        let section = sections + index * 40
        let address = peDword(data, section + 12)
        let size = peDword(data, section + 16)
        if rva >= address and rva - address < size:
          let offset = int(peDword(data, section + 20)) + int(rva - address)
          doAssert offset >= 0 and offset < data.len
          return offset
      raise newException(ValueError, "CET debug directory is outside image sections")
    let debugRva = peDword(data, optional + 112 + 6 * 8)
    let debugSize = int(peDword(data, optional + 112 + 6 * 8 + 4))
    doAssert debugRva != 0 and debugSize >= 28
    let debug = fileOffset(debugRva)
    doAssert debugSize mod 28 == 0 and debug + debugSize <= data.len
    var cet = false
    for index in 0 ..< debugSize div 28:
      let entry = debug + index * 28
      if peDword(data, entry + 12) == 20: # IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
        doAssert peDword(data, entry + 16) >= 4
        let payload = int(peDword(data, entry + 24))
        doAssert payload >= 0 and payload + int(peDword(data, entry + 16)) <= data.len
        cet = (peDword(data, payload) and 1) != 0 # CET_COMPAT
    doAssert cet, "Declared linker did not emit real CET compatibility metadata"

  proc buildCetChild(directory: string): string =
    let gcc = findExe("gcc")
    let clang = findExe("clang")
    doAssert gcc.len > 0 and clang.len > 0, "Declared GCC and LLVM toolchains required"
    let source = currentSourcePath.parentDir / "fixtures" / "cet_child.c"
    let objectFile = directory / "cet_child.o"
    result = directory / "cet_child.exe"
    let imports = execCmdEx(quoteShell(gcc) & " -print-file-name=libkernel32.a")
    doAssert imports.exitCode == 0
    let kernel32 = imports.output.strip()
    doAssert kernel32.isAbsolute() and fileExists(kernel32)
    let compile = execCmdEx(quoteShell(gcc) & " -c -O2 " & quoteShell(source) &
      " -o " & quoteShell(objectFile))
    doAssert compile.exitCode == 0, compile.output
    let objectBytes = readFile(objectFile)
    doAssert peWord(objectBytes, 0) == 0x8664,
      "Declared GCC default target did not produce an AMD64 COFF object"
    let link = execCmdEx(quoteShell(clang) &
      " --target=x86_64-w64-windows-gnu -fuse-ld=lld -nostdlib" &
      " -Wl,-e,cetChildEntry -Wl,-Xlink=-cetcompat " & quoteShell(objectFile) &
      " " & quoteShell(kernel32) & " -o " & quoteShell(result))
    doAssert link.exitCode == 0, link.output
    requireAmd64CetImage(result)

  proc runBorrowedCalls(exe, args: string; borrows: int;
                        callee = "GetCurrentProcessId"; arg: pointer = nil;
                        timeoutMs = 10_000'u32;
                        childString = ""): Outcome =
    requireAmd64CetImage(exe)
    var cmdW = toWide("\"" & exe & "\" " & args)
    var si: STARTUPINFOW
    si.cb = DWORD(sizeof(si))
    var pi: PROCESS_INFORMATION
    var processMachine, nativeMachine: WORD
    if IsWow64Process2(GetCurrentProcess(), addr processMachine,
        addr nativeMachine) == 0:
      raise newException(OSError, "IsWow64Process2 failed")
    var flags = CREATE_SUSPENDED or CREATE_NO_WINDOW
    var startup: pointer = addr si
    var extended: STARTUPINFOEXW
    var attributes: seq[byte]
    var attributesInitialized = false
    defer:
      if attributesInitialized:
        DeleteProcThreadAttributeList(extended.lpAttributeList)
    var machine = WORD(0x8664) # IMAGE_FILE_MACHINE_AMD64
    if nativeMachine == WORD(0xaa64): # IMAGE_FILE_MACHINE_ARM64
      # The entry-park implementation and this CET fixture are AMD64.
      # The declared fixture is independently verified as an AMD64 CET image.
      var size: uint = 0
      discard InitializeProcThreadAttributeList(nil, 1, 0, addr size)
      if size == 0:
        raise newException(OSError, "Machine attribute size query failed")
      attributes = newSeq[byte](int(size))
      extended.lpAttributeList = addr attributes[0]
      if InitializeProcThreadAttributeList(extended.lpAttributeList, 1, 0,
          addr size) == 0:
        raise newException(OSError, "Machine attribute initialization failed")
      attributesInitialized = true
      # winbase.h: ProcThreadAttributeValue(MachineType=25, input=true).
      if UpdateProcThreadAttribute(extended.lpAttributeList, 0, 0x20019'u,
          addr machine, uint(sizeof(machine)), nil, nil) == 0:
        raise newException(OSError, "AMD64 machine selection failed")
      extended.StartupInfo.cb = DWORD(sizeof(extended))
      startup = addr extended
      flags = flags or 0x00080000'u32 # EXTENDED_STARTUPINFO_PRESENT
    if CreateProcessW(nil, cast[LPWSTR](addr cmdW[0]), nil, nil, BOOL(0),
        flags, nil, nil, startup, addr pi) == 0:
      raise newException(OSError,
        "CreateProcessW(" & exe & ") failed (err=" & $GetLastError() & ")")
    result.pid = pi.dwProcessId

    var policy: DWORD = 0
    if GetProcessMitigationPolicy(pi.hProcess, ProcessUserShadowStackPolicy,
        addr policy, uint(sizeof(policy))) != 0:
      result.shadowStack = (policy and EnableUserShadowStack) != 0

    var park = parkChildAtEntryPoint(pi.hProcess, pi.hThread, false,
      10_000'u32)
    result.parked = park.status == epsParked
    var callArg = arg
    if result.parked and childString.len > 0:
      # A wide string the callee reads IN THE CHILD, e.g. a LoadLibraryW
      # path. Freed with the child.
      var w = toWide(childString)
      let size = uint(w.len * sizeof(uint16))
      callArg = VirtualAllocEx(pi.hProcess, nil, size, 0x3000'u32, 0x04'u32)
      doAssert callArg != nil
      var wrote: uint = 0
      doAssert WriteProcessMemory(pi.hProcess, callArg, addr w[0], size,
        addr wrote) != 0 and wrote == size
    if result.parked:
      let fn = kernel32Export(callee)
      for _ in 0 ..< borrows:
        var answer: uint64 = 0
        let ok = callOnParkedThread(park, pi.hThread, false, fn, callArg,
          timeoutMs, answer)
        result.calls.add ok
        result.answers.add answer
        if not ok:
          break
    releaseEntryPark(park)
    discard ResumeThread(pi.hThread)

    if WaitForSingleObject(pi.hProcess, 60_000'u32) != WAIT_OBJECT_0:
      var code: DWORD = 0
      if GetExitCodeProcess(pi.hProcess, addr code) == 0 or
          code == StillActive:
        result.hung = true
        discard TerminateProcess(pi.hProcess, 0xDEAD'u32)
        discard WaitForSingleObject(pi.hProcess, 10_000'u32)
    discard GetExitCodeProcess(pi.hProcess, addr result.exitCode)
    discard CloseHandle(pi.hThread)
    discard CloseHandle(pi.hProcess)

  proc runCetSuite() =
    suite "Windows entry park: a borrowed call must keep the shadow stack":
      let fixtureDirectory = createTempDir("stackable-cet-child-", "")
      defer: removeDir(fixtureDirectory)
      let child = buildCetChild(fixtureDirectory)

      test "a /CETCOMPAT child survives two borrowed calls and exits 0":
        require fileExists(child)
        let outcome = runBorrowedCalls(child, "", borrows = 2)
        checkpoint("fixture runs with a user shadow stack: " &
          $outcome.shadowStack & (if outcome.shadowStack: "" else:
            " -- this host cannot discriminate the shadow-stack hazard"))
        checkpoint("child exit code: 0x" & outcome.exitCode.int64.toHex(8) &
          " (0xC0000409 = shadow-stack violation in the borrowed call)")
        check outcome.parked
        check outcome.calls == @[true, true]
        # The borrowed callee ran IN the child, on its main thread, and its
        # `ret` came back: GetCurrentProcessId answered the CHILD's pid.
        check outcome.answers == @[uint64(outcome.pid), uint64(outcome.pid)]
        check not outcome.hung
        check outcome.exitCode == 0

      test "a borrowed call that outlives its hard deadline poisons the child":
        ## The slow path, under R2 of docs/windows-borrowed-call-deadline.md:
        ## a thread whose context is lent out is never resumed.
        ## `kernel32!Sleep(3000)` is borrowed with a 500 ms hard deadline, so
        ## the call is still running when the deadline passes. The borrow must
        ## then terminate the child with `InjectionAbandonedExitCode`, and the
        ## caller's release and `ResumeThread` (exactly what
        ## `injectShimIntoChild` does after a failed injection) must neither
        ## bring it back nor leave it hanging. When this test was written, the
        ## deadline was a 5 s budget and an expired borrow resumed the child,
        ## so this case asserted exit 0 instead. On this CET child that case
        ## also caught a stub that ended the borrow on a self-jump of its own
        ## and left `gcc.exe` spinning forever; the `hung` check keeps that.
        require fileExists(child)
        let outcome = runBorrowedCalls(child, "", borrows = 1,
          callee = "Sleep", arg = cast[pointer](3000), timeoutMs = 500'u32)
        checkpoint("fixture runs with a user shadow stack: " &
          $outcome.shadowStack)
        checkpoint("child exit code: 0x" & outcome.exitCode.int64.toHex(8) &
          " (0xC00000B5 = InjectionAbandonedExitCode)")
        check outcome.parked
        check outcome.calls == @[false]
        check not outcome.hung
        check outcome.exitCode == InjectionAbandonedExitCode

      test "a borrowed LoadLibraryW maps a real DLL and the child exits 0":
        ## What injection actually borrows the thread for. Unlike the two
        ## leaf callees above, the loader runs SSE code on its stack, so this
        ## is also the case that pins the Win64 call-site alignment the stub
        ## establishes (RSP 16-byte aligned at the `call`): measured, a stub
        ## that is 8 bytes off passes both cases above and kills the child
        ## here. `dbghelp.dll` is a System32 DLL the fixture does not import.
        require fileExists(child)
        let outcome = runBorrowedCalls(child, "", borrows = 1,
          callee = "LoadLibraryW",
          childString = getEnv("SystemRoot", r"C:\Windows") / "System32" /
            "dbghelp.dll")
        checkpoint("fixture runs with a user shadow stack: " &
          $outcome.shadowStack)
        checkpoint("child exit code: 0x" & outcome.exitCode.int64.toHex(8))
        check outcome.parked
        check outcome.calls == @[true]
        # LoadLibraryW's HMODULE came back through RAX: nonzero means mapped.
        check outcome.answers.len == 1 and outcome.answers[0] != 0
        check not outcome.hung
        check outcome.exitCode == 0

  runCetSuite()
