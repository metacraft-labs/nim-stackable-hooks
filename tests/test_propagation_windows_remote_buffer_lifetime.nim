## Regression test: the injected ``LoadLibraryW`` thread's remote buffer
## MUST outlive a wait that timed out.
##
## THE BUG THIS PINS
## -----------------
## ``injectShimIntoChild`` allocates ``remoteBuf`` in the CHILD's address
## space, writes the library path into it, and hands that pointer to a
## ``CreateRemoteThread(kernel32!LoadLibraryW, remoteBuf)``. The original
## code guarded the allocation with an unconditional
##
##     defer: discard VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE)
##
## which fires on EVERY exit path — including the ``ioWaitTimeout`` path,
## where ``WaitForSingleObject`` gave up after ``waitDeadlineMs`` while the
## remote thread was still running and still dereferencing the pointer.
## The free then unmapped a 64 KB reservation out from under a live remote
## thread, and the child died with ``STATUS_ACCESS_VIOLATION``
## (``0xC0000005``) inside ntdll's AVX2 zero-scan (``vpcmpeqb ymm1,ymm2,
## [rdx]``) over the path string. It only ever hit GRANDchildren, because
## the ROOT injector (``windows_injector.nim``) waits ``INFINITE`` and so
## always regains ownership of the buffer before freeing it.
##
## SHAPE OF THE TEST — the timeout arm is RACED FOR, not assumed
## -------------------------------------------------------------
## Reaching ``ioWaitTimeout`` means losing a race against the injected
## remote thread, and nothing here can make the OS lose that race on
## demand. A short deadline is NOT deterministic: with
## ``waitDeadlineMs = 1`` the remote ``LoadLibraryW`` on a non-existent
## path finishes inside the wait roughly half the time on a warm machine
## (measured), so a single-shot probe reports ``ioInjected`` and pins
## nothing. The honest shape is therefore:
##
##   * poll (``waitDeadlineMs = 0``), which loses the race almost always
##     but is still only *almost*; and
##   * RETRY, up to ``MaxTimeoutAttempts``, until a probe actually comes
##     back ``ioWaitTimeout`` — and FAIL if none ever does, so a build
##     where the arm became unreachable is reported rather than skipped.
##
## The assertion is unchanged and is made only on a probe that genuinely
## timed out:
##
##   1. the child-side region holding the library path is STILL COMMITTED
##      after ``ioWaitTimeout`` came back (``VirtualQueryEx`` reports
##      ``MEM_COMMIT``). Before the fix the region is ``MEM_FREE`` and the
##      path bytes are gone, so the region is not found at all.
##   2. the child does not exit with ``0xC0000005``.
##
## The second test pins the OPPOSITE direction, because "leak on timeout"
## has an obvious wrong over-correction — never freeing at all. A probe
## given a generous deadline reaches ``WAIT_OBJECT_0`` deterministically
## (``LoadLibraryW`` on a missing file fails and returns promptly), and
## the region MUST be gone afterwards.
##
## The library path used is a UNIQUE, NON-EXISTENT path, for two reasons:
## the loader never gets far enough to map anything (so no second copy of
## the string can appear in the child's loader structures and fake out the
## region search), and the fault reproduced by the original bug happens in
## the zero-scan over the string, strictly BEFORE any file is touched.

when not defined(windows):
  echo "[skip] propagation_windows_remote_buffer_lifetime is Windows-only"
  quit(0)

import std/[os, random, strutils, times, unittest]

import stackable_hooks/propagation_windows

type
  HANDLE = pointer
  DWORD = uint32
  BOOL = int32
  LPCWSTR = ptr uint16
  LPWSTR = ptr uint16
  SIZE_T = uint

  STARTUPINFOW {.bycopy.} = object
    cb: DWORD
    lpReserved: LPWSTR
    lpDesktop: LPWSTR
    lpTitle: LPWSTR
    dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars: DWORD
    dwFillAttribute, dwFlags: DWORD
    wShowWindow, cbReserved2: uint16
    lpReserved2: ptr byte
    hStdInput, hStdOutput, hStdError: HANDLE

  PROCESS_INFORMATION {.bycopy.} = object
    hProcess, hThread: HANDLE
    dwProcessId, dwThreadId: DWORD

  MEMORY_BASIC_INFORMATION {.bycopy.} = object
    BaseAddress: pointer
    AllocationBase: pointer
    AllocationProtect: DWORD
    PartitionId: uint16
    alignPad: uint16
    RegionSize: SIZE_T
    State: DWORD
    Protect: DWORD
    Type: DWORD

const
  CREATE_SUSPENDED = 0x00000004'u32
  MEM_COMMIT = 0x00001000'u32
  MEM_PRIVATE = 0x00020000'u32
  PAGE_READWRITE = 0x04'u32
  WAIT_OBJECT_0 = 0x0'u32
  STATUS_ACCESS_VIOLATION = 0xC0000005'u32
  ChildExitCode = 7'u32
  ## How many polls to spend trying to lose the race against the remote
  ## thread. A poll loses it in the overwhelming majority of attempts, so
  ## this is slack, not an expectation — but it is bounded and a run that
  ## exhausts it FAILS.
  MaxTimeoutAttempts = 40
  ## Comfortably longer than a ``LoadLibraryW`` that fails on a missing
  ## file; the success-direction probe must reach ``WAIT_OBJECT_0``.
  SuccessDeadlineMs = 10_000'u32

proc CreateProcessW(lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
                    lpProcessAttributes, lpThreadAttributes: pointer,
                    bInheritHandles: BOOL, dwCreationFlags: DWORD,
                    lpEnvironment: pointer, lpCurrentDirectory: LPCWSTR,
                    lpStartupInfo: pointer,
                    lpProcessInformation: ptr PROCESS_INFORMATION): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc VirtualQueryEx(hProcess: HANDLE, lpAddress: pointer,
                    lpBuffer: ptr MEMORY_BASIC_INFORMATION,
                    dwLength: SIZE_T): SIZE_T
  {.importc, stdcall, dynlib: "kernel32".}
proc ReadProcessMemory(hProcess: HANDLE, lpBaseAddress: pointer,
                       lpBuffer: pointer, nSize: SIZE_T,
                       lpNumberOfBytesRead: ptr SIZE_T): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc ResumeThread(hThread: HANDLE): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc GetExitCodeProcess(hProcess: HANDLE, lpExitCode: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc TerminateProcess(hProcess: HANDLE, uExitCode: DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc CloseHandle(hObject: HANDLE): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetLastError(): DWORD
  {.importc, stdcall, dynlib: "kernel32".}

proc toWide(s: string): seq[uint16] =
  ## Same straight ASCII widen the injector itself uses, so the bytes we
  ## search the child for are byte-identical to the bytes it wrote.
  result.setLen(s.len + 1)
  for i, c in s:
    result[i] = uint16(c)
  result[s.len] = 0'u16

proc regionHoldingPathAtBase(hProcess: HANDLE; wpath: seq[uint16]):
    tuple[found: bool; address: pointer] =
  ## Walk the child's address space for the injector's allocation: a
  ## PRIVATE, committed, read-write region that BEGINS at its own
  ## allocation base and whose first bytes are exactly the wide library
  ## path (including the terminating NUL). ``VirtualAllocEx(nil, …)``
  ## produces exactly that shape; a heap block or loader string never
  ## does, so the match cannot be faked by an unrelated copy of the path.
  let needle = cast[ptr UncheckedArray[byte]](unsafeAddr wpath[0])
  let needleLen = wpath.len * sizeof(uint16)
  var address: uint = 0
  var mbi: MEMORY_BASIC_INFORMATION
  while VirtualQueryEx(hProcess, cast[pointer](address), addr mbi,
      SIZE_T(sizeof(mbi))) == SIZE_T(sizeof(mbi)):
    let regionBase = cast[uint](mbi.BaseAddress)
    let regionSize = uint(mbi.RegionSize)
    if regionSize == 0:
      break
    if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE and
        mbi.Protect == PAGE_READWRITE and
        mbi.BaseAddress == mbi.AllocationBase and
        regionSize >= uint(needleLen):
      var buf = newSeq[byte](needleLen)
      var got: SIZE_T = 0
      if ReadProcessMemory(hProcess, mbi.BaseAddress, addr buf[0],
          SIZE_T(needleLen), addr got) != 0 and int(got) == needleLen:
        var same = true
        for i in 0 ..< needleLen:
          if buf[i] != needle[i]:
            same = false
            break
        if same:
          return (true, mbi.BaseAddress)
    let next = regionBase + regionSize
    if next <= address:
      break
    address = next
  (false, nil)

proc regionState(hProcess: HANDLE; address: pointer): DWORD =
  var mbi: MEMORY_BASIC_INFORMATION
  if VirtualQueryEx(hProcess, address, addr mbi,
      SIZE_T(sizeof(mbi))) != SIZE_T(sizeof(mbi)):
    return 0
  mbi.State

type
  TimeoutProbe = object
    ## Everything one injection told us about its child. Gathered in a
    ## plain proc (``unittest`` forbids ``return`` inside a ``test`` body)
    ## and asserted on afterwards.
    spawned*: bool
    spawnError*: DWORD
    outcome*: InjectionOutcome
    bufferFound*: bool
    bufferState*: DWORD
    exitedCleanly*: bool
    exitCode*: DWORD

proc probeInjection(libraryPath: string; deadlineMs: DWORD): TimeoutProbe =
  let system32 = getEnv("SystemRoot", r"C:\Windows") & r"\System32"
  let cmdExe = system32 & r"\cmd.exe"
  var cmdLine = toWide(cmdExe & " /c exit " & $ChildExitCode)
  var si: STARTUPINFOW
  si.cb = DWORD(sizeof(si))
  var pi: PROCESS_INFORMATION
  if CreateProcessW(nil, cast[LPWSTR](addr cmdLine[0]),
      nil, nil, BOOL(0), CREATE_SUSPENDED, nil, nil,
      cast[pointer](addr si), addr pi) == 0:
    result.spawnError = GetLastError()
    return
  result.spawned = true

  var childReaped = false
  defer:
    if not childReaped:
      discard TerminateProcess(pi.hProcess, 1'u32)
    discard CloseHandle(pi.hThread)
    discard CloseHandle(pi.hProcess)

  let cfg = InjectionConfig(maxInFlight: 16,
                            waitDeadlineMs: deadlineMs,
                            skipIfImageHasShim: false)
  result.outcome = injectShimIntoChild(pi.hProcess, libraryPath, "", cfg)

  # Whether the injector's child-side allocation is still mapped. On the
  # timeout arm the remote thread may still be reading the path string, so
  # it MUST be; on the WAIT_OBJECT_0 arm the thread has provably finished
  # with it and it must be gone.
  let region = regionHoldingPathAtBase(pi.hProcess, toWide(libraryPath))
  result.bufferFound = region.found
  if region.found:
    result.bufferState = regionState(pi.hProcess, region.address)

  # …and therefore the child must not be killed by the unmap.
  discard ResumeThread(pi.hThread)
  if WaitForSingleObject(pi.hProcess, 60_000'u32) == WAIT_OBJECT_0:
    childReaped = true
    result.exitedCleanly = true
    var exitCode: DWORD = 0
    discard GetExitCodeProcess(pi.hProcess, addr exitCode)
    result.exitCode = exitCode

proc uniqueMissingLibraryPath(tag: string): string =
  ## A unique, deliberately NON-EXISTENT library path. See the module
  ## docstring: nothing is ever mapped, so the only copy of these bytes in
  ## the child is the injector's own remote allocation.
  var rng = initRand(int(epochTime() * 1000.0) xor getCurrentProcessId())
  r"C:\io-mon-uaf-probe-" & tag & "-" & $getCurrentProcessId() & "-" &
    $rng.rand(high(int32)) & r"\probe.dll"

suite "propagation_windows remote-buffer lifetime (cross-process UAF)":

  test "ioWaitTimeout leaves the remote path buffer mapped; child survives":
    let libraryPath = uniqueMissingLibraryPath("timeout")
    check not fileExists(libraryPath)

    # Poll and RETRY until the injector actually loses the race. See the
    # module docstring: no deadline makes the timeout arm deterministic,
    # so the arm is raced for and its absence is a failure, not a skip.
    var probe: TimeoutProbe
    var attempts = 0
    var outcomes: seq[string] = @[]
    while attempts < MaxTimeoutAttempts:
      inc attempts
      probe = probeInjection(libraryPath, 0'u32)
      outcomes.add $probe.outcome
      if not probe.spawned or probe.outcome == ioWaitTimeout:
        break
    checkpoint("attempts = " & $attempts & " outcomes = " &
      outcomes.join(","))
    checkpoint("spawn ok=" & $probe.spawned & " err=" & $probe.spawnError)
    check probe.spawned

    check probe.outcome == ioWaitTimeout

    checkpoint("remote path buffer found = " & $probe.bufferFound &
      " state = 0x" & toHex(probe.bufferState))
    check probe.bufferFound
    check probe.bufferState == MEM_COMMIT

    checkpoint("child exit code = 0x" & toHex(probe.exitCode))
    check probe.exitedCleanly
    check probe.exitCode != STATUS_ACCESS_VIOLATION
    check probe.exitCode == ChildExitCode

  test "a completed LoadLibraryW frees the remote buffer (no over-correction)":
    # The inverse of the fix: "leak on timeout" must not become "never
    # free". WAIT_OBJECT_0 is proof the remote thread is done with the
    # path string, so the region must be gone by the time we look.
    let libraryPath = uniqueMissingLibraryPath("success")
    check not fileExists(libraryPath)

    let probe = probeInjection(libraryPath, SuccessDeadlineMs)
    checkpoint("spawn ok=" & $probe.spawned & " err=" & $probe.spawnError)
    check probe.spawned

    checkpoint("injectShimIntoChild outcome = " & $probe.outcome)
    check probe.outcome == ioInjected

    checkpoint("remote path buffer found = " & $probe.bufferFound &
      " state = 0x" & toHex(probe.bufferState))
    check not probe.bufferFound

    checkpoint("child exit code = 0x" & toHex(probe.exitCode))
    check probe.exitedCleanly
    check probe.exitCode == ChildExitCode
