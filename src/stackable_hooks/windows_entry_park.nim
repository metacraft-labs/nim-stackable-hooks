## Park a ``CREATE_SUSPENDED`` child at its image entry point so that the
## Windows loader initialises the process ON ITS OWN MAIN THREAD.
##
## WHY THIS EXISTS
## ---------------
## The Windows loader initialises a process on whichever thread reaches
## ``LdrInitializeThunk`` first. A ``CreateRemoteThread`` fired into a
## never-run ``CREATE_SUSPENDED`` child therefore runs
## ``LdrpInitializeProcess`` -- every static import's
## ``DLL_PROCESS_ATTACH``, ``msys-2.0.dll``'s included -- ON THAT REMOTE
## THREAD, which then exits. The MSYS2/Cygwin runtime is left bound to a
## dead thread and the shell wedges at its first ``fork()``: six threads in
## ``Wait``, no CPU, and no forked grandchild in the process tree.
##
## This is NOT the ``msys-2.0.dll`` base-address collision class described
## in ``codetracer-specs/Architecture/Hooking-Cygwin-Binaries-On-Windows.md``
## and rebasing does not help it. The decisive measurement: a
## ``CreateRemoteThread`` calling ``kernel32!GetCurrentProcessId`` -- no
## DLL, no section, nothing mapped -- hangs the same way, and so does
## ``LoadLibraryW`` of an already-mapped ``kernel32.dll``. There is no
## section to collide with in either case. The variable is the THREAD.
##
## THE SEQUENCE
## ------------
## 1. Read the child's image entry point out of its PEB.
## 2. Patch the entry with ``EB FE`` (``jmp $``, a two-byte self-jump).
## 3. ``ResumeThread``. The loader now runs ``LdrpInitializeProcess`` on the
##    MAIN thread -- which is what the Cygwin runtime requires -- and then
##    jumps to the entry point and spins there. No user code has run.
## 4. Poll ``GetThreadContext`` until the instruction pointer equals the
##    entry point. That is the proof the loader finished AND released the
##    loader lock. Measured at 1-2 ms on this host.
## 5. ``SuspendThread``. The child is now parked, fully initialised, with a
##    suspend count of exactly one -- byte-identical bookkeeping to what
##    ``CREATE_SUSPENDED`` left behind, so the caller's own
##    ``ResumeThread`` still drives the wakeup and nothing double-resumes.
## 6. The caller injects, then calls ``releaseEntryPark``, which restores
##    the two original bytes and leaves the thread suspended.
##
## REJECTED ALTERNATIVES, both measured on the same fork-heavy script
## ------------------------------------------------------------------
## * Injecting at the initial debug breakpoint
##   (``DEBUG_ONLY_THIS_PROCESS``). Looks right -- the breakpoint is
##   delivered after ``LdrpInitializeProcess`` ran on the main thread and
##   before the entry point -- but the debug port holds the loader lock
##   across the event. Hangs 5/5.
## * ``ResumeThread`` followed by a fixed ``Sleep`` and a post-hoc
##   injection. 0 ms hangs and >=1 ms passes, which makes it a race, not a
##   fix: nothing establishes that the runtime finished initialising.
##
## WHEN THE PARK IS UNSOUND
## ------------------------
## The park RUNS THE CHILD'S LOADER. A caller that asked for
## ``CREATE_SUSPENDED`` is entitled to a child that has executed nothing --
## Cygwin's own ``fork()`` depends on exactly that to copy the parent's
## address space in before the child runs. Callers must therefore not park
## a child whose suspension the caller themselves requested. See
## ``propagation_windows.autoPropagateCreateProcessW``, which decides this
## from the original creation flags.
##
## PORTABILITY
## -----------
## The self-jump encoding is x86. On Windows/ARM64 the park reports
## ``epsUnsupported`` and the caller keeps the legacy technique. A 32-bit
## host cannot address a 64-bit child's PEB or thread context either, so
## that combination reports ``epsUnsupported`` too; it is already handled
## by the 64-bit inject helper.

when not defined(windows):
  {.error: "stackable_hooks/windows_entry_park is Windows-only".}

{.push raises: [].}

type
  EntryParkStatus* = enum
    ## Outcome of ``parkChildAtEntryPoint``. The two failure modes are
    ## deliberately distinct because they leave the child in completely
    ## different states, and a caller must treat them differently.
    epsUnsupported
      ## This host/child combination cannot be parked (ARM64 host, or a
      ## 32-bit host looking at a 64-bit child). The child was NEVER
      ## RESUMED and has executed nothing.
    epsSetupFailed
      ## The PEB read or the entry-point patch failed. The child was NEVER
      ## RESUMED and has executed nothing -- it is still exactly as
      ## ``CreateProcessW`` left it, so falling back to the legacy
      ## pre-loader remote thread is sound for a native child.
    epsTimedOut
      ## The child WAS RESUMED and never reached its entry point. Its
      ## state is unknown: it may be wedged in the loader. The entry bytes
      ## have been restored and the thread re-suspended, but a caller must
      ## NOT inject after this -- that is the racy post-resume technique.
    epsParked
      ## The child is suspended at its patched entry point, fully
      ## initialised, loader lock free. The caller owns the park and must
      ## call ``releaseEntryPark``.

  EntryPark* = object
    ## Handle on a parked child. Zero-initialises to ``epsUnsupported``,
    ## so a default-constructed value is safe to test and safe to release.
    status*: EntryParkStatus
    entry*: pointer
    hProcess: pointer
    origBytes: array[2, byte]
    oldProtect: uint32

when defined(i386) or defined(amd64):

  type
    NtStatus = int32
    ProcessBasicInformation {.bycopy.} = object
      exitStatus: NtStatus
      pebBaseAddress: pointer
      affinityMask: uint
      basePriority: int32
      uniqueProcessId: uint
      inheritedFromUniqueProcessId: uint

  const
    # PEB.ImageBaseAddress. Which PEB `NtQueryInformationProcess` reports
    # follows the CALLER's bitness: a 64-bit caller always gets the 64-bit
    # PEB (even for a WOW64 target, whose 64-bit PEB still carries the
    # 32-bit image's base), a WOW64 caller gets the thunked 32-bit PEB.
    PebImageBaseOffset = when sizeof(pointer) == 8: 0x10'u else: 0x08'u

    # PE: e_lfanew at 0x3C; from the NT signature, Signature(4) +
    # IMAGE_FILE_HEADER(20) = 0x18 reaches the optional header, and
    # AddressOfEntryPoint sits 0x10 into it. Identical for PE32 and PE32+.
    DosLfanewOffset = 0x3C'u
    NtSignature = 0x00004550'u32          # "PE\0\0"
    EntryPointOffset = 0x28'u

    # CONTEXT_AMD64 | CONTEXT_CONTROL, and the field offsets we read. We
    # address the structure by offset rather than transcribing 1232 bytes
    # of register file that we never touch.
    ContextAmd64Control = 0x00100001'u32
    ContextAmd64Size = 1232
    ContextAmd64FlagsOffset = 0x30'u
    ContextAmd64RipOffset = 0xF8'u

    # CONTEXT_i386 | CONTEXT_CONTROL. WOW64_CONTEXT has the same layout.
    ContextI386Control = 0x00010001'u32
    ContextI386Size = 716
    ContextI386FlagsOffset = 0x00'u
    ContextI386EipOffset = 0xB8'u

    StillActive = 259'u32
    PageExecuteReadWrite = 0x40'u32
    SelfJump: array[2, byte] = [0xEB'u8, 0xFE'u8]

  proc NtQueryInformationProcess(hProcess: pointer; infoClass: uint32;
                                 info: pointer; infoLen: uint32;
                                 returnLen: ptr uint32): NtStatus
    {.importc, stdcall, dynlib: "ntdll".}
  proc ReadProcessMemory(hProcess: pointer; base: pointer; buf: pointer;
                         size: uint; read: ptr uint): int32
    {.importc, stdcall, dynlib: "kernel32".}
  proc WriteProcessMemory(hProcess: pointer; base: pointer; buf: pointer;
                          size: uint; written: ptr uint): int32
    {.importc, stdcall, dynlib: "kernel32".}
  proc VirtualProtectEx(hProcess: pointer; address: pointer; size: uint;
                        newProtect: uint32; oldProtect: ptr uint32): int32
    {.importc, stdcall, dynlib: "kernel32".}
  proc FlushInstructionCache(hProcess: pointer; base: pointer;
                             size: uint): int32
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetThreadContext(hThread: pointer; ctx: pointer): int32
    {.importc, stdcall, dynlib: "kernel32".}
  proc ResumeThread(hThread: pointer): uint32
    {.importc, stdcall, dynlib: "kernel32".}
  proc SuspendThread(hThread: pointer): uint32
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetExitCodeProcess(hProcess: pointer; code: ptr uint32): int32
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetTickCount64(): uint64
    {.importc, stdcall, dynlib: "kernel32".}
  proc SleepMs(ms: uint32)
    {.importc: "Sleep", stdcall, dynlib: "kernel32".}

  when sizeof(pointer) == 8:
    # Only exists on 64-bit Windows. Declaring it on a 32-bit build would
    # make Nim's dynlib loader abort at module init.
    proc Wow64GetThreadContext(hThread: pointer; ctx: pointer): int32
      {.importc, stdcall, dynlib: "kernel32".}

  proc alignUp16(p: pointer): pointer {.inline.} =
    ## GetThreadContext requires a 16-byte-aligned CONTEXT on x64 (it
    ## carries M128A fields); a misaligned one fails with ERROR_NOACCESS.
    ## Over-allocating and rounding up needs no alignment pragma.
    cast[pointer]((cast[uint](p) + 15'u) and not 15'u)

  proc childImageEntryPoint(hProcess: pointer; entry: var pointer): bool =
    ## Resolve the child's ``AddressOfEntryPoint`` through its PEB. Every
    ## step is validated: a plausible-looking wrong address here would put
    ## a two-byte self-jump somewhere arbitrary in the child.
    var pbi: ProcessBasicInformation
    var retLen: uint32 = 0
    if NtQueryInformationProcess(hProcess, 0'u32, addr pbi,
        uint32(sizeof(pbi)), addr retLen) != 0:
      return false
    if pbi.pebBaseAddress == nil:
      return false
    var got: uint = 0
    var imageBase: pointer = nil
    if ReadProcessMemory(hProcess,
        cast[pointer](cast[uint](pbi.pebBaseAddress) + PebImageBaseOffset),
        addr imageBase, uint(sizeof(pointer)), addr got) == 0 or
        imageBase == nil:
      return false
    var lfanew: int32 = 0
    if ReadProcessMemory(hProcess,
        cast[pointer](cast[uint](imageBase) + DosLfanewOffset),
        addr lfanew, 4'u, addr got) == 0:
      return false
    if lfanew <= 0 or lfanew > 0x1000:
      return false
    var signature: uint32 = 0
    if ReadProcessMemory(hProcess,
        cast[pointer](cast[uint](imageBase) + uint(lfanew)),
        addr signature, 4'u, addr got) == 0 or signature != NtSignature:
      return false
    var entryRva: uint32 = 0
    if ReadProcessMemory(hProcess,
        cast[pointer](cast[uint](imageBase) + uint(lfanew) + EntryPointOffset),
        addr entryRva, 4'u, addr got) == 0 or entryRva == 0:
      return false
    entry = cast[pointer](cast[uint](imageBase) + uint(entryRva))
    true

  proc instructionPointer(hThread: pointer; childIsWow64: bool;
                          ip: var uint64): bool =
    ## Read the thread's IP. A 64-bit caller looking at a WOW64 thread must
    ## use ``Wow64GetThreadContext``: plain ``GetThreadContext`` would
    ## report the 64-bit RIP inside ``wow64cpu``, never the 32-bit EIP we
    ## are comparing against.
    when sizeof(pointer) == 8:
      if childIsWow64:
        var raw: array[ContextI386Size + 16, byte]
        let ctx = alignUp16(addr raw[0])
        cast[ptr uint32](cast[uint](ctx) + ContextI386FlagsOffset)[] =
          ContextI386Control
        if Wow64GetThreadContext(hThread, ctx) == 0:
          return false
        ip = uint64(cast[ptr uint32](cast[uint](ctx) + ContextI386EipOffset)[])
        return true
      var raw: array[ContextAmd64Size + 16, byte]
      let ctx = alignUp16(addr raw[0])
      cast[ptr uint32](cast[uint](ctx) + ContextAmd64FlagsOffset)[] =
        ContextAmd64Control
      if GetThreadContext(hThread, ctx) == 0:
        return false
      ip = cast[ptr uint64](cast[uint](ctx) + ContextAmd64RipOffset)[]
      true
    else:
      # A 32-bit host only ever parks a WOW64 child; the 64-bit case is
      # refused in `parkChildAtEntryPoint` before we get here.
      var raw: array[ContextI386Size + 16, byte]
      let ctx = alignUp16(addr raw[0])
      cast[ptr uint32](cast[uint](ctx) + ContextI386FlagsOffset)[] =
        ContextI386Control
      if GetThreadContext(hThread, ctx) == 0:
        return false
      ip = uint64(cast[ptr uint32](cast[uint](ctx) + ContextI386EipOffset)[])
      true

  proc restoreEntryBytes(park: var EntryPark): bool =
    var written: uint = 0
    var prot: uint32 = 0
    let ok = WriteProcessMemory(park.hProcess, park.entry,
      addr park.origBytes[0], 2'u, addr written) != 0
    discard VirtualProtectEx(park.hProcess, park.entry, 2'u,
      park.oldProtect, addr prot)
    discard FlushInstructionCache(park.hProcess, park.entry, 2'u)
    ok

  proc parkChildAtEntryPoint*(hProcess, hThread: pointer;
                              childIsWow64: bool;
                              timeoutMs: uint32): EntryPark =
    ## Park ``hThread`` (the child's main thread, still carrying the
    ## ``CREATE_SUSPENDED`` count of one) at the child's image entry point.
    ##
    ## On ``epsParked`` the thread is suspended exactly once, so the park
    ## is suspend-count neutral and the caller's own ``ResumeThread``
    ## still owns the wakeup. On every other status the child needs no
    ## cleanup from the caller: this proc restores whatever it changed.
    result.status = epsUnsupported
    result.hProcess = hProcess
    if hProcess == nil or hThread == nil or timeoutMs == 0:
      return
    when sizeof(pointer) == 4:
      # A WOW64 caller can neither read a 64-bit PEB nor a 64-bit thread
      # context. `windows_injector.runInject64Helper` covers that case.
      if not childIsWow64:
        return

    var entry: pointer = nil
    if not childImageEntryPoint(hProcess, entry):
      result.status = epsSetupFailed
      return
    result.entry = entry

    var got: uint = 0
    if ReadProcessMemory(hProcess, entry, addr result.origBytes[0], 2'u,
        addr got) == 0 or got != 2:
      result.status = epsSetupFailed
      return
    if VirtualProtectEx(hProcess, entry, 2'u, PageExecuteReadWrite,
        addr result.oldProtect) == 0:
      result.status = epsSetupFailed
      return
    var written: uint = 0
    var selfJump = SelfJump
    if WriteProcessMemory(hProcess, entry, addr selfJump[0], 2'u,
        addr written) == 0 or written != 2:
      var prot: uint32 = 0
      discard VirtualProtectEx(hProcess, entry, 2'u, result.oldProtect,
        addr prot)
      result.status = epsSetupFailed
      return
    discard FlushInstructionCache(hProcess, entry, 2'u)

    # From here the child HAS BEEN RESUMED and no failure path may leave
    # the patched bytes behind.
    if ResumeThread(hThread) == high(uint32):
      discard restoreEntryBytes(result)
      result.status = epsSetupFailed
      return

    let deadline = GetTickCount64() + uint64(timeoutMs)
    let wantIp = uint64(cast[uint](entry))
    while true:
      var ip: uint64 = 0
      if instructionPointer(hThread, childIsWow64, ip) and ip == wantIp:
        discard SuspendThread(hThread)
        # Re-read after the suspend: the sample above was taken while the
        # thread was running, so only a post-suspend confirmation proves
        # the thread is actually stopped ON the self-jump.
        var confirmed: uint64 = 0
        if instructionPointer(hThread, childIsWow64, confirmed) and
            confirmed == wantIp:
          result.status = epsParked
          return
        discard ResumeThread(hThread)
      var exitCode: uint32 = 0
      if GetExitCodeProcess(hProcess, addr exitCode) != 0 and
          exitCode != StillActive:
        # The child died before reaching its entry point -- a missing
        # dependency, typically. Nothing to restore into a dead process.
        result.status = epsTimedOut
        return
      if GetTickCount64() >= deadline:
        break
      SleepMs(1'u32)

    discard SuspendThread(hThread)
    discard restoreEntryBytes(result)
    result.status = epsTimedOut

  proc releaseEntryPark*(park: var EntryPark): bool
      {.discardable.} =
    ## Restore the entry point and leave the thread SUSPENDED. Resuming is
    ## deliberately not done here: the park is suspend-count neutral, so
    ## the caller's existing ``ResumeThread`` -- the one that already
    ## decides whether the caller asked for a suspended child -- remains
    ## the single wakeup.
    if park.status != epsParked:
      return true
    result = restoreEntryBytes(park)
    park.status = epsSetupFailed

else:
  # Windows/ARM64: `EB FE` is not an instruction here and this repo has no
  # measured ARM64 equivalent. Report unsupported so callers keep the
  # legacy technique rather than patch two arbitrary bytes into the image.
  proc parkChildAtEntryPoint*(hProcess, hThread: pointer;
                              childIsWow64: bool;
                              timeoutMs: uint32): EntryPark =
    result.status = epsUnsupported

  proc releaseEntryPark*(park: var EntryPark): bool {.discardable.} =
    true

{.pop.}
