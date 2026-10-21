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
    epsLentOut
      ## A borrowed call (``borrowParkedThread``) missed its deadline. The
      ## thread is SUSPENDED with its context STILL LENT OUT, plus one EXTRA
      ## suspend so a caller's reflexive ``ResumeThread`` cannot run it, and
      ## the entry bytes are left in place (``releaseEntryPark`` is a no-op in
      ## this state). The child's fate is the caller's to decide, through the
      ## ``TimedOutBorrow`` building blocks -- keep waiting, terminate or
      ## detach. The library itself does NOTHING further. See
      ## ``docs/windows-borrowed-call-deadline.md``.
    epsDetached
      ## ``detachBorrowedChild`` ran on a lent-out park: the entry bytes were
      ## restored and the thread released, so the child is now running its
      ## OWN code with no injector present. ``releaseEntryPark`` is a no-op
      ## and the caller owes no resume.
    epsAbandoned
      ## ``terminateBorrowedChild`` ran on a lent-out park (directly, or
      ## because a caller passed ``btpTerminate`` to the boolean
      ## ``callOnParkedThread``). The child HAS BEEN
      ## TERMINATED and its main thread carries an extra suspend count, so a
      ## caller's ``ResumeThread`` cannot run it. Nothing about this child may
      ## be used again. See ``docs/windows-borrowed-call-deadline.md``.

  EntryPark* = object
    ## Handle on a parked child. Zero-initialises to ``epsUnsupported``,
    ## so a default-constructed value is safe to test and safe to release.
    status*: EntryParkStatus
    entry*: pointer
    hProcess: pointer
    origBytes: array[2, byte]
    oldProtect: uint32

  BorrowedCallStatus* = enum
    ## Outcome of ``borrowParkedThread``. What matters is the state each one
    ## leaves the CHILD in, because that decides whether the caller may
    ## resume it. See ``docs/windows-borrowed-call-deadline.md``.
    bcsNotRun
      ## Refused, or failed before the thread executed anything borrowed.
      ## The thread is exactly as the park left it. Resuming the child is
      ## safe; it simply runs uninjected.
    bcsReturned
      ## ``fn`` returned to the self-jump, ``ret`` holds its ``RAX``, and the
      ## saved context has been restored byte for byte.
    bcsNoResult
      ## ``fn`` returned and the saved context has been restored, but its
      ## return value could not be read. The child is intact; the call's
      ## effect is unknown.
    bcsChildExited
      ## The child died while ``fn`` ran. Nothing to restore.
    bcsTimedOut
      ## The call did not come back within the deadline (or the saved context
      ## could not be restored after it did). The thread is SUSPENDED with its
      ## context STILL LENT OUT; the library has TERMINATED NOTHING. The
      ## ``timedOut`` field carries a ``TimedOutBorrow`` whose building blocks
      ## -- keep waiting, terminate, detach -- are the only ways to act on the
      ## lent-out thread. See ``docs/windows-borrowed-call-deadline.md``.

  BorrowedCall* = object
    status*: BorrowedCallStatus
    ret*: uint64
      ## ``RAX`` on ``bcsReturned``; zero otherwise.
    elapsedMs*: uint64
      ## How long the call ran in the child, measured from the resume.
    timedOut*: TimedOutBorrow
      ## Meaningful only on ``bcsTimedOut``: the handle onto the lent-out
      ## thread. Pass it to exactly one building block. On every other status
      ## it is a zero value whose ``usesStub`` is ``false``.

  TimedOutBorrow* = object
    ## A borrowed call that missed its deadline, caught mid-flight. The
    ## thread is suspended with its context lent out (``RSP`` below the parked
    ## frame, the stub executing ``fn``), plus one extra suspend so a reflexive
    ## ``ResumeThread`` from the caller leaves it frozen. The ONLY operations
    ## are ``keepWaitingForBorrow``, ``terminateBorrowedChild`` and
    ## ``detachBorrowedChild``; the fields are not exported, so ordinary code
    ## cannot build or edit one, and there is no resume entry point. (Like any
    ## Nim object, ``fieldPairs`` or a ``cast`` can still reach the fields;
    ## that is deliberate abuse, not an API path.) This is how "never resume
    ## a lent-out context without the stub" is made structural, not merely
    ## documented. Copies of a handle are not tracked: act on ONE copy.
    hThread: pointer
    childIsWow64: bool
    park: ptr EntryPark
      ## Borrow of the caller's park. A building block writes the park's final
      ## status back through it (``epsParked`` on a late return, ``epsAbandoned``
      ## on terminate, ``epsDetached`` on detach), so the caller's own
      ## ``releaseEntryPark`` and branching see the right state.
    stub: pointer
      ## The CET call stub in the child. ``detachBorrowedChild`` refuses when
      ## this is ``nil``; it is the stub's tail that restores ``RSP``/``RCX``,
      ## so detach is unsound without it.
    stubLen: uint
    savedCtx: array[1248, byte]
      ## The parked context (``ContextAmd64Size`` = 1232, plus 16 for 16-byte
      ## alignment), saved before the borrow, handed back verbatim if the call
      ## later returns under ``keepWaitingForBorrow``. Sized by literal because
      ## this type is compiled on every architecture, while ``ContextAmd64Size``
      ## lives in the amd64/i386 branch below.
    live: bool
      ## ``true`` until a building block consumes the handle, so a second
      ## building block on the same handle is a no-op rather than a
      ## double-free or double-terminate.
    entryRestored: bool
      ## A ``detachBorrowedChild`` restored the entry bytes but could not
      ## release the thread. ``keepWaitingForBorrow`` then refuses: with the
      ## self-jump gone the call would run on into the child's program.
    stubBacked: bool
      ## Read through ``usesStub``.
    lentMs: uint64
      ## Read through ``elapsedMs``.

  DetachOutcome* = enum
    ## Result of ``detachBorrowedChild``.
    doDetached
      ## The entry bytes were restored and the thread released; the child is
      ## running its own code with no injector present.
    doChildExited
      ## The child had already died by the time detach ran.
    doRefusedNoStub
      ## The handle carries no stub (``usesStub == false``), so restoring
      ## ``RSP``/``RCX`` by the stub's tail is not possible. Nothing was done;
      ## the thread is left frozen.
    doFailed
      ## Restoring the entry bytes or resuming the thread failed. The thread
      ## is left frozen; the caller should terminate instead.

  BorrowTimeoutPolicy* = enum
    ## What a borrowing ENTRY POINT does with a timed-out borrow, chosen by the
    ## caller -- never a silent library default. These are the two TERMINAL
    ## choices (what to do once you have decided to stop waiting); "keep
    ## waiting" is not here because at the entry-point level it is the deadline
    ## itself (a larger ``deadlineMs``/``parkTimeoutMs``, up to
    ## ``InfiniteDeadline``), and for a caller that borrows directly it is the
    ## ``keepWaitingForBorrow`` building block. See
    ## ``docs/windows-borrowed-call-deadline.md``.
    btpTerminate
      ## Apply ``terminateBorrowedChild``: the child dies with
      ## ``InjectionAbandonedExitCode``. The tool must then report the loss
      ## (fail the spawn, raise, or record it).
    btpDetach
      ## Apply ``detachBorrowedChild``: the child reaches its real entry point
      ## with no injector present. Its monitoring is then UNKNOWN, not merely
      ## absent: the borrowed call runs to completion on its own, so a
      ## detached shim load leaves the shim mapped but never initialised,
      ## while a detached init goes on to install all, some or none of its
      ## hooks. The loss MUST be reported through the entry point's own
      ## channel (an outcome, a ``skipReason``), never swallowed.
      ##
      ## If detach cannot be carried out (``doFailed``, ``doRefusedNoStub``)
      ## the thread is still frozen and lent out, and its only other safe exit
      ## is termination; ``applyBorrowTimeoutPolicy`` then terminates and says
      ## so (``atpTerminated``) rather than leave a child frozen forever.

  AppliedTimeoutPolicy* = enum
    ## What ``applyBorrowTimeoutPolicy`` actually did to the child.
    atpTerminated
      ## Terminated with ``InjectionAbandonedExitCode``: the policy was
      ## ``btpTerminate``, or it was ``btpDetach`` and detach was impossible.
    atpDetached
      ## Released into its own program (``doDetached``).
    atpChildExited
      ## The child had already died; nothing was done to it.

func usesStub*(b: TimedOutBorrow): bool {.inline.} =
  ## Whether this handle is backed by the CET call stub. Always ``true`` for
  ## a handle a real borrow produced. A getter, not a field, so a caller
  ## cannot flip it.
  b.stubBacked

func elapsedMs*(b: TimedOutBorrow): uint64 {.inline.} =
  ## How long the call had run when the deadline passed.
  b.lentMs

const
  InfiniteDeadline* = 0xFFFF_FFFF'u32
    ## Win32 ``INFINITE``. As a deadline: wait as long as the child lives.
  DefaultInjectDeadlineMs* = 600_000'u32
    ## Hard deadline for the park and for each borrowed call. It is a last
    ## resort for a genuinely wedged child, not a performance budget: a
    ## healthy child on an I/O-starved host has been measured taking far
    ## longer than the 5 s this used to be, and the old recovery turned
    ## that slow child into a corrupted one.
  SlowInjectionNoticeMs* = 5_000'u32
    ## The old deadline. Consumers use it as the threshold above which an
    ## injection is worth annotating as slow. It has no effect on outcome.
  InjectionAbandonedExitCode* = 0xC00000B5'u32
    ## ``STATUS_IO_TIMEOUT``. The exit code a poisoned child is terminated
    ## with, so a post-mortem can tell it from a crash.

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
    # CONTEXT_AMD64 | CONTROL | INTEGER | FLOATING_POINT. `callOnParkedThread`
    # saves and restores the whole register file, not just the three
    # registers it overwrites: the thread it borrows is the child's MAIN
    # thread, parked mid-loader-handoff, and handing it back with anything
    # but the state it arrived in would be a corruption we could not see.
    ContextAmd64Full = 0x0010000B'u32
    ContextAmd64Size = 1232
    ContextAmd64FlagsOffset = 0x30'u
    ContextAmd64RaxOffset = 0x78'u
    ContextAmd64RcxOffset = 0x80'u
    ContextAmd64RspOffset = 0x98'u
    ContextAmd64RipOffset = 0xF8'u

    # CONTEXT_i386 | CONTEXT_CONTROL. WOW64_CONTEXT has the same layout.
    ContextI386Control = 0x00010001'u32
    ContextI386Size = 716
    ContextI386FlagsOffset = 0x00'u
    ContextI386EipOffset = 0xB8'u

    StillActive = 259'u32
    PageExecuteReadWrite = 0x40'u32
    # For `callOnParkedThread`'s call stub: written read-write, then flipped
    # to execute-read before the thread is pointed at it.
    PageReadWrite = 0x04'u32
    PageExecuteRead = 0x20'u32
    MemCommit = 0x00001000'u32
    MemReserve = 0x00002000'u32
    MemRelease = 0x00008000'u32
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
  proc VirtualAllocEx(hProcess: pointer; address: pointer; size: uint;
                      allocType: uint32; protect: uint32): pointer
    {.importc, stdcall, dynlib: "kernel32".}
  proc VirtualFreeEx(hProcess: pointer; address: pointer; size: uint;
                     freeType: uint32): int32
    {.importc, stdcall, dynlib: "kernel32".}
  proc FlushInstructionCache(hProcess: pointer; base: pointer;
                             size: uint): int32
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetThreadContext(hThread: pointer; ctx: pointer): int32
    {.importc, stdcall, dynlib: "kernel32".}
  proc SetThreadContext(hThread: pointer; ctx: pointer): int32
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
  proc TerminateProcess(hProcess: pointer; exitCode: uint32): int32
    {.importc, stdcall, dynlib: "kernel32".}
  proc WaitForSingleObject(h: pointer; ms: uint32): uint32
    {.importc, stdcall, dynlib: "kernel32".}

  proc deadlinePassed(start: uint64; timeoutMs: uint32): bool {.inline.} =
    ## ``InfiniteDeadline`` never passes: the wait is then bounded only by
    ## the child staying alive.
    timeoutMs != InfiniteDeadline and
      GetTickCount64() - start >= uint64(timeoutMs)

  proc pollPause(start: uint64) {.inline.} =
    ## 1 ms while the answer is expected any moment (a park measures 1-2 ms
    ## on a healthy host), then 10 ms: a wait that has already lasted this
    ## long is a starved host, and spinning GetThreadContext against it
    ## helps nothing.
    SleepMs(if GetTickCount64() - start < 100'u64: 1'u32 else: 10'u32)

  proc childAlive(hProcess: pointer): bool =
    var exitCode: uint32 = 0
    not (GetExitCodeProcess(hProcess, addr exitCode) != 0 and
         exitCode != StillActive)

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
    # The entry park and borrowed-call stubs execute x86 instructions. A
    # native ARM64 image can share the parent's pointer width but cannot
    # execute the two-byte self-jump. Refuse it before changing child memory.
    var machine: uint16 = 0
    if ReadProcessMemory(hProcess,
        cast[pointer](cast[uint](imageBase) + uint(lfanew) + 4'u),
        addr machine, 2'u, addr got) == 0 or got != 2'u:
      return false
    if machine notin [0x8664'u16, 0x014c'u16]:
      # IMAGE_FILE_MACHINE_AMD64 / IMAGE_FILE_MACHINE_I386.
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

    # `timeoutMs` is a HARD deadline for a wedged loader, not a budget for
    # a slow one (R5 in docs/windows-borrowed-call-deadline.md). Missing it
    # is safe here -- the thread is suspended before it reaches user code
    # and the entry bytes are restored under that suspension -- but it
    # leaves the child unmonitored, so a slow child must not trip it.
    let start = GetTickCount64()
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
      if not childAlive(hProcess):
        # The child died before reaching its entry point -- a missing
        # dependency, typically. Nothing to restore into a dead process.
        result.status = epsTimedOut
        return
      if deadlinePassed(start, timeoutMs):
        break
      pollPause(start)

    discard SuspendThread(hThread)
    discard restoreEntryBytes(result)
    result.status = epsTimedOut

  type
    ParkWait = enum
      pwParked    ## back on the self-jump, suspended
      pwExited    ## the child died
      pwDeadline  ## the hard deadline passed; suspended wherever it was

  proc waitForParkedIp(park: var EntryPark; hThread: pointer;
                       childIsWow64: bool; timeoutMs: uint32): ParkWait =
    ## Poll until the thread is stopped ON the ``EB FE`` at the entry point.
    ## The proof is the same one ``parkChildAtEntryPoint`` waits for when it
    ## first parks the thread: the instruction pointer is back on the
    ## self-jump, confirmed AFTER the suspend, so the thread is stopped
    ## there rather than merely observed passing through. The park keeps its
    ## own copy of the loop because its failure path has to restore the
    ## patched bytes, which a borrowed call must NOT do -- the park is still
    ## live across the call.
    ##
    ## On ``pwDeadline`` the thread is left SUSPENDED where it is. It is
    ## mid-call, and resuming it into the child's own code is exactly the
    ## corruption this module must never cause; ``borrowParkedThread`` wraps
    ## it in a ``TimedOutBorrow`` and hands policy to the caller.
    let start = GetTickCount64()
    let wantIp = uint64(cast[uint](park.entry))
    while true:
      var ip: uint64 = 0
      if instructionPointer(hThread, childIsWow64, ip) and ip == wantIp:
        discard SuspendThread(hThread)
        var confirmed: uint64 = 0
        if instructionPointer(hThread, childIsWow64, confirmed) and
            confirmed == wantIp:
          return pwParked
        discard ResumeThread(hThread)
      if not childAlive(park.hProcess):
        return pwExited
      if deadlinePassed(start, timeoutMs):
        discard SuspendThread(hThread)
        # The call may have come back between the last sample and the
        # suspend. Then it is simply a success, and a slow one.
        var last: uint64 = 0
        if instructionPointer(hThread, childIsWow64, last) and
            last == wantIp:
          return pwParked
        if not childAlive(park.hProcess):
          return pwExited
        return pwDeadline
      pollPause(start)

  proc savedCtxPtr(b: var TimedOutBorrow): pointer {.inline.} =
    ## The 16-byte-aligned CONTEXT inside the handle's in-object buffer.
    alignUp16(addr b.savedCtx[0])

  proc lendOut(park: var EntryPark; hThread: pointer; childIsWow64: bool;
               saved: pointer; stub: pointer; stubLen: uint;
               elapsedMs: uint64): TimedOutBorrow =
    ## Build the handle for a borrow that missed its deadline. The thread is
    ## already suspended once by ``waitForParkedIp``; add ONE MORE suspend so a
    ## caller's reflexive ``ResumeThread`` leaves it frozen, and mark the park
    ## ``epsLentOut`` so ``releaseEntryPark`` will not strip the ``EB FE`` out
    ## from under the lent-out thread. The library does nothing else: the
    ## caller's chosen building block decides the child's fate.
    discard SuspendThread(hThread)
    park.status = epsLentOut
    result = TimedOutBorrow(hThread: hThread, childIsWow64: childIsWow64,
      park: addr park, stub: stub, stubLen: stubLen, live: true,
      stubBacked: stub != nil, lentMs: elapsedMs)
    copyMem(savedCtxPtr(result), saved, ContextAmd64Size)

  proc resumeFully(hThread: pointer): bool {.discardable.} =
    ## Drive the suspend count to zero so the thread actually runs. A lent-out
    ## thread carries the deadline suspend plus the extra ``lendOut`` suspend;
    ## ``ResumeThread`` returns the PREVIOUS count, and zero/``high`` means it
    ## is already running or the call failed, so the loop is bounded and safe.
    ## ``true`` only when the count was seen to reach zero: a failed
    ## ``ResumeThread`` leaves the thread frozen, and ``detachBorrowedChild``
    ## must not report a frozen thread as released.
    for _ in 0 ..< 8:
      let prev = ResumeThread(hThread)
      if prev == high(uint32):
        return false
      if prev <= 1'u32:
        return true
    false

  proc keepWaitingForBorrow*(b: var TimedOutBorrow;
                             additionalMs: uint32): BorrowedCall =
    ## BUILDING BLOCK: give a timed-out borrow more time. Resume the lent-out
    ## thread and wait up to ``additionalMs`` more for the borrowed call to
    ## return to the parked entry point. The thread is only ever run back to
    ## the controlled self-jump, never into the child's own program.
    ##
    ## On ``bcsReturned`` the saved context is handed back and the park is
    ## ``epsParked`` again -- identical to a prompt return, so the caller's
    ## usual ``releaseEntryPark`` + ``ResumeThread`` runs the child normally.
    ## A fresh ``bcsTimedOut`` carries a new handle; ``bcsChildExited`` means
    ## the child died while waiting.
    result = BorrowedCall(status: bcsNotRun)
    if not b.live or b.park == nil or b.entryRestored:
      return
    let started = GetTickCount64()
    resumeFully(b.hThread)
    let waited = waitForParkedIp(b.park[], b.hThread, b.childIsWow64,
      additionalMs)
    result.elapsedMs = b.lentMs + (GetTickCount64() - started)
    case waited
    of pwExited:
      b.live = false
      result.status = bcsChildExited
      return
    of pwDeadline:
      # Still lent out. Re-wrap: ``lendOut`` adds the extra suspend again and
      # keeps the park ``epsLentOut``.
      result.status = bcsTimedOut
      result.timedOut = lendOut(b.park[], b.hThread, b.childIsWow64,
        savedCtxPtr(b), b.stub, b.stubLen, result.elapsedMs)
      b.live = false
      return
    of pwParked:
      discard
    # Back on the parked entry point and suspended: hand the thread back.
    b.live = false
    var doneRaw: array[ContextAmd64Size + 16, byte]
    let done = alignUp16(addr doneRaw[0])
    cast[ptr uint32](cast[uint](done) + ContextAmd64FlagsOffset)[] =
      ContextAmd64Full
    let haveResult = GetThreadContext(b.hThread, done) != 0
    if SetThreadContext(b.hThread, savedCtxPtr(b)) == 0:
      # Cannot restore the parked context: the thread is parked on the
      # self-jump with a stack pointer that is not the loader's. Re-lend it so
      # the caller can still terminate or detach rather than resume a bad
      # context.
      result.status = bcsTimedOut
      result.timedOut = lendOut(b.park[], b.hThread, b.childIsWow64,
        savedCtxPtr(b), b.stub, b.stubLen, result.elapsedMs)
      return
    b.park[].status = epsParked
    # Back on the self-jump: nothing executes the stub any more, so its page
    # is freed exactly as a prompt return frees it.
    discard VirtualFreeEx(b.park[].hProcess, b.stub, 0'u, MemRelease)
    if haveResult:
      result.ret = cast[ptr uint64](cast[uint](done) + ContextAmd64RaxOffset)[]
      result.status = bcsReturned
    else:
      result.status = bcsNoResult

  proc terminateBorrowedChild*(b: var TimedOutBorrow;
      exitCode: uint32 = InjectionAbandonedExitCode) =
    ## BUILDING BLOCK: today's default. The thread is already carrying the
    ## extra ``lendOut`` suspend, so even if the termination below failed the
    ## caller's ``ResumeThread`` would still leave it frozen. Terminate the
    ## child and wait, so a caller that reports the spawn as failed is not
    ## racing a process that is still exiting. Marks the park ``epsAbandoned``.
    if not b.live or b.park == nil:
      return
    b.live = false
    discard SuspendThread(b.hThread)
    discard TerminateProcess(b.park[].hProcess, exitCode)
    discard WaitForSingleObject(b.park[].hProcess, 30_000'u32)
    b.park[].status = epsAbandoned

  proc detachBorrowedChild*(b: var TimedOutBorrow): DetachOutcome =
    ## BUILDING BLOCK: let the borrowed call finish on its own and get the
    ## child back to its REAL entry point with no injector present. Allowed
    ## only with the stub, whose tail restores ``RSP``/``RCX`` by itself.
    ##
    ## In order, under the suspension:
    ##  1. restore the two original entry bytes over the ``EB FE`` self-jump,
    ##     so the stub's final ``jmp <entry>`` lands on the child's real first
    ##     instruction rather than the self-jump;
    ##  2. resume the thread fully, so it finishes ``fn`` and the stub's tail
    ##     carries it into the entry point on the parked ``RSP``/``RCX``;
    ##  3. leak the stub page (a live thread may still be in it) and discard
    ##     the saved parked context (there is no parked thread to hand back).
    ##
    ## ``fn`` is NOT abandoned: it runs to completion in the child, with no
    ## injector watching. A detached shim LOAD therefore leaves the shim
    ## mapped but never initialised; a detached INIT goes on to install
    ## whatever hooks it installs. What the child is monitored by afterwards
    ## is the callee's business, and a caller must report it as unknown.
    ##
    ## ``doFailed`` and ``doRefusedNoStub`` leave the handle LIVE and the
    ## thread frozen, so the caller can still ``terminateBorrowedChild`` --
    ## the only other safe exit for a lent-out thread.
    ##
    ## See ``docs/windows-borrowed-call-deadline.md`` for why this is the one
    ## recovery that cannot strand the child on the self-jump.
    if not b.stubBacked or b.stub == nil:
      return doRefusedNoStub
    if not b.live or b.park == nil:
      return doFailed
    if not childAlive(b.park[].hProcess):
      b.live = false
      b.park[].status = epsAbandoned
      return doChildExited
    if not restoreEntryBytes(b.park[]):
      # The self-jump may still be in place; resuming now could spin the
      # child on it forever. Do not resume; the handle stays live and the
      # thread frozen for the caller to terminate.
      b.park[].status = epsLentOut
      return doFailed
    if not resumeFully(b.hThread):
      # Still suspended. The entry bytes are already the real ones, so the
      # handle stays live for the caller to terminate.
      b.entryRestored = true
      b.park[].status = epsLentOut
      return doFailed
    b.live = false
    b.park[].status = epsDetached
    doDetached

  proc applyBorrowTimeoutPolicy*(b: var TimedOutBorrow;
                                 policy: BorrowTimeoutPolicy):
      AppliedTimeoutPolicy =
    ## Apply the CALLER's ``policy`` to a timed-out borrow and say what
    ## happened. This is the one dispatcher the borrowing entry points use, so
    ## ``btpDetach`` means the same thing everywhere: detach, and if detach
    ## cannot be carried out (the thread is still frozen and lent out),
    ## terminate -- the only other safe exit -- rather than leave a child that
    ## never runs again and never dies.
    case policy
    of btpTerminate:
      terminateBorrowedChild(b)
      atpTerminated
    of btpDetach:
      case detachBorrowedChild(b)
      of doDetached:
        atpDetached
      of doChildExited:
        atpChildExited
      of doRefusedNoStub, doFailed:
        terminateBorrowedChild(b)
        atpTerminated

  proc borrowParkedThread*(park: var EntryPark; hThread: pointer;
                           childIsWow64: bool; fn: pointer; arg: pointer;
                           deadlineMs: uint32): BorrowedCall =
    ## Call ``fn(arg)`` IN THE CHILD, ON ITS OWN MAIN THREAD, and come back
    ## with the thread parked exactly as it was.
    ##
    ## WHY THIS EXISTS, AND WHY A REMOTE THREAD IS NOT GOOD ENOUGH HERE.
    ## A ``CreateRemoteThread(LoadLibraryW)`` runs the injected DLL's entry
    ## point, its module body and its init export on a thread that then
    ## EXITS. For a shim built the way every Nim ``--threads:on`` shim is,
    ## that is a use-after-free waiting to happen: the allocator is a
    ## ``MemRegion`` THREADVAR, so it lives in that thread's TLS block,
    ## which the OS releases when the thread goes; every chunk carries a
    ## pointer back to the region that owns it; and so every process-global
    ## the module body allocated is owned by a region that no longer
    ## exists. The first free of one from any other thread -- a table
    ## rehash is enough -- dereferences it.
    ##
    ## Before the park this never bit, because the injecting thread ran the
    ## whole loader while the child's main thread had not started, and the
    ## two ended up with regions that compared equal. The park separates
    ## them, and the consequence was measured: an injected child faulted in
    ## ``addToSharedFreeList``, reading ``owner.sharedFreeLists[]`` in a
    ## page ``VirtualQuery`` reports as MEM_RESERVE, on the 64-to-128
    ## rehash of a shim-global table -- the 44th distinct environment
    ## variable, every run. Setting an unrelated environment variable moved
    ## the heap enough to make the same run silent instead, which is what a
    ## use-after-free looks like and why "it did not crash" is not
    ## evidence.
    ##
    ## Borrowing the parked thread removes the class rather than the
    ## symptom: the child's OWN main thread maps the shim and runs its
    ## init, so the globals are owned by the one thread guaranteed to
    ## outlive every free of them. It also means the loader provisions that
    ## thread's static-TLS block for the module as the mapping thread,
    ## rather than leaving it to the retrofit path.
    ##
    ## HOW THE RETURN IS ARRANGED. A small stub is written into the child:
    ##
    ##   sub rsp, 20h ; mov rax, fn ; call rax ;
    ##   mov rsp, <parked RSP> ; mov rcx, <parked RCX> ;
    ##   mov r11, <entry point> ; jmp r11
    ##
    ## and the thread is pointed at it with ``RCX`` = ``arg`` (the Win64
    ## first-argument register) and ``RSP`` a little below the parked frame.
    ## Resume, and wait for the instruction pointer to come back to the
    ## entry point, which still holds the park's ``EB FE``: the same proof
    ## the park itself waits on. ``RAX`` there is ``fn``'s result. Then the
    ## saved context is put back, so the thread ends up suspended exactly
    ## where it started, with the same suspend count, and the caller's single
    ## ``ResumeThread`` still owns the wakeup.
    ##
    ## THE ``call`` IS LOAD-BEARING: IT IS WHAT KEEPS THE SHADOW STACK SOUND.
    ## This proc used to write the entry point onto the ordinary stack as a
    ## return address and point ``RIP`` straight at ``fn``. No ``call`` ever
    ## executed, so the hardware shadow stack (Intel CET, "Hardware-enforced
    ## Stack Protection") received no matching entry, and in any child that
    ## runs with one -- every ``/CETCOMPAT`` image on a host that enforces
    ## it -- ``fn``'s ``ret`` raised ``#CP``: the child died with
    ## ``STATUS_STACK_BUFFER_OVERRUN`` (0xC0000409), fast-fail subcode 0x39
    ## ``FAST_FAIL_CONTROL_INVALID_RETURN_ADDRESS``. Measured on
    ## ``pwsh.exe`` (a ``/CETCOMPAT`` .NET apphost) at
    ## ``KERNELBASE!LoadLibraryExW``'s ``ret``. A real ``call`` pushes the
    ## return address onto BOTH stacks and ``ret`` pops both, so the shadow
    ## stack is balanced across the borrow; the stub then reaches the entry
    ## point with a ``jmp``, which the shadow stack does not track. The
    ## shadow-stack pointer is never touched, so the saved context is still
    ## a true description of the thread when it is put back.
    ## ``tests/test_windows_entry_park_shadow_stack.nim`` is the gate.
    ##
    ## WHY THE STUB ENDS AT THE ENTRY POINT, WITH THE PARKED ``RSP``. The
    ## thread coming back to the entry point's ``EB FE`` is the proof this
    ## proc waits for, so the stub ends there, on the parked stack pointer
    ## and with the entry point's argument (``RCX``) as the loader passed
    ## it: exactly the state a completed borrow hands back. The saved
    ## context is then restored on top of it. That same tail is what makes
    ## ``detachBorrowedChild`` possible: restore the entry bytes and let the
    ## thread run, and the tail carries it into the child's real entry point
    ## on the parked ``RSP``/``RCX`` with no injector present.
    ##
    ## FAILURE IS NEVER SILENT, AND THE LIBRARY NEVER RESUMES A LENT-OUT
    ## THREAD. Every status but ``bcsReturned`` means "the child was not
    ## injected"; a caller must not retry with a remote thread, which is the
    ## broken combination this proc exists to replace. ``bcsTimedOut`` means
    ## more: the thread's context is lent out and was NOT handed back, so the
    ## borrow returns a ``TimedOutBorrow`` and leaves the thread suspended
    ## (plus one extra suspend). The library terminates nothing and resumes
    ## nothing; the caller picks a building block -- keep waiting, terminate
    ## or detach. See ``docs/windows-borrowed-call-deadline.md``.
    ##
    ## THE DEADLINE IS A LAST RESORT. ``deadlineMs`` bounds a WEDGED call;
    ## while the child is alive and the call has not come back, this keeps
    ## waiting (``InfiniteDeadline`` waits for as long as the child lives).
    ## It used to be a 5 s budget whose expiry suspended the thread
    ## mid-call and returned ``false`` -- after which every caller restored
    ## the entry bytes and resumed it, and the child finished the borrowed
    ## call and returned into its real entry point on the borrowed stack.
    ## That is a corrupted child manufactured out of a slow one, and it was
    ## observed exactly so on an I/O-starved build host. The deadline now
    ## ends the wait with a ``TimedOutBorrow`` and never resumes the thread.
    ##
    ## WOW64 is refused (``false``) rather than approximated: a 32-bit
    ## child needs ``Wow64SetThreadContext`` and a 32-bit frame, and
    ## neither is measured here. Callers park only what they can borrow.
    result = BorrowedCall(status: bcsNotRun)
    when sizeof(pointer) == 8:
      if childIsWow64 or park.status != epsParked or hThread == nil or
          fn == nil or deadlineMs == 0:
        return

      var savedRaw: array[ContextAmd64Size + 16, byte]
      let saved = alignUp16(addr savedRaw[0])
      cast[ptr uint32](cast[uint](saved) + ContextAmd64FlagsOffset)[] =
        ContextAmd64Full
      if GetThreadContext(hThread, saved) == 0:
        return

      let savedRsp = cast[ptr uint64](cast[uint](saved) +
        ContextAmd64RspOffset)[]
      if savedRsp < 0x10000'u64:
        return

      # The stub runs just below the parked frame, on the thread's OWN
      # stack, so the stub's `call` and the callee grow it through the guard
      # page the ordinary way -- the child's own accesses, not ours, so the
      # guard page commits as it does for any deep call. The gap leaves the
      # parked frame untouched and stays well inside one page, so the first
      # access can reach no further than the guard page.
      #
      # Win64 call condition: RSP is 16-byte aligned at the `call`, so the
      # callee sees RSP+8 aligned. The stub's `sub rsp, 20h` (the callee's
      # home space) preserves the alignment set here.
      const StubGap = 0x200'u64
      if savedRsp <= StubGap + 0x40'u64:
        return
      let rsp = (savedRsp - StubGap) and not 0xF'u64

      # 0: sub rsp, 20h       48 83 EC 20
      # 4: mov rax, imm64     48 B8 <fn>
      # 14: call rax          FF D0
      # 16: mov rsp, imm64    48 BC <savedRsp>
      # 26: mov rcx, imm64    48 B9 <savedRcx>
      # 36: mov r11, imm64    49 BB <entry>
      # 46: jmp r11           41 FF E3
      # `RAX` -- the callee's result -- is left alone for the caller to read.
      # `RCX` is put back because it is the entry point's one argument (the
      # PEB, from `BaseThreadInitThunk`) and the callee is free to clobber
      # it. When the call comes back to the self-jump the saved context
      # restores it anyway. When the caller DETACHES a timed-out borrow
      # (``detachBorrowedChild``), the entry bytes are restored first and
      # this tail is what carries the thread into the program: on the
      # parked RSP, with the entry point's RCX, by a `jmp` that leaves the
      # CET shadow stack exactly as the park found it.
      var stubCode: array[49, byte] = [
        0x48'u8, 0x83, 0xEC, 0x20,
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xD0,
        0x48, 0xBC, 0, 0, 0, 0, 0, 0, 0, 0,
        0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,
        0x49, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0,
        0x41, 0xFF, 0xE3]
      proc putImm64(code: var array[49, byte]; at: int; value: uint64) =
        for i in 0 ..< 8:
          code[at + i] = byte((value shr (8 * i)) and 0xFF'u64)
      let savedRcx = cast[ptr uint64](cast[uint](saved) +
        ContextAmd64RcxOffset)[]
      putImm64(stubCode, 6, uint64(cast[uint](fn)))
      putImm64(stubCode, 18, savedRsp)
      putImm64(stubCode, 28, savedRcx)
      putImm64(stubCode, 38, uint64(cast[uint](park.entry)))
      let stub = VirtualAllocEx(park.hProcess, nil, uint(stubCode.len),
        MemCommit or MemReserve, PageReadWrite)
      if stub == nil:
        return
      # Owned by this frame until the thread is pointed at it; from then on
      # only proof that the thread is back on the parked entry point gives it
      # back. A thread that never came back may still be executing it, so
      # that path leaks it on purpose: one page of the child's address
      # space, reclaimed when the child exits (a poisoned child is
      # terminated at once), against unmapping code a live thread is
      # running.
      var stubOwned = true
      defer:
        if stubOwned:
          discard VirtualFreeEx(park.hProcess, stub, 0'u, MemRelease)
      var wroteStub: uint = 0
      var stubProtect: uint32 = 0
      if WriteProcessMemory(park.hProcess, stub, addr stubCode[0],
          uint(stubCode.len), addr wroteStub) == 0 or
          wroteStub != uint(stubCode.len):
        return
      if VirtualProtectEx(park.hProcess, stub, uint(stubCode.len),
          PageExecuteRead, addr stubProtect) == 0:
        return
      discard FlushInstructionCache(park.hProcess, stub, uint(stubCode.len))

      var callRaw: array[ContextAmd64Size + 16, byte]
      let call = alignUp16(addr callRaw[0])
      copyMem(call, saved, ContextAmd64Size)
      cast[ptr uint32](cast[uint](call) + ContextAmd64FlagsOffset)[] =
        ContextAmd64Full
      cast[ptr uint64](cast[uint](call) + ContextAmd64RspOffset)[] = rsp
      cast[ptr uint64](cast[uint](call) + ContextAmd64RcxOffset)[] =
        uint64(cast[uint](arg))
      cast[ptr uint64](cast[uint](call) + ContextAmd64RipOffset)[] =
        uint64(cast[uint](stub))
      if SetThreadContext(hThread, call) == 0:
        return

      # FROM HERE THE CONTEXT IS LENT OUT. Every exit below either hands it
      # back byte for byte or hands the caller a ``TimedOutBorrow``; the
      # library never resumes a lent-out thread itself and never terminates.
      if ResumeThread(hThread) == high(uint32):
        # Never ran, so restoring is enough -- if restoring works.
        if SetThreadContext(hThread, saved) != 0:
          return
        # The lent-out context is set and cannot be restored; resuming would
        # run the stub. Hand it back lent out, with the stub still mapped.
        stubOwned = false
        result.status = bcsTimedOut
        result.timedOut = lendOut(park, hThread, childIsWow64, saved, stub,
          uint(stubCode.len), 0)
        return
      # The thread may now be executing the stub.
      stubOwned = false

      let started = GetTickCount64()
      let waited = waitForParkedIp(park, hThread, childIsWow64, deadlineMs)
      result.elapsedMs = GetTickCount64() - started
      case waited
      of pwExited:
        result.status = bcsChildExited
        return
      of pwDeadline:
        # The call did not come back in time. The thread is suspended mid-stub,
        # context lent out, stub still mapped. Hand policy to the caller.
        result.status = bcsTimedOut
        result.timedOut = lendOut(park, hThread, childIsWow64, saved, stub,
          uint(stubCode.len), result.elapsedMs)
        return
      of pwParked:
        discard

      # Back on the parked entry point and suspended: nothing executes the
      # stub any more.
      stubOwned = true

      var doneRaw: array[ContextAmd64Size + 16, byte]
      let done = alignUp16(addr doneRaw[0])
      cast[ptr uint32](cast[uint](done) + ContextAmd64FlagsOffset)[] =
        ContextAmd64Full
      let haveResult = GetThreadContext(hThread, done) != 0

      # Hand the thread back byte-for-byte. The stub's tail already put the
      # parked RSP/RCX back and the thread is on the self-jump, but the full
      # register file is only byte-identical once the saved context is
      # restored. If that restore fails, hand the caller a lent-out borrow
      # rather than resume a thread the library could not fully hand back.
      if SetThreadContext(hThread, saved) == 0:
        result.status = bcsTimedOut
        result.timedOut = lendOut(park, hThread, childIsWow64, saved, stub,
          uint(stubCode.len), result.elapsedMs)
        return
      if haveResult:
        result.ret = cast[ptr uint64](cast[uint](done) +
          ContextAmd64RaxOffset)[]
        result.status = bcsReturned
      else:
        result.status = bcsNoResult

  proc callOnParkedThread*(park: var EntryPark; hThread: pointer;
                           childIsWow64: bool; fn: pointer; arg: pointer;
                           timeoutMs: uint32; onTimeout: BorrowTimeoutPolicy;
                           ret: var uint64): bool =
    ## Boolean form of ``borrowParkedThread``: ``true`` only on
    ## ``bcsReturned``. ``timeoutMs`` is the HARD deadline.
    ##
    ## A timed-out borrow leaves a lent-out thread that a bool cannot describe,
    ## so the caller MUST state its policy: ``onTimeout`` has NO default, which
    ## is the point -- this convenience never decides for the caller. On
    ## ``bcsTimedOut`` it applies that building block (``btpTerminate`` leaves
    ## the park ``epsAbandoned`` and the child dead; ``btpDetach`` leaves it
    ## ``epsDetached`` and the child running with its monitoring unknown, or
    ## terminated if detach was impossible -- see ``applyBorrowTimeoutPolicy``)
    ## and returns
    ## ``false``. A caller that wants to keep waiting, or to inspect the
    ## ``TimedOutBorrow`` itself, must use ``borrowParkedThread``.
    var r = borrowParkedThread(park, hThread, childIsWow64, fn, arg,
      timeoutMs)
    if r.status == bcsTimedOut:
      discard applyBorrowTimeoutPolicy(r.timedOut, onTimeout)
    ret = r.ret
    r.status == bcsReturned

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

  proc borrowParkedThread*(park: var EntryPark; hThread: pointer;
                           childIsWow64: bool; fn: pointer; arg: pointer;
                           deadlineMs: uint32): BorrowedCall =
    ## Nothing is ever parked on this architecture, so nothing can be
    ## borrowed. Refusing keeps the caller on the legacy technique rather
    ## than letting it believe a call happened.
    BorrowedCall(status: bcsNotRun)

  proc callOnParkedThread*(park: var EntryPark; hThread: pointer;
                           childIsWow64: bool; fn: pointer; arg: pointer;
                           timeoutMs: uint32; onTimeout: BorrowTimeoutPolicy;
                           ret: var uint64): bool =
    ret = 0
    false

  # The building blocks exist on every architecture so callers compile
  # unchanged, but no ``TimedOutBorrow`` can be live here: nothing is ever
  # lent out.
  proc keepWaitingForBorrow*(b: var TimedOutBorrow;
                             additionalMs: uint32): BorrowedCall =
    BorrowedCall(status: bcsNotRun)

  proc terminateBorrowedChild*(b: var TimedOutBorrow;
      exitCode: uint32 = InjectionAbandonedExitCode) =
    discard

  proc detachBorrowedChild*(b: var TimedOutBorrow): DetachOutcome =
    doRefusedNoStub

  proc applyBorrowTimeoutPolicy*(b: var TimedOutBorrow;
                                 policy: BorrowTimeoutPolicy):
      AppliedTimeoutPolicy =
    atpTerminated

{.pop.}
