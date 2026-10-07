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

  proc waitForParkedIp(park: var EntryPark; hThread: pointer;
                       childIsWow64: bool; timeoutMs: uint32): bool =
    ## Poll until the thread is stopped ON the ``EB FE`` at the entry point.
    ## The proof is the same one ``parkChildAtEntryPoint`` waits for when it
    ## first parks the thread: the instruction pointer is back on the
    ## self-jump, confirmed AFTER the suspend, so the thread is stopped
    ## there rather than merely observed passing through. The park keeps its
    ## own copy of the loop because its failure path has to restore the
    ## patched bytes, which a borrowed call must NOT do -- the park is still
    ## live across the call.
    let deadline = GetTickCount64() + uint64(timeoutMs)
    let wantIp = uint64(cast[uint](park.entry))
    while true:
      var ip: uint64 = 0
      if instructionPointer(hThread, childIsWow64, ip) and ip == wantIp:
        discard SuspendThread(hThread)
        var confirmed: uint64 = 0
        if instructionPointer(hThread, childIsWow64, confirmed) and
            confirmed == wantIp:
          return true
        discard ResumeThread(hThread)
      var exitCode: uint32 = 0
      if GetExitCodeProcess(park.hProcess, addr exitCode) != 0 and
          exitCode != StillActive:
        return false
      if GetTickCount64() >= deadline:
        return false
      SleepMs(1'u32)

  proc callOnParkedThread*(park: var EntryPark; hThread: pointer;
                           childIsWow64: bool; fn: pointer; arg: pointer;
                           timeoutMs: uint32; ret: var uint64): bool =
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
    ## WHY THE STUB ENDS AT THE ENTRY POINT, WITH THE PARKED ``RSP``. A
    ## borrowed call can outlive ``timeoutMs`` -- a shim ``LoadLibraryW``
    ## under a loaded host and an on-access scanner has been measured past
    ## the default 5 s. This proc then gives up, the caller releases the
    ## park and resumes the child, and the call finishes LATER, unwatched.
    ## Wherever the thread goes next is where the child's program continues.
    ## The stub therefore ends exactly where a completed borrow would have
    ## left the thread: at the entry point (its ``EB FE`` restored to the
    ## original bytes by then), on the parked stack pointer and with the
    ## entry point's argument (``RCX``) as the loader passed it, so the entry
    ## point's own return address and the shadow stack still agree and the
    ## program runs normally, uninjected. A stub that instead parked itself
    ## on a private self-jump was measured to strand ``gcc.exe`` spinning
    ## there forever after exactly such a timeout -- the
    ## slow-borrow case in the test above pins this.
    ##
    ## FAILURE IS NEVER SILENT. Every early return leaves ``ret`` at zero
    ## and answers ``false``; a caller must treat that as "the child was
    ## not injected" rather than retry with a remote thread, which is the
    ## broken combination this proc exists to replace.
    ##
    ## WOW64 is refused (``false``) rather than approximated: a 32-bit
    ## child needs ``Wow64SetThreadContext`` and a 32-bit frame, and
    ## neither is measured here. Callers park only what they can borrow.
    ret = 0
    when sizeof(pointer) == 8:
      if childIsWow64 or park.status != epsParked or hThread == nil or
          fn == nil or timeoutMs == 0:
        return false

      var savedRaw: array[ContextAmd64Size + 16, byte]
      let saved = alignUp16(addr savedRaw[0])
      cast[ptr uint32](cast[uint](saved) + ContextAmd64FlagsOffset)[] =
        ContextAmd64Full
      if GetThreadContext(hThread, saved) == 0:
        return false

      let savedRsp = cast[ptr uint64](cast[uint](saved) +
        ContextAmd64RspOffset)[]
      if savedRsp < 0x10000'u64:
        return false

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
        return false
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
      # it: on the completed path the saved context restores it anyway, but
      # on the late path below the thread enters the program from here.
      # Measured with a `/ENTRY` image that checks its argument: without
      # this it entered with a stale `RCX` after a timed-out borrow.
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
        return false
      # Owned by this frame until the thread is pointed at it; from then on
      # only proof that the thread is back on the parked entry point gives it
      # back. A thread that never came back may still be executing it, so
      # that path leaks it on purpose: one page of the child's address
      # space, reclaimed when the child exits, against unmapping code a live
      # thread is running.
      var stubOwned = true
      defer:
        if stubOwned:
          discard VirtualFreeEx(park.hProcess, stub, 0'u, MemRelease)
      var wroteStub: uint = 0
      var stubProtect: uint32 = 0
      if WriteProcessMemory(park.hProcess, stub, addr stubCode[0],
          uint(stubCode.len), addr wroteStub) == 0 or
          wroteStub != uint(stubCode.len):
        return false
      if VirtualProtectEx(park.hProcess, stub, uint(stubCode.len),
          PageExecuteRead, addr stubProtect) == 0:
        return false
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
        return false

      if ResumeThread(hThread) == high(uint32):
        discard SetThreadContext(hThread, saved)
        return false
      # The thread may now be executing the stub.
      stubOwned = false

      if not waitForParkedIp(park, hThread, childIsWow64, timeoutMs):
        # The child either died or never came back to the self-jump. Its
        # state is unknown; say so rather than restoring a context that may
        # no longer describe anything. If the call does finish later, the
        # stub delivers the thread to the entry point on the parked stack
        # pointer -- see "WHY THE STUB ENDS AT THE ENTRY POINT" above.
        discard SuspendThread(hThread)
        return false

      # Back on the parked entry point and suspended: nothing executes the
      # stub any more.
      stubOwned = true

      var doneRaw: array[ContextAmd64Size + 16, byte]
      let done = alignUp16(addr doneRaw[0])
      cast[ptr uint32](cast[uint](done) + ContextAmd64FlagsOffset)[] =
        ContextAmd64Full
      if GetThreadContext(hThread, done) == 0:
        return false
      ret = cast[ptr uint64](cast[uint](done) + ContextAmd64RaxOffset)[]

      # Hand the thread back byte-for-byte.
      if SetThreadContext(hThread, saved) == 0:
        return false
      true
    else:
      false

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

  proc callOnParkedThread*(park: var EntryPark; hThread: pointer;
                           childIsWow64: bool; fn: pointer; arg: pointer;
                           timeoutMs: uint32; ret: var uint64): bool =
    ## Nothing is ever parked on this architecture, so nothing can be
    ## borrowed. Refusing keeps the caller on the legacy technique rather
    ## than letting it believe a call happened.
    ret = 0
    false

{.pop.}
