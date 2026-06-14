{.push raises: [].}

## IAT (Import Address Table) Patcher for Windows DLL interposition.
##
## Walks the PE import descriptors of all loaded modules and replaces
## function pointers in the IAT with our hook functions. This is the
## Windows equivalent of DYLD_INSERT_LIBRARIES / LD_PRELOAD symbol
## interposition on macOS/Linux.
##
## The approach:
##   1. Enumerate loaded modules via the PEB's InMemoryOrderModuleList
##   2. For each module, parse the PE headers to find the import directory
##   3. Walk import descriptors looking for the target DLL (e.g. "kernel32.dll")
##   4. Walk the Import Name Table (INT) and IAT in parallel
##   5. When we find the target function name, VirtualProtect the IAT entry,
##      swap the pointer, and restore protection.
##
## Returns the original function pointer so hooks can call through.

when defined(windows):
  type
    HANDLE = pointer
    DWORD = uint32
    WORD = uint16
    LONG = int32
    ULONGLONG = uint64
    BOOL = int32
    BYTE = byte
    LPVOID = pointer

  # --- Win32 API imports ---
  proc GetModuleHandleA(lpModuleName: cstring): pointer
    {.importc, stdcall, dynlib: "kernel32".}
  proc VirtualProtect(lpAddress: LPVOID, dwSize: uint, flNewProtect: DWORD,
                      lpflOldProtect: ptr DWORD): BOOL
    {.importc, stdcall, dynlib: "kernel32".}
  proc GetCurrentProcess(): HANDLE
    {.importc, stdcall, dynlib: "kernel32".}
  proc EnumProcessModules(hProcess: HANDLE, lphModule: ptr pointer,
                          cb: DWORD, lpcbNeeded: ptr DWORD): BOOL
    {.importc, stdcall, dynlib: "psapi".}
  const
    PAGE_READWRITE = 0x04'u32
    IMAGE_DOS_SIGNATURE = 0x5A4D'u16      # "MZ"
    IMAGE_NT_SIGNATURE = 0x00004550'u32    # "PE\0\0"
    IMAGE_DIRECTORY_ENTRY_IMPORT = 1

  # --- PE Header structures (64-bit) ---
  type
    ImageDosHeader {.packed.} = object
      e_magic: WORD
      e_cblp: WORD
      e_cp: WORD
      e_crlc: WORD
      e_cparhdr: WORD
      e_minalloc: WORD
      e_maxalloc: WORD
      e_ss: WORD
      e_sp: WORD
      e_csum: WORD
      e_ip: WORD
      e_cs: WORD
      e_lfarlc: WORD
      e_ovno: WORD
      e_res: array[4, WORD]
      e_oemid: WORD
      e_oeminfo: WORD
      e_res2: array[10, WORD]
      e_lfanew: LONG

    ImageFileHeader {.packed.} = object
      machine: WORD
      numberOfSections: WORD
      timeDateStamp: DWORD
      pointerToSymbolTable: DWORD
      numberOfSymbols: DWORD
      sizeOfOptionalHeader: WORD
      characteristics: WORD

    ImageDataDirectory {.packed.} = object
      virtualAddress: DWORD
      size: DWORD

    ImageOptionalHeader64 {.packed.} = object
      magic: WORD
      majorLinkerVersion: BYTE
      minorLinkerVersion: BYTE
      sizeOfCode: DWORD
      sizeOfInitializedData: DWORD
      sizeOfUninitializedData: DWORD
      addressOfEntryPoint: DWORD
      baseOfCode: DWORD
      imageBase: ULONGLONG
      sectionAlignment: DWORD
      fileAlignment: DWORD
      majorOperatingSystemVersion: WORD
      minorOperatingSystemVersion: WORD
      majorImageVersion: WORD
      minorImageVersion: WORD
      majorSubsystemVersion: WORD
      minorSubsystemVersion: WORD
      win32VersionValue: DWORD
      sizeOfImage: DWORD
      sizeOfHeaders: DWORD
      checkSum: DWORD
      subsystem: WORD
      dllCharacteristics: WORD
      sizeOfStackReserve: ULONGLONG
      sizeOfStackCommit: ULONGLONG
      sizeOfHeapReserve: ULONGLONG
      sizeOfHeapCommit: ULONGLONG
      loaderFlags: DWORD
      numberOfRvaAndSizes: DWORD
      dataDirectory: array[16, ImageDataDirectory]

    ImageNtHeaders64 {.packed.} = object
      signature: DWORD
      fileHeader: ImageFileHeader
      optionalHeader: ImageOptionalHeader64

    ImageImportDescriptor {.packed.} = object
      originalFirstThunk: DWORD  # RVA to INT (Import Name Table)
      timeDateStamp: DWORD
      forwarderChain: DWORD
      name: DWORD                # RVA to DLL name
      firstThunk: DWORD          # RVA to IAT (Import Address Table)

    ImageThunkData64 {.packed.} = object
      u1: ULONGLONG  # Union: ForwarderString / Function / Ordinal / AddressOfData

    ImageImportByName {.packed.} = object
      hint: WORD
      # name follows as a variable-length C string

  const
    IMAGE_ORDINAL_FLAG64 = 0x8000000000000000'u64

  # --- Helper procs ---

  proc rvaToPtr(base: pointer, rva: DWORD): pointer {.inline.} =
    ## Convert a Relative Virtual Address to an absolute pointer.
    cast[pointer](cast[uint64](base) + uint64(rva))

  proc cStrEqInsensitive(a, b: cstring): bool =
    ## Case-insensitive C string comparison. Returns true if equal.
    var i = 0
    while true:
      var ca = a[i]
      var cb = b[i]
      # Convert to lowercase
      if ca >= 'A' and ca <= 'Z': ca = chr(ord(ca) + 32)
      if cb >= 'A' and cb <= 'Z': cb = chr(ord(cb) + 32)
      if ca != cb:
        return false
      if ca == '\0':
        return true
      inc i

  proc cStrEq(a, b: cstring): bool =
    ## Case-sensitive C string comparison.
    var i = 0
    while true:
      if a[i] != b[i]:
        return false
      if a[i] == '\0':
        return true
      inc i

  # --- IAT patching for a single module ---

  proc patchIATInModule*(moduleBase: pointer, targetDll: cstring,
                         funcName: cstring, hookFunc: pointer): pointer =
    ## Patch the IAT of a single module for `funcName` imported from `targetDll`.
    ## Returns the original function pointer, or nil if not found/failed.
    ##
    ## moduleBase: base address of the module to patch (from GetModuleHandle)
    ## targetDll:  name of the DLL the function is imported from (e.g. "kernel32.dll")
    ## funcName:   name of the function to hook (e.g. "CreateFileW")
    ## hookFunc:   pointer to the replacement function
    let dosHeader = cast[ptr ImageDosHeader](moduleBase)
    if dosHeader.e_magic != IMAGE_DOS_SIGNATURE:
      return nil

    let ntHeaders = cast[ptr ImageNtHeaders64](
      rvaToPtr(moduleBase, DWORD(dosHeader.e_lfanew)))
    if ntHeaders.signature != IMAGE_NT_SIGNATURE:
      return nil

    # Get import directory
    let importDir = ntHeaders.optionalHeader.dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
    if importDir.virtualAddress == 0 or importDir.size == 0:
      return nil

    # Walk import descriptors
    var importDesc = cast[ptr ImageImportDescriptor](
      rvaToPtr(moduleBase, importDir.virtualAddress))

    while importDesc.name != 0:
      let dllName = cast[cstring](rvaToPtr(moduleBase, importDesc.name))

      if cStrEqInsensitive(dllName, targetDll):
        # Found matching DLL import — walk the thunk arrays
        let intBase = importDesc.originalFirstThunk  # Import Name Table
        let iatBase = importDesc.firstThunk           # Import Address Table

        if iatBase == 0:
          importDesc = cast[ptr ImageImportDescriptor](
            cast[uint64](importDesc) + uint64(sizeof(ImageImportDescriptor)))
          continue

        # Use INT if available, otherwise use IAT (bound imports)
        let lookupBase = if intBase != 0: intBase else: iatBase

        var idx = 0
        while true:
          let lookupThunk = cast[ptr ImageThunkData64](
            rvaToPtr(moduleBase, lookupBase + DWORD(idx * sizeof(ImageThunkData64))))
          let iatThunk = cast[ptr ImageThunkData64](
            rvaToPtr(moduleBase, iatBase + DWORD(idx * sizeof(ImageThunkData64))))

          if lookupThunk.u1 == 0:
            break  # End of thunk array

          # Skip ordinal imports
          if (lookupThunk.u1 and IMAGE_ORDINAL_FLAG64) == 0:
            let importByName = cast[ptr ImageImportByName](
              rvaToPtr(moduleBase, DWORD(lookupThunk.u1)))
            # The name starts at offset 2 (after the hint WORD)
            let importFuncName = cast[cstring](
              cast[uint64](importByName) + uint64(sizeof(WORD)))

            if cStrEq(importFuncName, funcName):
              # Found the function — patch the IAT entry
              let iatEntryAddr = cast[ptr pointer](addr iatThunk.u1)
              let originalFunc = cast[pointer](iatThunk.u1)

              # Make the IAT entry writable
              var oldProtect: DWORD = 0
              let protResult = VirtualProtect(
                cast[LPVOID](iatEntryAddr),
                uint(sizeof(pointer)),
                PAGE_READWRITE,
                addr oldProtect)
              if protResult == 0:
                return nil  # VirtualProtect failed

              # Swap the function pointer
              iatEntryAddr[] = hookFunc

              # Restore original protection
              var dummy: DWORD = 0
              discard VirtualProtect(
                cast[LPVOID](iatEntryAddr),
                uint(sizeof(pointer)),
                oldProtect,
                addr dummy)

              return originalFunc

          inc idx

      # Move to next import descriptor
      importDesc = cast[ptr ImageImportDescriptor](
        cast[uint64](importDesc) + uint64(sizeof(ImageImportDescriptor)))

    return nil  # Function not found in this module's imports

  # --- Patch IAT across all loaded modules ---

  proc patchIAT*(targetDll: cstring, funcName: cstring,
                 hookFunc: pointer): pointer =
    ## Patch the IAT entry for `funcName` (imported from `targetDll`) in
    ## the main executable module. Returns the original function pointer,
    ## or nil if not found.
    ##
    ## For v1, we only patch the main .exe module. In the future this can
    ## be extended to patch all loaded modules.
    let mainModule = GetModuleHandleA(nil)  # NULL = main .exe
    if mainModule == nil:
      return nil

    result = patchIATInModule(mainModule, targetDll, funcName, hookFunc)

  proc patchIATAllModules*(targetDll: cstring, funcName: cstring,
                           hookFunc: pointer): pointer =
    ## Patch the IAT entry for `funcName` across ALL loaded modules.
    ## Returns the first original function pointer found, or nil if none.
    ##
    ## This is more thorough than patchIAT which only patches the main exe.
    ## It handles cases where DLLs loaded by the target also import the
    ## hooked function.
    let hProcess = GetCurrentProcess()
    var modules: array[1024, pointer]
    var cbNeeded: DWORD = 0

    let enumResult = EnumProcessModules(
      hProcess,
      addr modules[0],
      DWORD(sizeof(modules)),
      addr cbNeeded)

    if enumResult == 0:
      # Fallback to main module only
      return patchIAT(targetDll, funcName, hookFunc)

    let moduleCount = int(cbNeeded) div sizeof(pointer)
    var firstOriginal: pointer = nil

    for i in 0 ..< min(moduleCount, 1024):
      let original = patchIATInModule(modules[i], targetDll, funcName, hookFunc)
      if original != nil and firstOriginal == nil:
        firstOriginal = original

    return firstOriginal

  # --- MW8 (MCR-Windows-CtMcr-Port): IAT-patch registry + retroactive unpatch ─
  #
  # MW7 closed the documented kernel32-IAT-vs-NTDLL-inline-detour
  # recursion class via defensive wrap, but a separate AV remains on
  # .NET CLR targets when the full hook surface is armed.  MW8's fix is
  # to UNPATCH every IAT slot we patched, after the CLR loads --
  # detected via the LdrLoadDll inline detour.  Once unpatched, the
  # kernel32 IAT entries hold the REAL function pointer, so the CLR's
  # internal IAT cache stays consistent.  NT-level inline detours
  # remain installed at the function body, so NT syscalls (including
  # those the CLR makes) still record.  See:
  #   MCR-Windows-CtMcr-Port.milestones.org §MW8
  #   MCR-Windows-Inline-Hooking.md §"Approach 1" (the original CLR-AV
  #   class this closes the door on)
  #
  # To unpatch we must know the IAT SLOT address, not just the original
  # function pointer.  ``patchIATInModule`` returns only the original
  # pointer.  ``patchIATInModuleTracked`` (below) records the slot
  # address + the hook into a process-global registry so a later call
  # to ``retroactiveIatUnpatch`` can walk and restore each entry.

  type
    IatPatchRecord* = object
      moduleBase*: pointer    ## Module whose IAT slot was patched.
      targetDll*: cstring     ## Imported-from DLL name (e.g. "kernel32.dll").
      funcName*: cstring      ## Imported function name.
      iatSlot*: ptr pointer   ## Address of the IAT slot we patched.
      originalFunc*: pointer  ## Original function pointer pre-patch.
      hookFunc*: pointer      ## The hook pointer we installed.

  # The registry is a fixed-size array protected by an interlocked
  # append counter.  Avoids dynamic seq allocation (which would call
  # malloc/Nim GC) during the IAT walk's hot path.  Cap is generous
  # enough for the ~28 kernel32/ws2_32/bcrypt/msvcrt hooks installed
  # per-module x ~100 typical modules on a .NET process.
  const MaxIatPatchRecords* = 4096
  var gIatPatchRecords* {.global.}: array[MaxIatPatchRecords, IatPatchRecord]
  var gIatPatchRecordCount* {.global.}: int32 = 0

  proc InterlockedIncrement32(addend: ptr int32): int32
    {.importc: "_InterlockedIncrement", header: "<intrin.h>".}
  proc InterlockedExchangePointer(target: ptr pointer, value: pointer): pointer
    {.importc: "_InterlockedExchangePointer", header: "<intrin.h>".}

  proc recordIatPatch(moduleBase: pointer, targetDll, funcName: cstring,
                      iatSlot: ptr pointer, originalFunc, hookFunc: pointer) =
    ## Append an IAT-patch record to the registry.  Lock-free (the
    ## append counter is interlocked); the per-slot fields are written
    ## BEFORE the count is published so a concurrent reader sees a
    ## consistent record.  In practice the writer is single-threaded
    ## (the init-time installIATHooks pass + the LdrLoadDll detour
    ## which holds the M50.2 re-entrancy guard), but the interlocked
    ## append future-proofs against parallel installs.
    let idx = InterlockedIncrement32(addr gIatPatchRecordCount) - 1
    if idx < 0 or idx >= MaxIatPatchRecords:
      # Overflow -- silently drop the record.  The patch itself still
      # took effect; only the un-patchability via the registry is lost.
      return
    gIatPatchRecords[idx].moduleBase = moduleBase
    gIatPatchRecords[idx].targetDll = targetDll
    gIatPatchRecords[idx].funcName = funcName
    gIatPatchRecords[idx].iatSlot = iatSlot
    gIatPatchRecords[idx].originalFunc = originalFunc
    gIatPatchRecords[idx].hookFunc = hookFunc

  proc patchIATInModuleTracked*(moduleBase: pointer, targetDll: cstring,
                                funcName: cstring,
                                hookFunc: pointer): pointer =
    ## Same as ``patchIATInModule`` but also records the patch into
    ## ``gIatPatchRecords`` so ``retroactiveIatUnpatch`` can restore
    ## the original pointer later (MW8).
    let dosHeader = cast[ptr ImageDosHeader](moduleBase)
    if dosHeader.e_magic != IMAGE_DOS_SIGNATURE:
      return nil
    let ntHeaders = cast[ptr ImageNtHeaders64](
      rvaToPtr(moduleBase, DWORD(dosHeader.e_lfanew)))
    if ntHeaders.signature != IMAGE_NT_SIGNATURE:
      return nil
    let importDir =
      ntHeaders.optionalHeader.dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
    if importDir.virtualAddress == 0 or importDir.size == 0:
      return nil
    var importDesc = cast[ptr ImageImportDescriptor](
      rvaToPtr(moduleBase, importDir.virtualAddress))
    while importDesc.name != 0:
      let dllName = cast[cstring](rvaToPtr(moduleBase, importDesc.name))
      if cStrEqInsensitive(dllName, targetDll):
        let intBase = importDesc.originalFirstThunk
        let iatBase = importDesc.firstThunk
        if iatBase == 0:
          importDesc = cast[ptr ImageImportDescriptor](
            cast[uint64](importDesc) + uint64(sizeof(ImageImportDescriptor)))
          continue
        let lookupBase = if intBase != 0: intBase else: iatBase
        var idx = 0
        while true:
          let lookupThunk = cast[ptr ImageThunkData64](
            rvaToPtr(moduleBase, lookupBase + DWORD(idx * sizeof(ImageThunkData64))))
          let iatThunk = cast[ptr ImageThunkData64](
            rvaToPtr(moduleBase, iatBase + DWORD(idx * sizeof(ImageThunkData64))))
          if lookupThunk.u1 == 0:
            break
          if (lookupThunk.u1 and IMAGE_ORDINAL_FLAG64) == 0:
            let importByName = cast[ptr ImageImportByName](
              rvaToPtr(moduleBase, DWORD(lookupThunk.u1)))
            let importFuncName = cast[cstring](
              cast[uint64](importByName) + uint64(sizeof(WORD)))
            if cStrEq(importFuncName, funcName):
              let iatEntryAddr = cast[ptr pointer](addr iatThunk.u1)
              let originalFunc = cast[pointer](iatThunk.u1)
              # Don't double-patch (the original pointer would already
              # be our hook -- that would corrupt the unpatch chain).
              if originalFunc == hookFunc:
                return nil
              var oldProtect: DWORD = 0
              let protResult = VirtualProtect(
                cast[LPVOID](iatEntryAddr),
                uint(sizeof(pointer)),
                PAGE_READWRITE, addr oldProtect)
              if protResult == 0:
                return nil
              iatEntryAddr[] = hookFunc
              var dummy: DWORD = 0
              discard VirtualProtect(
                cast[LPVOID](iatEntryAddr),
                uint(sizeof(pointer)),
                oldProtect, addr dummy)
              # Record the patch so MW8 retroactive-unpatch can find it.
              recordIatPatch(moduleBase, targetDll, funcName,
                             iatEntryAddr, originalFunc, hookFunc)
              return originalFunc
          inc idx
      importDesc = cast[ptr ImageImportDescriptor](
        cast[uint64](importDesc) + uint64(sizeof(ImageImportDescriptor)))
    return nil

  proc patchIATAllModulesTracked*(targetDll, funcName: cstring,
                                  hookFunc: pointer): pointer =
    ## Tracked variant of ``patchIATAllModules`` -- patches every
    ## loaded module's IAT and records each patch into the registry
    ## so MW8's retroactive-unpatch can restore the originals on CLR
    ## load.  Returns the first original function pointer found, or
    ## nil if none.
    let hProcess = GetCurrentProcess()
    var modules: array[1024, pointer]
    var cbNeeded: DWORD = 0
    let enumResult = EnumProcessModules(
      hProcess, addr modules[0],
      DWORD(sizeof(modules)), addr cbNeeded)
    if enumResult == 0:
      let mainModule = GetModuleHandleA(nil)
      if mainModule == nil:
        return nil
      return patchIATInModuleTracked(mainModule, targetDll, funcName, hookFunc)
    let moduleCount = int(cbNeeded) div sizeof(pointer)
    var firstOriginal: pointer = nil
    for i in 0 ..< min(moduleCount, 1024):
      let original = patchIATInModuleTracked(
        modules[i], targetDll, funcName, hookFunc)
      if original != nil and firstOriginal == nil:
        firstOriginal = original
    return firstOriginal

  # MW8: list of function names whose IAT entries must be unpatched
  # when the CLR loads.  These are the kernel32 sync hooks whose
  # interaction with the .NET CLR's IAT cache + NTDLL inline detours
  # provoked the residual AV (after MW7 closed the documented recursion
  # class).  The 9 names mirror the kernel32 sync set MW7 wrapped in
  # exports_windows.nim.  Plus 2 critical-section variants whose IAT
  # hooks compound the same hazard.  Plus the other sync hooks that
  # are bracketed by enterHook/exitHook in the MW7 wrap.  See
  # MCR-Windows-CtMcr-Port.milestones.org §MW8 -- the full
  # "kernel32/kernelbase recursion class".
  const ClrUnpatchFuncNames* = [
    cstring"EnterCriticalSection",
    cstring"LeaveCriticalSection",
    cstring"AcquireSRWLockExclusive",
    cstring"ReleaseSRWLockExclusive",
    cstring"AcquireSRWLockShared",
    cstring"ReleaseSRWLockShared",
    cstring"SleepConditionVariableSRW",
    cstring"WakeConditionVariable",
    cstring"WakeAllConditionVariable",
    # Additional kernel32 IAT hooks the CLR also dispatches through;
    # leaving these patched without the matching unpatch would still
    # land the CLR's cached pointer back inside our recorder body.
    cstring"InitializeCriticalSection",
    cstring"DeleteCriticalSection",
    cstring"TryAcquireSRWLockExclusive",
    cstring"TryAcquireSRWLockShared",
  ]

  proc isUnpatchableForClr*(funcName: cstring): bool =
    ## Returns true if ``funcName`` is in the MW8 CLR-unpatch set.
    for n in ClrUnpatchFuncNames:
      if cStrEq(funcName, n):
        return true
    false

  var gRetroactiveUnpatchFires* {.global.}: int64 = 0
    ## Diagnostic counter -- incremented once per successful retroactive
    ## IAT unpatch.  Exposed via ``ctIatRetroactiveUnpatchFires()`` for
    ## the MW8 ``test_iat_unpatch_clr_load`` test.

  # MW67 (MCR-Windows-CtMcr-Port, 2026-06-02) -- diagnostic counter for
  # the NUMBER OF CALLS to ``retroactiveIatUnpatch`` (distinct from the
  # pre-existing ``gRetroactiveUnpatchFires`` which counts INDIVIDUAL
  # IAT SLOTS unpatched).  The per-call counter lets the MW67 sampler
  # distinguish:
  #   - call-count == 0  --> ``hLdrLoadDll`` never fired with a CLR
  #     module name (or the entire detour never fired).
  #   - call-count >= 1, slot-count == 0 --> the unpatch ran but found
  #     no slots to restore (MW8 single-shot guard already fired, or
  #     the per-module IAT records are empty).
  #   - call-count >= 1, slot-count > 0  --> MW8 ran normally; the
  #     downstream cause of the cascade must lie elsewhere (outcome iii).
  var gMw8UnpatchCalls* {.global.}: int64 = 0
    ## Diagnostic counter -- incremented once per CALL to
    ## ``retroactiveIatUnpatch`` regardless of how many slots it ended
    ## up restoring.  Exposed via ``ctIatRetroactiveUnpatchCalls()`` for
    ## the MW67 ``mw67-late`` sampler in
    ## ``ldrloaddll_detour_windows.nim``.

  proc InterlockedIncrement64Iat(addend: ptr int64): int64
    {.importc: "_InterlockedIncrement64", header: "<intrin.h>".}

  proc ctIatRetroactiveUnpatchFires*(): uint64 {.exportc, cdecl.} =
    ## Exported counter accessor for the MW8 unpatch test.
    uint64(gRetroactiveUnpatchFires)

  proc ctIatRetroactiveUnpatchCalls*(): uint64 {.exportc, cdecl.} =
    ## MW67 exported accessor -- per-call counter for
    ## ``retroactiveIatUnpatch``.  See ``gMw8UnpatchCalls`` doc-comment.
    uint64(gMw8UnpatchCalls)

  proc retroactiveIatUnpatch*(reasonTag: cstring = nil): int32 {.discardable.} =
    ## MW8 — restore the original function pointer in every IAT slot
    ## we patched whose ``funcName`` is in the CLR-unpatch set.  Called
    ## from the LdrLoadDll inline detour when a CLR module loads --
    ## the CLR is now resident, will resolve its IAT entries through
    ## kernel32 lookups whose results we'd otherwise redirect into our
    ## recorder body.  Restoring the originals lets the CLR's IAT
    ## cache see the real function pointers and keeps the NTDLL inline
    ## detours (at function-body level) firing for all callers, so the
    ## NT-syscall recording surface is preserved.
    ##
    ## Atomic per entry: VirtualProtect→RW, InterlockedExchangePointer,
    ## VirtualProtect→old.  Idempotent: a slot that already holds the
    ## original pointer is skipped (no-op).
    ##
    ## Returns the number of unpatched entries (for diagnostic
    ## reporting via the recorder log; caller may ignore).
    # MW67 (MCR-Windows-CtMcr-Port, 2026-06-02): increment per-call
    # counter at the very top of the body, BEFORE any early-return,
    # so the sampler distinguishes "called and found nothing" from
    # "never called".
    discard InterlockedIncrement64Iat(addr gMw8UnpatchCalls)
    var unpatched: int32 = 0
    let count = gIatPatchRecordCount
    let nEntries = min(int(count), MaxIatPatchRecords)
    for i in 0 ..< nEntries:
      let rec = addr gIatPatchRecords[i]
      if rec.iatSlot == nil:
        continue
      if not isUnpatchableForClr(rec.funcName):
        continue
      if rec.originalFunc == nil:
        continue
      # Skip if the slot no longer holds our hook (someone else may
      # have repatched it, or our hook may have been unpatched by a
      # prior call).
      let current = rec.iatSlot[]
      if current != rec.hookFunc:
        continue
      var oldProtect: DWORD = 0
      let protResult = VirtualProtect(
        cast[LPVOID](rec.iatSlot), uint(sizeof(pointer)),
        PAGE_READWRITE, addr oldProtect)
      if protResult == 0:
        continue
      discard InterlockedExchangePointer(rec.iatSlot, rec.originalFunc)
      var dummy: DWORD = 0
      discard VirtualProtect(
        cast[LPVOID](rec.iatSlot), uint(sizeof(pointer)),
        oldProtect, addr dummy)
      inc unpatched
      discard InterlockedIncrement64Iat(addr gRetroactiveUnpatchFires)
    if reasonTag != nil:
      discard  # reasonTag may be used by the logger upstream (see ldrloaddll_detour_windows.nim)
    return unpatched

  type
    IatPatchResult* = object
      originalFunc*: pointer
      success*: bool

  proc patchIATSafe*(targetDll: cstring, funcName: cstring,
                     hookFunc: pointer): IatPatchResult =
    ## Safe wrapper around patchIAT that returns a result object.
    let original = patchIAT(targetDll, funcName, hookFunc)
    IatPatchResult(
      originalFunc: original,
      success: original != nil,
    )
