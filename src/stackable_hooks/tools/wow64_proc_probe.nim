## 32-bit proc-address probe for WOW64 injection.
##
## ## Why this exists
##
## The Windows injector resolves ``LoadLibraryW`` with ``GetProcAddress`` in
## its OWN process and hands that address to ``CreateRemoteThread`` in the
## child. That is sound only while injector and child share a bitness: a
## 64-bit process and a WOW64 (32-bit) process load *different* copies of
## ``kernel32.dll`` — ``C:\Windows\System32`` versus
## ``C:\Windows\SysWOW64`` — at unrelated base addresses. Passing the
## 64-bit address into a 32-bit child does not fault cleanly; it starts a
## remote thread at a meaningless address.
##
## A 64-bit process cannot call ``GetProcAddress`` against the 32-bit
## kernel32 directly (``LoadLibraryW`` of SysWOW64\kernel32.dll from a
## 64-bit process fails: the image machine type does not match). Reading
## the child's PEB/module list and parsing its export table would work but
## means hand-rolling a PE parser inside the injector.
##
## The cheap alternative, and the one implemented here: ask a 32-bit
## process. This program runs as a WOW64 process, so ``GetModuleHandleW`` +
## ``GetProcAddress`` resolve against exactly the kernel32 the child will
## use, and it reports the answer through the one channel every process has
## regardless of bitness — **its exit code**.
##
## A Windows exit code is a ``DWORD``, which is exactly wide enough to carry
## a 32-bit pointer with no encoding, framing or stdio involved. Nothing has
## to be parsed and nothing can be truncated.
##
## ## Contract
##
## Two modes, selected by argument count:
##
##   * **kernel32 address** (0 or 1 args) — exit code is the address of the
##     requested proc in *this* (32-bit) process's kernel32. ``argv[1]``, when
##     present, names the proc; it defaults to ``LoadLibraryW`` so the common
##     case needs no arguments.
##   * **export RVA** (2 args: a DLL path and a proc name) — exit code is the
##     offset of that export from the DLL's base address.
##
##   * Exit code ``0`` = resolution failed, in either mode. No proc lives at
##     address 0, and no export sits at RVA 0 (that offset is the DOS
##     header), so 0 is unambiguous.
##
## ### Why the RVA mode exists
##
## After ``LoadLibraryW`` has run in the child, the injector needs to call
## ``repro_runtime_init`` there, which means knowing where that export landed.
## It used to compute the offset by loading the same DLL in ITSELF and
## subtracting the base — sound for a same-bitness shim, and impossible for a
## 32-bit one: a 64-bit process cannot ``LoadLibraryW`` a 32-bit image at all.
## The load simply failed, the offset was never computed, and the shim sat in
## the child fully loaded with its init never called — hooks uninstalled, not
## one record emitted, and no error anywhere, because loading the DLL had
## genuinely succeeded.
##
## An offset is bitness-agnostic once you can read the image's exports, and a
## 32-bit process can. Hence the second mode: same channel, same failure
## convention, no PE parser.
##
## The DLL is loaded with ``DONT_RESOLVE_DLL_REFERENCES`` so its ``DllMain``
## does NOT run. Resolving an export needs only the mapped image, and running
## a monitor shim's initialiser inside the probe would install hooks in the
## probe and emit stray records into whatever fragment directory the ambient
## environment names.
##
## The caller is expected to invoke this once per session and cache the
## result — the address is stable for the lifetime of a boot session
## (kernel32 is loaded at the same base in every WOW64 process), so paying
## a process spawn per injection would be waste.
##
## ## Building
##
## MUST be built 32-bit; the ``sizeof(pointer)`` guard below fails the
## compile otherwise, because a 64-bit build of this file would silently
## report the wrong address:
##
##     nim c --cpu:i386 --cc:gcc --out:stackable_hooks_wow64_probe32.exe \
##       src/stackable_hooks/tools/wow64_proc_probe.nim
##
## The produced executable is expected to sit beside the 32-bit shim under
## the name ``stackable_hooks_wow64_probe32.exe`` — see
## ``windows_injector.nim``'s naming-convention section.

when not defined(windows):
  {.error: "stackable_hooks/tools/wow64_proc_probe is Windows-only".}

when sizeof(pointer) != 4:
  {.error: "wow64_proc_probe MUST be compiled 32-bit (--cpu:i386): a 64-bit " &
           "build would resolve the 64-bit kernel32 and report an address " &
           "that is useless to a WOW64 child".}

import std/os

type
  HANDLE = pointer
  LPCWSTR = ptr uint16

const DONT_RESOLVE_DLL_REFERENCES = 0x00000001'u32

proc GetModuleHandleW(lpModuleName: LPCWSTR): HANDLE
  {.importc: "GetModuleHandleW", stdcall, dynlib: "kernel32".}
proc GetProcAddress(hModule: HANDLE, lpProcName: cstring): pointer
  {.importc: "GetProcAddress", stdcall, dynlib: "kernel32".}
proc LoadLibraryExW(lpLibFileName: LPCWSTR, hFile: HANDLE,
                    dwFlags: uint32): HANDLE
  {.importc: "LoadLibraryExW", stdcall, dynlib: "kernel32".}

proc toWide(s: string): seq[uint16] =
  result = newSeq[uint16](s.len + 1)
  for i, c in s:
    result[i] = uint16(ord(c))
  result[s.len] = 0

proc exportRva(dllPath, procName: string): int =
  ## Offset of `procName` from the base of `dllPath`, or 0 if it cannot be
  ## resolved. DONT_RESOLVE_DLL_REFERENCES maps the image without running its
  ## DllMain or loading its dependencies -- everything GetProcAddress needs,
  ## and nothing that would let the mapped DLL act.
  var pathW = toWide(dllPath)
  let module = LoadLibraryExW(cast[LPCWSTR](addr pathW[0]), nil,
    DONT_RESOLVE_DLL_REFERENCES)
  if module == nil:
    return 0
  let resolved = GetProcAddress(module, procName.cstring)
  if resolved == nil:
    return 0
  # Deliberately not FreeLibrary'd: the process is about to exit, and the
  # offset must stay valid until it is reported.
  int(cast[uint](resolved) - cast[uint](module))

proc kernel32Address(procName: string): int =
  var moduleName = toWide("kernel32.dll")
  let kernel32 = GetModuleHandleW(cast[LPCWSTR](addr moduleName[0]))
  if kernel32 == nil:
    return 0
  let resolved = GetProcAddress(kernel32, procName.cstring)
  if resolved == nil:
    return 0
  # `int` is 32-bit in this build, so the cast is exact and the OS receives
  # the pointer verbatim as the process exit code.
  cast[int](resolved)

proc main() =
  if paramCount() >= 2:
    quit(exportRva(paramStr(1), paramStr(2)))

  let procName =
    if paramCount() >= 1 and paramStr(1).len > 0: paramStr(1)
    else: "LoadLibraryW"
  quit(kernel32Address(procName))

main()
