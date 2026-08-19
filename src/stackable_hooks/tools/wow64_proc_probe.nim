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
##   * Exit code = the address of the requested proc in *this* (32-bit)
##     process's kernel32.
##   * Exit code ``0`` = resolution failed. ``LoadLibraryW`` is never at
##     address 0, so 0 is unambiguous as a failure signal.
##   * ``argv[1]``, when present, names the proc to resolve; it defaults to
##     ``LoadLibraryW`` so the common case needs no arguments.
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

proc GetModuleHandleW(lpModuleName: LPCWSTR): HANDLE
  {.importc: "GetModuleHandleW", stdcall, dynlib: "kernel32".}
proc GetProcAddress(hModule: HANDLE, lpProcName: cstring): pointer
  {.importc: "GetProcAddress", stdcall, dynlib: "kernel32".}

proc toWide(s: string): seq[uint16] =
  result = newSeq[uint16](s.len + 1)
  for i, c in s:
    result[i] = uint16(ord(c))
  result[s.len] = 0

proc main() =
  let procName =
    if paramCount() >= 1 and paramStr(1).len > 0: paramStr(1)
    else: "LoadLibraryW"

  var moduleName = toWide("kernel32.dll")
  let kernel32 = GetModuleHandleW(cast[LPCWSTR](addr moduleName[0]))
  if kernel32 == nil:
    quit(0)

  let resolved = GetProcAddress(kernel32, procName.cstring)
  if resolved == nil:
    quit(0)

  # `int` is 32-bit in this build, so the cast is exact and the OS receives
  # the pointer verbatim as the process exit code.
  quit(cast[int](resolved))

main()
