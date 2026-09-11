## Child fixture for ``tests/test_windows_entry_park_thread_locals.nim``.
##
## An ordinary console program. By the time ``main`` runs, the test has
## already injected ``park_tls_lib.dll`` into it -- either by borrowing this
## very thread (the technique under test) or with a remote thread (the
## control). Everything below is measured ON THE MAIN THREAD, because that
## is the thread that matters: it is the one that runs the whole program and
## outlives every helper.
##
## Exit codes are distinct so a failure says WHICH half broke:
##
##   0  every check passed
##   3  the fixture DLL is not mapped, or its exports are missing -- nothing
##      was injected, so the run proves nothing either way and must not be
##      read as a pass on either arm
##   4  the DLL's module initialisation ran on some OTHER thread. Its
##      process-global container is therefore owned by a `MemRegion` that
##      belongs to a thread this process does not control and may already
##      have destroyed; every later free of it from here is a use-after-free
##      whose visibility is a matter of heap layout
##   5  this thread's copy of the DLL's threadvar sits at a different offset
##      from the module's TLS block than a thread created after the
##      injection sees, i.e. this thread's `_tls_index` slot does not point
##      at this module's block
##   6  the container the DLL allocated at init did not survive being grown
##      from here
##
## A crash (0xC0000005, or Nim's SIGSEGV handler turning it into 1) is
## another way to fail, and the test accepts it on the control arm for the
## same reason: it means the main thread could not safely use the DLL.

import std/os

when not defined(windows):
  {.error: "park_tls_child is a Windows fixture".}

type
  DWORD = uint32
  HANDLE = pointer

proc GetModuleHandleW(name: ptr uint16): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc GetProcAddress(m: HANDLE, name: cstring): pointer
  {.importc, stdcall, dynlib: "kernel32".}
proc GetCurrentThreadId(): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc CreateThread(sa: pointer, stack: uint,
                  start: proc(p: pointer): DWORD {.stdcall.}, param: pointer,
                  flags: DWORD, tid: ptr DWORD): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc WaitForSingleObject(h: HANDLE, ms: DWORD): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc CloseHandle(h: HANDLE): int32
  {.importc, stdcall, dynlib: "kernel32".}

proc toWide(s: string): seq[uint16] =
  result.setLen(s.len + 1)
  for i, c in s:
    result[i] = uint16(c)
  result[s.len] = 0'u16

var
  offsetProc {.global.}: proc(): uint {.cdecl.}
  freshOffset {.global.}: uint

proc freshThreadMain(p: pointer): DWORD {.stdcall.} =
  ## A thread created AFTER the injection. The loader provisions those
  ## correctly whatever technique was used, so its offset is the reference
  ## the main thread is compared against.
  discard p
  freshOffset = offsetProc()
  0

when isMainModule:
  let libPath = getEnv("STACKABLE_HOOKS_TLS_LIB")
  var libW = toWide(extractFilename(libPath))
  let h = GetModuleHandleW(addr libW[0])
  if h == nil:
    quit(3)

  let initTidSym = GetProcAddress(h, "park_tls_init_tid")
  let offsetSym = GetProcAddress(h, "park_tls_offset")
  let growSym = GetProcAddress(h, "park_tls_grow")
  if initTidSym == nil or offsetSym == nil or growSym == nil:
    quit(3)

  # Reached the DLL and its exports, so the run is meaningful whatever
  # happens next. The test reads this file to tell "the control failed
  # because of the defect" from "the control failed because nothing was
  # injected", which would prove nothing.
  let mark = getEnv("STACKABLE_HOOKS_TLS_MARK")
  if mark.len > 0:
    try: writeFile(mark, "LOADED\n")
    except CatchableError: discard

  let initTid = cast[proc(): DWORD {.cdecl.}](initTidSym)()
  if initTid != GetCurrentThreadId():
    quit(4)

  offsetProc = cast[proc(): uint {.cdecl.}](offsetSym)
  let mainOffset = offsetProc()
  var tid: DWORD = 0
  let t = CreateThread(nil, 0, freshThreadMain, nil, 0, addr tid)
  if t != nil:
    discard WaitForSingleObject(t, 30_000'u32)
    discard CloseHandle(t)
    if mainOffset != freshOffset:
      quit(5)

  # 300 distinct keys rehash the table repeatedly; the first rehash frees
  # the array the DLL allocated in its module body.
  let grow = cast[proc(n: cint): cint {.cdecl.}](growSym)
  if grow(300'i32) != 300'i32:
    quit(6)
  quit(0)
