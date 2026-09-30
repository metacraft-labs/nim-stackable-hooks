## Real child of the entry-parking fixture. Exit codes identify the failing
## property: 3 = no DLL/exports, 4 = wrong initializing thread, 5 = broken
## thread-local state or worker lifecycle, 6 = failed container growth.
##
## Native TLS and GCC emulated TLS both satisfy the value/address isolation
## contract. Neither requires assumptions about offsets in Windows' TEB.

import std/os
import ./park_tls_values

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
  addressProc {.global.}: proc(): uint {.cdecl.}
  readProc {.global.}: proc(): int {.cdecl.}
  writeProc {.global.}: proc(value: int) {.cdecl.}
  freshAddress {.global.}: uint
  freshInitial, freshStored {.global.}: int

proc freshThreadMain(p: pointer): DWORD {.stdcall.} =
  discard p
  freshAddress = addressProc()
  freshInitial = readProc()
  writeProc(FreshProbeValue)
  freshStored = readProc()
  0

when isMainModule:
  let libPath = getEnv("STACKABLE_HOOKS_TLS_LIB")
  var libW = toWide(extractFilename(libPath))
  let h = GetModuleHandleW(addr libW[0])
  if h == nil:
    quit(3)

  let initTidSym = GetProcAddress(h, "park_tls_init_tid")
  let addressSym = GetProcAddress(h, "park_tls_probe_address")
  let readSym = GetProcAddress(h, "park_tls_probe_read")
  let writeSym = GetProcAddress(h, "park_tls_probe_write")
  let growSym = GetProcAddress(h, "park_tls_grow")
  if initTidSym == nil or addressSym == nil or readSym == nil or
      writeSym == nil or growSym == nil:
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

  addressProc = cast[proc(): uint {.cdecl.}](addressSym)
  readProc = cast[proc(): int {.cdecl.}](readSym)
  writeProc = cast[proc(value: int) {.cdecl.}](writeSym)
  let mainAddress = addressProc()
  if mainAddress == 0 or readProc() != InitialProbeValue:
    quit(5)
  writeProc(MainProbeValue)
  var tid: DWORD = 0
  let t = CreateThread(nil, 0, freshThreadMain, nil, 0, addr tid)
  if t == nil:
    quit(5)
  let waited = WaitForSingleObject(t, 30_000'u32)
  discard CloseHandle(t)
  if waited != 0 or freshAddress == 0 or freshAddress == mainAddress or
      freshInitial != 0 or freshStored != FreshProbeValue or
      addressProc() != mainAddress or readProc() != MainProbeValue:
    quit(5)

  # 300 distinct keys rehash the table repeatedly; the first rehash frees
  # the array the DLL allocated in its module body.
  let grow = cast[proc(n: cint): cint {.cdecl.}](growSym)
  if grow(300'i32) != 300'i32:
    quit(6)
  quit(0)
