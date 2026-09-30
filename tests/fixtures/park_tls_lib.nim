## A real injected DLL with thread-local state and a container allocated at
## module initialization. The tests also compile a deliberately broken variant
## whose probe is process-global; it must fail the same isolation checks.
## No mocks are used.

import std/tables
import ./park_tls_values

when not defined(windows):
  {.error: "park_tls_lib is a Windows fixture".}

proc GetCurrentThreadId(): uint32
  {.importc, stdcall, dynlib: "kernel32".}

when defined(parkTlsSharedProbe):
  var tlsProbe: int
else:
  var tlsProbe {.threadvar.}: int

var
  grown: Table[string, bool] = initTable[string, bool]()
  initTid: uint32 = GetCurrentThreadId()

tlsProbe = InitialProbeValue

proc park_tls_init_tid*(): uint32 {.exportc, cdecl, dynlib.} =
  initTid

proc park_tls_probe_address*(): uint {.exportc, cdecl, dynlib.} =
  cast[uint](addr tlsProbe)

proc park_tls_probe_read*(): int {.exportc, cdecl, dynlib.} =
  tlsProbe

proc park_tls_probe_write*(value: int) {.exportc, cdecl, dynlib.} =
  tlsProbe = value

proc park_tls_grow*(n: cint): cint {.exportc, cdecl, dynlib.} =
  # Every rehash frees storage allocated by the DLL's initializing thread.
  for i in 0 ..< int(n):
    grown["park-tls-key-" & $i] = true
  cint(grown.len)
