## Fixture DLL for ``tests/test_windows_entry_park_slow_call.nim``.
##
## Loading it is SLOW: its module initialiser, which the Nim runtime runs
## from ``DllMain(DLL_PROCESS_ATTACH)`` and therefore inside the child's
## ``LoadLibraryW``, sleeps for ``STACKABLE_HOOKS_SLOW_LOAD_MS``
## milliseconds. That makes the borrowed ``LoadLibraryW`` a real, slow call
## in a real child, which is the situation an I/O-starved build host
## produced by accident: a healthy child whose injection takes longer than
## the injector used to be willing to wait.
##
## The value is read from the CHILD's environment, which it inherits from
## the test, so each test case picks its own delay.
##
## ``slow_load_lib_init`` is a slow init export for the detach case: see its
## docstring.
##
## Win32 is called directly rather than through ``std/os`` so that the
## fixture does as little as possible under the loader lock.

when not defined(windows):
  {.error: "slow_load_lib is a Windows fixture".}

proc GetEnvironmentVariableW(name: ptr uint16; buf: ptr uint16;
                             size: uint32): uint32
  {.importc, stdcall, dynlib: "kernel32".}
proc Sleep(ms: uint32) {.importc, stdcall, dynlib: "kernel32".}

proc envMs(name: static string): uint32 =
  var nameW: array[name.len + 1, uint16]
  for i, c in name:
    nameW[i] = uint16(c)
  var buf: array[32, uint16]
  let n = GetEnvironmentVariableW(addr nameW[0], addr buf[0],
    uint32(buf.len))
  if n == 0 or n >= uint32(buf.len):
    return 0
  for i in 0 ..< int(n):
    let d = buf[i]
    if d < uint16('0') or d > uint16('9'):
      return 0
    result = result * 10 + uint32(d - uint16('0'))

let delay = envMs("STACKABLE_HOOKS_SLOW_LOAD_MS")
if delay > 0:
  Sleep(delay)

proc slow_load_lib_marker(): int32 {.exportc, dynlib, stdcall.} =
  ## Present so the image has an export table like a real shim's; unused.
  42

proc CreateFileW(name: ptr uint16; access, share: uint32; sa: pointer;
                 disposition, flags: uint32; tmpl: pointer): pointer
  {.importc, stdcall, dynlib: "kernel32".}
proc CloseHandle(h: pointer): int32 {.importc, stdcall, dynlib: "kernel32".}

proc slow_load_lib_init(): int32 {.exportc, dynlib, stdcall.} =
  ## Stands in for a shim's init export, for the detach test: sleeps for
  ## ``STACKABLE_HOOKS_SLOW_INIT_MS`` and then creates the file named by
  ## ``STACKABLE_HOOKS_INIT_MARKER`` -- the observable "it went on to install
  ## its hooks" of a call the injector stopped waiting for.
  let ms = envMs("STACKABLE_HOOKS_SLOW_INIT_MS")
  if ms > 0:
    Sleep(ms)
  const name = "STACKABLE_HOOKS_INIT_MARKER"
  var nameW: array[name.len + 1, uint16]
  for i, c in name:
    nameW[i] = uint16(c)
  var path: array[1024, uint16]
  let n = GetEnvironmentVariableW(addr nameW[0], addr path[0],
    uint32(path.len))
  if n == 0 or n >= uint32(path.len):
    return 0
  const GenericWrite = 0x40000000'u32
  const CreateAlways = 2'u32
  let h = CreateFileW(addr path[0], GenericWrite, 0, nil, CreateAlways, 0,
    nil)
  if h == nil or h == cast[pointer](-1):
    return 0
  discard CloseHandle(h)
  1
