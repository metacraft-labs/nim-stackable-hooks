## Injection fixture for ``tests/test_windows_entry_park_msys.nim``.
##
## Built with ``nim c --app:lib`` by the test, and injected into a live
## MSYS2/Cygwin shell. It exists to make the passing case NON-VACUOUS: it
## has a real ``DllMain`` doing real work (Nim's generated ``DllMain``
## calls ``NimMain`` on ``DLL_PROCESS_ATTACH``, which initialises the Nim
## runtime and then runs this module body), and it leaves a durable
## side effect the test can read back.
##
## Anything mapped-and-inert would prove nothing: the whole hazard is what
## the loader does on the injecting thread, and a DLL whose constructor
## never runs never reaches it. Appending one line per attach also lets the
## test count attaches rather than merely observing that the file exists.

import std/os

proc recordAttach() =
  let path = getEnv("STACKABLE_HOOKS_PARK_MARK")
  if path.len == 0:
    return
  try:
    let f = open(path, fmAppend)
    defer: f.close()
    f.write("ATTACH pid=" & $getCurrentProcessId() & "\n")
  except CatchableError:
    # A fixture that raises out of DllMain would fail the child for a
    # reason unrelated to what the test is measuring.
    discard

recordAttach()
