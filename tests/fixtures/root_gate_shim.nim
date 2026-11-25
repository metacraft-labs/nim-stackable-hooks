## Shim stand-in for ``tests/test_windows_root_machine_gate.nim``.
##
## Built with ``nim c --app:lib`` for the test binary's own CPU and injected
## by ``runWithMonitorShim`` into real children. It records the two steps the
## injector performs, so the test can tell "injected and initialised" from
## "left alone" by reading a file rather than by trusting the injector's own
## report:
##
## * ``ATTACH`` -- the module body, run by Nim's generated ``DllMain`` on
##   ``DLL_PROCESS_ATTACH``, i.e. the shim was loaded into the child;
## * ``INIT`` -- ``repro_runtime_init``, the export the injector calls
##   explicitly after the load (Nim's ``--app:lib`` does not call user code
##   on attach; reprobuild-pm spec/Monitor-Hook-Shim.md, "Grandchild
##   propagation").
##
## Each line carries the pid, so a stray record from another process cannot
## be mistaken for the root's.

import std/os

proc record(what: string) =
  let path = getEnv("STACKABLE_HOOKS_ROOT_GATE_MARK")
  if path.len == 0:
    return
  try:
    let f = open(path, fmAppend)
    defer: f.close()
    f.write(what & " pid=" & $getCurrentProcessId() & "\n")
  except CatchableError:
    # Raising out of DllMain or the init export would fail the child for a
    # reason unrelated to what the test measures.
    discard

proc repro_runtime_init() {.exportc, dynlib, cdecl.} =
  record("INIT")

record("ATTACH")
