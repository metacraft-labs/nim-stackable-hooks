## Real Windows processes and inherited OS pipes; no mock objects.
## Kernel32 is a real DLL load through the injector. Hook behavior is outside
## this capture regression: the contract under test is root-exit completion.
import std/[os, osproc, strutils, tempfiles]
import stackable_hooks/windows_injector

const
  RootArg = "--capture-root"
  WriterArg = "--capture-writer"
  Payload = repeat("captured-root-output\n", 2048) & "root-final-stdout\n"
  ErrorTail = "root-final-stderr\n"

proc waitForFile(path: string, attempts: int): bool =
  for _ in 0 ..< attempts:
    if fileExists(path):
      return true
    sleep(10)

if paramCount() == 2:
  let folder = paramStr(2)
  if paramStr(1) == WriterArg:
    # Keep the inherited stdout/stderr writers alive without producing bytes.
    # A hard 20-second bound makes the original EOF defect fail, not hang CI.
    writeFile(folder / "writer-ready", "ready")
    discard waitForFile(folder / "release-writer", 2000)
    writeFile(folder / "writer-finished.tmp", "finished")
    moveFile(folder / "writer-finished.tmp", folder / "writer-finished")
    quit(0)
  if paramStr(1) == RootArg:
    let writer = startProcess(getAppFilename(), args = @[WriterArg, folder],
      options = {poUsePath, poParentStreams})
    close(writer)
    if not waitForFile(folder / "writer-ready", 1000):
      quit(40)
    stdout.write(Payload)
    stdout.flushFile()
    stderr.write(ErrorTail)
    stderr.flushFile()
    quit(17)

let folder = createTempDir("stackable-hooks-", "-capture-root-exit")
try:
  let captured = folder / "captured.log"
  let systemDll = getEnv("SystemRoot", r"C:\Windows") / "System32" / "kernel32.dll"
  let outcome = runWithMonitorShim(@[getAppFilename(), RootArg, folder],
    systemDll, captureStdio = true, captureStdioPath = captured)
  let descendantExited = fileExists(folder / "writer-finished")
  echo "capture-root-exit=", outcome.exitCode,
    " descendant-exited=", descendantExited
  doAssert outcome.exitCode == 17, "root exit code was lost"
  doAssert not outcome.monitoringSkipped, "root DLL injection was skipped"
  doAssert readFile(captured) == Payload & ErrorTail,
    "buffered root stdout/stderr was lost"
  doAssert not descendantExited,
    "captured output waited for descendant pipe EOF after root exit"
finally:
  writeFile(folder / "release-writer", "release")
  if waitForFile(folder / "writer-finished", 1000):
    # The writer publishes completion immediately before process exit.
    removeDir(folder)

echo "root-exit capture and surviving-writer assertions passed"
