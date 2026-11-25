## `runWithMonitorShim(job = …)`: the root joins the caller's Job Object before
## it runs, and a refused assignment is reported, not raised.
##
## Real Windows processes and real Job Objects; no mocks. As in
## test_windows_injector_capture, kernel32.dll stands in for the shim: it is a
## real DLL load through the injector, and nothing here depends on hooks.
##
## Three properties, each against a real kernel object:
##  1. `job = nil` is the old behaviour: no assignment is attempted or reported.
##  2. With a job, the ROOT and the GRANDCHILD it spawns are both members. The
##     grandchild is created by the root's first act, so it can only be a
##     member if the root was one before it ran (a process created by a
##     non-member is not added to the job later).
##  3. A refused assignment is reported with the real error, the root's job
##     membership, and the root still runs. The refusal is provoked honestly:
##     a helper host nests itself into jobs until the kernel's depth limit
##     (measured: 101 levels on Windows 11 26200; the next assignment fails
##     with ERROR_NOT_SUPPORTED), so its child inherits a chain that cannot
##     take one more level.
import std/[os, osproc]
import stackable_hooks/windows_injector

type
  HANDLE = pointer
  DWORD = uint32
  BOOL = int32
  BasicAccounting {.bycopy.} = object
    ## JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    totalUser, totalKernel, periodUser, periodKernel: int64
    pageFaults, totalProcesses, activeProcesses, terminated: DWORD

proc CreateJobObjectW(attrs, name: pointer): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc AssignProcessToJobObject(job, process: HANDLE): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc QueryInformationJobObject(job: HANDLE; cls: int32; info: pointer;
    len: DWORD; ret: ptr DWORD): BOOL {.importc, stdcall, dynlib: "kernel32".}
proc CloseHandle(h: HANDLE): BOOL {.importc, stdcall, dynlib: "kernel32".}
proc GetCurrentProcess(): HANDLE {.importc, stdcall, dynlib: "kernel32".}
proc CreateIoCompletionPort(file, existing: HANDLE; key: uint;
    threads: DWORD): HANDLE {.importc, stdcall, dynlib: "kernel32".}
proc SetInformationJobObject(job: HANDLE; cls: int32; info: pointer;
    len: DWORD): BOOL {.importc, stdcall, dynlib: "kernel32".}
proc GetQueuedCompletionStatus(port: HANDLE; bytes: ptr DWORD; key: ptr uint;
    overlapped: ptr pointer; ms: DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}

type
  AssociateCompletionPort {.bycopy.} = object
    ## JOBOBJECT_ASSOCIATE_COMPLETION_PORT
    completionKey: pointer
    completionPort: HANDLE

const
  JobObjectAssociateCompletionPortInformation = 7'i32
  JobObjectMsgActiveProcessZero = 4'u32
  InvalidHandleValue = cast[HANDLE](-1)

proc watchJob(job: HANDLE): HANDLE =
  ## Associate a completion port with `job` BEFORE anything joins it, so its
  ## JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO is not missed. That message, not the
  ## root's own exit, is what says the job is empty: a process leaves the
  ## job's active count during its teardown, and nothing orders that against
  ## the root's handle becoming signalled. Reading the count straight after
  ## `runWithMonitorShim` returned saw `active=1` on a native ARM64 host
  ## (nim-stackable-hooks run 45595100361).
  ## https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_associate_completion_port
  result = CreateIoCompletionPort(InvalidHandleValue, nil, 0, 1)
  doAssert result != nil, "CreateIoCompletionPort failed"
  var assoc = AssociateCompletionPort(completionKey: job, completionPort: result)
  doAssert SetInformationJobObject(job,
    JobObjectAssociateCompletionPortInformation, addr assoc,
    DWORD(sizeof(assoc))) != 0, "associating the completion port failed"

proc waitJobEmpty(port: HANDLE; timeoutMs: DWORD): bool =
  ## True once the job reports ACTIVE_PROCESS_ZERO within `timeoutMs`. The
  ## timeout is a hang guard only: a job whose members have all exited posts
  ## the message promptly.
  while true:
    var msg: DWORD
    var key: uint
    var ov: pointer
    if GetQueuedCompletionStatus(port, addr msg, addr key, addr ov,
        timeoutMs) == 0:
      return false
    if msg == JobObjectMsgActiveProcessZero:
      return true

const
  RootArg = "--job-root"
  GrandchildArg = "--job-grandchild"
  DeepHostArg = "--job-deep-host"
  RootExit = 23

let systemDll = getEnv("SystemRoot", r"C:\Windows") / "System32" / "kernel32.dll"

proc accounting(job: HANDLE): BasicAccounting =
  doAssert QueryInformationJobObject(job, 1, addr result,
    DWORD(sizeof(result)), nil) != 0, "accounting query failed"

if paramCount() >= 1:
  case paramStr(1)
  of GrandchildArg:
    quit(0)
  of RootArg:
    let child = startProcess(getAppFilename(), args = @[GrandchildArg],
      options = {poParentStreams})
    discard waitForExit(child)
    close(child)
    quit(RootExit)
  of DeepHostArg:
    while true:
      let job = CreateJobObjectW(nil, nil)
      doAssert job != nil
      if AssignProcessToJobObject(job, GetCurrentProcess()) == 0:
        discard CloseHandle(job)
        break
    let fresh = CreateJobObjectW(nil, nil)
    let outcome = runWithMonitorShim(@[getAppFilename(), RootArg], systemDll,
      job = fresh)
    echo "deep: exit=", outcome.exitCode, " assigned=", outcome.jobAssigned,
      " err=", outcome.jobAssignError,
      " membership=", outcome.jobAssignRootMembership
    doAssert outcome.exitCode == RootExit, "the root must still run"
    doAssert not outcome.jobAssigned
    doAssert outcome.jobAssignError == 50, "expected ERROR_NOT_SUPPORTED"
    doAssert outcome.jobAssignRootMembership == rjmInJob
    # Nothing was ever added to the fresh job.
    doAssert accounting(fresh).totalProcesses == 0
    discard CloseHandle(fresh)
    quit(0)
  else:
    discard

block noJob:
  let outcome = runWithMonitorShim(@[getAppFilename(), RootArg], systemDll)
  doAssert outcome.exitCode == RootExit
  doAssert not outcome.jobAssigned
  doAssert outcome.jobAssignError == 0
  doAssert outcome.jobAssignRootMembership == rjmNotChecked

block withJob:
  let job = CreateJobObjectW(nil, nil)
  doAssert job != nil
  let port = watchJob(job)
  let outcome = runWithMonitorShim(@[getAppFilename(), RootArg], systemDll,
    job = job)
  doAssert waitJobEmpty(port, 60_000), "the job never reported itself empty"
  discard CloseHandle(port)
  let acct = accounting(job)
  echo "job: exit=", outcome.exitCode, " assigned=", outcome.jobAssigned,
    " total=", acct.totalProcesses, " active=", acct.activeProcesses
  doAssert outcome.exitCode == RootExit
  doAssert outcome.jobAssigned
  doAssert outcome.jobAssignError == 0
  doAssert outcome.jobAssignRootMembership == rjmNotChecked
  # The root and the grandchild it created as its first act: both members.
  doAssert acct.totalProcesses == 2, "expected root + grandchild in the job"
  doAssert acct.activeProcesses == 0, "both have exited"
  discard CloseHandle(job)

block refusedAssignment:
  let host = startProcess(getAppFilename(), args = @[DeepHostArg],
    options = {poParentStreams})
  let code = waitForExit(host)
  close(host)
  doAssert code == 0, "deep-host case failed with exit " & $code

echo "runWithMonitorShim job assignment assertions passed"
