## Machine-type decisions for injecting the monitor shim into a Windows child:
## the root a launcher starts (`windows_injector.runWithMonitorShim`) and
## every grandchild a monitored process starts
## (`propagation_windows.injectShimIntoChildReport`, which a shim's spawn hook
## calls). Both apply the same decision, `injectRoute`.
##
## `windows_injector.runWithMonitorShim` loads the shim into a child by running
## `LoadLibraryW` in it, either on its parked main thread or on a remote
## thread. Both need code of the child's own machine and an address the child
## can execute. Neither holds when the child's machine differs from this
## process's: an x64 engine emulated on Windows on Arm that starts a native
## ARM64 child cannot borrow its thread (the park writes x86 bytes), and
## `CreateRemoteThread` with the x64 `LoadLibraryW` address fails with
## `ERROR_INVALID_HANDLE` (6), which used to fail the whole action
## (reprobuild-pm issue 2026-11-20).
##
## The contract is reprobuild-pm spec/Monitor-Hook-Shim.md, "Windows on Arm64
## install backend", "Machine gate": the engine never injects a shim of the
## wrong machine, and a child no shipped shim can serve is resumed uninjected
## and reported as an unmonitored-subtree loss. io-mon's grandchild spawn hook
## applies the same gate and the same `inject=unsupported-process-machine`
## spelling.
##
## This module is pure and deliberately NOT Windows-gated, so the decision is
## unit-tested on every host (`tests/test_windows_machine.nim`); the injector
## only feeds it the machine codes it queried.
##
## Machine codes: https://learn.microsoft.com/windows/win32/sysinfo/image-file-machine-constants
## PE layout (`e_lfanew` at 0x3C, the `PE\0\0` signature, then the COFF
## `Machine` field): https://learn.microsoft.com/windows/win32/debug/pe-format

import std/strutils

{.push raises: [].}

const
  ImageFileMachineUnknown* = 0'u16
    ## The machine could not be determined. Never a guess for another value.
  ImageFileMachineI386* = 0x014C'u16
  ImageFileMachineAmd64* = 0x8664'u16
  ImageFileMachineArm64* = 0xAA64'u16

  PeHeaderWindow* = 4096
    ## How many leading bytes of an image `peFileMachine` reads. `e_lfanew`
    ## of every image the linkers we use produce is far below this.

type
  RootInjectRoute* = enum
    ## How a root or grandchild may be injected.
    rirSameMachine
      ## The child is of this process's machine and so is the shim: this
      ## process's `LoadLibraryW` address is the child's, and the entry park
      ## (whose self-jump and borrowed-call stub are this machine's code) is
      ## sound.
    rirWow64
      ## A 32-bit x86 child of an x64 process: the 32-bit shim, the WOW64
      ## probe's `LoadLibraryW` address and the remote-thread load.
    rirUnsupportedMachine
      ## No shim this process can inject serves the child. It runs
      ## uninjected and nothing is written into it first; a root is reported
      ## through `monitoringSkipped`, a grandchild as `ioUnsupportedMachine`,
      ## so the capture is graded incomplete.
    rirShimMachineMismatch
      ## The shim beside this process is of a different machine than this
      ## process. That is a packaging defect, not a property of the child, so
      ## the injector refuses loudly rather than run every action
      ## unmonitored.

proc hostImageMachine*(): uint16 =
  ## The machine of the image running this code, which is fixed when it is
  ## compiled. An x64 build emulated on Windows on Arm is still `0x8664`:
  ## emulation changes the host, not the process.
  when defined(arm64):
    ImageFileMachineArm64
  elif defined(amd64):
    ImageFileMachineAmd64
  elif defined(i386):
    ImageFileMachineI386
  else:
    ImageFileMachineUnknown

proc readU16(b: openArray[byte]; at: int): uint16 {.inline.} =
  uint16(b[at]) or (uint16(b[at + 1]) shl 8)

proc peImageMachine*(header: openArray[byte]): uint16 =
  ## The COFF `Machine` of a PE image from its leading bytes, or
  ## `ImageFileMachineUnknown` when they are not a whole DOS + PE header.
  if header.len < 0x40 or header[0] != byte('M') or header[1] != byte('Z'):
    return ImageFileMachineUnknown
  # `e_lfanew` is a signed LONG; reinterpret, never range-convert, so a
  # hostile or corrupt header reads as negative and is refused below.
  let lfanew = cast[int32](uint32(header[0x3C]) or
    (uint32(header[0x3D]) shl 8) or (uint32(header[0x3E]) shl 16) or
    (uint32(header[0x3F]) shl 24))
  if lfanew < 0x40 or int(lfanew) + 6 > header.len:
    return ImageFileMachineUnknown
  let at = int(lfanew)
  if header[at] != byte('P') or header[at + 1] != byte('E') or
      header[at + 2] != 0'u8 or header[at + 3] != 0'u8:
    return ImageFileMachineUnknown
  readU16(header, at + 4)

proc peFileMachine*(path: string): uint16 =
  ## `peImageMachine` of the file at `path`; unknown when it cannot be read.
  var f: File
  try:
    if not open(f, path, fmRead):
      return ImageFileMachineUnknown
  except IOError, OSError:
    return ImageFileMachineUnknown
  defer: close(f)
  var buf = newSeq[byte](PeHeaderWindow)
  var got = 0
  try:
    got = readBuffer(f, addr buf[0], buf.len)
  except IOError, OSError:
    return ImageFileMachineUnknown
  peImageMachine(buf.toOpenArray(0, got - 1))

proc injectRoute*(caller, child, childImage, shim: uint16;
                  childIsWow64: bool): RootInjectRoute =
  ## Decide how a root or grandchild may be injected.
  ##
  ## * `caller` -- this process's machine (`hostImageMachine`).
  ## * `child` -- the child's actual process machine, from
  ##   `GetProcessInformation(ProcessMachineTypeInfo)`; unknown where that
  ##   API does not exist (before Windows 11 / Server 2022). Such a host runs
  ##   no x64 emulation, so the WOW64 flag alone tells the routes apart there,
  ##   as it did before this gate existed.
  ## * `childImage` -- the PE machine of the child's image FILE on disk;
  ##   unknown when it cannot be read. It differs from `child` for a hybrid
  ##   image: an ARM64X image (most of System32 on Windows on Arm, cmd.exe
  ##   among them) started by an x64 process runs as an x64-mode (ARM64EC)
  ##   process, so `child` reads `0x8664` while the file is `0xAA64`. Neither
  ##   shim serves such a process: measured on the fleet's Windows on Arm
  ##   class, the x64 park times out on it and the remote-thread load fails
  ##   with err=5. reprobuild-pm spec/Monitor-Hook-Shim.md refuses ARM64EC
  ##   children by name. A WOW64 child is exempt: its image and process
  ##   machines are both x86.
  ## * `shim` -- the machine of the 64-bit (same-bitness) shim image; unknown
  ##   when its header cannot be read, in which case `LoadLibraryW` reports
  ##   the problem as before.
  ## * `childIsWow64` -- `IsWow64Process` of the child.
  ##
  ## A 32-bit caller keeps the routes it had before this gate: it is not a
  ## process the Windows on Arm leg builds, and its 64-bit children go through
  ## `runInject64Helper` rather than this decision.
  if caller notin [ImageFileMachineAmd64, ImageFileMachineArm64]:
    return (if childIsWow64: rirWow64 else: rirSameMachine)
  let effectiveChild =
    if child != ImageFileMachineUnknown: child
    elif childIsWow64: ImageFileMachineI386
    else: caller
  if effectiveChild == ImageFileMachineI386 and childIsWow64:
    # The WOW64 route (32-bit shim, 32-bit probe) is built for an x64 host.
    # An ARM64 caller has no x86 shim to offer (spec: refused "when no
    # x86-64 shim is shipped"), and neither shim of ours is x86 for it.
    return (if caller == ImageFileMachineAmd64: rirWow64
            else: rirUnsupportedMachine)
  if effectiveChild != caller:
    return rirUnsupportedMachine
  if child != ImageFileMachineUnknown and
      childImage != ImageFileMachineUnknown and childImage != child:
    return rirUnsupportedMachine
  if shim != ImageFileMachineUnknown and shim != caller:
    return rirShimMachineMismatch
  rirSameMachine

proc machineName(m: uint16): string =
  case m
  of ImageFileMachineI386: "x86"
  of ImageFileMachineAmd64: "x64"
  of ImageFileMachineArm64: "ARM64"
  of ImageFileMachineUnknown: "unknown"
  else: "other"

proc unsupportedMachineReason*(caller, child: uint16): string =
  ## Why a child is left uninjected by `rirUnsupportedMachine`.
  ## It opens with io-mon's spawn-gate spelling so both ends of the tree read
  ## the same in a capture.
  "inject=unsupported-process-machine:" & toHex(child) & " (" &
    machineName(child) & " child of a " & machineName(caller) & " process, " &
    toHex(caller) & "): no shim of the child's machine can be injected from " &
    "here, so it runs unmonitored and its capture is incomplete"

proc hybridImageReason*(caller, child, image: uint16): string =
  ## Why a hybrid child is left uninjected (see `injectRoute`'s
  ## `childImage`): the process runs as `child` from an image of machine
  ## `image`. Same prefix as `unsupportedMachineReason`.
  "inject=unsupported-process-machine:" & toHex(child) & " (an " &
    machineName(child) & "-mode process of a hybrid " & machineName(image) &
    " image, " & toHex(image) & ", started by a " & machineName(caller) &
    " process): no shim of this process can be injected into it, so it " &
    "runs unmonitored and its capture is incomplete"

type
  MachineGate* = object
    ## One gate decision and the machines it was made from, so a caller can
    ## both act on `route` and report what it saw.
    route*: RootInjectRoute
    caller*, child*, image*, shim*: uint16

proc decideGate*(caller, child, image, shim: uint16;
                 childIsWow64: bool): MachineGate =
  ## `injectRoute`, kept together with its inputs.
  MachineGate(route: injectRoute(caller, child, image, shim, childIsWow64),
    caller: caller, child: child, image: image, shim: shim)

proc gateReason*(g: MachineGate): string =
  ## "" unless the gate refused the child; otherwise the reason, opening
  ## with io-mon's `inject=unsupported-process-machine:<child>` token. A
  ## refused child of the caller's own process machine can only be a hybrid
  ## image (its image file is of another machine).
  if g.route != rirUnsupportedMachine:
    return ""
  if g.child == g.caller:
    hybridImageReason(g.caller, g.child, g.image)
  else:
    unsupportedMachineReason(g.caller, g.child)

proc shimMismatchReason*(caller, shim: uint16; shimPath: string): string =
  ## The error of `rirShimMachineMismatch`.
  "the monitor shim is a " & machineName(shim) & " image (" & toHex(shim) &
    ") but this process is " & machineName(caller) & " (" & toHex(caller) &
    "); the shim must be built for the same machine as the process that " &
    "injects it. shim=" & shimPath

{.pop.}
