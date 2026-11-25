## Unit tests for `stackable_hooks/windows_machine`: which shim, if any, the
## root injector may put into a child of a given machine.
##
## The module is pure and not Windows-gated, so the decision that caused
## reprobuild-pm issue 2026-11-20 -- an x64 engine on a Windows on Arm host
## calling `CreateRemoteThread(LoadLibraryW)` into a native ARM64 child, which
## failed with err=6 and failed the action -- is asserted here on every host.
## The live counterpart, which spawns real children on a native ARM64 host, is
## `test_windows_root_machine_gate`.
##
## Contract under test: reprobuild-pm spec/Monitor-Hook-Shim.md, "Windows on
## Arm64 install backend", "Machine gate": "The engine never injects a shim of
## the wrong machine."
##
## No mocks: the subjects are pure functions over machine codes and bytes.

import std/[os, strutils, unittest]

import stackable_hooks/windows_machine

proc peHeader(machine: uint16; lfanew = 0x80): seq[byte] =
  ## The smallest byte string `peImageMachine` reads: a DOS header whose
  ## `e_lfanew` points at a `PE\0\0` signature and the COFF `Machine` field.
  result = newSeq[byte](lfanew + 6)
  result[0] = byte('M')
  result[1] = byte('Z')
  result[0x3C] = byte(lfanew and 0xFF)
  result[0x3D] = byte((lfanew shr 8) and 0xFF)
  result[lfanew] = byte('P')
  result[lfanew + 1] = byte('E')
  result[lfanew + 4] = byte(machine and 0xFF)
  result[lfanew + 5] = byte(machine shr 8)

suite "PE machine of an image":
  test "reads the COFF Machine field of each supported machine":
    for m in [ImageFileMachineI386, ImageFileMachineAmd64,
              ImageFileMachineArm64]:
      check peImageMachine(peHeader(m)) == m

  test "follows e_lfanew wherever it points inside the header window":
    check peImageMachine(peHeader(ImageFileMachineArm64, 0x40)) ==
      ImageFileMachineArm64
    check peImageMachine(peHeader(ImageFileMachineArm64, 0xF8)) ==
      ImageFileMachineArm64

  test "anything that is not a whole PE header is unknown, never a guess":
    check peImageMachine(newSeq[byte]()) == ImageFileMachineUnknown
    var noMz = peHeader(ImageFileMachineAmd64)
    noMz[0] = byte('X')
    check peImageMachine(noMz) == ImageFileMachineUnknown
    var noPe = peHeader(ImageFileMachineAmd64)
    noPe[0x80] = byte('X')
    check peImageMachine(noPe) == ImageFileMachineUnknown
    let truncated = peHeader(ImageFileMachineAmd64)[0 ..< 0x80 + 5]
    check peImageMachine(truncated) == ImageFileMachineUnknown
    var negative = peHeader(ImageFileMachineAmd64)
    negative[0x3F] = 0x80'u8   # e_lfanew < 0
    check peImageMachine(negative) == ImageFileMachineUnknown

  test "an image file on disk: this test's own executable":
    # On Windows the test binary is a PE of exactly this process's machine;
    # elsewhere it is not a PE at all, and must not be read as one.
    let fromFile = peFileMachine(getAppFilename())
    when defined(windows):
      check fromFile == hostImageMachine()
    else:
      check fromFile == ImageFileMachineUnknown
    check peFileMachine(getAppFilename() & ".does-not-exist") ==
      ImageFileMachineUnknown

  test "the host machine is the one this process was compiled for":
    when defined(arm64):
      check hostImageMachine() == ImageFileMachineArm64
    elif defined(amd64):
      check hostImageMachine() == ImageFileMachineAmd64
    elif defined(i386):
      check hostImageMachine() == ImageFileMachineI386

suite "root injection route":
  const
    x86 = ImageFileMachineI386
    x64 = ImageFileMachineAmd64
    a64 = ImageFileMachineArm64
    unknown = ImageFileMachineUnknown

  test "issue 2026-11-20: an x64 engine never injects a native ARM64 child":
    check rootInjectRoute(caller = x64, child = a64, childImage = a64,
      shim = x64, childIsWow64 = false) == rirUnsupportedMachine

  test "a native ARM64 engine injects its ARM64 shim into an ARM64 child":
    check rootInjectRoute(a64, a64, a64, a64, false) == rirSameMachine

  test "a native ARM64 engine refuses every other child (no x64 shim ships)":
    check rootInjectRoute(a64, x64, x64, a64, false) == rirUnsupportedMachine
    # An x86 child of an ARM64 parent is WOW64 on Windows on Arm; the WOW64
    # route is the x64 host's and is never taken from an ARM64 caller.
    check rootInjectRoute(a64, x86, x86, a64, true) == rirUnsupportedMachine
    check rootInjectRoute(a64, unknown, x86, a64, true) == rirUnsupportedMachine

  test "the x64 routes are unchanged":
    check rootInjectRoute(x64, x64, x64, x64, false) == rirSameMachine
    check rootInjectRoute(x64, x86, x86, x64, true) == rirWow64

  test "an unknown child machine keeps the pre-gate behaviour":
    # `GetProcessInformation(ProcessMachineTypeInfo)` exists from Windows 11
    # and Server 2022 on. Where it is missing the host emulates no x64, so
    # the WOW64 flag alone still tells the routes apart, as it always did.
    check rootInjectRoute(x64, unknown, unknown, x64, false) == rirSameMachine
    check rootInjectRoute(x64, unknown, unknown, x64, true) == rirWow64
    check rootInjectRoute(a64, unknown, unknown, a64, false) == rirSameMachine

  test "an ARM64X image run as an x64 process is a hybrid root, refused":
    # Measured on the fleet's Windows on Arm class (run 45595100361):
    # System32's cmd.exe is an ARM64X image; started by an x64 process it
    # runs as an x64-mode (ARM64EC) process, `ProcessMachineTypeInfo` says
    # 8664, and the x64 park and remote-thread load both fail on it (the
    # park times out, CreateRemoteThread returns err=5).
    check rootInjectRoute(x64, x64, a64, x64, false) == rirUnsupportedMachine
    # The same image started by a native ARM64 process runs as ARM64.
    check rootInjectRoute(a64, a64, a64, a64, false) == rirSameMachine
    # An unreadable image says nothing either way.
    check rootInjectRoute(x64, x64, unknown, x64, false) == rirSameMachine

  test "the hybrid refusal names both machines":
    let reason = hybridImageReason(caller = x64, child = x64, image = a64)
    check "inject=unsupported-process-machine:8664" in reason
    check "AA64" in reason

  test "a 32-bit caller keeps its pre-gate routes":
    check rootInjectRoute(x86, x86, x86, x86, true) == rirWow64
    check rootInjectRoute(x86, unknown, unknown, x86, false) == rirSameMachine

  test "a shim of another machine than this process is never injected":
    # A packaging defect, not a property of the child: refuse loudly rather
    # than run every action unmonitored.
    check rootInjectRoute(a64, a64, a64, x64, false) == rirShimMachineMismatch
    check rootInjectRoute(x64, x64, x64, a64, false) == rirShimMachineMismatch
    # An unreadable shim header is not a mismatch: LoadLibraryW reports it.
    check rootInjectRoute(x64, x64, x64, unknown, false) == rirSameMachine

  test "the refusal names the child machine the way io-mon's spawn gate does":
    let reason = unsupportedMachineReason(caller = x64, child = a64)
    check "inject=unsupported-process-machine:AA64" in reason
    check "8664" in reason
