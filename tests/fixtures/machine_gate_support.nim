## Shared by the two live machine-gate tests,
## ``tests/test_windows_root_machine_gate.nim`` (the root launcher) and
## ``tests/test_windows_child_machine_gate.nim`` (grandchild propagation):
## the fixture shim built for the test's own CPU, the children each host can
## start, and reading the shim's records back.
##
## Children used, and why (measured on the fleet's Windows on Arm class,
## nim-stackable-hooks run 45595100361):
##
## * System32's ``cmd.exe`` is an ARM64X image. A native ARM64 parent starts
##   it as ARM64; an x64 parent starts it in x64 mode (an x64-mode process of
##   an ARM64 image file), the hybrid case.
## * SysWOW64's ``cmd.exe`` is x86 on every 64-bit Windows.
## * A pure ARM64 child for an x64 test is the ARM64 build of the root gate
##   test in its ``--exit-with`` mode, named by
##   ``STACKABLE_HOOKS_NATIVE_ARM64_CHILD`` (set by
##   scripts/windows-arm64-native-tests.ps1).

import std/[os, osproc, strutils]
import stackable_hooks/windows_machine

type
  HANDLE* = pointer
  WORD = uint16
  BOOL = int32
  StartupInfoW {.bycopy.} = object
    cb: uint32
    reserved: array[4, pointer]
    dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars,
      dwFillAttribute, dwFlags: uint32
    wShowWindow, cbReserved2: uint16
    lpReserved2: pointer
    hStdInput, hStdOutput, hStdError: HANDLE
  ProcessInformation* {.bycopy.} = object
    hProcess*, hThread*: HANDLE
    dwProcessId*, dwThreadId*: uint32

proc IsWow64Process2(hProcess: HANDLE; processMachine,
    nativeMachine: ptr WORD): BOOL {.importc, stdcall, dynlib: "kernel32".}
proc GetCurrentProcess(): HANDLE {.importc, stdcall, dynlib: "kernel32".}
proc CreateProcessW(app: WideCString; cmd: WideCString; pa, ta: pointer;
    inherit: BOOL; flags: uint32; env: pointer; cwd: WideCString;
    si: ptr StartupInfoW; pi: ptr ProcessInformation): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc ResumeThread*(h: HANDLE): uint32 {.importc, stdcall, dynlib: "kernel32".}
proc WaitForSingleObject*(h: HANDLE; ms: uint32): uint32
  {.importc, stdcall, dynlib: "kernel32".}
proc GetExitCodeProcess*(h: HANDLE; code: ptr uint32): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc CloseHandle*(h: HANDLE): BOOL {.importc, stdcall, dynlib: "kernel32".}

const
  MarkVar* = "STACKABLE_HOOKS_ROOT_GATE_MARK"
  NativeArm64ChildVar* = "STACKABLE_HOOKS_NATIVE_ARM64_CHILD"
  ExitWithArg* = "--exit-with"

proc hostNativeMachine*(): uint16 =
  ## The machine of the host, not of this (possibly emulated) process.
  var pm, nm: WORD
  doAssert IsWow64Process2(GetCurrentProcess(), addr pm, addr nm) != 0,
    "IsWow64Process2 failed"
  nm

proc system32Cmd*(): string =
  getEnv("SystemRoot", r"C:\Windows") / "System32" / "cmd.exe"

proc sysWow64Cmd*(): string =
  getEnv("SystemRoot", r"C:\Windows") / "SysWOW64" / "cmd.exe"

proc nativeArm64Child*(): string = getEnv(NativeArm64ChildVar)

proc childArgs*(exe: string; exitCode: int): seq[string] =
  ## cmd.exe, or a test binary in child mode, exiting with `exitCode`.
  if exe.toLowerAscii.endsWith("cmd.exe"):
    @[exe, "/d", "/c", "exit " & $exitCode]
  else:
    @[exe, ExitWithArg, $exitCode]

proc buildShim*(workDir, shimPath: string): string =
  ## Build ``root_gate_shim.nim`` for THIS binary's CPU, so it matches the
  ## caller as a real shim would. Returns "" or why it could not be built.
  let nimExe = findExe("nim")
  if nimExe.len == 0:
    return "nim is not on PATH; cannot build the fixture DLL"
  let fixture = currentSourcePath().parentDir() / "root_gate_shim.nim"
  let (output, code) = execCmdEx(quoteShellCommand(@[nimExe, "c",
    "--app:lib", "--cpu:" & hostCPU, "--hints:off", "--warnings:off",
    "--nimcache:" & (workDir / "nimcache"), "--out:" & shimPath, fixture]))
  if code != 0 or not fileExists(shimPath):
    return "fixture DLL build failed (" & $code & "):\n" & output
  if peFileMachine(shimPath) != hostImageMachine():
    return "fixture DLL is not of this process's machine"
  ""

proc records*(mark: string): seq[string] =
  ## The fixture shim's ATTACH / INIT lines, in order.
  if fileExists(mark):
    for line in readFile(mark).splitLines():
      if line.len > 0:
        result.add line

proc spawnSuspended*(exe: string; exitCode: int): ProcessInformation =
  ## Start `exe` suspended, inheriting this process's environment, the way
  ## a monitored parent's CreateProcessW is seen by the shim's spawn hook.
  ## `osproc` cannot create a suspended child.
  var si: StartupInfoW
  si.cb = uint32(sizeof(si))
  var cmd = newWideCString(quoteShellCommand(childArgs(exe, exitCode)))
  const createSuspended = 0x4'u32
  const createNoWindow = 0x0800_0000'u32
  doAssert CreateProcessW(nil, cmd, nil, nil, 0,
    createSuspended or createNoWindow, nil, nil, addr si, addr result) != 0,
    "CreateProcessW failed for " & exe

proc resumeAndExitCode*(pi: ProcessInformation): int =
  ## Resume, wait (60 s hang guard) and return the exit code, or -1.
  discard ResumeThread(pi.hThread)
  if WaitForSingleObject(pi.hProcess, 60_000) != 0:
    return -1
  var code: uint32
  if GetExitCodeProcess(pi.hProcess, addr code) == 0:
    return -1
  int(code)
