import std/strutils

when defined(windows):
  import stackable_hooks/inline_hook/windows_inline_hook

  type
    InstallProc = proc(target: pointer; hook: pointer;
                       outTrampoline: ptr pointer): cint {.cdecl, raises: [].}
    UninstallProc = proc(target: pointer): cint {.cdecl, raises: [].}

  proc acceptInstall(_: InstallProc) {.raises: [].} = discard
  proc acceptUninstall(_: UninstallProc) {.raises: [].} = discard

  acceptInstall(inlineHookInstall)
  acceptInstall(inlineHookInstallNoReturn)
  acceptInstall(inlineHookInstallUnsafeNoSuspend)
  acceptInstall(inlineHookInstallNoReturnUnsafeNoSuspend)
  acceptUninstall(inlineHookUninstall)
  acceptUninstall(inlineHookUninstallUnsafeNoSuspend)

  doAssert declared(inlineHookBeginTransaction)
  doAssert declared(inlineHookCommitTransaction)
  doAssert declared(inlineHookAbortTransaction)
  doAssert declared(inlineHookInHandler)
  doAssert declared(inlineHookEnter)
  doAssert declared(inlineHookLeave)
  doAssert declared(inlineHookInstallGetLastInstallMode)
else:
  const wrapperSource = staticRead("../src/stackable_hooks/inline_hook/windows_inline_hook.nim")
  doAssert "is Windows-only" in wrapperSource
  doAssert "inlineHookInstallUnsafeNoSuspend" in wrapperSource
  doAssert "inlineHookInstallNoReturnUnsafeNoSuspend" in wrapperSource
  doAssert "inlineHookUninstallUnsafeNoSuspend" in wrapperSource

  const inlineDir = currentSourcePath().replace("\\", "/").rsplit("/", 1)[0] &
    "/../src/stackable_hooks/inline_hook/windows"
  {.passC: "-I" & inlineDir.}
  {.compile: inlineDir & "/install_windows.c".}

  proc cInstall(target: pointer; hook: pointer; outTrampoline: ptr pointer): cint
    {.importc: "ct_inline_hook_install", cdecl.}
  proc cInstallNoSuspend(target: pointer; hook: pointer;
                         outTrampoline: ptr pointer): cint
    {.importc: "ct_inline_hook_install_no_suspend", cdecl.}
  proc cInstallNoReturn(target: pointer; hook: pointer;
                        outTrampoline: ptr pointer): cint
    {.importc: "ct_inline_hook_install_noreturn", cdecl.}
  proc cInstallNoReturnNoSuspend(target: pointer; hook: pointer;
                                 outTrampoline: ptr pointer): cint
    {.importc: "ct_inline_hook_install_noreturn_no_suspend", cdecl.}
  proc cUninstall(target: pointer): cint
    {.importc: "ct_inline_hook_uninstall", cdecl.}
  proc cUninstallNoSuspend(target: pointer): cint
    {.importc: "ct_inline_hook_uninstall_no_suspend", cdecl.}

  var trampoline: pointer
  doAssert cInstall(nil, nil, addr trampoline) == -4
  doAssert cInstallNoSuspend(nil, nil, addr trampoline) == -4
  doAssert cInstallNoReturn(nil, nil, addr trampoline) == -4
  doAssert cInstallNoReturnNoSuspend(nil, nil, addr trampoline) == -4
  doAssert cUninstall(nil) == -4
  doAssert cUninstallNoSuspend(nil) == -4

const headerSource = staticRead("../src/stackable_hooks/inline_hook/windows/install_windows.h")
const cSource = staticRead("../src/stackable_hooks/inline_hook/windows/install_windows.c")

doAssert "ct_inline_hook_install_no_suspend" in headerSource
doAssert "ct_inline_hook_install_noreturn_no_suspend" in headerSource
doAssert "ct_inline_hook_uninstall_no_suspend" in headerSource
doAssert "ct_inline_hook_install_no_suspend" in cSource
doAssert "ct_inline_hook_install_noreturn_no_suspend" in cSource
doAssert "ct_inline_hook_uninstall_no_suspend" in cSource
doAssert "Contract: use this entry point only when the caller" in headerSource
doAssert "not queued into transactions" in headerSource
