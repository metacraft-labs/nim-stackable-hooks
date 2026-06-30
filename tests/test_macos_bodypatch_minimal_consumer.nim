when defined(macosx):
  import stackable_hooks/platform/macos_bodypatch

  proc replacementOpen(path: cstring; flags: cint): cint {.cdecl.} =
    discard path
    discard flags
    -1

  proc replacementFork(): cint {.cdecl.} =
    -1

  proc exerciseBodypatchApi() =
    var installed, failed, absent: cint
    var tramp: pointer
    var trampErr: cint

    stackableMacosBodypatchInstallNamedExcluding(
      cstring("open"),
      cast[pointer](replacementOpen),
      cstring("libminimal_bodypatch_consumer"),
      addr installed,
      addr failed,
      addr absent)

    stackableMacosBodypatchInstallNamedTrampExcluding(
      cstring("fork"),
      cast[pointer](replacementFork),
      cstring("libminimal_bodypatch_consumer"),
      addr tramp,
      addr installed,
      addr failed,
      addr absent)

    discard stackableMacosBodypatchBuildTrampoline(tramp, addr trampErr)
    discard stackableMacosBodypatchInstall(tramp, cast[pointer](replacementFork))

  when isMainModule:
    exerciseBodypatchApi()
else:
  static:
    doAssert not defined(macosx)
