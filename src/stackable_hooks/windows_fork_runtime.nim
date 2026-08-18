when not defined(windows):
  {.error: "stackable_hooks/windows_fork_runtime is Windows-only".}

import std/os

proc resolveWindowsExecutable(executable, cwd: string): string =
  let (head, _, ext) = splitFile(executable)
  if head.len > 0 or isAbsolute(executable):
    let candidate =
      if isAbsolute(executable) or cwd.len == 0: executable
      else: cwd / executable
    if fileExists(candidate):
      return absolutePath(candidate)
    if ext.len == 0 and fileExists(candidate & ExeExt):
      return absolutePath(candidate & ExeExt)
  findExe(executable)

proc windowsForkRuntimeForImagePath*(imagePath: string): string =
  ## Return the adjacent MSYS2/Cygwin runtime used by a resolved image.
  ## Their fork emulation cannot tolerate a pre-main remote thread.
  if imagePath.len == 0:
    return ""
  for runtime in ["msys-2.0.dll", "cygwin1.dll"]:
    if fileExists(parentDir(imagePath) / runtime):
      return runtime

proc windowsForkRuntimeForExecutable*(executable: string; cwd = ""): string =
  windowsForkRuntimeForImagePath(resolveWindowsExecutable(executable, cwd))
