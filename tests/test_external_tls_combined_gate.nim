import std/[os, strutils]

let sourcePath = currentSourcePath().parentDir.parentDir /
  "src" / "stackable_hooks" / "reentrancy.nim"
let source = readFile(sourcePath).replace("\r\n", "\n")

doAssert source.contains("int _ct_hooks_allowed_get(void);")
doAssert source.contains(
  "{.importc: \"_ct_hooks_allowed_get\", cdecl.}")

let gateStart = source.find("proc hooksAllowed*(): bool =")
let nextProc = source.find("proc currentHookDepth*()", gateStart)
doAssert gateStart >= 0 and nextProc > gateStart
let gateBody = source[gateStart ..< nextProc]
doAssert gateBody.contains("ctHooksAllowedGet() != 0")
doAssert gateBody.contains(
  "ctHookDepthGet() == 0 and\n      not hooksExplicitlySuppressedForCurrentThread()")

echo "external TLS combined gate contract: OK"
