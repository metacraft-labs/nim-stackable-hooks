## Smoke test — verify the public surface imports and exports the names
## the consumer-facing examples in the README reference. Run with:
##   nim c -r tests/test_smoke.nim

import std/[os, unittest]

import stackable_hooks

suite "smoke":
  test "registry primitives reachable":
    var registry {.used.} = initHookRegistry()
    check declared(HookContext)
    check declared(HookCallback)

  test "reentrancy primitives reachable":
    check declared(hookDepth)
    check declared(hooksAllowed)

  test "propagation env helpers reachable":
    check declared(injectionEnvVar)
    check declared(buildInjectionEnv)

  test "unrewriteSipPath inverts rewriteSipPath for SIP-protected targets":
    # A sandbox-rewritten SIP path maps BACK to the original system path so a
    # launched-binary dependency is keyed on the real binary identity (the
    # CodeTracer §16.7.8 launched-binary fold relies on this inverse).
    const sandbox = "/opt/ct/sandbox-tools"
    check rewriteSipPath("/bin/sh", sandbox) == sandbox & "/bin/sh"
    check unrewriteSipPath(sandbox & "/bin/sh", sandbox) == "/bin/sh"
    # A trailing slash on the sandbox root is tolerated.
    check unrewriteSipPath(sandbox & "/bin/sh", sandbox & "/") == "/bin/sh"
    # A path NOT under the sandbox root is returned unchanged.
    check unrewriteSipPath("/usr/local/bin/python3", sandbox) ==
      "/usr/local/bin/python3"
    # A sandbox-rooted path that does NOT mirror a SIP-protected target is left
    # untouched (we never invent a system path for an unrelated file).
    check unrewriteSipPath(sandbox & "/tmp/scratch", sandbox) ==
      sandbox & "/tmp/scratch"
    # An empty sandbox dir is a no-op (defensive).
    check unrewriteSipPath("/bin/sh", "") == "/bin/sh"

  test "rewriteExecPathForSip uses Apple utility drop-ins only when seeded":
    ## Apple tools such as iconutil/hdiutil are SIP-protected just like
    ## /bin/sh, but unlike bash we cannot assume a buildable non-Apple
    ## replacement exists. Propagation must therefore be availability-gated:
    ## no seeded sandbox tool means leave the original path alone; a seeded
    ## drop-in means rewrite to it.
    const appleTool = "/usr/bin/iconutil"
    check isSipProtected(appleTool)

    let oldSandbox = getEnv("CT_SANDBOX_TOOLS_DIR")
    let sandbox = getTempDir() / "stackable-hooks-sip-apple-tools-test"
    removeDir(sandbox)
    createDir(sandbox / "usr" / "bin")
    putEnv("CT_SANDBOX_TOOLS_DIR", sandbox)
    try:
      check rewriteExecPathForSip(appleTool) == appleTool

      let dropIn = sandbox / "usr" / "bin" / "iconutil"
      writeFile(dropIn, "#!/bin/sh\nexit 0\n")
      setFilePermissions(dropIn, {fpUserRead, fpUserWrite, fpUserExec})
      check rewriteExecPathForSip(appleTool) == dropIn
    finally:
      if oldSandbox.len > 0:
        putEnv("CT_SANDBOX_TOOLS_DIR", oldSandbox)
      else:
        delEnv("CT_SANDBOX_TOOLS_DIR")
      removeDir(sandbox)

  test "SIP resolver preserves precedence and rejects protected link targets":
    # Resolver fixtures point to this real executable: no shim or platform
    # binary is mocked, and a /bin/sh link is the adversarial SIP escape.
    let work = getTempDir() / ("hooks-sip-resolver-" & $getCurrentProcessId())
    removeDir(work)
    let invocation = work / "invocation"
    let portable = work / "portable"
    createDir(invocation / "bin")
    createDir(portable / "bin")
    let savedSandbox = getEnv("CT_SANDBOX_TOOLS_DIR")
    let savedTools = getEnv("STACKABLE_HOOKS_TOOLS_DIR")
    putEnv("CT_SANDBOX_TOOLS_DIR", invocation)
    putEnv("STACKABLE_HOOKS_TOOLS_DIR", portable)
    defer:
      for entry in [("CT_SANDBOX_TOOLS_DIR", savedSandbox),
                    ("STACKABLE_HOOKS_TOOLS_DIR", savedTools)]:
        if entry[1].len > 0: putEnv(entry[0], entry[1])
        else: delEnv(entry[0])
      removeDir(work)
    let invocationSh = invocation / "bin" / "sh"
    let portableSh = portable / "bin" / "sh"
    createSymlink(getAppFilename(), portableSh)
    check rewriteExecPathForSip("/bin/sh") == portableSh
    createSymlink(getAppFilename(), invocationSh)
    check rewriteExecPathForSip("/bin/sh") == invocationSh
    removeFile(invocationSh)
    createSymlink("/bin/sh", invocationSh)
    check rewriteExecPathForSip("/bin/sh") == portableSh
    removeFile(invocationSh)
    createSymlink(work / "missing", invocationSh)
    check rewriteExecPathForSip("/bin/sh") == portableSh
    check rewriteExecPathForSip("/bin/no-such-stackable-tool") ==
      "/bin/no-such-stackable-tool"
    check rewriteExecPathForSip(getAppFilename()) == getAppFilename()
    let nonExecutable = invocation / "bin" / "no-such-stackable-tool"
    writeFile(nonExecutable, "unusable")
    setFilePermissions(nonExecutable, {fpUserRead, fpUserWrite})
    check rewriteExecPathForSip("/bin/no-such-stackable-tool") ==
      "/bin/no-such-stackable-tool"
