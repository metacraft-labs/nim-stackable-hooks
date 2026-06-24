## Smoke test — verify the public surface imports and exports the names
## the consumer-facing examples in the README reference. Run with:
##   nim c -r tests/test_smoke.nim

import std/unittest

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
