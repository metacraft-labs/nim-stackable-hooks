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
