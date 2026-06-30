when not defined(linux):
  {.error: "test_linux_preload_helpers is Linux-only".}

import std/unittest

import stackable_hooks/platform/linux_preload

suite "Linux preload helper primitives":

  test "reentrancy depth gates hook dispatch":
    check currentPreloadHookDepth() == 0
    check preloadHooksAllowed() != 0

    enterPreloadHook()
    check currentPreloadHookDepth() == 1
    check preloadHooksAllowed() == 0

    enterPreloadHook()
    check currentPreloadHookDepth() == 2
    exitPreloadHook()
    check currentPreloadHookDepth() == 1

    exitPreloadHook()
    check currentPreloadHookDepth() == 0
    check preloadHooksAllowed() != 0

    exitPreloadHook()
    check currentPreloadHookDepth() == 0

  test "RTLD_NEXT resolver suppresses hooks only during lookup":
    let before = currentPreloadHookDepth()
    discard resolveNextSymbol(cstring"write")
    check currentPreloadHookDepth() == before
