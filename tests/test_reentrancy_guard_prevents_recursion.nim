## Acceptance test from MCR-OS-Interposition.status.org M0 verification:
##
##   test_reentrancy_guard_prevents_recursion — Hook that internally calls
##   another hooked function; verify no infinite recursion, inner call
##   goes direct.
##
##   test_reentrancy_with_reentrancy_allows_chain — call_next temporarily
##   allows reentrancy for the hook chain to proceed.

import std/unittest

import stackable_hooks/reentrancy

suite "reentrancy_guard":
  test "depth starts at zero on fresh thread":
    check hookDepth == 0
    check hooksAllowed()

  test "enterHook / exitHook bracket depth":
    enterHook()
    check hookDepth == 1
    check not hooksAllowed()
    enterHook()
    check hookDepth == 2
    exitHook()
    exitHook()
    check hookDepth == 0
    check hooksAllowed()

  test "withReentrancy proceeds with body and restores depth":
    enterHook()
    var observed = -1
    proc body() {.nimcall, raises: [].} =
      observed = hookDepth
    withReentrancyVoid(body)
    check observed == 0
    check hookDepth == 1
    exitHook()
    check hookDepth == 0

  test "currentHookDepth named accessor matches template":
    enterHook()
    check currentHookDepth() == 1
    check hookDepth == currentHookDepth()
    exitHook()
    check currentHookDepth() == 0
