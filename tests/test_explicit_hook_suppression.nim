## Explicit hook suppression is SEPARATE state from the reentrancy depth.
##
## No mocks: this exercises the real per-thread storage (the Windows
## ``TlsAlloc`` slot / the POSIX ``_Thread_local`` flag) through the real
## public API.
##
## The distinction under test is load-bearing for ct_interpose. Two of its
## Windows gates (``threadCreateReplayAllowedEW`` in exports_windows.nim,
## ``threadCreateReplayAllowedNtdll`` and friends in
## ``ntdll_detours_windows.nim``) deliberately do NOT use ``hooksAllowed``:
## they can legitimately be reached while an outer hook holds the depth
## counter above zero, and they bracket their own bodies with
## enterHook/exitHook. What they must still reject is a thread that was
## PERMANENTLY retired from hook dispatch by
## ``suppressHooksForCurrentThread`` -- e.g. the ``hNtTerminateThread``
## path, which retires the thread just before a no-return syscall.
##
## So the two predicates must disagree in the depth>0 case. If
## ``hooksExplicitlySuppressedForCurrentThread`` were ever collapsed into
## an alias for "depth > 0", or left as a hardcoded ``false`` (which is
## what the POSIX branch used to be), those gates would compile, read
## correctly, and gate nothing. `depth alone must not imply explicit
## suppression` and `explicit suppression must outlive the depth counter`
## are the two assertions that catch each of those regressions.

import unittest
import stackable_hooks/reentrancy

suite "explicit_hook_suppression":

  test "a fresh thread is neither suppressed nor at depth":
    check currentHookDepth() == 0
    check not hooksExplicitlySuppressedForCurrentThread()
    check hooksAllowed()

  test "depth alone must not imply explicit suppression":
    enterHook()
    check currentHookDepth() == 1
    # hooksAllowed() is false purely because of the depth gate ...
    check not hooksAllowed()
    # ... but the explicit gate must stay open. This is the exact
    # discrimination the ct_interpose thread-creation gates rely on.
    check not hooksExplicitlySuppressedForCurrentThread()
    exitHook()
    check currentHookDepth() == 0
    check hooksAllowed()

  test "suppressHooksForCurrentThread sets the explicit gate":
    check not hooksExplicitlySuppressedForCurrentThread()
    suppressHooksForCurrentThread()
    check hooksExplicitlySuppressedForCurrentThread()
    check not hooksAllowed()

  test "explicit suppression must outlive the depth counter":
    # suppressHooksForCurrentThread also parks the depth counter at 1.
    # Drive it back to 0 and the thread must STILL read as suppressed --
    # otherwise the flag is just the depth counter wearing a new name and
    # an unbalanced exitHook would silently un-retire the thread.
    check hooksExplicitlySuppressedForCurrentThread()
    exitHook()
    check currentHookDepth() == 0
    check hooksExplicitlySuppressedForCurrentThread()
    check not hooksAllowed()
