## Acceptance test for the per-library `PropagationNode` registry —
## consumers enable/disable propagation per library and the registry
## walker only surfaces enabled libraries.

import std/unittest

import stackable_hooks/propagation

suite "per_library_enable_disable":
  test "registered node defaults to disabled":
    var node = PropagationNode(libraryPath: "/tmp/libA.so")
    registerPropagationNode(addr node)
    check not isAutoPropagationEnabled(addr node)

  test "enableAutoPropagation flips the bit":
    var node = PropagationNode(libraryPath: "/tmp/libB.so")
    registerPropagationNode(addr node)
    enableAutoPropagation(addr node)
    check isAutoPropagationEnabled(addr node)
    disableAutoPropagation(addr node)
    check not isAutoPropagationEnabled(addr node)

  test "enabledLibraryPaths surfaces only enabled libraries":
    # New static nodes so we don't interfere with the global registry
    # used by previous tests.
    var nodeC = PropagationNode(libraryPath: "/tmp/libC.so")
    var nodeD = PropagationNode(libraryPath: "/tmp/libD.so")
    registerPropagationNode(addr nodeC)
    registerPropagationNode(addr nodeD)
    enableAutoPropagation(addr nodeD)
    let paths = enabledLibraryPaths()
    check "/tmp/libD.so" in paths
    check "/tmp/libC.so" notin paths
    disableAutoPropagation(addr nodeD)

  test "double registration is a no-op":
    var node = PropagationNode(libraryPath: "/tmp/libE.so")
    registerPropagationNode(addr node)
    registerPropagationNode(addr node)
    enableAutoPropagation(addr node)
    let paths = enabledLibraryPaths()
    var seen = 0
    for p in paths:
      if p == "/tmp/libE.so": seen.inc
    check seen == 1
    disableAutoPropagation(addr node)
