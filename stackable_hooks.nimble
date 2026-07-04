# Package
version       = "0.1.0"
author        = "Metacraft Labs"
description   = "Cross-platform stackable hooks framework for Nim."
license       = "Apache-2.0"
srcDir        = "src"
skipDirs      = @["tests"]

# Dependencies
requires "nim >= 2.0.0"

task test, "Run the test suite":
  exec "nim c -r tests/test_smoke.nim"
  exec "nim c -r tests/test_hook_registry_priority_order.nim"
  exec "nim c -r tests/test_reentrancy_guard_prevents_recursion.nim"
  when defined(windows):
    exec "nim c -r tests/test_windows_iat_patch_basic.nim"
