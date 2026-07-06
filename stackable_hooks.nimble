# Package
import std/[algorithm, strutils]
version       = readFile("version.txt").strip()
author        = "Metacraft Labs"
description   = "Cross-platform stackable hooks framework for Nim."
license       = "Apache-2.0"
srcDir        = "src"
skipDirs      = @["tests"]

# Dependencies
requires "nim >= 2.0.0"

proc selectedTests(): seq[string] =
  result = @[
    "tests/test_hook_registry_priority_order.nim",
    "tests/test_linux_raw_syscalls.nim",
    "tests/test_per_library_enable_disable.nim",
    "tests/test_propagation_registry_concurrent.nim",
    "tests/test_reentrancy_guard_prevents_recursion.nim",
    "tests/test_safe_tls.nim",
    "tests/test_smoke.nim",
    "tests/test_windows_inline_hook_api.nim",
  ]
  when defined(macosx):
    result.add "tests/test_macos_bodypatch_minimal_consumer.nim"
  when defined(linux):
    result.add "tests/test_linux_preload_helpers.nim"
  when defined(windows):
    result.add "tests/test_propagation_windows_edge_cases.nim"
    result.add "tests/test_propagation_windows_fork_bomb.nim"
    result.add "tests/test_propagation_windows_smoke.nim"
  sort(result)

task test, "Run the stackable-hooks test suite":
  for testFile in selectedTests():
    exec "nim c -r " & testFile
