# Package
import std/strutils
version       = readFile("version.txt").strip()
author        = "Metacraft Labs"
description   = "Cross-platform stackable hooks framework for Nim."
license       = "Apache-2.0"
srcDir        = "src"
skipDirs      = @["tests"]

# Dependencies
requires "nim >= 2.0.0"

# The test corpus is NOT written out here. It lives in `tests/corpus.nim`,
# which `repro.nim` includes too, so the nimble lane and the reprobuild lane
# cannot drift apart. `tests/test_lane_registration.nim` fails the build if
# either lane grows a test path of its own or if a file under `tests/` is
# missing from the corpus.
include "tests/corpus.nim"

task test, "Run the stackable-hooks test suite":
  for testFile in hostTestSources():
    exec "nim c -r " & testFile
