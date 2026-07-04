# Package
version       = "0.1.0"
author        = "Metacraft Labs"
description   = "Cross-platform stackable hooks framework for Nim."
license       = "Apache-2.0"
srcDir        = "src"
skipDirs      = @["tests"]

# Dependencies
requires "nim >= 2.0.0"

task test, "Run the test suite via reprobuild":
  exec "repro test"
