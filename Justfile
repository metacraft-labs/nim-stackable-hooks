# `nim check src/stackable_hooks.nim` ALONE is vacuous for the Windows tree:
# the umbrella imports it only `when defined(windows)`, so on Linux/macOS a
# bogus symbol in `src/stackable_hooks/windows_injector.nim` left this recipe
# green (measured), and so did one in `platform/linux_preload.nim`. The two
# `--os:windows` lines are the cheap smoke for the file io-mon's
# decomposed-host-API work changed. The EXHAUSTIVE matrix -- every module and
# every test source against every target declared in `tests/corpus.nim` --
# runs as part of `just test`, via `tests/test_cross_target_compile.nim`.

# Check compilation, including both Windows arms of the injector.
build:
    nim check src/stackable_hooks.nim
    nim check --os:windows --cpu:amd64 src/stackable_hooks/windows_injector.nim
    nim check --os:windows --cpu:arm64 src/stackable_hooks/windows_injector.nim

# The corpus, and each entry's platform gate, live in `tests/corpus.nim`;
# `repro.nim` reads the same file, so this lane and the reprobuild lane
# cannot drift apart.

# Run the test suite.
test:
    nimble test

# Run the cross-target compile matrix on its own.
check-cross-targets:
    nim c -r tests/test_cross_target_compile.nim

# Lint all files
lint: lint-nix

# Format all files
format: format-nix

# Internal lint recipes
lint-nix:
    nixfmt --check flake.nix

# Internal format recipes
format-nix:
    nixfmt flake.nix

alias t := test
alias fmt := format
