# `nim check src/stackable_hooks.nim` ALONE is vacuous for the Windows tree:
# the umbrella imports it only `when defined(windows)`, so on Linux/macOS a
# bogus symbol in `src/stackable_hooks/windows_injector.nim` left the old
# `build` recipe green (measured), and so did one in
# `platform/linux_preload.nim`. The two `--os:windows` lines of `check` are
# the cheap smoke for the file io-mon's
# decomposed-host-API work changed. The EXHAUSTIVE matrix -- every module and
# every test source against every target declared in `tests/corpus.nim` --
# runs as part of `just test`, via `tests/test_cross_target_compile.nim`.

# Build through the reprobuild graph (`repro.nim`): every corpus test binary
# for this host is compiled, which compiles the framework. CI runs the same
# command.
build:
    repro build

# The cheap compile smoke of the umbrella and both Windows arms of the
# injector, run directly with the compiler. It is not a build or test entry
# point; `just test` covers the same ground through the cross-target matrix.
check:
    nim check src/stackable_hooks.nim
    nim check --os:windows --cpu:amd64 src/stackable_hooks/windows_injector.nim
    nim check --os:windows --cpu:arm64 src/stackable_hooks/windows_injector.nim

# The corpus, and each entry's platform gate, live in `tests/corpus.nim`;
# `repro.nim` reads the same file, and `stackable_hooks.nimble` does too, so
# the graph and the nimble task cannot drift apart.

# Run the test suite through `repro test` (the `test` collection of
# `repro.nim`, one build edge and one execute edge per corpus entry).
test:
    repro test

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

# Entering the dev shell from another git repository must write nothing there.
# Runs `nix develop`, so it is not part of the in-shell test recipes.
test-dev-shell:
    bash tests/dev_shell_writes_nothing_elsewhere.sh
