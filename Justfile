# Default target: check compilation
build:
    nim check src/stackable_hooks.nim

# Run the test suite
test:
    nimble test

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
