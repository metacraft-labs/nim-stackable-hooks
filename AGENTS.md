# Stackable Hooks — Developer & Agent Guide

This repository contains the cross-platform stackable hooks framework for Nim, providing priority-ordered hook registry dispatch, thread-local reentrancy guards, and child-process shim propagation.

For specific details, refer to the following documents:

- **Architecture and Code Layout**: [docs/contributors/architecture.md](file:///Users/zahary/m/io-mon-fixes/nim-stackable-hooks/docs/contributors/architecture.md)
  - Detail on Core Components (Registry, Reentrancy Guard, Propagation).
  - Directory structure layout mapping to source files.
  - Test suites and Nimble integration details.

- **Low-Level Platform Primitives**: [docs/contributors/platform-primitives.md](file:///Users/zahary/m/io-mon-fixes/nim-stackable-hooks/docs/contributors/platform-primitives.md)
  - Detailed descriptions of OS-specific interposition mechanisms.
  - Linux `LD_PRELOAD` & raw syscall interposing.
  - macOS VM remap, interposing, and body patch.
  - Windows PE Import Address Table (IAT) patching & inline hooks.
