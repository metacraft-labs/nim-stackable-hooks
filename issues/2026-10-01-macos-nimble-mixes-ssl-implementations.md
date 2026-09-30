# macOS Nimble mixes OpenSSL and system LibreSSL before running tests

| | |
| --- | --- |
| Status | in-progress; select the dev shell's OpenSSL runtime |
| Recorded | 2026-10-01 |
| Observed in | nim-stackable-hooks `5cadd95` and `8f33762` |
| Area | `flake.nix`, the native macOS `nimble test` environment |

## Observed

Native macOS jobs `110130986316` and `110132304991` fail before the first
test compiles. Nix supplies Nimble 0.20.1; `nimble test` exits 139 with
`SIGSEGV: Illegal storage access`. Linux's same native lane passes.

The exact CI Nimble executable reproduces locally on macOS 26.5.2 ARM64 at
`8f33762`. LLDB shows `SSL_CTX_new_ex` in Nix OpenSSL's `libssl.3.dylib`
calling `tls1_clear`/`ssl3_clear`/`tls1_cleanup_key_block` in Apple's
`/usr/lib/libssl.43.dylib`, where it faults at address `0x87`. Nimble is
retrieving compiler release metadata, before executing the test task.
A minimal task without dependency resolution passes with that same binary.

Setting only `DYLD_LIBRARY_PATH` to Nix OpenSSL 3.6.1's library directory
allows the unchanged full `nimble test` task to complete locally at
`8f33762`. Keep this dependency-resolution and TLS behavior intact; do not
disable certificate checks or drop the test runner's corpus.

## Expected and repair

The [CI workflow standards](https://github.com/metacraft-labs/metacraft-dev-guidelines/blob/af93327ef8a84eee9023d0e5693fbd009ef103db/policies/ci-workflow-standards.md)
require the native suite to execute. `flake.nix` provides Nimble, so its
runtime must resolve a consistent SSL implementation. On Darwin, export
the pinned `pkgs.openssl` library directory from the dev shell. Preserve
the Nimble task, every test and the existing platform corpus. Validate the
full native lane on a fresh macOS worker.

## Evidence and search

Logs: `/tmp/hooks-5cadd-macos-native-tests.log`,
`/tmp/hooks-8f337-macos-native-tests.log`,
`/tmp/hooks-nimble-local-repro.log`,
`/tmp/hooks-nimble-lldb-backtrace.log`,
`/tmp/hooks-nimble-openssl-control.log`.
Nimble: `/nix/store/7lb1xi8xz9d5504d07l0aqn5avndprcn-nimble-0.20.1/bin/nimble`.
Fetched `agents` and `dev`; searched current issues and issue history for
Nimble and `libssl.43` before recording. No earlier helper issue found.
