# Cross-target coverage assertions assume a non-Windows host

|             |                                       |
| ----------- | ------------------------------------- |
| Status      | in-progress                           |
| Recorded    | 2026-09-30                            |
| Observed in | nim-stackable-hooks `3554385`         |
| Area        | `tests/test_cross_target_compile.nim` |

## Observed

Windows x64 Reprobuild job `110056495641`, run `36764895453`, passes its
build and 51 of 52 test actions. The cross-target test performs all 93 selected
real Nim checks successfully, but two coverage assertions fail:

```text
targetsToCheck(@[tWindowsAmd64, tWindowsArm64]) was @[(os: "windows", cpu: "arm64")]
Check failed: "windows/amd64" in seen
seen was {"windows/arm64"}
```

The selector intentionally omits the native host target when other targets
remain. The assertions instead assume this host is neither Windows target.
The literal host-plus-ARM64 cases also duplicate the host on Windows ARM64.

## Expected

The test's documented cross-target contract and
[`tests/corpus.nim`](../tests/corpus.nim) require checking every declared
non-host target, with a host-target fallback when nothing else remains.
[`docs/contributors/architecture.md`](../docs/contributors/architecture.md)
also requires the real native build/run lane and both Windows injector checks
in `just build`. Preserve those checks and the corpus coverage assertions;
make their expected cross-target set depend on the actual host. Use a distinct
second target when exercising host exclusion.

## Evidence and repair direction

Evidence: `/tmp/hooks-355-windows-repro-evidence` and
`/tmp/hooks-355-windows-repro-job.log`. No runtime or selector change is needed.
Run the corrected full compiler matrix locally and add it to the existing
native Windows job so the host-dependent assertion is exercised directly.

Refreshed dev `8f4d806` and agents `0580d4a`; searched current issues and their
complete history for `targetsToCheck`, matrix coverage and cross-target failures.
No earlier record covers this assertion mismatch.

## Repair validation

Repair `1230347` preserves the selector, both declared Windows CPUs and
every corpus coverage assertion. Expected cross-target membership now excludes
the actual native Windows CPU, and the exclusion control uses a distinct second
target. All 102 real Nim checks pass on macOS ARM64 at that commit; workflow
validation also passes. PR 12 includes the same change at `eb40f51` and adds the
full matrix to its native Windows job. Real Windows verification is pending.
