# Windows Reprobuild CI uses a broken ambient compiler

| | |
| --- | --- |
| Status | in-progress; corrected Windows build passes, PR 12 promotion pending |
| Recorded | 2026-09-30 |
| Observed in | nim-stackable-hooks at `def2464b2d282c7c1a982689a25953e1d4501f93` |
| Area | `.github/workflows/ci-reprobuild.yml`, Windows toolchain activation |

## Observed

PR 12 Reprobuild run `36763681001`, Windows x64 job `110052344197`, fails
throughout test compilation with `nimbase.h: Invalid argument` and
`string.h: Invalid argument`. Commands resolve bare `gcc.exe` and Nim from
`C:\dev-deps\nim`; no runtime test executes. The actual GCC version is not
printed in that job and has not been measured.

The ordinary native Windows injection job at the same commit passes. It
explicitly selects the provisioned WinLibs GCC before compiling. Its workflow
already documents that the ambient GCC cannot read the CRT headers; the
Reprobuild lane does not apply that toolchain setup.

## Expected

`repro.nim` declares `nim >=2.2 <3.0` and `gcc >=12`. The CI environment must
activate a compiler satisfying that declared interface and capable of compiling
the same registered corpus as native CI. Use the declared provisioned toolchain
and retain all compile and runtime gates.

## Evidence

<https://github.com/metacraft-labs/nim-stackable-hooks/actions/runs/36763681001>.
Local log: `/tmp/hooks-pr12-windows-repro-failure.log`.
Fetched dev `8f4d806` and agents `b7a1cdd`, searched open issues and full issue
history for GCC, compiler PATH and these header errors. No existing issue owns
this workflow mismatch. This failure precedes the new capture regression's
execution and does not show that its runtime repair failed.

## Pinned toolchain result

At `3554385`, run `36764895453` passes the Windows Reprobuild build and
51 of 52 test actions. All 93 selected cross-target compiler checks pass as
well. The single failed action instead contains host-dependent matrix assertions,
recorded in `2026-09-30-cross-target-coverage-assertions-assume-a-posix-host.md`.
The original header/ambient-compiler failure is not reproduced. PR 12 at
`eb40f51` carries the separate assertion repair; ordinary promotion is pending.

## The full monitored suite passes; cross-check activation selects Nix

At `eb40f51`, run `36776479786`, Windows x64 job `110095572571`,
passes compilation and all 52 monitored test actions. The host-aware matrix
assertion and real capture regression now pass. The next `dev-exec just build`
step fails before invoking Just: `repro exec` tries Nix provisioning and
reports `bakForeignProvision is not supported on Windows`. No cross-check
test executes. The log is `/tmp/hooks-eb40-windows-repro-job.log`.

Set `REPRO_TOOL_PROVISIONING=tarball` for the Windows workflow environment.
This existing override is read by Reprobuild before dispatch and covers both
the direct build/test commands and `dev-exec`'s environment activation for
Just. Keep non-Windows mode selection unchanged. This retains every test and
uses the declared toolchain; it does not add a PATH bypass. Fetched dev
`8f4d806` and agents `aba22b9` before extending this existing workflow issue.

## Fresh-host runtime bootstrap on Linux and macOS

The separate runner-selection candidate `5cadd95` exposes bootstrap gaps
before helper tests execute. Linux job `110130967953` in run `36787069280`
installs Reprobuild v0.2.5 and fails with
`__repro-extract-interface: error while loading shared libraries`.
Legacy Reprobuild test job `110130986373` in run `36787065853` fails the same
way. This matches the existing owning record in
`reprobuild-specs/issues/2026-09-26-release-launcher-makes-the-engine-self-spawn-the-loader.md`.

macOS job `110130968087` in run `36787069280` also installs the release
bootstrap, then refuses monitoring because no non-SIP shell is available.
The shared source bootstrap already exports its rooted shell; that closure is
tracked in
`metacraft-specs/issues/2026-09-28-reprobuild-source-bootstrap-loses-runtime-dependencies.md`.

Select the already pinned source bootstrap for every Reprobuild job,
including the separate legacy Reprobuild entry in `ci.yml`. The workflow
changes are `65720d2` and `8f33762`; no helper runtime code changes.
Full CI is pending. Logs: `/tmp/hooks-5cadd-linux-repro.log`,
`/tmp/hooks-5cadd-macos-repro.log`,
`/tmp/hooks-5cadd-linux-native-repro.log`. These setup/launcher failures are
independent of the repaired Windows root-exit capture behavior.
