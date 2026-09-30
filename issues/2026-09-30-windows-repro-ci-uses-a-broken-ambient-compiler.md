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
