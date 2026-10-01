# Windows Reprobuild CI uses a broken ambient compiler

|             |                                                                      |
| ----------- | -------------------------------------------------------------------- |
| Status      | in-progress; corrected Windows build passes, PR 12 promotion pending |
| Recorded    | 2026-09-30                                                           |
| Observed in | nim-stackable-hooks at `def2464b2d282c7c1a982689a25953e1d4501f93`    |
| Area        | `.github/workflows/ci-reprobuild.yml`, Windows toolchain activation  |

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

## Declared tools missing from test execution and legacy cross-checks

At `65720d2`, run `36787321087`, both Linux jobs compile the corpus but
`test_cross_target_compile` cannot find `nim` on its execution PATH. The
package declares Nim for compilation; the binary's execute edge does not
name that runtime tool dependency. Windows x64 passes all 52 monitored
actions and then `dev-exec just build` fails because `just` is not declared.
The same cross-check failure appears at `bbbaee7` and `5cadd95`.
At `8f33762`, legacy Linux job `110132305154` rejects implicit provisioning
before running tests because the package sets no default provisioning mode.

Repair the recipe's environment contract: select the established Nix default
on POSIX and tarball default on Windows, declare Just, Nimble and its shell,
and attach Nim/compiler tool identities to test execution edges that spawn
compilers. Keep every corpus entry, assertion and monitor policy. Validate
recipe extraction and the actual existing cross-check commands, then full CI.
This follows `repro.nim`'s explicit runtime-compiler requirement and the
shared typed-tool execution contract used by RunQuota. The distinct Linux
raw-syscall exit 127 is recorded separately and remains a failing gate.

Fetched dev `8f4d806` and agents `0738aa9`; searched current issues and full
issue history for tool identities, absent Just and the monitored raw-syscall
failure before extending this record.

At `c8c90e7` the recipe now declares those tools and provisioning defaults;
`f3a9dc1` adds the independent signal fixture fix. Local extraction at
`f3a9dc1` reports 46 test actions on macOS, and the cross-target execute edge
has `toolIdentityRefs = [nim, gcc]` with Nim on its PATH. Both real legacy
cross-check commands pass locally. PR 12 at `f3a9dc1` is running complete
CI `36790688338` / `36790688346`.

The old `65720d2` macOS job `110131791732` fails every compile for missing
`string.h`: its compiler has no macOS SDK closure. The Nix default supplies
that closure for local cross-checks. Native Linux and macOS tests both pass
at `f3a9dc1`; its Windows x64 complete Reprobuild job now also passes.

## The CI wrapper overrides the package's Nix default

At `f3a9dc1`, macOS job `110142647642` in `36790688346` still fails
all 23 compiles with missing `string.h`. The log prints the exact shared
`dev-exec` wrapper: it appends `--tool-provisioning=path` to `repro build`
and `repro test` unless the caller supplies an explicit mode. That command
line overrides both the package default and the environment. Thus the local
`repro exec -- just build/test` control did not cover these two CI calls.
Evidence: `/tmp/hooks-f3-macos-repro.log`.

Match the existing RunQuota workflow: explicitly pass Nix provisioning on
POSIX and tarball provisioning on Windows to the two graph commands. Declare
Clang on macOS, matching Nim's actual backend; retain GCC elsewhere. Both
compilation and execution edges must carry their compiler identity, including
the runtime cross-target checks. Preserve every existing workflow command,
corpus entry and monitoring policy. Validate the resulting graph's compiler
closure and the full ordinary matrix, rather than only legacy cross-checks.

Candidate `9fcaf89` makes those declarations and passes local macOS
`repro build --tool-provisioning=nix --daemon=off` (23 compile actions)
and `repro test --tool-provisioning=nix --daemon=off` (46 total actions).
Its graph identifies Clang on every compile edge and Nim/Clang on every
execution edge; Clang resolves to the Nix wrapper with its SDK closure.
Workflow validation and commit checks pass. Logs:
`/tmp/hooks-explicit-toolchain-build.log`,
`/tmp/hooks-explicit-toolchain-test.log`; graph:
`/tmp/hooks-explicit-toolchain-graph.json`. The build/graph were measured
before the final comment-only recipe edit; the complete test graph was run
at committed `9fcaf89`. Remote ordinary CI is still required. This candidate
also selects already published hooks `d36cab8` as its Windows monitor input,
so the next complete matrix exercises page preparation and the matched child.

## Complete macOS CI confirms the explicit compiler closure

At `9fcaf89`, ordinary Reprobuild job `110157488672` in run
`36795362092` passes the monitored build, full test graph, native build
and native test cross-check. This exercises the exact CI wrapper commands
that previously lost the SDK closure. Linux ARM64 and Windows x64 also pass
at that commit; Linux x64 still has the separately diagnosed live INT3
fixture failure, and the Windows ARM job remains active. Log:
`/tmp/hooks-9fc-macos-repro.log`.

PR 12 now carries `4371fae`, adding only the controlled Linux fixture repair
and its recipe note above `9fcaf89`. All six native jobs pass at that SHA;
its legacy and full Reprobuild checks remain active. Keep this record open
until the complete helper candidate qualifies and reaches dev.
