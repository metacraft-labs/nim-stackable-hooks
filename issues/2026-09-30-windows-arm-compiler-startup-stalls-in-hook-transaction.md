# Windows ARM-host compiler startup stalls in the hook transaction

Status: open. Hooks `8f4d806`, io-mon `5e71adf`, RunQuota `8cf662c`.

## Observed

[Failure-only trace](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36695470313)
at shared actions `62594e4` completes 98 of 100 monitored compilations.
An assembler child and a GCC child both expire inside the borrowed shim-init
call. Both have loaded the shim and report initialization phase 22, immediately
before `ct_inline_hook_commit_transaction`. Their stopped instruction pointer
is `ntdll+0x176784`; reason 2 identifies the unchanged borrowed-call deadline.
The entry still contains its `EB FE` park. No test stage executes.

The retained DLL and bounded stack scan contain executable-address candidates
in the trampoline/relocation and suspension implementation, plus kernel32,
ntdll and the x64 emulator. These are not unwound frames and do not establish
which API is blocked. The transaction takes the registry lock, enumerates and
suspends other threads, allocates trampolines and patches target instructions.
Add volatile checkpoints around those individual operations before selecting
a repair. No timeout increase, bypass of injection, or missing-compiler
explanation is supported by these failures.

The balanced context-observation comparison at shared `4b21d61`, run
`36693214051`, also fails an assembler startup at the same ntdll offset.
That separate API-contract repair does not eliminate this failure.

## Expected

The [Windows inline-hook contract](../docs/contributors/platform-primitives.md)
requires patch writes to remain protected by thread suspension. The
[borrowed-call deadline rules](../docs/windows-borrowed-call-deadline.md)
require termination of a child whose initialization cannot safely return.
Keep both contracts. A repair must complete real monitored compiler startup
and retain hook semantics, thread-local state, slow-call and poison controls.
Use the full monitored graph for final validation, with the existing limits.

Fetched dev `8f4d806` and agents `e995df7`; dev is already an ancestor.
Searched current issues and their complete history for transaction, suspension
and deadlock reports. The existing running-context and lock-readiness issues
cover distinct defects; neither has been shown to cause this stalled commit.

## Protection-call checkpoint at `5c332cc`

Finer diagnostic [36706329422](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36706329422)
at shared actions `5c332cc55f8ad8222ad0a49c8e3ca2e72319405f` completes
99 of 100 monitored compilations against hooks `8f4d806` and io-mon
`5e71adf`. The assembler for `t_observation_extension_write_path` expires
with borrowed-call reason 2 and `init-phase=130`: immediately before the
first `VirtualProtect(..., PAGE_EXECUTE_READWRITE, ...)` in `write_patch`.
Checkpoint 131, immediately after that call, is not reached. The transaction
has already suspended its other threads. The main instruction pointer is
again `ntdll+0x176784`, and the child entry remains `EB FE`. The report's
executable-address scan still is not an unwound stack and does not identify
a lock owner. No missing compiler or timeout adjustment explains this result.

This narrows the stopped operation; it does not yet prove which suspended
thread or lock prevents completion. Compare real protection/cache-flush
calls with active and suspended protection workers on native Windows x64
and the ARM host before choosing a repair. Keep protected patch writes,
cache coherency, complete capture, and the existing poison/deadline rules.
Microsoft's [SuspendThread contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread)
warns of deadlock when a suspended thread owns a synchronization object.
Refreshed dev `8f4d806` and agents `71f2aae` before extending this record.

## Real protection controls and next observation

Standalone [36718424230](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36718424230)
at shared actions `fdd7a68fa5f7ed5c2aa53eb2678073b05ea643e8` completes all
16 cases on native x64 and all 16 on the ARM host. Each case executes 512
rounds. The active-worker control, writable protection under suspension,
cache flushing under suspension and writes to an already writable code page
all finish. No timeout or nonzero exit is recorded in either results file.
This does not reproduce the installer stall: it freezes only the four known
protection workers and changes private executable pages, while the installer
freezes every other process thread and patches executable image pages.

Full graph [36720335981](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36720335981)
at shared actions `25c6ec20fbd1dd1bb17f663e7650931985767242` retains all
100 compile actions and captures the exact patch target, frozen peer thread
ids and contexts, and runtime stack unwind results only after the existing
fatal deadline. Nearest exports are explicitly labeled as approximate; the
older executable-address scan remains distinct from unwound frames. It
prints no raw stack contents. Exact-source transforms and Windows x64 C
compilation/link pass locally against hooks `8f4d806` and io-mon `5e71adf`.
The real ARM-host run is pending. No production patching change is selected.

Refreshed dev `8f4d806` and agents `4fe105e` before extending this record.

## All-thread and image-page comparisons

Extended control `36720862528` at tooling `007dcb4` completes all 32 cases
on native x64. On ARM, three cases hit the 30-second whole-batch bound near
rounds 480, 483 and 511 of 512. Each reports phase 1, thread enumeration before
suspension, including the active-worker control. These are not observations
of a protection call deadlocking.

Corrected [36722317016](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36722317016)
at tooling `0a917c9f1f29f8cad9f8d4161cac191fbe8baaa0` uses 128 rounds per
batch and additionally exercises a real Kernel32 `GetFileAttributesW` code
page. It completes all 48 cases on native x64 and all 48 on the ARM host,
with every log reporting all rounds completed and every exit code zero. The
comparison spans active/frozen workers, known workers/all other threads,
private/custom-DLL/system-DLL executable pages, writable protection, cache
flushing and code-page writes. System-page writes retain the original byte.
Runtime checks verify the expected page type and executable protection.

These real controls do not reproduce the compiler's hook-transaction stall.
Keep the full `25c6ec2` trace pending and do not infer a production repair from
the protection API name or thread suspension alone. Refreshed dev `8f4d806`
and agents `9ac4b0c` before extending this record.

## Exact target and frozen threads at `25c6ec2`

Full diagnostic `36720335981` finishes with 95 successful and five failed
compilations against hooks `8f4d806`, io-mon `5e71adf` and RunQuota `8cf662c`.
Every failure records phase 130, immediately before the writable protection
call, with the exact target `Kernel32!CreateFileW` (module offset `0xf32f0`,
protection `PAGE_EXECUTE_WRITECOPY`). GCC, cc1 and assembler children are
represented. All stopped main threads are at `ntdll+0x176784` and retain the
entry park; three or four peers are frozen. Their recorded instruction
pointers are `ntdll+0x176874`, `+0x16d1a4`, `+0x16d824`, or `+0x19e408`.
The runtime unwind returns only its initial frame. Executable stack candidates
remain separate and do not identify the synchronization owner.

The earlier standalone control targets `GetFileAttributesW` and changes its
protection once before suspending peers. It therefore does not exercise the
first protection change on the exact failing target. Compare fresh processes
at `CreateFileW` with active peers, suspended peers before the first protection
change, and a protection change prepared while peers remain active. Preserve
patch-write suspension and the production hard deadline. This is a diagnostic
comparison, not an established production repair.

Evidence: `/tmp/windows-arm-trace25-evidence`. Refreshed dev `8f4d806` and
agents `8601e4b`; the same issue owns the repeated observation.

## Fresh target controls and real installer comparison

Fresh-process control `36735253958` at tooling `11655e2` passes all 48 cases
on each Windows host: 16 active, 16 suspended before the first writable
protection change, and 16 with that change prepared before suspension.
Every exit is zero. The ARM processes have two runtime peers; native x64 has
one. Control `36736311622` at tooling `7f8fe0c` first loads the six exact DLLs
from io-mon `5e71adf`'s `forceLoadObservedModules`; it also passes all 48 cases
per host with the same peer counts. Neither reproduces the compiler stall,
whose frozen peer counts are three or four.

Tooling `7c6167c` exercises hooks `8f4d806`'s actual C installer in fresh
processes. It installs a real `CreateFileW` hook through the transaction API,
opens `NUL` through its original trampoline, requires exactly one intercepted
call, removes the hook through another transaction, and verifies the restored
API. Original and prepared-protection modes run 32 times each on both hosts.
Two volatile stores expose entry/return of the actual `write_patch` protection
call if the disposable probe times out. All patch writes retain production
thread suspension. Local Windows C compilation/link, PowerShell syntax and
workflow lint pass. No production repair is inferred from the API-only controls.

Artifacts: `/tmp/windows-protection-116-evidence` and
`/tmp/windows-protection-7f-evidence`. Refreshed dev `8f4d806` and agents
`12f8a82` before extending the record.

## Actual installer and full-shim controls

Actual-installer run `36736842930` at tooling `7c6167c` passes all 64 cases
per host: 32 original and 32 prepared. Every log confirms a real intercepted
call and successful restoration. Direct initialization of the exact retained
shim in `36737795232`, tooling `9aac12d`, also passes all 64 cases per host.
Every process reports `actual-shim-init=0`, performs a real file call, and exits
normally. Its SHA-256 is
`7c2480628faf63a8048bddb3cfd9437096ddeee1adc87828bba36ab462562274`,
verified before use. Neither control reproduces borrowed initialization in
the full compiler workload. Evidence is in `/tmp/windows-createfile-hook-7c-evidence`
and `/tmp/windows-full-shim-9aa-evidence`.

Tooling `5383510` compares the protection preparation in the complete ARM
compiler graph at the original source revisions. Under the existing registry
lock, it makes exactly the queued `CreateFileW` target writable and restores
its original protection before the ordinary suspension. No instruction bytes
change during preparation. Ordinary patching, suspension, instruction-cache
flushing, hard deadlines and all tests remain. Failure traces include the
successfully prepared target address. Exact-source transformation, Windows
C compilation/link and workflow lint pass. This remains an experiment;
production hook code is unchanged.

## Repeated ordinary compiler-launch failures

RunQuota `48bb701`'s [ARM-host job](https://github.com/metacraft-labs/runquota/actions/runs/36729033751/job/109933446531)
finishes compilation with 101 successful actions and one failed action,
`t_hardware_run_tool_streams`. GCC reports that `cc1.exe` cannot be started.
io-mon stable `c01a3d8`'s [ARM-host job](https://github.com/metacraft-labs/io-mon/actions/runs/36729975964/job/109936751770)
reports 96 successful actions, two failed test compilations and two blocked
executions. Both compiles (`test_io_mon_cross_thread_sweep_sentinel` and
`test_shim_signal_handler_policy`) fail starting `as.exe`. Each compiler message
says `CreateProcess: No such file or directory`, matching the launch symptom
in the traced workloads. These ordinary reports contain no hook checkpoints
and do not independently prove the same underlying stall.

The io-mon tree equals previously validated `7bc8f72`, whose complete ARM-host
job passed. Public release assets and their source tag remain unchanged.
Retained failure reports: `/tmp/runquota-48bb-arm-evidence` and
`/tmp/io-mon-c01-arm-failure`. Refreshed hooks dev `8f4d806` and agents
`2c9f0f8` before extending this existing investigation. Prepared full graph
`36738909519` at tooling `5383510` is still running.

## Prepared CreateFileW moves the observed failure to a different page

Full controlled run `36738909519` at tooling `5383510` completes 98 of 100
compilations. Two assembler children expire with the same reason 2 and phase
130, but the patch target is now exactly `Ws2_32!connect` at module offset
`0x2bd0`, with `PAGE_EXECUTE_WRITECOPY` protection. Both traces also record the
successfully prepared `Kernel32!CreateFileW` target. The stopped main thread
is again at `ntdll+0x176784`; two or three peers are frozen. The affected
programs are `t_extension_rows_do_not_query_the_registry` and
`t_observation_store_round_trip`. The test stage does not run.

This is evidence against treating the failure as specific to CreateFileW.
It supports comparing protection preparation for every queued install range
while peers remain active. Tooling `8fd4eff` does that under the existing
registry lock, including the upstream padding of a detected hotpatch. Each
range has its original protection restored before ordinary thread suspension;
no instruction bytes change during preparation. The diagnostic exports the
number of prepared ranges and refuses an unexpected hook source revision.
All patch writes, restoration, cache flushes, tests and hard deadlines remain.
This is still an experiment, not a production repair.

Exact-source transformation and Windows C compilation/link pass against hooks
`8f4d806` with the all-range intervention. The earlier single-range DLL has
SHA-256 `A2B62B00CACD9BADBC14DFC19AD1FEB520AF48687CF7FA0A9127A9F257658CE6`;
its artifact is `/tmp/windows-arm-prepared-538-evidence`. Refreshed hooks dev
`8f4d806` and agents `6be90c1` before extending this record.

## Smaller reproduction through the borrowed main thread

The earlier standalone shim control calls initialization from ordinary `main`.
It does not reproduce the entry-park context of a compiler child. Tooling
`bec4778` adds a smaller real-image experiment: 128 native assembler launches,
then up to 128 monitored launches with eight concurrent fresh parents. Each
monitored parent uses the pinned `runWithMonitorShim` path, including entry
parking and borrowed initialization, with the retained DLL from failing run
`36720335981`. A failed sample stops queued work and retains active outcomes.
No production injection deadline is shortened.

The assembler processes a real input and must produce an x64 COFF object.
A monitored pass additionally requires that child's process-start, source-read
and object-write records, decoded from complete fragment frames. Source pins,
assembler/DLL hashes, per-launch logs and the existing failure-only context
observer are retained. This is supplemental diagnosis; it does not replace the
complete graph currently testing all-range preparation at `8fd4eff`.

The parent and failure observer compile and link for Windows x64 against hooks
`8f4d806` and io-mon `5e71adf`; workflow, Python and PowerShell syntax checks
also pass at tooling `bec4778`. Runtime results are pending. Refreshed hooks
dev `8f4d806` and agents `dc52095` before recording this experiment.
