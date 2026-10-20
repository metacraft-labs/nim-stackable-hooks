# A child parked at its entry point keeps spinning forever when the process that parked it dies

Status: open.

| | |
|---|---|
| Recorded | 2026-10-20 |
| Observed in | nim-stackable-hooks `4f8f7e6` (`origin/agents`), built into reprobuild's `librepro_monitor_shim.dll` by reprobuild `scripts/build_apps.sh` at reprobuild `07e3ec42e` plus an unrelated working-tree change, on eli-pc (Windows 11 x86_64), WinLibs gcc 16.1.0 / binutils from `. .\env.ps1`. Seen once, in the 3rd serial run of reprobuild's `tests/e2e/m83/t_e2e_data_file_validation`. Not reproduced on demand |
| Area | `src/stackable_hooks/windows_entry_park.nim` (`parkChildAtEntryPoint`, `releaseEntryPark`); its callers `propagation_windows.nim` (line 643, `defer: releaseEntryPark(park)`) and `windows_injector.nim` |

## Observed

A monitored reprobuild profile compile (`nim c` -> `gcc.exe` -> `as.exe`, every
process carrying the monitor shim) was still running 65 minutes after it
started. The process tree at that point:

- `as.exe` (pid 36800), started 18:32:39, assembling
  `@pnimcrypto@ssha2@ssha2_ref.nim.c.o`. Its parent, `gcc.exe` pid 32932, no
  longer existed. It had used **3,944 s of CPU** on one thread.
  `librepro_monitor_shim.dll` was loaded in it.
- Its only thread was at `as+0x1440`, executing `jmp as+0x1440` (`EB FE`).
  `as.exe`'s `AddressOfEntryPoint` is `0x1440`, and the bytes on disk there
  are `48 83 ec 28` (`sub $0x28,%rsp`). The process was therefore running,
  not suspended, on the entry-park self-jump, with the original bytes never
  restored.
- `nim` had exited. The reprobuild `__repro-compile-profile` helper that ran
  it was blocked in `ReadFile` on `nim`'s merged stdout/stderr pipe and never
  saw end-of-file: `as.exe` had inherited the pipe's write end and held it
  open. The helper, the io monitor above it, the engine and the test all
  waited on it until they were killed by hand.

The stacks came from `cdb -pv` (non-invasive), and the entry point and its
on-disk bytes from `objdump -p` / `objdump -d` of
`mingw64/x86_64-w64-mingw32/bin/as.exe`.

Earlier in the same session, two other gate runs and one unit-test compile
failed with a `gcc.exe` invocation that exited 1 and printed **no
diagnostic at all**. That may be the same event seen from `gcc`'s side, but
it was not connected to a parked child.

## Inference (not traced)

Parking writes `EB FE` at the entry point, resumes the child, polls until it
spins there, suspends it, injects, and only then restores the bytes in
`releaseEntryPark`. The restore runs in the INJECTING process, from a
`defer`. A child found running (not suspended) on the self-jump means the
injector stopped between `ResumeThread` and `SuspendThread`, and nothing ran
its cleanup. A `defer` does not run when the process dies (a crash, an
`ExitProcess` from another thread, a `TerminateProcess` from outside). Here
the injector was `gcc.exe`, and it was gone. Why `gcc` died in that window is
not known.

Whatever the cause of the injector's death, the result is unbounded: a child
that will never run its own code, spinning a core indefinitely and holding
every handle it inherited. Through those inherited pipes it wedges every
process up the tree that waits for end-of-file.

## Expected

No spec states this outright. Proposed: an injector that dies part-way
through a park must not leave the child alive. For example, the child could be
assigned before it is resumed to a job object that kills it when the
injector's handle closes, with the assignment ended after `releaseEntryPark`.
Or the parked child could re-check that its parent is still alive within a
bounded time. Whichever way, the parked state needs an owner that outlives
the injector, or a deadline enforced from the child's side.

## Search

Fetched `origin/agents` at `4f8f7e6` and searched the current and deleted
`issues/` for entry-point parking, orphaned children and an injector that
dies. `2026-09-30-windows-entry-park-polls-a-running-thread-context.md` is
about the polling while the injector is alive, a different defect. io-mon's
closed `2026-09-28-windows-complete-suite-exposes-fixture-and-monitor-isolation-failures.md`
named "an entry-point park timeout" only as one possible path of an ARM-host
failure.
