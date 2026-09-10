# Why a remote thread wedges an MSYS2/Cygwin child — the measurements

These are the probes that produced the diagnosis implemented in
`src/stackable_hooks/windows_entry_park.nim`. They are kept because the
measurements are expensive to reproduce and because two of them refute
things that look obviously true.

They are **evidence, not a lane**: nothing in CI builds them. Build by hand
with any MinGW or MSVC toolchain, e.g.

```sh
gcc -municode -O1 -o ep_probe.exe     ep_probe.c
gcc -municode -O1 -o inject_probe.exe inject_probe.c
gcc -municode -O1 -o dbg_probe.exe    dbg_probe.c
gcc -shared      -O1 -o mark.dll      mark.c
```

`mark.dll` appends one line per `DLL_PROCESS_ATTACH` to `%MARK_FILE%`; every
probe below is run with a real `DllMain` so nothing can pass by being inert.

## The symptom

An MSYS2/Cygwin `bash` injected the way the framework used to inject starts,
prints, and then stops: six threads in `Wait`, CPU frozen, **no forked
grandchild anywhere in the process tree** (`inspect.ps1` dumps exactly that).
It is not an exit code. It is not `0xC0000020`. The shell wedges at its first
`fork()`.

## The ladder — `inject_probe.c`

One binary, seven modes, so each variable is removed one at a time:

| mode | what it does | result on `heavy.sh` |
| --- | --- | --- |
| `plain` | `CreateProcessW`, nothing else | completes |
| `susp` | `CREATE_SUSPENDED` + `ResumeThread` | completes |
| `inject` | the framework's pre-park technique | **hangs** |
| `injectfree` | as `inject`, then `VirtualFreeEx` | **hangs** |
| `alloc` | `VirtualAllocEx` only, no thread | completes |
| `thread` | `CreateRemoteThread` on `kernel32!GetCurrentProcessId` | **hangs** |
| `post` | resume first, `Sleep(PROBE_DELAY_MS)`, then inject | 0 ms hangs, ≥1 ms passes |

The `thread` row is the decisive one. **No DLL, no section, nothing mapped**
— just a remote thread calling a function that returns a `DWORD` — and the
child still wedges. `LoadLibraryW` of an already-mapped `kernel32.dll` hangs
the same way. There is no section to collide with in either case, so this is
**not** the `msys-2.0.dll` base-address collision class described in
`codetracer-specs/Architecture/Hooking-Cygwin-Binaries-On-Windows.md`, and
rebasing cannot help it. On the host where all of this was measured
`msys-2.0.dll` sits at the factory `ImageBase` of `0x210040000` with WinFsp
installed and running, and that spec's §4.1 verification recipe passes
unmodified, repeatedly.

The `alloc` row removes the remaining alternative: allocating in the child is
harmless. The variable is **the thread**.

## Why the thread matters

The Windows loader initialises a process on whichever thread reaches
`LdrInitializeThunk` first. Fire a `CreateRemoteThread` into a
`CREATE_SUSPENDED` child that has never run and *that* thread executes
`LdrpInitializeProcess` — every static import's `DLL_PROCESS_ATTACH`,
`msys-2.0.dll`'s included — and then exits. The Cygwin runtime is left bound
to a dead thread, and its `fork()` never completes.

The `post` row says the same thing from the other side: it works only once
the child has been running long enough for the loader to have finished on the
main thread. That is a race, not a fix — which is why the framework refuses
to inject after a failed park rather than falling back to it.

## The two plausible fixes that are not — `dbg_probe.c`

Injecting at the **initial debug breakpoint** (`DEBUG_ONLY_THIS_PROCESS`)
looks right: the breakpoint is delivered after `LdrpInitializeProcess` ran on
the main thread and before the image entry point, so no user code has run and
the runtime is initialised on the correct thread. It **hangs 5/5**. The debug
port holds the loader lock across the event.

A fixed `Sleep` is the `post` mode above: measured racy.

## The fix — `ep_probe.c`

1. `CreateProcessW(CREATE_SUSPENDED)`.
2. Patch the image entry point with `EB FE` (`jmp $`).
3. `ResumeThread` — the loader now initialises **on the main thread**.
4. Poll `GetThreadContext` until `Rip == entry`. Measured at 1–2 ms.
5. `SuspendThread`, inject, restore the two original bytes, resume.

**20/20 green** on `heavy.sh` with `mark.dll`, where `inject_probe inject`
**hangs 20/20** on the same script with the same DLL. That is the
failing-before / passing-after pair; the landed version of it lives in
`tests/test_windows_entry_park_msys.nim`, which asserts both arms through the
public `injectShimIntoChild` rather than through these probes.

## The scripts

* `nofork.sh` — builtins only, no `fork()`. Completes even under `inject`,
  which is how we know the wedge is in `fork()` and not in startup.
* `forks.sh` / `forkmods.sh` — ten `$(...)` substitutions. Enough to wedge.
* `delayfork.sh` — spins on `SECONDS` with no fork for three seconds first,
  to separate "startup wedged" from "fork wedged".
* `heavy.sh` — 25 iterations of nested substitution and a pipeline, plus a
  subshell `cd`. The workload the 20/20 sweeps used.

`inspect.ps1` dumps the process tree, thread states and two CPU samples of a
wedged child. It takes the shell path from `PROBE_BASH` and falls back to a
Git-for-Windows default.
