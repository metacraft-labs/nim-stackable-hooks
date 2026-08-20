# Injecting into 32-bit (WOW64) children on Windows

`stackable_hooks/windows_injector` spawns a target suspended, writes the shim's
path into its address space, and calls `LoadLibraryW` there via
`CreateRemoteThread`. This document covers what changes when the target is a
**32-bit process on 64-bit Windows** (a WOW64 process), because two of the
three inputs to that sequence become wrong at once and neither failure is
self-describing.

## Why a 64-bit injector cannot inject a 64-bit shim into a 32-bit child

**The DLL is wrong.** `LoadLibraryW` refuses an image whose machine type does
not match the loading process and returns NULL. The child is left running and
unmonitored.

**The address is wrong.** The injector resolves `LoadLibraryW` with
`GetProcAddress` in *its own* process. That is sound between processes of the
same bitness, where `kernel32.dll` is loaded at a shared base — and it is what
the same-bitness path still does. A WOW64 process instead loads
`C:\Windows\SysWOW64\kernel32.dll` at an unrelated base, so the 64-bit address
names nothing in particular there. This failure is worse than the first: rather
than a clean NULL, `CreateRemoteThread` starts a thread at a meaningless
address in the child.

A 64-bit process also cannot resolve the 32-bit address for itself.
`LoadLibraryW` of `SysWOW64\kernel32.dll` from a 64-bit process fails on the
same machine-type check, so there is no in-process route to the answer. Walking
the child's PEB and parsing its export table would work, at the cost of a PE
parser inside the injector.

## How the address is obtained instead

Ask a 32-bit process, and let it answer through the one channel every process
has regardless of bitness: **its exit code**.

`src/stackable_hooks/tools/wow64_proc_probe.nim` is a small program built for
i386. Running as a WOW64 process, its `GetModuleHandleW` + `GetProcAddress`
resolve against exactly the `kernel32` the child will use, and it returns the
resulting pointer as its exit code. A Windows exit code is a `DWORD` — exactly
wide enough for a 32-bit pointer, with nothing to serialise, frame or parse,
and no possibility of truncation.

Contract:

| | |
|---|---|
| exit code | the address of the requested proc in a 32-bit process |
| exit code `0` | resolution failed — unambiguous, since no proc lives at address 0 |
| `argv[1]` | proc to resolve; defaults to `LoadLibraryW` |
| `argv[1] argv[2]` | a DLL path and a proc name — exit code is that export's **RVA** |

## Getting the shim initialised once it is loaded

Loading the DLL is only half of injection. The shim installs its hooks from
`repro_runtime_init`, which the injector starts as a second remote thread at
`(the child's module base) + (the RVA of that export)`.

The same-bitness path finds the RVA by loading the shim in the injector itself
and subtracting the base. **That is impossible for a 32-bit shim** — a 64-bit
process cannot `LoadLibraryW` a 32-bit image, for the same machine-type reason
the child cannot load the 64-bit one.

This failure is the quietest in the whole mechanism, and worth recognising by
its shape. `LoadLibraryW` in the child *succeeded*, so nothing errors. The shim
is present in the child, correctly mapped, and completely inert: no hooks
installed, not one record emitted. What it looks like from outside is a process
with no dependencies.

The probe's second mode answers it: an RVA is bitness-agnostic once something
that *can* read the image reports it. The DLL is opened with
`DONT_RESOLVE_DLL_REFERENCES`, so its `DllMain` does not run — resolving an
export needs only the mapped image, and running a monitor shim's initialiser
inside the probe would install hooks there and emit stray records into whatever
fragment directory the environment happens to name.

The same correction applies to `propagation_windows`, where a **64-bit** shim
propagating into a WOW64 grandchild injects `<name>32.dll` — a different binary
whose exports sit at different offsets — so its own in-module RVA does not
transfer either. A 32-bit shim propagating into a 32-bit child needs no probe:
it *is* the image being injected.

## Export names must match across bitnesses

32-bit mingw decorates stdcall exports with the callee's argument byte count.
`repro_runtime_init` takes one pointer, so a 32-bit build exports
`repro_runtime_init@4` while the 64-bit build — where there is no stdcall to
decorate — exports it plain. Every lookup asks for the undecorated name, so a
decorated export resolves to nothing and produces exactly the silent
loaded-but-inert child described above.

Build the 32-bit shim with `-Wl,--kill-at` to strip the decoration, keeping one
export name across both bitnesses, which is what the naming convention below
already assumes.

The probe carries a `sizeof(pointer) != 4` compile-time guard: a 64-bit build
of it would resolve the 64-bit `kernel32` and confidently report an address
that is useless to the child, which is precisely the bug this whole mechanism
exists to avoid.

Results are cached **per probe path, on success only**. The address is stable
for the life of a boot session, so re-spawning per injection is waste; failures
are not cached because a probe that is missing now may be built later in the
same session, and a caller asking about a different probe must not be answered
from an unrelated miss.

## Naming conventions

The injector finds both artefacts by convention, so a caller that already knows
the 64-bit shim path passes nothing extra:

```
<name>.dll                            the 64-bit shim
<name>32.dll                          the 32-bit shim, same directory
stackable_hooks_wow64_probe32.exe     the probe, same directory
```

`setWow64ShimPath` / `setWow64ProbePath` override both for layouts that differ.

## Failure policy

When the 32-bit address cannot be obtained, injection **fails with a
diagnostic** naming the missing probe and how to build it. It does not fall
back to this process's 64-bit `LoadLibraryW`: that address does not fault
cleanly in the child, so the fallback would trade a clear error for a
mysterious one.

Likewise a missing `<name>32.dll` fails before anything is written into the
child, rather than attempting the 64-bit shim and collecting a NULL.

## Building the 32-bit artefacts

Both need an i686 toolchain (`pacman -S mingw-w64-i686-gcc` under MSYS2):

```sh
nim c --cpu:i386 --cc:gcc --passL:"-static-libgcc" \
  --out:stackable_hooks_wow64_probe32.exe \
  src/stackable_hooks/tools/wow64_proc_probe.nim

# The shim additionally needs --kill-at, so that its stdcall exports carry
# the same names as the 64-bit build's (see "Export names" above).
nim c --cpu:i386 --cc:gcc --app:lib \
  --passL:"-static-libgcc" --passL:"-Wl,--kill-at" \
  --out:librepro_monitor_shim32.dll <shim source>
```

io-mon's `scripts/build_shim.sh` builds both the 32-bit shim and the probe
beside the 64-bit shim when a toolchain is present, and skips them with a note
otherwise — a host without one still gets a working 64-bit shim and a clear
error if it ever meets a 32-bit child.

### Two hazards worth knowing before you build

**Static-link the compiler runtime.** A shim linked against
`libgcc_s_seh-1.dll` (or `libgcc_s_dw2-1.dll`, 32-bit) resolves only where that
mingw `bin` directory is on the DLL search path — which it generally is not for
a child spawned by a build engine that composes its own environment. The
symptom is `LoadLibraryW returned NULL` with the shim plainly present on disk.
`-static-libgcc` reduces the import list to `KERNEL32` plus the UCRT stubs,
which the system resolves unconditionally.

**Do not put the i686 toolchain on the global PATH.** The 64-bit build will
then pick up the i686 compiler and fail on nimbase.h's pointer-size assertion.
Scope it to the 32-bit invocations. Note also that the i686 `gcc.exe` needs its
*own* `bin` directory on PATH to load `libwinpthread-1.dll` and
`libgcc_s_dw2-1.dll`; without it the compiler fails to start, exits 1 and
prints nothing, which reads as a compile error in whichever `.c` file happened
to be first.

Both hazards are the same underlying one — a mingw-linked binary invoked
without its toolchain reachable — and it is silent in every direction, so it is
worth recognising by shape: **a spawned toolchain binary that fails with no
diagnostic of its own has usually not reached `main`.**

## Why this matters beyond correctness

32-bit children are not exotic on Windows. PATH trampolines are a common
source: scoop's shims are i386, so `nim`, `gcc` and friends resolved through
`scoop\shims\` hand a 32-bit process to the injector even when the real tool is
64-bit. Older toolchain binaries are another — the ezwinports `make.exe` is
i386, which is why reprobuild's `packages/make.nim` pins the 64-bit WinLibs
`mingw32-make` instead.

For a consumer that grades dependency evidence, an un-injectable child is not
merely unmonitored: it is an *unknown-scope loss*, which can disqualify the
whole action from publishing to the action cache. One 32-bit trampoline on PATH
is enough to make every build in that tree uncacheable.

## Tests

`tests/test_windows_wow64_injection.nim` covers the naming conventions, the
override hooks, the bitness probe and the probe's caching and failure contract.
The live arm — running the real probe and checking the address is plausible —
runs when `stackable_hooks_wow64_probe32.exe` is present beside the test or
under `build/lib`, and skips otherwise, since the unit suite cannot assume an
i686 toolchain.
