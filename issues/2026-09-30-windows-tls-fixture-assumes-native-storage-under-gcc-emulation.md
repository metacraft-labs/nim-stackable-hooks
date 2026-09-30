# Windows TLS fixture assumes native storage with a compiler using emulation

Status: open. Hooks `72f5782`; the fixture is unchanged at fetched dev
`8f4d806`. Shared control `36698212669` at `c114b4a` reproduces this on both
Windows x64 and Windows ARM hosts with Nim 2.2.8 / WinLibs GCC 16.1.0.

## Observed

Both the unmodified entry park and the balanced-suspension diagnostic fail
`test_windows_entry_park_thread_locals`: the borrowed child exits 5 because
its probe offset from the native TEB TLS slot differs from a fresh thread's.
The remote-thread negative control still passes by rejecting the wrong
loading thread. All fixture injections succeed; no missing-DLL failure is
being counted as a control.

The retained actual DLL has `__emutls_v.tlsProbe` and calls
`__emutls_get_address`. A separate C probe compiled by the identical compiler
also calls that helper. GCC's
[emulated TLS contract](https://gcc.gnu.org/onlinedocs/gccint/Emulated-TLS.html)
uses a lookup function and control object; this variable is not a native
link-time offset in the module's TEB TLS block. The fixture's layout assertion
therefore rejects a supported implementation of thread-local storage.

## Expected and proposed repair

[Borrowed-call deadline rules](../docs/windows-borrowed-call-deadline.md)
require the child's own main thread to load the DLL and safely resume with
its state preserved. Keep the loading-thread assertion, real container
rehashing, real process injection, parked-state checks and all deadlines.

Replace the assumed layout with actual state checks: module initialization
writes the main thread's probe; a fresh real thread must see its own zero
initial value and distinct address; writing its value must leave the main
thread's value and address intact. Require thread creation and completion.
Retain the wrong-loading-thread negative control. Add a real fixture DLL
compiled with a deliberately shared probe, and require that control to fail
the state-isolation check specifically. This prevents a passing but unexercised
probe. No monitor implementation or timeout is changed by this repair.

The failure does not establish that balanced suspension repairs compiler
startup. The complete monitored compiler comparisons continue independently.
Fetched dev `8f4d806` and searched current/deleted issue history for TLS,
thread-local offsets and emulation. The running-context issue records the
symptom but does not cover this now-confirmed fixture assumption.
