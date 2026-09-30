# Windows x64 slow-call fixture assumes ComSpec has the same architecture

Status: open. Observed at hooks `ece47a5`, whose slow-call fixture is unchanged
from `def2464` and `78f144a`.

## Observed

Shared run `36790224207` at `68acdfb` compiles and executes all 26 Windows
host tests. Native x64 passes all 26. The ARM host passes 25 and fails the
first slow-call case at `park.status == epsParked`, with `epsTimedOut`.
This is before borrowed hook initialization; the page-preparation candidate
has not executed in that child. The original/prepared full-corpus comparison
at `a386525` retains both outcomes on each host.

The fixture compiles as x64 but spawns the ambient `ComSpec` and calls the
x64 entry park unconditionally. Its child architecture is not established.
Earlier balanced-context diagnostics already used a specifically compiled
x64 child, so their slow-call passes do not validate the ambient-ComSpec
assumption. This source-level gap is established; whether the failing child
is a different architecture remains to be measured.

## Expected and repair plan

[Borrowed-call deadline rules](../docs/windows-borrowed-call-deadline.md)
and the fixture header require a real x64 child, its own main-thread stack,
exit 42 after successful hand-back, and termination after a poisoned borrow.
Use the test executable itself with an early child-mode argument to produce
exit 42. That guarantees the parent's exact executable architecture without
selecting a host shell. Keep the real kernel Sleep, DLL loader delay,
propagation tail, poison checks and every deadline. Validate the unchanged
assertions on native x64 and x64 emulation; inspect ComSpec's PE machine as
supporting evidence rather than treating the inference as a measurement.

Fetched dev `8f4d806` and agents `2d697ce`; searched open issues and complete
issue history for ComSpec, ARM cmd and slow-call child assumptions. The
running-context issue covers a separate production API contract.
