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

## Paired runtime control

Shared `94359a5`, run `36791403406`, compares original `f3a9dc1` and
matched-child `6342a21` with identical production hooks. Native x64 passes
both variants' five cases. On the ARM host, the original fails its initial
park and the matched child passes all five slow/poison/propagation cases.
Both test executables and their real fixture DLLs have AMD64 PE machine
`0x8664`. No deadline, production context sampling or page protection changes.

The auxiliary `IsWow64Process2` observation reports process-machine `0`
and native-machine `0xaa64` for both ComSpec and its observer. The observer's
own PE machine is `0x8664`, so this API result does not distinguish the
child's architecture here and is not proof that ComSpec ran as native ARM64.
The paired fixture result establishes the practical fix independently.
Artifacts: `/tmp/hooks-6342-matched-arm`, `/tmp/hooks-6342-matched-x64`.

The ordinary helper ARM-host job at `5cadd95`, run `36787069280`, also
fails only the same initial slow-call park after monitored compilation;
log `/tmp/hooks-5cadd-arm-test.log`. This links the fixture correction to
the actual failing CI gate. Complete CI with the corrected fixture remains
required before promotion.
