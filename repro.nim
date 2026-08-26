## Reprobuild project file for nim-stackable-hooks.
##
## **Typed-Cross-Project-Deps rollout, repo #1 (Wave-0 leaf).** This is a
## pure-Nim leaf library — the cross-platform stackable-hooks framework
## (LD_PRELOAD / DYLD interpose / Windows IAT+inline-hook primitives) that
## io-mon's monitor shim and reprobuild's ``test-fixtures`` edge consume. It
## has NO in-scope sibling build dependencies of its own, so the ``uses:``
## block is just the toolchain floor and there is no ``uses: "<sibling>"``
## edge.
##
## A Mode 1 / Mode 3 hybrid (per
## ``reprobuild-specs/Three-Mode-Convention-System.md``) modelled on the
## canonical ``runquota/repro.nim`` / ``codetracer-trace-format-nim/repro.nim``
## recipes:
##
## * Declares the upstream tool dependencies via ``uses:`` so consumers that
##   depend on this repo (via ``uses: "stackable_hooks"``) pick up the same
##   toolchain floor the nimble file's ``requires "nim >= 2.0.0"`` implies.
## * Declares ``library stackable_hooks`` so consumers can express a
##   workspace dependency on this repo. The importable surface is the
##   ``src/`` tree that ``config.nims`` adds to ``--path`` (``switch("path",
##   "src")``); consumers ``import stackable_hooks`` (the umbrella at
##   ``src/stackable_hooks.nim``) or the individual submodules under
##   ``src/stackable_hooks/``.
## * Emits, per test file in the corpus, a BUILD edge
##   (``buildNimUnittest.build``) that compiles ``build/test-bin/<stem>`` and
##   an EXECUTE edge (``edge.testBinary.run``) that runs it — the two-edge
##   test template from ``reprobuild-specs/Package-Model.md`` §"The test
##   template", exactly as reprobuild's own ``repro.nim`` does it. The BUILD
##   halves collect into ``test-builds`` and the EXECUTE halves into ``test``
##   so ``repro build test`` / ``repro test`` materialise the runnable
##   closure.
##
## **Per-test platform gating is no longer decided here.** This file used to
## carry its own hand-written ``portableTestSpecs`` /
## ``linuxOnlyTestSpecs`` / ``windowsOnlyTestSpecs`` tables, and they had
## drifted from ``stackable_hooks.nimble``'s list: five nimble-listed tests
## were absent from this lane entirely, one test file was in neither lane, and
## the two lists disagreed about ``test_macos_bodypatch_minimal_consumer``.
## This file's comment block also mis-described the three
## ``test_propagation_windows_*`` files as uncompilable off Windows; they are
## ``when defined(windows)``-wrapped and compile fine.
##
## Both lanes now read ``tests/corpus.nim``. The per-entry ``targets`` list
## there decides everything: ``runsOnHost`` gates the edges below, and the
## non-host targets feed the cross-target ``nim check`` matrix that
## ``tests/test_cross_target_compile.nim`` drives. See that file's header for
## why the corpus exists and what
## ``tests/test_lane_registration.nim`` enforces about it.
##
## **KNOWN RED IN THIS LANE, PRE-EXISTING AND NOT INTRODUCED HERE.**
## ``stackable_hooks.test_execute.test_linux_raw_syscalls`` exits **127**
## under reprobuild's ``dgAutomaticMonitor`` dependency policy, so
## ``repro test`` exits 1 on Linux. It is not flaky and it is not a gating
## decision made here: it reproduces identically at the commit before the
## corpus landed (22 actions, 21 succeeded, that one failed, three runs) and
## after it (40 actions, 39 succeeded, the same one failed). The binary
## itself is healthy — run directly it exits 0 with 38 ``[OK]``.
##
## What the monitor costs is silent: under it the run dies after
## ``ucontext register helpers and raw register replay are exported through
## C ABI`` with only 35 ``[OK]``, so THREE cases never execute in this lane —
## ``SIGTRAP install/uninstall substrate restores process handler without
## raising trap``, ``live INT3 handler replays raw syscall and advances saved
## RIP`` and ``memory scanner describes callsites in a controlled executable
## buffer``. The io-mon shim and this repo's live SIGTRAP/INT3 patching do
## not coexist; both want the trap. Recorded here rather than tolerated
## quietly, because a lane whose exit code is always 1 stops being read, and
## because the three skipped cases are a coverage loss the ``[OK]`` count
## alone does not show. Fixing it is out of scope for the corpus work.

import repro_project_dsl

# ``ct_test_nim_unittest`` supplies the ``buildNimUnittest.build(...)``
# typed-tool used by every test BUILD edge below, and the
# ``edge.testBinary.run(...)`` UFCS dispatch for the EXECUTE edges. It
# re-exports ``repro_project_dsl`` so the import order is unimportant.
#
# Note: unlike reprobuild's own ``repro.nim`` this leaf recipe does NOT
# import ``ct_test_runner_install`` / call ``installCtTestRunner`` — that
# module is engine-coupled and lives at reprobuild's repo root, importable
# only from reprobuild's own project extraction, not from a sibling project.
# Without it the execute edges route through the engine's default
# direct-binary runner (run the binary, key on exit status), which is
# exactly the exit-0 verification this corpus needs; the Nim ``unittest``
# harness already prints per-suite results and exits non-zero on failure.
import ct_test_nim_unittest

# The shared corpus. `include`, not `import`, because `stackable_hooks.nimble`
# consumes the same file from NimScript and the two must be the same text.
include "tests/corpus.nim"

package stackable_hooks:
  uses:
    # Toolchain floor — the PATH-resolvable binaries the build needs.
    # ``nim`` compiles every test binary (the ``buildNimUnittest.build``
    # edges below) and is ALSO invoked at run time by
    # ``test_cross_target_compile`` as ``nim check --os:… --cpu:…``; ``gcc``
    # is the C back-end ``nim c`` shells out to (and, for
    # ``test_windows_inline_hook_api`` on Linux, the compiler for the
    # ``{.compile.}``d ``install_windows.c``). Sufficient for the path-mode
    # resolver under ``nix develop``.
    "nim >=2.2 <3.0"
    "gcc >=12"

  # Library declaration — the ``src/`` tree ``config.nims`` puts on
  # ``--path`` is importable when this package is consumed via
  # ``uses: "stackable_hooks"``. The umbrella is ``src/stackable_hooks.nim``;
  # consumers may also import the submodules under
  # ``src/stackable_hooks/`` directly.
  library stackable_hooks

  devEnv:
    task "bump-version", command = "nim r scripts/bump_version.nim", description = "Bump version number"

  build:
    # Two-edge test template (Package-Model.md §"The test template"): one
    # compile-only BUILD edge + one EXECUTE edge per test file. BUILD halves
    # collect into ``test-builds`` (compile-only verification); EXECUTE
    # halves collect into ``test`` so ``repro test`` / ``repro build test``
    # materialise the runnable closure (each execute edge transitively
    # depends on its build edge). ``--path:src`` is supplied by the repo's
    # ``config.nims``, so ``nim c`` resolves the framework imports without an
    # explicit path flag here.
    var testBuildActions: seq[BuildActionDef] = @[]
    var testExecuteActions: seq[BuildActionDef] = @[]

    proc emitTestPair(source, binary: string;
                      buildActions, executeActions: var seq[BuildActionDef]) =
      var lastSlash = -1
      for i in 0 ..< binary.len:
        if binary[i] == '/' or binary[i] == '\\':
          lastSlash = i
      let stem =
        if lastSlash >= 0: binary[lastSlash + 1 .. ^1]
        else: binary
      let edge = buildNimUnittest.build(
        source = source,
        binary = binary,
        actionId = "stackable_hooks.test_build." & stem)
      buildActions.add(edge.action)
      # ``registerImplicitName = false`` because the BUILD edge already owns
      # the binary basename as the implicit target name; the explicit
      # ``actionId`` is the execute edge's selector (mirrors reprobuild's
      # ``repro.nim`` two-edge shape).
      let executeEdge = edge.testBinary.run(
        actionId = "stackable_hooks.test_execute." & stem,
        registerImplicitName = false)
      executeActions.add(executeEdge)

    # One pair per corpus entry whose ``targets`` cover this host OS. The
    # gate is ``runsOnHost``, the exact predicate ``stackable_hooks.nimble``
    # uses, so the two lanes select the same corpus by construction rather
    # than by two people keeping two lists in step.
    for spec in hostTargets():
      emitTestPair(spec.testSource, spec.testBinary,
        testBuildActions, testExecuteActions)

    discard collect("test", testExecuteActions)
    discard collect("test-builds", testBuildActions)
