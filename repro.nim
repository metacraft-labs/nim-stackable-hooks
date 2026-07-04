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
## * Emits, per test file under ``tests/``, a BUILD edge
##   (``buildNimUnittest.build``) that compiles ``build/test-bin/<stem>`` and
##   an EXECUTE edge (``edge.testBinary.run``) that runs it — the two-edge
##   test template from ``reprobuild-specs/Package-Model.md`` §"The test
##   template", exactly as reprobuild's own ``repro.nim`` does it. The BUILD
##   halves collect into ``test-builds`` and the EXECUTE halves into ``test``
##   so ``repro build test`` / ``repro test`` materialise the runnable
##   closure.
##
## **Per-test platform gating.** Each test file self-adapts to its target OS
## via ``when defined(...)`` in the file itself; the edge here mirrors that
## exactly so the corpus this host runs matches what the repo's own
## ``nim c -r`` would run:
##
##   * The three ``test_propagation_windows_*`` files ``import
##     stackable_hooks/propagation_windows``, whose module head carries a hard
##     ``{.error: "Windows-only".}`` on non-Windows. Their top-of-file
##     ``when not defined(windows): quit(0)`` runtime guard never fires
##     because the unconditional ``import`` below it fails to COMPILE off
##     Windows. They are genuinely Windows-only, so their edges are gated
##     ``when defined(windows)`` at extraction and are simply absent from the
##     graph on Linux/macOS.
##   * Every other test compiles + runs to ``exit 0`` on this Linux host —
##     including ``test_macos_bodypatch_minimal_consumer`` (its non-macOS
##     ``else:`` branch is a trivial ``static: doAssert not defined(macosx)``)
##     and ``test_windows_inline_hook_api`` (its non-Windows ``else:`` branch
##     compiles ``install_windows.c`` and runs real C-ABI ``doAssert``s). Both
##     therefore keep a runnable edge on Linux; their OS-specific bodies are
##     the file's own concern.

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

type
  StackableTestSpec = object
    ## One entry per test file. ``source`` is the repo-relative ``.nim``
    ## path; ``binary`` is the ``build/test-bin/<stem>`` output.
    source: string
    binary: string

const portableTestSpecs: seq[StackableTestSpec] = @[
  # Tests that compile + run to exit 0 on every host (Linux/macOS/Windows).
  # Portable framework primitives with no OS gate in the file.
  StackableTestSpec(source: "tests/test_hook_registry_priority_order.nim",
    binary: "build/test-bin/test_hook_registry_priority_order"),
  StackableTestSpec(source: "tests/test_per_library_enable_disable.nim",
    binary: "build/test-bin/test_per_library_enable_disable"),
  StackableTestSpec(source: "tests/test_propagation_registry_concurrent.nim",
    binary: "build/test-bin/test_propagation_registry_concurrent"),
  StackableTestSpec(source: "tests/test_reentrancy_guard_prevents_recursion.nim",
    binary: "build/test-bin/test_reentrancy_guard_prevents_recursion"),
  StackableTestSpec(source: "tests/test_safe_tls.nim",
    binary: "build/test-bin/test_safe_tls"),
  StackableTestSpec(source: "tests/test_smoke.nim",
    binary: "build/test-bin/test_smoke"),
  # ``test_linux_raw_syscalls`` has no OS gate — its ``platform support is
  # explicit`` case has ``when linux/amd64`` … ``else`` arms so it compiles +
  # runs everywhere (asserting the unsupported-platform contract off Linux).
  StackableTestSpec(source: "tests/test_linux_raw_syscalls.nim",
    binary: "build/test-bin/test_linux_raw_syscalls"),
  # ``test_macos_bodypatch_minimal_consumer``: ``when defined(macosx):
  # <bodypatch API> else: static: doAssert not defined(macosx)`` — the
  # non-macOS arm is a trivial compile-time assertion, so it runs to exit 0
  # on Linux/Windows too.
  StackableTestSpec(source: "tests/test_macos_bodypatch_minimal_consumer.nim",
    binary: "build/test-bin/test_macos_bodypatch_minimal_consumer"),
  # ``test_windows_inline_hook_api``: ``when defined(windows): <Nim wrapper
  # API> else: <compile install_windows.c + run C-ABI doAsserts>`` — the
  # non-Windows arm does real C-ABI verification, so it runs to exit 0 on
  # Linux/macOS.
  StackableTestSpec(source: "tests/test_windows_inline_hook_api.nim",
    binary: "build/test-bin/test_windows_inline_hook_api"),
]

const linuxOnlyTestSpecs: seq[StackableTestSpec] = @[
  # ``test_linux_preload_helpers`` opens with ``when not defined(linux):
  # {.error.}`` — it imports ``stackable_hooks/platform/linux_preload`` and
  # exercises the LD_PRELOAD reentrancy/RTLD_NEXT primitives. Linux-only by
  # construction; gated ``when defined(linux)`` at extraction below.
  StackableTestSpec(source: "tests/test_linux_preload_helpers.nim",
    binary: "build/test-bin/test_linux_preload_helpers"),
]

const windowsOnlyTestSpecs: seq[StackableTestSpec] = @[
  # The three ``propagation_windows`` tests import a module whose head is
  # ``when not defined(windows): {.error: "Windows-only".}``. They do not
  # compile off Windows, so their edges are gated ``when defined(windows)``
  # and absent from the Linux/macOS graph.
  StackableTestSpec(source: "tests/test_propagation_windows_smoke.nim",
    binary: "build/test-bin/test_propagation_windows_smoke"),
  StackableTestSpec(source: "tests/test_propagation_windows_edge_cases.nim",
    binary: "build/test-bin/test_propagation_windows_edge_cases"),
  StackableTestSpec(source: "tests/test_propagation_windows_fork_bomb.nim",
    binary: "build/test-bin/test_propagation_windows_fork_bomb"),
]

package stackable_hooks:
  uses:
    # Toolchain floor — the PATH-resolvable binaries the build needs.
    # ``nim`` compiles every test binary (the ``buildNimUnittest.build``
    # edges below); ``gcc`` is the C back-end ``nim c`` shells out to (and,
    # for ``test_windows_inline_hook_api`` on Linux, the compiler for the
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

    # Portable tests — always in the graph.
    for spec in portableTestSpecs:
      emitTestPair(spec.source, spec.binary,
        testBuildActions, testExecuteActions)

    # Linux-only tests — only compilable/runnable on Linux; gated at
    # extraction so they never enter the graph on macOS/Windows.
    when defined(linux):
      for spec in linuxOnlyTestSpecs:
        emitTestPair(spec.source, spec.binary,
          testBuildActions, testExecuteActions)

    # Windows-only tests — import a ``{.error.}``-guarded module off Windows,
    # so their edges only exist when the extraction host is Windows.
    when defined(windows):
      for spec in windowsOnlyTestSpecs:
        emitTestPair(spec.source, spec.binary,
          testBuildActions, testExecuteActions)

    discard collect("test", testExecuteActions)
    discard collect("test-builds", testBuildActions)
