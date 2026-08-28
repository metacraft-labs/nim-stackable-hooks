## Single source of truth for this repository's test corpus and for the
## cross-target ``nim check`` matrix.
##
## WHY THIS FILE EXISTS
## --------------------
## This repo has three test runners, and until this file landed each one
## carried its own hand-written copy of the corpus:
##
## * ``Justfile`` (``just test`` -> ``nimble test``)
## * ``stackable_hooks.nimble`` -- ``selectedTests()``
## * ``repro.nim`` -- ``portableTestSpecs`` / ``linuxOnlyTestSpecs`` /
##   ``windowsOnlyTestSpecs``, the reprobuild CI lane (``ci-reprobuild.yml``
##   runs ``repro build`` / ``repro test`` beside ``just test``)
##
## The two lists diverged silently: five nimble-listed tests were absent
## from ``repro.nim``, ``tests/test_linux_raw_syscalls_aarch64.nim`` was in
## NEITHER (so it ran on no host at all), and the two lists disagreed about
## the gate on ``test_macos_bodypatch_minimal_consumer``. Divergence was
## invisible because nothing compared them.
##
## Both lanes now ``include "tests/corpus.nim"`` and derive their lists from
## ``testCorpus`` below, so the lists CANNOT differ. What a shared list still
## cannot prevent -- a new file under ``tests/`` that nobody adds here, or a
## lane quietly reintroducing a literal path of its own -- is policed by
## ``tests/test_lane_registration.nim``.
##
## HOW THE GATING IS EXPRESSED
## ---------------------------
## Every entry lists the ``nim`` ``(--os, --cpu)`` targets its source
## compiles for. That single list drives BOTH:
##
## * the host run lane -- a test is built and run on host OS ``X`` iff ``X``
##   appears among its targets (``runsOnHost``); and
## * the cross-target compile lane
##   (``tests/test_cross_target_compile.nim``) -- every declared target that
##   is not the host's own is ``nim check``ed from whatever host is running,
##   so a Windows-only arm is compile-verified on Linux and macOS.
##
## So a platform gate is always an explicit, reasoned ``targets`` list plus a
## ``why`` string -- never the absence of a line from somebody's list. Three
## test sources genuinely cannot be compiled off their platform (their module
## head is ``{.error.}``-guarded); every other source compiles on all three
## and gates itself internally with ``when defined(...)``.
##
## The target lists here were measured, not guessed: each ``(file, os, cpu)``
## pair below was run through ``nim check`` and recorded.

type
  HostOs* = enum
    ## The three host operating systems this repo supports. The string
    ## values are the ``nim --os:`` spellings.
    hoLinux = "linux"
    hoMacos = "macosx"
    hoWindows = "windows"

  CheckTarget* = object
    ## One ``nim check --os:<os> --cpu:<cpu>`` target.
    os*: string
    cpu*: string

  TestEntry* = object
    ## One test file under ``tests/``. ``stem`` is the basename without the
    ## ``.nim`` extension; the source path and the build output path are
    ## derived from it so no lane spells either one.
    stem*: string
    targets*: seq[CheckTarget]
    why*: string

  ModuleEntry* = object
    ## One library module under ``src/``. ``path`` is repo-relative.
    ##
    ## Library modules have no run lane -- ``just build`` only ever checked
    ## ``src/stackable_hooks.nim``, and the umbrella does not import the
    ## Windows-only tree, so ``src/stackable_hooks/windows_injector.nim`` was
    ## compiled by NOTHING automated (proven vacuous: a bogus symbol spliced
    ## into it left ``just build`` green). Every module is listed here and
    ## every listed target is checked by
    ## ``tests/test_cross_target_compile.nim``.
    path*: string
    targets*: seq[CheckTarget]
    why*: string

  CorpusError* = object of CatchableError
    ## Raised by the corpus helpers when asked about something they cannot
    ## answer. They never answer approximately.

const
  tLinuxAmd64* = CheckTarget(os: "linux", cpu: "amd64")
  tLinuxArm64* = CheckTarget(os: "linux", cpu: "arm64")
  tMacosArm64* = CheckTarget(os: "macosx", cpu: "arm64")
  tWindowsAmd64* = CheckTarget(os: "windows", cpu: "amd64")
  tWindowsArm64* = CheckTarget(os: "windows", cpu: "arm64")
  tWindowsI386* = CheckTarget(os: "windows", cpu: "i386")

  AllHostTargets* = @[tLinuxAmd64, tMacosArm64, tWindowsAmd64]
    ## One canonical target per host OS. An entry carrying this list
    ## compiles everywhere and therefore runs everywhere.

  WindowsOnlyTargets* = @[tWindowsAmd64, tWindowsArm64]
  LinuxOnlyTargets* = @[tLinuxAmd64, tLinuxArm64]
  MacosOnlyTargets* = @[tMacosArm64]

  TestSourceDir* = "tests"
  TestBinaryDir* = "build/test-bin"
  CorpusPath* = "tests/corpus.nim"
    ## This file. ``tests/test_lane_registration.nim`` requires each lane to
    ## name exactly this one path and no other ``.nim`` path.

const testCorpus*: seq[TestEntry] = @[
  # ---- compiles and runs on every host -------------------------------
  TestEntry(stem: "test_explicit_hook_suppression", targets: AllHostTargets,
    why: "Portable: exercises the real per-thread suppression storage " &
         "through the public reentrancy API on every platform."),
  TestEntry(stem: "test_external_tls_combined_gate", targets: AllHostTargets,
    why: "Portable: a source-text contract check over reentrancy.nim; " &
         "host-independent."),
  TestEntry(stem: "test_hook_registry_priority_order", targets: AllHostTargets,
    why: "Portable framework primitive, no OS gate in the file."),
  TestEntry(stem: "test_linux_raw_syscalls", targets: AllHostTargets,
    why: "Self-gating: its `platform support is explicit` case has " &
         "`when linux/amd64` / `else` arms, so it asserts the " &
         "unsupported-platform contract off Linux."),
  TestEntry(stem: "test_linux_raw_syscalls_aarch64",
    targets: @[tLinuxAmd64, tLinuxArm64, tMacosArm64, tWindowsAmd64],
    why: "Self-gating `when defined(linux) and defined(arm64)` with an " &
         "`else: static: doAssert` arm, so it compiles and runs " &
         "everywhere. linux/arm64 is listed explicitly because that is " &
         "the ONLY target on which its body is live; before this corpus " &
         "the file was in no lane at all and ran on no host."),
  TestEntry(stem: "test_macos_bodypatch_minimal_consumer",
    targets: AllHostTargets,
    why: "Self-gating `when defined(macosx)` with an " &
         "`else: static: doAssert not defined(macosx)` arm."),
  TestEntry(stem: "test_per_library_enable_disable", targets: AllHostTargets,
    why: "Portable propagation-registry behaviour, no OS gate."),
  TestEntry(stem: "test_propagation_registry_concurrent",
    targets: AllHostTargets,
    why: "Portable propagation-registry behaviour under threads."),
  TestEntry(stem: "test_propagation_windows_edge_cases",
    targets: @[tLinuxAmd64, tMacosArm64, tWindowsAmd64, tWindowsArm64],
    why: "Body is `when defined(windows)`-wrapped, so it COMPILES " &
         "everywhere and is a no-op off Windows. (repro.nim used to " &
         "claim it could not compile off Windows and gated its edge " &
         "away; that claim was wrong -- the file that actually has an " &
         "unconditional Windows-only import is " &
         "test_propagation_windows_remote_buffer_lifetime.)"),
  TestEntry(stem: "test_propagation_windows_fork_bomb",
    targets: @[tLinuxAmd64, tMacosArm64, tWindowsAmd64, tWindowsArm64],
    why: "Body is `when defined(windows)`-wrapped; compiles everywhere, " &
         "no-op off Windows."),
  TestEntry(stem: "test_propagation_windows_smoke",
    targets: @[tLinuxAmd64, tMacosArm64, tWindowsAmd64, tWindowsArm64],
    why: "Body is `when defined(windows)`-wrapped; compiles everywhere, " &
         "no-op off Windows."),
  TestEntry(stem: "test_reentrancy_guard_prevents_recursion",
    targets: AllHostTargets,
    why: "Portable reentrancy-guard behaviour, no OS gate."),
  TestEntry(stem: "test_safe_tls", targets: AllHostTargets,
    why: "Portable hostile-context-safe TLS behaviour, no OS gate."),
  TestEntry(stem: "test_smoke", targets: AllHostTargets,
    why: "Portable umbrella-import smoke test."),
  TestEntry(stem: "test_windows_env_block", targets: AllHostTargets,
    why: "stackable_hooks/windows_env_block is deliberately NOT " &
         "`when defined(windows)`-gated -- the lpEnvironment encoding is " &
         "pure string/UTF-16 work -- so this runs for real on every host."),
  TestEntry(stem: "test_windows_inline_hook_api", targets: AllHostTargets,
    why: "Off Windows its `else` arm compiles install_windows.c and runs " &
         "real C-ABI doAsserts, so it is genuine coverage everywhere."),
  TestEntry(stem: "test_windows_wow64_injection",
    targets: @[tLinuxAmd64, tMacosArm64, tWindowsAmd64, tWindowsArm64],
    why: "Body is `when defined(windows)`-wrapped; compiles everywhere, " &
         "no-op off Windows. Its Windows arm is compile-verified from " &
         "any host by the cross-target lane."),
  TestEntry(stem: "test_lane_registration", targets: AllHostTargets,
    why: "The recurrence guard itself: proves the lanes cannot diverge. " &
         "Pure source inspection, portable."),
  TestEntry(stem: "test_cross_target_compile", targets: AllHostTargets,
    why: "The cross-target `nim check` lane. Drives the compiler out of " &
         "process for every target below that is not the host's own."),

  # ---- genuinely platform-gated: the source cannot be COMPILED elsewhere
  TestEntry(stem: "test_linux_preload_helpers", targets: LinuxOnlyTargets,
    why: "Opens with `when not defined(linux): {.error.}` and imports " &
         "stackable_hooks/platform/linux_preload, which is itself " &
         "`{.error.}`-guarded off Linux. Linux-only by construction."),
  TestEntry(stem: "test_propagation_windows_remote_buffer_lifetime",
    targets: WindowsOnlyTargets,
    why: "Its `when not defined(windows): quit(0)` guard is DEAD CODE: " &
         "the unconditional `import stackable_hooks/propagation_windows` " &
         "below it fails to COMPILE off Windows, so the runtime skip can " &
         "never be reached. Windows-only by construction."),
  TestEntry(stem: "test_windows_injector_fork_runtime",
    targets: WindowsOnlyTargets,
    why: "Unconditionally imports stackable_hooks/windows_injector, whose " &
         "module head is `{.error.}` off Windows. Windows-only by " &
         "construction; both Windows CPUs are checked because " &
         "ci-reprobuild.yml runs eph-win-x64 AND eph-win-arm64."),
]

const moduleCorpus*: seq[ModuleEntry] = @[
  ModuleEntry(path: "src/stackable_hooks.nim",
    targets: @[tLinuxAmd64, tLinuxArm64, tMacosArm64, tWindowsAmd64,
               tWindowsArm64],
    why: "The public umbrella. Note it imports the Windows tree only " &
         "`when defined(windows)`, which is why checking it on Linux says " &
         "nothing about windows_injector.nim -- see that entry."),
  ModuleEntry(path: "src/stackable_hooks/hook_registry.nim",
    targets: AllHostTargets, why: "Portable framework core."),
  ModuleEntry(path: "src/stackable_hooks/propagation.nim",
    targets: AllHostTargets,
    why: "Portable; has an internal `when defined(macosx)` arm that the " &
         "macosx target here is what compiles."),
  ModuleEntry(path: "src/stackable_hooks/reentrancy.nim",
    targets: AllHostTargets,
    why: "Portable; internal `when defined(windows)` arms compiled by the " &
         "windows target here."),
  ModuleEntry(path: "src/stackable_hooks/safe_tls.nim",
    targets: AllHostTargets, why: "Portable pthread/TLS abstraction."),
  ModuleEntry(path: "src/stackable_hooks/windows_env_block.nim",
    targets: AllHostTargets,
    why: "Deliberately not OS-gated: pure lpEnvironment string encoding."),
  ModuleEntry(path: "src/stackable_hooks/propagation_windows.nim",
    targets: WindowsOnlyTargets,
    why: "`when not defined(windows): {.error.}` module head."),
  ModuleEntry(path: "src/stackable_hooks/windows_fork_runtime.nim",
    targets: WindowsOnlyTargets,
    why: "`when not defined(windows): {.error.}` module head."),
  ModuleEntry(path: "src/stackable_hooks/windows_injector.nim",
    targets: WindowsOnlyTargets,
    why: "`when not defined(windows): {.error.}` module head, and NOT " &
         "reachable from src/stackable_hooks.nim on a non-Windows host. " &
         "This entry is the whole reason the cross-target lane exists: " &
         "`just build` could not see a bogus symbol in this file."),
  ModuleEntry(path: "src/stackable_hooks/platform/linux_preload.nim",
    targets: LinuxOnlyTargets,
    why: "`when not defined(linux): {.error.}` module head."),
  ModuleEntry(path: "src/stackable_hooks/platform/linux_raw_syscalls.nim",
    targets: @[tLinuxAmd64, tLinuxArm64, tMacosArm64, tWindowsAmd64],
    why: "Compiles everywhere; its live body is " &
         "`when defined(linux) and defined(amd64)`."),
  ModuleEntry(path: "src/stackable_hooks/platform/linux_raw_syscalls_aarch64.nim",
    targets: @[tLinuxAmd64, tLinuxArm64, tMacosArm64, tWindowsAmd64],
    why: "Compiles everywhere; its live body is " &
         "`when defined(linux) and defined(arm64)`, so linux/arm64 is the " &
         "target that actually compiles the AArch64 body-patch code."),
  ModuleEntry(path: "src/stackable_hooks/platform/macos_bodypatch.nim",
    targets: MacosOnlyTargets,
    why: "`when not defined(macosx): {.error.}` module head."),
  ModuleEntry(path: "src/stackable_hooks/platform/windows_iat_patcher.nim",
    targets: @[tLinuxAmd64, tMacosArm64, tWindowsAmd64, tWindowsArm64],
    why: "Compiles everywhere (its body is `when defined(windows)`), and " &
         "is imported by NO other module and NO test -- the cross-target " &
         "lane is the only thing that compiles its Windows body."),
  ModuleEntry(path: "src/stackable_hooks/inline_hook/windows_inline_hook.nim",
    targets: WindowsOnlyTargets,
    why: "`when not defined(windows): {.error.}` module head."),
  ModuleEntry(path: "src/stackable_hooks/tools/inject_helper.nim",
    targets: WindowsOnlyTargets,
    why: "Windows-only AND `{.error.}` unless 64-bit, so amd64/arm64 " &
         "only -- i386 is a deliberate compile error there."),
  ModuleEntry(path: "src/stackable_hooks/tools/wow64_proc_probe.nim",
    targets: @[tWindowsI386],
    why: "Windows-only AND `{.error.}` unless 32-bit: its whole purpose " &
         "is to report a 32-bit proc address, so i386 is its only target."),
]

proc testSource*(e: TestEntry): string =
  ## Repo-relative path of the test source.
  TestSourceDir & "/" & e.stem & ".nim"

proc testBinary*(e: TestEntry): string =
  ## Repo-relative path of the compiled test binary.
  TestBinaryDir & "/" & e.stem

proc toHostOs*(osName: string): HostOs =
  ## Map a ``nim --os:`` spelling onto ``HostOs``.
  ##
  ## RAISES rather than guessing. A silently-wrong answer here would make
  ## an entry look gated for a platform nobody runs.
  case osName
  of "linux": hoLinux
  of "macosx": hoMacos
  of "windows": hoWindows
  else:
    raise newException(CorpusError,
      "corpus: unknown --os spelling: '" & osName & "'")

proc targetOses*(targets: seq[CheckTarget]): set[HostOs] =
  ## The set of host operating systems a target list covers.
  result = {}
  for t in targets:
    result.incl toHostOs(t.os)

proc hostOs*(): HostOs =
  when defined(linux): hoLinux
  elif defined(macosx): hoMacos
  elif defined(windows): hoWindows
  else:
    {.fatal: "stackable-hooks corpus: unsupported host OS".}

proc hostCpuName*(): string =
  ## The ``nim --cpu:`` spelling of the host this is running on.
  ##
  ## Deliberately NOT called ``hostCpu``: Nim identifiers are
  ## case-insensitive past the first character, so that spelling collides
  ## with ``system.hostCPU``.
  when defined(amd64): "amd64"
  elif defined(arm64): "arm64"
  elif defined(i386): "i386"
  else: hostCPU

proc runsOnHost*(e: TestEntry): bool =
  ## True iff this test's source compiles for -- and is therefore built and
  ## run on -- the current host OS. This is the ONLY gate both run lanes
  ## consult, so they cannot disagree.
  hostOs() in targetOses(e.targets)

proc hostTargets*(): seq[TestEntry] =
  ## The test entries this host builds and runs, in a stable order.
  result = @[]
  for e in testCorpus:
    if e.runsOnHost:
      result.add e
  # Insertion sort by source path: no std/algorithm import, so this stays
  # usable from NimScript (the .nimble file) unchanged.
  for i in 1 ..< result.len:
    let cur = result[i]
    var j = i - 1
    while j >= 0 and result[j].stem > cur.stem:
      result[j + 1] = result[j]
      dec j
    result[j + 1] = cur

proc hostTestSources*(): seq[string] =
  ## Repo-relative sources of the tests this host runs, sorted.
  result = @[]
  for e in hostTargets():
    result.add e.testSource
