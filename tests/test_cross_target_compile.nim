## The cross-target compile lane: every platform arm is checked from every
## host.
##
## WHY
## ---
## ``just build`` was ``nim check src/stackable_hooks.nim``, and the umbrella
## imports the Windows tree only ``when defined(windows)``. So on Linux and
## macOS NOTHING automated compiled
## ``src/stackable_hooks/windows_injector.nim`` -- proven vacuous by
## experiment: a bogus symbol spliced into that file left ``just build``
## green. Every ``--os:windows`` check during the io-mon decomposed-host-API
## campaign was a manual step, which matters because that file changed
## (``env`` on ``runWithMonitorShim``, ``rootPid`` on
## ``WindowsInjectionResult``). The same hole covered
## ``platform/windows_iat_patcher.nim``, which no module and no test imports
## at all.
##
## WHAT THIS DOES
## --------------
## For every entry in ``tests/corpus.nim`` -- both ``moduleCorpus`` and
## ``testCorpus`` -- it drives ``nim check --os:<os> --cpu:<cpu>`` out of
## process for each declared target that is not this host's own
## ``(os, cpu)``, and judges by EXIT CODE. A type-level or platform-arm
## breakage is only observable by running the compiler and reading its exit
## status; nothing in-process can see it.
##
## The host's own target is skipped because the run lane already compiles
## and runs it; everything else -- the macOS arm on Linux, both Windows CPUs
## everywhere, linux/arm64's AArch64 body-patch code on an amd64 host -- is
## checked here.
##
## NO MOCKS: this shells out to the real ``nim`` binary against the real
## sources. That is the point.
##
## ANTI-VACUITY
## ------------
## A matrix that silently covers fewer files than it claims is the exact
## failure this repo has already hit once (a coverage check that scanned two
## of the directories it claimed to cover). So the first case below asserts
## that EVERY corpus entry contributed at least one job before any job runs,
## and the counts are asserted, not printed.

import std/[os, osproc, sets, streams, strutils, unittest]

import ./corpus

type
  CheckJob = object
    kind: string       ## "module" or "test"
    file: string       ## repo-relative source
    os: string
    cpu: string

  CheckOutcome = object
    job: CheckJob
    exitCode: int
    output: string

proc label(j: CheckJob): string =
  "nim check --os:" & j.os & " --cpu:" & j.cpu & " " & j.file

let repoRoot = currentSourcePath().parentDir.parentDir

proc isHostTarget(t: CheckTarget): bool =
  t.os == $hostOs() and t.cpu == hostCpuName()

proc targetsToCheck(targets: seq[CheckTarget]): seq[CheckTarget] =
  ## The targets this lane checks for one corpus entry: every declared target
  ## except this host's own — UNLESS that would leave the entry with nothing
  ## to check, in which case the host's own target is checked after all.
  ##
  ## Skipping the host target is an OPTIMISATION (the run lane already
  ## compiles it) and it must never become a coverage hole. The fallback is
  ## not hypothetical: ``src/stackable_hooks/platform/macos_bodypatch.nim``
  ## declares ``MacosOnlyTargets == @[tMacosArm64]``, which IS the host on the
  ## ``eph-macos-arm64`` runner ``ci-reprobuild.yml`` uses. Without the
  ## fallback that entry would contribute no job there, and since a library
  ## module has no run lane at all it would be compiled by NOTHING — the exact
  ## vacuity this file exists to prevent, reintroduced on the one host that
  ## cannot observe it from here. One redundant ``nim check`` is the price of
  ## keeping "every corpus entry contributes at least one job" true on EVERY
  ## host, which is what makes the coverage assertion below unconditional.
  ##
  ## Found by mutation: forcing ``isHostTarget`` to report a macosx/arm64 host
  ## reddened the coverage case here on Linux with exactly that message.
  result = @[]
  for t in targets:
    if not t.isHostTarget: result.add t
  if result.len == 0:
    result = targets

proc crossTargetJobs(): seq[CheckJob] =
  result = @[]
  for m in moduleCorpus:
    for t in m.targets.targetsToCheck:
      result.add CheckJob(kind: "module", file: m.path, os: t.os, cpu: t.cpu)
  for e in testCorpus:
    for t in e.targets.targetsToCheck:
      result.add CheckJob(kind: "test", file: e.testSource, os: t.os,
                          cpu: t.cpu)

proc nimExeOrRaise(): string =
  ## The compiler this lane drives. Raises rather than skipping: a lane that
  ## quietly does nothing when its tool is absent is worse than no lane.
  result = findExe("nim")
  if result.len == 0:
    raise newException(OSError,
      "test_cross_target_compile: 'nim' is not on PATH; this lane cannot " &
      "verify anything without it")

proc runJobs(jobs: seq[CheckJob]; parallel: int): seq[CheckOutcome] =
  let nimExe = nimExeOrRaise()
  result = newSeq[CheckOutcome](jobs.len)
  for i, j in jobs:
    result[i] = CheckOutcome(job: j, exitCode: -1, output: "")
  var live: seq[tuple[idx: int, p: Process]] = @[]
  var next = 0
  while next < jobs.len or live.len > 0:
    while next < jobs.len and live.len < parallel:
      let j = jobs[next]
      # A per-(target, file) nimcache keeps parallel jobs from colliding and
      # still lets a rerun reuse work.
      let cacheDir = repoRoot / "build" / "xcheck-nimcache" /
        (j.os & "-" & j.cpu) / j.file.multiReplace(("/", "_"), ("\\", "_"))
      # `--errorMax` bounds the child's output so a catastrophic dump can
      # never fill the pipe and wedge this loop.
      let args = @["check",
        "--os:" & j.os, "--cpu:" & j.cpu,
        "--hints:off", "--warnings:off", "--colors:off", "--errorMax:5",
        "--nimcache:" & cacheDir,
        "--path:" & (repoRoot / "src"),
        repoRoot / j.file]
      live.add (next, startProcess(nimExe, workingDir = repoRoot,
        args = args, options = {poStdErrToStdOut}))
      inc next
    var progressed = false
    var k = 0
    while k < live.len:
      if live[k].p.peekExitCode() >= 0:
        let idx = live[k].idx
        result[idx].output = live[k].p.outputStream.readAll()
        result[idx].exitCode = live[k].p.waitForExit()
        live[k].p.close()
        live.delete(k)
        progressed = true
      else:
        inc k
    if not progressed and live.len > 0:
      sleep(20)

let jobs = crossTargetJobs()

template reportFailures(outcomes: seq[CheckOutcome]) =
  ## A ``template``, not a ``proc``: ``check`` inside a plain ``proc`` prints
  ## "Check failed" and the enclosing case still reports ``[OK]``.
  var failed: seq[string] = @[]
  for o in outcomes:
    if o.exitCode != 0:
      failed.add o.job.label & "  -> exit " & $o.exitCode & "\n" &
        o.output.strip()
  if failed.len > 0:
    checkpoint("cross-target compile failures:\n" & failed.join("\n"))
  check failed.len == 0

suite "cross-target compile matrix":

  test "the matrix covers every corpus entry it claims to cover":
    var filesInMatrix: HashSet[string]
    for j in jobs:
      filesInMatrix.incl j.file
    # Unconditional on every host: `targetsToCheck` falls back to the host's
    # own target rather than emitting nothing, so there is no exemption here
    # to reason about and no host on which this assertion quietly weakens.
    var missing: seq[string]
    for m in moduleCorpus:
      if m.path notin filesInMatrix:
        missing.add "module " & m.path & " contributed no cross-target job"
    for e in testCorpus:
      if e.testSource notin filesInMatrix:
        missing.add "test " & e.testSource & " contributed no cross-target job"
    if missing.len > 0:
      checkpoint(missing.join("\n"))
    check missing.len == 0
    check filesInMatrix.len == moduleCorpus.len + testCorpus.len
    check jobs.len > 0
    # `targetsToCheck`'s fallback arm never fires on THIS host (no corpus entry
    # here declares the host as its only target), so it is asserted on the
    # function with literals instead of waiting for the macOS runner where it
    # does. Without this, deleting the fallback reddens nothing on Linux and
    # the coverage assertion above silently becomes host-dependent again.
    let hostT = CheckTarget(os: $hostOs(), cpu: hostCpuName())
    check targetsToCheck(@[hostT]) == @[hostT]
    check targetsToCheck(@[hostT, tWindowsArm64]) == @[tWindowsArm64]
    check targetsToCheck(@[tWindowsArm64, hostT]) == @[tWindowsArm64]
    check targetsToCheck(@[tWindowsAmd64, tWindowsArm64]) ==
      @[tWindowsAmd64, tWindowsArm64]

  test "the Windows injector is in the matrix for both Windows CPUs":
    # Named explicitly because it is the file whose absence from every
    # automated lane motivated this whole test, and because it is the file
    # the io-mon decomposed-host-API work changed.
    var seen: HashSet[string]
    for j in jobs:
      if j.file == "src/stackable_hooks/windows_injector.nim":
        seen.incl j.os & "/" & j.cpu
    check "windows/amd64" in seen
    check "windows/arm64" in seen

  test "every declared cross-target compiles":
    let outcomes = runJobs(jobs, parallel = 12)
    var ran = 0
    for o in outcomes:
      if o.exitCode >= 0: inc ran
    # An outcome left at -1 means the pool never collected it.
    check ran == jobs.len
    reportFailures(outcomes)
    echo "cross-target compile: " & $jobs.len & " nim check runs, host " &
      $hostOs() & "/" & hostCpuName()
