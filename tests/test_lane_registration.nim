## The recurrence guard: the three test lanes CANNOT silently disagree.
##
## WHAT WENT WRONG, AND WHY A GUARD IS NEEDED AT ALL
## -------------------------------------------------
## This repo has three runners -- ``Justfile`` (-> ``nimble test``),
## ``stackable_hooks.nimble``'s test list, and ``repro.nim``'s reprobuild
## edges (a separate CI lane: ``.github/workflows/ci-reprobuild.yml`` runs
## ``repro build`` / ``repro test`` beside ``just test``). Two of them each
## kept a hand-written copy of the corpus, and the copies drifted:
##
## * five nimble-listed tests were absent from ``repro.nim`` and so ran in
##   no reprobuild lane;
## * ``tests/test_linux_raw_syscalls_aarch64.nim`` was in NEITHER list and
##   therefore ran on no host at all;
## * the two lists disagreed about ``test_macos_bodypatch_minimal_consumer``;
## * ``src/stackable_hooks/windows_injector.nim`` was compiled by nothing
##   automated on a non-Windows host.
##
## ``tests/corpus.nim`` removes the duplicate lists. This file guards what a
## shared list still cannot: a NEW file that nobody adds to the corpus, and a
## lane quietly reintroducing a path of its own.
##
## NO MOCKS. Every assertion below reads the real files on disk from the real
## repository root.
##
## THE PARSER RAISES; IT NEVER ANSWERS SHORT
## -----------------------------------------
## The equivalent guard in the sibling repo ``nim-shm-gset`` was defeated
## precisely here: its parser matched ONE literal needle and, when the source
## was spelled differently, returned fewer results instead of raising -- so a
## second writer spelled without spaces slipped past while the guard's count
## assertion still cheerfully read 1.
##
## ``nimStringLiterals`` below is therefore a COMPLETE lexical scan, not a
## needle search: it walks the source character by character through line
## comments, nested ``#[ ]#`` block comments, char literals (including the
## ``0xD65F03C0'u32`` numeric-suffix apostrophe that is NOT a char literal),
## raw strings, generalised raw string literals and triple-quoted strings,
## and it RAISES ``LaneParseError`` on every construct it cannot finish
## parsing. A file it cannot lex fails the test loudly instead of yielding a
## short, reassuring answer. The lane rules are then stated over the WHOLE
## literal set ("no literal may ..."), so a differently-spelled path cannot
## evade them the way a needle can.
##
## ``check`` is only ever used directly inside a ``test`` block here, and
## every assertion helper is a ``template``: ``check`` inside a plain ``proc``
## prints "Check failed" and still reports ``[OK]``.

import std/[os, sequtils, sets, strutils, unittest]

import ./corpus

type
  LaneParseError* = object of CatchableError
    ## Raised when a source cannot be lexed. Never swallowed.

proc laneFail(origin: string; pos: int; msg: string) {.noreturn.} =
  raise newException(LaneParseError,
    origin & ": byte offset " & $pos & ": " & msg)

const
  IdentStart = {'a'..'z', 'A'..'Z', '_', '\x80'..'\xFF'}
  IdentCont = {'a'..'z', 'A'..'Z', '0'..'9', '_', '\x80'..'\xFF'}
  AlnumUnderscore = {'a'..'z', 'A'..'Z', '0'..'9', '_'}

proc scanRawString(source, origin: string; start: int;
                   value: var string): int =
  ## Lex a raw string body that begins at ``source[start] == '"'``.
  ## Returns the index just past the closing quote. Raises if unterminated.
  assert source[start] == '"'
  var i = start
  if i + 2 < source.len and source[i+1] == '"' and source[i+2] == '"':
    # r""" ... """ -- same terminator rule as a normal triple-quoted string.
    i += 3
    let contentStart = i
    while true:
      if i + 2 >= source.len:
        laneFail(origin, start, "unterminated triple-quoted raw string")
      if source[i] == '"' and source[i+1] == '"' and source[i+2] == '"':
        var stop = i
        var j = i + 3
        while j < source.len and source[j] == '"':
          stop = j - 2
          inc j
        value = source[contentStart ..< stop]
        return j
      inc i
  inc i
  var buf = ""
  while true:
    if i >= source.len:
      laneFail(origin, start, "unterminated raw string literal")
    if source[i] == '"':
      if i + 1 < source.len and source[i+1] == '"':
        buf.add '"'
        i += 2
        continue
      value = buf
      return i + 1
    if source[i] == '\n':
      laneFail(origin, start, "newline inside a single-line raw string")
    buf.add source[i]
    inc i

proc scanString(source, origin: string; start: int;
                value: var string): int =
  ## Lex a normal (escaping) string literal beginning at ``source[start]``.
  ## Returns the index just past the closing quote. Raises if unterminated.
  assert source[start] == '"'
  if start + 2 < source.len and source[start+1] == '"' and
     source[start+2] == '"':
    return scanRawString(source, origin, start, value)
  var i = start + 1
  var buf = ""
  while true:
    if i >= source.len:
      laneFail(origin, start, "unterminated string literal (end of file)")
    let c = source[i]
    if c == '\n':
      laneFail(origin, start, "newline inside a single-line string literal")
    if c == '\\':
      if i + 1 >= source.len:
        laneFail(origin, start, "escape at end of file")
      let e = source[i+1]
      case e
      of 'n': buf.add '\n'
      of 't': buf.add '\t'
      of 'r': buf.add '\r'
      of '\\': buf.add '\\'
      of '"': buf.add '"'
      of '\'': buf.add '\''
      of '0'..'9', 'x', 'X', 'a', 'b', 'e', 'f', 'v', 'p', 'l', 'c',
         'A'..'W', 'Y', 'Z', 'd', 'g'..'k', 'm', 'o', 'q', 's', 'u', 'w',
         'y', 'z':
        # Numeric / named escapes: the exact expansion is irrelevant to the
        # lane rules below (they ask about path SHAPE), but the escape must
        # still be consumed so the closing quote is found correctly.
        buf.add '?'
      else:
        laneFail(origin, i, "unrecognised escape '\\" & e & "'")
      i += 2
      continue
    if c == '"':
      value = buf
      return i + 1
    buf.add c
    inc i

proc nimStringLiterals*(source, origin: string): seq[string] =
  ## Every string literal in ``source``, in order.
  ##
  ## A COMPLETE lexical scan, deliberately not a needle search. Raises
  ## ``LaneParseError`` on any construct it cannot finish parsing, so a
  ## source this routine does not understand fails loudly rather than
  ## producing a short list that the caller's count assertion would accept.
  result = @[]
  var i = 0
  let n = source.len
  while i < n:
    let c = source[i]
    if c == '#':
      if i + 1 < n and source[i+1] == '[':
        var depth = 1
        let opened = i
        i += 2
        while i < n and depth > 0:
          if i + 1 < n and source[i] == '#' and source[i+1] == '[':
            inc depth
            i += 2
          elif i + 1 < n and source[i] == ']' and source[i+1] == '#':
            dec depth
            i += 2
          else:
            inc i
        if depth != 0:
          laneFail(origin, opened, "unterminated '#[' block comment")
      else:
        while i < n and source[i] != '\n': inc i
    elif c == '\'':
      # A leading apostrophe is a char literal ONLY when it does not follow
      # an alphanumeric -- otherwise it is a typed-numeric-literal suffix
      # marker such as `0xD65F03C0'u32` or `16'u32`, which appears all over
      # this repo's AArch64 fixtures.
      if i > 0 and source[i-1] in AlnumUnderscore:
        inc i
        continue
      let opened = i
      inc i
      if i < n and source[i] == '\\':
        inc i
        while i < n and source[i] != '\'': inc i
      elif i < n:
        inc i
      if i >= n or source[i] != '\'':
        laneFail(origin, opened, "unterminated character literal")
      inc i
    elif c == '"':
      var value = ""
      i = scanString(source, origin, i, value)
      result.add value
    elif c in IdentStart:
      var j = i
      while j < n and source[j] in IdentCont: inc j
      if j < n and source[j] == '"':
        # Generalised raw string literal: `r"..."`, `R"..."`, `re"..."`, ...
        var value = ""
        i = scanRawString(source, origin, j, value)
        result.add value
      else:
        i = j
    else:
      inc i

proc readSourceOrRaise(path: string): string =
  ## Read a file the guard depends on. Raises rather than returning "" --
  ## an empty answer would make every "no forbidden literal" rule below
  ## pass vacuously.
  if not fileExists(path):
    raise newException(LaneParseError,
      "lane guard: required file is missing: " & path)
  result = readFile(path).replace("\r\n", "\n")
  if result.len == 0:
    raise newException(LaneParseError,
      "lane guard: required file is empty: " & path)

proc basenameOf(p: string): string =
  var cut = -1
  for i in 0 ..< p.len:
    if p[i] == '/' or p[i] == '\\': cut = i
  if cut >= 0: p[cut + 1 .. ^1] else: p

proc laneRuleViolations(literals: seq[string]): seq[string] =
  ## Which of ``literals`` a lane file is forbidden to contain, and why.
  ##
  ## Stated over the WHOLE literal set rather than as a search for one
  ## spelling: a lane file may name exactly one path, ``tests/corpus.nim``,
  ## and nothing that looks like a test source, stem or build output.
  result = @[]
  for lit in literals:
    if lit == CorpusPath: continue
    if lit.contains(TestBinaryDir):
      result.add "'" & lit & "' names the test binary directory; the " &
        "corpus derives binary paths (testBinary)"
    elif lit.startsWith(TestSourceDir & "/"):
      result.add "'" & lit & "' is a path under " & TestSourceDir &
        "/; only " & CorpusPath & " may be named"
    elif basenameOf(lit).startsWith("test_"):
      result.add "'" & lit & "' looks like a test stem or source; the " &
        "corpus owns those"

proc nimFilesUnder(dir: string; recursive: bool): seq[string] =
  ## Every ``.nim`` file in ``dir`` -- recursively when asked.
  ##
  ## Raises if the directory does not exist. A coverage check that silently
  ## scans nothing is the exact failure this whole file exists to prevent,
  ## and the most recent instance of it in this campaign was a check that
  ## walked two of the directories it claimed to walk.
  ##
  ## ``tests/`` is scanned NON-recursively on purpose: the corpus can only
  ## name ``tests/<stem>.nim``, so ``tests/fixtures/**`` is data, not a lane
  ## candidate. ``src/`` is scanned recursively because the module corpus
  ## carries full repo-relative paths.
  if not dirExists(dir):
    raise newException(LaneParseError,
      "lane guard: expected directory is missing: " & dir)
  result = @[]
  if recursive:
    for path in walkDirRec(dir, relative = false):
      if path.endsWith(".nim"):
        result.add path
  else:
    for kind, path in walkDir(dir, relative = false):
      if kind == pcFile and path.endsWith(".nim"):
        result.add path

proc justfileNimPaths(text: string): seq[string] =
  ## Every whitespace-delimited token in the Justfile that names a ``.nim``
  ## file. Not a Nim lexer -- just's recipes are shell, so the honest
  ## parse is "tokens".
  result = @[]
  for rawLine in text.split('\n'):
    let line = rawLine.strip()
    if line.startsWith("#"): continue
    for tok in line.splitWhitespace():
      let t = tok.strip(chars = {'"', '\'', '(', ')', ';', ','})
      if t.endsWith(".nim"):
        result.add t

let repoRoot = currentSourcePath().parentDir.parentDir

template checkNoViolations(label: string; violationsExpr: seq[string]) =
  ## A ``template``, not a ``proc``: ``check`` inside a plain ``proc``
  ## prints "Check failed" and the enclosing case still reports ``[OK]``.
  ##
  ## ``violationsExpr`` is bound to a ``let`` ONCE. It used to be referenced
  ## three times in the body, which re-evaluated the caller's expression
  ## three times; with a ``toSeq(setA - setB)`` argument that raised
  ## ``IndexDefect`` instead of printing the violation, so the case failed
  ## for the wrong reason and its message was lost. Found by mutation M4/M13.
  block:
    let violations: seq[string] = violationsExpr
    if violations.len > 0:
      checkpoint(label & " violations:\n  " & violations.join("\n  "))
    check violations.len == 0

suite "lane registration parity":

  test "the literal lexer raises on sources it cannot parse":
    # The parser's own contract, asserted before anything trusts it.
    expect LaneParseError:
      discard nimStringLiterals("let a = \"unterminated", "<probe>")
    expect LaneParseError:
      discard nimStringLiterals("let a = \"line\nbreak\"", "<probe>")
    expect LaneParseError:
      discard nimStringLiterals("#[ never closed", "<probe>")
    expect LaneParseError:
      discard nimStringLiterals("let c = 'x", "<probe>")
    expect LaneParseError:
      discard nimStringLiterals("let s = \"\"\"open", "<probe>")
    expect LaneParseError:
      discard nimStringLiterals("let s = r\"open", "<probe>")
    expect LaneParseError:
      discard readSourceOrRaise(repoRoot / "no-such-file.nim")

  test "the literal lexer sees every spelling, not one needle":
    # The nim-shm-gset defeat was a second writer "spelled without spaces".
    # These are the spellings a hand-written needle would miss.
    check nimStringLiterals("include \"tests/corpus.nim\"", "<p>") ==
      @["tests/corpus.nim"]
    check nimStringLiterals("include\"tests/corpus.nim\"", "<p>") ==
      @["tests/corpus.nim"]
    check nimStringLiterals("let a = \"x\" & \"y\"", "<p>") == @["x", "y"]
    check nimStringLiterals("let a = r\"tests\\t.nim\"", "<p>") ==
      @["tests\\t.nim"]
    check nimStringLiterals("let a = \"\"\"tests/t.nim\"\"\"", "<p>") ==
      @["tests/t.nim"]
    # Constructs that must NOT be mistaken for strings.
    check nimStringLiterals("# \"commented\"\nlet a = \"real\"", "<p>") ==
      @["real"]
    check nimStringLiterals("#[ \"a\" #[ \"b\" ]# ]#\nlet c = \"real\"",
      "<p>") == @["real"]
    check nimStringLiterals("let x = 0xD65F03C0'u32\nlet y = \"real\"",
      "<p>") == @["real"]
    check nimStringLiterals("let c = '\\\\'\nlet y = \"real\"", "<p>") ==
      @["real"]
    check nimStringLiterals("let c = '\"'\nlet y = \"real\"", "<p>") ==
      @["real"]

  test "the lane rule is asserted on the function, not only on the lanes":
    # ``laneRuleViolations`` is a PURE FUNCTION and until this case existed it
    # had no direct assertion at all: the lane cases below only ever feed it
    # the real files, which contain no violation, so every rule inside it read
    # as covered while being dead. Measured by mutation -- deleting the
    # binary-directory rule, deleting the test-stem rule, deleting the
    # source-path rule, dropping ``basenameOf``'s backslash split, and even
    # making the whole proc ``return @[]`` unconditionally ALL left the suite
    # green. Asserting on the function with a handful of literals is cheaper
    # and stronger than hunting for a lane file that happens to exercise it.
    check laneRuleViolations(@[CorpusPath]).len == 0
    check laneRuleViolations(@["nim c -r ", "src/stackable_hooks.nim"]).len == 0
    # rule 1: the build-output directory, wherever it appears in the literal
    check laneRuleViolations(@[TestBinaryDir & "/test_smoke"]).len == 1
    check laneRuleViolations(@["./" & TestBinaryDir & "/x"]).len == 1
    # rule 2: any path under tests/ other than the corpus itself
    check laneRuleViolations(@[TestSourceDir & "/helper.nim"]).len == 1
    check laneRuleViolations(@[TestSourceDir & "/test_smoke.nim"]).len == 1
    # rule 3: a bare stem or basename, with either separator
    check laneRuleViolations(@["test_smoke"]).len == 1
    check laneRuleViolations(@["./tests/test_smoke.nim"]).len == 1
    check laneRuleViolations(@["tests\\test_smoke.nim"]).len == 1
    check laneRuleViolations(@["build\\test-bin\\test_smoke"]).len == 1
    # every offending literal is reported, not just the first
    check laneRuleViolations(@["test_a", "test_b", "ok"]).len == 2
    # basenameOf underpins rule 3 and must split on BOTH separators
    check basenameOf("a/b/c.nim") == "c.nim"
    check basenameOf("a\\b\\c.nim") == "c.nim"
    check basenameOf("a/b\\c.nim") == "c.nim"
    check basenameOf("plain") == "plain"

  test "every test source on disk is registered in the corpus":
    var onDisk: HashSet[string]
    for path in nimFilesUnder(repoRoot / TestSourceDir, recursive = false):
      let stem = basenameOf(path)[0 ..< basenameOf(path).len - 4]
      if path == repoRoot / CorpusPath: continue
      onDisk.incl stem
    var registered: HashSet[string]
    for e in testCorpus:
      registered.incl e.stem
    let unregistered = toSeq(onDisk - registered)
    let ghosts = toSeq(registered - onDisk)
    checkNoViolations("test sources present on disk but in NO lane",
      unregistered)
    checkNoViolations("corpus entries with no source file", ghosts)
    # Anti-vacuity: a coverage check that scanned nothing must not pass.
    check onDisk.len >= 20
    check registered.len == onDisk.len

  test "every library module on disk is registered in the corpus":
    var onDisk: HashSet[string]
    for path in nimFilesUnder(repoRoot / "src", recursive = true):
      onDisk.incl path.relativePath(repoRoot).replace('\\', '/')
    var registered: HashSet[string]
    for m in moduleCorpus:
      registered.incl m.path
    let unregistered = toSeq(onDisk - registered)
    let ghosts = toSeq(registered - onDisk)
    checkNoViolations("library modules compiled by NO lane", unregistered)
    checkNoViolations("module corpus entries with no source file", ghosts)
    check onDisk.len >= 17
    check registered.len == onDisk.len

  test "no corpus entry is duplicated and every target is well-formed":
    var seenStems: HashSet[string]
    var dupes: seq[string]
    for e in testCorpus:
      if e.stem in seenStems: dupes.add e.stem
      seenStems.incl e.stem
      check e.targets.len > 0
      check e.why.len > 0
      # `toHostOs` raises on an --os spelling it does not know, so a typo in
      # a target cannot silently gate a test off every platform.
      discard targetOses(e.targets)
    var seenPaths: HashSet[string]
    for m in moduleCorpus:
      if m.path in seenPaths: dupes.add m.path
      seenPaths.incl m.path
      check m.targets.len > 0
      check m.why.len > 0
      discard targetOses(m.targets)
    checkNoViolations("duplicated corpus entries", dupes)

  test "an unknown --os spelling raises rather than gating silently":
    expect CorpusError:
      discard toHostOs("windwos")
    expect CorpusError:
      discard targetOses(@[CheckTarget(os: "win32", cpu: "amd64")])

  test "the nimble lane names no test path of its own":
    let src = readSourceOrRaise(repoRoot / "stackable_hooks.nimble")
    let literals = nimStringLiterals(src, "stackable_hooks.nimble")
    checkNoViolations("stackable_hooks.nimble", laneRuleViolations(literals))
    check CorpusPath in literals

  test "the reprobuild lane names no test path of its own":
    let src = readSourceOrRaise(repoRoot / "repro.nim")
    let literals = nimStringLiterals(src, "repro.nim")
    checkNoViolations("repro.nim", laneRuleViolations(literals))
    check CorpusPath in literals

  test "every .nim path the Justfile names exists":
    let text = readSourceOrRaise(repoRoot / "Justfile")
    let paths = justfileNimPaths(text)
    var missing: seq[string]
    for p in paths:
      if not fileExists(repoRoot / p):
        missing.add p
    checkNoViolations("Justfile", missing)
    # The Justfile must still be checking SOMETHING, or this rule is inert.
    check paths.len > 0

  test "this host actually selects a corpus":
    let selected = hostTargets()
    check selected.len > 0
    check selected.len <= testCorpus.len
    # Sorted and unique, so both lanes iterate in the same order.
    for i in 1 ..< selected.len:
      check selected[i-1].stem < selected[i].stem
    # Whatever this host omits, it omits for a stated reason.
    for e in testCorpus:
      if not e.runsOnHost:
        checkpoint("not run on " & $hostOs() & ": " & e.stem & " -- " & e.why)
        check hostOs() notin targetOses(e.targets)
