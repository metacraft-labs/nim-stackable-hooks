## Win32 environment-block encoding for `CreateProcessW`'s `lpEnvironment`.
##
## This module is deliberately **not** gated behind `when defined(windows)`.
## The encoding is pure string / UTF-16 work with no Win32 calls, so it can be
## compiled, executed and mutation-checked on a Linux or macOS host — which is
## the only way any part of the Windows spawn path gets *execution* coverage in
## a non-Windows development tree. `stackable_hooks/windows_injector` (which is
## Windows-only) imports it.
##
## The Win32 contract (see `CreateProcessW` / "Environment Variables"):
##
## * the block is a contiguous run of `NAME=VALUE` strings, each terminated by
##   a single NUL, with **one extra NUL** closing the block (the block ends in
##   two consecutive NUL code units);
## * when `CREATE_UNICODE_ENVIRONMENT` is set — and it MUST be set for a block
##   produced here — the code units are UTF-16LE, not bytes;
## * the entries must be **sorted case-insensitively by name**, in ordinal
##   (locale-independent) order.
##
## Getting any of those wrong yields a child with a silently truncated or empty
## environment rather than an error, so every rule above is unit-tested in
## `tests/test_windows_env_block.nim`.

import std/[algorithm, strtabs, strutils, unicode]

type
  WindowsEnvPair* = tuple[name, value: string]

proc appendUtf16*(dest: var seq[uint16]; s: string) =
  ## Append `s`, decoded as UTF-8, to `dest` as UTF-16 code units. Code points
  ## outside the BMP become a surrogate pair. No terminator is appended.
  for r in s.runes:
    let cp = uint32(int32(r))
    if cp < 0x10000'u32:
      dest.add uint16(cp)
    else:
      let v = cp - 0x10000'u32
      dest.add uint16(0xD800'u32 or (v shr 10))
      dest.add uint16(0xDC00'u32 or (v and 0x3FF'u32))

proc windowsEnvSortKey*(name: string): string =
  ## Sort key for one environment variable name.
  ##
  ## Windows sorts the block case-insensitively in *ordinal* order, i.e.
  ## `CompareStringOrdinal(..., bIgnoreCase = TRUE)`, whose case folding is an
  ## upper-casing. We approximate it by upper-casing the ASCII range only:
  ## real environment names are ASCII, and for ASCII the UTF-8 byte order of
  ## the upper-cased name is the same order as the UTF-16 code-unit order
  ## Windows compares in.
  ##
  ## Upper- rather than lower-casing is load-bearing: the six characters
  ## between `Z` (0x5A) and `a` (0x61) — ``[ \ ] ^ _ ` `` — sort on the
  ## opposite side of the letters under the two folds, and `_`-prefixed names
  ## are common.
  name.toUpperAscii()

proc encodeWindowsEnvironmentBlock*(env: openArray[WindowsEnvPair]): seq[uint16]
    {.raises: [ValueError].} =
  ## Encode `env` as a UTF-16 `lpEnvironment` block for `CreateProcessW`
  ## (which must then be called with `CREATE_UNICODE_ENVIRONMENT`).
  ##
  ## Raises `ValueError` rather than emitting a block that would be silently
  ## mis-parsed by the child:
  ##
  ## * an empty name — it would frame as a leading `=VALUE` entry;
  ## * an embedded NUL in a name or value — it would **truncate the block** at
  ##   that point, discarding every later variable;
  ## * an `=` inside a name at any index past 0 — it would re-split the entry
  ##   and rename the variable. Index 0 is allowed, because Windows' own
  ##   per-drive current-directory entries are spelled `=C:=C:\some\dir`;
  ## * two names that are equal case-insensitively — Windows environments are
  ##   case-insensitive, so which one the child sees would be arbitrary.
  ##   Callers layering one environment over another must merge first (that is
  ##   what the `StringTableRef` overload gives you for free).
  for pair in env:
    let (name, value) = pair
    if name.len == 0:
      raise newException(ValueError, "environment variable name is empty")
    if name.find('=', start = 1) >= 0:
      raise newException(ValueError,
        "environment variable name contains '=': " & name)
    if '\0' in name:
      raise newException(ValueError,
        "environment variable name contains NUL: " & name)
    if '\0' in value:
      raise newException(ValueError,
        "value of environment variable " & name & " contains NUL")

  if env.len == 0:
    # An environment block with no variables is just the block terminator.
    # Emitting two NULs keeps the "always ends in two NULs" invariant uniform
    # with the non-empty case; the child's parser stops at the first one.
    return @[0'u16, 0'u16]

  var pairs = @env
  pairs.sort(proc (a, b: WindowsEnvPair): int =
    result = cmp(windowsEnvSortKey(a.name), windowsEnvSortKey(b.name))
    if result == 0:
      result = cmp(a.name, b.name))

  for i in 1 ..< pairs.len:
    if windowsEnvSortKey(pairs[i].name) == windowsEnvSortKey(pairs[i - 1].name):
      raise newException(ValueError,
        "duplicate environment variable name: " & pairs[i].name)

  result = @[]
  for pair in pairs:
    let (name, value) = pair
    result.appendUtf16 name
    result.add uint16(ord('='))
    result.appendUtf16 value
    result.add 0'u16          # terminate this NAME=VALUE entry
  result.add 0'u16            # ... and terminate the block itself

proc encodeWindowsEnvironmentBlock*(env: StringTableRef): seq[uint16]
    {.raises: [ValueError].} =
  ## `StringTableRef` overload, matching `osproc.startProcess`'s `env`
  ## parameter shape. A `nil` table encodes as an empty block; callers that
  ## mean "inherit the parent's environment" must not call this at all and
  ## must pass `lpEnvironment = nil` instead. `lpEnvironmentArgs` below makes
  ## that choice for them.
  var pairs: seq[WindowsEnvPair] = @[]
  if env != nil:
    for name, value in env:
      pairs.add((name, value))
  encodeWindowsEnvironmentBlock(pairs)

const
  CREATE_UNICODE_ENVIRONMENT* = 0x00000400'u32
    ## `CreateProcessW`'s `dwCreationFlags` bit meaning "`lpEnvironment`
    ## points at a UTF-16 block, not an ANSI one". Declared here, alongside
    ## the encoder, rather than only in the Windows-gated
    ## `stackable_hooks/windows_injector`, so that `lpEnvironmentArgs` — the
    ## decision this flag takes part in — can be executed and mutation-checked
    ## on a non-Windows development host.
    ##
    ## Passing a block without this bit does not fail: `CreateProcessW` reads
    ## the same code units as ANSI, so a UTF-16 `A=1` block reads as the
    ## single-character name `A`, and the child comes up with a garbage
    ## environment. The flag and the pointer must therefore always be decided
    ## together, which is exactly what `lpEnvironmentArgs` returns.

proc lpEnvironmentArgs*(env: StringTableRef):
    tuple[extraFlags: uint32; blk: seq[uint16]] {.raises: [ValueError].} =
  ## The two `CreateProcessW` arguments a child environment decides: the
  ## `dwCreationFlags` bits to OR into the caller's, and the block that
  ## `lpEnvironment` must point at. An empty `blk` means "pass
  ## `lpEnvironment = NULL`".
  ##
  ## * `env == nil` ⇒ `(0, @[])` ⇒ `lpEnvironment = NULL` ⇒ the child
  ##   INHERITS the calling process's environment. This is byte-identical to
  ##   what `runWithMonitorShim` did before it took an `env` parameter at all,
  ##   so the default costs existing callers nothing.
  ## * a non-nil but EMPTY table ⇒ the flag AND a real (terminator-only)
  ##   block ⇒ the child gets an EMPTY environment. A deliberate request, and
  ##   an observably different outcome from inheriting.
  ##
  ## The decision is keyed on `env == nil` and never on whether the encoded
  ## block came back empty. Those two keys agree only by accident of
  ## `encodeWindowsEnvironmentBlock` returning `@[0, 0]` rather than `@[]` for
  ## no variables; keying on the block would mean a later "optimisation" of
  ## that one line silently downgraded "give the child an empty environment"
  ## to "let the child inherit ours" — a semantic flip, with no error, on a
  ## path that cannot be executed outside Windows. Keying on the caller's
  ## stated intent is correct regardless of what the encoder returns, and
  ## `tests/test_windows_env_block.nim` pins it.
  if env == nil:
    return (0'u32, newSeq[uint16]())
  var blk = encodeWindowsEnvironmentBlock(env)
  if blk.len == 0:
    # Unreachable with today's encoder, and defensive for the same reason:
    # having decided to pass a block, we must hand `CreateProcessW` at least
    # the block terminator. The call site dereferences `blk[0]`, so an empty
    # seq here would be a fault rather than a wrong answer.
    blk = @[0'u16, 0'u16]
  (CREATE_UNICODE_ENVIRONMENT, blk)
