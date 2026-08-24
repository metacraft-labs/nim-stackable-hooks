## Unit tests for the pure `CreateProcessW` `lpEnvironment` encoder.
##
## `stackable_hooks/windows_env_block` is not Windows-gated precisely so these
## can RUN on any host: the Windows spawn path around it can only ever be
## compile-checked in a Linux/macOS tree, and an environment block that is
## mis-sorted, mis-framed or mis-terminated produces a child with a silently
## truncated or empty environment rather than an error. Every rule the encoder
## claims is asserted here against the literal code-unit sequence.
##
## No mocks: the subject is a pure function over strings.

import std/[strtabs, strutils, unittest]

import stackable_hooks/windows_env_block

template decodeAscii(units: seq[uint16]): string =
  ## Render a block as text with NULs shown as '|', so a framing bug is a
  ## visible diff instead of a length mismatch. ASCII-only by construction —
  ## the UTF-16 cases assert on code units directly.
  var s = ""
  for u in units:
    if u == 0'u16: s.add '|'
    else: s.add chr(int(u) and 0xFF)
  s

template checkEndsWithDoubleNul(units: seq[uint16]) =
  check units.len >= 2
  check units[units.len - 1] == 0'u16
  check units[units.len - 2] == 0'u16

template rejectionMessage(a, b: WindowsEnvPair): string =
  ## The `ValueError` message `encodeWindowsEnvironmentBlock` raises for the
  ## two-entry input `[a, b]`, or `""` if it accepted them. A `template`, not
  ## a `proc`: a `check` inside a plain `proc` prints "Check failed" and still
  ## reports `[OK]`, so no assertion helper here may be a `proc`.
  var msg = ""
  try:
    discard encodeWindowsEnvironmentBlock([a, b])
  except ValueError as e:
    msg = e.msg
  msg

suite "Windows environment-block encoding":
  test "entries are framed NAME=VALUE NUL and the block is NUL-terminated":
    let block1 = encodeWindowsEnvironmentBlock(
      [("ALPHA", "one"), ("BETA", "two")])
    check decodeAscii(block1) == "ALPHA=one|BETA=two||"
    checkEndsWithDoubleNul(block1)

  test "names are sorted case-insensitively, not in input or ordinal order":
    # Input order is deliberately reverse-sorted, and the mixed casing means a
    # plain case-SENSITIVE ordinal sort would put every upper-case name before
    # every lower-case one ("Zeta" < "alpha") — the wrong answer.
    let blk = encodeWindowsEnvironmentBlock(
      [("Zeta", "z"), ("alpha", "a"), ("MIDDLE", "m")])
    check decodeAscii(blk) == "alpha=a|MIDDLE=m|Zeta=z||"

  test "case-insensitive folding is upper-casing, so '_' sorts after letters":
    # '_' is 0x5F: above 'Z' (0x5A) but below 'a' (0x61). Folding to upper case
    # (what CompareStringOrdinal does) puts _UNDER last; folding to lower case
    # would put it first. This is the difference the two folds disagree on.
    let blk = encodeWindowsEnvironmentBlock(
      [("_UNDER", "u"), ("zeta", "z"), ("Alpha", "a")])
    check decodeAscii(blk) == "Alpha=a|zeta=z|_UNDER=u||"

  test "an empty environment is just the block terminator":
    let blk = encodeWindowsEnvironmentBlock(newSeq[WindowsEnvPair]())
    check blk == @[0'u16, 0'u16]
    checkEndsWithDoubleNul(blk)

  test "a value containing '=' is preserved verbatim":
    # Only the FIRST '=' frames the entry; CFLAGS-style values full of '='
    # must survive untouched.
    let blk = encodeWindowsEnvironmentBlock(
      [("OPTS", "-Da=1 -Db=2"), ("EMPTY", "")])
    check decodeAscii(blk) == "EMPTY=|OPTS=-Da=1 -Db=2||"

  test "a leading '=' names a drive-current-directory entry":
    let blk = encodeWindowsEnvironmentBlock(
      [("PATH", "C:\\bin"), ("=C:", "C:\\work")])
    # '=' (0x3D) sorts before any letter, so the drive entry leads the block,
    # which is where Windows puts its own.
    check decodeAscii(blk) == "=C:=C:\\work|PATH=C:\\bin||"

  test "text is encoded as UTF-16, not as bytes":
    # U+00E9 is two UTF-8 bytes but one UTF-16 code unit; U+1F600 is four
    # UTF-8 bytes and a surrogate pair. A byte-per-code-unit encoder (the
    # shape the rest of windows_injector uses for ASCII-only strings) would
    # emit 0xC3,0xA9 and 0xF0,0x9F,0x98,0x80 instead.
    let blk = encodeWindowsEnvironmentBlock([("A", "\u00E9\u{1F600}")])
    check blk == @[
      uint16(ord('A')), uint16(ord('=')),
      0x00E9'u16,                       # é, one BMP code unit
      0xD83D'u16, 0xDE00'u16,           # U+1F600 surrogate pair
      0'u16, 0'u16]
    # And a non-ASCII NAME is encoded the same way, not truncated to a byte.
    let named = encodeWindowsEnvironmentBlock([("\u00C4", "v")])
    check named == @[0x00C4'u16, uint16(ord('=')), uint16(ord('v')),
                     0'u16, 0'u16]

  test "an embedded NUL is rejected instead of truncating the block":
    # This is the failure this validation exists for: the block would end at
    # the stray NUL and every later variable would silently vanish.
    expect ValueError:
      discard encodeWindowsEnvironmentBlock(
        [("A", "va\0lue"), ("B", "keep")])
    expect ValueError:
      discard encodeWindowsEnvironmentBlock([("N\0AME", "v")])

  test "a malformed name is rejected":
    expect ValueError:
      discard encodeWindowsEnvironmentBlock([("", "v")])
    expect ValueError:
      discard encodeWindowsEnvironmentBlock([("HAS=EQ", "v")])

  test "names differing only in case are rejected as duplicates":
    expect ValueError:
      discard encodeWindowsEnvironmentBlock([("Path", "a"), ("PATH", "b")])

  test "the duplicate report does not depend on input order":
    # The sort's secondary `cmp(a.name, b.name)` tie-break exists only for
    # this: names that collide under the case fold compare equal on the
    # primary key, so without a tie-break the (stable) sort would leave them
    # in input order and the diagnostic would name whichever spelling the
    # caller happened to list second. Both orders must report the same one.
    let lowerFirst = rejectionMessage(("Path", "a"), ("PATH", "b"))
    let upperFirst = rejectionMessage(("PATH", "b"), ("Path", "a"))
    check lowerFirst.len > 0
    check lowerFirst == upperFirst
    # Ordinal-greater spelling, deterministically: 'a' (0x61) > 'A' (0x41).
    check lowerFirst.endsWith(" Path")

  test "the StringTableRef overload sorts a table into the same block":
    let t = newStringTable(modeCaseSensitive)
    t["Zeta"] = "z"
    t["alpha"] = "a"
    t["MIDDLE"] = "m"
    check decodeAscii(encodeWindowsEnvironmentBlock(t)) ==
      "alpha=a|MIDDLE=m|Zeta=z||"
    check encodeWindowsEnvironmentBlock(newStringTable(modeCaseSensitive)) ==
      @[0'u16, 0'u16]

  test "a nil StringTableRef encodes as an empty block rather than faulting":
    # `runWithMonitorShim` never calls this with `nil` — it passes
    # `lpEnvironment = nil` instead — but the overload is exported and
    # documents the `nil` case, and `for k, v in (nil StringTableRef)`
    # dereferences a nil ref. Without the module's `if env != nil` guard this
    # is a fault, not a wrong answer.
    let blk = encodeWindowsEnvironmentBlock(StringTableRef(nil))
    check blk == @[0'u16, 0'u16]
    checkEndsWithDoubleNul(blk)

suite "CreateProcessW lpEnvironment decision":
  ## `lpEnvironmentArgs` is the `CreateProcessW` env/flag decision, lifted out
  ## of the Windows-gated `windows_injector` so it can be RUN here. Inside the
  ## injector it is unreachable on this host: `runWithMonitorShim` is behind
  ## `when not defined(windows)` and can only ever be `nim check`ed. These
  ## cases are the whole of the decision; the injector arm now only forwards
  ## the pair to `CreateProcessW`.

  test "nil means inherit: no flag, and no block to point lpEnvironment at":
    # The default. `lpEnvironment = NULL` is what the injector passed before
    # it had an `env` parameter, so this case must add NOTHING — not the
    # creation flag, and not a block.
    let args = lpEnvironmentArgs(nil)
    check args.extraFlags == 0'u32
    check args.blk.len == 0

  test "an empty table is NOT nil: flag set, and a real block is passed":
    # THE case Change 1 exists for. An empty-but-non-nil table means "give the
    # child an EMPTY environment", which is observably different from letting
    # it inherit ours, and the two must not collapse into each other. The
    # block is a terminator-only block — empty of variables, but not empty of
    # code units, because `lpEnvironment` has to point at something.
    let args = lpEnvironmentArgs(newStringTable(modeCaseSensitive))
    check args.extraFlags == CREATE_UNICODE_ENVIRONMENT
    check args.blk.len > 0
    check args.blk == @[0'u16, 0'u16]
    checkEndsWithDoubleNul(args.blk)

  test "a populated table sets the flag and encodes every variable":
    let t = newStringTable(modeCaseSensitive)
    t["Zeta"] = "z"
    t["alpha"] = "a"
    let args = lpEnvironmentArgs(t)
    check args.extraFlags == CREATE_UNICODE_ENVIRONMENT
    check decodeAscii(args.blk) == "alpha=a|Zeta=z||"
    checkEndsWithDoubleNul(args.blk)

  test "the flag is exactly CREATE_UNICODE_ENVIRONMENT, not some other bit":
    # A block passed without this specific bit is re-read as ANSI, which is
    # silent corruption rather than an error, so the constant's VALUE is
    # load-bearing and is pinned against <winbase.h> here.
    check CREATE_UNICODE_ENVIRONMENT == 0x00000400'u32

  test "a rejected environment propagates ValueError, it is not passed on":
    # The encoder's validation must not be bypassed by going through the
    # decision helper: a block that would truncate in the child has to reach
    # the caller as an error, never as a `CreateProcessW` argument.
    let t = newStringTable(modeCaseSensitive)
    t["BAD"] = "va\0lue"
    expect ValueError:
      discard lpEnvironmentArgs(t)
