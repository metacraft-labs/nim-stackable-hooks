## test_linux_image_code_ranges — which bytes of an executable mapping are code.
##
## `linux_image_code_ranges` answers from the image's ELF section table, so
## that the inline raw-syscall scanner never decodes read-only data that a
## linker or BOLT placed inside the executable `PT_LOAD` (the rustc 1.94.0
## `.rodata` jump-table entry `fa 0f 05 fe` that the INT3 patch corrupted).
##
## Three layers, no mocks:
##   (a) hand-built ELF64 bytes in a temp file drive the pure algorithm
##       through every diagnostic and the bias/clipping arithmetic;
##   (b) this test's own executable mapping, read from /proc/self/maps;
##   (c) a real shared library linked with `-z noseparate-code`, the layout
##       that puts `.rodata` into the `R E` segment: its data table must be
##       outside every code range while its function is inside one.

when not defined(linux):
  {.error: "test_linux_image_code_ranges is Linux-only".}

import std/[dynlib, os, osproc, posix, strutils, unittest]

import stackable_hooks/platform/linux_raw_syscalls
import stackable_hooks/platform/linux_image_code_ranges

proc put16(b: var seq[byte]; at: int; v: uint16) =
  b[at] = byte(v and 0xff); b[at + 1] = byte(v shr 8)
proc put32(b: var seq[byte]; at: int; v: uint32) =
  for i in 0 ..< 4: b[at + i] = byte((v shr (8 * i)) and 0xff)
proc put64(b: var seq[byte]; at: int; v: uint64) =
  for i in 0 ..< 8: b[at + i] = byte((v shr (8 * i)) and 0xff)

const
  ehdrSize = 64
  phdrSize = 56
  shdrSize = 64
  ptLoad = 1'u32
  pfR = 4'u32
  pfW = 2'u32
  pfX = 1'u32
  shtProgbits = 1'u32
  shtNobits = 8'u32
  shfWrite = 1'u64
  shfAlloc = 2'u64
  shfExec = 4'u64

type SyntheticSection = object
  stype: uint32
  flags: uint64
  address: uint64
  offset: uint64
  size: uint64

proc writePhdr(b: var seq[byte]; at: int; flags: uint32;
               offset, vaddr, filesz, memsz: uint64) =
  put32(b, at, ptLoad); put32(b, at + 4, flags)
  put64(b, at + 8, offset); put64(b, at + 16, vaddr); put64(b, at + 24, vaddr)
  put64(b, at + 32, filesz); put64(b, at + 40, memsz); put64(b, at + 48, 0x1000)

proc writeShdr(b: var seq[byte]; at: int; s: SyntheticSection) =
  put32(b, at + 4, s.stype); put64(b, at + 8, s.flags); put64(b, at + 16, s.address)
  put64(b, at + 24, s.offset); put64(b, at + 32, s.size); put64(b, at + 48, 1)

proc syntheticElf(withSectionHeaders = true): seq[byte] =
  ## Two PT_LOADs. The executable one maps file [0x1000, 0x3000) at vaddr
  ## 0x401000 (delta vaddr-offset = 0x400000) and holds .text (AX) at
  ## 0x401100..0x401500 spanning into the second page, .rodata (A) at
  ## 0x401600 and a NOBITS AX .text.bss at 0x402800. The RW one maps file
  ## [0x3000, 0x4000) at vaddr 0x404000 holding .data (WA).
  result = newSeq[byte](0x4000)
  result[0] = 0x7f; result[1] = byte('E'); result[2] = byte('L'); result[3] = byte('F')
  result[4] = 2; result[5] = 1; result[6] = 1
  put16(result, 0x10, 3)         # ET_DYN
  put16(result, 0x12, 62)        # EM_X86_64
  put32(result, 0x14, 1)
  put64(result, 0x20, 0x40)      # e_phoff
  put16(result, 0x34, uint16(ehdrSize))
  put16(result, 0x36, uint16(phdrSize)); put16(result, 0x38, 2)
  writePhdr(result, 0x40, pfR or pfX, 0x1000, 0x401000, 0x2000, 0x2000)
  writePhdr(result, 0x40 + phdrSize, pfR or pfW, 0x3000, 0x404000, 0x1000, 0x1000)
  if withSectionHeaders:
    let shoff = 0x3800'u64
    let sections = [
      SyntheticSection(),  # null
      SyntheticSection(stype: shtProgbits, flags: shfAlloc or shfExec,
        address: 0x401100, offset: 0x1100, size: 0x400),
      SyntheticSection(stype: shtProgbits, flags: shfAlloc,
        address: 0x401600, offset: 0x1600, size: 0x100),
      SyntheticSection(stype: shtNobits, flags: shfAlloc or shfExec,
        address: 0x402800, offset: 0x2800, size: 0x100),
      SyntheticSection(stype: shtProgbits, flags: shfAlloc or shfWrite,
        address: 0x404000, offset: 0x3000, size: 0x100)]
    put64(result, 0x28, shoff)
    put16(result, 0x3a, uint16(shdrSize)); put16(result, 0x3c, uint16(sections.len))
    for i, s in sections:
      writeShdr(result, int(shoff) + i * shdrSize, s)

proc writeTemp(dir, name: string; bytes: seq[byte]): string =
  result = dir / name
  writeFile(result, cast[string](bytes))

proc inodeOf(path: string): uint64 =
  var st: Stat
  doAssert stat(cstring(path), st) == 0
  uint64(st.st_ino)

proc fileMapping(path: string; start, stop, offset: uint): LinuxExecutableMapping =
  LinuxExecutableMapping(start: start, stop: stop, readable: true,
    executable: true, privateMapping: true, path: path, offset: offset,
    inode: inodeOf(path))

proc containsAddress(ranges: seq[LinuxAddressRange]; a: uint): bool =
  for r in ranges:
    if a >= r.start and a < r.stop: return true
  false

proc mappingHolding(a: uint): LinuxExecutableMapping =
  ## The /proc/self/maps entry that holds address `a`.
  for line in lines("/proc/self/maps"):
    let parsed = parseLinuxMapsLine(line)
    if parsed.ok and a >= parsed.mapping.start and a < parsed.mapping.stop:
      return parsed.mapping
  LinuxExecutableMapping()

proc liveProbe(): int = 7  # a function whose address must be in a code range

proc readerOver(bytes: seq[byte]): LinuxImageReader =
  ## A bounded reader over in-memory image bytes for the pure algorithm.
  let image = bytes
  result = proc(offset: uint64; dest: pointer; len: int): bool =
    if offset > uint64(image.len) or int(offset) + len > image.len: return false
    copyMem(dest, unsafeAddr image[int(offset)], len)
    true

proc syntheticMapping(start, stop, offset: uint): LinuxExecutableMapping =
  LinuxExecutableMapping(start: start, stop: stop, readable: true,
    executable: true, privateMapping: true, path: "/synthetic", offset: offset,
    inode: 42)

suite "linux image code ranges":
  let work = getTempDir() / ("stackable-image-code-ranges-" & $getCurrentProcessId())
  createDir(work)
  defer: removeDir(work)

  test "synthetic image: only the executable file-backed section is code, with the load bias applied":
    let path = writeTemp(work, "synthetic.so", syntheticElf())
    # Mapping of the whole exec segment, loaded at 0x7f00_0000_1000.
    let m = fileMapping(path, 0x7f0000001000'u, 0x7f0000003000'u, 0x1000)
    let r = linuxImageCodeRanges(m)
    check r.diagnostic == licrOk
    check r.osErrno == 0
    # .text 0x401100..0x401500 → bias = start - offset + p_offset - p_vaddr
    #   = 0x7f0000001000 - 0x1000 + 0x1000 - 0x401000
    check r.ranges == @[LinuxAddressRange(start: 0x7f0000001100'u,
                                          stop: 0x7f0000001500'u)]
    # .rodata (not executable) and the NOBITS section are not code.
    check not containsAddress(r.ranges, 0x7f0000001600'u)
    check not containsAddress(r.ranges, 0x7f0000002800'u)

  test "synthetic image: a mapping of the segment's second page clips the range":
    let path = writeTemp(work, "synthetic2.so", syntheticElf())
    # Kernel split the segment: this mapping is file [0x2000, 0x3000) only,
    # so .text's tail 0x401400..0x401500 (file 0x1400..0x1500) is NOT inside.
    let m = fileMapping(path, 0x7f0000002000'u, 0x7f0000003000'u, 0x2000)
    let r = linuxImageCodeRanges(m)
    check r.diagnostic == licrOk
    check r.ranges.len == 0
    # And a mapping that starts mid-way through .text clips its start.
    let m2 = fileMapping(path, 0x7f0000001300'u, 0x7f0000003000'u, 0x1300)
    let r2 = linuxImageCodeRanges(m2)
    check r2.diagnostic == licrOk
    check r2.ranges == @[LinuxAddressRange(start: 0x7f0000001300'u,
                                           stop: 0x7f0000001500'u)]

  test "synthetic image: each refusal has its own diagnostic":
    let good = writeTemp(work, "good.so", syntheticElf())
    var m = fileMapping(good, 0x1000'u, 0x3000'u, 0x1000)
    # Not file-backed.
    var anon = m; anon.path = ""
    check linuxImageCodeRanges(anon).diagnostic == licrNotFileBacked
    var pseudo = m; pseudo.path = "[vdso]"
    check linuxImageCodeRanges(pseudo).diagnostic == licrNotFileBacked
    # Nonexistent path.
    var missing = m; missing.path = work / "does-not-exist.so"
    let gone = linuxImageCodeRanges(missing)
    check gone.diagnostic == licrOpenFailed
    check gone.osErrno == ENOENT
    # Inode mismatch: the path now names another file than the mapped one.
    var replaced = m; replaced.inode = m.inode + 1
    check linuxImageCodeRanges(replaced).diagnostic == licrIdentityMismatch
    # Inode 0 (unknown) skips the identity check rather than failing it.
    var unknownInode = m; unknownInode.inode = 0
    check linuxImageCodeRanges(unknownInode).diagnostic == licrOk
    # Not an ELF64 file.
    let text = writeTemp(work, "text.so",
      cast[seq[byte]]("not an elf image at all\n".repeat(8)))  # longer than an ELF header
    check linuxImageCodeRanges(fileMapping(text, 0x1000'u, 0x3000'u, 0x1000)).diagnostic ==
      licrNotElf64
    var elf32 = syntheticElf(); elf32[4] = 1
    let elf32Path = writeTemp(work, "elf32.so", elf32)
    check linuxImageCodeRanges(fileMapping(elf32Path, 0x1000'u, 0x3000'u, 0x1000)).diagnostic ==
      licrNotElf64
    # No section header table (e_shoff = 0, e_shnum = 0).
    let stripped = writeTemp(work, "stripped.so", syntheticElf(withSectionHeaders = false))
    check linuxImageCodeRanges(fileMapping(stripped, 0x1000'u, 0x3000'u, 0x1000)).diagnostic ==
      licrNoSectionHeaders
    # Mapping offset outside every executable PT_LOAD (the RW segment's span).
    check linuxImageCodeRanges(fileMapping(good, 0x1000'u, 0x2000'u, 0x3000)).diagnostic ==
      licrSegmentNotFound
    # Truncated file: headers unreadable.
    let truncated = writeTemp(work, "truncated.so", syntheticElf()[0 ..< 0x100])
    check linuxImageCodeRanges(fileMapping(truncated, 0x1000'u, 0x3000'u, 0x1000)).diagnostic ==
      licrMalformed
    # Inverted mapping.
    var inverted = m; inverted.stop = inverted.start
    check linuxImageCodeRanges(inverted).diagnostic == licrMalformed

  test "pure algorithm: adjacent executable sections merge into one range":
    var elf = syntheticElf()
    # Turn .rodata into a second AX section directly after .text.
    let shoff = 0x3800
    put64(elf, shoff + 2 * shdrSize + 8, shfAlloc or shfExec)
    put64(elf, shoff + 2 * shdrSize + 16, 0x401500)
    put64(elf, shoff + 2 * shdrSize + 24, 0x1500)
    let m = syntheticMapping(0x1000'u, 0x3000'u, 0x1000)
    let r = linuxImageCodeRangesFromReader(m, 42, readerOver(elf))
    check r.diagnostic == licrOk
    check r.ranges == @[LinuxAddressRange(start: 0x1100'u, stop: 0x1600'u)]

  test "pure algorithm: the kernel's page size ties the mapping to its segment":
    # A 16 KiB-page kernel maps the executable segment (file 0x1000..0x3000)
    # from file offset 0, so the maps line says offset 0. With the 4 KiB default
    # that offset lies outside every segment's span; with the real page size the
    # segment is found and the bias is unchanged (0x7f0000000000 - 0 + 0x1000 -
    # 0x401000), so .text still lands at 0x7f0000001100.
    let reader = readerOver(syntheticElf())
    let m = syntheticMapping(0x7f0000000000'u, 0x7f0000004000'u, 0)
    check linuxImageCodeRangesFromReader(m, 42, reader).diagnostic == licrSegmentNotFound
    let r = linuxImageCodeRangesFromReader(m, 42, reader, pageSize = 0x4000)
    check r.diagnostic == licrOk
    check r.ranges == @[LinuxAddressRange(start: 0x7f0000001100'u,
                                          stop: 0x7f0000001500'u)]
    # A page size that is not a power of two, or below 4 KiB, is refused.
    check linuxImageCodeRangesFromReader(m, 42, reader, pageSize = 0x3000).diagnostic ==
      licrMalformed
    check linuxImageCodeRangesFromReader(m, 42, reader, pageSize = 0x800).diagnostic ==
      licrMalformed

  test "pure algorithm: header tables outside the gABI sizes or above the cap are malformed":
    let m = syntheticMapping(0x1000'u, 0x3000'u, 0x1000)
    check linuxImageCodeRangesFromReader(m, 42, readerOver(syntheticElf())).diagnostic ==
      licrOk
    var manySections = syntheticElf()
    put16(manySections, 0x3c, 4097)         # e_shnum above the cap
    check linuxImageCodeRangesFromReader(m, 42, readerOver(manySections)).diagnostic ==
      licrMalformed
    var oddShentsize = syntheticElf()
    put16(oddShentsize, 0x3a, 72)           # e_shentsize != 64
    check linuxImageCodeRangesFromReader(m, 42, readerOver(oddShentsize)).diagnostic ==
      licrMalformed
    var oddPhentsize = syntheticElf()
    put16(oddPhentsize, 0x36, 64)           # e_phentsize != 56
    check linuxImageCodeRangesFromReader(m, 42, readerOver(oddPhentsize)).diagnostic ==
      licrMalformed
    # An executable PT_LOAD whose page-rounded file span would wrap past 2^64
    # (p_offset 0, p_filesz just under 2^64) is refused before any bias is
    # derived from it, even for a mapping at file offset 0 that the wrapped
    # span might otherwise be taken to contain.
    var wrappingSegment = syntheticElf()
    put64(wrappingSegment, 0x40 + 8, 0)                        # p_offset
    put64(wrappingSegment, 0x40 + 32, high(uint64) - 0x100)    # p_filesz
    let m0 = syntheticMapping(0x7f0000000000'u, 0x7f0000004000'u, 0)
    check linuxImageCodeRangesFromReader(m0, 42, readerOver(wrappingSegment)).diagnostic ==
      licrMalformed

  test "live: this executable's own code mapping holds the test's functions":
    let probeAddr = cast[uint](liveProbe)
    let m = mappingHolding(probeAddr)
    require m.path.len > 0 and m.executable
    let r = linuxImageCodeRanges(m)
    checkpoint("mapping " & m.path & " diagnostic=" & $r.diagnostic &
      " ranges=" & $r.ranges.len)
    check r.diagnostic == licrOk
    check r.ranges.len > 0
    for range in r.ranges:
      check range.start >= m.start and range.stop <= m.stop and range.start < range.stop
    check containsAddress(r.ranges, probeAddr)

  test "live: data linked into the executable segment is not code":
    when defined(amd64) or defined(arm64):
      let src = work / "nosep.c"
      writeFile(src, """
__attribute__((used)) const unsigned char table[16] =
  {0xfa,0x0f,0x05,0xfe,1,2,3,4,5,6,7,8,9,10,11,12};
int nosep_function(int x) { return x + 1; }
""")
      let lib = work / "libnosep.so"
      let cc = getEnv("CC", "cc")
      let (ccOut, ccCode) = execCmdEx(quoteShellCommand(@[cc, "-shared", "-fPIC",
        "-Wl,-z,noseparate-code", "-o", lib, src]))
      checkpoint("cc: " & ccOut)
      require ccCode == 0
      let handle = loadLib(lib)
      require handle != nil
      let tableAddr = cast[uint](handle.symAddr("table"))
      let fnAddr = cast[uint](handle.symAddr("nosep_function"))
      require tableAddr != 0 and fnAddr != 0
      let m = mappingHolding(tableAddr)
      checkpoint("table mapping: " & $m.start.toHex & "-" & $m.stop.toHex &
        " x=" & $m.executable & " path=" & m.path)
      # Fixture precondition: the linker really put the table in the R E
      # segment. Without this the test would pass without testing anything.
      if not (m.executable and m.path == lib):
        checkpoint("fixture precondition failed: -z noseparate-code did not " &
          "place the data table in the executable mapping of " & lib)
      require m.executable and m.path == lib
      let r = linuxImageCodeRanges(m)
      check r.diagnostic == licrOk
      check r.ranges.len > 0
      check not containsAddress(r.ranges, tableAddr)
      check containsAddress(r.ranges, fnAddr)
    else:
      skip()
