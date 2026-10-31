when not defined(linux):
  {.error: "stackable_hooks/platform/linux_image_code_ranges is Linux-only".}

## Which bytes of an executable mapping are CODE.
##
## The inline raw-syscall scanner (`visitLinuxX8664SyscallMemory` in
## `linux_raw_syscalls`) is a linear sweep with an instruction-length decoder.
## It is instruction-boundary aware only while it is in sync with the
## instruction stream, and the one thing it cannot recover from is being
## pointed at bytes that were never instructions: read-only DATA that the
## linker or a post-link optimiser placed inside the executable `PT_LOAD`.
##
## That layout is ordinary, not exotic:
##
## - LLVM BOLT emits `.eh_frame`, `.gcc_except_table`, `.rodata` and
##   `.eh_frame_hdr` into the same `R E` segment as its new `.text`. The
##   upstream Rust 1.94.0 x86-64 tarball's `librustc_driver` is BOLT-optimised;
##   its `.rodata` holds PIC jump tables whose 32-bit entries can contain the
##   bytes `0f 05` (one is `fa 0f 05 fe`). The sweep reported that entry as a
##   `syscall` and the INT3 patch turned the table entry into `fa cc 05 fe`:
##   the next `switch` jumped mid-instruction and rustc died with SIGILL on
##   any crate with a `macro_rules!` (reprobuild-pm issue
##   2026-10-30-io-mon-shim-kills-upstream-rustc-1.94.0-on-crates-with-macro-rules).
## - GNU ld with `-z noseparate-code` (the default before binutils 2.31, and
##   still a common link flag) puts `.rodata` and `.eh_frame` in the one `R E`
##   segment.
##
## The ELF image itself says which bytes are code: the section headers carry
## `SHF_EXECINSTR` (ELF gABI, "Section Attribute Flags"). Section headers are
## not loaded into memory, so they are read from the image FILE named by the
## mapping, through a bounded set of `pread(2)` calls: the ELF header, the
## program headers and the section headers, never the body. The mapping's
## `/proc/self/maps` inode is compared with `fstat(2)` of the opened path so a
## file replaced since it was mapped is reported, not parsed.
##
## This module is pure geometry: it returns the runtime address ranges of the
## image's executable sections that fall inside one mapping. The consumer
## (io-mon) decides what a non-`licrOk` answer means; its documented bias is
## event loss over a patch that may corrupt the monitored program.

import std/[algorithm, posix, strutils]
import ./linux_raw_syscalls

type
  LinuxImageCodeRangeDiagnostic* = enum
    licrOk = "ok"
    licrNotFileBacked = "not-file-backed"   ## Anonymous or kernel mapping.
    licrOpenFailed = "open-failed"           ## `open(2)` of the path failed.
    licrIdentityMismatch = "identity-mismatch"
      ## The path names a file other than the mapped one (inode differs).
    licrNotElf64 = "not-elf64"               ## Not a little-endian ELF64 file.
    licrNoSectionHeaders = "no-section-headers"
      ## The image carries no section header table (stripped by `sstrip`
      ## or `objcopy --strip-section-headers`), so its code bytes are unknown.
    licrSegmentNotFound = "segment-not-found"
      ## No executable `PT_LOAD` covers the mapping's file offset.
    licrMalformed = "malformed"              ## Header fields out of range or unreadable.

  LinuxAddressRange* = object
    start*: uint
    stop*: uint   ## Exclusive.

  LinuxImageCodeRanges* = object
    diagnostic*: LinuxImageCodeRangeDiagnostic
    osErrno*: cint
      ## `errno` of the failed `open`/`fstat`/`pread`, 0 otherwise.
    ranges*: seq[LinuxAddressRange]
      ## Runtime address ranges of the `SHF_EXECINSTR` sections inside the
      ## mapping, clipped to `[mapping.start, mapping.stop)`, sorted by start,
      ## with overlapping and adjacent ranges merged. Empty with `licrOk` when
      ## the mapping holds no executable section at all.

  LinuxImageReader* = proc(offset: uint64; dest: pointer; len: int): bool
    {.closure, raises: [].}
    ## Reads exactly `len` bytes at `offset` of the image file into `dest`;
    ## `false` on a short read or an error.

const
  elfMagic = ['\x7f', 'E', 'L', 'F']
  elfClass64 = 2'u8
  elfDataLsb = 1'u8
  elf64EhdrSize = 64
  elf64PhdrSize = 56
  elf64ShdrSize = 64
  ptLoad = 1'u32
  pfX = 1'u32
  shtNobits = 8'u32
  shfAlloc = 0x2'u64
  shfExecinstr = 0x4'u64
  maxHeaderCount = 4096
    ## `e_phnum`/`e_shnum` are 16-bit, so a header table can be announced as
    ## 65535 entries. Linked images carry tens of sections, not thousands; the
    ## cap keeps the two table reads (and their transient buffers, allocated
    ## inside the shim on every scan) at 256 KiB at most. An image above it is
    ## reported `licrMalformed`, which the consumer treats as loss.
  defaultPageSize* = 4096'u64
    ## The page size `linuxImageCodeRangesFromReader` assumes when the caller
    ## gives none: the only one x86-64 and 32-bit ARM Linux have, which are
    ## the architectures whose code the raw-syscall scanner decodes.

proc readU16(b: openArray[byte]; at: int): uint16 {.inline.} =
  uint16(b[at]) or (uint16(b[at + 1]) shl 8)

proc readU32(b: openArray[byte]; at: int): uint32 {.inline.} =
  var v = 0'u32
  for i in 0 ..< 4: v = v or (uint32(b[at + i]) shl (8 * i))
  v

proc readU64(b: openArray[byte]; at: int): uint64 {.inline.} =
  var v = 0'u64
  for i in 0 ..< 8: v = v or (uint64(b[at + i]) shl (8 * i))
  v

proc fail(diag: LinuxImageCodeRangeDiagnostic; errno: cint = 0): LinuxImageCodeRanges =
  LinuxImageCodeRanges(diagnostic: diag, osErrno: errno)

proc mergeRanges(ranges: var seq[LinuxAddressRange]) =
  ## Sort by start and coalesce overlapping or touching ranges, so the scanner
  ## restarts its decoder once per contiguous code run.
  if ranges.len <= 1:
    return
  ranges.sort(proc(a, b: LinuxAddressRange): int = cmp(a.start, b.start))
  var merged: seq[LinuxAddressRange] = @[ranges[0]]
  for i in 1 ..< ranges.len:
    let r = ranges[i]
    if r.start <= merged[^1].stop:
      merged[^1].stop = max(merged[^1].stop, r.stop)
    else:
      merged.add r
  ranges = merged

proc linuxImageCodeRangesFromReader*(mapping: LinuxExecutableMapping;
                                     fileInode: uint64;
                                     read: LinuxImageReader;
                                     pageSize = defaultPageSize): LinuxImageCodeRanges
    {.raises: [].} =
  ## The pure algorithm: given the mapping, the inode of the file the caller
  ## opened and a bounded reader over that file, compute the executable-section
  ## ranges of the image inside the mapping. Exposed so tests can drive it over
  ## hand-built ELF bytes.
  ##
  ## `pageSize` is the running kernel's page size (a power of two): the kernel
  ## maps a `PT_LOAD` from its file offset rounded DOWN to a page, so the
  ## mapping's `offset` column is tied back to its segment through that same
  ## rounding. With a page larger than the segment alignment (16 KiB or 64 KiB
  ## AArch64 kernels) a 4 KiB rounding would miss the segment and report
  ## `licrSegmentNotFound`; it can never pick a wrong segment, because every
  ## segment of one image shares the load base the bias computes.
  if mapping.path.len == 0 or mapping.path[0] != '/':
    return fail(licrNotFileBacked)
  if mapping.stop <= mapping.start or read == nil:
    return fail(licrMalformed)
  if pageSize < defaultPageSize or (pageSize and (pageSize - 1)) != 0:
    return fail(licrMalformed)
  let pageMask = pageSize - 1
  if mapping.inode != 0 and fileInode != mapping.inode:
    return fail(licrIdentityMismatch)

  var ehdr: array[elf64EhdrSize, byte]
  if not read(0, addr ehdr[0], ehdr.len):
    return fail(licrMalformed)
  for i in 0 ..< elfMagic.len:
    if ehdr[i] != byte(elfMagic[i]):
      return fail(licrNotElf64)
  if ehdr[4] != elfClass64 or ehdr[5] != elfDataLsb:
    return fail(licrNotElf64)
  let phoff = readU64(ehdr, 0x20)
  let shoff = readU64(ehdr, 0x28)
  let phentsize = int(readU16(ehdr, 0x36))
  let phnum = int(readU16(ehdr, 0x38))
  let shentsize = int(readU16(ehdr, 0x3a))
  let shnum = int(readU16(ehdr, 0x3c))
  if shoff == 0 or shnum == 0:
    # `e_shnum == 0` with a non-zero `e_shoff` is the gABI's extended
    # numbering (the real count is in `sh[0].sh_size`); linked images do not
    # use it, so it is reported as "no table" rather than half-supported.
    return fail(licrNoSectionHeaders)
  # Every ELF64 linker emits the gABI's fixed entry sizes; an image announcing
  # another size, or more headers than the cap, is not one this reader claims
  # to understand.
  if phoff == 0 or phnum == 0 or phentsize != elf64PhdrSize or
      shentsize != elf64ShdrSize or phnum > maxHeaderCount or
      shnum > maxHeaderCount:
    return fail(licrMalformed)

  # Program headers: the executable PT_LOAD whose file span (page-rounded, as
  # the kernel maps it) holds the mapping's file offset gives the load bias.
  var phdrs = newSeq[byte](phnum * phentsize)
  if not read(phoff, addr phdrs[0], phdrs.len):
    return fail(licrMalformed)
  var biasFound = false
  var bias = 0'u64
  let mappingOffset = uint64(mapping.offset)
  for i in 0 ..< phnum:
    let at = i * phentsize
    if readU32(phdrs, at) != ptLoad or (readU32(phdrs, at + 4) and pfX) == 0:
      continue
    let pOffset = readU64(phdrs, at + 8)
    let pVaddr = readU64(phdrs, at + 16)
    let pFilesz = readU64(phdrs, at + 32)
    # A segment whose page-rounded file span would wrap past 2^64 is refused
    # before the span is computed, so the containment test below never sees
    # wrapped arithmetic. No loader maps such a segment; the image is malformed.
    if pOffset > high(uint64) - pageMask or
        pFilesz > high(uint64) - pageMask - pOffset:
      return fail(licrMalformed)
    let spanStart = pOffset and not pageMask
    let spanStop = (pOffset + pFilesz + pageMask) and not pageMask
    if mappingOffset >= spanStart and mappingOffset < spanStop:
      # Runtime address of file offset `o` within this segment is
      # `mapping.start + (o - mapping.offset)`, and its link-time address is
      # `p_vaddr + (o - p_offset)`; the bias is their difference.
      bias = uint64(mapping.start) - mappingOffset + pOffset - pVaddr
      biasFound = true
      break
  if not biasFound:
    return fail(licrSegmentNotFound)

  # Section headers: every allocated, executable, file-backed section that
  # intersects the mapping is code the scanner may decode from its start.
  var shdrs = newSeq[byte](shnum * shentsize)
  if not read(shoff, addr shdrs[0], shdrs.len):
    return fail(licrMalformed)
  result.diagnostic = licrOk
  for i in 0 ..< shnum:
    let at = i * shentsize
    let shType = readU32(shdrs, at + 4)
    let shFlags = readU64(shdrs, at + 8)
    let shAddr = readU64(shdrs, at + 16)
    let shSize = readU64(shdrs, at + 32)
    if shType == shtNobits or shSize == 0:
      continue
    if (shFlags and shfAlloc) == 0 or (shFlags and shfExecinstr) == 0:
      continue
    let rStart = shAddr + bias
    let rStop = rStart + shSize
    if rStop < rStart:  # overflow
      continue
    let start = max(rStart, uint64(mapping.start))
    let stop = min(rStop, uint64(mapping.stop))
    if start < stop:
      result.ranges.add LinuxAddressRange(start: uint(start), stop: uint(stop))
  mergeRanges(result.ranges)

proc linuxImageCodeRanges*(mapping: LinuxExecutableMapping): LinuxImageCodeRanges
    {.raises: [].} =
  ## Resolve the executable-section ranges of the image behind a file-backed
  ## mapping by reading its ELF headers from `mapping.path`. Only the headers
  ## are read (three bounded `pread`s); the descriptor is closed before
  ## returning. Runs in ordinary (not signal) context: the shim calls it from
  ## its constructor and its `dlopen` hooks, where it already reads
  ## `/proc/self/maps`. The kernel's page size comes from `sysconf(2)`.
  if mapping.path.len == 0 or mapping.path[0] != '/':
    return fail(licrNotFileBacked)
  let fd = posix.open(cstring(mapping.path), O_RDONLY or O_CLOEXEC)
  if fd < 0:
    return fail(licrOpenFailed, errno)
  defer: discard posix.close(fd)
  var st: Stat
  if fstat(fd, st) != 0:
    return fail(licrOpenFailed, errno)
  var readErrno: cint = 0
  let reader: LinuxImageReader = proc(offset: uint64; dest: pointer; len: int): bool
      {.closure, raises: [].} =
    var done = 0
    while done < len:
      let n = pread(fd, cast[pointer](cast[uint](dest) + uint(done)),
                    len - done, Off(offset + uint64(done)))
      if n <= 0:
        if n < 0: readErrno = errno
        return false
      done += int(n)
    true
  let page = sysconf(SC_PAGESIZE)
  let pageSize = if page > 0: uint64(page) else: defaultPageSize
  result = linuxImageCodeRangesFromReader(mapping, uint64(st.st_ino), reader,
                                          pageSize)
  if result.diagnostic == licrMalformed and readErrno != 0:
    result.osErrno = readErrno
