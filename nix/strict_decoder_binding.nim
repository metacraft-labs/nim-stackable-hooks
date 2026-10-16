## Generated beside this producer's declared include/ and lib/ artifacts.
## Imported only by the Linux AMD64 strict decoder path.
import std/os
const
  strictDecoderPrefix = currentSourcePath().parentDir.parentDir
  strictDecoderHeaders = strictDecoderPrefix / "include"
  strictDecoderArchive = strictDecoderPrefix / "lib" / "libZydis.a"
static:
  doAssert fileExists(strictDecoderArchive), "declared static decoder artifact is missing"
  doAssert fileExists(strictDecoderHeaders / "Zydis" / "Decoder.h"), "declared decoder headers are missing"
  doAssert fileExists(strictDecoderHeaders / "Zycore" / "Defines.h"), "declared Zycore headers are missing"
{.passC: "-I" & quoteShell(strictDecoderHeaders).}
{.passC: "-DZYDIS_STATIC_BUILD".}
{.passC: "-DZYCORE_STATIC_BUILD".}
{.passC: "-DZYAN_NO_LIBC".}
{.passL: quoteShell(strictDecoderArchive).}
