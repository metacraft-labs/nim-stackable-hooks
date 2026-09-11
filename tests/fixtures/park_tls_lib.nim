## Injection fixture for ``tests/test_windows_entry_park_thread_locals.nim``.
##
## A DLL shaped like every real monitor shim: built ``--app:lib
## --threads:on --mm:orc``, so Nim's generated ``DllMain`` runs this module
## body on ``DLL_PROCESS_ATTACH``, and the module body allocates a
## process-global container out of the ALLOCATING THREAD's ``MemRegion``.
##
## That region is a ``{.threadvar.}`` in the Nim runtime. It lives in the
## thread's TLS block, and the OS releases that block when the thread
## exits. Nim records the owning region in every chunk header and
## dereferences it on a cross-thread free, so a global allocated by a
## thread that later exits is a use-after-free waiting for the first free
## from some other thread -- silent while the released block happens to
## stay committed, an access violation once it does not.
##
## Three exports, and the test needs all three:
##
## * ``park_tls_init_tid`` -- WHICH THREAD ran this module's init. That is
##   the property under test: an injector that borrows the child's parked
##   main thread answers with the main thread, one that spins up a
##   ``CreateRemoteThread`` answers with a thread that no longer exists.
## * ``park_tls_offset`` -- where this thread's copy of a threadvar sits
##   relative to the block the loader recorded for this module in the
##   calling thread's TLS vector. A link-time constant, so every correctly
##   provisioned thread reports the same number.
## * ``park_tls_grow`` -- the allocation pattern that faulted in the field:
##   grow (and therefore free and reallocate) the container the module body
##   allocated, from whatever thread calls in.

import std/tables

when not defined(windows):
  {.error: "park_tls_lib is a Windows fixture".}

# ``__readgsqword`` needs the intrinsics header, and ``_tls_index`` is the
# slot number the LINKER assigns this module in every thread's TLS vector.
# It is emitted by the toolchain, not by Nim, so it has to be declared.
{.emit: """#include <intrin.h>
extern unsigned long _tls_index;
""".}

proc GetCurrentThreadId(): uint32
  {.importc, stdcall, dynlib: "kernel32".}

proc tlsIndexForThisModule(): uint =
  var v: uint
  {.emit: """`v` = (NU)_tls_index;""".}
  v

proc NtCurrentTebAddress(): uint =
  ## The TEB base. ``NtCurrentTeb`` is a header inline, not an export, so
  ## read the well-known ``gs:[0x30]`` self-pointer directly.
  var v: uint
  {.emit: """`v` = (NU)__readgsqword(0x30);""".}
  v

var
  tlsProbe {.threadvar.}: int
    ## One ordinary threadvar. Its identity does not matter; its ADDRESS
    ## relative to this module's TLS block is what gets measured.
  grown: Table[string, bool] = initTable[string, bool]()
    ## Allocated HERE, in the module body, i.e. out of the ``MemRegion`` of
    ## whichever thread mapped this DLL. That is the allocation whose later
    ## free has to cross threads -- or, if the injector did its job, does
    ## not have to.
  initTid: uint32 = GetCurrentThreadId()
    ## Captured in the module body, so this is the loading thread.

proc park_tls_init_tid*(): uint32 {.exportc, cdecl, dynlib.} =
  ## The thread that ran this module's initialisation.
  initTid

proc park_tls_offset*(): uint {.exportc, cdecl, dynlib.} =
  ## Distance from this module's TLS block, as recorded in the CALLING
  ## thread's TLS vector, to this thread's copy of ``tlsProbe``. Returns
  ## ``high(uint)`` when the thread has no TLS vector at all.
  let teb = NtCurrentTebAddress()
  let vector = cast[ptr ptr UncheckedArray[pointer]](teb + 0x58)[]
  if vector == nil:
    return high(uint)
  let slot = vector[][int(tlsIndexForThisModule())]
  cast[uint](addr tlsProbe) - cast[uint](slot)

proc park_tls_grow*(n: cint): cint {.exportc, cdecl, dynlib.} =
  ## Insert ``n`` distinct keys. The table rehashes several times on the
  ## way, and each rehash FREES the previous backing array -- the one the
  ## module body allocated -- from whatever thread calls this.
  for i in 0 ..< int(n):
    grown["park-tls-key-" & $i] = true
  cint(grown.len)
