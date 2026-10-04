# Windows patch writes restore only the first page's protection

Status: open. Observed by source inspection at nim-stackable-hooks
`7a325bc6cfe02de09939596b213cec1cc2fdf4f2`; no native failure is claimed.

## Observed

`src/stackable_hooks/inline_hook/windows/install_windows.c`, `write_patch`,
changes the whole patch span to writable, saves one `old_prot`, and restores
that value across the whole span. A patch crossing pages with different
original protections therefore gives the second page the first page's
protection. The restoration and instruction-cache-flush results are also
ignored before returning success.

The preparation helper already splits at VirtualQuery region boundaries, but
the later actual write still uses the single-value restoration. This is separate
from the prepared-page startup stall and from Gosti's measured hook latency.

## Expected

The [existing preparation requirements](2026-09-30-windows-arm-compiler-startup-stalls-in-hook-transaction.md)
preserve original protection transitions and each region's own protection.
The same ownership requirement applies after the actual patch write.
[VirtualProtect's contract](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
says that the old-protection output describes the first page only, while every
page intersecting the requested range is changed.

Keep distinct original protections and restore them individually. Define safe
failure handling after bytes have changed: returning an ordinary pre-write
failure could let the caller release a trampoline still referenced by the
patched entry. Preserve suspension, rollback and cache flushing. Qualify with
real executable pages having different protections, a boundary-crossing patch,
working target/trampoline calls and exact post-operation protection checks.

## Search

Refreshed `agents` and `dev`, searched open issues and deleted issue history for
cross-page and first-page restoration. The existing startup-stall record covers
preparation but does not record this later write-path defect. Found while
reviewing possible Windows hook-cost repairs; no performance cause is inferred.
