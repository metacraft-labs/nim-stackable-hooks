# Windows transaction header overstates rollback guarantees

Status: open documentation/implementation mismatch. Observed by source
inspection at dev `8f4d806` and candidate `d36cab8`.

## Observed

`ct_inline_hook_commit_transaction` documents in
`src/stackable_hooks/inline_hook/windows/install_windows.h` that a failed
commit rolls back the queue and leaves no targets modified. Its implementation
explicitly permits partial application in the M50.2 scope: completed installs
are uninstalled, but completed uninstalls are not reinstalled. The rollback
loop also ignores errors returned by `uninstall_locked`.

This predates the page-preparation candidate. No runtime reproduction was
performed for this record, and it does not explain the compiler-startup stall.

## Expected

The public header's commit contract promises full rollback. The implementation
comment deliberately documents a narrower guarantee. No separate specification
found in the repository settles that conflict. Proposed: reconcile the public
contract and implementation, then cover a failed commit after a completed
uninstall with a real Windows transaction test. Do not describe the existing
rollback as fully atomic before that decision and validation.

## Evidence

Fetched dev `8f4d806` and agents `23c3384`. Searched current issues, docs
and complete issue history for rollback, transaction and partial application;
the compiler-startup issue requires preserving the existing rollback behavior
but does not own this pre-existing guarantee mismatch. The relevant symbols
are `ct_inline_hook_commit_transaction` and `uninstall_locked`.
