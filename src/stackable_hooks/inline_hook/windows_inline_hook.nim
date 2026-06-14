## Nim wrapper over the Windows inline-hook C primitive.
##
## The C sources under `windows/` implement a Detours-style 5-byte
## `JMP rel32` installer with prologue length decoding, RIP-relative
## fixup for the trampoline, and a thread-suspension transaction that
## mirrors Detours' `DetourTransactionCommitEx` and minhook's
## `Freeze`/`Unfreeze` pattern.
##
## Spec citations live in the C files themselves:
##   - install_windows.c §"Thread safety" + §"Hot-patch support" + §"Trampoline"
##   - length_decoder.c  M50.0 prologue length decoding
##   - rel32_fixup.c     M50.1 rel32 / RIP-rel fixup
##
## Consumers call `inlineHookInstall(target, hook, outTrampoline)` to
## install a detour, save the returned `outTrampoline` so they can
## call through to the original function, and pair every install with
## a `inlineHookUninstall(target)` at teardown. The transaction API
## (`inlineHookBeginTransaction` / `inlineHookCommitTransaction` /
## `inlineHookAbortTransaction`) batches multiple installs under a
## single thread-suspend / cache-flush pair.

when not defined(windows):
  {.error: "stackable_hooks/inline_hook/windows_inline_hook is Windows-only".}

{.push raises: [].}

# Compile the C sources alongside the Nim module. `currentSourcePath`
# resolves to this file so relative paths land in the `windows/`
# sibling directory regardless of where the consumer's `nimcache`
# lives.
import std/os
const inlineDir = currentSourcePath().parentDir / "windows"

{.passC: "-I" & inlineDir & " -D_CRT_SECURE_NO_WARNINGS".}
{.compile: inlineDir / "length_decoder.c".}
{.compile: inlineDir / "rel32_fixup.c".}
{.compile: inlineDir / "install_windows.c".}

proc inlineHookInstall*(target: pointer; hook: pointer;
                        outTrampoline: ptr pointer): cint
  {.importc: "ct_inline_hook_install", cdecl.}
  ## Install a 5-byte JMP rel32 at `target` redirecting to `hook`.
  ## `*outTrampoline` receives a pointer to a heap-allocated stub that
  ## executes the displaced prologue bytes and then jumps to
  ## `target + N`, so the hook body can call through to the original
  ## function by casting `*outTrampoline` to the function's signature.
  ## Returns 0 on success, negative error code on failure (see
  ## install_windows.h for the taxonomy).

proc inlineHookInstallNoReturn*(target: pointer; hook: pointer;
                                outTrampoline: ptr pointer): cint
  {.importc: "ct_inline_hook_install_noreturn", cdecl.}
  ## Variant for targets that don't return (e.g. NoReturn, RtlExit*).
  ## Skips the trampoline-cache-flush step that the regular installer
  ## issues, since no code path will re-enter the target.

proc inlineHookUninstall*(target: pointer): cint
  {.importc: "ct_inline_hook_uninstall", cdecl.}
  ## Remove the inline hook at `target` and free the trampoline.

proc inlineHookBeginTransaction*(): cint
  {.importc: "ct_inline_hook_begin_transaction", cdecl.}
  ## Begin a multi-install transaction. Pair with `commitTransaction`
  ## or `abortTransaction`. Within a transaction, threads are
  ## suspended once and all writes are flushed together (mirrors
  ## Detours' `DetourTransactionCommitEx`).

proc inlineHookCommitTransaction*(): cint
  {.importc: "ct_inline_hook_commit_transaction", cdecl.}
  ## Commit the pending transaction.

proc inlineHookAbortTransaction*(): cint
  {.importc: "ct_inline_hook_abort_transaction", cdecl.}
  ## Abort the pending transaction.

proc inlineHookInHandler*(): cint
  {.importc: "ct_inline_hook_in_handler", cdecl.}
  ## Returns non-zero when the calling thread is currently dispatching
  ## an inline-hook handler. Used by hook bodies to detect re-entrancy
  ## from libc calls that themselves got inline-hooked.

proc inlineHookEnter*()
  {.importc: "ct_inline_hook_enter", cdecl.}
  ## Bump the per-thread `inHandler` counter. Paired with `leave`.

proc inlineHookLeave*()
  {.importc: "ct_inline_hook_leave", cdecl.}
  ## Decrement the per-thread `inHandler` counter.

proc inlineHookInstallGetLastInstallMode*(): cint
  {.importc: "ct_inline_hook_install_get_last_install_mode", cdecl.}
  ## Diagnostic: which install mode (regular 5-byte JMP vs hot-patch
  ## two-short-jump) the last `install` call used. Useful when a
  ## target is hot-patch-eligible (8B FF mov edi,edi preceded by 5×
  ## CC padding) so callers can confirm Detours' two-short-jump
  ## sequence was selected instead of the regular path.

{.pop.}
