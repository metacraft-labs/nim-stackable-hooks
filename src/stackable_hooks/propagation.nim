{.push raises: [].}

## Child-process propagation framework.
##
## Spec: ``MCR-Library-APIs.md`` §6.3 + ``MCR-OS-Interposition.status.org``
## §M0 *** Deliverables.
##
## Each consumer DLL that wants its hooks active in spawned children
## allocates one static ``PropagationNode``, registers it via
## ``registerPropagationNode``, and toggles propagation per-library via
## ``enableAutoPropagation`` / ``disableAutoPropagation``. At spawn
## time (``execve`` / ``posix_spawn`` on POSIX, ``CreateProcessW`` on
## Windows) the framework walks the registry, picks every enabled
## library, and injects each into the child:
##
## * Linux / FreeBSD: prepends every enabled library to ``LD_PRELOAD``.
## * macOS: prepends every enabled library to ``DYLD_INSERT_LIBRARIES``
##   and rewrites SIP-protected exec paths to the sandbox-tools copy
##   when the child is a system binary that strips DYLD overrides.
## * Windows: suspends the child, ``CreateRemoteThread(LoadLibraryW)``
##   for every enabled library, then runs its registered init
##   entrypoint (typically called ``<library>_init``).
##
## The registry is a singly-linked list traversed lock-free by the
## propagation hooks. Insertion is performed at library init time
## via a CAS-published ``next`` link. The enabled bit is per-node
## atomic so a library can flip propagation on/off at any time
## without taking a lock.

import std/[atomics, os, strutils]

when defined(macosx):
  proc injectionEnvVar*(): string =
    ## The environment variable name for macOS library injection.
    "DYLD_INSERT_LIBRARIES"

  proc buildInjectionEnv*(libraryPath: string): string =
    ## Build the value for DYLD_INSERT_LIBRARIES.
    ## If the variable already has a value, prepend our library.
    let existing = getEnv("DYLD_INSERT_LIBRARIES")
    if existing.len == 0:
      libraryPath
    else:
      libraryPath & ":" & existing

else:
  proc injectionEnvVar*(): string =
    ## The environment variable name for Linux library injection.
    "LD_PRELOAD"

  proc buildInjectionEnv*(libraryPath: string): string =
    ## Build the value for LD_PRELOAD.
    ## If the variable already has a value, prepend our library.
    let existing = getEnv("LD_PRELOAD")
    if existing.len == 0:
      libraryPath
    else:
      libraryPath & ":" & existing

# SIP-aware path rewriting (macOS only, but the function is cross-platform
# so it can be tested anywhere).

const sipProtectedPrefixes* = ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"]
  ## On macOS, binaries under these paths are protected by System Integrity
  ## Protection (SIP). DYLD_INSERT_LIBRARIES is stripped from the environment
  ## when executing these binaries. To work around this, ct_interpose can
  ## redirect execution to a sandbox-tools copy of the binary.

proc rewriteSipPath*(binaryPath: string, sandboxToolsDir: string): string =
  ## Given a binary path that may be SIP-protected, return the rewritten
  ## path pointing into `sandboxToolsDir`. If the path is not SIP-protected,
  ## return it unchanged.
  ##
  ## Example:
  ##   rewriteSipPath("/bin/bash", "/opt/ct/sandbox-tools")
  ##   => "/opt/ct/sandbox-tools/bin/bash"
  ##
  ##   rewriteSipPath("/usr/local/bin/python3", "/opt/ct/sandbox-tools")
  ##   => "/usr/local/bin/python3"  (not SIP-protected)
  for prefix in sipProtectedPrefixes:
    if binaryPath.startsWith(prefix):
      # Strip leading slash so we can join with sandboxToolsDir
      let stripped = binaryPath.strip(leading = true, trailing = false, chars = {'/'})
      if sandboxToolsDir.endsWith("/"):
        return sandboxToolsDir & stripped
      else:
        return sandboxToolsDir & "/" & stripped
  result = binaryPath

proc isSipProtected*(binaryPath: string): bool =
  ## Check whether a binary path falls under a SIP-protected prefix.
  for prefix in sipProtectedPrefixes:
    if binaryPath.startsWith(prefix):
      return true
  result = false

proc unrewriteSipPath*(binaryPath: string, sandboxToolsDir: string): string =
  ## Inverse of `rewriteSipPath`: given a path that may point into a
  ## `sandboxToolsDir` SIP sandbox copy, return the ORIGINAL system path it
  ## mirrors. If `binaryPath` is not under `sandboxToolsDir`, return it
  ## unchanged.
  ##
  ## The sandbox layout mirrors the original directory structure under the
  ## sandbox root (see `rewriteSipPath` / `prepareSandboxCopy`), so the inverse
  ## strips the sandbox prefix and restores the leading slash — but ONLY when the
  ## resulting path is genuinely SIP-protected, so an unrelated path that merely
  ## happens to share the prefix string is not mis-mapped.
  ##
  ## Example:
  ##   unrewriteSipPath("/opt/ct/sandbox-tools/bin/sh", "/opt/ct/sandbox-tools")
  ##   => "/bin/sh"
  ##
  ##   unrewriteSipPath("/opt/ct/sandbox-tools/bin/sh", "/opt/ct/sandbox-tools/")
  ##   => "/bin/sh"  (a trailing slash on the sandbox dir is tolerated)
  if sandboxToolsDir.len == 0:
    return binaryPath
  var root = sandboxToolsDir
  # Normalise a single trailing slash so the prefix comparison is exact.
  while root.len > 1 and root[^1] == '/':
    root.setLen(root.len - 1)
  let prefix = root & "/"
  if not binaryPath.startsWith(prefix):
    return binaryPath
  # Restore the original absolute path: leading slash + the mirrored remainder.
  let original = "/" & binaryPath[prefix.len .. ^1]
  # Only treat it as a sandbox copy if the restored path is genuinely SIP-
  # protected; otherwise leave the input untouched (defensive — never invent a
  # system path for an unrelated sandbox-rooted file).
  if isSipProtected(original):
    return original
  result = binaryPath

proc sandboxToolsDir*(): string =
  ## Return the sandbox-tools directory path.
  ## Uses CT_SANDBOX_TOOLS_DIR if set, otherwise defaults to
  ## a temporary directory under the user's cache.
  let envDir = getEnv("CT_SANDBOX_TOOLS_DIR")
  if envDir.len > 0:
    return envDir
  try:
    return getTempDir() / "ct-mcr-sandbox-tools"
  except OSError:
    return "/tmp/ct-mcr-sandbox-tools"

proc prepareSandboxCopy*(binaryPath: string,
                         sandboxDir: string): string {.raises: [OSError, IOError].} =
  ## If `binaryPath` is SIP-protected, copy it into `sandboxDir` mirroring
  ## the original directory structure. Returns the path to the copy.
  ## If the binary is not SIP-protected, returns `binaryPath` unchanged.
  ##
  ## Example:
  ##   prepareSandboxCopy("/bin/bash", "/tmp/ct-mcr-sandbox-tools")
  ##   => copies /bin/bash to /tmp/ct-mcr-sandbox-tools/bin/bash
  ##   => returns "/tmp/ct-mcr-sandbox-tools/bin/bash"
  ##
  ## The copy is a regular file without the hardened runtime flag,
  ## so DYLD_INSERT_LIBRARIES works on it.
  if not isSipProtected(binaryPath):
    return binaryPath

  let destPath = rewriteSipPath(binaryPath, sandboxDir)

  # Create parent directories if needed.
  let destDir = destPath.parentDir()
  if not dirExists(destDir):
    createDir(destDir)

  # Copy the binary (overwrite if already present to ensure freshness).
  copyFile(binaryPath, destPath)

  # Ensure the copy is executable.
  setFilePermissions(destPath, {fpUserExec, fpUserRead, fpUserWrite,
                                fpGroupExec, fpGroupRead,
                                fpOthersExec, fpOthersRead})

  return destPath

proc rewriteExecPathForSip*(binaryPath: string): string =
  ## Called by exec/posix_spawn hooks at runtime to rewrite a SIP-protected
  ## binary path to use the sandbox-tools copy. Reads CT_SANDBOX_TOOLS_DIR
  ## from the environment.
  ##
  ## Unlike `prepareSandboxCopy`, this does NOT copy the binary — it only
  ## rewrites the path if the sandbox copy already exists. The `ct-mcr record`
  ## command is responsible for pre-populating the sandbox-tools directory
  ## for the initial target; child process binaries must also be pre-populated
  ## (e.g. by a setup step or by the recorder preparing common tools ahead
  ## of time).
  ##
  ## Returns the rewritten path if a sandbox copy exists, or the original
  ## path otherwise.
  if not isSipProtected(binaryPath):
    return binaryPath

  let sandboxDir = sandboxToolsDir()
  if sandboxDir.len == 0:
    return binaryPath

  let rewritten = rewriteSipPath(binaryPath, sandboxDir)
  try:
    if fileExists(rewritten):
      return rewritten
  except OSError:
    discard

  # No sandbox copy available — return original path.
  # DYLD_INSERT_LIBRARIES will be stripped by SIP for this child.
  return binaryPath

# ---------------------------------------------------------------------------
# Per-library propagation registry
# ---------------------------------------------------------------------------

type
  PropagationNode* = object
    ## One node per consumer DLL. Each consumer declares ONE static
    ## instance and registers it via ``registerPropagationNode`` at
    ## library init time. The framework walks the linked list at
    ## spawn time and includes every node whose ``enabled`` atomic is
    ## true.
    ##
    ## Fields:
    ##   ``next`` — next node in the registry (singly linked, CAS-published).
    ##   ``libraryPath`` — absolute filesystem path of this library's image,
    ##     populated at registration time via ``dladdr`` (POSIX) or
    ##     ``GetModuleHandleExW(FROM_ADDRESS)`` (Windows).
    ##   ``initSymbol`` — name of the C-callable init entrypoint the Windows
    ##     injector calls after ``LoadLibraryW`` returns. POSIX backends
    ##     ignore this field (env-var injection runs the consumer's
    ##     library-load constructor automatically).
    ##   ``enabled`` — per-library on/off flip. Flipped via
    ##     ``enableAutoPropagation`` / ``disableAutoPropagation``.
    next*: ptr PropagationNode
    libraryPath*: string
    initSymbol*: string
    enabled*: Atomic[bool]

var
  gPropagationHead {.global.}: Atomic[ptr PropagationNode]

proc registerPropagationNode*(node: ptr PropagationNode) =
  ## CAS-publish ``node`` at the head of the registry. Idempotent —
  ## a re-registration call (same ``node`` pointer) is a no-op.
  if node == nil:
    return
  # If we're already in the chain (next non-nil OR head points at us),
  # bail. Walk the chain checking identity to be safe in the rare
  # double-register case.
  var cur = gPropagationHead.load()
  while cur != nil:
    if cur == node:
      return
    cur = cur.next
  # Push at head via CAS.
  while true:
    let head = gPropagationHead.load()
    node.next = head
    if gPropagationHead.compareExchange(node.next, node):
      break

iterator propagationNodes*(): ptr PropagationNode =
  ## Walk the registry. Safe to call from a spawn hook; concurrent
  ## registration would land new entries at the head ahead of where
  ## we're iterating, so the iterator sees an existing prefix
  ## without observing the new addition (acceptable: the new
  ## library would not have completed its own init before being
  ## eligible for propagation).
  var cur = gPropagationHead.load()
  while cur != nil:
    yield cur
    cur = cur.next

proc enableAutoPropagation*(node: ptr PropagationNode) =
  ## Mark this node for inclusion in child-process propagation.
  if node != nil:
    node.enabled.store(true)

proc disableAutoPropagation*(node: ptr PropagationNode) =
  ## Exclude this node from child-process propagation.
  if node != nil:
    node.enabled.store(false)

proc isAutoPropagationEnabled*(node: ptr PropagationNode): bool =
  if node == nil: false
  else: node.enabled.load()

proc enabledLibraryPaths*(): seq[string] =
  ## Snapshot every enabled library's path for use by the platform-
  ## specific spawn hook. Order is registry-insertion-LIFO, which
  ## matches the order callers usually want for ``LD_PRELOAD`` /
  ## ``DYLD_INSERT_LIBRARIES`` (later registrations win earlier slots
  ## in the env var).
  for node in propagationNodes():
    if node.enabled.load() and node.libraryPath.len > 0:
      result.add(node.libraryPath)

proc buildInjectionEnvFromRegistry*(): string =
  ## Build the LD_PRELOAD/DYLD_INSERT_LIBRARIES value from the
  ## registry. Each enabled library is prepended in registry-LIFO
  ## order, then the original env-var value is appended so the
  ## consumer doesn't drop overlays the user already had set.
  let libs = enabledLibraryPaths()
  if libs.len == 0:
    return getEnv(injectionEnvVar())
  result = libs[0]
  for i in 1 ..< libs.len:
    result.add(':')
    result.add(libs[i])
  let existing = getEnv(injectionEnvVar())
  if existing.len > 0:
    result.add(':')
    result.add(existing)
