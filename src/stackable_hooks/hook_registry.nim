{.push raises: [].}

## Hook registry — priority-ordered hook dispatch.
##
## Maintains a sorted list of hook callbacks per function name.
## Hooks are called in priority order (lower priority number = called first).
## Each hook receives a HookContext and can call `callNext` to proceed down
## the chain, or `callReal` to bypass remaining hooks and invoke the original.

import std/[tables, algorithm]
import ./reentrancy

type
  HookCallback* = proc(ctx: var HookContext) {.raises: [].}
    ## A hook function. Receives a mutable context that carries arguments,
    ## result, and chain position. Uses closure calling convention to allow
    ## capturing state (e.g. in tests or when hooks need external context).

  HookContext* = object
    ## Passed through the hook chain for each dispatched call.
    functionName*: string
    args*: seq[uint64]       ## Up to 6 register-width arguments
    result*: uint64          ## Return value (set by hooks or original)
    chainPos*: int           ## Current position in the hook chain (internal)
    registry*: ptr HookRegistry  ## Back-pointer to the registry (internal)

  HookEntry* = object
    ## A single registered hook.
    priority*: int
    callback*: HookCallback

  HookChain* = object
    ## Sorted list of hooks plus the original function callback.
    hooks*: seq[HookEntry]
    original*: HookCallback  ## The "real" function (or a test stub)

  HookRegistry* = object
    ## Maps function names to their hook chains.
    chains*: Table[string, HookChain]

proc initHookRegistry*(): HookRegistry =
  ## Create a new empty registry.
  HookRegistry(chains: initTable[string, HookChain]())

proc getChain(registry: var HookRegistry, name: string): ptr HookChain =
  ## Get or create the chain for `name`. Returns a stable pointer.
  discard registry.chains.hasKeyOrPut(name, HookChain())
  result = addr registry.chains.mgetOrPut(name, HookChain())

proc findChain(registry: ptr HookRegistry, name: string): ptr HookChain =
  ## Find existing chain for `name`, or nil if not present.
  if name in registry[].chains:
    result = addr registry[].chains.mgetOrPut(name, HookChain())
  else:
    result = nil

proc setOriginal*(registry: var HookRegistry, name: string,
                  cb: HookCallback) =
  ## Set (or replace) the original function callback for `name`.
  getChain(registry, name).original = cb

proc registerHook*(registry: var HookRegistry, name: string, priority: int,
                   cb: HookCallback) =
  ## Register a hook for function `name` at the given priority.
  ## Lower priority numbers run first.
  let chain = getChain(registry, name)
  chain.hooks.add(HookEntry(priority: priority, callback: cb))
  # Keep sorted by priority (stable sort preserves insertion order for ties).
  chain.hooks.sort(proc(a, b: HookEntry): int =
    cmp(a.priority, b.priority))

proc callNext*(ctx: var HookContext) =
  ## Proceed to the next hook in the chain, or to the original if no more
  ## hooks remain. Must be called from within a hook callback.
  let registry = ctx.registry
  if registry == nil:
    return
  let chain = findChain(registry, ctx.functionName)
  if chain == nil:
    return

  let nextPos = ctx.chainPos + 1
  if nextPos < chain.hooks.len:
    ctx.chainPos = nextPos
    chain.hooks[nextPos].callback(ctx)
  elif chain.original != nil:
    chain.original(ctx)

proc callReal*(ctx: var HookContext) =
  ## Bypass all remaining hooks and call the original function directly.
  let registry = ctx.registry
  if registry == nil:
    return
  let chain = findChain(registry, ctx.functionName)
  if chain == nil:
    return

  if chain.original != nil:
    chain.original(ctx)

proc currentPriority*(ctx: HookContext): int =
  ## Return the priority of the currently executing hook.
  ## Useful for diagnostics and testing.
  let chain = findChain(ctx.registry, ctx.functionName)
  if chain != nil and ctx.chainPos < chain.hooks.len:
    result = chain.hooks[ctx.chainPos].priority
  else:
    result = 0

proc dispatch*(registry: var HookRegistry, name: string,
               ctx: var HookContext) =
  ## Begin dispatching a call through the hook chain for `name`.
  ## Sets up the context and calls the first hook (or the original if
  ## no hooks are registered).
  ctx.functionName = name
  ctx.chainPos = 0
  ctx.registry = addr registry

  let chain = findChain(addr registry, name)
  if chain == nil:
    return

  if chain.hooks.len > 0:
    withHookGuard:
      chain.hooks[0].callback(ctx)
  elif chain.original != nil:
    chain.original(ctx)
