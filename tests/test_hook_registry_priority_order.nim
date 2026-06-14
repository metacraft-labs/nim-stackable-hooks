## Acceptance test from MCR-OS-Interposition.status.org M0 verification:
##
##   test_hook_registry_priority_order — Register 5 hooks with different
##   priorities; verify dispatch calls them in priority order.

import std/unittest

import stackable_hooks/hook_registry

suite "hook_registry_priority_order":
  test "five hooks dispatch in ascending priority":
    var registry = initHookRegistry()
    var order: seq[int] = @[]
    proc h10(ctx: var HookContext) {.raises: [].} =
      order.add(10); callNext(ctx)
    proc h30(ctx: var HookContext) {.raises: [].} =
      order.add(30); callNext(ctx)
    proc h20(ctx: var HookContext) {.raises: [].} =
      order.add(20); callNext(ctx)
    proc h50(ctx: var HookContext) {.raises: [].} =
      order.add(50); callNext(ctx)
    proc h40(ctx: var HookContext) {.raises: [].} =
      order.add(40); callNext(ctx)
    proc origNoop(ctx: var HookContext) {.raises: [].} =
      ctx.result = 42'u64

    registry.setOriginal("F", origNoop)
    registry.registerHook("F", 30, h30)
    registry.registerHook("F", 10, h10)
    registry.registerHook("F", 50, h50)
    registry.registerHook("F", 20, h20)
    registry.registerHook("F", 40, h40)

    var ctx = HookContext()
    registry.dispatch("F", ctx)

    check order == @[10, 20, 30, 40, 50]
    check ctx.result == 42'u64

  test "call_next chain reaches original":
    var registry = initHookRegistry()
    var origRan = false
    proc h1(ctx: var HookContext) {.raises: [].} = callNext(ctx)
    proc h2(ctx: var HookContext) {.raises: [].} = callNext(ctx)
    proc h3(ctx: var HookContext) {.raises: [].} = callNext(ctx)
    proc orig(ctx: var HookContext) {.raises: [].} =
      origRan = true; ctx.result = 1'u64

    registry.setOriginal("F", orig)
    registry.registerHook("F", 100, h1)
    registry.registerHook("F", 200, h2)
    registry.registerHook("F", 300, h3)

    var ctx = HookContext()
    registry.dispatch("F", ctx)
    check origRan
    check ctx.result == 1'u64

  test "call_real bypasses remaining hooks":
    var registry = initHookRegistry()
    var origRan = false
    var h2Ran = false
    proc h1(ctx: var HookContext) {.raises: [].} = callReal(ctx)
    proc h2(ctx: var HookContext) {.raises: [].} = h2Ran = true; callNext(ctx)
    proc orig(ctx: var HookContext) {.raises: [].} = origRan = true

    registry.setOriginal("F", orig)
    registry.registerHook("F", 100, h1)
    registry.registerHook("F", 200, h2)

    var ctx = HookContext()
    registry.dispatch("F", ctx)
    check origRan
    check not h2Ran
