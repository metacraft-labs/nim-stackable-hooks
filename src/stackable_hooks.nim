## stackable-hooks — public re-export module.
##
## Consumers `import stackable_hooks` for the framework basics; deeper
## platform-specific surfaces (IAT patcher, inline hook primitive) live
## under `stackable_hooks/platform/*` and `stackable_hooks/inline_hook/*`
## and are imported explicitly.

import stackable_hooks/hook_registry
import stackable_hooks/reentrancy
import stackable_hooks/propagation

export hook_registry
export reentrancy
export propagation

when defined(windows):
  import stackable_hooks/propagation_windows
  export propagation_windows
