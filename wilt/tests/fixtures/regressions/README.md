# Regression fixtures

Each `.wat` file here is the minimal input that triggered a specific
historical bug. The test harness (`wilt/tests/regressions.rs`) assembles
each one, runs the targeted transformation, and asserts the output still
validates (and, where meaningful, matches an expected shape).

If a bug reappears, the dedicated test fails. The fuzz + binaryen corpus
still run broadly, but those are stochastic / environmental; these are the
pinned truths.

| file | bug |
|---|---|
| `type_gc_block_type_ref.wat` | `type_gc` removed a type without rewriting the `block (type N)` immediate in a body that referenced it |
| `type_gc_import_type.wat` | `type_gc` didn't remap the type index of a function **import** |
| `dce_skips_simd_body.wat` | `dce::rewrite_body` silently kept stale `call` indices on bodies containing SIMD (walker failed) |
| `remove_br_stack_imbalance.wat` | naive `remove_unused_brs` deleted a `br 0` whose `end` had an extra value under the br — stack-polymorphic semantics masked the imbalance until the br was gone |
| `simplify_locals_loop.wat` | `simplify_locals` spun forever when a `local.set X` was followed by a `local.get/set/tee` for a **different** local |
| `dae_block_type_ref.wat` | `DAE` missed a blocktype type-reference (and earlier also missed calling `ensure_function_bodies_parsed`, silently walking zero bodies) |
