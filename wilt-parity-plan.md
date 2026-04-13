<!-- markdownlint-disable MD013 MD032 MD037 MD040 MD060 -->
# wilt ↔ wasm-opt parity plan

wasm-opt is an AST optimiser (binaryen parses to a full IR, transforms, re-emits). wilt is a **byte-level patch-in-place** linker pass: section-boundary index, opcode walker, targeted rewrites. That architectural asymmetry forces a prioritised list — some wasm-opt passes are essentially free for us, some are impossible without rebuilding the IR.

## Triage

### Tier 1 — cheap wins on our current walker

Passes that need only: section identification, opcode walking, byte-level splice. No dataflow, no CFG, no type inference.

| wasm-opt pass | wilt equivalent | notes |
|---|---|---|
| `remove-unused-module-elements` | extend DCE: funcs + types + globals + memories + tables + data + elements | we already have funcs; generalise `DceResult` to cover all 5 other index spaces |
| `remove-unused-types` | we have this (`type_gc`) — extend to handle rec groups & GC forms | currently bails on non-`0x60` |
| `duplicate-import-elimination` | hash each `(module, name, kind, desc)` import tuple, remap duplicates | pure byte work |
| `minify-imports-and-exports` | rename-in-place to short strings, keep a bidirectional map | needs LEB growth-awareness but trivial |
| `reorder-functions` (by call-frequency count) | count `call $f` references, emit functions in descending order | already have the walker |
| `reorder-globals` | same idea | trivial |
| `reorder-types` | same idea | constrained by sub-type ordering rules |
| `strip` / `strip-target-features` / `strip-eh` / `strip-dwarf` | drop named custom sections | essentially a filter |
| `limit-segments` | cap data/element segment count; coalesce adjacent | byte-level splice |
| `memory-packing` (lite version) | drop zero-tail of data segments | scan segment tails |
| `duplicate-function-elimination` | hash `(type, body-bytes-after-call-remap)`; remap callers | needs call-graph remap, which we now have |

### Tier 2 — needs a real instruction decoder + small analyses

Doable but requires growing `opcode.rs` toward SIMD/EH/atomics, and per-body scratch state (local-use counts, reaching defs, a block nesting stack).

| wasm-opt pass | wilt equivalent | cost |
|---|---|---|
| `precompute` (our `const_fold` extended) | full constant propagation over one function, all numeric types | medium — need per-local abstract values, not just byte patterns |
| `vacuum` (remove `nop`/unreachable-after-`br`/etc.) | walk instructions, drop trivially dead ones | small |
| `merge-blocks` | flatten single-entry/single-exit nested `block`s | needs nesting stack |
| `remove-unused-brs` | find `br` to immediately-following label | small walker change |
| `remove-unused-names` | strip unused `block`/`loop` labels | names are implicit in binary WASM — this is really about collapsing block types |
| `dae` (dead arg elimination) | find funcs where param N is never used; rewrite callers | needs call-site rewriting (we can do this) |
| `directize` | `call_indirect` targets single funcref → `call` | needs table-init analysis |
| `local-cse` | common subexpression within one function | needs expression hashing |
| `simplify-locals` (basic) | replace `local.get N` immediately after `local.set N` with `local.tee` | pattern match, small |
| `reorder-locals` | sort locals by use-count | local-count traversal |
| `inlining` (trivial only) | inline single-caller functions whose body is `local.get`s + `call`; remove | needs call-site rewriter we already have |

### Tier 3 — wants a full IR (skip or defer)

These presume you can *re-type-check* arbitrary edits, track stack effects, or rewrite control flow. Possible eventually with a small per-function SSA, but out of the "zero-copy byte patcher" bounds.

| pass | why skip |
|---|---|
| `coalesce-locals` | needs full liveness; type-coalesce check requires type lattice |
| `optimize-instructions` | ~thousands of peephole rewrites that depend on result types |
| `remove-unused-brs` (advanced branches) | re-encoding block types / unreachable-propagation |
| `flatten` / `re-reloop` | control-flow rebuilding |
| `ssa` / `rse` / `gufa` / `heap2local` | whole-function SSA/PTA |
| `outlining` / `code-folding` / `code-pushing` | needs global equivalence testing |
| All GC-specific passes (`type-refining`, `gto`, `global-struct-inference`, `type-merging`, `unsubtyping`, …) | depend on subtype lattice + whole-program analysis |
| All lowering passes (`i64-to-i32`, `memory64-lowering`, `sign-ext-lowering`, …) | sem-preserving rewrites over the whole module |

## Proposed wilt roadmap

### Milestone A — "pass-through" done (current state)

- `dce` (funcs): ✓
- `type_gc`: partial (bails on GC)
- `const_fold`: trivial i32 patterns
- `compress`: exists, not wired

Measured on binaryen text corpus: **5.7% modification rate, 699 B saved of 546 KB**. That's barely-moving.

### Milestone B — generalise DCE to *module elements* (highest leverage)

One `ModuleDceResult` covering functions, types, tables, memories, globals, data segments, elem segments, tags. Keep the existing call/ref.func remap. Add remapping for:
- `global.get` / `global.set` (global indices)
- `table.*` ops (table indices)
- data & elem index opcodes (`data.drop`, `elem.drop`, `memory.init`, `table.init`)

This single generalisation unlocks **remove-unused-module-elements**, which in practice is the pass that actually moves the needle on emscripten/rustc output.

Expected: modification rate 5% → 30%+ on the text corpus.

### Milestone C — vacuum + simplify-locals (basic)

Walk instructions per-body. Drop `nop`. Pattern-match `local.set N; local.get N` → `local.tee N`. Drop code after unconditional `br`/`return`/`unreachable` until matching `end`. Drop `drop; i32.const X` at end-of-block.

Small cost. Adds modification rate ~5-10%. Bytes saved: meaningful per-function.

### Milestone D — duplicate-function-elimination

Hash each function body (after normalising local-indices and call-targets through a stable canonicalisation). Remap call sites. This one pass often saves 5-15% on C++ output.

### Milestone E — precompute (real constant propagation)

Per-function abstract interpreter over a stack + locals, tracking `Constant(T) | Unknown`. Evaluate when both operands concrete; emit `T.const` + `drop` as needed. Covers i32/i64/f32/f64/ref.null. Replaces `const_fold`.

### Milestone F — reorder-* & strip-*

Four small passes. Mostly byte-level sort + filter. Good opportunity to add a `--minify` flag.

### Milestone G — minify-imports-and-exports

LEB-aware string rewriter. Bidirectional map output (so downstream tooling still works).

### Beyond G

Inlining (trivial) and dae are the first AST-adjacent passes. At that point it's worth evaluating whether to grow a thin per-function IR (just stack + locals + block nesting) that all non-trivial passes share, vs. keeping each as a hand-written byte walker. Binaryen's answer is "one IR" — wilt's USP is "no IR", so we should push byte-level as far as it goes and draw the line honestly when it costs more than it saves.

## What wilt should *not* try to match

- Anything GC-specific (rec groups, subtyping lattice, struct refinement). Wilt's audience is linker-output, mostly from Rust/C++ via LLVM, which rarely emits GC.
- Control-flow restructuring (`flatten`, `rereloop`). Irreducible flow is not worth it.
- Vendor lowering passes (`legalize-js-interface`, `i64-to-i32`). These are binaryen-as-polyfill, not wilt-as-linker-optimiser.

## Measurement

Every milestone must land with the existing harness showing:
- no new validation failures
- no shape regressions
- modification rate up
- bytes saved up
- no panics

The harness is the scoreboard. No pass lands without moving at least one of the last two numbers upward.
