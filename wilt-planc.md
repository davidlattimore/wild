<!-- markdownlint-disable MD013 MD060 -->
# wilt — Plan C: linker hints + per-body IR

Successor to Plan B. Plan B got us a zero-copy `MutModule`, ported the existing
passes onto it, added the Group B passes (reorder-locals, remove-unused-brs,
merge-blocks, simplify-locals, inline-trivial, DAE), and parallelised every
body-iterating pass with rayon. Result: wilt saves **18,575 B (3.2%)** on the
binaryen binary corpus in **49 ms** wall time — about **140× faster than
`wasm-opt -O`** (which saves 18.9% in 6.9 s).

The remaining gap to wasm-opt is roughly **a 6× factor in size savings**.
Plan B passes are byte-patch peepholes — the ceiling on what byte-patch can
extract is roughly where we are. Closing the gap requires two structural
moves that this plan describes:

1. A **`LinkerHints` trait** so wilt can take advantage of metadata held by an
   in-pipeline wasm linker (wild) without becoming part of wild.
2. A **per-body IR layer** (decoded instruction array → CFG → use-def) so
   passes that need within-body data flow can express themselves cleanly.

These two axes are orthogonal: hints close the world, IR enables intra-body
analysis. The next-level passes (real simplify-locals, real inliner, devirt
of `call_indirect`) need both, but each can be built and shipped
independently.

## Why wilt stays separate

Genuine standalone uses that don't go through wild:

- Post-build optimisation in CI on already-linked `.wasm` from any toolchain.
- Plugin-loading runtimes (host trims a third-party module before instantiate).
- Other wasm linkers (wasm-ld, wasm-tools, custom).
- Size-budget gates in build pipelines.
- A clean, small Rust optimiser that researchers can fork and prototype against.

Folding wilt into wild surrenders all of these for no architectural win.
The right shape is library wilt, with an opt-in trait that wild (or anyone
else with the metadata) can implement.

## Architecture

```text
┌─────────────────────────────────────────┐
│ wild  (wasm linker)                     │
│   - symbol table, relocations           │
│   - reachability analysis               │
│   - merge .o.wasm → wasm                │
│   - implements wilt::LinkerHints        │
└──────────────┬──────────────────────────┘
               │ &dyn LinkerHints
               ▼
┌─────────────────────────────────────────┐
│ wilt  (optimiser, library)              │
│ ┌─────────────────────────────────────┐ │
│ │ pass dispatch                       │ │
│ │   reads hints, or infers if absent  │ │
│ └────┬────────────────────────────────┘ │
│      │ uses                             │
│      ▼                                  │
│ ┌─────────────────────────────────────┐ │
│ │ wilt::ir  (private)                 │ │
│ │   per-body decoded form             │ │
│ │   CFG layer                         │ │
│ │   use-def chains                    │ │
│ └─────────────────────────────────────┘ │
│      │ emits                            │
│      ▼                                  │
│ ┌─────────────────────────────────────┐ │
│ │ MutModule (zero-copy bytes view)    │ │
│ └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

Three boundaries, all narrow:

- **wild ↔ wilt**: the `LinkerHints` trait. ~6 methods.
- **wilt passes ↔ IR**: private to wilt; free to evolve.
- **wilt passes ↔ MutModule**: today's API, unchanged.

Standalone wilt: drop the wild box, every pass receives `None` for hints,
IR still works. Loses closed-world precision on a few passes; otherwise
identical.

## `LinkerHints` trait

```rust
pub trait LinkerHints {
    /// Function is unreachable from outside the module — never exported,
    /// never reachable via ref.func or table init.
    fn is_internal(&self, func_idx: u32) -> bool;

    /// Number of static call sites for this function across the link set.
    /// `Some(1)` enables aggressive single-call-site inlining.
    fn call_count(&self, func_idx: u32) -> Option<u32>;

    /// Functions reachable through this table — closes the call_indirect set.
    fn table_targets(&self, table_idx: u32) -> Option<&[u32]>;

    /// Every function index that appears as a `ref.func` anywhere
    /// (bodies, element segments, global init exprs).
    fn ref_func_targets(&self) -> &[u32];

    /// Original input-object index, for layout / locality passes
    /// that want to cluster bodies that came from the same TU.
    fn origin_unit(&self, func_idx: u32) -> Option<u32>;

    /// True if this global is read anywhere in the link set.
    fn global_is_read(&self, global_idx: u32) -> bool;
}
```

Properties:

- **Default impls** for every method (returning the conservative answer)
  so adding a method is a SemVer minor change.
- **Sync**, so it can be borrowed across rayon workers.
- Pure accessor surface — wilt has no idea what wild's symbol table looks
  like; wild has no idea about wilt's `MutModule`.

Entry point:

```rust
pub fn optimise(input: &[u8]) -> Vec<u8> { /* current behaviour */ }
pub fn optimise_with_hints<H: LinkerHints>(input: &[u8], hints: &H) -> Vec<u8>;
```

Each pass's `apply_mut` grows an optional hints argument. Passes that
ignore hints stay byte-identical.

## IR design

### IR-1: per-body instruction array

```rust
pub struct Instr {
    pub op: u8,
    pub imm: u32,                 // primary immediate, or 0
    pub byte_range: (u32, u32),   // offset+len in original body bytes
}

pub struct BodyIr<'a> {
    pub bytes: &'a [u8],          // the original body
    pub instrs: Vec<Instr>,       // densely packed instruction list
    pub locals_end: usize,        // first instruction byte
}
```

Built lazily on first use within a fixpoint iteration; cached on
`MutModule`; invalidated when a pass calls `set_body`. `~16 B / instr`
flat. Skipped instructions never decode their immediates.

### IR-2: CFG layer

```rust
pub struct BasicBlock {
    pub instr_range: Range<u32>,         // indices into BodyIr.instrs
    pub successors: SmallVec<[u32; 4]>,  // basic-block indices
    pub block_kind: BlockKind,
}

pub struct CfgIr {
    pub blocks: Vec<BasicBlock>,
    pub entry: u32,
}
```

Built on top of `BodyIr` when a pass requests it. Shared across passes
that need it within the same fixpoint iteration.

### IR-3: use-def

For passes that want reaching-defs over locals: a per-block
`Vec<(local_idx, def_instr_idx)>` summary, propagated via standard
worklist algorithm. Built only when explicitly requested.

### What we explicitly DON'T build

- Full SSA construction.
- Sea-of-nodes.
- E-graph rewriting.

Those would double our codebase and we'd lose the speed-vs-wasm-opt pitch.

## Pass-by-pass plan after the foundation

| pass | needs IR | needs hints | what changes |
|---|---|---|---|
| `dae_v2` | no | yes | closed-world: drop conservative guard rails |
| `inliner_v2` | yes | yes | single-call-site aggressive inlining |
| `simplify_locals_v2` | yes (CFG + use-def) | no | reaching-def-based dead-store, copy-prop within body |
| `devirt_call_indirect` | yes | yes | new pass: when table_targets has 1–2 entries, rewrite call_indirect → call (or br_table over calls) |
| `dead_globals` | no | yes | new pass: globals nobody reads → remove |
| `cfg_dce` | yes (CFG) | no | unreachable basic blocks |
| `branch_threading` | yes (CFG) | no | `if cond ...; if cond ...` → `if cond { ... ... }` |

## What this architecture unlocks — concretely

Every entry below is a transformation that wilt **cannot do today** because it
either lacks closed-world information (no `LinkerHints`) or lacks intra-body
data flow (no IR). For each, the table marks which axis it depends on, gives
the worked example, and notes the expected payoff class.

### Hints-only (no IR needed)

#### 1. Closed-world DAE — remove any dead param, not just trailing

Today: `dae` only removes the LAST tail param of a function, with strict
guards (type unique across module, not exported, not ref-funcd). The "last
tail param" restriction comes from not wanting to renumber locals; the strict
guards come from open-world uncertainty.

With `is_internal(f) = true` and `ref_func_targets()` known: drop both
restrictions. Remove dead param at any position. Renumber locals using IR
(see #5 below). All callers are visible — every call-site can be rewritten.

```wat
;; before
(func $helper (param $a i32) (param $b i32) (param $c i32) (result i32)
  local.get $a       ;; only $a is read; $b and $c dead
  local.get $c       ;; oh wait — $c too
  i32.add)
(func $caller (export "x")
  (call $helper (i32.const 1) (i32.const 2) (i32.const 3)))

;; after dae_v2 (drop dead $b)
(func $helper (param $a i32) (param $c i32) (result i32)
  local.get $a
  local.get $c
  i32.add)
(func $caller (export "x")
  (call $helper (i32.const 1) (i32.const 3)))    ;; $b's push elided
```

#### 2. Dead globals

If `global_is_read(g) == false` for any global g across the link set, remove
the global definition AND every `global.set g` that writes to it (replace
with `drop`). Re-runs through vacuum to clean up the dropped values.

```wat
;; $g is set in two places, never read. Both writes become drops; $g vanishes.
(global $g (mut i32) (i32.const 0))
;; ...
(global.set $g (i32.const 5))   ;; → drop
(global.set $g (i32.const 7))   ;; → drop
```

#### 3. Indirect-target dead code elimination

Today's DCE keeps any function reachable via `ref.func` pessimistically.
With `table_targets(t)` known, a function appearing in a table that's
never `call_indirect`-ed can also be dropped.

#### 4. Type-section pre-merge dedup

When wild merges several `.o.wasm`, each input may declare its own
`(func (param i32) -> i32)` type. wild knows the equivalence; pass that
to wilt so type_gc can collapse them in one shot rather than rediscover
through bytewise comparison.

### IR-only (no hints needed)

#### 5. Local renumbering primitive

The single most reusable IR-level utility. Given an old → new local index
map and a body's `Vec<Instr>`, rewrite every `local.{get,set,tee}` immediate
to its new index. Cheap; needed by:

- DAE (when removing a non-tail param)
- Inliner (when splicing callee body into caller — callee's locals shift up)
- A future `coalesce_locals` pass (merge two locals never live at the same
  time into one slot)

#### 6. Reaching-definitions — real `simplify_locals`

Today's pass is single-basic-block straight-line. With CFG + reaching defs,
we handle:

```wat
;; current pass bails at the `if` and leaves both stores
i32.const 1
local.set $x       ;; LIVE only in then-branch; dead in else-branch
i32.const 2
if
  local.get $x
  drop
else
  ;; never reads $x here
end
;; v2 with reaching-defs: hoists $x's set into the then-branch, then
;; recognises the now-trivially-paired set/get → tee → drop.
```

Catches dead stores split by control flow, plus lets `vacuum`'s set/get
coalescing fire across structures it currently can't see.

#### 7. Copy propagation within body

`local.set $a (local.get $b)` followed by `local.get $a` → use `local.get $b`
directly, deleting the set. Needs def-use to confirm $b isn't redefined
between def and use.

```wat
;; before
local.get $b
local.set $a
;; ...100 instrs that don't touch $a or $b...
local.get $a
i32.add
;; after copy-prop
;; ...100 instrs (set deleted)...
local.get $b
i32.add
```

Common in compiler output (rustc emits `local.set X (local.get Y)` patterns
when lowering let-bindings).

#### 8. Constant propagation within body

Once we track def chains, `local.set $a (i32.const 42)` ... `local.get $a`
becomes `i32.const 42` inline. Combined with const-fold, cascades.

#### 9. CFG-based DCE

Current `vacuum` strips trailing nops and dead `block`s; CFG-aware DCE
removes any basic block unreachable from the function entry. Catches:

```wat
i32.const 1
br 0            ;; jump out of block unconditionally
;; everything below is unreachable but currently kept
i32.const 99
i32.add
local.set 0
```

#### 10. Branch threading

Two `if cond ...` with the same condition and no intervening writes →
merged. `if false ...` → take else branch unconditionally and drop the
condition. `block; br 0; unreachable; end` → just the `br`.

### Both IR + hints — the high-leverage passes

#### 11. Single-call-site inlining

`call_count(f) == Some(1)`: the only caller is known, the callee body
becomes part of the caller, the function definition is deleted (DCE
will pick it up). Mechanics:

```wat
;; before — $helper called once from $main
(func $helper (param $x i32) (result i32)
  local.get $x
  i32.const 5
  i32.mul)
(func $main (export "main") (result i32)
  i32.const 7
  call $helper)

;; after inliner_v2
(func $main (export "main") (result i32) (local $tmp i32)
  i32.const 7
  local.set $tmp        ;; arg becomes a local of caller
  local.get $tmp
  i32.const 5
  i32.mul)
;; $helper deleted by DCE next iteration
```

Then vacuum/simplify_locals/copy-prop fold the `set/get $tmp` pair away.
Net effect: `$helper`'s body inlined verbatim, `call` instruction gone,
function definition gone.

This is the biggest single win. Toolchains generate small static helpers
(`Box::new`, `Vec::with_capacity`, etc.) called from one site each;
inlining them deletes both the helper and the call.

#### 12. Devirtualize `call_indirect`

`table_targets(t) = [F]`: rewrite `call_indirect t` (which pops a table
index then makes an indirect call) to `drop ; call F`. Two-element targets
expand to a trivial `if`. Three or more: probably not worth it; bail.

```wat
;; before
i32.const 0          ;; table index — known to point at $foo
call_indirect (type $sig)

;; after, when table_targets = [$foo]
drop                  ;; drop the table idx (or skip its push entirely
                      ;;   if peephole pulls forward)
call $foo
```

Combined with copy-prop / const-prop, often the table-idx push can be
deleted entirely upstream.

#### 13. Cross-procedural argument liveness driving DAE

`dae_v2` knows `is_internal`. Combined with IR-level reaching-defs, can
detect: "this argument is immediately stored into a local that's never
read" — even if it would have been read in a different control-flow path
that's now provably unreachable. More aggressive than syntactic
"local-N never appears as a read".

#### 14. Inlining-driven simplify-locals cascade

After M6 inliner runs, the just-inlined callee's locals merge with the
caller's. simplify_locals_v2 then often discovers the inlined block is
mostly dead — the caller pushed a constant, the inlined body branched
on that constant, half the inlined body is now unreachable.

This cascade is where wasm-opt gets a lot of its 18.9% — not because any
single pass is magic, but because inliner + dce + simplify_locals interact
in the right order. We only need order, not novel algorithms.

### Quantified expectations (best-effort, to be validated per-milestone)

| pass family | corpus impact (estimate) | source of estimate |
|---|---|---|
| `dae_v2` | +1–2% bytes saved | binaryen's DAE pass on similar corpora |
| `simplify_locals_v2` | +2–4% | binaryen's simplify-locals contribution |
| `inliner_v2` | +5–10% | the single biggest classic LTO win |
| `devirt_call_indirect` | +0.5–2% | depends heavily on vtable density |
| `dead_globals` + cfg_dce | +1–2% | correlates with toolchain hygiene |
| **cumulative** | **~15% bytes saved** total | up from today's 3.2% |

Closes most of the gap to wasm-opt's 18.9% while staying under 200 ms
total wall time on the corpus (vs. wasm-opt's 6.9 s).

---

## Build order and milestones

Each milestone is independently shippable, independently revertable,
independently measurable. Numbers in parentheses are LOC estimates.

### M1: hints surface (~50 LOC, 1 day)

- Define `LinkerHints` trait with default impls.
- Add `optimise_with_hints` entry point that threads `Option<&dyn LinkerHints>`
  through `optimise_once`.
- All existing passes receive `_: Option<&dyn LinkerHints>` and ignore it.
- One smoke test: a fixture passes a mock hints impl that asserts every method
  is callable.
- **Measurement:** corpus byte-savings unchanged from today (proves additive).

### M2: `dae_v2` (~300 LOC, 2–3 days)

- New pass `passes::dae_v2`, used only when hints are present (else falls
  back to existing `dae`).
- With closed-world hints, drops these guards: "no other function uses this
  type", "ref.func target check" (now done by `is_internal`).
- Removes ALL dead params, not just trailing tail params.
- **Measurement:** standalone corpus unchanged. With a synthetic mock hints
  impl asserting `is_internal=true` for everything, expect bytes-saved to
  exceed today's `dae` by 2–4×.

### M3: per-body IR (`wilt::ir::body`) (~400 LOC, 3–4 days)

- `BodyIr` builder using `InstrIter` once.
- `MutModule` grows a `body_ir_cache: Vec<Option<BodyIr<'a>>>` zeroed on
  every `set_body`.
- API: `m.body_ir(i)` returns `&BodyIr<'a>`, building on first call.
- **Measurement:** corpus byte-savings unchanged. Wall time should drop
  slightly (passes within a fixpoint iter share decode work).

### M4: port `simplify_locals` to IR + use-def (~300 LOC, 3 days)

- New pass `passes::simplify_locals_v2` using CFG + reaching-defs.
- Handles dead-stores across basic blocks within a function.
- Handles `local.set X; <stuff with no effect on X>; local.set X` (current
  pass bails on the `<stuff>`).
- **Measurement:** expect text corpus +5–10% bytes-saved over current
  `simplify_locals`.

### M5: CFG layer (`wilt::ir::cfg`) (~500 LOC, 4–5 days)

- `BasicBlock` + `CfgIr` types built on `BodyIr`.
- Tested standalone via unit tests on small bodies.
- **Measurement:** no behaviour change yet; passes still use linear scan.

### M6: `inliner_v2` (~600 LOC, 1 week)

- New pass replacing `inline_trivial` (kept as fallback when no hints).
- Uses `call_count(f) == Some(1)` to inline single-call-site callees of any
  size.
- Local renumbering: shift caller's locals up by callee's local count;
  callee's local 0..N-1 become caller's pre-set locals from pushed args.
- Handles `return` in callee → `br L` to inline boundary.
- **Measurement:** expect 5–15% additional bytes-saved on corpus that uses
  small static helpers.

### M7: `devirt_call_indirect` (~400 LOC, 4 days)

- New pass requiring both IR and hints.
- For each `call_indirect (type T)` whose `table_targets` reports 1 entry:
  rewrite to `drop` (table idx) + `call F`.
- For 2 entries: `block; if cond ...; call F1; else; call F2; end`.
- For >2: pass; could escalate to `br_table` over calls but defer.
- **Measurement:** new territory; baseline against wasm-opt's `--directize`.

### M8 (stretch): `dead_globals` + `cfg_dce` + `branch_threading` (~400 LOC each)

Standard textbook algorithms once IR + CFG + hints are in place.

## What success looks like

After M2 (hints + dae_v2): wilt-standalone unchanged, wilt-with-wild
shows measurable improvement on a synthetic test.

After M4 (simplify_locals_v2): wilt-standalone improves on text corpus.

After M7 (full integration): wilt-with-wild captures **30–40%** of
wasm-opt's savings (vs. today's 17%) while still running ~50× faster.
Standalone wilt captures **20–25%** vs. today's 17%.

If we hit those numbers, the integration is justified. If not, the IR
work was overpriced and we revert to peepholes.

## Risks and non-goals

**Risks:**

- IR memory cost — `Vec<Instr>` per body is ~16 B/instr; a 100k-instr body
  takes 1.6 MB. Acceptable for typical wasm; pathological for fuzzer input.
  Mitigation: cap body size for IR construction; fall back to byte-patch.
- Cache invalidation — `set_body` must zero IR cache for that body. Easy
  to forget. Mitigation: enforce via `MutModule` API (single mutation
  point).
- `LinkerHints` API churn — adding methods is non-breaking via defaults,
  but renaming or changing semantics is. Stabilise the trait shape only
  after M2 ships in real use.
- Standalone wilt becoming the second-class citizen — every new pass must
  document its standalone-vs-with-hints behaviour and have tests for both.

**Non-goals:**

- Becoming wasm-opt. We'll never match it; we don't need to.
- Multi-module wasm linking from third-party `.wasm` (Wagner-objection
  applies; wild handles linking from `.o.wasm`).
- Profile-guided optimisation. wild doesn't do PGO today; wait.
- Custom IR exposed as a public crate. Stay private until a third-party
  consumer asks.

## Measurement contract

Each milestone reports, on the full binaryen corpus:

- wall time (debug + release)
- bytes saved
- modify rate
- regression vs. previous milestone (must not exceed 0)
- harness: zero panics / validation / shape / growth — non-negotiable

A milestone that doesn't pay off in size or speed is reverted, not
shipped behind a flag. Code rot is more expensive than re-derivation.

## Deferred / future work (no commitment, just so it's tracked)

### Layout for compression

Reorder items within each section (functions, data segments, type
entries) so that adjacent items share more bytes. The result is a
spec-compliant `.wasm` that compresses (gzip / brotli) noticeably
smaller. Wasm-opt does *call-frequency*-based reordering for cache
locality but doesn't aim at compression; this would be a genuine
asymmetric advantage.

What's needed:

- Compute a "byte-similarity" score per item (n-gram shingle Jaccard
  or SimHash).
- Cluster similar items adjacent (greedy nearest-neighbour suffices).
- Reuse existing index-remapping infrastructure (`dce`, `type_gc`,
  `reorder`) to update all references after reordering.
- Add a compressed-bytes column to the comparison harness (`gzip -9`
  / `brotli -q 11`) so we can measure wins on what matters.
- Guard: only commit a reordering if it's a wire-size win.

Caveats:

- Mild streaming-compile-latency cost on large modules; consider
  keeping the start function + a small "hot" prefix at the front.
- Determinism is essential; pick a stable tie-breaker.

Estimated effort: ~3-5 days. Could plausibly reach 120-130%+ of
wasm-opt's *compressed* size savings (a metric wasm-opt doesn't
target).

### Cross-BB simplify_locals (in progress as a separate task)

Real liveness analysis on the CFG: backward dataflow to compute
per-BB `live_in`/`live_out`, then mark `local.set X` dead when X
is not live at the set's exit. Catches dead stores split by control
flow that the current single-BB pass bails on. Estimate +10-15pp on
the comparison.

### Multi-callsite inliner with cost model

Allow inlining when `call_count > 1` if the body is small enough
that `N × inlined_size` beats `original_size + N × call_overhead`.
Probably +1-2pp.

### Cross-BB const propagation

Extend `const_prop` to track bindings across BB joins (intersection
of incoming bindings). Estimate +0.5-1pp.

### Function merging

Hash function bodies; identical bodies become a single function with
multiple call sites pointing at it. ~150 LOC. Estimate +1-3pp.

## Open questions to settle before M1

- **Hints object lifetime.** Does `optimise_with_hints` take `&H` for the
  whole call, or is hints rebuildable mid-pipeline (e.g., DCE invalidates
  call_count)? Initial answer: borrow for the whole call; passes that
  invalidate must explicitly say so. Revisit at M2.

- **Hints construction in tests.** Define a `wilt::testing::FixedHints`
  struct (already similar to `FixedSigs` in `block_walker`) so every
  pass that consumes hints has a one-liner test fixture.

- **Sequential vs. parallel hints lookup.** rayon workers will all call
  `is_internal` etc. concurrently. Trait must be `Sync`. Wild's impl
  will need to ensure its underlying tables aren't behind a `RefCell`.

- **Interaction with the fixpoint loop.** Hints are computed once per
  `optimise_with_hints` call but the fixpoint iterates inside. After
  passes 1..N have run, hints may be stale (functions removed, types
  changed). Initial answer: hints describe the INPUT. Passes that rely
  on accurate hints should run early in the pipeline, before structural
  changes invalidate them.
