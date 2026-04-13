<!-- markdownlint-disable MD013 MD032 MD040 MD060 -->
# wilt — Plan B: zero-copy foundation for Group B passes

## Why

Today's `optimise()` does 10 full parse-emit round trips per fixpoint iteration. Each pass allocates `Vec<u8>`s for every function body it touches (modified or not). Opcode walking returns heap-allocated `Vec<(usize, usize)>` per body.

Before adding Group B passes (reorder-locals, simplify-locals, trivial inlining — each of which walks every body), we need to fix the substrate. Otherwise Group B's per-function analysis gets multiplied by the existing allocation overhead.

Target: 5–10× throughput for the current pipeline, with no correctness change. Then Group B sits on a foundation that keeps the promise of "byte-patch + mmap".

## Architectural shift

From:

```
input → parse → pass1 → Vec<u8> → parse → pass2 → Vec<u8> → ... (10×)
```

To:

```
input → MutModule (borrows input) → pass1 → pass2 → ... → serialize() → Vec<u8>
```

Section boundaries don't change across passes — only payloads do. Bodies stay as `&[u8]` into the input mmap unless a pass touched them.

## Components

### 1. Baseline timing probe

Add a test that reports throughput on the text + binary corpus: `ms per MB input`, total wall time. Run once before any refactor so every step has a before/after.

### 2. `MutModule<'a>`

```rust
pub struct MutModule<'a> {
    input: &'a [u8],
    sections: Vec<Section>,                    // computed once at construction
    section_overrides: Vec<Option<Vec<u8>>>,   // None = use input slice
    body_overrides: Vec<Option<Vec<u8>>>,      // lazy, one slot per defined fn
    num_func_imports: Option<u32>,             // cached
    // other facts caches added as needed
}

impl<'a> MutModule<'a> {
    pub fn new(input: &'a [u8]) -> Result<Self, &'static str>;

    // Section access (dispatches to override or input).
    pub fn section_payload(&self, sec_idx: usize) -> &[u8];
    pub fn set_section_payload(&mut self, sec_idx: usize, payload: Vec<u8>);
    pub fn remove_section(&mut self, sec_idx: usize);

    // Body access.
    pub fn num_bodies(&self) -> usize;
    pub fn body_bytes(&self, local_idx: usize) -> &[u8];
    pub fn set_body(&mut self, local_idx: usize, bytes: Vec<u8>);

    // Serialise everything into a final Vec<u8>. Consumes the MutModule.
    pub fn serialize(self) -> Vec<u8>;
}
```

Invariants:
- `sections` built once; never mutated after `new()`.
- A pass can mark a section "dead" by `remove_section` — serialize() skips it.
- Bodies are lazy: `body_overrides` starts all `None`; on first `set_body`, the Vec is grown and filled.
- No re-parsing ever.

### 3. Port existing passes to `MutModule`

Incremental. Each pass changes from:

```rust
pub fn apply(module: &WasmModule) -> Vec<u8> { ... }
```

to:

```rust
pub fn apply(module: &mut MutModule) { ... }
```

The pipeline becomes:

```rust
pub fn optimise(input: &[u8]) -> Vec<u8> {
    let Ok(mut m) = MutModule::new(input) else { return input.to_vec() };
    for _ in 0..MAX_FIXPOINT_ITERATIONS {
        let snapshot = m.fingerprint();
        passes::dedup_imports::apply(&mut m);
        passes::dedup::apply(&mut m);
        passes::dce::apply(&mut m);
        // ...
        if m.fingerprint() == snapshot { break; }
    }
    m.serialize()
}
```

`fingerprint()` is a cheap hash of the override set — lets us detect fixpoint without reserialising.

### 4. Iterator walker

Replace `walk(body) -> Option<Vec<(usize, usize)>>` with:

```rust
pub struct InstrIter<'a> {
    body: &'a [u8],
    pos: usize,
    failed: bool,
}

impl<'a> Iterator for InstrIter<'a> {
    type Item = (usize, usize);   // (pos, len)
    fn next(&mut self) -> Option<Self::Item>;
}

impl<'a> InstrIter<'a> {
    pub fn failed(&self) -> bool;  // caller checks after the loop
}
```

Zero heap allocation. For peephole passes that need to look one instruction ahead, either:
- Iterate with a `.peekable()` wrapper, or
- Use a 2-slot ring buffer allocated on the stack.

### 5. `ModuleFacts` cache

Hoist cross-pass analyses into a struct computed once per fixpoint iteration:

```rust
pub struct ModuleFacts {
    pub num_func_imports: u32,
    pub ref_func_targets: HashSet<u32>,
    pub exported_func_indices: Vec<u32>,
    pub start_func: Option<u32>,
    // add as passes demand
}
```

Recomputed each iteration (cheap — one walk), passed by `&` to every pass.

### 6. Reusable scratch buffer

A single `Vec<u8>` owned by `MutModule` that body-rewriting passes borrow, clear, and reuse:

```rust
impl MutModule<'_> {
    pub fn scratch(&mut self) -> &mut Vec<u8>;  // .clear() called first
}
```

## Group B passes after the foundation

Once the foundation is in place, each Group B pass is a small delta — no cross-cutting infra rework:

| pass | LOC | shares |
|---|---|---|
| `reorder_locals` | ~150 | InstrIter + LocalRewriter |
| `remove_unused_brs` | ~200 | InstrIter + BlockWalker |
| `merge_blocks` | ~300 | BlockWalker |
| `simplify_locals` (basic) | ~300 | BlockWalker + reaching-defs-lite |
| trivial inlining | ~500 | CallerCounts (ModuleFacts) + LocalRewriter + body substitution |
| DAE | ~400 | ParamUse scan + all-callers rewriter |

New shared helpers (not in foundation — grow with the passes):

- `BlockWalker` — augments InstrIter with a depth counter + (labeltype, br-targeted?) stack.
- `LocalRewriter` — apply an `old→new` local index map over a body, using scratch.

## Execution correctness harness

Some Group B passes (simplify-locals, inlining) can produce **validating but semantically-wrong** output. The current harness catches validation failures and shape drift; it cannot catch "the module computes the wrong answer."

Add an execution-parity tier:

- Pick modules in the corpus with exported functions that take/return i32/i64/f32/f64.
- Run input and output through `wasmtime` with a fuzz-style input set.
- Compare results.

Separate test target so it's opt-in (requires `wasmtime` as a dev-dep).

## Staging

Each step lands independently with the harness green:

1. **Timing probe** — baseline number on file.
2. **`MutModule` + section-level port** — all passes keep working; body-level still uses old code internally, but sections go through `MutModule`. Remeasure.
3. **Body-level COW** — passes switch to `body_bytes()` / `set_body()`. Remeasure.
4. **Iterator walker + scratch** — port vacuum (hottest). Remeasure.
5. **`ModuleFacts` cache**.
6. **Execution-parity harness**.
7. Then Group B passes one at a time, each with its own correctness proof via execution parity.

Every step reversible. If a step doesn't pay off, skip it.

## Out of scope (Plan B doesn't touch these)

- GC-heavy passes (type-refining, gto, heap2local).
- Control-flow restructuring (flatten, rereloop).
- SIMD / atomics / EH pass coverage.
- A real per-function IR with typed stack tracking. (Simplify-locals approximates what's possible without one.)

## Measurement contract

Each step reports, on the full binaryen corpus:
- wall time (total + per-pass hot path if relevant)
- number of heap allocations (via `dhat` or a counting allocator, opt-in)
- bytes saved (must not regress)
- modify rate (must not regress)
- harness: zero panics / validation / shape / growth — non-negotiable
