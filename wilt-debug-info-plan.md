<!-- markdownlint-disable MD013 MD033 -->

# wilt — accurate debug info — Rust-style tiered rewriting

Status: **planned, not yet implemented**. Approved 2026-04-14.

## Context

wilt's passes currently leave `.debug_*`, `name`, and any external
source-map references silently stale after modifying code. Validators
accept the output but debuggers land on the wrong code; stack traces
show wrong function names. Same silent-corruption class of bug that
`wasm-opt -O` has — and we committed in the README (see
`wilt/README.md`) to do better.

Rust's `--release` has a clear contract at three `debuginfo` levels
(none / line-tables / full). wilt will offer the same, with the added
requirement that we stay **honest** — never emit references to stale
external data silently. Output is one self-consistent wasm file.

Guiding principle agreed in planning: **correctness first**. Edit-list
provenance is tractable (~10-15 % wall clock, ~10 MB memory on the
1.9 MB test binary) and gives us exact answers; we will not compromise
with coarse stubbing.

## Decisions (locked)

- Default tier: **full**; falls back to highest implemented until
  Phase 3 lands (so after Phase 2, default = `lines`).
- Scope of this plan: **Phase 1 (names) + Phase 2 (lines) +
  external source-map rewrite**. `full` (rewriting
  `.debug_info` / `.debug_str` / …) lives in a future plan.
- Byte provenance: **edit lists** at body granularity.
- Dependencies: **gimli** for DWARF; **DIY** for wasm `name` section
  and source-map V3. Runtime deps become `rayon` + `gimli`.
- Phase 2 ships as **two commits**: (a) edit-list plumbing across
  passes with DWARF still stubbed, (b) real DWARF rewrite via gimli.

## The four tiers

| Level    | Contents                                        | Rust analogue                        |
| -------- | ----------------------------------------------- | ------------------------------------ |
| `none`   | Strip everything                                | `-C debuginfo=0`                     |
| `names`  | Rewrite `name` section                          | (subset of line-tables)              |
| `lines`  | names + rewrite `.debug_line`                   | `-C debuginfo=line-tables-only`      |
| `full`   | lines + `.debug_info` + `.debug_str` + …        | `-C debuginfo=full`                  |

CLI: `--debug=<level>` plus `-g0/-g1/-g2/-g3` aliases for wasm-opt
muscle memory.

## Byte-provenance — edit-list approach

Per-body edit list. Each edit is a 16-byte record:

```rust
struct Edit {
    in_start: u32, in_len: u32,
    out_start: u32, out_len: u32,
}
struct BodyEdits {
    edits: Vec<Edit>,            // sorted by out_start
    src_funcs: Vec<Option<u32>>, // parallel; Some for inline splices
}
```

Semantics:

- `in_len == 0`: synthesised bytes (e.g. inline splice, drops spliced
  in by `pure_call_elim`).
- `out_len == 0`: deleted region.
- `src_funcs[i] == Some(f)`: this edit's output span came from input
  function `f` (not the body this `BodyEdits` belongs to) — lets the
  DWARF rewriter chase debug sequences from the callee into the
  caller's new code.

**Composition:** `compose(a, b)` merge-walks both sorted lists in
O(|a| + |b|). Done once at pipeline end — not per pass — so we pay
it linearly in the total final edit count, not quadratically.

**Per-pass overhead:** passes emit `Option<BodyEdits>` per body.
`None` means identity (no allocation, no work). `MutModule`'s COW
already knows which bodies a pass left alone — those get `None`
automatically. On real corpora ~90 % of bodies are untouched by ~90
% of passes.

**Cost estimate on the 1.9 MB test binary:**

| Approach                    | Extra CPU       | Extra memory |
| --------------------------- | --------------- | ------------ |
| Per-byte map                | +600-900 ms     | +100 MB      |
| Per-instruction map         | +300-500 ms     | +25 MB       |
| **Edit-list (chosen)**      | **+150-250 ms** | **+10 MB**   |
| Coarse region-level (stub)  | +20-40 ms       | +100 KB      |

~10-15 % wall-clock for full accuracy. Fully acceptable given wilt is
already 2× faster than wasm-opt.

## Dependencies

**Add:** `gimli = { version = "*", default-features = false, features = ["read", "write"] }`.
Apache-2.0/MIT. Rust compiler team. Used by addr2line, object,
backtrace, rustc itself — the blessed Rust DWARF library.

**DIY (keeps the rest of the zero-runtime-dep discipline):**

- Wasm `name` section parser/rewriter — ~150 LOC. Trivial format
  (three subsection types: module, function, local).
- Source-map V3 parser/rewriter — ~200 LOC. JSON + VLQ-encoded
  mappings.

## Architecture

### New modules

| File                                      | Purpose                              |
| ----------------------------------------- | ------------------------------------ |
| `wilt/src/remap.rs`                       | `FuncRemap`, `LocalRemap`, compose   |
| `wilt/src/provenance.rs`                  | `Edit`, `BodyEdits`, compose         |
| `wilt/src/debug_level.rs`                 | `DebugLevel` enum, entry wiring      |
| `wilt/src/passes/name_section.rs`         | Parse / rewrite / emit (DIY)         |
| `wilt/src/passes/dwarf_line.rs`           | gimli-backed `.debug_line` rewriter  |
| `wilt/src/passes/source_map.rs`           | V3 parse / rewrite (DIY)             |

### Central type

```rust
pub struct ModuleProvenance {
    pub funcs: FuncRemap,
    pub locals: LocalRemap,
    pub bodies: Vec<Option<BodyEdits>>,  // indexed by output body idx
    pub code_offsets: Vec<u32>,           // per output body, byte
                                          // offset into output code
                                          // section
}
```

### Pass signature changes — three categories

1. **Index-rewriting only** (`dedup`, `dedup_imports`, `dce`,
   `fn_merge`, `reorder`, `layout_for_compression`): now return
   `(Vec<u8>, FuncRemap)`.
2. **Body-rewriting** (`vacuum`, `const_fold`, `const_prop`,
   `copy_prop`, `branch_threading`, `if_fold`, `cfg_dce`,
   `remove_unused_brs`, `merge_blocks`, `simplify_locals`,
   `pure_call_elim`, `reorder_locals`): add
   `Vec<Option<BodyEdits>>` to return.
3. **Both** (`inline_trivial`, `dae`): add both.

`MutModule` gains `set_body_with_edits(idx, bytes, edits)`.

### Pipeline composition

`lib.rs`'s fixpoint accumulates `ModuleProvenance` across iterations.
After each `optimise_once`, the new provenance composes with the
running total. End of fixpoint: one combined `ModuleProvenance` for
input → final_output.

## Implementation phases

### Phase 1 — names tier — ~300 LOC — one commit

1. `remap.rs`: FuncRemap + LocalRemap + composition + proptest
   associativity.
2. Pass signature updates for category 1.
3. `passes/name_section.rs`: parse / rewrite / emit (DIY). Handles
   subsections 0 (module name), 1 (function names), 2 (local names).
4. `lib.rs`: compose FuncRemap across fixpoint iterations; new entry
   point `optimise_with_debug_level(input, level) -> Vec<u8>`.
5. `strip.rs`: `DebugLevel`-aware.
6. CLI `--debug=<level>` + `-g0..-g3` aliases.
7. Tests: named function survives dedup / reorder; merged funcs keep
   canonical name; eliminated entries drop cleanly.

### Phase 2a — edit-list plumbing — ~500 LOC — first of two commits

1. `provenance.rs`: Edit, BodyEdits, composition + proptest.
2. Signature updates for categories 2 and 3 (12+ passes). Each
   body-rewriting pass builds its BodyEdits at rewrite sites during
   the existing gather-then-apply phase.
3. `lib.rs`: compose provenance through fixpoint.
4. DWARF at this point: still stubbed — `--debug=lines` behaves as
   `names` until Phase 2b. Names tier fully works.
5. Tests: proptest that `apply(compose(A, B), bytes)` ==
   `apply(B, apply(A, bytes))` over random edit sequences.

### Phase 2b — DWARF rewrite — ~400 LOC + gimli — second of two commits

1. `passes/dwarf_line.rs`: gimli reads input line program; applies
   `ModuleProvenance` (funcs + body edits + code offsets); gimli
   writes new line program.
2. `code_offsets` computation in reorder / layout / final emit.
3. Integration: compile a small Rust program with `-C debuginfo=1`;
   run wilt at `--debug=lines`; dump DWARF via `wasm-tools print`
   or `llvm-dwarfdump`; verify correct source lines on live,
   unmodified bodies and reasonable locations on modified ones.
4. Perf regression test: corpus benchmark confirms < 25 % overhead.

### External source map — ~400 LOC — one commit

1. `passes/source_map.rs`: V3 parse + rewrite. VLQ decode, rewrite
   mappings array using same ModuleProvenance, re-encode.
2. CLI `--source-map-in <path> --source-map-out <path>`.
3. Warn-and-strip when input has `sourceMappingURL` but user did
   not supply `--source-map-in/out`. No silent staleness.
4. `external_debug_info` (DWARF package file pattern): stubbed for
   now — activate when a real user needs it.

## Performance budget

Current: ~1,700 ms on 1.9 MB test binary.

| Target             | Budget      | Notes                            |
| ------------------ | ----------- | -------------------------------- |
| `--debug=none`     | ≤ 1,750 ms  | drops customs; no tracking       |
| `--debug=names`    | ≤ 1,800 ms  | FuncRemap compose + name rewrite |
| `--debug=lines`    | ≤ 2,100 ms  | edit lists + gimli emit          |
| `--debug=full`     | — (future)  | Phase 3                          |

Fallback knobs if we overshoot: arena allocator for edits, more
aggressive skip-unchanged detection, per-body parallel compose.

## Verification strategy

- **Unit**: FuncRemap + BodyEdits composition associativity
  (proptest — already a dev-dep).
- **Unit**: name-section parse → emit round-trip.
- **Unit**: DWARF `.debug_line` round-trip via gimli on an LLVM-
  emitted sample.
- **Integration**: named function resolvable after full pipeline.
- **Integration**: real Rust binary's crash line resolves to the
  correct source line on wilt-optimised output.
- **Integration**: `.wasm.map` round-trip preserves browser source
  lookup.
- **Integration property**: for any edit-list pair (A, B),
  `apply(compose(A,B), bytes)` == `apply(B, apply(A, bytes))`.
- **Perf**: corpus benchmark confirms < 25 % overhead at `lines`.
- **Determinism**: existing `tests/determinism.rs` extended to cover
  provenance output.

## Files to change

**New:**

- `wilt/src/{remap, provenance, debug_level}.rs`
- `wilt/src/passes/{name_section, dwarf_line, source_map}.rs`
- `wilt/tests/{debug_levels, debug_source_map, debug_provenance}.rs`
- `wilt/tests/fixtures/debug_rust_tiny.wasm` (generated, checked in)

**Modified:**

- 12+ body-rewriting passes under `wilt/src/passes/`
- `wilt/src/mut_module.rs` — expose edits
- `wilt/src/lib.rs` — new entry points, compose provenance
- `wilt/src/bin/wilt.rs` — `--debug`, `--source-map-in/out`
- `wilt/src/passes/strip.rs` — tier-aware
- `wilt/README.md` — replace current "debug info invalidated"
  warning with the new tiered contract
- `wilt/Cargo.toml` — add `gimli`

## Open risks

1. **DWARF v5**. LLVM wasm emits v4 today but v5 is growing. gimli
   handles both; test early.
2. **Inline wrap blocks**. `inline_trivial`'s `block ... end` wrap
   around an inlined body needs a source location for its synthetic
   instructions. Policy: reuse the call site's line.
3. **Edit-list correctness**. The main bug surface. Proptest is the
   first line of defence; a sample-corpus integration test is the
   second.
4. **Fixpoint remap blowup**. Composition depth can be 10-40
   iterations; edit-list memory grows linearly in iteration count.
   Mitigate by compressing adjacent identity edits inside `compose`.

## Session breakdown

| Session | Deliverable                                   | LOC  |
| ------- | --------------------------------------------- | ---- |
| 1       | Phase 1 (names)                               | ~300 |
| 2       | Phase 2a (edit-list plumbing, stub DWARF)     | ~500 |
| 3       | Phase 2b (gimli DWARF rewrite)                | ~400 |
| 4       | External source-map rewrite                   | ~400 |

Each phase leaves the project shipping-ready. Strictly additive; we
can stop at any phase boundary and the previous work stands.
