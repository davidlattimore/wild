# wilt — WebAssembly In Link Time

Zero-copy WebAssembly optimiser. Parses WASM binary format directly using
memory-mapped input, only allocating for modified function bodies. Built
to run inline with a linker (wild's wasm front-end) and also usable
standalone.

## Status

- ~20 optimisation passes (const folding, const/copy propagation,
  CFG-aware dead-code, function dedup / merge / inline, block/branch
  peepholes, local renumbering, memory packing, compression layout,
  more).
- Roughly **2×** faster than `wasm-opt -O` on the binaries we've tested.
- On **real compiled wasm** (post-linker output): beats `wasm-opt -O`
  raw-bytes-saved on every binary we've measured, at 2× the speed.
- On the binaryen synthetic test corpus: 21% of wasm-opt's raw savings,
  28% of its gzip savings — dominated by custom-section policy (see
  [Debug info](#debug-info-is-invalidated--important) below).

## Usage

### Library

```rust
let input: Vec<u8> = std::fs::read("app.wasm")?;
let optimised = wilt::optimise(&input);           // preserves customs
let small = wilt::optimise_stripped(&input);      // + drops debug/name/target_features
```

Optionally pass `LinkerHints` to unlock closed-world passes (dead-arg
elimination, devirtualisation, dead-global elimination, etc.):

```rust
let hints = wilt::linker_hints::DerivedHints::from_bytes(&input).unwrap();
let out = wilt::optimise_with_hints(&input, &hints);
```

### CLI (drop-in for most `wasm-opt` usage)

```bash
wilt app.wasm -O3 -o app.opt.wasm
wilt app.wasm -O --strip-debug -o app.opt.wasm
wilt app.wasm --strip -v                 # shipping build (drops name + debug)
wilt app.wasm --print > out.wasm         # to stdout
```

Accepts `-O / -O0..-O4 / -Os / -Oz / -o / --output / --strip / --strip-debug /
--strip-producers / --print / -v / --enable-* / --disable-* / --pass-* / -g`.
Unknown wasm-opt-shaped flags (`--enable-X`, `--disable-X`, `--pass-X`,
`--no-X`, `--features X`) are silently accepted.

### In-linker (wild)

Wild links wasm and runs wilt inline when invoked with `-O<N>`:

```bash
wild --target wasm32 -O1 ...               # enable wilt
wild --target wasm32 -O1 --strip-debug ... # drop DWARF, keep names
wild --target wasm32 -O1 --strip-all ...   # drop names + DWARF
wild --target wasm32 ...                   # -O0: no wilt, wasm-ld compatible
```

Wilt is enabled by default (Cargo feature `wilt` in `libwild`); turn
off with `--no-default-features`. The optional `wasm-opt` feature
additionally LEB-compresses relocation payloads under
`--compress-relocations`.

## Debug info is invalidated — important

**wilt's `optimise()` does not keep DWARF, source maps, or the `name`
section consistent with the code it produces.** Our passes modify the
code section (inline, dedup, reorder, renumber locals, merge blocks,
pack memory, …) without rewriting the debug / name sections that
reference those indices and byte offsets. The customs survive
structurally — a validator accepts the output — but they point at the
wrong code. Set a breakpoint in the optimised output and you'll land
on the wrong source line; crash traces will attribute errors to the
wrong function names.

This is the **same position `wasm-opt` is in**. wasm-opt's solution is:

- `wasm-opt -O` (default): **silently discards `name` and replaces
  `.debug_line` with a minimal-valid stub.** Your debug info is gone
  even though you didn't ask for it to be gone.
- `wasm-opt -O -g` (preserve debug): **refuses to do most
  optimisations** — on the binaryen corpus, wasm-opt `-O -g` actually
  *grew* the output by 4 KB.

wilt's policy is explicit rather than implicit:

- **`optimise_stripped()` / `wilt --strip`** — removes `.debug_*`,
  source maps, `name`, and `target_features`. This is the correct,
  shippable-binary mode. Matches what wasm-opt `-O` does without
  advertising it.
- **`optimise()` / `wilt` without `--strip`** — preserves all custom
  sections *as bytes*, but those bytes are stale after we modify the
  code. **Do not rely on debug info from `optimise()`'s output.**

### Planned follow-up

A proper fix needs one of:

1. An opt-in "keep DWARF accurate" mode that disables code-modifying
   passes (equivalent to `wasm-opt -O -g` — costs most of the savings).
2. A DWARF line-program rewriter that updates offsets + index
   references to match the new code. Non-trivial but tractable.
3. An `external_debug_info` sidecar file: the main `.wasm` ships
   stripped, with a custom section pointing to a companion `.debug.wasm`
   containing the *original* debug sections. Preserves debugging for
   workflows that accept "debug points at pre-optimisation code".

Option 3 is on the roadmap. For now, use `--strip` for shipping and
assume debug info is gone.

## Architecture (brief)

`WasmModule` borrows from the input buffer and records section
boundaries without copying. Passes scan raw bytes (e.g. for `call`
opcodes), produce patches, and the emitter splices them in. The
middle of the pipeline uses a shared `MutModule` so body-modifying
passes can compose without reparsing.

The pipeline runs to a fixpoint (up to 40 iterations; usually
converges in 3–6). Each iteration can unlock later passes — dedup
removes duplicates → DCE cleans up → type_gc sheds unused types →
layout_for_compression orders bodies so gzip catches back-references.

All passes are deterministic. Output is byte-identical across
repeated calls and rayon thread counts — see `tests/determinism.rs`.

## Non-goals

- **Source-level debugging fidelity** on optimised output — see above.
- **Matching every wasm proposal.** GC, typed function refs, EH, and
  exotic SIMD sub-opcodes cause passes to bail defensively; output is
  still valid, just less optimised for those modules.
- **Drop-in for `wasm-opt`'s non-optimisation modes** (validators,
  printers, metadce, etc.). wilt is scoped to size reduction.

## License

Same as the parent workspace (Apache-2.0 OR MIT).
