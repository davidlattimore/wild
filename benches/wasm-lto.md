# Wasm LTO benchmarks (P7)

The plan's P7 question: **for a substrate runtime, is post-link
`wilt` enough on its own, or does invoking LLVM LTO buy meaningful
size / runtime / link-time wins?**

This file records the methodology, current numbers, and the
decision-relevant tradeoffs. Numbers are partial — see "Status"
below.

## Methodology

Bench harness: `wild/benches/wasm-lto-bench.sh`. Builds
`partner-chains-demo-runtime` (a representative Substrate runtime
with ~450 input objects) under several configurations, recording:

- wall-clock link time (the `cargo build -p
  partner-chains-demo-runtime --release` invocation, seeded by a
  warm host-side cache so we measure the wasm link, not the
  Rust-side build)
- raw `.wasm` size (the linker's own output, before any post-link
  processing)
- `.compact.wasm` size (after substrate-wasm-builder's
  `wasm-opt` pass)
- `.compact.compressed.wasm` size (zstd, on-chain shipping form)

Each config blanks the wasm artefacts and `touch`es `build.rs` to
force a relink — the host-side compile cache stays warm so we
measure linker work, not rustc work.

### Configurations

The plan's four LTO variants:

| # | Config                       | Wired today? |
| - | ---------------------------- | ------------ |
| a | wild + wilt                  | yes          |
| b | wild + L1 lowering + wilt    | yes (P3)\*   |
| c | wild + P4 batch FatLTO + wilt| API only     |
| d | wild + P5 UnifiedLTO + wilt  | API only     |

\* L1 only kicks in when bitcode inputs are present. Partner-chains
emits no bitcode under its default profile (verified by inspecting
`.rcgu.o` magic bytes — all `\0asm`), so (a) and (b) produce the
same numbers for this workload. midnight-node15 is the workload
that exercises (b) for real (one rlib member is `BC\xC0\xDE`).

(c) and (d) ship as library APIs but aren't wired into the main
link path yet — that's P5/P6 follow-up. They aren't measured here.

### Reference baseline

Compared against `rust-lld` (the bundled `wasm-ld` from
`llvm-tools-preview`), which is the linker partner-chains and most
substrate workspaces ship with today.

## Numbers (partial — see Status)

Hardware: Apple M-series, single warm filesystem cache between runs.

| Config                            | Wall    | raw.wasm     | .compact.wasm | .compressed |
| --------------------------------- | ------- | ------------ | ------------- | ----------- |
| rust-lld baseline                 |   23 s  | 3 611 222    | 3 451 393     | 697 777     |
| wild −O0 (raw, no wilt)           | TBD     | TBD          | TBD           | TBD         |
| wild −O1 (wilt basic)             | TBD     | TBD          | TBD           | TBD         |
| wild −O3 (wilt + strip, default)  | TBD     | TBD          | TBD           | TBD         |

Anchor numbers we saw earlier in development (informal — not from
this controlled bench):

- wild −O0: ≈ 3.66 MB raw, full pipeline succeeds, 18-25 s link.
- wild −O3 (default): ≈ 3.10 MB raw, ≈ 689 KB compressed.

Both are within a few percent of rust-lld's compressed output
(697 KB), with wild −O3 actually slightly smaller — wilt's
post-link DCE + type-GC + custom-section strip closes most of the
gap to rust-lld + wasm-opt.

## Status

**Not finalised.** During the bench run, the `wild −O0` config
hung on substrate-wasm-builder's target-feature probe (a tiny
dummy-crate compile that exercises the linker before the real
link). Wild's process sat in `S` state with 0 CPU — stdin or
file-lock wait — and never exited. The `set -e` in the harness
caught the resulting empty `stat` output, but the outer `tee`
masked the non-zero exit and the task reported success.

Sources for this hang to investigate:

1. Substrate-wasm-builder's target-feature probe spawned **two**
   identical `wasm-ld` invocations on the same dummy crate at the
   same second. Either substrate's probe genuinely runs two passes
   (e.g. one per candidate feature), or one is a child of the
   other. Either way, both got stuck.
2. Earlier in the same session, partner-chains built fine under
   wild — so the hang is conditional on something this session
   accumulated (probably zombie wasm-ld procs from killed test
   runs holding a lock).
3. The bench harness needs `pipefail` outside the script's tee, or
   the stat-failure to propagate as a non-zero exit, so a future
   hang surfaces as a failed task rather than a half-empty report.

These are tractable but separate concerns. Next session, with a
clean process table and the harness hardened, the table fills in.

## Decision (preliminary)

Even with only one reference data point and the informal
development-time numbers, the picture is:

- **wilt-only (wild −O3) is within ~0–2 % of rust-lld + wasm-opt**
  on final compressed size for this workload.
- **LTO would have to beat that gap to be worth the infrastructure
  cost** of wiring P4/P5 into the main pipeline + maintaining the
  subprocess + libLLVM paths.
- **For substrate runtimes specifically**, wilt's post-link passes
  (DCE, type-GC, custom-section strip) capture most of what cross-
  module LTO would deliver, because wasm bytecode is high-level
  enough that whole-program analysis post-link recovers cross-
  module inlining opportunities. This matches the prediction in
  `wild-lto-plan.md`.
- **For bitcode-only inputs** (midnight-node15's federated-authority
  rlib) the L1 path is required for the link to even succeed, so
  wiring (b) end-to-end is necessary regardless of the
  optimisation tradeoff.

Once the full table lands, the recommendation will be one of:

- **If wild −O3 stays within ~3 % of rust-lld**: ship wilt-only as
  the default, document LTO as opt-in, defer P5b in-process LLVM.
- **If LTO buys ≥10 % on either size or runtime**: prioritise
  wiring P4 into the main link path, then P5b.

Either way, P3 (L1 lowering) ships as default-on because it's
necessary for bitcode-input correctness, not just performance.

## Re-running

```bash
WILD=/tmp/wild-wasm-shim/wasm-ld \
PC=~/git/midnightntwrk/partner-chains \
RUST_LLD=$(find ~/.rustup/toolchains -name rust-lld -path '*/aarch64*' | head -1) \
bash benches/wasm-lto-bench.sh
```

Before running:

- `ps aux | grep -E "wild|wasm-ld|wilt"` — confirm no zombies from
  prior sessions.
- `pkill -9 -f wasm-ld` if any are present.
- Quiesce other workloads — bench is CPU-bound for wall-clock
  measurements.
