# Wild LTO Plan — FatLTO across ELF / Mach-O / Wasm, parallel, fast

## TL;DR

Wild grows full LTO support across all three platforms it links. The
architecture funnels every backend through a **Gold-plugin-shaped
driver trait** so the linker core has one path; backends wrap the less
expressive APIs (libLTO, subprocess `llc`) up into that common shape.
Optional `llvm` feature links libLLVM in-process for the speed-critical
UnifiedLTO path. GCC LTO keeps working identically — the `llvm` feature
only affects the LLVM lane. Every stage that can be parallelised **is**
parallelised via wild's existing rayon pool, with a persistent bitcode
cache keyed on input + target hashes. The end state: FatLTO-quality
optimisation at ThinLTO-speed build times across ELF, Mach-O, wasm.

## Goals

- FatLTO for ELF, Mach-O, wasm — producing valid, optimised binaries.
- **Fast FatLTO** — saturate all cores, not single-threaded like today.
- Preserve GCC LTO support without regression.
- One linker-core code path for LTO; backends behind a trait.
- Reuse wild's existing pipeline everywhere; LTO produces platform
  objects that enter the same merge / reloc / GC / validate path as
  non-LTO inputs.
- UnifiedLTO (LLVM 16+) as the north star for "fast FatLTO".
- Persistent cache — incremental rebuilds reuse optimised modules.

## Non-goals

- Replacing wilt. Wilt stays wild's post-link wasm optimiser;
  orthogonal to LTO.
- Cross-IR FatLTO (GCC GIMPLE + LLVM bitcode merged into one module).
  Nobody does this; LLD doesn't either.
- Reimplementing the LLVM pass manager in Rust. We use LLVM.
- LTO for platforms wild doesn't link (e.g. PE/COFF).

## Core principles

1. **Bitcode is a pre-normalisation step**. Nothing downstream of input
   classification knows whether a file came from bitcode or was always
   an object. `SymbolDb`, `Resolver`, `merge_inputs`, relocation
   patching, `validate_output`, and wilt are all unchanged.
2. **Gold shape is the common interface** — it's the most expressive of
   the three LTO protocols (Gold plugin, libLTO, subprocess `llc`).
   Backends that are less expressive adapt up by buffering; no
   information is thrown away in the abstraction.
3. **Wild stays in charge**. The driver trait is shaped so the linker
   drives the protocol, not the other way around — even when the
   underlying API (real Gold plugin) is callback-driven.
4. **Parallelism is the default**. Every per-input step runs through
   wild's rayon pool. Drivers that spawn subprocesses do so in parallel.
5. **Additive features**. The `llvm` feature speeds up LLVM LTO paths;
   disabling it never breaks a build that worked before. The `plugins`
   feature stays for platforms/toolchains that need the real plugin ABI.
6. **Rustc-level diagnostics** when LTO can't proceed: name the rlib,
   name the member, point at the workaround.

## Architecture overview

```text
                       ┌─────────────────────────────────────┐
                       │        wild core linker             │
                       │  input_data  ╲                      │
                       │  file_kind    ╲─► classification    │
                       │  symbol_db     ╲   │                │
                       │  resolution     ╲  │                │
                       │  merge_inputs    ╲ │ FileKind::*Ir  │
                       │  reloc patching   ╲│ ↓              │
                       │  validate_output  ─┤                │
                       │  wilt (wasm only)  │                │
                       └────────────────────┴────────────────┘
                                            │
                                            ▼
                       ┌─────────────────────────────────────┐
                       │   LtoDriver<P: Platform> trait      │
                       │   (Gold-plugin-shaped interface)    │
                       └─────────────────────────────────────┘
                            │            │             │
                ┌───────────┴──┐   ┌─────┴───────┐   ┌─┴────────────────┐
                │ ELF drivers  │   │ Mach-O      │   │ Wasm drivers     │
                │ Gcc Gold     │   │ libLTO      │   │ Subprocess llc   │
                │ Llvm Gold    │   │ (dlopen)    │   │ Llvm in-process  │
                │ Llvm in-proc │   │             │   │ (via `llvm` feat)│
                └──────────────┘   └─────────────┘   └──────────────────┘
```

### The `LtoDriver` trait

```rust
pub trait LtoDriver<P: Platform>: Send + Sync {
    /// Gold's onload: driver learns the linker callbacks it can call.
    fn onload(&mut self, linker: &LinkerApi<P>);

    /// Gold's claim_file_hook: driver decides whether to claim a
    /// bitcode input. Non-bitcode inputs are never passed in.
    fn claim_file(
        &mut self,
        input: InputRef<'_>,
        bytes: &[u8],
    ) -> Result<Claim<P>>;

    /// Gold's all_symbols_read_hook: claimed files are now compiled
    /// (possibly with cross-module optimisation) to platform objects.
    /// Called once per link, after every input has been classified.
    /// Implementations SHOULD parallelise internally via rayon.
    fn all_symbols_read(
        &mut self,
        pool: &rayon::ThreadPool,
    ) -> Result<Vec<P::ObjectFile>>;

    fn cleanup(&mut self);

    /// Invariant check — the dispatcher uses this to refuse routing an
    /// input to the wrong driver (e.g. GCC bitcode to the LLVM driver).
    fn handles(&self, kind: FileKind) -> bool;
}
```

`Claim<P>` carries the symbol list + linkage extracted at claim time,
so the linker's resolver can run without waiting for compilation.

### Compatibility invariant

**Rule**: wild must link any project it links today, regardless of
which optional features are compiled in. Encoded at the dispatcher:

```rust
let driver = pick_driver(file_kind, available_drivers);
assert!(driver.handles(file_kind),
    "driver mismatch for {file_kind:?} — dispatcher bug");
```

Fires loudly in CI if we ever misroute an IR.

## Phases

Each phase ships independently. No phase blocks its successor on
completeness — partial impls land behind feature flags.

### P0 — Diagnostic (DONE)

Shipped in this session. The current error now names the offending rlib
and offers three workarounds.

**Status**: ✅ landed. No further work.

### P1 — `llvm_tools` helper (1 day)

Move `find_llvm_tool` from `wild/tests/lld_wasm_tests.rs` into
`libwild/src/llvm_tools.rs`. Add `$WILD_LLC`, `$WILD_OPT`, `$WILD_LLVM_AR`
env vars. Version-check via `<tool> --version`, warn on skew vs Rust's
bundled LLVM.

**Deliverable**: `libwild::llvm_tools::{find, llc, opt, ar, version_of}`.
**Test**: unit test that `find("llc")` finds a tool on systems with
rustup + `llvm-tools-preview` installed.
**Success**: both test harness and linker call one implementation.

### P2 — Driver trait + refactor existing ELF plugin (3 days)

Introduce `LtoDriver<P>` trait. Refactor
`libwild/src/linker_plugins.rs` → `libwild/src/lto/elf_gold.rs`
implementing the trait. Dispatcher at input-classification time routes
`FileKind::{Llvm,Gcc}Ir` to the appropriate driver.

**Deliverable**: trait + one impl (ELF Gold plugin, existing behaviour,
zero regression).
**Test**: all existing LTO-enabled ELF integration tests pass
unchanged. Add test confirming GCC bitcode routes to the GCC driver
and LLVM bitcode to the LLVM driver.
**Success**: no behaviour change visible externally; code reorg only.

### P3 — Wasm subprocess driver (2 days)

`WasmSubprocessDriver` implements `LtoDriver<Wasm>`. On
`claim_file`, stashes bitcode and parses symbols from the module's
header (either via tiny in-house bitcode-symtab parser or `llvm-nm`
subprocess). On `all_symbols_read`, shells out to `llc -march=wasm32
-filetype=obj -O0` per input via rayon. Lowered objects feed the
existing wasm merge pipeline.

**Deliverable**: midnight-node-runtime links with wild when LTO
bitcode is present in inputs.
**Test**: regression test assembling a synthetic bitcode input + a
wasm object, link, validate.
**Success**: re-run this session's failing midnight-node15 build
without the `-C embed-bitcode=no` workaround; valid wasm output.

### P4 — FatLTO batch mode + `--lto-partitions=N` default (5 days)

Once P3's subprocess plumbing exists, add "combined optimisation"
mode: when driver sees multiple bitcode inputs, invoke
`llvm-link` to merge them, then `opt -passes='default<O3>' -lto-mode=default`
on the merged module, then `llc --lto-partitions=$(nproc)
-filetype=obj` for parallel codegen. One combined object out,
partitioned into N pieces.

**Improvement to existing ELF LTO**: default `--lto-partitions` from
`1` to `rayon::current_num_threads()`. Free codegen speedup for
everyone already using wild + plugins.

**Deliverable**: classic FatLTO, subprocess-based, with parallel
codegen.
**Test**: measured speedup benchmark committed to
`wild/benches/lto-partitions.rs`.
**Success**: >=(nproc / 2)× codegen speedup vs P3's per-input
mode for large link jobs.

### P5 — UnifiedLTO — the real fast-FatLTO (10 days subprocess, +10 in-process)

Split into two sub-phases:

**P5a — UnifiedLTO via subprocess** (10 days):

- Build combined module summary via `opt -thinlto-bc -lto-unified`.
- Parallel per-module optimisation: `opt -passes='thinlto-default<O3>'
  -summary-file=combined.summary` × N in rayon.
- Parallel per-module codegen: `llc` × N in rayon.
- Merge resulting objects.

**P5b — `llvm` feature, in-process libLLVM** (10 days):

**Status**: landed — `libwild/src/lto/wasm_unified_llvm.rs` wires
the FFI via `libloading` (not `llvm-sys`, for LLVM-version
independence and no build-time `llvm-config`).

- Feature `llvm` (off by default) dlopens the system libLLVM at
  runtime. Search order: `$WILD_LLVM_LIB` → well-known OS paths
  (Homebrew on macOS; `/usr/lib*`, `/usr/local/lib` on Linux) →
  dynamic loader default search path.
- In-process impl of the same pipeline as P5a: parse bitcode in a
  thread-local `LLVMContextRef`, run `default<O<N>>` via the new
  pass manager, emit a wasm object to a memory buffer. Wall-clock
  speedup comes from dropping process-spawn + temp-file overhead
  per module — matters because P5a calls `opt` + `llc` thousands of
  times for a large link.
- Gated behind the feature; falls back to P5a automatically when
  libLLVM is unavailable or any module fails to compile in-process.

**Deliverable**: a link built with P5b should match rust-lld's LTO
output in quality, but faster because wild parallelises stages
rust-lld runs serially.
**Test**: binary-compatible output (mod ordering) vs rust-lld on a
small corpus of synthetic test programs. Benchmark against
`rust-lld -flto=fat`.
**Success**: >=2× wall-clock speedup over rust-lld FatLTO on a
multi-core machine for a substrate runtime build.

### P6 — Persistent cache (5 days)

Per-module cache keyed on:

```text
(
    bitcode_content_hash,
    opt_level,
    target_features,
    lto_mode,           // thin | fat | unified
    llvm_version,
    wild_version,
)
```

Cache dir: `$CARGO_TARGET_DIR/wild-lto-cache/` (or
`$XDG_CACHE_HOME/wild/lto/` when invoked outside cargo). Shared across
ELF / Mach-O / wasm drivers — same hash inputs give same hash output
regardless of platform.

**Deliverable**: incremental relink reuses optimised modules for
unchanged inputs.
**Test**: relink benchmark — change one source file, rebuild, measure
LTO time. Should drop by ~((N-1)/N) on an N-module link.
**Success**: interactive rebuild of a substrate runtime with a
one-line edit completes in <30s (vs ~minutes today).

### P7 — Benchmarks + wilt-vs-LTO measurement (3 days)

Answer the unique wasm question empirically: does LTO beat
wilt-only post-link optimisation on substrate runtime? Bench harness:

- Link the partner-chains-demo-runtime four ways: (a) wild no LTO +
  wilt, (b) wild + L1 lowering + wilt, (c) wild + P4 FatLTO + wilt,
  (d) wild + P5 UnifiedLTO + wilt.
- Measure: final `.compact.compressed.wasm` size, runtime performance
  on a known benchmark (e.g. Plasm runtime bench), link wall-clock.

**Deliverable**: numbers committed to `wild/benches/wasm-lto.md`.
**Success**: informed decision on whether wasm users should default
to LTO or to wilt-only. If wilt-only wins, document that; if LTO
wins, enable by default.

### P8 — Mach-O driver (5 days)

`MachOLibLtoDriver` implements `LtoDriver<MachO>`. Uses `libLTO.dylib`
(the macOS-provided API) via libloading. Same Gold-shape adapter
pattern as wasm subprocess driver, but the transport is
in-process dlopen'd libLTO rather than a subprocess.

Already has precedent: wild's `macho-lto` feature is the existing
scaffold — we're filling it in.

**Deliverable**: Mach-O LTO works end-to-end on macOS.
**Test**: regression test linking an LTO-compiled C program for
aarch64-apple-darwin.
**Success**: produces a valid executable that runs.

## Parallelism map

Where the cores get used, by phase:

| Phase | Parallel units | Serial bottleneck |
|---|---|---|
| P3 | per-input `llc` | None |
| P4 | per-partition `llc` | `opt` on merged module |
| P5a | per-module `opt` + per-module `llc` | Combined summary build (fast) |
| P5b | per-module in-process opt + codegen | Combined summary build |

P5b is where wild beats rust-lld: rust-lld's LTO pipeline runs `opt`
serially on the merged module. UnifiedLTO flips that to per-module
parallel optimisation with combined-summary analysis, and wild's
natural rayon architecture lets every module run on its own core.

## File layout

```text
libwild/
  src/
    llvm_tools.rs         # P1: find/version/spawn LLVM tools
    lto/
      mod.rs              # P2: LtoDriver trait + dispatcher
      elf_gold.rs         # P2: existing linker_plugins.rs moved here
      wasm_subprocess.rs  # P3, P4
      wasm_unified.rs     # P5a (subprocess) + P5b (in-proc, #[cfg])
      macho_liblto.rs     # P8
      cache.rs            # P6
    file_kind.rs          # unchanged — already classifies LlvmIr/GccIr
```

Platform-specific writer code (`wasm_writer.rs`, `elf_writer.rs`,
`macho_writer.rs`) is untouched — LTO outputs platform objects that
enter those writers exactly as non-LTO objects do.

## Feature flags

| Flag | Default | Effect |
|---|---|---|
| `plugins` | off | ELF Gold plugin support (dlopen Gold plugins). Required for GCC LTO. |
| `macho-lto` | off | Mach-O libLTO support. Required for Mach-O LTO. |
| `llvm` | off | In-process libLLVM. P5b path. Implies `plugins` where it speeds up ELF LLVM LTO. |

No default changes in this plan — everyone opts into LTO. Post-P7
benchmark may change defaults for specific platforms.

## Compatibility rules (encoded as tests)

- Every test in `wild/tests/` passing today must still pass at every
  phase boundary.
- GCC LTO tests specifically: `lld_elf_tests.rs` cases involving
  `.gnu.lto_*` sections must continue to pass regardless of which
  LLVM features are built in.
- Dispatcher mismatch → loud panic in debug, error in release. No
  silent misrouting.

## Open questions (deferred)

- **In-process LLVM build size**: adding libLLVM to wild's binary
  pushes it from ~20 MB to ~200+ MB. Mitigation: gate strictly behind
  `llvm` feature, package a slim variant without it.
- **LLVM version skew**: which LLVM version does wild build against
  when the user's Rust toolchain may ship a different one? Options:
  (1) match rustup's toolchain version, (2) pin to latest stable LLVM.
  P5b design choice.
- **ThinLTO distributed mode**: LLVM supports distributed ThinLTO
  (build systems farm out per-module jobs). Worth it for wild?
  Probably not v1 — wait for users to ask.
- **Cross-language LTO**: Rust + C LTO'd together (both LLVM). Works
  in principle if both use compatible LLVM versions. Needs a test.
- **DWARF across LTO**: combined debug info generation. Rust-lld has
  complicated logic here; wild inherits the same complexity.
  Document as a P7-measured risk.

## Timeline

| Phase | Days | Cumulative |
|---|---|---|
| P0 | done | 0 |
| P1 | 1 | 1 |
| P2 | 3 | 4 |
| P3 | 2 | 6 |
| P4 | 5 | 11 |
| P5a | 10 | 21 |
| P5b | 10 | 31 |
| P6 | 5 | 36 |
| P7 | 3 | 39 |
| P8 | 5 | 44 |

~9 working weeks for the full plan. First usable milestone is **P3**
(midnight-node15 unblocked) at ~6 days. Real performance win arrives
at **P5** (~4 weeks). Parity with rust-lld is at **P5b** (~6 weeks).

## Success criteria for the whole plan

1. Every substrate runtime that builds with rust-lld also builds with
   wild, at any LTO level.
2. FatLTO wall-clock link time is faster on wild than on rust-lld, on
   multi-core machines.
3. GCC LTO users see no regressions.
4. Mach-O LTO works.
5. One LtoDriver trait, one dispatcher, one bitcode cache — shared
   across all three platforms.
6. Each phase's commit passes its own regression test + every prior
   phase's regression tests.

## Let's go

Start with **P1** — promote `find_llvm_tool` to a library, add env
overrides, version-check. Cheap, unblocks everything after it.
