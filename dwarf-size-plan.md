# DWARF debug-info size on Rust binaries — research + roadmap

*Last updated 2026-04-23. Driven by midnight-node's 1.32 GB debug build
(of which 1.13 GB is `.debug_*`) and a literature scan of existing
linker / debugger / compiler approaches.*

## TL;DR

Rust's debug info is dominated by **monomorphisation duplication**.
Each generic instantiation re-emits a full DIE tree and a full set of
fully-qualified names into `.debug_str`. Cross-CU dedup is held back
by DWARF's intra-CU reference forms (`DW_FORM_ref4/8`) and by rustc
not emitting type units (`DW_TAG_type_unit` / `DW_FORM_ref_sig8`).

Wild already does the cheap and load-bearing work:
SHF_MERGE on `.debug_str`, CIE dedup in `.eh_frame`, `.sframe`
generation, `--compress-debug-sections=zstd`, Mach-O
`__compact_unwind`. The next 50% of file-size reduction needs either
compiler-side work (type units, DWARF 5 indirection) or
`dsymutil`/`dwz`-class link-time DIE rewriting.

## What rustc emits today (rust 1.94, LLVM 21)

| Property | Status |
|---|---|
| DWARF version | **4** (clang defaults to 5; rustc lags) |
| Type units | **No** — every CU re-emits its own type DIEs |
| `DW_TAG_template_type_parameter` | **No** — generics are fully expanded, no template substrate |
| `DW_FORM_strx` indirection | **No** — DWARF 5 only |
| `.debug_rnglists` / `.debug_loclists` | **No** — DWARF 5 only |
| `-Z split-dwarf=split` (`.dwo`/`.dwp`) | Nightly only; stable equivalent is `-C split-debuginfo=unpacked` (linux) / `=packed` (mac) |
| v0 mangling in `DW_AT_linkage_name` | **Yes** (mostly), with legacy `_Z` for some symbols |
| `-C debuginfo=line-tables-only` | Stable; reduces to ~5× text-size overhead |
| Default `[profile.release]` debug | Off; midnight-node sets `debug = 1` in `.cargo/config.toml` |

## What wild does today

| Improvement | Status |
|---|---|
| SHF_MERGE dedup on `.debug_str` | ✓ via `string_merging.rs` (ELF only — Mach-O has no equivalent flag) |
| `--compress-debug-sections=zstd` | ✓ landed (`elf_compress.rs`) |
| `.eh_frame` CIE deduplication | ✓ via `eh_frame.rs::Cie::eligible_for_deduplication` |
| `.sframe` generation | ✓ via `sframe.rs` — wild leads here, most linkers don't emit it |
| Mach-O `__compact_unwind` → `__unwind_info` | ✓ |
| `--gdb-index` / `.debug_names` emission | ✗ silently ignored |
| `-Zsplit-dwarf` skeleton-CU pass-through | ✗ |
| Cross-CU DIE dedup (`dwz`-class) | ✗ |
| `.debug_abbrev` cross-CU dedup | ✗ |
| `.debug_line` file/dir-table dedup | ✗ |
| Dead-DIE strip under `--gc-sections` | ✗ |

## Measured shape on midnight-node

```text
.debug_info     313 MB    27 %    (DIEs)
.debug_str      579 MB    51 %    (mangled names + paths)
.debug_line     123 MB    11 %    (line programs)
.debug_ranges   108 MB     9 %    (address ranges)
.debug_loc       13 MB     1 %    (location expressions)
.debug_abbrev   1.2 MB    0.1 %   (abbreviation tables)
total          1153 MB   100 %    of which 86 % is debug
```

Recon over `.debug_info` (uncompressed) shows 21,008 CUs, 4.6 M
"interesting" DIEs (types + functions + namespaces), 1.36 M distinct
content hashes. **70 % of interesting DIEs are duplicates of an
already-seen content hash.** Save-potential breakdown:

```text
subprogram:    74 MB  (71 %)   — generic monomorphisations
namespace:     30 MB  (29 %)   — empty/trivial wrappers
all type tags: <0.2 MB         — already low-overhead
```

The bulk is **functions, not types**. Type-unit dedup would barely
move the needle for substrate; subprogram + namespace dedup is the
real prize and it's the harder one (intra-CU references entangle).

## Existing tools and what they do

- **`dwz`** — post-link DWARF compression. Walks all CUs, finds
  identical DIE subtrees, hoists them into shared "common-info" CUs
  with inter-CU refs. 30-40 % savings on Firefox-class C++ binaries.
  Not Rust-aware. Could plausibly hit 40 %+ on substrate but no public
  benchmarks. Runs as a separate post-pass; not folded into any linker.
- **`dsymutil`** (macOS) — re-reads DWARF from `N_OSO`-tagged source
  objects and merges into a `.dSYM` bundle. Does string-level dedup
  but not type-level dedup. Output is often 2-3× larger than the
  source `.o` files combined.
- **`llvm-dwp`** — packages `.dwo` files into a `.dwp` archive with
  type-signature dedup via `DW_FORM_ref_sig8`. The only practical
  cross-CU type dedup path with LLVM today. Not applicable to Rust
  because rustc doesn't emit type units.
- **gold `--gdb-index`** / **lld `--gdb-index`** / **lld
  `--compress-debug-sections=zlib|zstd`** — wild matches lld's
  compress flag; doesn't yet match the index flag.
- **mold** — passes `.debug_*` through; respects SHF_MERGE; supports
  `--compress-debug-sections=zlib`. No cross-CU DIE work.

## Ranked improvement ideas for wild

| # | Improvement | Size impact (substrate-class) | Cost | Side |
|---|---|---|---|---|
| 1 | Mach-O `.debug_str` cross-CU dedup (mirror ELF SHF_MERGE) | 5-15 % of debug | 1-2 wk | linker |
| 2 | Dead-DIE strip under `--gc-sections` | 0-30 % depending on GC ratio | 2-4 wk | linker |
| 3 | `.debug_abbrev` hash-and-collapse | 0.1 % of debug (small absolute) | 3-7 d | linker |
| 4 | `--gdb-index` / `.debug_names` emit | 0 %; saves debugger startup | 2-4 wk | linker |
| 5 | Default `--compress-debug-sections=zstd` for ELF debug builds | -76 % already (with flag); change just makes default | 1 d | linker |
| 6 | `.debug_line` file/dir table dedup | 2-5 % of debug | 1-2 wk | linker |
| 7 | rustc opt-in to DWARF 5 (`-C dwarf-version=5`) | 10-20 % (strx + rnglists) | upstream | compiler |
| 8 | wild support for `-Zsplit-dwarf` (skeleton CU pass-through) | binary size unchanged; ~50-70 % less link input bandwidth | 3-6 wk | linker |
| 9 | Cross-CU DIE dedup (`dwz`-equivalent inside wild) | 25-40 % of `.debug_info` | 3-6 mo | linker |
| 10 | rustc emit `DW_TAG_template_type_parameter` + type units for monomorphisations | 40-70 % of `.debug_info` | months upstream | compiler |
| 11 | Unwind compact representation for Linux (Rust-aware compact unwind) | 50-70 % of `.eh_frame` | months | linker + runtime |

### Notes on prioritisation

- **#5 is the cheapest win** — wild already implements compression;
  flipping the default for ELF debug builds is a one-line change plus
  CI/docs. Most users would benefit immediately.
- **#1 (Mach-O)** matters because Mach-O has no SHF_MERGE equivalent
  flag, so wild currently passes per-CU string pools through to
  `dsymutil` un-deduped. `dsymutil` then does the work, but the
  intermediate output is bloated.
- **#2 (dead-DIE strip)** has the widest range. On an embedded Rust
  binary with aggressive `--gc-sections`, it could be huge. On
  midnight-node it's harder to predict (depends on how much of the
  workspace is actually live in the final binary).
- **#9 (`dwz`-class)** is the prize for substrate-class binaries
  but is genuinely months of work. Tractable only if someone has a
  specific size budget that compression alone doesn't meet.
- **#10 (compiler-side type units)** is the structurally correct fix.
  Linker workarounds are nibbling around the edges. Worth opening a
  rustc issue if one doesn't already exist.

### What `wild` should NOT do

- **Invent a custom DWARF format.** Custom formats break gdb / lldb /
  addr2line / `objdump` / `dsymutil` / IDE integrations. We only emit
  things downstream tools already understand.
- **Rewrite DWARF for performance gains under 5 %.** The DWARF spec
  is unforgiving; bugs corrupt debug info silently (gdb prints `<no
  type>` instead of crashing). Engineering risk dominates small wins.

## Sneaky idea: link-time DWARF 4 → 5 upgrade

> Could the linker upgrade rustc's DWARF 4 output to DWARF 5 in-flight
> and pick up the smaller encodings for free?

Worked through what each piece would cost:

| DWARF 5 piece | Linker work | Saving on midnight-node |
|---|---|---:|
| Bump CU header `version` 4→5 + add `unit_type` byte | trivial | **0 bytes** — purely cosmetic; debuggers may reject it because attribute forms still look v4 |
| `.debug_line` v4 → v5 (separate `.debug_line_str`, indexed file/dir tables, optional MD5 hashes) | self-contained per CU; doesn't touch the DIE tree | 5-10 MB on `.debug_line`'s 123 MB |
| `.debug_ranges` → `.debug_rnglists` | rewrite every `DW_AT_ranges` attribute in `.debug_info` from `DW_FORM_sec_offset` → `DW_FORM_rnglistx`; update abbrev tables; emit per-CU `.debug_rnglists` headers | 40-60 MB on `.debug_ranges`'s 108 MB |
| `.debug_loc` → `.debug_loclists` | same shape: rewrite `DW_AT_location` / `DW_AT_frame_base` references | 5-8 MB on `.debug_loc`'s 13 MB |
| `.debug_str` → `.debug_str_offsets` indirection (`DW_FORM_strx`) | rewrite every `DW_FORM_strp` attribute in `.debug_info`; build per-CU `.debug_str_offsets` array | ~20-30 MB net (saves on attr forms, costs on offsets table) |
| `.debug_addr` indirection (`DW_FORM_addrx`) | same idea for addresses | ~5 MB |

**The "sneaky" part falls apart from row 3 onward.** Anything that
shrinks the DIE-attribute encoding requires the linker to:

1. Parse every CU's abbrev table.
2. Generate new abbrev codes that use the new forms.
3. Walk every DIE, rewrite each attribute's bytes when its form changed.
4. Rebuild the per-CU abbrev table.
5. Patch the CU header's `debug_abbrev_offset`.

That's the same engineering shape as cross-CU DIE-dedup (item #9 in
the table above) — full DWARF write pass via gimli, weeks of code,
fragile failure mode (silent corruption → `gdb: <no type>`).

**One genuinely sneaky standalone piece**: `.debug_line` v4 → v5
upgrade. Line programs are independent per CU, separate from the DIE
tree, and v5 compresses file/dir tables (deduped via
`.debug_line_str`). Engineering: 1-2 weeks. Saving: 5-10 MB on
midnight-node, larger on binaries with deeply-nested workspace paths
(substrate's `polkadot-sdk/.../sp-runtime/...` repeats per CU).
Risk: low — the only consumers are debuggers asking "what line is
this address on?", and a wrong answer surfaces immediately during
testing.

**Verdict**: file the full DWARF version upgrade as a sub-item of
"build a DWARF rewriter." If we ever do that work for DIE dedup,
`.debug_str_offsets` and `.debug_rnglists` upgrades fall out almost
free. As a standalone "let's just bump the version", only the
`.debug_line` v5 piece is tractable in isolation.

## Hard prerequisite for any DWARF rewrite work: debugger-based tests

DWARF corruption is silent. `gdb` and `lldb` print `<no type>` or
just resolve symbols to the wrong line — the binary still runs, the
linker doesn't error, and unit tests on the byte layout pass. The
only reliable signal is "does a real debugger get the right answer."

Before landing **any** DWARF rewrite (line v5 upgrade, abbrev dedup,
DIE dedup, anything), we need an integration-test harness that:

1. Compiles a small fixture with `-g`.
2. Links it twice — once via wild without the rewrite, once with.
3. Runs `addr2line` (or `llvm-addr2line` / `llvm-symbolizer` for
   compressed-debug paths where binutils may lack zstd) on a known
   set of addresses extracted from the fixture's symbol table.
4. Asserts the file/line/function output matches between the two
   builds (and matches expected values).
5. Optionally: drives `lldb` / `gdb` via batch scripts to set a
   breakpoint, run, and inspect a variable's printed value. Checks
   the variable's type name decodes correctly.

This becomes the gate. No DWARF-touching commit lands without it
passing on at least the line-table fixture for both addr2line and
one debugger.

## Background reading

- DWARF 5 spec — https://dwarfstd.org/dwarf5std.html
- LLVM source-level debugging — https://llvm.org/docs/SourceLevelDebugging.html
- GNU `dwz` — https://sourceware.org/dwz/
- SFrame spec — https://sourceware.org/binutils/docs/as/SFrame-spec.html
- gimli (DWARF read+write) — https://crates.io/crates/gimli
- Rust issue #34651 — debug-info size with monomorphisation
- Rust issue #56068 — duplicate type info across CGUs
- Rust issue #89391 — `.debug_str` size with v0 mangling
- Recon experiment under `experiments/dwarf-recon/` produces the
  numbers quoted above on any ELF.
