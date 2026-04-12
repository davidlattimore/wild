# WASM Linker — Known Gaps and TODOs

Status: 75 of 223 LLD tests passing (34%).

Reference: [tool-conventions/Linking.md](https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md).

## Implemented

### Core linking

- §2: 27 of 27 `R_WASM_*` relocation types handled
- §4.2: Symbol flags `BINDING_WEAK`, `UNDEFINED`, `EXPORTED`, `NO_STRIP`,
  `VISIBILITY_HIDDEN`
- §4.3: Import name resolution for unnamed undefined symbols
- §5: `WASM_SEGMENT_INFO` (alignment, names, TLS flags on segments)
- §6: `WASM_INIT_FUNCS` + `.init_array` constructor registration
- §7: COMDAT dedup — symbol-level via generic pipeline, losing data/function
  segments skipped on link
- §9.1: Section merging (type dedup, function, code, data, global)
- §9.2: Symbol resolution (strong/weak, entry point, `--export` flags)
- §9.4 (partial): Relocation application for the 11 supported types
- §9.5: Padded LEB128 patching
- §9.6: Output section ordering

### Memory layout

- `--stack-first` (default) / `--no-stack-first`
- `--initial-memory`, `--max-memory`, `--global-base`, `--no-growable-memory`
- `--initial-heap` (with correct u64 page calculation)
- Segment merging by name prefix (`.rodata.*` / `.data.*` / `.bss.*` grouping)
- Per-group output segments with group-aligned layout
- Name-based BSS classification (not content-based)
- `__heap_base` aligned to max data segment alignment

### Exports and globals

- `--export-dynamic` / `--export-all` (with `VISIBILITY_HIDDEN` filtering)
- `--export=<sym>` resolves both functions and globals
- `--export-table`, `--import-table`, `--growable-table`
- Export ordering: memory → globals → functions → table
- Linker-defined globals: `__stack_pointer`, `__data_end`, `__heap_base`,
  `__global_base`, `__rodata_start`, `__rodata_end`

### Code generation

- `__wasm_call_ctors` synthesis (before relocation pass for correct refs)
- Function-level GC with opcode-aware reachability scanner
- `--compress-relocations` via `wilt` pass (opcode-aware LEB128 compression)
- Custom section ordering (user → name → target_features) and concatenation

### Other

- Output validation (section order, function/code count, export indices,
  import accounting)
- Archives (via wild's generic pipeline)
- Name section (function names + global names)
- Bounds-safe padded LEB128, overflow-safe memory calculation
- Test runner: split-file, `%/t` substitution, `KNOWN_PASSING` lists

## Gaps

### High severity

- **Relocation coverage at 27/27.** Unhandled types still emit a
  deduplicated `tracing::warn!` if anything exotic appears.

  Caveats on the just-landed variants:

  - EH tag support now resolves kind-4 (`SYMTAB_EVENT`) symbols by
    name with §9.2 strong/weak rules and §7 COMDAT (kind 3) dedup,
    mirroring the function-merge pipeline. Hidden-visibility tags
    are filtered from `--export-dynamic` and `WASM_SYM_EXPORTED`
    tags emit kind-0x04 exports. `R_WASM_TAG_INDEX_LEB` (10)
    patches through the resolved output index. Still unmodelled:
    tag names in the name section, and full EH semantics
    (`throw`/`catch`/`delegate` validation, unwinding).
  - PIC-relative relocs (11/12/17/24) currently degrade to their
    non-REL siblings on the assumption of non-PIC output
    (`__memory_base = __table_base = 0`). When the PIC pipeline
    lands they need to switch to base-relative arithmetic.
  - Memory64 has a working end-to-end path: `--features=+memory64`
    / `-mwasm64` / `--target=wasm64-*` flip `args.memory64`, memory
    imports and memory sections carry the 0x04 limits bit with
    ULEB64 page counts, the eight address-typed linker-synth globals
    widen to i64 (imported `__memory_base` / `__stack_pointer`
    included under PIC — and the static-PIC `__memory_base` /
    `__table_base` / `__tls_base` triad now widens with them), and
    active data-segment offsets emit as `i64.const` with SLEB64
    payloads. `@TBREL` SLEB/SLEB64 values now carry the static-PIC
    `-1` bias so runtime `global.get __table_base + i*.const TBREL`
    resolves correctly (was writing absolute table index). A
    `pic-static64.s` test pins the mem64 static-PIC global widening
    and @TBREL/@MBREL path. Internal address arithmetic stays `u32`
    by default; the `wasm-addr64` Cargo feature switches the `Addr`
    type alias to `u64` for layouts above 4 GiB. Still to do:
    bulk-memory operand widths beyond `memory.init` (memory.copy /
    memory.fill operands pass through verbatim — a concern only if
    an input actually emits them under mem64 with >4 GiB ranges).
- **Exception handling** blocked — `SYMTAB_EVENT` (kind 4) and
  `R_WASM_EVENT_INDEX_LEB` are stubs; EH tags unparsed.
- **§8 target-features merging**: implemented in
  `merge_target_features`. `+` (0x2b, USED) and legacy `=` (0x3d,
  REQUIRED) unify into USED; `-` (0x2d, DISALLOWED) survives only
  when no input uses the feature; the USED-vs-DISALLOWED conflict
  case errors out. The spec §8 shared-memory/`atomics` guardrail
  also fires when `--shared-memory` is combined with any input
  listing `-atomics`. Covered by six unit tests.

### Medium severity

- **Relocatable output (`-r`) is lossy.** Type dedup, function merge,
  imports, linking section with symtab + segment info, and custom sections
  work, but relocation sections and COMDAT group records are omitted.
  Downstream linkers see a degraded object.
- **PIC / shared libraries are partially wired.**
  - `-pie`, `--pie`, `--experimental-pic` now set `WasmArgs.is_pic`
    (previously silently ignored).
  - Element segment init expression uses `global.get __table_base`
    under PIC (previously always `i32.const 1`, overriding the
    dynamic linker's runtime base).
  - Data segment init expression uses `global.get __memory_base`
    under `is_shared`.
  - Remaining gaps:
    - `WASM_DYLINK_NEEDED` subsection hardcoded empty
      (`wasm_writer.rs:95`); no `DYLINK_EXPORT_INFO` or
      `DYLINK_IMPORT_INFO`.
    - `@GOT` symbol pipeline: partial. Static/PIE links now
      internalise `GOT.func.<sym>` as a local immutable i32 global
      with init = target's indirect-table slot, and `GOT.mem.<sym>`
      with init = target's memory address. Shared output still
      passes these through. Unit test
      `got_func_import_parses_with_field_name` pins the parse
      path. `pic-static-unused` passes.
    - `pic-static` still ignored but partial support landed: wild
      now detects static-PIC mode (GOT imports or code relocations
      targeting `__memory_base` / `__table_base`) and under that
      mode:
      - Synthesises the triad `__memory_base` (0), `__table_base`
        (1), `__tls_base` (0) right after `__stack_pointer`.
      - Suppresses `__data_end` / `__heap_base` unless the user
        explicitly asked for them via `--export`.
      - Internalises `GOT.func` / `GOT.mem` / `GOT.data` module
        imports (llvm-mc's actual encoding — not the earlier wrong
        `GOT.func.<name>` field-prefix assumption) into local
        immutable i32 globals and removes the import entries.
      - Tag imports in output-import collection skip GOT imports
        and `__memory_base` / `__table_base` / `__tls_base`
        imports to avoid duplicates.

      `pic-static` now passes. Work across this session's PIC
      commits landed:
      - GOT globals emit as `GOT.func.internal.<sym>` /
        `GOT.data.internal.<sym>`, matching wasm-ld's naming.
      - GOT globals ordered func-first then data.
      - Indirect function table slots assigned in insertion order
        rather than sorted — `ret32` (first-referenced) takes
        slot 1.
      - Element-segment init expression uses
        `global.get __table_base` whenever a `__table_base`
        global exists (imported under shared, synthesised under
        static-PIC).
      - GOT.func references to *imported* (undefined) functions
        now get table slots. A pre-Pass-4 simulation of the
        import deduplication builds
        `function_import_output_idx: name → output funcidx`. The
        ctor-insertion and Pass-4 import shifts skip entries
        flagged as imports so the final table carries the right
        indices end-to-end.
      - Name section subsection 9 (data segment names) emitted
        when data segments exist. Placeholder names
        (`.data.<i>`) for now; proper per-segment names belong to
        a later commit.

      `@TBREL` SLEB / SLEB64 values under static-PIC now subtract
      `__table_base = 1` (types 12 and 24), cancelling the
      `global.get __table_base` the compiler emits alongside the
      reloc. `@MBREL` needs no bias since the static-PIC
      `__memory_base` is synthesised to 0.

      Four LLD PIC tests remain ignored; each needs its own
      feature chunk:
      - `weak-undefined-pic`: wasm-ld suppresses the import for
        weak-undefined functions, synthesises a trapping stub to
        own the call target, and names the GOT global
        `undefined_weak:<name>` (not `GOT.func.internal.<name>`)
        with init 0 (marker for "null function pointer").
      - `emit-relocs-fpic`: needs `--emit-relocs` support — wild
        doesn't preserve the reloc sections in the output.
      - `pic-empty` (lto/): LTO pipeline integration.
    - `@TBREL` / `@MBREL` static behaviour: under static link wild
      now synthesises `__memory_base` (init 0) and `__table_base`
      (init 1) as local immutable i32 globals, but only when an
      input actually references them as kind-2 symbols. This makes
      the compiler's `global.get __table_base` then `i32.const @TBREL`
      then `i32.add` sequence resolve at runtime (previously the
      `global.get` would fail because the referenced global didn't
      exist in the output).
    - Custom-section relocations: plumbing landed. wild parses
      `reloc.<custom_name>` sections, stores them per target custom
      section in `ParsedInput.custom_relocations`, and applies
      `R_WASM_GLOBAL_INDEX_I32` (13) during passthrough. Unresolved
      global references emit the `0xFFFFFFFF` sentinel per wasm-ld
      debug-section convention. `pic-static-unused` now passes.
      Other reloc types in custom sections (SECTION_OFFSET_I32 (9),
      FUNCTION_OFFSET_I32 (8), etc.) are still left as the
      compiler's placeholder bytes — add cases as downstream tests
      require them.
    - `_is_pic` alone (without `is_shared`) doesn't yet propagate
      to the "import `__memory_base` / `__table_base` /
      `__stack_pointer`" machinery — a pure `-pie` link today
      falls back to the static code path. Unifying the two
      requires a careful pass over the ~12 `is_shared` gates in
      the writer.
    - `R_WASM_MEMORY_ADDR_LOCREL_I32` in code sections (currently
      handled for data-section relocs only).
- **Symbol kinds `SYMTAB_SECTION` (3) and `SYMTAB_TABLE` (5)
  unimplemented.** Multi-table and section-symbol relocations degrade.
- **Shared memory / atomics.** `--shared-memory` flag exists but
  passive-segment synthesis and `__wasm_init_memory` are stub-level.
  Thread-model object files don't link correctly.
- **TLS (§16.3) — partial.** `__tls_base` / `__tls_size` / `__tls_align`
  are synthesised when TLS data is present or `--shared-memory` is set,
  and `@TLSREL` (reloc types 21, 25) resolves to the correct
  TLS-relative offset. `__tls_base` now follows the spec's
  mutability rule: **immutable** (init = absolute TLS block address)
  under non-shared, **mutable** (init = 0, set by `__wasm_init_tls`)
  under shared. Static-PIC detection no longer false-fires on
  `__tls_base` references or on GOT imports alone — only code or
  data that actually references `__memory_base` / `__table_base`
  via kind-2 symbols triggers the PIC triad. Lazy linker-global
  synthesis landed: `__tls_size`, `__tls_align`, `__data_end`,
  `__heap_base` are now only emitted when an input actually
  references them (or the user `--export`s them); `__tls_size` /
  `__tls_align` still emit unconditionally under `--shared-memory`
  because the eventual `__wasm_init_tls` will consume them. GOT.*
  import suppression in the output is now gated on `!is_shared`
  (matching the GOT internalisation pass) rather than `static_pic`,
  so a non-PIC link with `@GOT@TLS` no longer double-emits the
  import.
  Segment ordering landed: the data layout now has four passes —
  `.rodata.*`, `.tdata.*`, `.data.*` (non-TLS), `.bss.*` — matching
  wasm-ld. `.tdata` emits as its own `OutputDataSegment` (not
  merged into the `.data.*` blob), which is both the spec §16.3
  requirement for runtime `memory.init` and what the test suites
  expect in the `DATA` segment lists. With this in, wild's output
  for the non-shared variant of `tls-non-shared-memory.s` matches
  wasm-ld globally and data-segment-wise; the test still can't be
  added to `KNOWN_PASSING` because it bundles three other RUN
  lines (`-shared`, `-pie`, `--features=extended-const`) that need
  the shared-memory TLS pieces below.
  `__wasm_init_tls (i32) -> ()` synthesis landed under
  `--shared-memory`: body is `local.get 0; global.set __tls_base;
  local.get 0; i32.const 0; i32.const <tls_size>; memory.init
  <tdata_idx>, 0; end`. The emitted `.tdata` is already passive
  because the existing `use_passive` path flips all data segments
  to passive under `--shared-memory`, and `tls_segment_index`
  threads through from the layout pass so `memory.init` targets
  the right segment.
  Still missing for the canonical `tls.s`:
  - `@GOT@TLS` global internalisation under `--shared-memory` (the
    compiler imports `GOT.mem.<tlssym>`; wasm-ld under `-shared`
    replaces it with a local mutable i32 global initialised to 0
    and sets it at runtime from `__wasm_apply_global_tls_relocs`).
  - `__wasm_apply_global_tls_relocs ()->()` synthesis: one
    `global.get __tls_base; i32.const <offset>; i32.add;
    global.set <got_tls_idx>` block per internalised `@GOT@TLS`,
    plus a `call __wasm_apply_global_tls_relocs` tail inside
    `__wasm_init_tls`.
  - `tls_size` bug fixed: the computation now uses the same
    broader classification as the layout pass (`seg.is_tls` OR
    name starts with `.tdata`), so TLS sections declared only via
    the `"T"` section flag (which the parser doesn't always
    round-trip into `is_tls`) are counted. `tls.s` now reads
    `__tls_size = 12` as wasm-ld does.
  - Data-symbol address export as globals under `-shared`.
  - Import ordering: wasm-ld emits `env.memory` /
    `env.__indirect_function_table` / `env.__stack_pointer` /
    `env.__memory_base` / `env.__table_base` *before* any
    `GOT.*` imports; wild emits source order.

### Low severity

- **Symbol-flag plumbing is incomplete** — `EXPLICIT_NAME (0x40)`,
  `TLS (0x100)`, `ABSOLUTE (0x200)` are parsed (or missing entirely for
  ABSOLUTE) but not round-tripped to the output symbol table.
- **LTO / bitcode** input processing — unimplemented.
- **Debug info** beyond pass-through — DWARF rewriting and
  name-section demangling unimplemented; `.debug_*` sections flow through
  verbatim even when sections would need rebasing.
- `.import_module` / `.import_name` custom import attributes —
  unimplemented.
- `--export-memory=<name>` — unimplemented.
- `--keep-section`, `--Map`, `--build-id`, `--reproduce`,
  `-wrap`/`--wrap` — unimplemented.
- **Weak-undefined resolution** — weak refs to undefined symbols should
  resolve to 0; wild currently errors.
- **Signature-mismatch diagnostics** — type mismatches between
  declarations and definitions not warned.
- **Segment merging by name prefix** is *more* aggressive than the spec
  requires; compatible but non-standard.
- **Init-function priority uniqueness** unchecked (§9.6; probably harmless).
- **User-defined globals**: core path works (parse GLOBAL section, emit
  with correct valtype init exprs, resolve `R_WASM_GLOBAL_INDEX_LEB`,
  immutable-first ordering). Remaining: export data-symbol addresses as
  globals, mutable-global export gating, empty-name symbol pipeline fix.

### Pipeline integration

The wasm writer still re-parses raw binary input rather than fully
leveraging wild's generic pipeline. Longer-term improvements:

- Use `layout.symbol_resolutions` for symbol→address mapping
- Move relocation application into the generic writer framework
- Use pipeline section layout for memory offset assignment

## Implemented but untested

Features landed in code with no dedicated test in wild's wasm suite.
Priority candidates for follow-up test cases. Each line names the
shipping commit (where applicable) and what would need to be exercised.

### Relocation handlers

- `R_WASM_GLOBAL_INDEX_I32` (13), `TABLE_NUMBER_LEB` (20),
  `FUNCTION_INDEX_I32` (26) — `bbfae0a`. Need a `.s` or `.ll` test
  that emits each and checks the patched bytes.
- `R_WASM_MEMORY_ADDR_LEB64` (14), `SLEB64` (15), `I64` (16) —
  `87bf606`. Need a memory64 object exercising each width.
- `R_WASM_TABLE_INDEX_SLEB64` (18), `I64` (19),
  `FUNCTION_OFFSET_I64` (22) — `87bf606`. Same memory64 dependency.
- `R_WASM_MEMORY_ADDR_REL_SLEB` (11), `TABLE_INDEX_REL_SLEB` (12),
  `MEMORY_ADDR_REL_SLEB64` (17), `MEMORY_ADDR_LOCREL_I32` (23),
  `TABLE_INDEX_REL_SLEB64` (24), `MEMORY_ADDR_TLS_SLEB64` (25) —
  `09bde02`. PIC / memory64 / TLS paths.
- `R_WASM_TAG_INDEX_LEB` (10) — `f4ca707` + `53bdad4`. Need an EH
  object with a tag ref.

### EH / tag pipeline

- Tag section (id 13) parse → emit round-trip has a unit test in
  `wasm_writer::tests::tag_section_parse_roundtrip` covering type
  section, kind-0x04 import, and local tag def.
- Still uncovered: kind-4 (`SYMTAB_EVENT`) symbol merging with §9.2
  strong/weak, §7 COMDAT (kind 3) dedup, hidden-visibility
  filtering, and kind-0x04 export emission under
  `--export-dynamic`. Needs a multi-object end-to-end test.

### LEB / SLEB writers

- `write_padded_leb128`, `write_padded_sleb128`,
  `write_padded_leb128_u64`, `write_padded_sleb128_i64` all have
  unit tests in `wasm_writer::tests` covering 0, 1, -1, boundary
  powers of two, and type MIN/MAX.

### Writer and validator plumbing

- Unhandled-reloc `tracing::warn!` dedup — `9b4ba5f`. A targeted test
  that feeds an unknown reloc type and checks the warning fires once.
- Section-order validator using *logical* positions (datacount and
  tag) — covered by the existing output format but the ordering rule
  itself has no negative test.
- Tidy CRLF exemption for `wild/tests/lld-wasm/Inputs/libstub.so` —
  `255160b`. Relies on the `.gitattributes` entry staying put; a
  test asserting both file contents and attribute would catch
  accidental removal.

## Test suite skips — mapping to gaps

The `KNOWN_PASSING` allow-list in `wild/tests/lld_wasm_tests.rs` skips
categories that each map back to a gap above:

- multi-table / table manipulation → symbol kind `TABLE`, reloc 20
- `.import_module` / `.import_name` → custom attributes gap
- name-section demangling → debug info gap
- LTO / bitcode → LTO gap
- weak aliases → symbol flag plumbing gap
- DWARF debug info → debug info gap
- weak-undefined resolution → low-severity gap above
