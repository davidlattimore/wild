# WASM Linker — Known Gaps and TODOs

Status: 66 of 222 LLD tests passing (30%), 67 with `--include-ignored` (30%).

Reference: [tool-conventions/Linking.md](https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md).

## Implemented

### Core linking

- §2 (partial): 11 of 19 `R_WASM_*` relocation types — see gap list below
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

- **Relocation coverage is ~58%, not complete.** The match arm in
  `wasm_writer.rs:2062-2160` silently falls through on 8 of 19
  `R_WASM_*` variants — no diagnostic, quietly miscompiled output:
  - `R_WASM_EVENT_INDEX_LEB` (10)
  - `R_WASM_MEMORY_ADDR_LEB64` (14), `SLEB64` (15), `I64` (16)
  - `R_WASM_TABLE_NUMBER_LEB` (20)
  - `R_WASM_FUNCTION_OFFSET_I64` (22)
  - `R_WASM_TABLE_INDEX_REL_SLEB` (23), `REL_I32` (24), `REL_SLEB64` (25)
  - `R_WASM_GLOBAL_INDEX_I32` (26), `R_WASM_FUNCTION_INDEX_I32` (27)
- **memory64 / wasm64** blocked on the 64-bit relocation types above.
- **Exception handling** blocked — `SYMTAB_EVENT` (kind 4) and
  `R_WASM_EVENT_INDEX_LEB` are stubs; EH tags unparsed.
- **§8 target-features merging is absent.** `REQUIRED (0x2b)` vs
  `DISALLOWED (0x2d)` vs `USED (0x2c)` prefixes are concatenated, never
  checked across inputs. Spec requires a conflict error; wild emits a
  silently invalid module.

### Medium severity

- **Relocatable output (`-r`) is lossy.** Type dedup, function merge,
  imports, linking section with symtab + segment info, and custom sections
  work, but relocation sections and COMDAT group records are omitted.
  Downstream linkers see a degraded object.
- **PIC / shared libraries are header-level only.**
  `WASM_DYLINK_NEEDED` is hardcoded empty (`wasm_writer.rs:95`); no
  relocation adjustment for code-section offsets under PIC; `--shared`,
  `-pie`, `--experimental-pic` flags accepted but only partly honoured.
- **Symbol kinds `SYMTAB_SECTION` (3) and `SYMTAB_TABLE` (5)
  unimplemented.** Multi-table and section-symbol relocations degrade.
- **Shared memory / atomics.** `--shared-memory` flag exists but
  passive-segment synthesis and `__wasm_init_memory` are stub-level.
  Thread-model object files don't link correctly.
- **TLS (§10) not implemented.** `__tls_size`, `__tls_align`, `__tls_base`,
  `__wasm_init_tls` are neither synthesised nor exported.

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
