# WASM Linker — Known Gaps and TODOs

Status: 66 of 222 tests passing (30%), 67 with --include-ignored (30%).

Note: data-layout 32-bit path fully correct (globals, segments, relocations
all match wasm-ld), blocked only by wasm64 in the second RUN line.

## Implemented (per spec)

### Core linking (§2-§9)

- §2: All 10 core relocation types
- §4.2: Symbol flags — BINDING_WEAK, UNDEFINED, EXPORTED, NO_STRIP,
  VISIBILITY_HIDDEN
- §4.3: Import name resolution for unnamed undefined symbols
- §5: WASM_SEGMENT_INFO (alignment, names, TLS flags)
- §6: WASM_INIT_FUNCS + .init_array constructor registration
- §7: COMDAT dedup (symbol-level via generic pipeline, data/function skipping)
- §9.1: Section merging (type dedup, function, code, data, global)
- §9.2: Symbol resolution (strong/weak, entry point, --export flags)
- §9.4: Relocation application (all types, precise DATA section offsets)
- §9.5: Padded LEB128 patching
- §9.6: Output section ordering

### Memory layout

- --stack-first (default) / --no-stack-first
- --initial-memory, --max-memory, --global-base, --no-growable-memory
- --initial-heap (with correct u64 page calculation)
- Segment merging by name prefix (`.rodata.*` / `.data.*` / `.bss.*` grouping)
- Per-group output segments with group-aligned layout
- Name-based BSS classification (not content-based)
- __heap_base aligned to max data segment alignment

### Exports and globals

- --export-dynamic / --export-all (with VISIBILITY_HIDDEN filtering)
- --export=<sym> resolves both functions and globals
- --export-table, --import-table, --growable-table
- Export ordering: memory -> globals -> functions -> table
- Linker-defined globals: `__stack_pointer`, `__data_end`, `__heap_base`,
  `__global_base`, `__rodata_start`, `__rodata_end`

### Code generation

- __wasm_call_ctors synthesis (before relocation pass for correct refs)
- Function-level GC with opcode-aware reachability scanner
- --compress-relocations via wilt pass (full opcode-aware LEB128 compression)
- Custom section ordering (user -> name -> target_features) and concatenation

### Other

- Output validation (section order, function/code count, export indices,
  import accounting)
- Weak/COMDAT: relocations resolve to winning definition, losing data/function
  segments skipped
- Archives (via wild's generic pipeline)
- Name section (function names + global names)
- Bounds-safe padded LEB128, overflow-safe memory calculation
- Test runner: split-file, %/t substitution, KNOWN_PASSING lists

## Remaining gaps

### Not yet implemented

- **User-defined globals**: implemented (parse GLOBAL section, emit with
  correct valtype init exprs, resolve GLOBAL_INDEX_LEB relocs, immutable-first
  ordering). Remaining: export data symbol addresses as globals, mutable
  global export gating, empty-name symbol pipeline fix.
- **TLS** (§10): `__tls_size`, `__tls_align`, `__tls_base`, `__wasm_init_tls`
- **Shared memory**: passive segments, __wasm_init_memory
- **PIC/shared objects**: --experimental-pic, -shared, -pie
- **Relocatable output**: basic -r flag works (type dedup, function merge,
  imports, linking section with symbol table + segment info, custom sections).
  Missing: relocation sections, data segment merging, COMDAT in linking section.
- **LTO**: bitcode input processing
- **Debug info sections**: proper DWARF handling
- **.import_module / .import_name**: custom import attributes
- **--export-memory=\<name\>**: custom memory export name
- **--keep-section**: preserve specific sections through strip
- **Target features validation (§8)**: cross-input compatibility
- **Build ID**: --build-id
- **Map file**: --Map
- **-wrap / --wrap**: symbol wrapping
- **--reproduce**: create reproducible archive
- **Name section demangling**: C++ name demangling
- **Weak undefined resolution**: weak refs to undefined symbols -> 0
- **64-bit relocation types**: memory64/wasm64
- **Signature mismatch warnings**: type checking diagnostics

### Pipeline integration

The WASM writer re-parses raw binary input rather than fully leveraging
wild's generic pipeline. Longer-term improvements:

- Use layout.symbol_resolutions for symbol->address mapping
- Move relocation application into the generic writer framework
- Use pipeline section layout for memory offset assignment
