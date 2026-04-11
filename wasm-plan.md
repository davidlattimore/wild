# WASM Linker — Spec-Based Implementation Plan

Reference: [WebAssembly Linking Convention](https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md)

## Current State

Wild can link a single trivial WASM object into a valid module. The `entry` test passes with FileCheck validation. 28 tests pass (mostly error-path tests), 111 fail, 83 ignored.

## Spec Requirements (what a conforming linker must do)

### Phase 1: Input Parsing

| Requirement | Status |
| ----------------------------------- | ------ |
| Parse `linking` custom section (v2) | Delegated to `object` crate — partial |
| Parse `reloc.*` custom sections | Not implemented |
| Parse `target_features` section | Not implemented |
| Read symbol table (all 6 kinds) | Partial (via object crate) |
| Read segment info | Not implemented |
| Read init functions | Not implemented |
| Read COMDAT groups | Not implemented |
| Validate padded LEB128 | Not implemented |

### Phase 2: Symbol Resolution

| Requirement | Status |
| ------------------------------------------ | ------------ |
| Strong vs weak resolution | Not implemented |
| Local symbol scoping | Not implemented |
| Undefined symbol imports | Not implemented |
| COMDAT deduplication | Not implemented |
| Multiple definition errors | Not implemented |
| `--allow-undefined` flag | Parsed, not enforced |
| `--export` / `--export-if-defined` | Not implemented |
| `--export-dynamic` / `--export-all` | Not implemented |

### Phase 3: Index Renumbering & Layout

| Requirement | Status |
| ------------------------------------------ | -------------- |
| Function index renumbering | Not implemented |
| Global index renumbering | Not implemented |
| Table index renumbering | Not implemented |
| Data segment merging & layout | Not implemented |
| Memory size computation | Hardcoded 1 page |
| Stack allocation (`--stack-first`, etc.) | Not implemented |
| `--global-base` | Not implemented |
| `--initial-memory` / `--max-memory` | Not implemented |
| Type section deduplication | Not implemented |
| Indirect function table synthesis | Not implemented |

### Phase 4: Relocation Processing

| Requirement | Status |
| ------------------------------------------ | -------------- |
| R_WASM_FUNCTION_INDEX_LEB (0) | Not implemented |
| R_WASM_TABLE_INDEX_SLEB (1) | Not implemented |
| R_WASM_TABLE_INDEX_I32 (2) | Not implemented |
| R_WASM_MEMORY_ADDR_LEB (3) | Not implemented |
| R_WASM_MEMORY_ADDR_SLEB (4) | Not implemented |
| R_WASM_MEMORY_ADDR_I32 (5) | Not implemented |
| R_WASM_TYPE_INDEX_LEB (6) | Not implemented |
| R_WASM_GLOBAL_INDEX_LEB (7) | Not implemented |
| R_WASM_FUNCTION_OFFSET_I32 (8) | Not implemented |
| R_WASM_SECTION_OFFSET_I32 (9) | Not implemented |
| Padded LEB128 patching | Not implemented |

### Phase 5: Output Module Emission

| Requirement | Status |
| ------------------------------------------ | ------------- |
| Type section (synthesised) | Copied from input |
| Import section | Not implemented |
| Function section (merged) | Copied from input |
| Table section (synthesised) | Not implemented |
| Memory section | Hardcoded 1 page |
| Global section | Not implemented |
| Export section | Basic (entry + memory) |
| Code section (merged + relocated) | Copied from input |
| Data section (merged) | Not implemented |
| `__wasm_call_ctors` synthesis | Not implemented |
| Custom section merging | Not implemented |
| name section | Not implemented |

### Phase 6: Output Validation

| Requirement | Status |
| ------------------------------------------ | -------------- |
| Re-parse output and validate structure | Not implemented |
| Validate section ordering | Not implemented |
| Validate export completeness | Not implemented |
| Validate all indices in range | Not implemented |

## Implementation Tiers

### Tier 1 — Core linking (single & multi-object, no relocations)

Goal: link multiple objects with trivial functions, produce correct output with proper symbol resolution and exports.

1. **Parse linking section properly** — read symbol table with all flags (weak, local, hidden, exported, undefined), segment info, init functions
2. **Multi-object function merging** — renumber function indices, merge type sections (dedup), merge function sections, merge code sections
3. **Symbol resolution** — strong/weak, undefined handling, entry point lookup
4. **Export section from resolved symbols** — export entry + memory + any `--export` symbols
5. **Memory section** — compute from data segments (or 1 page minimum)
6. **Output validation** — re-parse with `wasmparser`, check section order, validate indices

### Tier 2 — Relocations & data

Goal: link real programs with data, function calls across objects, indirect calls.

1. **Relocation parsing** — read `reloc.*` sections
2. **Core relocations** — R_WASM_FUNCTION_INDEX_LEB, R_WASM_MEMORY_ADDR_*, R_WASM_GLOBAL_INDEX_LEB
3. **Data segment merging** — merge .data/.rodata/.bss, compute memory layout
4. **Global section** — `__stack_pointer` and other linker-defined globals
5. **LEB128 patching** — write padded LEB128 values into code section

### Tier 3 — Tables & indirect calls

Goal: support `call_indirect`, function pointers.

1. **Table synthesis** — build indirect function table from R_WASM_TABLE_INDEX_* relocations
2. **Element section** — populate table entries
3. **`--import-table` / `--export-table`**

### Tier 4 — Archives & libraries

Goal: support `.a` archives, `--whole-archive`, `-l` search.

1. **Archive member selection** — pull members that define needed symbols
2. **`--start-lib` / `--end-lib`** — lazy object semantics
3. **Library search** — `-L` paths, `-l` names

### Tier 5 — Constructors & GC

Goal: support init/fini, garbage collection.

1. **`__wasm_call_ctors`** — synthesize from init functions, respect priority
2. **`--gc-sections`** — remove unreferenced functions/data
3. **COMDAT deduplication**

### Tier 6 — Advanced features

1. **TLS** — `__tls_size`, `__tls_align`, `__tls_base`, `__wasm_init_tls`
2. **Shared memory** — passive segments, `__wasm_init_memory`
3. **PIC/shared objects** — `--experimental-pic`, `-shared`, `-pie`
4. **Relocatable output** — `-r` flag
5. **`--compress-relocations`**
6. **name section** — merge debug names
7. **target_features** — validate compatibility across inputs
8. **Build ID** — `--build-id`
9. **Map file** — `--Map`
10. **Strip** — `--strip-debug`, `--strip-all`

## wasm-ld CLI parity

Key flags to support (grouped by tier):

**Tier 1:** `-o`, `-e`/`--entry`, `--no-entry`, `--allow-undefined`
**Tier 2:** `--global-base`, `--initial-memory`, `--max-memory`, `--no-growable-memory`, `--stack-first`
**Tier 3:** `--import-table`, `--export-table`
**Tier 4:** `-L`, `-l`, `--whole-archive`, `--no-whole-archive`, `--start-lib`, `--end-lib`
**Tier 5:** `--gc-sections`, `--no-gc-sections`, `--export`, `--export-if-defined`, `--export-all`, `--export-dynamic`
**Tier 6:** `--shared-memory`, `--import-memory`, `--compress-relocations`, `--strip-debug`, `--strip-all`, `--build-id`, `-r`/`--relocatable`, `-shared`, `-pie`, `--Map`
