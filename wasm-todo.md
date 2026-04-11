# WASM Linker — Known Gaps and TODOs

## Tier 2 incomplete items

These are known gaps in the current Tier 2 implementation. They affect correctness for specific patterns but don't block the majority of test cases.

### Cross-object data symbol resolution

Data symbol address map is built per-object only. When object A references a data symbol defined in object B, the address won't resolve. Need a global data symbol name→address map analogous to `function_name_map`.

**Spec ref:** §9.4 — R_WASM_MEMORY_ADDR_* relocations reference symbol indices that may be undefined in the current object but defined in another.

### Data section relocation offset tracking

Pass 2.5 maps reloc offsets to data segments approximately — it checks if `reloc.offset < segment.data.len()` rather than computing exact byte positions within the DATA section payload. The DATA section payload has per-segment headers (flags + init_expr + data_len LEB) that affect offset calculations.

**Fix:** Parse the raw DATA section to record each segment's exact byte offset within the payload, then map reloc offsets precisely.

### Segment merging by name prefix

Spec §9.1 says: "Segments with common prefixes (.data, .rodata) merge into single output segments." Currently we emit one output segment per input segment. This produces correct but suboptimal output (more segments than necessary).

### Memory size alignment padding

Memory page count uses `stack_size + data_size` but `data_size` doesn't include alignment gaps between segments. Should account for the full `data_offset - stack_size` range.

### `--stack-first` flag

Stack is always placed at memory offset 0 growing up to `stack_size`. The `--stack-first` flag should place data after the stack, which is our current layout, but the flag also implies `__stack_pointer` starts at `stack_size` (top of stack). Need to verify this matches wasm-ld's behavior for `--stack-first` vs default.

### 64-bit relocation types

Types 14-16, 18-19, 22, 24 (the `*64` variants) are parsed but not applied. These are for `memory64` (wasm64) which is not yet a common target.

## Tier 3 — Tables (DONE)

Table section, element section, R_WASM_TABLE_INDEX_SLEB/I32 — all implemented.

## Tier 4 — Archives

- Archive member selection (pull members that define needed symbols)
- `--start-lib` / `--end-lib` (lazy object semantics)
- Library search (`-L` paths, `-l` names)

Wild's generic pipeline handles archives, but WASM archive integration hasn't been tested.

## Tier 5 — Constructors & GC

- `__wasm_call_ctors` synthesis from WASM_INIT_FUNCS (§6)
- COMDAT deduplication (§7)
- `.no_dead_strip` / `WASM_SYM_NO_STRIP` flag (§4.2, flag 0x80)

## Tier 6 — Advanced features

- TLS: `__tls_size`, `__tls_align`, `__tls_base`, `__wasm_init_tls`
- Shared memory: passive segments, `__wasm_init_memory`
- PIC/shared objects: `--experimental-pic`, `-shared`, `-pie`
- Relocatable output: `-r` flag
- `--compress-relocations`
- Target features validation (§8)
- Build ID (`--build-id`)
- Map file (`--Map`)
- `--keep-section`
- `.import_module` / `.import_name` directives
- `--export-memory=<name>`
- Weak symbol resolution (§9.2: strong vs weak)
- Symbol aliases

## Pipeline integration

The WASM writer currently re-parses raw binary input rather than using wild's generic pipeline for section data and symbol resolution. Longer-term, the writer should:

- Use `ObjectFile::raw_section_data()` for section bytes (partially done)
- Use `layout.symbol_resolutions` for symbol→address mapping
- Use the pipeline's section layout for memory offset assignment
- Move relocation application into the generic writer framework
