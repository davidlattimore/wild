# WebAssembly linking notes

## Specification

- [WebAssembly Linking Convention](https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md) -- the authoritative spec for object file format
- [WebAssembly Binary Format](https://webassembly.github.io/spec/core/binary/index.html)
- [WebAssembly Component Model](https://github.com/WebAssembly/component-model) (higher-level, future scope)

## Object file format

WASM object files (`.o`) are standard WASM modules with additional custom sections:

- `linking` -- version, symbol table, segment info, init functions, comdat groups
- `reloc.CODE`, `reloc.DATA`, etc. -- relocation entries per section

Unlike ELF/Mach-O, WASM relocations use **padded LEB128** encoding (5 bytes for i32, 10 for i64) so patching doesn't change instruction length.

### Symbol table

Stored in the `linking` custom section. Each entry has:

- Kind: FUNCTION, DATA, GLOBAL, SECTION, EVENT, TABLE
- Flags: BINDING_WEAK, BINDING_LOCAL, VISIBILITY_HIDDEN, UNDEFINED, EXPORTED, EXPLICIT_NAME, NO_STRIP, TLS, ABSOLUTE, ALIVE

### Relocation types

27 types defined (as of the current spec), including:

| Relocation | Description |
| ----------------------------- | --------------------------------- |
| R_WASM_FUNCTION_INDEX_LEB | Function index in LEB128 |
| R_WASM_TABLE_INDEX_SLEB | Table index (signed LEB128) |
| R_WASM_TABLE_INDEX_I32 | Table index (i32 in data segment) |
| R_WASM_MEMORY_ADDR_LEB | Memory address (LEB128) |
| R_WASM_MEMORY_ADDR_SLEB | Memory address (signed LEB128) |
| R_WASM_MEMORY_ADDR_I32 | Memory address (i32) |
| R_WASM_TYPE_INDEX_LEB | Type index |
| R_WASM_GLOBAL_INDEX_LEB | Global index |
| R_WASM_FUNCTION_OFFSET_I32 | Offset within function |
| R_WASM_SECTION_OFFSET_I32 | Offset within section |
| R_WASM_TAG_INDEX_LEB | Tag/event index |
| R_WASM_MEMORY_ADDR_TLS_SLEB | TLS memory address |
| R_WASM_TABLE_INDEX_REL_SLEB | Relative table index |
| R_WASM_MEMORY_ADDR_LOCREL_I32 | PC-relative memory address |
| R_WASM_TABLE_INDEX_SLEB64 | 64-bit table index |
| R_WASM_MEMORY_ADDR_LEB64 | 64-bit memory address variants |
| R_WASM_MEMORY_ADDR_SLEB64 | (signed) |
| R_WASM_MEMORY_ADDR_I64 | (i64 in data) |
| R_WASM_TABLE_NUMBER_LEB | Table number |

## Key differences from ELF/Mach-O

- No address space layout -- WASM uses index spaces (function index, global index, table index, memory offset)
- No GOT/PLT -- imports and exports are first-class module concepts
- No segments/program headers -- the output is a flat WASM module
- Data segments are explicit with base offset expressions
- Indirect calls go through a table, not function pointers
- Memory is a single linear block, grown with `memory.grow`
- Start function replaces `_start`/`main` entry point convention (though `_start` export is used by WASI)

## Linker phases (wasm-ld reference)

1. Parse object files, read `linking` and `reloc.*` custom sections
2. Build symbol table, resolve symbols across objects
3. Resolve weak symbols, handle comdat groups
4. Garbage collect unused functions/data
5. Assign indices (function, global, table, type) in the output module
6. Merge data segments, compute memory layout
7. Apply relocations (patch LEB128 immediates)
8. Emit output WASM module sections in order:
   Type, Import, Function, Table, Memory, Global, Export, Elem, Datacount, Code, Data, custom sections

## Existing linker implementations

| Linker | Language | License | Notes |
| -------------------- | -------- | ----------------------------- | ----- |
| wasm-ld (LLD) | C++ | Apache-2.0 WITH LLVM-exc | Canonical implementation, ~189 tests |
| Zig `link/Wasm.zig` | Zig | MIT | Independent from-scratch impl |
| Binaryen wasm-merge | C++ | Apache-2.0 | Module-level merging, not object linking |

All licenses are compatible with wild's MIT OR Apache-2.0.

## Test strategy

### Why LLD tests can't be converted to .wat

LLD's WASM tests use LLVM's assembly format (`.s` files assembled with `llvm-mc`) and LLVM IR (`.ll` files). These test **linker-level concepts** that WAT cannot express:

- Relocations (`R_WASM_*`) -- WAT has no relocation representation
- Symbol binding (weak, hidden, comdat) -- WAT has no symbol table
- Multi-file linking -- WAT is a single-module format
- Named sections (`.data.foo`, `.bss.bar`) -- WAT has no section naming

The WASM assembly mnemonics (`i32.const`, `call`, etc.) map to WAT, but the object-file framing (sections, symbols, relocations) does not.

### Recommended approach

Pre-compile LLD's `.s` test inputs to `.wasm` object files using `llvm-mc` and commit the binaries alongside human-readable `.wat` disassembly for review. This mirrors the `wild/tests/bins/` pattern used for ELF tests.

Alternatively, write new integration tests in the directive-based style (`wild/tests/sources/`) using C compiled with `clang --target=wasm32-wasi`.

### Useful Rust crates

- [`wasmparser`](https://crates.io/crates/wasmparser) -- parse WASM modules and object files (reads `linking`/`reloc.*` sections)
- [`wasm-encoder`](https://crates.io/crates/wasm-encoder) -- emit WASM modules
- Both from Bytecode Alliance, Apache-2.0 / MIT
