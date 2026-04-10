# Remaining Mach-O Work — 10 Tests + Architectural Issues

Status after session: **124 passed, 10 ignored** (from 100/34).

Dedicated plans exist for:
- `merge-scope-plan.md` — weak def visibility merging
- `subsections-via-symbols-plan.md` — per-symbol section splitting
- `tls-plan.md` — cross-dylib TLS and mismatch detection

## Remaining Tests

### order-file (blocked on subsections-via-symbols)

**Dependency**: Requires subsections-via-symbols to split `__text` at symbol
boundaries. Once that works, order-file is: sort subsections by order-file
priority before writing.

**Current state**: `-order_file` is parsed and symbol priorities are stored
in `MachOArgs::symbol_order: HashMap<String, u32>`. The reordering logic
is not implemented.

**Implementation**: After subsections-via-symbols lands, add a sort step in
`write_object_sections` that orders the subsection writes by priority from
`symbol_order`. Symbols not in the order file keep their original order.

### libunwind + objc-selector (blocked on Foundation framework)

Both tests fail because `_NSLog`, `_OBJC_CLASS_$_NSProcessInfo`, etc. are
undefined. The framework is linked (`-framework Foundation`) and wild's
framework resolution finds the `.tbd` file, but the symbols aren't extracted.

**Root cause**: Foundation.framework's `.tbd` re-exports from sub-libraries
(e.g., `/usr/lib/libobjc.A.dylib`, CoreFoundation). The current `.tbd`
parser (`collect_tbd_symbols`) reads the top-level `.tbd` but doesn't follow
re-export chains to the sub-libraries' `.tbd` files.

**Fix**: In `collect_tbd_symbols` (args/macho.rs), parse the `re-exports:`
field from the `.tbd` and recursively collect symbols from re-exported
libraries. Similar to how `collect_dylib_reexport_symbols` follows
`LC_REEXPORT_DYLIB` chains in binary dylibs.

**Additionally**: The `objc-selector` test needs full ObjC stub synthesis
(see ObjC section below), not just the current redirect-to-`_objc_msgSend`.

### literals (blocked on ARM64 compiler)

The test expects `__literal8` section dedup, but ARM64 Apple clang doesn't
emit `__literal8` sections for `double` constants — it encodes them as
immediates or in `__text`. The x86_64 compiler does emit them.

**Current state**: The literal merge infrastructure IS wired up (S_4BYTE/
S_8BYTE/S_16BYTE_LITERALS added to `is_merge_section()`, relocation handling
added). It will work when processing x86_64 objects or a future ARM64
compiler that emits literal sections.

**No code change needed** — just a compiler limitation. Could be tested
with a hand-crafted assembly test that explicitly creates `__literal8`.

## Architectural Issues

### Mach-O exports trie vs ELF .dynsym conflation

**Problem**: The exports trie is populated via `load_non_hidden_symbols()` →
`EXPORT_DYNAMIC` flag → `dynamic_symbol_definitions`. This only runs when
`should_export_all_dynamic_symbols()` is true. For Mach-O executables, this
defaults to false (only true with `-export_dynamic`).

But Mach-O executables SHOULD export all non-hidden symbols to the trie by
default. Setting `should_export_all_dynamic_symbols() = true` breaks the
`export-dynamic` test which checks `nm -g` (nlist) output.

**Root cause**: `nm -g` reads the nlist symbol table's N_EXT bit. The
exports trie is separate. Wild conflates them through `EXPORT_DYNAMIC`.

**Fix**: Separate the Mach-O exports trie population from the `EXPORT_DYNAMIC`
flag. Add a Mach-O-specific path in the writer that builds the trie from
all resolved external symbols, independent of the layout's dynamic export
marking.

**Blocks**: merge-scope test.

### ObjC _objc_msgSend$ full stub synthesis

**Current state**: `_objc_msgSend$<selector>` symbols are recognized (no
undefined error). The stub redirects to `_objc_msgSend` via a regular
12-byte PLT entry. The selector is NOT loaded into x1 — the call will
send the wrong selector.

**What's needed**: Full 32-byte stubs that:
1. Load selector string address into x1 from a `__objc_selrefs` entry
2. Load `_objc_msgSend` address from GOT into x16
3. Branch to x16
4. Pad to 32 bytes

This requires:
- A `__TEXT,__objc_methname` section with selector C-strings
- A `__DATA,__objc_selrefs` section with pointers to the strings
- 32-byte stub code in `__TEXT,__objc_stubs`
- Two GOT-like entries per stub: one for selref, one for msgSend

**Challenge**: The current allocation pipeline (12 bytes per stub, 8 bytes
per GOT entry) can't accommodate this. Options:

A. Synthesize everything post-layout in segment gaps (like init_offsets)
B. Add ObjC-specific allocation (detect at resolution time, allocate larger)
C. Use a separate output section for ObjC stubs (not PLT_GOT)

Option C is cleanest: add a dedicated output section for `__objc_stubs`
and `__objc_selrefs`, sized during layout based on the count of
`_objc_msgSend$*` symbols.

**Blocks**: objc-selector, libunwind (both need Foundation which needs
ObjC stubs).

### Foundation .tbd re-export chain following

**Problem**: `-framework Foundation` links Foundation.framework which has
a `.tbd` stub file. The `.tbd` lists re-exports to sub-libraries like
`/usr/lib/libobjc.A.dylib` and CoreFoundation. Wild's `.tbd` parser
doesn't follow these re-export chains.

**Impact**: Symbols like `_NSLog`, `_objc_msgSend`, `_OBJC_CLASS_$_*` are
"undefined" even though Foundation is linked.

**Fix**: Extend `collect_tbd_symbols` and `parse_tbd_install_name` to:
1. Parse `re-exports:` entries from `.tbd` files
2. Resolve re-exported library paths (may use `@rpath`, install names)
3. Recursively collect symbols from re-exported `.tbd` files
4. Add all collected symbols to `dylib_symbols`

## Priority Order

1. **Mach-O exports trie separation** — unblocks merge-scope (1 test)
2. **TLS Phase 1** (tls-plan.md) — unblocks tls, tls-dylib (2 tests)
3. **TLS Phase 2** (tls-plan.md) — unblocks tls-mismatch, tls-mismatch2 (2 tests)
4. **Subsections-via-symbols** (subsections-via-symbols-plan.md) — unblocks 1 test + order-file
5. **Foundation .tbd re-exports** — unblocks libunwind, objc-selector framework linking
6. **ObjC full stubs** — unblocks objc-selector runtime behavior
7. **Order-file** — blocked on #4
8. **literals** — blocked on compiler, infrastructure already done
