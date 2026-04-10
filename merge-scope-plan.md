# merge-scope: Weak Def Visibility Merging

## Problem

The `merge-scope` test has two objects defining `_foo` as a weak definition:

- `a.o`: `.weak_def_can_be_hidden` (n_desc = `N_WEAK_DEF | N_WEAK_REF` = 0x00C0)
- `b.o`: `.weak_definition` (n_desc = `N_WEAK_DEF` = 0x0080)

Expected: `_foo` appears in the exports trie (visible), because b.o's definition
is NOT "can be hidden". Currently `_foo` is absent from both the exports trie
and the nlist symbol table.

## Root Cause Analysis

Three interacting issues, from deepest to shallowest:

### 1. Mach-O export model differs from ELF (fundamental)

The exports trie is populated via `load_non_hidden_symbols()` in
`layout.rs:3697-3710`. This only runs when:

- `OutputKind::SharedObject` (dylibs), OR
- `needs_dynsym() && should_export_all_dynamic_symbols()`

For Mach-O executables, `should_export_all_dynamic_symbols()` returns
`self.export_dynamic` (default false). So **no symbols are exported to the
trie** unless `-export_dynamic` is passed.

This is correct for ELF but wrong for Mach-O. Apple's ld64 exports all
non-hidden external symbols to the trie by default for both executables
and dylibs.

**Attempted fix**: Setting `should_export_all_dynamic_symbols() = true`
unconditionally breaks the `export-dynamic` test, which specifically checks
that `_hello` is NOT in global symbols without `-export_dynamic`.

**The conflict**: `export-dynamic` test relies on the ELF behaviour where
symbols are NOT exported unless requested. But `merge-scope` relies on the
Mach-O behaviour where symbols ARE exported by default.

**Needed**: A way to export symbols to the Mach-O exports trie without
also adding them to the `EXPORT_DYNAMIC` flag path. The exports trie
and the `nm -g` output (nlist N_EXT) are different things:

- `nm -g` reads the nlist symbol table (controlled by `is_external` in
  `write_exe_symtab`)
- `objdump --macho --exports-trie` reads the LC_DYLD_EXPORTS_TRIE data
  (controlled by `dynamic_symbol_definitions`)

Currently both are conflated through `EXPORT_DYNAMIC`. They need to be
separated for Mach-O.

### 2. `visibility()` ignores N_WEAK_REF on defined symbols

`macho.rs:555-564`: The `visibility()` function only checks `N_PEXT`
in `n_type`. It ignores `N_WEAK_REF` in `n_desc` which means "can be
hidden". Both a.o and b.o report `Visibility::Default`.

**Fix**: Return `Visibility::Hidden` when a defined symbol has
`N_WEAK_REF` set in `n_desc`.

### 3. Visibility merge direction for weak defs

`symbol_db.rs:1235-1239`: `process_alternatives()` uses `max()` (most
restrictive wins). For Mach-O `weak_def_can_be_hidden`, the Apple
semantics are: the symbol is hidden only if ALL definitions have the
flag. If any definition is unconditionally visible, the result is visible.
This is `min()` (least restrictive wins).

**Fix**: Use `min()` for weak definitions (check `SymbolStrength::Weak`).

## Proposed Implementation

### Phase 1: Separate exports trie from EXPORT_DYNAMIC

Add a new code path in the Mach-O writer that populates the exports trie
from ALL resolved non-hidden symbols with non-zero addresses, independent
of the `EXPORT_DYNAMIC` flag. This can be done in `write_dylib_symtab` /
`write_exe_symtab` or as a separate function.

The exports trie writer (`macho_writer.rs:1033-1045`) already iterates
`dynamic_symbol_definitions`. Add a fallback: if `dynamic_symbol_definitions`
is empty for an executable, scan `symbol_resolutions` directly and include
all external non-hidden symbols.

### Phase 2: Fix visibility() for N_WEAK_REF

In `macho.rs:555-564`, return `Visibility::Hidden` when a defined symbol
has `N_WEAK_REF` set.

### Phase 3: Fix visibility merge for weak defs

In `symbol_db.rs:1235-1239`, use `min()` when all alternatives are weak.

### Phase 4: Verify

- `sold-macho/merge-scope` passes
- `sold-macho/export-dynamic` still passes (nm -g vs exports trie separation)
- Full test suite: no regressions

## Files to Modify

| File | Change |
| ---- | ------ |
| `libwild/src/macho_writer.rs` | Populate exports trie from all external symbols (not just EXPORT_DYNAMIC) |
| `libwild/src/macho.rs:555-564` | `visibility()`: return Hidden for N_WEAK_REF defined symbols |
| `libwild/src/symbol_db.rs:1235-1239` | `process_alternatives()`: use min() for weak defs |
| `wild/tests/sold_macho_tests.rs` | Un-skip merge-scope |

## Key Insight

The Mach-O exports trie serves a different purpose than ELF's .dynsym.
On Mach-O, the exports trie is used by dyld for ALL symbol resolution
(even in executables). On ELF, .dynsym is only for shared library
interop. Wild currently conflates them through `EXPORT_DYNAMIC`.
Separating these two concepts is the key architectural change needed.
