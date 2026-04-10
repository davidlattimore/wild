# TLS: Cross-Dylib and Type Mismatch

## Problem

Four failing TLS tests:

| Test | What | Failure |
| ---- | ---- | ------- |
| `tls` | exe links dylib with `_Thread_local int b; _Thread_local int c = 5;` | Segfault at runtime |
| `tls-dylib` | Same pattern, TLS defined in dylib | Segfault at runtime |
| `tls-mismatch` | `a.o` defines regular `int a`, `c.o` references as `_Thread_local` | Should error, doesn't (dylib case) |
| `tls-mismatch2` | `a.o` defines `_Thread_local int a`, `c.o` references as regular `int` | Should error, doesn't (dylib case) |

## Root Causes

### 1. `is_tls()` always returns false (macho.rs:601-604)

```rust
fn is_tls(&self) -> bool {
    false  // WRONG — should check section type
}
```

The symbol trait method `is_tls()` never reports true for Mach-O symbols.
This means the resolution pipeline can't distinguish TLS from regular symbols.

**Fix**: Check if the symbol's section (from `n_sect`) has type
`S_THREAD_LOCAL_VARIABLES` (0x13), `S_THREAD_LOCAL_REGULAR` (0x11), or
`S_THREAD_LOCAL_ZEROFILL` (0x12).

**Challenge**: `is_tls()` takes `&self` (just the nlist entry) and doesn't
have access to the section table. The section type is in the section header,
not the symbol. Options:

- **A**: Store a `is_tls` flag per symbol during parsing (extend the SymtabEntry wrapper)
- **B**: Add section table access to the Symbol trait (breaking change)
- **C**: Check `n_sect` against known TLS section indices cached in `File`

Option C is most practical: during `File::parse()`, record which section
indices are TLS. Then `is_tls()` checks `sections[n_sect-1].flags & 0xFF`
against TLS types. But `is_tls()` only has `&self` (the nlist), not the File.

Option A is cleanest: wrap the nlist with a bool flag set during symbol
enumeration. But `SymtabEntry` is currently `(macho::Nlist64<Endianness>)`.

**Simplest approach**: Store a `BitVec` or `HashSet<u8>` of TLS section
indices in `File`, and pass it through to `is_tls()` somehow. Or change
the `Symbol` trait to accept the `File` reference.

Actually — `is_tls()` is on `impl Symbol for SymtabEntry` which is a newtype
around `macho::Nlist64`. We can't add state. But we CAN check indirectly:
if the symbol's `n_desc` has `N_WEAK_DEF` that doesn't help. The only way
is to check the section type.

**Pragmatic approach**: Don't fix `is_tls()` directly. Instead, add TLS
checking at the points where it matters:
- Relocation processing (already done for object-to-object case)
- Dylib symbol import (new — needs TLS info from dylib parsing)
- Symbol resolution mismatch detection (new)

### 2. Cross-dylib TLS segfault (tls, tls-dylib tests)

When an executable references `extern _Thread_local int b` from a dylib,
the compiler generates:

1. A TLV descriptor in `__thread_vars` with `_b` as the symbol name
2. Code that loads the descriptor address via TLVP relocations (type 8/9)
3. A call to `tlv_get_addr` which reads the descriptor to find the actual
   thread-local storage

For a locally-defined TLS var, the TLV descriptor contains:
- `_tlv_bootstrap` function pointer (bound by dyld)
- pthread key (0, filled by runtime)
- offset into thread-local template data

For an extern TLS var from a dylib, the EXECUTABLE needs its own TLV
descriptor that references the dylib's TLS. But currently wild doesn't
create descriptors for extern TLS — it tries to resolve the symbol as
a regular import, which puts a regular GOT entry instead of a TLV
descriptor. At runtime, the code tries to use this as a TLV descriptor
and segfaults.

**What system ld64 does**: For each extern TLS symbol from a dylib, ld64
creates a "TLV descriptor" entry in the executable's `__thread_vars` that
binds to the dylib's TLV descriptor. The bind is a special `BIND_OPCODE_SET_TYPE_IMM(3)` (BIND_TYPE_THREADED_REBASE/BIND is NOT used — instead the standard dyld bind with type=TLV is used for the `_tlv_bootstrap` pointer slot).

Actually, for extern TLS from a dylib, the executable's code still
references the symbol via TLVP relocations. The linker creates a stub
TLV descriptor in `__thread_vars` where:
- slot 0 (`_tlv_bootstrap`): bind to dylib's `_tlv_bootstrap`
- slot 8 (key): 0
- slot 16 (offset): 0 (dylib handles this)

The bind entry uses the symbol's actual name (e.g., `_b`), and dyld
resolves it to the dylib's TLV descriptor address. The code then loads
from this descriptor.

**Simpler model**: Actually, for dylib TLS, the executable doesn't need
its own TLV descriptor. It just needs a GOT-like entry that points to the
dylib's TLV descriptor. The TLVP relocation loads this pointer, and the
runtime calls `tlv_get_addr` with it. The pointer is bound by dyld to
the dylib's `__thread_vars` entry.

This is essentially a GOT entry that resolves to a TLV descriptor address
in the dylib. The current code creates a regular GOT entry (which gets
bound to `_b`'s regular address, not the TLV descriptor) — hence the segfault.

### 3. Mismatch detection from dylibs (tls-mismatch tests)

The current TLS mismatch check (macho_writer.rs:2732-2758) only fires when
`orig_target_addr != 0` (defined symbol). For dylib symbols, `orig_target_addr == 0`
(undefined), so the check is skipped.

To detect mismatches involving dylib symbols, we need to know if the dylib's
symbol is TLS or not. This info isn't in the export trie (which only has
names and addresses). It would need to come from:
- The dylib's symbol table (nlist entries have section indices)
- The `.tbd` file (doesn't include TLS info)
- A heuristic: if the relocation is TLVP (type 8/9) and the symbol doesn't
  have a corresponding `__thread_vars` entry, it's a mismatch

**Pragmatic approach for tls-mismatch**: When parsing a dylib via
`handle_dylib_input`, also scan the nlist symbol table for TLS symbols
(check section type). Store a set of TLS symbol names alongside
`dylib_symbols`. Then at mismatch check time, compare.

## Implementation Plan

### Phase 1: Fix cross-dylib TLS (tls, tls-dylib)

The goal: when an extern TLS symbol from a dylib is referenced via TLVP
relocations, create a bind fixup that resolves to the dylib's TLV descriptor.

1. **Detect TLVP relocations to undefined symbols** — in the relocation
   processing (macho_writer.rs type 8/9), when `orig_target_addr == 0`:
   - Create a bind fixup in the GOT for the symbol
   - The GOT entry will be bound by dyld to the dylib's `__thread_vars` entry
   - The TLVP reloc loads this GOT address, which is the TLV descriptor

2. **Ensure the GOT entry is allocated** — TLVP relocs (type 8/9) need GOT
   entries. Currently `load_object_section_relocations` (macho.rs:1076-1085)
   doesn't allocate GOT for type 8/9 relocs targeting undefined symbols:
   ```rust
   8 | 9 => ValueFlags::DIRECT,  // WRONG — needs GOT for extern TLS
   ```
   Fix: when type 8/9 targets an undefined extern, set `ValueFlags::GOT`.

3. **Use the GOT address in TLVP relocation** — in `apply_relocations`
   type 8/9 handling, when `got_addr` is available, use it instead of
   `target_addr` (similar to GOT_LOAD type 5/6).

### Phase 2: Fix tls-mismatch detection from dylibs

1. **During dylib parsing** (`handle_dylib_input` in args/macho.rs):
   - After reading the export trie, also scan the nlist symbol table
   - For symbols in sections with type 0x11/0x12/0x13, add to a
     `dylib_tls_symbols: HashSet<Vec<u8>>` set in MachOArgs

2. **At mismatch check time** (macho_writer.rs type 8/9):
   - For extern symbols from dylibs (`orig_target_addr == 0`), check if
     the symbol is in `dylib_tls_symbols`
   - If a TLVP reloc references a symbol NOT in `dylib_tls_symbols`, error

3. **Reverse mismatch** (tls-mismatch2):
   - When a non-TLVP reloc (type 0/3/4) references a symbol that IS in
     `dylib_tls_symbols`, error

### Phase 3: Fix is_tls() (optional but correct)

If needed for other consumers of the Symbol trait:
- Cache TLS section indices in `File<'data>` during parsing
- Add a `tls_sections: Vec<bool>` (indexed by section index)
- In `is_tls()`, check `self.n_sect()` against the cached list

This requires changing the `SymtabEntry` newtype or the `File` struct.

## Files to Modify

| File | Change |
| ---- | ------ |
| `libwild/src/macho.rs:1076-1085` | Allocate GOT for TLVP relocs to undefined symbols |
| `libwild/src/macho_writer.rs:2732-2758` | Use GOT for extern TLVP, add dylib mismatch check |
| `libwild/src/args/macho.rs` | Add `dylib_tls_symbols` set, populate in `handle_dylib_input` |
| `wild/tests/sold_macho_tests.rs` | Un-skip tls, tls-dylib, tls-mismatch, tls-mismatch2 |

## Verification

```bash
cargo test --test sold_macho_tests 'tls' -- --include-ignored
cargo test --test sold_macho_tests  # full suite
```

## Complexity

Phase 1 (cross-dylib TLS): Medium — allocate GOT for TLVP, use GOT address
in relocation. Main risk: GOT binding for TLS might need different semantics
than regular GOT.

Phase 2 (mismatch from dylibs): Medium — parse nlist from dylib for TLS info.
Main risk: performance (scanning nlist for every dylib).

Phase 3 (is_tls): Low — mechanical caching.
