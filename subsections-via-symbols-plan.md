# subsections-via-symbols: Per-Symbol Section Splitting

## Problem

The `subsections-via-symbols` test expects that when `MH_SUBSECTIONS_VIA_SYMBOLS`
(0x2000) is set in an object's Mach-O header, each global symbol in `__text`
becomes its own subsection with independent alignment padding.

```asm
.subsections_via_symbols
.globl _fn1, _fn2
.text
.align 4          ; 16-byte alignment
_fn1: nop         ; 4 bytes
_fn2: nop         ; 4 bytes
```

Without subsections: `fn2 - fn1 = 4` (consecutive).
With subsections: `fn2 - fn1 = 16` (each symbol padded to section alignment).

## Previous Attempt

Implemented `section_size()` and `symbol_value_in_section()` overrides in
`macho.rs` that scanned ALL symbols per call to compute padded offsets.

**Result**: Correct output (`16 1`) but O(n^2) performance — a C++ object with
many symbols caused the test suite to go from 9s to 134s. Reverted.

## Proposed Approach: Use RelaxDeltaMap

Wild already has `section_relax_deltas` (`RelaxDeltaMap` / `SectionRelaxDeltas`)
for ELF relaxation. This is a sparse map of (input_offset -> cumulative_adjustment)
with O(log n) lookup via `partition_point`. It's used by `opt_input_to_output()`
at `layout.rs:3979-3982` to adjust symbol addresses.

The subsection padding can be expressed as "negative deletions" (insertions) at
symbol boundaries. The `RelaxDelta` struct tracks `cumulative_deleted`; for
subsection padding, this would be negative (cumulative_inserted).

### Alternative: Use a parallel `SubsectionDeltaMap`

Since `RelaxDelta.cumulative_deleted` is `u64` (unsigned), encoding insertions
needs a different representation. Options:

**A. Repurpose RelaxDeltaMap with signed cumulative field** — changes shared
infrastructure, risks breaking ELF.

**B. Create a separate `SubsectionPaddingMap`** — same structure but with
`cumulative_padding: u64` (added, not subtracted). Only populated for Mach-O
objects with `MH_SUBSECTIONS_VIA_SYMBOLS`.

**C. Store adjusted output offsets directly** — a per-section `Vec<(u64, u64)>`
mapping `(input_offset, output_offset)` for each symbol, populated once during
layout.

Option C is simplest and cleanest.

## Implementation Plan

### Step 1: Add subsection offset cache to ObjectLayoutState

In `layout.rs`, add a field to `ObjectLayoutState`:

```rust
/// For Mach-O objects with MH_SUBSECTIONS_VIA_SYMBOLS: maps
/// (section_index, input_offset) → output_offset for each global symbol.
/// Populated once during section loading, used by symbol resolution.
subsection_offsets: HashMap<usize, Vec<(u64, u64)>>,
```

Or more aligned with existing patterns, a sparse map similar to `RelaxDeltaMap`.

### Step 2: Populate during section loading

When loading a section from a Mach-O object with `flags & 0x2000`:

1. Collect all global symbol offsets within the section (sort by offset)
2. Compute padded output offset for each: `output = align_to(prev_end, section_align)`
3. Store the (input_offset → output_offset) mapping
4. Adjust the section's `size` field to the padded total

This runs ONCE per section (not per symbol), so it's O(n log n) total.

**Where**: In `ObjectLayoutState::load_section()` or the section loading path
(`layout.rs:3588-3616`), after the section slot transitions from Unloaded to
Loaded.

### Step 3: Use cache in symbol_value_in_section

In `layout.rs:3978-3982`, after `object.symbol_value_in_section()` returns the
raw input offset, check `subsection_offsets` for an adjusted value:

```rust
let input_offset = self.object.symbol_value_in_section(local_symbol, section_index)?;
let output_offset = if let Some(offsets) = self.subsection_offsets.get(&section_index.0) {
    // Binary search for this input_offset in the sorted pairs.
    offsets.iter()
        .find(|(inp, _)| *inp == input_offset)
        .map(|(_, out)| *out)
        .unwrap_or(input_offset)
} else {
    opt_input_to_output(self.section_relax_deltas.get(section_index.0), input_offset)
};
```

### Step 4: Adjust section size during loading

When populating the subsection cache, also update `Section::size` to the
padded total. This ensures the layout allocates enough space.

### Step 5: Adjust section data writing

In `write_object_sections` (`macho_writer.rs`), when copying section data
from an object with subsection padding, insert zero padding between symbol
boundaries to match the padded layout.

## Key Constraints

- `section_size()` is called once per section — fine for cache population
- `symbol_value_in_section()` is called once per symbol — must be O(log n) not O(n)
- The `File<'data>` struct stores `flags: u32` with MH_SUBSECTIONS_VIA_SYMBOLS
- Only `__text` sections need subsection splitting (data sections don't)
- The cache must survive from layout to the write phase

## Files to Modify

| File | Change |
| ---- | ------ |
| `libwild/src/layout.rs` | Add `subsection_offsets` to ObjectLayoutState, populate during section load, use in symbol resolution |
| `libwild/src/macho.rs` | Expose `has_subsections_via_symbols()` on File |
| `libwild/src/macho_writer.rs` | Insert padding when writing sections with subsection offsets |
| `wild/tests/sold_macho_tests.rs` | Un-skip subsections-via-symbols |

## Verification

```bash
cargo test --test sold_macho_tests -- --exact 'sold-macho/subsections-via-symbols' --include-ignored
cargo test --test sold_macho_tests  # full suite, check timing stays ~9s not ~130s
cargo test --test lld_macho_tests   # no regressions
```

## Complexity

Medium-high. The algorithm is straightforward (proven in the reverted attempt)
but the integration touches the layout pipeline's section loading and symbol
resolution paths. The main risk is ensuring the padded sizes propagate correctly
through the segment layout calculations.

## Relationship to order-file

`-order_file` requires subsections-via-symbols to reorder individual functions.
Once subsection splitting works, order-file becomes: sort the subsections by
the order file priority before writing. This is a natural follow-on.
