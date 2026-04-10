# Mach-O cstring merging implementation plan

## Goal

Enable `S_CSTRING_LITERALS` section merging for Mach-O, reusing the existing
`string_merging.rs` infrastructure that works for ELF.

## Current state

The generic pipeline already works for Mach-O identification:

- `macho.rs:402` `is_merge_section()` returns true for `S_CSTRING_LITERALS`
- `macho.rs:409` `is_strings()` returns true for cstring sections
- `resolution.rs:1119` `should_merge_sections()` gates on `args.should_merge_sections()`
- `string_merging.rs` is fully platform-generic (works for both ELF and Mach-O)

Flipping `MachOArgs::should_merge_sections()` to true activates the pipeline
but causes 40 test failures because the Mach-O writer doesn't handle merged
sections.

## What already works (no changes needed)

| Phase | File | Status |
| ----- | ---- | ------ |
| Section detection | `resolution.rs:1119-1230` | `SectionSlot::MergeStrings` created correctly |
| Input collection | `layout.rs:118` | `StringMergeInputs::new()` gathers Mach-O sections |
| Deduplication | `string_merging.rs:216` | `merge_strings()` is platform-generic |
| Address computation | `string_merging.rs:1093` | `MergedStringStartAddresses::compute()` works |
| Symbol resolution | `layout.rs:3936` | `get_merged_string_output_address()` called when `section_resolutions[i].address() == None` |
| Section resolution | `layout.rs:3848` | MergeStrings sections get `SectionResolution::none()` |

## What needs changing

### Step 1: Enable the flag

**File:** `libwild/src/args/macho.rs:230`

```rust
fn should_merge_sections(&self) -> bool {
    true
}
```

This activates the pipeline. All subsequent steps fix the breakage.

### Step 2: Write merged string data into the Mach-O output

**File:** `libwild/src/macho_writer.rs`

**Problem:** The ELF writer has `write_merged_strings()` (elf_writer.rs:3320) that
writes deduplicated bucket data into `OutputSectionPartMap` buffers. The Mach-O writer
doesn't use `OutputSectionPartMap` -- it writes directly to a flat `out: &mut [u8]`
buffer using file offsets computed from `SegmentMapping`.

**Solution:** Add a `write_merged_strings_macho()` function called from the main Mach-O
write path. This function:

1. Iterates `layout.merged_strings.for_each(|section_id, merged| { ... })`
2. For each merged section, looks up the output section's VM address from the layout
3. Maps VM address to file offset via `vm_addr_to_file_offset()`
4. Writes bucket data sequentially: for each bucket, for each string, copy to output

**Reference:** `elf_writer.rs:3320-3341` -- the logic is identical, just the buffer
access differs.

**Key question:** Where does the merged section's VM address come from? The
`MergedStringStartAddresses` stores per-bucket addresses. The first bucket's address
is the section start. We need:

```rust
fn write_merged_strings_macho(
    out: &mut [u8],
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
) {
    layout.merged_strings.for_each(|section_id, merged| {
        if merged.len() == 0 { return; }
        let bucket_addrs = layout.merged_string_start_addresses
            .get(section_id);
        for (i, bucket) in merged.buckets.iter().enumerate() {
            let vm_addr = bucket_addrs[i];
            let Some(file_offset) = vm_addr_to_file_offset(vm_addr, mappings) else {
                continue;
            };
            let mut pos = file_offset as usize;
            for string in &bucket.strings {
                let end = pos + string.len();
                if end <= out.len() {
                    out[pos..end].copy_from_slice(string);
                }
                pos = end;
            }
        }
    });
}
```

**Call site:** In `write_file()` (macho_writer.rs), after `write_object_sections()` and
before LINKEDIT writing. Approximately line 540 area.

### Step 3: Don't copy input data for merged sections

**File:** `libwild/src/macho_writer.rs`, `write_object_sections()` (~line 1618)

**Current:** Line 1620 skips sections where `section_res.address() == None`. This
correctly skips MergeStrings sections (they get `SectionResolution::none()`).

**Problem:** The section's input data is correctly NOT copied (good), but relocations
FROM other sections INTO the merged section need to resolve to merged addresses.
The relocation target resolution at line ~1795 computes:

```rust
sec_out + sym.n_value(le).wrapping_sub(sec_in)
```

For merged sections, `sec_out` is `None` so this path fails.

**Solution:** In the relocation resolution code (`apply_relocations`), when the target
symbol's section has `address() == None`, call `get_merged_string_output_address()`:

```rust
// In the symbol address computation path:
let target_addr = if let Some(sec_out) = obj.section_resolutions
    .get(sec_idx).and_then(|r| r.address())
{
    // Normal path: section base + offset
    sec_out + sym.n_value(le).wrapping_sub(sec_in)
} else {
    // Merged string path: look up in dedup map
    get_merged_string_output_address::<MachO>(
        sym_idx, addend, obj.object, &obj.sections,
        &layout.merged_strings,
        &layout.merged_string_start_addresses,
        false,
    )?.unwrap_or(0)
};
```

**Reference:** `elf_writer.rs:3170-3178` and `layout.rs:3936-3943` -- both use
`get_merged_string_output_address()` as the fallback when section address is None.

### Step 4: Handle section size accounting

**File:** `libwild/src/macho_writer.rs`

The Mach-O header writing (`write_headers`) computes segment/section sizes from the
memory layout. Merged strings contribute to the `__TEXT` segment (since `__cstring`
is in TEXT). The layout's `starting_mem_offsets_by_group` already accounts for merged
string sizes (the `OutputSectionPartMap` includes their allocations).

**Verify:** Check that `text_vm_end` in `write_headers()` already includes the
merged string section size. If the layout allocates VM space for merged strings
correctly (which it should, since the generic layout code handles this), then the
segment sizes should be correct automatically.

**Potential issue:** The Mach-O section headers list `__cstring` with a specific
`addr`, `size`, `offset`. If merged strings change the section's size, the section
header must reflect this. Currently section headers are generated from input sections
-- merged sections may need their own output section header.

This is the subtlest part. The section header generation in `write_headers()` needs
to handle the case where a `__cstring` section's data comes from merged buckets
rather than concatenated input sections.

### Step 5: Verify relocation application for non-extern relocations

**File:** `libwild/src/macho_writer.rs`, `apply_relocations()` (~line 1743)

Non-extern Mach-O relocations (r_extern=0) use section ordinals. When the target
section is a merged string section, `r_symbolnum` is the 1-based section ordinal.
The code at line ~2340 computes:

```rust
let sec_out = obj.section_resolutions.get(sec_idx)?.address()?;
```

For merged sections, `address()` returns `None` and the relocation silently fails
(returns `None` from the helper). This needs the same merged-string fallback as
Step 3.

## Implementation order

1. **Step 2 first** (write merged data) -- safest, no regressions possible since
   merging isn't enabled yet
2. **Step 3 + 5** (relocation resolution) -- fix the address computation fallback
3. **Step 4** (section headers) -- verify sizes are correct, fix if needed
4. **Step 1 last** (flip the flag) -- enable merging and run tests

## Testing

The `sold-macho/cstring` test verifies:

- Two objects with identical string `"Hello world\n"` share the same pointer
- Different string `"Howdy world\n"` gets a different pointer
- Output: `1 0` (x==y, y!=z)

Also verify: the `sold-macho/literals` test may also benefit (literal section merging).

## Risk

The Mach-O section header generation is the highest-risk area. The current code
generates `__cstring` headers from individual input sections. With merging, the
output `__cstring` section has a different size and offset than any single input.
May need to synthesize a section header for the merged output.

Run the full test suite (all 3 Mach-O test suites, 140+ tests) after each step
to catch regressions early.
