//! Reconnaissance: how much of `.debug_info` is structural DIE
//! redundancy that a `dsymutil`-style cross-CU dedup pass could
//! collapse?
//!
//! Walks every Compilation Unit, hashes each "interesting" DIE
//! subtree (types + functions + namespaces — the bits that
//! typically duplicate across CUs in a Rust workspace), and
//! reports:
//!   - Total CUs.
//!   - Total interesting DIEs.
//!   - Number of distinct content hashes.
//!   - Bytes spent on duplicates (sum of subtree-byte-sizes for
//!     every-but-the-first occurrence of each hash).
//!
//! That last number is the upper bound on what cross-CU DIE dedup
//! could save on this binary. Compare against `.debug_info` total
//! to know if the prize is real.
//!
//! Limitations:
//!   - Hash is over (tag, attribute spec list, attribute raw bytes,
//!     children's hashes recursively). Two DIEs that differ only in
//!     a `DW_AT_decl_file` (file-table index) hash differently even
//!     if logically the same type — so the reported saving is a
//!     LOWER bound after that adjustment. Real dedup tools normalise
//!     such "incidental" attributes; for recon, ignore.
//!   - Strings reached via `DW_FORM_strp` are compared by *offset
//!     into `.debug_str`*, not content. That's fine because wild
//!     already merges `.debug_str` so equal strings → equal offsets.
//!
//! Usage:
//!   dwarf-recon <path/to/elf>

use blake3::Hasher;
use gimli::EndianSlice;
use gimli::LittleEndian;
use object::Object;
use object::ObjectSection;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::process::ExitCode;

type Slice<'a> = EndianSlice<'a, LittleEndian>;

#[derive(Default, Debug)]
struct Stats {
    cu_count: usize,
    interesting_dies: usize,
    interesting_die_bytes: u64,
    distinct_hashes: usize,
    duplicate_die_count: usize,
    duplicate_die_bytes: u64,
    by_tag: HashMap<u16, TagStats>,
    debug_info_total: u64,
    debug_str_total: u64,
}

#[derive(Default, Debug, Clone)]
struct TagStats {
    count: usize,
    distinct_hashes: usize,
    duplicate_count: usize,
    duplicate_bytes: u64,
}

fn is_interesting_tag(tag: gimli::DwTag) -> bool {
    use gimli::constants::*;
    matches!(
        tag,
        DW_TAG_structure_type
            | DW_TAG_class_type
            | DW_TAG_union_type
            | DW_TAG_enumeration_type
            | DW_TAG_array_type
            | DW_TAG_pointer_type
            | DW_TAG_reference_type
            | DW_TAG_const_type
            | DW_TAG_volatile_type
            | DW_TAG_typedef
            | DW_TAG_subroutine_type
            | DW_TAG_template_type_parameter
            | DW_TAG_template_value_parameter
            | DW_TAG_subprogram
            | DW_TAG_namespace
    )
}

fn analyse(elf_bytes: &[u8]) -> Result<Stats, String> {
    let obj = object::File::parse(elf_bytes).map_err(|e| format!("parse: {e}"))?;
    let mut stats = Stats::default();

    let load_section = |id: gimli::SectionId| -> Result<Slice<'_>, String> {
        let name = id.name();
        let data = obj
            .section_by_name(name)
            .map(|s| s.data().unwrap_or(&[]))
            .unwrap_or(&[]);
        Ok(EndianSlice::new(data, LittleEndian))
    };

    let dwarf = gimli::Dwarf::load(load_section).map_err(|e| format!("dwarf load: {e}"))?;

    if let Some(s) = obj.section_by_name(".debug_info") {
        stats.debug_info_total = s.size();
    }
    if let Some(s) = obj.section_by_name(".debug_str") {
        stats.debug_str_total = s.size();
    }

    let mut hash_to_count: HashMap<[u8; 32], usize> = HashMap::new();
    let mut hash_to_bytes: HashMap<[u8; 32], u64> = HashMap::new();

    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(|e| format!("units: {e}"))? {
        stats.cu_count += 1;
        let unit = dwarf
            .unit(header)
            .map_err(|e| format!("unit @ {:?}: {e}", header.offset()))?;
        let unit_ref = unit.unit_ref(&dwarf);
        walk_unit(&unit_ref, &mut stats, &mut hash_to_count, &mut hash_to_bytes)
            .map_err(|e| format!("walk_unit: {e}"))?;
    }

    stats.distinct_hashes = hash_to_count.len();
    for (&hash, &count) in &hash_to_count {
        if count > 1 {
            stats.duplicate_die_count += count - 1;
            // Bytes saved if every duplicate were a reference instead.
            // Approximate: (count - 1) * average_size_for_hash.
            let bytes = hash_to_bytes[&hash];
            stats.duplicate_die_bytes += bytes * (count as u64 - 1);
        }
    }

    Ok(stats)
}

/// Walk every DIE in the unit; for each "interesting" tag, compute
/// a content hash of the DIE subtree (tag + attributes + children's
/// hashes) and record its on-disk byte size.
fn walk_unit(
    unit: &gimli::UnitRef<Slice<'_>>,
    stats: &mut Stats,
    hash_to_count: &mut HashMap<[u8; 32], usize>,
    hash_to_bytes: &mut HashMap<[u8; 32], u64>,
) -> Result<(), String> {
    let mut entries = unit.entries();
    let mut tree_stack: Vec<DieFrame> = Vec::new();

    while let Some((delta_depth, entry)) = entries.next_dfs().map_err(|e| format!("dfs: {e}"))? {
        // Pop frames as we move shallower.
        if delta_depth < 0 {
            for _ in 0..(-delta_depth) {
                if let Some(frame) = tree_stack.pop() {
                    finalize_frame(frame, stats, hash_to_count, hash_to_bytes);
                }
            }
        }

        let tag = entry.tag();
        let interesting = is_interesting_tag(tag);

        let mut frame = DieFrame {
            tag,
            interesting,
            hasher: Hasher::new(),
            byte_size_estimate: 0,
            child_hashes: Vec::new(),
        };
        // Hash the tag.
        frame.hasher.update(&tag.0.to_le_bytes());

        // Hash all attributes' raw forms + values.
        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next().map_err(|e| format!("attr: {e}"))? {
            frame.hasher.update(&attr.name().0.to_le_bytes());
            // Some attributes are "incidental": file indexes, line
            // numbers, comp_dir-relative offsets. Skip them so two
            // logically-equivalent DIEs from different CUs hash equal.
            if is_incidental_attr(attr.name()) {
                continue;
            }
            let value = attr.value();
            hash_attr_value(&mut frame.hasher, &value);
        }
        // Each DIE costs roughly: 1 byte abbrev + sum(attr form sizes).
        // Without an exact byte-count from gimli we estimate ~32 bytes/DIE
        // for "interesting" tags. Refine later if we want a tighter bound.
        frame.byte_size_estimate = 32;

        tree_stack.push(frame);

        // If the entry has no children, immediately collapse this frame.
        if !entry.has_children() {
            if let Some(frame) = tree_stack.pop() {
                finalize_frame(frame, stats, hash_to_count, hash_to_bytes);
            }
        }
    }

    // Drain remaining frames (the unit DIE itself, etc).
    while let Some(frame) = tree_stack.pop() {
        finalize_frame(frame, stats, hash_to_count, hash_to_bytes);
    }
    Ok(())
}

fn is_incidental_attr(name: gimli::DwAt) -> bool {
    use gimli::constants::*;
    matches!(
        name,
        DW_AT_decl_file
            | DW_AT_decl_line
            | DW_AT_decl_column
            | DW_AT_call_file
            | DW_AT_call_line
            | DW_AT_call_column
            | DW_AT_low_pc
            | DW_AT_high_pc
            | DW_AT_ranges
            | DW_AT_entry_pc
            | DW_AT_sibling
    )
}

fn hash_attr_value(h: &mut Hasher, value: &gimli::AttributeValue<Slice<'_>>) {
    use gimli::AttributeValue::*;
    // We hash a discriminant + payload bytes. Ranges, expressions,
    // and CU-relative refs don't survive cross-CU dedup as-is so we
    // hash by their content where possible.
    match value {
        Addr(a) => {
            h.update(&[1u8]);
            h.update(&a.to_le_bytes());
        }
        Block(b) => {
            h.update(&[2u8]);
            h.update(b.slice());
        }
        Data1(v) => {
            h.update(&[3u8]);
            h.update(&[*v]);
        }
        Data2(v) => {
            h.update(&[4u8]);
            h.update(&v.to_le_bytes());
        }
        Data4(v) => {
            h.update(&[5u8]);
            h.update(&v.to_le_bytes());
        }
        Data8(v) => {
            h.update(&[6u8]);
            h.update(&v.to_le_bytes());
        }
        Sdata(v) => {
            h.update(&[7u8]);
            h.update(&v.to_le_bytes());
        }
        Udata(v) => {
            h.update(&[8u8]);
            h.update(&v.to_le_bytes());
        }
        DebugStrRef(off) => {
            // Wild already merges .debug_str; equal strings give equal
            // offsets, so hashing the offset is correct.
            h.update(&[9u8]);
            h.update(&off.0.to_le_bytes());
        }
        String(s) => {
            h.update(&[10u8]);
            h.update(s.slice());
        }
        Flag(f) => {
            h.update(&[11u8]);
            h.update(&[*f as u8]);
        }
        UnitRef(r) => {
            // Intra-CU reference. Two different CUs with "the same"
            // local DIE structure will have different UnitRef offsets.
            // For dedup-recon purposes we hash nothing — this is the
            // single biggest source of "looks duplicate but hashes
            // different." Acceptable for an upper-bound estimate.
            h.update(&[12u8]);
            let _ = r;
        }
        DebugInfoRef(_) => {
            h.update(&[13u8]);
        }
        DebugLineRef(_) => {
            h.update(&[14u8]);
        }
        DebugRngListsBase(_) | DebugRngListsIndex(_) | RangeListsRef(_) => {
            h.update(&[15u8]);
        }
        DebugLocListsBase(_) | DebugLocListsIndex(_) | LocationListsRef(_) => {
            h.update(&[16u8]);
        }
        Exprloc(e) => {
            h.update(&[17u8]);
            h.update(e.0.slice());
        }
        DebugTypesRef(s) => {
            h.update(&[18u8]);
            h.update(&s.0.to_le_bytes());
        }
        SecOffset(_) => {
            h.update(&[19u8]);
        }
        Encoding(e) => {
            h.update(&[20u8]);
            h.update(&[e.0]);
        }
        DecimalSign(d) => {
            h.update(&[21u8]);
            h.update(&[d.0]);
        }
        Endianity(e) => {
            h.update(&[22u8]);
            h.update(&[e.0]);
        }
        Accessibility(a) => {
            h.update(&[23u8]);
            h.update(&[a.0]);
        }
        Visibility(v) => {
            h.update(&[24u8]);
            h.update(&[v.0]);
        }
        Virtuality(v) => {
            h.update(&[25u8]);
            h.update(&[v.0]);
        }
        Language(l) => {
            h.update(&[26u8]);
            h.update(&l.0.to_le_bytes());
        }
        Inline(i) => {
            h.update(&[27u8]);
            h.update(&[i.0]);
        }
        AddressClass(a) => {
            h.update(&[28u8]);
            h.update(&a.0.to_le_bytes());
        }
        Ordering(o) => {
            h.update(&[29u8]);
            h.update(&[o.0]);
        }
        IdentifierCase(i) => {
            h.update(&[30u8]);
            h.update(&[i.0]);
        }
        CallingConvention(c) => {
            h.update(&[31u8]);
            h.update(&[c.0]);
        }
        DwoId(d) => {
            h.update(&[32u8]);
            h.update(&d.0.to_le_bytes());
        }
        // Fallback: hash a discriminant only.
        _ => {
            h.update(&[255u8]);
        }
    }
}

struct DieFrame {
    tag: gimli::DwTag,
    interesting: bool,
    hasher: Hasher,
    byte_size_estimate: u64,
    child_hashes: Vec<[u8; 32]>,
}

fn finalize_frame(
    mut frame: DieFrame,
    stats: &mut Stats,
    hash_to_count: &mut HashMap<[u8; 32], usize>,
    hash_to_bytes: &mut HashMap<[u8; 32], u64>,
) {
    // Mix children's hashes into this DIE's hash so subtrees compose.
    for ch in &frame.child_hashes {
        frame.hasher.update(ch);
    }
    let h: [u8; 32] = *frame.hasher.finalize().as_bytes();

    if frame.interesting {
        stats.interesting_dies += 1;
        stats.interesting_die_bytes += frame.byte_size_estimate;
        *hash_to_count.entry(h).or_insert(0) += 1;
        hash_to_bytes
            .entry(h)
            .and_modify(|b| *b = (*b).max(frame.byte_size_estimate))
            .or_insert(frame.byte_size_estimate);

        let entry = stats.by_tag.entry(frame.tag.0).or_default();
        entry.count += 1;
    }
}

fn dwtag_name(tag: u16) -> &'static str {
    use gimli::constants::*;
    let t = gimli::DwTag(tag);
    match t {
        DW_TAG_structure_type => "structure_type",
        DW_TAG_class_type => "class_type",
        DW_TAG_union_type => "union_type",
        DW_TAG_enumeration_type => "enumeration_type",
        DW_TAG_array_type => "array_type",
        DW_TAG_pointer_type => "pointer_type",
        DW_TAG_reference_type => "reference_type",
        DW_TAG_const_type => "const_type",
        DW_TAG_volatile_type => "volatile_type",
        DW_TAG_typedef => "typedef",
        DW_TAG_subroutine_type => "subroutine_type",
        DW_TAG_template_type_parameter => "template_type_param",
        DW_TAG_template_value_parameter => "template_value_param",
        DW_TAG_subprogram => "subprogram",
        DW_TAG_namespace => "namespace",
        _ => "other",
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: {} <path/to/elf>", args[0]);
        return ExitCode::from(1);
    }
    let bytes = match fs::read(&args[1]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read: {e}");
            return ExitCode::from(1);
        }
    };

    let stats = match analyse(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("analyse: {e}");
            return ExitCode::from(2);
        }
    };

    println!("== {}", args[1]);
    println!(
        "  .debug_info: {} bytes,   .debug_str: {} bytes",
        stats.debug_info_total, stats.debug_str_total
    );
    println!("  CUs: {}", stats.cu_count);
    println!(
        "  interesting DIEs: {} (estimated {} bytes)",
        stats.interesting_dies, stats.interesting_die_bytes
    );
    println!(
        "  distinct content hashes: {}",
        stats.distinct_hashes
    );
    println!(
        "  duplicate DIEs (above the first per hash): {} ({} bytes)",
        stats.duplicate_die_count, stats.duplicate_die_bytes
    );
    if stats.interesting_die_bytes > 0 {
        println!(
            "  upper-bound saving on interesting DIEs: {:.2}%",
            100.0 * stats.duplicate_die_bytes as f64 / stats.interesting_die_bytes as f64
        );
    }
    println!("\n  by tag:");
    let mut tags: Vec<_> = stats.by_tag.iter().collect();
    tags.sort_by_key(|(_, s)| std::cmp::Reverse(s.count));
    for (tag, ts) in tags.iter().take(15) {
        println!("    {:>22}: {:>9} DIEs", dwtag_name(**tag), ts.count);
    }
    ExitCode::SUCCESS
}
