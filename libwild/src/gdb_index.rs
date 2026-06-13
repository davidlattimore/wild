//! Generates a `.gdb_index` section.
//!
//! The `.gdb_index` section is an accelerator structure that lets GDB skip parsing all
//! `.debug_info` at startup. We emit version 9, which includes a shortcut table.
//!
//! Format reference: <https://sourceware.org/gdb/current/onlinedocs/gdb.html/Index-Section-Format.html>

use crate::elf::Elf;
use crate::error::Context as _;
use crate::error::Result;
use crate::layout::FileLayout;
use crate::layout::FileLayoutState;
use crate::layout::GroupState;
use crate::layout::Layout;
use crate::output_section_id::SectionName;
use crate::platform::ObjectFile as _;
use crate::platform::SectionHeader as _;
use crate::resolution::SectionSlot;
use crate::timing_phase;
use crate::verbose_timing_phase;
use hashbrown::HashMap;
use itertools::Itertools as _;
use linker_utils::bit_misc::BitExtraction;
use linker_utils::elf::secnames;
use linker_utils::elf::secnames::DEBUG_INFO_SECTION_NAME;
use linker_utils::elf::secnames::DEBUG_INFO_SECTION_NAME_STR;
use linker_utils::utils::u32_from_slice;
use linker_utils::utils::u64_from_slice;
use object::read::elf::SectionHeader as _;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::mem::size_of;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

const GDB_INDEX_VERSION: u32 = 9;

#[derive(Debug, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C, packed)]
struct GdbIndexHeader {
    version: u32,
    cu_list_offset: u32,
    tu_list_offset: u32,
    address_area_offset: u32,
    symbol_table_offset: u32,
    shortcut_table_offset: u32,
    constant_pool_offset: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C, packed)]
struct GdbIndexCuEntry {
    cu_offset: u64,
    cu_length: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C, packed)]
struct GdbIndexAddressEntry {
    low_address: u64,
    high_address: u64,
    cu_index: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C, packed)]
struct GdbIndexShortcutTable {
    language_of_main: u32,
    name_of_main_offset: u32,
}

const HEADER_SIZE: usize = size_of::<GdbIndexHeader>();
const CU_ENTRY_SIZE: usize = size_of::<GdbIndexCuEntry>();
const ADDRESS_ENTRY_SIZE: usize = size_of::<GdbIndexAddressEntry>();
const SHORTCUT_TABLE_SIZE: usize = size_of::<GdbIndexShortcutTable>();
#[derive(Debug, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C, packed)]
struct GdbIndexHashSlot {
    name_offset: u32,
    cu_vector_offset: u32,
}

const HASH_SLOT_SIZE: usize = size_of::<GdbIndexHashSlot>();

/// The GDB index hash function.
fn gdb_hash(name: &[u8]) -> u32 {
    let mut r: u32 = 0;
    for &c in name {
        r = r
            .wrapping_mul(67)
            .wrapping_add(u32::from(c.to_ascii_lowercase()))
            .wrapping_sub(113);
    }
    r
}

/// Encode a CU vector entry: bits 0-23 = CU index, bits 28-30 = kind, bit 31 = is_static.
///
/// The attrs byte from `.debug_gnu_pubnames`/`.debug_gnu_pubtypes` packs kind in bits 4-6
/// and is_static in bit 7.
fn encode_cu_vector_entry(cu_index: u32, attrs: u8) -> u32 {
    let attrs = u64::from(attrs);
    let kind = attrs.extract_bit_range(4..7) as u32;
    let is_static = attrs.extract_bit_range(7..8) as u32;
    (cu_index & 0x00FF_FFFF) | (kind << 28) | (is_static << 31)
}

/// Number of hash table slots: next power of two >= 4/3 * n.
fn compute_hash_table_slots(num_symbols: usize) -> usize {
    if num_symbols == 0 {
        return 0;
    }
    (num_symbols * 4 / 3 + 1).next_power_of_two()
}

struct CuBoundary {
    offset: u64,
    length: u64,
}

/// Walk `.debug_info` bytes and return `(offset, total_length)` for each CU.
///
/// Each CU starts with an initial length field (§7.5.1.1) encoded per §7.4: a 4-byte value, or
/// `0xFFFF_FFFF` followed by an 8-byte length for DWARF-64.
fn parse_cu_boundaries(data: &[u8]) -> Result<Vec<CuBoundary>> {
    let mut cus = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= data.len() {
        let init_len = u32_from_slice(&data[offset..]);
        let total = if init_len == 0xFFFF_FFFF {
            crate::ensure!(
                offset + 12 <= data.len(),
                "Truncated DWARF64 initial length in .debug_info at offset {offset}"
            );
            let len = u64_from_slice(&data[offset + 4..]);
            12 + len as usize
        } else {
            4 + init_len as usize
        };
        crate::ensure!(
            total > 0 && offset + total <= data.len(),
            "Invalid CU length {total} in .debug_info at offset {offset}"
        );
        cus.push(CuBoundary {
            offset: offset as u64,
            length: total as u64,
        });
        offset += total;
    }
    Ok(cus)
}

struct PubnamesSet<'data> {
    debug_info_offset: u64,
    entries: Vec<(&'data [u8], u8)>,
}

/// Parse `.debug_gnu_pubnames` / `.debug_gnu_pubtypes` section data.
///
/// Each set has a header pointing to a CU in `.debug_info`, followed by
/// (die_offset, attrs_byte, NUL-terminated name) entries terminated by a zero die_offset.
fn parse_pubnames_sets<'data>(
    data: &'data [u8],
    section_name: &str,
) -> Result<Vec<PubnamesSet<'data>>> {
    let mut sets = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let init_len = u32_from_slice(&data[pos..]);

        let (header_size, set_end, debug_info_offset) = if init_len == 0xFFFF_FFFF {
            // DWARF64: 4 + 8(len) + 2(ver) + 8(offset) + 8(size) = 30
            crate::ensure!(
                pos + 30 <= data.len(),
                "Truncated DWARF64 header in {section_name} at offset {pos}"
            );
            let len = u64_from_slice(&data[pos + 4..]);
            let dio = u64_from_slice(&data[pos + 14..]);
            (30, pos + 12 + len as usize, dio)
        } else {
            // DWARF32: 4(len) + 2(ver) + 4(offset) + 4(size) = 14
            crate::ensure!(
                pos + 14 <= data.len(),
                "Truncated DWARF32 header in {section_name} at offset {pos}"
            );
            let dio = u64::from(u32_from_slice(&data[pos + 6..]));
            (14, pos + 4 + init_len as usize, dio)
        };

        let set_end = set_end.min(data.len());
        let mut ep = pos + header_size;
        let mut entries = Vec::new();
        let is_64 = init_len == 0xFFFF_FFFF;

        while ep < set_end {
            let die_offset = if is_64 {
                crate::ensure!(
                    ep + 8 <= set_end,
                    "Truncated die offset in {section_name} at offset {ep}"
                );
                let v = u64_from_slice(&data[ep..]);
                ep += 8;
                v
            } else {
                crate::ensure!(
                    ep + 4 <= set_end,
                    "Truncated die offset in {section_name} at offset {ep}"
                );
                let v = u64::from(u32_from_slice(&data[ep..]));
                ep += 4;
                v
            };
            if die_offset == 0 {
                break;
            }
            crate::ensure!(
                ep < set_end,
                "Missing attrs byte in {section_name} at offset {ep}"
            );
            let attrs = data[ep];
            ep += 1;
            let name_start = ep;
            while ep < set_end && data[ep] != 0 {
                ep += 1;
            }
            crate::ensure!(
                ep < set_end,
                "Unterminated name in {section_name} at offset {name_start}"
            );
            entries.push((&data[name_start..ep], attrs));
            ep += 1;
        }

        sets.push(PubnamesSet {
            debug_info_offset,
            entries,
        });
        pos = set_end;
    }
    Ok(sets)
}

/// Read section data from an input object by name.
fn section_by_name<'data>(
    object: &crate::elf::File<'data>,
    name: &str,
) -> Result<Option<Cow<'data, [u8]>>> {
    let Some((_index, header)) = object.section_by_name(name) else {
        return Ok(None);
    };
    Ok(Some(object.section_data_cow(header)?))
}

/// Compute the size from a scan result.
fn gdb_index_size_from_scan(scan: &GdbIndexScanResult) -> u64 {
    if scan.total_cus == 0 {
        return 0;
    }

    let mut cv_bytes = 0usize;
    let mut str_bytes = 0usize;
    for (name, sd) in &scan.sorted_symbols {
        // 4 bytes for the entry count, then 4 bytes per entry.
        cv_bytes += 4 + sd.cv_entries.len() * 4;
        str_bytes += name.len() + 1;
    }

    (HEADER_SIZE
        + scan.total_cus * CU_ENTRY_SIZE
        + scan.total_addr_entries * ADDRESS_ENTRY_SIZE
        + scan.ht_slots * HASH_SLOT_SIZE
        + SHORTCUT_TABLE_SIZE
        + cv_bytes
        + str_bytes) as u64
}

/// Pre-scan all input objects to compute the `.gdb_index` section size and return the scan result
/// for later use during the write phase.
pub(crate) fn compute_gdb_index_size(
    groups: &[GroupState<'_, Elf>],
) -> Result<(u64, Option<GdbIndexScanResult>)> {
    timing_phase!("Compute GDB index size");

    let objects: Vec<_> = groups
        .iter()
        .flat_map(|g| g.files.iter())
        .filter_map(|f| {
            let FileLayoutState::Object(obj) = f else {
                return None;
            };
            Some((obj.object, obj.sections.as_slice()))
        })
        .collect();
    let scan = scan_objects_for_gdb_index(&objects)?;

    let size = gdb_index_size_from_scan(&scan);
    if size == 0 {
        Ok((0, None))
    } else {
        Ok((size, Some(scan)))
    }
}

/// Write the `.gdb_index` section into `buf`.
///
/// Reads the output `.debug_info` (already written into `output_buf`) for the CU list,
/// and uses the pre-computed scan result for symbol data.
pub(crate) fn write_gdb_index(
    buf: &mut [u8],
    output_buf: &[u8],
    layout: &Layout<'_, Elf>,
    scan: &GdbIndexScanResult,
) -> Result {
    if buf.is_empty() {
        return Ok(());
    }

    let cu_entries = build_cu_list(output_buf, layout)?;
    let sorted_names = &scan.sorted_symbols;
    let ht_slots = scan.ht_slots;
    if !cu_entries.is_empty() && sorted_names.is_empty() {
        layout.symbol_db.warning(
            "Objects lack .debug_gnu_pubnames/.debug_gnu_pubtypes sections, so the symbol table in .gdb_index will be empty. \
             Compile with -ggnu-pubnames to populate it.",
        );
    }
    let addr_entries = build_address_entries(layout, &scan.per_object_cu_counts)?;

    let cu_list_off = HEADER_SIZE as u32;
    let tu_list_off = cu_list_off + (cu_entries.len() * CU_ENTRY_SIZE) as u32;
    let addr_off = tu_list_off;
    let sym_off = addr_off + (addr_entries.len() * ADDRESS_ENTRY_SIZE) as u32;
    let short_off = sym_off + (ht_slots * HASH_SLOT_SIZE) as u32;
    let cp_off = short_off + SHORTCUT_TABLE_SIZE as u32;

    let (cv_offsets, name_offsets) = write_constant_pool(buf, cp_off as usize, sorted_names);

    let hdr = GdbIndexHeader {
        version: GDB_INDEX_VERSION,
        cu_list_offset: cu_list_off,
        tu_list_offset: tu_list_off,
        address_area_offset: addr_off,
        symbol_table_offset: sym_off,
        shortcut_table_offset: short_off,
        constant_pool_offset: cp_off,
    };
    buf[..HEADER_SIZE].copy_from_slice(hdr.as_bytes());

    let mut off = cu_list_off as usize;
    for cu in &cu_entries {
        buf[off..off + CU_ENTRY_SIZE].copy_from_slice(cu.as_bytes());
        off += CU_ENTRY_SIZE;
    }

    off = addr_off as usize;
    for a in &addr_entries {
        buf[off..off + ADDRESS_ENTRY_SIZE].copy_from_slice(a.as_bytes());
        off += ADDRESS_ENTRY_SIZE;
    }

    write_hash_table(
        buf,
        ht_slots,
        sym_off as usize,
        sorted_names,
        &name_offsets,
        &cv_offsets,
    )?;

    // The shortcut table lets GDB quickly determine the language of `main` without scanning the
    // full index. Filling it requires looking up the DWARF language attribute of the main CU, which
    // we don't currently do. GDB handles zeroed values here by falling back to its own lookup.
    let so = short_off as usize;
    let sc = GdbIndexShortcutTable {
        language_of_main: 0,
        name_of_main_offset: 0,
    };
    buf[so..so + SHORTCUT_TABLE_SIZE].copy_from_slice(sc.as_bytes());
    Ok(())
}

/// Build the CU list from the already-written output `.debug_info`.
fn build_cu_list(output_buf: &[u8], layout: &Layout<'_, Elf>) -> Result<Vec<GdbIndexCuEntry>> {
    let Some(id) = layout
        .output_sections
        .section_id_by_name(SectionName(DEBUG_INFO_SECTION_NAME))
    else {
        return Ok(Vec::new());
    };
    let sl = layout.section_layouts.get(id);
    let start = sl.file_offset;
    let end = start + sl.file_size;
    crate::ensure!(
        end <= output_buf.len(),
        ".debug_info layout extends beyond output buffer ({end} > {})",
        output_buf.len()
    );
    Ok(parse_cu_boundaries(&output_buf[start..end])?
        .into_iter()
        .map(|cu| GdbIndexCuEntry {
            cu_offset: cu.offset,
            cu_length: cu.length,
        })
        .collect())
}

struct SymData {
    cv_entries: BTreeSet<u32>,
    hash: u32,
}

pub(crate) struct GdbIndexScanResult {
    total_cus: usize,
    total_addr_entries: usize,
    sorted_symbols: Vec<(Vec<u8>, SymData)>,
    ht_slots: usize,
    /// CU count for each object that has debug info, in input order. Used by
    /// `build_address_entries` to assign global CU indices.
    per_object_cu_counts: Vec<u32>,
}

/// Result of scanning a single input object for GDB index data.
struct PerObjectGdbScan {
    num_cus: usize,
    num_addr_entries: usize,
    /// `(name, local_cu_index, attrs)`. CU index is 0-based within this object.
    /// Names are owned because section data may have been decompressed.
    symbol_entries: Vec<(Vec<u8>, u32, u8)>,
}

/// Scan a single input object, returning per-object GDB index data with 0-based CU indices.
fn scan_one_object(
    object: &crate::elf::File<'_>,
    sections: &[SectionSlot],
) -> Result<Option<PerObjectGdbScan>> {
    let boundaries = match section_by_name(object, DEBUG_INFO_SECTION_NAME_STR)? {
        Some(data) => parse_cu_boundaries(&data)?,
        None => return Ok(None),
    };
    if boundaries.is_empty() {
        return Ok(None);
    }

    let mut num_addr_entries = 0usize;
    for (si, slot) in sections.iter().enumerate() {
        let SectionSlot::Loaded(section) = slot else {
            continue;
        };
        if section.size == 0 {
            continue;
        }
        let header = object.section(object::SectionIndex(si))?;
        if header.is_alloc() && header.is_executable() {
            num_addr_entries += 1;
        }
    }

    // Build offset-to-local-index map for this object's CUs.
    let mut offset_to_idx: HashMap<u64, u32> = HashMap::with_capacity(boundaries.len());
    for (i, cu) in boundaries.iter().enumerate() {
        offset_to_idx.insert(cu.offset, i as u32);
    }

    // Collect raw pubname entries with local CU indices and raw attrs.
    let mut symbol_entries = Vec::new();
    for section_name in [
        secnames::DEBUG_GNU_PUBNAMES_STR,
        secnames::DEBUG_GNU_PUBTYPES_STR,
    ] {
        let Some(data) = section_by_name(object, section_name)? else {
            continue;
        };
        for set in parse_pubnames_sets(&data, section_name)? {
            let Some(&local_cu_idx) = offset_to_idx.get(&set.debug_info_offset) else {
                continue;
            };
            for (name, attrs) in set.entries {
                symbol_entries.push((name.to_vec(), local_cu_idx, attrs));
            }
        }
    }

    Ok(Some(PerObjectGdbScan {
        num_cus: boundaries.len(),
        num_addr_entries,
        symbol_entries,
    }))
}

/// Merge per-object scan results into a single `GdbIndexScanResult`, assigning global CU indices.
fn merge_gdb_index_scans(per_object: Vec<Option<PerObjectGdbScan>>) -> GdbIndexScanResult {
    timing_phase!("Merge GDB index scans");

    let mut total_cus = 0usize;
    let mut total_addr_entries = 0usize;
    let mut sym_map: HashMap<Vec<u8>, SymData> = HashMap::new();
    let mut per_object_cu_counts = Vec::new();

    for scan in per_object {
        let Some(scan) = scan else {
            per_object_cu_counts.push(0);
            continue;
        };
        let base = total_cus as u32;
        total_cus += scan.num_cus;
        total_addr_entries += scan.num_addr_entries;
        per_object_cu_counts.push(scan.num_cus as u32);

        for (name, local_cu_idx, attrs) in scan.symbol_entries {
            let entry = encode_cu_vector_entry(base + local_cu_idx, attrs);
            let sd = sym_map.entry(name).or_insert_with_key(|name| SymData {
                cv_entries: BTreeSet::new(),
                hash: gdb_hash(name),
            });
            sd.cv_entries.insert(entry);
        }
    }

    let sorted: Vec<(Vec<u8>, SymData)> = sym_map
        .into_iter()
        .sorted_unstable_by(|(a, _), (b, _)| a.cmp(b))
        .collect();
    let ht_slots = compute_hash_table_slots(sorted.len());

    GdbIndexScanResult {
        total_cus,
        total_addr_entries,
        sorted_symbols: sorted,
        ht_slots,
        per_object_cu_counts,
    }
}

/// Scan all input objects in parallel to build the GDB index symbol table.
fn scan_objects_for_gdb_index(
    objects: &[(&crate::elf::File<'_>, &[SectionSlot])],
) -> Result<GdbIndexScanResult> {
    timing_phase!("Scan objects for GDB index");

    let per_object: Result<Vec<_>> = objects
        .par_iter()
        .map(|(object, sections)| scan_one_object(object, sections))
        .collect();

    Ok(merge_gdb_index_scans(per_object?))
}

/// Build address entries using resolved addresses from the final layout.
fn build_address_entries(
    layout: &Layout<'_, Elf>,
    per_object_cu_counts: &[u32],
) -> Result<Vec<GdbIndexAddressEntry>> {
    verbose_timing_phase!("Build GDB address entries");
    let mut entries = Vec::new();
    let mut cu_offset = 0u32;
    let mut cu_count_iter = per_object_cu_counts.iter();

    for group in &layout.group_layouts {
        for file in &group.files {
            let FileLayout::Object(obj) = file else {
                continue;
            };
            let &obj_cu_count = cu_count_iter.next().unwrap_or(&0);
            if obj_cu_count == 0 {
                continue;
            }
            let base_cu = cu_offset;

            // For objects with multiple CUs, build a section_index to local CU index map so each
            // section is assigned to the correct CU.
            let section_cu_map = if obj_cu_count > 1 {
                build_section_cu_map(obj.object, obj_cu_count)?
            } else {
                HashMap::new()
            };

            for (si, slot) in obj.sections.iter().enumerate() {
                let SectionSlot::Loaded(section) = slot else {
                    continue;
                };
                if section.size == 0 {
                    continue;
                }
                let header = obj.object.section(object::SectionIndex(si))?;
                if !header.is_alloc() || !header.is_executable() {
                    continue;
                }
                if let Some(addr) = obj.section_resolutions[si].address()
                    && addr != 0
                {
                    let local_cu = section_cu_map.get(&si).copied().unwrap_or(0);
                    entries.push(GdbIndexAddressEntry {
                        low_address: addr,
                        high_address: addr + section.size,
                        cu_index: base_cu + local_cu,
                    });
                }
            }

            cu_offset += obj_cu_count;
        }
    }
    Ok(entries)
}

/// Build a mapping from section index to local CU index for an input object with multiple CUs.
fn build_section_cu_map(
    object: &crate::elf::File<'_>,
    cu_count: u32,
) -> Result<HashMap<usize, u32>> {
    let boundaries = match section_by_name(object, DEBUG_INFO_SECTION_NAME_STR)? {
        Some(data) => parse_cu_boundaries(&data)?,
        None => return Ok(HashMap::new()),
    };
    if boundaries.len() != cu_count as usize {
        return Ok(HashMap::new());
    }

    // Find the relocation section for .debug_info.
    let rela_section = object
        .section_by_name(".rela.debug_info")
        .or_else(|| object.section_by_name(".rel.debug_info"));
    let Some((_rela_idx, rela_header)) = rela_section else {
        return Ok(HashMap::new());
    };

    let mut map: HashMap<usize, u32> = HashMap::new();

    if let Some((relas, _)) = rela_header.rela(object::LittleEndian, object.data)? {
        for rela in relas {
            let offset = object::read::elf::Rela::r_offset(rela, object::LittleEndian);
            let Some(sym_idx) = object::read::elf::Rela::symbol(rela, object::LittleEndian, false)
            else {
                continue;
            };
            let symbol = object.symbol(sym_idx)?;
            let Some(sec_idx) = object.symbol_section(symbol, sym_idx)? else {
                continue;
            };
            // Only record the first mapping for each section (a CU may reference the same
            // section many times via line tables, address ranges, etc.).
            if map.contains_key(&sec_idx.0) {
                continue;
            }
            // Find which CU this relocation offset belongs to.
            if let Some(local_cu) = cu_index_for_offset(&boundaries, offset) {
                map.insert(sec_idx.0, local_cu);
            }
        }
    }

    Ok(map)
}

/// Given a relocation offset within `.debug_info`, return the 0-based CU index it falls into.
fn cu_index_for_offset(boundaries: &[CuBoundary], offset: u64) -> Option<u32> {
    for (i, cu) in boundaries.iter().enumerate() {
        if offset >= cu.offset && offset < cu.offset + cu.length {
            return Some(i as u32);
        }
    }
    None
}

/// Write the constant pool (CU vectors followed by name strings) into `buf` starting at `cp_start`.
fn write_constant_pool(
    buf: &mut [u8],
    cp_start: usize,
    sorted: &[(Vec<u8>, SymData)],
) -> (Vec<u32>, Vec<u32>) {
    let mut cv_offsets = Vec::with_capacity(sorted.len());
    let mut off = cp_start;
    for (_, sd) in sorted {
        cv_offsets.push((off - cp_start) as u32);
        buf[off..off + 4].copy_from_slice(&(sd.cv_entries.len() as u32).to_le_bytes());
        off += 4;
        for &e in &sd.cv_entries {
            buf[off..off + 4].copy_from_slice(&e.to_le_bytes());
            off += 4;
        }
    }
    let mut name_offsets = Vec::with_capacity(sorted.len());
    for (name, _) in sorted {
        name_offsets.push((off - cp_start) as u32);
        buf[off..off + name.len()].copy_from_slice(name);
        off += name.len();
        buf[off] = 0;
        off += 1;
    }
    (cv_offsets, name_offsets)
}

/// Insert symbols into the open-addressing hash table region of `buf`.
fn write_hash_table(
    buf: &mut [u8],
    ht_slots: usize,
    ht_start: usize,
    sorted: &[(Vec<u8>, SymData)],
    name_offsets: &[u32],
    cv_offsets: &[u32],
) -> Result {
    verbose_timing_phase!("Write GDB hash table");
    let ht_end = ht_start + ht_slots * HASH_SLOT_SIZE;
    buf[ht_start..ht_end].fill(0);

    if ht_slots == 0 {
        return Ok(());
    }
    let mask = (ht_slots - 1) as u32;
    for (i, (_, sd)) in sorted.iter().enumerate() {
        let h = sd.hash;
        let step = (h.wrapping_mul(17) & mask) | 1;
        let mut slot = h & mask;
        let initial_slot = slot;
        loop {
            let so = ht_start + slot as usize * HASH_SLOT_SIZE;
            let existing = GdbIndexHashSlot::read_from_bytes(&buf[so..so + HASH_SLOT_SIZE])
                .context("Failed to read .gdb_index hash table slot")?;
            if existing.name_offset == 0 && existing.cu_vector_offset == 0 {
                let new_slot = GdbIndexHashSlot {
                    name_offset: name_offsets[i],
                    cu_vector_offset: cv_offsets[i],
                };
                buf[so..so + HASH_SLOT_SIZE].copy_from_slice(new_slot.as_bytes());
                break;
            }
            slot = (slot + step) & mask;
            crate::ensure!(slot != initial_slot, "gdb_index hash table is full");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gdb_hash_case_insensitive() {
        assert_eq!(gdb_hash(b"main"), gdb_hash(b"MAIN"));
        assert_eq!(gdb_hash(b"main"), gdb_hash(b"Main"));
        assert_ne!(gdb_hash(b"main"), gdb_hash(b"foo"));
    }

    #[test]
    fn test_hash_table_slots_power_of_two() {
        assert_eq!(compute_hash_table_slots(0), 0);
        assert_eq!(compute_hash_table_slots(1), 2);
        for n in 1..100 {
            let s = compute_hash_table_slots(n);
            assert!(s.is_power_of_two());
            assert!(s >= n);
        }
    }

    #[test]
    fn test_encode_cu_vector_entry() {
        // Global function: kind=3 in bits 4-6, is_static=0 in bit 7
        let e = encode_cu_vector_entry(5, 0b0011_0000);
        assert_eq!(e & 0x00FF_FFFF, 5);
        assert_eq!((e >> 28) & 0x7, 3);
        assert_eq!((e >> 31) & 0x1, 0);

        // Static function: kind=3, is_static=1
        let e2 = encode_cu_vector_entry(42, 0b1011_0000);
        assert_eq!(e2 & 0x00FF_FFFF, 42);
        assert_eq!((e2 >> 28) & 0x7, 3);
        assert_eq!((e2 >> 31) & 0x1, 1);
    }

    #[test]
    fn test_parse_cu_boundaries() {
        assert!(parse_cu_boundaries(&[]).unwrap().is_empty());

        // Single DWARF32 CU: init_length=8, total = 4 + 8 = 12 bytes.
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(&8u32.to_le_bytes());
        let cus = parse_cu_boundaries(&data).unwrap();
        assert_eq!(cus.len(), 1);
        assert_eq!(cus[0].offset, 0);
        assert_eq!(cus[0].length, 12);
    }

    #[test]
    fn test_header_size() {
        assert_eq!(HEADER_SIZE, 7 * 4);
    }
}
