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
use hashbrown::HashMap;
use itertools::Itertools as _;
use linker_utils::bit_misc::BitExtraction;
use linker_utils::elf::secnames::DEBUG_INFO_SECTION_NAME;
use linker_utils::elf::secnames::DEBUG_INFO_SECTION_NAME_STR;
use linker_utils::utils::u32_from_slice;
use linker_utils::utils::u64_from_slice;
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
fn parse_cu_boundaries(data: &[u8]) -> Vec<CuBoundary> {
    let mut cus = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= data.len() {
        let init_len = u32_from_slice(&data[offset..]);
        let total = if init_len == 0xFFFF_FFFF {
            if offset + 12 > data.len() {
                break;
            }
            let len = u64_from_slice(&data[offset + 4..]);
            12 + len as usize
        } else {
            4 + init_len as usize
        };
        if total == 0 || offset + total > data.len() {
            break;
        }
        cus.push(CuBoundary {
            offset: offset as u64,
            length: total as u64,
        });
        offset += total;
    }
    cus
}

struct PubnamesSet<'data> {
    debug_info_offset: u64,
    entries: Vec<(&'data [u8], u8)>,
}

/// Parse `.debug_gnu_pubnames` / `.debug_gnu_pubtypes` section data.
///
/// Each set has a header pointing to a CU in `.debug_info`, followed by
/// (die_offset, attrs_byte, NUL-terminated name) entries.
fn parse_pubnames_sets(data: &[u8]) -> Vec<PubnamesSet<'_>> {
    let mut sets = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let init_len = u32_from_slice(&data[pos..]);

        let (header_size, set_end, debug_info_offset) = if init_len == 0xFFFF_FFFF {
            // DWARF64: 4 + 8(len) + 2(ver) + 8(offset) + 8(size) = 30
            if pos + 30 > data.len() {
                break;
            }
            let len = u64_from_slice(&data[pos + 4..]);
            let dio = u64_from_slice(&data[pos + 14..]);
            (30, pos + 12 + len as usize, dio)
        } else {
            // DWARF32: 4(len) + 2(ver) + 4(offset) + 4(size) = 14
            if pos + 14 > data.len() {
                break;
            }
            let dio = u64::from(u32_from_slice(&data[pos + 6..]));
            (14, pos + 4 + init_len as usize, dio)
        };

        let set_end = set_end.min(data.len());
        let mut ep = pos + header_size;
        let mut entries = Vec::new();
        let is_64 = init_len == 0xFFFF_FFFF;

        while ep < set_end {
            let die_offset = if is_64 {
                if ep + 8 > set_end {
                    break;
                }
                let v = u64_from_slice(&data[ep..]);
                ep += 8;
                v
            } else {
                if ep + 4 > set_end {
                    break;
                }
                let v = u64::from(u32_from_slice(&data[ep..]));
                ep += 4;
                v
            };
            if die_offset == 0 {
                break;
            }
            if ep >= set_end {
                break;
            }
            let attrs = data[ep];
            ep += 1;
            let name_start = ep;
            while ep < set_end && data[ep] != 0 {
                ep += 1;
            }
            if ep >= set_end {
                break;
            }
            entries.push((&data[name_start..ep], attrs));
            ep += 1;
        }

        sets.push(PubnamesSet {
            debug_info_offset,
            entries,
        });
        pos = set_end;
    }
    sets
}

/// Read raw section data from an input object by name.
fn raw_section_by_name<'data>(
    object: &crate::elf::File<'data>,
    name: &str,
) -> Result<Option<&'data [u8]>> {
    let Some((_index, header)) = object.section_by_name(name) else {
        return Ok(None);
    };
    Ok(Some(object.raw_section_data(header)?))
}

/// Pre-scan all input objects to compute the `.gdb_index` section size.
pub(crate) fn compute_gdb_index_size(groups: &[GroupState<'_, Elf>]) -> Result<u64> {
    let objects = groups.iter().flat_map(|g| g.files.iter()).filter_map(|f| {
        let FileLayoutState::Object(obj) = f else {
            return None;
        };
        Some((obj.object, obj.sections.as_slice()))
    });
    let scan = scan_objects_for_gdb_index(objects)?;

    if scan.total_cus == 0 {
        return Ok(0);
    }

    let mut cv_bytes = 0usize;
    let mut str_bytes = 0usize;
    for (name, sd) in &scan.sorted_symbols {
        // 4 bytes for the entry count, then 4 bytes per entry.
        cv_bytes += 4 + sd.cv_entries.len() * 4;
        str_bytes += name.len() + 1;
    }

    Ok((HEADER_SIZE
        + scan.total_cus * CU_ENTRY_SIZE
        + scan.total_addr_entries * ADDRESS_ENTRY_SIZE
        + scan.ht_slots * HASH_SLOT_SIZE
        + SHORTCUT_TABLE_SIZE
        + cv_bytes
        + str_bytes) as u64)
}

/// Write the `.gdb_index` section into `buf`.
///
/// Reads the output `.debug_info` (already written into `output_buf`) for the CU list,
/// and re-scans input objects for address ranges and pubnames/pubtypes symbols.
pub(crate) fn write_gdb_index(
    buf: &mut [u8],
    output_buf: &[u8],
    layout: &Layout<'_, Elf>,
) -> Result {
    if buf.is_empty() {
        return Ok(());
    }

    let cu_entries = build_cu_list(output_buf, layout)?;
    let objects = layout
        .group_layouts
        .iter()
        .flat_map(|g| g.files.iter())
        .filter_map(|f| {
            let FileLayout::Object(obj) = f else {
                return None;
            };
            Some((obj.object, obj.sections.as_slice()))
        });
    let GdbIndexScanResult {
        sorted_symbols: sorted_names,
        ht_slots,
        ..
    } = scan_objects_for_gdb_index(objects)?;
    if !cu_entries.is_empty() && sorted_names.is_empty() {
        layout.symbol_db.warning(
            "Objects lack .debug_gnu_pubnames/.debug_gnu_pubtypes sections, so the symbol table in .gdb_index will be empty. \
             Compile with -ggnu-pubnames to populate it.",
        );
    }
    let addr_entries = build_address_entries(layout)?;

    let cu_list_off = HEADER_SIZE as u32;
    let tu_list_off = cu_list_off + (cu_entries.len() * CU_ENTRY_SIZE) as u32;
    let addr_off = tu_list_off;
    let sym_off = addr_off + (addr_entries.len() * ADDRESS_ENTRY_SIZE) as u32;
    let short_off = sym_off + (ht_slots * HASH_SLOT_SIZE) as u32;
    let cp_off = short_off + SHORTCUT_TABLE_SIZE as u32;

    // Write constant pool: CU vectors first, then name strings.
    let mut cv_offsets = Vec::with_capacity(sorted_names.len());
    let mut off = cp_off as usize;
    for (_, sd) in &sorted_names {
        cv_offsets.push((off - cp_off as usize) as u32);
        buf[off..off + 4].copy_from_slice(&(sd.cv_entries.len() as u32).to_le_bytes());
        off += 4;
        for &e in &sd.cv_entries {
            buf[off..off + 4].copy_from_slice(&e.to_le_bytes());
            off += 4;
        }
    }
    let mut name_offsets = Vec::with_capacity(sorted_names.len());
    for (name, _) in &sorted_names {
        name_offsets.push((off - cp_off as usize) as u32);
        buf[off..off + name.len()].copy_from_slice(name);
        off += name.len();
        buf[off] = 0;
        off += 1;
    }

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
        &sorted_names,
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
    Ok(parse_cu_boundaries(&output_buf[start..end])
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

struct GdbIndexScanResult<'data> {
    total_cus: usize,
    total_addr_entries: usize,
    sorted_symbols: Vec<(&'data [u8], SymData)>,
    ht_slots: usize,
}

/// Scan input objects to build the symbol table and count CUs / address entries.
fn scan_objects_for_gdb_index<'data>(
    objects: impl Iterator<Item = (&'data crate::elf::File<'data>, &'data [SectionSlot])>,
) -> Result<GdbIndexScanResult<'data>> {
    let mut total_cus = 0usize;
    let mut total_addr_entries = 0usize;
    let mut sym_map: HashMap<&'data [u8], SymData> = HashMap::new();
    let mut cu_offset = 0u32;

    for (object, sections) in objects {
        let boundaries = match raw_section_by_name(object, DEBUG_INFO_SECTION_NAME_STR)? {
            Some(data) => parse_cu_boundaries(data),
            None => continue,
        };
        if boundaries.is_empty() {
            continue;
        }

        let base = cu_offset;

        let mut obj_addr_count = 0usize;
        for (si, slot) in sections.iter().enumerate() {
            let SectionSlot::Loaded(section) = slot else {
                continue;
            };
            if section.size == 0 {
                continue;
            }
            let header = object.section(object::SectionIndex(si))?;
            if header.is_alloc() && header.is_executable() {
                obj_addr_count += 1;
            }
        }

        total_cus += boundaries.len();
        total_addr_entries += obj_addr_count;

        let mut offset_to_idx: HashMap<u64, u32> = HashMap::with_capacity(boundaries.len());
        for (i, cu) in boundaries.iter().enumerate() {
            offset_to_idx.insert(cu.offset, base + i as u32);
        }
        cu_offset += boundaries.len() as u32;

        for (name, entry) in collect_pubname_entries(object, &offset_to_idx)? {
            let sd = sym_map.entry(name).or_insert_with(|| SymData {
                cv_entries: BTreeSet::new(),
                hash: gdb_hash(name),
            });
            sd.cv_entries.insert(entry);
        }
    }

    let sorted: Vec<(&[u8], SymData)> = sym_map
        .into_iter()
        .sorted_unstable_by_key(|(name, _)| *name)
        .collect();
    let ht_slots = compute_hash_table_slots(sorted.len());
    Ok(GdbIndexScanResult {
        total_cus,
        total_addr_entries,
        sorted_symbols: sorted,
        ht_slots,
    })
}

/// Build address entries using resolved addresses from the final layout.
fn build_address_entries(layout: &Layout<'_, Elf>) -> Result<Vec<GdbIndexAddressEntry>> {
    let mut entries = Vec::new();
    let mut cu_offset = 0u32;

    for group in &layout.group_layouts {
        for file in &group.files {
            let FileLayout::Object(obj) = file else {
                continue;
            };
            let object = obj.object;

            let obj_cu_count = raw_section_by_name(object, DEBUG_INFO_SECTION_NAME_STR)?
                .map_or(0, |data| parse_cu_boundaries(data).len() as u32);
            if obj_cu_count == 0 {
                continue;
            }
            let base_cu = cu_offset;

            for (si, slot) in obj.sections.iter().enumerate() {
                let SectionSlot::Loaded(section) = slot else {
                    continue;
                };
                if section.size == 0 {
                    continue;
                }
                let header = object.section(object::SectionIndex(si))?;
                if !header.is_alloc() || !header.is_executable() {
                    continue;
                }
                if let Some(addr) = obj.section_resolutions[si].address()
                    && addr != 0
                {
                    entries.push(GdbIndexAddressEntry {
                        low_address: addr,
                        high_address: addr + section.size,
                        cu_index: base_cu,
                    });
                }
            }

            cu_offset += obj_cu_count;
        }
    }
    Ok(entries)
}

/// Collect encoded pubname/pubtype entries from an object's `.debug_gnu_pubnames`
/// and `.debug_gnu_pubtypes` sections, returning `(name, encoded_cu_vector_entry)` pairs.
fn collect_pubname_entries<'data>(
    object: &crate::elf::File<'data>,
    offset_to_idx: &HashMap<u64, u32>,
) -> Result<Vec<(&'data [u8], u32)>> {
    let mut entries = Vec::new();
    for section_name in [".debug_gnu_pubnames", ".debug_gnu_pubtypes"] {
        let Some(data) = raw_section_by_name(object, section_name)? else {
            continue;
        };
        for set in parse_pubnames_sets(data) {
            let Some(&cu_idx) = offset_to_idx.get(&set.debug_info_offset) else {
                continue;
            };
            for (name, attrs) in set.entries {
                entries.push((name, encode_cu_vector_entry(cu_idx, attrs)));
            }
        }
    }
    Ok(entries)
}

/// Insert symbols into the open-addressing hash table region of `buf`.
fn write_hash_table(
    buf: &mut [u8],
    ht_slots: usize,
    ht_start: usize,
    sorted: &[(&[u8], SymData)],
    name_offsets: &[u32],
    cv_offsets: &[u32],
) -> Result {
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
        assert!(parse_cu_boundaries(&[]).is_empty());

        // Single DWARF32 CU: init_length=8, total = 4 + 8 = 12 bytes.
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(&8u32.to_le_bytes());
        let cus = parse_cu_boundaries(&data);
        assert_eq!(cus.len(), 1);
        assert_eq!(cus[0].offset, 0);
        assert_eq!(cus[0].length, 12);
    }

    #[test]
    fn test_header_size() {
        assert_eq!(HEADER_SIZE, 7 * 4);
    }
}
