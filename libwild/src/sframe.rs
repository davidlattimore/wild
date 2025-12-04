use crate::bail;
use crate::error::Context as _;
use crate::error::Result;
use std::cmp;
use std::convert::TryInto;

/// Magic value identifying an SFrame section.
const SFRAME_MAGIC: u16 = 0xdee2;
/// Current supported SFrame version.
const SFRAME_VERSION_2: u8 = 2;

const FLAG_FDE_SORTED: u8 = 0x1;
const FLAG_FUNC_START_PCREL: u8 = 0x4;

const SFRAME_FRE_TYPE_ADDR1: u32 = 0;
const SFRAME_FRE_TYPE_ADDR2: u32 = 1;
const SFRAME_FRE_TYPE_ADDR4: u32 = 2;

const SFRAME_FRE_OFFSET_1B: u32 = 0;
const SFRAME_FRE_OFFSET_2B: u32 = 1;
const SFRAME_FRE_OFFSET_4B: u32 = 2;

const HEADER_SIZE: usize = 0x1c;
const FDE_SIZE: usize = 20;
const FDE_START_OFFSET_FIELD: usize = 0x14;
const FRE_START_OFFSET_FIELD: usize = 0x18;
const NUM_FRES_FIELD: usize = 0x0c;
const FRE_TYPE_FIELD: usize = 0x10;
const NUM_FDES_FIELD: usize = 0x08;
const AUX_LENGTH_FIELD: usize = 0x07;
const FLAGS_FIELD: usize = 0x03;
const VERSION_FIELD: usize = 0x02;

struct Entry {
    bytes: [u8; FDE_SIZE],
    func_addr: i128,
    fre_bytes: Vec<u8>,
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_i32(data: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn write_i32(data: &mut [u8], offset: usize, value: i32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn get_fre_type(addr_size: usize, offset_size: usize) -> u32 {
    let addr_type = match addr_size {
        1 => SFRAME_FRE_TYPE_ADDR1,
        2 => SFRAME_FRE_TYPE_ADDR2,
        4 => SFRAME_FRE_TYPE_ADDR4,
        _ => panic!("Invalid address size"),
    };
    let offset_type = match offset_size {
        1 => SFRAME_FRE_OFFSET_1B,
        2 => SFRAME_FRE_OFFSET_2B,
        4 => SFRAME_FRE_OFFSET_4B,
        _ => panic!("Invalid offset size"),
    };
    (addr_type << 4) | offset_type
}

fn get_fre_addr_size(fre_type: u32) -> usize {
    match (fre_type >> 4) & 0xF {
        SFRAME_FRE_TYPE_ADDR1 => 1,
        SFRAME_FRE_TYPE_ADDR2 => 2,
        SFRAME_FRE_TYPE_ADDR4 => 4,
        _ => 1,
    }
}

fn get_fre_offset_size(fre_type: u32) -> usize {
    match fre_type & 0xF {
        SFRAME_FRE_OFFSET_1B => 1,
        SFRAME_FRE_OFFSET_2B => 2,
        SFRAME_FRE_OFFSET_4B => 4,
        _ => 1,
    }
}

/// Sort the SFrame FDE array in-place by the functions' start addresses.
///
/// The SFrame header will be updated to mark the array as sorted. The FRE data is left untouched
/// as the descriptor entries reference it by offset.
pub(crate) fn sort_sframe_section(
    section: &mut [u8],
    section_base_address: u64,
    section_ranges: &[std::ops::Range<usize>],
) -> Result {
    if section.is_empty() {
        return Ok(());
    }

    let mut entries = Vec::new();
    let section_base = i128::from(section_base_address);

    let mut output_flags = 0u8;
    let mut output_aux_len = 0;
    let mut max_addr_size = 1;
    let mut max_offset_size = 1;
    let mut total_num_fres = 0;
    let mut first_section = true;

    for range in section_ranges {
        let offset = range.start;
        let len = range.end - range.start;

        if len < HEADER_SIZE {
            continue;
        }

        let magic = read_u16(section, offset);
        if magic != SFRAME_MAGIC {
            bail!("Invalid SFrame magic 0x{:x} at offset {}", magic, offset);
        }

        let version = section[offset + VERSION_FIELD];
        if version != SFRAME_VERSION_2 {
            bail!(
                "Unsupported SFrame version {} (expected {})",
                version,
                SFRAME_VERSION_2
            );
        }

        let flags = section[offset + FLAGS_FIELD];
        let pc_rel = flags & FLAG_FUNC_START_PCREL != 0;
        let aux_len = section[offset + AUX_LENGTH_FIELD] as usize;

        let num_fres = read_u32(section, offset + NUM_FRES_FIELD) as usize;
        let fre_type = read_u32(section, offset + FRE_TYPE_FIELD);

        max_addr_size = cmp::max(max_addr_size, get_fre_addr_size(fre_type));
        max_offset_size = cmp::max(max_offset_size, get_fre_offset_size(fre_type));

        if first_section {
            output_flags = flags;
            output_aux_len = aux_len;
            first_section = false;
        }

        total_num_fres += num_fres;

        let header_end_offset = HEADER_SIZE
            .checked_add(aux_len)
            .context("SFrame auxiliary header length overflow")?;

        let num_fdes = read_u32(section, offset + NUM_FDES_FIELD) as usize;
        let fde_offset = read_u32(section, offset + FDE_START_OFFSET_FIELD) as usize;
        let fre_offset = read_u32(section, offset + FRE_START_OFFSET_FIELD) as usize;

        let fde_start = offset + header_end_offset + fde_offset;
        let fre_start = offset + header_end_offset + fre_offset;

        let total_fde_bytes = FDE_SIZE
            .checked_mul(num_fdes)
            .context("SFrame FDE array size overflow")?;

        let fde_end = fde_start + total_fde_bytes;

        if fde_end > offset + len {
            bail!("SFrame FDE array truncated");
        }

        for index in 0..num_fdes {
            let offset_in_section = fde_start + index * FDE_SIZE;
            let mut bytes = [0u8; FDE_SIZE];
            bytes.copy_from_slice(&section[offset_in_section..offset_in_section + FDE_SIZE]);

            let start_value = i128::from(read_i32(&bytes, 0));
            let func_addr = if pc_rel {
                section_base + (offset_in_section as i128) + start_value
            } else {
                section_base + start_value
            };

            let curr_fre_offset = read_u32(&bytes, 8) as usize;
            let curr_fre_abs_start = fre_start + curr_fre_offset;

            // The end of the FRE data for this function is either the start of the next function's
            // FRE data, or the end of the section if this is the last one.
            // Since we don't know the order of FREs, we have to search for the next one.
            // The maximum possible offset is the end of the section relative to fre_start.
            let max_fre_offset = (offset + len)
                .checked_sub(fre_start)
                .context("Invalid SFrame FRE start")?;
            let mut next_fre_offset = max_fre_offset;

            for other_index in 0..num_fdes {
                if index == other_index {
                    continue;
                }
                let other_fde_offset = fde_start + other_index * FDE_SIZE;
                let other_fre_offset = read_u32(section, other_fde_offset + 8) as usize;
                if other_fre_offset > curr_fre_offset && other_fre_offset < next_fre_offset {
                    next_fre_offset = other_fre_offset;
                }
            }

            let curr_fre_len = next_fre_offset - curr_fre_offset;
            let mut fre_bytes = vec![0u8; curr_fre_len];
            if curr_fre_abs_start + curr_fre_len > offset + len {
                bail!("SFrame FRE data truncated");
            }
            fre_bytes
                .copy_from_slice(&section[curr_fre_abs_start..curr_fre_abs_start + curr_fre_len]);

            entries.push(Entry {
                bytes,
                func_addr,
                fre_bytes,
            });
        }
    }

    if entries.is_empty() {
        return Ok(());
    }

    entries.sort_by(|a, b| a.func_addr.cmp(&b.func_addr));

    let output_fre_type = get_fre_type(max_addr_size, max_offset_size);

    let num_fdes = entries.len();
    let header_end_offset = HEADER_SIZE + output_aux_len;

    let fde_offset = 0;
    let fde_size = num_fdes * FDE_SIZE;
    let fre_offset = fde_size;

    let total_fre_size: usize = entries.iter().map(|e| e.fre_bytes.len()).sum();
    let total_size = header_end_offset + fde_size + total_fre_size;

    if total_size > section.len() {
        bail!("Merged SFrame section too large");
    }

    section[0..2].copy_from_slice(&SFRAME_MAGIC.to_le_bytes());
    section[VERSION_FIELD] = SFRAME_VERSION_2;
    output_flags |= FLAG_FDE_SORTED;
    section[FLAGS_FIELD] = output_flags;
    section[AUX_LENGTH_FIELD] = output_aux_len as u8;

    section[NUM_FDES_FIELD..NUM_FDES_FIELD + 4].copy_from_slice(&(num_fdes as u32).to_le_bytes());
    section[NUM_FRES_FIELD..NUM_FRES_FIELD + 4]
        .copy_from_slice(&(total_num_fres as u32).to_le_bytes());
    section[FRE_TYPE_FIELD..FRE_TYPE_FIELD + 4].copy_from_slice(&output_fre_type.to_le_bytes());
    section[FDE_START_OFFSET_FIELD..FDE_START_OFFSET_FIELD + 4]
        .copy_from_slice(&(fde_offset as u32).to_le_bytes());
    section[FRE_START_OFFSET_FIELD..FRE_START_OFFSET_FIELD + 4]
        .copy_from_slice(&(fre_offset as u32).to_le_bytes());

    let mut current_fre_rel_offset = 0;
    let fde_start_idx = header_end_offset + fde_offset;
    let fre_start_idx = header_end_offset + fre_offset;

    for (index, entry) in entries.iter().enumerate() {
        let mut fde_bytes = entry.bytes;

        let fde_pos_in_section = fde_start_idx + index * FDE_SIZE;
        let pc_rel = output_flags & FLAG_FUNC_START_PCREL != 0;

        let new_value = if pc_rel {
            entry.func_addr - (section_base + fde_pos_in_section as i128)
        } else {
            entry.func_addr - section_base
        };
        let new_value_i32 = i32::try_from(new_value)
            .context("Function start address out of 32-bit range for SFrame entry")?;
        write_i32(&mut fde_bytes, 0, new_value_i32);

        fde_bytes[8..12].copy_from_slice(&(current_fre_rel_offset as u32).to_le_bytes());

        section[fde_pos_in_section..fde_pos_in_section + FDE_SIZE].copy_from_slice(&fde_bytes);

        let fre_len = entry.fre_bytes.len();
        let fre_pos = fre_start_idx + current_fre_rel_offset;
        section[fre_pos..fre_pos + fre_len].copy_from_slice(&entry.fre_bytes);

        current_fre_rel_offset += fre_len;
    }

    // padding
    if total_size < section.len() {
        for i in total_size..section.len() {
            section[i] = 0;
        }
    }

    Ok(())
}
