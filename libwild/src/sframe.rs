use crate::bail;
use crate::error::Context as _;
use crate::error::Result;
use std::convert::TryInto;

/// Magic value identifying an SFrame section.
const SFRAME_MAGIC: u16 = 0xdee2;
/// Current supported SFrame version.
const SFRAME_VERSION_2: u8 = 2;

const FLAG_FDE_SORTED: u8 = 0x1;
const FLAG_FUNC_START_PCREL: u8 = 0x4;

const HEADER_SIZE: usize = 0x1c;
const FDE_SIZE: usize = 20;
const FDE_START_OFFSET_FIELD: usize = 0x14;
const NUM_FDES_FIELD: usize = 0x08;
const AUX_LENGTH_FIELD: usize = 0x07;
const FLAGS_FIELD: usize = 0x03;
const VERSION_FIELD: usize = 0x02;

struct Entry {
    bytes: [u8; FDE_SIZE],
    func_addr: i128,
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

/// Sort the SFrame FDE array in-place by the functions' start addresses.
///
/// The SFrame header will be updated to mark the array as sorted. The FRE data is left untouched
/// as the descriptor entries reference it by offset.
pub(crate) fn sort_sframe_section(section: &mut [u8], section_base_address: u64) -> Result {
    if section.is_empty() {
        return Ok(());
    }

    if section.len() < HEADER_SIZE {
        bail!("SFrame section smaller than header");
    }

    let magic = read_u16(section, 0);
    if magic != SFRAME_MAGIC {
        bail!("Invalid SFrame magic 0x{:x}", magic);
    }

    let version = section[VERSION_FIELD];
    if version != SFRAME_VERSION_2 {
        bail!(
            "Unsupported SFrame version {} (expected {})",
            version,
            SFRAME_VERSION_2
        );
    }

    let mut flags = section[FLAGS_FIELD];
    let pc_rel = flags & FLAG_FUNC_START_PCREL != 0;
    let aux_len = section[AUX_LENGTH_FIELD] as usize;

    let header_end_offset = HEADER_SIZE
        .checked_add(aux_len)
        .context("SFrame auxiliary header length overflow")?;
    if section.len() < header_end_offset {
        bail!("SFrame header auxiliary data truncated");
    }

    let num_fdes = read_u32(section, NUM_FDES_FIELD) as usize;
    if num_fdes == 0 {
        section[FLAGS_FIELD] = flags | FLAG_FDE_SORTED;
        return Ok(());
    }

    let fde_offset = read_u32(section, FDE_START_OFFSET_FIELD) as usize;
    let fde_start = header_end_offset
        .checked_add(fde_offset)
        .context("SFrame FDE offset overflow")?;
    let total_fde_bytes = FDE_SIZE
        .checked_mul(num_fdes)
        .context("SFrame FDE array size overflow")?;
    let fde_end = fde_start
        .checked_add(total_fde_bytes)
        .context("SFrame FDE array extends past section")?;
    if fde_end > section.len() {
        bail!("SFrame FDE array truncated");
    }

    let section_base = i128::from(section_base_address);

    let mut entries = Vec::with_capacity(num_fdes);
    for index in 0..num_fdes {
        let offset_in_section = fde_start + index * FDE_SIZE;
        let mut bytes = [0u8; FDE_SIZE];
        bytes.copy_from_slice(&section[offset_in_section..offset_in_section + FDE_SIZE]);
        let start_value = i128::from(read_i32(&bytes, 0));
        let func_addr = if pc_rel {
            section_base + offset_in_section as i128 + start_value
        } else {
            section_base + start_value
        };
        entries.push(Entry {
            bytes,
            func_addr,
        });
    }

    entries.sort_by(|a, b| a.func_addr.cmp(&b.func_addr));

    flags |= FLAG_FDE_SORTED;
    section[FLAGS_FIELD] = flags;

    for (index, entry) in entries.into_iter().enumerate() {
        let offset_in_section = fde_start + index * FDE_SIZE;
        let new_value = if pc_rel {
            entry.func_addr - (section_base + offset_in_section as i128)
        } else {
            entry.func_addr - section_base
        };
        let new_value_i32 = i32::try_from(new_value)
            .context("Function start address out of 32-bit range for SFrame entry")?;
        let mut bytes = entry.bytes;
        write_i32(&mut bytes, 0, new_value_i32);
        section[offset_in_section..offset_in_section + FDE_SIZE].copy_from_slice(&bytes);
    }

    Ok(())
}
