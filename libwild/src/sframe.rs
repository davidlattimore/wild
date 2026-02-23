use crate::bail;
use crate::error::Context as _;
use crate::error::Result;
use crate::timing_phase;
use std::convert::TryFrom;
use std::convert::TryInto;

// Magic value identifying an SFrame section.
const SFRAME_MAGIC: u16 = 0xdee2;
// Current supported SFrame version.
const SFRAME_VERSION_2: u8 = 2;

const FLAG_FDE_SORTED: u8 = 0x1;
const FLAG_FRAME_POINTER: u8 = 0x2;
const FLAG_FUNC_START_PCREL: u8 = 0x4;
const FLAG_AARCH64_PAUTH: u8 = 0x8;

const HEADER_SIZE: usize = 0x1c;
const FDE_SIZE: usize = 20;

// Field offsets in the SFrame header
const VERSION_FIELD: usize = 0x02;
const FLAGS_FIELD: usize = 0x03;
const ABI_ARCH_FIELD: usize = 0x04;
const CFA_FIXED_FP_OFFSET_FIELD: usize = 0x05;
const CFA_FIXED_RA_OFFSET_FIELD: usize = 0x06;
const AUX_LENGTH_FIELD: usize = 0x07;
const NUM_FDES_FIELD: usize = 0x08;
const NUM_FRES_FIELD: usize = 0x0c;
const FRE_LEN_FIELD: usize = 0x10;
const FDE_START_OFFSET_FIELD: usize = 0x14;
const FRE_START_OFFSET_FIELD: usize = 0x18;

struct Entry {
    bytes: [u8; FDE_SIZE],
    func_addr: i128,
    fre_bytes: Vec<u8>,
}

#[derive(Debug, derive_more::Display)]
pub enum SframeError {
    #[display("Unsupported SFrame version {_0}")]
    UnsupportedVersion(u8),
    #[display("Invalid SFrame magic 0x{_0:x}")]
    BadMagicBytes(u16),
}

struct Header {
    magic: u16,
    version: u8,
    flags: u8,
    abi_arch: u8,
    cfa_fixed_fp_offset: i8,
    cfa_fixed_ra_offset: i8,
    aux_len: u8,
    num_fdes: u32,
    num_fres: u32,
    fre_len: u32,
    fde_start_offset: u32,
    fre_start_offset: u32,
}

impl Header {
    fn parse(data: &[u8]) -> Result<Self, SframeError> {
        let magic = read_u16(data, 0);
        if magic != SFRAME_MAGIC {
            return Err(SframeError::BadMagicBytes(magic));
        }

        let version = data[VERSION_FIELD];
        if version != SFRAME_VERSION_2 {
            return Err(SframeError::UnsupportedVersion(version));
        }

        Ok(Header {
            magic,
            version,
            flags: data[FLAGS_FIELD],
            abi_arch: data[ABI_ARCH_FIELD],
            cfa_fixed_fp_offset: data[CFA_FIXED_FP_OFFSET_FIELD] as i8,
            cfa_fixed_ra_offset: data[CFA_FIXED_RA_OFFSET_FIELD] as i8,
            aux_len: data[AUX_LENGTH_FIELD],
            num_fdes: read_u32(data, NUM_FDES_FIELD),
            num_fres: read_u32(data, NUM_FRES_FIELD),
            fre_len: read_u32(data, FRE_LEN_FIELD),
            fde_start_offset: read_u32(data, FDE_START_OFFSET_FIELD),
            fre_start_offset: read_u32(data, FRE_START_OFFSET_FIELD),
        })
    }

    fn write(&self, data: &mut [u8]) {
        data[0..2].copy_from_slice(&self.magic.to_le_bytes());
        data[VERSION_FIELD] = self.version;
        data[FLAGS_FIELD] = self.flags;
        data[ABI_ARCH_FIELD] = self.abi_arch;
        data[CFA_FIXED_FP_OFFSET_FIELD] = self.cfa_fixed_fp_offset as u8;
        data[CFA_FIXED_RA_OFFSET_FIELD] = self.cfa_fixed_ra_offset as u8;
        data[AUX_LENGTH_FIELD] = self.aux_len;
        data[NUM_FDES_FIELD..NUM_FDES_FIELD + 4].copy_from_slice(&self.num_fdes.to_le_bytes());
        data[NUM_FRES_FIELD..NUM_FRES_FIELD + 4].copy_from_slice(&self.num_fres.to_le_bytes());
        data[FRE_LEN_FIELD..FRE_LEN_FIELD + 4].copy_from_slice(&self.fre_len.to_le_bytes());
        data[FDE_START_OFFSET_FIELD..FDE_START_OFFSET_FIELD + 4]
            .copy_from_slice(&self.fde_start_offset.to_le_bytes());
        data[FRE_START_OFFSET_FIELD..FRE_START_OFFSET_FIELD + 4]
            .copy_from_slice(&self.fre_start_offset.to_le_bytes());
    }
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
pub(crate) fn sort_sframe_section(
    section: &mut [u8],
    section_base_address: u64,
    section_ranges: &[std::ops::Range<usize>],
) -> Result {
    if section.is_empty() {
        return Ok(());
    }
    timing_phase!("Sort .sframe");

    let mut entries = Vec::new();
    let section_base = i128::from(section_base_address);

    let mut output_flags = 0u8;
    let mut output_abi_arch = 0;
    let mut output_cfa_fixed_fp_offset = 0;
    let mut output_cfa_fixed_ra_offset = 0;
    let mut output_aux_len = 0;
    let mut total_num_fres = 0;
    let mut first_section = true;

    for range in section_ranges {
        let offset = range.start;
        let len = range.end - range.start;

        if len < HEADER_SIZE {
            continue;
        }

        let header = match Header::parse(&section[offset..offset + HEADER_SIZE]) {
            Ok(h) => h,
            Err(e @ SframeError::UnsupportedVersion(_)) => {
                crate::error::warning(&format!("{e}, disabling SFrame sorting"));
                return Ok(());
            }
            Err(e) => bail!("Failed to parse SFrame header at offset {}: {}", offset, e),
        };

        let pc_rel = header.flags & FLAG_FUNC_START_PCREL != 0;
        let aux_len = header.aux_len as usize;

        if first_section {
            output_flags = header.flags;
            output_abi_arch = header.abi_arch;
            output_cfa_fixed_fp_offset = header.cfa_fixed_fp_offset;
            output_cfa_fixed_ra_offset = header.cfa_fixed_ra_offset;
            output_aux_len = aux_len;
            first_section = false;
        } else {
            if (header.flags & FLAG_FRAME_POINTER) == 0 {
                output_flags &= !FLAG_FRAME_POINTER;
            }
            if (header.flags & FLAG_AARCH64_PAUTH) != 0 {
                output_flags |= FLAG_AARCH64_PAUTH;
            }
        }

        total_num_fres += header.num_fres as usize;

        let header_end_offset = HEADER_SIZE
            .checked_add(aux_len)
            .context("SFrame auxiliary header length overflow")?;

        let fde_start = offset + header_end_offset + header.fde_start_offset as usize;
        let fre_start = offset + header_end_offset + header.fre_start_offset as usize;

        let num_fdes = header.num_fdes as usize;
        let total_fde_bytes = FDE_SIZE
            .checked_mul(num_fdes)
            .context("SFrame FDE array size overflow")?;

        let fde_end = fde_start + total_fde_bytes;

        if fde_end > offset + len {
            bail!("SFrame FDE array truncated");
        }

        let mut fre_offsets = Vec::with_capacity(num_fdes + 1);
        for i in 0..num_fdes {
            let offset_in_section = fde_start + i * FDE_SIZE;
            let fre_offset = read_u32(section, offset_in_section + 8);
            fre_offsets.push(fre_offset);
        }

        // The end of the FRE data for this section is the upper bound.
        let max_fre_offset = (offset + len)
            .checked_sub(fre_start)
            .context("Invalid SFrame FRE start")? as u32;
        fre_offsets.push(max_fre_offset);

        fre_offsets.sort_unstable();
        fre_offsets.dedup();

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

            let curr_fre_offset = read_u32(&bytes, 8);

            // Find the length of the FRE data for this function.
            // It extends from curr_fre_offset to the next offset in our sorted list.
            let idx = fre_offsets.binary_search(&curr_fre_offset).map_err(|_| {
                crate::error::Error::with_message("FRE offset not found in sorted list")
            })?;

            let next_fre_offset = *fre_offsets.get(idx + 1).ok_or_else(|| {
                crate::error::Error::with_message("FRE offset index out of bounds")
            })?;

            let curr_fre_len = (next_fre_offset - curr_fre_offset) as usize;
            let curr_fre_abs_start = fre_start + curr_fre_offset as usize;

            if curr_fre_abs_start + curr_fre_len > offset + len {
                bail!("SFrame FRE data truncated");
            }

            let fre_bytes =
                section[curr_fre_abs_start..curr_fre_abs_start + curr_fre_len].to_owned();

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

    entries.sort_by_key(|a| a.func_addr);

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

    let header = Header {
        magic: SFRAME_MAGIC,
        version: SFRAME_VERSION_2,
        flags: output_flags | FLAG_FDE_SORTED,
        abi_arch: output_abi_arch,
        cfa_fixed_fp_offset: output_cfa_fixed_fp_offset,
        cfa_fixed_ra_offset: output_cfa_fixed_ra_offset,
        aux_len: output_aux_len as u8,
        num_fdes: num_fdes as u32,
        num_fres: total_num_fres as u32,
        fre_len: total_fre_size as u32,
        fde_start_offset: fde_offset as u32,
        fre_start_offset: fre_offset as u32,
    };
    header.write(&mut section[0..HEADER_SIZE]);

    let mut current_fre_rel_offset = 0;
    let fde_start_idx = header_end_offset + fde_offset;
    let fre_start_idx = header_end_offset + fre_offset;

    for (index, entry) in entries.iter().enumerate() {
        let mut fde_bytes = entry.bytes;

        let fde_pos_in_section = fde_start_idx + index * FDE_SIZE;
        let pc_rel = header.flags & FLAG_FUNC_START_PCREL != 0;

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
        section[total_size..].fill(0);
    }

    Ok(())
}
