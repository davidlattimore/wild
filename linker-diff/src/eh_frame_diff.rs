use crate::Result;
use crate::header_diff::Converter;
use crate::header_diff::DiffMode;
use crate::header_diff::FieldValues;
use anyhow::Context;
use anyhow::bail;
use bytemuck::Pod;
use bytemuck::Zeroable;
use linker_utils::elf::secnames::EH_FRAME_HDR_SECTION_NAME_STR;
use linker_utils::elf::secnames::EH_FRAME_SECTION_NAME_STR;
use linker_utils::utils::u32_from_slice;
use object::LittleEndian;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use object::SymbolKind;
use object::elf::ProgramHeader64;
use object::read::elf::ProgramHeader;
use std::collections::HashMap;
use std::collections::HashSet;
use std::mem::offset_of;

pub(crate) fn report_diffs(report: &mut crate::Report, objects: &[crate::Binary]) {
    report.add_diffs(crate::header_diff::diff_fields(
        objects,
        read_eh_frame_hdr_fields,
        "eh_frame",
        DiffMode::Normal,
    ));
}

fn read_eh_frame_hdr_fields(object: &crate::Binary) -> Result<FieldValues> {
    let mut values = FieldValues::default();

    let Some(segment_hdr) = eh_frame_segment(object) else {
        values.insert_string_owned("GNU_EH_FRAME".to_owned(), "Missing".to_owned());
        return Ok(values);
    };

    let Some(section) = object.section_by_name(EH_FRAME_HDR_SECTION_NAME_STR) else {
        values.insert_string_owned(
            EH_FRAME_HDR_SECTION_NAME_STR.to_owned(),
            "Missing".to_owned(),
        );
        return Ok(values);
    };

    let address1 = segment_hdr.p_vaddr(LittleEndian);
    let address2 = section.address();
    if address1 != address2 {
        bail!(".eh_frame_hdr address doesn't match GNU_EN_FRAME segment");
    }

    let data = section.data()?;
    let header: &EhFrameHdr = bytemuck::from_bytes(&data[..size_of::<EhFrameHdr>()]);
    let header_entries: &[EhFrameHdrEntry] = bytemuck::cast_slice(&data[size_of::<EhFrameHdr>()..]);

    values.insert("version", header.version, Converter::None, object);
    values.insert(
        "frame_pointer_encoding",
        header.frame_pointer_encoding,
        Converter::None,
        object,
    );
    values.insert(
        "count_encoding",
        header.count_encoding,
        Converter::None,
        object,
    );
    values.insert(
        "table_encoding",
        header.table_encoding,
        Converter::None,
        object,
    );
    values.insert(
        "frame_pointer",
        (address1 as i64 + i64::from(header.frame_pointer)) as u64
            + offset_of!(EhFrameHdr, frame_pointer) as u64,
        Converter::SectionAddress,
        object,
    );

    // The rest of our checking code only currently supports one set of encodings for now.
    if header.frame_pointer_encoding != 0x1b {
        bail!(
            "Unsupported frame pointer encoding 0x{:x}",
            header.frame_pointer_encoding
        );
    }
    if header.count_encoding != 3 {
        bail!("Unsupported count encoding 0x{:x}", header.count_encoding);
    }
    if header.table_encoding != 0x3b {
        bail!("Unsupported table encoding 0x{:x}", header.table_encoding);
    }

    verify_frames(object, &mut values, header_entries, address1)?;
    Ok(values)
}

const EH_FRAME_PC_BEGIN_OFFSET: usize = 8;

fn verify_frames(
    object: &crate::Binary,
    values: &mut FieldValues,
    header_entries: &[EhFrameHdrEntry],
    header_base: u64,
) -> Result {
    let mut functions_without_frame_info = HashMap::new();
    for sym in object.elf_file.symbols() {
        if sym.kind() == SymbolKind::Text {
            functions_without_frame_info.insert(sym.address(), sym);
        }
    }

    let mut frame_to_info = HashMap::new();

    let eh_frame_section = object
        .section_by_name(EH_FRAME_SECTION_NAME_STR)
        .context("Missing .eh_frame section")?;
    let eh_frame_base = eh_frame_section.address();
    let eh_frame_data = eh_frame_section.data()?;
    let mut offset = 0;
    const PREFIX_LEN: usize = size_of::<EhFrameEntryPrefix>();
    while offset + PREFIX_LEN <= eh_frame_data.len() {
        let prefix: EhFrameEntryPrefix =
            bytemuck::pod_read_unaligned(&eh_frame_data[offset..offset + PREFIX_LEN]);
        if prefix.cie_id != 0 {
            // This is an FDE.
            let pc_begin_bytes = eh_frame_data[offset + EH_FRAME_PC_BEGIN_OFFSET..]
                .first_chunk::<4>()
                .context("Invalid FDE")?;
            let info_address = eh_frame_base + offset as u64;
            let pc_begin = (info_address + EH_FRAME_PC_BEGIN_OFFSET as u64)
                .wrapping_add(i64::from(i32::from_le_bytes(*pc_begin_bytes)) as u64);
            functions_without_frame_info.remove(&pc_begin);
            // Note, we don't check the symbol that we matched against because some frames won't
            // have symbols.
            if let Some(previous_info) = frame_to_info.insert(pc_begin, info_address) {
                bail!(
                    "Duplicate frame info for address 0x{pc_begin:x}. \
                     0x:{previous_info:x}, 0x{info_address:x}"
                );
            }
        }
        offset += size_of_val(&prefix.length) + prefix.length as usize;
    }

    // TODO: Enable this or clean it it up.
    if false {
        for sym in functions_without_frame_info.values() {
            if sym.size() == 0 {
                continue;
            }
            values.insert_string_owned(
                format!("fn.{}", sym.name()?),
                "Missing frame info".to_owned(),
            );
        }
    }

    let mut seen = HashSet::new();
    for hdr in header_entries {
        let frame_address = (header_base as i64 + i64::from(hdr.frame_ptr)) as u64;
        let hdr_info_address = (header_base as i64 + i64::from(hdr.frame_info_ptr)) as u64;
        if let Some(info_address) = frame_to_info.remove(&frame_address) {
            seen.insert(frame_address);
            if hdr_info_address != info_address {
                bail!(
                    ".eh_frame_hdr info address didn't match for 0x{frame_address:x}. \
                     .eh_frame_hdr has 0x{hdr_info_address:x}, but .eh_frame has \
                     0x{info_address:x}"
                );
            }
        } else if seen.contains(&frame_address) {
            // TODO: Investigate and consider if this should be an error.

            //bail!("Address 0x{frame_address:x} is duplicated in .eh_frame_hdr");
        } else if let Some(pc_begin) =
            read_eh_frame_pc_begin(eh_frame_data, hdr_info_address, eh_frame_base)
        {
            let offset = hdr_info_address - eh_frame_base;
            bail!(
                ".eh_frame_hdr is inconsistent with .eh_frame. Entry at 0x{hdr_info_address:x} \
                 (offset 0x{offset:x}) is for frame 0x{pc_begin:x}, but .eh_frame_hdr says \
                 0x{frame_address:x}"
            );
        } else {
            bail!(".eh_frame_hdr contains invalid info pointer 0x{hdr_info_address:x}");
        }
    }

    Ok(())
}

fn read_eh_frame_pc_begin(
    eh_frame_data: &[u8],
    hdr_info_address: u64,
    eh_frame_base: u64,
) -> Option<u64> {
    let start_offset =
        hdr_info_address.checked_sub(eh_frame_base)? as usize + EH_FRAME_PC_BEGIN_OFFSET;
    if start_offset >= eh_frame_data.len() {
        return None;
    }
    Some(
        (hdr_info_address + EH_FRAME_PC_BEGIN_OFFSET as u64)
            .wrapping_add(i64::from(u32_from_slice(&eh_frame_data[start_offset..])) as u64),
    )
}

fn eh_frame_segment(object: &crate::Binary) -> Option<ProgramHeader64<LittleEndian>> {
    for hdr in object.elf_file.elf_program_headers() {
        if hdr.p_type.get(LittleEndian) == object::elf::PT_GNU_EH_FRAME {
            return Some(*hdr);
        }
    }
    None
}

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
struct EhFrameHdr {
    version: u8,
    frame_pointer_encoding: u8,
    count_encoding: u8,
    table_encoding: u8,
    // For now we just use 32 bit pointer and count because it means that they're aligned. If we
    // need to upgrade these to u64, then we'd have to write these as unaligned fields.
    frame_pointer: i32,
    entry_count: u32,
}

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
struct EhFrameHdrEntry {
    frame_ptr: i32,
    frame_info_ptr: i32,
}

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
struct EhFrameEntryPrefix {
    length: u32,
    cie_id: u32,
}
