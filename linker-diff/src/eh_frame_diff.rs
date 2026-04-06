use crate::Result;
use crate::header_diff::Converter;
use crate::header_diff::DiffMode;
use crate::header_diff::FieldValues;
use anyhow::Context;
use anyhow::bail;
use gimli::EndianSlice;
use gimli::UnwindSection;
use hashbrown::HashMap;
use linker_utils::elf::secnames::EH_FRAME_HDR_SECTION_NAME_STR;
use linker_utils::elf::secnames::EH_FRAME_SECTION_NAME_STR;
use object::LittleEndian;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use object::SymbolKind;
use object::elf::ProgramHeader64;
use object::read::elf::ProgramHeader;
use std::mem::offset_of;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::KnownLayout;

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
    let header = EhFrameHdr::ref_from_bytes(&data[..size_of::<EhFrameHdr>()]).unwrap();
    let Ok(header_entries) = <[EhFrameHdrEntry]>::ref_from_bytes(&data[size_of::<EhFrameHdr>()..])
    else {
        bail!("Size mismatch in .eh_frame_hdr entries");
    };

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

    let eh_frame_section = object
        .section_by_name(EH_FRAME_SECTION_NAME_STR)
        .context("Missing .eh_frame section")?;
    let eh_frame_base = eh_frame_section.address();
    let eh_frame_data = eh_frame_section.data()?;

    let eh_frame: gimli::EhFrame<EndianSlice<'_, gimli::LittleEndian>> =
        gimli::EhFrame::new(eh_frame_data, gimli::LittleEndian);
    let bases = gimli::BaseAddresses::default().set_eh_frame(eh_frame_base);

    // Multiple FDEs can legitimately share a pc_begin, so track all of them.
    let mut frame_to_infos: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut info_to_pc_begin: HashMap<u64, u64> = HashMap::new();

    let mut entries = eh_frame.entries(&bases);
    while let Some(entry) = entries.next()? {
        if let gimli::CieOrFde::Fde(partial) = entry {
            let info_address = eh_frame_base + partial.offset() as u64;
            let fde =
                partial.parse(|section, bases, offset| section.cie_from_offset(bases, offset))?;
            let pc_begin = fde.initial_address();
            functions_without_frame_info.remove(&pc_begin);
            frame_to_infos
                .entry(pc_begin)
                .or_default()
                .push(info_address);
            info_to_pc_begin.insert(info_address, pc_begin);
        }
    }

    // TODO: Enable this or clean it up.
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

    for hdr in header_entries {
        let frame_address = (header_base as i64 + i64::from(hdr.frame_ptr)) as u64;
        let hdr_info_address = (header_base as i64 + i64::from(hdr.frame_info_ptr)) as u64;
        if let Some(infos) = frame_to_infos.get(&frame_address) {
            if !infos.contains(&hdr_info_address) {
                bail!(
                    ".eh_frame_hdr info address didn't match for 0x{frame_address:x}. \
                     .eh_frame_hdr has 0x{hdr_info_address:x}, but .eh_frame has {:?}",
                    infos.iter().map(|a| format!("0x{a:x}")).collect::<Vec<_>>()
                );
            }
        } else if let Some(&pc_begin) = info_to_pc_begin.get(&hdr_info_address) {
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

fn eh_frame_segment(object: &crate::Binary) -> Option<ProgramHeader64<LittleEndian>> {
    for hdr in object.elf_file.elf_program_headers() {
        if hdr.p_type.get(LittleEndian) == object::elf::PT_GNU_EH_FRAME {
            return Some(*hdr);
        }
    }
    None
}

#[derive(FromBytes, KnownLayout, Immutable, Clone, Copy)]
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

#[derive(FromBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
struct EhFrameHdrEntry {
    frame_ptr: i32,
    frame_info_ptr: i32,
}
