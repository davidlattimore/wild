use crate::alignment::MACHO_PAGE_ALIGNMENT;
use crate::bail;
use crate::elf::get_page_mask;
use crate::ensure;
use crate::error;
use crate::error::Context;
use crate::error::Result;
use crate::file_writer::SizedOutput;
use crate::file_writer::split_buffers_by_alignment;
use crate::file_writer::split_output_by_group;
use crate::file_writer::split_output_into_sections;
use crate::layout::EpilogueLayout;
use crate::layout::FileLayout;
use crate::layout::Layout;
use crate::layout::ObjectLayout;
use crate::layout::OutputRecordLayout;
use crate::layout::PreludeLayout;
use crate::layout::Resolution;
use crate::layout::ResolutionState;
use crate::layout::Section;
use crate::layout::SymbolCopyInfo;
use crate::macho::CHAINED_FIXUP_PAGE_START_SIZE;
use crate::macho::CS_BLOB_HEADERS_SIZE;
use crate::macho::CS_BLOCK_SIZE;
use crate::macho::CS_BLOCK_SIZE_EXP;
use crate::macho::CS_HASH_SIZE;
use crate::macho::ChainedFixupsHeader;
use crate::macho::CodeSignatureCommand;
use crate::macho::DYLINKER_PATH;
use crate::macho::DyldChainedFixupsCommand;
use crate::macho::DylibCommand;
use crate::macho::DylinkerCommand;
use crate::macho::EntryPointCommand;
use crate::macho::FileHeader;
use crate::macho::GOT_ENTRY_SIZE;
use crate::macho::MACHO_COMMAND_ALIGNMENT;
use crate::macho::MACHO_START_MEM_ADDRESS;
use crate::macho::MAX_SEGMENT_COUNT;
use crate::macho::MachO;
use crate::macho::PLT_ENTRY_SIZE;
use crate::macho::PROGRAM_SEGMENT_DEFS;
use crate::macho::SEG_DATA_CONST;
use crate::macho::SectionEntry;
use crate::macho::SegmentCommand;
use crate::macho::SegmentSectionsInfo;
use crate::macho::SegmentType;
use crate::macho::SymtabCommand;
use crate::macho::code_signature_identifier;
use crate::macho::code_signature_padded_identifier_size;
use crate::macho::get_segment_sections;
use crate::macho::load_dylib_command_size;
use crate::macho_object::CS_ADHOC;
use crate::macho_object::CS_EXECSEG_MAIN_BINARY;
use crate::macho_object::CS_HASHTYPE_SHA256;
use crate::macho_object::CS_LINKER_SIGNED;
use crate::macho_object::CS_SUPPORTSEXECSEG;
use crate::macho_object::CSMAGIC_CODEDIRECTORY;
use crate::macho_object::CSMAGIC_EMBEDDED_SIGNATURE;
use crate::macho_object::CSSLOT_CODEDIRECTORY;
use crate::macho_object::CodeSignatureBlobIndex;
use crate::macho_object::CodeSignatureCodeDirectory;
use crate::macho_object::CodeSignatureSuperBlob;
use crate::macho_object::DYLD_CHAINED_IMPORT;
use crate::macho_object::DYLD_CHAINED_PTR_64_OFFSET;
use crate::macho_object::DyldChainedStartsInSegment;
use crate::output_section_id;
use crate::output_section_id::SectionName;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::output_trace::HexU64;
use crate::output_trace::TraceOutput;
use crate::part_id;
use crate::platform::Arch;
use crate::platform::Args;
use crate::platform::ObjectFile;
use crate::platform::Symbol;
use crate::resolution::SectionSlot;
use crate::symbol_db::SymbolId;
use crate::timing_phase;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use itertools::Itertools;
use linker_utils::elf::RelocationKind;
use linker_utils::utils::slice_from_all_bytes_mut;
use object::BigEndian;
use object::Endianness;
use object::SymbolIndex;
use object::U16;
use object::U32;
use object::from_bytes_mut;
use object::macho;
use object::macho::CPU_SUBTYPE_ARM64_ALL;
use object::macho::CPU_TYPE_ARM64;
use object::macho::LC_CODE_SIGNATURE;
use object::macho::LC_DYLD_CHAINED_FIXUPS;
use object::macho::LC_LOAD_DYLIB;
use object::macho::LC_LOAD_DYLINKER;
use object::macho::LC_MAIN;
use object::macho::LC_SEGMENT_64;
use object::macho::LC_SYMTAB;
use object::macho::MH_CIGAM_64;
use object::macho::MH_EXECUTE;
use object::macho::N_ABS;
use object::macho::N_SECT;
use object::macho::RelocationInfo;
use object::macho::SEG_DATA;
use object::macho::SEG_LINKEDIT;
use object::macho::SEG_PAGEZERO;
use object::macho::SEG_TEXT;
use object::slice_from_bytes_mut;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;
use sha2::Digest;
use sha2::Sha256;
use std::ops::BitAnd;
use tracing::debug_span;
use zerocopy::FromBytes;
use zerocopy::FromZeros;

const LE: Endianness = Endianness::Little;

type MachOLayout<'data> = Layout<'data, MachO>;
type SymtabEntry = object::macho::Nlist64<Endianness>;

pub(crate) fn write<'data, A: Arch<Platform = MachO>>(
    sized_output: &mut SizedOutput,
    layout: &MachOLayout<'data>,
) -> Result {
    timing_phase!("Write data to file");
    let (mut section_buffers, mut padding) =
        split_output_into_sections(layout, &mut sized_output.out);
    padding.fill_zero();

    let mut writable_buckets = split_buffers_by_alignment(&mut section_buffers, layout);
    let groups_and_buffers = split_output_by_group(layout, &mut writable_buckets);
    groups_and_buffers
        .into_par_iter()
        .try_for_each(|(group, mut buffers)| -> Result {
            verbose_timing_phase!("Write group");

            let mut symbol_writer = MachOSymbolTableWriter {
                next_strtab_offset: group.strtab_start_offset,
            };
            for file in &group.files {
                write_file::<A>(
                    file,
                    &mut buffers,
                    layout,
                    &sized_output.trace,
                    &mut symbol_writer,
                )
                .with_context(|| format!("Failed copying from {file} to output file"))?;
            }
            Ok(())
        })?;

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;
    write_got_entries(layout, section_buffers.get_mut(output_section_id::GOT))?;
    write_plt_entries::<A>(layout, section_buffers.get_mut(output_section_id::PLT_GOT))?;

    write_code_signature(layout, sized_output)?;

    Ok(())
}

fn write_file<'data, A: Arch<Platform = MachO>>(
    file: &FileLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    _trace: &TraceOutput,
    symbol_writer: &mut MachOSymbolTableWriter,
) -> Result {
    match file {
        FileLayout::Object(s) => {
            write_object::<A>(s, buffers, layout, symbol_writer)?;
        }
        FileLayout::Prelude(s) => write_prelude::<A>(s, buffers, layout)?,
        FileLayout::Epilogue(s) => write_epilogue::<A>(s, buffers, layout)?,
        _ => {
            // TODO
        }
    }
    Ok(())
}

fn write_prelude<'data, A: Arch<Platform = MachO>>(
    prelude: &PreludeLayout<MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
) -> Result {
    verbose_timing_phase!("Write prelude");
    debug_assert_eq!(
        prelude.imported_library_paths.len(),
        prelude.format_specific.load_dylib_command_sizes.len()
    );

    let header = from_bytes_mut(buffers.get_mut(part_id::FILE_HEADER))
        .map_err(|_| error!("Invalid file header allocation"))?
        .0;
    populate_file_header::<A>(layout, prelude, header)?;

    let load_cmd_err = |()| error!("Invalid LOAD_COMMANDS allocation");
    let mut load_command_buffer = slice_from_all_bytes_mut(buffers.get_mut(part_id::LOAD_COMMANDS));
    write_segment_commands::<A>(layout, &mut load_command_buffer)?;

    let (entry_point_command, mut load_command_buffer) =
        from_bytes_mut(load_command_buffer).map_err(load_cmd_err)?;
    write_entry_point_command::<A>(layout, entry_point_command)?;

    let command_size = (size_of::<DylinkerCommand>() + DYLINKER_PATH.len())
        .next_multiple_of(MACHO_COMMAND_ALIGNMENT);
    let command_buffer = load_command_buffer.split_off_mut(..command_size).unwrap();
    let (dylinker_command, dylinker_path_buffer) =
        from_bytes_mut(command_buffer).map_err(|_| error!("Invalid INTERP command allocation"))?;
    write_dylinker_command::<A>(dylinker_command, dylinker_path_buffer);

    for (path, &command_size) in prelude
        .imported_library_paths
        .iter()
        .zip(&prelude.format_specific.load_dylib_command_sizes)
    {
        let command_buffer = load_command_buffer.split_off_mut(..command_size).unwrap();
        let (dylib_command, dylib_path_buffer) =
            from_bytes_mut(command_buffer).map_err(load_cmd_err)?;
        write_dylib_command::<A>(dylib_command, dylib_path_buffer, path.as_bytes());
    }

    let (chained_fixups_command, load_command_buffer) =
        from_bytes_mut(load_command_buffer).map_err(load_cmd_err)?;
    write_dyld_chained_fixups_command::<A>(layout, chained_fixups_command);

    let (symtab_command, load_command_buffer) =
        from_bytes_mut(load_command_buffer).map_err(load_cmd_err)?;
    write_symtab_command::<A>(layout, symtab_command);

    let (code_signature_command, load_command_buffer) =
        from_bytes_mut(load_command_buffer).map_err(load_cmd_err)?;
    write_code_signature_command::<A>(layout, code_signature_command);
    ensure!(
        load_command_buffer.is_empty(),
        "Trailing bytes in LOAD_COMMANDS allocation"
    );

    // Fill up one extra character as n_strx == 0 is treated as unnamed.
    buffers.get_mut(part_id::STRTAB).fill(0);

    Ok(())
}

fn write_epilogue<A: Arch<Platform = MachO>>(
    _epilogue: &EpilogueLayout<MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'_>,
) -> Result {
    verbose_timing_phase!("Write epilogue");
    write_chained_fixup_table::<A>(layout, buffers.get_mut(part_id::CHAINED_FIXUP_TABLE))?;

    Ok(())
}

fn write_got_entries(layout: &MachOLayout<'_>, got: &mut [u8]) -> Result {
    let got_layout = layout.section_layouts.get(output_section_id::GOT);

    let sorted_symbols = &layout.format_specific.imported_symbols;
    for (i, imported_symbol) in sorted_symbols.iter().enumerate() {
        let offset = imported_symbol
            .got_address
            .get()
            .checked_sub(got_layout.mem_offset)
            .ok_or_else(|| error!("GOT entry address is before __got"))?
            as usize;
        let end = offset + GOT_ENTRY_SIZE as usize;

        /* DYLD_CHAINED_PTR_64 format:
        uint64_t dyld_chained_ptr_64_bind:
          ordinal: 24
          addend: 8 // 0 thru 255
          reserved: 19 // all zeros
          next: 12 // 4-byte stride
          bind: 1 // == 1
        */
        let bind = 1u64 << 63;
        // TODO: when crossing a page boundary, next is equal to zero
        let next = if i == sorted_symbols.len() - 1 { 0 } else { 2 };
        let next = next << 51;
        let ordinal = i as u64;
        got[offset..end].copy_from_slice(&(bind | next | ordinal).to_le_bytes());
    }

    Ok(())
}

fn write_plt_entries<A: Arch<Platform = MachO>>(
    layout: &MachOLayout<'_>,
    plt: &mut [u8],
) -> Result {
    let plt_layout = layout.section_layouts.get(output_section_id::PLT_GOT);

    for imported_symbol in &layout.format_specific.imported_symbols {
        let Some(stub_address) = imported_symbol.plt_address else {
            continue;
        };

        let offset = stub_address
            .get()
            .checked_sub(plt_layout.mem_offset)
            .ok_or_else(|| error!("STUB entry address is before __stubs"))?
            as usize;
        let end = offset + PLT_ENTRY_SIZE as usize;

        A::write_plt_entry(
            &mut plt[offset..end],
            imported_symbol.got_address.get(),
            stub_address.get(),
        )?;
    }

    Ok(())
}

fn populate_file_header<A: Arch<Platform = MachO>>(
    layout: &MachOLayout,
    prelude: &PreludeLayout<MachO>,
    header: &mut FileHeader,
) -> Result {
    let load_commands_info = get_segment_sections(layout, SegmentType::LoadCommands)
        .ok_or_else(|| error!("LoadCommands segment is mandatory"))?;

    header.magic.set(BigEndian, MH_CIGAM_64);
    header.cputype.set(LE, CPU_TYPE_ARM64);
    header.cpusubtype.set(LE, CPU_SUBTYPE_ARM64_ALL.into());
    header.filetype.set(LE, MH_EXECUTE);
    header
        .ncmds
        .set(LE, prelude.format_specific.load_command_count as u32);
    header
        .sizeofcmds
        .set(LE, load_commands_info.segment_size.file_size as u32);
    header.flags.set(
        LE,
        macho::MH_PIE | macho::MH_DYLDLINK | macho::MH_NOUNDEFS | macho::MH_TWOLEVEL,
    );
    header.reserved.set(LE, 0);
    Ok(())
}

fn split_segment_command_buffer(
    bytes: &mut [u8],
    section_count: usize,
) -> Result<(&mut SegmentCommand, &mut [SectionEntry])> {
    let (command, rest) =
        from_bytes_mut(bytes).map_err(|_| error!("Invalid segment command allocation"))?;
    let (sections, rest) = slice_from_bytes_mut(rest, section_count)
        .map_err(|_| error!("Invalid segment section allocation"))?;
    ensure!(
        rest.is_empty(),
        "Trailing bytes in segment command allocation"
    );
    Ok((command, sections))
}

fn write_segment_commands<A: Arch<Platform = MachO>>(
    layout: &MachOLayout,
    load_commands: &mut &mut [u8],
) -> Result {
    let load_cmd_err = |()| error!("Invalid LOAD_COMMANDS allocation");
    let pagezero_segment = from_bytes_mut(
        load_commands
            .split_off_mut(..size_of::<SegmentCommand>())
            .unwrap(),
    )
    .map_err(load_cmd_err)?
    .0;
    write_segment(
        SEG_PAGEZERO,
        macho::VmProt(0),
        pagezero_segment,
        0,
        0,
        0,
        MACHO_START_MEM_ADDRESS,
        0,
    );

    let text_segment_sections = get_segment_sections(layout, SegmentType::TextSections)
        .ok_or_else(|| error!("TextSections segment is mandatory"))?
        .segment_sections;
    // The __TEXT segment in the layout includes also all the commands!
    let text_segment_size = get_segment_sections(layout, SegmentType::Text)
        .ok_or_else(|| error!("Text segment is mandatory"))?
        .segment_size;
    let command_size =
        size_of::<SegmentCommand>() + size_of::<SectionEntry>() * text_segment_sections.len();
    let (text_segment, text_sections) = split_segment_command_buffer(
        load_commands
            .split_off_mut(..command_size)
            .ok_or_else(|| load_cmd_err(()))?,
        text_segment_sections.len(),
    )?;
    write_segment(
        SEG_TEXT,
        macho::VM_PROT_READ | macho::VM_PROT_EXECUTE,
        text_segment,
        text_segment_size.file_offset as u64,
        text_segment_size.file_size as u64,
        text_segment_size.mem_offset,
        text_segment_size.mem_size,
        text_segment_sections.len(),
    );
    write_sections(SEG_TEXT, text_sections, &text_segment_sections)?;

    if let Some(data_segment_info) = get_segment_sections(layout, SegmentType::DataSections) {
        let data_segment_sections = data_segment_info.segment_sections;
        let data_segment_size = data_segment_info.segment_size;
        let command_size =
            size_of::<SegmentCommand>() + size_of::<SectionEntry>() * data_segment_sections.len();
        let (data_segment, data_sections) = split_segment_command_buffer(
            load_commands
                .split_off_mut(..command_size)
                .ok_or_else(|| load_cmd_err(()))?,
            data_segment_sections.len(),
        )?;
        write_segment(
            SEG_DATA,
            macho::VM_PROT_READ | macho::VM_PROT_WRITE,
            data_segment,
            data_segment_size.file_offset as u64,
            data_segment_size.file_size as u64,
            data_segment_size.mem_offset,
            data_segment_size.mem_size,
            data_segment_sections.len(),
        );
        write_sections(SEG_DATA, data_sections, &data_segment_sections)?;
    }

    if let Some(data_const_segment_info) =
        get_segment_sections(layout, SegmentType::DataConstSections)
    {
        let data_const_segment_sections = data_const_segment_info.segment_sections;
        let data_const_segment_size = data_const_segment_info.segment_size;
        let command_size = size_of::<SegmentCommand>()
            + size_of::<SectionEntry>() * data_const_segment_sections.len();
        let (data_const_segment, data_const_sections) = split_segment_command_buffer(
            load_commands
                .split_off_mut(..command_size)
                .ok_or_else(|| load_cmd_err(()))?,
            data_const_segment_sections.len(),
        )?;
        write_segment(
            SEG_DATA_CONST,
            macho::VM_PROT_READ | macho::VM_PROT_WRITE,
            data_const_segment,
            data_const_segment_size.file_offset as u64,
            data_const_segment_size.file_size as u64,
            data_const_segment_size.mem_offset,
            data_const_segment_size.mem_size,
            data_const_segment_sections.len(),
        );
        write_sections(
            SEG_DATA_CONST,
            data_const_sections,
            &data_const_segment_sections,
        )?;
    }

    let linkedit_segment_size = get_segment_sections(layout, SegmentType::LinkeditSections)
        .ok_or_else(|| error!("LinkeditSections segment is mandatory"))?
        .segment_size;
    let linkedit_segment = from_bytes_mut(
        load_commands
            .split_off_mut(..size_of::<SegmentCommand>())
            .ok_or_else(|| load_cmd_err(()))?,
    )
    .map_err(load_cmd_err)?
    .0;
    write_segment(
        SEG_LINKEDIT,
        macho::VM_PROT_READ,
        linkedit_segment,
        linkedit_segment_size.file_offset as u64,
        linkedit_segment_size.file_size as u64,
        linkedit_segment_size.mem_offset,
        linkedit_segment_size.mem_size,
        // The sections in the __LINKEDIT are "hidden".
        0,
    );
    Ok(())
}

fn write_segment(
    seg_name: &str,
    prot_flags: object::macho::VmProt,
    segment_cmd: &mut SegmentCommand,
    file_offset: u64,
    file_size: u64,
    mem_offset: u64,
    mem_size: u64,
    section_count: usize,
) {
    segment_cmd.cmd.set(LE, LC_SEGMENT_64);
    segment_cmd.cmdsize.set(
        LE,
        (size_of::<SegmentCommand>() + size_of::<SectionEntry>() * section_count) as u32,
    );
    segment_cmd.segname[..seg_name.len()].copy_from_slice(seg_name.as_bytes());
    segment_cmd.segname[seg_name.len()..].zero();
    segment_cmd.fileoff.set(LE, file_offset);
    segment_cmd.filesize.set(LE, file_size);
    segment_cmd.vmaddr.set(LE, mem_offset);
    segment_cmd.vmsize.set(LE, mem_size);
    segment_cmd.maxprot.set(LE, prot_flags);
    segment_cmd.initprot.set(LE, prot_flags);
    segment_cmd.nsects.set(LE, section_count as u32);
    segment_cmd.flags.set(LE, macho::SegmentFlags(0));
}

fn write_sections(
    seg_name: &str,
    sections: &mut [SectionEntry],
    segment_sections: &[(
        OutputRecordLayout,
        Option<SectionName<'_>>,
        crate::macho::SectionFlags,
    )],
) -> Result {
    for (section, (size, section_name, section_flags)) in sections.iter_mut().zip(segment_sections)
    {
        let section_name = section_name
            .ok_or_else(|| error!("section name must be known"))?
            .0;

        section.segname[..seg_name.len()].copy_from_slice(seg_name.as_bytes());
        section.segname[seg_name.len()..].zero();
        section.sectname[..section_name.len()].copy_from_slice(section_name);
        section.sectname[section_name.len()..].zero();
        section.addr.set(LE, size.mem_offset);
        section.size.set(LE, size.mem_size);
        section.offset.set(LE, size.file_offset as u32);
        section.align.set(LE, u32::from(size.alignment.exponent));
        section.reloff.set(LE, 0);
        section.nreloc.set(LE, 0);
        section.flags.set(LE, *section_flags);
        section.reserved1.set(LE, 0);
        // TODO: find a better place
        let reserved2 =
            if section_flags.0 & macho::SECTION_TYPE == u32::from(macho::S_SYMBOL_STUBS.0) {
                PLT_ENTRY_SIZE as u32
            } else {
                0
            };
        section.reserved2.set(LE, reserved2);
        section.reserved3.set(LE, 0);
    }

    Ok(())
}

fn write_object<'data, A: Arch<Platform = MachO>>(
    object: &ObjectLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    symbol_writer: &mut MachOSymbolTableWriter,
) -> Result {
    verbose_timing_phase!("Write object", file_id = object.file_id.as_u32());

    let _span = debug_span!("write_file", filename = %object.input).entered();
    let _file_span = layout.args().common().trace_span_for_file(object.file_id);
    for (i, sec) in object.sections.iter().enumerate() {
        match sec {
            SectionSlot::Loaded(sec) => {
                write_object_section::<A>(object, layout, sec, object::SectionIndex(i), buffers)?;
            }
            _ => (),
        }
    }

    write_symbols(object, buffers, layout, symbol_writer)?;

    Ok(())
}

fn write_object_section<'data, A: Arch<Platform = MachO>>(
    object_layout: &ObjectLayout<'data, MachO>,
    layout: &MachOLayout<'data>,
    section: &Section,
    section_index: object::SectionIndex,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let out = write_section_raw(object_layout, layout, section, section_index, buffers)?;

    let section_address = object_layout.section_resolutions[section_index.0]
        .address()
        .context("Attempted to apply relocations to a section that we didn't load")?;

    for rel in object_layout.relocations(section_index)?.relocations {
        apply_relocation::<A>(object_layout, section_address, rel.info(LE), layout, out)?;
    }

    Ok(())
}

#[inline(always)]
fn apply_relocation<'data, A: Arch<Platform = MachO>>(
    object_layout: &ObjectLayout<'data, MachO>,
    section_address: u64,
    rel: RelocationInfo,
    layout: &MachOLayout<'data>,
    out: &mut [u8],
) -> Result {
    let offset_in_section = u64::from(rel.r_address);
    let place = section_address + offset_in_section;

    let _span = tracing::trace_span!(
        "relocation",
        address = place,
        address_hex = %HexU64::new(place)
    )
    .entered();

    let rel_info = A::relocation_from_raw(rel)?;
    let (resolution, _symbol_index, local_symbol_id) = get_resolution(rel, object_layout, layout)?;
    let flags = layout.flags_for_symbol(local_symbol_id);

    let mask = get_page_mask(rel_info.mask);
    let value = match rel_info.kind {
        RelocationKind::Absolute => resolution.value().bitand(mask.symbol_plus_addend),
        RelocationKind::AbsoluteLowPart => resolution.value().bitand(mask.symbol_plus_addend),
        RelocationKind::Relative => resolution
            .value()
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::GotRelative => resolution
            .value()
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::Got => resolution.value().bitand(mask.symbol_plus_addend),
        _ => todo!(),
    };

    tracing::trace!(
            %flags,
            ?rel_info.kind,
            %rel_info.size,
            value,
            value_hex = %HexU64::new(value),
            symbol_name = %layout.symbol_db.symbol_name_for_display(local_symbol_id),
            "relocation applied");

    rel_info.write_to_buffer(value, &mut out[offset_in_section as usize..])?;

    Ok(())
}

fn write_section_raw<'out, 'data>(
    object: &ObjectLayout<'data, MachO>,
    layout: &MachOLayout,
    sec: &Section,
    section_index: object::SectionIndex,
    buffers: &'out mut OutputSectionPartMap<&mut [u8]>,
) -> Result<&'out mut [u8]> {
    let part_id = object.section_part_id(section_index, &layout.symbol_db.section_part_ids);
    if layout
        .output_sections
        .has_data_in_file(part_id.output_section_id())
    {
        let section_buffer = buffers.get_mut(part_id);
        let allocation_size = sec.capacity(part_id, &layout.output_sections) as usize;
        if section_buffer.len() < allocation_size {
            bail!(
                "Insufficient space allocated to section `{}`. Tried to take {} bytes, but only {} remain",
                object.object.section_display_name(section_index),
                allocation_size,
                section_buffer.len()
            );
        }
        let out = section_buffer.split_off_mut(..allocation_size).unwrap();
        let object_section = object.object.section(section_index)?;

        let section_size = object.object.section_size(object_section)?;
        let (out, padding) = out.split_at_mut(section_size as usize);
        object.object.copy_section_data(object_section, out)?;
        padding.fill(0);
        Ok(out)
    } else {
        Ok(&mut [])
    }
}

fn get_resolution<'data>(
    rel: RelocationInfo,
    object_layout: &ObjectLayout<'data, MachO>,
    layout: &MachOLayout,
) -> Result<(Resolution<MachO>, SymbolIndex, SymbolId)> {
    let symbol_index = SymbolIndex(rel.r_symbolnum as usize);
    let local_symbol_id = object_layout.symbol_id_range.input_to_id(symbol_index);
    let sym = object_layout.object.symbol(symbol_index)?;
    let section_index = object_layout.object.symbol_section(sym, symbol_index)?;
    let resolution = layout
        .merged_symbol_resolution(local_symbol_id)
        .or_else(|| {
            section_index.and_then(|section_index| {
                let section_address =
                    object_layout.section_resolutions[section_index.0].address()?;
                Some(Resolution {
                    raw_value: ResolutionState::Resolved(section_address),
                    dynamic_symbol_index: None,
                    flags: ValueFlags::empty(),
                    format_specific: Default::default(),
                })
            })
        })
        .with_context(|| {
            format!(
                "Missing resolution for: {}",
                layout.symbol_debug(local_symbol_id)
            )
        })?;
    Ok((resolution, symbol_index, local_symbol_id))
}

fn write_entry_point_command<A: Arch<Platform = MachO>>(
    layout: &MachOLayout,
    command: &mut EntryPointCommand,
) -> Result {
    let SegmentSectionsInfo { segment_size, .. } =
        get_segment_sections(layout, SegmentType::TextSections)
            .ok_or_else(|| error!("TextSections segment is mandatory"))?;

    command.cmd.set(LE, LC_MAIN);
    command
        .cmdsize
        .set(LE, size_of::<EntryPointCommand>() as u32);
    command.entryoff.set(LE, segment_size.file_offset as u64);
    command.stacksize.set(LE, 0);
    Ok(())
}

fn write_dylinker_command<A: Arch<Platform = MachO>>(
    command: &mut DylinkerCommand,
    path_buffer: &mut [u8],
) {
    command.cmd.set(LE, LC_LOAD_DYLINKER);
    command.cmdsize.set(
        LE,
        ((size_of::<DylinkerCommand>() + DYLINKER_PATH.len())
            .next_multiple_of(MACHO_COMMAND_ALIGNMENT)) as u32,
    );
    command
        .name
        .offset
        .set(LE, size_of::<DylinkerCommand>() as u32);

    path_buffer[0..DYLINKER_PATH.len()].copy_from_slice(DYLINKER_PATH);
    path_buffer[DYLINKER_PATH.len()..].zero();
}

fn write_dylib_command<A: Arch<Platform = MachO>>(
    command: &mut DylibCommand,
    path_buffer: &mut [u8],
    path: &[u8],
) {
    command.cmd.set(LE, LC_LOAD_DYLIB);
    command
        .cmdsize
        .set(LE, load_dylib_command_size(path) as u32);
    command
        .dylib
        .name
        .offset
        .set(LE, size_of::<DylibCommand>() as u32);
    // TODO
    command.dylib.timestamp.set(LE, 2);
    // TODO
    command
        .dylib
        .current_version
        .set(LE, macho::Version(1356 << 16));
    command
        .dylib
        .compatibility_version
        .set(LE, macho::Version(1 << 16));

    path_buffer[0..path.len()].copy_from_slice(path);
    path_buffer[path.len()..].zero();
}

fn write_dyld_chained_fixups_command<A: Arch<Platform = MachO>>(
    layout: &MachOLayout,
    command: &mut DyldChainedFixupsCommand,
) {
    let chained_fixup_table = layout
        .section_layouts
        .get(output_section_id::CHAINED_FIXUP_TABLE);

    command.cmd.set(LE, LC_DYLD_CHAINED_FIXUPS);
    command
        .cmdsize
        .set(LE, size_of::<DyldChainedFixupsCommand>() as u32);
    command
        .dataoff
        .set(LE, chained_fixup_table.file_offset as u32);
    command
        .datasize
        .set(LE, chained_fixup_table.file_size as u32);
}

fn write_symtab_command<A: Arch<Platform = MachO>>(
    layout: &MachOLayout,
    command: &mut SymtabCommand,
) {
    let symtab = layout.section_layouts.get(output_section_id::SYMTAB_GLOBAL);
    let strtab = layout.section_layouts.get(output_section_id::STRTAB);

    command.cmd.set(LE, LC_SYMTAB);
    command.cmdsize.set(LE, size_of::<SymtabCommand>() as u32);
    command.symoff.set(LE, symtab.file_offset as u32);
    command
        .nsyms
        .set(LE, (symtab.file_size / size_of::<SymtabEntry>()) as u32);
    command.stroff.set(LE, strtab.file_offset as u32);
    command.strsize.set(LE, strtab.file_size as u32);
}

fn write_code_signature_command<A: Arch<Platform = MachO>>(
    layout: &MachOLayout,
    command: &mut CodeSignatureCommand,
) {
    let code_signature = layout
        .section_layouts
        .get(output_section_id::CODE_SIGNATURE);

    command.cmd.set(LE, LC_CODE_SIGNATURE);
    command
        .cmdsize
        .set(LE, size_of::<CodeSignatureCommand>() as u32);
    command.dataoff.set(LE, code_signature.file_offset as u32);
    command.datasize.set(LE, code_signature.file_size as u32);
}

fn write_chained_fixup_table<A: Arch<Platform = MachO>>(
    layout: &MachOLayout,
    chained_fixup_table: &mut [u8],
) -> Result {
    let symbols = &layout.format_specific.imported_symbols;

    let active_segments = PROGRAM_SEGMENT_DEFS
        .iter()
        .filter(|segment| {
            segment.count_as_segment && get_segment_sections(layout, segment.segment_type).is_some()
        })
        .collect_vec();
    // The __PAGEZERO segment needs to be added manually.
    let segment_count = active_segments.len() + 1;
    ensure!(
        segment_count <= MAX_SEGMENT_COUNT,
        "unexpected number of active segments"
    );
    let starts_in_image_len = size_of::<u32>() * (segment_count + 1);
    let starts_in_segment_len =
        size_of::<DyldChainedStartsInSegment>() + CHAINED_FIXUP_PAGE_START_SIZE as usize;
    let imports_len = size_of::<u32>() * symbols.len();

    let starts_offset = size_of::<ChainedFixupsHeader>();
    let imports_offset = starts_offset + starts_in_image_len + starts_in_segment_len;
    let symbols_offset = imports_offset + imports_len;

    let (header, rest) = ChainedFixupsHeader::mut_from_prefix(chained_fixup_table)
        .map_err(|_| error!("Invalid chained fixups header allocation"))?;
    let (starts_in_image, rest) = slice_from_bytes_mut::<U32<Endianness>>(rest, segment_count + 1)
        .map_err(|_| error!("Invalid chained fixups starts allocation"))?;

    // 1) fill up ChainedFixupsHeader
    header.fixups_version.set(0);
    header.starts_offset.set(starts_offset as u32);
    header.imports_offset.set(imports_offset as u32);
    header.symbols_offset.set(symbols_offset as u32);
    header.imports_count.set(symbols.len() as u32);
    header.imports_format.set(DYLD_CHAINED_IMPORT);
    header.symbols_format.set(0);

    let data_const_segment_index = active_segments
        .iter()
        .position(|segment_type| segment_type.segment_type == SegmentType::DataConstSections);

    // 2) fill up dyld_chained_starts_in_image, which is `seg_count` (u32) followed by
    //    `seg_info_offset` ([u32; seg_count]); only __DATA_CONST,__got segment is covered
    starts_in_image[0].set(LE, segment_count as u32);
    starts_in_image[1..].fill(U32::new(LE, 0));

    // Early exit if we don't have any GOT entry to be encoded.
    let Some(data_const_segment_index) = data_const_segment_index else {
        rest.zero();
        return Ok(());
    };

    starts_in_image[data_const_segment_index + 1].set(LE, starts_in_image_len as u32);

    let (starts_in_segment, rest) = DyldChainedStartsInSegment::mut_from_prefix(rest)
        .map_err(|_| error!("Invalid chained fixups starts in segment allocation"))?;
    let (page_starts, rest) = slice_from_bytes_mut::<U16<Endianness>>(rest, 1)
        .map_err(|_| error!("Invalid chained fixups page starts allocation"))?;
    let (imports, string_pool) = slice_from_bytes_mut::<U32<Endianness>>(rest, symbols.len())
        .map_err(|_| error!("Invalid chained fixups imports allocation"))?;

    // 3) fill up DyldChainedStartsInSegment for the __got section
    let data_const_segment = get_segment_sections(layout, SegmentType::DataConstSections)
        .ok_or_else(|| error!("__DATA_CONST segment expected"))?
        .segment_size;

    starts_in_segment.size.set(starts_in_segment_len as u32);
    starts_in_segment
        .page_size
        .set(MACHO_PAGE_ALIGNMENT.value() as u16);
    starts_in_segment
        .pointer_format
        .set(DYLD_CHAINED_PTR_64_OFFSET);
    starts_in_segment
        .segment_offset
        .set(data_const_segment.file_offset as u64);
    starts_in_segment.max_valid_pointer.set(0);
    // TODO:
    starts_in_segment.page_count.set(1);
    page_starts[0].set(LE, 0);

    // 4) fill up all imported symbols chunked by the pages
    // TODO: support more pages
    assert!(symbols.len() < MACHO_PAGE_ALIGNMENT.value() as usize / size_of::<u32>());

    let sorted_symbols = &layout.format_specific.imported_symbols;
    let mut symbol_offsets = Vec::with_capacity(sorted_symbols.len());
    let mut str_offset = 0;
    for imported_symbol in sorted_symbols {
        let symbol = &imported_symbol.symbol;
        string_pool[str_offset..str_offset + symbol.name.len()].copy_from_slice(symbol.name);
        string_pool[str_offset + symbol.name.len()] = b'\0';
        symbol_offsets.push(str_offset);
        str_offset += symbol.name.len() + 1;
    }

    // Emit `dyld_chained_import` that is built by 3 pieces:
    // lib_ordinal: 8
    // weak_import: 1
    // name_offset: 23
    for (i, imported_symbol) in sorted_symbols.iter().enumerate() {
        imports[i].set(
            Endianness::Little,
            u32::from(imported_symbol.symbol.library_index) | ((symbol_offsets[i] as u32) << 9),
        );
    }

    // Pad a couple of bytes (related to the MAX_SEGMENT_COUNT).
    string_pool[str_offset..].fill(0);

    Ok(())
}

fn write_code_signature(layout: &MachOLayout, sized_output: &mut SizedOutput) -> Result {
    verbose_timing_phase!("Write code signature");

    let code_signature_section = layout
        .section_layouts
        .get(output_section_id::CODE_SIGNATURE);
    let code_signature_identifier = code_signature_identifier(layout.args());
    let padded_identifier_size = code_signature_padded_identifier_size(layout.args()) as usize;
    let calculated_hashes: Vec<_> = sized_output.out[..code_signature_section.file_offset]
        .par_chunks(CS_BLOCK_SIZE)
        .map(Sha256::digest)
        .collect();
    let calculated_hashes = calculated_hashes.into_iter().flatten().collect_vec();

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;
    let code_signature = section_buffers.get_mut(output_section_id::CODE_SIGNATURE);

    let (super_blob, rest): (&mut CodeSignatureSuperBlob, &mut [u8]) =
        CodeSignatureSuperBlob::mut_from_prefix(code_signature)
            .map_err(|_| error!("Invalid CODE_SIGNATURE allocation"))?;
    let (blob_indices, rest) = <[CodeSignatureBlobIndex]>::mut_from_prefix_with_elems(rest, 1)
        .map_err(|_| error!("Invalid CODE_SIGNATURE allocation"))?;
    let blob_index = &mut blob_indices[0];
    let (code_directories, rest) =
        <[CodeSignatureCodeDirectory]>::mut_from_prefix_with_elems(rest, 1)
            .map_err(|_| error!("Invalid CODE_SIGNATURE allocation"))?;
    let code_dir = &mut code_directories[0];
    let (identifier, hashes) = rest.split_at_mut(padded_identifier_size);

    super_blob.magic.set(CSMAGIC_EMBEDDED_SIGNATURE);
    super_blob
        .length
        .set(code_signature_section.file_size as u32);
    super_blob.count.set(1);

    blob_index.type_.set(CSSLOT_CODEDIRECTORY);
    blob_index.offset.set(CS_BLOB_HEADERS_SIZE as u32);
    blob_index.padding.set(0);

    code_dir.magic.set(CSMAGIC_CODEDIRECTORY);
    code_dir
        .length
        .set((code_signature_section.file_size as u64 - CS_BLOB_HEADERS_SIZE) as u32);
    code_dir.version.set(CS_SUPPORTSEXECSEG);
    code_dir.flags.set(CS_ADHOC | CS_LINKER_SIGNED);
    code_dir
        .hash_offset
        .set(size_of::<CodeSignatureCodeDirectory>() as u32 + padded_identifier_size as u32);
    code_dir
        .ident_offset
        .set(size_of::<CodeSignatureCodeDirectory>() as u32);
    code_dir.n_special_slots.set(0);
    code_dir
        .n_code_slots
        .set(code_signature_section.file_offset.div_ceil(CS_BLOCK_SIZE) as u32);
    code_dir
        .code_limit
        .set(code_signature_section.file_offset as u32);
    code_dir.hash_size = CS_HASH_SIZE;
    code_dir.hash_type = CS_HASHTYPE_SHA256;
    code_dir.platform = 0;
    code_dir.page_size = CS_BLOCK_SIZE_EXP;
    code_dir.spare2.set(0);
    code_dir.scatter_offset.set(0);
    code_dir.team_offset.set(0);
    code_dir.spare3.set(0);
    code_dir.code_limit64.set(0);

    let text_segment_size = get_segment_sections(layout, SegmentType::Text)
        .ok_or_else(|| error!("Text segment is mandatory"))?
        .segment_size;
    code_dir
        .exec_seg_base
        .set(text_segment_size.file_offset as u64);
    code_dir
        .exec_seg_limit
        .set(text_segment_size.file_size as u64);
    // TODO: change once shared libraries are supported
    code_dir.exec_seg_flags.set(CS_EXECSEG_MAIN_BINARY);

    identifier[..code_signature_identifier.len()].copy_from_slice(code_signature_identifier);
    identifier[code_signature_identifier.len()..].fill(0);
    hashes.copy_from_slice(&calculated_hashes);

    #[cfg(target_os = "macos")]
    if let crate::file_writer::OutputBuffer::Mmap(output) = &mut sized_output.out {
        // Match lld's workaround for the macOS kernel caching signature-verification
        // data before the final code signature has been written:
        //
        // https://openradar.appspot.com/FB8914231
        unsafe {
            libc::msync(
                output.as_mut_ptr().cast(),
                code_signature_section.file_offset + code_signature_section.file_size,
                libc::MS_INVALIDATE,
            );
        }
    }

    Ok(())
}

struct MachOSymbolTableWriter {
    next_strtab_offset: u32,
}

impl MachOSymbolTableWriter {
    fn write_str(&mut self, name: &[u8], buffers: &mut OutputSectionPartMap<&mut [u8]>) -> u32 {
        let len_with_terminator = name.len() + 1;
        let offset = self.next_strtab_offset;
        let out = buffers
            .get_mut(part_id::STRTAB)
            .split_off_mut(..len_with_terminator)
            .unwrap();
        out[..name.len()].copy_from_slice(name);
        out[name.len()] = 0;
        self.next_strtab_offset += len_with_terminator as u32;
        offset
    }

    #[inline(always)]
    fn define_symbol(
        &mut self,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
        name: &[u8],
        section: u8,
        symbol_type: object::macho::SymbolFlags,
        desc: object::macho::SymbolDesc,
        value: u64,
    ) -> Result {
        let entry = self.write_entry(name, buffers)?;
        entry.n_sect = section;
        entry.n_type = symbol_type;
        entry.n_value.set(LE, value);
        entry.n_desc.set(LE, desc);

        Ok(())
    }

    fn write_entry<'out>(
        &mut self,
        name: &[u8],
        buffers: &'out mut OutputSectionPartMap<&mut [u8]>,
    ) -> Result<&'out mut SymtabEntry> {
        let string_offset = self.write_str(name, buffers);
        let entry_bytes = buffers
            .get_mut(part_id::SYMTAB_GLOBAL)
            .split_off_mut(..size_of::<SymtabEntry>())
            .unwrap();
        let entry: &mut SymtabEntry = from_bytes_mut(entry_bytes)
            .map_err(|_| error!("Invalid SYMTAB_GLOBAL entry allocation"))?
            .0;
        entry.n_strx.set(LE, string_offset);
        Ok(entry)
    }
}

fn write_symbols<'data>(
    object: &ObjectLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    symbol_writer: &mut MachOSymbolTableWriter,
) -> Result {
    for ((sym_index, sym), flags) in object
        .object
        .enumerate_symbols()
        .zip(layout.per_symbol_flags.raw_range(object.symbol_id_range))
    {
        let symbol_id = object.symbol_id_range.input_to_id(sym_index);
        let Some(info) = SymbolCopyInfo::new(
            object.object,
            sym_index,
            sym,
            symbol_id,
            &layout.symbol_db,
            flags.get(),
            &object.sections,
        ) else {
            continue;
        };

        let mut value = 0;
        let (section, symbol_type, desc) =
            if let Some(section_index) = object.object.symbol_section(sym, sym_index)? {
                let section_id = match &object.sections[section_index.0] {
                    SectionSlot::Loaded(_) => object
                        .section_part_id(section_index, &layout.symbol_db.section_part_ids)
                        .output_section_id(),
                    _ => bail!(
                        "Tried to copy a symbol in a section we didn't load. {}",
                        layout.symbol_debug(symbol_id)
                    ),
                };
                let primary_id = layout.output_sections.primary_output_section(section_id);
                let n_type = sym.n_type.with_type(N_SECT);
                let n_sect = macho_section_index(layout, primary_id).with_context(|| {
                    format!(
                        "No Mach-O section index for {} while writing {}",
                        primary_id,
                        layout.symbol_debug(symbol_id)
                    )
                })?;
                let n_desc = sym.n_desc.get(LE);
                (n_sect, n_type, n_desc)
            } else if sym.is_absolute() {
                let n_desc = sym.n_desc.get(LE);
                (0, sym.n_type.with_type(N_ABS), n_desc)
            } else {
                bail!("Attempted to output a Mach-O symtab entry with an unexpected section type")
            };

        if let Some(res) = layout.local_symbol_resolution(symbol_id) {
            value = res.value_for_symbol_table();
        }

        symbol_writer.define_symbol(buffers, info.name, section, symbol_type, desc, value)?;
    }

    Ok(())
}

// TODO: This is inefficient; simplify it once load commands use a table allocator instead of
// being modeled as a section.
fn macho_section_index(
    layout: &MachOLayout<'_>,
    section_id: output_section_id::OutputSectionId,
) -> Result<u8> {
    // The section index is one-based.
    let mut section_idx = 1u8;
    let mut in_section_segment = false;
    for event in &layout.output_order {
        match event {
            output_section_id::OrderEvent::SegmentStart(segment_id) => {
                let segment_type = layout.program_segments.segment_def(segment_id).segment_type;
                // TODO: Right now, the various load commands are mapped as "sections", so we can't
                // just take the mapped index of the output "section".
                in_section_segment = matches!(
                    segment_type,
                    SegmentType::TextSections
                        | SegmentType::DataSections
                        | SegmentType::DataConstSections
                );
            }
            output_section_id::OrderEvent::SegmentEnd(_) => {
                in_section_segment = false;
            }
            output_section_id::OrderEvent::Section(current) if in_section_segment => {
                if current == section_id {
                    return Ok(section_idx);
                }
                section_idx = section_idx
                    .checked_add(1)
                    .ok_or(error!("Section index out of range (u8)"))?;
            }
            _ => {}
        }
    }

    bail!("cannot find the output section")
}
