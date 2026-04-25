use crate::bail;
use crate::ensure;
use crate::error;
use crate::error::Context;
use crate::error::Result;
use crate::file_writer::SizedOutput;
use crate::file_writer::split_buffers_by_alignment;
use crate::file_writer::split_output_by_group;
use crate::file_writer::split_output_into_sections;
use crate::layout::FileLayout;
use crate::layout::HeaderInfo;
use crate::layout::Layout;
use crate::layout::ObjectLayout;
use crate::layout::OutputRecordLayout;
use crate::layout::PreludeLayout;
use crate::layout::Resolution;
use crate::layout::Section;
use crate::macho::ChainedFixupsHeader;
use crate::macho::DEFAULT_SEGMENT_COUNT;
use crate::macho::DYLINKER_PATH;
use crate::macho::DyldChainedFixupsCommand;
use crate::macho::DyldChainedFixupsImporstFormat;
use crate::macho::DylinkerCommand;
use crate::macho::EntryPointCommand;
use crate::macho::FileHeader;
use crate::macho::MACHO_COMMAND_ALIGNMENT;
use crate::macho::MACHO_START_MEM_ADDRESS;
use crate::macho::MachO;
use crate::macho::SectionEntry;
use crate::macho::SegmentCommand;
use crate::macho::SegmentSectionsInfo;
use crate::macho::SegmentType;
use crate::macho::get_segment_sections;
use crate::output_section_id;
use crate::output_section_id::SectionName;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::output_trace::HexU64;
use crate::output_trace::TraceOutput;
use crate::part_id;
use crate::platform::Arch;
use crate::platform::Args;
use crate::platform::ObjectFile;
use crate::platform::RelocationList;
use crate::resolution::SectionSlot;
use crate::symbol_db::SymbolId;
use crate::timing_phase;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use gimli::LittleEndian;
use linker_utils::elf::RelocationKind;
use object::BigEndian;
use object::Endianness;
use object::SymbolIndex;
use object::U32;
use object::from_bytes_mut;
use object::macho;
use object::macho::CPU_TYPE_ARM64;
use object::macho::LC_DYLD_CHAINED_FIXUPS;
use object::macho::LC_LOAD_DYLINKER;
use object::macho::LC_MAIN;
use object::macho::LC_SEGMENT_64;
use object::macho::MH_CIGAM_64;
use object::macho::MH_EXECUTE;
use object::macho::Relocation;
use object::macho::RelocationInfo;
use object::macho::SEG_DATA;
use object::macho::SEG_LINKEDIT;
use object::macho::SEG_PAGEZERO;
use object::macho::SEG_TEXT;
use object::slice_from_bytes_mut;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use tracing::debug_span;
use zerocopy::FromZeros;

const LE: Endianness = Endianness::Little;
type MachOLayout<'data> = Layout<'data, MachO>;

pub(crate) fn write<'data, A: Arch<Platform = MachO>>(
    sized_output: &mut SizedOutput,
    layout: &MachOLayout<'data>,
) -> Result {
    timing_phase!("Write data to file");
    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out);

    let mut writable_buckets = split_buffers_by_alignment(&mut section_buffers, layout);
    let groups_and_buffers = split_output_by_group(layout, &mut writable_buckets);
    groups_and_buffers
        .into_par_iter()
        .try_for_each(|(group, mut buffers)| -> Result {
            verbose_timing_phase!("Write group");

            for file in &group.files {
                write_file::<A>(file, &mut buffers, layout, &sized_output.trace)
                    .with_context(|| format!("Failed copying from {file} to output file"))?;
            }
            Ok(())
        })?;

    Ok(())
}

fn write_file<'data, A: Arch<Platform = MachO>>(
    file: &FileLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    _trace: &TraceOutput,
) -> Result {
    match file {
        FileLayout::Object(s) => {
            write_object::<A>(s, buffers, layout)?;
        }
        FileLayout::Prelude(s) => write_prelude::<A>(s, buffers, layout)?,
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

    let header: &mut FileHeader = from_bytes_mut(buffers.get_mut(part_id::FILE_HEADER))
        .map_err(|_| error!("Invalid file header allocation"))?
        .0;
    populate_file_header::<A>(layout, &prelude.header_info, header)?;

    write_segment_commands::<A>(layout, buffers)?;

    let entry_point_command: &mut EntryPointCommand =
        from_bytes_mut(buffers.get_mut(part_id::ENTRY_POINT))
            .map_err(|_| error!("Invalid ENTRY_POINT command allocation"))?
            .0;
    write_entry_point_command::<A>(layout, entry_point_command)?;

    let (dylinker_command, dylinker_path_buffer): (&mut DylinkerCommand, &mut [u8]) =
        from_bytes_mut(buffers.get_mut(part_id::INTERP))
            .map_err(|_| error!("Invalid INTERP command allocation"))?;
    write_dylinker_command::<A>(dylinker_command, dylinker_path_buffer);

    let chained_fixups_command: &mut DyldChainedFixupsCommand =
        from_bytes_mut(buffers.get_mut(part_id::DYLD_CHAINED_FIXUPS))
            .map_err(|_| error!("Invalid DYLD_CHAINED_FIXUPS command allocation"))?
            .0;
    write_dyld_chained_fixups_command::<A>(layout, chained_fixups_command);

    let chained_fixup_table = buffers.get_mut(part_id::CHAINED_FIXUP_TABLE);
    chained_fixup_table.fill(0);
    let starts_len = size_of::<u32>() * (DEFAULT_SEGMENT_COUNT + 1);
    let min_len = size_of::<ChainedFixupsHeader>() + starts_len;
    if chained_fixup_table.len() < min_len {
        bail!(
            "CHAINED_FIXUP_TABLE allocation too small. Need at least {} bytes, got {}",
            min_len,
            chained_fixup_table.len()
        );
    }
    let (chained_fixups_header, rest): (&mut ChainedFixupsHeader, &mut [u8]) =
        from_bytes_mut(chained_fixup_table)
            .map_err(|_| error!("Invalid chained fixups header allocation"))?;
    let (starts_in_image, _) =
        slice_from_bytes_mut::<U32<Endianness>>(rest, DEFAULT_SEGMENT_COUNT + 1)
            .map_err(|_| error!("Invalid chained fixups starts allocation"))?;
    write_chained_fixup_table::<A>(chained_fixups_header, starts_in_image)?;

    Ok(())
}

fn populate_file_header<A: Arch<Platform = MachO>>(
    layout: &MachOLayout,
    _header_info: &HeaderInfo,
    header: &mut FileHeader,
) -> Result {
    let load_commands_info = get_segment_sections(layout, SegmentType::LoadCommands)
        .ok_or_else(|| error!("LoadCommands segment is mandatory"))?;

    header.magic = U32::new(BigEndian, MH_CIGAM_64);
    header.cputype = U32::new(LE, CPU_TYPE_ARM64);
    header.cpusubtype = U32::new(LE, 0);
    header.filetype = U32::new(LE, MH_EXECUTE);
    // TODO: a cleaner way how to filter out sections being part of the final output?
    header.ncmds = U32::new(
        LE,
        load_commands_info
            .segment_sections
            .iter()
            .filter(|s| s.0.mem_size > 0)
            .count() as u32,
    );
    header.sizeofcmds = U32::new(LE, load_commands_info.segment_size.file_size as u32);
    header.flags = U32::new(
        LE,
        macho::MH_PIE | macho::MH_DYLDLINK | macho::MH_NOUNDEFS | macho::MH_TWOLEVEL,
    );
    header.reserved = U32::new(LE, 0);
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
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let pagezero_segment =
        split_segment_command_buffer(buffers.get_mut(part_id::PAGEZERO_SEGMENT), 0)?.0;
    write_segment(
        layout,
        part_id::PAGEZERO_SEGMENT,
        SEG_PAGEZERO,
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
    let (text_segment, text_sections) = split_segment_command_buffer(
        buffers.get_mut(part_id::TEXT_SEGMENT),
        text_segment_sections.len(),
    )?;
    write_segment(
        layout,
        part_id::TEXT_SEGMENT,
        SEG_TEXT,
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
        let (data_segment, data_sections) = split_segment_command_buffer(
            buffers.get_mut(part_id::DATA_SEGMENT),
            data_segment_sections.len(),
        )?;
        write_segment(
            layout,
            part_id::DATA_SEGMENT,
            SEG_DATA,
            data_segment,
            data_segment_size.file_offset as u64,
            data_segment_size.file_size as u64,
            data_segment_size.mem_offset,
            data_segment_size.mem_size,
            data_segment_sections.len(),
        );
        write_sections(SEG_DATA, data_sections, &data_segment_sections)?;
    }

    let linkedit_segment_size = get_segment_sections(layout, SegmentType::LinkeditSections)
        .ok_or_else(|| error!("LinkeditSections segment is mandatory"))?
        .segment_size;
    let linkedit_segment =
        split_segment_command_buffer(buffers.get_mut(part_id::LINK_EDIT_SEGMENT), 0)?.0;
    write_segment(
        layout,
        part_id::LINK_EDIT_SEGMENT,
        SEG_LINKEDIT,
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
    layout: &MachOLayout,
    part_id: part_id::PartId,
    seg_name: &str,
    segment_cmd: &mut SegmentCommand,
    file_offset: u64,
    file_size: u64,
    mem_offset: u64,
    mem_size: u64,
    section_count: usize,
) {
    let prot_flags = layout
        .output_sections
        .section_flags(part_id.output_section_id())
        .raw();

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
    segment_cmd.flags.set(LE, 0);
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
        // TODO
        section.align.set(LE, 0);
        section.reloff.set(LE, 0);
        section.nreloc.set(LE, 0);
        section.flags.set(LE, section_flags.raw());
        section.reserved1.set(LE, 0);
        section.reserved2.set(LE, 0);
        section.reserved3.set(LE, 0);
    }

    Ok(())
}

fn write_object<'data, A: Arch<Platform = MachO>>(
    object: &ObjectLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
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

    Ok(())
}

fn write_object_section<'data, A: Arch<Platform = MachO>>(
    object_layout: &ObjectLayout<'data, MachO>,
    layout: &MachOLayout<'data>,
    section: &Section,
    section_index: object::SectionIndex,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let mut out = write_section_raw(object_layout, layout, section, section_index, buffers)?;

    let section_address = object_layout.section_resolutions[section_index.0]
        .address()
        .context("Attempted to apply relocations to a section that we didn't load")?;
    dbg!(section_address);
    let object_section = object_layout.object.section(section_index)?;

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
    let mut addend = rel.r_address;
    let (resolution, symbol_index, local_symbol_id) = get_resolution(rel, object_layout, layout)?;

    tracing::trace!(
            ?rel_info.kind,
            %rel_info.size,
            symbol_name = %layout.symbol_db.symbol_name_for_display(local_symbol_id),
            "relocation applied");

    let value = match rel_info.kind {
        RelocationKind::Relative => {
            dbg!(resolution);
            todo!()
        }
        _ => todo!(),
    };

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
                    raw_value: section_address,
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

fn write_chained_fixup_table<A: Arch<Platform = MachO>>(
    header: &mut ChainedFixupsHeader,
    starts_in_image: &mut [U32<Endianness>],
) -> Result {
    let starts_len = size_of::<u32>() * (DEFAULT_SEGMENT_COUNT + 1);
    if starts_in_image.len() != DEFAULT_SEGMENT_COUNT + 1 {
        bail!(
            "Invalid chained fixups starts allocation. Expected {} entries, got {}",
            DEFAULT_SEGMENT_COUNT + 1,
            starts_in_image.len()
        );
    }

    header.fixups_version.set(LE, 0);
    header
        .starts_offset
        .set(LE, size_of::<ChainedFixupsHeader>() as u32);
    header
        .imports_offset
        .set(LE, (size_of::<ChainedFixupsHeader>() + starts_len) as u32);
    header
        .symbols_offset
        .set(LE, (size_of::<ChainedFixupsHeader>() + starts_len) as u32);
    header.imports_count.set(LE, 0);
    header.imports_format.set(
        LE,
        DyldChainedFixupsImporstFormat::DYLD_CHAINED_IMPORT as u32,
    );
    header.symbols_format.set(LE, 0);

    starts_in_image[0].set(LE, DEFAULT_SEGMENT_COUNT as u32);
    starts_in_image[1..].fill(U32::new(LE, 0));

    Ok(())
}
