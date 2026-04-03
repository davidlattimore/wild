// TODO
#![allow(unused_variables)]
#![allow(unused)]

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
use crate::layout::OutputRecordLayout;
use crate::layout::PreludeLayout;
use crate::macho::FileHeader;
use crate::macho::MachO;
use crate::macho::SectionEntry;
use crate::macho::SegmentCommand;
use crate::macho::SegmentType;
use crate::output_section_id;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::SectionName;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::output_trace::TraceOutput;
use crate::part_id;
use crate::platform::Arch;
use crate::timing_phase;
use crate::verbose_timing_phase;
use object::BigEndian;
use object::Endianness;
use object::U32;
use object::from_bytes_mut;
use object::macho::CPU_TYPE_ARM64;
use object::macho::LC_SEGMENT_64;
use object::macho::MH_CIGAM_64;
use object::macho::MH_EXECUTE;
use object::macho::SEG_DATA;
use object::macho::SEG_PAGEZERO;
use object::macho::SEG_TEXT;
use object::slice_from_bytes_mut;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
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
    trace: &TraceOutput,
) -> Result {
    match file {
        FileLayout::Object(s) => {
            // TODO
            // write_object::<A>(s, buffers, table_writer, layout, trace, sym_index_map)?;
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
    populate_file_header::<A>(layout, &prelude.header_info, header);

    let pagezero_command: &mut SegmentCommand =
        from_bytes_mut(buffers.get_mut(part_id::PAGEZERO_SEGMENT))
            .map_err(|_| error!("Invalid PAGEZERO segment allocation"))?
            .0;
    write_pagezero_command::<A>(pagezero_command);

    write_segment_commands::<A>(layout, buffers)?;

    Ok(())
}

fn get_segment_sections<'data>(
    layout: &MachOLayout<'data>,
    segment_type: SegmentType,
) -> Vec<(OutputRecordLayout, Option<SectionName<'data>>)> {
    let mut in_matching_segment = false;
    let mut sections = Vec::new();

    for event in &layout.output_order {
        match event {
            OrderEvent::SegmentStart(segment_id)
                if layout.program_segments.segment_def(segment_id).segment_type == segment_type =>
            {
                in_matching_segment = true;
            }
            OrderEvent::SegmentEnd(segment_id)
                if layout.program_segments.segment_def(segment_id).segment_type == segment_type =>
            {
                if in_matching_segment {
                    break;
                }
            }
            OrderEvent::Section(section_id) if in_matching_segment => {
                let sizes = *layout.section_layouts.get(section_id);
                let merge_target = layout.output_sections.primary_output_section(section_id);

                if sizes.file_size == 0
                    && sizes.mem_size == 0
                    && layout.output_sections.output_section_indexes[merge_target.as_usize()]
                        .is_none()
                {
                    continue;
                }
                sections.push((sizes, layout.output_sections.name(section_id)));
            }
            _ => {}
        }
    }

    sections
}

fn populate_file_header<A: Arch<Platform = MachO>>(
    layout: &MachOLayout,
    _header_info: &HeaderInfo,
    header: &mut FileHeader,
) {
    // TODO: can we do better?
    let load_commands_size = layout
        .segment_layouts
        .segments
        .iter()
        .find(|seg| {
            layout.program_segments.segment_def(seg.id).segment_type
                == crate::macho::SegmentType::LoadCommand
        })
        .map_or(0, |seg| seg.sizes.file_size);
    let commands = layout
        .output_order
        .into_iter()
        .skip_while(|event| {
            if let OrderEvent::SegmentStart(segment_id) = event {
                layout
                    .program_segments
                    .segment_def(*segment_id)
                    .segment_type
                    != SegmentType::LoadCommand
            } else {
                true
            }
        })
        .skip(1)
        .take_while(|event| !matches!(event, OrderEvent::SegmentEnd(..)))
        .count();

    header.magic = U32::new(BigEndian, MH_CIGAM_64);
    header.cputype = U32::new(LE, CPU_TYPE_ARM64);
    header.cpusubtype = U32::new(LE, 0);
    // TODO
    header.filetype = U32::new(LE, MH_EXECUTE);
    header.ncmds = U32::new(LE, commands as u32);
    header.sizeofcmds = U32::new(LE, load_commands_size as u32);
    header.flags = U32::new(LE, 0);
    header.reserved = U32::new(LE, 0);
}

fn write_pagezero_command<A: Arch<Platform = MachO>>(command: &mut SegmentCommand) {
    command.cmd.set(LE, LC_SEGMENT_64);
    command.cmdsize.set(LE, size_of::<SegmentCommand>() as u32);
    command.segname[..SEG_PAGEZERO.len()].copy_from_slice(SEG_PAGEZERO.as_bytes());
    command.vmaddr.set(LE, 0);
    // The entire 32-bit address space maps to the zero page.
    command.vmsize.set(LE, 1 << 32);
    command.fileoff.set(LE, 0);
    command.filesize.set(LE, 0);
    command.maxprot.set(LE, 0);
    command.initprot.set(LE, 0);
    command.nsects.set(LE, 0);
    command.flags.set(LE, 0);
}

fn split_segment_command_buffer(
    bytes: &mut [u8],
    section_count: usize,
) -> Result<(&mut SegmentCommand, &mut [SectionEntry])> {
    let (command, rest) =
        from_bytes_mut(bytes).map_err(|_| error!("Invalid segment command allocation"))?;
    let (sections, rest) = slice_from_bytes_mut(rest, section_count)
        .map_err(|_| error!("Invalid segment section allocation"))?;
    if !rest.is_empty() {
        return Err(error!("Trailing bytes in segment command allocation"));
    }
    Ok((command, sections))
}

fn write_segment_commands<A: Arch<Platform = MachO>>(
    layout: &MachOLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    for (part_id, seg_name, segment_type) in [
        (part_id::TEXT_SEGMENT, SEG_TEXT, SegmentType::Text),
        (part_id::DATA_SEGMENT, SEG_DATA, SegmentType::Data),
    ] {
        let segment_sections = get_segment_sections(layout, segment_type);
        let (segment_cmd, sections) =
            split_segment_command_buffer(buffers.get_mut(part_id), segment_sections.len())?;

        debug_assert_eq!(sections.len(), segment_sections.len());

        // TODO: a better approach?
        let segment_sizes = layout
            .segment_layouts
            .segments
            .iter()
            .find(|s| layout.program_segments.segment_def(s.id).segment_type == segment_type)
            .ok_or_else(|| error!("Missing layout for segment {segment_type:?}"))?
            .sizes;

        segment_cmd.cmd.set(LE, LC_SEGMENT_64);
        segment_cmd.cmdsize.set(
            LE,
            (size_of::<SegmentCommand>() + size_of::<SectionEntry>() * segment_sections.len())
                as u32,
        );
        segment_cmd.segname[..seg_name.len()].copy_from_slice(seg_name.as_bytes());
        segment_cmd.segname[seg_name.len()..].zero();
        // TODO: segment OutputRecordLayout
        segment_cmd.vmaddr.set(LE, segment_sizes.mem_offset);
        segment_cmd.vmsize.set(LE, segment_sizes.mem_size);
        // TODO: should be likely offset relative to the place after the commands
        segment_cmd
            .fileoff
            .set(LE, segment_sizes.file_offset as u64);
        segment_cmd.filesize.set(LE, segment_sizes.file_size as u64);
        segment_cmd.maxprot.set(LE, 0);
        segment_cmd.initprot.set(LE, 0);
        segment_cmd.nsects.set(LE, segment_sections.len() as u32);
        segment_cmd.flags.set(LE, 0);

        for (section, (size, section_name)) in sections.iter_mut().zip(segment_sections) {
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
            section.flags.set(LE, 0);
            section.reserved1.set(LE, 0);
            section.reserved2.set(LE, 0);
            section.reserved3.set(LE, 0);
        }
    }
    Ok(())
}
