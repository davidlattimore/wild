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
use crate::layout::PreludeLayout;
use crate::macho::FileHeader;
use crate::macho::MachO;
use crate::macho::SegmentCommand;
use crate::macho::SegmentType;
use crate::output_section_id::OrderEvent;
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
use object::macho::SEG_PAGEZERO;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

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

    Ok(())
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
    dbg!(commands);
    dbg!(load_commands_size);

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
