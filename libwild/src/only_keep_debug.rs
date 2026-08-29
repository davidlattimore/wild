// Post-layout pass that implements `--only-keep-debug`.
//
// Zeroes `file_size` for every `SHF_ALLOC` non-NOTE section, then recalculates
// file offsets and segment sizes so the output ELF is self-consistent.

use crate::compression::recalculate_file_offsets;
use crate::elf;
use crate::elf::ElfClass;
use crate::error::Result;
use crate::layout::Layout;
use crate::platform::Arch;
use crate::platform::Args as _;
use crate::platform::SectionFlags as _;
use crate::timing_phase;
use linker_utils::elf::sht;

pub(crate) fn maybe_only_keep_debug_elf<C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    layout: &mut Layout<elf::Elf<C>>,
) -> Result {
    if !layout.args().only_keep_debug() {
        return Ok(());
    }
    timing_phase!("Only-keep-debug: zero alloc sections");
    zero_alloc_section_sizes(layout);
    recalculate_file_offsets(layout)?;
    Ok(())
}

fn zero_alloc_section_sizes<C: ElfClass>(layout: &mut Layout<elf::Elf<C>>) {
    // Skip internal linker-generated header sections (file header, program headers,
    // section headers). These are SHF_ALLOC but must be written to the output file.
    let header_ids = [
        crate::output_section_id::FILE_HEADER,
        elf::output_section_id::PROGRAM_HEADERS,
        elf::output_section_id::SECTION_HEADERS,
    ];
    for (section_id, _) in layout.output_sections.ids_with_info() {
        if header_ids.contains(&section_id) {
            continue;
        }
        let flags = layout.output_sections.section_flags(section_id);
        let section_type = layout
            .output_sections
            .output_info(section_id)
            .section_attributes
            .ty;

        if !flags.is_alloc() || section_type == sht::NOTE {
            continue;
        }

        for part_id in section_id.parts::<elf::Elf<C>>() {
            layout.section_part_layouts.get_mut(part_id).file_size = 0;
        }

        for group in &mut layout.group_layouts {
            for part_id in section_id.parts::<elf::Elf<C>>() {
                *group.file_sizes.get_mut(part_id) = 0;
            }
        }

        layout.section_layouts.get_mut(section_id).file_size = 0;
        layout.merged_section_layouts.get_mut(section_id).file_size = 0;
    }
}
