//! Used after `finalise_layout` to verify that all section output offsets were bumped by an amount
//! equal to the size requested for that section.

use crate::alignment::Alignment;
use crate::error::Result;
use crate::layout::FileLayout;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_part_map::OutputSectionPartMap;
use anyhow::bail;

pub(crate) struct OffsetVerifier {
    expected: OutputSectionPartMap<u64>,
    sizes: OutputSectionPartMap<u64>,
}

impl OffsetVerifier {
    pub(crate) fn new(
        starting_offsets: &OutputSectionPartMap<u64>,
        sizes: &OutputSectionPartMap<u64>,
    ) -> Self {
        let mut expected = starting_offsets.clone();
        expected.merge(sizes);
        clear_ignored(&mut expected);
        Self {
            expected,
            sizes: sizes.clone(),
        }
    }

    pub(crate) fn verify(
        &self,
        memory_offsets: &OutputSectionPartMap<u64>,
        output_sections: &OutputSections,
        files: &[FileLayout],
    ) -> Result {
        if memory_offsets == &self.expected {
            return Ok(());
        }
        let expected = offsets_by_key(&self.expected, output_sections);
        let actual = offsets_by_key(memory_offsets, output_sections);
        let sizes = offsets_by_key(&self.sizes, output_sections);
        let mut problems = Vec::new();
        for (((section_id, alignment, exp), (_, _, act)), (_, _, size)) in
            expected.iter().zip(actual.iter()).zip(sizes)
        {
            if exp != act {
                let actual_bump = *act as i64 - (*exp as i64 - size as i64);
                problems.push(format!(
                    "Section `{}` alignment: {alignment} expected: 0x{exp:x} actual: 0x{act:x} \
                     bumped by: 0x{actual_bump:x} requested size: 0x{size:x}\n",
                    String::from_utf8_lossy(output_sections.name(*section_id))
                ));
            }
        }
        let files = files.iter().map(|f| f.to_string()).collect::<Vec<_>>();
        bail!(
            "Unexpected memory offsets:\n{}\nfor files:\n{}",
            problems.join(""),
            files.join("\n")
        );
    }
}

/// Clear offsets for sections where we never take the address of a section offset during
/// `finalise_layout`.
pub(crate) fn clear_ignored(expected: &mut OutputSectionPartMap<u64>) {
    /// A distinctive value that should definitely make things fail if we actually do make use of
    /// one of these offsets during `finalise_layout`.
    const IGNORED_OFFSET: u64 = 0x98760000;
    expected.rela_plt = IGNORED_OFFSET;
    expected.eh_frame_hdr = IGNORED_OFFSET;
    expected.rela_dyn_general = IGNORED_OFFSET;
    expected.rela_dyn_relative = IGNORED_OFFSET;
    expected.rela_dyn_relative = IGNORED_OFFSET;
    expected.gnu_version = IGNORED_OFFSET;
    expected.gnu_hash = IGNORED_OFFSET;
    expected.dynamic = IGNORED_OFFSET;
    expected.interp = IGNORED_OFFSET;
    expected.file_header = IGNORED_OFFSET;
    expected.program_headers = IGNORED_OFFSET;
    expected.section_headers = IGNORED_OFFSET;
    expected.shstrtab = IGNORED_OFFSET;
}

fn offsets_by_key(
    memory_offsets: &OutputSectionPartMap<u64>,
    output_sections: &OutputSections,
) -> Vec<(OutputSectionId, Alignment, u64)> {
    let mut offsets_by_key = Vec::new();
    memory_offsets.output_order_map(output_sections, |section_id, alignment, offset| {
        offsets_by_key.push((section_id, alignment, *offset))
    });
    offsets_by_key
}
