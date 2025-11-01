//! Used after `finalise_layout` to verify that all section output offsets were bumped by an amount
//! equal to the size requested for that section.

use crate::bail;
use crate::error::Result;
use crate::layout::FileLayout;
use crate::output_section_id::OutputOrder;
use crate::output_section_id::OutputSections;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::part_id;
use crate::part_id::PartId;
use itertools::Itertools;

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
        output_order: &OutputOrder,
        files: &[FileLayout],
    ) -> Result {
        if memory_offsets == &self.expected && self.alignments_ok() {
            return Ok(());
        }
        let expected = offsets_by_key(&self.expected, output_order);
        let actual = offsets_by_key(memory_offsets, output_order);
        let sizes = offsets_by_key(&self.sizes, output_order);
        let mut problems = Vec::new();

        for (((part_id, exp), (_, act)), (_, size)) in expected.iter().zip(actual.iter()).zip(sizes)
        {
            let alignment = part_id.alignment();
            if exp != act {
                let actual_bump = *act as i64 - (*exp as i64 - size as i64);
                problems.push(format!(
                    "Part #{part_id} (section {} alignment: {alignment}) expected: 0x{exp:x} \
                     actual: 0x{act:x} bumped by: 0x{actual_bump:x} requested size: 0x{size:x}\n",
                    output_sections.display_name(part_id.output_section_id())
                ));
            }
            if !size.is_multiple_of(part_id.alignment().value())
                && !should_ignore_alignment(*part_id)
            {
                problems.push(format!(
                    "Part #{part_id} (section {} alignment: {alignment}) \
                     has non aligned size: 0x{size:x}\n",
                    output_sections.display_name(part_id.output_section_id())
                ));
            }
        }

        let files = files.iter().map(|f| f.to_string()).collect_vec();

        bail!(
            "Unexpected memory offsets:\n{}\nfor files:\n{}",
            problems.join(""),
            files.join("\n")
        );
    }

    fn alignments_ok(&self) -> bool {
        self.sizes.parts.iter().enumerate().all(|(i, size)| {
            let part_id = PartId::from_usize(i);
            size.is_multiple_of(part_id.alignment().value()) || should_ignore_alignment(part_id)
        })
    }
}

fn should_ignore_alignment(part_id: PartId) -> bool {
    part_id.should_pack()
        || [part_id::GNU_HASH, part_id::EH_FRAME, part_id::GNU_VERSION_D].contains(&part_id)
}

/// Clear offsets for sections where we never take the address of a section offset during
/// `finalise_layout`.
pub(crate) fn clear_ignored(expected: &mut OutputSectionPartMap<u64>) {
    /// A distinctive value that should definitely make things fail if we actually do make use of
    /// one of these offsets during `finalise_layout`.
    const IGNORED_OFFSET: u64 = 0x98760000;

    const IGNORED: &[PartId] = &[
        part_id::RELA_PLT,
        part_id::EH_FRAME_HDR,
        part_id::RELA_DYN_GENERAL,
        part_id::RELA_DYN_RELATIVE,
        part_id::GNU_VERSION,
        part_id::GNU_HASH,
        part_id::DYNAMIC,
        part_id::INTERP,
        part_id::FILE_HEADER,
        part_id::PROGRAM_HEADERS,
        part_id::SECTION_HEADERS,
        part_id::SHSTRTAB,
    ];

    for part_id in IGNORED {
        *expected.get_mut(*part_id) = IGNORED_OFFSET;
    }
}

fn offsets_by_key(
    memory_offsets: &OutputSectionPartMap<u64>,
    output_order: &OutputOrder,
) -> Vec<(PartId, u64)> {
    let mut offsets_by_key = Vec::new();
    memory_offsets.output_order_map(output_order, |part_id, _alignment, offset| {
        offsets_by_key.push((part_id, *offset));
    });
    offsets_by_key
}
