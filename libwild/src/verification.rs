//! Used after `finalise_layout` to verify that all section output offsets were bumped by an amount
//! equal to the size requested for that section.

use crate::bail;
use crate::error::Result;
use crate::layout::FileLayout;
use crate::output_section_id::OutputOrder;
use crate::output_section_id::OutputSections;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::part_id::PartId;
use crate::platform::Platform;
use itertools::Itertools;

pub(crate) struct OffsetVerifier {
    expected: OutputSectionPartMap<u64>,
    sizes: OutputSectionPartMap<u64>,
}

impl OffsetVerifier {
    pub(crate) fn new<P: Platform>(
        starting_offsets: &OutputSectionPartMap<u64>,
        sizes: &OutputSectionPartMap<u64>,
    ) -> Self {
        let mut expected = starting_offsets.clone();
        expected.merge(sizes);
        clear_ignored::<P>(&mut expected);
        Self {
            expected,
            sizes: sizes.clone(),
        }
    }

    pub(crate) fn verify<'data, P: Platform>(
        &self,
        memory_offsets: &OutputSectionPartMap<u64>,
        output_sections: &OutputSections<P>,
        output_order: &OutputOrder,
        files: &[FileLayout<'data, P>],
    ) -> Result {
        if memory_offsets == &self.expected && self.alignments_ok(output_sections) {
            return Ok(());
        }
        let expected = offsets_by_key(&self.expected, output_order, output_sections);
        let actual = offsets_by_key(memory_offsets, output_order, output_sections);
        let sizes = offsets_by_key(&self.sizes, output_order, output_sections);
        let mut problems = Vec::new();

        for (((part_id, exp), (_, act)), (_, size)) in expected.iter().zip(actual.iter()).zip(sizes)
        {
            let alignment = part_id.alignment(output_sections);
            if exp != act {
                let actual_bump = *act as i64 - (*exp as i64 - size as i64);
                problems.push(format!(
                    "Part #{part_id} (section {} alignment: {alignment}) expected: 0x{exp:x} \
                     actual: 0x{act:x} bumped by: 0x{actual_bump:x} requested size: 0x{size:x}\n",
                    output_sections.display_name(part_id.output_section_id::<P>())
                ));
            }
            if !size.is_multiple_of(part_id.alignment(output_sections).value())
                && !should_ignore_alignment::<P>(*part_id)
            {
                problems.push(format!(
                    "Part #{part_id} (section {} alignment: {alignment}) \
                     has non aligned size: 0x{size:x}\n",
                    output_sections.display_name(part_id.output_section_id::<P>())
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

    fn alignments_ok<P: Platform>(&self, output_sections: &OutputSections<P>) -> bool {
        self.sizes.iter().all(|(part_id, size)| {
            size.is_multiple_of(part_id.alignment(output_sections).value())
                || should_ignore_alignment::<P>(part_id)
        })
    }
}

fn should_ignore_alignment<P: Platform>(part_id: PartId) -> bool {
    let section_id = part_id.output_section_id::<P>();
    part_id.should_pack::<P>() || P::VERIFY_IGNORE_ALIGNMENT_SECTION_IDS.contains(&section_id)
}

/// Clear offsets for sections where we never take the address of a section offset during
/// `finalise_layout`.
pub(crate) fn clear_ignored<P: Platform>(expected: &mut OutputSectionPartMap<u64>) {
    /// A distinctive value that should definitely make things fail if we actually do make use of
    /// one of these offsets during `finalise_layout`.
    const IGNORED_OFFSET: u64 = 0x98760000;

    for &section_id in P::VERIFY_IGNORE_SECTION_IDS {
        if let Some(part_id) = P::single_part_id(section_id) {
            *expected.get_mut(part_id) = IGNORED_OFFSET;
        }
    }
}

fn offsets_by_key<P: Platform>(
    memory_offsets: &OutputSectionPartMap<u64>,
    output_order: &OutputOrder,
    output_sections: &OutputSections<P>,
) -> Vec<(PartId, u64)> {
    let mut offsets_by_key = Vec::new();
    memory_offsets.output_order_map(
        output_order,
        output_sections,
        |part_id, _alignment, offset| {
            offsets_by_key.push((part_id, *offset));
        },
    );
    offsets_by_key
}
