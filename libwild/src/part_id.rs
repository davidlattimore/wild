use crate::alignment::Alignment;
use crate::alignment::NUM_ALIGNMENTS;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::platform;
use crate::platform::Platform;
use std::fmt::Debug;

/// An ID for a part of an output section. Parts IDs are ordered with generated
/// single-part-per-section parts first, followed by parts that belong to multi-part sections,
/// followed by sections that are partitioned by alignment and lastly custom sections, which are
/// also partitioned by alignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct PartId(u32);

pub(crate) const UNMAPPED: PartId =
    crate::output_section_id::CommonSinglePartSectionId::Unmapped.part_id();

pub(crate) const FILE_HEADER: PartId =
    crate::output_section_id::CommonSinglePartSectionId::FileHeader.part_id();

pub(crate) const fn regular_part_base<P: Platform>() -> PartId {
    PartId::from_u32(P::NUM_SINGLE_PART_SECTIONS)
}

/// Returns whether the supplied section meets our criteria for section merging. Section merging is
/// optional, so there are cases where we might be able to merge, but don't currently. For example
/// if alignment is > 1.
pub(crate) fn should_merge_sections(
    section_header: &impl platform::SectionHeader,
    section_alignment: u64,
    args: &impl platform::Args,
) -> bool {
    if !args.should_merge_sections() {
        return false;
    }
    section_header.is_merge_section() && section_alignment <= 1
}

impl PartId {
    /// A placeholder used for custom sections before we know their actual PartId.
    pub(crate) const CUSTOM_PLACEHOLDER: PartId = PartId(u32::MAX);

    pub(crate) fn output_section_id<P: Platform>(self) -> OutputSectionId {
        if self < regular_part_base::<P>() {
            P::single_part_output_section_id(self).unwrap_or_else(|| {
                panic!(
                    "platform {} has no output section ID for part {self:?}",
                    std::any::type_name::<P>()
                )
            })
        } else {
            OutputSectionId::from_u32(
                (self.0 - regular_part_base::<P>().0) / (NUM_ALIGNMENTS as u32)
                    + crate::output_section_id::regular_section_base::<P>().as_u32(),
            )
        }
    }

    pub(crate) fn from_usize(raw: usize) -> Self {
        PartId(u32::try_from(raw).expect("Part IDs overflowed 32 bits"))
    }

    pub(crate) fn as_usize(self) -> usize {
        self.0 as usize
    }

    pub(crate) const fn as_u32(self) -> u32 {
        self.0
    }

    pub(crate) const fn offset(self, offset: usize) -> PartId {
        PartId(self.0 + offset as u32)
    }

    pub(crate) const fn from_u32(value: u32) -> PartId {
        PartId(value)
    }

    pub(crate) fn alignment<P: Platform>(
        self,
        output_sections: &OutputSections<'_, P>,
    ) -> Alignment {
        if let Some(offset) = self.0.checked_sub(regular_part_base::<P>().0) {
            Alignment {
                exponent: NUM_ALIGNMENTS as u8 - 1 - (offset % NUM_ALIGNMENTS as u32) as u8,
            }
        } else {
            self.output_section_id::<P>().min_alignment(output_sections)
        }
    }
}

impl PartId {
    /// Returns whether we should skip adding padding after this section.
    pub(crate) fn should_pack<P: Platform>(self) -> bool {
        let section_id = self.output_section_id::<P>();
        P::PACKED_SECTION_IDS.contains(&section_id)
    }
}

#[cfg(test)]
pub(crate) fn built_in_part_ids<P: Platform>() -> impl Iterator<Item = PartId> {
    let regular_part_base = regular_part_base::<P>();
    let single_part_ids = (0..regular_part_base.0).map(PartId::from_u32);
    let regular_part_ids = (0..P::NUM_BUILT_IN_REGULAR_SECTIONS * NUM_ALIGNMENTS)
        .map(move |offset| regular_part_base.offset(offset));
    single_part_ids.chain(regular_part_ids)
}

impl std::fmt::Display for PartId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.as_usize(), f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::RelocationModel;
    use crate::output_kind::OutputKind;
    use crate::output_section_id;

    fn check_platform_part_ids<P: Platform>() {
        let output_kind = OutputKind::StaticExecutable(RelocationModel::NonRelocatable);
        let output_sections = OutputSections::<P>::with_base_address(0, output_kind);
        let regular_part_base = regular_part_base::<P>();
        let regular_section_base = output_section_id::regular_section_base::<P>();
        let num_single_part_sections = P::NUM_SINGLE_PART_SECTIONS as usize;

        for section_id in (0..num_single_part_sections).map(OutputSectionId::from_usize) {
            let part_id = P::single_part_id(section_id).unwrap();
            assert_eq!(P::single_part_output_section_id(part_id), Some(section_id));
            assert_eq!(
                section_id.base_part_id::<P>(),
                part_id,
                "single-part base ID failed for {}",
                std::any::type_name::<P>()
            );
            assert_eq!(
                part_id.output_section_id::<P>(),
                section_id,
                "single-part round trip failed for {}",
                std::any::type_name::<P>()
            );
        }

        assert_eq!(P::single_part_id(regular_section_base), None);
        assert_eq!(P::single_part_output_section_id(regular_part_base), None);
        for offset in 0..P::NUM_BUILT_IN_REGULAR_SECTIONS {
            let section_id = regular_section_base.offset(offset);
            for part_id in section_id.parts::<P>() {
                let alignment = part_id.alignment(&output_sections);
                assert_eq!(
                    part_id.output_section_id::<P>(),
                    section_id,
                    "regular-part round trip failed for {}",
                    std::any::type_name::<P>()
                );
                assert_eq!(
                    section_id.part_id_with_alignment::<P>(alignment),
                    part_id,
                    "regular-part alignment conversion failed for {}",
                    std::any::type_name::<P>()
                );
            }
        }

        assert_eq!(
            P::built_in_section_details().len(),
            output_section_id::num_built_in_sections::<P>(),
            "built-in section definitions don't cover the ID range for {}",
            std::any::type_name::<P>()
        );
    }

    #[test]
    fn test_platform_part_id_invariants() {
        check_platform_part_ids::<crate::elf::Elf>();
        check_platform_part_ids::<crate::macho::MachO>();
        check_platform_part_ids::<crate::wasm::Wasm>();
    }
}
