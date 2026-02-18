use crate::alignment::Alignment;
use crate::alignment::NUM_ALIGNMENTS;
use crate::args::Args;
use crate::output_section_id::BuiltInSectionDetails;
use crate::output_section_id::FINI;
use crate::output_section_id::INIT;
use crate::output_section_id::OutputSectionId;
use crate::platform;
use std::fmt::Debug;

/// An ID for a part of an output section. Parts IDs are ordered with generated
/// single-part-per-section parts first, followed by parts that belong to multi-part sections,
/// followed by sections that are partitioned by alignment and lastly custom sections, which are
/// also partitioned by alignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct PartId(u32);

// Sections that we generate ourselves rather than copying directly from input objects.
pub(crate) const FILE_HEADER: PartId = PartId(0);
pub(crate) const PROGRAM_HEADERS: PartId = PartId(1);
pub(crate) const SECTION_HEADERS: PartId = PartId(2);
pub(crate) const SHSTRTAB: PartId = PartId(3);
pub(crate) const STRTAB: PartId = PartId(4);
pub(crate) const GOT: PartId = PartId(5);
pub(crate) const PLT_GOT: PartId = PartId(6);
pub(crate) const RELA_PLT: PartId = PartId(7);
pub(crate) const EH_FRAME: PartId = PartId(8);
pub(crate) const EH_FRAME_HDR: PartId = PartId(9);
pub(crate) const SFRAME: PartId = PartId(10);
pub(crate) const DYNAMIC: PartId = PartId(11);
pub(crate) const SYSV_HASH: PartId = PartId(12);
pub(crate) const GNU_HASH: PartId = PartId(13);
pub(crate) const DYNSYM: PartId = PartId(14);
pub(crate) const DYNSTR: PartId = PartId(15);
pub(crate) const INTERP: PartId = PartId(16);
pub(crate) const GNU_VERSION: PartId = PartId(17);
pub(crate) const GNU_VERSION_D: PartId = PartId(18);
pub(crate) const GNU_VERSION_R: PartId = PartId(19);
pub(crate) const NOTE_GNU_PROPERTY: PartId = PartId(20);
pub(crate) const NOTE_GNU_BUILD_ID: PartId = PartId(21);
pub(crate) const SYMTAB_LOCAL: PartId = PartId(22);
pub(crate) const SYMTAB_GLOBAL: PartId = PartId(23);
pub(crate) const RELA_DYN_RELATIVE: PartId = PartId(24);
pub(crate) const RELA_DYN_GENERAL: PartId = PartId(25);
pub(crate) const RISCV_ATTRIBUTES: PartId = PartId(26);
pub(crate) const RELRO_PADDING: PartId = PartId(27);

pub(crate) const NUM_SINGLE_PART_SECTIONS: u32 = 28;

#[cfg(test)]
pub(crate) const NUM_BUILT_IN_PARTS: usize = NUM_SINGLE_PART_SECTIONS as usize
    + crate::output_section_id::NUM_BUILT_IN_REGULAR_SECTIONS * crate::alignment::NUM_ALIGNMENTS;

/// A placeholder used for custom sections before we know their actual PartId.
pub(crate) const CUSTOM_PLACEHOLDER: PartId = PartId(u32::MAX);

/// Returns whether the supplied section meets our criteria for section merging. Section merging is
/// optional, so there are cases where we might be able to merge, but don't currently. For example
/// if alignment is > 1.
pub(crate) fn should_merge_sections<S: platform::SectionFlags>(
    section_flags: S,
    section_alignment: u64,
    args: &Args,
) -> bool {
    if !args.merge_sections {
        return false;
    }
    section_flags.is_merge_section() && section_alignment <= 1
}

impl PartId {
    pub(crate) const fn output_section_id(self) -> OutputSectionId {
        if self.0 < NUM_SINGLE_PART_SECTIONS {
            OutputSectionId::from_u32(self.0)
        } else {
            OutputSectionId::from_u32(
                (self.0 - NUM_SINGLE_PART_SECTIONS) / (NUM_ALIGNMENTS as u32)
                    + NUM_SINGLE_PART_SECTIONS,
            )
        }
    }

    pub(crate) fn from_usize(raw: usize) -> Self {
        PartId(u32::try_from(raw).expect("Part IDs overflowed 32 bits"))
    }

    pub(crate) fn as_usize(self) -> usize {
        self.0 as usize
    }

    pub(crate) fn built_in_details(self) -> &'static BuiltInSectionDetails {
        self.output_section_id().built_in_details()
    }

    pub(crate) fn offset(self, offset: usize) -> PartId {
        PartId(self.0 + offset as u32)
    }

    pub(crate) const fn from_u32(value: u32) -> PartId {
        PartId(value)
    }

    pub(crate) fn alignment(self) -> Alignment {
        if let Some(offset) = self.0.checked_sub(NUM_SINGLE_PART_SECTIONS) {
            Alignment {
                exponent: NUM_ALIGNMENTS as u8 - 1 - (offset % NUM_ALIGNMENTS as u32) as u8,
            }
        } else {
            self.built_in_details().min_alignment
        }
    }
}

impl PartId {
    /// Returns whether we should skip adding padding after this section. This is a special rule
    /// that's just for `.init` and `.fini`. The `.init` section `crti.o` contains the start of a
    /// function and `crtn.o` contains the end of that function. If `.init` has say alignment = 4
    /// and we add padding after it to bring it up to a multiple of 4 bytes, then we'll break the
    /// function, since the padding bytes won't be valid instructions.
    pub(crate) fn should_pack(self) -> bool {
        let section_id = self.output_section_id();
        section_id == INIT || section_id == FINI
    }
}

#[cfg(test)]
pub(crate) fn built_in_part_ids()
-> impl ExactSizeIterator<Item = PartId> + DoubleEndedIterator<Item = PartId> {
    (0..NUM_BUILT_IN_PARTS).map(|n| PartId(n as u32))
}

impl std::fmt::Display for PartId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.as_usize(), f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversion_consistency() {
        for i in NUM_SINGLE_PART_SECTIONS..NUM_SINGLE_PART_SECTIONS + 40 {
            let part_id = PartId::from_u32(i);
            let section_id = part_id.output_section_id();
            let alignment = part_id.alignment();
            let part_id2 = section_id.part_id_with_alignment(alignment);
            assert_eq!(part_id, part_id2);
        }
    }
}
