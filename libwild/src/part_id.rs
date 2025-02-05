use crate::alignment::Alignment;
use crate::alignment::NUM_ALIGNMENTS;
use crate::args::Args;
use crate::elf::SectionHeader;
use crate::error::Result;
use crate::output_section_id;
use crate::output_section_id::BuiltInSectionDetails;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::SectionName;
use crate::output_section_id::FINI;
use crate::output_section_id::INIT;
#[allow(clippy::wildcard_imports)]
use linker_utils::elf::secnames::*;
use linker_utils::elf::shf;
use linker_utils::elf::sht;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::SectionType;
use std::fmt::Debug;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TemporaryPartId<'data> {
    BuiltIn(PartId),
    Custom(CustomSectionId<'data>, Alignment),
    EhFrameData,
}

/// An ID for a part of an output section. Parts IDs are ordered with generated
/// single-part-per-section parts first, followed by parts that belong to multi-part sections,
/// followed by sections that are partitioned by alignment and lastly custom sections, which are
/// also partitioned by alignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct PartId(u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CustomSectionId<'data> {
    pub(crate) name: SectionName<'data>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct UnresolvedSection<'data> {
    pub(crate) part_id: TemporaryPartId<'data>,
    pub(crate) is_string_merge: bool,
}

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
pub(crate) const DYNAMIC: PartId = PartId(10);
pub(crate) const GNU_HASH: PartId = PartId(11);
pub(crate) const DYNSYM: PartId = PartId(12);
pub(crate) const DYNSTR: PartId = PartId(13);
pub(crate) const INTERP: PartId = PartId(14);
pub(crate) const GNU_VERSION: PartId = PartId(15);
pub(crate) const GNU_VERSION_R: PartId = PartId(16);
pub(crate) const NOTE_GNU_PROPERTY: PartId = PartId(17);
pub(crate) const NOTE_GNU_BUILD_ID: PartId = PartId(18);

pub(crate) const NUM_SINGLE_PART_SECTIONS: u32 = 19;

// Generated sections that have more than one part. Fortunately they all have exactly 2 parts.
pub(crate) const SYMTAB_LOCAL: PartId = PartId::multi(0);
pub(crate) const SYMTAB_GLOBAL: PartId = PartId::multi(1);
pub(crate) const RELA_DYN_RELATIVE: PartId = PartId::multi(2);
pub(crate) const RELA_DYN_GENERAL: PartId = PartId::multi(3);

pub(crate) const MULTI_PART_BASE: u32 = NUM_SINGLE_PART_SECTIONS;
pub(crate) const NUM_TWO_PART_SECTIONS: u32 = 2;
pub(crate) const NUM_PARTS_PER_TWO_PART_SECTION: u32 = 2;

/// The offset at which we start splitting sections by alignment.
pub(crate) const REGULAR_PART_BASE: u32 =
    NUM_SINGLE_PART_SECTIONS + NUM_TWO_PART_SECTIONS * NUM_PARTS_PER_TWO_PART_SECTION;

/// Regular sections are sections that come from input files and can contain a mix of alignments.
pub(crate) const NUM_GENERATED_PARTS: usize = REGULAR_PART_BASE as usize;

#[cfg(test)]
pub(crate) const NUM_BUILT_IN_PARTS: usize = NUM_GENERATED_PARTS
    + output_section_id::NUM_BUILT_IN_REGULAR_SECTIONS * crate::alignment::NUM_ALIGNMENTS;

/// A placeholder used for custom sections before we know their actual PartId.
pub(crate) const CUSTOM_PLACEHOLDER: PartId = PartId(u32::MAX);

impl<'data> UnresolvedSection<'data> {
    pub(crate) fn from_section(
        object: &crate::elf::File<'data>,
        section: &SectionHeader,
        args: &Args,
    ) -> Result<Option<Self>> {
        // Ideally we support reading an actual linker script to make these decisions, but for now
        // we just hard code stuff.
        let section_name = object.section_name(section).unwrap_or_default();
        let section_flags = SectionFlags::from_header(section);
        let alignment = Alignment::new(object.section_alignment(section)?.max(1))?;
        let built_in_section_id = if section_name.starts_with(RODATA_SECTION_NAME) {
            Some(output_section_id::RODATA)
        } else if section_name.starts_with(TEXT_SECTION_NAME) {
            Some(output_section_id::TEXT)
        } else if section_name.starts_with(DATA_SECTION_NAME) {
            Some(output_section_id::DATA)
        } else if section_name.starts_with(BSS_SECTION_NAME) {
            Some(output_section_id::BSS)
        } else if section_name.starts_with(INIT_ARRAY_SECTION_NAME)
            || section_name.starts_with(b".ctors")
        {
            Some(output_section_id::INIT_ARRAY)
        } else if section_name.starts_with(FINI_ARRAY_SECTION_NAME)
            || section_name.starts_with(b".dtors")
        {
            Some(output_section_id::FINI_ARRAY)
        } else if section_name == INIT_SECTION_NAME {
            Some(output_section_id::INIT)
        } else if section_name == FINI_SECTION_NAME {
            Some(output_section_id::FINI)
        } else if section_name == PREINIT_ARRAY_SECTION_NAME {
            Some(output_section_id::PREINIT_ARRAY)
        } else if section_name.starts_with(TDATA_SECTION_NAME) {
            Some(output_section_id::TDATA)
        } else if section_name.starts_with(TBSS_SECTION_NAME) {
            Some(output_section_id::TBSS)
        } else if section_name == COMMENT_SECTION_NAME {
            Some(output_section_id::COMMENT)
        } else if section_name == EH_FRAME_SECTION_NAME {
            return Ok(Some(UnresolvedSection {
                part_id: TemporaryPartId::EhFrameData,
                is_string_merge: false,
            }));
        } else if section_name.starts_with(GCC_EXCEPT_TABLE_SECTION_NAME) {
            Some(output_section_id::GCC_EXCEPT_TABLE)
        } else if section_name == NOTE_ABI_TAG_SECTION_NAME {
            Some(output_section_id::NOTE_ABI_TAG)
        } else if section_name == NOTE_GNU_BUILD_ID_SECTION_NAME {
            Some(output_section_id::NOTE_GNU_BUILD_ID)
        } else if section_name.starts_with(b".rela")
            || STRTAB_SECTION_NAME == section_name
            || SYMTAB_SECTION_NAME == section_name
            || SHSTRTAB_SECTION_NAME == section_name
            || GROUP_SECTION_NAME == section_name
        {
            // We don't currently allow references to these sections, discard them so that we avoid
            // allocating output section IDs.
            None
        } else if args.strip_debug
            && section_name.starts_with(b".debug_")
            && !section_flags.contains(shf::ALLOC)
        {
            // Drop soon string merge debug info section.
            None
        } else if section_name == NOTE_GNU_PROPERTY_SECTION_NAME {
            return Ok(Some(UnresolvedSection {
                part_id: TemporaryPartId::BuiltIn(NOTE_GNU_PROPERTY),
                is_string_merge: false,
            }));
        } else {
            let sh_type = SectionType::from_header(section);
            if !section_name.is_empty() {
                let custom_section_id = CustomSectionId {
                    name: SectionName(section_name),
                };
                return Ok(Some(UnresolvedSection {
                    part_id: TemporaryPartId::Custom(custom_section_id, alignment),
                    is_string_merge: should_merge_strings(
                        section,
                        object.section_alignment(section)?,
                        args,
                    ),
                }));
            }
            if !section_flags.contains(shf::ALLOC) {
                None
            } else if sh_type == sht::PROGBITS {
                if section_flags.contains(shf::EXECINSTR) {
                    Some(output_section_id::TEXT)
                } else if section_flags.contains(shf::TLS) {
                    Some(output_section_id::TDATA)
                } else if section_flags.contains(shf::WRITE) {
                    Some(output_section_id::DATA)
                } else {
                    Some(output_section_id::RODATA)
                }
            } else if sh_type == sht::NOBITS {
                if section_flags.contains(shf::TLS) {
                    Some(output_section_id::TBSS)
                } else {
                    Some(output_section_id::BSS)
                }
            } else {
                None
            }
        };
        let Some(built_in_section_id) = built_in_section_id else {
            return Ok(None);
        };
        let part_id = built_in_section_id.part_id_with_alignment(alignment);
        Ok(Some(UnresolvedSection {
            part_id: TemporaryPartId::BuiltIn(part_id),
            is_string_merge: should_merge_strings(
                section,
                object.section_alignment(section)?,
                args,
            ),
        }))
    }

    pub(crate) fn name(&self) -> SectionName<'data> {
        self.part_id.name()
    }
}

/// Returns whether the supplied section meets our criteria for string merging. String merging is
/// optional, so there are cases where we might be able to merge, but don't currently. For example
/// if alignment is > 1.
fn should_merge_strings(section: &SectionHeader, section_alignment: u64, args: &Args) -> bool {
    if !args.merge_strings {
        return false;
    }
    let section_flags = SectionFlags::from_header(section);
    section_flags.contains(shf::MERGE)
        && section_flags.contains(shf::STRINGS)
        && section_alignment <= 1
}

impl PartId {
    const fn multi(offset: u32) -> PartId {
        PartId(NUM_SINGLE_PART_SECTIONS + offset)
    }

    pub(crate) const fn output_section_id(self) -> OutputSectionId {
        if self.0 < NUM_SINGLE_PART_SECTIONS {
            OutputSectionId::from_u32(self.0)
        } else if self.0 < REGULAR_PART_BASE {
            OutputSectionId::from_u32(
                (self.0 - MULTI_PART_BASE) / NUM_PARTS_PER_TWO_PART_SECTION
                    + NUM_SINGLE_PART_SECTIONS,
            )
        } else {
            OutputSectionId::from_u32(
                (self.0 - REGULAR_PART_BASE) / (NUM_ALIGNMENTS as u32)
                    + NUM_SINGLE_PART_SECTIONS
                    + NUM_TWO_PART_SECTIONS,
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
        if let Some(offset) = self.0.checked_sub(REGULAR_PART_BASE) {
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
    /// that's just for `.init` and `.fini`. The `.init` section `crti.o` contains the starts of a
    /// function and `crtn.o` contains the end of that function. If `.init` has say alignment = 4
    /// and we add padding after it to bring it up to a multiple of 4 bytes, then we'll break the
    /// function, since the padding bytes won't be valid instructions.
    pub(crate) fn should_pack(self) -> bool {
        let section_id = self.output_section_id();
        section_id == INIT || section_id == FINI
    }
}

impl<'data> TemporaryPartId<'data> {
    fn name(&self) -> SectionName<'data> {
        match self {
            TemporaryPartId::BuiltIn(id) => id.built_in_details().name,
            TemporaryPartId::Custom(id, _) => id.name,
            TemporaryPartId::EhFrameData => EH_FRAME.built_in_details().name,
        }
    }
}

#[cfg(test)]
pub(crate) fn built_in_part_ids(
) -> impl ExactSizeIterator<Item = PartId> + DoubleEndedIterator<Item = PartId> {
    (0..NUM_BUILT_IN_PARTS).map(|n| PartId(n as u32))
}

impl std::fmt::Display for PartId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.as_usize(), f)
    }
}

impl std::fmt::Display for TemporaryPartId<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemporaryPartId::BuiltIn(id) => {
                write!(
                    f,
                    "section #{} ({})",
                    id.as_usize(),
                    id.built_in_details().name
                )
            }
            TemporaryPartId::Custom(custom, _) => {
                write!(f, "custom section `{}`", custom.name)
            }
            TemporaryPartId::EhFrameData => write!(f, "eh_frame data"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversion_consistency() {
        for i in REGULAR_PART_BASE..REGULAR_PART_BASE + 40 {
            let part_id = PartId::from_u32(i);
            let section_id = part_id.output_section_id();
            let alignment = part_id.alignment();
            let part_id2 = section_id.part_id_with_alignment(alignment);
            assert_eq!(part_id, part_id2);
        }
    }
}
