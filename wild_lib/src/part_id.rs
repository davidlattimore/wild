use crate::alignment::Alignment;
use crate::alignment::NUM_ALIGNMENTS;
use crate::args::Args;
use crate::elf::SectionHeader;
use crate::error::Result;
use crate::output_section_id;
use crate::output_section_id::BuiltInSectionDetails;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::SectionDetails;
use crate::output_section_id::SectionName;
use object::read::elf::SectionHeader as _;
use std::fmt::Debug;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TemporaryPartId<'data> {
    BuiltIn(PartId),
    Custom(CustomSectionId<'data>),
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
    pub(crate) alignment: Alignment,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct UnloadedSection<'data> {
    pub(crate) part_id: TemporaryPartId<'data>,
    pub(crate) details: SectionDetails<'data>,
    pub(crate) is_string_merge: bool,
}

// Sections that we generate ourselves rather than copying directly from input objects.
pub(crate) const FILE_HEADER: PartId = PartId(0);
pub(crate) const PROGRAM_HEADERS: PartId = PartId(1);
pub(crate) const SECTION_HEADERS: PartId = PartId(2);
pub(crate) const SHSTRTAB: PartId = PartId(3);
pub(crate) const STRTAB: PartId = PartId(4);
pub(crate) const GOT: PartId = PartId(5);
pub(crate) const PLT: PartId = PartId(6);
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

pub(crate) const NUM_SINGLE_PART_SECTIONS: u32 = 17;

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

impl<'data> UnloadedSection<'data> {
    #[allow(clippy::if_same_then_else)]
    pub(crate) fn from_section(
        object: &crate::elf::File<'data>,
        section: &SectionHeader,
        args: &Args,
    ) -> Result<Option<Self>> {
        // Ideally we support reading an actual linker script to make these decisions, but for now
        // we just hard code stuff.
        let e = object::LittleEndian;
        let section_name = object.section_name(section).unwrap_or_default();
        let sh_flags = section.sh_flags.get(e);
        let alignment = Alignment::new(section.sh_addralign(e).max(1))?;
        let built_in_section_id = if section_name.starts_with(b".rodata") {
            Some(output_section_id::RODATA)
        } else if section_name.starts_with(b".text") {
            Some(output_section_id::TEXT)
        } else if section_name.starts_with(b".data") {
            Some(output_section_id::DATA)
        } else if section_name.starts_with(b".bss") {
            Some(output_section_id::BSS)
        } else if section_name.starts_with(b".init_array") || section_name.starts_with(b".ctors.") {
            Some(output_section_id::INIT_ARRAY)
        } else if section_name.starts_with(b".fini_array") || section_name.starts_with(b".dtors.") {
            Some(output_section_id::FINI_ARRAY)
        } else if section_name == b".init" {
            Some(output_section_id::INIT)
        } else if section_name == b".fini" {
            Some(output_section_id::FINI)
        } else if section_name == b".preinit_array" {
            Some(output_section_id::PREINIT_ARRAY)
        } else if section_name.starts_with(b".tdata") {
            Some(output_section_id::TDATA)
        } else if section_name.starts_with(b".tbss") {
            Some(output_section_id::TBSS)
        } else if section_name == b".comment" {
            Some(output_section_id::COMMENT)
        } else if section_name == b".eh_frame" {
            return Ok(Some(UnloadedSection {
                part_id: TemporaryPartId::EhFrameData,
                details: output_section_id::EH_FRAME.built_in_details().details,
                is_string_merge: false,
            }));
        } else if section_name.starts_with(b".gcc_except_table") {
            Some(output_section_id::GCC_EXCEPT_TABLE)
        } else if section_name.starts_with(b".rela")
            || b".strtab" == section_name
            || b".symtab" == section_name
            || b".shstrtab" == section_name
            || b".group" == section_name
        {
            // We don't currently allow references to these sections, discard them so that we avoid
            // allocating output section IDs.
            None
        } else if args.strip_debug && section_name == b".debug_str" {
            None
        } else {
            let sh_type = section.sh_type.get(e);
            let ty = if sh_type == object::elf::SHT_NOBITS {
                sh_type
            } else {
                object::elf::SHT_PROGBITS
            };
            let retain = sh_flags & crate::elf::shf::GNU_RETAIN != 0;
            let section_flags = sh_flags;
            if !section_name.is_empty() {
                let custom_section_id = CustomSectionId {
                    name: SectionName(section_name),
                    alignment,
                };
                let details = SectionDetails {
                    name: SectionName(section_name),
                    ty,
                    section_flags,
                    element_size: 0,
                    retain,
                    packed: false,
                };
                return Ok(Some(UnloadedSection {
                    part_id: TemporaryPartId::Custom(custom_section_id),
                    details,
                    is_string_merge: should_merge_strings(section, args),
                }));
            }
            if sh_flags & u64::from(object::elf::SHF_ALLOC) == 0 {
                None
            } else if sh_type == object::elf::SHT_PROGBITS {
                if sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0 {
                    Some(output_section_id::TEXT)
                } else if sh_flags & u64::from(object::elf::SHF_TLS) != 0 {
                    Some(output_section_id::TDATA)
                } else if sh_flags & u64::from(object::elf::SHF_WRITE) != 0 {
                    Some(output_section_id::DATA)
                } else {
                    Some(output_section_id::RODATA)
                }
            } else if sh_type == object::elf::SHT_NOBITS {
                if sh_flags & u64::from(object::elf::SHF_TLS) != 0 {
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
        Ok(Some(UnloadedSection {
            part_id: TemporaryPartId::BuiltIn(part_id),
            details: built_in_section_id.built_in_details().details,
            is_string_merge: should_merge_strings(section, args),
        }))
    }
}

/// Returns whether the supplied section meets our criteria for string merging. String merging is
/// optional, so there are cases where we might be able to merge, but don't currently. For example
/// if alignment is > 1.
fn should_merge_strings(section: &SectionHeader, args: &Args) -> bool {
    if !args.merge_strings {
        return false;
    }
    let e = object::LittleEndian;
    let sh_flags = section.sh_flags.get(e);
    (sh_flags & crate::elf::shf::MERGE) != 0
        && (sh_flags & crate::elf::shf::STRINGS) != 0
        && section.sh_addralign.get(e) <= 1
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

    pub(crate) fn offset(&self, offset: usize) -> PartId {
        PartId(self.0 + offset as u32)
    }

    pub(crate) const fn from_u32(value: u32) -> PartId {
        PartId(value)
    }

    pub(crate) fn alignment(&self) -> Alignment {
        if let Some(offset) = self.0.checked_sub(REGULAR_PART_BASE) {
            Alignment {
                exponent: NUM_ALIGNMENTS as u16 - 1 - (offset % NUM_ALIGNMENTS as u32) as u16,
            }
        } else {
            self.built_in_details().min_alignment
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

impl<'data> std::fmt::Display for TemporaryPartId<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemporaryPartId::BuiltIn(id) => {
                write!(
                    f,
                    "section #{} ({})",
                    id.as_usize(),
                    id.built_in_details().details.name
                )
            }
            TemporaryPartId::Custom(custom) => {
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
