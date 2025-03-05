//! Instructions for adding a new generated, single-part output section:
//!
//! * Add a new constant `PartId` to `part_id.rs`.
//! * Update `NUM_SINGLE_PART_SECTIONS` in `part_id.rs`.
//! * Define a constant `OutputSectionId` below.
//! * Add the section definition info to `SECTION_DEFINITIONS`, most likely inserting it just before
//!   the multi-part sections.
//! * Add the section to `test_constant_ids` to make sure the ID is consistent with its position in
//!   `SECTION_DEFINITIONS`.
//! * Insert the new section into the output order in `sections_and_segments_events`. The position needs
//!   to be consistent with the access flags on the section. e.g. if the section is read-only data,
//!   it should go between the start and end of the read-only segment.
//!
//! Adding a new alignment-base (regular) section is similar to the above, but skip the steps
//! related to `part_id.rs` and insert later in `SECTION_DEFINITIONS` (probably at the end). Also,
//! update `NUM_BUILT_IN_REGULAR_SECTIONS`.

use self::elf::TLS_MODULE_BASE_SYMBOL_NAME;
use crate::alignment;
use crate::alignment::Alignment;
use crate::alignment::NUM_ALIGNMENTS;
use crate::args::OutputKind;
use crate::elf;
use crate::elf::DynamicEntry;
use crate::elf::Versym;
use crate::error::Result;
use crate::layout::NonAddressableCounts;
use crate::layout::OutputRecordLayout;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::part_id;
use crate::part_id::NUM_PARTS_PER_TWO_PART_SECTION;
use crate::part_id::NUM_SINGLE_PART_SECTIONS;
use crate::part_id::PartId;
use crate::part_id::REGULAR_PART_BASE;
use crate::program_segments::ProgramSegmentId;
use crate::resolution::SectionSlot;
use ahash::AHashMap;
use anyhow::anyhow;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::SectionType;
#[allow(clippy::wildcard_imports)]
use linker_utils::elf::secnames::*;
use linker_utils::elf::shf;
use linker_utils::elf::sht;
use std::fmt::Debug;
use std::fmt::Display;

/// Number of non-regular sections that we define. A non-regular section is one that isn't split by
/// alignment. They're always generated. Most of them only have a single part.
pub(crate) const NUM_NON_REGULAR_SECTIONS: u32 =
    part_id::NUM_SINGLE_PART_SECTIONS + part_id::NUM_TWO_PART_SECTIONS;

/// Number of sections that we have built-in IDs for.
pub(crate) const NUM_BUILT_IN_SECTIONS: usize =
    NUM_NON_REGULAR_SECTIONS as usize + NUM_BUILT_IN_REGULAR_SECTIONS;

/// An ID for an output section. This is used for looking up section info. It's independent of
/// section ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct OutputSectionId(u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CustomSectionDetails<'data> {
    pub(crate) name: SectionName<'data>,
    pub(crate) index: object::SectionIndex,
    pub(crate) alignment: Alignment,
    pub(crate) section_flags: SectionFlags,
    pub(crate) ty: SectionType,
}

// Single-part sections that we generate ourselves rather than copying directly from input objects.
pub(crate) const FILE_HEADER: OutputSectionId = part_id::FILE_HEADER.output_section_id();
pub(crate) const PROGRAM_HEADERS: OutputSectionId = part_id::PROGRAM_HEADERS.output_section_id();
pub(crate) const SECTION_HEADERS: OutputSectionId = part_id::SECTION_HEADERS.output_section_id();
pub(crate) const SHSTRTAB: OutputSectionId = part_id::SHSTRTAB.output_section_id();
pub(crate) const STRTAB: OutputSectionId = part_id::STRTAB.output_section_id();
pub(crate) const GOT: OutputSectionId = part_id::GOT.output_section_id();
pub(crate) const RELA_PLT: OutputSectionId = part_id::RELA_PLT.output_section_id();
pub(crate) const EH_FRAME: OutputSectionId = part_id::EH_FRAME.output_section_id();
pub(crate) const EH_FRAME_HDR: OutputSectionId = part_id::EH_FRAME_HDR.output_section_id();
pub(crate) const DYNAMIC: OutputSectionId = part_id::DYNAMIC.output_section_id();
pub(crate) const GNU_HASH: OutputSectionId = part_id::GNU_HASH.output_section_id();
pub(crate) const DYNSYM: OutputSectionId = part_id::DYNSYM.output_section_id();
pub(crate) const DYNSTR: OutputSectionId = part_id::DYNSTR.output_section_id();
pub(crate) const INTERP: OutputSectionId = part_id::INTERP.output_section_id();
pub(crate) const GNU_VERSION: OutputSectionId = part_id::GNU_VERSION.output_section_id();
pub(crate) const GNU_VERSION_R: OutputSectionId = part_id::GNU_VERSION_R.output_section_id();
pub(crate) const PLT_GOT: OutputSectionId = part_id::PLT_GOT.output_section_id();
pub(crate) const NOTE_GNU_PROPERTY: OutputSectionId =
    part_id::NOTE_GNU_PROPERTY.output_section_id();
pub(crate) const NOTE_GNU_BUILD_ID: OutputSectionId =
    part_id::NOTE_GNU_BUILD_ID.output_section_id();

// These two are multi-part sections, but we can pick any part we wish in order to get the section
// ID.
pub(crate) const SYMTAB: OutputSectionId = part_id::SYMTAB_LOCAL.output_section_id();
pub(crate) const RELA_DYN: OutputSectionId = part_id::RELA_DYN_RELATIVE.output_section_id();

pub(crate) const RODATA: OutputSectionId = OutputSectionId::regular(0);
pub(crate) const INIT_ARRAY: OutputSectionId = OutputSectionId::regular(1);
pub(crate) const FINI_ARRAY: OutputSectionId = OutputSectionId::regular(2);
pub(crate) const PREINIT_ARRAY: OutputSectionId = OutputSectionId::regular(3);
pub(crate) const TEXT: OutputSectionId = OutputSectionId::regular(4);
pub(crate) const INIT: OutputSectionId = OutputSectionId::regular(5);
pub(crate) const FINI: OutputSectionId = OutputSectionId::regular(6);
pub(crate) const DATA: OutputSectionId = OutputSectionId::regular(7);
pub(crate) const TDATA: OutputSectionId = OutputSectionId::regular(8);
pub(crate) const TBSS: OutputSectionId = OutputSectionId::regular(9);
pub(crate) const BSS: OutputSectionId = OutputSectionId::regular(10);
pub(crate) const COMMENT: OutputSectionId = OutputSectionId::regular(11);
pub(crate) const GCC_EXCEPT_TABLE: OutputSectionId = OutputSectionId::regular(12);
pub(crate) const NOTE_ABI_TAG: OutputSectionId = OutputSectionId::regular(13);
pub(crate) const DATA_REL_RO: OutputSectionId = OutputSectionId::regular(14);

pub(crate) const NUM_BUILT_IN_REGULAR_SECTIONS: usize = 15;

pub(crate) struct OutputSections<'data> {
    /// The base address for our output binary.
    pub(crate) base_address: u64,
    pub(crate) section_infos: Vec<SectionOutputInfo<'data>>,

    // TODO: Consider moving this to Layout. We can't populate this until we know which output
    // sections have content, which we don't know until half way through the layout phase.
    /// Mapping from internal section IDs to output section indexes. None, if the section isn't
    /// being output.
    pub(crate) output_section_indexes: Vec<Option<u16>>,

    custom_by_name: AHashMap<SectionName<'data>, OutputSectionId>,
    sections_and_segments_events: Vec<OrderEvent>,
}

#[derive(Default)]
struct CustomSectionIds {
    ro: Vec<OutputSectionId>,
    exec: Vec<OutputSectionId>,
    data: Vec<OutputSectionId>,
    bss: Vec<OutputSectionId>,
    nonalloc: Vec<OutputSectionId>,
}

impl OutputSections<'_> {
    /// Returns an iterator that emits all section IDs and their info.
    pub(crate) fn ids_with_info(
        &self,
    ) -> impl Iterator<Item = (OutputSectionId, &SectionOutputInfo)> {
        self.section_infos
            .iter()
            .enumerate()
            .map(|(raw, info)| (OutputSectionId::from_usize(raw), info))
    }

    /// Determine which loadable segment, if any, each output section is contained within and update
    /// the section info accordingly.
    fn determine_loadable_segment_ids(&mut self) -> Result {
        let mut load_seg_by_section_id = vec![None; self.section_infos.len()];
        let mut current_load_seg = None;

        for event in self.sections_and_segments_events() {
            match event {
                OrderEvent::SegmentStart(seg_id) => {
                    if seg_id.segment_type() == object::elf::PT_LOAD {
                        current_load_seg = Some(seg_id);
                    }
                }
                OrderEvent::SegmentEnd(seg_id) => {
                    if current_load_seg == Some(seg_id) {
                        current_load_seg = None;
                    }
                }
                OrderEvent::Section(section_id) => {
                    load_seg_by_section_id[section_id.as_usize()] = Some(current_load_seg);
                }
            }
        }

        load_seg_by_section_id
            .iter()
            .zip(self.section_infos.iter_mut())
            .try_for_each(|(load_seg, info)| -> Result {
                let load_seg_id = load_seg.ok_or_else(|| {
                    anyhow!(
                        "Section `{}` is missing from output order (update sections_and_segments_events)",
                        info.name,
                    )
                })?;
                info.loadable_segment_id = load_seg_id;
                Ok(())
            })?;
        Ok(())
    }

    pub(crate) fn num_parts(&self) -> usize {
        part_id::REGULAR_PART_BASE as usize
            + (self.num_sections() - NUM_NON_REGULAR_SECTIONS as usize) * NUM_ALIGNMENTS
    }

    pub(crate) fn new_part_map<T: Default>(&self) -> OutputSectionPartMap<T> {
        OutputSectionPartMap::with_size(self.num_parts())
    }

    pub(crate) fn new_section_map<T: Default>(&self) -> OutputSectionMap<T> {
        OutputSectionMap::with_size(self.num_sections())
    }

    pub(crate) fn new_section_map_with<T>(&self, new: impl FnMut() -> T) -> OutputSectionMap<T> {
        let mut values = Vec::new();
        values.resize_with(self.num_sections(), new);
        OutputSectionMap::from_values(values)
    }

    pub(crate) fn section_type(&self, section_id: OutputSectionId) -> SectionType {
        self.output_info(section_id).ty
    }

    pub(crate) fn section_flags(&self, section_id: OutputSectionId) -> SectionFlags {
        self.output_info(section_id).section_flags
    }
}

#[derive(Debug)]
pub(crate) struct SectionOutputInfo<'data> {
    pub(crate) loadable_segment_id: Option<ProgramSegmentId>,
    pub(crate) name: SectionName<'data>,
    pub(crate) section_flags: SectionFlags,
    pub(crate) ty: SectionType,
}

pub(crate) struct BuiltInSectionDetails {
    pub(crate) name: SectionName<'static>,
    pub(crate) section_flags: SectionFlags,
    /// Sections to try to link to. The first section that we're outputting is the one used.
    pub(crate) link: &'static [OutputSectionId],
    start_symbol_name: Option<&'static str>,
    end_symbol_name: Option<&'static str>,
    pub(crate) min_alignment: Alignment,
    info_fn: Option<fn(&InfoInputs) -> u32>,
    pub(crate) keep_if_empty: bool,
    pub(crate) element_size: u64,
    pub(crate) ty: SectionType,
}

impl BuiltInSectionDetails {
    pub(crate) fn start_symbol_name(&self, output_kind: OutputKind) -> Option<&'static str> {
        if self.start_symbol_name == Some(TLS_MODULE_BASE_SYMBOL_NAME)
            && output_kind != OutputKind::SharedObject
        {
            None
        } else {
            self.start_symbol_name
        }
    }

    pub(crate) fn end_symbol_name(&self, output_kind: OutputKind) -> Option<&'static str> {
        if self.end_symbol_name == Some(TLS_MODULE_BASE_SYMBOL_NAME)
            && output_kind == OutputKind::SharedObject
        {
            None
        } else {
            self.end_symbol_name
        }
    }
}

const DEFAULT_DEFS: BuiltInSectionDetails = BuiltInSectionDetails {
    name: SectionName(&[]),
    section_flags: SectionFlags::empty(),
    link: &[],
    start_symbol_name: None,
    end_symbol_name: None,
    min_alignment: alignment::MIN,
    info_fn: None,
    keep_if_empty: false,
    element_size: 0,
    ty: sht::NULL,
};

const SECTION_DEFINITIONS: [BuiltInSectionDetails; NUM_BUILT_IN_SECTIONS] = [
    // A section into which we write headers.
    BuiltInSectionDetails {
        name: SectionName(b""),
        section_flags: shf::ALLOC,
        start_symbol_name: Some("__ehdr_start"),
        keep_if_empty: true,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(PROGRAM_HEADERS_SECTION_NAME),
        section_flags: shf::ALLOC,
        min_alignment: alignment::PROGRAM_HEADER_ENTRY,
        keep_if_empty: true,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(SECTION_HEADERS_SECTION_NAME),
        section_flags: shf::ALLOC,
        keep_if_empty: true,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(SHSTRTAB_SECTION_NAME),
        ty: sht::STRTAB,
        keep_if_empty: true,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(STRTAB_SECTION_NAME),
        ty: sht::STRTAB,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(GOT_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::WRITE.with(shf::ALLOC),
        element_size: crate::elf::GOT_ENTRY_SIZE,
        min_alignment: alignment::GOT_ENTRY,
        start_symbol_name: Some("_GLOBAL_OFFSET_TABLE_"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(PLT_GOT_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC.with(shf::EXECINSTR),
        element_size: crate::elf::PLT_ENTRY_SIZE,
        min_alignment: alignment::PLT,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(RELA_PLT_SECTION_NAME),
        ty: sht::RELA,
        section_flags: shf::ALLOC.with(shf::INFO_LINK),
        element_size: elf::RELA_ENTRY_SIZE,
        link: &[DYNSYM, SYMTAB],
        min_alignment: alignment::RELA_ENTRY,
        start_symbol_name: Some("__rela_iplt_start"),
        end_symbol_name: Some("__rela_iplt_end"),
        info_fn: Some(rela_plt_info),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(EH_FRAME_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC,
        min_alignment: alignment::USIZE,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(EH_FRAME_HDR_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC,
        min_alignment: alignment::EH_FRAME_HDR,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(DYNAMIC_SECTION_NAME),
        ty: sht::DYNAMIC,
        section_flags: shf::ALLOC.with(shf::WRITE),
        element_size: size_of::<DynamicEntry>() as u64,
        link: &[DYNSTR],
        min_alignment: alignment::USIZE,
        start_symbol_name: Some("_DYNAMIC"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(GNU_HASH_SECTION_NAME),
        ty: sht::GNU_HASH,
        section_flags: shf::ALLOC,
        link: &[DYNSYM],
        min_alignment: alignment::GNU_HASH,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(DYNSYM_SECTION_NAME),
        ty: sht::DYNSYM,
        section_flags: shf::ALLOC,
        element_size: size_of::<elf::SymtabEntry>() as u64,
        link: &[DYNSTR],
        min_alignment: alignment::SYMTAB_ENTRY,
        info_fn: Some(dynsym_info),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(DYNSTR_SECTION_NAME),
        ty: sht::STRTAB,
        section_flags: shf::ALLOC,
        min_alignment: alignment::MIN,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(INTERP_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(GNU_VERSION_SECTION_NAME),
        ty: sht::GNU_VERSYM,
        section_flags: shf::ALLOC,
        element_size: size_of::<Versym>() as u64,
        min_alignment: alignment::VERSYM,
        link: &[DYNSYM],
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(GNU_VERSION_R_SECTION_NAME),
        ty: sht::GNU_VERNEED,
        section_flags: shf::ALLOC,
        info_fn: Some(version_r_info),
        min_alignment: alignment::VERSION_R,
        link: &[DYNSTR],
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(NOTE_GNU_PROPERTY_SECTION_NAME),
        ty: sht::NOTE,
        section_flags: shf::ALLOC,
        min_alignment: alignment::NOTE_GNU_PROPERTY,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(NOTE_GNU_BUILD_ID_SECTION_NAME),
        ty: sht::NOTE,
        section_flags: shf::ALLOC,
        min_alignment: alignment::NOTE_GNU_BUILD_ID,
        ..DEFAULT_DEFS
    },
    // Multi-part generated sections
    BuiltInSectionDetails {
        name: SectionName(SYMTAB_SECTION_NAME),
        ty: sht::SYMTAB,
        element_size: size_of::<elf::SymtabEntry>() as u64,
        min_alignment: alignment::SYMTAB_ENTRY,
        link: &[STRTAB],
        info_fn: Some(symtab_info),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(RELA_DYN_SECTION_NAME),
        ty: sht::RELA,
        section_flags: shf::ALLOC,
        element_size: elf::RELA_ENTRY_SIZE,
        min_alignment: alignment::RELA_ENTRY,
        link: &[DYNSYM],
        ..DEFAULT_DEFS
    },
    // Start of regular sections
    BuiltInSectionDetails {
        name: SectionName(RODATA_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(INIT_ARRAY_SECTION_NAME),
        ty: sht::INIT_ARRAY,
        section_flags: shf::ALLOC.with(shf::WRITE).with(shf::GNU_RETAIN),
        element_size: size_of::<u64>() as u64,
        start_symbol_name: Some("__init_array_start"),
        end_symbol_name: Some("__init_array_end"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(FINI_ARRAY_SECTION_NAME),
        ty: sht::FINI_ARRAY,
        section_flags: shf::ALLOC.with(shf::WRITE).with(shf::GNU_RETAIN),
        element_size: size_of::<u64>() as u64,
        start_symbol_name: Some("__fini_array_start"),
        end_symbol_name: Some("__fini_array_end"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(PREINIT_ARRAY_SECTION_NAME),
        ty: sht::PREINIT_ARRAY,
        section_flags: shf::ALLOC.with(shf::GNU_RETAIN),
        start_symbol_name: Some("__preinit_array_start"),
        end_symbol_name: Some("__preinit_array_end"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(TEXT_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC.with(shf::EXECINSTR),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(INIT_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC.with(shf::EXECINSTR).with(shf::GNU_RETAIN),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(FINI_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC.with(shf::EXECINSTR).with(shf::GNU_RETAIN),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(DATA_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC.with(shf::WRITE),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(TDATA_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::WRITE.with(shf::ALLOC).with(shf::TLS),
        // The symbol is defined twice, but later on we make a filtering based on the output type!
        start_symbol_name: Some(TLS_MODULE_BASE_SYMBOL_NAME),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(TBSS_SECTION_NAME),
        ty: sht::NOBITS,
        section_flags: shf::WRITE.with(shf::ALLOC).with(shf::TLS),
        end_symbol_name: Some(TLS_MODULE_BASE_SYMBOL_NAME),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(BSS_SECTION_NAME),
        ty: sht::NOBITS,
        section_flags: shf::ALLOC.with(shf::WRITE),
        end_symbol_name: Some("_end"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(COMMENT_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::STRINGS.with(shf::MERGE).with(shf::GNU_RETAIN),
        element_size: 1,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(GCC_EXCEPT_TABLE_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(NOTE_ABI_TAG_SECTION_NAME),
        ty: sht::NOTE,
        section_flags: shf::ALLOC.with(shf::GNU_RETAIN),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        name: SectionName(DATA_REL_RO_SECTION_NAME),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC.with(shf::WRITE),
        ..DEFAULT_DEFS
    },
];

pub(crate) fn built_in_section_ids()
-> impl ExactSizeIterator<Item = OutputSectionId> + DoubleEndedIterator<Item = OutputSectionId> {
    (0..NUM_BUILT_IN_SECTIONS).map(|n| OutputSectionId(n as u32))
}

impl OutputSectionId {
    pub(crate) const fn regular(offset: u32) -> OutputSectionId {
        OutputSectionId(NUM_NON_REGULAR_SECTIONS + offset)
    }

    pub(crate) fn as_usize(self) -> usize {
        self.0 as usize
    }

    pub(crate) const fn from_u32(raw: u32) -> Self {
        Self(raw)
    }

    pub(crate) fn from_usize(value: usize) -> Self {
        Self(value as u32)
    }

    pub(crate) fn num_parts(self) -> usize {
        if self.0 < part_id::NUM_SINGLE_PART_SECTIONS {
            1
        } else if self.0 < NUM_NON_REGULAR_SECTIONS {
            part_id::NUM_PARTS_PER_TWO_PART_SECTION as usize
        } else {
            NUM_ALIGNMENTS
        }
    }

    pub(crate) fn built_in_details(self) -> &'static BuiltInSectionDetails {
        &SECTION_DEFINITIONS[self.as_usize()]
    }

    pub(crate) fn opt_built_in_details(self) -> Option<&'static BuiltInSectionDetails> {
        SECTION_DEFINITIONS.get(self.as_usize())
    }

    fn event(self) -> OrderEvent {
        OrderEvent::Section(self)
    }

    pub(crate) fn min_alignment(self) -> Alignment {
        SECTION_DEFINITIONS
            .get(self.as_usize())
            .map_or(alignment::MIN, |d| d.min_alignment)
    }

    pub(crate) fn is_regular(self) -> bool {
        self.0 >= NUM_NON_REGULAR_SECTIONS
    }

    /// Returns the part ID in this section that has the specified alignment. Can only be called for
    /// regular sections.
    pub(crate) const fn part_id_with_alignment(self, alignment: Alignment) -> PartId {
        let Some(regular_offset) = self.0.checked_sub(NUM_NON_REGULAR_SECTIONS) else {
            panic!("part_id_with_alignment can only be called for regular sections");
        };
        PartId::from_u32(
            part_id::REGULAR_PART_BASE
                + (regular_offset * NUM_ALIGNMENTS as u32)
                + NUM_ALIGNMENTS as u32
                - 1
                - alignment.exponent as u32,
        )
    }

    /// Returns the first part ID for this section.
    pub(crate) fn base_part_id(self) -> PartId {
        if self.0 < NUM_SINGLE_PART_SECTIONS {
            PartId::from_u32(self.0)
        } else if let Some(offset) = self.0.checked_sub(NUM_NON_REGULAR_SECTIONS) {
            PartId::from_u32(REGULAR_PART_BASE + offset * NUM_ALIGNMENTS as u32)
        } else {
            PartId::from_u32(
                (self.0 - NUM_SINGLE_PART_SECTIONS) * NUM_PARTS_PER_TWO_PART_SECTION
                    + NUM_SINGLE_PART_SECTIONS,
            )
        }
    }

    pub(crate) fn info(self, inputs: &InfoInputs) -> u32 {
        self.opt_built_in_details()
            .and_then(|d| d.info_fn)
            .map_or(0, |info_fn| (info_fn)(inputs))
    }

    pub(crate) fn element_size(self) -> u64 {
        self.opt_built_in_details().map_or(0, |d| d.element_size)
    }
}

/// The bits of `Layout` that are needed for computing info fields.
pub(crate) struct InfoInputs<'layout> {
    pub(crate) section_part_layouts: &'layout OutputSectionPartMap<OutputRecordLayout>,
    pub(crate) non_addressable_counts: &'layout NonAddressableCounts,
    pub(crate) output_section_indexes: &'layout [Option<u16>],
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum OrderEvent {
    SegmentStart(ProgramSegmentId),
    SegmentEnd(ProgramSegmentId),
    Section(OutputSectionId),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SectionName<'data>(pub(crate) &'data [u8]);

impl SectionName<'_> {
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.0
    }
}

impl Debug for SectionName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", String::from_utf8_lossy(self.0)))
    }
}

pub(crate) struct OutputSectionsBuilder<'data> {
    base_address: u64,
    custom_by_name: AHashMap<SectionName<'data>, OutputSectionId>,
    // TODO: Change this to be an OutputSectionMap.
    section_infos: Vec<SectionOutputInfo<'data>>,
}

impl<'data> OutputSectionsBuilder<'data> {
    pub(crate) fn build(self) -> Result<OutputSections<'data>> {
        let mut custom = CustomSectionIds::default();

        for (offset, info) in self.section_infos[NUM_BUILT_IN_SECTIONS..]
            .iter()
            .enumerate()
        {
            let id = OutputSectionId::from_usize(NUM_BUILT_IN_SECTIONS + offset);
            if info.section_flags.contains(shf::EXECINSTR) {
                custom.exec.push(id);
            } else if !info.section_flags.contains(shf::WRITE) {
                if info.section_flags.contains(shf::ALLOC) {
                    custom.ro.push(id);
                } else {
                    custom.nonalloc.push(id);
                }
            } else if info.ty == sht::NOBITS {
                custom.bss.push(id);
            } else {
                custom.data.push(id);
            }
        }

        let mut output_sections = OutputSections {
            base_address: self.base_address,
            section_infos: self.section_infos,
            custom_by_name: self.custom_by_name,
            output_section_indexes: Default::default(),
            sections_and_segments_events: custom.sections_and_segments_events(),
        };

        output_sections.determine_loadable_segment_ids()?;

        Ok(output_sections)
    }

    pub(crate) fn add_sections(
        &mut self,
        custom_sections: &[CustomSectionDetails<'data>],
        sections: &mut [SectionSlot],
    ) {
        for custom in custom_sections {
            // Some flags, when set on the input section, don't propagate to the output section.
            let section_flags = custom.section_flags.without(shf::GROUP);

            let section_id = self.add_section(custom.name, section_flags, custom.ty);
            // Section flags are sometimes different, take the union of everything we're
            // given.
            self.section_infos[section_id.as_usize()].section_flags |= section_flags;

            if let Some(slot) = sections.get_mut(custom.index.0) {
                slot.set_part_id(section_id.part_id_with_alignment(custom.alignment));
            }
        }
    }

    pub(crate) fn add_section(
        &mut self,
        name: SectionName<'data>,
        section_flags: SectionFlags,
        section_type: SectionType,
    ) -> OutputSectionId {
        *self.custom_by_name.entry(name).or_insert_with(|| {
            let id = OutputSectionId::from_usize(self.section_infos.len());
            self.section_infos.push(SectionOutputInfo {
                section_flags,
                name,
                // We'll fill this in properly in `determine_loadable_segment_ids`.
                loadable_segment_id: None,
                ty: section_type,
            });
            id
        })
    }

    pub(crate) fn with_base_address(base_address: u64) -> Self {
        let section_infos = SECTION_DEFINITIONS
            .iter()
            .map(|d| SectionOutputInfo {
                section_flags: d.section_flags,
                name: d.name,
                loadable_segment_id: Some(crate::program_segments::LOAD_RO),
                ty: d.ty,
            })
            .collect();
        Self {
            section_infos,
            base_address,
            custom_by_name: AHashMap::new(),
        }
    }
}

impl CustomSectionIds {
    /// Returns vector of events for each section and segment in output order.
    /// Segments span multiple sections and can overlap, so are represented as start and end events.
    fn sections_and_segments_events(&self) -> Vec<OrderEvent> {
        fn build_section_events(
            sections: &[OutputSectionId],
        ) -> impl Iterator<Item = OrderEvent> + '_ {
            sections.iter().copied().map(OrderEvent::Section)
        }

        let mut events = Vec::with_capacity(64);

        events.push(OrderEvent::SegmentStart(crate::program_segments::LOAD_RO));
        events.push(FILE_HEADER.event());
        events.push(OrderEvent::SegmentStart(crate::program_segments::PHDR));
        events.push(PROGRAM_HEADERS.event());
        events.push(OrderEvent::SegmentEnd(crate::program_segments::PHDR));
        events.push(SECTION_HEADERS.event());
        events.push(OrderEvent::SegmentStart(crate::program_segments::INTERP));
        events.push(INTERP.event());
        events.push(OrderEvent::SegmentEnd(crate::program_segments::INTERP));
        events.push(OrderEvent::SegmentStart(crate::program_segments::NOTE));
        events.push(NOTE_GNU_PROPERTY.event());
        events.push(NOTE_GNU_BUILD_ID.event());
        events.push(NOTE_ABI_TAG.event());
        events.push(OrderEvent::SegmentEnd(crate::program_segments::NOTE));
        events.push(GNU_HASH.event());
        events.push(DYNSYM.event());
        events.push(DYNSTR.event());
        events.push(GNU_VERSION.event());
        events.push(GNU_VERSION_R.event());
        events.push(RELA_DYN.event());
        events.push(RELA_PLT.event());
        events.push(RODATA.event());
        events.push(OrderEvent::SegmentStart(crate::program_segments::EH_FRAME));
        events.push(EH_FRAME_HDR.event());
        events.push(OrderEvent::SegmentEnd(crate::program_segments::EH_FRAME));
        events.push(EH_FRAME.event());
        events.push(PREINIT_ARRAY.event());
        events.push(GCC_EXCEPT_TABLE.event());
        events.extend(build_section_events(&self.ro));
        events.push(OrderEvent::SegmentEnd(crate::program_segments::LOAD_RO));

        events.push(OrderEvent::SegmentStart(crate::program_segments::LOAD_EXEC));
        events.push(PLT_GOT.event());
        events.push(TEXT.event());
        events.push(INIT.event());
        events.push(FINI.event());
        events.extend(build_section_events(&self.exec));
        events.push(OrderEvent::SegmentEnd(crate::program_segments::LOAD_EXEC));

        events.push(OrderEvent::SegmentStart(crate::program_segments::LOAD_RW));
        events.push(OrderEvent::SegmentStart(crate::program_segments::RELRO));
        events.push(OrderEvent::SegmentStart(crate::program_segments::TLS));
        events.push(TDATA.event());
        events.push(TBSS.event());
        events.push(OrderEvent::SegmentEnd(crate::program_segments::TLS));
        events.push(INIT_ARRAY.event());
        events.push(FINI_ARRAY.event());
        events.push(DATA_REL_RO.event());
        events.push(OrderEvent::SegmentStart(crate::program_segments::DYNAMIC));
        events.push(DYNAMIC.event());
        events.push(OrderEvent::SegmentEnd(crate::program_segments::DYNAMIC));
        events.push(GOT.event());
        events.push(OrderEvent::SegmentEnd(crate::program_segments::RELRO));
        events.push(DATA.event());
        events.extend(build_section_events(&self.data));
        events.push(BSS.event());
        events.extend(build_section_events(&self.bss));
        events.push(OrderEvent::SegmentEnd(crate::program_segments::LOAD_RW));

        events.push(OrderEvent::SegmentStart(crate::program_segments::STACK));
        events.push(OrderEvent::SegmentEnd(crate::program_segments::STACK));

        events.extend(build_section_events(&self.nonalloc));
        events.push(COMMENT.event());
        events.push(SHSTRTAB.event());
        events.push(SYMTAB.event());
        events.push(STRTAB.event());

        events
    }
}

impl<'data> OutputSections<'data> {
    /// Returns an iterator of events for each section and segment in output order. Segments span
    /// multiple sections and can overlap, so are represented as start and end events.
    pub(crate) fn sections_and_segments_events(&self) -> impl Iterator<Item = OrderEvent> + '_ {
        self.sections_and_segments_events.iter().copied()
    }

    #[must_use]
    pub(crate) fn num_sections(&self) -> usize {
        self.section_infos.len()
    }

    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn num_regular_sections(&self) -> usize {
        self.section_infos.len() - NUM_NON_REGULAR_SECTIONS as usize
    }

    pub(crate) fn has_data_in_file(&self, section_id: OutputSectionId) -> bool {
        // Note, we treat TBSS as having data in the file, even though it's a NOBITS section. This
        // allows us to more easily place TBSS before other PROGBITS sections. Effectively TBSS is
        // NOBITS, but we put zero padding of the same size in the file. GNU ld doesn't do this. It
        // instead puts TBSS and the subsequent section at the same address.
        self.output_info(section_id).ty != sht::NOBITS
            || section_id == crate::output_section_id::TBSS
    }

    pub(crate) fn output_info(&self, id: OutputSectionId) -> &SectionOutputInfo<'data> {
        &self.section_infos[id.as_usize()]
    }

    /// Returns the output index of the built-in-section `id` or None if the section isn't being
    /// output.
    pub(crate) fn output_index_of_section(&self, id: OutputSectionId) -> Option<u16> {
        self.output_section_indexes
            .get(id.as_usize())
            .copied()
            .flatten()
    }

    /// Returns whether we're going to emit the specified section.
    pub(crate) fn will_emit_section(&self, id: OutputSectionId) -> bool {
        self.output_index_of_section(id).is_some()
    }

    pub(crate) fn loadable_segment_id_for(&self, id: OutputSectionId) -> Option<ProgramSegmentId> {
        self.output_info(id).loadable_segment_id
    }

    pub(crate) fn name(&self, section_id: OutputSectionId) -> SectionName<'data> {
        self.output_info(section_id).name
    }

    pub(crate) fn display_name(&self, section_id: OutputSectionId) -> std::borrow::Cow<str> {
        String::from_utf8_lossy(self.name(section_id).0)
    }

    pub(crate) fn custom_name_to_id(&self, name: SectionName) -> Option<OutputSectionId> {
        self.custom_by_name.get(&name).copied()
    }

    #[cfg(test)]
    pub(crate) fn for_testing() -> OutputSections<'static> {
        let mut builder = OutputSectionsBuilder::with_base_address(0x1000);
        builder.add_section(SectionName(b"ro"), shf::GNU_RETAIN, sht::PROGBITS);
        builder.add_section(SectionName(b"exec"), shf::EXECINSTR, sht::PROGBITS);
        builder.add_section(SectionName(b"data"), shf::WRITE, sht::PROGBITS);
        builder.add_section(SectionName(b"bss"), shf::WRITE, sht::NOBITS);
        builder.build().unwrap()
    }
}

pub(crate) fn link_ids(section_id: OutputSectionId) -> &'static [OutputSectionId] {
    SECTION_DEFINITIONS
        .get(section_id.as_usize())
        .map(|def| def.link)
        .unwrap_or_default()
}

impl Display for SectionName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.0))
    }
}

fn symtab_info(info: &InfoInputs) -> u32 {
    // For SYMTAB, the info field holds the index of the first non-local symbol.
    (info
        .section_part_layouts
        .get(part_id::SYMTAB_LOCAL)
        .file_size
        / size_of::<elf::SymtabEntry>()) as u32
}

fn version_r_info(info: &InfoInputs) -> u32 {
    info.non_addressable_counts.verneed_count as u32
}

fn dynsym_info(_info: &InfoInputs) -> u32 {
    // The only local we ever write to .dynsym is the null symbol, so this is unconditionally 1.
    1
}

fn rela_plt_info(info: &InfoInputs) -> u32 {
    // .rela.plt contains relocations for .got, so should link to it.
    u32::from(info.output_section_indexes[GOT.0 as usize].unwrap_or(0))
}

impl std::fmt::Display for OutputSectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.as_usize(), f)
    }
}

/// Verifies that our constants for section IDs match their respective offsets in
/// `SECTION_DEFINITIONS`.
#[test]
fn test_constant_ids() {
    let check = &[
        (FILE_HEADER, FILEHEADER_SECTION_NAME),
        (RODATA, RODATA_SECTION_NAME),
        (TEXT, TEXT_SECTION_NAME),
        (INIT_ARRAY, INIT_ARRAY_SECTION_NAME),
        (FINI_ARRAY, FINI_ARRAY_SECTION_NAME),
        (PREINIT_ARRAY, PREINIT_ARRAY_SECTION_NAME),
        (DATA, DATA_SECTION_NAME),
        (EH_FRAME, EH_FRAME_SECTION_NAME),
        (EH_FRAME_HDR, EH_FRAME_HDR_SECTION_NAME),
        (SHSTRTAB, SHSTRTAB_SECTION_NAME),
        (SYMTAB, SYMTAB_SECTION_NAME),
        (STRTAB, STRTAB_SECTION_NAME),
        (TDATA, TDATA_SECTION_NAME),
        (TBSS, TBSS_SECTION_NAME),
        (BSS, BSS_SECTION_NAME),
        (GOT, GOT_SECTION_NAME),
        (INIT, INIT_SECTION_NAME),
        (FINI, FINI_SECTION_NAME),
        (RELA_PLT, RELA_PLT_SECTION_NAME),
        (COMMENT, COMMENT_SECTION_NAME),
        (DYNAMIC, DYNAMIC_SECTION_NAME),
        (DYNSYM, DYNSYM_SECTION_NAME),
        (DYNSTR, DYNSTR_SECTION_NAME),
        (RELA_DYN, RELA_DYN_SECTION_NAME),
        (GCC_EXCEPT_TABLE, GCC_EXCEPT_TABLE_SECTION_NAME),
        (INTERP, INTERP_SECTION_NAME),
        (GNU_VERSION, GNU_VERSION_SECTION_NAME),
        (GNU_VERSION_R, GNU_VERSION_R_SECTION_NAME),
        (PROGRAM_HEADERS, PROGRAM_HEADERS_SECTION_NAME),
        (SECTION_HEADERS, SECTION_HEADERS_SECTION_NAME),
        (GNU_HASH, GNU_HASH_SECTION_NAME),
        (PLT_GOT, PLT_GOT_SECTION_NAME),
        (NOTE_ABI_TAG, NOTE_ABI_TAG_SECTION_NAME),
        (NOTE_GNU_PROPERTY, NOTE_GNU_PROPERTY_SECTION_NAME),
        (NOTE_GNU_BUILD_ID, NOTE_GNU_BUILD_ID_SECTION_NAME),
        (DATA_REL_RO, DATA_REL_RO_SECTION_NAME),
    ];
    for (id, name) in check {
        assert_eq!(id.built_in_details().name.bytes(), *name);
    }
    assert_eq!(NUM_BUILT_IN_SECTIONS, check.len());
}
