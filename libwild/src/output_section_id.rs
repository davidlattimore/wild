//! Instructions for adding a new generated, single-part output section:
//!
//! * Add a new constant `PartId` to `part_id.rs`.
//! * Update `NUM_SINGLE_PART_SECTIONS` in `part_id.rs`.
//! * Define a constant `OutputSectionId` below.
//! * Add the section definition info to `SECTION_DEFINITIONS`, most likely inserting it just before
//!   the multi-part sections.
//! * Add the section to `test_constant_ids` to make sure the ID is consistent with its position in
//!   `SECTION_DEFINITIONS`.
//! * Insert the new section into the output order in `sections_and_segments_events`. The position
//!   needs to be consistent with the access flags on the section. e.g. if the section is read-only
//!   data, it should go between the start and end of the read-only segment.
//!
//! Adding a new alignment-base (regular) section is similar to the above, but skip the steps
//! related to `part_id.rs` and insert later in `SECTION_DEFINITIONS` (probably at the end). Also,
//! update `NUM_BUILT_IN_REGULAR_SECTIONS`.

use crate::alignment;
use crate::alignment::Alignment;
use crate::alignment::NUM_ALIGNMENTS;
use crate::args::Args;
use crate::elf;
use crate::elf::DynamicEntry;
use crate::elf::GLOBAL_POINTER_SYMBOL_NAME;
use crate::elf::Versym;
use crate::layout::NonAddressableCounts;
use crate::layout::OutputRecordLayout;
use crate::layout_rules::SectionKind;
use crate::linker_script;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::part_id;
use crate::part_id::NUM_SINGLE_PART_SECTIONS;
use crate::part_id::PartId;
use crate::program_segments::PROGRAM_SEGMENT_DEFS;
use crate::program_segments::ProgramSegmentDef;
use crate::program_segments::ProgramSegmentId;
use crate::program_segments::ProgramSegments;
use crate::program_segments::STACK_SEGMENT_DEF;
use crate::resolution::SectionSlot;
use crate::timing_phase;
use core::slice;
use hashbrown::HashMap;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::SectionType;
use linker_utils::elf::SegmentType;
use linker_utils::elf::pt;
#[allow(clippy::wildcard_imports)]
use linker_utils::elf::secnames::*;
use linker_utils::elf::shf;
use linker_utils::elf::sht;
use std::fmt::Debug;
use std::fmt::Display;
use std::iter::Copied;
use std::ops::Range;

/// Number of sections that we have built-in IDs for.
pub(crate) const NUM_BUILT_IN_SECTIONS: usize =
    part_id::NUM_SINGLE_PART_SECTIONS as usize + NUM_BUILT_IN_REGULAR_SECTIONS;

/// An ID for an output section. This is used for looking up section info. It's independent of
/// section ordering.
#[derive(Clone, Copy, PartialEq, Eq, Hash, derive_more::Debug)]
#[debug("osid-{_0}")]
pub(crate) struct OutputSectionId(u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CustomSectionDetails<'data> {
    pub(crate) name: SectionName<'data>,
    pub(crate) index: object::SectionIndex,
    pub(crate) alignment: Alignment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InitFiniSectionDetail {
    pub(crate) index: u32,
    pub(crate) primary: OutputSectionId,
    pub(crate) priority: u16,
    pub(crate) alignment: Alignment,
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
pub(crate) const SFRAME: OutputSectionId = part_id::SFRAME.output_section_id();
pub(crate) const DYNAMIC: OutputSectionId = part_id::DYNAMIC.output_section_id();
pub(crate) const HASH: OutputSectionId = part_id::SYSV_HASH.output_section_id();
pub(crate) const GNU_HASH: OutputSectionId = part_id::GNU_HASH.output_section_id();
pub(crate) const DYNSYM: OutputSectionId = part_id::DYNSYM.output_section_id();
pub(crate) const DYNSTR: OutputSectionId = part_id::DYNSTR.output_section_id();
pub(crate) const INTERP: OutputSectionId = part_id::INTERP.output_section_id();
pub(crate) const GNU_VERSION: OutputSectionId = part_id::GNU_VERSION.output_section_id();
pub(crate) const GNU_VERSION_D: OutputSectionId = part_id::GNU_VERSION_D.output_section_id();
pub(crate) const GNU_VERSION_R: OutputSectionId = part_id::GNU_VERSION_R.output_section_id();
pub(crate) const PLT_GOT: OutputSectionId = part_id::PLT_GOT.output_section_id();
pub(crate) const NOTE_GNU_PROPERTY: OutputSectionId =
    part_id::NOTE_GNU_PROPERTY.output_section_id();
pub(crate) const NOTE_GNU_BUILD_ID: OutputSectionId =
    part_id::NOTE_GNU_BUILD_ID.output_section_id();

pub(crate) const SYMTAB_LOCAL: OutputSectionId = part_id::SYMTAB_LOCAL.output_section_id();
#[allow(dead_code)]
pub(crate) const SYMTAB_GLOBAL: OutputSectionId = part_id::SYMTAB_GLOBAL.output_section_id();
pub(crate) const RELA_DYN_RELATIVE: OutputSectionId =
    part_id::RELA_DYN_RELATIVE.output_section_id();
pub(crate) const RELA_DYN_GENERAL: OutputSectionId = part_id::RELA_DYN_GENERAL.output_section_id();
pub(crate) const RISCV_ATTRIBUTES: OutputSectionId = part_id::RISCV_ATTRIBUTES.output_section_id();
pub(crate) const RELRO_PADDING: OutputSectionId = part_id::RELRO_PADDING.output_section_id();

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

#[derive(Debug)]
pub(crate) struct OutputSections<'data> {
    /// The base address for our output binary.
    pub(crate) base_address: u64,
    pub(crate) section_infos: OutputSectionMap<SectionOutputInfo<'data>>,

    // TODO: Consider moving this to Layout. We can't populate this until we know which output
    // sections have content, which we don't know until half way through the layout phase.
    /// Mapping from internal section IDs to output section indexes. None, if the section isn't
    /// being output.
    pub(crate) output_section_indexes: Vec<Option<u16>>,

    custom_by_name: HashMap<SectionName<'data>, OutputSectionId>,

    init_fini_by_priority: HashMap<(OutputSectionId, u16), OutputSectionId>,
}

/// Encodes the order of output sections and the start and end of each program segment. This struct
/// is intended to be used by iterating over it.
#[derive(Debug)]
pub(crate) struct OutputOrder {
    events: Vec<OrderEvent>,
}

pub(crate) struct OutputOrderDisplay<'a, 'data> {
    order: &'a OutputOrder,
    sections: &'a OutputSections<'data>,
    program_segments: &'a ProgramSegments,
}

struct OutputOrderBuilder<'scope, 'data> {
    events: Vec<OrderEvent>,

    program_segments: ProgramSegments,

    /// Indexes correspond to elements of `PROGRAM_SEGMENT_DEFS`.
    active_segment_kinds: Vec<Option<ProgramSegmentId>>,

    output_sections: &'scope OutputSections<'data>,
    secondary: &'scope OutputSectionMap<Vec<OutputSectionId>>,
}

impl<'scope, 'data> OutputOrderBuilder<'scope, 'data> {
    fn new(
        output_sections: &'scope OutputSections<'data>,
        secondary: &'scope OutputSectionMap<Vec<OutputSectionId>>,
    ) -> Self {
        Self {
            events: Vec::new(),
            program_segments: ProgramSegments::empty(),
            output_sections,
            active_segment_kinds: vec![None; PROGRAM_SEGMENT_DEFS.len()],
            secondary,
        }
    }

    fn add_section(&mut self, section_id: OutputSectionId) {
        // When RELRO segment ends, also end the RW LOAD segment so that subsequent non-RELRO
        // sections go into a new LOAD segment.
        if self.relro_segment_will_end(section_id) {
            self.end_rw_load_segment();
        }

        let (stop, start) = self.start_stop_segments_for_section(section_id);

        for segment_id in stop {
            self.events.push(OrderEvent::SegmentEnd(segment_id));
        }

        let section_info = self.output_sections.output_info(section_id);
        debug_assert!(
            matches!(section_info.kind, SectionKind::Primary(_)),
            "Attempted to directly emit secondary section {section_id}"
        );

        // Only emit SetLocation if the section has ALLOC flag, meaning it can be placed
        // in a segment. Sections without ALLOC (like custom sections before their flags
        // are propagated) will have their location handled directly in layout_section_parts
        // via section_info.location.
        if let Some(location) = section_info.location
            && section_info.section_flags.contains(shf::ALLOC)
        {
            self.events.push(OrderEvent::SetLocation(location));
        }

        for segment_id in start {
            self.events.push(OrderEvent::SegmentStart(segment_id));
        }

        self.events.push(OrderEvent::Section(section_id));

        let secondaries: &Vec<OutputSectionId> = self.secondary.get(section_id);
        // stable ordering: tie-break by original index
        let mut keyed: Vec<(u16, OutputSectionId)> = secondaries
            .iter()
            .map(|&sid| {
                // default: put non-initfini after all initfini, and keep their relative order
                let key_pri = match self.output_sections.secondary_order(sid) {
                    Some(crate::output_section_id::SecondaryOrder::InitFini { priority }) => {
                        priority
                    }
                    None => u16::MAX,
                };
                (key_pri, sid)
            })
            .collect();
        keyed.sort_by_key(|(pri, _sid)| *pri);

        for (_pri, sid) in keyed {
            self.events.push(OrderEvent::Section(sid));
        }
    }

    /// Returns true if processing the given section will cause the RELRO segment to end.
    fn relro_segment_will_end(&self, section_id: OutputSectionId) -> bool {
        self.active_segment_kinds
            .iter()
            .zip(PROGRAM_SEGMENT_DEFS)
            .any(|(id, def)| {
                id.is_some()
                    && def.segment_type == pt::GNU_RELRO
                    && !self
                        .output_sections
                        .should_include_in_segment(section_id, *def)
            })
    }

    /// Ends the currently active RW LOAD segment, if any. This is used when the RELRO segment
    /// ends to force .data and other non-RELRO sections into a new LOAD segment.
    fn end_rw_load_segment(&mut self) {
        let rw_load_def_index = PROGRAM_SEGMENT_DEFS.iter().position(|def| {
            def.segment_type == pt::LOAD && def.is_writable() && !def.is_executable()
        });

        if let Some(def_index) = rw_load_def_index
            && let Some(segment_id) = self.active_segment_kinds[def_index].take()
        {
            self.events.push(OrderEvent::SegmentEnd(segment_id));
        }
    }

    /// Returns whatever `SegmentStart` and/or `SegmentEnd` events are necessary prior to the start
    /// of `section_id`. We add segment start/stop events based on the properties of the section
    /// we're about to begin. For example, if the there's a TLS segment active, but the incoming
    /// section doesn't have the TLS flag set, then we need to end the TLS segment. Similarly, if a
    /// read-only LOAD segment is active and we're about to start a section that needs to be
    /// writable, then we'll need to end the current LOAD segment and start a new writable one.
    fn start_stop_segments_for_section(
        &mut self,
        section_id: OutputSectionId,
    ) -> (Vec<ProgramSegmentId>, Vec<ProgramSegmentId>) {
        let mut stop = Vec::new();
        let mut start = Vec::new();

        // Secondary sections don't begin or end segments.
        if self.output_sections.merge_target(section_id).is_some() {
            return (stop, start);
        }

        let section_info = self.output_sections.output_info(section_id);
        if section_info.location.is_some() {
            // If we're setting the location, then first end all active segments.
            for id in &mut self.active_segment_kinds {
                if let Some(id) = id.take() {
                    stop.push(id);
                }
            }
        }

        PROGRAM_SEGMENT_DEFS
            .iter()
            .zip(self.active_segment_kinds.iter_mut())
            .for_each(|(segment_def, active_id)| {
                let should_be_active = self
                    .output_sections
                    .should_include_in_segment(section_id, *segment_def);

                match (active_id.as_ref().copied(), should_be_active) {
                    // Remain inactive
                    (None, false) => {}

                    // Remain active
                    (Some(_), true) => {}

                    // Start segment
                    (None, true) => {
                        let segment_id = self.program_segments.add_segment(*segment_def);
                        start.push(segment_id);
                        *active_id = Some(segment_id);
                    }

                    // End segment
                    (Some(segment_id), false) => {
                        stop.push(segment_id);
                        *active_id = None;
                    }
                }
            });

        (stop, start)
    }

    fn add_sections(&mut self, sections: &[OutputSectionId]) {
        for section in sections {
            self.add_section(*section);
        }
    }

    fn build(mut self) -> (OutputOrder, ProgramSegments) {
        for segment_id in self.active_segment_kinds.into_iter().flatten() {
            self.events.push(OrderEvent::SegmentEnd(segment_id));
        }

        let segment_id = self.program_segments.add_segment(STACK_SEGMENT_DEF);
        self.events.push(OrderEvent::SegmentStart(segment_id));
        self.events.push(OrderEvent::SegmentEnd(segment_id));

        (
            OutputOrder {
                events: self.events,
            },
            self.program_segments,
        )
    }
}

#[derive(Default)]
struct CustomSectionIds {
    ro: Vec<OutputSectionId>,
    exec: Vec<OutputSectionId>,
    data: Vec<OutputSectionId>,
    bss: Vec<OutputSectionId>,
    nonalloc: Vec<OutputSectionId>,
    tdata: Vec<OutputSectionId>,
    tbss: Vec<OutputSectionId>,
}

impl<'data> OutputSections<'data> {
    /// Returns an iterator that emits all section IDs and their info.
    pub(crate) fn ids_with_info(
        &self,
    ) -> impl Iterator<Item = (OutputSectionId, &SectionOutputInfo<'data>)> {
        self.section_infos.iter()
    }

    pub(crate) fn num_parts(&self) -> usize {
        part_id::NUM_SINGLE_PART_SECTIONS as usize
            + (self.num_sections() - part_id::NUM_SINGLE_PART_SECTIONS as usize) * NUM_ALIGNMENTS
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

    pub(crate) fn section_flags(&self, section_id: OutputSectionId) -> SectionFlags {
        self.output_info(section_id).section_flags
    }

    /// Returns the ID of the primary output section for the supplied section ID.
    pub(crate) fn primary_output_section(&self, section_id: OutputSectionId) -> OutputSectionId {
        self.merge_target(section_id).unwrap_or(section_id)
    }

    /// Returns the ID of the section that the specified section should be merged into, if any, or
    /// None if the supplied section is itself a primary section.
    pub(crate) fn merge_target(&self, section_id: OutputSectionId) -> Option<OutputSectionId> {
        match self.output_info(section_id).kind {
            SectionKind::Primary(_) => None,
            SectionKind::Secondary(primary_id) => Some(primary_id),
        }
    }

    /// Returns whether we should include the specified section in a program segment with the
    /// supplied properties.
    fn should_include_in_segment(
        &self,
        section_id: OutputSectionId,
        segment_def: ProgramSegmentDef,
    ) -> bool {
        let info = self.output_info(section_id);

        match segment_def.segment_type {
            pt::NOTE => info.ty == sht::NOTE,
            pt::TLS => info.section_flags.contains(shf::TLS),
            pt::LOAD => {
                info.section_flags.contains(shf::ALLOC)
                    && info.section_flags.contains(shf::WRITE) == segment_def.is_writable()
                    && info.section_flags.contains(shf::EXECINSTR) == segment_def.is_executable()
            }
            pt::GNU_RELRO => {
                info.section_flags.contains(shf::TLS)
                    || section_id
                        .opt_built_in_details()
                        .is_some_and(|details| details.is_relro)
            }
            other => section_id
                .opt_built_in_details()
                .and_then(|details| details.target_segment_type)
                .is_some_and(|target_segment_type| target_segment_type == other),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SectionOutputInfo<'data> {
    pub(crate) kind: SectionKind<'data>,
    pub(crate) section_flags: SectionFlags,
    pub(crate) ty: SectionType,
    pub(crate) min_alignment: Alignment,
    pub(crate) entsize: u64,
    pub(crate) location: Option<linker_script::Location>,
    pub(crate) secondary_order: Option<SecondaryOrder>,
}

pub(crate) struct BuiltInSectionDetails {
    pub(crate) kind: SectionKind<'static>,
    pub(crate) section_flags: SectionFlags,
    /// Sections to try to link to. The first section that we're outputting is the one used.
    pub(crate) link: &'static [OutputSectionId],
    pub(crate) start_symbol_name: Option<&'static str>,
    pub(crate) end_symbol_name: Option<&'static str>,
    pub(crate) group_end_symbol_name: Option<&'static str>,
    pub(crate) min_alignment: Alignment,
    info_fn: Option<fn(&InfoInputs) -> u32>,
    pub(crate) keep_if_empty: bool,
    pub(crate) mark_zero_sized_input_as_content: bool,
    pub(crate) element_size: u64,
    pub(crate) ty: SectionType,
    is_relro: bool,
    target_segment_type: Option<SegmentType>,
}

const DEFAULT_DEFS: BuiltInSectionDetails = BuiltInSectionDetails {
    kind: SectionKind::Primary(SectionName(&[])),
    section_flags: SectionFlags::empty(),
    link: &[],
    start_symbol_name: None,
    end_symbol_name: None,
    group_end_symbol_name: None,
    min_alignment: alignment::MIN,
    info_fn: None,
    keep_if_empty: false,
    mark_zero_sized_input_as_content: true,
    element_size: 0,
    ty: sht::NULL,
    is_relro: false,
    target_segment_type: None,
};

const SECTION_DEFINITIONS: [BuiltInSectionDetails; NUM_BUILT_IN_SECTIONS] = [
    // A section into which we write headers.
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"")),
        section_flags: shf::ALLOC,
        start_symbol_name: Some("__ehdr_start"),
        keep_if_empty: true,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(PROGRAM_HEADERS_SECTION_NAME)),
        section_flags: shf::ALLOC,
        min_alignment: alignment::PROGRAM_HEADER_ENTRY,
        keep_if_empty: true,
        target_segment_type: Some(pt::PHDR),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(SECTION_HEADERS_SECTION_NAME)),
        section_flags: shf::ALLOC,
        keep_if_empty: true,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(SHSTRTAB_SECTION_NAME)),
        ty: sht::STRTAB,
        keep_if_empty: true,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(STRTAB_SECTION_NAME)),
        ty: sht::STRTAB,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(GOT_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::WRITE.with(shf::ALLOC),
        element_size: crate::elf::GOT_ENTRY_SIZE,
        min_alignment: alignment::GOT_ENTRY,
        start_symbol_name: Some("_GLOBAL_OFFSET_TABLE_"),
        is_relro: true,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(PLT_GOT_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC.with(shf::EXECINSTR),
        element_size: crate::elf::PLT_ENTRY_SIZE,
        min_alignment: alignment::PLT,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(RELA_PLT_SECTION_NAME)),
        ty: sht::RELA,
        section_flags: shf::ALLOC.with(shf::INFO_LINK),
        element_size: elf::RELA_ENTRY_SIZE,
        link: &[DYNSYM, SYMTAB_LOCAL],
        min_alignment: alignment::RELA_ENTRY,
        start_symbol_name: Some("__rela_iplt_start"),
        end_symbol_name: Some("__rela_iplt_end"),
        info_fn: Some(rela_plt_info),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(EH_FRAME_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC,
        min_alignment: alignment::USIZE,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(EH_FRAME_HDR_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC,
        min_alignment: alignment::EH_FRAME_HDR,
        target_segment_type: Some(pt::GNU_EH_FRAME),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(SFRAME_SECTION_NAME)),
        ty: sht::GNU_SFRAME,
        section_flags: shf::ALLOC,
        min_alignment: alignment::USIZE,
        target_segment_type: Some(pt::GNU_SFRAME),
        mark_zero_sized_input_as_content: false,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(DYNAMIC_SECTION_NAME)),
        ty: sht::DYNAMIC,
        section_flags: shf::ALLOC.with(shf::WRITE),
        element_size: size_of::<DynamicEntry>() as u64,
        link: &[DYNSTR],
        min_alignment: alignment::USIZE,
        start_symbol_name: Some("_DYNAMIC"),
        is_relro: true,
        target_segment_type: Some(pt::DYNAMIC),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(HASH_SECTION_NAME)),
        ty: sht::HASH,
        section_flags: shf::ALLOC,
        link: &[DYNSYM],
        min_alignment: alignment::SYSV_HASH,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(GNU_HASH_SECTION_NAME)),
        ty: sht::GNU_HASH,
        section_flags: shf::ALLOC,
        link: &[DYNSYM],
        min_alignment: alignment::GNU_HASH,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(DYNSYM_SECTION_NAME)),
        ty: sht::DYNSYM,
        section_flags: shf::ALLOC,
        element_size: size_of::<elf::SymtabEntry>() as u64,
        link: &[DYNSTR],
        min_alignment: alignment::SYMTAB_ENTRY,
        info_fn: Some(dynsym_info),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(DYNSTR_SECTION_NAME)),
        ty: sht::STRTAB,
        section_flags: shf::ALLOC,
        min_alignment: alignment::MIN,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(INTERP_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC,
        target_segment_type: Some(pt::INTERP),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(GNU_VERSION_SECTION_NAME)),
        ty: sht::GNU_VERSYM,
        section_flags: shf::ALLOC,
        element_size: size_of::<Versym>() as u64,
        min_alignment: alignment::VERSYM,
        link: &[DYNSYM],
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(GNU_VERSION_D_SECTION_NAME)),
        ty: sht::GNU_VERDEF,
        section_flags: shf::ALLOC,
        info_fn: Some(version_d_info),
        min_alignment: alignment::VERSION_D,
        link: &[DYNSTR],
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(GNU_VERSION_R_SECTION_NAME)),
        ty: sht::GNU_VERNEED,
        section_flags: shf::ALLOC,
        info_fn: Some(version_r_info),
        min_alignment: alignment::VERSION_R,
        link: &[DYNSTR],
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(NOTE_GNU_PROPERTY_SECTION_NAME)),
        ty: sht::NOTE,
        section_flags: shf::ALLOC,
        min_alignment: alignment::NOTE_GNU_PROPERTY,
        target_segment_type: Some(pt::GNU_PROPERTY),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(NOTE_GNU_BUILD_ID_SECTION_NAME)),
        ty: sht::NOTE,
        section_flags: shf::ALLOC,
        min_alignment: alignment::NOTE_GNU_BUILD_ID,
        ..DEFAULT_DEFS
    },
    // Multi-part generated sections
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(SYMTAB_SECTION_NAME)),
        ty: sht::SYMTAB,
        element_size: size_of::<elf::SymtabEntry>() as u64,
        min_alignment: alignment::SYMTAB_ENTRY,
        link: &[STRTAB],
        info_fn: Some(symtab_info),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Secondary(SYMTAB_LOCAL),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(RELA_DYN_SECTION_NAME)),
        ty: sht::RELA,
        section_flags: shf::ALLOC,
        element_size: elf::RELA_ENTRY_SIZE,
        min_alignment: alignment::RELA_ENTRY,
        link: &[DYNSYM],
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Secondary(RELA_DYN_RELATIVE),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(RISCV_ATTRIBUTES_SECTION_NAME)),
        ty: sht::RISCV_ATTRIBUTES,
        target_segment_type: Some(pt::RISCV_ATTRIBUTES),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(RELRO_PADDING_SECTION_NAME)),
        ty: sht::NOBITS,
        section_flags: shf::ALLOC.with(shf::WRITE),
        is_relro: true,
        keep_if_empty: true,
        ..DEFAULT_DEFS
    },
    // Start of regular sections
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(RODATA_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(INIT_ARRAY_SECTION_NAME)),
        ty: sht::INIT_ARRAY,
        section_flags: shf::ALLOC.with(shf::WRITE),
        element_size: size_of::<u64>() as u64,
        start_symbol_name: Some("__init_array_start"),
        group_end_symbol_name: Some("__init_array_end"),
        min_alignment: alignment::USIZE,
        is_relro: true,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(FINI_ARRAY_SECTION_NAME)),
        ty: sht::FINI_ARRAY,
        section_flags: shf::ALLOC.with(shf::WRITE),
        element_size: size_of::<u64>() as u64,
        start_symbol_name: Some("__fini_array_start"),
        group_end_symbol_name: Some("__fini_array_end"),
        min_alignment: alignment::USIZE,
        is_relro: true,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(PREINIT_ARRAY_SECTION_NAME)),
        ty: sht::PREINIT_ARRAY,
        section_flags: shf::ALLOC.with(shf::WRITE),
        start_symbol_name: Some("__preinit_array_start"),
        end_symbol_name: Some("__preinit_array_end"),
        is_relro: true,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(TEXT_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC.with(shf::EXECINSTR),
        end_symbol_name: Some("_etext"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(INIT_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC.with(shf::EXECINSTR),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(FINI_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC.with(shf::EXECINSTR),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(DATA_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC.with(shf::WRITE),
        // TODO: define the symbol only on RISC-V target
        start_symbol_name: Some(GLOBAL_POINTER_SYMBOL_NAME),
        end_symbol_name: Some("_edata"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(TDATA_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::WRITE.with(shf::ALLOC).with(shf::TLS),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(TBSS_SECTION_NAME)),
        ty: sht::NOBITS,
        section_flags: shf::WRITE.with(shf::ALLOC).with(shf::TLS),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(BSS_SECTION_NAME)),
        ty: sht::NOBITS,
        section_flags: shf::ALLOC.with(shf::WRITE),
        end_symbol_name: Some("_end"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(COMMENT_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::STRINGS.with(shf::MERGE),
        element_size: 1,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(GCC_EXCEPT_TABLE_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(NOTE_ABI_TAG_SECTION_NAME)),
        ty: sht::NOTE,
        section_flags: shf::ALLOC,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(DATA_REL_RO_SECTION_NAME)),
        ty: sht::PROGBITS,
        section_flags: shf::ALLOC.with(shf::WRITE),
        is_relro: true,
        ..DEFAULT_DEFS
    },
];

pub(crate) fn built_in_section_ids()
-> impl ExactSizeIterator<Item = OutputSectionId> + DoubleEndedIterator<Item = OutputSectionId> {
    (0..NUM_BUILT_IN_SECTIONS).map(|n| OutputSectionId(n as u32))
}

impl OutputSectionId {
    pub(crate) const fn regular(offset: u32) -> OutputSectionId {
        OutputSectionId(NUM_SINGLE_PART_SECTIONS + offset)
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

    pub(crate) fn part_id_range(self) -> Range<PartId> {
        let base = self.base_part_id();
        let count = self.num_parts();
        base..base.offset(count)
    }

    pub(crate) fn num_parts(self) -> usize {
        if self.0 < part_id::NUM_SINGLE_PART_SECTIONS {
            1
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

    pub(crate) fn min_alignment(self) -> Alignment {
        SECTION_DEFINITIONS
            .get(self.as_usize())
            .map_or(alignment::MIN, |d| d.min_alignment)
    }

    pub(crate) fn marks_zero_sized_inputs_as_content(self) -> bool {
        if let Some(details) = self.opt_built_in_details() {
            details.mark_zero_sized_input_as_content
        } else {
            true
        }
    }

    pub(crate) fn is_regular(self) -> bool {
        self.0 >= NUM_SINGLE_PART_SECTIONS
    }

    /// Returns the part ID in this section that has the specified alignment. Can only be called for
    /// regular sections.
    pub(crate) const fn part_id_with_alignment(self, alignment: Alignment) -> PartId {
        let Some(regular_offset) = self.0.checked_sub(NUM_SINGLE_PART_SECTIONS) else {
            panic!("part_id_with_alignment can only be called for regular sections");
        };
        PartId::from_u32(
            part_id::NUM_SINGLE_PART_SECTIONS
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
        } else {
            PartId::from_u32(
                NUM_SINGLE_PART_SECTIONS
                    + (self.0 - NUM_SINGLE_PART_SECTIONS) * NUM_ALIGNMENTS as u32,
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
    SetLocation(linker_script::Location),
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

#[derive(Debug, Clone, Copy)]
pub(crate) enum SecondaryOrder {
    InitFini { priority: u16 },
}

impl CustomSectionIds {
    fn build_output_order_and_program_segments(
        &self,
        output_sections: &OutputSections,
        secondary: &OutputSectionMap<Vec<OutputSectionId>>,
    ) -> (OutputOrder, ProgramSegments) {
        let mut builder = OutputOrderBuilder::new(output_sections, secondary);

        builder.add_section(FILE_HEADER);
        builder.add_section(PROGRAM_HEADERS);
        builder.add_section(SECTION_HEADERS);
        builder.add_section(NOTE_GNU_PROPERTY);
        builder.add_section(NOTE_GNU_BUILD_ID);
        builder.add_section(INTERP);
        builder.add_section(NOTE_ABI_TAG);
        builder.add_section(HASH);
        builder.add_section(GNU_HASH);
        builder.add_section(DYNSYM);
        builder.add_section(DYNSTR);
        builder.add_section(GNU_VERSION);
        builder.add_section(GNU_VERSION_D);
        builder.add_section(GNU_VERSION_R);
        builder.add_section(RELA_DYN_RELATIVE);
        builder.add_section(RELA_PLT);
        builder.add_section(RODATA);
        builder.add_section(EH_FRAME_HDR);
        builder.add_section(EH_FRAME);
        builder.add_section(SFRAME);
        builder.add_section(GCC_EXCEPT_TABLE);
        builder.add_sections(&self.ro);

        builder.add_section(PLT_GOT);
        builder.add_section(TEXT);
        builder.add_section(INIT);
        builder.add_section(FINI);
        builder.add_sections(&self.exec);

        builder.add_section(TDATA);
        builder.add_sections(&self.tdata);
        builder.add_section(TBSS);
        builder.add_sections(&self.tbss);
        builder.add_section(INIT_ARRAY);
        builder.add_section(FINI_ARRAY);
        builder.add_section(PREINIT_ARRAY);
        builder.add_section(DATA_REL_RO);
        builder.add_section(DYNAMIC);
        builder.add_section(GOT);
        builder.add_section(RELRO_PADDING);
        builder.add_section(DATA);
        builder.add_sections(&self.data);
        builder.add_section(BSS);
        builder.add_sections(&self.bss);

        builder.add_sections(&self.nonalloc);
        builder.add_section(COMMENT);
        builder.add_section(RISCV_ATTRIBUTES);
        builder.add_section(SHSTRTAB);
        builder.add_section(SYMTAB_LOCAL);
        builder.add_section(STRTAB);

        builder.build()
    }
}

impl<'data> OutputSections<'data> {
    pub(crate) fn secondary_order(&self, id: OutputSectionId) -> Option<SecondaryOrder> {
        self.section_infos.get(id).secondary_order
    }
    pub(crate) fn add_sections(
        &mut self,
        custom_sections: &[CustomSectionDetails<'data>],
        sections: &mut [SectionSlot],
        args: &Args,
    ) {
        for custom in custom_sections {
            let name_str = std::str::from_utf8(custom.name.bytes()).ok();
            let location = name_str.and_then(|name| {
                args.section_start
                    .get(name)
                    .map(|&address| linker_script::Location { address })
            });
            let section_id = self.add_named_section(custom.name, custom.alignment, location);

            if let Some(slot) = sections.get_mut(custom.index.0) {
                slot.set_part_id(section_id.part_id_with_alignment(custom.alignment));
            }
        }
    }

    pub(crate) fn add_named_section(
        &mut self,
        name: SectionName<'data>,
        min_alignment: Alignment,
        location: Option<linker_script::Location>,
    ) -> OutputSectionId {
        *self.custom_by_name.entry(name).or_insert_with(|| {
            self.section_infos.add_new(SectionOutputInfo {
                kind: SectionKind::Primary(name),
                // Section flags and type will be filled in based on the attributes of the sections
                // that get placed into this output section.
                section_flags: SectionFlags::empty(),
                ty: SectionType::from_u32(0),
                min_alignment,
                entsize: 0,
                location,
                secondary_order: None,
            })
        })
    }

    pub(crate) fn add_secondary_section(
        &mut self,
        primary_id: OutputSectionId,
        min_alignment: Alignment,
        secondary_order: Option<SecondaryOrder>,
    ) -> OutputSectionId {
        let primary_entsize = self.section_infos.get(primary_id).entsize;
        let section_flag = self.section_infos.get(primary_id).section_flags;
        let ty = self.section_infos.get(primary_id).ty;
        self.section_infos.add_new(SectionOutputInfo {
            kind: SectionKind::Secondary(primary_id),
            section_flags: section_flag,
            ty,
            min_alignment,
            entsize: primary_entsize,
            location: None,
            secondary_order,
        })
    }

    pub(crate) fn with_base_address(base_address: u64) -> Self {
        let section_infos = SECTION_DEFINITIONS
            .iter()
            .map(|d| SectionOutputInfo {
                section_flags: d.section_flags,
                kind: d.kind,
                ty: d.ty,
                min_alignment: d.min_alignment,
                entsize: d.element_size,
                location: None,
                secondary_order: None,
            })
            .collect();

        Self {
            section_infos: OutputSectionMap::from_values(section_infos),
            base_address,
            custom_by_name: HashMap::new(),
            output_section_indexes: Default::default(),
            init_fini_by_priority: HashMap::new(),
        }
    }

    pub(crate) fn bump_min_alignment(&mut self, sid: OutputSectionId, a: Alignment) {
        let info = self.section_infos.get_mut(sid);
        info.min_alignment = core::cmp::max(info.min_alignment, a);
    }

    pub(crate) fn get_or_create_init_fini_secondary(
        &mut self,
        primary: OutputSectionId,
        priority: u16,
        min_alignment: Alignment,
    ) -> OutputSectionId {
        let key = (primary, priority);
        if let Some(&sid) = self.init_fini_by_priority.get(&key) {
            self.bump_min_alignment(sid, min_alignment);
            return sid;
        }

        let sid = self.add_secondary_section(
            primary,
            min_alignment,
            Some(SecondaryOrder::InitFini { priority }),
        );

        self.init_fini_by_priority.insert(key, sid);
        sid
    }

    pub(crate) fn output_order(&self) -> (OutputOrder, ProgramSegments) {
        timing_phase!("Compute output order");

        let mut custom = CustomSectionIds::default();

        let mut secondary: OutputSectionMap<Vec<OutputSectionId>> = self.new_section_map();

        self.section_infos.for_each(|id, info| {
            if let SectionKind::Secondary(primary) = info.kind {
                secondary.get_mut(primary).push(id);
                return;
            }
            if id.as_usize() < NUM_BUILT_IN_SECTIONS {
                return;
            }

            if info.section_flags.contains(shf::EXECINSTR) {
                custom.exec.push(id);
            } else if info.section_flags.contains(shf::TLS) {
                if info.ty == sht::NOBITS {
                    custom.tbss.push(id);
                } else {
                    custom.tdata.push(id);
                }
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
        });

        custom.build_output_order_and_program_segments(self, &secondary)
    }

    #[must_use]
    pub(crate) fn num_sections(&self) -> usize {
        self.section_infos.len()
    }

    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn num_regular_sections(&self) -> usize {
        self.section_infos.len() - NUM_SINGLE_PART_SECTIONS as usize
    }

    pub(crate) fn has_data_in_file(&self, section_id: OutputSectionId) -> bool {
        // Note, we treat TLS sections (e.g. .tbss) as having data in the file, even if they're
        // NOBITS. This allows us to more easily place .tbss before other PROGBITS sections.
        // Effectively .tbss is NOBITS, but we put zero padding of the same size in the file. GNU ld
        // doesn't do this. It instead puts .tbss and the subsequent section at the same address.
        self.output_info(section_id).ty != sht::NOBITS
            || self
                .output_info(section_id)
                .section_flags
                .contains(shf::TLS)
    }

    pub(crate) fn output_info(&self, id: OutputSectionId) -> &SectionOutputInfo<'data> {
        self.section_infos.get(id)
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

    pub(crate) fn name(&self, section_id: OutputSectionId) -> Option<SectionName<'data>> {
        match self.output_info(section_id).kind {
            SectionKind::Primary(section_name) => Some(section_name),
            SectionKind::Secondary(_) => None,
        }
    }

    pub(crate) fn display_name(&self, section_id: OutputSectionId) -> String {
        match self.output_info(section_id).kind {
            SectionKind::Primary(section_name) => {
                format!("`{}`", String::from_utf8_lossy(section_name.0))
            }
            SectionKind::Secondary(primary_id) => {
                format!("{} (secondary)", self.display_name(primary_id))
            }
        }
    }

    pub(crate) fn section_debug(&self, section_id: OutputSectionId) -> String {
        let merge_target = self.primary_output_section(section_id);
        let merge = if merge_target == section_id {
            String::new()
        } else {
            format!(" merged into {merge_target}")
        };
        format!("{section_id}{merge} ({})", self.display_name(merge_target))
    }

    pub(crate) fn custom_name_to_id(&self, name: SectionName) -> Option<OutputSectionId> {
        self.custom_by_name.get(&name).copied()
    }

    #[cfg(test)]
    pub(crate) fn for_testing() -> OutputSections<'static> {
        let mut output_sections = OutputSections::with_base_address(0x1000);
        let mut add_name = |name: &'static str| {
            output_sections.add_named_section(SectionName(name.as_bytes()), alignment::MIN, None)
        };
        add_name("ro");
        add_name("exec");
        add_name("data");
        add_name("bss");
        output_sections
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

fn version_d_info(info: &InfoInputs) -> u32 {
    info.non_addressable_counts.verdef_count.into()
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

impl<'a> IntoIterator for &'a OutputOrder {
    type Item = OrderEvent;

    type IntoIter = Copied<slice::Iter<'a, OrderEvent>>;

    fn into_iter(self) -> Self::IntoIter {
        self.events.iter().copied()
    }
}

impl OutputOrder {
    pub(crate) fn display<'a, 'data>(
        &'a self,
        sections: &'a OutputSections<'data>,
        program_segments: &'a ProgramSegments,
    ) -> OutputOrderDisplay<'a, 'data> {
        OutputOrderDisplay {
            order: self,
            sections,
            program_segments,
        }
    }
}

impl Display for OutputOrderDisplay<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for event in &self.order.events {
            match event {
                OrderEvent::SegmentStart(program_segment_id) => {
                    writeln!(
                        f,
                        "START({})",
                        program_segment_id.display(self.program_segments)
                    )?;
                }
                OrderEvent::SegmentEnd(program_segment_id) => {
                    writeln!(
                        f,
                        "END({})",
                        program_segment_id.display(self.program_segments)
                    )?;
                }
                OrderEvent::Section(output_section_id) => {
                    writeln!(f, "  {}", self.sections.display_name(*output_section_id))?;
                }
                OrderEvent::SetLocation(location) => {
                    writeln!(f, "SET_LOCATION(0x{:x})", location.address)?;
                }
            }
        }

        Ok(())
    }
}

impl Display for OutputSections<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.section_infos.for_each(|section_id, info| {
            let _ = writeln!(f, "{section_id}: {}", info.kind);
        });
        Ok(())
    }
}

impl Display for SectionKind<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SectionKind::Primary(section_name) => write!(f, "{section_name}"),
            SectionKind::Secondary(primary_id) => write!(f, "Secondary to {primary_id}"),
        }
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
        (SFRAME, SFRAME_SECTION_NAME),
        (SHSTRTAB, SHSTRTAB_SECTION_NAME),
        (SYMTAB_LOCAL, SYMTAB_SECTION_NAME),
        (SYMTAB_GLOBAL, &[]),
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
        (RELA_DYN_RELATIVE, RELA_DYN_SECTION_NAME),
        (RELA_DYN_GENERAL, &[]),
        (RISCV_ATTRIBUTES, RISCV_ATTRIBUTES_SECTION_NAME),
        (GCC_EXCEPT_TABLE, GCC_EXCEPT_TABLE_SECTION_NAME),
        (INTERP, INTERP_SECTION_NAME),
        (HASH, HASH_SECTION_NAME),
        (GNU_VERSION, GNU_VERSION_SECTION_NAME),
        (GNU_VERSION_D, GNU_VERSION_D_SECTION_NAME),
        (GNU_VERSION_R, GNU_VERSION_R_SECTION_NAME),
        (PROGRAM_HEADERS, PROGRAM_HEADERS_SECTION_NAME),
        (SECTION_HEADERS, SECTION_HEADERS_SECTION_NAME),
        (GNU_HASH, GNU_HASH_SECTION_NAME),
        (PLT_GOT, PLT_GOT_SECTION_NAME),
        (NOTE_ABI_TAG, NOTE_ABI_TAG_SECTION_NAME),
        (NOTE_GNU_PROPERTY, NOTE_GNU_PROPERTY_SECTION_NAME),
        (NOTE_GNU_BUILD_ID, NOTE_GNU_BUILD_ID_SECTION_NAME),
        (DATA_REL_RO, DATA_REL_RO_SECTION_NAME),
        (RELRO_PADDING, RELRO_PADDING_SECTION_NAME),
    ];
    for (id, name) in check {
        match id.built_in_details().kind {
            SectionKind::Primary(section_name) => {
                assert_eq!(section_name.to_string(), String::from_utf8_lossy(name));
            }
            SectionKind::Secondary(_) => assert!(name.is_empty()),
        }
    }
    assert_eq!(NUM_BUILT_IN_SECTIONS, check.len());
}
