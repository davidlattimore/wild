//! Instructions for adding a new generated, single-part output section:
//!
//! * Add a new constant `PartId` to `part_id.rs`.
//! * Update `NUM_SINGLE_PART_SECTIONS` in `part_id.rs`.
//! * Define a constant `OutputSectionId` below.
//! * Add the section definition info to `SECTION_DEFINITIONS`, most likely inserting at the end of
//!   the single-part sections.
//! * Insert the new section into the output order in `sections_and_segments_events`. The position
//!   needs to be consistent with the access flags on the section. e.g. if the section is read-only
//!   data, it should go between the start and end of the read-only segment.
//!
//! Adding a new alignment-base (regular) section is similar to the above, but skip the steps
//! related to `part_id.rs` and insert later in `SECTION_DEFINITIONS`, probably at the end so that
//! you don't have to renumber. Also, update `NUM_BUILT_IN_REGULAR_SECTIONS`.

use crate::Result;
use crate::alignment::Alignment;
use crate::alignment::NUM_ALIGNMENTS;
use crate::grouping::SequencedLinkerScript;
use crate::layout_rules::LocationCounter;
use crate::layout_rules::SectionKind;
use crate::linker_script;
use crate::linker_script::Expression;
use crate::output_kind::OutputKind;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::part_id;
use crate::part_id::NUM_SINGLE_PART_SECTIONS;
use crate::part_id::PartId;
use crate::platform::Args;
use crate::platform::Platform;
use crate::platform::ProgramSegmentDef;
use crate::platform::SectionAttributes as _;
use crate::program_segments::ProgramSegmentId;
use crate::program_segments::ProgramSegments;
use crate::timing_phase;
use core::slice;
use hashbrown::HashMap;
use itertools::multizip;
use std::fmt::Debug;
use std::fmt::Display;
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
pub(crate) const SYMTAB_GLOBAL: OutputSectionId = part_id::SYMTAB_GLOBAL.output_section_id();
pub(crate) const RELA_DYN_RELATIVE: OutputSectionId =
    part_id::RELA_DYN_RELATIVE.output_section_id();
pub(crate) const RELA_DYN_GENERAL: OutputSectionId = part_id::RELA_DYN_GENERAL.output_section_id();
pub(crate) const RELR_DYN: OutputSectionId = part_id::RELR_DYN.output_section_id();
pub(crate) const RISCV_ATTRIBUTES: OutputSectionId = part_id::RISCV_ATTRIBUTES.output_section_id();
pub(crate) const RELRO_PADDING: OutputSectionId = part_id::RELRO_PADDING.output_section_id();
pub(crate) const SYMTAB_SHNDX_LOCAL: OutputSectionId =
    part_id::SYMTAB_SHNDX_LOCAL.output_section_id();
pub(crate) const SYMTAB_SHNDX_GLOBAL: OutputSectionId =
    part_id::SYMTAB_SHNDX_GLOBAL.output_section_id();
pub(crate) const GDB_INDEX: OutputSectionId = part_id::GDB_INDEX.output_section_id();

// Mach-O specific sections
pub(crate) const LINK_EDIT_SEGMENT: OutputSectionId =
    part_id::LINK_EDIT_SEGMENT.output_section_id();
pub(crate) const LOAD_COMMANDS: OutputSectionId = part_id::LOAD_COMMANDS.output_section_id();
pub(crate) const CHAINED_FIXUP_TABLE: OutputSectionId =
    part_id::CHAINED_FIXUP_TABLE.output_section_id();
pub(crate) const CODE_SIGNATURE: OutputSectionId = part_id::CODE_SIGNATURE.output_section_id();

// Wasm specific sections.
pub(crate) const WASM_TYPE: OutputSectionId = part_id::WASM_TYPE.output_section_id();
pub(crate) const WASM_IMPORT: OutputSectionId = part_id::WASM_IMPORT.output_section_id();
pub(crate) const WASM_FUNCTION: OutputSectionId = part_id::WASM_FUNCTION.output_section_id();
pub(crate) const WASM_TABLE: OutputSectionId = part_id::WASM_TABLE.output_section_id();
pub(crate) const WASM_MEMORY: OutputSectionId = part_id::WASM_MEMORY.output_section_id();
pub(crate) const WASM_GLOBAL: OutputSectionId = part_id::WASM_GLOBAL.output_section_id();
pub(crate) const WASM_EXPORT: OutputSectionId = part_id::WASM_EXPORT.output_section_id();
pub(crate) const WASM_START: OutputSectionId = part_id::WASM_START.output_section_id();
pub(crate) const WASM_ELEMENT: OutputSectionId = part_id::WASM_ELEMENT.output_section_id();
pub(crate) const WASM_DATA_COUNT: OutputSectionId = part_id::WASM_DATA_COUNT.output_section_id();
pub(crate) const WASM_CODE: OutputSectionId = part_id::WASM_CODE.output_section_id();
pub(crate) const WASM_DATA: OutputSectionId = part_id::WASM_DATA.output_section_id();

// Regular sections copied from the input objects.
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
// Mach-O specific sections
pub(crate) const CSTRING: OutputSectionId = OutputSectionId::regular(15);

pub(crate) const NUM_BUILT_IN_REGULAR_SECTIONS: usize = 16;

#[derive(Debug)]
pub(crate) struct OutputSections<'data, P: Platform> {
    /// The base address for our output binary.
    pub(crate) base_address: Expression<'data>,
    pub(crate) section_infos: OutputSectionMap<SectionOutputInfo<'data, P>>,

    // TODO: Consider moving this to Layout. We can't populate this until we know which output
    // sections have content, which we don't know until half way through the layout phase.
    /// Mapping from internal section IDs to output section indexes. None, if the section isn't
    /// being output.
    pub(crate) output_section_indexes: Vec<Option<u32>>,

    custom_by_name: HashMap<SectionName<'data>, OutputSectionId>,

    init_fini_by_priority: HashMap<(OutputSectionId, u16), OutputSectionId>,

    rosegment: bool,
}

/// Encodes the order of output sections and the start and end of each program segment. This struct
/// is intended to be used by iterating over it.
#[derive(Debug)]
pub(crate) struct OutputOrder<'data> {
    events: Vec<OrderEvent<'data>>,
    num_location_counters: usize,
}

pub(crate) struct OutputOrderDisplay<'a, 'data, P: Platform> {
    order: &'a OutputOrder<'data>,
    sections: &'a OutputSections<'data, P>,
    program_segments: &'a ProgramSegments<P::ProgramSegmentDef>,
}

pub(crate) struct OutputOrderBuilder<'scope, 'data, P: Platform> {
    events: Vec<OrderEvent<'data>>,

    program_segments: ProgramSegments<P::ProgramSegmentDef>,

    /// Indexes correspond to elements of `PROGRAM_SEGMENT_DEFS`.
    active_segment_kinds: Vec<Option<ProgramSegmentId>>,
    active_segment_regions: Vec<Option<&'data [u8]>>,

    output_sections: &'scope OutputSections<'data, P>,
    secondary: &'scope OutputSectionMap<Vec<OutputSectionId>>,
    output_kind: OutputKind,
    has_custom_phdrs: bool,
    location_counters: &'scope [crate::layout_rules::LocationCounter<'data>],
}

impl<'scope, 'data, P: Platform> OutputOrderBuilder<'scope, 'data, P> {
    pub(crate) fn new(
        output_kind: OutputKind,
        output_sections: &'scope OutputSections<'data, P>,
        secondary: &'scope OutputSectionMap<Vec<OutputSectionId>>,
        has_custom_phdrs: bool,
        location_counters: &'scope [crate::layout_rules::LocationCounter<'data>],
    ) -> Self {
        Self {
            events: Vec::new(),
            program_segments: ProgramSegments::empty(),
            output_sections,
            active_segment_kinds: vec![None; P::program_segment_defs().len()],
            active_segment_regions: vec![None; P::program_segment_defs().len()],
            secondary,
            output_kind,
            has_custom_phdrs,
            location_counters,
        }
    }

    fn emit_section_locations(&mut self, info: &SectionOutputInfo<'data, P>) {
        if let Some(ref loc_info) = info.location_info {
            let (start_idx, end_idx) = loc_info.location_counters;

            for idx in start_idx..end_idx {
                let lc = &self.location_counters[idx];
                match lc {
                    LocationCounter::Absolute(expr) => {
                        self.events.push(OrderEvent::SetLocation(expr.clone(), idx));
                    }
                    LocationCounter::Relative(expr, section_id) => {
                        let primary_id = self.output_sections.primary_output_section(*section_id);
                        self.events.push(OrderEvent::SetLocationRelative(
                            expr.clone(),
                            primary_id,
                            idx,
                        ));
                    }
                }
            }
        }
    }

    pub(crate) fn add_section(&mut self, section_id: OutputSectionId) {
        // When RELRO segment ends, also end the RW LOAD segment so that subsequent non-RELRO
        // sections go into a new LOAD segment.
        if self.should_end_current_rw_segment(section_id) {
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

        // Only emit SetSectionAddress if the section has ALLOC flag, meaning it can be placed in a
        // segment. Sections without ALLOC (like custom sections before their flags are propagated)
        // will have their location handled directly in compute_layout_sections.
        if let Some(ref loc_info) = section_info.location_info
            && let Some(ref location) = loc_info.location
            && section_info.section_attributes.is_alloc()
        {
            self.events
                .push(OrderEvent::SetSectionAddress(location.clone()));
        }

        for segment_id in start {
            self.events.push(OrderEvent::SegmentStart(segment_id));
        }

        self.emit_section_locations(section_info);

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
            let sec_info = self.output_sections.output_info(sid);
            self.emit_section_locations(sec_info);
            self.events.push(OrderEvent::Section(sid));
        }
    }

    /// Returns true if processing the given section will cause the RELRO segment to end.
    fn should_end_current_rw_segment(&self, section_id: OutputSectionId) -> bool {
        self.active_segment_kinds
            .iter()
            .zip(P::program_segment_defs())
            .any(|(id, def)| {
                id.is_some()
                    && def.should_cut_rw_segment_when_ending()
                    && !self
                        .output_sections
                        .should_include_in_segment(section_id, *def)
            })
    }

    /// Ends the currently active RW LOAD segment, if any. This is used when the RELRO segment
    /// ends to force .data and other non-RELRO sections into a new LOAD segment.
    fn end_rw_load_segment(&mut self) {
        let rw_load_def_index = P::program_segment_defs()
            .iter()
            .position(|def| def.is_loadable() && def.is_writable() && !def.is_executable());

        if let Some(def_index) = rw_load_def_index
            && let Some(segment_id) = self.active_segment_kinds[def_index].take()
        {
            self.events.push(OrderEvent::SegmentEnd(segment_id));
            self.active_segment_regions[def_index] = None;
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

        if self.has_custom_phdrs {
            return (stop, start);
        }

        if self.output_kind.is_partial_object() {
            return (start, stop);
        }

        // Secondary sections don't begin or end segments.
        if self.output_sections.merge_target(section_id).is_some() {
            return (stop, start);
        }

        let section_info = self.output_sections.output_info(section_id);
        if section_info
            .location_info
            .as_ref()
            .and_then(|info| info.location.as_ref())
            .is_some()
        {
            // If we're setting the location, then first end all active segments.
            for (id, region) in self
                .active_segment_kinds
                .iter_mut()
                .zip(&mut self.active_segment_regions)
            {
                if let Some(id) = id.take() {
                    stop.push(id);
                    *region = None;
                }
            }
        }

        let section_region = section_info.region_name;
        multizip((
            P::program_segment_defs(),
            self.active_segment_kinds.iter_mut(),
            self.active_segment_regions.iter_mut(),
        ))
        .for_each(|(segment_def, active_id, active_region)| {
            let should_be_active = self
                .output_sections
                .should_include_in_segment(section_id, *segment_def);

            match (active_id.as_ref(), should_be_active) {
                // Remain inactive
                (None, false) => {}

                // Remain active
                (Some(segment_id), true) => {
                    if *active_region != section_region {
                        stop.push(*segment_id);
                        let new_segment_id = self.program_segments.add_segment(*segment_def);
                        start.push(new_segment_id);
                        *active_id = Some(new_segment_id);
                        *active_region = section_region;
                    }
                }
                // Start segment
                (None, true) => {
                    let segment_id = self.program_segments.add_segment(*segment_def);
                    start.push(segment_id);
                    *active_id = Some(segment_id);
                    *active_region = section_region;
                }

                // End segment
                (Some(segment_id), false) => {
                    stop.push(*segment_id);
                    *active_id = None;
                    *active_region = None;
                }
            }
        });

        (stop, start)
    }

    pub(crate) fn add_segment_with_sections(
        &mut self,
        ptype: u32,
        pflags: u32,
        sections: &[OutputSectionId],
        output_sections: &OutputSections<'data, P>,
    ) -> ProgramSegmentId {
        let segment_id = self
            .program_segments
            .add_segment(P::ProgramSegmentDef::from_linker_script(ptype, pflags));
        self.events.push(OrderEvent::SegmentStart(segment_id));
        for section in sections {
            let section_info = output_sections.section_infos.get(*section);
            self.emit_section_locations(section_info);
            self.events.push(OrderEvent::Section(*section));

            let secondaries: &Vec<OutputSectionId> = self.secondary.get(*section);
            for sid in secondaries {
                self.events.push(OrderEvent::Section(*sid));
            }
        }
        self.events.push(OrderEvent::SegmentEnd(segment_id));
        segment_id
    }

    pub(crate) fn add_sections(&mut self, sections: &[OutputSectionId]) {
        for section in sections {
            self.add_section(*section);
        }
    }

    pub(crate) fn build(mut self) -> (OutputOrder<'data>, ProgramSegments<P::ProgramSegmentDef>) {
        for segment_id in self.active_segment_kinds.into_iter().flatten() {
            self.events.push(OrderEvent::SegmentEnd(segment_id));
        }

        if !self.output_kind.is_partial_object() && !self.has_custom_phdrs {
            for def in P::unconditional_segment_defs() {
                let segment_id = self.program_segments.add_segment(*def);
                self.events.push(OrderEvent::SegmentStart(segment_id));
                self.events.push(OrderEvent::SegmentEnd(segment_id));
            }
        }

        (
            OutputOrder {
                events: self.events,
                num_location_counters: self.location_counters.len(),
            },
            self.program_segments,
        )
    }
}

#[derive(Default)]
pub(crate) struct CustomSectionIds {
    pub(crate) ro: Vec<OutputSectionId>,
    pub(crate) exec: Vec<OutputSectionId>,
    pub(crate) data: Vec<OutputSectionId>,
    pub(crate) bss: Vec<OutputSectionId>,
    pub(crate) nonalloc: Vec<OutputSectionId>,
    pub(crate) tdata: Vec<OutputSectionId>,
    pub(crate) tbss: Vec<OutputSectionId>,
}

impl<'data, P: Platform> OutputSections<'data, P> {
    /// Returns an iterator that emits all section IDs and their info.
    pub(crate) fn ids_with_info(
        &self,
    ) -> impl Iterator<Item = (OutputSectionId, &SectionOutputInfo<'data, P>)> {
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

    pub(crate) fn section_flags(&self, section_id: OutputSectionId) -> P::SectionFlags {
        self.output_info(section_id).section_attributes.flags()
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
    pub(crate) fn should_include_in_segment(
        &self,
        section_id: OutputSectionId,
        segment_def: P::ProgramSegmentDef,
    ) -> bool {
        let info = self.output_info(section_id);
        segment_def.should_include_section(info, section_id, self.rosegment)
    }
}

// TODO: There's also a type with this name in layout_rules. Rename one of them to avoid confusion.
#[derive(Debug)]
pub(crate) struct SectionOutputInfo<'data, P: Platform> {
    pub(crate) kind: SectionKind<'data>,
    pub(crate) section_attributes: P::SectionAttributes,
    pub(crate) min_alignment: Alignment,
    pub(crate) location_info: Option<SectionLocationInfo<'data>>,
    pub(crate) secondary_order: Option<SecondaryOrder>,
    pub(crate) phdr_name: Option<&'data [u8]>,
    pub(crate) region_name: Option<&'data [u8]>,
}

impl OutputSectionId {
    pub(crate) const fn regular(offset: u32) -> OutputSectionId {
        OutputSectionId(NUM_SINGLE_PART_SECTIONS + offset)
    }

    pub(crate) const fn as_usize(self) -> usize {
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

    pub(crate) fn parts(self) -> PartIdIterator {
        PartIdIterator {
            next: self.base_part_id(),
            remaining: self.num_parts(),
        }
    }

    pub(crate) fn opt_built_in_details<P: Platform>(
        self,
    ) -> Option<&'static P::BuiltInSectionDetails> {
        P::built_in_section_details().get(self.as_usize())
    }

    pub(crate) fn min_alignment<P: Platform>(
        self,
        output_sections: &OutputSections<P>,
    ) -> Alignment {
        output_sections.section_infos.get(self).min_alignment
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

    /// Returns whether this section ID corresponds to a custom section as opposed to a built-in
    /// section.
    pub(crate) fn is_custom(self) -> bool {
        self.as_usize() >= NUM_BUILT_IN_SECTIONS
    }
}

#[derive(Debug, Clone)]
pub(crate) enum OrderEvent<'data> {
    SegmentStart(ProgramSegmentId),
    SegmentEnd(ProgramSegmentId),
    Section(OutputSectionId),
    SetLocation(linker_script::Expression<'data>, usize),
    SetLocationRelative(linker_script::Expression<'data>, OutputSectionId, usize),
    SetSectionAddress(linker_script::Expression<'data>),
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

impl<'data, P: Platform> OutputSections<'data, P> {
    pub(crate) fn secondary_order(&self, id: OutputSectionId) -> Option<SecondaryOrder> {
        self.section_infos.get(id).secondary_order
    }
    pub(crate) fn add_sections(
        &mut self,
        custom_sections: &[CustomSectionDetails<'data>],
        section_part_ids: &mut [PartId],
        args: &P::Args,
    ) {
        for custom in custom_sections {
            let location = args
                .start_address_for_section(custom.name)
                .map(linker_script::Expression::Number);
            let location_info = location.map(|loc| SectionLocationInfo {
                location_counters: (0, 0),
                location: Some(loc),
                at_location: None,
                is_top_level: true,
            });
            let section_id =
                self.add_named_section(custom.name, custom.alignment, None, None, location_info);

            section_part_ids[custom.index.0] = section_id.part_id_with_alignment(custom.alignment);
        }
    }

    /// Applies `--section-start` / `-Ttext` / `-Tdata` / `-Tbss` overrides to the built-in
    /// sections `.text`, `.data`, and `.bss`. Must be called after `with_base_address` and before
    /// the layout phase reads `section_info.location`.
    pub(crate) fn apply_section_start_overrides(&mut self, args: &P::Args) {
        for (section_id, name) in [
            (TEXT, SectionName(b".text")),
            (DATA, SectionName(b".data")),
            (BSS, SectionName(b".bss")),
        ] {
            if let Some(address) = args.start_address_for_section(name) {
                let info = self.section_infos.get_mut(section_id);
                if let Some(ref mut loc_info) = info.location_info {
                    loc_info.location = Some(linker_script::Expression::Number(address));
                } else {
                    info.location_info = Some(SectionLocationInfo {
                        location_counters: (0, 0),
                        location: Some(linker_script::Expression::Number(address)),
                        at_location: None,
                        is_top_level: true,
                    });
                }
            }
        }
    }

    pub(crate) fn add_named_section(
        &mut self,
        name: SectionName<'data>,
        min_alignment: Alignment,
        phdr_name: Option<&'data [u8]>,
        region_name: Option<&'data [u8]>,
        location_info: Option<SectionLocationInfo<'data>>,
    ) -> OutputSectionId {
        *self.custom_by_name.entry(name).or_insert_with(|| {
            self.section_infos.add_new(SectionOutputInfo {
                kind: SectionKind::Primary(name),
                // Section flags and type will be filled in based on the attributes of the sections
                // that get placed into this output section.
                section_attributes: Default::default(),
                min_alignment,
                location_info,
                secondary_order: None,
                phdr_name,
                region_name,
            })
        })
    }

    pub(crate) fn add_secondary_section(
        &mut self,
        primary_id: OutputSectionId,
        min_alignment: Alignment,
        secondary_order: Option<SecondaryOrder>,
        location_info: Option<SectionLocationInfo<'data>>,
    ) -> OutputSectionId {
        let primary_info = self.section_infos.get(primary_id);
        let section_attributes = primary_info.section_attributes;
        let location_info = location_info.or_else(|| primary_info.location_info.clone());
        self.section_infos.add_new(SectionOutputInfo {
            kind: SectionKind::Secondary(primary_id),
            section_attributes,
            min_alignment,
            location_info,
            secondary_order,
            phdr_name: None,
            region_name: primary_info.region_name,
        })
    }

    pub(crate) fn with_base_address(base_address: u64) -> Self {
        let section_infos = P::built_in_section_infos();
        let base_address = Expression::Number(base_address);

        Self {
            section_infos: OutputSectionMap::from_values(section_infos),
            base_address,
            custom_by_name: HashMap::new(),
            output_section_indexes: Default::default(),
            init_fini_by_priority: HashMap::new(),
            rosegment: true,
        }
    }

    pub(crate) fn set_rosegment(&mut self, rosegment: bool) {
        self.rosegment = rosegment;
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
            None,
        );

        self.init_fini_by_priority.insert(key, sid);
        sid
    }

    pub(crate) fn output_order(
        &self,
        output_kind: OutputKind,
        linker_scripts: &[&SequencedLinkerScript<'data, P>],
        location_counters: &[crate::layout_rules::LocationCounter<'data>],
    ) -> Result<(OutputOrder<'data>, ProgramSegments<P::ProgramSegmentDef>)> {
        timing_phase!("Compute output order");

        let has_custom_phdrs = linker_scripts
            .iter()
            .any(|s| !s.parsed.program_headers.is_empty());

        let mut custom = CustomSectionIds::default();

        let mut secondary: OutputSectionMap<Vec<OutputSectionId>> = self.new_section_map();

        let mut phdr_map: Option<HashMap<&[u8], Vec<OutputSectionId>>> =
            has_custom_phdrs.then(HashMap::new);

        self.section_infos.for_each(|id, info| {
            if let SectionKind::Secondary(primary) = info.kind {
                secondary.get_mut(primary).push(id);
                return;
            }

            if has_custom_phdrs {
                if let Some(phdr_name) = info.phdr_name {
                    phdr_map
                        .as_mut()
                        .unwrap()
                        .entry(phdr_name)
                        .or_default()
                        .push(id);
                    return;
                }

                if id == FILE_HEADER
                    || id == PROGRAM_HEADERS
                    || id == SECTION_HEADERS
                    || id == RISCV_ATTRIBUTES
                {
                    return;
                }
            } else if id.as_usize() < NUM_BUILT_IN_SECTIONS {
                return;
            }

            if info.section_attributes.is_executable() {
                custom.exec.push(id);
            } else if info.section_attributes.is_tls() {
                if info.section_attributes.is_no_bits() {
                    custom.tbss.push(id);
                } else {
                    custom.tdata.push(id);
                }
            } else if !info.section_attributes.is_writable() {
                if info.section_attributes.is_alloc() {
                    custom.ro.push(id);
                } else {
                    custom.nonalloc.push(id);
                }
            } else if info.section_attributes.is_no_bits() {
                custom.bss.push(id);
            } else {
                custom.data.push(id);
            }
        });

        if has_custom_phdrs {
            P::build_custom_output_order_and_program_segments(
                &custom,
                output_kind,
                self,
                &secondary,
                linker_scripts,
                &mut phdr_map.unwrap(),
                location_counters,
            )
        } else {
            Ok(P::build_output_order_and_program_segments(
                &custom,
                output_kind,
                self,
                &secondary,
                location_counters,
            ))
        }
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
        let attributes = self.output_info(section_id).section_attributes;
        !attributes.is_no_bits() || attributes.is_tls()
    }

    pub(crate) fn output_info(&self, id: OutputSectionId) -> &SectionOutputInfo<'data, P> {
        self.section_infos.get(id)
    }

    /// Returns the output index of the built-in-section `id` or None if the section isn't being
    /// output.
    pub(crate) fn output_index_of_section(&self, id: OutputSectionId) -> Option<u32> {
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

    pub(crate) fn part_debug(&self, part_id: PartId) -> String {
        let alignment = part_id.alignment(self);
        format!(
            "{} align={alignment}",
            self.section_debug(part_id.output_section_id())
        )
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

    pub(crate) fn custom_name_to_id<'a>(&self, name: SectionName<'a>) -> Option<OutputSectionId> {
        self.custom_by_name.get(&name).copied()
    }

    /// Look up a section by name across all sections — both built-in and custom.
    pub(crate) fn section_id_by_name(&self, name: SectionName) -> Option<OutputSectionId> {
        if let Some(id) = self.custom_by_name.get(&name).copied() {
            return Some(id);
        }
        let mut found = None;
        self.section_infos.for_each(|id, _| {
            if found.is_none() && self.name(id) == Some(name) {
                found = Some(id);
            }
        });
        found
    }

    /// Returns whether the specified section should have a symbol emitted for it. This function is
    /// mainly used during partial linking.
    pub(crate) fn will_emit_section_symbol_for_partial_objects(
        &self,
        section_id: OutputSectionId,
    ) -> bool {
        P::will_emit_section_symbol_for_partial_objects(self, section_id)
    }

    pub(crate) fn set_base_address(&mut self, base_address: Expression<'data>) {
        self.base_address = base_address;
    }

    #[cfg(test)]
    pub(crate) fn for_testing() -> OutputSections<'static, crate::elf::Elf> {
        use crate::elf::Elf;

        let mut output_sections = OutputSections::<Elf>::with_base_address(0x1000);
        let mut add_name = |name: &'static str| {
            output_sections.add_named_section(
                SectionName(name.as_bytes()),
                crate::alignment::MIN,
                None,
                None,
                None,
            )
        };
        add_name("ro");
        add_name("exec");
        add_name("data");
        add_name("bss");
        output_sections
    }
}

impl Display for SectionName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.0))
    }
}

impl std::fmt::Display for OutputSectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.as_usize(), f)
    }
}

impl<'data, 'a> IntoIterator for &'a OutputOrder<'data> {
    type Item = OrderEvent<'data>;

    type IntoIter = std::iter::Cloned<slice::Iter<'a, OrderEvent<'data>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.events.iter().cloned()
    }
}

impl<'data> OutputOrder<'data> {
    pub(crate) fn num_location_counters(&self) -> usize {
        self.num_location_counters
    }

    pub(crate) fn display<'a, P: Platform>(
        &'a self,
        sections: &'a OutputSections<'data, P>,
        program_segments: &'a ProgramSegments<P::ProgramSegmentDef>,
    ) -> OutputOrderDisplay<'a, 'data, P> {
        OutputOrderDisplay {
            order: self,
            sections,
            program_segments,
        }
    }
}

impl<'data, P: Platform> Display for OutputOrderDisplay<'_, 'data, P> {
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
                OrderEvent::SetLocation(expr, _) => {
                    writeln!(f, "SET_LOCATION({expr:?})")?;
                }
                OrderEvent::SetLocationRelative(expr, section_id, _) => {
                    writeln!(
                        f,
                        "SET_LOCATION_RELATIVE({expr:?}, {})",
                        self.sections.display_name(*section_id)
                    )?;
                }
                OrderEvent::SetSectionAddress(expr) => {
                    writeln!(f, "SET_SECTION_ADDRESS({expr:?})")?;
                }
            }
        }

        Ok(())
    }
}

impl<P: Platform> Display for OutputSections<'_, P> {
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

pub(crate) struct PartIdIterator {
    next: PartId,
    remaining: usize,
}

impl Iterator for PartIdIterator {
    type Item = PartId;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            None
        } else {
            self.remaining -= 1;
            let id = self.next;
            self.next = self.next.offset(1);
            Some(id)
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SectionLocationInfo<'data> {
    pub(crate) location_counters: (usize, usize),
    pub(crate) location: Option<Expression<'data>>,
    pub(crate) at_location: Option<Expression<'data>>,
    pub(crate) is_top_level: bool,
}
