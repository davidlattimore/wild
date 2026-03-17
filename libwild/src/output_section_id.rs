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

use crate::alignment::Alignment;
use crate::alignment::NUM_ALIGNMENTS;
use crate::layout_rules::SectionKind;
use crate::linker_script;
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
use crate::resolution::SectionSlot;
use crate::timing_phase;
use core::slice;
use hashbrown::HashMap;
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
pub(crate) struct OutputSections<'data, P: Platform> {
    /// The base address for our output binary.
    pub(crate) base_address: u64,
    pub(crate) section_infos: OutputSectionMap<SectionOutputInfo<'data, P>>,

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

pub(crate) struct OutputOrderDisplay<'a, 'data, P: Platform> {
    order: &'a OutputOrder,
    sections: &'a OutputSections<'data, P>,
    program_segments: &'a ProgramSegments<P::ProgramSegmentDef>,
}

struct OutputOrderBuilder<'scope, 'data, P: Platform> {
    events: Vec<OrderEvent>,

    program_segments: ProgramSegments<P::ProgramSegmentDef>,

    /// Indexes correspond to elements of `PROGRAM_SEGMENT_DEFS`.
    active_segment_kinds: Vec<Option<ProgramSegmentId>>,

    output_sections: &'scope OutputSections<'data, P>,
    secondary: &'scope OutputSectionMap<Vec<OutputSectionId>>,
}

impl<'scope, 'data, P: Platform> OutputOrderBuilder<'scope, 'data, P> {
    fn new(
        output_sections: &'scope OutputSections<'data, P>,
        secondary: &'scope OutputSectionMap<Vec<OutputSectionId>>,
    ) -> Self {
        Self {
            events: Vec::new(),
            program_segments: ProgramSegments::empty(),
            output_sections,
            active_segment_kinds: vec![None; P::program_segment_defs().len()],
            secondary,
        }
    }

    fn add_section(&mut self, section_id: OutputSectionId) {
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

        // Only emit SetLocation if the section has ALLOC flag, meaning it can be placed
        // in a segment. Sections without ALLOC (like custom sections before their flags
        // are propagated) will have their location handled directly in layout_section_parts
        // via section_info.location.
        if let Some(location) = section_info.location
            && section_info.section_attributes.is_alloc()
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

        P::program_segment_defs()
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

    fn build(mut self) -> (OutputOrder, ProgramSegments<P::ProgramSegmentDef>) {
        for segment_id in self.active_segment_kinds.into_iter().flatten() {
            self.events.push(OrderEvent::SegmentEnd(segment_id));
        }

        for def in P::unconditional_segment_defs() {
            let segment_id = self.program_segments.add_segment(*def);
            self.events.push(OrderEvent::SegmentStart(segment_id));
            self.events.push(OrderEvent::SegmentEnd(segment_id));
        }

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
    fn should_include_in_segment(
        &self,
        section_id: OutputSectionId,
        segment_def: P::ProgramSegmentDef,
    ) -> bool {
        let info = self.output_info(section_id);
        segment_def.should_include_section(info, section_id)
    }
}

// TODO: There's also a type with this name in layout_rules. Rename one of them to avoid confusion.
#[derive(Debug)]
pub(crate) struct SectionOutputInfo<'data, P: Platform> {
    pub(crate) kind: SectionKind<'data>,
    pub(crate) section_attributes: P::SectionAttributes,
    pub(crate) min_alignment: Alignment,
    pub(crate) location: Option<linker_script::Location>,
    pub(crate) secondary_order: Option<SecondaryOrder>,
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
    fn build_output_order_and_program_segments<'data, P: Platform>(
        &self,
        output_sections: &OutputSections<'data, P>,
        secondary: &OutputSectionMap<Vec<OutputSectionId>>,
    ) -> (OutputOrder, ProgramSegments<P::ProgramSegmentDef>) {
        let mut builder = OutputOrderBuilder::<P>::new(output_sections, secondary);

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

impl<'data, P: Platform> OutputSections<'data, P> {
    pub(crate) fn secondary_order(&self, id: OutputSectionId) -> Option<SecondaryOrder> {
        self.section_infos.get(id).secondary_order
    }
    pub(crate) fn add_sections(
        &mut self,
        custom_sections: &[CustomSectionDetails<'data>],
        sections: &mut [SectionSlot],
        args: &P::Args,
    ) {
        for custom in custom_sections {
            let location = args
                .start_address_for_section(custom.name)
                .map(|address| linker_script::Location { address });
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
                section_attributes: Default::default(),
                min_alignment,
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
        let section_attributes = self.section_infos.get(primary_id).section_attributes;
        self.section_infos.add_new(SectionOutputInfo {
            kind: SectionKind::Secondary(primary_id),
            section_attributes,
            min_alignment,
            location: None,
            secondary_order,
        })
    }

    pub(crate) fn with_base_address(base_address: u64) -> Self {
        let section_infos = P::built_in_section_infos();

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

    pub(crate) fn output_order(&self) -> (OutputOrder, ProgramSegments<P::ProgramSegmentDef>) {
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

        custom.build_output_order_and_program_segments::<P>(self, &secondary)
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

    #[cfg(test)]
    pub(crate) fn for_testing() -> OutputSections<'static, crate::elf::Elf> {
        use crate::elf::Elf;

        let mut output_sections = OutputSections::<Elf>::with_base_address(0x1000);
        let mut add_name = |name: &'static str| {
            output_sections.add_named_section(
                SectionName(name.as_bytes()),
                crate::alignment::MIN,
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

impl<'a> IntoIterator for &'a OutputOrder {
    type Item = OrderEvent;

    type IntoIter = Copied<slice::Iter<'a, OrderEvent>>;

    fn into_iter(self) -> Self::IntoIter {
        self.events.iter().copied()
    }
}

impl OutputOrder {
    pub(crate) fn display<'a, 'data, P: Platform>(
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
                OrderEvent::SetLocation(location) => {
                    writeln!(f, "SET_LOCATION(0x{:x})", location.address)?;
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
