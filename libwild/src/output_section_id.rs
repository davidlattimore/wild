//! Section and part IDs are platform-specific. These instructions apply to all platforms.
//!
//! Instructions for adding a new generated, single-part output section:
//!
//! * Add a variant to the platform's `SinglePartSectionId` enum.
//! * Define constants derived from the variant in the platform's `part_id` and `output_section_id`
//!   modules.
//! * Add the section definition info to `SECTION_DEFINITIONS`.
//! * Insert the new section into the output order in `sections_and_segments_events`. The position
//!   needs to be consistent with the access flags on the section. e.g. if the section is read-only
//!   data, it should go between the start and end of the read-only segment.
//!
//! Adding a new alignment-based (regular) section is similar to the above, but add it to the
//! platform's `RegularSectionId` enum and only define an `OutputSectionId` constant. Insert it
//! later in `SECTION_DEFINITIONS`.

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
use crate::parsing::SymbolLoc;
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
use std::hash::Hash;
use std::hash::Hasher;
use std::ops::Range;

/// An ID for an output section. This is used for looking up section info. It's independent of
/// section ordering.
#[derive(Clone, Copy, PartialEq, Eq, Hash, derive_more::Debug)]
#[debug("osid-{_0}")]
pub(crate) struct OutputSectionId(u32);

#[repr(u32)]
#[derive(Clone, Copy)]
pub(crate) enum CommonSinglePartSectionId {
    Unmapped,
    FileHeader,

    // Must be last.
    Count,
}

impl CommonSinglePartSectionId {
    pub(crate) const fn part_id(self) -> PartId {
        PartId::from_u32(self as u32)
    }

    pub(crate) const fn output_section_id(self) -> OutputSectionId {
        OutputSectionId::from_u32(self as u32)
    }
}

pub(crate) const NUM_COMMON_SINGLE_PART_SECTIONS: u32 = CommonSinglePartSectionId::Count as u32;

#[cfg(test)]
pub(crate) const UNMAPPED: OutputSectionId =
    CommonSinglePartSectionId::Unmapped.output_section_id();

pub(crate) const FILE_HEADER: OutputSectionId =
    CommonSinglePartSectionId::FileHeader.output_section_id();

#[derive(Debug)]
pub(crate) struct CustomSectionDetails<'data, P: Platform> {
    pub(crate) identity: SectionIdentity<'data, P>,
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

    custom_by_identity: HashMap<SectionIdentity<'data, P>, OutputSectionId>,

    init_fini_by_priority: HashMap<(OutputSectionId, u16), OutputSectionId>,

    rosegment: bool,

    output_kind: OutputKind,
}

/// Encodes the order of output sections and the start and end of each program segment. This struct
/// is intended to be used by iterating over it.
#[derive(Debug)]
pub(crate) struct OutputOrder<'data> {
    events: Vec<OrderEvent<'data>>,
    num_location_counters: usize,
    has_custom_phdrs: bool,
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
    last_location_counter: Option<LocationCounterIndex>,
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
            program_segments: ProgramSegments::empty(has_custom_phdrs),
            output_sections,
            active_segment_kinds: vec![None; P::program_segment_defs().len()],
            active_segment_regions: vec![None; P::program_segment_defs().len()],
            secondary,
            output_kind,
            has_custom_phdrs,
            location_counters,
            last_location_counter: location_counters.last().map(|_| 0),
        }
    }

    fn emit_location_counters(
        &mut self,
        lc_start: LocationCounterIndex,
        lc_end: LocationCounterIndex,
    ) {
        for idx in lc_start..lc_end {
            let lc = &self.location_counters[idx];
            match lc {
                LocationCounter::Absolute(expr, loc) => {
                    self.events
                        .push(OrderEvent::SetLocation(expr.clone(), loc.clone(), idx));
                }
                LocationCounter::Relative(expr, loc, section_id) => {
                    let primary_id = self.output_sections.primary_output_section(*section_id);
                    self.events.push(OrderEvent::SetLocationRelative(
                        expr.clone(),
                        primary_id,
                        loc.clone(),
                        idx,
                    ));
                }
            }
        }
        self.last_location_counter = self.last_location_counter.map(|l| l.max(lc_end));
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

        if let Some(ref loc_info) = section_info.location_info {
            let (lc_start, lc_stop) = loc_info.location_counters;
            self.emit_location_counters(lc_start, lc_stop);
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
            let sec_info = self.output_sections.output_info(sid);
            if let Some(ref loc_info) = sec_info.location_info {
                let (lc_start, lc_stop) = loc_info.location_counters;
                self.emit_location_counters(lc_start, lc_stop);
            }
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

    pub(crate) fn push_event(&mut self, event: OrderEvent<'data>) {
        self.events.push(event);
    }

    pub(crate) fn add_custom_segment(
        &mut self,
        segment_def: P::ProgramSegmentDef,
    ) -> ProgramSegmentId {
        self.program_segments.add_segment(segment_def)
    }

    pub(crate) fn get_segment_mut(&mut self, id: ProgramSegmentId) -> &mut P::ProgramSegmentDef {
        self.program_segments.segment_def_mut(id)
    }

    pub(crate) fn add_sections(&mut self, sections: &[OutputSectionId]) {
        for section in sections {
            self.add_section(*section);
        }
    }

    pub(crate) fn build(mut self) -> (OutputOrder<'data>, ProgramSegments<P::ProgramSegmentDef>) {
        if let Some(lc) = self.last_location_counter {
            self.emit_location_counters(lc, self.location_counters.len());
        }

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
                has_custom_phdrs: self.has_custom_phdrs,
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
        crate::part_id::regular_part_base::<P>().as_usize()
            + (self.num_sections() - regular_section_base::<P>().as_usize()) * NUM_ALIGNMENTS
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
        P::program_segment_should_include_section(segment_def, info, section_id, self.rosegment)
    }
}

// TODO: There's also a type with this name in layout_rules. Rename one of them to avoid confusion.
#[derive(Debug)]
pub(crate) struct SectionOutputInfo<'data, P: Platform> {
    pub(crate) kind: SectionKind<'data, P>,
    pub(crate) section_attributes: P::SectionAttributes,
    pub(crate) min_alignment: Alignment,
    pub(crate) location_info: Option<SectionLocationInfo<'data>>,
    pub(crate) secondary_order: Option<SecondaryOrder>,
    pub(crate) region_name: Option<&'data [u8]>,
    pub(crate) fill: Option<[u8; 4]>,
    pub(crate) phdrs: Vec<&'data [u8]>,
}

impl OutputSectionId {
    pub(crate) const fn as_u32(self) -> u32 {
        self.0
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

    pub(crate) const fn offset(self, offset: usize) -> Self {
        Self(self.0 + offset as u32)
    }

    pub(crate) fn part_id_range<P: Platform>(self) -> Range<PartId> {
        let base = self.base_part_id::<P>();
        let count = self.num_parts::<P>();
        base..base.offset(count)
    }

    pub(crate) fn num_parts<P: Platform>(self) -> usize {
        if self.0 < regular_section_base::<P>().0 {
            1
        } else {
            NUM_ALIGNMENTS
        }
    }

    pub(crate) fn parts<P: Platform>(self) -> PartIdIterator {
        PartIdIterator {
            next: self.base_part_id::<P>(),
            remaining: self.num_parts::<P>(),
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

    pub(crate) fn is_regular<P: Platform>(self) -> bool {
        self.0 >= regular_section_base::<P>().0
    }

    /// Returns the part ID in this section that has the specified alignment. Can only be called for
    /// regular sections.
    pub(crate) const fn part_id_with_alignment<P: Platform>(self, alignment: Alignment) -> PartId {
        let Some(regular_offset) = self.0.checked_sub(regular_section_base::<P>().0) else {
            panic!("part_id_with_alignment can only be called for regular sections");
        };
        PartId::from_u32(
            crate::part_id::regular_part_base::<P>().as_u32()
                + (regular_offset * NUM_ALIGNMENTS as u32)
                + NUM_ALIGNMENTS as u32
                - 1
                - alignment.exponent as u32,
        )
    }

    /// Returns the first part ID for this section.
    pub(crate) fn base_part_id<P: Platform>(self) -> PartId {
        if self.0 < regular_section_base::<P>().0 {
            P::single_part_id(self).unwrap_or_else(|| {
                panic!(
                    "platform {} has no part ID for output section {self:?}",
                    std::any::type_name::<P>()
                )
            })
        } else {
            PartId::from_u32(
                crate::part_id::regular_part_base::<P>().as_u32()
                    + (self.0 - regular_section_base::<P>().0) * NUM_ALIGNMENTS as u32,
            )
        }
    }

    /// Returns whether this section ID corresponds to a custom section as opposed to a built-in
    /// section.
    pub(crate) const fn is_custom<P: Platform>(self) -> bool {
        self.as_usize() >= num_built_in_sections::<P>()
    }
}

pub(crate) const fn regular_section_base<P: Platform>() -> OutputSectionId {
    OutputSectionId::from_u32(P::NUM_SINGLE_PART_SECTIONS)
}

#[derive(Debug, Clone)]
pub(crate) enum OrderEvent<'data> {
    SegmentStart(ProgramSegmentId),
    SegmentEnd(ProgramSegmentId),
    Section(OutputSectionId),
    SetLocation(
        linker_script::Expression<'data>,
        SymbolLoc,
        LocationCounterIndex,
    ),
    SetLocationRelative(
        linker_script::Expression<'data>,
        OutputSectionId,
        SymbolLoc,
        LocationCounterIndex,
    ),
    SetSectionAddress(linker_script::Expression<'data>),
}

/// The section's complete identity. Determines whether sections are combined into the same output
/// section.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SectionIdentity<'data, P: Platform> {
    name: SectionName<'data>,
    format_specific: P::SectionIdentityExt,
}

impl<'data, P: Platform> SectionIdentity<'data, P> {
    pub(crate) const fn new(
        name: SectionName<'data>,
        format_specific: P::SectionIdentityExt,
    ) -> Self {
        Self {
            name,
            format_specific,
        }
    }

    pub(crate) fn section_name(&self) -> SectionName<'data> {
        self.name
    }
}

impl<'data, P: Platform> PartialEq for SectionIdentity<'data, P> {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.format_specific == other.format_specific
    }
}

impl<'data, P: Platform> Eq for SectionIdentity<'data, P> {}

impl<'data, P: Platform> Hash for SectionIdentity<'data, P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.format_specific.hash(state);
    }
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
        custom_sections: &[CustomSectionDetails<'data, P>],
        section_part_ids: &mut [PartId],
        args: &P::Args,
    ) {
        for custom in custom_sections {
            let location = args
                .start_address_for_section(custom.identity.section_name())
                .map(linker_script::Expression::Number);
            let location_info = location.map(|loc| SectionLocationInfo {
                location_counters: (0, 0),
                location: Some(loc),
                at_location: None,
                is_top_level: true,
            });
            let section_id = self.add_named_section(
                custom.identity,
                custom.alignment,
                None,
                location_info.as_ref(),
                None,
                Vec::new(),
                None,
            );

            let part_id = if section_id.is_regular::<P>() {
                section_id.part_id_with_alignment::<P>(custom.alignment)
            } else {
                section_id.base_part_id::<P>()
            };
            section_part_ids[custom.index.0] = part_id;
        }
    }

    /// Applies `--section-start` / `-Ttext` / `-Tdata` / `-Tbss` overrides to the built-in
    /// sections `.text`, `.data`, and `.bss`. Must be called after `with_base_address` and before
    /// the layout phase reads `section_info.location`.
    pub(crate) fn apply_section_start_overrides(&mut self, args: &P::Args) {
        // TODO: The names here are definitely ELF-specific. Look at moving this code.
        for (section_id, name) in [
            (P::TEXT_SECTION_ID, SectionName(b".text")),
            (P::DATA_SECTION_ID, SectionName(b".data")),
            (P::BSS_SECTION_ID, SectionName(b".bss")),
        ] {
            let Some(section_id) = section_id else {
                continue;
            };
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
        identity: SectionIdentity<'data, P>,
        min_alignment: Alignment,
        region_name: Option<&'data [u8]>,
        location_info: Option<&SectionLocationInfo<'data>>,
        fill: Option<[u8; 4]>,
        phdrs: Vec<&'data [u8]>,
        attributes: Option<&linker_script::SectionAttributes>,
    ) -> OutputSectionId {
        let mut resolved_id = None;
        if !self.output_kind.is_partial_object()
            && let Some(builtin_id) = (0..regular_section_base::<P>().as_usize())
                .map(OutputSectionId::from_usize)
                .find(|&bid| self.identity(bid) == Some(identity))
        {
            resolved_id = Some(builtin_id);
        }

        let output_id = match self.custom_by_identity.entry(identity) {
            hashbrown::hash_map::Entry::Occupied(e) => *e.get(),
            hashbrown::hash_map::Entry::Vacant(e) => {
                if let Some(builtin_id) = resolved_id {
                    *e.insert(builtin_id)
                } else {
                    let new_id = self.section_infos.add_new(SectionOutputInfo {
                        kind: SectionKind::Primary(identity),
                        section_attributes: attributes
                            .map(|attr| P::set_section_attributes(attr, Default::default()))
                            .unwrap_or_default(),
                        min_alignment,
                        location_info: location_info.cloned(),
                        secondary_order: None,
                        region_name,
                        fill,
                        phdrs,
                    });
                    return *e.insert(new_id);
                }
            }
        };

        let info = self.section_infos.get_mut(output_id);
        info.min_alignment = info.min_alignment.max(min_alignment);
        info.region_name = region_name.or(info.region_name);
        if location_info.is_some() {
            info.location_info = location_info.cloned();
        }
        info.fill = fill.or(info.fill);
        if !phdrs.is_empty() {
            info.phdrs = phdrs;
        }
        info.section_attributes = attributes.map_or(info.section_attributes, |attr| {
            P::set_section_attributes(attr, info.section_attributes)
        });

        output_id
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
            region_name: primary_info.region_name,
            fill: primary_info.fill,
            phdrs: Vec::new(),
        })
    }

    pub(crate) fn with_base_address(base_address: u64, output_kind: OutputKind) -> Self {
        let section_infos = P::built_in_section_infos();
        let base_address = Expression::Number(base_address);

        Self {
            section_infos: OutputSectionMap::from_values(section_infos),
            base_address,
            custom_by_identity: HashMap::new(),
            output_section_indexes: Default::default(),
            init_fini_by_priority: HashMap::new(),
            rosegment: true,
            output_kind,
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

        self.section_infos.for_each(|id, info| {
            if let SectionKind::Secondary(primary) = info.kind {
                secondary.get_mut(primary).push(id);
                return;
            }

            if !id.is_regular::<P>() && P::single_part_id(id).is_none() {
                return;
            }

            if has_custom_phdrs {
                if !info.phdrs.is_empty() {
                    return;
                }

                if id == FILE_HEADER || P::CUSTOM_PHDR_EXCLUDED_SECTION_IDS.contains(&id) {
                    return;
                } else if id.as_usize() < num_built_in_sections::<P>()
                    && let Some(identity) = self.identity(id)
                    && self.custom_identity_to_id(identity).is_some()
                {
                    return;
                }
            } else if !id.is_custom::<P>() {
                return;
            }

            let attr = info.section_attributes;
            if attr.is_executable() {
                custom.exec.push(id);
            } else if attr.is_tls() {
                if attr.is_no_bits() {
                    custom.tbss.push(id);
                } else {
                    custom.tdata.push(id);
                }
            } else if !attr.is_writable() {
                if attr.is_alloc() {
                    custom.ro.push(id);
                } else {
                    custom.nonalloc.push(id);
                }
            } else if attr.is_no_bits() {
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
        self.section_infos.len() - regular_section_base::<P>().as_usize()
    }

    pub(crate) fn has_data_in_file(&self, section_id: OutputSectionId) -> bool {
        let attributes = self.output_info(section_id).section_attributes;
        !attributes.is_no_bits()
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

    pub(crate) fn output_index_of_nearest_section(&self, id: OutputSectionId) -> Option<u32> {
        let sections = self.output_section_indexes[..=id.as_usize()].iter().rev();

        for section in sections {
            if section.is_some() {
                return *section;
            }
        }
        None
    }

    /// Returns whether we're going to emit the specified section.
    pub(crate) fn will_emit_section(&self, id: OutputSectionId) -> bool {
        self.output_index_of_section(id).is_some()
    }

    pub(crate) fn identity(
        &self,
        section_id: OutputSectionId,
    ) -> Option<SectionIdentity<'data, P>> {
        match self.output_info(section_id).kind {
            SectionKind::Primary(identity) => Some(identity),
            SectionKind::Secondary(_) => None,
        }
    }

    pub(crate) fn name(&self, section_id: OutputSectionId) -> Option<SectionName<'data>> {
        self.identity(section_id)
            .map(|identity| identity.section_name())
    }

    pub(crate) fn display_name(&self, section_id: OutputSectionId) -> String {
        match self.output_info(section_id).kind {
            SectionKind::Primary(identity) => format!("`{identity}`"),
            SectionKind::Secondary(primary_id) => {
                format!("{} (secondary)", self.display_name(primary_id))
            }
        }
    }

    pub(crate) fn part_debug(&self, part_id: PartId) -> String {
        let alignment = part_id.alignment(self);
        format!(
            "{} align={alignment}",
            self.section_debug(part_id.output_section_id::<P>())
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

    pub(crate) fn custom_identity_to_id<'a>(
        &self,
        identity: SectionIdentity<'a, P>,
    ) -> Option<OutputSectionId> {
        self.custom_by_identity.get(&identity).copied()
    }

    /// Look up a section by name across both built-in and custom sections.
    /// Returns None if the platform cannot construct an identity from the name alone or if no
    /// matching section exists.
    pub(crate) fn section_id_by_name<'a>(&self, name: SectionName<'a>) -> Option<OutputSectionId> {
        let identity = P::section_identity_from_name(name)?;
        if let Some(id) = self.custom_by_identity.get(&identity).copied() {
            return Some(id);
        }
        let mut found = None;
        self.section_infos.for_each(|id, _| {
            if found.is_none() && self.identity(id) == Some(identity) {
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
    pub(crate) fn for_testing() -> OutputSections<'static, crate::elf::Elf64> {
        use crate::elf::Elf64;

        let output_kind = crate::output_kind::OutputKind::StaticExecutable(
            crate::args::RelocationModel::NonRelocatable,
        );
        let mut output_sections = OutputSections::<Elf64>::with_base_address(0x1000, output_kind);
        let mut add_name = |name: &'static str| {
            output_sections.add_named_section(
                SectionIdentity::new(SectionName(name.as_bytes()), ()),
                crate::alignment::MIN,
                None,
                None,
                None,
                Vec::new(),
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

impl<P: Platform> Display for SectionIdentity<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        P::fmt_section_identity(self.name, &self.format_specific, f)
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

    pub(crate) fn has_custom_phdrs(&self) -> bool {
        self.has_custom_phdrs
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
                OrderEvent::SetLocation(expr, ..) => {
                    writeln!(f, "SET_LOCATION({expr:?})")?;
                }
                OrderEvent::SetLocationRelative(expr, section_id, ..) => {
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

impl<P: Platform> Display for SectionKind<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SectionKind::Primary(identity) => write!(f, "{identity}"),
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

pub(crate) type LocationCounterIndex = usize;

#[derive(Debug, Clone)]
pub(crate) struct SectionLocationInfo<'data> {
    /// End is exclusive
    pub(crate) location_counters: (LocationCounterIndex, LocationCounterIndex),
    pub(crate) location: Option<Expression<'data>>,
    pub(crate) at_location: Option<Expression<'data>>,
    pub(crate) is_top_level: bool,
}

pub(crate) const fn num_built_in_sections<P: Platform>() -> usize {
    regular_section_base::<P>().as_usize() + P::NUM_BUILT_IN_REGULAR_SECTIONS
}
