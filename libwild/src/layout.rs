//! Traverses the graph of symbol references to figure out what sections from the input files are
//! referenced. Determines which sections need to be linked, sums their sizes decides what goes
//! where in the output file then allocates addresses for each symbol.

use crate::OutputKind;
use crate::alignment;
use crate::alignment::Alignment;
use crate::bail;
use crate::debug_assert_bail;
use crate::diagnostics::SymbolInfoPrinter;
use crate::ensure;
use crate::error::Context;
use crate::error::Error;
use crate::error::Result;
use crate::file_writer;
use crate::grouping::Group;
use crate::input_data::FileId;
use crate::input_data::InputRef;
use crate::input_data::PRELUDE_FILE_ID;
use crate::layout_rules::SectionKind;
use crate::output_section_id;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputOrder;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::parsing::InternalSymDefInfo;
use crate::parsing::SymbolPlacement;
use crate::part_id;
use crate::part_id::NUM_SINGLE_PART_SECTIONS;
use crate::part_id::PartId;
use crate::platform::Arch;
use crate::platform::Args as _;
use crate::platform::NonAddressableIndexes as _;
use crate::platform::ObjectFile;
use crate::platform::Platform;
use crate::platform::ProgramSegmentDef as _;
use crate::platform::RelaxSymbolInfo;
use crate::platform::SectionAttributes as _;
use crate::platform::SectionFlags as _;
use crate::platform::SectionHeader as _;
use crate::platform::Symbol as _;
use crate::program_segments::ProgramSegmentId;
use crate::program_segments::ProgramSegments;
use crate::resolution;
use crate::resolution::NotLoaded;
use crate::resolution::ResolvedGroup;
use crate::resolution::ResolvedLinkerScript;
use crate::resolution::ResolvedSyntheticSymbols;
use crate::resolution::SectionSlot;
use crate::resolution::UnloadedSection;
use crate::sharding::ShardKey;
use crate::string_merging::MergedStringStartAddresses;
use crate::string_merging::MergedStringsSection;
use crate::string_merging::get_merged_string_output_address;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolDebug;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use crate::symbol_db::Visibility;
use crate::symbol_db::is_mapping_symbol_name;
use crate::timing_phase;
use crate::value_flags::AtomicPerSymbolFlags;
use crate::value_flags::FlagsForSymbol as _;
use crate::value_flags::PerSymbolFlags;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use crossbeam_queue::ArrayQueue;
use crossbeam_queue::SegQueue;
use hashbrown::HashMap;
use itertools::Itertools;
use linker_utils::elf::RelocationKind;
use linker_utils::relaxation::RelaxDeltaMap;
use linker_utils::relaxation::SectionRelaxDeltas;
use linker_utils::relaxation::opt_input_to_output;
use object::SectionIndex;
use rayon::Scope;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use smallvec::SmallVec;
use std::ffi::CString;
use std::fmt::Display;
use std::mem::replace;
use std::mem::size_of;
use std::mem::swap;
use std::mem::take;
use std::num::NonZeroU32;
use std::sync::Mutex;
use std::sync::atomic;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;

pub fn compute<'data, P: Platform, A: Arch<Platform = P>>(
    symbol_db: SymbolDb<'data, A::Platform>,
    mut per_symbol_flags: PerSymbolFlags,
    mut groups: Vec<ResolvedGroup<'data, A::Platform>>,
    mut output_sections: OutputSections<'data, P>,
    output: &mut file_writer::Output,
) -> Result<Layout<'data, A::Platform>> {
    timing_phase!("Layout");

    let layout_resources_ext = <A::Platform as Platform>::layout_resources_ext(&symbol_db.groups);

    let atomic_per_symbol_flags = per_symbol_flags.borrow_atomic();

    let mut symbol_info_printer = SymbolInfoPrinter::new(symbol_db.args, &groups);
    symbol_info_printer.update(&symbol_db, &atomic_per_symbol_flags);

    let string_merge_inputs =
        crate::string_merging::StringMergeInputs::new(&mut groups, &output_sections)?;

    let (merged_strings, gc_outputs) = rayon::join(
        || {
            crate::string_merging::merge_strings(
                &string_merge_inputs,
                &output_sections,
                symbol_db.args,
            )
        },
        || {
            find_required_sections::<A>(
                groups,
                &symbol_db,
                &atomic_per_symbol_flags,
                &output_sections,
                layout_resources_ext,
            )
        },
    );
    let merged_strings = merged_strings?;
    let gc_outputs = gc_outputs?;

    let mut group_states = gc_outputs.group_states;

    let epilogue_file_id = FileId::new(group_states.len() as u32, 0);

    P::finalise_copy_relocations(&mut group_states, &symbol_db, &atomic_per_symbol_flags)?;

    let mut dynamic_symbol_definitions =
        merge_dynamic_symbol_definitions(&group_states, &symbol_db)?;

    group_states.push(GroupState {
        files: vec![FileLayoutState::Epilogue(EpilogueLayoutState::new(
            symbol_db.args,
            symbol_db.output_kind,
            &mut dynamic_symbol_definitions,
        ))],
        queue: LocalWorkQueue::new(epilogue_file_id.group()),
        common: CommonGroupState::new(&output_sections),
        num_symbols: 0,
    });

    let properties_and_attributes = P::create_layout_properties::<A>(
        symbol_db.args,
        objects_iter(&group_states).map(|obj| obj.object),
        objects_iter(&group_states).map(|obj| &obj.format_specific),
    )?;

    let finalise_sizes_resources = FinaliseSizesResources {
        dynamic_symbol_definitions: &dynamic_symbol_definitions,
        symbol_db: &symbol_db,
        merged_strings: &merged_strings,
        format_specific: &properties_and_attributes,
    };

    finalise_all_sizes(
        &mut group_states,
        &output_sections,
        &atomic_per_symbol_flags,
        &finalise_sizes_resources,
    )?;

    // Dropping `symbol_info_printer` will cause it to print. So we'll either print now, or, if we
    // got an error or panic, then we'll have printed at that point.
    symbol_info_printer.update(&symbol_db, &atomic_per_symbol_flags);
    drop(symbol_info_printer);

    let non_addressable_counts = apply_non_addressable_indexes(&mut group_states, &symbol_db)?;

    propagate_section_attributes(&group_states, &mut output_sections);

    let (output_order, program_segments) = output_sections.output_order();

    tracing::trace!(
        "Output order:\n{}",
        output_order.display::<A::Platform>(&output_sections, &program_segments)
    );

    let mut section_part_sizes = compute_total_section_part_sizes(
        &mut group_states,
        &mut output_sections,
        &output_order,
        &program_segments,
        &mut per_symbol_flags,
        gc_outputs.must_keep_sections,
        &finalise_sizes_resources,
    )?;

    let mut section_part_layouts = layout_section_parts::<A::Platform>(
        &section_part_sizes,
        &output_sections,
        &program_segments,
        &output_order,
        symbol_db.args,
    );

    if symbol_db.args.should_relax() && A::supports_size_reduction_relaxations() {
        perform_iterative_relaxation::<A>(
            &mut group_states,
            &mut section_part_sizes,
            &mut section_part_layouts,
            &output_sections,
            &program_segments,
            &output_order,
            &symbol_db,
            &per_symbol_flags,
        );
    }

    let section_layouts = layout_sections(&output_sections, &section_part_layouts);
    let mut merged_section_layouts = section_layouts.clone();
    merge_secondary_parts(&output_sections, &mut merged_section_layouts);

    output.set_size(compute_total_file_size(&section_layouts));

    let Some(FileLayoutState::Prelude(internal)) =
        &group_states.first().and_then(|g| g.files.first())
    else {
        unreachable!();
    };
    let header_info = internal.header_info.as_ref().unwrap();
    let segment_layouts = compute_segment_layout::<A::Platform>(
        &section_layouts,
        &output_sections,
        &output_order,
        &program_segments,
        header_info,
        symbol_db.args,
    )?;

    let mem_offsets: OutputSectionPartMap<u64> = starting_memory_offsets(&section_part_layouts);
    let starting_mem_offsets_by_group = compute_start_offsets_by_group(&group_states, mem_offsets);

    let merged_string_start_addresses = MergedStringStartAddresses::compute(
        &output_sections,
        &starting_mem_offsets_by_group,
        &merged_strings,
    );

    let mut symbol_resolutions = SymbolResolutions {
        resolutions: Vec::with_capacity(symbol_db.num_symbols()),
    };

    let mut res_writer = sharded_vec_writer::VecWriter::new(&mut symbol_resolutions.resolutions);

    let mut per_group_res_writers = group_states
        .iter()
        .map(|group| res_writer.take_shard(group.num_symbols))
        .collect_vec();

    let resources = FinaliseLayoutResources {
        symbol_db: &symbol_db,
        output_sections: &output_sections,
        output_order: &output_order,
        section_layouts: &section_layouts,
        merged_string_start_addresses: &merged_string_start_addresses,
        merged_strings: &merged_strings,
        per_symbol_flags: &per_symbol_flags,
        dynamic_symbol_definitions: &dynamic_symbol_definitions,
        segment_layouts: &segment_layouts,
        program_segments: &program_segments,
        format_specific: &properties_and_attributes,
    };

    let group_layouts = compute_symbols_and_layouts(
        group_states,
        starting_mem_offsets_by_group,
        &mut per_group_res_writers,
        &resources,
    )?;

    for shard in per_group_res_writers {
        res_writer
            .try_return_shard(shard)
            .context("Group resolutions not filled")?;
    }

    update_dynamic_symbol_resolutions(
        &resources,
        &group_layouts,
        &mut symbol_resolutions.resolutions,
    );
    update_defsym_symbol_resolutions(&symbol_db, &mut symbol_resolutions.resolutions)?;
    crate::gc_stats::maybe_write_gc_stats(&group_layouts, symbol_db.args)?;

    // Evaluate ASSERT commands from all linker scripts now that layout is complete.
    crate::expression_eval::evaluate_assertions(
        &symbol_db.groups,
        &section_layouts,
        &output_sections,
    )?;

    let relocation_statistics = OutputSectionMap::with_size(section_layouts.len());

    Ok(Layout {
        symbol_db,
        symbol_resolutions,
        segment_layouts,
        section_part_layouts,
        section_layouts,
        merged_section_layouts,
        group_layouts,
        output_sections,
        program_segments,
        output_order,
        non_addressable_counts,
        merged_strings,
        merged_string_start_addresses,
        has_static_tls: gc_outputs.has_static_tls,
        has_variant_pcs: gc_outputs.has_variant_pcs,
        relocation_statistics,
        per_symbol_flags,
        dynamic_symbol_definitions,
        properties_and_attributes,
    })
}

struct FinaliseSizesResources<'data, 'scope, P: Platform> {
    dynamic_symbol_definitions: &'scope [DynamicSymbolDefinition<'data, P>],
    symbol_db: &'scope SymbolDb<'data, P>,
    merged_strings: &'scope OutputSectionMap<MergedStringsSection<'data>>,
    format_specific: &'scope P::LayoutExt,
}

/// Update resolutions for defsym symbols that reference other symbols.
fn update_defsym_symbol_resolutions<'data, P: Platform>(
    symbol_db: &SymbolDb<'data, P>,
    resolutions: &mut [Option<Resolution<P>>],
) -> Result {
    verbose_timing_phase!("Update symdef resolutions");

    for group in &symbol_db.groups {
        let mut symbol_id = group.symbol_id_range().start();

        match group {
            Group::Prelude(prelude) => {
                for def_info in &prelude.symbol_definitions {
                    update_defsym_symbol_resolution(symbol_id, def_info, symbol_db, resolutions)?;
                    symbol_id = symbol_id.next();
                }
            }
            Group::LinkerScripts(scripts) => {
                for script in scripts {
                    for def_info in &script.parsed.symbol_defs {
                        update_defsym_symbol_resolution(
                            symbol_id,
                            def_info,
                            symbol_db,
                            resolutions,
                        )?;
                        symbol_id = symbol_id.next();
                    }
                }
            }
            Group::Objects(_) | Group::SyntheticSymbols(_) => {}
            #[cfg(feature = "plugins")]
            Group::LtoInputs(_) => {}
        }
    }

    Ok(())
}

fn update_defsym_symbol_resolution<'data, P: Platform>(
    symbol_id: SymbolId,
    def_info: &InternalSymDefInfo,
    symbol_db: &SymbolDb<'data, P>,
    resolutions: &mut [Option<Resolution<P>>],
) -> Result {
    let SymbolPlacement::DefsymSymbol(target_name, offset) = def_info.placement else {
        return Ok(());
    };

    if !symbol_db.is_canonical(symbol_id) {
        return Ok(());
    }

    let Some(target_symbol_id) =
        symbol_db.get_unversioned(&UnversionedSymbolName::prehashed(target_name.as_bytes()))
    else {
        return Err(symbol_db.missing_defsym_target_error(def_info.name, target_name));
    };

    let canonical_target_id = symbol_db.definition(target_symbol_id);
    if let Some(target_value) = resolutions[canonical_target_id.as_usize()]
        .as_ref()
        .map(|r| r.raw_value)
        && let Some(resolution) = &mut resolutions[symbol_id.as_usize()]
    {
        // Apply the offset from the defsym expression.
        resolution.raw_value = (target_value as i64).wrapping_add(offset) as u64;
    }

    Ok(())
}

/// Update resolutions for all dynamic symbols that our output file defines.
fn update_dynamic_symbol_resolutions<'data, P: Platform>(
    resources: &FinaliseLayoutResources<'_, 'data, P>,
    layouts: &[GroupLayout<'data, P>],
    resolutions: &mut [Option<Resolution<P>>],
) {
    timing_phase!("Update dynamic symbol resolutions");

    let Some(FileLayout::Epilogue(epilogue)) = layouts.last().and_then(|g| g.files.last()) else {
        panic!("Epilogue should be the last file");
    };

    for (index, sym) in resources.dynamic_symbol_definitions.iter().enumerate() {
        let dynamic_symbol_index = NonZeroU32::try_from(epilogue.dynsym_start_index + index as u32)
            .expect("Dynamic symbol definitions should start > 0");
        if let Some(res) = &mut resolutions[sym.symbol_id.as_usize()] {
            res.dynamic_symbol_index = Some(dynamic_symbol_index);
        }
    }
}

fn finalise_all_sizes<'data, P: Platform>(
    group_states: &mut [GroupState<'data, P>],
    output_sections: &OutputSections<P>,
    per_symbol_flags: &AtomicPerSymbolFlags,
    resources: &FinaliseSizesResources<'data, '_, P>,
) -> Result {
    timing_phase!("Finalise per-object sizes");

    group_states.par_iter_mut().try_for_each(|state| {
        verbose_timing_phase!("Finalise sizes for group");
        state.finalise_sizes(output_sections, per_symbol_flags, resources)
    })
}

fn merge_dynamic_symbol_definitions<'data, P: Platform>(
    group_states: &[GroupState<'data, P>],
    symbol_db: &SymbolDb<'data, P>,
) -> Result<Vec<DynamicSymbolDefinition<'data, P>>> {
    timing_phase!("Merge dynamic symbol definitions");

    let mut dynamic_symbol_definitions = Vec::new();
    for group in group_states {
        dynamic_symbol_definitions.extend(group.common.dynamic_symbol_definitions.iter().copied());
    }

    append_prelude_defsym_dynamic_symbols(
        group_states,
        symbol_db,
        &mut dynamic_symbol_definitions,
    )?;

    Ok(dynamic_symbol_definitions)
}

fn append_prelude_defsym_dynamic_symbols<'data, P: Platform>(
    group_states: &[GroupState<'data, P>],
    symbol_db: &SymbolDb<'data, P>,
    dynamic_symbol_definitions: &mut Vec<DynamicSymbolDefinition<'data, P>>,
) -> Result {
    if symbol_db.output_kind.needs_dynsym()
        && let Some(first_group) = group_states.first()
        && let Some(FileLayoutState::Prelude(prelude)) = first_group.files.first()
    {
        let symbol_id_range = prelude.symbol_id_range;
        for (index, def_info) in prelude
            .internal_symbols
            .symbol_definitions
            .iter()
            .enumerate()
        {
            if !matches!(def_info.placement, SymbolPlacement::DefsymSymbol(_, _)) {
                continue;
            }

            let symbol_id = symbol_id_range.offset_to_id(index);
            if !symbol_db.is_canonical(symbol_id)
                || dynamic_symbol_definitions
                    .iter()
                    .any(|def| def.symbol_id == symbol_id)
            {
                continue;
            }

            dynamic_symbol_definitions
                .push(P::create_dynamic_symbol_definition(symbol_db, symbol_id)?);
        }
    }

    Ok(())
}

fn objects_iter<'groups, 'data, P: Platform>(
    group_states: &'groups [GroupState<'data, P>],
) -> impl Iterator<Item = &'groups ObjectLayoutState<'data, P>> + Clone {
    group_states.iter().flat_map(|group| {
        group.files.iter().filter_map(|file| match file {
            FileLayoutState::Object(object) => Some(object),
            _ => None,
        })
    })
}

fn compute_total_file_size(section_layouts: &OutputSectionMap<OutputRecordLayout>) -> u64 {
    let mut file_size = 0;
    section_layouts.for_each(|_, s| file_size = file_size.max(s.file_offset + s.file_size));
    file_size as u64
}

/// Information about what goes where. Also includes relocation data, since that's computed at the
/// same time.
#[derive(Debug)]
pub struct Layout<'data, P: Platform> {
    pub(crate) symbol_db: SymbolDb<'data, P>,
    pub(crate) symbol_resolutions: SymbolResolutions<P>,
    pub(crate) section_part_layouts: OutputSectionPartMap<OutputRecordLayout>,

    pub(crate) section_layouts: OutputSectionMap<OutputRecordLayout>,

    /// This is like `section_layouts`, but where secondary sections are merged into their primary
    /// section. Values for secondary sections are reset to 0 and should not be used.
    pub(crate) merged_section_layouts: OutputSectionMap<OutputRecordLayout>,

    pub(crate) group_layouts: Vec<GroupLayout<'data, P>>,
    pub(crate) segment_layouts: SegmentLayouts,
    pub(crate) output_sections: OutputSections<'data, P>,
    pub(crate) program_segments: ProgramSegments<P::ProgramSegmentDef>,
    pub(crate) output_order: OutputOrder,
    pub(crate) non_addressable_counts: P::NonAddressableCounts,
    pub(crate) merged_strings: OutputSectionMap<MergedStringsSection<'data>>,
    pub(crate) merged_string_start_addresses: MergedStringStartAddresses,
    pub(crate) relocation_statistics: OutputSectionMap<AtomicU64>,
    pub(crate) has_static_tls: bool,
    pub(crate) has_variant_pcs: bool,
    pub(crate) per_symbol_flags: PerSymbolFlags,
    pub(crate) dynamic_symbol_definitions: Vec<DynamicSymbolDefinition<'data, P>>,
    pub(crate) properties_and_attributes: P::LayoutExt,
}

#[derive(Debug)]
pub(crate) struct SegmentLayouts {
    /// The layout of each of our segments. Segments containing no active output sections will have
    /// been filtered, so don't try to index this by our internal segment IDs.
    pub(crate) segments: Vec<SegmentLayout>,
    pub(crate) tls_layout: Option<OutputRecordLayout>,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct SegmentLayout {
    pub(crate) id: ProgramSegmentId,
    pub(crate) sizes: OutputRecordLayout,
}

#[derive(Debug)]
pub(crate) struct SymbolResolutions<P: Platform> {
    resolutions: Vec<Option<Resolution<P>>>,
}

pub(crate) enum FileLayout<'data, P: Platform> {
    Prelude(PreludeLayout<'data, P>),
    Object(ObjectLayout<'data, P>),
    Dynamic(DynamicLayout<'data, P>),
    SyntheticSymbols(SyntheticSymbolsLayout<'data>),
    Epilogue(EpilogueLayout<P>),
    NotLoaded,
    LinkerScript(LinkerScriptLayoutState<'data>),
}

/// Address information for a symbol.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct Resolution<P: Platform> {
    /// An address or absolute value.
    pub(crate) raw_value: u64,

    pub(crate) dynamic_symbol_index: Option<NonZeroU32>,

    pub(crate) flags: ValueFlags,

    pub(crate) format_specific: P::ResolutionExt,
}

/// Address information for a section.
#[derive(derive_more::Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct SectionResolution {
    #[debug("0x{address:x}")]
    address: u64,
}

impl SectionResolution {
    /// Returns a resolution for a section that we didn't load, or for which we don't have an
    /// address (e.g. string-merge sections).
    fn none() -> SectionResolution {
        SectionResolution { address: u64::MAX }
    }

    pub(crate) fn address(self) -> Option<u64> {
        if self.address == u64::MAX {
            None
        } else {
            Some(self.address)
        }
    }

    /// Converts to a resolution compatible with what's used for symbols.
    pub(crate) fn full_resolution<P: Platform>(self) -> Option<Resolution<P>> {
        let address = self.address()?;
        Some(Resolution {
            raw_value: address,
            dynamic_symbol_index: None,
            flags: ValueFlags::empty(),
            format_specific: Default::default(),
        })
    }
}

pub(crate) enum FileLayoutState<'data, P: Platform> {
    Prelude(PreludeLayoutState<'data, P>),
    Object(ObjectLayoutState<'data, P>),
    Dynamic(DynamicLayoutState<'data, P>),
    NotLoaded(NotLoaded),
    SyntheticSymbols(SyntheticSymbolsLayoutState<'data>),
    Epilogue(EpilogueLayoutState<P>),
    LinkerScript(LinkerScriptLayoutState<'data>),
}

/// Data that doesn't come from any input files, but needs to be written by the linker.
pub(crate) struct PreludeLayoutState<'data, P: Platform> {
    file_id: FileId,
    symbol_id_range: SymbolIdRange,
    internal_symbols: InternalSymbols<'data>,
    entry_symbol_id: Option<SymbolId>,
    identity: String,
    header_info: Option<HeaderInfo>,
    dynamic_linker: Option<CString>,
    pub(crate) format_specific: P::PreludeLayoutStateExt,
}

pub(crate) struct SyntheticSymbolsLayoutState<'data> {
    file_id: FileId,
    symbol_id_range: SymbolIdRange,
    internal_symbols: InternalSymbols<'data>,
}

pub(crate) struct EpilogueLayoutState<P: Platform> {
    format_specific: P::EpilogueLayoutExt,
}

#[derive(Debug)]
pub(crate) struct LinkerScriptLayoutState<'data> {
    file_id: FileId,
    input: InputRef<'data>,
    symbol_id_range: SymbolIdRange,
    pub(crate) internal_symbols: InternalSymbols<'data>,
}

#[derive(Debug)]
pub(crate) struct SyntheticSymbolsLayout<'data> {
    pub(crate) internal_symbols: InternalSymbols<'data>,
}

#[derive(Debug)]
pub(crate) struct EpilogueLayout<P: Platform> {
    pub(crate) format_specific: P::EpilogueLayoutExt,
    pub(crate) dynsym_start_index: u32,
}

#[derive(Debug)]
pub(crate) struct ObjectLayout<'data, P: Platform> {
    pub(crate) input: InputRef<'data>,
    pub(crate) file_id: FileId,
    pub(crate) object: &'data P::File<'data>,
    pub(crate) sections: Vec<SectionSlot>,
    pub(crate) relocations: P::RelocationSections,
    pub(crate) section_resolutions: Vec<SectionResolution>,
    pub(crate) symbol_id_range: SymbolIdRange,
    /// SFrame section ranges for this object, relative to the start of the .sframe output section.
    pub(crate) sframe_ranges: Vec<std::ops::Range<usize>>,
    /// Sparse map from section index to relaxation delta details.
    pub(crate) section_relax_deltas: RelaxDeltaMap,
}

#[derive(Debug)]
pub(crate) struct PreludeLayout<'data, P: Platform> {
    pub(crate) entry_symbol_id: Option<SymbolId>,
    pub(crate) identity: String,
    pub(crate) header_info: HeaderInfo,
    pub(crate) internal_symbols: InternalSymbols<'data>,
    pub(crate) dynamic_linker: Option<CString>,
    pub(crate) format_specific: P::PreludeLayoutExt,
}

#[derive(Debug)]
pub(crate) struct InternalSymbols<'data> {
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo<'data>>,
    pub(crate) start_symbol_id: SymbolId,
}

#[derive(Debug)]
pub(crate) struct DynamicLayout<'data, P: Platform> {
    pub(crate) file_id: FileId,
    input: InputRef<'data>,

    /// The name we'll put into the binary to tell the dynamic loader what to load.
    pub(crate) lib_name: &'data [u8],

    pub(crate) symbol_id_range: SymbolIdRange,

    pub(crate) object: &'data P::File<'data>,

    pub(crate) format_specific_layout: P::DynamicLayoutExt<'data>,
}

pub(crate) trait HandlerData {
    fn symbol_id_range(&self) -> SymbolIdRange;

    fn file_id(&self) -> FileId;
}

trait SymbolRequestHandler<'data, P: Platform>: std::fmt::Display + HandlerData {
    fn finalise_symbol_sizes(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        symbol_flags: &AtomicPerSymbolFlags,
        resources: &FinaliseSizesResources<'data, '_, P>,
    ) -> Result {
        let symbol_db = resources.symbol_db;

        let _file_span = symbol_db.args.common().trace_span_for_file(self.file_id());
        let symbol_id_range = self.symbol_id_range();

        for (local_index, atomic_flags) in symbol_flags.range(symbol_id_range).iter().enumerate() {
            let symbol_id = symbol_id_range.offset_to_id(local_index);
            if !symbol_db.is_canonical(symbol_id) {
                continue;
            }
            let flags = atomic_flags.get();

            P::finalise_sizes_for_symbol(common, symbol_db, symbol_id, flags)?;

            P::allocate_resolution(flags, &mut common.mem_sizes, symbol_db.output_kind);

            if symbol_db.args.common().verify_allocation_consistency {
                verify_consistent_allocation_handling::<P>(flags, symbol_db.output_kind)?;
            }
        }

        Ok(())
    }

    fn load_symbol<'scope, A: Arch<Platform = P>>(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        symbol_id: SymbolId,
        resources: &'scope GraphResources<'data, 'scope, P>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result;
}

pub(crate) fn export_dynamic<'data, P: Platform>(
    common: &mut CommonGroupState<'data, P>,
    symbol_id: SymbolId,
    symbol_db: &SymbolDb<'data, P>,
) -> Result {
    common
        .dynamic_symbol_definitions
        .push(P::create_dynamic_symbol_definition(symbol_db, symbol_id)?);

    Ok(())
}

/// Computes how much to allocate for a particular resolution. This is intended for debug assertions
/// when we're writing, to make sure that we would have allocated memory before we write.
pub(crate) fn compute_allocations<P: Platform>(
    resolution: &Resolution<P>,
    output_kind: OutputKind,
) -> OutputSectionPartMap<u64> {
    let mut sizes = OutputSectionPartMap::with_size(NUM_SINGLE_PART_SECTIONS as usize);
    P::allocate_resolution(resolution.flags, &mut sizes, output_kind);
    sizes
}

impl<'data, P: Platform> HandlerData for ObjectLayoutState<'data, P> {
    fn file_id(&self) -> FileId {
        self.file_id
    }

    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }
}

impl<'data, P: Platform> SymbolRequestHandler<'data, P> for ObjectLayoutState<'data, P> {
    fn load_symbol<'scope, A: Arch<Platform = P>>(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope, P>,
        queue: &mut LocalWorkQueue,
        _scope: &Scope<'scope>,
    ) -> Result {
        debug_assert_bail!(
            resources.symbol_db.is_canonical(symbol_id),
            "Tried to load symbol in a file that doesn't hold the definition: {}",
            resources.symbol_debug(symbol_id)
        );

        let object_symbol_index = self.symbol_id_range.id_to_input(symbol_id);
        let local_symbol = self.object.symbol(object_symbol_index)?;

        if let Some(section_id) = self
            .object
            .symbol_section(local_symbol, object_symbol_index)?
        {
            queue
                .local_work
                .push(WorkItem::LoadSection(SectionLoadRequest::new(
                    self.file_id,
                    section_id,
                )));
        } else if let Some(common_symbol) = local_symbol.as_common() {
            common.allocate(common_symbol.part_id, common_symbol.size);
        }

        Ok(())
    }
}

impl<'data, P: Platform> HandlerData for DynamicLayoutState<'data, P> {
    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }

    fn file_id(&self) -> FileId {
        self.file_id
    }
}

impl<'data, P: Platform> SymbolRequestHandler<'data, P> for DynamicLayoutState<'data, P> {
    fn load_symbol<'scope, A: Arch<Platform = P>>(
        &mut self,
        _common: &mut CommonGroupState<'data, P>,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope, P>,
        _queue: &mut LocalWorkQueue,
        _scope: &Scope<'scope>,
    ) -> Result {
        let local_index = object::SymbolIndex(symbol_id.to_offset(self.symbol_id_range()));
        self.object
            .dynamic_symbol_used(local_index, &mut self.format_specific_state)?;

        // Check for arch-specific VARIANT_PCS flags.
        if A::is_symbol_variant_pcs(self.object, local_index) {
            resources
                .has_variant_pcs
                .store(true, atomic::Ordering::Relaxed);
        }

        Ok(())
    }
}

impl<P: Platform> HandlerData for PreludeLayoutState<'_, P> {
    fn file_id(&self) -> FileId {
        self.file_id
    }

    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }
}

impl<'data, P: Platform> SymbolRequestHandler<'data, P> for PreludeLayoutState<'data, P> {
    fn load_symbol<'scope, A: Arch<Platform = P>>(
        &mut self,
        _common: &mut CommonGroupState<'data, P>,
        _symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope, P>,
        _queue: &mut LocalWorkQueue,
        _scope: &Scope<'scope>,
    ) -> Result {
        Ok(())
    }
}

impl HandlerData for LinkerScriptLayoutState<'_> {
    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }

    fn file_id(&self) -> FileId {
        self.file_id
    }
}

impl<'data, P: Platform> SymbolRequestHandler<'data, P> for LinkerScriptLayoutState<'data> {
    fn load_symbol<'scope, A: Arch<Platform = P>>(
        &mut self,
        _common: &mut CommonGroupState<'data, P>,
        _symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope, P>,
        _queue: &mut LocalWorkQueue,
        _scope: &Scope<'scope>,
    ) -> Result {
        Ok(())
    }
}

impl HandlerData for SyntheticSymbolsLayoutState<'_> {
    fn file_id(&self) -> FileId {
        self.file_id
    }

    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }
}

impl<'data, P: Platform> SymbolRequestHandler<'data, P> for SyntheticSymbolsLayoutState<'data> {
    fn load_symbol<'scope, A: Arch<Platform = P>>(
        &mut self,
        _common: &mut CommonGroupState<'data, P>,
        symbol_id: SymbolId,
        resources: &'scope GraphResources<'data, 'scope, P>,
        _queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result {
        let def_info =
            &self.internal_symbols.symbol_definitions[self.symbol_id_range.id_to_offset(symbol_id)];

        if let Some(output_section_id) = def_info.section_id() {
            // We've gotten a request to load a __start_ / __stop_ symbol, sent requests to load all
            // sections that would go into that section.
            let sections = resources.start_stop_sections.get(output_section_id);
            while let Some(request) = sections.pop() {
                resources.send_work::<A>(
                    request.file_id,
                    WorkItem::LoadSection(request),
                    resources,
                    scope,
                );
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct CommonGroupState<'data, P: Platform> {
    mem_sizes: OutputSectionPartMap<u64>,

    section_attributes: OutputSectionMap<Option<P::SectionAttributes>>,

    /// Dynamic symbols that need to be defined. Because of the ordering requirements for symbol
    /// hashes, these get defined by the epilogue. The object on which a particular dynamic symbol
    /// is stored is non-deterministic and is whichever object first requested export of that
    /// symbol. That's OK though because the epilogue will sort all dynamic symbols.
    dynamic_symbol_definitions: Vec<DynamicSymbolDefinition<'data, P>>,

    pub(crate) format_specific: P::CommonGroupStateExt,
}

impl<'data, P: Platform> CommonGroupState<'data, P> {
    fn new(output_sections: &OutputSections<P>) -> Self {
        Self {
            mem_sizes: output_sections.new_part_map(),
            section_attributes: output_sections.new_section_map(),
            dynamic_symbol_definitions: Default::default(),
            format_specific: Default::default(),
        }
    }

    fn validate_sizes(&self) -> Result {
        P::validate_sizes(&self.mem_sizes)
    }

    fn finalise_layout(
        &self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
    ) -> u32 {
        // strtab
        let offset = memory_offsets.get_mut(part_id::STRTAB);
        let strtab_offset_start = (*offset
            - section_layouts.get(output_section_id::STRTAB).mem_offset)
            .try_into()
            .expect("Symbol string table overflowed 32 bits");
        *offset += self.mem_sizes.get(part_id::STRTAB);

        // symtab
        memory_offsets.increment(
            part_id::SYMTAB_LOCAL,
            *self.mem_sizes.get(part_id::SYMTAB_LOCAL),
        );
        memory_offsets.increment(
            part_id::SYMTAB_GLOBAL,
            *self.mem_sizes.get(part_id::SYMTAB_GLOBAL),
        );

        strtab_offset_start
    }

    pub(crate) fn allocate(&mut self, part_id: PartId, size: u64) {
        self.mem_sizes.increment(part_id, size);
    }

    /// Allocate resources and update attributes based on a section having been loaded.
    fn section_loaded(
        &mut self,
        part_id: PartId,
        header: &P::SectionHeader,
        section: Section,
        output_sections: &OutputSections<P>,
    ) {
        self.allocate(part_id, section.capacity(output_sections));
        self.store_section_attributes(part_id, header);
    }

    fn store_section_attributes(&mut self, part_id: PartId, header: &P::SectionHeader) {
        let existing_attributes = self.section_attributes.get_mut(part_id.output_section_id());

        let new_attributes = P::section_attributes(header);

        if let Some(existing) = existing_attributes {
            existing.merge(new_attributes);
        } else {
            *existing_attributes = Some(new_attributes);
        }
    }
}

pub(crate) struct ObjectLayoutState<'data, P: Platform> {
    pub(crate) input: InputRef<'data>,
    pub(crate) file_id: FileId,
    pub(crate) symbol_id_range: SymbolIdRange,
    pub(crate) object: &'data P::File<'data>,

    /// Info about each of our sections. Indexed the same as the sections in the input object.
    pub(crate) sections: Vec<SectionSlot>,

    /// Mapping from sections to their corresponding relocation section.
    pub(crate) relocations: P::RelocationSections,

    pub(crate) format_specific: P::ObjectLayoutStateExt<'data>,

    /// Sparse map from section index to relaxation delta details, built during `finalise_sizes`
    /// and later transferred to `ObjectLayout`.
    section_relax_deltas: RelaxDeltaMap,
}

#[derive(Debug, Default)]
pub(crate) struct LocalWorkQueue {
    /// The index of the worker that owns this queue.
    index: usize,

    /// Work that needs to be processed by the worker that owns this queue.
    local_work: Vec<WorkItem>,
}

pub(crate) struct DynamicLayoutState<'data, P: Platform> {
    pub(crate) object: &'data P::File<'data>,
    input: InputRef<'data>,
    file_id: FileId,
    pub(crate) symbol_id_range: SymbolIdRange,
    pub(crate) lib_name: &'data [u8],

    pub(crate) format_specific_state: P::DynamicLayoutStateExt<'data>,
}

#[derive(derive_more::Debug, Clone, Copy)]
pub(crate) struct DynamicSymbolDefinition<'data, P: Platform> {
    pub(crate) symbol_id: SymbolId,
    #[debug("{:?}", String::from_utf8_lossy(name))]
    pub(crate) name: &'data [u8],
    pub(crate) format_specific: P::DynamicSymbolDefinitionExt,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Section {
    pub(crate) index: object::SectionIndex,
    pub(crate) part_id: PartId,
    /// Size in the output. This starts as the input section size, then may be reduced by
    /// relaxation-induced byte deletions during `scan_relaxations`.
    pub(crate) size: u64,
    pub(crate) flags: ValueFlags,
    pub(crate) is_writable: bool,
}

#[derive(Debug)]
pub(crate) struct GroupLayout<'data, P: Platform> {
    pub(crate) files: Vec<FileLayout<'data, P>>,

    /// The offset in .dynstr at which we'll start writing.
    pub(crate) dynstr_start_offset: u32,

    /// The offset in .strtab at which we'll start writing.
    pub(crate) strtab_start_offset: u32,

    pub(crate) mem_sizes: OutputSectionPartMap<u64>,
    pub(crate) file_sizes: OutputSectionPartMap<usize>,

    pub(crate) format_specific: P::GroupLayoutExt,
}

#[derive(Debug)]
pub(crate) struct GroupState<'data, P: Platform> {
    queue: LocalWorkQueue,
    pub(crate) files: Vec<FileLayoutState<'data, P>>,
    pub(crate) common: CommonGroupState<'data, P>,
    num_symbols: usize,
}

/// The sizes and positions of either a segment or an output section. Note, we use usize for file
/// offsets and sizes, since we mmap our output file, so we're frequently working with in-memory
/// slices. This means that if we were linking on a 32 bit system that we'd be limited to file
/// offsets that were 32 bits. This isn't a loss though, since we couldn't mmap an output file where
/// that would be a problem on a 32 bit system.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutputRecordLayout {
    pub(crate) file_size: usize,
    pub(crate) mem_size: u64,
    pub(crate) alignment: Alignment,
    pub(crate) file_offset: usize,
    pub(crate) mem_offset: u64,
}

pub(crate) struct GraphResources<'data, 'scope, P: Platform> {
    pub(crate) symbol_db: &'scope SymbolDb<'data, P>,

    output_sections: &'scope OutputSections<'data, P>,

    worker_slots: Vec<Mutex<WorkerSlot<'data, P>>>,

    errors: Mutex<Vec<Error>>,

    pub(crate) per_symbol_flags: &'scope AtomicPerSymbolFlags<'scope>,

    /// Sections that we'll keep, even if their total size is zero.
    must_keep_sections: OutputSectionMap<AtomicBool>,

    pub(crate) has_static_tls: AtomicBool,

    has_variant_pcs: AtomicBool,

    /// For each OutputSectionId, this tracks a list of sections that should be loaded if that
    /// section gets referenced. The sections here will only be those that are eligible for having
    /// __start_ / __stop_ symbols. i.e. sections that don't start their names with a ".".
    start_stop_sections: OutputSectionMap<SegQueue<SectionLoadRequest>>,

    /// The number of groups that haven't yet completed activation.
    activations_remaining: AtomicUsize,

    /// Groups that cannot be processed until all groups have completed activation.
    delay_processing: ArrayQueue<GroupState<'data, P>>,

    pub(crate) layout_resources_ext: P::LayoutResourcesExt<'data>,
}

pub(crate) struct FinaliseLayoutResources<'scope, 'data, P: Platform> {
    pub(crate) symbol_db: &'scope SymbolDb<'data, P>,
    pub(crate) per_symbol_flags: &'scope PerSymbolFlags,
    output_sections: &'scope OutputSections<'data, P>,
    output_order: &'scope OutputOrder,
    pub(crate) section_layouts: &'scope OutputSectionMap<OutputRecordLayout>,
    merged_string_start_addresses: &'scope MergedStringStartAddresses,
    merged_strings: &'scope OutputSectionMap<MergedStringsSection<'data>>,
    dynamic_symbol_definitions: &'scope Vec<DynamicSymbolDefinition<'data, P>>,
    segment_layouts: &'scope SegmentLayouts,
    program_segments: &'scope ProgramSegments<P::ProgramSegmentDef>,
    format_specific: &'scope P::LayoutExt,
}

#[derive(Copy, Clone, Debug)]
enum WorkItem {
    /// The symbol's resolution flags have been made non-empty. The object that owns the symbol
    /// should perform any additional actions required, e.g. load the section that contains the
    /// symbol and process any relocations for that section.
    LoadGlobalSymbol(SymbolId),

    /// A direct reference to a dynamic symbol has been encountered. The symbol should be defined in
    /// BSS with a copy relocation.
    CopyRelocateSymbol(SymbolId),

    /// A request to load a particular section.
    LoadSection(SectionLoadRequest),

    /// Requests that the specified symbol be exported as a dynamic symbol. Will be ignored if the
    /// object that defines the symbol is not loaded or is itself a shared object.
    ExportDynamic(SymbolId),
}

#[derive(Copy, Clone, Debug)]
struct SectionLoadRequest {
    file_id: FileId,

    /// The offset of the section within the file's sections. i.e. the same as
    /// object::SectionIndex, but stored as a u32 for compactness.
    section_index: u32,
}

impl WorkItem {
    fn file_id<P: Platform>(self, symbol_db: &SymbolDb<P>) -> FileId {
        match self {
            WorkItem::LoadGlobalSymbol(s) | WorkItem::CopyRelocateSymbol(s) => {
                symbol_db.file_id_for_symbol(s)
            }
            WorkItem::LoadSection(s) => s.file_id,
            WorkItem::ExportDynamic(symbol_id) => symbol_db.file_id_for_symbol(symbol_id),
        }
    }
}

impl<'data, P: Platform> Layout<'data, P> {
    pub(crate) fn prelude(&self) -> &PreludeLayout<'data, P> {
        let Some(FileLayout::Prelude(i)) = self.group_layouts.first().and_then(|g| g.files.first())
        else {
            panic!("Prelude layout not found at expected offset");
        };
        i
    }

    pub(crate) fn args(&self) -> &'data P::Args {
        self.symbol_db.args
    }

    pub(crate) fn symbol_debug<'layout>(
        &'layout self,
        symbol_id: SymbolId,
    ) -> SymbolDebug<'layout, 'data, P> {
        self.symbol_db
            .symbol_debug(&self.per_symbol_flags, symbol_id)
    }

    #[inline(always)]
    pub(crate) fn merged_symbol_resolution(&self, symbol_id: SymbolId) -> Option<Resolution<P>> {
        self.local_symbol_resolution(self.symbol_db.definition(symbol_id))
            .copied()
            .map(|mut res| {
                res.flags.merge(
                    self.symbol_db
                        .flags_for_symbol(&self.per_symbol_flags, symbol_id),
                );
                res
            })
    }

    pub(crate) fn local_symbol_resolution(&self, symbol_id: SymbolId) -> Option<&Resolution<P>> {
        self.symbol_resolutions.resolutions[symbol_id.as_usize()].as_ref()
    }

    pub(crate) fn resolutions_in_range(
        &self,
        range: SymbolIdRange,
    ) -> impl Iterator<Item = (SymbolId, Option<&Resolution<P>>)> {
        self.symbol_resolutions.resolutions[range.as_usize()]
            .iter()
            .enumerate()
            .map(move |(i, res)| (range.offset_to_id(i), res.as_ref()))
    }

    pub(crate) fn entry_symbol_address(&self) -> Result<u64> {
        let Some(symbol_id) = self.prelude().entry_symbol_id else {
            if self.symbol_db.output_kind == OutputKind::SharedObject {
                // Shared objects don't have an implicit entry point.
                return Ok(0);
            }

            // There's no entry point specified, set it to the start of .text. This is pretty weird,
            // but it's what GNU ld does.
            let text_layout = self.section_layouts.get(output_section_id::TEXT);
            if text_layout.mem_size == 0 {
                crate::error::warning(
                    "cannot find entry symbol `_start` and .text is empty, not setting entry point",
                );

                return Ok(0);
            }

            crate::error::warning(&format!(
                "cannot find entry symbol `_start`, defaulting to 0x{}",
                text_layout.mem_offset
            ));
            return Ok(text_layout.mem_offset);
        };

        let resolution = self.local_symbol_resolution(symbol_id).with_context(|| {
            format!(
                "Entry point symbol was defined, but didn't get loaded. {}",
                self.symbol_debug(symbol_id)
            )
        })?;

        if !resolution.flags().is_address() && !resolution.flags().is_absolute() {
            bail!(
                "Entry point must be an address or absolute value. {}",
                self.symbol_debug(symbol_id)
            );
        }

        Ok(resolution.value())
    }

    pub(crate) fn tls_start_address(&self) -> u64 {
        // If we don't have a TLS segment then the value we return won't really matter.
        self.segment_layouts
            .tls_layout
            .as_ref()
            .map_or(0, |seg| seg.mem_offset)
    }

    /// Returns the memory address of the end of the TLS segment including any padding required to
    /// make sure that the TCB will be usize-aligned.
    pub(crate) fn tls_end_address(&self) -> u64 {
        self.segment_layouts.tls_layout.as_ref().map_or(0, |seg| {
            seg.alignment.align_up(seg.mem_offset + seg.mem_size)
        })
    }

    /// Returns the memory address of the start of the TLS segment used by the AArch64.
    pub(crate) fn tls_start_address_aarch64(&self) -> u64 {
        self.segment_layouts.tls_layout.as_ref().map_or(0, |seg| {
            // Two words at TP are reserved by the arch.
            seg.alignment.align_down(seg.mem_offset - 2 * 8)
        })
    }

    pub(crate) fn layout_data(&self) -> linker_layout::Layout {
        let files = self
            .group_layouts
            .iter()
            .flat_map(|group| {
                group.files.iter().filter_map(|file| match file {
                    FileLayout::Object(obj) => Some(linker_layout::InputFile {
                        path: obj.input.file.filename.clone(),
                        archive_entry: obj.input.entry.as_ref().map(|e| {
                            linker_layout::ArchiveEntryInfo {
                                range: e.byte_range(),
                                identifier: e.identifier.as_slice().to_owned(),
                            }
                        }),
                        sections: obj
                            .section_resolutions
                            .iter()
                            .zip(obj.object.section_iter())
                            .zip(&obj.sections)
                            .map(|((res, section), section_slot)| {
                                (matches!(section_slot, SectionSlot::Loaded(..))
                                    && section.is_alloc()
                                    && obj.object.section_size(section).is_ok_and(|s| s > 0))
                                .then(|| {
                                    let address = res.address;
                                    let size = match section_slot {
                                        SectionSlot::Loaded(sec) => sec.size,
                                        _ => obj.object.section_size(section).unwrap(),
                                    };
                                    linker_layout::Section {
                                        mem_range: address..(address + size),
                                    }
                                })
                            })
                            .collect(),
                        temporary: obj.input.file.modifiers.temporary,
                    }),
                    _ => None,
                })
            })
            .collect();
        linker_layout::Layout { files }
    }

    pub(crate) fn flags_for_symbol(&self, symbol_id: SymbolId) -> ValueFlags {
        self.symbol_db
            .flags_for_symbol(&self.per_symbol_flags, symbol_id)
    }

    pub(crate) fn file_layout(&self, file_id: FileId) -> &FileLayout<'data, P> {
        let group_layout = &self.group_layouts[file_id.group()];
        &group_layout.files[file_id.file()]
    }

    /// Returns the base address of the global offset table. This needs to be consistent with the
    /// symbol `_GLOBAL_OFFSET_TABLE_`.
    pub(crate) fn got_base(&self) -> u64 {
        let got_layout = self.section_layouts.get(output_section_id::GOT);
        got_layout.mem_offset
    }

    /// Returns whether we're going to output the .gnu.version section.
    pub(crate) fn gnu_version_enabled(&self) -> bool {
        self.section_part_layouts
            .get(part_id::GNU_VERSION)
            .file_size
            > 0
    }
}

fn layout_sections<P: Platform>(
    output_sections: &OutputSections<P>,
    section_part_layouts: &OutputSectionPartMap<OutputRecordLayout>,
) -> OutputSectionMap<OutputRecordLayout> {
    section_part_layouts.merge_parts(|section_id, layouts| {
        let info = output_sections.section_infos.get(section_id);
        let mut file_offset = usize::MAX;
        let mut mem_offset = u64::MAX;
        let mut file_end = 0;
        let mut mem_end = 0;
        let mut alignment = info.min_alignment;

        for part in layouts {
            file_offset = file_offset.min(part.file_offset);
            mem_offset = mem_offset.min(part.mem_offset);
            file_end = file_end.max(part.file_offset + part.file_size);
            mem_end = mem_end.max(part.mem_offset + part.mem_size);
            if part.mem_size > 0 {
                alignment = alignment.max(part.alignment);
            }
        }
        OutputRecordLayout {
            file_size: file_end - file_offset,
            mem_size: mem_end - mem_offset,
            alignment,
            file_offset,
            mem_offset,
        }
    })
}

fn merge_secondary_parts<P: Platform>(
    output_sections: &OutputSections<P>,
    section_layouts: &mut OutputSectionMap<OutputRecordLayout>,
) {
    for (id, info) in output_sections.ids_with_info() {
        if let SectionKind::Secondary(primary_id) = info.kind {
            let secondary_layout = take(section_layouts.get_mut(id));
            section_layouts.get_mut(primary_id).merge(&secondary_layout);
        }
    }
}

fn compute_start_offsets_by_group<P: Platform>(
    group_states: &[GroupState<P>],
    mut mem_offsets: OutputSectionPartMap<u64>,
) -> Vec<OutputSectionPartMap<u64>> {
    timing_phase!("Compute per-group start offsets");

    group_states
        .iter()
        .map(|group| {
            let group_mem_starts = mem_offsets.clone();
            mem_offsets.merge(&group.common.mem_sizes);
            group_mem_starts
        })
        .collect_vec()
}

fn compute_symbols_and_layouts<'data, P: Platform>(
    group_states: Vec<GroupState<'data, P>>,
    starting_mem_offsets_by_group: Vec<OutputSectionPartMap<u64>>,
    per_group_res_writers: &mut [sharded_vec_writer::Shard<Option<Resolution<P>>>],
    resources: &FinaliseLayoutResources<'_, 'data, P>,
) -> Result<Vec<GroupLayout<'data, P>>> {
    timing_phase!("Assign symbol addresses");

    group_states
        .into_par_iter()
        .zip(starting_mem_offsets_by_group)
        .zip(per_group_res_writers)
        .map(|((state, mut memory_offsets), symbols_out)| {
            verbose_timing_phase!("Assign addresses for group");

            if cfg!(debug_assertions) {
                let offset_verifier = crate::verification::OffsetVerifier::new(
                    &memory_offsets,
                    &state.common.mem_sizes,
                );

                // Make sure that ignored offsets really aren't used by `finalise_layout` by setting
                // them to an arbitrary value. If they are used, we'll quickly notice.
                crate::verification::clear_ignored(&mut memory_offsets);

                let layout = state.finalise_layout(&mut memory_offsets, symbols_out, resources)?;

                offset_verifier.verify(
                    &memory_offsets,
                    resources.output_sections,
                    resources.output_order,
                    &layout.files,
                )?;
                Ok(layout)
            } else {
                state.finalise_layout(&mut memory_offsets, symbols_out, resources)
            }
        })
        .collect()
}

fn compute_segment_layout<P: Platform>(
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
    output_sections: &OutputSections<P>,
    output_order: &OutputOrder,
    program_segments: &ProgramSegments<P::ProgramSegmentDef>,
    header_info: &HeaderInfo,
    args: &P::Args,
) -> Result<SegmentLayouts> {
    #[derive(Clone)]
    struct Record {
        segment_id: ProgramSegmentId,
        file_start: usize,
        file_end: usize,
        mem_start: u64,
        mem_end: u64,
        alignment: Alignment,
    }

    timing_phase!("Compute segment layouts");

    use output_section_id::OrderEvent;
    let mut complete = Vec::with_capacity(program_segments.len());
    let mut active_segments = vec![None; program_segments.len()];

    for event in output_order {
        match event {
            OrderEvent::SegmentStart(segment_id) => {
                if program_segments.is_stack_segment(segment_id) {
                    // STACK segment is special as it does not contain any section.
                    active_segments[segment_id.as_usize()] = Some(Record {
                        segment_id,
                        file_start: 0,
                        file_end: 0,
                        mem_start: 0,
                        mem_end: args.stack_size_override().map_or(0, |size| size.get()),
                        alignment: alignment::MIN,
                    });
                } else {
                    active_segments[segment_id.as_usize()] = Some(Record {
                        segment_id,
                        file_start: usize::MAX,
                        file_end: 0,
                        mem_start: u64::MAX,
                        mem_end: 0,
                        alignment: alignment::MIN,
                    });
                }
            }
            OrderEvent::SegmentEnd(segment_id) => {
                let record = active_segments[segment_id.as_usize()]
                    .take()
                    .context("SegmentEnd without matching SegmentStart")?;

                complete.push(record);
            }
            OrderEvent::Section(section_id) => {
                let section_layout = section_layouts.get(section_id);
                let merge_target = output_sections.primary_output_section(section_id);

                // Skip all ignored sections that will not end up in the final file.
                if section_layout.file_size == 0
                    && section_layout.mem_size == 0
                    && output_sections.output_section_indexes[merge_target.as_usize()].is_none()
                {
                    continue;
                }
                let section_flags = output_sections.section_flags(merge_target);
                let section_info = output_sections.output_info(section_id);

                if active_segments.iter().all(|s| s.is_none()) {
                    ensure!(
                        section_layout.mem_offset == 0,
                        "Expected zero address for section {} not present in any program segment.",
                        output_sections.section_debug(section_id)
                    );
                    ensure!(
                        !section_flags.is_alloc(),
                        "Alloc section {} not present in any program segment.",
                        output_sections.section_debug(section_id)
                    );
                } else {
                    P::validate_section(
                        section_info,
                        section_flags,
                        section_layout,
                        merge_target,
                        output_sections,
                        section_id,
                    )?;
                    for opt_rec in &mut active_segments {
                        let Some(rec) = opt_rec.as_mut() else {
                            continue;
                        };

                        rec.file_start = rec.file_start.min(section_layout.file_offset);
                        rec.mem_start = rec.mem_start.min(section_layout.mem_offset);
                        rec.file_end = rec
                            .file_end
                            .max(section_layout.file_offset + section_layout.file_size);
                        rec.mem_end = rec
                            .mem_end
                            .max(section_layout.mem_offset + section_layout.mem_size);
                        rec.alignment = rec.alignment.max(section_layout.alignment);
                    }
                }
            }
            OrderEvent::SetLocation(_) => {}
        }
    }

    complete.sort_by_key(|r| r.segment_id);

    assert_eq!(complete.len(), program_segments.len());
    let mut tls_layout = None;

    let mut segments: Vec<SegmentLayout> = header_info
        .active_segment_ids
        .iter()
        .map(|&id| {
            let r = &complete[id.as_usize()];

            let sizes = OutputRecordLayout {
                file_size: r.file_end - r.file_start,
                mem_size: r.mem_end - r.mem_start,
                alignment: r.alignment,
                file_offset: r.file_start,
                mem_offset: r.mem_start,
            };

            if program_segments.is_tls_segment(id) {
                tls_layout = Some(sizes);
            }

            SegmentLayout { id, sizes }
        })
        .collect();

    segments.sort_by_key(|s| program_segments.order_key(s.id, s.sizes.mem_offset));

    Ok(SegmentLayouts {
        segments,
        tls_layout,
    })
}

fn compute_total_section_part_sizes<'data, P: Platform>(
    group_states: &mut [GroupState<'data, P>],
    output_sections: &mut OutputSections<P>,
    output_order: &OutputOrder,
    program_segments: &ProgramSegments<P::ProgramSegmentDef>,
    per_symbol_flags: &mut PerSymbolFlags,
    must_keep_sections: OutputSectionMap<bool>,
    resources: &FinaliseSizesResources<'data, '_, P>,
) -> Result<OutputSectionPartMap<u64>> {
    timing_phase!("Compute total section sizes");

    let mut total_sizes: OutputSectionPartMap<u64> = output_sections.new_part_map();
    for group_state in group_states.iter() {
        total_sizes.merge(&group_state.common.mem_sizes);
    }

    // We need to apply late-stage adjustments for the epilogue before we do so for the prelude,
    // since the prelude needs to know if the .hash section will be written, which is decided by the
    // epilogue.
    let last_group = group_states.last_mut().unwrap();
    let Some(FileLayoutState::Epilogue(epilogue)) = last_group.files.last_mut() else {
        unreachable!();
    };

    epilogue.apply_late_size_adjustments(&mut last_group.common, &mut total_sizes, resources)?;

    let first_group = group_states.first_mut().unwrap();
    let Some(FileLayoutState::Prelude(prelude)) = first_group.files.first_mut() else {
        unreachable!();
    };

    prelude.apply_late_size_adjustments(
        &mut first_group.common,
        &mut total_sizes,
        must_keep_sections,
        output_sections,
        output_order,
        program_segments,
        per_symbol_flags,
        resources,
    )?;

    Ok(total_sizes)
}

/// Propagates attributes from input sections to the output sections into which they were placed.
fn propagate_section_attributes<'data, P: Platform>(
    group_states: &[GroupState<'data, P>],
    output_sections: &mut OutputSections<P>,
) {
    timing_phase!("Propagate section attributes");

    for group_state in group_states {
        group_state
            .common
            .section_attributes
            .for_each(|section_id, attributes| {
                if let Some(attributes) = attributes {
                    attributes.apply(output_sections, section_id);
                }
            });
    }
}

/// This is similar to computing start addresses, but is used for things that aren't addressable,
/// but which need to be unique. It's non parallel. It could potentially be run in parallel with
/// some of the stages that run after it, that don't need access to the file states.
fn apply_non_addressable_indexes<'data, P: Platform>(
    group_states: &mut [GroupState<'data, P>],
    symbol_db: &SymbolDb<'data, P>,
) -> Result<P::NonAddressableCounts> {
    timing_phase!("Apply non-addressable indexes");

    let mut indexes = P::NonAddressableIndexes::new(symbol_db);

    let mut counts = P::NonAddressableCounts::default();

    for g in group_states.iter_mut() {
        for s in &mut g.files {
            match s {
                FileLayoutState::Dynamic(s) => {
                    s.object.apply_non_addressable_indexes_dynamic(
                        &mut indexes,
                        &mut counts,
                        &mut s.format_specific_state,
                    )?;
                }
                FileLayoutState::Epilogue(s) => {
                    P::apply_non_addressable_indexes_epilogue(&mut counts, &mut s.format_specific);
                }
                _ => {}
            }
        }
    }

    P::apply_non_addressable_indexes(
        symbol_db,
        &counts,
        group_states.iter_mut().map(|g| &mut g.common.mem_sizes),
    );

    Ok(counts)
}

/// Returns the starting memory address for each alignment within each segment.
fn starting_memory_offsets(
    section_layouts: &OutputSectionPartMap<OutputRecordLayout>,
) -> OutputSectionPartMap<u64> {
    timing_phase!("Compute per-alignment offsets");

    section_layouts.map(|_, rec| rec.mem_offset)
}

#[derive(Default)]
struct WorkerSlot<'data, P: Platform> {
    work: Vec<WorkItem>,
    worker: Option<GroupState<'data, P>>,
}

#[derive(Debug)]
struct GcOutputs<'data, P: Platform> {
    group_states: Vec<GroupState<'data, P>>,
    must_keep_sections: OutputSectionMap<bool>,
    has_static_tls: bool,
    has_variant_pcs: bool,
}

struct GroupActivationInputs<'data, P: Platform> {
    resolved: ResolvedGroup<'data, P>,
    num_symbols: usize,
    group_index: usize,
}

impl<'data, P: Platform> GroupActivationInputs<'data, P> {
    fn activate_group<'scope, A: Arch<Platform = P>>(
        self,
        resources: &'scope GraphResources<'data, '_, P>,
        scope: &Scope<'scope>,
    ) {
        let GroupActivationInputs {
            resolved,
            num_symbols,
            group_index,
        } = self;

        let files = resolved
            .files
            .into_iter()
            .map(|file| file.create_layout_state())
            .collect();
        let mut group = GroupState {
            queue: LocalWorkQueue::new(group_index),
            num_symbols,
            files,
            common: CommonGroupState::new(resources.output_sections),
        };

        let mut should_delay_processing = false;

        for file in &mut group.files {
            let r = activate::<A>(&mut group.common, file, &mut group.queue, resources, scope)
                .with_context(|| format!("Failed to activate {file}"));

            // SyntheticSymbols can't be processed until all groups have completed activation, since
            // it can read from `start_stop_sections` which gets populated by other objects during
            // activation.
            should_delay_processing |= matches!(file, FileLayoutState::SyntheticSymbols(_));

            if let Err(error) = r {
                resources.errors.lock().unwrap().push(error);
            }
        }

        if should_delay_processing {
            resources.delay_processing.push(group).unwrap();
        } else {
            group.do_pending_work::<A>(resources, scope);
        }

        let remaining = resources
            .activations_remaining
            .fetch_sub(1, atomic::Ordering::Relaxed)
            - 1;

        if remaining == 0 {
            while let Some(group) = resources.delay_processing.pop() {
                group.do_pending_work::<A>(resources, scope);
            }
        }
    }
}

fn find_required_sections<'data, A: Arch>(
    groups_in: Vec<resolution::ResolvedGroup<'data, A::Platform>>,
    symbol_db: &SymbolDb<'data, A::Platform>,
    per_symbol_flags: &AtomicPerSymbolFlags,
    output_sections: &OutputSections<'data, A::Platform>,
    layout_resources_ext: <A::Platform as Platform>::LayoutResourcesExt<'data>,
) -> Result<GcOutputs<'data, A::Platform>> {
    timing_phase!("Find required sections");

    let num_groups = groups_in.len();

    let mut worker_slots = Vec::with_capacity(num_groups);
    worker_slots.resize_with(num_groups, || {
        Mutex::new(WorkerSlot {
            work: Default::default(),
            worker: None,
        })
    });

    let resources = GraphResources {
        symbol_db,
        output_sections,
        worker_slots,
        errors: Mutex::new(Vec::new()),
        per_symbol_flags,
        must_keep_sections: output_sections.new_section_map(),
        has_static_tls: AtomicBool::new(false),
        has_variant_pcs: AtomicBool::new(false),
        start_stop_sections: output_sections.new_section_map(),
        activations_remaining: AtomicUsize::new(num_groups),
        delay_processing: ArrayQueue::new(1),
        layout_resources_ext,
    };
    let resources_ref = &resources;

    rayon::in_place_scope(|scope| {
        queue_initial_group_processing::<A>(groups_in, symbol_db, resources_ref, scope);
    });

    let mut errors: Vec<Error> = take(resources.errors.lock().unwrap().as_mut());
    // TODO: Figure out good way to report more than one error.
    if let Some(error) = errors.pop() {
        return Err(error);
    }

    let mut group_states = unwrap_worker_states(&resources.worker_slots);

    <A::Platform as Platform>::finalise_find_required_sections(&group_states);

    // Give our prelude a chance to tie up a few last sizes while we still have access to
    // `resources`.
    let prelude_group = &mut group_states[0];
    let FileLayoutState::Prelude(prelude) = &mut prelude_group.files[0] else {
        unreachable!("Prelude must be first");
    };

    <A::Platform as Platform>::pre_finalise_sizes_prelude(
        prelude,
        &mut prelude_group.common,
        &resources,
    );

    let must_keep_sections = resources.must_keep_sections.into_map(|v| v.into_inner());

    Ok(GcOutputs {
        group_states,
        must_keep_sections,
        has_static_tls: resources.has_static_tls.load(atomic::Ordering::Relaxed),
        has_variant_pcs: resources.has_variant_pcs.load(atomic::Ordering::Relaxed),
    })
}

fn queue_initial_group_processing<'data, 'scope, A: Arch>(
    groups_in: Vec<resolution::ResolvedGroup<'data, A::Platform>>,
    symbol_db: &'scope SymbolDb<'data, A::Platform>,
    resources: &'scope GraphResources<'data, '_, A::Platform>,
    scope: &Scope<'scope>,
) {
    verbose_timing_phase!("Create worker slots");

    assert_eq!(groups_in.len(), symbol_db.groups.len());

    groups_in
        .into_iter()
        .enumerate()
        .zip(&symbol_db.groups)
        .for_each(|((group_index, resolved), group)| {
            scope.spawn(move |scope| {
                verbose_timing_phase!("Activate group");
                let inputs = GroupActivationInputs {
                    resolved,
                    num_symbols: group.num_symbols(),
                    group_index,
                };
                inputs.activate_group::<A>(resources, scope);
            });
        });
}

fn unwrap_worker_states<'data, P: Platform>(
    worker_slots: &[Mutex<WorkerSlot<'data, P>>],
) -> Vec<GroupState<'data, P>> {
    worker_slots
        .iter()
        .filter_map(|w| w.lock().unwrap().worker.take())
        .collect()
}

impl<'data, P: Platform> GroupState<'data, P> {
    /// Does work until there's nothing left in the queue, then returns our worker to its slot and
    /// shuts down.
    fn do_pending_work<'scope, A: Arch<Platform = P>>(
        mut self,
        resources: &'scope GraphResources<'data, '_, P>,
        scope: &Scope<'scope>,
    ) {
        loop {
            while let Some(work_item) = self.queue.local_work.pop() {
                let file_id = work_item.file_id(resources.symbol_db);
                let file = &mut self.files[file_id.file()];
                if let Err(error) = file.do_work::<A>(
                    &mut self.common,
                    work_item,
                    resources,
                    &mut self.queue,
                    scope,
                ) {
                    resources.report_error(error);
                    return;
                }
            }
            {
                let mut slot = resources.worker_slots[self.queue.index].lock().unwrap();
                if slot.work.is_empty() {
                    slot.worker = Some(self);
                    return;
                }
                swap(&mut slot.work, &mut self.queue.local_work);
            };
        }
    }

    fn finalise_sizes(
        &mut self,
        output_sections: &OutputSections<P>,
        per_symbol_flags: &AtomicPerSymbolFlags,
        resources: &FinaliseSizesResources<'data, '_, P>,
    ) -> Result {
        for file_state in &mut self.files {
            file_state.finalise_sizes(
                &mut self.common,
                output_sections,
                per_symbol_flags,
                resources,
            )?;
        }

        self.common.validate_sizes()?;
        Ok(())
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut sharded_vec_writer::Shard<Option<Resolution<P>>>,
        resources: &FinaliseLayoutResources<'_, 'data, P>,
    ) -> Result<GroupLayout<'data, P>> {
        let format_specific = P::finalise_group_layout(memory_offsets);
        let files = self
            .files
            .into_iter()
            .map(|file| file.finalise_layout(memory_offsets, resolutions_out, resources))
            .collect::<Result<Vec<_>>>()?;

        let strtab_start_offset = self
            .common
            .finalise_layout(memory_offsets, resources.section_layouts);
        let dynstr_start_offset = (memory_offsets.get(part_id::DYNSTR)
            - resources
                .section_layouts
                .get(output_section_id::DYNSTR)
                .mem_offset) as u32;
        memory_offsets.increment(part_id::DYNSTR, *self.common.mem_sizes.get(part_id::DYNSTR));

        Ok(GroupLayout {
            files,
            strtab_start_offset,
            dynstr_start_offset,
            file_sizes: compute_file_sizes(&self.common.mem_sizes, resources.output_sections),
            mem_sizes: self.common.mem_sizes,
            format_specific,
        })
    }
}

fn activate<'data, 'scope, A: Arch>(
    common: &mut CommonGroupState<'data, A::Platform>,
    file: &mut FileLayoutState<'data, A::Platform>,
    queue: &mut LocalWorkQueue,
    resources: &'scope GraphResources<'data, '_, A::Platform>,
    scope: &Scope<'scope>,
) -> Result {
    match file {
        FileLayoutState::Object(s) => s.activate::<A>(common, resources, queue, scope)?,
        FileLayoutState::Prelude(s) => s.activate::<A>(common, resources, queue, scope)?,
        FileLayoutState::Dynamic(s) => s.activate::<A>(common, resources, queue, scope)?,
        FileLayoutState::LinkerScript(s) => s.activate(common, resources)?,
        FileLayoutState::Epilogue(_) => {}
        FileLayoutState::NotLoaded(_) => {}
        FileLayoutState::SyntheticSymbols(_) => {}
    }
    Ok(())
}

impl LocalWorkQueue {
    #[inline(always)]
    fn send_work<'data, 'scope, A: Arch>(
        &mut self,
        resources: &'scope GraphResources<'data, '_, A::Platform>,
        file_id: FileId,
        work: WorkItem,
        scope: &Scope<'scope>,
    ) {
        if file_id.group() == self.index {
            self.local_work.push(work);
        } else {
            resources.send_work::<A>(file_id, work, resources, scope);
        }
    }

    fn new(index: usize) -> LocalWorkQueue {
        Self {
            index,
            local_work: Default::default(),
        }
    }

    #[inline(always)]
    pub(crate) fn send_symbol_request<'data, 'scope, A: Arch>(
        &mut self,
        symbol_id: SymbolId,
        resources: &'scope GraphResources<'data, '_, A::Platform>,
        scope: &Scope<'scope>,
    ) {
        debug_assert!(resources.symbol_db.is_canonical(symbol_id));
        let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        self.send_work::<A>(
            resources,
            symbol_file_id,
            WorkItem::LoadGlobalSymbol(symbol_id),
            scope,
        );
    }

    pub(crate) fn send_copy_relocation_request<'data, 'scope, A: Arch>(
        &mut self,
        symbol_id: SymbolId,
        resources: &'scope GraphResources<'data, '_, A::Platform>,
        scope: &Scope<'scope>,
    ) {
        debug_assert!(resources.symbol_db.is_canonical(symbol_id));
        let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        self.send_work::<A>(
            resources,
            symbol_file_id,
            WorkItem::CopyRelocateSymbol(symbol_id),
            scope,
        );
    }
}

impl<'data, P: Platform> GraphResources<'data, '_, P> {
    pub(crate) fn report_error(&self, error: Error) {
        self.errors.lock().unwrap().push(error);
    }

    /// Sends all work in `work` to the worker for `file_id`. Leaves `work` empty so that it can be
    /// reused.
    #[inline(always)]
    fn send_work<'scope, A: Arch<Platform = P>>(
        &self,
        file_id: FileId,
        work: WorkItem,
        resources: &'scope GraphResources<'data, '_, P>,
        scope: &Scope<'scope>,
    ) {
        let worker;
        {
            let mut slot = self.worker_slots[file_id.group()].lock().unwrap();
            worker = slot.worker.take();
            slot.work.push(work);
        };
        if let Some(worker) = worker {
            scope.spawn(|scope| {
                verbose_timing_phase!("Work with object");
                worker.do_pending_work::<A>(resources, scope);
            });
        }
    }

    pub(crate) fn local_flags_for_symbol(&self, symbol_id: SymbolId) -> ValueFlags {
        self.per_symbol_flags.flags_for_symbol(symbol_id)
    }

    pub(crate) fn symbol_debug<'a>(&'a self, symbol_id: SymbolId) -> SymbolDebug<'a, 'data, P> {
        self.symbol_db
            .symbol_debug(self.per_symbol_flags, symbol_id)
    }

    fn keep_section(&self, section_id: OutputSectionId) {
        let keep = self.must_keep_sections.get(section_id);

        // We only write after reading and determining that we need to write. This likely makes the
        // case where we do write slower, but the case where we don't write faster and also avoids
        // gaining exclusive access to the cache line unless necessary. This has a small but
        // measurable performance effect.
        if !keep.load(atomic::Ordering::Relaxed) {
            keep.store(true, atomic::Ordering::Relaxed);
        }
    }
}

impl<'data, P: Platform> FileLayoutState<'data, P> {
    fn finalise_sizes(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        output_sections: &OutputSections<P>,
        per_symbol_flags: &AtomicPerSymbolFlags,
        resources: &FinaliseSizesResources<'data, '_, P>,
    ) -> Result {
        match self {
            FileLayoutState::Object(s) => {
                s.finalise_sizes(common, output_sections, per_symbol_flags, resources);
                s.finalise_symbol_sizes(common, per_symbol_flags, resources)?;
            }
            FileLayoutState::Dynamic(s) => {
                s.finalise_sizes(common)?;
                s.finalise_symbol_sizes(common, per_symbol_flags, resources)?;
            }
            FileLayoutState::Prelude(s) => {
                PreludeLayoutState::finalise_sizes(common, resources.merged_strings);
                s.finalise_symbol_sizes(common, per_symbol_flags, resources)?;
            }
            FileLayoutState::SyntheticSymbols(s) => {
                s.finalise_sizes(common, per_symbol_flags, resources)?;
                s.finalise_symbol_sizes(common, per_symbol_flags, resources)?;
            }
            FileLayoutState::Epilogue(s) => {
                s.finalise_sizes(common, resources);
            }
            FileLayoutState::LinkerScript(s) => {
                s.finalise_sizes(common, per_symbol_flags, resources)?;
                s.finalise_symbol_sizes(common, per_symbol_flags, resources)?;
            }
            FileLayoutState::NotLoaded(_) => {}
        }

        P::finalise_sizes_all(&mut common.mem_sizes, resources.symbol_db);

        Ok(())
    }

    fn do_work<'scope, A: Arch<Platform = P>>(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        work_item: WorkItem,
        resources: &'scope GraphResources<'data, 'scope, P>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result {
        match work_item {
            WorkItem::LoadGlobalSymbol(symbol_id) => self
                .handle_symbol_request::<A>(common, symbol_id, resources, queue, scope)
                .with_context(|| {
                    format!(
                        "Failed to load {} from {self}",
                        resources.symbol_debug(symbol_id),
                    )
                }),
            WorkItem::CopyRelocateSymbol(symbol_id) => match self {
                FileLayoutState::Dynamic(state) => {
                    P::copy_relocate_symbol(state, symbol_id, resources)
                }

                _ => {
                    bail!(
                        "Internal error: ExportCopyRelocation sent to non-dynamic object for: {}",
                        resources.symbol_debug(symbol_id)
                    )
                }
            },
            WorkItem::LoadSection(request) => match self {
                FileLayoutState::Object(object_layout_state) => object_layout_state
                    .handle_section_load_request::<A>(
                        common,
                        resources,
                        queue,
                        request.section_index(),
                        scope,
                    ),
                _ => bail!("Request to load section from non-object: {self}"),
            },
            WorkItem::ExportDynamic(symbol_id) => match self {
                FileLayoutState::Object(object) => {
                    object.export_dynamic::<A>(common, symbol_id, resources, queue, scope)
                }
                _ => {
                    // Non-loaded and dynamic objects don't do anything in response to a request to
                    // export a dynamic symbol.
                    Ok(())
                }
            },
        }
    }

    fn handle_symbol_request<'scope, A: Arch<Platform = P>>(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        symbol_id: SymbolId,
        resources: &'scope GraphResources<'data, 'scope, P>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result {
        match self {
            FileLayoutState::Object(state) => {
                SymbolRequestHandler::load_symbol::<A>(
                    state, common, symbol_id, resources, queue, scope,
                )?;
            }
            FileLayoutState::Prelude(state) => {
                SymbolRequestHandler::load_symbol::<A>(
                    state, common, symbol_id, resources, queue, scope,
                )?;
            }
            FileLayoutState::Dynamic(state) => {
                SymbolRequestHandler::load_symbol::<A>(
                    state, common, symbol_id, resources, queue, scope,
                )?;
            }
            FileLayoutState::LinkerScript(_) => {}
            FileLayoutState::NotLoaded(_) => {}
            FileLayoutState::SyntheticSymbols(state) => {
                SymbolRequestHandler::load_symbol::<A>(
                    state, common, symbol_id, resources, queue, scope,
                )?;
            }
            FileLayoutState::Epilogue(_) => {
                // The epilogue doesn't define symbols. In fact, it isn't even created until after
                // the GC phase graph traversal.
                unreachable!();
            }
        }
        Ok(())
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut sharded_vec_writer::Shard<Option<Resolution<P>>>,
        resources: &FinaliseLayoutResources<'_, 'data, P>,
    ) -> Result<FileLayout<'data, P>> {
        let resolutions_out = &mut ResolutionWriter { resolutions_out };
        let file_layout = match self {
            Self::Object(s) => {
                let _span = tracing::debug_span!(
                    "finalise_layout",
                    file = %s.input
                )
                .entered();
                FileLayout::Object(s.finalise_layout(memory_offsets, resolutions_out, resources)?)
            }
            Self::Prelude(s) => FileLayout::Prelude(s.finalise_layout(
                memory_offsets,
                resolutions_out,
                resources,
            )?),
            Self::Epilogue(s) => {
                FileLayout::Epilogue(s.finalise_layout(memory_offsets, resources)?)
            }
            Self::SyntheticSymbols(s) => FileLayout::SyntheticSymbols(s.finalise_layout(
                memory_offsets,
                resolutions_out,
                resources,
            )?),
            Self::Dynamic(s) => FileLayout::Dynamic(s.finalise_layout(
                memory_offsets,
                resolutions_out,
                resources,
            )?),
            Self::LinkerScript(s) => {
                s.finalise_layout(memory_offsets, resolutions_out, resources)?;
                FileLayout::LinkerScript(s)
            }
            Self::NotLoaded(s) => {
                for _ in 0..s.symbol_id_range.len() {
                    resolutions_out.write(None)?;
                }
                FileLayout::NotLoaded
            }
        };
        Ok(file_layout)
    }
}

fn compute_file_sizes<P: Platform>(
    mem_sizes: &OutputSectionPartMap<u64>,
    output_sections: &OutputSections<'_, P>,
) -> OutputSectionPartMap<usize> {
    mem_sizes.map(|part_id, size| {
        if output_sections.has_data_in_file(part_id.output_section_id()) {
            *size as usize
        } else {
            0
        }
    })
}

impl<P: Platform> std::fmt::Display for PreludeLayoutState<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt("<prelude>", f)
    }
}

impl<P: Platform> std::fmt::Display for EpilogueLayoutState<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt("<epilogue>", f)
    }
}

impl std::fmt::Display for SyntheticSymbolsLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt("<synthetic>", f)
    }
}

impl std::fmt::Display for LinkerScriptLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl<'data, P: Platform> std::fmt::Display for FileLayoutState<'data, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileLayoutState::Object(s) => std::fmt::Display::fmt(s, f),
            FileLayoutState::Dynamic(s) => std::fmt::Display::fmt(s, f),
            FileLayoutState::LinkerScript(s) => std::fmt::Display::fmt(s, f),
            FileLayoutState::Prelude(_) => std::fmt::Display::fmt("<prelude>", f),
            FileLayoutState::SyntheticSymbols(_) => std::fmt::Display::fmt("<synthetic>", f),
            FileLayoutState::NotLoaded(_) => std::fmt::Display::fmt("<not-loaded>", f),
            FileLayoutState::Epilogue(_) => std::fmt::Display::fmt("<epilogue>", f),
        }
    }
}

impl<'data, P: Platform> std::fmt::Display for FileLayout<'data, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Object(s) => std::fmt::Display::fmt(s, f),
            Self::Dynamic(s) => std::fmt::Display::fmt(s, f),
            Self::LinkerScript(s) => std::fmt::Display::fmt(s, f),
            Self::Prelude(_) => std::fmt::Display::fmt("<prelude>", f),
            Self::Epilogue(_) => std::fmt::Display::fmt("<epilogue>", f),
            Self::SyntheticSymbols(_) => std::fmt::Display::fmt("<synthetic>", f),
            Self::NotLoaded => std::fmt::Display::fmt("<not loaded>", f),
        }
    }
}

impl<'data, P: Platform> std::fmt::Display for GroupLayout<'data, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.files.len() == 1 {
            self.files[0].fmt(f)
        } else {
            write!(
                f,
                "Group with {} files. Rerun with {}=1",
                self.files.len(),
                crate::args::FILES_PER_GROUP_ENV
            )
        }
    }
}

impl<'data, P: Platform> std::fmt::Display for GroupState<'data, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.files.len() == 1 {
            self.files[0].fmt(f)
        } else {
            write!(
                f,
                "Group with {} files. Rerun with {}=1",
                self.files.len(),
                crate::args::FILES_PER_GROUP_ENV
            )
        }
    }
}

impl<'data, P: Platform> std::fmt::Debug for FileLayout<'data, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self, f)
    }
}

impl<'data, P: Platform> std::fmt::Display for ObjectLayoutState<'data, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        // TODO: This is mostly for debugging use. Consider only showing this if some environment
        // variable is set, or only in debug builds.
        write!(f, " ({})", self.file_id())
    }
}

impl<'data, P: Platform> std::fmt::Display for DynamicLayoutState<'data, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        write!(f, " ({})", self.file_id())
    }
}

impl<'data, P: Platform> std::fmt::Display for DynamicLayout<'data, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        write!(f, " ({})", self.file_id)
    }
}

impl<'data, P: Platform> std::fmt::Display for ObjectLayout<'data, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        // TODO: This is mostly for debugging use. Consider only showing this if some environment
        // variable is set, or only in debug builds.
        write!(f, " ({})", self.file_id)
    }
}

impl Section {
    fn create<'data, P: Platform>(
        header: &P::SectionHeader,
        object_state: &ObjectLayoutState<'data, P>,
        section_index: object::SectionIndex,
        part_id: PartId,
    ) -> Result<Section> {
        let size = object_state.object.section_size(header)?;
        let section = Section {
            index: section_index,
            part_id,
            size,
            flags: ValueFlags::empty(),
            is_writable: header.is_writable(),
        };
        Ok(section)
    }

    // How much space we take up. This is our size rounded up to the next multiple of our
    // alignment, unless we're in a packed section, in which case it's just our size.
    pub(crate) fn capacity<P: Platform>(&self, output_sections: &OutputSections<P>) -> u64 {
        if self.part_id.should_pack() {
            self.size
        } else {
            self.alignment(output_sections).align_up(self.size)
        }
    }

    pub(crate) fn output_section_id(&self) -> OutputSectionId {
        self.part_id.output_section_id()
    }

    pub(crate) fn output_part_id(&self) -> PartId {
        self.part_id
    }

    /// Returns the alignment for this section.
    fn alignment<P: Platform>(&self, output_sections: &OutputSections<P>) -> Alignment {
        self.part_id.alignment(output_sections)
    }
}

pub(crate) fn resolution_flags(rel_kind: RelocationKind) -> ValueFlags {
    match rel_kind {
        RelocationKind::PltRelative | RelocationKind::PltRelGotBase => {
            ValueFlags::PLT | ValueFlags::GOT
        }
        RelocationKind::Got
        | RelocationKind::GotRelGotBase
        | RelocationKind::GotRelative
        | RelocationKind::GotRelativeLoongArch64 => ValueFlags::GOT,
        RelocationKind::GotTpOff
        | RelocationKind::GotTpOffLoongArch64
        | RelocationKind::GotTpOffGot
        | RelocationKind::GotTpOffGotBase => ValueFlags::GOT_TLS_OFFSET,
        RelocationKind::TlsGd | RelocationKind::TlsGdGot | RelocationKind::TlsGdGotBase => {
            ValueFlags::GOT_TLS_MODULE
        }
        RelocationKind::TlsDesc
        | RelocationKind::TlsDescLoongArch64
        | RelocationKind::TlsDescGot
        | RelocationKind::TlsDescGotBase
        | RelocationKind::TlsDescCall => ValueFlags::GOT_TLS_DESCRIPTOR,
        RelocationKind::TlsLd | RelocationKind::TlsLdGot | RelocationKind::TlsLdGotBase => {
            ValueFlags::empty()
        }
        RelocationKind::Absolute
        | RelocationKind::AbsoluteSet
        | RelocationKind::AbsoluteSetWord6
        | RelocationKind::AbsoluteAddition
        | RelocationKind::AbsoluteAdditionWord6
        | RelocationKind::AbsoluteSubtraction
        | RelocationKind::AbsoluteSubtractionWord6
        | RelocationKind::Relative
        | RelocationKind::RelativeRiscVLow12
        | RelocationKind::RelativeLoongArchHigh
        | RelocationKind::DtpOff
        | RelocationKind::TpOff
        | RelocationKind::SymRelGotBase
        | RelocationKind::PairSubtractionULEB128(..) => ValueFlags::DIRECT,
        RelocationKind::None | RelocationKind::AbsoluteLowPart | RelocationKind::Alignment => {
            ValueFlags::empty()
        }
    }
}

impl<'data, P: Platform> PreludeLayoutState<'data, P> {
    fn new(input_state: resolution::ResolvedPrelude<'data>) -> Self {
        Self {
            file_id: PRELUDE_FILE_ID,
            symbol_id_range: SymbolIdRange::prelude(input_state.symbol_definitions.len()),
            internal_symbols: InternalSymbols {
                symbol_definitions: input_state.symbol_definitions,
                start_symbol_id: SymbolId::zero(),
            },
            entry_symbol_id: None,
            identity: format!("Linker: {}", crate::identity::linker_identity()),
            header_info: None,
            dynamic_linker: None,
            format_specific: Default::default(),
        }
    }

    fn activate<'scope, A: Arch<Platform = P>>(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        resources: &'scope GraphResources<'data, '_, P>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result {
        if resources.symbol_db.args.should_write_linker_identity() {
            // Allocate space to store the identity of the linker in the .comment section.
            common.allocate(
                output_section_id::COMMENT.part_id_with_alignment(alignment::MIN),
                self.identity.len() as u64,
            );
        }

        self.load_entry_point::<A>(resources, queue, scope);

        P::allocate_prelude(common, resources.symbol_db);

        if resources.symbol_db.output_kind.is_dynamic_executable() {
            self.dynamic_linker = resources
                .symbol_db
                .args
                .dynamic_linker()
                .map(|p| CString::new(p.as_os_str().as_encoded_bytes()))
                .transpose()?;
        }
        if let Some(dynamic_linker) = self.dynamic_linker.as_ref() {
            common.allocate(
                part_id::INTERP,
                dynamic_linker.as_bytes_with_nul().len() as u64,
            );
        }

        self.mark_defsyms_as_used::<A>(resources, queue, scope);

        Ok(())
    }

    /// Mark defsyms from the command-line as being directly referenced so that we emit the symbols
    /// even if nothing in the code references them.
    fn mark_defsyms_as_used<'scope, A: Arch>(
        &self,
        resources: &'scope GraphResources<'data, '_, A::Platform>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) {
        for (index, def_info) in self.internal_symbols.symbol_definitions.iter().enumerate() {
            let symbol_id = self.symbol_id_range.offset_to_id(index);
            if !resources.symbol_db.is_canonical(symbol_id) {
                continue;
            }

            match def_info.placement {
                SymbolPlacement::DefsymAbsolute(_) => {
                    resources
                        .per_symbol_flags
                        .get_atomic(symbol_id)
                        .or_assign(ValueFlags::DIRECT);
                }
                SymbolPlacement::DefsymSymbol(target_name, _offset) => {
                    resources
                        .per_symbol_flags
                        .get_atomic(symbol_id)
                        .or_assign(ValueFlags::DIRECT);

                    // Also mark the target symbol as used and queue it for loading to prevent it
                    // from being GC'd.
                    if let Some(target_symbol_id) = resources
                        .symbol_db
                        .get_unversioned(&UnversionedSymbolName::prehashed(target_name.as_bytes()))
                    {
                        let canonical_target_id = resources.symbol_db.definition(target_symbol_id);
                        let file_id = resources.symbol_db.file_id_for_symbol(canonical_target_id);
                        let old_flags = resources
                            .per_symbol_flags
                            .get_atomic(canonical_target_id)
                            .fetch_or(ValueFlags::DIRECT);

                        if !old_flags.has_resolution() {
                            queue.send_work::<A>(
                                resources,
                                file_id,
                                WorkItem::LoadGlobalSymbol(canonical_target_id),
                                scope,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn load_entry_point<'scope, A: Arch<Platform = P>>(
        &mut self,
        resources: &'scope GraphResources<'data, '_, P>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) {
        let Some(symbol_id) =
            resources
                .symbol_db
                .get_unversioned(&UnversionedSymbolName::prehashed(
                    resources.symbol_db.entry_symbol_name(),
                ))
        else {
            // We'll emit a warning when writing the file if it's an executable.
            return;
        };

        let symbol_id = resources.symbol_db.definition(symbol_id);

        self.entry_symbol_id = Some(symbol_id);
        let file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        let old_flags = resources
            .per_symbol_flags
            .get_atomic(symbol_id)
            .fetch_or(ValueFlags::DIRECT);
        if !old_flags.has_resolution() {
            queue.send_work::<A>(
                resources,
                file_id,
                WorkItem::LoadGlobalSymbol(symbol_id),
                scope,
            );
        }
    }

    fn finalise_sizes(
        common: &mut CommonGroupState<'data, P>,
        merged_strings: &OutputSectionMap<MergedStringsSection<'data>>,
    ) {
        merged_strings.for_each(|section_id, merged| {
            if merged.len() > 0 {
                common.allocate(
                    section_id.part_id_with_alignment(alignment::MIN),
                    merged.len(),
                );
            }
        });
    }

    /// This function is where we determine sizes that depend on other sizes. For example, the size
    /// of the section headers table, which depends on which sections we're writing, which depends
    /// on which sections are non-empty. We also decide which internal symtab entries we'll write
    /// here, since that also depends on which sections we're writing.
    fn apply_late_size_adjustments(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        total_sizes: &mut OutputSectionPartMap<u64>,
        must_keep_sections: OutputSectionMap<bool>,
        output_sections: &mut OutputSections<P>,
        output_order: &OutputOrder,
        program_segments: &ProgramSegments<P::ProgramSegmentDef>,
        per_symbol_flags: &mut PerSymbolFlags,
        resources: &FinaliseSizesResources<'data, '_, P>,
    ) -> Result {
        // Total section  sizes have already been computed. So any allocations we do need to update
        // both `total_sizes` and the size records in `common`. We track the extra sizes in
        // `extra_sizes` which we can then later add to both.
        let mut extra_sizes = OutputSectionPartMap::with_size(common.mem_sizes.num_parts());

        self.determine_header_sizes(
            total_sizes,
            &mut extra_sizes,
            must_keep_sections,
            output_sections,
            program_segments,
            output_order,
            resources,
            per_symbol_flags,
        );

        self.allocate_symbol_table_sizes(
            output_sections,
            per_symbol_flags,
            resources.symbol_db,
            &mut extra_sizes,
        )?;

        // We need to allocate both our own size record and the group totals, since they've already
        // been computed.
        common.mem_sizes.merge(&extra_sizes);
        total_sizes.merge(&extra_sizes);

        Ok(())
    }

    /// Allocates space for our internal symbols. For unreferenced symbols, we also update the
    /// symbol so that it is treated as referenced, but only for symbols in sections that we're
    /// going to emit.
    fn allocate_symbol_table_sizes(
        &self,
        output_sections: &OutputSections<P>,
        per_symbol_flags: &mut PerSymbolFlags,
        symbol_db: &SymbolDb<'data, P>,
        extra_sizes: &mut OutputSectionPartMap<u64>,
    ) -> Result<(), Error> {
        if symbol_db.args.should_strip_all() {
            return Ok(());
        }

        self.internal_symbols.allocate_symbol_table_sizes(
            extra_sizes,
            symbol_db,
            |symbol_id, def_info| {
                let flags = per_symbol_flags.flags_for_symbol(symbol_id);

                // If the symbol is referenced, then we keep it.
                if flags.has_resolution() {
                    return true;
                }

                // We always emit symbols that the user requested be undefined.
                let mut should_emit = def_info.placement == SymbolPlacement::ForceUndefined;

                // Keep the symbol if we're going to write the section, even though the symbol isn't
                // referenced. It can be useful to have symbols like _GLOBAL_OFFSET_TABLE_ when
                // using a debugger.
                should_emit |= def_info.section_id().is_some_and(|output_section_id| {
                    output_sections.will_emit_section(output_section_id)
                });

                if should_emit {
                    // Mark the symbol as referenced so that we later generate a resolution for
                    // it and subsequently write it to the symbol table.
                    per_symbol_flags.set_flag(symbol_id, ValueFlags::DIRECT);
                }

                should_emit
            },
        )
    }

    fn determine_header_sizes(
        &mut self,
        total_sizes: &OutputSectionPartMap<u64>,
        extra_sizes: &mut OutputSectionPartMap<u64>,
        must_keep_sections: OutputSectionMap<bool>,
        output_sections: &mut OutputSections<P>,
        program_segments: &ProgramSegments<P::ProgramSegmentDef>,
        output_order: &OutputOrder,
        resources: &FinaliseSizesResources<'data, '_, P>,
        symbol_flags: &PerSymbolFlags,
    ) {
        use output_section_id::OrderEvent;

        // Determine which sections to keep. To start with, we keep all sections that we've
        // previously marked as needing to be kept. These may include sections that are empty, but
        // into which we've loaded an empty input section.
        let mut keep_sections = must_keep_sections;

        // Next, keep any sections for which we've recorded a non-zero size.
        total_sizes.map(|part_id, size| {
            if *size > 0 {
                *keep_sections.get_mut(part_id.output_section_id()) = true;
            }
        });

        // Keep any sections that we've said we want to keep regardless.
        P::apply_force_keep_sections(&mut keep_sections, resources.symbol_db.args);

        // Keep any sections that have a start/stop symbol which is referenced.
        symbol_flags
            .raw_range(self.symbol_id_range())
            .iter()
            .zip(self.internal_symbols.symbol_definitions.iter())
            .for_each(|(raw_flags, definition)| {
                if raw_flags.get().has_resolution()
                    && let Some(section_id) = definition.section_id()
                {
                    *keep_sections.get_mut(section_id) = true;
                }
            });

        for i in 0..output_sections.num_sections() {
            let section_id = OutputSectionId::from_usize(i);

            // If any secondary sections were marked to be kept, then unmark them and mark the
            // primary instead.
            if let Some(primary_id) = output_sections.merge_target(section_id) {
                let keep_secondary = replace(keep_sections.get_mut(section_id), false);
                *keep_sections.get_mut(primary_id) |= keep_secondary;
            }

            // Remove any built-in sections without a type except for section 0 (the file header).
            // This should just be the .phdr and .shdr sections which contain the program headers
            // and section headers. We need these sections in order to allocate space for those
            // structures, but other linkers don't emit section headers for them, so neither should
            // we. Custom sections (e.g. from linker scripts) that still have NULL type get the
            // default section type assigned instead, since an empty but explicitly defined section
            // should still be emitted if something references it.
            let section_info = output_sections.section_infos.get(section_id);
            if section_info.section_attributes.is_null()
                && section_id != output_section_id::FILE_HEADER
            {
                if section_id.is_custom() {
                    output_sections
                        .section_infos
                        .get_mut(section_id)
                        .section_attributes
                        .set_to_default_type();
                } else {
                    *keep_sections.get_mut(section_id) = false;
                }
            }
        }

        let num_sections = keep_sections.values_iter().filter(|p| **p).count();

        // Compute output indexes of each section.
        let mut next_output_index = 0;
        let mut output_section_indexes = vec![None; output_sections.num_sections()];
        for event in output_order {
            if let OrderEvent::Section(id) = event
                && *keep_sections.get(id)
            {
                debug_assert!(
                    output_sections.merge_target(id).is_none(),
                    "Tried to allocate section header for secondary section {}",
                    output_sections.section_debug(id)
                );
                output_section_indexes[id.as_usize()] = Some(next_output_index);
                next_output_index += 1;
            };
        }
        output_sections.output_section_indexes = output_section_indexes;

        // Determine which program segments contain sections that we're keeping.
        let mut keep_segments = program_segments
            .iter()
            .map(|details| details.always_keep())
            .collect_vec();
        let mut active_segments = Vec::with_capacity(4);
        for event in output_order {
            match event {
                OrderEvent::SegmentStart(segment_id) => active_segments.push(segment_id),
                OrderEvent::SegmentEnd(segment_id) => active_segments.retain(|a| *a != segment_id),
                OrderEvent::Section(section_id) => {
                    if *keep_sections.get(section_id) {
                        for segment_id in &active_segments {
                            keep_segments[segment_id.as_usize()] = true;
                        }
                        active_segments.clear();
                    }
                }
                OrderEvent::SetLocation(_) => {}
            }
        }

        // Always keep the program headers segment even though we don't emit any sections in it.
        keep_segments[0] = true;

        P::update_segment_keep_list(
            program_segments,
            &mut keep_segments,
            resources.symbol_db.args,
        );

        let active_segment_ids = (0..program_segments.len())
            .map(ProgramSegmentId::new)
            .filter(|id| keep_segments[id.as_usize()] || program_segments.is_stack_segment(*id))
            .collect();

        let header_info = HeaderInfo {
            num_output_sections_with_content: num_sections
                .try_into()
                .expect("output section count must fit in a u16"),

            active_segment_ids,
        };

        // Allocate space for headers based on segment and section counts.
        P::allocate_header_sizes(self, extra_sizes, &header_info, output_sections);

        self.header_info = Some(header_info);
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter<P>,
        resources: &FinaliseLayoutResources<'_, 'data, P>,
    ) -> Result<PreludeLayout<'data, P>> {
        let header_layout = resources
            .section_layouts
            .get(output_section_id::FILE_HEADER);
        assert_eq!(header_layout.file_offset, 0);

        let format_specific = P::finalise_prelude_layout(&self, memory_offsets, resources)?;

        self.internal_symbols
            .finalise_layout(memory_offsets, resolutions_out, resources)?;

        if resources.symbol_db.args.should_write_linker_identity() {
            memory_offsets.increment(
                output_section_id::COMMENT.part_id_with_alignment(alignment::MIN),
                self.identity.len() as u64,
            );
        }

        resources.merged_strings.for_each(|section_id, merged| {
            if merged.len() > 0 {
                memory_offsets.increment(
                    section_id.part_id_with_alignment(alignment::MIN),
                    merged.len(),
                );
            }
        });

        Ok(PreludeLayout {
            internal_symbols: self.internal_symbols,
            entry_symbol_id: self.entry_symbol_id,
            identity: self.identity,
            dynamic_linker: self.dynamic_linker,
            header_info: self
                .header_info
                .expect("we should have computed header info by now"),
            format_specific,
        })
    }
}

impl<'data> InternalSymbols<'data> {
    fn activate_symbols<P: Platform>(
        &self,
        common: &mut CommonGroupState<'data, P>,
        resources: &GraphResources<'data, '_, P>,
    ) -> Result {
        for (offset, def_info) in self.symbol_definitions.iter().enumerate() {
            let symbol_id = self.start_symbol_id.add_usize(offset);
            if !resources.symbol_db.is_canonical(symbol_id) {
                continue;
            }

            // Mark the section referenced by this symbol so that empty sections
            // defined by the linker script are still emitted.
            if let Some(section_id) = def_info.section_id() {
                resources
                    .must_keep_sections
                    .get(section_id)
                    .fetch_or(true, atomic::Ordering::Relaxed);
            }

            // PROVIDE_HIDDEN symbols should not be exported to dynsym.
            if def_info.is_hidden {
                continue;
            }

            resources
                .per_symbol_flags
                .get_atomic(symbol_id)
                .fetch_or(ValueFlags::EXPORT_DYNAMIC);

            if resources.symbol_db.output_kind.needs_dynsym() {
                export_dynamic(common, symbol_id, resources.symbol_db)?;
            }
        }

        Ok(())
    }

    fn allocate_symbol_table_sizes<P: Platform>(
        &self,
        sizes: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<'data, P>,
        mut should_keep_symbol: impl FnMut(SymbolId, &InternalSymDefInfo) -> bool,
    ) -> Result {
        // Allocate space in the symbol table for the symbols that we define.
        for (index, def_info) in self.symbol_definitions.iter().enumerate() {
            let symbol_id = self.start_symbol_id.add_usize(index);
            if !symbol_db.is_canonical(symbol_id) || symbol_id.is_undefined() {
                continue;
            }

            if !should_keep_symbol(symbol_id, def_info) {
                continue;
            }

            P::allocate_internal_symbol(symbol_id, def_info, sizes, symbol_db)?;
        }
        Ok(())
    }

    fn finalise_layout<P: Platform>(
        &self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter<P>,
        resources: &FinaliseLayoutResources<'_, 'data, P>,
    ) -> Result {
        // Define symbols that are optionally put at the start/end of some sections.
        for (local_index, &def_info) in self.symbol_definitions.iter().enumerate() {
            let symbol_id = self.start_symbol_id.add_usize(local_index);

            let resolution =
                create_start_end_symbol_resolution(memory_offsets, resources, def_info, symbol_id);

            resolutions_out.write(resolution)?;
        }
        Ok(())
    }

    pub(crate) fn symbol_id_range(&self) -> SymbolIdRange {
        SymbolIdRange::input(self.start_symbol_id, self.symbol_definitions.len())
    }
}

fn create_start_end_symbol_resolution<'data, P: Platform>(
    memory_offsets: &mut OutputSectionPartMap<u64>,
    resources: &FinaliseLayoutResources<'_, 'data, P>,
    def_info: InternalSymDefInfo,
    symbol_id: SymbolId,
) -> Option<Resolution<P>> {
    if !resources.symbol_db.is_canonical(symbol_id) {
        return None;
    }

    if !resources
        .per_symbol_flags
        .flags_for_symbol(symbol_id)
        .has_resolution()
    {
        return None;
    }

    let raw_value = match def_info.placement {
        SymbolPlacement::Undefined | SymbolPlacement::ForceUndefined => 0,
        SymbolPlacement::SectionStart(section_id) => {
            resources.section_layouts.get(section_id).mem_offset
        }

        SymbolPlacement::SectionEnd(section_id) => {
            let sec = resources.section_layouts.get(section_id);
            sec.mem_offset + sec.mem_size
        }

        SymbolPlacement::SectionGroupEnd(section_id) => {
            let mut end = {
                let sec = resources.section_layouts.get(section_id);
                sec.mem_offset + sec.mem_size
            };

            for (id, info) in resources.output_sections.ids_with_info() {
                if let SectionKind::Secondary(primary_id) = info.kind
                    && primary_id == section_id
                {
                    let sec = resources.section_layouts.get(id);
                    let candidate_end = sec.mem_offset + sec.mem_size;
                    if candidate_end > end {
                        end = candidate_end;
                    }
                }
            }
            end
        }

        SymbolPlacement::DefsymAbsolute(value) => value,

        SymbolPlacement::DefsymSymbol(_, _) => {
            // For defsym symbols that reference another symbol, we defer resolution
            // until later when all symbols have been resolved. This is handled by
            // update_defsym_symbol_resolutions() which is called after layout is complete.
            0
        }

        SymbolPlacement::LoadBaseAddress => resources
            .segment_layouts
            .segments
            .iter()
            .find(|seg| resources.program_segments.segment_def(seg.id).is_loadable())
            .map(|seg| seg.sizes.mem_offset)?,
    };

    Some(P::create_resolution(
        resources
            .symbol_db
            .flags_for_symbol(resources.per_symbol_flags, symbol_id),
        raw_value,
        None,
        memory_offsets,
    ))
}

pub(crate) fn should_emit_undefined_error<P: Platform>(
    symbol: &P::SymtabEntry,
    sym_file_id: FileId,
    sym_def_file_id: FileId,
    flags: ValueFlags,
    args: &P::Args,
    output_kind: OutputKind,
) -> bool {
    // TODO: Investigate whether this behaviour is correct or if we should actually be calling
    // `should_allow_shlib_undefined` here instead or as well as `should_allow_object_undefined`.
    if (output_kind.is_shared_object() && args.should_allow_object_undefined()) || symbol.is_weak()
    {
        return false;
    }

    let is_symbol_undefined =
        sym_file_id == sym_def_file_id && symbol.is_undefined() && flags.is_absolute();

    match args.unresolved_symbols_behaviour() {
        crate::args::UnresolvedSymbols::IgnoreAll
        | crate::args::UnresolvedSymbols::IgnoreInObjectFiles => false,
        _ => is_symbol_undefined,
    }
}

impl<'data> SyntheticSymbolsLayoutState<'data> {
    fn new(input_state: ResolvedSyntheticSymbols<'data>) -> SyntheticSymbolsLayoutState<'data> {
        SyntheticSymbolsLayoutState {
            file_id: input_state.file_id,
            symbol_id_range: SymbolIdRange::input(
                input_state.start_symbol_id,
                input_state.symbol_definitions.len(),
            ),
            internal_symbols: InternalSymbols {
                symbol_definitions: input_state.symbol_definitions,
                start_symbol_id: input_state.start_symbol_id,
            },
        }
    }

    fn finalise_sizes<P: Platform>(
        &self,
        common: &mut CommonGroupState<'data, P>,
        per_symbol_flags: &AtomicPerSymbolFlags,
        resources: &FinaliseSizesResources<'data, '_, P>,
    ) -> Result {
        let symbol_db = resources.symbol_db;

        if !symbol_db.args.should_strip_all() {
            self.internal_symbols.allocate_symbol_table_sizes(
                &mut common.mem_sizes,
                symbol_db,
                |symbol_id, _| {
                    // For user-defined start/stop symbols, we only emit them if they're referenced.
                    per_symbol_flags
                        .flags_for_symbol(symbol_id)
                        .has_resolution()
                },
            )?;
        }

        Ok(())
    }

    fn finalise_layout<P: Platform>(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter<P>,
        resources: &FinaliseLayoutResources<'_, 'data, P>,
    ) -> Result<SyntheticSymbolsLayout<'data>> {
        self.internal_symbols
            .finalise_layout(memory_offsets, resolutions_out, resources)?;

        Ok(SyntheticSymbolsLayout {
            internal_symbols: self.internal_symbols,
        })
    }
}

impl<'data, P: Platform> EpilogueLayoutState<P> {
    fn new(
        args: &P::Args,
        output_kind: OutputKind,
        dynamic_symbol_definitions: &mut [DynamicSymbolDefinition<P>],
    ) -> Self {
        EpilogueLayoutState {
            format_specific: P::new_epilogue_layout(args, output_kind, dynamic_symbol_definitions),
        }
    }

    fn apply_late_size_adjustments(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        total_sizes: &mut OutputSectionPartMap<u64>,
        resources: &FinaliseSizesResources<'data, '_, P>,
    ) -> Result {
        let mut extra_sizes = OutputSectionPartMap::with_size(common.mem_sizes.num_parts());
        P::apply_late_size_adjustments_epilogue(
            &mut self.format_specific,
            total_sizes,
            &mut extra_sizes,
            resources.dynamic_symbol_definitions,
            resources.symbol_db.args,
        )?;

        // See comments in Prelude::apply_late_size_adjustments.
        total_sizes.merge(&extra_sizes);
        common.mem_sizes.merge(&extra_sizes);

        Ok(())
    }

    fn finalise_sizes(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        resources: &FinaliseSizesResources<'data, '_, P>,
    ) {
        let symbol_db = resources.symbol_db;

        P::finalise_sizes_epilogue(
            &mut self.format_specific,
            &mut common.mem_sizes,
            resources.dynamic_symbol_definitions,
            resources.format_specific,
            symbol_db,
        );
    }

    fn finalise_layout(
        mut self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resources: &FinaliseLayoutResources<'_, 'data, P>,
    ) -> Result<EpilogueLayout<P>> {
        let dynsym_start_index = ((memory_offsets.get(part_id::DYNSYM)
            - resources
                .section_layouts
                .get(output_section_id::DYNSYM)
                .mem_offset)
            / size_of::<P::SymtabEntry>() as u64)
            .try_into()
            .context("Too many dynamic symbols")?;

        P::finalise_layout_epilogue(
            &mut self.format_specific,
            memory_offsets,
            resources.symbol_db,
            resources.format_specific,
            dynsym_start_index,
            resources.dynamic_symbol_definitions,
        )?;

        Ok(EpilogueLayout {
            format_specific: self.format_specific,
            dynsym_start_index,
        })
    }
}

#[derive(Debug)]
pub(crate) struct HeaderInfo {
    pub(crate) num_output_sections_with_content: u16,
    pub(crate) active_segment_ids: Vec<ProgramSegmentId>,
}

/// Construct a new inactive instance, which means we don't yet load non-GC sections and only
/// load them later if a symbol from this object is referenced.
fn new_object_layout_state<P: Platform>(
    input_state: resolution::ResolvedObject<P>,
) -> FileLayoutState<P> {
    // Note, this function is called for all objects from a single thread, so don't be tempted to do
    // significant work here. Do work when activate is called instead. Doing it there also means
    // that we don't do the work unless the object is actually needed.

    FileLayoutState::Object(ObjectLayoutState {
        file_id: input_state.common.file_id,
        symbol_id_range: input_state.common.symbol_id_range,
        input: input_state.common.input,
        object: input_state.common.object,
        sections: input_state.sections,
        relocations: input_state.relocations,
        format_specific: Default::default(),
        section_relax_deltas: RelaxDeltaMap::new(),
    })
}

fn new_dynamic_object_layout_state<'data, P: Platform>(
    input_state: &resolution::ResolvedDynamic<'data, P>,
) -> FileLayoutState<'data, P> {
    FileLayoutState::Dynamic(DynamicLayoutState {
        file_id: input_state.common.file_id,
        symbol_id_range: input_state.common.symbol_id_range,
        lib_name: input_state.lib_name(),
        object: input_state.common.object,
        input: input_state.common.input,
        format_specific_state: Default::default(),
    })
}

impl<'data, P: Platform> ObjectLayoutState<'data, P> {
    #[inline(always)]
    fn activate<'scope, A: Arch<Platform = P>>(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        resources: &'scope GraphResources<'data, 'scope, P>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result {
        let mut frame_section_index = None;
        let mut note_gnu_property_section = None;
        let mut riscv_attributes_section = None;

        let no_gc = !resources.symbol_db.args.should_gc_sections();

        for (i, section) in self.sections.iter().enumerate() {
            match section {
                SectionSlot::MustLoad(..)
                | SectionSlot::UnloadedDebugInfo(..)
                | SectionSlot::MergeStrings(_) => {
                    queue
                        .local_work
                        .push(WorkItem::LoadSection(SectionLoadRequest::new(
                            self.file_id,
                            object::SectionIndex(i),
                        )));
                }
                SectionSlot::Unloaded(sec) => {
                    if no_gc {
                        queue
                            .local_work
                            .push(WorkItem::LoadSection(SectionLoadRequest::new(
                                self.file_id,
                                object::SectionIndex(i),
                            )));
                    } else if sec.start_stop_eligible {
                        resources
                            .start_stop_sections
                            .get(sec.part_id.output_section_id())
                            .push(SectionLoadRequest {
                                file_id: self.file_id,
                                section_index: i as u32,
                            });
                    }
                }
                SectionSlot::FrameData(index) => {
                    frame_section_index = Some(*index);
                }
                SectionSlot::NoteGnuProperty(index) => {
                    note_gnu_property_section = Some(*index);
                }
                SectionSlot::RiscvVAttributes(index) => {
                    riscv_attributes_section = Some(*index);
                }
                _ => (),
            }
        }

        if let Some(frame_data_section_index) = frame_section_index {
            <A::Platform as Platform>::load_exception_frame_data::<A>(
                self,
                common,
                frame_data_section_index,
                resources,
                queue,
                scope,
            )?;
        }

        if let Some(section_index) = note_gnu_property_section {
            self.object
                .process_gnu_note_section(&mut self.format_specific, section_index)?;
        }

        if let Some(riscv_attributes_index) = riscv_attributes_section {
            A::process_riscv_attributes(
                self.object,
                &mut self.format_specific,
                riscv_attributes_index,
            )
            .context("Cannot parse .riscv.attributes section")?;
        }

        let export_all_dynamic = resources.symbol_db.output_kind == OutputKind::SharedObject
            && (!self.input.has_archive_semantics()
                || resources
                    .symbol_db
                    .args
                    .should_export_dynamic(self.input.lib_name()))
            || resources.symbol_db.output_kind.needs_dynsym()
                && resources.symbol_db.args.should_export_all_dynamic_symbols();
        if export_all_dynamic
            || resources.symbol_db.output_kind.needs_dynsym()
                && resources.symbol_db.export_list.is_some()
        {
            self.load_non_hidden_symbols::<A>(common, resources, queue, export_all_dynamic, scope)?;
        }

        Ok(())
    }

    fn handle_section_load_request<'scope, A: Arch<Platform = P>>(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        resources: &'scope GraphResources<'data, 'scope, P>,
        queue: &mut LocalWorkQueue,
        section_index: SectionIndex,
        scope: &Scope<'scope>,
    ) -> Result<(), Error> {
        match &self.sections[section_index.0] {
            SectionSlot::Unloaded(unloaded) | SectionSlot::MustLoad(unloaded) => {
                self.load_section::<A>(common, queue, *unloaded, section_index, resources, scope)?;
            }
            SectionSlot::UnloadedDebugInfo(part_id) => {
                // On RISC-V, the debug info sections contain relocations to local symbols (e.g.
                // labels).
                self.load_debug_section::<A>(
                    common,
                    queue,
                    *part_id,
                    section_index,
                    resources,
                    scope,
                )?;
            }
            SectionSlot::Discard => {
                bail!(
                    "{self}: Don't know what segment to put `{}` in, but it's referenced",
                    self.object.section_display_name(section_index),
                );
            }
            SectionSlot::Loaded(_)
            | SectionSlot::FrameData(..)
            | SectionSlot::LoadedDebugInfo(..)
            | SectionSlot::NoteGnuProperty(..)
            | SectionSlot::RiscvVAttributes(..) => {}
            SectionSlot::MergeStrings(sec) => {
                // We currently always load everything in merge-string sections. i.e. we don't GC
                // unreferenced data. So the only thing we need to do here is propagate section
                // flags.
                let header = self.object.section(section_index)?;
                common.store_section_attributes(sec.part_id, header);
            }
        };

        Ok(())
    }

    fn load_section<'scope, A: Arch<Platform = P>>(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        queue: &mut LocalWorkQueue,
        unloaded: UnloadedSection,
        section_index: SectionIndex,
        resources: &'scope GraphResources<'data, 'scope, P>,
        scope: &Scope<'scope>,
    ) -> Result {
        let part_id = unloaded.part_id;
        let header = self.object.section(section_index)?;
        let section = Section::create(header, self, section_index, part_id)?;

        <A::Platform as Platform>::load_object_section_relocations::<A>(
            self, common, queue, resources, section, scope,
        )?;

        tracing::debug!(loaded_section = %self.object.section_display_name(section_index), file = %self.input);

        common.section_loaded(part_id, header, section, resources.output_sections);

        let section_id = section.output_section_id();

        if section.size > 0 {
            P::non_empty_section_loaded::<A>(self, common, queue, unloaded, resources, scope)?;
        } else if P::is_zero_sized_section_content(section_id) {
            resources.keep_section(section_id);
        }

        self.sections[section_index.0] = SectionSlot::Loaded(section);

        Ok(())
    }

    fn load_debug_section<'scope, A: Arch<Platform = P>>(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        queue: &mut LocalWorkQueue,

        part_id: PartId,
        section_index: SectionIndex,
        resources: &'scope GraphResources<'data, '_, P>,
        scope: &Scope<'scope>,
    ) -> Result {
        let header = self.object.section(section_index)?;
        let section = Section::create(header, self, section_index, part_id)?;
        if A::local_symbols_in_debug_info() {
            <A::Platform as Platform>::load_object_debug_relocations::<A>(
                self, common, queue, resources, section, scope,
            )?;
        }

        tracing::debug!(loaded_debug_section = %self.object.section_display_name(section_index),);
        common.section_loaded(part_id, header, section, resources.output_sections);
        self.sections[section_index.0] = SectionSlot::LoadedDebugInfo(section);

        Ok(())
    }

    fn finalise_sizes(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        output_sections: &OutputSections<P>,
        per_symbol_flags: &AtomicPerSymbolFlags,
        resources: &FinaliseSizesResources<'data, '_, P>,
    ) {
        common.mem_sizes.resize(output_sections.num_parts());
        if !resources.symbol_db.args.should_strip_all() {
            self.allocate_symtab_space(common, resources.symbol_db, per_symbol_flags);
        }
        let output_kind = resources.symbol_db.output_kind;
        for slot in &mut self.sections {
            if let SectionSlot::Loaded(section) = slot {
                P::allocate_resolution(section.flags, &mut common.mem_sizes, output_kind);
            }
        }

        P::finalise_object_sizes(self, common);
    }

    fn allocate_symtab_space(
        &self,
        common: &mut CommonGroupState<'data, P>,
        symbol_db: &SymbolDb<'data, P>,
        per_symbol_flags: &AtomicPerSymbolFlags,
    ) {
        let _file_span = symbol_db.args.common().trace_span_for_file(self.file_id());
        P::allocate_object_symtab_space(self, common, symbol_db, per_symbol_flags);
    }

    fn finalise_layout(
        mut self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter<P>,
        resources: &FinaliseLayoutResources<'_, 'data, P>,
    ) -> Result<ObjectLayout<'data, P>> {
        let _file_span = resources
            .symbol_db
            .args
            .common()
            .trace_span_for_file(self.file_id());
        let symbol_id_range = self.symbol_id_range();

        let sframe_start_address = resources
            .section_layouts
            .get(output_section_id::SFRAME)
            .mem_offset;
        let mut sframe_ranges = Vec::new();

        let mut section_resolutions = Vec::with_capacity(self.sections.len());
        for slot in &mut self.sections {
            let resolution = match slot {
                SectionSlot::Loaded(sec) => {
                    let part_id = sec.part_id;
                    let address = *memory_offsets.get(part_id);
                    // TODO: We probably need to be able to handle sections that are ifuncs and
                    // sections that need a TLS GOT struct.
                    *memory_offsets.get_mut(part_id) += sec.capacity(resources.output_sections);
                    // Collect SFrame section ranges while we're already iterating
                    if part_id.output_section_id() == output_section_id::SFRAME {
                        let offset = (address - sframe_start_address) as usize;
                        let len = sec.size as usize;
                        sframe_ranges.push(offset..offset + len);
                    }
                    SectionResolution { address }
                }
                &mut SectionSlot::LoadedDebugInfo(sec) => {
                    let address = *memory_offsets.get(sec.part_id);
                    *memory_offsets.get_mut(sec.part_id) += sec.capacity(resources.output_sections);
                    SectionResolution { address }
                }
                SectionSlot::FrameData(..) => {
                    let address = P::frame_data_base_address(memory_offsets);
                    SectionResolution { address }
                }
                _ => SectionResolution::none(),
            };
            section_resolutions.push(resolution);
        }

        for ((local_symbol_index, local_symbol), &flags) in self
            .object
            .enumerate_symbols()
            .zip(resources.per_symbol_flags.raw_range(symbol_id_range))
        {
            self.finalise_symbol(
                resources,
                flags.get(),
                local_symbol,
                local_symbol_index,
                &section_resolutions,
                memory_offsets,
                resolutions_out,
            )?;
        }

        P::finalise_object_layout(&self, memory_offsets);

        Ok(ObjectLayout {
            input: self.input,
            file_id: self.file_id,
            object: self.object,
            sections: self.sections,
            relocations: self.relocations,
            section_resolutions,
            symbol_id_range,
            sframe_ranges,
            section_relax_deltas: self.section_relax_deltas,
        })
    }

    fn finalise_symbol<'scope>(
        &self,
        resources: &FinaliseLayoutResources<'scope, 'data, P>,
        flags: ValueFlags,
        local_symbol: &P::SymtabEntry,
        local_symbol_index: object::SymbolIndex,
        section_resolutions: &[SectionResolution],
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter<P>,
    ) -> Result {
        let resolution = self.create_symbol_resolution(
            resources,
            flags,
            local_symbol,
            local_symbol_index,
            section_resolutions,
            memory_offsets,
        )?;

        resolutions_out.write(resolution)
    }

    fn create_symbol_resolution<'scope>(
        &self,
        resources: &FinaliseLayoutResources<'scope, 'data, P>,
        flags: ValueFlags,
        local_symbol: &P::SymtabEntry,
        local_symbol_index: object::SymbolIndex,
        section_resolutions: &[SectionResolution],
        memory_offsets: &mut OutputSectionPartMap<u64>,
    ) -> Result<Option<Resolution<P>>> {
        let symbol_id_range = self.symbol_id_range();
        let symbol_id = symbol_id_range.input_to_id(local_symbol_index);

        if !flags.has_resolution() || !resources.symbol_db.is_canonical(symbol_id) {
            return Ok(None);
        }

        let raw_value = if let Some(section_index) = self
            .object
            .symbol_section(local_symbol, local_symbol_index)?
        {
            if let Some(section_address) = section_resolutions[section_index.0].address() {
                let input_offset = local_symbol.value();
                let output_offset = opt_input_to_output(
                    self.section_relax_deltas.get(section_index.0),
                    input_offset,
                );
                output_offset + section_address
            } else {
                match get_merged_string_output_address::<P>(
                    local_symbol_index,
                    0,
                    self.object,
                    &self.sections,
                    resources.merged_strings,
                    resources.merged_string_start_addresses,
                    true,
                )? {
                    Some(x) => x,
                    None => {
                        // Don't error for mapping symbols. They cannot have relocations refer to
                        // them, so we don't need to produce a resolution.
                        if resources.symbol_db.is_mapping_symbol(symbol_id) {
                            return Ok(None);
                        }
                        bail!(
                            "Symbol is in a section that we didn't load. \
                             Symbol: {} Section: {} Res: {flags}",
                            resources.symbol_debug(symbol_id),
                            section_debug::<P>(self.object, section_index),
                        );
                    }
                }
            }
        } else if let Some(common) = local_symbol.as_common() {
            let offset = memory_offsets.get_mut(common.part_id);
            let address = *offset;
            *offset += common.size;
            address
        } else {
            local_symbol.value()
        };

        let mut dynamic_symbol_index = None;
        if flags.is_dynamic() {
            // This is an undefined weak symbol. Emit it as a dynamic symbol so that it can be
            // overridden at runtime.
            let dyn_sym_index = P::take_dynsym_index(memory_offsets, resources.section_layouts)?;
            dynamic_symbol_index = Some(
                NonZeroU32::new(dyn_sym_index)
                    .context("Attempted to create dynamic symbol index 0")?,
            );
        }

        Ok(Some(P::create_resolution(
            flags,
            raw_value,
            dynamic_symbol_index,
            memory_offsets,
        )))
    }

    fn load_non_hidden_symbols<'scope, A: Arch<Platform = P>>(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        resources: &'scope GraphResources<'data, 'scope, P>,
        queue: &mut LocalWorkQueue,
        export_all_dynamic: bool,
        scope: &Scope<'scope>,
    ) -> Result {
        for (sym_index, sym) in self.object.enumerate_symbols() {
            let symbol_id = self.symbol_id_range().input_to_id(sym_index);

            if !can_export_symbol(sym, symbol_id, resources, export_all_dynamic) {
                continue;
            }

            let old_flags = resources
                .per_symbol_flags
                .get_atomic(symbol_id)
                .fetch_or(ValueFlags::EXPORT_DYNAMIC);

            if !old_flags.has_resolution() {
                self.load_symbol::<A>(common, symbol_id, resources, queue, scope)?;
            }

            if !old_flags.needs_export_dynamic() {
                export_dynamic(common, symbol_id, resources.symbol_db)?;
            }
        }
        Ok(())
    }

    fn export_dynamic<'scope, A: Arch<Platform = P>>(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        symbol_id: SymbolId,
        resources: &'scope GraphResources<'data, 'scope, P>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result {
        let sym = self
            .object
            .symbol(self.symbol_id_range.id_to_input(symbol_id))?;

        // Shared objects that we're linking against sometimes define symbols that are also defined
        // in regular object. When that happens, if we resolve the symbol to the definition from the
        // regular object, then the shared object might send us a request to export the definition
        // provided by the regular object. This isn't always possible, since the symbol might be
        // hidden.
        if !can_export_symbol(sym, symbol_id, resources, true) {
            return Ok(());
        }

        let old_flags = resources
            .per_symbol_flags
            .get_atomic(symbol_id)
            .fetch_or(ValueFlags::EXPORT_DYNAMIC);

        if !old_flags.has_resolution() {
            self.load_symbol::<A>(common, symbol_id, resources, queue, scope)?;
        }

        if !old_flags.needs_export_dynamic() {
            export_dynamic(common, symbol_id, resources.symbol_db)?;
        }

        Ok(())
    }

    pub(crate) fn relocations(&self, index: SectionIndex) -> Result<P::RelocationList<'data>> {
        self.object.relocations(index, &self.relocations)
    }
}

pub(crate) struct SymbolCopyInfo<'data> {
    pub(crate) name: &'data [u8],
}

impl<'data> SymbolCopyInfo<'data> {
    /// The primary purpose of this function is to determine whether a symbol should be copied into
    /// the symtab. In the process, we also return the name of the symbol, to avoid needing to read
    /// it again.
    #[inline(always)]
    pub(crate) fn new<P: Platform>(
        object: &P::File<'data>,
        sym_index: object::SymbolIndex,
        sym: &P::SymtabEntry,
        symbol_id: SymbolId,
        symbol_db: &SymbolDb<'data, P>,
        symbol_state: ValueFlags,
        sections: &[SectionSlot],
    ) -> Option<SymbolCopyInfo<'data>> {
        if !symbol_db.is_canonical(symbol_id) || sym.is_undefined() {
            return None;
        }

        if let Ok(Some(section)) = object.symbol_section(sym, sym_index)
            && !sections[section.0].is_loaded()
        {
            // Symbol is in a discarded section.
            return None;
        }

        if sym.as_common().is_some() && !symbol_state.has_resolution() {
            return None;
        }

        // Reading the symbol name is slightly expensive, so we want to do that after all the other
        // checks. That's also the reason why we return the symbol name, so that the caller, if it
        // needs the name, doesn't have a go and read it again.
        let name = object.symbol_name(sym).ok()?;
        if name.is_empty()
            || (sym.is_local() && name.starts_with(b".L"))
            || is_mapping_symbol_name(name)
        {
            return None;
        }

        if symbol_db.args.should_strip_symbol_named(name) {
            return None;
        }

        Some(SymbolCopyInfo { name })
    }
}

/// Returns whether the supplied symbol can be exported when we're outputting a shared object.
fn can_export_symbol<'data, P: Platform>(
    sym: &P::SymtabEntry,
    symbol_id: SymbolId,
    resources: &GraphResources<'data, '_, P>,
    export_all_dynamic: bool,
) -> bool {
    if sym.is_undefined() || sym.is_local() {
        return false;
    }

    let visibility = sym.visibility();

    if visibility == Visibility::Hidden {
        return false;
    }

    if !resources.symbol_db.is_canonical(symbol_id) {
        return false;
    }

    let flags = resources.local_flags_for_symbol(symbol_id);

    if flags.is_downgraded_to_local() {
        return false;
    }

    if !export_all_dynamic
        && let Some(export_list) = &resources.symbol_db.export_list
        && let Ok(symbol_name) = resources.symbol_db.symbol_name(symbol_id)
        && !&export_list.contains(&UnversionedSymbolName::prehashed(symbol_name.bytes()))
    {
        return false;
    }

    true
}

pub(crate) struct ResolutionWriter<'writer, 'out, P: Platform> {
    resolutions_out: &'writer mut sharded_vec_writer::Shard<'out, Option<Resolution<P>>>,
}

impl<P: Platform> ResolutionWriter<'_, '_, P> {
    pub(crate) fn write(&mut self, res: Option<Resolution<P>>) -> Result {
        self.resolutions_out.try_push(res)?;
        Ok(())
    }
}

impl<'data, P: Platform> resolution::ResolvedFile<'data, P> {
    fn create_layout_state(self) -> FileLayoutState<'data, P> {
        match self {
            resolution::ResolvedFile::Object(s) => new_object_layout_state(s),
            resolution::ResolvedFile::Dynamic(s) => new_dynamic_object_layout_state(&s),
            resolution::ResolvedFile::Prelude(s) => {
                FileLayoutState::Prelude(PreludeLayoutState::new(s))
            }
            resolution::ResolvedFile::NotLoaded(s) => FileLayoutState::NotLoaded(s),
            resolution::ResolvedFile::LinkerScript(s) => {
                FileLayoutState::LinkerScript(LinkerScriptLayoutState::new(s))
            }
            resolution::ResolvedFile::SyntheticSymbols(s) => {
                FileLayoutState::SyntheticSymbols(SyntheticSymbolsLayoutState::new(s))
            }
            #[cfg(feature = "plugins")]
            resolution::ResolvedFile::LtoInput(s) => FileLayoutState::NotLoaded(NotLoaded {
                symbol_id_range: s.symbol_id_range,
            }),
        }
    }
}

impl<P: Platform> Resolution<P> {
    pub(crate) fn flags(self) -> ValueFlags {
        self.flags
    }

    pub(crate) fn value(self) -> u64 {
        self.raw_value
    }

    pub(crate) fn address(&self) -> Result<u64> {
        if !self.flags.is_address() {
            bail!("Expected address, found {}", self.flags);
        }
        Ok(self.raw_value)
    }

    pub(crate) fn value_for_symbol_table(&self) -> u64 {
        self.raw_value
    }

    pub(crate) fn is_absolute(&self) -> bool {
        self.flags.is_absolute()
    }

    pub(crate) fn dynamic_symbol_index(&self) -> Result<u32> {
        Ok(self
            .dynamic_symbol_index
            .context("Missing dynamic_symbol_index")?
            .get())
    }
}

/// Maximum number of relaxation scan iterations. In practice convergence
/// happens in 2–3 passes.
const MAX_RELAXATION_ITERATIONS: usize = 5;

/// Sentinel value stored in `SymbolOutputInfos::addresses` for symbols whose output address is
/// unknown.
const SYMBOL_ADDRESS_UNRESOLVED: u64 = u64::MAX;

/// Stores precomputed output-address information for every symbol.
struct SymbolOutputInfos {
    addresses: Vec<u64>,
}

impl SymbolOutputInfos {
    fn resolve(
        &self,
        symbol_id: SymbolId,
        per_symbol_flags: &PerSymbolFlags,
    ) -> Option<RelaxSymbolInfo> {
        let addr = *self.addresses.get(symbol_id.as_usize())?;
        if addr == SYMBOL_ADDRESS_UNRESOLVED {
            return None;
        }
        Some(RelaxSymbolInfo {
            output_address: addr,
            is_interposable: per_symbol_flags
                .flags_for_symbol(symbol_id)
                .is_interposable(),
        })
    }
}

/// Compute the output address of every loaded input section and every symbol in a single parallel
/// pass over groups.
fn compute_section_and_symbol_addresses<'data, P: Platform>(
    group_states: &[GroupState<'data, P>],
    section_part_layouts: &OutputSectionPartMap<OutputRecordLayout>,
    symbol_db: &SymbolDb<'data, P>,
    output_sections: &OutputSections<P>,
) -> (Vec<Vec<Vec<u64>>>, SymbolOutputInfos) {
    timing_phase!("Compute section and symbol addresses");
    let mem_offsets: OutputSectionPartMap<u64> = starting_memory_offsets(section_part_layouts);
    let starting_offsets = compute_start_offsets_by_group(group_states, mem_offsets);

    let symbol_addresses: Vec<AtomicU64> = (0..symbol_db.num_symbols())
        .map(|_| AtomicU64::new(SYMBOL_ADDRESS_UNRESOLVED))
        .collect();

    let section_addresses: Vec<Vec<Vec<u64>>> = group_states
        .par_iter()
        .enumerate()
        .map(|(group_idx, group)| {
            let mut offsets = starting_offsets[group_idx].clone();

            group
                .files
                .iter()
                .map(|file| match file {
                    FileLayoutState::Object(obj) => {
                        let mut addresses = vec![0u64; obj.sections.len()];
                        for (sec_idx, slot) in obj.sections.iter().enumerate() {
                            match slot {
                                SectionSlot::Loaded(sec) => {
                                    addresses[sec_idx] = *offsets.get(sec.part_id);
                                    *offsets.get_mut(sec.part_id) += sec.capacity(output_sections);
                                }
                                SectionSlot::LoadedDebugInfo(sec) => {
                                    // Advance offsets so subsequent sections are placed
                                    // correctly, but we don't need the address for relaxation.
                                    *offsets.get_mut(sec.part_id) += sec.capacity(output_sections);
                                }
                                _ => {}
                            }
                        }

                        P::compute_object_addresses(obj, &mut offsets);

                        // While we have the section addresses, also resolve symbol
                        // output addresses for this file's canonical definitions.
                        for sym_offset in 0..obj.symbol_id_range.len() {
                            let sym_input_idx = object::SymbolIndex(sym_offset);
                            let Ok(sym) = obj.object.symbol(sym_input_idx) else {
                                continue;
                            };
                            let sym_id = obj.symbol_id_range.input_to_id(sym_input_idx);
                            let def_id = symbol_db.definition(sym_id);
                            // Only record the address for the canonical definition.
                            if def_id != sym_id {
                                continue;
                            }

                            match obj.object.symbol_section(sym, sym_input_idx) {
                                Ok(Some(section)) => {
                                    let sec_addr = addresses.get(section.0).copied().unwrap_or(0);
                                    if sec_addr == 0 {
                                        continue;
                                    }
                                    symbol_addresses[sym_id.as_usize()]
                                        .store(sec_addr + sym.value(), Relaxed);
                                }
                                Ok(None) if sym.is_absolute() => {
                                    symbol_addresses[sym_id.as_usize()].store(sym.value(), Relaxed);
                                }
                                _ => continue,
                            }
                        }

                        addresses
                    }
                    _ => vec![],
                })
                .collect()
        })
        .collect();

    let addresses = symbol_addresses
        .into_iter()
        .map(|a| a.into_inner())
        .collect();

    (section_addresses, SymbolOutputInfos { addresses })
}

/// Per-file list of section indices to rescan on subsequent relaxation iterations. Indexed as
/// `[group_idx][file_idx]`.  Files that are not objects get an empty entry.
type RescanSections = Vec<Vec<SmallVec<[usize; 16]>>>;

/// Like `RescanSections` but each entry also carries the minimum margin (in bytes) among the
/// section's unrelaxed candidates.  This is returned by `relaxation_scan_pass` and then filtered
/// by `total_deleted` to produce a `RescanSections` for the next iteration.
type RescanCandidates = Vec<Vec<SmallVec<[(usize, u64); 16]>>>;

/// Run one pass of the relaxation scan across all groups/objects.  Returns the total number of
/// bytes newly deleted in this pass together with the set of sections that should be rescanned on
/// the next iteration.
fn relaxation_scan_pass<'data, A: Arch>(
    group_states: &mut [GroupState<'data, A::Platform>],
    section_part_layouts: &OutputSectionPartMap<OutputRecordLayout>,
    symbol_db: &SymbolDb<'data, A::Platform>,
    per_symbol_flags: &PerSymbolFlags,
    section_part_sizes: &mut OutputSectionPartMap<u64>,
    prev_rescan: Option<&RescanSections>,
    output_sections: &OutputSections<A::Platform>,
) -> (u64, RescanCandidates) {
    timing_phase!("Relaxation scan pass");

    let (section_addresses, symbol_infos) = compute_section_and_symbol_addresses(
        group_states,
        section_part_layouts,
        symbol_db,
        output_sections,
    );

    // Scan each group.
    #[expect(clippy::type_complexity)]
    let group_results: Vec<(OutputSectionPartMap<u64>, Vec<SmallVec<[(usize, u64); 16]>>)> =
        group_states
            .par_iter_mut()
            .enumerate()
            .map(|(group_idx, group)| {
                let mut reductions =
                    OutputSectionPartMap::with_size(section_part_sizes.num_parts());
                let mut file_rescans: Vec<SmallVec<[(usize, u64); 16]>> =
                    Vec::with_capacity(group.files.len());

                for (file_idx, file) in group.files.iter_mut().enumerate() {
                    let FileLayoutState::Object(obj) = file else {
                        file_rescans.push(SmallVec::new());
                        continue;
                    };

                    let file_section_addrs = &section_addresses[group_idx][file_idx];

                    let sections_to_scan: SmallVec<[usize; 16]> = match prev_rescan {
                        Some(rescan) => rescan[group_idx][file_idx].clone(),
                        None => obj
                            .sections
                            .iter()
                            .enumerate()
                            .filter_map(|(i, slot)| {
                                if let SectionSlot::Loaded(_) = slot
                                    && let Ok(header) = obj.object.section(SectionIndex(i))
                                    && header.is_executable()
                                {
                                    Some(i)
                                } else {
                                    None
                                }
                            })
                            .collect(),
                    };

                    let mut next_rescan: SmallVec<[(usize, u64); 16]> = SmallVec::new();

                    for sec_idx in &sections_to_scan {
                        let sec_idx = *sec_idx;
                        let section_index = SectionIndex(sec_idx);
                        let relocs = match obj.object.relocations(section_index, &obj.relocations) {
                            Ok(r) => r,
                            Err(_) => continue,
                        };

                        let sec_output_addr = file_section_addrs.get(sec_idx).copied().unwrap_or(0);
                        if sec_output_addr == 0 {
                            continue;
                        }

                        let existing_deltas = obj.section_relax_deltas.get(sec_idx);

                        // Symbol resolver: look up the canonical definition's output
                        // address via the precomputed table.
                        let mut resolve_symbol =
                            |sym_idx: object::SymbolIndex| -> Option<RelaxSymbolInfo> {
                                let local_id = obj.symbol_id_range.input_to_id(sym_idx);
                                let def_id = symbol_db.definition(local_id);
                                symbol_infos.resolve(def_id, per_symbol_flags)
                            };

                        let section_header = match obj.object.section(section_index) {
                            Ok(h) => h,
                            Err(_) => continue,
                        };
                        let section_bytes = match obj.object.raw_section_data(section_header) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };

                        let (raw_deltas, min_margin) = A::collect_relaxation_deltas(
                            sec_output_addr,
                            section_bytes,
                            relocs,
                            existing_deltas,
                            &mut resolve_symbol,
                        );

                        if let Some(margin) = min_margin {
                            next_rescan.push((sec_idx, margin));
                        }

                        if raw_deltas.is_empty() {
                            continue;
                        }

                        let new_total_deleted: u64 =
                            raw_deltas.iter().map(|(_, b)| u64::from(*b)).sum();

                        if let SectionSlot::Loaded(sec) = &mut obj.sections[sec_idx] {
                            let old_capacity = sec.capacity(output_sections);
                            sec.size -= new_total_deleted;
                            let new_capacity = sec.capacity(output_sections);
                            debug_assert!(old_capacity >= new_capacity);
                            let capacity_reduction = old_capacity - new_capacity;
                            if capacity_reduction > 0 {
                                let part_id = sec.part_id;
                                group
                                    .common
                                    .mem_sizes
                                    .decrement(part_id, capacity_reduction);
                                *reductions.get_mut(part_id) += capacity_reduction;
                            }
                        }

                        if let Some(existing) = obj.section_relax_deltas.get_mut(sec_idx) {
                            existing.merge_additional(raw_deltas);
                        } else {
                            obj.section_relax_deltas
                                .insert_sorted(sec_idx, SectionRelaxDeltas::new(raw_deltas));
                        }
                    }

                    file_rescans.push(next_rescan);
                }

                (reductions, file_rescans)
            })
            .collect();

    let mut total_deleted = 0u64;
    let mut next_rescan_candidates: RescanCandidates = Vec::with_capacity(group_results.len());
    for (reduction, file_rescans) in group_results {
        for (idx, &amount) in reduction.parts.iter().enumerate() {
            if amount > 0 {
                let part_id = PartId::from_usize(idx);
                section_part_sizes.decrement(part_id, amount);
                total_deleted += amount;
            }
        }
        next_rescan_candidates.push(file_rescans);
    }

    (total_deleted, next_rescan_candidates)
}

fn perform_iterative_relaxation<'data, A: Arch>(
    group_states: &mut [GroupState<'data, A::Platform>],
    section_part_sizes: &mut OutputSectionPartMap<u64>,
    section_part_layouts: &mut OutputSectionPartMap<OutputRecordLayout>,
    output_sections: &OutputSections<A::Platform>,
    program_segments: &ProgramSegments<<A::Platform as Platform>::ProgramSegmentDef>,
    output_order: &OutputOrder,
    symbol_db: &SymbolDb<'data, A::Platform>,
    per_symbol_flags: &PerSymbolFlags,
) {
    timing_phase!("Iterative relaxation");

    let mut rescan_sections: Option<RescanSections> = None;

    for _iteration in 0..MAX_RELAXATION_ITERATIONS {
        if let Some(ref rescan) = rescan_sections
            && rescan
                .iter()
                .all(|files| files.iter().all(|secs| secs.is_empty()))
        {
            break;
        }

        let (deleted, next_candidates) = relaxation_scan_pass::<A>(
            group_states,
            section_part_layouts,
            symbol_db,
            per_symbol_flags,
            section_part_sizes,
            rescan_sections.as_ref(),
            output_sections,
        );

        if deleted == 0 {
            break;
        }

        // Filter the rescan candidates: only keep sections whose closest
        // unrelaxed candidate is within `deleted` bytes of the relaxation
        // boundary.  Candidates further away cannot possibly succeed because
        // addresses shift by at most `deleted` bytes per iteration.
        rescan_sections = Some(
            next_candidates
                .into_iter()
                .map(|files| {
                    files
                        .into_iter()
                        .map(|secs| {
                            secs.into_iter()
                                .filter(|&(_, margin)| margin <= deleted)
                                .map(|(idx, _)| idx)
                                .collect()
                        })
                        .collect()
                })
                .collect(),
        );

        *section_part_layouts = layout_section_parts::<A::Platform>(
            section_part_sizes,
            output_sections,
            program_segments,
            output_order,
            symbol_db.args,
        );
    }
}

fn layout_section_parts<P: Platform>(
    sizes: &OutputSectionPartMap<u64>,
    output_sections: &OutputSections<P>,
    program_segments: &ProgramSegments<P::ProgramSegmentDef>,
    output_order: &OutputOrder,
    args: &P::Args,
) -> OutputSectionPartMap<OutputRecordLayout> {
    let segment_alignments = compute_segment_alignments::<P>(
        sizes,
        program_segments,
        output_order,
        args,
        output_sections,
    );

    let mut file_offset = 0;
    let mut mem_offset = output_sections.base_address;
    let mut nonalloc_mem_offsets: OutputSectionMap<u64> =
        OutputSectionMap::with_size(output_sections.num_sections());

    let mut pending_location = None;

    let mut records_out = output_sections.new_part_map();

    for event in output_order {
        match event {
            OrderEvent::SetLocation(location) => {
                pending_location = Some(location);
            }
            OrderEvent::SegmentStart(segment_id) => {
                if program_segments.is_load_segment(segment_id) {
                    let segment_alignment = segment_alignments
                        .get(&segment_id)
                        .copied()
                        .unwrap_or_else(|| args.loadable_segment_alignment());
                    if let Some(location) = pending_location.take() {
                        mem_offset = location.address;
                        file_offset =
                            segment_alignment.align_modulo(mem_offset, file_offset as u64) as usize;
                    } else {
                        mem_offset = segment_alignment.align_modulo(file_offset as u64, mem_offset);
                    }
                }
            }
            OrderEvent::SegmentEnd(_) => {}
            OrderEvent::Section(section_id) => {
                debug_assert!(
                    pending_location.is_none(),
                    "SetLocation, Section without SegmentStart"
                );
                let section_info = output_sections.output_info(section_id);
                let part_id_range = section_id.part_id_range();
                let max_alignment = sizes.max_alignment(part_id_range.clone(), output_sections);
                if let Some(location) = section_info.location {
                    mem_offset = location.address;
                }

                records_out[part_id_range.clone()]
                    .iter_mut()
                    .zip(&sizes[part_id_range.clone()])
                    .enumerate()
                    .for_each(|(offset, (part_layout, &part_size))| {
                        let part_id = part_id_range.start.offset(offset);
                        let alignment = part_id.alignment(output_sections).min(max_alignment);
                        let merge_target = output_sections.primary_output_section(section_id);
                        let section_flags = output_sections.section_flags(merge_target);
                        let mem_size = if section_id == output_section_id::RELRO_PADDING {
                            let page_alignment = args.loadable_segment_alignment();
                            let aligned_offset = page_alignment.align_up(mem_offset);
                            aligned_offset - mem_offset
                        } else {
                            part_size
                        };

                        // Note, we align up even if our size is zero, otherwise our section will
                        // start at an unaligned address.
                        file_offset = alignment.align_up_usize(file_offset);

                        if section_flags.is_alloc() {
                            mem_offset = alignment.align_up(mem_offset);

                            let file_size = if output_sections.has_data_in_file(merge_target) {
                                mem_size as usize
                            } else {
                                0
                            };

                            *part_layout = OutputRecordLayout {
                                file_size,
                                mem_size,
                                alignment,
                                file_offset,
                                mem_offset,
                            };

                            file_offset += file_size;
                            mem_offset += mem_size;
                        } else {
                            let section_id = part_id.output_section_id();
                            let mem_offset =
                                alignment.align_up(*nonalloc_mem_offsets.get(section_id));

                            *nonalloc_mem_offsets.get_mut(section_id) += mem_size;

                            *part_layout = OutputRecordLayout {
                                file_size: mem_size as usize,
                                mem_size,
                                alignment,
                                file_offset,
                                mem_offset,
                            };
                            file_offset += mem_size as usize;
                        }
                    });
            }
        };
    }

    records_out
}

/// Computes the maximum alignment for each LOAD segment by examining the alignments of all sections
/// that will be placed in that segment.
fn compute_segment_alignments<P: Platform>(
    sizes: &OutputSectionPartMap<u64>,
    program_segments: &ProgramSegments<P::ProgramSegmentDef>,
    output_order: &OutputOrder,
    args: &P::Args,
    output_sections: &OutputSections<P>,
) -> HashMap<ProgramSegmentId, Alignment> {
    timing_phase!("Computing segment alignments");

    let mut segment_alignments: HashMap<ProgramSegmentId, Alignment> = HashMap::new();
    let mut active_load_segments: Vec<ProgramSegmentId> = Vec::new();

    for event in output_order {
        match event {
            OrderEvent::SegmentStart(segment_id) => {
                if program_segments.is_load_segment(segment_id) {
                    // Initialize with the base loadable segment alignment
                    segment_alignments
                        .entry(segment_id)
                        .or_insert_with(|| args.loadable_segment_alignment());
                    active_load_segments.push(segment_id);
                }
            }
            OrderEvent::SegmentEnd(segment_id) => {
                active_load_segments.retain(|&id| id != segment_id);
            }
            OrderEvent::Section(section_id) => {
                let part_id_range = section_id.part_id_range();
                let max_alignment = sizes.max_alignment(part_id_range, output_sections);

                // Update the alignment for all active LOAD segments
                for &segment_id in &active_load_segments {
                    segment_alignments
                        .entry(segment_id)
                        .and_modify(|a| *a = (*a).max(max_alignment));
                }
            }
            OrderEvent::SetLocation(_) => {}
        }
    }

    segment_alignments
}

impl<'data, P: Platform> DynamicLayoutState<'data, P> {
    fn activate<'scope, A: Arch<Platform = P>>(
        &mut self,
        common: &mut CommonGroupState<'data, P>,
        resources: &'scope GraphResources<'data, '_, P>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result {
        P::activate_dynamic(self, common);

        self.request_all_undefined_symbols::<A>(resources, queue, scope)
    }

    fn request_all_undefined_symbols<'scope, A: Arch<Platform = P>>(
        &self,
        resources: &'scope GraphResources<'data, '_, P>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result {
        let mut check_undefined_cache = None;

        for symbol_id in self.symbol_id_range() {
            let definition_symbol_id = resources.symbol_db.definition(symbol_id);

            let flags = resources.local_flags_for_symbol(definition_symbol_id);

            if flags.is_dynamic() && flags.is_absolute() {
                // Our shared object references an undefined symbol. Whether that is an error or
                // not, depends on flags, whether the symbol is weak and whether all of the shared
                // object's dependencies are loaded.

                let args = resources.symbol_db.args;
                let check_undefined = *check_undefined_cache
                    .get_or_insert_with(|| self.object.should_enforce_undefined(resources));

                if check_undefined {
                    let symbol = self
                        .object
                        .symbol(self.symbol_id_range.id_to_input(symbol_id))?;
                    if !symbol.is_weak() {
                        let should_report = !matches!(
                            args.unresolved_symbols_behaviour(),
                            crate::args::UnresolvedSymbols::IgnoreAll
                                | crate::args::UnresolvedSymbols::IgnoreInSharedLibs
                        );

                        if should_report {
                            let symbol_name =
                                resources.symbol_db.symbol_name_for_display(symbol_id);

                            if args.should_error_on_unresolved_symbols() {
                                bail!("undefined reference to `{symbol_name}` from {self}");
                            }
                            crate::error::warning(&format!(
                                "undefined reference to `{symbol_name}` from {self}"
                            ));
                        }
                    }
                }
            } else if definition_symbol_id != symbol_id {
                let file_id = resources.symbol_db.file_id_for_symbol(definition_symbol_id);

                queue.send_work::<A>(
                    resources,
                    file_id,
                    WorkItem::ExportDynamic(definition_symbol_id),
                    scope,
                );
            }
        }

        Ok(())
    }

    fn finalise_sizes(&mut self, common: &mut CommonGroupState<'data, P>) -> Result {
        P::finalise_sizes_dynamic(self, common)?;

        self.object.finalise_sizes_dynamic(
            self.lib_name,
            &mut self.format_specific_state,
            &mut common.mem_sizes,
        )?;

        Ok(())
    }

    fn finalise_layout(
        mut self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter<P>,
        resources: &FinaliseLayoutResources<'_, 'data, P>,
    ) -> Result<DynamicLayout<'data, P>> {
        let format_specific_layout =
            P::finalise_layout_dynamic(&mut self, memory_offsets, resources, resolutions_out)?;

        let file_id = self.file_id();

        Ok(DynamicLayout {
            file_id,
            input: self.input,
            lib_name: self.lib_name,
            object: self.object,
            symbol_id_range: self.symbol_id_range,
            format_specific_layout,
        })
    }
}

impl<'data> LinkerScriptLayoutState<'data> {
    fn finalise_layout<P: Platform>(
        &self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter<P>,
        resources: &FinaliseLayoutResources<'_, 'data, P>,
    ) -> Result {
        self.internal_symbols
            .finalise_layout(memory_offsets, resolutions_out, resources)
    }

    fn new(input: ResolvedLinkerScript<'data>) -> Self {
        Self {
            file_id: input.file_id,
            input: input.input,
            symbol_id_range: input.symbol_id_range,
            internal_symbols: InternalSymbols {
                symbol_definitions: input.symbol_definitions,
                start_symbol_id: input.symbol_id_range.start(),
            },
        }
    }

    fn activate<P: Platform>(
        &self,
        common: &mut CommonGroupState<'data, P>,
        resources: &GraphResources<'data, '_, P>,
    ) -> Result {
        self.internal_symbols.activate_symbols(common, resources)
    }

    fn finalise_sizes<P: Platform>(
        &self,
        common: &mut CommonGroupState<'data, P>,
        per_symbol_flags: &AtomicPerSymbolFlags,
        resources: &FinaliseSizesResources<'data, '_, P>,
    ) -> Result {
        self.internal_symbols.allocate_symbol_table_sizes(
            &mut common.mem_sizes,
            resources.symbol_db,
            |symbol_id, _info| {
                per_symbol_flags
                    .flags_for_symbol(symbol_id)
                    .has_resolution()
            },
        )?;

        Ok(())
    }
}

impl<'data, P: Platform> Layout<'data, P> {
    pub(crate) fn mem_address_of_built_in(&self, section_id: OutputSectionId) -> u64 {
        self.section_layouts.get(section_id).mem_offset
    }
}

impl<'data, P: Platform> std::fmt::Debug for FileLayoutState<'data, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileLayoutState::Object(s) => f.debug_tuple("Object").field(&s.input).finish(),
            FileLayoutState::Prelude(_) => f.debug_tuple("Internal").finish(),
            FileLayoutState::Dynamic(s) => f.debug_tuple("Dynamic").field(&s.input).finish(),
            FileLayoutState::LinkerScript(s) => {
                f.debug_tuple("LinkerScript").field(&s.input).finish()
            }
            FileLayoutState::NotLoaded(_) => Display::fmt(&"<not loaded>", f),
            FileLayoutState::Epilogue(_) => Display::fmt(&"<custom sections>", f),
            FileLayoutState::SyntheticSymbols(_) => Display::fmt(&"<synthetic symbols>", f),
        }
    }
}

pub(crate) fn section_debug<P: Platform>(
    object: &P::File<'_>,
    section_index: object::SectionIndex,
) -> impl std::fmt::Display {
    let name = object
        .section(section_index)
        .and_then(|section| object.section_name(section))
        .map_or_else(
            |_| "??".to_owned(),
            |name| String::from_utf8_lossy(name).into_owned(),
        );
    std::fmt::from_fn(move |f| write!(f, "`{name}`"))
}

impl SectionLoadRequest {
    fn new(file_id: FileId, section_index: SectionIndex) -> Self {
        Self {
            file_id,
            section_index: section_index.0 as u32,
        }
    }

    fn section_index(self) -> SectionIndex {
        SectionIndex(self.section_index as usize)
    }
}

pub(crate) fn needs_tlsld(relocation_kind: RelocationKind) -> bool {
    matches!(
        relocation_kind,
        RelocationKind::TlsLd | RelocationKind::TlsLdGot | RelocationKind::TlsLdGotBase
    )
}

impl<'data, P: Platform> ObjectLayout<'data, P> {
    pub(crate) fn relocations(&self, index: SectionIndex) -> Result<P::RelocationList<'data>> {
        self.object.relocations(index, &self.relocations)
    }
}

/// Performs layout of sections and segments then makes sure that the loadable segments don't
/// overlap and that sections don't overlap.
#[test]
fn test_no_disallowed_overlaps() {
    use crate::elf::Elf;
    use crate::output_section_id::OrderEvent;

    let mut output_sections = OutputSections::<Elf>::with_base_address(0x1000);
    let (output_order, program_segments) = output_sections.output_order();
    let args = crate::args::elf::ElfArgs::default();
    let section_part_sizes = output_sections.new_part_map::<u64>().map(|_, _| 7);

    let section_part_layouts = layout_section_parts::<Elf>(
        &section_part_sizes,
        &output_sections,
        &program_segments,
        &output_order,
        &args,
    );

    let section_layouts = layout_sections(&output_sections, &section_part_layouts);

    // Make sure no alloc sections overlap
    let mut last_file_start = 0;
    let mut last_mem_start = 0;
    let mut last_file_end = 0;
    let mut last_mem_end = 0;
    let mut last_section_id = output_section_id::FILE_HEADER;

    for event in &output_order {
        let OrderEvent::Section(section_id) = event else {
            continue;
        };

        let section_flags = output_sections.section_flags(section_id);
        if !section_flags.is_alloc() {
            return;
        }

        let section = section_layouts.get(section_id);
        let mem_offset = section.mem_offset;
        let mem_end = mem_offset + section.mem_size;
        assert!(
            mem_offset >= last_mem_end,
            "Memory sections: {last_section_id} @{last_mem_start:x}..{last_mem_end:x} overlaps {section_id} @{mem_offset:x}..{mem_end:x}",
        );
        let file_offset = section.file_offset;
        let file_end = file_offset + section.file_size;
        assert!(
            file_offset >= last_file_end,
            "File sections {last_section_id} @{last_file_start:x}..{last_file_end} {section_id} @{file_offset:x}..{file_end:x}",
        );
        last_mem_start = mem_offset;
        last_file_start = file_offset;
        last_mem_end = mem_end;
        last_file_end = file_end;
        last_section_id = section_id;
    }

    let header_info = HeaderInfo {
        num_output_sections_with_content: 0,
        active_segment_ids: (0..program_segments.len())
            .map(ProgramSegmentId::new)
            .collect(),
    };

    let mut section_index = 0;
    output_sections.section_infos.for_each(|_, info| {
        if info.section_attributes.is_alloc() {
            output_sections
                .output_section_indexes
                .push(Some(section_index));
            section_index += 1;
        } else {
            output_sections.output_section_indexes.push(None);
        }
    });

    let segment_layouts = compute_segment_layout::<Elf>(
        &section_layouts,
        &output_sections,
        &output_order,
        &program_segments,
        &header_info,
        &args,
    )
    .unwrap();

    // Make sure loadable segments don't overlap in memory or in the file.
    let mut last_file = 0;
    let mut last_mem = 0;
    for seg_layout in &segment_layouts.segments {
        let seg_id = seg_layout.id;
        if program_segments.is_load_segment(seg_id) {
            continue;
        }
        assert!(
            seg_layout.sizes.mem_offset >= last_mem,
            "Overlapping memory segment: {} < {}",
            last_mem,
            seg_layout.sizes.mem_offset,
        );
        assert!(
            seg_layout.sizes.file_offset >= last_file,
            "Overlapping file segment {} < {}",
            last_file,
            seg_layout.sizes.file_offset,
        );
        last_mem = seg_layout.sizes.mem_offset + seg_layout.sizes.mem_size;
        last_file = seg_layout.sizes.file_offset + seg_layout.sizes.file_size;
    }
}

/// Verifies that we allocate and use consistent amounts of various output sections for the supplied
/// combination of flags and output kind. If this function returns an error, then we would have
/// failed during writing anyway. By failing now, we can report the particular combination of inputs
/// that caused the failure.
fn verify_consistent_allocation_handling<P: Platform>(
    flags: ValueFlags,
    output_kind: OutputKind,
) -> Result {
    let output_sections = OutputSections::with_base_address(0);
    let (output_order, _program_segments) = output_sections.output_order();
    let mut mem_sizes = output_sections.new_part_map();
    P::allocate_resolution(flags, &mut mem_sizes, output_kind);
    let mut memory_offsets = output_sections.new_part_map();
    *memory_offsets.get_mut(part_id::GOT) = 0x10;
    *memory_offsets.get_mut(part_id::PLT_GOT) = 0x10;
    let has_dynamic_symbol =
        flags.is_dynamic() || (flags.needs_export_dynamic() && flags.is_interposable());
    let dynamic_symbol_index = has_dynamic_symbol.then(|| NonZeroU32::new(1).unwrap());

    let resolution = P::create_resolution(flags, 0, dynamic_symbol_index, &mut memory_offsets);

    P::verify_resolution_allocation(
        &output_sections,
        &output_order,
        output_kind,
        &mem_sizes,
        &resolution,
    )
    .with_context(|| {
        format!(
            "Inconsistent allocation detected. \
             output_kind={output_kind:?} \
             flags={flags} \
             has_dynamic_symbol={has_dynamic_symbol:?}"
        )
    })?;

    Ok(())
}

impl<'scope, 'data, P: Platform> FinaliseLayoutResources<'scope, 'data, P> {
    fn symbol_debug<'a>(&'a self, symbol_id: SymbolId) -> SymbolDebug<'a, 'data, P> {
        self.symbol_db
            .symbol_debug(self.per_symbol_flags, symbol_id)
    }
}

impl OutputRecordLayout {
    fn merge(&mut self, other: &OutputRecordLayout) {
        debug_assert!(other.mem_offset >= self.mem_offset);
        debug_assert!(other.file_offset >= self.file_offset);
        self.mem_size += other.mem_size;
        self.file_size += other.file_size;
        if other.mem_size > 0 {
            self.alignment = self.alignment.max(other.alignment);
        }
    }
}

// This implementation is just here so that we can store a Box<dyn Drop> elsewhere in order to erase
// the type parameter P, allowing deferred dropping to occur.
impl<'data, P: Platform> Drop for Layout<'data, P> {
    fn drop(&mut self) {}
}
