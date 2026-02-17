//! Traverses the graph of symbol references to figure out what sections from the input files are
//! referenced. Determines which sections need to be linked, sums their sizes decides what goes
//! where in the output file then allocates addresses for each symbol.

use self::elf::GNU_NOTE_NAME;
use self::elf::NoteHeader;
use self::elf::Symbol;
use self::output_section_id::InfoInputs;
use crate::OutputKind;
use crate::alignment;
use crate::alignment::Alignment;
use crate::arch::Architecture;
use crate::args::Args;
use crate::args::BuildIdOption;
use crate::args::Strip;
use crate::bail;
use crate::debug_assert_bail;
use crate::diagnostics::SymbolInfoPrinter;
use crate::elf;
use crate::elf::EhFrameHdrEntry;
use crate::elf::ElfLayoutProperties;
use crate::elf::ElfObjectLayoutState;
use crate::elf::File;
use crate::elf::FileHeader;
use crate::elf::Rela;
use crate::elf::RelocationList;
use crate::elf::SectionAttributes;
use crate::elf::Versym;
use crate::elf_riscv64;
use crate::elf_writer;
use crate::ensure;
use crate::error;
use crate::error::Context;
use crate::error::Error;
use crate::error::Result;
use crate::error::warning;
use crate::file_writer;
use crate::grouping::Group;
use crate::input_data::FileId;
use crate::input_data::InputRef;
use crate::input_data::PRELUDE_FILE_ID;
use crate::layout_rules::SectionKind;
use crate::output_section_id;
use crate::output_section_id::FILE_HEADER;
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
use crate::platform::ObjectFile as _;
use crate::platform::Platform;
use crate::platform::RelaxSymbolInfo;
use crate::platform::Relaxation as _;
use crate::platform::Relocation;
use crate::platform::RelocationSequence;
use crate::platform::SectionFlags as _;
use crate::platform::SectionHeader as _;
use crate::platform::Symbol as _;
use crate::program_segments::ProgramSegmentId;
use crate::program_segments::ProgramSegments;
use crate::resolution;
use crate::resolution::FrameIndex;
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
use crate::symbol_db::RawSymbolName;
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
use crate::version_script::VersionScript;
use crossbeam_queue::ArrayQueue;
use crossbeam_queue::SegQueue;
use foldhash::HashSet;
use hashbrown::HashMap;
use itertools::Itertools;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::pt;
use linker_utils::elf::secnames;
use linker_utils::elf::shf;
use linker_utils::elf::sht;
use linker_utils::elf::sht::NOTE;
use linker_utils::elf::sht::RISCV_ATTRIBUTES;
use linker_utils::relaxation::RelaxDeltaMap;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::relaxation::SectionRelaxDeltas;
use linker_utils::relaxation::opt_input_to_output;
use object::LittleEndian;
use object::SectionIndex;
use object::elf::gnu_hash;
use object::read::elf::Crel;
use object::read::elf::Dyn as _;
use object::read::elf::RelocationSections;
use object::read::elf::VerdefIterator;
use rayon::Scope;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSliceMut;
use smallvec::SmallVec;
use std::ffi::CString;
use std::fmt::Display;
use std::mem::replace;
use std::mem::size_of;
use std::mem::swap;
use std::mem::take;
use std::num::NonZeroU32;
use std::num::NonZeroU64;
use std::sync::Mutex;
use std::sync::atomic;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use zerocopy::FromBytes;

pub fn compute<'data, P: Platform<'data>>(
    symbol_db: SymbolDb<'data>,
    mut per_symbol_flags: PerSymbolFlags,
    mut groups: Vec<ResolvedGroup<'data>>,
    mut output_sections: OutputSections<'data>,
    output: &mut file_writer::Output,
) -> Result<Layout<'data>> {
    timing_phase!("Layout");

    let sonames = Sonames::new(&symbol_db.groups);

    let atomic_per_symbol_flags = per_symbol_flags.borrow_atomic();

    let symbol_info_printer = symbol_db.args.sym_info.as_ref().map(|sym_name| {
        SymbolInfoPrinter::new(&symbol_db, sym_name, &atomic_per_symbol_flags, &groups)
    });

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
            find_required_sections::<P>(
                groups,
                &symbol_db,
                &atomic_per_symbol_flags,
                &output_sections,
                sonames,
            )
        },
    );
    let merged_strings = merged_strings?;
    let gc_outputs = gc_outputs?;

    let mut group_states = gc_outputs.group_states;

    let epilogue_file_id = FileId::new(group_states.len() as u32, 0);

    group_states.push(GroupState {
        files: vec![FileLayoutState::Epilogue(EpilogueLayoutState::new(
            symbol_db.args,
        ))],
        queue: LocalWorkQueue::new(epilogue_file_id.group()),
        common: CommonGroupState::new(&output_sections),
        num_symbols: 0,
    });

    finalise_copy_relocations(&mut group_states, &symbol_db, &atomic_per_symbol_flags)?;
    let (dynamic_symbol_definitions, gnu_hash_layout) =
        merge_dynamic_symbol_definitions(&group_states, &symbol_db)?;
    let properties_and_attributes = ElfLayoutProperties::new::<P>(
        objects_iter(&group_states).map(|obj| obj.object),
        objects_iter(&group_states).map(|obj| &obj.format_specific_layout_state),
        symbol_db.args,
    )?;

    let finalise_sizes_resources = FinaliseSizesResources {
        dynamic_symbol_definitions: &dynamic_symbol_definitions,
        symbol_db: &symbol_db,
        merged_strings: &merged_strings,
        gnu_hash_layout,
        properties_and_attributes: &properties_and_attributes,
    };

    finalise_all_sizes(
        &mut group_states,
        &output_sections,
        &atomic_per_symbol_flags,
        &finalise_sizes_resources,
    )?;

    // Dropping `symbol_info_printer` will cause it to print. So we'll either print now, or, if we
    // got an error, then we'll have printed at that point.
    drop(symbol_info_printer);

    let non_addressable_counts = apply_non_addressable_indexes(&mut group_states, &symbol_db)?;

    propagate_section_attributes(&group_states, &mut output_sections);

    let (output_order, program_segments) = output_sections.output_order();

    tracing::trace!(
        "Output order:\n{}",
        output_order.display(&output_sections, &program_segments)
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

    let mut section_part_layouts = layout_section_parts(
        &section_part_sizes,
        &output_sections,
        &program_segments,
        &output_order,
        symbol_db.args,
    );

    if symbol_db.args.relax && matches!(symbol_db.args.arch, Architecture::RISCV64) {
        perform_iterative_relaxation(
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
    let segment_layouts = compute_segment_layout(
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
        properties_and_attributes: &properties_and_attributes,
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

struct FinaliseSizesResources<'data, 'scope> {
    dynamic_symbol_definitions: &'scope [DynamicSymbolDefinition<'data>],
    symbol_db: &'scope SymbolDb<'data>,
    merged_strings: &'scope OutputSectionMap<MergedStringsSection<'data>>,
    gnu_hash_layout: Option<GnuHashLayout>,
    properties_and_attributes: &'scope ElfLayoutProperties,
}

/// Update resolutions for defsym symbols that reference other symbols.
fn update_defsym_symbol_resolutions(
    symbol_db: &SymbolDb,
    resolutions: &mut [Option<Resolution>],
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

fn update_defsym_symbol_resolution(
    symbol_id: SymbolId,
    def_info: &InternalSymDefInfo,
    symbol_db: &SymbolDb,
    resolutions: &mut [Option<Resolution>],
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
fn update_dynamic_symbol_resolutions(
    resources: &FinaliseLayoutResources,
    layouts: &[GroupLayout],
    resolutions: &mut [Option<Resolution>],
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

/// Where we've decided that we need copy relocations, look for symbols with the same address as the
/// symbols with copy relocations. If the other symbol is non-weak, then we do the copy relocation
/// for that symbol instead. We also request dynamic symbol definitions for each copy relocation.
/// For that reason, this needs to be done before we merge dynamic symbol definitions.
fn finalise_copy_relocations<'data>(
    group_states: &mut [GroupState<'data>],
    symbol_db: &SymbolDb<'data>,
    symbol_flags: &AtomicPerSymbolFlags,
) -> Result {
    timing_phase!("Finalise copy relocations");

    group_states.par_iter_mut().try_for_each(|group| {
        verbose_timing_phase!("Finalise copy relocations for group");
        for file in &mut group.files {
            if let FileLayoutState::Dynamic(dynamic) = file {
                dynamic.finalise_copy_relocations(&mut group.common, symbol_db, symbol_flags)?;
            }
        }

        Ok(())
    })
}

fn finalise_all_sizes<'data>(
    group_states: &mut [GroupState<'data>],
    output_sections: &OutputSections,
    per_symbol_flags: &AtomicPerSymbolFlags,
    resources: &FinaliseSizesResources<'data, '_>,
) -> Result {
    timing_phase!("Finalise per-object sizes");

    group_states.par_iter_mut().try_for_each(|state| {
        verbose_timing_phase!("Finalise sizes for group");
        state.finalise_sizes(output_sections, per_symbol_flags, resources)
    })
}

fn merge_dynamic_symbol_definitions<'data>(
    group_states: &[GroupState<'data>],
    symbol_db: &SymbolDb<'data>,
) -> Result<(Vec<DynamicSymbolDefinition<'data>>, Option<GnuHashLayout>)> {
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

    let mut opt_gnu_hash_layout = None;

    // If we're going to emit .gnu.hash, then we need to stort the dynamic symbols by bucket.
    // Tie-break by name for determinism. We can use an unstable sort because names should be
    // unique. We use a parallel sort because we're processing symbols from potentially many input
    // objects, so there can be a lot.
    if symbol_db.args.hash_style.includes_gnu() {
        // Our number of buckets is computed somewhat arbitrarily so that we have on average 2
        // symbols per bucket, but then we round up to a power of two.
        let num_defs = dynamic_symbol_definitions.len();
        let gnu_hash_layout = GnuHashLayout {
            bucket_count: (num_defs / 2).next_power_of_two() as u32,
            bloom_shift: 6,
            bloom_count: 1,
            // `symbol_base` is set later in `finalise_layout`.
            symbol_base: 0,
        };

        dynamic_symbol_definitions
            .par_sort_unstable_by_key(|d| (gnu_hash_layout.bucket_for_hash(d.hash), d.name));

        opt_gnu_hash_layout = Some(gnu_hash_layout);
    }

    Ok((dynamic_symbol_definitions, opt_gnu_hash_layout))
}

fn append_prelude_defsym_dynamic_symbols<'data>(
    group_states: &[GroupState<'data>],
    symbol_db: &SymbolDb<'data>,
    dynamic_symbol_definitions: &mut Vec<DynamicSymbolDefinition<'data>>,
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

            let symbol_name = symbol_db.symbol_name(symbol_id)?;
            let RawSymbolName {
                name,
                version_name,
                is_default,
            } = RawSymbolName::parse(symbol_name.bytes());

            let mut version = object::elf::VER_NDX_GLOBAL;
            if symbol_db.version_script.version_count() > 0
                && let Some(v) = symbol_db
                    .version_script
                    .version_for_symbol(&UnversionedSymbolName::prehashed(name), version_name)?
            {
                version = v;
                if !is_default {
                    version |= object::elf::VERSYM_HIDDEN;
                }
            }
            dynamic_symbol_definitions.push(DynamicSymbolDefinition::new(symbol_id, name, version));
        }
    }

    Ok(())
}

fn objects_iter<'groups, 'data>(
    group_states: &'groups [GroupState<'data>],
) -> impl Iterator<Item = &'groups ObjectLayoutState<'data>> + Clone {
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
pub struct Layout<'data> {
    pub(crate) symbol_db: SymbolDb<'data>,
    pub(crate) symbol_resolutions: SymbolResolutions,
    pub(crate) section_part_layouts: OutputSectionPartMap<OutputRecordLayout>,

    pub(crate) section_layouts: OutputSectionMap<OutputRecordLayout>,

    /// This is like `section_layouts`, but where secondary sections are merged into their primary
    /// section. Values for secondary sections are reset to 0 and should not be used.
    pub(crate) merged_section_layouts: OutputSectionMap<OutputRecordLayout>,

    pub(crate) group_layouts: Vec<GroupLayout<'data>>,
    pub(crate) segment_layouts: SegmentLayouts,
    pub(crate) output_sections: OutputSections<'data>,
    pub(crate) program_segments: ProgramSegments,
    pub(crate) output_order: OutputOrder,
    pub(crate) non_addressable_counts: NonAddressableCounts,
    pub(crate) merged_strings: OutputSectionMap<MergedStringsSection<'data>>,
    pub(crate) merged_string_start_addresses: MergedStringStartAddresses,
    pub(crate) relocation_statistics: OutputSectionMap<AtomicU64>,
    pub(crate) has_static_tls: bool,
    pub(crate) has_variant_pcs: bool,
    pub(crate) per_symbol_flags: PerSymbolFlags,
    pub(crate) dynamic_symbol_definitions: Vec<DynamicSymbolDefinition<'data>>,
    pub(crate) properties_and_attributes: ElfLayoutProperties,
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
pub(crate) struct SymbolResolutions {
    resolutions: Vec<Option<Resolution>>,
}

pub(crate) enum FileLayout<'data> {
    Prelude(PreludeLayout<'data>),
    Object(ObjectLayout<'data>),
    Dynamic(DynamicLayout<'data>),
    SyntheticSymbols(SyntheticSymbolsLayout<'data>),
    Epilogue(EpilogueLayout),
    NotLoaded,
    LinkerScript(LinkerScriptLayoutState<'data>),
}

/// Address information for a symbol.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct Resolution {
    /// An address or absolute value.
    pub(crate) raw_value: u64,

    pub(crate) dynamic_symbol_index: Option<NonZeroU32>,

    /// The base GOT address for this resolution. For pointers to symbols the GOT entry will
    /// contain a single pointer. For TLS variables there can be up to 3 pointers. If
    /// ValueFlags::GOT_TLS_OFFSET is set, then that will be the first value. If
    /// ValueFlags::GOT_TLS_MODULE is set, then there will be a pair of values (module and
    /// offset within module).
    pub(crate) got_address: Option<NonZeroU64>,
    pub(crate) plt_address: Option<NonZeroU64>,
    pub(crate) flags: ValueFlags,
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
    pub(crate) fn full_resolution(self) -> Option<Resolution> {
        let address = self.address()?;
        Some(Resolution {
            raw_value: address,
            dynamic_symbol_index: None,
            got_address: None,
            plt_address: None,
            flags: ValueFlags::empty(),
        })
    }
}

enum FileLayoutState<'data> {
    Prelude(PreludeLayoutState<'data>),
    Object(ObjectLayoutState<'data>),
    Dynamic(DynamicLayoutState<'data>),
    NotLoaded(NotLoaded),
    SyntheticSymbols(SyntheticSymbolsLayoutState<'data>),
    Epilogue(EpilogueLayoutState),
    LinkerScript(LinkerScriptLayoutState<'data>),
}

/// Data that doesn't come from any input files, but needs to be written by the linker.
struct PreludeLayoutState<'data> {
    file_id: FileId,
    symbol_id_range: SymbolIdRange,
    internal_symbols: InternalSymbols<'data>,
    entry_symbol_id: Option<SymbolId>,
    needs_tlsld_got_entry: bool,
    identity: String,
    header_info: Option<HeaderInfo>,
    dynamic_linker: Option<CString>,
    shstrtab_size: u64,
}

pub(crate) struct SyntheticSymbolsLayoutState<'data> {
    file_id: FileId,
    symbol_id_range: SymbolIdRange,
    internal_symbols: InternalSymbols<'data>,
}

pub(crate) struct EpilogueLayoutState {
    sysv_hash_layout: Option<SysvHashLayout>,
    gnu_hash_layout: Option<GnuHashLayout>,
    build_id_size: Option<usize>,

    verdefs: Option<Vec<VersionDef>>,
}

pub(crate) struct LinkerScriptLayoutState<'data> {
    file_id: FileId,
    input: InputRef<'data>,
    symbol_id_range: SymbolIdRange,
    pub(crate) internal_symbols: InternalSymbols<'data>,
}

#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct GnuHashLayout {
    pub(crate) bucket_count: u32,
    pub(crate) bloom_shift: u32,
    pub(crate) bloom_count: u32,
    pub(crate) symbol_base: u32,
}

#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct SysvHashLayout {
    pub(crate) bucket_count: u32,
    pub(crate) chain_count: u32,
}

#[derive(Debug)]
pub(crate) struct SyntheticSymbolsLayout<'data> {
    pub(crate) internal_symbols: InternalSymbols<'data>,
}

#[derive(Debug)]
pub(crate) struct EpilogueLayout {
    pub(crate) sysv_hash_layout: Option<SysvHashLayout>,
    pub(crate) gnu_hash_layout: Option<GnuHashLayout>,
    pub(crate) dynsym_start_index: u32,
    pub(crate) verdefs: Option<Vec<VersionDef>>,
    pub(crate) riscv_attributes_length: u32,
}

#[derive(Debug)]
pub(crate) struct ObjectLayout<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) file_id: FileId,
    pub(crate) object: &'data File<'data>,
    pub(crate) sections: Vec<SectionSlot>,
    pub(crate) relocations: RelocationSections,
    pub(crate) section_resolutions: Vec<SectionResolution>,
    pub(crate) symbol_id_range: SymbolIdRange,
    /// SFrame section ranges for this object, relative to the start of the .sframe output section.
    pub(crate) sframe_ranges: Vec<std::ops::Range<usize>>,
    /// Sparse map from section index to relaxation delta details.
    pub(crate) section_relax_deltas: RelaxDeltaMap,
}

#[derive(Debug)]
pub(crate) struct PreludeLayout<'data> {
    pub(crate) entry_symbol_id: Option<SymbolId>,
    pub(crate) tlsld_got_entry: Option<NonZeroU64>,
    pub(crate) identity: String,
    pub(crate) header_info: HeaderInfo,
    pub(crate) internal_symbols: InternalSymbols<'data>,
    pub(crate) dynamic_linker: Option<CString>,
}

#[derive(Debug)]
pub(crate) struct InternalSymbols<'data> {
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo<'data>>,
    pub(crate) start_symbol_id: SymbolId,
}

pub(crate) struct DynamicLayout<'data> {
    pub(crate) file_id: FileId,
    input: InputRef<'data>,

    /// The name we'll put into the binary to tell the dynamic loader what to load.
    pub(crate) lib_name: &'data [u8],

    pub(crate) symbol_id_range: SymbolIdRange,

    pub(crate) object: &'data crate::elf::File<'data>,

    /// Mapping from local symbol indexes to versions in the input file.
    pub(crate) input_symbol_versions: &'data [Versym],

    /// Mapping from input versions to output versions. Input version 1 is at index 0.
    pub(crate) version_mapping: Vec<u16>,

    pub(crate) verneed_info: Option<VerneedInfo<'data>>,

    /// Whether this is the last DynamicLayout that puts content into .gnu.version_r.
    pub(crate) is_last_verneed: bool,

    pub(crate) copy_relocation_symbols: Vec<SymbolId>,
}

trait HandlerData {
    fn symbol_id_range(&self) -> SymbolIdRange;

    fn file_id(&self) -> FileId;
}

trait SymbolRequestHandler<'data>: std::fmt::Display + HandlerData {
    fn finalise_symbol_sizes(
        &mut self,
        common: &mut CommonGroupState,
        symbol_flags: &AtomicPerSymbolFlags,
        resources: &FinaliseSizesResources,
    ) -> Result {
        let symbol_db = resources.symbol_db;

        let _file_span = symbol_db.args.trace_span_for_file(self.file_id());
        let symbol_id_range = self.symbol_id_range();

        for (local_index, atomic_flags) in symbol_flags.range(symbol_id_range).iter().enumerate() {
            let symbol_id = symbol_id_range.offset_to_id(local_index);
            if !symbol_db.is_canonical(symbol_id) {
                continue;
            }
            let flags = atomic_flags.get();

            // It might be tempting to think that this code should only be run for dynamic objects,
            // however regular objects can own dynamic symbols too if the symbol is an undefined
            // weak symbol.
            if flags.is_dynamic() && flags.has_resolution() {
                let name = symbol_db.symbol_name(symbol_id)?;
                let name = RawSymbolName::parse(name.bytes()).name;

                if flags.needs_copy_relocation() {
                    // The dynamic symbol is a definition, so is handled by the epilogue. We only
                    // need to deal with the symtab entry here.
                    let entry_size = size_of::<elf::SymtabEntry>() as u64;
                    common.allocate(part_id::SYMTAB_GLOBAL, entry_size);
                    common.allocate(part_id::STRTAB, name.len() as u64 + 1);
                } else {
                    common.allocate(part_id::DYNSTR, name.len() as u64 + 1);
                    common.allocate(part_id::DYNSYM, crate::elf::SYMTAB_ENTRY_SIZE);
                }
            }

            if symbol_db.args.verify_allocation_consistency {
                verify_consistent_allocation_handling(flags, symbol_db.output_kind)?;
            }

            allocate_symbol_resolution(flags, &mut common.mem_sizes, symbol_db.output_kind);

            if symbol_db.args.got_plt_syms && flags.needs_got() {
                let name = symbol_db.symbol_name(symbol_id)?;
                let name = RawSymbolName::parse(name.bytes()).name;
                let name_len = name.len() + 4; // "$got" or "$plt" suffix

                let entry_size = size_of::<elf::SymtabEntry>() as u64;
                common.allocate(part_id::SYMTAB_LOCAL, entry_size);
                common.allocate(part_id::STRTAB, name_len as u64 + 1);

                if flags.needs_plt() {
                    common.allocate(part_id::SYMTAB_LOCAL, entry_size);
                    common.allocate(part_id::STRTAB, name_len as u64 + 1);
                }
            }
        }

        Ok(())
    }

    fn load_symbol<'scope, P: Platform<'data>>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_id: SymbolId,
        resources: &'scope GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result;
}

fn export_dynamic<'data>(
    common: &mut CommonGroupState<'data>,
    symbol_id: SymbolId,
    symbol_db: &SymbolDb<'data>,
) -> Result {
    let name = symbol_db.symbol_name(symbol_id)?;
    let RawSymbolName {
        name,
        version_name,
        is_default,
    } = RawSymbolName::parse(name.bytes());

    let mut version = object::elf::VER_NDX_GLOBAL;
    if symbol_db.version_script.version_count() > 0 {
        // TODO: We already hashed this symbol at some point previously. See if we can avoid
        // rehashing it here and if that actually saves us time.
        if let Some(v) = symbol_db
            .version_script
            .version_for_symbol(&UnversionedSymbolName::prehashed(name), version_name)?
        {
            version = v;
            if !is_default {
                version |= object::elf::VERSYM_HIDDEN;
            }
        }
    }

    common
        .dynamic_symbol_definitions
        .push(DynamicSymbolDefinition::new(symbol_id, name, version));

    Ok(())
}

fn allocate_symbol_resolution(
    flags: ValueFlags,
    mem_sizes: &mut OutputSectionPartMap<u64>,
    output_kind: OutputKind,
) {
    allocate_resolution(flags, mem_sizes, output_kind);
}

/// Computes how much to allocate for a particular resolution. This is intended for debug assertions
/// when we're writing, to make sure that we would have allocated memory before we write.
pub(crate) fn compute_allocations(
    resolution: &Resolution,
    output_kind: OutputKind,
) -> OutputSectionPartMap<u64> {
    let mut sizes = OutputSectionPartMap::with_size(NUM_SINGLE_PART_SECTIONS as usize);
    allocate_resolution(resolution.flags, &mut sizes, output_kind);
    sizes
}

fn allocate_resolution(
    flags: ValueFlags,
    mem_sizes: &mut OutputSectionPartMap<u64>,
    output_kind: OutputKind,
) {
    let has_dynamic_symbol = flags.is_dynamic() || flags.needs_export_dynamic();

    if flags.needs_got() && !flags.is_tls() {
        mem_sizes.increment(part_id::GOT, elf::GOT_ENTRY_SIZE);
        if flags.needs_plt() {
            mem_sizes.increment(part_id::PLT_GOT, elf::PLT_ENTRY_SIZE);
        }
        if flags.is_ifunc() {
            mem_sizes.increment(part_id::RELA_PLT, elf::RELA_ENTRY_SIZE);
        } else if flags.is_interposable() && has_dynamic_symbol {
            mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
        } else if flags.is_address() && output_kind.is_relocatable() {
            mem_sizes.increment(part_id::RELA_DYN_RELATIVE, elf::RELA_ENTRY_SIZE);
        }
    }

    if flags.needs_ifunc_got_for_address() {
        mem_sizes.increment(part_id::GOT, elf::GOT_ENTRY_SIZE);
        if output_kind.is_relocatable() {
            mem_sizes.increment(part_id::RELA_DYN_RELATIVE, elf::RELA_ENTRY_SIZE);
        }
    }

    if flags.needs_got_tls_offset() {
        mem_sizes.increment(part_id::GOT, elf::GOT_ENTRY_SIZE);
        if flags.is_interposable() || output_kind.is_shared_object() {
            mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
        }
    }

    if flags.needs_got_tls_module() {
        mem_sizes.increment(part_id::GOT, elf::GOT_ENTRY_SIZE * 2);
        // For executables, the TLS module ID is known at link time. For shared objects, we
        // need a runtime relocation to fill it in.
        if !output_kind.is_executable() || flags.is_dynamic() {
            mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
        }
        if flags.is_interposable() && has_dynamic_symbol {
            mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
        }
    }

    if flags.needs_got_tls_descriptor() {
        mem_sizes.increment(part_id::GOT, elf::GOT_ENTRY_SIZE * 2);
        mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
    }
}

impl HandlerData for ObjectLayoutState<'_> {
    fn file_id(&self) -> FileId {
        self.file_id
    }

    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }
}

impl<'data> SymbolRequestHandler<'data> for ObjectLayoutState<'data> {
    fn load_symbol<'scope, P: Platform<'data>>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope>,
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

impl HandlerData for DynamicLayoutState<'_> {
    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }

    fn file_id(&self) -> FileId {
        self.file_id
    }
}

impl<'data> SymbolRequestHandler<'data> for DynamicLayoutState<'data> {
    fn load_symbol<'scope, P: Platform<'data>>(
        &mut self,
        _common: &mut CommonGroupState,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope>,
        _queue: &mut LocalWorkQueue,
        _scope: &Scope<'scope>,
    ) -> Result {
        let local_index = symbol_id.to_offset(self.symbol_id_range());
        if let Some(&version_index) = self.symbol_versions.get(local_index) {
            let version_index = version_index.0.get(LittleEndian) & object::elf::VERSYM_VERSION;
            // Versions 0 and 1 are local and global. We care about the versions after that.
            if version_index > object::elf::VER_NDX_GLOBAL {
                *self
                    .symbol_versions_needed
                    .get_mut(version_index as usize - 1)
                    .with_context(|| format!("Invalid symbol version index {version_index}"))? =
                    true;
            }
        }

        // Check for VARIANT_PCS flag in AArch64 symbols
        if P::KIND == crate::arch::Architecture::AArch64
            && let Ok(sym) = self.object.symbols.symbol(object::SymbolIndex(local_index))
            && (sym.st_other & object::elf::STO_AARCH64_VARIANT_PCS) != 0
        {
            resources
                .has_variant_pcs
                .store(true, atomic::Ordering::Relaxed);
        }

        // Check for VARIANT_CC flag in RISC-V symbols
        if P::KIND == crate::arch::Architecture::RISCV64
            && let Ok(sym) = self.object.symbols.symbol(object::SymbolIndex(local_index))
            && (sym.st_other & object::elf::STO_RISCV_VARIANT_CC) != 0
        {
            resources
                .has_variant_pcs
                .store(true, atomic::Ordering::Relaxed);
        }

        Ok(())
    }
}

impl HandlerData for PreludeLayoutState<'_> {
    fn file_id(&self) -> FileId {
        self.file_id
    }

    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }
}

impl<'data> SymbolRequestHandler<'data> for PreludeLayoutState<'data> {
    fn load_symbol<'scope, P: Platform<'data>>(
        &mut self,
        _common: &mut CommonGroupState,
        _symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope>,
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

impl<'data> SymbolRequestHandler<'data> for LinkerScriptLayoutState<'data> {
    fn load_symbol<'scope, P: Platform<'data>>(
        &mut self,
        _common: &mut CommonGroupState<'data>,
        _symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope>,
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

impl<'data> SymbolRequestHandler<'data> for SyntheticSymbolsLayoutState<'data> {
    fn load_symbol<'scope, P: Platform<'data>>(
        &mut self,
        _common: &mut CommonGroupState,
        symbol_id: SymbolId,
        resources: &'scope GraphResources<'data, 'scope>,
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
                resources.send_work::<P>(
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
struct CommonGroupState<'data> {
    mem_sizes: OutputSectionPartMap<u64>,

    section_attributes: OutputSectionMap<Option<SectionAttributes>>,

    /// Dynamic symbols that need to be defined. Because of the ordering requirements for symbol
    /// hashes, these get defined by the epilogue. The object on which a particular dynamic symbol
    /// is stored is non-deterministic and is whichever object first requested export of that
    /// symbol. That's OK though because the epilogue will sort all dynamic symbols.
    dynamic_symbol_definitions: Vec<DynamicSymbolDefinition<'data>>,

    exception_frame_relocations: usize,
    exception_frame_count: usize,
}

impl CommonGroupState<'_> {
    fn new(output_sections: &OutputSections) -> Self {
        Self {
            mem_sizes: output_sections.new_part_map(),
            section_attributes: output_sections.new_section_map(),
            dynamic_symbol_definitions: Default::default(),
            exception_frame_count: 0,
            exception_frame_relocations: 0,
        }
    }

    fn validate_sizes(&self) -> Result {
        if *self.mem_sizes.get(part_id::GNU_VERSION) > 0 {
            let num_dynamic_symbols =
                self.mem_sizes.get(part_id::DYNSYM) / crate::elf::SYMTAB_ENTRY_SIZE;
            let num_versym = self.mem_sizes.get(part_id::GNU_VERSION) / size_of::<Versym>() as u64;
            if num_versym != num_dynamic_symbols {
                bail!(
                    "Object has {num_dynamic_symbols} dynamic symbols, but \
                         has {num_versym} versym entries"
                );
            }
        }

        Ok(())
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

    fn allocate(&mut self, part_id: PartId, size: u64) {
        self.mem_sizes.increment(part_id, size);
    }

    /// Allocate resources and update attributes based on a section having been loaded.
    fn section_loaded(
        &mut self,
        part_id: PartId,
        header: &object::elf::SectionHeader64<LittleEndian>,
        section: Section,
    ) {
        self.allocate(part_id, section.capacity());
        self.store_section_attributes(part_id, header);
    }

    fn store_section_attributes(
        &mut self,
        part_id: PartId,
        header: &object::elf::SectionHeader64<LittleEndian>,
    ) {
        let existing_attributes = self.section_attributes.get_mut(part_id.output_section_id());

        let new_attributes = header.attributes();

        if let Some(existing) = existing_attributes {
            existing.merge(new_attributes);
        } else {
            *existing_attributes = Some(new_attributes);
        }
    }
}

struct ObjectLayoutState<'data> {
    input: InputRef<'data>,
    file_id: FileId,
    symbol_id_range: SymbolIdRange,
    object: &'data File<'data>,

    /// Info about each of our sections. Indexed the same as the sections in the input object.
    sections: Vec<SectionSlot>,

    /// Mapping from sections to their corresponding relocation section.
    relocations: object::read::elf::RelocationSections,

    cies: SmallVec<[CieAtOffset<'data>; 2]>,

    eh_frame_section: Option<&'data object::elf::SectionHeader64<LittleEndian>>,
    eh_frame_size: u64,

    format_specific_layout_state: ElfObjectLayoutState,

    /// Indexed by `FrameIndex`.
    exception_frames: ExceptionFrames<'data>,

    /// Sparse map from section index to relaxation delta details, built during `finalise_sizes`
    /// and later transferred to `ObjectLayout`.
    section_relax_deltas: RelaxDeltaMap,
}

enum ExceptionFrames<'data> {
    Rela(Vec<ExceptionFrame<'data, Rela>>),
    Crel(Vec<ExceptionFrame<'data, Crel>>),
}

#[derive(Default)]
struct ExceptionFrame<'data, R: Relocation> {
    /// The relocations that need to be processed if we load this frame.
    relocations: R::Sequence<'data>,

    /// Number of bytes required to store this frame.
    frame_size: u32,

    /// The index of the previous frame that is for the same section.
    previous_frame_for_section: Option<FrameIndex>,
}

#[derive(Debug, Default)]
struct LocalWorkQueue {
    /// The index of the worker that owns this queue.
    index: usize,

    /// Work that needs to be processed by the worker that owns this queue.
    local_work: Vec<WorkItem>,
}

struct DynamicLayoutState<'data> {
    object: &'data File<'data>,
    input: InputRef<'data>,
    file_id: FileId,
    symbol_id_range: SymbolIdRange,
    lib_name: &'data [u8],

    /// Which symbol versions are needed. A symbol version is needed if a symbol with that version
    /// has been loaded. The first version has index 1, so we store it at offset 0.
    symbol_versions_needed: Vec<bool>,

    /// The contents of the .gnu.version section. Maps from symbol index to symbol version index.
    symbol_versions: &'data [Versym],

    verneed_info: Option<VerneedInfo<'data>>,

    non_addressable_indexes: NonAddressableIndexes,

    /// Maps from addresses within the shared object to copy relocations at that address.
    copy_relocations: HashMap<u64, CopyRelocationInfo>,
}

struct CopyRelocationInfo {
    /// The symbol ID for which we'll actually generate the copy relocation. Initially, this is
    /// just the first symbol at a particular address for which we requested a copy relocation,
    /// then later we may update it to point to a different symbol if that first symbol was
    /// weak.
    symbol_id: SymbolId,

    is_weak: bool,
}

pub(crate) struct VerneedInfo<'data> {
    pub(crate) defs: VerdefIterator<'data, FileHeader>,
    pub(crate) string_table_index: object::SectionIndex,

    /// Number of symbol versions that we're going to emit. This is the number of entries in
    /// `symbol_versions_needed` that are true. Computed after graph traversal.
    pub(crate) version_count: u16,
}

#[derive(derive_more::Debug, Clone, Copy)]
pub(crate) struct DynamicSymbolDefinition<'data> {
    pub(crate) symbol_id: SymbolId,
    #[debug("{:?}", String::from_utf8_lossy(name))]
    pub(crate) name: &'data [u8],
    pub(crate) hash: u32,
    pub(crate) version: u16,
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
pub(crate) struct GroupLayout<'data> {
    pub(crate) files: Vec<FileLayout<'data>>,

    /// The offset in .dynstr at which we'll start writing.
    pub(crate) dynstr_start_offset: u32,

    /// The offset in .strtab at which we'll start writing.
    pub(crate) strtab_start_offset: u32,

    pub(crate) eh_frame_start_address: u64,

    pub(crate) mem_sizes: OutputSectionPartMap<u64>,
    pub(crate) file_sizes: OutputSectionPartMap<usize>,
}

#[derive(Debug)]
struct GroupState<'data> {
    queue: LocalWorkQueue,
    files: Vec<FileLayoutState<'data>>,
    common: CommonGroupState<'data>,
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

struct GraphResources<'data, 'scope> {
    symbol_db: &'scope SymbolDb<'data>,

    output_sections: &'scope OutputSections<'data>,

    worker_slots: Vec<Mutex<WorkerSlot<'data>>>,

    errors: Mutex<Vec<Error>>,

    per_symbol_flags: &'scope AtomicPerSymbolFlags<'scope>,

    /// Sections that we'll keep, even if their total size is zero.
    must_keep_sections: OutputSectionMap<AtomicBool>,

    has_static_tls: AtomicBool,

    has_variant_pcs: AtomicBool,

    uses_tlsld: AtomicBool,

    /// For each OutputSectionId, this tracks a list of sections that should be loaded if that
    /// section gets referenced. The sections here will only be those that are eligible for having
    /// __start_ / __stop_ symbols. i.e. sections that don't start their names with a ".".
    start_stop_sections: OutputSectionMap<SegQueue<SectionLoadRequest>>,

    /// The number of groups that haven't yet completed activation.
    activations_remaining: AtomicUsize,

    /// Groups that cannot be processed until all groups have completed activation.
    delay_processing: ArrayQueue<GroupState<'data>>,

    sonames: Sonames<'data>,
}

struct FinaliseLayoutResources<'scope, 'data> {
    symbol_db: &'scope SymbolDb<'data>,
    per_symbol_flags: &'scope PerSymbolFlags,
    output_sections: &'scope OutputSections<'data>,
    output_order: &'scope OutputOrder,
    section_layouts: &'scope OutputSectionMap<OutputRecordLayout>,
    merged_string_start_addresses: &'scope MergedStringStartAddresses,
    merged_strings: &'scope OutputSectionMap<MergedStringsSection<'data>>,
    dynamic_symbol_definitions: &'scope Vec<DynamicSymbolDefinition<'data>>,
    segment_layouts: &'scope SegmentLayouts,
    program_segments: &'scope ProgramSegments,
    properties_and_attributes: &'scope ElfLayoutProperties,
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
    fn file_id(self, symbol_db: &SymbolDb) -> FileId {
        match self {
            WorkItem::LoadGlobalSymbol(s) | WorkItem::CopyRelocateSymbol(s) => {
                symbol_db.file_id_for_symbol(s)
            }
            WorkItem::LoadSection(s) => s.file_id,
            WorkItem::ExportDynamic(symbol_id) => symbol_db.file_id_for_symbol(symbol_id),
        }
    }
}

impl<'data> Layout<'data> {
    pub(crate) fn prelude(&self) -> &PreludeLayout<'data> {
        let Some(FileLayout::Prelude(i)) = self.group_layouts.first().and_then(|g| g.files.first())
        else {
            panic!("Prelude layout not found at expected offset");
        };
        i
    }

    pub(crate) fn args(&self) -> &'data Args {
        self.symbol_db.args
    }

    pub(crate) fn symbol_debug(&self, symbol_id: SymbolId) -> SymbolDebug<'_> {
        self.symbol_db
            .symbol_debug(&self.per_symbol_flags, symbol_id)
    }

    #[inline(always)]
    pub(crate) fn merged_symbol_resolution(&self, symbol_id: SymbolId) -> Option<Resolution> {
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

    pub(crate) fn local_symbol_resolution(&self, symbol_id: SymbolId) -> Option<&Resolution> {
        self.symbol_resolutions.resolutions[symbol_id.as_usize()].as_ref()
    }

    pub(crate) fn resolutions_in_range(
        &self,
        range: SymbolIdRange,
    ) -> impl Iterator<Item = (SymbolId, Option<&Resolution>)> {
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
                                    && section.flags().is_alloc()
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

    pub(crate) fn file_layout(&self, file_id: FileId) -> &FileLayout<'data> {
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

    pub(crate) fn info_inputs(&self) -> InfoInputs<'_> {
        InfoInputs {
            section_part_layouts: &self.section_part_layouts,
            non_addressable_counts: &self.non_addressable_counts,
            output_section_indexes: &self.output_sections.output_section_indexes,
        }
    }
}

fn layout_sections(
    output_sections: &OutputSections,
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

fn merge_secondary_parts(
    output_sections: &OutputSections,
    section_layouts: &mut OutputSectionMap<OutputRecordLayout>,
) {
    for (id, info) in output_sections.ids_with_info() {
        if let SectionKind::Secondary(primary_id) = info.kind {
            let secondary_layout = take(section_layouts.get_mut(id));
            section_layouts.get_mut(primary_id).merge(&secondary_layout);
        }
    }
}

fn compute_start_offsets_by_group(
    group_states: &[GroupState<'_>],
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

fn compute_symbols_and_layouts<'data>(
    group_states: Vec<GroupState<'data>>,
    starting_mem_offsets_by_group: Vec<OutputSectionPartMap<u64>>,
    per_group_res_writers: &mut [sharded_vec_writer::Shard<Option<Resolution>>],
    resources: &FinaliseLayoutResources<'_, 'data>,
) -> Result<Vec<GroupLayout<'data>>> {
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

fn compute_segment_layout(
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
    output_sections: &OutputSections,
    output_order: &OutputOrder,
    program_segments: &ProgramSegments,
    header_info: &HeaderInfo,
    args: &Args,
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
                        mem_end: args.z_stack_size.map_or(0, |size| size.get()),
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
                        !section_flags.contains(shf::ALLOC),
                        "Section with SHF_ALLOC flag {} not present in any program segment.",
                        output_sections.section_debug(section_id)
                    );
                } else {
                    // TODO: Remove the NOTE exception. Non-alloc sections should be placed outside
                    // of program segments. NOTE sections are sometimes alloc and sometimes not.
                    // Alloc NOTE sections should be placed within a LOAD segment and within a NOTE
                    // segment. Non-alloc NOTE sections shouldn't be in any segment.

                    // The .riscv.attributes section is non-alloc but is expected to be put into a
                    // RISCV_ATTRIBUTES segment.
                    if [NOTE, RISCV_ATTRIBUTES].contains(&section_info.ty) {
                    } else {
                        // All segments should only cover sections that are allocated and have a
                        // non-zero address.
                        ensure!(
                            section_layout.mem_offset != 0 || merge_target == FILE_HEADER,
                            "Missing memory offset for section {} present in a program segment.",
                            output_sections.section_debug(section_id),
                        );
                        ensure!(
                            section_flags.contains(shf::ALLOC),
                            "Missing SHF_ALLOC section flag for section {} present in a program \
                         segment.",
                            output_sections.section_debug(section_id)
                        );
                    }
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

fn compute_total_section_part_sizes(
    group_states: &mut [GroupState],
    output_sections: &mut OutputSections,
    output_order: &OutputOrder,
    program_segments: &ProgramSegments,
    per_symbol_flags: &mut PerSymbolFlags,
    must_keep_sections: OutputSectionMap<bool>,
    resources: &FinaliseSizesResources,
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
fn propagate_section_attributes(group_states: &[GroupState], output_sections: &mut OutputSections) {
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
fn apply_non_addressable_indexes(
    group_states: &mut [GroupState],
    symbol_db: &SymbolDb,
) -> Result<NonAddressableCounts> {
    timing_phase!("Apply non-addressable indexes");

    let mut indexes = NonAddressableIndexes {
        // Allocate version indexes starting from after the local and global indexes and any
        // versions defined by a version script.
        gnu_version_r_index: object::elf::VER_NDX_GLOBAL
            + 1.max(symbol_db.version_script.version_count()),
    };

    let mut counts = NonAddressableCounts {
        verneed_count: 0,
        verdef_count: 0,
    };

    for g in group_states.iter_mut() {
        for s in &mut g.files {
            match s {
                FileLayoutState::Dynamic(s) => {
                    s.apply_non_addressable_indexes(&mut indexes, &mut counts)?;
                }
                FileLayoutState::Epilogue(s) => {
                    counts.verdef_count += s
                        .verdefs
                        .as_ref()
                        .map(|v| v.len() as u16)
                        .unwrap_or_default();
                }
                _ => {}
            }
        }
    }

    // If we were going to output symbol versions, but we didn't actually use any, then we drop all
    // versym allocations. This is partly to avoid wasting unnecessary space in the output file, but
    // mostly in order match what GNU ld does.
    if (counts.verneed_count == 0 && counts.verdef_count == 0)
        && symbol_db.output_kind.should_output_symbol_versions()
    {
        for g in group_states {
            *g.common.mem_sizes.get_mut(part_id::GNU_VERSION) = 0;
        }
    }
    Ok(counts)
}

#[derive(Clone, Copy, Default)]
struct NonAddressableIndexes {
    gnu_version_r_index: u16,
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct NonAddressableCounts {
    /// The number of shared objects that want to emit a verneed record.
    pub(crate) verneed_count: u64,
    /// The number of verdef records provided in version script.
    pub(crate) verdef_count: u16,
}

/// Returns the starting memory address for each alignment within each segment.
fn starting_memory_offsets(
    section_layouts: &OutputSectionPartMap<OutputRecordLayout>,
) -> OutputSectionPartMap<u64> {
    timing_phase!("Compute per-alignment offsets");

    section_layouts.map(|_, rec| rec.mem_offset)
}

#[derive(Default)]
struct WorkerSlot<'data> {
    work: Vec<WorkItem>,
    worker: Option<GroupState<'data>>,
}

#[derive(Debug)]
struct GcOutputs<'data> {
    group_states: Vec<GroupState<'data>>,
    must_keep_sections: OutputSectionMap<bool>,
    has_static_tls: bool,
    has_variant_pcs: bool,
}

struct GroupActivationInputs<'data> {
    resolved: ResolvedGroup<'data>,
    num_symbols: usize,
    group_index: usize,
}

impl<'data> GroupActivationInputs<'data> {
    fn activate_group<'scope, P: Platform<'data>>(
        self,
        resources: &'scope GraphResources<'data, '_>,
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
            let r = activate::<P>(&mut group.common, file, &mut group.queue, resources, scope)
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
            group.do_pending_work::<P>(resources, scope);
        }

        let remaining = resources
            .activations_remaining
            .fetch_sub(1, atomic::Ordering::Relaxed)
            - 1;

        if remaining == 0 {
            while let Some(group) = resources.delay_processing.pop() {
                group.do_pending_work::<P>(resources, scope);
            }
        }
    }
}

fn find_required_sections<'data, P: Platform<'data>>(
    groups_in: Vec<resolution::ResolvedGroup<'data>>,
    symbol_db: &SymbolDb<'data>,
    per_symbol_flags: &AtomicPerSymbolFlags,
    output_sections: &OutputSections<'data>,
    sonames: Sonames<'data>,
) -> Result<GcOutputs<'data>> {
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
        uses_tlsld: AtomicBool::new(false),
        start_stop_sections: output_sections.new_section_map(),
        activations_remaining: AtomicUsize::new(num_groups),
        delay_processing: ArrayQueue::new(1),
        sonames,
    };
    let resources_ref = &resources;

    rayon::in_place_scope(|scope| {
        queue_initial_group_processing::<P>(groups_in, symbol_db, resources_ref, scope);
    });

    let mut errors: Vec<Error> = take(resources.errors.lock().unwrap().as_mut());
    // TODO: Figure out good way to report more than one error.
    if let Some(error) = errors.pop() {
        return Err(error);
    }

    let mut group_states = unwrap_worker_states(&resources.worker_slots);
    let must_keep_sections = resources.must_keep_sections.into_map(|v| v.into_inner());

    tracing::debug!(target: "metrics", total = group_states
        .iter()
        .map(|g| g.common.exception_frame_count)
        .sum::<usize>(), "exception frames");

    tracing::debug!(target: "metrics", section = "`.eh_frame`", relocations = group_states
        .iter()
        .map(|g| g.common.exception_frame_relocations)
        .sum::<usize>(), "resolved relocations");

    // Give our prelude a chance to tie up a few last sizes while we still have access to
    // `resources`.
    let prelude_group = &mut group_states[0];
    let FileLayoutState::Prelude(prelude) = &mut prelude_group.files[0] else {
        unreachable!("Prelude must be first");
    };
    prelude.pre_finalise_sizes(
        &mut prelude_group.common,
        &resources.uses_tlsld,
        resources.symbol_db.args,
        resources.symbol_db.output_kind,
    );

    Ok(GcOutputs {
        group_states,
        must_keep_sections,
        has_static_tls: resources.has_static_tls.load(atomic::Ordering::Relaxed),
        has_variant_pcs: resources.has_variant_pcs.load(atomic::Ordering::Relaxed),
    })
}

fn queue_initial_group_processing<'data, 'scope, P: Platform<'data>>(
    groups_in: Vec<resolution::ResolvedGroup<'data>>,
    symbol_db: &'scope SymbolDb<'data>,
    resources: &'scope GraphResources<'data, '_>,
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
                inputs.activate_group::<P>(resources, scope);
            });
        });
}

fn unwrap_worker_states<'data>(
    worker_slots: &[Mutex<WorkerSlot<'data>>],
) -> Vec<GroupState<'data>> {
    worker_slots
        .iter()
        .filter_map(|w| w.lock().unwrap().worker.take())
        .collect()
}

impl<'data> GroupState<'data> {
    /// Does work until there's nothing left in the queue, then returns our worker to its slot and
    /// shuts down.
    fn do_pending_work<'scope, P: Platform<'data>>(
        mut self,
        resources: &'scope GraphResources<'data, '_>,
        scope: &Scope<'scope>,
    ) {
        loop {
            while let Some(work_item) = self.queue.local_work.pop() {
                let file_id = work_item.file_id(resources.symbol_db);
                let file = &mut self.files[file_id.file()];
                if let Err(error) = file.do_work::<P>(
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
        output_sections: &OutputSections,
        per_symbol_flags: &AtomicPerSymbolFlags,
        resources: &FinaliseSizesResources<'data, '_>,
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
        resolutions_out: &mut sharded_vec_writer::Shard<Option<Resolution>>,
        resources: &FinaliseLayoutResources<'_, 'data>,
    ) -> Result<GroupLayout<'data>> {
        let eh_frame_start_address = *memory_offsets.get(part_id::EH_FRAME);
        let mut files = self
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

        set_last_verneed(&self.common, resources, memory_offsets, &mut files);

        Ok(GroupLayout {
            files,
            strtab_start_offset,
            dynstr_start_offset,
            file_sizes: compute_file_sizes(&self.common.mem_sizes, resources.output_sections),
            mem_sizes: self.common.mem_sizes,
            eh_frame_start_address,
        })
    }
}

/// Determines if the sizes from `common` indicate that we're working with the last group that
/// contributes to .gnu.version_r. If we are, then finds the last dynamic object in the group that
/// has verdef_info and lets it know that it's the last verneed. This is needed when we write so
/// that we know whether to output the offset to the next verneed, or zero for the last record.
fn set_last_verneed(
    common: &CommonGroupState,
    resources: &FinaliseLayoutResources,
    memory_offsets: &OutputSectionPartMap<u64>,
    files: &mut [FileLayout],
) {
    let gnu_version_r_layout = resources
        .section_layouts
        .get(output_section_id::GNU_VERSION_R);
    let is_last_verneed = *common.mem_sizes.get(part_id::GNU_VERSION_R) > 0
        && (*memory_offsets.get(part_id::GNU_VERSION_R)
            == gnu_version_r_layout.mem_offset + gnu_version_r_layout.mem_size);
    if is_last_verneed {
        for file in files.iter_mut().rev() {
            if let FileLayout::Dynamic(d) = file
                && d.verneed_info.is_some()
            {
                d.is_last_verneed = true;
                break;
            }
        }
    }
}

fn activate<'data, 'scope, P: Platform<'data>>(
    common: &mut CommonGroupState<'data>,
    file: &mut FileLayoutState<'data>,
    queue: &mut LocalWorkQueue,
    resources: &'scope GraphResources<'data, '_>,
    scope: &Scope<'scope>,
) -> Result {
    match file {
        FileLayoutState::Object(s) => s.activate::<P>(common, resources, queue, scope)?,
        FileLayoutState::Prelude(s) => s.activate::<P>(common, resources, queue, scope)?,
        FileLayoutState::Dynamic(s) => s.activate::<P>(common, resources, queue, scope)?,
        FileLayoutState::LinkerScript(s) => s.activate(common, resources)?,
        FileLayoutState::Epilogue(_) => {}
        FileLayoutState::NotLoaded(_) => {}
        FileLayoutState::SyntheticSymbols(_) => {}
    }
    Ok(())
}

impl LocalWorkQueue {
    #[inline(always)]
    fn send_work<'data, 'scope, P: Platform<'data>>(
        &mut self,
        resources: &'scope GraphResources<'data, '_>,
        file_id: FileId,
        work: WorkItem,
        scope: &Scope<'scope>,
    ) {
        if file_id.group() == self.index {
            self.local_work.push(work);
        } else {
            resources.send_work::<P>(file_id, work, resources, scope);
        }
    }

    fn new(index: usize) -> LocalWorkQueue {
        Self {
            index,
            local_work: Default::default(),
        }
    }

    #[inline(always)]
    fn send_symbol_request<'data, 'scope, P: Platform<'data>>(
        &mut self,
        symbol_id: SymbolId,
        resources: &'scope GraphResources<'data, '_>,
        scope: &Scope<'scope>,
    ) {
        debug_assert!(resources.symbol_db.is_canonical(symbol_id));
        let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        self.send_work::<P>(
            resources,
            symbol_file_id,
            WorkItem::LoadGlobalSymbol(symbol_id),
            scope,
        );
    }

    fn send_copy_relocation_request<'data, 'scope, P: Platform<'data>>(
        &mut self,
        symbol_id: SymbolId,
        resources: &'scope GraphResources<'data, '_>,
        scope: &Scope<'scope>,
    ) {
        debug_assert!(resources.symbol_db.is_canonical(symbol_id));
        let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        self.send_work::<P>(
            resources,
            symbol_file_id,
            WorkItem::CopyRelocateSymbol(symbol_id),
            scope,
        );
    }
}

impl<'data> GraphResources<'data, '_> {
    fn report_error(&self, error: Error) {
        self.errors.lock().unwrap().push(error);
    }

    /// Sends all work in `work` to the worker for `file_id`. Leaves `work` empty so that it can be
    /// reused.
    #[inline(always)]
    fn send_work<'scope, P: Platform<'data>>(
        &self,
        file_id: FileId,
        work: WorkItem,
        resources: &'scope GraphResources<'data, '_>,
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
                worker.do_pending_work::<P>(resources, scope);
            });
        }
    }

    fn local_flags_for_symbol(&self, symbol_id: SymbolId) -> ValueFlags {
        self.per_symbol_flags.flags_for_symbol(symbol_id)
    }

    fn symbol_debug(&'_ self, symbol_id: SymbolId) -> SymbolDebug<'_> {
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

impl<'data> FileLayoutState<'data> {
    fn finalise_sizes(
        &mut self,
        common: &mut CommonGroupState<'data>,
        output_sections: &OutputSections,
        per_symbol_flags: &AtomicPerSymbolFlags,
        resources: &FinaliseSizesResources<'data, '_>,
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

        finalise_gnu_version_size(common, resources.symbol_db);

        Ok(())
    }

    fn do_work<'scope, P: Platform<'data>>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        work_item: WorkItem,
        resources: &'scope GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result {
        match work_item {
            WorkItem::LoadGlobalSymbol(symbol_id) => self
                .handle_symbol_request::<P>(common, symbol_id, resources, queue, scope)
                .with_context(|| {
                    format!(
                        "Failed to load {} from {self}",
                        resources.symbol_debug(symbol_id),
                    )
                }),
            WorkItem::CopyRelocateSymbol(symbol_id) => match self {
                FileLayoutState::Dynamic(state) => state.copy_relocate_symbol(symbol_id, resources),

                _ => {
                    bail!(
                        "Internal error: ExportCopyRelocation sent to non-dynamic object for: {}",
                        resources.symbol_debug(symbol_id)
                    )
                }
            },
            WorkItem::LoadSection(request) => match self {
                FileLayoutState::Object(object_layout_state) => object_layout_state
                    .handle_section_load_request::<P>(
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
                    object.export_dynamic::<P>(common, symbol_id, resources, queue, scope)
                }
                _ => {
                    // Non-loaded and dynamic objects don't do anything in response to a request to
                    // export a dynamic symbol.
                    Ok(())
                }
            },
        }
    }

    fn handle_symbol_request<'scope, P: Platform<'data>>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_id: SymbolId,
        resources: &'scope GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result {
        match self {
            FileLayoutState::Object(state) => {
                state.load_symbol::<P>(common, symbol_id, resources, queue, scope)?;
            }
            FileLayoutState::Prelude(state) => {
                state.load_symbol::<P>(common, symbol_id, resources, queue, scope)?;
            }
            FileLayoutState::Dynamic(state) => {
                state.load_symbol::<P>(common, symbol_id, resources, queue, scope)?;
            }
            FileLayoutState::LinkerScript(_) => {}
            FileLayoutState::NotLoaded(_) => {}
            FileLayoutState::SyntheticSymbols(state) => {
                state.load_symbol::<P>(common, symbol_id, resources, queue, scope)?;
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
        resolutions_out: &mut sharded_vec_writer::Shard<Option<Resolution>>,
        resources: &FinaliseLayoutResources<'_, 'data>,
    ) -> Result<FileLayout<'data>> {
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

fn finalise_gnu_version_size(common: &mut CommonGroupState, symbol_db: &SymbolDb) {
    if symbol_db.output_kind.should_output_symbol_versions() {
        let num_dynamic_symbols =
            common.mem_sizes.get(part_id::DYNSYM) / crate::elf::SYMTAB_ENTRY_SIZE;
        // Note, sets the GNU_VERSION allocation rather than incrementing it. Assuming there are
        // multiple files in our group, we'll update this same value multiple times, each time
        // with a possibly revised dynamic symbol count. The important thing is that when we're
        // done finalising the group sizes, the GNU_VERSION size should be consistent with the
        // DYNSYM size.
        *common.mem_sizes.get_mut(part_id::GNU_VERSION) =
            num_dynamic_symbols * crate::elf::GNU_VERSION_ENTRY_SIZE;
    }
}

fn compute_file_sizes(
    mem_sizes: &OutputSectionPartMap<u64>,
    output_sections: &OutputSections<'_>,
) -> OutputSectionPartMap<usize> {
    mem_sizes.map(|part_id, size| {
        if output_sections.has_data_in_file(part_id.output_section_id()) {
            *size as usize
        } else {
            0
        }
    })
}

impl std::fmt::Display for PreludeLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt("<prelude>", f)
    }
}

impl std::fmt::Display for EpilogueLayoutState {
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

impl std::fmt::Display for FileLayoutState<'_> {
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

impl std::fmt::Display for FileLayout<'_> {
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

impl std::fmt::Display for GroupLayout<'_> {
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

impl std::fmt::Display for GroupState<'_> {
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

impl std::fmt::Debug for FileLayout<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self, f)
    }
}

impl std::fmt::Display for ObjectLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        // TODO: This is mostly for debugging use. Consider only showing this if some environment
        // variable is set, or only in debug builds.
        write!(f, " ({})", self.file_id())
    }
}

impl std::fmt::Display for DynamicLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        write!(f, " ({})", self.file_id())
    }
}

impl std::fmt::Display for DynamicLayout<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        write!(f, " ({})", self.file_id)
    }
}

impl std::fmt::Display for ObjectLayout<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        // TODO: This is mostly for debugging use. Consider only showing this if some environment
        // variable is set, or only in debug builds.
        write!(f, " ({})", self.file_id)
    }
}

impl Section {
    fn create(
        header: &crate::elf::SectionHeader,
        object_state: &mut ObjectLayoutState,
        section_index: object::SectionIndex,
        part_id: PartId,
    ) -> Result<Section> {
        let size = object_state.object.section_size(header)?;
        let section = Section {
            index: section_index,
            part_id,
            size,
            flags: ValueFlags::empty(),
            is_writable: header.flags().is_writable(),
        };
        Ok(section)
    }

    // How much space we take up. This is our size rounded up to the next multiple of our
    // alignment, unless we're in a packed section, in which case it's just our size.
    pub(crate) fn capacity(&self) -> u64 {
        if self.part_id.should_pack() {
            self.size
        } else {
            self.alignment().align_up(self.size)
        }
    }

    pub(crate) fn output_section_id(&self) -> OutputSectionId {
        self.part_id.output_section_id()
    }

    pub(crate) fn output_part_id(&self) -> PartId {
        self.part_id
    }

    /// Returns the alignment for this section.
    fn alignment(&self) -> Alignment {
        self.part_id.alignment()
    }

    /// Returns whether to reverse the contents of this section. This is true for .ctors/.dtors
    /// sections.
    pub(crate) fn should_reverse_contents(
        &self,
        file: &crate::elf::File,
        output_sections: &OutputSections,
    ) -> bool {
        // Getting the section name is expensive, so we only do it when the output section is
        // .init_array / .fini_array.
        let section_id = output_sections.primary_output_section(self.part_id.output_section_id());
        if section_id != output_section_id::INIT_ARRAY
            && section_id != output_section_id::FINI_ARRAY
        {
            return false;
        }

        file.section(self.index)
            .and_then(|header| file.section_name(header))
            .is_ok_and(|section_name| {
                // .ctors and .dtors sections need their contents reversed when merged into
                // .init_array/.fini_array
                section_name.starts_with(secnames::CTORS_SECTION_NAME)
                    || section_name.starts_with(secnames::DTORS_SECTION_NAME)
            })
    }
}

#[inline(always)]
fn process_relocation<'data, 'scope, P: Platform<'data>, R: Relocation>(
    object: &ObjectLayoutState,
    common: &mut CommonGroupState,
    rel: &R,
    section: &object::elf::SectionHeader64<LittleEndian>,
    resources: &'scope GraphResources<'data, '_>,
    queue: &mut LocalWorkQueue,
    is_debug_section: bool,
    scope: &Scope<'scope>,
) -> Result<RelocationModifier> {
    let args = resources.symbol_db.args;
    let mut next_modifier = RelocationModifier::Normal;
    if let Some(local_sym_index) = rel.symbol() {
        let symbol_db = resources.symbol_db;
        let local_symbol_id = object.symbol_id_range.input_to_id(local_sym_index);
        let symbol_id = symbol_db.definition(local_symbol_id);
        let mut flags = resources.local_flags_for_symbol(symbol_id);
        flags.merge(resources.local_flags_for_symbol(local_symbol_id));
        let rel_offset = rel.offset();
        let r_type = rel.raw_type();
        let section_flags = SectionFlags::from_header(section);

        let rel_info = if let Some(relaxation) = P::Relaxation::new(
            r_type,
            object.object.raw_section_data(section)?,
            rel_offset,
            flags,
            symbol_db.output_kind,
            section_flags,
            true,
        )
        .filter(|relaxation| args.relax || relaxation.is_mandatory())
        {
            next_modifier = relaxation.next_modifier();
            relaxation.rel_info()
        } else {
            P::relocation_from_raw(r_type)?
        };

        let section_is_writable = section_flags.is_writable();
        let mut flags_to_add = resolution_flags(rel_info.kind);

        if !section_flags.contains(shf::ALLOC) {
            // Non-alloc sections never get dynamic relocations, so there's nothing to do here.
        } else if rel_info.kind.is_tls() {
            if does_relocation_require_static_tls(rel_info.kind) {
                resources
                    .has_static_tls
                    .store(true, atomic::Ordering::Relaxed);
            }

            if needs_tlsld(rel_info.kind) && !resources.uses_tlsld.load(atomic::Ordering::Relaxed) {
                resources.uses_tlsld.store(true, atomic::Ordering::Relaxed);
            }
        } else if flags_to_add.needs_direct() && flags.is_interposable() {
            if section_is_writable {
                common.allocate(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
            } else if flags.is_function() {
                // Create a PLT entry for the function and refer to that instead.
                flags_to_add.remove(ValueFlags::DIRECT);
                flags_to_add |= ValueFlags::PLT | ValueFlags::GOT;
            } else if !flags.is_absolute() {
                match args.copy_relocations {
                    crate::args::CopyRelocations::Allowed => {
                        flags_to_add |= ValueFlags::COPY_RELOCATION;
                    }
                    crate::args::CopyRelocations::Disallowed(reason) => {
                        // We don't at present support text relocations, so if we can't apply a copy
                        // relocation, we error instead.
                        bail!(
                            "Direct relocation ({}) to dynamic symbol from non-writable section, \
                            but copy relocations are disabled because {reason}. {}",
                            P::rel_type_to_string(r_type),
                            resources.symbol_debug(symbol_id),
                        );
                    }
                }
            }
        } else if flags.is_ifunc()
            && rel_info.kind == RelocationKind::Absolute
            && section_is_writable
            && symbol_db.output_kind.is_relocatable()
        {
            common.allocate(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
        } else if symbol_db.output_kind.is_relocatable()
            && rel_info.kind == RelocationKind::Absolute
            && flags.is_address()
        {
            if section_is_writable {
                common.allocate(part_id::RELA_DYN_RELATIVE, elf::RELA_ENTRY_SIZE);
            } else if !is_debug_section {
                bail!(
                    "Cannot apply relocation {} to read-only section. \
                    Please recompile with -fPIC or link with -no-pie",
                    P::rel_type_to_string(r_type),
                );
            }
        }

        // For ifunc symbols with GOT-relative references (like R_X86_64_GOTPCRELX), we need a
        // separate GOT entry for address equality. The main GOT entry will be used by the PLT stub
        // with an IRELATIVE relocation, while this extra entry will contain the PLT stub address so
        // that all references to the ifunc return the same address.

        let relocation_needs_got = flags_to_add.needs_got();

        if flags.is_ifunc() && !symbol_db.output_kind.is_static_executable() {
            flags_to_add |= ValueFlags::GOT | ValueFlags::PLT;
        }

        if flags.is_ifunc() && relocation_needs_got && !symbol_db.output_kind.is_relocatable() {
            flags_to_add |= ValueFlags::IFUNC_GOT_FOR_ADDRESS;
        }

        let atomic_flags = &resources.per_symbol_flags.get_atomic(symbol_id);
        let previous_flags = atomic_flags.fetch_or(flags_to_add);

        if !previous_flags.has_resolution() {
            if flags.is_ifunc() && symbol_db.output_kind.is_static_executable() {
                atomic_flags.fetch_or(ValueFlags::GOT | ValueFlags::PLT);
            }

            queue.send_symbol_request::<P>(symbol_id, resources, scope);
            if should_emit_undefined_error(
                object.object.symbol(local_sym_index)?,
                object.file_id,
                symbol_db.file_id_for_symbol(symbol_id),
                flags,
                args,
                symbol_db.output_kind,
            ) {
                let symbol_name = symbol_db.symbol_name_for_display(symbol_id);
                let source_info = crate::dwarf_address_info::get_source_info::<P>(
                    object.object,
                    &object.relocations,
                    section,
                    rel_offset,
                )
                .context("Failed to get source info")?;

                if args.error_unresolved_symbols {
                    resources.report_error(error!(
                        "Undefined symbol {symbol_name}, referenced by {}\n    {}",
                        source_info, object.input,
                    ));
                } else {
                    crate::error::warning(&format!(
                        "Undefined symbol {symbol_name}, referenced by {}\n    {}",
                        source_info, object.input,
                    ));
                }
            }
        }

        if flags_to_add.needs_copy_relocation() && !previous_flags.needs_copy_relocation() {
            queue.send_copy_relocation_request::<P>(symbol_id, resources, scope);
        }
    }
    Ok(next_modifier)
}

/// Returns whether the supplied relocation type requires static TLS. If true and we're writing a
/// shared object, then the STATIC_TLS will be set in the shared object which is a signal to the
/// runtime loader that the shared object cannot be loaded at runtime (e.g. with dlopen).
fn does_relocation_require_static_tls(rel_kind: RelocationKind) -> bool {
    resolution_flags(rel_kind) == ValueFlags::GOT_TLS_OFFSET
}

fn resolution_flags(rel_kind: RelocationKind) -> ValueFlags {
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

impl<'data> PreludeLayoutState<'data> {
    fn new(input_state: resolution::ResolvedPrelude<'data>) -> Self {
        Self {
            file_id: PRELUDE_FILE_ID,
            symbol_id_range: SymbolIdRange::prelude(input_state.symbol_definitions.len()),
            internal_symbols: InternalSymbols {
                symbol_definitions: input_state.symbol_definitions,
                start_symbol_id: SymbolId::zero(),
            },
            entry_symbol_id: None,
            needs_tlsld_got_entry: false,
            identity: format!("Linker: {}", crate::identity::linker_identity()),
            header_info: None,
            dynamic_linker: None,
            shstrtab_size: 0,
        }
    }

    fn activate<'scope, P: Platform<'data>>(
        &mut self,
        common: &mut CommonGroupState,
        resources: &'scope GraphResources<'data, '_>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result {
        if resources.symbol_db.args.should_write_linker_identity {
            // Allocate space to store the identity of the linker in the .comment section.
            common.allocate(
                output_section_id::COMMENT.part_id_with_alignment(alignment::MIN),
                self.identity.len() as u64,
            );
        }

        // The first entry in the symbol table must be null. Similarly, the first string in the
        // strings table must be empty.
        if !resources.symbol_db.args.strip_all() {
            common.allocate(part_id::SYMTAB_LOCAL, size_of::<elf::SymtabEntry>() as u64);
            common.allocate(part_id::STRTAB, 1);
        }

        self.load_entry_point::<P>(resources, queue, scope);

        if resources.symbol_db.output_kind.needs_dynsym() {
            // Allocate space for the null symbol.
            common.allocate(part_id::DYNSTR, 1);
            common.allocate(part_id::DYNSYM, size_of::<elf::SymtabEntry>() as u64);
        }

        if resources.symbol_db.output_kind.is_dynamic_executable() {
            self.dynamic_linker = resources
                .symbol_db
                .args
                .dynamic_linker
                .as_ref()
                .map(|p| CString::new(p.as_os_str().as_encoded_bytes()))
                .transpose()?;
        }
        if let Some(dynamic_linker) = self.dynamic_linker.as_ref() {
            common.allocate(
                part_id::INTERP,
                dynamic_linker.as_bytes_with_nul().len() as u64,
            );
        }

        self.mark_defsyms_as_used::<P>(resources, queue, scope);

        Ok(())
    }

    /// Mark defsyms from the command-line as being directly referenced so that we emit the symbols
    /// even if nothing in the code references them.
    fn mark_defsyms_as_used<'scope, P: Platform<'data>>(
        &self,
        resources: &'scope GraphResources<'data, '_>,
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
                            queue.send_work::<P>(
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

    fn load_entry_point<'scope, P: Platform<'data>>(
        &mut self,
        resources: &'scope GraphResources<'data, '_>,
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
            queue.send_work::<P>(
                resources,
                file_id,
                WorkItem::LoadGlobalSymbol(symbol_id),
                scope,
            );
        }
    }

    fn pre_finalise_sizes(
        &mut self,
        common: &mut CommonGroupState,
        uses_tlsld: &AtomicBool,
        args: &Args,
        output_kind: OutputKind,
    ) {
        if uses_tlsld.load(atomic::Ordering::Relaxed) {
            // Allocate space for a TLS module number and offset for use with TLSLD relocations.
            common.allocate(part_id::GOT, elf::GOT_ENTRY_SIZE * 2);
            self.needs_tlsld_got_entry = true;
            // For shared objects, we'll need to use a DTPMOD relocation to fill in the TLS module
            // number.
            if !output_kind.is_executable() {
                common.allocate(part_id::RELA_DYN_GENERAL, crate::elf::RELA_ENTRY_SIZE);
            }
        }

        if args.should_write_eh_frame_hdr {
            common.allocate(part_id::EH_FRAME_HDR, size_of::<elf::EhFrameHdr>() as u64);
        }
    }

    fn finalise_sizes(
        common: &mut CommonGroupState<'data>,
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
        common: &mut CommonGroupState,
        total_sizes: &mut OutputSectionPartMap<u64>,
        must_keep_sections: OutputSectionMap<bool>,
        output_sections: &mut OutputSections,
        output_order: &OutputOrder,
        program_segments: &ProgramSegments,
        per_symbol_flags: &mut PerSymbolFlags,
        resources: &FinaliseSizesResources,
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
        output_sections: &OutputSections,
        per_symbol_flags: &mut PerSymbolFlags,
        symbol_db: &SymbolDb<'_>,
        extra_sizes: &mut OutputSectionPartMap<u64>,
    ) -> Result<(), Error> {
        if symbol_db.args.strip_all() {
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
        output_sections: &mut OutputSections,
        program_segments: &ProgramSegments,
        output_order: &OutputOrder,
        resources: &FinaliseSizesResources,
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
        for section_id in output_section_id::built_in_section_ids() {
            if section_id.built_in_details().keep_if_empty {
                // Don't keep .relro_padding if relro is disabled.
                if section_id == output_section_id::RELRO_PADDING && !resources.symbol_db.args.relro
                {
                    continue;
                }
                *keep_sections.get_mut(section_id) = true;
            }
        }

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
            // we. Custom sections (e.g. from linker scripts) that still have NULL type get
            // PROGBITS assigned instead, since an empty but explicitly defined section should still
            // be emitted if something references it.
            let section_info = output_sections.section_infos.get(section_id);
            if section_info.ty == sht::NULL && section_id != output_section_id::FILE_HEADER {
                if section_id.as_usize() >= output_section_id::NUM_BUILT_IN_SECTIONS {
                    output_sections.section_infos.get_mut(section_id).ty = sht::PROGBITS;
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

        // If relro is disabled, then discard the relro segment.
        if !resources.symbol_db.args.relro {
            for (segment_def, keep) in program_segments.into_iter().zip(keep_segments.iter_mut()) {
                if segment_def.segment_type == pt::GNU_RELRO {
                    *keep = false;
                }
            }
        }

        let active_segment_ids = (0..program_segments.len())
            .map(ProgramSegmentId::new)
            .filter(|id| keep_segments[id.as_usize()] || program_segments.is_stack_segment(*id))
            .collect();

        let header_info = HeaderInfo {
            num_output_sections_with_content: num_sections
                .try_into()
                .expect("output section count must fit in a u16"),

            active_segment_ids,
            eflags: resources.properties_and_attributes.eflags,
        };

        // Allocate space for headers based on segment and section counts.
        extra_sizes.increment(part_id::FILE_HEADER, u64::from(elf::FILE_HEADER_SIZE));
        extra_sizes.increment(part_id::PROGRAM_HEADERS, header_info.program_headers_size());
        extra_sizes.increment(part_id::SECTION_HEADERS, header_info.section_headers_size());
        self.shstrtab_size = output_sections
            .ids_with_info()
            .filter(|(id, _info)| output_sections.output_index_of_section(*id).is_some())
            .map(|(_id, info)| {
                if let SectionKind::Primary(name) = info.kind {
                    name.len() as u64 + 1
                } else {
                    0
                }
            })
            .sum::<u64>();
        extra_sizes.increment(part_id::SHSTRTAB, self.shstrtab_size);

        self.header_info = Some(header_info);
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<'_, '_>,
    ) -> Result<PreludeLayout<'data>> {
        let header_layout = resources
            .section_layouts
            .get(output_section_id::FILE_HEADER);
        assert_eq!(header_layout.file_offset, 0);

        let tlsld_got_entry = self.needs_tlsld_got_entry.then(|| {
            let address = NonZeroU64::new(*memory_offsets.get(part_id::GOT))
                .expect("GOT address must never be zero");
            memory_offsets.increment(part_id::GOT, elf::GOT_ENTRY_SIZE * 2);
            address
        });

        // Take the null symbol's index.
        if resources.symbol_db.output_kind.needs_dynsym() {
            take_dynsym_index(memory_offsets, resources.section_layouts)?;
        }

        self.internal_symbols
            .finalise_layout(memory_offsets, resolutions_out, resources)?;

        if resources.symbol_db.args.should_write_linker_identity {
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
            tlsld_got_entry,
            identity: self.identity,
            dynamic_linker: self.dynamic_linker,
            header_info: self
                .header_info
                .expect("we should have computed header info by now"),
        })
    }
}

impl<'data> InternalSymbols<'data> {
    fn allocate_symbol_table_sizes(
        &self,
        sizes: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<'_>,
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

            // PROVIDE_HIDDEN symbols are local, others are global
            let symtab_part = if def_info.is_hidden {
                part_id::SYMTAB_LOCAL
            } else {
                part_id::SYMTAB_GLOBAL
            };
            sizes.increment(symtab_part, size_of::<elf::SymtabEntry>() as u64);
            let symbol_name = symbol_db.symbol_name(symbol_id)?;
            let symbol_name = RawSymbolName::parse(symbol_name.bytes()).name;
            sizes.increment(part_id::STRTAB, symbol_name.len() as u64 + 1);
        }
        Ok(())
    }

    fn finalise_layout(
        &self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources,
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

fn create_start_end_symbol_resolution(
    memory_offsets: &mut OutputSectionPartMap<u64>,
    resources: &FinaliseLayoutResources<'_, '_>,
    def_info: InternalSymDefInfo,
    symbol_id: SymbolId,
) -> Option<Resolution> {
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
            .find(|seg| resources.program_segments.segment_def(seg.id).segment_type == pt::LOAD)
            .map(|seg| seg.sizes.mem_offset)?,
    };

    Some(create_resolution(
        resources
            .symbol_db
            .flags_for_symbol(resources.per_symbol_flags, symbol_id),
        raw_value,
        None,
        memory_offsets,
    ))
}

fn should_emit_undefined_error(
    symbol: &Symbol,
    sym_file_id: FileId,
    sym_def_file_id: FileId,
    flags: ValueFlags,
    args: &Args,
    output_kind: OutputKind,
) -> bool {
    if (output_kind.is_shared_object() && !args.no_undefined) || symbol.is_weak() {
        return false;
    }

    let is_symbol_undefined =
        sym_file_id == sym_def_file_id && symbol.is_undefined() && flags.is_absolute();

    match args.unresolved_symbols {
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

    fn finalise_sizes(
        &self,
        common: &mut CommonGroupState,
        per_symbol_flags: &AtomicPerSymbolFlags,
        resources: &FinaliseSizesResources,
    ) -> Result {
        let symbol_db = resources.symbol_db;

        if !symbol_db.args.strip_all() {
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

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<'_, 'data>,
    ) -> Result<SyntheticSymbolsLayout<'data>> {
        self.internal_symbols
            .finalise_layout(memory_offsets, resolutions_out, resources)?;

        Ok(SyntheticSymbolsLayout {
            internal_symbols: self.internal_symbols,
        })
    }
}

impl EpilogueLayoutState {
    fn new(args: &Args) -> EpilogueLayoutState {
        let build_id_size = match &args.build_id {
            BuildIdOption::None => None,
            BuildIdOption::Fast => Some(size_of::<blake3::Hash>()),
            BuildIdOption::Hex(hex) => Some(hex.len()),
            BuildIdOption::Uuid => Some(size_of::<uuid::Uuid>()),
        };

        EpilogueLayoutState {
            sysv_hash_layout: None,
            gnu_hash_layout: None,
            build_id_size,
            verdefs: Default::default(),
        }
    }

    fn apply_late_size_adjustments(
        &mut self,
        common: &mut CommonGroupState,
        total_sizes: &mut OutputSectionPartMap<u64>,
        resources: &FinaliseSizesResources,
    ) -> Result {
        if resources.symbol_db.args.hash_style.includes_sysv() {
            let mut extra_sizes = OutputSectionPartMap::with_size(common.mem_sizes.num_parts());
            self.allocate_sysv_hash(&mut extra_sizes, total_sizes, resources)?;

            // See comments in Prelude::apply_late_size_adjustments.
            total_sizes.merge(&extra_sizes);
            common.mem_sizes.merge(&extra_sizes);
        }

        Ok(())
    }

    fn gnu_build_id_note_section_size(&self) -> Option<u64> {
        Some((size_of::<NoteHeader>() + GNU_NOTE_NAME.len() + self.build_id_size?) as u64)
    }

    fn finalise_sizes(
        &mut self,
        common: &mut CommonGroupState,
        resources: &FinaliseSizesResources,
    ) {
        let symbol_db = resources.symbol_db;

        if symbol_db.output_kind.needs_dynamic() {
            let dynamic_entry_size = size_of::<crate::elf::DynamicEntry>();
            common.allocate(
                part_id::DYNAMIC,
                (elf_writer::NUM_EPILOGUE_DYNAMIC_ENTRIES * dynamic_entry_size) as u64,
            );
            if let Some(rpath) = symbol_db.args.rpath.as_ref() {
                common.allocate(part_id::DYNAMIC, dynamic_entry_size as u64);
                common.allocate(part_id::DYNSTR, rpath.len() as u64 + 1);
            }
            if let Some(soname) = symbol_db.args.soname.as_ref() {
                common.allocate(part_id::DYNSTR, soname.len() as u64 + 1);
                common.allocate(part_id::DYNAMIC, dynamic_entry_size as u64);
            }
            for aux in &symbol_db.args.auxiliary {
                common.allocate(part_id::DYNSTR, aux.len() as u64 + 1);
                common.allocate(part_id::DYNAMIC, dynamic_entry_size as u64);
            }

            if let Some(gnu_hash_layout) = resources.gnu_hash_layout {
                self.allocate_gnu_hash(common, gnu_hash_layout, resources);
            }

            common.allocate(
                part_id::DYNSTR,
                resources
                    .dynamic_symbol_definitions
                    .iter()
                    .map(|n| n.name.len() + 1)
                    .sum::<usize>() as u64,
            );
            common.allocate(
                part_id::DYNSYM,
                (resources.dynamic_symbol_definitions.len() * size_of::<elf::SymtabEntry>()) as u64,
            );
        }

        common.allocate(
            part_id::NOTE_GNU_PROPERTY,
            crate::elf::gnu_property_notes_section_size(
                &resources.properties_and_attributes.gnu_property_notes,
            ),
        );
        common.allocate(
            part_id::RISCV_ATTRIBUTES,
            resources
                .properties_and_attributes
                .riscv_attributes
                .section_size,
        );

        if let Some(build_id_sec_size) = self.gnu_build_id_note_section_size() {
            common.allocate(part_id::NOTE_GNU_BUILD_ID, build_id_sec_size);
        }

        let version_count = symbol_db.version_script.version_count();
        if version_count > 0 {
            // If soname is not provided, allocate space for file name as the base version
            let base_version_name = if symbol_db.args.soname.is_none() {
                let file_name = symbol_db
                    .args
                    .output
                    .file_name()
                    .expect("File name should be present at this point")
                    .to_string_lossy()
                    .to_string();
                common.allocate(part_id::DYNSTR, file_name.len() as u64 + 1);
                file_name
            } else {
                String::new()
            };

            let mut verdefs = Vec::with_capacity(version_count.into());

            // Base version
            verdefs.push(VersionDef {
                name: base_version_name.into_bytes(),
                parent_index: None,
            });

            match &symbol_db.version_script {
                VersionScript::Regular(version_script) => {
                    // Take all but the base version
                    for version in version_script.version_iter().skip(1) {
                        verdefs.push(VersionDef {
                            name: version.name.to_vec(),
                            parent_index: version.parent_index,
                        });
                        common.allocate(part_id::DYNSTR, version.name.len() as u64 + 1);
                    }
                }
                VersionScript::Rust(_) => {}
            }

            let dependencies_count = symbol_db.version_script.parent_count();
            common.allocate(
                part_id::GNU_VERSION_D,
                (size_of::<crate::elf::Verdef>() as u16 * version_count
                    + size_of::<crate::elf::Verdaux>() as u16
                        * (version_count + dependencies_count))
                    .into(),
            );
            self.verdefs.replace(verdefs);
        }
    }

    /// Allocates space required for .gnu.hash. Also sorts dynamic symbol definitions by their hash
    /// bucket as required by .gnu.hash.
    fn allocate_gnu_hash(
        &mut self,
        common: &mut CommonGroupState,
        gnu_hash_layout: GnuHashLayout,
        resources: &FinaliseSizesResources,
    ) {
        let num_blume = 1;
        let num_defs = resources.dynamic_symbol_definitions.len();
        common.allocate(
            part_id::GNU_HASH,
            (size_of::<elf::GnuHashHeader>()
                + size_of::<u64>() * num_blume
                + size_of::<u32>() * gnu_hash_layout.bucket_count as usize
                + size_of::<u32>() * num_defs) as u64,
        );
        self.gnu_hash_layout = Some(gnu_hash_layout);
    }

    fn allocate_sysv_hash(
        &mut self,
        sizes_out: &mut OutputSectionPartMap<u64>,
        total_sizes: &OutputSectionPartMap<u64>,
        resources: &FinaliseSizesResources,
    ) -> Result {
        let num_defs = resources.dynamic_symbol_definitions.len();
        if num_defs == 0 {
            return Ok(());
        }

        let bucket_count = ((num_defs / 2).max(1)).next_power_of_two() as u32;
        // Whereas `num_defs` above is the number of definitions, this is the number of dynamic
        // symbols, which also includes undefined dynamic symbols.
        let num_dynsym = *total_sizes.get(part_id::DYNSYM) / elf::SYMTAB_ENTRY_SIZE;
        let chain_count = num_dynsym
            .try_into()
            .context("Too many dynamic symbols for .hash")?;

        let sysv_hash_layout = SysvHashLayout {
            bucket_count,
            chain_count,
        };

        *sizes_out.get_mut(part_id::SYSV_HASH) += sysv_hash_layout.byte_size()?;
        self.sysv_hash_layout = Some(sysv_hash_layout);

        Ok(())
    }

    fn finalise_layout(
        mut self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resources: &FinaliseLayoutResources,
    ) -> Result<EpilogueLayout> {
        let dynsym_start_index = ((memory_offsets.get(part_id::DYNSYM)
            - resources
                .section_layouts
                .get(output_section_id::DYNSYM)
                .mem_offset)
            / elf::SYMTAB_ENTRY_SIZE)
            .try_into()
            .context("Too many dynamic symbols")?;

        if let Some(gnu_hash_layout) = self.gnu_hash_layout.as_mut() {
            gnu_hash_layout.symbol_base = dynsym_start_index;
        }

        if let Some(sysv_hash_layout) = self.sysv_hash_layout.as_mut() {
            let additional = u32::try_from(resources.dynamic_symbol_definitions.len())
                .context("Too many dynamic symbols for .hash")?;
            sysv_hash_layout.chain_count = dynsym_start_index
                .checked_add(additional)
                .context("Too many dynamic symbols for .hash")?;
        }

        if let Some(sysv_hash_layout) = &self.sysv_hash_layout {
            memory_offsets.increment(part_id::SYSV_HASH, sysv_hash_layout.byte_size()?);
        }

        memory_offsets.increment(
            part_id::DYNSYM,
            resources.dynamic_symbol_definitions.len() as u64 * elf::SYMTAB_ENTRY_SIZE,
        );

        memory_offsets.increment(
            part_id::NOTE_GNU_PROPERTY,
            crate::elf::gnu_property_notes_section_size(
                &resources.properties_and_attributes.gnu_property_notes,
            ),
        );

        memory_offsets.increment(
            part_id::RISCV_ATTRIBUTES,
            resources
                .properties_and_attributes
                .riscv_attributes
                .section_size,
        );

        if let Some(build_id_sec_size) = self.gnu_build_id_note_section_size() {
            memory_offsets.increment(part_id::NOTE_GNU_BUILD_ID, build_id_sec_size);
        }

        if let Some(verdefs) = &self.verdefs {
            memory_offsets.increment(
                part_id::GNU_VERSION_D,
                (size_of::<crate::elf::Verdef>() * verdefs.len()
                    + size_of::<crate::elf::Verdaux>()
                        * (verdefs.len()
                            + resources.symbol_db.version_script.parent_count() as usize))
                    as u64,
            );
        }

        Ok(EpilogueLayout {
            sysv_hash_layout: self.sysv_hash_layout,
            gnu_hash_layout: self.gnu_hash_layout,
            dynsym_start_index,
            verdefs: self.verdefs,
            riscv_attributes_length: resources
                .properties_and_attributes
                .riscv_attributes
                .section_size as u32,
        })
    }
}

#[derive(Debug)]
pub(crate) struct HeaderInfo {
    pub(crate) num_output_sections_with_content: u16,
    pub(crate) active_segment_ids: Vec<ProgramSegmentId>,
    pub(crate) eflags: crate::elf::Eflags,
}

impl HeaderInfo {
    pub(crate) fn program_headers_size(&self) -> u64 {
        u64::from(elf::PROGRAM_HEADER_SIZE) * self.active_segment_ids.len() as u64
    }

    pub(crate) fn section_headers_size(&self) -> u64 {
        u64::from(elf::SECTION_HEADER_SIZE) * u64::from(self.num_output_sections_with_content)
    }
}

/// Construct a new inactive instance, which means we don't yet load non-GC sections and only
/// load them later if a symbol from this object is referenced.
fn new_object_layout_state(input_state: resolution::ResolvedObject) -> FileLayoutState {
    // Note, this function is called for all objects from a single thread, so don't be tempted to do
    // significant work here. Do work when activate is called instead. Doing it there also means
    // that we don't do the work unless the object is actually needed.

    FileLayoutState::Object(ObjectLayoutState {
        file_id: input_state.common.file_id,
        symbol_id_range: input_state.common.symbol_id_range,
        input: input_state.common.input,
        object: input_state.common.object,
        eh_frame_section: None,
        eh_frame_size: 0,
        sections: input_state.sections,
        relocations: input_state.relocations,
        cies: Default::default(),
        format_specific_layout_state: Default::default(),
        exception_frames: Default::default(),
        section_relax_deltas: RelaxDeltaMap::new(),
    })
}

fn new_dynamic_object_layout_state<'data>(
    input_state: &resolution::ResolvedDynamic<'data>,
) -> FileLayoutState<'data> {
    FileLayoutState::Dynamic(DynamicLayoutState {
        file_id: input_state.common.file_id,
        symbol_id_range: input_state.common.symbol_id_range,
        lib_name: input_state.lib_name(),
        symbol_versions: input_state.common.object.versym,
        object: input_state.common.object,
        input: input_state.common.input,
        copy_relocations: Default::default(),

        // These fields are filled in properly when we activate.
        symbol_versions_needed: Default::default(),

        // These fields are filled in when we finalise sizes.
        verneed_info: None,
        non_addressable_indexes: Default::default(),
    })
}

impl<'data> ObjectLayoutState<'data> {
    #[inline(always)]
    fn activate<'scope, P: Platform<'data>>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        resources: &'scope GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result {
        let mut eh_frame_section = None;
        let mut note_gnu_property_section = None;
        let mut riscv_attributes_section = None;

        let no_gc = !resources.symbol_db.args.gc_sections;

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
                SectionSlot::EhFrameData(index) => {
                    eh_frame_section = Some(*index);
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

        if let Some(eh_frame_section_index) = eh_frame_section {
            process_eh_frame_data::<P>(
                self,
                common,
                self.symbol_id_range(),
                eh_frame_section_index,
                resources,
                queue,
                scope,
            )?;
            let eh_frame_section = self.object.section(eh_frame_section_index)?;
            self.eh_frame_section = Some(eh_frame_section);
        }

        if let Some(note_gnu_property_index) = note_gnu_property_section {
            process_gnu_property_note(self, note_gnu_property_index)?;
        }

        if let Some(riscv_attributes_index) = riscv_attributes_section {
            ensure!(
                P::elf_header_arch_magic() == object::elf::EM_RISCV,
                ".riscv.attribute section is supported only for riscv64 target"
            );
            self.format_specific_layout_state.riscv_attributes =
                crate::elf::process_riscv_attributes(self.object, riscv_attributes_index)
                    .context("Cannot parse .riscv.attributes section")?;
        }

        let export_all_dynamic = resources.symbol_db.output_kind == OutputKind::SharedObject
            && !(self.input.has_archive_semantics()
                && resources
                    .symbol_db
                    .args
                    .exclude_libs
                    .should_exclude(self.input.lib_name()))
            || resources.symbol_db.output_kind.needs_dynsym()
                && resources.symbol_db.args.export_all_dynamic_symbols;
        if export_all_dynamic
            || resources.symbol_db.output_kind.needs_dynsym()
                && resources.symbol_db.export_list.is_some()
        {
            self.load_non_hidden_symbols::<P>(common, resources, queue, export_all_dynamic, scope)?;
        }

        Ok(())
    }

    fn handle_section_load_request<'scope, P: Platform<'data>>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        resources: &'scope GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
        section_index: SectionIndex,
        scope: &Scope<'scope>,
    ) -> Result<(), Error> {
        match &self.sections[section_index.0] {
            SectionSlot::Unloaded(unloaded) | SectionSlot::MustLoad(unloaded) => {
                self.load_section::<P>(common, queue, *unloaded, section_index, resources, scope)?;
            }
            SectionSlot::UnloadedDebugInfo(part_id) => {
                // On RISC-V, the debug info sections contain relocations to local symbols (e.g.
                // labels).
                self.load_debug_section::<P>(
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
            | SectionSlot::EhFrameData(..)
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

    fn load_section<'scope, P: Platform<'data>>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        queue: &mut LocalWorkQueue,
        unloaded: UnloadedSection,
        section_index: SectionIndex,
        resources: &'scope GraphResources<'data, 'scope>,
        scope: &Scope<'scope>,
    ) -> Result {
        let part_id = unloaded.part_id;
        let header = self.object.section(section_index)?;
        let section = Section::create(header, self, section_index, part_id)?;

        match self.relocations(section.index)? {
            RelocationList::Rela(relocations) => {
                self.load_section_relocations::<P, Rela>(
                    common,
                    queue,
                    resources,
                    section,
                    relocations.rel_iter(),
                    scope,
                )?;
            }
            RelocationList::Crel(relocations) => {
                self.load_section_relocations::<P, Crel>(
                    common,
                    queue,
                    resources,
                    section,
                    relocations.flat_map(|r| r.ok()),
                    scope,
                )?;
            }
        }

        tracing::debug!(loaded_section = %self.object.section_display_name(section_index), file = %self.input);

        common.section_loaded(part_id, header, section);

        let section_id = section.output_section_id();

        if section.size > 0 {
            let sizes = match &self.exception_frames {
                ExceptionFrames::Rela(exception_frames) => self
                    .process_section_exception_frames::<P, Rela>(
                        unloaded.last_frame_index,
                        common,
                        resources,
                        queue,
                        scope,
                        exception_frames,
                    )?,
                ExceptionFrames::Crel(exception_frames) => self
                    .process_section_exception_frames::<P, Crel>(
                        unloaded.last_frame_index,
                        common,
                        resources,
                        queue,
                        scope,
                        exception_frames,
                    )?,
            };

            self.eh_frame_size += sizes.eh_frame_size;

            if resources.symbol_db.args.should_write_eh_frame_hdr {
                common.allocate(
                    part_id::EH_FRAME_HDR,
                    size_of::<EhFrameHdrEntry>() as u64 * sizes.num_frames,
                );
            }
        } else if section_id.marks_zero_sized_inputs_as_content() {
            resources.keep_section(section_id);
        }

        self.sections[section_index.0] = SectionSlot::Loaded(section);

        Ok(())
    }

    fn load_section_relocations<'scope, P: Platform<'data>, R: Relocation>(
        &self,
        common: &mut CommonGroupState<'data>,
        queue: &mut LocalWorkQueue,
        resources: &'scope GraphResources<'data, '_>,
        section: Section,
        relocations: impl Iterator<Item = R>,
        scope: &Scope<'scope>,
    ) -> Result {
        let mut modifier = RelocationModifier::Normal;
        for rel in relocations {
            if modifier == RelocationModifier::SkipNextRelocation {
                modifier = RelocationModifier::Normal;
                continue;
            }
            modifier = process_relocation::<P, R>(
                self,
                common,
                &rel,
                self.object.section(section.index)?,
                resources,
                queue,
                false,
                scope,
            )
            .with_context(|| {
                format!(
                    "Failed to copy section {} from file {self}",
                    section_debug(self.object, section.index)
                )
            })?;
        }

        Ok(())
    }

    /// Processes the exception frames for a section that we're loading.
    fn process_section_exception_frames<'scope, P: Platform<'data>, R: Relocation>(
        &self,
        frame_index: Option<FrameIndex>,
        common: &mut CommonGroupState<'data>,
        resources: &'scope GraphResources<'data, '_>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
        exception_frames: &[ExceptionFrame<'data, R>],
    ) -> Result<EhFrameSizes> {
        let mut num_frames = 0;
        let mut eh_frame_size = 0;
        let mut next_frame_index = frame_index;
        while let Some(frame_index) = next_frame_index {
            let frame_data = &exception_frames[frame_index.as_usize()];
            next_frame_index = frame_data.previous_frame_for_section;

            eh_frame_size += u64::from(frame_data.frame_size);

            num_frames += 1;

            // Request loading of any sections/symbols referenced by the FDEs for our
            // section.
            if let Some(eh_frame_section) = self.eh_frame_section {
                for rel in frame_data.relocations.rel_iter() {
                    process_relocation::<P, <R::Sequence<'data> as RelocationSequence>::Rel>(
                        self,
                        common,
                        &rel,
                        eh_frame_section,
                        resources,
                        queue,
                        false,
                        scope,
                    )?;
                }
                common.exception_frame_relocations += frame_data.relocations.num_relocations();
            }
        }

        Ok(EhFrameSizes {
            num_frames,
            eh_frame_size,
        })
    }

    fn load_debug_section<'scope, P: Platform<'data>>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        queue: &mut LocalWorkQueue,

        part_id: PartId,
        section_index: SectionIndex,
        resources: &'scope GraphResources<'data, '_>,
        scope: &Scope<'scope>,
    ) -> Result {
        let header = self.object.section(section_index)?;
        let section = Section::create(header, self, section_index, part_id)?;
        if P::local_symbols_in_debug_info() {
            match self.relocations(section.index)? {
                RelocationList::Rela(relocations) => self.load_debug_relocations::<P, Rela>(
                    common,
                    queue,
                    resources,
                    section,
                    relocations.rel_iter(),
                    scope,
                )?,
                RelocationList::Crel(relocations) => self.load_debug_relocations::<P, Crel>(
                    common,
                    queue,
                    resources,
                    section,
                    relocations.flat_map(|r| r.ok()),
                    scope,
                )?,
            }
        }

        tracing::debug!(loaded_debug_section = %self.object.section_display_name(section_index),);
        common.section_loaded(part_id, header, section);
        self.sections[section_index.0] = SectionSlot::LoadedDebugInfo(section);

        Ok(())
    }

    fn load_debug_relocations<'scope, P: Platform<'data>, R: Relocation>(
        &self,
        common: &mut CommonGroupState<'data>,
        queue: &mut LocalWorkQueue,
        resources: &'scope GraphResources<'data, '_>,
        section: Section,
        relocations: impl Iterator<Item = R>,
        scope: &Scope<'scope>,
    ) -> Result<(), Error> {
        for rel in relocations {
            let modifier = process_relocation::<P, R>(
                self,
                common,
                &rel,
                self.object.section(section.index)?,
                resources,
                queue,
                true,
                scope,
            )
            .with_context(|| {
                format!(
                    "Failed to copy section {} from file {self}",
                    section_debug(self.object, section.index)
                )
            })?;
            ensure!(
                modifier == RelocationModifier::Normal,
                "All debug relocations must be processed"
            );
        }

        Ok(())
    }

    fn finalise_sizes(
        &mut self,
        common: &mut CommonGroupState,
        output_sections: &OutputSections,
        per_symbol_flags: &AtomicPerSymbolFlags,
        resources: &FinaliseSizesResources<'data, '_>,
    ) {
        common.mem_sizes.resize(output_sections.num_parts());
        if !resources.symbol_db.args.strip_all() {
            self.allocate_symtab_space(common, resources.symbol_db, per_symbol_flags);
        }
        let output_kind = resources.symbol_db.output_kind;
        for slot in &mut self.sections {
            if let SectionSlot::Loaded(section) = slot {
                allocate_resolution(section.flags, &mut common.mem_sizes, output_kind);
            }
        }

        // TODO: Deduplicate CIEs from different objects, then only allocate space for those CIEs
        // that we "won".
        for cie in &self.cies {
            self.eh_frame_size += cie.cie.bytes.len() as u64;
        }
        common.allocate(part_id::EH_FRAME, self.eh_frame_size);
    }

    fn allocate_symtab_space(
        &self,
        common: &mut CommonGroupState,
        symbol_db: &SymbolDb<'data>,
        per_symbol_flags: &AtomicPerSymbolFlags,
    ) {
        let _file_span = symbol_db.args.trace_span_for_file(self.file_id());

        let mut num_locals = 0;
        let mut num_globals = 0;
        let mut strings_size = 0;
        for ((sym_index, sym), flags) in self
            .object
            .symbols
            .enumerate()
            .zip(per_symbol_flags.range(self.symbol_id_range()))
        {
            let symbol_id = self.symbol_id_range.input_to_id(sym_index);
            if let Some(info) = SymbolCopyInfo::new(
                self.object,
                sym_index,
                sym,
                symbol_id,
                symbol_db,
                flags.get(),
                &self.sections,
            ) {
                // If we've decided to emit the symbol even though it's not referenced (because it's
                // in a section we're emitting), then make sure we have a resolution for it.
                flags.fetch_or(ValueFlags::DIRECT);
                if is_symtab_local(sym, flags.get()) {
                    num_locals += 1;
                } else {
                    num_globals += 1;
                }
                let name = RawSymbolName::parse(info.name).name;
                strings_size += name.len() + 1;
            }
        }
        let entry_size = size_of::<elf::SymtabEntry>() as u64;
        common.allocate(part_id::SYMTAB_LOCAL, num_locals * entry_size);
        common.allocate(part_id::SYMTAB_GLOBAL, num_globals * entry_size);
        common.allocate(part_id::STRTAB, strings_size as u64);
    }

    fn finalise_layout(
        mut self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<'_, 'data>,
    ) -> Result<ObjectLayout<'data>> {
        let _file_span = resources.symbol_db.args.trace_span_for_file(self.file_id());
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
                    *memory_offsets.get_mut(part_id) += sec.capacity();
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
                    *memory_offsets.get_mut(sec.part_id) += sec.capacity();
                    SectionResolution { address }
                }
                SectionSlot::EhFrameData(..) => {
                    // References to symbols defined in .eh_frame are a bit weird, since it's a
                    // section where we're GCing stuff, but crtbegin.o and crtend.o use them in
                    // order to find the start and end of the whole .eh_frame section.
                    let address = *memory_offsets.get(part_id::EH_FRAME);
                    SectionResolution { address }
                }
                _ => SectionResolution::none(),
            };
            section_resolutions.push(resolution);
        }

        for ((local_symbol_index, local_symbol), &flags) in self
            .object
            .symbols
            .enumerate()
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

        memory_offsets.increment(part_id::EH_FRAME, self.eh_frame_size);

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
        resources: &FinaliseLayoutResources<'scope, 'data>,
        flags: ValueFlags,
        local_symbol: &object::elf::Sym64<LittleEndian>,
        local_symbol_index: object::SymbolIndex,
        section_resolutions: &[SectionResolution],
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
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
        resources: &FinaliseLayoutResources<'scope, 'data>,
        flags: ValueFlags,
        local_symbol: &object::elf::Sym64<LittleEndian>,
        local_symbol_index: object::SymbolIndex,
        section_resolutions: &[SectionResolution],
        memory_offsets: &mut OutputSectionPartMap<u64>,
    ) -> Result<Option<Resolution>> {
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
                match get_merged_string_output_address(
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
                            section_debug(self.object, section_index),
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
            let dyn_sym_index = take_dynsym_index(memory_offsets, resources.section_layouts)?;
            dynamic_symbol_index = Some(
                NonZeroU32::new(dyn_sym_index)
                    .context("Attempted to create dynamic symbol index 0")?,
            );
        }

        Ok(Some(create_resolution(
            flags,
            raw_value,
            dynamic_symbol_index,
            memory_offsets,
        )))
    }

    fn load_non_hidden_symbols<'scope, P: Platform<'data>>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        resources: &'scope GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
        export_all_dynamic: bool,
        scope: &Scope<'scope>,
    ) -> Result {
        for (sym_index, sym) in self.object.symbols.enumerate() {
            let symbol_id = self.symbol_id_range().input_to_id(sym_index);

            if !can_export_symbol(sym, symbol_id, resources, export_all_dynamic) {
                continue;
            }

            let old_flags = resources
                .per_symbol_flags
                .get_atomic(symbol_id)
                .fetch_or(ValueFlags::EXPORT_DYNAMIC);

            if !old_flags.has_resolution() {
                self.load_symbol::<P>(common, symbol_id, resources, queue, scope)?;
            }

            if !old_flags.needs_export_dynamic() {
                export_dynamic(common, symbol_id, resources.symbol_db)?;
            }
        }
        Ok(())
    }

    fn export_dynamic<'scope, P: Platform<'data>>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_id: SymbolId,
        resources: &'scope GraphResources<'data, 'scope>,
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
            self.load_symbol::<P>(common, symbol_id, resources, queue, scope)?;
        }

        if !old_flags.needs_export_dynamic() {
            export_dynamic(common, symbol_id, resources.symbol_db)?;
        }

        Ok(())
    }

    fn relocations(&self, index: SectionIndex) -> Result<RelocationList<'data>> {
        self.object.relocations(index, &self.relocations)
    }
}

/// Returns true if a symbol should be treated as local in the symbol table.
/// This includes both originally-local symbols and symbols downgraded by version scripts.
#[inline]
fn is_symtab_local(sym: &crate::elf::Symbol, flags: ValueFlags) -> bool {
    sym.is_local() || flags.is_downgraded_to_local()
}

pub(crate) struct SymbolCopyInfo<'data> {
    pub(crate) name: &'data [u8],
}

impl<'data> SymbolCopyInfo<'data> {
    /// The primary purpose of this function is to determine whether a symbol should be copied into
    /// the symtab. In the process, we also return the name of the symbol, to avoid needing to read
    /// it again.
    #[inline(always)]
    pub(crate) fn new(
        object: &crate::elf::File<'data>,
        sym_index: object::SymbolIndex,
        sym: &crate::elf::Symbol,
        symbol_id: SymbolId,
        symbol_db: &SymbolDb<'data>,
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

        if let Strip::Retain(retain) = &symbol_db.args.strip
            && !retain.contains(name)
        {
            return None;
        }

        Some(SymbolCopyInfo { name })
    }
}

/// Returns whether the supplied symbol can be exported when we're outputting a shared object.
fn can_export_symbol(
    sym: &crate::elf::SymtabEntry,
    symbol_id: SymbolId,
    resources: &GraphResources,
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

fn process_eh_frame_data<'data, 'scope, P: Platform<'data>>(
    object: &mut ObjectLayoutState<'data>,
    common: &mut CommonGroupState<'data>,
    file_symbol_id_range: SymbolIdRange,
    eh_frame_section_index: object::SectionIndex,
    resources: &'scope GraphResources<'data, '_>,
    queue: &mut LocalWorkQueue,
    scope: &Scope<'scope>,
) -> Result {
    let eh_frame_section = object.object.section(eh_frame_section_index)?;
    let data = object.object.raw_section_data(eh_frame_section)?;
    let exception_frames = match object.relocations(eh_frame_section_index)? {
        RelocationList::Rela(relocations) => {
            ExceptionFrames::Rela(process_eh_frame_relocations::<P, Rela>(
                object,
                common,
                file_symbol_id_range,
                resources,
                queue,
                eh_frame_section,
                data,
                &relocations,
                scope,
            )?)
        }
        RelocationList::Crel(crel_iterator) => {
            ExceptionFrames::Crel(process_eh_frame_relocations::<P, Crel>(
                object,
                common,
                file_symbol_id_range,
                resources,
                queue,
                eh_frame_section,
                data,
                &crel_iterator.collect::<Result<Vec<Crel>, _>>()?,
                scope,
            )?)
        }
    };

    object.exception_frames = exception_frames;

    Ok(())
}

fn process_eh_frame_relocations<'data, 'scope, P: Platform<'data>, R: Relocation>(
    object: &mut ObjectLayoutState<'data>,
    common: &mut CommonGroupState<'data>,
    file_symbol_id_range: SymbolIdRange,
    resources: &'scope GraphResources<'data, '_>,
    queue: &mut LocalWorkQueue,
    eh_frame_section: &'data object::elf::SectionHeader64<LittleEndian>,
    data: &'data [u8],
    relocations: &R::Sequence<'data>,
    scope: &Scope<'scope>,
) -> Result<Vec<ExceptionFrame<'data, R>>> {
    const PREFIX_LEN: usize = size_of::<elf::EhFrameEntryPrefix>();

    let mut rel_iter = relocations.rel_iter().enumerate().peekable();
    let mut offset = 0;
    let mut exception_frames = Vec::new();

    while offset + PREFIX_LEN <= data.len() {
        // Although the section data will be aligned within the object file, there's
        // no guarantee that the object is aligned within the archive to any more
        // than 2 bytes, so we can't rely on alignment here. Archives are annoying!
        // See https://www.airs.com/blog/archives/170
        let prefix =
            elf::EhFrameEntryPrefix::read_from_bytes(&data[offset..offset + PREFIX_LEN]).unwrap();
        let size = size_of_val(&prefix.length) + prefix.length as usize;
        let next_offset = offset + size;

        if next_offset > data.len() {
            bail!("Invalid .eh_frame data");
        }

        if prefix.cie_id == 0 {
            // This is a CIE
            let mut referenced_symbols: SmallVec<[SymbolId; 1]> = Default::default();
            // When deduplicating CIEs, we take into consideration the bytes of the CIE and all the
            // symbols it references. If however, it references something other than a symbol, then,
            // because we're not taking that into consideration, we disallow deduplication.
            let mut eligible_for_deduplication = true;
            while let Some((_, rel)) = rel_iter.peek() {
                let rel_offset = rel.offset();
                if rel_offset >= next_offset as u64 {
                    // This relocation belongs to the next entry.
                    break;
                }

                // We currently always load all CIEs, so any relocations found in CIEs always need
                // to be processed.
                process_relocation::<P, <R::Sequence<'data> as RelocationSequence>::Rel>(
                    object,
                    common,
                    rel,
                    eh_frame_section,
                    resources,
                    queue,
                    false,
                    scope,
                )?;

                if let Some(local_sym_index) = rel.symbol() {
                    let local_symbol_id = file_symbol_id_range.input_to_id(local_sym_index);
                    let definition = resources.symbol_db.definition(local_symbol_id);
                    referenced_symbols.push(definition);
                } else {
                    eligible_for_deduplication = false;
                }
                rel_iter.next();
            }

            object.cies.push(CieAtOffset {
                offset: offset as u32,
                cie: Cie {
                    bytes: &data[offset..next_offset],
                    eligible_for_deduplication,
                    referenced_symbols,
                },
            });
        } else {
            // This is an FDE
            let mut section_index = None;
            let rel_start_index = rel_iter.peek().map_or(0, |(i, _)| *i);
            let mut rel_end_index = 0;

            while let Some((rel_index, rel)) = rel_iter.peek() {
                let rel_offset = rel.offset();
                if rel_offset < next_offset as u64 {
                    let is_pc_begin = (rel_offset as usize - offset) == elf::FDE_PC_BEGIN_OFFSET;

                    if is_pc_begin && let Some(index) = rel.symbol() {
                        let elf_symbol = object.object.symbol(index)?;
                        section_index = object.object.symbol_section(elf_symbol, index)?;
                    }
                    rel_end_index = rel_index + 1;
                    rel_iter.next();
                } else {
                    break;
                }
            }

            if let Some(section_index) = section_index
                && let Some(unloaded) = object.sections[section_index.0].unloaded_mut()
            {
                let frame_index = FrameIndex::from_usize(exception_frames.len());

                // Update our unloaded section to point to our new frame. Our frame will then in
                // turn point to whatever the section pointed to before.
                let previous_frame_for_section = unloaded.last_frame_index.replace(frame_index);

                exception_frames.push(ExceptionFrame {
                    relocations: relocations.subsequence(rel_start_index..rel_end_index),
                    frame_size: size as u32,
                    previous_frame_for_section,
                });
            }
        }
        offset = next_offset;
    }

    common.exception_frame_count += object.exception_frames.len();

    // Allocate space for any remaining bytes in .eh_frame that aren't large enough to constitute an
    // actual entry. crtend.o has a single u32 equal to 0 as an end marker.
    object.eh_frame_size += (data.len() - offset) as u64;

    Ok(exception_frames)
}

fn process_gnu_property_note(
    object: &mut ObjectLayoutState,
    note_section_index: object::SectionIndex,
) -> Result {
    let section = object.object.section(note_section_index)?;
    let e = LittleEndian;

    let Some(notes) = object::read::elf::SectionHeader::notes(section, e, object.object.data)?
    else {
        return Ok(());
    };

    for note in notes {
        for gnu_property in note?
            .gnu_properties(e)
            .ok_or(error!("Invalid type of .note.gnu.property"))?
        {
            let gnu_property = gnu_property?;

            // Right now, skip all properties other than those with size equal to 4.
            // There are existing properties, but unused right now:
            // GNU_PROPERTY_STACK_SIZE, GNU_PROPERTY_NO_COPY_ON_PROTECTED
            // TODO: support in the future
            if gnu_property.pr_data().len() != 4 {
                continue;
            }
            object
                .format_specific_layout_state
                .gnu_property_notes
                .push(crate::elf::GnuProperty {
                    ptype: gnu_property.pr_type(),
                    data: gnu_property.data_u32(e)?,
                });
        }
    }

    Ok(())
}

/// A "common information entry". This is part of the .eh_frame data in ELF.
#[derive(PartialEq, Eq, Hash)]
struct Cie<'data> {
    bytes: &'data [u8],
    eligible_for_deduplication: bool,
    referenced_symbols: SmallVec<[SymbolId; 1]>,
}

struct CieAtOffset<'data> {
    // TODO: Use or remove. I think we need this when we implement deduplication of CIEs.
    /// Offset within .eh_frame
    #[allow(dead_code)]
    offset: u32,
    cie: Cie<'data>,
}

struct ResolutionWriter<'writer, 'out> {
    resolutions_out: &'writer mut sharded_vec_writer::Shard<'out, Option<Resolution>>,
}

impl ResolutionWriter<'_, '_> {
    fn write(&mut self, res: Option<Resolution>) -> Result {
        self.resolutions_out.try_push(res)?;
        Ok(())
    }
}

#[inline(always)]
fn create_resolution(
    flags: ValueFlags,
    raw_value: u64,
    dynamic_symbol_index: Option<NonZeroU32>,
    memory_offsets: &mut OutputSectionPartMap<u64>,
) -> Resolution {
    let mut resolution = Resolution {
        raw_value,
        dynamic_symbol_index,
        got_address: None,
        plt_address: None,
        flags,
    };
    if flags.needs_plt() {
        let plt_address = allocate_plt(memory_offsets);
        resolution.plt_address = Some(plt_address);
        if flags.is_dynamic() {
            resolution.raw_value = plt_address.get();
        }
        // For ifunc with address equality needs, allocate 2 GOT entries
        // - First entry: Used by PLT
        // - Second entry: Used by GOT-relative references
        let num_got_entries = if flags.needs_ifunc_got_for_address() {
            2
        } else {
            1
        };
        resolution.got_address = Some(allocate_got(num_got_entries, memory_offsets));
    } else if flags.is_tls() {
        // Handle the TLS GOT addresses where we can combine up to 3 different access methods.
        let mut num_got_slots = 0;
        if flags.needs_got_tls_offset() {
            num_got_slots += 1;
        }
        if flags.needs_got_tls_module() {
            num_got_slots += 2;
        }
        if flags.needs_got_tls_descriptor() {
            num_got_slots += 2;
        }
        debug_assert!(num_got_slots > 0);
        resolution.got_address = Some(allocate_got(num_got_slots, memory_offsets));
    } else if flags.needs_got() {
        resolution.got_address = Some(allocate_got(1, memory_offsets));
    }
    resolution
}

fn allocate_got(num_entries: u64, memory_offsets: &mut OutputSectionPartMap<u64>) -> NonZeroU64 {
    let got_address = NonZeroU64::new(*memory_offsets.get(part_id::GOT)).unwrap();
    memory_offsets.increment(part_id::GOT, elf::GOT_ENTRY_SIZE * num_entries);
    got_address
}

fn allocate_plt(memory_offsets: &mut OutputSectionPartMap<u64>) -> NonZeroU64 {
    let plt_address = NonZeroU64::new(*memory_offsets.get(part_id::PLT_GOT)).unwrap();
    memory_offsets.increment(part_id::PLT_GOT, elf::PLT_ENTRY_SIZE);
    plt_address
}

impl<'data> resolution::ResolvedFile<'data> {
    fn create_layout_state(self) -> FileLayoutState<'data> {
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

impl Resolution {
    pub(crate) fn got_address(&self) -> Result<u64> {
        Ok(self.got_address.context("Missing GOT address")?.get())
    }

    pub(crate) fn got_address_for_relocation(&self) -> Result<u64> {
        let mut got_address = self.got_address()?;
        if self.flags.needs_ifunc_got_for_address() {
            got_address += elf::GOT_ENTRY_SIZE;
        }
        Ok(got_address)
    }

    pub(crate) fn tlsgd_got_address(&self) -> Result<u64> {
        debug_assert_bail!(
            self.flags.needs_got_tls_module(),
            "Called tlsgd_got_address without GOT_TLS_MODULE being set"
        );
        // If we've got both a GOT_TLS_OFFSET and a GOT_TLS_MODULE, then the latter comes second.
        let mut got_address = self.got_address()?;
        if self.flags.needs_got_tls_offset() {
            got_address += elf::GOT_ENTRY_SIZE;
        }
        Ok(got_address)
    }

    pub(crate) fn tls_descriptor_got_address(&self) -> Result<u64> {
        debug_assert_bail!(
            self.flags.needs_got_tls_descriptor(),
            "Called tls_descriptor_got_address without GOT_TLS_DESCRIPTOR being set"
        );
        // We might have both GOT_TLS_OFFSET, GOT_TLS_MODULE and GOT_TLS_DESCRIPTOR at the same time
        // for a single symbol. Then the TLS descriptor comes as the last one.
        let mut got_address = self.got_address()?;
        if self.flags.needs_got_tls_offset() {
            got_address += elf::GOT_ENTRY_SIZE;
        }
        if self.flags.needs_got_tls_module() {
            got_address += 2 * elf::GOT_ENTRY_SIZE;
        }

        Ok(got_address)
    }

    pub(crate) fn plt_address(&self) -> Result<u64> {
        Ok(self.plt_address.context("Missing PLT address")?.get())
    }

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

    #[inline(always)]
    pub(crate) fn value_with_addend(
        &self,
        addend: i64,
        symbol_index: object::SymbolIndex,
        object_layout: &ObjectLayout,
        merged_strings: &OutputSectionMap<MergedStringsSection>,
        merged_string_start_addresses: &MergedStringStartAddresses,
    ) -> Result<u64> {
        if self.flags.is_ifunc() {
            return Ok(self.plt_address()?.wrapping_add(addend as u64));
        }

        // For most symbols, `raw_value` won't be zero, so we can save ourselves from looking up the
        // section to see if it's a string-merge section. For string-merge symbols with names,
        // `raw_value` will have already been computed, so we can avoid computing it again.
        if self.raw_value == 0
            && let Some(r) = get_merged_string_output_address(
                symbol_index,
                addend,
                object_layout.object,
                &object_layout.sections,
                merged_strings,
                merged_string_start_addresses,
                false,
            )?
        {
            if self.raw_value != 0 {
                bail!("Merged string resolution has value 0x{}", self.raw_value);
            }
            return Ok(r);
        }
        Ok(self.raw_value.wrapping_add(addend as u64))
    }
}

/// Maximum number of relaxation scan iterations. In practice convergence
/// happens in 2–3 passes.
const MAX_RELAXATION_ITERATIONS: usize = 5;

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
        if addr == 0 {
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

/// Compute the output address of every loaded input section across all object files.
fn compute_object_section_addresses(
    group_states: &[GroupState],
    section_part_layouts: &OutputSectionPartMap<OutputRecordLayout>,
) -> Vec<Vec<Vec<u64>>> {
    let mem_offsets: OutputSectionPartMap<u64> = starting_memory_offsets(section_part_layouts);
    let starting_offsets = compute_start_offsets_by_group(group_states, mem_offsets);

    group_states
        .iter()
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
                                    *offsets.get_mut(sec.part_id) += sec.capacity();
                                }
                                SectionSlot::LoadedDebugInfo(sec) => {
                                    // Advance offsets so subsequent sections are placed
                                    // correctly, but we don't need the address for relaxation.
                                    *offsets.get_mut(sec.part_id) += sec.capacity();
                                }
                                _ => {}
                            }
                        }
                        offsets.increment(part_id::EH_FRAME, obj.eh_frame_size);
                        addresses
                    }
                    _ => vec![],
                })
                .collect()
        })
        .collect()
}

fn build_symbol_output_infos(
    group_states: &[GroupState],
    section_addresses: &[Vec<Vec<u64>>],
    symbol_db: &SymbolDb,
) -> SymbolOutputInfos {
    let mut addresses = vec![0u64; symbol_db.num_symbols()];

    for (group_idx, group) in group_states.iter().enumerate() {
        for (file_idx, file) in group.files.iter().enumerate() {
            let FileLayoutState::Object(obj) = file else {
                continue;
            };
            let file_section_addrs = &section_addresses[group_idx][file_idx];

            for sym_offset in 0..obj.symbol_id_range.len() {
                let sym_input_idx = object::SymbolIndex(sym_offset);
                let Ok(sym) = obj.object.symbol(sym_input_idx) else {
                    continue;
                };
                let Ok(Some(section)) = obj.object.symbol_section(sym, sym_input_idx) else {
                    continue;
                };
                let sym_id = obj.symbol_id_range.input_to_id(sym_input_idx);
                let def_id = symbol_db.definition(sym_id);
                // Only record the address for the canonical definition.
                if def_id != sym_id {
                    continue;
                }
                let sec_addr = file_section_addrs.get(section.0).copied().unwrap_or(0);
                if sec_addr == 0 {
                    continue;
                }
                addresses[sym_id.as_usize()] = sec_addr + sym.value();
            }
        }
    }

    SymbolOutputInfos { addresses }
}

/// Run one pass of the relaxation scan across all groups/objects. Returns the total number of bytes
/// newly deleted in this pass.
fn relaxation_scan_pass(
    group_states: &mut [GroupState],
    section_part_layouts: &OutputSectionPartMap<OutputRecordLayout>,
    symbol_db: &SymbolDb,
    per_symbol_flags: &PerSymbolFlags,
    section_part_sizes: &mut OutputSectionPartMap<u64>,
) -> u64 {
    timing_phase!("Relaxation scan pass");

    let arch = symbol_db.args.arch;

    // Compute per-section output addresses from the current layout.
    let section_addresses = compute_object_section_addresses(group_states, section_part_layouts);

    // Build a flat symbol to output-address table.
    let symbol_infos = build_symbol_output_infos(group_states, &section_addresses, symbol_db);

    // Scan each group.
    let group_reductions: Vec<OutputSectionPartMap<u64>> = group_states
        .par_iter_mut()
        .enumerate()
        .map(|(group_idx, group)| {
            let mut reductions = OutputSectionPartMap::with_size(section_part_sizes.num_parts());

            for (file_idx, file) in group.files.iter_mut().enumerate() {
                let FileLayoutState::Object(obj) = file else {
                    continue;
                };

                let file_section_addrs = &section_addresses[group_idx][file_idx];

                let exec_sections: SmallVec<[usize; 16]> = obj
                    .sections
                    .iter()
                    .enumerate()
                    .filter_map(|(i, slot)| {
                        if let SectionSlot::Loaded(_) = slot
                            && let Ok(header) = obj.object.section(SectionIndex(i))
                            && SectionFlags::from_header(header).contains(shf::EXECINSTR)
                        {
                            Some(i)
                        } else {
                            None
                        }
                    })
                    .collect();

                for sec_idx in exec_sections {
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

                    let raw_deltas = match arch {
                        Architecture::RISCV64 => match relocs {
                            RelocationList::Rela(rela_list) => {
                                elf_riscv64::collect_relaxation_deltas(
                                    sec_output_addr,
                                    rela_list.rel_iter(),
                                    existing_deltas,
                                    &mut resolve_symbol,
                                )
                            }
                            RelocationList::Crel(crel_iter) => {
                                elf_riscv64::collect_relaxation_deltas(
                                    sec_output_addr,
                                    crel_iter.flatten(),
                                    existing_deltas,
                                    &mut resolve_symbol,
                                )
                            }
                        },
                        _ => continue,
                    };

                    if raw_deltas.is_empty() {
                        continue;
                    }

                    let new_total_deleted: u64 =
                        raw_deltas.iter().map(|(_, b)| u64::from(*b)).sum();

                    if let SectionSlot::Loaded(sec) = &mut obj.sections[sec_idx] {
                        let old_capacity = sec.capacity();
                        sec.size -= new_total_deleted;
                        let new_capacity = sec.capacity();
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
            }

            reductions
        })
        .collect();

    // Aggregate the per-group reductions into section_part_sizes and compute the total bytes
    // deleted.
    let mut total_deleted = 0u64;
    for reduction in &group_reductions {
        for (idx, &amount) in reduction.parts.iter().enumerate() {
            if amount > 0 {
                let part_id = PartId::from_usize(idx);
                section_part_sizes.decrement(part_id, amount);
                total_deleted += amount;
            }
        }
    }

    total_deleted
}

fn perform_iterative_relaxation(
    group_states: &mut [GroupState],
    section_part_sizes: &mut OutputSectionPartMap<u64>,
    section_part_layouts: &mut OutputSectionPartMap<OutputRecordLayout>,
    output_sections: &OutputSections,
    program_segments: &ProgramSegments,
    output_order: &OutputOrder,
    symbol_db: &SymbolDb,
    per_symbol_flags: &PerSymbolFlags,
) {
    timing_phase!("Iterative relaxation");

    for _iteration in 0..MAX_RELAXATION_ITERATIONS {
        let deleted = relaxation_scan_pass(
            group_states,
            section_part_layouts,
            symbol_db,
            per_symbol_flags,
            section_part_sizes,
        );

        if deleted == 0 {
            break;
        }

        *section_part_layouts = layout_section_parts(
            section_part_sizes,
            output_sections,
            program_segments,
            output_order,
            symbol_db.args,
        );
    }
}

fn layout_section_parts(
    sizes: &OutputSectionPartMap<u64>,
    output_sections: &OutputSections,
    program_segments: &ProgramSegments,
    output_order: &OutputOrder,
    args: &Args,
) -> OutputSectionPartMap<OutputRecordLayout> {
    let segment_alignments =
        compute_segment_alignments(sizes, program_segments, output_order, args);

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
                let max_alignment = sizes.max_alignment(part_id_range.clone());
                if let Some(location) = section_info.location {
                    mem_offset = location.address;
                }

                records_out[part_id_range.clone()]
                    .iter_mut()
                    .zip(&sizes[part_id_range.clone()])
                    .enumerate()
                    .for_each(|(offset, (part_layout, &part_size))| {
                        let part_id = part_id_range.start.offset(offset);
                        let alignment = part_id.alignment().min(max_alignment);
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

                        if section_flags.contains(shf::ALLOC) {
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
fn compute_segment_alignments(
    sizes: &OutputSectionPartMap<u64>,
    program_segments: &ProgramSegments,
    output_order: &OutputOrder,
    args: &Args,
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
                let max_alignment = sizes.max_alignment(part_id_range);

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

impl<'data> DynamicLayoutState<'data> {
    fn activate<'scope, P: Platform<'data>>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        resources: &'scope GraphResources<'data, '_>,
        queue: &mut LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result {
        self.symbol_versions_needed = vec![false; self.object.verdefnum as usize];

        common.allocate(
            part_id::DYNAMIC,
            size_of::<crate::elf::DynamicEntry>() as u64,
        );

        common.allocate(part_id::DYNSTR, self.lib_name.len() as u64 + 1);

        self.request_all_undefined_symbols::<P>(resources, queue, scope)
    }

    fn request_all_undefined_symbols<'scope, P: Platform<'data>>(
        &self,
        resources: &'scope GraphResources<'data, '_>,
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
                let check_undefined = *check_undefined_cache.get_or_insert_with(|| {
                    let is_executable = resources.symbol_db.output_kind.is_executable();
                    !args.allow_shlib_undefined
                        && is_executable
                        // Like lld, our behaviour for --no-allow-shlib-undefined is to only report
                        // errors for shared objects that have all their dependencies in the link.
                        // This is in contrast to GNU ld which recursively loads all transitive
                        // dependencies of shared objects and checks our shared object against
                        // those.
                        && self.has_complete_deps(resources)
                });

                if check_undefined {
                    let symbol = self
                        .object
                        .symbol(self.symbol_id_range.id_to_input(symbol_id))?;
                    if !symbol.is_weak() {
                        let should_report = !matches!(
                            args.unresolved_symbols,
                            crate::args::UnresolvedSymbols::IgnoreAll
                                | crate::args::UnresolvedSymbols::IgnoreInSharedLibs
                        );

                        if should_report {
                            let symbol_name =
                                resources.symbol_db.symbol_name_for_display(symbol_id);

                            if args.error_unresolved_symbols {
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

                queue.send_work::<P>(
                    resources,
                    file_id,
                    WorkItem::ExportDynamic(definition_symbol_id),
                    scope,
                );
            }
        }

        Ok(())
    }

    fn finalise_copy_relocations(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_db: &SymbolDb<'data>,
        per_symbol_flags: &AtomicPerSymbolFlags,
    ) -> Result {
        // Skip iterating over our symbol table if we don't have any copy relocations.
        if self.copy_relocations.is_empty() {
            return Ok(());
        }

        self.select_copy_relocation_alternatives(per_symbol_flags, common, symbol_db)
    }

    fn finalise_sizes(&mut self, common: &mut CommonGroupState<'data>) -> Result {
        self.allocate_for_copy_relocations(common)?;
        self.allocate_for_versions(common)
    }

    fn allocate_for_versions(&mut self, common: &mut CommonGroupState<'data>) -> Result {
        let e = LittleEndian;
        let mut version_count = 0;

        if let Some((mut verdef_iterator, link)) = self.object.verdef.clone() {
            let defs = verdef_iterator.clone();

            let strings = self.object.sections.strings(e, self.object.data, link)?;
            let mut base_size = 0;
            while let Some((verdef, mut aux_iterator)) = verdef_iterator.next()? {
                let version_index = verdef.vd_ndx.get(e);

                if version_index == 0 {
                    bail!("Invalid version index");
                }

                let flags = verdef.vd_flags.get(e);
                let is_base = (flags & object::elf::VER_FLG_BASE) != 0;

                // Keep the base version and any versions that are referenced.
                let needed = is_base
                    || *self
                        .symbol_versions_needed
                        .get(usize::from(version_index - 1))
                        .context("Invalid version index")?;

                if needed {
                    // For the base version, we use the lib_name rather than the version name from
                    // the input file. This matches what GNU ld appears to do. Also, if we don't do
                    // this, then the C runtime hits an assertion failure, because it expects to be
                    // able to find a DT_NEEDED entry that matches the base name of a version.
                    let name = if is_base {
                        self.lib_name
                    } else {
                        // Every VERDEF entry should have at least one AUX entry.
                        let aux = aux_iterator.next()?.context("VERDEF with no AUX entry")?;
                        aux.name(e, strings)?
                    };

                    let name_size = name.len() as u64 + 1;

                    if is_base {
                        // The base version doesn't count as a version, so we don't increment
                        // version_count here. We emit it as a Verneed, whereas the actual versions
                        // are emitted as Vernaux.
                        base_size = name_size;
                    } else {
                        common.allocate(part_id::DYNSTR, name_size);
                        version_count += 1;
                    }
                }
            }

            if version_count > 0 {
                common.allocate(part_id::DYNSTR, base_size);
                common.allocate(
                    part_id::GNU_VERSION_R,
                    size_of::<crate::elf::Verneed>() as u64
                        + u64::from(version_count) * size_of::<crate::elf::Vernaux>() as u64,
                );

                self.verneed_info = Some(VerneedInfo {
                    defs,
                    string_table_index: link,
                    version_count,
                });
            }
        }

        Ok(())
    }

    /// Looks for any non-weak symbols at the same addresses as any of our copy relocations. If
    /// found, we'll generate the copy relocation for the strong symbol instead of weak symbol at
    /// the same address.
    fn select_copy_relocation_alternatives(
        &mut self,
        per_symbol_flags: &AtomicPerSymbolFlags,
        common: &mut CommonGroupState<'data>,
        symbol_db: &SymbolDb<'data>,
    ) -> Result {
        for (i, symbol) in self.object.symbols.iter().enumerate() {
            let address = symbol.value();
            let Some(info) = self.copy_relocations.get_mut(&address) else {
                continue;
            };

            let symbol_id = self.symbol_id_range.offset_to_id(i);

            if !symbol_db.is_canonical(symbol_id) {
                continue;
            }

            export_dynamic(common, symbol_id, symbol_db)?;

            per_symbol_flags
                .get_atomic(symbol_id)
                .fetch_or(ValueFlags::COPY_RELOCATION);

            if symbol.is_weak() || !info.is_weak || info.symbol_id == symbol_id {
                continue;
            }

            info.symbol_id = symbol_id;
            info.is_weak = false;
        }

        Ok(())
    }

    fn allocate_for_copy_relocations(&self, common: &mut CommonGroupState<'data>) -> Result {
        for value in self.copy_relocations.values() {
            let symbol_id = value.symbol_id;

            let symbol = self
                .object
                .symbol(self.symbol_id_range().id_to_input(symbol_id))?;

            let section_index = symbol.section_index();

            let section = self.object.section(section_index)?;

            let alignment = Alignment::new(self.object.section_alignment(section)?)?;

            // Allocate space in BSS for the copy of the symbol.
            let size = symbol.size();
            common.allocate(
                output_section_id::BSS.part_id_with_alignment(alignment),
                alignment.align_up(size),
            );

            // Allocate space required for the copy relocation itself.
            common.allocate(part_id::RELA_DYN_GENERAL, crate::elf::RELA_ENTRY_SIZE);
        }

        Ok(())
    }

    fn apply_non_addressable_indexes(
        &mut self,
        indexes: &mut NonAddressableIndexes,
        counts: &mut NonAddressableCounts,
    ) -> Result {
        self.non_addressable_indexes = *indexes;
        if let Some(info) = self.verneed_info.as_ref()
            && info.version_count > 0
        {
            counts.verneed_count += 1;
            indexes.gnu_version_r_index = indexes
                .gnu_version_r_index
                .checked_add(info.version_count)
                .context("Symbol versions overflowed 2**16")?;
        }
        Ok(())
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<'_, 'data>,
    ) -> Result<DynamicLayout<'data>> {
        let version_mapping = self.compute_version_mapping();

        let copy_relocation_symbols = self
            .copy_relocations
            .values()
            .map(|info| info.symbol_id)
            // We'll write the copy relocations in this order, so we need to sort it to ensure
            // deterministic output.
            .sorted()
            .collect_vec();

        let copy_relocation_addresses =
            self.assign_copy_relocation_addresses(&copy_relocation_symbols, memory_offsets)?;

        for (local_symbol, &flags) in self
            .object
            .symbols
            .iter()
            .zip(resources.per_symbol_flags.raw_range(self.symbol_id_range()))
        {
            let flags = flags.get();

            if !flags.has_resolution() {
                resolutions_out.write(None)?;
                continue;
            }

            let address;
            let dynamic_symbol_index;

            if flags.needs_copy_relocation() {
                let input_address = local_symbol.value();

                address = *copy_relocation_addresses
                    .get(&input_address)
                    .context("Internal error: Missing copy relocation address")?;

                // Since this is a definition, the dynamic symbol index will be determined by the
                // epilogue and set by `update_dynamic_symbol_resolutions`.
                dynamic_symbol_index = None;
            } else {
                address = 0;
                let symbol_index = take_dynsym_index(memory_offsets, resources.section_layouts)?;

                dynamic_symbol_index = Some(
                    NonZeroU32::new(symbol_index)
                        .context("Tried to create dynamic symbol index 0")?,
                );
            }

            let resolution =
                create_resolution(flags, address, dynamic_symbol_index, memory_offsets);

            resolutions_out.write(Some(resolution))?;
        }

        if let Some(v) = self.verneed_info.as_ref() {
            memory_offsets.increment(
                part_id::GNU_VERSION_R,
                size_of::<crate::elf::Verneed>() as u64
                    + u64::from(v.version_count) * size_of::<crate::elf::Vernaux>() as u64,
            );
        }

        Ok(DynamicLayout {
            file_id: self.file_id(),
            input: self.input,
            lib_name: self.lib_name,
            object: self.object,
            symbol_id_range: self.symbol_id_range,
            input_symbol_versions: self.symbol_versions,
            copy_relocation_symbols,
            version_mapping,
            verneed_info: self.verneed_info,
            // We set this to true later for one object.
            is_last_verneed: false,
        })
    }

    /// Computes a mapping from input versions to output versions.
    fn compute_version_mapping(&self) -> Vec<u16> {
        let mut out = vec![object::elf::VER_NDX_GLOBAL; self.symbol_versions_needed.len()];
        let mut next_output_version = self.non_addressable_indexes.gnu_version_r_index;
        for (input_version, needed) in self.symbol_versions_needed.iter().enumerate() {
            if *needed {
                out[input_version] = next_output_version;
                next_output_version += 1;
            }
        }
        out
    }

    fn copy_relocate_symbol<'scope>(
        &mut self,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope>,
    ) -> std::result::Result<(), Error> {
        let symbol = self
            .object
            .symbol(self.symbol_id_range().id_to_input(symbol_id))?;

        // Note, we're a shared object, so this is the address relative to the load address of the
        // shared object, not an offset within a section like with regular input objects. That means
        // that we don't need to take the section into account.
        let address = symbol.value();

        let info = self
            .copy_relocations
            .entry(address)
            .or_insert_with(|| CopyRelocationInfo {
                symbol_id,
                is_weak: symbol.is_weak(),
            });

        info.add_symbol(symbol_id, symbol.is_weak(), resources);

        Ok(())
    }

    fn assign_copy_relocation_addresses(
        &self,
        copy_relocation_symbols: &[SymbolId],
        memory_offsets: &mut OutputSectionPartMap<u64>,
    ) -> Result<HashMap<u64, u64>> {
        copy_relocation_symbols
            .iter()
            .map(|symbol_id| {
                let symbol = self
                    .object
                    .symbol(self.symbol_id_range.id_to_input(*symbol_id))?;

                let input_address = symbol.value();

                let output_address =
                    assign_copy_relocation_address(self.object, symbol, memory_offsets)?;

                Ok((input_address, output_address))
            })
            .try_collect()
    }

    /// Return whether all DT_NEEDED entries for this shared object correspond to input files that
    /// we have loaded.
    fn has_complete_deps(&self, resources: &GraphResources) -> bool {
        let Ok(dynamic_tags) = self.object.dynamic_tags() else {
            return true;
        };

        let e = LittleEndian;
        for entry in dynamic_tags {
            let value = entry.d_val(e);
            match entry.d_tag(e) as u32 {
                object::elf::DT_NEEDED => {
                    let Ok(name) = self.object.symbols.strings().get(value as u32) else {
                        return false;
                    };
                    if !resources.sonames.contains(name) {
                        return false;
                    }
                }
                _ => {}
            }
        }

        true
    }
}

impl<'data> LinkerScriptLayoutState<'data> {
    fn finalise_layout(
        &self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<'_, 'data>,
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

    fn activate(
        &self,
        common: &mut CommonGroupState<'data>,
        resources: &GraphResources<'data, '_>,
    ) -> Result {
        for (offset, def_info) in self.internal_symbols.symbol_definitions.iter().enumerate() {
            let symbol_id = self.symbol_id_range.offset_to_id(offset);
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

    fn finalise_sizes(
        &self,
        common: &mut CommonGroupState<'data>,
        per_symbol_flags: &AtomicPerSymbolFlags,
        resources: &FinaliseSizesResources,
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

impl CopyRelocationInfo {
    fn add_symbol(&mut self, symbol_id: SymbolId, is_weak: bool, resources: &GraphResources) {
        if self.symbol_id == symbol_id || is_weak {
            return;
        }

        if !self.is_weak {
            warning(&format!(
                "Multiple non-weak symbols at the same address have copy relocations: {}, {}",
                resources.symbol_debug(self.symbol_id),
                resources.symbol_debug(symbol_id)
            ));
        }

        self.symbol_id = symbol_id;
        self.is_weak = false;
    }
}

/// Assigns the address in BSS for the copy relocation of a symbol.
fn assign_copy_relocation_address(
    file: &File,
    local_symbol: &object::elf::Sym64<LittleEndian>,
    memory_offsets: &mut OutputSectionPartMap<u64>,
) -> Result<u64, Error> {
    let section_index = local_symbol.section_index();
    let section = file.section(section_index)?;
    let alignment = Alignment::new(file.section_alignment(section)?)?;
    let bss = memory_offsets.get_mut(output_section_id::BSS.part_id_with_alignment(alignment));
    let a = *bss;
    *bss += alignment.align_up(local_symbol.size());
    Ok(a)
}

fn take_dynsym_index(
    memory_offsets: &mut OutputSectionPartMap<u64>,
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
) -> Result<u32> {
    let index = u32::try_from(
        (memory_offsets.get(part_id::DYNSYM)
            - section_layouts.get(output_section_id::DYNSYM).mem_offset)
            / crate::elf::SYMTAB_ENTRY_SIZE,
    )
    .context("Too many dynamic symbols")?;
    memory_offsets.increment(part_id::DYNSYM, crate::elf::SYMTAB_ENTRY_SIZE);
    Ok(index)
}

impl Layout<'_> {
    pub(crate) fn mem_address_of_built_in(&self, section_id: OutputSectionId) -> u64 {
        self.section_layouts.get(section_id).mem_offset
    }
}

impl std::fmt::Debug for FileLayoutState<'_> {
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

fn section_debug(object: &crate::elf::File, section_index: object::SectionIndex) -> SectionDebug {
    let name = object
        .section(section_index)
        .and_then(|section| object.section_name(section))
        .map_or_else(
            |_| "??".to_owned(),
            |name| String::from_utf8_lossy(name).into_owned(),
        );
    SectionDebug { name }
}

struct SectionDebug {
    name: String,
}

impl Display for SectionDebug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{}`", self.name)
    }
}

impl GnuHashLayout {
    pub(crate) fn bucket_for_hash(&self, hash: u32) -> u32 {
        hash % self.bucket_count
    }
}

impl<'data> DynamicSymbolDefinition<'data> {
    fn new(symbol_id: SymbolId, name: &'data [u8], version: u16) -> Self {
        Self {
            symbol_id,
            name,
            hash: gnu_hash(name),
            version,
        }
    }
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

fn needs_tlsld(relocation_kind: RelocationKind) -> bool {
    matches!(
        relocation_kind,
        RelocationKind::TlsLd | RelocationKind::TlsLdGot | RelocationKind::TlsLdGotBase
    )
}

impl<'data> ObjectLayout<'data> {
    pub(crate) fn relocations(&self, index: SectionIndex) -> Result<RelocationList<'data>> {
        self.object.relocations(index, &self.relocations)
    }
}

/// Performs layout of sections and segments then makes sure that the loadable segments don't
/// overlap and that sections don't overlap.
#[test]
fn test_no_disallowed_overlaps() {
    use crate::output_section_id::OrderEvent;

    let mut output_sections = OutputSections::with_base_address(0x1000);
    let (output_order, program_segments) = output_sections.output_order();
    let args = Args::default();
    let section_part_sizes = output_sections.new_part_map::<u64>().map(|_, _| 7);

    let section_part_layouts = layout_section_parts(
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
        if !section_flags.contains(shf::ALLOC) {
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
        eflags: elf::Eflags(0),
    };

    let mut section_index = 0;
    output_sections.section_infos.for_each(|_, info| {
        if info.section_flags.contains(shf::ALLOC) {
            output_sections
                .output_section_indexes
                .push(Some(section_index));
            section_index += 1;
        } else {
            output_sections.output_section_indexes.push(None);
        }
    });

    let segment_layouts = compute_segment_layout(
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
fn verify_consistent_allocation_handling(flags: ValueFlags, output_kind: OutputKind) -> Result {
    let output_sections = OutputSections::with_base_address(0);
    let (output_order, _program_segments) = output_sections.output_order();
    let mut mem_sizes = output_sections.new_part_map();
    allocate_symbol_resolution(flags, &mut mem_sizes, output_kind);
    let mut memory_offsets = output_sections.new_part_map();
    *memory_offsets.get_mut(part_id::GOT) = 0x10;
    *memory_offsets.get_mut(part_id::PLT_GOT) = 0x10;
    let has_dynamic_symbol =
        flags.is_dynamic() || (flags.needs_export_dynamic() && flags.is_interposable());
    let dynamic_symbol_index = has_dynamic_symbol.then(|| NonZeroU32::new(1).unwrap());

    let resolution = create_resolution(flags, 0, dynamic_symbol_index, &mut memory_offsets);

    elf_writer::verify_resolution_allocation(
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

pub(crate) struct Sonames<'data>(HashSet<&'data [u8]>);

impl<'data> Sonames<'data> {
    /// Builds an index of the DT_SONAMEs of the input dynamic objects. Note, that we include
    /// --as-needed shared objects that we're not actually linking against. This means that we can
    /// report --no-shlib-undefined errors for shared libraries that have all of their dependencies
    /// as inputs, even if we weren't going to add them as direct dependencies of our output file.
    fn new(groups: &[Group<'data, crate::elf::File<'data>>]) -> Self {
        timing_phase!("Build SONAME index");

        Sonames(
            groups
                .iter()
                .flat_map(|group| {
                    let objects = match group {
                        Group::Objects(objects) => *objects,
                        _ => &[],
                    };
                    objects.iter().filter_map(|input| {
                        input
                            .parsed
                            .object
                            .dynamic_tag_values()
                            .map(|tag_values| tag_values.lib_name(&input.parsed.input))
                    })
                })
                .collect(),
        )
    }

    fn contains(&self, name: &[u8]) -> bool {
        self.0.contains(name)
    }
}

#[derive(derive_more::Debug)]
pub(crate) struct VersionDef {
    #[debug("{}", String::from_utf8_lossy(name))]
    pub(crate) name: Vec<u8>,
    pub(crate) parent_index: Option<u16>,
}

impl<'scope, 'data> FinaliseLayoutResources<'scope, 'data> {
    fn symbol_debug(&'_ self, symbol_id: SymbolId) -> SymbolDebug<'_> {
        self.symbol_db
            .symbol_debug(self.per_symbol_flags, symbol_id)
    }
}

impl SysvHashLayout {
    fn byte_size(self) -> Result<u64> {
        let words = 2u64
            .checked_add(u64::from(self.bucket_count))
            .and_then(|v| v.checked_add(u64::from(self.chain_count)))
            .context("Too many dynamic symbols for .hash")?;
        Ok(words * size_of::<u32>() as u64)
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

struct EhFrameSizes {
    num_frames: u64,
    eh_frame_size: u64,
}

impl<'data> Default for ExceptionFrames<'data> {
    fn default() -> Self {
        ExceptionFrames::Rela(Vec::new())
    }
}

impl<'data> ExceptionFrames<'data> {
    pub(crate) fn len(&self) -> usize {
        match self {
            ExceptionFrames::Rela(f) => f.len(),
            ExceptionFrames::Crel(f) => f.len(),
        }
    }
}
