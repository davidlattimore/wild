//! Traverses the graph of symbol references to figure out what sections from the input files are
//! referenced. Determines which sections need to be linked, sums their sizes decides what goes
//! where in the output file then allocates addresses for each symbol.

use self::output_section_id::InfoInputs;
use crate::alignment;
use crate::alignment::Alignment;
use crate::arch::Arch;
use crate::arch::Relaxation as _;
use crate::args::Args;
use crate::args::OutputKind;
use crate::debug_assert_bail;
use crate::elf;
use crate::elf::EhFrameHdrEntry;
use crate::elf::File;
use crate::elf::FileHeader;
use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
use crate::elf::Versym;
use crate::elf_writer;
use crate::error::Error;
use crate::error::Result;
use crate::input_data::FileId;
use crate::input_data::InputRef;
use crate::input_data::PRELUDE_FILE_ID;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_id::FILE_HEADER;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::parsing::InternalSymDefInfo;
use crate::part_id;
use crate::part_id::PartId;
use crate::part_id::NUM_GENERATED_PARTS;
use crate::program_segments;
use crate::program_segments::ProgramSegmentId;
use crate::program_segments::MAX_SEGMENTS;
use crate::program_segments::STACK;
use crate::resolution;
use crate::resolution::FrameIndex;
use crate::resolution::NotLoaded;
use crate::resolution::ResolutionOutputs;
use crate::resolution::ResolvedEpilogue;
use crate::resolution::SectionSlot;
use crate::resolution::UnloadedSection;
use crate::resolution::ValueFlags;
use crate::sharding::ShardKey;
use crate::storage::StorageModel;
use crate::storage::SymbolNameMap as _;
use crate::string_merging::get_merged_string_output_address;
use crate::string_merging::MergeStringsSection;
use crate::string_merging::MergedStringStartAddresses;
use crate::symbol::SymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolDebug;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use crate::threading::prelude::*;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use anyhow::Context;
use bitflags::bitflags;
use crossbeam_queue::ArrayQueue;
use itertools::Itertools;
use linker_utils::elf::shf;
use linker_utils::elf::SectionFlags;
use object::elf::gnu_hash;
use object::elf::Rela64;
use object::read::elf::Dyn as _;
use object::read::elf::Rela as _;
use object::read::elf::Sym as _;
use object::read::elf::VerdefIterator;
use object::LittleEndian;
use object::SectionIndex;
use smallvec::SmallVec;
use std::ffi::CString;
use std::fmt::Display;
use std::mem::replace;
use std::mem::size_of;
use std::mem::swap;
use std::mem::take;
use std::num::NonZeroU32;
use std::num::NonZeroU64;
use std::sync::atomic;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicU8;
use std::sync::Mutex;

#[tracing::instrument(skip_all, name = "Layout")]
pub fn compute<'data, 'symbol_db, S: StorageModel, A: Arch>(
    symbol_db: &'symbol_db SymbolDb<'data, S>,
    resolved: ResolutionOutputs<'data>,
    output: &mut elf_writer::Output,
) -> Result<Layout<'data, 'symbol_db, S>> {
    let ResolutionOutputs {
        groups,
        mut output_sections,
        merged_strings,
        custom_start_stop_defs,
    } = resolved;

    if let Some(sym_info) = symbol_db.args.sym_info.as_deref() {
        print_symbol_info(symbol_db, sym_info);
    }
    let symbol_resolution_flags = vec![AtomicResolutionFlags::empty(); symbol_db.num_symbols()];
    let gc_outputs = find_required_sections::<S, A>(
        groups,
        symbol_db,
        &output_sections,
        &symbol_resolution_flags,
        &merged_strings,
        custom_start_stop_defs,
    )?;
    let mut group_states = gc_outputs.group_states;

    merge_dynamic_symbol_definitions(&mut group_states)?;
    finalise_all_sizes(
        symbol_db,
        &output_sections,
        &mut group_states,
        &symbol_resolution_flags,
    )?;
    let symbol_resolution_flags: Vec<ResolutionFlags> = symbol_resolution_flags
        .into_iter()
        .map(|f| f.into_non_atomic())
        .collect();
    let non_addressable_counts = apply_non_addressable_indexes(&mut group_states, symbol_db.args)?;
    let section_part_sizes = compute_total_section_part_sizes(
        &mut group_states,
        &mut output_sections,
        &symbol_resolution_flags,
        gc_outputs.sections_with_content,
    );
    let section_part_layouts = layout_section_parts(&section_part_sizes, &output_sections);
    let section_layouts = layout_sections(&section_part_layouts);
    output.set_size(compute_total_file_size(&section_layouts));

    let Some(FileLayoutState::Prelude(internal)) =
        &group_states.first().and_then(|g| g.files.first())
    else {
        unreachable!();
    };
    let header_info = internal.header_info.as_ref().unwrap();
    let segment_layouts = compute_segment_layout(&section_layouts, &output_sections, header_info)?;

    let mem_offsets: OutputSectionPartMap<u64> = starting_memory_offsets(&section_part_layouts);
    let starting_mem_offsets_by_group = compute_start_offsets_by_group(&group_states, mem_offsets);
    let merged_string_start_addresses =
        MergedStringStartAddresses::compute(&output_sections, &starting_mem_offsets_by_group);
    let mut symbol_resolutions = SymbolResolutions {
        resolutions: Vec::with_capacity(symbol_db.num_symbols()),
    };

    let mut res_writer = sharded_vec_writer::VecWriter::new(&mut symbol_resolutions.resolutions);

    let mut per_group_res_writers = group_states
        .iter()
        .map(|group| res_writer.take_shard(group.num_symbols))
        .collect_vec();

    let resources = FinaliseLayoutResources {
        symbol_db,
        symbol_resolution_flags: &symbol_resolution_flags,
        output_sections: &output_sections,
        section_layouts: &section_layouts,
        merged_string_start_addresses: &merged_string_start_addresses,
        merged_strings: &merged_strings,
    };
    let group_layouts = compute_symbols_and_layouts(
        group_states,
        starting_mem_offsets_by_group,
        &mut per_group_res_writers,
        &resources,
    )?;
    for shard in per_group_res_writers {
        res_writer.try_return_shard(shard)?;
    }
    update_dynamic_symbol_resolutions(&group_layouts, &mut symbol_resolutions.resolutions);
    crate::gc_stats::maybe_write_gc_stats(&group_layouts, symbol_db.args)?;

    let relocation_statistics = OutputSectionMap::with_size(section_layouts.len());

    Ok(Layout {
        symbol_db,
        symbol_resolutions,
        segment_layouts,
        section_part_layouts,
        section_layouts,
        group_layouts,
        output_sections,
        non_addressable_counts,
        symbol_resolution_flags,
        merged_strings,
        merged_string_start_addresses,
        has_static_tls: gc_outputs.has_static_tls,
        relocation_statistics,
    })
}

/// Update resolutions for all dynamic symbols that our output file defines.
#[tracing::instrument(skip_all, name = "Update dynamic symbol resolutions")]
fn update_dynamic_symbol_resolutions(
    layouts: &[GroupLayout],
    resolutions: &mut [Option<Resolution>],
) {
    let Some(FileLayout::Epilogue(epilogue)) = layouts.last().and_then(|g| g.files.last()) else {
        panic!("Epilogue should be the last file");
    };
    for (index, sym) in epilogue.dynamic_symbol_definitions.iter().enumerate() {
        let dynamic_symbol_index = NonZeroU32::try_from(epilogue.dynsym_start_index + index as u32)
            .expect("Dynamic symbol definitions should start > 0");
        if let Some(res) = &mut resolutions[sym.symbol_id.as_usize()] {
            res.dynamic_symbol_index = Some(dynamic_symbol_index);
        }
    }
}

#[tracing::instrument(skip_all, name = "Finalise per-object sizes")]
fn finalise_all_sizes<'data, S: StorageModel>(
    symbol_db: &SymbolDb<'data, S>,
    output_sections: &OutputSections,
    group_states: &mut [GroupState<'data>],
    symbol_resolution_flags: &[AtomicResolutionFlags],
) -> Result {
    group_states.par_iter_mut().try_for_each(|state| {
        state.finalise_sizes(symbol_db, output_sections, symbol_resolution_flags)
    })
}

#[tracing::instrument(skip_all, name = "Merge dynamic symbol definitions")]
fn merge_dynamic_symbol_definitions(group_states: &mut [GroupState]) -> Result {
    let mut dynamic_symbol_definitions = Vec::new();
    for group in group_states.iter() {
        dynamic_symbol_definitions.extend(group.common.dynamic_symbol_definitions.iter().copied());
    }
    let Some(FileLayoutState::Epilogue(epilogue)) =
        group_states.last_mut().and_then(|g| g.files.last_mut())
    else {
        panic!("Internal error, epilogue must be last");
    };
    epilogue.dynamic_symbol_definitions = dynamic_symbol_definitions;
    Ok(())
}

fn compute_total_file_size(section_layouts: &OutputSectionMap<OutputRecordLayout>) -> u64 {
    let mut file_size = 0;
    section_layouts.for_each(|_, s| file_size = file_size.max(s.file_offset + s.file_size));
    file_size as u64
}

/// Information about what goes where. Also includes relocation data, since that's computed at the
/// same time.
pub struct Layout<'data, 'symbol_db, S: StorageModel> {
    pub(crate) symbol_db: &'symbol_db SymbolDb<'data, S>,
    pub(crate) symbol_resolutions: SymbolResolutions,
    pub(crate) section_part_layouts: OutputSectionPartMap<OutputRecordLayout>,
    pub(crate) section_layouts: OutputSectionMap<OutputRecordLayout>,
    pub(crate) group_layouts: Vec<GroupLayout<'data>>,
    pub(crate) segment_layouts: SegmentLayouts,
    pub(crate) output_sections: OutputSections<'data>,
    pub(crate) non_addressable_counts: NonAddressableCounts,
    pub(crate) symbol_resolution_flags: Vec<ResolutionFlags>,
    pub(crate) merged_strings: OutputSectionMap<MergeStringsSection<'data>>,
    pub(crate) merged_string_start_addresses: MergedStringStartAddresses,
    pub(crate) relocation_statistics: OutputSectionMap<AtomicU64>,
    pub(crate) has_static_tls: bool,
}

pub(crate) struct SegmentLayouts {
    /// The layout of each of our segments. Segments containing no active output sections will have
    /// been filtered, so don't try to index this by our internal segment IDs.
    pub(crate) segments: Vec<SegmentLayout>,
    pub(crate) tls_start_address: Option<u64>,
}

#[derive(Default, Clone)]
pub(crate) struct SegmentLayout {
    pub(crate) id: ProgramSegmentId,
    pub(crate) sizes: OutputRecordLayout,
}

pub(crate) struct SymbolResolutions {
    resolutions: Vec<Option<Resolution>>,
}

pub(crate) enum FileLayout<'data> {
    Prelude(PreludeLayout),
    Object(ObjectLayout<'data>),
    Dynamic(DynamicLayout<'data>),
    Epilogue(EpilogueLayout<'data>),
    NotLoaded,
}

/// Address information for a symbol.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct Resolution {
    /// An address or absolute value.
    pub(crate) raw_value: u64,

    pub(crate) dynamic_symbol_index: Option<NonZeroU32>,

    /// The base GOT address for this resolution. For pointers to symbols the GOT entry will contain
    /// a single pointer. For TLS variables there can be up to 3 pointers. If
    /// ResolutionFlags::GOT_TLS_OFFSET is set, then that will be the first value. If
    /// ResolutionFlags::GOT_TLS_MODULE is set, then there will be a pair of values (module and
    /// offset within module).
    pub(crate) got_address: Option<NonZeroU64>,
    pub(crate) plt_address: Option<NonZeroU64>,
    pub(crate) resolution_flags: ResolutionFlags,
    pub(crate) value_flags: ValueFlags,
}

/// Address information for a section.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct SectionResolution {
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
            resolution_flags: ResolutionFlags::empty(),
            value_flags: ValueFlags::empty(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsMode {
    /// Convert TLS access to local-exec mode.
    LocalExec,

    /// Preserve TLS access mode of the input.
    Preserve,
}

enum FileLayoutState<'data> {
    Prelude(PreludeLayoutState),
    Object(ObjectLayoutState<'data>),
    Dynamic(DynamicLayoutState<'data>),
    NotLoaded(NotLoaded),
    Epilogue(EpilogueLayoutState<'data>),
}

/// Data that doesn't come from any input files, but needs to be written by the linker.
struct PreludeLayoutState {
    file_id: FileId,
    symbol_id_range: SymbolIdRange,
    internal_symbols: InternalSymbols,
    entry_symbol_id: Option<SymbolId>,
    needs_tlsld_got_entry: bool,
    identity: String,
    header_info: Option<HeaderInfo>,
    dynamic_linker: Option<CString>,
    shstrtab_size: u64,
}

pub(crate) struct EpilogueLayoutState<'data> {
    file_id: FileId,
    symbol_id_range: SymbolIdRange,
    internal_symbols: InternalSymbols,

    dynamic_symbol_definitions: Vec<DynamicSymbolDefinition<'data>>,
    gnu_hash_layout: Option<GnuHashLayout>,
}

#[derive(Default, Debug)]
pub(crate) struct GnuHashLayout {
    pub(crate) bucket_count: u32,
    pub(crate) bloom_shift: u32,
    pub(crate) bloom_count: u32,
    pub(crate) symbol_base: u32,
}

pub(crate) struct EpilogueLayout<'data> {
    pub(crate) internal_symbols: InternalSymbols,
    pub(crate) gnu_hash_layout: Option<GnuHashLayout>,
    pub(crate) dynamic_symbol_definitions: Vec<DynamicSymbolDefinition<'data>>,
    dynsym_start_index: u32,
}

pub(crate) struct ObjectLayout<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) file_id: FileId,
    pub(crate) object: &'data File<'data>,
    pub(crate) sections: Vec<SectionSlot<'data>>,
    pub(crate) section_resolutions: Vec<SectionResolution>,
    pub(crate) symbol_id_range: SymbolIdRange,
}

pub(crate) struct PreludeLayout {
    pub(crate) entry_symbol_id: Option<SymbolId>,
    pub(crate) tlsld_got_entry: Option<NonZeroU64>,
    pub(crate) identity: String,
    pub(crate) header_info: HeaderInfo,
    pub(crate) internal_symbols: InternalSymbols,
    pub(crate) dynamic_linker: Option<CString>,
}

pub(crate) struct InternalSymbols {
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo>,
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

    pub(crate) verdef_info: Option<VerdefInfo<'data>>,

    /// Whether this is the last DynamicLayout that puts content into .gnu.version_r.
    pub(crate) is_last_verneed: bool,
}

trait HandlerData {
    fn symbol_id_range(&self) -> SymbolIdRange;

    fn file_id(&self) -> FileId;
}

trait SymbolRequestHandler<'data, S: StorageModel>: std::fmt::Display + HandlerData {
    fn finalise_symbol_sizes(
        &mut self,
        common: &mut CommonGroupState,
        symbol_db: &SymbolDb<'data, S>,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        let _file_span = symbol_db.args.trace_span_for_file(self.file_id());
        let symbol_id_range = self.symbol_id_range();

        for (local_index, resolution_flags) in symbol_resolution_flags[symbol_id_range.as_usize()]
            .iter()
            .enumerate()
        {
            let symbol_id = symbol_id_range.offset_to_id(local_index);
            if !symbol_db.is_canonical(symbol_id) {
                continue;
            }
            let value_flags = symbol_db.local_symbol_value_flags(symbol_id);
            let current_res_flags = resolution_flags.get();

            // It might be tempting to think that this code should only be run for dynamic objects,
            // however regular objects can own dynamic symbols too if the symbol is an undefined
            // weak symbol.
            if value_flags.contains(ValueFlags::DYNAMIC) && !current_res_flags.is_empty() {
                if current_res_flags.contains(ResolutionFlags::COPY_RELOCATION) {
                    self.allocate_copy_relocation(common, symbol_db, symbol_id)
                        .with_context(|| {
                            format!(
                                "Failed to apply copy relocation for symbol `{}`",
                                symbol_db.symbol_name_for_display(symbol_id)
                            )
                        })?;
                } else {
                    let name = symbol_db.symbol_name(symbol_id)?;
                    common.allocate(part_id::DYNSTR, name.len() as u64 + 1);
                    common.allocate(part_id::DYNSYM, crate::elf::SYMTAB_ENTRY_SIZE);
                }
            }

            // Once we're relatively confident that we're no longer seeing cases where we allocate
            // too much or too little space, we can probably remove this.
            if !are_flags_valid(value_flags, current_res_flags, symbol_db.args.output_kind) {
                bail!(
                    "{self}: Unexpected flag combination for symbol `{}` ({}): \
                     value_flags={value_flags}, \
                     resolution_flags={}, \
                     output_kind={:?}",
                    symbol_db.symbol_name(symbol_id)?,
                    symbol_id,
                    current_res_flags,
                    symbol_db.args.output_kind
                );
            }

            allocate_symbol_resolution(
                value_flags,
                resolution_flags,
                &mut common.mem_sizes,
                symbol_db.args.output_kind,
            );
        }
        if symbol_db.args.should_output_symbol_versions() {
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
        Ok(())
    }

    fn load_symbol<'scope, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope, S>,
        queue: &mut LocalWorkQueue,
    ) -> Result;

    fn allocate_copy_relocation(
        &mut self,
        _common: &mut CommonGroupState,
        symbol_db: &SymbolDb<'data, S>,
        symbol_id: SymbolId,
    ) -> Result {
        bail!(
            "Cannot perform copy relocation for undefined symbol `{}`",
            symbol_db.symbol_name(symbol_id)?
        );
    }
}

fn export_dynamic<'data, S: StorageModel>(
    common: &mut CommonGroupState<'data>,
    symbol_id: SymbolId,
    graph_resources: &GraphResources<'data, '_, S>,
) -> Result {
    let name = graph_resources.symbol_db.symbol_name(symbol_id)?;
    common
        .dynamic_symbol_definitions
        .push(DynamicSymbolDefinition::new(symbol_id, name.bytes()));
    Ok(())
}

fn allocate_symbol_resolution(
    value_flags: ValueFlags,
    resolution_flags: &AtomicResolutionFlags,
    mem_sizes: &mut OutputSectionPartMap<u64>,
    output_kind: OutputKind,
) {
    if value_flags.contains(ValueFlags::IFUNC) {
        resolution_flags.fetch_or(ResolutionFlags::GOT | ResolutionFlags::PLT);
    }
    let resolution_flags = resolution_flags.get();

    allocate_resolution(value_flags, resolution_flags, mem_sizes, output_kind);
}

/// Computes how much to allocation for a particular resolution. This is intended for debug
/// assertions when we're writing, to make sure that we would have allocated memory before we write.
pub(crate) fn compute_allocations(
    resolution: &Resolution,
    output_kind: OutputKind,
) -> OutputSectionPartMap<u64> {
    let mut sizes = OutputSectionPartMap::with_size(NUM_GENERATED_PARTS);
    allocate_resolution(
        resolution.value_flags,
        resolution.resolution_flags,
        &mut sizes,
        output_kind,
    );
    sizes
}

fn allocate_resolution(
    value_flags: ValueFlags,
    resolution_flags: ResolutionFlags,
    mem_sizes: &mut OutputSectionPartMap<u64>,
    output_kind: OutputKind,
) {
    let has_dynamic_symbol = value_flags.contains(ValueFlags::DYNAMIC)
        || resolution_flags.contains(ResolutionFlags::EXPORT_DYNAMIC);
    if resolution_flags.contains(ResolutionFlags::COPY_RELOCATION) {
        // Allocate space required for a copy relocation.
        mem_sizes.increment(part_id::RELA_DYN_GENERAL, crate::elf::RELA_ENTRY_SIZE);
    }
    if resolution_flags.contains(ResolutionFlags::GOT) {
        mem_sizes.increment(part_id::GOT, elf::GOT_ENTRY_SIZE);
        if resolution_flags.contains(ResolutionFlags::PLT) {
            mem_sizes.increment(part_id::PLT_GOT, elf::PLT_ENTRY_SIZE);
        }
        if value_flags.contains(ValueFlags::IFUNC) {
            mem_sizes.increment(part_id::RELA_PLT, elf::RELA_ENTRY_SIZE);
        } else if resolution_flags.contains(ResolutionFlags::COPY_RELOCATION) {
            // Copy relocation means that we know the relative address.
            if output_kind.is_relocatable() {
                mem_sizes.increment(part_id::RELA_DYN_RELATIVE, elf::RELA_ENTRY_SIZE);
            }
        } else if !value_flags.contains(ValueFlags::CAN_BYPASS_GOT) && has_dynamic_symbol {
            mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
        } else if value_flags.contains(ValueFlags::ADDRESS) && output_kind.is_relocatable() {
            mem_sizes.increment(part_id::RELA_DYN_RELATIVE, elf::RELA_ENTRY_SIZE);
        }
    }
    if resolution_flags.contains(ResolutionFlags::GOT_TLS_MODULE) {
        mem_sizes.increment(part_id::GOT, elf::GOT_ENTRY_SIZE * 2);
        // For executables, the TLS module ID is known at link time. For shared objects, we
        // need a runtime relocation to fill it in.
        if !output_kind.is_executable() {
            mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
        }
        if !value_flags.contains(ValueFlags::CAN_BYPASS_GOT) && has_dynamic_symbol {
            mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
        }
    }
    if resolution_flags.contains(ResolutionFlags::GOT_TLS_OFFSET) {
        mem_sizes.increment(part_id::GOT, elf::GOT_ENTRY_SIZE);
        if !value_flags.contains(ValueFlags::CAN_BYPASS_GOT) {
            mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
        }
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

impl<'data, S: StorageModel> SymbolRequestHandler<'data, S> for ObjectLayoutState<'data> {
    fn load_symbol<'scope, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope, S>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        debug_assert_bail!(
            resources.symbol_db.is_canonical(symbol_id),
            "Tried to load symbol in a file that doesn't hold the definition: {}",
            resources.symbol_db.symbol_debug(symbol_id)
        );
        let object_symbol_index = self.symbol_id_range.id_to_input(symbol_id);
        let local_symbol = self.object.symbol(object_symbol_index)?;
        if let Some(section_id) = self
            .object
            .symbol_section(local_symbol, object_symbol_index)?
        {
            self.sections_required.push(SectionRequest::new(section_id));
            self.load_sections::<S, A>(common, resources, queue)?;
        } else if local_symbol.is_common(LittleEndian) {
            let common_symbol = CommonSymbol::new(local_symbol)?;
            common.allocate(
                output_section_id::BSS.part_id_with_alignment(common_symbol.alignment),
                common_symbol.size,
            );
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

impl<'data, S: StorageModel> SymbolRequestHandler<'data, S> for DynamicLayoutState<'data> {
    fn load_symbol<'scope, A: Arch>(
        &mut self,
        _common: &mut CommonGroupState,
        symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope, S>,
        _queue: &mut LocalWorkQueue,
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
        Ok(())
    }

    /// Allocate the space required to perform a copy relocation for `symbol_id`. Copy relocations
    /// are used when a direct reference is made to a symbol that is defined by a dynamic object.
    fn allocate_copy_relocation(
        &mut self,
        common: &mut CommonGroupState,
        symbol_db: &SymbolDb<'data, S>,
        symbol_id: SymbolId,
    ) -> Result {
        if symbol_db.args.output_kind == OutputKind::SharedObject {
            bail!("Cannot directly access dynamic symbol when building a shared object",);
        }
        let symbol = self
            .object
            .symbol(self.symbol_id_range().id_to_input(symbol_id))?;
        let section_index = symbol.st_shndx(LittleEndian);
        if section_index == 0 {
            bail!("Cannot apply copy relocation for symbol");
        }
        let section = self
            .object
            .section(SectionIndex(usize::from(section_index)))?;
        let alignment = Alignment::new(self.object.section_alignment(section)?)?;

        // Allocate space in BSS for the copy of the symbol.
        let st_size = symbol.st_size(LittleEndian);
        common.allocate(
            output_section_id::BSS.part_id_with_alignment(alignment),
            st_size,
        );

        Ok(())
    }
}

impl HandlerData for PreludeLayoutState {
    fn file_id(&self) -> FileId {
        self.file_id
    }

    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }
}

impl<'data, S: StorageModel> SymbolRequestHandler<'data, S> for PreludeLayoutState {
    fn load_symbol<'scope, A: Arch>(
        &mut self,
        _common: &mut CommonGroupState,
        _symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope, S>,
        _queue: &mut LocalWorkQueue,
    ) -> Result {
        Ok(())
    }
}

impl HandlerData for EpilogueLayoutState<'_> {
    fn file_id(&self) -> FileId {
        self.file_id
    }

    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }
}

impl<'data, S: StorageModel> SymbolRequestHandler<'data, S> for EpilogueLayoutState<'data> {
    fn load_symbol<'scope, A: Arch>(
        &mut self,
        _common: &mut CommonGroupState,
        _symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope, S>,
        _queue: &mut LocalWorkQueue,
    ) -> Result {
        Ok(())
    }
}

struct CommonGroupState<'data> {
    mem_sizes: OutputSectionPartMap<u64>,

    /// Dynamic symbols that need to be defined. Because of the ordering requirements for symbol
    /// hashes, these get defined by the epilogue. The object on which a particular dynamic symbol
    /// is stored is non-deterministic and is whichever object first requested export of that
    /// symbol. That's OK though because the epilogue will sort all dynamic symbols.
    dynamic_symbol_definitions: Vec<DynamicSymbolDefinition<'data>>,
}

impl CommonGroupState<'_> {
    fn new(output_sections: &OutputSections) -> Self {
        Self {
            mem_sizes: output_sections.new_part_map(),
            dynamic_symbol_definitions: Default::default(),
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
}

fn create_global_address_emitter(
    symbol_resolution_flags: &[ResolutionFlags],
) -> GlobalAddressEmitter {
    GlobalAddressEmitter {
        symbol_resolution_flags,
    }
}

struct ObjectLayoutState<'data> {
    input: InputRef<'data>,
    file_id: FileId,
    symbol_id_range: SymbolIdRange,
    object: &'data File<'data>,

    /// Info about each of our sections. Empty until this object has been activated. Indexed the
    /// same as the sections in the input object.
    sections: Vec<SectionSlot<'data>>,

    /// A queue of sections that we need to load.
    sections_required: Vec<SectionRequest>,

    cies: SmallVec<[CieAtOffset<'data>; 2]>,

    /// Indexed by `FrameIndex`.
    exception_frames: Vec<ExceptionFrame<'data>>,

    eh_frame_section: Option<&'data object::elf::SectionHeader64<LittleEndian>>,
    eh_frame_size: u64,
}

#[derive(Default)]
struct ExceptionFrame<'data> {
    /// The relocations that need to be processed if we load this frame.
    relocations: &'data [Rela64<LittleEndian>],

    /// Number of bytes required to store this frame.
    frame_size: u32,

    /// The index of the previous frame that is for the same section.
    previous_frame_for_section: Option<FrameIndex>,
}

#[derive(Default)]
struct LocalWorkQueue {
    /// The index of the worker that owns this queue.
    index: usize,

    /// Work that needs to be processed by the worker that owns this queue.
    local_work: Vec<WorkItem>,
}

bitflags! {
    /// What kind of resolution we want for a symbol or section.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
    pub(crate) struct ResolutionFlags: u8 {
        /// The direct value is needed. e.g. via a relative or absolute relocation that doesn't use the
        /// PLT or GOT.
        const DIRECT = 1 << 0;

        /// An address in the global offset table is needed.
        const GOT = 1 << 1;

        /// A PLT entry is needed.
        const PLT = 1 << 2;

        /// A double GOT entry is needed in order to store the module number and offset within the
        /// module. Only set for TLS variables.
        const GOT_TLS_MODULE = 1 << 3;

        /// A single GOT entry is needed to store the offset of the TLS variable within the initial
        /// TLS block.
        const GOT_TLS_OFFSET = 1 << 4;

        /// The request originated from a dynamic object, so the symbol should be put into the dynamic
        /// symbol table.
        const EXPORT_DYNAMIC = 1 << 5;

        /// We encountered a direct reference to a symbol from a non-writable section and so we're
        /// going to need to do a copy relocation.
        const COPY_RELOCATION = 1 << 6;
    }
}

struct AtomicResolutionFlags {
    value: AtomicU8,
}

impl AtomicResolutionFlags {
    fn empty() -> Self {
        Self::new(ResolutionFlags::empty())
    }

    fn new(flags: ResolutionFlags) -> Self {
        Self {
            value: AtomicU8::new(flags.bits()),
        }
    }

    fn into_non_atomic(self) -> ResolutionFlags {
        ResolutionFlags::from_bits_retain(self.value.into_inner())
    }

    fn fetch_or(&self, flags: ResolutionFlags) -> ResolutionFlags {
        // Calling fetch_or on our atomic requires that we gain exclusive access to the cache line
        // containing the atomic. If all the bits are already set, then that's wasteful, so we first
        // check if the bits are set and if they are, we skip the fetch_or call.
        let current_bits = self.value.load(atomic::Ordering::Relaxed);
        if current_bits & flags.bits() == flags.bits() {
            return ResolutionFlags::from_bits_retain(current_bits);
        }
        let previous_bits = self.value.fetch_or(flags.bits(), atomic::Ordering::Relaxed);
        ResolutionFlags::from_bits_retain(previous_bits)
    }

    fn get(&self) -> ResolutionFlags {
        ResolutionFlags::from_bits_retain(self.value.load(atomic::Ordering::Relaxed))
    }
}

impl Clone for AtomicResolutionFlags {
    fn clone(&self) -> Self {
        Self {
            value: AtomicU8::new(self.value.load(atomic::Ordering::Relaxed)),
        }
    }
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

    verdef_info: Option<VerdefInfo<'data>>,

    non_addressable_indexes: NonAddressableIndexes,
}

pub(crate) struct VerdefInfo<'data> {
    pub(crate) defs: VerdefIterator<'data, FileHeader>,
    pub(crate) string_table_index: object::SectionIndex,

    /// Number of symbol versions that we're going to emit. This is the number of entries in
    /// `symbol_versions_needed` that are true. Computed after graph traversal.
    pub(crate) version_count: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct DynamicSymbolDefinition<'data> {
    pub(crate) symbol_id: SymbolId,
    pub(crate) name: &'data [u8],
    pub(crate) hash: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Section {
    pub(crate) index: object::SectionIndex,
    pub(crate) part_id: PartId,
    /// Size in memory.
    pub(crate) size: u64,
    pub(crate) resolution_kind: ResolutionFlags,
    pub(crate) is_writable: bool,
}

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

struct GraphResources<'data, 'scope, S: StorageModel> {
    symbol_db: &'scope SymbolDb<'data, S>,

    worker_slots: Vec<Mutex<WorkerSlot<'data>>>,

    errors: Mutex<Vec<Error>>,

    waiting_workers: ArrayQueue<GroupState<'data>>,

    /// A queue in which we store threads when they're idle so that other threads can wake them up
    /// when more work comes in. We always have one less slot in this array than the number of
    /// threads, since we never want all threads to be idle because that means we're finished. None
    /// if we're running with a single thread - mostly because ArrayQueue panics if we try to create
    /// an instance with zero size.
    idle_threads: Option<ArrayQueue<std::thread::Thread>>,

    done: AtomicBool,

    symbol_resolution_flags: &'scope [AtomicResolutionFlags],

    /// Which sections have we loaded an input section into. This is not the same as checking
    /// whether the mem sizes for that section are non-zero because we can load an input section
    /// with size 0. If we do that, we still need to produce the output section so that we have
    /// something to refer to in the symtab.
    sections_with_content: OutputSectionMap<AtomicBool>,

    merged_strings: &'scope OutputSectionMap<MergeStringsSection<'data>>,

    has_static_tls: AtomicBool,
}

struct FinaliseLayoutResources<'scope, 'data, S: StorageModel> {
    symbol_db: &'scope SymbolDb<'data, S>,
    symbol_resolution_flags: &'scope [ResolutionFlags],
    output_sections: &'scope OutputSections<'data>,
    section_layouts: &'scope OutputSectionMap<OutputRecordLayout>,
    merged_string_start_addresses: &'scope MergedStringStartAddresses,
    merged_strings: &'scope OutputSectionMap<MergeStringsSection<'data>>,
}

#[derive(Copy, Clone, Debug)]
enum WorkItem {
    /// The symbol's resolution flags have been made non-empty. The object that owns the symbol
    /// should perform any additional actions required, e.g. load the section that contains the
    /// symbol and process any relocations for that section.
    LoadGlobalSymbol(SymbolId),

    /// A direct reference to a dynamic symbol has been encountered. The symbol should be defined in
    /// BSS with a copy relocation.
    ExportCopyRelocation(SymbolId),
}

impl WorkItem {
    fn file_id<S: StorageModel>(self, symbol_db: &SymbolDb<S>) -> FileId {
        symbol_db.file_id_for_symbol(self.symbol_id())
    }

    fn symbol_id(self) -> SymbolId {
        match self {
            WorkItem::LoadGlobalSymbol(s) => s,
            WorkItem::ExportCopyRelocation(s) => s,
        }
    }
}

impl<'data, S: StorageModel> Layout<'data, '_, S> {
    pub(crate) fn prelude(&self) -> &PreludeLayout {
        let Some(FileLayout::Prelude(i)) = self.group_layouts.first().and_then(|g| g.files.first())
        else {
            panic!("Prelude layout not found at expected offset");
        };
        i
    }

    pub(crate) fn args(&self) -> &'data Args {
        self.symbol_db.args
    }

    pub(crate) fn symbol_debug(&self, symbol_id: SymbolId) -> SymbolDebug<'_, 'data, S> {
        self.symbol_db.symbol_debug(symbol_id)
    }

    pub(crate) fn merged_symbol_resolution(&self, symbol_id: SymbolId) -> Option<Resolution> {
        self.local_symbol_resolution(self.symbol_db.definition(symbol_id))
            .copied()
            .map(|mut res| {
                res.value_flags
                    .merge(self.symbol_db.symbol_value_flags(symbol_id));
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
        if self.args().output_kind == OutputKind::SharedObject {
            // Shared objects don't have an entry point.
            return Ok(0);
        }
        let symbol_id = self
            .prelude()
            .entry_symbol_id
            .context("Entry point is undefined")?;
        let resolution = self.local_symbol_resolution(symbol_id).with_context(|| {
            format!(
                "Entry point symbol was defined, but didn't get loaded. {}",
                self.symbol_debug(symbol_id)
            )
        })?;
        if !resolution.value_flags().contains(ValueFlags::ADDRESS) {
            bail!(
                "Entry point must be an address. {}",
                self.symbol_debug(symbol_id)
            );
        }
        Ok(resolution.value())
    }

    pub(crate) fn tls_start_address(&self) -> u64 {
        let tdata = &self.section_layouts.get(output_section_id::TDATA);
        tdata.mem_offset
    }

    /// Returns the memory address of the end of the TLS segment including any padding required to
    /// make sure that the TCB will be usize-aligned.
    pub(crate) fn tls_end_address(&self) -> u64 {
        let tbss = self.section_layouts.get(output_section_id::TBSS);
        let tdata = self.section_layouts.get(output_section_id::TDATA);
        let tls_end = tbss.mem_offset + tbss.mem_size;
        let alignment = tbss.alignment.max(tdata.alignment);
        alignment.align_up(tls_end)
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
                                range: e.from.clone(),
                                identifier: e.identifier.as_slice().to_owned(),
                            }
                        }),
                        sections: obj
                            .section_resolutions
                            .iter()
                            .zip(obj.object.sections.iter())
                            .zip(&obj.sections)
                            .map(|((res, section), section_slot)| {
                                (matches!(section_slot, SectionSlot::Loaded(..))
                                    && SectionFlags::from_header(section).contains(shf::ALLOC)
                                    && obj.object.section_size(section).is_ok_and(|s| s > 0))
                                .then(|| {
                                    let address = res.address;
                                    linker_layout::Section {
                                        mem_range: address
                                            ..(address + obj.object.section_size(section).unwrap()),
                                    }
                                })
                            })
                            .collect(),
                    }),
                    _ => None,
                })
            })
            .collect();
        linker_layout::Layout { files }
    }

    pub(crate) fn resolution_flags_for_symbol(&self, symbol_id: SymbolId) -> ResolutionFlags {
        self.symbol_resolution_flags[symbol_id.as_usize()]
    }

    pub(crate) fn file_layout(&self, file_id: FileId) -> &FileLayout {
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

    pub(crate) fn info_inputs(&self) -> InfoInputs {
        InfoInputs {
            section_part_layouts: &self.section_part_layouts,
            non_addressable_counts: &self.non_addressable_counts,
        }
    }
}

fn layout_sections(
    section_part_layouts: &OutputSectionPartMap<OutputRecordLayout>,
) -> OutputSectionMap<OutputRecordLayout> {
    section_part_layouts.merge_parts(|layouts| {
        let mut file_offset = usize::MAX;
        let mut mem_offset = u64::MAX;
        let mut file_end = 0;
        let mut mem_end = 0;
        let mut alignment = alignment::MIN;
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

#[tracing::instrument(skip_all, name = "Compute per-group start offsets")]
fn compute_start_offsets_by_group(
    group_states: &[GroupState<'_>],
    mut mem_offsets: OutputSectionPartMap<u64>,
) -> Vec<OutputSectionPartMap<u64>> {
    group_states
        .iter()
        .map(|group| {
            let group_mem_starts = mem_offsets.clone();
            mem_offsets.merge(&group.common.mem_sizes);
            group_mem_starts
        })
        .collect_vec()
}

#[tracing::instrument(skip_all, name = "Assign symbol addresses")]
fn compute_symbols_and_layouts<'data, S: StorageModel>(
    group_states: Vec<GroupState<'data>>,
    starting_mem_offsets_by_group: Vec<OutputSectionPartMap<u64>>,
    per_group_res_writers: &mut [sharded_vec_writer::Shard<Option<Resolution>>],
    resources: &FinaliseLayoutResources<'_, 'data, S>,
) -> Result<Vec<GroupLayout<'data>>> {
    group_states
        .into_par_iter()
        .zip(starting_mem_offsets_by_group)
        .zip(per_group_res_writers)
        .map(|((state, mut memory_offsets), symbols_out)| {
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
                    &layout.files,
                )?;
                Ok(layout)
            } else {
                state.finalise_layout(&mut memory_offsets, symbols_out, resources)
            }
        })
        .collect()
}

#[tracing::instrument(skip_all, name = "Compute segment layouts")]
fn compute_segment_layout(
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
    output_sections: &OutputSections,
    header_info: &HeaderInfo,
) -> Result<SegmentLayouts> {
    struct Record {
        segment_id: ProgramSegmentId,
        file_start: usize,
        file_end: usize,
        mem_start: u64,
        mem_end: u64,
        alignment: Alignment,
    }

    use output_section_id::OrderEvent;
    let mut complete = Vec::with_capacity(crate::program_segments::MAX_SEGMENTS);
    let mut active_records = Vec::new();

    for event in output_sections.sections_and_segments_events() {
        match event {
            OrderEvent::SegmentStart(segment_id) => {
                if segment_id == STACK {
                    // STACK segment is special as it does not contain any section.
                    active_records.push((
                        segment_id,
                        Record {
                            segment_id,
                            file_start: 0,
                            file_end: 0,
                            mem_start: 0,
                            mem_end: 0,
                            alignment: alignment::MIN,
                        },
                    ));
                } else {
                    active_records.push((
                        segment_id,
                        Record {
                            segment_id,
                            file_start: usize::MAX,
                            file_end: 0,
                            mem_start: u64::MAX,
                            mem_end: 0,
                            alignment: alignment::MIN,
                        },
                    ));
                }
            }
            OrderEvent::SegmentEnd(segment_id) => {
                let (popped_segment_id, record) = active_records
                    .pop()
                    .expect("SegmentEnd without matching SegmentStart");
                ensure!(
                    popped_segment_id == segment_id,
                    format!(
                        "Expected SegmentEnd event for segment `{}`, got `{}`",
                        segment_id.as_usize(),
                        popped_segment_id.as_usize()
                    )
                );
                complete.push(record);
            }
            OrderEvent::Section(section_id) => {
                let part = section_layouts.get(section_id);

                // Skip all ignored sections that will not end up in the final file.
                if output_sections.output_section_indexes[section_id.as_usize()].is_none() {
                    continue;
                }
                let section_flags = output_sections.section_flags(section_id);

                if active_records.is_empty() {
                    ensure!(
                    part.mem_offset == 0,
                    "Expected zero address for section `{}` not present in any program segment.",
                    output_sections.name(section_id)
                );
                    ensure!(
                        !section_flags.contains(shf::ALLOC),
                        "Section with SHF_ALLOC flag `{}` not present in any program segment.",
                        output_sections.name(section_id)
                    );
                } else {
                    // All segments should only cover sections that are allocated and have a non-zero address.
                    ensure!(
                        part.mem_offset != 0 || section_id == FILE_HEADER,
                        "Missing memory offset for section `{}` present in a program segment.",
                        output_sections.name(section_id)
                    );
                    ensure!(
                        section_flags.contains(shf::ALLOC),
                        "Missing SHF_ALLOC section flag for section `{}` present in a program \
                         segment.",
                        output_sections.name(section_id)
                    );
                    for (_, rec) in &mut active_records {
                        rec.file_start = rec.file_start.min(part.file_offset);
                        rec.mem_start = rec.mem_start.min(part.mem_offset);
                        rec.file_end = rec.file_end.max(part.file_offset + part.file_size);
                        rec.mem_end = rec.mem_end.max(part.mem_offset + part.mem_size);
                        rec.alignment = rec.alignment.max(part.alignment);
                    }
                }
            }
        }
    }

    complete.sort_by_key(|r| r.segment_id);
    assert_eq!(complete.len(), MAX_SEGMENTS);
    let mut tls_start_address = None;
    let segments = header_info
        .active_segment_ids
        .iter()
        .map(|&id| {
            let r = &complete[id.as_usize()];
            if id == program_segments::TLS {
                tls_start_address = Some(r.mem_start);
            }
            SegmentLayout {
                id,
                sizes: OutputRecordLayout {
                    file_size: r.file_end - r.file_start,
                    mem_size: r.mem_end - r.mem_start,
                    alignment: r.alignment,
                    file_offset: r.file_start,
                    mem_offset: r.mem_start,
                },
            }
        })
        .collect();
    Ok(SegmentLayouts {
        segments,
        tls_start_address,
    })
}

#[tracing::instrument(skip_all, name = "Compute total section sizes")]
fn compute_total_section_part_sizes(
    group_states: &mut [GroupState],
    output_sections: &mut OutputSections,
    symbol_resolution_flags: &[ResolutionFlags],
    sections_with_content: OutputSectionMap<bool>,
) -> OutputSectionPartMap<u64> {
    let mut total_sizes: OutputSectionPartMap<u64> = output_sections.new_part_map();
    for group_state in group_states.iter() {
        total_sizes.merge(&group_state.common.mem_sizes);
    }
    let first_group = group_states.first_mut().unwrap();
    let Some(FileLayoutState::Prelude(internal_layout)) = first_group.files.first_mut() else {
        unreachable!();
    };
    internal_layout.determine_header_sizes(
        &mut first_group.common,
        &mut total_sizes,
        sections_with_content,
        output_sections,
        symbol_resolution_flags,
    );
    total_sizes
}

/// This is similar to computing start addresses, but is used for things that aren't addressable,
/// but which need to be unique. It's non parallel. It could potentially be run in parallel with
/// some of the stages that run after it, that don't need access to the file states.
#[tracing::instrument(skip_all, name = "Apply non-addressable indexes")]
fn apply_non_addressable_indexes(
    group_states: &mut [GroupState],
    args: &Args,
) -> Result<NonAddressableCounts> {
    let mut indexes = NonAddressableIndexes {
        // Allocate version indexes starting from after the local and global indexes.
        gnu_version_r_index: object::elf::VER_NDX_GLOBAL + 1,
    };
    let mut counts = NonAddressableCounts { verneed_count: 0 };
    for g in group_states.iter_mut() {
        for s in &mut g.files {
            match s {
                FileLayoutState::Dynamic(s) => {
                    s.apply_non_addressable_indexes(&mut indexes, &mut counts)?;
                }
                _ => {}
            }
        }
    }

    // If we were going to output symbol versions, but we didn't actually use any, then we drop all
    // versym allocations. This is partly to avoid wasting unnecessary space in the output file, but
    // mostly in order match what GNU ld does.
    if counts.verneed_count == 0 && args.should_output_symbol_versions() {
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

#[derive(Copy, Clone)]
pub(crate) struct NonAddressableCounts {
    /// The number of shared objects that want to emit a verneed record.
    pub(crate) verneed_count: u64,
}

/// Returns the starting memory address for each alignment within each segment.
#[tracing::instrument(skip_all, name = "Compute per-alignment offsets")]
fn starting_memory_offsets(
    section_layouts: &OutputSectionPartMap<OutputRecordLayout>,
) -> OutputSectionPartMap<u64> {
    section_layouts.map(|_, rec| rec.mem_offset)
}

#[derive(Default)]
struct WorkerSlot<'data> {
    work: Vec<WorkItem>,
    worker: Option<GroupState<'data>>,
}

struct GcOutputs<'data> {
    group_states: Vec<GroupState<'data>>,
    sections_with_content: OutputSectionMap<bool>,
    has_static_tls: bool,
}

#[tracing::instrument(skip_all, name = "Find required sections")]
fn find_required_sections<'data, S: StorageModel, A: Arch>(
    groups_in: Vec<resolution::ResolvedGroup<'data>>,
    symbol_db: &SymbolDb<'data, S>,
    output_sections: &OutputSections<'data>,
    symbol_resolution_flags: &[AtomicResolutionFlags],
    merged_strings: &OutputSectionMap<MergeStringsSection<'data>>,
    custom_start_stop_defs: Vec<InternalSymDefInfo>,
) -> Result<GcOutputs<'data>> {
    let num_workers = groups_in.len();
    let (worker_slots, groups) = create_worker_slots(
        groups_in,
        output_sections,
        symbol_db,
        custom_start_stop_defs,
    );

    let num_threads = symbol_db.args.num_threads.get();

    let idle_threads = (num_threads > 1).then(|| ArrayQueue::new(num_threads - 1));
    let resources = GraphResources {
        symbol_db,
        worker_slots,
        errors: Mutex::new(Vec::new()),
        waiting_workers: ArrayQueue::new(num_workers),
        // NB, the -1 is because we never want all our threads to be idle. Once the last thread is
        // about to go idle, we're done and need to wake up and terminate all the the threads.
        idle_threads,
        done: AtomicBool::new(false),
        symbol_resolution_flags,
        sections_with_content: output_sections.new_section_map(),
        merged_strings,
        has_static_tls: AtomicBool::new(false),
    };
    let resources_ref = &resources;

    groups
        .into_par_iter()
        .enumerate()
        .try_for_each(|(i, mut group)| -> Result {
            let _span = tracing::debug_span!("find_required_sections", gid = i).entered();
            for file in &mut group.files {
                activate::<S, A>(&mut group.common, file, &mut group.queue, resources_ref)
                    .with_context(|| format!("Failed to activate {file}"))?;
            }
            let _ = resources_ref.waiting_workers.push(group);
            Ok(())
        })?;

    crate::threading::scope(|scope| {
        for _ in 0..num_threads {
            scope.spawn(|_| {
                let panic_result = std::panic::catch_unwind(|| {
                    let mut idle = false;
                    while !resources.done.load(atomic::Ordering::SeqCst) {
                        while let Some(worker) = resources.waiting_workers.pop() {
                            worker.do_pending_work::<S, A>(resources_ref);
                        }
                        if idle {
                            // Wait until there's more work to do or until we shut down.
                            std::thread::park();
                            idle = false;
                        } else {
                            if resources
                                .idle_threads
                                .as_ref()
                                .map_or(true, |idle_threads| {
                                    idle_threads.push(std::thread::current()).is_err()
                                })
                            {
                                // We're the only thread running. Either because there is only one
                                // thread (resources.idle_threads is None) or because all other threads
                                // are sleeping (resources.idle_threads is full). We're idle and all the
                                // other threads are too. Time to shut down.
                                resources.shut_down();
                                break;
                            }
                            idle = true;
                            // Go around the loop again before we park the thread. This ensures that we
                            // check for waiting workers in between when we added our thread to the idle
                            // list and when we park.
                        }
                    }
                });
                // Make sure we shut down if one of our threads panics, otherwise our other threads
                // will wait indefinitely for the thread that panicked to finish its work.
                if panic_result.is_err() {
                    resources.shut_down();
                }
            });
        }
    });
    let mut errors: Vec<Error> = take(resources.errors.lock().unwrap().as_mut());
    // TODO: Figure out good way to report more than one error.
    if let Some(error) = errors.pop() {
        return Err(error);
    }
    let group_states = unwrap_worker_states(&resources.worker_slots);
    let sections_with_content = resources.sections_with_content.into_map(|v| v.into_inner());
    Ok(GcOutputs {
        group_states,
        sections_with_content,
        has_static_tls: resources.has_static_tls.load(atomic::Ordering::Relaxed),
    })
}

fn create_worker_slots<'data, S: StorageModel>(
    groups_in: Vec<resolution::ResolvedGroup<'data>>,
    output_sections: &OutputSections<'data>,
    symbol_db: &SymbolDb<'data, S>,
    mut custom_start_stop_defs: Vec<InternalSymDefInfo>,
) -> (Vec<Mutex<WorkerSlot<'data>>>, Vec<GroupState<'data>>) {
    let mut worker_slots = Vec::with_capacity(groups_in.len());
    let group_states = groups_in
        .into_iter()
        .enumerate()
        .zip(&symbol_db.num_symbols_per_group)
        .map(|((group_index, group), &num_symbols)| {
            let files = group
                .files
                .into_iter()
                .map(|file| file.create_layout_state(&mut custom_start_stop_defs))
                .collect();
            worker_slots.push(Mutex::new(WorkerSlot {
                work: Default::default(),
                worker: None,
            }));
            GroupState {
                queue: LocalWorkQueue::new(group_index),
                num_symbols,
                files,
                common: CommonGroupState::new(output_sections),
            }
        })
        .collect();
    (worker_slots, group_states)
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
    fn do_pending_work<'scope, S: StorageModel, A: Arch>(
        mut self,
        resources: &GraphResources<'data, 'scope, S>,
    ) {
        loop {
            while let Some(work_item) = self.queue.local_work.pop() {
                let file_id = work_item.file_id(resources.symbol_db);
                let file = &mut self.files[file_id.file()];
                if let Err(error) =
                    file.do_work::<S, A>(&mut self.common, work_item, resources, &mut self.queue)
                {
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

    fn finalise_sizes<S: StorageModel>(
        &mut self,
        symbol_db: &SymbolDb<'data, S>,
        output_sections: &OutputSections,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        for file_state in &mut self.files {
            file_state.finalise_sizes(
                &mut self.common,
                symbol_db,
                output_sections,
                symbol_resolution_flags,
            )?;
        }
        self.common.validate_sizes()?;
        Ok(())
    }

    fn finalise_layout<S: StorageModel>(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut sharded_vec_writer::Shard<Option<Resolution>>,
        resources: &FinaliseLayoutResources<'_, 'data, S>,
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
fn set_last_verneed<S: StorageModel>(
    common: &CommonGroupState,
    resources: &FinaliseLayoutResources<S>,
    memory_offsets: &mut OutputSectionPartMap<u64>,
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
            if let FileLayout::Dynamic(d) = file {
                if d.verdef_info.is_some() {
                    d.is_last_verneed = true;
                    break;
                }
            }
        }
    }
}

fn activate<'data, S: StorageModel, A: Arch>(
    common: &mut CommonGroupState<'data>,
    file: &mut FileLayoutState<'data>,
    queue: &mut LocalWorkQueue,
    resources: &GraphResources<'data, '_, S>,
) -> Result {
    match file {
        FileLayoutState::Object(s) => s.activate::<S, A>(common, resources, queue),
        FileLayoutState::Prelude(s) => s.activate(common, resources, queue),
        FileLayoutState::Dynamic(s) => s.activate(common, resources, queue),
        FileLayoutState::NotLoaded(_) => Ok(()),
        FileLayoutState::Epilogue(_) => Ok(()),
    }
}

impl LocalWorkQueue {
    fn send_work<S: StorageModel>(
        &mut self,
        resources: &GraphResources<S>,
        file_id: FileId,
        work: WorkItem,
    ) {
        if file_id.group() == self.index {
            self.local_work.push(work);
        } else {
            resources.send_work(file_id, work);
        }
    }

    fn new(index: usize) -> LocalWorkQueue {
        Self {
            index,
            local_work: Default::default(),
        }
    }

    fn send_symbol_request<S: StorageModel>(
        &mut self,
        symbol_id: SymbolId,
        resources: &GraphResources<S>,
    ) {
        debug_assert!(resources.symbol_db.is_canonical(symbol_id));
        let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        self.send_work(
            resources,
            symbol_file_id,
            WorkItem::LoadGlobalSymbol(symbol_id),
        );
    }

    fn send_copy_relocation_request<S: StorageModel>(
        &mut self,
        symbol_id: SymbolId,
        resources: &GraphResources<S>,
    ) {
        debug_assert!(resources.symbol_db.is_canonical(symbol_id));
        let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        self.send_work(
            resources,
            symbol_file_id,
            WorkItem::ExportCopyRelocation(symbol_id),
        );
    }
}

impl<S: StorageModel> GraphResources<'_, '_, S> {
    fn report_error(&self, error: Error) {
        self.errors.lock().unwrap().push(error);
    }

    /// Sends all work in `work` to the worker for `file_id`. Leaves `work` empty so that it can be
    /// reused.
    fn send_work(&self, file_id: FileId, work: WorkItem) {
        let worker;
        {
            let mut slot = self.worker_slots[file_id.group()].lock().unwrap();
            worker = slot.worker.take();
            slot.work.push(work);
        };
        if let Some(worker) = worker {
            // The capacity of `waiting_workers` is equal to the total number of workers, so the
            // following should never fail.
            let _ = self.waiting_workers.push(worker);
            // If there's an idle thread, wake it so that it can process the work.
            if let Some(thread) = self
                .idle_threads
                .as_ref()
                .and_then(|idle_threads| idle_threads.pop())
            {
                thread.unpark();
            }
        }
    }

    fn shut_down(&self) {
        self.done.store(true, atomic::Ordering::SeqCst);
        // Wake up all sleeping threads so that they can shut down.
        if let Some(idle_threads) = self.idle_threads.as_ref() {
            while let Some(thread) = idle_threads.pop() {
                thread.unpark();
            }
        }
    }
}

impl<'data> FileLayoutState<'data> {
    fn finalise_sizes<S: StorageModel>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_db: &SymbolDb<'data, S>,
        output_sections: &OutputSections,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        match self {
            FileLayoutState::Object(s) => {
                s.finalise_sizes(common, symbol_db, output_sections, symbol_resolution_flags);
                s.finalise_symbol_sizes(common, symbol_db, symbol_resolution_flags)?;
            }
            FileLayoutState::Dynamic(s) => {
                s.finalise_sizes(common)?;
                s.finalise_symbol_sizes(common, symbol_db, symbol_resolution_flags)?;
            }
            FileLayoutState::Prelude(s) => {
                s.finalise_sizes(common, symbol_db, symbol_resolution_flags)?;
                s.finalise_symbol_sizes(common, symbol_db, symbol_resolution_flags)?;
            }
            FileLayoutState::Epilogue(s) => {
                s.finalise_sizes(common, symbol_db, symbol_resolution_flags)?;
                s.finalise_symbol_sizes(common, symbol_db, symbol_resolution_flags)?;
            }
            FileLayoutState::NotLoaded(_) => {}
        }
        Ok(())
    }

    fn do_work<'scope, S: StorageModel, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        work_item: WorkItem,
        resources: &GraphResources<'data, 'scope, S>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        match work_item {
            WorkItem::LoadGlobalSymbol(symbol_id) => self
                .handle_symbol_request::<S, A>(common, symbol_id, resources, queue)
                .with_context(|| {
                    format!(
                        "Failed to load {} from {self}",
                        resources.symbol_db.symbol_debug(symbol_id),
                    )
                }),
            WorkItem::ExportCopyRelocation(symbol_id) => match self {
                FileLayoutState::Dynamic(_) => export_dynamic(common, symbol_id, resources),
                _ => {
                    bail!(
                        "Internal error: ExportCopyRelocation sent to non-dynamic object for: {}",
                        resources.symbol_db.symbol_debug(symbol_id)
                    )
                }
            },
        }
    }

    fn handle_symbol_request<'scope, S: StorageModel, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope, S>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        match self {
            FileLayoutState::Object(state) => {
                state.load_symbol::<A>(common, symbol_id, resources, queue)?;
            }
            FileLayoutState::Prelude(state) => {
                state.load_symbol::<A>(common, symbol_id, resources, queue)?;
            }
            FileLayoutState::Dynamic(state) => {
                state.load_symbol::<A>(common, symbol_id, resources, queue)?;
            }
            FileLayoutState::NotLoaded(_) => {}
            FileLayoutState::Epilogue(state) => {
                state.load_symbol::<A>(common, symbol_id, resources, queue)?;
            }
        }
        Ok(())
    }

    fn finalise_layout<S: StorageModel>(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut sharded_vec_writer::Shard<Option<Resolution>>,
        resources: &FinaliseLayoutResources<'_, 'data, S>,
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
            Self::Epilogue(s) => FileLayout::Epilogue(s.finalise_layout(
                memory_offsets,
                resolutions_out,
                resources,
            )?),
            Self::Dynamic(s) => FileLayout::Dynamic(s.finalise_layout(
                memory_offsets,
                resolutions_out,
                resources,
            )?),
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

impl std::fmt::Display for PreludeLayoutState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt("<prelude>", f)
    }
}

impl std::fmt::Display for EpilogueLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt("<epilogue>", f)
    }
}

impl std::fmt::Display for FileLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileLayoutState::Object(s) => std::fmt::Display::fmt(s, f),
            FileLayoutState::Dynamic(s) => std::fmt::Display::fmt(s, f),
            FileLayoutState::Prelude(_) => std::fmt::Display::fmt("<prelude>", f),
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
            Self::Prelude(_) => std::fmt::Display::fmt("<prelude>", f),
            Self::Epilogue(_) => std::fmt::Display::fmt("<epilogue>", f),
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

struct SectionRequest {
    id: object::SectionIndex,
}

impl SectionRequest {
    fn new(id: object::SectionIndex) -> Self {
        Self { id }
    }
}

impl Section {
    fn create(
        object_state: &mut ObjectLayoutState,
        section_index: object::SectionIndex,
        part_id: PartId,
    ) -> Result<Section> {
        let object_section = object_state.object.section(section_index)?;
        let size = object_state.object.section_size(object_section)?;
        let section = Section {
            index: section_index,
            part_id,
            size,
            resolution_kind: ResolutionFlags::empty(),
            is_writable: SectionFlags::from_header(object_section).contains(shf::WRITE),
        };
        Ok(section)
    }

    // How much space we take up. This is our size rounded up to the next multiple of our alignment,
    // unless we're in a packed section, in which case it's just our size.
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
}

fn process_relocation<S: StorageModel, A: Arch>(
    object: &mut ObjectLayoutState,
    common: &mut CommonGroupState,
    rel: &Rela64<LittleEndian>,
    section: &object::elf::SectionHeader64<LittleEndian>,
    resources: &GraphResources<S>,
    queue: &mut LocalWorkQueue,
) -> Result {
    let args = resources.symbol_db.args;
    if let Some(local_sym_index) = rel.symbol(LittleEndian, false) {
        let symbol_db = resources.symbol_db;
        let symbol_id = symbol_db.definition(object.symbol_id_range.input_to_id(local_sym_index));
        let symbol_value_flags = symbol_db.local_symbol_value_flags(symbol_id);
        let canonical_symbol_value_flags = symbol_db.symbol_value_flags(symbol_id);
        let rel_offset = rel.r_offset.get(LittleEndian);
        let r_type = rel.r_type(LittleEndian, false);

        let rel_info = if let Some(relaxation) = A::Relaxation::new(
            r_type,
            object.object.raw_section_data(section)?,
            rel_offset,
            symbol_value_flags,
            args.output_kind,
            SectionFlags::from_header(section),
        ) {
            relaxation.rel_info()
        } else {
            RelocationKindInfo::from_raw(r_type)?
        };
        if does_relocation_require_static_tls(r_type) {
            resources
                .has_static_tls
                .store(true, atomic::Ordering::Relaxed);
        }

        let section_is_writable = SectionFlags::from_header(section).contains(shf::WRITE);
        let mut resolution_kind = resolution_flags(rel_info.kind);
        if resolution_kind.contains(ResolutionFlags::DIRECT)
            && symbol_value_flags.contains(ValueFlags::DYNAMIC)
        {
            if section_is_writable {
                common.allocate(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
            } else if canonical_symbol_value_flags.contains(ValueFlags::FUNCTION) {
                resolution_kind.remove(ResolutionFlags::DIRECT);
                resolution_kind |= ResolutionFlags::PLT | ResolutionFlags::GOT;
            } else if !symbol_value_flags.contains(ValueFlags::ABSOLUTE) {
                resolution_kind |= ResolutionFlags::COPY_RELOCATION;
            }
        }

        let previous_flags =
            resources.symbol_resolution_flags[symbol_id.as_usize()].fetch_or(resolution_kind);

        if args.is_relocatable()
            && rel_info.kind == RelocationKind::Absolute
            && symbol_value_flags.contains(ValueFlags::ADDRESS)
        {
            common.allocate(part_id::RELA_DYN_RELATIVE, elf::RELA_ENTRY_SIZE);
        }

        if previous_flags.is_empty() {
            queue.send_symbol_request(symbol_id, resources);
        }

        if resolution_kind.contains(ResolutionFlags::COPY_RELOCATION)
            && !previous_flags.contains(ResolutionFlags::COPY_RELOCATION)
        {
            queue.send_copy_relocation_request(symbol_id, resources);
        }
    }
    Ok(())
}

/// Returns whether the supplied relocation type requires static TLS. If true and we're writing a
/// shared object, then the STATIC_TLS will be set in the shared object which is a signal to the
/// runtime loader that the shared object cannot be loaded at runtime (e.g. with dlopen).
fn does_relocation_require_static_tls(r_type: u32) -> bool {
    r_type == object::elf::R_X86_64_GOTTPOFF
}

fn resolution_flags(rel_kind: RelocationKind) -> ResolutionFlags {
    match rel_kind {
        RelocationKind::PltRelative | RelocationKind::PltRelGotBase => {
            ResolutionFlags::PLT | ResolutionFlags::GOT
        }
        RelocationKind::GotRelGotBase | RelocationKind::GotRelative => ResolutionFlags::GOT,
        RelocationKind::GotTpOff => ResolutionFlags::GOT_TLS_OFFSET,
        RelocationKind::TlsGd => ResolutionFlags::GOT_TLS_MODULE,
        RelocationKind::TlsLd => ResolutionFlags::empty(),
        RelocationKind::Absolute
        | RelocationKind::Relative
        | RelocationKind::DtpOff
        | RelocationKind::TpOff
        | RelocationKind::SymRelGotBase
        | RelocationKind::None => ResolutionFlags::DIRECT,
    }
}

impl PreludeLayoutState {
    fn new(input_state: resolution::ResolvedPrelude<'_>) -> Self {
        Self {
            file_id: PRELUDE_FILE_ID,
            symbol_id_range: SymbolIdRange::prelude(input_state.symbol_definitions.len()),
            internal_symbols: InternalSymbols {
                symbol_definitions: input_state.symbol_definitions.to_owned(),
                start_symbol_id: SymbolId::zero(),
            },
            entry_symbol_id: None,
            needs_tlsld_got_entry: false,
            identity: crate::identity::linker_identity(),
            header_info: None,
            dynamic_linker: None,
            shstrtab_size: 0,
        }
    }

    fn activate<S: StorageModel>(
        &mut self,
        common: &mut CommonGroupState,
        resources: &GraphResources<S>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        resources.merged_strings.for_each(|section_id, merged| {
            if merged.len() > 0 {
                common.allocate(
                    section_id.part_id_with_alignment(alignment::MIN),
                    merged.len(),
                );
            }
        });

        // Allocate space to store the identify of the linker in the .comment section.
        common.allocate(
            output_section_id::COMMENT.part_id_with_alignment(alignment::MIN),
            self.identity.len() as u64,
        );

        // The first entry in the symbol table must be null. Similarly, the first string in the
        // strings table must be empty.
        if !resources.symbol_db.args.strip_all {
            common.allocate(part_id::SYMTAB_LOCAL, size_of::<elf::SymtabEntry>() as u64);
            common.allocate(part_id::STRTAB, 1);
        }

        if resources.symbol_db.args.output_kind.is_executable() {
            self.load_entry_point(resources, queue)?;
        }
        if resources.symbol_db.args.tls_mode() == TlsMode::Preserve {
            // Allocate space for a TLS module number and offset for use with TLSLD relocations.
            common.allocate(part_id::GOT, elf::GOT_ENTRY_SIZE * 2);
            self.needs_tlsld_got_entry = true;
            // For shared objects, we'll need to use a DTPMOD relocation to fill in the TLS module
            // number.
            if !resources.symbol_db.args.output_kind.is_executable() {
                common.allocate(part_id::RELA_DYN_GENERAL, crate::elf::RELA_ENTRY_SIZE);
            }
        }

        if resources.symbol_db.args.needs_dynsym() {
            // Allocate space for the null symbol.
            common.allocate(part_id::DYNSTR, 1);
            common.allocate(part_id::DYNSYM, size_of::<elf::SymtabEntry>() as u64);
        }

        self.dynamic_linker = resources
            .symbol_db
            .args
            .dynamic_linker
            .as_ref()
            .map(|p| CString::new(p.as_os_str().as_encoded_bytes()))
            .transpose()?;
        if let Some(dynamic_linker) = self.dynamic_linker.as_ref() {
            common.allocate(
                part_id::INTERP,
                dynamic_linker.as_bytes_with_nul().len() as u64,
            );
        }

        Ok(())
    }

    fn load_entry_point<S: StorageModel>(
        &mut self,
        resources: &GraphResources<S>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        let symbol_id = resources
            .symbol_db
            .global_names
            .get(&SymbolName::prehashed(b"_start"))
            .context("Missing _start symbol")?;
        self.entry_symbol_id = Some(symbol_id);
        let file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        let old_flags = resources.symbol_resolution_flags[symbol_id.as_usize()]
            .fetch_or(ResolutionFlags::DIRECT);
        if old_flags.is_empty() {
            queue.send_work(resources, file_id, WorkItem::LoadGlobalSymbol(symbol_id));
        }
        Ok(())
    }

    fn finalise_sizes<S: StorageModel>(
        &mut self,
        common: &mut CommonGroupState,
        symbol_db: &SymbolDb<'_, S>,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        if !symbol_db.args.strip_all {
            self.internal_symbols.allocate_symbol_table_sizes(
                common,
                symbol_db,
                symbol_resolution_flags,
            )?;
        }

        if symbol_db.args.should_write_eh_frame_hdr {
            common.allocate(part_id::EH_FRAME_HDR, size_of::<elf::EhFrameHdr>() as u64);
        }

        Ok(())
    }

    /// This function is where we determine sizes that depend on other sizes. For example, the size
    /// of the section headers table depends on which sections we're writing which depends on which
    /// sections are non-empty.
    fn determine_header_sizes(
        &mut self,
        common: &mut CommonGroupState,
        total_sizes: &mut OutputSectionPartMap<u64>,
        sections_with_content: OutputSectionMap<bool>,
        output_sections: &mut OutputSections,
        symbol_resolution_flags: &[ResolutionFlags],
    ) {
        use output_section_id::OrderEvent;

        // Determine which sections to keep. To start with, we keep all sections into which we've
        // loaded an input section. Note, this includes where the input section and even the output
        // section is empty. We still need the output section as it may contain symbols.
        let mut keep_sections = sections_with_content.into_raw_values();

        // Next, keep any sections for which we've recorded a non-zero size, even if we didn't
        // record the loading of an input section. This covers sections where we generate content.
        total_sizes.map(|part_id, size| {
            if *size > 0 {
                keep_sections[part_id.output_section_id().as_usize()] = true;
            }
        });

        // Keep any sections that we've said we want to keep regardless.
        for section_id in output_section_id::built_in_section_ids() {
            if section_id.built_in_details().keep_if_empty {
                keep_sections[section_id.as_usize()] = true;
            }
        }

        // Keep any sections that have a start/stop symbol which is referenced.
        symbol_resolution_flags[self.symbol_id_range().as_usize()]
            .iter()
            .zip(self.internal_symbols.symbol_definitions.iter())
            .for_each(|(symbol_state, definition)| {
                if !symbol_state.is_empty() {
                    if let Some(section_id) = definition.section_id() {
                        keep_sections[section_id.as_usize()] = true;
                    }
                }
            });
        let num_sections = keep_sections.iter().filter(|p| **p).count();

        // Compute output indexes of each of section.
        let mut next_output_index = 0;
        let mut output_section_indexes = vec![None; output_sections.num_sections()];
        for event in output_sections.sections_and_segments_events() {
            if let OrderEvent::Section(id) = event {
                if keep_sections[id.as_usize()] {
                    output_section_indexes[id.as_usize()] = Some(next_output_index);
                    next_output_index += 1;
                }
            };
        }
        output_sections.output_section_indexes = output_section_indexes;

        // Determine which program segments contain sections that we're keeping.
        let mut keep_segments = [false; crate::program_segments::MAX_SEGMENTS];
        let mut active_segments = Vec::with_capacity(4);
        for event in output_sections.sections_and_segments_events() {
            match event {
                OrderEvent::SegmentStart(segment_id) => active_segments.push(segment_id),
                OrderEvent::SegmentEnd(segment_id) => active_segments.retain(|a| *a != segment_id),
                OrderEvent::Section(section_id) => {
                    if keep_sections[section_id.as_usize()] {
                        for segment_id in &active_segments {
                            keep_segments[segment_id.as_usize()] = true;
                        }
                        active_segments.clear();
                    }
                }
            }
        }
        let active_segment_ids = (0..crate::program_segments::MAX_SEGMENTS)
            .filter(|i| keep_segments[*i] || i == &STACK.as_usize())
            .map(ProgramSegmentId::new)
            .collect();

        let header_info = HeaderInfo {
            num_output_sections_with_content: num_sections
                .try_into()
                .expect("output section count must fit in a u16"),

            active_segment_ids,
        };

        // Allocate space for headers based on segment and section counts.
        let mut extra_sizes = OutputSectionPartMap::with_size(common.mem_sizes.num_parts());

        extra_sizes.increment(part_id::FILE_HEADER, u64::from(elf::FILE_HEADER_SIZE));
        extra_sizes.increment(part_id::PROGRAM_HEADERS, header_info.program_headers_size());
        extra_sizes.increment(part_id::SECTION_HEADERS, header_info.section_headers_size());
        self.shstrtab_size = output_sections
            .ids_with_info()
            .filter(|(id, _info)| output_sections.output_index_of_section(*id).is_some())
            .map(|(_id, info)| info.name.len() as u64 + 1)
            .sum::<u64>();
        extra_sizes.increment(part_id::SHSTRTAB, self.shstrtab_size);

        // We need to allocate both our own size record and the file totals, since they've already
        // been computed.
        common.mem_sizes.merge(&extra_sizes);
        total_sizes.merge(&extra_sizes);

        self.header_info = Some(header_info);
    }

    fn finalise_layout<S: StorageModel>(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<S>,
    ) -> Result<PreludeLayout> {
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
        if resources.symbol_db.args.needs_dynsym() {
            take_dynsym_index(memory_offsets, resources.section_layouts)?;
        }

        self.internal_symbols
            .finalise_layout(memory_offsets, resolutions_out, resources)?;

        memory_offsets.increment(
            output_section_id::COMMENT.part_id_with_alignment(alignment::MIN),
            self.identity.len() as u64,
        );
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

impl InternalSymbols {
    fn allocate_symbol_table_sizes<S: StorageModel>(
        &mut self,
        common: &mut CommonGroupState,
        symbol_db: &SymbolDb<'_, S>,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        // Allocate space in the symbol table for the symbols that we define.
        for index in 0..self.symbol_definitions.len() {
            let symbol_id = self.start_symbol_id.add_usize(index);
            if !symbol_db.is_canonical(symbol_id) || symbol_id.is_undefined() {
                continue;
            }
            // We don't put internal symbols in the symbol table if they aren't referenced.
            if symbol_resolution_flags[symbol_id.as_usize()]
                .get()
                .is_empty()
            {
                continue;
            }

            common.allocate(part_id::SYMTAB_GLOBAL, size_of::<elf::SymtabEntry>() as u64);
            let symbol_name = symbol_db.symbol_name(symbol_id)?;
            common.allocate(part_id::STRTAB, symbol_name.len() as u64 + 1);
        }
        Ok(())
    }

    fn finalise_layout<S: StorageModel>(
        &self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<S>,
    ) -> Result {
        // Define symbols that are optionally put at the start/end of some sections.
        let mut emitter = create_global_address_emitter(resources.symbol_resolution_flags);
        for (local_index, def_info) in self.symbol_definitions.iter().enumerate() {
            let symbol_id = self.start_symbol_id.add_usize(local_index);
            if !resources.symbol_db.is_canonical(symbol_id) {
                resolutions_out.write(None)?;
                continue;
            }
            // We don't put internal symbols in the symbol table if they aren't referenced.
            if resources.symbol_resolution_flags[symbol_id.as_usize()].is_empty() {
                resolutions_out.write(None)?;
                continue;
            }

            let (raw_value, value_flags) = match def_info {
                InternalSymDefInfo::Undefined => (0, ValueFlags::ABSOLUTE),
                InternalSymDefInfo::SectionStart(section_id) => (
                    resources.section_layouts.get(*section_id).mem_offset,
                    ValueFlags::ADDRESS,
                ),
                InternalSymDefInfo::SectionEnd(section_id) => {
                    let sec = resources.section_layouts.get(*section_id);
                    (sec.mem_offset + sec.mem_size, ValueFlags::ADDRESS)
                }
            };
            emitter.emit_resolution(
                symbol_id,
                raw_value,
                None,
                value_flags,
                resolutions_out,
                memory_offsets,
            )?;
        }
        Ok(())
    }
}

impl<'data> EpilogueLayoutState<'data> {
    fn new(
        input_state: ResolvedEpilogue,
        custom_start_stop_defs: Vec<InternalSymDefInfo>,
    ) -> EpilogueLayoutState<'data> {
        EpilogueLayoutState {
            file_id: input_state.file_id,
            symbol_id_range: SymbolIdRange::epilogue(
                input_state.start_symbol_id,
                custom_start_stop_defs.len(),
            ),
            internal_symbols: InternalSymbols {
                symbol_definitions: custom_start_stop_defs,
                start_symbol_id: input_state.start_symbol_id,
            },
            dynamic_symbol_definitions: Default::default(),
            gnu_hash_layout: None,
        }
    }

    fn finalise_sizes<S: StorageModel>(
        &mut self,
        common: &mut CommonGroupState,
        symbol_db: &SymbolDb<'data, S>,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        if !symbol_db.args.strip_all {
            self.internal_symbols.allocate_symbol_table_sizes(
                common,
                symbol_db,
                symbol_resolution_flags,
            )?;
        }

        if symbol_db.args.needs_dynamic() {
            let dynamic_entry_size = size_of::<crate::elf::DynamicEntry>();
            common.allocate(
                part_id::DYNAMIC,
                (elf_writer::NUM_EPILOGUE_DYNAMIC_ENTRIES * dynamic_entry_size) as u64,
            );
            for rpath in &symbol_db.args.rpaths {
                common.allocate(part_id::DYNAMIC, dynamic_entry_size as u64);
                common.allocate(part_id::DYNSTR, rpath.len() as u64 + 1);
            }
            if let Some(soname) = symbol_db.args.soname.as_ref() {
                common.allocate(part_id::DYNSTR, soname.len() as u64 + 1);
                common.allocate(part_id::DYNAMIC, dynamic_entry_size as u64);
            }

            self.allocate_gnu_hash(common);

            common.allocate(
                part_id::DYNSTR,
                self.dynamic_symbol_definitions
                    .iter()
                    .map(|n| n.name.len() + 1)
                    .sum::<usize>() as u64,
            );
            common.allocate(
                part_id::DYNSYM,
                (self.dynamic_symbol_definitions.len() * size_of::<elf::SymtabEntry>()) as u64,
            );
        }

        Ok(())
    }

    /// Allocates space required for .gnu.hash. Also sorts dynamic symbol definitions by their hash
    /// bucket as required by .gnu.hash.
    fn allocate_gnu_hash(&mut self, common: &mut CommonGroupState) {
        // Our number of buckets is computed somewhat arbitrarily so that we have on average 2
        // symbols per bucket, but then we round up to a power of two.
        let num_defs = self.dynamic_symbol_definitions.len();
        let gnu_hash_layout = GnuHashLayout {
            bucket_count: (num_defs / 2).next_power_of_two() as u32,
            bloom_shift: 6,
            bloom_count: 1,
            // `symbol_base` is set later in `finalise_layout`.
            symbol_base: 0,
        };
        // Sort by bucket. Tie-break by name for determinism. We can use an unstable sort
        // because name should be unique. We use a parallel sort because we're processing
        // symbols from potentially many input objects, so there can be a lot.
        self.dynamic_symbol_definitions
            .par_sort_unstable_by_key(|d| (gnu_hash_layout.bucket_for_hash(d.hash), d.name));
        let num_blume = 1;
        common.allocate(
            part_id::GNU_HASH,
            (size_of::<elf::GnuHashHeader>()
                + size_of::<u64>() * num_blume
                + size_of::<u32>() * gnu_hash_layout.bucket_count as usize
                + size_of::<u32>() * num_defs) as u64,
        );
        self.gnu_hash_layout = Some(gnu_hash_layout);
    }

    fn finalise_layout<S: StorageModel>(
        mut self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<'_, 'data, S>,
    ) -> Result<EpilogueLayout<'data>> {
        self.internal_symbols
            .finalise_layout(memory_offsets, resolutions_out, resources)?;

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

        memory_offsets.increment(
            part_id::DYNSYM,
            self.dynamic_symbol_definitions.len() as u64 * elf::SYMTAB_ENTRY_SIZE,
        );

        Ok(EpilogueLayout {
            internal_symbols: self.internal_symbols,
            gnu_hash_layout: self.gnu_hash_layout,
            dynamic_symbol_definitions: self.dynamic_symbol_definitions,
            dynsym_start_index,
        })
    }
}

pub(crate) struct HeaderInfo {
    pub(crate) num_output_sections_with_content: u16,
    pub(crate) active_segment_ids: Vec<ProgramSegmentId>,
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

    if let Some(non_dynamic) = input_state.non_dynamic {
        FileLayoutState::Object(ObjectLayoutState {
            file_id: input_state.file_id,
            symbol_id_range: input_state.symbol_id_range,
            input: input_state.input,
            object: input_state.object,
            exception_frames: Default::default(),
            eh_frame_section: None,
            eh_frame_size: 0,
            sections: non_dynamic.sections,
            sections_required: Default::default(),
            cies: Default::default(),
        })
    } else {
        FileLayoutState::Dynamic(DynamicLayoutState {
            file_id: input_state.file_id,
            symbol_id_range: input_state.symbol_id_range,
            lib_name: input_state.input.lib_name(),
            symbol_versions: input_state.object.versym,
            object: input_state.object,
            input: input_state.input,

            // These fields are filled in properly when we activate.
            symbol_versions_needed: Default::default(),

            // These fields are filled in when we finalise sizes.
            verdef_info: None,
            non_addressable_indexes: Default::default(),
        })
    }
}

impl<'data> ObjectLayoutState<'data> {
    fn activate<'scope, S: StorageModel, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        resources: &GraphResources<'data, 'scope, S>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        let mut eh_frame_section = None;
        let no_gc = !resources.symbol_db.args.gc_sections;
        for (i, section) in self.sections.iter().enumerate() {
            match section {
                SectionSlot::MustLoad(..) | SectionSlot::UnloadedDebugInfo(..) => {
                    self.sections_required
                        .push(SectionRequest::new(object::SectionIndex(i)));
                }
                SectionSlot::Unloaded(..) if no_gc => {
                    self.sections_required
                        .push(SectionRequest::new(object::SectionIndex(i)));
                }
                SectionSlot::EhFrameData(index) => {
                    eh_frame_section = Some(*index);
                }
                _ => (),
            }
        }
        if let Some(eh_frame_section_index) = eh_frame_section {
            process_eh_frame_data::<S, A>(
                self,
                common,
                self.symbol_id_range(),
                eh_frame_section_index,
                resources,
                queue,
            )?;
            let eh_frame_section = self.object.section(eh_frame_section_index)?;
            self.eh_frame_section = Some(eh_frame_section);
        }
        if resources.symbol_db.args.output_kind == OutputKind::SharedObject {
            self.load_non_hidden_symbols::<S, A>(common, resources, queue)?;
        }
        self.load_sections::<S, A>(common, resources, queue)
    }

    /// Loads sections in `sections_required` (which may be empty).
    fn load_sections<'scope, S: StorageModel, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        resources: &GraphResources<'data, 'scope, S>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        let _file_span = resources.symbol_db.args.trace_span_for_file(self.file_id());
        let _span = tracing::debug_span!("load_sections", file = %self.input).entered();
        while let Some(section_request) = self.sections_required.pop() {
            let section_id = section_request.id;
            match &self.sections[section_id.0] {
                SectionSlot::Unloaded(unloaded) | SectionSlot::MustLoad(unloaded) => {
                    self.load_section::<S, A>(common, queue, *unloaded, section_id, resources)?;
                }
                SectionSlot::UnloadedDebugInfo(part_id) => {
                    self.load_debug_section(common, *part_id, section_id)?;
                }
                SectionSlot::Discard => {
                    bail!(
                        "{self}: Don't know what segment to put `{}` in, but it's referenced",
                        self.object.section_display_name(section_id),
                    );
                }
                SectionSlot::Loaded(_)
                | SectionSlot::EhFrameData(..)
                | SectionSlot::LoadedDebugInfo(..) => {}
                SectionSlot::MergeStrings(_) => {
                    // We currently always load everything in merge-string sections. i.e. we don't
                    // GC unreferenced data. So there's nothing to do here.
                }
            }
        }
        Ok(())
    }

    fn load_section<'scope, S: StorageModel, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        queue: &mut LocalWorkQueue,
        unloaded: UnloadedSection,
        section_id: SectionIndex,
        resources: &GraphResources<'data, 'scope, S>,
    ) -> Result {
        let part_id = unloaded.part_id;
        let section = Section::create(self, section_id, part_id)?;
        for rel in self.object.relocations(section.index)? {
            process_relocation::<S, A>(
                self,
                common,
                rel,
                self.object.section(section.index)?,
                resources,
                queue,
            )?;
        }
        tracing::debug!(loaded_section = %self.object.section_display_name(section_id),);
        common.allocate(part_id, section.capacity());

        resources
            .sections_with_content
            .get(part_id.output_section_id())
            .fetch_or(true, atomic::Ordering::Relaxed);

        self.process_section_exception_frames::<S, A>(
            unloaded.last_frame_index,
            common,
            resources,
            queue,
        )?;

        self.sections[section_id.0] = SectionSlot::Loaded(section);

        Ok(())
    }

    /// Processes the exception frames for a section that we're loading.
    fn process_section_exception_frames<S: StorageModel, A: Arch>(
        &mut self,
        frame_index: Option<FrameIndex>,
        common: &mut CommonGroupState<'data>,
        resources: &GraphResources<'data, '_, S>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        let mut num_frames = 0;
        let mut next_frame_index = frame_index;
        while let Some(frame_index) = next_frame_index {
            let frame_data = &self.exception_frames[frame_index.as_usize()];
            next_frame_index = frame_data.previous_frame_for_section;

            self.eh_frame_size += u64::from(frame_data.frame_size);

            num_frames += 1;

            let frame_data_relocations = frame_data.relocations;

            // Request loading of any sections/symbols referenced by the FDEs for our
            // section.
            if let Some(eh_frame_section) = self.eh_frame_section {
                for rel in frame_data_relocations {
                    process_relocation::<S, A>(
                        self,
                        common,
                        rel,
                        eh_frame_section,
                        resources,
                        queue,
                    )?;
                }
            }
        }

        if resources.symbol_db.args.should_write_eh_frame_hdr {
            common.allocate(
                part_id::EH_FRAME_HDR,
                size_of::<EhFrameHdrEntry>() as u64 * num_frames,
            );
        }

        Ok(())
    }

    fn load_debug_section(
        &mut self,
        common: &mut CommonGroupState<'data>,
        part_id: PartId,
        section_id: SectionIndex,
    ) -> Result {
        let section = Section::create(self, section_id, part_id)?;
        tracing::debug!(loaded_debug_section = %self.object.section_display_name(section_id),);
        common.allocate(part_id, section.capacity());
        self.sections[section_id.0] = SectionSlot::LoadedDebugInfo(section);

        Ok(())
    }

    fn finalise_sizes<S: StorageModel>(
        &mut self,
        common: &mut CommonGroupState,
        symbol_db: &SymbolDb<'data, S>,
        output_sections: &OutputSections,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) {
        common.mem_sizes.resize(output_sections.num_parts());
        if !symbol_db.args.strip_all {
            self.allocate_symtab_space(common, symbol_db, symbol_resolution_flags);
        }
        let output_kind = symbol_db.args.output_kind;
        for slot in &mut self.sections {
            if let SectionSlot::Loaded(section) = slot {
                allocate_resolution(
                    ValueFlags::ADDRESS,
                    section.resolution_kind,
                    &mut common.mem_sizes,
                    output_kind,
                );
            }
        }
        // TODO: Deduplicate CIEs from different objects, then only allocate space for those CIEs
        // that we "won".
        for cie in &self.cies {
            self.eh_frame_size += cie.cie.bytes.len() as u64;
        }
        common.allocate(part_id::EH_FRAME, self.eh_frame_size);
    }

    fn allocate_symtab_space<S: StorageModel>(
        &mut self,
        common: &mut CommonGroupState,
        symbol_db: &SymbolDb<'data, S>,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) {
        let _file_span = symbol_db.args.trace_span_for_file(self.file_id());

        let mut num_locals = 0;
        let mut num_globals = 0;
        let mut strings_size = 0;
        for ((sym_index, sym), sym_state) in self
            .object
            .symbols
            .enumerate()
            .zip(&symbol_resolution_flags[self.symbol_id_range().as_usize()])
        {
            let symbol_id = self.symbol_id_range.input_to_id(sym_index);
            if let Some(info) = SymbolCopyInfo::new(
                self.object,
                sym_index,
                sym,
                symbol_id,
                symbol_db,
                sym_state.get(),
                &self.sections,
            ) {
                // If we've decided to emit the symbol even though it's not referenced (because it's
                // in a section we're emitting), then make sure we have a resolution for it.
                sym_state.fetch_or(ResolutionFlags::DIRECT);
                if sym.is_local() {
                    num_locals += 1;
                } else {
                    num_globals += 1;
                }
                strings_size += info.name.len() + 1;
            }
        }
        let entry_size = size_of::<elf::SymtabEntry>() as u64;
        common.allocate(part_id::SYMTAB_LOCAL, num_locals * entry_size);
        common.allocate(part_id::SYMTAB_GLOBAL, num_globals * entry_size);
        common.allocate(part_id::STRTAB, strings_size as u64);
    }

    fn finalise_layout<S: StorageModel>(
        mut self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<'_, 'data, S>,
    ) -> Result<ObjectLayout<'data>> {
        let _file_span = resources.symbol_db.args.trace_span_for_file(self.file_id());
        let symbol_id_range = self.symbol_id_range();

        let mut emitter = create_global_address_emitter(resources.symbol_resolution_flags);

        let mut section_resolutions = Vec::with_capacity(self.sections.len());
        for slot in &mut self.sections {
            let resolution = match slot {
                SectionSlot::Loaded(sec) => {
                    let part_id = sec.part_id;
                    let address = *memory_offsets.get(part_id);
                    // TODO: We probably need to be able to handle sections that are ifuncs and sections
                    // that need a TLS GOT struct.
                    *memory_offsets.get_mut(part_id) += sec.capacity();
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

        for ((local_symbol_index, local_symbol), &resolution_flags) in self
            .object
            .symbols
            .enumerate()
            .zip(&resources.symbol_resolution_flags[symbol_id_range.as_usize()])
        {
            self.finalise_symbol(
                resources,
                resolution_flags,
                local_symbol,
                local_symbol_index,
                &section_resolutions,
                memory_offsets,
                &mut emitter,
                resolutions_out,
            )?;
        }

        memory_offsets.increment(part_id::EH_FRAME, self.eh_frame_size);

        Ok(ObjectLayout {
            input: self.input,
            file_id: self.file_id,
            object: self.object,
            sections: self.sections,
            section_resolutions,
            symbol_id_range,
        })
    }

    fn finalise_symbol<'scope, S: StorageModel>(
        &self,
        resources: &FinaliseLayoutResources<'scope, 'data, S>,
        resolution_flags: ResolutionFlags,
        local_symbol: &object::elf::Sym64<LittleEndian>,
        local_symbol_index: object::SymbolIndex,
        section_resolutions: &[SectionResolution],
        memory_offsets: &mut OutputSectionPartMap<u64>,
        emitter: &mut GlobalAddressEmitter<'scope>,
        resolutions_out: &mut ResolutionWriter,
    ) -> Result {
        let symbol_id_range = self.symbol_id_range();
        let symbol_id = symbol_id_range.input_to_id(local_symbol_index);
        if resolution_flags.is_empty() {
            resolutions_out.write(None)?;
            return Ok(());
        }
        if !resources.symbol_db.is_canonical(symbol_id) {
            resolutions_out.write(None)?;
            return Ok(());
        }
        let e = LittleEndian;
        let value_flags = resources.symbol_db.local_symbol_value_flags(symbol_id);
        let raw_value = if let Some(section_index) = self
            .object
            .symbol_section(local_symbol, local_symbol_index)?
        {
            if let Some(section_address) = section_resolutions[section_index.0].address() {
                local_symbol.st_value(e) + section_address
            } else {
                get_merged_string_output_address(
                    local_symbol_index,
                    0,
                    self.object,
                    &self.sections,
                    resources.merged_strings,
                    resources.merged_string_start_addresses,
                    true,
                )?
                .ok_or_else(|| {
                    anyhow!(
                        "Symbol is in a section that we didn't load. Symbol: {} Section: {}",
                        resources.symbol_db.symbol_debug(symbol_id),
                        section_debug(self.object, section_index),
                    )
                })?
            }
        } else if local_symbol.is_common(e) {
            let common = CommonSymbol::new(local_symbol)?;
            let offset = memory_offsets
                .get_mut(output_section_id::BSS.part_id_with_alignment(common.alignment));
            let address = *offset;
            *offset += common.size;
            address
        } else {
            local_symbol.st_value(e)
        };
        let mut dynamic_symbol_index = None;
        if value_flags.contains(ValueFlags::DYNAMIC) {
            // This is an undefined weak symbol. Emit it as a dynamic symbol so that it can be
            // overridden at runtime.
            let dyn_sym_index = take_dynsym_index(memory_offsets, resources.section_layouts)?;
            dynamic_symbol_index = Some(
                NonZeroU32::new(dyn_sym_index)
                    .context("Attempted to create dynamic symbol index 0")?,
            );
        }
        emitter.emit_resolution(
            symbol_id,
            raw_value,
            dynamic_symbol_index,
            value_flags,
            resolutions_out,
            memory_offsets,
        )?;
        Ok(())
    }

    fn load_non_hidden_symbols<'scope, S: StorageModel, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        resources: &GraphResources<'data, 'scope, S>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        for (sym_index, sym) in self.object.symbols.enumerate() {
            if can_export_symbol(sym) {
                let symbol_id = self.symbol_id_range().input_to_id(sym_index);
                let value_flags = resources.symbol_db.local_symbol_value_flags(symbol_id);
                if value_flags.contains(ValueFlags::DOWNGRADE_TO_LOCAL) {
                    continue;
                }
                let old_flags = resources.symbol_resolution_flags[symbol_id.as_usize()]
                    .fetch_or(ResolutionFlags::EXPORT_DYNAMIC);
                if old_flags.is_empty() {
                    self.load_symbol::<A>(common, symbol_id, resources, queue)?;
                }
                if !old_flags.contains(ResolutionFlags::EXPORT_DYNAMIC) {
                    export_dynamic(common, symbol_id, resources)?;
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct SymbolCopyInfo<'data> {
    pub(crate) name: &'data [u8],
}

impl<'data> SymbolCopyInfo<'data> {
    /// The primary purpose of this function is to determine whether a symbol should be copied into
    /// the symtab. In the process, we also return the name of the symbol, to avoid needing to read
    /// it again.
    pub(crate) fn new<S: StorageModel>(
        object: &crate::elf::File<'data>,
        sym_index: object::SymbolIndex,
        sym: &crate::elf::Symbol,
        symbol_id: SymbolId,
        symbol_db: &SymbolDb<'data, S>,
        symbol_state: ResolutionFlags,
        sections: &[SectionSlot],
    ) -> Option<SymbolCopyInfo<'data>> {
        let e = LittleEndian;
        if !symbol_db.is_canonical(symbol_id) || sym.is_undefined(e) {
            return None;
        }
        if let Ok(Some(section)) = object.symbol_section(sym, sym_index) {
            if !sections[section.0].is_loaded() {
                // Symbol is in discarded section.
                return None;
            }
        }
        if sym.is_common(e) && symbol_state.is_empty() {
            return None;
        }
        // Reading the symbol name is slightly expensive, so we want to do that after all the other
        // checks. That's also the reason why we return the symbol name, so that the caller, if it
        // needs the name, doesn't have a go and read it again.
        let name = object.symbol_name(sym).ok()?;
        if name.is_empty() || (sym.is_local() && name.starts_with(b".L")) {
            return None;
        }
        Some(SymbolCopyInfo { name })
    }
}

/// Returns whether the supplied symbol can be exported when we're outputting a shared object.
pub(crate) fn can_export_symbol(sym: &crate::elf::SymtabEntry) -> bool {
    let visibility = sym.st_visibility();
    !sym.is_undefined(LittleEndian)
        && !sym.is_local()
        && (visibility == object::elf::STV_DEFAULT || visibility == object::elf::STV_PROTECTED)
}

fn process_eh_frame_data<S: StorageModel, A: Arch>(
    object: &mut ObjectLayoutState,
    common: &mut CommonGroupState,
    file_symbol_id_range: SymbolIdRange,
    eh_frame_section_index: object::SectionIndex,
    resources: &GraphResources<S>,
    queue: &mut LocalWorkQueue,
) -> Result {
    let eh_frame_section = object.object.section(eh_frame_section_index)?;
    let data = object.object.raw_section_data(eh_frame_section)?;
    const PREFIX_LEN: usize = size_of::<elf::EhFrameEntryPrefix>();
    let e = LittleEndian;
    let relocations = object.object.relocations(eh_frame_section_index)?;
    let mut rel_iter = relocations.iter().enumerate().peekable();
    let mut offset = 0;

    while offset + PREFIX_LEN <= data.len() {
        // Although the section data will be aligned within the object file, there's
        // no guarantee that the object is aligned within the archive to any more
        // than 2 bytes, so we can't rely on alignment here. Archives are annoying!
        // See https://www.airs.com/blog/archives/170
        let prefix: elf::EhFrameEntryPrefix =
            bytemuck::pod_read_unaligned(&data[offset..offset + PREFIX_LEN]);
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
                let rel_offset = rel.r_offset.get(e);
                if rel_offset >= next_offset as u64 {
                    // This relocation belongs to the next entry.
                    break;
                }
                // We currently always load all CIEs, so any relocations found in CIEs always need
                // to be processed.
                process_relocation::<S, A>(
                    object,
                    common,
                    rel,
                    eh_frame_section,
                    resources,
                    queue,
                )?;
                if let Some(local_sym_index) = rel.symbol(e, false) {
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
                let rel_offset = rel.r_offset.get(e);
                if rel_offset < next_offset as u64 {
                    let is_pc_begin = (rel_offset as usize - offset) == elf::FDE_PC_BEGIN_OFFSET;

                    if is_pc_begin {
                        if let Some(index) = rel.symbol(e, false) {
                            let elf_symbol = object.object.symbol(index)?;
                            section_index = object.object.symbol_section(elf_symbol, index)?;
                        }
                    }
                    rel_end_index = rel_index + 1;
                    rel_iter.next();
                } else {
                    break;
                }
            }

            if let Some(section_index) = section_index {
                if let Some(unloaded) = object.sections[section_index.0].unloaded_mut() {
                    let frame_index = FrameIndex::from_usize(object.exception_frames.len());

                    // Update our unloaded section to point to our new frame. Our frame will then in
                    // turn point to whatever the section pointed to before.
                    let previous_frame_for_section =
                        replace(&mut unloaded.last_frame_index, Some(frame_index));

                    object.exception_frames.push(ExceptionFrame {
                        relocations: &relocations[rel_start_index..rel_end_index],
                        frame_size: size as u32,
                        previous_frame_for_section,
                    });
                }
            }
        }
        offset = next_offset;
    }

    // Allocate space for any remaining bytes in .eh_frame that aren't large enough to constitute an
    // actual entry. crtend.o has a single u32 equal to 0 as an end marker.
    object.eh_frame_size += (data.len() - offset) as u64;
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

#[derive(Clone, Copy)]
struct CommonSymbol {
    size: u64,
    alignment: Alignment,
}

impl CommonSymbol {
    fn new(local_symbol: &crate::elf::SymtabEntry) -> Result<CommonSymbol> {
        let e = LittleEndian;
        debug_assert!(local_symbol.is_common(e));
        // Common symbols misuse the value field (which we access via `address()`) to store the
        // alignment.
        let alignment = Alignment::new(local_symbol.st_value(e))?;
        let size = alignment.align_up(local_symbol.st_size(e));
        Ok(CommonSymbol { size, alignment })
    }
}

struct GlobalAddressEmitter<'state> {
    symbol_resolution_flags: &'state [ResolutionFlags],
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

impl GlobalAddressEmitter<'_> {
    fn emit_resolution(
        &mut self,
        symbol_id: SymbolId,
        raw_value: u64,
        dynamic_symbol_index: Option<NonZeroU32>,
        value_flags: ValueFlags,
        resolutions_out: &mut ResolutionWriter,
        memory_offsets: &mut OutputSectionPartMap<u64>,
    ) -> Result {
        let resolution = create_resolution(
            self.symbol_resolution_flags[symbol_id.as_usize()],
            raw_value,
            dynamic_symbol_index,
            value_flags,
            memory_offsets,
        );
        resolutions_out.write(Some(resolution))?;
        Ok(())
    }
}

fn create_resolution(
    res_kind: ResolutionFlags,
    raw_value: u64,
    dynamic_symbol_index: Option<NonZeroU32>,
    value_flags: ValueFlags,
    memory_offsets: &mut OutputSectionPartMap<u64>,
) -> Resolution {
    let mut resolution = Resolution {
        raw_value,
        dynamic_symbol_index,
        got_address: None,
        plt_address: None,
        resolution_flags: res_kind,
        value_flags,
    };
    if res_kind.contains(ResolutionFlags::PLT) {
        let plt_address = allocate_plt(memory_offsets);
        resolution.plt_address = Some(plt_address);
        if value_flags.contains(ValueFlags::DYNAMIC) {
            resolution.raw_value = plt_address.get();
        }
        resolution.got_address = Some(allocate_got(1, memory_offsets));
    } else if res_kind.contains(ResolutionFlags::GOT) {
        resolution.got_address = Some(allocate_got(1, memory_offsets));
    } else if res_kind.contains(ResolutionFlags::GOT_TLS_OFFSET) {
        if res_kind.contains(ResolutionFlags::GOT_TLS_MODULE) {
            resolution.got_address = Some(allocate_got(3, memory_offsets));
        } else {
            resolution.got_address = Some(allocate_got(1, memory_offsets));
        }
    } else if res_kind.contains(ResolutionFlags::GOT_TLS_MODULE) {
        resolution.got_address = Some(allocate_got(2, memory_offsets));
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
    fn create_layout_state(
        self,
        custom_start_stop_defs: &mut Vec<InternalSymDefInfo>,
    ) -> FileLayoutState<'data> {
        match self {
            resolution::ResolvedFile::Object(s) => new_object_layout_state(s),
            resolution::ResolvedFile::Prelude(s) => {
                FileLayoutState::Prelude(PreludeLayoutState::new(s))
            }
            resolution::ResolvedFile::NotLoaded(s) => FileLayoutState::NotLoaded(s),
            resolution::ResolvedFile::Epilogue(s) => {
                FileLayoutState::Epilogue(EpilogueLayoutState::new(s, take(custom_start_stop_defs)))
            }
        }
    }
}

impl Resolution {
    pub(crate) fn got_address(&self) -> Result<u64> {
        Ok(self.got_address.context("Missing GOT address")?.get())
    }

    pub(crate) fn tlsgd_got_address(&self) -> Result<u64> {
        debug_assert_bail!(
            self.resolution_flags
                .contains(ResolutionFlags::GOT_TLS_MODULE),
            "Called tlsgd_got_address without GOT_TLS_MODULE being set"
        );
        let got_address = self.got_address()?;
        // If we've got both a GOT_TLS_OFFSET and a GOT_TLS_MODULE, then the latter comes second.
        if self
            .resolution_flags
            .contains(ResolutionFlags::GOT_TLS_OFFSET)
        {
            return Ok(got_address + crate::elf::GOT_ENTRY_SIZE);
        }
        Ok(got_address)
    }

    pub(crate) fn plt_address(&self) -> Result<u64> {
        Ok(self.plt_address.context("Missing PLT address")?.get())
    }

    pub(crate) fn value_flags(self) -> ValueFlags {
        self.value_flags
    }

    pub(crate) fn value(self) -> u64 {
        self.raw_value
    }

    pub(crate) fn address(&self) -> Result<u64> {
        if !self.value_flags.contains(ValueFlags::ADDRESS) {
            bail!("Expected address, found {}", self.value_flags);
        }
        Ok(self.raw_value)
    }

    pub(crate) fn value_for_symbol_table(&self) -> u64 {
        self.raw_value
    }

    pub(crate) fn is_absolute(&self) -> bool {
        self.value_flags.contains(ValueFlags::ABSOLUTE)
    }

    pub(crate) fn dynamic_symbol_index(&self) -> Result<u32> {
        Ok(self
            .dynamic_symbol_index
            .context("Missing dynamic_symbol_index")?
            .get())
    }

    pub(crate) fn value_with_addend(
        &self,
        addend: u64,
        symbol_index: object::SymbolIndex,
        object_layout: &ObjectLayout,
        merged_strings: &OutputSectionMap<MergeStringsSection>,
        merged_string_start_addresses: &MergedStringStartAddresses,
    ) -> Result<u64> {
        // For most symbols, `raw_value` won't be zero, so we can save ourselves from looking up the
        // section to see if it's a string-merge section. For string-merge symbols with names,
        // `raw_value` will have already been computed, so we can avoid computing it again.
        if self.raw_value == 0 {
            if let Some(r) = get_merged_string_output_address(
                symbol_index,
                addend,
                object_layout.object,
                &object_layout.sections,
                merged_strings,
                merged_string_start_addresses,
                false,
            )? {
                if self.raw_value != 0 {
                    bail!("Merged string resolution has value 0x{}", self.raw_value);
                }
                return Ok(r);
            }
        }
        Ok(self.raw_value.wrapping_add(addend))
    }
}

fn layout_section_parts(
    sizes: &OutputSectionPartMap<u64>,
    output_sections: &OutputSections,
) -> OutputSectionPartMap<OutputRecordLayout> {
    let mut file_offset = 0;
    let mut mem_offset = output_sections.base_address;
    let mut current_seg_id = None;
    let mut nonalloc_mem_offsets: OutputSectionMap<u64> =
        OutputSectionMap::with_size(output_sections.num_sections());

    sizes.output_order_map(output_sections, |part_id, section_alignment, part_size| {
        let section_id = part_id.output_section_id();
        let section_flags = output_sections.section_flags(section_id);
        let mem_size = *part_size;
        // Note, we align up even if our size is zero, otherwise our section will start at an
        // unaligned address.
        file_offset = section_alignment.align_up_usize(file_offset);

        if section_flags.contains(shf::ALLOC) {
            mem_offset = section_alignment.align_up(mem_offset);
            let seg_id = output_sections.loadable_segment_id_for(section_id);
            if current_seg_id != seg_id {
                current_seg_id = seg_id;
                let segment_alignment = seg_id.map_or(alignment::MIN, |s| s.alignment());
                mem_offset = segment_alignment.align_modulo(file_offset as u64, mem_offset);
            }
            let file_size = if output_sections.has_data_in_file(section_id) {
                mem_size as usize
            } else {
                0
            };

            let section_layout = OutputRecordLayout {
                alignment: section_alignment,
                file_offset,
                mem_offset,
                file_size,
                mem_size,
            };
            file_offset += file_size;
            mem_offset += mem_size;
            section_layout
        } else {
            let section_id = part_id.output_section_id();
            let mem_offset = section_alignment.align_up(*nonalloc_mem_offsets.get(section_id));

            *nonalloc_mem_offsets.get_mut(section_id) += mem_size;

            let section_layout = OutputRecordLayout {
                alignment: section_alignment,
                file_offset,
                mem_offset,
                file_size: mem_size as usize,
                mem_size,
            };
            file_offset += mem_size as usize;
            section_layout
        }
    })
}

impl<'data> DynamicLayoutState<'data> {
    fn activate<S: StorageModel>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        resources: &GraphResources<'data, '_, S>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        let dt_info = DynamicTagValues::read(self.object)?;
        self.symbol_versions_needed = vec![false; dt_info.verdefnum as usize];
        if let Some(soname) = dt_info.soname {
            self.lib_name = soname;
        }
        common.allocate(
            part_id::DYNAMIC,
            size_of::<crate::elf::DynamicEntry>() as u64,
        );
        common.allocate(part_id::DYNSTR, self.lib_name.len() as u64 + 1);
        self.request_all_undefined_symbols(common, resources, queue)
    }

    fn request_all_undefined_symbols<S: StorageModel>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        resources: &GraphResources<'data, '_, S>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        for symbol_id in self.symbol_id_range() {
            if resources.symbol_db.is_canonical(symbol_id) {
                continue;
            }
            let definition_symbol_id = resources.symbol_db.definition(symbol_id);
            let file_id = resources.symbol_db.file_id_for_symbol(definition_symbol_id);
            // If a shared object references a symbol from say another shared object, there's
            // nothing we need to do.
            if !resources.symbol_db.file(file_id).is_regular_object() {
                continue;
            }
            let old_flags = resources.symbol_resolution_flags[definition_symbol_id.as_usize()]
                .fetch_or(ResolutionFlags::EXPORT_DYNAMIC);
            if old_flags.is_empty() {
                queue.send_symbol_request(definition_symbol_id, resources);
            }
            if !old_flags.contains(ResolutionFlags::EXPORT_DYNAMIC) {
                export_dynamic(common, definition_symbol_id, resources)?;
            }
        }
        Ok(())
    }

    fn finalise_sizes(&mut self, common: &mut CommonGroupState<'data>) -> Result {
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
                    // Every VERDEF entry should have at least one AUX entry.
                    let aux = aux_iterator.next()?.context("VERDEF with no AUX entry")?;
                    let name = aux.name(e, strings)?;
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

                self.verdef_info = Some(VerdefInfo {
                    defs,
                    string_table_index: link,
                    version_count,
                });
            }
        }

        Ok(())
    }

    fn apply_non_addressable_indexes(
        &mut self,
        indexes: &mut NonAddressableIndexes,
        counts: &mut NonAddressableCounts,
    ) -> Result {
        self.non_addressable_indexes = *indexes;
        if let Some(info) = self.verdef_info.as_ref() {
            if info.version_count > 0 {
                counts.verneed_count += 1;
                indexes.gnu_version_r_index = indexes
                    .gnu_version_r_index
                    .checked_add(info.version_count)
                    .context("Symbol versions overflowed 2**16")?;
            }
        }
        Ok(())
    }

    fn finalise_layout<S: StorageModel>(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<'_, 'data, S>,
    ) -> Result<DynamicLayout<'data>> {
        let version_mapping = self.compute_version_mapping();

        for (local_symbol, &resolution_flags) in self
            .object
            .symbols
            .iter()
            .zip(&resources.symbol_resolution_flags[self.symbol_id_range().as_usize()])
        {
            if resolution_flags.is_empty() {
                resolutions_out.write(None)?;
                continue;
            }

            let needs_copy_relocation = resolution_flags.contains(ResolutionFlags::COPY_RELOCATION);
            let address;
            let dynamic_symbol_index;
            if needs_copy_relocation {
                address =
                    assign_copy_relocation_address(self.object, local_symbol, memory_offsets)?;
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

            let resolution = create_resolution(
                resolution_flags,
                address,
                dynamic_symbol_index,
                ValueFlags::DYNAMIC,
                memory_offsets,
            );
            resolutions_out.write(Some(resolution))?;
        }

        if let Some(v) = self.verdef_info.as_ref() {
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
            version_mapping,
            verdef_info: self.verdef_info,
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
}

/// Assigns the address in BSS for the copy relocation of a symbol.
fn assign_copy_relocation_address(
    file: &File,
    local_symbol: &object::elf::Sym64<LittleEndian>,
    memory_offsets: &mut OutputSectionPartMap<u64>,
) -> Result<u64, Error> {
    let section_index = local_symbol.st_shndx(LittleEndian);
    let section = file.section(SectionIndex(usize::from(section_index)))?;
    let alignment = Alignment::new(file.section_alignment(section)?)?;
    let bss = memory_offsets.get_mut(output_section_id::BSS.part_id_with_alignment(alignment));
    let a = *bss;
    *bss += local_symbol.st_size(LittleEndian);
    Ok(a)
}

#[derive(Default)]
struct DynamicTagValues<'data> {
    verdefnum: u64,
    soname: Option<&'data [u8]>,
}

impl<'data> DynamicTagValues<'data> {
    fn read(file: &File<'data>) -> Result<Self> {
        let mut values = DynamicTagValues::default();
        let Ok(dynamic_tags) = file.dynamic_tags() else {
            return Ok(values);
        };
        let e = LittleEndian;
        for entry in dynamic_tags {
            let value = entry.d_val(e);
            match entry.d_tag(e) as u32 {
                object::elf::DT_VERDEFNUM => {
                    values.verdefnum = value;
                }
                object::elf::DT_SONAME => {
                    values.soname = Some(
                        file.symbols
                            .strings()
                            .get(value as u32)
                            .map_err(|()| anyhow!("Invalid DT_SONAME 0x{value:x}"))?,
                    );
                }
                _ => {}
            }
        }
        Ok(values)
    }
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

impl<S: StorageModel> Layout<'_, '_, S> {
    pub(crate) fn mem_address_of_built_in(&self, section_id: OutputSectionId) -> u64 {
        self.section_layouts.get(section_id).mem_offset
    }
}

impl std::fmt::Debug for FileLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileLayoutState::Object(s) => f.debug_tuple("Object").field(&s.input).finish(),
            FileLayoutState::Prelude(_) => f.debug_tuple("Internal").finish(),
            FileLayoutState::Dynamic(_) => f.debug_tuple("Dynamic").finish(),
            FileLayoutState::NotLoaded(_) => Display::fmt(&"<not loaded>", f),
            FileLayoutState::Epilogue(_) => Display::fmt(&"<custom sections>", f),
        }
    }
}

fn print_symbol_info<S: StorageModel>(symbol_db: &SymbolDb<S>, name: &str) {
    if let Some(symbol_id) = symbol_db
        .global_names
        .get(&SymbolName::prehashed(name.as_bytes()))
    {
        println!(
            "Global definition:\n   {}",
            symbol_db.symbol_debug(symbol_id)
        );
    } else {
        println!("No global symbol `{name}` defined by any input files");
    }
    println!("Definitions / references for `{name}`:");
    for i in 0..symbol_db.num_symbols() {
        let symbol_id = SymbolId::from_usize(i);
        if symbol_db
            .symbol_name(symbol_id)
            .is_ok_and(|sym_name| sym_name.bytes() == name.as_bytes())
        {
            let file_id = symbol_db.file_id_for_symbol(symbol_id);
            match symbol_db.file(file_id) {
                crate::parsing::ParsedInput::Prelude(_) => println!("  <prelude>"),
                crate::parsing::ParsedInput::Object(o) => {
                    let local_index = symbol_id.to_input(o.symbol_id_range);
                    match o.object.symbol(local_index) {
                        Ok(sym) => {
                            println!(
                                "  {}: symbol_id={symbol_id} Local #{local_index} \
                                in File #{file_id} {} ({})",
                                crate::symbol::SymDebug(sym),
                                o.input,
                                symbol_db.local_symbol_value_flags(symbol_id),
                            );
                        }
                        Err(e) => {
                            println!("  Corrupted input (file_id #{file_id}) {}: {e}", o.input);
                        }
                    }
                }
                crate::parsing::ParsedInput::Epilogue(_) => println!("  <epilogue>"),
            }
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
    fn new(symbol_id: SymbolId, name: &'data [u8]) -> Self {
        Self {
            symbol_id,
            name,
            hash: gnu_hash(name),
        }
    }
}

/// Performs layout of sections and segments then makes sure that the loadable segments don't
/// overlap and that sections don't overlap.
#[test]
fn test_no_disallowed_overlaps() {
    use crate::output_section_id::OrderEvent;

    let mut output_sections =
        crate::output_section_id::OutputSectionsBuilder::with_base_address(0x1000)
            .build()
            .unwrap();
    let section_part_sizes = output_sections.new_part_map::<u64>().map(|_, _| 7);
    let section_part_layouts = layout_section_parts(&section_part_sizes, &output_sections);
    let section_layouts = layout_sections(&section_part_layouts);

    // Make sure no alloc sections overlap
    let mut last_file_start = 0;
    let mut last_mem_start = 0;
    let mut last_file_end = 0;
    let mut last_mem_end = 0;
    let mut last_section_id = output_section_id::FILE_HEADER;
    for event in output_sections.sections_and_segments_events() {
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
        active_segment_ids: (0..MAX_SEGMENTS).map(ProgramSegmentId::new).collect(),
    };

    let mut section_index = 0;
    for section in &output_sections.section_infos {
        if section.section_flags.contains(shf::ALLOC) {
            output_sections
                .output_section_indexes
                .push(Some(section_index));
            section_index += 1;
        } else {
            output_sections.output_section_indexes.push(None);
        }
    }

    let segment_layouts =
        compute_segment_layout(&section_layouts, &output_sections, &header_info).unwrap();

    // Make sure loadable segments don't overlap in memory or in the file.
    let mut last_file = 0;
    let mut last_mem = 0;
    for seg_layout in &segment_layouts.segments {
        let seg_id = seg_layout.id;
        if seg_id.segment_type() != object::elf::PT_LOAD {
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

impl Display for ResolutionFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

/// Verifies that the code that allocates space for resolutions is consistent with the code that
/// writes those resolutions. e.g. we don't allocate too little or too much space.
#[test]
fn test_resolution_allocation_consistency() -> Result {
    use crate::args::RelocationModel;
    use std::collections::HashSet;

    let value_flag_sets = (0..=255)
        .map(ValueFlags::from_bits_truncate)
        .collect::<HashSet<_>>();
    let resolution_flag_sets = (0..=255)
        .map(ResolutionFlags::from_bits_truncate)
        .collect::<HashSet<_>>();
    let output_kinds = &[
        OutputKind::StaticExecutable(RelocationModel::NonRelocatable),
        OutputKind::StaticExecutable(RelocationModel::Relocatable),
        OutputKind::DynamicExecutable(RelocationModel::NonRelocatable),
        OutputKind::DynamicExecutable(RelocationModel::Relocatable),
        OutputKind::SharedObject,
    ];
    let output_sections = OutputSections::for_testing();
    for &value_flags in &value_flag_sets {
        for &resolution_flags in &resolution_flag_sets {
            for &output_kind in output_kinds {
                // Skip invalid combinations.
                if !are_flags_valid(value_flags, resolution_flags, output_kind) {
                    continue;
                }

                let mut mem_sizes = output_sections.new_part_map();
                let resolution_flags = AtomicResolutionFlags::new(resolution_flags);
                allocate_symbol_resolution(
                    value_flags,
                    &resolution_flags,
                    &mut mem_sizes,
                    output_kind,
                );
                let resolution_flags = resolution_flags.get();

                let mut memory_offsets =
                    OutputSectionPartMap::with_size(part_id::NUM_BUILT_IN_PARTS);
                // We use NonZero to represent offsets for these sections, so set them all to
                // non-zero values.
                *memory_offsets.get_mut(part_id::GOT) = 0x10;
                *memory_offsets.get_mut(part_id::PLT_GOT) = 0x10;

                let has_dynamic_symbol = value_flags.contains(ValueFlags::DYNAMIC)
                    || (resolution_flags.contains(ResolutionFlags::EXPORT_DYNAMIC)
                        && !value_flags.contains(ValueFlags::CAN_BYPASS_GOT));
                let dynamic_symbol_index = has_dynamic_symbol.then(|| NonZeroU32::new(1).unwrap());
                let resolution = create_resolution(
                    resolution_flags,
                    0,
                    dynamic_symbol_index,
                    value_flags,
                    &mut memory_offsets,
                );

                crate::elf_writer::verify_resolution_allocation(
                    &output_sections,
                    output_kind,
                    &mem_sizes,
                    &resolution,
                )
                .with_context(|| {
                    format!(
                        "Failed. output_kind={output_kind:?} \
                         value_flags={value_flags} \
                         resolution_flags={resolution_flags} \
                         has_dynamic_symbol={has_dynamic_symbol:?}"
                    )
                })?;
            }
        }
    }
    Ok(())
}

/// Returns whether a particular combination of flags is one that we consider valid and supported.
/// Certain combinations don't make sense and this function should return false for those
/// combinations. This lets us test that our allocation and writing are consistent for all supported
/// combinations without getting test failures for unsupported combinations. It also lets us report
/// unsupported combinations at runtime.
fn are_flags_valid(
    value_flags: ValueFlags,
    resolution_flags: ResolutionFlags,
    output_kind: OutputKind,
) -> bool {
    // This could just be one expression, but it'd make it harder to see what each invalid
    // combination represented.
    if !value_flags.contains(ValueFlags::ADDRESS)
        && !value_flags.contains(ValueFlags::ABSOLUTE)
        && !value_flags.contains(ValueFlags::DYNAMIC)
        && !value_flags.contains(ValueFlags::IFUNC)
    {
        return false;
    }
    if value_flags.contains(ValueFlags::DYNAMIC) && value_flags.contains(ValueFlags::IFUNC) {
        return false;
    }
    if value_flags.contains(ValueFlags::DYNAMIC) && value_flags.contains(ValueFlags::CAN_BYPASS_GOT)
    {
        return false;
    }
    if (resolution_flags.contains(ResolutionFlags::GOT_TLS_MODULE)
        || resolution_flags.contains(ResolutionFlags::GOT_TLS_OFFSET))
        && ((value_flags.contains(ValueFlags::ABSOLUTE)
            && !value_flags.contains(ValueFlags::DYNAMIC))
            || value_flags.contains(ValueFlags::IFUNC)
            || resolution_flags.contains(ResolutionFlags::PLT))
    {
        return false;
    }
    if resolution_flags.contains(ResolutionFlags::GOT)
        && (resolution_flags.contains(ResolutionFlags::GOT_TLS_MODULE)
            || resolution_flags.contains(ResolutionFlags::GOT_TLS_OFFSET))
    {
        return false;
    }
    if output_kind.is_static_executable()
        && (value_flags.contains(ValueFlags::DYNAMIC)
            || resolution_flags.contains(ResolutionFlags::EXPORT_DYNAMIC))
    {
        return false;
    }
    if output_kind.is_executable()
        && value_flags.contains(ValueFlags::ADDRESS)
        && !value_flags.contains(ValueFlags::CAN_BYPASS_GOT)
    {
        return false;
    }
    if output_kind == OutputKind::SharedObject
        && value_flags.contains(ValueFlags::CAN_BYPASS_GOT)
        && (resolution_flags.contains(ResolutionFlags::GOT_TLS_MODULE)
            || resolution_flags.contains(ResolutionFlags::GOT_TLS_OFFSET))
    {
        return false;
    }
    if value_flags.contains(ValueFlags::ADDRESS) && value_flags.contains(ValueFlags::DYNAMIC) {
        return false;
    }
    if value_flags.contains(ValueFlags::DYNAMIC)
        && value_flags.contains(ValueFlags::DOWNGRADE_TO_LOCAL)
    {
        return false;
    }
    if value_flags.contains(ValueFlags::DYNAMIC)
        && resolution_flags.contains(ResolutionFlags::EXPORT_DYNAMIC)
        && !value_flags.contains(ValueFlags::ABSOLUTE)
    {
        return false;
    }
    if resolution_flags.contains(ResolutionFlags::COPY_RELOCATION)
        && (!resolution_flags.contains(ResolutionFlags::DIRECT)
            || !value_flags.contains(ValueFlags::DYNAMIC)
            || value_flags.contains(ValueFlags::FUNCTION)
            || resolution_flags.contains(ResolutionFlags::PLT))
    {
        return false;
    }
    if value_flags.contains(ValueFlags::ABSOLUTE)
        && value_flags.contains(ValueFlags::DYNAMIC)
        && resolution_flags.contains(ResolutionFlags::COPY_RELOCATION)
    {
        return false;
    }
    if resolution_flags.contains(ResolutionFlags::PLT)
        && !resolution_flags.contains(ResolutionFlags::GOT)
    {
        return false;
    }
    true
}
