//! Traverses the graph of symbol references to figure out what sections from the input files are
//! referenced. Determines which sections need to be linked, sums their sizes decides what goes
//! where in the output file then allocates addresses for each symbol.

use crate::alignment;
use crate::alignment::Alignment;
use crate::args::Args;
use crate::args::HashStyle;
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
use crate::input_data::INTERNAL_FILE_ID;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_id::UnloadedSection;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::parsing::InternalSymDefInfo;
use crate::program_segments;
use crate::program_segments::ProgramSegmentId;
use crate::program_segments::MAX_SEGMENTS;
use crate::relaxation::Relaxation;
use crate::resolution;
use crate::resolution::MergedStringResolution;
use crate::resolution::ResolvedEpilogue;
use crate::resolution::SectionSlot;
use crate::resolution::ValueFlags;
use crate::sharding::split_slice;
use crate::sharding::ShardKey;
use crate::symbol::SymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolDebug;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use crate::threading::prelude::*;
use ahash::AHashMap;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use bitflags::bitflags;
use crossbeam_queue::ArrayQueue;
use object::elf::gnu_hash;
use object::elf::Rela64;
use object::read::elf::Dyn;
use object::read::elf::Rela as _;
use object::read::elf::SectionHeader as _;
use object::read::elf::Sym as _;
use object::read::elf::VerdefIterator;
use object::LittleEndian;
use smallvec::SmallVec;
use std::ffi::CString;
use std::fmt::Display;
use std::mem::size_of;
use std::num::NonZeroU32;
use std::num::NonZeroU64;
use std::sync::atomic;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::Mutex;

#[tracing::instrument(skip_all, name = "Layout")]
pub fn compute<'data>(
    symbol_db: &'data SymbolDb<'data>,
    file_states: Vec<resolution::ResolvedFile<'data>>,
    mut output_sections: OutputSections<'data>,
    output: &mut elf_writer::Output,
) -> Result<Layout<'data>> {
    if let Some(sym_info) = symbol_db.args.sym_info.as_deref() {
        print_symbol_info(symbol_db, sym_info);
    }
    let symbol_resolution_flags = vec![AtomicResolutionFlags::empty(); symbol_db.num_symbols()];
    let mut layout_states = find_required_sections(
        file_states,
        symbol_db,
        &output_sections,
        &symbol_resolution_flags,
    )?;
    merge_dynamic_symbol_definitions(&mut layout_states)?;
    finalise_all_sizes(
        symbol_db,
        &output_sections,
        &mut layout_states,
        &symbol_resolution_flags,
    )?;
    let symbol_resolution_flags: Vec<ResolutionFlags> = symbol_resolution_flags
        .into_iter()
        .map(|f| f.into_non_atomic())
        .collect();
    let non_addressable_counts = apply_non_addressable_indexes(&mut layout_states, symbol_db.args)?;
    let section_part_sizes = compute_total_section_part_sizes(
        &mut layout_states,
        &mut output_sections,
        &symbol_resolution_flags,
    );
    let section_part_layouts = layout_section_parts(&section_part_sizes, &output_sections);
    let section_layouts = layout_sections(&section_part_layouts);
    output.set_size(compute_total_file_size(&section_layouts));

    let FileLayoutState::Internal(internal) = &layout_states[INTERNAL_FILE_ID.as_usize()] else {
        unreachable!();
    };
    let header_info = internal.header_info.as_ref().unwrap();
    let segment_layouts = compute_segment_layout(&section_layouts, &output_sections, header_info);

    let mem_offsets: OutputSectionPartMap<u64> =
        starting_memory_offsets(&section_part_layouts, &output_sections);
    let starting_mem_offsets_by_file = compute_start_offsets_by_file(&layout_states, mem_offsets);
    let merged_string_start_addresses =
        MergedStringStartAddresses::compute(&output_sections, &starting_mem_offsets_by_file);
    let mut symbol_resolutions = SymbolResolutions {
        resolutions: vec![None; symbol_db.num_symbols()],
    };
    let mut resolutions_by_file = split_slice(
        &mut symbol_resolutions.resolutions,
        &symbol_db.num_symbols_per_file,
    );
    let file_layouts = compute_symbols_and_layouts(
        layout_states,
        starting_mem_offsets_by_file,
        &section_layouts,
        symbol_db,
        &merged_string_start_addresses,
        &output_sections,
        &mut resolutions_by_file,
        &symbol_resolution_flags,
    )?;
    update_dynamic_symbol_resolutions(&file_layouts, &mut symbol_resolutions.resolutions);
    crate::gc_stats::maybe_write_gc_stats(&file_layouts, symbol_db.args)?;

    Ok(Layout {
        symbol_db,
        symbol_resolutions,
        segment_layouts,
        section_part_layouts,
        section_layouts,
        file_layouts,
        output_sections,
        non_addressable_counts,
        symbol_resolution_flags,
    })
}

/// Update resolutions for all dynamic symbols that our output file defines.
#[tracing::instrument(skip_all, name = "Update dynamic symbol resolutions")]
fn update_dynamic_symbol_resolutions(
    layouts: &[FileLayout],
    resolutions: &mut [Option<Resolution>],
) {
    let Some(FileLayout::Epilogue(epilogue)) = layouts.last() else {
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
fn finalise_all_sizes(
    symbol_db: &SymbolDb,
    output_sections: &OutputSections,
    layout_states: &mut [FileLayoutState],
    symbol_resolution_flags: &[AtomicResolutionFlags],
) -> Result {
    layout_states.par_iter_mut().try_for_each(|state| {
        state.finalise_sizes(symbol_db, output_sections, symbol_resolution_flags)
    })
}

#[tracing::instrument(skip_all, name = "Merge dynamic symbol definitions")]
fn merge_dynamic_symbol_definitions(layout_states: &mut [FileLayoutState]) -> Result {
    let mut dynamic_symbol_definitions = Vec::new();
    for state in layout_states.iter() {
        if let Some(common) = state.common() {
            dynamic_symbol_definitions.extend(common.dynamic_symbol_definitions.iter().copied());
        }
    }
    let Some(FileLayoutState::Epilogue(epilogue)) = layout_states.last_mut() else {
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
pub struct Layout<'data> {
    pub(crate) symbol_db: &'data SymbolDb<'data>,
    pub(crate) symbol_resolutions: SymbolResolutions,
    pub(crate) section_part_layouts: OutputSectionPartMap<OutputRecordLayout>,
    pub(crate) section_layouts: OutputSectionMap<OutputRecordLayout>,
    pub(crate) file_layouts: Vec<FileLayout<'data>>,
    pub(crate) segment_layouts: SegmentLayouts,
    pub(crate) output_sections: OutputSections<'data>,
    pub(crate) non_addressable_counts: NonAddressableCounts,
    pub(crate) symbol_resolution_flags: Vec<ResolutionFlags>,
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
    Internal(InternalLayout<'data>),
    Object(ObjectLayout<'data>),
    Dynamic(DynamicLayout<'data>),
    Epilogue(EpilogueLayout<'data>),
    NotLoaded,
}

/// The addresses of the start of the merged strings for each output section.
pub(crate) struct MergedStringStartAddresses {
    addresses: OutputSectionMap<u64>,
}

/// Address information for a symbol or section.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct Resolution {
    /// An address or absolute value.
    pub(crate) raw_value: u64,

    pub(crate) dynamic_symbol_index: Option<NonZeroU32>,

    pub(crate) got_address: Option<NonZeroU64>,
    pub(crate) plt_address: Option<NonZeroU64>,
    pub(crate) resolution_flags: ResolutionFlags,
    pub(crate) value_flags: ValueFlags,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsMode {
    /// Convert TLS access to local-exec mode.
    LocalExec,

    /// Preserve TLS access mode of the input.
    Preserve,
}

enum FileLayoutState<'data> {
    Internal(Box<InternalLayoutState<'data>>),
    Object(Box<ObjectLayoutState<'data>>),
    Dynamic(Box<DynamicLayoutState<'data>>),
    NotLoaded,
    Epilogue(Box<EpilogueLayoutState<'data>>),
}

/// Data that doesn't come from any input files, but needs to be written by the linker.
struct InternalLayoutState<'data> {
    common: CommonLayoutState<'data>,
    internal_symbols: InternalSymbols,
    entry_symbol_id: Option<SymbolId>,
    needs_tlsld_got_entry: bool,
    merged_strings: OutputSectionMap<resolution::MergedStringsSection<'data>>,
    identity: String,
    header_info: Option<HeaderInfo>,
    dynamic_linker: Option<CString>,
}

pub(crate) struct EpilogueLayoutState<'data> {
    common: CommonLayoutState<'data>,
    internal_symbols: InternalSymbols,

    dynamic_symbol_definitions: Vec<DynamicSymbolDefinition<'data>>,
    gnu_hash_layout: Option<GnuHashLayout>,
}

#[derive(Default)]
pub(crate) struct GnuHashLayout {
    pub(crate) bucket_count: u32,
    pub(crate) bloom_shift: u32,
    pub(crate) bloom_count: u32,
    pub(crate) symbol_base: u32,
}

pub(crate) struct EpilogueLayout<'data> {
    pub(crate) mem_sizes: OutputSectionPartMap<u64>,
    pub(crate) file_sizes: OutputSectionPartMap<usize>,
    pub(crate) internal_symbols: InternalSymbols,
    pub(crate) strings_offset_start: u32,
    pub(crate) gnu_hash_layout: Option<GnuHashLayout>,
    pub(crate) dynamic_symbol_definitions: Vec<DynamicSymbolDefinition<'data>>,
    pub(crate) dynstr_offset_start: u32,
    dynsym_start_index: u32,
}

pub(crate) struct ObjectLayout<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) file_id: FileId,
    pub(crate) object: &'data File<'data>,
    pub(crate) mem_sizes: OutputSectionPartMap<u64>,
    pub(crate) file_sizes: OutputSectionPartMap<usize>,
    pub(crate) sections: Vec<SectionSlot<'data>>,
    pub(crate) section_resolutions: Vec<Option<Resolution>>,
    pub(crate) strtab_offset_start: u32,
    pub(crate) plt_relocations: Vec<IfuncRelocation>,
    /// The memory address of the start of this object's allocation within .eh_frame.
    pub(crate) eh_frame_start_address: u64,
    pub(crate) symbol_id_range: SymbolIdRange,
    pub(crate) merged_string_resolutions: Vec<Option<MergedStringResolution>>,
    pub(crate) dynstr_start_offset: u64,
}

pub(crate) struct InternalLayout<'data> {
    pub(crate) mem_sizes: OutputSectionPartMap<u64>,
    pub(crate) file_sizes: OutputSectionPartMap<usize>,
    pub(crate) strings_offset_start: u32,
    pub(crate) entry_symbol_id: Option<SymbolId>,
    pub(crate) tlsld_got_entry: Option<NonZeroU64>,
    pub(crate) merged_strings: OutputSectionMap<resolution::MergedStringsSection<'data>>,
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
    file_sizes: OutputSectionPartMap<usize>,

    /// The name we'll put into the binary to tell the dynamic loader what to load.
    pub(crate) lib_name: &'data [u8],

    /// The offset in .dynstr at which we'll start writing.
    pub(crate) dynstr_start_offset: u64,

    pub(crate) symbol_id_range: SymbolIdRange,

    pub(crate) object: &'data crate::elf::File<'data>,

    /// Mapping from local symbol indexes to versions in the input file.
    pub(crate) input_symbol_versions: &'data [Versym],

    pub(crate) version_mapping: Vec<u16>,
    pub(crate) verdef_info: Option<VerdefInfo<'data>>,

    /// Whether this is the last DynamicLayout that puts content into .gnu.version_r.
    pub(crate) is_last_verneed: bool,
}

#[derive(Debug)]
pub(crate) struct IfuncRelocation {
    pub(crate) resolver: u64,
    pub(crate) got_address: u64,
}

trait SymbolRequestHandler<'data>: std::fmt::Display {
    fn finalise_symbol_sizes(
        &mut self,
        symbol_db: &SymbolDb,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        let symbol_id_range = self.symbol_id_range();
        let common = self.common_mut();
        for (local_index, resolution_flags) in symbol_resolution_flags[symbol_id_range.as_usize()]
            .iter()
            .enumerate()
        {
            let symbol_id = symbol_id_range.offset_to_id(local_index);
            if !symbol_db.is_canonical(symbol_id) {
                continue;
            }
            let value_flags = symbol_db.local_symbol_value_flags(symbol_id);

            if value_flags.contains(ValueFlags::DYNAMIC) && !resolution_flags.get().is_empty() {
                let name = symbol_db.symbol_name(symbol_id)?;
                common.mem_sizes.dynstr += name.len() as u64 + 1;
                common.mem_sizes.dynsym += crate::elf::SYMTAB_ENTRY_SIZE;
            }

            allocate_symbol_resolution(
                value_flags,
                resolution_flags,
                &mut common.mem_sizes,
                symbol_db.args.output_kind,
            );
        }
        if symbol_db.args.should_output_symbol_versions() {
            let num_dynamic_symbols = common.mem_sizes.dynsym / crate::elf::SYMTAB_ENTRY_SIZE;
            common.mem_sizes.gnu_version = num_dynamic_symbols * crate::elf::GNU_VERSION_ENTRY_SIZE;
        }
        Ok(())
    }

    fn symbol_id_range(&self) -> SymbolIdRange;

    fn common_mut(&mut self) -> &mut CommonLayoutState<'data>;

    fn file_id(&self) -> FileId;

    fn export_dynamic<'scope>(
        &mut self,
        symbol_id: SymbolId,
        graph_resources: &GraphResources<'data, 'scope>,
    ) -> Result {
        let name = graph_resources.symbol_db.symbol_name(symbol_id)?;
        self.common_mut()
            .dynamic_symbol_definitions
            .push(DynamicSymbolDefinition::new(symbol_id, name.bytes()));
        Ok(())
    }

    fn load_symbol<'scope>(
        &mut self,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result;
}

fn allocate_symbol_resolution(
    value_flags: ValueFlags,
    resolution_flags: &AtomicResolutionFlags,
    mem_sizes: &mut OutputSectionPartMap<u64>,
    output_kind: OutputKind,
) {
    if value_flags.contains(ValueFlags::IFUNC) {
        resolution_flags.fetch_or(ResolutionFlags::GOT | ResolutionFlags::PLT);
        mem_sizes.rela_plt += elf::RELA_ENTRY_SIZE;
    }
    let resolution_flags = resolution_flags.get();
    if resolution_flags.contains(ResolutionFlags::PLT) {
        mem_sizes.plt += elf::PLT_ENTRY_SIZE;
    }

    allocate_resolution(value_flags, resolution_flags, mem_sizes, output_kind);
}

fn allocate_resolution(
    value_flags: ValueFlags,
    resolution_flags: ResolutionFlags,
    mem_sizes: &mut OutputSectionPartMap<u64>,
    output_kind: OutputKind,
) {
    if resolution_flags.contains(ResolutionFlags::GOT) {
        mem_sizes.got += elf::GOT_ENTRY_SIZE;
        if output_kind.is_relocatable() && !value_flags.contains(ValueFlags::IFUNC) {
            if value_flags.contains(ValueFlags::DYNAMIC)
                || (resolution_flags.contains(ResolutionFlags::EXPORT_DYNAMIC)
                    && !value_flags.contains(ValueFlags::CAN_BYPASS_GOT))
            {
                mem_sizes.rela_dyn_glob_dat += elf::RELA_ENTRY_SIZE;
            } else if value_flags.contains(ValueFlags::ADDRESS)
                && !resolution_flags.contains(ResolutionFlags::TLS)
            {
                mem_sizes.rela_dyn_relative += elf::RELA_ENTRY_SIZE;
            }
        }
    }
    if resolution_flags.contains(ResolutionFlags::GOT_TLS_MODULE) {
        mem_sizes.got += elf::GOT_ENTRY_SIZE;
        // For executables, the TLS module ID is known at link time. For shared objects, we
        // need a runtime relocation to fill it in.
        if !output_kind.is_executable() {
            mem_sizes.rela_dyn_glob_dat += elf::RELA_ENTRY_SIZE;
        }
    }
}

impl<'data> SymbolRequestHandler<'data> for ObjectLayoutState<'data> {
    fn common_mut(&mut self) -> &mut CommonLayoutState<'data> {
        &mut self.state.common
    }

    fn load_symbol<'scope>(
        &mut self,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        debug_assert_bail!(
            resources.symbol_db.is_canonical(symbol_id),
            "Tried to load symbol in a file that doesn't hold the definition: {}",
            resources.symbol_db.symbol_debug(symbol_id)
        );
        let object_symbol_index = self.state.common.symbol_id_range.id_to_input(symbol_id);
        let local_symbol = self.object.symbol(object_symbol_index)?;
        if let Some(section_id) = self
            .object
            .symbol_section(local_symbol, object_symbol_index)?
        {
            self.state
                .sections_required
                .push(SectionRequest::new(section_id));
            self.load_sections(resources, queue)?;
        } else if local_symbol.is_common(LittleEndian) {
            let common = CommonSymbol::new(local_symbol)?;
            *self
                .state
                .common
                .mem_sizes
                .regular_mut(output_section_id::BSS, common.alignment) += common.size;
        }
        Ok(())
    }

    fn file_id(&self) -> FileId {
        self.state.common.file_id
    }

    fn symbol_id_range(&self) -> SymbolIdRange {
        self.state.common.symbol_id_range
    }
}

impl<'data> SymbolRequestHandler<'data> for DynamicLayoutState<'data> {
    fn symbol_id_range(&self) -> SymbolIdRange {
        self.common.symbol_id_range
    }

    fn common_mut(&mut self) -> &mut CommonLayoutState<'data> {
        &mut self.common
    }

    fn file_id(&self) -> FileId {
        self.common.file_id
    }

    fn load_symbol<'scope>(
        &mut self,
        symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope>,
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

    fn export_dynamic<'scope>(
        &mut self,
        _symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope>,
    ) -> Result {
        // Nothing to do. We're a dynamic object that presumably already exports this symbol.
        Ok(())
    }
}

impl<'data> SymbolRequestHandler<'data> for InternalLayoutState<'data> {
    fn common_mut(&mut self) -> &mut CommonLayoutState<'data> {
        &mut self.common
    }

    fn file_id(&self) -> FileId {
        self.common.file_id
    }

    fn load_symbol<'scope>(
        &mut self,
        _symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope>,
        _queue: &mut LocalWorkQueue,
    ) -> Result {
        Ok(())
    }

    fn export_dynamic<'scope>(
        &mut self,
        _symbol_id: SymbolId,
        _graph_resources: &GraphResources<'data, 'scope>,
    ) -> Result {
        Ok(())
    }

    fn symbol_id_range(&self) -> SymbolIdRange {
        self.common.symbol_id_range
    }
}

impl<'data> SymbolRequestHandler<'data> for EpilogueLayoutState<'data> {
    fn common_mut(&mut self) -> &mut CommonLayoutState<'data> {
        &mut self.common
    }

    fn file_id(&self) -> FileId {
        self.common.file_id
    }

    fn load_symbol<'scope>(
        &mut self,
        _symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope>,
        _queue: &mut LocalWorkQueue,
    ) -> Result {
        Ok(())
    }

    fn symbol_id_range(&self) -> SymbolIdRange {
        self.common.symbol_id_range
    }
}

struct CommonLayoutState<'data> {
    file_id: FileId,
    mem_sizes: OutputSectionPartMap<u64>,

    /// Which sections have we loaded an input section into. This is not the same as checking
    /// whether the mem sizes for that section are non-zero because we can load an input section
    /// with size 0. If we do that, we still need to produce the output section so that we have
    /// something to refer to in the symtab.
    sections_with_content: OutputSectionMap<bool>,

    symbol_id_range: SymbolIdRange,

    /// Dynamic symbols defined by this object. Because of the ordering requirements for symbol
    /// hashes, these get defined by the epilogue.
    dynamic_symbol_definitions: Vec<DynamicSymbolDefinition<'data>>,
}

impl CommonLayoutState<'_> {
    fn new(
        file_id: FileId,
        output_sections: &OutputSections,
        symbol_id_range: SymbolIdRange,
    ) -> Self {
        Self {
            file_id,
            mem_sizes: OutputSectionPartMap::with_size(output_sections.len()),
            sections_with_content: OutputSectionMap::with_size(output_sections.len()),
            symbol_id_range,
            dynamic_symbol_definitions: Default::default(),
        }
    }

    fn finalise_layout(
        &self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
    ) -> u32 {
        // strtab
        let offset = &mut memory_offsets.symtab_strings;
        let strtab_offset_start = (*offset
            - section_layouts
                .built_in(output_section_id::STRTAB)
                .mem_offset)
            .try_into()
            .expect("Symbol string table overflowed 32 bits");
        *offset += self.mem_sizes.symtab_strings;

        // symtab
        memory_offsets.symtab_locals += self.mem_sizes.symtab_locals;
        memory_offsets.symtab_globals += self.mem_sizes.symtab_globals;

        strtab_offset_start
    }

    fn create_global_address_emitter<'state>(
        &'state self,
        memory_offsets: &OutputSectionPartMap<u64>,
        symbol_resolution_flags: &'state [ResolutionFlags],
    ) -> GlobalAddressEmitter<'state> {
        GlobalAddressEmitter {
            next_got_address: memory_offsets.got,
            next_plt_address: memory_offsets.plt,
            symbol_resolution_flags,
            plt_relocations: Default::default(),
            symbol_id_range: self.symbol_id_range,
        }
    }
}

struct ObjectLayoutState<'data> {
    input: InputRef<'data>,
    object: &'data File<'data>,
    state: ObjectLayoutMutableState<'data>,
    section_frame_data: Vec<SectionFrameData<'data>>,
    eh_frame_section: Option<&'data object::elf::SectionHeader64<LittleEndian>>,
}

/// The parts of `ObjectLayoutState` that we mutate during layout. Separate so that we can pass
/// mutable references to it while holding shared references to the other bits of
/// `ObjectLayoutState`.
struct ObjectLayoutMutableState<'data> {
    common: CommonLayoutState<'data>,

    /// Info about each of our sections. Empty until this object has been activated. Indexed the
    /// same as the sections in the input object.
    sections: Vec<SectionSlot<'data>>,

    /// A queue of sections that we need to load.
    sections_required: Vec<SectionRequest>,

    merged_string_resolutions: Vec<Option<MergedStringResolution>>,

    cies: SmallVec<[CieAtOffset<'data>; 2]>,
}

#[derive(Default)]
struct SectionFrameData<'data> {
    /// Outgoing references from the FDE(s) for our section. Generally all relocations for a section
    /// would be contiguous, so we'd only need one slice. In theory though it's possible that there
    /// could be more than one group, so we accommodate that, but optimise for the common case of
    /// one group.
    relocations: SmallVec<[&'data [Rela64<LittleEndian>]; 1]>,

    /// Number of FDEs associated with symbols in this section.
    num_fdes: u32,

    /// Number of bytes required to store the FDEs associated with this section.
    total_fde_size: u32,
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
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) struct ResolutionFlags: u8 {
        /// The direct value is needed. e.g. via a relative or absolute relocation that doesn't use the
        /// PLT or GOT.
        const DIRECT = 1 << 0;

        /// An address in the global offset table is needed.
        const GOT = 1 << 1;

        /// A PLT entry is needed.
        const PLT = 1 << 2;

        /// A second GOT entry is needed in order to store the module number. Only set for TLS
        /// variables.
        const GOT_TLS_MODULE = 1 << 3;

        const TLS = 1 << 4;

        /// The request originated from a dynamic object, so the symbol should be put into the dynamic
        /// symbol table.
        const EXPORT_DYNAMIC = 1 << 5;
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
    common: CommonLayoutState<'data>,
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

#[derive(Debug)]
pub(crate) struct Section<'data> {
    pub(crate) index: object::SectionIndex,
    pub(crate) output_section_id: Option<OutputSectionId>,
    /// Size in memory.
    pub(crate) size: u64,
    /// Our data. May be empty if we're in a zero-initialised section.
    pub(crate) data: &'data [u8],
    pub(crate) alignment: Alignment,
    pub(crate) resolution_kind: ResolutionFlags,
    packed: bool,
}

struct FileWorker<'data> {
    queue: LocalWorkQueue,
    state: FileLayoutState<'data>,
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

    worker_slots: Vec<Mutex<WorkerSlot<'data>>>,

    errors: Mutex<Vec<Error>>,

    waiting_workers: ArrayQueue<FileWorker<'data>>,

    /// A queue in which we store threads when they're idle so that other threads can wake them up
    /// when more work comes in. We always have one less slot in this array than the number of
    /// threads, since we never want all threads to be idle because that means we're finished. None
    /// if we're running with a single thread - mostly because ArrayQueue panics if we try to create
    /// an instance with zero size.
    idle_threads: Option<ArrayQueue<std::thread::Thread>>,

    done: AtomicBool,
    output_sections: &'scope OutputSections<'data>,

    symbol_resolution_flags: &'scope [AtomicResolutionFlags],
}

#[derive(Copy, Clone, Debug)]
enum WorkItem {
    LoadGlobalSymbol(SymbolId),
    ExportSymbol(SymbolId),
}

impl<'data> Layout<'data> {
    pub(crate) fn internal(&self) -> &InternalLayout {
        let Some(FileLayout::Internal(i)) = self.file_layouts.first() else {
            panic!("Internal layout not found at expected offset");
        };
        i
    }

    pub(crate) fn args(&self) -> &'data Args {
        self.symbol_db.args
    }

    pub(crate) fn symbol_debug(&self, symbol_id: SymbolId) -> SymbolDebug {
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
            .internal()
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
        let tdata = &self.section_layouts.built_in(output_section_id::TDATA);
        tdata.mem_offset
    }

    /// Returns the memory address of the end of the TLS segment including any padding required to
    /// make sure that the TCB will be usize-aligned.
    pub(crate) fn tls_end_address(&self) -> u64 {
        let tbss = self.section_layouts.built_in(output_section_id::TBSS);
        let tdata = self.section_layouts.built_in(output_section_id::TDATA);
        let tls_end = tbss.mem_offset + tbss.mem_size;
        let alignment = tbss.alignment.max(tdata.alignment);
        alignment.align_up(tls_end)
    }

    pub(crate) fn vma_of_section(&self, section_id: OutputSectionId) -> u64 {
        self.section_layouts.get(section_id).mem_offset
    }

    pub(crate) fn size_of_section(&self, section_id: OutputSectionId) -> u64 {
        self.section_layouts.get(section_id).file_size as u64
    }

    pub(crate) fn has_data_in_section(&self, id: OutputSectionId) -> bool {
        alignment::all_alignments()
            .any(|alignment| self.section_part_layouts.regular(id, alignment).mem_size > 0)
    }

    pub(crate) fn layout_data(&self) -> linker_layout::Layout {
        let e = object::LittleEndian;
        let files = self
            .file_layouts
            .iter()
            .filter_map(|file| match file {
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
                        .map(|((maybe_res, section), section_slot)| {
                            maybe_res.and_then(|res| {
                                (matches!(section_slot, SectionSlot::Loaded(..))
                                    && section.sh_size.get(e) > 0)
                                    .then(|| {
                                        let address = res.address().unwrap();
                                        linker_layout::Section {
                                            mem_range: address..(address + section.sh_size.get(e)),
                                        }
                                    })
                            })
                        })
                        .collect(),
                }),
                _ => None,
            })
            .collect();
        linker_layout::Layout { files }
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

#[tracing::instrument(skip_all, name = "Compute per-file start offsets")]
fn compute_start_offsets_by_file(
    layout_states: &[FileLayoutState<'_>],
    mut mem_offsets: OutputSectionPartMap<u64>,
) -> Vec<Option<OutputSectionPartMap<u64>>> {
    layout_states
        .iter()
        .map(|file| {
            if let Some(sizes) = file.mem_sizes() {
                let file_mem_starts = mem_offsets.clone();
                mem_offsets.merge(sizes);
                Some(file_mem_starts)
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
}

#[tracing::instrument(skip_all, name = "Assign symbol addresses")]
fn compute_symbols_and_layouts<'data>(
    layout_states: Vec<FileLayoutState<'data>>,
    starting_mem_offsets_by_file: Vec<Option<OutputSectionPartMap<u64>>>,
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
    symbol_db: &SymbolDb<'data>,
    merged_string_start_addresses: &MergedStringStartAddresses,
    output_sections: &OutputSections,
    symbol_resolutions: &mut [&mut [Option<Resolution>]],
    symbol_resolution_flags: &[ResolutionFlags],
) -> Result<Vec<FileLayout<'data>>> {
    layout_states
        .into_par_iter()
        .zip(starting_mem_offsets_by_file)
        .zip(symbol_resolutions)
        .map(|((state, mut memory_offsets), symbols_out)| {
            state.finalise_layout(
                memory_offsets.as_mut(),
                section_layouts,
                symbol_db,
                merged_string_start_addresses,
                output_sections,
                symbols_out,
                symbol_resolution_flags,
            )
        })
        .collect()
}

#[tracing::instrument(skip_all, name = "Compute segment layouts")]
fn compute_segment_layout(
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
    output_sections: &OutputSections,
    header_info: &HeaderInfo,
) -> SegmentLayouts {
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
    let mut active_records = AHashMap::new();
    output_sections.sections_and_segments_do(|event| match event {
        OrderEvent::SegmentStart(segment_id) => {
            active_records.insert(
                segment_id,
                Record {
                    segment_id,
                    file_start: usize::MAX,
                    file_end: 0,
                    mem_start: u64::MAX,
                    mem_end: 0,
                    alignment: alignment::MIN,
                },
            );
        }
        OrderEvent::SegmentEnd(segment_id) => {
            let record = active_records
                .remove(&segment_id)
                .expect("SegmentEnd without matching SegmentStart");
            complete.push(record);
        }
        OrderEvent::Section(section_id, _section_details) => {
            let part = section_layouts.get(section_id);
            for rec in active_records.values_mut() {
                rec.file_start = rec.file_start.min(part.file_offset);
                rec.mem_start = rec.mem_start.min(part.mem_offset);
                rec.file_end = rec.file_end.max(part.file_offset + part.file_size);
                rec.mem_end = rec.mem_end.max(part.mem_offset + part.mem_size);
                rec.alignment = rec.alignment.max(part.alignment);
            }
        }
    });
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
    SegmentLayouts {
        segments,
        tls_start_address,
    }
}

#[tracing::instrument(skip_all, name = "Compute total section sizes")]
fn compute_total_section_part_sizes(
    layout_states: &mut [FileLayoutState],
    output_sections: &mut OutputSections,
    symbol_resolution_flags: &[ResolutionFlags],
) -> OutputSectionPartMap<u64> {
    let mut total_sizes: OutputSectionPartMap<u64> =
        OutputSectionPartMap::with_size(output_sections.len());
    let mut sections_with_content: OutputSectionMap<bool> =
        OutputSectionMap::with_size(output_sections.len());
    for file_state in layout_states.iter() {
        if let Some(sizes) = file_state.mem_sizes() {
            total_sizes.merge(sizes);
        }
        if let Some(common) = file_state.common() {
            sections_with_content.merge(&common.sections_with_content, |a, b| a | b);
        }
    }
    let FileLayoutState::Internal(internal_layout) =
        &mut layout_states[INTERNAL_FILE_ID.as_usize()]
    else {
        unreachable!();
    };
    internal_layout.determine_header_sizes(
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
    layout_states: &mut [FileLayoutState],
    args: &Args,
) -> Result<NonAddressableCounts> {
    let mut indexes = NonAddressableIndexes {
        // Allocate version indexes starting from after the local and global indexes.
        gnu_version_r_index: object::elf::VER_NDX_GLOBAL + 1,
    };
    let mut counts = NonAddressableCounts { verneed_count: 0 };
    for s in layout_states.iter_mut() {
        match s {
            FileLayoutState::Dynamic(s) => {
                s.apply_non_addressable_indexes(&mut indexes, &mut counts)?
            }
            _ => {}
        }
    }

    // If we were going to output symbol versions, but we didn't actually use any, then we drop all
    // versym allocations. This is partly to avoid wasting unnecessary space in the output file, but
    // mostly in order match what GNU ld does.
    if counts.verneed_count == 0 && args.should_output_symbol_versions() {
        for s in layout_states {
            match s {
                FileLayoutState::Internal(s) => s.common.mem_sizes.gnu_version = 0,
                FileLayoutState::Object(s) => s.state.common.mem_sizes.gnu_version = 0,
                FileLayoutState::Dynamic(s) => s.common.mem_sizes.gnu_version = 0,
                FileLayoutState::Epilogue(s) => s.common.mem_sizes.gnu_version = 0,
                _ => {}
            }
        }
    }
    Ok(counts)
}

#[derive(Clone, Copy, Default)]
struct NonAddressableIndexes {
    gnu_version_r_index: u16,
}

pub(crate) struct NonAddressableCounts {
    /// The number of shared objects that want to emit a verneed record.
    pub(crate) verneed_count: u64,
}

/// Returns the starting memory address for each alignment within each segment.
#[tracing::instrument(skip_all, name = "Compute per-alignment offsets")]
fn starting_memory_offsets(
    section_layouts: &OutputSectionPartMap<OutputRecordLayout>,
    output_sections: &OutputSections,
) -> OutputSectionPartMap<u64> {
    section_layouts.map(output_sections, |_, rec| rec.mem_offset)
}

#[derive(Default)]
struct WorkerSlot<'data> {
    work: Vec<WorkItem>,
    worker: Option<FileWorker<'data>>,
}

#[tracing::instrument(skip_all, name = "Find required sections")]
fn find_required_sections<'data>(
    file_states: Vec<resolution::ResolvedFile<'data>>,
    symbol_db: &SymbolDb<'data>,
    output_sections: &OutputSections<'data>,
    symbol_resolution_flags: &[AtomicResolutionFlags],
) -> Result<Vec<FileLayoutState<'data>>> {
    let num_workers = file_states.len();
    let (worker_slots, workers) = create_worker_slots(file_states, output_sections);

    let num_threads = symbol_db.args.num_threads.get();

    let idle_threads = (num_threads > 1).then(|| ArrayQueue::new(num_threads - 1));
    let resources = &GraphResources {
        symbol_db,
        worker_slots,
        errors: Mutex::new(Vec::new()),
        waiting_workers: ArrayQueue::new(num_workers),
        // NB, the -1 is because we never want all our threads to be idle. Once the last thread is
        // about to go idle, we're done and need to wake up and terminate all the the threads.
        idle_threads,
        done: AtomicBool::new(false),
        output_sections,
        symbol_resolution_flags,
    };

    workers
        .into_par_iter()
        .try_for_each(|mut worker| -> Result {
            worker
                .activate(resources)
                .with_context(|| format!("Failed to activate {}", worker.state))?;
            let _ = resources.waiting_workers.push(worker);
            Ok(())
        })?;

    std::thread::scope(|scope| {
        for _ in 0..num_threads {
            scope.spawn(|| {
                let panic_result = std::panic::catch_unwind(|| {
                    let mut idle = false;
                    while !resources.done.load(atomic::Ordering::SeqCst) {
                        while let Some(worker) = resources.waiting_workers.pop() {
                            worker.do_pending_work(resources);
                        }
                        if idle {
                            // Wait until there's more work to do or until we shut down.
                            std::thread::park();
                            idle = false;
                        } else {
                            if resources
                                .idle_threads
                                .as_ref()
                                .map(|idle_threads| {
                                    idle_threads.push(std::thread::current()).is_err()
                                })
                                .unwrap_or(true)
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
    let mut errors: Vec<Error> = core::mem::take(resources.errors.lock().unwrap().as_mut());
    // TODO: Figure out good way to report more than one error.
    if let Some(error) = errors.pop() {
        return Err(error);
    }
    let worker_slots = &resources.worker_slots;
    unwrap_worker_states(worker_slots)
}

fn create_worker_slots<'data>(
    file_states: Vec<resolution::ResolvedFile<'data>>,
    output_sections: &OutputSections<'data>,
) -> (Vec<Mutex<WorkerSlot<'data>>>, Vec<FileWorker<'data>>) {
    file_states
        .into_iter()
        .enumerate()
        .map(|(index, f)| {
            let worker = FileWorker {
                queue: LocalWorkQueue::new(index),
                state: f.create_layout_state(output_sections),
            };
            let slot = WorkerSlot {
                work: Default::default(),
                worker: None,
            };
            (Mutex::new(slot), worker)
        })
        .unzip()
}

fn unwrap_worker_states<'data>(
    worker_slots: &[Mutex<WorkerSlot<'data>>],
) -> Result<Vec<FileLayoutState<'data>>> {
    Ok(worker_slots
        .iter()
        .filter_map(|w| w.lock().unwrap().worker.take())
        .map(|w| w.state)
        .collect())
}

impl<'data> FileWorker<'data> {
    /// Does work until there's nothing left in the queue, then returns our worker to its slot and
    /// shuts down.
    fn do_pending_work<'scope>(mut self, resources: &GraphResources<'data, 'scope>) {
        loop {
            while let Some(work_item) = self.queue.local_work.pop() {
                if let Err(error) = self.state.do_work(work_item, resources, &mut self.queue) {
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
                core::mem::swap(&mut slot.work, &mut self.queue.local_work);
            };
        }
    }

    fn activate(&mut self, resources: &GraphResources<'data, '_>) -> Result {
        match &mut self.state {
            FileLayoutState::Object(s) => s.activate(resources, &mut self.queue),
            FileLayoutState::Internal(s) => s.activate(resources),
            FileLayoutState::Dynamic(s) => s.activate(resources, &mut self.queue),
            FileLayoutState::NotLoaded => Ok(()),
            FileLayoutState::Epilogue(_) => Ok(()),
        }
    }
}

impl LocalWorkQueue {
    fn send_work(&mut self, resources: &GraphResources, file_id: FileId, work: WorkItem) {
        if file_id.as_usize() == self.index {
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

    fn send_symbol_request(&mut self, symbol_id: SymbolId, resources: &GraphResources) {
        debug_assert!(resources.symbol_db.is_canonical(symbol_id));
        let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        self.send_work(
            resources,
            symbol_file_id,
            WorkItem::LoadGlobalSymbol(symbol_id),
        );
    }

    fn send_export_dynamic_request(&mut self, symbol_id: SymbolId, resources: &GraphResources) {
        debug_assert!(resources.symbol_db.is_canonical(symbol_id));
        let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        self.send_work(resources, symbol_file_id, WorkItem::ExportSymbol(symbol_id));
    }
}

impl<'data, 'scope> GraphResources<'data, 'scope> {
    fn report_error(&self, error: Error) {
        self.errors.lock().unwrap().push(error);
    }

    /// Sends all work in `work` to the worker for `file_id`. Leaves `work` empty so that it can be
    /// reused.
    fn send_work(&self, file_id: FileId, work: WorkItem) {
        let worker;
        {
            let mut slot = self.worker_slots[file_id.as_usize()].lock().unwrap();
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
    fn finalise_sizes(
        &mut self,
        symbol_db: &SymbolDb,
        output_sections: &OutputSections,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        match self {
            FileLayoutState::Object(s) => {
                s.finalise_sizes(symbol_db, output_sections, symbol_resolution_flags)
                    .with_context(|| format!("finalise_sizes failed for {s}"))?;
                s.finalise_symbol_sizes(symbol_db, symbol_resolution_flags)?;
            }
            FileLayoutState::Dynamic(s) => {
                s.finalise_sizes()?;
                s.finalise_symbol_sizes(symbol_db, symbol_resolution_flags)?;
            }
            FileLayoutState::Internal(s) => {
                s.finalise_sizes(symbol_db, symbol_resolution_flags)?;
                s.finalise_symbol_sizes(symbol_db, symbol_resolution_flags)?;
            }
            FileLayoutState::Epilogue(s) => {
                s.finalise_sizes(symbol_db, symbol_resolution_flags)?;
                s.finalise_symbol_sizes(symbol_db, symbol_resolution_flags)?;
            }
            FileLayoutState::NotLoaded => {}
        }
        self.validate_sizes()?;
        Ok(())
    }

    fn do_work<'scope>(
        &mut self,
        work_item: WorkItem,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        match work_item {
            WorkItem::LoadGlobalSymbol(symbol_id) => self
                .handle_symbol_request(symbol_id, resources, queue)
                .with_context(|| {
                    format!(
                        "Failed to load {} from {self}",
                        resources.symbol_db.symbol_debug(symbol_id),
                    )
                }),
            WorkItem::ExportSymbol(symbol_id) => {
                self.handle_export_dynamic_request(symbol_id, resources)
            }
        }
    }

    fn handle_export_dynamic_request(
        &mut self,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, '_>,
    ) -> std::result::Result<(), Error> {
        match self {
            FileLayoutState::Internal(s) => s.export_dynamic(symbol_id, resources),
            FileLayoutState::Object(s) => s.export_dynamic(symbol_id, resources),
            FileLayoutState::Dynamic(s) => s.export_dynamic(symbol_id, resources),
            FileLayoutState::Epilogue(s) => s.export_dynamic(symbol_id, resources),
            FileLayoutState::NotLoaded => {
                panic!("Non-loaded file was asked to export a symbol")
            }
        }
    }

    fn handle_symbol_request<'scope>(
        &mut self,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        match self {
            FileLayoutState::Object(state) => {
                state.load_symbol(symbol_id, resources, queue)?;
            }
            FileLayoutState::Internal(state) => {
                state.load_symbol(symbol_id, resources, queue)?;
            }
            FileLayoutState::Dynamic(state) => state.load_symbol(symbol_id, resources, queue)?,
            FileLayoutState::NotLoaded => {}
            FileLayoutState::Epilogue(state) => state.load_symbol(symbol_id, resources, queue)?,
        }
        Ok(())
    }

    pub(crate) fn mem_sizes(&self) -> Option<&OutputSectionPartMap<u64>> {
        match self {
            Self::Object(s) => Some(&s.state.common.mem_sizes),
            Self::Internal(s) => Some(&s.common.mem_sizes),
            Self::Dynamic(s) => Some(&s.common.mem_sizes),
            Self::NotLoaded => None,
            Self::Epilogue(s) => Some(&s.common.mem_sizes),
        }
    }

    pub(crate) fn common(&self) -> Option<&CommonLayoutState<'data>> {
        match self {
            Self::Object(s) => Some(&s.state.common),
            Self::Internal(s) => Some(&s.common),
            Self::Epilogue(s) => Some(&s.common),
            Self::Dynamic(s) => Some(&s.common),
            Self::NotLoaded => None,
        }
    }

    fn finalise_layout(
        self,
        memory_offsets: Option<&mut OutputSectionPartMap<u64>>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
        symbol_db: &SymbolDb,
        merged_string_start_addresses: &MergedStringStartAddresses,
        output_sections: &OutputSections,
        addresses_out: &mut [Option<Resolution>],
        symbol_resolution_flags: &[ResolutionFlags],
    ) -> Result<FileLayout<'data>> {
        let file_layout = match self {
            Self::Object(s) => FileLayout::Object(s.finalise_layout(
                memory_offsets.unwrap(),
                addresses_out,
                section_layouts,
                symbol_db,
                output_sections,
                merged_string_start_addresses,
                symbol_resolution_flags,
            )?),
            Self::Internal(s) => FileLayout::Internal(s.finalise_layout(
                memory_offsets.unwrap(),
                section_layouts,
                addresses_out,
                output_sections,
                symbol_db,
                symbol_resolution_flags,
            )?),
            Self::Epilogue(s) => FileLayout::Epilogue(s.finalise_layout(
                memory_offsets.unwrap(),
                section_layouts,
                addresses_out,
                output_sections,
                symbol_db,
                symbol_resolution_flags,
            )?),
            Self::Dynamic(s) => FileLayout::Dynamic(s.finalise_layout(
                memory_offsets.unwrap(),
                section_layouts,
                addresses_out,
                output_sections,
                symbol_resolution_flags,
            )?),
            Self::NotLoaded => FileLayout::NotLoaded,
        };
        Ok(file_layout)
    }

    fn validate_sizes(&self) -> Result {
        if let Some(common) = self.common() {
            if common.mem_sizes.gnu_version > 0 {
                let num_dynamic_symbols = common.mem_sizes.dynsym / crate::elf::SYMTAB_ENTRY_SIZE;
                let num_versym =
                    common.mem_sizes.gnu_version / core::mem::size_of::<Versym>() as u64;
                if num_versym != num_dynamic_symbols {
                    bail!(
                        "Object has {num_dynamic_symbols} dynamic symbols, but \
                         has versym {num_versym} entries"
                    );
                }
            }
        }
        Ok(())
    }
}

impl<'data> FileLayout<'data> {
    pub(crate) fn file_sizes(&self) -> Option<&OutputSectionPartMap<usize>> {
        match self {
            Self::Object(s) => Some(&s.file_sizes),
            Self::Internal(s) => Some(&s.file_sizes),
            Self::Epilogue(s) => Some(&s.file_sizes),
            Self::NotLoaded => None,
            Self::Dynamic(s) => Some(&s.file_sizes),
        }
    }
}

fn compute_file_sizes(
    mem_sizes: &OutputSectionPartMap<u64>,
    output_sections: &OutputSections<'_>,
) -> OutputSectionPartMap<usize> {
    mem_sizes.map(output_sections, |output_section_id, size| {
        if output_sections.has_data_in_file(output_section_id) {
            *size as usize
        } else {
            0
        }
    })
}

impl<'data> std::fmt::Display for InternalLayoutState<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt("<internal>", f)
    }
}

impl<'data> std::fmt::Display for EpilogueLayoutState<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt("<custom sections>", f)
    }
}

impl<'data> std::fmt::Display for FileLayoutState<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileLayoutState::Object(s) => std::fmt::Display::fmt(s, f),
            FileLayoutState::Dynamic(s) => std::fmt::Display::fmt(s, f),
            FileLayoutState::Internal(_) => std::fmt::Display::fmt("<internal>", f),
            FileLayoutState::NotLoaded => std::fmt::Display::fmt("<not-loaded>", f),
            FileLayoutState::Epilogue(_) => std::fmt::Display::fmt("<custom sections>", f),
        }
    }
}

impl<'data> std::fmt::Display for FileLayout<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Object(s) => std::fmt::Display::fmt(s, f),
            Self::Dynamic(s) => std::fmt::Display::fmt(s, f),
            Self::Internal(_) => std::fmt::Display::fmt("<internal>", f),
            Self::Epilogue(_) => std::fmt::Display::fmt("<custom sections>", f),
            Self::NotLoaded => std::fmt::Display::fmt("<not loaded>", f),
        }
    }
}

impl<'data> std::fmt::Debug for FileLayout<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self, f)
    }
}

impl<'data> std::fmt::Display for ObjectLayoutState<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        // TODO: This is mostly for debugging use. Consider only showing this if some environment
        // variable is set, or only in debug builds.
        write!(f, " ({})", self.file_id())
    }
}

impl<'data> std::fmt::Display for DynamicLayoutState<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        write!(f, " ({})", self.file_id())
    }
}

impl<'data> std::fmt::Display for DynamicLayout<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        write!(f, " ({})", self.file_id)
    }
}

impl<'data> std::fmt::Display for ObjectLayout<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        // TODO: This is mostly for debugging use. Consider only showing this if some environment
        // variable is set, or only in debug builds.
        write!(f, " ({})", self.file_id)
    }
}

struct SectionRequest {
    id: object::SectionIndex,
    resolution_kind: ResolutionFlags,
}

impl SectionRequest {
    fn new(id: object::SectionIndex) -> Self {
        Self {
            id,
            resolution_kind: ResolutionFlags::empty(),
        }
    }
}

impl<'data> Section<'data> {
    fn create<'scope>(
        worker: &mut ObjectLayoutState<'data>,
        queue: &mut LocalWorkQueue,
        unloaded: &UnloadedSection<'data>,
        section_id: object::SectionIndex,
        resources: &GraphResources<'data, 'scope>,
    ) -> Result<Section<'data>> {
        let e = LittleEndian;
        let object_section = worker.object.section(section_id)?;
        let alignment = Alignment::new(object_section.sh_addralign(e))?;
        let size = object_section.sh_size(e);
        let section_data = worker.object.section_data(object_section)?;
        for rel in worker.object.relocations(section_id)? {
            apply_relocation(worker, rel, object_section, resources, queue)?;
        }
        let section = Section {
            index: section_id,
            output_section_id: None,
            alignment,
            size,
            data: section_data,
            resolution_kind: ResolutionFlags::empty(),
            packed: unloaded.details.packed,
        };
        Ok(section)
    }

    // How much space we take up. This is our size rounded up to the next multiple of our alignment,
    // unless we're in a packed section, in which case it's just our size.
    pub(crate) fn capacity(&self) -> u64 {
        if self.packed {
            self.size
        } else {
            self.alignment.align_up(self.size)
        }
    }
}

fn apply_relocation(
    object: &mut ObjectLayoutState,
    rel: &Rela64<LittleEndian>,
    section: &object::elf::SectionHeader64<LittleEndian>,
    resources: &GraphResources,
    queue: &mut LocalWorkQueue,
) -> Result {
    let args = resources.symbol_db.args;
    let state = &mut object.state;
    if let Some(local_sym_index) = rel.symbol(LittleEndian, false) {
        let symbol_db = resources.symbol_db;
        let symbol_id =
            symbol_db.definition(state.common.symbol_id_range.input_to_id(local_sym_index));
        let symbol_value_flags = symbol_db.local_symbol_value_flags(symbol_id);
        let rel_offset = rel.r_offset.get(LittleEndian);
        let mut r_type = rel.r_type(LittleEndian, false);
        if let Some((_relaxation, new_r_type)) = Relaxation::new(
            r_type,
            object.object.section_data(section)?,
            rel_offset,
            symbol_value_flags,
            args.output_kind,
        ) {
            r_type = new_r_type;
        }
        let rel_info = RelocationKindInfo::from_raw(r_type)?;
        let resolution_kind = resolution_flags(rel_info.kind);
        match (args.is_relocatable(), rel_info.kind) {
            (true, RelocationKind::Absolute)
                if symbol_value_flags.contains(ValueFlags::ADDRESS) =>
            {
                state.common.mem_sizes.rela_dyn_relative += elf::RELA_ENTRY_SIZE;
            }
            (_, RelocationKind::Absolute | RelocationKind::Relative)
                if symbol_value_flags.contains(ValueFlags::DYNAMIC)
                    || resolution_kind.contains(ResolutionFlags::EXPORT_DYNAMIC) =>
            {
                state.common.mem_sizes.rela_dyn_glob_dat += elf::RELA_ENTRY_SIZE;
            }
            _ => {}
        }
        let previous_flags =
            resources.symbol_resolution_flags[symbol_id.as_usize()].fetch_or(resolution_kind);
        if previous_flags.is_empty() {
            queue.send_symbol_request(symbol_id, resources);
        }
    }
    Ok(())
}

fn resolution_flags(rel_kind: RelocationKind) -> ResolutionFlags {
    match rel_kind {
        RelocationKind::PltRelative => ResolutionFlags::PLT | ResolutionFlags::GOT,
        RelocationKind::Got | RelocationKind::GotRelative => ResolutionFlags::GOT,
        RelocationKind::GotTpOff => ResolutionFlags::GOT | ResolutionFlags::TLS,
        RelocationKind::TlsGd => {
            ResolutionFlags::GOT | ResolutionFlags::TLS | ResolutionFlags::GOT_TLS_MODULE
        }
        RelocationKind::TlsLd => ResolutionFlags::empty(),
        RelocationKind::Absolute => ResolutionFlags::DIRECT,
        RelocationKind::Relative => ResolutionFlags::DIRECT,
        RelocationKind::DtpOff | RelocationKind::TpOff => ResolutionFlags::DIRECT,
        RelocationKind::None => ResolutionFlags::DIRECT,
    }
}

impl<'data> InternalLayoutState<'data> {
    fn new(
        input_state: resolution::ResolvedInternal<'data>,
        output_sections: &OutputSections,
    ) -> Self {
        let mut layout = Self {
            common: CommonLayoutState::new(
                INTERNAL_FILE_ID,
                output_sections,
                SymbolIdRange::internal(input_state.symbol_definitions.len()),
            ),
            internal_symbols: InternalSymbols {
                symbol_definitions: input_state.symbol_definitions.to_owned(),
                start_symbol_id: SymbolId::zero(),
            },
            entry_symbol_id: None,
            needs_tlsld_got_entry: false,
            merged_strings: input_state.merged_strings,
            identity: crate::identity::linker_identity(),
            header_info: None,
            dynamic_linker: None,
        };

        layout.merged_strings.for_each(|section_id, merged| {
            if merged.len > 0 {
                *layout
                    .common
                    .mem_sizes
                    .regular_mut(section_id, alignment::MIN) += merged.len;
            }
        });

        // Allocate space to store the identify of the linker in the .comment section.
        *layout
            .common
            .mem_sizes
            .regular_mut(output_section_id::COMMENT, alignment::MIN) +=
            layout.identity.len() as u64;

        layout
    }

    fn activate(&mut self, resources: &GraphResources) -> Result {
        // The first entry in the symbol table must be null. Similarly, the first string in the
        // strings table must be empty.
        if !resources.symbol_db.args.strip_all {
            self.common.mem_sizes.symtab_locals = size_of::<elf::SymtabEntry>() as u64;
            self.common.mem_sizes.symtab_strings = 1;
        }

        if resources.symbol_db.args.output_kind.is_executable() {
            self.load_entry_point(resources)?;
        }
        if resources.symbol_db.args.tls_mode() == TlsMode::Preserve {
            // Allocate space for a TLS module number and offset for use with TLSLD relocations.
            self.common.mem_sizes.got += elf::GOT_ENTRY_SIZE * 2;
            self.needs_tlsld_got_entry = true;
            // For shared objects, we'll need to use a DTPMOD relocation to fill in the TLS module
            // number.
            if !resources.symbol_db.args.output_kind.is_executable() {
                self.common.mem_sizes.rela_dyn_glob_dat += crate::elf::RELA_ENTRY_SIZE;
            }
        }

        if resources.symbol_db.args.is_relocatable() {
            // Allocate space for the null symbol.
            self.common.mem_sizes.dynstr += 1;
            self.common.mem_sizes.dynsym += size_of::<elf::SymtabEntry>() as u64;
        }

        self.dynamic_linker = resources
            .symbol_db
            .args
            .dynamic_linker
            .as_ref()
            .map(|p| CString::new(p.as_os_str().as_encoded_bytes()))
            .transpose()?;
        if let Some(dynamic_linker) = self.dynamic_linker.as_ref() {
            self.common.mem_sizes.interp += dynamic_linker.as_bytes_with_nul().len() as u64;
        }

        Ok(())
    }

    fn load_entry_point(&mut self, resources: &GraphResources) -> Result {
        let symbol_id = *resources
            .symbol_db
            .global_names
            .get(&SymbolName::prehashed(b"_start"))
            .context("Missing _start symbol")?;
        self.entry_symbol_id = Some(symbol_id);
        let file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        let old_flags = resources.symbol_resolution_flags[symbol_id.as_usize()]
            .fetch_or(ResolutionFlags::DIRECT);
        if old_flags.is_empty() {
            resources.send_work(file_id, WorkItem::LoadGlobalSymbol(symbol_id));
        }
        Ok(())
    }

    fn finalise_sizes(
        &mut self,
        symbol_db: &SymbolDb,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        if !symbol_db.args.strip_all {
            self.internal_symbols.allocate_symbol_table_sizes(
                symbol_db,
                &mut self.common,
                symbol_resolution_flags,
            )?;
        }

        if symbol_db.args.should_write_eh_frame_hdr {
            self.common.mem_sizes.eh_frame_hdr += core::mem::size_of::<elf::EhFrameHdr>() as u64;
        }

        Ok(())
    }

    /// This function is where we determine sizes that depend on other sizes. For example, the size
    /// of the section headers table depends on which sections we're writing which depends on which
    /// sections are non-empty.
    fn determine_header_sizes(
        &mut self,
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
        total_sizes.output_order_map(output_sections, |section_id, _alignment, size| {
            if *size > 0 {
                keep_sections[section_id.as_usize()] = true;
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
        let mut output_section_indexes = vec![None; output_sections.len()];
        output_sections.sections_and_segments_do(|event| {
            if let OrderEvent::Section(id, _) = event {
                if keep_sections[id.as_usize()] {
                    output_section_indexes[id.as_usize()] = Some(next_output_index);
                    next_output_index += 1;
                }
            }
        });
        output_sections.output_section_indexes = output_section_indexes;

        // Determine which program segments contain sections that we're keeping.
        let mut keep_segments = [false; crate::program_segments::MAX_SEGMENTS];
        let mut active_segments = Vec::with_capacity(4);
        output_sections.sections_and_segments_do(|event| match event {
            OrderEvent::SegmentStart(segment_id) => active_segments.push(segment_id),
            OrderEvent::SegmentEnd(segment_id) => active_segments.retain(|a| *a != segment_id),
            OrderEvent::Section(section_id, _) => {
                if keep_sections[section_id.as_usize()] {
                    for segment_id in &active_segments {
                        keep_segments[segment_id.as_usize()] = true;
                    }
                    active_segments.clear();
                }
            }
        });
        let active_segment_ids = (0..crate::program_segments::MAX_SEGMENTS)
            .filter(|i| keep_segments[*i])
            .map(ProgramSegmentId::new)
            .collect();

        let header_info = HeaderInfo {
            num_output_sections_with_content: num_sections
                .try_into()
                .expect("output section count must fit in a u16"),

            active_segment_ids,
        };

        // Allocate space for headers based on segment and section counts.
        let mut extra_sizes = OutputSectionPartMap::with_size(self.common.mem_sizes.len());

        extra_sizes.file_header = u64::from(elf::FILE_HEADER_SIZE);
        extra_sizes.program_headers = header_info.program_headers_size();
        extra_sizes.section_headers = header_info.section_headers_size();
        extra_sizes.shstrtab = output_sections
            .ids_with_info()
            .filter(|(id, _info)| output_sections.output_index_of_section(*id).is_some())
            .map(|(_id, info)| info.details.name.len() as u64 + 1)
            .sum::<u64>();

        // We need to allocate both our own size record and the file totals, since they've already
        // been computed.
        self.common.mem_sizes.merge(&extra_sizes);
        total_sizes.merge(&extra_sizes);

        self.header_info = Some(header_info);
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
        resolutions_out: &mut [Option<Resolution>],
        output_sections: &OutputSections,
        symbol_db: &SymbolDb,
        symbol_resolution_flags: &[ResolutionFlags],
    ) -> Result<InternalLayout<'data>> {
        let header_layout = section_layouts.built_in(output_section_id::FILE_HEADER);
        assert_eq!(header_layout.file_offset, 0);

        let tlsld_got_entry = self.needs_tlsld_got_entry.then(|| {
            let address =
                NonZeroU64::new(memory_offsets.got).expect("GOT address must never be zero");
            memory_offsets.got += elf::GOT_ENTRY_SIZE * 2;
            address
        });

        self.internal_symbols.finalise_layout(
            &self.common,
            symbol_db,
            memory_offsets,
            section_layouts,
            resolutions_out,
            symbol_resolution_flags,
        )?;

        let strings_offset_start = self.common.finalise_layout(memory_offsets, section_layouts);
        Ok(InternalLayout {
            file_sizes: compute_file_sizes(&self.common.mem_sizes, output_sections),
            mem_sizes: self.common.mem_sizes,
            internal_symbols: self.internal_symbols,
            strings_offset_start,
            entry_symbol_id: self.entry_symbol_id,
            tlsld_got_entry,
            merged_strings: self.merged_strings,
            identity: self.identity,
            dynamic_linker: self.dynamic_linker,
            header_info: self
                .header_info
                .expect("we should have computed header info by now"),
        })
    }
}

impl InternalSymbols {
    fn allocate_symbol_table_sizes(
        &mut self,
        symbol_db: &SymbolDb<'_>,
        common: &mut CommonLayoutState,
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

            common.mem_sizes.symtab_globals += size_of::<elf::SymtabEntry>() as u64;
            let symbol_name = symbol_db.symbol_name(symbol_id)?;
            common.mem_sizes.symtab_strings += symbol_name.len() as u64 + 1;
        }
        Ok(())
    }

    fn finalise_layout(
        &self,
        common: &CommonLayoutState,
        symbol_db: &SymbolDb,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
        resolutions_out: &mut [Option<Resolution>],
        symbol_resolution_flags: &[ResolutionFlags],
    ) -> Result {
        // Define symbols that are optionally put at the start/end of some sections.
        let mut emitter =
            common.create_global_address_emitter(memory_offsets, symbol_resolution_flags);
        for (local_index, def_info) in self.symbol_definitions.iter().enumerate() {
            let symbol_id = self.start_symbol_id.add_usize(local_index);
            if !symbol_db.is_canonical(symbol_id) {
                continue;
            }
            // We don't put internal symbols in the symbol table if they aren't referenced.
            if symbol_resolution_flags[symbol_id.as_usize()].is_empty() {
                continue;
            }

            let (raw_value, value_flags) = match def_info {
                InternalSymDefInfo::Undefined => (0, ValueFlags::ABSOLUTE),
                InternalSymDefInfo::SectionStart(section_id) => (
                    section_layouts.built_in(*section_id).mem_offset,
                    ValueFlags::ADDRESS,
                ),
                InternalSymDefInfo::SectionEnd(section_id) => {
                    let sec = &section_layouts.built_in(*section_id);
                    (sec.mem_offset + sec.mem_size, ValueFlags::ADDRESS)
                }
            };
            emitter.emit_resolution(
                symbol_id,
                symbol_db,
                raw_value,
                None,
                value_flags,
                resolutions_out,
            )?;
        }
        Ok(())
    }
}

impl<'data> EpilogueLayoutState<'data> {
    fn new(
        input_state: ResolvedEpilogue,
        output_sections: &OutputSections,
    ) -> EpilogueLayoutState<'data> {
        EpilogueLayoutState {
            common: CommonLayoutState::new(
                input_state.file_id,
                output_sections,
                SymbolIdRange::epilogue(
                    input_state.start_symbol_id,
                    input_state.symbol_definitions.len(),
                ),
            ),
            internal_symbols: InternalSymbols {
                symbol_definitions: input_state.symbol_definitions,
                start_symbol_id: input_state.start_symbol_id,
            },
            dynamic_symbol_definitions: Default::default(),
            gnu_hash_layout: None,
        }
    }

    fn finalise_sizes(
        &mut self,
        symbol_db: &SymbolDb,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        if !symbol_db.args.strip_all {
            self.internal_symbols.allocate_symbol_table_sizes(
                symbol_db,
                &mut self.common,
                symbol_resolution_flags,
            )?;
        }

        if symbol_db.args.needs_dynamic() {
            self.common.mem_sizes.dynamic += (elf_writer::NUM_EPILOGUE_DYNAMIC_ENTRIES
                * core::mem::size_of::<crate::elf::DynamicEntry>())
                as u64;
        }

        let num_defs = self.dynamic_symbol_definitions.len();
        // Our number of buckets is computed somewhat arbitrarily so that we have on average 2
        // symbols per bucket, but then we round up to a power of two.
        if symbol_db.args.hash_style == Some(HashStyle::Gnu) {
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
            self.common.mem_sizes.dynstr += self
                .dynamic_symbol_definitions
                .iter()
                .map(|n| n.name.len() + 1)
                .sum::<usize>() as u64;
            self.common.mem_sizes.dynsym +=
                (self.dynamic_symbol_definitions.len() * size_of::<elf::SymtabEntry>()) as u64;
            // .gnu.hash
            let num_blume = 1;
            self.common.mem_sizes.gnu_hash += (core::mem::size_of::<elf::GnuHashHeader>()
                + core::mem::size_of::<u64>() * num_blume
                + core::mem::size_of::<u32>() * gnu_hash_layout.bucket_count as usize
                + core::mem::size_of::<u32>() * num_defs)
                as u64;
            self.gnu_hash_layout = Some(gnu_hash_layout);
        } else if !self.dynamic_symbol_definitions.is_empty() {
            bail!("Dynamic linking requires that --hash-style is specified");
        }

        Ok(())
    }

    fn finalise_layout(
        mut self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
        resolutions_out: &mut [Option<Resolution>],
        output_sections: &OutputSections,
        symbol_db: &SymbolDb,
        symbol_resolution_flags: &[ResolutionFlags],
    ) -> Result<EpilogueLayout<'data>> {
        self.internal_symbols.finalise_layout(
            &self.common,
            symbol_db,
            memory_offsets,
            section_layouts,
            resolutions_out,
            symbol_resolution_flags,
        )?;

        let dynstr_offset_start = (memory_offsets.dynstr
            - section_layouts
                .built_in(output_section_id::DYNSTR)
                .mem_offset)
            .try_into()
            .context("Symbol string table overflowed 32 bits")?;

        let strings_offset_start = self.common.finalise_layout(memory_offsets, section_layouts);
        if let Some(gnu_hash_layout) = self.gnu_hash_layout.as_mut() {
            gnu_hash_layout.symbol_base = ((memory_offsets.dynsym
                - section_layouts
                    .built_in(output_section_id::DYNSYM)
                    .mem_offset)
                / elf::SYMTAB_ENTRY_SIZE)
                .try_into()
                .context("Too many dynamic symbols")?;
        }

        let dynsym_start_index = ((memory_offsets.dynsym
            - section_layouts
                .built_in(output_section_id::DYNSYM)
                .mem_offset)
            / elf::SYMTAB_ENTRY_SIZE) as u32;

        Ok(EpilogueLayout {
            file_sizes: compute_file_sizes(&self.common.mem_sizes, output_sections),
            mem_sizes: self.common.mem_sizes,
            internal_symbols: self.internal_symbols,
            strings_offset_start,
            gnu_hash_layout: self.gnu_hash_layout,
            dynamic_symbol_definitions: self.dynamic_symbol_definitions,
            dynstr_offset_start,
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
        u64::from(elf::SECTION_HEADER_SIZE) * self.num_output_sections_with_content as u64
    }
}

/// Construct a new inactive instance, which means we don't yet load non-GC sections and only
/// load them later if a symbol from this object is referenced.
fn new_object_layout_state<'data>(
    input_state: resolution::ResolvedObject<'data>,
    output_sections: &OutputSections,
) -> FileLayoutState<'data> {
    // Note, this function is called for all objects from a single thread, so don't be tempted to do
    // significant work here. Do work when activate is called instead. Doing it there also means
    // that we don't do the work unless the object is actually needed.

    let common = CommonLayoutState::new(
        input_state.file_id,
        output_sections,
        input_state.symbol_id_range,
    );
    if let Some(non_dynamic) = input_state.non_dynamic {
        FileLayoutState::Object(Box::new(ObjectLayoutState {
            input: input_state.input,
            object: input_state.object,
            section_frame_data: Default::default(),
            eh_frame_section: None,
            state: ObjectLayoutMutableState {
                common,
                sections: non_dynamic.sections,
                sections_required: Default::default(),
                merged_string_resolutions: non_dynamic.merged_string_resolutions,
                cies: Default::default(),
            },
        }))
    } else {
        FileLayoutState::Dynamic(Box::new(DynamicLayoutState {
            lib_name: input_state.input.lib_name(),
            symbol_versions: input_state.object.versym,
            object: input_state.object,
            input: input_state.input,
            common,

            // These fields are filled in properly when we activate.
            symbol_versions_needed: Default::default(),

            // These fields are filled in when we finalise sizes.
            verdef_info: None,
            non_addressable_indexes: Default::default(),
        }))
    }
}

impl<'data> ObjectLayoutState<'data> {
    fn activate<'scope>(
        &mut self,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        let mut eh_frame_section = None;
        for (i, section) in self.state.sections.iter().enumerate() {
            match section {
                SectionSlot::Unloaded(unloaded_section) => {
                    let retain = unloaded_section.details.retain;
                    if retain {
                        self.state
                            .sections_required
                            .push(SectionRequest::new(object::SectionIndex(i)));
                    }
                }
                SectionSlot::EhFrameData(index) => {
                    eh_frame_section = Some(*index);
                }
                _ => (),
            }
        }
        if let Some(eh_frame_section_index) = eh_frame_section {
            process_eh_frame_data(
                self,
                self.symbol_id_range(),
                eh_frame_section_index,
                resources,
                queue,
            )?;
            let eh_frame_section = self.object.section(eh_frame_section_index)?;
            self.eh_frame_section = Some(eh_frame_section);
        }
        if resources.symbol_db.args.output_kind == OutputKind::SharedObject {
            self.load_non_hidden_symbols(resources, queue)?;
        }
        self.load_sections(resources, queue)
    }

    /// Loads sections in `sections_required` (which may be empty).
    fn load_sections<'scope>(
        &mut self,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        while let Some(section_request) = self.state.sections_required.pop() {
            let section_id = section_request.id;
            match &self.state.sections[section_id.0] {
                SectionSlot::Unloaded(unloaded) => {
                    let unloaded = *unloaded;
                    if unloaded.is_string_merge {
                        // We currently always load all string-merge data regardless of whether it's
                        // referenced.
                        continue;
                    }
                    let mut section =
                        Section::create(self, queue, &unloaded, section_id, resources)?;
                    let sec_id = resources
                        .output_sections
                        .output_section_id(unloaded.output_section_id)?;
                    let allocation = self
                        .state
                        .common
                        .mem_sizes
                        .regular_mut(sec_id, section.alignment);
                    *allocation += section.capacity();
                    *self.state.common.sections_with_content.get_mut(sec_id) = true;
                    section.output_section_id = Some(sec_id);
                    if let Some(frame_data) = self.section_frame_data.get_mut(section_id.0) {
                        self.state.common.mem_sizes.eh_frame +=
                            u64::from(frame_data.total_fde_size);
                        if resources.symbol_db.args.should_write_eh_frame_hdr {
                            self.state.common.mem_sizes.eh_frame_hdr +=
                                core::mem::size_of::<EhFrameHdrEntry>() as u64
                                    * u64::from(frame_data.num_fdes);
                        }
                        // Take ownership of the section's frame data relocations. We only apply
                        // these once when the section is loaded, so after this we won't need them
                        // any more. By taking ownership, we drop our borrow of self.
                        let frame_data_relocations = core::mem::take(&mut frame_data.relocations);
                        // Request loading of any sections/symbols referenced by the FDEs for our
                        // section.
                        if let Some(eh_frame_section) = self.eh_frame_section {
                            for relocations in &frame_data_relocations {
                                for rel in *relocations {
                                    apply_relocation(
                                        self,
                                        rel,
                                        eh_frame_section,
                                        resources,
                                        queue,
                                    )?;
                                }
                            }
                        }
                    }
                    self.state.sections[section_id.0] = SectionSlot::Loaded(section);
                }
                SectionSlot::Discard => {
                    bail!(
                        "{self}: Don't know what segment to put `{}` in, but it's referenced",
                        self.object.section_display_name(section_id),
                    );
                }
                SectionSlot::Loaded(_) | SectionSlot::EhFrameData(..) => {}
                SectionSlot::MergeStrings(_) => {
                    // We currently always load everything in merge-string sections. i.e. we don't
                    // GC unreferenced data. So there's nothing to do here.
                }
            }
            if let SectionSlot::Loaded(section) = &mut self.state.sections[section_id.0] {
                section.resolution_kind |= section_request.resolution_kind;
            };
        }
        Ok(())
    }

    fn finalise_sizes(
        &mut self,
        symbol_db: &SymbolDb,
        output_sections: &OutputSections,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        self.state.common.mem_sizes.resize(output_sections.len());
        if !symbol_db.args.strip_all {
            self.allocate_symtab_space(symbol_db, symbol_resolution_flags)?;
        }
        let output_kind = symbol_db.args.output_kind;
        let mem_sizes = &mut self.state.common.mem_sizes;
        for slot in &mut self.state.sections {
            if let SectionSlot::Loaded(section) = slot {
                allocate_resolution(
                    ValueFlags::ADDRESS,
                    section.resolution_kind,
                    mem_sizes,
                    output_kind,
                );
            }
        }
        // TODO: Deduplicate CIEs from different objects, then only allocate space for those CIEs
        // that we "won".
        for cie in &self.state.cies {
            self.state.common.mem_sizes.eh_frame += cie.cie.bytes.len() as u64;
        }
        Ok(())
    }

    fn allocate_symtab_space(
        &mut self,
        symbol_db: &SymbolDb<'_>,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        let mut num_locals = 0;
        let mut num_globals = 0;
        let mut strings_size = 0;
        for ((sym_index, sym), sym_state) in self
            .object
            .symbols
            .enumerate()
            .zip(&symbol_resolution_flags[self.symbol_id_range().as_usize()])
        {
            let symbol_id = self.state.common.symbol_id_range.input_to_id(sym_index);
            if let Some(info) = SymbolCopyInfo::new(
                self.object,
                sym_index,
                sym,
                symbol_id,
                symbol_db,
                sym_state.get(),
                &self.state.sections,
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
        self.state.common.mem_sizes.symtab_locals += num_locals * entry_size;
        self.state.common.mem_sizes.symtab_globals += num_globals * entry_size;
        self.state.common.mem_sizes.symtab_strings += strings_size as u64;
        Ok(())
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut [Option<Resolution>],
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
        symbol_db: &SymbolDb,
        output_sections: &OutputSections,
        merged_string_start_addresses: &MergedStringStartAddresses,
        symbol_resolution_flags: &[ResolutionFlags],
    ) -> Result<ObjectLayout<'data>> {
        let dynstr_start_offset =
            memory_offsets.dynstr - section_layouts.get(output_section_id::DYNSTR).mem_offset;
        let symbol_id_range = self.symbol_id_range();
        let mut sections = self.state.sections;

        let mut emitter = self
            .state
            .common
            .create_global_address_emitter(memory_offsets, symbol_resolution_flags);

        let mut section_resolutions = Vec::with_capacity(sections.len());
        for slot in sections.iter_mut() {
            match slot {
                SectionSlot::Loaded(sec) => {
                    let output_section_id = sec.output_section_id.with_context(|| {
                        format!(
                            "Tried to load section `{}` which isn't mapped to an output section",
                            self.object.section_display_name(sec.index)
                        )
                    })?;
                    let address = memory_offsets.regular_mut(output_section_id, sec.alignment);
                    // TODO: We probably need to be able to handle sections that are ifuncs and sections
                    // that need a TLS GOT struct.
                    section_resolutions.push(Some(emitter.create_resolution(
                        sec.resolution_kind,
                        *address,
                        None,
                        ValueFlags::ADDRESS,
                    )?));
                    *address += sec.capacity();
                }
                SectionSlot::EhFrameData(..) => {
                    // References to symbols defined in .eh_frame are a bit weird, since it's a
                    // section where we're GCing stuff, but crtbegin.o and crtend.o use them in
                    // order to find the start and end of the whole .eh_frame section.
                    section_resolutions.push(Some(emitter.create_resolution(
                        ResolutionFlags::DIRECT,
                        memory_offsets.eh_frame,
                        None,
                        ValueFlags::ADDRESS,
                    )?));
                }
                _ => {
                    section_resolutions.push(None);
                }
            }
        }

        let mut dyn_sym_index = dynamic_symtab_index(memory_offsets, section_layouts)?;
        let e = LittleEndian;
        for ((local_symbol_index, local_symbol), symbol_state) in self
            .object
            .symbols
            .enumerate()
            .zip(&symbol_resolution_flags[symbol_id_range.as_usize()])
        {
            if symbol_state.is_empty() {
                continue;
            }
            let symbol_id = symbol_id_range.input_to_id(local_symbol_index);
            if !symbol_db.is_canonical(symbol_id) {
                continue;
            }
            let value_flags = symbol_db.local_symbol_value_flags(symbol_id);
            let raw_value = if let Some(section_index) = self
                .object
                .symbol_section(local_symbol, local_symbol_index)?
            {
                if let Some(section_resolution) = section_resolutions[section_index.0].as_ref() {
                    local_symbol.st_value(e) + section_resolution.address()?
                } else {
                    merged_string_start_addresses
                        .try_resolve_local(
                            &self.state.merged_string_resolutions,
                            symbol_id_range.input_to_offset(local_symbol_index),
                        )
                        .ok_or_else(|| {
                            anyhow!(
                                "Symbol is in a section that we didn't load. Symbol: {} Section: {}",
                                symbol_db.symbol_debug(symbol_id),
                                section_debug(self.object, section_index),
                            )
                        })?
                }
            } else if local_symbol.is_common(e) {
                let common = CommonSymbol::new(local_symbol)?;
                let offset = memory_offsets.regular_mut(output_section_id::BSS, common.alignment);
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
                dynamic_symbol_index = Some(
                    NonZeroU32::new(dyn_sym_index)
                        .context("Attempted to create dynamic symbol index 0")?,
                );
                dyn_sym_index += 1;
            }
            emitter.emit_resolution(
                symbol_id,
                symbol_db,
                raw_value,
                dynamic_symbol_index,
                value_flags,
                resolutions_out,
            )?;
        }

        let plt_relocations = emitter.plt_relocations;
        let strtab_offset_start = self
            .state
            .common
            .finalise_layout(memory_offsets, section_layouts);

        Ok(ObjectLayout {
            input: self.input,
            file_id: self.state.common.file_id,
            object: self.object,
            file_sizes: compute_file_sizes(&self.state.common.mem_sizes, output_sections),
            mem_sizes: self.state.common.mem_sizes,
            sections,
            section_resolutions,
            strtab_offset_start,
            plt_relocations,
            eh_frame_start_address: memory_offsets.eh_frame,
            symbol_id_range,
            merged_string_resolutions: self.state.merged_string_resolutions,
            dynstr_start_offset,
        })
    }

    fn load_non_hidden_symbols<'scope>(
        &mut self,
        resources: &GraphResources<'data, 'scope>,
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
                    self.load_symbol(symbol_id, resources, queue)?;
                }
                if !old_flags.contains(ResolutionFlags::EXPORT_DYNAMIC) {
                    self.export_dynamic(symbol_id, resources)?;
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
    pub(crate) fn new(
        object: &crate::elf::File<'data>,
        sym_index: object::SymbolIndex,
        sym: &crate::elf::Symbol,
        symbol_id: SymbolId,
        symbol_db: &SymbolDb,
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
    !sym.is_undefined(LittleEndian) && !sym.is_local() && sym.st_visibility() == 0
}

impl MergedStringStartAddresses {
    #[tracing::instrument(skip_all, name = "Compute merged string section start addresses")]
    fn compute(
        output_sections: &OutputSections<'_>,
        starting_mem_offsets_by_file: &[Option<OutputSectionPartMap<u64>>],
    ) -> Self {
        let mut addresses = OutputSectionMap::with_size(output_sections.len());
        if let Some(internal_start_offsets) =
            &starting_mem_offsets_by_file[crate::input_data::INTERNAL_FILE_ID.as_usize()]
        {
            for i in 0..output_sections.num_regular_sections() {
                let section_id = OutputSectionId::regular(i as u16);
                *addresses.get_mut(section_id) =
                    *internal_start_offsets.regular(section_id, alignment::MIN);
            }
        }
        Self { addresses }
    }

    /// Returns the address of `local_symbol_index` if it points to a merged string, or None if not.
    fn try_resolve_local(
        &self,
        merged_string_resolutions: &[Option<MergedStringResolution>],
        local_symbol_index: usize,
    ) -> Option<u64> {
        merged_string_resolutions[local_symbol_index].map(|res| self.resolve(res))
    }

    pub(crate) fn resolve(&self, res: resolution::MergedStringResolution) -> u64 {
        self.addresses.get(res.output_section_id) + res.offset
    }
}

fn process_eh_frame_data(
    object: &mut ObjectLayoutState,
    file_symbol_id_range: SymbolIdRange,
    eh_frame_section_index: object::SectionIndex,
    resources: &GraphResources,
    queue: &mut LocalWorkQueue,
) -> Result {
    object
        .section_frame_data
        .resize_with(object.state.sections.len(), Default::default);
    let eh_frame_section = object.object.section(eh_frame_section_index)?;
    let data = object.object.section_data(eh_frame_section)?;
    const PREFIX_LEN: usize = core::mem::size_of::<elf::EhFrameEntryPrefix>();
    let e = LittleEndian;
    let relocations = object.object.relocations(eh_frame_section_index)?;
    let mut rel_iter = relocations.iter().enumerate().peekable();
    let mut offset = 0;
    let mut pending: Option<PendingEhFrameRelocations> = None;
    while offset + PREFIX_LEN <= data.len() {
        // Although the section data will be aligned within the object file, there's
        // no guarantee that the object is aligned within the archive to any more
        // than 2 bytes, so we can't rely on alignment here. Archives are annoying!
        // See https://www.airs.com/blog/archives/170
        let prefix: elf::EhFrameEntryPrefix =
            bytemuck::pod_read_unaligned(&data[offset..offset + PREFIX_LEN]);
        let size = core::mem::size_of_val(&prefix.length) + prefix.length as usize;
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
                apply_relocation(object, rel, eh_frame_section, resources, queue)?;
                if let Some(local_sym_index) = rel.symbol(e, false) {
                    let local_symbol_id = file_symbol_id_range.input_to_id(local_sym_index);
                    let definition = resources.symbol_db.definition(local_symbol_id);
                    referenced_symbols.push(definition);
                } else {
                    eligible_for_deduplication = false;
                }
                rel_iter.next();
            }
            object.state.cies.push(CieAtOffset {
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
            let rel_start_index = rel_iter.peek().map(|(i, _)| *i).unwrap_or(0);
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
                let new_pending = PendingEhFrameRelocations {
                    section_index,
                    start: rel_start_index,
                    end: rel_end_index,
                };
                if let Some(p) = pending.as_mut() {
                    if !p.merge(&new_pending) {
                        p.apply(&mut object.section_frame_data, relocations);
                        pending = Some(new_pending);
                    }
                } else {
                    pending = Some(new_pending);
                }
                let section_frame_data = &mut object.section_frame_data[section_index.0];
                section_frame_data.num_fdes += 1;
                section_frame_data.total_fde_size += size as u32;
            }
        }
        offset = next_offset;
    }
    if let Some(p) = pending {
        p.apply(&mut object.section_frame_data, relocations);
    }
    // Allocate space for any remaining bytes in .eh_frame that aren't large enough to constitute an
    // actual entry. crtend.o has a single u32 equal to 0 as an end marker.
    object.state.common.mem_sizes.eh_frame += (data.len() - offset) as u64;
    Ok(())
}

struct PendingEhFrameRelocations {
    section_index: object::SectionIndex,
    start: usize,
    end: usize,
}

impl PendingEhFrameRelocations {
    fn apply<'data>(
        &self,
        section_frame_data: &mut [SectionFrameData<'data>],
        relocations: &'data [Rela64<LittleEndian>],
    ) {
        let section_frame_data = &mut section_frame_data[self.section_index.0];
        section_frame_data
            .relocations
            .push(&relocations[self.start..self.end]);
    }

    fn merge(&mut self, new_pending: &PendingEhFrameRelocations) -> bool {
        if self.section_index != new_pending.section_index || new_pending.start != self.end {
            return false;
        }
        self.end = new_pending.end;
        true
    }
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
    next_got_address: u64,
    next_plt_address: u64,
    symbol_resolution_flags: &'state [ResolutionFlags],
    plt_relocations: Vec<IfuncRelocation>,
    symbol_id_range: SymbolIdRange,
}

impl<'state> GlobalAddressEmitter<'state> {
    fn emit_resolution(
        &mut self,
        symbol_id: SymbolId,
        symbol_db: &'state SymbolDb<'state>,
        raw_value: u64,
        dynamic_symbol_index: Option<NonZeroU32>,
        value_flags: ValueFlags,
        resolutions_out: &mut [Option<Resolution>],
    ) -> Result {
        debug_assert_bail!(
            symbol_id >= self.symbol_id_range.start()
                && symbol_id.to_offset(self.symbol_id_range) < resolutions_out.len(),
            "Tried to emit resolution for {} which is outside {}..{}",
            symbol_db.symbol_debug(symbol_id),
            self.symbol_id_range.start(),
            self.symbol_id_range
                .start()
                .add_usize(resolutions_out.len())
        );
        let resolution = self.create_resolution(
            self.symbol_resolution_flags[symbol_id.as_usize()],
            raw_value,
            dynamic_symbol_index,
            value_flags,
        )?;
        let local_symbol_index = symbol_id.to_offset(self.symbol_id_range);
        resolutions_out[local_symbol_index] = Some(resolution);
        Ok(())
    }

    fn create_resolution(
        &mut self,
        res_kind: ResolutionFlags,
        raw_value: u64,
        dynamic_symbol_index: Option<NonZeroU32>,
        value_flags: ValueFlags,
    ) -> Result<Resolution> {
        let mut resolution = Resolution {
            raw_value,
            dynamic_symbol_index,
            got_address: None,
            plt_address: None,
            resolution_flags: res_kind,
            value_flags,
        };
        if value_flags.contains(ValueFlags::IFUNC) {
            debug_assert_bail!(
                res_kind.contains(ResolutionFlags::GOT),
                "Missing GOT for ifunc {res_kind:?} -- {value_flags}"
            );
            debug_assert_bail!(
                res_kind.contains(ResolutionFlags::PLT),
                "Missing PLT for ifunc"
            );
            // IFuncs need to always have GOT. Currently we also always create a PLT entry.
            let got_address = self.allocate_got();
            let plt_address = self.allocate_plt();
            // An ifunc is always resolved at runtime, so we need a relocation for it.
            self.plt_relocations.push(IfuncRelocation {
                resolver: raw_value,
                got_address: got_address.get(),
            });
            resolution.got_address = Some(got_address);
            resolution.plt_address = Some(plt_address);
            return Ok(resolution);
        }
        if res_kind.contains(ResolutionFlags::PLT) {
            resolution.plt_address = Some(self.allocate_plt());
        }
        if res_kind.contains(ResolutionFlags::GOT) {
            resolution.got_address = Some(self.allocate_got());
        }
        if res_kind.contains(ResolutionFlags::GOT_TLS_MODULE) {
            debug_assert!(res_kind.contains(ResolutionFlags::GOT));
            self.allocate_got();
        }
        Ok(resolution)
    }

    fn allocate_got(&mut self) -> NonZeroU64 {
        let got_address = NonZeroU64::new(self.next_got_address).unwrap();
        self.next_got_address += elf::GOT_ENTRY_SIZE;
        got_address
    }

    fn allocate_plt(&mut self) -> NonZeroU64 {
        let plt_address = NonZeroU64::new(self.next_plt_address).unwrap();
        self.next_plt_address += elf::PLT_ENTRY_SIZE;
        plt_address
    }
}

impl<'data> resolution::ResolvedFile<'data> {
    fn create_layout_state(self, output_sections: &OutputSections) -> FileLayoutState<'data> {
        match self {
            resolution::ResolvedFile::Object(s) => new_object_layout_state(s, output_sections),
            resolution::ResolvedFile::Internal(s) => {
                FileLayoutState::Internal(Box::new(InternalLayoutState::new(s, output_sections)))
            }
            resolution::ResolvedFile::NotLoaded => FileLayoutState::NotLoaded,
            resolution::ResolvedFile::Epilogue(s) => {
                FileLayoutState::Epilogue(Box::new(EpilogueLayoutState::new(s, output_sections)))
            }
        }
    }
}

impl Resolution {
    pub(crate) fn got_address(&self) -> Result<u64> {
        Ok(self.got_address.context("Missing GOT address")?.get())
    }

    pub(crate) fn plt_address(&self) -> Result<u64> {
        Ok(self.plt_address.context("Missing PLT address")?.get())
    }

    pub(crate) fn value_flags(self) -> ValueFlags {
        self.value_flags
    }

    pub(crate) fn value(self) -> u64 {
        if self.value_flags.contains(ValueFlags::DYNAMIC) {
            0
        } else {
            self.raw_value
        }
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
}

fn layout_section_parts(
    sizes: &OutputSectionPartMap<u64>,
    output_sections: &OutputSections,
) -> OutputSectionPartMap<OutputRecordLayout> {
    let mut file_offset = 0;
    let mut mem_offset = output_sections.base_address;
    let mut current_seg_id = None;
    sizes.output_order_map(
        output_sections,
        |section_id, section_alignment, part_size| {
            let defs = output_sections.details(section_id);
            let mem_size = *part_size;
            // Note, we align up even if our size is zero, otherwise our section will start at an
            // unaligned address.
            file_offset = section_alignment.align_up_usize(file_offset);
            mem_offset = section_alignment.align_up(mem_offset);
            let seg_id = output_sections.loadable_segment_id_for(section_id);
            if current_seg_id != seg_id {
                current_seg_id = seg_id;
                let segment_alignment = seg_id.map(|s| s.alignment()).unwrap_or(alignment::MIN);
                mem_offset = segment_alignment.align_modulo(file_offset as u64, mem_offset);
            }
            let file_size = if defs.has_data_in_file() {
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
        },
    )
}

impl<'data> DynamicLayoutState<'data> {
    fn activate(&mut self, resources: &GraphResources, queue: &mut LocalWorkQueue) -> Result {
        let dt_info = DynamicTagValues::read(self.object)?;
        self.symbol_versions_needed = vec![false; dt_info.verdefnum as usize];
        if let Some(soname) = dt_info.soname {
            self.lib_name = soname;
        }
        self.common.mem_sizes.dynamic += core::mem::size_of::<crate::elf::DynamicEntry>() as u64;
        self.common.mem_sizes.dynstr += self.lib_name.len() as u64 + 1;
        self.request_all_undefined_symbols(resources, queue)
    }

    fn request_all_undefined_symbols(
        &self,
        resources: &GraphResources,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        for symbol_id in self.symbol_id_range() {
            if resources.symbol_db.is_canonical(symbol_id) {
                continue;
            }
            let definition_symbol_id = resources.symbol_db.definition(symbol_id);
            let old_flags = resources.symbol_resolution_flags[definition_symbol_id.as_usize()]
                .fetch_or(ResolutionFlags::EXPORT_DYNAMIC);
            if old_flags.is_empty() {
                queue.send_symbol_request(definition_symbol_id, resources);
            }
            if !old_flags.contains(ResolutionFlags::EXPORT_DYNAMIC) {
                queue.send_export_dynamic_request(definition_symbol_id, resources);
            }
        }
        Ok(())
    }

    fn finalise_sizes(&mut self) -> Result {
        let e = LittleEndian;
        let mut version_count = 0;

        if let Some((mut verdef_iterator, link)) = self.object.verdef.clone() {
            let defs = verdef_iterator.clone();

            let strings = self.object.sections.strings(e, self.object.data, link)?;
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
                    // The base version doesn't count as a version. We emit it as a Verneed, whereas
                    // the actual versions are emitted as Vernaux.
                    if !is_base {
                        version_count += 1;
                    }
                    // Every VERDEF entry should have at least one AUX entry.
                    let aux = aux_iterator.next()?.context("VERDEF with no AUX entry")?;
                    let name = aux.name(e, strings)?;
                    self.common.mem_sizes.dynstr += name.len() as u64 + 1;
                }
            }

            if version_count > 0 {
                self.common.mem_sizes.gnu_version_r += core::mem::size_of::<crate::elf::Verneed>()
                    as u64
                    + u64::from(version_count) * core::mem::size_of::<crate::elf::Vernaux>() as u64;

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

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
        resolutions_out: &mut [Option<Resolution>],
        output_sections: &OutputSections,
        symbol_resolution_flags: &[ResolutionFlags],
    ) -> Result<DynamicLayout<'data>> {
        let version_mapping = self.compute_version_mapping();

        let dynstr_start_offset =
            memory_offsets.dynstr - section_layouts.get(output_section_id::DYNSTR).mem_offset;

        let mut emitter = self
            .common
            .create_global_address_emitter(memory_offsets, symbol_resolution_flags);

        let mut next_symbol_index = dynamic_symtab_index(memory_offsets, section_layouts)?;

        for ((_local_symbol, symbol_state), resolution) in self
            .object
            .symbols
            .iter()
            .zip(&symbol_resolution_flags[self.symbol_id_range().as_usize()])
            .zip(resolutions_out)
        {
            if symbol_state.is_empty() {
                continue;
            }
            *resolution = Some(
                emitter.create_resolution(
                    *symbol_state,
                    0,
                    Some(
                        NonZeroU32::new(next_symbol_index)
                            .context("Tried to create dynamic symbol index 0")?,
                    ),
                    ValueFlags::DYNAMIC,
                )?,
            );

            next_symbol_index += 1;
        }

        let gnu_version_r_layout = section_layouts.get(output_section_id::GNU_VERSION_R);
        let is_last_verneed = memory_offsets.gnu_version_r + self.common.mem_sizes.gnu_version_r
            == gnu_version_r_layout.mem_offset + gnu_version_r_layout.mem_size;

        Ok(DynamicLayout {
            file_id: self.file_id(),
            input: self.input,
            file_sizes: self
                .common
                .mem_sizes
                .map(output_sections, |_section_id, mem_size| *mem_size as usize),
            lib_name: self.lib_name,
            dynstr_start_offset,
            object: self.object,
            symbol_id_range: self.common.symbol_id_range,
            input_symbol_versions: self.symbol_versions,
            version_mapping,
            verdef_info: self.verdef_info,
            is_last_verneed,
        })
    }

    /// Computes a mapping from input versions to output versions.
    fn compute_version_mapping(&self) -> Vec<u16> {
        let mut out = vec![0; self.symbol_versions_needed.len()];
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

fn dynamic_symtab_index(
    memory_offsets: &mut OutputSectionPartMap<u64>,
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
) -> Result<u32> {
    u32::try_from(
        (memory_offsets.dynsym - section_layouts.get(output_section_id::DYNSYM).mem_offset)
            / crate::elf::SYMTAB_ENTRY_SIZE,
    )
    .context("Too many dynamic symbols")
}

impl<'data> Layout<'data> {
    pub(crate) fn mem_address_of_built_in(&self, output_section_id: OutputSectionId) -> u64 {
        self.section_layouts.built_in(output_section_id).mem_offset
    }
}

impl<'data> std::fmt::Debug for FileLayoutState<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileLayoutState::Object(s) => f.debug_tuple("Object").field(&s.input).finish(),
            FileLayoutState::Internal(_) => f.debug_tuple("Internal").finish(),
            FileLayoutState::Dynamic(_) => f.debug_tuple("Dynamic").finish(),
            FileLayoutState::NotLoaded => Display::fmt(&"<not loaded>", f),
            FileLayoutState::Epilogue(_) => Display::fmt(&"<custom sections>", f),
        }
    }
}

fn print_symbol_info(symbol_db: &SymbolDb, name: &str) {
    if let Some(symbol_id) = symbol_db
        .global_names
        .get(&SymbolName::prehashed(name.as_bytes()))
    {
        println!(
            "Global definition:\n   {}",
            symbol_db.symbol_debug(*symbol_id)
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
            match &symbol_db.inputs[file_id.as_usize()] {
                crate::parsing::InputObject::Internal(_) => println!("  <internal>"),
                crate::parsing::InputObject::Object(o) => {
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
                            println!("  Corrupted input (file_id #{file_id}) {}: {e}", o.input)
                        }
                    }
                }
                crate::parsing::InputObject::Epilogue(_) => println!("  <epilogue>"),
            }
        }
    }
}

fn section_debug(object: &crate::elf::File, section_index: object::SectionIndex) -> SectionDebug {
    let name = object
        .section(section_index)
        .and_then(|section| object.section_name(section))
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .unwrap_or_else(|_| "??".to_owned());
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
        (hash & ((1 << self.bloom_shift) - 1)) % self.bucket_count
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
    let output_sections =
        crate::output_section_id::OutputSectionsBuilder::with_base_address(0x1000)
            .build()
            .unwrap();
    let section_part_sizes = OutputSectionPartMap::<u64>::with_size(output_sections.len())
        .output_order_map(&output_sections, |_, _, _| 7);
    let section_part_layouts = layout_section_parts(&section_part_sizes, &output_sections);
    let section_layouts = layout_sections(&section_part_layouts);

    // Make sure no sections overlap
    let mut last_file_start = 0;
    let mut last_mem_start = 0;
    let mut last_file_end = 0;
    let mut last_mem_end = 0;
    let mut last_section_id = output_section_id::FILE_HEADER;
    output_sections.sections_do(|section_id, _section_details| {
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
    });
    let header_info = HeaderInfo {
        num_output_sections_with_content: 0,
        active_segment_ids: (0..MAX_SEGMENTS).map(ProgramSegmentId::new).collect(),
    };

    let segment_layouts = compute_segment_layout(&section_layouts, &output_sections, &header_info);

    // Make sure loadable segments don't overlap in memory or in the file.
    let mut last_file = 0;
    let mut last_mem = 0;
    for seg_layout in segment_layouts.segments.iter() {
        let seg_id = seg_layout.id;
        if seg_id.segment_type() != elf::SegmentType::Load {
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
    let value_flag_sets: &[ValueFlags] = &[
        ValueFlags::ADDRESS,
        ValueFlags::ADDRESS | ValueFlags::CAN_BYPASS_GOT,
        ValueFlags::ABSOLUTE,
        ValueFlags::ABSOLUTE | ValueFlags::CAN_BYPASS_GOT,
        ValueFlags::IFUNC,
        ValueFlags::DYNAMIC,
    ];
    let resolution_flag_sets = &[
        ResolutionFlags::DIRECT,
        ResolutionFlags::EXPORT_DYNAMIC,
        ResolutionFlags::DIRECT | ResolutionFlags::GOT | ResolutionFlags::EXPORT_DYNAMIC,
        ResolutionFlags::GOT,
        ResolutionFlags::GOT | ResolutionFlags::PLT,
        ResolutionFlags::TLS,
        ResolutionFlags::TLS | ResolutionFlags::GOT,
        ResolutionFlags::TLS | ResolutionFlags::GOT | ResolutionFlags::GOT_TLS_MODULE,
    ];
    let output_kinds = &[
        OutputKind::NonRelocatableStaticExecutable,
        OutputKind::PositionIndependentStaticExecutable,
        OutputKind::DynamicExecutable,
        OutputKind::SharedObject,
    ];
    let output_sections = OutputSections::for_testing();
    for &value_flags in value_flag_sets {
        for &resolution_flags in resolution_flag_sets {
            // Skip invalid combinations.
            if resolution_flags.contains(ResolutionFlags::TLS)
                && (value_flags.contains(ValueFlags::ABSOLUTE)
                    || value_flags.contains(ValueFlags::IFUNC))
            {
                continue;
            }

            // TODO: Make this combination work.
            if value_flags.contains(ValueFlags::IFUNC)
                && resolution_flags.contains(ResolutionFlags::EXPORT_DYNAMIC)
            {
                continue;
            }

            for &output_kind in output_kinds {
                // Skip invalid combinations.
                if output_kind.is_static_executable()
                    && (value_flags.contains(ValueFlags::DYNAMIC)
                        || resolution_flags.contains(ResolutionFlags::EXPORT_DYNAMIC))
                {
                    continue;
                }
                if output_kind.is_executable()
                    && value_flags.contains(ValueFlags::ADDRESS)
                    && !value_flags.contains(ValueFlags::CAN_BYPASS_GOT)
                {
                    continue;
                }

                let mut mem_sizes = OutputSectionPartMap::with_size(output_sections.len());
                let resolution_flags = AtomicResolutionFlags::new(resolution_flags);
                allocate_symbol_resolution(
                    value_flags,
                    &resolution_flags,
                    &mut mem_sizes,
                    output_kind,
                );
                let resolution_flags = resolution_flags.get();

                let mut emitter = GlobalAddressEmitter {
                    next_got_address: 1,
                    next_plt_address: 1,
                    symbol_resolution_flags: &[],
                    plt_relocations: Default::default(),
                    symbol_id_range: SymbolIdRange::input(SymbolId::from_usize(1), 0),
                };
                let has_dynamic_symbol = value_flags.contains(ValueFlags::DYNAMIC)
                    || (resolution_flags.contains(ResolutionFlags::EXPORT_DYNAMIC)
                        && !value_flags.contains(ValueFlags::CAN_BYPASS_GOT));
                let dynamic_symbol_index = has_dynamic_symbol.then(|| NonZeroU32::new(1).unwrap());
                let resolution = emitter.create_resolution(
                    resolution_flags,
                    0,
                    dynamic_symbol_index,
                    value_flags,
                )?;

                crate::elf_writer::verify_resolution_allocation(
                    &output_sections,
                    output_kind,
                    mem_sizes,
                    &resolution,
                )
                .with_context(|| {
                    format!(
                        "Failed. output_kind={output_kind:?}
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
