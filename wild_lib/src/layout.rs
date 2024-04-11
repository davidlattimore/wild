//! Traverses the graph of symbol references to figure out what sections from the input files are
//! referenced. Determines which sections need to be linked, sums their sizes decides what goes
//! where in the output file then allocates addresses for each symbol.

use crate::alignment;
use crate::alignment::Alignment;
use crate::args::Args;
use crate::debug_assert_bail;
use crate::elf;
use crate::elf::EhFrameHdrEntry;
use crate::elf::File;
use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
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
use crate::program_segments::ProgramSegmentId;
use crate::program_segments::MAX_SEGMENTS;
use crate::relaxation::Relaxation;
use crate::resolution;
use crate::resolution::MergedStringResolution;
use crate::resolution::ResolvedEpilogue;
use crate::resolution::SectionSlot;
use crate::resolution::ValueKind;
use crate::sharding::split_slice;
use crate::sharding::ShardKey;
use crate::symbol::SymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolDebug;
use crate::symbol_db::SymbolId;
use ahash::AHashMap;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use crossbeam_queue::ArrayQueue;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use object::ObjectSymbolTable as _;
use rayon::prelude::IndexedParallelIterator;
use rayon::prelude::IntoParallelIterator;
use rayon::prelude::IntoParallelRefMutIterator;
use rayon::prelude::ParallelIterator;
use smallvec::SmallVec;
use std::ffi::CString;
use std::fmt::Display;
use std::mem::size_of;
use std::num::NonZeroU64;
use std::sync::atomic;
use std::sync::atomic::AtomicBool;
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
    let mut layout_states = find_required_sections(file_states, symbol_db, &output_sections)?;
    finalise_all_sizes(symbol_db, &output_sections, &mut layout_states)?;
    let section_part_sizes =
        compute_total_section_part_sizes(&mut layout_states, &mut output_sections);
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
    )?;

    Ok(Layout {
        symbol_db,
        symbol_resolutions,
        segment_layouts,
        section_part_layouts,
        section_layouts,
        file_layouts,
        output_sections,
    })
}

#[tracing::instrument(skip_all, name = "Finalise per-object sizes")]
fn finalise_all_sizes(
    symbol_db: &SymbolDb,
    output_sections: &OutputSections,
    layout_states: &mut [FileLayoutState],
) -> Result {
    layout_states
        .par_iter_mut()
        .try_for_each(|state| state.finalise_sizes(symbol_db, output_sections))
}

fn compute_total_file_size(section_layouts: &OutputSectionMap<OutputRecordLayout>) -> u64 {
    let mut file_size = 0;
    section_layouts.for_each(|_, s| file_size = file_size.max(s.file_offset + s.file_size));
    file_size as u64
}

/// Information about what goes where. Also includes relocation data, since that's computed at the
/// same time.
pub struct Layout<'data> {
    pub symbol_db: &'data SymbolDb<'data>,
    pub(crate) symbol_resolutions: SymbolResolutions,
    pub(crate) section_part_layouts: OutputSectionPartMap<OutputRecordLayout>,
    pub(crate) section_layouts: OutputSectionMap<OutputRecordLayout>,
    pub(crate) file_layouts: Vec<FileLayout<'data>>,
    pub(crate) segment_layouts: SegmentLayouts,
    pub output_sections: OutputSections<'data>,
}

pub(crate) struct SegmentLayouts {
    /// The layout of each of our segments. Segments containing no active output sections will have
    /// been filtered, so don't try to index this by our internal segment IDs.
    pub(crate) segments: Vec<SegmentLayout>,
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
    Epilogue(EpilogueLayout),
    NotLoaded,
}

/// The addresses of the start of the merged strings for each output section.
pub(crate) struct MergedStringStartAddresses {
    addresses: OutputSectionMap<u64>,
}

/// Address information for a symbol or section.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct Resolution {
    // TODO: Experiment with putting these in separate vectors.
    pub(crate) value: ResolutionValue,

    pub(crate) got_address: Option<NonZeroU64>,
    pub(crate) plt_address: Option<NonZeroU64>,
    // TODO: Try to remove this.
    pub(crate) kind: TargetResolutionKind,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ResolutionValue {
    /// An absolute value.
    Absolute(u64),

    /// An address of something.
    Address(u64),

    /// A dynamic symbol index.
    Dynamic(u32),
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
    Epilogue(Box<EpilogueLayoutState>),
}

/// Data that doesn't come from any input files, but needs to be written by the linker.
struct InternalLayoutState<'data> {
    common: CommonLayoutState,
    internal_symbols: InternalSymbols,
    entry_symbol_id: Option<SymbolId>,
    needs_tlsld_got_entry: bool,
    merged_strings: OutputSectionMap<resolution::MergedStringsSection<'data>>,
    identity: String,
    header_info: Option<HeaderInfo>,
    dynamic_linker: Option<CString>,
}

pub(crate) struct EpilogueLayoutState {
    common: CommonLayoutState,
    internal_symbols: InternalSymbols,
}

pub(crate) struct EpilogueLayout {
    pub(crate) mem_sizes: OutputSectionPartMap<u64>,
    pub(crate) file_sizes: OutputSectionPartMap<usize>,
    pub(crate) internal_symbols: InternalSymbols,
    pub(crate) strings_offset_start: u32,
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
    pub(crate) start_symbol_id: SymbolId,
    pub(crate) num_symbols: usize,
}

pub(crate) struct InternalLayout<'data> {
    pub(crate) mem_sizes: OutputSectionPartMap<u64>,
    pub(crate) file_sizes: OutputSectionPartMap<usize>,
    // TODO: Investigate if we should get rid of this. Right now, any weak symbols that are
    // undefined use this resolution, which means they all share the same GOT entry. However the
    // whole point of a GOT entry is generally that it can be overridden at runtime, so probably
    // each undefined weak symbol should have a separate GOT entry. If the GOT entries can be
    // overridden at runtime, then PLT entries might also be needed, since calling the function at
    // runtime might now not be undefined behaviour. However, it's possible that we may still want
    // this. Especially for statically linked executables in case we encounter GOT relocations that
    // we can't optimise away.
    pub(crate) undefined_symbol_resolution: Resolution,
    pub(crate) strings_offset_start: u32,
    pub(crate) entry_symbol_id: SymbolId,
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

    pub(crate) start_symbol_id: SymbolId,
    pub(crate) num_symbols: usize,

    pub(crate) object: &'data crate::elf::File<'data>,
}

#[derive(Debug)]
pub(crate) struct IfuncRelocation {
    pub(crate) resolver: u64,
    pub(crate) got_address: u64,

    /// The address of the RELA entry. If we're writing a relocatable binary then we need to apply a
    /// relocation to the relocation!
    pub(crate) relocation_address: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SymbolKind {
    Regular,
    IFunc,
}

trait SymbolRequestHandler<'data>: std::fmt::Display {
    /// Handles a request for a symbol, updating state as necessary.
    fn handle_symbol_request<'scope>(
        &mut self,
        symbol_request: SymbolRequest,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        let symbol_id = symbol_request.symbol_id;
        let local_index = symbol_request.symbol_id.offset_from(self.start_symbol_id());
        let mut common = self.common_mut();
        if local_index >= common.symbol_states.len() {
            bail!(
                "Internal error: Requested `{}` from `{self}`, \
                 but local index {local_index} >= {}",
                resources.symbol_db.symbol_debug(symbol_id),
                common.symbol_states.len()
            );
        }
        if common.symbol_states[local_index] == TargetResolutionKind::None {
            let symbol_kind = self.load_symbol(symbol_id, local_index, resources, queue)?;
            if symbol_kind == SymbolKind::IFunc {
                common = self.common_mut();
                common.mem_sizes.got += elf::GOT_ENTRY_SIZE;
                common.mem_sizes.plt += elf::PLT_ENTRY_SIZE;
                common.mem_sizes.rela_plt += elf::RELA_ENTRY_SIZE;
                if resources.symbol_db.args.is_relocatable() {
                    match resources.symbol_db.symbol_value_kind(symbol_id) {
                        ValueKind::Address => {
                            // We need two entries. One for the resolver and one for the address at which
                            // the resolution will be stored.
                            common.mem_sizes.rela_dyn_relative += elf::RELA_ENTRY_SIZE * 2;
                        }
                        ValueKind::Dynamic => {
                            // If our resolver is dynamic, then its relocation will be a glob-dat
                            // relocation, while the relocation for the destination will still be
                            // relative (it doesn't depend on the dynamic library).
                            common.mem_sizes.rela_dyn_glob_dat += elf::RELA_ENTRY_SIZE;
                            common.mem_sizes.rela_dyn_relative += elf::RELA_ENTRY_SIZE;
                        }
                        ValueKind::Absolute => {
                            bail!("An ifunc cannot resolve to an absolute value")
                        }
                    }
                }
                common.symbol_states[local_index] = TargetResolutionKind::IFunc;
            } else {
                common = self.common_mut();
                common.symbol_states[local_index] = TargetResolutionKind::Value;
            }
        }
        match symbol_request.target_resolution_kind {
            TargetResolutionKind::Got | TargetResolutionKind::Plt => {
                if common.symbol_states[local_index] < TargetResolutionKind::Got {
                    common.symbol_states[local_index] = TargetResolutionKind::Got;
                    common.mem_sizes.got += elf::GOT_ENTRY_SIZE;
                    if resources.symbol_db.args.is_relocatable() {
                        match resources.symbol_db.symbol_value_kind(symbol_id) {
                            ValueKind::Address => {
                                common.mem_sizes.rela_dyn_relative += elf::RELA_ENTRY_SIZE;
                            }
                            ValueKind::Dynamic => {
                                common.mem_sizes.rela_dyn_glob_dat += elf::RELA_ENTRY_SIZE;
                            }
                            ValueKind::Absolute => {}
                        }
                    }
                }
                if matches!(
                    symbol_request.target_resolution_kind,
                    TargetResolutionKind::Plt
                ) && common.symbol_states[local_index] < TargetResolutionKind::Plt
                {
                    common.symbol_states[local_index] = TargetResolutionKind::Plt;
                    common.mem_sizes.plt += elf::PLT_ENTRY_SIZE;
                }
            }
            TargetResolutionKind::GotTlsOffset => {
                if common.symbol_states[local_index] < TargetResolutionKind::Got {
                    common.symbol_states[local_index] = TargetResolutionKind::GotTlsOffset;
                    common.mem_sizes.got += elf::GOT_ENTRY_SIZE;
                }
            }
            TargetResolutionKind::GotTlsDouble => match &common.symbol_states[local_index] {
                TargetResolutionKind::Value => {
                    common.symbol_states[local_index] = TargetResolutionKind::GotTlsDouble;
                    common.mem_sizes.got += elf::GOT_ENTRY_SIZE * 2;
                }
                TargetResolutionKind::GotTlsDouble => {}
                other => {
                    bail!("Invalid state transition {other:?} -> TlsGot");
                }
            },
            _ => {}
        }
        Ok(())
    }

    fn start_symbol_id(&self) -> SymbolId;

    fn common_mut(&mut self) -> &mut CommonLayoutState;

    fn file_id(&self) -> FileId;

    fn load_symbol<'scope>(
        &mut self,
        symbol_id: SymbolId,
        local_index: usize,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result<SymbolKind>;

    /// Returns whether `local_index` is a weak definition.
    fn is_weak(&self, local_index: usize) -> bool;
}

impl<'data> SymbolRequestHandler<'data> for ObjectLayoutState<'data> {
    fn common_mut(&mut self) -> &mut CommonLayoutState {
        &mut self.state.common
    }

    fn load_symbol<'scope>(
        &mut self,
        symbol_id: SymbolId,
        local_index: usize,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result<SymbolKind> {
        debug_assert_bail!(
            resources.symbol_db.is_definition(symbol_id),
            "Tried to load symbol in a file that doesn't hold the definition: {}",
            resources.symbol_db.symbol_debug(symbol_id)
        );
        let object_symbol_index = object::SymbolIndex(local_index);
        let local_symbol = self.object.symbol_by_index(object_symbol_index)?;
        let symbol_kind = match local_symbol.flags() {
            object::SymbolFlags::Elf { st_info, .. } => {
                if st_info & 0xf == 10 {
                    SymbolKind::IFunc
                } else {
                    SymbolKind::Regular
                }
            }
            _ => SymbolKind::Regular,
        };
        match local_symbol.section() {
            object::SymbolSection::Section(section_id) => {
                self.state
                    .sections_required
                    .push(SectionRequest::new(section_id));
                self.load_sections(resources, queue)?;
            }
            object::SymbolSection::Common => {
                let common = CommonSymbol::new(&local_symbol)?;
                *self
                    .state
                    .common
                    .mem_sizes
                    .regular_mut(output_section_id::BSS, common.alignment) += common.size;
            }
            _ => {}
        }
        Ok(symbol_kind)
    }

    fn is_weak(&self, local_index: usize) -> bool {
        let object_symbol_index = object::SymbolIndex(local_index);
        self.object
            .symbol_by_index(object_symbol_index)
            .map(|local_symbol| local_symbol.is_weak())
            .unwrap_or(false)
    }

    fn file_id(&self) -> FileId {
        self.state.common.file_id
    }

    fn start_symbol_id(&self) -> SymbolId {
        self.state.common.start_symbol_id
    }
}

impl<'data> SymbolRequestHandler<'data> for DynamicLayoutState<'data> {
    fn start_symbol_id(&self) -> SymbolId {
        self.common.start_symbol_id
    }

    fn common_mut(&mut self) -> &mut CommonLayoutState {
        &mut self.common
    }

    fn file_id(&self) -> FileId {
        self.common.file_id
    }

    fn load_symbol<'scope>(
        &mut self,
        _symbol_id: SymbolId,
        local_index: usize,
        _resources: &GraphResources<'data, 'scope>,
        _queue: &mut LocalWorkQueue,
    ) -> Result<SymbolKind> {
        // TODO: Reading symbol names involves finding the null terminator, which is slightly
        // expensive. We do it up to three times. Once when we build the symbol DB, now, then when
        // we write out the dynamic symbol table. Look into just storing the names the first time.
        let symbol = self
            .object
            .dynamic_symbol_table()
            .context("Missing dynamic symbol table")?
            .symbol_by_index(object::SymbolIndex(local_index))?;
        let name = symbol.name_bytes()?;
        self.common.mem_sizes.dynstr += name.len() as u64 + 1;
        self.common.mem_sizes.dynsym += crate::elf::SYMTAB_ENTRY_SIZE;
        Ok(SymbolKind::Regular)
    }

    fn is_weak(&self, local_index: usize) -> bool {
        self.object
            .symbol_by_index(object::SymbolIndex(local_index))
            .map(|sym| sym.is_local())
            .unwrap_or(false)
    }
}

impl<'data> SymbolRequestHandler<'data> for InternalLayoutState<'data> {
    fn common_mut(&mut self) -> &mut CommonLayoutState {
        &mut self.common
    }

    fn file_id(&self) -> FileId {
        self.common.file_id
    }

    fn load_symbol<'scope>(
        &mut self,
        _symbol_id: SymbolId,
        _local_index: usize,
        _resources: &GraphResources<'data, 'scope>,
        _queue: &mut LocalWorkQueue,
    ) -> Result<SymbolKind> {
        Ok(SymbolKind::Regular)
    }

    fn is_weak(&self, _local_index: usize) -> bool {
        // None of our internal symbols are currently weak.
        false
    }

    fn start_symbol_id(&self) -> SymbolId {
        // Internal-layout always starts from the undefined symbol.
        SymbolId::undefined()
    }
}

impl<'data> SymbolRequestHandler<'data> for EpilogueLayoutState {
    fn common_mut(&mut self) -> &mut CommonLayoutState {
        &mut self.common
    }

    fn file_id(&self) -> FileId {
        self.common.file_id
    }

    fn load_symbol<'scope>(
        &mut self,
        _symbol_id: SymbolId,
        _local_index: usize,
        _resources: &GraphResources<'data, 'scope>,
        _queue: &mut LocalWorkQueue,
    ) -> Result<SymbolKind> {
        Ok(SymbolKind::Regular)
    }

    fn is_weak(&self, _local_index: usize) -> bool {
        // Custom section start/stop symbols are currently never weak.
        false
    }

    fn start_symbol_id(&self) -> SymbolId {
        self.common.start_symbol_id
    }
}

struct CommonLayoutState {
    file_id: FileId,
    mem_sizes: OutputSectionPartMap<u64>,

    /// Which sections have we loaded an input section into. This is not the same as checking
    /// whether the mem sizes for that section are non-zero because we can load an input section
    /// with size 0. If we do that, we still need to produce the output section so that we have
    /// something to refer to in the symtab.
    sections_with_content: OutputSectionMap<bool>,

    /// States of each of our symbols. For symbols defined by us, this tracks whether we've done
    /// things like allocated a GOT entry for the symbol. For symbols defined in other files, it
    /// tracks whether we've asked the other file to allocate a GOT entry.
    symbol_states: Vec<TargetResolutionKind>,

    start_symbol_id: SymbolId,
}

impl CommonLayoutState {
    fn new(
        file_id: FileId,
        num_symbols: usize,
        output_sections: &OutputSections,
        start_symbol_id: SymbolId,
    ) -> Self {
        Self {
            file_id,
            mem_sizes: OutputSectionPartMap::with_size(output_sections.len()),
            sections_with_content: OutputSectionMap::with_size(output_sections.len()),
            symbol_states: vec![TargetResolutionKind::None; num_symbols],
            start_symbol_id,
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
        symbol_db: &'state SymbolDb,
    ) -> GlobalAddressEmitter {
        GlobalAddressEmitter {
            next_got_address: memory_offsets.got,
            next_plt_address: memory_offsets.plt,
            next_rela_plt_address: memory_offsets.rela_plt,
            symbol_states: &self.symbol_states,
            symbol_db,
            plt_relocations: Default::default(),
            start_symbol_id: self.start_symbol_id,
        }
    }
}

struct ObjectLayoutState<'data> {
    input: InputRef<'data>,
    object: &'data File<'data>,
    state: ObjectLayoutMutableState<'data>,
    section_frame_data: Vec<SectionFrameData>,
}

/// The parts of `ObjectLayoutState` that we mutate during layout. Separate so that we can pass
/// mutable references to it while holding shared references to the other bits of
/// `ObjectLayoutState`.
struct ObjectLayoutMutableState<'data> {
    common: CommonLayoutState,

    /// Info about each of our sections. Empty until this object has been activated. Indexed the
    /// same as the sections in the input object.
    sections: Vec<SectionSlot<'data>>,

    /// A queue of sections that we need to load.
    sections_required: Vec<SectionRequest>,

    merged_string_resolution: Vec<Option<MergedStringResolution>>,

    cies: SmallVec<[CieAtOffset<'data>; 2]>,
}

#[derive(Default)]
struct SectionFrameData {
    /// Outgoing references from the FDE(s) for our section. Generally we have one symbol per
    /// section and each symbol has an associated FDE. The FDE generally has 1 or 2 references
    /// (including the reference to the symbol that the FDE is for). The second reference is usually
    /// an exception table. Since we expect that there's often 1 or 2 references, we avoid a
    /// separate allocation for those cases.
    relocation_actions: SmallVec<[RelocationLayoutAction; 2]>,

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

/// What kind of resolution we want for a symbol or section.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub(crate) enum TargetResolutionKind {
    /// No resolution.
    #[default]
    None,

    /// Just a value or address.
    Value,

    /// An address in the global offset table.
    Got,

    /// A TLS offset in the global offset table.
    GotTlsOffset,

    /// A PLT entry and a GOT entry.
    Plt,

    /// A PLT entry and a GOT entry. The GOT entry will have a relocation that will be resolved at
    /// program startup by calling the ifunc resolver function.
    IFunc,

    /// A double-entry in the global offset table. Used to store the module number and offset for a
    /// TLS variable.
    GotTlsDouble,
}

struct DynamicLayoutState<'data> {
    object: &'data File<'data>,
    input: InputRef<'data>,
    common: CommonLayoutState,
    lib_name: &'data [u8],
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
    pub(crate) resolution_kind: TargetResolutionKind,
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
}

// TODO: Consider flattening this if we're sure that we're not going to need other kinds of work
// items.
#[derive(Copy, Clone, Debug)]
enum WorkItem {
    LoadGlobalSymbol(SymbolRequest),
}

#[derive(Copy, Clone, Debug)]
struct SymbolRequest {
    symbol_id: SymbolId,
    target_resolution_kind: TargetResolutionKind,
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

    pub(crate) fn symbol_resolution(&self, symbol_id: SymbolId) -> Option<&Resolution> {
        let canonical = self.symbol_db.definition(symbol_id);
        self.symbol_resolutions.resolutions[canonical.as_usize()].as_ref()
    }

    pub(crate) fn resolutions_in_range(
        &self,
        start: SymbolId,
        num_symbols: usize,
    ) -> impl Iterator<Item = (SymbolId, Option<&Resolution>)> {
        self.symbol_resolutions.resolutions[start.as_usize()..start.as_usize() + num_symbols]
            .iter()
            .enumerate()
            .map(move |(i, res)| (start.add_usize(i), res.as_ref()))
    }

    pub(crate) fn entry_symbol_address(&self) -> Result<u64> {
        let symbol_id = self.internal().entry_symbol_id;
        match self.symbol_resolution(symbol_id) {
            Some(Resolution {
                value: ResolutionValue::Address(address),
                ..
            }) => Ok(*address),
            Some(Resolution {
                value: ResolutionValue::Dynamic(..),
                ..
            }) => {
                bail!(
                    "Symbol can't be from a dynamic library: {}",
                    self.symbol_debug(symbol_id)
                )
            }
            Some(Resolution {
                value: ResolutionValue::Absolute(..),
                ..
            }) => {
                bail!(
                    "Symbol can't be an absolute value: {}",
                    self.symbol_debug(symbol_id)
                )
            }
            None => {
                bail!(
                    "Symbol was present, but didn't get loaded: {}",
                    self.symbol_debug(symbol_id)
                )
            }
        }
    }

    pub(crate) fn tls_start_address(&self) -> u64 {
        let tdata = &self.section_layouts.built_in(output_section_id::TDATA);
        tdata.mem_offset
    }

    /// Returns the memory address of the end of the TLS segment including any padding required to
    /// make sure that the TCB will be usize-aligned.
    pub(crate) fn tls_end_address(&self) -> u64 {
        let tbss = &self.section_layouts.built_in(output_section_id::TBSS);
        let tls_end = tbss.mem_offset + tbss.mem_size;
        // If the end of the TLS segment isn't usize-aligned, then padding will be inserted so
        // that the TCB is properly aligned.
        alignment::USIZE.align_up(tls_end)
    }

    pub(crate) fn vma_of_section(&self, section_id: OutputSectionId) -> u64 {
        self.section_layouts.get(section_id).mem_offset
    }

    pub(crate) fn size_of_section(&self, section_id: OutputSectionId) -> u64 {
        self.section_layouts.get(section_id).file_size as u64
    }

    pub(crate) fn is_file_loaded(&self, file_id: FileId) -> bool {
        !matches!(self.file_layouts[file_id.as_usize()], FileLayout::NotLoaded)
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
    let segments = header_info
        .active_segment_ids
        .iter()
        .map(|&id| {
            let r = &complete[id.as_usize()];
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
    SegmentLayouts { segments }
}

#[tracing::instrument(skip_all, name = "Compute total section sizes")]
fn compute_total_section_part_sizes(
    layout_states: &mut [FileLayoutState],
    output_sections: &mut OutputSections,
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
    );
    total_sizes
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
    };

    workers
        .into_par_iter()
        .try_for_each(|mut worker| -> Result {
            worker.activate(resources)?;
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
            FileLayoutState::Dynamic(s) => s.activate(),
            FileLayoutState::NotLoaded => Ok(()),
            FileLayoutState::Epilogue(_) => Ok(()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkDestination {
    Local,
    Remote,
}

impl LocalWorkQueue {
    fn send_work(
        &mut self,
        resources: &GraphResources,
        file_id: FileId,
        work: WorkItem,
    ) -> WorkDestination {
        if file_id.as_usize() == self.index {
            self.local_work.push(work);
            WorkDestination::Local
        } else {
            resources.send_work(file_id, work);
            WorkDestination::Remote
        }
    }

    fn new(index: usize) -> LocalWorkQueue {
        Self {
            index,
            local_work: Default::default(),
        }
    }

    fn send_symbol_request(
        &mut self,
        symbol_id: SymbolId,
        plt_got_flags: TargetResolutionKind,
        resources: &GraphResources,
    ) -> WorkDestination {
        let symbol_definition = resources.symbol_db.definition(symbol_id);
        let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_definition);
        let symbol_request = SymbolRequest {
            symbol_id: symbol_definition,
            target_resolution_kind: plt_got_flags,
        };
        self.send_work(
            resources,
            symbol_file_id,
            WorkItem::LoadGlobalSymbol(symbol_request),
        )
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
    fn finalise_sizes(&mut self, symbol_db: &SymbolDb, output_sections: &OutputSections) -> Result {
        match self {
            FileLayoutState::Object(s) => s
                .finalise_sizes(symbol_db, output_sections)
                .with_context(|| format!("finalise_sizes failed for {s}"))?,
            FileLayoutState::Dynamic(s) => s.finalise_sizes()?,
            FileLayoutState::Internal(s) => s.finalise_sizes(symbol_db)?,
            FileLayoutState::Epilogue(s) => s.finalise_sizes(symbol_db)?,
            FileLayoutState::NotLoaded => {}
        }
        Ok(())
    }

    fn do_work<'scope>(
        &mut self,
        work_item: WorkItem,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        match work_item {
            WorkItem::LoadGlobalSymbol(symbol_request) => self
                .handle_symbol_request(symbol_request, resources, queue)
                .with_context(|| {
                    format!(
                        "Failed to load {} from {self}",
                        resources.symbol_db.symbol_debug(symbol_request.symbol_id),
                    )
                }),
        }
    }

    fn handle_symbol_request<'scope>(
        &mut self,
        symbol_request: SymbolRequest,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        match self {
            FileLayoutState::Object(state) => {
                state.handle_symbol_request(symbol_request, resources, queue)?;
            }
            FileLayoutState::Internal(state) => {
                state.handle_symbol_request(symbol_request, resources, queue)?;
            }
            FileLayoutState::Dynamic(state) => {
                state.handle_symbol_request(symbol_request, resources, queue)?
            }
            FileLayoutState::NotLoaded => {}
            FileLayoutState::Epilogue(state) => {
                state.handle_symbol_request(symbol_request, resources, queue)?
            }
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

    pub(crate) fn common(&self) -> Option<&CommonLayoutState> {
        match self {
            Self::Object(s) => Some(&s.state.common),
            Self::Internal(s) => Some(&s.common),
            Self::Epilogue(s) => Some(&s.common),
            Self::Dynamic(_) => None,
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
    ) -> Result<FileLayout<'data>> {
        let file_layout = match self {
            Self::Object(s) => FileLayout::Object(s.finalise_layout(
                memory_offsets.unwrap(),
                addresses_out,
                section_layouts,
                symbol_db,
                output_sections,
                merged_string_start_addresses,
            )?),
            Self::Internal(s) => FileLayout::Internal(s.finalise_layout(
                memory_offsets.unwrap(),
                section_layouts,
                addresses_out,
                output_sections,
                symbol_db,
            )?),
            Self::Epilogue(s) => FileLayout::Epilogue(s.finalise_layout(
                memory_offsets.unwrap(),
                section_layouts,
                addresses_out,
                output_sections,
                symbol_db,
            )?),
            Self::Dynamic(s) => FileLayout::Dynamic(s.finalise_layout(
                memory_offsets.unwrap(),
                section_layouts,
                addresses_out,
                output_sections,
                symbol_db,
            )?),
            Self::NotLoaded => FileLayout::NotLoaded,
        };
        Ok(file_layout)
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

impl std::fmt::Display for EpilogueLayoutState {
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
    resolution_kind: TargetResolutionKind,
}

impl SectionRequest {
    fn new(id: object::SectionIndex) -> Self {
        Self {
            id,
            resolution_kind: Default::default(),
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
        let object_section = worker.object.section_by_index(section_id)?;
        let alignment = Alignment::new(object_section.align())?;
        let size = object_section.size();
        let section_data = object_section.data()?;
        for (rel_offset, rel) in object_section.relocations() {
            if let Some(action) = RelocationLayoutAction::new(
                &rel,
                &object_section,
                rel_offset,
                &worker.state,
                resources.symbol_db,
            )? {
                action.apply(resources, &mut worker.state, queue);
            }
        }
        let section = Section {
            index: section_id,
            output_section_id: None,
            alignment,
            size,
            data: section_data,
            resolution_kind: TargetResolutionKind::None,
            packed: unloaded.details.packed,
        };
        Ok(section)
    }

    fn allocate_required_entries(
        &mut self,
        request: &SectionRequest,
        mem_sizes: &mut OutputSectionPartMap<u64>,
        args: &Args,
    ) -> Result {
        if self.resolution_kind >= request.resolution_kind {
            return Ok(());
        }
        match (self.resolution_kind, request.resolution_kind) {
            (_, TargetResolutionKind::Got) => {
                mem_sizes.got += elf::GOT_ENTRY_SIZE;
                if args.is_relocatable() {
                    mem_sizes.rela_dyn_relative += elf::RELA_ENTRY_SIZE;
                }
            }
            (
                TargetResolutionKind::Value | TargetResolutionKind::None,
                TargetResolutionKind::GotTlsOffset,
            ) => {
                mem_sizes.got += elf::GOT_ENTRY_SIZE;
            }
            (TargetResolutionKind::Got, TargetResolutionKind::Plt) => {
                mem_sizes.plt += elf::PLT_ENTRY_SIZE;
            }
            (_, TargetResolutionKind::Plt) => {
                mem_sizes.got += elf::GOT_ENTRY_SIZE;
                if args.is_relocatable() {
                    mem_sizes.rela_dyn_relative += elf::RELA_ENTRY_SIZE;
                }
                mem_sizes.plt += elf::PLT_ENTRY_SIZE;
            }
            (
                TargetResolutionKind::Value | TargetResolutionKind::None,
                TargetResolutionKind::GotTlsDouble,
            ) => {
                mem_sizes.got += elf::GOT_ENTRY_SIZE * 2;
            }
            (_, TargetResolutionKind::Value) => {}
            (a, b) => bail!("Unexpected state transition {a:?} -> {b:?}"),
        }
        self.resolution_kind = request.resolution_kind;
        Ok(())
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

/// Represents an action that we need to perform during layout if we decide that we need to apply a
/// relocation. For regular sections we always create the action then apply it straight away,
/// however for FDEs (frame description entries), we create them, store them and only later decide
/// if we're going to apply them.
#[derive(Clone, Copy, Debug)]
struct RelocationLayoutAction {
    kind: RelocationLayoutActionKind,
    dynamic_relocation_required: bool,
}

/// An action that we need to perform if we decide to use a particular relocation.
#[derive(Clone, Copy, Debug)]
enum RelocationLayoutActionKind {
    LoadSymbol(SymbolId, TargetResolutionKind),
    LoadSection(object::SectionIndex, TargetResolutionKind),
}

impl RelocationLayoutAction {
    fn new(
        rel: &object::Relocation,
        section: &elf::Section,
        rel_offset: u64,
        state: &ObjectLayoutMutableState<'_>,
        symbol_db: &SymbolDb,
    ) -> Result<Option<Self>> {
        let args = symbol_db.args;
        match rel.target() {
            object::RelocationTarget::Symbol(local_sym_index) => {
                let symbol_id = state.common.start_symbol_id.add_usize(local_sym_index.0);
                return Ok(Some(Self::for_symbol(
                    rel, rel_offset, section, symbol_db, symbol_id, args,
                )?));
            }
            object::RelocationTarget::Section(local_section_index) => {
                return Ok(Some(Self::for_section(
                    rel,
                    rel_offset,
                    section,
                    args,
                    local_section_index,
                )?));
            }
            _ => {}
        };
        Ok(None)
    }

    fn for_symbol(
        rel: &object::Relocation,
        rel_offset: u64,
        section: &elf::Section,
        symbol_db: &SymbolDb<'_>,
        symbol_id: SymbolId,
        args: &Args,
    ) -> Result<RelocationLayoutAction> {
        let symbol_value_kind = symbol_db.symbol_value_kind(symbol_db.definition(symbol_id));
        let object::RelocationFlags::Elf { mut r_type } = rel.flags() else {
            unreachable!();
        };
        if let Some((_relaxation, new_r_type)) = Relaxation::new(
            r_type,
            section.data()?,
            rel_offset,
            symbol_value_kind,
            args.output_kind,
        ) {
            r_type = new_r_type;
        }
        let rel_info = RelocationKindInfo::from_raw(r_type)?;
        let resolution_kind = TargetResolutionKind::new(rel_info.kind)?;
        let dynamic_relocation_required = args.is_relocatable()
            && matches!(rel_info.kind, RelocationKind::Absolute)
            && matches!(symbol_value_kind, ValueKind::Address);
        let relocation_layout_action = RelocationLayoutAction {
            kind: RelocationLayoutActionKind::LoadSymbol(symbol_id, resolution_kind),
            dynamic_relocation_required,
        };
        Ok(relocation_layout_action)
    }

    fn for_section(
        rel: &object::Relocation,
        rel_offset: u64,
        section: &elf::Section,
        args: &Args,
        local_section_index: object::SectionIndex,
    ) -> Result<RelocationLayoutAction, Error> {
        let object::RelocationFlags::Elf { mut r_type } = rel.flags() else {
            unreachable!();
        };
        if let Some((_relaxation, new_r_type)) = Relaxation::new(
            r_type,
            section.data()?,
            rel_offset,
            ValueKind::Address,
            args.output_kind,
        ) {
            r_type = new_r_type;
        }
        let rel_info = RelocationKindInfo::from_raw(r_type)?;
        let resolution_kind = TargetResolutionKind::new(rel_info.kind)?;
        Ok(RelocationLayoutAction {
            kind: RelocationLayoutActionKind::LoadSection(local_section_index, resolution_kind),
            dynamic_relocation_required: args.is_relocatable()
                && matches!(rel_info.kind, RelocationKind::Absolute),
        })
    }

    fn apply(
        &self,
        resources: &GraphResources<'_, '_>,
        state: &mut ObjectLayoutMutableState<'_>,
        queue: &mut LocalWorkQueue,
    ) {
        match self.kind {
            RelocationLayoutActionKind::LoadSymbol(symbol_id, resolution_kind) => {
                let local_sym_index = symbol_id.offset_from(state.common.start_symbol_id);
                if state.common.symbol_states[local_sym_index] < resolution_kind {
                    let destination =
                        queue.send_symbol_request(symbol_id, resolution_kind, resources);
                    // For a symbol request that has a local destination, we'll update the symbol
                    // state when we process the request.
                    if destination == WorkDestination::Remote {
                        state.common.symbol_states[local_sym_index] = resolution_kind;
                    }
                }
            }
            RelocationLayoutActionKind::LoadSection(local_section_index, resolution_kind) => {
                // TODO: See if it's worthwhile checking if we've already loaded the section.
                state.sections_required.push(SectionRequest {
                    id: local_section_index,
                    resolution_kind,
                });
            }
        }
        if self.dynamic_relocation_required {
            state.common.mem_sizes.rela_dyn_relative += elf::RELA_ENTRY_SIZE;
        }
    }
}

impl TargetResolutionKind {
    fn new(rel_kind: RelocationKind) -> Result<Self> {
        Ok(match rel_kind {
            RelocationKind::PltRelative => Self::Plt,
            RelocationKind::Got | RelocationKind::GotRelative => Self::Got,
            RelocationKind::GotTpOff => Self::GotTlsOffset,
            RelocationKind::TlsGd | RelocationKind::TlsLd => Self::GotTlsDouble,
            RelocationKind::Absolute => Self::Value,
            RelocationKind::Relative => Self::Value,
            RelocationKind::DtpOff | RelocationKind::TpOff => Self::Value,
            RelocationKind::None => Self::Value,
        })
    }

    pub(crate) fn needs_got_entry(&self) -> bool {
        !matches!(self, Self::Value | Self::None)
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
                input_state.symbol_definitions.len(),
                output_sections,
                SymbolId::undefined(),
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

        // The first entry in the symbol table must be null. Similarly, the first string in the
        // strings table must be empty.
        layout.common.mem_sizes.symtab_locals = size_of::<elf::SymtabEntry>() as u64;
        layout.common.mem_sizes.symtab_strings = 1;

        // Allocate a GOT entry that we can use for any references to undefined weak symbols.
        layout.common.mem_sizes.got += elf::GOT_ENTRY_SIZE;

        layout
    }

    fn activate(&mut self, resources: &GraphResources<'_, '_>) -> Result {
        let symbol_id = *resources
            .symbol_db
            .global_names
            .get(&SymbolName::prehashed(b"_start"))
            .context("Missing _start symbol")?;
        self.entry_symbol_id = Some(symbol_id);
        let file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        resources.send_work(
            file_id,
            WorkItem::LoadGlobalSymbol(SymbolRequest {
                symbol_id,
                target_resolution_kind: Default::default(),
            }),
        );
        if resources.symbol_db.args.tls_mode() == TlsMode::Preserve {
            // Allocate space for a TLS module number and offset for use with TLSLD relocations.
            self.common.mem_sizes.got += elf::GOT_ENTRY_SIZE * 2;
            self.needs_tlsld_got_entry = true;
        }

        if resources.symbol_db.args.is_relocatable() {
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

    fn finalise_sizes(&mut self, symbol_db: &SymbolDb) -> Result {
        if !symbol_db.args.strip_all {
            self.internal_symbols
                .allocate_symbol_table_sizes(symbol_db, &mut self.common)?;
        }

        self.common.mem_sizes.eh_frame_hdr += core::mem::size_of::<elf::EhFrameHdr>() as u64;

        Ok(())
    }

    fn determine_header_sizes(
        &mut self,
        total_sizes: &mut OutputSectionPartMap<u64>,
        sections_with_content: OutputSectionMap<bool>,
        output_sections: &mut OutputSections,
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
        self.common
            .symbol_states
            .iter()
            .zip(self.internal_symbols.symbol_definitions.iter())
            .for_each(|(symbol_state, definition)| {
                if *symbol_state != TargetResolutionKind::None {
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

        // Allocate space for headers based on segment and section counts. We need to allocate both
        // our own size record and the file totals, since they've already been computed.
        self.common.mem_sizes.file_header = u64::from(elf::FILE_HEADER_SIZE);
        total_sizes.file_header += self.common.mem_sizes.file_header;

        self.common.mem_sizes.program_headers = header_info.program_headers_size();
        total_sizes.program_headers += self.common.mem_sizes.program_headers;

        self.common.mem_sizes.section_headers = header_info.section_headers_size();
        total_sizes.section_headers += self.common.mem_sizes.section_headers;

        self.common.mem_sizes.shstrtab = output_sections
            .ids_with_info()
            .filter(|(id, _info)| output_sections.output_index_of_section(*id).is_some())
            .map(|(_id, info)| info.details.name.len() as u64 + 1)
            .sum::<u64>();
        total_sizes.shstrtab += self.common.mem_sizes.shstrtab;

        self.header_info = Some(header_info);
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
        resolutions_out: &mut [Option<Resolution>],
        output_sections: &OutputSections,
        symbol_db: &SymbolDb,
    ) -> Result<InternalLayout<'data>> {
        let header_layout = section_layouts.built_in(output_section_id::FILE_HEADER);
        assert_eq!(header_layout.file_offset, 0);

        // We need a GOT address to use for any relocations that point to undefined weak symbols.
        let undefined_symbol_resolution = Resolution {
            value: ResolutionValue::Absolute(0),
            got_address: Some(
                NonZeroU64::new(memory_offsets.got).expect("GOT address must never be zero"),
            ),
            // If anything ever actually tries to call the PLT for an undefined symbol, it's
            // undefined behaviour, so we can put whatever pointer we like here.
            plt_address: NonZeroU64::new(0xdead),
            kind: TargetResolutionKind::Plt,
        };
        memory_offsets.got += elf::GOT_ENTRY_SIZE;

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
        )?;

        let strings_offset_start = self.common.finalise_layout(memory_offsets, section_layouts);
        Ok(InternalLayout {
            file_sizes: compute_file_sizes(&self.common.mem_sizes, output_sections),
            mem_sizes: self.common.mem_sizes,
            internal_symbols: self.internal_symbols,
            undefined_symbol_resolution,
            strings_offset_start,
            entry_symbol_id: self.entry_symbol_id.unwrap(),
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
    ) -> Result {
        // Allocate space in the symbol table for the symbols that we define.
        for (index, def_info) in self.symbol_definitions.iter().enumerate() {
            let symbol_id = self.start_symbol_id.add_usize(index);
            if !symbol_db.is_definition(symbol_id) || symbol_id.is_undefined() {
                continue;
            }
            let sym_state = &common.symbol_states[index];
            // Don't allocate space for symbols that are in our headers section, since it doesn't
            // have an entry.
            if def_info.section_id() == Some(output_section_id::FILE_HEADER) {
                continue;
            }

            // We don't put internal symbols in the symbol table if they aren't referenced.
            if matches!(sym_state, TargetResolutionKind::None) {
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
    ) -> Result {
        // Define symbols that are optionally put at the start/end of some sections.
        let mut emitter = common.create_global_address_emitter(memory_offsets, symbol_db);
        for (local_index, def_info) in self.symbol_definitions.iter().enumerate() {
            let symbol_id = self.start_symbol_id.add_usize(local_index);
            if !symbol_db.is_definition(symbol_id) {
                continue;
            }
            let sym_state = &common.symbol_states[local_index];

            // We don't put internal symbols in the symbol table if they aren't referenced.
            if matches!(sym_state, TargetResolutionKind::None) {
                continue;
            }

            let value = match def_info {
                InternalSymDefInfo::Undefined => ResolutionValue::Absolute(0),
                InternalSymDefInfo::SectionStart(section_id) => {
                    ResolutionValue::Address(section_layouts.built_in(*section_id).mem_offset)
                }
                InternalSymDefInfo::SectionEnd(section_id) => {
                    let sec = &section_layouts.built_in(*section_id);
                    ResolutionValue::Address(sec.mem_offset + sec.mem_size)
                }
            };
            emitter.emit_resolution(symbol_id, value, resolutions_out)?;
        }
        Ok(())
    }
}

impl EpilogueLayoutState {
    fn new(input_state: ResolvedEpilogue, output_sections: &OutputSections) -> EpilogueLayoutState {
        EpilogueLayoutState {
            common: CommonLayoutState::new(
                input_state.file_id,
                input_state.symbol_definitions.len(),
                output_sections,
                input_state.start_symbol_id,
            ),
            internal_symbols: InternalSymbols {
                symbol_definitions: input_state.symbol_definitions,
                start_symbol_id: input_state.start_symbol_id,
            },
        }
    }

    fn finalise_sizes(&mut self, symbol_db: &SymbolDb) -> Result {
        if !symbol_db.args.strip_all {
            self.internal_symbols
                .allocate_symbol_table_sizes(symbol_db, &mut self.common)?;
        }

        if symbol_db.args.needs_dynamic() {
            self.common.mem_sizes.dynamic += (elf_writer::NUM_EPILOGUE_DYNAMIC_ENTRIES
                * core::mem::size_of::<crate::elf::DynamicEntry>())
                as u64;
        }

        Ok(())
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
        resolutions_out: &mut [Option<Resolution>],
        output_sections: &OutputSections,
        symbol_db: &SymbolDb,
    ) -> Result<EpilogueLayout> {
        self.internal_symbols.finalise_layout(
            &self.common,
            symbol_db,
            memory_offsets,
            section_layouts,
            resolutions_out,
        )?;

        let strings_offset_start = self.common.finalise_layout(memory_offsets, section_layouts);
        Ok(EpilogueLayout {
            file_sizes: compute_file_sizes(&self.common.mem_sizes, output_sections),
            mem_sizes: self.common.mem_sizes,
            internal_symbols: self.internal_symbols,
            strings_offset_start,
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
    let common = CommonLayoutState::new(
        input_state.file_id,
        input_state.num_symbols,
        output_sections,
        input_state.start_symbol_id,
    );
    if let Some(non_dynamic) = input_state.non_dynamic {
        FileLayoutState::Object(Box::new(ObjectLayoutState {
            input: input_state.input,
            object: input_state.object,
            section_frame_data: Default::default(),
            state: ObjectLayoutMutableState {
                common,
                sections: non_dynamic.sections,
                sections_required: Default::default(),
                merged_string_resolution: non_dynamic.merged_string_resolutions,
                cies: Default::default(),
            },
        }))
    } else {
        FileLayoutState::Dynamic(Box::new(DynamicLayoutState {
            lib_name: input_state
                .input
                .file
                .filename
                .file_name()
                .map(|f| f.as_encoded_bytes())
                .unwrap_or_default(),
            object: input_state.object,
            input: input_state.input,
            common,
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
                    eh_frame_section = Some(self.object.section_by_index(*index)?);
                }
                _ => (),
            }
        }
        if let Some(eh_frame_section) = eh_frame_section {
            process_eh_frame_data(
                self.object,
                self.start_symbol_id(),
                &mut self.section_frame_data,
                &mut self.state,
                eh_frame_section,
                resources,
                queue,
            )?;
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
                    if let Some(frame_data) = self.section_frame_data.get(section_id.0) {
                        self.state.common.mem_sizes.eh_frame +=
                            u64::from(frame_data.total_fde_size);
                        self.state.common.mem_sizes.eh_frame_hdr +=
                            core::mem::size_of::<EhFrameHdrEntry>() as u64
                                * u64::from(frame_data.num_fdes);
                        // Request loading of any sections/symbols referenced by the FDEs for our
                        // section.
                        for action in &frame_data.relocation_actions {
                            action.apply(resources, &mut self.state, queue);
                        }
                    }
                    self.state.sections[section_id.0] = SectionSlot::Loaded(section);
                }
                SectionSlot::Discard => {
                    let object_section = self.object.section_by_index(section_id)?;
                    bail!(
                        "{self}: Don't know what segment to put `{}` in, but it's referenced",
                        String::from_utf8_lossy(object_section.name_bytes()?),
                    );
                }
                SectionSlot::Loaded(_) | SectionSlot::EhFrameData(..) => {}
                SectionSlot::MergeStrings(_) => {
                    // We currently always load everything in merge-string sections. i.e. we don't
                    // GC unreferenced data. So there's nothing to do here.
                }
            }
            if let SectionSlot::Loaded(section) = &mut self.state.sections[section_id.0] {
                section.allocate_required_entries(
                    &section_request,
                    &mut self.state.common.mem_sizes,
                    resources.symbol_db.args,
                )?;
            };
        }
        Ok(())
    }

    fn finalise_sizes(&mut self, symbol_db: &SymbolDb, output_sections: &OutputSections) -> Result {
        self.state.common.mem_sizes.resize(output_sections.len());
        if !symbol_db.args.strip_all {
            self.allocate_symtab_space(symbol_db)?;
        }
        // TODO: Deduplicate CIEs from different objects, then only allocate space for those CIEs
        // that we "won".
        for cie in &self.state.cies {
            self.state.common.mem_sizes.eh_frame += cie.cie.bytes.len() as u64;
        }
        Ok(())
    }

    fn allocate_symtab_space(&mut self, symbol_db: &SymbolDb<'_>) -> Result {
        let mut num_locals = 0;
        let mut num_globals = 0;
        let mut strings_size = 0;
        for sym in self.object.symbols() {
            match sym.section() {
                object::SymbolSection::Section(section_index) => {
                    if self.state.sections[section_index.0].is_loaded() {
                        let name = &sym.name_bytes()?;
                        if should_copy_symbol(name) {
                            if sym.is_global() {
                                num_globals += 1;
                            } else {
                                num_locals += 1;
                            }
                            strings_size += name.len() + 1;
                        }
                    }
                }
                object::SymbolSection::Common => {
                    let symbol_id = self.start_symbol_id().add_usize(sym.index().0);
                    let symbol_file_id = symbol_db.file_id_for_symbol(symbol_id);
                    if symbol_file_id == self.state.common.file_id
                        && self.state.common.symbol_states[sym.index().0]
                            != TargetResolutionKind::None
                    {
                        num_globals += 1;
                        strings_size += sym.name_bytes()?.len() + 1;
                    }
                }
                _ => {}
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
    ) -> Result<ObjectLayout<'data>> {
        let start_symbol_id = self.start_symbol_id();
        let mut sections = self.state.sections;

        let mut emitter = self
            .state
            .common
            .create_global_address_emitter(memory_offsets, symbol_db);

        let mut section_resolutions = Vec::with_capacity(sections.len());
        for slot in sections.iter_mut() {
            match slot {
                SectionSlot::Loaded(sec) => {
                    let output_section_id = sec.output_section_id.with_context(|| {
                        format!(
                            "Tried to load section `{}` which isn't mapped to an output section",
                            self.object
                                .section_by_index(sec.index)
                                .and_then(|s| s.name())
                                .unwrap_or("??")
                        )
                    })?;
                    let address = memory_offsets.regular_mut(output_section_id, sec.alignment);
                    // TODO: We probably need to be able to handle sections that are ifuncs and sections
                    // that need a TLS GOT struct.
                    section_resolutions.push(Some(emitter.create_resolution(
                        sec.resolution_kind,
                        ResolutionValue::Address(*address),
                    )?));
                    *address += sec.capacity();
                }
                SectionSlot::EhFrameData(..) => {
                    // References to symbols defined in .eh_frame are a bit weird, since it's a
                    // section where we're GCing stuff, but crtbegin.o and crtend.o use them in
                    // order to find the start and end of the whole .eh_frame section.
                    section_resolutions.push(Some(emitter.create_resolution(
                        TargetResolutionKind::Value,
                        ResolutionValue::Address(memory_offsets.eh_frame),
                    )?));
                }
                _ => {
                    section_resolutions.push(None);
                }
            }
        }

        for (local_symbol, symbol_state) in
            self.object.symbols().zip(&self.state.common.symbol_states)
        {
            if *symbol_state == TargetResolutionKind::None {
                continue;
            }
            let symbol_id = start_symbol_id.add_usize(local_symbol.index().0);
            if !symbol_db.is_definition(symbol_id) {
                continue;
            }
            let local_symbol = self.object.symbol_by_index(local_symbol.index())?;
            let value = match local_symbol.section() {
                object::SymbolSection::Section(section_index) => {
                    if let Some(section_resolution) = section_resolutions[section_index.0].as_ref()
                    {
                        ResolutionValue::Address(
                            local_symbol.address() + section_resolution.value.address_or_value()?,
                        )
                    } else {
                        ResolutionValue::Address(merged_string_start_addresses
                            .try_resolve_local(
                                &self.state.merged_string_resolution,
                                local_symbol.index(),
                            )
                            .ok_or_else(|| {
                                anyhow!(
                                    "Symbol is in a section that we didn't load. Symbol: {} Section: {}",
                                    symbol_db.symbol_debug(symbol_id),
                                    section_debug(self.object, section_index),
                                )
                            })?)
                    }
                }
                object::SymbolSection::Common => {
                    let common = CommonSymbol::new(&local_symbol)?;
                    let offset =
                        memory_offsets.regular_mut(output_section_id::BSS, common.alignment);
                    let address = *offset;
                    *offset += common.size;
                    ResolutionValue::Address(address)
                }
                object::SymbolSection::Absolute => {
                    ResolutionValue::Absolute(local_symbol.address())
                }
                _ => ResolutionValue::Address(local_symbol.address()),
            };
            emitter.emit_resolution(symbol_id, value, resolutions_out)?;
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
            start_symbol_id,
            num_symbols: self.state.common.symbol_states.len(),
        })
    }
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
        local_symbol_index: object::SymbolIndex,
    ) -> Option<u64> {
        merged_string_resolutions[local_symbol_index.0].map(|res| self.resolve(res))
    }

    pub(crate) fn resolve(&self, res: resolution::MergedStringResolution) -> u64 {
        self.addresses.get(res.output_section_id) + res.offset
    }
}

/// Returns whether we should copy a symbol with the specified name into the output symbol table.
/// Symbols with empty names and those starting with '.' aren't copied.
pub(crate) fn should_copy_symbol(name: &[u8]) -> bool {
    !name.is_empty() && !name.starts_with(b".")
}

fn process_eh_frame_data<'data>(
    object: &crate::elf::File<'data>,
    file_start_symbol: SymbolId,
    section_frame_data: &mut Vec<SectionFrameData>,
    state: &mut ObjectLayoutMutableState<'data>,
    eh_frame_section: elf::Section<'data, '_>,
    resources: &GraphResources,
    queue: &mut LocalWorkQueue,
) -> Result {
    section_frame_data.resize_with(state.sections.len(), Default::default);
    let data = eh_frame_section.data()?;
    const PREFIX_LEN: usize = core::mem::size_of::<elf::EhFrameEntryPrefix>();
    let mut relocations = eh_frame_section.relocations().peekable();
    let mut offset = 0;
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
            while let Some((rel_offset, rel)) = relocations.peek() {
                if *rel_offset >= next_offset as u64 {
                    // This relocation belongs to the next entry.
                    break;
                }
                // We currently always load all CIEs, so any relocations found in CIEs always need
                // to be processed.
                if let Some(action) = RelocationLayoutAction::new(
                    rel,
                    &eh_frame_section,
                    *rel_offset,
                    state,
                    resources.symbol_db,
                )? {
                    action.apply(resources, state, queue);
                }
                if let object::RelocationTarget::Symbol(local_sym_index) = rel.target() {
                    let local_symbol_id = file_start_symbol.add_usize(local_sym_index.0);
                    let definition = resources.symbol_db.definition(local_symbol_id);
                    referenced_symbols.push(definition);
                } else {
                    eligible_for_deduplication = false;
                }
                relocations.next();
            }
            state.cies.push(CieAtOffset {
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
            let mut actions: SmallVec<[RelocationLayoutAction; 2]> = Default::default();

            while let Some((rel_offset, rel)) = relocations.peek() {
                if *rel_offset < next_offset as u64 {
                    let is_pc_begin = (*rel_offset as usize - offset) == elf::FDE_PC_BEGIN_OFFSET;

                    if is_pc_begin {
                        match rel.target() {
                            object::RelocationTarget::Symbol(index) => {
                                let elf_symbol = &object.symbol_by_index(index)?;
                                section_index = elf_symbol.section_index();
                            }
                            object::RelocationTarget::Section(index) => {
                                section_index = Some(index);
                            }
                            _ => {}
                        };
                    }
                    if let Some(action) = RelocationLayoutAction::new(
                        rel,
                        &eh_frame_section,
                        *rel_offset,
                        state,
                        resources.symbol_db,
                    )? {
                        actions.push(action);
                    }
                    relocations.next();
                } else {
                    break;
                }
            }
            if let Some(section_index) = section_index {
                let section_frame_data = &mut section_frame_data[section_index.0];
                section_frame_data.relocation_actions.append(&mut actions);
                section_frame_data.num_fdes += 1;
                section_frame_data.total_fde_size += size as u32;
            }
        }
        offset = next_offset;
    }
    // Allocate space for any remaining bytes in .eh_frame that aren't large enough to constitute an
    // actual entry. crtend.o has a single u32 equal to 0 as an end marker.
    state.common.mem_sizes.eh_frame += (data.len() - offset) as u64;
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
    fn new(local_symbol: &crate::elf::Symbol) -> Result<CommonSymbol> {
        debug_assert!(local_symbol.is_common());
        // Common symbols misuse the value field (which we access via `address()`) to store the
        // alignment.
        let alignment = Alignment::new(local_symbol.address())?;
        let size = alignment.align_up(local_symbol.size());
        Ok(CommonSymbol { size, alignment })
    }
}

struct GlobalAddressEmitter<'state> {
    next_got_address: u64,
    next_plt_address: u64,
    next_rela_plt_address: u64,
    symbol_states: &'state [TargetResolutionKind],
    symbol_db: &'state SymbolDb<'state>,
    plt_relocations: Vec<IfuncRelocation>,
    start_symbol_id: SymbolId,
}

impl<'state> GlobalAddressEmitter<'state> {
    fn emit_resolution(
        &mut self,
        symbol_id: SymbolId,
        value: ResolutionValue,
        resolutions_out: &mut [Option<Resolution>],
    ) -> Result {
        debug_assert_bail!(
            symbol_id >= self.start_symbol_id
                && symbol_id.offset_from(self.start_symbol_id) < resolutions_out.len(),
            "Tried to emit resolution for {} which is outside {}..{}",
            self.symbol_db.symbol_debug(symbol_id),
            self.start_symbol_id,
            self.start_symbol_id.add_usize(resolutions_out.len())
        );
        let local_symbol_index = symbol_id.offset_from(self.start_symbol_id);
        let resolution = self.create_resolution(self.symbol_states[local_symbol_index], value)?;
        resolutions_out[local_symbol_index] = Some(resolution);
        Ok(())
    }

    fn create_resolution(
        &mut self,
        res_kind: TargetResolutionKind,
        value: ResolutionValue,
    ) -> Result<Resolution> {
        let mut resolution = Resolution {
            value,
            got_address: None,
            plt_address: None,
            kind: res_kind,
        };
        match res_kind {
            TargetResolutionKind::None | TargetResolutionKind::Value => {}
            TargetResolutionKind::Got | TargetResolutionKind::GotTlsOffset => {
                resolution.got_address = Some(self.allocate_got());
            }
            TargetResolutionKind::Plt => {
                resolution.got_address = Some(self.allocate_got());
                resolution.plt_address = Some(self.allocate_plt());
            }
            TargetResolutionKind::IFunc => {
                let got_address = self.allocate_got();
                resolution.got_address = Some(got_address);
                let plt_address = self.allocate_plt();
                // An ifunc is always resolved at runtime, so we need a relocation for it.
                self.plt_relocations.push(IfuncRelocation {
                    resolver: value.address()?,
                    got_address: got_address.get(),
                    relocation_address: self.next_rela_plt_address,
                });
                if self.symbol_db.args.is_relocatable() {
                    self.next_rela_plt_address += elf::RELA_ENTRY_SIZE;
                }
                // If a symbol refers to an ifunc, then all access needs to go via the PLT.
                resolution.value = ResolutionValue::Address(plt_address.get());
                resolution.plt_address = Some(plt_address);
            }
            TargetResolutionKind::GotTlsDouble => {
                // Allocate two GOT entries, storing a pointer to the first. This double-entry is
                // the structure expected by __tls_get_addr.
                resolution.got_address = Some(self.allocate_got());
                self.allocate_got();
            }
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
    fn activate(&mut self) -> Result {
        self.common.mem_sizes.dynamic += core::mem::size_of::<crate::elf::DynamicEntry>() as u64;
        self.common.mem_sizes.dynstr += self.lib_name.len() as u64 + 1;
        Ok(())
    }

    fn finalise_sizes(&mut self) -> Result {
        Ok(())
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
        resolutions_out: &mut [Option<Resolution>],
        output_sections: &OutputSections,
        symbol_db: &SymbolDb,
    ) -> Result<DynamicLayout<'data>> {
        let dynstr_start_offset =
            memory_offsets.dynstr - section_layouts.get(output_section_id::DYNSTR).mem_offset;

        let mut emitter = self
            .common
            .create_global_address_emitter(memory_offsets, symbol_db);

        let mut next_symbol_index = u32::try_from(
            (memory_offsets.dynsym - section_layouts.get(output_section_id::DYNSYM).mem_offset)
                / crate::elf::SYMTAB_ENTRY_SIZE,
        )
        .context("Too many dynamic symbols")?;

        debug_assert_eq!(resolutions_out.len(), self.common.symbol_states.len());

        for ((_local_symbol, symbol_state), resolution) in self
            .object
            .dynamic_symbols()
            .zip(&self.common.symbol_states)
            .zip(resolutions_out)
        {
            if *symbol_state == TargetResolutionKind::None {
                continue;
            }
            *resolution =
                Some(emitter.create_resolution(
                    *symbol_state,
                    ResolutionValue::Dynamic(next_symbol_index),
                )?);

            next_symbol_index += 1;
        }

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
            start_symbol_id: self.common.start_symbol_id,
            num_symbols: self.common.symbol_states.len(),
        })
    }
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
    for i in 0..symbol_db.num_symbols() {
        let symbol_id = SymbolId::from_usize(i);
        if symbol_db
            .symbol_name(symbol_id)
            .is_ok_and(|sym_name| sym_name.bytes() == name.as_bytes())
        {
            println!("{}", symbol_db.symbol_debug(symbol_id));
        }
    }
}

fn section_debug(object: &crate::elf::File, section_index: object::SectionIndex) -> SectionDebug {
    let name = object
        .section_by_index(section_index)
        .and_then(|section| section.name_bytes())
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

impl ResolutionValue {
    pub(crate) fn address_or_value(&self) -> Result<u64> {
        match self {
            ResolutionValue::Absolute(v) | ResolutionValue::Address(v) => Ok(*v),
            ResolutionValue::Dynamic(..) => bail!("Unexpected dynamic resolution"),
        }
    }

    pub(crate) fn address(&self) -> Result<u64> {
        match self {
            ResolutionValue::Address(v) => Ok(*v),
            ResolutionValue::Absolute(..) => bail!("Unexpected absolute value"),
            ResolutionValue::Dynamic(..) => bail!("Unexpected dynamic resolution"),
        }
    }

    pub(crate) fn is_absolute(&self) -> bool {
        matches!(self, ResolutionValue::Absolute(..))
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
