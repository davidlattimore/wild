//! Traverses the graph of symbol references to figure out what sections from the input files are
//! referenced. Determines which sections need to be linked, sums their sizes decides what goes
//! where in the output file then allocates addresses for each symbol.

use crate::alignment;
use crate::alignment::Alignment;
use crate::args::Args;
use crate::elf;
use crate::elf::File;
use crate::error::Error;
use crate::error::Result;
use crate::input_data::FileId;
use crate::input_data::InputRef;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_id::TemporaryOutputSectionId;
use crate::output_section_id::UnloadedSection;
use crate::output_section_id::NUM_BUILT_IN_SECTIONS;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::program_segments;
use crate::program_segments::ProgramSegmentId;
use crate::resolution;
use crate::resolution::LocalSymbolResolution;
use crate::resolution::SectionSlot;
use crate::symbol::SymbolName;
use crate::symbol_db;
use crate::symbol_db::GlobalSymbolId;
use crate::symbol_db::InternalSymDefInfo;
use crate::symbol_db::SymbolDb;
use crate::timing::Timing;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use crossbeam_queue::ArrayQueue;
use fxhash::FxHashMap;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use rayon::prelude::IndexedParallelIterator;
use rayon::prelude::IntoParallelIterator;
use rayon::prelude::IntoParallelRefMutIterator;
use rayon::prelude::ParallelIterator;
use std::mem::size_of;
use std::num::NonZeroU64;
use std::sync::atomic;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

pub(crate) fn compute<'data>(
    symbol_db: &'data SymbolDb<'data>,
    file_states: Vec<resolution::ResolvedFile<'data>>,
    output_sections: OutputSections<'data>,
    timing: &mut Timing,
) -> Result<Layout<'data>> {
    let tls_mode = determine_tls_mode(symbol_db);
    if let Some(sym_info) = symbol_db.args.sym_info.as_deref() {
        print_symbol_info(symbol_db, &file_states, sym_info);
    }
    let mut layout_states =
        find_required_sections(file_states, symbol_db, &output_sections, tls_mode)?;
    timing.complete("Find required sections");
    layout_states
        .par_iter_mut()
        .try_for_each(|state| state.finalise_sizes(symbol_db, &output_sections))?;
    timing.complete("Finalise sizes");
    let section_part_sizes = compute_total_section_part_sizes(&layout_states, &output_sections);
    timing.complete("Sum section sizes");
    let section_part_layouts = layout_section_parts(&section_part_sizes, &output_sections);
    let section_layouts = layout_sections(&section_part_layouts);
    let segment_layouts = compute_segment_layout(&section_layouts, &output_sections);
    let mem_offsets: OutputSectionPartMap<u64> =
        starting_memory_offsets(&section_part_layouts, &output_sections);
    timing.complete("Section/segment sizing");
    let starting_mem_offsets_by_file = compute_start_offsets_by_file(&layout_states, mem_offsets);
    timing.complete("Allocate sizes to files");
    let symbols_and_layouts = compute_symbols_and_layouts(
        layout_states,
        starting_mem_offsets_by_file,
        &section_layouts,
        symbol_db,
    )?;
    timing.complete("Assign symbol addresses");

    // Merge global symbol addresses emitted by all files into a single table.
    let mut symbol_addresses = vec![None; symbol_db.num_symbols()];
    let mut file_layouts = Vec::with_capacity(symbols_and_layouts.len());
    for (symbols, file_layout) in symbols_and_layouts {
        file_layouts.push(file_layout);
        for global in symbols {
            symbol_addresses[global.symbol_id.as_usize()] = Some(global.resolution);
        }
    }
    timing.complete("Merge symbol addresses");
    Ok(Layout {
        symbol_db,
        symbol_addresses: SymbolResolutions {
            resolutions: symbol_addresses,
        },
        segment_layouts,
        section_part_layouts,
        section_layouts,
        file_layouts,
        output_sections,
        tls_mode,
    })
}

/// Information about what goes where. Also includes relocation data, since that's computed at the
/// same time.
pub(crate) struct Layout<'data> {
    pub(crate) symbol_db: &'data SymbolDb<'data>,
    pub(crate) symbol_addresses: SymbolResolutions,
    pub(crate) section_part_layouts: OutputSectionPartMap<OutputRecordLayout>,
    pub(crate) section_layouts: OutputSectionMap<OutputRecordLayout>,
    pub(crate) file_layouts: Vec<FileLayout<'data>>,
    pub(crate) segment_layouts: Vec<SegmentLayout>,
    pub(crate) output_sections: OutputSections<'data>,
    pub(crate) tls_mode: TlsMode,
}

#[derive(Default, Clone)]
pub(crate) struct SegmentLayout {
    pub(crate) sizes: OutputRecordLayout,
}

pub(crate) struct SymbolResolutions {
    resolutions: Vec<Option<SymbolResolution>>,
}

pub(crate) enum FileLayout<'data> {
    Internal(InternalLayout),
    Object(ObjectLayout<'data>),
    Dynamic(DynamicLayout<'data>),
}

#[derive(Debug, Clone)]
pub(crate) enum SymbolResolution {
    Resolved(Resolution),
    Dynamic,
}

/// Address information for a symbol or section.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Resolution {
    // TODO: Experiment with putting these in separate vectors.
    pub(crate) address: u64,
    pub(crate) got_address: Option<NonZeroU64>,
    pub(crate) plt_address: Option<NonZeroU64>,
    pub(crate) kind: TargetResolutionKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsMode {
    /// Convert TLS access to local-exec mode.
    LocalExec,

    /// Preserve TLS access mode of the input.
    Preserve,
}

enum FileLayoutState<'data> {
    Internal(InternalLayoutState),
    Object(ObjectLayoutState<'data>),
    #[allow(dead_code)]
    Dynamic(DynamicLayoutState<'data>),
    NotLoaded,
}

/// Data that doesn't come from any input files, but needs to be written by the linker.
struct InternalLayoutState {
    common: CommonLayoutState,
    defined: Vec<GlobalSymbolId>,
    symbol_definitions: Vec<InternalSymDefInfo>,
    entry_symbol_id: Option<GlobalSymbolId>,
    needs_tlsld_got_entry: bool,
}

pub(crate) struct ObjectLayout<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) file_id: FileId,
    pub(crate) object: Box<File<'data>>,
    pub(crate) mem_sizes: OutputSectionPartMap<u64>,
    pub(crate) sections: Vec<SectionSlot<'data>>,
    pub(crate) section_resolutions: Vec<Option<Resolution>>,
    pub(crate) strings_offset_start: u32,
    pub(crate) plt_relocations: Vec<PltRelocation>,
    pub(crate) loaded_symbols: Vec<GlobalSymbolId>,
    pub(crate) local_symbol_resolutions: Vec<LocalSymbolResolution>,
}

pub(crate) struct InternalLayout {
    pub(crate) mem_sizes: OutputSectionPartMap<u64>,
    pub(crate) undefined_symbol_resolution: Resolution,
    pub(crate) defined: Vec<GlobalSymbolId>,
    pub(crate) strings_offset_start: u32,
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo>,
    pub(crate) entry_symbol_id: GlobalSymbolId,
    pub(crate) tlsld_got_entry: Option<NonZeroU64>,
}

pub(crate) struct DynamicLayout<'data> {
    #[allow(dead_code)]
    input: InputRef<'data>,
}

#[derive(Debug)]
pub(crate) struct PltRelocation {
    pub(crate) resolver: u64,
    pub(crate) got_address: u64,
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
        let symbol = resources.symbol_db.symbol(symbol_id);
        debug_assert_eq!(symbol.file_id, self.file_id());
        let local_index = symbol.local_index_without_checking_file_id().0;
        let mut common = self.common_mut();
        if local_index >= common.symbol_states.len() {
            bail!(
                "Internal error: Requested symbol `{}` from `{self}`, \
                 but local index {local_index} >= {}",
                resources.symbol_db.symbol_name(symbol_id),
                common.symbol_states.len()
            );
        }
        if common.symbol_states[local_index] == TargetResolutionKind::None {
            if self.load_symbol(symbol_id, local_index, resources, queue)? == SymbolKind::IFunc {
                common = self.common_mut();
                common.mem_sizes.got += elf::GOT_ENTRY_SIZE;
                common.mem_sizes.plt += elf::PLT_ENTRY_SIZE;
                common.mem_sizes.rela_plt += elf::RELA_ENTRY_SIZE;
                common.symbol_states[local_index] = TargetResolutionKind::IFunc;
            } else {
                common = self.common_mut();
                common.symbol_states[local_index] = TargetResolutionKind::Address;
            }
        }
        if symbol_request.flags.needs_got()
            && common.symbol_states[local_index] < TargetResolutionKind::Got
        {
            common.symbol_states[local_index] = TargetResolutionKind::Got;
            common.mem_sizes.got += elf::GOT_ENTRY_SIZE;
        }
        if matches!(symbol_request.flags, PltGotFlags::TlsGot) {
            match &common.symbol_states[local_index] {
                TargetResolutionKind::Address => {
                    common.symbol_states[local_index] = TargetResolutionKind::TlsGot;
                    common.mem_sizes.got += elf::GOT_ENTRY_SIZE * 2;
                }
                TargetResolutionKind::TlsGot => {}
                other => {
                    bail!("Invalid state transition {other:?} -> TlsGot");
                }
            }
        }
        if symbol_request.flags.needs_plt()
            && common.symbol_states[local_index] < TargetResolutionKind::Plt
        {
            if !symbol_request.flags.needs_got() {
                bail!("Invalid request: needs_plt was set, but needs_got wasn't");
            }
            common.symbol_states[local_index] = TargetResolutionKind::Plt;
            common.mem_sizes.plt += elf::PLT_ENTRY_SIZE;
        }
        Ok(())
    }

    fn common_mut(&mut self) -> &mut CommonLayoutState;

    fn file_id(&self) -> FileId;

    fn load_symbol<'scope>(
        &mut self,
        symbol_id: GlobalSymbolId,
        local_index: usize,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result<SymbolKind>;

    /// Returns whether `local_index` is a weak definition.
    fn is_weak(&self, local_index: usize) -> bool;
}

impl<'data> SymbolRequestHandler<'data> for ObjectLayoutState<'data> {
    fn common_mut(&mut self) -> &mut CommonLayoutState {
        &mut self.common
    }

    fn load_symbol<'scope>(
        &mut self,
        symbol_id: GlobalSymbolId,
        local_index: usize,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result<SymbolKind> {
        self.loaded_symbols.push(symbol_id);
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
        if let object::SymbolSection::Section(section_id) = local_symbol.section() {
            self.sections_required.push(SectionRequest::new(section_id));
            self.load_sections(resources, queue)?;
        } else if let Some(common) = CommonSymbol::new(&local_symbol)? {
            *self
                .common
                .mem_sizes
                .regular_mut(output_section_id::BSS, common.alignment) += common.size;
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
        self.common.file_id
    }
}

impl<'data> SymbolRequestHandler<'data> for InternalLayoutState {
    fn common_mut(&mut self) -> &mut CommonLayoutState {
        &mut self.common
    }

    fn file_id(&self) -> FileId {
        self.common.file_id
    }

    fn load_symbol<'scope>(
        &mut self,
        _symbol_id: GlobalSymbolId,
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
}

struct CommonLayoutState {
    file_id: FileId,
    mem_sizes: OutputSectionPartMap<u64>,
    /// States of each global symbol that we defined. Indexed as by Symbol::local_index.
    symbol_states: Vec<TargetResolutionKind>,
}

impl CommonLayoutState {
    fn new(file_id: FileId, num_symbols: usize, output_sections: &OutputSections) -> Self {
        Self {
            file_id,
            mem_sizes: OutputSectionPartMap::with_size(output_sections.len()),
            symbol_states: vec![TargetResolutionKind::None; num_symbols],
        }
    }

    fn finalise_layout(
        &self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
    ) -> u32 {
        // strtab
        let offset = &mut memory_offsets.symtab_strings;
        let strings_offset_start = (*offset
            - section_layouts
                .built_in(output_section_id::STRTAB)
                .mem_offset)
            .try_into()
            .expect("Symbol string table overflowed 32 bits");
        *offset += self.mem_sizes.symtab_strings;

        // symtab
        memory_offsets.symtab_locals += self.mem_sizes.symtab_locals;
        memory_offsets.symtab_globals += self.mem_sizes.symtab_globals;

        strings_offset_start
    }

    fn create_global_address_emitter<'state>(
        &'state self,
        memory_offsets: &OutputSectionPartMap<u64>,
        symbol_db: &'state SymbolDb,
    ) -> GlobalAddressEmitter {
        GlobalAddressEmitter {
            next_got_address: memory_offsets.got,
            next_plt_address: memory_offsets.plt,
            symbol_states: &self.symbol_states,
            symbol_db,
            file_id: self.file_id,
            plt_relocations: Default::default(),
        }
    }
}

struct ObjectLayoutState<'data> {
    input: InputRef<'data>,
    object: Box<File<'data>>,
    common: CommonLayoutState,

    /// Info about each of our sections. Empty until this object has been activated. Indexed the
    /// same as the sections in the input object.
    sections: Vec<SectionSlot<'data>>,

    /// Indexed as for object.symbols()
    local_symbol_states: Vec<LocalSymbolState>,

    /// Indexed as for object.symbols()
    plt_got_flags: Vec<PltGotFlags>,

    /// A queue of sections that we need to load.
    sections_required: Vec<SectionRequest>,

    loaded_symbols: Vec<GlobalSymbolId>,
    local_symbol_resolutions: Vec<resolution::LocalSymbolResolution>,
}

#[derive(Default)]
struct LocalWorkQueue {
    /// The index of the worker that owns this queue.
    index: usize,

    /// Work that needs to be processed by the worker that owns this queue.
    local_work: Vec<WorkItem>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum LocalSymbolState {
    Unloaded,
    Loaded,
}

/// What kind of resolution we want for a symbol or section.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum TargetResolutionKind {
    /// No resolution.
    None,

    /// Just an address.
    Address,

    /// An address in the global offset table.
    Got,

    /// A PLT entry and a GOT entry.
    Plt,

    /// A PLT entry and a GOT entry. The GOT entry will have a relocation that will be resolved at
    /// program startup by calling the ifunc resolver function.
    IFunc,

    /// A double-entry in the global offset table. Used to store the module number and offset for a
    /// TLS variable.
    TlsGot,
}

struct DynamicLayoutState<'data> {
    // TODO: Use this or remove it.
    #[allow(dead_code)]
    object: Box<File<'data>>,
    input: InputRef<'data>,
    referenced_symbol_ids: Vec<GlobalSymbolId>,
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
    pub(crate) resolution_kind: PltGotFlags,
    packed: bool,
}

struct FileWorker<'data> {
    queue: LocalWorkQueue,
    state: Box<FileLayoutState<'data>>,
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

#[derive(Default, Clone, Debug)]
pub(crate) struct SegmentOffsets(pub(crate) [u64; NUM_BUILT_IN_SECTIONS]);

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
    tls_mode: TlsMode,
}

#[derive(Copy, Clone, Debug)]
enum WorkItem {
    LoadGlobalSymbol(SymbolRequest),
    // TODO: Consider getting rid of `Activate` and just calling an activate method on each file.
    /// Load any non-GC sections. Loading a symbol causes this to happen, however for non-archived
    /// object files, we need to activate them even if there aren't any external references to their
    /// symbols.
    Activate,
}

#[derive(Copy, Clone, Debug)]
struct SymbolRequest {
    symbol_id: GlobalSymbolId,
    flags: PltGotFlags,
}

struct GlobalSymbolAddress {
    symbol_id: GlobalSymbolId,
    resolution: SymbolResolution,
}

impl<'data> Layout<'data> {
    pub(crate) fn internal(&self) -> &InternalLayout {
        let Some(FileLayout::Internal(i)) = self.file_layouts.first() else {
            panic!("Internal layout not found at expected offset");
        };
        i
    }

    pub(crate) fn config(&self) -> &'data Args {
        self.symbol_db.args
    }

    pub(crate) fn global_symbol_resolution(
        &self,
        symbol_id: GlobalSymbolId,
    ) -> Option<&SymbolResolution> {
        self.symbol_addresses.resolutions[symbol_id.as_usize()].as_ref()
    }

    pub(crate) fn entry_symbol_address(&self) -> Result<u64> {
        let symbol_id = self.internal().entry_symbol_id;
        match self.global_symbol_resolution(symbol_id) {
            Some(SymbolResolution::Resolved(resolution)) => Ok(resolution.address),
            Some(SymbolResolution::Dynamic) => {
                let symbol_name = self.symbol_db.symbol_name(symbol_id);
                bail!("{symbol_name} can't be from a dynamic library",)
            }
            None => {
                let symbol_name = self.symbol_db.symbol_name(symbol_id);
                bail!("{symbol_name} symbol was present, but didn't get loaded")
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

fn compute_symbols_and_layouts<'data>(
    layout_states: Vec<FileLayoutState<'data>>,
    starting_mem_offsets_by_file: Vec<Option<OutputSectionPartMap<u64>>>,
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
    symbol_db: &SymbolDb<'_>,
) -> Result<Vec<(Vec<GlobalSymbolAddress>, FileLayout<'data>)>> {
    layout_states
        .into_par_iter()
        .zip(starting_mem_offsets_by_file)
        .filter_map(|(state, mut memory_offsets)| {
            state
                .finalise_layout(memory_offsets.as_mut(), section_layouts, symbol_db)
                .transpose()
        })
        .collect()
}

fn compute_segment_layout(
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
    output_sections: &OutputSections,
) -> Vec<SegmentLayout> {
    struct Record {
        segment_id: ProgramSegmentId,
        file_start: usize,
        file_end: usize,
        mem_start: u64,
        mem_end: u64,
        alignment: Alignment,
    }

    use output_section_id::OrderEvent;
    let mut complete = Vec::with_capacity(crate::program_segments::NUM_SEGMENTS);
    let mut active_records = FxHashMap::default();
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
    complete
        .into_iter()
        .map(|r| SegmentLayout {
            sizes: OutputRecordLayout {
                file_size: r.file_end - r.file_start,
                mem_size: r.mem_end - r.mem_start,
                alignment: r.alignment,
                file_offset: r.file_start,
                mem_offset: r.mem_start,
            },
        })
        .collect()
}

fn compute_total_section_part_sizes(
    layout_states: &Vec<FileLayoutState>,
    output_sections: &OutputSections,
) -> OutputSectionPartMap<u64> {
    let mut total_sizes: OutputSectionPartMap<u64> =
        OutputSectionPartMap::with_size(output_sections.len());
    for file_state in layout_states {
        if let Some(sizes) = file_state.mem_sizes() {
            total_sizes.merge(sizes);
        }
    }
    total_sizes
}

/// Returns the starting memory address for each alignment within each segment.
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

fn find_required_sections<'data>(
    file_states: Vec<resolution::ResolvedFile<'data>>,
    symbol_db: &SymbolDb<'data>,
    output_sections: &OutputSections<'data>,
    tls_mode: TlsMode,
) -> Result<Vec<FileLayoutState<'data>>> {
    let waiting_workers = ArrayQueue::new(file_states.len());
    let worker_slots = create_worker_slots(file_states, output_sections, &waiting_workers);

    let num_threads = symbol_db.args.num_threads.get();

    let idle_threads = (num_threads > 1).then(|| ArrayQueue::new(num_threads - 1));
    let resources = &GraphResources {
        symbol_db,
        worker_slots,
        errors: Mutex::new(Vec::new()),
        waiting_workers,
        // NB, the -1 is because we never want all our threads to be idle. Once the last thread is
        // about to go idle, we're done and need to wake up and terminate all the the threads.
        idle_threads,
        done: AtomicBool::new(false),
        output_sections,
        tls_mode,
    };

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
    waiting_workers: &ArrayQueue<FileWorker<'data>>,
) -> Vec<Mutex<WorkerSlot<'data>>> {
    file_states
        .into_iter()
        .enumerate()
        .map(|(index, f)| {
            let mut initial_work = Vec::new();
            let worker = FileWorker {
                queue: LocalWorkQueue::new(index),
                state: Box::new(f.create_layout_state(&mut initial_work, output_sections)),
            };
            let slot = if initial_work.is_empty() {
                WorkerSlot {
                    work: initial_work,
                    worker: Some(worker),
                }
            } else {
                let _ = waiting_workers.push(worker);
                WorkerSlot {
                    work: initial_work,
                    worker: None,
                }
            };
            Mutex::new(slot)
        })
        .collect()
}

fn unwrap_worker_states<'data>(
    worker_slots: &[Mutex<WorkerSlot<'data>>],
) -> Result<Vec<FileLayoutState<'data>>> {
    Ok(worker_slots
        .iter()
        .filter_map(|w| w.lock().unwrap().worker.take())
        .map(|w| *w.state)
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

    fn send_symbol_request(
        &mut self,
        symbol_id: GlobalSymbolId,
        plt_got_flags: PltGotFlags,
        resources: &GraphResources,
    ) {
        let symbol = resources.symbol_db.symbol(symbol_id);
        let symbol_request = SymbolRequest {
            symbol_id,
            flags: plt_got_flags,
        };
        self.send_work(
            resources,
            symbol.file_id,
            WorkItem::LoadGlobalSymbol(symbol_request),
        );
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
            FileLayoutState::Object(s) => s.finalise_sizes(symbol_db, output_sections)?,
            FileLayoutState::Internal(s) => s.finalise_sizes(symbol_db, output_sections)?,
            _ => (),
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
                        "Failed to load symbol {} from {self}",
                        resources.symbol_db.symbol_name(symbol_request.symbol_id),
                    )
                }),
            WorkItem::Activate => match self {
                Self::Object(s) => s.activate(resources, queue),
                Self::Internal(s) => s.activate(resources),
                _ => unreachable!(),
            },
        }
    }

    fn handle_symbol_request<'scope>(
        &mut self,
        symbol_request: SymbolRequest,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        match self {
            FileLayoutState::Internal(state) => {
                state.handle_symbol_request(symbol_request, resources, queue)?;
            }
            FileLayoutState::Object(state) => {
                state.handle_symbol_request(symbol_request, resources, queue)?;
            }
            FileLayoutState::Dynamic(state) => state.load_symbol(symbol_request, resources)?,
            FileLayoutState::NotLoaded => {}
        }
        Ok(())
    }

    pub(crate) fn mem_sizes(&self) -> Option<&OutputSectionPartMap<u64>> {
        match self {
            Self::Internal(s) => Some(&s.common.mem_sizes),
            Self::Object(s) => Some(&s.common.mem_sizes),
            Self::Dynamic(_) => None,
            Self::NotLoaded => None,
        }
    }

    fn finalise_layout(
        self,
        memory_offsets: Option<&mut OutputSectionPartMap<u64>>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
        symbol_db: &SymbolDb,
    ) -> Result<Option<(Vec<GlobalSymbolAddress>, FileLayout<'data>)>> {
        let mut addresses_out = Vec::new();
        let file_layout = match self {
            Self::Internal(s) => FileLayout::Internal(s.finalise_layout(
                memory_offsets.unwrap(),
                section_layouts,
                &mut addresses_out,
                symbol_db,
            )?),
            Self::Object(s) => FileLayout::Object(s.finalise_layout(
                memory_offsets.unwrap(),
                &mut addresses_out,
                section_layouts,
                symbol_db,
            )?),
            Self::Dynamic(s) => FileLayout::Dynamic(s.finalise_layout(&mut addresses_out)),
            Self::NotLoaded => {
                return Ok(None);
            }
        };
        Ok(Some((addresses_out, file_layout)))
    }
}

impl<'data> FileLayout<'data> {
    pub(crate) fn mem_sizes(&self) -> Option<&OutputSectionPartMap<u64>> {
        match self {
            Self::Internal(s) => Some(&s.mem_sizes),
            Self::Object(s) => Some(&s.mem_sizes),
            Self::Dynamic(_) => None,
        }
    }

    pub(crate) fn file_sizes(
        &self,
        output_sections: &OutputSections,
    ) -> Option<OutputSectionPartMap<usize>> {
        self.mem_sizes().map(|sizes| {
            sizes.map(output_sections, |output_section_id, size| {
                if output_sections.has_data_in_file(output_section_id) {
                    *size as usize
                } else {
                    0
                }
            })
        })
    }
}

impl std::fmt::Display for InternalLayoutState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt("<internal>", f)
    }
}

impl<'data> std::fmt::Display for FileLayoutState<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal(_) => std::fmt::Display::fmt("<internal>", f),
            Self::Object(s) => std::fmt::Display::fmt(s, f),
            Self::Dynamic(_) => todo!(),
            Self::NotLoaded => std::fmt::Display::fmt("<not-loaded>", f),
        }
    }
}

impl<'data> std::fmt::Display for FileLayout<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal(_) => std::fmt::Display::fmt("<internal>", f),
            Self::Object(s) => std::fmt::Display::fmt(s, f),
            Self::Dynamic(_) => todo!(),
        }
    }
}

impl<'data> std::fmt::Display for ObjectLayoutState<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl<'data> std::fmt::Display for ObjectLayout<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

struct SectionRequest {
    id: object::SectionIndex,
    flags: PltGotFlags,
}

impl SectionRequest {
    fn new(id: object::SectionIndex) -> Self {
        Self {
            id,
            flags: Default::default(),
        }
    }

    fn allocate_required_entries(
        &self,
        section: &mut Section,
        mem_sizes: &mut OutputSectionPartMap<u64>,
    ) -> Result<()> {
        if section.resolution_kind == self.flags {
            return Ok(());
        }
        match (section.resolution_kind, self.flags) {
            (PltGotFlags::Neither, PltGotFlags::Got) => {
                mem_sizes.got += elf::GOT_ENTRY_SIZE;
            }
            (PltGotFlags::Neither, PltGotFlags::Plt) => {
                mem_sizes.got += elf::GOT_ENTRY_SIZE;
                mem_sizes.plt += elf::PLT_ENTRY_SIZE;
            }
            (PltGotFlags::Got, PltGotFlags::Plt) => {
                mem_sizes.plt += elf::PLT_ENTRY_SIZE;
            }
            (PltGotFlags::Neither, PltGotFlags::TlsGot) => {
                mem_sizes.got += elf::GOT_ENTRY_SIZE * 2;
            }
            (_, PltGotFlags::Neither) | (PltGotFlags::Plt, PltGotFlags::Got) => {
                return Ok(());
            }
            (a, b) => bail!("Unexpected state transition {a:?} {b:?}"),
        }
        section.resolution_kind = self.flags;
        Ok(())
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
        for (_, rel) in object_section.relocations() {
            let mut section_to_load = None;
            let mut symbol_to_load = None;
            let plt_got_flags = PltGotFlags::from_rel(&rel, resources.tls_mode);
            match rel.target() {
                object::RelocationTarget::Symbol(local_sym_index) => {
                    match &worker.local_symbol_states[local_sym_index.0] {
                        LocalSymbolState::Unloaded => {
                            worker.local_symbol_states[local_sym_index.0] =
                                LocalSymbolState::Loaded;
                            worker.plt_got_flags[local_sym_index.0] = plt_got_flags;
                        }
                        _ => {
                            if worker.plt_got_flags[local_sym_index.0] >= plt_got_flags {
                                // We've already processed a relocation to this symbol and the
                                // PLT/GOT flags haven't changed (or are weaker), nothing more to do
                                // for this relocation.
                                continue;
                            } else {
                                // We've processed this symbol before, but the PLT/GOT requirements
                                // just got stronger, so we'll still need to send a symbol request.
                                worker.plt_got_flags[local_sym_index.0] = plt_got_flags;
                            }
                        }
                    }
                    let symbol_res = worker.local_symbol_resolutions[local_sym_index.0];
                    match symbol_res {
                        LocalSymbolResolution::Global(symbol_id) => {
                            symbol_to_load = Some(symbol_id);
                        }
                        LocalSymbolResolution::WeakRefToGlobal(symbol_id) => {
                            symbol_to_load = Some(symbol_id);
                        }
                        LocalSymbolResolution::LocalSection(local_section_index) => {
                            section_to_load = Some(local_section_index);
                        }
                        _ => {}
                    }
                }
                object::RelocationTarget::Section(local_section_index) => {
                    section_to_load = Some(local_section_index);
                }
                _ => {}
            };

            if let Some(local_section_index) = section_to_load {
                // TODO: See if it's worthwhile checking if we've already loaded the section.
                worker.sections_required.push(SectionRequest {
                    id: local_section_index,
                    flags: plt_got_flags,
                });
            }
            if let Some(symbol_id) = symbol_to_load {
                queue.send_symbol_request(symbol_id, plt_got_flags, resources);
            }
        }
        let section = Section {
            index: section_id,
            output_section_id: None,
            alignment,
            size,
            data: section_data,
            resolution_kind: PltGotFlags::Neither,
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

// TODO: Can we unify this with TargetResolutionKind?
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum PltGotFlags {
    /// No PLT or GOT is required.
    #[default]
    Neither,

    /// A single GOT entry is required.
    Got,

    /// A PLT and a GOT entry are required.
    Plt,

    /// A double-GOT entry is required for a TLS variable. The first entry contains the module index
    /// and the second the offset within the module.
    TlsGot,
}

impl PltGotFlags {
    fn from_rel(rel: &object::Relocation, tls_mode: TlsMode) -> PltGotFlags {
        // TODO: This could probably be more efficiently implemented as lookup table indexed by the
        // raw relocation type. We can then select which lookup table to use based on tls_mode.
        match rel.kind() {
            object::RelocationKind::PltRelative => PltGotFlags::Plt,
            object::RelocationKind::Got
            | object::RelocationKind::GotRelative
            | object::RelocationKind::GotBaseRelative
            | object::RelocationKind::GotBaseOffset => PltGotFlags::Got,
            object::RelocationKind::Unknown => match rel.flags() {
                object::RelocationFlags::Elf { r_type } => match r_type {
                    22 | 41 | 42 => PltGotFlags::Got,
                    19 | 20 => match tls_mode {
                        TlsMode::LocalExec => PltGotFlags::Neither,
                        TlsMode::Preserve => PltGotFlags::TlsGot,
                    },
                    _ => PltGotFlags::Neither,
                },
                _ => unimplemented!(),
            },
            _ => PltGotFlags::Neither,
        }
    }

    fn needs_got(&self) -> bool {
        matches!(self, Self::Got | Self::Plt)
    }

    fn needs_plt(&self) -> bool {
        matches!(self, Self::Plt)
    }
}

impl InternalLayoutState {
    fn new(input_state: resolution::ResolvedInternal, output_sections: &OutputSections) -> Self {
        let mut layout = Self {
            common: CommonLayoutState::new(
                input_state.file_id,
                input_state.symbol_definitions.len(),
                output_sections,
            ),
            defined: input_state.defined,
            symbol_definitions: input_state.symbol_definitions,
            entry_symbol_id: None,
            needs_tlsld_got_entry: false,
        };

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
            .symbol_ids
            .get(&SymbolName::new(b"_start"))
            .context("Missing _start symbol")?;
        self.entry_symbol_id = Some(symbol_id);
        let file_id = resources.symbol_db.symbol(symbol_id).file_id;
        resources.send_work(
            file_id,
            WorkItem::LoadGlobalSymbol(SymbolRequest {
                symbol_id,
                flags: Default::default(),
            }),
        );
        if resources.tls_mode == TlsMode::Preserve {
            // Allocate space for a TLS module number and offset for use with TLSLD relocations.
            self.common.mem_sizes.got += elf::GOT_ENTRY_SIZE * 2;
            self.needs_tlsld_got_entry = true;
        }
        Ok(())
    }

    fn finalise_sizes(&mut self, symbol_db: &SymbolDb, output_sections: &OutputSections) -> Result {
        self.common.mem_sizes.file_headers = u64::from(elf::FILE_HEADER_SIZE)
            + InternalLayout::program_headers_size()
            + InternalLayout::section_headers_size(output_sections);

        self.common.mem_sizes.shstrtab += output_sections
            .section_infos
            .iter()
            .map(|s| s.details.name.len() as u64 + 1)
            .sum::<u64>();

        if !symbol_db.args.strip_all {
            self.allocate_symbol_table_sizes(symbol_db)?;
        }
        Ok(())
    }

    fn allocate_symbol_table_sizes(&mut self, symbol_db: &SymbolDb<'_>) -> Result {
        // Allocate space in the symbol table for the symbols that we define.
        for &symbol_id in &self.defined {
            let symbol = symbol_db.symbol(symbol_id);
            let local_index = symbol.local_index_for_file(self.file_id())?;
            let def_info = &self.symbol_definitions[local_index.0];
            let sym_state = &self.common.symbol_states[local_index.0];
            // Don't allocate space for symbols that are in our headers section, since it doesn't
            // have an entry.
            if def_info.section_id() == output_section_id::HEADERS {
                continue;
            }

            // We don't put internal symbols in the symbol table if they aren't referenced.
            if matches!(sym_state, TargetResolutionKind::None) {
                continue;
            }

            self.common.mem_sizes.symtab_globals += size_of::<elf::SymtabEntry>() as u64;
            self.common.mem_sizes.symtab_strings +=
                symbol_db.symbol_name(symbol_id).len() as u64 + 1;
        }
        Ok(())
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
        global_addresses_out: &mut Vec<GlobalSymbolAddress>,
        symbol_db: &SymbolDb,
    ) -> Result<InternalLayout> {
        let header_layout = section_layouts.built_in(output_section_id::HEADERS);
        assert_eq!(header_layout.file_offset, 0);
        assert_eq!(header_layout.mem_offset, elf::START_MEM_ADDRESS);

        // We need a GOT address to use for any relocations that point to undefined weak symbols.
        let undefined_symbol_resolution = Resolution {
            address: 0,
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

        // Define symbols that are optionally put at the start/end of some sections.
        let mut emitter = self
            .common
            .create_global_address_emitter(memory_offsets, symbol_db);
        for symbol_id in &self.defined {
            let symbol = symbol_db.symbol(*symbol_id);
            let local_index = symbol.local_index_for_file(self.file_id())?;
            let def_info = &self.symbol_definitions[local_index.0];
            let sym_state = &self.common.symbol_states[local_index.0];

            // We don't put internal symbols in the symbol table if they aren't referenced.
            if matches!(sym_state, TargetResolutionKind::None) {
                continue;
            }

            let address = match def_info {
                InternalSymDefInfo::SectionStart(section_id) => {
                    section_layouts.built_in(*section_id).mem_offset
                }
                InternalSymDefInfo::SectionEnd(section_id) => {
                    let sec = &section_layouts.built_in(*section_id);
                    sec.mem_offset + sec.mem_size
                }
            };
            if let Some(global) = emitter.build_symbol(*symbol_id, address)? {
                global_addresses_out.push(global);
            }
        }

        let strings_offset_start = self.common.finalise_layout(memory_offsets, section_layouts);
        Ok(InternalLayout {
            mem_sizes: self.common.mem_sizes,
            defined: self.defined,
            symbol_definitions: self.symbol_definitions,
            undefined_symbol_resolution,
            strings_offset_start,
            entry_symbol_id: self.entry_symbol_id.unwrap(),
            tlsld_got_entry,
        })
    }
}

impl InternalLayout {
    pub(crate) fn program_headers_size() -> u64 {
        u64::from(elf::PROGRAM_HEADER_SIZE) * program_segments::NUM_SEGMENTS as u64
    }

    pub(crate) fn section_headers_size(output_sections: &OutputSections) -> u64 {
        u64::from(elf::SECTION_HEADER_SIZE) * output_sections.len() as u64
    }
}

impl<'data> ObjectLayoutState<'data> {
    /// Construct a new inactive instance, which means we don't yet load non-GC sections and only
    /// load them later if a symbol from this object is referenced.
    fn new(
        input_state: resolution::ResolvedObject<'data>,
        output_sections: &OutputSections,
    ) -> ObjectLayoutState<'data> {
        let num_symbols = input_state.local_symbol_resolutions.len();
        ObjectLayoutState {
            input: input_state.input,
            object: input_state.object,
            common: CommonLayoutState::new(
                input_state.file_id,
                input_state.local_symbol_resolutions.len(),
                output_sections,
            ),
            sections: input_state.sections,
            loaded_symbols: Default::default(),
            local_symbol_states: vec![LocalSymbolState::Unloaded; num_symbols],
            plt_got_flags: vec![PltGotFlags::Neither; num_symbols],
            sections_required: Default::default(),
            local_symbol_resolutions: input_state.local_symbol_resolutions,
        }
    }

    fn activate<'scope>(
        &mut self,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        for (i, section) in self.sections.iter().enumerate() {
            if let SectionSlot::Unloaded(unloaded_section) = section {
                let retain = unloaded_section.details.retain;
                if retain {
                    self.sections_required
                        .push(SectionRequest::new(object::SectionIndex(i)));
                }
            }
        }
        self.load_sections(resources, queue)
    }

    /// Loads sections in `sections_required` (which may be empty) and if we haven't already been
    /// activated (self.sections is empty) then activates (loads required sections).
    fn load_sections<'scope>(
        &mut self,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        while let Some(section_request) = self.sections_required.pop() {
            let section_id = section_request.id;
            match &self.sections[section_id.0] {
                SectionSlot::Unloaded(unloaded) => {
                    let unloaded = *unloaded;
                    let mut section =
                        Section::create(self, queue, &unloaded, section_id, resources)?;
                    let sec_id = match unloaded.output_section_id {
                        TemporaryOutputSectionId::BuiltIn(sec_id) => sec_id,
                        TemporaryOutputSectionId::Custom(custom_section_id) => resources
                            .output_sections
                            .custom_name_to_id(custom_section_id.name)
                            .context("Internal error: Didn't allocate ID for a custom section")?,
                    };
                    let allocation = self.common.mem_sizes.regular_mut(sec_id, section.alignment);
                    *allocation += section.capacity();
                    section.output_section_id = Some(sec_id);
                    self.sections[section_id.0] = SectionSlot::Loaded(section);
                }
                SectionSlot::Discard => {
                    let object_section = self.object.section_by_index(section_id)?;
                    bail!(
                        "{self}: Don't know what segment to put `{}` in, but it's referenced",
                        String::from_utf8_lossy(object_section.name_bytes()?),
                    );
                }
                SectionSlot::Loaded(_) => {}
            }
            let SectionSlot::Loaded(section) = &mut self.sections[section_id.0] else {
                unreachable!();
            };
            section_request.allocate_required_entries(section, &mut self.common.mem_sizes)?;
        }
        Ok(())
    }

    fn finalise_sizes(&mut self, symbol_db: &SymbolDb, output_sections: &OutputSections) -> Result {
        self.common.mem_sizes.resize(output_sections.len());
        if symbol_db.args.strip_all {
            return Ok(());
        }
        let mut num_locals = 0;
        let mut num_globals = 0;
        let mut strings_size = 0;
        for sym in self.object.symbols() {
            if let object::SymbolSection::Section(section_index) = sym.section() {
                if matches!(self.sections[section_index.0], SectionSlot::Loaded(_)) {
                    if sym.is_local() {
                        num_locals += 1;
                    } else {
                        num_globals += 1;
                    }
                    strings_size += sym.name_bytes()?.len() + 1;
                }
            } else if sym.is_common() {
                if let Some(symbol_id) =
                    self.local_symbol_resolutions[sym.index().0].global_symbol_id()
                {
                    let symbol = symbol_db.symbol(symbol_id);
                    if symbol.file_id == self.common.file_id {
                        num_globals += 1;
                        strings_size += sym.name_bytes()?.len() + 1;
                    }
                }
            }
        }
        let entry_size = size_of::<elf::SymtabEntry>() as u64;
        self.common.mem_sizes.symtab_locals += num_locals * entry_size;
        self.common.mem_sizes.symtab_globals += num_globals * entry_size;
        self.common.mem_sizes.symtab_strings += strings_size as u64;
        Ok(())
    }

    fn finalise_layout(
        mut self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        global_addresses_out: &mut Vec<GlobalSymbolAddress>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
        symbol_db: &SymbolDb,
    ) -> Result<ObjectLayout<'data>> {
        // Sort in order to ensure deterministic allocation of PLT/GOT entries as well as output
        // order.
        self.loaded_symbols.sort();

        let file_id = self.file_id();
        let mut sections = self.sections;

        let mut emitter = self
            .common
            .create_global_address_emitter(memory_offsets, symbol_db);

        let mut section_resolutions = Vec::with_capacity(sections.len());
        for slot in sections.iter_mut() {
            if let SectionSlot::Loaded(sec) = slot {
                let output_section_id = sec.output_section_id.with_context(|| {
                    format!(
                        "Tried to load section `{}` which isn't mapped to an output section",
                        self.object
                            .section_by_index(sec.index)
                            .and_then(|s| s.name())
                            .unwrap_or("??")
                    )
                })?;
                let offset = memory_offsets.regular_mut(output_section_id, sec.alignment);
                // TODO: We probably need to be able to handle sections that are ifuncs and sections
                // that need a TLS GOT struct.
                let target_resolution = match sec.resolution_kind {
                    PltGotFlags::Neither => TargetResolutionKind::Address,
                    PltGotFlags::Got => TargetResolutionKind::Got,
                    PltGotFlags::Plt => TargetResolutionKind::Plt,
                    PltGotFlags::TlsGot => TargetResolutionKind::TlsGot,
                };
                section_resolutions
                    .push(Some(emitter.create_resolution(target_resolution, *offset)?));
                *offset += sec.capacity();
            } else {
                section_resolutions.push(None);
            }
        }

        for symbol_id in &self.loaded_symbols {
            let symbol = symbol_db.symbol(*symbol_id);
            let local_index = symbol.local_index_for_file(file_id)?;
            let local_symbol = self.object.symbol_by_index(local_index)?;
            let mut address = local_symbol.address();
            if let Some(section_index) = local_symbol.section_index() {
                let section_resolution =
                    section_resolutions[section_index.0]
                        .as_ref()
                        .ok_or_else(|| {
                            let symbol_name = symbol_db.symbol_name(*symbol_id);
                            anyhow!("Symbol `{symbol_name}` is in a section that we didn't load")
                        })?;
                address += section_resolution.address;
            } else if let Some(common) = CommonSymbol::new(&local_symbol)? {
                let offset = memory_offsets.regular_mut(output_section_id::BSS, common.alignment);
                address = *offset;
                *offset += common.size;
            }
            if let Some(global) = emitter.build_symbol(*symbol_id, address)? {
                global_addresses_out.push(global);
            }
        }

        let plt_relocations = emitter.plt_relocations;
        let strings_offset_start = self.common.finalise_layout(memory_offsets, section_layouts);

        Ok(ObjectLayout {
            input: self.input,
            file_id: self.common.file_id,
            object: self.object,
            mem_sizes: self.common.mem_sizes,
            local_symbol_resolutions: self.local_symbol_resolutions,
            sections,
            section_resolutions,
            strings_offset_start,
            plt_relocations,
            loaded_symbols: self.loaded_symbols,
        })
    }
}

#[derive(Clone, Copy)]
struct CommonSymbol {
    size: u64,
    alignment: Alignment,
}

impl CommonSymbol {
    fn new(local_symbol: &crate::elf::Symbol) -> Result<Option<CommonSymbol>> {
        if !local_symbol.is_common() {
            return Ok(None);
        }
        // Common symbols misuse the value field (which we access via `address()`) to store the
        // alignment.
        let alignment = Alignment::new(local_symbol.address())?;
        let size = alignment.align_up(local_symbol.size());
        Ok(Some(CommonSymbol { size, alignment }))
    }
}

struct GlobalAddressEmitter<'state> {
    next_got_address: u64,
    next_plt_address: u64,
    symbol_states: &'state [TargetResolutionKind],
    symbol_db: &'state SymbolDb<'state>,
    file_id: FileId,
    plt_relocations: Vec<PltRelocation>,
}

impl<'state> GlobalAddressEmitter<'state> {
    fn build_symbol(
        &mut self,
        symbol_id: GlobalSymbolId,
        address: u64,
    ) -> Result<Option<GlobalSymbolAddress>> {
        let local_symbol_index = self
            .symbol_db
            .symbol(symbol_id)
            .local_index_for_file(self.file_id)?;
        let resolution =
            self.create_resolution(self.symbol_states[local_symbol_index.0], address)?;
        Ok(Some(GlobalSymbolAddress {
            symbol_id,
            resolution: SymbolResolution::Resolved(resolution),
        }))
    }

    fn create_resolution(
        &mut self,
        res_kind: TargetResolutionKind,
        address: u64,
    ) -> Result<Resolution> {
        let mut resolution = Resolution {
            address,
            got_address: None,
            plt_address: None,
            kind: res_kind,
        };
        match res_kind {
            TargetResolutionKind::None | TargetResolutionKind::Address => {}
            TargetResolutionKind::Got => {
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
                self.plt_relocations.push(PltRelocation {
                    resolver: address,
                    got_address: got_address.get(),
                });
                // If a symbol refers to an ifunc, then all access needs to go via the PLT.
                resolution.address = plt_address.get();
                resolution.plt_address = Some(plt_address);
            }
            TargetResolutionKind::TlsGot => {
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
    fn create_layout_state(
        self,
        initial_work_queue: &mut Vec<WorkItem>,
        output_sections: &OutputSections,
    ) -> FileLayoutState<'data> {
        match self {
            resolution::ResolvedFile::Internal(s) => {
                initial_work_queue.push(WorkItem::Activate);
                FileLayoutState::Internal(InternalLayoutState::new(s, output_sections))
            }
            resolution::ResolvedFile::Object(s) => {
                initial_work_queue.push(WorkItem::Activate);
                FileLayoutState::Object(ObjectLayoutState::new(s, output_sections))
            }
            resolution::ResolvedFile::NotLoaded => FileLayoutState::NotLoaded,
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
    let mut mem_offset = elf::START_MEM_ADDRESS;
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
            if current_seg_id != Some(seg_id) {
                current_seg_id = Some(seg_id);
                let segment_alignment = section_alignment.max(seg_id.alignment());
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

/// Returns how we should handle TLS relocations like TLSLD and TLSGD.
fn determine_tls_mode(symbol_db: &SymbolDb<'_>) -> TlsMode {
    if symbol_db.args.link_static {
        TlsMode::LocalExec
    } else {
        TlsMode::Preserve
    }
}

#[allow(dead_code)]
impl<'data> DynamicLayoutState<'data> {
    fn load_symbol(
        &mut self,
        _symbol_request: SymbolRequest,
        _resources: &GraphResources,
    ) -> Result {
        todo!();
        // let local_info = self
        //     .defined_symbols
        //     .get(symbol_request.symbol_id, resources.symbol_db)?;
        // let local_symbol_id = local_info.local_symbol_id;
        // // TODO: Now that we know what range of symbol IDs we are responsible for, we could do a vec
        // // lookup here instead of a hashset insertion.
        // if self.referenced_symbols.insert(local_symbol_id) {
        //     self.referenced_symbol_ids.push(symbol_request.symbol_id)
        // }
    }

    fn new(input_state: symbol_db::ObjectSymbols<'data>) -> DynamicLayoutState<'data> {
        DynamicLayoutState {
            object: input_state.object,
            referenced_symbol_ids: Default::default(),
            input: input_state.input,
        }
    }

    fn finalise_layout(self, addresses_out: &mut Vec<GlobalSymbolAddress>) -> DynamicLayout<'data> {
        addresses_out.extend(self.referenced_symbol_ids.iter().map(|symbol_id| {
            GlobalSymbolAddress {
                symbol_id: *symbol_id,
                resolution: SymbolResolution::Dynamic,
            }
        }));
        DynamicLayout { input: self.input }
    }
}

impl<'data> ObjectLayout<'data> {
    pub(crate) fn global_id_for_symbol(&self, sym: &elf::Symbol) -> Option<GlobalSymbolId> {
        self.local_symbol_resolutions[sym.index().0].global_symbol_id()
    }
}

impl<'data> std::fmt::Debug for FileLayoutState<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal(_) => f.debug_tuple("Internal").finish(),
            Self::Object(s) => f.debug_tuple("Object").field(&s.input).finish(),
            Self::Dynamic(_) => f.debug_tuple("Dynamic").finish(),
            Self::NotLoaded => "<not loaded>".fmt(f),
        }
    }
}
fn print_symbol_info(symbol_db: &SymbolDb, files: &[resolution::ResolvedFile], name: &str) {
    let Some(symbol_id) = symbol_db.symbol_ids.get(&SymbolName::new(name.as_bytes())) else {
        println!("No global symbol `{name}` defined by any input files");
        return;
    };
    let symbol = symbol_db.symbol(*symbol_id);
    let file = &files[symbol.file_id.as_usize()];
    println!("Symbol `{name}` defined by {file}");
}

/// Performs layout of sections and segments then makes sure that the loadable segments don't
/// overlap and that sections don't overlap.
#[test]
fn test_no_disallowed_overlaps() {
    let output_sections = crate::output_section_id::OutputSectionsBuilder::default()
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
    let mut last_section_id = output_section_id::HEADERS;
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

    let segment_layouts = compute_segment_layout(&section_layouts, &output_sections);

    // Make sure loadable segments don't overlap in memory or in the file.
    let mut last_file = 0;
    let mut last_mem = 0;
    for (seg_id, seg_layout) in program_segments::segment_ids().zip(segment_layouts.iter()) {
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
