//! This module resolves symbol references between objects. In the process, it decides which archive
//! entries are needed. We also resolve which output section, if any, each input section should be
//! assigned to.

use crate::LayoutRules;
use crate::alignment::Alignment;
use crate::args::Args;
use crate::bail;
use crate::debug_assert_bail;
use crate::elf::File;
use crate::error::Context as _;
use crate::error::Error;
use crate::error::Result;
use crate::grouping::Group;
use crate::grouping::SequencedInputObject;
use crate::hash::PassThroughHashMap;
use crate::hash::PreHashed;
use crate::input_data::FileId;
use crate::input_data::InputRef;
use crate::input_data::PRELUDE_FILE_ID;
use crate::layout_rules::SectionRuleOutcome;
use crate::layout_rules::SectionRules;
use crate::output_section_id::CustomSectionDetails;
use crate::output_section_id::OutputSections;
use crate::output_section_id::SectionName;
use crate::output_section_map::OutputSectionMap;
use crate::parsing::InternalSymDefInfo;
use crate::parsing::SymbolPlacement;
use crate::part_id;
use crate::part_id::PartId;
use crate::string_merging::MergedStringsSection;
use crate::string_merging::StringMergeSectionExtra;
use crate::string_merging::StringMergeSectionSlot;
use crate::symbol::PreHashedSymbolName;
use crate::symbol::UnversionedSymbolName;
use crate::symbol::VersionedSymbolName;
use crate::symbol_db::RawSymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use atomic_take::AtomicTake;
use bitflags::bitflags;
use crossbeam_queue::ArrayQueue;
use crossbeam_queue::SegQueue;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::SectionType;
use linker_utils::elf::secnames;
use linker_utils::elf::shf;
use object::LittleEndian;
use object::read::elf::Sym as _;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use std::num::NonZeroU32;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::thread::Thread;

pub(crate) struct ResolutionOutputs<'data> {
    pub(crate) groups: Vec<ResolvedGroup<'data>>,
    pub(crate) merged_strings: OutputSectionMap<MergedStringsSection<'data>>,
}

#[tracing::instrument(skip_all, name = "Symbol resolution")]
pub fn resolve_symbols_and_sections<'data>(
    symbol_db: &mut SymbolDb<'data>,
    herd: &'data bumpalo_herd::Herd,
    output_sections: &mut OutputSections<'data>,
    layout_rules: &LayoutRules<'data>,
) -> Result<ResolutionOutputs<'data>> {
    let (mut resolved_groups, undefined_symbols) = resolve_symbols_in_files(symbol_db)?;

    resolve_sections(&mut resolved_groups, herd, symbol_db, layout_rules)?;

    let mut custom_start_stop_defs = Vec::new();

    assign_section_ids(&mut resolved_groups, output_sections);

    let merged_strings = crate::string_merging::merge_strings(
        &mut resolved_groups,
        output_sections,
        symbol_db.args,
    )?;

    canonicalise_undefined_symbols(
        undefined_symbols,
        output_sections,
        &resolved_groups,
        symbol_db,
        &mut custom_start_stop_defs,
    )?;

    let ResolvedFile::Epilogue(epilogue) = resolved_groups
        .last_mut()
        .unwrap()
        .files
        .last_mut()
        .unwrap()
    else {
        panic!("Epilogue must always be last");
    };

    epilogue.custom_start_stop_defs = custom_start_stop_defs;

    crate::symbol_db::resolve_alternative_symbol_definitions(symbol_db, &resolved_groups)?;

    Ok(ResolutionOutputs {
        groups: resolved_groups,
        merged_strings,
    })
}

#[tracing::instrument(skip_all, name = "Resolve symbols")]
fn resolve_symbols_in_files<'data>(
    symbol_db: &mut SymbolDb<'data>,
) -> Result<(Vec<ResolvedGroup<'data>>, SegQueue<UndefinedSymbol<'data>>)> {
    let mut symbol_definitions = symbol_db.take_definitions();
    let mut symbol_definitions_slice = symbol_definitions.as_mut();

    let mut definitions_per_group_and_file = Vec::new();
    definitions_per_group_and_file.resize_with(symbol_db.groups.len(), Vec::new);

    let work_queue = SegQueue::new();

    let mut resolved: Vec<ResolvedGroup<'_>> = symbol_db
        .groups
        .iter()
        .zip(&mut definitions_per_group_and_file)
        .map(|(group, definitions_out_per_file)| {
            resolve_group(
                group,
                &work_queue,
                definitions_out_per_file,
                &mut symbol_definitions_slice,
            )
        })
        .collect();

    let num_objects = symbol_db.num_objects();
    if num_objects == 0 {
        bail!("no input files");
    }
    let outputs = Outputs::new(num_objects);

    let num_threads = symbol_db.args.available_threads.get();

    let resources = ResolutionResources {
        definitions_per_file: &definitions_per_group_and_file,
        idle_threads: (num_threads > 1).then(|| ArrayQueue::new(num_threads - 1)),
        symbol_db,
        outputs: &outputs,
        work_queue,
    };

    let done = AtomicBool::new(false);

    rayon::scope(|s| {
        s.spawn_broadcast(|_, _| {
            let mut idle = false;
            while !done.load(Ordering::Relaxed) {
                while let Some(work_item) = resources.work_queue.pop() {
                    let r =
                        process_object(work_item.file_id, work_item.definitions_out, &resources);
                    if let Err(e) = r {
                        // We currently only store the first error.
                        let _ = resources.outputs.errors.push(e);
                    }
                }
                if idle {
                    // Wait until there's more work to do or until we shut down.
                    std::thread::park();
                    idle = false;
                } else {
                    if let Some(idle_threads) = resources.idle_threads.as_ref() {
                        if idle_threads.push(std::thread::current()).is_err() {
                            // No space left in our idle queue means that all other threads are idle, so
                            // we're done.
                            done.store(true, Ordering::Relaxed);
                            while let Some(thread) = idle_threads.pop() {
                                thread.unpark();
                            }
                            break;
                        }
                    } else {
                        // We're running on a single thread, so we're done.
                        break;
                    }
                    idle = true;
                    // Go around the loop again before we park the thread. This ensures that we
                    // check for waiting work in between when we added our thread to the idle
                    // list and when we park.
                }
            }
        });
    });

    drop(resources);
    drop(definitions_per_group_and_file);
    symbol_db.restore_definitions(symbol_definitions);

    if let Some(e) = outputs.errors.pop() {
        return Err(e);
    }

    for obj in outputs.loaded {
        let file_id = obj.file_id;
        resolved[file_id.group()].files[file_id.file()] = ResolvedFile::Object(obj);
    }

    Ok((resolved, outputs.undefined_symbols))
}

fn resolve_group<'data, 'definitions>(
    group: &Group<'data>,
    work_queue: &SegQueue<LoadObjectRequest<'definitions>>,
    definitions_out_per_file: &mut Vec<AtomicTake<&'definitions mut [SymbolId]>>,
    symbol_definitions_slice: &mut &'definitions mut [SymbolId],
) -> ResolvedGroup<'data> {
    match group {
        Group::Prelude(prelude) => {
            let definitions_out = crate::slice::slice_take_prefix_mut(
                symbol_definitions_slice,
                prelude.symbol_definitions.len(),
            );

            work_queue.push(LoadObjectRequest {
                file_id: PRELUDE_FILE_ID,
                definitions_out,
            });

            definitions_out_per_file.push(AtomicTake::empty());

            ResolvedGroup {
                files: vec![ResolvedFile::Prelude(ResolvedPrelude {
                    symbol_definitions: prelude.symbol_definitions.clone(),
                })],
            }
        }
        Group::Objects(parsed_input_objects) => {
            definitions_out_per_file.reserve(parsed_input_objects.len());

            let files = parsed_input_objects
                .iter()
                .map(|s| {
                    let definitions_out = crate::slice::slice_take_prefix_mut(
                        symbol_definitions_slice,
                        s.symbol_id_range.len(),
                    );

                    if s.is_optional() {
                        definitions_out_per_file.push(AtomicTake::new(definitions_out));
                    } else {
                        work_queue.push(LoadObjectRequest {
                            file_id: s.file_id,
                            definitions_out,
                        });
                        definitions_out_per_file.push(AtomicTake::empty());
                    }

                    ResolvedFile::NotLoaded(NotLoaded {
                        symbol_id_range: s.symbol_id_range,
                    })
                })
                .collect();

            ResolvedGroup { files }
        }
        Group::LinkerScripts(scripts) => {
            let files = scripts
                .iter()
                .map(|s| {
                    definitions_out_per_file.push(AtomicTake::empty());

                    ResolvedFile::LinkerScript(ResolvedLinkerScript {
                        input: s.parsed.input.clone(),
                        file_id: s.file_id,
                        symbol_id_range: s.symbol_id_range,
                        // TODO: Consider alternative to cloning this.
                        symbol_definitions: s.parsed.symbol_defs.clone(),
                    })
                })
                .collect();

            ResolvedGroup { files }
        }
        Group::Epilogue(epilogue) => {
            definitions_out_per_file.push(AtomicTake::empty());

            ResolvedGroup {
                files: vec![ResolvedFile::Epilogue(ResolvedEpilogue {
                    file_id: epilogue.file_id,
                    start_symbol_id: epilogue.start_symbol_id,
                    custom_start_stop_defs: Vec::new(),
                })],
            }
        }
    }
}

#[tracing::instrument(skip_all, name = "Resolve sections")]
fn resolve_sections<'data>(
    groups: &mut [ResolvedGroup<'data>],
    herd: &'data bumpalo_herd::Herd,
    symbol_db: &SymbolDb<'data>,
    layout_rules: &LayoutRules<'data>,
) -> Result {
    let loaded_metrics: LoadedMetrics = Default::default();

    groups.par_iter_mut().try_for_each_init(
        || herd.get(),
        |allocator, group| -> Result {
            for file in &mut group.files {
                let ResolvedFile::Object(obj) = file else {
                    continue;
                };
                let Some(mut non_dynamic) = obj.non_dynamic.take() else {
                    continue;
                };

                non_dynamic.sections = resolve_sections_for_object(
                    obj,
                    &mut non_dynamic.custom_sections,
                    &mut non_dynamic.string_merge_extras,
                    symbol_db.args,
                    allocator,
                    &loaded_metrics,
                    &layout_rules.section_rules,
                )?;

                non_dynamic.relocations = obj.object.parse_relocations()?;

                obj.non_dynamic = Some(non_dynamic);
            }
            Ok(())
        },
    )?;

    loaded_metrics.log();

    Ok(())
}

/// A request to load an object.
struct LoadObjectRequest<'definitions> {
    /// The ID of the object to load.
    file_id: FileId,

    /// The symbol resolutions for the object to be loaded that should be written to when we load
    /// the object.
    definitions_out: &'definitions mut [SymbolId],
}

#[derive(Default)]
pub(crate) struct LoadedMetrics {
    pub(crate) loaded_bytes: AtomicUsize,
    pub(crate) loaded_compressed_bytes: AtomicUsize,
    pub(crate) decompressed_bytes: AtomicUsize,
}

impl LoadedMetrics {
    fn log(&self) {
        let loaded_bytes = self.loaded_bytes.load(Ordering::Relaxed);
        let loaded_compressed_bytes = self.loaded_compressed_bytes.load(Ordering::Relaxed);
        let decompressed_bytes = self.decompressed_bytes.load(Ordering::Relaxed);
        tracing::debug!(target: "metrics", loaded_bytes, loaded_compressed_bytes, decompressed_bytes, "input_sections");
    }
}

struct ResolutionResources<'data, 'definitions, 'outer_scope> {
    definitions_per_file: &'outer_scope Vec<Vec<AtomicTake<&'definitions mut [SymbolId]>>>,
    idle_threads: Option<ArrayQueue<Thread>>,
    symbol_db: &'outer_scope SymbolDb<'data>,
    outputs: &'outer_scope Outputs<'data>,
    work_queue: SegQueue<LoadObjectRequest<'definitions>>,
}

impl ResolutionResources<'_, '_, '_> {
    /// Request loading of `file_id`.
    #[inline(always)]
    fn request_file_id(&self, file_id: FileId) {
        let Some(definitions_out) =
            self.definitions_per_file[file_id.group()][file_id.file()].take()
        else {
            // The definitions have previously been taken indicating that this file has already been
            // processed, nothing more to do.
            return;
        };

        self.work_queue.push(LoadObjectRequest {
            file_id,
            definitions_out,
        });

        // If there is a thread sleeping, wake it.
        if let Some(thread) = self
            .idle_threads
            .as_ref()
            .and_then(|idle_threads| idle_threads.pop())
        {
            thread.unpark();
        }
    }
}

pub(crate) struct ResolvedGroup<'data> {
    pub(crate) files: Vec<ResolvedFile<'data>>,
}

pub(crate) enum ResolvedFile<'data> {
    NotLoaded(NotLoaded),
    Prelude(ResolvedPrelude<'data>),
    Object(ResolvedObject<'data>),
    LinkerScript(ResolvedLinkerScript<'data>),
    Epilogue(ResolvedEpilogue<'data>),
}

pub(crate) struct NotLoaded {
    pub(crate) symbol_id_range: SymbolIdRange,
}

/// A section, but where we may or may not yet have decided to load it.
#[derive(Clone, Copy)]
pub(crate) enum SectionSlot {
    /// We've decided that this section won't be loaded.
    Discard,

    /// The section hasn't been loaded yet, but may be loaded if it's referenced.
    Unloaded(UnloadedSection),

    /// The section had the retain bit set, so must be loaded.
    MustLoad(UnloadedSection),

    /// We've already loaded the section.
    Loaded(crate::layout::Section),

    /// The section contains .eh_frame data.
    EhFrameData(object::SectionIndex),

    /// The section is a string-merge section.
    MergeStrings(StringMergeSectionSlot),

    // The section contains a debug info section that might be loaded.
    UnloadedDebugInfo(PartId),

    // Loaded section with debug info content.
    LoadedDebugInfo(crate::layout::Section),

    // GNU property section (.note.gnu.property)
    NoteGnuProperty(object::SectionIndex),

    // RISC-V attributes section (.riscv.attributes)
    RiscvVAttributes(object::SectionIndex),
}

#[derive(Clone, Copy)]
pub(crate) struct UnloadedSection {
    pub(crate) part_id: PartId,

    /// The index of the last FDE for this section. Previous FDEs will be linked from this.
    pub(crate) last_frame_index: Option<FrameIndex>,

    /// Whether the section has a name that makes it eligible for generation of __start_ / __stop_
    /// symbols. In particular, the name of the section doesn't start with a ".".
    pub(crate) start_stop_eligible: bool,
}

impl UnloadedSection {
    fn new(part_id: PartId) -> Self {
        Self {
            part_id,
            last_frame_index: None,
            start_stop_eligible: false,
        }
    }
}

/// An index into the exception frames for an object.
#[derive(Clone, Copy)]
pub(crate) struct FrameIndex(NonZeroU32);

#[derive(Clone)]
pub(crate) struct ResolvedPrelude<'data> {
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo<'data>>,
}

pub(crate) struct ResolvedObject<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) object: &'data File<'data>,
    pub(crate) file_id: FileId,
    pub(crate) symbol_id_range: SymbolIdRange,

    pub(crate) non_dynamic: Option<NonDynamicResolved<'data>>,
}

/// Parts of a resolved object that are only applicable to non-dynamic objects.
pub(crate) struct NonDynamicResolved<'data> {
    pub(crate) sections: Vec<SectionSlot>,
    pub(crate) relocations: object::read::elf::RelocationSections,

    pub(crate) string_merge_extras: Vec<StringMergeSectionExtra<'data>>,

    /// Details about each custom section that is defined in this object.
    custom_sections: Vec<CustomSectionDetails<'data>>,
}

pub(crate) struct ResolvedLinkerScript<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) file_id: FileId,
    pub(crate) symbol_id_range: SymbolIdRange,
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo<'data>>,
}

#[derive(Clone)]
pub(crate) struct ResolvedEpilogue<'data> {
    pub(crate) file_id: FileId,
    pub(crate) start_symbol_id: SymbolId,
    pub(crate) custom_start_stop_defs: Vec<InternalSymDefInfo<'data>>,
}

#[tracing::instrument(skip_all, name = "Assign section IDs")]
fn assign_section_ids<'data>(
    resolved: &mut [ResolvedGroup<'data>],
    output_sections: &mut OutputSections<'data>,
) {
    for group in resolved {
        for file in &mut group.files {
            if let ResolvedFile::Object(s) = file {
                if let Some(non_dynamic) = s.non_dynamic.as_mut() {
                    output_sections.add_sections(
                        &non_dynamic.custom_sections,
                        non_dynamic.sections.as_mut_slice(),
                    );
                }
            }
        }
    }
}

struct Outputs<'data> {
    /// Where we put objects once we've loaded them.
    loaded: ArrayQueue<ResolvedObject<'data>>,

    /// Any errors that we encountered.
    errors: ArrayQueue<Error>,

    undefined_symbols: SegQueue<UndefinedSymbol<'data>>,
}

impl Outputs<'_> {
    fn new(num_objects: usize) -> Self {
        Self {
            loaded: ArrayQueue::new(num_objects),
            errors: ArrayQueue::new(1),
            undefined_symbols: SegQueue::new(),
        }
    }
}

fn process_object<'scope, 'data: 'scope, 'definitions>(
    file_id: FileId,
    definitions_out: &mut [SymbolId],
    resources: &'scope ResolutionResources<'data, 'definitions, 'scope>,
) -> Result {
    match &resources.symbol_db.groups[file_id.group()] {
        Group::Prelude(prelude) => {
            load_prelude(prelude, definitions_out, resources);
        }
        Group::Objects(parsed_input_objects) => {
            let obj = &parsed_input_objects[file_id.file()];
            let input = obj.parsed.input.clone();
            let res = ResolvedObject::new(
                obj,
                resources,
                definitions_out,
                &resources.outputs.undefined_symbols,
            )
            .with_context(|| format!("Failed to process {input}"))?;
            let _ = resources.outputs.loaded.push(res);
        }
        Group::LinkerScripts(_) => {}
        Group::Epilogue(_) => {}
    }
    Ok(())
}

struct UndefinedSymbol<'data> {
    /// If we have a file ID here and that file is loaded, then the symbol is actually defined and
    /// this record can be ignored.
    ignore_if_loaded: Option<FileId>,
    name: PreHashedSymbolName<'data>,
    symbol_id: SymbolId,
}

fn load_prelude(
    prelude: &crate::parsing::Prelude,
    definitions_out: &mut [SymbolId],
    resources: &ResolutionResources,
) {
    if resources.symbol_db.args.output_kind().is_executable() {
        // The start symbol could be defined within an archive entry. If it is, then we need to load
        // it. We don't currently store the resulting SymbolId, but instead look it up again during
        // layout.
        load_symbol_named(
            resources,
            &mut SymbolId::undefined(),
            resources.symbol_db.entry_symbol_name(),
        );
    }

    // Try to resolve any symbols that the user requested be undefined (e.g. via --undefined). If an
    // object defines such a symbol, request that the object be loaded. Also, point our undefined
    // symbol record to the definition.
    for (def_info, definition_out) in prelude.symbol_definitions.iter().zip(definitions_out) {
        match def_info.placement {
            SymbolPlacement::ForceUndefined => {
                load_symbol_named(resources, definition_out, def_info.name);
            }
            _ => {}
        }
    }
}

fn load_symbol_named(resources: &ResolutionResources, definition_out: &mut SymbolId, name: &[u8]) {
    if let Some(symbol_id) = resources
        .symbol_db
        .get_unversioned(&UnversionedSymbolName::prehashed(name))
    {
        *definition_out = symbol_id;

        let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        resources.request_file_id(symbol_file_id);
    }
}

#[tracing::instrument(skip_all, name = "Canonicalise undefined symbols")]
fn canonicalise_undefined_symbols<'data>(
    undefined_symbols: SegQueue<UndefinedSymbol<'data>>,
    output_sections: &OutputSections,
    groups: &[ResolvedGroup],
    symbol_db: &mut SymbolDb<'data>,
    custom_start_stop_defs: &mut Vec<InternalSymDefInfo<'data>>,
) -> Result {
    let mut name_to_id: PassThroughHashMap<UnversionedSymbolName<'data>, SymbolId> =
        Default::default();

    let mut versioned_name_to_id: PassThroughHashMap<VersionedSymbolName<'data>, SymbolId> =
        Default::default();

    let mut undefined_symbols = Vec::from_iter(undefined_symbols);

    // Sort by symbol ID to ensure deterministic behaviour. This means that the canonical symbol ID
    // for any given name will be the one for the earliest file that refers to that symbol.
    undefined_symbols.sort_by_key(|u| u.symbol_id);

    for undefined in undefined_symbols {
        let is_defined = undefined.ignore_if_loaded.is_some_and(|file_id| {
            !matches!(
                groups[file_id.group()].files[file_id.file()],
                ResolvedFile::NotLoaded(_)
            )
        });

        if is_defined {
            // The archive entry that defined the symbol in question ended up being loaded, so the
            // weak symbol is defined after all.
            continue;
        }

        match undefined.name {
            PreHashedSymbolName::Unversioned(pre_hashed) => {
                match name_to_id.entry(pre_hashed) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        let symbol_id = allocate_start_stop_symbol_id(
                            pre_hashed,
                            symbol_db,
                            custom_start_stop_defs,
                            output_sections,
                        );

                        // If the symbol isn't a start/stop symbol, then assign responsibility for the
                        // symbol to the first object that referenced it. This lets us have PLT/GOT entries
                        // for the symbol if they're needed.
                        let symbol_id = symbol_id.unwrap_or(undefined.symbol_id);
                        entry.insert(symbol_id);
                        symbol_db.replace_definition(undefined.symbol_id, symbol_id);
                    }
                    std::collections::hash_map::Entry::Occupied(entry) => {
                        symbol_db.replace_definition(undefined.symbol_id, *entry.get());
                    }
                }
            }
            PreHashedSymbolName::Versioned(pre_hashed) => {
                match versioned_name_to_id.entry(pre_hashed) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(undefined.symbol_id);
                    }
                    std::collections::hash_map::Entry::Occupied(entry) => {
                        symbol_db.replace_definition(undefined.symbol_id, *entry.get());
                    }
                }
            }
        }
    }

    Ok(())
}

fn allocate_start_stop_symbol_id<'data>(
    name: PreHashed<UnversionedSymbolName<'data>>,
    symbol_db: &mut SymbolDb<'data>,
    custom_start_stop_defs: &mut Vec<InternalSymDefInfo<'data>>,
    output_sections: &OutputSections,
) -> Option<SymbolId> {
    let symbol_name_bytes = name.bytes();

    let (section_name, is_start) = if let Some(s) = symbol_name_bytes.strip_prefix(b"__start_") {
        (s, true)
    } else if let Some(s) = symbol_name_bytes.strip_prefix(b"__stop_") {
        (s, false)
    } else {
        return None;
    };

    let section_id = output_sections.custom_name_to_id(SectionName(section_name))?;

    let symbol_id = symbol_db.add_start_stop_symbol(name);

    let def_info = if is_start {
        InternalSymDefInfo::notype(SymbolPlacement::SectionStart(section_id), name.bytes())
    } else {
        InternalSymDefInfo::notype(SymbolPlacement::SectionEnd(section_id), name.bytes())
    };

    custom_start_stop_defs.push(def_info);

    Some(symbol_id)
}

impl<'data> ResolvedObject<'data> {
    fn new(
        obj: &'data SequencedInputObject<'data>,
        resources: &ResolutionResources<'data, '_, '_>,
        definitions_out: &mut [SymbolId],
        undefined_symbols_out: &SegQueue<UndefinedSymbol<'data>>,
    ) -> Result<Self> {
        let mut non_dynamic = None;

        if obj.is_dynamic() {
            resolve_dynamic_symbols(obj, resources, undefined_symbols_out, definitions_out)
                .with_context(|| format!("Failed to resolve symbols in {obj}"))?;
        } else {
            resolve_symbols(obj, resources, undefined_symbols_out, definitions_out)
                .with_context(|| format!("Failed to resolve symbols in {obj}"))?;

            // We'll fill this in during section resolution.
            non_dynamic = Some(NonDynamicResolved {
                sections: Default::default(),
                relocations: Default::default(),
                string_merge_extras: Default::default(),
                custom_sections: Default::default(),
            });
        }

        Ok(Self {
            input: obj.parsed.input.clone(),
            object: &obj.parsed.object,
            file_id: obj.file_id,
            symbol_id_range: obj.symbol_id_range,
            non_dynamic,
        })
    }
}

fn resolve_sections_for_object<'data>(
    obj: &ResolvedObject<'data>,
    custom_sections: &mut Vec<CustomSectionDetails<'data>>,
    string_merge_extras: &mut Vec<StringMergeSectionExtra<'data>>,
    args: &Args,
    allocator: &bumpalo_herd::Member<'data>,
    loaded_metrics: &LoadedMetrics,
    rules: &SectionRules,
) -> Result<Vec<SectionSlot>> {
    let sections = obj
        .object
        .sections
        .enumerate()
        .map(|(input_section_index, input_section)| {
            let section_name = obj.object.section_name(input_section).unwrap_or_default();

            if section_name.starts_with(secnames::GNU_LTO_SYMTAB_PREFIX.as_bytes()) {
                bail!("GCC IR (LTO mode) is not supported yet");
            }

            let section_flags = SectionFlags::from_header(input_section);
            let raw_alignment = obj.object.section_alignment(input_section)?;
            let alignment = Alignment::new(raw_alignment.max(1))?;
            let should_merge_strings =
                part_id::should_merge_strings(section_flags, raw_alignment, args);

            let mut unloaded_section;
            let mut must_load = section_flags.should_retain();
            let mut is_debug_info = false;
            let section_type = SectionType::from_header(input_section);

            match rules.lookup(section_name, section_flags, section_type) {
                SectionRuleOutcome::Section(output_info) => {
                    let part_id = output_info.section_id.part_id_with_alignment(alignment);

                    must_load |= output_info.must_keep;

                    unloaded_section = UnloadedSection::new(part_id);
                }
                SectionRuleOutcome::Discard => return Ok(SectionSlot::Discard),
                SectionRuleOutcome::EhFrame => {
                    return Ok(SectionSlot::EhFrameData(input_section_index));
                }
                SectionRuleOutcome::NoteGnuProperty => {
                    return Ok(SectionSlot::NoteGnuProperty(input_section_index));
                }
                SectionRuleOutcome::Debug => {
                    if args.strip_debug && !section_flags.contains(shf::ALLOC) {
                        return Ok(SectionSlot::Discard);
                    }

                    is_debug_info = !section_flags.contains(shf::ALLOC);

                    unloaded_section = UnloadedSection::new(part_id::CUSTOM_PLACEHOLDER);
                }
                SectionRuleOutcome::Custom => {
                    unloaded_section = UnloadedSection::new(part_id::CUSTOM_PLACEHOLDER);
                    unloaded_section.start_stop_eligible = !section_name.starts_with(b".");
                }
                SectionRuleOutcome::RiscVAttribute => {
                    return Ok(SectionSlot::RiscvVAttributes(input_section_index));
                }
            };

            if unloaded_section.part_id == part_id::CUSTOM_PLACEHOLDER {
                let custom_section = CustomSectionDetails {
                    name: SectionName(section_name),
                    alignment,
                    index: input_section_index,
                };

                custom_sections.push(custom_section);
            }

            let slot = if should_merge_strings {
                let section_data =
                    obj.object
                        .section_data(input_section, allocator, loaded_metrics)?;

                string_merge_extras.push(StringMergeSectionExtra {
                    index: input_section_index,
                    section_data,
                });

                SectionSlot::MergeStrings(StringMergeSectionSlot::new(unloaded_section.part_id))
            } else if is_debug_info {
                SectionSlot::UnloadedDebugInfo(part_id::CUSTOM_PLACEHOLDER)
            } else if must_load {
                SectionSlot::MustLoad(unloaded_section)
            } else {
                SectionSlot::Unloaded(unloaded_section)
            };

            Ok(slot)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(sections)
}

fn resolve_symbols<'data>(
    obj: &SequencedInputObject<'data>,
    resources: &ResolutionResources<'data, '_, '_>,
    undefined_symbols_out: &SegQueue<UndefinedSymbol<'data>>,
    definitions_out: &mut [SymbolId],
) -> Result {
    obj.parsed
        .object
        .symbols
        .enumerate()
        .zip(definitions_out)
        .try_for_each(
            |((local_symbol_index, local_symbol), definition)| -> Result {
                resolve_symbol(
                    local_symbol_index,
                    local_symbol,
                    definition,
                    resources,
                    obj,
                    undefined_symbols_out,
                    false,
                )
            },
        )?;
    Ok(())
}

fn resolve_dynamic_symbols<'data>(
    obj: &SequencedInputObject<'data>,
    resources: &ResolutionResources<'data, '_, '_>,
    undefined_symbols_out: &SegQueue<UndefinedSymbol<'data>>,
    definitions_out: &mut [SymbolId],
) -> Result {
    obj.parsed
        .object
        .symbols
        .enumerate()
        .zip(definitions_out)
        .try_for_each(
            |((local_symbol_index, local_symbol), definition)| -> Result {
                resolve_symbol(
                    local_symbol_index,
                    local_symbol,
                    definition,
                    resources,
                    obj,
                    undefined_symbols_out,
                    true,
                )
            },
        )?;
    Ok(())
}

#[inline(always)]
fn resolve_symbol<'data>(
    local_symbol_index: object::SymbolIndex,
    local_symbol: &crate::elf::SymtabEntry,
    definition_out: &mut SymbolId,
    resources: &ResolutionResources<'data, '_, '_>,
    obj: &SequencedInputObject<'data>,
    undefined_symbols_out: &SegQueue<UndefinedSymbol<'data>>,
    is_from_shared_object: bool,
) -> Result {
    // Don't try to resolve symbols that are already defined, e.g. locals and globals that we
    // define. Also don't try to resolve symbol zero - the undefined symbol. Hidden symbols exported
    // from shared objects don't make sense, so we skip resolving them as well.
    if !definition_out.is_undefined()
        || local_symbol_index.0 == 0
        || (is_from_shared_object && crate::elf::is_hidden_symbol(local_symbol))
    {
        return Ok(());
    }

    let name_info = RawSymbolName::parse(obj.parsed.object.symbol_name(local_symbol)?);

    debug_assert_bail!(
        !local_symbol.is_local(),
        "Only globals should be undefined, found symbol `{}` ({local_symbol_index})",
        name_info,
    );

    assert!(!local_symbol.is_definition(LittleEndian));
    let prehashed_name = PreHashedSymbolName::from_raw(&name_info);

    match resources.symbol_db.get(&prehashed_name) {
        Some(symbol_id) => {
            *definition_out = symbol_id;
            let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);

            if symbol_file_id != obj.file_id && !local_symbol.is_weak() {
                // Undefined symbols in shared objects should actually activate as-needed shared
                // objects, however the rules for whether this should result in a DT_NEEDED entry
                // are kind of subtle, so for now, we don't activate shared objects from shared
                // objects. See
                // https://github.com/davidlattimore/wild/issues/930#issuecomment-3007027924 for
                // more details. TODO: Fix this.
                if !is_from_shared_object || !resources.symbol_db.file(symbol_file_id).is_dynamic()
                {
                    resources.request_file_id(symbol_file_id);
                }
            } else if symbol_file_id != PRELUDE_FILE_ID {
                // The symbol is weak and we can't be sure that the file that defined it will end up
                // being loaded, so the symbol might actually be undefined. Register it as an
                // undefined symbol then later when we handle undefined symbols, we'll check if the
                // file got loaded. TODO: If the file is a non-archived object, or possibly even if
                // it's an archived object that we've already decided to load, then we could skip
                // this.
                undefined_symbols_out.push(UndefinedSymbol {
                    ignore_if_loaded: Some(symbol_file_id),
                    name: prehashed_name,
                    symbol_id: obj.symbol_id_range.input_to_id(local_symbol_index),
                });
            }
        }
        None => {
            undefined_symbols_out.push(UndefinedSymbol {
                ignore_if_loaded: None,
                name: prehashed_name,
                symbol_id: obj.symbol_id_range.input_to_id(local_symbol_index),
            });
        }
    }
    Ok(())
}

impl std::fmt::Display for ResolvedObject<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl std::fmt::Display for ResolvedLinkerScript<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl std::fmt::Display for ResolvedFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolvedFile::NotLoaded(_) => std::fmt::Display::fmt("<not loaded>", f),
            ResolvedFile::Prelude(_) => std::fmt::Display::fmt("<prelude>", f),
            ResolvedFile::Object(o) => std::fmt::Display::fmt(o, f),
            ResolvedFile::LinkerScript(o) => std::fmt::Display::fmt(o, f),
            ResolvedFile::Epilogue(_) => std::fmt::Display::fmt("<epilogue>", f),
        }
    }
}

impl SectionSlot {
    pub(crate) fn is_loaded(&self) -> bool {
        !matches!(self, SectionSlot::Discard | SectionSlot::Unloaded(..))
    }

    pub(crate) fn set_part_id(&mut self, part_id: PartId) {
        match self {
            SectionSlot::Discard => todo!(),
            SectionSlot::Unloaded(section) => section.part_id = part_id,
            SectionSlot::MustLoad(section) => section.part_id = part_id,
            SectionSlot::Loaded(section) => section.part_id = part_id,
            SectionSlot::EhFrameData(_) => todo!(),
            SectionSlot::MergeStrings(section) => section.part_id = part_id,
            SectionSlot::UnloadedDebugInfo(out) => *out = part_id,
            SectionSlot::LoadedDebugInfo(section) => section.part_id = part_id,
            SectionSlot::NoteGnuProperty(_) | SectionSlot::RiscvVAttributes(_) => {}
        }
    }

    pub(crate) fn unloaded_mut(&mut self) -> Option<&mut UnloadedSection> {
        match self {
            SectionSlot::Unloaded(unloaded) | SectionSlot::MustLoad(unloaded) => Some(unloaded),
            _ => None,
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct ValueFlags: u8 {
        /// Something with an address. e.g. a regular symbol, a section etc.
        const ADDRESS = 1 << 0;

        /// An absolute value that won't change depending on load address. This could be a symbol
        /// with an absolute value or an undefined symbol, which needs to always resolve to 0
        /// regardless of load address.
        const ABSOLUTE = 1 << 1;

        /// The value is from a shared (dynamic) object, so although it may have an address, it
        /// won't be known until runtime. If combined with `ABSOLUTE`, then the symbol isn't
        /// actually defined by any shared object. We'll emit a dynamic relocation for it on a
        /// best-effort basis only. e.g. if there are direct references to it from a read-only
        /// section we'll fill them in as zero.
        const DYNAMIC = 1 << 2;

        /// The value refers to an ifunc. The actual address won't be known until runtime.
        const IFUNC = 1 << 3;

        /// Whether the definition of the symbol is final and cannot be overridden at runtime.
        const NON_INTERPOSABLE = 1 << 4;

        /// We have a version script and the version script says that the symbol should be downgraded to
        /// a local. It's still treated as a global for name lookup purposes, but after that, it becomes
        /// local.
        const DOWNGRADE_TO_LOCAL = 1 << 5;

        /// Set when the value is a function. Currently only set for dynamic symbols, since that's
        /// all we need it for.
        const FUNCTION = 1 << 6;
    }
}

pub(crate) struct AtomicValueFlags(AtomicU8);

impl ValueFlags {
    /// Returns self merged with `other` which should be the flags for the local (possibly
    /// non-canonical symbol definition). Sometimes an object will reference a symbol that it
    /// doesn't define and will mark that symbol as hidden, however the object that defines the
    /// symbol gives the symbol default visibility. In this case, we want references in the object
    /// defining it as hidden to be allowed to bypass the GOT/PLT.
    pub(crate) fn merge(&mut self, other: ValueFlags) {
        if other.contains(ValueFlags::NON_INTERPOSABLE) {
            *self |= ValueFlags::NON_INTERPOSABLE;
        }
    }

    #[must_use]
    pub(crate) fn is_dynamic(self) -> bool {
        self.contains(ValueFlags::DYNAMIC)
    }

    #[must_use]
    pub(crate) fn is_ifunc(self) -> bool {
        self.contains(ValueFlags::IFUNC)
    }

    #[must_use]
    pub(crate) fn is_address(self) -> bool {
        self.contains(ValueFlags::ADDRESS)
    }

    #[must_use]
    pub(crate) fn is_absolute(self) -> bool {
        self.contains(ValueFlags::ABSOLUTE)
    }

    #[must_use]
    pub(crate) fn is_function(self) -> bool {
        self.contains(ValueFlags::FUNCTION)
    }
    #[must_use]
    pub(crate) fn is_downgraded_to_local(self) -> bool {
        self.contains(ValueFlags::DOWNGRADE_TO_LOCAL)
    }

    #[must_use]
    pub(crate) fn is_interposable(self) -> bool {
        !self.contains(ValueFlags::NON_INTERPOSABLE)
    }

    pub(crate) fn as_atomic(self) -> AtomicValueFlags {
        AtomicValueFlags(AtomicU8::new(self.0.bits()))
    }
}

impl AtomicValueFlags {
    pub(crate) fn get(&self) -> ValueFlags {
        ValueFlags::from_bits_retain(self.0.load(Ordering::Relaxed))
    }

    pub(crate) fn or_assign(&self, flags: ValueFlags) {
        self.0.fetch_or(flags.bits(), Ordering::Relaxed);
    }

    pub(crate) fn into_non_atomic(self) -> ValueFlags {
        ValueFlags::from_bits_retain(self.0.into_inner())
    }
}

impl std::fmt::Display for ValueFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

impl FrameIndex {
    pub(crate) fn from_usize(raw: usize) -> Self {
        Self(NonZeroU32::new(raw as u32 + 1).unwrap())
    }

    pub(crate) fn as_usize(self) -> usize {
        self.0.get() as usize - 1
    }
}

// We create quite a lot of `SectionSlot`s. We don't generally copy them, however we do need to
// eventually drop the Vecs that contain them. Dropping those Vecs is a lot cheaper if the slots
// don't need to have run Drop. We check for this, by making sure the type implements `Copy`
#[test]
fn section_slot_is_copy() {
    fn assert_copy<T: Copy>(_v: T) {}

    assert_copy(SectionSlot::Discard);
}
