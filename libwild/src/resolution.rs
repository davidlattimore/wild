//! This module resolves symbol references between objects. In the process, it decides which archive
//! entries are needed. We also resolve which output section, if any, each input section should be
//! assigned to.

use self::part_id::NOTE_GNU_PROPERTY;
use crate::args::Args;
use crate::debug_assert_bail;
use crate::elf::File;
use crate::error::Error;
use crate::error::Result;
use crate::grouping::Group;
use crate::hash::PassThroughHashMap;
use crate::hash::PreHashed;
use crate::input_data::FileId;
use crate::input_data::InputRef;
use crate::input_data::PRELUDE_FILE_ID;
use crate::input_data::UNINITIALISED_FILE_ID;
use crate::output_section_id::CustomSectionDetails;
use crate::output_section_id::OutputSections;
use crate::output_section_id::OutputSectionsBuilder;
use crate::output_section_id::SectionName;
use crate::output_section_map::OutputSectionMap;
use crate::parsing::InternalSymDefInfo;
use crate::parsing::ParsedInput;
use crate::parsing::ParsedInputObject;
use crate::part_id;
use crate::part_id::PartId;
use crate::part_id::TemporaryPartId;
use crate::part_id::UnresolvedSection;
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
use anyhow::Context;
use anyhow::bail;
use atomic_take::AtomicTake;
use bitflags::bitflags;
use crossbeam_queue::ArrayQueue;
use crossbeam_queue::SegQueue;
use itertools::Itertools;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::SectionType;
use linker_utils::elf::shf;
use object::LittleEndian;
use object::read::elf::Sym as _;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use std::num::NonZeroU32;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::thread::Thread;

pub(crate) struct ResolutionOutputs<'data> {
    pub(crate) groups: Vec<ResolvedGroup<'data>>,
    pub(crate) output_sections: OutputSections<'data>,
    pub(crate) merged_strings: OutputSectionMap<MergedStringsSection<'data>>,
    pub(crate) custom_start_stop_defs: Vec<InternalSymDefInfo>,
}

#[tracing::instrument(skip_all, name = "Symbol resolution")]
pub fn resolve_symbols_and_sections<'data>(
    groups: &'data [Group<'data>],
    symbol_db: &mut SymbolDb<'data>,
    herd: &'data bumpalo_herd::Herd,
) -> Result<ResolutionOutputs<'data>> {
    let (mut groups, undefined_symbols) = resolve_symbols_in_files(groups, symbol_db)?;

    resolve_sections(&mut groups, herd, symbol_db.args)?;

    let output_sections = assign_section_ids(&mut groups, symbol_db.args)?;

    let merged_strings =
        crate::string_merging::merge_strings(&mut groups, &output_sections, symbol_db.args)?;

    let custom_start_stop_defs =
        canonicalise_undefined_symbols(undefined_symbols, &output_sections, &groups, symbol_db)?;

    crate::symbol_db::resolve_alternative_symbol_definitions(symbol_db, &groups)?;

    Ok(ResolutionOutputs {
        groups,
        output_sections,
        merged_strings,
        custom_start_stop_defs,
    })
}

#[tracing::instrument(skip_all, name = "Resolve symbols")]
pub(crate) fn resolve_symbols_in_files<'data>(
    groups: &'data [Group<'data>],
    symbol_db: &mut SymbolDb<'data>,
) -> Result<(Vec<ResolvedGroup<'data>>, SegQueue<UndefinedSymbol<'data>>)> {
    let mut num_objects = 0;

    let mut symbol_definitions = symbol_db.take_definitions();
    let mut symbol_definitions_slice = symbol_definitions.as_mut();

    let mut definitions_per_group_and_file = groups
        .iter()
        .map(|group| {
            group
                .files
                .iter()
                .map(|file| {
                    AtomicTake::new(crate::slice::slice_take_prefix_mut(
                        &mut symbol_definitions_slice,
                        file.num_symbols(),
                    ))
                })
                .collect_vec()
        })
        .collect_vec();

    let work_queue = SegQueue::new();

    let mut resolved: Vec<ResolvedGroup<'_>> = groups
        .iter()
        .zip(&mut definitions_per_group_and_file)
        .map(|(group, definitions_per_file)| {
            let files = group
                .files
                .iter()
                .zip(definitions_per_file)
                .map(|(file, definitions)| match file {
                    ParsedInput::Prelude(s) => {
                        work_queue.push(LoadObjectRequest {
                            file_id: PRELUDE_FILE_ID,
                            definitions_out: definitions.take().unwrap(),
                        });
                        ResolvedFile::Prelude(ResolvedPrelude {
                            symbol_definitions: &s.symbol_definitions,
                        })
                    }
                    ParsedInput::Object(s) => {
                        if !s.is_optional() {
                            work_queue.push(LoadObjectRequest {
                                file_id: s.file_id,
                                definitions_out: definitions.take().unwrap(),
                            });
                        }
                        num_objects += 1;
                        ResolvedFile::NotLoaded(NotLoaded {
                            symbol_id_range: s.symbol_id_range,
                        })
                    }
                    ParsedInput::Epilogue(s) => ResolvedFile::Epilogue(ResolvedEpilogue {
                        file_id: UNINITIALISED_FILE_ID,
                        start_symbol_id: s.start_symbol_id,
                    }),
                })
                .collect();

            ResolvedGroup { files }
        })
        .collect();

    if num_objects == 0 {
        bail!("Cannot link with 0 input files");
    }

    let outputs = Outputs::new(num_objects);

    let num_threads = symbol_db.args.num_threads.get();

    let resources = ResolutionResources {
        groups,
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

#[tracing::instrument(skip_all, name = "Resolve sections")]
fn resolve_sections<'data>(
    groups: &mut [ResolvedGroup<'data>],
    herd: &'data bumpalo_herd::Herd,
    args: &Args,
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
                    args,
                    allocator,
                    &loaded_metrics,
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
    groups: &'data [Group<'data>],
    definitions_per_file: &'outer_scope Vec<Vec<AtomicTake<&'definitions mut [SymbolId]>>>,
    idle_threads: Option<ArrayQueue<Thread>>,
    symbol_db: &'outer_scope SymbolDb<'data>,
    outputs: &'outer_scope Outputs<'data>,
    work_queue: SegQueue<LoadObjectRequest<'definitions>>,
}

impl ResolutionResources<'_, '_, '_> {
    /// Request loading of `file_id`.
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
    Epilogue(ResolvedEpilogue),
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

    /// The section contain .eh_frame data.
    EhFrameData(object::SectionIndex),

    /// The section is a string-merge section.
    MergeStrings(StringMergeSectionSlot),

    // The section contains a debug info section that might be loaded.
    UnloadedDebugInfo(PartId),

    // Loaded section with debug info content.
    LoadedDebugInfo(crate::layout::Section),

    // GNU property section (.note.gnu.property)
    NoteGnuProperty(object::SectionIndex),
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

#[derive(Clone, Copy)]
pub(crate) struct ResolvedPrelude<'data> {
    pub(crate) symbol_definitions: &'data [InternalSymDefInfo],
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

#[derive(Clone, Copy)]
pub(crate) struct ResolvedEpilogue {
    pub(crate) file_id: FileId,
    pub(crate) start_symbol_id: SymbolId,
}

#[tracing::instrument(skip_all, name = "Assign section IDs")]
fn assign_section_ids<'data>(
    resolved: &mut [ResolvedGroup<'data>],
    args: &Args,
) -> Result<OutputSections<'data>> {
    let mut output_sections_builder = OutputSectionsBuilder::with_base_address(args.base_address());
    for group in resolved {
        for file in &mut group.files {
            if let ResolvedFile::Object(s) = file {
                if let Some(non_dynamic) = s.non_dynamic.as_mut() {
                    output_sections_builder.add_sections(
                        &non_dynamic.custom_sections,
                        non_dynamic.sections.as_mut_slice(),
                    );
                }
            }
        }
    }
    output_sections_builder.build()
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
    match &resources.groups[file_id.group()].files[file_id.file()] {
        ParsedInput::Object(obj) => {
            let input = obj.input.clone();
            let res = ResolvedObject::new(
                obj,
                resources,
                definitions_out,
                &resources.outputs.undefined_symbols,
            )
            .with_context(|| format!("Failed to process {input}"))?;
            let _ = resources.outputs.loaded.push(res);
        }
        ParsedInput::Prelude(prelude) => {
            load_prelude(prelude, definitions_out, resources);
        }
        ParsedInput::Epilogue(_) => {}
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
        // The _start symbol could be defined within an archive entry. If it is, then we need to
        // load it. We don't currently store the resulting SymbolId, but instead look it up again
        // during layout.
        load_symbol_named(resources, &mut SymbolId::undefined(), b"_start");
    }

    // Try to resolve any symbols that the user requested be undefined (e.g. via --undefined). If an
    // object defines such a symbol, request that the object be loaded. Also, point our undefined
    // symbol record to the definition.
    for (def_info, definition_out) in prelude.symbol_definitions.iter().zip(definitions_out) {
        match def_info {
            InternalSymDefInfo::ForceUndefined(undefined_symbol_index) => {
                let name = prelude.get_undefined_name(*undefined_symbol_index);

                load_symbol_named(resources, definition_out, name);
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
) -> Result<Vec<InternalSymDefInfo>> {
    let mut custom_start_stop_defs = Vec::new();

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
                            &mut custom_start_stop_defs,
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

    Ok(custom_start_stop_defs)
}

fn allocate_start_stop_symbol_id<'data>(
    name: PreHashed<UnversionedSymbolName<'data>>,
    symbol_db: &mut SymbolDb<'data>,
    custom_start_stop_defs: &mut Vec<InternalSymDefInfo>,
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
        InternalSymDefInfo::SectionStart(section_id)
    } else {
        InternalSymDefInfo::SectionEnd(section_id)
    };

    custom_start_stop_defs.push(def_info);

    Some(symbol_id)
}

impl<'data> ResolvedObject<'data> {
    fn new(
        obj: &'data ParsedInputObject<'data>,
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
            input: obj.input.clone(),
            object: &obj.object,
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
) -> Result<Vec<SectionSlot>> {
    let sections = obj
        .object
        .sections
        .enumerate()
        .map(|(input_section_index, input_section)| {
            if let Some(unloaded) =
                UnresolvedSection::from_section(obj.object, input_section, args)?
            {
                let section_flags = SectionFlags::from_header(input_section);
                let mut part_id = part_id::CUSTOM_PLACEHOLDER;
                let mut custom_section = None;
                match unloaded.part_id {
                    TemporaryPartId::Custom(_, alignment) => {
                        custom_section = Some(CustomSectionDetails {
                            name: unloaded.name(),
                            alignment,
                            section_flags,
                            ty: SectionType::from_header(input_section),
                            index: input_section_index,
                        });
                    }
                    TemporaryPartId::BuiltIn(p) => part_id = p,
                    TemporaryPartId::EhFrameData => (),
                }
                let slot = if unloaded.is_string_merge {
                    let section_data =
                        obj.object
                            .section_data(input_section, allocator, loaded_metrics)?;
                    string_merge_extras.push(StringMergeSectionExtra {
                        index: input_section_index,
                        section_data,
                    });
                    SectionSlot::MergeStrings(StringMergeSectionSlot::new(part_id))
                } else {
                    match unloaded.part_id {
                        TemporaryPartId::BuiltIn(id) if id == NOTE_GNU_PROPERTY => {
                            SectionSlot::NoteGnuProperty(input_section_index)
                        }
                        TemporaryPartId::BuiltIn(id)
                            if id
                                .output_section_id()
                                .built_in_details()
                                .section_flags
                                .should_retain() =>
                        {
                            SectionSlot::MustLoad(UnloadedSection::new(id))
                        }
                        TemporaryPartId::BuiltIn(id) => {
                            SectionSlot::Unloaded(UnloadedSection::new(id))
                        }
                        TemporaryPartId::Custom(custom_section_id, _alignment) => {
                            let section_name = custom_section_id.name.bytes();
                            if section_name.starts_with(b".debug_")
                                && !section_flags.contains(shf::ALLOC)
                            {
                                if args.strip_debug {
                                    custom_section = None;
                                    SectionSlot::Discard
                                } else {
                                    SectionSlot::UnloadedDebugInfo(part_id::CUSTOM_PLACEHOLDER)
                                }
                            } else if section_flags.should_retain() {
                                SectionSlot::MustLoad(UnloadedSection::new(
                                    part_id::CUSTOM_PLACEHOLDER,
                                ))
                            } else {
                                let mut unloaded_section =
                                    UnloadedSection::new(part_id::CUSTOM_PLACEHOLDER);
                                unloaded_section.start_stop_eligible =
                                    !section_name.starts_with(b".");
                                SectionSlot::Unloaded(unloaded_section)
                            }
                        }
                        TemporaryPartId::EhFrameData => {
                            SectionSlot::EhFrameData(input_section_index)
                        }
                    }
                };
                custom_sections.extend(custom_section.into_iter());
                Ok(slot)
            } else {
                Ok(SectionSlot::Discard)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(sections)
}

fn resolve_symbols<'data>(
    obj: &ParsedInputObject<'data>,
    resources: &ResolutionResources<'data, '_, '_>,
    undefined_symbols_out: &SegQueue<UndefinedSymbol<'data>>,
    definitions_out: &mut [SymbolId],
) -> Result {
    obj.object
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
    obj: &ParsedInputObject<'data>,
    resources: &ResolutionResources<'data, '_, '_>,
    undefined_symbols_out: &SegQueue<UndefinedSymbol<'data>>,
    definitions_out: &mut [SymbolId],
) -> Result {
    obj.object
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

fn resolve_symbol<'data>(
    local_symbol_index: object::SymbolIndex,
    local_symbol: &crate::elf::SymtabEntry,
    definition_out: &mut SymbolId,
    resources: &ResolutionResources<'data, '_, '_>,
    obj: &ParsedInputObject<'data>,
    undefined_symbols_out: &SegQueue<UndefinedSymbol<'data>>,
    is_from_shared_object: bool,
) -> Result {
    // Don't try to resolve symbols that are already defined, e.g. locals and globals that we
    // define. Also don't try to resolve symbol zero - the undefined symbol.
    if !definition_out.is_undefined() || local_symbol_index.0 == 0 {
        return Ok(());
    }

    let name_info = RawSymbolName::parse(obj.object.symbol_name(local_symbol)?);

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
                // Undefined symbols in shared objects don't trigger loading of other objects.
                if !is_from_shared_object {
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

impl std::fmt::Display for ResolvedFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolvedFile::NotLoaded(_) => std::fmt::Display::fmt("<not loaded>", f),
            ResolvedFile::Prelude(_) => std::fmt::Display::fmt("<prelude>", f),
            ResolvedFile::Object(o) => std::fmt::Display::fmt(o, f),
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
            SectionSlot::NoteGnuProperty(_) => {}
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

        /// An absolute value that won't be change depending on load address. This could be a symbol
        /// with an absolute value or an undefined symbol, which needs to always resolve to 0 regardless
        /// of load address.
        const ABSOLUTE = 1 << 1;

        /// The value is from a shared (dynamic) object, so although it may have an address, it
        /// won't be know until runtime. If combined with `ABSOLUTE`, then the symbol isn't actually
        /// defined by any shared object. We'll emit a dynamic relocation for it on a best-effort
        /// basis only. e.g. if there are direct references to it from a read-only section we'll
        /// fill them in as zero.
        const DYNAMIC = 1 << 2;

        /// The value refers to an ifunc. The actual address won't be known until runtime.
        const IFUNC = 1 << 3;

        /// Whether the GOT can be bypassed for this value. Always true for non-symbols. For symbols,
        /// this indicates that the symbol cannot be interposed (overridden at runtime).
        const CAN_BYPASS_GOT = 1 << 4;

        /// We have a version script and the version script says that the symbol should be downgraded to
        /// a local. It's still treated as a global for name lookup purposes, but after that, it becomes
        /// local.
        const DOWNGRADE_TO_LOCAL = 1 << 5;

        /// Set when the value is function. Currently only set for dynamic symbols, since that's all
        /// we need it for.
        const FUNCTION = 1 << 6;
    }
}

impl ValueFlags {
    /// Returns self merged with `other` which should be the flags for the local (possibly
    /// non-canonical symbol definition). Sometimes an object will reference a symbol that it
    /// doesn't define and will mark that symbol as hidden however the object that defines the
    /// symbol gives the symbol default visibility. In this case, we want references in the object
    /// defining it as hidden to be allowed to bypass the GOT/PLT.
    pub(crate) fn merge(&mut self, other: ValueFlags) {
        if other.contains(ValueFlags::CAN_BYPASS_GOT) {
            *self |= ValueFlags::CAN_BYPASS_GOT;
        }
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
