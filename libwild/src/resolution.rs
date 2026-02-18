//! This module resolves symbol references between objects. In the process, it decides which archive
//! entries are needed. We also resolve which output section, if any, each input section should be
//! assigned to.

use crate::LayoutRules;
use crate::alignment::Alignment;
use crate::args::Args;
use crate::bail;
use crate::debug_assert_bail;
use crate::elf::File;
use crate::elf::RawSymbolName;
use crate::elf::SectionHeader;
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
use crate::output_section_id::InitFiniSectionDetail;
use crate::output_section_id::OutputSections;
use crate::output_section_id::SectionName;
use crate::parsing::InternalSymDefInfo;
use crate::parsing::SymbolPlacement;
use crate::part_id;
use crate::part_id::PartId;
use crate::platform::DynamicTagValues as _;
use crate::platform::ObjectFile;
use crate::platform::RawSymbolName as _;
use crate::platform::SectionFlags as _;
use crate::platform::SectionHeader as _;
use crate::platform::SectionType as _;
use crate::platform::Symbol as _;
use crate::platform::VerneedTable as _;
use crate::string_merging::StringMergeSectionExtra;
use crate::string_merging::StringMergeSectionSlot;
use crate::symbol::PreHashedSymbolName;
use crate::symbol::UnversionedSymbolName;
use crate::symbol::VersionedSymbolName;
use crate::symbol_db;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use crate::symbol_db::SymbolStrength;
use crate::symbol_db::Visibility;
use crate::timing_phase;
use crate::value_flags::PerSymbolFlags;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use atomic_take::AtomicTake;
use crossbeam_queue::ArrayQueue;
use crossbeam_queue::SegQueue;
use linker_utils::elf::secnames;
use object::SectionIndex;
use rayon::Scope;
use rayon::iter::IntoParallelIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use std::num::NonZeroU32;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

#[derive(Default)]
pub(crate) struct Resolver<'data> {
    undefined_symbols: Vec<UndefinedSymbol<'data>>,
    pub(crate) resolved_groups: Vec<ResolvedGroup<'data>>,
}

impl<'data> Resolver<'data> {
    /// Resolves undefined symbols. In the process of resolving symbols, we decide which archive
    /// entries to load. Some symbols may not have definitions, in which case we'll note those for
    /// later processing. Can be called multiple times with additional groups having been added to
    /// the SymbolDb in between.
    pub(crate) fn resolve_symbols_and_select_archive_entries(
        &mut self,
        symbol_db: &mut SymbolDb<'data, crate::elf::File<'data>>,
    ) -> Result {
        resolve_symbols_and_select_archive_entries(self, symbol_db)
    }

    /// For all regular objects that we've decided to load, decide what to do with each section.
    /// Canonicalises undefined symbols. Some undefined symbols might be able to become defined if
    /// we can identify them as start/stop symbols for which we found a custom section with the
    /// appropriate name.
    pub(crate) fn resolve_sections_and_canonicalise_undefined(
        mut self,
        symbol_db: &mut SymbolDb<'data, crate::elf::File<'data>>,
        per_symbol_flags: &mut PerSymbolFlags,
        output_sections: &mut OutputSections<'data>,
        layout_rules: &LayoutRules<'data>,
    ) -> Result<Vec<ResolvedGroup<'data>>> {
        timing_phase!("Section resolution");

        resolve_sections(&mut self.resolved_groups, symbol_db, layout_rules)?;

        let mut syn = symbol_db.new_synthetic_symbols_group();

        assign_section_ids(&mut self.resolved_groups, output_sections, symbol_db.args);

        canonicalise_undefined_symbols(
            self.undefined_symbols,
            output_sections,
            &self.resolved_groups,
            symbol_db,
            per_symbol_flags,
            &mut syn,
        );

        self.resolved_groups.push(ResolvedGroup {
            files: vec![ResolvedFile::SyntheticSymbols(syn)],
        });

        Ok(self.resolved_groups)
    }
}

fn resolve_symbols_and_select_archive_entries<'data>(
    resolver: &mut Resolver<'data>,
    symbol_db: &mut SymbolDb<'data, crate::elf::File<'data>>,
) -> Result {
    timing_phase!("Resolve symbols");

    // Note, this is the total number of objects including those that we might have processed in
    // previous calls. This is just an upper bound on how many objects might need to be loaded. We
    // can't just count the objects in the new groups because we might end up loading some of the
    // objects from earlier groups.
    let num_regular_objects = symbol_db.num_regular_objects();
    let num_lto_objects = symbol_db.num_lto_objects();
    if num_regular_objects == 0 && num_lto_objects == 0 {
        bail!("no input files");
    }

    let mut symbol_definitions = symbol_db.take_definitions();
    let mut symbol_definitions_slice: &mut [SymbolId] = symbol_definitions.as_mut();

    let mut definitions_per_group_and_file = Vec::new();
    definitions_per_group_and_file.resize_with(symbol_db.groups.len(), Vec::new);

    let outputs = {
        verbose_timing_phase!("Allocate outputs store");
        Outputs::new(num_regular_objects, num_lto_objects)
    };

    let mut initial_work = Vec::new();

    {
        verbose_timing_phase!("Resolution setup");

        let pre_existing_groups = resolver.resolved_groups.len();
        let new_groups = &symbol_db.groups[pre_existing_groups..];

        for (group, definitions_out_per_file) in resolver
            .resolved_groups
            .iter()
            .zip(&mut definitions_per_group_and_file)
        {
            *definitions_out_per_file = group
                .files
                .iter()
                .map(|file| {
                    let definitions = symbol_definitions_slice
                        .split_off_mut(..file.symbol_id_range().len())
                        .unwrap();

                    if matches!(file, ResolvedFile::NotLoaded(_)) {
                        AtomicTake::new(definitions)
                    } else {
                        AtomicTake::empty()
                    }
                })
                .collect();
        }

        resolver.resolved_groups.extend(
            new_groups
                .iter()
                .zip(&mut definitions_per_group_and_file[pre_existing_groups..])
                .map(|(group, definitions_out_per_file)| {
                    resolve_group(
                        group,
                        &mut initial_work,
                        definitions_out_per_file,
                        &mut symbol_definitions_slice,
                        symbol_db,
                        &outputs,
                    )
                }),
        );
    };

    let resources = ResolutionResources {
        definitions_per_file: &definitions_per_group_and_file,
        symbol_db,
        outputs: &outputs,
    };

    rayon::in_place_scope(|scope| {
        initial_work.into_par_iter().for_each(|work_item| {
            process_object(work_item, &resources, scope);
        });
    });

    {
        verbose_timing_phase!("Drop definitions_per_group_and_file");
        drop(definitions_per_group_and_file);
    }

    symbol_db.restore_definitions(symbol_definitions);

    if let Some(e) = outputs.errors.pop() {
        return Err(e);
    }

    verbose_timing_phase!("Gather loaded objects");

    for obj in outputs.loaded {
        let file_id = match &obj {
            ResolvedFile::Object(o) => o.common.file_id,
            ResolvedFile::Dynamic(o) => o.common.file_id,
            _ => unreachable!(),
        };
        resolver.resolved_groups[file_id.group()].files[file_id.file()] = obj;
    }

    #[cfg(feature = "plugins")]
    for obj in outputs.loaded_lto_objects {
        let file_id = obj.file_id;
        resolver.resolved_groups[file_id.group()].files[file_id.file()] =
            ResolvedFile::LtoInput(obj);
    }

    resolver.undefined_symbols.extend(outputs.undefined_symbols);

    Ok(())
}

fn resolve_group<'data, 'definitions>(
    group: &Group<'data, crate::elf::File<'data>>,
    initial_work_out: &mut Vec<LoadObjectSymbolsRequest<'definitions>>,
    definitions_out_per_file: &mut Vec<AtomicTake<&'definitions mut [SymbolId]>>,
    symbol_definitions_slice: &mut &'definitions mut [SymbolId],
    symbol_db: &SymbolDb<'data, crate::elf::File<'data>>,
    outputs: &Outputs<'data>,
) -> ResolvedGroup<'data> {
    match group {
        Group::Prelude(prelude) => {
            let definitions_out = symbol_definitions_slice
                .split_off_mut(..prelude.symbol_definitions.len())
                .unwrap();

            work_items_do(
                PRELUDE_FILE_ID,
                definitions_out,
                symbol_db,
                outputs,
                |work_item| {
                    initial_work_out.push(work_item);
                },
            );

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
                    let definitions_out = symbol_definitions_slice
                        .split_off_mut(..s.symbol_id_range.len())
                        .unwrap();

                    if s.is_optional() {
                        definitions_out_per_file.push(AtomicTake::new(definitions_out));
                    } else {
                        work_items_do(
                            s.file_id,
                            definitions_out,
                            symbol_db,
                            outputs,
                            |work_item| {
                                initial_work_out.push(work_item);
                            },
                        );
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
                        input: s.parsed.input,
                        file_id: s.file_id,
                        symbol_id_range: s.symbol_id_range,
                        // TODO: Consider alternative to cloning this.
                        symbol_definitions: s.parsed.symbol_defs.clone(),
                    })
                })
                .collect();

            ResolvedGroup { files }
        }
        Group::SyntheticSymbols(syn) => {
            definitions_out_per_file.push(AtomicTake::empty());

            ResolvedGroup {
                files: vec![ResolvedFile::SyntheticSymbols(ResolvedSyntheticSymbols {
                    file_id: syn.file_id,
                    start_symbol_id: syn.symbol_id_range.start(),
                    symbol_definitions: Vec::new(),
                })],
            }
        }
        #[cfg(feature = "plugins")]
        Group::LtoInputs(lto_objects) => ResolvedGroup {
            files: lto_objects
                .iter()
                .map(|o| {
                    let definitions_out = symbol_definitions_slice
                        .split_off_mut(..o.symbol_id_range.len())
                        .unwrap();

                    if o.is_optional() {
                        definitions_out_per_file.push(AtomicTake::new(definitions_out));
                    } else {
                        work_items_do(
                            o.file_id,
                            definitions_out,
                            symbol_db,
                            outputs,
                            |work_item| {
                                initial_work_out.push(work_item);
                            },
                        );
                        definitions_out_per_file.push(AtomicTake::empty());
                    }

                    ResolvedFile::NotLoaded(NotLoaded {
                        symbol_id_range: o.symbol_id_range,
                    })
                })
                .collect(),
        },
    }
}

fn resolve_sections<'data>(
    groups: &mut [ResolvedGroup<'data>],
    symbol_db: &SymbolDb<'data, crate::elf::File<'data>>,
    layout_rules: &LayoutRules<'data>,
) -> Result {
    timing_phase!("Resolve sections");

    let loaded_metrics: LoadedMetrics = Default::default();
    let herd = symbol_db.herd;

    groups.par_iter_mut().try_for_each_init(
        || herd.get(),
        |allocator, group| -> Result {
            verbose_timing_phase!("Resolve group sections");

            for file in &mut group.files {
                let ResolvedFile::Object(obj) = file else {
                    continue;
                };

                obj.sections = resolve_sections_for_object(
                    obj,
                    symbol_db.args,
                    allocator,
                    &loaded_metrics,
                    &layout_rules.section_rules,
                )?;

                obj.relocations = obj.common.object.parse_relocations()?;
            }
            Ok(())
        },
    )?;

    loaded_metrics.log();

    Ok(())
}

const MAX_SYMBOLS_PER_WORK_ITEM: usize = 5000;

/// A request to load a chunk of symbols from an object.
struct LoadObjectSymbolsRequest<'definitions> {
    /// The ID of the object to load.
    file_id: FileId,

    symbol_start_offset: usize,

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

struct ResolutionResources<'data, 'scope> {
    definitions_per_file: &'scope Vec<Vec<AtomicTake<&'scope mut [SymbolId]>>>,
    symbol_db: &'scope SymbolDb<'data, crate::elf::File<'data>>,
    outputs: &'scope Outputs<'data>,
}

impl<'scope> ResolutionResources<'_, 'scope> {
    /// Request loading of `file_id` if it hasn't already been requested.
    #[inline(always)]
    fn try_request_file_id(&'scope self, file_id: FileId, scope: &Scope<'scope>) {
        let definitions_group = &self.definitions_per_file[file_id.group()];

        let Some(atomic_take) = &definitions_group.get(file_id.file()) else {
            // A group from a previous resolution batch. Assume that the relevant file was already
            // loaded.
            return;
        };

        // Do a read before we call `take`. Reads are cheaper, so this is an optimisation that
        // reduces the need for exclusive access to the cache line.
        if atomic_take.is_taken() {
            // The definitions have previously been taken indicating that this file has already been
            // processed, nothing more to do.
            return;
        }

        let Some(definitions_out) = atomic_take.take() else {
            // Another thread just beat us to it.
            return;
        };

        work_items_do(
            file_id,
            definitions_out,
            self.symbol_db,
            self.outputs,
            |work_item| {
                scope.spawn(|scope| {
                    process_object(work_item, self, scope);
                });
            },
        );
    }

    fn handle_result(&self, result: Result) {
        if let Err(error) = result {
            let _ = self.outputs.errors.push(error);
        }
    }
}

fn work_items_do<'definitions, 'data>(
    file_id: FileId,
    mut definitions_out: &'definitions mut [SymbolId],
    symbol_db: &SymbolDb<'data, crate::elf::File<'data>>,
    outputs: &Outputs<'data>,
    mut request_callback: impl FnMut(LoadObjectSymbolsRequest<'definitions>),
) {
    match &symbol_db.groups[file_id.group()] {
        Group::Objects(parsed_input_objects) => {
            let obj = &parsed_input_objects[file_id.file()];
            let common = ResolvedCommon::new(obj);
            let resolved_object =
                if let Some(dynamic_tag_values) = obj.parsed.object.dynamic_tag_values() {
                    ResolvedFile::Dynamic(ResolvedDynamic::new(common, dynamic_tag_values))
                } else {
                    ResolvedFile::Object(ResolvedObject::new(common))
                };
            // Push won't fail because we allocated enough space for all the objects.
            outputs.loaded.push(resolved_object).unwrap();
        }
        #[cfg(feature = "plugins")]
        Group::LtoInputs(lto_objects) => {
            let obj = &lto_objects[file_id.file()];
            // Push won't fail because we allocated enough space for all the LTO objects.
            outputs
                .loaded_lto_objects
                .push(ResolvedLtoInput {
                    file_id: obj.file_id,
                    symbol_id_range: obj.symbol_id_range,
                })
                .unwrap();

            request_callback(LoadObjectSymbolsRequest {
                file_id,
                symbol_start_offset: 0,
                definitions_out,
            });
            return;
        }
        _ => {}
    }

    let chunk_size = match &symbol_db.groups[file_id.group()] {
        Group::Objects(_) => MAX_SYMBOLS_PER_WORK_ITEM,
        _ => definitions_out.len(),
    };

    let mut symbol_start_offset = 0;
    loop {
        let len = chunk_size.min(definitions_out.len());
        let chunk_definitions_out = definitions_out.split_off_mut(..len).unwrap();

        let work_item = LoadObjectSymbolsRequest {
            file_id,
            definitions_out: chunk_definitions_out,
            symbol_start_offset,
        };
        request_callback(work_item);

        symbol_start_offset += len;
        if definitions_out.is_empty() {
            break;
        }
    }
}

#[derive(Debug)]
pub(crate) struct ResolvedGroup<'data> {
    pub(crate) files: Vec<ResolvedFile<'data>>,
}

#[derive(Debug)]
pub(crate) enum ResolvedFile<'data> {
    NotLoaded(NotLoaded),
    Prelude(ResolvedPrelude<'data>),
    Object(ResolvedObject<'data>),
    Dynamic(ResolvedDynamic<'data>),
    LinkerScript(ResolvedLinkerScript<'data>),
    SyntheticSymbols(ResolvedSyntheticSymbols<'data>),
    #[cfg(feature = "plugins")]
    LtoInput(ResolvedLtoInput),
}

#[derive(Debug)]
pub(crate) struct NotLoaded {
    pub(crate) symbol_id_range: SymbolIdRange,
}

/// A section, but where we may or may not yet have decided to load it.
#[derive(Debug, Clone, Copy)]
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

#[derive(Debug, Clone, Copy)]
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
#[derive(Debug, Clone, Copy)]
pub(crate) struct FrameIndex(NonZeroU32);

#[derive(Debug, Clone)]
pub(crate) struct ResolvedPrelude<'data> {
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo<'data>>,
}

/// Resolved state common to dynamic and regular objects.
#[derive(Debug)]
pub(crate) struct ResolvedCommon<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) object: &'data File<'data>,
    pub(crate) file_id: FileId,
    pub(crate) symbol_id_range: SymbolIdRange,
}

#[derive(Debug)]
pub(crate) struct ResolvedObject<'data> {
    pub(crate) common: ResolvedCommon<'data>,

    pub(crate) sections: Vec<SectionSlot>,
    pub(crate) relocations: object::read::elf::RelocationSections,

    pub(crate) string_merge_extras:
        Vec<StringMergeSectionExtra<'data, linker_utils::elf::SectionFlags>>,

    /// Details about each custom section that is defined in this object.
    custom_sections: Vec<CustomSectionDetails<'data>>,

    init_fini_sections: Vec<InitFiniSectionDetail>,
}

#[derive(Debug)]
pub(crate) struct ResolvedDynamic<'data> {
    pub(crate) common: ResolvedCommon<'data>,
    dynamic_tag_values: crate::elf::DynamicTagValues<'data>,
}

#[derive(Debug)]
pub(crate) struct ResolvedLinkerScript<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) file_id: FileId,
    pub(crate) symbol_id_range: SymbolIdRange,
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo<'data>>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedSyntheticSymbols<'data> {
    pub(crate) file_id: FileId,
    pub(crate) start_symbol_id: SymbolId,
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo<'data>>,
}

#[cfg(feature = "plugins")]
#[derive(Debug, Clone)]
pub(crate) struct ResolvedLtoInput {
    pub(crate) file_id: FileId,
    pub(crate) symbol_id_range: SymbolIdRange,
}

fn assign_section_ids<'data>(
    resolved: &mut [ResolvedGroup<'data>],
    output_sections: &mut OutputSections<'data>,
    args: &Args,
) {
    timing_phase!("Assign section IDs");

    for group in resolved {
        for file in &mut group.files {
            if let ResolvedFile::Object(s) = file {
                output_sections.add_sections(&s.custom_sections, s.sections.as_mut_slice(), args);
                apply_init_fini_secondaries(
                    &s.init_fini_sections,
                    s.sections.as_mut_slice(),
                    output_sections,
                );
            }
        }
    }
}

fn parse_priority_suffix(suffix: &[u8]) -> Option<u16> {
    if suffix.is_empty() || !suffix.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let value = core::str::from_utf8(suffix).ok()?.parse::<u32>().ok()?;
    Some(u16::try_from(value).unwrap_or(u16::MAX))
}

fn init_fini_priority(name: &[u8]) -> Option<u16> {
    if name == secnames::INIT_ARRAY_SECTION_NAME || name == secnames::FINI_ARRAY_SECTION_NAME {
        return Some(u16::MAX);
    }

    if let Some(rest) = name.strip_prefix(b".init_array.") {
        return parse_priority_suffix(rest);
    }

    if let Some(rest) = name.strip_prefix(b".fini_array.") {
        return parse_priority_suffix(rest);
    }

    // .ctors and .dtors without suffix have the same priority as .init_array/.fini_array
    if name == secnames::CTORS_SECTION_NAME || name == secnames::DTORS_SECTION_NAME {
        return Some(u16::MAX);
    }

    // .ctors uses descending order (65535 = lowest priority, 0 = highest)
    // while .init_array uses ascending order (0 = highest priority, 65535 = lowest)
    if let Some(rest) = name.strip_prefix(b".ctors.") {
        return parse_priority_suffix(rest).map(|p| u16::MAX.saturating_sub(p));
    }

    if let Some(rest) = name.strip_prefix(b".dtors.") {
        return parse_priority_suffix(rest).map(|p| u16::MAX.saturating_sub(p));
    }

    None
}

struct Outputs<'data> {
    /// Where we put objects once we've loaded them.
    loaded: ArrayQueue<ResolvedFile<'data>>,

    #[cfg(feature = "plugins")]
    loaded_lto_objects: ArrayQueue<ResolvedLtoInput>,

    /// Any errors that we encountered.
    errors: ArrayQueue<Error>,

    undefined_symbols: SegQueue<UndefinedSymbol<'data>>,
}

impl Outputs<'_> {
    #[allow(unused_variables)]
    fn new(num_regular_objects: usize, num_lto_objects: usize) -> Self {
        Self {
            loaded: ArrayQueue::new(num_regular_objects.max(1)),
            #[cfg(feature = "plugins")]
            loaded_lto_objects: ArrayQueue::new(num_lto_objects.max(1)),
            errors: ArrayQueue::new(1),
            undefined_symbols: SegQueue::new(),
        }
    }
}

fn process_object<'scope, 'data: 'scope, 'definitions>(
    work_item: LoadObjectSymbolsRequest<'definitions>,
    resources: &'scope ResolutionResources<'data, 'scope>,
    scope: &Scope<'scope>,
) {
    let file_id = work_item.file_id;
    let definitions_out = work_item.definitions_out;

    match &resources.symbol_db.groups[file_id.group()] {
        Group::Prelude(prelude) => {
            verbose_timing_phase!("Resolve prelude symbols");

            load_prelude(prelude, definitions_out, resources, scope);
        }
        Group::Objects(parsed_input_objects) => {
            verbose_timing_phase!("Resolve object symbols");

            let obj = &parsed_input_objects[file_id.file()];

            resources.handle_result(
                resolve_symbols(
                    obj,
                    resources,
                    work_item.symbol_start_offset,
                    definitions_out,
                    scope,
                )
                .with_context(|| format!("Failed to resolve symbols in {obj}")),
            );
        }
        Group::LinkerScripts(_) => {}
        Group::SyntheticSymbols(_) => {}
        #[cfg(feature = "plugins")]
        Group::LtoInputs(objects) => {
            let obj = &objects[file_id.file()];
            resources.handle_result(
                resolve_lto_symbols(obj, resources, definitions_out, scope)
                    .with_context(|| format!("Failed to resolve symbols in {obj}")),
            );
        }
    }
}

#[cfg(feature = "plugins")]
fn resolve_lto_symbols<'data, 'scope>(
    obj: &crate::linker_plugins::LtoInput<'data>,
    resources: &'scope ResolutionResources<'data, 'scope>,
    definitions_out: &mut [SymbolId],
    scope: &Scope<'scope>,
) -> Result {
    obj.symbols
        .iter()
        .enumerate()
        .zip(definitions_out)
        .try_for_each(
            |((local_symbol_index, local_symbol), definition)| -> Result {
                if !local_symbol.is_definition() {
                    let mut name_info = RawSymbolName::parse(local_symbol.name.bytes());
                    if let Some(version) = local_symbol.version {
                        name_info.version_name = Some(version);
                    }

                    let symbol_attributes = SymbolAttributes {
                        name_info,
                        is_local: false,
                        default_visibility: local_symbol.visibility == object::elf::STV_DEFAULT,
                        is_weak: local_symbol.kind
                            == Some(crate::linker_plugins::SymbolKind::WeakUndef),
                    };

                    resolve_symbol(
                        obj.symbol_id_range.offset_to_id(local_symbol_index),
                        &symbol_attributes,
                        definition,
                        resources,
                        false,
                        obj.file_id,
                        scope,
                    )?;
                }

                Ok(())
            },
        )
}

struct UndefinedSymbol<'data> {
    /// If we have a file ID here and that file is loaded, then the symbol is actually defined and
    /// this record can be ignored.
    ignore_if_loaded: Option<FileId>,
    name: PreHashedSymbolName<'data>,
    symbol_id: SymbolId,
}

fn load_prelude<'scope>(
    prelude: &crate::parsing::Prelude,
    definitions_out: &mut [SymbolId],
    resources: &'scope ResolutionResources<'_, 'scope>,
    scope: &Scope<'scope>,
) {
    // The start symbol could be defined within an archive entry. If it is, then we need to load
    // it. We don't currently store the resulting SymbolId, but instead look it up again during
    // layout.
    load_symbol_named(
        resources,
        &mut SymbolId::undefined(),
        resources.symbol_db.entry_symbol_name(),
        scope,
    );

    // Try to resolve any symbols that the user requested be undefined (e.g. via --undefined). If an
    // object defines such a symbol, request that the object be loaded. Also, point our undefined
    // symbol record to the definition.
    for (def_info, definition_out) in prelude.symbol_definitions.iter().zip(definitions_out) {
        match def_info.placement {
            SymbolPlacement::ForceUndefined | SymbolPlacement::DefsymSymbol(_, _) => {
                load_symbol_named(resources, definition_out, def_info.name, scope);
            }
            _ => {}
        }
    }
}

fn load_symbol_named<'scope>(
    resources: &'scope ResolutionResources<'_, 'scope>,
    definition_out: &mut SymbolId,
    name: &[u8],
    scope: &Scope<'scope>,
) {
    if let Some(symbol_id) = resources
        .symbol_db
        .get_unversioned(&UnversionedSymbolName::prehashed(name))
    {
        *definition_out = symbol_id;

        let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        resources.try_request_file_id(symbol_file_id, scope);
    }
}

/// Where there are multiple references to undefined symbols with the same name, pick one reference
/// as the canonical one to which we'll refer. Where undefined symbols can be resolved to
/// __start/__stop symbols that refer to the start or stop of a custom section, collect that
/// information up and put it into `custom_start_stop_defs`.
fn canonicalise_undefined_symbols<'data>(
    mut undefined_symbols: Vec<UndefinedSymbol<'data>>,
    output_sections: &OutputSections,
    groups: &[ResolvedGroup<'data>],
    symbol_db: &mut SymbolDb<'data, crate::elf::File<'data>>,
    per_symbol_flags: &mut PerSymbolFlags,
    custom_start_stop_defs: &mut ResolvedSyntheticSymbols<'data>,
) {
    timing_phase!("Canonicalise undefined symbols");

    let mut name_to_id: PassThroughHashMap<UnversionedSymbolName<'data>, SymbolId> =
        Default::default();

    let mut versioned_name_to_id: PassThroughHashMap<VersionedSymbolName<'data>, SymbolId> =
        Default::default();

    // Sort by symbol ID to ensure deterministic behaviour. We sort in reverse order so that LTO
    // outputs get higher priority than LTO inputs. This means that the canonical symbol ID for any
    // given name will be the one for the last file that refers to that symbol.
    undefined_symbols.sort_by_key(|u| usize::MAX - u.symbol_id.as_usize());

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
                    hashbrown::hash_map::Entry::Vacant(entry) => {
                        let symbol_id = allocate_start_stop_symbol_id(
                            pre_hashed,
                            symbol_db,
                            per_symbol_flags,
                            custom_start_stop_defs,
                            output_sections,
                        );

                        // We either make our undefined symbol dynamic, allowing the possibility
                        // that it might end up being defined at runtime, or we make it
                        // non-interposable, which means it'll remain null and even if it ends up
                        // defined at runtime, we won't use that definition. If the symbol doesn't
                        // have default visibility, then we make it non-interposable. If we're
                        // building a shared object, we always make the symbol dynamic. If we're
                        // building a statically linked executable, then we always make it
                        // non-interposable. If we're building a regular, dynamically linked
                        // executable, then we make it dynamic if the symbol is weak and otherwise
                        // make it non-interposable. That last case, a non-weak, default-visibility,
                        // undefined symbol in an executable is generally a link error, however if
                        // the flag --warn-unresolved-symbols is passed, then it won't be. Linker
                        // behaviour differs in this case. GNU ld makes the symbol non-interposable,
                        // while lld makes it dynamic. We match GNU ld in this case.
                        if symbol_id.is_none() {
                            let output_kind = symbol_db.output_kind;
                            let visibility = symbol_db.input_symbol_visibility(undefined.symbol_id);

                            if visibility == Visibility::Default
                                && (output_kind.is_shared_object()
                                    || (!output_kind.is_static_executable()
                                        && symbol_db.symbol_strength(undefined.symbol_id, groups)
                                            == SymbolStrength::Weak))
                            {
                                per_symbol_flags.set_flag(undefined.symbol_id, ValueFlags::DYNAMIC);
                            } else {
                                per_symbol_flags
                                    .set_flag(undefined.symbol_id, ValueFlags::NON_INTERPOSABLE);
                            }
                        }

                        // If the symbol isn't a start/stop symbol, then assign responsibility for
                        // the symbol to the first object that referenced
                        // it. This lets us have PLT/GOT entries
                        // for the symbol if they're needed.
                        let symbol_id = symbol_id.unwrap_or(undefined.symbol_id);
                        entry.insert(symbol_id);
                        symbol_db.replace_definition(undefined.symbol_id, symbol_id);
                    }
                    hashbrown::hash_map::Entry::Occupied(entry) => {
                        symbol_db.replace_definition(undefined.symbol_id, *entry.get());
                    }
                }
            }
            PreHashedSymbolName::Versioned(pre_hashed) => {
                match versioned_name_to_id.entry(pre_hashed) {
                    hashbrown::hash_map::Entry::Vacant(entry) => {
                        entry.insert(undefined.symbol_id);
                    }
                    hashbrown::hash_map::Entry::Occupied(entry) => {
                        symbol_db.replace_definition(undefined.symbol_id, *entry.get());
                    }
                }
            }
        }
    }
}

fn allocate_start_stop_symbol_id<'data>(
    name: PreHashed<UnversionedSymbolName<'data>>,
    symbol_db: &mut SymbolDb<'data, crate::elf::File<'data>>,
    per_symbol_flags: &mut PerSymbolFlags,
    custom_start_stop_defs: &mut ResolvedSyntheticSymbols<'data>,
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

    let def_info = if is_start {
        InternalSymDefInfo::notype(SymbolPlacement::SectionStart(section_id), name.bytes())
    } else {
        InternalSymDefInfo::notype(SymbolPlacement::SectionEnd(section_id), name.bytes())
    };

    let symbol_id = symbol_db.add_synthetic_symbol(per_symbol_flags, name, custom_start_stop_defs);

    custom_start_stop_defs.symbol_definitions.push(def_info);

    Some(symbol_id)
}

impl<'data> ResolvedCommon<'data> {
    fn new(obj: &'data SequencedInputObject<'data, crate::elf::File<'data>>) -> Self {
        Self {
            input: obj.parsed.input,
            object: &obj.parsed.object,
            file_id: obj.file_id,
            symbol_id_range: obj.symbol_id_range,
        }
    }

    pub(crate) fn symbol_strength(&self, symbol_id: SymbolId) -> SymbolStrength {
        let local_index = symbol_id.to_input(self.symbol_id_range);
        let Ok(obj_symbol) = self.object.symbol(local_index) else {
            // Errors from this function should have been reported elsewhere.
            return SymbolStrength::Undefined;
        };
        if obj_symbol.is_weak() {
            SymbolStrength::Weak
        } else if obj_symbol.is_common() {
            SymbolStrength::Common(obj_symbol.size())
        } else if obj_symbol.is_gnu_unique() {
            SymbolStrength::GnuUnique
        } else {
            SymbolStrength::Strong
        }
    }
}

fn apply_init_fini_secondaries<'data>(
    details: &[InitFiniSectionDetail],
    sections: &mut [SectionSlot],
    output_sections: &mut OutputSections<'data>,
) {
    for d in details {
        let Some(slot) = sections.get_mut(d.index as usize) else {
            continue;
        };

        let unloaded = match slot {
            SectionSlot::Unloaded(u) | SectionSlot::MustLoad(u) => u,
            _ => continue,
        };

        let sid =
            output_sections.get_or_create_init_fini_secondary(d.primary, d.priority, d.alignment);
        unloaded.part_id = sid.part_id_with_alignment(d.alignment);
    }
}

impl<'data> ResolvedObject<'data> {
    fn new(common: ResolvedCommon<'data>) -> Self {
        Self {
            common,
            // We'll fill this the rest during section resolution.
            sections: Default::default(),
            relocations: Default::default(),
            string_merge_extras: Default::default(),
            custom_sections: Default::default(),
            init_fini_sections: Default::default(),
        }
    }
}

impl<'data> ResolvedDynamic<'data> {
    fn new(
        common: ResolvedCommon<'data>,
        dynamic_tag_values: crate::elf::DynamicTagValues<'data>,
    ) -> Self {
        Self {
            common,
            dynamic_tag_values,
        }
    }

    pub(crate) fn lib_name(&self) -> &'data [u8] {
        self.dynamic_tag_values.lib_name(&self.common.input)
    }
}

fn resolve_sections_for_object<'data>(
    obj: &mut ResolvedObject<'data>,
    args: &Args,
    allocator: &bumpalo_herd::Member<'data>,
    loaded_metrics: &LoadedMetrics,
    rules: &SectionRules,
) -> Result<Vec<SectionSlot>> {
    // Note, we build up the collection with push rather than collect because at the time of
    // writing, object's `SectionTable::enumerate` isn't an exact-size iterator, so using collect
    // would result in resizing.
    let mut sections = Vec::with_capacity(obj.common.object.num_sections());
    for (input_section_index, input_section) in obj.common.object.enumerate_sections() {
        sections.push(resolve_section(
            input_section_index,
            input_section,
            obj,
            args,
            allocator,
            loaded_metrics,
            rules,
        )?);
    }
    Ok(sections)
}

#[inline(always)]
fn resolve_section<'data>(
    input_section_index: SectionIndex,
    input_section: &SectionHeader,
    obj: &mut ResolvedObject<'data>,
    args: &Args,
    allocator: &bumpalo_herd::Member<'data>,
    loaded_metrics: &LoadedMetrics,
    rules: &SectionRules,
) -> Result<SectionSlot> {
    let section_name = obj
        .common
        .object
        .section_name(input_section)
        .unwrap_or_default();

    if section_name.starts_with(secnames::GNU_LTO_SYMTAB_PREFIX.as_bytes()) {
        if cfg!(feature = "plugins") {
            bail!("Found GCC LTO input that we didn't supply to linker plugin");
        }
        return Err(symbol_db::linker_plugin_disabled_error());
    }

    let section_flags = input_section.flags();
    let raw_alignment = obj.common.object.section_alignment(input_section)?;
    let alignment = Alignment::new(raw_alignment.max(1))?;
    let should_merge_sections = part_id::should_merge_sections(section_flags, raw_alignment, args);

    let mut unloaded_section;
    let mut is_debug_info = false;
    let section_type = input_section.section_type();
    let mut must_load = section_flags.should_retain() || section_type.is_note();

    match rules.lookup(section_name, section_flags, section_type) {
        SectionRuleOutcome::Section(output_info) => {
            let part_id = if output_info.section_id.is_regular() {
                output_info.section_id.part_id_with_alignment(alignment)
            } else {
                output_info.section_id.base_part_id()
            };

            must_load |= output_info.must_keep;

            unloaded_section = UnloadedSection::new(part_id);
        }
        SectionRuleOutcome::SortedSection(output_info) => {
            let part_id = if output_info.section_id.is_regular() {
                output_info.section_id.part_id_with_alignment(alignment)
            } else {
                output_info.section_id.base_part_id()
            };
            if let Some(priority) = init_fini_priority(section_name) {
                obj.init_fini_sections.push(InitFiniSectionDetail {
                    index: input_section_index.0 as u32,
                    primary: output_info.section_id,
                    priority,
                    alignment,
                });
            }

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
            if args.strip_debug() && !section_flags.is_alloc() {
                return Ok(SectionSlot::Discard);
            }

            is_debug_info = !section_flags.is_alloc();

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

        obj.custom_sections.push(custom_section);
    }

    let slot = if should_merge_sections {
        let section_data =
            obj.common
                .object
                .section_data(input_section, allocator, loaded_metrics)?;
        let section_flags = input_section.flags();

        if section_data.is_empty() {
            SectionSlot::Discard
        } else {
            obj.string_merge_extras.push(StringMergeSectionExtra {
                index: input_section_index,
                section_data,
                section_flags,
            });

            SectionSlot::MergeStrings(StringMergeSectionSlot::new(unloaded_section.part_id))
        }
    } else if is_debug_info {
        SectionSlot::UnloadedDebugInfo(part_id::CUSTOM_PLACEHOLDER)
    } else if must_load {
        SectionSlot::MustLoad(unloaded_section)
    } else {
        SectionSlot::Unloaded(unloaded_section)
    };

    Ok(slot)
}

fn resolve_symbols<'data, 'scope>(
    obj: &SequencedInputObject<'data, crate::elf::File<'data>>,
    resources: &'scope ResolutionResources<'data, 'scope>,
    start_symbol_offset: usize,
    definitions_out: &mut [SymbolId],
    scope: &Scope<'scope>,
) -> Result {
    let verneed = obj.parsed.object.verneed_table()?;

    obj.parsed.object.symbols()[start_symbol_offset..]
        .iter()
        .enumerate()
        .zip(definitions_out)
        .try_for_each(
            |((local_symbol_index, local_symbol), definition)| -> Result {
                // Don't try to resolve symbols that are already defined, e.g. locals and globals
                // that we define. Also don't try to resolve symbol zero - the undefined symbol.
                // Hidden symbols exported from shared objects don't make sense, so we skip
                // resolving them as well.
                if !definition.is_undefined()
                    || start_symbol_offset + local_symbol_index == 0
                    || (obj.is_dynamic() && local_symbol.is_hidden())
                {
                    return Ok(());
                }

                let name_bytes = obj.parsed.object.symbol_name(local_symbol)?;

                let name_info = if let Some(version_name) =
                    verneed.version_name(object::SymbolIndex(local_symbol_index))
                {
                    RawSymbolName {
                        name: name_bytes,
                        version_name: Some(version_name),
                        is_default: false,
                    }
                } else {
                    RawSymbolName::parse(name_bytes)
                };

                let symbol_attributes = SymbolAttributes {
                    name_info,
                    is_local: local_symbol.is_local(),
                    default_visibility: local_symbol.is_interposable(),
                    is_weak: local_symbol.is_weak(),
                };

                resolve_symbol(
                    obj.symbol_id_range
                        .offset_to_id(start_symbol_offset + local_symbol_index),
                    &symbol_attributes,
                    definition,
                    resources,
                    obj.is_dynamic(),
                    obj.file_id,
                    scope,
                )
            },
        )
}

#[derive(Debug)]
struct SymbolAttributes<'data> {
    is_local: bool,
    default_visibility: bool,
    is_weak: bool,
    name_info: RawSymbolName<'data>,
}

#[inline(always)]
fn resolve_symbol<'data, 'scope>(
    local_symbol_id: SymbolId,
    local_symbol_attributes: &SymbolAttributes<'data>,
    definition_out: &mut SymbolId,
    resources: &'scope ResolutionResources<'data, 'scope>,
    is_dynamic: bool,
    file_id: FileId,
    scope: &Scope<'scope>,
) -> Result {
    debug_assert_bail!(
        !local_symbol_attributes.is_local,
        "Only globals should be undefined, found symbol `{}` ({local_symbol_id})",
        local_symbol_attributes.name_info,
    );

    let prehashed_name = PreHashedSymbolName::from_raw(&local_symbol_attributes.name_info);

    // Only default-visibility symbols can reference symbols from shared objects.
    let allow_dynamic = local_symbol_attributes.default_visibility;

    match resources.symbol_db.get(&prehashed_name, allow_dynamic) {
        Some(symbol_id) => {
            *definition_out = symbol_id;
            let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);

            if symbol_file_id != file_id && !local_symbol_attributes.is_weak {
                // Undefined symbols in shared objects should actually activate as-needed shared
                // objects, however the rules for whether this should result in a DT_NEEDED entry
                // are kind of subtle, so for now, we don't activate shared objects from shared
                // objects. See
                // https://github.com/davidlattimore/wild/issues/930#issuecomment-3007027924 for
                // more details. TODO: Fix this.
                if !is_dynamic || !resources.symbol_db.file(symbol_file_id).is_dynamic() {
                    resources.try_request_file_id(symbol_file_id, scope);
                }
            } else if symbol_file_id != PRELUDE_FILE_ID {
                // The symbol is weak and we can't be sure that the file that defined it will end up
                // being loaded, so the symbol might actually be undefined. Register it as an
                // undefined symbol then later when we handle undefined symbols, we'll check if the
                // file got loaded. TODO: If the file is a non-archived object, or possibly even if
                // it's an archived object that we've already decided to load, then we could skip
                // this.
                resources.outputs.undefined_symbols.push(UndefinedSymbol {
                    ignore_if_loaded: Some(symbol_file_id),
                    name: prehashed_name,
                    symbol_id: local_symbol_id,
                });
            }
        }
        None => {
            resources.outputs.undefined_symbols.push(UndefinedSymbol {
                ignore_if_loaded: None,
                name: prehashed_name,
                symbol_id: local_symbol_id,
            });
        }
    }
    Ok(())
}

impl std::fmt::Display for ResolvedObject<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.common.input, f)
    }
}

impl std::fmt::Display for ResolvedDynamic<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.common.input, f)
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
            ResolvedFile::Dynamic(o) => std::fmt::Display::fmt(o, f),
            ResolvedFile::LinkerScript(o) => std::fmt::Display::fmt(o, f),
            ResolvedFile::SyntheticSymbols(_) => std::fmt::Display::fmt("<synthetic>", f),
            #[cfg(feature = "plugins")]
            ResolvedFile::LtoInput(_) => std::fmt::Display::fmt("<lto object>", f),
        }
    }
}

impl SectionSlot {
    pub(crate) fn is_loaded(&self) -> bool {
        !matches!(self, SectionSlot::Discard | SectionSlot::Unloaded(..))
    }

    pub(crate) fn set_part_id(&mut self, part_id: PartId) {
        match self {
            SectionSlot::Unloaded(section) => section.part_id = part_id,
            SectionSlot::MustLoad(section) => section.part_id = part_id,
            SectionSlot::Loaded(section) => section.part_id = part_id,
            SectionSlot::EhFrameData(_) => todo!(),
            SectionSlot::MergeStrings(section) => section.part_id = part_id,
            SectionSlot::UnloadedDebugInfo(out) => *out = part_id,
            SectionSlot::LoadedDebugInfo(section) => section.part_id = part_id,
            SectionSlot::Discard
            | SectionSlot::NoteGnuProperty(_)
            | SectionSlot::RiscvVAttributes(_) => {}
        }
    }

    pub(crate) fn unloaded_mut(&mut self) -> Option<&mut UnloadedSection> {
        match self {
            SectionSlot::Unloaded(unloaded) | SectionSlot::MustLoad(unloaded) => Some(unloaded),
            _ => None,
        }
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

impl ResolvedFile<'_> {
    fn symbol_id_range(&self) -> SymbolIdRange {
        match self {
            ResolvedFile::NotLoaded(s) => s.symbol_id_range,
            ResolvedFile::Prelude(s) => s.symbol_id_range(),
            ResolvedFile::Object(s) => s.common.symbol_id_range,
            ResolvedFile::Dynamic(s) => s.common.symbol_id_range,
            ResolvedFile::LinkerScript(s) => s.symbol_id_range,
            ResolvedFile::SyntheticSymbols(s) => s.symbol_id_range(),
            #[cfg(feature = "plugins")]
            ResolvedFile::LtoInput(s) => s.symbol_id_range,
        }
    }
}

impl ResolvedPrelude<'_> {
    fn symbol_id_range(&self) -> SymbolIdRange {
        SymbolIdRange::input(SymbolId::undefined(), self.symbol_definitions.len())
    }
}

impl ResolvedSyntheticSymbols<'_> {
    fn symbol_id_range(&self) -> SymbolIdRange {
        SymbolIdRange::input(self.start_symbol_id, self.symbol_definitions.len())
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
