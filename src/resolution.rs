//! This module resolves symbol references between objects. In the process, it decides which archive
//! entries are needed. We also resolve which output section, if any, each input section should be
//! assigned to.

use crate::elf::File;
use crate::error::Error;
use crate::error::Result;
use crate::input_data::FileId;
use crate::input_data::InputRef;
use crate::input_data::INTERNAL_FILE_ID;
use crate::output_section_id::OutputSections;
use crate::output_section_id::OutputSectionsBuilder;
use crate::output_section_id::SectionDetails;
use crate::output_section_id::TemporaryOutputSectionId;
use crate::output_section_id::UnloadedSection;
use crate::symbol::SymbolName;
use crate::symbol_db;
use crate::symbol_db::ArchivedObject;
use crate::symbol_db::FileSymbols;
use crate::symbol_db::GlobalSymbolId;
use crate::symbol_db::InternalSymbols;
use crate::symbol_db::LocalIndexUpdate;
use crate::symbol_db::PendingSymbol;
use crate::symbol_db::SymbolDb;
use crate::timing::Timing;
use anyhow::bail;
use anyhow::Context;
use crossbeam_queue::ArrayQueue;
use crossbeam_queue::SegQueue;
use crossbeam_utils::atomic::AtomicCell;
use fxhash::FxHashMap;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use std::collections::BTreeMap;

pub(crate) fn resolve_symbols_and_sections<'data>(
    file_states: Vec<FileSymbols<'data>>,
    symbol_db: &mut SymbolDb<'data>,
    timing: &mut Timing,
) -> Result<(Vec<ResolvedFile<'data>>, OutputSections<'data>)> {
    let num_objects = file_states.len();
    let mut objects = Vec::new();
    type ArchiveEntryCell<'data> = AtomicCell<Option<Box<ArchivedObject<'data>>>>;
    let mut archive_entries: Vec<ArchiveEntryCell> = Vec::new();
    // We use a Box so that lock-free operation is possible. Verify that our cells are actually
    // lock-free.
    assert!(ArchiveEntryCell::is_lock_free());
    archive_entries.resize_with(num_objects, || AtomicCell::new(None));
    let mut internal = None;
    let mut resolved: Vec<ResolvedFile<'_>> = file_states
        .into_iter()
        .map(|f| match f {
            FileSymbols::Internal(s) => {
                internal = Some(s);
                ResolvedFile::NotLoaded
            }
            FileSymbols::Object(s) => {
                objects.push(s);
                ResolvedFile::NotLoaded
            }
            FileSymbols::ArchiveEntry(s) => {
                let file_id = s.file_id();
                // TODO: If we're going to box these, we might as well box them earlier (in
                // symbol_db).
                archive_entries[file_id.as_usize()].store(Some(Box::new(s)));
                ResolvedFile::NotLoaded
            }
        })
        .collect();
    let mut internal = internal.unwrap();
    let outputs = Outputs::new(num_objects);
    rayon::scope(|s| {
        for obj in objects {
            s.spawn(|s| {
                let r = process_object(obj, symbol_db, &archive_entries, s, &outputs);
                if let Err(e) = r {
                    // We currently only store the first error.
                    let _ = outputs.errors.push(e);
                }
            })
        }
    });
    if let Some(e) = outputs.errors.pop() {
        return Err(e);
    }
    for obj in outputs.loaded {
        let file_id = obj.file_id;
        resolved[file_id.as_usize()] = ResolvedFile::Object(obj);
    }
    timing.complete("Resolve symbols");

    update_archive_local_indexes(symbol_db, outputs.local_index_updates)?;
    timing.complete("Update archive local symbol indexes");

    let output_sections = assign_section_ids(&resolved)?;
    timing.complete("Assign section IDs");

    allocate_start_stop_symbol_ids(
        outputs.start_stop_sets,
        &mut internal,
        &mut resolved,
        &output_sections,
        symbol_db,
    )?;
    timing.complete("Process custom section start/stop refs");

    resolve_alternative_symbol_definitions(symbol_db, &resolved)?;
    timing.complete("Resolve alternative symbol definitions");

    resolved[INTERNAL_FILE_ID.as_usize()] = ResolvedFile::Internal(internal);
    Ok((resolved, output_sections))
}

/// For each symbol that has multiple definitions, some of which may be weak, some strong, some
/// "common" symbols and some in archive entries that weren't loaded, resolve which version of the
/// symbol we're using. The symbol we select will be the first strongly defined symbol in a loaded
/// object, or if there are no strong definitions, then the first definition in a loaded object. If
/// a symbol definition is a common symbol, then the largest definition will be used.
fn resolve_alternative_symbol_definitions<'data>(
    symbol_db: &mut SymbolDb<'data>,
    resolved: &[ResolvedFile<'data>],
) -> Result {
    // For now, we do this from a single thread since we don't expect a lot of symbols will have
    // multiple definitions. If it turns out that there are cases where it's actually taking
    // significant time, then we could parallelise this without too much work.
    for (symbol_id, alternatives) in core::mem::take(&mut symbol_db.alternate_definitions) {
        if let Some(selected) = select_symbol(symbol_db, symbol_id, resolved, &alternatives) {
            symbol_db.replace_symbol(symbol_id, selected);
        }
    }
    Ok(())
}

/// Selects which version of the symbol to use. Returns None if we should leave things alone and
/// continue using the first definition of the symbol.
fn select_symbol<'data>(
    symbol_db: &SymbolDb<'data>,
    symbol_id: GlobalSymbolId,
    objects: &[ResolvedFile<'data>],
    alternatives: &[crate::symbol::Symbol],
) -> Option<crate::symbol::Symbol> {
    let first_symbol = symbol_db.symbol(symbol_id);
    let first_strength = SymbolStrength::determine(objects, first_symbol);
    if first_strength == SymbolStrength::Strong {
        return None;
    }
    let mut max_common = None;
    for alt in alternatives {
        let strength = SymbolStrength::determine(objects, alt);
        match strength {
            SymbolStrength::Strong => return Some(*alt),
            SymbolStrength::Common(size) => {
                if let Some((previous_size, _)) = max_common {
                    if size <= previous_size {
                        continue;
                    }
                }
                max_common = Some((size, alt));
            }
            _ => {}
        }
    }
    if let Some((_, alt)) = max_common {
        return Some(*alt);
    }
    if first_strength != SymbolStrength::Undefined {
        return None;
    }
    for alt in alternatives {
        let strength = SymbolStrength::determine(objects, alt);
        if strength != SymbolStrength::Undefined {
            return Some(*alt);
        }
    }
    None
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum SymbolStrength {
    /// The object containing this symbol wasn't loaded, so the definition can be ignored.
    Undefined,

    /// The object weakly defines the symbol.
    Weak,

    /// The object strongly defines the symbol.
    Strong,

    /// The symbol is a "common" symbol with the specified size. The definition with the largest
    /// size will be selected.
    Common(u64),
}

impl SymbolStrength {
    fn determine(objects: &[ResolvedFile<'_>], symbol: &crate::symbol::Symbol) -> SymbolStrength {
        if let ResolvedFile::Object(obj) = &objects[symbol.file_id.as_usize()] {
            let Ok(obj_symbol) = obj
                .object
                .symbol_by_index(symbol.local_index_without_checking_file_id())
            else {
                // Errors from this function should have been reported elsewhere.
                return SymbolStrength::Undefined;
            };
            if obj_symbol.is_weak() {
                SymbolStrength::Weak
            } else if obj_symbol.is_common() {
                SymbolStrength::Common(obj_symbol.size())
            } else {
                SymbolStrength::Strong
            }
        } else {
            SymbolStrength::Undefined
        }
    }
}

pub(crate) enum ResolvedFile<'data> {
    NotLoaded,
    Internal(ResolvedInternal),
    Object(ResolvedObject<'data>),
}

/// A section, but where we may or may not yet have decided to load it.
#[derive(Debug)]
pub(crate) enum SectionSlot<'data> {
    Discard,
    Unloaded(UnloadedSection<'data>),
    Loaded(crate::layout::Section<'data>),
}

#[derive(Copy, Clone)]
pub(crate) enum LocalSymbolResolution {
    UnresolvedWeak,
    TlsGetAddr,
    WeakRefToGlobal(GlobalSymbolId),
    Global(GlobalSymbolId),
    LocalSection(object::SectionIndex),
    UndefinedSymbol,
    Null,
}

pub(crate) type ResolvedInternal = InternalSymbols;

pub(crate) struct ResolvedObject<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) object: Box<File<'data>>,
    pub(crate) file_id: FileId,
    pub(crate) local_symbol_resolutions: Vec<LocalSymbolResolution>,
    pub(crate) sections: Vec<SectionSlot<'data>>,

    /// Details about each custom section that is defined in this object. The index is an index into
    /// self.sections.
    custom_sections: Vec<(object::SectionIndex, SectionDetails<'data>)>,
}

fn update_archive_local_indexes(
    symbol_db: &mut SymbolDb<'_>,
    local_index_updates: SegQueue<Vec<LocalIndexUpdate>>,
) -> Result {
    for update in local_index_updates.into_iter().flatten() {
        symbol_db.apply_update(update)?;
    }
    Ok(())
}

fn assign_section_ids<'data>(resolved: &[ResolvedFile<'data>]) -> Result<OutputSections<'data>> {
    let mut output_sections_builder = OutputSectionsBuilder::default();
    for s in resolved {
        if let ResolvedFile::Object(s) = s {
            output_sections_builder.add_sections(&s.custom_sections)?;
        }
    }
    output_sections_builder.build()
}

struct Outputs<'data> {
    /// Where we put objects once we've loaded them.
    loaded: ArrayQueue<ResolvedObject<'data>>,

    /// Any errors that we encountered.
    errors: ArrayQueue<Error>,

    /// Start/stop references to custom sections.
    start_stop_sets: SegQueue<StartStopSet<'data>>,

    local_index_updates: SegQueue<Vec<LocalIndexUpdate>>,
}

impl<'data> Outputs<'data> {
    fn new(num_objects: usize) -> Self {
        Self {
            loaded: ArrayQueue::new(num_objects),
            errors: ArrayQueue::new(1),
            start_stop_sets: SegQueue::new(),
            local_index_updates: SegQueue::new(),
        }
    }
}

fn process_object<'scope, 'data: 'scope>(
    obj: symbol_db::ObjectSymbols<'data>,
    symbol_db: &'scope SymbolDb<'data>,
    archive_entries: &'scope [AtomicCell<Option<Box<ArchivedObject<'data>>>>],
    s: &rayon::Scope<'scope>,
    outputs: &'scope Outputs<'data>,
) -> Result {
    let request_file_id = |file_id: FileId| {
        if let Some(entry) = archive_entries[file_id.as_usize()].take() {
            s.spawn(|s| {
                let r = process_archive_entry(*entry, symbol_db, archive_entries, s, outputs);
                if let Err(error) = r {
                    let _ = outputs.errors.push(error);
                }
            });
        }
    };
    let res = ResolvedObject::new(obj, symbol_db, request_file_id, &outputs.start_stop_sets)?;
    let _ = outputs.loaded.push(res);
    Ok(())
}

fn process_archive_entry<'scope, 'data: 'scope>(
    entry: ArchivedObject<'data>,
    symbol_db: &'scope SymbolDb<'data>,
    archive_entries: &'scope [AtomicCell<Option<Box<ArchivedObject<'data>>>>],
    s: &rayon::Scope<'scope>,
    outputs: &'scope Outputs<'data>,
) -> Result {
    let (entry_obj, symbols) = match entry {
        ArchivedObject::Unloaded(u) => u.load()?,
    };

    outputs.local_index_updates.push(crate_local_index_updates(
        entry_obj.file_id,
        symbols,
        symbol_db,
    ));
    process_object(entry_obj, symbol_db, archive_entries, s, outputs)
}

/// Returns a list of updates that we need to make to the global symbol DB now that we have loaded
/// an archive entry and know the local indexes of each of the symbols that it defines.
fn crate_local_index_updates(
    file_id: FileId,
    symbols: Vec<PendingSymbol>,
    symbol_db: &SymbolDb<'_>,
) -> Vec<LocalIndexUpdate> {
    symbols
        .into_iter()
        .filter_map(|sym| {
            symbol_db
                .symbol_ids
                .get(&sym.name)
                .map(|symbol_id| LocalIndexUpdate {
                    file_id,
                    symbol_id: *symbol_id,
                    local_index: sym.symbol.local_index_without_checking_file_id(),
                })
        })
        .collect()
}

struct StartStopSet<'data> {
    file_id: FileId,
    start_stop_refs: FxHashMap<&'data [u8], Vec<object::SymbolIndex>>,
}

fn allocate_start_stop_symbol_ids<'data>(
    start_stop_sets: SegQueue<StartStopSet<'data>>,
    internal: &mut ResolvedInternal,
    objects: &mut [ResolvedFile],
    output_sections: &OutputSections,
    symbol_db: &mut SymbolDb<'data>,
) -> Result {
    let mut names: BTreeMap<&[u8], Vec<(FileId, object::SymbolIndex)>> = Default::default();
    let start_stop_sets = Vec::from_iter(start_stop_sets);
    for s in start_stop_sets {
        for (name, symbol_indexes) in s.start_stop_refs {
            let refs = names.entry(name).or_default();
            for sym_index in symbol_indexes {
                refs.push((s.file_id, sym_index));
            }
        }
    }
    for (symbol_name, refs) in names.into_iter() {
        let local_index = object::SymbolIndex(internal.symbol_definitions.len());

        let (section_name, is_start) = if let Some(s) = symbol_name.strip_prefix(b"__start_") {
            (s, true)
        } else if let Some(s) = symbol_name.strip_prefix(b"__stop_") {
            (s, false)
        } else {
            bail!(
                "Internal error: Unexpected start/stop symbol `{}`",
                String::from_utf8_lossy(symbol_name)
            );
        };
        let section_id = if let Some(s) = output_sections.custom_name_to_id(section_name) {
            s
        } else {
            if all_unresolved_weak(&refs, objects) {
                // There's no output section with the appropriate name, but the references are all weak,
                // so we ignore it.
                continue;
            }
            bail!(
                "Reference to undefined symbol `{}` and there's no custom section named `{}`",
                String::from_utf8_lossy(symbol_name),
                String::from_utf8_lossy(section_name),
            )
        };

        let global_symbol_id = symbol_db.add_start_stop_symbol(symbol_name, local_index)?;
        let def_info = if is_start {
            symbol_db::InternalSymDefInfo::SectionStart(section_id)
        } else {
            symbol_db::InternalSymDefInfo::SectionEnd(section_id)
        };
        internal.symbol_definitions.push(def_info);
        internal.defined.push(global_symbol_id);
        for (file_id, sym_index) in refs {
            if let ResolvedFile::Object(obj) = &mut objects[file_id.as_usize()] {
                let res = &mut obj.local_symbol_resolutions[sym_index.0];
                *res = match *res {
                    LocalSymbolResolution::UndefinedSymbol => {
                        LocalSymbolResolution::Global(global_symbol_id)
                    }
                    LocalSymbolResolution::UnresolvedWeak => {
                        LocalSymbolResolution::WeakRefToGlobal(global_symbol_id)
                    }
                    _ => unreachable!(),
                }
            }
        }
    }
    Ok(())
}

/// Returns whether all the specified symbols in the specified files are unresolved weak references.
fn all_unresolved_weak(
    refs: &[(FileId, object::SymbolIndex)],
    objects: &mut [ResolvedFile<'_>],
) -> bool {
    refs.iter().all(|(file_id, sym_index)| {
        if let ResolvedFile::Object(obj) = &objects[file_id.as_usize()] {
            matches!(
                obj.local_symbol_resolutions[sym_index.0],
                LocalSymbolResolution::UnresolvedWeak
            )
        } else {
            unreachable!();
        }
    })
}

impl<'data> ResolvedObject<'data> {
    fn new(
        obj: symbol_db::ObjectSymbols<'data>,
        symbol_db: &SymbolDb<'data>,
        request_file_id: impl FnMut(FileId),
        start_stop_sets: &SegQueue<StartStopSet<'data>>,
    ) -> Result<Self> {
        let local_symbol_resolutions =
            resolve_symbols(&obj, symbol_db, request_file_id, start_stop_sets)
                .with_context(|| format!("Failed to resolve symbols in {obj}"))?;

        let mut custom_sections = Vec::new();
        let sections = resolve_sections(&obj, &mut custom_sections)?;

        Ok(Self {
            input: obj.input,
            object: obj.object,
            file_id: obj.file_id,
            local_symbol_resolutions,
            sections,
            custom_sections,
        })
    }
}

fn resolve_sections<'data>(
    obj: &symbol_db::ObjectSymbols<'data>,
    custom_sections: &mut Vec<(object::SectionIndex, SectionDetails<'data>)>,
) -> Result<Vec<SectionSlot<'data>>> {
    let sections = obj
        .object
        .sections()
        .map(|input_section| {
            if let Some(unloaded) = UnloadedSection::from_section(&input_section)? {
                if let TemporaryOutputSectionId::Custom(_custom_section_id) =
                    unloaded.output_section_id
                {
                    custom_sections.push((input_section.index(), unloaded.details));
                }

                Ok(SectionSlot::Unloaded(unloaded))
            } else {
                Ok(SectionSlot::Discard)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(sections)
}

fn resolve_symbols<'data>(
    obj: &symbol_db::ObjectSymbols<'data>,
    symbol_db: &SymbolDb<'data>,
    mut request_file_id: impl FnMut(FileId),
    start_stop_sets: &SegQueue<StartStopSet<'data>>,
) -> Result<Vec<LocalSymbolResolution>> {
    let mut start_stop_refs: FxHashMap<&'data [u8], Vec<object::SymbolIndex>> =
        FxHashMap::default();
    let local_symbol_resolutions = obj
        .object
        .symbols()
        .map(|local_symbol| {
            let name_bytes = local_symbol.name_bytes()?;
            let symbol_state = if name_bytes.is_empty() || local_symbol.is_local() {
                if let Some(local_section_index) = local_symbol.section_index() {
                    LocalSymbolResolution::LocalSection(local_section_index)
                } else {
                    LocalSymbolResolution::Null
                }
            } else {
                match symbol_db.symbol_ids.get(&SymbolName::new(name_bytes)) {
                    Some(&symbol_id) => {
                        let symbol = symbol_db.symbol(symbol_id);
                        if symbol.file_id != obj.file_id && !local_symbol.is_weak() {
                            request_file_id(symbol.file_id);
                        }

                        if local_symbol.is_weak() {
                            LocalSymbolResolution::WeakRefToGlobal(symbol_id)
                        } else {
                            LocalSymbolResolution::Global(symbol_id)
                        }
                    }
                    None => {
                        if name_bytes.starts_with(b"__start_") || name_bytes.starts_with(b"__stop_")
                        {
                            start_stop_refs
                                .entry(name_bytes)
                                .or_default()
                                .push(local_symbol.index());
                            // We'll allocate a GlobalSymbolId for this after graph traversal is complete,
                            // then fix this up to point to that instead.
                            if local_symbol.is_weak() {
                                LocalSymbolResolution::UnresolvedWeak
                            } else {
                                LocalSymbolResolution::UndefinedSymbol
                            }
                        } else if local_symbol.is_weak() {
                            LocalSymbolResolution::UnresolvedWeak
                        } else if symbol_db.args.link_static
                            && name_bytes == "__tls_get_addr".as_bytes()
                        {
                            // This is normally provided by the dynamic linker. However we're statically
                            // linking. We'll fix up references to this when we apply relocations by
                            // rewriting the instructions to directly access the appropriate TLS variable.
                            LocalSymbolResolution::TlsGetAddr
                        } else {
                            LocalSymbolResolution::UndefinedSymbol
                        }
                    }
                }
            };
            Ok(symbol_state)
        })
        .collect::<Result<Vec<_>>>()?;
    if !start_stop_refs.is_empty() {
        start_stop_sets.push(StartStopSet {
            file_id: obj.file_id,
            start_stop_refs,
        });
    }
    Ok(local_symbol_resolutions)
}

impl LocalSymbolResolution {
    pub(crate) fn global_symbol_id(self) -> Option<GlobalSymbolId> {
        match self {
            LocalSymbolResolution::WeakRefToGlobal(id) => Some(id),
            LocalSymbolResolution::Global(id) => Some(id),
            _ => None,
        }
    }
}

impl<'data> std::fmt::Display for ResolvedObject<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl<'data> std::fmt::Display for ResolvedFile<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolvedFile::NotLoaded => std::fmt::Display::fmt("<not loaded>", f),
            ResolvedFile::Internal(_) => std::fmt::Display::fmt("<internal>", f),
            ResolvedFile::Object(o) => std::fmt::Display::fmt(o, f),
        }
    }
}
