//! This module resolves symbol references between objects. In the process, it decides which archive
//! entries are needed. We also resolve which output section, if any, each input section should be
//! assigned to.

use crate::args::Args;
use crate::elf::File;
use crate::error::Error;
use crate::error::Result;
use crate::input_data;
use crate::input_data::FileId;
use crate::input_data::InputRef;
use crate::input_data::INTERNAL_FILE_ID;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_id::OutputSectionsBuilder;
use crate::output_section_id::SectionDetails;
use crate::output_section_id::TemporaryOutputSectionId;
use crate::output_section_id::UnloadedSection;
use crate::output_section_map::OutputSectionMap;
use crate::symbol::SymbolName;
use crate::symbol_db;
use crate::symbol_db::FileSymbols;
use crate::symbol_db::GlobalSymbolId;
use crate::symbol_db::InternalSymDefInfo;
use crate::symbol_db::InternalSymbols;
use crate::symbol_db::ObjectSymbols;
use crate::symbol_db::SymbolDb;
use ahash::AHashMap;
use anyhow::bail;
use anyhow::Context;
use crossbeam_queue::ArrayQueue;
use crossbeam_queue::SegQueue;
use crossbeam_utils::atomic::AtomicCell;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use std::collections::BTreeMap;
use std::ffi::CString;

#[tracing::instrument(skip_all, name = "Symbol resolution")]
pub(crate) fn resolve_symbols_and_sections<'data>(
    file_states: Vec<FileSymbols<'data>>,
    symbol_db: &mut SymbolDb<'data>,
) -> Result<(Vec<ResolvedFile<'data>>, OutputSections<'data>)> {
    let (mut resolved, start_stop_sets, mut internal) =
        resolve_symbols_in_files(file_states, symbol_db)?;

    let output_sections = assign_section_ids(&resolved, symbol_db.args)?;

    let merged_strings = merge_strings(&mut resolved, &output_sections)?;

    allocate_start_stop_symbol_ids(
        start_stop_sets,
        &mut internal,
        &mut resolved,
        &output_sections,
        symbol_db,
    )?;

    resolve_alternative_symbol_definitions(symbol_db, &resolved)?;
    filter_overridden_internal_symbols(&mut internal, symbol_db);

    resolved[INTERNAL_FILE_ID.as_usize()] = ResolvedFile::Internal(ResolvedInternal {
        dynamic_linker: internal.dynamic_linker,
        symbol_definitions: internal.symbol_definitions,
        defined: internal.defined,
        file_id: internal.file_id,
        merged_strings,
    });
    Ok((resolved, output_sections))
}

#[tracing::instrument(skip_all, name = "Resolve symbols")]
pub(crate) fn resolve_symbols_in_files<'data>(
    file_states: Vec<FileSymbols<'data>>,
    symbol_db: &mut SymbolDb<'data>,
) -> Result<(
    Vec<ResolvedFile<'data>>,
    SegQueue<StartStopSet<'data>>,
    InternalSymbols,
)> {
    let num_objects = file_states.len();
    let mut objects = Vec::new();
    type ArchiveEntryCell<'data> = AtomicCell<Option<Box<ObjectSymbols<'data>>>>;
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
                // TODO: If we're going to box these, we might as well box them earlier (in
                // symbol_db).
                archive_entries[s.file_id.as_usize()].store(Some(Box::new(s)));
                ResolvedFile::NotLoaded
            }
        })
        .collect();
    let internal = internal.unwrap();
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
    Ok((resolved, outputs.start_stop_sets, internal))
}

/// For each symbol that has multiple definitions, some of which may be weak, some strong, some
/// "common" symbols and some in archive entries that weren't loaded, resolve which version of the
/// symbol we're using. The symbol we select will be the first strongly defined symbol in a loaded
/// object, or if there are no strong definitions, then the first definition in a loaded object. If
/// a symbol definition is a common symbol, then the largest definition will be used.
#[tracing::instrument(skip_all, name = "Resolve alternative symbol definitions")]
fn resolve_alternative_symbol_definitions<'data>(
    symbol_db: &mut SymbolDb<'data>,
    resolved: &[ResolvedFile<'data>],
) -> Result {
    // For now, we do this from a single thread since we don't expect a lot of symbols will have
    // multiple definitions. If it turns out that there are cases where it's actually taking
    // significant time, then we could parallelise this without too much work.
    let alternate_definitions =
        core::mem::replace(&mut symbol_db.alternate_definitions, AHashMap::new());
    for (symbol_id, alternatives) in alternate_definitions {
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

/// Filter out any internally defined symbols that have been overridden by user code.
#[tracing::instrument(skip_all, name = "Filter overridden internal symbols")]
fn filter_overridden_internal_symbols(
    internal: &mut InternalSymbols,
    symbol_db: &mut SymbolDb<'_>,
) {
    internal
        .defined
        .retain(|symbol_id| symbol_db.symbol(*symbol_id).file_id == input_data::INTERNAL_FILE_ID);
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
    Internal(ResolvedInternal<'data>),
    Object(ResolvedObject<'data>),
}

/// A section, but where we may or may not yet have decided to load it.
#[derive(Debug)]
pub(crate) enum SectionSlot<'data> {
    Discard,
    Unloaded(UnloadedSection<'data>),
    Loaded(crate::layout::Section<'data>),
    EhFrameData(object::SectionIndex),
    MergeStrings(MergeStringsFileSection<'data>),
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum LocalSymbolResolution {
    UnresolvedWeak,
    TlsGetAddr,
    WeakRefToGlobal(GlobalSymbolId),
    Global(GlobalSymbolId),
    LocalSection(object::SectionIndex),
    MergedString(MergedStringResolution),
    UndefinedSymbol,
    Null,
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct MergedStringResolution {
    pub(crate) symbol_id: Option<GlobalSymbolId>,
    pub(crate) output_section_id: OutputSectionId,
    pub(crate) offset: u64,
}

pub(crate) struct ResolvedInternal<'data> {
    // TODO: Use this - when we implement dynamic linking
    #[allow(dead_code)]
    pub(crate) dynamic_linker: Option<CString>,
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo>,
    pub(crate) defined: Vec<GlobalSymbolId>,
    pub(crate) file_id: FileId,
    pub(crate) merged_strings: OutputSectionMap<MergedStringsSection<'data>>,
}

pub(crate) struct ResolvedObject<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) object: Box<File<'data>>,
    pub(crate) file_id: FileId,
    pub(crate) local_symbol_resolutions: Vec<LocalSymbolResolution>,
    pub(crate) sections: Vec<SectionSlot<'data>>,
    merge_strings_sections: Vec<MergeStringsFileSection<'data>>,

    /// Details about each custom section that is defined in this object. The index is an index into
    /// self.sections.
    custom_sections: Vec<(object::SectionIndex, SectionDetails<'data>)>,
}

#[derive(Debug)]
pub(crate) struct MergeStringsFileSection<'data> {
    output_section_id: OutputSectionId,

    /// The strings from this section. Only present temporarily during resolution.
    strings: Vec<StringToMerge<'data>>,

    /// References into this section. Only present temporarily during resolution.
    references: Vec<RefToMergeString>,
}

/// A reference to a section that is enabled for string-merging.
#[derive(Debug)]
struct RefToMergeString {
    /// The offset within the input section of the symbol.
    offset: u64,

    symbol_index: object::SymbolIndex,

    global_symbol_id: Option<GlobalSymbolId>,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
struct StringToMerge<'data> {
    bytes: &'data [u8],
    hash: u64,
}

#[derive(Default)]
struct MergeStringsSection<'data> {
    strings: Vec<&'data [u8]>,
    next_offset: u64,
    string_offsets: crate::hash::PassThroughHashMap<StringToMerge<'data>, u64>,
}

pub(crate) struct MergedStringsSection<'data> {
    pub(crate) len: u64,
    pub(crate) strings: Vec<&'data [u8]>,
}

impl<'data> MergeStringsSection<'data> {
    /// Adds `string`, deduplicating with an existing string if an identical string is already
    /// present. Returns the offset into the section.
    fn add_string(&mut self, string: StringToMerge<'data>) -> u64 {
        *self.string_offsets.entry(string).or_insert_with(|| {
            let offset = self.next_offset;
            self.next_offset += string.bytes.len() as u64;
            self.strings.push(string.bytes);
            offset
        })
    }
}

/// Merges identical strings from all loaded objects where those strings are from input sections
/// that are marked with both the SHF_MERGE and SHF_STRINGS flags.
#[tracing::instrument(skip_all, name = "Merge strings")]
fn merge_strings<'data>(
    resolved: &mut [ResolvedFile<'data>],
    output_sections: &OutputSections,
) -> Result<OutputSectionMap<MergedStringsSection<'data>>> {
    let mut strings_by_section: OutputSectionMap<MergeStringsSection> =
        OutputSectionMap::with_size(output_sections.len());
    for file in resolved {
        let ResolvedFile::Object(obj) = file else {
            continue;
        };
        for sec in &mut obj.merge_strings_sections {
            let string_to_offset = strings_by_section.get_mut(sec.output_section_id);
            let mut symbols = sec.references.iter().peekable();
            // The offset within the input section of the current string.
            let mut input_offset = 0;
            for string in &sec.strings {
                let output_offset = string_to_offset.add_string(*string);
                while let Some(merge_ref) = symbols.peek() {
                    debug_assert!(
                        merge_ref.offset >= input_offset,
                        "String-merge symbol offsets went backwards"
                    );
                    let offset_into_string = merge_ref.offset - input_offset;
                    if offset_into_string >= string.bytes.len() as u64 {
                        // This reference belongs to a subsequent string.
                        break;
                    }
                    obj.local_symbol_resolutions[merge_ref.symbol_index.0] =
                        LocalSymbolResolution::MergedString(MergedStringResolution {
                            symbol_id: merge_ref.global_symbol_id,
                            output_section_id: sec.output_section_id,
                            offset: output_offset + offset_into_string,
                        });
                    symbols.next();
                }
                input_offset += string.bytes.len() as u64;
            }
        }
    }
    Ok(strings_by_section.into_map(|s| MergedStringsSection {
        len: s.next_offset,
        strings: s.strings,
    }))
}

#[tracing::instrument(skip_all, name = "Assign section IDs")]
fn assign_section_ids<'data>(
    resolved: &[ResolvedFile<'data>],
    args: &Args,
) -> Result<OutputSections<'data>> {
    let mut output_sections_builder = OutputSectionsBuilder::with_base_address(args.base_address());
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
}

impl<'data> Outputs<'data> {
    fn new(num_objects: usize) -> Self {
        Self {
            loaded: ArrayQueue::new(num_objects),
            errors: ArrayQueue::new(1),
            start_stop_sets: SegQueue::new(),
        }
    }
}

fn process_object<'scope, 'data: 'scope>(
    obj: symbol_db::ObjectSymbols<'data>,
    symbol_db: &'scope SymbolDb<'data>,
    archive_entries: &'scope [AtomicCell<Option<Box<ObjectSymbols<'data>>>>],
    s: &rayon::Scope<'scope>,
    outputs: &'scope Outputs<'data>,
) -> Result {
    let request_file_id = |file_id: FileId| {
        if let Some(entry) = archive_entries[file_id.as_usize()].take() {
            s.spawn(|s| {
                let r = process_object(*entry, symbol_db, archive_entries, s, outputs);
                if let Err(error) = r {
                    let _ = outputs.errors.push(error);
                }
            });
        }
    };
    let input = obj.input;
    let res = ResolvedObject::new(obj, symbol_db, request_file_id, &outputs.start_stop_sets)
        .with_context(|| format!("Failed to process {input}"))?;
    let _ = outputs.loaded.push(res);
    Ok(())
}

struct StartStopSet<'data> {
    file_id: FileId,
    start_stop_refs: AHashMap<&'data [u8], Vec<object::SymbolIndex>>,
}

#[tracing::instrument(skip_all, name = "Process custom section start/stop refs")]
fn allocate_start_stop_symbol_ids<'data>(
    start_stop_sets: SegQueue<StartStopSet<'data>>,
    internal: &mut InternalSymbols,
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
        let mut custom_sections = Vec::new();
        let mut sections = resolve_sections(&obj, &mut custom_sections, symbol_db.args)?;

        let local_symbol_resolutions = resolve_symbols(
            &obj,
            symbol_db,
            request_file_id,
            start_stop_sets,
            &mut sections,
        )
        .with_context(|| format!("Failed to resolve symbols in {obj}"))?;

        let mut merge_strings_sections = Vec::new();
        for slot in &mut sections {
            if let SectionSlot::MergeStrings(merge) = slot {
                let mut owned_merge = merge.take();
                // We need references sorted by offset so that we can find which references belong
                // to which strings as we iterate through them when doing the merge.
                owned_merge.references.sort_by_key(|r| r.offset);
                merge_strings_sections.push(owned_merge);
            }
        }

        Ok(Self {
            input: obj.input,
            object: obj.object,
            file_id: obj.file_id,
            local_symbol_resolutions,
            sections,
            custom_sections,
            merge_strings_sections,
        })
    }
}

fn resolve_sections<'data>(
    obj: &symbol_db::ObjectSymbols<'data>,
    custom_sections: &mut Vec<(object::SectionIndex, SectionDetails<'data>)>,
    args: &Args,
) -> Result<Vec<SectionSlot<'data>>> {
    let sections = obj
        .object
        .sections()
        .map(|input_section| {
            if let Some(unloaded) = UnloadedSection::from_section(&input_section, args)? {
                match unloaded.output_section_id {
                    TemporaryOutputSectionId::BuiltIn(_) => Ok(SectionSlot::Unloaded(unloaded)),
                    TemporaryOutputSectionId::Custom(_custom_section_id) => {
                        custom_sections.push((input_section.index(), unloaded.details));
                        Ok(SectionSlot::Unloaded(unloaded))
                    }
                    TemporaryOutputSectionId::EhFrameData => {
                        Ok(SectionSlot::EhFrameData(input_section.index()))
                    }
                    TemporaryOutputSectionId::StringMerge(output_section_id) => {
                        Ok(SectionSlot::MergeStrings(MergeStringsFileSection::new(
                            input_section,
                            output_section_id,
                        )?))
                    }
                }
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
    sections: &mut [SectionSlot<'data>],
) -> Result<Vec<LocalSymbolResolution>> {
    let mut start_stop_refs: AHashMap<&'data [u8], Vec<object::SymbolIndex>> = AHashMap::new();
    let local_symbol_resolutions = obj
        .object
        .symbols()
        .map(|local_symbol| {
            let name_bytes = local_symbol.name_bytes()?;
            let mut global_symbol_id = None;
            let symbol_state = if name_bytes.is_empty() || local_symbol.is_local() {
                if let Some(local_section_index) = local_symbol.section_index() {
                    LocalSymbolResolution::LocalSection(local_section_index)
                } else {
                    LocalSymbolResolution::Null
                }
            } else {
                match symbol_db.symbol_ids.get(&SymbolName::new(name_bytes)) {
                    Some(&symbol_id) => {
                        global_symbol_id = Some(symbol_id);
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
            if let Some(local_section_index) = local_symbol.section_index() {
                if let SectionSlot::MergeStrings(merge) = &mut sections[local_section_index.0] {
                    merge.references.push(RefToMergeString {
                        global_symbol_id,
                        offset: local_symbol.address(),
                        symbol_index: local_symbol.index(),
                    });
                }
            }
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

impl<'data> SectionSlot<'data> {
    pub(crate) fn is_loaded(&self) -> bool {
        matches!(self, SectionSlot::Loaded(_))
    }
}

impl<'data> MergeStringsFileSection<'data> {
    fn new(
        input_section: crate::elf::Section<'data, '_>,
        output_section_id: OutputSectionId,
    ) -> Result<MergeStringsFileSection<'data>> {
        let mut remaining = input_section.data()?;
        let mut strings = Vec::new();
        while !remaining.is_empty() {
            let len = memchr::memchr(0, remaining)
                .map(|i| i + 1)
                .with_context(|| {
                    format!(
                        "String in section `{}` is not null-terminated",
                        input_section.name().unwrap_or("??")
                    )
                })?;
            let (bytes, rest) = remaining.split_at(len);
            let hash = crate::hash::hash_bytes(bytes);
            strings.push(StringToMerge { bytes, hash });
            remaining = rest;
        }
        Ok(MergeStringsFileSection {
            output_section_id,
            strings,
            // This will get filled in when we read the symbol table.
            references: Default::default(),
        })
    }

    /// Returns an owned version of `self` with the heap-allocated parts of `self` cleared.
    fn take(&mut self) -> MergeStringsFileSection<'data> {
        MergeStringsFileSection {
            output_section_id: self.output_section_id,
            strings: core::mem::take(&mut self.strings),
            references: core::mem::take(&mut self.references),
        }
    }
}

impl<'data> std::hash::Hash for StringToMerge<'data> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}
