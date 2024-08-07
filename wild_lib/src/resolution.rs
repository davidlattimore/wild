//! This module resolves symbol references between objects. In the process, it decides which archive
//! entries are needed. We also resolve which output section, if any, each input section should be
//! assigned to.

use crate::args::Args;
use crate::debug_assert_bail;
use crate::elf::File;
use crate::error::Error;
use crate::error::Result;
use crate::hash::PassThroughHashMap;
use crate::hash::PreHashed;
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
use crate::parsing::InternalInputObject;
use crate::parsing::InternalSymDefInfo;
use crate::parsing::ParsedInput;
use crate::parsing::ParsedInputObject;
use crate::sharding::split_slice;
use crate::sharding::ShardKey;
use crate::symbol::SymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use anyhow::bail;
use anyhow::Context;
use bitflags::bitflags;
use crossbeam_queue::ArrayQueue;
use crossbeam_queue::SegQueue;
use crossbeam_utils::atomic::AtomicCell;
use object::read::elf::Sym as _;
use object::LittleEndian;
use std::fmt::Display;

pub(crate) struct ResolutionOutputs<'data> {
    pub(crate) files: Vec<ResolvedFile<'data>>,
    pub(crate) output_sections: OutputSections<'data>,
    pub(crate) merged_strings: OutputSectionMap<MergeStringsSection<'data>>,
}

#[tracing::instrument(skip_all, name = "Symbol resolution")]
pub fn resolve_symbols_and_sections<'data>(
    file_states: &'data [ParsedInput<'data>],
    symbol_db: &mut SymbolDb<'data>,
) -> Result<ResolutionOutputs<'data>> {
    let (mut resolved, undefined_symbols, internal) =
        resolve_symbols_in_files(file_states, symbol_db)?;

    let output_sections = assign_section_ids(&resolved, symbol_db.args)?;

    let merged_strings = merge_strings(&mut resolved, &output_sections)?;

    let Some(ResolvedFile::Epilogue(mut custom)) = resolved.pop() else {
        panic!("Epilogue must be the last input");
    };

    canonicalise_undefined_symbols(
        undefined_symbols,
        &mut custom,
        &output_sections,
        &resolved,
        symbol_db,
    )?;

    resolved.push(ResolvedFile::Epilogue(custom));

    resolve_alternative_symbol_definitions(symbol_db, &resolved)?;

    resolved[INTERNAL_FILE_ID.as_usize()] = ResolvedFile::Internal(ResolvedInternal {
        symbol_definitions: &internal.symbol_definitions,
    });
    Ok(ResolutionOutputs {
        files: resolved,
        output_sections,
        merged_strings,
    })
}

/// A cell that holds mutable reference to the symbol definitions for one of our input objects. We
/// unfortunately need to box these mutable slices, otherwise the cell isn't lock-free.
type DefinitionsCell<'definitions> = AtomicCell<Option<Box<&'definitions mut [SymbolId]>>>;

#[tracing::instrument(skip_all, name = "Resolve symbols")]
pub(crate) fn resolve_symbols_in_files<'data>(
    file_states: &'data [ParsedInput<'data>],
    symbol_db: &mut SymbolDb<'data>,
) -> Result<(
    Vec<ResolvedFile<'data>>,
    SegQueue<UndefinedSymbol<'data>>,
    &'data InternalInputObject,
)> {
    let mut num_objects = 0;
    let mut objects = Vec::new();
    assert!(DefinitionsCell::is_lock_free());
    let mut symbol_definitions = symbol_db.take_definitions();
    let definitions_per_file: Vec<DefinitionsCell> =
        split_slice(&mut symbol_definitions, &symbol_db.num_symbols_per_file)
            .into_iter()
            .map(|defs| DefinitionsCell::new(Some(Box::new(defs))))
            .collect();
    let mut internal = None;
    let mut resolved: Vec<ResolvedFile<'_>> = file_states
        .iter()
        .map(|file| match file {
            ParsedInput::Internal(s) => {
                // We don't yet have all the information we need to construct ResolvedInternal, so
                // we stash away our input for now and let the caller construct it later.
                internal = Some(s);
                ResolvedFile::NotLoaded
            }
            ParsedInput::Object(s) => {
                if !s.is_optional() {
                    let definitions = definitions_per_file[s.file_id.as_usize()].take().unwrap();
                    objects.push((s, definitions));
                }
                num_objects += 1;
                ResolvedFile::NotLoaded
            }
            ParsedInput::Epilogue(s) => ResolvedFile::Epilogue(ResolvedEpilogue {
                file_id: s.file_id,
                start_symbol_id: s.start_symbol_id,
                symbol_definitions: vec![],
            }),
        })
        .collect();
    if num_objects == 0 {
        bail!("Cannot link with 0 input files");
    }
    let outputs = Outputs::new(num_objects);
    let resources = ResolutionResources {
        file_states,
        definitions_per_file: &definitions_per_file,
        symbol_db,
        outputs: &outputs,
    };
    crate::threading::scope(|s| {
        for (obj, definitions) in objects {
            s.spawn(|s| {
                let r = process_object(obj, *definitions, s, &resources);
                if let Err(e) = r {
                    // We currently only store the first error.
                    let _ = resources.outputs.errors.push(e);
                }
            })
        }
    });
    drop(definitions_per_file);
    symbol_db.restore_definitions(symbol_definitions);
    if let Some(e) = outputs.errors.pop() {
        return Err(e);
    }
    for obj in outputs.loaded {
        let file_id = obj.file_id;
        resolved[file_id.as_usize()] = ResolvedFile::Object(obj);
    }
    let internal = internal.unwrap();
    Ok((resolved, outputs.undefined_symbols, internal))
}

struct ResolutionResources<'data, 'definitions, 'outer_scope> {
    file_states: &'data [ParsedInput<'data>],
    definitions_per_file: &'outer_scope Vec<DefinitionsCell<'definitions>>,
    symbol_db: &'outer_scope SymbolDb<'data>,
    outputs: &'outer_scope Outputs<'data>,
}

/// For each symbol that has multiple definitions, some of which may be weak, some strong, some
/// "common" symbols and some in archive entries that weren't loaded, resolve which version of the
/// symbol we're using. The symbol we select will be the first strongly defined symbol in a loaded
/// object, or if there are no strong definitions, then the first definition in a loaded object. If
/// a symbol definition is a common symbol, then the largest definition will be used.
#[tracing::instrument(skip_all, name = "Resolve alternative symbol definitions")]
fn resolve_alternative_symbol_definitions<'data>(
    symbol_db: &mut SymbolDb<'data>,
    resolved: &[ResolvedFile],
) -> Result {
    // For now, we do this from a single thread since we don't expect a lot of symbols will have
    // multiple definitions. If it turns out that there are cases where it's actually taking
    // significant time, then we could parallelise this without too much work.
    let previous_definitions = core::mem::take(&mut symbol_db.alternative_definitions);
    let symbols_with_alternatives = core::mem::take(&mut symbol_db.symbols_with_alternatives);
    let mut alternatives = Vec::new();
    for first in symbols_with_alternatives {
        alternatives.clear();
        let mut symbol_id = first;
        loop {
            symbol_id = previous_definitions[symbol_id.as_usize()];
            if symbol_id.is_undefined() {
                break;
            }
            alternatives.push(symbol_id);
        }
        let selected = select_symbol(symbol_db, first, &alternatives, resolved);
        symbol_db.replace_definition(first, selected);
        for &alt in &alternatives {
            symbol_db.replace_definition(alt, selected);
        }
    }
    Ok(())
}

/// Selects which version of the symbol to use.
fn select_symbol(
    symbol_db: &SymbolDb,
    symbol_id: SymbolId,
    alternatives: &[SymbolId],
    resolved: &[ResolvedFile],
) -> SymbolId {
    let first_strength = symbol_db.symbol_strength(symbol_id, resolved);
    if first_strength == SymbolStrength::Strong {
        return symbol_id;
    }
    let mut max_common = None;
    for &alt in alternatives.iter().rev() {
        // Dynamic symbols, even strong ones, don't override non-dynamic weak symbols.
        if symbol_db
            .symbol_value_flags(alt)
            .contains(ValueFlags::DYNAMIC)
        {
            continue;
        }
        let strength = symbol_db.symbol_strength(alt, resolved);
        match strength {
            SymbolStrength::Strong => return alt,
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
        return alt;
    }
    if first_strength != SymbolStrength::Undefined {
        return symbol_id;
    }
    for &alt in alternatives.iter().rev() {
        let strength = symbol_db.symbol_strength(alt, resolved);
        if strength != SymbolStrength::Undefined {
            return alt;
        }
    }
    symbol_id
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

pub enum ResolvedFile<'data> {
    NotLoaded,
    Internal(ResolvedInternal<'data>),
    Object(ResolvedObject<'data>),
    Epilogue(ResolvedEpilogue),
}

/// A section, but where we may or may not yet have decided to load it.
pub(crate) enum SectionSlot<'data> {
    Discard,
    Unloaded(UnloadedSection<'data>),
    Loaded(crate::layout::Section<'data>),
    EhFrameData(object::SectionIndex),
    MergeStrings(MergeStringsFileSection<'data>),
}

pub(crate) struct ResolvedInternal<'data> {
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
    pub(crate) sections: Vec<SectionSlot<'data>>,
    merge_strings_sections: Vec<object::SectionIndex>,

    /// Details about each custom section that is defined in this object. The index is an index into
    /// self.sections.
    custom_sections: Vec<(object::SectionIndex, SectionDetails<'data>)>,
}

pub struct ResolvedEpilogue {
    pub(crate) file_id: FileId,
    pub(crate) start_symbol_id: SymbolId,
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo>,
}

pub(crate) struct MergeStringsFileSection<'data> {
    temporary_section_id: TemporaryOutputSectionId<'data>,

    /// The strings from this section. Only present temporarily during resolution.
    strings: Vec<PreHashed<StringToMerge<'data>>>,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(crate) struct StringToMerge<'data> {
    bytes: &'data [u8],
}

#[derive(Default)]
pub(crate) struct MergeStringsSection<'data> {
    /// The strings in this section in order. Includes null terminators.
    pub(crate) strings: Vec<&'data [u8]>,

    /// The offset within the section of the next string to be added, or if we're done adding
    /// things, then this is the size of the output section.
    pub(crate) next_offset: u64,

    /// The offsets of each string in the output section keyed by the string contents.
    pub(crate) string_offsets: PassThroughHashMap<StringToMerge<'data>, u64>,
}

impl<'data> MergeStringsSection<'data> {
    /// Adds `string`, deduplicating with an existing string if an identical string is already
    /// present. Returns the offset into the section.
    fn add_string(&mut self, string: PreHashed<StringToMerge<'data>>) -> u64 {
        *self.string_offsets.entry(string).or_insert_with(|| {
            let offset = self.next_offset;
            self.next_offset += string.bytes.len() as u64;
            self.strings.push(string.bytes);
            offset
        })
    }

    pub(crate) fn get(&self, string: &PreHashed<StringToMerge<'data>>) -> Option<u64> {
        self.string_offsets.get(string).copied()
    }

    pub(crate) fn len(&self) -> u64 {
        self.next_offset
    }
}

/// Merges identical strings from all loaded objects where those strings are from input sections
/// that are marked with both the SHF_MERGE and SHF_STRINGS flags.
#[tracing::instrument(skip_all, name = "Merge strings")]
fn merge_strings<'data>(
    resolved: &mut [ResolvedFile<'data>],
    output_sections: &OutputSections,
) -> Result<OutputSectionMap<MergeStringsSection<'data>>> {
    let mut strings_by_section: OutputSectionMap<MergeStringsSection> =
        OutputSectionMap::with_size(output_sections.len());
    for file in resolved {
        let ResolvedFile::Object(obj) = file else {
            continue;
        };
        let Some(non_dynamic) = obj.non_dynamic.as_mut() else {
            continue;
        };
        for &section_index in &non_dynamic.merge_strings_sections {
            let SectionSlot::MergeStrings(sec) = &mut non_dynamic.sections[section_index.0] else {
                unreachable!();
            };
            let output_section_id = output_sections.output_section_id(sec.temporary_section_id)?;
            sec.set_precomputed_output_section_id(output_section_id);
            let string_to_offset = strings_by_section.get_mut(output_section_id);
            for string in &sec.strings {
                string_to_offset.add_string(*string);
            }
        }
    }
    Ok(strings_by_section)
}

#[tracing::instrument(skip_all, name = "Assign section IDs")]
fn assign_section_ids<'data>(
    resolved: &[ResolvedFile<'data>],
    args: &Args,
) -> Result<OutputSections<'data>> {
    let mut output_sections_builder = OutputSectionsBuilder::with_base_address(args.base_address());
    for s in resolved {
        if let ResolvedFile::Object(s) = s {
            if let Some(non_dynamic) = s.non_dynamic.as_ref() {
                output_sections_builder
                    .add_sections(&non_dynamic.custom_sections)
                    .with_context(|| format!("Failed to process custom sections for {s}"))?;
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

impl<'data> Outputs<'data> {
    fn new(num_objects: usize) -> Self {
        Self {
            loaded: ArrayQueue::new(num_objects),
            errors: ArrayQueue::new(1),
            undefined_symbols: SegQueue::new(),
        }
    }
}

fn process_object<'scope, 'data: 'scope, 'definitions>(
    obj: &'data ParsedInputObject<'data>,
    definitions_out: &mut [SymbolId],
    s: &crate::threading::Scope<'scope>,
    resources: &'scope ResolutionResources<'data, 'definitions, 'scope>,
) -> Result {
    let request_file_id = |file_id: FileId| {
        if let Some(definitions) = resources.definitions_per_file[file_id.as_usize()].take() {
            s.spawn(move |s| {
                if let ParsedInput::Object(obj) = &resources.file_states[file_id.as_usize()] {
                    let r = process_object(obj, *definitions, s, resources);
                    if let Err(error) = r {
                        let _ = resources.outputs.errors.push(error);
                    }
                }
            });
        }
    };
    let input = obj.input.clone();
    let res = ResolvedObject::new(
        obj,
        resources.symbol_db,
        request_file_id,
        definitions_out,
        &resources.outputs.undefined_symbols,
    )
    .with_context(|| format!("Failed to process {input}"))?;
    let _ = resources.outputs.loaded.push(res);
    Ok(())
}

struct UndefinedSymbol<'data> {
    /// If we have a file ID here and that file is loaded, then the symbol is actually defined and
    /// this record can be ignored.
    ignore_if_loaded: Option<FileId>,
    name: PreHashed<SymbolName<'data>>,
    symbol_id: SymbolId,
}

#[tracing::instrument(skip_all, name = "Canonicalise undefined symbols")]
fn canonicalise_undefined_symbols<'data>(
    undefined_symbols: SegQueue<UndefinedSymbol<'data>>,
    epilogue: &mut ResolvedEpilogue,
    output_sections: &OutputSections,
    files: &[ResolvedFile],
    symbol_db: &mut SymbolDb<'data>,
) -> Result {
    let mut name_to_id: PassThroughHashMap<SymbolName<'data>, SymbolId> = Default::default();
    let mut undefined_symbols = Vec::from_iter(undefined_symbols);
    // Sort by symbol ID to ensure deterministic behaviour. This means that the canonical symbol ID
    // for any given name will be the one for the earliest file that refers to that symbol.
    undefined_symbols.sort_by_key(|u| u.symbol_id);
    for undefined in undefined_symbols {
        if undefined
            .ignore_if_loaded
            .is_some_and(|file_id| !matches!(files[file_id.as_usize()], ResolvedFile::NotLoaded))
        {
            // The archive entry that defined the symbol in question ended up being loaded, so the
            // weak symbol is defined after all.
            continue;
        }
        match name_to_id.entry(undefined.name) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                let symbol_id = allocate_start_stop_symbol_id(
                    undefined.name,
                    symbol_db,
                    epilogue,
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
    Ok(())
}

fn allocate_start_stop_symbol_id<'data>(
    name: PreHashed<SymbolName<'data>>,
    symbol_db: &mut SymbolDb<'data>,
    epilogue: &mut ResolvedEpilogue,
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
    let section_id = output_sections.custom_name_to_id(section_name)?;

    let symbol_id = symbol_db.add_start_stop_symbol(name);
    let def_info = if is_start {
        InternalSymDefInfo::SectionStart(section_id)
    } else {
        InternalSymDefInfo::SectionEnd(section_id)
    };
    epilogue.symbol_definitions.push(def_info);
    Some(symbol_id)
}

impl<'data> ResolvedObject<'data> {
    fn new(
        obj: &'data ParsedInputObject<'data>,
        symbol_db: &SymbolDb<'data>,
        request_file_id: impl FnMut(FileId),
        definitions_out: &mut [SymbolId],
        undefined_symbols_out: &SegQueue<UndefinedSymbol<'data>>,
    ) -> Result<Self> {
        let mut non_dynamic = None;

        if obj.is_dynamic() {
            resolve_dynamic_symbols(
                obj,
                symbol_db,
                request_file_id,
                undefined_symbols_out,
                definitions_out,
            )
            .with_context(|| format!("Failed to resolve symbols in {obj}"))?;
        } else {
            let mut custom_sections = Vec::new();
            let sections = resolve_sections(obj, &mut custom_sections, symbol_db.args)?;
            resolve_symbols(
                obj,
                symbol_db,
                request_file_id,
                undefined_symbols_out,
                definitions_out,
            )
            .with_context(|| format!("Failed to resolve symbols in {obj}"))?;
            let mut merge_strings_sections = Vec::new();
            for (i, slot) in sections.iter().enumerate() {
                if matches!(slot, SectionSlot::MergeStrings(_)) {
                    merge_strings_sections.push(object::SectionIndex(i));
                }
            }
            non_dynamic = Some(NonDynamicResolved {
                sections,
                merge_strings_sections,
                custom_sections,
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

fn resolve_sections<'data>(
    obj: &ParsedInputObject<'data>,
    custom_sections: &mut Vec<(object::SectionIndex, SectionDetails<'data>)>,
    args: &Args,
) -> Result<Vec<SectionSlot<'data>>> {
    let sections = obj
        .object
        .sections
        .enumerate()
        .map(|(input_section_index, input_section)| {
            if let Some(unloaded) = UnloadedSection::from_section(&obj.object, input_section, args)?
            {
                if unloaded.is_string_merge {
                    if let TemporaryOutputSectionId::Custom(_custom_section_id) =
                        unloaded.output_section_id
                    {
                        custom_sections.push((input_section_index, unloaded.details));
                    }
                    Ok(SectionSlot::MergeStrings(MergeStringsFileSection::new(
                        &obj.object,
                        input_section,
                        unloaded.output_section_id,
                    )?))
                } else {
                    match unloaded.output_section_id {
                        TemporaryOutputSectionId::BuiltIn(_) => Ok(SectionSlot::Unloaded(unloaded)),
                        TemporaryOutputSectionId::Custom(_custom_section_id) => {
                            custom_sections.push((input_section_index, unloaded.details));
                            Ok(SectionSlot::Unloaded(unloaded))
                        }
                        TemporaryOutputSectionId::EhFrameData => {
                            Ok(SectionSlot::EhFrameData(input_section_index))
                        }
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
    obj: &ParsedInputObject<'data>,
    symbol_db: &SymbolDb<'data>,
    mut request_file_id: impl FnMut(FileId),
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
                    symbol_db,
                    obj,
                    &mut request_file_id,
                    undefined_symbols_out,
                )
            },
        )?;
    Ok(())
}

fn resolve_dynamic_symbols<'data>(
    obj: &ParsedInputObject<'data>,
    symbol_db: &SymbolDb<'data>,
    mut request_file_id: impl FnMut(FileId),
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
                    symbol_db,
                    obj,
                    &mut request_file_id,
                    undefined_symbols_out,
                )
            },
        )?;
    Ok(())
}

fn resolve_symbol<'data>(
    local_symbol_index: object::SymbolIndex,
    local_symbol: &crate::elf::SymtabEntry,
    definition_out: &mut SymbolId,
    symbol_db: &SymbolDb<'data>,
    obj: &ParsedInputObject<'data>,
    request_file_id: &mut impl FnMut(FileId),
    undefined_symbols_out: &SegQueue<UndefinedSymbol<'data>>,
) -> Result {
    // Don't try to resolve symbols that are already defined, e.g. locals and globals that we
    // define. Also don't try to resolve symbol zero - the undefined symbol.
    if !definition_out.is_undefined() || local_symbol_index.0 == 0 {
        return Ok(());
    }
    let name_bytes = obj.object.symbol_name(local_symbol)?;
    debug_assert_bail!(
        !local_symbol.is_local(),
        "Only globals should be undefined, found symbol `{}` ({local_symbol_index})",
        String::from_utf8_lossy(name_bytes)
    );
    assert!(!local_symbol.is_definition(LittleEndian));
    let prehashed_name = SymbolName::prehashed(name_bytes);
    match symbol_db.global_names.get(&prehashed_name) {
        Some(&symbol_id) => {
            *definition_out = symbol_id;
            let symbol_file_id = symbol_db.file_id_for_symbol(symbol_id);
            if symbol_file_id != obj.file_id && !local_symbol.is_weak() {
                request_file_id(symbol_file_id);
            } else if symbol_file_id != INTERNAL_FILE_ID {
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
            ResolvedFile::Epilogue(_) => std::fmt::Display::fmt("<custom sections>", f),
        }
    }
}

impl<'data> SectionSlot<'data> {
    pub(crate) fn is_loaded(&self) -> bool {
        !matches!(self, SectionSlot::Discard | SectionSlot::Unloaded(..))
    }
}

impl<'data> MergeStringsFileSection<'data> {
    fn new(
        object: &crate::elf::File<'data>,
        input_section: &crate::elf::SectionHeader,
        section_id: TemporaryOutputSectionId<'data>,
    ) -> Result<MergeStringsFileSection<'data>> {
        let mut remaining = object.section_data(input_section)?;
        let mut strings = Vec::new();
        while !remaining.is_empty() {
            strings.push(StringToMerge::take_hashed(&mut remaining)?);
        }
        Ok(MergeStringsFileSection {
            temporary_section_id: section_id,
            strings,
        })
    }

    /// Store the output section ID, so that we don't have to recompute it again later.
    fn set_precomputed_output_section_id(&mut self, section_id: OutputSectionId) {
        // Built-in isn't quite accurate, but it serves out purpose.
        self.temporary_section_id = TemporaryOutputSectionId::BuiltIn(section_id);
    }

    pub(crate) fn precomputed_output_section_id(&self) -> OutputSectionId {
        match self.temporary_section_id {
            TemporaryOutputSectionId::BuiltIn(id) => id,
            _ => panic!("Call to `precomputed_output_section_id` when we haven't stored the ID"),
        }
    }
}

impl<'data> StringToMerge<'data> {
    /// Takes from `source` up to the next null terminator. Returns a prehashed reference to what
    /// was taken.
    pub(crate) fn take_hashed(source: &mut &'data [u8]) -> Result<PreHashed<StringToMerge<'data>>> {
        let len = memchr::memchr(0, source)
            .map(|i| i + 1)
            .context("String in merge-string section is not null-terminated")?;
        let (bytes, rest) = source.split_at(len);
        let hash = crate::hash::hash_bytes(bytes);
        *source = rest;
        Ok(PreHashed::new(StringToMerge { bytes }, hash))
    }
}

impl Display for StringToMerge<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.bytes))
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

impl Display for ValueFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

impl<'data> SymbolDb<'data> {
    fn symbol_strength(&self, symbol_id: SymbolId, resolved: &[ResolvedFile]) -> SymbolStrength {
        let file_id = self.file_id_for_symbol(symbol_id);
        if let ResolvedFile::Object(obj) = &resolved[file_id.as_usize()] {
            let local_index = symbol_id.to_input(obj.symbol_id_range);
            let Ok(obj_symbol) = obj.object.symbol(local_index) else {
                // Errors from this function should have been reported elsewhere.
                return SymbolStrength::Undefined;
            };
            let e = LittleEndian;
            if obj_symbol.is_weak() {
                SymbolStrength::Weak
            } else if obj_symbol.is_common(e) {
                SymbolStrength::Common(obj_symbol.st_size(e))
            } else {
                SymbolStrength::Strong
            }
        } else {
            SymbolStrength::Undefined
        }
    }
}
