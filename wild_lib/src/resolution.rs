//! This module resolves symbol references between objects. In the process, it decides which archive
//! entries are needed. We also resolve which output section, if any, each input section should be
//! assigned to.

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
use crate::output_section_id::OutputSections;
use crate::output_section_id::OutputSectionsBuilder;
use crate::output_section_id::SectionDetails;
use crate::output_section_map::OutputSectionMap;
use crate::parsing::InternalSymDefInfo;
use crate::parsing::ParsedInput;
use crate::parsing::ParsedInputObject;
use crate::parsing::Prelude;
use crate::part_id::PartId;
use crate::part_id::TemporaryPartId;
use crate::part_id::UnloadedSection;
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
use itertools::Itertools;
use object::read::elf::Sym as _;
use object::LittleEndian;
use std::fmt::Display;

pub(crate) struct ResolutionOutputs<'data> {
    pub(crate) groups: Vec<ResolvedGroup<'data>>,
    pub(crate) output_sections: OutputSections<'data>,
    pub(crate) merged_strings: OutputSectionMap<MergeStringsSection<'data>>,
    pub(crate) custom_start_stop_defs: Vec<InternalSymDefInfo>,
}

#[tracing::instrument(skip_all, name = "Symbol resolution")]
pub fn resolve_symbols_and_sections<'data>(
    groups: &'data [Group<'data>],
    symbol_db: &mut SymbolDb<'data>,
) -> Result<ResolutionOutputs<'data>> {
    let (mut groups, undefined_symbols, internal) = resolve_symbols_in_files(groups, symbol_db)?;

    let output_sections = assign_section_ids(&groups, symbol_db.args)?;

    let merged_strings = merge_strings(&mut groups, &output_sections)?;

    let custom_start_stop_defs =
        canonicalise_undefined_symbols(undefined_symbols, &output_sections, &groups, symbol_db)?;

    resolve_alternative_symbol_definitions(symbol_db, &groups)?;

    groups[PRELUDE_FILE_ID.group()].files[PRELUDE_FILE_ID.file()] =
        ResolvedFile::Prelude(ResolvedPrelude {
            symbol_definitions: &internal.symbol_definitions,
        });
    Ok(ResolutionOutputs {
        groups,
        output_sections,
        merged_strings,
        custom_start_stop_defs,
    })
}

/// A cell that holds mutable reference to the symbol definitions for one of our input objects. We
/// unfortunately need to box these mutable slices, otherwise the cell isn't lock-free.
type DefinitionsCell<'definitions> = AtomicCell<Option<Box<&'definitions mut [SymbolId]>>>;

#[tracing::instrument(skip_all, name = "Resolve symbols")]
pub(crate) fn resolve_symbols_in_files<'data>(
    groups: &'data [Group<'data>],
    symbol_db: &mut SymbolDb<'data>,
) -> Result<(
    Vec<ResolvedGroup<'data>>,
    SegQueue<UndefinedSymbol<'data>>,
    &'data Prelude,
)> {
    let mut num_objects = 0;
    let mut objects = Vec::new();
    assert!(DefinitionsCell::is_lock_free());

    let mut symbol_definitions = symbol_db.take_definitions();
    let mut symbol_definitions_slice = symbol_definitions.as_mut();
    let mut definitions_per_group_and_file: Vec<Vec<DefinitionsCell>> = groups
        .iter()
        .map(|group| {
            group
                .files
                .iter()
                .map(|file| {
                    DefinitionsCell::new(Some(Box::new(crate::slice::slice_take_prefix_mut(
                        &mut symbol_definitions_slice,
                        file.num_symbols(),
                    ))))
                })
                .collect_vec()
        })
        .collect_vec();

    let mut prelude = None;
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
                        // We don't yet have all the information we need to construct
                        // ResolvedPrelude, so we stash away our input for now and let the caller
                        // construct it later.
                        prelude = Some(s);
                        ResolvedFile::NotLoaded(NotLoaded {
                            symbol_id_range: SymbolIdRange::prelude(0),
                        })
                    }
                    ParsedInput::Object(s) => {
                        if !s.is_optional() {
                            objects.push((s, definitions.take().unwrap()));
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
    let resources = ResolutionResources {
        groups,
        definitions_per_file: &definitions_per_group_and_file,
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

    drop(definitions_per_group_and_file);
    symbol_db.restore_definitions(symbol_definitions);
    if let Some(e) = outputs.errors.pop() {
        return Err(e);
    }

    for obj in outputs.loaded {
        let file_id = obj.file_id;
        resolved[file_id.group()].files[file_id.file()] = ResolvedFile::Object(obj);
    }

    Ok((resolved, outputs.undefined_symbols, prelude.unwrap()))
}

struct ResolutionResources<'data, 'definitions, 'outer_scope> {
    groups: &'data [Group<'data>],
    definitions_per_file: &'outer_scope Vec<Vec<DefinitionsCell<'definitions>>>,
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
    resolved: &[ResolvedGroup],
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
    resolved: &[ResolvedGroup],
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
pub(crate) enum SectionSlot<'data> {
    Discard,
    Unloaded(UnloadedSection<'data>),
    Loaded(crate::layout::Section<'data>),
    EhFrameData(object::SectionIndex),
    MergeStrings(MergeStringsFileSection<'data>),
}

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
    pub(crate) sections: Vec<SectionSlot<'data>>,
    merge_strings_sections: Vec<UnresolvedMergeStringsFileSection<'data>>,

    /// Details about each custom section that is defined in this object.
    custom_sections: Vec<SectionDetails<'data>>,
}

pub(crate) struct ResolvedEpilogue {
    pub(crate) file_id: FileId,
    pub(crate) start_symbol_id: SymbolId,
}

#[derive(Clone, Copy)]
pub(crate) struct MergeStringsFileSection<'data> {
    temporary_part_id: TemporaryPartId<'data>,
}

pub(crate) struct UnresolvedMergeStringsFileSection<'data> {
    section_index: object::SectionIndex,
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
    resolved: &mut [ResolvedGroup<'data>],
    output_sections: &OutputSections,
) -> Result<OutputSectionMap<MergeStringsSection<'data>>> {
    let mut strings_by_section = output_sections.new_section_map::<MergeStringsSection>();
    for group in resolved {
        for file in &mut group.files {
            let ResolvedFile::Object(obj) = file else {
                continue;
            };
            let Some(non_dynamic) = obj.non_dynamic.as_mut() else {
                continue;
            };
            for merge_info in &non_dynamic.merge_strings_sections {
                let SectionSlot::MergeStrings(sec) =
                    &mut non_dynamic.sections[merge_info.section_index.0]
                else {
                    unreachable!();
                };
                let part_id = output_sections.part_id(sec.temporary_part_id)?;
                sec.set_precomputed_part_id(part_id);

                let string_to_offset = strings_by_section.get_mut(part_id.output_section_id());
                for string in &merge_info.strings {
                    string_to_offset.add_string(*string);
                }
            }
        }
    }
    Ok(strings_by_section)
}

#[tracing::instrument(skip_all, name = "Assign section IDs")]
fn assign_section_ids<'data>(
    resolved: &[ResolvedGroup<'data>],
    args: &Args,
) -> Result<OutputSections<'data>> {
    let mut output_sections_builder = OutputSectionsBuilder::with_base_address(args.base_address());
    for group in resolved {
        for file in &group.files {
            if let ResolvedFile::Object(s) = file {
                if let Some(non_dynamic) = s.non_dynamic.as_ref() {
                    output_sections_builder
                        .add_sections(&non_dynamic.custom_sections)
                        .with_context(|| format!("Failed to process custom sections for {s}"))?;
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
        if let Some(definitions) =
            resources.definitions_per_file[file_id.group()][file_id.file()].take()
        {
            s.spawn(move |s| {
                if let ParsedInput::Object(obj) =
                    &resources.groups[file_id.group()].files[file_id.file()]
                {
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
    output_sections: &OutputSections,
    groups: &[ResolvedGroup],
    symbol_db: &mut SymbolDb<'data>,
) -> Result<Vec<InternalSymDefInfo>> {
    let mut custom_start_stop_defs = Vec::new();
    let mut name_to_id: PassThroughHashMap<SymbolName<'data>, SymbolId> = Default::default();
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
        match name_to_id.entry(undefined.name) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                let symbol_id = allocate_start_stop_symbol_id(
                    undefined.name,
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
    Ok(custom_start_stop_defs)
}

fn allocate_start_stop_symbol_id<'data>(
    name: PreHashed<SymbolName<'data>>,
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
    let section_id = output_sections.custom_name_to_id(section_name)?;

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
            let mut merge_strings_sections = Vec::new();

            let sections = resolve_sections(
                obj,
                &mut custom_sections,
                &mut merge_strings_sections,
                symbol_db.args,
            )?;

            resolve_symbols(
                obj,
                symbol_db,
                request_file_id,
                undefined_symbols_out,
                definitions_out,
            )
            .with_context(|| format!("Failed to resolve symbols in {obj}"))?;

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
    custom_sections: &mut Vec<SectionDetails<'data>>,
    merge_strings_out: &mut Vec<UnresolvedMergeStringsFileSection<'data>>,
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
                    if let TemporaryPartId::Custom(_custom_section_id) = unloaded.part_id {
                        custom_sections.push(unloaded.details);
                    }
                    Ok(SectionSlot::MergeStrings(MergeStringsFileSection::new(
                        &obj.object,
                        input_section,
                        input_section_index,
                        unloaded.part_id,
                        merge_strings_out,
                    )?))
                } else {
                    match unloaded.part_id {
                        TemporaryPartId::BuiltIn(_) => Ok(SectionSlot::Unloaded(unloaded)),
                        TemporaryPartId::Custom(_custom_section_id) => {
                            custom_sections.push(unloaded.details);
                            Ok(SectionSlot::Unloaded(unloaded))
                        }
                        TemporaryPartId::EhFrameData => {
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

impl<'data> std::fmt::Display for ResolvedObject<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl<'data> std::fmt::Display for ResolvedFile<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolvedFile::NotLoaded(_) => std::fmt::Display::fmt("<not loaded>", f),
            ResolvedFile::Prelude(_) => std::fmt::Display::fmt("<prelude>", f),
            ResolvedFile::Object(o) => std::fmt::Display::fmt(o, f),
            ResolvedFile::Epilogue(_) => std::fmt::Display::fmt("<epilogue>", f),
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
        input_section_index: object::SectionIndex,
        section_id: TemporaryPartId<'data>,
        merge_strings_out: &mut Vec<UnresolvedMergeStringsFileSection<'data>>,
    ) -> Result<MergeStringsFileSection<'data>> {
        let mut remaining = object.section_data(input_section)?;
        let mut strings = Vec::new();
        while !remaining.is_empty() {
            strings.push(StringToMerge::take_hashed(&mut remaining)?);
        }
        merge_strings_out.push(UnresolvedMergeStringsFileSection {
            section_index: input_section_index,
            strings,
        });
        Ok(MergeStringsFileSection {
            temporary_part_id: section_id,
        })
    }

    /// Store the part ID, so that we don't have to recompute it again later.
    fn set_precomputed_part_id(&mut self, part_id: PartId) {
        // Built-in isn't quite accurate, but it serves out purpose.
        self.temporary_part_id = TemporaryPartId::BuiltIn(part_id);
    }

    pub(crate) fn precomputed_part_id(&self) -> PartId {
        match self.temporary_part_id {
            TemporaryPartId::BuiltIn(id) => id,
            _ => panic!("Call to `precomputed_part_id` when we haven't stored the ID"),
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
    fn symbol_strength(&self, symbol_id: SymbolId, resolved: &[ResolvedGroup]) -> SymbolStrength {
        let file_id = self.file_id_for_symbol(symbol_id);
        if let ResolvedFile::Object(obj) = &resolved[file_id.group()].files[file_id.file()] {
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

// We create quite a lot of `SectionSlot`s. We don't generally copy them, however we do need to
// eventually drop the Vecs that contain them. Dropping those Vecs is a lot cheaper if the slots
// don't need to have run Drop. We check for this, by making sure the type implements `Copy`
#[test]
fn section_slot_is_copy() {
    fn assert_copy<T: Copy>(_v: T) {}

    assert_copy(SectionSlot::Discard);
}
