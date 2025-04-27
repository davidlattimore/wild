//! Reads global symbols for each input file and builds a map from symbol names to IDs together with
//! information about where each symbol can be obtained.

use crate::InputLinkerScript;
use crate::args::Args;
use crate::args::OutputKind;
use crate::error::Result;
use crate::grouping::Group;
use crate::hash::PassThroughHashMap;
use crate::hash::PreHashed;
use crate::hash::hash_bytes;
use crate::input_data::FileId;
use crate::input_data::PRELUDE_FILE_ID;
use crate::input_data::UNINITIALISED_FILE_ID;
use crate::input_data::VersionScriptData;
use crate::output_section_id::OutputSectionId;
use crate::parsing::InternalSymDefInfo;
use crate::parsing::ParsedInput;
use crate::parsing::ParsedInputObject;
use crate::parsing::Prelude;
use crate::parsing::ProcessedLinkerScript;
use crate::resolution::ResolvedFile;
use crate::resolution::ResolvedGroup;
use crate::resolution::ValueFlags;
use crate::sharding::ShardKey;
use crate::symbol::PreHashedSymbolName;
use crate::symbol::UnversionedSymbolName;
use crate::symbol::VersionedSymbolName;
use crate::version_script::VersionScript;
use anyhow::Context;
use anyhow::Error;
use anyhow::bail;
use crossbeam_queue::SegQueue;
use foldhash::HashMap;
use foldhash::fast::RandomState;
use itertools::Itertools;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::shf;
use object::LittleEndian;
use object::read::elf::Sym as _;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use std::collections::hash_map;
use std::fmt::Display;
use std::mem::replace;
use std::mem::take;
use symbolic_demangle::demangle;

pub struct SymbolDb<'data> {
    pub(crate) args: &'data Args,

    pub(crate) groups: Vec<Group<'data>>,

    buckets: Vec<SymbolBucket<'data>>,

    /// Which file each symbol ID belongs to. Indexes past the end are assumed to be for custom
    /// section start/stop symbols.
    symbol_file_ids: Vec<FileId>,

    /// Mapping from symbol IDs to the canonical definition of that symbol. For global symbols that
    /// were selected as the definition and for all locals, this will point to itself. e.g. the
    /// value at index 5 will be the symbol ID 5.
    symbol_definitions: Vec<SymbolId>,

    symbol_value_flags: Vec<ValueFlags>,

    /// The number of symbols in each group, keyed by the index of the group.
    pub(crate) num_symbols_per_group: Vec<usize>,

    epilogue_file_id: FileId,

    /// The names of symbols that mark the start / stop of sections. These are indexed by the offset
    /// into the epilogue's symbol IDs.
    start_stop_symbol_names: Vec<UnversionedSymbolName<'data>>,

    pub(crate) version_script: VersionScript<'data>,

    /// The name of the entry symbol if overridden by a linker script.
    entry: Option<&'data [u8]>,
}

struct SymbolBucket<'data> {
    /// Mapping from global symbol names to a symbol ID with that name. If there are multiple
    /// globals with the same name, then this will point to the one we encountered first, which may
    /// not be the selected definition. In order to find the selected definition, you still need to
    /// look at `symbol_definitions`.
    name_to_id: PassThroughHashMap<UnversionedSymbolName<'data>, SymbolId>,

    versioned_name_to_id: PassThroughHashMap<VersionedSymbolName<'data>, SymbolId>,

    /// Global symbols that have multiple definitions keyed by the first symbol with that name.
    alternative_definitions: HashMap<SymbolId, Vec<SymbolId>>,

    /// Alternative definitions, but only for versioned symbols. This might be more efficient with a
    /// proper multi-map that doesn't need a separate Vec for each value, however we don't expect
    /// many entries here.
    alternative_versioned_definitions: HashMap<SymbolId, Vec<SymbolId>>,
}

/// A global symbol that hasn't been put into our database yet.
#[derive(Clone, Copy)]
struct PendingSymbol<'data> {
    symbol_id: SymbolId,
    name: PreHashed<UnversionedSymbolName<'data>>,
}

#[derive(Clone, Copy)]
struct PendingVersionedSymbol<'data> {
    symbol_id: SymbolId,
    name: PreHashed<VersionedSymbolName<'data>>,
}

/// An ID for a symbol. All symbols from all input files are allocated a unique symbol ID. The
/// symbol ID 0 is reserved for the undefined symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SymbolId(u32);

/// A range of symbol IDs that are defined by the same input file.
///
/// This exists to translate between 3 different ways of identifying a symbol:
/// - A `SymbolId` is a globally unique identifier for a symbol.
/// - An `object::SymbolIndex` is an index into the ELF symbol table of the input file.
/// - A `usize` offset is an index into our own data structures for the file.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SymbolIdRange {
    start_symbol_id: SymbolId,
    num_symbols: usize,
}

pub(crate) struct SymbolNameDisplay<'data> {
    name: Option<UnversionedSymbolName<'data>>,
    demangle: bool,
}

impl SymbolIdRange {
    pub(crate) fn prelude(num_symbols: usize) -> SymbolIdRange {
        SymbolIdRange {
            start_symbol_id: SymbolId::undefined(),
            num_symbols,
        }
    }

    pub(crate) fn epilogue(start_symbol_id: SymbolId, num_symbols: usize) -> SymbolIdRange {
        SymbolIdRange {
            start_symbol_id,
            num_symbols,
        }
    }

    pub(crate) fn input(start_symbol_id: SymbolId, num_symbols: usize) -> SymbolIdRange {
        SymbolIdRange {
            start_symbol_id,
            num_symbols,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.num_symbols
    }

    pub(crate) fn start(&self) -> SymbolId {
        self.start_symbol_id
    }

    pub(crate) fn set_start(&mut self, start: SymbolId) {
        self.start_symbol_id = start;
    }

    pub(crate) fn as_usize(&self) -> std::ops::Range<usize> {
        self.start_symbol_id.as_usize()..self.start_symbol_id.as_usize() + self.num_symbols
    }

    pub(crate) fn offset_to_id(&self, offset: usize) -> SymbolId {
        debug_assert!(offset < self.num_symbols);
        self.start_symbol_id.add_usize(offset)
    }

    pub(crate) fn id_to_offset(&self, symbol_id: SymbolId) -> usize {
        let offset = (symbol_id.0 - self.start_symbol_id.0) as usize;
        debug_assert!(
            offset < self.num_symbols,
            "{symbol_id} not within {}..{}",
            self.start_symbol_id.0,
            self.start_symbol_id.0 as usize + self.num_symbols
        );
        offset
    }

    pub(crate) fn offset_to_input(&self, offset: usize) -> object::SymbolIndex {
        debug_assert!(offset < self.num_symbols);
        object::SymbolIndex(offset)
    }

    pub(crate) fn input_to_offset(&self, symbol_index: object::SymbolIndex) -> usize {
        let offset = symbol_index.0;
        debug_assert!(offset < self.num_symbols);
        offset
    }

    pub(crate) fn input_to_id(&self, symbol_index: object::SymbolIndex) -> SymbolId {
        self.offset_to_id(self.input_to_offset(symbol_index))
    }

    pub(crate) fn id_to_input(&self, symbol_id: SymbolId) -> object::SymbolIndex {
        self.offset_to_input(self.id_to_offset(symbol_id))
    }

    /// Returns a range that covers from the start of `a` to the end of `b`.
    pub(crate) fn covering(a: SymbolIdRange, b: SymbolIdRange) -> SymbolIdRange {
        SymbolIdRange {
            start_symbol_id: a.start_symbol_id,
            num_symbols: b.start_symbol_id.as_usize() + b.len() - a.start_symbol_id.as_usize(),
        }
    }

    pub(crate) fn empty() -> SymbolIdRange {
        Self::input(SymbolId::from_usize(0), 0)
    }
}

impl IntoIterator for SymbolIdRange {
    type Item = SymbolId;

    type IntoIter = SymbolIdRangeIterator;

    fn into_iter(self) -> Self::IntoIter {
        SymbolIdRangeIterator {
            remaining: self.len(),
            next: self.start_symbol_id,
        }
    }
}

pub(crate) struct SymbolIdRangeIterator {
    remaining: usize,
    next: SymbolId,
}

impl Iterator for SymbolIdRangeIterator {
    type Item = SymbolId;

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining = self.remaining.checked_sub(1)?;
        let value = self.next;
        self.next = value.next();
        Some(value)
    }
}

struct SymbolLoadOutputs<'data> {
    /// Pending non-versioned symbols, grouped by hash bucket.
    pending_symbols_by_bucket: Vec<PendingSymbolHashBucket<'data>>,
}

#[derive(Default, Clone)]
struct PendingSymbolHashBucket<'data> {
    symbols: Vec<PendingSymbol<'data>>,

    versioned_symbols: Vec<PendingVersionedSymbol<'data>>,
}

impl<'data> SymbolDb<'data> {
    #[tracing::instrument(skip_all, name = "Build symbol DB")]
    pub fn build(
        groups: Vec<Group<'data>>,
        version_script_data: Option<VersionScriptData<'data>>,
        args: &'data Args,
        linker_scripts: &[InputLinkerScript<'data>],
    ) -> Result<Self> {
        let version_script = version_script_data
            .map(VersionScript::parse)
            .transpose()?
            .unwrap_or_default();

        let num_symbols_per_group = groups.iter().map(|g| g.num_symbols()).collect_vec();

        let num_symbols = num_symbols_per_group.iter().sum();

        let mut symbol_definitions: Vec<SymbolId> = Vec::with_capacity(num_symbols);
        let mut symbol_value_flags: Vec<ValueFlags> = Vec::with_capacity(num_symbols);
        let mut symbol_file_ids: Vec<FileId> = Vec::with_capacity(num_symbols);

        let mut symbol_definitions_writer =
            sharded_vec_writer::VecWriter::new(&mut symbol_definitions);
        let mut symbol_value_flags_writer =
            sharded_vec_writer::VecWriter::new(&mut symbol_value_flags);
        let mut symbol_file_ids_writer = sharded_vec_writer::VecWriter::new(&mut symbol_file_ids);

        let mut per_group_writers = groups
            .iter()
            .zip(&num_symbols_per_group)
            .map(|(g, &num_symbols)| {
                SymbolInfoWriter::new(
                    g.start_symbol_id(),
                    symbol_definitions_writer.take_shard(num_symbols),
                    symbol_value_flags_writer.take_shard(num_symbols),
                    symbol_file_ids_writer.take_shard(num_symbols),
                )
            })
            .collect_vec();

        let per_group_outputs =
            read_symbols(&groups, &version_script, &mut per_group_writers, args)?;

        for writer in per_group_writers {
            symbol_definitions_writer.return_shard(writer.resolutions);
            symbol_value_flags_writer.return_shard(writer.value_kinds);
            symbol_file_ids_writer.return_shard(writer.file_ids);
        }

        let Some(Group::Epilogue(epilogue)) = groups.last() else {
            bail!("Epilogue should always be last");
        };
        let epilogue_file_id = epilogue.file_id;

        let num_buckets = num_symbol_hash_buckets(args);
        let mut buckets = Vec::new();
        buckets.resize_with(num_buckets, || SymbolBucket {
            name_to_id: Default::default(),
            versioned_name_to_id: Default::default(),
            alternative_definitions: HashMap::with_hasher(RandomState::default()),
            alternative_versioned_definitions: HashMap::with_hasher(RandomState::default()),
        });

        let mut index = SymbolDb {
            args,
            buckets,
            epilogue_file_id,
            symbol_file_ids,
            symbol_definitions,
            groups,
            num_symbols_per_group,
            start_stop_symbol_names: Default::default(),
            symbol_value_flags,
            version_script,
            entry: None,
        };

        index.populate_symbol_db(&per_group_outputs)?;

        for script in linker_scripts {
            index.apply_linker_script(script);
        }

        Ok(index)
    }

    #[tracing::instrument(skip_all, name = "Populate symbol map")]
    fn populate_symbol_db(&mut self, per_group_outputs: &[SymbolLoadOutputs<'data>]) -> Result {
        self.buckets
            .par_iter_mut()
            .enumerate()
            .for_each(|(b, bucket)| {
                // The following approximation should be an upper bound on the number of global
                // names we'll have. There will likely be at least a few global symbols with the
                // same name, in which case the actual number will be slightly smaller.
                let approx_num_symbols = per_group_outputs
                    .iter()
                    .map(|s| s.pending_symbols_by_bucket[b].symbols.len())
                    .sum();
                bucket.name_to_id.reserve(approx_num_symbols);

                for outputs in per_group_outputs {
                    let pending = &outputs.pending_symbols_by_bucket[b];

                    for symbol in &pending.symbols {
                        bucket.add_symbol(symbol);
                    }

                    for symbol in &pending.versioned_symbols {
                        bucket.add_versioned_symbol(symbol);
                    }
                }
            });

        Ok(())
    }

    pub(crate) fn add_start_stop_symbol(
        &mut self,
        symbol_name: PreHashed<UnversionedSymbolName<'data>>,
    ) -> SymbolId {
        let symbol_id = SymbolId::from_usize(self.symbol_definitions.len());

        let num_buckets = self.buckets.len();
        self.buckets[symbol_name.hash() as usize % num_buckets].add_symbol(&PendingSymbol {
            symbol_id,
            name: symbol_name,
        });

        self.symbol_definitions.push(symbol_id);
        self.start_stop_symbol_names.push(*symbol_name);
        self.num_symbols_per_group[self.epilogue_file_id.group()] += 1;

        self.symbol_value_flags
            .push(ValueFlags::ADDRESS | ValueFlags::NON_INTERPOSABLE);

        symbol_id
    }

    /// Reads the symbol visibility from the original object.
    fn input_symbol_visibility(&self, symbol_id: SymbolId) -> Visibility {
        let file_id = self.file_id_for_symbol(symbol_id);
        match &self.groups[file_id.group()] {
            Group::Prelude(_) => Visibility::Default,
            Group::Objects(parsed_input_objects) => {
                let obj = &parsed_input_objects[file_id.file()];
                let local_index = symbol_id.to_input(obj.symbol_id_range);

                let Ok(obj_symbol) = obj.object.symbol(local_index) else {
                    return Visibility::Default;
                };

                match obj_symbol.st_visibility() {
                    object::elf::STV_PROTECTED => Visibility::Protected,
                    object::elf::STV_HIDDEN => Visibility::Hidden,
                    _ => Visibility::Default,
                }
            }
            Group::LinkerScripts(_) => Visibility::Default,
            Group::Epilogue(_) => Visibility::Default,
        }
    }

    /// Returns a struct that can be used to print debug information about the specified symbol.
    pub(crate) fn symbol_debug(&self, symbol_id: SymbolId) -> SymbolDebug<'_, 'data> {
        SymbolDebug {
            db: self,
            symbol_id,
        }
    }

    pub(crate) fn symbol_name_for_display(&self, symbol_id: SymbolId) -> SymbolNameDisplay<'data> {
        SymbolNameDisplay {
            name: self.symbol_name(symbol_id).ok(),
            demangle: self.args.demangle,
        }
    }

    pub(crate) fn symbol_name(&self, symbol_id: SymbolId) -> Result<UnversionedSymbolName<'data>> {
        let file_id = self.file_id_for_symbol(symbol_id);
        match &self.groups[file_id.group()] {
            Group::Prelude(prelude) => Ok(prelude.symbol_name(symbol_id, self.args.output_kind())),
            Group::Objects(parsed_input_objects) => {
                parsed_input_objects[file_id.file()].symbol_name(symbol_id)
            }
            Group::LinkerScripts(scripts) => Ok(scripts[file_id.file()].symbol_name(symbol_id)),
            Group::Epilogue(epilogue) => {
                Ok(self.start_stop_symbol_names[symbol_id.offset_from(epilogue.start_symbol_id)])
            }
        }
    }

    /// Returns the value flags for the specified symbol without taking into consideration what
    /// symbol is the definition.
    pub(crate) fn local_symbol_value_flags(&self, symbol_id: SymbolId) -> ValueFlags {
        self.symbol_value_flags[symbol_id.as_usize()]
    }

    pub(crate) fn symbol_value_flags(&self, symbol_id: SymbolId) -> ValueFlags {
        let mut flags = self.local_symbol_value_flags(self.definition(symbol_id));
        flags.merge(self.local_symbol_value_flags(symbol_id));
        flags
    }

    pub(crate) fn num_symbols(&self) -> usize {
        self.symbol_definitions.len()
    }

    pub(crate) fn num_objects(&self) -> usize {
        self.groups
            .iter()
            .map(|group| match group {
                Group::Prelude(_) => 0,
                Group::Objects(parsed_input_objects) => parsed_input_objects.len(),
                Group::LinkerScripts(_) => 0,
                Group::Epilogue(_) => 0,
            })
            .sum()
    }

    /// If we have a symbol that when demangled produces `target_name`, then return the mangled
    /// name. Note, this scans every symbol, so should only be used for debugging / diagnostic
    /// purposes.
    pub(crate) fn find_mangled_name(&self, target_name: &str) -> Option<String> {
        for i in 1..self.num_symbols() {
            let symbol_id = SymbolId(i as u32);
            let Ok(name) = self.symbol_name(symbol_id) else {
                continue;
            };

            let Ok(name) = std::str::from_utf8(name.bytes()) else {
                continue;
            };

            if demangle(name) == target_name {
                return Some(name.to_owned());
            }
        }

        None
    }

    /// Returns our mapping from symbol IDs to the IDs that define them. Definitions should be
    /// restored later by calling `restore_definitions`. While the definitions are taken, any method
    /// that requires definitions will fail.
    pub(crate) fn take_definitions(&mut self) -> Vec<SymbolId> {
        take(&mut self.symbol_definitions)
    }

    pub(crate) fn restore_definitions(&mut self, definitions: Vec<SymbolId>) {
        self.symbol_definitions = definitions;
    }

    pub(crate) fn file_id_for_symbol(&self, symbol_id: SymbolId) -> FileId {
        self.symbol_file_ids
            .get(symbol_id.as_usize())
            .copied()
            .unwrap_or(self.epilogue_file_id)
    }

    /// Returns whether the supplied symbol ID is the canonical ID. A symbol won't be canonical, if
    /// it resolves to a different symbol. The symbol may still be undefined.
    pub(crate) fn is_canonical(&self, symbol_id: SymbolId) -> bool {
        let resolution = self.symbol_definitions[symbol_id.as_usize()];
        resolution == symbol_id
    }

    pub(crate) fn definition(&self, symbol_id: SymbolId) -> SymbolId {
        // We need to do two steps when finding the definition for a symbol, since the definition
        // may have changed since we did the original name lookup. It would be possible to avoid
        // this, by resolving all definitions before we resolve references, except then, due to
        // archive semantics, we'd need to do two passes to resolve symbols, one to determine which
        // archive members to load, then a second to determine which symbols to use.
        let step1 = self.symbol_definitions[symbol_id.as_usize()];
        self.symbol_definitions[step1.as_usize()]
    }

    pub(crate) fn replace_definition(&mut self, symbol_id: SymbolId, new_definition: SymbolId) {
        self.symbol_definitions[symbol_id.as_usize()] = new_definition;
    }

    pub(crate) fn file(&self, file_id: FileId) -> ParsedInput {
        match &self.groups[file_id.group()] {
            Group::Prelude(prelude) => ParsedInput::Prelude(prelude),
            Group::Objects(parsed_input_objects) => {
                ParsedInput::Object(&parsed_input_objects[file_id.file()])
            }
            Group::LinkerScripts(scripts) => ParsedInput::LinkerScript(&scripts[file_id.file()]),
            Group::Epilogue(epilogue) => ParsedInput::Epilogue(epilogue),
        }
    }

    pub(crate) fn is_mapping_symbol(&self, symbol_id: SymbolId) -> bool {
        let Ok(name) = self.symbol_name(symbol_id) else {
            // We don't want to bother the caller with an error here. If there's a problem getting
            // the name, it will be reported elsewhere.
            return false;
        };
        is_mapping_symbol_name(name.bytes())
    }

    pub(crate) fn get_unversioned(
        &self,
        prehashed: &PreHashed<UnversionedSymbolName>,
    ) -> Option<SymbolId> {
        let num_buckets = self.buckets.len();
        self.buckets[prehashed.hash() as usize % num_buckets]
            .name_to_id
            .get(prehashed)
            .copied()
    }

    #[inline(always)]
    pub(crate) fn get(&self, key: &PreHashedSymbolName) -> Option<SymbolId> {
        let num_buckets = self.buckets.len();

        match key {
            PreHashedSymbolName::Unversioned(key) => self.buckets
                [key.hash() as usize % num_buckets]
                .name_to_id
                .get(key)
                .copied(),
            PreHashedSymbolName::Versioned(key) => self.buckets[key.hash() as usize % num_buckets]
                .versioned_name_to_id
                .get(key)
                .copied(),
        }
    }

    pub(crate) fn all_unversioned_symbols(
        &self,
    ) -> impl Iterator<Item = (&PreHashed<UnversionedSymbolName>, &SymbolId)> {
        self.buckets.iter().flat_map(|b| b.name_to_id.iter())
    }

    #[inline(always)]
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
            } else if obj_symbol.st_bind() == object::elf::STB_GNU_UNIQUE {
                SymbolStrength::GnuUnique
            } else {
                SymbolStrength::Strong
            }
        } else {
            SymbolStrength::Undefined
        }
    }

    /// Returns whether the specified symbol is defined in a section with the SHF_GROUP flag set.
    fn is_in_comdat_group(&self, symbol_id: SymbolId, resolved: &[ResolvedGroup]) -> bool {
        let file_id = self.file_id_for_symbol(symbol_id);
        let ResolvedFile::Object(obj) = &resolved[file_id.group()].files[file_id.file()] else {
            return false;
        };

        let local_index = symbol_id.to_input(obj.symbol_id_range);
        let Ok(obj_symbol) = obj.object.symbol(local_index) else {
            return false;
        };

        let section_index = object::SectionIndex(usize::from(obj_symbol.st_shndx(LittleEndian)));
        let Ok(header) = obj.object.section(section_index) else {
            return false;
        };

        let flags = SectionFlags::from_header(header);

        flags.contains(shf::GROUP)
    }

    pub(crate) fn entry_symbol_name(&self) -> &[u8] {
        // The --entry flag is used first, falling back to what the linker script says, or otherwise
        // defaults to `_start`.
        self.args
            .entry
            .as_ref()
            .map(|n| n.as_bytes())
            .or(self.entry)
            .unwrap_or(b"_start")
    }

    fn apply_linker_script(&mut self, script: &InputLinkerScript<'data>) {
        for cmd in &script.script.commands {
            if let crate::linker_script::Command::Entry(symbol_name) = cmd {
                self.entry = Some(*symbol_name);
            }
        }
    }
}

impl<'data> SymbolBucket<'data> {
    fn add_symbol(&mut self, pending: &PendingSymbol<'data>) {
        match self.name_to_id.entry(pending.name) {
            hash_map::Entry::Occupied(entry) => {
                let first_symbol_id = *entry.get();
                self.add_extra_symbol_definition(first_symbol_id, pending.symbol_id);
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(pending.symbol_id);
            }
        }
    }

    fn add_versioned_symbol(&mut self, pending: &PendingVersionedSymbol<'data>) {
        match self.versioned_name_to_id.entry(pending.name) {
            hash_map::Entry::Occupied(entry) => {
                let first_symbol_id = *entry.get();
                self.alternative_versioned_definitions
                    .entry(first_symbol_id)
                    .or_default()
                    .push(pending.symbol_id);
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(pending.symbol_id);
            }
        }
    }

    fn add_extra_symbol_definition(&mut self, first_symbol_id: SymbolId, new_symbol_id: SymbolId) {
        self.alternative_definitions
            .entry(first_symbol_id)
            .or_default()
            .push(new_symbol_id);
    }
}

/// For each symbol that has multiple definitions, some of which may be weak, some strong, some
/// "common" symbols and some in archive entries that weren't loaded, resolve which version of the
/// symbol we're using. The symbol we select will be the first strongly defined symbol in a loaded
/// object, or if there are no strong definitions, then the first definition in a loaded object. If
/// a symbol definition is a common symbol, then the largest definition will be used.
#[tracing::instrument(skip_all, name = "Resolve alternative symbol definitions")]
pub(crate) fn resolve_alternative_symbol_definitions<'data>(
    symbol_db: &mut SymbolDb<'data>,
    resolved: &[ResolvedGroup],
) -> Result {
    let mut buckets = take(&mut symbol_db.buckets);
    let error_queue = SegQueue::new();

    let replacements: Vec<Vec<SymbolReplacement>> = buckets
        .par_iter_mut()
        .map(|bucket| {
            let mut local_replacements = Vec::new();

            process_alternatives(
                &mut bucket.alternative_definitions,
                &mut local_replacements,
                &error_queue,
                symbol_db,
                resolved,
            );

            process_alternatives(
                &mut bucket.alternative_versioned_definitions,
                &mut local_replacements,
                &error_queue,
                symbol_db,
                resolved,
            );

            local_replacements
        })
        .collect();

    let mut duplicate_errors: Vec<anyhow::Error> = error_queue.into_iter().collect();
    duplicate_errors.sort_by_key(|e| e.to_string());

    if !duplicate_errors.is_empty() {
        let error_details = duplicate_errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        return Err(anyhow::Error::msg(format!(
            "Duplicate symbols detected: {error_details}"
        )));
    }

    for r in replacements.iter().flat_map(|r| r.iter()) {
        // TODO: Currently we only make the symbol non-interposable, but we should also actually
        // change its visibility too. We need somewhere to store this information. We also need
        // linker-diff to report when we get exported dynamic symbols wrong.
        if r.visibility != Visibility::Default {
            let value_flags = &mut symbol_db.symbol_value_flags[r.replace.as_usize()];
            if !value_flags.contains(ValueFlags::DYNAMIC) {
                *value_flags |= ValueFlags::NON_INTERPOSABLE;
            }
        }
        symbol_db.replace_definition(r.replace, r.selected);
    }

    symbol_db.buckets = buckets;

    Ok(())
}

#[derive(Clone, Copy)]
struct SymbolReplacement {
    /// The symbol to be replaced.
    replace: SymbolId,

    /// The symbol that was selected as the definition to use.
    selected: SymbolId,

    visibility: Visibility,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Visibility {
    Default,
    Protected,
    Hidden,
}

fn process_alternatives(
    alternative_definitions: &mut HashMap<SymbolId, Vec<SymbolId>>,
    local_replacements: &mut Vec<SymbolReplacement>,
    error_queue: &SegQueue<Error>,
    symbol_db: &SymbolDb,
    resolved: &[ResolvedGroup],
) {
    for (first, alternatives) in replace(
        alternative_definitions,
        HashMap::with_hasher(RandomState::default()),
    ) {
        // Compute the most restrictive visibility of any of the alternative definitions. This is
        // the visibility we'll use for our selected symbol. This seems like odd behaviour, but it
        // matches what GNU ld appears to do and some programs will fail to link if we don't do
        // this.
        let visibility = alternatives
            .iter()
            .fold(symbol_db.input_symbol_visibility(first), |vis, id| {
                vis.max(symbol_db.input_symbol_visibility(*id))
            });

        match select_symbol(symbol_db, first, &alternatives, resolved) {
            Ok(selected) => {
                local_replacements.push(SymbolReplacement {
                    replace: first,
                    selected,
                    visibility,
                });

                for alt in alternatives {
                    local_replacements.push(SymbolReplacement {
                        replace: alt,
                        selected,
                        visibility,
                    });
                }
            }
            Err(err) => {
                error_queue.push(err);
            }
        }
    }
}

/// Selects which version of the symbol to use.
#[inline(always)]
fn select_symbol(
    symbol_db: &SymbolDb,
    symbol_id: SymbolId,
    alternatives: &[SymbolId],
    resolved: &[ResolvedGroup],
) -> Result<SymbolId, anyhow::Error> {
    let mut max_common = None;
    let mut strong_symbol = None;

    let all_symbols = std::iter::once(symbol_id).chain(alternatives.iter().copied());

    for alt in all_symbols {
        if symbol_db.symbol_value_flags(alt).is_dynamic() {
            continue;
        }

        let strength = symbol_db.symbol_strength(alt, resolved);
        match strength {
            SymbolStrength::Strong => {
                if let Some(existing) = strong_symbol {
                    // We don't implement full COMDAT logic, however if we encounter duplicate
                    // strong definitions, then we don't emit errors if all the strong definitions
                    // are defined in COMDAT group sections.
                    if !symbol_db.is_in_comdat_group(existing, resolved)
                        || !symbol_db.is_in_comdat_group(alt, resolved)
                    {
                        bail!(
                            "{}, defined in {} and {}",
                            symbol_db.symbol_name_for_display(symbol_id),
                            symbol_db.file(symbol_db.file_id_for_symbol(existing)),
                            symbol_db.file(symbol_db.file_id_for_symbol(alt)),
                        );
                    }
                } else {
                    strong_symbol = Some(alt);
                }
            }
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

    if let Some(strong_symbol) = strong_symbol {
        return Ok(strong_symbol);
    }

    if let Some((_, alt)) = max_common {
        return Ok(alt);
    }

    let first_strength = symbol_db.symbol_strength(symbol_id, resolved);
    if first_strength != SymbolStrength::Undefined {
        return Ok(symbol_id);
    }

    for &alt in alternatives.iter().rev() {
        let strength = symbol_db.symbol_strength(alt, resolved);
        if strength != SymbolStrength::Undefined {
            return Ok(alt);
        }
    }

    Ok(symbol_id)
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum SymbolStrength {
    /// The object containing this symbol wasn't loaded, so the definition can be ignored.
    Undefined,

    /// The object weakly defines the symbol.
    Weak,

    /// The object uses STB_GNU_UNIQUE binding.
    GnuUnique,

    /// The object strongly defines the symbol.
    Strong,

    /// The symbol is a "common" symbol with the specified size. The definition with the largest
    /// size will be selected.
    Common(u64),
}

/// Returns whether the supplied symbol name is for a [mapping
/// symbol](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#mapping-symbols).
pub(crate) fn is_mapping_symbol_name(name: &[u8]) -> bool {
    name.starts_with(b"$x") || name.starts_with(b"$d")
}

#[tracing::instrument(skip_all, name = "Read symbols")]
fn read_symbols<'data, 'out>(
    groups: &[Group<'data>],
    version_script: &VersionScript,
    symbols_out_by_group: &mut [SymbolInfoWriter],
    args: &Args,
) -> Result<Vec<SymbolLoadOutputs<'data>>> {
    let num_buckets = num_symbol_hash_buckets(args);

    groups
        .par_iter()
        .zip(symbols_out_by_group)
        .map(|(group, symbols_out)| {
            let mut outputs = SymbolLoadOutputs {
                pending_symbols_by_bucket: vec![PendingSymbolHashBucket::default(); num_buckets],
            };

            match group {
                Group::Prelude(prelude) => {
                    prelude.load_symbols(symbols_out, &mut outputs, args.output_kind());
                }
                Group::Objects(parsed_input_objects) => {
                    for obj in *parsed_input_objects {
                        load_symbols_from_file(
                            obj,
                            version_script,
                            symbols_out,
                            &mut outputs,
                            args,
                        )
                        .with_context(|| format!("Failed to load symbols from `{}`", obj.input))?;
                    }
                }
                Group::LinkerScripts(scripts) => {
                    for script in scripts {
                        load_linker_script_symbols(script, symbols_out, &mut outputs);
                    }
                }
                Group::Epilogue(_) => {
                    // Custom section start/stop symbols are generated after archive handling.
                }
            }

            Ok(outputs)
        })
        .collect::<Result<Vec<SymbolLoadOutputs>>>()
}

fn load_linker_script_symbols<'data>(
    script: &ProcessedLinkerScript<'data>,
    symbols_out: &mut SymbolInfoWriter,
    outputs: &mut SymbolLoadOutputs<'data>,
) {
    for (offset, name) in script.symbol_names.iter().enumerate() {
        let symbol_id = script.symbol_id_range.offset_to_id(offset);

        outputs.add_non_versioned(PendingSymbol::from_prehashed(
            symbol_id,
            PreHashed::new(*name, hash_bytes(name.bytes())),
        ));

        symbols_out.set_next(
            ValueFlags::ADDRESS | ValueFlags::NON_INTERPOSABLE,
            symbol_id,
            script.file_id,
        );
    }
}

fn load_symbols_from_file<'data>(
    s: &ParsedInputObject<'data>,
    version_script: &VersionScript,
    symbols_out: &mut SymbolInfoWriter,
    outputs: &mut SymbolLoadOutputs<'data>,
    args: &Args,
) -> Result {
    if s.is_dynamic() {
        DynamicObjectSymbolLoader::new(&s.object)?.load_symbols(s.file_id, symbols_out, outputs)
    } else {
        RegularObjectSymbolLoader {
            object: &s.object,
            args,
            version_script,
        }
        .load_symbols(s.file_id, symbols_out, outputs)
    }
}

fn value_flags_from_elf_symbol(sym: &crate::elf::Symbol, args: &Args) -> ValueFlags {
    let is_undefined = sym.is_undefined(LittleEndian);

    let non_interposable = sym.st_visibility() != object::elf::STV_DEFAULT
        || sym.is_local()
        || args.output_kind().is_static_executable()
        // Symbols defined in an executable cannot be interposed since the executable is always the
        // first place checked for a symbol by the dynamic loader.
        || (args.output_kind().is_executable() && !is_undefined);

    let mut flags: ValueFlags = if sym.is_absolute(LittleEndian) {
        ValueFlags::ABSOLUTE
    } else if sym.st_type() == object::elf::STT_GNU_IFUNC {
        ValueFlags::IFUNC
    } else if is_undefined {
        if non_interposable {
            ValueFlags::ABSOLUTE
        } else {
            // If we can't bypass the GOT, then an undefined symbol might be able to be defined at
            // runtime by a dynamic library that gets loaded.
            ValueFlags::DYNAMIC | ValueFlags::ABSOLUTE
        }
    } else {
        ValueFlags::ADDRESS
    };

    if non_interposable {
        flags |= ValueFlags::NON_INTERPOSABLE;
    }
    flags
}

struct SymbolInfoWriter<'out> {
    resolutions: sharded_vec_writer::Shard<'out, SymbolId>,
    value_kinds: sharded_vec_writer::Shard<'out, ValueFlags>,
    file_ids: sharded_vec_writer::Shard<'out, FileId>,
    next: SymbolId,
}

impl<'out> SymbolInfoWriter<'out> {
    fn new(
        base: SymbolId,
        resolutions: sharded_vec_writer::Shard<'out, SymbolId>,
        value_kinds: sharded_vec_writer::Shard<'out, ValueFlags>,
        file_ids: sharded_vec_writer::Shard<'out, FileId>,
    ) -> Self {
        Self {
            resolutions,
            value_kinds,
            file_ids,
            next: base,
        }
    }

    fn set_next(&mut self, value_flags: ValueFlags, resolution: SymbolId, file_id: FileId) {
        debug_assert!(file_id != UNINITIALISED_FILE_ID);
        self.value_kinds.push(value_flags);
        self.resolutions.push(resolution);
        self.file_ids.push(file_id);
        self.next = SymbolId::from_usize(self.next.as_usize() + 1);
    }
}

trait SymbolLoader<'data> {
    fn load_symbols(
        &self,
        file_id: FileId,
        symbols_out: &mut SymbolInfoWriter,
        outputs: &mut SymbolLoadOutputs<'data>,
    ) -> Result {
        let e = LittleEndian;
        let base_symbol_id = symbols_out.next;

        for symbol in self.object().symbols.iter() {
            let symbol_id = symbols_out.next;
            let mut value_flags = self.compute_value_flags(symbol);

            if symbol.is_undefined(e) || self.should_ignore_symbol(symbol) {
                symbols_out.set_next(value_flags, SymbolId::undefined(), file_id);
                continue;
            }

            let resolution = symbol_id;

            let local_index = symbol_id.offset_from(base_symbol_id);

            if symbol.is_local() {
                symbols_out.set_next(value_flags, resolution, file_id);
                continue;
            }

            let info = self.get_symbol_name_and_version(symbol, local_index)?;

            let name = UnversionedSymbolName::prehashed(info.name_bytes);

            if self.should_downgrade_to_local(&name) {
                value_flags |= ValueFlags::DOWNGRADE_TO_LOCAL;
                // If we're downgrading to a local, then we're writing a shared object. Shared
                // objects should never bypass the GOT for TLS variables.
                if symbol.st_type() != object::elf::STT_TLS {
                    value_flags |= ValueFlags::NON_INTERPOSABLE;
                }
            }

            if info.is_default {
                let pending = PendingSymbol::from_prehashed(symbol_id, name);
                outputs.add_non_versioned(pending);
            }

            if let Some(version) = info.version_name {
                let pending = PendingVersionedSymbol::from_prehashed(symbol_id, name, version);
                outputs.add_versioned(pending);
            }

            symbols_out.set_next(value_flags, resolution, file_id);
        }

        Ok(())
    }

    fn object(&self) -> &crate::elf::File<'data>;

    fn compute_value_flags(&self, symbol: &crate::elf::Symbol) -> ValueFlags;

    /// Returns whether we should downgrade a symbol with the specified name to be a local.
    fn should_downgrade_to_local(&self, _name: &PreHashed<UnversionedSymbolName>) -> bool {
        false
    }

    /// Returns whether the supplied symbol should be ignore.
    fn should_ignore_symbol(&self, _symbol: &crate::elf::Symbol) -> bool {
        false
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &crate::elf::Symbol,
        local_index: usize,
    ) -> Result<RawSymbolName<'data>>;
}

pub(crate) struct RawSymbolName<'data> {
    pub(crate) name_bytes: &'data [u8],

    pub(crate) version_name: Option<&'data [u8]>,

    /// Whether the symbol can be referred to without a version.
    pub(crate) is_default: bool,
}

struct RegularObjectSymbolLoader<'a, 'data> {
    object: &'a crate::elf::File<'data>,
    args: &'a Args,
    version_script: &'a VersionScript<'a>,
}

struct DynamicObjectSymbolLoader<'a, 'data> {
    object: &'a crate::elf::File<'data>,
    version_names: Vec<Option<&'data [u8]>>,
}

impl<'a, 'data> DynamicObjectSymbolLoader<'a, 'data> {
    fn new(object: &'a crate::elf::File<'data>) -> Result<Self> {
        let endian = LittleEndian;

        let mut version_names = vec![None; object.verdefnum as usize + 1];

        // See https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/symversion.html
        // for information about symbol versioning.

        if let Some((verdefs, string_table_index)) = &object.verdef {
            let strings = object
                .sections
                .strings(endian, object.data, *string_table_index)?;

            for r in verdefs.clone() {
                let (verdef, mut aux_iterator) = r?;
                // Every VERDEF entry should have at least one AUX entry. We currently only care
                // about the first one.
                let aux = aux_iterator.next()?.context("VERDEF with no AUX entry")?;
                let version_index = verdef.vd_ndx.get(endian);
                let name = aux.name(endian, strings)?;

                *version_names
                    .get_mut(usize::from(version_index))
                    .with_context(|| format!("Invalid version index {version_index}"))? =
                    Some(name);
            }
        }

        Ok(Self {
            object,
            version_names,
        })
    }
}

impl<'data> SymbolLoader<'data> for RegularObjectSymbolLoader<'_, 'data> {
    fn compute_value_flags(&self, symbol: &crate::elf::Symbol) -> ValueFlags {
        value_flags_from_elf_symbol(symbol, self.args)
    }

    fn should_downgrade_to_local(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        self.version_script.is_local(name)
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &crate::elf::Symbol,
        _local_index: usize,
    ) -> Result<RawSymbolName<'data>> {
        Ok(RawSymbolName::parse(self.object.symbol_name(symbol)?))
    }

    fn object(&self) -> &crate::elf::File<'data> {
        self.object
    }
}

impl<'data> RawSymbolName<'data> {
    pub(crate) fn parse(mut name_bytes: &'data [u8]) -> Self {
        let mut version_name = None;
        let mut is_default = true;

        // Symbols can contain version specifiers, e.g. `foo@1.1` or `foo@@2.0`. The latter,
        // with double-at specifies that it's the default version.
        if let Some(at_offset) = memchr::memchr(b'@', name_bytes) {
            if name_bytes[at_offset..].starts_with(b"@@") {
                version_name = Some(&name_bytes[at_offset + 2..]);
            } else {
                version_name = Some(&name_bytes[at_offset + 1..]);
                is_default = false;
            }

            name_bytes = &name_bytes[..at_offset];
        }

        RawSymbolName {
            name_bytes,
            version_name,
            is_default,
        }
    }
}

impl<'data> SymbolLoader<'data> for DynamicObjectSymbolLoader<'_, 'data> {
    fn compute_value_flags(&self, symbol: &crate::elf::Symbol) -> ValueFlags {
        let mut flags = ValueFlags::DYNAMIC;
        let st_type = symbol.st_type();
        if st_type == object::elf::STT_FUNC || st_type == object::elf::STT_GNU_IFUNC {
            flags |= ValueFlags::FUNCTION;
        }
        if symbol.is_undefined(LittleEndian) {
            flags |= ValueFlags::ABSOLUTE;
        }
        flags
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &crate::elf::Symbol,
        local_index: usize,
    ) -> Result<RawSymbolName<'data>> {
        let name_bytes = self.object.symbol_name(symbol)?;

        let is_default;
        let version_name;

        if let Some(versym) = self.object.versym.get(local_index) {
            let versym = versym.0.get(LittleEndian);
            is_default = versym & object::elf::VERSYM_HIDDEN == 0;
            let version_index = versym & object::elf::VERSYM_VERSION;
            version_name = self
                .version_names
                .get(usize::from(version_index))
                .copied()
                .flatten();
        } else {
            is_default = true;
            version_name = None;
        };

        Ok(RawSymbolName {
            name_bytes,
            version_name,
            is_default,
        })
    }

    fn object(&self) -> &crate::elf::File<'data> {
        self.object
    }

    fn should_ignore_symbol(&self, symbol: &crate::elf::Symbol) -> bool {
        // Shared objects shouldn't export hidden symbols. If for some reason they do, ignore them.
        crate::elf::is_hidden_symbol(symbol)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SymbolDebug<'db, 'data> {
    db: &'db SymbolDb<'data>,
    symbol_id: SymbolId,
}

impl std::fmt::Display for SymbolDebug<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let symbol_id = self.symbol_id;
        let symbol_name = self
            .db
            .symbol_name(symbol_id)
            .unwrap_or_else(|_| UnversionedSymbolName::new(b"??"));
        let definition = self.db.definition(symbol_id);
        let file_id = self.db.file_id_for_symbol(symbol_id);
        let file = self.db.file(file_id);
        let local_index = symbol_id.to_offset(file.symbol_id_range());
        if definition.is_undefined() {
            write!(f, "undefined ")?;
        }
        if symbol_name.bytes().is_empty() {
            match file {
                ParsedInput::Prelude(_) => write!(f, "<unnamed internal symbol>")?,
                ParsedInput::Object(o) => {
                    let symbol_index = symbol_id.to_input(file.symbol_id_range());
                    if let Some(section_name) = o
                        .object
                        .symbol(symbol_index)
                        .ok()
                        .and_then(|symbol| {
                            o.object.symbol_section(symbol, symbol_index).ok().flatten()
                        })
                        .map(|section_index| o.object.section_display_name(section_index))
                    {
                        write!(f, "section `{section_name}`")?;
                    } else {
                        write!(f, "<unnamed symbol>")?;
                    }
                }
                ParsedInput::LinkerScript(s) => {
                    write!(f, "Symbol from linker script `{}`", s.input)?;
                }
                ParsedInput::Epilogue(_) => write!(f, "<unnamed custom-section symbol>")?,
            }
        } else {
            write!(f, "symbol `{}`", self.db.symbol_name_for_display(symbol_id))?;
        }
        write!(
            f,
            " ({symbol_id} local={local_index}) in file #{file_id} ({file})"
        )?;
        if symbol_id != definition && !definition.is_undefined() {
            let definition_file_id = self.db.file_id_for_symbol(definition);
            let definition_file = self.db.file(definition_file_id);
            write!(
                f,
                " defined as {definition} in file #{definition_file_id} ({definition_file})"
            )?;
        }
        write!(f, " ({})", self.db.local_symbol_value_flags(symbol_id))?;
        Ok(())
    }
}

impl SymbolId {
    pub(crate) fn undefined() -> Self {
        Self(0)
    }

    pub(crate) fn from_usize(value: usize) -> SymbolId {
        Self::new(u32::try_from(value).expect("Symbols overflowed 32 bits"))
    }

    const fn new(value: u32) -> SymbolId {
        SymbolId(value)
    }

    pub(crate) fn offset_from(self, base: SymbolId) -> usize {
        (self.0 - base.0) as usize
    }

    pub(crate) fn to_offset(self, range: SymbolIdRange) -> usize {
        range.id_to_offset(self)
    }

    pub(crate) fn to_input(self, range: SymbolIdRange) -> object::SymbolIndex {
        range.id_to_input(self)
    }

    pub(crate) fn is_undefined(self) -> bool {
        self.0 == 0
    }

    pub(crate) fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl TryFrom<usize> for SymbolId {
    type Error = crate::error::Error;

    fn try_from(value: usize) -> std::result::Result<Self, Self::Error> {
        Ok(SymbolId(u32::try_from(value).context("Too many symbols")?))
    }
}

impl Prelude<'_> {
    fn load_symbols(
        &self,
        symbols_out: &mut SymbolInfoWriter,
        outputs: &mut SymbolLoadOutputs,
        output_kind: OutputKind,
    ) {
        for definition in &self.symbol_definitions {
            let symbol_id = symbols_out.next;
            let value_flags = match definition {
                InternalSymDefInfo::Undefined | InternalSymDefInfo::ForceUndefined(_) => {
                    ValueFlags::ABSOLUTE
                }
                InternalSymDefInfo::SectionStart(section_id) => {
                    let def = section_id.built_in_details();
                    let name = def.start_symbol_name(output_kind).unwrap().as_bytes();
                    outputs.add_non_versioned(PendingSymbol::new(symbol_id, name));
                    ValueFlags::ADDRESS | ValueFlags::NON_INTERPOSABLE
                }
                InternalSymDefInfo::SectionEnd(section_id) => {
                    let def = section_id.built_in_details();
                    let name = def.end_symbol_name(output_kind).unwrap().as_bytes();
                    outputs.add_non_versioned(PendingSymbol::new(symbol_id, name));
                    ValueFlags::ADDRESS | ValueFlags::NON_INTERPOSABLE
                }
            };
            symbols_out.set_next(value_flags, symbol_id, PRELUDE_FILE_ID);
        }
    }
}

impl std::fmt::Display for SymbolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl InternalSymDefInfo {
    pub(crate) fn section_id(self) -> Option<OutputSectionId> {
        match self {
            InternalSymDefInfo::Undefined | InternalSymDefInfo::ForceUndefined(_) => None,
            InternalSymDefInfo::SectionStart(i) => Some(i),
            InternalSymDefInfo::SectionEnd(i) => Some(i),
        }
    }
}

impl<'data> PendingSymbol<'data> {
    fn new(symbol_id: SymbolId, name: &'data [u8]) -> PendingSymbol<'data> {
        Self::from_prehashed(symbol_id, UnversionedSymbolName::prehashed(name))
    }

    fn from_prehashed(
        symbol_id: SymbolId,
        name: PreHashed<UnversionedSymbolName<'data>>,
    ) -> PendingSymbol<'data> {
        PendingSymbol { symbol_id, name }
    }
}

impl<'data> PendingVersionedSymbol<'data> {
    fn from_prehashed(
        symbol_id: SymbolId,
        name: PreHashed<UnversionedSymbolName<'data>>,
        version: &'data [u8],
    ) -> PendingVersionedSymbol<'data> {
        PendingVersionedSymbol {
            symbol_id,
            name: VersionedSymbolName::prehashed(name, version),
        }
    }
}

/// Decides how many buckets we should use for symbol names.
fn num_symbol_hash_buckets(args: &Args) -> usize {
    args.num_threads.get()
}

impl<'data> SymbolLoadOutputs<'data> {
    fn add_non_versioned(&mut self, pending: PendingSymbol<'data>) {
        let num_buckets = self.pending_symbols_by_bucket.len();

        self.pending_symbols_by_bucket[pending.name.hash() as usize % num_buckets]
            .symbols
            .push(pending);
    }

    fn add_versioned(&mut self, pending: PendingVersionedSymbol<'data>) {
        let num_buckets = self.pending_symbols_by_bucket.len();

        self.pending_symbols_by_bucket[pending.name.hash() as usize % num_buckets]
            .versioned_symbols
            .push(pending);
    }
}

impl ShardKey for SymbolId {
    fn zero() -> Self {
        SymbolId(0)
    }

    fn add_usize(self, offset: usize) -> Self {
        SymbolId(
            (self.as_usize() + offset)
                .try_into()
                .expect("Symbol ID overflowed 32 bits"),
        )
    }

    fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl Display for RawSymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.name_bytes))?;
        if let Some(version) = self.version_name {
            if self.is_default {
                write!(f, "@@")?;
            } else {
                write!(f, "@")?;
            }
            write!(f, "{}", String::from_utf8_lossy(version))?;
        }

        Ok(())
    }
}

impl Display for SymbolNameDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = self.name {
            if let Ok(s) = std::str::from_utf8(name.bytes()) {
                if self.demangle {
                    Display::fmt(&symbolic_demangle::demangle(s), f)
                } else {
                    Display::fmt(s, f)
                }
            } else {
                write!(f, "INVALID UTF-8({:?})", name.bytes())
            }
        } else {
            write!(f, "SYMBOL-READ-ERROR")
        }
    }
}
