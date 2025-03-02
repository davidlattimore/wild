//! Reads global symbols for each input file and builds a map from symbol names to IDs together with
//! information about where each symbol can be obtained.

use crate::args::Args;
use crate::args::OutputKind;
use crate::error::Result;
use crate::grouping::Group;
use crate::hash::PassThroughHashMap;
use crate::hash::PreHashed;
use crate::input_data::FileId;
use crate::input_data::PRELUDE_FILE_ID;
use crate::input_data::UNINITIALISED_FILE_ID;
use crate::input_data::VersionScriptData;
use crate::linker_script::VersionScript;
use crate::output_section_id::OutputSectionId;
use crate::parsing::InternalSymDefInfo;
use crate::parsing::ParsedInput;
use crate::parsing::Prelude;
use crate::resolution::ValueFlags;
use crate::sharding::ShardKey;
use crate::symbol::PreHashedSymbolName;
use crate::symbol::UnversionedSymbolName;
use crate::symbol::VersionedSymbolName;
use ahash::HashMap;
use ahash::RandomState;
use anyhow::Context;
use itertools::Itertools;
use object::LittleEndian;
use object::read::elf::Sym as _;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use std::collections::hash_map;
use std::fmt::Display;
use std::mem::replace;
use std::mem::take;

pub struct SymbolDb<'data> {
    pub(crate) args: &'data Args,

    pub(crate) groups: &'data [Group<'data>],

    /// Mapping from global symbol names to a symbol ID with that name. If there are multiple
    /// globals with the same name, then this will point to the one we encountered first, which may
    /// not be the selected definition. In order to find the selected definition, you still need to
    /// look a `symbol_definitions`.
    name_to_id: PassThroughHashMap<UnversionedSymbolName<'data>, SymbolId>,
    versioned_name_to_id: PassThroughHashMap<VersionedSymbolName<'data>, SymbolId>,

    /// Which file each symbol ID belongs to. Indexes past the end are assumed to be for custom
    /// section start/stop symbols.
    symbol_file_ids: Vec<FileId>,

    /// Mapping from symbol IDs to the canonical definition of that symbol. For global symbols that
    /// were selected as the definition and for all locals, this will point to itself. e.g. the
    /// value at index 5 will be the symbol ID 5.
    symbol_definitions: Vec<SymbolId>,

    symbol_value_flags: Vec<ValueFlags>,

    /// Global symbols that have multiple definitions. Indexed by symbol ID. It'd be nice if we
    /// didn't need to store this and could just determine the canonical definition as we add
    /// symbols. Unfortunately archive semantics make that impossible because we don't yet know
    /// which archive entries will and won't be loaded. For the first symbol with a name, this
    /// points to the last symbol with that name. That in turn then points to each previous
    /// alternate definition with that name until the undefined symbol is reached.
    pub(crate) alternative_definitions: Vec<SymbolId>,

    /// Alternative definitions, but only for versioned symbols. This might be more efficient with a
    /// proper multi-map that doesn't need a separate Vec for each value, however we don't expect
    /// many entries here.
    pub(crate) alternative_versioned_definitions: HashMap<SymbolId, Vec<SymbolId>>,

    /// The symbol IDs of the first symbol with each name for which there are alternative
    /// definitions. This can be used to find the head of a linked list in
    /// `alternative_definitions`.
    pub(crate) symbols_with_alternatives: Vec<SymbolId>,

    /// The number of symbols in each group, keyed by the index of the group.
    pub(crate) num_symbols_per_group: Vec<usize>,

    epilogue_file_id: FileId,

    /// The names of symbols that mark the start / stop of sections. These are indexed by the offset
    /// into the epilogue's symbol IDs.
    start_stop_symbol_names: Vec<UnversionedSymbolName<'data>>,
}

/// A global symbol that hasn't been put into our database yet.
#[derive(Clone, Copy)]
pub(crate) struct PendingSymbol<'data> {
    pub(crate) symbol_id: SymbolId,
    pub(crate) name: PreHashed<UnversionedSymbolName<'data>>,
}

#[derive(Clone, Copy)]
pub(crate) struct PendingVersionedSymbol<'data> {
    pub(crate) symbol_id: SymbolId,
    pub(crate) name: PreHashed<VersionedSymbolName<'data>>,
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

#[derive(Default)]
struct SymbolLoadOutputs<'data> {
    pending_symbols: Vec<PendingSymbol<'data>>,
    pending_versioned_symbols: Vec<PendingVersionedSymbol<'data>>,
}

impl<'data> SymbolDb<'data> {
    #[tracing::instrument(skip_all, name = "Build symbol DB")]
    pub fn build(
        groups: &'data [Group],
        version_script_data: Option<&VersionScriptData>,
        args: &'data Args,
    ) -> Result<Self> {
        let version_script = version_script_data
            .map(VersionScript::parse)
            .transpose()?
            .unwrap_or_default();

        let num_symbols_per_group = groups
            .iter()
            .map(|g| g.files.iter().map(|f| f.num_symbols()).sum())
            .collect_vec();

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

        let symbol_per_file = read_symbols(groups, &version_script, &mut per_group_writers, args)?;

        for writer in per_group_writers {
            symbol_definitions_writer.return_shard(writer.resolutions);
            symbol_value_flags_writer.return_shard(writer.value_kinds);
            symbol_file_ids_writer.return_shard(writer.file_ids);
        }

        let epilogue_file_id = groups.last().unwrap().files.last().unwrap().file_id();
        let mut index = SymbolDb {
            args,
            name_to_id: Default::default(),
            versioned_name_to_id: Default::default(),
            alternative_definitions: vec![SymbolId::undefined(); num_symbols],
            alternative_versioned_definitions: HashMap::with_hasher(RandomState::new()),
            symbols_with_alternatives: Vec::new(),
            epilogue_file_id,
            symbol_file_ids,
            symbol_definitions,
            groups,
            num_symbols_per_group,
            start_stop_symbol_names: Default::default(),
            symbol_value_flags,
        };
        index.populate_symbol_db(symbol_per_file)?;
        Ok(index)
    }

    #[tracing::instrument(skip_all, name = "Populate symbol map")]
    fn populate_symbol_db(&mut self, symbol_per_file: Vec<SymbolLoadOutputs<'data>>) -> Result {
        // The following approximation should be an upper bound on the number of global names we'll
        // have. There will likely be at least a few global symbols with the same name, in which
        // case the actual number will be slightly smaller.
        let approx_num_symbols = symbol_per_file
            .iter()
            .map(|s| s.pending_symbols.len())
            .sum();
        self.name_to_id.reserve(approx_num_symbols);

        for pending in symbol_per_file {
            for symbol in pending.pending_symbols {
                self.add_symbol(symbol);
            }

            for symbol in pending.pending_versioned_symbols {
                self.add_versioned_symbol(symbol);
            }
        }

        Ok(())
    }

    fn add_symbol(&mut self, pending: PendingSymbol<'data>) {
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

    fn add_versioned_symbol(&mut self, pending: PendingVersionedSymbol<'data>) {
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
        // Update the entry at `first_symbol_id` to point to the new last symbol (the
        // pending symbol).
        let previous_last = replace(
            &mut self.alternative_definitions[first_symbol_id.as_usize()],
            new_symbol_id,
        );

        // Our pending symbol is now last. Update its entry to point to the previous last
        // symbol.
        self.alternative_definitions[new_symbol_id.as_usize()] = previous_last;

        if previous_last.is_undefined() {
            // This is the first alternative definition for this name, note the first symbol
            // ID for later when we resolve alternatives.
            self.symbols_with_alternatives.push(first_symbol_id);
        }
    }

    pub(crate) fn add_start_stop_symbol(
        &mut self,
        symbol_name: PreHashed<UnversionedSymbolName<'data>>,
    ) -> SymbolId {
        let symbol_id = SymbolId::from_usize(self.symbol_definitions.len());
        self.add_symbol(PendingSymbol {
            symbol_id,
            name: symbol_name,
        });
        self.symbol_definitions.push(symbol_id);
        self.start_stop_symbol_names.push(*symbol_name);
        self.num_symbols_per_group[self.epilogue_file_id.group()] += 1;
        self.symbol_value_flags
            .push(ValueFlags::ADDRESS | ValueFlags::CAN_BYPASS_GOT);
        symbol_id
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
        let input_object = self.file(file_id);
        match input_object {
            ParsedInput::Prelude(o) => Ok(o.symbol_name(symbol_id, self.args.output_kind())),
            ParsedInput::Object(o) => o.symbol_name(symbol_id),
            ParsedInput::Epilogue(o) => {
                Ok(self.start_stop_symbol_names[symbol_id.offset_from(o.start_symbol_id)])
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

    pub(crate) fn file(&self, file_id: FileId) -> &ParsedInput<'data> {
        &self.groups[file_id.group()].files[file_id.file()]
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
        self.name_to_id.get(prehashed).copied()
    }

    pub(crate) fn get(&self, key: &PreHashedSymbolName) -> Option<SymbolId> {
        match key {
            PreHashedSymbolName::Unversioned(key) => self.name_to_id.get(key).copied(),
            PreHashedSymbolName::Versioned(key) => self.versioned_name_to_id.get(key).copied(),
        }
    }

    pub(crate) fn all_unversioned_symbols(
        &self,
    ) -> impl Iterator<Item = (&PreHashed<UnversionedSymbolName>, &SymbolId)> {
        self.name_to_id.iter()
    }
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
    symbols_out_by_file: &mut [SymbolInfoWriter],
    args: &Args,
) -> Result<Vec<SymbolLoadOutputs<'data>>> {
    groups
        .par_iter()
        .zip(symbols_out_by_file)
        .map(|(group, symbols_out)| {
            let mut outputs = SymbolLoadOutputs::default();

            for file in &group.files {
                let filename = file.filename();

                load_symbols_from_file(file, version_script, symbols_out, &mut outputs, args)
                    .with_context(|| {
                        format!("Failed to load symbols from `{}`", filename.display())
                    })?;
            }

            Ok(outputs)
        })
        .collect::<Result<Vec<SymbolLoadOutputs>>>()
}

fn load_symbols_from_file<'data>(
    reader: &ParsedInput<'data>,
    version_script: &VersionScript,
    symbols_out: &mut SymbolInfoWriter,
    outputs: &mut SymbolLoadOutputs<'data>,
    args: &Args,
) -> Result {
    match reader {
        ParsedInput::Object(s) => {
            if s.is_dynamic() {
                DynamicObjectSymbolLoader::new(&s.object)?.load_symbols(
                    s.file_id,
                    symbols_out,
                    outputs,
                )?;
            } else {
                RegularObjectSymbolLoader {
                    object: &s.object,
                    args,
                    version_script,
                }
                .load_symbols(s.file_id, symbols_out, outputs)?;
            }
        }
        ParsedInput::Prelude(s) => s.load_symbols(symbols_out, outputs, args.output_kind()),
        ParsedInput::Epilogue(_) => {
            // Custom section start/stop symbols are generated after archive handling.
        }
    }
    Ok(())
}

fn value_flags_from_elf_symbol(sym: &crate::elf::Symbol, args: &Args) -> ValueFlags {
    let is_undefined = sym.is_undefined(LittleEndian);
    let mut can_bypass_got = sym.st_visibility() != object::elf::STV_DEFAULT
        || sym.is_local()
        || args.output_kind().is_static_executable()
        // Symbols defined in an executable cannot be interposed since the executable is always the
        // first place checked for a symbol by the dynamic loader.
        || (args.output_kind().is_executable() && !is_undefined);
    // When writing a shared object, TLS variables should never bypass the GOT, even if they're
    // local variables.
    if args.output_kind() == OutputKind::SharedObject && sym.st_type() == object::elf::STT_TLS {
        can_bypass_got = false;
    }
    let mut flags: ValueFlags = if sym.is_absolute(LittleEndian) {
        ValueFlags::ABSOLUTE
    } else if sym.st_type() == object::elf::STT_GNU_IFUNC {
        ValueFlags::IFUNC
    } else if is_undefined {
        if can_bypass_got {
            ValueFlags::ABSOLUTE
        } else {
            // If we can't bypass the GOT, then an undefined symbol might be able to be defined at
            // runtime by a dynamic library that gets loaded.
            ValueFlags::DYNAMIC | ValueFlags::ABSOLUTE
        }
    } else {
        ValueFlags::ADDRESS
    };
    if can_bypass_got {
        flags |= ValueFlags::CAN_BYPASS_GOT;
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
            if symbol.is_undefined(e) {
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
                    value_flags |= ValueFlags::CAN_BYPASS_GOT;
                }
            }

            if info.is_default {
                let pending = PendingSymbol::from_prehashed(symbol_id, name);
                outputs.pending_symbols.push(pending);
            }

            if let Some(version) = info.version_name {
                let pending = PendingVersionedSymbol::from_prehashed(symbol_id, name, version);
                outputs.pending_versioned_symbols.push(pending);
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

impl Prelude {
    fn load_symbols(
        &self,
        symbols_out: &mut SymbolInfoWriter,
        outputs: &mut SymbolLoadOutputs,
        output_kind: OutputKind,
    ) {
        outputs
            .pending_symbols
            .reserve(self.symbol_definitions.len());
        for definition in &self.symbol_definitions {
            let symbol_id = symbols_out.next;
            let value_flags = match definition {
                InternalSymDefInfo::Undefined => ValueFlags::ABSOLUTE,
                InternalSymDefInfo::SectionStart(section_id) => {
                    let def = section_id.built_in_details();
                    let name = def.start_symbol_name(output_kind).unwrap().as_bytes();
                    outputs
                        .pending_symbols
                        .push(PendingSymbol::new(symbol_id, name));
                    ValueFlags::ADDRESS | ValueFlags::CAN_BYPASS_GOT
                }
                InternalSymDefInfo::SectionEnd(section_id) => {
                    let def = section_id.built_in_details();
                    let name = def.end_symbol_name(output_kind).unwrap().as_bytes();
                    outputs
                        .pending_symbols
                        .push(PendingSymbol::new(symbol_id, name));
                    ValueFlags::ADDRESS | ValueFlags::CAN_BYPASS_GOT
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
            InternalSymDefInfo::Undefined => None,
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
