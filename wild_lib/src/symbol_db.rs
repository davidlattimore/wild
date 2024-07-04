//! Reads global symbols for each input file and builds a map from symbol names to IDs together with
//! information about where each symbol can be obtained.

use crate::args::Args;
use crate::args::OutputKind;
use crate::error::Result;
use crate::hash::PassThroughHashMap;
use crate::hash::PreHashed;
use crate::input_data::FileId;
use crate::input_data::VersionScriptData;
use crate::linker_script::VersionScript;
use crate::output_section_id::OutputSectionId;
use crate::parsing::InternalInputObject;
use crate::parsing::InternalSymDefInfo;
use crate::parsing::ParsedInput;
use crate::resolution::ValueFlags;
use crate::sharding::Shard;
use crate::sharding::ShardKey;
use crate::symbol::SymbolName;
use crate::threading::prelude::*;
use ahash::AHashMap;
use anyhow::Context;
use object::read::elf::Sym as _;
use object::LittleEndian;
use std::collections::hash_map;

pub struct SymbolDb<'data> {
    pub(crate) args: &'data Args,

    pub(crate) inputs: &'data [ParsedInput<'data>],

    /// Mapping from global symbol names to a symbol ID with that name. If there are multiple
    /// globals with the same name, then this will point to the one we encountered first, which may
    /// not be the selected definition. In order to find the selected definition, you still need to
    /// look a `symbol_definitions`.
    pub(crate) global_names: PassThroughHashMap<SymbolName<'data>, SymbolId>,

    /// Which file each symbol ID belongs to. Indexes past the end are assumed to be for custom
    /// section start/stop symbols.
    symbol_files: Vec<FileId>,

    /// Mapping from symbol IDs to the canonical definition of that symbol. For global symbols that
    /// were selected as the definition and for all locals, this will point to itself. e.g. the
    /// value at index 5 will be the symbol ID 5.
    symbol_definitions: Vec<SymbolId>,

    symbol_value_kinds: Vec<ValueFlags>,

    /// Global symbols that have multiple definitions. Keyed by the canonical symbol ID with that
    /// name.
    pub(crate) alternate_definitions: AHashMap<SymbolId, Vec<SymbolId>>,

    pub(crate) num_symbols_per_file: Vec<usize>,

    custom_sections_file_id: FileId,

    start_stop_symbol_names: Vec<SymbolName<'data>>,
}

/// A global symbol that hasn't been put into our database yet.
#[derive(Clone, Copy)]
pub(crate) struct PendingSymbol<'data> {
    pub(crate) symbol_id: SymbolId,
    pub(crate) name: PreHashed<SymbolName<'data>>,
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

impl SymbolIdRange {
    pub(crate) fn internal(num_symbols: usize) -> SymbolIdRange {
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
        debug_assert!(offset < self.num_symbols);
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

struct SymbolLoadOutputs<'data> {
    pending_symbols: Vec<PendingSymbol<'data>>,
}

impl<'data> SymbolDb<'data> {
    #[tracing::instrument(skip_all, name = "Build symbol DB")]
    pub fn build(
        inputs: &'data [ParsedInput],
        version_script_data: Option<&VersionScriptData>,
        args: &'data Args,
    ) -> Result<Self> {
        let version_script = version_script_data
            .map(VersionScript::parse)
            .transpose()?
            .unwrap_or_default();

        let num_symbols_per_file = inputs
            .iter()
            .map(|f| f.num_symbols())
            .collect::<Vec<usize>>();
        let num_symbols = num_symbols_per_file.iter().sum();
        let mut symbol_definitions: Vec<SymbolId> = vec![SymbolId::undefined(); num_symbols];
        let mut symbol_value_kinds: Vec<ValueFlags> = vec![ValueFlags::ABSOLUTE; num_symbols];
        let mut per_file_resolutions =
            crate::sharding::split_to_shards(&mut symbol_definitions, &num_symbols_per_file);
        let mut per_file_kinds =
            crate::sharding::split_to_shards(&mut symbol_value_kinds, &num_symbols_per_file);
        let symbol_files = num_symbols_per_file
            .iter()
            .enumerate()
            .flat_map(|(file_id, num_symbols)| {
                std::iter::repeat(FileId::new(file_id as u32)).take(*num_symbols)
            })
            .collect();

        let symbol_per_file = read_symbols(
            inputs,
            &version_script,
            &mut per_file_resolutions,
            &mut per_file_kinds,
            args,
        )?;
        let custom_sections_file_id = FileId::from_usize(inputs.len() - 1)?;
        debug_assert!(matches!(
            inputs[custom_sections_file_id.as_usize()],
            ParsedInput::Epilogue(..)
        ));
        let mut index = SymbolDb {
            args,
            global_names: Default::default(),
            alternate_definitions: AHashMap::new(),
            custom_sections_file_id,
            symbol_files,
            symbol_definitions,
            inputs,
            num_symbols_per_file,
            start_stop_symbol_names: Default::default(),
            symbol_value_kinds,
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
        self.global_names.reserve(approx_num_symbols);
        for pending in symbol_per_file {
            self.add_symbols(pending.pending_symbols);
        }
        Ok(())
    }

    fn add_symbols(&mut self, pending: Vec<PendingSymbol<'data>>) {
        for symbol in pending {
            self.add_symbol(symbol);
        }
    }

    fn add_symbol(&mut self, pending: PendingSymbol<'data>) {
        match self.global_names.entry(pending.name) {
            hash_map::Entry::Occupied(entry) => {
                let symbol_id = *entry.get();
                self.alternate_definitions
                    .entry(symbol_id)
                    .or_default()
                    .push(pending.symbol_id);
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(pending.symbol_id);
            }
        }
    }

    pub(crate) fn add_start_stop_symbol(
        &mut self,
        symbol_name: PreHashed<SymbolName<'data>>,
    ) -> SymbolId {
        let symbol_id = SymbolId::from_usize(self.symbol_definitions.len());
        self.add_symbol(PendingSymbol {
            symbol_id,
            name: symbol_name,
        });
        self.symbol_definitions.push(symbol_id);
        self.start_stop_symbol_names.push(*symbol_name);
        self.num_symbols_per_file[self.custom_sections_file_id.as_usize()] += 1;
        self.symbol_value_kinds.push(ValueFlags::ADDRESS);
        symbol_id
    }

    /// Returns a struct that can be used to print debug information about the specified symbol.
    pub(crate) fn symbol_debug(&self, symbol_id: SymbolId) -> SymbolDebug {
        SymbolDebug {
            db: self,
            symbol_id,
        }
    }

    pub(crate) fn symbol_name(&self, symbol_id: SymbolId) -> Result<SymbolName<'data>> {
        let file_id = self.file_id_for_symbol(symbol_id);
        let input_object = &self.inputs[file_id.as_usize()];
        match input_object {
            ParsedInput::Internal(o) => Ok(o.symbol_name(symbol_id)),
            ParsedInput::Object(o) => o.symbol_name(symbol_id),
            ParsedInput::Epilogue(o) => {
                Ok(self.start_stop_symbol_names[symbol_id.offset_from(o.start_symbol_id)])
            }
        }
    }

    /// Returns the value flags for the specified symbol without taking into consideration what
    /// symbol is the definition.
    pub(crate) fn local_symbol_value_flags(&self, symbol_id: SymbolId) -> ValueFlags {
        self.symbol_value_kinds[symbol_id.as_usize()]
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
        core::mem::take(&mut self.symbol_definitions)
    }

    pub(crate) fn restore_definitions(&mut self, definitions: Vec<SymbolId>) {
        self.symbol_definitions = definitions;
    }

    pub(crate) fn file_id_for_symbol(&self, symbol_id: SymbolId) -> FileId {
        self.symbol_files
            .get(symbol_id.as_usize())
            .copied()
            .unwrap_or(self.custom_sections_file_id)
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
}

#[tracing::instrument(skip_all, name = "Read symbols")]
fn read_symbols<'data>(
    readers: &[ParsedInput<'data>],
    version_script: &VersionScript,
    per_file_resolutions: &mut [Shard<SymbolId, SymbolId>],
    per_file_value_kinds: &mut [Shard<SymbolId, ValueFlags>],
    args: &Args,
) -> Result<Vec<SymbolLoadOutputs<'data>>> {
    let symbol_per_file = readers
        .par_iter()
        .zip(per_file_resolutions)
        .zip(per_file_value_kinds)
        .map(|((reader, resolutions), value_kinds)| {
            let filename = reader.filename();
            load_symbols_from_file(reader, version_script, resolutions, value_kinds, args)
                .with_context(|| format!("Failed to load symbols from `{}`", filename.display()))
        })
        .collect::<Result<Vec<SymbolLoadOutputs>>>()?;
    Ok(symbol_per_file)
}

fn load_symbols_from_file<'data>(
    reader: &ParsedInput<'data>,
    version_script: &VersionScript,
    resolutions: &mut Shard<SymbolId, SymbolId>,
    value_kinds: &mut Shard<SymbolId, ValueFlags>,
    args: &Args,
) -> Result<SymbolLoadOutputs<'data>> {
    Ok(match reader {
        ParsedInput::Object(s) => {
            if s.is_dynamic() {
                DynamicObjectSymbolLoader.load_symbols(&s.object, resolutions, value_kinds)?
            } else {
                RegularObjectSymbolLoader {
                    args,
                    version_script,
                }
                .load_symbols(&s.object, resolutions, value_kinds)?
            }
        }
        ParsedInput::Internal(s) => s.load_symbols(resolutions, value_kinds)?,
        ParsedInput::Epilogue(_) => SymbolLoadOutputs {
            // Custom section start/stop symbols are generated after archive handling.
            pending_symbols: vec![],
        },
    })
}

fn value_flags_from_elf_symbol(sym: &crate::elf::Symbol, args: &Args) -> ValueFlags {
    let is_undefined = sym.is_undefined(LittleEndian);
    let mut can_bypass_got = sym.st_visibility() != object::elf::STV_DEFAULT
        || sym.is_local()
        || args.output_kind.is_static_executable()
        // Symbols defined in an executable cannot be interposed since the executable is always the
        // first place checked for a symbol by the dynamic loader.
        || (args.output_kind.is_executable() && !is_undefined);
    // When writing a shared object, TLS variables should never bypass the GOT, even if they're
    // local variables.
    if args.output_kind == OutputKind::SharedObject && sym.st_type() == object::elf::STT_TLS {
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
            ValueFlags::DYNAMIC
        }
    } else {
        ValueFlags::ADDRESS
    };
    if can_bypass_got {
        flags |= ValueFlags::CAN_BYPASS_GOT;
    }
    flags
}

trait SymbolLoader {
    fn load_symbols<'data>(
        &self,
        object: &crate::elf::File<'data>,
        resolutions: &mut Shard<'_, SymbolId, SymbolId>,
        value_kinds: &mut Shard<'_, SymbolId, ValueFlags>,
    ) -> Result<SymbolLoadOutputs<'data>> {
        let e = LittleEndian;
        let mut pending_symbols = Vec::new();
        let base_symbol_id = resolutions.start_key;
        for ((symbol, (symbol_id, resolution)), value_kind) in object
            .symbols
            .iter()
            .zip(resolutions.iter_mut())
            .zip(value_kinds.values_mut())
        {
            *value_kind = self.compute_value_flags(symbol);
            if symbol.is_undefined(e) {
                continue;
            }
            *resolution = symbol_id;

            if symbol.is_local()
                || self.is_hidden_version(symbol_id.offset_from(base_symbol_id), object)
            {
                continue;
            }
            let name = SymbolName::prehashed(object.symbol_name(symbol)?);
            *value_kind |= self.value_flags_for_name(&name);
            let pending = PendingSymbol::from_prehashed(symbol_id, name);
            pending_symbols.push(pending);
        }
        Ok(SymbolLoadOutputs { pending_symbols })
    }

    fn compute_value_flags(&self, symbol: &crate::elf::Symbol) -> ValueFlags;

    /// Second phase of value flag computation. This is separate from `compute_value_flags` because
    /// it requires the symbol name, which is slightly expensive to get, so we'd rather not get it
    /// if we don't have to.
    fn value_flags_for_name(&self, _name: &PreHashed<SymbolName>) -> ValueFlags {
        ValueFlags::empty()
    }

    fn is_hidden_version(&self, _symbol_index: usize, _object: &crate::elf::File) -> bool {
        false
    }
}

struct RegularObjectSymbolLoader<'a> {
    args: &'a Args,
    version_script: &'a VersionScript<'a>,
}

struct DynamicObjectSymbolLoader;

impl SymbolLoader for RegularObjectSymbolLoader<'_> {
    fn compute_value_flags(&self, symbol: &crate::elf::Symbol) -> ValueFlags {
        value_flags_from_elf_symbol(symbol, self.args)
    }

    fn value_flags_for_name(&self, name: &PreHashed<SymbolName>) -> ValueFlags {
        if self.version_script.is_local(name) {
            ValueFlags::DOWNGRADE_TO_LOCAL | ValueFlags::CAN_BYPASS_GOT
        } else {
            ValueFlags::empty()
        }
    }
}

impl SymbolLoader for DynamicObjectSymbolLoader {
    fn compute_value_flags(&self, _symbol: &crate::elf::Symbol) -> ValueFlags {
        ValueFlags::DYNAMIC
    }

    fn is_hidden_version(&self, symbol_index: usize, object: &crate::elf::File) -> bool {
        object
            .versym
            .get(symbol_index)
            .is_some_and(|versym| versym.0.get(LittleEndian) & object::elf::VERSYM_HIDDEN != 0)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SymbolDebug<'db, 'data> {
    db: &'db SymbolDb<'data>,
    symbol_id: SymbolId,
}

impl<'db, 'data> std::fmt::Display for SymbolDebug<'db, 'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let symbol_id = self.symbol_id;
        let symbol_name = self
            .db
            .symbol_name(symbol_id)
            .unwrap_or_else(|_| SymbolName::new(b"??"));
        let definition = self.db.definition(symbol_id);
        let file_id = self.db.file_id_for_symbol(symbol_id);
        let file = &self.db.inputs[file_id.as_usize()];
        let local_index = symbol_id.to_offset(file.symbol_id_range());
        if definition.is_undefined() {
            write!(f, "undefined ")?;
        }
        if symbol_name.bytes().is_empty() {
            match file {
                ParsedInput::Internal(_) => write!(f, "<unnamed internal symbol>")?,
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
                        write!(f, "section `{}`", section_name)?;
                    } else {
                        write!(f, "<unnamed symbol>")?;
                    }
                }
                ParsedInput::Epilogue(_) => write!(f, "<unnamed custom-section symbol>")?,
            }
        } else {
            write!(f, "symbol `{symbol_name}`")?;
        }
        write!(
            f,
            " ({symbol_id} local={local_index}) in file #{file_id} ({file})"
        )?;
        if symbol_id != definition && !definition.is_undefined() {
            let definition_file_id = self.db.file_id_for_symbol(definition);
            let definition_file = &self.db.inputs[definition_file_id.as_usize()];
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

    pub(crate) fn is_undefined(&self) -> bool {
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

impl InternalInputObject {
    fn load_symbols(
        &self,
        resolutions: &mut Shard<SymbolId, SymbolId>,
        value_kinds: &mut Shard<SymbolId, ValueFlags>,
    ) -> Result<SymbolLoadOutputs<'static>> {
        let mut pending_symbols = Vec::with_capacity(self.symbol_definitions.len());
        for ((definition, (symbol_id, resolution)), value_flags) in self
            .symbol_definitions
            .iter()
            .zip(resolutions.iter_mut())
            .zip(value_kinds.values_mut())
        {
            *resolution = symbol_id;
            match definition {
                InternalSymDefInfo::Undefined => {
                    *value_flags = ValueFlags::ABSOLUTE;
                }
                InternalSymDefInfo::SectionStart(section_id) => {
                    let def = section_id.built_in_details();
                    let name = def.start_symbol_name.unwrap().as_bytes();
                    pending_symbols.push(PendingSymbol::new(symbol_id, name));
                    *value_flags = ValueFlags::ADDRESS;
                }
                InternalSymDefInfo::SectionEnd(section_id) => {
                    let def = section_id.built_in_details();
                    let name = def.end_symbol_name.unwrap().as_bytes();
                    pending_symbols.push(PendingSymbol::new(symbol_id, name));
                    *value_flags = ValueFlags::ADDRESS;
                }
            }
        }
        Ok(SymbolLoadOutputs { pending_symbols })
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
        Self::from_prehashed(symbol_id, SymbolName::prehashed(name))
    }

    fn from_prehashed(
        symbol_id: SymbolId,
        name: PreHashed<SymbolName<'data>>,
    ) -> PendingSymbol<'data> {
        PendingSymbol { symbol_id, name }
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
