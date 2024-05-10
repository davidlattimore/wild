//! Reads global symbols for each input file and builds a map from symbol names to IDs together with
//! information about where each symbol can be obtained.

use crate::args::Args;
use crate::error::Result;
use crate::hash::PassThroughHashMap;
use crate::hash::PreHashed;
use crate::input_data::FileId;
use crate::output_section_id::OutputSectionId;
use crate::parsing::InputObject;
use crate::parsing::InternalInputObject;
use crate::parsing::InternalSymDefInfo;
use crate::resolution::ValueKind;
use crate::sharding::Shard;
use crate::sharding::ShardKey;
use crate::symbol::SymbolName;
use ahash::AHashMap;
use anyhow::Context;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use rayon::iter::IndexedParallelIterator as _;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::ParallelIterator;
use std::collections::hash_map;

pub struct SymbolDb<'data> {
    pub(crate) args: &'data Args,

    pub(crate) inputs: &'data [InputObject<'data>],

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

    symbol_value_kinds: Vec<ValueKind>,

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
    start_symbol_index: object::SymbolIndex,
    num_symbols: usize,
}

impl SymbolIdRange {
    pub(crate) fn internal(num_symbols: usize) -> SymbolIdRange {
        SymbolIdRange {
            start_symbol_id: SymbolId::undefined(),
            start_symbol_index: object::SymbolIndex(0),
            num_symbols,
        }
    }

    pub(crate) fn epilogue(start_symbol_id: SymbolId, num_symbols: usize) -> SymbolIdRange {
        SymbolIdRange {
            start_symbol_id,
            start_symbol_index: object::SymbolIndex(0),
            num_symbols,
        }
    }

    pub(crate) fn input(
        start_symbol_id: SymbolId,
        start_symbol_index: object::SymbolIndex,
        num_symbols: usize,
    ) -> SymbolIdRange {
        SymbolIdRange {
            start_symbol_id,
            start_symbol_index,
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
        object::SymbolIndex(self.start_symbol_index.0 + offset)
    }

    pub(crate) fn input_to_offset(&self, symbol_index: object::SymbolIndex) -> usize {
        let offset = symbol_index.0 - self.start_symbol_index.0;
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

struct SymbolLoadOutputs<'data> {
    pending_symbols: Vec<PendingSymbol<'data>>,
}

impl<'data> SymbolDb<'data> {
    #[tracing::instrument(skip_all, name = "Build symbol DB")]
    pub fn build(inputs: &'data [InputObject], args: &'data Args) -> Result<Self> {
        let num_symbols_per_file = inputs
            .iter()
            .map(|f| f.num_symbols())
            .collect::<Vec<usize>>();
        let num_symbols = num_symbols_per_file.iter().sum();
        let mut symbol_definitions: Vec<SymbolId> = vec![SymbolId::undefined(); num_symbols];
        let mut symbol_value_kinds: Vec<ValueKind> = vec![ValueKind::Absolute; num_symbols];
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

        let symbol_per_file = read_symbols(inputs, &mut per_file_resolutions, &mut per_file_kinds)?;
        let custom_sections_file_id = FileId::from_usize(inputs.len() - 1)?;
        debug_assert!(matches!(
            inputs[custom_sections_file_id.as_usize()],
            InputObject::Epilogue(..)
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

    pub(crate) fn add_start_stop_symbol(&mut self, symbol_name: &'data [u8]) -> SymbolId {
        let symbol_id = SymbolId::from_usize(self.symbol_definitions.len());
        self.add_symbol(PendingSymbol {
            symbol_id,
            name: SymbolName::prehashed(symbol_name),
        });
        self.symbol_definitions.push(symbol_id);
        self.start_stop_symbol_names
            .push(SymbolName::new(symbol_name));
        self.num_symbols_per_file[self.custom_sections_file_id.as_usize()] += 1;
        self.symbol_value_kinds.push(ValueKind::Address);
        symbol_id
    }

    /// Returns a struct that can be used to print debug information about the specified symbol.
    pub(crate) fn symbol_debug(&self, symbol_id: SymbolId) -> SymbolDebug {
        SymbolDebug {
            db: self,
            symbol_id,
        }
    }

    pub(crate) fn symbol_name(&self, symbol_id: SymbolId) -> Result<SymbolName> {
        let file_id = self.file_id_for_symbol(symbol_id);
        let input_object = &self.inputs[file_id.as_usize()];
        match input_object {
            InputObject::Internal(o) => Ok(o.symbol_name(symbol_id)),
            InputObject::Object(o) => o.symbol_name(symbol_id),
            InputObject::Epilogue(o) => {
                Ok(self.start_stop_symbol_names[symbol_id.offset_from(o.start_symbol_id)])
            }
        }
    }

    pub(crate) fn symbol_value_kind(&self, symbol_id: SymbolId) -> ValueKind {
        self.symbol_value_kinds[symbol_id.as_usize()]
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

    /// Returns whether the supplied symbol ID is a definition. A symbol won't be a definition, if
    /// it resolves to a different symbol.
    pub(crate) fn is_definition(&self, symbol_id: SymbolId) -> bool {
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
    readers: &[InputObject<'data>],
    per_file_resolutions: &mut [Shard<SymbolId, SymbolId>],
    per_file_value_kinds: &mut [Shard<SymbolId, ValueKind>],
) -> Result<Vec<SymbolLoadOutputs<'data>>> {
    let symbol_per_file = readers
        .par_iter()
        .zip(per_file_resolutions)
        .zip(per_file_value_kinds)
        .map(|((reader, resolutions), value_kinds)| {
            let filename = reader.filename();
            load_symbols_from_file(reader, resolutions, value_kinds)
                .with_context(|| format!("Failed to load symbols from `{}`", filename.display()))
        })
        .collect::<Result<Vec<SymbolLoadOutputs>>>()?;
    Ok(symbol_per_file)
}

fn load_symbols_from_file<'data>(
    reader: &InputObject<'data>,
    resolutions: &mut Shard<SymbolId, SymbolId>,
    value_kinds: &mut Shard<SymbolId, ValueKind>,
) -> Result<SymbolLoadOutputs<'data>> {
    Ok(match reader {
        InputObject::Object(s) => {
            if s.is_dynamic {
                load_symbols(
                    s.object.dynamic_symbols(),
                    resolutions,
                    value_kinds,
                    |_sym| ValueKind::Dynamic,
                )?
            } else {
                load_symbols(
                    s.object.symbols(),
                    resolutions,
                    value_kinds,
                    |sym| match sym.section() {
                        object::SymbolSection::Absolute => ValueKind::Absolute,
                        _ => {
                            if sym.elf_symbol().st_info & crate::elf::SYMBOL_TYPE_MASK
                                == crate::elf::SYMBOL_TYPE_IFUNC
                            {
                                ValueKind::IFunc
                            } else {
                                ValueKind::Address
                            }
                        }
                    },
                )?
            }
        }
        InputObject::Internal(s) => s.load_symbols(resolutions, value_kinds)?,
        InputObject::Epilogue(_) => SymbolLoadOutputs {
            // Custom section start/stop symbols are generated after archive handling.
            pending_symbols: vec![],
        },
    })
}

fn load_symbols<'data>(
    symbols: crate::elf::SymbolIterator<'data, '_>,
    resolutions: &mut Shard<'_, SymbolId, SymbolId>,
    value_kinds: &mut Shard<'_, SymbolId, ValueKind>,
    compute_value_kind: impl Fn(&crate::elf::Symbol) -> ValueKind,
) -> Result<SymbolLoadOutputs<'data>> {
    let mut pending_symbols = Vec::new();
    for ((symbol, (symbol_id, resolution)), value_kind) in symbols
        .zip(resolutions.iter_mut())
        .zip(value_kinds.values_mut())
    {
        if symbol.is_undefined() {
            continue;
        }
        *resolution = symbol_id;
        *value_kind = compute_value_kind(&symbol);

        if symbol.is_local() {
            continue;
        }
        let name = symbol.name_bytes()?;
        let pending = PendingSymbol::new(symbol_id, name);
        pending_symbols.push(pending);
    }
    Ok(SymbolLoadOutputs { pending_symbols })
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
                InputObject::Internal(_) => write!(f, "<unnamed internal symbol>")?,
                InputObject::Object(o) => {
                    if let Some(section_name) = o
                        .object
                        .symbol_by_index(symbol_id.to_input(file.symbol_id_range()))
                        .ok()
                        .and_then(|symbol| symbol.section_index())
                        .and_then(|section_index| o.object.section_by_index(section_index).ok())
                        .and_then(|section| section.name_bytes().ok())
                    {
                        write!(f, "section `{}`", String::from_utf8_lossy(section_name))?;
                    } else {
                        write!(f, "<unnamed symbol>")?;
                    }
                }
                InputObject::Epilogue(_) => write!(f, "<unnamed custom-section symbol>")?,
            }
        } else {
            write!(f, "symbol `{symbol_name}`")?;
        }
        write!(
            f,
            " ({symbol_id} local={local_index}) in file #{file_id} ({file})"
        )?;
        if symbol_id == definition {
            return Ok(());
        }
        if !definition.is_undefined() {
            let definition_file_id = self.db.file_id_for_symbol(definition);
            let definition_file = &self.db.inputs[definition_file_id.as_usize()];
            write!(
                f,
                " defined as {definition} in file #{definition_file_id} ({definition_file})"
            )?;
        }
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
        value_kinds: &mut Shard<SymbolId, ValueKind>,
    ) -> Result<SymbolLoadOutputs<'static>> {
        let mut pending_symbols = Vec::with_capacity(self.symbol_definitions.len());
        for ((definition, (symbol_id, resolution)), value_kind) in self
            .symbol_definitions
            .iter()
            .zip(resolutions.iter_mut())
            .zip(value_kinds.values_mut())
        {
            *resolution = symbol_id;
            match definition {
                InternalSymDefInfo::Undefined => {
                    *value_kind = ValueKind::Absolute;
                }
                InternalSymDefInfo::SectionStart(section_id) => {
                    let def = section_id.built_in_details();
                    let name = def.start_symbol_name.unwrap().as_bytes();
                    pending_symbols.push(PendingSymbol::new(symbol_id, name));
                    *value_kind = ValueKind::Address;
                }
                InternalSymDefInfo::SectionEnd(section_id) => {
                    let def = section_id.built_in_details();
                    let name = def.end_symbol_name.unwrap().as_bytes();
                    pending_symbols.push(PendingSymbol::new(symbol_id, name));
                    *value_kind = ValueKind::Address;
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
        PendingSymbol {
            symbol_id,
            name: SymbolName::prehashed(name),
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
