//! Reads global symbols for each input file and builds a map from symbol names to IDs together with
//! information about where each symbol can be obtained.

use crate::archive_splitter::InputBytes;
use crate::args::Args;
use crate::elf::File;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::hash::PassThroughHashMap;
use crate::input_data;
use crate::input_data::FileId;
use crate::input_data::InputRef;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::resolution::ValueKind;
use crate::symbol;
use crate::symbol::Symbol;
use crate::symbol::SymbolName;
use ahash::AHashMap;
use anyhow::bail;
use anyhow::Context;
use object::Object;
use object::ObjectSymbol;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::IntoParallelIterator;
use rayon::prelude::ParallelIterator;
use std::collections::hash_map;
use std::ffi::CString;
use std::num::NonZeroU32;
use std::path::Path;

pub struct SymbolDb<'data> {
    pub args: &'data Args,
    pub(crate) symbol_ids: PassThroughHashMap<SymbolName<'data>, GlobalSymbolId>,
    pub(crate) symbols: Vec<Symbol>,
    pub(crate) symbol_names: Vec<SymbolName<'data>>,
    pub(crate) alternate_definitions: AHashMap<GlobalSymbolId, Vec<Symbol>>,
}

/// A symbol that hasn't been given an ID yet.
#[derive(Clone, Copy)]
pub(crate) struct PendingSymbol<'data> {
    pub(crate) symbol: Symbol,
    pub(crate) name: SymbolName<'data>,
}

/// An index into SymbolIndex.symbols. This is as opposed to a symbol ID within an object file,
/// which is an index into the symbol table for just that object file and is represented as
/// object::SymbolIndex.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct GlobalSymbolId(NonZeroU32);

const NUM_RESERVED_SYMBOL_IDS: usize = 0;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct ObjectSymDefInfo {
    /// The index of the symbol within the symbol table of the object that defined it.
    pub(crate) local_symbol_id: object::SymbolIndex,
}

#[derive(Clone, Copy)]
pub(crate) enum InternalSymDefInfo {
    /// Defines a symbol that points to the start of a section.
    SectionStart(OutputSectionId),

    /// Defines a symbol that points at the non-inclusive end of the section. i.e. 1 byte past the
    /// last byte of the section.
    SectionEnd(OutputSectionId),
}

pub enum FileSymbols<'data> {
    Internal(InternalSymbols),
    Object(ObjectSymbols<'data>),
    ArchiveEntry(ObjectSymbols<'data>),
}

pub struct InternalSymbols {
    // TODO: Use this - when we implement dynamic linking
    #[allow(dead_code)]
    pub(crate) dynamic_linker: Option<CString>,
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo>,
    pub(crate) defined: Vec<GlobalSymbolId>,
    pub(crate) file_id: FileId,
}

pub struct ObjectSymbols<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) object: Box<File<'data>>,
    pub(crate) file_id: FileId,
}

enum FileSymbolReader<'data> {
    Internal(InternalSymbolReader),
    Object(ObjectSymbolReader<'data>),
    Dynamic(ObjectSymbolReader<'data>),
}

struct InternalSymbolReader {
    dynamic_linker: Option<CString>,
    symbol_definitions: Vec<InternalSymDefInfo>,
}

struct ObjectSymbolReader<'data> {
    input: InputRef<'data>,
    object: Box<File<'data>>,
}

enum SymbolReader<'data> {
    Object(ObjectSymbolReader<'data>),
    Internal(InternalSymbolReader),
}

struct SymbolLoadOutputs<'data> {
    pending_symbols: Vec<PendingSymbol<'data>>,
    reader: SymbolReader<'data>,
}

impl<'data> SymbolDb<'data> {
    #[tracing::instrument(skip_all, name = "Build symbol DB")]
    pub fn build(
        inputs: &'data [InputBytes],
        args: &'data Args,
    ) -> Result<(Self, Vec<FileSymbols<'data>>)> {
        // Reserve IDs for our reserved symbols, plus symbol 0, which is never used, but allows us
        // to represent symbols with a NonZeroU32.
        let symbols = vec![symbol::PLACEHOLDER; NUM_RESERVED_SYMBOL_IDS + 1];
        let mut symbol_names = Vec::new();
        symbol_names.resize_with(NUM_RESERVED_SYMBOL_IDS + 1, SymbolName::placeholder);
        let mut index = Self {
            args,
            symbol_ids: Default::default(),
            symbols,
            symbol_names,
            alternate_definitions: AHashMap::new(),
        };
        let readers = inputs
            .par_iter()
            .map(|f| FileSymbolReader::new(f, args))
            .collect::<Result<Vec<FileSymbolReader>>>()?;
        let per_file_symbols = index.load_symbols(readers)?;
        Ok((index, per_file_symbols))
    }

    fn load_symbols(
        &mut self,
        readers: Vec<FileSymbolReader<'data>>,
    ) -> Result<Vec<FileSymbols<'data>>> {
        let symbol_per_file = read_symbols(readers, self.args)?;
        self.populate_symbol_db(symbol_per_file)
    }

    #[tracing::instrument(skip_all, name = "Populate symbol map")]
    fn populate_symbol_db(
        &mut self,
        symbol_per_file: Vec<Vec<SymbolLoadOutputs<'data>>>,
    ) -> Result<Vec<FileSymbols<'data>>> {
        let approx_num_symbols = symbol_per_file.iter().map(|s| s.len()).sum();
        self.symbol_names.reserve(approx_num_symbols);
        self.symbol_ids.reserve(approx_num_symbols);
        self.symbols.reserve(approx_num_symbols);
        symbol_per_file
            .into_iter()
            .flatten()
            .enumerate()
            .map(|(file_id, pending)| {
                let file_id = FileId::new(file_id as u32);
                let defined = self.add_symbols(pending.pending_symbols, file_id)?;
                Ok(match pending.reader {
                    SymbolReader::Object(state) => {
                        if state.is_from_archive() {
                            FileSymbols::ArchiveEntry(state.symbols_defined(file_id))
                        } else {
                            FileSymbols::Object(state.symbols_defined(file_id))
                        }
                    }
                    SymbolReader::Internal(state) => {
                        FileSymbols::Internal(state.symbols_defined(defined, file_id))
                    }
                })
            })
            .collect()
    }

    /// Adds some symbols, assigning them IDs as we go. Returns the IDs that were allocated.
    fn add_symbols(
        &mut self,
        pending: Vec<PendingSymbol<'data>>,
        file_id: FileId,
    ) -> Result<Vec<GlobalSymbolId>> {
        // TODO: Consider alternatives to collecting these symbol IDs. The only user of them is for
        // internal symbols. Or perhaps we can use them for objects as well in order to pre-populate
        // its local symbol table for globals that it defines. This might speed up resolution.
        let mut symbol_ids = Vec::with_capacity(pending.len());
        for mut symbol in pending {
            symbol.symbol.file_id = file_id;
            let symbol_id = self.add_symbol(symbol)?;
            symbol_ids.push(symbol_id);
        }
        Ok(symbol_ids)
    }

    fn add_symbol(&mut self, pending: PendingSymbol<'data>) -> Result<GlobalSymbolId> {
        match self.symbol_ids.entry(pending.name) {
            hash_map::Entry::Occupied(entry) => {
                let symbol_id = *entry.get();
                self.alternate_definitions
                    .entry(symbol_id)
                    .or_default()
                    .push(pending.symbol);
                Ok(symbol_id)
            }
            hash_map::Entry::Vacant(entry) => {
                let symbol_id = self.symbols.len().try_into()?;
                entry.insert(symbol_id);
                self.symbols.push(pending.symbol);
                self.symbol_names.push(pending.name);
                Ok(symbol_id)
            }
        }
    }

    pub(crate) fn add_start_stop_symbol(
        &mut self,
        symbol_name: &'data [u8],
        local_index: object::SymbolIndex,
    ) -> Result<GlobalSymbolId> {
        self.add_symbol(PendingSymbol {
            symbol: Symbol::new(
                input_data::INTERNAL_FILE_ID,
                local_index,
                ValueKind::Address,
            ),
            name: SymbolName::new(symbol_name),
        })
    }

    pub(crate) fn symbol(&self, symbol_id: GlobalSymbolId) -> &Symbol {
        &self.symbols[symbol_id.as_usize()]
    }

    pub(crate) fn symbol_name(&self, symbol_id: GlobalSymbolId) -> SymbolName {
        debug_assert_eq!(self.symbol_names.len(), self.symbols.len());
        self.symbol_names[symbol_id.as_usize()]
    }

    pub(crate) fn replace_symbol(&mut self, symbol_id: GlobalSymbolId, replacement: Symbol) {
        self.symbols[symbol_id.as_usize()] = replacement;
    }

    pub(crate) fn num_symbols(&self) -> usize {
        self.symbols.len()
    }
}

#[tracing::instrument(skip_all, name = "Read symbols")]
fn read_symbols<'data>(
    readers: Vec<FileSymbolReader<'data>>,
    args: &Args,
) -> Result<Vec<Vec<SymbolLoadOutputs<'data>>>, anyhow::Error> {
    let symbol_per_file = readers
        .into_par_iter()
        .map(|reader| {
            let filename = reader.filename();
            load_symbols_from_file(reader, args)
                .with_context(|| format!("Failed to load symbols from `{}`", filename.display()))
        })
        .collect::<Result<Vec<Vec<SymbolLoadOutputs>>>>()?;
    Ok(symbol_per_file)
}

fn load_symbols_from_file<'data>(
    reader: FileSymbolReader<'data>,
    args: &Args,
) -> Result<Vec<SymbolLoadOutputs<'data>>> {
    Ok(match reader {
        FileSymbolReader::Object(s) => vec![s.load_symbols()?],
        FileSymbolReader::Internal(s) => vec![s.load_symbols(args)?],
        FileSymbolReader::Dynamic(s) => vec![s.load_dynamic_symbols()?],
    })
}

impl<'data> ObjectSymbolReader<'data> {
    fn new(input: &'data InputBytes) -> Result<Self> {
        let object = Box::new(
            File::parse(input.data)
                .with_context(|| format!("Failed to parse object file `{input}`"))?,
        );
        Ok(Self {
            input: input.input,
            object,
        })
    }

    fn is_from_archive(&self) -> bool {
        self.input.entry_filename.is_some()
    }

    fn filename(&self) -> &'data Path {
        &self.input.file.filename
    }

    fn load_symbols(mut self) -> Result<SymbolLoadOutputs<'data>> {
        let pending_symbols = self.pending_symbols()?;
        Ok(SymbolLoadOutputs {
            pending_symbols,
            reader: SymbolReader::Object(self),
        })
    }

    fn pending_symbols(&mut self) -> Result<Vec<PendingSymbol<'data>>> {
        let mut pending_symbols = Vec::new();
        for symbol in self.object.symbols() {
            if symbol.is_undefined() || symbol.is_local() {
                continue;
            }
            let name = symbol.name_bytes()?;
            let pending = PendingSymbol::new(
                // This gets filled in after all objects load their symbols, since we don't know how
                // many objects in each archive until then.
                FileId::placeholder(),
                symbol.index(),
                symbol_kind(&symbol),
                name,
            );
            pending_symbols.push(pending);
        }
        Ok(pending_symbols)
    }

    fn load_dynamic_symbols(self) -> Result<SymbolLoadOutputs<'data>> {
        let mut symbols = Vec::new();
        for symbol in self.object.dynamic_symbols() {
            if symbol.is_undefined() || symbol.is_local() {
                continue;
            }
            let name = symbol.name_bytes()?;
            symbols.push(PendingSymbol::new(
                FileId::placeholder(),
                symbol.index(),
                symbol_kind(&symbol),
                name,
            ));
        }
        Ok(SymbolLoadOutputs {
            pending_symbols: symbols,
            reader: SymbolReader::Object(self),
        })
    }

    fn symbols_defined(self, file_id: FileId) -> ObjectSymbols<'data> {
        ObjectSymbols {
            file_id,
            input: self.input,
            object: self.object,
        }
    }
}

fn symbol_kind(symbol: &crate::elf::Symbol) -> ValueKind {
    match symbol.section() {
        object::SymbolSection::Absolute => ValueKind::Absolute,
        _ => ValueKind::Address,
    }
}

impl InternalSymbolReader {
    fn load_symbols(mut self, args: &Args) -> Result<SymbolLoadOutputs<'static>> {
        let mut symbols = Vec::new();
        for section_id in output_section_id::built_in_section_ids() {
            // If we're not producing a relocatable output, then don't define any symbols for the
            // .dynamic section.
            if section_id == output_section_id::DYNAMIC && !args.is_relocatable() {
                continue;
            }
            let def = section_id.built_in_details();
            if let Some(name) = def.start_symbol_name {
                symbols.push(PendingSymbol::new(
                    input_data::INTERNAL_FILE_ID,
                    object::SymbolIndex(self.symbol_definitions.len()),
                    ValueKind::Address,
                    name.as_bytes(),
                ));
                self.symbol_definitions
                    .push(InternalSymDefInfo::SectionStart(section_id));
            }
            if let Some(name) = def.end_symbol_name {
                symbols.push(PendingSymbol::new(
                    input_data::INTERNAL_FILE_ID,
                    object::SymbolIndex(self.symbol_definitions.len()),
                    ValueKind::Address,
                    name.as_bytes(),
                ));
                self.symbol_definitions
                    .push(InternalSymDefInfo::SectionEnd(section_id));
            }
        }
        Ok(SymbolLoadOutputs {
            pending_symbols: symbols,
            reader: SymbolReader::Internal(self),
        })
    }

    fn symbols_defined(self, defined: Vec<GlobalSymbolId>, file_id: FileId) -> InternalSymbols {
        InternalSymbols {
            file_id,
            dynamic_linker: self.dynamic_linker,
            defined,
            symbol_definitions: self.symbol_definitions,
        }
    }
}

impl GlobalSymbolId {
    pub(crate) fn as_usize(&self) -> usize {
        self.0.get() as usize
    }

    // TODO: Use or remove
    #[allow(dead_code)]
    const fn new(value: u32) -> GlobalSymbolId {
        match NonZeroU32::new(value) {
            Some(x) => GlobalSymbolId(x),
            None => panic!("Called GlobalSymbolId::new with ID 0"),
        }
    }
}

impl TryFrom<usize> for GlobalSymbolId {
    type Error = crate::error::Error;

    fn try_from(value: usize) -> std::result::Result<Self, Self::Error> {
        Ok(GlobalSymbolId(
            NonZeroU32::new(u32::try_from(value).context("Too many symbols")?)
                .context("Attempt to create GlobalSymbolId with ID 0")?,
        ))
    }
}

impl<'data> FileSymbolReader<'data> {
    fn new(input: &'data InputBytes, args: &'data Args) -> Result<Self> {
        Ok(match input.kind {
            FileKind::ElfObject | FileKind::Archive => {
                Self::Object(ObjectSymbolReader::new(input)?)
            }
            FileKind::Internal => Self::Internal(InternalSymbolReader::new(args)?),
            FileKind::ElfDynamic => {
                if true {
                    bail!("Dynamic linking is not yet implemented");
                }
                Self::Dynamic(ObjectSymbolReader::new(input)?)
            }
            FileKind::Text => unreachable!("Should have been handled earlier"),
        })
    }

    fn filename(&self) -> &'data Path {
        match self {
            Self::Object(s) => s.filename(),
            Self::Internal(s) => s.filename(),
            Self::Dynamic(s) => s.filename(),
        }
    }
}

impl InternalSymbolReader {
    fn new(args: &Args) -> Result<Self> {
        Ok(Self {
            dynamic_linker: args
                .dynamic_linker
                .as_ref()
                .map(|p| CString::new(p.as_os_str().as_encoded_bytes()))
                .transpose()?,
            symbol_definitions: Default::default(),
        })
    }

    fn filename(&self) -> &'static Path {
        Path::new("<internal>")
    }
}

impl std::fmt::Display for GlobalSymbolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.get().fmt(f)
    }
}

impl<'data> std::fmt::Display for ObjectSymbols<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl InternalSymDefInfo {
    pub(crate) fn section_id(self) -> OutputSectionId {
        match self {
            InternalSymDefInfo::SectionStart(i) => i,
            InternalSymDefInfo::SectionEnd(i) => i,
        }
    }
}

impl<'data> PendingSymbol<'data> {
    fn new(
        file_id: FileId,
        local_index: object::SymbolIndex,
        kind: ValueKind,
        name: &'data [u8],
    ) -> PendingSymbol<'data> {
        PendingSymbol {
            symbol: Symbol::new(file_id, local_index, kind),
            name: SymbolName::new(name),
        }
    }
}
