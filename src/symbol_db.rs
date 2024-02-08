//! Reads global symbols for each input file and builds a map from symbol names to IDs together with
//! information about where each symbol can be obtained.

use crate::archive;
use crate::archive::ArchiveEntry;
use crate::archive::ArchiveIterator;
use crate::archive::ExtendedFilenames;
use crate::args::Args;
use crate::elf::File;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::hash::PassThroughHashMap;
use crate::input_data;
use crate::input_data::FileId;
use crate::input_data::InputData;
use crate::input_data::InputFile;
use crate::input_data::InputRef;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::symbol;
use crate::symbol::Symbol;
use crate::symbol::SymbolName;
use crate::timing::Timing;
use ahash::AHashMap;
use anyhow::bail;
use anyhow::Context;
use object::Object;
use object::ObjectSymbol;
use rayon::prelude::IntoParallelIterator;
use rayon::prelude::ParallelIterator;
use std::collections::hash_map;
use std::ffi::CString;
use std::num::NonZeroU32;
use std::path::Path;

pub(crate) struct SymbolDb<'data> {
    pub(crate) args: &'data Args,
    pub(crate) symbol_ids: PassThroughHashMap<SymbolName<'data>, GlobalSymbolId>,
    symbols: Vec<Symbol>,
    symbol_names: Vec<SymbolName<'data>>,
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

pub(crate) enum FileSymbols<'data> {
    Internal(InternalSymbols),
    Object(ObjectSymbols<'data>),
    ArchiveEntry(ArchivedObject<'data>),
}

pub(crate) struct InternalSymbols {
    // TODO: Use this - when we implement dynamic linking
    #[allow(dead_code)]
    pub(crate) dynamic_linker: Option<CString>,
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo>,
    pub(crate) defined: Vec<GlobalSymbolId>,
    pub(crate) file_id: FileId,
}

pub(crate) struct ObjectSymbols<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) object: Box<File<'data>>,
    pub(crate) file_id: FileId,
}

// TODO: Either add support for archive files that don't have a symbol table, in which case this
// enum would get a second variant, or if we're not doing that, then get rid of this enum.
pub(crate) enum ArchivedObject<'data> {
    Unloaded(UnloadedArchivedObject<'data>),
}

pub(crate) struct UnloadedArchivedObject<'data> {
    file_id: FileId,
    /// The offset in the archive of the start of the headers for the object.
    header_offset: u32,
    pub(crate) input_file: &'data InputFile,
    filenames: Option<ExtendedFilenames<'data>>,
}

/// A record indicating an update that we should make to the local index for a symbol. This is
/// necessary for archives, since we don't know the local indexes until we actually load the object,
/// which we don't do unless we know we're going to use that archive entry.
pub(crate) struct LocalIndexUpdate {
    pub(crate) file_id: FileId,
    pub(crate) symbol_id: GlobalSymbolId,
    pub(crate) local_index: object::SymbolIndex,
}

impl<'data> UnloadedArchivedObject<'data> {
    pub(crate) fn load(&self) -> Result<(ObjectSymbols<'data>, Vec<PendingSymbol<'data>>)> {
        let data = self.input_file.data();
        let Some(ArchiveEntry::Regular(archive_entry)) =
            archive::ArchiveIterator::from_entry_bytes(&data[self.header_offset as usize..])
                .next()
                .transpose()?
        else {
            bail!("Archive symbol table referenced invalid entry");
        };
        let object = Box::new(File::parse(archive_entry.entry_data)?);
        let reader = ObjectSymbolReader {
            input_file: self.input_file,
            object,
        };
        let pending = reader.load_symbols()?;
        let SymbolReader::Object(reader) = pending.reader else {
            unreachable!();
        };
        Ok((
            ObjectSymbols {
                file_id: self.file_id,
                input: InputRef {
                    file: self.input_file,
                    entry_filename: Some(archive_entry.identifier(self.filenames)),
                },
                object: reader.object,
            },
            pending.pending_symbols,
        ))
    }
}

enum FileSymbolReader<'data> {
    Internal(InternalSymbolReader),
    Object(ObjectSymbolReader<'data>),
    Archive(ArchiveSymbolReader<'data>),
    Dynamic(ObjectSymbolReader<'data>),
}

struct InternalSymbolReader {
    dynamic_linker: Option<CString>,
    symbol_definitions: Vec<InternalSymDefInfo>,
}

struct ObjectSymbolReader<'data> {
    input_file: &'data InputFile,
    object: Box<File<'data>>,
}

struct ArchiveSymbolReader<'data> {
    input_file: &'data InputFile,
    data: &'data [u8],
}

struct UnloadedArchivedObjectSymbolReader<'data> {
    /// The offset in the archive of the start of the headers for the object.
    header_offset: u32,
    input_file: &'data InputFile,
    filenames: Option<ExtendedFilenames<'data>>,
}

enum SymbolReader<'data> {
    Object(ObjectSymbolReader<'data>),
    ArchiveEntry(UnloadedArchivedObjectSymbolReader<'data>),
    Internal(InternalSymbolReader),
}

struct SymbolLoadOutputs<'data> {
    pending_symbols: Vec<PendingSymbol<'data>>,
    reader: SymbolReader<'data>,
}

impl<'data> SymbolDb<'data> {
    pub(crate) fn build(
        input_data: &'data InputData,
        timing: &mut Timing,
    ) -> Result<(Self, Vec<FileSymbols<'data>>)> {
        // Reserve IDs for our reserved symbols, plus symbol 0, which is never used, but allows us
        // to represent symbols with a NonZeroU32.
        let symbols = vec![symbol::PLACEHOLDER; NUM_RESERVED_SYMBOL_IDS + 1];
        let mut symbol_names = Vec::new();
        symbol_names.resize_with(NUM_RESERVED_SYMBOL_IDS + 1, SymbolName::placeholder);
        let mut index = Self {
            args: input_data.config,
            symbol_ids: Default::default(),
            symbols,
            symbol_names,
            alternate_definitions: AHashMap::new(),
        };
        let readers = input_data
            .files
            .iter()
            .map(|f| FileSymbolReader::new(f, input_data.config))
            .collect::<Result<Vec<FileSymbolReader>>>()?;
        let file_symbols = index.load_symbols(readers, timing)?;
        timing.complete("Building symbol DB");
        Ok((index, file_symbols))
    }

    fn load_symbols(
        &mut self,
        readers: Vec<FileSymbolReader<'data>>,
        timing: &mut Timing,
    ) -> Result<Vec<FileSymbols<'data>>> {
        let symbol_per_file = readers
            .into_par_iter()
            .map(|reader| {
                let filename = reader.filename();
                load_symbols_from_file(reader).with_context(|| {
                    format!("Failed to load symbols from `{}`", filename.display())
                })
            })
            .collect::<Result<Vec<Vec<SymbolLoadOutputs>>>>()?;
        timing.complete("Reading symbols");

        symbol_per_file
            .into_iter()
            .flatten()
            .enumerate()
            .map(|(file_id, pending)| {
                let file_id = FileId::new(file_id as u32);
                let defined = self.add_symbols(pending.pending_symbols, file_id)?;
                Ok(match pending.reader {
                    SymbolReader::Object(state) => {
                        FileSymbols::Object(state.symbols_defined(file_id))
                    }
                    SymbolReader::ArchiveEntry(state) => {
                        FileSymbols::ArchiveEntry(state.symbols_defined(file_id))
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
            symbol: Symbol::new(input_data::INTERNAL_FILE_ID, local_index),
            name: SymbolName::new(symbol_name),
        })
    }

    pub(crate) fn symbol(&self, symbol_id: GlobalSymbolId) -> &Symbol {
        &self.symbols[symbol_id.as_usize()]
    }

    fn symbol_mut(&mut self, symbol_id: GlobalSymbolId, file_id: FileId) -> Option<&mut Symbol> {
        let symbol = &mut self.symbols[symbol_id.as_usize()];
        if symbol.file_id == file_id {
            return Some(symbol);
        }
        (self.alternate_definitions.get_mut(&symbol_id)?)
            .iter_mut()
            .find(|symbol| symbol.file_id == file_id)
    }

    pub(crate) fn symbol_name(&self, symbol_id: GlobalSymbolId) -> SymbolName {
        debug_assert_eq!(self.symbol_names.len(), self.symbols.len());
        self.symbol_names[symbol_id.as_usize()]
    }

    pub(crate) fn apply_update(&mut self, update: LocalIndexUpdate) -> Result {
        let symbol = self
            .symbol_mut(update.symbol_id, update.file_id)
            .context("Tried to update symbol for a file that didn't define that symbol")?;
        symbol.set_local_index(update.local_index);
        Ok(())
    }

    pub(crate) fn replace_symbol(&mut self, symbol_id: GlobalSymbolId, replacement: Symbol) {
        self.symbols[symbol_id.as_usize()] = replacement;
    }

    pub(crate) fn num_symbols(&self) -> usize {
        self.symbols.len()
    }
}

fn load_symbols_from_file(reader: FileSymbolReader) -> Result<Vec<SymbolLoadOutputs>> {
    Ok(match reader {
        FileSymbolReader::Internal(s) => vec![s.load_symbols()?],
        FileSymbolReader::Object(s) => vec![s.load_symbols()?],
        FileSymbolReader::Archive(s) => s.load_symbols()?,
        FileSymbolReader::Dynamic(s) => vec![s.load_dynamic_symbols()?],
    })
}

impl<'data> ObjectSymbolReader<'data> {
    fn load_symbols(self) -> Result<SymbolLoadOutputs<'data>> {
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
                name,
            );
            pending_symbols.push(pending);
        }
        Ok(SymbolLoadOutputs {
            pending_symbols,
            reader: SymbolReader::Object(self),
        })
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
            input: InputRef {
                file: self.input_file,
                entry_filename: None,
            },
            object: self.object,
        }
    }
}

impl<'data> ArchiveSymbolReader<'data> {
    fn load_symbols(self) -> Result<Vec<SymbolLoadOutputs<'data>>> {
        let mut symbol_table = None;
        let mut filenames = None;
        let mut num_entries = 0;
        for entry in ArchiveIterator::from_archive_bytes(self.data)? {
            let entry = entry?;
            num_entries += 1;
            match entry {
                ArchiveEntry::Symbols(t) => symbol_table = Some(t),
                ArchiveEntry::Filenames(t) => filenames = Some(t),
                _ => break,
            }
        }
        // Allow completely empty archives without reporting an error due to not not containing a
        // symbol table.
        if num_entries == 0 {
            return Ok(Vec::new());
        }
        let symbol_table =
            symbol_table.context("Archives without symbol tables are not currently supported")?;
        self.load_from_symbol_table(symbol_table, filenames)
    }

    fn load_from_symbol_table(
        self,
        symbol_table: archive::SymbolTable<'data>,
        filenames: Option<ExtendedFilenames<'data>>,
    ) -> Result<Vec<SymbolLoadOutputs<'data>>> {
        let mut symbols = Vec::with_capacity(symbol_table.num_symbols() as usize);
        symbols.extend(symbol_table.symbols().map(|s| {
            PendingSymbol::new(
                FileId::placeholder(),
                // We misuse the local index to temporarily store the header offset. We'll populate
                // the actual local index when/if we load the object file.
                object::SymbolIndex(s.header_offset as usize),
                s.name,
            )
        }));
        symbols.sort_by_key(|s| s.symbol.local_index_without_checking_file_id().0);
        let mut objects = Vec::new();
        let mut object_symbols = Vec::new();
        let mut header_offset = 0;
        for mut symbol in symbols {
            if symbol.symbol.local_index_without_checking_file_id().0 as u32 != header_offset {
                if !object_symbols.is_empty() {
                    objects.push(SymbolLoadOutputs {
                        pending_symbols: core::mem::take(&mut object_symbols),
                        reader: SymbolReader::ArchiveEntry(UnloadedArchivedObjectSymbolReader {
                            header_offset,
                            input_file: self.input_file,
                            filenames,
                        }),
                    });
                }
                header_offset = symbol.symbol.local_index_without_checking_file_id().0 as u32;
            }
            // We don't know the local index until we load the object file contained within the
            // archive entry. We put a large distinctive value here so that if we try to use it
            // prior to putting the actual index here, we'll crash in a way that will be easier to
            // diagnose.
            symbol.symbol.set_local_index(object::SymbolIndex(999999));
            object_symbols.push(symbol);
        }
        if !object_symbols.is_empty() {
            objects.push(SymbolLoadOutputs {
                pending_symbols: core::mem::take(&mut object_symbols),
                reader: SymbolReader::ArchiveEntry(UnloadedArchivedObjectSymbolReader {
                    header_offset,
                    input_file: self.input_file,
                    filenames,
                }),
            });
        }
        Ok(objects)
    }
}

impl<'data> UnloadedArchivedObjectSymbolReader<'data> {
    fn symbols_defined(self, file_id: FileId) -> ArchivedObject<'data> {
        ArchivedObject::Unloaded(UnloadedArchivedObject {
            file_id,
            header_offset: self.header_offset,
            input_file: self.input_file,
            filenames: self.filenames,
        })
    }
}

impl InternalSymbolReader {
    fn load_symbols(mut self) -> Result<SymbolLoadOutputs<'static>> {
        let mut symbols = Vec::new();
        for section_id in output_section_id::built_in_section_ids() {
            let def = section_id.built_in_details();
            if let Some(name) = def.start_symbol_name {
                symbols.push(PendingSymbol::new(
                    input_data::INTERNAL_FILE_ID,
                    object::SymbolIndex(self.symbol_definitions.len()),
                    name.as_bytes(),
                ));
                self.symbol_definitions
                    .push(InternalSymDefInfo::SectionStart(section_id));
            }
            if let Some(name) = def.end_symbol_name {
                symbols.push(PendingSymbol::new(
                    input_data::INTERNAL_FILE_ID,
                    object::SymbolIndex(self.symbol_definitions.len()),
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
    fn new(input_file: &'data InputFile, args: &'data Args) -> Result<Self> {
        Ok(match input_file.kind {
            FileKind::Internal => Self::Internal(InternalSymbolReader::new(args)?),
            FileKind::Archive => Self::Archive(ArchiveSymbolReader::new(input_file)),
            FileKind::ElfObject => Self::Object(ObjectSymbolReader::new(input_file)?),
            FileKind::ElfDynamic => {
                if true {
                    bail!("Dynamic linking is not yet implemented");
                }
                Self::Dynamic(ObjectSymbolReader::new(input_file)?)
            }
            FileKind::Text => unreachable!("Should have been handled earlier"),
        })
    }

    fn filename(&self) -> &'data Path {
        match self {
            Self::Internal(s) => s.filename(),
            Self::Object(s) => s.filename(),
            Self::Archive(s) => s.filename(),
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

impl<'data> ObjectSymbolReader<'data> {
    fn new(input_file: &'data InputFile) -> Result<Self> {
        let object = Box::new(File::parse(input_file.data()).with_context(|| {
            format!(
                "Failed to parse object file `{}`",
                input_file.filename.display()
            )
        })?);
        Ok(Self { input_file, object })
    }

    fn filename(&self) -> &'data Path {
        &self.input_file.filename
    }
}

impl<'data> ArchiveSymbolReader<'data> {
    fn new(input_file: &'data InputFile) -> Self {
        Self {
            input_file,
            data: input_file.data(),
        }
    }

    fn filename(&self) -> &'data Path {
        &self.input_file.filename
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

impl<'data> ArchivedObject<'data> {
    pub(crate) fn file_id(&self) -> FileId {
        match self {
            ArchivedObject::Unloaded(s) => s.file_id,
        }
    }
}

impl<'data> PendingSymbol<'data> {
    fn new(
        file_id: FileId,
        local_index: object::SymbolIndex,
        name: &'data [u8],
    ) -> PendingSymbol<'data> {
        PendingSymbol {
            symbol: Symbol::new(file_id, local_index),
            name: SymbolName::new(name),
        }
    }
}
