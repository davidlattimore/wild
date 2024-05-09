use crate::archive_splitter::InputBytes;
use crate::args::Args;
use crate::args::Modifiers;
use crate::args::OutputKind;
use crate::elf::File;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::input_data::FileId;
use crate::input_data::InputRef;
use crate::input_data::INTERNAL_FILE_ID;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::sharding::ShardKey;
use crate::symbol::SymbolName;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use anyhow::Context;
use object::Object as _;
use object::ObjectSymbol;
use object::ObjectSymbolTable as _;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefIterator as _;
use rayon::iter::ParallelIterator as _;
use std::path::Path;

#[tracing::instrument(skip_all, name = "Parse input files")]
pub(crate) fn parse_input_files<'data>(
    inputs: &'data [InputBytes],
    args: &'data Args,
) -> Result<Vec<InputObject<'data>>> {
    let mut objects = inputs
        .par_iter()
        .enumerate()
        .map(|(index, f)| InputObject::new(f, FileId::from_usize(index)?, args))
        .collect::<Result<Vec<InputObject>>>()?;
    objects.push(InputObject::Epilogue(Epilogue {
        file_id: FileId::from_usize(objects.len())?,
        start_symbol_id: SymbolId::undefined(),
    }));
    let mut next_symbol_id = SymbolId::undefined();
    for obj in &mut objects {
        match obj {
            InputObject::Internal(_) => {
                // No need to store the symbol ID, since internal always starts from the undefined
                // symbol.
                assert_eq!(next_symbol_id, SymbolId::undefined());
            }
            InputObject::Object(o) => {
                o.symbol_id_range.set_start(next_symbol_id);
            }
            InputObject::Epilogue(o) => {
                o.start_symbol_id = next_symbol_id;
            }
        }
        next_symbol_id = next_symbol_id.add_usize(obj.num_symbols());
    }
    Ok(objects)
}

pub(crate) enum InputObject<'data> {
    Internal(InternalInputObject),
    Object(RegularInputObject<'data>),
    Epilogue(Epilogue),
}

pub(crate) struct InternalInputObject {
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo>,
}

pub(crate) struct RegularInputObject<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) object: Box<File<'data>>,
    pub(crate) symbol_id_range: SymbolIdRange,
    pub(crate) file_id: FileId,
    pub(crate) is_dynamic: bool,
    modifiers: Modifiers,
}

pub(crate) struct Epilogue {
    pub(crate) file_id: FileId,
    pub(crate) start_symbol_id: SymbolId,
}

#[derive(Clone, Copy)]
pub(crate) enum InternalSymDefInfo {
    /// Symbol 0 - the undefined symbol.
    Undefined,

    /// Defines a symbol that points to the start of a section.
    SectionStart(OutputSectionId),

    /// Defines a symbol that points at the non-inclusive end of the section. i.e. 1 byte past the
    /// last byte of the section.
    SectionEnd(OutputSectionId),
}

impl<'data> RegularInputObject<'data> {
    fn new(input: &'data InputBytes, file_id: FileId, is_dynamic: bool) -> Result<Self> {
        let object = Box::new(
            File::parse(input.data)
                .with_context(|| format!("Failed to parse object file `{input}`"))?,
        );
        // Note, this looks bad performance-wise, but it seems like it's actually OK. Initially, I
        // tried using object.section_by_name(".symtab") then getting the size and computing the
        // number of symbols from that. However it turns out that, perhaps not surprisingly that
        // `section_by_name` is really slow.
        let num_symbols = if is_dynamic {
            object.dynamic_symbols().count()
        } else {
            object.symbols().count()
        };
        // object.symbols() may not return the null symbol.
        let start_symbol_index = if is_dynamic {
            object
                .dynamic_symbols()
                .next()
                .map(|s| s.index())
                .unwrap_or(object::SymbolIndex(0))
        } else {
            object
                .symbols()
                .next()
                .map(|s| s.index())
                .unwrap_or(object::SymbolIndex(0))
        };
        Ok(Self {
            input: input.input.clone(),
            object,
            symbol_id_range: SymbolIdRange::input(
                // Filled in once we've parsed all objects.
                SymbolId::undefined(),
                start_symbol_index,
                num_symbols,
            ),
            file_id,
            is_dynamic,
            modifiers: input.modifiers,
        })
    }

    /// Returns whether this input should be skipped if there are no non-weak reference to symbols
    /// it defines. This is true for archive entries and shared objects for which --as-needed is
    /// true.
    pub(crate) fn is_optional(&self) -> bool {
        self.input.entry.is_some() || (self.is_dynamic && self.modifiers.as_needed)
    }

    fn filename(&self) -> &'data Path {
        &self.input.file.filename
    }

    pub(crate) fn symbol_name(
        &self,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> Result<SymbolName<'data>> {
        let index = symbol_id.to_input(self.symbol_id_range);
        let symbol = if self.is_dynamic {
            self.object
                .dynamic_symbol_table()
                .context("Missing dynamic symbol table")?
                .symbol_by_index(index)?
        } else {
            self.object.symbol_by_index(index)?
        };
        Ok(SymbolName::new(symbol.name_bytes()?))
    }
}

impl<'data> InputObject<'data> {
    fn new(input: &'data InputBytes, file_id: FileId, args: &'data Args) -> Result<Self> {
        Ok(match input.kind {
            FileKind::ElfObject | FileKind::Archive => {
                Self::Object(RegularInputObject::new(input, file_id, false)?)
            }
            FileKind::Internal => Self::Internal(InternalInputObject::new(file_id, args)?),
            FileKind::ElfDynamic => Self::Object(RegularInputObject::new(input, file_id, true)?),
            FileKind::Text => unreachable!("Should have been handled earlier"),
        })
    }

    pub(crate) fn num_symbols(&self) -> usize {
        match self {
            InputObject::Internal(o) => o.symbol_definitions.len(),
            InputObject::Object(o) => o.symbol_id_range.len(),
            InputObject::Epilogue(_) => {
                // Initially, we report 0 symbols because we don't know what symbols we'll define
                // until after archives have been processed. We're the last input file, so we can
                // allocate symbols at the end.
                0
            }
        }
    }

    pub(crate) fn filename(&self) -> &'data Path {
        match self {
            InputObject::Object(s) => s.filename(),
            InputObject::Internal(_) => Path::new("<<internal>>"),
            InputObject::Epilogue(_) => Path::new("<<custom sections>>"),
        }
    }

    pub(crate) fn symbol_id_range(&self) -> SymbolIdRange {
        match self {
            InputObject::Internal(o) => SymbolIdRange::internal(o.symbol_definitions.len()),
            InputObject::Object(o) => o.symbol_id_range,
            InputObject::Epilogue(o) => SymbolIdRange::epilogue(o.start_symbol_id, 0),
        }
    }
}

impl InternalInputObject {
    fn new(file_id: FileId, args: &Args) -> Result<Self> {
        assert_eq!(file_id, INTERNAL_FILE_ID);
        // The undefined symbol must always be symbol 0.
        let mut symbol_definitions = vec![InternalSymDefInfo::Undefined];
        for section_id in output_section_id::built_in_section_ids() {
            // If we're not producing a relocatable output, then don't define any symbols for the
            // .dynamic section.
            if section_id == output_section_id::DYNAMIC && !args.is_relocatable() {
                continue;
            }
            let def = section_id.built_in_details();
            // .rela.plt start/stop symbols are only emitted for non-relocatable executables.
            // Emitting them for relocatable binaries causes glibc to try to call the resolver
            // functions without taking into account that the binary has been relocated.
            if args.output_kind != OutputKind::NonRelocatableStaticExecutable
                && section_id == output_section_id::RELA_PLT
            {
                continue;
            }
            if def.start_symbol_name.is_some() {
                symbol_definitions.push(InternalSymDefInfo::SectionStart(section_id));
            }
            if def.end_symbol_name.is_some() {
                symbol_definitions.push(InternalSymDefInfo::SectionEnd(section_id));
            }
        }
        Ok(Self { symbol_definitions })
    }

    pub(crate) fn symbol_name(&self, symbol_id: SymbolId) -> SymbolName<'static> {
        let def = &self.symbol_definitions[symbol_id.as_usize()];
        let name = match def {
            InternalSymDefInfo::Undefined => Some(""),
            InternalSymDefInfo::SectionStart(section_id) => {
                section_id.built_in_details().start_symbol_name
            }
            InternalSymDefInfo::SectionEnd(section_id) => {
                section_id.built_in_details().end_symbol_name
            }
        }
        .unwrap();
        SymbolName::new(name.as_bytes())
    }
}

impl<'data> std::fmt::Display for RegularInputObject<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl<'data> std::fmt::Display for InputObject<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputObject::Internal(_) => std::fmt::Display::fmt("<internal>", f),
            InputObject::Object(o) => std::fmt::Display::fmt(o, f),
            InputObject::Epilogue(_) => std::fmt::Display::fmt("<custom-sections>", f),
        }
    }
}
