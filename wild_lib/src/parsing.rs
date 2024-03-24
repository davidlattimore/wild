use crate::archive_splitter::InputBytes;
use crate::args::Args;
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
use anyhow::bail;
use anyhow::Context;
use object::Object as _;
use object::ObjectSymbol;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefIterator as _;
use rayon::iter::ParallelIterator as _;
use std::ffi::CString;
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
                o.start_symbol_id = next_symbol_id;
            }
            InputObject::Dynamic(o) => {
                o.start_symbol_id = next_symbol_id;
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
    Dynamic(RegularInputObject<'data>),
    Epilogue(Epilogue),
}

pub(crate) struct InternalInputObject {
    pub(crate) dynamic_linker: Option<CString>,
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo>,
}

pub(crate) struct RegularInputObject<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) object: Box<File<'data>>,
    pub(crate) num_symbols: usize,
    pub(crate) start_symbol_id: SymbolId,
    pub(crate) file_id: FileId,
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
    fn new(input: &'data InputBytes, file_id: FileId) -> Result<Self> {
        let object = Box::new(
            File::parse(input.data)
                .with_context(|| format!("Failed to parse object file `{input}`"))?,
        );
        // Note, this looks bad performance-wise, but it seems like it's actually OK. Initially, I
        // tried using object.section_by_name(".symtab") then getting the size and computing the
        // number of symbols from that. However it turns out that, perhaps not surprisingly that
        // `section_by_name` is really slow.
        let num_symbols = object.symbols().count();
        Ok(Self {
            input: input.input,
            object,
            num_symbols,
            // Filled in once we've parsed all objects.
            start_symbol_id: SymbolId::undefined(),
            file_id,
        })
    }

    pub(crate) fn is_from_archive(&self) -> bool {
        self.input.entry_filename.is_some()
    }

    fn filename(&self) -> &'data Path {
        &self.input.file.filename
    }

    pub(crate) fn symbol_name(
        &self,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> Result<SymbolName<'data>> {
        let symbol = self.object.symbol_by_index(object::SymbolIndex(
            symbol_id.offset_from(self.start_symbol_id),
        ))?;
        Ok(SymbolName::new(symbol.name_bytes()?))
    }
}

impl<'data> InputObject<'data> {
    fn new(input: &'data InputBytes, file_id: FileId, args: &'data Args) -> Result<Self> {
        Ok(match input.kind {
            FileKind::ElfObject | FileKind::Archive => {
                Self::Object(RegularInputObject::new(input, file_id)?)
            }
            FileKind::Internal => Self::Internal(InternalInputObject::new(file_id, args)?),
            FileKind::ElfDynamic => {
                if true {
                    bail!("Dynamic linking is not yet implemented");
                }
                Self::Dynamic(RegularInputObject::new(input, file_id)?)
            }
            FileKind::Text => unreachable!("Should have been handled earlier"),
        })
    }

    pub(crate) fn num_symbols(&self) -> usize {
        match self {
            InputObject::Internal(o) => o.symbol_definitions.len(),
            InputObject::Object(o) => o.num_symbols,
            InputObject::Dynamic(_) => todo!(),
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
            InputObject::Dynamic(s) => s.filename(),
            InputObject::Epilogue(_) => Path::new("<<custom sections>>"),
        }
    }

    pub(crate) fn start_symbol_id(&self) -> SymbolId {
        match self {
            InputObject::Internal(_) => SymbolId::undefined(),
            InputObject::Object(o) => o.start_symbol_id,
            InputObject::Dynamic(o) => o.start_symbol_id,
            InputObject::Epilogue(o) => o.start_symbol_id,
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
            if def.start_symbol_name.is_some() {
                symbol_definitions.push(InternalSymDefInfo::SectionStart(section_id));
            }
            if def.end_symbol_name.is_some() {
                symbol_definitions.push(InternalSymDefInfo::SectionEnd(section_id));
            }
        }
        Ok(Self {
            dynamic_linker: args
                .dynamic_linker
                .as_ref()
                .map(|p| CString::new(p.as_os_str().as_encoded_bytes()))
                .transpose()?,
            symbol_definitions,
        })
    }

    pub(crate) fn symbol_name(&self, symbol_id: SymbolId) -> SymbolName<'static> {
        let def = &self.symbol_definitions[symbol_id.offset_from(SymbolId::undefined())];
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
            InputObject::Dynamic(o) => std::fmt::Display::fmt(o, f),
            InputObject::Epilogue(_) => std::fmt::Display::fmt("<custom-sections>", f),
        }
    }
}
