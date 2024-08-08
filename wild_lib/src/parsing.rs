use crate::archive_splitter::InputBytes;
use crate::args::Args;
use crate::args::Modifiers;
use crate::args::OutputKind;
use crate::args::RelocationModel;
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
use crate::threading::prelude::*;
use anyhow::Context;
use std::path::Path;

#[tracing::instrument(skip_all, name = "Parse input files")]
pub(crate) fn parse_input_files<'data>(
    inputs: &'data [InputBytes],
    args: &'data Args,
) -> Result<Vec<ParsedInput<'data>>> {
    let mut objects = inputs
        .par_iter()
        .enumerate()
        .map(|(index, f)| ParsedInput::new(f, FileId::from_usize(index)?, args))
        .collect::<Result<Vec<ParsedInput>>>()?;
    objects.push(ParsedInput::Epilogue(Epilogue {
        file_id: FileId::from_usize(objects.len())?,
        start_symbol_id: SymbolId::undefined(),
    }));
    let mut next_symbol_id = SymbolId::undefined();
    for obj in &mut objects {
        match obj {
            ParsedInput::Internal(_) => {
                // No need to store the symbol ID, since internal always starts from the undefined
                // symbol.
                assert_eq!(next_symbol_id, SymbolId::undefined());
            }
            ParsedInput::Object(o) => {
                o.symbol_id_range.set_start(next_symbol_id);
            }
            ParsedInput::Epilogue(o) => {
                o.start_symbol_id = next_symbol_id;
            }
        }
        next_symbol_id = next_symbol_id.add_usize(obj.num_symbols());
    }
    Ok(objects)
}

// Object is much larger than the other two, but there's many objects and only ever one of each of
// the two smaller variants, so it doesn't matter.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ParsedInput<'data> {
    Internal(InternalInputObject),
    Object(ParsedInputObject<'data>),
    Epilogue(Epilogue),
}

pub(crate) struct InternalInputObject {
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo>,
}

pub(crate) struct ParsedInputObject<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) object: File<'data>,
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

impl<'data> ParsedInputObject<'data> {
    fn new(input: &'data InputBytes, file_id: FileId, is_dynamic: bool) -> Result<Self> {
        let object = File::parse(input.data, is_dynamic)
            .with_context(|| format!("Failed to parse object file `{input}`"))?;
        let num_symbols = object.symbols.len();
        Ok(Self {
            input: input.input.clone(),
            object,
            symbol_id_range: SymbolIdRange::input(
                // Filled in once we've parsed all objects.
                SymbolId::undefined(),
                num_symbols,
            ),
            file_id,
            is_dynamic,
            modifiers: input.modifiers,
        })
    }

    pub(crate) fn is_dynamic(&self) -> bool {
        self.is_dynamic
    }

    /// Returns whether this input should be skipped if there are no non-weak reference to symbols
    /// it defines. This is true for archive entries and shared objects for which --as-needed is
    /// true.
    pub(crate) fn is_optional(&self) -> bool {
        self.input.entry.is_some() || (self.is_dynamic() && self.modifiers.as_needed)
    }

    fn filename(&self) -> &'data Path {
        &self.input.file.filename
    }

    pub(crate) fn symbol_name(
        &self,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> Result<SymbolName<'data>> {
        let index = symbol_id.to_input(self.symbol_id_range);
        let symbol = self.object.symbol(index)?;
        Ok(SymbolName::new(self.object.symbol_name(symbol)?))
    }
}

impl<'data> ParsedInput<'data> {
    fn new(input: &'data InputBytes, file_id: FileId, args: &'data Args) -> Result<Self> {
        Ok(match input.kind {
            FileKind::ElfObject | FileKind::Archive => {
                Self::Object(ParsedInputObject::new(input, file_id, false)?)
            }
            FileKind::Internal => Self::Internal(InternalInputObject::new(file_id, args)?),
            FileKind::ElfDynamic => Self::Object(ParsedInputObject::new(input, file_id, true)?),
            FileKind::Text => unreachable!("Should have been handled earlier"),
        })
    }

    pub(crate) fn num_symbols(&self) -> usize {
        match self {
            ParsedInput::Internal(o) => o.symbol_definitions.len(),
            ParsedInput::Object(o) => o.symbol_id_range.len(),
            ParsedInput::Epilogue(_) => {
                // Initially, we report 0 symbols because we don't know what symbols we'll define
                // until after archives have been processed. We're the last input file, so we can
                // allocate symbols at the end.
                0
            }
        }
    }

    pub(crate) fn filename(&self) -> &'data Path {
        match self {
            ParsedInput::Object(s) => s.filename(),
            ParsedInput::Internal(_) => Path::new("<<internal>>"),
            ParsedInput::Epilogue(_) => Path::new("<<epilogue>>"),
        }
    }

    pub(crate) fn symbol_id_range(&self) -> SymbolIdRange {
        match self {
            ParsedInput::Internal(o) => SymbolIdRange::internal(o.symbol_definitions.len()),
            ParsedInput::Object(o) => o.symbol_id_range,
            ParsedInput::Epilogue(o) => SymbolIdRange::epilogue(o.start_symbol_id, 0),
        }
    }

    pub(crate) fn is_regular_object(&self) -> bool {
        match self {
            ParsedInput::Object(o) => !o.is_dynamic(),
            ParsedInput::Internal(_) => false,
            ParsedInput::Epilogue(_) => false,
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
            if args.output_kind != OutputKind::StaticExecutable(RelocationModel::NonRelocatable)
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

impl<'data> std::fmt::Display for ParsedInputObject<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl<'data> std::fmt::Display for ParsedInput<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParsedInput::Internal(_) => std::fmt::Display::fmt("<internal>", f),
            ParsedInput::Object(o) => std::fmt::Display::fmt(o, f),
            ParsedInput::Epilogue(_) => std::fmt::Display::fmt("<custom-sections>", f),
        }
    }
}
