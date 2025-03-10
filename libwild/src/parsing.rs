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
use crate::input_data::PRELUDE_FILE_ID;
use crate::input_data::UNINITIALISED_FILE_ID;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::sharding::ShardKey;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use anyhow::Context;
use anyhow::bail;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use std::path::Path;

#[tracing::instrument(skip_all, name = "Parse input files")]
pub(crate) fn parse_input_files<'data>(
    inputs: &'data [InputBytes],
    args: &'data Args,
) -> Result<Vec<ParsedInput<'data>>> {
    let mut objects = inputs
        .par_iter()
        .map(|f| ParsedInput::new(f, args))
        .collect::<Result<Vec<ParsedInput>>>()?;

    set_start_symbol_ids(&mut objects);

    Ok(objects)
}

fn set_start_symbol_ids(objects: &mut [ParsedInput]) {
    let mut next_symbol_id = SymbolId::undefined();
    for obj in objects {
        match obj {
            ParsedInput::Prelude(_) => {
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
}

// Object is much larger than the other two, but there's many objects and only ever one of each of
// the two smaller variants, so it doesn't matter.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ParsedInput<'data> {
    Prelude(Prelude<'data>),
    Object(ParsedInputObject<'data>),
    Epilogue(Epilogue),
}

pub(crate) struct Prelude<'data> {
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo>,
    undefined: &'data [String],
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

impl Epilogue {
    fn new() -> Self {
        Self {
            file_id: UNINITIALISED_FILE_ID,
            // Filled in later in `set_start_symbol_ids`.
            start_symbol_id: SymbolId::undefined(),
        }
    }
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

    /// An undefined symbol supplied by the user, e.g. via `--undefined=symbol-name`.
    ForceUndefined(UndefinedSymbolIndex),
}

/// The index of an undefined symbol supplied by the user, e.g. via the `--undefined=symbol-name`.
#[derive(Clone, Copy)]
pub(crate) struct UndefinedSymbolIndex(u32);

impl<'data> ParsedInputObject<'data> {
    fn new(input: &'data InputBytes, is_dynamic: bool) -> Result<Self> {
        let object = File::parse(input.data, is_dynamic)
            .with_context(|| format!("Failed to parse object file `{input}`"))?;

        let num_symbols = object.symbols.len();

        Ok(Self {
            input: input.input.clone(),
            object,
            symbol_id_range: SymbolIdRange::input(
                // Filled in later in `set_start_symbol_ids`.
                SymbolId::undefined(),
                num_symbols,
            ),
            file_id: UNINITIALISED_FILE_ID,
            is_dynamic,
            modifiers: input.modifiers,
        })
    }

    pub(crate) fn is_dynamic(&self) -> bool {
        self.is_dynamic
    }

    /// Returns whether this input should be skipped if there are no non-weak references to symbols
    /// it defines. This is true for archive entries for which --whole-archive is false and shared
    /// objects for which --as-needed is true.
    pub(crate) fn is_optional(&self) -> bool {
        (self.input.has_archive_semantics() && !self.modifiers.whole_archive)
            || (self.is_dynamic() && self.modifiers.as_needed)
    }

    fn filename(&self) -> &'data Path {
        &self.input.file.filename
    }

    pub(crate) fn symbol_name(
        &self,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> Result<UnversionedSymbolName<'data>> {
        let index = symbol_id.to_input(self.symbol_id_range);
        let symbol = self.object.symbol(index)?;
        Ok(UnversionedSymbolName::new(self.object.symbol_name(symbol)?))
    }
}

impl<'data> ParsedInput<'data> {
    fn new(input: &'data InputBytes, args: &'data Args) -> Result<Self> {
        Ok(match input.kind {
            FileKind::ElfObject | FileKind::Archive => {
                let obj = ParsedInputObject::new(input, false)?;
                if obj.object.arch == args.arch {
                    Self::Object(obj)
                } else {
                    bail!(
                        "`{}` has incompatible architecture: {:?}, expecting {:?}",
                        obj.filename().display(),
                        obj.object.arch,
                        args.arch,
                    )
                }
            }
            FileKind::Prelude => Self::Prelude(Prelude::new(args)),
            FileKind::ElfDynamic => Self::Object(ParsedInputObject::new(input, true)?),
            FileKind::ThinArchive | FileKind::Text => {
                unreachable!("{:?} should have been handled earlier", input.kind)
            }
            FileKind::Epilogue => Self::Epilogue(Epilogue::new()),
        })
    }

    pub(crate) fn num_symbols(&self) -> usize {
        match self {
            ParsedInput::Prelude(o) => o.symbol_definitions.len(),
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
            ParsedInput::Prelude(_) => Path::new("<<prelude>>"),
            ParsedInput::Epilogue(_) => Path::new("<<epilogue>>"),
        }
    }

    pub(crate) fn symbol_id_range(&self) -> SymbolIdRange {
        match self {
            ParsedInput::Prelude(o) => SymbolIdRange::prelude(o.symbol_definitions.len()),
            ParsedInput::Object(o) => o.symbol_id_range,
            ParsedInput::Epilogue(o) => SymbolIdRange::epilogue(o.start_symbol_id, 0),
        }
    }

    pub(crate) fn file_id(&self) -> FileId {
        let file_id = match self {
            ParsedInput::Prelude(_) => PRELUDE_FILE_ID,
            ParsedInput::Object(s) => s.file_id,
            ParsedInput::Epilogue(s) => s.file_id,
        };
        debug_assert_ne!(
            file_id, UNINITIALISED_FILE_ID,
            "Called ParsedInput::file_id before set_file_id was called"
        );
        file_id
    }

    pub(crate) fn set_file_id(&mut self, file_id: FileId) {
        match self {
            ParsedInput::Prelude(_) => {
                assert_eq!(file_id, PRELUDE_FILE_ID);
            }
            ParsedInput::Object(s) => s.file_id = file_id,
            ParsedInput::Epilogue(s) => s.file_id = file_id,
        }
    }
}

impl<'data> Prelude<'data> {
    fn new(args: &'data Args) -> Self {
        // The undefined symbol must always be symbol 0.
        let mut symbol_definitions = vec![InternalSymDefInfo::Undefined];

        for section_id in output_section_id::built_in_section_ids() {
            // If we're producing non-relocatable, static executable, then don't define any symbols
            // for the .dynamic section.
            if section_id == output_section_id::DYNAMIC
                && args.output_kind()
                    == OutputKind::StaticExecutable(RelocationModel::NonRelocatable)
            {
                continue;
            }

            let def = section_id.built_in_details();
            // .rela.plt start/stop symbols are only emitted for non-relocatable executables.
            // Emitting them for relocatable binaries causes glibc to try to call the resolver
            // functions without taking into account that the binary has been relocated.
            if args.output_kind() != OutputKind::StaticExecutable(RelocationModel::NonRelocatable)
                && section_id == output_section_id::RELA_PLT
            {
                continue;
            }

            if def.start_symbol_name(args.output_kind()).is_some() {
                symbol_definitions.push(InternalSymDefInfo::SectionStart(section_id));
            }

            if def.end_symbol_name(args.output_kind()).is_some() {
                symbol_definitions.push(InternalSymDefInfo::SectionEnd(section_id));
            }
        }

        symbol_definitions.extend(
            (0..args.undefined.len())
                .map(|i| InternalSymDefInfo::ForceUndefined(UndefinedSymbolIndex(i as u32))),
        );

        Self {
            symbol_definitions,
            undefined: &args.undefined,
        }
    }

    pub(crate) fn symbol_name(
        &self,
        symbol_id: SymbolId,
        output_kind: OutputKind,
    ) -> UnversionedSymbolName<'data> {
        let def = &self.symbol_definitions[symbol_id.as_usize()];
        let name = match def {
            InternalSymDefInfo::Undefined => Some(""),
            InternalSymDefInfo::SectionStart(section_id) => {
                section_id.built_in_details().start_symbol_name(output_kind)
            }
            InternalSymDefInfo::SectionEnd(section_id) => {
                section_id.built_in_details().end_symbol_name(output_kind)
            }
            InternalSymDefInfo::ForceUndefined(i) => Some(self.undefined[i.0 as usize].as_str()),
        }
        .unwrap();
        UnversionedSymbolName::new(name.as_bytes())
    }

    pub(crate) fn get_undefined_name(
        &self,
        undefined_symbol_index: UndefinedSymbolIndex,
    ) -> &'data [u8] {
        self.undefined[undefined_symbol_index.0 as usize].as_bytes()
    }
}

impl std::fmt::Display for ParsedInputObject<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl std::fmt::Display for ParsedInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParsedInput::Prelude(_) => std::fmt::Display::fmt("<prelude>", f),
            ParsedInput::Object(o) => std::fmt::Display::fmt(o, f),
            ParsedInput::Epilogue(_) => std::fmt::Display::fmt("<epilogue>", f),
        }
    }
}
