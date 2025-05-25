use crate::LayoutRules;
use crate::OutputSections;
use crate::archive_splitter::InputBytes;
use crate::args::Args;
use crate::args::Modifiers;
use crate::args::OutputKind;
use crate::args::RelocationModel;
use crate::bail;
use crate::elf::File;
use crate::error::Context as _;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::input_data::FileId;
use crate::input_data::InputLinkerScript;
use crate::input_data::InputRef;
use crate::input_data::UNINITIALISED_FILE_ID;
use crate::layout_rules::LayoutRulesBuilder;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::sharding::ShardKey;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;

#[tracing::instrument(skip_all, name = "Parse input files")]
pub(crate) fn parse_input_files<'data>(
    inputs: &[InputBytes<'data>],
    linker_scripts_in: &[InputLinkerScript<'data>],
    args: &'data Args,
    output_sections: &mut OutputSections<'data>,
    herd: &'data bumpalo_herd::Herd,
) -> Result<(ParsedInputs<'data>, LayoutRules<'data>)> {
    let (objects, prelude) = rayon::join(
        || {
            inputs
                .par_iter()
                .map(|f| ParsedInputObject::new(f, args))
                .collect::<Result<Vec<ParsedInputObject>>>()
        },
        move || Prelude::new(args),
    );

    let mut builder = LayoutRulesBuilder::default();

    let linker_scripts = linker_scripts_in
        .iter()
        .map(|script| builder.process_linker_script(script, output_sections))
        .collect::<Result<Vec<ProcessedLinkerScript>>>()?;

    let layout_rules = builder.build();

    let objects = herd.get().alloc_slice_fill_iter(objects?.into_iter());

    let mut parsed_inputs = ParsedInputs {
        prelude,
        objects,
        linker_scripts,
        epilogue: Epilogue::new(),
    };

    set_start_symbol_ids(&mut parsed_inputs);

    Ok((parsed_inputs, layout_rules))
}

pub(crate) struct ParsedInputs<'data> {
    pub(crate) prelude: Prelude<'data>,
    pub(crate) objects: &'data mut [ParsedInputObject<'data>],
    pub(crate) linker_scripts: Vec<ProcessedLinkerScript<'data>>,
    pub(crate) epilogue: Epilogue,
}

impl ParsedInputs<'_> {
    pub(crate) fn num_symbols(&self) -> usize {
        self.epilogue.start_symbol_id.as_usize()
    }
}

fn set_start_symbol_ids(objects: &mut ParsedInputs) {
    let mut next_symbol_id = SymbolId::undefined();
    next_symbol_id = next_symbol_id.add_usize(objects.prelude.symbol_definitions.len());

    for obj in objects.objects.iter_mut() {
        obj.symbol_id_range.set_start(next_symbol_id);
        next_symbol_id = next_symbol_id.add_usize(obj.symbol_id_range.len());
    }

    for script in &mut objects.linker_scripts {
        script.symbol_id_range.set_start(next_symbol_id);
        next_symbol_id = next_symbol_id.add_usize(script.symbol_id_range.len());
    }

    objects.epilogue.start_symbol_id = next_symbol_id;
}

pub(crate) enum ParsedInput<'data> {
    Prelude(&'data Prelude<'data>),
    Object(&'data ParsedInputObject<'data>),
    LinkerScript(&'data ProcessedLinkerScript<'data>),
    Epilogue(&'data Epilogue),
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

pub(crate) struct ProcessedLinkerScript<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) file_id: FileId,
    pub(crate) symbol_names: Vec<UnversionedSymbolName<'data>>,
    pub(crate) symbol_defs: Vec<InternalSymDefInfo>,
    pub(crate) symbol_id_range: SymbolIdRange,
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
    fn new(input: &InputBytes<'data>, args: &Args) -> Result<Self> {
        let is_dynamic = input.kind == FileKind::ElfDynamic;

        let object = File::parse(input.data, is_dynamic)
            .with_context(|| format!("Failed to parse object file `{input}`"))?;

        if object.arch != args.arch {
            bail!(
                "`{}` has incompatible architecture: {:?}, expecting {:?}",
                input.input,
                object.arch,
                args.arch,
            )
        }

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

    pub(crate) fn set_file_id(&mut self, file_id: FileId) {
        self.file_id = file_id;
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

impl ParsedInput<'_> {
    pub(crate) fn symbol_id_range(&self) -> SymbolIdRange {
        match self {
            ParsedInput::Prelude(o) => SymbolIdRange::prelude(o.symbol_definitions.len()),
            ParsedInput::Object(o) => o.symbol_id_range,
            ParsedInput::LinkerScript(o) => o.symbol_id_range,
            ParsedInput::Epilogue(o) => SymbolIdRange::epilogue(
                o.start_symbol_id,
                // The epilogue allocates symbols after inputs are parsed, so it effectively owns
                // the rest of the symbol ID space.
                u32::MAX as usize - o.start_symbol_id.as_usize(),
            ),
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

            if def.start_symbol_name.is_some() {
                symbol_definitions.push(InternalSymDefInfo::SectionStart(section_id));
            }

            if def.end_symbol_name.is_some() {
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

    pub(crate) fn symbol_name(&self, symbol_id: SymbolId) -> UnversionedSymbolName<'data> {
        let def = &self.symbol_definitions[symbol_id.as_usize()];
        let name = match def {
            InternalSymDefInfo::Undefined => Some(""),
            InternalSymDefInfo::SectionStart(section_id) => {
                section_id.built_in_details().start_symbol_name
            }
            InternalSymDefInfo::SectionEnd(section_id) => {
                section_id.built_in_details().end_symbol_name
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

impl<'data> ProcessedLinkerScript<'data> {
    pub(crate) fn symbol_name(&self, symbol_id: SymbolId) -> UnversionedSymbolName<'data> {
        let local_index = self.symbol_id_range.id_to_offset(symbol_id);
        self.symbol_names[local_index]
    }
}

impl std::fmt::Display for ParsedInputObject<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl std::fmt::Display for ProcessedLinkerScript<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl std::fmt::Display for ParsedInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParsedInput::Prelude(_) => std::fmt::Display::fmt("<prelude>", f),
            ParsedInput::Object(o) => std::fmt::Display::fmt(o, f),
            ParsedInput::LinkerScript(o) => std::fmt::Display::fmt(o, f),
            ParsedInput::Epilogue(_) => std::fmt::Display::fmt("<epilogue>", f),
        }
    }
}
