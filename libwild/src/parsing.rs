use crate::LayoutRules;
use crate::OutputSections;
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
use crate::input_data::InputBytes;
use crate::input_data::InputLinkerScript;
use crate::input_data::InputRef;
use crate::layout_rules::LayoutRulesBuilder;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolId;
use linker_utils::elf::SymbolType;
use linker_utils::elf::stt;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;

#[tracing::instrument(skip_all, name = "Parse input files")]
pub(crate) fn parse_input_files<'data>(
    inputs: &[InputBytes<'data>],
    linker_scripts: Vec<ProcessedLinkerScript<'data>>,
    args: &'data Args,
) -> Result<ParsedInputs<'data>> {
    let (objects, prelude) = rayon::join(
        || {
            inputs
                .par_iter()
                .map(|f| ParsedInputObject::new(f, args))
                .collect::<Result<Vec<ParsedInputObject>>>()
        },
        move || Prelude::new(args),
    );

    let objects = objects?;

    let num_symbols = count_symbols(&prelude, &objects, &linker_scripts);

    Ok(ParsedInputs {
        prelude,
        objects,
        linker_scripts,
        num_symbols,
    })
}

#[tracing::instrument(skip_all, name = "Process linker scripts")]
pub(crate) fn process_linker_scripts<'data>(
    linker_scripts_in: &[InputLinkerScript<'data>],
    output_sections: &mut OutputSections<'data>,
) -> Result<(Vec<ProcessedLinkerScript<'data>>, LayoutRules<'data>)> {
    let mut builder = LayoutRulesBuilder::default();

    let linker_scripts = linker_scripts_in
        .iter()
        .map(|script| builder.process_linker_script(script, output_sections))
        .collect::<Result<Vec<ProcessedLinkerScript>>>()?;

    Ok((linker_scripts, builder.build()))
}

pub(crate) struct ParsedInputs<'data> {
    pub(crate) prelude: Prelude<'data>,
    pub(crate) objects: Vec<ParsedInputObject<'data>>,
    pub(crate) linker_scripts: Vec<ProcessedLinkerScript<'data>>,

    /// Total number of symbols in the prelude, input objects and defined by linker scripts. Doesn't
    /// include symbols defined by the epilogue, since we don't know what they will be until later.
    pub(crate) num_symbols: usize,
}

#[derive(Debug)]
pub(crate) struct Prelude<'data> {
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo<'data>>,
}

#[derive(Debug)]
pub(crate) struct ParsedInputObject<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) object: File<'data>,
    pub(crate) is_dynamic: bool,
    pub(crate) modifiers: Modifiers,
}

#[derive(Debug)]
pub(crate) struct ProcessedLinkerScript<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) symbol_defs: Vec<InternalSymDefInfo<'data>>,
}

#[derive(Debug)]
pub(crate) struct Epilogue {
    pub(crate) file_id: FileId,
    pub(crate) start_symbol_id: SymbolId,
}

#[derive(Clone, Copy, derive_more::Debug)]
pub(crate) struct InternalSymDefInfo<'data> {
    pub(crate) placement: SymbolPlacement,
    #[debug("{:?}", String::from_utf8_lossy(name))]
    pub(crate) name: &'data [u8],
    pub(crate) elf_symbol_type: SymbolType,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SymbolPlacement {
    /// Symbol 0 - the undefined symbol.
    Undefined,

    /// Defines a symbol that points to the start of a section.
    SectionStart(OutputSectionId),

    /// Defines a symbol that points at the non-inclusive end of the section. i.e. 1 byte past the
    /// last byte of the section.
    SectionEnd(OutputSectionId),

    /// An undefined symbol supplied by the user, e.g. via `--undefined=symbol-name`.
    ForceUndefined,
}

impl<'data> InternalSymDefInfo<'data> {
    pub(crate) fn notype(placement: SymbolPlacement, name: &'data [u8]) -> Self {
        Self {
            placement,
            name,
            elf_symbol_type: stt::NOTYPE,
        }
    }
}

impl<'data> ParsedInputObject<'data> {
    fn new(input: &InputBytes<'data>, args: &Args) -> Result<Self> {
        let is_dynamic = input.kind == FileKind::ElfDynamic;

        let object = File::parse(input.data, is_dynamic)
            .with_context(|| format!("Failed to parse object file `{input}`"))?;

        if object.arch != args.arch {
            bail!(
                "`{}` has incompatible architecture: {}, expecting {}",
                input.input,
                object.arch,
                args.arch,
            )
        }

        Ok(Self {
            input: input.input.clone(),
            object,
            is_dynamic,
            modifiers: input.modifiers,
        })
    }

    fn num_symbols(&self) -> usize {
        self.object.symbols.len()
    }
}

impl<'data> Prelude<'data> {
    fn new(args: &'data Args) -> Self {
        // The undefined symbol must always be symbol 0.
        let mut symbol_definitions =
            vec![InternalSymDefInfo::notype(SymbolPlacement::Undefined, &[])];

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

            if let Some(name) = def.start_symbol_name {
                symbol_definitions.push(InternalSymDefInfo::notype(
                    SymbolPlacement::SectionStart(section_id),
                    name.as_bytes(),
                ));
            }

            if let Some(name) = def.end_symbol_name {
                symbol_definitions.push(InternalSymDefInfo::notype(
                    SymbolPlacement::SectionEnd(section_id),
                    name.as_bytes(),
                ));
            }

            if let Some(names) = def.synthetic_symbol_names {
                for name in names {
                    symbol_definitions.push(InternalSymDefInfo::notype(
                        SymbolPlacement::SectionStart(section_id),
                        name.as_bytes(),
                    ));
                }
            }
        }

        // We define _TLS_MODULE_BASE_ either at the start or end of the TLS segment, depending on
        // whether we're building a shared object or an executable. This symbol is used for TLSDESC.
        // See https://www.fsfla.org/~lxoliva/writeups/TLS/RFC-TLSDESC-x86.txt for more details.
        symbol_definitions.push(InternalSymDefInfo {
            placement: if args.output_kind() == OutputKind::SharedObject {
                SymbolPlacement::SectionStart(output_section_id::TDATA)
            } else {
                SymbolPlacement::SectionEnd(output_section_id::TBSS)
            },
            name: b"_TLS_MODULE_BASE_",
            elf_symbol_type: stt::TLS,
        });

        symbol_definitions.extend(args.undefined.iter().map(|name| {
            InternalSymDefInfo::notype(SymbolPlacement::ForceUndefined, name.as_bytes())
        }));

        Self { symbol_definitions }
    }

    pub(crate) fn symbol_name(&self, symbol_id: SymbolId) -> UnversionedSymbolName<'data> {
        let def = &self.symbol_definitions[symbol_id.as_usize()];
        UnversionedSymbolName::new(def.name)
    }
}

fn count_symbols(
    prelude: &Prelude,
    objects: &[ParsedInputObject],
    linker_scripts: &[ProcessedLinkerScript],
) -> usize {
    let in_objects = objects.iter().map(|o| o.num_symbols()).sum::<usize>();

    let in_linker_scripts = linker_scripts
        .iter()
        .map(|l| l.num_symbols())
        .sum::<usize>();

    prelude.symbol_definitions.len() + in_objects + in_linker_scripts
}

impl<'data> ProcessedLinkerScript<'data> {
    pub(crate) fn num_symbols(&self) -> usize {
        self.symbol_defs.len()
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
