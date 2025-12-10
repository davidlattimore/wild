use crate::OutputKind;
use crate::OutputSections;
use crate::args::Args;
use crate::args::DefsymValue;
use crate::args::Modifiers;
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
use crate::symbol_db::SymbolIdRange;
use crate::timing_phase;
use crate::verbose_timing_phase;
use linker_utils::elf::SymbolType;
use linker_utils::elf::stt;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;

pub(crate) fn parse_input_files<'data>(
    inputs: &[InputBytes<'data>],
    args: &'data Args,
) -> Result<Vec<ParsedInputObject<'data>>> {
    timing_phase!("Parse input files");

    inputs
        .par_iter()
        .map(|f| ParsedInputObject::new(f, args))
        .collect::<Result<Vec<ParsedInputObject>>>()
}

pub(crate) fn process_linker_scripts<'data>(
    linker_scripts_in: &[InputLinkerScript<'data>],
    output_sections: &mut OutputSections<'data>,
    layout_rules_builder: &mut LayoutRulesBuilder<'data>,
) -> Result<Vec<ProcessedLinkerScript<'data>>> {
    timing_phase!("Process linker scripts");

    linker_scripts_in
        .iter()
        .map(|script| layout_rules_builder.process_linker_script(script, output_sections))
        .collect::<Result<Vec<ProcessedLinkerScript>>>()
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
pub(crate) struct SyntheticSymbols {
    pub(crate) file_id: FileId,
    pub(crate) symbol_id_range: SymbolIdRange,
}

#[derive(Clone, Copy, derive_more::Debug)]
pub(crate) struct InternalSymDefInfo<'data> {
    pub(crate) placement: SymbolPlacement<'data>,
    #[debug("{:?}", String::from_utf8_lossy(name))]
    pub(crate) name: &'data [u8],
    pub(crate) elf_symbol_type: SymbolType,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SymbolPlacement<'data> {
    /// Symbol 0 - the undefined symbol.
    Undefined,

    /// Defines a symbol that points to the start of a section.
    SectionStart(OutputSectionId),

    /// Defines a symbol that points at the non-inclusive end of the section. i.e. 1 byte past the
    /// last byte of the section.
    SectionEnd(OutputSectionId),

    /// An undefined symbol supplied by the user, e.g. via `--undefined=symbol-name`.
    ForceUndefined,

    /// A symbol defined via --defsym with an absolute address.
    DefsymAbsolute(u64),

    /// A symbol defined via --defsym that references another symbol.
    /// Stores the name of the target symbol.
    DefsymSymbol(&'data str),
}

impl<'data> InternalSymDefInfo<'data> {
    pub(crate) fn notype(placement: SymbolPlacement<'data>, name: &'data [u8]) -> Self {
        Self {
            placement,
            name,
            elf_symbol_type: stt::NOTYPE,
        }
    }
}

impl<'data> ParsedInputObject<'data> {
    fn new(input: &InputBytes<'data>, args: &Args) -> Result<Self> {
        verbose_timing_phase!("Parse file");
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

    pub(crate) fn num_symbols(&self) -> usize {
        self.object.symbols.len()
    }
}

impl<'data> Prelude<'data> {
    pub(crate) fn new(args: &'data Args, output_kind: OutputKind) -> Self {
        verbose_timing_phase!("Construct prelude");

        // The undefined symbol must always be symbol 0.
        let mut symbol_definitions =
            vec![InternalSymDefInfo::notype(SymbolPlacement::Undefined, &[])];

        for section_id in output_section_id::built_in_section_ids() {
            // If we're producing non-relocatable, static executable, then don't define any symbols
            // for the .dynamic section.
            if section_id == output_section_id::DYNAMIC
                && output_kind == OutputKind::StaticExecutable(RelocationModel::NonRelocatable)
            {
                continue;
            }

            let def = section_id.built_in_details();
            // .rela.plt start/stop symbols are only emitted for non-relocatable executables.
            // Emitting them for relocatable binaries causes glibc to try to call the resolver
            // functions without taking into account that the binary has been relocated.
            if output_kind != OutputKind::StaticExecutable(RelocationModel::NonRelocatable)
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
        }

        // We define _TLS_MODULE_BASE_ either at the start or end of the TLS segment, depending on
        // whether we're building a shared object or an executable. This symbol is used for TLSDESC.
        // See https://www.fsfla.org/~lxoliva/writeups/TLS/RFC-TLSDESC-x86.txt for more details.
        symbol_definitions.push(InternalSymDefInfo {
            placement: if output_kind == OutputKind::SharedObject {
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

        // Add symbols defined via --defsym
        symbol_definitions.extend(args.defsym.iter().map(|(name, value)| {
            let placement = match value {
                DefsymValue::Value(addr) => SymbolPlacement::DefsymAbsolute(*addr),
                DefsymValue::Symbol(target) => SymbolPlacement::DefsymSymbol(target.as_str()),
            };
            InternalSymDefInfo::notype(placement, name.as_bytes())
        }));

        Self { symbol_definitions }
    }

    pub(crate) fn symbol_name(&self, symbol_id: SymbolId) -> UnversionedSymbolName<'data> {
        let def = &self.symbol_definitions[symbol_id.as_usize()];
        UnversionedSymbolName::new(def.name)
    }
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
