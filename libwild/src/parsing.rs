use crate::OutputKind;
use crate::OutputSections;
use crate::args::Modifiers;
use crate::error::Context as _;
use crate::error::Result;
use crate::input_data::FileId;
use crate::input_data::InputBytes;
use crate::input_data::InputLinkerScript;
use crate::input_data::InputRef;
use crate::layout_rules::LayoutRulesBuilder;
use crate::linker_script::Expression;
use crate::output_section_id::OutputSectionId;
use crate::platform::Args;
use crate::platform::ObjectFile;
use crate::platform::Platform;
use crate::platform::Symbol;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use crate::timing_phase;
use crate::verbose_timing_phase;

pub(crate) fn process_linker_scripts<'data, P: Platform>(
    linker_scripts_in: &[InputLinkerScript<'data>],
    output_sections: &mut OutputSections<'data, P>,
    layout_rules_builder: &mut LayoutRulesBuilder<'data>,
) -> Result<Vec<ProcessedLinkerScript<'data, P>>> {
    timing_phase!("Process linker scripts");

    linker_scripts_in
        .iter()
        .map(|script| layout_rules_builder.process_linker_script(script, output_sections))
        .collect::<Result<Vec<ProcessedLinkerScript<P>>>>()
}

#[derive(Debug)]
pub(crate) struct Prelude<'data, P: Platform> {
    pub(crate) symbol_definitions: indexmap::IndexMap<&'data [u8], InternalSymDefInfo<'data, P>>,
}

#[derive(Debug)]
pub(crate) struct ParsedInputObject<'data, P: Platform> {
    pub(crate) input: InputRef<'data>,
    pub(crate) object: P::File<'data>,
    pub(crate) modifiers: Modifiers,
}

#[derive(Debug)]
pub(crate) struct ProcessedLinkerScript<'data, P: Platform> {
    pub(crate) input: InputRef<'data>,
    pub(crate) symbol_defs: indexmap::IndexMap<&'data [u8], InternalSymDefInfo<'data, P>>,
    pub(crate) assertions: Vec<crate::linker_script::AssertCommand<'data>>,
    /// Raw bytes of the linker script file. Used to compute line numbers from
    /// `AssertCommand::remainder` when reporting errors.
    pub(crate) file_bytes: &'data [u8],
    pub(crate) memory_regions: Vec<crate::linker_script::MemoryRegion<'data>>,
    pub(crate) program_headers: Vec<crate::linker_script::Phdr<'data>>,
}

#[derive(Debug)]
pub(crate) struct SyntheticSymbols {
    pub(crate) file_id: FileId,
    pub(crate) symbol_id_range: SymbolIdRange,
}

#[derive(Clone, derive_more::Debug)]
pub(crate) struct InternalSymDefInfo<'data, P: Platform> {
    pub(crate) symbol: P::SymtabEntry,
    pub(crate) placement: SymbolPlacement<'data>,
    #[debug("{:?}", String::from_utf8_lossy(name))]
    pub(crate) name: &'data [u8],
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum SymbolPlacement<'data> {
    /// Symbol 0 - the undefined symbol.
    Undefined,

    /// Defines a symbol that points to the start of a section.
    SectionStart(OutputSectionId),

    /// Defines a symbol that points at the non-inclusive end of the section. i.e. 1 byte past the
    /// last byte of the section.
    SectionEnd(OutputSectionId),

    /// Where secondary sections are merged into a primary section, this causes our symbol to point
    /// to the non-inclusive end of the last section merged into the specified primary.
    SectionGroupEnd(OutputSectionId),

    /// An undefined symbol supplied by the user, e.g. via `--undefined=symbol-name`.
    ForceUndefined,

    /// A symbol that redirects to some other symbol.
    Redirect(Redirect<'data>),

    /// Symbol will point to the start of the first loadable segment.
    LoadBaseAddress,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum SymbolLoc<'data> {
    SectionStart(OutputSectionId),
    SectionEnd(OutputSectionId),
    FirstSection,
    Expression(Expression<'data>, Option<OutputSectionId>),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Redirect<'data> {
    pub(crate) kind: RedirectKind,
    pub(crate) expression: Expression<'data>,
    pub(crate) loc: SymbolLoc<'data>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedirectKind {
    DefSym,
    Script,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SegmentName {
    Text,
    Rodata,
    Data,
    Bss,
    /// Any segment name not in the known set. Wild has no `-T` override for
    /// these, so they always resolve to the default value.
    Other,
}

impl SegmentName {
    pub(crate) fn from_bytes(name: &[u8]) -> Self {
        match name {
            b"text" => Self::Text,
            b"rodata" => Self::Rodata,
            b"data" => Self::Data,
            b"bss" => Self::Bss,
            _ => Self::Other,
        }
    }
}

/// Parse a number. Interprets 0x prefix as hex, otherwise as decimal.
pub(crate) fn parse_number(s: &str) -> Result<u64, ()> {
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        s.parse::<u64>().map_err(|_| ())
    }
}

impl<'data, P: Platform> InternalSymDefInfo<'data, P> {
    pub(crate) fn new(placement: SymbolPlacement<'data>, name: &'data [u8]) -> Self {
        Self {
            placement,
            name,
            symbol: P::default_symtab_entry(),
        }
    }

    pub(crate) fn with_hidden(self, hidden: bool) -> Self {
        Self {
            symbol: self.symbol.with_hidden(hidden),
            ..self
        }
    }

    pub(crate) fn hide(&mut self) -> &mut Self {
        self.symbol = self.symbol.with_hidden(true);
        self
    }

    pub(crate) fn set_hidden(&mut self, hidden: bool) -> &mut Self {
        self.symbol = self.symbol.with_hidden(hidden);
        self
    }
}

impl<'data, P: Platform> ParsedInputObject<'data, P> {
    pub(crate) fn new(input: &InputBytes<'data>, args: &P::Args) -> Result<Box<Self>> {
        verbose_timing_phase!("Parse file");

        let object = P::File::parse(input, args)
            .with_context(|| format!("Failed to parse object file `{input}`"))?;

        Ok(Box::new(Self {
            input: input.input,
            object,
            modifiers: input.modifiers,
        }))
    }

    pub(crate) fn is_dynamic(&self) -> bool {
        self.object.is_dynamic()
    }

    pub(crate) fn num_symbols(&self) -> usize {
        self.object.num_symbols()
    }
}

impl<'data, P: Platform> Prelude<'data, P> {
    pub(crate) fn new(args: &'data P::Args, output_kind: OutputKind) -> Result<Self> {
        verbose_timing_phase!("Construct prelude");

        let mut symbols = InternalSymbolsBuilder::default();

        P::create_linker_defined_symbols(&mut symbols, output_kind, args);

        args.force_undefined_symbol_names().iter().for_each(|name| {
            symbols.add_symbol(InternalSymDefInfo::new(
                SymbolPlacement::ForceUndefined,
                name.as_bytes(),
            ));
        });

        // Add symbols defined via the command line.
        args.defsym()
            .iter()
            .try_for_each(|(name, value)| -> Result<()> {
                let mut value = winnow::BStr::new(value);
                let expr = crate::linker_script::parse_expression(&mut value)
                    .with_context(|| format!("Failed to parse --defsym {name}={value}"))?;

                let placement = SymbolPlacement::Redirect(Redirect {
                    kind: RedirectKind::DefSym,
                    expression: expr,
                    loc: SymbolLoc::None,
                });
                symbols.add_symbol(InternalSymDefInfo::new(placement, name.as_bytes()));
                Ok(())
            })?;

        Ok(Self {
            symbol_definitions: symbols.symbol_definitions,
        })
    }

    pub(crate) fn symbol_name(&self, symbol_id: SymbolId) -> UnversionedSymbolName<'data> {
        let def = &self.symbol_definitions[symbol_id.as_usize()];
        UnversionedSymbolName::new(def.name)
    }
}

#[derive(Default)]
pub(crate) struct InternalSymbolsBuilder<'data, P: Platform> {
    symbol_definitions: indexmap::IndexMap<&'data [u8], InternalSymDefInfo<'data, P>>,
}

impl<'data, P: Platform> InternalSymbolsBuilder<'data, P> {
    pub(crate) fn add_symbol(
        &mut self,
        def: InternalSymDefInfo<'data, P>,
    ) -> &mut InternalSymDefInfo<'data, P> {
        let index = self.symbol_definitions.len();
        self.symbol_definitions.insert(def.name, def);
        &mut self.symbol_definitions[index]
    }

    pub(crate) fn section_start(
        &mut self,
        section_id: OutputSectionId,
        name: &'static str,
    ) -> &mut InternalSymDefInfo<'data, P> {
        self.add_symbol(InternalSymDefInfo::new(
            SymbolPlacement::SectionStart(section_id),
            name.as_bytes(),
        ))
    }

    pub(crate) fn section_end(
        &mut self,
        section_id: OutputSectionId,
        name: &'static str,
    ) -> &mut InternalSymDefInfo<'data, P> {
        self.add_symbol(InternalSymDefInfo::new(
            SymbolPlacement::SectionEnd(section_id),
            name.as_bytes(),
        ))
    }

    pub(crate) fn section_group_end(
        &mut self,
        section_id: OutputSectionId,
        name: &'static str,
    ) -> &mut InternalSymDefInfo<'data, P> {
        self.add_symbol(InternalSymDefInfo::new(
            SymbolPlacement::SectionGroupEnd(section_id),
            name.as_bytes(),
        ))
    }
}

impl<'data, P: Platform> ProcessedLinkerScript<'data, P> {
    pub(crate) fn num_symbols(&self) -> usize {
        self.symbol_defs.len()
    }
}

impl<'data, P: Platform> std::fmt::Display for ParsedInputObject<'data, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl<'data, P: Platform> std::fmt::Display for ProcessedLinkerScript<'data, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl Redirect<'_> {
    pub(crate) fn missing_target(&self, target_name: &[u8]) -> crate::error::Error {
        crate::error!(
            "Symbol '{name}' referenced by {kind} does not exist",
            name = String::from_utf8_lossy(target_name),
            kind = self.kind.message_text(),
        )
    }

    pub(crate) fn missing_resolution(&self, target_name: &[u8]) -> crate::error::Error {
        crate::error!(
            "Symbol '{name}' referenced by {kind} has no resolution.",
            name = String::from_utf8_lossy(target_name),
            kind = self.kind.message_text(),
        )
    }
}

impl RedirectKind {
    fn message_text(self) -> &'static str {
        match self {
            RedirectKind::DefSym => "--defsym",
            RedirectKind::Script => "linker script",
        }
    }
}
