use crate::OutputKind;
use crate::OutputSections;
use crate::args::Args;
use crate::args::DefsymValue;
use crate::args::Modifiers;
use crate::args::RelocationModel;
use crate::error::Context as _;
use crate::error::Result;
use crate::input_data::FileId;
use crate::input_data::InputBytes;
use crate::input_data::InputLinkerScript;
use crate::input_data::InputRef;
use crate::layout_rules::LayoutRulesBuilder;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::platform::ObjectFile;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use crate::timing_phase;
use crate::verbose_timing_phase;
use linker_utils::elf::SymbolType;
use linker_utils::elf::stt;

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
pub(crate) struct ParsedInputObject<'data, O: ObjectFile<'data>> {
    pub(crate) input: InputRef<'data>,
    pub(crate) object: O,
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
    /// If true, this symbol should have hidden visibility (from PROVIDE_HIDDEN).
    pub(crate) is_hidden: bool,
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

    /// Where secondary sections are merged into a primary section, this causes our symbol to point
    /// to the non-inclusive end of the last section merged into the specified primary.
    SectionGroupEnd(OutputSectionId),

    /// An undefined symbol supplied by the user, e.g. via `--undefined=symbol-name`.
    ForceUndefined,

    /// A symbol defined via --defsym with an absolute address.
    DefsymAbsolute(u64),

    /// A symbol defined via --defsym that references another symbol.
    /// Stores the name of the target symbol and an optional offset to add to its value.
    DefsymSymbol(&'data str, i64),

    /// Symbol will point to the start of the first loadable segment.
    LoadBaseAddress,
}

/// Result of parsing a defsym-style expression like "0x1000", "symbol", or "symbol+0x40".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParsedSymbolExpression<'a> {
    /// An absolute numeric value.
    Absolute(u64),
    /// A symbol reference with an optional offset.
    SymbolWithOffset(&'a str, i64),
}

impl<'a> ParsedSymbolExpression<'a> {
    pub(crate) fn to_placement(self) -> SymbolPlacement<'a> {
        match self {
            ParsedSymbolExpression::Absolute(value) => SymbolPlacement::DefsymAbsolute(value),
            ParsedSymbolExpression::SymbolWithOffset(sym, offset) => {
                SymbolPlacement::DefsymSymbol(sym, offset)
            }
        }
    }
}

pub fn parse_symbol_expression(s: &str) -> ParsedSymbolExpression<'_> {
    let mut symbol = None;
    let mut offset: i64 = 0;
    let mut token_start = 0;
    let mut current_sign: i64 = 1;

    // Handle leading sign
    if s.starts_with('-') {
        current_sign = -1;
        token_start = 1;
    } else if s.starts_with('+') {
        token_start = 1;
    }

    for (i, ch) in s.bytes().enumerate().skip(token_start) {
        if ch == b'+' || ch == b'-' {
            let token = s[token_start..i].trim();
            if let Ok(val) = parse_number(token) {
                offset = offset.wrapping_add(current_sign * val as i64);
            } else if symbol.is_none() && !token.is_empty() {
                symbol = Some(token);
            }
            current_sign = if ch == b'+' { 1 } else { -1 };
            token_start = i + 1;
        }
    }

    // Process the last token
    let token = s[token_start..].trim();
    if let Ok(val) = parse_number(token) {
        offset = offset.wrapping_add(current_sign * val as i64);
    } else if symbol.is_none() && !token.is_empty() {
        symbol = Some(token);
    }

    match symbol {
        Some(sym) => ParsedSymbolExpression::SymbolWithOffset(sym, offset),
        None => ParsedSymbolExpression::Absolute(offset as u64),
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

impl<'data> InternalSymDefInfo<'data> {
    pub(crate) fn notype(placement: SymbolPlacement<'data>, name: &'data [u8]) -> Self {
        Self {
            placement,
            name,
            elf_symbol_type: stt::NOTYPE,
            is_hidden: false,
        }
    }

    pub(crate) fn hidden(placement: SymbolPlacement<'data>, name: &'data [u8]) -> Self {
        Self {
            placement,
            name,
            elf_symbol_type: stt::NOTYPE,
            is_hidden: true,
        }
    }
}

impl<'data, O: ObjectFile<'data>> ParsedInputObject<'data, O> {
    pub(crate) fn new(input: &InputBytes<'data>, args: &Args) -> Result<Box<Self>> {
        verbose_timing_phase!("Parse file");

        let object = O::parse(input, args)
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

            if let Some(name) = def.group_end_symbol_name {
                symbol_definitions.push(InternalSymDefInfo::notype(
                    SymbolPlacement::SectionGroupEnd(section_id),
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
            is_hidden: false,
        });

        symbol_definitions.extend(args.undefined.iter().map(|name| {
            InternalSymDefInfo::notype(SymbolPlacement::ForceUndefined, name.as_bytes())
        }));

        // Add symbols defined via --defsym
        symbol_definitions.extend(args.defsym.iter().map(|(name, value)| {
            let placement = match value {
                DefsymValue::Value(addr) => SymbolPlacement::DefsymAbsolute(*addr),
                DefsymValue::SymbolWithOffset(target, offset) => {
                    SymbolPlacement::DefsymSymbol(target.as_str(), *offset)
                }
            };
            InternalSymDefInfo::notype(placement, name.as_bytes())
        }));

        symbol_definitions.push(InternalSymDefInfo::notype(
            SymbolPlacement::LoadBaseAddress,
            b"__executable_start",
        ));

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

impl<'data, O: ObjectFile<'data>> std::fmt::Display for ParsedInputObject<'data, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl std::fmt::Display for ProcessedLinkerScript<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}
