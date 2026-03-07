//! COFF object file wrapper for PE linking.
//!
//! Provides a unified `CoffObjectFile` type that implements the `ObjectFile` trait,
//! abstracting over regular COFF and COFF bigobj files.

use crate::args::Args;
use crate::args::windows::PeArgs;
use crate::arch::Architecture;
use crate::bail;
use crate::error::Context as _;
use crate::error::Result;
use crate::input_data::InputBytes;
use crate::layout::DynamicSymbolDefinition;
use crate::layout::OutputRecordLayout;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::platform;
use crate::resolution::LoadedMetrics;
use crate::resolution::UnloadedSection;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::Visibility;
use object::LittleEndian;
use object::pe;
use object::read::coff::CoffHeader;
use object::read::coff::ImageSymbol;
use rayon::Scope;
use std::borrow::Cow;
use std::fmt::Display;

// ── PE Platform ─────────────────────────────────────────────────────────────

pub(crate) struct PePlatform;

impl<'data> platform::Platform<'data> for PePlatform {
    type Relaxation = NeverRelaxation;
    type File = CoffObjectFile<'data>;

    fn finish_link(
        _file_loader: &mut crate::input_data::FileLoader<'data>,
        args: &'data Args<PeArgs>,
        _plugin: &mut Option<crate::linker_plugins::LinkerPlugin<'data>>,
        mut symbol_db: SymbolDb<'data, CoffObjectFile<'data>>,
        mut per_symbol_flags: crate::value_flags::PerSymbolFlags,
        resolver: crate::resolution::Resolver<'data, CoffObjectFile<'data>>,
        mut output_sections: OutputSections<'data>,
        layout_rules_builder: crate::layout_rules::LayoutRulesBuilder<'data>,
        output_kind: crate::OutputKind,
    ) -> Result<Option<crate::layout::Layout<'data, CoffObjectFile<'data>>>> {
        let layout_rules = layout_rules_builder.build();
        let resolved = resolver.resolve_sections_and_canonicalise_undefined(
            &mut symbol_db,
            &mut per_symbol_flags,
            &mut output_sections,
            &layout_rules,
        )?;

        // PE does its own layout and writing — the ELF Layout type doesn't apply.
        crate::pe_writer::link(&symbol_db, &resolved, args, output_kind)?;

        Ok(None)
    }

    fn elf_header_arch_magic() -> u16 {
        unreachable!("PE does not use ELF headers")
    }

    fn get_dynamic_relocation_type(
        _relocation: linker_utils::elf::DynamicRelocationKind,
    ) -> u32 {
        unreachable!("PE does not use ELF dynamic relocations")
    }

    fn write_plt_entry(_plt_entry: &mut [u8], _got_address: u64, _plt_address: u64) -> Result {
        unreachable!("PE does not use PLT")
    }

    fn relocation_from_raw(_r_type: u32) -> Result<linker_utils::elf::RelocationKindInfo> {
        unreachable!("PE does not use ELF relocations")
    }

    fn rel_type_to_string(_r_type: u32) -> Cow<'static, str> {
        unreachable!("PE does not use ELF relocations")
    }

    fn local_symbols_in_debug_info() -> bool {
        false
    }

    fn tp_offset_start(
        _layout: &crate::layout::Layout<'data, Self::File>,
    ) -> u64 {
        0
    }

    fn get_property_class(_property_type: u32) -> Option<crate::elf::PropertyClass> {
        None
    }

    fn merge_eflags(_eflags: impl Iterator<Item = u32>) -> Result<u32> {
        Ok(0)
    }

    fn high_part_relocations() -> &'static [u32] {
        &[]
    }

    fn get_source_info(
        _object: &Self::File,
        _relocations: &<Self::File as platform::ObjectFile<'data>>::RelocationSections,
        _section: &<Self::File as platform::ObjectFile<'data>>::SectionHeader,
        _offset_in_section: u64,
    ) -> Result<platform::SourceInfo> {
        bail!("Source info not supported for PE/COFF")
    }

    fn new_relaxation(
        _relocation_kind: u32,
        _section_bytes: &[u8],
        _offset_in_section: u64,
        _flags: crate::value_flags::ValueFlags,
        _output_kind: crate::OutputKind,
        _section_flags: <Self::File as platform::ObjectFile<'data>>::SectionFlags,
        _non_zero_address: bool,
        _relax_deltas: Option<&linker_utils::relaxation::SectionRelaxDeltas>,
    ) -> Option<Self::Relaxation> {
        None
    }
}

/// Stub relaxation type for PE — no relaxations supported.
pub(crate) enum NeverRelaxation {}

impl platform::Relaxation for NeverRelaxation {
    fn apply(&self, _section_bytes: &mut [u8], _offset: &mut u64, _addend: &mut i64) {
        match *self {}
    }

    fn rel_info(&self) -> linker_utils::elf::RelocationKindInfo {
        match *self {}
    }

    fn debug_kind(&self) -> impl std::fmt::Debug {
        match *self {}
    }

    fn next_modifier(&self) -> linker_utils::relaxation::RelocationModifier {
        match *self {}
    }

    fn is_mandatory(&self) -> bool {
        match *self {}
    }
}

// ── Core COFF object file type ──────────────────────────────────────────────

/// A parsed COFF object file that implements the `ObjectFile` trait.
/// Handles both regular COFF and COFF bigobj formats uniformly.
#[derive(Debug)]
pub(crate) struct CoffObjectFile<'data> {
    data: &'data [u8],
    sections: &'data [pe::ImageSectionHeader],
    /// Pre-parsed symbols (leaked allocation to satisfy `'data` lifetime).
    symbols: &'data [CoffSymbol],
    /// Pre-resolved section names (leaked, parallel to `sections`).
    section_names: &'data [&'data [u8]],
    /// String table for resolving symbol names.
    strings: object::read::StringTable<'data>,
    machine: u16,
}

/// Pre-parsed COFF symbol entry.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffSymbol {
    name_data_offset: u32,
    section_number: i32,
    storage_class: u8,
    value: u32,
    number_of_aux_symbols: u8,
    has_name: bool,
}

/// COFF section characteristics flags.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CoffSectionFlags(u32);

/// COFF section content type.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CoffSectionType(u32);

/// Stub segment type for COFF.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CoffSegmentType;

impl platform::SegmentType for CoffSegmentType {}

/// Stub program segment def for COFF.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffProgramSegmentDef;

impl Display for CoffProgramSegmentDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CoffSegment")
    }
}

impl platform::ProgramSegmentDef for CoffProgramSegmentDef {
    fn is_writable(self) -> bool {
        false
    }
    fn is_executable(self) -> bool {
        false
    }
    fn always_keep(self) -> bool {
        false
    }
    fn is_loadable(self) -> bool {
        false
    }
    fn is_stack(self) -> bool {
        false
    }
    fn is_tls(self) -> bool {
        false
    }
    fn order_key(self) -> usize {
        0
    }
    fn should_include_section(
        self,
        _section_info: &crate::output_section_id::SectionOutputInfo,
        _section_id: OutputSectionId,
    ) -> bool {
        false
    }
}

/// COFF symbol name (no versioning).
#[derive(Debug)]
pub(crate) struct CoffRawSymbolName<'data> {
    name: &'data [u8],
}

/// Stub verneed table — COFF has no symbol versioning.
#[derive(Debug)]
pub(crate) struct NeverVerneed;

/// Stub dynamic tag values — COFF has no dynamic linking.
#[derive(Debug)]
pub(crate) enum NeverDynamicTagValues {}

// ── Parsing ─────────────────────────────────────────────────────────────────

impl<'data> CoffObjectFile<'data> {
    fn parse_impl(data: &'data [u8]) -> Result<Self> {
        let kind =
            object::FileKind::parse(data).context("Failed to identify COFF file kind")?;
        match kind {
            object::FileKind::Coff => Self::parse_regular(data),
            object::FileKind::CoffBig => Self::parse_big(data),
            _ => bail!("Not a COFF file"),
        }
    }

    fn parse_regular(data: &'data [u8]) -> Result<Self> {
        let mut offset = 0;
        let header = pe::ImageFileHeader::parse(data, &mut offset)
            .context("Failed to parse COFF header")?;
        let machine = header.machine.get(LittleEndian);
        let (section_table, sym_table) = header
            .sections(data, offset)
            .and_then(|s| header.symbols(data).map(|sym| (s, sym)))
            .context("Failed to parse COFF sections/symbols")?;
        let strings = sym_table.strings();

        let symbols = Self::collect_symbols(data, &sym_table)?;
        let sections = section_table.iter().as_slice();
        let section_names = Self::resolve_all_section_names(sections, &strings)?;

        Ok(CoffObjectFile {
            data,
            sections,
            symbols,
            section_names,
            strings,
            machine,
        })
    }

    fn parse_big(data: &'data [u8]) -> Result<Self> {
        let mut offset = 0;
        let header = pe::AnonObjectHeaderBigobj::parse(data, &mut offset)
            .context("Failed to parse COFF bigobj header")?;
        let machine = header.machine.get(LittleEndian);
        let (section_table, sym_table) = header
            .sections(data, offset)
            .and_then(|s| header.symbols(data).map(|sym| (s, sym)))
            .context("Failed to parse COFF bigobj sections/symbols")?;
        let strings = sym_table.strings();

        let symbols = Self::collect_symbols(data, &sym_table)?;
        let sections = section_table.iter().as_slice();
        let section_names = Self::resolve_all_section_names(sections, &strings)?;

        Ok(CoffObjectFile {
            data,
            sections,
            symbols,
            section_names,
            strings,
            machine,
        })
    }

    fn collect_symbols<Coff: CoffHeader>(
        data: &'data [u8],
        sym_table: &object::read::coff::SymbolTable<'data, &'data [u8], Coff>,
    ) -> Result<&'data [CoffSymbol]> {
        let mut symbols_vec = Vec::new();
        for (_, symbol) in sym_table.iter() {
            let raw_name = symbol.raw_name();
            let name_data_offset =
                (raw_name.as_ptr() as usize - data.as_ptr() as usize) as u32;
            let has_name = *raw_name != [0u8; 8];

            symbols_vec.push(CoffSymbol {
                name_data_offset,
                section_number: symbol.section_number() as i32,
                storage_class: symbol.storage_class(),
                value: symbol.value(),
                number_of_aux_symbols: symbol.number_of_aux_symbols(),
                has_name,
            });
            for _ in 0..symbol.number_of_aux_symbols() {
                symbols_vec.push(CoffSymbol {
                    name_data_offset: 0,
                    section_number: 0,
                    storage_class: pe::IMAGE_SYM_CLASS_NULL,
                    value: 0,
                    number_of_aux_symbols: 0,
                    has_name: false,
                });
            }
        }

        Ok(Box::leak(symbols_vec.into_boxed_slice()))
    }

    fn resolve_all_section_names(
        sections: &'data [pe::ImageSectionHeader],
        strings: &object::read::StringTable<'data>,
    ) -> Result<&'data [&'data [u8]]> {
        let names: Vec<&'data [u8]> = sections
            .iter()
            .map(|header| Self::resolve_section_name(header, strings))
            .collect::<Result<_>>()?;
        Ok(Box::leak(names.into_boxed_slice()))
    }

    fn resolve_section_name(
        header: &'data pe::ImageSectionHeader,
        strings: &object::read::StringTable<'data>,
    ) -> Result<&'data [u8]> {
        let name = &header.name;
        if name[0] == b'/' {
            let offset_str = &name[1..];
            let len = offset_str.iter().position(|&b| b == 0).unwrap_or(7);
            let offset_str = std::str::from_utf8(&offset_str[..len])
                .context("Invalid COFF section name string table reference")?;
            let offset: u32 = offset_str
                .trim()
                .parse()
                .context("Invalid COFF section name string table offset")?;
            strings
                .get(offset)
                .map_err(|()| crate::error!("COFF section name string table offset out of range"))
        } else {
            let len = name.iter().position(|&b| b == 0).unwrap_or(8);
            Ok(&name[..len])
        }
    }

    fn resolve_symbol_name(&self, sym: &CoffSymbol) -> Result<&'data [u8]> {
        let off = sym.name_data_offset as usize;
        let name = self
            .data
            .get(off..off + 8)
            .context("COFF symbol name offset out of range")?;
        if name[..4] == [0, 0, 0, 0] {
            let offset = u32::from_le_bytes(name[4..8].try_into().unwrap());
            self.strings
                .get(offset)
                .map_err(|()| crate::error!("Invalid COFF symbol string table offset"))
        } else {
            let len = name.iter().position(|&b| b == 0).unwrap_or(8);
            Ok(&name[..len])
        }
    }

    fn section_index_of(&self, header: &pe::ImageSectionHeader) -> usize {
        let ptr_offset = (header as *const _ as usize)
            .wrapping_sub(self.sections.as_ptr() as usize);
        ptr_offset / core::mem::size_of::<pe::ImageSectionHeader>()
    }
}

// ── Symbol trait impl ───────────────────────────────────────────────────────

impl platform::Symbol for CoffSymbol {
    fn as_common(&self) -> Option<platform::CommonSymbol> {
        if self.storage_class == pe::IMAGE_SYM_CLASS_EXTERNAL
            && self.section_number == 0
            && self.value != 0
        {
            let size = self.value as u64;
            let alignment = crate::alignment::Alignment::new(1).unwrap();
            let part_id = crate::output_section_id::BSS.part_id_with_alignment(alignment);
            Some(platform::CommonSymbol { size, part_id })
        } else {
            None
        }
    }

    fn is_undefined(&self) -> bool {
        self.section_number == 0
            && self.value == 0
            && self.storage_class == pe::IMAGE_SYM_CLASS_EXTERNAL
    }

    fn is_local(&self) -> bool {
        self.storage_class != pe::IMAGE_SYM_CLASS_EXTERNAL
            && self.storage_class != pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
    }

    fn is_absolute(&self) -> bool {
        self.section_number == pe::IMAGE_SYM_ABSOLUTE as i32
    }

    fn is_weak(&self) -> bool {
        self.storage_class == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
    }

    fn visibility(&self) -> Visibility {
        Visibility::Default
    }

    fn value(&self) -> u64 {
        self.value as u64
    }

    fn size(&self) -> u64 {
        if self.is_common() {
            self.value as u64
        } else {
            0
        }
    }

    fn section_index(&self) -> object::SectionIndex {
        if self.section_number > 0 {
            object::SectionIndex(self.section_number as usize)
        } else {
            object::SectionIndex(0)
        }
    }

    fn has_name(&self) -> bool {
        self.has_name
    }

    fn debug_string(&self) -> String {
        format!(
            "sect={} class={} val={}",
            self.section_number, self.storage_class, self.value
        )
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn is_interposable(&self) -> bool {
        false
    }

    fn is_func(&self) -> bool {
        false
    }

    fn is_ifunc(&self) -> bool {
        false
    }

    fn is_hidden(&self) -> bool {
        false
    }

    fn is_gnu_unique(&self) -> bool {
        false
    }
}

// ── Section trait impls ─────────────────────────────────────────────────────

impl<'data> platform::SectionHeader<'data, CoffObjectFile<'data>>
    for pe::ImageSectionHeader
{
    fn flags(&self) -> CoffSectionFlags {
        CoffSectionFlags(self.characteristics.get(LittleEndian))
    }

    fn attributes(&self) -> () {}

    fn section_type(&self) -> CoffSectionType {
        CoffSectionType(self.characteristics.get(LittleEndian))
    }
}

impl platform::SectionFlags for CoffSectionFlags {
    fn is_alloc(self) -> bool {
        self.0 & pe::IMAGE_SCN_MEM_DISCARDABLE == 0
    }

    fn is_writable(self) -> bool {
        self.0 & pe::IMAGE_SCN_MEM_WRITE != 0
    }

    fn is_executable(self) -> bool {
        self.0 & pe::IMAGE_SCN_MEM_EXECUTE != 0
    }

    fn is_tls(self) -> bool {
        false
    }

    fn is_merge_section(self) -> bool {
        false
    }

    fn is_strings(self) -> bool {
        false
    }

    fn should_retain(self) -> bool {
        false
    }

    fn should_exclude(&self) -> bool {
        self.0 & pe::IMAGE_SCN_LNK_REMOVE != 0
    }

    fn is_group(self) -> bool {
        self.0 & pe::IMAGE_SCN_LNK_COMDAT != 0
    }
}

impl platform::SectionType for CoffSectionType {
    fn is_null(self) -> bool {
        self.0 == 0
    }

    fn is_note(self) -> bool {
        false
    }

    fn is_prog_bits(self) -> bool {
        self.0 & pe::IMAGE_SCN_CNT_CODE != 0
            || self.0 & pe::IMAGE_SCN_CNT_INITIALIZED_DATA != 0
    }

    fn is_no_bits(self) -> bool {
        self.0 & pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0
    }
}

impl platform::SectionAttributes for () {
    fn merge(&mut self, _rhs: Self) {}

    fn apply(&self, _output_sections: &mut OutputSections, _section_id: OutputSectionId) {}
}

// ── RawSymbolName ───────────────────────────────────────────────────────────

impl<'data> platform::RawSymbolName<'data> for CoffRawSymbolName<'data> {
    fn parse(bytes: &'data [u8]) -> Self {
        CoffRawSymbolName { name: bytes }
    }

    fn name(&self) -> &'data [u8] {
        self.name
    }

    fn version_name(&self) -> Option<&'data [u8]> {
        None
    }

    fn is_default(&self) -> bool {
        true
    }
}

// ── VerneedTable ────────────────────────────────────────────────────────────

impl<'data> platform::VerneedTable<'data> for NeverVerneed {
    fn version_name(&self, _local_symbol_index: object::SymbolIndex) -> Option<&'data [u8]> {
        None
    }
}

// ── DynamicTagValues ────────────────────────────────────────────────────────

impl<'data> platform::DynamicTagValues<'data> for NeverDynamicTagValues {
    fn lib_name(&self, _input: &crate::input_data::InputRef<'data>) -> &'data [u8] {
        match *self {}
    }
}

// ── NonAddressableIndexes ───────────────────────────────────────────────────

impl platform::NonAddressableIndexes for () {
    fn new<'data, O: platform::ObjectFile<'data>>(_symbol_db: &SymbolDb<'data, O>) -> Self {}
}

// ── ObjectFile trait implementation ─────────────────────────────────────────

impl<'data> platform::ObjectFile<'data> for CoffObjectFile<'data> {
    type ArgsType = PeArgs;
    type Symbol = CoffSymbol;
    type SectionHeader = pe::ImageSectionHeader;
    type SectionIterator = core::slice::Iter<'data, pe::ImageSectionHeader>;
    type SectionFlags = CoffSectionFlags;
    type SectionType = CoffSectionType;
    type SegmentType = CoffSegmentType;
    type SectionAttributes = ();
    type DynamicTagValues = NeverDynamicTagValues;
    type DynamicEntry = ();
    type RelocationList = &'data [pe::ImageRelocation];
    type RelocationSections = ();
    type VersionNames = ();
    type RawSymbolName = CoffRawSymbolName<'data>;
    type VerneedTable = NeverVerneed;
    type FileLayoutState = ();
    type LayoutProperties = ();
    type SymbolVersionIndex = ();
    type DynamicLayoutState = ();
    type DynamicLayout = ();
    type NonAddressableCounts = ();
    type NonAddressableIndexes = ();
    type EpilogueLayout = ();
    type GroupLayoutExt = ();
    type CommonGroupStateExt = ();
    type LayoutResourcesExt = ();
    type ProgramSegmentDef = CoffProgramSegmentDef;

    // ── Parsing ─────────────────────────────────────────────────────────

    fn parse_bytes(input: &'data [u8], _is_dynamic: bool) -> Result<Self> {
        Self::parse_impl(input)
    }

    fn parse(input: &InputBytes<'data>, args: &Args<PeArgs>) -> Result<Self> {
        let file = Self::parse_impl(input.data)?;

        let file_arch = Architecture::try_from(file.machine)?;
        if file_arch != args.arch {
            bail!(
                "`{input}` has incompatible architecture: {file_arch}, expecting {}",
                args.arch,
            );
        }

        Ok(file)
    }

    fn is_dynamic(&self) -> bool {
        false
    }

    // ── Symbols ─────────────────────────────────────────────────────────

    fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    fn symbols(&self) -> &'data [CoffSymbol] {
        self.symbols
    }

    fn enumerate_symbols(
        &self,
    ) -> impl Iterator<Item = (object::SymbolIndex, &'data CoffSymbol)> {
        self.symbols
            .iter()
            .enumerate()
            .map(|(i, s)| (object::SymbolIndex(i), s))
    }

    fn symbols_iter(&self) -> impl Iterator<Item = &'data CoffSymbol> {
        self.symbols.iter()
    }

    fn symbol(&self, index: object::SymbolIndex) -> Result<&'data CoffSymbol> {
        self.symbols
            .get(index.0)
            .with_context(|| format!("Invalid COFF symbol index {}", index.0))
    }

    fn symbol_name(&self, symbol: &CoffSymbol) -> Result<&'data [u8]> {
        self.resolve_symbol_name(symbol)
    }

    fn symbol_section(
        &self,
        symbol: &CoffSymbol,
        _index: object::SymbolIndex,
    ) -> Result<Option<object::SectionIndex>> {
        if symbol.section_number > 0 {
            Ok(Some(object::SectionIndex(symbol.section_number as usize)))
        } else {
            Ok(None)
        }
    }

    fn symbol_versions(&self) -> &[()] {
        &[]
    }

    fn symbol_version_debug(&self, _symbol_index: object::SymbolIndex) -> Option<String> {
        None
    }

    fn get_version_names(&self) -> Result<()> {
        Ok(())
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &CoffSymbol,
        _local_index: usize,
        _version_names: &(),
    ) -> Result<CoffRawSymbolName<'data>> {
        let name = self.resolve_symbol_name(symbol)?;
        Ok(CoffRawSymbolName { name })
    }

    fn verneed_table(&self) -> Result<NeverVerneed> {
        Ok(NeverVerneed)
    }

    // ── Sections ────────────────────────────────────────────────────────

    fn num_sections(&self) -> usize {
        self.sections.len()
    }

    fn section_iter(&self) -> Self::SectionIterator {
        self.sections.iter()
    }

    fn enumerate_sections(
        &self,
    ) -> impl Iterator<Item = (object::SectionIndex, &'data pe::ImageSectionHeader)> {
        self.sections
            .iter()
            .enumerate()
            .map(|(i, s)| (object::SectionIndex(i + 1), s))
    }

    fn section(&self, index: object::SectionIndex) -> Result<&'data pe::ImageSectionHeader> {
        let idx = index
            .0
            .checked_sub(1)
            .with_context(|| format!("Invalid COFF section index {}", index.0))?;
        self.sections
            .get(idx)
            .with_context(|| format!("COFF section index {} out of range", index.0))
    }

    fn section_by_name(
        &self,
        name: &str,
    ) -> Option<(object::SectionIndex, &'data pe::ImageSectionHeader)> {
        for (i, section_name) in self.section_names.iter().enumerate() {
            if *section_name == name.as_bytes() {
                return Some((object::SectionIndex(i + 1), &self.sections[i]));
            }
        }
        None
    }

    fn section_name(
        &self,
        section_header: &pe::ImageSectionHeader,
    ) -> Result<&'data [u8]> {
        let index = self.section_index_of(section_header);
        self.section_names
            .get(index)
            .copied()
            .context("Section header not found in this file")
    }

    fn section_size(&self, header: &pe::ImageSectionHeader) -> Result<u64> {
        Ok(header.size_of_raw_data.get(LittleEndian) as u64)
    }

    fn section_alignment(&self, header: &pe::ImageSectionHeader) -> Result<u64> {
        let chars = header.characteristics.get(LittleEndian);
        let align_field = (chars & pe::IMAGE_SCN_ALIGN_MASK) >> 20;
        if align_field == 0 {
            Ok(1)
        } else {
            Ok(1u64 << (align_field - 1))
        }
    }

    fn raw_section_data(&self, section: &pe::ImageSectionHeader) -> Result<&'data [u8]> {
        let offset = section.pointer_to_raw_data.get(LittleEndian) as usize;
        let size = section.size_of_raw_data.get(LittleEndian) as usize;
        if size == 0 {
            return Ok(&[]);
        }
        self.data
            .get(offset..offset + size)
            .context("COFF section data out of range")
    }

    fn section_data(
        &self,
        section: &pe::ImageSectionHeader,
        _member: &bumpalo_herd::Member<'data>,
        _loaded_metrics: &LoadedMetrics,
    ) -> Result<&'data [u8]> {
        self.raw_section_data(section)
    }

    fn copy_section_data(&self, section: &pe::ImageSectionHeader, out: &mut [u8]) -> Result {
        let data = self.raw_section_data(section)?;
        out[..data.len()].copy_from_slice(data);
        Ok(())
    }

    fn section_data_cow(&self, section: &pe::ImageSectionHeader) -> Result<Cow<'data, [u8]>> {
        self.raw_section_data(section).map(Cow::Borrowed)
    }

    fn section_display_name(&self, index: object::SectionIndex) -> Cow<'data, str> {
        let idx = index.0.checked_sub(1).unwrap_or(0);
        if let Some(name) = self.section_names.get(idx) {
            String::from_utf8_lossy(name)
        } else {
            Cow::Owned(format!("section {}", index.0))
        }
    }

    // ── Relocations ─────────────────────────────────────────────────────

    fn relocations(
        &self,
        index: object::SectionIndex,
        _relocations: &(),
    ) -> Result<&'data [pe::ImageRelocation]> {
        let idx = index.0.checked_sub(1).unwrap_or(0);
        if let Some(section) = self.sections.get(idx) {
            let offset = section.pointer_to_relocations.get(LittleEndian) as usize;
            let count = section.number_of_relocations.get(LittleEndian) as usize;
            if count == 0 {
                return Ok(&[]);
            }
            let size = count * core::mem::size_of::<pe::ImageRelocation>();
            let reloc_data = self
                .data
                .get(offset..offset + size)
                .context("COFF relocation data out of range")?;
            Ok(object::pod::slice_from_all_bytes(reloc_data)
                .map_err(|()| crate::error!("Failed to parse COFF relocations"))?)
        } else {
            Ok(&[])
        }
    }

    fn parse_relocations(&self) -> Result<()> {
        Ok(())
    }

    // ── Dynamic linking stubs ───────────────────────────────────────────

    fn dynamic_tags(&self) -> Result<&'data [()]> {
        Ok(&[])
    }

    fn dynamic_tag_values(&self) -> Option<NeverDynamicTagValues> {
        None
    }

    fn activate_dynamic(&self, _state: &mut ()) {}

    fn dynamic_symbol_used(
        &self,
        _symbol_index: object::SymbolIndex,
        _state: &mut (),
    ) -> Result {
        Ok(())
    }

    fn finalise_sizes_dynamic(
        &self,
        _lib_name: &[u8],
        _state: &mut (),
        _mem_sizes: &mut OutputSectionPartMap<u64>,
    ) -> Result {
        Ok(())
    }

    fn apply_non_addressable_indexes_dynamic(
        &self,
        _indexes: &mut (),
        _counts: &mut (),
        _state: &mut (),
    ) -> Result {
        Ok(())
    }

    fn finalise_layout_dynamic(
        &self,
        _state: (),
        _memory_offsets: &mut OutputSectionPartMap<u64>,
        _section_layouts: &OutputSectionMap<OutputRecordLayout>,
    ) {}

    // ── Layout stubs ────────────────────────────────────────────────────

    fn new_epilogue_layout(
        _args: &Args<PeArgs>,
        _output_kind: crate::OutputKind,
        _dynamic_symbol_definitions: &mut [DynamicSymbolDefinition<'_>],
    ) {}

    fn apply_non_addressable_indexes_epilogue(_counts: &mut (), _state: &mut ()) {}

    fn apply_non_addressable_indexes<'groups>(
        _symbol_db: &SymbolDb<'data, Self>,
        _counts: &(),
        _mem_sizes_iter: impl Iterator<Item = &'groups mut OutputSectionPartMap<u64>>,
    ) {
    }

    fn finalise_sizes_epilogue(
        _state: &mut (),
        _mem_sizes: &mut OutputSectionPartMap<u64>,
        _dynamic_symbol_definitions: &[DynamicSymbolDefinition<'data>],
        _properties: &(),
        _symbol_db: &SymbolDb<'data, Self>,
    ) {
    }

    fn finalise_sizes_all(
        _mem_sizes: &mut OutputSectionPartMap<u64>,
        _symbol_db: &SymbolDb<'data, Self>,
    ) {
    }

    fn apply_late_size_adjustments_epilogue(
        _state: &mut (),
        _current_sizes: &OutputSectionPartMap<u64>,
        _extra_sizes: &mut OutputSectionPartMap<u64>,
        _dynamic_symbol_defs: &[DynamicSymbolDefinition],
    ) -> Result {
        Ok(())
    }

    fn finalise_layout_epilogue(
        _epilogue_state: &mut (),
        _memory_offsets: &mut OutputSectionPartMap<u64>,
        _symbol_db: &SymbolDb<'data, Self>,
        _common_state: &(),
        _dynsym_start_index: u32,
        _dynamic_symbol_defs: &[DynamicSymbolDefinition],
    ) -> Result {
        Ok(())
    }

    fn process_gnu_note_section(
        &self,
        _state: &mut (),
        _section_index: object::SectionIndex,
    ) -> Result {
        Ok(())
    }

    fn create_layout_properties<'states, 'files, P: platform::Platform<'data, File = Self>>(
        _args: &Args<PeArgs>,
        _objects: impl Iterator<Item = &'files Self>,
        _states: impl Iterator<Item = &'states ()> + Clone,
    ) -> Result<()>
    where
        'data: 'files,
        'data: 'states,
    {
        Ok(())
    }

    fn load_exception_frame_data<'scope, P: platform::Platform<'data, File = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _eh_frame_section_index: object::SectionIndex,
        _resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _scope: &Scope<'scope>,
    ) -> Result {
        Ok(())
    }

    fn non_empty_section_loaded<'scope, P: platform::Platform<'data, File = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _unloaded: UnloadedSection,
        _resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        _scope: &Scope<'scope>,
    ) -> Result {
        Ok(())
    }

    fn finalise_group_layout(_memory_offsets: &OutputSectionPartMap<u64>) {}

    fn finalise_find_required_sections(
        _groups: &[crate::layout::GroupState<'data, Self>],
    ) {
    }

    fn pre_finalise_sizes_prelude(
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _args: &Args<PeArgs>,
    ) {
    }

    fn finalise_object_sizes(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
    }

    fn finalise_object_layout(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut OutputSectionPartMap<u64>,
    ) {
    }

    fn compute_object_addresses(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut OutputSectionPartMap<u64>,
    ) {
    }

    fn frame_data_base_address(_memory_offsets: &OutputSectionPartMap<u64>) -> u64 {
        0
    }

    fn should_enforce_undefined(
        &self,
        _resources: &crate::layout::GraphResources<'data, '_, Self>,
    ) -> bool {
        false
    }

    fn layout_resources_ext(
        _groups: &[crate::grouping::Group<'data, Self>],
    ) -> () {
    }

    fn load_object_section_relocations<'scope, P: platform::Platform<'data, File = Self>>(
        _state: &crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _section: crate::layout::Section,
        _scope: &Scope<'scope>,
    ) -> Result {
        Ok(())
    }

    fn load_object_debug_relocations<'scope, P: platform::Platform<'data, File = Self>>(
        _state: &crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _section: crate::layout::Section,
        _scope: &Scope<'scope>,
    ) -> Result {
        Ok(())
    }

    fn create_dynamic_symbol_definition(
        _symbol_db: &SymbolDb<'data, Self>,
        _symbol_id: crate::symbol_db::SymbolId,
    ) -> Result<DynamicSymbolDefinition<'data>> {
        bail!("PE does not support dynamic symbol definitions")
    }

    fn validate_section(
        _section_info: &crate::output_section_id::SectionOutputInfo,
        _section_flags: CoffSectionFlags,
        _section_layout: &OutputRecordLayout,
        _merge_target: OutputSectionId,
        _output_sections: &OutputSections<'data>,
        _section_id: OutputSectionId,
    ) -> Result {
        Ok(())
    }

    fn default_section_type() -> CoffSectionType {
        CoffSectionType(0)
    }

    fn verify_resolution_allocation(
        _output_sections: &OutputSections,
        _output_order: &crate::output_section_id::OutputOrder,
        _output_kind: crate::OutputKind,
        _mem_sizes: &OutputSectionPartMap<u64>,
        _resolution: &crate::layout::Resolution,
    ) -> Result {
        Ok(())
    }

    fn update_segment_keep_list(
        _program_segments: &crate::program_segments::ProgramSegments<CoffProgramSegmentDef>,
        _keep_segments: &mut [bool],
        _args: &Args<PeArgs>,
    ) {
    }

    fn program_segment_defs() -> &'static [CoffProgramSegmentDef] {
        &[]
    }

    fn unconditional_segment_defs() -> &'static [CoffProgramSegmentDef] {
        &[]
    }

    fn apply_force_keep_sections(
        _keep_sections: &mut crate::output_section_map::OutputSectionMap<bool>,
        _args: &Args<PeArgs>,
    ) {
    }

    fn is_zero_sized_section_content(_section_id: crate::output_section_id::OutputSectionId) -> bool {
        false
    }

    fn create_linker_defined_symbols(
        symbols: &mut crate::parsing::InternalSymbolsBuilder<'data>,
        _output_kind: crate::output_kind::OutputKind,
    ) {
        // The undefined symbol must always be symbol 0.
        symbols
            .add_symbol(crate::parsing::InternalSymDefInfo::new(
                crate::parsing::SymbolPlacement::Undefined,
                b"",
            ))
            .hide();
    }
}
