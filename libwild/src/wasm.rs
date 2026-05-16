// TODO
#![allow(unused_variables)]
#![allow(unused)]

use crate::alignment::Alignment;
use crate::args::wasm::WasmArgs;
use crate::ensure;
use crate::error::Context as _;
use crate::error::Result;
use crate::layout_rules::SectionKind;
use crate::output_section_id::SectionName;
use crate::platform;
use linker_utils::utils::u32_from_slice;
use std::ops::Range;
use wasmparser::KnownCustom;
use wasmparser::Linking;
use wasmparser::Parser;
use wasmparser::Payload;
use wasmparser::RelocationEntry;
use wasmparser::SegmentFlags;
use wasmparser::SymbolFlags;
use wasmparser::SymbolInfo;

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct Wasm;

/// Magic bytes at the start of every Wasm module.
pub(crate) const WASM_MAGIC: [u8; 4] = [0x00, b'a', b's', b'm'];

/// Supported Wasm binary format version.
pub(crate) const WASM_VERSION: u32 = 1;

pub(crate) mod section_id {
    pub(crate) const TYPE: u8 = 1;
    pub(crate) const IMPORT: u8 = 2;
    pub(crate) const FUNCTION: u8 = 3;
    pub(crate) const TABLE: u8 = 4;
    pub(crate) const MEMORY: u8 = 5;
    pub(crate) const GLOBAL: u8 = 6;
    pub(crate) const EXPORT: u8 = 7;
    pub(crate) const START: u8 = 8;
    pub(crate) const ELEMENT: u8 = 9;
    pub(crate) const CODE: u8 = 10;
    pub(crate) const DATA: u8 = 11;
    pub(crate) const DATA_COUNT: u8 = 12;
    pub(crate) const MAX: u8 = DATA_COUNT;
}

/// Size of a `[Option<u32>; _]` lookup that can be indexed by any standard section id.
pub(crate) const STANDARD_SECTION_LOOKUP_LEN: usize = section_id::MAX as usize + 1;

/// `R_WASM_TYPE_INDEX_LEB` from the Wasm Tool Conventions. The only reloc whose `index` field
/// refers to a type index rather than a symbol index.
pub(crate) const R_WASM_TYPE_INDEX_LEB: u8 = 6;

/// The custom-section name used for the linker metadata.
pub(crate) const LINKING_SECTION_NAME: &str = "linking";

/// The prefix of every `reloc.*` custom section.
pub(crate) const RELOC_SECTION_PREFIX: &str = "reloc.";

/// The custom-section name used for the WebAssembly target features.
pub(crate) const TARGET_FEATURES_SECTION_NAME: &str = "target_features";

#[derive(derive_more::Debug)]
pub(crate) struct File<'data> {
    #[debug(skip)]
    pub(crate) data: &'data [u8],

    pub(crate) version: u32,

    #[debug(skip)]
    pub(crate) sections: Vec<SectionHeader>,

    /// For each standard Wasm section id, the index into `sections`, if present.
    #[debug(skip)]
    pub(crate) standard_section_index: [Option<u32>; STANDARD_SECTION_LOOKUP_LEN],

    #[debug(skip)]
    pub(crate) symbols: Vec<WasmSymbol>,

    #[debug(skip)]
    pub(crate) segments: Vec<WasmSegmentInfo<'data>>,

    #[debug(skip)]
    pub(crate) reloc_sections: Vec<WasmRelocSection>,

    pub(crate) linking_version: Option<u32>,

    /// Raw payload of the `target_features` custom section, if present.
    #[debug(skip)]
    pub(crate) target_features_raw: Option<&'data [u8]>,
}

/// A single section of a Wasm module.
#[derive(Debug, Default, Clone)]
pub(crate) struct SectionHeader {
    /// The wasm section id.
    pub(crate) id: u8,

    /// Byte range of the section (id + size + payload) within the original Wasm binary.
    pub(crate) payload_range: Range<u32>,

    /// For custom sections, the byte range within the input data of the section's name string.
    /// `None` for standard sections, whose canonical name is derived from `id`.
    pub(crate) name_range: Option<Range<u32>>,
}

impl SectionHeader {
    pub(crate) fn is_custom(&self) -> bool {
        self.id == 0
    }

    pub(crate) fn payload_range_usize(&self) -> Range<usize> {
        self.payload_range.start as usize..self.payload_range.end as usize
    }
}

fn standard_section_name(id: u8) -> Option<&'static [u8]> {
    Some(match id {
        section_id::TYPE => b"type",
        section_id::IMPORT => b"import",
        section_id::FUNCTION => b"function",
        section_id::TABLE => b"table",
        section_id::MEMORY => b"memory",
        section_id::GLOBAL => b"global",
        section_id::EXPORT => b"export",
        section_id::START => b"start",
        section_id::ELEMENT => b"element",
        section_id::CODE => b"code",
        section_id::DATA => b"data",
        section_id::DATA_COUNT => b"data_count",
        _ => return None,
    })
}

// NOTE: We deliberately don't reuse `wasmparser::SymbolInfo<'data>` here. It carries `&'data str`
// names, but `Platform::SymtabEntry` requires `Symbol: 'static + Copy`, so a wrapper around
// `SymbolInfo` would have to drop the borrowed strings anyway.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WasmSymbol {
    pub(crate) kind: WasmSymbolKind,
    pub(crate) flags: u32,
    pub(crate) index: u32,
    pub(crate) offset: u32,
    pub(crate) size: u32,
    pub(crate) name_start: u32,
    pub(crate) name_len: u32,
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub(crate) enum WasmSymbolKind {
    #[default]
    Null, // Doesn't correspond to any real wasm symbol kind.
    Func,
    Data,
    Global,
    Section,
    Event,
    Table,
}

impl WasmSymbol {
    fn raw_flags(&self) -> SymbolFlags {
        SymbolFlags::from_bits_truncate(self.flags)
    }

    pub(crate) fn is_undefined(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::UNDEFINED)
    }

    pub(crate) fn is_weak(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::BINDING_WEAK)
    }

    pub(crate) fn is_local(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::BINDING_LOCAL)
    }

    pub(crate) fn is_hidden(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::VISIBILITY_HIDDEN)
    }

    pub(crate) fn is_exported(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::EXPORTED)
    }

    fn has_name(&self) -> bool {
        self.name_len != 0
    }

    fn name_range(&self) -> Range<usize> {
        let s = self.name_start as usize;
        s..s + self.name_len as usize
    }
}

/// Per-data-segment metadata from the `linking` section.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WasmSegmentInfo<'data> {
    pub(crate) name: &'data str,
    pub(crate) alignment: Alignment,
    pub(crate) flags: SegmentFlags,
}

/// All relocations read from a single `reloc.*` custom section.
#[derive(Debug, Clone)]
pub(crate) struct WasmRelocSection {
    /// Index (into [`File::sections`]) of the section that the relocations apply to.
    pub(crate) target_section_index: u32,
    pub(crate) entries: Vec<WasmRelocation>,
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct WasmRelocation {
    /// Wasm relocation type code.
    pub(crate) ty: u8,
    /// Byte offset within the target section's payload.
    pub(crate) offset: u32,
    /// Symbol or type index.
    pub(crate) index: u32,
    pub(crate) addend: i64,
}

impl WasmRelocation {
    fn from_entry(entry: RelocationEntry) -> Self {
        Self {
            ty: entry.ty as u8,
            offset: entry.offset,
            index: entry.index,
            addend: entry.addend,
        }
    }

    /// Whether `index` refers to a symbol rather than a type index.
    #[expect(dead_code)] // Will be used once relocation application lands.
    fn refers_to_symbol(&self) -> bool {
        self.ty != R_WASM_TYPE_INDEX_LEB
    }
}

impl<'data> platform::ObjectFile<'data> for File<'data> {
    type Platform = Wasm;

    fn parse_bytes(input: &'data [u8], _is_dynamic: bool) -> crate::error::Result<Self> {
        parse_wasm_module(input).context("failed to parse Wasm object file")
    }

    fn parse(
        input: &crate::input_data::InputBytes<'data>,
        args: &<Self::Platform as platform::Platform>::Args,
    ) -> crate::error::Result<Self> {
        Self::parse_bytes(input.data, false)
    }

    fn is_dynamic(&self) -> bool {
        // Wasm has no notion of "dynamic objects" in the ELF sense yet.
        false
    }

    fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    fn symbols_iter(&self) -> impl Iterator<Item = &WasmSymbol> {
        self.symbols.iter()
    }

    fn symbol(
        &self,
        index: object::SymbolIndex,
    ) -> crate::error::Result<&<Self::Platform as platform::Platform>::SymtabEntry> {
        self.symbols
            .get(index.0)
            .ok_or_else(|| crate::error!("wasm symbol index {} out of range", index.0))
    }

    fn section_size(
        &self,
        header: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<u64> {
        Ok(header.payload_range.len() as u64)
    }

    fn symbol_name(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
    ) -> crate::error::Result<&'data [u8]> {
        if !symbol.has_name() {
            return Ok(&[]);
        }
        self.data
            .get(symbol.name_range())
            .ok_or_else(|| crate::error!("wasm symbol name range out of bounds"))
    }

    fn symbol_offset_in_section(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        _section_index: object::SectionIndex,
    ) -> crate::error::Result<u64> {
        Ok(match symbol.kind {
            WasmSymbolKind::Data => u64::from(symbol.offset),
            _ => 0,
        })
    }

    fn num_sections(&self) -> usize {
        self.sections.len()
    }

    fn section_iter<'a>(&'a self) -> <Self::Platform as platform::Platform>::SectionIterator<'a> {
        self.sections.iter()
    }

    fn enumerate_sections(
        &self,
    ) -> impl Iterator<
        Item = (
            object::SectionIndex,
            &<Self::Platform as platform::Platform>::SectionHeader,
        ),
    > {
        self.sections
            .iter()
            .enumerate()
            .map(|(i, section)| (object::SectionIndex(i), section))
    }

    fn section(
        &self,
        index: object::SectionIndex,
    ) -> crate::error::Result<&<Self::Platform as platform::Platform>::SectionHeader> {
        self.sections
            .get(index.0)
            .ok_or_else(|| crate::error!("wasm section index {} out of range", index.0))
    }

    fn section_by_name(
        &self,
        name: &str,
    ) -> Option<(
        object::SectionIndex,
        &<Self::Platform as platform::Platform>::SectionHeader,
    )> {
        let needle = name.as_bytes();
        self.sections
            .iter()
            .enumerate()
            .find(|(_, header)| {
                if let Some(name_range) = &header.name_range {
                    self.data
                        .get(name_range.start as usize..name_range.end as usize)
                        == Some(needle)
                } else {
                    standard_section_name(header.id) == Some(needle)
                }
            })
            .map(|(i, header)| (object::SectionIndex(i), header))
    }

    fn symbol_section(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        _index: object::SymbolIndex,
    ) -> crate::error::Result<Option<object::SectionIndex>> {
        if symbol.is_undefined() {
            return Ok(None);
        }
        // Map each symbol kind to the wasm section that holds its definition.
        let std_id: u8 = match symbol.kind {
            WasmSymbolKind::Func => section_id::CODE,
            WasmSymbolKind::Data => section_id::DATA,
            WasmSymbolKind::Global => section_id::GLOBAL,
            WasmSymbolKind::Table => section_id::TABLE,
            WasmSymbolKind::Event | WasmSymbolKind::Null => return Ok(None),
            WasmSymbolKind::Section => {
                return Ok(self
                    .sections
                    .get(symbol.index as usize)
                    .map(|_| object::SectionIndex(symbol.index as usize)));
            }
        };
        Ok(self.standard_section_index[std_id as usize].map(|i| object::SectionIndex(i as usize)))
    }

    fn symbol_versions(&self) -> &[<Self::Platform as platform::Platform>::SymbolVersionIndex] {
        // Wasm doesn't have ELF-style symbol versioning.
        &[]
    }

    fn dynamic_symbol_used(
        &self,
        _symbol_index: object::SymbolIndex,
        _state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
    ) -> crate::error::Result {
        // Wasm has no dynamic objects yet.
        Ok(())
    }

    fn finalise_sizes_dynamic(
        &self,
        _lib_name: &[u8],
        _state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn apply_non_addressable_indexes_dynamic(
        &self,
        _indexes: &mut <Self::Platform as platform::Platform>::NonAddressableIndexes,
        _counts: &mut <Self::Platform as platform::Platform>::NonAddressableCounts,
        _state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn section_name(&self, index: object::SectionIndex) -> crate::error::Result<&'data [u8]> {
        let header = self
            .sections
            .get(index.0)
            .ok_or_else(|| crate::error!("wasm section index {} out of range", index.0))?;
        if let Some(name_range) = &header.name_range {
            Ok(&self.data[name_range.start as usize..name_range.end as usize])
        } else {
            standard_section_name(header.id)
                .ok_or_else(|| crate::error!("unknown wasm section id {}", header.id))
        }
    }

    fn raw_section_data(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<&'data [u8]> {
        Ok(&self.data[section.payload_range_usize()])
    }

    fn section_data(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
        _member: &bumpalo_herd::Member<'data>,
        _loaded_metrics: &crate::resolution::LoadedMetrics,
    ) -> crate::error::Result<&'data [u8]> {
        // Wasm sections are never compressed.
        self.raw_section_data(section)
    }

    fn copy_section_data(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
        out: &mut [u8],
    ) -> crate::error::Result {
        let bytes = self.raw_section_data(section)?;
        ensure!(
            out.len() == bytes.len(),
            "copy_section_data: output buffer size {} does not match section size {}",
            out.len(),
            bytes.len()
        );
        out.copy_from_slice(bytes);
        Ok(())
    }

    fn section_data_cow(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<std::borrow::Cow<'data, [u8]>> {
        Ok(std::borrow::Cow::Borrowed(self.raw_section_data(section)?))
    }

    fn section_alignment(
        &self,
        _section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<u64> {
        // Wasm sections themselves don't carry an alignment requirement.
        Ok(1)
    }

    fn relocations(
        &self,
        _index: object::SectionIndex,
        _relocations: &<Self::Platform as platform::Platform>::RelocationSections,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RelocationList<'data>> {
        // Relocation entries are parsed and stored on `File::reloc_sections` but not yet plumbed
        // through the layout pipeline.
        Ok(RelocationList {
            _phantom: std::marker::PhantomData,
        })
    }

    fn parse_relocations(
        &self,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RelocationSections> {
        Ok(())
    }

    fn symbol_version_debug(&self, symbol_index: object::SymbolIndex) -> Option<String> {
        // Wasm doesn't have ELF-style symbol versioning.
        None
    }

    fn section_display_name(&self, index: object::SectionIndex) -> std::borrow::Cow<'data, str> {
        self.section_name(index).map_or_else(
            |_| format!("<index {}>", index.0).into(),
            String::from_utf8_lossy,
        )
    }

    fn dynamic_tag_values(
        &self,
    ) -> Option<<Self::Platform as platform::Platform>::DynamicTagValues<'data>> {
        None
    }

    fn get_version_names(
        &self,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::VersionNames<'data>> {
        Ok(())
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        _local_index: usize,
        _version_names: &<Self::Platform as platform::Platform>::VersionNames<'data>,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RawSymbolName<'data>> {
        Ok(RawSymbolName {
            name: self.symbol_name(symbol)?,
        })
    }

    fn should_enforce_undefined(
        &self,
        _resources: &crate::layout::GraphResources<'data, '_, Self::Platform>,
    ) -> bool {
        // Wasm has no dynamic objects yet, so this is never reached in practice.
        false
    }

    fn verneed_table(
        &self,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::VerneedTable<'data>> {
        Ok(VerneedTable { _phantom: &[] })
    }

    fn process_gnu_note_section(
        &self,
        state: &mut <Self::Platform as platform::Platform>::ObjectLayoutStateExt<'data>,
        section_index: object::SectionIndex,
    ) -> crate::error::Result {
        // Wasm objects don't carry GNU property notes.
        Ok(())
    }

    fn dynamic_tags(
        &self,
    ) -> crate::error::Result<&'data [<Self::Platform as platform::Platform>::DynamicEntry]> {
        Ok(&[])
    }
}

impl platform::SectionHeader for SectionHeader {
    fn is_alloc(&self) -> bool {
        true
    }

    fn is_writable(&self) -> bool {
        // Wasm sections are not classified into RW vs RO at the section level.
        false
    }

    fn is_executable(&self) -> bool {
        // Code lives in the dedicated CODE section.
        false
    }

    fn is_tls(&self) -> bool {
        // Wasm has no TLS yet.
        false
    }

    fn is_merge_section(&self) -> bool {
        false
    }

    fn is_strings(&self) -> bool {
        false
    }

    fn should_retain(&self) -> bool {
        false
    }

    fn should_exclude(&self) -> bool {
        false
    }

    fn is_group(&self) -> bool {
        false
    }

    fn is_note(&self) -> bool {
        false
    }

    fn is_prog_bits(&self) -> bool {
        true
    }

    fn is_no_bits(&self) -> bool {
        false
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionType {}

impl platform::SectionType for SectionType {
    fn is_rela(&self) -> bool {
        false
    }

    fn is_rel(&self) -> bool {
        false
    }

    fn is_symtab(&self) -> bool {
        false
    }

    fn is_strtab(&self) -> bool {
        false
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionFlags {}

impl platform::SectionFlags for SectionFlags {
    fn is_alloc(self) -> bool {
        // All Wasm sections are conceptually loaded.
        true
    }
}

impl platform::Symbol for WasmSymbol {
    fn as_common(&self) -> Option<platform::CommonSymbol> {
        // Wasm has no COMMON symbols.
        None
    }

    fn is_undefined(&self) -> bool {
        WasmSymbol::is_undefined(self)
    }

    fn is_local(&self) -> bool {
        WasmSymbol::is_local(self)
    }

    fn is_absolute(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::ABSOLUTE)
    }

    fn is_weak(&self) -> bool {
        WasmSymbol::is_weak(self)
    }

    fn visibility(&self) -> crate::symbol_db::Visibility {
        if self.is_hidden() {
            crate::symbol_db::Visibility::Hidden
        } else {
            crate::symbol_db::Visibility::Default
        }
    }

    fn value(&self) -> u64 {
        match self.kind {
            WasmSymbolKind::Data => u64::from(self.offset),
            _ => u64::from(self.index),
        }
    }

    fn size(&self) -> u64 {
        u64::from(self.size)
    }

    fn has_name(&self) -> bool {
        WasmSymbol::has_name(self)
    }

    fn is_default_strippable(&self, _name: &[u8]) -> bool {
        // No equivalent of ELF's `.L` local symbol convention.
        false
    }

    fn debug_string(&self) -> String {
        format!("<Wasm symbol kind={:?} index={}>", self.kind, self.index)
    }

    fn is_tls(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::TLS)
    }

    fn is_interposable(&self) -> bool {
        // No dynamic linking yet; symbols can't be interposed at runtime.
        false
    }

    fn is_func(&self) -> bool {
        self.kind == WasmSymbolKind::Func
    }

    fn is_ifunc(&self) -> bool {
        false
    }

    fn is_hidden(&self) -> bool {
        WasmSymbol::is_hidden(self)
    }

    fn is_gnu_unique(&self) -> bool {
        false
    }

    fn with_hidden(mut self, hidden: bool) -> Self {
        let bit = SymbolFlags::VISIBILITY_HIDDEN.bits();
        if hidden {
            self.flags |= bit;
        } else {
            self.flags &= !bit;
        }
        self
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionAttributes {}

impl platform::SectionAttributes for SectionAttributes {
    type Platform = Wasm;

    fn merge(&mut self, _rhs: Self) {
        // No per-section attributes to merge yet.
    }

    fn apply(
        &self,
        _output_sections: &mut crate::output_section_id::OutputSections<Self::Platform>,
        _section_id: crate::output_section_id::OutputSectionId,
    ) {
        // No-op: Wasm output sections inherit their attributes from `SECTION_DEFINITIONS`.
    }

    fn is_null(&self) -> bool {
        false
    }

    fn is_alloc(&self) -> bool {
        true
    }

    fn is_executable(&self) -> bool {
        false
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn is_writable(&self) -> bool {
        false
    }

    fn is_no_bits(&self) -> bool {
        false
    }

    fn flags(&self) -> <Self::Platform as platform::Platform>::SectionFlags {
        SectionFlags::default()
    }

    fn ty(&self) -> <Self::Platform as platform::Platform>::SectionType {
        SectionType::default()
    }

    fn set_to_default_type(&mut self) {
        // Wasm has no per-section type to reset.
    }
}

#[derive(Debug)]
pub(crate) struct NonAddressableIndexes {}

impl platform::NonAddressableIndexes for NonAddressableIndexes {
    fn new<P: platform::Platform>(symbol_db: &crate::symbol_db::SymbolDb<P>) -> Self {
        Self {}
    }
}

/// Segment kinds used purely to drive output ordering. Wasm has no loadable program segments. These
/// variants are just a way to group the output sections in the canonical module layout.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub(crate) enum SegmentType {
    /// Holds the 8-byte module preamble.
    Header,
    /// Holds all standard Wasm sections in canonical order.
    Module,
    /// Anything not explicitly placed.
    #[default]
    Unused,
}

impl platform::SegmentType for SegmentType {}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProgramSegmentDef {
    pub(crate) segment_type: SegmentType,
}

impl std::fmt::Display for ProgramSegmentDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.segment_type)
    }
}

impl platform::ProgramSegmentDef for ProgramSegmentDef {
    type Platform = Wasm;

    fn is_writable(self) -> bool {
        false
    }

    fn is_executable(self) -> bool {
        false
    }

    fn always_keep(self) -> bool {
        true
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
        self.segment_type as usize
    }

    fn should_include_section(
        self,
        _section_info: &crate::output_section_id::SectionOutputInfo<Self::Platform>,
        section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        use crate::output_section_id as osid;

        let section_segment_type = match section_id {
            osid::FILE_HEADER => SegmentType::Header,
            osid::WASM_TYPE
            | osid::WASM_IMPORT
            | osid::WASM_FUNCTION
            | osid::WASM_TABLE
            | osid::WASM_MEMORY
            | osid::WASM_GLOBAL
            | osid::WASM_EXPORT
            | osid::WASM_START
            | osid::WASM_ELEMENT
            | osid::WASM_DATA_COUNT
            | osid::WASM_CODE
            | osid::WASM_DATA => SegmentType::Module,
            _ => SegmentType::Unused,
        };

        self.segment_type == section_segment_type
    }
}

pub(crate) struct BuiltInSectionDetails {
    pub(crate) kind: SectionKind<'static>,
    pub(crate) target_segment_type: Option<SegmentType>,
}

impl platform::BuiltInSectionDetails for BuiltInSectionDetails {}

const DEFAULT_DEFS: BuiltInSectionDetails = BuiltInSectionDetails {
    kind: SectionKind::Primary(SectionName(&[])),
    target_segment_type: None,
};

const SECTION_DEFINITIONS: [BuiltInSectionDetails;
    crate::output_section_id::NUM_BUILT_IN_SECTIONS] = {
    use crate::layout_rules::SectionKind;
    use crate::output_section_id as osid;
    use crate::output_section_id::SectionName;

    let mut defs: [BuiltInSectionDetails; osid::NUM_BUILT_IN_SECTIONS] =
        [DEFAULT_DEFS; osid::NUM_BUILT_IN_SECTIONS];

    // The module preamble.
    defs[osid::FILE_HEADER.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"WASM_HEADER")),
        target_segment_type: Some(SegmentType::Header),
    };

    // Standard Wasm sections.
    defs[osid::WASM_TYPE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"type")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_IMPORT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"import")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_FUNCTION.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"function")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_TABLE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"table")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_MEMORY.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"memory")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_GLOBAL.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"global")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_EXPORT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"export")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_START.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"start")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_ELEMENT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"element")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_DATA_COUNT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"data_count")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_CODE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"code")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_DATA.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"data")),
        target_segment_type: Some(SegmentType::Module),
    };

    defs
};

const PROGRAM_SEGMENT_DEFS: &[ProgramSegmentDef] = &[
    ProgramSegmentDef {
        segment_type: SegmentType::Header,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::Module,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::Unused,
    },
];

#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct DynamicTagValues<'data> {
    _phantom: std::marker::PhantomData<&'data [u8]>,
}

impl<'data> platform::DynamicTagValues<'data> for DynamicTagValues<'data> {
    fn lib_name(&self, input: &crate::input_data::InputRef<'data>) -> &'data [u8] {
        todo!()
    }
}

#[derive(Debug)]
pub(crate) struct RawSymbolName<'data> {
    pub(crate) name: &'data [u8],
}

impl<'data> platform::RawSymbolName<'data> for RawSymbolName<'data> {
    fn parse(bytes: &'data [u8]) -> Self {
        Self { name: bytes }
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

impl std::fmt::Display for RawSymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&String::from_utf8_lossy(self.name), f)
    }
}

pub(crate) struct VerneedTable<'data> {
    _phantom: &'data [u8],
}

impl<'data> platform::VerneedTable<'data> for VerneedTable<'data> {
    fn version_name(&self, local_symbol_index: object::SymbolIndex) -> Option<&'data [u8]> {
        None
    }
}

// TODO
#[derive(Debug, Default)]
pub(crate) struct RelocationList<'data> {
    _phantom: std::marker::PhantomData<&'data ()>,
}

impl<'data> platform::RelocationList<'data> for RelocationList<'data> {
    fn num_relocations(&self) -> usize {
        0
    }
}

impl platform::Platform for Wasm {
    type File<'data> = File<'data>;
    type SymtabEntry = WasmSymbol;
    type SectionHeader = SectionHeader;
    type SectionFlags = SectionFlags;
    type SectionAttributes = SectionAttributes;
    type SectionType = SectionType;
    type SegmentType = SegmentType;
    type ProgramSegmentDef = ProgramSegmentDef;
    type BuiltInSectionDetails = BuiltInSectionDetails;
    type RelocationSections = ();
    type DynamicEntry = ();
    type DynamicSymbolDefinitionExt = ();
    type RelocationInfo = u32;
    type NonAddressableIndexes = NonAddressableIndexes;
    type NonAddressableCounts = ();
    type EpilogueLayoutExt = ();
    type GroupLayoutExt = ();
    type CommonGroupStateExt = ();
    type ArchIdentifier = ();
    type Args = WasmArgs;
    type ResolutionExt = ();
    type SymtabShndxEntry = ();
    type SymbolVersionIndex = ();
    type LayoutExt = ();
    type SectionIterator<'a> = core::slice::Iter<'a, SectionHeader>;
    type DynamicTagValues<'data> = DynamicTagValues<'data>;
    type RelocationList<'data> = RelocationList<'data>;
    type DynamicLayoutStateExt<'data> = ();
    type DynamicLayoutExt<'data> = ();
    type LayoutResourcesExt<'data> = ();
    type PreludeLayoutStateExt = ();
    type PreludeLayoutExt = ();
    type ObjectLayoutStateExt<'data> = ();
    type RawSymbolName<'data> = RawSymbolName<'data>;
    type VersionNames<'data> = ();
    type VerneedTable<'data> = VerneedTable<'data>;

    fn link_for_arch<'data>(
        linker: &'data crate::Linker,
        args: &'data Self::Args,
    ) -> crate::error::Result<crate::LinkerOutput<'data>> {
        if !cfg!(feature = "wasm") {
            crate::bail!(
                "Wasm support is still experimental. Rebuild with `--features wasm` to enable it."
            );
        }

        linker.link_for_arch::<Wasm, crate::wasm_wasm32::WasmWasm32>(args)
    }

    fn write_output_file<'data, A: platform::Arch<Platform = Self>>(
        output: &crate::file_writer::Output,
        layout: &crate::layout::Layout<'data, Self>,
    ) -> crate::error::Result {
        todo!()
    }

    fn section_attributes(header: &Self::SectionHeader) -> Self::SectionAttributes {
        SectionAttributes::default()
    }

    fn apply_force_keep_sections(
        _keep_sections: &mut crate::output_section_map::OutputSectionMap<bool>,
        _args: &Self::Args,
    ) {
        // No `-u` / `--require-defined` analogue is wired through for Wasm yet.
    }

    fn is_zero_sized_section_content(
        _section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        false
    }

    fn built_in_section_details() -> &'static [Self::BuiltInSectionDetails] {
        &SECTION_DEFINITIONS
    }

    fn finalise_group_layout(
        memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> Self::GroupLayoutExt {
    }

    fn frame_data_base_address(
        memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> u64 {
        0
    }

    fn finalise_find_required_sections<'data>(
        groups: &mut [crate::layout::GroupState<Self>],
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn activate_dynamic<'data>(
        state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
        todo!()
    }

    fn pre_finalise_sizes_prelude<'scope, 'data>(
        prelude: &mut crate::layout::PreludeLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        resources: &crate::layout::GraphResources<'data, 'scope, Self>,
    ) {
        todo!()
    }

    fn finalise_sizes_dynamic<'data>(
        object: &mut crate::layout::DynamicLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) -> crate::error::Result {
        todo!()
    }

    fn finalise_object_sizes<'data>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
        todo!()
    }

    fn finalise_object_layout<'data>(
        object: &crate::layout::ObjectLayoutState<'data, Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
        todo!()
    }

    fn finalise_layout_dynamic<'data>(
        state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
        resolutions_out: &mut crate::layout::ResolutionWriter<Self>,
    ) -> crate::error::Result<Self::DynamicLayoutExt<'data>> {
        todo!()
    }

    fn take_dynsym_index(
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        section_layouts: &crate::output_section_map::OutputSectionMap<
            crate::layout::OutputRecordLayout,
        >,
    ) -> crate::error::Result<u32> {
        todo!()
    }

    fn compute_object_addresses<'data>(
        object: &crate::layout::ObjectLayoutState<'data, Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
        todo!()
    }

    fn layout_resources_ext<'data>(
        groups: &[crate::grouping::Group<'data, Self>],
    ) -> Self::LayoutResourcesExt<'data> {
    }

    fn load_object_section_relocations<'data, 'scope, A: platform::Arch<Platform = Self>>(
        state: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        queue: &mut crate::layout::LocalWorkQueue,
        resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        section: crate::layout::Section,
        section_index: object::SectionIndex,
        scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        todo!()
    }

    fn create_dynamic_symbol_definition<'data>(
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> crate::error::Result<crate::layout::DynamicSymbolDefinition<'data, Self>> {
        todo!()
    }

    fn update_segment_keep_list(
        program_segments: &crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
        keep_segments: &mut [bool],
        args: &Self::Args,
    ) {
        todo!()
    }

    fn program_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        PROGRAM_SEGMENT_DEFS
    }

    fn unconditional_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }

    fn create_linker_defined_symbols(
        symbols: &mut crate::parsing::InternalSymbolsBuilder<Self>,
        output_kind: crate::output_kind::OutputKind,
        args: &Self::Args,
    ) {
        // TODO: emit `__heap_base`, `__data_end`, `__stack_pointer`, etc.
    }

    fn built_in_section_infos<'data>()
    -> Vec<crate::output_section_id::SectionOutputInfo<'data, Self>> {
        SECTION_DEFINITIONS
            .iter()
            .map(|d| crate::output_section_id::SectionOutputInfo {
                section_attributes: SectionAttributes::default(),
                kind: d.kind,
                min_alignment: crate::alignment::MIN,
                location: None,
                secondary_order: None,
            })
            .collect()
    }

    fn create_layout_properties<'data, 'states, 'files, A: platform::Arch<Platform = Self>>(
        args: &Self::Args,
        objects: impl Iterator<Item = &'files Self::File<'data>>,
        states: impl Iterator<Item = &'states Self::ObjectLayoutStateExt<'data>> + Clone,
    ) -> crate::error::Result<Self::LayoutExt>
    where
        'data: 'files,
        'data: 'states,
    {
        Ok(())
    }

    fn load_exception_frame_data<'data, 'scope, A: platform::Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        eh_frame_section_index: object::SectionIndex,
        resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        queue: &mut crate::layout::LocalWorkQueue,
        scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        // Wasm doesn't have ELF-style `.eh_frame`.
        Ok(())
    }

    fn non_empty_section_loaded<'data, 'scope, A: platform::Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        queue: &mut crate::layout::LocalWorkQueue,
        unloaded: crate::resolution::UnloadedSection,
        resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        todo!()
    }

    fn new_epilogue_layout(
        args: &Self::Args,
        output_kind: crate::output_kind::OutputKind,
        dynamic_symbol_definitions: &mut [crate::layout::DynamicSymbolDefinition<'_, Self>],
    ) -> Self::EpilogueLayoutExt {
    }

    fn apply_non_addressable_indexes_epilogue(
        counts: &mut Self::NonAddressableCounts,
        state: &mut Self::EpilogueLayoutExt,
    ) {
        // No-op: Wasm has no version table.
    }

    fn apply_non_addressable_indexes<'data, 'groups>(
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        counts: &Self::NonAddressableCounts,
        mem_sizes_iter: impl Iterator<
            Item = &'groups mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        >,
    ) {
        // No-op for now.
    }

    fn finalise_sizes_epilogue<'data>(
        state: &mut Self::EpilogueLayoutExt,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        dynamic_symbol_definitions: &[crate::layout::DynamicSymbolDefinition<'data, Self>],
        properties: &Self::LayoutExt,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
        todo!()
    }

    fn finalise_sizes_all<'data>(
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
        todo!()
    }

    fn apply_late_size_adjustments_epilogue(
        state: &mut Self::EpilogueLayoutExt,
        current_sizes: &crate::output_section_part_map::OutputSectionPartMap<u64>,
        extra_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
        args: &Self::Args,
    ) -> crate::error::Result {
        Ok(())
    }

    fn finalise_layout_epilogue<'data>(
        epilogue_state: &mut Self::EpilogueLayoutExt,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        common_state: &Self::LayoutExt,
        dynsym_start_index: u32,
        dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
    ) -> crate::error::Result {
        Ok(())
    }

    fn is_symbol_non_interposable<'data>(
        _object: &Self::File<'data>,
        _args: &Self::Args,
        _sym: &Self::SymtabEntry,
        _output_kind: crate::output_kind::OutputKind,
        _export_list: Option<&crate::export_list::ExportList>,
        _lib_name: &[u8],
        _archive_semantics: bool,
        _is_undefined: bool,
    ) -> bool {
        // No dynamic linking yet, so nothing can be interposed.
        true
    }

    fn allocate_header_sizes(
        prelude: &mut crate::layout::PreludeLayoutState<Self>,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        header_info: &crate::layout::HeaderInfo,
        output_sections: &crate::output_section_id::OutputSections<Self>,
    ) {
        todo!()
    }

    fn finalise_sizes_for_symbol<'data>(
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        symbol_id: crate::symbol_db::SymbolId,
        flags: crate::value_flags::ValueFlags,
    ) -> crate::error::Result {
        todo!()
    }

    fn allocate_resolution(
        flags: crate::value_flags::ValueFlags,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        output_kind: crate::output_kind::OutputKind,
        args: &Self::Args,
    ) {
        todo!()
    }

    fn allocate_object_symtab_space<'data>(
        state: &crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        per_symbol_flags: &crate::value_flags::AtomicPerSymbolFlags,
    ) -> crate::error::Result {
        todo!()
    }

    fn allocate_internal_symbol(
        symbol_id: crate::symbol_db::SymbolId,
        def_info: &crate::parsing::InternalSymDefInfo<Self>,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) -> crate::error::Result {
        todo!()
    }

    fn allocate_prelude(
        common: &mut crate::layout::CommonGroupState<Self>,
        symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) {
        todo!()
    }

    fn finalise_prelude_layout<'data>(
        prelude: &crate::layout::PreludeLayoutState<Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
    ) -> crate::error::Result<Self::PreludeLayoutExt> {
        Ok(())
    }

    fn create_resolution(
        flags: crate::value_flags::ValueFlags,
        raw_value: u64,
        dynamic_symbol_index: Option<std::num::NonZeroU32>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> crate::layout::Resolution<Self> {
        todo!()
    }

    fn raw_symbol_name<'data>(
        name_bytes: &'data [u8],
        verneed_table: &Self::VerneedTable<'data>,
        symbol_index: object::SymbolIndex,
    ) -> Self::RawSymbolName<'data> {
        RawSymbolName { name: name_bytes }
    }

    fn default_layout_rules(_args: &Self::Args) -> Vec<crate::layout_rules::SectionRule<'static>> {
        Vec::new()
    }

    fn align_load_segment_start(
        _segment_def: Self::ProgramSegmentDef,
        _segment_alignment: crate::alignment::Alignment,
        _file_offset: &mut usize,
        _mem_offset: &mut u64,
    ) {
        // Wasm has no load segments in the ELF sense.
    }

    fn build_output_order_and_program_segments<'data>(
        _custom: &crate::output_section_id::CustomSectionIds,
        output_kind: crate::output_kind::OutputKind,
        output_sections: &crate::output_section_id::OutputSections<'data, Self>,
        secondary: &crate::output_section_map::OutputSectionMap<
            Vec<crate::output_section_id::OutputSectionId>,
        >,
    ) -> (
        crate::output_section_id::OutputOrder,
        crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
    ) {
        use crate::output_section_id as osid;

        let mut builder = crate::output_section_id::OutputOrderBuilder::<Self>::new(
            output_kind,
            output_sections,
            secondary,
        );

        builder.add_section(osid::FILE_HEADER);
        builder.add_section(osid::WASM_TYPE);
        builder.add_section(osid::WASM_IMPORT);
        builder.add_section(osid::WASM_FUNCTION);
        builder.add_section(osid::WASM_TABLE);
        builder.add_section(osid::WASM_MEMORY);
        builder.add_section(osid::WASM_GLOBAL);
        builder.add_section(osid::WASM_EXPORT);
        builder.add_section(osid::WASM_START);
        builder.add_section(osid::WASM_ELEMENT);
        builder.add_section(osid::WASM_DATA_COUNT);
        builder.add_section(osid::WASM_CODE);
        builder.add_section(osid::WASM_DATA);

        builder.build()
    }

    fn default_symtab_entry() -> Self::SymtabEntry {
        WasmSymbol::default()
    }

    fn start_memory_address(_output_kind: crate::output_kind::OutputKind) -> u64 {
        // Wasm uses linear memory; the linker just lays out at offset 0.
        0
    }
}

fn parse_wasm_module<'data>(input: &'data [u8]) -> Result<File<'data>> {
    ensure!(input.len() >= 8, "Wasm module too short");
    ensure!(input[..4] == WASM_MAGIC, "missing Wasm magic header");
    let version = u32_from_slice(&input[4..8]);
    ensure!(
        version == WASM_VERSION,
        "unsupported Wasm version {version}"
    );

    let mut sections: Vec<SectionHeader> = Vec::new();
    let mut symbols: Vec<WasmSymbol> = Vec::new();
    let mut segments: Vec<WasmSegmentInfo<'data>> = Vec::new();
    let mut reloc_sections: Vec<WasmRelocSection> = Vec::new();
    let mut linking_version: Option<u32> = None;
    let mut target_features_raw: Option<&'data [u8]> = None;
    let mut standard_section_index = [None; STANDARD_SECTION_LOOKUP_LEN];

    for payload in Parser::new(0).parse_all(input) {
        let payload = payload?;
        let Some((id, range)) = payload.as_section() else {
            continue;
        };

        let mut name_range: Option<Range<u32>> = None;

        if let Payload::CustomSection(reader) = &payload {
            let section_name = reader.name();
            let name_end = reader.data_offset();
            let name_start = name_end - section_name.len();
            name_range = Some(name_start as u32..name_end as u32);

            if section_name == LINKING_SECTION_NAME {
                if let KnownCustom::Linking(linking) = reader.as_known() {
                    linking_version = Some(linking.version());
                    parse_linking_subsections(input, &linking, &mut symbols, &mut segments)?;
                }
            } else if section_name.starts_with(RELOC_SECTION_PREFIX) {
                if let KnownCustom::Reloc(reloc) = reader.as_known() {
                    let target_section_index = reloc.section_index();
                    let mut entries = Vec::new();
                    for entry in reloc.entries() {
                        entries.push(WasmRelocation::from_entry(entry?));
                    }
                    reloc_sections.push(WasmRelocSection {
                        target_section_index,
                        entries,
                    });
                }
            } else if section_name == TARGET_FEATURES_SECTION_NAME {
                target_features_raw = Some(reader.data());
            }
        } else if (section_id::TYPE..=section_id::MAX).contains(&id) {
            standard_section_index[id as usize] = Some(sections.len() as u32);
        }

        sections.push(SectionHeader {
            id,
            payload_range: range.start as u32..range.end as u32,
            name_range,
        });
    }

    Ok(File {
        data: input,
        version,
        sections,
        standard_section_index,
        symbols,
        segments,
        reloc_sections,
        linking_version,
        target_features_raw,
    })
}

fn parse_linking_subsections<'data>(
    data: &'data [u8],
    linking: &wasmparser::LinkingSectionReader<'data>,
    symbols: &mut Vec<WasmSymbol>,
    segments: &mut Vec<WasmSegmentInfo<'data>>,
) -> Result {
    let data_start = data.as_ptr() as usize;
    let to_name_range = |s: &str| -> (u32, u32) {
        let start = s.as_ptr() as usize - data_start;
        (start as u32, s.len() as u32)
    };
    for sub in linking.subsections() {
        let sub = sub?;
        match sub {
            Linking::SymbolTable(map) => {
                for sym in map {
                    symbols.push(wasm_symbol_from_info(sym?, to_name_range));
                }
            }
            Linking::SegmentInfo(map) => {
                for seg in map {
                    let seg = seg?;
                    segments.push(WasmSegmentInfo {
                        name: seg.name,
                        alignment: Alignment::from_exponent(seg.alignment)?,
                        flags: seg.flags,
                    });
                }
            }
            // `InitFuncs`, `ComdatInfo`, and `Unknown` subsections are not consumed.
            _ => {}
        }
    }

    Ok(())
}

fn wasm_symbol_from_info(
    info: SymbolInfo<'_>,
    to_name_range: impl Fn(&str) -> (u32, u32),
) -> WasmSymbol {
    let mut sym = WasmSymbol::default();
    let mut set_name = |name: Option<&str>| {
        if let Some(n) = name {
            let (start, len) = to_name_range(n);
            sym.name_start = start;
            sym.name_len = len;
        }
    };
    match info {
        SymbolInfo::Func { flags, index, name } => {
            sym.kind = WasmSymbolKind::Func;
            sym.flags = flags.bits();
            sym.index = index;
            set_name(name);
        }
        SymbolInfo::Data {
            flags,
            name,
            symbol,
        } => {
            sym.kind = WasmSymbolKind::Data;
            sym.flags = flags.bits();
            let (start, len) = to_name_range(name);
            sym.name_start = start;
            sym.name_len = len;
            if let Some(def) = symbol {
                sym.index = def.index;
                sym.offset = def.offset;
                sym.size = def.size;
            }
        }
        SymbolInfo::Global { flags, index, name } => {
            sym.kind = WasmSymbolKind::Global;
            sym.flags = flags.bits();
            sym.index = index;
            set_name(name);
        }
        SymbolInfo::Section { flags, section } => {
            sym.kind = WasmSymbolKind::Section;
            sym.flags = flags.bits();
            sym.index = section;
        }
        SymbolInfo::Event { flags, index, name } => {
            sym.kind = WasmSymbolKind::Event;
            sym.flags = flags.bits();
            sym.index = index;
            set_name(name);
        }
        SymbolInfo::Table { flags, index, name } => {
            sym.kind = WasmSymbolKind::Table;
            sym.flags = flags.bits();
            sym.index = index;
            set_name(name);
        }
    }

    sym
}
