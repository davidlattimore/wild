// WASM platform support for wild linker.
#![allow(unused_variables, dead_code)]

use crate::OutputKind;
use crate::args::wasm::WasmArgs;
use crate::platform;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Wasm;

// --- Sub-types ---

/// WASM symbol entry. For now wraps basic info extracted from the object crate.
#[derive(Debug, Clone)]
pub(crate) struct WasmSymbol {
    pub(crate) name_offset: u32,
    pub(crate) is_undefined: bool,
    pub(crate) is_weak: bool,
    pub(crate) is_local: bool,
    pub(crate) is_hidden: bool,
    pub(crate) value: u64,
    pub(crate) size: u64,
    pub(crate) section_index: object::SectionIndex,
    pub(crate) is_func: bool,
}

impl platform::Symbol for WasmSymbol {
    fn as_common(&self) -> Option<platform::CommonSymbol> {
        None
    }

    fn is_undefined(&self) -> bool {
        self.is_undefined
    }

    fn is_local(&self) -> bool {
        self.is_local
    }

    fn is_absolute(&self) -> bool {
        false
    }

    fn is_weak(&self) -> bool {
        self.is_weak
    }

    fn visibility(&self) -> crate::symbol_db::Visibility {
        if self.is_hidden {
            crate::symbol_db::Visibility::Hidden
        } else {
            crate::symbol_db::Visibility::Default
        }
    }

    fn value(&self) -> u64 {
        self.value
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn section_index(&self) -> object::SectionIndex {
        self.section_index
    }

    fn has_name(&self) -> bool {
        true
    }

    fn debug_string(&self) -> String {
        format!("WasmSymbol(value={})", self.value)
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn is_interposable(&self) -> bool {
        false
    }

    fn is_func(&self) -> bool {
        self.is_func
    }

    fn is_ifunc(&self) -> bool {
        false
    }

    fn is_hidden(&self) -> bool {
        self.is_hidden
    }

    fn is_gnu_unique(&self) -> bool {
        false
    }
}

/// WASM section header — lightweight wrapper.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SectionHeader {
    pub(crate) index: usize,
    pub(crate) size: u64,
    pub(crate) is_code: bool,
    pub(crate) is_data: bool,
}

impl platform::SectionHeader for SectionHeader {
    fn is_alloc(&self) -> bool {
        self.is_code || self.is_data
    }
    fn is_writable(&self) -> bool {
        self.is_data
    }
    fn is_executable(&self) -> bool {
        self.is_code
    }
    fn is_tls(&self) -> bool {
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
        self.is_code || self.is_data
    }
    fn is_no_bits(&self) -> bool {
        false
    }
}

/// WASM section flags — trivial since WASM sections don't have flags.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SectionFlags;

impl platform::SectionFlags for SectionFlags {
    fn is_alloc(self) -> bool {
        false // WASM has no alloc/non-alloc distinction; no program segments
    }
}

/// WASM section type — trivial.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SectionType;

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

/// WASM segment type — WASM has no segments.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SegmentType;

impl platform::SegmentType for SegmentType {}

/// WASM section attributes.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SectionAttributes {
    pub(crate) is_code: bool,
    pub(crate) is_data: bool,
}

impl platform::SectionAttributes for SectionAttributes {
    type Platform = Wasm;

    fn merge(&mut self, rhs: Self) {
        self.is_code |= rhs.is_code;
        self.is_data |= rhs.is_data;
    }

    fn apply(
        &self,
        _output_sections: &mut crate::output_section_id::OutputSections<Wasm>,
        _section_id: crate::output_section_id::OutputSectionId,
    ) {
    }

    fn is_null(&self) -> bool {
        !self.is_code && !self.is_data
    }

    fn is_alloc(&self) -> bool {
        false // WASM has no alloc/non-alloc; no program segments
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

    fn flags(&self) -> SectionFlags {
        SectionFlags
    }

    fn ty(&self) -> SectionType {
        SectionType
    }

    fn set_to_default_type(&mut self) {}
}

/// WASM program segment def — empty, WASM has no segments.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProgramSegmentDef;

impl std::fmt::Display for ProgramSegmentDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wasm-segment")
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
        _section_info: &crate::output_section_id::SectionOutputInfo<Wasm>,
        _section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        false
    }
}

/// Empty built-in section details.
#[derive(Debug)]
pub(crate) struct BuiltInSectionDetails;

impl platform::BuiltInSectionDetails for BuiltInSectionDetails {}

/// Non-addressable indexes (empty for WASM).
#[derive(Debug, Default)]
pub(crate) struct NonAddressableIndexes;

impl platform::NonAddressableIndexes for NonAddressableIndexes {
    fn new<P: platform::Platform>(_symbol_db: &crate::symbol_db::SymbolDb<P>) -> Self {
        NonAddressableIndexes
    }
}

/// WASM relocation list — empty for hello world.
#[derive(Debug)]
pub(crate) struct RelocationList<'data> {
    _phantom: std::marker::PhantomData<&'data ()>,
}

impl<'data> platform::RelocationList<'data> for RelocationList<'data> {
    fn num_relocations(&self) -> usize {
        0
    }
}

/// Dynamic tag values (unused for WASM).
#[derive(Debug)]
pub(crate) struct DynamicTagValues<'data> {
    _phantom: std::marker::PhantomData<&'data ()>,
}

impl<'data> platform::DynamicTagValues<'data> for DynamicTagValues<'data> {
    fn lib_name(&self, _input: &crate::input_data::InputRef<'data>) -> &'data [u8] {
        b""
    }
}

/// Raw symbol name wrapper.
#[derive(Debug)]
pub(crate) struct RawSymbolName<'data> {
    pub(crate) name: &'data [u8],
}

impl<'data> platform::RawSymbolName<'data> for RawSymbolName<'data> {
    fn parse(bytes: &'data [u8]) -> Self {
        RawSymbolName { name: bytes }
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
        write!(f, "{}", String::from_utf8_lossy(self.name))
    }
}

/// Verneed table (unused for WASM — no symbol versioning).
pub(crate) struct VerneedTable<'data> {
    _phantom: std::marker::PhantomData<&'data ()>,
}

impl<'data> platform::VerneedTable<'data> for VerneedTable<'data> {
    fn version_name(&self, _local_symbol_index: object::SymbolIndex) -> Option<&'data [u8]> {
        None
    }
}

/// Section iterator.
pub(crate) struct WasmSectionIter<'data> {
    inner: core::slice::Iter<'data, SectionHeader>,
}

impl<'data> Iterator for WasmSectionIter<'data> {
    type Item = &'data SectionHeader;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

// --- Object file ---

#[derive(derive_more::Debug)]
pub(crate) struct File<'data> {
    #[debug(skip)]
    pub(crate) data: &'data [u8],
    pub(crate) symbols: Vec<WasmSymbol>,
    pub(crate) symbol_names: Vec<&'data [u8]>,
    pub(crate) sections: Vec<SectionHeader>,
}

impl<'data> platform::ObjectFile<'data> for File<'data> {
    type Platform = Wasm;

    fn parse_bytes(input: &'data [u8], _is_dynamic: bool) -> crate::error::Result<Self> {
        use object::Object as _;
        use object::ObjectSection as _;
        use object::ObjectSymbol as _;

        let wasm_file = object::read::wasm::WasmFile::parse(input)?;

        // Build sections with a mapping from object crate indices to contiguous indices.
        let mut sections = Vec::new();
        let mut section_index_map = std::collections::HashMap::new();
        for section in wasm_file.sections() {
            let kind = section.kind();
            let our_index = sections.len();
            section_index_map.insert(section.index().0, our_index);
            sections.push(SectionHeader {
                index: our_index,
                size: section.size(),
                is_code: kind == object::SectionKind::Text,
                is_data: kind == object::SectionKind::Data
                    || kind == object::SectionKind::ReadOnlyData,
            });
        }

        let mut symbols = Vec::new();
        let mut symbol_names = Vec::new();

        for sym in wasm_file.symbols() {
            let name = sym.name_bytes().unwrap_or(b"");
            let raw_section = sym.section_index().unwrap_or(object::SectionIndex(0));
            let section_index = object::SectionIndex(
                section_index_map.get(&raw_section.0).copied().unwrap_or(0),
            );
            symbols.push(WasmSymbol {
                name_offset: symbol_names.len() as u32,
                is_undefined: sym.is_undefined(),
                is_weak: sym.is_weak(),
                is_local: sym.is_local(),
                is_hidden: false,
                value: sym.address(),
                size: sym.size(),
                section_index,
                is_func: sym.kind() == object::SymbolKind::Text,
            });
            symbol_names.push(name);
        }

        Ok(File {
            data: input,
            symbols,
            symbol_names,
            sections,
        })
    }

    fn parse(
        input: &crate::input_data::InputBytes<'data>,
        _args: &WasmArgs,
    ) -> crate::error::Result<Self> {
        Self::parse_bytes(input.data, false)
    }

    fn is_dynamic(&self) -> bool {
        false
    }

    fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    fn symbols_iter(&self) -> impl Iterator<Item = &'data WasmSymbol> {
        // Safety: symbols are owned by File which lives for 'data.
        // The symbols Vec is allocated once and never reallocated.
        let slice = self.symbols.as_slice();
        let ptr = slice.as_ptr();
        let len = slice.len();
        unsafe { std::slice::from_raw_parts(ptr, len) }.iter()
    }

    fn symbol(
        &self,
        index: object::SymbolIndex,
    ) -> crate::error::Result<&'data WasmSymbol> {
        let sym = self
            .symbols
            .get(index.0)
            .ok_or_else(|| crate::error!("Symbol index {} out of range", index.0))?;
        // Safety: same as symbols_iter
        Ok(unsafe { &*(sym as *const WasmSymbol) })
    }

    fn section_size(&self, header: &SectionHeader) -> crate::error::Result<u64> {
        Ok(header.size)
    }

    fn symbol_name(&self, symbol: &WasmSymbol) -> crate::error::Result<&'data [u8]> {
        let idx = symbol.name_offset as usize;
        let name = self
            .symbol_names
            .get(idx)
            .ok_or_else(|| crate::error!("Symbol name index {} out of range", idx))?;
        // Safety: symbol_names stores &'data [u8] references
        Ok(unsafe { &*((*name) as *const [u8]) })
    }

    fn num_sections(&self) -> usize {
        self.sections.len()
    }

    fn section_iter(&self) -> WasmSectionIter<'data> {
        let slice = self.sections.as_slice();
        let ptr = slice.as_ptr();
        let len = slice.len();
        WasmSectionIter {
            inner: unsafe { std::slice::from_raw_parts(ptr, len) }.iter(),
        }
    }

    fn enumerate_sections(
        &self,
    ) -> impl Iterator<Item = (object::SectionIndex, &'data SectionHeader)> {
        let slice = self.sections.as_slice();
        let ptr = slice.as_ptr();
        let len = slice.len();
        unsafe { std::slice::from_raw_parts(ptr, len) }
            .iter()
            .enumerate()
            .map(|(i, s)| (object::SectionIndex(i), s))
    }

    fn section(&self, index: object::SectionIndex) -> crate::error::Result<&'data SectionHeader> {
        let s = self
            .sections
            .get(index.0)
            .ok_or_else(|| crate::error!("Section index {} out of range", index.0))?;
        Ok(unsafe { &*(s as *const SectionHeader) })
    }

    fn section_by_name(&self, _name: &str) -> Option<(object::SectionIndex, &'data SectionHeader)> {
        None
    }

    fn symbol_section(
        &self,
        symbol: &WasmSymbol,
        _index: object::SymbolIndex,
    ) -> crate::error::Result<Option<object::SectionIndex>> {
        if symbol.is_undefined {
            Ok(None)
        } else {
            Ok(Some(symbol.section_index))
        }
    }

    fn symbol_value_in_section(
        &self,
        symbol: &WasmSymbol,
        _section_index: object::SectionIndex,
    ) -> crate::error::Result<u64> {
        Ok(symbol.value)
    }

    fn symbol_versions(&self) -> &[()] {
        &[]
    }

    fn dynamic_symbol_used(
        &self,
        _symbol_index: object::SymbolIndex,
        _state: &mut (),
    ) -> crate::error::Result {
        Ok(())
    }

    fn finalise_sizes_dynamic(
        &self,
        _lib_name: &[u8],
        _state: &mut (),
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn raw_section_data(
        &self,
        _header: &SectionHeader,
    ) -> crate::error::Result<&'data [u8]> {
        Ok(&[])
    }

    fn section_data(
        &self,
        section: &SectionHeader,
        _member: &bumpalo_herd::Member<'data>,
        _loaded_metrics: &crate::resolution::LoadedMetrics,
    ) -> crate::error::Result<&'data [u8]> {
        self.raw_section_data(section)
    }

    fn copy_section_data(
        &self,
        _section: &SectionHeader,
        _out: &mut [u8],
    ) -> crate::error::Result {
        Ok(())
    }

    fn section_data_cow(
        &self,
        section: &SectionHeader,
    ) -> crate::error::Result<std::borrow::Cow<'data, [u8]>> {
        Ok(std::borrow::Cow::Borrowed(self.raw_section_data(section)?))
    }

    fn section_alignment(
        &self,
        _section: &SectionHeader,
    ) -> crate::error::Result<u64> {
        Ok(1)
    }

    fn relocations(
        &self,
        _index: object::SectionIndex,
        _relocations: &(),
    ) -> crate::error::Result<RelocationList<'data>> {
        Ok(RelocationList {
            _phantom: std::marker::PhantomData,
        })
    }

    fn parse_relocations(&self) -> crate::error::Result<()> {
        Ok(())
    }

    fn symbol_version_debug(&self, _symbol_index: object::SymbolIndex) -> Option<String> {
        None
    }

    fn section_display_name(&self, index: object::SectionIndex) -> std::borrow::Cow<'data, str> {
        std::borrow::Cow::Owned(format!("wasm-section-{}", index.0))
    }

    fn section_name(
        &self,
        _section_header: &'data SectionHeader,
    ) -> crate::error::Result<&'data [u8]> {
        Ok(b"")
    }

    fn apply_non_addressable_indexes_dynamic(
        &self,
        _indexes: &mut NonAddressableIndexes,
        _counts: &mut (),
        _state: &mut (),
    ) -> crate::error::Result {
        Ok(())
    }

    fn dynamic_tag_values(&self) -> Option<DynamicTagValues<'data>> {
        None
    }

    fn get_version_names(&self) -> crate::error::Result<()> {
        Ok(())
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &WasmSymbol,
        local_index: usize,
        _version_names: &(),
    ) -> crate::error::Result<RawSymbolName<'data>> {
        let name = self.symbol_name(symbol)?;
        Ok(RawSymbolName { name })
    }

    fn should_enforce_undefined(
        &self,
        _resources: &crate::layout::GraphResources<'data, '_, Wasm>,
    ) -> bool {
        false
    }

    fn verneed_table(&self) -> crate::error::Result<VerneedTable<'data>> {
        Ok(VerneedTable {
            _phantom: std::marker::PhantomData,
        })
    }

    fn process_gnu_note_section(
        &self,
        _state: &mut (),
        _section_index: object::SectionIndex,
    ) -> crate::error::Result {
        Ok(())
    }

    fn dynamic_tags(&self) -> crate::error::Result<&'data [()]> {
        Ok(&[])
    }
}

// --- Platform impl ---

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
    type NonAddressableIndexes = NonAddressableIndexes;
    type NonAddressableCounts = ();
    type EpilogueLayoutExt = ();
    type GroupLayoutExt = ();
    type CommonGroupStateExt = ();
    type ArchIdentifier = ();
    type Args = WasmArgs;
    type ResolutionExt = ();
    type SymbolVersionIndex = ();
    type LayoutExt = ();
    type SectionIterator<'data> = WasmSectionIter<'data>;
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
    type SymtabShndxEntry = u32;

    fn link_for_arch<'data>(
        linker: &'data crate::Linker,
        args: &'data Self::Args,
    ) -> crate::error::Result<crate::LinkerOutput<'data>> {
        linker.link_for_arch::<Wasm, crate::wasm_arch::WasmArch>(args)
    }

    fn write_output_file<'data, A: platform::Arch<Platform = Self>>(
        output: &crate::file_writer::Output,
        layout: &crate::layout::Layout<'data, Self>,
    ) -> crate::error::Result {
        output.write(layout, |_sized_output, lay| {
            crate::wasm_writer::write_direct::<A>(lay)
        })
    }

    fn section_attributes(header: &Self::SectionHeader) -> Self::SectionAttributes {
        SectionAttributes {
            is_code: header.is_code,
            is_data: header.is_data,
        }
    }

    fn apply_force_keep_sections(
        _keep_sections: &mut crate::output_section_map::OutputSectionMap<bool>,
        _args: &Self::Args,
    ) {
    }

    fn is_zero_sized_section_content(
        _section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        false
    }

    fn built_in_section_details() -> &'static [Self::BuiltInSectionDetails] {
        &[]
    }

    fn finalise_group_layout(
        _memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> Self::GroupLayoutExt {
    }

    fn frame_data_base_address(
        _memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> u64 {
        0
    }

    fn start_memory_address(_output_kind: OutputKind) -> u64 {
        0
    }

    fn finalise_find_required_sections(_groups: &[crate::layout::GroupState<Self>]) {}

    fn activate_dynamic<'data>(
        _state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
    }

    fn pre_finalise_sizes_prelude<'scope, 'data>(
        _prelude: &mut crate::layout::PreludeLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _resources: &crate::layout::GraphResources<'data, 'scope, Self>,
    ) {
    }

    fn finalise_sizes_dynamic<'data>(
        _object: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn finalise_object_sizes<'data>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
    }

    fn finalise_object_layout<'data>(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
    }

    fn finalise_layout_dynamic<'data>(
        _state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
        _resolutions_out: &mut crate::layout::ResolutionWriter<Self>,
    ) -> crate::error::Result<Self::DynamicLayoutExt<'data>> {
        Ok(())
    }

    fn take_dynsym_index(
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _section_layouts: &crate::output_section_map::OutputSectionMap<
            crate::layout::OutputRecordLayout,
        >,
    ) -> crate::error::Result<u32> {
        Ok(1)
    }

    fn compute_object_addresses<'data>(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
    }

    fn layout_resources_ext<'data>(
        _groups: &[crate::grouping::Group<'data, Self>],
    ) -> Self::LayoutResourcesExt<'data> {
    }

    fn load_object_section_relocations<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _state: &crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _section: crate::layout::Section,
        _scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn create_dynamic_symbol_definition<'data>(
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> crate::error::Result<crate::layout::DynamicSymbolDefinition<'data, Self>> {
        let name = symbol_db.symbol_name(symbol_id)?.bytes();
        Ok(crate::layout::DynamicSymbolDefinition {
            symbol_id,
            name,
            format_specific: (),
        })
    }

    fn update_segment_keep_list(
        _program_segments: &crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
        _keep_segments: &mut [bool],
        _args: &Self::Args,
    ) {
    }

    fn program_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }

    fn unconditional_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }

    fn create_linker_defined_symbols(
        _symbols: &mut crate::parsing::InternalSymbolsBuilder,
        _output_kind: OutputKind,
        _args: &Self::Args,
    ) {
    }

    fn built_in_section_infos<'data>()
    -> Vec<crate::output_section_id::SectionOutputInfo<'data, Self>> {
        use crate::output_section_id::NUM_BUILT_IN_SECTIONS;
        use crate::output_section_id::SectionOutputInfo;
        use crate::layout_rules::SectionKind;
        use crate::output_section_id::SectionName;

        let mut infos: Vec<SectionOutputInfo<'data, Self>> =
            Vec::with_capacity(NUM_BUILT_IN_SECTIONS);
        for _ in 0..NUM_BUILT_IN_SECTIONS {
            infos.push(SectionOutputInfo {
                kind: SectionKind::Primary(SectionName(b"")),
                section_attributes: SectionAttributes::default(),
                min_alignment: crate::alignment::MIN,
                location: None,
                secondary_order: None,
            });
        }
        infos[crate::output_section_id::TEXT.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b".text")),
            section_attributes: SectionAttributes {
                is_code: true,
                is_data: false,
            },
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        infos
    }

    fn create_layout_properties<'data, 'states, 'files, A: platform::Arch<Platform = Self>>(
        _args: &Self::Args,
        _objects: impl Iterator<Item = &'files Self::File<'data>>,
        _states: impl Iterator<Item = &'states Self::ObjectLayoutStateExt<'data>> + Clone,
    ) -> crate::error::Result<Self::LayoutExt>
    where
        'data: 'files,
        'data: 'states,
    {
        Ok(())
    }

    fn load_exception_frame_data<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _eh_frame_section_index: object::SectionIndex,
        _resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn non_empty_section_loaded<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _unloaded: crate::resolution::UnloadedSection,
        _resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        _scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn new_epilogue_layout(
        _args: &Self::Args,
        _output_kind: OutputKind,
        _dynamic_symbol_definitions: &mut [crate::layout::DynamicSymbolDefinition<'_, Self>],
    ) -> Self::EpilogueLayoutExt {
    }

    fn apply_non_addressable_indexes_epilogue(
        _counts: &mut Self::NonAddressableCounts,
        _state: &mut Self::EpilogueLayoutExt,
    ) {
    }

    fn apply_non_addressable_indexes<'data, 'groups>(
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _counts: &Self::NonAddressableCounts,
        _mem_sizes_iter: impl Iterator<
            Item = &'groups mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        >,
    ) {
    }

    fn finalise_sizes_epilogue<'data>(
        _state: &mut Self::EpilogueLayoutExt,
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _dynamic_symbol_definitions: &[crate::layout::DynamicSymbolDefinition<'data, Self>],
        _properties: &Self::LayoutExt,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
    }

    fn finalise_sizes_all<'data>(
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
    }

    fn apply_late_size_adjustments_epilogue(
        _state: &mut Self::EpilogueLayoutExt,
        _current_sizes: &crate::output_section_part_map::OutputSectionPartMap<u64>,
        _extra_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
        _args: &Self::Args,
    ) -> crate::error::Result {
        Ok(())
    }

    fn finalise_layout_epilogue<'data>(
        _epilogue_state: &mut Self::EpilogueLayoutExt,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _common_state: &Self::LayoutExt,
        _dynsym_start_index: u32,
        _dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
    ) -> crate::error::Result {
        Ok(())
    }

    fn is_symbol_non_interposable<'data>(
        _object: &Self::File<'data>,
        _args: &Self::Args,
        _sym: &Self::SymtabEntry,
        _output_kind: OutputKind,
        _export_list: Option<&crate::export_list::ExportList>,
        _lib_name: &[u8],
        _archive_semantics: bool,
        _is_undefined: bool,
    ) -> bool {
        true
    }

    fn allocate_header_sizes(
        _prelude: &mut crate::layout::PreludeLayoutState<Self>,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _header_info: &crate::layout::HeaderInfo,
        _output_sections: &crate::output_section_id::OutputSections<Self>,
    ) {
        // WASM header is 8 bytes (magic + version).
        sizes.increment(crate::part_id::FILE_HEADER, 8);
    }

    fn finalise_sizes_for_symbol<'data>(
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _symbol_id: crate::symbol_db::SymbolId,
        _flags: crate::value_flags::ValueFlags,
    ) -> crate::error::Result {
        Ok(())
    }

    fn allocate_resolution(
        _flags: crate::value_flags::ValueFlags,
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _output_kind: OutputKind,
        _args: &Self::Args,
    ) {
    }

    fn allocate_object_symtab_space<'data>(
        _state: &crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _per_symbol_flags: &crate::value_flags::AtomicPerSymbolFlags,
    ) -> crate::error::Result {
        Ok(())
    }

    fn allocate_internal_symbol(
        _symbol_id: crate::symbol_db::SymbolId,
        _def_info: &crate::parsing::InternalSymDefInfo,
        _sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn allocate_prelude(
        _common: &mut crate::layout::CommonGroupState<Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) {
    }

    fn finalise_prelude_layout<'data>(
        _prelude: &crate::layout::PreludeLayoutState<Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
    ) -> crate::error::Result<Self::PreludeLayoutExt> {
        Ok(())
    }

    fn create_resolution(
        flags: crate::value_flags::ValueFlags,
        raw_value: u64,
        dynamic_symbol_index: Option<std::num::NonZeroU32>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> crate::layout::Resolution<Self> {
        crate::layout::Resolution {
            raw_value,
            dynamic_symbol_index,
            flags,
            format_specific: (),
        }
    }

    fn raw_symbol_name<'data>(
        name_bytes: &'data [u8],
        _verneed_table: &Self::VerneedTable<'data>,
        _symbol_index: object::SymbolIndex,
    ) -> Self::RawSymbolName<'data> {
        RawSymbolName { name: name_bytes }
    }

    fn default_layout_rules() -> &'static [crate::layout_rules::SectionRule<'static>] {
        &[]
    }

    fn build_output_order_and_program_segments<'data>(
        custom: &crate::output_section_id::CustomSectionIds,
        output_kind: OutputKind,
        output_sections: &crate::output_section_id::OutputSections<'data, Self>,
        secondary: &crate::output_section_map::OutputSectionMap<
            Vec<crate::output_section_id::OutputSectionId>,
        >,
    ) -> (
        crate::output_section_id::OutputOrder,
        crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
    ) {
        use crate::output_section_id;
        let mut builder = crate::output_section_id::OutputOrderBuilder::<Self>::new(
            output_kind,
            output_sections,
            secondary,
        );

        builder.add_section(output_section_id::FILE_HEADER);
        builder.add_section(output_section_id::TEXT);
        builder.add_sections(&custom.exec);
        builder.add_section(output_section_id::RODATA);
        builder.add_sections(&custom.ro);
        builder.add_section(output_section_id::DATA);
        builder.add_sections(&custom.data);

        builder.build()
    }
}
