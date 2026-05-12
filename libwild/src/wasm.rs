// TODO
#![allow(unused_variables)]
#![allow(unused)]

use crate::alignment::Alignment;
use crate::args::wasm::WasmArgs;
use crate::ensure;
use crate::error::Context as _;
use crate::error::Result;
use crate::platform;
use linker_utils::utils::u32_from_slice;
use std::ops::Range;
use wasmparser::KnownCustom;
use wasmparser::Linking;
use wasmparser::Parser;
use wasmparser::Payload;
use wasmparser::RelocationEntry;
use wasmparser::SegmentFlags;
use wasmparser::SymbolInfo;

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct Wasm;

/// Magic bytes at the start of every Wasm module.
pub(crate) const WASM_MAGIC: [u8; 4] = [0x00, b'a', b's', b'm'];

/// Supported Wasm binary format version.
pub(crate) const WASM_VERSION: u32 = 1;

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
    pub(crate) sections: Vec<WasmSection<'data>>,

    #[debug(skip)]
    pub(crate) symbols: Vec<WasmSymbol<'data>>,

    #[debug(skip)]
    pub(crate) segments: Vec<WasmSegmentInfo<'data>>,

    #[debug(skip)]
    pub(crate) reloc_sections: Vec<WasmRelocSection>,

    pub(crate) linking_version: Option<u32>,

    /// Raw payload of the `target_features` custom section, if present.
    #[debug(skip)]
    pub(crate) target_features_raw: Option<&'data [u8]>,
}

/// A single section of a Wasm module, as it appears in the binary.
#[derive(Debug, Clone)]
pub(crate) struct WasmSection<'data> {
    /// The wasm section id.
    pub(crate) id: u8,

    /// Name of a custom section, or `None` for standard sections.
    pub(crate) name: Option<&'data str>,

    /// Byte range of the section (id + size + payload) within the original Wasm binary.
    pub(crate) range: Range<usize>,

    /// The payload bytes of the section.
    pub(crate) payload: &'data [u8],
}

impl<'data> WasmSection<'data> {
    pub(crate) fn is_custom(&self) -> bool {
        self.id == 0
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WasmSymbol<'data> {
    pub(crate) info: SymbolInfo<'data>,
}

impl<'data> WasmSymbol<'data> {
    pub(crate) fn flags(&self) -> wasmparser::SymbolFlags {
        match self.info {
            SymbolInfo::Func { flags, .. }
            | SymbolInfo::Data { flags, .. }
            | SymbolInfo::Global { flags, .. }
            | SymbolInfo::Section { flags, .. }
            | SymbolInfo::Event { flags, .. }
            | SymbolInfo::Table { flags, .. } => flags,
        }
    }

    pub(crate) fn name(&self) -> Option<&'data str> {
        match self.info {
            SymbolInfo::Func { name, .. }
            | SymbolInfo::Global { name, .. }
            | SymbolInfo::Event { name, .. }
            | SymbolInfo::Table { name, .. } => name,
            SymbolInfo::Data { name, .. } => Some(name),
            SymbolInfo::Section { .. } => None,
        }
    }

    pub(crate) fn is_undefined(&self) -> bool {
        self.flags().contains(wasmparser::SymbolFlags::UNDEFINED)
    }

    pub(crate) fn is_weak(&self) -> bool {
        self.flags().contains(wasmparser::SymbolFlags::BINDING_WEAK)
    }

    pub(crate) fn is_local(&self) -> bool {
        self.flags()
            .contains(wasmparser::SymbolFlags::BINDING_LOCAL)
    }

    pub(crate) fn is_hidden(&self) -> bool {
        self.flags()
            .contains(wasmparser::SymbolFlags::VISIBILITY_HIDDEN)
    }

    pub(crate) fn is_exported(&self) -> bool {
        self.flags().contains(wasmparser::SymbolFlags::EXPORTED)
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
    pub(crate) entries: Vec<RelocationEntry>,
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

    fn symbols_iter(&self) -> impl Iterator<Item = &'data ()> {
        [].iter()
    }

    fn symbol(
        &self,
        index: object::SymbolIndex,
    ) -> crate::error::Result<&'data <Self::Platform as platform::Platform>::SymtabEntry> {
        todo!()
    }

    fn section_size(
        &self,
        header: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<u64> {
        todo!()
    }

    fn symbol_name(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
    ) -> crate::error::Result<&'data [u8]> {
        todo!()
    }

    fn symbol_offset_in_section(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        section_index: object::SectionIndex,
    ) -> crate::error::Result<u64> {
        todo!()
    }

    fn num_sections(&self) -> usize {
        // TODO
        0
    }

    fn section_iter(&self) -> <Self::Platform as platform::Platform>::SectionIterator<'data> {
        [].iter()
    }

    fn enumerate_sections(
        &self,
    ) -> impl Iterator<
        Item = (
            object::SectionIndex,
            &'data <Self::Platform as platform::Platform>::SectionHeader,
        ),
    > {
        [].iter()
            .enumerate()
            .map(|(i, section)| (object::SectionIndex(i), section))
    }

    fn section(
        &self,
        index: object::SectionIndex,
    ) -> crate::error::Result<&'data <Self::Platform as platform::Platform>::SectionHeader> {
        todo!()
    }

    fn section_by_name(
        &self,
        name: &str,
    ) -> Option<(
        object::SectionIndex,
        &'data <Self::Platform as platform::Platform>::SectionHeader,
    )> {
        todo!()
    }

    fn symbol_section(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        index: object::SymbolIndex,
    ) -> crate::error::Result<Option<object::SectionIndex>> {
        todo!()
    }

    fn symbol_versions(&self) -> &[<Self::Platform as platform::Platform>::SymbolVersionIndex] {
        // Wasm doesn't have ELF-style symbol versioning.
        &[]
    }

    fn dynamic_symbol_used(
        &self,
        symbol_index: object::SymbolIndex,
        state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
    ) -> crate::error::Result {
        todo!()
    }

    fn finalise_sizes_dynamic(
        &self,
        lib_name: &[u8],
        state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> crate::error::Result {
        todo!()
    }

    fn apply_non_addressable_indexes_dynamic(
        &self,
        indexes: &mut <Self::Platform as platform::Platform>::NonAddressableIndexes,
        counts: &mut <Self::Platform as platform::Platform>::NonAddressableCounts,
        state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
    ) -> crate::error::Result {
        todo!()
    }

    fn section_name(
        &self,
        section_header: &'data <Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<&'data [u8]> {
        todo!()
    }

    fn raw_section_data(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<&'data [u8]> {
        todo!()
    }

    fn section_data(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
        member: &bumpalo_herd::Member<'data>,
        loaded_metrics: &crate::resolution::LoadedMetrics,
    ) -> crate::error::Result<&'data [u8]> {
        todo!()
    }

    fn copy_section_data(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
        out: &mut [u8],
    ) -> crate::error::Result {
        todo!()
    }

    fn section_data_cow(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<std::borrow::Cow<'data, [u8]>> {
        todo!()
    }

    fn section_alignment(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<u64> {
        todo!()
    }

    fn relocations(
        &self,
        index: object::SectionIndex,
        relocations: &<Self::Platform as platform::Platform>::RelocationSections,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RelocationList<'data>> {
        todo!()
    }

    fn parse_relocations(
        &self,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RelocationSections> {
        todo!()
    }

    fn symbol_version_debug(&self, symbol_index: object::SymbolIndex) -> Option<String> {
        // Wasm doesn't have ELF-style symbol versioning.
        None
    }

    fn section_display_name(&self, index: object::SectionIndex) -> std::borrow::Cow<'data, str> {
        todo!()
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
        local_index: usize,
        version_names: &<Self::Platform as platform::Platform>::VersionNames<'data>,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RawSymbolName<'data>> {
        todo!()
    }

    fn should_enforce_undefined(
        &self,
        resources: &crate::layout::GraphResources<'data, '_, Self::Platform>,
    ) -> bool {
        todo!()
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

#[derive(Debug, Default)]
pub(crate) struct SectionHeader {}

impl platform::SectionHeader for SectionHeader {
    fn is_alloc(&self) -> bool {
        todo!()
    }

    fn is_writable(&self) -> bool {
        todo!()
    }

    fn is_executable(&self) -> bool {
        todo!()
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
        todo!()
    }

    fn is_no_bits(&self) -> bool {
        todo!()
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

impl platform::Symbol for () {
    fn as_common(&self) -> Option<platform::CommonSymbol> {
        // Wasm doesn't really have COMMON symbols in the ELF sense.
        None
    }

    fn is_undefined(&self) -> bool {
        todo!()
    }

    fn is_local(&self) -> bool {
        todo!()
    }

    fn is_absolute(&self) -> bool {
        todo!()
    }

    fn is_weak(&self) -> bool {
        todo!()
    }

    fn visibility(&self) -> crate::symbol_db::Visibility {
        todo!()
    }

    fn value(&self) -> u64 {
        todo!()
    }

    fn size(&self) -> u64 {
        todo!()
    }

    fn has_name(&self) -> bool {
        todo!()
    }

    fn is_default_strippable(&self, name: &[u8]) -> bool {
        todo!()
    }

    fn debug_string(&self) -> String {
        String::from("WasmSymbol")
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn is_interposable(&self) -> bool {
        todo!()
    }

    fn is_func(&self) -> bool {
        todo!()
    }

    fn is_ifunc(&self) -> bool {
        false
    }

    fn is_hidden(&self) -> bool {
        todo!()
    }

    fn is_gnu_unique(&self) -> bool {
        false
    }

    fn with_hidden(self, hidden: bool) -> Self {
        // TODO: track hidden visibility on the Wasm symbol once linking-section
        // flags are wired up.
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionAttributes {}

impl platform::SectionAttributes for SectionAttributes {
    type Platform = Wasm;

    fn merge(&mut self, rhs: Self) {
        todo!()
    }

    fn apply(
        &self,
        output_sections: &mut crate::output_section_id::OutputSections<Self::Platform>,
        section_id: crate::output_section_id::OutputSectionId,
    ) {
        todo!()
    }

    fn is_null(&self) -> bool {
        todo!()
    }

    fn is_alloc(&self) -> bool {
        todo!()
    }

    fn is_executable(&self) -> bool {
        todo!()
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn is_writable(&self) -> bool {
        todo!()
    }

    fn is_no_bits(&self) -> bool {
        todo!()
    }

    fn flags(&self) -> <Self::Platform as platform::Platform>::SectionFlags {
        SectionFlags::default()
    }

    fn ty(&self) -> <Self::Platform as platform::Platform>::SectionType {
        SectionType::default()
    }

    fn set_to_default_type(&mut self) {
        todo!()
    }
}

#[derive(Debug)]
pub(crate) struct NonAddressableIndexes {}

impl platform::NonAddressableIndexes for NonAddressableIndexes {
    fn new<P: platform::Platform>(symbol_db: &crate::symbol_db::SymbolDb<P>) -> Self {
        Self {}
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SegmentType {}

impl platform::SegmentType for SegmentType {}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct ProgramSegmentDef {}

impl std::fmt::Display for ProgramSegmentDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WasmProgramSegment")
    }
}

impl platform::ProgramSegmentDef for ProgramSegmentDef {
    type Platform = Wasm;

    fn is_writable(self) -> bool {
        todo!()
    }

    fn is_executable(self) -> bool {
        todo!()
    }

    fn always_keep(self) -> bool {
        todo!()
    }

    fn is_loadable(self) -> bool {
        todo!()
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
        section_info: &crate::output_section_id::SectionOutputInfo<Self::Platform>,
        section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        todo!()
    }
}

pub(crate) struct BuiltInSectionDetails {}

impl platform::BuiltInSectionDetails for BuiltInSectionDetails {}

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
    type SymtabEntry = ();
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
    type SectionIterator<'data> = core::slice::Iter<'data, SectionHeader>;
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
        keep_sections: &mut crate::output_section_map::OutputSectionMap<bool>,
        args: &Self::Args,
    ) {
        todo!()
    }

    fn is_zero_sized_section_content(
        section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        todo!()
    }

    fn built_in_section_details() -> &'static [Self::BuiltInSectionDetails] {
        &[]
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
        &[]
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
        // TODO
        Vec::new()
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
        object: &Self::File<'data>,
        args: &Self::Args,
        sym: &Self::SymtabEntry,
        output_kind: crate::output_kind::OutputKind,
        export_list: Option<&crate::export_list::ExportList>,
        lib_name: &[u8],
        archive_semantics: bool,
        is_undefined: bool,
    ) -> bool {
        todo!()
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
        custom: &crate::output_section_id::CustomSectionIds,
        output_kind: crate::output_kind::OutputKind,
        output_sections: &crate::output_section_id::OutputSections<'data, Self>,
        secondary: &crate::output_section_map::OutputSectionMap<
            Vec<crate::output_section_id::OutputSectionId>,
        >,
    ) -> (
        crate::output_section_id::OutputOrder,
        crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
    ) {
        todo!()
    }

    fn default_symtab_entry() -> Self::SymtabEntry {}

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

    let mut sections: Vec<WasmSection<'data>> = Vec::new();
    let mut symbols: Vec<WasmSymbol<'data>> = Vec::new();
    let mut segments: Vec<WasmSegmentInfo<'data>> = Vec::new();
    let mut reloc_sections: Vec<WasmRelocSection> = Vec::new();
    let mut linking_version: Option<u32> = None;
    let mut target_features_raw: Option<&'data [u8]> = None;

    for payload in Parser::new(0).parse_all(input) {
        let payload = payload?;
        let Some((id, range)) = payload.as_section() else {
            continue;
        };

        let mut name = None;
        let payload_bytes: &'data [u8];

        match payload {
            Payload::CustomSection(reader) => {
                let section_name = reader.name();
                name = Some(section_name);
                payload_bytes = &input[range.clone()];

                if section_name == LINKING_SECTION_NAME {
                    if let KnownCustom::Linking(linking) = reader.as_known() {
                        linking_version = Some(linking.version());
                        parse_linking_subsections(&linking, &mut symbols, &mut segments)?;
                    }
                } else if section_name.starts_with(RELOC_SECTION_PREFIX) {
                    if let KnownCustom::Reloc(reloc) = reader.as_known() {
                        let target_section_index = reloc.section_index();
                        let mut entries = Vec::new();
                        for entry in reloc.entries() {
                            entries.push(entry?);
                        }
                        reloc_sections.push(WasmRelocSection {
                            target_section_index,
                            entries,
                        });
                    }
                } else if section_name == TARGET_FEATURES_SECTION_NAME {
                    target_features_raw = Some(reader.data());
                }
            }
            _ => {
                payload_bytes = &input[range.clone()];
            }
        }

        sections.push(WasmSection {
            id,
            name,
            range,
            payload: payload_bytes,
        });
    }

    Ok(File {
        data: input,
        version,
        sections,
        symbols,
        segments,
        reloc_sections,
        linking_version,
        target_features_raw,
    })
}

fn parse_linking_subsections<'data>(
    linking: &wasmparser::LinkingSectionReader<'data>,
    symbols: &mut Vec<WasmSymbol<'data>>,
    segments: &mut Vec<WasmSegmentInfo<'data>>,
) -> Result {
    for sub in linking.subsections() {
        let sub = sub?;
        match sub {
            Linking::SymbolTable(map) => {
                for sym in map {
                    symbols.push(WasmSymbol { info: sym? });
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
