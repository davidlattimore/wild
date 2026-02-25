use crate::Args;
use crate::OutputKind;
use crate::Result;
use crate::input_data::InputBytes;
use crate::input_data::InputRef;
use crate::layout;
use crate::layout::DynamicSymbolDefinition;
use crate::layout::Layout;
use crate::layout::ObjectLayoutState;
use crate::layout::OutputRecordLayout;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::part_id::PartId;
use crate::resolution::LoadedMetrics;
use crate::resolution::UnloadedSection;
use crate::symbol_db::SymbolDb;
use crate::value_flags::ValueFlags;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::relaxation::SectionRelaxDeltas;
use rayon::Scope;
use std::borrow::Cow;
use std::num::NonZeroU32;
use std::ops::Range;
use std::path::PathBuf;

/// Represents a supported object file format + architecture combination.
pub(crate) trait Platform<'data>: 'data {
    type Relaxation: Relaxation;
    type File: ObjectFile<'data>;

    // Get ELF header magic for the architecture.
    fn elf_header_arch_magic() -> u16;

    // Get dynamic relocation value specific for the architecture.
    fn get_dynamic_relocation_type(relocation: DynamicRelocationKind) -> u32;

    // Write PLT entry for the architecture.
    fn write_plt_entry(plt_entry: &mut [u8], got_address: u64, plt_address: u64) -> Result;

    // Make architecture-specific parsing of the relocation types.
    fn relocation_from_raw(r_type: u32) -> Result<RelocationKindInfo>;

    // Get string representation of a relocation specific for the architecture.
    fn rel_type_to_string(r_type: u32) -> Cow<'static, str>;

    // Get DTV OFFSET.
    fn get_dtv_offset() -> u64 {
        0
    }

    // Some architectures use debug info relocation that depend on local symbols.
    fn local_symbols_in_debug_info() -> bool;

    // Get position of the $tp (thread pointer) in the TLS section. Each platform defines
    // a different place based on the following article:
    // https://maskray.me/blog/2021-02-14-all-about-thread-local-storage#tls-variants
    fn tp_offset_start(layout: &Layout<'data>) -> u64;

    // Classify a GNU property note.
    fn get_property_class(property_type: u32) -> Option<crate::elf::PropertyClass>;

    // Merge e_flags of the input files and provide an error
    // if the flags are not compatible.
    fn merge_eflags(eflags: impl Iterator<Item = u32>) -> Result<u32>;

    // A list of high-part relocations that need to be tracked in a relocation cache
    fn high_part_relocations() -> &'static [u32];

    /// Whether the platform supports relaxations that reduce the sizes of function.
    fn supports_size_reduction_relaxations() -> bool {
        false
    }

    /// Uses debug info, if available, to get information about where in the source code a
    /// particular offset in a particular section came from.
    fn get_source_info(
        object: &Self::File,
        relocations: &<Self::File as ObjectFile<'data>>::RelocationSections,
        section: &<Self::File as ObjectFile<'data>>::SectionHeader,
        offset_in_section: u64,
    ) -> Result<SourceInfo>;

    fn collect_relaxation_deltas(
        _section_output_address: u64,
        _section_bytes: &[u8],
        // TODO: Change to be non-ELF specific.
        _relocations: crate::elf::RelocationList<'data>,
        _existing_deltas: Option<&SectionRelaxDeltas>,
        _resolve_symbol: impl FnMut(object::SymbolIndex) -> Option<RelaxSymbolInfo>,
    ) -> (Vec<(u64, u32)>, Option<u64>) {
        // This function should not be called unless `supports_size_reduction_relaxations` returns
        // true in which case this function should be implemented.
        unreachable!();
    }

    fn is_symbol_variant_pcs(_object: &Self::File, _symbol_index: object::SymbolIndex) -> bool {
        false
    }

    /// Tries to create a relaxation for the relocation of the specified kind, to be applied at the
    /// specified offset in the supplied section.
    fn new_relaxation(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        flags: ValueFlags,
        output_kind: OutputKind,
        section_flags: <<Self::File as ObjectFile<'data>>::SectionHeader as SectionHeader>::SectionFlags,
        non_zero_address: bool,
        relax_deltas: Option<&SectionRelaxDeltas>,
    ) -> Option<Self::Relaxation>;
}

pub(crate) trait Relaxation {
    fn apply(&self, section_bytes: &mut [u8], offset_in_section: &mut u64, addend: &mut i64);

    fn rel_info(&self) -> RelocationKindInfo;

    fn debug_kind(&self) -> impl std::fmt::Debug;

    fn next_modifier(&self) -> RelocationModifier;

    fn is_mandatory(&self) -> bool;
}

pub(crate) struct RelaxSymbolInfo {
    /// The symbol's approximate output address (section base + offset within section).
    pub output_address: u64,
    /// Whether the symbol may be interposed at runtime.
    pub is_interposable: bool,
}

/// Abstracts over the different object file formats that we support (or may support). e.g. ELF.
pub(crate) trait ObjectFile<'data>: Send + Sync + Sized + std::fmt::Debug + 'data {
    type Symbol: Symbol;
    type SectionHeader: SectionHeader;
    type SectionIterator: Iterator<Item = &'data Self::SectionHeader>;
    type DynamicTagValues: DynamicTagValues<'data>;
    type RelocationSections: std::fmt::Debug + Default + Send + Sync + 'static;
    type RelocationList: Send + Sync + 'data;
    type DynamicEntry: Send + Sync + 'data;
    type VerneedTable: VerneedTable<'data>;
    type EpilogueLayout: Send + Sync + 'static;
    type DynamicLayoutState: Default + Send + Sync + 'data;
    type DynamicLayout: std::fmt::Debug + Send + Sync + 'data;
    type NonAddressableIndexes: NonAddressableIndexes + Send + Sync + 'data;
    type NonAddressableCounts: Default + Send + Sync + 'data;
    type GroupLayoutExt: std::fmt::Debug + Send + Sync + 'static;
    type CommonGroupStateExt: Default + std::fmt::Debug + Send + Sync + 'static;

    /// An index into the local object's symbol versions.
    type SymbolVersionIndex: Copy;

    /// Format-specific per-file state used during the layout phase.
    type FileLayoutState: 'data;

    /// Format-specific properties produced by the layout phase.
    type LayoutProperties: 'static;

    /// The name of a symbol, possibly with a version.
    type RawSymbolName: RawSymbolName<'data>;

    /// For platforms that don't support symbol versioning, this can just be the unit type.
    type VersionNames;

    fn parse_bytes(input: &'data [u8], is_dynamic: bool) -> Result<Self>;

    /// As for `parse_bytes` but also validates that the file architecture matches what is expected
    /// based on `args`.
    fn parse(input: &InputBytes<'data>, args: &Args) -> Result<Self>;

    fn is_dynamic(&self) -> bool;

    fn num_symbols(&self) -> usize;

    fn symbols(&self) -> &'data [Self::Symbol];

    fn enumerate_symbols(
        &self,
    ) -> impl Iterator<Item = (object::SymbolIndex, &'data Self::Symbol)> {
        self.symbols()
            .iter()
            .enumerate()
            .map(|(i, sym)| (object::SymbolIndex(i), sym))
    }

    // TODO: Remove implementations of this as this default should be fine. Perhaps first check if
    // all platforms can get a slice of symbols.
    fn symbols_iter(&self) -> impl Iterator<Item = &'data Self::Symbol> {
        self.symbols().iter()
    }

    fn symbol(&self, index: object::SymbolIndex) -> Result<&'data Self::Symbol>;

    fn section_size(&self, header: &Self::SectionHeader) -> Result<u64>;

    fn symbol_name(&self, symbol: &Self::Symbol) -> Result<&'data [u8]>;

    fn num_sections(&self) -> usize;

    fn section_iter(&self) -> Self::SectionIterator;

    fn enumerate_sections(
        &self,
    ) -> impl Iterator<Item = (object::SectionIndex, &'data Self::SectionHeader)>;

    fn section(&self, index: object::SectionIndex) -> Result<&'data Self::SectionHeader>;

    fn section_by_name(
        &self,
        name: &str,
    ) -> Option<(object::SectionIndex, &'data Self::SectionHeader)>;

    fn symbol_section(
        &self,
        symbol: &Self::Symbol,
        index: object::SymbolIndex,
    ) -> Result<Option<object::SectionIndex>>;

    fn symbol_versions(&self) -> &[Self::SymbolVersionIndex];

    /// The dynamic object will be linked against. This is a chance to perform extra initialisation
    /// of `state`.
    fn activate_dynamic(&self, state: &mut Self::DynamicLayoutState);

    fn dynamic_symbol_used(
        &self,
        symbol_index: object::SymbolIndex,
        state: &mut Self::DynamicLayoutState,
    ) -> Result;

    fn finalise_sizes_dynamic(
        &self,
        lib_name: &[u8],
        state: &mut Self::DynamicLayoutState,
        mem_sizes: &mut OutputSectionPartMap<u64>,
    ) -> Result;

    fn apply_non_addressable_indexes_dynamic(
        &self,
        indexes: &mut Self::NonAddressableIndexes,
        counts: &mut Self::NonAddressableCounts,
        state: &mut Self::DynamicLayoutState,
    ) -> Result;

    fn finalise_layout_dynamic(
        &self,
        state: Self::DynamicLayoutState,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
    ) -> Self::DynamicLayout;

    fn apply_non_addressable_indexes_epilogue(
        counts: &mut Self::NonAddressableCounts,
        state: &mut Self::EpilogueLayout,
    );

    fn apply_non_addressable_indexes<'groups>(
        symbol_db: &SymbolDb<'data, Self>,
        counts: &Self::NonAddressableCounts,
        mem_sizes_iter: impl Iterator<Item = &'groups mut OutputSectionPartMap<u64>>,
    );

    fn finalise_sizes_epilogue(
        state: &mut Self::EpilogueLayout,
        mem_sizes: &mut OutputSectionPartMap<u64>,
        properties: &Self::LayoutProperties,
        symbol_db: &SymbolDb<'data, Self>,
    );

    fn finalise_sizes_all(
        mem_sizes: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<'data, Self>,
    );

    fn apply_late_size_adjustments_epilogue(
        state: &mut crate::elf::EpilogueLayout,
        current_sizes: &OutputSectionPartMap<u64>,
        extra_sizes: &mut OutputSectionPartMap<u64>,
        dynamic_symbol_defs: &[DynamicSymbolDefinition],
    ) -> Result;

    fn finalise_layout_epilogue(
        epilogue_state: &mut Self::EpilogueLayout,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<'data, Self>,
        common_state: &crate::elf::ElfLayoutProperties,
        dynsym_start_index: u32,
        dynamic_symbol_defs: &[DynamicSymbolDefinition],
    ) -> Result;

    fn dynamic_tags(&self) -> Result<&'data [Self::DynamicEntry]>;

    fn section_name(&self, section_header: &Self::SectionHeader) -> Result<&'data [u8]>;

    /// Returns the raw section data. Doesn't handle decompression.
    fn raw_section_data(&self, section: &Self::SectionHeader) -> Result<&'data [u8]>;

    fn section_data(
        &self,
        section: &Self::SectionHeader,
        member: &bumpalo_herd::Member<'data>,
        loaded_metrics: &LoadedMetrics,
    ) -> Result<&'data [u8]>;

    /// Copies the data for the specified section into `out`, which must be the correct size.
    /// Decompresses the data if necessary.
    fn copy_section_data(&self, section: &Self::SectionHeader, out: &mut [u8]) -> Result;

    /// Returns the contents of a section as a Cow. Will heap-allocate if the section is compressed.
    fn section_data_cow(&self, section: &Self::SectionHeader) -> Result<Cow<'data, [u8]>>;

    fn section_alignment(&self, section: &Self::SectionHeader) -> Result<u64>;

    fn relocations(
        &self,
        index: object::SectionIndex,
        relocations: &Self::RelocationSections,
    ) -> Result<Self::RelocationList>;

    fn parse_relocations(&self) -> Result<Self::RelocationSections>;

    /// Get the version of a symbol. Only intended for diagnostic purposes since it's potentially
    /// quite slow.
    fn symbol_version_debug(&self, symbol_index: object::SymbolIndex) -> Option<String>;

    fn section_display_name(&self, index: object::SectionIndex) -> Cow<'data, str>;

    fn dynamic_tag_values(&self) -> Option<Self::DynamicTagValues>;

    fn get_version_names(&self) -> Result<Self::VersionNames>;

    fn get_symbol_name_and_version(
        &self,
        symbol: &Self::Symbol,
        local_index: usize,
        version_names: &Self::VersionNames,
    ) -> Result<Self::RawSymbolName>;

    fn verneed_table(&self) -> Result<Self::VerneedTable>;

    fn process_gnu_note_section(
        &self,
        state: &mut Self::FileLayoutState,
        section_index: object::SectionIndex,
    ) -> Result;

    fn create_layout_properties<'states, 'files, P: Platform<'data, File = Self>>(
        args: &Args,
        objects: impl Iterator<Item = &'files Self>,
        states: impl Iterator<Item = &'states Self::FileLayoutState> + Clone,
    ) -> Result<Self::LayoutProperties>
    where
        'data: 'files,
        'data: 'states;

    fn load_exception_frame_data<'scope, P: Platform<'data, File = Self>>(
        object: &mut ObjectLayoutState<'data>,
        common: &mut layout::CommonGroupState<'data>,
        eh_frame_section_index: object::SectionIndex,
        resources: &'scope layout::GraphResources<'data, '_>,
        queue: &mut layout::LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result;

    /// Called when a section is loaded (not GCed). Implementations should process any exception
    /// frame data related to the loaded section.
    fn non_empty_section_loaded<'scope, P: Platform<'data, File = Self>>(
        object: &mut layout::ObjectLayoutState<'data>,
        common: &mut layout::CommonGroupState<'data>,
        queue: &mut layout::LocalWorkQueue,
        unloaded: UnloadedSection,
        resources: &'scope layout::GraphResources<'data, 'scope>,
        scope: &Scope<'scope>,
    ) -> Result;

    fn finalise_group_layout(memory_offsets: &OutputSectionPartMap<u64>) -> Self::GroupLayoutExt;

    /// Called after GC phase has completed. Mostly useful for platform-specific logging.
    fn finalise_find_required_sections(groups: &[layout::GroupState]);

    fn pre_finalise_sizes_prelude(common: &mut layout::CommonGroupState, args: &Args);

    fn finalise_object_sizes(
        object: &mut layout::ObjectLayoutState<'data>,
        common: &mut layout::CommonGroupState,
    );

    fn finalise_object_layout(
        object: &layout::ObjectLayoutState<'data>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
    );

    fn compute_object_addresses(
        object: &layout::ObjectLayoutState<'data>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
    );

    /// Resolves a reference to the frame data section.
    fn frame_data_base_address(memory_offsets: &OutputSectionPartMap<u64>) -> u64;
}

pub(crate) trait SectionHeader: std::fmt::Debug + Send + Sync + 'static {
    type SectionFlags: SectionFlags;
    type SectionType: SectionType;
    type Attributes: SectionAttributes;

    fn flags(&self) -> Self::SectionFlags;

    fn attributes(&self) -> Self::Attributes;

    fn section_type(&self) -> Self::SectionType;
}

pub(crate) trait SectionType: Copy {
    fn is_note(self) -> bool;

    fn is_prog_bits(self) -> bool;

    /// Returns whether the section has no contents in the file (zero initialised).
    fn is_no_bits(self) -> bool;
}

pub(crate) trait SectionFlags: Copy + std::fmt::Debug + Send + Sync + 'static {
    fn is_alloc(self) -> bool;

    fn is_writable(self) -> bool;

    fn is_executable(self) -> bool;

    fn is_tls(self) -> bool;

    fn is_merge_section(self) -> bool;

    fn is_strings(self) -> bool;

    fn should_retain(self) -> bool;

    fn should_exclude(&self) -> bool;

    fn is_group(self) -> bool;
}

pub(crate) trait Symbol: std::fmt::Debug + Send + Sync + 'static {
    /// Returns information about the symbol if it's a common symbol. Platforms that don't have
    /// common symbols can just return None.
    fn as_common(&self) -> Option<CommonSymbol>;

    fn is_common(&self) -> bool {
        self.as_common().is_some()
    }

    fn is_undefined(&self) -> bool;

    fn is_local(&self) -> bool;

    fn is_absolute(&self) -> bool;

    fn is_weak(&self) -> bool;

    fn visibility(&self) -> crate::symbol_db::Visibility;

    fn value(&self) -> u64;

    fn size(&self) -> u64;

    fn section_index(&self) -> object::SectionIndex;

    fn has_name(&self) -> bool;

    fn debug_string(&self) -> String;

    /// Returns whether this symbol has been declared as a TLS variable.
    fn is_tls(&self) -> bool;

    /// Returns whether this symbol can be interposed (overridden) at runtime by DSOs earlier in the
    /// load order.
    fn is_interposable(&self) -> bool;

    fn is_func(&self) -> bool;

    fn is_ifunc(&self) -> bool;

    fn is_hidden(&self) -> bool;

    fn is_gnu_unique(&self) -> bool;
}

#[derive(Clone, Copy)]
pub(crate) struct CommonSymbol {
    pub(crate) size: u64,
    pub(crate) part_id: PartId,
}

pub(crate) trait Relocation: Send + Sync + Copy + 'static {
    type Sequence<'data>: RelocationSequence<'data>;

    fn symbol(&self) -> Option<object::SymbolIndex>;

    fn raw_type(&self) -> u32;

    fn offset(&self) -> u64;

    fn addend(&self) -> i64;
}

pub(crate) trait RelocationSequence<'data> {
    type Rel: Relocation;

    fn rel_iter(&self) -> impl Iterator<Item = Self::Rel>;
    fn subsequence(&self, range: Range<usize>) -> Self;
    fn num_relocations(&self) -> usize;
}

pub(crate) trait RawSymbolName<'data>: Send + Sync + 'data {
    fn parse(bytes: &'data [u8]) -> Self;

    fn name(&self) -> &'data [u8];

    fn version_name(&self) -> Option<&'data [u8]>;

    fn is_default(&self) -> bool;
}

pub(crate) trait VerneedTable<'data>: Send + Sync + 'data {
    fn version_name(&self, local_symbol_index: object::SymbolIndex) -> Option<&'data [u8]>;
}

pub(crate) trait DynamicTagValues<'data>: std::fmt::Debug + Send + Sync + 'data {
    fn lib_name(&self, input: &InputRef<'data>) -> &'data [u8];
}

pub(crate) trait NonAddressableIndexes {
    fn new<'data, O: ObjectFile<'data>>(symbol_db: &SymbolDb<'data, O>) -> Self;
}

pub(crate) trait SectionAttributes: std::fmt::Debug + Send + Sync + 'static {
    fn merge(&mut self, rhs: Self);

    fn apply(&self, output_sections: &mut OutputSections, section_id: OutputSectionId);
}

pub(crate) struct SourceInfo(pub(crate) Option<SourceInfoDetails>);

#[derive(Debug)]
pub(crate) struct SourceInfoDetails {
    pub(crate) path: PathBuf,
    pub(crate) line: u64,
}

/// An index into the exception frames for an object. Interpretation of the value is up to the
/// platform.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FrameIndex(NonZeroU32);

impl FrameIndex {
    pub(crate) fn from_usize(raw: usize) -> Self {
        Self(NonZeroU32::new(raw as u32 + 1).unwrap())
    }

    pub(crate) fn as_usize(self) -> usize {
        self.0.get() as usize - 1
    }
}
