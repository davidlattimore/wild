use crate::OutputKind;
use crate::Result;
use crate::alignment::Alignment;
use crate::args::DefsymValue;
use crate::bail;
use crate::error::Warning;
use crate::grouping::Group;
use crate::input_data::FileLoader;
use crate::input_data::InputBytes;
use crate::input_data::InputRef;
use crate::layout;
use crate::layout::CommonGroupState;
use crate::layout::DynamicSymbolDefinition;
use crate::layout::Layout;
use crate::layout::ObjectLayoutState;
use crate::layout::OutputRecordLayout;
use crate::layout::PreludeLayoutState;
use crate::layout_rules;
use crate::layout_rules::LayoutRulesBuilder;
use crate::layout_rules::SectionRule;
use crate::layout_rules::SectionRuleOutcome;
use crate::linker_plugins::LinkerPlugin;
use crate::output_section_id::CustomSectionIds;
use crate::output_section_id::OutputOrder;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_id::SectionName;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::parsing::InternalSymDefInfo;
use crate::part_id::PartId;
use crate::program_segments::ProgramSegments;
use crate::resolution::LoadedMetrics;
use crate::resolution::Resolver;
use crate::resolution::UnloadedSection;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::value_flags::AtomicPerSymbolFlags;
use crate::value_flags::PerSymbolFlags;
use crate::value_flags::ValueFlags;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::relaxation::SectionRelaxDeltas;
use rayon::Scope;
use std::borrow::Cow;
use std::fmt::Display;
use std::num::NonZeroU32;
use std::num::NonZeroU64;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

/// Represents a supported architecture. Note that implementations are file-format specific.
pub(crate) trait Arch: Send + Sync + 'static {
    type Relaxation: Relaxation;
    type Platform: Platform;

    /// Returns the identifier to be written into the output file that identifies the file as
    /// belonging to this architecture. e.g. for ELF, this is the header magic for the architecture.
    fn arch_identifier() -> <Self::Platform as Platform>::ArchIdentifier;

    /// Get dynamic relocation value specific for the architecture.
    fn get_dynamic_relocation_type(relocation: DynamicRelocationKind) -> u32;

    /// Write PLT entry for the architecture.
    fn write_plt_entry(plt_entry: &mut [u8], got_address: u64, plt_address: u64) -> Result;

    /// Make architecture-specific parsing of the relocation types.
    fn relocation_from_raw(r_type: u32) -> Result<RelocationKindInfo>;

    /// Get string representation of a relocation specific for the architecture.
    fn rel_type_to_string(r_type: u32) -> Cow<'static, str>;

    /// Get DTV OFFSET.
    fn get_dtv_offset() -> u64 {
        0
    }

    /// Some architectures use debug info relocation that depend on local symbols.
    fn local_symbols_in_debug_info() -> bool;

    /// Get position of the $tp (thread pointer) in the TLS section. Each platform defines
    /// a different place based on the following article:
    /// https://maskray.me/blog/2021-02-14-all-about-thread-local-storage#tls-variants
    fn tp_offset_start(layout: &Layout<Self::Platform>) -> u64;

    /// Classify a GNU property note.
    fn get_property_class(property_type: u32) -> Option<crate::elf::PropertyClass>;

    /// Merge e_flags of the input files and provide an error
    /// if the flags are not compatible.
    fn merge_eflags(eflags: impl Iterator<Item = u32>) -> Result<u32>;

    /// A list of high-part relocations that need to be tracked in a relocation cache
    fn high_part_relocations() -> &'static [u32];

    /// Whether the platform supports relaxations that reduce the sizes of function.
    fn supports_size_reduction_relaxations() -> bool {
        false
    }

    /// Uses debug info, if available, to get information about where in the source code a
    /// particular offset in a particular section came from.
    fn get_source_info<'data>(
        object: &<Self::Platform as Platform>::File<'data>,
        relocations: &<Self::Platform as Platform>::RelocationSections,
        section: &<Self::Platform as Platform>::SectionHeader,
        offset_in_section: u64,
    ) -> Result<SourceInfo>;

    fn collect_relaxation_deltas<'data>(
        _section_output_address: u64,
        _section_bytes: &[u8],
        _relocations: <Self::Platform as Platform>::RelocationList<'data>,
        _existing_deltas: Option<&SectionRelaxDeltas>,
        _resolve_symbol: impl FnMut(object::SymbolIndex) -> Option<RelaxSymbolInfo>,
    ) -> (Vec<(u64, u32)>, Option<u64>) {
        // This function should not be called unless `supports_size_reduction_relaxations` returns
        // true in which case this function should be implemented.
        unreachable!();
    }

    fn is_symbol_variant_pcs(
        _object: &<Self::Platform as Platform>::File<'_>,
        _symbol_index: object::SymbolIndex,
    ) -> bool {
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
        section_flags: <Self::Platform as Platform>::SectionFlags,
        non_zero_address: bool,
        relax_deltas: Option<&SectionRelaxDeltas>,
    ) -> Option<Self::Relaxation>;

    /// Fill `len` bytes of NOP padding at `offset` in `buf`.
    fn fill_nop_padding(_buf: &mut [u8], _offset: usize, _len: usize) {}

    fn process_riscv_attributes<'data>(
        _object: &<Self::Platform as Platform>::File<'data>,
        _format_specific: &mut <Self::Platform as Platform>::ObjectLayoutStateExt<'data>,
        _riscv_attributes_section_index: object::SectionIndex,
    ) -> Result {
        bail!(".riscv.attribute section is supported only for riscv64 target");
    }
}

pub(crate) trait Relaxation: Send + Sync + 'static {
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

/// A platform for which we support writing producing linked outputs.
pub(crate) trait Platform: Copy + Send + Sync + Sized + std::fmt::Debug + 'static {
    type File<'data>: ObjectFile<'data, Platform = Self>;
    type SymtabEntry: Symbol;
    type SectionHeader: SectionHeader;
    type SectionFlags: SectionFlags;
    type SectionAttributes: SectionAttributes<Platform = Self>;
    type SectionType: SectionType;
    type SegmentType: SegmentType;
    type ProgramSegmentDef: ProgramSegmentDef<Platform = Self>;
    type BuiltInSectionDetails: BuiltInSectionDetails;
    type RelocationSections: std::fmt::Debug + Default + Send + Sync + 'static;
    type DynamicEntry: Send + Sync + 'static;
    type DynamicSymbolDefinitionExt: Copy + Send + Sync + std::fmt::Debug + 'static;
    type NonAddressableIndexes: NonAddressableIndexes + Send + Sync + 'static;
    type NonAddressableCounts: Default + Send + Sync + 'static;
    type EpilogueLayoutExt: Send + Sync + 'static;
    type GroupLayoutExt: std::fmt::Debug + Send + Sync + 'static;
    type CommonGroupStateExt: Default + std::fmt::Debug + Send + Sync + 'static;
    type ArchIdentifier: Send + Sync + 'static;
    type Args: Args;
    type ResolutionExt: Default + std::fmt::Debug + Copy + Send + Sync + 'static;

    /// An index into the local object's symbol versions.
    type SymbolVersionIndex: Send + Sync + Copy;

    /// Format-specific properties produced by the layout phase.
    type LayoutExt: Send + Sync + 'static;

    type SectionIterator<'data>: Iterator<Item = &'data Self::SectionHeader>;
    type DynamicTagValues<'data>: DynamicTagValues<'data>;
    type RelocationList<'data>: RelocationList<'data>;
    type DynamicLayoutStateExt<'data>: Default + Send + Sync + 'data;
    type DynamicLayoutExt<'data>: std::fmt::Debug + Send + Sync + 'data;
    type LayoutResourcesExt<'data>: std::fmt::Debug + Send + Sync + 'data;
    type PreludeLayoutStateExt: std::fmt::Debug + Default + Send + Sync + 'static;
    type PreludeLayoutExt: std::fmt::Debug + Default + Send + Sync + 'static;

    /// Format-specific per-file state used during the layout phase.
    type ObjectLayoutStateExt<'data>: Default + Send + Sync + 'data;

    /// The name of a symbol, possibly with a version.
    type RawSymbolName<'data>: RawSymbolName<'data>;

    /// For platforms that don't support symbol versioning, this can just be the unit type.
    type VersionNames<'data>;

    /// For platforms that don't support symbol versioning, this can just be the unit type.
    type VerneedTable<'data>: VerneedTable<'data>;

    /// Invoke the linker for requested architecture.
    fn link_for_arch<'data>(
        linker: &'data crate::Linker,
        args: &'data Self::Args,
    ) -> Result<crate::LinkerOutput<'data>>;

    fn write_output_file<'data, A: Arch<Platform = Self>>(
        output: &crate::file_writer::Output,
        layout: &Layout<'data, Self>,
    ) -> Result;

    /// Possibly initialise a linker plugin if the platform supports it and the arguments specifies
    /// that one should be used.
    fn maybe_init_linker_plugin<'data>(
        _args: &'data Self::Args,
        _linker_plugin_arena: &'data colosseum::sync::Arena<crate::linker_plugins::LoadedPlugin>,
        _herd: &'data bumpalo_herd::Herd,
    ) -> Result<Option<crate::linker_plugins::LinkerPlugin<'data>>> {
        Ok(None)
    }

    /// Called once all symbols have been read, but only if a linker plugin is active.
    fn plugin_all_symbols_read<'data>(
        _plugin: &mut LinkerPlugin<'data>,
        _symbol_db: &mut SymbolDb<'data, Self>,
        _resolver: &mut Resolver<'data, Self>,
        _file_loader: &mut FileLoader<'data>,
        _per_symbol_flags: &mut PerSymbolFlags,
        _output_sections: &mut OutputSections<'data, Self>,
        _layout_rules_builder: &mut LayoutRulesBuilder<'data>,
    ) -> Result {
        // Platforms that implement maybe_init_linker_plugin must implement this method too.
        unimplemented!();
    }

    #[allow(dead_code)]
    fn resolve_lto_symbols<'data, 'scope>(
        _obj: &crate::linker_plugins::LtoInput<'data>,
        _resources: &'scope crate::resolution::ResolutionResources<'data, 'scope, Self>,
        _definitions_out: &mut [SymbolId],
        _scope: &Scope<'scope>,
    ) -> Result {
        Ok(())
    }

    /// Returns attributes of the supplied section. This is type+flags and doesn't include other
    /// information like name, size etc.
    fn section_attributes(header: &Self::SectionHeader) -> Self::SectionAttributes;

    /// Validate that the supplied sizes are internally consistent.
    fn validate_sizes(_mem_sizes: &OutputSectionPartMap<u64>) -> Result {
        Ok(())
    }

    /// Implementations can force certain sections to be kept. Only needs to be done for sections
    /// that need to be emitted even if empty.
    fn apply_force_keep_sections(keep_sections: &mut OutputSectionMap<bool>, args: &Self::Args);

    /// Returns whether an input section with zero size destined for the specified output section
    /// should be considered content and thus prevent the output section from being discarded.
    fn is_zero_sized_section_content(section_id: OutputSectionId) -> bool;

    fn built_in_section_details() -> &'static [Self::BuiltInSectionDetails];

    fn finalise_group_layout(memory_offsets: &OutputSectionPartMap<u64>) -> Self::GroupLayoutExt;

    /// Resolves a reference to the frame data section.
    fn frame_data_base_address(memory_offsets: &OutputSectionPartMap<u64>) -> u64;

    /// Called after GC phase has completed. Mostly useful for platform-specific logging.
    fn finalise_find_required_sections(groups: &[layout::GroupState<Self>]);

    /// The dynamic object will be linked against. This is a chance to perform extra initialisation
    /// of `state`.
    fn activate_dynamic<'data>(
        state: &mut layout::DynamicLayoutState<'data, Self>,
        common: &mut CommonGroupState<'data, Self>,
    );

    fn pre_finalise_sizes_prelude<'scope, 'data>(
        prelude: &mut layout::PreludeLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
        resources: &layout::GraphResources<'data, 'scope, Self>,
    );

    fn finalise_sizes_dynamic<'data>(
        object: &mut layout::DynamicLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
    ) -> Result;

    fn finalise_object_sizes<'data>(
        object: &mut layout::ObjectLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
    );

    fn finalise_object_layout<'data>(
        object: &layout::ObjectLayoutState<'data, Self>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
    );

    fn finalise_layout_dynamic<'data>(
        state: &mut layout::DynamicLayoutState<'data, Self>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resources: &layout::FinaliseLayoutResources<'_, 'data, Self>,
        resolutions_out: &mut layout::ResolutionWriter<Self>,
    ) -> Result<Self::DynamicLayoutExt<'data>>;

    /// Returns the next dynamic symbol index, bumping `memory_offsets` to point to the subsequent
    /// one.
    fn take_dynsym_index(
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
    ) -> Result<u32>;

    fn compute_object_addresses<'data>(
        object: &layout::ObjectLayoutState<'data, Self>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
    );

    fn layout_resources_ext<'data>(
        groups: &[Group<'data, Self>],
    ) -> Self::LayoutResourcesExt<'data>;

    /// Calls `load_section_relocations` on `state` for the relocations in `section`.
    fn load_object_section_relocations<'data, 'scope, A: Arch<Platform = Self>>(
        state: &layout::ObjectLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
        queue: &mut layout::LocalWorkQueue,
        resources: &'scope layout::GraphResources<'data, '_, Self>,
        section: layout::Section,
        scope: &Scope<'scope>,
    ) -> Result;

    /// Calls `load_debug_relocations` on `state` for the relocations in `section`.
    fn load_object_debug_relocations<'data, 'scope, A: Arch<Platform = Self>>(
        state: &layout::ObjectLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
        queue: &mut layout::LocalWorkQueue,
        resources: &'scope layout::GraphResources<'data, '_, Self>,
        section: layout::Section,
        scope: &Scope<'scope>,
    ) -> Result;

    fn create_dynamic_symbol_definition<'data>(
        symbol_db: &SymbolDb<'data, Self>,
        symbol_id: SymbolId,
    ) -> Result<layout::DynamicSymbolDefinition<'data, Self>>;

    fn validate_section<'data>(
        _section_info: &crate::output_section_id::SectionOutputInfo<Self>,
        _section_flags: Self::SectionFlags,
        _section_layout: &OutputRecordLayout,
        _merge_target: OutputSectionId,
        _output_sections: &OutputSections<'data, Self>,
        _section_id: OutputSectionId,
    ) -> Result {
        Ok(())
    }

    /// Called when we detect an internal error with allocation in order to try and help determine
    /// what we did wrong. Can optionally return a more helpful error.
    fn verify_resolution_allocation(
        _output_sections: &OutputSections<Self>,
        _output_order: &OutputOrder,
        _output_kind: OutputKind,
        _mem_sizes: &OutputSectionPartMap<u64>,
        _resolution: &layout::Resolution<Self>,
    ) -> Result {
        Ok(())
    }

    /// Updates the list of segments to keep.
    fn update_segment_keep_list(
        program_segments: &ProgramSegments<Self::ProgramSegmentDef>,
        keep_segments: &mut [bool],
        args: &Self::Args,
    );

    fn program_segment_defs() -> &'static [Self::ProgramSegmentDef];

    /// Returns segment definitions that should be unconditionally emitted without content.
    fn unconditional_segment_defs() -> &'static [Self::ProgramSegmentDef];

    fn create_linker_defined_symbols(
        symbols: &mut crate::parsing::InternalSymbolsBuilder,
        output_kind: OutputKind,
        args: &Self::Args,
    );

    fn built_in_section_infos<'data>()
    -> Vec<crate::output_section_id::SectionOutputInfo<'data, Self>>;

    fn create_layout_properties<'data, 'states, 'files, A: Arch<Platform = Self>>(
        args: &Self::Args,
        objects: impl Iterator<Item = &'files Self::File<'data>>,
        states: impl Iterator<Item = &'states Self::ObjectLayoutStateExt<'data>> + Clone,
    ) -> Result<Self::LayoutExt>
    where
        'data: 'files,
        'data: 'states;

    fn load_exception_frame_data<'data, 'scope, A: Arch<Platform = Self>>(
        object: &mut ObjectLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
        eh_frame_section_index: object::SectionIndex,
        resources: &'scope layout::GraphResources<'data, '_, Self>,
        queue: &mut layout::LocalWorkQueue,
        scope: &Scope<'scope>,
    ) -> Result;

    /// Called when a section is loaded (not GCed). Implementations should process any exception
    /// frame data related to the loaded section.
    fn non_empty_section_loaded<'data, 'scope, A: Arch<Platform = Self>>(
        object: &mut layout::ObjectLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
        queue: &mut layout::LocalWorkQueue,
        unloaded: UnloadedSection,
        resources: &'scope layout::GraphResources<'data, 'scope, Self>,
        scope: &Scope<'scope>,
    ) -> Result;

    fn new_epilogue_layout(
        args: &Self::Args,
        output_kind: OutputKind,
        dynamic_symbol_definitions: &mut [DynamicSymbolDefinition<'_, Self>],
    ) -> Self::EpilogueLayoutExt;

    fn apply_non_addressable_indexes_epilogue(
        counts: &mut Self::NonAddressableCounts,
        state: &mut Self::EpilogueLayoutExt,
    );

    fn apply_non_addressable_indexes<'data, 'groups>(
        symbol_db: &SymbolDb<'data, Self>,
        counts: &mut Self::NonAddressableCounts,
        indexes: &Self::NonAddressableIndexes,
        mem_sizes_iter: impl Iterator<Item = &'groups mut OutputSectionPartMap<u64>>,
    );

    fn finalise_sizes_epilogue<'data>(
        state: &mut Self::EpilogueLayoutExt,
        mem_sizes: &mut OutputSectionPartMap<u64>,
        dynamic_symbol_definitions: &[DynamicSymbolDefinition<'data, Self>],
        properties: &Self::LayoutExt,
        symbol_db: &SymbolDb<'data, Self>,
    );

    fn finalise_sizes_all<'data>(
        mem_sizes: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<'data, Self>,
    );

    fn apply_late_size_adjustments_epilogue(
        state: &mut Self::EpilogueLayoutExt,
        current_sizes: &OutputSectionPartMap<u64>,
        extra_sizes: &mut OutputSectionPartMap<u64>,
        dynamic_symbol_defs: &[DynamicSymbolDefinition<Self>],
        args: &Self::Args,
    ) -> Result;

    fn finalise_layout_epilogue<'data>(
        epilogue_state: &mut Self::EpilogueLayoutExt,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<'data, Self>,
        common_state: &Self::LayoutExt,
        dynsym_start_index: u32,
        dynamic_symbol_defs: &[DynamicSymbolDefinition<Self>],
    ) -> Result;

    fn is_symbol_non_interposable<'data>(
        object: &Self::File<'data>,
        args: &Self::Args,
        sym: &Self::SymtabEntry,
        output_kind: OutputKind,
        export_list: Option<&crate::export_list::ExportList>,
        lib_name: &[u8],
        archive_semantics: bool,
        is_undefined: bool,
    ) -> bool;

    /// Given the name of an init/fini section, returns the sort priority, if any.
    fn init_section_priority(_name: &[u8]) -> Option<u16> {
        None
    }

    /// Verifies that it's OK to load a section with the given name. Mostly just used to detect
    /// linker plugin inputs, since we shouldn't be loading those.
    fn verify_allowed_input_section_name(_name: &[u8]) -> Result {
        Ok(())
    }

    /// Allocate space for headers based on segment and section counts.
    fn allocate_header_sizes(
        prelude: &mut PreludeLayoutState<Self>,
        sizes: &mut OutputSectionPartMap<u64>,
        header_info: &layout::HeaderInfo,
        output_sections: &OutputSections<Self>,
    );

    /// Gives the platform an opportunity to error out if an input stack section is requesting an
    /// executable stack, but that's not permitted due to flags.
    fn validate_stack_section(
        _section: &Self::SectionHeader,
        _object: &impl std::fmt::Display,
        _args: &Self::Args,
    ) -> Result {
        Ok(())
    }

    fn finalise_sizes_for_symbol<'data>(
        common: &mut CommonGroupState<'data, Self>,
        symbol_db: &SymbolDb<'data, Self>,
        symbol_id: SymbolId,
        flags: ValueFlags,
    ) -> Result;

    fn allocate_resolution<'data>(
        flags: ValueFlags,
        mem_sizes: &mut OutputSectionPartMap<u64>,
        output_kind: OutputKind,
    );

    fn allocate_object_symtab_space<'data>(
        state: &ObjectLayoutState<'data, Self>,
        common: &mut CommonGroupState<'data, Self>,
        symbol_db: &SymbolDb<'data, Self>,
        per_symbol_flags: &AtomicPerSymbolFlags,
    );

    fn allocate_internal_symbol(
        symbol_id: SymbolId,
        def_info: &InternalSymDefInfo,
        sizes: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<Self>,
    ) -> Result;

    fn allocate_prelude(common: &mut CommonGroupState<Self>, symbol_db: &SymbolDb<Self>);

    fn finalise_prelude_layout<'data>(
        prelude: &layout::PreludeLayoutState<Self>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resources: &layout::FinaliseLayoutResources<'_, 'data, Self>,
    ) -> Result<Self::PreludeLayoutExt>;

    fn create_resolution(
        flags: ValueFlags,
        raw_value: u64,
        dynamic_symbol_index: Option<NonZeroU32>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
    ) -> layout::Resolution<Self>;

    fn validate_resolution(
        _name: &[u8],
        _resolution: &crate::layout::Resolution<Self>,
        _got: &Self::SectionHeader,
        _got_data: &[u8],
    ) -> Result {
        Ok(())
    }

    fn raw_symbol_name<'data>(
        name_bytes: &'data [u8],
        verneed_table: &Self::VerneedTable<'data>,
        symbol_index: object::SymbolIndex,
    ) -> Self::RawSymbolName<'data>;

    fn parse_raw_symbol_name<'data>(name_bytes: &'data [u8]) -> Self::RawSymbolName<'data> {
        <Self::RawSymbolName<'data> as RawSymbolName>::parse(name_bytes)
    }

    fn default_layout_rules() -> &'static [SectionRule<'static>];

    /// Only called if a linker script that provides custom sections and layout rules is present.
    /// Gives the platform a chance to add extra built-in rules that need to be present even when a
    /// linker script is providing most of the rules.
    fn linker_script_rules_pre_build(_rule_builder: &mut layout_rules::LayoutRulesBuilder) {}

    fn copy_relocate_symbol<'scope, 'data>(
        _state: &mut layout::DynamicLayoutState<Self>,
        _symbol_id: SymbolId,
        _resources: &layout::GraphResources<'data, 'scope, Self>,
    ) -> Result {
        bail!("Platform does not support copy relocations");
    }

    fn finalise_copy_relocations<'data>(
        _group_states: &mut [layout::GroupState<'data, Self>],
        _symbol_db: &SymbolDb<'data, Self>,
        _symbol_flags: &AtomicPerSymbolFlags,
    ) -> Result {
        Ok(())
    }

    fn build_output_order_and_program_segments<'data>(
        custom: &CustomSectionIds,
        output_kind: OutputKind,
        output_sections: &OutputSections<'data, Self>,
        secondary: &OutputSectionMap<Vec<OutputSectionId>>,
    ) -> (OutputOrder, ProgramSegments<Self::ProgramSegmentDef>);

    fn will_emit_section_symbol_for_partial_objects(
        _output_sections: &OutputSections<Self>,
        _section_id: OutputSectionId,
    ) -> bool {
        false
    }

    fn lookup_for_partial_link(
        _section_name: &[u8],
        _section: &Self::SectionHeader,
    ) -> SectionRuleOutcome {
        SectionRuleOutcome::Custom
    }
}

/// Abstracts over the different object file formats that we support (or may support). e.g. ELF.
pub(crate) trait ObjectFile<'data>: Sized + Send + Sync + std::fmt::Debug + 'data {
    type Platform: Platform<File<'data> = Self>;

    fn parse_bytes(input: &'data [u8], is_dynamic: bool) -> Result<Self>;

    /// As for `parse_bytes` but also validates that the file architecture matches what is expected
    /// based on `args`.
    fn parse(input: &InputBytes<'data>, args: &<Self::Platform as Platform>::Args) -> Result<Self>;

    fn is_dynamic(&self) -> bool;

    fn num_symbols(&self) -> usize;

    fn enumerate_symbols(
        &self,
    ) -> impl Iterator<
        Item = (
            object::SymbolIndex,
            &'data <Self::Platform as Platform>::SymtabEntry,
        ),
    > {
        self.symbols_iter()
            .enumerate()
            .map(|(i, sym)| (object::SymbolIndex(i), sym))
    }

    fn symbols_iter(
        &self,
    ) -> impl Iterator<Item = &'data <Self::Platform as Platform>::SymtabEntry>;

    fn symbol(
        &self,
        index: object::SymbolIndex,
    ) -> Result<&'data <Self::Platform as Platform>::SymtabEntry>;

    fn section_size(&self, header: &<Self::Platform as Platform>::SectionHeader) -> Result<u64>;

    fn symbol_name(
        &self,
        symbol: &<Self::Platform as Platform>::SymtabEntry,
    ) -> Result<&'data [u8]>;

    fn num_sections(&self) -> usize;

    fn section_iter(&self) -> <Self::Platform as Platform>::SectionIterator<'data>;

    fn enumerate_sections(
        &self,
    ) -> impl Iterator<
        Item = (
            object::SectionIndex,
            &'data <Self::Platform as Platform>::SectionHeader,
        ),
    >;

    fn section(
        &self,
        index: object::SectionIndex,
    ) -> Result<&'data <Self::Platform as Platform>::SectionHeader>;

    fn section_by_name(
        &self,
        name: &str,
    ) -> Option<(
        object::SectionIndex,
        &'data <Self::Platform as Platform>::SectionHeader,
    )>;

    fn symbol_section(
        &self,
        symbol: &<Self::Platform as Platform>::SymtabEntry,
        index: object::SymbolIndex,
    ) -> Result<Option<object::SectionIndex>>;

    fn symbol_versions(&self) -> &[<Self::Platform as Platform>::SymbolVersionIndex];

    fn dynamic_symbol_used(
        &self,
        symbol_index: object::SymbolIndex,
        state: &mut <Self::Platform as Platform>::DynamicLayoutStateExt<'data>,
    ) -> Result;

    fn finalise_sizes_dynamic(
        &self,
        lib_name: &[u8],
        state: &mut <Self::Platform as Platform>::DynamicLayoutStateExt<'data>,
        mem_sizes: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<'data, Self::Platform>,
    ) -> Result;

    fn apply_non_addressable_indexes_dynamic(
        &self,
        indexes: &mut <Self::Platform as Platform>::NonAddressableIndexes,
        counts: &mut <Self::Platform as Platform>::NonAddressableCounts,
        state: &mut <Self::Platform as Platform>::DynamicLayoutStateExt<'data>,
    ) -> Result;

    fn section_name(
        &self,
        section_header: &<Self::Platform as Platform>::SectionHeader,
    ) -> Result<&'data [u8]>;

    /// Returns the raw section data. Doesn't handle decompression.
    fn raw_section_data(
        &self,
        section: &<Self::Platform as Platform>::SectionHeader,
    ) -> Result<&'data [u8]>;

    fn section_data(
        &self,
        section: &<Self::Platform as Platform>::SectionHeader,
        member: &bumpalo_herd::Member<'data>,
        loaded_metrics: &LoadedMetrics,
    ) -> Result<&'data [u8]>;

    /// Copies the data for the specified section into `out`, which must be the correct size.
    /// Decompresses the data if necessary.
    fn copy_section_data(
        &self,
        section: &<Self::Platform as Platform>::SectionHeader,
        out: &mut [u8],
    ) -> Result;

    /// Returns the contents of a section as a Cow. Will heap-allocate if the section is compressed.
    fn section_data_cow(
        &self,
        section: &<Self::Platform as Platform>::SectionHeader,
    ) -> Result<Cow<'data, [u8]>>;

    fn section_alignment(
        &self,
        section: &<Self::Platform as Platform>::SectionHeader,
    ) -> Result<u64>;

    fn relocations(
        &self,
        index: object::SectionIndex,
        relocations: &<Self::Platform as Platform>::RelocationSections,
    ) -> Result<<Self::Platform as Platform>::RelocationList<'data>>;

    fn parse_relocations(&self) -> Result<<Self::Platform as Platform>::RelocationSections>;

    /// Get the version of a symbol. Only intended for diagnostic purposes since it's potentially
    /// quite slow.
    fn symbol_version_debug(&self, symbol_index: object::SymbolIndex) -> Option<String>;

    fn section_display_name(&self, index: object::SectionIndex) -> Cow<'data, str>;

    fn dynamic_tag_values(&self) -> Option<<Self::Platform as Platform>::DynamicTagValues<'data>>;

    fn get_version_names(&self) -> Result<<Self::Platform as Platform>::VersionNames<'data>>;

    fn get_symbol_name_and_version(
        &self,
        symbol: &<Self::Platform as Platform>::SymtabEntry,
        local_index: usize,
        version_names: &<Self::Platform as Platform>::VersionNames<'data>,
    ) -> Result<<Self::Platform as Platform>::RawSymbolName<'data>>;

    /// Returns whether we should check for undefined symbols in `self`. Only called for dynamic
    /// objects.
    fn should_enforce_undefined(
        &self,
        resources: &layout::GraphResources<'data, '_, Self::Platform>,
    ) -> bool;

    fn verneed_table(&self) -> Result<<Self::Platform as Platform>::VerneedTable<'data>>;

    fn process_gnu_note_section(
        &self,
        state: &mut <Self::Platform as Platform>::ObjectLayoutStateExt<'data>,
        section_index: object::SectionIndex,
    ) -> Result;

    fn dynamic_tags(&self) -> Result<&'data [<Self::Platform as Platform>::DynamicEntry]>;
}

pub(crate) trait SectionHeader: std::fmt::Debug + Send + Sync + 'static {
    fn is_alloc(&self) -> bool;

    fn is_writable(&self) -> bool;

    fn is_executable(&self) -> bool;

    fn is_tls(&self) -> bool;

    fn is_merge_section(&self) -> bool;

    fn is_strings(&self) -> bool;

    fn should_retain(&self) -> bool;

    fn should_exclude(&self) -> bool;

    fn is_group(&self) -> bool;

    fn is_note(&self) -> bool;

    fn is_prog_bits(&self) -> bool;

    /// Returns whether the section has no contents in the file (zero initialised).
    fn is_no_bits(&self) -> bool;
}

pub(crate) trait SectionType:
    Default + Copy + Send + Sync + std::fmt::Debug + 'static
{
    fn is_rela(&self) -> bool;
    fn is_rel(&self) -> bool;
    fn is_symtab(&self) -> bool;
    fn is_strtab(&self) -> bool;
}

pub(crate) trait SegmentType:
    Default + Copy + Send + Sync + std::fmt::Debug + 'static
{
}

pub(crate) trait SectionFlags:
    Default + Copy + std::fmt::Debug + Send + Sync + 'static
{
    fn is_alloc(self) -> bool;
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

pub(crate) trait RelocationList<'data>: Send + Sync + 'data {
    fn num_relocations(&self) -> usize;
}

pub(crate) trait RawSymbolName<'data>: Send + Sync + std::fmt::Display + 'data {
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

pub(crate) trait NonAddressableIndexes: Send + Sync + 'static {
    fn new<P: Platform>(symbol_db: &SymbolDb<P>) -> Self;
}

pub(crate) trait SectionAttributes:
    std::fmt::Debug + Default + Send + Sync + Copy + 'static
{
    type Platform: Platform;

    fn merge(&mut self, rhs: Self);

    fn apply(
        &self,
        output_sections: &mut OutputSections<Self::Platform>,
        section_id: OutputSectionId,
    );

    fn is_null(&self) -> bool;

    fn is_alloc(&self) -> bool;

    fn is_executable(&self) -> bool;

    fn is_tls(&self) -> bool;

    fn is_writable(&self) -> bool;

    fn is_no_bits(&self) -> bool;

    fn flags(&self) -> <Self::Platform as Platform>::SectionFlags;

    fn ty(&self) -> <Self::Platform as Platform>::SectionType;

    /// Called for custom sections that return true to `is_null`.
    fn set_to_default_type(&mut self);
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

pub(crate) trait ProgramSegmentDef: Copy + Send + Sync + Display + 'static {
    type Platform: Platform;

    fn is_writable(self) -> bool;

    fn is_executable(self) -> bool;

    fn always_keep(self) -> bool;

    fn is_loadable(self) -> bool;

    fn is_stack(self) -> bool;

    fn is_tls(self) -> bool;

    /// Returns a numeric value that can be used to sort the segments as they should appear in the
    /// program headers table. Segments with lower values will appear first.
    fn order_key(self) -> usize;

    /// Returns whether we should include the specified section in a segment with the properties of
    /// `self`
    fn should_include_section(
        self,
        section_info: &crate::output_section_id::SectionOutputInfo<Self::Platform>,
        section_id: OutputSectionId,
    ) -> bool;

    /// Returns whether the current RW segment should end when this segment ends.
    fn should_cut_rw_segment_when_ending(self) -> bool {
        false
    }
}

pub(crate) trait BuiltInSectionDetails: Send + Sync + 'static {}

pub(crate) trait Args: std::fmt::Debug + Send + Sync + 'static {
    fn parse<S, I>(&mut self, input: I) -> Result
    where
        S: AsRef<str>,
        I: Iterator<Item = S>;

    fn gc_stats_output_file(&self) -> Option<&Path> {
        None
    }

    fn gc_stats_ignore(&self) -> &[String] {
        &[]
    }

    fn verbose_gc_stats(&self) -> bool {
        false
    }

    fn should_strip_debug(&self) -> bool;

    fn should_strip_all(&self) -> bool;

    /// Returns whether a symbol with the specified name should be stripped. Should return false if
    /// name-based stripping is not being applied.
    fn should_strip_symbol_named(&self, _name: &[u8]) -> bool {
        false
    }

    /// Returns a list of symbol names that should be treated as undefined.
    fn force_undefined_symbol_names(&self) -> &[String] {
        &[]
    }

    fn force_export_symbol_names(&self) -> &[String] {
        &[]
    }

    fn symbol_names_to_wrap(&self) -> &[String] {
        &[]
    }

    fn entry_symbol_name<'a>(&'a self, linker_script_entry: Option<&'a [u8]>) -> &'a [u8];

    fn version_script_path(&self) -> Option<&Path> {
        None
    }

    fn lib_search_path(&self) -> &[Box<Path>];

    fn output(&self) -> &Arc<Path>;

    fn common(&self) -> &crate::args::CommonArgs;

    fn common_mut(&mut self) -> &mut crate::args::CommonArgs;

    fn sysroot(&self) -> Option<&Path> {
        None
    }

    fn export_list_path(&self) -> Option<&Path> {
        None
    }

    fn should_gc_sections(&self) -> bool {
        true
    }

    fn should_relax(&self) -> bool {
        false
    }

    fn should_emit_got_plt_syms(&self) -> bool {
        false
    }

    fn should_export_all_dynamic_symbols(&self) -> bool;

    /// Returns whether all symbols from the specified input should be exported as dynamic symbols.
    fn should_export_dynamic(&self, lib_name: &[u8]) -> bool;

    /// Returns whether to allow undefined symbols in regular object files.
    fn should_allow_object_undefined(&self, _output_kind: OutputKind) -> bool {
        false
    }

    /// Returns whether multiple symbols with the same name should be permitted.
    fn allow_multiple_definitions(&self) -> bool {
        false
    }

    fn unresolved_symbols_behaviour(&self) -> crate::args::UnresolvedSymbols {
        crate::args::UnresolvedSymbols::ReportAll
    }

    fn defsym(&self) -> &[(String, DefsymValue)] {
        &[]
    }

    fn stack_size_override(&self) -> Option<NonZeroU64> {
        None
    }

    fn copy_relocations_enabled(&self) -> crate::args::CopyRelocations {
        crate::args::CopyRelocations::Disallowed(
            crate::args::CopyRelocationsDisabledReason::Unsupported,
        )
    }

    fn should_error_on_unresolved_symbols(&self) -> bool {
        true
    }

    /// Whether the linker name and version should be written into the output file.
    fn should_write_linker_identity(&self) -> bool {
        false
    }

    fn dynamic_linker(&self) -> Option<&Path> {
        None
    }

    /// Gives the command-line the option to force the start address for a section based on its
    /// name.
    fn start_address_for_section(&self, _section_name: SectionName) -> Option<u64> {
        None
    }

    fn loadable_segment_alignment(&self) -> Alignment;

    fn should_merge_sections(&self) -> bool;

    fn dependency_file(&self) -> Option<&Path> {
        None
    }

    fn should_write_trace_file(&self) -> bool {
        false
    }

    fn relocation_model(&self) -> crate::args::RelocationModel;

    fn should_output_executable(&self) -> bool;

    fn warning(&self, message: impl Into<String>) {
        (self.common().warning_callback)(Warning::new(message.into()));
    }

    fn warn_unsupported(&self, opt: &str) -> Result {
        use crate::args::WILD_UNSUPPORTED_ENV;

        let message = format!("{opt} is not yet supported");

        match std::env::var(WILD_UNSUPPORTED_ENV)
            .unwrap_or_default()
            .as_str()
        {
            "warn" | "" => self.warning(message),
            "ignore" => {}
            "error" => bail!("{message}"),
            other => bail!("Unsupported value for {WILD_UNSUPPORTED_ENV}={other}"),
        }
        Ok(())
    }

    fn should_output_partial_object(&self) -> bool {
        false
    }
}
