use crate::Args;
use crate::OutputKind;
use crate::Result;
use crate::arch::Architecture;
use crate::input_data::InputBytes;
use crate::layout::Layout;
use crate::part_id::PartId;
use crate::resolution::LoadedMetrics;
use crate::value_flags::ValueFlags;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::relaxation::RelocationModifier;
use std::borrow::Cow;
use std::ops::Range;

/// Represents a supported object file format + architecture combination.
pub(crate) trait Platform<'data> {
    type Relaxation: Relaxation;
    type File: ObjectFile<'data>;

    // Architecture identifier
    const KIND: Architecture;

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
    fn tp_offset_start(layout: &Layout) -> u64;

    // Classify a GNU property note.
    fn get_property_class(property_type: u32) -> Option<crate::elf::PropertyClass>;

    // Merge e_flags of the input files and provide an error
    // if the flags are not compatible.
    fn merge_eflags(eflags: impl Iterator<Item = u32>) -> Result<u32>;

    // A list of high-part relocations that need to be tracked in a relocation cache
    fn high_part_relocations() -> &'static [u32];
}

pub(crate) trait Relaxation {
    /// Tries to create a relaxation for the relocation of the specified kind, to be applied at the
    /// specified offset in the supplied section.
    fn new(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        flags: ValueFlags,
        output_kind: OutputKind,
        section_flags: linker_utils::elf::SectionFlags,
        non_zero_address: bool,
    ) -> Option<Self>
    where
        Self: std::marker::Sized;

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
pub(crate) trait ObjectFile<'data>: Send + Sync + Sized + std::fmt::Debug {
    type Symbol: Symbol + 'static;
    type SectionHeader: SectionHeader + 'static;
    type SectionIterator: Iterator<Item = &'data Self::SectionHeader>;
    type DynamicTagValues;
    type RelocationSections;
    type RelocationList;
    type DynamicEntry;

    fn parse_bytes(input: &'data [u8], is_dynamic: bool) -> Result<Self>;

    /// As for `parse_bytes` but also validates that the file architecture matches what is expected
    /// based on `args`.
    fn parse(input: &InputBytes<'data>, args: &Args) -> Result<Self>;

    fn is_dynamic(&self) -> bool;

    fn num_symbols(&self) -> usize;

    fn symbol(&self, index: object::SymbolIndex) -> Result<&'data Self::Symbol>;

    fn section_size(&self, header: &Self::SectionHeader) -> Result<u64>;

    fn symbol_name(&self, symbol: &Self::Symbol) -> Result<&'data [u8]>;

    fn section_iter(&self) -> Self::SectionIterator;

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
}

pub(crate) trait SectionHeader {
    type SectionFlags: SectionFlags;
    type Attributes;

    fn flags(&self) -> Self::SectionFlags;
    fn attributes(&self) -> Self::Attributes;
}

pub(crate) trait SectionFlags: Copy {
    fn is_alloc(self) -> bool;
    fn is_writable(self) -> bool;
}

pub(crate) trait Symbol {
    type Debug<'data>: std::fmt::Display
    where
        Self: 'data;

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
}

#[derive(Clone, Copy)]
pub(crate) struct CommonSymbol {
    pub(crate) size: u64,
    pub(crate) part_id: PartId,
}

pub(crate) trait Relocation: Copy + 'static {
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
