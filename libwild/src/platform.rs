use crate::Args;
use crate::Result;
use crate::input_data::InputBytes;
use crate::part_id::PartId;
use crate::resolution::LoadedMetrics;
use std::borrow::Cow;

/// An object file. Abstracts over the different object file formats that we support (or may
/// support). e.g. ELF
pub(crate) trait ObjectFile<'data>: Send + Sync + Sized + std::fmt::Debug {
    type Symbol: Symbol;
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
