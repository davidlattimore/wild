use crate::part_id::PartId;
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
