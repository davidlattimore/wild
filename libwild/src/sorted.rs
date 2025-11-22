use crate::input_data::FileId;
use crate::layout::Section;

#[derive(Clone)]
pub struct SectionToSort {
    pub file_id: FileId,
    pub section: Section,
    pub priority: u16,
    pub is_ctors_like: bool,
}

#[derive(Clone)]
pub struct SortedPlanEntry {
    pub file_id: FileId,
    pub section: Section,
    pub dst_file_off: u64,
    pub is_ctors_like: bool,
}

#[inline]
pub fn file_rank(file_id: FileId) -> u32 {
    ((file_id.group() as u32) << 16) | file_id.file() as u32
}
