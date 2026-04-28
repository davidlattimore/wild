/// An ID for an input section. All sections from all input files are allocated a unique section ID.
/// This allows information about sections to be stored in a single large `Vec` indexed by
/// `InputSectionId`, rather than in per-object `Vec`s.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct InputSectionId(u32);

/// A range of section IDs that are owned by the same input file.
///
/// This exists to translate between two different ways of identifying an input section:
/// - An `InputSectionId` is a globally unique identifier for a section.
/// - An `object::SectionIndex` is an index into the section table of a single input file.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SectionIdRange {
    start_section_id: InputSectionId,
    num_sections: usize,
}

impl InputSectionId {
    pub(crate) fn from_usize(value: usize) -> InputSectionId {
        Self(u32::try_from(value).expect("Sections overflowed 32 bits"))
    }

    pub(crate) fn as_usize(self) -> usize {
        self.0 as usize
    }

    pub(crate) fn add_usize(self, value: usize) -> InputSectionId {
        Self::from_usize(self.as_usize() + value)
    }
}

impl SectionIdRange {
    pub(crate) fn input(start_section_id: InputSectionId, num_sections: usize) -> Self {
        Self {
            start_section_id,
            num_sections,
        }
    }

    #[cfg(feature = "plugins")]
    pub(crate) fn empty() -> Self {
        Self {
            start_section_id: InputSectionId(0),
            num_sections: 0,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.num_sections
    }

    pub(crate) fn start(&self) -> InputSectionId {
        self.start_section_id
    }

    pub(crate) fn as_usize(&self) -> std::ops::Range<usize> {
        self.start_section_id.as_usize()..self.start_section_id.as_usize() + self.num_sections
    }

    pub(crate) fn input_to_id(&self, section_index: object::SectionIndex) -> InputSectionId {
        debug_assert!(
            section_index.0 < self.num_sections,
            "input_to_id({section_index}) with num_sections={}",
            self.num_sections
        );
        self.start_section_id.add_usize(section_index.0)
    }
}
