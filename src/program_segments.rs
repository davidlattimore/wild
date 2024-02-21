use crate::elf::SegmentType;

pub(crate) const NUM_SEGMENTS: usize = PROGRAM_SEGMENT_DEFS.len();

#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Debug)]
pub(crate) struct ProgramSegmentId(u8);

pub(crate) const LOAD_RO: ProgramSegmentId = ProgramSegmentId(0);
pub(crate) const LOAD_EXEC: ProgramSegmentId = ProgramSegmentId(1);
pub(crate) const LOAD_RW: ProgramSegmentId = ProgramSegmentId(2);
pub(crate) const TLS: ProgramSegmentId = ProgramSegmentId(3);
pub(crate) const EH_FRAME: ProgramSegmentId = ProgramSegmentId(4);

pub(crate) struct ProgramSegmentDef {
    pub(crate) segment_type: SegmentType,
    pub(crate) segment_flags: u32,
}

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

const PROGRAM_SEGMENT_DEFS: &[ProgramSegmentDef] = &[
    ProgramSegmentDef {
        segment_type: SegmentType::Load,
        segment_flags: PF_R,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::Load,
        segment_flags: PF_R | PF_X,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::Load,
        segment_flags: PF_R | PF_W,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::Tls,
        segment_flags: PF_R,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::EhFrame,
        segment_flags: PF_R,
    },
];

#[cfg(test)]
pub(crate) fn segment_ids() -> impl Iterator<Item = ProgramSegmentId> {
    (0..NUM_SEGMENTS).map(|i| ProgramSegmentId(i as u8))
}

impl ProgramSegmentId {
    pub(crate) fn as_usize(self) -> usize {
        self.0.into()
    }

    pub(crate) fn segment_type(self) -> SegmentType {
        PROGRAM_SEGMENT_DEFS[self.as_usize()].segment_type
    }

    pub(crate) fn segment_flags(&self) -> u32 {
        PROGRAM_SEGMENT_DEFS[self.as_usize()].segment_flags
    }

    pub(crate) fn new(segment_id: usize) -> Self {
        Self(
            segment_id
                .try_into()
                .expect("Tried to create a ProgramSegmentId >= 256"),
        )
    }

    pub(crate) fn alignment(&self) -> crate::alignment::Alignment {
        if self.segment_type() == SegmentType::Load {
            crate::alignment::PAGE
        } else {
            crate::alignment::MIN
        }
    }
}

/// Verifies that any section that isn't NOBITS is allocated to exactly one LOAD segment. This isn't
/// a hard requirement. We may decide to relax this in future for some kinds of segments - e.g.
/// debug data.
#[test]
fn test_all_alloc_sections_in_a_loadable_segment() {
    use crate::output_section_id::OrderEvent;
    let output_sections = crate::output_section_id::OutputSections::for_testing();
    let mut active = Vec::new();
    output_sections.sections_and_segments_do(|event| match event {
        OrderEvent::SegmentStart(segment_id) => {
            active.push(segment_id);
        }
        OrderEvent::SegmentEnd(segment_id) => {
            let end = active.pop();
            assert_eq!(end, Some(segment_id));
        }
        OrderEvent::Section(section_id, section_details) => {
            let has_load_segment = active
                .iter()
                .any(|seg_id| seg_id.segment_type() == crate::elf::SegmentType::Load);
            let is_alloc = (section_details.section_flags & crate::elf::shf::ALLOC) != 0;
            if section_details.has_data_in_file() && is_alloc && !has_load_segment {
                panic!(
                    "alloc section {section_id:?} is not NOBITS, but isn't allocated to a LOAD segment"
                );
            }
        }
    });
}

#[test]
fn test_constant_segment_ids() {
    assert_eq!(PROGRAM_SEGMENT_DEFS[LOAD_RO.as_usize()].segment_flags, PF_R);
    assert_eq!(
        PROGRAM_SEGMENT_DEFS[LOAD_RW.as_usize()].segment_flags,
        PF_R | PF_W
    );
    assert_eq!(
        PROGRAM_SEGMENT_DEFS[LOAD_EXEC.as_usize()].segment_flags,
        PF_R | PF_X
    );
    assert_eq!(
        PROGRAM_SEGMENT_DEFS[TLS.as_usize()].segment_type,
        SegmentType::Tls
    );
}
