pub(crate) const MAX_SEGMENTS: usize = PROGRAM_SEGMENT_DEFS.len();

#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Debug)]
pub(crate) struct ProgramSegmentId(u8);

pub(crate) const PHDR: ProgramSegmentId = ProgramSegmentId(0);
pub(crate) const INTERP: ProgramSegmentId = ProgramSegmentId(1);
pub(crate) const LOAD_RO: ProgramSegmentId = ProgramSegmentId(2);
pub(crate) const LOAD_EXEC: ProgramSegmentId = ProgramSegmentId(3);
pub(crate) const LOAD_RW: ProgramSegmentId = ProgramSegmentId(4);
pub(crate) const TLS: ProgramSegmentId = ProgramSegmentId(5);
pub(crate) const EH_FRAME: ProgramSegmentId = ProgramSegmentId(6);
pub(crate) const DYNAMIC: ProgramSegmentId = ProgramSegmentId(7);

pub(crate) struct ProgramSegmentDef {
    pub(crate) segment_type: u32,
    pub(crate) segment_flags: u32,
}

const PROGRAM_SEGMENT_DEFS: &[ProgramSegmentDef] = &[
    ProgramSegmentDef {
        segment_type: object::elf::PT_PHDR,
        segment_flags: object::elf::PF_R,
    },
    ProgramSegmentDef {
        segment_type: object::elf::PT_INTERP,
        segment_flags: object::elf::PF_R,
    },
    ProgramSegmentDef {
        segment_type: object::elf::PT_LOAD,
        segment_flags: object::elf::PF_R,
    },
    ProgramSegmentDef {
        segment_type: object::elf::PT_LOAD,
        segment_flags: object::elf::PF_R | object::elf::PF_X,
    },
    ProgramSegmentDef {
        segment_type: object::elf::PT_LOAD,
        segment_flags: object::elf::PF_R | object::elf::PF_W,
    },
    ProgramSegmentDef {
        segment_type: object::elf::PT_TLS,
        segment_flags: object::elf::PF_R,
    },
    ProgramSegmentDef {
        segment_type: object::elf::PT_GNU_EH_FRAME,
        segment_flags: object::elf::PF_R,
    },
    ProgramSegmentDef {
        segment_type: object::elf::PT_DYNAMIC,
        segment_flags: object::elf::PF_R | object::elf::PF_W,
    },
];

impl ProgramSegmentId {
    pub(crate) fn as_usize(self) -> usize {
        self.0.into()
    }

    pub(crate) fn segment_type(self) -> u32 {
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
        if self.segment_type() == object::elf::PT_LOAD {
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
    use linker_utils::elf::shf;

    let output_sections = crate::output_section_id::OutputSections::for_testing();
    let mut active = Vec::new();
    for event in output_sections.sections_and_segments_events() {
        match event {
            OrderEvent::SegmentStart(segment_id) => {
                active.push(segment_id);
            }
            OrderEvent::SegmentEnd(segment_id) => {
                let end = active.pop();
                assert_eq!(end, Some(segment_id));
            }
            OrderEvent::Section(section_id) => {
                let section_details = output_sections.details(section_id);
                let has_load_segment = active
                    .iter()
                    .any(|seg_id| seg_id.segment_type() == object::elf::PT_LOAD);
                let is_alloc = section_details.section_flags.contains(shf::ALLOC);
                if section_details.has_data_in_file() && is_alloc && !has_load_segment {
                    panic!(
                    "alloc section {section_id:?} is not NOBITS, but isn't allocated to a LOAD segment"
                );
                }
            }
        }
    }
}

#[test]
fn test_constant_segment_ids() {
    assert_eq!(
        PROGRAM_SEGMENT_DEFS[LOAD_RO.as_usize()].segment_flags,
        object::elf::PF_R
    );
    assert_eq!(
        PROGRAM_SEGMENT_DEFS[LOAD_RW.as_usize()].segment_flags,
        object::elf::PF_R | object::elf::PF_W
    );
    assert_eq!(
        PROGRAM_SEGMENT_DEFS[LOAD_EXEC.as_usize()].segment_flags,
        object::elf::PF_R | object::elf::PF_X
    );
    assert_eq!(
        PROGRAM_SEGMENT_DEFS[TLS.as_usize()].segment_type,
        object::elf::PT_TLS
    );
    assert_eq!(
        PROGRAM_SEGMENT_DEFS[DYNAMIC.as_usize()].segment_type,
        object::elf::PT_DYNAMIC
    );
    assert_eq!(
        PROGRAM_SEGMENT_DEFS[PHDR.as_usize()].segment_type,
        object::elf::PT_PHDR
    );
    assert_eq!(
        PROGRAM_SEGMENT_DEFS[INTERP.as_usize()].segment_type,
        object::elf::PT_INTERP
    );
}
