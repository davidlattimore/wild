use crate::alignment::Alignment;
use linker_utils::elf::SegmentFlags;
use linker_utils::elf::SegmentType;
use linker_utils::elf::pf;
use linker_utils::elf::pt;
use std::fmt::Display;

#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Debug)]
pub(crate) struct ProgramSegmentId(u8);

pub(crate) struct ProgramSegments {
    program_segment_details: Vec<ProgramSegmentDef>,
}

#[derive(Clone, Copy)]
pub(crate) struct ProgramSegmentDef {
    pub(crate) segment_type: SegmentType,
    pub(crate) segment_flags: SegmentFlags,
}

/// The different kinds of program segments that we generate based on section properties. Note, this
/// doesn't include the PT_GNU_STACK segment, since it isn't generated in response to any sections
/// because it doesn't contain any.
pub(crate) const PROGRAM_SEGMENT_DEFS: &[ProgramSegmentDef] = &[
    ProgramSegmentDef {
        segment_type: pt::PHDR,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::INTERP,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::NOTE,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::LOAD,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::LOAD,
        segment_flags: pf::READABLE.with(pf::EXECUTABLE),
    },
    ProgramSegmentDef {
        segment_type: pt::LOAD,
        segment_flags: pf::READABLE.with(pf::WRITABLE),
    },
    ProgramSegmentDef {
        segment_type: pt::TLS,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::GNU_EH_FRAME,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::DYNAMIC,
        segment_flags: pf::READABLE.with(pf::WRITABLE),
    },
    ProgramSegmentDef {
        segment_type: pt::GNU_RELRO,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::RISCV_ATTRIBUTES,
        segment_flags: pf::READABLE,
    },
];

pub(crate) const STACK_SEGMENT_DEF: ProgramSegmentDef = ProgramSegmentDef {
    segment_type: pt::GNU_STACK,
    segment_flags: pf::READABLE.with(pf::WRITABLE),
};

impl ProgramSegmentDef {
    pub(crate) fn is_writable(self) -> bool {
        self.segment_flags.contains(pf::WRITABLE)
    }

    pub(crate) fn is_executable(self) -> bool {
        self.segment_flags.contains(pf::EXECUTABLE)
    }

    pub(crate) fn always_keep(self) -> bool {
        self.segment_type == pt::PHDR
    }
}

impl ProgramSegments {
    pub(crate) fn empty() -> ProgramSegments {
        Self {
            program_segment_details: Vec::new(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.program_segment_details.len()
    }

    pub(crate) fn segment_alignment(
        &self,
        segment_id: ProgramSegmentId,
        args: &crate::Args,
    ) -> Alignment {
        if self.segment_def(segment_id).segment_type == pt::LOAD {
            args.loadable_segment_alignment()
        } else {
            crate::alignment::MIN
        }
    }

    pub(crate) fn segment_def(&self, segment_id: ProgramSegmentId) -> &ProgramSegmentDef {
        &self.program_segment_details[segment_id.as_usize()]
    }

    pub(crate) fn add_segment(&mut self, segment_def: ProgramSegmentDef) -> ProgramSegmentId {
        let id = ProgramSegmentId::new(self.program_segment_details.len());
        self.program_segment_details.push(segment_def);
        id
    }

    pub(crate) fn is_load_segment(&self, segment_id: ProgramSegmentId) -> bool {
        self.segment_def(segment_id).segment_type == pt::LOAD
    }

    pub(crate) fn is_stack_segment(&self, segment_id: ProgramSegmentId) -> bool {
        self.segment_def(segment_id).segment_type == pt::GNU_STACK
    }

    pub(crate) fn is_tls_segment(&self, segment_id: ProgramSegmentId) -> bool {
        self.segment_def(segment_id).segment_type == pt::TLS
    }

    /// Returns a tuple that can be used for sorting the order of segments in the program headers
    /// table.
    pub(crate) fn order_key(&self, segment_id: ProgramSegmentId, mem_start: u64) -> (usize, u64) {
        let def = self.segment_def(segment_id);

        // Segment types that we put first. Other types
        const TYPE_ORDER: &[SegmentType] = &[pt::PHDR, pt::INTERP, pt::LOAD, pt::DYNAMIC];

        let type_pos = TYPE_ORDER
            .iter()
            .position(|t| *t == def.segment_type)
            .unwrap_or(TYPE_ORDER.len() + def.segment_type.raw() as usize);

        (type_pos, mem_start)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = ProgramSegmentDef> {
        self.program_segment_details.iter().copied()
    }
}

impl ProgramSegmentId {
    pub(crate) fn as_usize(self) -> usize {
        self.0.into()
    }

    pub(crate) fn new(segment_id: usize) -> Self {
        Self(
            segment_id
                .try_into()
                .expect("Tried to create a ProgramSegmentId >= 256"),
        )
    }

    pub(crate) fn display<'a>(
        self,
        program_segments: &'a ProgramSegments,
    ) -> ProgramSegmentDisplay<'a> {
        ProgramSegmentDisplay {
            id: self,
            program_segments,
        }
    }
}

pub(crate) struct ProgramSegmentDisplay<'a> {
    id: ProgramSegmentId,
    program_segments: &'a ProgramSegments,
}

impl Display for ProgramSegmentDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let info = self.program_segments.segment_def(self.id);
        write!(f, "{}, {}", info.segment_type, info.segment_flags)
    }
}

impl<'a> IntoIterator for &'a ProgramSegments {
    type Item = &'a ProgramSegmentDef;

    type IntoIter = std::slice::Iter<'a, ProgramSegmentDef>;

    fn into_iter(self) -> Self::IntoIter {
        self.program_segment_details.iter()
    }
}
