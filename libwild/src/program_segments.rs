use crate::alignment::Alignment;

#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Debug)]
pub(crate) struct ProgramSegmentId(u8);

pub(crate) struct ProgramSegments {
    program_segment_details: Vec<ProgramSegmentDef>,
}

#[derive(Clone, Copy)]
pub(crate) struct ProgramSegmentDef {
    pub(crate) segment_type: u32,
    pub(crate) segment_flags: u32,
}

/// The different kinds of program segments that we generate based on section properties. Note, this
/// doesn't include the PT_GNU_STACK segment, since it isn't generated in response to any sections
/// because it doesn't contain any.
pub(crate) const PROGRAM_SEGMENT_DEFS: &[ProgramSegmentDef] = &[
    ProgramSegmentDef {
        segment_type: object::elf::PT_PHDR,
        segment_flags: object::elf::PF_R,
    },
    ProgramSegmentDef {
        segment_type: object::elf::PT_INTERP,
        segment_flags: object::elf::PF_R,
    },
    ProgramSegmentDef {
        segment_type: object::elf::PT_NOTE,
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
    ProgramSegmentDef {
        segment_type: object::elf::PT_GNU_RELRO,
        segment_flags: object::elf::PF_R,
    },
];

pub(crate) const STACK_SEGMENT_DEF: ProgramSegmentDef = ProgramSegmentDef {
    segment_type: object::elf::PT_GNU_STACK,
    segment_flags: object::elf::PF_R | object::elf::PF_W,
};

impl ProgramSegmentDef {
    pub(crate) fn is_writable(self) -> bool {
        (self.segment_flags & object::elf::PF_W) != 0
    }

    pub(crate) fn is_executable(self) -> bool {
        (self.segment_flags & object::elf::PF_X) != 0
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
        if self.segment_def(segment_id).segment_type == object::elf::PT_LOAD {
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
        self.segment_def(segment_id).segment_type == object::elf::PT_LOAD
    }

    pub(crate) fn is_stack_segment(&self, segment_id: ProgramSegmentId) -> bool {
        self.segment_def(segment_id).segment_type == object::elf::PT_GNU_STACK
    }

    pub(crate) fn is_tls_segment(&self, segment_id: ProgramSegmentId) -> bool {
        self.segment_def(segment_id).segment_type == object::elf::PT_TLS
    }

    /// Returns a tuple that can be used for sorting the order of segments in the program headers
    /// table.
    pub(crate) fn order_key(&self, segment_id: ProgramSegmentId, mem_start: u64) -> (usize, u64) {
        let def = self.segment_def(segment_id);

        // Segment types that we put first. Other types
        const TYPE_ORDER: &[u32] = &[
            object::elf::PT_PHDR,
            object::elf::PT_INTERP,
            object::elf::PT_LOAD,
            object::elf::PT_DYNAMIC,
        ];

        let type_pos = TYPE_ORDER
            .iter()
            .position(|t| *t == def.segment_type)
            .unwrap_or(TYPE_ORDER.len() + def.segment_type as usize);

        (type_pos, mem_start)
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
}

impl<'a> IntoIterator for &'a ProgramSegments {
    type Item = &'a ProgramSegmentDef;

    type IntoIter = std::slice::Iter<'a, ProgramSegmentDef>;

    fn into_iter(self) -> Self::IntoIter {
        self.program_segment_details.iter()
    }
}
