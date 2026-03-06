use crate::platform;
use std::fmt::Display;

#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Debug)]
pub(crate) struct ProgramSegmentId(u8);

#[derive(Debug)]
pub(crate) struct ProgramSegments<T: platform::ProgramSegmentDef> {
    program_segment_details: Vec<T>,
}

impl<T: platform::ProgramSegmentDef> ProgramSegments<T> {
    pub(crate) fn empty() -> ProgramSegments<T> {
        Self {
            program_segment_details: Vec::new(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.program_segment_details.len()
    }

    pub(crate) fn segment_def(&self, segment_id: ProgramSegmentId) -> &T {
        &self.program_segment_details[segment_id.as_usize()]
    }

    pub(crate) fn add_segment(&mut self, segment_def: T) -> ProgramSegmentId {
        let id = ProgramSegmentId::new(self.program_segment_details.len());
        self.program_segment_details.push(segment_def);
        id
    }

    pub(crate) fn is_load_segment(&self, segment_id: ProgramSegmentId) -> bool {
        self.segment_def(segment_id).is_loadable()
    }

    pub(crate) fn is_stack_segment(&self, segment_id: ProgramSegmentId) -> bool {
        self.segment_def(segment_id).is_stack()
    }

    pub(crate) fn is_tls_segment(&self, segment_id: ProgramSegmentId) -> bool {
        self.segment_def(segment_id).is_tls()
    }

    /// Returns a tuple that can be used for sorting the order of segments in the program headers
    /// table.
    pub(crate) fn order_key(&self, segment_id: ProgramSegmentId, mem_start: u64) -> (usize, u64) {
        let def = self.segment_def(segment_id);

        (def.order_key(), mem_start)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = T> {
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

    pub(crate) fn display<T: platform::ProgramSegmentDef>(
        self,
        program_segments: &ProgramSegments<T>,
    ) -> impl Display {
        program_segments.program_segment_details[self.0 as usize]
    }
}

impl<'a, T: platform::ProgramSegmentDef> IntoIterator for &'a ProgramSegments<T> {
    type Item = &'a T;

    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.program_segment_details.iter()
    }
}
