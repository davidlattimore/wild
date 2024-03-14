use crate::output_section_id::OutputSectionId;

/// A map from output section IDs to something.
pub(crate) struct OutputSectionMap<T> {
    // TODO: Consider only storing frequently used segment IDs in an array and storing less
    // frequently used IDs in an on-demand sorted Vec or smallvec.
    values: Vec<T>,
}

impl<T: Default> OutputSectionMap<T> {
    pub(crate) fn with_size(len: usize) -> Self {
        let mut values = Vec::new();
        values.resize_with(len, T::default);
        Self { values }
    }

    pub(crate) fn into_raw_values(self) -> Vec<T> {
        self.values
    }
}

impl<T> OutputSectionMap<T> {
    pub(crate) fn from_values(values: Vec<T>) -> Self {
        Self { values }
    }

    // TODO: This seems to be the same as `get`. Get rid of it?
    pub(crate) fn built_in(&self, index: OutputSectionId) -> &T {
        &self.values[index.as_usize()]
    }

    pub(crate) fn get_mut(&mut self, id: OutputSectionId) -> &mut T {
        &mut self.values[id.as_usize()]
    }

    pub(crate) fn get(&self, id: OutputSectionId) -> &T {
        &self.values[id.as_usize()]
    }

    pub(crate) fn for_each(&self, mut cb: impl FnMut(OutputSectionId, &T)) {
        self.values
            .iter()
            .enumerate()
            .for_each(|(k, v)| cb(OutputSectionId::from_usize(k), v));
    }

    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }

    pub(crate) fn into_map<U>(self, cb: impl FnMut(T) -> U) -> OutputSectionMap<U> {
        OutputSectionMap {
            values: self.values.into_iter().map(cb).collect(),
        }
    }
}

impl<T> OutputSectionMap<T>
where
    T: Copy,
{
    pub(crate) fn merge(&mut self, other: &Self, cb: impl Fn(T, T) -> T) {
        self.values
            .iter_mut()
            .zip(other.values.iter())
            .for_each(|(a, b)| {
                *a = cb(*a, *b);
            });
    }
}
