#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationModifier {
    Normal,
    SkipNextRelocation,
}

/// Records the number of bytes deleted at a specific offset within an input section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelaxDelta {
    /// Offset within the input section where the deletion occurs.
    pub input_offset: u64,
    /// Cumulative bytes deleted up to and including this entry.
    pub cumulative_deleted: u64,
    /// Number of bytes deleted at this position.
    pub bytes_deleted: u32,
}

/// Tracks all relaxation-induced byte deletions for a single section.
#[derive(Debug, Clone, Default)]
pub struct SectionRelaxDeltas {
    /// Sorted (by `input_offset`) list of individual deletions.
    /// Each entry carries a precomputed `cumulative_deleted` field.
    deltas: Vec<RelaxDelta>,
}

impl SectionRelaxDeltas {
    #[must_use]
    pub fn new(raw: Vec<(u64, u32)>) -> Self {
        debug_assert!(
            raw.windows(2).all(|w| w[0].0 < w[1].0),
            "entries must be sorted by input_offset in strictly ascending order"
        );

        let mut deltas = Vec::with_capacity(raw.len());
        let mut running = 0u64;
        for (input_offset, bytes_deleted) in raw {
            running += u64::from(bytes_deleted);
            deltas.push(RelaxDelta {
                input_offset,
                cumulative_deleted: running,
                bytes_deleted,
            });
        }

        SectionRelaxDeltas { deltas }
    }

    #[must_use]
    pub fn deltas(&self) -> &[RelaxDelta] {
        &self.deltas
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.deltas.is_empty()
    }

    #[must_use]
    pub fn total_deleted(&self) -> u64 {
        self.deltas.last().map_or(0, |d| d.cumulative_deleted)
    }

    /// Merges additional `(input_offset, bytes_deleted)` pairs into this set of deltas.
    /// The additional pairs must not overlap with existing entries.
    /// After merging, cumulative deleted counts are recomputed.
    pub fn merge_additional(&mut self, additional: Vec<(u64, u32)>) {
        if additional.is_empty() {
            return;
        }
        let mut raw: Vec<(u64, u32)> = self
            .deltas
            .iter()
            .map(|d| (d.input_offset, d.bytes_deleted))
            .chain(additional)
            .collect();
        raw.sort_by_key(|(offset, _)| *offset);
        debug_assert!(
            raw.windows(2).all(|w| w[0].0 < w[1].0),
            "merge_additional: duplicate or overlapping offsets"
        );
        *self = SectionRelaxDeltas::new(raw);
    }

    #[must_use]
    pub fn has_delta_at(&self, offset: u64) -> bool {
        self.deltas
            .binary_search_by_key(&offset, |d| d.input_offset)
            .is_ok()
    }

    // Converts an input section offset to the corresponding output section offset by subtracting
    // the cumulative bytes deleted strictly before `input_offset`.
    #[must_use]
    pub fn input_to_output_offset(&self, input_offset: u64) -> u64 {
        if self.deltas.is_empty() {
            return input_offset;
        }

        // Find the number of deltas whose input_offset is strictly before the
        // queried input_offset.
        let idx = self
            .deltas
            .partition_point(|d| d.input_offset < input_offset);

        if idx == 0 {
            input_offset
        } else {
            input_offset - self.deltas[idx - 1].cumulative_deleted
        }
    }

    // Converts an output section offset back to the corresponding input section offset.
    #[must_use]
    pub fn output_to_input_offset(&self, output_offset: u64) -> u64 {
        if self.deltas.is_empty() {
            return output_offset;
        }

        let lo = self.deltas.partition_point(|d| {
            d.input_offset + u64::from(d.bytes_deleted) - d.cumulative_deleted <= output_offset
        });

        if lo == 0 {
            output_offset
        } else {
            output_offset + self.deltas[lo - 1].cumulative_deleted
        }
    }

    #[must_use]
    pub fn cursor(&self) -> RelaxCursor<'_> {
        RelaxCursor {
            deltas: &self.deltas,
            index: 0,
            current_cumulative: 0,
        }
    }
}

pub struct RelaxCursor<'a> {
    deltas: &'a [RelaxDelta],
    /// Index of the next delta that has not yet been "consumed".
    index: usize,
    /// Cumulative bytes deleted up to (but not including) `deltas[index]`.
    current_cumulative: u64,
}

impl RelaxCursor<'_> {
    // Translates an input section offset to the corresponding output section offset.
    #[inline]
    pub fn translate(&mut self, input_offset: u64) -> u64 {
        // Advance past all deltas that are strictly before the queried offset.
        while self.index < self.deltas.len() && self.deltas[self.index].input_offset < input_offset
        {
            self.current_cumulative = self.deltas[self.index].cumulative_deleted;
            self.index += 1;
        }
        input_offset - self.current_cumulative
    }
}

// Translates an input offset through optional relaxation deltas.
#[inline]
#[must_use]
pub fn opt_input_to_output(deltas: Option<&SectionRelaxDeltas>, input_offset: u64) -> u64 {
    match deltas {
        Some(d) => d.input_to_output_offset(input_offset),
        None => input_offset,
    }
}

/// Sparse map from section index to [`SectionRelaxDeltas`].
#[derive(Debug, Clone, Default)]
pub struct RelaxDeltaMap {
    /// Sorted by section index
    entries: Vec<(usize, SectionRelaxDeltas)>,
}

impl RelaxDeltaMap {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn insert(&mut self, section_index: usize, deltas: SectionRelaxDeltas) {
        debug_assert!(
            self.entries
                .last()
                .is_none_or(|(idx, _)| *idx < section_index),
            "entries must be inserted in ascending section index order"
        );
        self.entries.push((section_index, deltas));
    }

    #[must_use]
    pub fn get(&self, section_index: usize) -> Option<&SectionRelaxDeltas> {
        self.entries
            .binary_search_by_key(&section_index, |(idx, _)| *idx)
            .ok()
            .map(|i| &self.entries[i].1)
    }

    #[must_use]
    pub fn get_mut(&mut self, section_index: usize) -> Option<&mut SectionRelaxDeltas> {
        self.entries
            .binary_search_by_key(&section_index, |(idx, _)| *idx)
            .ok()
            .map(|i| &mut self.entries[i].1)
    }

    pub fn insert_sorted(&mut self, section_index: usize, deltas: SectionRelaxDeltas) {
        let pos = self
            .entries
            .partition_point(|(idx, _)| *idx < section_index);
        debug_assert!(
            pos >= self.entries.len() || self.entries[pos].0 != section_index,
            "insert_sorted: duplicate section_index {section_index}"
        );
        self.entries.insert(pos, (section_index, deltas));
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
