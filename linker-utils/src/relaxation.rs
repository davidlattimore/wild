#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationModifier {
    Normal,
    SkipNextRelocation,
}

/// Records a signed byte adjustment at a specific offset within an input
/// section.
///
/// * **Positive** `bytes_delta` — bytes were *deleted* (shorter output). Used by ELF
///   linker-relaxation (e.g. R_RISCV_RELAX pruning a superseded NOP).
/// * **Negative** `bytes_delta` — bytes were *inserted* (longer output). Used by Mach-O
///   `MH_SUBSECTIONS_VIA_SYMBOLS` alignment padding before each subsection boundary.
///
/// The core invariant is the same in both directions:
/// `output = input.wrapping_sub(cumulative_delta as u64)`. For a
/// positive `cumulative_delta` that's `input - delta`; for a negative
/// one it's `input + |delta|` via two's-complement wraparound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelaxDelta {
    /// Offset within the input section the adjustment is anchored at.
    pub input_offset: u64,
    /// Cumulative signed bytes adjusted (deleted if positive, inserted
    /// if negative) up to and including this entry.
    pub cumulative_delta: i64,
    /// Bytes adjusted (deleted if positive, inserted if negative) at
    /// this exact position.
    pub bytes_delta: i32,
}

/// Tracks all relaxation-induced or padding-induced byte adjustments
/// for a single section. Formerly `SectionRelaxDeltas` (kept as a type
/// alias below for source-compatibility).
///
/// The representation is direction-agnostic — ELF passes positive
/// deletions, Mach-O subsections-via-symbols will pass negative
/// insertions. Callers that assume strictly-positive deltas (historic
/// ELF code) continue to work because signed arithmetic narrows back
/// to `u32` / `u64` via `as`-cast without surprise when the values
/// really are positive.
#[derive(Debug, Clone, Default)]
pub struct SectionDeltas {
    /// Sorted (by `input_offset`) list of individual adjustments.
    /// Each entry carries a precomputed `cumulative_delta` field.
    deltas: Vec<RelaxDelta>,
}

/// Source-compatibility alias. All existing ELF callers use this name;
/// it stays in place while the struct itself is direction-agnostic.
pub type SectionRelaxDeltas = SectionDeltas;

impl SectionDeltas {
    #[must_use]
    pub fn new(raw: Vec<(u64, i32)>) -> Self {
        debug_assert!(
            raw.windows(2).all(|w| w[0].0 < w[1].0),
            "entries must be sorted by input_offset in strictly ascending order"
        );

        let mut deltas = Vec::with_capacity(raw.len());
        let mut running: i64 = 0;
        for (input_offset, bytes_delta) in raw {
            running += i64::from(bytes_delta);
            deltas.push(RelaxDelta {
                input_offset,
                cumulative_delta: running,
                bytes_delta,
            });
        }

        SectionDeltas { deltas }
    }

    #[must_use]
    pub fn deltas(&self) -> &[RelaxDelta] {
        &self.deltas
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.deltas.is_empty()
    }

    /// Cumulative signed delta across the whole section (positive =
    /// bytes deleted, negative = bytes inserted). `0` when empty.
    #[must_use]
    pub fn total_delta(&self) -> i64 {
        self.deltas.last().map_or(0, |d| d.cumulative_delta)
    }

    /// Merges additional `(input_offset, bytes_delta)` pairs into this
    /// set. The additional pairs must not overlap with existing entries.
    /// After merging, cumulative counts are recomputed.
    pub fn merge_additional(&mut self, additional: Vec<(u64, i32)>) {
        if additional.is_empty() {
            return;
        }
        let mut raw: Vec<(u64, i32)> = self
            .deltas
            .iter()
            .map(|d| (d.input_offset, d.bytes_delta))
            .chain(additional)
            .collect();
        raw.sort_by_key(|(offset, _)| *offset);
        debug_assert!(
            raw.windows(2).all(|w| w[0].0 < w[1].0),
            "merge_additional: duplicate or overlapping offsets"
        );
        *self = SectionDeltas::new(raw);
    }

    #[must_use]
    pub fn has_delta_at(&self, offset: u64) -> bool {
        self.deltas
            .binary_search_by_key(&offset, |d| d.input_offset)
            .is_ok()
    }

    /// Returns the signed bytes adjusted at `offset`, or `0` if there
    /// is no entry at that offset. Positive = deletion, negative =
    /// insertion.
    #[must_use]
    pub fn delta_at(&self, offset: u64) -> i32 {
        self.deltas
            .binary_search_by_key(&offset, |d| d.input_offset)
            .map_or(0, |i| self.deltas[i].bytes_delta)
    }

    /// Converts an input section offset to the corresponding output
    /// section offset by applying the cumulative delta whose anchor
    /// affects this position. Anchor semantics are sign-aware:
    ///
    /// * **Deletion** (`bytes_delta > 0`): entry at `X` covers queries for `input > X`. The bytes
    ///   at `[X, X+delta)` are themselves deleted; a query for input `X` returns output `X` by
    ///   convention (the position of the next surviving byte).
    /// * **Insertion** (`bytes_delta < 0`): entry at `X` covers queries for `input >= X`. The
    ///   insertion happens *before* the content at `X`, so a symbol located at `X` gets pushed to
    ///   `X + |delta|`.
    ///
    /// Both flavours share the same map and can be mixed within one
    /// section — the sign of each entry picks its own anchor semantics
    /// on the fly.
    #[must_use]
    pub fn input_to_output_offset(&self, input_offset: u64) -> u64 {
        if self.deltas.is_empty() {
            return input_offset;
        }

        let idx = self.deltas.partition_point(|d| {
            d.input_offset < input_offset || (d.input_offset == input_offset && d.bytes_delta < 0)
        });

        if idx == 0 {
            input_offset
        } else {
            // `x - cum` for positive (deletion) cum; `x + |cum|` for
            // negative (insertion) cum. Two's-complement does both in
            // one instruction via wrapping_sub.
            input_offset.wrapping_sub(self.deltas[idx - 1].cumulative_delta as u64)
        }
    }

    /// Converts an output section offset back to the corresponding
    /// input section offset. Symmetric inverse of
    /// [`Self::input_to_output_offset`].
    #[must_use]
    pub fn output_to_input_offset(&self, output_offset: u64) -> u64 {
        if self.deltas.is_empty() {
            return output_offset;
        }

        // For each entry, its visibility boundary in the output is
        // `input_offset + bytes_delta - cumulative_delta`. That formula
        // is unchanged by the signed refactor: both terms carry sign.
        let lo = self.deltas.partition_point(|d| {
            let boundary = i128::from(d.input_offset) + i128::from(d.bytes_delta)
                - i128::from(d.cumulative_delta);
            boundary <= i128::from(output_offset)
        });

        if lo == 0 {
            output_offset
        } else {
            output_offset.wrapping_add(self.deltas[lo - 1].cumulative_delta as u64)
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
    /// Cumulative signed bytes adjusted up to (but not including)
    /// `deltas[index]`.
    current_cumulative: i64,
}

impl RelaxCursor<'_> {
    /// Translates an input section offset to the corresponding output
    /// section offset. Anchor rules match
    /// [`SectionDeltas::input_to_output_offset`]: deletion entries are
    /// strict-before, insertion entries are inclusive-before.
    #[inline]
    pub fn translate(&mut self, input_offset: u64) -> u64 {
        while self.index < self.deltas.len() && {
            let d = &self.deltas[self.index];
            d.input_offset < input_offset || (d.input_offset == input_offset && d.bytes_delta < 0)
        } {
            self.current_cumulative = self.deltas[self.index].cumulative_delta;
            self.index += 1;
        }
        input_offset.wrapping_sub(self.current_cumulative as u64)
    }
}

/// Translates an input offset through optional relaxation deltas.
#[inline]
#[must_use]
pub fn opt_input_to_output(deltas: Option<&SectionDeltas>, input_offset: u64) -> u64 {
    match deltas {
        Some(d) => d.input_to_output_offset(input_offset),
        None => input_offset,
    }
}

/// Sparse map from section index to [`SectionDeltas`].
///
/// Former name `RelaxDeltaMap` — kept as a type alias below.
#[derive(Debug, Clone, Default)]
pub struct SectionDeltaMap {
    /// Sorted by section index
    entries: Vec<(usize, SectionDeltas)>,
}

/// Source-compatibility alias. Call sites that predate the
/// signed-direction refactor keep using `RelaxDeltaMap`.
pub type RelaxDeltaMap = SectionDeltaMap;

impl SectionDeltaMap {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn insert(&mut self, section_index: usize, deltas: SectionDeltas) {
        debug_assert!(
            self.entries
                .last()
                .is_none_or(|(idx, _)| *idx < section_index),
            "entries must be inserted in ascending section index order"
        );
        self.entries.push((section_index, deltas));
    }

    #[must_use]
    pub fn get(&self, section_index: usize) -> Option<&SectionDeltas> {
        self.entries
            .binary_search_by_key(&section_index, |(idx, _)| *idx)
            .ok()
            .map(|i| &self.entries[i].1)
    }

    #[must_use]
    pub fn get_mut(&mut self, section_index: usize) -> Option<&mut SectionDeltas> {
        self.entries
            .binary_search_by_key(&section_index, |(idx, _)| *idx)
            .ok()
            .map(|i| &mut self.entries[i].1)
    }

    pub fn insert_sorted(&mut self, section_index: usize, deltas: SectionDeltas) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_invariant_unchanged() {
        // ELF case: 4 bytes deleted at input offset 20.
        let d = SectionDeltas::new(vec![(20, 4)]);
        assert_eq!(d.total_delta(), 4);
        // Before the deletion — offset unchanged.
        assert_eq!(d.input_to_output_offset(15), 15);
        // At the anchor — strict-before semantics leaves it unchanged.
        assert_eq!(d.input_to_output_offset(20), 20);
        // After the deletion — shifted down by 4.
        assert_eq!(d.input_to_output_offset(30), 26);
        // Round trip.
        assert_eq!(d.output_to_input_offset(26), 30);
    }

    #[test]
    fn insertion_invariant_via_negative_delta() {
        // Subsections case: 12 bytes of padding inserted before
        // input_offset 4. Inclusive-before semantics: a symbol located
        // AT input_offset 4 gets pushed by the padding, too.
        let d = SectionDeltas::new(vec![(4, -12)]);
        assert_eq!(d.total_delta(), -12);
        assert_eq!(d.input_to_output_offset(0), 0);
        // The symbol at the insertion anchor is itself pushed.
        assert_eq!(d.input_to_output_offset(4), 16);
        // So is everything after it.
        assert_eq!(d.input_to_output_offset(8), 20);
        // Round trip for a non-padding output position.
        assert_eq!(d.output_to_input_offset(20), 8);
    }

    #[test]
    fn mixed_deletion_and_insertion_composes() {
        // A synthetic scenario: delete 4 at offset 10, then insert 8
        // (delta = -8) at offset 20. Cumulatives should be 4 then -4.
        let d = SectionDeltas::new(vec![(10, 4), (20, -8)]);
        assert_eq!(d.deltas()[0].cumulative_delta, 4);
        assert_eq!(d.deltas()[1].cumulative_delta, -4);
        assert_eq!(d.total_delta(), -4);
        // At the deletion anchor — strict-before leaves it alone.
        assert_eq!(d.input_to_output_offset(10), 10);
        // After the deletion but before the insertion: -4.
        assert_eq!(d.input_to_output_offset(15), 11);
        // At the insertion anchor — inclusive-before pushes it.
        assert_eq!(d.input_to_output_offset(20), 24);
        // After both anchors: cumulative = -4, so +4.
        assert_eq!(d.input_to_output_offset(25), 29);
    }

    #[test]
    fn cursor_matches_direct_lookup_across_signs() {
        let d = SectionDeltas::new(vec![(10, 4), (20, -8), (30, 2)]);
        let mut c = d.cursor();
        for probe in [5u64, 15, 25, 35] {
            assert_eq!(c.translate(probe), d.input_to_output_offset(probe));
        }
    }

    #[test]
    fn delta_at_returns_signed_amount() {
        let d = SectionDeltas::new(vec![(10, 4), (20, -8)]);
        assert_eq!(d.delta_at(10), 4);
        assert_eq!(d.delta_at(20), -8);
        assert_eq!(d.delta_at(15), 0);
    }

    #[test]
    fn empty_is_identity() {
        let d = SectionDeltas::default();
        assert_eq!(d.total_delta(), 0);
        assert_eq!(d.input_to_output_offset(42), 42);
        assert_eq!(d.output_to_input_offset(42), 42);
    }

    #[test]
    fn merge_additional_recomputes_cumulatives() {
        let mut d = SectionDeltas::new(vec![(10, 4)]);
        d.merge_additional(vec![(5, 2), (20, 6)]);
        let xs = d.deltas();
        assert_eq!(xs.len(), 3);
        assert_eq!(xs[0].cumulative_delta, 2);
        assert_eq!(xs[1].cumulative_delta, 6);
        assert_eq!(xs[2].cumulative_delta, 12);
    }
}
