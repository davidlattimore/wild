use crate::alignment;
use crate::alignment::Alignment;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputOrder;
use crate::output_section_id::OutputSectionId;
use crate::output_section_map::OutputSectionMap;
use crate::part_id::PartId;
use std::mem::take;
use std::ops::AddAssign;
use std::ops::Index;
use std::ops::IndexMut;
use std::ops::Range;

/// A map from each part of each output section to some value. Different sections are split into
/// parts in different ways. Sections that come from input files are split by alignment. Some
/// sections have no splitting and some have splitting that is specific to that particular section.
/// For example the symbol table is split into local then global symbols.
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub(crate) struct OutputSectionPartMap<T> {
    // TODO: We used to store all the generated parts in separate instance variables. When we
    // switched to instead storing them in this Vec, we saw a small drop in performance (about 2%).
    // This may be due to an extra pointer indirection and/or bounds checking. Experiment with
    // storing all our built-in parts in an array.
    #[debug(skip)]
    pub(crate) parts: Vec<T>,
}

impl<T: Default> OutputSectionPartMap<T> {
    pub(crate) fn with_size(size: usize) -> Self {
        let mut parts = Vec::new();
        parts.resize_with(size, Default::default);
        Self { parts }
    }
}

impl<T> Index<Range<PartId>> for OutputSectionPartMap<T> {
    type Output = [T];

    fn index(&self, index: Range<PartId>) -> &Self::Output {
        &self.parts[index.start.as_usize()..index.end.as_usize()]
    }
}

impl<T> IndexMut<Range<PartId>> for OutputSectionPartMap<T> {
    fn index_mut(&mut self, index: Range<PartId>) -> &mut Self::Output {
        &mut self.parts[index.start.as_usize()..index.end.as_usize()]
    }
}

impl<T> OutputSectionPartMap<T> {
    pub(crate) fn num_parts(&self) -> usize {
        self.parts.len()
    }

    pub(crate) fn get_mut(&mut self, part_id: PartId) -> &mut T {
        &mut self.parts[part_id.as_usize()]
    }

    pub(crate) fn get(&self, part_id: PartId) -> &T {
        &self.parts[part_id.as_usize()]
    }
}

impl<T: Default> OutputSectionPartMap<T> {
    pub(crate) fn take(&mut self, part_id: PartId) -> T {
        take(self.get_mut(part_id))
    }
}

impl OutputSectionPartMap<u64> {
    pub(crate) fn increment(&mut self, part_id: PartId, size: u64) {
        *self.get_mut(part_id) += size;
    }

    pub(crate) fn decrement(&mut self, part_id: PartId, size: u64) {
        let v = self.get_mut(part_id);
        debug_assert!(
            *v >= size,
            "decrement underflow for {part_id:?}: {v} < {size}"
        );
        *v -= size;
    }
}

impl<T: Default + PartialEq> OutputSectionPartMap<T> {
    /// Iterate through all contained T, producing a new map of U from the values returned by the
    /// callback.
    pub(crate) fn map<U: Default>(
        &self,
        mut cb: impl FnMut(PartId, &T) -> U,
    ) -> OutputSectionPartMap<U> {
        OutputSectionPartMap {
            parts: self
                .parts
                .iter()
                .enumerate()
                .map(|(i, value)| cb(PartId::from_usize(i), value))
                .collect(),
        }
    }

    /// Iterate through all contained T in output order, producing a new map of U from the values
    /// returned by the callback. Note, the alignment is the alignment of the PartId, but capped at
    /// the maximum alignment of the highest alignment PartId with a non-default value.
    pub(crate) fn output_order_map<U: Default>(
        &self,
        output_order: &OutputOrder,
        mut cb: impl FnMut(PartId, Alignment, &T) -> U,
    ) -> OutputSectionPartMap<U> {
        let mut parts_out = Vec::new();
        parts_out.resize_with(self.parts.len(), U::default);
        let mut output = OutputSectionPartMap { parts: parts_out };

        for event in output_order {
            let OrderEvent::Section(section_id) = event else {
                continue;
            };

            let part_id_range = section_id.part_id_range();
            let max_alignment = self.max_alignment(part_id_range.clone());
            output[part_id_range.clone()]
                .iter_mut()
                .zip(&self[part_id_range.clone()])
                .enumerate()
                .for_each(|(offset, (out, input))| {
                    let part_id = part_id_range.start.offset(offset);
                    let alignment = part_id.alignment().min(max_alignment);
                    *out = cb(part_id, alignment, input);
                });
        }

        output
    }

    /// Returns the maximum alignment for any part with a non-default value starting from
    /// `base_part_id` for the next `count` parts. The returned value will not be any less than the
    /// minimum alignment for the section.
    pub(crate) fn max_alignment(&self, range: Range<PartId>) -> Alignment {
        self[range.clone()]
            .iter()
            .position(|p| *p != T::default())
            .map_or(alignment::MIN, |o| range.start.offset(o).alignment())
            .max(range.start.output_section_id().min_alignment())
    }

    /// Zip mutable references to values in `self` with shared references from `other` producing a
    /// new map with the returned values. For custom sections, `other` must be a subset of `self`.
    /// Values not in `other` will not be in the returned map.
    fn mut_with_map<U, V: Default>(
        &mut self,
        other: &OutputSectionPartMap<U>,
        mut cb: impl FnMut(&mut T, &U) -> V,
    ) -> OutputSectionPartMap<V> {
        let parts = self
            .parts
            .iter_mut()
            .zip(other.parts.iter())
            .map(|(t, u)| cb(t, u))
            .collect();

        OutputSectionPartMap { parts }
    }
}

impl<T: Default> OutputSectionPartMap<T> {
    pub(crate) fn resize(&mut self, num_parts: usize) {
        self.parts.resize_with(num_parts, Default::default);
    }
}

impl<T: Copy> OutputSectionPartMap<T> {
    /// Merges the parts of each section together.
    pub(crate) fn merge_parts<U: Default + Copy>(
        &self,
        mut cb: impl FnMut(OutputSectionId, &[T]) -> U,
    ) -> OutputSectionMap<U> {
        let num_sections = PartId::from_usize(self.parts.len())
            .output_section_id()
            .as_usize();
        let mut parts = self.parts.as_slice();
        let values_out = (0..num_sections)
            .map(|i| {
                let num_parts = OutputSectionId::from_usize(i).num_parts();
                let (section_parts, rest) = parts.split_at(num_parts);
                parts = rest;
                cb(OutputSectionId::from_usize(i), section_parts)
            })
            .collect();
        OutputSectionMap::from_values(values_out)
    }
}

impl<T: AddAssign + Copy + Default> OutputSectionPartMap<T> {
    pub(crate) fn merge(&mut self, rhs: &Self) {
        if self.num_parts() < rhs.num_parts() {
            self.resize(rhs.num_parts());
        }
        for (left, right) in self.parts.iter_mut().zip(rhs.parts.iter()) {
            *left += *right;
        }
    }
}

impl<'out> OutputSectionPartMap<&'out mut [u8]> {
    pub(crate) fn take_mut(
        &mut self,
        sizes: &OutputSectionPartMap<usize>,
    ) -> OutputSectionPartMap<&'out mut [u8]> {
        self.mut_with_map(sizes, |buffer, size| buffer.split_off_mut(..*size).unwrap())
    }
}

#[test]
fn test_merge_parts() {
    let output_sections = crate::output_section_id::OutputSections::for_testing();
    let (output_order, _program_segments) = output_sections.output_order();
    let mut expected_sum_of_sums = 0;
    let all_1 = output_sections
        .new_part_map::<u32>()
        .output_order_map(&output_order, |_, _, _| {
            expected_sum_of_sums += 1;
            1
        });
    let num_regular_sections = output_sections.num_regular_sections();
    let mut num_sections_with_17 = 0;
    let sum_of_1s: OutputSectionMap<u32> = all_1.merge_parts(|_, values| values.iter().sum());
    let mut sum_of_sums = 0;
    sum_of_1s.for_each(|section_id, sum| {
        sum_of_sums += *sum;
        if *sum == 17 {
            num_sections_with_17 += 1;
        }
        assert!(*sum > 0, "Expected non-zero sum for section {section_id:?}");
    });
    assert_eq!(num_regular_sections, num_sections_with_17);
    assert_eq!(sum_of_sums, expected_sum_of_sums);

    let mut headers_only = output_sections.new_part_map::<u32>();
    *headers_only.get_mut(crate::part_id::FILE_HEADER) += 42;
    let merged: OutputSectionMap<u32> = headers_only.merge_parts(|_, values| values.iter().sum());
    assert_eq!(*merged.get(crate::output_section_id::FILE_HEADER), 42);
    assert_eq!(*merged.get(crate::output_section_id::TEXT), 0);
    assert_eq!(*merged.get(crate::output_section_id::BSS), 0);
}

#[test]
fn test_mut_with_map() {
    let output_sections = crate::output_section_id::OutputSections::for_testing();
    let mut input1 = output_sections.new_part_map::<u32>().map(|_, _| 1);
    let input2 = output_sections.new_part_map::<u32>().map(|_, _| 2);
    let expected = output_sections.new_part_map::<u32>().map(|_, _| 3);
    input1.mut_with_map(&input2, |a, b| *a += *b);
    assert_eq!(input1, expected);
}

#[test]
fn test_merge() {
    let output_sections = crate::output_section_id::OutputSections::for_testing();
    let mut input1 = output_sections.new_part_map::<u32>().map(|_, _| 1);
    let input2 = output_sections.new_part_map::<u32>().map(|_, _| 2);
    let expected = output_sections.new_part_map::<u32>().map(|_, _| 3);
    input1.merge(&input2);
    assert_eq!(input1, expected);
}

#[test]
fn test_merge_with_custom_sections() {
    let output_sections = crate::output_section_id::OutputSections::for_testing();
    let mut m1 = output_sections.new_part_map::<u32>();
    let mut m2 = output_sections.new_part_map::<u32>();
    assert_eq!(m2.num_parts(), output_sections.num_parts());
    m2.resize(output_sections.num_parts() + 2);
    m1.merge(&m2);
    assert_eq!(m1.num_parts(), output_sections.num_parts() + 2);
}

/// output_order_map and `OutputSections::sections_and_segments_events` used to each independently
/// define the output order. This test made sure that they were consistent. Now the former uses the
/// latter, so this test is less important. It's kept for the time being anyway.
#[test]
fn test_output_order_map_consistent() {
    use itertools::Itertools;

    let output_sections = crate::output_section_id::OutputSections::for_testing();
    let (output_order, _program_segments) = output_sections.output_order();
    let part_map = output_sections.new_part_map::<u32>();

    // First, make sure that all our built-in part-ids are here. If they're not, we'd fail anyway,
    // but we can give a much better failure message if we check first.
    let mut missing: hashbrown::HashSet<PartId> = crate::part_id::built_in_part_ids().collect();
    part_map.map(|part_id, _| {
        missing.remove(&part_id);
    });
    let missing = missing.into_iter().sorted().collect_vec();
    assert!(
        missing.is_empty(),
        "Built-in sections missing from output_order_map: {}",
        missing
            .iter()
            .map(|id| format!(
                "{id} (in {})",
                output_sections.display_name(id.output_section_id())
            ))
            .collect_vec()
            .join(", ")
    );

    let mut ordering_a = Vec::new();
    part_map.output_order_map(&output_order, |part_id, _, _| {
        let section_id = part_id.output_section_id();
        if ordering_a.last() != Some(&section_id.as_usize()) {
            ordering_a.push(section_id.as_usize());
        }
    });
    let ordering_b = output_order
        .into_iter()
        .filter_map(|event| {
            if let OrderEvent::Section(id) = event {
                Some(id.as_usize())
            } else {
                None
            }
        })
        .collect_vec();

    assert_eq!(ordering_a, ordering_b);
}

#[test]
fn test_output_order_map() {
    use crate::output_section_id;

    let output_sections = crate::output_section_id::OutputSections::for_testing();
    let (output_order, _program_segments) = output_sections.output_order();
    let mut part_map = output_sections.new_part_map::<u32>();

    const PART_ID1: PartId = output_section_id::DATA.part_id_with_alignment(alignment::USIZE);
    *part_map.get_mut(PART_ID1) += 32;

    const PART_ID2: PartId = output_section_id::DATA.part_id_with_alignment(alignment::MIN);
    *part_map.get_mut(PART_ID2) += 5;

    part_map.output_order_map(&output_order, |part_id, alignment, &value| match part_id {
        PART_ID1 => {
            assert_eq!(alignment, alignment::USIZE);
            assert_eq!(value, 32);
        }
        PART_ID2 => {
            assert_eq!(alignment, alignment::MIN);
            assert_eq!(value, 5);
        }
        _ => {
            if part_id.output_section_id() == output_section_id::DATA {
                assert!(
                    alignment <= alignment::USIZE,
                    "Unexpected alignment {alignment}"
                );
            }
            assert_eq!(value, 0);
        }
    });
}

#[test]
fn test_max_alignment() {
    use crate::output_section_id;

    let output_sections = crate::output_section_id::OutputSections::for_testing();
    let mut part_map = output_sections.new_part_map::<u32>();

    assert_eq!(
        part_map.max_alignment(output_section_id::DATA.part_id_range()),
        alignment::MIN
    );

    const PART_ID1: PartId = output_section_id::DATA.part_id_with_alignment(alignment::USIZE);
    *part_map.get_mut(PART_ID1) += 32;

    const PART_ID2: PartId = output_section_id::DATA.part_id_with_alignment(alignment::MIN);
    *part_map.get_mut(PART_ID2) += 5;

    assert_eq!(
        part_map.max_alignment(output_section_id::DATA.part_id_range()),
        alignment::USIZE
    );
}
