use crate::alignment;
use crate::alignment::Alignment;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_map::OutputSectionMap;
use crate::part_id::PartId;
use std::ops::AddAssign;

/// A map from each part of each output section to some value. Different sections are split into
/// parts in different ways. Sections that come from input files are split by alignment. Some
/// sections have no splitting and some have splitting that is specific to that particular section.
/// For example the symbol table is split into local then global symbols.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct OutputSectionPartMap<T> {
    // TODO: We used to store all the generated parts in separate instance variables. When we
    // switched to instead storing them in this Vec, we saw a small drop in performance (about 2%).
    // This may be due to an extra pointer indirection and/or bounds checking. Experiment with
    // storing all our built-in parts an an array.
    pub(crate) parts: Vec<T>,
}

impl<T: Default> OutputSectionPartMap<T> {
    pub(crate) fn with_size(size: usize) -> Self {
        let mut parts = Vec::new();
        parts.resize_with(size, Default::default);
        Self { parts }
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
        core::mem::take(self.get_mut(part_id))
    }
}

impl OutputSectionPartMap<u64> {
    pub(crate) fn increment(&mut self, part_id: PartId, size: u64) {
        *self.get_mut(part_id) += size;
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
    /// the maximum alignment of highest alignment PartId with a non-default value.
    pub(crate) fn output_order_map<U: Default>(
        &self,
        output_sections: &OutputSections,
        mut cb: impl FnMut(PartId, Alignment, &T) -> U,
    ) -> OutputSectionPartMap<U> {
        let mut parts_out = Vec::new();
        parts_out.resize_with(self.parts.len(), U::default);

        output_sections.sections_do(|section_id, _| {
            let count = section_id.num_parts();
            let base_part_id = section_id.base_part_id();
            let max_alignment = self.parts
                [base_part_id.as_usize()..base_part_id.as_usize() + count]
                .iter()
                .position(|p| *p != T::default())
                .map(|o| base_part_id.offset(o).alignment())
                .unwrap_or(alignment::MIN)
                .max(base_part_id.output_section_id().min_alignment());
            parts_out[base_part_id.as_usize()..base_part_id.as_usize() + count]
                .iter_mut()
                .enumerate()
                .for_each(|(offset, out)| {
                    let part_id = base_part_id.offset(offset);
                    let alignment = part_id.alignment().min(max_alignment);
                    *out = cb(part_id, alignment, self.get(part_id))
                });
        });

        OutputSectionPartMap { parts: parts_out }
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
        self.parts.resize_with(num_parts, Default::default)
    }
}

impl<T: Copy> OutputSectionPartMap<T> {
    /// Merges the parts of each section together.
    pub(crate) fn merge_parts<U: Default + Copy>(
        &self,
        mut cb: impl FnMut(&[T]) -> U,
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
                cb(section_parts)
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
        self.mut_with_map(sizes, |buffer, size| {
            crate::slice::slice_take_prefix_mut(buffer, *size)
        })
    }
}

#[test]
fn test_merge_parts() {
    let output_sections = OutputSections::for_testing();
    let mut expected_sum_of_sums = 0;
    let all_1 =
        output_sections
            .new_part_map::<u32>()
            .output_order_map(&output_sections, |_, _, _| {
                expected_sum_of_sums += 1;
                1
            });
    let num_regular_sections = output_sections.num_regular_sections();
    let mut num_sections_with_16 = 0;
    let sum_of_1s: OutputSectionMap<u32> = all_1.merge_parts(|values| values.iter().sum());
    let mut sum_of_sums = 0;
    sum_of_1s.for_each(|section_id, sum| {
        sum_of_sums += *sum;
        if *sum == 16 {
            num_sections_with_16 += 1;
        }
        assert!(*sum > 0, "Expected non-zero sum for section {section_id:?}");
    });
    assert_eq!(num_regular_sections, num_sections_with_16);
    assert_eq!(sum_of_sums, expected_sum_of_sums);

    let mut headers_only = output_sections.new_part_map::<u32>();
    *headers_only.get_mut(crate::part_id::FILE_HEADER) += 42;
    let merged: OutputSectionMap<u32> = headers_only.merge_parts(|values| values.iter().sum());
    assert_eq!(*merged.get(crate::output_section_id::FILE_HEADER), 42);
    assert_eq!(*merged.get(crate::output_section_id::TEXT), 0);
    assert_eq!(*merged.get(crate::output_section_id::BSS), 0);
}

#[test]
fn test_mut_with_map() {
    let output_sections = OutputSections::for_testing();
    let mut input1 = output_sections.new_part_map::<u32>().map(|_, _| 1);
    let input2 = output_sections.new_part_map::<u32>().map(|_, _| 2);
    let expected = output_sections.new_part_map::<u32>().map(|_, _| 3);
    input1.mut_with_map(&input2, |a, b| *a += *b);
    assert_eq!(input1, expected);
}

#[test]
fn test_merge() {
    let output_sections = OutputSections::for_testing();
    let mut input1 = output_sections.new_part_map::<u32>().map(|_, _| 1);
    let input2 = output_sections.new_part_map::<u32>().map(|_, _| 2);
    let expected = output_sections.new_part_map::<u32>().map(|_, _| 3);
    input1.merge(&input2);
    assert_eq!(input1, expected);
}

#[test]
fn test_merge_with_custom_sections() {
    let output_sections = OutputSections::for_testing();
    let mut m1 = output_sections.new_part_map::<u32>();
    let mut m2 = output_sections.new_part_map::<u32>();
    assert_eq!(m2.num_parts(), output_sections.num_parts());
    m2.resize(output_sections.num_parts() + 2);
    m1.merge(&m2);
    assert_eq!(m1.num_parts(), output_sections.num_parts() + 2);
}

/// output_order_map and `OutputSections::sections_and_segments_do` used to each independently
/// define the output order. This test made sure that they were consistent. Now the former is uses
/// the latter, so this test is less important. It's kept for the time being anyway.
#[test]
fn test_output_order_map_consistent() {
    use itertools::Itertools;

    let output_sections = crate::output_section_id::OutputSections::for_testing();
    let part_map = output_sections.new_part_map::<u32>();

    // First, make sure that all our built-in part-ids are here. If they're not, we'd fail anyway,
    // but we can give a much better failure message if we check first.
    let mut missing: std::collections::HashSet<PartId> =
        crate::part_id::built_in_part_ids().collect();
    part_map.map(|part_id, _| {
        missing.remove(&part_id);
    });
    let mut missing = missing.into_iter().collect_vec();
    missing.sort();
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
    part_map.output_order_map(&output_sections, |part_id, _, _| {
        let section_id = part_id.output_section_id();
        if ordering_a.last() != Some(&section_id.as_usize()) {
            ordering_a.push(section_id.as_usize());
        }
    });
    let mut ordering_b = Vec::new();
    output_sections.sections_do(|id, _| ordering_b.push(id.as_usize()));
    assert_eq!(ordering_a, ordering_b);
}
