use crate::alignment;
use crate::alignment::Alignment;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputOrder;
use crate::output_section_id::OutputSections;
use crate::part_id::PartId;
use crate::platform::Platform;
use std::collections::BTreeMap;
use std::mem::take;
use std::ops::AddAssign;
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
    parts: Vec<T>,

    #[debug(skip)]
    sparse: Option<Box<SparsePartMap<T>>>,
}

#[derive(Clone, PartialEq, Eq, Default)]
struct SparsePartMap<T> {
    contents: BTreeMap<PartId, T>,
}

impl<T: Default> OutputSectionPartMap<T> {
    pub(crate) fn with_dense_size(size: usize) -> Self {
        let mut parts = Vec::new();
        parts.resize_with(size, Default::default);
        Self {
            parts,
            sparse: None,
        }
    }
}

impl<T> Default for OutputSectionPartMap<T> {
    fn default() -> Self {
        Self {
            parts: Vec::new(),
            sparse: None,
        }
    }
}

pub(crate) enum RangeIterator<'a, T> {
    Dense(PartId, &'a [T]),
    Sparse(std::collections::btree_map::Range<'a, PartId, T>),
}

impl<'a, T> Iterator for RangeIterator<'a, T> {
    type Item = (PartId, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            RangeIterator::Dense(part_id, items) => {
                let item = items.split_off_first()?;
                let id = *part_id;
                *part_id = part_id.offset(1);
                Some((id, item))
            }
            RangeIterator::Sparse(range) => range.next().map(|(&id, item)| (id, item)),
        }
    }
}

impl<T: Default> OutputSectionPartMap<T> {
    pub(crate) fn new_empty_like<U: Default>(&self) -> OutputSectionPartMap<U> {
        OutputSectionPartMap::with_dense_size(self.parts.len())
    }

    pub(crate) fn get_mut(&mut self, part_id: PartId) -> &mut T {
        self.parts.get_mut(part_id.as_usize()).unwrap_or_else(|| {
            self.sparse
                .get_or_insert_default()
                .contents
                .entry(part_id)
                .or_default()
        })
    }

    /// Note, range must be either entirely dense or entirely sparse. Itended use-case is to get all
    /// parts for a single section.
    pub(crate) fn in_range(&self, range: Range<PartId>) -> RangeIterator<'_, T> {
        if let Some(values) = self.parts.get(range.start.as_usize()..range.end.as_usize()) {
            RangeIterator::Dense(range.start, values)
        } else if let Some(sparse) = self.sparse.as_ref() {
            RangeIterator::Sparse(sparse.contents.range(range))
        } else {
            RangeIterator::Sparse(Default::default())
        }
    }

    pub(crate) fn values_in_range(&self, range: Range<PartId>) -> impl Iterator<Item = &T> {
        self.in_range(range).map(|(_, v)| v)
    }
}

impl<T: Default + Copy> OutputSectionPartMap<T> {
    pub(crate) fn get(&self, part_id: PartId) -> T {
        self.parts
            .get(part_id.as_usize())
            .copied()
            .unwrap_or_else(|| {
                self.sparse
                    .as_ref()
                    .and_then(|sparse| sparse.contents.get(&part_id))
                    .copied()
                    .unwrap_or_default()
            })
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

    /// Increment `self` by `sizes`. Returns the pre-increment values, but only for entries actually
    /// present in `sizes`.
    pub(crate) fn merge_and_return_start_offsets(&mut self, sizes: &Self) -> Self {
        self.mut_with_map(sizes, |offset, size| {
            let start = *offset;
            *offset += *size;
            start
        })
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
            sparse: self.sparse.as_ref().map(|sparse| {
                Box::new(SparsePartMap {
                    contents: sparse
                        .contents
                        .iter()
                        .map(|(id, value)| (*id, cb(*id, value)))
                        .collect(),
                })
            }),
        }
    }

    /// Iterate through all contained T in output order, producing a new map of U from the values
    /// returned by the callback. Note, the alignment is the alignment of the PartId, but capped at
    /// the maximum alignment of the highest alignment PartId with a non-default value.
    pub(crate) fn output_order_map<U: Default, P: Platform>(
        &self,
        output_order: &OutputOrder,
        output_sections: &OutputSections<P>,
        mut cb: impl FnMut(PartId, Alignment, &T) -> U,
    ) -> OutputSectionPartMap<U> {
        let mut parts_out = Vec::new();
        parts_out.resize_with(self.parts.len(), U::default);
        let mut output = OutputSectionPartMap {
            parts: parts_out,
            sparse: None,
        };

        for event in output_order {
            let OrderEvent::Section(section_id) = event else {
                continue;
            };

            let part_id_range = section_id.part_id_range::<P>();
            let max_alignment = self.max_alignment(part_id_range.clone(), output_sections);

            for (part_id, input) in self.in_range(part_id_range.clone()) {
                let alignment = part_id.alignment(output_sections).min(max_alignment);
                *output.get_mut(part_id) = cb(part_id, alignment, input);
            }
        }

        output
    }

    /// Returns the maximum alignment for any part with a non-default value starting from
    /// `base_part_id` for the next `count` parts. The returned value will not be any less than the
    /// minimum alignment for the section.
    pub(crate) fn max_alignment<P: Platform>(
        &self,
        range: Range<PartId>,
        output_sections: &OutputSections<P>,
    ) -> Alignment {
        self.in_range(range.clone())
            .find(|(_, value)| **value != T::default())
            .map_or(alignment::MIN, |(part_id, _)| {
                part_id.alignment(output_sections)
            })
            .max(
                range
                    .start
                    .output_section_id::<P>()
                    .min_alignment(output_sections),
            )
    }

    /// Zip mutable references to values in `self` with shared references from `other` producing a
    /// new map with the returned values. For custom sections, `other` must be a subset of `self`.
    /// Values not in `other` will not be in the returned map.
    fn mut_with_map<U: Default, V: Default>(
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

        let Some(other_sparse) = other.sparse.as_ref() else {
            return OutputSectionPartMap {
                parts,
                sparse: None,
            };
        };

        let self_sparse = self.sparse.get_or_insert_with(|| {
            Box::new(SparsePartMap {
                contents: BTreeMap::new(),
            })
        });

        let contents = other_sparse
            .contents
            .iter()
            .map(|(part_id, right_value)| {
                let left_value = self_sparse.contents.entry(*part_id).or_default();
                (*part_id, cb(left_value, right_value))
            })
            .collect();

        OutputSectionPartMap {
            parts,
            sparse: Some(Box::new(SparsePartMap { contents })),
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (PartId, &T)> {
        self.parts
            .iter()
            .enumerate()
            .map(|(i, value)| (PartId::from_usize(i), value))
            .chain(
                self.sparse
                    .as_ref()
                    .map(|sparse| sparse.contents.iter())
                    .unwrap_or_default()
                    .map(|(part_id, value)| (*part_id, value)),
            )
    }
}

impl<T: AddAssign + Copy + Default> OutputSectionPartMap<T> {
    pub(crate) fn merge(&mut self, rhs: &Self) {
        for (left, right) in self.parts.iter_mut().zip(rhs.parts.iter()) {
            *left += *right;
        }

        if let Some(rhs_sparse) = rhs.sparse.as_ref() {
            let lhs_sparse = self.sparse.get_or_insert_default();
            for (part_id, right) in &rhs_sparse.contents {
                *lhs_sparse.contents.entry(*part_id).or_default() += *right;
            }
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
    use crate::elf::Elf64;

    let output_sections = crate::output_section_id::OutputSections::<Elf64>::for_testing();
    let (output_order, _program_segments) = output_sections
        .output_order(
            crate::output_kind::OutputKind::StaticExecutable(crate::args::RelocationModel::Fixed),
            &[],
            &[],
        )
        .unwrap();

    let mut part_map = output_sections.new_part_map::<u32>();
    for (section_id, _) in output_sections.ids_with_info() {
        if section_id.is_custom::<Elf64>() {
            let _ =
                part_map.get_mut(section_id.part_id_with_alignment::<Elf64>(crate::alignment::MIN));
        }
    }

    let mut expected_sum_of_sums = 0;
    let all_1 = part_map.output_order_map(&output_order, &output_sections, |_, _, _| {
        expected_sum_of_sums += 1;
        1
    });

    let mut num_sections_with_all_alignments = 0;

    let mut sum_of_1s = output_sections.new_section_map::<u32>();
    sum_of_1s.for_each_mut(|section_id, sum| {
        if !section_id.is_regular::<Elf64>()
            && <Elf64 as crate::platform::Platform>::single_part_id(section_id).is_none()
        {
            return;
        }
        let range = section_id.part_id_range::<Elf64>();
        *sum = all_1.values_in_range(range).sum();
    });

    let mut sum_of_sums = 0;
    sum_of_1s.for_each(|section_id, sum| {
        sum_of_sums += *sum;
        if *sum == crate::alignment::NUM_ALIGNMENTS as u32 {
            num_sections_with_all_alignments += 1;
        }

        let unsupported_single_part = !section_id.is_regular::<Elf64>()
            && <Elf64 as crate::platform::Platform>::single_part_id(section_id).is_none();

        let expected =
            if section_id == crate::output_section_id::UNMAPPED || unsupported_single_part {
                0
            } else if section_id.is_custom::<Elf64>() {
                1
            } else if section_id.is_regular::<Elf64>() {
                crate::alignment::NUM_ALIGNMENTS as u32
            } else {
                1
            };

        assert_eq!(*sum, expected, "Unexpected sum for section {section_id:?}");
    });
    assert_eq!(
        <Elf64 as Platform>::NUM_BUILT_IN_REGULAR_SECTIONS,
        num_sections_with_all_alignments
    );
    assert_eq!(sum_of_sums, expected_sum_of_sums);

    let mut headers_only = output_sections.new_part_map::<u32>();
    *headers_only.get_mut(crate::part_id::FILE_HEADER) += 42;

    let mut merged = output_sections.new_section_map::<u32>();
    merged.for_each_mut(|section_id, sum| {
        if !section_id.is_regular::<Elf64>()
            && <Elf64 as crate::platform::Platform>::single_part_id(section_id).is_none()
        {
            return;
        }
        let range = section_id.part_id_range::<Elf64>();
        *sum = headers_only.values_in_range(range).sum();
    });

    assert_eq!(*merged.get(crate::output_section_id::FILE_HEADER), 42);
    assert_eq!(*merged.get(crate::elf::output_section_id::TEXT), 0);
    assert_eq!(*merged.get(crate::elf::output_section_id::BSS), 0);
}

#[test]
fn test_mut_with_map() {
    let output_sections =
        crate::output_section_id::OutputSections::<crate::elf::Elf64>::for_testing();
    let mut input1 = output_sections.new_part_map::<u32>().map(|_, _| 1);
    let input2 = output_sections.new_part_map::<u32>().map(|_, _| 2);
    let expected = output_sections.new_part_map::<u32>().map(|_, _| 3);
    input1.mut_with_map(&input2, |a, b| *a += *b);
    assert_eq!(input1, expected);
}

#[test]
fn test_merge() {
    let output_sections =
        crate::output_section_id::OutputSections::<crate::elf::Elf64>::for_testing();
    let mut input1 = output_sections.new_part_map::<u32>().map(|_, _| 1);
    let input2 = output_sections.new_part_map::<u32>().map(|_, _| 2);
    let expected = output_sections.new_part_map::<u32>().map(|_, _| 3);
    input1.merge(&input2);
    assert_eq!(input1, expected);
}

/// output_order_map and `OutputSections::sections_and_segments_events` used to each independently
/// define the output order. This test made sure that they were consistent. Now the former uses the
/// latter, so this test is less important. It's kept for the time being anyway.
#[test]
fn test_output_order_map_consistent() {
    use crate::elf::Elf64;
    use itertools::Itertools;

    let output_sections =
        crate::output_section_id::OutputSections::<crate::elf::Elf64>::for_testing();
    let (output_order, _program_segments) = output_sections
        .output_order(
            crate::output_kind::OutputKind::StaticExecutable(crate::args::RelocationModel::Fixed),
            &[],
            &[],
        )
        .unwrap();
    let mut part_map = output_sections.new_part_map::<u32>();

    let custom_sections = output_sections
        .ids_with_info()
        .map(|(section_id, _)| section_id)
        .filter(|section_id| section_id.is_custom::<Elf64>())
        .collect_vec();

    for section_id in custom_sections.into_iter().rev() {
        let _ = part_map.get_mut(section_id.part_id_with_alignment::<Elf64>(crate::alignment::MIN));
    }

    // First, make sure that all our built-in part-ids are here. If they're not, we'd fail anyway,
    // but we can give a much better failure message if we check first.
    let mut missing: hashbrown::HashSet<PartId> =
        crate::part_id::built_in_part_ids::<Elf64>().collect();
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
                output_sections.display_name(id.output_section_id::<Elf64>())
            ))
            .collect_vec()
            .join(", ")
    );

    let mut ordering_a = Vec::new();
    part_map.output_order_map(&output_order, &output_sections, |part_id, _, _| {
        let section_id = part_id.output_section_id::<Elf64>();
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
    use crate::elf::Elf64;
    use crate::elf::output_section_id;

    let output_sections = crate::output_section_id::OutputSections::<Elf64>::for_testing();
    let (output_order, _program_segments) = output_sections
        .output_order(
            crate::output_kind::OutputKind::StaticExecutable(crate::args::RelocationModel::Fixed),
            &[],
            &[],
        )
        .unwrap();
    let mut part_map = output_sections.new_part_map::<u32>();

    const PART_ID1: PartId =
        output_section_id::DATA.part_id_with_alignment::<Elf64>(alignment::USIZE);
    *part_map.get_mut(PART_ID1) += 32;

    const PART_ID2: PartId =
        output_section_id::DATA.part_id_with_alignment::<Elf64>(alignment::MIN);
    *part_map.get_mut(PART_ID2) += 5;

    part_map.output_order_map(
        &output_order,
        &output_sections,
        |part_id, alignment, &value| match part_id {
            PART_ID1 => {
                assert_eq!(alignment, alignment::USIZE);
                assert_eq!(value, 32);
            }
            PART_ID2 => {
                assert_eq!(alignment, alignment::MIN);
                assert_eq!(value, 5);
            }
            _ => {
                if part_id.output_section_id::<Elf64>() == output_section_id::DATA {
                    assert!(
                        alignment <= alignment::USIZE,
                        "Unexpected alignment {alignment}"
                    );
                }
                assert_eq!(value, 0);
            }
        },
    );
}

#[test]
fn test_max_alignment() {
    use crate::elf::Elf64;
    use crate::elf::output_section_id;

    let output_sections = crate::output_section_id::OutputSections::<Elf64>::for_testing();
    let mut part_map = output_sections.new_part_map::<u32>();

    assert_eq!(
        part_map.max_alignment(
            output_section_id::DATA.part_id_range::<Elf64>(),
            &output_sections,
        ),
        alignment::MIN
    );

    const PART_ID1: PartId =
        output_section_id::DATA.part_id_with_alignment::<Elf64>(alignment::USIZE);
    *part_map.get_mut(PART_ID1) += 32;

    const PART_ID2: PartId =
        output_section_id::DATA.part_id_with_alignment::<Elf64>(alignment::MIN);
    *part_map.get_mut(PART_ID2) += 5;

    assert_eq!(
        part_map.max_alignment(
            output_section_id::DATA.part_id_range::<Elf64>(),
            &output_sections,
        ),
        alignment::USIZE
    );
}
