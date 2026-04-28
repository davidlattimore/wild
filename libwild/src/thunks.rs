//! Support for range-extension thunks.
//!
//! Thunks are needed when range-limited branch instructions are used, if the target of the branch
//! is outside that range. For example, on aarch64, many branches are limited to +/- 128 MiB.
//!
//! Our support for range-extension thunks makes some assumptions in order to be as efficient as
//! possible. The main assumption is that the bulk of the executable code will be placed into a
//! single output part. We call this part the primary-part. Its ID can be obtained from
//! `ThunkConfig::primary_function_part_id`. We assume that all the other executable code will be
//! before this primary part and that it'll fit within the range of a range-limited branch
//! instruction. This, we refer to as the non-primary parts. It includes functions with higher
//! alignment, the PLT, .init, .fini etc.
//!
//! When processing relocations, we check if a relocation is range-limited. If it is, then we handle
//! it in one of the following ways depending on whether the section containing the relocation is
//! mapped to the primary part and whether the definition symbol is contained in a section that's
//! mapped to the primary part.
//!
//! * Non-primary part references non-primary part: Assumed to be in range.
//! * Non-primary part references primary part: Stored in
//!   ThunkLayoutBuilder::non_primary_referenced_symbols.
//! * Prmary part references anything: ValueFlags::HAS_RANGE_LIMITED_REL set for local symbol in the
//!   object that made the reference.

use crate::input_data::FileId;
use crate::layout;
use crate::layout::FileLayoutState;
use crate::output_section_id::OutputSections;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::part_id::PartId;
use crate::platform::Arch;
use crate::platform::Platform;
use crate::platform::SectionAttributes as _;
use crate::resolution;
use crate::symbol_db::SymbolId;
use crate::timing_phase;
use crate::value_flags::FlagsForSymbol;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use crossbeam_queue::SegQueue;
use rayon::iter::IntoParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator as _;
use std::collections::HashSet;

/// Identifies a ThunkBlock within a Vec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ThunkBlockId(u32);

impl ThunkBlockId {
    /// The first ThunkBlock. Covers non-primary parts as well as the start of the primary part.
    pub(crate) const FIRST: ThunkBlockId = ThunkBlockId(0);

    pub(crate) fn as_usize(self) -> usize {
        self.0 as usize
    }
}

pub(crate) struct ThunkBlock {
    /// Sorted and deduplicated SymbolIds for which we need thunks.
    pub(crate) symbols: Vec<SymbolId>,
}

struct ThunkBlockBuilder<'data, 'state, P: Platform> {
    objects: Vec<&'state layout::ObjectLayoutState<'data, P>>,
    symbols: Vec<SymbolId>,
}

impl<'data, 'state, P: Platform> Default for ThunkBlockBuilder<'data, 'state, P> {
    fn default() -> Self {
        Self {
            objects: Vec::new(),
            symbols: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ThunkLayoutBuilder {
    /// The range beyond which we'll allocate thunks, allowing a bit of overhead for the thunks
    /// themselves.
    branch_range: u64,

    primary_function_part_id: PartId,

    /// Symbols that are defined in primary parts and referenced by range-limited relocations from
    /// non-primary parts.
    non_primary_referenced_symbols: SegQueue<SymbolId>,
}

/// How much space we allow for the thunks themselves in the thunk block. Note, we don't actually
/// allocate this much space. This is used for determining whether we might need a thunk for a
/// particular reference. i.e. we subtract this from the relocation range. At some stage, we may
/// want to try and get rid of this so that we have tighter bounds on when thunks are used. In that
/// case, a good starting bound would be a count of the number of symbols in each block where we set
/// ValueFlags::HAS_RANGE_LIMITED_REL.
const MAXIMUM_THUNK_BYTES_PER_BLOCK: u64 = 1024 * 1024;

impl ThunkLayoutBuilder {
    /// Creates a thunk layout builder or returns None if thunks either aren't supported or aren't
    /// needed.
    pub(crate) fn new<A: Arch>(
        groups: &[resolution::ResolvedGroup<A::Platform>],
    ) -> Option<ThunkLayoutBuilder> {
        let config = A::thunk_config()?;

        timing_phase!("Create thunk layout builder");

        let total_executable_bytes: u64 = groups
            .iter()
            .flat_map(|group| group.files.iter())
            .filter_map(|file| {
                if let resolution::ResolvedFile::Object(obj) = file {
                    Some(obj.executable_bytes)
                } else {
                    None
                }
            })
            .sum();

        if total_executable_bytes < config.min_branch_range {
            // Total text size is small enough that we know we won't need any thunks.
            return None;
        }

        Some(ThunkLayoutBuilder {
            branch_range: config.min_branch_range - MAXIMUM_THUNK_BYTES_PER_BLOCK,
            primary_function_part_id: config.primary_function_part_id,
            non_primary_referenced_symbols: SegQueue::new(),
        })
    }

    /// Assigns thunk blocks to objects and builds the final `Vec<ThunkBlock>`.
    pub(crate) fn build<'data, P: Platform>(
        mut self,
        group_states: &mut [layout::GroupState<'data, P>],
        symbol_db: &crate::symbol_db::SymbolDb<'data, P>,
        per_symbol_flags: &crate::value_flags::PerSymbolFlags,
        output_sections: &OutputSections<P>,
        section_part_sizes: &OutputSectionPartMap<u64>,
    ) -> Vec<ThunkBlock> {
        timing_phase!("Build thunk layout");

        let non_primary_text_size =
            self.compute_non_primary_text_size(output_sections, section_part_sizes);

        let primary_ranges = collect_primary_ranges(group_states, non_primary_text_size);

        let mut block_builders =
            assign_thunk_blocks_to_groups(group_states, &primary_ranges, self.branch_range);

        self.process_primary_part_refs(
            &primary_ranges,
            symbol_db,
            per_symbol_flags,
            &mut block_builders,
        );

        self.process_non_primary_part_refs(&mut block_builders);

        let blocks = block_builders
            .into_par_iter()
            .map(|block| block.build())
            .collect();

        tracing::trace!("Thunk blocks: {blocks:#?}");

        blocks
    }

    fn compute_non_primary_text_size<P: Platform>(
        &self,
        output_sections: &OutputSections<P>,
        section_part_sizes: &OutputSectionPartMap<u64>,
    ) -> u64 {
        verbose_timing_phase!("Compute non-primary text size");

        let non_primary_text_bytes: u64 = output_sections
            .ids_with_info()
            .filter(|(_, info)| info.section_attributes.is_executable())
            .flat_map(|(section_id, _)| {
                let base = section_id.base_part_id();
                (0..section_id.num_parts()).map(move |i| base.offset(i))
            })
            .filter(|&part_id| part_id != self.primary_function_part_id)
            .map(|part_id| *section_part_sizes.get(part_id))
            .sum();
        non_primary_text_bytes
    }

    fn process_non_primary_part_refs<P: Platform>(
        &mut self,
        block_builders: &mut [ThunkBlockBuilder<'_, '_, P>],
    ) {
        verbose_timing_phase!("Process non-primary part refs");

        block_builders[ThunkBlockId::FIRST.as_usize()]
            .symbols
            .extend(core::mem::take(&mut self.non_primary_referenced_symbols));
    }

    fn process_primary_part_refs<'data, P: Platform>(
        &self,
        primary_ranges: &[Vec<Option<(u64, u64)>>],
        symbol_db: &crate::symbol_db::SymbolDb<'data, P>,
        per_symbol_flags: &crate::value_flags::PerSymbolFlags,
        block_builders: &mut [ThunkBlockBuilder<'data, '_, P>],
    ) {
        verbose_timing_phase!("Process primary part refs");

        let primary_range_for_symbol = |definition_id: SymbolId| -> Option<(u64, u64)> {
            let definition_flags = per_symbol_flags.flags_for_symbol(definition_id);

            if definition_flags.contains(ValueFlags::IFUNC)
                || definition_flags.contains(ValueFlags::DYNAMIC)
                || symbol_db.part_id_for_symbol(definition_id) != self.primary_function_part_id
            {
                return None;
            }

            let fid = symbol_db.file_id_for_symbol(definition_id);
            primary_ranges[fid.group()][fid.file()]
        };

        // Returns true if a thunk can be skipped based on known source and definition positions.
        let provably_in_range = |src_start: u64, src_end: u64, definition_id: SymbolId| -> bool {
            let definition_flags = per_symbol_flags.flags_for_symbol(definition_id);
            if definition_flags.contains(ValueFlags::DYNAMIC) {
                // For dynamic targets (e.g. PLT), source distance depends on pre-.text executable
                // bytes that aren't captured by primary ranges alone.
                return false;
            }

            if let Some((def_start, def_end)) = primary_range_for_symbol(definition_id) {
                let span_start = src_start.min(def_start);
                let span_end = src_end.max(def_end);
                return span_end.saturating_sub(span_start) < self.branch_range;
            }

            src_end < self.branch_range
        };

        // Collect primary-section range-limited symbols by scanning each block's objects in
        // parallel, then reducing object-local symbol sets into one set per block.
        block_builders.into_par_iter().for_each(|block| {
            let symbols = block
                .objects
                .par_iter()
                .map(|obj| {
                    verbose_timing_phase!("Collect object primary part thunks");

                    let mut object_symbols = HashSet::new();
                    for (i, raw_flags) in per_symbol_flags
                        .raw_range(obj.symbol_id_range)
                        .iter()
                        .enumerate()
                    {
                        if !raw_flags.get().contains(ValueFlags::HAS_RANGE_LIMITED_REL) {
                            continue;
                        }

                        let local_symbol_id = obj.symbol_id_range.offset_to_id(i);
                        let definition_id = symbol_db.definition(local_symbol_id);
                        let Some((src_start, src_end)) =
                            primary_ranges[obj.file_id.group()][obj.file_id.file()]
                        else {
                            continue;
                        };

                        if !provably_in_range(src_start, src_end, definition_id) {
                            object_symbols.insert(definition_id);
                        }
                    }
                    object_symbols
                })
                .reduce(HashSet::new, |mut a, mut b| {
                    verbose_timing_phase!("Merge thunk block symbols");

                    if b.len() > a.len() {
                        std::mem::swap(&mut a, &mut b);
                    }
                    a.extend(b);
                    a
                });

            block.symbols.extend(symbols);
        });
    }
}

fn collect_primary_ranges<P: Platform>(
    group_states: &[layout::GroupState<P>],
    initial_offset: u64,
) -> Vec<Vec<Option<(u64, u64)>>> {
    let mut offset = initial_offset;
    group_states
        .iter()
        .map(|group| {
            group
                .files
                .iter()
                .map(|file| {
                    if let FileLayoutState::Object(obj) = file {
                        let start = offset;
                        let end = start + obj.post_gc_primary_bytes;
                        offset = end;
                        Some((start, end))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .collect()
}

/// Records that a thunkable relocation was encountered during the GC phase. The actual decision
/// about whether a thunk is needed is deferred to `ThunkLayoutBuilder::build()`.
pub(crate) fn handle_thunk_extensions_for_relocation<A: Arch>(
    section_part_id: PartId,
    resources: &layout::GraphResources<'_, '_, A::Platform>,
    local_symbol_id: SymbolId,
    symbol_id: SymbolId,
    r_type: u32,
) {
    if resources.thunk_layout_builder.is_some()
        && let Some(config) = A::thunk_config()
        && let Some(rel_info) = A::relocation_from_raw(r_type).ok()
        && rel_info.thunkable
    {
        if section_part_id == config.primary_function_part_id {
            resources
                .per_symbol_flags
                .get_atomic(local_symbol_id)
                .or_assign(ValueFlags::HAS_RANGE_LIMITED_REL);
        } else {
            let canonical_symbol_id = resources.symbol_db.definition(symbol_id);
            if resources.symbol_db.part_id_for_symbol(canonical_symbol_id)
                == config.primary_function_part_id
            {
                resources
                    .thunk_layout_builder
                    .as_ref()
                    .unwrap()
                    .non_primary_referenced_symbols
                    .push(canonical_symbol_id);
            }
        }
    }
}

fn assign_thunk_blocks_to_groups<'data, 'state, P: Platform>(
    group_states: &'state mut [layout::GroupState<'data, P>],
    primary_ranges: &[Vec<Option<(u64, u64)>>],
    max_branch_range: u64,
) -> Vec<ThunkBlockBuilder<'data, 'state, P>> {
    verbose_timing_phase!("Assign thunk blocks");

    let post_gc_bounds: Vec<(FileId, u64, u64)> = group_states
        .iter()
        .enumerate()
        .flat_map(|(group_id, group)| {
            group
                .files
                .iter()
                .enumerate()
                .filter_map(move |(file_id, file)| match file {
                    FileLayoutState::Object(obj) => {
                        let (start, end) = primary_ranges[group_id][file_id]?;
                        (end > start).then_some((obj.file_id, start, end))
                    }
                    _ => None,
                })
        })
        .collect();

    let num_blocks = assign_thunk_blocks(
        post_gc_bounds.iter().copied(),
        max_branch_range,
        |fid, bid, is_owner| {
            if let FileLayoutState::Object(obj) = &mut group_states[fid.group()].files[fid.file()] {
                obj.thunk_block_id = bid;
                obj.owns_thunk_block = is_owner;
            }
        },
    );

    let mut block_builders: Vec<ThunkBlockBuilder<'data, 'state, P>> = (0..num_blocks.max(1))
        .map(|_| ThunkBlockBuilder::default())
        .collect();

    for group in group_states.iter() {
        for file in &group.files {
            if let FileLayoutState::Object(obj) = file
                && obj.post_gc_primary_bytes > 0
            {
                block_builders[obj.thunk_block_id.as_usize()]
                    .objects
                    .push(obj);
            }
        }
    }

    block_builders
}

/// Assigns objects to thunk blocks based on their post-GC positions.
///
/// `objects` yields `(file_id, start, end)` for each object in order of increasing address.
/// `assign` is called for every object with `(file_id, block_id, is_owner)`.
/// Returns the number of blocks created.
fn assign_thunk_blocks(
    objects: impl Iterator<Item = (FileId, u64, u64)>,
    max_branch_range: u64,
    mut assign: impl FnMut(FileId, ThunkBlockId, bool),
) -> usize {
    let mut num_blocks: usize = 0;

    let mut iter = objects;

    let Some((first_file_id, _first_start, first_end)) = iter.next() else {
        return num_blocks;
    };

    // ThunkBlock::FIRST is always owned by the first object.
    num_blocks += 1;
    assign(first_file_id, ThunkBlockId::FIRST, true);

    // We alternate between "previous" mode (pending_next==None) and "next" mode. While in previous
    // mode, we assign objects to the previous thunk block. While in next mode, we assign objects to
    // the next block, which we haven't yet decided exactly where it will go. Whenever adding a new
    // object might put something out-of-range, we switch modes.
    let mut prev_block_id = ThunkBlockId::FIRST;
    let mut prev_block_pos = first_end;
    // Tracks an unplaced "next" block: (block_id, first_file_id_using_it, first_object_start).
    let mut pending_next: Option<(ThunkBlockId, FileId, u64)> = None;

    for (file_id, start, end) in iter {
        if let Some((next_id, first_file_id, first_object_start)) = pending_next {
            if end - first_object_start >= max_branch_range {
                // Block is placed on this object: it becomes the owner and switches to "previous".
                assign(first_file_id, next_id, false);
                assign(file_id, next_id, true);
                prev_block_id = next_id;
                prev_block_pos = end;
                pending_next = None;
            } else {
                assign(file_id, next_id, false);
                pending_next = Some((next_id, first_file_id, first_object_start));
            }
        } else if end - prev_block_pos >= max_branch_range {
            let next_id = ThunkBlockId(num_blocks as u32);
            num_blocks += 1;
            pending_next = Some((next_id, file_id, start));
        } else {
            assign(file_id, prev_block_id, false);
        }
    }

    // If the loop ended with a pending next block that never needed splitting, the first object
    // using it becomes the owner (block is effectively at the start of this group).
    if let Some((next_id, first_file_id, _)) = pending_next {
        assign(first_file_id, next_id, true);
    }

    num_blocks
}

impl<'data, 'state, P: Platform> ThunkBlockBuilder<'data, 'state, P> {
    fn build(mut self) -> ThunkBlock {
        verbose_timing_phase!("Build thunk block");
        // Sorting is needed for deterministic output, since the symbols came here in hashset
        // iteration order. Deduplication has mostly already occurred, but the non-primary hasn't
        // yet been deduplicated against other thunks for the first block.
        self.symbols.sort();
        self.symbols.dedup();
        ThunkBlock {
            symbols: self.symbols,
        }
    }
}

impl std::fmt::Debug for ThunkBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ThunkBlock with {} thunks", self.symbols.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_objects(offsets_and_sizes: &[(u64, u64)]) -> Vec<(FileId, u64, u64)> {
        offsets_and_sizes
            .iter()
            .enumerate()
            .map(|(i, &(start, size))| (FileId::new(0, i as u32), start, start + size))
            .collect()
    }

    #[test]
    fn test_assign_thunk_blocks_single_cluster() {
        // 3 objects all within max_range=1000: single ThunkBlock owned by first object.
        let mut assignments: HashMap<FileId, (ThunkBlockId, bool)> = HashMap::new();
        let num_blocks = assign_thunk_blocks(
            make_objects(&[(0, 100), (100, 100), (200, 100)]).into_iter(),
            1000,
            |fid, bid, is_owner| {
                assignments.insert(fid, (bid, is_owner));
            },
        );
        assert_eq!(num_blocks, 1);
        assert_eq!(assignments[&FileId::new(0, 0)], (ThunkBlockId(0), true));
        for f in 1..3 {
            assert_eq!(assignments[&FileId::new(0, f as u32)].0, ThunkBlockId(0));
        }
    }

    #[test]
    fn test_assign_thunk_blocks_placement() {
        // 5 objects. Objects 0,1 are in range of block #0. Object 2 goes out of range,
        // so we start block #1 (tentatively assigned to 2). Object 4's end goes out of range
        // of first_object_start (object 2's offset), so block #1 is placed on object 4.
        let mut assignments: HashMap<FileId, ThunkBlockId> = HashMap::new();
        let mut owners: HashMap<ThunkBlockId, FileId> = HashMap::new();
        let num_blocks = assign_thunk_blocks(
            make_objects(&[(0, 100), (300, 100), (600, 100), (900, 100), (1200, 100)]).into_iter(),
            500,
            |fid, bid, is_owner| {
                assignments.insert(fid, bid);
                if is_owner {
                    owners.insert(bid, fid);
                }
            },
        );
        assert_eq!(num_blocks, 2);
        assert_eq!(owners[&ThunkBlockId(0)], FileId::new(0, 0));
        assert_eq!(owners[&ThunkBlockId(1)], FileId::new(0, 4));
        assert_eq!(assignments[&FileId::new(0, 0)], ThunkBlockId(0));
        assert_eq!(assignments[&FileId::new(0, 1)], ThunkBlockId(0));
        assert_eq!(assignments[&FileId::new(0, 2)], ThunkBlockId(1));
        assert_eq!(assignments[&FileId::new(0, 3)], ThunkBlockId(1));
        assert_eq!(assignments[&FileId::new(0, 4)], ThunkBlockId(1));
    }
}
