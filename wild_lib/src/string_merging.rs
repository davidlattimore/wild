//! Input sections that are marked as string-merge sections need special processing. Our algorithm
//! is somewhat complicated in an attempt to get good performance. A rough outline of our algorithm
//! is here with more details throughout the code.
//!
//! We group input sections by the output section into which they are to be placed. We then process
//! each output section one at a time.
//!
//! Taking all the input sections for a particular output section, we group adjacent input sections
//! so that each group has a roughly similar size in bytes.
//!
//! With multiple threads, we alternate between two phases:
//!
//! Phase 1: We split input sections by looking for null terminators, then we hash the resulting
//! string and store it in a bucket based on its hash.
//!
//! Phase 2: We take the outputs of phase 1 and insert the strings into a hashmap for the bucket
//! that the string is in. We then update an offset map that maps input offsets to bucket-relative
//! outputs.
//!
//! Threads can switch between phases multiple times until all work for the section is complete. At
//! that point, we do some finishing work single-threaded such as computing the starting offset of
//! each bucket and populating a hashmap from input to output offset for any offsets that didn't fit
//! in our primary offset map.

use crate::alignment;
use crate::args::Args;
use crate::error::Result;
use crate::hash::PassThroughHashMap;
use crate::hash::PreHashed;
use crate::output_section_id::OutputSections;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::part_id::PartId;
use crate::resolution::ResolvedFile;
use crate::resolution::ResolvedGroup;
use crate::resolution::SectionSlot;
use ahash::HashMap;
use anyhow::bail;
use anyhow::Context;
use crossbeam_queue::ArrayQueue;
use crossbeam_utils::atomic::AtomicCell;
use itertools::Itertools as _;
use object::read::elf::Sym as _;
use object::LittleEndian;
use sharded_offset_map::OffsetMap;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

/// The maximum number of input section groups we'll split before we start putting groups into
/// buckets. A higher value will mean it's longer before we can reuse the associated heap
/// allocations, so will likely result in more heap allocations.
const MAX_INPUT_GROUPS_BEFORE_BUCKETING: u32 = 2;

/// Approximate number of groups each thread will process. Smaller numbers will result in larger
/// groups, which tends to improve cache performance but makes it harder to balance work between
/// threads.
const APPROXIMATE_GROUPS_PER_THREAD: usize = 16;

/// Setting this to a higher value increases the potential for parallelism of hash table population
/// and possibly gives better cache performance. However, it also increases heap allocations.
/// Changing this value will result in a different ordering of strings within the output file.
const MERGE_STRING_BUCKET_BITS: usize = 5;
const MERGE_STRING_BUCKETS: usize = 1 << MERGE_STRING_BUCKET_BITS;

/// Number of input offsets to represent by a single block. A block can store up to 12 offsets. If
/// we get more than 12 offsets within a block, then we need to spill the offset to a hashmap.
/// Increasing this value decreases memory usage, however it may result in more offsets being
/// spilled to the hashmap.
const MAP_BLOCK_SIZE: u64 = 256;

#[derive(Clone, Copy)]
pub(crate) struct StringMergeSectionSlot {
    pub(crate) part_id: PartId,

    /// The sum of the sizes of the input sections prior to this one with the same `part_id`.
    /// Populated during string merging.
    start_input_offset: LinearInputOffset,
}

impl StringMergeSectionSlot {
    pub(crate) fn new(part_id: PartId) -> Self {
        Self {
            part_id,
            // We'll fill this in during string merging.
            start_input_offset: LinearInputOffset(0),
        }
    }
}

/// Extra stuff that we don't want to put in `StringMergeSectionSlot` because like all section
/// slots, we want to keep it as small as possible.
pub(crate) struct StringMergeSectionExtra<'data> {
    pub(crate) index: object::SectionIndex,
    pub(crate) section_data: &'data [u8],
}

/// An input offset. We pretend that we've placed all input sections for a given output section one
/// after the other. This offset is then the offset into that space.
#[derive(Copy, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct LinearInputOffset(u64);

impl std::ops::Add<u64> for LinearInputOffset {
    type Output = LinearInputOffset;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

#[derive(Clone, Copy)]
struct StringMergeInputSection<'data> {
    section_data: &'data [u8],

    /// The sum of the sizes of the input sections prior to this one with the same `part_id`.`
    start_input_offset: LinearInputOffset,
}

/// A string from a string-merge section. Includes the null terminator.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(crate) struct MergeString<'data> {
    bytes: &'data [u8],
}

/// The addresses of the start of the merged strings for each output section.
pub(crate) struct MergedStringStartAddresses {
    addresses: OutputSectionMap<[u64; MERGE_STRING_BUCKETS]>,
}

/// A section containing null terminated strings post-merging.
pub(crate) struct MergedStringsSection<'data> {
    /// The buckets based on the hash value of the input string.
    pub(crate) buckets: Vec<MergeStringsSectionBucket<'data>>,

    /// The byte offset of each bucket in the final section.
    pub(crate) bucket_offsets: [u64; MERGE_STRING_BUCKETS],

    /// Map from input offsets to output offsets.
    string_offsets: OffsetMap<BucketOffset, MAP_BLOCK_SIZE>,

    /// Offsets of strings that didn't fit in `string_offsets`.
    overflowed_string_offsets: HashMap<LinearInputOffset, BucketOffset>,
}

impl Default for MergedStringsSection<'_> {
    fn default() -> Self {
        Self {
            buckets: Default::default(),
            bucket_offsets: [0; MERGE_STRING_BUCKETS],
            string_offsets: Default::default(),
            overflowed_string_offsets: HashMap::with_hasher(ahash::RandomState::new()),
        }
    }
}

#[derive(Default)]
pub(crate) struct MergeStringsSectionBucket<'data> {
    index: usize,

    /// Input sections need to be added to a bucket in deterministic order, otherwise we'll get
    /// non-deterministic results. This is the index of the next input group that should be added.
    next_input_group_index: usize,

    /// The strings in this section in order. Includes null terminators.
    pub(crate) strings: Vec<&'data [u8]>,

    /// The offset within the section of the next string to be added, or if we're done adding
    /// things, then this is the size of the output section.
    pub(crate) next_offset: u32,

    /// The total size of all added strings, used for statistics.
    pub(crate) input_string_byte_size: usize,

    /// The total number of all added strings, used for statistics.
    pub(crate) input_string_count: usize,

    /// The offsets of each string in the output section keyed by the string contents.
    pub(crate) string_offsets: PassThroughHashMap<MergeString<'data>, u32>,
}

/// Merges identical strings from all loaded objects where those strings are from input sections
/// that are marked with both the SHF_MERGE and SHF_STRINGS flags.
#[tracing::instrument(skip_all, name = "Merge strings")]
pub(crate) fn merge_strings<'data>(
    resolved: &mut [ResolvedGroup<'data>],
    output_sections: &OutputSections,
    args: &Args,
) -> Result<OutputSectionMap<MergedStringsSection<'data>>> {
    let input_sections_by_output =
        group_merge_string_sections_by_output(resolved, output_sections)?;

    let mut output_string_sections = output_sections.new_section_map::<MergedStringsSection>();

    let reuse_pool = ReusePool::new();

    input_sections_by_output.try_for_each(|section_id, input_sections| {
        let output_section = output_string_sections.get_mut(section_id);
        output_section.add_input_sections(input_sections, args, &reuse_pool)
    })?;

    output_string_sections.for_each(|section_id, sec| {
        if sec.len() > 0 {
            tracing::debug!(target: "metrics",
                section = ?output_sections.name(section_id),
                string_count = sec.string_count(),
                byte_size = sec.len(),
                input_string_count = sec.input_string_count(),
                input_string_byte_size = sec.input_string_byte_size(),
                output_map_overflow = sec.overflowed_string_offsets.len(),
                "merge_strings");
        }
    });

    tracing::debug!(target: "metrics",
        reused = reuse_pool.reused.load(Ordering::Relaxed),
        reuse_drop = reuse_pool.dropped.load(Ordering::Relaxed),
        created = reuse_pool.strings_by_bucket.len()
            + reuse_pool.dropped.load(Ordering::Relaxed) as usize,
        "merge_strings");

    reuse_pool.drop_in_background();

    Ok(output_string_sections)
}

// Gather up all the string-merge sections, grouping them by their output section ID. We return a
// reference to the `MergeStringsFileSection` rather than copying it because it appears to be
// faster.
fn group_merge_string_sections_by_output<'data>(
    resolved: &mut [ResolvedGroup<'data>],
    output_sections: &OutputSections,
) -> Result<OutputSectionMap<Vec<StringMergeInputSection<'data>>>> {
    let mut input_sections = output_sections.new_section_map::<Vec<StringMergeInputSection>>();

    let mut starting_offsets = output_sections.new_section_map::<LinearInputOffset>();

    for group in resolved {
        for file in &mut group.files {
            let ResolvedFile::Object(obj) = file else {
                continue;
            };
            let Some(non_dynamic) = obj.non_dynamic.as_mut() else {
                continue;
            };
            for extra in &non_dynamic.string_merge_extras {
                let SectionSlot::MergeStrings(sec) = &mut non_dynamic.sections[extra.index.0]
                else {
                    bail!("Internal error: expected SectionSlot::MergeStrings");
                };

                let section_id = sec.part_id.output_section_id();
                let starting_offset = starting_offsets.get_mut(section_id);
                sec.start_input_offset = *starting_offset;

                input_sections
                    .get_mut(section_id)
                    .push(StringMergeInputSection {
                        section_data: extra.section_data,
                        start_input_offset: *starting_offset,
                    });

                *starting_offset = *starting_offset
                    + (extra.section_data.len() as u64).next_multiple_of(MAP_BLOCK_SIZE);
            }
        }
    }

    Ok(input_sections)
}

#[derive(Clone)]
struct StringToMerge<'data> {
    string: PreHashed<MergeString<'data>>,
    offset_key: OffsetKey,
}

#[derive(Clone, Copy)]
enum OffsetKey {
    OffsetInShard(sharded_offset_map::OffsetInShard),
    Overflow(LinearInputOffset),
}

struct SectionGroup<'data, 'offsets, 'sections> {
    index: usize,
    sections: &'sections [StringMergeInputSection<'data>],
    offsets_shard: sharded_offset_map::Shard<'offsets, BucketOffset, MAP_BLOCK_SIZE>,
}

/// The outputs of splitting one input section.
struct SplitOutput<'data, 'offsets> {
    strings_by_bucket: Box<StringsByBucket<'data>>,
    offsets_shard: sharded_offset_map::Shard<'offsets, BucketOffset, MAP_BLOCK_SIZE>,
    buckets_processed: usize,
}

#[derive(Clone)]
struct StringsByBucket<'data> {
    buckets: [Vec<StringToMerge<'data>>; MERGE_STRING_BUCKETS],
}

impl StringsByBucket<'_> {
    fn clear(&mut self) {
        for b in &mut self.buckets {
            b.clear();
        }
    }
}

impl<'data> SplitOutput<'data, '_> {
    /// Split an input section into strings and hash those strings, collecting the results into
    /// buckets based on the string hashes.
    fn process_input_section(&mut self, input_section: &StringMergeInputSection<'data>) -> Result {
        let mut input_offset = input_section.start_input_offset;
        let mut remaining = input_section.section_data;
        while !remaining.is_empty() {
            let string = MergeString::take_hashed(&mut remaining)?;
            // Insert 0, then we'll update it later once we know the output offset. We do the
            // initial insertion now since insertions need to happen in sequential order, whereas by
            // the time we know the output offset, we're processing just a single bucket.
            let offset_key = match self.offsets_shard.insert(input_offset.0, BucketOffset(0)) {
                Ok(offset_in_shard) => OffsetKey::OffsetInShard(offset_in_shard),
                Err(_) => OffsetKey::Overflow(input_offset),
            };
            self.strings_by_bucket.buckets[(string.hash() as usize) % MERGE_STRING_BUCKETS]
                .push(StringToMerge { string, offset_key });
            input_offset = input_offset + string.bytes.len() as u64;
        }
        Ok(())
    }
}

type SplitOutputCell<'data, 'offsets> = AtomicCell<Option<Box<SplitOutput<'data, 'offsets>>>>;

const _: () = assert!(SplitOutputCell::is_lock_free());

impl<'data> MergedStringsSection<'data> {
    fn add_input_sections(
        &mut self,
        input_sections: &[StringMergeInputSection<'data>],
        args: &Args,
        reuse_pool: &ReusePool<'data>,
    ) -> Result {
        // We later create ArrayQueues with capacity for all input sections and ArrayQueue panics if
        // asked for zero capacity. Also, spawning tasks and all the other work we do here would be
        // a waste if we have no input sections.
        if input_sections.is_empty() {
            return Ok(());
        }

        let num_threads = args.num_threads.get();

        let mut resources = create_split_resources(
            &mut self.string_offsets,
            input_sections,
            num_threads,
            reuse_pool,
        );

        let (error_tx, error_rx) = std::sync::mpsc::channel();

        // Spawn a task for each thread.
        crate::threading::scope(|s| {
            for _ in 0..num_threads {
                s.spawn(|_| {
                    if let Err(error) = do_splitting_work(&resources) {
                        let _ = error_tx.send(error);
                    }
                });
            }
        });

        // Check if we got any errors. We only look at the first error. First we need to drop our
        // sender, otherwise the recv will block forever.
        drop(error_tx);
        if let Ok(error) = error_rx.recv() {
            return Err(error);
        }

        // Handle any offsets that didn't fit in their respective blocks in the offset map.
        let overflow = core::mem::replace(&mut resources.overflowed_offsets, ArrayQueue::new(1));
        overflow.into_iter().flatten().for_each(|o| {
            self.overflowed_string_offsets.insert(o.input, o.output);
        });

        // Move our buckets out of `resources` and convert it to a regular Vec.
        let mut buckets = resources
            .finished_buckets
            .into_iter()
            .map(|b| *b)
            .collect_vec();
        buckets.sort_by_key(|b| b.index);
        self.buckets = buckets;

        // Compute the starting offset of each bucket.
        for i in 1..MERGE_STRING_BUCKETS {
            self.bucket_offsets[i] =
                self.bucket_offsets[i - 1] + u64::from(self.buckets[i - 1].next_offset);
        }

        Ok(())
    }

    /// Returns the size in bytes of this section.
    pub(crate) fn len(&self) -> u64 {
        self.buckets
            .last()
            .map(|last_bucket| {
                u64::from(last_bucket.next_offset) + self.bucket_offsets[last_bucket.index]
            })
            .unwrap_or_default()
    }

    pub(crate) fn input_string_byte_size(&self) -> usize {
        self.buckets.iter().map(|b| b.input_string_byte_size).sum()
    }

    pub(crate) fn input_string_count(&self) -> usize {
        self.buckets.iter().map(|b| b.input_string_count).sum()
    }

    pub(crate) fn string_count(&self) -> usize {
        self.buckets.iter().map(|b| b.strings.len()).sum()
    }
}

struct SplitResources<'data, 'offsets, 'reuse_pool, 'sections> {
    num_input_groups: usize,
    unprocessed: ArrayQueue<SectionGroup<'data, 'offsets, 'sections>>,
    split_outputs: Vec<AtomicCell<Option<Box<SplitOutput<'data, 'offsets>>>>>,
    finished_buckets: ArrayQueue<Box<MergeStringsSectionBucket<'data>>>,
    in_progress_buckets: ArrayQueue<Box<MergeStringsSectionBucket<'data>>>,
    overflowed_offsets: ArrayQueue<Vec<OverflowedOffset>>,
    offset_writer: Mutex<sharded_offset_map::ShardedWriter<'offsets, BucketOffset, MAP_BLOCK_SIZE>>,
    reuse_pool: &'reuse_pool ReusePool<'data>,
}

fn create_split_resources<'data, 'offsets, 'reuse_pool, 'sections>(
    string_offsets: &'offsets mut OffsetMap<BucketOffset, MAP_BLOCK_SIZE>,
    input_sections: &'sections [StringMergeInputSection<'data>],
    num_threads: usize,
    reuse_pool: &'reuse_pool ReusePool<'data>,
) -> SplitResources<'data, 'offsets, 'reuse_pool, 'sections> {
    let input_size = total_input_size(input_sections);
    let mut offset_writer = string_offsets.start_sharded_write(input_size.0);

    let target_group_size = compute_target_group_size(input_size, num_threads) as u64;
    let unprocessed: ArrayQueue<SectionGroup> =
        ArrayQueue::new(APPROXIMATE_GROUPS_PER_THREAD * num_threads);

    let mut group_start_index = 0;
    let mut group_size = 0;

    input_sections
        .iter()
        .enumerate()
        .for_each(|(index, section)| {
            let size = (section.section_data.len() as u64).next_multiple_of(MAP_BLOCK_SIZE);
            let is_last_section = index == input_sections.len() - 1;
            let space_remaining = unprocessed.capacity() - unprocessed.len();

            let mut group_end_index = index;

            let new_size = group_size + size;
            let mut should_end_group = new_size > target_group_size
                && new_size.abs_diff(target_group_size) > size.abs_diff(target_group_size)
                && group_size > 0
                && space_remaining >= 2;

            if is_last_section {
                group_size += size;
                should_end_group = true;
                group_end_index += 1;
            }

            if should_end_group {
                let first_section = &input_sections[group_start_index];
                let last_section = &input_sections[group_end_index - 1];
                let offsets_shard = offset_writer.take_shard(
                    last_section.start_input_offset.0 - first_section.start_input_offset.0
                        + (last_section.section_data.len() as u64).next_multiple_of(MAP_BLOCK_SIZE),
                );

                let r = unprocessed.push(SectionGroup {
                    index: unprocessed.len(),
                    sections: &input_sections[group_start_index..group_end_index],
                    offsets_shard,
                });
                // We shouldn't have ended the previous group if that would have resulted in there
                // being no more space.
                assert!(r.is_ok());

                group_size = 0;
                group_start_index = group_end_index;
            }

            group_size += size;
        });

    let split_outputs = (0..input_sections.len())
        .map(|_| SplitOutputCell::new(None))
        .collect_vec();

    let in_progress_buckets: ArrayQueue<Box<MergeStringsSectionBucket>> =
        ArrayQueue::new(MERGE_STRING_BUCKETS);
    (0..MERGE_STRING_BUCKETS).for_each(|i| {
        let _ = in_progress_buckets.push(Box::new(MergeStringsSectionBucket::new(i)));
    });

    let overflowed_offsets = ArrayQueue::new(num_threads);

    SplitResources {
        num_input_groups: unprocessed.len(),
        unprocessed,
        split_outputs,
        finished_buckets: ArrayQueue::new(MERGE_STRING_BUCKETS),
        in_progress_buckets,
        overflowed_offsets,
        offset_writer: Mutex::new(offset_writer),
        reuse_pool,
    }
}

fn compute_target_group_size(input_size: LinearInputOffset, num_threads: usize) -> usize {
    1.max(input_size.0 as usize / num_threads / APPROXIMATE_GROUPS_PER_THREAD)
}

/// Holds instances of data structures that we reuse where possible. This allows us to reduce the
/// number of separate heap allocations we make.
struct ReusePool<'data> {
    strings_by_bucket: ArrayQueue<Box<StringsByBucket<'data>>>,

    /// The number of `StringsByBucket` instances that have been successfully reused.
    reused: AtomicU32,

    /// The number of `StringsByBucket` instances that were dropped because our array queue wasn't
    /// big enough.
    dropped: AtomicU32,
}

impl<'data> ReusePool<'data> {
    fn new() -> Self {
        Self {
            strings_by_bucket: ArrayQueue::new(256),
            reused: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
        }
    }

    fn return_strings_by_bucket(&self, mut strings_by_bucket: Box<StringsByBucket<'data>>) {
        strings_by_bucket.clear();

        // If our queue is full, that's OK, we just drop the value.
        let r = self.strings_by_bucket.push(strings_by_bucket);
        if r.is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn new_strings_by_bucket(&self) -> Box<StringsByBucket<'data>> {
        self.strings_by_bucket
            .pop()
            .inspect(|_| {
                self.reused.fetch_add(1, Ordering::Relaxed);
            })
            .unwrap_or_else(|| {
                Box::new(StringsByBucket {
                    buckets: [(); MERGE_STRING_BUCKETS].map(|()| Vec::new()),
                })
            })
    }

    /// Drops storage of this pool in the background.
    #[tracing::instrument(skip_all, name = "Start background string-merge pool drop")]
    fn drop_in_background(self) {
        /// A placeholder type with the same size and alignment as `StringToMerge`, but with no lifetime.
        #[derive(Default)]
        struct StringToMergePlaceholder {
            _v: [u64; size_of::<StringToMerge>() / 8],
        }

        // Make sure our placeholder has the same size and alignment as `StringToMerge` otherwise
        // we'll end up making new heap allocations which would defeat the purpose.
        const _: () = {
            assert!(size_of::<StringToMerge>() == size_of::<StringToMergePlaceholder>());
            assert!(align_of::<StringToMerge>() == align_of::<StringToMergePlaceholder>());
        };

        // Convert our vectors in-place to types without an associated lifetime. This conversion
        // should take very little time. We monitor the time it takes above just to make sure. From
        // experiments on a large link, actually dropping can take around 174ms, whereas what we do
        // here takes around 0.03ms. We still have to pay to do the full drop, but it can be done
        // concurrently, whereas if we waited for it to drop here it'd happen on a single thread.
        let to_drop = self
            .strings_by_bucket
            .into_iter()
            .map(|s| {
                s.buckets
                    .into_iter()
                    .map(|mut v| {
                        v.clear();
                        let new_vec: Vec<StringToMergePlaceholder> = v
                            .into_iter()
                            .map(|_| StringToMergePlaceholder::default())
                            .collect();
                        new_vec
                    })
                    .collect_vec()
            })
            .collect_vec();
        crate::threading::spawn(|| drop(to_drop));
    }
}

/// Returns the total size of our input sections. Each input section's size is rounded up to a block
/// size.
fn total_input_size(input_sections: &[StringMergeInputSection<'_>]) -> LinearInputOffset {
    let input_size = input_sections
        .last()
        .map(|sec| {
            sec.start_input_offset
                + (sec.section_data.len() as u64).next_multiple_of(MAP_BLOCK_SIZE)
        })
        .unwrap_or_default();
    input_size
}

fn do_splitting_work(resources: &SplitResources) -> Result {
    let mut overflowed_offsets = Vec::new();
    let mut idle_cycles = 0;

    // Towards the end, we will likely reach a point where some threads are still working and the
    // remaining threads have nothing more they can do. What that happens, the threads with nothing
    // to do shut down. It should be impossible for all threads to shut down without actually
    // completing all the work.
    while idle_cycles < 4 {
        idle_cycles += 1;

        // Phase 1: Split input sections and hash the resulting strings.
        for _ in 0..MAX_INPUT_GROUPS_BEFORE_BUCKETING {
            if let Some(input_section) = resources.unprocessed.pop() {
                idle_cycles = 0;
                process_input_section_group(resources, input_section)?;
            } else {
                break;
            }
        }

        // Phase 2: Put input strings into hashmaps, deduplicating them and recording
        // input-to-output offsets mappings.
        while let Some(bucket) = resources.in_progress_buckets.pop() {
            if work_with_bucket(resources, bucket, &mut overflowed_offsets)? {
                idle_cycles = 0;
            } else {
                break;
            }
        }
    }

    // We couldn't find any more work to do. If there is any, it'll need to be finished by whatever
    // threads are still running. Shut down.
    let r = resources.overflowed_offsets.push(overflowed_offsets);
    // We allocated exactly enough space for each thread to push one value.
    assert!(r.is_ok());
    Ok(())
}

/// Perform initial processing of the input sections in a group.
fn process_input_section_group<'data, 'offsets>(
    resources: &SplitResources<'data, 'offsets, '_, '_>,
    group_in: SectionGroup<'data, 'offsets, '_>,
) -> Result {
    let mut out = Box::new(SplitOutput {
        strings_by_bucket: resources.reuse_pool.new_strings_by_bucket(),
        offsets_shard: group_in.offsets_shard,
        buckets_processed: 0,
    });
    for section in group_in.sections {
        out.process_input_section(section)?;
    }
    resources.split_outputs[group_in.index].store(Some(out));

    Ok(())
}

/// Do all work possible with the supplied bucket then return it to an appropriate location.
fn work_with_bucket<'data>(
    resources: &SplitResources<'data, '_, '_, '_>,
    mut bucket: Box<MergeStringsSectionBucket<'data>>,
    overflowed_offsets: &mut Vec<OverflowedOffset>,
) -> Result<bool> {
    let mut did_work = false;
    while bucket.next_input_group_index < resources.num_input_groups {
        let section_index = bucket.next_input_group_index;
        let Some(mut split_output) = resources.split_outputs[section_index].take() else {
            // The input isn't available, but the bucket to the back of the queue.
            let r = resources.in_progress_buckets.push(bucket);
            // We should have allocated enough space for all the buckets to be ready.
            assert!(r.is_ok());
            return Ok(did_work);
        };

        did_work = true;

        bucket.process_split_output(&mut split_output, overflowed_offsets)?;

        // Advance to the next input for this bucket.
        bucket.next_input_group_index += 1;

        split_output.buckets_processed += 1;

        if split_output.buckets_processed == MERGE_STRING_BUCKETS {
            // The split output has now been processed by all buckets, so we're done with
            // it. Put it in pool for reuse.
            resources
                .reuse_pool
                .return_strings_by_bucket(split_output.strings_by_bucket);

            // We've finished writing the shard too.
            split_output.offsets_shard.finish();
            resources
                .offset_writer
                .lock()
                .unwrap()
                .return_shard(split_output.offsets_shard);
        } else {
            // Another thread can process this split output for the next bucket.
            resources.split_outputs[section_index].store(Some(split_output));
        }
    }

    // This bucket has now processed all input sections, so it's done.
    let _ = resources.finished_buckets.push(bucket);
    Ok(did_work)
}

#[derive(Clone, Copy, Default)]
struct BucketOffset(u32);

struct OverflowedOffset {
    input: LinearInputOffset,
    output: BucketOffset,
}

impl BucketOffset {
    fn new(offset: u32, bucket: usize) -> Result<Self> {
        if offset >= 1 << (32 - MERGE_STRING_BUCKET_BITS) {
            bail!("Merge-string bucket too large");
        }
        Ok(BucketOffset(
            (bucket as u32) << (32 - MERGE_STRING_BUCKET_BITS) | offset,
        ))
    }

    fn bucket(self) -> usize {
        (self.0 >> (32 - MERGE_STRING_BUCKET_BITS)) as usize
    }

    fn offset_in_bucket(self) -> u64 {
        u64::from(self.0 & ((1 << (32 - MERGE_STRING_BUCKET_BITS)) - 1))
    }
}

impl<'data> MergeStringsSectionBucket<'data> {
    fn process_split_output(
        &mut self,
        split_output: &mut SplitOutput<'data, '_>,
        overflowed_offsets: &mut Vec<OverflowedOffset>,
    ) -> Result {
        let bucket_index = self.index;
        for string in &split_output.strings_by_bucket.buckets[bucket_index] {
            let offset_in_bucket = self.add_string(string.string, bucket_index)?;
            match string.offset_key {
                OffsetKey::OffsetInShard(offset_in_shard) => {
                    *split_output.offsets_shard.get_mut(offset_in_shard) = offset_in_bucket;
                }
                OffsetKey::Overflow(linear_input_offset) => {
                    overflowed_offsets.push(OverflowedOffset {
                        input: linear_input_offset,
                        output: offset_in_bucket,
                    });
                }
            }
        }
        Ok(())
    }

    /// Adds `string`, deduplicating with an existing string if an identical string is already
    /// present.
    fn add_string(
        &mut self,
        string: PreHashed<MergeString<'data>>,
        bucket_index: usize,
    ) -> Result<BucketOffset> {
        self.input_string_byte_size += string.bytes.len();
        self.input_string_count += 1;
        let offset = *self.string_offsets.entry(string).or_insert_with(|| {
            let offset = self.next_offset;
            self.next_offset += string.bytes.len() as u32;
            self.strings.push(string.bytes);
            offset
        });
        BucketOffset::new(offset, bucket_index)
    }

    fn new(i: usize) -> Self {
        Self {
            index: i,
            ..Default::default()
        }
    }
}

impl<'data> MergeString<'data> {
    /// Takes from `source` up to the next null terminator. Returns a prehashed reference to what
    /// was taken.
    pub(crate) fn take_hashed(source: &mut &'data [u8]) -> Result<PreHashed<MergeString<'data>>> {
        let len = memchr::memchr(0, source)
            .map(|i| i + 1)
            .context("String in merge-string section is not null-terminated")?;
        let (bytes, rest) = source.split_at(len);
        let hash = crate::hash::hash_bytes(bytes);
        *source = rest;
        Ok(PreHashed::new(MergeString { bytes }, hash))
    }
}

/// Looks for a merged string at `symbol_index` + `addend` in the input and if found, returns its
/// address in the output.
pub(crate) fn get_merged_string_output_address(
    symbol_index: object::SymbolIndex,
    addend: u64,
    object: &crate::elf::File,
    sections: &[SectionSlot],
    merged_strings: &OutputSectionMap<MergedStringsSection>,
    merged_string_start_addresses: &MergedStringStartAddresses,
    zero_unnamed: bool,
) -> Result<Option<u64>> {
    let symbol = object.symbol(symbol_index)?;
    let Some(section_index) = object.symbol_section(symbol, symbol_index)? else {
        return Ok(None);
    };
    let SectionSlot::MergeStrings(merge_slot) = &sections[section_index.0] else {
        return Ok(None);
    };
    let mut input_offset = symbol.st_value(LittleEndian);

    // When we reference data in a string-merge section via a named symbol, we determine which
    // string we're referencing without taking the addend into account, then apply the addend
    // afterward. However when the reference is to a section (a symbol without a name), we take the
    // addend into account up-front before we determine which string we're pointing at. This is a
    // bit weird, but seems to match what other linkers do.
    let symbol_has_name = symbol.st_name(LittleEndian) != 0;
    if !symbol_has_name {
        // We're computing a resolution for an unnamed symbol, just use the value of 0 for now.
        // We'll compute the address later when we're processing relocations that reference the
        // section.
        if zero_unnamed {
            return Ok(Some(0));
        }
        input_offset = input_offset.wrapping_add(addend);
    }

    let section_id = merge_slot.part_id.output_section_id();
    let strings_section = merged_strings.get(section_id);
    let linear_input_offset = merge_slot.start_input_offset + input_offset;
    let string_offset = strings_section
        .string_offsets
        .get(linear_input_offset.0)
        .or_else(|| {
            strings_section
                .overflowed_string_offsets
                .get(&linear_input_offset)
                .copied()
        })
        .with_context(|| {
            format!(
                "Failed to find merge-string at offset {}",
                linear_input_offset.0
            )
        })?;
    let bucket_base =
        merged_string_start_addresses.addresses.get(section_id)[string_offset.bucket()];
    let mut address = bucket_base + string_offset.offset_in_bucket();
    if symbol_has_name {
        address = address.wrapping_add(addend);
    }
    Ok(Some(address))
}

impl MergedStringStartAddresses {
    #[tracing::instrument(skip_all, name = "Compute merged string section start addresses")]
    pub(crate) fn compute(
        output_sections: &OutputSections<'_>,
        starting_mem_offsets_by_group: &[OutputSectionPartMap<u64>],
        merge_string_sections: &OutputSectionMap<MergedStringsSection>,
    ) -> Self {
        let mut addresses = output_sections.new_section_map_with(|| [0; MERGE_STRING_BUCKETS]);
        let internal_start_offsets = starting_mem_offsets_by_group.first().unwrap();
        merge_string_sections.for_each(|section_id, sec| {
            if !section_id.is_regular() {
                return;
            }
            // We already have the offsets of each bucket relative to the start of the section. So
            // now we just need to add the section's start address to all of these.
            let base =
                *internal_start_offsets.get(section_id.part_id_with_alignment(alignment::MIN));
            let bucket_offsets_out = addresses.get_mut(section_id);
            *bucket_offsets_out = sec.bucket_offsets;
            for offset in bucket_offsets_out {
                *offset += base;
            }
        });
        Self { addresses }
    }
}

impl std::fmt::Display for MergeString<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.bytes))
    }
}
