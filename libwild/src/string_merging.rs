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
//! that the string is in. As we do this, we compute bucket-relative offsets for each string and
//! store these into entries in a map that we set up in phase 1.
//!
//! Threads can switch between phases multiple times until all work for the section is complete. At
//! that point, we do some finishing work single-threaded such as computing the starting offset of
//! each bucket and populating a hashmap from input to output offset for any offsets that didn't fit
//! in our primary offset map.

use crate::alignment;
use crate::args::Args;
use crate::args::Experiment;
use crate::bail;
use crate::error::Context as _;
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
use crate::timing_phase;
use crossbeam_channel::Sender;
use crossbeam_queue::ArrayQueue;
use crossbeam_utils::atomic::AtomicCell;
use hashbrown::HashMap;
use itertools::Itertools as _;
use linker_utils::elf;
use linker_utils::elf::shf;
use object::LittleEndian;
use object::read::elf::Sym as _;
use rayon::iter::ParallelBridge as _;
use rayon::iter::ParallelIterator as _;
use sharded_offset_map::OffsetMap;
use std::cell::RefCell;
use std::mem::replace;
use std::mem::take;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use thread_local::ThreadLocal;

/// Maximum number of threads that can split and hash input sections at once. We default to allowing
/// splitting parallelism up to the number of threads, but beyond about 24 it doesn't really help.
const MAX_SPLIT_PARALLELISM: u64 = 24;

/// How large a group of input sections should get before we break to the next group.
const MIN_GROUP_BYTES: u64 = 140_000;

/// Setting this to a higher value increases the potential for parallelism of hash table population
/// and gives better cache performance. However, it also increases heap allocations. Changing this
/// value will result in a different ordering of strings within the output file.
const MERGE_STRING_BUCKET_BITS: usize = 4;
const MERGE_STRING_BUCKETS: usize = 1 << MERGE_STRING_BUCKET_BITS;

/// Number of input offsets to represent by a single block. A block can store up to 12 offsets. If
/// we get more than 12 offsets within a block, then we need to spill the offset to a hashmap.
/// Increasing this value decreases memory usage, however it may result in more offsets being
/// spilled to the hashmap.
const MAP_BLOCK_SIZE: u64 = 256;

#[derive(Debug, Clone, Copy)]
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
#[derive(Debug)]
pub(crate) struct StringMergeSectionExtra<'data> {
    pub(crate) index: object::SectionIndex,
    pub(crate) section_data: &'data [u8],
    pub(crate) section_flags: elf::SectionFlags,
}

/// An input offset. We pretend that we've placed all input sections for a given output section one
/// after the other. This offset is then the offset into that space.
#[derive(Debug, Copy, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
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

    /// The sum of the sizes of the input sections prior to this one with the same `part_id`.
    start_input_offset: LinearInputOffset,

    is_string: bool,
}

/// A string from a string-merge section. Includes the null terminator.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(crate) struct MergeString<'data> {
    bytes: &'data [u8],
}

/// The addresses of the start of the merged strings for each output section.
#[derive(Debug)]
pub(crate) struct MergedStringStartAddresses {
    addresses: OutputSectionMap<[u64; MERGE_STRING_BUCKETS]>,
}

/// A section containing null terminated strings post-merging.
#[derive(derive_more::Debug)]
pub(crate) struct MergedStringsSection<'data> {
    /// The buckets based on the hash value of the input string.
    pub(crate) buckets: Vec<MergeStringsSectionBucket<'data>>,

    /// The byte offset of each bucket in the final section.
    bucket_offsets: [u64; MERGE_STRING_BUCKETS],

    /// Map from input offsets to output offsets.
    #[debug(skip)]
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
            overflowed_string_offsets: HashMap::new(),
        }
    }
}

#[derive(derive_more::Debug, Default)]
pub(crate) struct MergeStringsSectionBucket<'data> {
    index: usize,

    /// Input sections need to be added to a bucket in deterministic order, otherwise we'll get
    /// non-deterministic results. This is the index of the next input group that should be added.
    next_input_group_index: usize,

    /// The strings in this section, in order. Includes null terminators.
    /// TODO: Debug
    #[debug(skip)]
    pub(crate) strings: Vec<&'data [u8]>,

    /// The offset within the section of the next string to be added, or if we're done adding
    /// things, then this is the size of the output section.
    next_offset: u32,

    /// The total size of all added strings, used for statistics.
    input_string_byte_size: usize,

    /// The total number of all added strings, used for statistics.
    input_string_count: usize,

    /// The offsets of each string in the output section, keyed by the string contents.
    string_offsets: PassThroughHashMap<MergeString<'data>, u32>,
}

/// Merges identical strings from all loaded objects where those strings are from input sections
/// that are marked with both the SHF_MERGE and SHF_STRINGS flags.
pub(crate) fn merge_strings<'data>(
    resolved: &mut [ResolvedGroup<'data>],
    output_sections: &OutputSections,
    args: &Args,
) -> Result<OutputSectionMap<MergedStringsSection<'data>>> {
    timing_phase!("Merge strings");

    let input_sections_by_output =
        group_merge_string_sections_by_output(resolved, output_sections)?;

    let mut output_string_sections = output_sections.new_section_map::<MergedStringsSection>();

    let num_threads = rayon::current_num_threads();
    let split_parallelism = args.numeric_experiment(
        Experiment::MergeStringSplitParallelism,
        (num_threads as u64).min(MAX_SPLIT_PARALLELISM),
    ) as usize;

    let reuse_pool = ReusePool::new(MERGE_STRING_BUCKETS * split_parallelism);

    input_sections_by_output.try_for_each(|section_id, input_sections| {
        let output_section = output_string_sections.get_mut(section_id);
        output_section.add_input_sections(input_sections, &reuse_pool, args)?;

        assert_eq!(
            reuse_pool.available.load(Ordering::Relaxed),
            reuse_pool.capacity,
        );

        Ok(())
    })?;

    output_string_sections.for_each(|section_id, sec| {
        if sec.len() > 0 {
            tracing::debug!(target: "metrics",
                section = %output_sections.display_name(section_id),
                string_count = sec.string_count(),
                byte_size = sec.len(),
                input_string_count = sec.input_string_count(),
                input_string_byte_size = sec.input_string_byte_size(),
                output_map_overflow = sec.overflowed_string_offsets.len(),
                "merge_strings");
        }
    });

    // Dropping our ReusePool can take a little while, do it in the background while we continue
    // with other work.
    rayon::spawn(|| drop(reuse_pool));

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
                        is_string: extra.section_flags.contains(shf::STRINGS),
                    });

                *starting_offset = *starting_offset
                    + (extra.section_data.len() as u64).next_multiple_of(MAP_BLOCK_SIZE);
            }
        }
    }

    Ok(input_sections)
}

struct StringToMerge<'data, 'offsets> {
    string: PreHashed<MergeString<'data>>,
    offset_out: OffsetOut<'offsets>,
}

/// A place where we'll store the `BucketOffset` of the the string once known.
enum OffsetOut<'offsets> {
    InShard(&'offsets mut BucketOffset),
    Overflow(LinearInputOffset),
}

/// A group of input sections that we'll process together. Grouping input sections allows us to
/// reduce some overheads by doing some bookkeeping per-group rather than per input section.
struct SectionGroup<'data, 'offsets, 'sections> {
    index: usize,
    sections: &'sections [StringMergeInputSection<'data>],
    offsets_shard: sharded_offset_map::Shard<'offsets, BucketOffset, MAP_BLOCK_SIZE>,
}

/// Split an input section into strings and hash those strings, collecting the results into
/// buckets based on the string hashes.
fn process_input_section<'data, 'offsets>(
    input_section: &StringMergeInputSection<'data>,
    buckets: &mut [Vec<StringToMerge<'data, 'offsets>>; MERGE_STRING_BUCKETS],
    offsets_shard: &mut sharded_offset_map::Shard<'offsets, BucketOffset, MAP_BLOCK_SIZE>,
) -> Result {
    let mut input_offset = input_section.start_input_offset;
    let mut remaining = input_section.section_data;
    while !remaining.is_empty() {
        let string = if input_section.is_string {
            MergeString::take_string_hashed(&mut remaining)?
        } else {
            MergeString::take_hashed(&mut remaining)
        };
        // Insert 0, then we'll update it later once we know the output offset. We do the
        // initial insertion now since insertions need to happen in sequential order, whereas by
        // the time we know the output offset, we're processing just a single bucket.
        let offset_key = match offsets_shard.insert(input_offset.0, BucketOffset(0)) {
            Ok(offset_in_shard) => OffsetOut::InShard(offset_in_shard),
            Err(_) => OffsetOut::Overflow(input_offset),
        };
        buckets[(string.hash() as usize) % MERGE_STRING_BUCKETS].push(StringToMerge {
            string,
            offset_out: offset_key,
        });
        input_offset = input_offset + string.bytes.len() as u64;
    }
    Ok(())
}

enum WorkItem<'data> {
    SplitInput(PoolReservation, Arc<Sender<WorkItem<'data>>>),
    Bucket(
        Box<MergeStringsSectionBucket<'data>>,
        Arc<Sender<WorkItem<'data>>>,
    ),
}

impl<'data> MergedStringsSection<'data> {
    fn add_input_sections(
        &mut self,
        input_sections: &[StringMergeInputSection<'data>],
        reuse_pool: &ReusePool,
        args: &Args,
    ) -> Result {
        // We later create ArrayQueues with capacity for all input sections and ArrayQueue panics if
        // asked for zero capacity. Also, spawning tasks and all the other work we do here would be
        // a waste if we have no input sections.
        if input_sections.is_empty() {
            return Ok(());
        }

        let mut resources =
            create_split_resources(&mut self.string_offsets, input_sections, reuse_pool, args);

        let (work_send, work_recv) = crossbeam_channel::bounded(reuse_pool.capacity);
        let work_send = Arc::new(work_send);

        // Queue some number of tasks to process input section groups. As these tasks complete,
        // they'll queue bucket processing tasks to take those inputs. As the bucket processing
        // tasks complete, they will, as capacity permits, queue additional input processing tasks.
        // This continues until the last inputs and the last buckets have been processed.
        while let Ok(reservation) = reuse_pool.try_reserve(MERGE_STRING_BUCKETS) {
            work_send
                .send(WorkItem::SplitInput(reservation, work_send.clone()))
                .unwrap();
        }

        // The loop below will only terminate once all references to the sender have been dropped.
        // Each work item holds a reference to the sender, so this is the only other reference.
        drop(work_send);

        work_recv
            .into_iter()
            .par_bridge()
            .for_each(|work_item| match work_item {
                WorkItem::SplitInput(mut reservation, work_send) => {
                    if let Some(input_section) = resources.unprocessed.pop()
                        && let Err(error) = process_input_section_group(
                            &resources,
                            input_section,
                            &work_send,
                            &mut reservation,
                        )
                    {
                        let _ = resources.errors.push(error);
                    }

                    resources.reuse_pool.unreserve(reservation);
                }
                WorkItem::Bucket(bucket, work_send) => {
                    if let Err(error) = work_with_bucket(&resources, bucket, &work_send) {
                        let _ = resources.errors.push(error);
                    }
                }
            });

        // Check if we got any errors. We only look at the first error.
        if let Some(error) = resources.errors.pop() {
            return Err(error);
        }

        // Handle any offsets that didn't fit in their respective blocks in the offset map.
        let overflow = core::mem::take(&mut resources.overflowed_offsets);
        overflow
            .into_iter()
            .flat_map(|cell| cell.into_inner())
            .for_each(|o| {
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

        resources.finished_shards.into_iter().for_each(|shard| {
            resources
                .offset_writer
                .return_shard(shard.into_inner().unwrap());
        });

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

struct SplitResources<'data, 'offsets, 'scope> {
    /// The number of input groups that we're processing. This is used so that we can know when
    /// we've processed all input groups for a particular hash bucket.
    num_input_groups: usize,

    /// Groups that we haven't yet processed in phase 1.
    unprocessed: ArrayQueue<SectionGroup<'data, 'offsets, 'scope>>,

    // The shards that we've finished processing in their correct order. Note, this `AtomicCell`
    // isn't lock-free, since the shard is larger than a usize. This doesn't seem to make any
    // measurable difference to performance for our use-case.
    finished_shards:
        Vec<AtomicCell<Option<sharded_offset_map::Shard<'offsets, BucketOffset, MAP_BLOCK_SIZE>>>>,

    /// Indexed by group and bucket. See `string_bucket_offset` for computation.
    strings_by_bucket_and_group: Vec<Mutex<StringsSlot<'data, 'offsets>>>,

    /// Hash buckets that we've finished with. These have had all input groups applied.
    finished_buckets: ArrayQueue<Box<MergeStringsSectionBucket<'data>>>,

    offset_writer: sharded_offset_map::ShardedWriter<'offsets, BucketOffset, MAP_BLOCK_SIZE>,

    /// Any offsets that couldn't fit in the offset map due to too many strings within a block.
    overflowed_offsets: ThreadLocal<RefCell<Vec<OverflowedOffset>>>,

    errors: ArrayQueue<crate::error::Error>,

    reuse_pool: &'scope ReusePool,
}

fn string_bucket_offset(input: usize, bucket: usize) -> usize {
    input * MERGE_STRING_BUCKETS + bucket
}

impl<'scope, 'data: 'scope, 'offsets> SplitResources<'data, 'offsets, 'scope> {
    fn swap_strings_slot(
        &self,
        input: usize,
        bucket: usize,
        slot: StringsSlot<'data, 'offsets>,
    ) -> StringsSlot<'data, 'offsets> {
        let mut lock = self.strings_by_bucket_and_group[string_bucket_offset(input, bucket)]
            .lock()
            .unwrap();
        replace(&mut lock, slot)
    }
}

enum StringsSlot<'data, 'offsets> {
    Empty,
    WaitingForStrings(Box<MergeStringsSectionBucket<'data>>),
    Strings(Vec<StringToMerge<'data, 'offsets>>),
}

fn create_split_resources<'data, 'offsets, 'scope>(
    string_offsets: &'offsets mut OffsetMap<BucketOffset, MAP_BLOCK_SIZE>,
    input_sections: &'scope [StringMergeInputSection<'data>],
    reuse_pool: &'scope ReusePool,
    args: &Args,
) -> SplitResources<'data, 'offsets, 'scope> {
    let input_size = total_input_size(input_sections);
    let mut offset_writer = string_offsets.start_sharded_write(input_size.0);

    let min_group_bytes =
        args.numeric_experiment(Experiment::MergeStringMinGroupBytes, MIN_GROUP_BYTES);

    let unprocessed: ArrayQueue<SectionGroup> = ArrayQueue::new(input_sections.len());

    let mut group_start_index = 0;
    let mut group_size = 0;

    input_sections
        .iter()
        .enumerate()
        .for_each(|(index, section)| {
            let size = (section.section_data.len() as u64).next_multiple_of(MAP_BLOCK_SIZE);
            let is_last_section = index == input_sections.len() - 1;

            let mut group_end_index = index;

            let new_size = group_size + size;
            let mut should_end_group = new_size > min_group_bytes
                && new_size.abs_diff(min_group_bytes) > size.abs_diff(min_group_bytes)
                && group_size > 0;

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
                // We allocated enough space for each section to be in its own group.
                assert!(r.is_ok());

                group_size = 0;
                group_start_index = group_end_index;
            }

            group_size += size;
        });

    let num_groups = unprocessed.len();
    let mut strings_by_bucket_and_group = Vec::new();
    strings_by_bucket_and_group.resize_with(num_groups * MERGE_STRING_BUCKETS, || {
        Mutex::new(StringsSlot::Empty)
    });

    let mut finished_shards = Vec::new();
    finished_shards.resize_with(num_groups, || AtomicCell::new(None));

    let resources = SplitResources {
        num_input_groups: unprocessed.len(),
        unprocessed,
        strings_by_bucket_and_group,
        finished_buckets: ArrayQueue::new(MERGE_STRING_BUCKETS),
        finished_shards,
        overflowed_offsets: ThreadLocal::new(),
        offset_writer,
        errors: ArrayQueue::new(1),
        reuse_pool,
    };

    (0..MERGE_STRING_BUCKETS).for_each(|i| {
        resources.swap_strings_slot(
            0,
            i,
            StringsSlot::WaitingForStrings(Box::new(MergeStringsSectionBucket::new(i))),
        );
    });

    resources
}

struct ReusePool {
    string_vecs: ArrayQueue<Vec<StringToMerge<'static, 'static>>>,

    capacity: usize,

    /// Number of Vecs that haven't yet been reserved.
    available: AtomicUsize,
}

/// Holds instances of data structures that we reuse where possible. This allows us to reduce the
/// number of separate heap allocations we make.
impl ReusePool {
    fn new(capacity: usize) -> Self {
        Self {
            string_vecs: ArrayQueue::new(capacity),
            capacity,
            available: AtomicUsize::new(capacity),
        }
    }

    fn take_string_merge_vec<'data, 'offsets>(
        &self,
        reservation: &mut PoolReservation,
    ) -> Vec<StringToMerge<'data, 'offsets>> {
        reservation.remaining = reservation.remaining.checked_sub(1).unwrap();
        self.string_vecs
            .pop()
            .map_or_else(|| Vec::with_capacity(1024), reuse_vec)
    }

    fn return_strings_to_merge(&self, strings_to_merge: Vec<StringToMerge<'_, '_>>) {
        let r = self.string_vecs.push(reuse_vec(strings_to_merge));
        assert!(r.is_ok());

        self.available.fetch_add(1, Ordering::Relaxed);
    }

    /// Attempt to reserve the specified number of Vecs. Fails if there isn't at least that many
    /// already available.
    fn try_reserve(&self, num_vecs: usize) -> Result<PoolReservation, ()> {
        let available = self.available.load(Ordering::Relaxed);
        if available < num_vecs {
            return Err(());
        }

        if self
            .available
            .compare_exchange(
                available,
                available - num_vecs,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return Err(());
        }

        Ok(PoolReservation {
            remaining: num_vecs,
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn unreserve(&self, reservation: PoolReservation) {
        if reservation.remaining == 0 {
            return;
        }
        self.available
            .fetch_add(reservation.remaining, Ordering::Relaxed);
    }
}

struct PoolReservation {
    remaining: usize,
}

/// Returns the total size of our input sections. Each input section's size is rounded up to a block
/// size.
fn total_input_size(input_sections: &[StringMergeInputSection<'_>]) -> LinearInputOffset {
    input_sections
        .last()
        .map(|sec| {
            sec.start_input_offset
                + (sec.section_data.len() as u64).next_multiple_of(MAP_BLOCK_SIZE)
        })
        .unwrap_or_default()
}

/// Perform initial processing of the input sections in a group.
fn process_input_section_group<'data, 'offsets, 'scope>(
    resources: &'scope SplitResources<'data, 'offsets, '_>,
    mut group_in: SectionGroup<'data, 'offsets, 'scope>,
    work_send: &Arc<Sender<WorkItem<'data>>>,
    reservation: &mut PoolReservation,
) -> Result {
    let mut buckets: [Vec<StringToMerge<'data, 'offsets>>; MERGE_STRING_BUCKETS] = [();
        MERGE_STRING_BUCKETS]
        .map(|()| resources.reuse_pool.take_string_merge_vec(reservation));

    for section in group_in.sections {
        process_input_section(section, &mut buckets, &mut group_in.offsets_shard)?;
    }

    group_in.offsets_shard.finish();
    resources.finished_shards[group_in.index].store(Some(group_in.offsets_shard));

    for (i, bucket_out) in buckets.iter_mut().enumerate() {
        let prev_slot =
            resources.swap_strings_slot(group_in.index, i, StringsSlot::Strings(take(bucket_out)));
        if let StringsSlot::WaitingForStrings(bucket) = prev_slot {
            work_send
                .send(WorkItem::Bucket(bucket, work_send.clone()))
                .unwrap();
        }
    }

    Ok(())
}

/// Do all work possible with the supplied bucket then return it to an appropriate location.
fn work_with_bucket<'data>(
    resources: &SplitResources<'data, '_, '_>,
    mut bucket: Box<MergeStringsSectionBucket<'data>>,
    work_send: &Arc<Sender<WorkItem<'data>>>,
) -> Result {
    let mut overflowed_offsets = resources.overflowed_offsets.get_or_default().borrow_mut();

    while bucket.next_input_group_index < resources.num_input_groups {
        let mut strings_to_merge = {
            let group_index = bucket.next_input_group_index;

            let mut lock = resources.strings_by_bucket_and_group
                [string_bucket_offset(group_index, bucket.index)]
            .lock()
            .unwrap();

            let slot = replace(&mut *lock, StringsSlot::Empty);
            let StringsSlot::Strings(strings) = slot else {
                *lock = StringsSlot::WaitingForStrings(bucket);
                return Ok(());
            };

            strings
        };

        bucket.process_split_output(&mut strings_to_merge, &mut overflowed_offsets)?;

        resources
            .reuse_pool
            .return_strings_to_merge(strings_to_merge);

        while let Ok(reservation) = resources.reuse_pool.try_reserve(MERGE_STRING_BUCKETS) {
            work_send
                .send(WorkItem::SplitInput(reservation, work_send.clone()))
                .unwrap();
        }

        // Advance to the next input for this bucket.
        bucket.next_input_group_index += 1;
    }

    // This bucket has now processed all input sections, so it's done.
    let _ = resources.finished_buckets.push(bucket);
    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
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
            ((bucket as u32) << (32 - MERGE_STRING_BUCKET_BITS)) | offset,
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
        strings_to_merge: &mut [StringToMerge<'data, '_>],
        overflowed_offsets: &mut Vec<OverflowedOffset>,
    ) -> Result {
        let bucket_index = self.index;
        for string in strings_to_merge {
            let offset_in_bucket = self.add_string(string.string, bucket_index)?;
            match &mut string.offset_out {
                OffsetOut::InShard(o) => {
                    **o = offset_in_bucket;
                }
                OffsetOut::Overflow(linear_input_offset) => {
                    overflowed_offsets.push(OverflowedOffset {
                        input: *linear_input_offset,
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

    pub(crate) fn len(&self) -> usize {
        self.next_offset as usize
    }
}

impl<'data> MergeString<'data> {
    /// Takes from `source` up to the next null terminator. Returns a prehashed reference to what
    /// was taken.
    pub(crate) fn take_string_hashed(
        source: &mut &'data [u8],
    ) -> Result<PreHashed<MergeString<'data>>> {
        let len = memchr::memchr(0, source)
            .map(|i| i + 1)
            .context("String in merge-string section is not null-terminated")?;
        let (bytes, rest) = source.split_at(len);
        let hash = crate::hash::hash_bytes(bytes);
        *source = rest;
        Ok(PreHashed::new(MergeString { bytes }, hash))
    }

    /// Takes the whole `source`. Returns a prehashed reference to what was taken.
    pub(crate) fn take_hashed(source: &mut &'data [u8]) -> PreHashed<MergeString<'data>> {
        let bytes = take(source);
        let hash = crate::hash::hash_bytes(bytes);
        PreHashed::new(MergeString { bytes }, hash)
    }
}

/// Looks for a merged string at `symbol_index` + `addend` in the input and if found, returns its
/// address in the output.
#[inline(always)]
pub(crate) fn get_merged_string_output_address(
    symbol_index: object::SymbolIndex,
    addend: i64,
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
        input_offset = input_offset.wrapping_add(addend as u64);
    }

    let section_id = merge_slot.part_id.output_section_id();
    let strings_section = merged_strings.get(section_id);
    let string_offset = find_string(merge_slot, input_offset, strings_section)?;
    let bucket_base =
        merged_string_start_addresses.addresses.get(section_id)[string_offset.bucket()];
    let mut address = bucket_base + string_offset.offset_in_bucket();
    if symbol_has_name {
        address = address.wrapping_add(addend as u64);
    }
    Ok(Some(address))
}

fn find_string(
    merge_slot: &StringMergeSectionSlot,
    input_offset: u64,
    strings_section: &MergedStringsSection<'_>,
) -> Result<BucketOffset> {
    let linear_input_offset = merge_slot.start_input_offset + input_offset;
    let string_offset = strings_section
        .string_offsets
        .get(linear_input_offset.0)
        .or_else(|| {
            strings_section
                .overflowed_string_offsets
                .get(&linear_input_offset)
                .copied()
        });

    if let Some(string_offset) = string_offset {
        return Ok(string_offset);
    }

    // Our input offset wasn't found, so it likely points part way into a string. Search backwards
    // until we find it. It should be possible to do this more efficiently, but since we expect this
    // to be very rare, we don't bother for now.
    for i in 1..=input_offset {
        let linear_input_offset = merge_slot.start_input_offset + (input_offset - i);
        let string_offset = strings_section
            .string_offsets
            .get(linear_input_offset.0)
            .or_else(|| {
                strings_section
                    .overflowed_string_offsets
                    .get(&linear_input_offset)
                    .copied()
            });

        if let Some(string_offset) = string_offset {
            return Ok(BucketOffset(string_offset.0 + i as u32));
        }
    }

    bail!(
        "Failed to find merge-string at offset {}",
        linear_input_offset.0
    )
}

impl MergedStringStartAddresses {
    pub(crate) fn compute(
        output_sections: &OutputSections<'_>,
        starting_mem_offsets_by_group: &[OutputSectionPartMap<u64>],
        merge_string_sections: &OutputSectionMap<MergedStringsSection>,
    ) -> Self {
        timing_phase!("Compute merged string section start addresses");

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

/// Returns an empty `Vec<U>` that reuses the storage of the supplied `Vec<T>`. `T` and `U` must
/// have the same size and alignment.
fn reuse_vec<T, U>(mut v: Vec<T>) -> Vec<U> {
    debug_assert_eq!(size_of::<T>(), size_of::<U>());
    debug_assert_eq!(align_of::<T>(), align_of::<U>());
    let old_storage = v.as_ptr();
    v.clear();
    // Convert the type of the vec. This relies on a specialised implementation of `collect`. Were
    // it not for that, we'd get a new heap allocation, which would defeat the purpose.
    let u: Vec<U> = v.into_iter().map(|_| unreachable!()).collect();
    // Make sure that we actually reused the old storage.
    debug_assert_eq!(old_storage as usize, u.as_ptr() as usize);
    u
}
