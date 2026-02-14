//! Input sections that are marked as string-merge sections need special processing. Our algorithm
//! is somewhat complicated in an attempt to get good performance. A rough outline of our algorithm
//! is here with more details throughout the code. Contrary to what the name might suggest, this
//! algorithm also supports merging non-string sections. The only difference between handling string
//! and non-string sections is we split the former into multiple slices at the null terminators, and
//! treat the latter as a single slice.
//!
//! We group input sections by the output section into which they are to be placed. We then process
//! each output section one at a time.
//!
//! Taking all the input sections for a particular output section, we group adjacent input sections
//! so that each group has a roughly similar size in bytes.
//!
//! With multiple threads, we alternate between two phases:
//!
//! Phase 1: We take the whole input sections or split string sections by looking for null
//! terminators, then we hash the resulting slices and store it in a bucket based on its hash.
//!
//! Phase 2: We take the outputs of phase 1 and insert the slices into a hashmap for the bucket
//! that the slice is in. As we do this, we compute bucket-relative offsets for each string and
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
use crate::platform::Symbol as _;
use crate::resolution::ResolvedFile;
use crate::resolution::ResolvedGroup;
use crate::resolution::SectionSlot;
use crate::timing_phase;
use crate::verbose_timing_phase;
use crossbeam_queue::ArrayQueue;
use crossbeam_utils::atomic::AtomicCell;
use hashbrown::HashMap;
use itertools::Itertools as _;
use linker_utils::elf;
use linker_utils::elf::shf;
use rayon::Scope;
use sharded_offset_map::OffsetMap;
use sharded_offset_map::ShardedWriter;
use std::cell::RefCell;
use std::mem::replace;
use std::mem::take;
use std::ops::Range;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use thread_local::ThreadLocal;

/// Maximum number of threads that can split and hash input sections at once. We default to allowing
/// splitting parallelism up to the number of threads, but beyond about 24 it doesn't really help.
const MAX_SPLIT_PARALLELISM: u64 = 24;

/// How large should our chunks of input bytes be.
const TARGET_GROUP_SIZE_BYTES: u64 = 140_000;

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

pub(crate) struct StringMergeInputs<'data> {
    input_sections_by_output: OutputSectionMap<Vec<StringMergeInputSection<'data>>>,
}

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

impl std::ops::Sub<LinearInputOffset> for LinearInputOffset {
    type Output = u64;

    fn sub(self, rhs: LinearInputOffset) -> Self::Output {
        self.0 - rhs.0
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
    inputs: &StringMergeInputs<'data>,
    output_sections: &OutputSections,
    args: &Args,
) -> Result<OutputSectionMap<MergedStringsSection<'data>>> {
    timing_phase!("Merge strings");

    let mut output_string_sections = output_sections.new_section_map::<MergedStringsSection>();

    let num_threads = rayon::current_num_threads();
    let split_parallelism = args.numeric_experiment(
        Experiment::MergeStringSplitParallelism,
        (num_threads as u64).min(MAX_SPLIT_PARALLELISM),
    ) as usize;

    let reuse_pool = ReusePool::new(MERGE_STRING_BUCKETS * split_parallelism);

    inputs
        .input_sections_by_output
        .try_for_each(|section_id, input_sections| {
            // We later create ArrayQueues with capacity for all input sections and ArrayQueue
            // panics if asked for zero capacity. Also, spawning tasks and all the other
            // work we do here would be a waste if we have no input sections.
            if input_sections.is_empty() {
                return Ok(());
            }

            verbose_timing_phase!(
                "Merge section",
                section_name = output_sections.display_name(section_id)
            );

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

impl<'data> StringMergeInputs<'data> {
    pub(crate) fn new(
        resolved: &mut [ResolvedGroup<'data>],
        output_sections: &OutputSections,
    ) -> Result<Self> {
        Ok(Self {
            input_sections_by_output: group_merge_string_sections_by_output(
                resolved,
                output_sections,
            )?,
        })
    }
}

// Gather up all the string-merge sections, grouping them by their output section ID. We return a
// reference to the `MergeStringsFileSection` rather than copying it because it appears to be
// faster.
fn group_merge_string_sections_by_output<'data>(
    resolved: &mut [ResolvedGroup<'data>],
    output_sections: &OutputSections,
) -> Result<OutputSectionMap<Vec<StringMergeInputSection<'data>>>> {
    verbose_timing_phase!("Find merge sectionns");

    let mut input_sections = output_sections.new_section_map::<Vec<StringMergeInputSection>>();

    let mut starting_offsets = output_sections.new_section_map::<LinearInputOffset>();

    for group in resolved {
        for file in &mut group.files {
            let ResolvedFile::Object(obj) = file else {
                continue;
            };
            for extra in &obj.string_merge_extras {
                let SectionSlot::MergeStrings(sec) = &mut obj.sections[extra.index.0] else {
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

    /// Restrict to just strings that start within the specified range.
    range: Range<LinearInputOffset>,
}

/// Split an input section into strings and hash those strings, collecting the results into
/// buckets based on the string hashes.
fn process_input_section<'data, 'offsets>(
    input_section: &StringMergeInputSection<'data>,
    buckets: &mut [Vec<StringToMerge<'data, 'offsets>>; MERGE_STRING_BUCKETS],
    offsets_shard: &mut sharded_offset_map::Shard<'offsets, BucketOffset, MAP_BLOCK_SIZE>,
    range: &Range<LinearInputOffset>,
) -> Result {
    let mut input_offset = input_section.start_input_offset;
    let mut remaining = input_section.section_data;
    if range.start > input_offset {
        // Non-string merge sections should never be split.
        debug_assert!(input_section.is_string);

        let offset_in_section = (range.start - input_offset) as usize;
        let advance = if remaining[offset_in_section - 1] == 0 {
            // Our range started just after a null character, so we're already at the start of a
            // string.
            offset_in_section
        } else {
            // Our range start is part way through a string, find end of the string and start from
            // there.
            memchr::memchr(0, &remaining[offset_in_section..])
                .map_or(remaining.len(), |null_offset| {
                    offset_in_section + null_offset + 1
                })
        };
        input_offset = input_offset + advance as u64;
        remaining = &remaining[advance..];
    }

    let mut insert_data = |data: PreHashed<MergeString<'data>>,
                           input_offset: &mut LinearInputOffset| {
        // Insert 0, then we'll update it later once we know the output offset. We do the
        // initial insertion now since insertions need to happen in sequential order, whereas by
        // the time we know the output offset, we're processing just a single bucket.

        let offset_key = match offsets_shard.insert(input_offset.0, BucketOffset(0)) {
            Ok(offset_in_shard) => OffsetOut::InShard(offset_in_shard),
            Err(_) => OffsetOut::Overflow(*input_offset),
        };
        buckets[(data.hash() as usize) % MERGE_STRING_BUCKETS].push(StringToMerge {
            string: data,
            offset_out: offset_key,
        });
        *input_offset = *input_offset + data.bytes.len() as u64;
    };

    // Non-string section is just a single slice.
    if !input_section.is_string {
        let section_data = MergeString::take_hashed(&mut remaining);

        insert_data(section_data, &mut input_offset);
        return Ok(());
    }

    // String section, so split at null terminators.
    while !remaining.is_empty() && input_offset < range.end {
        let string = MergeString::take_string_hashed(&mut remaining)?;

        insert_data(string, &mut input_offset);
    }

    Ok(())
}

impl<'data> MergedStringsSection<'data> {
    fn add_input_sections(
        &mut self,
        input_sections: &[StringMergeInputSection<'data>],
        reuse_pool: &ReusePool,
        args: &Args,
    ) -> Result {
        let mut resources =
            create_split_resources(&mut self.string_offsets, input_sections, reuse_pool, args);

        rayon::in_place_scope(|s| {
            // Spawn some number of tasks to process input section groups. As these tasks complete,
            // they'll spawn bucket processing tasks to take those inputs. As the bucket processing
            // tasks complete, they will, as capacity permits, spawn additional input processing
            // tasks. This continues until the last inputs and the last buckets have been processed.
            try_spawn_input_processing(&resources, s);
        });

        // Check if we got any errors. We only look at the first error.
        if let Some(error) = resources.errors.pop() {
            return Err(error);
        }

        {
            verbose_timing_phase!("Handle overflows");

            // Handle any offsets that didn't fit in their respective blocks in the offset map.
            let overflow = core::mem::take(&mut resources.overflowed_offsets);
            overflow
                .into_iter()
                .flat_map(|cell| cell.into_inner())
                .for_each(|o| {
                    self.overflowed_string_offsets.insert(o.input, o.output);
                });
        }

        verbose_timing_phase!("Finalise merged section");

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

// Spawn as many input-processing tasks as allowed.
fn try_spawn_input_processing<'scope>(
    resources: &'scope SplitResources<'_, '_, '_>,
    scope: &Scope<'scope>,
) {
    loop {
        let Ok(mut reservation) = resources.reuse_pool.try_reserve(MERGE_STRING_BUCKETS) else {
            return;
        };

        scope.spawn(|scope| {
            if let Some(input_section) = resources.unprocessed.pop()
                && let Err(error) =
                    process_input_section_group(resources, input_section, scope, &mut reservation)
            {
                let _ = resources.errors.push(error);
            }

            resources.reuse_pool.unreserve(reservation);
        });
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
    verbose_timing_phase!("Create input section groups");

    let input_size = total_input_size(input_sections);
    let mut offset_writer = string_offsets.start_sharded_write(input_size.0);

    let target_group_size = args
        .numeric_experiment(
            Experiment::MergeStringMinGroupBytes,
            TARGET_GROUP_SIZE_BYTES,
        )
        .next_multiple_of(MAP_BLOCK_SIZE) as usize;

    let groups = split_sections(input_sections, &mut offset_writer, target_group_size);

    let unprocessed: ArrayQueue<SectionGroup> = ArrayQueue::new(groups.len());
    for group in groups {
        let _ = unprocessed.push(group);
    }

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

/// Split `sections` into slices of at most `size`. A single input section might be split into
/// multiple groups, or a group might contain multiple input sections. The last slice may be
/// smaller. If the sections are string sections, then the split will occur after exactly size bytes
/// unless we run out of sections first. If a section is a non-string merge section, then the whole
/// section will be taken regardless of size.
fn split_sections<'data, 'offsets, 'sections>(
    sections: &'sections [StringMergeInputSection<'data>],
    offset_writer: &mut ShardedWriter<'offsets, BucketOffset, MAP_BLOCK_SIZE>,
    size: usize,
) -> Vec<SectionGroup<'data, 'offsets, 'sections>> {
    assert!(size.is_multiple_of(MAP_BLOCK_SIZE as usize));

    let mut result = Vec::new();

    let mut section_index = 0;
    let mut offset_in_section = 0;

    while section_index < sections.len() {
        // Remaining needs to be signed, since if we encounter non-string merge sections, we'll need
        // to take the entire section, which may cause us to go negative.
        let mut remaining = size as isize;
        let start_section_index = section_index;
        let first_section_start_offset = offset_in_section;
        let mut end_section = false;

        // Iterate through sections until we fill `size` bytes
        while remaining > 0 {
            let sec = &sections[section_index];
            let available = (sec.padded_len() - offset_in_section) as isize;

            if available > remaining && sec.is_string {
                // Still some of this section left for the next group, so don't advance.
                offset_in_section += remaining as usize;
                remaining = 0;
            } else {
                remaining -= available;
                if remaining <= 0 || section_index + 1 == sections.len() {
                    offset_in_section += available as usize;
                    end_section = true;
                    break;
                }
                section_index += 1;
                offset_in_section = 0;
            }
        }

        let index = result.len();
        let group_size = size as isize - remaining;

        let linear_start =
            sections[start_section_index].start_input_offset + first_section_start_offset as u64;
        let linear_end = sections[section_index].start_input_offset + offset_in_section as u64;

        let offsets_shard = offset_writer.take_shard(group_size as u64);

        debug_assert_eq!(linear_start.0, offsets_shard.base());
        debug_assert_eq!(linear_end.0, offsets_shard.base() + offsets_shard.len());

        result.push(SectionGroup {
            sections: &sections[start_section_index..=section_index],
            range: linear_start..linear_end,
            index,
            offsets_shard,
        });

        if end_section {
            section_index += 1;
            offset_in_section = 0;
        }
    }

    result
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
    scope: &Scope<'scope>,
    reservation: &mut PoolReservation,
) -> Result {
    verbose_timing_phase!("Split and hash");

    let mut buckets: [Vec<StringToMerge<'data, 'offsets>>; MERGE_STRING_BUCKETS] = [();
        MERGE_STRING_BUCKETS]
        .map(|()| resources.reuse_pool.take_string_merge_vec(reservation));

    for section in group_in.sections {
        process_input_section(
            section,
            &mut buckets,
            &mut group_in.offsets_shard,
            &group_in.range,
        )?;
    }

    group_in.offsets_shard.finish();
    resources.finished_shards[group_in.index].store(Some(group_in.offsets_shard));

    for (i, bucket_out) in buckets.iter_mut().enumerate() {
        let prev_slot =
            resources.swap_strings_slot(group_in.index, i, StringsSlot::Strings(take(bucket_out)));
        if let StringsSlot::WaitingForStrings(bucket) = prev_slot {
            scope.spawn(|scope| {
                if let Err(error) = work_with_bucket(resources, bucket, scope) {
                    let _ = resources.errors.push(error);
                }
            });
        }
    }

    Ok(())
}

/// Do all work possible with the supplied bucket then return it to an appropriate location.
fn work_with_bucket<'data, 'scope>(
    resources: &'scope SplitResources<'data, '_, '_>,
    mut bucket: Box<MergeStringsSectionBucket<'data>>,
    scope: &Scope<'scope>,
) -> Result {
    verbose_timing_phase!("Bucket strings");

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

        try_spawn_input_processing(resources, scope);

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
    let mut input_offset = symbol.value();

    // When we reference data in a string-merge section via a named symbol, we determine which
    // string we're referencing without taking the addend into account, then apply the addend
    // afterward. However when the reference is to a section (a symbol without a name), we take the
    // addend into account up-front before we determine which string we're pointing at. This is a
    // bit weird, but seems to match what other linkers do.
    let symbol_has_name = symbol.has_name();
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

impl StringMergeInputSection<'_> {
    /// Returns the length of this section's data rounded up to the next multiple of the block size.
    fn padded_len(&self) -> usize {
        self.section_data
            .len()
            .next_multiple_of(MAP_BLOCK_SIZE as usize)
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
