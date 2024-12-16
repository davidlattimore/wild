use crate::alignment;
use crate::error::Result;
use crate::hash::PassThroughHashMap;
use crate::hash::PreHashed;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::part_id::PartId;
use crate::resolution::ResolvedFile;
use crate::resolution::ResolvedGroup;
use crate::resolution::SectionSlot;
use anyhow::bail;
use anyhow::Context;
use object::read::elf::Sym as _;
use object::LittleEndian;
use rayon::iter::IndexedParallelIterator as _;
use rayon::iter::IntoParallelRefMutIterator as _;
use rayon::iter::ParallelIterator;

const MERGE_STRING_BUCKETS: usize = 32;

#[derive(Clone, Copy)]
pub(crate) struct MergeStringsFileSection<'data> {
    pub(crate) part_id: PartId,
    pub(crate) section_data: &'data [u8],
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(crate) struct StringToMerge<'data> {
    bytes: &'data [u8],
}

/// The addresses of the start of the merged strings for each output section.
pub(crate) struct MergedStringStartAddresses {
    addresses: OutputSectionMap<u64>,
}

#[derive(Default)]
pub(crate) struct MergeStringsSection<'data> {
    /// The buckets based on the hash value of the input string.
    pub(crate) buckets: [MergeStringsSectionBucket<'data>; MERGE_STRING_BUCKETS],

    /// The byte offset of each bucket in the final section.
    pub(crate) bucket_offsets: [u64; MERGE_STRING_BUCKETS],
}

#[derive(Default)]
pub(crate) struct MergeStringsSectionBucket<'data> {
    /// The strings in this section in order. Includes null terminators.
    pub(crate) strings: Vec<&'data [u8]>,

    /// The offset within the section of the next string to be added, or if we're done adding
    /// things, then this is the size of the output section.
    pub(crate) next_offset: u32,

    /// The total size of all added strings, used for statistics.
    pub(crate) totally_added: usize,

    /// The total number of all added strings, used for statistics.
    pub(crate) totally_added_strings: usize,

    /// The offsets of each string in the output section keyed by the string contents.
    pub(crate) string_offsets: PassThroughHashMap<StringToMerge<'data>, u32>,
}

/// Merges identical strings from all loaded objects where those strings are from input sections
/// that are marked with both the SHF_MERGE and SHF_STRINGS flags.
#[tracing::instrument(skip_all, name = "Merge strings")]
pub(crate) fn merge_strings<'data>(
    resolved: &mut [ResolvedGroup<'data>],
    output_sections: &OutputSections,
) -> Result<OutputSectionMap<MergeStringsSection<'data>>> {
    let input_sections = group_merge_string_sections_by_output(resolved, output_sections)?;

    let mut strings_by_section = output_sections.new_section_map::<MergeStringsSection>();

    // The number of workers we create is a trade off. A higher number will mean more input sections
    // get processed in each cycle, which will likely mean less cycles and thus less total time
    // spent waiting for the last work item in each batch to finish. However, it will mean more heap
    // allocations. Processing more input sections in each batch may also reduce the chances of
    // having stuff still in cache.
    let num_workers = 64;
    let mut workers = vec![StringMergeWorker::default(); num_workers];

    input_sections.try_for_each(|section_id, input_sections| {
        let output_section = strings_by_section.get_mut(section_id);
        output_section.add_input_sections(input_sections, &mut workers)
    })?;

    strings_by_section.for_each(|section_id, sec| {
        if sec.len() > 0 {
            tracing::debug!(target: "metrics", section = ?output_sections.name(section_id), size = sec.len(),
                totally_added = sec.totally_added(), strings = sec.string_count(), totally_added_strings = sec.totally_added_strings(),
                "merge_strings");
        }
    });

    Ok(strings_by_section)
}

// Gather up all the string-merge sections, grouping them by their output section ID. We return a
// reference to the `MergeStringsFileSection` rather than copying it because it appears to be
// faster.
fn group_merge_string_sections_by_output<'data, 'a>(
    resolved: &'a [ResolvedGroup<'data>],
    output_sections: &OutputSections,
) -> Result<OutputSectionMap<Vec<&'a MergeStringsFileSection<'data>>>> {
    let mut input_sections = output_sections.new_section_map::<Vec<&MergeStringsFileSection>>();

    for group in resolved {
        for file in &group.files {
            let ResolvedFile::Object(obj) = file else {
                continue;
            };
            let Some(non_dynamic) = obj.non_dynamic.as_ref() else {
                continue;
            };
            for &section_index in &non_dynamic.merge_strings_section_indexes {
                let SectionSlot::MergeStrings(sec) = &non_dynamic.sections[section_index.0] else {
                    bail!("Internal error: expected SectionSlot::MergeStrings");
                };
                input_sections
                    .get_mut(sec.part_id.output_section_id())
                    .push(sec);
            }
        }
    }

    Ok(input_sections)
}

#[derive(Default, Clone)]
struct StringMergeWorker<'data> {
    buckets: [Vec<PreHashed<StringToMerge<'data>>>; MERGE_STRING_BUCKETS],
}

impl StringMergeWorker<'_> {
    fn clear(&mut self) {
        for b in &mut self.buckets {
            b.clear();
        }
    }
}

impl<'data> MergeStringsSection<'data> {
    fn add_input_sections(
        &mut self,
        input_sections: &[&MergeStringsFileSection<'data>],
        workers: &mut [StringMergeWorker<'data>],
    ) -> Result {
        for chunk_sections in input_sections.chunks(workers.len()) {
            let active_work_items = &mut workers[..chunk_sections.len()];

            // Split our sections into strings and hash those strings, collecting the results into
            // buckets based on the string hashes.
            active_work_items
                .par_iter_mut()
                .zip(chunk_sections)
                .try_for_each(|(work_item, input_section)| -> Result {
                    work_item.clear();
                    let mut remaining = input_section.section_data;
                    while !remaining.is_empty() {
                        let string = StringToMerge::take_hashed(&mut remaining)?;
                        work_item.buckets[(string.hash() as usize) % MERGE_STRING_BUCKETS]
                            .push(string);
                    }
                    Ok(())
                })?;

            let active_work_items = &active_work_items[..];

            // Process each bucket in parallel, taking all the per-bucket outputs from the previous
            // step and merging them.
            self.buckets
                .par_iter_mut()
                .enumerate()
                .for_each(|(bucket_index, bucket_out)| {
                    for work_item in active_work_items {
                        for string in &work_item.buckets[bucket_index] {
                            bucket_out.add_string(*string);
                        }
                    }
                });
        }

        // Compute the starting offset of each bucket.
        for i in 1..MERGE_STRING_BUCKETS {
            self.bucket_offsets[i] = self.bucket_offsets[i - 1] + self.buckets[i - 1].len();
        }

        Ok(())
    }

    pub(crate) fn get(&self, string: &PreHashed<StringToMerge<'data>>) -> Option<u64> {
        let bucket_index = (string.hash() as usize) % MERGE_STRING_BUCKETS;
        self.buckets[bucket_index]
            .get(string)
            .map(|offset| self.bucket_offsets[bucket_index] + u64::from(offset))
    }

    pub(crate) fn len(&self) -> u64 {
        self.bucket_offsets[MERGE_STRING_BUCKETS - 1]
            + u64::from(self.buckets[MERGE_STRING_BUCKETS - 1].next_offset)
    }

    pub(crate) fn totally_added(&self) -> usize {
        self.buckets.iter().map(|b| b.totally_added).sum()
    }

    pub(crate) fn totally_added_strings(&self) -> usize {
        self.buckets.iter().map(|b| b.totally_added_strings).sum()
    }

    pub(crate) fn string_count(&self) -> usize {
        self.buckets.iter().map(|b| b.strings.len()).sum()
    }
}

impl<'data> MergeStringsSectionBucket<'data> {
    /// Adds `string`, deduplicating with an existing string if an identical string is already
    /// present.
    fn add_string(&mut self, string: PreHashed<StringToMerge<'data>>) {
        self.totally_added += string.bytes.len();
        self.totally_added_strings += 1;
        self.string_offsets.entry(string).or_insert_with(|| {
            let offset = self.next_offset;
            self.next_offset += string.bytes.len() as u32;
            self.strings.push(string.bytes);
            offset
        });
    }

    pub(crate) fn get(&self, string: &PreHashed<StringToMerge<'data>>) -> Option<u32> {
        self.string_offsets.get(string).copied()
    }

    pub(crate) fn len(&self) -> u64 {
        u64::from(self.next_offset)
    }
}

impl<'data> StringToMerge<'data> {
    /// Takes from `source` up to the next null terminator. Returns a prehashed reference to what
    /// was taken.
    pub(crate) fn take_hashed(source: &mut &'data [u8]) -> Result<PreHashed<StringToMerge<'data>>> {
        let len = memchr::memchr(0, source)
            .map(|i| i + 1)
            .context("String in merge-string section is not null-terminated")?;
        let (bytes, rest) = source.split_at(len);
        let hash = crate::hash::hash_bytes(bytes);
        *source = rest;
        Ok(PreHashed::new(StringToMerge { bytes }, hash))
    }
}

/// Looks for a merged string at `symbol_index` + `addend` in the input and if found, returns its
/// address in the output.
pub(crate) fn get_merged_string_output_address(
    symbol_index: object::SymbolIndex,
    addend: u64,
    object: &crate::elf::File,
    sections: &[SectionSlot],
    merged_strings: &OutputSectionMap<MergeStringsSection>,
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
    let data = merge_slot.section_data;
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

    if input_offset > data.len() as u64 {
        bail!(
            "Invalid merge-string offset {input_offset} in section of length {}",
            data.len()
        );
    }

    let string = StringToMerge::take_hashed(&mut &data[input_offset as usize..])?;
    let section_id = merge_slot.part_id.output_section_id();
    let strings_section = merged_strings.get(section_id);
    let output_offset = strings_section
        .get(&string)
        .with_context(|| format!("Failed to find merge-string `{}`", *string))?;
    let section_base = merged_string_start_addresses.addresses.get(section_id);
    let mut address = section_base + output_offset;
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
    ) -> Self {
        let mut addresses = OutputSectionMap::with_size(output_sections.num_sections());
        let internal_start_offsets = starting_mem_offsets_by_group.first().unwrap();
        for i in 0..output_sections.num_regular_sections() {
            let section_id = OutputSectionId::regular(i as u32);
            *addresses.get_mut(section_id) =
                *internal_start_offsets.get(section_id.part_id_with_alignment(alignment::MIN));
        }
        Self { addresses }
    }
}

impl std::fmt::Display for StringToMerge<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.bytes))
    }
}
