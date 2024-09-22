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
use fxhash::FxHashMap;
use object::read::elf::SectionHeader as _;
use object::read::elf::Sym as _;
use object::LittleEndian;
use rayon::iter::ParallelBridge;
use rayon::iter::ParallelIterator;
use std::collections::HashMap;

const MERGE_STRING_BUCKETS: usize = 32;

/// Information about a string-merge section prior to merging.
pub(crate) struct UnresolvedMergeStringsFileSection<'data> {
    section_index: object::SectionIndex,
    buckets: [Vec<PreHashed<StringToMerge<'data>>>; MERGE_STRING_BUCKETS],
}

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

pub(crate) struct StringOffsetCache {
    /// A map from input offset to output offset. Input offsets are relative to the start of the
    /// input file. Output offsets are relative to the start of the output section. None if caching
    /// is disabled.
    input_to_output: Option<FxHashMap<u64, u64>>,
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
    pub(crate) next_offset: u64,

    /// The total size of all added strings, used for statistics.
    pub(crate) totally_added: usize,

    /// The total number of all added strings, used for statistics.
    pub(crate) totally_added_strings: usize,

    /// The offsets of each string in the output section keyed by the string contents.
    pub(crate) string_offsets: PassThroughHashMap<StringToMerge<'data>, u64>,
}

/// Merges identical strings from all loaded objects where those strings are from input sections
/// that are marked with both the SHF_MERGE and SHF_STRINGS flags.
#[tracing::instrument(skip_all, name = "Merge strings")]
pub(crate) fn merge_strings<'data>(
    resolved: &mut [ResolvedGroup<'data>],
    output_sections: &OutputSections,
) -> Result<OutputSectionMap<MergeStringsSection<'data>>> {
    let mut worklist_per_section: HashMap<OutputSectionId, [Vec<_>; MERGE_STRING_BUCKETS]> =
        HashMap::new();

    for group in resolved {
        for file in &mut group.files {
            let ResolvedFile::Object(obj) = file else {
                continue;
            };
            let Some(non_dynamic) = obj.non_dynamic.as_mut() else {
                continue;
            };
            for merge_info in &non_dynamic.merge_strings_sections {
                let SectionSlot::MergeStrings(sec) =
                    non_dynamic.sections[merge_info.section_index.0]
                else {
                    bail!("Internal error: expected SectionSlot::MergeStrings");
                };

                let id = sec.part_id.output_section_id();
                worklist_per_section.entry(id).or_default();
                for (i, bucket) in worklist_per_section
                    .get_mut(&id)
                    .unwrap()
                    .iter_mut()
                    .enumerate()
                {
                    bucket.push(&merge_info.buckets[i]);
                }
            }
        }
    }

    let mut strings_by_section = output_sections.new_section_map::<MergeStringsSection>();

    for (section_id, buckets) in worklist_per_section.iter() {
        let merged_strings = strings_by_section.get_mut(*section_id);

        buckets
            .iter()
            .zip(merged_strings.buckets.iter_mut())
            .par_bridge()
            .for_each(|(string_lists, merged_strings)| {
                for strings in string_lists {
                    for string in strings.iter() {
                        merged_strings.add_string(*string);
                    }
                }
            });

        for i in 1..MERGE_STRING_BUCKETS {
            merged_strings.bucket_offsets[i] =
                merged_strings.bucket_offsets[i - 1] + merged_strings.buckets[i - 1].len();
        }
    }

    strings_by_section.for_each(|section_id, sec| {
        if sec.len() > 0 {
            let input_sections = worklist_per_section.get(&section_id).unwrap()[0].len();
            tracing::debug!(target: "metrics", section = ?output_sections.name(section_id), size = sec.len(),
                totally_added = sec.totally_added(), strings = sec.string_count(), totally_added_strings = sec.totally_added_strings(),
                input_sections, "merge_strings");
        }
    });

    Ok(strings_by_section)
}

impl<'data> MergeStringsSection<'data> {
    pub(crate) fn get(&self, string: &PreHashed<StringToMerge<'data>>) -> Option<u64> {
        let bucket_index = (string.hash() as usize) % MERGE_STRING_BUCKETS;
        self.buckets[bucket_index]
            .get(string)
            .map(|offset| self.bucket_offsets[bucket_index] + offset)
    }

    pub(crate) fn len(&self) -> u64 {
        self.bucket_offsets[MERGE_STRING_BUCKETS - 1]
            + self.buckets[MERGE_STRING_BUCKETS - 1].next_offset
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
            self.next_offset += string.bytes.len() as u64;
            self.strings.push(string.bytes);
            offset
        });
    }

    pub(crate) fn get(&self, string: &PreHashed<StringToMerge<'data>>) -> Option<u64> {
        self.string_offsets.get(string).copied()
    }

    pub(crate) fn len(&self) -> u64 {
        self.next_offset
    }
}

impl<'data> UnresolvedMergeStringsFileSection<'data> {
    pub(crate) fn new(
        section_data: &'data [u8],
        section_index: object::SectionIndex,
    ) -> Result<UnresolvedMergeStringsFileSection<'data>> {
        let mut remaining = section_data;
        let mut buckets: [Vec<PreHashed<StringToMerge>>; MERGE_STRING_BUCKETS] = Default::default();
        while !remaining.is_empty() {
            let string = StringToMerge::take_hashed(&mut remaining)?;
            buckets[(string.hash() as usize) % MERGE_STRING_BUCKETS].push(string);
        }
        Ok(UnresolvedMergeStringsFileSection {
            section_index,
            buckets,
        })
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
    string_offset_cache: &mut StringOffsetCache,
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

    let input_section_start = object.section(section_index)?.sh_offset(LittleEndian);

    let input_offset_in_file = input_section_start.wrapping_add(input_offset);

    let cache_entry = if let Some(cache) = string_offset_cache.input_to_output.as_mut() {
        match cache.entry(input_offset_in_file) {
            std::collections::hash_map::Entry::Occupied(entry) => return Ok(Some(*entry.get())),
            std::collections::hash_map::Entry::Vacant(entry) => Some(entry),
        }
    } else {
        None
    };

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
    if let Some(cache_entry) = cache_entry {
        cache_entry.insert(address);
    }
    Ok(Some(address))
}

impl StringOffsetCache {
    pub(crate) fn new() -> Self {
        Self {
            input_to_output: Some(Default::default()),
        }
    }

    /// Returns an instance that doesn't cache.
    pub(crate) fn no_caching() -> StringOffsetCache {
        Self {
            input_to_output: None,
        }
    }
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
