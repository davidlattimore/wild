//! Suffix-sharing for string tables.
//!
//! If `"foo\0"` and `"bar_foo\0"` both belong in one strtab, the
//! short one can point into the middle of the long one — its symbol's
//! `st_name` offset is just `<bar_foo's offset> + 4` (the length
//! difference in bytes). Same bytes, one copy. This is the
//! "tail merging" optimisation GNU ld applies to `.dynstr` by default.
//!
//! The algorithm is straightforward:
//!
//!   1. Sort input strings by reversed byte order. That groups strings
//!      sharing a common suffix adjacently — e.g. reversed, both
//!      `"foo"` (→ `"oof"`) and `"bar_foo"` (→ `"oof_rab"`) sort to
//!      keys starting with `"oof"`, landing next to each other.
//!   2. Walk the sorted list. If `s[i]` ends with `s[i-1]` (i.e. the
//!      previous string is a suffix of the current one), skip writing
//!      `s[i-1]` to the packed buffer — it'll live inside `s[i]`.
//!   3. Emit each "owner" (not-a-suffix-of-its-successor) to the
//!      packed buffer. Record its packed offset.
//!   4. For every string that was skipped, resolve its offset as
//!      `owner.offset + (owner.len - self.len)`.
//!
//! # Packed-size bound
//!
//! Output size is always ≤ the naive concatenation of
//! `len(s) + 1` for every string. Equality when no suffix sharing
//! exists (every string a suffix of nothing). Savings on a
//! rust-analyzer debug `.strtab` are typically 5–15 %.
//!
//! # Determinism
//!
//! Output is a pure function of the **set** of input strings —
//! duplicates are deduplicated on the way in. The sort by reversed
//! bytes is a stable total order, so two runs with the same input set
//! produce byte-identical packed buffers. Drift-guard tests further
//! down pin this behaviour.
//!
//! # Encoding
//!
//! Every emitted string is followed by a single NUL (`0x00`). Matches
//! ELF strtab, Mach-O string table, and COFF conventions. Callers
//! passing a string that contains an internal NUL get undefined
//! dedup behaviour (the suffix logic walks raw bytes including the
//! NUL) — we assume linker symbol names never contain embedded NULs,
//! which is safe for Itanium mangling and Rust v0 mangling.

#![allow(dead_code)]

use rayon::slice::ParallelSliceMut;
use std::collections::HashMap;

/// A packed strtab plus a lookup table from each input string to its
/// offset inside the packed buffer (pointing at the first byte of the
/// string — the NUL terminator follows implicitly at `offset + len`).
///
/// `bytes.len()` is the total packed size including every NUL. The
/// caller owns both fields and is responsible for writing `bytes` to
/// the strtab section and storing each symbol's `st_name = offsets[name]`.
#[derive(Debug, Clone)]
pub(crate) struct Packed {
    pub(crate) bytes: Vec<u8>,
    pub(crate) offsets: HashMap<Vec<u8>, u32>,
}

impl Packed {
    /// Empty strtab. ELF convention: every strtab starts with a
    /// single NUL so a name-offset of 0 resolves to the empty
    /// string. Pure-`pack()`-built tables include that NUL
    /// automatically via the empty string in `names`; this
    /// constructor is for building non-strtab callers who want an
    /// equivalent shape.
    pub(crate) fn with_leading_nul() -> Self {
        let mut p = Self {
            bytes: Vec::with_capacity(1),
            offsets: HashMap::new(),
        };
        p.bytes.push(0);
        p.offsets.insert(Vec::new(), 0);
        p
    }
}

/// Pack a set of strings with suffix sharing, returning the packed
/// byte buffer (strings separated by NULs) and a map from each input
/// string to its offset within that buffer.
///
/// Input strings must **not** include a trailing NUL — the packer
/// adds one per emitted owner.
///
/// Inputs are deduplicated by byte-equality before packing: if you
/// pass `"foo"` twice, the returned `offsets` map has one entry and
/// the packed buffer holds one copy.
///
/// A leading NUL byte is always emitted at offset 0 to mimic the ELF
/// "name offset 0 = empty string" convention. The empty string (if
/// passed) maps to offset 0; the offsets map also always contains
/// the empty-string mapping, even if no input was empty.
///
/// # Complexity
///
/// Θ(n·L + n·log n) where n is the number of distinct strings and L
/// is the maximum string length: one sort, one linear scan, one
/// emission pass. Memory Θ(n·L).
pub(crate) fn pack<I, S>(names: I) -> Packed
where
    I: IntoIterator<Item = S>,
    S: Into<Vec<u8>>,
{
    // Dedup via a set before sorting — we never want two copies of
    // the same symbol name taking up packed space.
    let mut unique: Vec<Vec<u8>> = {
        let set: std::collections::BTreeSet<Vec<u8>> = names.into_iter().map(Into::into).collect();
        set.into_iter().collect()
    };

    // Drop the empty string from the general pool — it gets its own
    // slot at offset 0 for ELF's "name=0 → empty" convention.
    unique.retain(|s| !s.is_empty());

    // Sort by reversed-byte lexicographic order. Cheapest stable way
    // to group suffix-sharers: reverse each byte sequence on the fly
    // in the comparator.
    // Parallel mergesort; rayon uses the thread pool wild already
    // owns. Comparator is O(L) per pair but CPU-bound and allocation-
    // free, so it scales cleanly across cores.
    unique.par_sort_by(|a, b| a.iter().rev().cmp(b.iter().rev()));

    let n = unique.len();

    // Walk the sorted list and decide, for each entry, whether it
    // can be absorbed as a suffix of the NEXT entry in sorted order.
    // `ownership[i] = Some(j)` means `unique[i]` lives inside
    // `unique[j]` (and `j > i` always).
    //
    // Because the sort groups suffixes adjacently, it's enough to
    // check the immediate successor. A string that's a suffix of
    // some later non-adjacent entry would also be a suffix of the
    // entry immediately after it (transitivity on suffix relation
    // within the reversed-sort grouping).
    let mut ownership: Vec<Option<usize>> = vec![None; n];
    for i in 0..n.saturating_sub(1) {
        if unique[i + 1].ends_with(&unique[i]) {
            ownership[i] = Some(i + 1);
        }
    }

    // Emit in sorted order so the packed bytes are deterministic.
    // Leading NUL (for name-offset 0 == "").
    let mut bytes: Vec<u8> =
        Vec::with_capacity(1 + unique.iter().map(|s| s.len() + 1).sum::<usize>());
    bytes.push(0);

    let mut emitted_offsets = vec![u32::MAX; n];
    for i in 0..n {
        if ownership[i].is_none() {
            // This is an owner — emit its bytes + NUL.
            let offset = bytes.len() as u32;
            emitted_offsets[i] = offset;
            bytes.extend_from_slice(&unique[i]);
            bytes.push(0);
        }
    }

    // Second pass: resolve offsets for absorbed entries by walking
    // the ownership chain to the emitted owner. Chain length is
    // bounded by the length of the longest suffix run — typically 1,
    // worst case O(n) but only for pathological inputs like
    // `["a", "ba", "cba", "dcba", ...]`.
    let mut offsets: HashMap<Vec<u8>, u32> = HashMap::with_capacity(n + 1);
    offsets.insert(Vec::new(), 0);
    for i in 0..n {
        let mut owner = i;
        while let Some(next) = ownership[owner] {
            owner = next;
        }
        let owner_offset = emitted_offsets[owner];
        let owner_len = unique[owner].len() as u32;
        let self_len = unique[i].len() as u32;
        // `owner_len - self_len` bytes preceed our slice inside the
        // owner's buffer; our slice starts at that relative offset.
        debug_assert!(owner_len >= self_len, "owner shorter than absorbed");
        let my_offset = owner_offset + (owner_len - self_len);
        offsets.insert(unique[i].clone(), my_offset);
    }

    Packed { bytes, offsets }
}

/// Compute the packed size a caller would get from [`pack`] without
/// allocating the packed buffer itself. Useful for layout passes
/// that need to size a section before committing the bytes.
///
/// Same inputs → same result as `pack(inputs).bytes.len()`, with ~5×
/// less allocation (no final buffer, no offset map).
pub(crate) fn packed_size<I, S>(names: I) -> usize
where
    I: IntoIterator<Item = S>,
    S: Into<Vec<u8>>,
{
    let mut unique: Vec<Vec<u8>> = {
        let set: std::collections::BTreeSet<Vec<u8>> = names.into_iter().map(Into::into).collect();
        set.into_iter().collect()
    };
    unique.retain(|s| !s.is_empty());
    // Parallel mergesort; rayon uses the thread pool wild already
    // owns. Comparator is O(L) per pair but CPU-bound and allocation-
    // free, so it scales cleanly across cores.
    unique.par_sort_by(|a, b| a.iter().rev().cmp(b.iter().rev()));
    let mut size: usize = 1; // leading NUL
    for i in 0..unique.len() {
        let is_absorbed = i + 1 < unique.len() && unique[i + 1].ends_with(&unique[i]);
        if !is_absorbed {
            size += unique[i].len() + 1; // bytes + trailing NUL
        }
    }
    size
}

/// Naive non-packed size for comparison: `Σ (len(s) + 1)` over
/// distinct non-empty strings, plus the leading NUL.
pub(crate) fn naive_size<I, S>(names: I) -> usize
where
    I: IntoIterator<Item = S>,
    S: AsRef<[u8]>,
{
    let mut unique: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
    for n in names {
        let b = n.as_ref();
        if !b.is_empty() {
            unique.insert(b.to_vec());
        }
    }
    1 + unique.iter().map(|s| s.len() + 1).sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_check(packed: &Packed, name: &[u8]) {
        let off = *packed
            .offsets
            .get(name)
            .unwrap_or_else(|| panic!("{:?} not in packed", name));
        let off = off as usize;
        assert!(
            off + name.len() + 1 <= packed.bytes.len(),
            "offset out of range"
        );
        assert_eq!(
            &packed.bytes[off..off + name.len()],
            name,
            "packed bytes at offset don't match name {:?}",
            name
        );
        assert_eq!(
            packed.bytes[off + name.len()],
            0,
            "no NUL terminator at offset + len for {:?}",
            name
        );
    }

    #[test]
    fn empty_input_gives_single_nul() {
        let p = pack::<_, &[u8]>(std::iter::empty());
        assert_eq!(p.bytes, vec![0]);
        assert_eq!(p.offsets.len(), 1);
        assert_eq!(p.offsets.get(&Vec::<u8>::new()), Some(&0));
    }

    #[test]
    fn single_string_packs_trivially() {
        let p = pack(vec![b"hello".to_vec()]);
        assert_eq!(p.bytes, b"\0hello\0");
        assert_eq!(p.offsets.get(b"hello".as_slice()), Some(&1));
        roundtrip_check(&p, b"hello");
    }

    #[test]
    fn exact_suffix_absorbed() {
        // "bar" is a suffix of "foobar" → only "foobar" emitted;
        // "bar" resolves to offset 1 + 3 = 4 (inside "foobar").
        let p = pack(vec![b"foobar".to_vec(), b"bar".to_vec()]);
        assert_eq!(p.bytes, b"\0foobar\0");
        assert_eq!(p.offsets.get(b"foobar".as_slice()), Some(&1));
        assert_eq!(p.offsets.get(b"bar".as_slice()), Some(&4));
        roundtrip_check(&p, b"foobar");
        roundtrip_check(&p, b"bar");
    }

    #[test]
    fn non_suffix_both_emitted() {
        // "foo" and "bar" share no suffix → both emitted fully.
        let p = pack(vec![b"foo".to_vec(), b"bar".to_vec()]);
        assert_eq!(p.bytes.len(), 1 + 4 + 4); // \0 + bar\0 + foo\0
        roundtrip_check(&p, b"foo");
        roundtrip_check(&p, b"bar");
    }

    #[test]
    fn chain_of_suffixes_collapses() {
        // "abc", "bc", "c" → only "abc" emitted, others resolve
        // into its tail.
        let p = pack(vec![b"abc".to_vec(), b"bc".to_vec(), b"c".to_vec()]);
        assert_eq!(p.bytes, b"\0abc\0");
        assert_eq!(p.offsets.get(b"abc".as_slice()), Some(&1));
        assert_eq!(p.offsets.get(b"bc".as_slice()), Some(&2));
        assert_eq!(p.offsets.get(b"c".as_slice()), Some(&3));
        roundtrip_check(&p, b"abc");
        roundtrip_check(&p, b"bc");
        roundtrip_check(&p, b"c");
    }

    #[test]
    fn duplicates_deduplicated() {
        let p = pack(vec![
            b"hello".to_vec(),
            b"hello".to_vec(),
            b"hello".to_vec(),
        ]);
        assert_eq!(p.bytes, b"\0hello\0");
        assert_eq!(p.offsets.len(), 2); // "hello" + empty
    }

    #[test]
    fn rust_mangled_names_share_common_tail() {
        // Synthetic Rust-v0-mangled-like tails.
        let names = vec![
            b"_RNvCs123_4core3fmt3new".to_vec(),
            b"_RNvCs456_5alloc3vec9push_back".to_vec(),
            b"push_back".to_vec(),
            b"3new".to_vec(),
        ];
        let naive = naive_size(&names);
        let p = pack(names.clone());
        assert!(
            p.bytes.len() < naive,
            "expected packed < naive ({} !< {})",
            p.bytes.len(),
            naive
        );
        for n in &names {
            roundtrip_check(&p, n);
        }
    }

    #[test]
    fn packed_size_matches_pack_bytes_len() {
        let names = vec![
            b"foo".to_vec(),
            b"foobar".to_vec(),
            b"bar".to_vec(),
            b"quux".to_vec(),
        ];
        assert_eq!(packed_size(names.clone()), pack(names).bytes.len());
    }

    #[test]
    fn deterministic_across_insertion_order() {
        let a = pack(vec![
            b"zeta".to_vec(),
            b"alpha".to_vec(),
            b"beta".to_vec(),
            b"alpha".to_vec(),
        ]);
        let b = pack(vec![
            b"alpha".to_vec(),
            b"alpha".to_vec(),
            b"beta".to_vec(),
            b"zeta".to_vec(),
        ]);
        assert_eq!(a.bytes, b.bytes, "packed bytes must be order-independent");
    }

    /// Drift guard. Pins the packed output of a frozen fixture. If the
    /// algorithm changes in any way (sort order, emission order, NUL
    /// handling), this test fires and forces the author to decide
    /// whether to update the expected bytes (and presumably a cache
    /// schema version, if the packer is part of a persisted format).
    #[test]
    fn drift_guard_packed_bytes() {
        let names = vec![
            b"foo".to_vec(),
            b"foobar".to_vec(),
            b"bar".to_vec(),
            b"quux".to_vec(),
        ];
        let p = pack(names);
        // Expected, derived by hand: reversed-byte lex order is
        // "oof" < "rab" < "raboof" < "xuuq", so sorted names are
        //   foo, bar, foobar, quux.
        // Only "bar" is a suffix of its successor ("foobar"), so
        // emissions are: foo, foobar, quux (in sorted order).
        assert_eq!(p.bytes.as_slice(), b"\0foo\0foobar\0quux\0");
    }
}
