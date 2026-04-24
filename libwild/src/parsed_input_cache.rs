//! Zero-copy on-disk cache for the parsed form of an input object.
//!
//! Tier-1 of wild's incremental-linking plan (see
//! `project_incremental_link_plan.md`) needs a fast path that skips
//! re-parsing a clean input's symbol table on every link. Postcard-
//! serialised caches would pay a fresh allocation + copy on every
//! deserialisation — wild already mmaps every input, so this module
//! stores the cached parse result in the same shape: a fixed-layout,
//! `repr(C)` blob that can be `mmap`ed and interpreted in place.
//!
//! # Format (schema v1)
//!
//! ```text
//! +------------------ CacheHeader (48 bytes) -----------------+
//! | magic [8]  schema u32  flags u32  n_symbols u64           |
//! | symbols_off u64  names_off u64  names_len u64             |
//! +--- symbols (n_symbols × sizeof(CachedSymbol) = 24 bytes) -+
//! | [name_off u32] [name_len u32] [hash u64] [flags u32]       |
//! | [kind u8] [_pad u8×3]                                      |
//! | …                                                          |
//! +-------------------- names blob -----------------------------+
//! | symbol name bytes, concatenated, NUL-separated optional    |
//! +------------------------------------------------------------+
//! ```
//!
//! The whole file is `8`-byte aligned so the symbol-array cast is
//! sound on every supported arch. On load we validate magic +
//! schema, then cast the symbol region straight to
//! `&[CachedSymbol]`. Name bytes are returned as slices into the
//! mmap'd buffer — zero copy, no lifetime juggling beyond the
//! borrow of the backing `&'data [u8]`.
//!
//! **Not yet hooked into the main loader.** Landing this module
//! first (with round-trip tests) gives the next session a green
//! foundation to slot a cache-lookup into `load_inputs`. Shipping
//! the wiring before the format is settled would be the same shape
//! of risk that bit us on the Mach-O umbrella regression — a
//! correctness-critical change fused with a storage-format churn.

use std::mem::size_of;
use std::path::Path;
use std::path::PathBuf;

/// Locate the on-disk cache file for a given input. Returns
/// `None` when we can't determine a cache directory (no
/// `$XDG_CACHE_HOME` *and* no `$HOME`), in which case callers
/// fall back to the re-parse path without caching.
///
/// File name is derived from blake3(absolute_input_path) ‖ schema
/// so different inputs with the same basename (very common across
/// cargo's `deps/` directory — the `libfoo-<hash>.rlib` shape) can't
/// collide. `std::path::Path::canonicalize` is deliberately NOT
/// used here: wild's input fingerprints are path-string-based too,
/// so staying symlink-literal keeps the two layers consistent.
pub(crate) fn cache_path_for_input(input: &Path) -> Option<PathBuf> {
    let dir = if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        PathBuf::from(xdg).join("wild").join("parsed-inputs")
    } else {
        let home = std::env::var_os("HOME")?;
        PathBuf::from(home)
            .join(".cache")
            .join("wild")
            .join("parsed-inputs")
    };
    let mut key = blake3::Hasher::new();
    key.update(input.as_os_str().as_encoded_bytes());
    key.update(&SCHEMA.to_le_bytes());
    let hex = key.finalize().to_hex();
    Some(dir.join(format!("{hex}.wildpi")))
}

/// 8-byte magic at the head of every cache file. Distinct from
/// `WILDIH01` (the `.wild-hashes` side-car magic) so mixing the two
/// fails loudly at `load`.
const MAGIC: &[u8; 8] = b"WILDPI01";

/// Schema is hand-bumped whenever `CacheHeader` or `CachedSymbol`
/// grows/shrinks a field. Cache files carrying an older schema are
/// rejected cleanly and the caller falls back to re-parsing.
const SCHEMA: u32 = 1;

/// Alignment requirement for the whole file: we cast the symbol
/// region to `&[CachedSymbol]` which must land on an 8-byte
/// boundary. Since we control layout (header is 56 bytes = 8×7,
/// symbols start immediately after) this is free, but we assert it
/// at load time to be safe.
const REQUIRED_ALIGN: usize = 8;

/// Symbol kind tag. `u8` so it packs into `CachedSymbol` without
/// bloat; exhaustive on purpose so new variants force a schema bump.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CachedSymbolKind {
    Undefined = 0,
    Local = 1,
    /// Non-local, defined. Covers the usual "global" + "weak defined"
    /// cases; wild's `load_symbols` differentiates further via
    /// `flags`.
    Defined = 2,
}

impl CachedSymbolKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Undefined),
            1 => Some(Self::Local),
            2 => Some(Self::Defined),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CacheHeader {
    magic: [u8; 8],
    schema: u32,
    flags: u32,
    n_symbols: u64,
    symbols_off: u64,
    names_off: u64,
    names_len: u64,
}

const _: () = {
    // Size must be stable (changes force schema bump). Field
    // accounting: magic(8) + schema(4) + flags(4) + n_symbols(8)
    // + symbols_off(8) + names_off(8) + names_len(8) = 48.
    assert!(size_of::<CacheHeader>() == 48);
    // Alignment must not exceed the whole-file guarantee.
    assert!(std::mem::align_of::<CacheHeader>() <= REQUIRED_ALIGN);
};

#[repr(C)]
#[derive(Clone, Copy)]
struct CachedSymbol {
    name_off: u32,
    name_len: u32,
    hash: u64,
    flags: u32,
    kind: u8,
    _pad: [u8; 3],
}

const _: () = {
    assert!(size_of::<CachedSymbol>() == 24);
    assert!(std::mem::align_of::<CachedSymbol>() <= REQUIRED_ALIGN);
};

/// Zero-copy view over a cache buffer. Holds the mmap'd bytes by
/// reference and yields iterator entries that also borrow into the
/// same buffer.
pub(crate) struct CacheView<'data> {
    bytes: &'data [u8],
    header: &'data CacheHeader,
    symbols: &'data [CachedSymbol],
    names: &'data [u8],
}

/// One entry out of the cache, fully resolved — `name` is a slice
/// into the cache mmap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CachedEntry<'data> {
    pub(crate) name: &'data [u8],
    pub(crate) hash: u64,
    pub(crate) flags: u32,
    pub(crate) kind: CachedSymbolKind,
}

impl<'data> CacheView<'data> {
    /// Validate + construct a view. Returns `None` on any mismatch —
    /// callers fall back to the re-parse path. We never `panic!`
    /// here: a stale/corrupt cache must never prevent the link.
    pub(crate) fn from_bytes(bytes: &'data [u8]) -> Option<Self> {
        if bytes.len() < size_of::<CacheHeader>() {
            return None;
        }
        if bytes.as_ptr() as usize % REQUIRED_ALIGN != 0 {
            // `mmap` always returns page-aligned pointers so this
            // only trips for in-memory tests on misaligned buffers.
            return None;
        }
        let header = unsafe { &*(bytes.as_ptr() as *const CacheHeader) };
        if &header.magic != MAGIC {
            return None;
        }
        if header.schema != SCHEMA {
            return None;
        }
        let n = header.n_symbols as usize;
        let sym_start = header.symbols_off as usize;
        let sym_end = sym_start.checked_add(n.checked_mul(size_of::<CachedSymbol>())?)?;
        if sym_end > bytes.len() {
            return None;
        }
        if sym_start % std::mem::align_of::<CachedSymbol>() != 0 {
            return None;
        }
        let names_start = header.names_off as usize;
        let names_end = names_start.checked_add(header.names_len as usize)?;
        if names_end > bytes.len() {
            return None;
        }
        let symbols = unsafe {
            std::slice::from_raw_parts(bytes.as_ptr().add(sym_start) as *const CachedSymbol, n)
        };
        let names = &bytes[names_start..names_end];
        Some(Self {
            bytes,
            header,
            symbols,
            names,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.header.n_symbols as usize
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Resolve one entry. Returns `None` only on corruption
    /// (out-of-range name slice or unknown kind tag).
    pub(crate) fn get(&self, idx: usize) -> Option<CachedEntry<'data>> {
        let s = self.symbols.get(idx)?;
        let off = s.name_off as usize;
        let len = s.name_len as usize;
        let name = self.names.get(off..off.checked_add(len)?)?;
        let kind = CachedSymbolKind::from_u8(s.kind)?;
        Some(CachedEntry {
            name,
            hash: s.hash,
            flags: s.flags,
            kind,
        })
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = CachedEntry<'data>> + '_ {
        (0..self.len()).filter_map(move |i| self.get(i))
    }

    /// Raw bytes backing this view. Useful only for pass-through
    /// tests that want to exercise `from_bytes` again.
    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> &'data [u8] {
        self.bytes
    }
}

/// Builder for a fresh cache. Accepts entries one by one and emits
/// a single `Vec<u8>` ready for `write`. Callers are responsible
/// for atomically replacing the old cache file (write-to-tmp,
/// rename) to avoid torn reads under racing links.
pub(crate) struct CacheBuilder {
    entries: Vec<CachedSymbol>,
    names: Vec<u8>,
    // Dedup identical names so two symbols with the same string
    // share the same name_off/name_len pair. Saves a little space
    // and matches how symbol tables usually look (weak/strong pairs
    // sharing a name).
    name_map: hashbrown::HashMap<Vec<u8>, (u32, u32), foldhash::fast::FixedState>,
}

impl Default for CacheBuilder {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            names: Vec::new(),
            name_map: hashbrown::HashMap::with_hasher(Default::default()),
        }
    }
}

impl CacheBuilder {
    pub(crate) fn add(&mut self, name: &[u8], hash: u64, flags: u32, kind: CachedSymbolKind) {
        let (name_off, name_len) = match self.name_map.get(name) {
            Some(&p) => p,
            None => {
                let off = self.names.len() as u32;
                let len = name.len() as u32;
                self.names.extend_from_slice(name);
                self.name_map.insert(name.to_vec(), (off, len));
                (off, len)
            }
        };
        self.entries.push(CachedSymbol {
            name_off,
            name_len,
            hash,
            flags,
            kind: kind as u8,
            _pad: [0; 3],
        });
    }

    /// Atomically write the cache to `path`. Uses the same
    /// tmp-file-and-rename pattern as other wild side-cars so a
    /// concurrent reader never observes a torn cache.
    pub(crate) fn write_to(self, path: &std::path::Path) -> std::io::Result<()> {
        let bytes = self.finish();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("wildpi.tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        let header_size = size_of::<CacheHeader>();
        let sym_bytes = self.entries.len() * size_of::<CachedSymbol>();
        // Names go right after the symbol region. Pad symbol region
        // to 8 bytes (already aligned by construction — CachedSymbol
        // is 24 bytes, any multiple of 24 is also a multiple of 8).
        let symbols_off = header_size;
        let names_off = symbols_off + sym_bytes;
        let names_len = self.names.len();
        let total = names_off + names_len;

        let mut out = Vec::with_capacity(total);
        let header = CacheHeader {
            magic: *MAGIC,
            schema: SCHEMA,
            flags: 0,
            n_symbols: self.entries.len() as u64,
            symbols_off: symbols_off as u64,
            names_off: names_off as u64,
            names_len: names_len as u64,
        };
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(&header as *const CacheHeader as *const u8, header_size)
        };
        out.extend_from_slice(hdr_bytes);
        let sym_raw =
            unsafe { std::slice::from_raw_parts(self.entries.as_ptr() as *const u8, sym_bytes) };
        out.extend_from_slice(sym_raw);
        out.extend_from_slice(&self.names);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Force an 8-byte aligned backing buffer so `from_bytes` accepts
    /// the test slice. On real use the mmap'd page is always
    /// page-aligned.
    #[repr(C, align(8))]
    struct Aligned<const N: usize>([u8; N]);

    fn aligned(bytes: &[u8]) -> Box<[u8]> {
        // Copy into an over-aligned Vec. We ensure alignment by using
        // an 8-byte-aligned ZST prefix via `Box::from`.
        let layout = std::alloc::Layout::from_size_align(bytes.len().max(1), 8).unwrap();
        unsafe {
            let ptr = std::alloc::alloc(layout);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
            let slice = std::slice::from_raw_parts_mut(ptr, bytes.len());
            Box::from_raw(slice)
        }
    }

    #[test]
    fn roundtrip_single_symbol() {
        let mut b = CacheBuilder::default();
        b.add(b"_main", 0xdead_beef, 0x11, CachedSymbolKind::Defined);
        let bytes = b.finish();
        let buf = aligned(&bytes);
        let view = CacheView::from_bytes(&buf).expect("view");
        assert_eq!(view.len(), 1);
        let e = view.get(0).unwrap();
        assert_eq!(e.name, b"_main");
        assert_eq!(e.hash, 0xdead_beef);
        assert_eq!(e.flags, 0x11);
        assert_eq!(e.kind, CachedSymbolKind::Defined);
    }

    #[test]
    fn roundtrip_many_and_iter_order_preserved() {
        let mut b = CacheBuilder::default();
        let fixtures: &[(&[u8], u64, u32, CachedSymbolKind)] = &[
            (b"_start", 1, 0, CachedSymbolKind::Local),
            (b"_main", 2, 0x11, CachedSymbolKind::Defined),
            (b"_printf", 3, 0, CachedSymbolKind::Undefined),
            (b"", 4, 0, CachedSymbolKind::Defined), // empty name is valid
        ];
        for &(n, h, f, k) in fixtures {
            b.add(n, h, f, k);
        }
        let bytes = b.finish();
        let buf = aligned(&bytes);
        let view = CacheView::from_bytes(&buf).unwrap();
        let got: Vec<_> = view.iter().collect();
        assert_eq!(got.len(), fixtures.len());
        for (g, &(n, h, f, k)) in got.iter().zip(fixtures) {
            assert_eq!(g.name, n);
            assert_eq!(g.hash, h);
            assert_eq!(g.flags, f);
            assert_eq!(g.kind, k);
        }
    }

    #[test]
    fn name_dedup_shares_bytes() {
        // Two symbols with the same name should share the names
        // region — confirms the builder actually dedups.
        let mut b = CacheBuilder::default();
        b.add(b"_shared", 1, 0, CachedSymbolKind::Defined);
        b.add(b"_shared", 2, 0, CachedSymbolKind::Local);
        let bytes = b.finish();
        let buf = aligned(&bytes);
        let view = CacheView::from_bytes(&buf).unwrap();
        assert_eq!(view.len(), 2);
        // Names region should contain "_shared" exactly once.
        let names_off = view.header.names_off as usize;
        let names_len = view.header.names_len as usize;
        assert_eq!(names_len, b"_shared".len());
        assert_eq!(&buf[names_off..names_off + names_len], b"_shared");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = CacheBuilder::default();
        b.add(b"_x", 1, 0, CachedSymbolKind::Defined);
        let mut bytes = b.finish();
        // Flip one magic byte.
        bytes[0] ^= 1;
        let buf = aligned(&bytes);
        assert!(CacheView::from_bytes(&buf).is_none());
    }

    #[test]
    fn rejects_bad_schema() {
        let mut b = CacheBuilder::default();
        b.add(b"_x", 1, 0, CachedSymbolKind::Defined);
        let mut bytes = b.finish();
        // Bump schema field past known value. Layout: magic[8] then
        // schema u32 little-endian at offset 8.
        bytes[8] = (SCHEMA + 1) as u8;
        let buf = aligned(&bytes);
        assert!(CacheView::from_bytes(&buf).is_none());
    }

    #[test]
    fn rejects_truncated_buffer() {
        let mut b = CacheBuilder::default();
        b.add(b"_truncated", 1, 0, CachedSymbolKind::Defined);
        let bytes = b.finish();
        // Drop the last 5 bytes of the names region.
        let truncated = &bytes[..bytes.len() - 5];
        let buf = aligned(truncated);
        assert!(CacheView::from_bytes(&buf).is_none());
    }

    #[test]
    fn rejects_misaligned_buffer() {
        // Force a buffer that begins at an odd address. We copy the
        // cache into a Vec and then view it starting one byte in —
        // guaranteed misaligned.
        let mut b = CacheBuilder::default();
        b.add(b"_x", 1, 0, CachedSymbolKind::Defined);
        let bytes = b.finish();
        let mut padded = Vec::with_capacity(bytes.len() + 1);
        padded.push(0u8);
        padded.extend_from_slice(&bytes);
        // The real cache starts at padded[1..]; its ptr is
        // padded.as_ptr() + 1, which is odd-aligned.
        let view_bytes = &padded[1..];
        assert!(CacheView::from_bytes(view_bytes).is_none());
    }

    #[test]
    fn unknown_kind_tag_returns_none_from_get() {
        // Build a valid cache, then poke an invalid kind byte.
        let mut b = CacheBuilder::default();
        b.add(b"_x", 1, 0, CachedSymbolKind::Defined);
        let mut bytes = b.finish();
        // Find the symbol region and overwrite the kind byte with 99.
        let hdr_size = size_of::<CacheHeader>();
        // CachedSymbol layout: name_off(4) name_len(4) hash(8) flags(4) kind(1)
        let kind_off = hdr_size + 4 + 4 + 8 + 4;
        bytes[kind_off] = 99;
        let buf = aligned(&bytes);
        let view = CacheView::from_bytes(&buf).expect("structure still valid");
        assert_eq!(view.len(), 1);
        // Per-entry `get` reports None rather than panicking.
        assert!(view.get(0).is_none());
    }

    #[test]
    fn empty_cache_roundtrips() {
        let b = CacheBuilder::default();
        let bytes = b.finish();
        let buf = aligned(&bytes);
        let view = CacheView::from_bytes(&buf).unwrap();
        assert!(view.is_empty());
        assert_eq!(view.iter().count(), 0);
    }

    #[test]
    fn write_to_atomically_persists_and_reloads() {
        let mut b = CacheBuilder::default();
        b.add(b"_a", 1, 0, CachedSymbolKind::Defined);
        b.add(b"_b", 2, 0x10, CachedSymbolKind::Undefined);

        let tmp =
            std::env::temp_dir().join(format!("wild-parsed-cache-{}.wildpi", std::process::id()));
        let _ = std::fs::remove_file(&tmp);

        b.write_to(&tmp).expect("write");
        // The tmp-suffix file must not be left behind — rename
        // should have consumed it.
        let leftover = tmp.with_extension("wildpi.tmp");
        assert!(!leftover.exists(), "tmp {leftover:?} should be gone");

        let bytes = std::fs::read(&tmp).unwrap();
        let buf = aligned(&bytes);
        let view = CacheView::from_bytes(&buf).expect("view from file bytes");
        assert_eq!(view.len(), 2);
        assert_eq!(view.get(0).unwrap().name, b"_a");
        assert_eq!(view.get(1).unwrap().name, b"_b");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn cache_path_derivation_is_collision_free_for_same_basename() {
        // The `libfoo-<hash>.rlib` cargo convention means multiple
        // inputs with the same basename live in different dirs.
        // cache_path_for_input must disambiguate.
        // Force XDG_CACHE_HOME so the test is deterministic.
        let prev = std::env::var_os("XDG_CACHE_HOME");
        unsafe {
            std::env::set_var("XDG_CACHE_HOME", std::env::temp_dir());
        }
        let a = cache_path_for_input(Path::new("/tmp/build-a/libfoo-abc.rlib"));
        let b = cache_path_for_input(Path::new("/tmp/build-b/libfoo-abc.rlib"));
        let a = a.expect("a");
        let b = b.expect("b");
        assert_ne!(
            a, b,
            "same-basename inputs from different dirs produced the same cache path"
        );
        // Same input twice → same cache path.
        let a2 = cache_path_for_input(Path::new("/tmp/build-a/libfoo-abc.rlib")).unwrap();
        assert_eq!(a, a2, "identical input path produced different cache paths");
        // Restore env.
        match prev {
            Some(v) => unsafe { std::env::set_var("XDG_CACHE_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_CACHE_HOME") },
        }
    }

    #[test]
    fn names_are_zero_copy_into_backing_buffer() {
        // Stress the zero-copy property: the name slice returned by
        // `get` must point inside the cache bytes, not into some
        // heap-allocated String.
        let mut b = CacheBuilder::default();
        b.add(b"_zcopy", 0, 0, CachedSymbolKind::Defined);
        let bytes = b.finish();
        let buf = aligned(&bytes);
        let view = CacheView::from_bytes(&buf).unwrap();
        let entry = view.get(0).unwrap();
        let name_ptr = entry.name.as_ptr() as usize;
        let buf_start = buf.as_ptr() as usize;
        let buf_end = buf_start + buf.len();
        assert!(
            (buf_start..buf_end).contains(&name_ptr),
            "name slice at {name_ptr:#x} outside buffer [{buf_start:#x}..{buf_end:#x})"
        );
    }
}
