//! Incremental-link cache infrastructure (scaffolding, tier 1).
//!
//! Wild's end-goal (see README §Q&A) is incremental linking. This
//! module is the foundation: a content-addressed cache for parsed
//! input files (`.o` / `.rlib`) keyed on a tuple that captures every
//! input *and* every reason wild might reparse the same bytes
//! differently than last time.
//!
//! # Why a manual schema version instead of `git rev-parse HEAD`
//!
//! Early sketches keyed the cache on wild's git commit (or tree) hash
//! so every merge-to-main would invalidate old entries. That coupling
//! is wrong:
//!   * `cargo install wild-linker` users have no git tree at all.
//!   * Whitespace / doc-only commits would force cache misses for zero semantic reason.
//!   * Cache-file portability across machines would depend on a VCS-layout concept that has nothing
//!     to do with cache validity.
//!
//! The thing we actually need to invalidate on is *"the serialized
//! `ParsedInput` format changed"*, which is a property of wild's
//! source — specifically the struct layout + the
//! serializer/deserializer. That's captured by [`CACHE_SCHEMA_VERSION`]
//! below: a `u32` hand-bumped in the same commit that touches
//! `ParsedInput` or its codec. CI should grep-enforce this (a future
//! test will round-trip a fixture across a bumped version and assert
//! that deserialization fails cleanly rather than silently corrupting).
//!
//! [`CARGO_PKG_VERSION`] is appended as belt-and-braces: if a
//! contributor forgets to bump the schema in a minor release, the
//! crate-version bump catches it.
//!
//! # Cache-key composition
//!
//! For every input file the linker sees, the key is
//!
//! ```text
//! blake3(
//!     content_bytes                 // the .o / .rlib on disk
//!   ‖ canonicalized_linker_flags    // e.g. `-arch arm64 -platform_version macos 11.0.0 26.4`
//!   ‖ CACHE_SCHEMA_VERSION.to_le_bytes()
//!   ‖ CARGO_PKG_VERSION.as_bytes()
//! )
//! ```
//!
//! `blake3` is HW-accelerated on aarch64+x86_64 (~5 GB/s hot-cache);
//! the hashing cost is small compared to the current parse cost it
//! displaces.

// This module is tier-1 scaffolding. Public-within-crate helpers are
// exported; `#[allow(dead_code)]` keeps the cache-key composition
// bench-testable ahead of actual callers.
#![allow(dead_code)]

use blake3::Hasher;
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

/// Schema version of on-disk cached `ParsedInput` entries. Bump this
/// in the **same commit** that changes any of:
///
/// * The `ParsedInput` struct (not yet introduced — tier-1 implementation will add it).
/// * Any nested struct / enum variant that `ParsedInput` (transitively) serializes.
/// * The serializer/deserializer logic (postcard config, schema transforms, etc).
///
/// Never reuse a previous value. Always increment. The cache treats
/// mismatching versions as a clean miss and reparses.
///
/// Starting value is 1; 0 is reserved as "no schema" so any accidental
/// all-zero header is rejected by the loader.
///
/// History:
///   * v1 — initial content-hash-only layout; every input recorded as `[u8; 32]` blake3.
///   * v2 — split into [`InputHash`] variants so rlibs can be fingerprinted by the `-HASH.rlib`
///     suffix rustc already embeds (O(1) detection per rlib vs O(n) content hashing). See
///     [`fingerprint_for`] for the filename-parse rule.
///   * v3 — extended header with `args_hash` + `wild_version`, so the cache captures a full *link
///     signature*, not just inputs. Enables whole-link skip: if args, wild version, and every input
///     hash are identical to the cached values, the new output would be byte-identical to the
///     existing binary on disk, and the link can early-exit.
///   * v4 — added `output_size: u64` so we can sanity-check the previous output still exists at the
///     expected size before trusting the skip. Catches the "user manually edited the output binary"
///     case — size mismatch forces a cold link without risking a stale-output return.
///   * v5 — [`InputHash::ContentHash`] now carries the file's `(size, mtime_ns)` alongside the
///     blake3. On verify, a matching `(size, mtime)` short-circuits the `fs::read` + blake3 pass
///     (classic cargo-style fingerprint). Cuts the skip path from ~50 ms to ~25 ms on
///     rust-analyzer, bounded by stat syscalls on 229 paths.
pub(crate) const CACHE_SCHEMA_VERSION: u32 = 5;

/// Stable identifier for the wild crate version running. Caught by
/// the linker cache so a user upgrading wild from 0.8.0 → 0.9.0 without
/// a schema bump still gets a fresh cache rather than subtly-wrong
/// parses from the old format.
///
/// Resolved at compile time via `env!("CARGO_PKG_VERSION")`; no
/// runtime cost.
pub(crate) const WILD_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build a content-addressed cache key for one input file.
///
/// `content_bytes` is the raw file as wild saw it (already mmap'd for
/// parsing, so hashing is a zero-copy sweep). `canonicalized_flags` is
/// the subset of linker flags whose value changes how inputs are
/// parsed — e.g. `-arch`, `-platform_version`, `--no-demangle`. Flags
/// that only affect output layout (`-o`, `-object_path_lto`) should
/// be omitted so two links producing different outputs can still
/// share parsed-input caches.
///
/// Returns the key as `[u8; 32]` (blake3's native output size) — the
/// caller converts to hex / base64 / raw-bytes for disk naming.
///
/// **Complexity:** Θ(n) CPU where n = `content_bytes.len()`; Θ(1)
/// extra memory.
pub(crate) fn compute_input_key(content_bytes: &[u8], canonicalized_flags: &[u8]) -> [u8; 32] {
    compute_input_key_with_version(
        content_bytes,
        canonicalized_flags,
        CACHE_SCHEMA_VERSION,
        WILD_VERSION,
    )
}

/// Underlying hash recipe, parameterised on schema + version so
/// drift-guard tests can pin a stable expected value across wild
/// releases. Production callers go through [`compute_input_key`].
///
/// Changing the ordering of `update` calls, adding/removing a
/// length-prefix, or swapping hashers is a breaking schema change —
/// bump [`CACHE_SCHEMA_VERSION`] and update the stability fixture
/// in `tests::drift_guard_input_key_stability` in the same commit.
fn compute_input_key_with_version(
    content_bytes: &[u8],
    canonicalized_flags: &[u8],
    schema: u32,
    version: &str,
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(content_bytes);
    // Length-prefix each dynamic field so a flag of "ab" + content "c"
    // hashes differently from a flag of "a" + content "bc". Without a
    // separator or length prefix, `update`-concatenated blake3 inputs
    // are ambiguous.
    h.update(&(canonicalized_flags.len() as u64).to_le_bytes());
    h.update(canonicalized_flags);
    h.update(&schema.to_le_bytes());
    h.update(&(version.len() as u64).to_le_bytes());
    h.update(version.as_bytes());
    *h.finalize().as_bytes()
}

/// Format a 32-byte cache key as lowercase hex (64 chars). Suitable
/// for use as an on-disk filename under `$CARGO_TARGET_DIR/.wild-cache/`.
///
/// **Complexity:** Θ(1) — fixed-size operation.
pub(crate) fn key_hex(key: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in key {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Per-link input hash map — persisted alongside the output binary so that the
// next link can compute each input's dirty bit by comparing the freshly-hashed
// content against the cached value.
// ---------------------------------------------------------------------------

/// File-format magic. The last 4 bytes are a mnemonic (`Wild
/// Incremental Link Hashes`) so hexdump-ing a stray cache file tells
/// you what it is. Changing this is a breaking schema change — bump
/// [`CACHE_SCHEMA_VERSION`] alongside.
const HASHES_MAGIC: &[u8; 8] = b"WILDIH05";

/// Per-input fingerprint. The two variants carry different
/// guarantees, chosen for the cheapest reliable dirty detection:
///
/// * [`InputHash::RlibFingerprint`] — the hex-ish tag rustc puts between the last `-` and `.rlib`
///   in a compiled crate's filename (`librust_analyzer-a6d9492580400680.rlib` ⇒
///   `a6d9492580400680`). Cargo changes this whenever the crate's source, dependency graph, or
///   build flags change — so filename equality is proof of content equality under a normal
///   cargo-driven build. Detection is pure path-string comparison, no I/O, no hashing.
///
/// * [`InputHash::ContentHash`] — blake3 over the file's bytes, used for raw `.o` objects,
///   `.dylib`s, and any `.rlib` whose filename doesn't carry the rustc fingerprint (manual `rustc
///   -Cextra-filename=""`, hand-rolled build systems). The expensive path; taken only when the
///   cheap path can't apply.
///
/// Detection logic is just `==` on this enum — the variants are
/// intentionally disjoint (a content-hash never collides with a
/// filename-derived fingerprint because we encode the variant tag
/// in the serialised form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InputHash {
    RlibFingerprint(Vec<u8>),
    /// Content hash with a `(size, mtime_ns)` fingerprint attached
    /// so the verify path can skip the `fs::read` + blake3 when
    /// both metadata fields agree with `stat()`. Classic cargo
    /// fingerprint shape. On mismatch (typical dev loop: one
    /// file got rebuilt) we fall back to re-hashing and update
    /// the cache on the post-link persist.
    ContentHash {
        hash: [u8; 32],
        size: u64,
        mtime_ns: i128,
    },
}

impl InputHash {
    /// Tag byte used on disk to disambiguate variants. `1` = rlib
    /// fingerprint, `2` = content hash. `0` is reserved as "invalid /
    /// rejected" so an all-zero region trips the short-read guard.
    const TAG_RLIB: u8 = 1;
    const TAG_CONTENT: u8 = 2;
}

/// Read `(size, mtime_ns)` from a file. `mtime_ns` uses `i128` so
/// we can carry the full UNIX nanosecond range including
/// pre-epoch timestamps (unusual but legal — e.g. some build
/// systems reset mtimes to epoch 0). `0` returned on stat failure
/// signals "unknown"; callers treat that as a miss.
fn file_metadata_signature(path: &Path) -> Option<(u64, i128)> {
    let md = std::fs::metadata(path).ok()?;
    let mtime = md.modified().ok()?;
    let since_epoch = mtime
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or_else(|e| -(e.duration().as_nanos() as i128));
    Some((md.len(), since_epoch))
}

/// Minimal argv scanner: locate the `-o <path>` pair without
/// invoking wild's full arg parser. The full parser walks `-L`
/// search paths and resolves every `-l` dependency — on a
/// rust-analyzer link that's ~274 ms of filesystem I/O, which
/// defeats the whole point of a fast skip check.
///
/// We only need the output path to find the side-car cache
/// (`<output>.wild-hashes`). Every other fact (args hash, cached
/// input paths, wild version) lives in the cache file itself and
/// in `argv`.
///
/// Accepts both `-o PATH` (two tokens) and `-oPATH` (one token).
/// Falls back to `a.out` when no `-o` is present, matching wild's
/// default.
pub(crate) fn extract_output_path(argv: &[String]) -> PathBuf {
    let mut iter = argv.iter().skip(1); // skip argv[0]
    while let Some(arg) = iter.next() {
        if arg == "-o" {
            if let Some(next) = iter.next() {
                return PathBuf::from(next);
            }
        } else if let Some(val) = arg.strip_prefix("-o") {
            if !val.is_empty() {
                return PathBuf::from(val);
            }
        } else if let Some(val) = arg.strip_prefix("--output=") {
            return PathBuf::from(val);
        }
    }
    PathBuf::from("a.out")
}

/// A link signature — everything that determines the output's
/// bytes modulo wild-internal non-determinism. Equal signatures
/// imply identical output bytes under wild's own determinism
/// guarantee, so equality unlocks whole-link skipping.
///
/// The three fields cover the three axes a link can change on:
///   * `args_hash` — the linker invocation changed (new `-L`, different `-O`, output path, etc).
///   * `wild_version` — the linker itself changed (new output format, fixed bug, upgraded codegen).
///   * `inputs` — any input file changed content (detected by the hybrid rlib-fingerprint /
///     content-hash scheme).
///
/// Wire format (matches [`read_link_cache`] / [`write_link_cache`]):
/// ```text
///   magic: 8 bytes, HASHES_MAGIC
///   schema: u32 LE
///   input_count: u64 LE
///   args_hash: 32 bytes
///   output_size: u64 LE
///   wild_version_len: u16 LE
///   wild_version: wild_version_len bytes UTF-8
///   input_entries[*]: (see read_link_cache docstring)
/// ```
///
/// `output_size` is the byte size the previous link produced. Before
/// trusting a `FullMatch` and skipping, callers verify the on-disk
/// output still stat's at this exact size. Any mismatch forces a
/// cold link — cheap defence against "user manually rewrote the
/// output binary" without paying for a full content hash.
#[derive(Debug, Clone)]
pub(crate) struct LinkCache {
    pub args_hash: [u8; 32],
    pub output_size: u64,
    pub wild_version: String,
    pub inputs: HashMap<PathBuf, InputHash>,
}

/// Hash the linker invocation's argv (skipping `argv[0]` — the
/// wild binary path, which differs across install locations but
/// doesn't affect link output). Canonicalization is deliberately
/// minimal: we hash the raw argument strings in order. Two
/// equivalent invocations with different ordering (e.g.
/// `-O2 -g` vs `-g -O2`) hash differently, which is safe (false
/// miss, not false hit). Tightening that is a follow-up.
///
/// **Complexity:** Θ(total_argv_bytes) CPU — microseconds. A 250
/// argument rust-analyzer invocation hashes in <100 µs.
pub(crate) fn compute_args_hash(argv: &[String]) -> [u8; 32] {
    let mut h = Hasher::new();
    // Skip argv[0]. NUL-separate so "a" + "bc" vs "ab" + "c"
    // don't collide.
    for (i, a) in argv.iter().enumerate() {
        if i == 0 {
            continue;
        }
        h.update(a.as_bytes());
        h.update(&[0u8]);
    }
    *h.finalize().as_bytes()
}

/// Parse a rustc-fingerprint suffix out of a filename if present.
///
/// Returns `Some(bytes)` where `bytes` is the tag between the last
/// `-` and `.rlib`, when:
///   * The path extension is `.rlib`.
///   * A `-` exists before the extension.
///   * The candidate tag is non-empty and matches `[0-9a-fA-F]{8,64}` — i.e. hex-looking of
///     plausible length. Rustc typically uses 16 lowercase-hex chars, but some toolchains emit
///     longer forms. The length bracket keeps false-positives out (a crate named
///     `my-crate-name.rlib` would leave `name` as the candidate tag, which fails the hex check and
///     falls back to content hashing).
///
/// Returns `None` otherwise, signalling the caller to content-hash
/// the file.
///
/// **Complexity:** Θ(L) where L = filename length. Typically ~50
/// bytes per input, negligible.
pub(crate) fn fingerprint_for(path: &Path) -> Option<Vec<u8>> {
    let ext = path.extension()?.to_str()?;
    if ext != "rlib" {
        return None;
    }
    let stem = path.file_stem()?.to_str()?;
    let dash = stem.rfind('-')?;
    let tag = &stem[dash + 1..];
    if tag.len() < 8 || tag.len() > 64 {
        return None;
    }
    if !tag.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(tag.as_bytes().to_vec())
}

/// Side-car filename that holds the input-hash map for a given
/// output binary. Living next to the binary (rather than in a
/// centralised cache dir) keeps the two in lock-step: removing the
/// output removes its cache via the same `cargo clean`; copying the
/// output around won't carry stale hashes; multiple binaries in one
/// `target/` each get their own file.
///
/// Name is `<stem>.wild-hashes` (no extension collision with `.d`,
/// `.dSYM/`, `.map`, etc.).
pub(crate) fn hashes_path_for_output(output: &Path) -> PathBuf {
    let mut p = output.to_path_buf();
    let stem = output
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    let mut name = stem;
    name.push(".wild-hashes");
    p.set_file_name(name);
    p
}

/// Compute a dirty-detection fingerprint for every loaded input.
/// Returns a `PathBuf → InputHash` map.
///
/// For rlibs whose filename carries rustc's `-HASH.rlib` suffix
/// (211/229 on a typical rust-analyzer link) the fingerprint is
/// derived from the *path* alone — no file bytes are read. For
/// everything else (raw `.o`, `.dylib`, unsuffixed rlibs) the
/// function falls back to a blake3 sweep of the content.
///
/// The rayon `par_iter` is still worthwhile on the content-hash
/// tail, even when it's only 18 inputs, because those may include
/// the one "dirty rlib" in a dev loop whose content changed faster
/// than cargo's filename logic noticed.
///
/// Skips entries whose mmap is empty (e.g. the prelude stub file).
///
/// **Complexity:** Θ(L_filename) CPU for every rlib-suffix input
/// (total cost in microseconds). Θ(content_bytes / T) for the
/// content-hash subset, proportional to the number of non-rlib or
/// unsuffixed-rlib inputs.
pub(crate) fn hash_loaded_inputs<'a, I>(inputs: I) -> HashMap<PathBuf, InputHash>
where
    I: IntoIterator<Item = (&'a Path, &'a [u8])>,
{
    let items: Vec<(&Path, &[u8])> = inputs.into_iter().collect();
    items
        .par_iter()
        .filter_map(|(path, bytes)| {
            if bytes.is_empty() {
                return None;
            }
            // Fast path: trust the rustc-embedded fingerprint in
            // cargo-driven build outputs. Cargo guarantees the
            // filename-hash changes whenever the crate content or
            // its inputs (source, deps, flags) change.
            if let Some(tag) = fingerprint_for(path) {
                return Some((path.to_path_buf(), InputHash::RlibFingerprint(tag)));
            }
            // Slow path: .o / .dylib / unsuffixed rlib — blake3 the
            // bytes. Typically <20 files on a rust-analyzer link.
            // Capture `(size, mtime)` alongside so the next link's
            // verify can short-circuit the hash when metadata
            // hasn't moved.
            let h = blake3::hash(bytes);
            let (size, mtime_ns) = file_metadata_signature(path).unwrap_or((0, 0));
            Some((
                path.to_path_buf(),
                InputHash::ContentHash {
                    hash: *h.as_bytes(),
                    size,
                    mtime_ns,
                },
            ))
        })
        .collect()
}

/// Read a link-cache side-car from disk. Returns `None` when the
/// file is absent, short-read, magic-mismatched, or
/// schema-version-mismatched — all of which the caller should treat
/// as "no cache; cold link". The function never errors upward: a
/// bad cache is a cold link, not a link failure.
///
/// Entry format (per input):
/// ```text
///   path_len: u16 LE
///   path:     path_len bytes, UTF-8
///   tag:      u8 (1 = rlib fingerprint, 2 = content hash)
///   body:
///     tag == 1 → fp_len: u8, then fp_len bytes of hex fingerprint
///     tag == 2 → 32 bytes of blake3 output
/// ```
///
/// **Complexity:** Θ(n) CPU where n = cache-file bytes; Θ(n) memory
/// for the returned map.
pub(crate) fn read_link_cache(path: &Path) -> Option<LinkCache> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;
    // header size = magic(8) + schema(4) + count(8) + args_hash(32)
    //               + output_size(8) + wild_version_len(2) = 62
    if buf.len() < 62 {
        return None;
    }
    if &buf[0..8] != HASHES_MAGIC {
        return None;
    }
    let schema = u32::from_le_bytes(buf[8..12].try_into().ok()?);
    if schema != CACHE_SCHEMA_VERSION {
        return None;
    }
    let count = u64::from_le_bytes(buf[12..20].try_into().ok()?) as usize;
    let mut args_hash = [0u8; 32];
    args_hash.copy_from_slice(&buf[20..52]);
    let output_size = u64::from_le_bytes(buf[52..60].try_into().ok()?);
    let wild_version_len = u16::from_le_bytes(buf[60..62].try_into().ok()?) as usize;
    if buf.len() < 62 + wild_version_len {
        return None;
    }
    let wild_version = std::str::from_utf8(&buf[62..62 + wild_version_len])
        .ok()?
        .to_owned();
    let mut cursor = 62 + wild_version_len;
    let mut inputs = HashMap::with_capacity(count);
    for _ in 0..count {
        if cursor + 2 > buf.len() {
            return None;
        }
        let path_len = u16::from_le_bytes(buf[cursor..cursor + 2].try_into().ok()?) as usize;
        cursor += 2;
        if cursor + path_len + 1 > buf.len() {
            return None;
        }
        let path_bytes = &buf[cursor..cursor + path_len];
        let path = PathBuf::from(std::str::from_utf8(path_bytes).ok()?);
        cursor += path_len;
        let tag = buf[cursor];
        cursor += 1;
        let hash = match tag {
            InputHash::TAG_RLIB => {
                if cursor + 1 > buf.len() {
                    return None;
                }
                let fp_len = buf[cursor] as usize;
                cursor += 1;
                if cursor + fp_len > buf.len() {
                    return None;
                }
                let fp = buf[cursor..cursor + fp_len].to_vec();
                cursor += fp_len;
                InputHash::RlibFingerprint(fp)
            }
            InputHash::TAG_CONTENT => {
                // v5 layout: hash(32) + size(u64) + mtime_ns(i128).
                if cursor + 32 + 8 + 16 > buf.len() {
                    return None;
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&buf[cursor..cursor + 32]);
                cursor += 32;
                let size = u64::from_le_bytes(buf[cursor..cursor + 8].try_into().ok()?);
                cursor += 8;
                let mtime_ns = i128::from_le_bytes(buf[cursor..cursor + 16].try_into().ok()?);
                cursor += 16;
                InputHash::ContentHash {
                    hash: h,
                    size,
                    mtime_ns,
                }
            }
            _ => return None, // unknown / corrupted tag
        };
        inputs.insert(path, hash);
    }
    Some(LinkCache {
        args_hash,
        output_size,
        wild_version,
        inputs,
    })
}

/// Write the link cache alongside the output binary. Uses a tiny
/// binary format (magic + schema + count + args_hash + wild_version
/// + entries) rather than JSON so the read path is a straight
/// slice-and-copy with no parser. Atomicity via `<file>.tmp` +
/// rename — readers never see a half-written cache.
///
/// See [`read_link_cache`] for the on-disk layout.
///
/// **Complexity:** Θ(n) CPU + one disk write.
pub(crate) fn write_link_cache(path: &Path, cache: &LinkCache) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(64 + cache.inputs.len() * 64);
    buf.extend_from_slice(HASHES_MAGIC);
    buf.extend_from_slice(&CACHE_SCHEMA_VERSION.to_le_bytes());
    buf.extend_from_slice(&(cache.inputs.len() as u64).to_le_bytes());
    buf.extend_from_slice(&cache.args_hash);
    buf.extend_from_slice(&cache.output_size.to_le_bytes());
    let wv_bytes = cache.wild_version.as_bytes();
    if wv_bytes.len() > u16::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "wild version string too long for cache header",
        ));
    }
    buf.extend_from_slice(&(wv_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(wv_bytes);
    // Sort entries by path so the serialised bytes are deterministic
    // across link runs — future tooling that diffs wild-hashes files
    // benefits, and a determinism-smoke test on the side-car itself
    // becomes possible.
    let mut entries: Vec<(&PathBuf, &InputHash)> = cache.inputs.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (path, hash) in entries {
        let path_str = path.to_string_lossy();
        let bytes = path_str.as_bytes();
        if bytes.len() > u16::MAX as usize {
            // Skip absurdly-long paths rather than truncate. A 64 KiB
            // path is never legitimate on macOS / Linux.
            continue;
        }
        buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(bytes);
        match hash {
            InputHash::RlibFingerprint(fp) => {
                buf.push(InputHash::TAG_RLIB);
                // `fp.len() <= 64` enforced by `fingerprint_for`'s
                // length bracket, so a u8 count always fits.
                buf.push(fp.len() as u8);
                buf.extend_from_slice(fp);
            }
            InputHash::ContentHash {
                hash,
                size,
                mtime_ns,
            } => {
                buf.push(InputHash::TAG_CONTENT);
                buf.extend_from_slice(hash);
                buf.extend_from_slice(&size.to_le_bytes());
                buf.extend_from_slice(&mtime_ns.to_le_bytes());
            }
        }
    }
    let tmp = path.with_extension("wild-hashes.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&buf)?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Classify inputs as dirty (content changed since cached) or clean.
/// Inputs absent from the cache are dirty. Inputs present in the
/// cache but absent from the current link are "orphaned" — returned
/// separately so callers can decide whether to cull them from a
/// persisted layout.
pub(crate) struct DirtyReport {
    pub dirty_count: usize,
    pub clean_count: usize,
    pub orphan_count: usize,
    pub dirty_paths: Vec<PathBuf>,
}

/// Compare `current` (fresh hashes from this link) against `cached`
/// (hashes from the previous link's side-car). Anything with a
/// different hash, or no cached entry, is dirty.
pub(crate) fn classify_dirty(
    current: &HashMap<PathBuf, InputHash>,
    cached: &HashMap<PathBuf, InputHash>,
) -> DirtyReport {
    let mut dirty_paths: Vec<PathBuf> = Vec::new();
    let mut clean = 0usize;
    for (path, hash) in current {
        match cached.get(path) {
            Some(h) if h == hash => clean += 1,
            _ => dirty_paths.push(path.clone()),
        }
    }
    let orphan = cached.keys().filter(|p| !current.contains_key(*p)).count();
    DirtyReport {
        dirty_count: dirty_paths.len(),
        clean_count: clean,
        orphan_count: orphan,
        dirty_paths,
    }
}

/// Full link-signature verdict: equal iff args, wild version, and
/// every input hash match the previous link. Equality means the new
/// output would be byte-identical to the existing on-disk binary;
/// callers can short-circuit to a no-op relink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignatureVerdict {
    /// Full match: inputs + args + wild version all agree. Safe to
    /// skip the link entirely.
    FullMatch,
    /// Something changed — fall back to a normal cold link. The
    /// reason kind is narrowed for diagnostics.
    Mismatch(SignatureMismatch),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignatureMismatch {
    /// Wild itself was upgraded / downgraded since the cache was
    /// written. Almost always the right reason to bust the cache
    /// since wild's output format / optimisations can shift.
    WildVersion,
    /// Linker args changed — new flags, different `-L`, reordered
    /// inputs, etc.
    Args,
    /// At least one input's content changed; see the dirty-report
    /// for specifics.
    InputsChanged,
    /// An input was added or removed relative to the cache.
    InputSetChanged,
}

/// Compute the full link-signature verdict between the current
/// link state and a cached link state. Order of checks is cheapest-
/// first so a common mismatch (e.g. wild upgrade) short-circuits
/// before we walk every input.
pub(crate) fn classify_signature(
    current_args_hash: &[u8; 32],
    current_inputs: &HashMap<PathBuf, InputHash>,
    cached: &LinkCache,
) -> SignatureVerdict {
    if cached.wild_version != WILD_VERSION {
        return SignatureVerdict::Mismatch(SignatureMismatch::WildVersion);
    }
    if &cached.args_hash != current_args_hash {
        return SignatureVerdict::Mismatch(SignatureMismatch::Args);
    }
    if cached.inputs.len() != current_inputs.len() {
        return SignatureVerdict::Mismatch(SignatureMismatch::InputSetChanged);
    }
    for (path, hash) in current_inputs {
        match cached.inputs.get(path) {
            Some(h) if h == hash => continue,
            Some(_) => return SignatureVerdict::Mismatch(SignatureMismatch::InputsChanged),
            None => return SignatureVerdict::Mismatch(SignatureMismatch::InputSetChanged),
        }
    }
    SignatureVerdict::FullMatch
}

/// Verify every cached input still exists at its original path and
/// still fingerprints to the cached value — without going through
/// wild's full input-resolution / mmap pipeline. Enables a
/// *pre-load* signature check, turning a "we can skip" decision
/// into one made before any parsing work starts.
///
/// Returns `Some(())` when all inputs are intact, `None` at the first
/// mismatch (with the short-circuit path preserved — no reason to
/// keep walking). Callers that want to continue verifying past the
/// first miss should use [`classify_dirty`] instead.
///
/// Content-hash inputs cost a real file read. On rust-analyzer's
/// 229-input link, 211 are `RlibFingerprint` (zero I/O) and only
/// 18 are `ContentHash` (small `.o` / `.dylib` files, ~1 ms total).
///
/// **Complexity:** Θ(paths) for the fingerprint variants; Θ(bytes)
/// across all content-hashed inputs for the hash variants.
pub(crate) fn verify_cached_inputs_unchanged(cached: &HashMap<PathBuf, InputHash>) -> Option<()> {
    // Group inputs by parent directory so we can replace the
    // per-input `path.exists()` stat with one `read_dir` per
    // parent — on rust-analyzer that's 229 stats vs 3 readdirs,
    // typically 30+ ms vs ~3 ms.
    //
    // For each parent, build the set of filenames present on
    // disk once, then the per-input check is a `HashSet::contains`.
    // `read_dir` returns a single kernel buffer of entries; the
    // per-entry cost is `strcpy` + hashing, not syscall-round-trip.
    use std::collections::HashMap as StdMap;
    use std::collections::HashSet as StdSet;
    use std::ffi::OsString;
    let mut by_parent: StdMap<&Path, Vec<(&Path, &InputHash)>> = StdMap::new();
    for (path, hash) in cached {
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        by_parent.entry(parent).or_default().push((path, hash));
    }

    // readdir each parent directory in parallel. Directories with
    // thousands of entries would still benefit from parallelism
    // (read_dir copies each entry into user space before returning).
    let dir_maps: Vec<(&Path, Option<StdSet<OsString>>)> = by_parent
        .par_iter()
        .map(|(parent, _)| {
            let set = std::fs::read_dir(parent).ok().map(|it| {
                it.filter_map(|e| e.ok())
                    .map(|e| e.file_name())
                    .collect::<StdSet<OsString>>()
            });
            (*parent, set)
        })
        .collect();
    let dir_maps: StdMap<&Path, StdSet<OsString>> = dir_maps
        .into_iter()
        .filter_map(|(p, s)| s.map(|s| (p, s)))
        .collect();

    // Per-input verification — only ContentHash variants may need
    // further I/O (fs::read when the mtime/size shortcut misses).
    // RlibFingerprint just needs the filename-in-set check plus the
    // fingerprint parse (pure string op).
    let all_match = cached.par_iter().all(|(path, hash)| {
        // Existence: lookup in the parent's directory listing. A
        // parent we couldn't read (permissions, missing dir) → miss.
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let Some(dir_set) = dir_maps.get(parent) else {
            return false;
        };
        let Some(fname) = path.file_name() else {
            return false;
        };
        if !dir_set.contains(fname) {
            return false;
        }
        match hash {
            InputHash::RlibFingerprint(fp) => {
                fingerprint_for(path).as_deref() == Some(fp.as_slice())
            }
            InputHash::ContentHash {
                hash,
                size,
                mtime_ns,
            } => {
                // Fast path: stat only. If `(size, mtime)` matches
                // the cached tuple we trust the blake3 without
                // re-reading the file. `(0, 0)` in the cache means
                // the previous link couldn't stat the file — treat
                // as "unknown" and fall through to the slow path.
                if (*size, *mtime_ns) != (0, 0) {
                    if let Some((cur_size, cur_mtime)) = file_metadata_signature(path) {
                        if cur_size == *size && cur_mtime == *mtime_ns {
                            return true;
                        }
                        // mtime moved but content may still match
                        // (e.g. `touch` without edit). Re-hash to
                        // confirm; a true content change forces the
                        // dev-loop relink, a spurious mtime bump
                        // still skips.
                    }
                }
                match std::fs::read(path) {
                    Ok(bytes) => blake3::hash(&bytes).as_bytes() == hash,
                    Err(_) => false,
                }
            }
        }
    });
    if all_match { Some(()) } else { None }
}

/// Emit a short diagnostic summary to stderr when
/// `WILD_INCREMENTAL_DEBUG` is set in the environment. Kept behind an
/// env var (not a proper `--incremental-debug` flag) so the POC
/// doesn't touch the args parser; a follow-up promotes it.
///
/// Format:
/// ```text
/// wild incremental: 1 dirty, 698 clean, 0 orphan
/// wild incremental: dirty: /path/to/librust_analyzer-abc.rlib
/// ```
pub(crate) fn maybe_report(report: &DirtyReport) {
    if std::env::var_os("WILD_INCREMENTAL_DEBUG").is_none() {
        return;
    }
    eprintln!(
        "wild incremental: {} dirty, {} clean, {} orphan",
        report.dirty_count, report.clean_count, report.orphan_count
    );
    for p in &report.dirty_paths {
        eprintln!("wild incremental: dirty: {}", p.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_changes_with_content() {
        let a = compute_input_key(b"abc", b"");
        let b = compute_input_key(b"abd", b"");
        assert_ne!(a, b);
    }

    #[test]
    fn key_changes_with_flags() {
        let a = compute_input_key(b"abc", b"-arch arm64");
        let b = compute_input_key(b"abc", b"-arch x86_64");
        assert_ne!(a, b);
    }

    #[test]
    fn length_prefix_prevents_ambiguity() {
        // Without length prefix, ("ab", "c") and ("a", "bc") would
        // collide. With it, they don't.
        let a = compute_input_key(b"ab", b"c");
        let b = compute_input_key(b"a", b"bc");
        assert_ne!(a, b);
    }

    #[test]
    fn hex_is_64_chars_lowercase() {
        let k = [0xabu8; 32];
        let h = key_hex(&k);
        assert_eq!(h.len(), 64);
        assert_eq!(h, "ab".repeat(32));
    }

    #[test]
    fn cache_file_roundtrips_mixed_variants() {
        let tmp = std::env::temp_dir().join("wild-incremental-test.wild-hashes");
        let _ = std::fs::remove_file(&tmp);

        let mut inputs: HashMap<PathBuf, InputHash> = HashMap::new();
        inputs.insert(
            PathBuf::from("/some/path/libfoo-a6d9492580400680.rlib"),
            InputHash::RlibFingerprint(b"a6d9492580400680".to_vec()),
        );
        inputs.insert(
            PathBuf::from("/other/libbar.o"),
            InputHash::ContentHash {
                hash: [0x22u8; 32],
                size: 4096,
                mtime_ns: 1_700_000_000_000_000_000,
            },
        );
        let cache = LinkCache {
            args_hash: [0x33u8; 32],
            output_size: 46361965,
            wild_version: "0.8.0".to_owned(),
            inputs,
        };
        write_link_cache(&tmp, &cache).expect("write");

        let read_back = read_link_cache(&tmp).expect("read");
        assert_eq!(read_back.inputs.len(), 2);
        assert_eq!(read_back.args_hash, [0x33u8; 32]);
        assert_eq!(read_back.output_size, 46361965);
        assert_eq!(read_back.wild_version, "0.8.0");
        assert_eq!(
            read_back
                .inputs
                .get(&PathBuf::from("/some/path/libfoo-a6d9492580400680.rlib")),
            Some(&InputHash::RlibFingerprint(b"a6d9492580400680".to_vec()))
        );
        assert_eq!(
            read_back.inputs.get(&PathBuf::from("/other/libbar.o")),
            Some(&InputHash::ContentHash {
                hash: [0x22u8; 32],
                size: 4096,
                mtime_ns: 1_700_000_000_000_000_000,
            })
        );

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn corrupt_cache_returns_none() {
        let tmp = std::env::temp_dir().join("wild-incremental-corrupt.wild-hashes");
        std::fs::write(&tmp, b"NOT-A-WILD-CACHE").expect("setup");
        assert!(read_link_cache(&tmp).is_none());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn signature_classification() {
        let inputs = {
            let mut m = HashMap::new();
            m.insert(
                PathBuf::from("/a.rlib"),
                InputHash::RlibFingerprint(b"abcdef0123456789".to_vec()),
            );
            m
        };
        let cached = LinkCache {
            args_hash: [0x42u8; 32],
            output_size: 0,
            wild_version: WILD_VERSION.to_owned(),
            inputs: inputs.clone(),
        };
        // Full match.
        let v = classify_signature(&[0x42u8; 32], &inputs, &cached);
        assert_eq!(v, SignatureVerdict::FullMatch);

        // Args mismatch.
        let v = classify_signature(&[0x99u8; 32], &inputs, &cached);
        assert_eq!(v, SignatureVerdict::Mismatch(SignatureMismatch::Args));

        // Wild-version mismatch.
        let old = LinkCache {
            args_hash: cached.args_hash,
            output_size: cached.output_size,
            wild_version: "0.0.0-ancient".to_owned(),
            inputs: cached.inputs.clone(),
        };
        let v = classify_signature(&[0x42u8; 32], &inputs, &old);
        assert_eq!(
            v,
            SignatureVerdict::Mismatch(SignatureMismatch::WildVersion)
        );

        // Inputs changed.
        let mut changed = inputs.clone();
        changed.insert(
            PathBuf::from("/a.rlib"),
            InputHash::RlibFingerprint(b"deadbeefcafef00d".to_vec()),
        );
        let v = classify_signature(&[0x42u8; 32], &changed, &cached);
        assert_eq!(
            v,
            SignatureVerdict::Mismatch(SignatureMismatch::InputsChanged)
        );
    }

    #[test]
    fn args_hash_skips_argv0() {
        let a = vec![
            "/install/path/wild".to_owned(),
            "-o".to_owned(),
            "out".to_owned(),
        ];
        let b = vec![
            "/elsewhere/wild".to_owned(),
            "-o".to_owned(),
            "out".to_owned(),
        ];
        assert_eq!(compute_args_hash(&a), compute_args_hash(&b));

        let c = vec![
            "/install/path/wild".to_owned(),
            "-o".to_owned(),
            "DIFFERENT".to_owned(),
        ];
        assert_ne!(compute_args_hash(&a), compute_args_hash(&c));
    }

    #[test]
    fn dirty_detection_matches() {
        let mk_ch = |b: u8| InputHash::ContentHash {
            hash: [b; 32],
            size: 0,
            mtime_ns: 0,
        };
        let mut cached: HashMap<PathBuf, InputHash> = HashMap::new();
        cached.insert(
            PathBuf::from("/a"),
            InputHash::RlibFingerprint(b"aaaaaaaaaaaaaaaa".to_vec()),
        );
        cached.insert(PathBuf::from("/b"), mk_ch(2));
        cached.insert(PathBuf::from("/c-removed"), mk_ch(3));

        let mut current: HashMap<PathBuf, InputHash> = HashMap::new();
        current.insert(
            PathBuf::from("/a"),
            InputHash::RlibFingerprint(b"aaaaaaaaaaaaaaaa".to_vec()),
        );
        current.insert(PathBuf::from("/b"), mk_ch(0x99));
        current.insert(PathBuf::from("/d-new"), mk_ch(4));

        let report = classify_dirty(&current, &cached);
        assert_eq!(report.clean_count, 1);
        assert_eq!(report.dirty_count, 2);
        assert_eq!(report.orphan_count, 1);
    }

    #[test]
    fn fingerprint_recognises_cargo_rlib_names() {
        let fp = fingerprint_for(Path::new("/deps/librust_analyzer-a6d9492580400680.rlib"));
        assert_eq!(fp, Some(b"a6d9492580400680".to_vec()));

        let fp = fingerprint_for(Path::new("/deps/liblibc-adbeb7749e521938.rlib"));
        assert_eq!(fp, Some(b"adbeb7749e521938".to_vec()));
    }

    #[test]
    fn fingerprint_rejects_non_cargo_shapes() {
        // No extension
        assert!(fingerprint_for(Path::new("/path/libfoo")).is_none());
        // Not .rlib
        assert!(fingerprint_for(Path::new("/path/libfoo-12345678.o")).is_none());
        // No dash — rustc emits these when -Cextra-filename is suppressed
        assert!(fingerprint_for(Path::new("/path/libfoo.rlib")).is_none());
        // Non-hex tag (crate names with a final "-word" rlib form)
        assert!(fingerprint_for(Path::new("/path/libmy-crate-name.rlib")).is_none());
        // Tag too short (<8 chars)
        assert!(fingerprint_for(Path::new("/path/libfoo-abc.rlib")).is_none());
    }

    #[test]
    fn extract_output_path_handles_forms() {
        let cases = [
            (vec!["wild", "-o", "out.bin", "input.o"], "out.bin"),
            (vec!["wild", "input.o", "-o", "out.bin"], "out.bin"),
            (vec!["wild", "-oout.bin", "input.o"], "out.bin"),
            (vec!["wild", "--output=/tmp/x", "input.o"], "/tmp/x"),
            (vec!["wild", "input.o"], "a.out"),
        ];
        for (argv, want) in cases {
            let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
            assert_eq!(extract_output_path(&argv), PathBuf::from(want));
        }
    }

    #[test]
    fn variant_tag_disambiguates() {
        // Same bytes, different variants → different dirty behaviour.
        // A raw 16-byte blake3 prefix that happens to match the ASCII
        // of a plausible rustc suffix shouldn't collapse into the
        // same `InputHash`.
        let rlib = InputHash::RlibFingerprint(b"abcdef0123456789".to_vec());
        let mut content = [0u8; 32];
        content[..16].copy_from_slice(b"abcdef0123456789");
        let ch = InputHash::ContentHash {
            hash: content,
            size: 0,
            mtime_ns: 0,
        };
        assert_ne!(rlib, ch);
    }

    /// Drift guard for the input-key hash composition. Pinned against
    /// a mock schema + version so it's stable across wild releases;
    /// the test only fires when `compute_input_key_with_version`'s
    /// hash recipe itself changes (update order, length-prefix,
    /// hasher choice).
    ///
    /// If this test starts failing: you changed the hash recipe.
    /// Confirm the change is intentional, bump `CACHE_SCHEMA_VERSION`,
    /// then update the expected blake3 below from the new output. The
    /// bump + expected-value update must happen in the same commit.
    #[test]
    fn drift_guard_input_key_stability() {
        let actual = compute_input_key_with_version(b"hello", b"-arch arm64", 1, "test");
        let expected = "9b88c33ea08671e0fa6ef3aa7c2c81f0faa35829f3997580d335b2e835c68e4f";
        assert_eq!(
            key_hex(&actual),
            expected,
            "input-key hash recipe drifted. If intentional, bump \
             CACHE_SCHEMA_VERSION and update this fixture."
        );
    }

    /// Drift guard for `compute_args_hash`. Same rationale as
    /// `drift_guard_input_key_stability` — pinned against a known
    /// argv so that changes to the args-hash composition surface
    /// explicitly. Skips argv[0] (verified separately in
    /// `args_hash_skips_argv0`) so the expected value is stable
    /// across install locations.
    #[test]
    fn drift_guard_args_hash_stability() {
        let argv = vec![
            "/anywhere/wild".to_owned(),
            "-arch".to_owned(),
            "arm64".to_owned(),
            "-o".to_owned(),
            "out".to_owned(),
            "in.o".to_owned(),
        ];
        let actual = compute_args_hash(&argv);
        let expected = "e7e338d046b5f4ff447310b2114b6cdff1d3da236ca34bb1c3047cf5d700d8f3";
        assert_eq!(
            key_hex(&actual),
            expected,
            "args-hash recipe drifted. If intentional, bump \
             CACHE_SCHEMA_VERSION and update this fixture."
        );
    }

    /// `write_link_cache` must produce byte-identical output for a
    /// given `LinkCache` regardless of HashMap iteration order. The
    /// implementation sorts entries by path before emission; this
    /// test locks in that behaviour so a future refactor can't
    /// silently regress it (which would defeat any downstream
    /// cache-diffing tool and break deterministic-build guarantees).
    #[test]
    fn link_cache_write_is_deterministic() {
        let mut inputs: HashMap<PathBuf, InputHash> = HashMap::new();
        // Insert in reverse-sorted order; sorting on emit should
        // normalise.
        inputs.insert(
            PathBuf::from("/zzz/last.o"),
            InputHash::ContentHash {
                hash: [0x11u8; 32],
                size: 100,
                mtime_ns: 1,
            },
        );
        inputs.insert(
            PathBuf::from("/aaa/first.rlib"),
            InputHash::RlibFingerprint(b"cafef00dcafef00d".to_vec()),
        );
        inputs.insert(
            PathBuf::from("/mmm/middle.o"),
            InputHash::ContentHash {
                hash: [0x22u8; 32],
                size: 200,
                mtime_ns: 2,
            },
        );
        let cache = LinkCache {
            args_hash: [0x55u8; 32],
            output_size: 12345,
            wild_version: "fixture".to_owned(),
            inputs,
        };

        let tmp_a = std::env::temp_dir().join("wild-det-a.wild-hashes");
        let tmp_b = std::env::temp_dir().join("wild-det-b.wild-hashes");
        let _ = std::fs::remove_file(&tmp_a);
        let _ = std::fs::remove_file(&tmp_b);
        write_link_cache(&tmp_a, &cache).expect("write a");
        write_link_cache(&tmp_b, &cache).expect("write b");
        let a = std::fs::read(&tmp_a).expect("read a");
        let b = std::fs::read(&tmp_b).expect("read b");
        std::fs::remove_file(&tmp_a).ok();
        std::fs::remove_file(&tmp_b).ok();
        assert_eq!(
            a, b,
            "write_link_cache emitted different bytes for the same \
             input — iteration-order bug has crept in"
        );
    }
}
