//! P6: Persistent cache for LTO-optimised per-module objects.
//!
//! Cache keys fold every input that changes the output of an LTO
//! step:
//! - the bitcode content (blake3 hash of the raw bytes),
//! - the opt level (`-O<N>`),
//! - the target-features string the caller chose,
//! - the LTO mode (none / thin / fat / unified),
//! - the LLVM version reported by `llc --version`,
//! - the wild version (from `env!("CARGO_PKG_VERSION")`).
//!
//! Any of those changing invalidates the entry. Two links with the
//! same tuple get the same bytes back.
//!
//! # Directory resolution
//!
//! In priority order:
//! 1. `$WILD_LTO_CACHE_DIR` — explicit override.
//! 2. `$CARGO_TARGET_DIR/wild-lto-cache/` — when invoked under cargo.
//! 3. `$XDG_CACHE_HOME/wild/lto/` — Unix cache convention.
//! 4. `$HOME/.cache/wild/lto/` — fallback.
//! 5. `std::env::temp_dir()/wild-lto-cache/` — last resort; means the cache survives only while the
//!    process's temp dir does.
//!
//! # Platform agnosticism
//!
//! The cache is shared across wasm / ELF / Mach-O drivers. Same hash
//! tuple → same file. A bitcode blob produced by the Rust compiler
//! for wasm gives different content from the ELF version, so the
//! blake3 hash naturally separates them — no need for a "platform"
//! field in the key.
//!
//! # Concurrency
//!
//! Writes are atomic (write to `.tmp`, rename to final). Two linkers
//! that happen to compute the same entry at once won't corrupt each
//! other — one rename wins. Reads don't lock; a partial read of a
//! tmp-being-renamed is impossible on POSIX because rename is atomic
//! on the same filesystem.

use crate::error::Error;
use crate::error::Result;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

/// All the inputs to an LTO step that change its output.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    /// Hex-encoded blake3 of the raw bitcode bytes.
    content_hash: String,
    /// The `-O` flag that will be fed to opt/llc, e.g. `"-O2"`.
    opt_level: String,
    /// Target features passed to llc (`"+simd128,+bulk-memory"` or
    /// empty). Separated out from `opt_level` to keep keys stable
    /// across unrelated opt tweaks that don't touch features.
    target_features: String,
    /// LTO mode, freeform string (`"off"`, `"thin"`, `"fat"`,
    /// `"unified"`). Freeform rather than enum-typed so this module
    /// doesn't grow a `match` every time `LtoMode` gets a variant.
    lto_mode: String,
    /// LLVM version, e.g. `"21.1.4"`. Discovered from `llc --version`
    /// at link time via [`crate::llvm_tools::version_of`].
    llvm_version: String,
    /// Wild's own version string. Any bug fix that changes emission
    /// bumps the crate version and invalidates cached bytes — a cheap
    /// correctness firewall.
    wild_version: String,
}

impl CacheKey {
    pub(crate) fn new(
        bitcode: &[u8],
        opt_level: &str,
        target_features: &str,
        lto_mode: &str,
        llvm_version: &str,
    ) -> Self {
        Self {
            content_hash: blake3::hash(bitcode).to_hex().to_string(),
            opt_level: opt_level.to_owned(),
            target_features: target_features.to_owned(),
            lto_mode: lto_mode.to_owned(),
            llvm_version: llvm_version.to_owned(),
            wild_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// The filename this key maps to inside the cache dir. Stable
    /// under iteration order, short enough to fit in one directory
    /// entry, unique enough that collisions are astronomical.
    fn filename(&self) -> String {
        // All the key fields get folded into one blake3 — the output
        // filename is `<64-hex>.obj`. We keep the content hash
        // visible in the prefix for at-a-glance debugging of cache
        // contents.
        let mut h = blake3::Hasher::new();
        h.update(self.content_hash.as_bytes());
        h.update(b"\0");
        h.update(self.opt_level.as_bytes());
        h.update(b"\0");
        h.update(self.target_features.as_bytes());
        h.update(b"\0");
        h.update(self.lto_mode.as_bytes());
        h.update(b"\0");
        h.update(self.llvm_version.as_bytes());
        h.update(b"\0");
        h.update(self.wild_version.as_bytes());
        let digest = h.finalize();
        format!(
            "{}-{}.obj",
            &self.content_hash[..16], // first 8 bytes for human scan
            digest.to_hex(),
        )
    }
}

/// The cache directory itself. Cheap to construct (doesn't touch
/// disk until first use). Passes through `put`/`get` in a way that's
/// safe to call from any thread.
#[derive(Debug, Clone)]
pub(crate) struct CacheDir {
    root: PathBuf,
}

impl CacheDir {
    /// Resolve the cache directory from env vars + conventions. Does
    /// not create it on disk — that happens lazily on first `put`.
    pub(crate) fn resolve() -> Self {
        let root = Self::resolve_path();
        Self { root }
    }

    fn resolve_path() -> PathBuf {
        if let Some(p) = std::env::var_os("WILD_LTO_CACHE_DIR") {
            return PathBuf::from(p);
        }
        if let Some(p) = std::env::var_os("CARGO_TARGET_DIR") {
            return PathBuf::from(p).join("wild-lto-cache");
        }
        if let Some(p) = std::env::var_os("XDG_CACHE_HOME") {
            return PathBuf::from(p).join("wild").join("lto");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".cache").join("wild").join("lto");
        }
        std::env::temp_dir().join("wild-lto-cache")
    }

    /// Return the bytes cached for this key, or `None` if the key
    /// isn't present / the file is unreadable. A read error is
    /// treated as a cache miss on purpose — a corrupted cache entry
    /// must not fail the link.
    pub(crate) fn get(&self, key: &CacheKey) -> Option<Vec<u8>> {
        let path = self.root.join(key.filename());
        std::fs::read(&path).ok()
    }

    /// Atomically store bytes for this key. Write-to-tmp + rename
    /// keeps concurrent linkers safe. Errors are warnings, not
    /// fatals — a working link without a cache entry beats a broken
    /// link with a cache write failure.
    pub(crate) fn put(&self, key: &CacheKey, bytes: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.root).map_err(|e| {
            Error::with_message(format!("create LTO cache dir {}: {e}", self.root.display()))
        })?;
        let final_path = self.root.join(key.filename());
        // Unique per-writer tmp name to avoid races.
        let tmp_path = self
            .root
            .join(format!("{}.{}.tmp", key.filename(), std::process::id()));
        std::fs::write(&tmp_path, bytes).map_err(|e| {
            Error::with_message(format!("write LTO cache tmp {}: {e}", tmp_path.display()))
        })?;
        std::fs::rename(&tmp_path, &final_path).map_err(|e| {
            // Clean up tmp if rename failed — best-effort; ignore
            // errors because the original error is more useful.
            let _ = std::fs::remove_file(&tmp_path);
            Error::with_message(format!(
                "rename LTO cache {} → {}: {e}",
                tmp_path.display(),
                final_path.display()
            ))
        })?;
        Ok(())
    }

    /// Directory root — surfaced for tests and for debug / inspection
    /// tooling. Not a stable API surface.
    #[cfg(test)]
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

/// Run `work` to produce object bytes for `key`, caching the result.
/// If the cache has the entry, returns the cached bytes without
/// calling `work`. Otherwise calls `work`, stores its result, and
/// returns it.
///
/// A cache-write failure is logged at `warn` level but doesn't turn
/// a successful compile into a failed link.
pub(crate) fn get_or_compute(
    dir: &CacheDir,
    key: &CacheKey,
    work: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    if let Some(hit) = dir.get(key) {
        tracing::debug!("LTO cache hit: {}", key.filename());
        return Ok(hit);
    }
    tracing::debug!("LTO cache miss: {}", key.filename());
    let bytes = work()?;
    if let Err(e) = dir.put(key, &bytes) {
        tracing::warn!("LTO cache write failed (non-fatal): {e:?}");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_cache() -> (tempfile::TempDir, CacheDir) {
        let td = tempfile::tempdir().unwrap();
        let dir = CacheDir {
            root: td.path().to_path_buf(),
        };
        (td, dir)
    }

    #[test]
    fn key_is_deterministic_over_same_inputs() {
        let a = CacheKey::new(b"bitcode", "-O2", "+simd128", "fat", "21.0.0");
        let b = CacheKey::new(b"bitcode", "-O2", "+simd128", "fat", "21.0.0");
        assert_eq!(a, b);
        assert_eq!(a.filename(), b.filename());
    }

    #[test]
    fn key_differentiates_on_every_field() {
        let base = CacheKey::new(b"bitcode", "-O2", "+simd128", "fat", "21.0.0");
        let diff_bc = CacheKey::new(b"bitcode!", "-O2", "+simd128", "fat", "21.0.0");
        let diff_opt = CacheKey::new(b"bitcode", "-O3", "+simd128", "fat", "21.0.0");
        let diff_feat = CacheKey::new(b"bitcode", "-O2", "", "fat", "21.0.0");
        let diff_mode = CacheKey::new(b"bitcode", "-O2", "+simd128", "thin", "21.0.0");
        let diff_llvm = CacheKey::new(b"bitcode", "-O2", "+simd128", "fat", "22.0.0");
        for other in &[diff_bc, diff_opt, diff_feat, diff_mode, diff_llvm] {
            assert_ne!(&base, other, "keys should differ: {other:?}");
            assert_ne!(base.filename(), other.filename());
        }
    }

    #[test]
    fn filename_encodes_content_prefix_for_debuggability() {
        let key = CacheKey::new(b"bitcode", "-O2", "+simd128", "fat", "21.0.0");
        let prefix = &key.content_hash[..16];
        assert!(
            key.filename().starts_with(prefix),
            "filename should start with content-hash prefix: {}",
            key.filename()
        );
        assert!(key.filename().ends_with(".obj"));
    }

    #[test]
    fn get_miss_returns_none_and_does_not_create_the_dir() {
        let td = tempfile::tempdir().unwrap();
        let dir = CacheDir {
            root: td.path().join("non-existent-yet"),
        };
        let key = CacheKey::new(b"bc", "-O2", "", "fat", "21.0.0");
        assert!(dir.get(&key).is_none());
        assert!(!dir.root().exists(), "get-miss must not create cache dir");
    }

    #[test]
    fn put_then_get_roundtrips_bytes() {
        let (_td, dir) = mk_cache();
        let key = CacheKey::new(b"my-bitcode", "-O2", "", "fat", "21.0.0");
        let payload = b"\0asm\x01\x00\x00\x00 pretend wasm object".to_vec();
        dir.put(&key, &payload).unwrap();
        let round = dir.get(&key).expect("cache hit");
        assert_eq!(round, payload);
    }

    #[test]
    fn put_overwrites_previous_entry_atomically() {
        let (_td, dir) = mk_cache();
        let key = CacheKey::new(b"bc", "-O2", "", "fat", "21.0.0");
        dir.put(&key, b"first").unwrap();
        dir.put(&key, b"second").unwrap();
        assert_eq!(dir.get(&key).unwrap(), b"second");
    }

    #[test]
    fn get_or_compute_skips_work_on_hit() {
        let (_td, dir) = mk_cache();
        let key = CacheKey::new(b"bc", "-O2", "", "fat", "21.0.0");
        // Prime the cache.
        dir.put(&key, b"cached-bytes").unwrap();

        let counter = std::sync::atomic::AtomicU32::new(0);
        let result = get_or_compute(&dir, &key, || {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(b"freshly-computed".to_vec())
        })
        .unwrap();

        assert_eq!(result, b"cached-bytes");
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "work closure must not run on cache hit"
        );
    }

    #[test]
    fn get_or_compute_runs_work_on_miss_and_stores_result() {
        let (_td, dir) = mk_cache();
        let key = CacheKey::new(b"bc", "-O2", "", "fat", "21.0.0");

        let result = get_or_compute(&dir, &key, || Ok(b"first-pass".to_vec())).unwrap();
        assert_eq!(result, b"first-pass");
        // Second call should hit the cache.
        let counter = std::sync::atomic::AtomicU32::new(0);
        let result2 = get_or_compute(&dir, &key, || {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(b"should-be-ignored".to_vec())
        })
        .unwrap();
        assert_eq!(result2, b"first-pass");
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn env_override_wins_over_cargo_target_dir() {
        let td_env = tempfile::tempdir().unwrap();
        let td_cargo = tempfile::tempdir().unwrap();
        // SAFETY: single-threaded test; env mutation scoped to this
        // test.
        unsafe {
            std::env::set_var("WILD_LTO_CACHE_DIR", td_env.path());
            std::env::set_var("CARGO_TARGET_DIR", td_cargo.path());
        }
        let resolved = CacheDir::resolve().root.clone();
        unsafe {
            std::env::remove_var("WILD_LTO_CACHE_DIR");
            std::env::remove_var("CARGO_TARGET_DIR");
        }
        assert_eq!(resolved, td_env.path());
    }

    #[test]
    fn cargo_target_dir_used_when_no_explicit_override() {
        let td = tempfile::tempdir().unwrap();
        unsafe {
            std::env::remove_var("WILD_LTO_CACHE_DIR");
            std::env::set_var("CARGO_TARGET_DIR", td.path());
        }
        let resolved = CacheDir::resolve().root.clone();
        unsafe {
            std::env::remove_var("CARGO_TARGET_DIR");
        }
        assert_eq!(resolved, td.path().join("wild-lto-cache"));
    }
}
