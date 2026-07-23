use crate::error::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Metadata recorded for an input file during linking.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CachedInputFile {
    pub path: PathBuf,
    pub modification_time: Option<SystemTime>,
    pub size_bytes: u64,
    pub hash: u64,
}

/// Information about a symbol exported by a cached input file.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CachedSymbolInfo {
    pub name: String,
    pub section_index: Option<u32>,
    pub value: u64,
    pub is_weak: bool,
    pub is_global: bool,
}

/// Metrics summary for an incremental linking pass.
#[derive(Debug, Default, Clone)]
pub struct IncrementalSummary {
    pub total_inputs: usize,
    pub unchanged_inputs: usize,
    pub modified_inputs: usize,
    pub reused_symbols: usize,
}

/// The state of an incremental build saved to disk.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct IncrementalState {
    pub cached_inputs: HashMap<PathBuf, CachedInputFile>,
    pub cached_symbols: HashMap<PathBuf, Vec<CachedSymbolInfo>>,
    pub output_path: PathBuf,
    pub last_build_time: Option<SystemTime>,
}

impl IncrementalState {
    /// Determines the cache directory path given the output binary path and optional explicit dir.
    pub fn get_cache_dir(output_path: &Path, custom_dir: Option<&Path>) -> PathBuf {
        if let Some(dir) = custom_dir {
            dir.to_path_buf()
        } else {
            let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
            parent.join(".wild_cache")
        }
    }

    /// The path to the binary state file inside the cache directory.
    pub fn state_file_path(cache_dir: &Path) -> PathBuf {
        cache_dir.join("incremental_state.bin")
    }

    /// Attempts to load the existing incremental state from disk.
    pub fn load(cache_dir: &Path) -> Option<Self> {
        let state_path = Self::state_file_path(cache_dir);
        let bytes = fs::read(state_path).ok()?;
        postcard::from_bytes(&bytes).ok()
    }

    /// Saves current incremental state to disk.
    pub fn save(&self, cache_dir: &Path) -> Result<()> {
        fs::create_dir_all(cache_dir).with_context(|| {
            format!(
                "Failed to create incremental cache directory `{}`",
                cache_dir.display()
            )
        })?;
        let state_path = Self::state_file_path(cache_dir);
        let bytes = postcard::to_allocvec(self).with_context(|| "Failed to serialize incremental state".to_string())?;
        fs::write(&state_path, bytes).with_context(|| {
            format!(
                "Failed to write incremental state file `{}`",
                state_path.display()
            )
        })?;
        Ok(())
    }

    /// Records or updates metadata for a loaded input file.
    pub fn record_input(
        &mut self,
        path: PathBuf,
        size_bytes: u64,
        mtime: Option<SystemTime>,
        hash: u64,
    ) {
        self.cached_inputs.insert(
            path.clone(),
            CachedInputFile {
                path,
                modification_time: mtime,
                size_bytes,
                hash,
            },
        );
    }

    /// Returns `true` if the input file matches what was previously cached.
    pub fn is_input_unchanged(
        &self,
        path: &Path,
        size_bytes: u64,
        mtime: Option<SystemTime>,
        hash: u64,
    ) -> bool {
        if let Some(cached) = self.cached_inputs.get(path) {
            cached.size_bytes == size_bytes
                && cached.hash == hash
                && (mtime.is_none()
                    || cached.modification_time.is_none()
                    || cached.modification_time == mtime)
        } else {
            false
        }
    }

    /// Fast-path check: returns `true` if file size and modification time match cached entries.
    pub fn is_mtime_unchanged(
        &self,
        path: &Path,
        size_bytes: u64,
        mtime: Option<SystemTime>,
    ) -> bool {
        if let (Some(cached), Some(mtime)) = (self.cached_inputs.get(path), mtime) {
            cached.size_bytes == size_bytes
                && cached.modification_time.is_some()
                && cached.modification_time == Some(mtime)
        } else {
            false
        }
    }

    /// Record symbols associated with an input file.
    pub fn record_symbols(&mut self, path: PathBuf, symbols: Vec<CachedSymbolInfo>) {
        self.cached_symbols.insert(path, symbols);
    }

    /// Retrieve symbols associated with an input file if cached.
    pub fn get_cached_symbols(&self, path: &Path) -> Option<&[CachedSymbolInfo]> {
        self.cached_symbols.get(path).map(|v| v.as_slice())
    }

    /// Computes summary stats for loaded input files.
    pub fn evaluate_summary<'a, I>(&self, loaded_files: I) -> IncrementalSummary
    where
        I: IntoIterator<Item = (&'a Path, u64, Option<SystemTime>, u64)>,
    {
        let mut summary = IncrementalSummary::default();
        for (path, len, mtime, hash) in loaded_files {
            summary.total_inputs += 1;
            if self.is_input_unchanged(path, len, mtime, hash) {
                summary.unchanged_inputs += 1;
                if let Some(symbols) = self.get_cached_symbols(path) {
                    summary.reused_symbols += symbols.len();
                }
            } else {
                summary.modified_inputs += 1;
            }
        }
        summary
    }
}

/// Compute a fast 64-bit blake3 hash of byte slice.
pub fn compute_input_hash(data: &[u8]) -> u64 {
    let hash = blake3::hash(data);
    let bytes = hash.as_bytes();
    u64::from_le_bytes(bytes[0..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incremental_state_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("wild_inc_test_{}", std::process::id()));
        let cache_dir = temp_dir.join(".wild_cache");

        let mut state = IncrementalState::default();
        let file1 = temp_dir.join("main.o");
        let file2 = temp_dir.join("foo.o");

        let _ = fs::create_dir_all(&temp_dir);
        fs::write(&file1, b"main_bytes").unwrap();
        fs::write(&file2, b"foo_bytes").unwrap();

        let h1 = compute_input_hash(b"main_bytes");
        let h2 = compute_input_hash(b"foo_bytes");

        state.record_input(file1.clone(), 10, None, h1);
        state.record_input(file2.clone(), 9, None, h2);

        state.save(&cache_dir).unwrap();

        let loaded = IncrementalState::load(&cache_dir).expect("Failed to load saved state");
        assert!(loaded.is_input_unchanged(&file1, 10, None, h1));
        assert!(loaded.is_input_unchanged(&file2, 9, None, h2));
        assert!(!loaded.is_input_unchanged(&file1, 10, None, 99999));
        assert!(!loaded.is_input_unchanged(&temp_dir.join("bar.o"), 5, None, h1));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
