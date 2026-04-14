//! Function- and local-index remap tables, composable across passes.
//!
//! Several passes renumber the function-index space (`dedup`, `dce`,
//! `fn_merge`, `reorder`, `layout_for_compression`, `inline_trivial`
//! when it fully inlines away a callee, `dedup_imports` for import
//! indices). Each currently builds its own `Vec<Option<u32>>` and
//! throws it away after rewriting the sections it cares about.
//!
//! To honour debug info (Phase 1 of `wilt-debug-info-plan.md`), we
//! need these remaps exposed and composable: after the full pipeline
//! we want one map from "input function index" → "output function
//! index or eliminated".
//!
//! Invariants:
//! - `entries[i] == Some(j)` means input function `i` maps to output
//!   function `j`.
//! - `entries[i] == None` means input function `i` was eliminated
//!   (inlined fully, or deduped into another function that's
//!   represented elsewhere in the map).
//! - Multiple inputs may map to the same output (merges).
//! - The identity remap has `entries[i] == Some(i)` for all `i` up
//!   to the module's function count.

use std::collections::HashMap;

/// Remap from input absolute function index → output absolute function
/// index, or `None` for eliminated functions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuncRemap {
    entries: Vec<Option<u32>>,
}

impl FuncRemap {
    /// Build an identity remap for `n` functions.
    pub fn identity(n: u32) -> Self {
        Self { entries: (0..n).map(Some).collect() }
    }

    /// Direct construction from a per-input-index slice.
    pub fn from_entries(entries: Vec<Option<u32>>) -> Self { Self { entries } }

    /// Look up an input index. `None` = eliminated; out-of-range also
    /// returns `None`.
    pub fn lookup(&self, input: u32) -> Option<u32> {
        self.entries.get(input as usize).copied().flatten()
    }

    /// Total input function slot count this map covers.
    pub fn len(&self) -> u32 { self.entries.len() as u32 }

    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn entries(&self) -> &[Option<u32>] { &self.entries }

    /// Compose two remaps: `self` = input → mid, `next` = mid → out;
    /// result = input → out. Eliminated inputs (or mid-indices that
    /// `next` eliminates) stay eliminated.
    ///
    /// Complexity: O(|self|).
    pub fn compose(&self, next: &FuncRemap) -> FuncRemap {
        let entries = self.entries.iter()
            .map(|slot| match slot {
                Some(mid) => next.entries.get(*mid as usize).copied().flatten(),
                None => None,
            })
            .collect();
        FuncRemap { entries }
    }

    /// If two inputs mapped to the same output, return the canonical
    /// set keyed by output index. Useful for the name-section
    /// rewriter's "pick the first name for a merged function" rule.
    pub fn by_output(&self) -> HashMap<u32, Vec<u32>> {
        let mut m: HashMap<u32, Vec<u32>> = HashMap::new();
        for (i, slot) in self.entries.iter().enumerate() {
            if let Some(out) = slot {
                m.entry(*out).or_default().push(i as u32);
            }
        }
        m
    }
}

/// Remap of local indices within a single function. Per-function
/// because each function has its own local-index space.
///
/// Not fully threaded in Phase 1 — only function names get remapped
/// in the name section; local names pass through untouched. This
/// type is present so Phase 1's plumbing and Phase 2's work share
/// the same shape.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalRemap {
    /// Keyed by output-absolute function index.
    per_function: HashMap<u32, Vec<u32>>,
}

impl LocalRemap {
    pub fn new() -> Self { Self::default() }
    pub fn insert(&mut self, func: u32, map: Vec<u32>) {
        self.per_function.insert(func, map);
    }
    pub fn lookup(&self, func: u32, input_local: u32) -> Option<u32> {
        self.per_function.get(&func)
            .and_then(|v| v.get(input_local as usize).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_compose_identity() {
        let a = FuncRemap::identity(5);
        let b = FuncRemap::identity(5);
        assert_eq!(a.compose(&b), FuncRemap::identity(5));
    }

    #[test]
    fn compose_chains_deletions() {
        // 0→1, 1→0, 2 eliminated.
        let a = FuncRemap::from_entries(vec![Some(1), Some(0), None]);
        // 0→0, 1→1
        let b = FuncRemap::from_entries(vec![Some(0), Some(1)]);
        let c = a.compose(&b);
        assert_eq!(c.lookup(0), Some(1));
        assert_eq!(c.lookup(1), Some(0));
        assert_eq!(c.lookup(2), None);
    }

    #[test]
    fn compose_eliminates_when_mid_eliminated() {
        // 0 → 1
        let a = FuncRemap::from_entries(vec![Some(1)]);
        // mid-idx 1 eliminated
        let b = FuncRemap::from_entries(vec![Some(0), None]);
        let c = a.compose(&b);
        assert_eq!(c.lookup(0), None);
    }

    #[test]
    fn merge_shows_up_in_by_output() {
        // 0 and 2 both map to 0; 1 maps to 1.
        let r = FuncRemap::from_entries(vec![Some(0), Some(1), Some(0)]);
        let m = r.by_output();
        let mut zero = m.get(&0).cloned().unwrap();
        zero.sort();
        assert_eq!(zero, vec![0, 2]);
        assert_eq!(m.get(&1), Some(&vec![1]));
    }

    #[test]
    fn compose_associativity_small() {
        // (a∘b)∘c == a∘(b∘c) for specific remaps.
        let a = FuncRemap::from_entries(vec![Some(1), Some(2), None, Some(0)]);
        let b = FuncRemap::from_entries(vec![Some(2), Some(0), Some(1)]);
        let c = FuncRemap::from_entries(vec![Some(1), None, Some(0)]);
        let left  = a.compose(&b).compose(&c);
        let right = a.compose(&b.compose(&c));
        assert_eq!(left, right);
    }

    #[test]
    fn lookup_out_of_range_is_none() {
        let r = FuncRemap::identity(3);
        assert_eq!(r.lookup(7), None);
    }

    #[test]
    fn local_remap_roundtrip() {
        let mut l = LocalRemap::new();
        l.insert(0, vec![0, 2, 1]);
        assert_eq!(l.lookup(0, 0), Some(0));
        assert_eq!(l.lookup(0, 1), Some(2));
        assert_eq!(l.lookup(0, 2), Some(1));
        assert_eq!(l.lookup(0, 5), None);
        assert_eq!(l.lookup(7, 0), None);
    }
}
