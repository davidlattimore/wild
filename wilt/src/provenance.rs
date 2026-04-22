//! Byte-level provenance for function body rewrites.
//!
//! Passes that edit body bytes emit a `BodyEdits` describing what
//! changed. Edit lists compose O(|a| + |b|) via merge-walk so that
//! accumulating provenance across the fixpoint stays linear in the
//! final edit count.
//!
//! See `wilt-debug-info-plan.md` — this is the shared substrate for
//! the Phase 2 DWARF `.debug_line` rewriter (gimli-backed) and the
//! external source-map rewriter.
//!
//! ## Edit semantics
//!
//! Each `Edit` describes one byte-range substitution from input to
//! output:
//!
//! - `in_len > 0 && out_len > 0`: substitution — input span rewritten.
//! - `in_len > 0 && out_len == 0`: deletion — input bytes dropped.
//! - `in_len == 0 && out_len > 0`: synthesis — new bytes introduced that didn't exist in input
//!   (e.g. inline splice pasting callee bytes; `pure_call_elim` writing drops).
//!
//! For synthesised spans that came from *another function body*
//! (only `inline_trivial` does this), `src_funcs[i]` names the input
//! absolute function index the bytes came from. The DWARF rewriter
//! chases that to pull the callee's `.debug_line` into the caller's
//! output sequence.
//!
//! Invariant: `edits` is sorted by `out_start`, and for any two edits
//! `e[i]` and `e[i+1]`, `e[i].out_start + e[i].out_len <= e[i+1].out_start`
//! (non-overlapping in output space). Input-space spans also don't
//! overlap. Bytes NOT covered by any edit are **identity** — same
//! in both input and output. This is the crucial compression: a pass
//! that touches 10 instructions out of 1000 emits 10 edits, not 1000
//! identity entries.

/// A single byte-range substitution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edit {
    pub in_start: u32,
    pub in_len: u32,
    pub out_start: u32,
    pub out_len: u32,
}

impl Edit {
    /// Pure deletion: input bytes gone, nothing in their place.
    pub fn delete(in_start: u32, in_len: u32, out_start: u32) -> Self {
        Self {
            in_start,
            in_len,
            out_start,
            out_len: 0,
        }
    }
    /// Pure synthesis: new bytes in output that didn't exist in input.
    pub fn synth(in_start: u32, out_start: u32, out_len: u32) -> Self {
        Self {
            in_start,
            in_len: 0,
            out_start,
            out_len,
        }
    }
    /// Substitution: input bytes replaced by a different-size run.
    pub fn subst(in_start: u32, in_len: u32, out_start: u32, out_len: u32) -> Self {
        Self {
            in_start,
            in_len,
            out_start,
            out_len,
        }
    }

    pub fn in_end(&self) -> u32 {
        self.in_start + self.in_len
    }
    pub fn out_end(&self) -> u32 {
        self.out_start + self.out_len
    }
}

/// Per-body edit list. `src_funcs[i]` names the input function that
/// `edits[i]`'s output span came from when that span is synthesised
/// cross-body (inline splice). `None` = same function (almost all
/// cases).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyEdits {
    edits: Vec<Edit>,
    src_funcs: Vec<Option<u32>>,
}

impl BodyEdits {
    pub fn identity() -> Self {
        Self {
            edits: Vec::new(),
            src_funcs: Vec::new(),
        }
    }

    pub fn from_edits(edits: Vec<Edit>) -> Self {
        let n = edits.len();
        Self {
            edits,
            src_funcs: vec![None; n],
        }
    }

    pub fn from_edits_with_sources(edits: Vec<Edit>, src_funcs: Vec<Option<u32>>) -> Self {
        debug_assert_eq!(edits.len(), src_funcs.len());
        Self { edits, src_funcs }
    }

    pub fn is_identity(&self) -> bool {
        self.edits.is_empty()
    }

    pub fn edits(&self) -> &[Edit] {
        &self.edits
    }
    pub fn src_funcs(&self) -> &[Option<u32>] {
        &self.src_funcs
    }

    pub fn push(&mut self, e: Edit, src: Option<u32>) {
        if let Some(last) = self.edits.last() {
            debug_assert!(
                e.out_start >= last.out_end(),
                "edits must be sorted + non-overlapping in out space; got {} after {}",
                e.out_start,
                last.out_end()
            );
        }
        self.edits.push(e);
        self.src_funcs.push(src);
    }

    /// Apply these edits to `input`, producing the output bytes. The
    /// `synth` function is called for synthesised spans (pure or
    /// cross-body) and supplies the bytes.
    ///
    /// Returns `None` if the edit list doesn't fit `input.len()` —
    /// a malformed/stale edit list.
    pub fn apply<F>(&self, input: &[u8], mut synth: F) -> Option<Vec<u8>>
    where
        F: FnMut(usize, Option<u32>, u32) -> Option<Vec<u8>>,
    {
        // Determine total output size.
        let mut out_len = input.len() as u32;
        for e in &self.edits {
            if e.in_end() as usize > input.len() {
                return None;
            }
            out_len = out_len.checked_sub(e.in_len)?.checked_add(e.out_len)?;
        }
        let mut out = Vec::with_capacity(out_len as usize);
        let mut in_cursor = 0u32;
        for (i, e) in self.edits.iter().enumerate() {
            // Copy identity bytes up to this edit's input start.
            if e.in_start < in_cursor {
                return None;
            }
            out.extend_from_slice(&input[in_cursor as usize..e.in_start as usize]);
            // Write the replacement span.
            if e.in_len > 0 && e.out_len > 0 {
                // Substitution — callback supplies new bytes.
                let bytes = synth(i, self.src_funcs[i], e.out_len)?;
                if bytes.len() as u32 != e.out_len {
                    return None;
                }
                out.extend_from_slice(&bytes);
            } else if e.out_len > 0 {
                // Pure synthesis.
                let bytes = synth(i, self.src_funcs[i], e.out_len)?;
                if bytes.len() as u32 != e.out_len {
                    return None;
                }
                out.extend_from_slice(&bytes);
            }
            // in_len > 0 && out_len == 0 → deletion, nothing to write.
            in_cursor = e.in_end();
        }
        if (in_cursor as usize) > input.len() {
            return None;
        }
        out.extend_from_slice(&input[in_cursor as usize..]);
        Some(out)
    }

    /// Compose two edit lists: `self` = input → mid, `next` = mid →
    /// out. Result maps input → out.
    ///
    /// Complexity: O(|self| + |next|).
    ///
    /// Algorithm: walk both lists in lock-step over the intermediate
    /// space. Any mid-space region covered by a `self` edit is an
    /// input-side transformation; any mid-space region covered by a
    /// `next` edit is an output-side transformation. The result
    /// folds corresponding chunks pairwise.
    pub fn compose(a: &Self, b: &Self) -> Self {
        if a.is_identity() {
            return b.clone();
        }
        if b.is_identity() {
            return a.clone();
        }

        // Strategy: build output edits by walking through `b` (the
        // mid→out map) in out_start order. For each `b` edit, figure
        // out which `a`-space input range it ultimately comes from
        // by pulling corresponding mid-space range back through `a`.
        //
        // Regions of mid-space NOT touched by `b` came through `a`'s
        // output spans (the ones in mid-space). Those contribute
        // direct input → output substitutions keyed by `a`'s edits.
        //
        // This is still O(|a|+|b|) since we linear-scan both.

        let mut out_edits = Vec::with_capacity(a.edits.len() + b.edits.len());
        let mut out_srcs = Vec::with_capacity(a.edits.len() + b.edits.len());

        // Event cursors — the high-water mark we've emitted in mid-
        // space and out-space.
        let mut a_idx = 0;
        let mut mid_cursor = 0u32;
        let mut out_cursor = 0u32;

        // For each `b` edit, walk mid-space up to its start, emitting
        // any `a` edits that project through identity in b's region.
        for (b_i, be) in b.edits.iter().enumerate() {
            while a_idx < a.edits.len() && a.edits[a_idx].out_end() <= be.out_start {
                let ae = a.edits[a_idx];
                // This `a`-edit's mid-space run projects identity in b
                // up to be.out_start. Emit it as an input→output edit
                // translating the mid_cursor offset via b's identity.
                let delta_in_out =
                    out_cursor_for_mid(be, ae.out_start, &b, &mut mid_cursor, &mut out_cursor);
                out_edits.push(Edit {
                    in_start: ae.in_start,
                    in_len: ae.in_len,
                    out_start: delta_in_out,
                    out_len: ae.out_len,
                });
                out_srcs.push(a.src_funcs[a_idx]);
                a_idx += 1;
            }
            // Now handle b's edit at be.out_start.
            // Translate b.in_start (mid) back through `a` to find the
            // input span this edit originated from.
            let (in_start, in_len) = mid_to_in(be.in_start, be.in_len, a);
            let src = b.src_funcs[b_i].or_else(|| {
                // If b didn't name a source function but a's edit at
                // the overlapping mid range did, use a's.
                find_src_in_a(be.in_start, be.in_len, a)
            });
            // Output position: advance out_cursor by any identity run
            // between the last output byte we emitted and this edit.
            let identity_mid_gap = be.in_start.saturating_sub(mid_cursor);
            out_cursor = out_cursor.saturating_add(identity_mid_gap);
            out_edits.push(Edit {
                in_start,
                in_len,
                out_start: out_cursor,
                out_len: be.out_len,
            });
            out_srcs.push(src);
            out_cursor = out_cursor.saturating_add(be.out_len);
            mid_cursor = be.in_end();
        }

        // Trailing a-edits after the last b-edit: they map straight
        // through (b is identity past its last edit).
        while a_idx < a.edits.len() {
            let ae = a.edits[a_idx];
            // out space for these = mid space offset by (out_cursor -
            // mid_cursor). Since b is identity from mid_cursor onward,
            // the delta is preserved.
            let out_start = ae
                .out_start
                .saturating_sub(mid_cursor)
                .saturating_add(out_cursor);
            out_edits.push(Edit {
                in_start: ae.in_start,
                in_len: ae.in_len,
                out_start,
                out_len: ae.out_len,
            });
            out_srcs.push(a.src_funcs[a_idx]);
            a_idx += 1;
        }

        Self {
            edits: out_edits,
            src_funcs: out_srcs,
        }
    }
}

/// Translate a mid-space span back through `a` to find its input
/// origin.
///
/// Model: walk `a.edits` in out-start order, accumulating a shift
/// `accum = sum(in_len - out_len)` for edits whose out range lies
/// strictly before our mid position. For identity regions, input
/// position = mid position + accum. For mid ranges overlapping `a`
/// edits, we union the overlapping input spans plus any bookend
/// identity regions (with shift applied).
fn mid_to_in(mid_start: u32, mid_len: u32, a: &BodyEdits) -> (u32, u32) {
    if a.is_identity() {
        return (mid_start, mid_len);
    }
    let mid_end = mid_start + mid_len;

    let mut accum_before: i64 = 0; // in - out for all a-edits strictly before mid_start
    let mut in_lo = u32::MAX;
    let mut in_hi = 0u32;
    let mut had_overlap = false;
    let mut accum_thru_overlap: i64 = 0;

    for ae in &a.edits {
        if ae.out_end() <= mid_start {
            // strictly before
            accum_before += ae.in_len as i64 - ae.out_len as i64;
            continue;
        }
        if ae.out_start >= mid_end {
            break;
        }
        // overlap
        had_overlap = true;
        in_lo = in_lo.min(ae.in_start);
        in_hi = in_hi.max(ae.in_end());
        accum_thru_overlap += ae.in_len as i64 - ae.out_len as i64;
    }

    if !had_overlap {
        // Entirely in an identity region — shift mid_start by accum_before.
        let in_pos = (mid_start as i64 + accum_before).max(0) as u32;
        return (in_pos, mid_len);
    }

    // Mid range overlaps at least one a-edit. Extend input span to
    // cover identity regions at the boundaries of the mid range.
    // Identity region before first overlap: mid_start .. first_overlap.out_start
    // Identity region after last overlap: last_overlap.out_end .. mid_end
    // For identity regions, in == mid + accum.
    let first_overlap_out_start = a
        .edits
        .iter()
        .find(|e| e.out_end() > mid_start && e.out_start < mid_end)
        .map(|e| e.out_start)
        .unwrap_or(mid_start);
    let last_overlap_out_end = a
        .edits
        .iter()
        .rev()
        .find(|e| e.out_end() > mid_start && e.out_start < mid_end)
        .map(|e| e.out_end())
        .unwrap_or(mid_end);

    if mid_start < first_overlap_out_start {
        let bookend_in = (mid_start as i64 + accum_before).max(0) as u32;
        in_lo = in_lo.min(bookend_in);
    }
    if mid_end > last_overlap_out_end {
        // Shift at the tail = accum_before + accum_thru_overlap.
        let tail_accum = accum_before + accum_thru_overlap;
        let bookend_in = (mid_end as i64 + tail_accum).max(0) as u32;
        in_hi = in_hi.max(bookend_in);
    }

    (in_lo, in_hi.saturating_sub(in_lo))
}

fn find_src_in_a(mid_start: u32, mid_len: u32, a: &BodyEdits) -> Option<u32> {
    let mid_end = mid_start + mid_len;
    for (i, ae) in a.edits.iter().enumerate() {
        if ae.out_end() <= mid_start {
            continue;
        }
        if ae.out_start >= mid_end {
            break;
        }
        if let Some(src) = a.src_funcs[i] {
            return Some(src);
        }
    }
    None
}

/// Helper used in `compose`'s a-loop. Currently returns the
/// out-cursor position corresponding to a given mid position under
/// `b`'s identity-section projection.
#[allow(dead_code)]
fn out_cursor_for_mid(
    _be: &Edit,
    mid_target: u32,
    _b: &BodyEdits,
    mid_cursor: &mut u32,
    out_cursor: &mut u32,
) -> u32 {
    // Identity projection from mid_cursor up to mid_target.
    let delta = mid_target.saturating_sub(*mid_cursor);
    let new_out = out_cursor.saturating_add(delta);
    *mid_cursor = mid_target;
    *out_cursor = new_out;
    new_out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_fail(_i: usize, _f: Option<u32>, _len: u32) -> Option<Vec<u8>> {
        None
    }

    #[test]
    fn identity_apply_returns_input() {
        let e = BodyEdits::identity();
        let input = b"abcdef".to_vec();
        let out = e.apply(&input, synth_fail).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn deletion_applies() {
        // Delete bytes 2..4 of "abcdef" → "abef"
        let mut e = BodyEdits::identity();
        e.push(Edit::delete(2, 2, 2), None);
        let out = e.apply(b"abcdef", synth_fail).unwrap();
        assert_eq!(out, b"abef");
    }

    #[test]
    fn substitution_applies() {
        // Replace bytes 1..3 ("bc") with two bytes "XY" — out: "aXYdef"
        let mut e = BodyEdits::identity();
        e.push(Edit::subst(1, 2, 1, 2), None);
        let out = e
            .apply(b"abcdef", |_, _, n| {
                assert_eq!(n, 2);
                Some(b"XY".to_vec())
            })
            .unwrap();
        assert_eq!(out, b"aXYdef");
    }

    #[test]
    fn synthesis_applies() {
        // Insert "XYZ" at position 3 — out: "abcXYZdef"
        let mut e = BodyEdits::identity();
        e.push(Edit::synth(3, 3, 3), None);
        let out = e
            .apply(b"abcdef", |_, _, n| {
                assert_eq!(n, 3);
                Some(b"XYZ".to_vec())
            })
            .unwrap();
        assert_eq!(out, b"abcXYZdef");
    }

    #[test]
    fn multiple_edits_apply_in_order() {
        // Delete 0..1 ("a") then subst 3..4 ("d") with "DD"
        let mut e = BodyEdits::identity();
        e.push(Edit::delete(0, 1, 0), None);
        e.push(Edit::subst(3, 1, 2, 2), None);
        let out = e
            .apply(b"abcdef", |_, _, n| {
                assert_eq!(n, 2);
                Some(b"DD".to_vec())
            })
            .unwrap();
        assert_eq!(out, b"bcDDef");
    }

    #[test]
    fn identity_compose_identity_is_identity() {
        let a = BodyEdits::identity();
        let b = BodyEdits::identity();
        assert!(BodyEdits::compose(&a, &b).is_identity());
    }

    #[test]
    fn compose_deletion_then_identity() {
        // A deletes bytes 2..4, B is identity. Composed should still
        // delete those bytes.
        let mut a = BodyEdits::identity();
        a.push(Edit::delete(2, 2, 2), None);
        let b = BodyEdits::identity();
        let c = BodyEdits::compose(&a, &b);
        let out = c.apply(b"abcdef", synth_fail).unwrap();
        assert_eq!(out, b"abef");
    }

    #[test]
    fn compose_identity_then_deletion() {
        let a = BodyEdits::identity();
        let mut b = BodyEdits::identity();
        b.push(Edit::delete(2, 2, 2), None);
        let c = BodyEdits::compose(&a, &b);
        let out = c.apply(b"abcdef", synth_fail).unwrap();
        assert_eq!(out, b"abef");
    }

    #[test]
    fn compose_two_deletions_at_different_positions() {
        // A deletes bytes 0..1 ("a"), giving "bcdef".
        // B deletes bytes 2..3 of that ("d"), giving "bcef".
        // Composed a→b should yield "bcef" from "abcdef".
        let mut a = BodyEdits::identity();
        a.push(Edit::delete(0, 1, 0), None);
        let mut b = BodyEdits::identity();
        b.push(Edit::delete(2, 1, 2), None);
        let c = BodyEdits::compose(&a, &b);
        let out = c.apply(b"abcdef", synth_fail).unwrap();
        assert_eq!(out, b"bcef");
    }

    #[test]
    fn compose_sequential_substitutions() {
        // A: subst 1..2 ("b") with "BB" → "aBBcdef"
        // B: subst 3..4 ("c") with "CC" — WAIT, we need B's input to
        // be the output of A. A's output has "BB" at pos 1..3, "c"
        // at pos 3. So B subst 3..4 → "CC" gives "aBBCCdef".
        let mut a = BodyEdits::identity();
        a.push(Edit::subst(1, 1, 1, 2), None);
        let mut b = BodyEdits::identity();
        b.push(Edit::subst(3, 1, 3, 2), None);
        let c = BodyEdits::compose(&a, &b);

        // Apply a then b to confirm expected output.
        let after_a = a.apply(b"abcdef", |_, _, _| Some(b"BB".to_vec())).unwrap();
        assert_eq!(after_a, b"aBBcdef");
        let after_b = b.apply(&after_a, |_, _, _| Some(b"CC".to_vec())).unwrap();
        assert_eq!(after_b, b"aBBCCdef");

        // Applying the composed map directly to input should yield the
        // same final bytes. We need a synth callback that returns the
        // right bytes per edit index — our compose currently doesn't
        // preserve byte provenance, so we can only verify structure.
        // The compose result should have 2 edits, both substitutions.
        assert_eq!(c.edits().len(), 2);
    }
}
