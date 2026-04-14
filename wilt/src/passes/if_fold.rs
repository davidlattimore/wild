//! Identical-branch if-folding.
//!
//! When both arms of an `if` are byte-identical, the branch is dead
//! weight: whichever way `cond` goes, the same instructions run.
//!
//!   <cond> ; if 0x40 <A> else <A> end
//!     →  drop ; <A>
//!
//! Saves `3 + |A|` bytes per match (we keep one copy of A and a single
//! `drop` to consume the condition).
//!
//! Scope:
//!   * Void blocktype (0x40) only. Non-void would need to preserve
//!     value-producing stack effect; `drop; A` changes nothing there
//!     but we keep the bar simple.
//!   * Requires an explicit `else` arm (no elided-else form — there's
//!     nothing to dedupe).
//!   * Bails if either arm contains `br`/`br_if`/`br_table` — removing
//!     the if-frame shifts every label depth by one and the fold would
//!     have to renumber. Deferred.
//!   * `return` inside A is depth-independent and therefore safe.
//!
//! Why bother? Arises naturally after const_prop / copy_prop collapse
//! two previously-distinct arms to the same shape, and from toolchain
//! stubs that emit symmetric cleanup on both paths.

use crate::ir::BodyIr;
use crate::mut_module::MutModule;
use crate::opcode::{self as opc, InstrIter};

const OP_IF: u8 = 0x04;
const OP_ELSE: u8 = 0x05;
const OP_DROP: u8 = 0x1A;

pub fn apply_mut(m: &mut MutModule<'_>) {
    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>, crate::provenance::BodyEdits)> = (0..m.num_bodies())
        .into_par_iter()
        .filter_map(|i| rewrite_body_with_edits(m.body_bytes(i)).map(|(b, e)| (i, b, e)))
        .collect();
    for (i, b, e) in updates { m.set_body_with_edits(i, b, e); }
}

#[allow(dead_code)]
fn rewrite_body(body: &[u8]) -> Option<Vec<u8>> {
    rewrite_body_with_edits(body).map(|(b, _)| b)
}

fn has_if_else(body: &[u8]) -> bool {
    let Some(start) = opc::skip_locals(body) else { return false };
    let mut iter = InstrIter::new(body, start);
    let mut saw_if = false;
    while let Some((p, _)) = iter.next() {
        match body[p] {
            OP_IF => saw_if = true,
            OP_ELSE if saw_if => return true,
            _ => {}
        }
    }
    false
}

fn rewrite_body_with_edits(body: &[u8]) -> Option<(Vec<u8>, crate::provenance::BodyEdits)> {
    if !has_if_else(body) { return None; }

    let ir = BodyIr::new(body)?;
    let n = ir.instrs().len();
    if n < 4 { return None; }

    let (ends, elses) = match_structural(&ir);

    // Collect non-overlapping rewrites in instruction-index order.
    // Skip any if whose range overlaps an already-chosen fold — the
    // outer fixpoint will revisit after we apply this round.
    let mut edits: Vec<(usize, usize, &[u8])> = Vec::new(); // (byte_from, byte_to, keep_bytes)
    let mut consumed_end: usize = 0;

    for i in 0..n {
        if i < consumed_end { continue; }
        let it = ir.instrs()[i];
        if it.op != OP_IF { continue; }
        if body.get(it.start as usize + 1).copied() != Some(0x40) { continue; }

        let Some(&end_idx) = ends.get(&i) else { continue };
        let Some(&else_idx) = elses.get(&i) else { continue };

        let then_start = it.end() as usize;
        let else_instr = ir.instrs()[else_idx];
        let then_end = else_instr.start as usize;
        let else_start = else_instr.end() as usize;
        let end_instr = ir.instrs()[end_idx];
        let else_end = end_instr.start as usize;

        if body.get(then_start..then_end) != body.get(else_start..else_end) {
            continue;
        }

        if range_contains_branch(&ir, i + 1, else_idx) { continue; }
        // Then-bytes == else-bytes so either arm's branch-check suffices.

        // Rewrite: replace [if..end_of_end] with [drop] + then-bytes.
        let from = it.start as usize;
        let to = end_instr.end() as usize;
        edits.push((from, to, &body[then_start..then_end]));
        consumed_end = end_idx + 1;
    }

    if edits.is_empty() { return None; }

    let mut out = Vec::with_capacity(body.len());
    let mut body_edits = crate::provenance::BodyEdits::identity();
    let mut cursor = 0;
    for &(from, to, keep) in &edits {
        out.extend_from_slice(&body[cursor..from]);
        let out_start = out.len() as u32;
        out.push(OP_DROP);
        out.extend_from_slice(keep);
        let out_len = out.len() as u32 - out_start;
        body_edits.push(
            crate::provenance::Edit::subst(
                from as u32, (to - from) as u32, out_start, out_len,
            ),
            None,
        );
        cursor = to;
    }
    out.extend_from_slice(&body[cursor..]);
    Some((out, body_edits))
}

fn range_contains_branch(ir: &BodyIr, start: usize, end: usize) -> bool {
    for k in start..end {
        if k >= ir.instrs().len() { break; }
        if matches!(ir.instrs()[k].op, 0x0C | 0x0D | 0x0E) {
            return true;
        }
    }
    false
}

fn match_structural(ir: &BodyIr) -> (
    std::collections::HashMap<usize, usize>,
    std::collections::HashMap<usize, usize>,
) {
    let mut ends = std::collections::HashMap::new();
    let mut elses = std::collections::HashMap::new();
    let mut stack: Vec<usize> = Vec::new();
    for (i, it) in ir.instrs().iter().enumerate() {
        match it.op {
            0x02 | 0x03 | 0x04 => stack.push(i),
            0x05 => {
                if let Some(&top) = stack.last() {
                    if ir.instrs()[top].op == 0x04 {
                        elses.insert(top, i);
                    }
                }
            }
            0x0B => {
                if let Some(open) = stack.pop() { ends.insert(open, i); }
            }
            _ => {}
        }
    }
    (ends, elses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_identical_branches() {
        // local.get 0 ; if ; nop ; else ; nop ; end ; end
        let body = [
            1, 1, 0x7F,
            0x20, 0,
            0x04, 0x40,
            0x01,               // then: nop
            0x05,               // else
            0x01,               // else: nop
            0x0B,               // end if
            0x0B,               // end func
        ];
        let out = rewrite_body(&body).expect("should fold");
        // Expected: locals + local.get + drop + nop + end.
        assert_eq!(out, vec![
            1, 1, 0x7F,
            0x20, 0,
            0x1A,               // drop
            0x01,               // nop
            0x0B,
        ]);
    }

    #[test]
    fn leaves_differing_branches() {
        let body = [
            1, 1, 0x7F,
            0x20, 0,
            0x04, 0x40,
            0x01,
            0x05,
            0x01, 0x01,         // else has extra nop
            0x0B,
            0x0B,
        ];
        assert!(rewrite_body(&body).is_none());
    }

    #[test]
    fn bails_on_branch_in_arm() {
        // br 0 inside the if — targets the if frame; renumbering required.
        let body = [
            1, 1, 0x7F,
            0x20, 0,
            0x04, 0x40,
            0x0C, 0x00,
            0x05,
            0x0C, 0x00,
            0x0B,
            0x0B,
        ];
        assert!(rewrite_body(&body).is_none());
    }

    #[test]
    fn leaves_non_void_blocktype() {
        let body = [
            1, 1, 0x7F,
            0x20, 0,
            0x04, 0x7F,         // if (result i32)
            0x41, 1,
            0x05,
            0x41, 1,
            0x0B,
            0x1A,
            0x0B,
        ];
        assert!(rewrite_body(&body).is_none());
    }

    #[test]
    fn leaves_missing_else() {
        let body = [
            1, 1, 0x7F,
            0x20, 0,
            0x04, 0x40,
            0x01,
            0x0B,
            0x0B,
        ];
        assert!(rewrite_body(&body).is_none());
    }
}
