//! Constant-condition branch elimination.
//!
//! When the cond pushed onto the stack right before an `if` is a
//! statically-known constant (`i32.const N`), the wasm runtime would
//! always pick the same arm. We can rewrite ahead of time:
//!
//!   <i32.const N> ; if 0x40 <then> else <else> end
//!     →  <then>          if N ≠ 0
//!     →  <else>          if N == 0
//!
//!   <i32.const N> ; if 0x40 <then> end
//!     →  <then>          if N ≠ 0
//!     →  (nothing)       if N == 0
//!
//! Scope (this pass): only `if` with empty blocktype (no input/output
//! arity). Multi-value `if` would need stack-shape rewriting we don't
//! do here. Only `i32.const`-as-condition; an enclosing `i32.eqz` /
//! cmp would also work in principle but is left for a future
//! `const_fold` extension.
//!
//! Builds on the M5 + if/else conditional-edges work. Runs after
//! const_prop in the pipeline so propagated constants feed it.

use crate::ir::BodyIr;
use crate::leb128;
use crate::mut_module::MutModule;

const OP_I32_CONST: u8 = 0x41;
const OP_IF: u8 = 0x04;

pub fn apply_mut(m: &mut MutModule<'_>) {
    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>)> = (0..m.num_bodies())
        .into_par_iter()
        .filter_map(|i| rewrite_body(m.body_bytes(i)).map(|b| (i, b)))
        .collect();
    for (i, b) in updates { m.set_body(i, b); }
}

fn rewrite_body(body: &[u8]) -> Option<Vec<u8>> {
    let ir = BodyIr::new(body)?;
    let n = ir.instrs().len();
    if n < 3 { return None; }

    // Pre-pass: matching ends + elses for every if/block/loop.
    let (ends, elses) = match_structural(&ir);

    // Find applicable patterns. Process at most one rewrite per if so
    // we don't trip over our own edits — the fixpoint loop catches
    // nested cases on subsequent iterations.
    let mut deletes: Vec<(usize, usize)> = Vec::new();

    for i in 0..n {
        let it = ir.instrs()[i];
        if it.op != OP_IF { continue; }

        let blocktype_byte = body.get(it.start as usize + 1).copied();
        if blocktype_byte != Some(0x40) { continue; }

        if i == 0 { continue; }
        let prev = ir.instrs()[i - 1];
        if prev.op != OP_I32_CONST { continue; }
        let Some((cond, _)) = leb128::read_i32(&body[(prev.start + 1) as usize..]) else { continue };
        let truthy = cond != 0;

        let end_idx = match ends.get(&i) { Some(&e) => e, None => continue };
        let else_idx = elses.get(&i).copied();

        // Determine the index range of the *chosen* branch and bail if
        // it contains any br/br_if/br_table — removing the if frame
        // shifts label depths and we'd need to rewrite all those
        // labels (deferred to a future pass).
        let (chosen_start, chosen_end) = match (truthy, else_idx) {
            (true, Some(e)) => (i + 1, e),
            (true, None) => (i + 1, end_idx),
            (false, Some(e)) => (e + 1, end_idx),
            (false, None) => (i + 1, i + 1),         // empty
        };
        if range_contains_branch(&ir, chosen_start, chosen_end) { continue; }

        // Byte positions of the structural pieces.
        let const_start = prev.start as usize;
        let if_end = (it.end()) as usize;          // first byte of then body
        let end_byte_start = ir.instrs()[end_idx].start as usize;
        let end_byte_end = ir.instrs()[end_idx].end() as usize;

        match (truthy, else_idx) {
            // Take then; delete cond+if and the else-clause+end.
            (true, Some(e_idx)) => {
                let else_start = ir.instrs()[e_idx].start as usize;
                deletes.push((const_start, if_end));
                deletes.push((else_start, end_byte_end));
            }
            (true, None) => {
                // Take then; delete cond+if and end.
                deletes.push((const_start, if_end));
                deletes.push((end_byte_start, end_byte_end));
            }
            // Take else; delete cond+if+then+else_opcode and end.
            (false, Some(e_idx)) => {
                let else_end = ir.instrs()[e_idx].end() as usize;
                deletes.push((const_start, else_end));
                deletes.push((end_byte_start, end_byte_end));
            }
            // Take nothing; delete cond+if+then+end entirely.
            (false, None) => {
                deletes.push((const_start, end_byte_end));
            }
        }
    }
    if deletes.is_empty() { return None; }

    // Sort + dedupe overlapping ranges (shouldn't happen but be safe).
    deletes.sort_by_key(|&(s, _)| s);
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (s, e) in deletes {
        if let Some(last) = merged.last_mut() {
            if s < last.1 {
                // Overlap — extend.
                if e > last.1 { last.1 = e; }
                continue;
            }
        }
        merged.push((s, e));
    }

    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for &(s, e) in &merged {
        out.extend_from_slice(&body[cursor..s]);
        cursor = e;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

/// True if any instruction in `[start, end)` is a br/br_if/br_table.
/// Used to gate the unwrap — removing an if frame shifts label depths.
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
    fn folds_truthy_if_else() {
        // (func i32.const 1 if nop else i32.const 99 drop end end)
        let body = [
            0u8,
            0x41, 1,            // i32.const 1
            0x04, 0x40,         // if
            0x01,               // then: nop
            0x05,               // else
            0x41, 99,           // i32.const 99
            0x1A,               // drop
            0x0B,               // end if
            0x0B,               // end func
        ];
        let out = rewrite_body(&body).expect("should fold");
        // Expected: locals + (then body = nop) + end func.
        let expected = vec![0u8, 0x01, 0x0B];
        assert_eq!(out, expected);
    }

    #[test]
    fn folds_falsy_if_else() {
        let body = [
            0u8,
            0x41, 0,            // i32.const 0
            0x04, 0x40,         // if
            0x01,               // then: nop
            0x05,               // else
            0x41, 7,            // i32.const 7
            0x1A,               // drop
            0x0B,               // end if
            0x0B,               // end func
        ];
        let out = rewrite_body(&body).expect("should fold");
        // Expected: locals + (else body = i32.const 7 ; drop) + end func.
        let expected = vec![0u8, 0x41, 7, 0x1A, 0x0B];
        assert_eq!(out, expected);
    }

    #[test]
    fn folds_truthy_if_no_else() {
        let body = [
            0u8,
            0x41, 1,            // i32.const 1
            0x04, 0x40,         // if
            0x01,               // then: nop
            0x0B,               // end if
            0x0B,               // end func
        ];
        let out = rewrite_body(&body).expect("should fold");
        let expected = vec![0u8, 0x01, 0x0B];
        assert_eq!(out, expected);
    }

    #[test]
    fn folds_falsy_if_no_else() {
        let body = [
            0u8,
            0x41, 0,            // i32.const 0
            0x04, 0x40,         // if
            0x01,               // then: nop
            0x0B,               // end if
            0x0B,               // end func
        ];
        let out = rewrite_body(&body).expect("should fold");
        // Whole construct (cond + if + then + end) gone.
        let expected = vec![0u8, 0x0B];
        assert_eq!(out, expected);
    }

    #[test]
    fn leaves_non_empty_blocktype_alone() {
        // if with result type — out of scope.
        let body = [
            0u8,
            0x41, 1,
            0x04, 0x7F,         // if (result i32)
            0x41, 5,
            0x05,
            0x41, 9,
            0x0B,
            0x1A,
            0x0B,
        ];
        assert!(rewrite_body(&body).is_none());
    }

    #[test]
    fn leaves_dynamic_cond_alone() {
        // local.get 0 ; if … — cond not statically known.
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
