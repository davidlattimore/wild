//! Per-body constant propagation through locals — CFG-aware.
//!
//! Forward dataflow over `CfgIr`. Lattice: for each local, either
//! "unknown" (not in the bindings map) or "exactly these const bytes"
//! (`Vec<u8>` storing the original `T.const N` instruction).
//!
//! Per-BB transfer: scans the BB straight-line, recognising the
//! `<T.const>; local.set X` pattern that binds X to that const's
//! bytes. Other writes to X (set with non-const-on-stack, tee) clear
//! the binding. Calls / arithmetic don't affect locals.
//!
//! Meet at BB entry: intersection of predecessors' out-states; an
//! entry survives only if every predecessor agrees on the same bytes.
//! BBs with no predecessor (entry only, in our CFGs) start empty.
//!
//! Replacement: at each `local.get X` where X is bound to bytes B,
//! replace the get with B (only if `B.len() <= get.len`, so we never
//! grow). Downstream simplify_locals + vacuum then collapse the
//! orphaned set / const-drop pair.
//!
//! Coverage: cross-BB through if/else (we built the conditional CFG
//! edges in M5+), through loops (the fixpoint converges on the
//! intersection of header preds), through any structured CF.
//! Standalone — no hints required.

use std::collections::HashMap;

use crate::ir::{BodyIr, CfgIr};
use crate::leb128;
use crate::mut_module::MutModule;
use crate::opcode::{self as opc, InstrIter};

const OP_I32_CONST: u8 = 0x41;
const OP_I64_CONST: u8 = 0x42;
const OP_F32_CONST: u8 = 0x43;
const OP_F64_CONST: u8 = 0x44;
const OP_LOCAL_GET: u8 = 0x20;
const OP_LOCAL_SET: u8 = 0x21;
const OP_LOCAL_TEE: u8 = 0x22;

type Bindings = HashMap<u32, Vec<u8>>;

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

fn rewrite_body_with_edits(body: &[u8]) -> Option<(Vec<u8>, crate::provenance::BodyEdits)> {
    // Bail-early: const_prop only fires when there's BOTH a const opcode
    // AND a local.get to potentially rewrite. Cheap byte scan first.
    if !has_const_and_local_get(body) { return None; }

    let ir = BodyIr::new(body)?;
    let cfg = CfgIr::build(&ir)?;
    let nbb = cfg.blocks.len();
    if nbb == 0 || ir.instrs().is_empty() { return None; }

    // Predecessors per BB (CfgIr stores successors only).
    let mut preds: Vec<Vec<u32>> = vec![Vec::new(); nbb];
    for (bi, bb) in cfg.blocks.iter().enumerate() {
        for edge in &bb.successors {
            preds[edge.target as usize].push(bi as u32);
        }
    }

    // Forward dataflow. bb_out[bi] = bindings just AFTER BB bi.
    let mut bb_out: Vec<Bindings> = vec![HashMap::new(); nbb];
    for _ in 0..1_000 {
        let mut changed = false;
        for bi in 0..nbb {
            let in_state = meet_in(bi as u32, &preds[bi], &bb_out);
            let new_out = transfer(&ir, &cfg.blocks[bi], in_state);
            if new_out != bb_out[bi] {
                bb_out[bi] = new_out;
                changed = true;
            }
        }
        if !changed { break; }
    }

    // Recompute bb_in for each BB and record rewrites.
    let mut rewrites: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    for (bi, bb) in cfg.blocks.iter().enumerate() {
        let in_state = meet_in(bi as u32, &preds[bi], &bb_out);
        record_rewrites(&ir, bb, in_state, &mut rewrites);
    }
    if rewrites.is_empty() { return None; }
    rewrites.sort_by_key(|e| e.0);

    let mut out = Vec::with_capacity(body.len());
    let mut edits = crate::provenance::BodyEdits::identity();
    let mut cursor = 0;
    for (p, len, repl) in &rewrites {
        out.extend_from_slice(&body[cursor..*p]);
        let out_start = out.len() as u32;
        out.extend_from_slice(repl);
        let out_len = out.len() as u32 - out_start;
        edits.push(
            crate::provenance::Edit::subst(*p as u32, *len as u32, out_start, out_len),
            None,
        );
        cursor = p + len;
    }
    out.extend_from_slice(&body[cursor..]);
    Some((out, edits))
}

fn meet_in(_bi: u32, preds: &[u32], bb_out: &[Bindings]) -> Bindings {
    if preds.is_empty() { return HashMap::new(); }
    let mut iter = preds.iter();
    let first = *iter.next().unwrap();
    let mut result = bb_out[first as usize].clone();
    for &p in iter {
        let other = &bb_out[p as usize];
        result.retain(|k, v| other.get(k) == Some(v));
    }
    result
}

fn transfer(ir: &BodyIr, bb: &crate::ir::BasicBlock, in_state: Bindings) -> Bindings {
    let mut state = in_state;
    let mut skip_next_set = false;
    for k in bb.start_instr..bb.end_instr {
        let i = k as usize;
        let op = ir.instrs()[i].op;
        match op {
            OP_I32_CONST | OP_I64_CONST | OP_F32_CONST | OP_F64_CONST => {
                if (k + 1) < bb.end_instr
                    && ir.instrs()[(k + 1) as usize].op == OP_LOCAL_SET
                {
                    if let Some(x) = local_idx(ir, (k + 1) as usize) {
                        state.insert(x, ir.instr_bytes(i).to_vec());
                        skip_next_set = true;
                    }
                }
            }
            OP_LOCAL_SET => {
                if skip_next_set { skip_next_set = false; }
                else if let Some(x) = local_idx(ir, i) { state.remove(&x); }
            }
            OP_LOCAL_TEE => {
                if let Some(x) = local_idx(ir, i) { state.remove(&x); }
            }
            _ => {}
        }
    }
    state
}

fn record_rewrites(
    ir: &BodyIr, bb: &crate::ir::BasicBlock, in_state: Bindings,
    out: &mut Vec<(usize, usize, Vec<u8>)>,
) {
    let mut state = in_state;
    let mut skip_next_set = false;
    for k in bb.start_instr..bb.end_instr {
        let i = k as usize;
        let it = ir.instrs()[i];
        match it.op {
            OP_I32_CONST | OP_I64_CONST | OP_F32_CONST | OP_F64_CONST => {
                if (k + 1) < bb.end_instr
                    && ir.instrs()[(k + 1) as usize].op == OP_LOCAL_SET
                {
                    if let Some(x) = local_idx(ir, (k + 1) as usize) {
                        state.insert(x, ir.instr_bytes(i).to_vec());
                        skip_next_set = true;
                    }
                }
            }
            OP_LOCAL_GET => {
                if let Some(x) = local_idx(ir, i) {
                    if let Some(bytes) = state.get(&x) {
                        if bytes.len() <= it.len as usize {
                            out.push((it.start as usize, it.len as usize, bytes.clone()));
                        }
                    }
                }
            }
            OP_LOCAL_SET => {
                if skip_next_set { skip_next_set = false; }
                else if let Some(x) = local_idx(ir, i) { state.remove(&x); }
            }
            OP_LOCAL_TEE => {
                if let Some(x) = local_idx(ir, i) { state.remove(&x); }
            }
            _ => {}
        }
    }
}

fn local_idx(ir: &BodyIr, i: usize) -> Option<u32> {
    leb128::read_u32(&ir.instr_bytes(i)[1..]).map(|(v, _)| v)
}

fn has_const_and_local_get(body: &[u8]) -> bool {
    let Some(start) = opc::skip_locals(body) else { return false };
    let mut iter = InstrIter::new(body, start);
    let mut has_const = false;
    let mut has_get = false;
    while let Some((p, _)) = iter.next() {
        match body[p] {
            OP_I32_CONST | OP_I64_CONST | OP_F32_CONST | OP_F64_CONST => has_const = true,
            OP_LOCAL_GET => has_get = true,
            _ => {}
        }
        if has_const && has_get { return true; }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propagates_within_basic_block() {
        // Same as the old test — must still pass.
        let body = [
            1, 1, 0x7F,
            0x41, 5,
            0x21, 0,
            0x01,
            0x20, 0,
            0x1A,
            0x0B,
        ];
        let out = rewrite_body(&body).expect("should propagate");
        let expected = vec![
            1, 1, 0x7F, 0x41, 5, 0x21, 0, 0x01, 0x41, 5, 0x1A, 0x0B,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn no_propagation_after_overwrite() {
        let body = [
            1, 1, 0x7F,
            0x41, 5,
            0x21, 0,
            0x41, 7,
            0x21, 0,
            0x20, 0,
            0x1A,
            0x0B,
        ];
        let out = rewrite_body(&body).expect("should propagate from second const");
        let expected = vec![
            1, 1, 0x7F, 0x41, 5, 0x21, 0, 0x41, 7, 0x21, 0, 0x41, 7, 0x1A, 0x0B,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn discriminates_locals() {
        let body = [
            1, 2, 0x7F,
            0x41, 5,
            0x21, 0,
            0x41, 9,
            0x21, 1,
            0x20, 0,
            0x1A,
            0x20, 1,
            0x1A,
            0x0B,
        ];
        let out = rewrite_body(&body).expect("should propagate both");
        let expected = vec![
            1, 2, 0x7F, 0x41, 5, 0x21, 0, 0x41, 9, 0x21, 1,
            0x41, 5, 0x1A, 0x41, 9, 0x1A, 0x0B,
        ];
        assert_eq!(out, expected);
    }

    // CROSS-BB: const set in then-branch only; meet at post-end is empty.
    #[test]
    fn no_propagation_when_only_one_branch_sets() {
        // local 0; i32.const 0; if; i32.const 5; local.set 0; end;
        // local.get 0; drop; end-func.
        let body = [
            1, 1, 0x7F,
            0x41, 0,           // cond
            0x04, 0x40,        // if
            0x41, 5,
            0x21, 0,           // local.set 0 only in then
            0x0B,              // end if
            0x20, 0,           // local.get 0 — has only one path with binding
            0x1A,
            0x0B,
        ];
        // Conservatively: meet of (then-branch with binding, no-else with no binding)
        // → empty. So no rewrite.
        assert!(rewrite_body(&body).is_none());
    }

    // CROSS-BB win: const set in BOTH branches with same value → propagates.
    #[test]
    fn propagates_when_both_branches_set_same_value() {
        // i32.const 1 cond; if; i32.const 5 set 0; else; i32.const 5 set 0; end;
        // local.get 0; drop; end-func.
        let body = [
            1, 1, 0x7F,
            0x41, 1,           // cond
            0x04, 0x40,        // if
            0x41, 5,
            0x21, 0,
            0x05,              // else
            0x41, 5,
            0x21, 0,
            0x0B,              // end if
            0x20, 0,           // local.get 0 — both branches bound to 5
            0x1A,
            0x0B,
        ];
        let out = rewrite_body(&body).expect("both branches agree → propagate");
        // local.get 0 should become i32.const 5.
        let last_ops: Vec<u8> = out.iter().rev().take(4).copied().collect();
        // Last 4 bytes: end-func, drop, the const value (5), const opcode (0x41) → reversed
        // Just check that 0x20 (local.get) is gone in favor of 0x41 (i32.const).
        assert!(out.windows(2).any(|w| w == [0x41, 5]),
            "expected an i32.const 5 in the output, got {:?}", out);
        assert!(!out.contains(&0x20),
            "local.get should have been rewritten away");
    }
}
