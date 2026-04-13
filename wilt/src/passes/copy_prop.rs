//! Per-body copy propagation through locals — CFG-aware.
//!
//! Forward dataflow over `CfgIr`. Lattice: for each local, either
//! "unknown" (no binding) or "this local is currently an alias of
//! source-local Y" (i.e. `$a := $b`).
//!
//! Per-BB transfer:
//!   `local.get $b ; local.set $a`  → bind $a := $b.
//!   `local.set $a` (any other source) → clear $a.
//!   `local.tee $a`                  → clear $a.
//!   any write to $b (the source)    → invalidate every binding whose
//!                                     source IS $b (alias chain breaks).
//!
//! Replacement: at each `local.get $a` where $a is bound to $b,
//! rewrite to `local.get $b` provided the LEB encoding of $b is no
//! longer than $a's. The rewrite doesn't directly save bytes — it
//! makes $a a dead local (no more readers), which simplify_locals
//! then deletes.
//!
//! Runs after const_prop in the pipeline. Standalone — no hints.

use std::collections::HashMap;

use crate::ir::{BodyIr, CfgIr};
use crate::leb128;
use crate::mut_module::MutModule;
use crate::opcode::{self as opc, InstrIter};

const OP_LOCAL_GET: u8 = 0x20;
const OP_LOCAL_SET: u8 = 0x21;
const OP_LOCAL_TEE: u8 = 0x22;

type Bindings = HashMap<u32, u32>;     // dest_local → source_local

pub fn apply_mut(m: &mut MutModule<'_>) {
    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>)> = (0..m.num_bodies())
        .into_par_iter()
        .filter_map(|i| rewrite_body(m.body_bytes(i)).map(|b| (i, b)))
        .collect();
    for (i, b) in updates { m.set_body(i, b); }
}

fn rewrite_body(body: &[u8]) -> Option<Vec<u8>> {
    if !has_get_then_set(body) { return None; }

    let ir = BodyIr::new(body)?;
    let cfg = CfgIr::build(&ir)?;
    let nbb = cfg.blocks.len();
    if nbb == 0 || ir.instrs().is_empty() { return None; }

    let mut preds: Vec<Vec<u32>> = vec![Vec::new(); nbb];
    for (bi, bb) in cfg.blocks.iter().enumerate() {
        for edge in &bb.successors {
            preds[edge.target as usize].push(bi as u32);
        }
    }

    let mut bb_out: Vec<Bindings> = vec![HashMap::new(); nbb];
    for _ in 0..1_000 {
        let mut changed = false;
        for bi in 0..nbb {
            let in_state = meet_in(&preds[bi], &bb_out);
            let new_out = transfer(&ir, &cfg.blocks[bi], in_state);
            if new_out != bb_out[bi] {
                bb_out[bi] = new_out;
                changed = true;
            }
        }
        if !changed { break; }
    }

    let mut rewrites: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    for (bi, bb) in cfg.blocks.iter().enumerate() {
        let in_state = meet_in(&preds[bi], &bb_out);
        record_rewrites(&ir, bb, in_state, &mut rewrites);
    }
    if rewrites.is_empty() { return None; }
    rewrites.sort_by_key(|e| e.0);

    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for (p, len, repl) in &rewrites {
        out.extend_from_slice(&body[cursor..*p]);
        out.extend_from_slice(repl);
        cursor = p + len;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

fn meet_in(preds: &[u32], bb_out: &[Bindings]) -> Bindings {
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
    let mut last_get_local: Option<u32> = None;
    for k in bb.start_instr..bb.end_instr {
        let i = k as usize;
        let op = ir.instrs()[i].op;
        match op {
            OP_LOCAL_GET => {
                last_get_local = local_idx(ir, i);
            }
            OP_LOCAL_SET => {
                if let Some(a) = local_idx(ir, i) {
                    if let Some(b) = last_get_local.filter(|b| *b != a) {
                        state.insert(a, b);
                    } else {
                        state.remove(&a);
                    }
                    // Anything aliased to $a is now stale (a's value changed).
                    state.retain(|_, src| *src != a);
                }
                last_get_local = None;
            }
            OP_LOCAL_TEE => {
                if let Some(a) = local_idx(ir, i) {
                    state.remove(&a);
                    state.retain(|_, src| *src != a);
                }
                last_get_local = None;
            }
            _ => { last_get_local = None; }
        }
    }
    state
}

fn record_rewrites(
    ir: &BodyIr, bb: &crate::ir::BasicBlock, in_state: Bindings,
    out: &mut Vec<(usize, usize, Vec<u8>)>,
) {
    let mut state = in_state;
    let mut last_get_local: Option<u32> = None;
    for k in bb.start_instr..bb.end_instr {
        let i = k as usize;
        let it = ir.instrs()[i];
        match it.op {
            OP_LOCAL_GET => {
                if let Some(a) = local_idx(ir, i) {
                    if let Some(&b) = state.get(&a) {
                        // Replace local.get $a with local.get $b iff
                        // the encoding is not longer.
                        let mut repl = Vec::with_capacity(1 + 5);
                        repl.push(OP_LOCAL_GET);
                        leb128::write_u32(&mut repl, b);
                        if repl.len() <= it.len as usize {
                            out.push((it.start as usize, it.len as usize, repl));
                        }
                    }
                    last_get_local = Some(a);
                } else {
                    last_get_local = None;
                }
            }
            OP_LOCAL_SET => {
                if let Some(a) = local_idx(ir, i) {
                    if let Some(b) = last_get_local.filter(|b| *b != a) {
                        state.insert(a, b);
                    } else {
                        state.remove(&a);
                    }
                    state.retain(|_, src| *src != a);
                }
                last_get_local = None;
            }
            OP_LOCAL_TEE => {
                if let Some(a) = local_idx(ir, i) {
                    state.remove(&a);
                    state.retain(|_, src| *src != a);
                }
                last_get_local = None;
            }
            _ => { last_get_local = None; }
        }
    }
}

fn local_idx(ir: &BodyIr, i: usize) -> Option<u32> {
    leb128::read_u32(&ir.instr_bytes(i)[1..]).map(|(v, _)| v)
}

/// Cheap precheck: at minimum we need a get-then-set anywhere in the
/// body for a binding to be created, AND another local.get later for
/// the rewrite to be useful. The simpler "any get and any set" is a
/// good enough negative filter.
fn has_get_then_set(body: &[u8]) -> bool {
    let Some(start) = opc::skip_locals(body) else { return false };
    let mut iter = InstrIter::new(body, start);
    let mut has_get = false;
    let mut has_set = false;
    while let Some((p, _)) = iter.next() {
        match body[p] {
            OP_LOCAL_GET => has_get = true,
            OP_LOCAL_SET => has_set = true,
            _ => {}
        }
        if has_get && has_set { return true; }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_within_basic_block() {
        // local.get $b; local.set $a; nop; local.get $a → local.get $b.
        let body = [
            1, 2, 0x7F,
            0x20, 1,           // local.get 1 ($b)
            0x21, 0,           // local.set 0 ($a := $b)
            0x01,              // nop
            0x20, 0,           // local.get 0 ($a) — rewrite to local.get 1
            0x1A,
            0x0B,
        ];
        let out = rewrite_body(&body).expect("should propagate");
        assert_eq!(out, vec![
            1, 2, 0x7F,
            0x20, 1,
            0x21, 0,
            0x01,
            0x20, 1,           // rewritten
            0x1A,
            0x0B,
        ]);
    }

    #[test]
    fn invalidates_when_source_overwritten() {
        // local.get 1; local.set 0; local.set 1 (overwrite source);
        // local.get 0 — must NOT rewrite to local.get 1 (source stale).
        let body = [
            1, 2, 0x7F,
            0x20, 1,
            0x21, 0,           // 0 := 1
            0x41, 99,
            0x21, 1,           // 1 overwritten
            0x20, 0,           // local.get 0 — should NOT become get 1
            0x1A,
            0x0B,
        ];
        assert!(rewrite_body(&body).is_none());
    }

    #[test]
    fn no_rewrite_for_self_alias() {
        // local.get 0; local.set 0 — no actual aliasing, just identity.
        let body = [
            1, 1, 0x7F,
            0x20, 0,
            0x21, 0,
            0x20, 0,
            0x1A,
            0x0B,
        ];
        assert!(rewrite_body(&body).is_none());
    }
}
