//! Dead-store elimination for locals — backward liveness over the CFG.
//!
//! Replaces every `local.set X` whose stored value is never subsequently
//! read with `drop` (same stack effect, smaller). Catches:
//!   * dead stores in straight-line code (the original M4 case);
//!   * dead stores split by control flow (then-branch sets, else-branch sets,
//!     sets-before-loop-back-edge, etc.);
//!   * sets followed by `return` / `unreachable` (function exits before any subsequent read).
//!
//! Mechanism: standard backward dataflow on `CfgIr`. Per BB, compute
//!   use[BB]  = locals read before being killed in BB
//!   kill[BB] = locals written in BB (set or tee)
//! Iterate to fixpoint:
//!   live_out[BB] = ∪ live_in[succ]   for succ in successors[BB]
//!   live_in[BB]  = use[BB] ∪ (live_out[BB] − kill[BB])
//! Then for each `local.set X`, walk its BB backward from `live_out`
//! tracking liveness; the set is dead iff X ∉ live just after it.
//!
//! Falls back to no-op when BodyIr/CfgIr can't be built (unknown opcodes).

use crate::ir::BodyIr;
use crate::ir::CfgIr;
use crate::leb128;
use crate::mut_module::MutModule;
use crate::opcode::InstrIter;
use crate::opcode::{self as opc};
use std::collections::HashSet;

const OP_DROP: u8 = 0x1A;
const OP_LOCAL_GET: u8 = 0x20;
const OP_LOCAL_SET: u8 = 0x21;
const OP_LOCAL_TEE: u8 = 0x22;

pub fn apply_mut(m: &mut MutModule<'_>) {
    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>, crate::provenance::BodyEdits)> = (0..m.num_bodies())
        .into_par_iter()
        .filter_map(|i| rewrite_body_with_edits(m.body_bytes(i)).map(|(b, e)| (i, b, e)))
        .collect();
    for (i, b, e) in updates {
        m.set_body_with_edits(i, b, e);
    }
}

#[allow(dead_code)]
fn rewrite_body(body: &[u8]) -> Option<Vec<u8>> {
    rewrite_body_with_edits(body).map(|(b, _)| b)
}

fn rewrite_body_with_edits(body: &[u8]) -> Option<(Vec<u8>, crate::provenance::BodyEdits)> {
    // Bail-early: if no local.set in the body, there's nothing for us
    // to mark dead. Avoids the cost of building BodyIr + CfgIr +
    // running dataflow on bodies that pure passthrough / arithmetic.
    if !has_local_set(body) {
        return None;
    }

    let ir = BodyIr::new(body)?;
    let cfg = CfgIr::build(&ir)?;
    let nbb = cfg.blocks.len();
    if nbb == 0 || ir.instrs().is_empty() {
        return None;
    }

    // Per-BB use / kill sets (forward-scan each BB once).
    let mut use_in: Vec<HashSet<u32>> = vec![HashSet::new(); nbb];
    let mut kill_in: Vec<HashSet<u32>> = vec![HashSet::new(); nbb];
    for (bi, bb) in cfg.blocks.iter().enumerate() {
        let mut killed: HashSet<u32> = HashSet::new();
        let mut used: HashSet<u32> = HashSet::new();
        for k in bb.start_instr..bb.end_instr {
            let it = ir.instrs()[k as usize];
            match it.op {
                OP_LOCAL_GET => {
                    if let Some(x) = local_idx(&ir, k as usize) {
                        if !killed.contains(&x) {
                            used.insert(x);
                        }
                    }
                }
                OP_LOCAL_SET | OP_LOCAL_TEE => {
                    if let Some(x) = local_idx(&ir, k as usize) {
                        killed.insert(x);
                    }
                }
                _ => {}
            }
        }
        use_in[bi] = used;
        kill_in[bi] = killed;
    }

    // Backward dataflow to fixpoint. Loop counter caps pathological cases.
    let mut live_in: Vec<HashSet<u32>> = vec![HashSet::new(); nbb];
    let mut live_out: Vec<HashSet<u32>> = vec![HashSet::new(); nbb];
    for _ in 0..1_000 {
        let mut changed = false;
        for bi in (0..nbb).rev() {
            let mut new_out: HashSet<u32> = HashSet::new();
            for edge in &cfg.blocks[bi].successors {
                for &x in &live_in[edge.target as usize] {
                    new_out.insert(x);
                }
            }
            let mut new_in = use_in[bi].clone();
            for &x in &new_out {
                if !kill_in[bi].contains(&x) {
                    new_in.insert(x);
                }
            }
            if new_in != live_in[bi] {
                live_in[bi] = new_in;
                changed = true;
            }
            if new_out != live_out[bi] {
                live_out[bi] = new_out;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Walk each BB backward; mark each `local.set X` dead iff X is not
    // live at the set's exit.
    let mut dead: Vec<(usize, usize)> = Vec::new();
    for (bi, bb) in cfg.blocks.iter().enumerate() {
        let mut live = live_out[bi].clone();
        for k in (bb.start_instr..bb.end_instr).rev() {
            let it = ir.instrs()[k as usize];
            match it.op {
                OP_LOCAL_GET => {
                    if let Some(x) = local_idx(&ir, k as usize) {
                        live.insert(x);
                    }
                }
                OP_LOCAL_SET => {
                    if let Some(x) = local_idx(&ir, k as usize) {
                        if !live.contains(&x) {
                            dead.push((it.start as usize, it.len as usize));
                        }
                        live.remove(&x);
                    }
                }
                OP_LOCAL_TEE => {
                    // tee writes X without reading old X. Don't flag dead
                    // (the value remains on stack regardless).
                    if let Some(x) = local_idx(&ir, k as usize) {
                        live.remove(&x);
                    }
                }
                _ => {}
            }
        }
    }
    if dead.is_empty() {
        return None;
    }
    dead.sort_by_key(|d| d.0);

    // Replace each dead local.set with `drop` (same stack effect).
    let mut out = Vec::with_capacity(body.len());
    let mut edits = crate::provenance::BodyEdits::identity();
    let mut cursor = 0;
    for (p, len) in &dead {
        out.extend_from_slice(&body[cursor..*p]);
        let out_start = out.len() as u32;
        out.push(OP_DROP);
        edits.push(
            crate::provenance::Edit::subst(*p as u32, *len as u32, out_start, 1),
            None,
        );
        cursor = p + len;
    }
    out.extend_from_slice(&body[cursor..]);
    Some((out, edits))
}

fn local_idx(ir: &BodyIr, i: usize) -> Option<u32> {
    leb128::read_u32(&ir.instr_bytes(i)[1..]).map(|(v, _)| v)
}

/// Quick byte-scan: does the body's instruction stream contain at
/// least one `local.set` opcode? Cheaper than building IR.
fn has_local_set(body: &[u8]) -> bool {
    let Some(start) = opc::skip_locals(body) else {
        return false;
    };
    let mut iter = InstrIter::new(body, start);
    while let Some((p, _)) = iter.next() {
        if body[p] == OP_LOCAL_SET {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // Existing M4 cases — must still pass.
    #[test]
    fn dead_set_before_end() {
        let body = [1, 1, 0x7F, 0x41, 5, 0x21, 0, 0x0B];
        let out = rewrite_body(&body).unwrap();
        assert_eq!(out, vec![1, 1, 0x7F, 0x41, 5, 0x1A, 0x0B]);
    }

    #[test]
    fn live_set_read_after() {
        let body = [1, 1, 0x7F, 0x41, 5, 0x21, 0, 0x20, 0, 0x1A, 0x0B];
        assert!(rewrite_body(&body).is_none());
    }

    #[test]
    fn dead_set_overwritten_by_set() {
        let body = [1, 1, 0x7F, 0x41, 5, 0x21, 0, 0x41, 7, 0x21, 0, 0x0B];
        let out = rewrite_body(&body).unwrap();
        assert_eq!(out, vec![1, 1, 0x7F, 0x41, 5, 0x1A, 0x41, 7, 0x1A, 0x0B]);
    }

    #[test]
    fn different_local_doesnt_keep_set_alive() {
        let body = [1, 2, 0x7F, 0x41, 5, 0x21, 0, 0x20, 1, 0x1A, 0x0B];
        let out = rewrite_body(&body).unwrap();
        assert_eq!(out, vec![1, 2, 0x7F, 0x41, 5, 0x1A, 0x20, 1, 0x1A, 0x0B]);
    }

    #[test]
    fn skips_past_empty_block() {
        let body = [1, 1, 0x7F, 0x41, 5, 0x21, 0, 0x02, 0x40, 0x0B, 0x0B];
        let out = rewrite_body(&body).expect("dead set with no later read");
        assert_eq!(out[5], 0x1A);
    }

    #[test]
    fn keeps_set_when_block_reads_local() {
        let body = [
            1, 1, 0x7F, 0x41, 5, 0x21, 0, 0x02, 0x40, 0x20, 0, 0x1A, 0x0B, 0x0B,
        ];
        assert!(rewrite_body(&body).is_none());
    }

    #[test]
    fn return_terminates_function() {
        let body = [1, 1, 0x7F, 0x41, 5, 0x21, 0, 0x0F, 0x0B];
        let out = rewrite_body(&body).expect("set before return is dead");
        assert_eq!(out[5], 0x1A);
    }

    // CROSS-BB CASES — the new wins over single-BB scan.

    #[test]
    fn dead_set_inside_then_branch() {
        // (func (local i32)
        //   i32.const 1
        //   if
        //     i32.const 5
        //     local.set 0    ;; DEAD — never read in then-branch or after
        //   end
        // )
        let body = [
            1, 1, 0x7F, 0x41, 1, 0x04, 0x40, 0x41, 5, 0x21, 0, // dead local.set 0
            0x0B, 0x0B,
        ];
        let out = rewrite_body(&body).expect("set inside then-branch with no later read");
        // local.set 0 → drop.
        assert_eq!(
            out,
            vec![1, 1, 0x7F, 0x41, 1, 0x04, 0x40, 0x41, 5, 0x1A, 0x0B, 0x0B,]
        );
    }

    #[test]
    fn live_set_inside_then_branch_read_after_if() {
        // (func (local i32)
        //   i32.const 1
        //   if
        //     i32.const 5
        //     local.set 0    ;; LIVE — read after the if
        //   end
        //   local.get 0
        //   drop
        // )
        let body = [
            1, 1, 0x7F, 0x41, 1, 0x04, 0x40, 0x41, 5, 0x21, 0, 0x0B, 0x20,
            0, // read AFTER the if
            0x1A, 0x0B,
        ];
        assert!(rewrite_body(&body).is_none());
    }

    #[test]
    fn dead_set_in_loop_body_no_subsequent_read() {
        // (func (local i32)
        //   loop
        //     i32.const 5
        //     local.set 0    ;; killed each iteration; never read
        //     br 0
        //   end
        // )
        let body = [
            1, 1, 0x7F, 0x03, 0x40, 0x41, 5, 0x21, 0, // never read
            0x0C, 0, 0x0B, 0x0B,
        ];
        let out = rewrite_body(&body).expect("set in loop with no read is dead");
        assert_eq!(out[7], 0x1A);
    }
}
