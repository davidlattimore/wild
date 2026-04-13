//! Dead-store elimination for locals.
//!
//! Replaces a `local.set X` whose stored value is never read before
//! being overwritten (or before the function ends) with `drop`. Stack
//! effect is preserved (both pop one value).
//!
//! M4: built on `wilt::ir::BodyIr` so the forward-scan can step past
//! nested blocks/loops/ifs whose bodies don't read the local. The
//! previous version bailed on every block opcode; this one skips them
//! when safe and continues scanning.
//!
//! Coverage is still single-basic-block when the `local.set` is itself
//! inside a block (we bail when the scan exits the set's enclosing
//! block). Full cross-CFG-block reaching defs lands with M5 (CFG layer).

use crate::ir::BodyIr;
use crate::leb128;
use crate::mut_module::MutModule;

const OP_UNREACHABLE: u8 = 0x00;
const OP_BLOCK: u8 = 0x02;
const OP_LOOP: u8 = 0x03;
const OP_IF: u8 = 0x04;
const OP_ELSE: u8 = 0x05;
const OP_END: u8 = 0x0B;
const OP_BR: u8 = 0x0C;
const OP_BR_IF: u8 = 0x0D;
const OP_BR_TABLE: u8 = 0x0E;
const OP_RETURN: u8 = 0x0F;
const OP_DROP: u8 = 0x1A;
const OP_LOCAL_GET: u8 = 0x20;
const OP_LOCAL_SET: u8 = 0x21;
const OP_LOCAL_TEE: u8 = 0x22;

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
    if ir.instrs().is_empty() { return None; }

    let mut dead: Vec<(usize, usize)> = Vec::new();
    for i in 0..ir.instrs().len() {
        let it = ir.instrs()[i];
        if it.op != OP_LOCAL_SET { continue; }
        let Some(x) = ir.imm_u32(i) else { continue };
        if classify(&ir, i, x) == Verdict::Dead {
            dead.push((it.start as usize, it.len as usize));
        }
    }
    if dead.is_empty() { return None; }

    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for &(p, len) in &dead {
        out.extend_from_slice(&body[cursor..p]);
        out.push(OP_DROP);
        cursor = p + len;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

#[derive(PartialEq, Eq)]
enum Verdict { Dead, Alive, Bail }

/// Forward-scan from instruction `i` (a `local.set X`) to determine
/// whether the stored value of local X is ever read before being
/// overwritten or before the function exits. Steps past nested
/// block/loop/if when their bodies don't read X.
fn classify(ir: &BodyIr, i: usize, x: u32) -> Verdict {
    let n = ir.instrs().len();
    let mut j = i + 1;
    while j < n {
        let it = ir.instrs()[j];
        match it.op {
            OP_LOCAL_GET => {
                if read_idx(ir, j) == Some(x) { return Verdict::Alive; }
                j += 1;
            }
            OP_LOCAL_SET | OP_LOCAL_TEE => {
                if read_idx(ir, j) == Some(x) { return Verdict::Dead; }
                j += 1;
            }
            OP_BLOCK | OP_LOOP | OP_IF => {
                let Some(end_idx) = matching_end(ir, j) else { return Verdict::Bail; };
                if range_reads(ir, j + 1..end_idx, x) {
                    // Conservative: a get_X inside might read our value
                    // on some path. Don't try to prove otherwise here —
                    // M5 (CFG) will handle that.
                    return Verdict::Alive;
                }
                j = end_idx + 1;
            }
            OP_END => {
                // Function-body end is the only "bare" end we expect to
                // see at the scan's outer level. Anything else means
                // we're scanning from inside an enclosing block — bail
                // because the value can still be read in the parent.
                return if j == n - 1 { Verdict::Dead } else { Verdict::Bail };
            }
            OP_BR | OP_BR_IF | OP_BR_TABLE => return Verdict::Bail,
            OP_RETURN | OP_UNREACHABLE => return Verdict::Dead,
            OP_ELSE => return Verdict::Bail,
            _ => j += 1,
        }
    }
    Verdict::Dead
}

fn read_idx(ir: &BodyIr, i: usize) -> Option<u32> {
    leb128::read_u32(&ir.instr_bytes(i)[1..]).map(|(v, _)| v)
}

fn matching_end(ir: &BodyIr, open_idx: usize) -> Option<usize> {
    let n = ir.instrs().len();
    let mut depth = 1;
    let mut k = open_idx + 1;
    while k < n {
        match ir.instrs()[k].op {
            OP_BLOCK | OP_LOOP | OP_IF => depth += 1,
            OP_END => {
                depth -= 1;
                if depth == 0 { return Some(k); }
            }
            _ => {}
        }
        k += 1;
    }
    None
}

fn range_reads(ir: &BodyIr, range: std::ops::Range<usize>, x: u32) -> bool {
    for i in range {
        if ir.instrs()[i].op == OP_LOCAL_GET && read_idx(ir, i) == Some(x) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // (func (local i32)
        //   i32.const 5
        //   local.set 0     ;; old pass bailed; new pass skips past block
        //   block
        //   end
        // )
        let body = [
            1, 1, 0x7F,
            0x41, 5,
            0x21, 0,
            0x02, 0x40,    // block empty
            0x0B,          // end block
            0x0B,          // end func
        ];
        let out = rewrite_body(&body).expect("v2 should detect dead set across empty block");
        let expected = vec![
            1, 1, 0x7F,
            0x41, 5,
            0x1A,          // local.set 0 → drop
            0x02, 0x40,
            0x0B,
            0x0B,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn skips_block_that_writes_unrelated_local() {
        // Block body contains local.tee 1 — doesn't read local 0.
        let body = [
            1, 2, 0x7F,
            0x41, 5,
            0x21, 0,
            0x02, 0x40,
            0x41, 9,
            0x22, 1,       // local.tee 1 — doesn't read local 0
            0x1A,
            0x0B,
            0x0B,
        ];
        let out = rewrite_body(&body).expect("should skip past block touching unrelated local");
        // local.set 0 → drop. Block contents preserved.
        assert_eq!(out[5], 0x1A);
    }

    #[test]
    fn keeps_set_when_block_reads_local() {
        let body = [
            1, 1, 0x7F,
            0x41, 5,
            0x21, 0,        // set local 0
            0x02, 0x40,
            0x20, 0,        // get local 0 inside block — keeps value alive
            0x1A,
            0x0B,
            0x0B,
        ];
        assert!(rewrite_body(&body).is_none());
    }

    #[test]
    fn bails_on_br() {
        // br is a barrier we can't reason about without CFG.
        let body = [
            1, 1, 0x7F,
            0x02, 0x40,
            0x41, 5,
            0x21, 0,
            0x0C, 0,        // br 0 — unknown control flow target
            0x0B,
            0x0B,
        ];
        // The set is inside the block; bail at br anyway.
        assert!(rewrite_body(&body).is_none());
    }

    #[test]
    fn return_terminates_function() {
        let body = [
            1, 1, 0x7F,
            0x41, 5,
            0x21, 0,
            0x0F,           // return — value never read
            0x0B,
        ];
        let out = rewrite_body(&body).expect("set before return is dead");
        // local.set 0 replaced with drop; return + end preserved.
        assert_eq!(out[5], 0x1A);
    }
}
