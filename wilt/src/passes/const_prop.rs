//! Per-body constant propagation through locals.
//!
//! Pattern: `<T.const N> ; local.set $a` makes `$a` hold `N`. While
//! that binding is live, every `local.get $a` is replaced with
//! `<T.const N>`. Once the binding holds, simplify_locals can mark
//! the set as dead (the local is no longer read), and vacuum can
//! delete the now-orphaned `T.const N ; drop` pair.
//!
//! Net byte savings per propagated chain (after the cascade):
//! ~`const_bytes + 1`. Modest per match; the corpus impact depends
//! on how many such patterns there are.
//!
//! Scope: single basic block. Bindings are cleared on any control-
//! flow opcode (block/loop/if/else/end/br/br_if/br_table/return/
//! unreachable/call/call_indirect), on any other write to the same
//! local, and on any opcode that writes to memory/global (could
//! affect side-effecting reads, though for locals strictly we only
//! need to clear on writes to the bound local). A future CFG-aware
//! version (M5 follow-up) would propagate across BB boundaries.
//!
//! Standalone — no hints required.

use crate::ir::BodyIr;
use crate::leb128;
use crate::mut_module::MutModule;

const OP_LOCAL_GET: u8 = 0x20;
const OP_LOCAL_SET: u8 = 0x21;
const OP_LOCAL_TEE: u8 = 0x22;
const OP_I32_CONST: u8 = 0x41;
const OP_I64_CONST: u8 = 0x42;
const OP_F32_CONST: u8 = 0x43;
const OP_F64_CONST: u8 = 0x44;

pub fn apply_mut(m: &mut MutModule<'_>) {
    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>)> = (0..m.num_bodies())
        .into_par_iter()
        .filter_map(|i| rewrite_body(m.body_bytes(i)).map(|b| (i, b)))
        .collect();
    for (i, b) in updates { m.set_body(i, b); }
}

/// Per-instruction snapshot of "local k holds the constant whose bytes
/// are stored as instr_bytes(idx)". When the binding is invalidated
/// we just remove the entry. None = no current binding for this local.
struct Bindings {
    /// (local_idx, source_const_instr_idx) — keep small + linear; per-body
    /// binding count rarely exceeds a handful.
    bindings: Vec<(u32, usize)>,
}

impl Bindings {
    fn new() -> Self { Self { bindings: Vec::new() } }
    fn get(&self, local: u32) -> Option<usize> {
        self.bindings.iter().rev().find(|(l, _)| *l == local).map(|(_, i)| *i)
    }
    fn set(&mut self, local: u32, source: usize) {
        self.bindings.retain(|(l, _)| *l != local);
        self.bindings.push((local, source));
    }
    fn invalidate(&mut self, local: u32) {
        self.bindings.retain(|(l, _)| *l != local);
    }
    fn clear(&mut self) { self.bindings.clear(); }
}

fn rewrite_body(body: &[u8]) -> Option<Vec<u8>> {
    let ir = BodyIr::new(body)?;
    let n = ir.instrs().len();
    if n < 3 { return None; }

    let mut bindings = Bindings::new();
    // Replacements: (instr_idx_to_replace, replacement_const_instr_idx).
    let mut rewrites: Vec<(usize, usize)> = Vec::new();

    let mut i = 0;
    let mut skip_next_set = false;
    while i < n {
        let it = ir.instrs()[i];
        match it.op {
            OP_I32_CONST | OP_I64_CONST | OP_F32_CONST | OP_F64_CONST => {
                // If followed by `local.set $a`, register the binding
                // and tell the next iteration NOT to invalidate.
                if i + 1 < n && ir.instrs()[i + 1].op == OP_LOCAL_SET {
                    if let Some(a) = local_idx(&ir, i + 1) {
                        bindings.set(a, i);
                        skip_next_set = true;
                    }
                }
            }
            OP_LOCAL_GET => {
                if let Some(a) = local_idx(&ir, i) {
                    if let Some(src) = bindings.get(a) {
                        rewrites.push((i, src));
                    }
                }
            }
            OP_LOCAL_SET | OP_LOCAL_TEE => {
                if skip_next_set && it.op == OP_LOCAL_SET {
                    skip_next_set = false;     // the just-bound set; leave binding live
                } else if let Some(a) = local_idx(&ir, i) {
                    bindings.invalidate(a);
                }
            }
            // Control flow / opaque calls clear all bindings.
            0x02 | 0x03 | 0x04 | 0x05 | 0x0B
            | 0x0C | 0x0D | 0x0E | 0x0F | 0x00
            | 0x10 | 0x11 => bindings.clear(),
            _ => {}
        }
        i += 1;
    }
    if rewrites.is_empty() { return None; }

    // Build edits: replace each rewritten local.get with the const bytes.
    let mut edits: Vec<(usize, usize, &[u8])> = Vec::new();
    for &(get_idx, src_idx) in &rewrites {
        let get = ir.instrs()[get_idx];
        let src = ir.instrs()[src_idx];
        let const_bytes = &body[src.start as usize..src.end() as usize];
        // Only commit if the substitution is no larger (we want a
        // strict no-grow contract). For typical small consts that
        // matches local.get on a small index — both 2 bytes.
        if const_bytes.len() > get.len as usize { continue; }
        edits.push((get.start as usize, get.len as usize, const_bytes));
    }
    if edits.is_empty() { return None; }

    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    edits.sort_by_key(|e| e.0);
    for (p, len, repl) in &edits {
        out.extend_from_slice(&body[cursor..*p]);
        out.extend_from_slice(repl);
        cursor = p + len;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

fn local_idx(ir: &BodyIr, i: usize) -> Option<u32> {
    let bytes = ir.instr_bytes(i);
    leb128::read_u32(&bytes[1..]).map(|(v, _)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propagates_const_through_local() {
        // body: 1 local of i32 ; i32.const 5 ; local.set 0 ; nop ;
        //       local.get 0 ; drop ; end
        let body = [
            1, 1, 0x7F,
            0x41, 5,
            0x21, 0,
            0x01,           // nop — no control flow, no clears
            0x20, 0,        // local.get 0 — should become i32.const 5
            0x1A,
            0x0B,
        ];
        let out = rewrite_body(&body).expect("should propagate");
        let expected = vec![
            1, 1, 0x7F,
            0x41, 5,
            0x21, 0,
            0x01,
            0x41, 5,        // local.get 0 → i32.const 5
            0x1A,
            0x0B,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn no_propagation_after_overwrite() {
        // local.set 0 (5) ; local.set 0 (7) ; local.get 0 — must NOT use 5
        let body = [
            1, 1, 0x7F,
            0x41, 5,
            0x21, 0,
            0x41, 7,
            0x21, 0,        // overwrite — clears binding
            0x20, 0,        // local.get 0 — rebinds via the const-7 set?
            0x1A,
            0x0B,
        ];
        let out = rewrite_body(&body).expect("should propagate from the SECOND const");
        // The second const-7+set rebinds; subsequent get becomes i32.const 7.
        let expected = vec![
            1, 1, 0x7F,
            0x41, 5,
            0x21, 0,
            0x41, 7,
            0x21, 0,
            0x41, 7,        // local.get 0 → i32.const 7
            0x1A,
            0x0B,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn binding_cleared_by_control_flow() {
        // local.set 0 (5) ; block ... end ; local.get 0 — block clears bindings
        let body = [
            1, 1, 0x7F,
            0x41, 5,
            0x21, 0,
            0x02, 0x40,
            0x0B,           // end of block — clears
            0x20, 0,        // local.get 0 — NO replacement
            0x1A,
            0x0B,
        ];
        assert!(rewrite_body(&body).is_none());
    }

    #[test]
    fn discriminates_locals() {
        // local.set 0 (5) ; local.set 1 (9) ; local.get 0 → const 5; local.get 1 → const 9
        let body = [
            1, 2, 0x7F,
            0x41, 5,
            0x21, 0,
            0x41, 9,
            0x21, 1,
            0x20, 0,        // → const 5
            0x1A,
            0x20, 1,        // → const 9
            0x1A,
            0x0B,
        ];
        let out = rewrite_body(&body).expect("should propagate both");
        let expected = vec![
            1, 2, 0x7F,
            0x41, 5,
            0x21, 0,
            0x41, 9,
            0x21, 1,
            0x41, 5,
            0x1A,
            0x41, 9,
            0x1A,
            0x0B,
        ];
        assert_eq!(out, expected);
    }
}
