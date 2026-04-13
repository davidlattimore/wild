//! Trivial function inlining.
//!
//! Replace `call f` with the callee's body when the callee matches a
//! strictly-narrow "trivial" pattern, small enough that inlining
//! always-or-almost-always shrinks the module (DCE on the next
//! fixpoint iteration removes the now-orphaned callee).
//!
//! Patterns recognised:
//!   * Empty — callee has signature `() -> ()`, no locals, body is
//!     just `end`. `call f` becomes nothing.
//!   * Identity — signature `(T) -> T`, no locals, body is
//!     `local.get 0 ; end`. `call f` leaves the arg on the stack;
//!     delete the call.
//!   * Const — signature `() -> T`, no locals, body is a single
//!     `T.const N ; end`. `call f` becomes `T.const N` (only when
//!     that's no larger than the `call f` bytes — avoids growth).
//!
//! Not touched: imported functions, `ref.func` references, callees
//! with locals or control flow. The pass runs on a MutModule so
//! unchanged bodies never allocate.

use crate::block_walker::{ModuleSigs, SigResolver};
use crate::leb128;
use crate::module::WasmModule;
use crate::mut_module::MutModule;
use crate::opcode::{self, InstrIter};

pub fn apply_mut(m: &mut MutModule<'_>) {
    let input = m.input();
    let Ok(wm) = WasmModule::parse(input) else { return };
    let Some(sigs) = ModuleSigs::from_module(&wm) else { return };

    let num_imports = m.facts.num_func_imports;
    let num_bodies = m.num_bodies();

    // Classify each defined function's body.
    let mut trivial: Vec<Option<Trivial>> = Vec::with_capacity(num_bodies);
    for i in 0..num_bodies {
        let body = m.body_bytes(i);
        let sig = sigs.func_sig(num_imports + i as u32).unwrap_or((0, 0));
        trivial.push(classify(body, sig));
    }

    // Fast-path: if no callees are trivial, nothing to do.
    if trivial.iter().all(Option::is_none) { return; }

    // Rewrite every caller body in parallel — bodies are independent,
    // and `trivial` + `num_imports` are read-only.
    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>)> = (0..num_bodies)
        .into_par_iter()
        .filter_map(|i| rewrite_body(m.body_bytes(i), &trivial, num_imports).map(|b| (i, b)))
        .collect();
    for (i, b) in updates { m.set_body(i, b); }
}

#[derive(Clone)]
enum Trivial {
    /// Call is a no-op; delete the `call f` bytes entirely.
    DeleteCall,
    /// Replace `call f` with these bytes (a single constant instruction).
    ReplaceWithConst(Vec<u8>),
}

fn classify(body: &[u8], sig: (u32, u32)) -> Option<Trivial> {
    // Must have no locals.
    let (groups, off) = leb128::read_u32(body)?;
    if groups != 0 { return None; }

    // Case: body is just `end`.
    if body.get(off) == Some(&0x0B) && off + 1 == body.len() {
        if sig == (0, 0) {
            return Some(Trivial::DeleteCall);
        }
        return None;
    }

    // Otherwise: exactly one instruction followed by end.
    let len = opcode::instr_len(body, off)?;
    let op_start = off;
    let op_end = off + len;
    if body.get(op_end) != Some(&0x0B) { return None; }
    if op_end + 1 != body.len() { return None; }

    let op = body[op_start];
    match op {
        // local.get 0 as identity: needs (T) -> T.
        0x20 => {
            let (n, _) = leb128::read_u32(&body[op_start + 1..])?;
            if n == 0 && sig.0 == 1 && sig.1 == 1 {
                return Some(Trivial::DeleteCall);
            }
            None
        }
        // *.const: (nothing) -> T.
        0x41 | 0x42 | 0x43 | 0x44 => {
            if sig.0 == 0 && sig.1 == 1 {
                return Some(Trivial::ReplaceWithConst(
                    body[op_start..op_end].to_vec(),
                ));
            }
            None
        }
        _ => None,
    }
}

fn rewrite_body(
    body: &[u8],
    trivial: &[Option<Trivial>],
    num_imports: u32,
) -> Option<Vec<u8>> {
    let instrs_start = opcode::skip_locals(body)?;
    let mut edits: Vec<(usize, usize, &[u8])> = Vec::new();

    let mut iter = InstrIter::new(body, instrs_start);
    while let Some((p, len)) = iter.next() {
        if body[p] != 0x10 { continue; }    // call
        let Some((f, _)) = leb128::read_u32(&body[p + 1..]) else { continue };
        if f < num_imports { continue; }
        let local_idx = (f - num_imports) as usize;
        let Some(Some(t)) = trivial.get(local_idx) else { continue };
        match t {
            Trivial::DeleteCall => edits.push((p, len, &[])),
            Trivial::ReplaceWithConst(bytes) => {
                if bytes.len() <= len {
                    edits.push((p, len, bytes.as_slice()));
                }
            }
        }
    }
    if iter.failed() { return None; }
    if edits.is_empty() { return None; }

    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for (p, len, replacement) in &edits {
        out.extend_from_slice(&body[cursor..*p]);
        out.extend_from_slice(replacement);
        cursor = p + len;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_empty() {
        let body = [0, 0x0B];
        assert!(matches!(classify(&body, (0, 0)), Some(Trivial::DeleteCall)));
        assert!(classify(&body, (0, 1)).is_none());
    }

    #[test]
    fn classifies_identity() {
        let body = [0, 0x20, 0, 0x0B];
        assert!(matches!(classify(&body, (1, 1)), Some(Trivial::DeleteCall)));
        // Wrong sig.
        assert!(classify(&body, (2, 1)).is_none());
        // Wrong local index.
        let body2 = [0, 0x20, 1, 0x0B];
        assert!(classify(&body2, (1, 1)).is_none());
    }

    #[test]
    fn classifies_const() {
        // i32.const 42.
        let body = [0, 0x41, 42, 0x0B];
        let t = classify(&body, (0, 1)).expect("should classify");
        match t {
            Trivial::ReplaceWithConst(b) => assert_eq!(b, vec![0x41, 42]),
            _ => panic!("expected const"),
        }
    }

    #[test]
    fn rejects_nonzero_locals() {
        // 1 group of 1 local → has locals → not trivial.
        let body = [1, 1, 0x7F, 0x0B];
        assert!(classify(&body, (0, 0)).is_none());
    }

    #[test]
    fn rewrites_call_to_empty_as_delete() {
        // Caller body: nop ; call 0 ; end. Callee 0 (defined) is Empty.
        let body = [0, 0x01, 0x10, 0, 0x0B];
        let trivial = vec![Some(Trivial::DeleteCall)];
        let out = rewrite_body(&body, &trivial, 0).expect("should rewrite");
        assert_eq!(out, vec![0, 0x01, 0x0B]);
    }

    #[test]
    fn rewrites_call_to_const() {
        // Caller: call 0 ; drop ; end. Callee 0 is i32.const 7.
        let body = [0, 0x10, 0, 0x1A, 0x0B];
        let trivial = vec![Some(Trivial::ReplaceWithConst(vec![0x41, 7]))];
        let out = rewrite_body(&body, &trivial, 0).expect("should rewrite");
        assert_eq!(out, vec![0, 0x41, 7, 0x1A, 0x0B]);
    }

    #[test]
    fn skips_imports() {
        // Call target 0 is an import (num_imports = 1). No trivial slot
        // for it. Defined func 0 not called. Nothing to do.
        let body = [0, 0x10, 0, 0x0B];
        let trivial = vec![Some(Trivial::DeleteCall)];
        assert!(rewrite_body(&body, &trivial, 1).is_none());
    }
}
