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
use crate::linker_hints::LinkerHints;
use crate::module::WasmModule;
use crate::mut_module::MutModule;
use crate::opcode::{self, InstrIter};

pub fn apply_mut(m: &mut MutModule<'_>) {
    apply_mut_with_hints(m, None)
}

pub fn apply_mut_with_hints(m: &mut MutModule<'_>, hints: Option<&dyn LinkerHints>) {
    let input = m.input();
    let Ok(mut wm) = WasmModule::parse(input) else { return };
    wm.ensure_function_bodies_parsed();
    let Some(sigs) = ModuleSigs::from_module(&wm) else { return };

    let num_imports = m.facts.num_func_imports;
    let num_bodies = m.num_bodies();

    // Count call sites per defined function — needed so we can promote
    // a single-call-site `() -> ()` callee to ReplaceWithBody (M6) without
    // bloating the module on multi-call functions.
    let call_counts = count_call_sites(m, num_imports, num_bodies);

    // Classify each defined function's body. ReplaceWithBody requires
    // BOTH unique-caller AND closed-world is_internal — without the
    // latter we can't be sure DCE will reap the orphaned callee, and
    // pasting bytes without removing the original grows the module.
    let mut trivial: Vec<Option<Trivial>> = Vec::with_capacity(num_bodies);
    for i in 0..num_bodies {
        let body = m.body_bytes(i);
        let abs_idx = num_imports + i as u32;
        let sig = sigs.func_sig(abs_idx).unwrap_or((0, 0));
        let is_unique = call_counts.get(i).copied() == Some(1);
        let inline_safe = is_unique && hints.is_some_and(|h| h.is_internal(abs_idx));
        trivial.push(classify(body, sig, inline_safe));
    }

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
    /// Inline the entire callee body in place of `call f`. M6 — only
    /// fires when the callee has exactly one caller, so the caller bytes
    /// grow by ~the callee's body bytes but the callee is then orphaned
    /// and DCE'd next iteration. Net shrink.
    ReplaceWithBody(Vec<u8>),
}

/// Maximum bytes we'll inline-paste a body for the unique-caller case.
/// Larger bodies get diminishing returns vs. binary size; cap to keep
/// behaviour predictable.
const MAX_INLINE_BODY_BYTES: usize = 64;

fn classify(body: &[u8], sig: (u32, u32), is_unique_caller: bool) -> Option<Trivial> {
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

    // Try the one-instruction patterns first (Empty / Identity / Const).
    let len = opcode::instr_len(body, off)?;
    let op_start = off;
    let op_end = off + len;
    let one_instr_body = body.get(op_end) == Some(&0x0B) && op_end + 1 == body.len();

    if one_instr_body {
        let op = body[op_start];
        match op {
            0x20 => {
                let (n, _) = leb128::read_u32(&body[op_start + 1..])?;
                if n == 0 && sig.0 == 1 && sig.1 == 1 {
                    return Some(Trivial::DeleteCall);
                }
            }
            0x41 | 0x42 | 0x43 | 0x44 => {
                if sig.0 == 0 && sig.1 == 1 {
                    return Some(Trivial::ReplaceWithConst(
                        body[op_start..op_end].to_vec(),
                    ));
                }
            }
            _ => {}
        }
    }

    // M6 — single-caller `() -> ()` body inlining. Conservative pre-checks:
    //   * exactly one caller (else bloat),
    //   * sig is `() -> ()` (no args to materialise, no result on stack),
    //   * no locals references in the body (callee body would clash with
    //     caller's locals if pasted verbatim — this guard is the simplest
    //     way to keep the splice bytewise),
    //   * no return / br / br_table / br_if / call_indirect — control
    //     flow that escapes the body would mean the inlined region's
    //     branch targets shift, which we don't yet handle,
    //   * body bytes ≤ MAX_INLINE_BODY_BYTES.
    if is_unique_caller && sig == (0, 0) {
        let body_instrs = &body[off..body.len() - 1]; // drop trailing end
        if body_instrs.len() <= MAX_INLINE_BODY_BYTES
            && body_instrs.last().is_some()
            && safe_to_inline_verbatim(body, off)
        {
            return Some(Trivial::ReplaceWithBody(body_instrs.to_vec()));
        }
    }

    None
}

/// Walk the callee body and reject any opcode whose semantics cross
/// the function boundary (return, br to function-level), modifies a
/// local (would clash with caller numbering), or that we can't bound.
fn safe_to_inline_verbatim(body: &[u8], instrs_start: usize) -> bool {
    let mut iter = InstrIter::new(body, instrs_start);
    while let Some((p, _)) = iter.next() {
        let op = body[p];
        match op {
            // Locals — would reference caller's locals after splice.
            0x20 | 0x21 | 0x22 => return false,
            // return — semantics differ when inlined.
            0x0F => return false,
            // br / br_if / br_table that could escape — over-conservative
            // bail rather than try to compute "stays inside body".
            0x0C | 0x0D | 0x0E => return false,
            // call_indirect — table semantics complicate things; skip.
            0x11 => return false,
            _ => {}
        }
    }
    !iter.failed()
}

/// Count `call N` occurrences targeting each defined function index.
fn count_call_sites(
    m: &MutModule<'_>,
    num_imports: u32,
    num_bodies: usize,
) -> Vec<u32> {
    let mut counts = vec![0u32; num_bodies];
    for i in 0..num_bodies {
        let body = m.body_bytes(i);
        let Some(start) = opcode::skip_locals(body) else { continue };
        let mut iter = InstrIter::new(body, start);
        while let Some((p, _)) = iter.next() {
            if body[p] != 0x10 { continue; }
            if let Some((f, _)) = leb128::read_u32(&body[p + 1..]) {
                if f >= num_imports {
                    let local_idx = (f - num_imports) as usize;
                    if local_idx < counts.len() { counts[local_idx] += 1; }
                }
            }
        }
    }
    counts
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
            Trivial::ReplaceWithBody(bytes) => {
                edits.push((p, len, bytes.as_slice()));
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

    // Helper: most pre-M6 tests don't care about the unique-caller flag.
    fn cls(body: &[u8], sig: (u32, u32)) -> Option<Trivial> {
        classify(body, sig, false)
    }

    #[test]
    fn classifies_empty() {
        let body = [0, 0x0B];
        assert!(matches!(cls(&body, (0, 0)), Some(Trivial::DeleteCall)));
        assert!(cls(&body, (0, 1)).is_none());
    }

    #[test]
    fn classifies_identity() {
        let body = [0, 0x20, 0, 0x0B];
        assert!(matches!(cls(&body, (1, 1)), Some(Trivial::DeleteCall)));
        assert!(cls(&body, (2, 1)).is_none());
        let body2 = [0, 0x20, 1, 0x0B];
        assert!(cls(&body2, (1, 1)).is_none());
    }

    #[test]
    fn classifies_const() {
        let body = [0, 0x41, 42, 0x0B];
        let t = cls(&body, (0, 1)).expect("should classify");
        match t {
            Trivial::ReplaceWithConst(b) => assert_eq!(b, vec![0x41, 42]),
            _ => panic!("expected const"),
        }
    }

    #[test]
    fn rejects_nonzero_locals() {
        let body = [1, 1, 0x7F, 0x0B];
        assert!(cls(&body, (0, 0)).is_none());
    }

    // M6: single-caller `() -> ()` bodies become ReplaceWithBody.
    #[test]
    fn classifies_single_caller_void_body() {
        // (func () -> () nop nop end)
        let body = [0, 0x01, 0x01, 0x0B];
        // Without unique-caller flag — falls back to no-match.
        assert!(cls(&body, (0, 0)).is_none());
        // With unique-caller — becomes ReplaceWithBody.
        let t = classify(&body, (0, 0), true).expect("should classify");
        match t {
            Trivial::ReplaceWithBody(b) => assert_eq!(b, vec![0x01, 0x01]),
            _ => panic!("expected body inline"),
        }
    }

    #[test]
    fn rejects_inline_when_body_uses_locals() {
        // local.get 0 inside body — would clash with caller's local 0.
        let body = [0, 0x20, 0, 0x1A, 0x0B];
        assert!(classify(&body, (0, 0), true).is_none());
    }

    #[test]
    fn rejects_inline_when_body_has_branch() {
        // br 0 — control flow we don't yet rewire.
        let body = [0, 0x02, 0x40, 0x0C, 0x00, 0x0B, 0x0B];
        assert!(classify(&body, (0, 0), true).is_none());
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
