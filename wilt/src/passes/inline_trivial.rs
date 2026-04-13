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

    // Classify each defined function's body. ReplaceWithBody*  variants
    // both require unique-caller AND closed-world is_internal — without
    // the latter, DCE may not reap the orphaned callee and the module
    // grows.
    let mut trivial: Vec<Option<Trivial>> = Vec::with_capacity(num_bodies);
    let func_types = read_defined_func_type_indices(&wm).unwrap_or_default();
    for i in 0..num_bodies {
        let body = m.body_bytes(i);
        let abs_idx = num_imports + i as u32;
        let sig = sigs.func_sig(abs_idx).unwrap_or((0, 0));
        let is_unique = call_counts.get(i).copied() == Some(1);
        let inline_safe = is_unique && hints.is_some_and(|h| h.is_internal(abs_idx));
        let mut entry = classify(body, sig, inline_safe);
        // Patch ReplaceWithBodyParams's param_types with real valtypes.
        if let Some(Trivial::ReplaceWithBodyParams { param_types, .. }) = entry.as_mut() {
            if let Some(&tidx) = func_types.get(i) {
                if let Some(real) = read_param_types(&wm, tidx) {
                    *param_types = real;
                } else {
                    entry = None;
                }
            } else {
                entry = None;
            }
        }
        trivial.push(entry);
    }

    if trivial.iter().all(Option::is_none) { return; }

    // Per-caller param counts for splice bookkeeping.
    let caller_param_counts: Vec<u32> = (0..num_bodies)
        .map(|i| sigs.func_sig(num_imports + i as u32).map(|(p, _)| p).unwrap_or(0))
        .collect();

    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>)> = (0..num_bodies)
        .into_par_iter()
        .filter_map(|i| {
            let cp = caller_param_counts.get(i).copied().unwrap_or(0);
            rewrite_body(m.body_bytes(i), &trivial, num_imports, cp).map(|b| (i, b))
        })
        .collect();
    for (i, b) in updates { m.set_body(i, b); }
}

fn read_defined_func_type_indices(module: &WasmModule<'_>) -> Option<Vec<u32>> {
    let sec = module.section(crate::module::SECTION_FUNCTION)?;
    let p = sec.payload.slice(module.data());
    let (count, mut off) = leb128::read_u32(p)?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (t, c) = leb128::read_u32(p.get(off..)?)?;
        off += c;
        out.push(t);
    }
    Some(out)
}

#[derive(Clone)]
enum Trivial {
    /// Call is a no-op; delete the `call f` bytes entirely.
    DeleteCall,
    /// Replace `call f` with these bytes (a single constant instruction).
    ReplaceWithConst(Vec<u8>),
    /// Inline the entire callee body in place of `call f`. M6 phase 1 —
    /// `() -> ()` callees with no locals references.
    ReplaceWithBody(Vec<u8>),
    /// Inline a `(T_0, .., T_{N-1}) -> ()` callee. M6 phase 2. The
    /// caller materialises args into N freshly-allocated caller locals,
    /// then pastes the body with `local.{get,set,tee} k` rewritten to
    /// `local.{...} (caller_first_new_local + k)`.
    ReplaceWithBodyParams { param_types: Vec<u8>, body: Vec<u8> },
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

    // M6 phase 1 — single-caller `() -> ()` body inlining.
    if is_unique_caller && sig == (0, 0) {
        let body_instrs = &body[off..body.len() - 1];
        if body_instrs.len() <= MAX_INLINE_BODY_BYTES
            && body_instrs.last().is_some()
            && safe_to_inline_no_locals(body, off)
        {
            return Some(Trivial::ReplaceWithBody(body_instrs.to_vec()));
        }
    }

    // M6 phase 2 — single-caller `(T...) -> ()` body inlining.
    // Same constraints as phase 1 except local refs are allowed (we
    // remap them at splice time). Also: 0 declared locals so the only
    // locals referenced are the params we're remapping.
    if is_unique_caller && sig.0 > 0 && sig.1 == 0 {
        let body_instrs = &body[off..body.len() - 1];
        if body_instrs.len() <= MAX_INLINE_BODY_BYTES
            && body_instrs.last().is_some()
            && safe_to_inline_with_param_locals(body, off, sig.0)
        {
            // Param valtypes aren't carried in the body; they're in
            // the function type. The caller knows them via ModuleSigs
            // — we stash a placeholder here and patch at splice time.
            // For simplicity we record the count (=sig.0); the caller's
            // pass passes in the param type list separately when it
            // chooses to splice.
            return Some(Trivial::ReplaceWithBodyParams {
                param_types: vec![0u8; sig.0 as usize], // patched at use
                body: body_instrs.to_vec(),
            });
        }
    }

    None
}

/// Phase-1 safety predicate: callee body has zero locals references
/// (all variants of local.{get,set,tee} rejected). Inlining bytes
/// verbatim is then trivially correct.
fn safe_to_inline_no_locals(body: &[u8], instrs_start: usize) -> bool {
    let mut iter = InstrIter::new(body, instrs_start);
    while let Some((p, _)) = iter.next() {
        match body[p] {
            0x20 | 0x21 | 0x22 => return false,
            0x0F => return false,
            0x0C | 0x0D | 0x0E => return false,
            0x11 => return false,
            _ => {}
        }
    }
    !iter.failed()
}

/// Phase-2 safety predicate: callee body may reference locals
/// `0..n_params` (its parameters) but nothing higher. Same control-flow
/// constraints as phase 1.
fn safe_to_inline_with_param_locals(body: &[u8], instrs_start: usize, n_params: u32) -> bool {
    let mut iter = InstrIter::new(body, instrs_start);
    while let Some((p, _)) = iter.next() {
        let op = body[p];
        match op {
            0x20 | 0x21 | 0x22 => {
                let Some((k, _)) = leb128::read_u32(&body[p + 1..]) else { return false };
                if k >= n_params { return false; }
            }
            0x0F | 0x0C | 0x0D | 0x0E | 0x11 => return false,
            _ => {}
        }
    }
    !iter.failed()
}

/// Rewrite every `local.{get,set,tee} k` immediate in `body` by adding
/// `delta` to its index. Returns `None` if any opcode can't be decoded.
fn rebase_locals(body: &[u8], delta: u32) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut iter = InstrIter::new(body, 0);
    let mut cursor = 0;
    while let Some((p, _)) = iter.next() {
        let op = body[p];
        if matches!(op, 0x20 | 0x21 | 0x22) {
            let (k, c) = leb128::read_u32(&body[p + 1..])?;
            out.extend_from_slice(&body[cursor..p]);
            out.push(op);
            leb128::write_u32(&mut out, k + delta);
            cursor = p + 1 + c;
        }
    }
    if iter.failed() { return None; }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

/// Read the param valtype bytes for a function type. Returns None on
/// unsupported (non-0x60) form or unrecognised valtype byte.
fn read_param_types(module: &WasmModule<'_>, type_idx: u32) -> Option<Vec<u8>> {
    let sec = module.section(crate::module::SECTION_TYPE)?;
    let p = sec.payload.slice(module.data());
    let (count, mut off) = leb128::read_u32(p)?;
    if type_idx >= count { return None; }
    for ti in 0..count {
        if *p.get(off)? != 0x60 { return None; }
        off += 1;
        let (params, c) = leb128::read_u32(p.get(off..)?)?;
        off += c;
        let params_start = off;
        for _ in 0..params {
            let vt = *p.get(off)?;
            if !matches!(vt, 0x7B..=0x7F | 0x6F | 0x70) { return None; }
            off += 1;
        }
        let params_end = off;
        // skip results
        let (results, c) = leb128::read_u32(p.get(off..)?)?;
        off += c;
        for _ in 0..results {
            let vt = *p.get(off)?;
            if !matches!(vt, 0x7B..=0x7F | 0x6F | 0x70) { return None; }
            off += 1;
        }
        if ti == type_idx {
            return Some(p[params_start..params_end].to_vec());
        }
    }
    None
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
    caller_param_count: u32,
) -> Option<Vec<u8>> {
    let (groups_count, hdr_after_count) = leb128::read_u32(body)?;
    // Sum existing declared-locals to get the caller's running local count.
    let mut declared_count = 0u32;
    let mut groups_off = hdr_after_count;
    for _ in 0..groups_count {
        let (n, c) = leb128::read_u32(body.get(groups_off..)?)?;
        groups_off += c + 1; // n + valtype byte
        declared_count += n;
    }
    let instrs_start = groups_off;
    let mut next_new_local = caller_param_count + declared_count;

    let mut edits: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    let mut new_local_types: Vec<u8> = Vec::new();

    let mut iter = InstrIter::new(body, instrs_start);
    while let Some((p, len)) = iter.next() {
        if body[p] != 0x10 { continue; }
        let Some((f, _)) = leb128::read_u32(&body[p + 1..]) else { continue };
        if f < num_imports { continue; }
        let local_idx = (f - num_imports) as usize;
        let Some(Some(t)) = trivial.get(local_idx) else { continue };
        match t {
            Trivial::DeleteCall => edits.push((p, len, Vec::new())),
            Trivial::ReplaceWithConst(bytes) => {
                if bytes.len() <= len {
                    edits.push((p, len, bytes.clone()));
                }
            }
            Trivial::ReplaceWithBody(bytes) => {
                edits.push((p, len, bytes.clone()));
            }
            Trivial::ReplaceWithBodyParams { param_types, body: callee } => {
                let n = param_types.len() as u32;
                let first_new = next_new_local;
                let Some(remapped) = rebase_locals(callee, first_new) else { continue };
                let mut repl = Vec::with_capacity(callee.len() + 2 * n as usize);
                // Pop args in reverse (top-of-stack = last arg = first_new + n - 1).
                for k in (0..n).rev() {
                    repl.push(0x21);                      // local.set
                    leb128::write_u32(&mut repl, first_new + k);
                }
                repl.extend_from_slice(&remapped);
                new_local_types.extend_from_slice(param_types);
                next_new_local += n;
                edits.push((p, len, repl));
            }
        }
    }
    if iter.failed() { return None; }
    if edits.is_empty() && new_local_types.is_empty() { return None; }

    // Re-emit body. Locals header may have grown.
    let mut out = Vec::with_capacity(body.len());
    if new_local_types.is_empty() {
        out.extend_from_slice(&body[..instrs_start]);
    } else {
        // Append one group per new local (no coalescing — types may
        // differ; coalescing is a future micro-opt).
        leb128::write_u32(&mut out, groups_count + new_local_types.len() as u32);
        out.extend_from_slice(&body[hdr_after_count..instrs_start]);
        for vt in &new_local_types {
            leb128::write_u32(&mut out, 1);
            out.push(*vt);
        }
    }
    let mut cursor = instrs_start;
    for (p, len, repl) in &edits {
        out.extend_from_slice(&body[cursor..*p]);
        out.extend_from_slice(repl);
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
        let body = [0, 0x01, 0x10, 0, 0x0B];
        let trivial = vec![Some(Trivial::DeleteCall)];
        let out = rewrite_body(&body, &trivial, 0, 0).expect("should rewrite");
        assert_eq!(out, vec![0, 0x01, 0x0B]);
    }

    #[test]
    fn rewrites_call_to_const() {
        let body = [0, 0x10, 0, 0x1A, 0x0B];
        let trivial = vec![Some(Trivial::ReplaceWithConst(vec![0x41, 7]))];
        let out = rewrite_body(&body, &trivial, 0, 0).expect("should rewrite");
        assert_eq!(out, vec![0, 0x41, 7, 0x1A, 0x0B]);
    }

    #[test]
    fn skips_imports() {
        let body = [0, 0x10, 0, 0x0B];
        let trivial = vec![Some(Trivial::DeleteCall)];
        assert!(rewrite_body(&body, &trivial, 1, 0).is_none());
    }

    // M6 phase 2: 1-param void callee inlined into a 0-param caller.
    #[test]
    fn rewrites_call_with_one_param() {
        // Caller body: 0 locals, i32.const 5, call 0, end. Caller has 0 params.
        let body = [0, 0x41, 5, 0x10, 0, 0x0B];
        let callee_body = vec![0x20, 0, 0x1A]; // local.get 0; drop
        let trivial = vec![Some(Trivial::ReplaceWithBodyParams {
            param_types: vec![0x7F],          // i32
            body: callee_body,
        })];
        let out = rewrite_body(&body, &trivial, 0, 0).expect("should inline");
        // Locals header: was 0 groups; now 1 group of (1, i32).
        // Body: i32.const 5, local.set 0, local.get 0, drop, end.
        let expected = vec![
            1, 1, 0x7F,        // 1 group: 1 i32
            0x41, 5,
            0x21, 0,           // local.set 0 (the new local for the arg)
            0x20, 0,           // local.get 0 (remapped from callee's local 0)
            0x1A,              // drop
            0x0B,              // end
        ];
        assert_eq!(out, expected);
    }
}
