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

    // Classify each defined function's body. ReplaceWithBody* variants
    // require closed-world is_internal AND a profitability check —
    // unique-caller is always profitable; multi-callsite is gated on
    // the per-site inlined-size vs callee-overhead cost model.
    let mut trivial: Vec<Option<Trivial>> = Vec::with_capacity(num_bodies);
    let func_types = read_defined_func_type_indices(&wm).unwrap_or_default();
    for i in 0..num_bodies {
        let body = m.body_bytes(i);
        let abs_idx = num_imports + i as u32;
        let sig = sigs.func_sig(abs_idx).unwrap_or((0, 0));
        let n_callers = call_counts.get(i).copied().unwrap_or(0);
        let internal = hints.is_some_and(|h| h.is_internal(abs_idx));
        let mut entry = classify(body, sig, n_callers, internal);
        // Patch ReplaceWithBodyParams's param_types + result_blocktype.
        if let Some(Trivial::ReplaceWithBodyParams {
            param_types, result_blocktype, ..
        }) = entry.as_mut() {
            if let Some(&tidx) = func_types.get(i) {
                if let Some((real_params, real_results)) = read_func_sig_types(&wm, tidx) {
                    *param_types = real_params;
                    if real_results.is_empty() {
                        *result_blocktype = 0x40;
                    } else if real_results.len() == 1 {
                        *result_blocktype = real_results[0];
                    } else {
                        // Multi-value result — out of scope; bail.
                        entry = None;
                    }
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
    /// Inline a `(T_0, .., T_{N-1}) -> R?` callee — M6 phase 2/3/4.
    /// Args are materialised into freshly-allocated caller locals; the
    /// body is pasted with `local.{get,set,tee} k → (first_new + k)`.
    ///
    /// `wrap_for_return == true`: the body is wrapped in
    /// `block <result_blocktype> ... end` and every `return` is
    /// rewritten to `br N` where N is the return's nesting depth.
    ///
    /// `result_blocktype` is `0x40` for void callees or the single
    /// valtype byte for `(T...) -> R` callees (phase 4).
    ReplaceWithBodyParams {
        param_types: Vec<u8>,
        /// Phase 5: callee's declared local valtypes (in order).
        /// Empty for callees with no declared locals.
        declared_types: Vec<u8>,
        body: Vec<u8>,
        wrap_for_return: bool,
        result_blocktype: u8,
    },
}

/// Maximum bytes we'll inline-paste a body for the unique-caller case.
/// Larger bodies get diminishing returns vs. binary size; cap to keep
/// behaviour predictable.
const MAX_INLINE_BODY_BYTES: usize = 64;

/// Cost model for multi-callsite inlining. Original size (callee
/// definition + N call instructions) is roughly `body_total + 5 + N*2`.
/// After inlining: callee removed, each call replaced by inlined_size
/// bytes. Wins iff `N * (inlined_size - 2) < body_total + 5`.
fn multi_caller_profitable(
    body_total: usize, n_params: u32, has_wrap: bool, n_callers: u32,
) -> bool {
    if n_callers == 0 { return false; }
    if n_callers == 1 { return true; }
    let body_instr_bytes = body_total.saturating_sub(1);
    let inlined_size =
        body_instr_bytes
        + 2 * n_params as usize           // local.set chain
        + if has_wrap { 2 } else { 0 };   // block + end
    let added_per_site = inlined_size as i64 - 2;
    let total_added = n_callers as i64 * added_per_site;
    let callee_savings = body_total as i64 + 5;
    callee_savings > total_added
}

fn classify(
    body: &[u8],
    sig: (u32, u32),
    n_callers: u32,
    internal: bool,
) -> Option<Trivial> {
    let is_unique_caller = n_callers == 1;
    // Parse locals header. Phase 5 supports callees with declared locals.
    let (locals_end, declared_types) = parse_locals_header(body)?;

    // The Empty / Identity / Const fast-paths require zero declared locals.
    let no_declared = declared_types.is_empty();

    // Case: body is just `end`.
    if no_declared && body.get(locals_end) == Some(&0x0B) && locals_end + 1 == body.len() {
        if sig == (0, 0) {
            return Some(Trivial::DeleteCall);
        }
        return None;
    }

    // One-instruction patterns (need no declared locals).
    if no_declared {
        let len = opcode::instr_len(body, locals_end)?;
        let op_start = locals_end;
        let op_end = locals_end + len;
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
    }

    // The inline-paste variants (ReplaceWithBody*) need closed-world
    // visibility (`internal`) so DCE can reap the orphaned callee.
    if !internal { return None; }
    let _ = is_unique_caller;

    // M6 phase 1 — `() -> ()` no-locals body inlining (verbatim paste).
    if sig == (0, 0) && no_declared {
        let body_instrs = &body[locals_end..body.len() - 1];
        if body_instrs.len() <= MAX_INLINE_BODY_BYTES
            && body_instrs.last().is_some()
            && safe_to_inline_no_locals(body, locals_end)
            && multi_caller_profitable(body.len(), 0, false, n_callers)
        {
            return Some(Trivial::ReplaceWithBody(body_instrs.to_vec()));
        }
    }

    // M6 phase 2-7 — general inliner: any params, any declared locals,
    // any `return`/br pattern, any `call`/`call_indirect`, 0 or 1
    // result valtype. Now also: any number of callers if the cost
    // model says it's a win.
    if sig.1 <= 1 {
        let body_instrs = &body[locals_end..body.len() - 1];
        if body_instrs.len() <= MAX_INLINE_BODY_BYTES
            && body_instrs.last().is_some()
        {
            let total_locals = sig.0 + declared_types.len() as u32;
            let (safe, has_return) =
                safe_to_inline_with_param_locals_v3(body, locals_end, total_locals);
            if safe && multi_caller_profitable(body.len(), sig.0, has_return, n_callers) {
                let result_blocktype = if sig.1 == 0 { 0x40 } else { 0u8 /* patched */ };
                return Some(Trivial::ReplaceWithBodyParams {
                    param_types: vec![0u8; sig.0 as usize],
                    declared_types,
                    body: body_instrs.to_vec(),
                    wrap_for_return: has_return,
                    result_blocktype,
                });
            }
        }
    }

    None
}

/// Decode the locals header. Returns `(byte_offset_of_first_instr,
/// declared_local_valtypes_in_order)`. `None` on unrecognised valtype.
fn parse_locals_header(body: &[u8]) -> Option<(usize, Vec<u8>)> {
    let (groups, mut off) = leb128::read_u32(body)?;
    let mut types = Vec::new();
    for _ in 0..groups {
        let (n, c) = leb128::read_u32(body.get(off..)?)?;
        off += c;
        let vt = *body.get(off)?;
        if !matches!(vt, 0x7B..=0x7F | 0x6F | 0x70) { return None; }
        off += 1;
        for _ in 0..n {
            types.push(vt);
        }
    }
    Some((off, types))
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

/// Phase 2-7 safety predicate. The only hard constraint is local
/// references: indices >= `n_locals` would point at non-existent
/// callee locals (we don't paste them). Everything else is allowed:
/// - `return` and br variants force a wrap (phase 3/6).
/// - `call F` and `call_indirect` are fine — their immediates are
///   module-global indices (function/type/table), unchanged by the
///   splice (phase 7).
fn safe_to_inline_with_param_locals_v3(body: &[u8], instrs_start: usize, n_locals: u32)
    -> (bool, bool)
{
    let mut iter = InstrIter::new(body, instrs_start);
    let mut needs_wrap = false;
    while let Some((p, _)) = iter.next() {
        let op = body[p];
        match op {
            0x20 | 0x21 | 0x22 => {
                let Some((k, _)) = leb128::read_u32(&body[p + 1..]) else { return (false, false) };
                if k >= n_locals { return (false, false); }
            }
            0x0F | 0x0C | 0x0D | 0x0E => needs_wrap = true,
            _ => {}
        }
    }
    if iter.failed() { return (false, false); }
    (true, needs_wrap)
}

/// Rewrite every `return` opcode in `body` (already locals-stripped
/// instruction stream) to `br N` where N is the return's enclosing
/// block/loop/if nesting depth. The caller will wrap the resulting
/// stream in `block 0x40 ... end`, so depth 0 == that wrapping block.
fn rewrite_returns_to_br(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len() + 8);
    let mut iter = InstrIter::new(body, 0);
    let mut cursor = 0;
    let mut depth: u32 = 0;
    while let Some((p, len)) = iter.next() {
        let op = body[p];
        match op {
            0x02 | 0x03 | 0x04 => depth += 1,
            0x0B => depth = depth.saturating_sub(1),
            0x0F => {
                out.extend_from_slice(&body[cursor..p]);
                out.push(0x0C);                            // br
                leb128::write_u32(&mut out, depth);
                cursor = p + len;
            }
            _ => {}
        }
    }
    if iter.failed() { return None; }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
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

/// Read both the param and result valtype byte vectors for a function
/// type. Returns None on unsupported (non-0x60) form or unrecognised
/// valtype byte.
fn read_func_sig_types(module: &WasmModule<'_>, type_idx: u32)
    -> Option<(Vec<u8>, Vec<u8>)>
{
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
        let (results, c) = leb128::read_u32(p.get(off..)?)?;
        off += c;
        let results_start = off;
        for _ in 0..results {
            let vt = *p.get(off)?;
            if !matches!(vt, 0x7B..=0x7F | 0x6F | 0x70) { return None; }
            off += 1;
        }
        let results_end = off;
        if ti == type_idx {
            return Some((
                p[params_start..params_end].to_vec(),
                p[results_start..results_end].to_vec(),
            ));
        }
    }
    None
}

#[allow(dead_code)]
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
            Trivial::ReplaceWithBodyParams {
                param_types, declared_types, body: callee, wrap_for_return, result_blocktype,
            } => {
                // Guard: local index is a u32 LEB. If adding the callee's
                // locals would overflow — OR would push a single function's
                // local count past what validators accept — we can't inline
                // this site. Happens with deep fixpoint cascades where a hot
                // caller inlines dozens of small helpers, each adding its
                // locals slot-by-slot.
                //
                // Cap is deliberately conservative (50k). wasm's spec bound
                // is 2^32 but real-world validators reject counts far below
                // that; binaryen's corpus reproduces this with a handful of
                // pathological .wast inputs.
                const MAX_LOCALS_PER_FUNCTION: u32 = 50_000;
                let n = param_types.len() as u32;
                let extra = n.checked_add(declared_types.len() as u32);
                let Some(extra) = extra else { continue };
                let Some(total) = next_new_local.checked_add(extra) else { continue };
                if total > MAX_LOCALS_PER_FUNCTION { continue; }
                let first_new = next_new_local;
                let Some(remapped) = rebase_locals(callee, first_new) else { continue };
                // Body might still reference declared locals at indices
                // n..n+d (already rebased above).
                let body_part = if *wrap_for_return {
                    match rewrite_returns_to_br(&remapped) {
                        Some(b) => b,
                        None => continue,
                    }
                } else {
                    remapped
                };
                let mut repl = Vec::with_capacity(body_part.len() + 2 * n as usize + 4);
                for k in (0..n).rev() {
                    repl.push(0x21);
                    leb128::write_u32(&mut repl, first_new + k);
                }
                if *wrap_for_return {
                    // Wrap with block <result_blocktype>. Return → br N
                    // lands at this block's end with the result on stack.
                    repl.push(0x02);
                    repl.push(*result_blocktype);
                    repl.extend_from_slice(&body_part);
                    repl.push(0x0B);
                } else {
                    repl.extend_from_slice(&body_part);
                }
                new_local_types.extend_from_slice(param_types);
                new_local_types.extend_from_slice(declared_types);
                next_new_local = next_new_local.saturating_add(extra);
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

    // Helper: most pre-M6 tests are fast-path Empty/Identity/Const
    // patterns that don't need internal/n_callers info.
    fn cls(body: &[u8], sig: (u32, u32)) -> Option<Trivial> {
        classify(body, sig, 0, false)
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
        let t = classify(&body, (0, 0), 1, true).expect("should classify");
        match t {
            Trivial::ReplaceWithBody(b) => assert_eq!(b, vec![0x01, 0x01]),
            _ => panic!("expected body inline"),
        }
    }

    #[test]
    fn rejects_inline_when_body_uses_locals() {
        // local.get 0 inside body — would clash with caller's local 0.
        let body = [0, 0x20, 0, 0x1A, 0x0B];
        assert!(classify(&body, (0, 0), 1, true).is_none());
    }

    #[test]
    fn phase6_accepts_body_with_internal_branch() {
        // body: block; br 0; end; end.  Used to bail; phase 6 wraps
        // and trusts wasm's structured CF: br L semantics are unchanged
        // from the body's perspective because the wrap only adds an
        // OUTER frame.
        let body = [0, 0x02, 0x40, 0x0C, 0x00, 0x0B, 0x0B];
        let entry = classify(&body, (0, 0), 1, true);
        // Should classify as ReplaceWithBodyParams with wrap_for_return.
        match entry {
            Some(Trivial::ReplaceWithBodyParams { wrap_for_return: true, .. }) => {}
            _ => panic!("phase 6 should classify body-with-br as ReplaceWithBodyParams + wrap"),
        }
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
            declared_types: vec![],
            body: callee_body,
            wrap_for_return: false,
            result_blocktype: 0x40,
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

    // M6 phase 3: callee body with `return` — wrap + rewrite.
    #[test]
    fn rewrites_call_with_return_wraps_and_rewrites_br() {
        // Caller: 0 locals, i32.const 5, call 0, end. Callee 0 takes
        // 1 i32 param and has body `local.get 0 ; drop ; return`.
        let body = [0u8, 0x41, 5, 0x10, 0, 0x0B];
        let callee_body = vec![0x20, 0, 0x1A, 0x0F]; // local.get 0; drop; return
        let trivial = vec![Some(Trivial::ReplaceWithBodyParams {
            param_types: vec![0x7F],
            declared_types: vec![],
            body: callee_body,
            wrap_for_return: true,
            result_blocktype: 0x40,
        })];
        let out = rewrite_body(&body, &trivial, 0, 0).expect("should inline + wrap");
        // Expected: 1 group of (1, i32) header. Caller body:
        //   i32.const 5
        //   local.set 0          ;; arg materialised
        //   block 0x40           ;; wrap
        //     local.get 0        ;; remapped from callee's local 0
        //     drop
        //     br 0               ;; was return, now br to wrap-end
        //   end                  ;; wrap end
        //   end                  ;; func end
        let expected = vec![
            1, 1, 0x7F,
            0x41, 5,
            0x21, 0,
            0x02, 0x40,
            0x20, 0,
            0x1A,
            0x0C, 0,
            0x0B,
            0x0B,
        ];
        assert_eq!(out, expected);
    }

    // M6 phase 4: 1-result callee with return — wrap blocktype is the
    // result valtype, not 0x40.
    #[test]
    fn rewrites_call_returning_value_uses_result_blocktype() {
        // Caller: 0 locals ; i32.const 5 ; call 0 ; drop ; end.
        let body = [0u8, 0x41, 5, 0x10, 0, 0x1A, 0x0B];
        // Callee: (i32) -> i32, body = local.get 0 ; return.
        let callee_body = vec![0x20, 0, 0x0F];
        let trivial = vec![Some(Trivial::ReplaceWithBodyParams {
            param_types: vec![0x7F],
            declared_types: vec![],
            body: callee_body,
            wrap_for_return: true,
            result_blocktype: 0x7F,    // i32
        })];
        let out = rewrite_body(&body, &trivial, 0, 0).expect("should inline");
        // 1 group of (1, i32). Body:
        //   i32.const 5
        //   local.set 0
        //   block (result i32)
        //     local.get 0
        //     br 0
        //   end
        //   drop
        //   end
        let expected = vec![
            1, 1, 0x7F,
            0x41, 5,
            0x21, 0,
            0x02, 0x7F,        // block (result i32)
            0x20, 0,           // local.get 0 (the new local)
            0x0C, 0,           // br 0 (return rewritten)
            0x0B,              // end of wrap
            0x1A,              // drop
            0x0B,              // end func
        ];
        assert_eq!(out, expected);
    }

    // M6 phase 5: callee with declared locals — they get appended to
    // the caller's locals header alongside the param locals.
    #[test]
    fn rewrites_call_with_declared_locals() {
        // Caller: 0 locals ; i32.const 5 ; call 0 ; end.
        let body = [0u8, 0x41, 5, 0x10, 0, 0x0B];
        // Callee: (i32) -> () with one declared i64.
        // Body (instr stream only): local.set 1 (i64-coerced — illustrative)
        //                            local.get 0
        //                            drop
        // For this unit test we only verify the locals header rewrite;
        // semantically we'd want the i64 set with an i64 source. We
        // construct a body that just touches local 1 (declared).
        let callee_body = vec![
            0x42, 0,    // i64.const 0
            0x21, 1,    // local.set 1 (the declared local)
            0x20, 0,    // local.get 0
            0x1A,       // drop
        ];
        let trivial = vec![Some(Trivial::ReplaceWithBodyParams {
            param_types: vec![0x7F],   // i32 param
            declared_types: vec![0x7E], // i64 declared local
            body: callee_body,
            wrap_for_return: false,
            result_blocktype: 0x40,
        })];
        let out = rewrite_body(&body, &trivial, 0, 0).expect("should inline");
        // Expected locals header: 2 groups (one per appended local).
        // Body: i32.const 5, local.set 0, i64.const 0, local.set 1,
        //       local.get 0, drop, end.
        // Locals 0..1 in the splice = (param_i32, declared_i64) of the callee.
        let expected = vec![
            2,                  // 2 groups
            1, 0x7F,            // (1, i32) — for the param
            1, 0x7E,            // (1, i64) — for the declared local
            0x41, 5,
            0x21, 0,            // local.set 0 (arg materialised)
            0x42, 0,            // i64.const 0 (callee's instr)
            0x21, 1,            // local.set 1 (callee's declared, rebased to caller idx 1)
            0x20, 0,            // local.get 0 (callee's param 0, rebased)
            0x1A,
            0x0B,
        ];
        assert_eq!(out, expected);
    }

    // Phase 7: callee body containing call_indirect — module-global
    // type/table indices unchanged by the splice.
    #[test]
    fn phase7_accepts_callee_with_call_indirect() {
        // Callee body: i32.const 0; call_indirect (type 0) (table 0); end.
        let body = [
            0,
            0x41, 0,
            0x11, 0, 0,
            0x0B,
        ];
        // sig (1) -> () with one i32 param.
        let entry = classify(&body, (1, 0), 1, true);
        match entry {
            Some(Trivial::ReplaceWithBodyParams { .. }) => {}
            _ => panic!("call_indirect inside callee should now classify"),
        }
    }

    // Multi-callsite cost model: tiny body with 2 callers should be
    // profitable to inline; larger body shouldn't.
    #[test]
    fn multi_caller_profitable_for_tiny_body() {
        // Tiny body: just `nop` (1 byte instr). body_total = 3 (1 locals
        // header + 1 nop + 1 end). With 0 params, no wrap:
        // inlined_size = 3-1 = 2. added_per_site = 2 - 2 = 0.
        // total_added = 2*0 = 0. callee_savings = 3+5 = 8 > 0. PROFITABLE.
        let body = [0, 0x01, 0x0B];
        match classify(&body, (0, 0), 2, true) {
            Some(_) => {}
            None => panic!("tiny body with 2 callers should be inline-profitable"),
        }
    }

    #[test]
    fn multi_caller_unprofitable_for_large_body_with_params() {
        // Big body: 32 nops (32 bytes). body_total = 1 + 32 + 1 = 34.
        // 2 params, has wrap.
        // inlined_size = 33 + 4 + 2 = 39. added_per_site = 37.
        // total_added = 5 * 37 = 185. callee_savings = 39. NOT profitable.
        let mut body = vec![0]; // 0 locals
        for _ in 0..32 { body.push(0x01); } // 32 nops
        body.push(0x0B); // end
        match classify(&body, (2, 0), 5, true) {
            None => {}
            Some(_) => panic!("large body × 5 callers should NOT be inline-profitable"),
        }
    }
}
