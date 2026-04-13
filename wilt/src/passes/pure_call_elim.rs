//! Pure-call elimination.
//!
//! General form: `call f ; drop^k` where `f` is pure with arity `n -> k`
//! becomes `drop^n`. The call is stack-wise just "pop n, push k" and
//! pure means no observable side effects, so if the caller immediately
//! throws the k results away we can drop the arguments directly and
//! skip the call.
//!
//! Savings per site: `1 + uleb(f) + k - n` bytes. We apply only when
//! this is positive.
//!
//! Relies on `LinkerHints::func_is_pure`. DerivedHints computes purity
//! by fixpoint over defined bodies; imports are pessimistically impure.
//!
//! Out of scope:
//!   * Pure calls whose results are *consumed* (would need constant
//!     substitution, i.e. real IPA).
//!   * Impure calls with dropped results (unsound — side effects
//!     still have to run).

use std::collections::HashMap;

use crate::leb128;
use crate::linker_hints::LinkerHints;
use crate::module::{self as wmod, WasmModule};
use crate::mut_module::MutModule;
use crate::opcode::{self as opc};

const OP_CALL: u8 = 0x10;
const OP_DROP: u8 = 0x1A;

type Arity = (u32, u32);   // (params, results)

pub fn apply_mut_with_hints(m: &mut MutModule<'_>, hints: Option<&dyn LinkerHints>) {
    let Some(hints) = hints else { return };
    let input = m.input();
    let Ok(wm) = WasmModule::parse(input) else { return };

    let arities = match compute_pure_arities(&wm, hints) {
        Some(a) if !a.is_empty() => a,
        _ => return,
    };

    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>)> = (0..m.num_bodies())
        .into_par_iter()
        .filter_map(|i| rewrite_body(m.body_bytes(i), &arities).map(|b| (i, b)))
        .collect();
    for (i, b) in updates { m.set_body(i, b); }
}

fn rewrite_body(body: &[u8], arities: &HashMap<u32, Arity>) -> Option<Vec<u8>> {
    let start = opc::skip_locals(body)?;
    let mut off = start;
    // Rewrites are (span_start, span_end, num_drops_to_write).
    let mut edits: Vec<(usize, usize, u32)> = Vec::new();
    while off < body.len() {
        let op = *body.get(off)?;
        if op == 0x0B { break; }
        let len = opc::instr_len(body, off)?;
        if op != OP_CALL { off += len; continue; }

        let (f, _) = leb128::read_u32(&body[off + 1..])?;
        let Some(&(n, k)) = arities.get(&f) else { off += len; continue };

        // Look ahead for exactly k consecutive drops.
        let mut probe = off + len;
        let mut drops = 0u32;
        while drops < k && probe < body.len() {
            let op2 = *body.get(probe)?;
            if op2 != OP_DROP { break; }
            probe += 1;
            drops += 1;
        }
        if drops < k { off += len; continue; }

        let orig_span = probe - off;
        let new_span = n as usize;
        if new_span >= orig_span { off += len; continue; }

        edits.push((off, probe, n));
        off = probe;
    }
    if edits.is_empty() { return None; }

    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for &(s, e, n) in &edits {
        out.extend_from_slice(&body[cursor..s]);
        for _ in 0..n { out.push(OP_DROP); }
        cursor = e;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

fn compute_pure_arities(
    module: &WasmModule<'_>, hints: &dyn LinkerHints,
) -> Option<HashMap<u32, Arity>> {
    let num_imports = count_func_imports(module)?;
    let func_types = read_defined_func_type_indices(module)?;
    let type_arities = scan_type_arities(module)?;

    let mut out = HashMap::new();
    for (i, &tidx) in func_types.iter().enumerate() {
        let abs = num_imports + i as u32;
        if !hints.func_is_pure(abs) { continue; }
        let Some(&arity) = type_arities.get(tidx as usize) else { continue };
        out.insert(abs, arity);
    }
    // Linker-annotated pure imports: include if any.
    for abs in 0..num_imports {
        if !hints.func_is_pure(abs) { continue; }
        let Some(tidx) = import_func_type_idx(module, abs) else { continue };
        let Some(&arity) = type_arities.get(tidx as usize) else { continue };
        out.insert(abs, arity);
    }
    Some(out)
}

/// Parse the type section and return `(params_count, results_count)`
/// for every `0x60`-form entry. Returns `None` on any unrecognised
/// form / malformed layout (we'd rather bail than lie).
fn scan_type_arities(module: &WasmModule<'_>) -> Option<Vec<Arity>> {
    let Some(sec) = module.section(wmod::SECTION_TYPE) else { return Some(Vec::new()) };
    let p = sec.payload.slice(module.data());
    let (count, mut off) = leb128::read_u32(p)?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let form = *p.get(off)?;
        if form != 0x60 { return None; }
        off += 1;
        let (nparams, c) = leb128::read_u32(p.get(off..)?)?;
        off += c;
        // One byte per valtype (MVP numeric set — GC types would break
        // this, but DerivedHints doesn't mark GC modules as having pure
        // funcs reliably anyway).
        for _ in 0..nparams {
            let vt = *p.get(off)?;
            if !matches!(vt, 0x7B..=0x7F) { return None; }
            off += 1;
        }
        let (nresults, c) = leb128::read_u32(p.get(off..)?)?;
        off += c;
        for _ in 0..nresults {
            let vt = *p.get(off)?;
            if !matches!(vt, 0x7B..=0x7F) { return None; }
            off += 1;
        }
        out.push((nparams, nresults));
    }
    Some(out)
}

fn count_func_imports(module: &WasmModule<'_>) -> Option<u32> {
    let sec = module.section(wmod::SECTION_IMPORT)?;
    let p = sec.payload.slice(module.data());
    let (count, mut off) = leb128::read_u32(p)?;
    let mut n = 0;
    for _ in 0..count {
        let (ml, c) = leb128::read_u32(p.get(off..)?)?;
        off = off.checked_add(c)?.checked_add(ml as usize)?;
        let (fl, c) = leb128::read_u32(p.get(off..)?)?;
        off = off.checked_add(c)?.checked_add(fl as usize)?;
        let kind = *p.get(off)?;
        off += 1;
        match kind {
            0x00 => { let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c; n += 1; }
            0x01 => { off += 1; let flags = *p.get(off)?; off += 1;
                let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c;
                if flags & 1 != 0 { let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c; } }
            0x02 => { let flags = *p.get(off)?; off += 1;
                let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c;
                if flags & 1 != 0 { let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c; } }
            0x03 => off += 2,
            _ => return None,
        }
    }
    Some(n)
}

fn import_func_type_idx(module: &WasmModule<'_>, wanted_abs: u32) -> Option<u32> {
    let sec = module.section(wmod::SECTION_IMPORT)?;
    let p = sec.payload.slice(module.data());
    let (count, mut off) = leb128::read_u32(p)?;
    let mut n: u32 = 0;
    for _ in 0..count {
        let (ml, c) = leb128::read_u32(p.get(off..)?)?; off += c + ml as usize;
        let (fl, c) = leb128::read_u32(p.get(off..)?)?; off += c + fl as usize;
        let kind = *p.get(off)?; off += 1;
        match kind {
            0x00 => {
                let (t, c) = leb128::read_u32(p.get(off..)?)?;
                off += c;
                if n == wanted_abs { return Some(t); }
                n += 1;
            }
            0x01 => { off += 1; let flags = *p.get(off)?; off += 1;
                let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c;
                if flags & 1 != 0 { let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c; } }
            0x02 => { let flags = *p.get(off)?; off += 1;
                let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c;
                if flags & 1 != 0 { let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c; } }
            0x03 => off += 2,
            _ => return None,
        }
    }
    None
}

fn read_defined_func_type_indices(module: &WasmModule<'_>) -> Option<Vec<u32>> {
    let sec = module.section(wmod::SECTION_FUNCTION)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_pure_void_call() {
        // body = [0 locals, call 0, end]
        let body = [0u8, OP_CALL, 0x00, 0x0B];
        let mut arities = HashMap::new();
        arities.insert(0u32, (0, 0));
        let out = rewrite_body(&body, &arities).expect("should drop");
        assert_eq!(out, vec![0u8, 0x0B]);
    }

    #[test]
    fn elides_pure_1_to_1_with_drop() {
        // push arg (local.get 0), call 0, drop, end.
        let body = [0u8, 0x20, 0x00, OP_CALL, 0x00, OP_DROP, 0x0B];
        let mut arities = HashMap::new();
        arities.insert(0u32, (1, 1));
        let out = rewrite_body(&body, &arities).expect("should fold");
        // call+drop (3 bytes) replaced by 1 drop: arg stays, one drop consumes it.
        assert_eq!(out, vec![0u8, 0x20, 0x00, OP_DROP, 0x0B]);
    }

    #[test]
    fn elides_pure_0_to_2_with_two_drops() {
        // call 0, drop, drop, end. f is pure () -> (i32, i32).
        let body = [0u8, OP_CALL, 0x00, OP_DROP, OP_DROP, 0x0B];
        let mut arities = HashMap::new();
        arities.insert(0u32, (0, 2));
        let out = rewrite_body(&body, &arities).expect("should fold");
        // call+2 drops (4 bytes) replaced by 0 drops.
        assert_eq!(out, vec![0u8, 0x0B]);
    }

    #[test]
    fn bails_when_too_few_drops() {
        // call 0, drop, end. f is () -> (i32, i32) — only one drop follows.
        let body = [0u8, OP_CALL, 0x00, OP_DROP, 0x0B];
        let mut arities = HashMap::new();
        arities.insert(0u32, (0, 2));
        assert!(rewrite_body(&body, &arities).is_none());
    }

    #[test]
    fn bails_when_no_savings() {
        // f is (i32, i32, i32) -> (i32). orig = 3, replacement = 3 drops = 3.
        // `call f; drop` = 3 bytes; replacement = 3 bytes → no saving.
        let body = [0u8, OP_CALL, 0x00, OP_DROP, 0x0B];
        let mut arities = HashMap::new();
        arities.insert(0u32, (3, 1));
        assert!(rewrite_body(&body, &arities).is_none());
    }

    #[test]
    fn leaves_impure_call() {
        let body = [0u8, OP_CALL, 0x00, 0x0B];
        let arities: HashMap<u32, Arity> = HashMap::new();
        assert!(rewrite_body(&body, &arities).is_none());
    }
}
