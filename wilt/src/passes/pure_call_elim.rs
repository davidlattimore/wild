//! Pure-call elimination: delete `call f` when `f` is pure and has
//! signature `(void) -> (void)`. The call produces nothing and has no
//! side effects, so it's a no-op at every call site.
//!
//! Relies on `LinkerHints::func_is_pure` (standalone: `DerivedHints`
//! computes the pure set by fixpoint over defined bodies). Imports
//! are pessimistically impure, so this pass is safe even when we
//! can't see the import's implementation.
//!
//! Out of scope (good follow-ups):
//!   * `call f; drop×k` when `f` is pure with `k` results — needs
//!     recognition of the post-call drop run.
//!   * Pure calls whose results are consumed: we can't elide the
//!     call without changing stack shape (would need to replace with
//!     equivalent constants, i.e. real IPA).
//!
//! Byte savings per match: `1 + uleb128_len(f)` (≥ 2 bytes).

use std::collections::HashSet;

use crate::leb128;
use crate::linker_hints::LinkerHints;
use crate::module::{self as wmod, WasmModule};
use crate::mut_module::MutModule;
use crate::opcode::{self as opc, InstrIter};

const OP_CALL: u8 = 0x10;

pub fn apply_mut_with_hints(m: &mut MutModule<'_>, hints: Option<&dyn LinkerHints>) {
    let Some(hints) = hints else { return };
    let input = m.input();
    let Ok(wm) = WasmModule::parse(input) else { return };

    // Set of function indices that are *both* pure and have void
    // signature `() -> ()`. Computed once per pass invocation; the
    // hint does the pure test, the module's type section does arity.
    let voidable = match compute_voidable(&wm, hints) {
        Some(v) if !v.is_empty() => v,
        _ => return,
    };

    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>)> = (0..m.num_bodies())
        .into_par_iter()
        .filter_map(|i| rewrite_body(m.body_bytes(i), &voidable).map(|b| (i, b)))
        .collect();
    for (i, b) in updates { m.set_body(i, b); }
}

fn rewrite_body(body: &[u8], voidable: &HashSet<u32>) -> Option<Vec<u8>> {
    let start = opc::skip_locals(body)?;
    let mut iter = InstrIter::new(body, start);
    let mut deletes: Vec<(usize, usize)> = Vec::new();
    while let Some((p, len)) = iter.next() {
        if body[p] != OP_CALL { continue; }
        let (f, _) = leb128::read_u32(&body[p + 1..])?;
        if voidable.contains(&f) {
            deletes.push((p, len));
        }
    }
    if deletes.is_empty() { return None; }

    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for (p, len) in &deletes {
        out.extend_from_slice(&body[cursor..*p]);
        cursor = p + len;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

fn compute_voidable(module: &WasmModule<'_>, hints: &dyn LinkerHints) -> Option<HashSet<u32>> {
    let data = module.data();
    let num_imports = count_func_imports(module)?;
    let func_types = read_defined_func_type_indices(module)?;
    let void_types = scan_void_type_indices(module);

    let mut out = HashSet::new();
    for (i, &tidx) in func_types.iter().enumerate() {
        let abs = num_imports + i as u32;
        if void_types.contains(&tidx) && hints.func_is_pure(abs) {
            out.insert(abs);
        }
    }
    // Also include imported funcs whose type is void AND func_is_pure.
    // In practice DerivedHints never marks imports pure, but linker
    // hints COULD — e.g. a pure-annotated WASI call. Cheap to allow.
    for abs in 0..num_imports {
        if hints.func_is_pure(abs) {
            let tidx = import_func_type_idx(module, abs)?;
            if void_types.contains(&tidx) { out.insert(abs); }
        }
    }
    let _ = data;
    Some(out)
}

/// Return the set of type indices whose entry is exactly
/// `0x60 0x00 0x00` — the byte pattern for `() -> ()`.
fn scan_void_type_indices(module: &WasmModule<'_>) -> HashSet<u32> {
    let mut out = HashSet::new();
    let Some(sec) = module.section(wmod::SECTION_TYPE) else { return out };
    let p = sec.payload.slice(module.data());
    let Some((count, mut off)) = leb128::read_u32(p) else { return out };
    for i in 0..count {
        let Some(&form) = p.get(off) else { return out };
        if form != 0x60 { return out; }
        // Peek next two bytes: expected empty params and empty results.
        let params_empty = p.get(off + 1).copied() == Some(0x00);
        let results_empty = p.get(off + 2).copied() == Some(0x00);
        if params_empty && results_empty {
            out.insert(i);
            off += 3;
            continue;
        }
        // Otherwise skip the entry — decode params vec, then results vec.
        off += 1;
        for _ in 0..2 {
            let Some((n, c)) = leb128::read_u32(p.get(off..).unwrap_or(&[])) else { return out };
            off += c;
            off += n as usize;  // one byte per valtype (MVP numeric set)
            if off > p.len() { return out; }
        }
    }
    out
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
    use crate::linker_hints::testing::FixedHints;

    #[test]
    fn drops_pure_void_call() {
        // body = [0 locals, call 0, end]
        let body = [0u8, OP_CALL, 0x00, 0x0B];
        let mut voidable = HashSet::new();
        voidable.insert(0u32);
        let out = rewrite_body(&body, &voidable).expect("should drop");
        assert_eq!(out, vec![0u8, 0x0B]);
    }

    #[test]
    fn leaves_impure_call() {
        let body = [0u8, OP_CALL, 0x00, 0x0B];
        let voidable = HashSet::new();
        assert!(rewrite_body(&body, &voidable).is_none());
    }

    #[test]
    fn pure_set_empty_when_no_hints() {
        let _h = FixedHints::default();
        let voidable: HashSet<u32> = HashSet::new();
        // With no marked-pure funcs, rewrite_body is a no-op.
        let body = [0u8, OP_CALL, 0x00, 0x0B];
        assert!(rewrite_body(&body, &voidable).is_none());
    }
}
