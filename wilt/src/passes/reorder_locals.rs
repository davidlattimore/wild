//! Reorder function-body locals by descending use count so the hottest
//! locals get small-LEB indices.
//!
//! Params (the first `num_params` locals, inferred from the function type)
//! cannot be reordered — their positions are fixed by the signature.
//! Declared locals (indices `num_params..total`) can be permuted freely.
//!
//! The locals header is re-emitted to reflect the new valtype layout.
//! Body opcodes `local.get`, `local.set`, `local.tee` are rewritten.
//!
//! Uses `MutModule` for COW: unchanged bodies never allocate.

use crate::leb128;
use crate::module::{self, WasmModule};
use crate::mut_module::MutModule;
use crate::opcode;

pub fn apply_mut(m: &mut MutModule<'_>) {
    let input = m.input();
    // Pull info we need from WasmModule (function section type indices + type section params).
    let Ok(wm) = WasmModule::parse(input) else { return };
    let num_imports = m.facts.num_func_imports;
    let Some(type_indices) = read_function_type_indices(&wm) else { return };
    let Some(type_param_counts) = read_type_param_counts(&wm) else { return };

    let _ = num_imports; // reserved for future use
    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>)> = (0..m.num_bodies())
        .into_par_iter()
        .filter_map(|i| {
            let type_idx = *type_indices.get(i).unwrap_or(&0) as usize;
            let num_params = type_param_counts.get(type_idx).copied().unwrap_or(0);
            reorder_body(m.body_bytes(i), num_params).map(|b| (i, b))
        })
        .collect();
    for (i, b) in updates { m.set_body(i, b); }
}

/// Parse the function section to learn each function's type index.
fn read_function_type_indices(module: &WasmModule<'_>) -> Option<Vec<u32>> {
    let sec = module.section(module::SECTION_FUNCTION)?;
    let data = module.data();
    let p = sec.payload.slice(data);
    let (count, mut off) = leb128::read_u32(p)?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (t, c) = leb128::read_u32(&p[off..])?;
        off += c;
        out.push(t);
    }
    Some(out)
}

/// Parse the type section, returning the number of params per type index.
/// Only handles canonical `0x60 func` types; returns None on unknown forms.
fn read_type_param_counts(module: &WasmModule<'_>) -> Option<Vec<u32>> {
    let sec = module.section(module::SECTION_TYPE)?;
    let data = module.data();
    let p = sec.payload.slice(data);
    let (count, mut off) = leb128::read_u32(p)?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if *p.get(off)? != 0x60 { return None; }
        off += 1;
        let (params, c) = leb128::read_u32(&p[off..])?;
        off += c;
        for _ in 0..params {
            let v = *p.get(off)?;
            off += 1;
            if !matches!(v, 0x7B..=0x7F | 0x6F | 0x70) { return None; }
        }
        let (results, c) = leb128::read_u32(&p[off..])?;
        off += c;
        for _ in 0..results {
            let v = *p.get(off)?;
            off += 1;
            if !matches!(v, 0x7B..=0x7F | 0x6F | 0x70) { return None; }
        }
        out.push(params);
    }
    Some(out)
}

const OP_LOCAL_GET: u8 = 0x20;
const OP_LOCAL_SET: u8 = 0x21;
const OP_LOCAL_TEE: u8 = 0x22;

/// Core of the pass. Returns None if the body can't be cleanly rewritten
/// (unknown valtype, walker failure, no declared locals to reorder).
fn reorder_body(body: &[u8], num_params: u32) -> Option<Vec<u8>> {
    // 1. Parse locals header.
    let mut off = 0;
    let (group_count, c) = leb128::read_u32(body)?;
    off += c;
    // Flat array of valtypes for declared locals only (params are not here).
    let mut declared_types: Vec<u8> = Vec::new();
    for _ in 0..group_count {
        let (n, c) = leb128::read_u32(body.get(off..)?)?;
        off += c;
        let vt = *body.get(off)?;
        off += 1;
        if !matches!(vt, 0x7B..=0x7F | 0x6F | 0x70) { return None; }
        for _ in 0..n { declared_types.push(vt); }
    }
    let instrs_start = off;
    if declared_types.is_empty() { return None; }

    let total_locals = num_params + declared_types.len() as u32;

    // 2. Scan body, counting uses per local index.
    let mut uses = vec![0u32; total_locals as usize];
    let mut iter = opcode::InstrIter::new(body, instrs_start);
    for (p, _) in &mut iter {
        let op = body[p];
        if matches!(op, OP_LOCAL_GET | OP_LOCAL_SET | OP_LOCAL_TEE) {
            let (idx, _) = leb128::read_u32(&body[p + 1..])?;
            if (idx as usize) < uses.len() { uses[idx as usize] += 1; }
        }
    }
    if iter.failed() { return None; }

    // 3. Determine new ordering for declared locals (indices [num_params..total]).
    //    Stable: ties break by original index so output is deterministic.
    let mut order: Vec<u32> = (num_params..total_locals).collect();
    order.sort_by(|a, b| uses[*b as usize].cmp(&uses[*a as usize]).then(a.cmp(b)));

    // Identity? No-op.
    if order.iter().enumerate().all(|(i, &orig)| orig == num_params + i as u32) {
        return None;
    }

    // 4. Build index_map[orig] = new for full space (params map to themselves).
    let mut remap = vec![0u32; total_locals as usize];
    for i in 0..num_params { remap[i as usize] = i; }
    for (new_pos, &orig) in order.iter().enumerate() {
        remap[orig as usize] = num_params + new_pos as u32;
    }

    // 5. Emit new locals header: flat valtype array in new order, run-length encoded.
    let mut new_declared_types: Vec<u8> = Vec::with_capacity(declared_types.len());
    for &orig in &order {
        let local = (orig - num_params) as usize;
        new_declared_types.push(declared_types[local]);
    }
    let mut new_header = Vec::with_capacity(body.len());
    let groups = rle_groups(&new_declared_types);
    leb128::write_u32(&mut new_header, groups.len() as u32);
    for (n, vt) in groups {
        leb128::write_u32(&mut new_header, n);
        new_header.push(vt);
    }

    // 6. Emit body with local.get/set/tee immediates remapped.
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&new_header);
    let mut cursor = instrs_start;
    let mut iter = opcode::InstrIter::new(body, instrs_start);
    for (p, len) in &mut iter {
        let op = body[p];
        if matches!(op, OP_LOCAL_GET | OP_LOCAL_SET | OP_LOCAL_TEE) {
            if let Some((idx, c)) = leb128::read_u32(&body[p + 1..]) {
                let new_idx = remap[idx as usize];
                if new_idx != idx {
                    out.extend_from_slice(&body[cursor..p]);
                    out.push(op);
                    leb128::write_u32(&mut out, new_idx);
                    cursor = p + 1 + c;
                }
            }
        }
        let _ = len;
    }
    if iter.failed() { return None; }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

fn rle_groups(types: &[u8]) -> Vec<(u32, u8)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < types.len() {
        let vt = types[i];
        let mut n = 1u32;
        while i + (n as usize) < types.len() && types[i + n as usize] == vt {
            n += 1;
        }
        out.push((n, vt));
        i += n as usize;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorders_by_use_count() {
        // body: 1 local group of (2, i32) — two i32 locals, indices 0 and 1.
        // instructions: local.get 1; local.get 1; local.get 1; local.get 0; end
        let body = vec![
            1,          // group count
            2, 0x7F,    // (2 locals, i32)
            0x20, 1,    // local.get 1
            0x20, 1,    // local.get 1
            0x20, 1,    // local.get 1
            0x20, 0,    // local.get 0
            0x0B,       // end
        ];
        // 0 params → declared start at 0. But note: num_params = 0, so
        // both locals can be reordered. Local 1 used 3x, local 0 used 1x.
        // After reorder: local 1 → index 0, local 0 → index 1.
        let out = reorder_body(&body, 0).unwrap();
        // Expect: same header (still (2, i32)), but gets remapped.
        let expected = vec![
            1,
            2, 0x7F,
            0x20, 0,
            0x20, 0,
            0x20, 0,
            0x20, 1,
            0x0B,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn noop_when_order_already_best() {
        let body = vec![
            1,
            2, 0x7F,
            0x20, 0,
            0x20, 0,
            0x20, 1,
            0x0B,
        ];
        assert!(reorder_body(&body, 0).is_none());
    }
}
