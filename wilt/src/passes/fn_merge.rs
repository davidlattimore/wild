//! Function merging — dedupe identical-body functions.
//!
//! For each pair of defined functions with the same signature AND the
//! same body bytes (locals header included), pick a canonical and
//! redirect every `call N` targeting the others to call the canonical
//! instead. The non-canonical functions become orphaned; DCE on the
//! next fixpoint iteration removes them.
//!
//! Common in compiler output — toolchains emit identical thunks /
//! shims for trait dispatch, error formatting helpers, etc.
//!
//! Standalone-friendly (no hints needed) — but only merges functions
//! we can prove are direct-call-only:
//!   * not exported,
//!   * not the start function,
//!   * not appearing as a `ref.func` target in any body or element segment.
//! Anything in those sets keeps its identity (its index is part of
//! the module's external contract).

use crate::leb128;
use crate::module::WasmModule;
use crate::module::{self as wmod};
use crate::mut_module::MutModule;
use crate::opcode::InstrIter;
use crate::opcode::{self};
use std::collections::HashMap;
use std::collections::HashSet;

pub fn apply_mut(m: &mut MutModule<'_>) {
    let input = m.input();
    let Ok(mut wm) = WasmModule::parse(input) else {
        return;
    };
    wm.ensure_function_bodies_parsed();
    let data = wm.data();

    let num_imports = m.facts.num_func_imports;
    let num_bodies = m.num_bodies();
    if num_bodies < 2 {
        return;
    }

    let func_types = match read_defined_func_type_indices(&wm) {
        Some(v) => v,
        None => return,
    };

    let exported: HashSet<u32> = m.facts.exported_func_indices.iter().copied().collect();
    let start = m.facts.start_func;
    let ref_funcs = collect_ref_func_targets(&wm);

    // Group safe-to-redirect bodies by (type_idx, hash(body)). Hashing
    // is O(body) but only 8 bytes per key — vs cloning the whole body
    // into the HashMap key. Verify byte-equality on collision before
    // committing to the merge.
    use std::hash::Hash;
    use std::hash::Hasher;
    let mut groups: HashMap<(u32, u64), Vec<u32>> = HashMap::new();
    for i in 0..num_bodies {
        let abs_idx = num_imports + i as u32;
        if exported.contains(&abs_idx) || ref_funcs.contains(&abs_idx) || start == Some(abs_idx) {
            continue;
        }
        let tidx = match func_types.get(i) {
            Some(&t) => t,
            None => continue,
        };
        let body = m.body_bytes(i);
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        body.hash(&mut hasher);
        let h = hasher.finish();
        groups.entry((tidx, h)).or_default().push(abs_idx);
    }

    // Build remap: non-canonical → lowest-index canonical. Verify
    // byte-equality between members before merging (hash collisions
    // would otherwise corrupt the module).
    let mut remap: HashMap<u32, u32> = HashMap::new();
    for members in groups.values() {
        if members.len() < 2 {
            continue;
        }
        // Cluster members by exact body equality (O(N²) within a
        // group, but groups are tiny in practice).
        let mut clusters: Vec<Vec<u32>> = Vec::new();
        'outer: for &abs in members {
            let body = m.body_bytes((abs - num_imports) as usize);
            for cluster in clusters.iter_mut() {
                let canon = cluster[0];
                let canon_body = m.body_bytes((canon - num_imports) as usize);
                if body == canon_body {
                    cluster.push(abs);
                    continue 'outer;
                }
            }
            clusters.push(vec![abs]);
        }
        for cluster in &clusters {
            if cluster.len() < 2 {
                continue;
            }
            let canonical = *cluster.iter().min().unwrap();
            for &abs in cluster {
                if abs != canonical {
                    remap.insert(abs, canonical);
                }
            }
        }
    }
    if remap.is_empty() {
        return;
    }

    let _ = data;

    // Rewrite every body's `call N` for N in remap.
    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>)> = (0..num_bodies)
        .into_par_iter()
        .filter_map(|i| rewrite_calls(m.body_bytes(i), &remap).map(|b| (i, b)))
        .collect();
    for (i, b) in updates {
        m.set_body(i, b);
    }
}

fn rewrite_calls(body: &[u8], remap: &HashMap<u32, u32>) -> Option<Vec<u8>> {
    let start = opcode::skip_locals(body)?;
    let mut iter = InstrIter::new(body, start);
    let mut edits: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    while let Some((p, len)) = iter.next() {
        if body[p] != 0x10 {
            continue;
        } // call
        let Some((f, _)) = leb128::read_u32(&body[p + 1..]) else {
            continue;
        };
        if let Some(&new_f) = remap.get(&f) {
            if new_f != f {
                let mut repl = Vec::with_capacity(1 + 5);
                repl.push(0x10);
                leb128::write_u32(&mut repl, new_f);
                edits.push((p, len, repl));
            }
        }
    }
    if iter.failed() {
        return None;
    }
    if edits.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for (p, len, repl) in &edits {
        out.extend_from_slice(&body[cursor..*p]);
        out.extend_from_slice(repl);
        cursor = p + len;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
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

/// Conservative ref.func target collector. Scans bodies and explicit-
/// funcidx element segment vecs. Skips global init exprs (rare); any
/// function reachable only via global init stays merged-out.
fn collect_ref_func_targets(module: &WasmModule<'_>) -> HashSet<u32> {
    let data = module.data();
    let mut out = HashSet::new();
    for body in module.function_bodies() {
        let b = body.body.slice(data);
        let Some(start) = opcode::skip_locals(b) else {
            continue;
        };
        let mut iter = InstrIter::new(b, start);
        while let Some((p, _)) = iter.next() {
            if b[p] == 0xD2 {
                if let Some((f, _)) = leb128::read_u32(&b[p + 1..]) {
                    out.insert(f);
                }
            }
        }
    }
    if let Some(sec) = module.section(wmod::SECTION_ELEMENT) {
        if let Some(targets) = super::dce::scan_elements_funcidx(sec.payload.slice(data)) {
            out.extend(targets);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assemble(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).unwrap()
    }

    #[test]
    fn merges_two_identical_internal_helpers() {
        let wat = r#"
            (module
              (func $h1 (result i32) i32.const 42)
              (func $h2 (result i32) i32.const 42)
              (func $caller (export "caller") (result i32)
                call $h1
                call $h2
                i32.add)
            )
        "#;
        let bytes = assemble(wat);
        let mut m = MutModule::new(&bytes).unwrap();
        apply_mut(&mut m);
        let out = m.serialize();
        // Caller used to call $h1 then $h2; after merge both go to $h1
        // (lower index = canonical).
        // Verify by re-parsing and inspecting calls in body 2.
        let mut wm = WasmModule::parse(&out).unwrap();
        wm.ensure_function_bodies_parsed();
        let body2 = wm.function_bodies()[2].body.slice(wm.data());
        let mut calls: Vec<u32> = Vec::new();
        let start = opcode::skip_locals(body2).unwrap();
        let mut iter = InstrIter::new(body2, start);
        while let Some((p, _)) = iter.next() {
            if body2[p] == 0x10 {
                if let Some((f, _)) = leb128::read_u32(&body2[p + 1..]) {
                    calls.push(f);
                }
            }
        }
        assert_eq!(
            calls,
            vec![0, 0],
            "both calls should target the canonical $h1 (index 0)"
        );
    }

    #[test]
    fn does_not_merge_when_function_is_exported() {
        let wat = r#"
            (module
              (func (export "h1") (result i32) i32.const 42)
              (func (export "h2") (result i32) i32.const 42)
              (func $caller (export "caller") (result i32)
                call 0
                call 1
                i32.add)
            )
        "#;
        let bytes = assemble(wat);
        let mut m = MutModule::new(&bytes).unwrap();
        apply_mut(&mut m);
        let out = m.serialize();
        // No change — both candidates exported.
        assert_eq!(out, bytes);
    }

    #[test]
    fn does_not_merge_when_function_is_ref_funcd() {
        let wat = r#"
            (module
              (table 1 1 funcref)
              (elem (i32.const 0) $h1)
              (func $h1 (result i32) i32.const 42)
              (func $h2 (result i32) i32.const 42)
              (func $caller (export "caller") (result i32)
                call $h1
                call $h2
                i32.add)
            )
        "#;
        let bytes = assemble(wat);
        let mut m = MutModule::new(&bytes).unwrap();
        apply_mut(&mut m);
        let out = m.serialize();
        // $h1 is ref.func'd → not redirectable, but $h2 isn't, but
        // there's only one viable candidate so the group has size 1
        // and no merge happens.
        assert_eq!(out, bytes);
    }
}
