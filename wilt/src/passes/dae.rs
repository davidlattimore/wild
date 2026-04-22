//! Dead Argument Elimination — narrow variant.
//!
//! Remove the last tail parameter from a defined function when it's
//! never referenced by the body (no `local.get`/`set`/`tee` of its
//! index), and rewire every call site.
//!
//! On its own this grows the module by +1 byte per call site
//! (inserted `drop`) and shrinks the type entry by 1 valtype byte.
//! The win comes after the fixpoint iterates and
//! `vacuum`/`const_fold` collapses `<const>; drop` sequences at
//! callers — net bytes drop when callers pushed trivial values.
//!
//! Guard rails — the pass only touches a function when ALL of:
//!   * it's a defined function (not an import),
//!   * its type is used by no other function and by no `call_indirect`,
//!   * it isn't in the export section,
//!   * it has no declared locals (only params),
//!   * it has at least one param,
//!   * the last param is never referenced (any of get/set/tee) in the body.
//!
//! One param per invocation; the outer fixpoint picks up successive
//! trailing-dead params.

use crate::leb128;
use crate::linker_hints::LinkerHints;
use crate::module::WasmModule;
use crate::module::{self as wmod};
use crate::mut_module::MutModule;
use crate::opcode::InstrIter;
use crate::opcode::{self};

/// Backwards-compatible entry: today's pipeline calls this with no hints.
pub fn apply_mut(m: &mut MutModule<'_>) {
    apply_mut_with_hints(m, None)
}

/// Hint-aware variant. When `hints` provides `is_internal(f)`, we trust
/// it as a sole replacement for the conservative quartet (not exported
/// AND not ref.func'd AND not start AND not table-target). The
/// type-uniqueness check still applies — shrinking a shared type would
/// break unrelated functions regardless of how internal they are.
pub fn apply_mut_with_hints(m: &mut MutModule<'_>, hints: Option<&dyn LinkerHints>) {
    let input = m.input();
    let Ok(mut wm) = WasmModule::parse(input) else {
        return;
    };
    wm.ensure_function_bodies_parsed();
    let data = wm.data();

    let Some(type_ends) = read_type_ends(&wm) else {
        return;
    };
    let Some(func_types) = read_defined_func_types(&wm) else {
        return;
    };
    let num_imports = m.facts.num_func_imports;

    // Count type references: defined functions, imported functions,
    // call_indirect occurrences.
    let num_types = type_ends.len();
    let mut type_refs = vec![0u32; num_types];
    // Imported functions with function kind — scan once.
    if let Some(sec) = wm.section(wmod::SECTION_IMPORT) {
        let p = sec.payload.slice(data);
        if let Some(indices) = read_import_func_types(p) {
            for t in indices {
                if (t as usize) < num_types {
                    type_refs[t as usize] += 1;
                }
            }
        }
    }
    for &t in &func_types {
        if (t as usize) < num_types {
            type_refs[t as usize] += 1;
        }
    }
    // call_indirect refs.
    if !mark_call_indirect_types(&wm, &mut type_refs) {
        return;
    }

    // Internal-function check: prefer hints when given (closed-world);
    // else fall back to the conservative quartet.
    let exported: std::collections::HashSet<u32> =
        m.facts.exported_func_indices.iter().copied().collect();
    let reffed = if hints.is_some() {
        // Hints subsume ref.func discovery via is_internal; skip the scan.
        Default::default()
    } else {
        collect_ref_func_targets(&wm)
    };
    let is_internal = |abs_idx: u32| -> bool {
        if let Some(h) = hints {
            h.is_internal(abs_idx)
        } else {
            !exported.contains(&abs_idx)
                && !reffed.contains(&abs_idx)
                && m.facts.start_func != Some(abs_idx)
        }
    };

    // Pick a single candidate: first defined function that qualifies.
    let mut candidate: Option<Candidate> = None;
    for i in 0..m.num_bodies() {
        let abs_idx = num_imports + i as u32;
        if !is_internal(abs_idx) {
            continue;
        }
        let tidx = func_types[i];
        if type_refs[tidx as usize] != 1 {
            continue;
        }
        let type_entry = type_entry_bytes(&wm, tidx, &type_ends);
        let Some(type_info) = parse_func_type(type_entry) else {
            continue;
        };
        if type_info.param_count == 0 {
            continue;
        }
        let body = m.body_bytes(i);
        let (groups, _) = match leb128::read_u32(body) {
            Some(x) => x,
            None => continue,
        };
        if groups != 0 {
            continue;
        }
        if !param_unreferenced(body, type_info.param_count - 1) {
            continue;
        }

        let _ = type_info;
        candidate = Some(Candidate {
            abs_idx,
            type_idx: tidx,
        });
        break;
    }
    let Some(cand) = candidate else { return };

    // Apply: (1) shrink type entry, (2) insert drop before every
    // `call cand.abs_idx` in every body.
    if !rewrite_type_section(m, &wm, cand.type_idx, &type_ends, &cand) {
        return;
    }
    use rayon::prelude::*;
    let target = cand.abs_idx;
    let updates: Vec<(usize, Vec<u8>)> = (0..m.num_bodies())
        .into_par_iter()
        .filter_map(|i| insert_drops_before_call(m.body_bytes(i), target).map(|b| (i, b)))
        .collect();
    for (i, b) in updates {
        m.set_body(i, b);
    }
}

struct Candidate {
    abs_idx: u32,
    type_idx: u32,
}

struct ParsedFuncType {
    param_count: u32,
    param_count_leb_len: usize,
    last_param_byte_offset_in_entry: usize,
}

// ────── helpers ──────

fn read_type_ends(module: &WasmModule<'_>) -> Option<Vec<usize>> {
    let sec = module.section(wmod::SECTION_TYPE)?;
    let p = sec.payload.slice(module.data());
    let (count, mut off) = leb128::read_u32(p)?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if *p.get(off)? != 0x60 {
            return None;
        }
        off += 1;
        let (params, c) = leb128::read_u32(p.get(off..)?)?;
        off += c;
        for _ in 0..params {
            let vt = *p.get(off)?;
            if !matches!(vt, 0x7B..=0x7F | 0x6F | 0x70) {
                return None;
            }
            off += 1;
        }
        let (results, c) = leb128::read_u32(p.get(off..)?)?;
        off += c;
        for _ in 0..results {
            let vt = *p.get(off)?;
            if !matches!(vt, 0x7B..=0x7F | 0x6F | 0x70) {
                return None;
            }
            off += 1;
        }
        out.push(off);
    }
    (off == p.len()).then_some(out)
}

fn type_entry_bytes<'a>(module: &'a WasmModule<'_>, tidx: u32, ends: &[usize]) -> &'a [u8] {
    let sec = module.section(wmod::SECTION_TYPE).unwrap();
    let p = sec.payload.slice(module.data());
    let hdr = leb128::read_u32(p).unwrap().1;
    let start = if tidx == 0 {
        hdr
    } else {
        ends[(tidx - 1) as usize]
    };
    let end = ends[tidx as usize];
    &p[start..end]
}

/// Parse one func type entry (starting at 0x60). Returns info about
/// the last param's position within the entry so we can trim it.
fn parse_func_type(entry: &[u8]) -> Option<ParsedFuncType> {
    if *entry.get(0)? != 0x60 {
        return None;
    }
    let (params, c) = leb128::read_u32(entry.get(1..)?)?;
    let param_count_leb_len = c;
    let mut off = 1 + c;
    let first_param_byte = off;
    for _ in 0..params {
        off += 1;
    }
    let last_param_byte_offset = if params > 0 {
        off - 1
    } else {
        first_param_byte
    };
    Some(ParsedFuncType {
        param_count: params,
        param_count_leb_len,
        last_param_byte_offset_in_entry: last_param_byte_offset,
    })
}

fn read_defined_func_types(module: &WasmModule<'_>) -> Option<Vec<u32>> {
    let Some(sec) = module.section(wmod::SECTION_FUNCTION) else {
        return Some(Vec::new());
    };
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

fn read_import_func_types(payload: &[u8]) -> Option<Vec<u32>> {
    let (count, mut off) = leb128::read_u32(payload)?;
    let mut out = Vec::new();
    for _ in 0..count {
        let (ml, c) = leb128::read_u32(payload.get(off..)?)?;
        off = off.checked_add(c)?.checked_add(ml as usize)?;
        let (fl, c) = leb128::read_u32(payload.get(off..)?)?;
        off = off.checked_add(c)?.checked_add(fl as usize)?;
        let kind = *payload.get(off)?;
        off += 1;
        match kind {
            0x00 => {
                let (t, c) = leb128::read_u32(payload.get(off..)?)?;
                off += c;
                out.push(t);
            }
            0x01 => {
                off += 1;
                let flags = *payload.get(off)?;
                off += 1;
                let (_, c) = leb128::read_u32(payload.get(off..)?)?;
                off += c;
                if flags & 1 != 0 {
                    let (_, c) = leb128::read_u32(payload.get(off..)?)?;
                    off += c;
                }
            }
            0x02 => {
                let flags = *payload.get(off)?;
                off += 1;
                let (_, c) = leb128::read_u32(payload.get(off..)?)?;
                off += c;
                if flags & 1 != 0 {
                    let (_, c) = leb128::read_u32(payload.get(off..)?)?;
                    off += c;
                }
            }
            0x03 => off += 2,
            _ => return None,
        }
    }
    Some(out)
}

/// Scan every function body and mark every type index referenced by
/// `call_indirect` or by a block/loop/if blocktype that encodes a
/// type index. Returns false if any body can't be walked cleanly.
/// Collect every function index referenced by a `ref.func` opcode
/// anywhere in the module — inside code-section bodies, in element
/// segment init expressions, or in global init expressions. A function
/// in this set is callable via `call_indirect` through the table and
/// must keep its original signature.
fn collect_ref_func_targets(module: &WasmModule<'_>) -> std::collections::HashSet<u32> {
    let data = module.data();
    let mut out = std::collections::HashSet::new();

    // Body code: scan every ref.func (0xD2).
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

    // Element + global sections: reuse the shared const-expr scanner
    // (handles ref.func in init exprs and explicit funcidx vecs).
    if let Some(sec) = module.section(wmod::SECTION_ELEMENT) {
        if let Some(indices) = super::dce::scan_elements_funcidx(sec.payload.slice(data)) {
            out.extend(indices);
        }
    }
    if let Some(sec) = module.section(wmod::SECTION_GLOBAL) {
        let p = sec.payload.slice(data);
        if let Some((count, mut off)) = leb128::read_u32(p) {
            for _ in 0..count {
                if off + 2 > p.len() {
                    break;
                }
                off += 2;
                let Some((end, targets)) = super::dce::scan_const_expr(p, off) else {
                    break;
                };
                out.extend(targets);
                off = end;
            }
        }
    }

    out
}

fn mark_call_indirect_types(module: &WasmModule<'_>, refs: &mut [u32]) -> bool {
    let data = module.data();
    for body in module.function_bodies() {
        let b = body.body.slice(data);
        let Some(start) = opcode::skip_locals(b) else {
            return false;
        };
        let mut iter = InstrIter::new(b, start);
        while let Some((p, _)) = iter.next() {
            let op = b[p];
            match op {
                0x11 => {
                    let Some((t, _)) = leb128::read_u32(&b[p + 1..]) else {
                        return false;
                    };
                    if (t as usize) < refs.len() {
                        refs[t as usize] += 1;
                    }
                }
                0x02 | 0x03 | 0x04 => {
                    let Some((val, _)) = leb128::read_u32(&b[p + 1..]) else {
                        return false;
                    };
                    if val != 0x40 && !matches!(val as u8, 0x6F..=0x7F) {
                        if (val as usize) < refs.len() {
                            refs[val as usize] += 1;
                        }
                    }
                }
                _ => {}
            }
        }
        if iter.failed() {
            return false;
        }
    }
    true
}

fn param_unreferenced(body: &[u8], param_idx: u32) -> bool {
    let Some(start) = opcode::skip_locals(body) else {
        return false;
    };
    let mut iter = InstrIter::new(body, start);
    let mut referenced = false;
    while let Some((p, _)) = iter.next() {
        match body[p] {
            0x20 | 0x21 | 0x22 => {
                if let Some((n, _)) = leb128::read_u32(&body[p + 1..]) {
                    if n == param_idx {
                        referenced = true;
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    !iter.failed() && !referenced
}

fn rewrite_type_section(
    m: &mut MutModule<'_>,
    module: &WasmModule<'_>,
    type_idx: u32,
    ends: &[usize],
    cand: &Candidate,
) -> bool {
    let Some(sec_idx) = m.find_section(wmod::SECTION_TYPE) else {
        return false;
    };
    let sec = module.section(wmod::SECTION_TYPE).unwrap();
    let p = sec.payload.slice(module.data());

    let (_, hdr_len) = match leb128::read_u32(p) {
        Some(x) => x,
        None => return false,
    };
    let start = if type_idx == 0 {
        hdr_len
    } else {
        ends[(type_idx - 1) as usize]
    };
    let end = ends[type_idx as usize];
    let entry = &p[start..end];

    // Build new entry: 0x60 | new_param_count_leb | params[..-1] | rest.
    let Some(parsed) = parse_func_type(entry) else {
        return false;
    };
    let mut new_entry = Vec::with_capacity(entry.len());
    new_entry.push(0x60);
    leb128::write_u32(&mut new_entry, parsed.param_count - 1);
    let params_region_end = 1 + parsed.param_count_leb_len + parsed.param_count as usize;
    // Copy params except the last:
    new_entry.extend_from_slice(&entry[1 + parsed.param_count_leb_len..params_region_end - 1]);
    // Copy results region verbatim.
    new_entry.extend_from_slice(&entry[params_region_end..]);

    // Stitch new payload.
    let mut new_payload = Vec::with_capacity(p.len());
    // Keep the count LEB unchanged (type count doesn't change).
    new_payload.extend_from_slice(&p[..hdr_len]);
    // All type entries up to and including type_idx, with this one replaced.
    let mut prev_end = hdr_len;
    for (i, &e) in ends.iter().enumerate() {
        if i == type_idx as usize {
            new_payload.extend_from_slice(&new_entry);
        } else {
            new_payload.extend_from_slice(&p[prev_end..e]);
        }
        prev_end = e;
    }
    let _ = cand;
    m.set_section_payload(sec_idx, new_payload);
    true
}

fn insert_drops_before_call(body: &[u8], target: u32) -> Option<Vec<u8>> {
    let start = opcode::skip_locals(body)?;
    let mut iter = InstrIter::new(body, start);
    let mut hits: Vec<usize> = Vec::new();
    while let Some((p, _)) = iter.next() {
        if body[p] != 0x10 {
            continue;
        }
        if let Some((f, _)) = leb128::read_u32(&body[p + 1..]) {
            if f == target {
                hits.push(p);
            }
        }
    }
    if iter.failed() {
        return None;
    }
    if hits.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(body.len() + hits.len());
    let mut cursor = 0;
    for p in &hits {
        out.extend_from_slice(&body[cursor..*p]);
        out.push(0x1A); // drop
        cursor = *p;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_last_param_unreferenced() {
        // body: 0 local groups + local.get 0 + drop + end.
        // Param 0 referenced; param 1 not.
        let body = [0, 0x20, 0, 0x1A, 0x0B];
        assert!(param_unreferenced(&body, 1));
        assert!(!param_unreferenced(&body, 0));
    }

    #[test]
    fn parses_func_type_arities() {
        // 0x60 (param i32 i64) (result f32)
        let entry = [0x60, 2, 0x7F, 0x7E, 1, 0x7D];
        let p = parse_func_type(&entry).unwrap();
        assert_eq!(p.param_count, 2);
        assert_eq!(p.param_count_leb_len, 1);
        assert_eq!(p.last_param_byte_offset_in_entry, 3); // 0x7E
    }

    #[test]
    fn insert_drop_at_call_sites() {
        // body: nop; call 2; drop; end. Target func = 2.
        let body = [0, 0x01, 0x10, 2, 0x1A, 0x0B];
        let out = insert_drops_before_call(&body, 2).unwrap();
        // Expect a drop inserted before `call 2`.
        assert_eq!(out, vec![0, 0x01, 0x1A, 0x10, 2, 0x1A, 0x0B]);
    }

    #[test]
    fn insert_noop_when_no_callsite() {
        let body = [0, 0x01, 0x0B];
        assert!(insert_drops_before_call(&body, 0).is_none());
    }
}
