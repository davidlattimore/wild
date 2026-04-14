//! Wasm `name` custom section — parse, rewrite via `FuncRemap`,
//! re-emit.
//!
//! Format (wasm spec, "Names Section" appendix):
//!
//! ```text
//! name-section := "name" (subsection)*
//! subsection := subsection_id:byte size:u32 content:bytes
//!   0: module name       name:string
//!   1: function names    vec<(funcidx, name)>
//!   2: local names       vec<(funcidx, vec<(localidx, name)>)>
//!   3..=N: label/type/… newer subsections
//! ```
//!
//! Phase 1 handles subsections 0/1/2. Function indices in 1 and 2 are
//! remapped via `FuncRemap`; eliminated entries are dropped; when
//! multiple inputs merge to the same output, the first input's name
//! wins (deterministic — composition preserves original ordering).
//! Local indices inside subsection 2 pass through unchanged (Phase 2
//! will plumb `LocalRemap` once local renumbering lands in the
//! provenance machinery).
//!
//! Any subsection id ≥ 3 passes through **byte-identical**. The wasm
//! spec allows unknown subsections; LLVM emits subsection 4 (type
//! names) for GC-using modules, and more will land over time.

use crate::leb128;
use crate::remap::FuncRemap;

/// Rewrite a `name` custom section's payload using the supplied
/// FuncRemap. Returns `None` if the payload is malformed — caller
/// should pass the original bytes through in that case.
pub fn rewrite(payload: &[u8], remap: &FuncRemap) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(payload.len());
    let mut off = 0;
    while off < payload.len() {
        let sub_id = *payload.get(off)?;
        off += 1;
        let (sub_size, c) = leb128::read_u32(payload.get(off..)?)?;
        off += c;
        let sub_end = off.checked_add(sub_size as usize)?;
        if sub_end > payload.len() { return None; }
        let sub_content = &payload[off..sub_end];

        match sub_id {
            0 => {
                // Module name — no indices, pass through.
                emit_subsection(&mut out, sub_id, sub_content);
            }
            1 => {
                let rewritten = rewrite_function_names(sub_content, remap)?;
                if !rewritten.is_empty() {
                    emit_subsection(&mut out, sub_id, &rewritten);
                }
            }
            2 => {
                let rewritten = rewrite_local_names(sub_content, remap)?;
                if !rewritten.is_empty() {
                    emit_subsection(&mut out, sub_id, &rewritten);
                }
            }
            _ => {
                // Unknown or newer subsection — passthrough.
                emit_subsection(&mut out, sub_id, sub_content);
            }
        }
        off = sub_end;
    }
    Some(out)
}

fn emit_subsection(out: &mut Vec<u8>, sub_id: u8, content: &[u8]) {
    out.push(sub_id);
    leb128::write_u32(out, content.len() as u32);
    out.extend_from_slice(content);
}

/// `vec<(funcidx: u32, name: vec<byte>)>`. Rewrite funcidx via the
/// remap; drop entries whose funcidx was eliminated. If multiple
/// input entries collide on the same output index, keep the first
/// (deterministic and matches `by_output`'s canonical policy).
fn rewrite_function_names(content: &[u8], remap: &FuncRemap) -> Option<Vec<u8>> {
    let (count, mut off) = leb128::read_u32(content)?;
    let mut pairs: Vec<(u32, &[u8])> = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (idx, c) = leb128::read_u32(content.get(off..)?)?;
        off += c;
        let (nlen, c) = leb128::read_u32(content.get(off..)?)?;
        off += c;
        let name_end = off.checked_add(nlen as usize)?;
        if name_end > content.len() { return None; }
        let name = &content[off..name_end];
        off = name_end;

        if let Some(new_idx) = remap.lookup(idx) {
            pairs.push((new_idx, name));
        }
    }

    // Dedupe colliding output indices: keep first occurrence (by
    // input order, which is the byte order of the input section).
    pairs.sort_by_key(|&(idx, _)| idx);
    pairs.dedup_by_key(|&mut (idx, _)| idx);

    if pairs.is_empty() { return Some(Vec::new()); }

    let mut out = Vec::new();
    leb128::write_u32(&mut out, pairs.len() as u32);
    for (idx, name) in &pairs {
        leb128::write_u32(&mut out, *idx);
        leb128::write_u32(&mut out, name.len() as u32);
        out.extend_from_slice(name);
    }
    Some(out)
}

/// `vec<(funcidx: u32, vec<(localidx: u32, name: vec<byte>)>)>`.
/// Rewrite outer funcidx; local indices pass through.
fn rewrite_local_names(content: &[u8], remap: &FuncRemap) -> Option<Vec<u8>> {
    let (count, mut off) = leb128::read_u32(content)?;
    // Collect (funcidx, raw_locals_vec_bytes) so we can drop eliminated
    // funcs cheaply. Locals vec bytes are opaque to us here.
    let mut entries: Vec<(u32, &[u8])> = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (idx, c) = leb128::read_u32(content.get(off..)?)?;
        off += c;
        let (ncount, c) = leb128::read_u32(content.get(off..)?)?;
        // The inner vec runs from current off for ncount entries.
        let inner_start = off;
        off += c;
        for _ in 0..ncount {
            let (_lidx, c) = leb128::read_u32(content.get(off..)?)?;
            off += c;
            let (nlen, c) = leb128::read_u32(content.get(off..)?)?;
            off += c;
            off = off.checked_add(nlen as usize)?;
            if off > content.len() { return None; }
        }
        let inner_bytes = &content[inner_start..off];
        if let Some(new_idx) = remap.lookup(idx) {
            entries.push((new_idx, inner_bytes));
        }
    }

    entries.sort_by_key(|&(idx, _)| idx);
    entries.dedup_by_key(|&mut (idx, _)| idx);

    if entries.is_empty() { return Some(Vec::new()); }

    let mut out = Vec::new();
    leb128::write_u32(&mut out, entries.len() as u32);
    for (idx, inner) in &entries {
        leb128::write_u32(&mut out, *idx);
        out.extend_from_slice(inner);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_func_names(entries: &[(u32, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        leb128::write_u32(&mut out, entries.len() as u32);
        for (idx, name) in entries {
            leb128::write_u32(&mut out, *idx);
            leb128::write_u32(&mut out, name.len() as u32);
            out.extend_from_slice(name.as_bytes());
        }
        out
    }

    fn wrap_subsection(id: u8, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(id);
        leb128::write_u32(&mut out, content.len() as u32);
        out.extend_from_slice(content);
        out
    }

    #[test]
    fn passthrough_identity_keeps_all_names() {
        let fnames = build_func_names(&[(0, "foo"), (1, "bar")]);
        let payload = wrap_subsection(1, &fnames);
        let remap = FuncRemap::identity(2);
        let out = rewrite(&payload, &remap).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn remap_reorders_indices() {
        // input: foo=0, bar=1 → output: foo=1, bar=0 (swap).
        let fnames = build_func_names(&[(0, "foo"), (1, "bar")]);
        let payload = wrap_subsection(1, &fnames);
        let remap = FuncRemap::from_entries(vec![Some(1), Some(0)]);
        let out = rewrite(&payload, &remap).unwrap();

        let expected_inner = build_func_names(&[(0, "bar"), (1, "foo")]);
        let expected = wrap_subsection(1, &expected_inner);
        assert_eq!(out, expected);
    }

    #[test]
    fn eliminated_entries_vanish() {
        // input: foo=0, bar=1, baz=2 → foo survives, bar+baz dropped.
        let fnames = build_func_names(&[(0, "foo"), (1, "bar"), (2, "baz")]);
        let payload = wrap_subsection(1, &fnames);
        let remap = FuncRemap::from_entries(vec![Some(0), None, None]);
        let out = rewrite(&payload, &remap).unwrap();
        let expected_inner = build_func_names(&[(0, "foo")]);
        let expected = wrap_subsection(1, &expected_inner);
        assert_eq!(out, expected);
    }

    #[test]
    fn merged_entries_first_name_wins() {
        // input: 0 and 2 both map to 0; first input occurrence ("foo")
        // keeps the name in output.
        let fnames = build_func_names(&[(0, "foo"), (2, "baz")]);
        let payload = wrap_subsection(1, &fnames);
        let remap = FuncRemap::from_entries(vec![Some(0), None, Some(0)]);
        let out = rewrite(&payload, &remap).unwrap();
        let expected_inner = build_func_names(&[(0, "foo")]);
        let expected = wrap_subsection(1, &expected_inner);
        assert_eq!(out, expected);
    }

    #[test]
    fn empty_function_names_subsection_drops() {
        // All entries eliminated → subsection has 0 entries. We drop
        // the whole subsection rather than emit an empty one.
        let fnames = build_func_names(&[(0, "foo"), (1, "bar")]);
        let payload = wrap_subsection(1, &fnames);
        let remap = FuncRemap::from_entries(vec![None, None]);
        let out = rewrite(&payload, &remap).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn unknown_subsection_passes_through() {
        // Subsection 99 — should be preserved verbatim.
        let weird = vec![0xAAu8, 0xBB, 0xCC];
        let payload = wrap_subsection(99, &weird);
        let remap = FuncRemap::identity(0);
        let out = rewrite(&payload, &remap).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn module_name_survives() {
        // Subsection 0: just a name string.
        let mut sub0 = Vec::new();
        leb128::write_u32(&mut sub0, 4);
        sub0.extend_from_slice(b"myfn");
        let payload = wrap_subsection(0, &sub0);
        let remap = FuncRemap::identity(0);
        let out = rewrite(&payload, &remap).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn mixed_subsections_order_preserved() {
        // Emit 0, 1, 99 — order must stay.
        let sub0 = {
            let mut v = Vec::new();
            leb128::write_u32(&mut v, 3);
            v.extend_from_slice(b"mod");
            v
        };
        let sub1 = build_func_names(&[(0, "foo")]);
        let sub99 = vec![0x01, 0x02];
        let mut payload = Vec::new();
        payload.extend_from_slice(&wrap_subsection(0, &sub0));
        payload.extend_from_slice(&wrap_subsection(1, &sub1));
        payload.extend_from_slice(&wrap_subsection(99, &sub99));
        let remap = FuncRemap::identity(1);
        let out = rewrite(&payload, &remap).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn local_names_funcidx_remap() {
        // One entry for func 0 with local 0 named "x".
        let mut inner = Vec::new();
        leb128::write_u32(&mut inner, 1);        // local count
        leb128::write_u32(&mut inner, 0);        // local idx
        leb128::write_u32(&mut inner, 1);        // name length
        inner.push(b'x');

        let mut content = Vec::new();
        leb128::write_u32(&mut content, 1);      // func count
        leb128::write_u32(&mut content, 0);      // funcidx = 0
        content.extend_from_slice(&inner);

        let payload = wrap_subsection(2, &content);
        // 0 → 3
        let remap = FuncRemap::from_entries(vec![Some(3)]);
        let out = rewrite(&payload, &remap).unwrap();

        // Expected: same structure but funcidx=3.
        let mut expected_content = Vec::new();
        leb128::write_u32(&mut expected_content, 1);
        leb128::write_u32(&mut expected_content, 3);
        expected_content.extend_from_slice(&inner);
        let expected = wrap_subsection(2, &expected_content);
        assert_eq!(out, expected);
    }

    #[test]
    fn malformed_returns_none() {
        // Subsection claims size 100 but only 3 bytes follow.
        let payload = vec![1u8, 100, 0x00, 0x00, 0x00];
        let remap = FuncRemap::identity(0);
        assert!(rewrite(&payload, &remap).is_none());
    }
}
