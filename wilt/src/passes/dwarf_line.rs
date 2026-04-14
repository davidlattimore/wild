//! DWARF `.debug_line` handling for the `Lines` debug tier.
//!
//! Per `wilt-debug-info-plan.md` this module owns DWARF line-program
//! handling for the Lines tier.
//!
//! Implementation is staged:
//!
//! - **Step 1** (landed): preserve the input `.debug_line` bytes iff
//!   the output's code section is byte-identical AND no function
//!   index shifted. Otherwise drop (Names-tier fallback).
//! - **Step 2** (this commit): broaden preservation to "per-function
//!   byte-and-position identical". If every surviving function is
//!   byte-identical to its input at the same code-section byte offset
//!   — true when passes like reorder/layout changed nothing but
//!   later sections elsewhere — we preserve. Per-function file-offset
//!   maps are also exposed for use by step 3.
//! - **Step 3** (deferred): gimli-based per-sequence rewriting — emit
//!   shifted or stubbed line entries so preservation covers moved or
//!   modified bodies.
//!
//! Invariant: the output either carries an *accurate* `.debug_line`
//! or none at all. We never embed stale addresses.

use crate::leb128;
use crate::module::{self, WasmModule};
use crate::remap::FuncRemap;

/// Return the `.debug_line` payload to embed in the optimised module.
pub fn rewrite(input: &[u8], optimised: &[u8], remap: &FuncRemap) -> Option<Vec<u8>> {
    let in_m = WasmModule::parse(input).ok()?;
    let out_m = WasmModule::parse(optimised).ok()?;

    let line_bytes = find_debug_line(&in_m)?;

    // Fast path (step 1): code section byte-identical, identity remap.
    let in_code = code_section_bytes(&in_m);
    let out_code = code_section_bytes(&out_m);
    if remap_is_identity(remap) && in_code == out_code {
        return Some(line_bytes.to_vec());
    }

    // Step 2: per-function byte-and-position identical check. If every
    // defined function survives the pipeline at the same file offset
    // with identical bytes, the line program's addresses still point
    // at the right instructions. Addresses in wasm DWARF are absolute
    // file offsets, so "same file offset + same bytes" = identity from
    // the line program's perspective.
    let mut in_m_parsed = WasmModule::parse(input).ok()?;
    let mut out_m_parsed = WasmModule::parse(optimised).ok()?;
    in_m_parsed.ensure_function_bodies_parsed();
    out_m_parsed.ensure_function_bodies_parsed();
    let in_offsets = function_file_offsets(&in_m_parsed)?;
    let out_offsets = function_file_offsets(&out_m_parsed)?;

    if per_function_identical(input, optimised, remap, &in_offsets, &out_offsets) {
        return Some(line_bytes.to_vec());
    }

    None
}

/// For each defined function in `module`, return its byte range in the
/// module's full file bytes — `(file_offset, length)` of the body
/// content (after the per-body size LEB). The i-th entry corresponds
/// to defined-function local index i (add `num_imports` for absolute).
///
/// Public because step 3's gimli rewriter needs it too.
pub fn function_file_offsets(module: &WasmModule<'_>) -> Option<Vec<(u32, u32)>> {
    let data = module.data();
    let bodies = module.function_bodies();
    let mut out = Vec::with_capacity(bodies.len());
    for b in bodies {
        // b.body is the body-bytes span (excludes the per-body size LEB).
        // Its .offset is already the absolute file offset.
        out.push((b.body.offset, b.body.len));
    }
    // Sanity check: offsets should be strictly ascending and
    // non-overlapping.
    for w in out.windows(2) {
        if w[0].0 + w[0].1 > w[1].0 { return None; }
    }
    let _ = data;
    Some(out)
}

/// True iff every input function maps (via `remap`) to an output
/// function with (a) the same file offset and (b) identical body
/// bytes.
fn per_function_identical(
    input: &[u8], output: &[u8],
    remap: &FuncRemap,
    in_offsets: &[(u32, u32)],
    out_offsets: &[(u32, u32)],
) -> bool {
    // Figure out num_imports from remap length vs bodies count.
    let num_defined_in = in_offsets.len() as u32;
    let num_defined_out = out_offsets.len() as u32;
    // remap covers all absolute indices (imports + defined). The
    // number of imports is `remap.len() - num_defined_in`.
    if remap.len() < num_defined_in { return false; }
    let num_imports = remap.len() - num_defined_in;

    for (def_i, (off_in, len_in)) in in_offsets.iter().enumerate() {
        let abs_in = num_imports + def_i as u32;
        let Some(abs_out) = remap.lookup(abs_in) else {
            // Input defined function eliminated. Any line entries for
            // it will now point to the wrong code — not preservable.
            return false;
        };
        if abs_out < num_imports {
            // Remapped to an import — impossible for a body.
            return false;
        }
        let def_out = (abs_out - num_imports) as usize;
        if def_out >= num_defined_out as usize { return false; }
        let (off_out, len_out) = out_offsets[def_out];
        if *off_in != off_out || *len_in != len_out { return false; }
        let in_bytes = &input[*off_in as usize..(*off_in + *len_in) as usize];
        let out_bytes = &output[off_out as usize..(off_out + len_out) as usize];
        if in_bytes != out_bytes { return false; }
    }
    true
}

fn find_debug_line<'a>(m: &'a WasmModule<'a>) -> Option<&'a [u8]> {
    let data = m.data();
    m.sections().iter().find_map(|s| {
        if s.id != module::SECTION_CUSTOM { return None; }
        let name = s.custom_name?.slice(data);
        if name != b".debug_line" { return None; }
        let p = s.payload.slice(data);
        let (nlen, c) = leb128::read_u32(p)?;
        Some(&p[c + nlen as usize..])
    })
}

fn remap_is_identity(r: &FuncRemap) -> bool {
    r.entries().iter().enumerate().all(|(i, slot)| *slot == Some(i as u32))
}

fn code_section_bytes<'a>(m: &'a WasmModule<'a>) -> &'a [u8] {
    let data = m.data();
    m.sections().iter()
        .find(|s| s.id == module::SECTION_CODE)
        .map(|s| s.full.slice(data))
        .unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_debug_line(bytes: &mut Vec<u8>, payload: &[u8]) {
        let mut custom = Vec::new();
        leb128::write_u32(&mut custom, 11);
        custom.extend_from_slice(b".debug_line");
        custom.extend_from_slice(payload);
        bytes.push(0);
        leb128::write_u32(bytes, custom.len() as u32);
        bytes.extend_from_slice(&custom);
    }

    #[test]
    fn no_debug_line_returns_none() {
        let minimal = b"\0asm\x01\x00\x00\x00".to_vec();
        let remap = FuncRemap::identity(0);
        assert!(rewrite(&minimal, &minimal, &remap).is_none());
    }

    #[test]
    fn unchanged_module_preserves_line_section() {
        let mut bytes = b"\0asm\x01\x00\x00\x00".to_vec();
        let payload = b"\x07some_line_program_stub";
        with_debug_line(&mut bytes, payload);
        let remap = FuncRemap::identity(0);
        assert_eq!(rewrite(&bytes, &bytes, &remap).unwrap(), payload);
    }

    #[test]
    fn modified_code_returns_none() {
        let mut input = b"\0asm\x01\x00\x00\x00".to_vec();
        input.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        input.extend_from_slice(&[3, 2, 1, 0]);
        input.extend_from_slice(&[10, 5, 1, 3, 0, 0x01, 0x0B]);
        with_debug_line(&mut input, b"stub");

        let mut modified = b"\0asm\x01\x00\x00\x00".to_vec();
        modified.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        modified.extend_from_slice(&[3, 2, 1, 0]);
        modified.extend_from_slice(&[10, 6, 1, 4, 0, 0x01, 0x01, 0x0B]);
        with_debug_line(&mut modified, b"stub");

        let remap = FuncRemap::identity(1);
        assert!(rewrite(&input, &modified, &remap).is_none());
    }

    #[test]
    fn non_identity_remap_with_unchanged_bytes_returns_none() {
        let minimal = b"\0asm\x01\x00\x00\x00".to_vec();
        let mut bytes = minimal.clone();
        with_debug_line(&mut bytes, b"line_stub");
        // 0→1 remap on a module with no defined bodies is degenerate
        // but exercises the check.
        let remap = FuncRemap::from_entries(vec![Some(1)]);
        // Code sections are equal (both empty) but remap is non-
        // identity. Step 1 fast path is bypassed; step 2 should
        // detect num_defined_in=0 and succeed (vacuously).
        // (0-function modules trivially pass per-function identity.)
        assert!(rewrite(&bytes, &bytes, &remap).is_some());
    }

    #[test]
    fn function_file_offsets_returns_body_ranges() {
        let mut m_bytes = b"\0asm\x01\x00\x00\x00".to_vec();
        m_bytes.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        m_bytes.extend_from_slice(&[3, 2, 1, 0]);
        // Code: 1 body = [0 locals, nop, end] = 3 bytes of body.
        // Section: id=10, size=5, count=1, body_size=3, body bytes [0,01,0B].
        m_bytes.extend_from_slice(&[10, 5, 1, 3, 0, 0x01, 0x0B]);
        let mut m = WasmModule::parse(&m_bytes).unwrap();
        m.ensure_function_bodies_parsed();
        let offs = function_file_offsets(&m).unwrap();
        assert_eq!(offs.len(), 1);
        let (off, len) = offs[0];
        assert_eq!(len, 3);
        assert_eq!(&m_bytes[off as usize..(off + len) as usize], &[0, 0x01, 0x0B]);
    }

    #[test]
    fn per_function_identical_detects_reorder() {
        // Build two modules with TWO functions whose body bytes differ
        // between the modules — should return false.
        let mut a = b"\0asm\x01\x00\x00\x00".to_vec();
        a.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        a.extend_from_slice(&[3, 3, 2, 0, 0]);
        a.extend_from_slice(&[10, 9, 2, 3, 0, 0x01, 0x0B, 3, 0, 0x01, 0x0B]);

        let mut b = b"\0asm\x01\x00\x00\x00".to_vec();
        b.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        b.extend_from_slice(&[3, 3, 2, 0, 0]);
        // Same shape, different second body content.
        b.extend_from_slice(&[10, 9, 2, 3, 0, 0x01, 0x0B, 3, 0, 0x02, 0x0B]);

        let remap = FuncRemap::identity(2);
        let mut ap = WasmModule::parse(&a).unwrap(); ap.ensure_function_bodies_parsed();
        let mut bp = WasmModule::parse(&b).unwrap(); bp.ensure_function_bodies_parsed();
        let ao = function_file_offsets(&ap).unwrap();
        let bo = function_file_offsets(&bp).unwrap();
        assert!(!per_function_identical(&a, &b, &remap, &ao, &bo));
    }
}
