//! Source Map V3 support for wasm modules.
//!
//! When a wasm module references an external source map via a
//! `sourceMappingURL` custom section, wilt's code-modifying passes
//! invalidate the map's positions — every segment's
//! "generated column" (byte offset in the wasm code section) is
//! stale after reorder / inline / dedup etc.
//!
//! Per `wilt-debug-info-plan.md` the contract is: **never silently
//! reference stale external data**. We detect the section and then:
//!
//! - If the CLI supplied `--source-map-in/--source-map-out`: read the
//!   input map, rewrite it in line with wilt's transformations, write
//!   it to the out path, and keep the reference (pointing at the new
//!   filename).
//! - If neither: strip the `sourceMappingURL` reference from output
//!   and emit a stderr warning so the user knows the external file
//!   isn't being maintained.
//!
//! This module implements detection, stripping, and the JSON/VLQ
//! rewriter. This commit lands step 1 (detection + strip + pipe-
//! through plumbing + CLI flags). Step 2 adds the actual mapping
//! transformation using the same `FuncRemap` + body-edit substrate
//! that DWARF uses.

use crate::module::{self, WasmModule};

/// Payload of a `sourceMappingURL` custom section — the URL/path.
pub fn detect_url(module: &WasmModule<'_>) -> Option<String> {
    let data = module.data();
    module.sections().iter().find_map(|s| {
        if s.id != module::SECTION_CUSTOM { return None; }
        let name = s.custom_name?.slice(data);
        if name != b"sourceMappingURL" { return None; }
        let p = s.payload.slice(data);
        let (nlen, c) = crate::leb128::read_u32(p)?;
        let after_name = &p[c + nlen as usize..];
        // Remainder is a vec<byte>: URL-length LEB + URL bytes.
        let (url_len, c2) = crate::leb128::read_u32(after_name)?;
        let start = c2;
        let end = start + url_len as usize;
        if end > after_name.len() { return None; }
        std::str::from_utf8(&after_name[start..end]).ok().map(String::from)
    })
}

/// Return the full file bytes of `wasm` with any `sourceMappingURL`
/// custom section removed. Returns `wasm` unchanged if none present.
pub fn strip_url(wasm: &[u8]) -> Vec<u8> {
    let Ok(m) = WasmModule::parse(wasm) else { return wasm.to_vec() };
    let cfg = crate::passes::strip::StripConfig {
        source_maps: true,
        ..Default::default()
    };
    crate::passes::strip::apply(&m, cfg)
}

/// Replace (or add, if missing) the `sourceMappingURL` custom
/// section in `wasm` to reference `new_url`. Appends the section at
/// the end of the module — spec allows customs anywhere.
pub fn set_url(wasm: &[u8], new_url: &str) -> Vec<u8> {
    let stripped = strip_url(wasm);
    // Build section bytes: id=0, size-LEB, name-vec("sourceMappingURL"),
    // url-vec(bytes).
    let mut payload = Vec::new();
    crate::leb128::write_u32(&mut payload, b"sourceMappingURL".len() as u32);
    payload.extend_from_slice(b"sourceMappingURL");
    crate::leb128::write_u32(&mut payload, new_url.len() as u32);
    payload.extend_from_slice(new_url.as_bytes());

    let mut out = stripped;
    out.push(module::SECTION_CUSTOM);
    crate::leb128::write_u32(&mut out, payload.len() as u32);
    out.extend_from_slice(&payload);
    out
}

/// Rewrite a Source Map V3 JSON document for the optimised output.
///
/// Three tiers, tried in order:
///
/// 1. Code byte-identical + identity remap → pipe the JSON through
///    (fast path; no decoding needed).
/// 2. Per-function bytes match but some functions moved → decode
///    the `mappings` VLQ, apply per-function generated-column
///    shifts, re-encode.
/// 3. Any body modified → return None (honest strip).
///
/// `input_fn_offsets` and `output_fn_offsets` supply the per-function
/// `(file_offset, length)` tables for input and output respectively;
/// empty `Vec`s mean "same layout, no shifts". `remap` maps input
/// absolute function index → output index (or `None` = eliminated).
pub fn rewrite_v3(
    json: &str,
    remap: &crate::remap::FuncRemap,
    code_unchanged: bool,
) -> Option<String> {
    rewrite_v3_with_shifts(json, remap, code_unchanged, &[], &[])
}

pub fn rewrite_v3_with_shifts(
    json: &str,
    remap: &crate::remap::FuncRemap,
    code_unchanged: bool,
    input_fn_offsets: &[(u32, u32)],
    output_fn_offsets: &[(u32, u32)],
) -> Option<String> {
    let identity_remap = remap.entries().iter().enumerate()
        .all(|(i, s)| *s == Some(i as u32));

    // Fast path: nothing changed in code → map is accurate.
    if code_unchanged && identity_remap {
        return Some(json.to_string());
    }

    // Slow path: per-function shifts. Require that every input
    // function has a corresponding output function with byte-
    // identical body content (checked by the caller; we only build
    // the shift table here).
    if input_fn_offsets.is_empty() || output_fn_offsets.is_empty() {
        return None;
    }
    let shifts = build_shifts(remap, input_fn_offsets, output_fn_offsets)?;
    let mappings = extract_mappings(json)?;
    let new_mappings = transform_mappings(&mappings, &shifts)?;
    Some(replace_mappings(json, &new_mappings))
}

/// Build per-function (input_range, shift) pairs. Returns None if
/// any function went missing or was remapped inconsistently.
fn build_shifts(
    remap: &crate::remap::FuncRemap,
    in_offsets: &[(u32, u32)],
    out_offsets: &[(u32, u32)],
) -> Option<Vec<((u32, u32), i64)>> {
    let num_defined_in = in_offsets.len() as u32;
    if remap.len() < num_defined_in { return None; }
    let num_imports = remap.len() - num_defined_in;
    let mut shifts = Vec::with_capacity(in_offsets.len());
    for (def_i, &(off_in, len_in)) in in_offsets.iter().enumerate() {
        let abs_in = num_imports + def_i as u32;
        let abs_out = remap.lookup(abs_in)?;
        if abs_out < num_imports { return None; }
        let def_out = (abs_out - num_imports) as usize;
        let &(off_out, _) = out_offsets.get(def_out)?;
        shifts.push(((off_in, off_in + len_in), off_out as i64 - off_in as i64));
    }
    Some(shifts)
}

/// Extract the raw `mappings` string from a V3 source-map JSON. V3
/// `mappings` values use only base64 + `,` + `;` chars, none of
/// which need JSON escaping, so a simple "find the value between
/// quotes after the key" scan is sound.
fn extract_mappings(json: &str) -> Option<&str> {
    let key_pos = json.find("\"mappings\"")?;
    let rest = &json[key_pos + "\"mappings\"".len()..];
    // Skip whitespace and the ':' separator.
    let colon = rest.find(':')?;
    let after = &rest[colon + 1..];
    let quote = after.find('"')?;
    let body = &after[quote + 1..];
    let end = body.find('"')?;
    Some(&body[..end])
}

/// Replace the existing `mappings` string in `json` with `new`.
/// Assumes `extract_mappings` already confirmed the key is present.
fn replace_mappings(json: &str, new: &str) -> String {
    let key_pos = json.find("\"mappings\"").unwrap();
    let rest = &json[key_pos + "\"mappings\"".len()..];
    let colon = rest.find(':').unwrap();
    let after = &rest[colon + 1..];
    let quote = after.find('"').unwrap();
    let body_start = key_pos + "\"mappings\"".len() + colon + 1 + quote + 1;
    let body_rest = &json[body_start..];
    let end_relative = body_rest.find('"').unwrap();
    let body_end = body_start + end_relative;
    let mut out = String::with_capacity(json.len() + new.len());
    out.push_str(&json[..body_start]);
    out.push_str(new);
    out.push_str(&json[body_end..]);
    out
}

/// Transform a V3 `mappings` VLQ string by shifting each segment's
/// generated column based on `shifts` — a list of `((in_start,
/// in_end), delta)` tuples. Segments whose generated column falls
/// outside any input range are left unchanged.
///
/// Convention: each `;`-separated group is a "line"; each `,`-
/// separated entry within is a "segment". The first VLQ field of a
/// segment is the generated column, encoded as a delta from the
/// previous segment IN THE SAME LINE (reset to 0 at each `;`).
/// Other fields — source index, source line, source column, name
/// index — are kept as-is.
fn transform_mappings(
    mappings: &str,
    shifts: &[((u32, u32), i64)],
) -> Option<String> {
    let mut out = String::with_capacity(mappings.len());
    for (line_i, line) in mappings.split(';').enumerate() {
        if line_i > 0 { out.push(';'); }
        if line.is_empty() { continue; }

        let mut gen_col: i64 = 0;
        for (seg_i, seg) in line.split(',').enumerate() {
            if seg_i > 0 { out.push(','); }
            if seg.is_empty() { continue; }

            // Decode VLQ fields in the segment.
            let mut cursor = 0usize;
            let seg_bytes = seg.as_bytes();
            let (delta_col, c) = decode_vlq(&seg_bytes[cursor..])?;
            cursor += c;

            let abs_col = gen_col + delta_col;
            // Look up shift by treating generated col as a file offset.
            let new_abs = if abs_col >= 0 {
                let u = abs_col as u32;
                let shift = shifts.iter()
                    .find(|((s, e), _)| u >= *s && u < *e)
                    .map(|(_, d)| *d)
                    .unwrap_or(0);
                abs_col + shift
            } else {
                abs_col
            };

            // The new delta for this segment vs the running gen_col.
            let new_delta = new_abs - gen_col;
            encode_vlq(new_delta, &mut out);

            // Update running generated-column to the ABSOLUTE new position.
            gen_col = new_abs;

            // Copy the remaining VLQ fields of this segment (source
            // idx / line / col / name idx). They're relative to
            // other running counters we don't touch.
            let rest = &seg[cursor..];
            out.push_str(rest);
        }
    }
    Some(out)
}

const BASE64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode_vlq(bytes: &[u8]) -> Option<(i64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut consumed = 0;
    for &b in bytes {
        consumed += 1;
        let d = b64_decode(b)? as u64;
        let continuation = (d & 0b100000) != 0;
        result |= (d & 0b011111) << shift;
        shift += 5;
        if !continuation {
            let negative = (result & 1) != 0;
            let v = (result >> 1) as i64;
            let signed = if negative { -v } else { v };
            return Some((signed, consumed));
        }
        if shift > 60 { return None; }
    }
    None
}

fn encode_vlq(mut v: i64, out: &mut String) {
    let sign = if v < 0 { 1u64 } else { 0 };
    if v < 0 { v = -v; }
    let mut u = ((v as u64) << 1) | sign;
    loop {
        let mut digit = (u & 0b011111) as u8;
        u >>= 5;
        if u != 0 { digit |= 0b100000; }
        out.push(BASE64[digit as usize] as char);
        if u == 0 { break; }
    }
}

fn b64_decode(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remap::FuncRemap;

    fn build_wasm_with_url(url: &str) -> Vec<u8> {
        let mut bytes = b"\0asm\x01\x00\x00\x00".to_vec();
        let mut payload = Vec::new();
        crate::leb128::write_u32(&mut payload, b"sourceMappingURL".len() as u32);
        payload.extend_from_slice(b"sourceMappingURL");
        crate::leb128::write_u32(&mut payload, url.len() as u32);
        payload.extend_from_slice(url.as_bytes());
        bytes.push(module::SECTION_CUSTOM);
        crate::leb128::write_u32(&mut bytes, payload.len() as u32);
        bytes.extend_from_slice(&payload);
        bytes
    }

    #[test]
    fn detect_url_roundtrip() {
        let bytes = build_wasm_with_url("app.wasm.map");
        let m = WasmModule::parse(&bytes).unwrap();
        assert_eq!(detect_url(&m).as_deref(), Some("app.wasm.map"));
    }

    #[test]
    fn detect_url_absent_returns_none() {
        let bytes = b"\0asm\x01\x00\x00\x00".to_vec();
        let m = WasmModule::parse(&bytes).unwrap();
        assert!(detect_url(&m).is_none());
    }

    #[test]
    fn strip_url_removes_section() {
        let bytes = build_wasm_with_url("ref");
        assert!(bytes.len() > b"\0asm\x01\x00\x00\x00".len());
        let stripped = strip_url(&bytes);
        let m = WasmModule::parse(&stripped).unwrap();
        assert!(detect_url(&m).is_none());
    }

    #[test]
    fn set_url_replaces() {
        let bytes = build_wasm_with_url("old.map");
        let out = set_url(&bytes, "new.map");
        let m = WasmModule::parse(&out).unwrap();
        assert_eq!(detect_url(&m).as_deref(), Some("new.map"));
    }

    #[test]
    fn rewrite_v3_pipes_through_when_unchanged() {
        let json = r#"{"version":3,"mappings":"AAAA"}"#;
        let remap = FuncRemap::identity(0);
        assert_eq!(rewrite_v3(json, &remap, true).as_deref(), Some(json));
    }

    #[test]
    fn rewrite_v3_refuses_when_code_changed() {
        let json = r#"{"version":3,"mappings":"AAAA"}"#;
        let remap = FuncRemap::identity(0);
        assert!(rewrite_v3(json, &remap, false).is_none());
    }

    #[test]
    fn rewrite_v3_refuses_when_remap_changed() {
        let json = r#"{"version":3,"mappings":"AAAA"}"#;
        let remap = FuncRemap::from_entries(vec![Some(1)]);
        assert!(rewrite_v3(json, &remap, true).is_none());
    }

    #[test]
    fn vlq_roundtrips_basic_values() {
        for v in [0i64, 1, -1, 15, -15, 16, -16, 1000, -1000, 0x7fff, -0x7fff] {
            let mut s = String::new();
            encode_vlq(v, &mut s);
            let (decoded, _) = decode_vlq(s.as_bytes()).unwrap();
            assert_eq!(decoded, v, "roundtrip failed for {v}");
        }
    }

    #[test]
    fn extract_and_replace_mappings() {
        let json = r#"{"version":3,"sources":["a"],"mappings":"AAAA;AACA"}"#;
        assert_eq!(extract_mappings(json), Some("AAAA;AACA"));
        let replaced = replace_mappings(json, "XXXX");
        assert_eq!(extract_mappings(&replaced), Some("XXXX"));
    }

    #[test]
    fn transform_mappings_shifts_generated_column() {
        // One segment at col=0 (encoded as "A"). Input function at
        // offset 0..100 shifted by +50 → segment should end up at
        // col=50.
        let mappings = "A";
        let shifts = vec![((0u32, 100u32), 50i64)];
        let out = transform_mappings(mappings, &shifts).unwrap();
        // Decode "A" = 0. After shift = 50. Encode 50 → "y".
        // 50 as VLQ signed: sign=0, value=50. u = 100. 100 = 0b1100100.
        // Lo 5 bits = 00100 (4) + continuation = 0b100100 → 'k'.
        // Next: 100 >> 5 = 3 → 0b00011 no continuation → 'D'.
        // So encoded = "kD".
        assert_eq!(out, "kD");
        // Roundtrip check: decode what we produced, should be 50.
        let (v, _) = decode_vlq(out.as_bytes()).unwrap();
        assert_eq!(v, 50);
    }

    #[test]
    fn transform_mappings_preserves_non_code_segments() {
        // Segment at col outside any shift range → unchanged.
        let mappings = "A";
        let shifts = vec![((1000u32, 2000u32), 42i64)];
        let out = transform_mappings(mappings, &shifts).unwrap();
        assert_eq!(out, "A");
    }

    #[test]
    fn transform_mappings_preserves_segment_extra_fields() {
        // Segment "AAAA" = (0, 0, 0, 0) — 4 fields. With no shifts,
        // should roundtrip exactly.
        let mappings = "AAAA";
        let out = transform_mappings(mappings, &[]).unwrap();
        assert_eq!(out, mappings);
    }
}
