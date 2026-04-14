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
/// Today's implementation is **pipe-through**: returns the map
/// unchanged. Step 2 will apply per-function generated-column
/// transformations keyed on `FuncRemap` + input/output code section
/// layouts. For the pipe-through version to be *honest*, callers
/// must only invoke this when wilt's pipeline produced no changes
/// that would invalidate the map. The current gate: identity remap
/// and code section byte-identical (i.e. nothing changed in code).
pub fn rewrite_v3(
    json: &str,
    remap: &crate::remap::FuncRemap,
    code_unchanged: bool,
) -> Option<String> {
    if !code_unchanged { return None; }
    if !remap.entries().iter().enumerate().all(|(i, s)| *s == Some(i as u32)) {
        return None;
    }
    Some(json.to_string())
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
}
