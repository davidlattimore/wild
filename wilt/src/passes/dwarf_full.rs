//! DWARF `Full` debug tier — preservation and rewriting of the full
//! `.debug_*` section set (type info, variable names, scopes, ranges,
//! location lists, …) beyond just `.debug_line`.
//!
//! This sits at the top of the tier ladder:
//!
//! - `None`   : strip everything.
//! - `Names`  : rewrite the `name` section.
//! - `Lines`  : Names + rewrite `.debug_line`.
//! - `Full`   : Lines + preserve-or-rewrite the rest of the DWARF
//!              sections that reference code addresses.
//!
//! Implementation staged (mirrors Phase 2b's structure):
//!
//! - **Step 1** (this commit): preserve-if-accurate. When the code
//!   section is byte-identical to the input's AND the FuncRemap is
//!   identity, every input `.debug_*` section is still correct —
//!   preserve them verbatim. Any deviation and we drop all debug
//!   sections except `.debug_line` (which the Lines-tier machinery
//!   handles independently).
//! - **Step 2** (deferred): per-function byte-level address patching
//!   of `.debug_info` / `.debug_ranges` / `.debug_loc` for the
//!   "bodies byte-identical, some moved" case.
//! - **Step 3** (deferred): gimli write-API re-emission for the
//!   "some bodies modified" case, dropping DIEs whose subprograms
//!   lost their bodies.
//!
//! Invariant: no stale addresses ever reach the output.

use crate::module::{self, WasmModule};
use crate::remap::FuncRemap;

/// The DWARF custom sections whose contents reference code addresses
/// and therefore need to be either preserved verbatim (code-identical
/// case) or rewritten (future steps).
const CODE_REFERENCING: &[&str] = &[
    ".debug_info",
    ".debug_ranges",
    ".debug_rnglists",
    ".debug_loc",
    ".debug_loclists",
    ".debug_aranges",
    ".debug_addr",
];

/// DWARF sections that carry no code addresses — always safe to
/// preserve verbatim when their referencing sections are preserved.
const NON_ADDRESS: &[&str] = &[
    ".debug_abbrev",
    ".debug_str",
    ".debug_line_str",
    ".debug_str_offsets",
    ".debug_macinfo",
    ".debug_macro",
    ".debug_names",
    ".debug_pubnames",
    ".debug_pubtypes",
];

/// Returned by `preserve_full_debug` when the input's full DWARF can
/// be embedded in the output verbatim. Each pair is
/// `(custom_section_name, payload_bytes)`.
pub struct PreservedDebug {
    pub sections: Vec<(String, Vec<u8>)>,
}

/// Decide whether the Full-tier DWARF sections from `input` can be
/// preserved in `optimised`. Returns `Some(preserved)` when yes.
///
/// Today's criterion (step 1): code section byte-identical AND
/// identity FuncRemap. Wider criteria land in follow-up steps.
pub fn preserve_full_debug(
    input: &[u8], optimised: &[u8], remap: &FuncRemap,
) -> Option<PreservedDebug> {
    let in_m = WasmModule::parse(input).ok()?;
    let out_m = WasmModule::parse(optimised).ok()?;

    // Gate: any discrepancy → None (caller strips the whole bundle).
    if !remap_is_identity(remap) { return None; }
    if code_section_bytes(&in_m) != code_section_bytes(&out_m) { return None; }

    // Collect every `.debug_*` custom section (bar `.debug_line` —
    // Lines tier owns that one).
    let in_data = in_m.data();
    let mut sections = Vec::new();
    for s in in_m.sections() {
        if s.id != module::SECTION_CUSTOM { continue; }
        let Some(name_span) = s.custom_name else { continue };
        let name_bytes = name_span.slice(in_data);
        let Ok(name) = std::str::from_utf8(name_bytes) else { continue };
        if name == ".debug_line" { continue; }
        if !is_debug_section(name) { continue; }

        // Extract the payload content (everything after the name vec).
        let p = s.payload.slice(in_data);
        let Some((nlen, c)) = crate::leb128::read_u32(p) else { continue };
        let start = c + nlen as usize;
        if start > p.len() { continue; }
        sections.push((name.to_string(), p[start..].to_vec()));
    }
    Some(PreservedDebug { sections })
}

fn is_debug_section(name: &str) -> bool {
    CODE_REFERENCING.contains(&name) || NON_ADDRESS.contains(&name)
        || name.starts_with(".debug_")
}

fn remap_is_identity(r: &FuncRemap) -> bool {
    r.entries().iter().enumerate().all(|(i, s)| *s == Some(i as u32))
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
    use crate::leb128;

    fn with_custom(bytes: &mut Vec<u8>, name: &str, payload: &[u8]) {
        let mut section = Vec::new();
        leb128::write_u32(&mut section, name.len() as u32);
        section.extend_from_slice(name.as_bytes());
        section.extend_from_slice(payload);
        bytes.push(module::SECTION_CUSTOM);
        leb128::write_u32(bytes, section.len() as u32);
        bytes.extend_from_slice(&section);
    }

    #[test]
    fn unchanged_module_preserves_all_debug_sections() {
        let mut bytes = b"\0asm\x01\x00\x00\x00".to_vec();
        with_custom(&mut bytes, ".debug_info", b"di-stub");
        with_custom(&mut bytes, ".debug_str", b"ds-stub");
        with_custom(&mut bytes, ".debug_ranges", b"dr-stub");

        let remap = FuncRemap::identity(0);
        let preserved = preserve_full_debug(&bytes, &bytes, &remap).unwrap();
        assert_eq!(preserved.sections.len(), 3);
        let names: Vec<&str> = preserved.sections.iter()
            .map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&".debug_info"));
        assert!(names.contains(&".debug_str"));
        assert!(names.contains(&".debug_ranges"));
    }

    #[test]
    fn skip_debug_line_left_to_lines_tier() {
        let mut bytes = b"\0asm\x01\x00\x00\x00".to_vec();
        with_custom(&mut bytes, ".debug_line", b"line-stub");
        with_custom(&mut bytes, ".debug_info", b"info-stub");

        let remap = FuncRemap::identity(0);
        let preserved = preserve_full_debug(&bytes, &bytes, &remap).unwrap();
        let names: Vec<&str> = preserved.sections.iter()
            .map(|(n, _)| n.as_str()).collect();
        assert!(!names.contains(&".debug_line"),
                "debug_line must be left for the Lines tier");
        assert!(names.contains(&".debug_info"));
    }

    #[test]
    fn modified_code_returns_none() {
        let mut input = b"\0asm\x01\x00\x00\x00".to_vec();
        input.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        input.extend_from_slice(&[3, 2, 1, 0]);
        input.extend_from_slice(&[10, 5, 1, 3, 0, 0x01, 0x0B]);
        with_custom(&mut input, ".debug_info", b"info");

        let mut modified = b"\0asm\x01\x00\x00\x00".to_vec();
        modified.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        modified.extend_from_slice(&[3, 2, 1, 0]);
        modified.extend_from_slice(&[10, 6, 1, 4, 0, 0x01, 0x01, 0x0B]);
        with_custom(&mut modified, ".debug_info", b"info");

        let remap = FuncRemap::identity(1);
        assert!(preserve_full_debug(&input, &modified, &remap).is_none());
    }

    #[test]
    fn non_identity_remap_returns_none() {
        let mut bytes = b"\0asm\x01\x00\x00\x00".to_vec();
        with_custom(&mut bytes, ".debug_info", b"info");
        let remap = FuncRemap::from_entries(vec![Some(1)]);
        assert!(preserve_full_debug(&bytes, &bytes, &remap).is_none());
    }

    #[test]
    fn no_debug_sections_returns_empty() {
        let bytes = b"\0asm\x01\x00\x00\x00".to_vec();
        let remap = FuncRemap::identity(0);
        let preserved = preserve_full_debug(&bytes, &bytes, &remap).unwrap();
        assert!(preserved.sections.is_empty());
    }
}
