//! DWARF `.debug_line` handling for the `Lines` debug tier.
//!
//! Per `wilt-debug-info-plan.md` this module ultimately owns full
//! rewriting of the line program using gimli's read/write API so line
//! numbers stay accurate after our code-modifying passes. That lands
//! in a follow-up commit.
//!
//! Today's implementation is the honest MVP: **preserve iff accurate**.
//! If the optimiser produced output whose code section is byte-
//! identical to the input's AND no functions got renumbered, the
//! input's `.debug_line` is still valid verbatim — return it. Any
//! discrepancy and we say so by returning `None` (caller falls back
//! to Names tier, which strips `.debug_line` outright).
//!
//! This leaves no lies in the output: at Lines tier you either get
//! accurate line tables or none at all. Partial preservation (per-
//! function sequences) is tracked as follow-up work.

use crate::module::{self, WasmModule};
use crate::remap::FuncRemap;

/// Return the `.debug_line` payload to embed in the optimised module.
///
/// `Some(bytes)` → caller should write this as the `.debug_line`
/// custom section of the output.
/// `None` → we can't guarantee accuracy; caller should drop the
/// section (Names-tier behaviour).
pub fn rewrite(input: &[u8], optimised: &[u8], remap: &FuncRemap) -> Option<Vec<u8>> {
    let in_m = WasmModule::parse(input).ok()?;
    let out_m = WasmModule::parse(optimised).ok()?;

    // Grab the input's `.debug_line` payload, if any. No input debug
    // info → nothing to do.
    let in_data = in_m.data();
    let line_bytes = in_m.sections().iter().find_map(|s| {
        if s.id != module::SECTION_CUSTOM { return None; }
        let name = s.custom_name?.slice(in_data);
        if name != b".debug_line" { return None; }
        let p = s.payload.slice(in_data);
        let (nlen, c) = crate::leb128::read_u32(p)?;
        Some(&p[c + nlen as usize..])
    })?;

    // Precondition check: did anything relevant to line info change?
    //
    // "Relevant" = function indices shifted (remap is not identity),
    // OR the code section's bytes differ from input's. Either way,
    // addresses embedded in the line program are stale.
    if !remap_is_identity(remap) {
        return None;
    }
    let in_code = code_section_bytes(&in_m);
    let out_code = code_section_bytes(&out_m);
    if in_code != out_code {
        return None;
    }

    // Code is byte-identical and the function index space is
    // unchanged. The input's line program is correct verbatim.
    Some(line_bytes.to_vec())
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

    #[test]
    fn no_debug_line_returns_none() {
        let minimal = b"\0asm\x01\x00\x00\x00".to_vec();
        let remap = FuncRemap::identity(0);
        assert!(rewrite(&minimal, &minimal, &remap).is_none());
    }

    #[test]
    fn unchanged_module_preserves_line_section() {
        // Build a minimal module with a .debug_line custom section.
        let mut bytes = b"\0asm\x01\x00\x00\x00".to_vec();
        // Custom section: id=0, size LEB, name vec ".debug_line", payload.
        let payload = b"\x07some_line_program_stub";
        let mut custom = Vec::new();
        crate::leb128::write_u32(&mut custom, 11);
        custom.extend_from_slice(b".debug_line");
        custom.extend_from_slice(payload);
        bytes.push(0);
        crate::leb128::write_u32(&mut bytes, custom.len() as u32);
        bytes.extend_from_slice(&custom);

        let remap = FuncRemap::identity(0);
        let out = rewrite(&bytes, &bytes, &remap).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn modified_code_returns_none() {
        // Build a module with a code section (minimal) and a
        // .debug_line. Then pass a modified output (different code).
        let mut input = b"\0asm\x01\x00\x00\x00".to_vec();
        // Type: () -> ()
        input.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        // Function: 1 fn, type 0
        input.extend_from_slice(&[3, 2, 1, 0]);
        // Code: 1 body = [0 locals, nop, end]
        input.extend_from_slice(&[10, 5, 1, 3, 0, 0x01, 0x0B]);
        // Debug line custom
        let payload = b"stub";
        let mut custom = Vec::new();
        crate::leb128::write_u32(&mut custom, 11);
        custom.extend_from_slice(b".debug_line");
        custom.extend_from_slice(payload);
        input.push(0);
        crate::leb128::write_u32(&mut input, custom.len() as u32);
        input.extend_from_slice(&custom);

        // Modified output: same shape but with an extra nop in the body.
        let mut modified = b"\0asm\x01\x00\x00\x00".to_vec();
        modified.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        modified.extend_from_slice(&[3, 2, 1, 0]);
        // Body has TWO nops now — code section differs.
        modified.extend_from_slice(&[10, 6, 1, 4, 0, 0x01, 0x01, 0x0B]);
        modified.push(0);
        crate::leb128::write_u32(&mut modified, custom.len() as u32);
        modified.extend_from_slice(&custom);

        let remap = FuncRemap::identity(1);
        assert!(rewrite(&input, &modified, &remap).is_none(),
                "modified code must NOT reuse the input's .debug_line");
    }

    #[test]
    fn non_identity_remap_returns_none() {
        let minimal = b"\0asm\x01\x00\x00\x00".to_vec();
        let mut bytes = minimal.clone();
        let payload = b"line_stub";
        let mut custom = Vec::new();
        crate::leb128::write_u32(&mut custom, 11);
        custom.extend_from_slice(b".debug_line");
        custom.extend_from_slice(payload);
        bytes.push(0);
        crate::leb128::write_u32(&mut bytes, custom.len() as u32);
        bytes.extend_from_slice(&custom);

        // Non-identity remap: function 0 became function 1.
        let remap = FuncRemap::from_entries(vec![Some(1)]);
        assert!(rewrite(&bytes, &bytes, &remap).is_none());
    }
}
