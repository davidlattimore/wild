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
//! - **Step 1**: preserve-if-accurate. When the code section is
//!   byte-identical to the input's AND the FuncRemap is identity,
//!   every input `.debug_*` section is still correct — preserve
//!   them verbatim.
//! - **Step 2** (this commit): per-function byte-level address
//!   patching of the simpler address-carrying sections —
//!   `.debug_ranges` and `.debug_loc` (DWARF 4 fixed formats) —
//!   for the "bodies byte-identical, some moved" case. `.debug_info`
//!   and DWARF-5 variants stay preserve-or-strip; step 3 extends
//!   coverage.
//! - **Step 3** (deferred): gimli-driven DIE-walker for
//!   `.debug_info` address attributes + DWARF-5 rnglists/loclists.
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
pub fn preserve_full_debug(
    input: &[u8], optimised: &[u8], remap: &FuncRemap,
) -> Option<PreservedDebug> {
    let mut in_m = WasmModule::parse(input).ok()?;
    let mut out_m = WasmModule::parse(optimised).ok()?;
    in_m.ensure_function_bodies_parsed();
    out_m.ensure_function_bodies_parsed();

    // Fast path (step 1): code section byte-identical AND identity
    // remap → preserve all `.debug_*` sections verbatim.
    let code_identical = code_section_bytes(&in_m) == code_section_bytes(&out_m);
    if remap_is_identity(remap) && code_identical {
        return Some(collect_debug_sections(&in_m, None));
    }

    // Step 2: per-function bytes match, possibly at different file
    // offsets. Build the shifts table and patch `.debug_ranges` /
    // `.debug_loc`. Drop `.debug_info` and DWARF-5 variants (step 3).
    let in_offsets = crate::passes::dwarf_line::function_file_offsets(&in_m)?;
    let out_offsets = crate::passes::dwarf_line::function_file_offsets(&out_m)?;
    let shifts = build_shifts(remap, &in_offsets, &out_offsets,
                              input, optimised)?;
    // If shifts is empty of non-zero entries, nothing moved — bail
    // and let step 1's code-identical gate handle the degenerate
    // case.
    Some(collect_debug_sections(&in_m, Some(&shifts)))
}

/// Build the per-function shifts table: for each input defined
/// function, `((in_start, in_end), delta)` iff the body is byte-
/// identical to the remapped output function's. If ANY function
/// fails that check, return `None` (caller strips all).
fn build_shifts(
    remap: &FuncRemap,
    in_offsets: &[(u32, u32)],
    out_offsets: &[(u32, u32)],
    input: &[u8], output: &[u8],
) -> Option<Vec<((u32, u32), i64)>> {
    let num_defined_in = in_offsets.len() as u32;
    if remap.len() < num_defined_in { return None; }
    let num_imports = remap.len() - num_defined_in;
    // Guard: a module with no defined functions shouldn't have a
    // non-identity remap. If it does, something else changed (e.g.
    // an import renumbering) and we can't reason about it here.
    if num_defined_in == 0 {
        for i in 0..remap.len() {
            if remap.lookup(i) != Some(i) { return None; }
        }
    }
    let mut shifts = Vec::with_capacity(in_offsets.len());
    for (def_i, &(off_in, len_in)) in in_offsets.iter().enumerate() {
        let abs_in = num_imports + def_i as u32;
        let abs_out = remap.lookup(abs_in)?;
        if abs_out < num_imports { return None; }
        let def_out = (abs_out - num_imports) as usize;
        let &(off_out, len_out) = out_offsets.get(def_out)?;
        if len_in != len_out { return None; }
        let in_bytes = &input[off_in as usize..(off_in + len_in) as usize];
        let out_bytes = &output[off_out as usize..(off_out + len_out) as usize];
        if in_bytes != out_bytes { return None; }
        shifts.push(((off_in, off_in + len_in), off_out as i64 - off_in as i64));
    }
    Some(shifts)
}

/// Walk the module's custom sections and collect preservable
/// `.debug_*` payloads. If `shifts` is `Some`, apply address
/// patches to `.debug_ranges` and `.debug_loc`; drop any section
/// whose content we can't safely patch (e.g. `.debug_info` —
/// step 3 handles those).
fn collect_debug_sections(
    m: &WasmModule<'_>, shifts: Option<&[((u32, u32), i64)]>,
) -> PreservedDebug {
    let data = m.data();
    let mut sections = Vec::new();
    for s in m.sections() {
        if s.id != module::SECTION_CUSTOM { continue; }
        let Some(name_span) = s.custom_name else { continue };
        let name_bytes = name_span.slice(data);
        let Ok(name) = std::str::from_utf8(name_bytes) else { continue };
        if name == ".debug_line" { continue; }
        if !is_debug_section(name) { continue; }

        let p = s.payload.slice(data);
        let Some((nlen, c)) = crate::leb128::read_u32(p) else { continue };
        let start = c + nlen as usize;
        if start > p.len() { continue; }
        let body = &p[start..];

        match (shifts, name) {
            (None, _) => sections.push((name.to_string(), body.to_vec())),
            (Some(sh), ".debug_ranges") => {
                if let Some(patched) = patch_debug_ranges(body, sh) {
                    sections.push((name.to_string(), patched));
                }
            }
            (Some(sh), ".debug_loc") => {
                if let Some(patched) = patch_debug_loc(body, sh) {
                    sections.push((name.to_string(), patched));
                }
            }
            (Some(_), n) if NON_ADDRESS.contains(&n) => {
                sections.push((n.to_string(), body.to_vec()));
            }
            // Other address-referencing sections under the
            // moved-bodies case: step 3 will handle. Today, drop.
            _ => {}
        }
    }
    PreservedDebug { sections }
}

/// DWARF-4 `.debug_ranges`: a concatenation of range lists, each
/// list terminated by (0, 0). (base, anchor) pairs where start ==
/// u32::MAX set a base-address for subsequent (relative) entries;
/// we pass them through (wasm codegen rarely uses them).
///
/// For wasm (32-bit addresses), each entry is 8 bytes.
fn patch_debug_ranges(
    body: &[u8], shifts: &[((u32, u32), i64)],
) -> Option<Vec<u8>> {
    if body.len() % 8 != 0 { return None; }
    let mut out = body.to_vec();
    let mut i = 0;
    while i + 8 <= out.len() {
        let start = u32::from_le_bytes(out[i..i + 4].try_into().ok()?);
        let end = u32::from_le_bytes(out[i + 4..i + 8].try_into().ok()?);
        if start == 0 && end == 0 {
            // Terminator — no patch.
            i += 8;
            continue;
        }
        if start == u32::MAX {
            // Base-address selection — passes the base forward but
            // doesn't itself describe a code range. Leave as-is.
            i += 8;
            continue;
        }
        // Find the shift. Addresses should fall within one of the
        // input function ranges; if not (ranges extending into
        // padding / unknown areas) we bail defensively.
        let shift = shifts.iter()
            .find(|((s, e), _)| start >= *s && end <= *e)
            .map(|(_, d)| *d)?;
        let new_start = (start as i64 + shift).max(0) as u32;
        let new_end = (end as i64 + shift).max(0) as u32;
        out[i..i + 4].copy_from_slice(&new_start.to_le_bytes());
        out[i + 4..i + 8].copy_from_slice(&new_end.to_le_bytes());
        i += 8;
    }
    Some(out)
}

/// DWARF-4 `.debug_loc`: list of (start, end, expr_len, expr_bytes)
/// entries, each list terminated by (0, 0). Patch start/end the
/// same as `.debug_ranges`; pass the expression bytes through.
fn patch_debug_loc(
    body: &[u8], shifts: &[((u32, u32), i64)],
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i + 8 <= body.len() {
        let start = u32::from_le_bytes(body[i..i + 4].try_into().ok()?);
        let end = u32::from_le_bytes(body[i + 4..i + 8].try_into().ok()?);

        if start == 0 && end == 0 {
            // Terminator — copy and move on.
            out.extend_from_slice(&body[i..i + 8]);
            i += 8;
            continue;
        }
        if start == u32::MAX {
            // Base-address entry — no expression bytes follow.
            out.extend_from_slice(&body[i..i + 8]);
            i += 8;
            continue;
        }

        // Active location entry: 8-byte range + 2-byte expr length +
        // expr bytes.
        if i + 10 > body.len() { return None; }
        let expr_len = u16::from_le_bytes(body[i + 8..i + 10].try_into().ok()?) as usize;
        let entry_end = i + 10 + expr_len;
        if entry_end > body.len() { return None; }

        let shift = shifts.iter()
            .find(|((s, e), _)| start >= *s && end <= *e)
            .map(|(_, d)| *d)?;
        let new_start = (start as i64 + shift).max(0) as u32;
        let new_end = (end as i64 + shift).max(0) as u32;

        out.extend_from_slice(&new_start.to_le_bytes());
        out.extend_from_slice(&new_end.to_le_bytes());
        out.extend_from_slice(&body[i + 8..entry_end]);
        i = entry_end;
    }
    Some(out)
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

    #[test]
    fn patch_debug_ranges_shifts_address_pair() {
        // One range (100..200) that belongs to a function shifted +50.
        let mut body = Vec::new();
        body.extend_from_slice(&100u32.to_le_bytes());
        body.extend_from_slice(&200u32.to_le_bytes());
        // Terminator.
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());

        let shifts = vec![((50u32, 250u32), 50i64)];
        let patched = patch_debug_ranges(&body, &shifts).unwrap();
        let new_start = u32::from_le_bytes(patched[0..4].try_into().unwrap());
        let new_end = u32::from_le_bytes(patched[4..8].try_into().unwrap());
        assert_eq!(new_start, 150);
        assert_eq!(new_end, 250);
        // Terminator unchanged.
        assert_eq!(&patched[8..16], &[0; 8]);
    }

    #[test]
    fn patch_debug_ranges_passes_through_base_selection() {
        // Base-address entry: (u32::MAX, base) — not a code range,
        // should pass through verbatim.
        let mut body = Vec::new();
        body.extend_from_slice(&u32::MAX.to_le_bytes());
        body.extend_from_slice(&1000u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());

        let shifts = vec![((0u32, 10000u32), 42i64)];
        let patched = patch_debug_ranges(&body, &shifts).unwrap();
        assert_eq!(patched, body);
    }

    #[test]
    fn patch_debug_loc_shifts_active_range() {
        // One entry: start=100, end=200, expr_len=2, expr=[0x01, 0x02].
        // Shift range by +50 → start=150, end=250; expr untouched.
        let mut body = Vec::new();
        body.extend_from_slice(&100u32.to_le_bytes());
        body.extend_from_slice(&200u32.to_le_bytes());
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(&[0x01, 0x02]);
        body.extend_from_slice(&0u32.to_le_bytes()); // terminator
        body.extend_from_slice(&0u32.to_le_bytes());

        let shifts = vec![((50u32, 250u32), 50i64)];
        let patched = patch_debug_loc(&body, &shifts).unwrap();
        assert_eq!(u32::from_le_bytes(patched[0..4].try_into().unwrap()), 150);
        assert_eq!(u32::from_le_bytes(patched[4..8].try_into().unwrap()), 250);
        assert_eq!(u16::from_le_bytes(patched[8..10].try_into().unwrap()), 2);
        assert_eq!(&patched[10..12], &[0x01, 0x02]);
        assert_eq!(&patched[12..20], &[0; 8]);
    }
}
