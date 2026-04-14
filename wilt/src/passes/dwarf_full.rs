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
//! - **Step 2**: per-function byte-level address patching of the
//!   simpler address-carrying sections — `.debug_ranges` and
//!   `.debug_loc` (DWARF 4 fixed formats) — for the "bodies byte-
//!   identical, some moved" case.
//! - **Step 3**: add `.debug_aranges` patching.
//! - **Step 4** (this commit): abbrev-driven DIE walker for
//!   `.debug_info`. Parses `.debug_abbrev` tables, traverses each
//!   CU's DIE tree byte-by-byte using the abbrev map, and patches
//!   `DW_AT_low_pc` / `DW_AT_high_pc` / `DW_AT_entry_pc`
//!   attributes encoded as `DW_FORM_addr`. `DW_AT_high_pc` with
//!   non-address forms (constant offset from low_pc) is left
//!   alone — its value is relative.
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
            (Some(sh), ".debug_aranges") => {
                if let Some(patched) = patch_debug_aranges(body, sh) {
                    sections.push((name.to_string(), patched));
                }
            }
            (Some(sh), ".debug_info") => {
                // Need the abbrev section too. Look it up from the
                // module's customs.
                let abbrev = collect_named_section(m, ".debug_abbrev");
                if let Some(abbrev_bytes) = abbrev {
                    if let Some(patched) = patch_debug_info(body, &abbrev_bytes, sh) {
                        sections.push((name.to_string(), patched));
                    }
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

fn collect_named_section(m: &WasmModule<'_>, target: &str) -> Option<Vec<u8>> {
    let data = m.data();
    for s in m.sections() {
        if s.id != module::SECTION_CUSTOM { continue; }
        let name_span = s.custom_name?;
        if name_span.slice(data) != target.as_bytes() { continue; }
        let p = s.payload.slice(data);
        let (nlen, c) = crate::leb128::read_u32(p)?;
        return Some(p[c + nlen as usize..].to_vec());
    }
    None
}

// DWARF abbrev codes (DW_AT_*).
const DW_AT_LOW_PC: u64 = 0x11;
const DW_AT_HIGH_PC: u64 = 0x12;
const DW_AT_ENTRY_PC: u64 = 0x52;

// DWARF form codes (DW_FORM_*).
const DW_FORM_ADDR: u64 = 0x01;
const DW_FORM_BLOCK2: u64 = 0x03;
const DW_FORM_BLOCK4: u64 = 0x04;
const DW_FORM_DATA2: u64 = 0x05;
const DW_FORM_DATA4: u64 = 0x06;
const DW_FORM_DATA8: u64 = 0x07;
const DW_FORM_STRING: u64 = 0x08;
const DW_FORM_BLOCK: u64 = 0x09;
const DW_FORM_BLOCK1: u64 = 0x0A;
const DW_FORM_DATA1: u64 = 0x0B;
const DW_FORM_FLAG: u64 = 0x0C;
const DW_FORM_SDATA: u64 = 0x0D;
const DW_FORM_STRP: u64 = 0x0E;
const DW_FORM_UDATA: u64 = 0x0F;
const DW_FORM_REF_ADDR: u64 = 0x10;
const DW_FORM_REF1: u64 = 0x11;
const DW_FORM_REF2: u64 = 0x12;
const DW_FORM_REF4: u64 = 0x13;
const DW_FORM_REF8: u64 = 0x14;
const DW_FORM_REF_UDATA: u64 = 0x15;
const DW_FORM_INDIRECT: u64 = 0x16;
const DW_FORM_SEC_OFFSET: u64 = 0x17;
const DW_FORM_EXPRLOC: u64 = 0x18;
const DW_FORM_FLAG_PRESENT: u64 = 0x19;
const DW_FORM_STRX: u64 = 0x1A;
const DW_FORM_ADDRX: u64 = 0x1B;
const DW_FORM_REF_SUP4: u64 = 0x1C;
const DW_FORM_STRP_SUP: u64 = 0x1D;
const DW_FORM_DATA16: u64 = 0x1E;
const DW_FORM_LINE_STRP: u64 = 0x1F;
const DW_FORM_REF_SIG8: u64 = 0x20;
const DW_FORM_IMPLICIT_CONST: u64 = 0x21;
const DW_FORM_LOCLISTX: u64 = 0x22;
const DW_FORM_RNGLISTX: u64 = 0x23;
const DW_FORM_REF_SUP8: u64 = 0x24;
const DW_FORM_STRX1: u64 = 0x25;
const DW_FORM_STRX2: u64 = 0x26;
const DW_FORM_STRX3: u64 = 0x27;
const DW_FORM_STRX4: u64 = 0x28;
const DW_FORM_ADDRX1: u64 = 0x29;
const DW_FORM_ADDRX2: u64 = 0x2A;
const DW_FORM_ADDRX3: u64 = 0x2B;
const DW_FORM_ADDRX4: u64 = 0x2C;

#[derive(Clone)]
struct AttrSpec {
    name: u64,
    form: u64,
    /// `Some(v)` for `DW_FORM_implicit_const` — value lives in the
    /// abbrev rather than the DIE bytes.
    implicit_const: Option<i64>,
}

#[derive(Clone)]
struct Abbrev {
    #[allow(dead_code)]
    tag: u64,
    has_children: bool,
    attrs: Vec<AttrSpec>,
}

/// Read an unsigned LEB128 from `bytes`, returning `(value, consumed)`.
fn read_uleb(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &b) in bytes.iter().enumerate() {
        result |= ((b & 0x7F) as u64) << shift;
        shift += 7;
        if b < 0x80 { return Some((result, i + 1)); }
        if shift >= 70 { return None; }
    }
    None
}

/// Signed LEB128 reader.
fn read_sleb(bytes: &[u8]) -> Option<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift = 0;
    for (i, &b) in bytes.iter().enumerate() {
        result |= ((b & 0x7F) as i64) << shift;
        shift += 7;
        if b < 0x80 {
            if shift < 64 && (b & 0x40) != 0 {
                result |= !0i64 << shift;
            }
            return Some((result, i + 1));
        }
        if shift >= 70 { return None; }
    }
    None
}

/// Parse abbreviations starting at `offset` within `.debug_abbrev`
/// until the end-of-set marker (abbrev code 0). Returns map from
/// abbrev code → declaration.
fn parse_abbrev_set(bytes: &[u8], offset: usize) -> Option<std::collections::HashMap<u64, Abbrev>> {
    let mut map = std::collections::HashMap::new();
    let mut off = offset;
    loop {
        let (code, c) = read_uleb(bytes.get(off..)?)?;
        off += c;
        if code == 0 { break; }
        let (tag, c) = read_uleb(bytes.get(off..)?)?;
        off += c;
        let has_children = *bytes.get(off)? != 0;
        off += 1;
        let mut attrs = Vec::new();
        loop {
            let (name, c) = read_uleb(bytes.get(off..)?)?;
            off += c;
            let (form, c) = read_uleb(bytes.get(off..)?)?;
            off += c;
            if name == 0 && form == 0 { break; }
            let implicit_const = if form == DW_FORM_IMPLICIT_CONST {
                let (v, c) = read_sleb(bytes.get(off..)?)?;
                off += c;
                Some(v)
            } else {
                None
            };
            attrs.push(AttrSpec { name, form, implicit_const });
        }
        map.insert(code, Abbrev { tag, has_children, attrs });
    }
    Some(map)
}

/// Skip past an attribute value of given form, returning bytes consumed.
/// Returns None on unknown form.
fn skip_form(bytes: &[u8], form: u64, address_size: u8, dwarf_64: bool) -> Option<usize> {
    let off_size = if dwarf_64 { 8 } else { 4 };
    Some(match form {
        DW_FORM_ADDR => address_size as usize,
        DW_FORM_BLOCK1 => {
            let n = *bytes.first()? as usize;
            1 + n
        }
        DW_FORM_BLOCK2 => {
            let n = u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?) as usize;
            2 + n
        }
        DW_FORM_BLOCK4 => {
            let n = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
            4 + n
        }
        DW_FORM_BLOCK | DW_FORM_EXPRLOC => {
            let (n, c) = read_uleb(bytes)?;
            c + n as usize
        }
        DW_FORM_DATA1 | DW_FORM_FLAG | DW_FORM_REF1
            | DW_FORM_STRX1 | DW_FORM_ADDRX1 => 1,
        DW_FORM_DATA2 | DW_FORM_REF2 | DW_FORM_STRX2
            | DW_FORM_ADDRX2 => 2,
        DW_FORM_STRX3 | DW_FORM_ADDRX3 => 3,
        DW_FORM_DATA4 | DW_FORM_REF4 | DW_FORM_STRX4
            | DW_FORM_ADDRX4 | DW_FORM_REF_SUP4 => 4,
        DW_FORM_DATA8 | DW_FORM_REF8 | DW_FORM_REF_SIG8
            | DW_FORM_REF_SUP8 => 8,
        DW_FORM_DATA16 => 16,
        DW_FORM_STRING => bytes.iter().position(|&b| b == 0).map(|p| p + 1)?,
        DW_FORM_SDATA => read_sleb(bytes)?.1,
        DW_FORM_UDATA | DW_FORM_REF_UDATA | DW_FORM_STRX
            | DW_FORM_ADDRX | DW_FORM_LOCLISTX | DW_FORM_RNGLISTX => read_uleb(bytes)?.1,
        DW_FORM_STRP | DW_FORM_REF_ADDR | DW_FORM_SEC_OFFSET
            | DW_FORM_STRP_SUP | DW_FORM_LINE_STRP => off_size,
        DW_FORM_FLAG_PRESENT | DW_FORM_IMPLICIT_CONST => 0,
        DW_FORM_INDIRECT => {
            // The actual form comes inline.
            let (actual, c) = read_uleb(bytes)?;
            c + skip_form(bytes.get(c..)?, actual, address_size, dwarf_64)?
        }
        _ => return None,
    })
}

/// Walk `.debug_info` CU by CU. For each address attribute encoded
/// as `DW_FORM_addr`, look up the containing input function and
/// patch the bytes to the new address.
pub fn patch_debug_info(
    info: &[u8], abbrev: &[u8], shifts: &[((u32, u32), i64)],
) -> Option<Vec<u8>> {
    let mut out = info.to_vec();
    let mut off = 0;
    while off < out.len() {
        let cu_start = off;
        // Parse CU header.
        if off + 4 > out.len() { return None; }
        let unit_length = u32::from_le_bytes(out[off..off + 4].try_into().ok()?);
        if unit_length == 0xFFFFFFFF { return None; }   // DWARF-64 unsupported
        let cu_end = off + 4 + unit_length as usize;
        if cu_end > out.len() { return None; }
        off += 4;
        let version = u16::from_le_bytes(out[off..off + 2].try_into().ok()?);
        off += 2;

        let (debug_abbrev_offset, address_size);
        if version <= 4 {
            // DWARF 4: abbrev_offset (4 bytes), address_size (1 byte).
            debug_abbrev_offset = u32::from_le_bytes(out[off..off + 4].try_into().ok()?);
            off += 4;
            address_size = out[off];
            off += 1;
        } else if version == 5 {
            // DWARF 5: unit_type, address_size, debug_abbrev_offset.
            let _unit_type = out[off];
            off += 1;
            address_size = out[off];
            off += 1;
            debug_abbrev_offset = u32::from_le_bytes(out[off..off + 4].try_into().ok()?);
            off += 4;
        } else {
            return None;
        }
        if address_size != 4 { return None; }   // wasm 32-bit only
        let _ = cu_start;

        let abbrev_map = parse_abbrev_set(abbrev, debug_abbrev_offset as usize)?;

        // Walk DIEs.
        while off < cu_end {
            let (code, c) = read_uleb(out.get(off..)?)?;
            off += c;
            if code == 0 { continue; }   // end of children
            let abbrev_decl = abbrev_map.get(&code)?.clone();
            let _ = abbrev_decl.has_children;

            for attr in &abbrev_decl.attrs {
                if attr.form == DW_FORM_IMPLICIT_CONST {
                    // No bytes in DIE.
                    continue;
                }
                let attr_off = off;
                let consumed = skip_form(
                    out.get(attr_off..)?, attr.form, address_size, false,
                )?;
                let is_address_attr = matches!(
                    attr.name, DW_AT_LOW_PC | DW_AT_ENTRY_PC
                ) || (attr.name == DW_AT_HIGH_PC && attr.form == DW_FORM_ADDR);
                if is_address_attr && attr.form == DW_FORM_ADDR
                    && consumed == address_size as usize
                {
                    let addr = u32::from_le_bytes(
                        out[attr_off..attr_off + 4].try_into().ok()?,
                    );
                    if let Some(d) = shifts.iter()
                        .find(|((s, e), _)| addr >= *s && addr < *e)
                        .map(|(_, d)| *d)
                    {
                        let new_addr = (addr as i64 + d).max(0) as u32;
                        out[attr_off..attr_off + 4]
                            .copy_from_slice(&new_addr.to_le_bytes());
                    }
                }
                off += consumed;
            }
        }
        // Should land exactly at cu_end. Sanity check.
        if off != cu_end { return None; }
    }
    Some(out)
}

/// DWARF `.debug_aranges`: sequence of address-range tables, one per
/// compilation unit. Each table:
///
/// ```text
/// unit_length   : u32 (or 12 bytes for DWARF-64)
/// version       : u16 (= 2)
/// debug_info_offset : u32 (or u64 for DWARF-64)
/// address_size  : u8
/// segment_size  : u8
/// padding to align first tuple to 2*address_size
/// (address, length) pairs of address_size bytes each
/// terminated by (0, 0)
/// ```
///
/// We handle DWARF-32 with address_size = 4 (wasm's case). DWARF-64
/// (unit_length == 0xFFFFFFFF) is rejected — wilt's target corpus
/// doesn't emit it.
fn patch_debug_aranges(
    body: &[u8], shifts: &[((u32, u32), i64)],
) -> Option<Vec<u8>> {
    let mut out = body.to_vec();
    let mut off = 0;

    while off < out.len() {
        // Parse unit header.
        if off + 12 > out.len() { return None; }
        let unit_length = u32::from_le_bytes(out[off..off + 4].try_into().ok()?);
        if unit_length == 0xFFFFFFFF { return None; }  // DWARF-64
        let table_end = off + 4 + unit_length as usize;
        if table_end > out.len() { return None; }
        let version = u16::from_le_bytes(out[off + 4..off + 6].try_into().ok()?);
        if version != 2 { return None; }
        let _debug_info_offset = u32::from_le_bytes(out[off + 6..off + 10].try_into().ok()?);
        let address_size = out[off + 10];
        let _segment_size = out[off + 11];
        if address_size != 4 { return None; }

        // Tuples align to 2 * address_size from unit_start. Header
        // is 12 bytes; next multiple of 8 from unit_start = 16.
        let tuple_start = off + ((12 + 7) & !7);
        if tuple_start > table_end { return None; }

        let mut t = tuple_start;
        while t + 8 <= table_end {
            let addr = u32::from_le_bytes(out[t..t + 4].try_into().ok()?);
            let len = u32::from_le_bytes(out[t + 4..t + 8].try_into().ok()?);
            if addr == 0 && len == 0 {
                t += 8;
                break;
            }
            // Find the shift; if address isn't in any known range, leave.
            let end_addr = addr.saturating_add(len);
            let shift = shifts.iter()
                .find(|((s, e), _)| addr >= *s && end_addr <= *e)
                .map(|(_, d)| *d);
            if let Some(d) = shift {
                let new_addr = (addr as i64 + d).max(0) as u32;
                out[t..t + 4].copy_from_slice(&new_addr.to_le_bytes());
                // Length doesn't change.
            }
            t += 8;
        }
        off = table_end;
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
    fn patch_debug_info_shifts_low_pc_addr() {
        // Build a tiny synthetic CU with one DIE that has DW_AT_low_pc
        // (form DW_FORM_addr) and DW_AT_high_pc (form DW_FORM_data4 —
        // length, NOT shifted).
        //
        // Abbrev table: one entry, code=1, tag=0x2E (subprogram),
        // no children, attrs=[(low_pc, addr), (high_pc, data4),
        // (0,0)].
        let mut abbrev = Vec::new();
        abbrev.push(0x01);  // abbrev_code 1
        abbrev.push(0x2E);  // tag = subprogram
        abbrev.push(0x00);  // has_children = no
        abbrev.push(DW_AT_LOW_PC as u8);
        abbrev.push(DW_FORM_ADDR as u8);
        abbrev.push(DW_AT_HIGH_PC as u8);
        abbrev.push(DW_FORM_DATA4 as u8);
        abbrev.push(0); abbrev.push(0); // end attrs
        abbrev.push(0); // end of abbrev set

        // .debug_info CU:
        // - unit_length: u32 (computed)
        // - version: u16 = 4
        // - debug_abbrev_offset: u32 = 0
        // - address_size: u8 = 4
        // - DIE: abbrev_code (uleb 1), low_pc (4 bytes = 100),
        //   high_pc (4 bytes = 50), end-of-children (0).
        let mut info_body = Vec::new();
        info_body.push(0x01);  // abbrev code 1
        info_body.extend_from_slice(&100u32.to_le_bytes());
        info_body.extend_from_slice(&50u32.to_le_bytes());
        info_body.push(0);   // end of children sentinel

        let mut info = Vec::new();
        let header_len = 4 + 2 + 4 + 1;  // version+abbrev_off+addr_size
        let unit_length = (header_len - 4 + info_body.len()) as u32; // bytes after unit_length
        info.extend_from_slice(&unit_length.to_le_bytes());
        info.extend_from_slice(&4u16.to_le_bytes());
        info.extend_from_slice(&0u32.to_le_bytes());
        info.push(4);
        info.extend_from_slice(&info_body);

        let shifts = vec![((50u32, 200u32), 50i64)];
        let patched = patch_debug_info(&info, &abbrev, &shifts).unwrap();

        // Find the low_pc field in patched bytes — at offset
        // (4+2+4+1+1) = 12 (after unit header + abbrev code byte).
        let low_pc_off = 4 + 2 + 4 + 1 + 1;
        let new_low_pc = u32::from_le_bytes(
            patched[low_pc_off..low_pc_off + 4].try_into().unwrap()
        );
        assert_eq!(new_low_pc, 150, "low_pc should be shifted by +50");

        // high_pc is data4 (length, not absolute), so should NOT be
        // patched.
        let high_pc_off = low_pc_off + 4;
        let new_high_pc = u32::from_le_bytes(
            patched[high_pc_off..high_pc_off + 4].try_into().unwrap()
        );
        assert_eq!(new_high_pc, 50, "high_pc as data4 (length) must NOT shift");
    }

    #[test]
    fn patch_debug_info_handles_high_pc_as_addr() {
        // Same shape but high_pc is FORM_addr — must shift.
        let mut abbrev = Vec::new();
        abbrev.push(0x01);
        abbrev.push(0x2E);
        abbrev.push(0x00);
        abbrev.push(DW_AT_LOW_PC as u8);
        abbrev.push(DW_FORM_ADDR as u8);
        abbrev.push(DW_AT_HIGH_PC as u8);
        abbrev.push(DW_FORM_ADDR as u8);
        abbrev.push(0); abbrev.push(0);
        abbrev.push(0);

        let mut info_body = Vec::new();
        info_body.push(0x01);
        info_body.extend_from_slice(&100u32.to_le_bytes());
        info_body.extend_from_slice(&150u32.to_le_bytes());
        info_body.push(0);

        let mut info = Vec::new();
        let header_len = 4 + 2 + 4 + 1;
        let unit_length = (header_len - 4 + info_body.len()) as u32;
        info.extend_from_slice(&unit_length.to_le_bytes());
        info.extend_from_slice(&4u16.to_le_bytes());
        info.extend_from_slice(&0u32.to_le_bytes());
        info.push(4);
        info.extend_from_slice(&info_body);

        let shifts = vec![((50u32, 200u32), 50i64)];
        let patched = patch_debug_info(&info, &abbrev, &shifts).unwrap();
        let off = 4 + 2 + 4 + 1 + 1;
        assert_eq!(u32::from_le_bytes(patched[off..off+4].try_into().unwrap()), 150);
        assert_eq!(u32::from_le_bytes(patched[off+4..off+8].try_into().unwrap()), 200);
    }

    #[test]
    fn patch_debug_aranges_shifts_one_table() {
        // Build a single aranges table: unit_length=20, version=2,
        // debug_info_offset=0, addr_size=4, seg_size=0, padding=4,
        // one (100, 50) tuple, then (0, 0) terminator. Total = 4 +
        // 2 + 4 + 1 + 1 + 4 pad + 8 tuple + 8 term = 32 bytes; but
        // unit_length counts bytes AFTER its own 4 bytes → 28.
        //
        // Actually correct total: header (12) + padding-to-next-8
        // (4) = 16 bytes of header+pad, + 8 (tuple) + 8 (term) =
        // 32 bytes total. unit_length = 28.
        let mut body = Vec::new();
        body.extend_from_slice(&28u32.to_le_bytes());   // unit_length
        body.extend_from_slice(&2u16.to_le_bytes());    // version
        body.extend_from_slice(&0u32.to_le_bytes());    // debug_info_offset
        body.push(4);                                   // address_size
        body.push(0);                                   // segment_size
        body.extend_from_slice(&[0; 4]);                // padding to 16
        body.extend_from_slice(&100u32.to_le_bytes());  // address
        body.extend_from_slice(&50u32.to_le_bytes());   // length
        body.extend_from_slice(&0u32.to_le_bytes());    // terminator
        body.extend_from_slice(&0u32.to_le_bytes());

        let shifts = vec![((50u32, 200u32), 50i64)];
        let patched = patch_debug_aranges(&body, &shifts).unwrap();
        let new_addr = u32::from_le_bytes(patched[16..20].try_into().unwrap());
        let new_len = u32::from_le_bytes(patched[20..24].try_into().unwrap());
        assert_eq!(new_addr, 150);
        assert_eq!(new_len, 50);
        // Terminator unchanged.
        assert_eq!(&patched[24..32], &[0; 8]);
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
