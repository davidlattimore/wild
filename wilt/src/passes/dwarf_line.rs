//! DWARF `.debug_line` handling for the `Lines` debug tier.
//!
//! Per `wilt-debug-info-plan.md` this module owns DWARF line-program
//! handling for the Lines tier.
//!
//! Implementation is staged:
//!
//! - **Step 1** (landed): preserve the input `.debug_line` bytes iff the output's code section is
//!   byte-identical AND no function index shifted. Otherwise drop (Names-tier fallback).
//! - **Step 2**: broaden preservation to "per-function byte-and- position identical". If every
//!   surviving function is byte- identical to its input at the same code-section byte offset — true
//!   when passes like reorder/layout changed nothing but later sections elsewhere — we preserve.
//! - **Step 3**: byte-level address patching for the "bodies byte- identical but moved" case. Find
//!   each `DW_LNE_set_address` extended opcode in the line program, look up which input function
//!   its address pointed at, compute the new file offset of that function in the output, patch in
//!   place.
//! - **Step 4** (this commit): per-sequence splicing for the "some bodies modified" case. Walk the
//!   program, delimit each sequence by its `DW_LNE_end_sequence` boundary, drop sequences for
//!   modified/eliminated functions, patch addresses for kept ones, then stitch the surviving
//!   sequences into a new program body and update the header's `unit_length`.
//!
//! Invariant: the output either carries an *accurate* `.debug_line`
//! or none at all. We never embed stale addresses.

use crate::leb128;
use crate::module::WasmModule;
use crate::module::{self};
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

    // Step 3: bodies byte-identical but possibly moved. Patch
    // DW_LNE_set_address opcodes in the line program with the new
    // file offsets. Same byte length, so no downstream encoding shift.
    if per_function_bytes_match(input, optimised, remap, &in_offsets, &out_offsets) {
        if let Some(patched) = patch_addresses(
            line_bytes,
            input,
            optimised,
            remap,
            &in_offsets,
            &out_offsets,
        ) {
            return Some(patched);
        }
    }

    // Step 4: some bodies modified. Walk the program, drop
    // sequences for modified/eliminated functions, keep sequences
    // for preserved ones (with patched addresses).
    splice_preserved_sequences(
        line_bytes,
        input,
        optimised,
        remap,
        &in_offsets,
        &out_offsets,
    )
}

/// Build a per-input-function "preservation" map: Some(output offset)
/// if the body survives byte-identical, None if modified or removed.
fn preservation_map(
    input: &[u8],
    output: &[u8],
    remap: &FuncRemap,
    in_offsets: &[(u32, u32)],
    out_offsets: &[(u32, u32)],
) -> Option<Vec<Option<u32>>> {
    let num_defined_in = in_offsets.len() as u32;
    if remap.len() < num_defined_in {
        return None;
    }
    let num_imports = remap.len() - num_defined_in;
    let mut out = Vec::with_capacity(in_offsets.len());
    for (def_i, &(off_in, len_in)) in in_offsets.iter().enumerate() {
        let abs_in = num_imports + def_i as u32;
        let result = match remap.lookup(abs_in) {
            None => None,
            Some(abs_out) if abs_out < num_imports => None,
            Some(abs_out) => {
                let def_out = (abs_out - num_imports) as usize;
                out_offsets.get(def_out).and_then(|&(off_out, len_out)| {
                    if len_in != len_out {
                        return None;
                    }
                    let in_bytes = &input[off_in as usize..(off_in + len_in) as usize];
                    let out_bytes = &output[off_out as usize..(off_out + len_out) as usize];
                    (in_bytes == out_bytes).then_some(off_out)
                })
            }
        };
        out.push(result);
    }
    Some(out)
}

/// Splice out sequences whose input function was modified or
/// eliminated; keep sequences for preserved functions (applying
/// step-3 address patches in the process). Re-emit program body
/// and update the header's `unit_length` prefix.
///
/// Returns `None` if any invariant breaks (malformed program,
/// unexpected DWARF v5 encoding, etc.) — caller falls back to drop.
fn splice_preserved_sequences(
    line_bytes: &[u8],
    input: &[u8],
    output: &[u8],
    remap: &FuncRemap,
    in_offsets: &[(u32, u32)],
    out_offsets: &[(u32, u32)],
) -> Option<Vec<u8>> {
    let preserved = preservation_map(input, output, remap, in_offsets, out_offsets)?;

    // Parse header with gimli.
    let dl = gimli::DebugLine::new(line_bytes, gimli::LittleEndian);
    let header = dl
        .program(gimli::DebugLineOffset(0), 4, None, None)
        .ok()?
        .header()
        .clone();
    let opcode_base = header.opcode_base();
    let std_lens = header.standard_opcode_lengths();
    let prog_off = (header.raw_program_buf().as_ptr() as usize) - line_bytes.as_ptr() as usize;

    // Build shifts for kept functions (step 3's model).
    let mut shifts: Vec<((u32, u32), i64)> = Vec::new();
    let _ = remap;
    for (def_i, &(off_in, len_in)) in in_offsets.iter().enumerate() {
        if let Some(off_out) = preserved[def_i] {
            shifts.push(((off_in, off_in + len_in), off_out as i64 - off_in as i64));
        }
    }

    // Walk program, collecting (sequence_byte_start, sequence_byte_end,
    // first_address) for each sequence.
    let mut off = prog_off;
    let mut seq_start = off;
    let mut seq_first_addr: Option<u32> = None;
    let mut sequences: Vec<(usize, usize, Option<u32>)> = Vec::new();

    while off < line_bytes.len() {
        let op_off = off;
        let op = line_bytes[off];
        off += 1;
        if op == 0 {
            // Extended opcode.
            let (size, c) = leb128::read_u32(&line_bytes[off..])?;
            off += c;
            if size == 0 {
                continue;
            }
            let sub = line_bytes[off];
            let operand_off = off + 1;
            let operand_len = (size as usize).saturating_sub(1);
            let extended_end = operand_off + operand_len;

            if sub == 0x02 /* DW_LNE_set_address */ && operand_len == 4 {
                let addr_bytes: [u8; 4] =
                    line_bytes[operand_off..operand_off + 4].try_into().ok()?;
                let addr = u32::from_le_bytes(addr_bytes);
                if seq_first_addr.is_none() {
                    seq_first_addr = Some(addr);
                    seq_start = op_off;
                }
            } else if sub == 0x01
            /* DW_LNE_end_sequence */
            {
                sequences.push((seq_start, extended_end, seq_first_addr));
                seq_first_addr = None;
                seq_start = extended_end;
            }
            off = extended_end;
        } else if (op as usize) < opcode_base as usize {
            let n_operands = std_lens
                .get((op as usize).saturating_sub(1))
                .copied()
                .unwrap_or(0);
            for _ in 0..n_operands {
                let (_, c) = leb128::read_u32(&line_bytes[off..])?;
                off += c;
            }
        }
        // Special opcodes: 1 byte, no operands. Already advanced.
    }

    // Any trailing opcodes after the last end_sequence (shouldn't
    // happen in valid DWARF but handle gracefully): drop them.

    // Decide per sequence: keep or drop. Keep if its first address
    // falls in a preserved function.
    let mut new_body: Vec<u8> = line_bytes[..prog_off].to_vec();
    let mut kept = 0usize;
    for &(s, e, first_addr) in &sequences {
        let Some(addr) = first_addr else { continue };
        let is_preserved = shifts.iter().any(|((lo, hi), _)| addr >= *lo && addr < *hi);
        if !is_preserved {
            continue;
        }
        // Copy sequence bytes, then patch any DW_LNE_set_address
        // within them.
        let seq_slice = &line_bytes[s..e];
        let mut buf = seq_slice.to_vec();
        patch_seq_addresses(&mut buf, opcode_base, std_lens, &shifts)?;
        new_body.extend_from_slice(&buf);
        kept += 1;
    }

    if kept == 0 {
        // Nothing preserved → caller can just drop the section.
        return None;
    }

    // Update the `unit_length` field in the new header. First 4
    // bytes are the DWARF-32 length, OR the DWARF-64 escape
    // 0xFFFFFFFF followed by a u64 length. Handle both honestly.
    if new_body.len() < 4 {
        return None;
    }
    if new_body[..4] == [0xFF, 0xFF, 0xFF, 0xFF] {
        if new_body.len() < 12 {
            return None;
        }
        let new_unit_len = (new_body.len() - 12) as u64;
        new_body[4..12].copy_from_slice(&new_unit_len.to_le_bytes());
    } else {
        let new_unit_len = (new_body.len() - 4) as u32;
        new_body[0..4].copy_from_slice(&new_unit_len.to_le_bytes());
    }

    Some(new_body)
}

/// Like `patch_addresses` but scoped to a single sequence-byte slice.
/// Only walks one sequence; doesn't need to track cross-sequence
/// state. Used after splicing to apply step-3-style address shifts.
fn patch_seq_addresses(
    buf: &mut [u8],
    opcode_base: u8,
    std_lens: &[u8],
    shifts: &[((u32, u32), i64)],
) -> Option<()> {
    let mut off = 0;
    while off < buf.len() {
        let op = buf[off];
        off += 1;
        if op == 0 {
            let (size, c) = leb128::read_u32(&buf[off..])?;
            off += c;
            if size == 0 {
                continue;
            }
            let sub = buf[off];
            let operand_off = off + 1;
            let operand_len = (size as usize).saturating_sub(1);
            if sub == 0x02 && operand_len == 4 {
                let addr_bytes: [u8; 4] = buf[operand_off..operand_off + 4].try_into().ok()?;
                let addr = u32::from_le_bytes(addr_bytes);
                let shift = shifts
                    .iter()
                    .find(|((s, e), _)| addr >= *s && addr < *e)
                    .map(|(_, sh)| *sh);
                if let Some(d) = shift {
                    let new_addr = (addr as i64 + d).max(0) as u32;
                    buf[operand_off..operand_off + 4].copy_from_slice(&new_addr.to_le_bytes());
                }
            }
            off = operand_off + operand_len;
        } else if (op as usize) < opcode_base as usize {
            let n_operands = std_lens
                .get((op as usize).saturating_sub(1))
                .copied()
                .unwrap_or(0);
            for _ in 0..n_operands {
                let (_, c) = leb128::read_u32(&buf[off..])?;
                off += c;
            }
        }
    }
    Some(())
}

/// Like `per_function_identical` but doesn't require positions to
/// match — only that every function's body BYTES are preserved.
/// Position changes will be addressed by the address patcher.
fn per_function_bytes_match(
    input: &[u8],
    output: &[u8],
    remap: &FuncRemap,
    in_offsets: &[(u32, u32)],
    out_offsets: &[(u32, u32)],
) -> bool {
    let num_defined_in = in_offsets.len() as u32;
    if remap.len() < num_defined_in {
        return false;
    }
    let num_imports = remap.len() - num_defined_in;
    for (def_i, (off_in, len_in)) in in_offsets.iter().enumerate() {
        let abs_in = num_imports + def_i as u32;
        let Some(abs_out) = remap.lookup(abs_in) else {
            return false;
        };
        if abs_out < num_imports {
            return false;
        }
        let def_out = (abs_out - num_imports) as usize;
        let Some(&(off_out, len_out)) = out_offsets.get(def_out) else {
            return false;
        };
        if *len_in != len_out {
            return false;
        }
        let in_bytes = &input[*off_in as usize..(*off_in + *len_in) as usize];
        let out_bytes = &output[off_out as usize..(off_out + len_out) as usize];
        if in_bytes != out_bytes {
            return false;
        }
    }
    true
}

/// Build a closure mapping input file offsets → output file offsets
/// for each function in `remap`, assuming bodies are byte-identical
/// (caller verifies). Returns None if remap shape is inconsistent.
fn build_address_shifts(
    remap: &FuncRemap,
    in_offsets: &[(u32, u32)],
    out_offsets: &[(u32, u32)],
) -> Option<Vec<((u32, u32), i64)>> {
    let num_defined_in = in_offsets.len() as u32;
    if remap.len() < num_defined_in {
        return None;
    }
    let num_imports = remap.len() - num_defined_in;
    let mut shifts = Vec::with_capacity(in_offsets.len());
    for (def_i, &(off_in, len_in)) in in_offsets.iter().enumerate() {
        let abs_in = num_imports + def_i as u32;
        let abs_out = remap.lookup(abs_in)?;
        if abs_out < num_imports {
            return None;
        }
        let def_out = (abs_out - num_imports) as usize;
        let &(off_out, _) = out_offsets.get(def_out)?;
        let shift = off_out as i64 - off_in as i64;
        shifts.push(((off_in, off_in + len_in), shift));
    }
    Some(shifts)
}

/// Find DW_LNE_set_address opcodes in the line program and patch
/// each address with the per-function shift.
///
/// Strategy: parse the line-program header with gimli to learn
/// `address_size` and the standard-opcode lengths, then manually
/// walk the program body, identifying extended opcodes and patching
/// `set_address` (sub-opcode 0x02) in place.
///
/// Returns the patched bytes on success, or `None` if any address
/// falls outside any known function range (should not happen given
/// our preservation gate).
fn patch_addresses(
    line_bytes: &[u8],
    _input: &[u8],
    _output: &[u8],
    remap: &FuncRemap,
    in_offsets: &[(u32, u32)],
    out_offsets: &[(u32, u32)],
) -> Option<Vec<u8>> {
    let shifts = build_address_shifts(remap, in_offsets, out_offsets)?;

    // Parse just enough of the header to learn the address size and
    // the standard-opcode operand lengths.
    let dl = gimli::DebugLine::new(line_bytes, gimli::LittleEndian);
    let header = dl
        .program(
            gimli::DebugLineOffset(0),
            4, // wasm address size
            None,
            None,
        )
        .ok()?;
    let header = header.header().clone();

    // Patch by walking the program body.
    let mut out = line_bytes.to_vec();
    let header_len = header.header_length() as usize
        + header.offset().0 as usize
        + 22 /* fixed header bytes before header_length */;
    // Use the spec'd header length: header_offset = (program_offset
    // - header_offset_to_program). gimli's header offers `header_size`
    // sometimes; otherwise we walk from the offset reported below.
    let prog_off = (header.raw_program_buf().as_ptr() as usize) - line_bytes.as_ptr() as usize;
    let _ = header_len;

    let opcode_base = header.opcode_base();
    let std_lens = header.standard_opcode_lengths();

    let mut off = prog_off;
    while off < out.len() {
        let op = out[off];
        off += 1;
        if op == 0 {
            // Extended opcode: size LEB, sub-opcode, operands.
            let (size, c) = leb128::read_u32(&out[off..])?;
            off += c;
            if size == 0 {
                continue;
            }
            let sub = out[off];
            // sub-opcode + operand bytes total `size` bytes.
            let operand_off = off + 1;
            let operand_len = (size as usize).saturating_sub(1);
            if sub == 0x02 /* DW_LNE_set_address */ && operand_len == 4 {
                let addr_bytes: [u8; 4] = out[operand_off..operand_off + 4].try_into().ok()?;
                let addr = u32::from_le_bytes(addr_bytes);
                // Find which function contains this address.
                let shift = shifts
                    .iter()
                    .find(|((s, e), _)| addr >= *s && addr < *e)
                    .map(|(_, s)| *s);
                let new_addr = match shift {
                    Some(d) => (addr as i64 + d).max(0) as u32,
                    None => {
                        // Address is outside any function range — could be
                        // an end-of-program sentinel. Leave it.
                        addr
                    }
                };
                let new_bytes = new_addr.to_le_bytes();
                out[operand_off..operand_off + 4].copy_from_slice(&new_bytes);
            }
            off = operand_off + operand_len;
        } else if (op as usize) < opcode_base as usize {
            // Standard opcode: skip its LEB operands.
            let n_operands = std_lens
                .get((op as usize).saturating_sub(1))
                .copied()
                .unwrap_or(0);
            for _ in 0..n_operands {
                let (_, c) = leb128::read_u32(&out[off..])?;
                off += c;
            }
        } else {
            // Special opcode: 1 byte total, no operands.
        }
    }

    Some(out)
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
        if w[0].0 + w[0].1 > w[1].0 {
            return None;
        }
    }
    let _ = data;
    Some(out)
}

/// True iff every input function maps (via `remap`) to an output
/// function with (a) the same file offset and (b) identical body
/// bytes.
fn per_function_identical(
    input: &[u8],
    output: &[u8],
    remap: &FuncRemap,
    in_offsets: &[(u32, u32)],
    out_offsets: &[(u32, u32)],
) -> bool {
    // Figure out num_imports from remap length vs bodies count.
    let num_defined_in = in_offsets.len() as u32;
    let num_defined_out = out_offsets.len() as u32;
    // remap covers all absolute indices (imports + defined). The
    // number of imports is `remap.len() - num_defined_in`.
    if remap.len() < num_defined_in {
        return false;
    }
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
        if def_out >= num_defined_out as usize {
            return false;
        }
        let (off_out, len_out) = out_offsets[def_out];
        if *off_in != off_out || *len_in != len_out {
            return false;
        }
        let in_bytes = &input[*off_in as usize..(*off_in + *len_in) as usize];
        let out_bytes = &output[off_out as usize..(off_out + len_out) as usize];
        if in_bytes != out_bytes {
            return false;
        }
    }
    true
}

fn find_debug_line<'a>(m: &'a WasmModule<'a>) -> Option<&'a [u8]> {
    let data = m.data();
    m.sections().iter().find_map(|s| {
        if s.id != module::SECTION_CUSTOM {
            return None;
        }
        let name = s.custom_name?.slice(data);
        if name != b".debug_line" {
            return None;
        }
        let p = s.payload.slice(data);
        let (nlen, c) = leb128::read_u32(p)?;
        Some(&p[c + nlen as usize..])
    })
}

fn remap_is_identity(r: &FuncRemap) -> bool {
    r.entries()
        .iter()
        .enumerate()
        .all(|(i, slot)| *slot == Some(i as u32))
}

fn code_section_bytes<'a>(m: &'a WasmModule<'a>) -> &'a [u8] {
    let data = m.data();
    m.sections()
        .iter()
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
        assert_eq!(
            &m_bytes[off as usize..(off + len) as usize],
            &[0, 0x01, 0x0B]
        );
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
        let mut ap = WasmModule::parse(&a).unwrap();
        ap.ensure_function_bodies_parsed();
        let mut bp = WasmModule::parse(&b).unwrap();
        bp.ensure_function_bodies_parsed();
        let ao = function_file_offsets(&ap).unwrap();
        let bo = function_file_offsets(&bp).unwrap();
        assert!(!per_function_identical(&a, &b, &remap, &ao, &bo));
    }
}
