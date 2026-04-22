// Type GC pass.
//
// Removes types not referenced by any function, import, or call_indirect.
// Remaps type indices in function section, imports, and code section.

use crate::leb128;
use crate::module::WasmModule;
use crate::module::{self};
use crate::opcode;

/// Result of type GC: which types to keep and how to remap.
pub struct TypeGcResult {
    /// For each original type index, the new index (None if removed).
    pub index_map: Vec<Option<u32>>,
    pub kept: usize,
    /// If true, the pass gave up (e.g. unrecognised type form) and
    /// the caller must emit the module unchanged.
    pub bail: bool,
}

/// Walk the type section and return the end offset of each type entry
/// (relative to the type-section payload). Returns None if we encounter
/// anything we don't understand — GC types, rec groups, reftype valtypes,
/// component-model forms, truncated input, etc. In that case the caller
/// must not mutate the module.
fn type_entry_ends(payload: &[u8]) -> Option<Vec<usize>> {
    let (count, mut off) = leb128::read_u32(payload)?;
    let mut ends = Vec::with_capacity(count as usize);
    for _ in 0..count {
        // Form byte: only plain 0x60 func types are handled here.
        if *payload.get(off)? != 0x60 {
            return None;
        }
        off += 1;
        let (param_count, c) = leb128::read_u32(payload.get(off..)?)?;
        off += c;
        for _ in 0..param_count {
            let b = *payload.get(off)?;
            off += 1;
            // Accept only numeric valtypes: i32 0x7F, i64 0x7E, f32 0x7D,
            // f64 0x7C, v128 0x7B. Reftypes (0x70, 0x6F, 0x63, 0x64, …)
            // may be followed by a heap-type LEB — we'd need a full
            // decoder. Bail rather than guess.
            if !matches!(b, 0x7B..=0x7F) {
                return None;
            }
        }
        let (result_count, c) = leb128::read_u32(payload.get(off..)?)?;
        off += c;
        for _ in 0..result_count {
            let b = *payload.get(off)?;
            off += 1;
            if !matches!(b, 0x7B..=0x7F) {
                return None;
            }
        }
        ends.push(off);
    }
    (off == payload.len()).then_some(ends)
}

/// Analyse which types are referenced.
pub fn analyse(module: &WasmModule<'_>) -> TypeGcResult {
    let data = module.data();

    let Some(type_sec) = module.section(module::SECTION_TYPE) else {
        return TypeGcResult {
            index_map: Vec::new(),
            kept: 0,
            bail: false,
        };
    };
    let type_payload = type_sec.payload.slice(data);
    let Some(ends) = type_entry_ends(type_payload) else {
        return TypeGcResult {
            index_map: Vec::new(),
            kept: 0,
            bail: true,
        };
    };
    let num_types = ends.len();

    // Types can also be referenced from: call_indirect, block/loop/if
    // block-types, try/try_table (EH), tag sections, and element segment
    // init expressions. Without a full instruction decoder we conservatively
    // over-approximate: any byte inside the code/element sections that looks
    // like it *could* be one of those opcodes causes us to mark the following
    // LEB-decoded value as a used type. Plus any tag section → bail.
    const SECTION_TAG: u8 = 13;
    if module.section(SECTION_TAG).is_some() {
        return TypeGcResult {
            index_map: (0..num_types as u32).map(Some).collect(),
            kept: num_types,
            bail: false,
        };
    }

    let mut used = vec![false; num_types];
    let mut mark = |idx: u32| {
        if let Some(slot) = used.get_mut(idx as usize) {
            *slot = true;
        }
    };
    for sec_id in [module::SECTION_CODE, module::SECTION_ELEMENT] {
        if let Some(sec) = module.section(sec_id) {
            let bytes = sec.payload.slice(data);
            let mut i = 0;
            while i < bytes.len() {
                let op = bytes[i];
                i += 1;
                // block/loop/if/try/try_table/legacy-catch: blocktype follows.
                // blocktype is a signed-LEB (s33) — if non-negative, it's a type idx.
                if matches!(op, 0x02 | 0x03 | 0x04 | 0x06 | 0x1f) {
                    if let Some((val, _)) = leb128::read_u32(&bytes[i..]) {
                        // 0x40 = empty; 0x6F..=0x7F = valtypes. Otherwise treat as type idx.
                        if val != 0x40 && !matches!(val as u8, 0x6F..=0x7F) {
                            mark(val);
                        }
                    }
                }
                // call_indirect: type idx follows.
                if op == 0x11 {
                    if let Some((val, _)) = leb128::read_u32(&bytes[i..]) {
                        mark(val);
                    }
                }
            }
        }
    }

    // Scan function section: each entry is a type index.
    if let Some(sec) = module.section(module::SECTION_FUNCTION) {
        let payload = sec.payload.slice(data);
        if let Some((count, mut off)) = leb128::read_u32(payload) {
            for _ in 0..count {
                if let Some((type_idx, c)) = leb128::read_u32(&payload[off..]) {
                    off += c;
                    if (type_idx as usize) < num_types {
                        used[type_idx as usize] = true;
                    }
                }
            }
        }
    }

    // Scan import section: function imports reference type indices.
    if let Some(sec) = module.section(module::SECTION_IMPORT) {
        let payload = sec.payload.slice(data);
        if let Some((count, mut off)) = leb128::read_u32(payload) {
            for _ in 0..count {
                // module name
                if let Some((len, c)) = leb128::read_u32(&payload[off..]) {
                    off += c + len as usize;
                } else {
                    break;
                }
                // field name
                if let Some((len, c)) = leb128::read_u32(&payload[off..]) {
                    off += c + len as usize;
                } else {
                    break;
                }
                // kind
                if off >= payload.len() {
                    break;
                }
                let kind = payload[off];
                off += 1;
                match kind {
                    0x00 => {
                        // Function import: type index
                        if let Some((type_idx, c)) = leb128::read_u32(&payload[off..]) {
                            off += c;
                            if (type_idx as usize) < num_types {
                                used[type_idx as usize] = true;
                            }
                        }
                    }
                    0x01 => {
                        // Table: elemtype + limits
                        off += 1; // elemtype
                        let flags = payload.get(off).copied().unwrap_or(0);
                        off += 1;
                        if let Some((_, c)) = leb128::read_u32(&payload[off..]) {
                            off += c;
                        }
                        if flags & 1 != 0 {
                            if let Some((_, c)) = leb128::read_u32(&payload[off..]) {
                                off += c;
                            }
                        }
                    }
                    0x02 => {
                        // Memory: limits
                        let flags = payload.get(off).copied().unwrap_or(0);
                        off += 1;
                        if let Some((_, c)) = leb128::read_u32(&payload[off..]) {
                            off += c;
                        }
                        if flags & 1 != 0 {
                            if let Some((_, c)) = leb128::read_u32(&payload[off..]) {
                                off += c;
                            }
                        }
                    }
                    0x03 => {
                        // Global: valtype + mutability
                        off += 2;
                    }
                    _ => break,
                }
            }
        }
    }

    // Build index map.
    let mut index_map = Vec::with_capacity(num_types);
    let mut new_idx = 0u32;
    let mut kept = 0;
    for &u in &used {
        if u {
            index_map.push(Some(new_idx));
            new_idx += 1;
            kept += 1;
        } else {
            index_map.push(None);
        }
    }

    TypeGcResult {
        index_map,
        kept,
        bail: false,
    }
}

/// Apply type GC to a module, producing new bytes.
pub fn apply(module: &WasmModule<'_>) -> Vec<u8> {
    let result = analyse(module);
    let data = module.data();

    // Bail: we hit something we don't understand during analysis.
    // Emit the module unchanged rather than risk corruption.
    if result.bail {
        return data.to_vec();
    }

    // If nothing was removed, return unchanged.
    let num_types = result.index_map.len();
    if result.kept == num_types {
        return data.to_vec();
    }

    // If surviving types keep their original indices (only trailing types
    // were removed), bodies don't need rewriting. Otherwise we must walk
    // the code section and remap blocktype / call_indirect type immediates,
    // or this pass silently corrupts the module.
    let needs_body_rewrite = result
        .index_map
        .iter()
        .enumerate()
        .any(|(i, m)| matches!(m, Some(new_i) if *new_i as usize != i));

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..8]);

    for section in module.sections() {
        match section.id {
            module::SECTION_TYPE => {
                emit_filtered_type_section(&mut out, section, data, &result);
            }
            module::SECTION_FUNCTION => {
                emit_remapped_function_section(&mut out, section, data, &result);
            }
            module::SECTION_IMPORT if needs_body_rewrite => {
                if !emit_remapped_import_section(&mut out, section, data, &result) {
                    return data.to_vec();
                }
            }
            module::SECTION_CODE if needs_body_rewrite => {
                if !emit_remapped_code_section(&mut out, section, data, &result) {
                    // Body walk bailed — fall back to emitting input unchanged.
                    return data.to_vec();
                }
            }
            _ => {
                out.extend_from_slice(section.full.slice(data));
            }
        }
    }

    out
}

/// Rewrite block/loop/if blocktype and call_indirect type-index immediates
/// in every function body. Returns false on any decoding failure — caller
/// must then emit the module unchanged.
fn emit_remapped_code_section(
    out: &mut Vec<u8>,
    section: &module::Section,
    data: &[u8],
    result: &TypeGcResult,
) -> bool {
    let payload = section.payload.slice(data);
    let Some((count, hdr_len)) = leb128::read_u32(payload) else {
        return false;
    };

    let mut new_payload = Vec::with_capacity(payload.len());
    leb128::write_u32(&mut new_payload, count);

    let mut off = hdr_len;
    for _ in 0..count {
        let Some((body_size, c)) = leb128::read_u32(&payload[off..]) else {
            return false;
        };
        off += c;
        let body_end = match off.checked_add(body_size as usize) {
            Some(n) if n <= payload.len() => n,
            _ => return false,
        };
        let body = &payload[off..body_end];

        let Some(new_body) = rewrite_body_type_refs(body, &result.index_map) else {
            return false;
        };

        leb128::write_u32(&mut new_payload, new_body.len() as u32);
        new_payload.extend_from_slice(&new_body);
        off = body_end;
    }

    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
    true
}

/// Remap function-import type indices. Non-function imports are copied
/// byte-for-byte. Returns false on any decode failure.
fn emit_remapped_import_section(
    out: &mut Vec<u8>,
    section: &module::Section,
    data: &[u8],
    result: &TypeGcResult,
) -> bool {
    let payload = section.payload.slice(data);
    let Some((count, hdr_len)) = leb128::read_u32(payload) else {
        return false;
    };

    let mut new_payload = Vec::with_capacity(payload.len());
    leb128::write_u32(&mut new_payload, count);

    let mut off = hdr_len;
    for _ in 0..count {
        let entry_start = off;
        // module name
        let Some((mlen, c)) = leb128::read_u32(payload.get(off..).unwrap_or(&[])) else {
            return false;
        };
        off += c + mlen as usize;
        if off > payload.len() {
            return false;
        }
        // field name
        let Some((flen, c)) = leb128::read_u32(payload.get(off..).unwrap_or(&[])) else {
            return false;
        };
        off += c + flen as usize;
        if off >= payload.len() {
            return false;
        }
        let kind = payload[off];
        off += 1;
        match kind {
            0x00 => {
                // Function: type index — remap.
                let Some((type_idx, c)) = leb128::read_u32(payload.get(off..).unwrap_or(&[]))
                else {
                    return false;
                };
                let new_idx = match result.index_map.get(type_idx as usize).copied().flatten() {
                    Some(n) => n,
                    None => return false,
                };
                new_payload.extend_from_slice(&payload[entry_start..off]);
                leb128::write_u32(&mut new_payload, new_idx);
                off += c;
            }
            0x01 => {
                // Table: elemtype + limits
                let table_start = off;
                off += 1;
                let flags = *payload.get(off).unwrap_or(&0);
                off += 1;
                let Some((_, c)) = leb128::read_u32(payload.get(off..).unwrap_or(&[])) else {
                    return false;
                };
                off += c;
                if flags & 1 != 0 {
                    let Some((_, c)) = leb128::read_u32(payload.get(off..).unwrap_or(&[])) else {
                        return false;
                    };
                    off += c;
                }
                new_payload.extend_from_slice(&payload[entry_start..table_start]);
                new_payload.extend_from_slice(&payload[table_start..off]);
            }
            0x02 => {
                // Memory: limits
                let mem_start = off;
                let flags = *payload.get(off).unwrap_or(&0);
                off += 1;
                let Some((_, c)) = leb128::read_u32(payload.get(off..).unwrap_or(&[])) else {
                    return false;
                };
                off += c;
                if flags & 1 != 0 {
                    let Some((_, c)) = leb128::read_u32(payload.get(off..).unwrap_or(&[])) else {
                        return false;
                    };
                    off += c;
                }
                new_payload.extend_from_slice(&payload[entry_start..mem_start]);
                new_payload.extend_from_slice(&payload[mem_start..off]);
            }
            0x03 => {
                // Global: valtype (1 byte) + mutability (1 byte)
                let glob_start = off;
                off += 2;
                if off > payload.len() {
                    return false;
                }
                new_payload.extend_from_slice(&payload[entry_start..glob_start]);
                new_payload.extend_from_slice(&payload[glob_start..off]);
            }
            _ => return false,
        }
    }

    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
    true
}

fn rewrite_body_type_refs(body: &[u8], map: &[Option<u32>]) -> Option<Vec<u8>> {
    let instrs_start = opcode::skip_locals(body)?;
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[..instrs_start]);

    let mut cursor = instrs_start;
    let mut iter = opcode::InstrIter::new(body, instrs_start);
    while let Some((p, _)) = iter.next() {
        let op = body[p];
        let imm_off = p + 1;

        if matches!(op, 0x02 | 0x03 | 0x04) {
            // Blocktype: 0x40 (empty), single-byte valtype (0x6F..=0x7F),
            // or non-negative s33 type index. u32 LEB-decodes identically
            // to positive s33, so we can reuse read_u32.
            let (val, vc) = leb128::read_u32(body.get(imm_off..)?)?;
            let is_typeidx = val != 0x40 && !matches!(val as u8, 0x6F..=0x7F);
            if is_typeidx {
                let new_idx = map.get(val as usize).copied().flatten()?;
                if new_idx != val {
                    out.extend_from_slice(&body[cursor..p]);
                    out.push(op);
                    leb128::write_u32(&mut out, new_idx);
                    cursor = imm_off + vc;
                }
            }
        } else if op == 0x11 {
            // call_indirect: type_idx LEB, then table_idx LEB.
            let (val, vc) = leb128::read_u32(body.get(imm_off..)?)?;
            let new_idx = map.get(val as usize).copied().flatten()?;
            if new_idx != val {
                out.extend_from_slice(&body[cursor..p]);
                out.push(op);
                leb128::write_u32(&mut out, new_idx);
                cursor = imm_off + vc;
            }
        }
    }
    if iter.failed() {
        return None;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

fn emit_filtered_type_section(
    out: &mut Vec<u8>,
    section: &module::Section,
    data: &[u8],
    result: &TypeGcResult,
) {
    let payload = section.payload.slice(data);
    // analyse() already guaranteed this succeeds (otherwise it sets bail).
    let Some(ends) = type_entry_ends(payload) else {
        out.extend_from_slice(section.full.slice(data));
        return;
    };
    let header_len = leb128::read_u32(payload).map(|(_, c)| c).unwrap_or(0);

    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, result.kept as u32);

    let mut start = header_len;
    for (i, &end) in ends.iter().enumerate() {
        if result.index_map.get(i).copied().flatten().is_some() {
            new_payload.extend_from_slice(&payload[start..end]);
        }
        start = end;
    }

    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn emit_remapped_function_section(
    out: &mut Vec<u8>,
    section: &module::Section,
    data: &[u8],
    result: &TypeGcResult,
) {
    let payload = section.payload.slice(data);
    let Some((count, mut off)) = leb128::read_u32(payload) else {
        out.extend_from_slice(section.full.slice(data));
        return;
    };

    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, count);
    for _ in 0..count {
        let Some((type_idx, c)) = leb128::read_u32(&payload[off..]) else {
            break;
        };
        off += c;
        let new_type = result
            .index_map
            .get(type_idx as usize)
            .copied()
            .flatten()
            .unwrap_or(type_idx);
        leb128::write_u32(&mut new_payload, new_type);
    }

    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_module_two_types() -> Vec<u8> {
        let mut data = b"\0asm\x01\x00\x00\x00".to_vec();
        // Type section: 2 types
        // type 0: () -> ()
        // type 1: (i32) -> (i32)
        data.extend_from_slice(&[
            1, 9, 2, 0x60, 0, 0, // type 0
            0x60, 1, 0x7F, 1, 0x7F, // type 1
        ]);
        // Function section: 1 function using type 0 (type 1 unused)
        data.extend_from_slice(&[3, 2, 1, 0]);
        // Export
        data.extend_from_slice(&[7, 5, 1, 1, b'f', 0x00, 0]);
        // Code section: 1 body
        data.extend_from_slice(&[10, 4, 1, 2, 0, 0x0B]);
        data
    }

    #[test]
    fn type_gc_removes_unused() {
        let data = build_module_two_types();
        let module = WasmModule::parse(&data).unwrap();
        let result = analyse(&module);
        assert_eq!(result.kept, 1);
        assert_eq!(result.index_map, vec![Some(0), None]);
    }

    #[test]
    fn type_gc_apply_shrinks() {
        let data = build_module_two_types();
        let module = WasmModule::parse(&data).unwrap();
        let output = apply(&module);
        assert!(output.len() < data.len());

        // Verify output is valid.
        let module2 = WasmModule::parse(&output).unwrap();
        assert_eq!(module2.function_count(), 1);
    }

    #[test]
    fn type_gc_noop_all_used() {
        let mut data = b"\0asm\x01\x00\x00\x00".to_vec();
        // 1 type, 1 function using it
        data.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        data.extend_from_slice(&[3, 2, 1, 0]);
        data.extend_from_slice(&[7, 5, 1, 1, b'f', 0x00, 0]);
        data.extend_from_slice(&[10, 4, 1, 2, 0, 0x0B]);

        let module = WasmModule::parse(&data).unwrap();
        let output = apply(&module);
        assert_eq!(output, data);
    }
}
