// Type GC pass.
//
// Removes types not referenced by any function, import, or call_indirect.
// Remaps type indices in function section, imports, and code section.

use crate::leb128;
use crate::module::{self, WasmModule};

/// Result of type GC: which types to keep and how to remap.
pub struct TypeGcResult {
    /// For each original type index, the new index (None if removed).
    pub index_map: Vec<Option<u32>>,
    pub kept: usize,
}

/// Analyse which types are referenced.
pub fn analyse(module: &WasmModule<'_>) -> TypeGcResult {
    let data = module.data();

    // Count types.
    let num_types = match module.section(module::SECTION_TYPE) {
        Some(sec) => {
            let payload = sec.payload.slice(data);
            leb128::read_u32(payload).map(|(c, _)| c as usize).unwrap_or(0)
        }
        None => return TypeGcResult { index_map: Vec::new(), kept: 0 },
    };

    let mut used = vec![false; num_types];

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
                        if let Some((_, c)) = leb128::read_u32(&payload[off..]) { off += c; }
                        if flags & 1 != 0 {
                            if let Some((_, c)) = leb128::read_u32(&payload[off..]) { off += c; }
                        }
                    }
                    0x02 => {
                        // Memory: limits
                        let flags = payload.get(off).copied().unwrap_or(0);
                        off += 1;
                        if let Some((_, c)) = leb128::read_u32(&payload[off..]) { off += c; }
                        if flags & 1 != 0 {
                            if let Some((_, c)) = leb128::read_u32(&payload[off..]) { off += c; }
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

    TypeGcResult { index_map, kept }
}

/// Apply type GC to a module, producing new bytes.
pub fn apply(module: &WasmModule<'_>) -> Vec<u8> {
    let result = analyse(module);
    let data = module.data();

    // If nothing was removed, return unchanged.
    let num_types = result.index_map.len();
    if result.kept == num_types {
        return data.to_vec();
    }

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
            _ => {
                out.extend_from_slice(section.full.slice(data));
            }
        }
    }

    out
}

fn emit_filtered_type_section(
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
    leb128::write_u32(&mut new_payload, result.kept as u32);

    for i in 0..count {
        let start = off;
        // Parse type entry to find its end.
        if off >= payload.len() {
            break;
        }
        let form = payload[off]; // 0x60 = func
        off += 1;
        // params
        if let Some((param_count, c)) = leb128::read_u32(&payload[off..]) {
            off += c + param_count as usize;
        }
        // results
        if let Some((result_count, c)) = leb128::read_u32(&payload[off..]) {
            off += c + result_count as usize;
        }

        if result.index_map.get(i as usize) != Some(&None) {
            // Keep this type — copy bytes verbatim.
            new_payload.extend_from_slice(&payload[start..off]);
        }
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
        let new_type = result.index_map
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
        data.extend_from_slice(&[1, 9, 2,
            0x60, 0, 0,           // type 0
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
