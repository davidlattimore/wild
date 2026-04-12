// Dead Code Elimination pass.
//
// Removes functions not reachable from exports or the start function.
// Produces a new module with unreachable functions removed and all
// indices remapped.

use crate::leb128;
use crate::module::{self, WasmModule};
use crate::scan;

/// Result of DCE analysis: which functions to keep.
pub struct DceResult {
    /// For each original function index, the new index (None if removed).
    pub index_map: Vec<Option<u32>>,
    /// Number of functions kept.
    pub kept: usize,
}

/// Analyse which functions are reachable from exports and start function.
pub fn analyse(module: &mut WasmModule<'_>) -> DceResult {
    let exported = module.exported_function_indices();
    let start = module.start_function();

    let mut roots: Vec<u32> = exported;
    if let Some(s) = start {
        roots.push(s);
    }

    let graph = scan::call_graph(module);
    let reachable = scan::reachable_from(&graph, &roots);

    let mut index_map = Vec::with_capacity(reachable.len());
    let mut new_idx = 0u32;
    let mut kept = 0;
    for &r in &reachable {
        if r {
            index_map.push(Some(new_idx));
            new_idx += 1;
            kept += 1;
        } else {
            index_map.push(None);
        }
    }

    DceResult { index_map, kept }
}

/// Apply DCE to a module, producing new bytes.
pub fn apply(module: &mut WasmModule<'_>) -> Vec<u8> {
    let result = analyse(module);
    let data = module.data();

    // If nothing was removed, return unchanged.
    if result.kept == module.num_function_bodies() {
        return data.to_vec();
    }

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..8]); // header

    for section in module.sections() {
        match section.id {
            module::SECTION_FUNCTION => {
                emit_filtered_function_section(&mut out, section, data, &result);
            }
            module::SECTION_CODE => {
                emit_filtered_code_section(&mut out, module, data, &result);
            }
            module::SECTION_EXPORT => {
                emit_remapped_export_section(&mut out, section, data, &result);
            }
            _ => {
                // Copy verbatim.
                out.extend_from_slice(section.full.slice(data));
            }
        }
    }

    out
}

fn emit_filtered_function_section(
    out: &mut Vec<u8>,
    section: &module::Section,
    data: &[u8],
    result: &DceResult,
) {
    let payload = section.payload.slice(data);
    let Some((count, mut off)) = leb128::read_u32(payload) else {
        out.extend_from_slice(section.full.slice(data));
        return;
    };

    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, result.kept as u32);
    for i in 0..count {
        let Some((type_idx, c)) = leb128::read_u32(&payload[off..]) else {
            break;
        };
        off += c;
        if result.index_map.get(i as usize) == Some(&None) {
            continue;
        }
        leb128::write_u32(&mut new_payload, type_idx);
    }

    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn emit_filtered_code_section(
    out: &mut Vec<u8>,
    module: &WasmModule<'_>,
    data: &[u8],
    result: &DceResult,
) {
    let bodies = module.function_bodies();
    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, result.kept as u32);
    for (i, body) in bodies.iter().enumerate() {
        if result.index_map.get(i) == Some(&None) {
            continue;
        }
        // Copy body verbatim — zero-copy in spirit.
        new_payload.extend_from_slice(body.full.slice(data));
    }

    out.push(module::SECTION_CODE);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn emit_remapped_export_section(
    out: &mut Vec<u8>,
    section: &module::Section,
    data: &[u8],
    result: &DceResult,
) {
    let payload = section.payload.slice(data);
    let Some((count, mut off)) = leb128::read_u32(payload) else {
        out.extend_from_slice(section.full.slice(data));
        return;
    };

    // Build new export section, remapping function indices.
    let mut entries = Vec::new();
    for _ in 0..count {
        let Some((name_len, c)) = leb128::read_u32(&payload[off..]) else {
            break;
        };
        let name_start = off + c;
        off = name_start + name_len as usize;
        let kind = payload[off];
        off += 1;
        let Some((index, c)) = leb128::read_u32(&payload[off..]) else {
            break;
        };
        off += c;

        let new_index = if kind == 0x00 {
            // Function export — remap.
            match result.index_map.get(index as usize) {
                Some(Some(new_idx)) => *new_idx,
                _ => continue, // removed (shouldn't happen for exports)
            }
        } else {
            index // non-function: keep as-is
        };

        entries.push((
            &payload[name_start..name_start + name_len as usize],
            kind,
            new_index,
        ));
    }

    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, entries.len() as u32);
    for (name, kind, index) in &entries {
        leb128::write_u32(&mut new_payload, name.len() as u32);
        new_payload.extend_from_slice(name);
        new_payload.push(*kind);
        leb128::write_u32(&mut new_payload, *index);
    }

    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_module_with_functions(num_funcs: usize, exports: &[(u32, &str)]) -> Vec<u8> {
        let mut data = b"\0asm\x01\x00\x00\x00".to_vec();

        // Type section: 1 type, () -> ()
        data.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);

        // Function section
        let mut func_payload = Vec::new();
        leb128::write_u32(&mut func_payload, num_funcs as u32);
        for _ in 0..num_funcs {
            leb128::write_u32(&mut func_payload, 0);
        }
        data.push(3);
        leb128::write_u32(&mut data, func_payload.len() as u32);
        data.extend_from_slice(&func_payload);

        // Export section
        let mut export_payload = Vec::new();
        leb128::write_u32(&mut export_payload, exports.len() as u32);
        for &(idx, name) in exports {
            leb128::write_u32(&mut export_payload, name.len() as u32);
            export_payload.extend_from_slice(name.as_bytes());
            export_payload.push(0x00);
            leb128::write_u32(&mut export_payload, idx);
        }
        data.push(7);
        leb128::write_u32(&mut data, export_payload.len() as u32);
        data.extend_from_slice(&export_payload);

        // Code section
        let mut code_payload = Vec::new();
        leb128::write_u32(&mut code_payload, num_funcs as u32);
        for _ in 0..num_funcs {
            code_payload.push(2); // body size
            code_payload.push(0); // 0 locals
            code_payload.push(0x0B); // end
        }
        data.push(10);
        leb128::write_u32(&mut data, code_payload.len() as u32);
        data.extend_from_slice(&code_payload);

        data
    }

    #[test]
    fn dce_removes_unused() {
        let data = build_module_with_functions(3, &[(0, "_start")]);
        let mut module = WasmModule::parse(&data).unwrap();
        let result = analyse(&mut module);
        assert_eq!(result.kept, 1);
        assert_eq!(result.index_map, vec![Some(0), None, None]);
    }

    #[test]
    fn dce_keeps_all_exported() {
        let data = build_module_with_functions(2, &[(0, "a"), (1, "b")]);
        let mut module = WasmModule::parse(&data).unwrap();
        let result = analyse(&mut module);
        assert_eq!(result.kept, 2);
    }

    #[test]
    fn dce_apply_shrinks_output() {
        let data = build_module_with_functions(3, &[(0, "_start")]);
        let mut module = WasmModule::parse(&data).unwrap();
        let output = apply(&mut module);

        assert!(output.len() < data.len(), "DCE should shrink the module");

        // Output should be valid.
        let module2 = WasmModule::parse(&output).unwrap();
        assert_eq!(module2.function_count(), 1);
    }

    #[test]
    fn dce_noop_when_all_reachable() {
        let data = build_module_with_functions(1, &[(0, "_start")]);
        let mut module = WasmModule::parse(&data).unwrap();
        let output = apply(&mut module);
        assert_eq!(output, data);
    }
}
