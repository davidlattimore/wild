//! Duplicate-import elimination.
//!
//! Merges function imports that share (module, field, type_idx). The first
//! occurrence is canonical; later copies are removed from the import
//! section, and all callers are remapped to the canonical's new index.
//!
//! Removing imports shifts the function index space: every imported
//! function after a removed dup shifts down by one, and every defined
//! function shifts down by the total number of removed imports.

use crate::leb128;
use crate::module::WasmModule;
use crate::module::{self};
use std::collections::HashMap;

pub fn apply(module: &mut WasmModule<'_>) -> Vec<u8> {
    apply_with_remap(module).0
}

pub fn apply_with_remap(module: &mut WasmModule<'_>) -> (Vec<u8>, crate::remap::FuncRemap) {
    module.ensure_function_bodies_parsed();
    let num_defined = module.num_function_bodies() as u32;
    let data = module.data();
    let Some((entries, num_func_imports)) = super::dce::parse_imports(module) else {
        return (
            data.to_vec(),
            crate::remap::FuncRemap::identity(num_defined),
        );
    };
    if num_func_imports < 2 {
        return (
            data.to_vec(),
            crate::remap::FuncRemap::identity(num_func_imports + num_defined),
        );
    }

    // Group function imports by (module, field, type_idx). Canonical = first.
    let mut canonical_of: Vec<u32> = (0..num_func_imports).collect();
    let mut seen: HashMap<(&str, &str, u32), u32> = HashMap::new();
    let mut func_cursor = 0u32;
    let mut found_dup = false;
    for e in &entries {
        if e.kind != 0x00 {
            continue;
        }
        let key = (e.module_name, e.field_name, e.type_idx);
        match seen.get(&key) {
            Some(&canonical) => {
                canonical_of[func_cursor as usize] = canonical;
                found_dup = true;
            }
            None => {
                seen.insert(key, func_cursor);
            }
        }
        func_cursor += 1;
    }
    if !found_dup {
        return (
            data.to_vec(),
            crate::remap::FuncRemap::identity(num_func_imports + num_defined),
        );
    }

    if !super::dce::all_bodies_walkable(module) {
        return (
            data.to_vec(),
            crate::remap::FuncRemap::identity(num_func_imports + num_defined),
        );
    }

    // Compute new-position for every function-import index (skipping dups).
    // new_of[old_func_idx] = Some(new_func_idx) if kept, None if collapsed
    // into canonical. Collapsed entries point at the canonical's NEW index.
    let mut new_func_of: Vec<u32> = vec![0; num_func_imports as usize];
    let mut kept = 0u32;
    for i in 0..num_func_imports {
        if canonical_of[i as usize] == i {
            new_func_of[i as usize] = kept;
            kept += 1;
        }
    }
    // Second pass for dups — they map to their canonical's new index.
    for i in 0..num_func_imports {
        let c = canonical_of[i as usize];
        if c != i {
            new_func_of[i as usize] = new_func_of[c as usize];
        }
    }

    // Build full index_map covering all absolute function indices.
    let total = num_func_imports + num_defined;

    let mut index_map: Vec<Option<u32>> = Vec::with_capacity(total as usize);
    for i in 0..num_func_imports {
        index_map.push(Some(new_func_of[i as usize]));
    }
    for i in 0..num_defined {
        index_map.push(Some(kept + i));
    }

    // Safety rail: bail on element sections we can't rewrite. DCE's shared
    // emit falls back to verbatim, which here would carry stale indices.
    if let Some(sec) = module.section(module::SECTION_ELEMENT) {
        if super::dce::scan_elements_funcidx(sec.payload.slice(data)).is_none() {
            return (data.to_vec(), crate::remap::FuncRemap::identity(total));
        }
    }

    let bytes = emit(
        module,
        data,
        &index_map,
        &entries,
        &canonical_of,
        num_func_imports,
    );
    (bytes, crate::remap::FuncRemap::from_entries(index_map))
}

fn emit(
    module: &WasmModule<'_>,
    data: &[u8],
    index_map: &[Option<u32>],
    entries: &[super::dce::ImportEntry<'_>],
    canonical_of: &[u32],
    num_func_imports: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..8]);

    for section in module.sections() {
        match section.id {
            module::SECTION_IMPORT => emit_imports(
                &mut out,
                section,
                data,
                entries,
                canonical_of,
                num_func_imports,
            ),
            module::SECTION_EXPORT => {
                super::dce::emit_remapped_export_section(&mut out, section, data, index_map)
            }
            module::SECTION_GLOBAL => {
                super::dce::emit_remapped_global_section(&mut out, section, data, index_map)
            }
            module::SECTION_ELEMENT => {
                super::dce::emit_remapped_element_section(&mut out, section, data, index_map)
            }
            module::SECTION_START => {
                super::dce::emit_remapped_start_section(&mut out, section, data, index_map)
            }
            module::SECTION_CODE => emit_code(&mut out, module, data, index_map),
            _ => out.extend_from_slice(section.full.slice(data)),
        }
    }
    out
}

fn emit_imports(
    out: &mut Vec<u8>,
    section: &module::Section,
    data: &[u8],
    entries: &[super::dce::ImportEntry<'_>],
    canonical_of: &[u32],
    _num_func_imports: u32,
) {
    let payload = section.payload.slice(data);
    let mut new_payload = Vec::new();
    // Count kept entries: non-function imports (all kept) + canonical functions.
    let mut keep = Vec::new();
    let mut fi = 0u32;
    for e in entries {
        if e.kind == 0x00 {
            let canonical = canonical_of[fi as usize];
            if canonical == fi {
                keep.push(e);
            }
            fi += 1;
        } else {
            keep.push(e);
        }
    }
    leb128::write_u32(&mut new_payload, keep.len() as u32);
    for e in keep {
        let (off, len) = e.span;
        new_payload.extend_from_slice(&payload[off..off + len]);
    }
    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn emit_code(out: &mut Vec<u8>, module: &WasmModule<'_>, data: &[u8], index_map: &[Option<u32>]) {
    let bodies = module.function_bodies();
    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, bodies.len() as u32);
    for body in bodies {
        let body_bytes = body.body.slice(data);
        let rewritten = super::dce::rewrite_body(body_bytes, index_map)
            .expect("body walkability guaranteed by precheck");
        leb128::write_u32(&mut new_payload, rewritten.len() as u32);
        new_payload.extend_from_slice(&rewritten);
    }
    out.push(module::SECTION_CODE);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}
