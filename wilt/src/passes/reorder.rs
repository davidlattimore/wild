//! Renumber defined functions by descending call frequency so that hot
//! targets sit in small-LEB indices. Each `call` / `ref.func` / export /
//! element / global-init reference to a function whose index crosses a
//! LEB byte boundary (128, 16384, …) gets shorter.
//!
//! Imports stay fixed (can't reshuffle the import space). Only defined
//! functions are permuted.

use crate::leb128;
use crate::module::WasmModule;
use crate::module::{self};
use crate::opcode;

pub fn apply(module: &mut WasmModule<'_>) -> Vec<u8> {
    apply_with_remap(module).0
}

pub fn apply_with_remap(module: &mut WasmModule<'_>) -> (Vec<u8>, crate::remap::FuncRemap) {
    module.ensure_function_bodies_parsed();
    let num_defined = module.num_function_bodies() as u32;
    if num_defined < 2 {
        return (
            module.data().to_vec(),
            crate::remap::FuncRemap::identity(
                super::dce::count_func_imports_pub(module) + num_defined,
            ),
        );
    }
    let num_imports = super::dce::count_func_imports_pub(module);
    let total = num_imports + num_defined;
    let data = module.data();

    // Bail in cases where downstream emit isn't safe. Element sections
    // with expr-form variants (flags 4-7) aren't rewritten by our shared
    // emit helper — they'd carry stale indices into the output.
    if let Some(sec) = module.section(module::SECTION_ELEMENT) {
        let p = sec.payload.slice(data);
        if super::dce::scan_elements_funcidx(p).is_none() {
            return (data.to_vec(), crate::remap::FuncRemap::identity(total));
        }
    }

    // Count references to each function (absolute-indexed).
    let mut count = vec![0u32; total as usize];
    for body in module.function_bodies() {
        let b = body.body.slice(data);
        let Some(start) = opcode::skip_locals(b) else {
            return (data.to_vec(), crate::remap::FuncRemap::identity(total));
        };
        let Some(instrs) = opcode::walk(b, start) else {
            return (data.to_vec(), crate::remap::FuncRemap::identity(total));
        };
        for (p, _) in instrs {
            let op = b[p];
            if op == opcode::OP_CALL || op == opcode::OP_REF_FUNC {
                if let Some((t, _)) = leb128::read_u32(&b[p + 1..]) {
                    if (t as usize) < count.len() {
                        count[t as usize] += 1;
                    }
                }
            }
        }
    }
    // Exports, start, globals, elements also reference functions but their
    // count-per-reference is tiny vs call-site counts; include for precision.
    for idx in module.exported_function_indices() {
        if (idx as usize) < count.len() {
            count[idx as usize] += 1;
        }
    }
    if let Some(s) = module.start_function() {
        if (s as usize) < count.len() {
            count[s as usize] += 1;
        }
    }

    // Build a permutation of defined indices, sorted by descending count.
    // Stable by original index on ties so behaviour is deterministic.
    let mut order: Vec<u32> = (num_imports..total).collect();
    order.sort_by(|a, b| count[*b as usize].cmp(&count[*a as usize]).then(a.cmp(b)));

    // If already in best order, no-op.
    if order
        .iter()
        .enumerate()
        .all(|(i, &orig)| orig == num_imports + i as u32)
    {
        return (data.to_vec(), crate::remap::FuncRemap::identity(total));
    }

    // index_map[orig_abs] = new_abs
    let mut index_map: Vec<Option<u32>> = (0..num_imports).map(Some).collect();
    index_map.resize(total as usize, None);
    for (new_local, &orig_abs) in order.iter().enumerate() {
        index_map[orig_abs as usize] = Some(num_imports + new_local as u32);
    }

    let bytes = emit(module, data, &index_map, num_imports, &order);
    (bytes, crate::remap::FuncRemap::from_entries(index_map))
}

/// Apply an arbitrary permutation of defined function indices. The
/// `order` slice maps new defined-position → original absolute index.
/// `imports..total` are reordered; imports stay fixed. Used by both
/// the call-frequency reorder and the layout-for-compression pass.
pub fn apply_with_order(module: &mut WasmModule<'_>, order: Vec<u32>) -> Vec<u8> {
    apply_with_order_remap(module, order).0
}

pub fn apply_with_order_remap(
    module: &mut WasmModule<'_>,
    order: Vec<u32>,
) -> (Vec<u8>, crate::remap::FuncRemap) {
    module.ensure_function_bodies_parsed();
    let num_defined = module.num_function_bodies() as u32;
    let num_imports = super::dce::count_func_imports_pub(module);
    let total = num_imports + num_defined;
    let data = module.data();

    if let Some(sec) = module.section(module::SECTION_ELEMENT) {
        let p = sec.payload.slice(data);
        if super::dce::scan_elements_funcidx(p).is_none() {
            return (data.to_vec(), crate::remap::FuncRemap::identity(total));
        }
    }

    if !super::dce::all_bodies_walkable(module) {
        return (data.to_vec(), crate::remap::FuncRemap::identity(total));
    }

    if order
        .iter()
        .enumerate()
        .all(|(i, &orig)| orig == num_imports + i as u32)
    {
        return (data.to_vec(), crate::remap::FuncRemap::identity(total));
    }

    let mut index_map: Vec<Option<u32>> = (0..num_imports).map(Some).collect();
    index_map.resize(total as usize, None);
    for (new_local, &orig_abs) in order.iter().enumerate() {
        index_map[orig_abs as usize] = Some(num_imports + new_local as u32);
    }
    let bytes = emit(module, data, &index_map, num_imports, &order);
    (bytes, crate::remap::FuncRemap::from_entries(index_map))
}

fn emit(
    module: &WasmModule<'_>,
    data: &[u8],
    index_map: &[Option<u32>],
    num_imports: u32,
    new_order: &[u32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..8]);

    // Read original function-section type indices keyed by abs idx.
    let orig_type_idx = read_function_types(module, data);

    for section in module.sections() {
        match section.id {
            module::SECTION_FUNCTION => {
                emit_function_permuted(&mut out, section, &orig_type_idx, new_order, num_imports);
            }
            module::SECTION_CODE => {
                emit_code_permuted(&mut out, module, data, index_map, new_order, num_imports);
            }
            module::SECTION_EXPORT => {
                super::dce::emit_remapped_export_section(&mut out, section, data, index_map);
            }
            module::SECTION_GLOBAL => {
                super::dce::emit_remapped_global_section(&mut out, section, data, index_map);
            }
            module::SECTION_ELEMENT => {
                super::dce::emit_remapped_element_section(&mut out, section, data, index_map);
            }
            module::SECTION_START => {
                super::dce::emit_remapped_start_section(&mut out, section, data, index_map);
            }
            _ => out.extend_from_slice(section.full.slice(data)),
        }
    }
    out
}

fn read_function_types(module: &WasmModule<'_>, data: &[u8]) -> Vec<u32> {
    let Some(sec) = module.section(module::SECTION_FUNCTION) else {
        return Vec::new();
    };
    let payload = sec.payload.slice(data);
    let Some((count, mut off)) = leb128::read_u32(payload) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let Some((t, c)) = leb128::read_u32(&payload[off..]) else {
            break;
        };
        off += c;
        out.push(t);
    }
    out
}

fn emit_function_permuted(
    out: &mut Vec<u8>,
    section: &module::Section,
    orig_type_idx: &[u32],
    new_order: &[u32],
    num_imports: u32,
) {
    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, new_order.len() as u32);
    for &orig_abs in new_order {
        let local = (orig_abs - num_imports) as usize;
        if let Some(&t) = orig_type_idx.get(local) {
            leb128::write_u32(&mut new_payload, t);
        }
    }
    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn emit_code_permuted(
    out: &mut Vec<u8>,
    module: &WasmModule<'_>,
    data: &[u8],
    index_map: &[Option<u32>],
    new_order: &[u32],
    num_imports: u32,
) {
    let bodies = module.function_bodies();
    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, bodies.len() as u32);
    for &orig_abs in new_order {
        let local = (orig_abs - num_imports) as usize;
        let body = &bodies[local];
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leb128 as l;

    #[test]
    fn reorders_by_call_count() {
        // Build a module with 3 functions, func 2 called most.
        let mut data = b"\0asm\x01\x00\x00\x00".to_vec();
        data.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]); // type () -> ()

        // 3 funcs of type 0
        data.push(3);
        let mut fp = Vec::new();
        l::write_u32(&mut fp, 3);
        for _ in 0..3 {
            l::write_u32(&mut fp, 0);
        }
        l::write_u32(&mut data, fp.len() as u32);
        data.extend_from_slice(&fp);

        // Export func 0 so DCE-ish things don't kick
        data.push(7);
        let mut ep = Vec::new();
        l::write_u32(&mut ep, 1);
        l::write_u32(&mut ep, 1);
        ep.push(b'a');
        ep.push(0x00);
        l::write_u32(&mut ep, 0);
        l::write_u32(&mut data, ep.len() as u32);
        data.extend_from_slice(&ep);

        // Code: body 0 calls func 2 three times; bodies 1, 2 empty.
        data.push(10);
        let mut cp = Vec::new();
        l::write_u32(&mut cp, 3);
        // body 0: 0 locals; call 2; call 2; call 2; end  (7 bytes)
        let body0 = vec![0, 0x10, 2, 0x10, 2, 0x10, 2, 0x0B];
        l::write_u32(&mut cp, body0.len() as u32);
        cp.extend_from_slice(&body0);
        // body 1: 0 locals, end
        let body1 = vec![0, 0x0B];
        l::write_u32(&mut cp, body1.len() as u32);
        cp.extend_from_slice(&body1);
        // body 2: same
        l::write_u32(&mut cp, body1.len() as u32);
        cp.extend_from_slice(&body1);
        l::write_u32(&mut data, cp.len() as u32);
        data.extend_from_slice(&cp);

        let mut module = WasmModule::parse(&data).unwrap();
        let out = apply(&mut module);
        assert_ne!(out, data);
        // Output should validate structurally.
        WasmModule::parse(&out).unwrap();
    }
}
