//! Duplicate-function elimination.
//!
//! Finds functions whose type-index + body-bytes are byte-identical and
//! collapses them: all callers (code, exports, globals, elements) are
//! remapped to a single canonical copy, and the duplicates become
//! unreachable — the next `dce` run sweeps them up.
//!
//! This is the simplest, safest form: no canonicalisation of local indices
//! or call targets, just exact byte match. It still catches lots of
//! templated C++ / monomorphised generics / thunk patterns.

use crate::leb128;
use crate::module::WasmModule;
use crate::module::{self};
use crate::opcode;
use std::collections::HashMap;
use std::collections::HashSet;

/// Produce an index map: for each absolute function index, the canonical
/// absolute index it should be remapped to (identity for functions that
/// aren't duplicates).
fn build_remap(module: &mut WasmModule<'_>) -> Option<Vec<Option<u32>>> {
    module.ensure_function_bodies_parsed();
    let num_defined = module.num_function_bodies() as u32;
    if num_defined < 2 {
        return None;
    }

    let data = module.data();
    let num_imports = super::dce::count_func_imports_pub(module);

    // Read function section type indices (aligned with function_bodies()).
    let func_sec = module.section(module::SECTION_FUNCTION)?;
    let payload = func_sec.payload.slice(data);
    let (count, mut off) = leb128::read_u32(payload)?;
    if count != num_defined {
        return None;
    }
    let mut type_idx = Vec::with_capacity(num_defined as usize);
    for _ in 0..count {
        let (t, c) = leb128::read_u32(&payload[off..])?;
        off += c;
        type_idx.push(t);
    }

    // Collect every function that's used as a `ref.func` target anywhere
    // in the module (code bodies + global/element init expressions).
    // Those functions are "declared" only by that specific ref.func, and
    // merging them might leave the canonical undeclared at validation.
    // Safest: exclude the whole ref-target set from dedup groups.
    let reffed = collect_ref_func_targets(module);

    // Group by (type_idx, body_bytes). Keep the first occurrence as the
    // canonical; later duplicates map to it.
    let mut groups: HashMap<(u32, &[u8]), u32> = HashMap::new();
    let total = num_imports + num_defined;
    let mut remap: Vec<Option<u32>> = (0..total).map(Some).collect();
    let mut found_dup = false;

    for (i, body) in module.function_bodies().iter().enumerate() {
        let abs = num_imports + i as u32;
        if reffed.contains(&abs) {
            continue;
        }
        let bytes = body.full.slice(data);
        let key = (type_idx[i], bytes);
        match groups.get(&key) {
            Some(&canonical) if canonical != abs => {
                remap[abs as usize] = Some(canonical);
                found_dup = true;
            }
            _ => {
                groups.insert(key, abs);
            }
        }
    }

    found_dup.then_some(remap)
}

fn collect_ref_func_targets(module: &WasmModule<'_>) -> HashSet<u32> {
    let data = module.data();
    let mut set: HashSet<u32> = HashSet::new();

    // Code bodies.
    for body in module.function_bodies() {
        let b = body.body.slice(data);
        let Some(start) = opcode::skip_locals(b) else {
            continue;
        };
        let Some(instrs) = opcode::walk(b, start) else {
            continue;
        };
        for (p, _) in instrs {
            if b[p] == opcode::OP_REF_FUNC {
                if let Some((t, _)) = leb128::read_u32(&b[p + 1..]) {
                    set.insert(t);
                }
            }
        }
    }

    // Globals (const exprs).
    if let Some(sec) = module.section(module::SECTION_GLOBAL) {
        let p = sec.payload.slice(data);
        if let Some((count, mut off)) = leb128::read_u32(p) {
            for _ in 0..count {
                if off + 2 > p.len() {
                    break;
                }
                off += 2;
                let Some((end, targets)) = super::dce::scan_const_expr(p, off) else {
                    break;
                };
                for t in targets {
                    set.insert(t);
                }
                off = end;
            }
        }
    }

    // Element section (funcref lists ⇒ declared targets; expr-form variants:
    // we bail and verbatim-copy elsewhere, so any ref.func inside an expr
    // stays referring to its original index — still need to treat as reffed).
    if let Some(sec) = module.section(module::SECTION_ELEMENT) {
        let p = sec.payload.slice(data);
        if let Some(targets) = super::dce::scan_elements_funcidx(p) {
            for t in targets {
                set.insert(t);
            }
        }
    }

    set
}

pub fn apply(module: &mut WasmModule<'_>) -> Vec<u8> {
    let data = module.data();
    let Some(remap) = build_remap(module) else {
        return data.to_vec();
    };

    if !super::dce::all_bodies_walkable(module) {
        return data.to_vec();
    }

    // Emit: walk sections, applying the remap to function-index references.
    // Unlike DCE we're NOT removing functions here — same function count,
    // just redirecting callers. DCE on the next run will notice the
    // duplicates are unreachable and remove them.
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..8]);

    for section in module.sections() {
        match section.id {
            module::SECTION_CODE => emit_code(&mut out, module, data, &remap),
            module::SECTION_EXPORT => emit_export(&mut out, section, data, &remap),
            module::SECTION_GLOBAL => emit_global(&mut out, section, data, &remap),
            module::SECTION_ELEMENT => emit_element(&mut out, section, data, &remap),
            _ => out.extend_from_slice(section.full.slice(data)),
        }
    }
    out
}

fn emit_code(out: &mut Vec<u8>, module: &WasmModule<'_>, data: &[u8], remap: &[Option<u32>]) {
    let bodies = module.function_bodies();
    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, bodies.len() as u32);
    for body in bodies {
        let body_bytes = body.body.slice(data);
        let rewritten = super::dce::rewrite_body(body_bytes, remap)
            .expect("body walkability guaranteed by precheck");
        leb128::write_u32(&mut new_payload, rewritten.len() as u32);
        new_payload.extend_from_slice(&rewritten);
    }
    out.push(module::SECTION_CODE);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn emit_export(out: &mut Vec<u8>, section: &module::Section, data: &[u8], remap: &[Option<u32>]) {
    let payload = section.payload.slice(data);
    let Some((count, mut off)) = leb128::read_u32(payload) else {
        out.extend_from_slice(section.full.slice(data));
        return;
    };
    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, count);
    for _ in 0..count {
        let Some((name_len, c)) = leb128::read_u32(&payload[off..]) else {
            break;
        };
        let name_start = off + c;
        off = name_start + name_len as usize;
        let kind = payload[off];
        off += 1;
        let Some((idx, c)) = leb128::read_u32(&payload[off..]) else {
            break;
        };
        off += c;
        let new_idx = if kind == 0x00 {
            remap.get(idx as usize).copied().flatten().unwrap_or(idx)
        } else {
            idx
        };
        leb128::write_u32(&mut new_payload, name_len);
        new_payload.extend_from_slice(&payload[name_start..name_start + name_len as usize]);
        new_payload.push(kind);
        leb128::write_u32(&mut new_payload, new_idx);
    }
    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn emit_global(out: &mut Vec<u8>, section: &module::Section, data: &[u8], remap: &[Option<u32>]) {
    let payload = section.payload.slice(data);
    let Some((count, mut off)) = leb128::read_u32(payload) else {
        out.extend_from_slice(section.full.slice(data));
        return;
    };
    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, count);
    for _ in 0..count {
        if off + 2 > payload.len() {
            break;
        }
        new_payload.extend_from_slice(&payload[off..off + 2]);
        off += 2;
        let Some((end, _)) = super::dce::scan_const_expr(payload, off) else {
            new_payload.extend_from_slice(&payload[off..]);
            break;
        };
        new_payload.extend_from_slice(&super::dce::rewrite_const_expr(&payload[off..end], remap));
        off = end;
    }
    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn emit_element(out: &mut Vec<u8>, section: &module::Section, data: &[u8], remap: &[Option<u32>]) {
    super::dce::emit_remapped_element_section(out, section, data, remap);
}
