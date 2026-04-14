// Dead Code Elimination pass.
//
// Removes defined (non-imported) functions not reachable from exports,
// the start function, ref.func opcodes, or any other defined function.
// Imported functions are never removed — they occupy the low part of
// the function index space and are always "live" from wilt's view.
//
// The pass rewrites function-index references in:
//   * function section
//   * code section bodies (`call` and `ref.func` opcodes)
//   * export section
//
// Element, global, table (other than funcref sizes) sections may also
// carry function references — they're handled by bailing when present.

use crate::leb128;
use crate::module::{self, WasmModule};
use crate::opcode;
use crate::scan;

/// Return true iff every function body in the module can be decoded
/// fully by `opcode::walk`. A pass that plans to remap function indices
/// must call this first — if it's false, emitting bodies would leave
/// stale indices in places `rewrite_body` silently refused to touch.
pub fn all_bodies_walkable(module: &WasmModule<'_>) -> bool {
    let data = module.data();
    for body in module.function_bodies() {
        let bytes = body.body.slice(data);
        let Some(start) = opcode::skip_locals(bytes) else { return false };
        if opcode::walk(bytes, start).is_none() {
            return false;
        }
    }
    true
}

/// Result of DCE analysis.
pub struct DceResult {
    /// Maps each absolute function index (imports + defined) to its new
    /// absolute index, or None if removed. Imports always remap identity.
    pub index_map: Vec<Option<u32>>,
    /// Number of imported functions (the unchanged prefix).
    pub num_imports: u32,
    /// Number of defined functions kept post-DCE.
    pub defined_kept: u32,
}

impl DceResult {
    fn identity(num_imports: u32, num_defined: u32) -> Self {
        let total = num_imports + num_defined;
        Self {
            index_map: (0..total).map(Some).collect(),
            num_imports,
            defined_kept: num_defined,
        }
    }
}

/// Count imported functions in the IMPORT section. Returns 0 if absent.
/// Also returns whether any non-function imports exist (affects export index space).
/// Walk a constant expression (used for global inits and element offsets)
/// and return (end_offset_after_END, ref_func_targets).
/// Returns None if we hit an opcode we don't know how to skip.
pub fn scan_const_expr(bytes: &[u8], start: usize) -> Option<(usize, Vec<u32>)> {
    let mut off = start;
    let mut targets = Vec::new();
    while off < bytes.len() {
        let op = bytes[off];
        if op == 0x0B { return Some((off + 1, targets)); }
        let len = opcode::instr_len(bytes, off)?;
        if op == opcode::OP_REF_FUNC {
            if let Some((t, _)) = leb128::read_u32(&bytes[off + 1..]) {
                targets.push(t);
            }
        }
        off += len;
    }
    None
}

/// Scan the global section payload for all ref.func targets across all
/// global init expressions. Returns None if any expression can't be walked.
fn scan_globals_for_ref_func(payload: &[u8]) -> Option<Vec<u32>> {
    let (count, mut off) = leb128::read_u32(payload)?;
    let mut out = Vec::new();
    for _ in 0..count {
        // valtype (1 byte) + mut (1 byte) + init expr
        if off + 2 > payload.len() { return None; }
        off += 2;
        let (end, targets) = scan_const_expr(payload, off)?;
        out.extend(targets);
        off = end;
    }
    Some(out)
}

/// Walk an element section payload, returning all funcidx references
/// across every segment. Returns None if any segment uses an encoding
/// we can't rewrite on emit (flags 4-7 — expression-list variants).
pub fn scan_elements_funcidx(payload: &[u8]) -> Option<Vec<u32>> {
    let (count, mut off) = leb128::read_u32(payload)?;
    let mut roots = Vec::new();
    for _ in 0..count {
        let (flags, c) = leb128::read_u32(payload.get(off..)?)?;
        off += c;
        match flags {
            0 => {
                let (end, _) = scan_const_expr(payload, off)?;
                off = end;
                off = read_funcidx_vec(payload, off, &mut roots)?;
            }
            1 | 3 => {
                // elemkind byte
                off += 1;
                off = read_funcidx_vec(payload, off, &mut roots)?;
            }
            2 => {
                // tableidx
                let (_, c) = leb128::read_u32(payload.get(off..)?)?;
                off += c;
                let (end, _) = scan_const_expr(payload, off)?;
                off = end;
                off += 1; // elemkind
                off = read_funcidx_vec(payload, off, &mut roots)?;
            }
            _ => return None,
        }
    }
    Some(roots)
}

fn read_funcidx_vec(payload: &[u8], mut off: usize, roots: &mut Vec<u32>) -> Option<usize> {
    let (n, c) = leb128::read_u32(payload.get(off..)?)?;
    off += c;
    for _ in 0..n {
        let (idx, c) = leb128::read_u32(payload.get(off..)?)?;
        off += c;
        roots.push(idx);
    }
    Some(off)
}

/// A single parsed import entry, retaining its byte span for re-emit.
pub struct ImportEntry<'a> {
    pub module_name: &'a str,
    pub field_name: &'a str,
    pub kind: u8,
    /// For function imports: the type index. Otherwise, 0 (not meaningful).
    pub type_idx: u32,
    /// Span (offset, len) within the import-section payload covering this
    /// entire entry.
    pub span: (usize, usize),
}

/// Parse every import, returning (entries, function_import_count). Returns
/// None if the import section can't be fully parsed.
pub fn parse_imports<'a>(module: &'a WasmModule<'_>) -> Option<(Vec<ImportEntry<'a>>, u32)> {
    let sec = module.section(module::SECTION_IMPORT)?;
    let data = module.data();
    let p = sec.payload.slice(data);
    let (count, mut off) = leb128::read_u32(p)?;
    let mut entries = Vec::with_capacity(count as usize);
    let mut func_count = 0u32;
    for _ in 0..count {
        let start = off;
        let (l, c) = leb128::read_u32(p.get(off..)?)?;
        let mn_start = off + c;
        off = mn_start + l as usize;
        let module_name = std::str::from_utf8(p.get(mn_start..off)?).ok()?;
        let (l, c) = leb128::read_u32(p.get(off..)?)?;
        let fn_start = off + c;
        off = fn_start + l as usize;
        let field_name = std::str::from_utf8(p.get(fn_start..off)?).ok()?;
        let kind = *p.get(off)?;
        off += 1;
        let mut type_idx = 0u32;
        match kind {
            0x00 => {
                let (t, c) = leb128::read_u32(p.get(off..)?)?;
                type_idx = t;
                off += c;
                func_count += 1;
            }
            0x01 => {
                off += 1; // reftype
                let flags = *p.get(off)?;
                off += 1;
                let (_, c) = leb128::read_u32(p.get(off..)?)?;
                off += c;
                if flags & 1 != 0 {
                    let (_, c) = leb128::read_u32(p.get(off..)?)?;
                    off += c;
                }
            }
            0x02 => {
                let flags = *p.get(off)?;
                off += 1;
                let (_, c) = leb128::read_u32(p.get(off..)?)?;
                off += c;
                if flags & 1 != 0 {
                    let (_, c) = leb128::read_u32(p.get(off..)?)?;
                    off += c;
                }
            }
            0x03 => { off += 2; }
            0x04 => {
                off += 1;
                let (_, c) = leb128::read_u32(p.get(off..)?)?;
                off += c;
            }
            _ => return None,
        }
        entries.push(ImportEntry {
            module_name, field_name, kind, type_idx,
            span: (start, off - start),
        });
    }
    Some((entries, func_count))
}

pub fn count_func_imports_pub(module: &WasmModule<'_>) -> u32 {
    let Some(sec) = module.section(module::SECTION_IMPORT) else { return 0 };
    let data = module.data();
    let p = sec.payload.slice(data);
    let Some((count, mut off)) = leb128::read_u32(p) else { return 0 };
    let mut n = 0;
    for _ in 0..count {
        // module name
        let Some((l, c)) = leb128::read_u32(&p[off..]) else { return n };
        off += c + l as usize;
        if off > p.len() { return n }
        // field name
        let Some((l, c)) = leb128::read_u32(&p[off..]) else { return n };
        off += c + l as usize;
        if off >= p.len() { return n }
        let kind = p[off];
        off += 1;
        match kind {
            0x00 => {
                if let Some((_, c)) = leb128::read_u32(&p[off..]) { off += c; n += 1; } else { return n }
            }
            0x01 => {
                // table: reftype + limits
                if off >= p.len() { return n }
                off += 1; // reftype
                if off >= p.len() { return n }
                let flags = p[off];
                off += 1;
                if let Some((_, c)) = leb128::read_u32(&p[off..]) { off += c; } else { return n }
                if flags & 1 != 0 {
                    if let Some((_, c)) = leb128::read_u32(&p[off..]) { off += c; } else { return n }
                }
            }
            0x02 => {
                // memory: limits
                if off >= p.len() { return n }
                let flags = p[off];
                off += 1;
                if let Some((_, c)) = leb128::read_u32(&p[off..]) { off += c; } else { return n }
                if flags & 1 != 0 {
                    if let Some((_, c)) = leb128::read_u32(&p[off..]) { off += c; } else { return n }
                }
            }
            0x03 => {
                // global: valtype + mut
                off += 2;
            }
            0x04 => {
                // tag: 1-byte attribute + typeidx LEB
                off += 1;
                if let Some((_, c)) = leb128::read_u32(&p[off..]) { off += c; } else { return n }
            }
            _ => return n,
        }
    }
    n
}

pub fn analyse(module: &mut WasmModule<'_>) -> DceResult {
    module.ensure_function_bodies_parsed();
    let num_defined = module.num_function_bodies() as u32;
    let num_imports = count_func_imports_pub(module);
    let total = num_imports + num_defined;
    let data = module.data();

    // Element segments: scan funcref lists so referenced functions are
    // kept as roots, and ensure every segment uses an encoding we can
    // rewrite on emit. Bail on expression-list variants (flags 4-7) —
    // those need a full const-expr rewriter within vec<expr>.
    let mut element_ref_func_targets: Vec<u32> = Vec::new();
    if let Some(sec) = module.section(module::SECTION_ELEMENT) {
        let p = sec.payload.slice(data);
        match scan_elements_funcidx(p) {
            Some(targets) => element_ref_func_targets = targets,
            None => return DceResult::identity(num_imports, num_defined),
        }
    }

    // Globals: init expressions can contain `ref.func $f`. Collect those
    // as extra roots so we don't remove them; we'll also rewrite the
    // immediate in apply(). If any global init expression is unwalkable,
    // bail to preserve correctness.
    let mut global_ref_func_targets: Vec<u32> = Vec::new();
    if let Some(sec) = module.section(module::SECTION_GLOBAL) {
        let p = sec.payload.slice(data);
        match scan_globals_for_ref_func(p) {
            Some(targets) => global_ref_func_targets = targets,
            None => return DceResult::identity(num_imports, num_defined),
        }
    }

    // Walk defined function bodies with a real instruction decoder. If any
    // body uses opcodes we can't decode (SIMD / atomics / EH), bail rather
    // than risk rewriting calls inside them.
    let mut graph: Vec<Vec<u32>> = vec![Vec::new(); total as usize];
    let mut extra_roots: Vec<u32> = Vec::new();
    for (local_idx, body) in module.function_bodies().iter().enumerate() {
        let abs_idx = num_imports + local_idx as u32;
        let body_bytes = body.body.slice(data);
        let Some(start) = opcode::skip_locals(body_bytes) else {
            return DceResult::identity(num_imports, num_defined);
        };
        let Some(instrs) = opcode::walk(body_bytes, start) else {
            return DceResult::identity(num_imports, num_defined);
        };
        for (p, _) in instrs {
            let op = body_bytes[p];
            if op == opcode::OP_CALL {
                if let Some((target, _)) = leb128::read_u32(&body_bytes[p + 1..]) {
                    if target < total { graph[abs_idx as usize].push(target); }
                }
            } else if op == opcode::OP_REF_FUNC {
                if let Some((target, _)) = leb128::read_u32(&body_bytes[p + 1..]) {
                    if target < total { extra_roots.push(target); }
                }
            }
        }
    }

    let exports = module.exported_function_indices();
    let start = module.start_function();

    // If nothing in the module points at defined functions (only imports
    // exist as "roots"), assume the module is a test fixture or library and
    // keep all defined bodies. Applying DCE with zero real roots would
    // delete every defined function — almost never what's wanted.
    if exports.is_empty() && start.is_none() && extra_roots.is_empty()
        && global_ref_func_targets.is_empty()
        && element_ref_func_targets.is_empty()
    {
        return DceResult::identity(num_imports, num_defined);
    }

    let mut roots: Vec<u32> = exports;
    if let Some(s) = start { roots.push(s); }
    roots.extend(extra_roots);
    roots.extend(global_ref_func_targets.iter().copied());
    roots.extend(element_ref_func_targets.iter().copied());
    // Imports are always "reachable" — declared externally.
    for i in 0..num_imports { roots.push(i); }

    let reachable = scan::reachable_from(&graph, &roots);

    // Build index map. Imports stay identity; defined funcs get renumbered
    // starting at `num_imports`.
    let mut index_map = Vec::with_capacity(total as usize);
    for i in 0..num_imports {
        index_map.push(Some(i));
    }
    let mut new_abs = num_imports;
    let mut defined_kept = 0;
    for i in 0..num_defined {
        let abs = (num_imports + i) as usize;
        if reachable.get(abs).copied().unwrap_or(true) {
            index_map.push(Some(new_abs));
            new_abs += 1;
            defined_kept += 1;
        } else {
            index_map.push(None);
        }
    }

    DceResult { index_map, num_imports, defined_kept }
}

pub fn apply(module: &mut WasmModule<'_>) -> Vec<u8> {
    apply_with_remap(module).0
}

/// Same as `apply` but returns the input→output function-index remap
/// alongside the bytes. Callers that care about keeping debug / name
/// sections consistent with the new index space use this.
pub fn apply_with_remap(module: &mut WasmModule<'_>) -> (Vec<u8>, crate::remap::FuncRemap) {
    let result = analyse(module);
    let data = module.data();
    let num_defined = module.num_function_bodies() as u32;
    let num_total = result.num_imports + num_defined;

    if result.defined_kept == num_defined {
        return (data.to_vec(), crate::remap::FuncRemap::identity(num_total));
    }

    // Safety: removing defined funcs means surviving funcs get renumbered.
    // We must be able to rewrite every body's call / ref.func immediates;
    // if any body has an opcode we can't decode (e.g. SIMD), bail.
    if !all_bodies_walkable(module) {
        return (data.to_vec(), crate::remap::FuncRemap::identity(num_total));
    }

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..8]);

    for section in module.sections() {
        match section.id {
            module::SECTION_FUNCTION => emit_function_section(&mut out, section, data, &result),
            module::SECTION_CODE => emit_code_section(&mut out, module, data, &result),
            module::SECTION_EXPORT => emit_export_section(&mut out, section, data, &result),
            module::SECTION_GLOBAL => emit_global_section(&mut out, section, data, &result),
            module::SECTION_ELEMENT => emit_element_section(&mut out, section, data, &result),
            module::SECTION_START => emit_start_section(&mut out, section, data, &result),
            _ => out.extend_from_slice(section.full.slice(data)),
        }
    }
    let remap = crate::remap::FuncRemap::from_entries(result.index_map);
    (out, remap)
}

fn emit_function_section(out: &mut Vec<u8>, section: &module::Section, data: &[u8], r: &DceResult) {
    let payload = section.payload.slice(data);
    let Some((count, mut off)) = leb128::read_u32(payload) else {
        out.extend_from_slice(section.full.slice(data));
        return;
    };

    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, r.defined_kept);
    for i in 0..count {
        let Some((type_idx, c)) = leb128::read_u32(&payload[off..]) else { break };
        off += c;
        let abs = r.num_imports + i;
        if r.index_map.get(abs as usize).copied().flatten().is_some() {
            leb128::write_u32(&mut new_payload, type_idx);
        }
    }

    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn emit_code_section(out: &mut Vec<u8>, module: &WasmModule<'_>, data: &[u8], r: &DceResult) {
    let bodies = module.function_bodies();
    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, r.defined_kept);

    for (i, body) in bodies.iter().enumerate() {
        let abs = r.num_imports + i as u32;
        if r.index_map.get(abs as usize).copied().flatten().is_none() {
            continue;
        }
        let body_bytes = body.body.slice(data);
        // Safe to unwrap: apply() prechecks all_bodies_walkable before
        // reaching this emit path.
        let rewritten = rewrite_body(body_bytes, &r.index_map)
            .expect("body walkability guaranteed by precheck");
        leb128::write_u32(&mut new_payload, rewritten.len() as u32);
        new_payload.extend_from_slice(&rewritten);
    }

    out.push(module::SECTION_CODE);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

/// Rewrite `call` and `ref.func` immediates in a function body using the
/// index map. Returns `None` if the body contains an opcode we can't
/// decode — callers must then bail their whole pass, because silently
/// emitting the body verbatim would leave stale function indices when
/// `index_map` is non-identity.
pub fn rewrite_body(body: &[u8], index_map: &[Option<u32>]) -> Option<Vec<u8>> {
    let start = opcode::skip_locals(body)?;
    let instrs = opcode::walk(body, start)?;

    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[..start]);
    let mut cursor = start;

    for (p, _len) in &instrs {
        let op = body[*p];
        if op == opcode::OP_CALL || op == opcode::OP_REF_FUNC {
            if let Some((target, c)) = leb128::read_u32(&body[p + 1..]) {
                let new_target = index_map
                    .get(target as usize)
                    .copied()
                    .flatten()
                    .unwrap_or(target);
                if new_target != target {
                    out.extend_from_slice(&body[cursor..*p]);
                    out.push(op);
                    leb128::write_u32(&mut out, new_target);
                    cursor = p + 1 + c;
                }
            }
        }
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

fn emit_start_section(out: &mut Vec<u8>, section: &module::Section, data: &[u8], r: &DceResult) {
    emit_remapped_start_section(out, section, data, &r.index_map);
}

pub fn emit_remapped_start_section(
    out: &mut Vec<u8>,
    section: &module::Section,
    data: &[u8],
    index_map: &[Option<u32>],
) {
    let payload = section.payload.slice(data);
    let Some((idx, _)) = leb128::read_u32(payload) else {
        out.extend_from_slice(section.full.slice(data));
        return;
    };
    let new_idx = index_map.get(idx as usize).copied().flatten().unwrap_or(idx);
    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, new_idx);
    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn emit_global_section(out: &mut Vec<u8>, section: &module::Section, data: &[u8], r: &DceResult) {
    emit_remapped_global_section(out, section, data, &r.index_map);
}

pub fn emit_remapped_global_section(
    out: &mut Vec<u8>,
    section: &module::Section,
    data: &[u8],
    index_map: &[Option<u32>],
) {
    let payload = section.payload.slice(data);
    let Some((count, mut off)) = leb128::read_u32(payload) else {
        out.extend_from_slice(section.full.slice(data));
        return;
    };

    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, count);
    for _ in 0..count {
        if off + 2 > payload.len() { break; }
        new_payload.extend_from_slice(&payload[off..off + 2]);
        off += 2;
        let Some((end, _)) = scan_const_expr(payload, off) else {
            new_payload.extend_from_slice(&payload[off..]);
            break;
        };
        let rewritten = rewrite_const_expr(&payload[off..end], index_map);
        new_payload.extend_from_slice(&rewritten);
        off = end;
    }

    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn emit_element_section(out: &mut Vec<u8>, section: &module::Section, data: &[u8], r: &DceResult) {
    emit_remapped_element_section(out, section, data, &r.index_map);
}

/// Emit an element section with all function-index references rewritten
/// via `index_map`. If the section contains any segment with an encoding
/// variant we can't walk (flags 4-7, the expression-list forms), falls
/// back to verbatim copy of the entire section.
pub fn emit_remapped_element_section(
    out: &mut Vec<u8>,
    section: &module::Section,
    data: &[u8],
    index_map: &[Option<u32>],
) {
    let payload = section.payload.slice(data);
    let Some((count, start_off)) = leb128::read_u32(payload) else {
        out.extend_from_slice(section.full.slice(data));
        return;
    };
    // Prepass: bail to verbatim copy if any segment isn't a flag 0-3 variant.
    if !all_segments_funcidx_form(payload, count, start_off) {
        out.extend_from_slice(section.full.slice(data));
        return;
    }

    let mut off = start_off;
    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, count);

    for _ in 0..count {
        let (flags, c) = leb128::read_u32(&payload[off..]).expect("pre-checked");
        off += c;
        match flags {
            0 => {
                leb128::write_u32(&mut new_payload, flags);
                let (end, _) = scan_const_expr(payload, off).expect("pre-checked");
                new_payload.extend_from_slice(&rewrite_const_expr(&payload[off..end], index_map));
                off = end;
                off = write_remapped_funcidx_vec(&mut new_payload, payload, off, index_map);
            }
            1 | 3 => {
                leb128::write_u32(&mut new_payload, flags);
                new_payload.push(payload[off]);
                off += 1;
                off = write_remapped_funcidx_vec(&mut new_payload, payload, off, index_map);
            }
            2 => {
                leb128::write_u32(&mut new_payload, flags);
                let (tableidx, c) = leb128::read_u32(&payload[off..]).expect("pre-checked");
                leb128::write_u32(&mut new_payload, tableidx);
                off += c;
                let (end, _) = scan_const_expr(payload, off).expect("pre-checked");
                new_payload.extend_from_slice(&rewrite_const_expr(&payload[off..end], index_map));
                off = end;
                new_payload.push(payload[off]);
                off += 1;
                off = write_remapped_funcidx_vec(&mut new_payload, payload, off, index_map);
            }
            _ => unreachable!("pre-checked"),
        }
    }

    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn all_segments_funcidx_form(payload: &[u8], count: u32, mut off: usize) -> bool {
    for _ in 0..count {
        let Some((flags, c)) = leb128::read_u32(&payload[off..]) else { return false };
        off += c;
        match flags {
            0 => {
                let Some((end, _)) = scan_const_expr(payload, off) else { return false };
                off = end;
                let Some(no) = skip_funcidx_vec(payload, off) else { return false };
                off = no;
            }
            1 | 3 => {
                if off >= payload.len() { return false; }
                off += 1; // elemkind
                let Some(no) = skip_funcidx_vec(payload, off) else { return false };
                off = no;
            }
            2 => {
                let Some((_, c)) = leb128::read_u32(&payload[off..]) else { return false };
                off += c;
                let Some((end, _)) = scan_const_expr(payload, off) else { return false };
                off = end;
                if off >= payload.len() { return false; }
                off += 1;
                let Some(no) = skip_funcidx_vec(payload, off) else { return false };
                off = no;
            }
            _ => return false,
        }
    }
    true
}

fn skip_funcidx_vec(payload: &[u8], mut off: usize) -> Option<usize> {
    let (n, c) = leb128::read_u32(payload.get(off..)?)?;
    off += c;
    for _ in 0..n {
        let (_, c) = leb128::read_u32(payload.get(off..)?)?;
        off += c;
    }
    Some(off)
}

pub fn write_remapped_funcidx_vec(
    out: &mut Vec<u8>,
    payload: &[u8],
    mut off: usize,
    index_map: &[Option<u32>],
) -> usize {
    let Some((n, c)) = leb128::read_u32(&payload[off..]) else { return off };
    off += c;
    leb128::write_u32(out, n);
    for _ in 0..n {
        let Some((idx, c)) = leb128::read_u32(&payload[off..]) else { return off };
        off += c;
        let new_idx = index_map.get(idx as usize).copied().flatten().unwrap_or(idx);
        leb128::write_u32(out, new_idx);
    }
    off
}

pub fn rewrite_const_expr(bytes: &[u8], index_map: &[Option<u32>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut off = 0;
    while off < bytes.len() {
        let op = bytes[off];
        if op == 0x0B {
            out.push(op);
            off += 1;
            break;
        }
        let Some(len) = opcode::instr_len(bytes, off) else {
            // Defensive: copy remainder verbatim.
            out.extend_from_slice(&bytes[off..]);
            return out;
        };
        if op == opcode::OP_REF_FUNC {
            if let Some((t, c)) = leb128::read_u32(&bytes[off + 1..]) {
                let new_t = index_map.get(t as usize).copied().flatten().unwrap_or(t);
                out.push(op);
                leb128::write_u32(&mut out, new_t);
                off += 1 + c;
                continue;
            }
        }
        out.extend_from_slice(&bytes[off..off + len]);
        off += len;
    }
    out.extend_from_slice(&bytes[off..]);
    out
}

fn emit_export_section(out: &mut Vec<u8>, section: &module::Section, data: &[u8], r: &DceResult) {
    emit_remapped_export_section(out, section, data, &r.index_map);
}

pub fn emit_remapped_export_section(
    out: &mut Vec<u8>,
    section: &module::Section,
    data: &[u8],
    index_map: &[Option<u32>],
) {
    let payload = section.payload.slice(data);
    let Some((count, mut off)) = leb128::read_u32(payload) else {
        out.extend_from_slice(section.full.slice(data));
        return;
    };

    let mut entries = Vec::new();
    for _ in 0..count {
        let Some((name_len, c)) = leb128::read_u32(&payload[off..]) else { break };
        let name_start = off + c;
        off = name_start + name_len as usize;
        let kind = payload[off];
        off += 1;
        let Some((index, c)) = leb128::read_u32(&payload[off..]) else { break };
        off += c;

        let new_index = if kind == 0x00 {
            match index_map.get(index as usize).copied().flatten() {
                Some(n) => n,
                None => continue,
            }
        } else {
            index
        };

        entries.push((&payload[name_start..name_start + name_len as usize], kind, new_index));
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
        data.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);

        let mut func_payload = Vec::new();
        leb128::write_u32(&mut func_payload, num_funcs as u32);
        for _ in 0..num_funcs { leb128::write_u32(&mut func_payload, 0); }
        data.push(3);
        leb128::write_u32(&mut data, func_payload.len() as u32);
        data.extend_from_slice(&func_payload);

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

        let mut code_payload = Vec::new();
        leb128::write_u32(&mut code_payload, num_funcs as u32);
        for _ in 0..num_funcs {
            code_payload.push(2);
            code_payload.push(0);
            code_payload.push(0x0B);
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
        assert_eq!(result.defined_kept, 1);
        assert_eq!(result.num_imports, 0);
        assert_eq!(result.index_map, vec![Some(0), None, None]);
    }

    #[test]
    fn dce_keeps_all_exported() {
        let data = build_module_with_functions(2, &[(0, "a"), (1, "b")]);
        let mut module = WasmModule::parse(&data).unwrap();
        let result = analyse(&mut module);
        assert_eq!(result.defined_kept, 2);
    }

    #[test]
    fn dce_apply_shrinks_output() {
        let data = build_module_with_functions(3, &[(0, "_start")]);
        let mut module = WasmModule::parse(&data).unwrap();
        let output = apply(&mut module);
        assert!(output.len() < data.len());
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
