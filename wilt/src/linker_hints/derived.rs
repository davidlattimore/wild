//! `DerivedHints` — synthesize closed-world hints by scanning a
//! finalised `.wasm` module.
//!
//! Approximates what a wasm linker (wild) would provide if invoking
//! wilt as a library. For benchmark / contract-test purposes: lets us
//! exercise wilt's hint-aware passes against a real corpus that
//! doesn't otherwise have a linker driving it.
//!
//! Computed:
//! - `internal`: defined funcs not exported, not in element segments,
//!   not appearing as a `ref.func` target anywhere, not the start
//!   function. Anything in those sets is potentially reachable from
//!   outside the module's call graph.
//! - `call_count`: per-defined-func count of `call N` references
//!   across every body.
//! - `tables`: function indices stored in each (active) element segment.
//!   Indexed by the segment's table index.
//! - `ref_func_targets`: union of every `ref.func N` target across
//!   bodies, element segments, and global init exprs.
//! - `global_is_read`: false iff `global.get g` never appears in any
//!   body or any init expression.
//!
//! What we DON'T compute (would be linker-side only):
//! - `origin_unit`: the input-object identity is gone after linking.

use std::collections::{HashMap, HashSet};

use super::{ConstVal, LinkerHints};
use crate::leb128;
use crate::module::{self as wmod, WasmModule};
use crate::opcode::{self, InstrIter};

pub struct DerivedHints {
    internal: HashSet<u32>,
    call_counts: HashMap<u32, u32>,
    tables: HashMap<u32, Vec<u32>>,
    ref_funcs: Vec<u32>,
    unread_globals: HashSet<u32>,
    global_consts: HashMap<u32, ConstVal>,
    pure_funcs: HashSet<u32>,
}

impl DerivedHints {
    /// Best-effort: returns `None` if the module can't be parsed, or if
    /// any analysis bails (e.g., unknown opcode in a body).
    pub fn from_bytes(input: &[u8]) -> Option<Self> {
        let mut wm = WasmModule::parse(input).ok()?;
        wm.ensure_function_bodies_parsed();
        let data = wm.data();

        let num_imports = count_func_imports(&wm).unwrap_or(0);
        let num_defined = wm.function_bodies().len() as u32;
        let total_funcs = num_imports + num_defined;

        // External function set: starts as exported func indices,
        // grows with element / ref.func / start.
        let mut external: HashSet<u32> = HashSet::new();
        for idx in collect_exported_func_indices(&wm) {
            external.insert(idx);
        }
        if let Some(idx) = collect_start_func(&wm) {
            external.insert(idx);
        }

        // ref.func targets — body bytecode + element segs + global init.
        let mut ref_funcs: HashSet<u32> = HashSet::new();
        for body in wm.function_bodies() {
            let b = body.body.slice(data);
            scan_body_ref_funcs(b, &mut ref_funcs);
        }
        let mut tables: HashMap<u32, Vec<u32>> = HashMap::new();
        if let Some(sec) = wm.section(wmod::SECTION_ELEMENT) {
            collect_element_func_refs(sec.payload.slice(data), &mut tables, &mut ref_funcs);
        }
        if let Some(sec) = wm.section(wmod::SECTION_GLOBAL) {
            collect_global_init_ref_funcs(sec.payload.slice(data), &mut ref_funcs);
        }
        for &f in &ref_funcs {
            external.insert(f);
        }

        // Internal = defined funcs not in external.
        let mut internal: HashSet<u32> = HashSet::new();
        for i in num_imports..total_funcs {
            if !external.contains(&i) {
                internal.insert(i);
            }
        }

        // Call counts (defined funcs only).
        let mut call_counts: HashMap<u32, u32> = HashMap::new();
        for body in wm.function_bodies() {
            let b = body.body.slice(data);
            scan_body_calls(b, num_imports, &mut call_counts);
        }

        // Globals: read set across bodies + init exprs.
        let num_globals = count_globals(&wm).unwrap_or(0);
        let mut read_globals: HashSet<u32> = HashSet::new();
        for body in wm.function_bodies() {
            let b = body.body.slice(data);
            scan_body_global_reads(b, &mut read_globals);
        }
        // Init exprs can also `global.get` an imported global. Conservatively
        // mark any imported global as read.
        let num_imported_globals = count_imported_globals(&wm).unwrap_or(0);
        for g in 0..num_imported_globals {
            read_globals.insert(g);
        }

        let mut unread_globals: HashSet<u32> = HashSet::new();
        for g in 0..num_globals {
            if !read_globals.contains(&g) {
                unread_globals.insert(g);
            }
        }

        let global_consts = collect_global_consts(&wm, num_imported_globals);

        let pure_funcs = derive_pure_funcs(&wm, num_imports);

        Some(DerivedHints {
            internal,
            call_counts,
            tables,
            ref_funcs: ref_funcs.into_iter().collect(),
            unread_globals,
            global_consts,
            pure_funcs,
        })
    }
}

impl LinkerHints for DerivedHints {
    fn is_internal(&self, f: u32) -> bool { self.internal.contains(&f) }
    fn call_count(&self, f: u32) -> Option<u32> { self.call_counts.get(&f).copied() }
    fn table_targets(&self, t: u32) -> Option<&[u32]> {
        self.tables.get(&t).map(|v| v.as_slice())
    }
    fn ref_func_targets(&self) -> &[u32] { &self.ref_funcs }
    fn global_is_read(&self, g: u32) -> bool { !self.unread_globals.contains(&g) }
    fn global_const(&self, g: u32) -> Option<ConstVal> { self.global_consts.get(&g).copied() }
    fn func_is_pure(&self, f: u32) -> bool { self.pure_funcs.contains(&f) }
}

/// Per-defined-function facts used in the purity fixpoint.
struct PurityFacts {
    walkable: bool,
    intrinsic_impure: bool,   // any single-opcode side effect
    calls_import: bool,
    callees_defined: Vec<u32>, // absolute func indices of defined callees
}

fn derive_pure_funcs(module: &WasmModule<'_>, num_imports: u32) -> HashSet<u32> {
    let data = module.data();
    let num_defined = module.function_bodies().len() as u32;
    let mut facts: Vec<PurityFacts> = Vec::with_capacity(num_defined as usize);
    for body in module.function_bodies() {
        facts.push(scan_purity(body.body.slice(data), num_imports));
    }

    // Fixpoint: start optimistic for each walkable+intrinsic-pure func.
    let mut pure: HashSet<u32> = HashSet::new();
    for (i, f) in facts.iter().enumerate() {
        if f.walkable && !f.intrinsic_impure && !f.calls_import {
            pure.insert(num_imports + i as u32);
        }
    }
    loop {
        let mut to_demote: Vec<u32> = Vec::new();
        for &idx in pure.iter() {
            let i = (idx - num_imports) as usize;
            let f = &facts[i];
            if !f.callees_defined.iter().all(|c| pure.contains(c)) {
                to_demote.push(idx);
            }
        }
        if to_demote.is_empty() { break; }
        for idx in to_demote { pure.remove(&idx); }
    }
    pure
}

/// Scan a body for side effects and direct callees. Conservative:
/// any opcode we don't know → intrinsic_impure = true.
fn scan_purity(body: &[u8], num_imports: u32) -> PurityFacts {
    let Some(start) = opcode::skip_locals(body) else {
        return PurityFacts { walkable: false, intrinsic_impure: true,
                             calls_import: false, callees_defined: Vec::new() };
    };
    let mut f = PurityFacts {
        walkable: true, intrinsic_impure: false,
        calls_import: false, callees_defined: Vec::new(),
    };
    let mut iter = InstrIter::new(body, start);
    while let Some((p, _)) = iter.next() {
        let op = body[p];
        if op == 0xFC {
            // Decode the sub-opcode: the trunc_sat family (0..=7) and
            // table.size (0x10) are pure. Everything else in this prefix
            // mutates memory, tables, or data segments.
            if let Some((sub, _)) = leb128::read_u32(&body[p + 1..]) {
                if !matches!(sub, 0x00..=0x07 | 0x10) {
                    f.intrinsic_impure = true;
                }
            } else {
                f.intrinsic_impure = true;
            }
        } else if is_side_effect_opcode(op) {
            f.intrinsic_impure = true;
        }
        if op == 0x10 {
            if let Some((callee, _)) = leb128::read_u32(&body[p + 1..]) {
                if callee < num_imports {
                    f.calls_import = true;
                } else {
                    f.callees_defined.push(callee);
                }
            } else {
                f.intrinsic_impure = true;
            }
        }
    }
    if iter.failed() { f.walkable = false; f.intrinsic_impure = true; }
    f
}

/// Opcodes that on their own imply an observable side effect. 0xFC is
/// decoded separately above (most sub-ops are mutations, a couple are
/// pure). 0xFD (SIMD) stays pessimistically impure because some sub-ops
/// are stores and precise classification isn't wired; 0xFE (atomics)
/// always implies shared-memory semantics.
fn is_side_effect_opcode(op: u8) -> bool {
    matches!(op,
        0x11        // call_indirect
        | 0x24        // global.set
        | 0x26        // table.set
        | 0x36..=0x3E // i32/i64/f32/f64 stores
        | 0x40        // memory.grow
        | 0xFD | 0xFE
    )
}

/// Walk the globals section. Imported globals are not in this section
/// (they live in SECTION_IMPORT) — indices start at `first_defined_idx`.
/// For each defined global, if mutability is 0 and the init expr is
/// exactly one `*.const N` followed by `end`, record the literal.
fn collect_global_consts(
    module: &WasmModule<'_>, first_defined_idx: u32,
) -> HashMap<u32, ConstVal> {
    let mut out = HashMap::new();
    let Some(sec) = module.section(wmod::SECTION_GLOBAL) else { return out };
    let p = sec.payload.slice(module.data());
    let Some((count, mut off)) = leb128::read_u32(p) else { return out };
    for i in 0..count {
        // globaltype = valtype(1 byte) + mut(1 byte)
        if off + 2 > p.len() { return out; }
        let _valtype = p[off];
        let mutability = p[off + 1];
        off += 2;
        // init expr: single const + end — or anything else (we skip).
        if mutability == 0 {
            if let Some((val, next)) = read_single_const(p, off) {
                out.insert(first_defined_idx + i, val);
                off = next;
                continue;
            }
        }
        // Skip init expr up to terminating `end`.
        let Some(end_off) = skip_const_expr(p, off) else { return out };
        off = end_off;
    }
    out
}

/// Decode `(*.const N)(end)` starting at `off`. Returns (value, new_off)
/// on match, `None` if the init expr is anything else.
fn read_single_const(p: &[u8], off: usize) -> Option<(ConstVal, usize)> {
    let op = *p.get(off)?;
    match op {
        0x41 => {  // i32.const
            let (v, c) = leb128::read_i32(p.get(off + 1..)?)?;
            if *p.get(off + 1 + c)? != 0x0B { return None; }
            Some((ConstVal::I32(v), off + 1 + c + 1))
        }
        0x42 => {  // i64.const
            let (v, c) = leb128::read_i64(p.get(off + 1..)?)?;
            if *p.get(off + 1 + c)? != 0x0B { return None; }
            Some((ConstVal::I64(v), off + 1 + c + 1))
        }
        0x43 => {  // f32.const (4 raw bytes LE)
            let bytes: [u8; 4] = p.get(off + 1..off + 5)?.try_into().ok()?;
            if *p.get(off + 5)? != 0x0B { return None; }
            Some((ConstVal::F32(u32::from_le_bytes(bytes)), off + 6))
        }
        0x44 => {  // f64.const (8 raw bytes LE)
            let bytes: [u8; 8] = p.get(off + 1..off + 9)?.try_into().ok()?;
            if *p.get(off + 9)? != 0x0B { return None; }
            Some((ConstVal::F64(u64::from_le_bytes(bytes)), off + 10))
        }
        _ => None,
    }
}

// ───── helpers ─────

fn count_func_imports(module: &WasmModule<'_>) -> Option<u32> {
    let sec = module.section(wmod::SECTION_IMPORT)?;
    let p = sec.payload.slice(module.data());
    let (count, mut off) = leb128::read_u32(p)?;
    let mut n = 0;
    for _ in 0..count {
        let (ml, c) = leb128::read_u32(p.get(off..)?)?;
        off = off.checked_add(c)?.checked_add(ml as usize)?;
        let (fl, c) = leb128::read_u32(p.get(off..)?)?;
        off = off.checked_add(c)?.checked_add(fl as usize)?;
        let kind = *p.get(off)?;
        off += 1;
        match kind {
            0x00 => {
                let (_, c) = leb128::read_u32(p.get(off..)?)?;
                off += c;
                n += 1;
            }
            0x01 => { off += 1; let flags = *p.get(off)?; off += 1;
                let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c;
                if flags & 1 != 0 { let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c; } }
            0x02 => { let flags = *p.get(off)?; off += 1;
                let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c;
                if flags & 1 != 0 { let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c; } }
            0x03 => off += 2,
            _ => return None,
        }
    }
    Some(n)
}

fn count_imported_globals(module: &WasmModule<'_>) -> Option<u32> {
    let sec = module.section(wmod::SECTION_IMPORT)?;
    let p = sec.payload.slice(module.data());
    let (count, mut off) = leb128::read_u32(p)?;
    let mut n = 0;
    for _ in 0..count {
        let (ml, c) = leb128::read_u32(p.get(off..)?)?;
        off += c + ml as usize;
        let (fl, c) = leb128::read_u32(p.get(off..)?)?;
        off += c + fl as usize;
        let kind = *p.get(off)?;
        off += 1;
        match kind {
            0x00 => { let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c; }
            0x01 => { off += 1; let flags = *p.get(off)?; off += 1;
                let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c;
                if flags & 1 != 0 { let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c; } }
            0x02 => { let flags = *p.get(off)?; off += 1;
                let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c;
                if flags & 1 != 0 { let (_, c) = leb128::read_u32(p.get(off..)?)?; off += c; } }
            0x03 => { off += 2; n += 1; }
            _ => return None,
        }
    }
    Some(n)
}

fn count_globals(module: &WasmModule<'_>) -> Option<u32> {
    let imported = count_imported_globals(module).unwrap_or(0);
    let defined = module.section(wmod::SECTION_GLOBAL)
        .and_then(|sec| {
            let (count, _) = leb128::read_u32(sec.payload.slice(module.data()))?;
            Some(count)
        })
        .unwrap_or(0);
    Some(imported + defined)
}

fn collect_exported_func_indices(module: &WasmModule<'_>) -> Vec<u32> {
    let mut out = Vec::new();
    let Some(sec) = module.section(wmod::SECTION_EXPORT) else { return out };
    let p = sec.payload.slice(module.data());
    let (count, mut off) = match leb128::read_u32(p) { Some(x) => x, None => return out };
    for _ in 0..count {
        let Some((nl, c)) = leb128::read_u32(p.get(off..).unwrap_or(&[])) else { break };
        off += c + nl as usize;
        if off >= p.len() { break; }
        let kind = p[off];
        off += 1;
        let Some((idx, c)) = leb128::read_u32(p.get(off..).unwrap_or(&[])) else { break };
        off += c;
        if kind == 0x00 { out.push(idx); }
    }
    out
}

fn collect_start_func(module: &WasmModule<'_>) -> Option<u32> {
    let sec = module.section(wmod::SECTION_START)?;
    let (idx, _) = leb128::read_u32(sec.payload.slice(module.data()))?;
    Some(idx)
}

fn scan_body_ref_funcs(body: &[u8], out: &mut HashSet<u32>) {
    let Some(start) = opcode::skip_locals(body) else { return };
    let mut iter = InstrIter::new(body, start);
    while let Some((p, _)) = iter.next() {
        if body[p] == 0xD2 {
            if let Some((f, _)) = leb128::read_u32(&body[p + 1..]) { out.insert(f); }
        }
    }
}

fn scan_body_calls(body: &[u8], num_imports: u32, counts: &mut HashMap<u32, u32>) {
    let Some(start) = opcode::skip_locals(body) else { return };
    let mut iter = InstrIter::new(body, start);
    while let Some((p, _)) = iter.next() {
        if body[p] != 0x10 { continue; }
        if let Some((f, _)) = leb128::read_u32(&body[p + 1..]) {
            if f >= num_imports {
                *counts.entry(f).or_insert(0) += 1;
            }
        }
    }
}

fn scan_body_global_reads(body: &[u8], out: &mut HashSet<u32>) {
    let Some(start) = opcode::skip_locals(body) else { return };
    let mut iter = InstrIter::new(body, start);
    while let Some((p, _)) = iter.next() {
        if body[p] == 0x23 {     // global.get
            if let Some((g, _)) = leb128::read_u32(&body[p + 1..]) { out.insert(g); }
        }
    }
}

/// Walk an element section and harvest function indices into per-table
/// vectors plus the union ref_funcs set. Best-effort; bails silently
/// on segment encodings we don't fully decode.
fn collect_element_func_refs(
    payload: &[u8],
    tables: &mut HashMap<u32, Vec<u32>>,
    ref_funcs: &mut HashSet<u32>,
) {
    let Some((count, mut off)) = leb128::read_u32(payload) else { return };
    for _ in 0..count {
        let Some((flags, c)) = leb128::read_u32(payload.get(off..).unwrap_or(&[])) else { return };
        off += c;
        let table_idx = match flags {
            0 => 0u32,
            2 => {
                let Some((t, c)) = leb128::read_u32(payload.get(off..).unwrap_or(&[])) else { return };
                off += c;
                t
            }
            // Other flag forms (1, 3, 4, 5, 6, 7) and expression-vec
            // segments are decoded in dce::scan_elements_funcidx; the
            // common case for our corpus is 0/2.
            _ => return,
        };
        // Skip offset expr (active) — only flags 0/2 are active here.
        let Some(end_offset) = skip_const_expr(payload, off) else { return };
        off = end_offset;
        let Some((n, c)) = leb128::read_u32(payload.get(off..).unwrap_or(&[])) else { return };
        off += c;
        for _ in 0..n {
            let Some((f, c)) = leb128::read_u32(payload.get(off..).unwrap_or(&[])) else { return };
            off += c;
            ref_funcs.insert(f);
            tables.entry(table_idx).or_default().push(f);
        }
    }
}

fn collect_global_init_ref_funcs(payload: &[u8], out: &mut HashSet<u32>) {
    let Some((count, mut off)) = leb128::read_u32(payload) else { return };
    for _ in 0..count {
        if off + 2 > payload.len() { return; }
        off += 2;        // valtype + mutability
        let Some(end) = scan_const_expr_for_ref_func(payload, off, out) else { return };
        off = end;
    }
}

/// Return the offset just past the terminating `end` of a const expr,
/// without inspecting opcodes. Used only for skipping active element
/// offset exprs (which are simple: i32.const N ; end).
fn skip_const_expr(payload: &[u8], start: usize) -> Option<usize> {
    let mut off = start;
    while off < payload.len() {
        let len = opcode::instr_len(payload, off)?;
        if payload[off] == 0x0B { return Some(off + 1); }
        off += len;
    }
    None
}

fn scan_const_expr_for_ref_func(
    payload: &[u8], start: usize, out: &mut HashSet<u32>,
) -> Option<usize> {
    let mut off = start;
    while off < payload.len() {
        let len = opcode::instr_len(payload, off)?;
        let op = payload[off];
        if op == 0xD2 {
            if let Some((f, _)) = leb128::read_u32(&payload[off + 1..]) { out.insert(f); }
        }
        if op == 0x0B { return Some(off + 1); }
        off += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assemble(wat: &str) -> Vec<u8> { wat::parse_str(wat).unwrap() }

    #[test]
    fn marks_internal_helper_internal() {
        let wat = r#"
            (module
              (func $helper)
              (func $exp (export "exp")
                call $helper)
            )
        "#;
        let bytes = assemble(wat);
        let h = DerivedHints::from_bytes(&bytes).unwrap();
        // $helper is func 0 (no imports). Not exported, not ref.func'd.
        assert!(h.is_internal(0));
        // $exp is exported → external.
        assert!(!h.is_internal(1));
        // call_count of $helper = 1.
        assert_eq!(h.call_count(0), Some(1));
    }

    #[test]
    fn marks_ref_func_target_external() {
        let wat = r#"
            (module
              (table 1 1 funcref)
              (elem (i32.const 0) $f)
              (func $f (export "f"))
            )
        "#;
        let bytes = assemble(wat);
        let h = DerivedHints::from_bytes(&bytes).unwrap();
        // $f is exported AND in element segment.
        assert!(!h.is_internal(0));
        // table 0 has [0] as its sole target.
        assert_eq!(h.table_targets(0), Some(&[0u32][..]));
    }

    #[test]
    fn detects_unread_globals() {
        let wat = r#"
            (module
              (global $written (mut i32) (i32.const 0))
              (global $read    (mut i32) (i32.const 0))
              (func $f (export "f")
                i32.const 5
                global.set $written
                global.get $read
                drop)
            )
        "#;
        let bytes = assemble(wat);
        let h = DerivedHints::from_bytes(&bytes).unwrap();
        assert!(!h.global_is_read(0)); // $written never read
        assert!(h.global_is_read(1));  // $read read once
    }
}
