//! Remove passive & declarative element segments that are never referenced
//! by `table.init` or `elem.drop`. Active segments are left alone (they
//! initialise a table at module load).
//!
//! Mirror of `unused_data.rs` for the element index space.

use crate::leb128;
use crate::module::{self, WasmModule};
use crate::opcode;

const OP_PREFIX_FC: u8 = 0xFC;
const SUB_TABLE_INIT: u32 = 0x0C;
const SUB_ELEM_DROP: u32 = 0x0D;

// GC opcodes that reference element segments: array.new_elem (0xFB 0x0A),
// array.init_elem (0xFB 0x13). Second LEB is the elem idx.
const OP_PREFIX_FB: u8 = 0xFB;
const SUB_GC_ARRAY_NEW_ELEM: u32 = 0x0A;
const SUB_GC_ARRAY_INIT_ELEM: u32 = 0x13;

pub fn apply(module: &mut WasmModule<'_>) -> Vec<u8> {
    module.ensure_function_bodies_parsed();
    let data = module.data();
    let Some(sec_idx) = module.sections().iter().position(|s| s.id == module::SECTION_ELEMENT)
    else {
        return data.to_vec();
    };
    let sec = &module.sections()[sec_idx];
    let payload = sec.payload.slice(data);
    let Some(segs) = parse_elem_segments(payload) else {
        return data.to_vec();
    };

    let referenced = match collect_referenced(module) {
        Some(set) => set,
        None => return data.to_vec(),
    };

    let mut keep: Vec<bool> = Vec::with_capacity(segs.len());
    let mut any_removed = false;
    for (i, s) in segs.iter().enumerate() {
        if s.removable && !referenced.contains(&(i as u32)) {
            keep.push(false);
            any_removed = true;
        } else {
            keep.push(true);
        }
    }
    if !any_removed { return data.to_vec(); }

    let mut seg_map: Vec<Option<u32>> = Vec::with_capacity(segs.len());
    let mut next = 0u32;
    for k in &keep {
        if *k { seg_map.push(Some(next)); next += 1; } else { seg_map.push(None); }
    }
    let new_count = next;

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..8]);
    for section in module.sections() {
        match section.id {
            module::SECTION_ELEMENT => emit_element_section(&mut out, section, data, &segs, &keep, new_count),
            module::SECTION_CODE => emit_code_section(&mut out, module, data, &seg_map),
            _ => out.extend_from_slice(section.full.slice(data)),
        }
    }
    out
}

struct Segment {
    /// Safe to remove? Active variants must stay (flags 0, 2, 4, 6).
    removable: bool,
    span: (usize, usize),
}

fn parse_elem_segments(payload: &[u8]) -> Option<Vec<Segment>> {
    let (count, mut off) = leb128::read_u32(payload)?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let start = off;
        let (flags, c) = leb128::read_u32(payload.get(off..)?)?;
        off += c;
        // Only handle the encodings we understand cleanly. If unknown, bail.
        let removable = match flags {
            0 | 2 | 4 | 6 => false,  // active
            1 | 3 | 5 | 7 => true,   // passive or declarative
            _ => return None,
        };
        match flags {
            0 => {
                off = skip_const_expr(payload, off)?;
                off = skip_funcidx_vec(payload, off)?;
            }
            1 | 3 => {
                off += 1;                       // elemkind
                off = skip_funcidx_vec(payload, off)?;
            }
            2 => {
                let (_, c) = leb128::read_u32(payload.get(off..)?)?;
                off += c;                       // tableidx
                off = skip_const_expr(payload, off)?;
                off += 1;                       // elemkind
                off = skip_funcidx_vec(payload, off)?;
            }
            4 => {
                off = skip_const_expr(payload, off)?;
                off = skip_expr_vec(payload, off)?;
            }
            5 | 7 => {
                off += 1;                       // reftype
                off = skip_expr_vec(payload, off)?;
            }
            6 => {
                let (_, c) = leb128::read_u32(payload.get(off..)?)?;
                off += c;
                off = skip_const_expr(payload, off)?;
                off += 1;                       // reftype
                off = skip_expr_vec(payload, off)?;
            }
            _ => return None,
        }
        out.push(Segment { removable, span: (start, off - start) });
    }
    Some(out)
}

fn skip_const_expr(bytes: &[u8], mut off: usize) -> Option<usize> {
    while off < bytes.len() {
        if bytes[off] == 0x0B { return Some(off + 1); }
        let len = opcode::instr_len(bytes, off)?;
        off += len;
    }
    None
}

fn skip_funcidx_vec(bytes: &[u8], mut off: usize) -> Option<usize> {
    let (n, c) = leb128::read_u32(bytes.get(off..)?)?;
    off += c;
    for _ in 0..n {
        let (_, c) = leb128::read_u32(bytes.get(off..)?)?;
        off += c;
    }
    Some(off)
}

fn skip_expr_vec(bytes: &[u8], mut off: usize) -> Option<usize> {
    let (n, c) = leb128::read_u32(bytes.get(off..)?)?;
    off += c;
    for _ in 0..n {
        off = skip_const_expr(bytes, off)?;
    }
    Some(off)
}

fn collect_referenced(module: &WasmModule<'_>) -> Option<std::collections::HashSet<u32>> {
    let mut set = std::collections::HashSet::new();
    let data = module.data();
    for body in module.function_bodies() {
        let b = body.body.slice(data);
        let Some(start) = opcode::skip_locals(b) else { return None };
        let Some(instrs) = opcode::walk(b, start) else { return None };
        for (p, _) in instrs {
            if b[p] == OP_PREFIX_FC {
                let (sub, c) = leb128::read_u32(&b[p + 1..])?;
                if sub == SUB_TABLE_INIT {
                    // elemidx, then tableidx
                    let (elem, _) = leb128::read_u32(&b[p + 1 + c..])?;
                    set.insert(elem);
                } else if sub == SUB_ELEM_DROP {
                    let (elem, _) = leb128::read_u32(&b[p + 1 + c..])?;
                    set.insert(elem);
                }
            } else if b[p] == OP_PREFIX_FB {
                let (sub, c) = leb128::read_u32(&b[p + 1..])?;
                if sub == SUB_GC_ARRAY_NEW_ELEM || sub == SUB_GC_ARRAY_INIT_ELEM {
                    let (_, c1) = leb128::read_u32(&b[p + 1 + c..])?; // typeidx
                    let (elem, _) = leb128::read_u32(&b[p + 1 + c + c1..])?;
                    set.insert(elem);
                }
            }
        }
    }
    Some(set)
}

fn emit_element_section(out: &mut Vec<u8>, section: &module::Section, data: &[u8], segs: &[Segment], keep: &[bool], new_count: u32) {
    let payload = section.payload.slice(data);
    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, new_count);
    for (s, k) in segs.iter().zip(keep) {
        if *k {
            let (off, len) = s.span;
            new_payload.extend_from_slice(&payload[off..off + len]);
        }
    }
    out.push(section.id);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn emit_code_section(out: &mut Vec<u8>, module: &WasmModule<'_>, data: &[u8], seg_map: &[Option<u32>]) {
    let bodies = module.function_bodies();
    let mut new_payload = Vec::new();
    leb128::write_u32(&mut new_payload, bodies.len() as u32);
    for body in bodies {
        let body_bytes = body.body.slice(data);
        let rewritten = rewrite_body_elemidx(body_bytes, seg_map);
        leb128::write_u32(&mut new_payload, rewritten.len() as u32);
        new_payload.extend_from_slice(&rewritten);
    }
    out.push(module::SECTION_CODE);
    leb128::write_u32(out, new_payload.len() as u32);
    out.extend_from_slice(&new_payload);
}

fn rewrite_body_elemidx(body: &[u8], seg_map: &[Option<u32>]) -> Vec<u8> {
    let Some(start) = opcode::skip_locals(body) else { return body.to_vec() };
    let Some(instrs) = opcode::walk(body, start) else { return body.to_vec() };

    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[..start]);
    let mut cursor = start;

    for (p, len) in &instrs {
        if body[*p] == OP_PREFIX_FC {
            if let Some((sub, c)) = leb128::read_u32(&body[*p + 1..]) {
                if sub == SUB_TABLE_INIT || sub == SUB_ELEM_DROP {
                    if let Some((idx, ci)) = leb128::read_u32(&body[*p + 1 + c..]) {
                        let new_idx = seg_map.get(idx as usize).copied().flatten().unwrap_or(idx);
                        if new_idx != idx {
                            out.extend_from_slice(&body[cursor..*p]);
                            out.push(OP_PREFIX_FC);
                            leb128::write_u32(&mut out, sub);
                            leb128::write_u32(&mut out, new_idx);
                            let consumed = 1 + c + ci;
                            let trailing = *len - consumed;
                            out.extend_from_slice(&body[*p + consumed..*p + consumed + trailing]);
                            cursor = *p + *len;
                        }
                    }
                }
            }
        }
    }
    out.extend_from_slice(&body[cursor..]);
    out
}
