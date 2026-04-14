// Constant Folding pass.
//
// Scans function bodies for constant arithmetic patterns and
// evaluates them at link time. Only allocates a new body when
// a fold is actually found (zero-copy for unmodified functions).
//
// Patterns:
//   i32.const X; i32.const Y; i32.add  →  i32.const (X + Y)
//   i32.const X; i32.const Y; i32.sub  →  i32.const (X - Y)
//   i32.const X; i32.const Y; i32.mul  →  i32.const (X * Y)
//   i32.const X; i32.const Y; i32.and  →  i32.const (X & Y)
//   i32.const X; i32.const Y; i32.or   →  i32.const (X | Y)
//   i32.const X; i32.const Y; i32.xor  →  i32.const (X ^ Y)
//   i32.const X; i32.const Y; i32.shl  →  i32.const (X << Y)

use crate::leb128;
use crate::module::{self, WasmModule};

// i32 opcodes.
const I32_CONST: u8 = 0x41;
const I32_ADD: u8 = 0x6A;
const I32_SUB: u8 = 0x6B;
const I32_MUL: u8 = 0x6C;
const I32_AND: u8 = 0x71;
const I32_OR: u8 = 0x72;
const I32_XOR: u8 = 0x73;
const I32_SHL: u8 = 0x74;
const I32_SHR_U: u8 = 0x76;

/// Read a signed LEB128 i32 value.
fn read_sleb128_i32(data: &[u8]) -> Option<(i32, usize)> {
    let mut result: i32 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7F) as i32) << shift;
        shift += 7;
        if byte < 0x80 {
            if shift < 32 && (byte & 0x40) != 0 {
                result |= !0 << shift;
            }
            return Some((result, i + 1));
        }
        if shift >= 35 {
            return None;
        }
    }
    None
}

/// Write a signed LEB128 i32 value.
fn write_sleb128_i32(out: &mut Vec<u8>, mut value: i32) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if !done {
            byte |= 0x80;
        }
        out.push(byte);
        if done {
            break;
        }
    }
}

/// Try to fold constants in a function body.
/// Returns None if no folds were found (body unchanged).
/// Back-compat wrapper: bytes only.
fn fold_body(body: &[u8]) -> Option<Vec<u8>> {
    fold_body_with_edits(body).map(|(bytes, _)| bytes)
}

/// Returns `(output_bytes, BodyEdits)` — the edits describe byte-
/// level provenance of the rewrite. For Phase 2b's DWARF rewriter.
fn fold_body_with_edits(body: &[u8]) -> Option<(Vec<u8>, crate::provenance::BodyEdits)> {
    let instr_start = crate::opcode::skip_locals(body)?;
    let spans: Vec<(usize, usize)> = crate::opcode::walk(body, instr_start)?
        .into_iter()
        .map(|(p, len)| (p, p + len))
        .collect();

    // Find foldable spans. Each replacement is (from, to, Repl).
    // Two-const triples: collapse to a single i32.const.
    // Single-const+identity-binop pairs: collapse to nothing (delete both).
    enum Repl { Const(i32), Empty }
    let mut replacements: Vec<(usize, usize, Repl)> = Vec::new();
    let mut i = 0;
    while i < spans.len() {
        if i + 2 < spans.len() {
            let (a0, a1) = spans[i];
            let (b0, b1) = spans[i + 1];
            let (c0, _c1) = spans[i + 2];
            if body[a0] == I32_CONST && body[b0] == I32_CONST {
                if let (Some((va, _)), Some((vb, _))) = (
                    read_sleb128_i32(&body[a0 + 1..a1]),
                    read_sleb128_i32(&body[b0 + 1..b1]),
                ) {
                    if let Some(r) = evaluate(body[c0], va, vb) {
                        replacements.push((a0, spans[i + 2].1, Repl::Const(r)));
                        i += 3;
                        continue;
                    }
                }
            }
        }
        if i + 1 < spans.len() {
            let (a0, a1) = spans[i];
            let (b0, _b1) = spans[i + 1];
            if body[a0] == I32_CONST {
                if let Some((v, _)) = read_sleb128_i32(&body[a0 + 1..a1]) {
                    if is_rhs_identity(body[b0], v) {
                        replacements.push((a0, spans[i + 1].1, Repl::Empty));
                        i += 2;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }

    if replacements.is_empty() { return None; }

    let mut out = Vec::with_capacity(body.len());
    let mut edits = crate::provenance::BodyEdits::identity();
    let mut cursor = 0usize;
    for (from, to, repl) in replacements {
        out.extend_from_slice(&body[cursor..from]);
        let in_start = from as u32;
        let in_len = (to - from) as u32;
        let out_start = out.len() as u32;
        match repl {
            Repl::Const(val) => {
                out.push(I32_CONST);
                write_sleb128_i32(&mut out, val);
                let out_len = out.len() as u32 - out_start;
                edits.push(
                    crate::provenance::Edit::subst(in_start, in_len, out_start, out_len),
                    None,
                );
            }
            Repl::Empty => {
                edits.push(
                    crate::provenance::Edit::delete(in_start, in_len, out_start),
                    None,
                );
            }
        }
        cursor = to;
    }
    out.extend_from_slice(&body[cursor..]);
    Some((out, edits))
}

/// True if `<x> ; i32.const v ; op` is semantically `<x>` — i.e. v is
/// the right-hand identity for the binop. Commutative op + left-hand
/// identity is not matched here (would need backward value tracking).
fn is_rhs_identity(op: u8, v: i32) -> bool {
    matches!((op, v),
        (I32_ADD, 0) | (I32_SUB, 0)
        | (I32_OR, 0) | (I32_XOR, 0)
        | (I32_SHL, 0) | (I32_SHR_U, 0) | (0x75 /*shr_s*/, 0)
        | (I32_MUL, 1)
        | (I32_AND, -1)
    )
}

/// Evaluate a binary operation on two i32 constants.
fn evaluate(opcode: u8, a: i32, b: i32) -> Option<i32> {
    match opcode {
        I32_ADD => Some(a.wrapping_add(b)),
        I32_SUB => Some(a.wrapping_sub(b)),
        I32_MUL => Some(a.wrapping_mul(b)),
        I32_AND => Some(a & b),
        I32_OR => Some(a | b),
        I32_XOR => Some(a ^ b),
        I32_SHL => Some(a.wrapping_shl(b as u32)),
        I32_SHR_U => Some((a as u32).wrapping_shr(b as u32) as i32),
        _ => None,
    }
}

/// Apply constant folding to a module.
/// MutModule-style entry point: walk each defined body and set overrides
/// for those we folded. Zero-alloc for unchanged bodies.
pub fn apply_mut(m: &mut crate::mut_module::MutModule<'_>) {
    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>, crate::provenance::BodyEdits)> = (0..m.num_bodies())
        .into_par_iter()
        .filter_map(|i| fold_body_with_edits(m.body_bytes(i)).map(|(b, e)| (i, b, e)))
        .collect();
    for (i, b, e) in updates { m.set_body_with_edits(i, b, e); }
}

pub fn apply(module: &WasmModule<'_>) -> Vec<u8> {
    let data = module.data();
    let Some(code_sec_idx) = module.sections().iter().position(|s| s.id == module::SECTION_CODE) else {
        return data.to_vec();
    };

    // Parse function bodies to know their boundaries.
    let code_sec = &module.sections()[code_sec_idx];
    let code_payload = code_sec.payload.slice(data);
    let Some((func_count, mut off)) = leb128::read_u32(code_payload) else {
        return data.to_vec();
    };

    // Try folding each function body.
    let mut replacements: Vec<Option<Vec<u8>>> = Vec::new();
    let mut any_folded = false;

    for _ in 0..func_count {
        let Some((body_size, size_consumed)) = leb128::read_u32(&code_payload[off..]) else {
            break;
        };
        off += size_consumed;
        let body = &code_payload[off..off + body_size as usize];
        off += body_size as usize;

        if let Some(new_body) = fold_body(body) {
            replacements.push(Some(new_body));
            any_folded = true;
        } else {
            replacements.push(None);
        }
    }

    if !any_folded {
        return data.to_vec();
    }

    // Rebuild code section with folded bodies.
    let mut new_code_payload = Vec::new();
    leb128::write_u32(&mut new_code_payload, func_count);

    off = leb128::u32_size(func_count) as usize;
    for replacement in &replacements {
        let Some((body_size, size_consumed)) = leb128::read_u32(&code_payload[off..]) else {
            break;
        };
        off += size_consumed;
        let original_body = &code_payload[off..off + body_size as usize];
        off += body_size as usize;

        match replacement {
            Some(new_body) => {
                leb128::write_u32(&mut new_code_payload, new_body.len() as u32);
                new_code_payload.extend_from_slice(new_body);
            }
            None => {
                leb128::write_u32(&mut new_code_payload, body_size);
                new_code_payload.extend_from_slice(original_body);
            }
        }
    }

    // Emit module with replaced code section.
    let mut replacements_map = std::collections::HashMap::new();
    replacements_map.insert(code_sec_idx, new_code_payload);
    crate::emit::emit_with_replacements(module, &replacements_map)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bodies start with a locals-vec header: `0` = zero locals.
    #[test]
    fn fold_add() {
        let body = vec![0, I32_CONST, 10, I32_CONST, 20, I32_ADD, 0x0B];
        let folded = fold_body(&body).unwrap();
        assert_eq!(folded, vec![0, I32_CONST, 30, 0x0B]);
    }

    #[test]
    fn fold_sub() {
        let body = vec![0, I32_CONST, 50, I32_CONST, 20, I32_SUB, 0x0B];
        let folded = fold_body(&body).unwrap();
        assert_eq!(folded, vec![0, I32_CONST, 30, 0x0B]);
    }

    #[test]
    fn fold_mul() {
        let body = vec![0, I32_CONST, 6, I32_CONST, 7, I32_MUL, 0x0B];
        let folded = fold_body(&body).unwrap();
        assert_eq!(folded, vec![0, I32_CONST, 42, 0x0B]);
    }

    #[test]
    fn no_fold_without_pattern() {
        let body = vec![0, I32_CONST, 10, 0x0B];
        assert!(fold_body(&body).is_none());
    }

    #[test]
    fn fold_simple_and() {
        let body = vec![0, I32_CONST, 15, I32_CONST, 6, I32_AND, 0x0B];
        let folded = fold_body(&body).unwrap();
        assert_eq!(folded, vec![0, I32_CONST, 6, 0x0B]);
    }

    #[test]
    fn fold_identity_add_zero() {
        // local.get 0 ; i32.const 0 ; i32.add → local.get 0
        let body = vec![0, 0x20, 0, I32_CONST, 0, I32_ADD, 0x0B];
        let folded = fold_body(&body).unwrap();
        assert_eq!(folded, vec![0, 0x20, 0, 0x0B]);
    }

    #[test]
    fn fold_identity_mul_one() {
        let body = vec![0, 0x20, 0, I32_CONST, 1, I32_MUL, 0x0B];
        let folded = fold_body(&body).unwrap();
        assert_eq!(folded, vec![0, 0x20, 0, 0x0B]);
    }

    #[test]
    fn fold_identity_and_neg_one() {
        // -1 sleb = 0x7F
        let body = vec![0, 0x20, 0, I32_CONST, 0x7F, I32_AND, 0x0B];
        let folded = fold_body(&body).unwrap();
        assert_eq!(folded, vec![0, 0x20, 0, 0x0B]);
    }

    #[test]
    fn leave_non_identity_pair() {
        // i32.const 2 ; i32.mul — not identity.
        let body = vec![0, 0x20, 0, I32_CONST, 2, I32_MUL, 0x0B];
        assert!(fold_body(&body).is_none());
    }

    #[test]
    fn fold_preserves_surrounding() {
        // nop; i32.const 3; i32.const 4; i32.add; drop; end
        let body = vec![0, 0x01, I32_CONST, 3, I32_CONST, 4, I32_ADD, 0x1A, 0x0B];
        let folded = fold_body(&body).unwrap();
        assert_eq!(folded, vec![0, 0x01, I32_CONST, 7, 0x1A, 0x0B]);
    }

    #[test]
    fn edits_reconstruct_output_for_two_const_fold() {
        let body = vec![0, I32_CONST, 10, I32_CONST, 20, I32_ADD, 0x0B];
        let (out, edits) = fold_body_with_edits(&body).unwrap();
        // Apply the edits to the input, using the output bytes to
        // supply substituted spans. If they match, edits correctly
        // describe the rewrite.
        let reconstructed = edits.apply(&body, |i, _src, _len| {
            let e = edits.edits().get(i)?;
            Some(out[e.out_start as usize .. e.out_end() as usize].to_vec())
        }).unwrap();
        assert_eq!(reconstructed, out);
    }

    #[test]
    fn edits_reconstruct_output_for_identity_fold() {
        // local.get 0 ; i32.const 0 ; i32.add → local.get 0
        let body = vec![0, 0x20, 0, I32_CONST, 0, I32_ADD, 0x0B];
        let (out, edits) = fold_body_with_edits(&body).unwrap();
        let reconstructed = edits.apply(&body, |i, _src, _len| {
            let e = edits.edits().get(i)?;
            Some(out[e.out_start as usize .. e.out_end() as usize].to_vec())
        }).unwrap();
        assert_eq!(reconstructed, out);
    }

    #[test]
    fn apply_on_module() {
        let mut data = b"\0asm\x01\x00\x00\x00".to_vec();
        // Type: () -> ()
        data.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        // Function: 1 func, type 0
        data.extend_from_slice(&[3, 2, 1, 0]);
        // Export
        data.extend_from_slice(&[7, 5, 1, 1, b'f', 0x00, 0]);
        // Code: body = [0 locals, i32.const 3, i32.const 4, i32.add, drop, end]
        let body = vec![0, I32_CONST, 3, I32_CONST, 4, I32_ADD, 0x1A, 0x0B];
        let mut code = Vec::new();
        leb128::write_u32(&mut code, 1); // 1 function
        leb128::write_u32(&mut code, body.len() as u32);
        code.extend_from_slice(&body);
        data.push(10);
        leb128::write_u32(&mut data, code.len() as u32);
        data.extend_from_slice(&code);

        let module = WasmModule::parse(&data).unwrap();
        let output = apply(&module);

        assert!(output.len() < data.len(), "folding should shrink the module");

        // Verify output is valid.
        WasmModule::parse(&output).unwrap();
    }
}
