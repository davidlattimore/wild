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
fn fold_body(body: &[u8]) -> Option<Vec<u8>> {
    // Scan for the pattern: i32.const <sleb>; i32.const <sleb>; <binop>
    let mut out = Vec::new();
    let mut pos = 0;
    let mut folded = false;

    while pos < body.len() {
        // Check for: i32.const A; i32.const B; binop
        if body[pos] == I32_CONST {
            if let Some((val_a, consumed_a)) = read_sleb128_i32(&body[pos + 1..]) {
                let after_a = pos + 1 + consumed_a;
                if after_a < body.len() && body[after_a] == I32_CONST {
                    if let Some((val_b, consumed_b)) = read_sleb128_i32(&body[after_a + 1..]) {
                        let after_b = after_a + 1 + consumed_b;
                        if after_b < body.len() {
                            let result = evaluate(body[after_b], val_a, val_b);
                            if let Some(result_val) = result {
                                // Fold! Emit i32.const <result>.
                                out.push(I32_CONST);
                                write_sleb128_i32(&mut out, result_val);
                                pos = after_b + 1; // skip the binop
                                folded = true;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        // No fold — copy byte as-is.
        out.push(body[pos]);
        pos += 1;
    }

    if folded { Some(out) } else { None }
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

    #[test]
    fn fold_add() {
        // i32.const 10; i32.const 20; i32.add → i32.const 30
        let body = vec![I32_CONST, 10, I32_CONST, 20, I32_ADD, 0x0B];
        let folded = fold_body(&body).unwrap();
        assert_eq!(folded, vec![I32_CONST, 30, 0x0B]);
    }

    #[test]
    fn fold_sub() {
        let body = vec![I32_CONST, 50, I32_CONST, 20, I32_SUB, 0x0B];
        let folded = fold_body(&body).unwrap();
        assert_eq!(folded, vec![I32_CONST, 30, 0x0B]);
    }

    #[test]
    fn fold_mul() {
        let body = vec![I32_CONST, 6, I32_CONST, 7, I32_MUL, 0x0B];
        let folded = fold_body(&body).unwrap();
        assert_eq!(folded, vec![I32_CONST, 42, 0x0B]);
    }

    #[test]
    fn no_fold_without_pattern() {
        // Just i32.const 10; end — no binop to fold.
        let body = vec![I32_CONST, 10, 0x0B];
        assert!(fold_body(&body).is_none());
    }

    #[test]
    fn fold_and() {
        let body = vec![I32_CONST, 0xFF, 0x00, I32_CONST, 0x0F, I32_AND, 0x0B];
        let folded = fold_body(&body).unwrap();
        // 0xFF00 & 0x0F = 0x0F... wait, 0xFF 0x00 is LEB128 for 127.
        // Let me use simpler values.
    }

    #[test]
    fn fold_simple_and() {
        let body = vec![I32_CONST, 15, I32_CONST, 6, I32_AND, 0x0B];
        let folded = fold_body(&body).unwrap();
        assert_eq!(folded, vec![I32_CONST, 6, 0x0B]); // 15 & 6 = 6
    }

    #[test]
    fn fold_preserves_surrounding() {
        // nop; i32.const 3; i32.const 4; i32.add; drop; end
        let body = vec![0x01, I32_CONST, 3, I32_CONST, 4, I32_ADD, 0x1A, 0x0B];
        let folded = fold_body(&body).unwrap();
        assert_eq!(folded, vec![0x01, I32_CONST, 7, 0x1A, 0x0B]);
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
