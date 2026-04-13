//! Vacuum pass — removes trivially-useless instructions.
//!
//! Current scope: drop every `nop` (0x01). Later extensions:
//!   - dead code after `br` / `return` / `unreachable` until matching `end`
//!   - collapse `drop` following a pure, side-effect-free producer
//!   - empty `block`/`loop`
//!
//! Byte-level: walks each function body via the shared opcode walker,
//! splices out nop instructions, rewrites the body-size LEB.

use crate::leb128;
use crate::module::{self, WasmModule};
use crate::opcode;

const OP_NOP: u8 = 0x01;
const OP_UNREACHABLE: u8 = 0x00;
const OP_BLOCK: u8 = 0x02;
const OP_LOOP: u8 = 0x03;
const OP_IF: u8 = 0x04;
const OP_ELSE: u8 = 0x05;
const OP_END: u8 = 0x0B;
const OP_BR: u8 = 0x0C;
const OP_BR_TABLE: u8 = 0x0E;
const OP_RETURN: u8 = 0x0F;
const OP_DROP: u8 = 0x1A;
const OP_LOCAL_GET: u8 = 0x20;
const OP_LOCAL_SET: u8 = 0x21;
const OP_LOCAL_TEE: u8 = 0x22;
const OP_GLOBAL_GET: u8 = 0x23;
const OP_I32_CONST: u8 = 0x41;
const OP_I64_CONST: u8 = 0x42;
const OP_F32_CONST: u8 = 0x43;
const OP_F64_CONST: u8 = 0x44;
const OP_REF_NULL: u8 = 0xD0;
const OP_REF_FUNC: u8 = 0xD2;

// Numeric op codes used in peephole patterns.
const OP_I32_EQ: u8 = 0x46;
const OP_I32_NE: u8 = 0x47;
const OP_I32_EQZ: u8 = 0x45;
const OP_I32_ADD: u8 = 0x6A;
const OP_I32_SUB: u8 = 0x6B;
const OP_I32_MUL: u8 = 0x6C;
const OP_I32_OR: u8 = 0x72;
const OP_I32_XOR: u8 = 0x73;
const OP_I32_SHL: u8 = 0x74;
const OP_I32_SHR_S: u8 = 0x75;
const OP_I32_SHR_U: u8 = 0x76;
const OP_I64_EQ: u8 = 0x51;
const OP_I64_NE: u8 = 0x52;
const OP_I64_EQZ: u8 = 0x50;

/// Pure producers: push exactly one value, no side effects, no traps.
/// Removing a `(producer, drop)` pair is always safe.
fn is_pure_producer(op: u8) -> bool {
    matches!(
        op,
        OP_LOCAL_GET | OP_GLOBAL_GET
            | OP_I32_CONST | OP_I64_CONST | OP_F32_CONST | OP_F64_CONST
            | OP_REF_NULL | OP_REF_FUNC
    )
}

fn is_block_starter(op: u8) -> bool {
    matches!(op, OP_BLOCK | OP_LOOP | OP_IF)
}

fn is_unconditional_terminator(op: u8) -> bool {
    matches!(op, OP_UNREACHABLE | OP_BR | OP_BR_TABLE | OP_RETURN)
}

/// Clean a function body: drop `nop`s and dead code after unconditional
/// terminators up to the enclosing `end`/`else`. Returns None if nothing
/// changed or the body can't be walked (unknown opcode).
fn clean_body(body: &[u8]) -> Option<Vec<u8>> {
    let start = opcode::skip_locals(body)?;
    let instrs = opcode::walk(body, start)?;

    // GC-specific opcodes (0xFB prefix) have stack effects that depend on
    // type-indexed fields our peepholes don't reason about. Rather than
    // risk invalid output, skip any body that contains them — the walker
    // still succeeds (which matters for DCE), but this pass is a no-op.
    if instrs.iter().any(|&(p, _)| body[p] == 0xFB) {
        return None;
    }

    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[..start]);
    let mut changed = false;

    // While `dead` is true, we're skipping bytes. `nested` tracks block
    // starters opened inside the dead zone; we stop skipping when we see
    // an `end`/`else` at `nested == 0` — that's the closer of the block
    // that contained the terminator.
    let mut dead = false;
    let mut nested: u32 = 0;
    // Number of following instructions to discard (set by peepholes that
    // replace a multi-instruction sequence with fewer instructions).
    let mut skip_remaining: u32 = 0;

    let mut idx = 0;
    while idx < instrs.len() {
        let (p, len) = instrs[idx];
        let p = &p; let len = &len;
        idx += 1;

        if skip_remaining > 0 {
            skip_remaining -= 1;
            continue;
        }

        let op = body[*p];

        // Peephole: empty void-typed control structures.
        //   block 0x40 end      → (removed)
        //   loop  0x40 end      → (removed)
        //   if    0x40 end      → drop
        //   if    0x40 else end → drop
        // Length of a void block/loop/if instruction is 2: opcode + 0x40.
        if !dead && is_block_starter(op) && *len == 2 && body[*p + 1] == 0x40
            && idx < instrs.len()
        {
            let (next_p, _) = instrs[idx];
            let next_op = body[next_p];
            if next_op == OP_END {
                // block/loop/if with empty body.
                if op == OP_IF { out.push(OP_DROP); }
                skip_remaining = 1;
                changed = true;
                continue;
            }
            if op == OP_IF && next_op == OP_ELSE && idx + 1 < instrs.len() {
                let (end_p, _) = instrs[idx + 1];
                if body[end_p] == OP_END {
                    out.push(OP_DROP);
                    skip_remaining = 2;
                    changed = true;
                    continue;
                }
            }
        }

        // Peephole: i32.const 0; (add|or|xor|sub|shl|shr_s|shr_u) → (nothing).
        //           i32.const 1; i32.mul → (nothing).
        //           i32.const 0; i32.eq → i32.eqz (saves 2 bytes).
        //           i32.const 0; i32.ne → i32.eqz; i32.eqz. No net gain.
        //           i64.const 0; i64.eq → i64.eqz.
        // In all cases the "producer" before `const` leaves its value on
        // the stack; we just strip the redundant const + op.
        // Detect constants by their canonical single-byte LEB form:
        // 0 encodes as `0x00`, +1 as `0x01`. Instruction length = 2 means
        // opcode + single-byte immediate.
        if !dead && idx < instrs.len() && *len == 2 {
            let imm = body[*p + 1];
            let (np, _) = instrs[idx];
            let nop = body[np];
            let is_zero = imm == 0x00;
            let is_one = imm == 0x01;

            if op == OP_I32_CONST {
                if is_zero && matches!(nop,
                    OP_I32_ADD | OP_I32_OR | OP_I32_XOR | OP_I32_SUB
                    | OP_I32_SHL | OP_I32_SHR_S | OP_I32_SHR_U
                ) {
                    skip_remaining = 1; changed = true; continue;
                }
                if is_one && nop == OP_I32_MUL {
                    skip_remaining = 1; changed = true; continue;
                }
                if is_zero && nop == OP_I32_EQ {
                    out.push(OP_I32_EQZ);
                    skip_remaining = 1; changed = true; continue;
                }
            }
            if op == OP_I64_CONST && is_zero && nop == OP_I64_EQ {
                out.push(OP_I64_EQZ);
                skip_remaining = 1; changed = true; continue;
            }
            let _ = (OP_I32_NE, OP_I64_NE);
        }

        // Peephole: <pure producer>; drop → (nothing).
        // Must not fire inside dead code (we'd be re-emitting anyway).
        if !dead && is_pure_producer(op) && idx < instrs.len() {
            let (np, _) = instrs[idx];
            if body[np] == OP_DROP {
                skip_remaining = 1;
                changed = true;
                continue;
            }
        }

        // Peephole: local.get N; local.set N → (nothing).
        // Writing a local to itself is a pure no-op.
        if !dead && op == OP_LOCAL_GET && idx < instrs.len() {
            let (np, nlen) = instrs[idx];
            if body[np] == OP_LOCAL_SET {
                let (a, _) = crate::leb128::read_u32(&body[*p + 1..*p + len]).unwrap_or((0, 0));
                let (b, _) = crate::leb128::read_u32(&body[np + 1..np + nlen]).unwrap_or((u32::MAX, 0));
                if a == b {
                    skip_remaining = 1;
                    changed = true;
                    continue;
                }
            }
        }

        // Peephole: local.set N; local.get N → local.tee N.
        // Only safe outside dead code (we mustn't rewrite then skip).
        if !dead && op == OP_LOCAL_SET && idx < instrs.len() {
            let (np, nlen) = instrs[idx];
            if body[np] == OP_LOCAL_GET {
                let (a, _) = crate::leb128::read_u32(&body[*p + 1..*p + len]).unwrap_or((0, 0));
                let (b, _) = crate::leb128::read_u32(&body[np + 1..np + nlen]).unwrap_or((u32::MAX, 0));
                if a == b {
                    out.push(OP_LOCAL_TEE);
                    crate::leb128::write_u32(&mut out, a);
                    skip_remaining = 1;
                    changed = true;
                    continue;
                }
            }
        }

        if dead {
            if is_block_starter(op) {
                nested += 1;
            } else if op == OP_END {
                if nested == 0 {
                    // Closes the block that contained the terminator — emit it
                    // and resume normal processing.
                    out.extend_from_slice(&body[*p..*p + len]);
                    dead = false;
                    continue;
                } else {
                    nested -= 1;
                }
            } else if op == OP_ELSE && nested == 0 {
                // End of then-branch, start of else-branch (reachable again).
                out.extend_from_slice(&body[*p..*p + len]);
                dead = false;
                continue;
            }
            // any other instruction: skip.
            changed = true;
            continue;
        }

        if op == OP_NOP {
            changed = true;
            continue;
        }

        out.extend_from_slice(&body[*p..*p + len]);

        if is_unconditional_terminator(op) {
            dead = true;
            nested = 0;
        }
    }

    if !changed { return None; }
    Some(out)
}

/// MutModule-style entry point. Iterates bodies once, sets overrides
/// only for the ones we actually changed. Zero allocation for unchanged
/// bodies.
pub fn apply_mut(m: &mut crate::mut_module::MutModule<'_>) {
    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>)> = (0..m.num_bodies())
        .into_par_iter()
        .filter_map(|i| clean_body(m.body_bytes(i)).map(|b| (i, b)))
        .collect();
    for (i, b) in updates { m.set_body(i, b); }
}

pub fn apply(module: &WasmModule<'_>) -> Vec<u8> {
    let data = module.data();
    let Some(code_idx) = module.sections().iter().position(|s| s.id == module::SECTION_CODE)
    else {
        return data.to_vec();
    };
    let code_sec = &module.sections()[code_idx];
    let payload = code_sec.payload.slice(data);
    let Some((func_count, header_len)) = leb128::read_u32(payload) else {
        return data.to_vec();
    };

    // Walk each body; build (maybe-rewritten) bodies vector.
    let mut off = header_len;
    let mut new_bodies: Vec<Option<Vec<u8>>> = Vec::with_capacity(func_count as usize);
    let mut any_changed = false;
    for _ in 0..func_count {
        let Some((body_size, c)) = leb128::read_u32(&payload[off..]) else {
            return data.to_vec();
        };
        off += c;
        let body = &payload[off..off + body_size as usize];
        off += body_size as usize;
        match clean_body(body) {
            Some(new) => { new_bodies.push(Some(new)); any_changed = true; }
            None => new_bodies.push(None),
        }
    }

    if !any_changed {
        return data.to_vec();
    }

    // Rebuild code section payload.
    let mut new_payload = Vec::with_capacity(payload.len());
    leb128::write_u32(&mut new_payload, func_count);
    off = header_len;
    for new in &new_bodies {
        let Some((body_size, c)) = leb128::read_u32(&payload[off..]) else { break };
        off += c;
        let end = off + body_size as usize;
        match new {
            Some(b) => {
                leb128::write_u32(&mut new_payload, b.len() as u32);
                new_payload.extend_from_slice(b);
            }
            None => {
                leb128::write_u32(&mut new_payload, body_size);
                new_payload.extend_from_slice(&payload[off..end]);
            }
        }
        off = end;
    }

    let mut replacements = std::collections::HashMap::new();
    replacements.insert(code_idx, new_payload);
    crate::emit::emit_with_replacements(module, &replacements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_trailing_nops() {
        // [0 locals, nop, nop, end] — just nops.
        let body = vec![0, 0x01, 0x01, 0x0B];
        let out = clean_body(&body).unwrap();
        assert_eq!(out, vec![0, 0x0B]);
    }

    #[test]
    fn no_change_when_already_clean() {
        // [0 locals, local.get 0, end] — nothing to strip or fold.
        let body = vec![0, 0x20, 0, 0x0B];
        assert!(clean_body(&body).is_none());
    }

    #[test]
    fn fold_const_drop() {
        // [0 locals, i32.const 5, drop, end] → [0 locals, end]
        let body = vec![0, 0x41, 5, 0x1A, 0x0B];
        let out = clean_body(&body).unwrap();
        assert_eq!(out, vec![0, 0x0B]);
    }

    #[test]
    fn fold_set_get_into_tee() {
        // local.set 3; local.get 3 → local.tee 3
        let body = vec![0, 0x41, 5, 0x21, 3, 0x20, 3, 0x1A, 0x0B];
        let out = clean_body(&body).unwrap();
        assert_eq!(out, vec![0, 0x41, 5, 0x22, 3, 0x1A, 0x0B]);
    }

    #[test]
    fn apply_on_module() {
        let mut data = b"\0asm\x01\x00\x00\x00".to_vec();
        data.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);              // type
        data.extend_from_slice(&[3, 2, 1, 0]);                        // func
        data.extend_from_slice(&[7, 5, 1, 1, b'f', 0x00, 0]);         // export
        // code: 1 body = [0 locals, nop, nop, end] (5 bytes)
        data.extend_from_slice(&[10, 6, 1, 4, 0, 0x01, 0x01, 0x0B]);
        let module = WasmModule::parse(&data).unwrap();
        let out = apply(&module);
        assert!(out.len() < data.len());
        WasmModule::parse(&out).unwrap();
    }
}
