//! Trim trailing zero bytes from data segments.
//!
//! WASM memory is zero-initialised. Writing zeros over zero is a no-op,
//! so we can shorten any data segment's byte vector by dropping trailing
//! 0x00 bytes without observable effect.
//!
//! Handled segment encodings:
//!   flag 0: active, memidx 0, expr, bytes_vec
//!   flag 1: passive, bytes_vec
//!   flag 2: active, memidx, expr, bytes_vec
//! Anything else (unknown flags, future proposals): bail on the whole
//! section to avoid corruption.

use crate::leb128;
use crate::module::{self, WasmModule};

/// MutModule-style: modify only the data section payload in place.
pub fn apply_mut(m: &mut crate::mut_module::MutModule<'_>) {
    let Some(sec_idx) = m.find_section(module::SECTION_DATA) else { return };
    let payload = m.section_payload(sec_idx);
    let Some(new_payload) = pack(payload) else { return };
    if new_payload.len() == payload.len() { return; }
    m.set_section_payload(sec_idx, new_payload);
}

pub fn apply(module: &WasmModule<'_>) -> Vec<u8> {
    let data = module.data();
    let Some(sec_idx) = module.sections().iter().position(|s| s.id == module::SECTION_DATA)
    else {
        return data.to_vec();
    };
    let sec = &module.sections()[sec_idx];
    let payload = sec.payload.slice(data);

    let Some(new_payload) = pack(payload) else {
        return data.to_vec();
    };
    if new_payload.len() == payload.len() {
        return data.to_vec();
    }

    let mut replacements = std::collections::HashMap::new();
    replacements.insert(sec_idx, new_payload);
    crate::emit::emit_with_replacements(module, &replacements)
}

fn pack(payload: &[u8]) -> Option<Vec<u8>> {
    let (count, start) = leb128::read_u32(payload)?;
    let mut new = Vec::with_capacity(payload.len());
    leb128::write_u32(&mut new, count);
    let mut off = start;
    for _ in 0..count {
        let (flags, c) = leb128::read_u32(payload.get(off..)?)?;
        off += c;
        leb128::write_u32(&mut new, flags);
        match flags {
            0 => {
                // active, memidx 0, expr, bytes
                let expr_end = skip_const_expr(payload, off)?;
                new.extend_from_slice(&payload[off..expr_end]);
                off = expr_end;
                off = pack_bytes_vec(&mut new, payload, off)?;
            }
            1 => {
                // passive, bytes
                off = pack_bytes_vec(&mut new, payload, off)?;
            }
            2 => {
                // active, memidx, expr, bytes
                let (_, c) = leb128::read_u32(payload.get(off..)?)?;
                new.extend_from_slice(&payload[off..off + c]);
                off += c;
                let expr_end = skip_const_expr(payload, off)?;
                new.extend_from_slice(&payload[off..expr_end]);
                off = expr_end;
                off = pack_bytes_vec(&mut new, payload, off)?;
            }
            _ => return None,
        }
    }
    Some(new)
}

fn skip_const_expr(bytes: &[u8], mut off: usize) -> Option<usize> {
    while off < bytes.len() {
        let op = bytes[off];
        if op == 0x0B { return Some(off + 1); }
        let len = crate::opcode::instr_len(bytes, off)?;
        off += len;
    }
    None
}

fn pack_bytes_vec(out: &mut Vec<u8>, payload: &[u8], off: usize) -> Option<usize> {
    let (n, c) = leb128::read_u32(payload.get(off..)?)?;
    let start = off + c;
    let end = start + n as usize;
    if end > payload.len() { return None; }
    let original = &payload[start..end];
    // Find the length with trailing zeros stripped.
    let new_len = original.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
    leb128::write_u32(out, new_len as u32);
    out.extend_from_slice(&original[..new_len]);
    Some(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_trailing_zeros() {
        // Data section: 1 segment, passive, bytes = [1, 2, 0, 0, 0]
        // Expected: bytes = [1, 2]
        let mut payload = Vec::new();
        leb128::write_u32(&mut payload, 1); // count
        leb128::write_u32(&mut payload, 1); // flags: passive
        leb128::write_u32(&mut payload, 5); // bytes len
        payload.extend_from_slice(&[1, 2, 0, 0, 0]);

        let new = pack(&payload).unwrap();
        // Decode: count, flag, len, bytes
        let (count, mut off) = leb128::read_u32(&new).unwrap();
        assert_eq!(count, 1);
        let (flags, c) = leb128::read_u32(&new[off..]).unwrap();
        assert_eq!(flags, 1);
        off += c;
        let (n, c) = leb128::read_u32(&new[off..]).unwrap();
        assert_eq!(n, 2);
        off += c;
        assert_eq!(&new[off..off + 2], &[1, 2]);
    }

    #[test]
    fn all_zero_becomes_empty() {
        let mut payload = Vec::new();
        leb128::write_u32(&mut payload, 1);
        leb128::write_u32(&mut payload, 1);
        leb128::write_u32(&mut payload, 4);
        payload.extend_from_slice(&[0, 0, 0, 0]);
        let new = pack(&payload).unwrap();
        let (_, mut off) = leb128::read_u32(&new).unwrap();
        let (_, c) = leb128::read_u32(&new[off..]).unwrap();
        off += c;
        let (n, _) = leb128::read_u32(&new[off..]).unwrap();
        assert_eq!(n, 0);
    }
}
