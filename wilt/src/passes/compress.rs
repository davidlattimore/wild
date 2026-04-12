// LEB128 compression pass.
//
// In linked WASM output, function bodies still contain 5-byte padded
// LEB128 from the input objects (used for relocation patching). This
// pass compresses them to minimal encoding, matching wasm-ld's output.
//
// Compressed opcodes:
//   call        (0x10) — funcidx immediate
//   call_indirect (0x11) — typeidx + tableidx immediates
//   br          (0x0C) — labelidx
//   br_if       (0x0D) — labelidx
//   br_table    (0x0E) — vec(labelidx) + labelidx
//   local.get/set/tee (0x20-0x22) — localidx
//   global.get/set (0x23-0x24) — globalidx
//   memory.size/grow (0x3F-0x40) — memidx
//   block/loop/if (0x02-0x04) — blocktype (may be type index)
//   All memory load/store ops (0x28-0x3E) — align + offset

use crate::leb128;
use crate::module::{self, WasmModule};

/// Compress a single function body by replacing padded LEB128 with compact.
/// Returns None if no compression was needed.
fn compress_body(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut pos = 0;
    let mut compressed = false;

    // Skip local declarations.
    if let Some((local_count, c)) = leb128::read_u32(&body[pos..]) {
        // Copy local count as compact LEB.
        let old_size = c;
        let new_size = leb128::u32_size(local_count);
        if old_size != new_size {
            compressed = true;
        }
        leb128::write_u32(&mut out, local_count);
        pos += c;
        for _ in 0..local_count {
            if let Some((count, c)) = leb128::read_u32(&body[pos..]) {
                let old_s = c;
                let new_s = leb128::u32_size(count);
                if old_s != new_s { compressed = true; }
                leb128::write_u32(&mut out, count);
                pos += c;
            }
            if pos < body.len() {
                out.push(body[pos]); // valtype
                pos += 1;
            }
        }
    }

    while pos < body.len() {
        let opcode = body[pos];
        out.push(opcode);
        pos += 1;

        match opcode {
            // call funcidx
            0x10 => {
                compress_leb(&body, &mut pos, &mut out, &mut compressed);
            }
            // call_indirect typeidx tableidx
            0x11 => {
                compress_leb(&body, &mut pos, &mut out, &mut compressed);
                compress_leb(&body, &mut pos, &mut out, &mut compressed);
            }
            // block/loop/if — blocktype
            0x02 | 0x03 | 0x04 => {
                if pos < body.len() {
                    if body[pos] == 0x40 {
                        // void
                        out.push(body[pos]);
                        pos += 1;
                    } else if body[pos] < 0x80 && body[pos] >= 0x60 {
                        // value type (single byte, 0x7F..0x60 range)
                        out.push(body[pos]);
                        pos += 1;
                    } else {
                        // Type index as signed LEB128 — compress it.
                        compress_sleb(&body, &mut pos, &mut out, &mut compressed);
                    }
                }
            }
            // br, br_if
            0x0C | 0x0D => {
                compress_leb(&body, &mut pos, &mut out, &mut compressed);
            }
            // br_table
            0x0E => {
                if let Some((count, c)) = leb128::read_u32(&body[pos..]) {
                    let old_s = c;
                    let new_s = leb128::u32_size(count);
                    if old_s != new_s { compressed = true; }
                    leb128::write_u32(&mut out, count);
                    pos += c;
                    for _ in 0..=count {
                        compress_leb(&body, &mut pos, &mut out, &mut compressed);
                    }
                }
            }
            // local.get/set/tee, global.get/set
            0x20..=0x24 => {
                compress_leb(&body, &mut pos, &mut out, &mut compressed);
            }
            // Memory load/store: align + offset
            0x28..=0x3E => {
                compress_leb(&body, &mut pos, &mut out, &mut compressed);
                compress_leb(&body, &mut pos, &mut out, &mut compressed);
            }
            // memory.size, memory.grow
            0x3F | 0x40 => {
                compress_leb(&body, &mut pos, &mut out, &mut compressed);
            }
            // i32.const (signed LEB128)
            0x41 => {
                compress_sleb(&body, &mut pos, &mut out, &mut compressed);
            }
            // i64.const (signed LEB128)
            0x42 => {
                compress_sleb64(&body, &mut pos, &mut out, &mut compressed);
            }
            // f32.const
            0x43 => {
                if pos + 4 <= body.len() {
                    out.extend_from_slice(&body[pos..pos + 4]);
                    pos += 4;
                }
            }
            // f64.const
            0x44 => {
                if pos + 8 <= body.len() {
                    out.extend_from_slice(&body[pos..pos + 8]);
                    pos += 8;
                }
            }
            // 0xFC prefix (misc ops): saturating truncations + bulk memory.
            // Read the sub-opcode first (so we know how many further
            // immediates follow), then compress the LEB-encoded operands.
            0xFC => {
                let Some((sub, _)) = leb128::read_u32(&body[pos..]) else {
                    return None;
                };
                compress_leb(&body, &mut pos, &mut out, &mut compressed);
                let leb_immediates: usize = match sub {
                    // i{32,64}.trunc_sat_f{32,64}_{s,u}.
                    0x00..=0x07 => 0,
                    // memory.init dataidx memidx
                    0x08 => 2,
                    // data.drop dataidx
                    0x09 => 1,
                    // memory.copy dst src
                    0x0A => 2,
                    // memory.fill memidx
                    0x0B => 1,
                    // table.init elemidx tableidx
                    0x0C => 2,
                    // elem.drop elemidx
                    0x0D => 1,
                    // table.copy dst src
                    0x0E => 2,
                    // table.grow / table.size / table.fill: tableidx
                    0x0F | 0x10 | 0x11 => 1,
                    // Unknown sub-opcode — refuse to compress so we don't
                    // silently corrupt the body.
                    _ => return None,
                };
                for _ in 0..leb_immediates {
                    compress_leb(&body, &mut pos, &mut out, &mut compressed);
                }
            }
            // SIMD (0xFD) and atomics (0xFE) have wildly varying operand
            // shapes; compressing them safely is a separate project, so
            // any body carrying one is left uncompressed.
            0xFD | 0xFE => return None,
            // All other opcodes: no immediates to compress
            _ => {}
        }
    }

    if compressed { Some(out) } else { None }
}

/// Read a LEB128, write it back in compact form.
fn compress_leb(body: &[u8], pos: &mut usize, out: &mut Vec<u8>, changed: &mut bool) {
    if let Some((val, c)) = leb128::read_u32(&body[*pos..]) {
        let new_size = leb128::u32_size(val);
        if c != new_size {
            *changed = true;
        }
        leb128::write_u32(out, val);
        *pos += c;
    }
}

/// Read a signed LEB128 i32, write it back in compact form.
fn compress_sleb(body: &[u8], pos: &mut usize, out: &mut Vec<u8>, changed: &mut bool) {
    if let Some((val, c)) = read_sleb128_i32(&body[*pos..]) {
        let old_size = c;
        let mut tmp = Vec::new();
        write_sleb128_i32(&mut tmp, val);
        if old_size != tmp.len() {
            *changed = true;
        }
        out.extend_from_slice(&tmp);
        *pos += c;
    }
}

/// Read a signed LEB128 i64, write it back in compact form.
fn compress_sleb64(body: &[u8], pos: &mut usize, out: &mut Vec<u8>, changed: &mut bool) {
    if let Some((val, c)) = read_sleb128_i64(&body[*pos..]) {
        let old_size = c;
        let mut tmp = Vec::new();
        write_sleb128_i64(&mut tmp, val);
        if old_size != tmp.len() {
            *changed = true;
        }
        out.extend_from_slice(&tmp);
        *pos += c;
    }
}

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
        if shift >= 35 { return None; }
    }
    None
}

fn write_sleb128_i32(out: &mut Vec<u8>, mut value: i32) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if !done { byte |= 0x80; }
        out.push(byte);
        if done { break; }
    }
}

fn read_sleb128_i64(data: &[u8]) -> Option<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        if byte < 0x80 {
            if shift < 64 && (byte & 0x40) != 0 {
                result |= !0i64 << shift;
            }
            return Some((result, i + 1));
        }
        if shift >= 70 { return None; }
    }
    None
}

fn write_sleb128_i64(out: &mut Vec<u8>, mut value: i64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if !done { byte |= 0x80; }
        out.push(byte);
        if done { break; }
    }
}

/// Apply LEB128 compression to all function bodies in the module.
pub fn apply(module: &WasmModule<'_>) -> Vec<u8> {
    let data = module.data();
    let Some(code_sec_idx) = module.sections().iter().position(|s| s.id == module::SECTION_CODE) else {
        return data.to_vec();
    };

    let code_sec = &module.sections()[code_sec_idx];
    let code_payload = code_sec.payload.slice(data);
    let Some((func_count, mut off)) = leb128::read_u32(code_payload) else {
        return data.to_vec();
    };

    let mut replacements: Vec<Option<Vec<u8>>> = Vec::new();
    let mut any_compressed = false;

    for _ in 0..func_count {
        let Some((body_size, c)) = leb128::read_u32(&code_payload[off..]) else { break; };
        off += c;
        let body = &code_payload[off..off + body_size as usize];

        if let Some(compressed) = compress_body(body) {
            any_compressed = true;
            replacements.push(Some(compressed));
        } else {
            replacements.push(None);
        }

        off += body_size as usize;
    }

    if !any_compressed {
        return data.to_vec();
    }

    // Rebuild code section with compressed bodies.
    let mut new_code = Vec::new();
    leb128::write_u32(&mut new_code, func_count);

    let mut off2 = leb128::u32_size(func_count);
    for replacement in &replacements {
        let Some((body_size, c)) = leb128::read_u32(&code_payload[off2..]) else { break; };
        off2 += c;
        let original_body = &code_payload[off2..off2 + body_size as usize];

        match replacement {
            Some(new_body) => {
                leb128::write_u32(&mut new_code, new_body.len() as u32);
                new_code.extend_from_slice(new_body);
            }
            None => {
                leb128::write_u32(&mut new_code, body_size);
                new_code.extend_from_slice(original_body);
            }
        }
        off2 += body_size as usize;
    }

    let mut section_replacements = std::collections::HashMap::new();
    section_replacements.insert(code_sec_idx, new_code);
    crate::emit::emit_with_replacements(module, &section_replacements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_padded_call() {
        // call with 5-byte padded LEB128 for index 1
        let body = vec![
            0x00, // 0 locals
            0x10, 0x81, 0x80, 0x80, 0x80, 0x00, // call 1 (padded)
            0x1A, // drop
            0x0B, // end
        ];
        let compressed = compress_body(&body).expect("should compress");
        assert_eq!(compressed, vec![
            0x00, // 0 locals
            0x10, 0x01, // call 1 (compact)
            0x1A, // drop
            0x0B, // end
        ]);
    }

    #[test]
    fn no_compress_already_compact() {
        let body = vec![
            0x00, // 0 locals
            0x10, 0x01, // call 1 (already compact)
            0x0B, // end
        ];
        assert!(compress_body(&body).is_none(), "already compact");
    }

    #[test]
    fn compress_bulk_memory_copy() {
        // memory.copy 0 0 with both memory indices padded to 5 bytes.
        // Opcode sequence: 0xFC 0x0A <dst_mem> <src_mem>.
        let body = vec![
            0x00, // 0 locals
            0xFC, 0x8A, 0x80, 0x80, 0x80, 0x00, // 0xFC sub=0x0A (padded)
            0x80, 0x80, 0x80, 0x80, 0x00,       // dst memidx = 0 (padded)
            0x80, 0x80, 0x80, 0x80, 0x00,       // src memidx = 0 (padded)
            0x0B, // end
        ];
        let compressed = compress_body(&body).expect("should compress");
        assert_eq!(
            compressed,
            vec![
                0x00,       // 0 locals
                0xFC, 0x0A, // memory.copy (compact sub-opcode)
                0x00, 0x00, // dst=0, src=0 (compact)
                0x0B,
            ]
        );
    }

    #[test]
    fn compress_bulk_memory_init() {
        // memory.init dataidx=3 memidx=0, both padded.
        let body = vec![
            0x00, // 0 locals
            0xFC, 0x88, 0x80, 0x80, 0x80, 0x00, // 0xFC sub=0x08 (padded)
            0x83, 0x80, 0x80, 0x80, 0x00,       // dataidx=3 (padded)
            0x80, 0x80, 0x80, 0x80, 0x00,       // memidx=0 (padded)
            0x0B,
        ];
        let compressed = compress_body(&body).expect("should compress");
        assert_eq!(
            compressed,
            vec![0x00, 0xFC, 0x08, 0x03, 0x00, 0x0B]
        );
    }

    #[test]
    fn bulk_memory_trunc_sat_has_no_immediates() {
        // i32.trunc_sat_f32_s (0xFC 0x00) — no extra operands.
        let body = vec![
            0x00,
            0xFC, 0x80, 0x80, 0x80, 0x80, 0x00, // 0xFC sub=0x00 (padded)
            0x0B,
        ];
        let compressed = compress_body(&body).expect("should compress");
        assert_eq!(compressed, vec![0x00, 0xFC, 0x00, 0x0B]);
    }

    #[test]
    fn unknown_bulk_sub_opcode_refuses_to_compress() {
        // Made-up 0xFC sub-opcode 0x42 — walker must bail rather than
        // silently mis-compress the remainder of the body.
        let body = vec![
            0x00,
            0xFC, 0x42,
            0x0B,
        ];
        assert!(compress_body(&body).is_none());
    }

    #[test]
    fn simd_and_atomics_bodies_are_left_alone() {
        // A single SIMD opcode (0xFD) — refuse to compress the body.
        let body = vec![0x00, 0xFD, 0x00, 0x0B];
        assert!(compress_body(&body).is_none());
        // Same for atomics (0xFE).
        let body = vec![0x00, 0xFE, 0x00, 0x0B];
        assert!(compress_body(&body).is_none());
    }

    #[test]
    fn compress_memory_load() {
        // i32.load with padded alignment and offset
        let body = vec![
            0x00, // 0 locals
            0x28, 0x82, 0x80, 0x80, 0x80, 0x00, // align=2 (padded)
                  0x80, 0x80, 0x80, 0x80, 0x00, // offset=0 (padded)
            0x0B,
        ];
        let compressed = compress_body(&body).expect("should compress");
        assert_eq!(compressed, vec![
            0x00, // 0 locals
            0x28, 0x02, 0x00, // align=2, offset=0 (compact)
            0x0B,
        ]);
    }
}
