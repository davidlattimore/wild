//! Instruction-level WASM decoder shared by passes.
//!
//! Tight over byte-scanning hacks: every `walk` hit is a real instruction
//! boundary, every `instr_len` returns the exact number of bytes for that
//! instruction (including immediates). Returns `None` for opcodes in
//! proposals we don't yet handle — callers must treat that as "bail".

use crate::leb128;

// Opcodes with function-index immediates we may want to rewrite.
pub const OP_CALL: u8 = 0x10;
pub const OP_REF_FUNC: u8 = 0xD2;
pub const OP_I32_CONST: u8 = 0x41;

/// Skip past the locals vector at the start of a function body. Returns
/// the byte offset of the first instruction, or None on malformed input.
/// Read a valtype at `bytes[off]` and return its total byte length.
/// Numeric (i32/i64/f32/f64/v128): 1 byte. Simple reftypes (funcref 0x70,
/// externref 0x6F, anyref 0x6E, etc.): 1 byte. Parametric reftypes
/// (`ref null $ht` = 0x6C, `ref $ht` = 0x6B): 1 byte prefix + heap-type LEB.
/// Returns None for anything we don't recognise — caller bails.
pub fn valtype_len(bytes: &[u8], off: usize) -> Option<usize> {
    let v = *bytes.get(off)?;
    match v {
        // Numeric: i32 0x7F, i64 0x7E, f32 0x7D, f64 0x7C, v128 0x7B.
        0x7B..=0x7F => Some(1),
        // Simple reftypes that are unambiguously 1-byte across all spec
        // revisions: funcref 0x70, externref 0x6F.
        0x6F | 0x70 => Some(1),
        // Everything else — GC drafts, parametric reftypes, newer
        // proposals — has encoding differences between spec revisions and
        // toolchain versions. Bail rather than misparse.
        _ => None,
    }
}

pub fn skip_locals(body: &[u8]) -> Option<usize> {
    let (count, mut off) = leb128::read_u32(body)?;
    for _ in 0..count {
        let (_, c) = leb128::read_u32(body.get(off..)?)?;
        off += c;
        off += valtype_len(body, off)?;
    }
    Some(off)
}

/// Return the length of the instruction at `pos`, including opcode + immediates.
/// `None` means "we don't know how to decode this opcode" — callers should bail.
pub fn instr_len(body: &[u8], pos: usize) -> Option<usize> {
    let op = *body.get(pos)?;
    let rest = body.get(pos + 1..)?;
    let imm = match op {
        // zero-immediate
        0x00 | 0x01 | 0x05 | 0x0B | 0x0F | 0x1A | 0x1B | 0x45..=0xC4 | 0xD1 | 0xD3 | 0xD4 => 0, /* ref.eq, ref.as_non_null */
        // blocktype (signed LEB s33; we over-read as u32 — only the length matters)
        0x02 | 0x03 | 0x04 => leb128::read_u32(rest)?.1,
        // single u32 LEB
        0x0C | 0x0D | 0x10 | 0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0xD2 | 0xD5
        | 0xD6 => leb128::read_u32(rest)?.1, // br_on_null / non_null
        // br_table: vec<labelidx> + default
        0x0E => {
            let (n, mut c) = leb128::read_u32(rest)?;
            for _ in 0..=n {
                c += leb128::read_u32(rest.get(c..)?)?.1;
            }
            c
        }
        // call_indirect: typeidx + tableidx
        0x11 => {
            let (_, c1) = leb128::read_u32(rest)?;
            let (_, c2) = leb128::read_u32(rest.get(c1..)?)?;
            c1 + c2
        }
        // select-with-types: vec<valtype>.
        0x1C => {
            let (n, c) = leb128::read_u32(rest)?;
            let mut total = c;
            for _ in 0..n {
                total += valtype_len(rest, total)?;
            }
            total
        }
        // memarg for load/store. Base form is align:u32 offset:u32.
        // Multi-memory proposal: if bit 6 of align is set, a memidx:u32
        // LEB appears between align and offset.
        0x28..=0x3E => {
            let (align, c1) = leb128::read_u32(rest)?;
            let mut total = c1;
            if align & 0x40 != 0 {
                let (_, cm) = leb128::read_u32(rest.get(total..)?)?;
                total += cm;
            }
            let (_, c2) = leb128::read_u32(rest.get(total..)?)?;
            total + c2
        }
        // memory.size / memory.grow — 1 byte memidx
        0x3F | 0x40 => 1,
        // const opcodes — i32/i64 are sleb128; use skip_len so
        // multi-byte encodings that don't fit in u32 still parse.
        0x41 | 0x42 => leb128::skip_len(rest)?,
        0x43 => 4, // f32
        0x44 => 8, // f64
        // ref.null: heaptype LEB
        0xD0 => leb128::read_u32(rest)?.1,
        // Prefix 0xFC — saturating truncation (0x00..=0x07, no imm),
        // bulk memory / table ops (0x08..=0x11, varying imm). Sub-opcode
        // is a u32 LEB per spec; in practice all are single bytes.
        0xFC => {
            let (sub, c) = leb128::read_u32(rest)?;
            let after_sub = rest.get(c..)?;
            let extra = match sub {
                0x00..=0x07 => 0,
                0x08 => {
                    // memory.init: dataidx + memidx
                    let (_, c1) = leb128::read_u32(after_sub)?;
                    c1 + 1
                }
                0x09 => leb128::read_u32(after_sub)?.1, // data.drop
                0x0A => {
                    // memory.copy: 2 memidx LEBs
                    let (_, c1) = leb128::read_u32(after_sub)?;
                    let (_, c2) = leb128::read_u32(after_sub.get(c1..)?)?;
                    c1 + c2
                }
                0x0B => leb128::read_u32(after_sub)?.1, // memory.fill: memidx LEB
                0x0C => {
                    // table.init: elemidx + tableidx
                    let (_, c1) = leb128::read_u32(after_sub)?;
                    let (_, c2) = leb128::read_u32(after_sub.get(c1..)?)?;
                    c1 + c2
                }
                0x0D => leb128::read_u32(after_sub)?.1, // elem.drop
                0x0E => {
                    // table.copy: 2 tableidx
                    let (_, c1) = leb128::read_u32(after_sub)?;
                    let (_, c2) = leb128::read_u32(after_sub.get(c1..)?)?;
                    c1 + c2
                }
                0x0F..=0x11 => leb128::read_u32(after_sub)?.1, // table.grow/size/fill
                _ => return None,
            };
            c + extra
        }
        // Prefix 0xFB — GC proposal. Cover the canonical sub-opcode set
        // (0x00..=0x1E); bail on later additions (shared / descriptor /
        // atomic variants still in flight).
        0xFB => {
            let (sub, c) = leb128::read_u32(rest)?;
            let after_sub = rest.get(c..)?;
            let extra = match sub {
                // single typeidx
                0x00 | 0x01 | 0x06 | 0x07 | 0x0B | 0x0C | 0x0D | 0x0E | 0x10 => {
                    leb128::read_u32(after_sub)?.1
                }
                // typeidx + second LEB (fieldidx / dataidx / elemidx / typeidx / N)
                0x02 | 0x03 | 0x04 | 0x05 | 0x08 | 0x09 | 0x0A | 0x11 | 0x12 | 0x13 => {
                    let (_, c1) = leb128::read_u32(after_sub)?;
                    let (_, c2) = leb128::read_u32(after_sub.get(c1..)?)?;
                    c1 + c2
                }
                // array.len — no immediate
                0x0F => 0,
                // ref.test / ref.cast variants — heap-type LEB
                0x14 | 0x15 | 0x16 | 0x17 => leb128::read_u32(after_sub)?.1,
                // br_on_cast / br_on_cast_fail: flags byte + labelidx + 2 heap-types
                0x18 | 0x19 => {
                    // flags (1 byte)
                    let mut t = 1;
                    // labelidx
                    let (_, cl) = leb128::read_u32(after_sub.get(t..)?)?;
                    t += cl;
                    // ht1
                    let (_, ch1) = leb128::read_u32(after_sub.get(t..)?)?;
                    t += ch1;
                    // ht2
                    let (_, ch2) = leb128::read_u32(after_sub.get(t..)?)?;
                    t + ch2
                }
                // any.convert_extern / extern.convert_any / ref.i31 /
                // i31.get_s / i31.get_u — no immediates.
                0x1A..=0x1E => 0,
                _ => return None,
            };
            c + extra
        }
        // SIMD / atomics / EH — still too broad to handle safely.
        0xFD | 0xFE | 0x06 | 0x07 | 0x08 | 0x09 | 0x18 | 0x1F => return None,
        _ => return None,
    };
    Some(1 + imm)
}

/// Walk instructions in `body` starting at `start`, collecting (offset, length) pairs.
/// Returns None if any opcode can't be decoded.
pub fn walk(body: &[u8], start: usize) -> Option<Vec<(usize, usize)>> {
    let mut iter = InstrIter::new(body, start);
    let mut out = Vec::new();
    for item in &mut iter {
        out.push(item);
    }
    if iter.failed() { None } else { Some(out) }
}

/// Zero-allocation instruction iterator. Yields `(offset, length)` pairs.
/// On decoding failure, iteration stops and `failed()` returns true — the
/// caller must check this before trusting the partial result.
pub struct InstrIter<'a> {
    body: &'a [u8],
    pos: usize,
    failed: bool,
}

impl<'a> InstrIter<'a> {
    #[inline]
    pub fn new(body: &'a [u8], start: usize) -> Self {
        Self {
            body,
            pos: start,
            failed: false,
        }
    }

    /// After iteration ends, `true` if the walker bailed on an unknown opcode.
    #[inline]
    pub fn failed(&self) -> bool {
        self.failed
    }
}

impl<'a> Iterator for InstrIter<'a> {
    type Item = (usize, usize);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.pos >= self.body.len() {
            return None;
        }
        match instr_len(self.body, self.pos) {
            Some(n) => {
                let out = (self.pos, n);
                self.pos += n;
                Some(out)
            }
            None => {
                self.failed = true;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_simple() {
        // [0 locals, i32.const 5, i32.const 7, i32.add, drop, end]
        let body = [0, 0x41, 5, 0x41, 7, 0x6A, 0x1A, 0x0B];
        let start = skip_locals(&body).unwrap();
        assert_eq!(start, 1);
        let instrs = walk(&body, start).unwrap();
        let opcodes: Vec<u8> = instrs.iter().map(|&(p, _)| body[p]).collect();
        assert_eq!(opcodes, vec![0x41, 0x41, 0x6A, 0x1A, 0x0B]);
    }

    #[test]
    fn walk_bails_on_simd() {
        // [0 locals, 0xFD (SIMD prefix), …]
        let body = [0, 0xFD, 0, 0x0B];
        let start = skip_locals(&body).unwrap();
        assert!(walk(&body, start).is_none());
    }

    /// Regression: `i64.const`'s sleb128 value can run 9–10 bytes, which
    /// exceeds the 5-byte range `read_u32` is willing to read. Before
    /// switching to `leb128::skip_len`, `instr_len` returned `None` on
    /// every large-value `i64.const` — silently breaking every pass that
    /// used `InstrIter` on bodies containing such constants.
    #[test]
    fn instr_len_handles_max_i64_const() {
        // i64.const with a 9-byte sleb (an actual encoding from a
        // wasm-smith fuzz failure).
        let body = [0x42, 0x88, 0xef, 0x99, 0xab, 0xc5, 0xe8, 0x8c, 0x91, 0x11];
        assert_eq!(instr_len(&body, 0), Some(10));
    }
}
