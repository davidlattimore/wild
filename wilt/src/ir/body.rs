//! Per-body IR — instruction index built lazily from `&[u8]`.
//!
//! Plan C / M3: the foundation for passes that need O(1) instruction
//! addressing or cross-instruction analysis (use-def, CFG basic-block
//! splitting). InstrIter is fine for sequential scans; this struct is
//! for passes that can't be expressed sequentially.
//!
//! Zero-copy: borrows the body slice. `Instr` carries `(op, start, len)`
//! — no decoded immediates. Passes that need immediates call
//! `imm_u32(i)`, which decodes lazily.
//!
//! No caching on `MutModule` yet — each pass builds its own. Caching
//! would matter only if multiple passes within one fixpoint iteration
//! both want IR for the same bodies. M4 will add caching if profiling
//! says it's worth the API complexity.

use crate::leb128;
use crate::opcode::InstrIter;
use crate::opcode::{self};

/// One decoded-into-an-array instruction. Compact (12 bytes); densely
/// packed into a `Vec`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Instr {
    pub op: u8,
    /// Byte offset of this instruction's opcode within the body.
    pub start: u32,
    /// Total bytes (opcode + immediates).
    pub len: u32,
}

impl Instr {
    /// Byte range `[start, start+len)`.
    #[inline]
    pub fn end(&self) -> u32 {
        self.start + self.len
    }
}

/// Per-function-body instruction index. Borrows the body slice.
pub struct BodyIr<'a> {
    body: &'a [u8],
    instrs: Vec<Instr>,
    instrs_start: usize,
}

impl<'a> BodyIr<'a> {
    /// Build from a function body (locals header + instructions).
    /// Returns `None` if `skip_locals` or `InstrIter` fails — caller's
    /// pass should bail to byte-patch fallback.
    pub fn new(body: &'a [u8]) -> Option<Self> {
        let instrs_start = opcode::skip_locals(body)?;
        let mut instrs = Vec::new();
        let mut iter = InstrIter::new(body, instrs_start);
        for (p, l) in &mut iter {
            instrs.push(Instr {
                op: body[p],
                start: p as u32,
                len: l as u32,
            });
        }
        if iter.failed() {
            return None;
        }
        Some(Self {
            body,
            instrs,
            instrs_start,
        })
    }

    /// The full body bytes (locals header + instructions).
    #[inline]
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    /// All instructions in order.
    #[inline]
    pub fn instrs(&self) -> &[Instr] {
        &self.instrs
    }

    /// Byte offset of the first instruction (i.e. just past the locals
    /// header). Useful for callers re-emitting bodies that want to copy
    /// the locals header verbatim.
    #[inline]
    pub fn instrs_start(&self) -> usize {
        self.instrs_start
    }

    /// Bytes of instruction `i`, including opcode + immediates.
    #[inline]
    pub fn instr_bytes(&self, i: usize) -> &'a [u8] {
        let it = &self.instrs[i];
        &self.body[it.start as usize..it.end() as usize]
    }

    /// Decode the first u32-LEB immediate at instruction `i`, if the
    /// opcode is wider than 1 byte. Returns `None` for zero-immediate
    /// opcodes, or when the LEB doesn't fit in `u32` (use `skip_len`-style
    /// helpers if you only need length).
    ///
    /// Note: this is correct only for opcodes whose first immediate IS a
    /// u32 LEB (call N, local.get N, br L, blocktype-as-typeidx, etc.).
    /// For memarg loads/stores it returns the `align` field. For const
    /// opcodes it returns the LEB value if fits, else `None`.
    pub fn imm_u32(&self, i: usize) -> Option<u32> {
        let it = &self.instrs[i];
        if it.len <= 1 {
            return None;
        }
        leb128::read_u32(&self.body[(it.start + 1) as usize..]).map(|(v, _)| v)
    }

    /// Locate the instruction (if any) whose byte range contains `byte_off`.
    /// Linear scan; callers doing many lookups should build a side index.
    pub fn instr_at_byte(&self, byte_off: usize) -> Option<usize> {
        self.instrs
            .iter()
            .position(|it| (it.start as usize) <= byte_off && byte_off < (it.end() as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_simple_body() {
        // [0 locals, i32.const 5, i32.const 7, i32.add, drop, end]
        let body = [0u8, 0x41, 5, 0x41, 7, 0x6A, 0x1A, 0x0B];
        let ir = BodyIr::new(&body).unwrap();
        assert_eq!(ir.instrs_start(), 1);
        let ops: Vec<u8> = ir.instrs().iter().map(|i| i.op).collect();
        assert_eq!(ops, vec![0x41, 0x41, 0x6A, 0x1A, 0x0B]);
        // Instruction lengths.
        let lens: Vec<u32> = ir.instrs().iter().map(|i| i.len).collect();
        assert_eq!(lens, vec![2, 2, 1, 1, 1]);
    }

    #[test]
    fn imm_u32_decodes_lebs() {
        // local.get 42, then end.
        let body = [0u8, 0x20, 42, 0x0B];
        let ir = BodyIr::new(&body).unwrap();
        assert_eq!(ir.imm_u32(0), Some(42));
        assert_eq!(ir.imm_u32(1), None); // end has no immediate
    }

    #[test]
    fn handles_large_i64_const_via_skip_len() {
        // The LEB-decoder regression case: 9-byte i64.const sleb.
        let body = [
            0u8, 0x42, 0x88, 0xef, 0x99, 0xab, 0xc5, 0xe8, 0x8c, 0x91, 0x11, 0x0B,
        ];
        let ir = BodyIr::new(&body).unwrap();
        assert_eq!(ir.instrs().len(), 2);
        assert_eq!(ir.instrs()[0].len, 10); // opcode + 9 LEB bytes
        // imm_u32 returns None — value doesn't fit in u32.
        assert_eq!(ir.imm_u32(0), None);
    }

    #[test]
    fn bails_on_simd() {
        // SIMD opcode 0xFD — instr_len returns None → BodyIr::new returns None.
        let body = [0u8, 0xFD, 0x7C, 0x0B];
        assert!(BodyIr::new(&body).is_none());
    }

    #[test]
    fn instr_at_byte_finds_owner() {
        let body = [0u8, 0x41, 5, 0x41, 7, 0x6A, 0x0B];
        let ir = BodyIr::new(&body).unwrap();
        assert_eq!(ir.instr_at_byte(1), Some(0)); // first const opcode
        assert_eq!(ir.instr_at_byte(2), Some(0)); // its LEB
        assert_eq!(ir.instr_at_byte(3), Some(1)); // second const
        assert_eq!(ir.instr_at_byte(5), Some(2)); // i32.add
        assert_eq!(ir.instr_at_byte(99), None); // out of bounds
    }

    #[test]
    fn instr_bytes_round_trip() {
        let body = [0u8, 0x41, 0x88, 0x01, 0x0B]; // i32.const 136 (2-byte LEB), end
        let ir = BodyIr::new(&body).unwrap();
        assert_eq!(ir.instr_bytes(0), &[0x41, 0x88, 0x01]);
        assert_eq!(ir.instr_bytes(1), &[0x0B]);
    }
}
