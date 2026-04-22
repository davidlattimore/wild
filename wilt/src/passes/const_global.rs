//! Constant-global folding: rewrite `global.get g` into the literal
//! value when `LinkerHints::global_const(g)` resolves it.
//!
//! Only fires when the replacement is no larger than the original
//! `global.get g`. The rewrite doesn't just save bytes directly — it
//! feeds `const_prop`, `branch_threading`, and `const_fold` on the
//! next fixpoint iteration, so constants in globals cascade through
//! the rest of the pipeline.
//!
//! Standalone: `DerivedHints::from_bytes` scans the globals section
//! and returns `ConstVal` for every non-mutable `*.const` init. The
//! same trait method is what a linker supplies when it hands us an
//! already-materialised constant pool.

use crate::leb128;
use crate::linker_hints::ConstVal;
use crate::linker_hints::LinkerHints;
use crate::mut_module::MutModule;
use crate::opcode::InstrIter;
use crate::opcode::{self as opc};

const OP_GLOBAL_GET: u8 = 0x23;
const OP_I32_CONST: u8 = 0x41;
const OP_I64_CONST: u8 = 0x42;
const OP_F32_CONST: u8 = 0x43;
const OP_F64_CONST: u8 = 0x44;

pub fn apply_mut_with_hints(m: &mut MutModule<'_>, hints: Option<&dyn LinkerHints>) {
    let Some(hints) = hints else { return };
    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>)> = (0..m.num_bodies())
        .into_par_iter()
        .filter_map(|i| rewrite_body(m.body_bytes(i), hints).map(|b| (i, b)))
        .collect();
    for (i, b) in updates {
        m.set_body(i, b);
    }
}

fn rewrite_body(body: &[u8], hints: &dyn LinkerHints) -> Option<Vec<u8>> {
    let start = opc::skip_locals(body)?;
    let mut iter = InstrIter::new(body, start);
    let mut rewrites: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    while let Some((p, len)) = iter.next() {
        if body[p] != OP_GLOBAL_GET {
            continue;
        }
        let (g, _) = leb128::read_u32(&body[p + 1..])?;
        let Some(val) = hints.global_const(g) else {
            continue;
        };
        let repl = encode_const(val);
        if repl.len() > len {
            continue;
        }
        rewrites.push((p, len, repl));
    }
    if rewrites.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for (p, len, repl) in &rewrites {
        out.extend_from_slice(&body[cursor..*p]);
        out.extend_from_slice(repl);
        cursor = p + len;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

fn encode_const(v: ConstVal) -> Vec<u8> {
    let mut out = Vec::with_capacity(11);
    match v {
        ConstVal::I32(n) => {
            out.push(OP_I32_CONST);
            leb128::write_i32(&mut out, n);
        }
        ConstVal::I64(n) => {
            out.push(OP_I64_CONST);
            leb128::write_i64(&mut out, n);
        }
        ConstVal::F32(bits) => {
            out.push(OP_F32_CONST);
            out.extend_from_slice(&bits.to_le_bytes());
        }
        ConstVal::F64(bits) => {
            out.push(OP_F64_CONST);
            out.extend_from_slice(&bits.to_le_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linker_hints::testing::FixedHints;

    #[test]
    fn folds_i32_global_get() {
        // local body: global.get 0 ; drop ; end
        let body = [0u8, OP_GLOBAL_GET, 0x00, 0x1A, 0x0B];
        let mut h = FixedHints::default();
        h.global_consts.insert(0, ConstVal::I32(42));
        let out = rewrite_body(&body, &h).expect("should fold");
        // i32.const 42 encodes as [0x41, 0x2A] (1-byte sleb for 42).
        assert_eq!(out, vec![0u8, 0x41, 0x2A, 0x1A, 0x0B]);
    }

    #[test]
    fn leaves_unknown_global() {
        let body = [0u8, OP_GLOBAL_GET, 0x00, 0x1A, 0x0B];
        let h = FixedHints::default();
        assert!(rewrite_body(&body, &h).is_none());
    }

    #[test]
    fn skips_when_constant_would_grow_bytes() {
        // `global.get 0` is 2 bytes (0x23, 0x00). An i32.const large
        // enough to need 3+ sleb bytes shouldn't replace it.
        let body = [0u8, OP_GLOBAL_GET, 0x00, 0x1A, 0x0B];
        let mut h = FixedHints::default();
        h.global_consts.insert(0, ConstVal::I32(1_000_000));
        assert!(rewrite_body(&body, &h).is_none());
    }

    #[test]
    fn folds_i64_zero() {
        let body = [0u8, OP_GLOBAL_GET, 0x00, 0x1A, 0x0B];
        let mut h = FixedHints::default();
        h.global_consts.insert(0, ConstVal::I64(0));
        let out = rewrite_body(&body, &h).expect("should fold");
        // i64.const 0 = [0x42, 0x00] — exactly 2 bytes.
        assert_eq!(out, vec![0u8, 0x42, 0x00, 0x1A, 0x0B]);
    }
}
