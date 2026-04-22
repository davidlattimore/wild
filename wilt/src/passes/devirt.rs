//! Devirtualization of `call_indirect`.
//!
//! Plan C / M7. When `LinkerHints::table_targets(t)` reports exactly
//! one function reachable through table `t`, the `call_indirect` is
//! actually a direct call in disguise. Replace it with
//!
//!   drop          ;; consume the runtime table index — no longer needed
//!   call F        ;; the direct call to the table's only target
//!
//! Stack effect is identical (both pop the index then F's params, both
//! push F's results), so the substitution is sound provided F's type
//! matches the `call_indirect`'s declared type.
//!
//! Size: drop + call F is typically the same length as call_indirect
//! (1 + LEB + LEB → 1 + 1 + LEB). Even when neutral, the direct call
//! unlocks the inliner / DCE downstream.
//!
//! No-hint mode: the pass is a no-op. Standalone wilt has no way to
//! know a table's target set without doing whole-module reachability
//! itself, which DCE only does loosely.

use crate::leb128;
use crate::linker_hints::LinkerHints;
use crate::mut_module::MutModule;
use crate::opcode::InstrIter;
use crate::opcode::{self};

const OP_DROP: u8 = 0x1A;
const OP_CALL: u8 = 0x10;
const OP_CALL_INDIRECT: u8 = 0x11;

pub fn apply_mut(m: &mut MutModule<'_>) {
    apply_mut_with_hints(m, None)
}

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
    let start = opcode::skip_locals(body)?;
    let mut iter = InstrIter::new(body, start);
    let mut edits: Vec<(usize, usize, Vec<u8>)> = Vec::new();

    while let Some((p, len)) = iter.next() {
        if body[p] != OP_CALL_INDIRECT {
            continue;
        }
        let imm_off = p + 1;
        let (_type_idx, c1) = leb128::read_u32(&body[imm_off..])?;
        let (table_idx, _c2) = leb128::read_u32(&body[imm_off + c1..])?;

        let Some(targets) = hints.table_targets(table_idx) else {
            continue;
        };
        if targets.len() != 1 {
            continue;
        }
        let f = targets[0];

        let mut repl = Vec::with_capacity(2 + 5);
        repl.push(OP_DROP);
        repl.push(OP_CALL);
        leb128::write_u32(&mut repl, f);

        // Hint-aware passes never grow. Skip if the substitution would.
        if repl.len() > len {
            continue;
        }
        edits.push((p, len, repl));
    }
    if iter.failed() {
        return None;
    }
    if edits.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for (p, len, repl) in &edits {
        out.extend_from_slice(&body[cursor..*p]);
        out.extend_from_slice(repl);
        cursor = p + len;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linker_hints::testing::FixedHints;

    #[test]
    fn rewrites_singleton_table() {
        // body: 0 locals, i32.const 0 (table idx), call_indirect type 0 table 0, end.
        // Hints: table 0 has only target [7].
        let body = [0, 0x41, 0, 0x11, 0, 0, 0x0B];
        let mut h = FixedHints::default();
        h.tables.insert(0, vec![7]);
        let out = rewrite_body(&body, &h).expect("should devirt");
        // Expect: 0 locals, i32.const 0, drop, call 7, end.
        // Note: original `call_indirect 0 0` is 3 bytes (0x11 0x00 0x00).
        // Replacement `drop call 7` is 3 bytes (0x1A 0x10 0x07).
        assert_eq!(out, vec![0, 0x41, 0, 0x1A, 0x10, 7, 0x0B]);
    }

    #[test]
    fn leaves_alone_when_table_has_multiple_targets() {
        let body = [0, 0x41, 0, 0x11, 0, 0, 0x0B];
        let mut h = FixedHints::default();
        h.tables.insert(0, vec![5, 9]);
        assert!(rewrite_body(&body, &h).is_none());
    }

    #[test]
    fn leaves_alone_when_hint_missing_for_table() {
        let body = [0, 0x41, 0, 0x11, 0, 0, 0x0B];
        let h = FixedHints::default(); // no tables
        assert!(rewrite_body(&body, &h).is_none());
    }

    #[test]
    fn no_op_when_no_call_indirect() {
        let body = [0, 0x41, 5, 0x1A, 0x0B];
        let mut h = FixedHints::default();
        h.tables.insert(0, vec![3]);
        assert!(rewrite_body(&body, &h).is_none());
    }

    #[test]
    fn skips_when_replacement_would_grow() {
        // call_indirect with small immediates (3 bytes total). Target
        // function index 200 needs a 2-byte LEB → drop+call would be
        // 4 bytes. Skip rather than grow.
        let body = [0, 0x41, 0, 0x11, 0, 0, 0x0B];
        let mut h = FixedHints::default();
        h.tables.insert(0, vec![200]);
        assert!(rewrite_body(&body, &h).is_none());
    }
}
