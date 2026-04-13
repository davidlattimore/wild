//! Local dead-code elimination — instructions between an unconditional
//! terminator (`br`, `br_table`, `return`, `unreachable`) and the next
//! structural opcode (`block`, `loop`, `if`, `else`, `end`).
//!
//! Plan C / M8.b. The name is historical — an earlier draft used the
//! `CfgIr` reachability analysis, but our CFG doesn't yet model the
//! conditional edges of `if`/`else`, so it could mismark live BBs as
//! dead. The local pattern below is sound and catches the common case:
//! the tail after an unconditional jump.
//!
//! Soundness: after an unconditional terminator, the wasm stack becomes
//! polymorphic until the next structural marker. Any non-structural
//! instructions in between are unreachable; deleting them leaves the
//! validator with the same polymorphic-at-end shape it would have seen
//! anyway.
//!
//! Limitation: dead nested `block`/`loop`/`if` constructs aren't
//! removed — we only delete non-structural instructions. A future
//! pass with a proper if/else-aware CFG can do better.

use crate::mut_module::MutModule;
use crate::opcode::{self, InstrIter};

pub fn apply_mut(m: &mut MutModule<'_>) {
    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>)> = (0..m.num_bodies())
        .into_par_iter()
        .filter_map(|i| rewrite_body(m.body_bytes(i)).map(|b| (i, b)))
        .collect();
    for (i, b) in updates { m.set_body(i, b); }
}

fn rewrite_body(body: &[u8]) -> Option<Vec<u8>> {
    let start = opcode::skip_locals(body)?;
    let mut iter = InstrIter::new(body, start);
    let mut deletes: Vec<(usize, usize)> = Vec::new();
    let mut dead_start: Option<usize> = None;
    let mut has_gc = false;

    while let Some((p, len)) = iter.next() {
        let op = body[p];
        // GC-prefixed opcodes (0xFB) introduce sub-opcodes whose
        // structural semantics we don't fully model — `br_on_cast` /
        // `br_on_cast_fail` are conditional branches, and dropping
        // anything in their orbit can leave a real producer eliminated.
        // Bail wholesale on any body containing them.
        if op == 0xFB { has_gc = true; }
        let is_terminator = matches!(op, 0x0C | 0x0E | 0x0F | 0x00);
        let is_structural = matches!(op, 0x02 | 0x03 | 0x04 | 0x05 | 0x0B);

        if let Some(s) = dead_start {
            if is_structural {
                if s < p { deletes.push((s, p)); }
                dead_start = None;
            }
        } else if is_terminator {
            dead_start = Some(p + len);
        }
    }
    if iter.failed() || has_gc { return None; }
    if deletes.is_empty() { return None; }

    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for (s, e) in &deletes {
        out.extend_from_slice(&body[cursor..*s]);
        cursor = *e;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletes_dead_tail_after_br() {
        let body = [
            0,
            0x02, 0x40,
            0x41, 1,
            0x0C, 0,
            0x41, 2,            // dead
            0x1A,               // dead
            0x0B,
            0x0B,
        ];
        let out = rewrite_body(&body).expect("dead tail should be removed");
        assert_eq!(out, vec![
            0, 0x02, 0x40, 0x41, 1, 0x0C, 0, 0x0B, 0x0B,
        ]);
    }

    #[test]
    fn keeps_reachable_code() {
        let body = [0u8, 0x41, 1, 0x1A, 0x0B];
        assert!(rewrite_body(&body).is_none());
    }

    #[test]
    fn deletes_dead_tail_after_return() {
        let body = [0u8, 0x41, 1, 0x0F, 0x41, 2, 0x1A, 0x0B];
        let out = rewrite_body(&body).expect("dead tail should be removed");
        assert_eq!(out, vec![0u8, 0x41, 1, 0x0F, 0x0B]);
    }

    #[test]
    fn deletes_dead_tail_after_unreachable() {
        let body = [0u8, 0x00, 0x41, 99, 0x1A, 0x0B];
        let out = rewrite_body(&body).expect("dead tail should be removed");
        assert_eq!(out, vec![0u8, 0x00, 0x0B]);
    }

    #[test]
    fn br_if_does_not_make_subsequent_code_dead() {
        // br_if is conditional; tail is not unconditionally unreachable.
        let body = [
            0,
            0x02, 0x40,
            0x41, 1,
            0x0D, 0,            // br_if 0
            0x41, 2,            // STILL REACHABLE (when br_if didn't take)
            0x1A,
            0x0B,
            0x0B,
        ];
        assert!(rewrite_body(&body).is_none());
    }

    #[test]
    fn does_not_delete_structural_in_dead_region() {
        // After br, a nested block-open occurs. Local rule stops at the
        // structural opcode without touching nested structure. Anything
        // strictly before the block-open gets deleted; nested block stays.
        let body = [
            0,
            0x02, 0x40,         // outer block
            0x0C, 0,            // br 0 — terminator
            0x41, 9,            // dead
            0x02, 0x40,         // block-open — structural; reachable per local rule
            0x0B,               // end-block (inner)
            0x0B,               // end-block (outer)
            0x0B,               // end-func
        ];
        let out = rewrite_body(&body).expect("dead tail before nested block should be removed");
        // i32.const 9 deleted; nested block left alone.
        assert_eq!(out, vec![
            0,
            0x02, 0x40,
            0x0C, 0,
            0x02, 0x40,
            0x0B, 0x0B, 0x0B,
        ]);
    }
}
