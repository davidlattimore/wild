//! Dead-store elimination for globals.
//!
//! Plan C / M8.a. With `LinkerHints::global_is_read(g) == false` we
//! can replace `global.set g` with `drop` — same stack effect (both
//! pop one value), at least one byte saved per write. A companion
//! pass that removes the global *definition* (and renumbers the
//! global index space everywhere) is M8 follow-up work; this pass
//! cuts only the writes, keeping the global slot intact.
//!
//! No-hints mode: the pass is a no-op. Standalone wilt has no closed-
//! world view of who reads which global.

use crate::leb128;
use crate::linker_hints::LinkerHints;
use crate::mut_module::MutModule;
use crate::opcode::{self, InstrIter};

const OP_DROP: u8 = 0x1A;
const OP_GLOBAL_SET: u8 = 0x24;

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
    for (i, b) in updates { m.set_body(i, b); }
}

fn rewrite_body(body: &[u8], hints: &dyn LinkerHints) -> Option<Vec<u8>> {
    let start = opcode::skip_locals(body)?;
    let mut iter = InstrIter::new(body, start);
    let mut edits: Vec<(usize, usize)> = Vec::new();
    while let Some((p, len)) = iter.next() {
        if body[p] != OP_GLOBAL_SET { continue; }
        let Some((g, _)) = leb128::read_u32(&body[p + 1..]) else { continue };
        if hints.global_is_read(g) { continue; }
        edits.push((p, len));
    }
    if iter.failed() { return None; }
    if edits.is_empty() { return None; }

    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for (p, len) in &edits {
        out.extend_from_slice(&body[cursor..*p]);
        out.push(OP_DROP);
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
    fn replaces_dead_global_set_with_drop() {
        // body: 0 locals, i32.const 5, global.set 0, end
        let body = [0, 0x41, 5, 0x24, 0, 0x0B];
        let mut h = FixedHints::default();
        h.unread_globals.insert(0);
        let out = rewrite_body(&body, &h).unwrap();
        // Expect: 0 locals, i32.const 5, drop, end
        assert_eq!(out, vec![0, 0x41, 5, 0x1A, 0x0B]);
    }

    #[test]
    fn leaves_alone_when_global_is_read() {
        let body = [0, 0x41, 5, 0x24, 0, 0x0B];
        let h = FixedHints::default();      // default: globals are read
        assert!(rewrite_body(&body, &h).is_none());
    }

    #[test]
    fn handles_multiple_writes_to_same_dead_global() {
        // Two writes to global 0; both should become drops.
        let body = [0, 0x41, 5, 0x24, 0, 0x41, 7, 0x24, 0, 0x0B];
        let mut h = FixedHints::default();
        h.unread_globals.insert(0);
        let out = rewrite_body(&body, &h).unwrap();
        assert_eq!(out, vec![0, 0x41, 5, 0x1A, 0x41, 7, 0x1A, 0x0B]);
    }

    #[test]
    fn discriminates_between_globals() {
        // global 0 dead, global 1 alive.
        let body = [0,
            0x41, 5, 0x24, 0,    // global.set 0 — dead → drop
            0x41, 7, 0x24, 1,    // global.set 1 — alive
            0x0B];
        let mut h = FixedHints::default();
        h.unread_globals.insert(0);
        let out = rewrite_body(&body, &h).unwrap();
        assert_eq!(out, vec![0, 0x41, 5, 0x1A, 0x41, 7, 0x24, 1, 0x0B]);
    }
}
