//! Remove `br L` that is a no-op.
//!
//! Conservative-but-sound subset: `br 0` immediately followed by the
//! `end` of its enclosing construct, when
//!   (a) the enclosing construct is a `block`/`if`/`else` (not `loop`),
//!   (b) the br is in reachable code, and
//!   (c) the stack depth at the br equals `entry_depth + fallthrough_arity`
//!       of the enclosing frame.
//!
//! Condition (c) is the key — without it, `br`'s stack-polymorphic
//! semantics hide a latent imbalance that surfaces at `end` once the
//! br is gone. Tracking stack depth requires `BlockWalker` Phase 2.
//!
//! Bodies that can't be tracked (unknown opcodes, missing sig resolver
//! for a call) are left untouched.

use crate::block_walker::BlockKind;
use crate::block_walker::BlockWalker;
use crate::block_walker::ModuleSigs;
use crate::leb128;
use crate::module::WasmModule;
use crate::mut_module::MutModule;
use crate::opcode;

pub fn apply_mut(m: &mut MutModule<'_>) {
    let input = m.input();
    let Ok(wm) = WasmModule::parse(input) else {
        return;
    };
    let Some(sigs) = ModuleSigs::from_module(&wm) else {
        return;
    };

    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>, crate::provenance::BodyEdits)> = (0..m.num_bodies())
        .into_par_iter()
        .map_init(
            || Vec::with_capacity(16),
            |frames, i| {
                rewrite_body_with_edits(m.body_bytes(i), &sigs, frames).map(|(b, e)| (i, b, e))
            },
        )
        .filter_map(|x| x)
        .collect();
    for (i, b, e) in updates {
        m.set_body_with_edits(i, b, e);
    }
}

#[allow(dead_code)]
fn rewrite_body(
    body: &[u8],
    sigs: &ModuleSigs,
    frames: &mut Vec<crate::block_walker::BlockFrame>,
) -> Option<Vec<u8>> {
    rewrite_body_with_edits(body, sigs, frames).map(|(b, _)| b)
}

fn rewrite_body_with_edits(
    body: &[u8],
    sigs: &ModuleSigs,
    frames: &mut Vec<crate::block_walker::BlockFrame>,
) -> Option<(Vec<u8>, crate::provenance::BodyEdits)> {
    let instrs_start = opcode::skip_locals(body)?;

    // Two-instruction window so we can spot `br 0 ; end` pairs.
    let mut prev: Option<(u8, usize, usize, i32, bool)> = None;
    let mut to_remove: Vec<(usize, usize)> = Vec::new();

    let mut w = BlockWalker::with_resolver(body, instrs_start, frames, Some(sigs));
    while let Some(step) = w.next() {
        if step.op == 0x0B {
            // end — check if prev was a removable `br 0`.
            if let (Some((0x0C, pp, plen, psd, preach)), Some(frame)) = (prev, step.closed_frame) {
                if preach
                    && !matches!(frame.kind, BlockKind::Loop)
                    && psd == frame.entry_depth + frame.fallthrough_arity as i32
                {
                    if let Some((label, _)) = leb128::read_u32(&body[pp + 1..]) {
                        if label == 0 {
                            to_remove.push((pp, plen));
                        }
                    }
                }
            }
        }
        prev = Some((
            step.op,
            step.pos,
            step.len,
            step.stack_depth_before,
            step.reachable_before,
        ));
    }
    if w.failed() {
        return None;
    }
    if to_remove.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(body.len());
    let mut edits = crate::provenance::BodyEdits::identity();
    let mut cursor = 0;
    for &(p, len) in &to_remove {
        out.extend_from_slice(&body[cursor..p]);
        let out_start = out.len() as u32;
        edits.push(
            crate::provenance::Edit::delete(p as u32, len as u32, out_start),
            None,
        );
        cursor = p + len;
    }
    out.extend_from_slice(&body[cursor..]);
    Some((out, edits))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(body: &[u8]) -> Option<Vec<u8>> {
        // Empty-sig context: no calls in our test bodies.
        let mut types: Vec<(u32, u32)> = Vec::new();
        let _ = &mut types;
        let sigs = ModuleSigs::from_module(
            &WasmModule::parse(&[0, 0x61, 0x73, 0x6D, 1, 0, 0, 0]).unwrap(),
        )
        .unwrap();
        let mut frames = Vec::new();
        rewrite_body(body, &sigs, &mut frames)
    }

    #[test]
    fn removes_br0_before_end_of_empty_block() {
        // (func
        //   block        ;; empty blocktype
        //     br 0
        //   end
        // )
        let body = [0, 0x02, 0x40, 0x0C, 0x00, 0x0B, 0x0B];
        let out = run(&body).expect("should rewrite");
        assert_eq!(out, vec![0, 0x02, 0x40, 0x0B, 0x0B]);
    }

    #[test]
    fn keeps_br0_in_loop() {
        let body = [0, 0x03, 0x40, 0x0C, 0x00, 0x0B, 0x0B];
        assert!(run(&body).is_none());
    }

    #[test]
    fn keeps_br_when_stack_depth_mismatches() {
        // block with empty blocktype, but stack has an extra i32
        // under the br. Removing br 0 would leave i32 on stack at
        // end → validation error. Must NOT remove.
        // (func
        //   i32.const 1        ;; depth 1 (outside block)
        //   block
        //     i32.const 2      ;; depth 2 (> entry_depth 1 + fallthrough 0)
        //     br 0             ;; stack under br has an extra value
        //   end                ;; end expects depth == 1
        //   drop
        // )
        let body = [
            0, 0x41, 1, 0x02, 0x40, 0x41, 2, 0x0C, 0x00, 0x0B, 0x1A, 0x0B,
        ];
        assert!(run(&body).is_none());
    }

    #[test]
    fn keeps_br_in_unreachable_region() {
        // If there's a br 0 in dead code right before end, we conservatively
        // leave it alone (reachable_before is false).
        let body = [
            0, 0x02, 0x40, 0x00, // unreachable → region becomes unreachable
            0x0C, 0x00, // dead br 0
            0x0B, 0x0B,
        ];
        assert!(run(&body).is_none());
    }
}
