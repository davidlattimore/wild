//! Remove a `block` whose label is never a branch target.
//!
//! When nothing inside `block L ... end` branches to `L`, the block is
//! pure scoping; its body's stack effect is identical whether wrapped
//! or not. We delete the `block`-open and `end` opcode+immediate
//! bytes, then decrement the label of any inner `br` / `br_if` whose
//! target is outside the removed block.
//!
//! Scope:
//!   * Only `block` (`0x02`). `loop` labels are back-edges; `if`/`else`
//!     have cond/then/else semantics we don't want to touch here.
//!   * Bodies containing `br_table` (`0x0E`) are bailed — relabelling
//!     all its labels is straightforward but we defer until needed.
//!   * One removal per invocation; the outer fixpoint iterates.
//!
//! Relies on `BlockWalker` Phase 2 to resolve each `br`'s target frame.

use crate::block_walker::{BlockKind, BlockWalker, ModuleSigs};
use crate::leb128;
use crate::module::WasmModule;
use crate::mut_module::MutModule;
use crate::opcode;

pub fn apply_mut(m: &mut MutModule<'_>) {
    let input = m.input();
    let Ok(wm) = WasmModule::parse(input) else { return };
    let Some(sigs) = ModuleSigs::from_module(&wm) else { return };

    use rayon::prelude::*;
    let updates: Vec<(usize, Vec<u8>)> = (0..m.num_bodies())
        .into_par_iter()
        .map_init(
            || Vec::with_capacity(16),
            |frames, i| rewrite_body(m.body_bytes(i), &sigs, frames).map(|b| (i, b)),
        )
        .filter_map(|x| x)
        .collect();
    for (i, b) in updates { m.set_body(i, b); }
}

struct FrameInfo {
    open_pos: usize,
    open_len: usize,
    end_pos: usize,
    end_len: usize,
    kind: BlockKind,
    stack_idx: usize,
    targeted: bool,
}

struct BrInfo {
    imm_pos: usize,
    old_label: u32,
    old_label_len: usize,
    target_stack_idx: usize,
}

fn rewrite_body(
    body: &[u8],
    sigs: &ModuleSigs,
    frames_buf: &mut Vec<crate::block_walker::BlockFrame>,
) -> Option<Vec<u8>> {
    let instrs_start = opcode::skip_locals(body)?;

    let mut frame_infos: Vec<FrameInfo> = Vec::new();
    // Maps current walker-frame-stack index -> frame_infos index.
    let mut active: Vec<usize> = Vec::new();
    let mut br_infos: Vec<BrInfo> = Vec::new();
    let mut bail = false;

    let mut w = BlockWalker::with_resolver(body, instrs_start, frames_buf, Some(sigs));
    while let Some(step) = w.next() {
        match step.op {
            0x02 | 0x03 | 0x04 => {
                let kind = w.frames().last()?.kind;
                let stack_idx = w.frames().len() - 1;
                active.push(frame_infos.len());
                frame_infos.push(FrameInfo {
                    open_pos: step.pos,
                    open_len: step.len,
                    end_pos: 0,
                    end_len: 0,
                    kind,
                    stack_idx,
                    targeted: false,
                });
            }
            0x0B => {
                if let Some(fi) = active.pop() {
                    frame_infos[fi].end_pos = step.pos;
                    frame_infos[fi].end_len = step.len;
                }
            }
            0x0C | 0x0D => {
                // Walker frames size BEFORE br is the enclosing count.
                // (br doesn't push/pop frames.)
                let stack_n = w.frames().len();
                let (label, lc) = leb128::read_u32(&body[step.pos + 1..])?;
                let Some(target) = stack_n.checked_sub(1).and_then(|x| x.checked_sub(label as usize)) else {
                    bail = true; break;
                };
                if target < active.len() {
                    frame_infos[active[target]].targeted = true;
                }
                br_infos.push(BrInfo {
                    imm_pos: step.pos + 1,
                    old_label: label,
                    old_label_len: lc,
                    target_stack_idx: target,
                });
            }
            0x0E => { bail = true; break; }
            _ => {}
        }
    }
    if w.failed() || bail { return None; }

    // Pick the first block whose label is never branched to.
    // Require end_pos > 0 (we must have seen its end during the walk).
    let Some(removed) = frame_infos.iter()
        .find(|f| matches!(f.kind, BlockKind::Block) && !f.targeted && f.end_pos > 0)
    else {
        return None;
    };

    // Collect edits.
    // Deletion ranges: open instruction + end instruction.
    let del_open = (removed.open_pos, removed.open_len);
    let del_end = (removed.end_pos, removed.end_len);

    // Relabels: any br whose target is strictly outside the removed
    // block (target_stack_idx < removed.stack_idx) and whose br lives
    // inside the removed block needs its label decremented by 1.
    //
    // "Br lives inside removed": the br's imm_pos is in
    // (removed.open_pos, removed.end_pos). Equivalent: walk up from
    // br's containing frame and find `removed` as an ancestor.
    let removed_idx = frame_infos.iter().position(|f| std::ptr::eq(f, removed)).unwrap();
    let mut relabels: Vec<(&BrInfo, u32)> = Vec::new();
    for br in &br_infos {
        if br.imm_pos > removed.open_pos && br.imm_pos < removed.end_pos
            && br.target_stack_idx < removed.stack_idx
        {
            relabels.push((br, br.old_label - 1));
        }
    }
    let _ = removed_idx;

    // Emit body with edits applied in byte order.
    let mut edits: Vec<Edit> = Vec::new();
    edits.push(Edit::Delete(del_open.0, del_open.1));
    for (br, new_label) in &relabels {
        edits.push(Edit::Relabel {
            imm_pos: br.imm_pos,
            old_len: br.old_label_len,
            new_label: *new_label,
        });
    }
    edits.push(Edit::Delete(del_end.0, del_end.1));
    edits.sort_by_key(|e| e.pos());

    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for e in &edits {
        out.extend_from_slice(&body[cursor..e.pos()]);
        match e {
            Edit::Delete(_, len) => {
                cursor = e.pos() + len;
            }
            Edit::Relabel { imm_pos, old_len, new_label } => {
                leb128::write_u32(&mut out, *new_label);
                cursor = imm_pos + old_len;
            }
        }
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

enum Edit {
    Delete(usize, usize),
    Relabel { imm_pos: usize, old_len: usize, new_label: u32 },
}

impl Edit {
    fn pos(&self) -> usize {
        match self {
            Edit::Delete(p, _) => *p,
            Edit::Relabel { imm_pos, .. } => *imm_pos,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_sigs() -> ModuleSigs {
        ModuleSigs::from_module(&WasmModule::parse(&[
            0,0x61,0x73,0x6D,1,0,0,0
        ]).unwrap()).unwrap()
    }

    fn run(body: &[u8]) -> Option<Vec<u8>> {
        let sigs = empty_sigs();
        let mut frames = Vec::new();
        rewrite_body(body, &sigs, &mut frames)
    }

    #[test]
    fn removes_block_with_no_internal_br() {
        // (func
        //   block
        //     nop
        //   end
        // )
        let body = [
            0,
            0x02, 0x40,
            0x01,
            0x0B,
            0x0B,
        ];
        let out = run(&body).expect("should rewrite");
        assert_eq!(out, vec![0, 0x01, 0x0B]);
    }

    #[test]
    fn keeps_block_targeted_by_br() {
        let body = [
            0,
            0x02, 0x40,
            0x0C, 0x00,
            0x0B,
            0x0B,
        ];
        assert!(run(&body).is_none());
    }

    #[test]
    fn keeps_loop() {
        let body = [
            0,
            0x03, 0x40,
            0x01,
            0x0B,
            0x0B,
        ];
        assert!(run(&body).is_none());
    }

    #[test]
    fn decrements_outer_targeting_br_inside_removed() {
        // (func
        //   block       ;; A — targeted by inner br 1
        //     block     ;; B — NOT targeted (no br 0 to it). Removable.
        //       br 1    ;; targets A; after B removed must become br 0.
        //     end
        //   end
        // )
        let body = [
            0,
            0x02, 0x40,   // A
            0x02, 0x40,   // B (candidate)
            0x0C, 0x01,   // br 1 → A
            0x0B,         // end B
            0x0B,         // end A
            0x0B,         // end func
        ];
        let out = run(&body).expect("should rewrite");
        // After removing B: A opcodes stay, br 1 -> br 0, B open+end gone.
        // New sequence: locals, block A, br 0, end A, end func
        let expected = vec![
            0,
            0x02, 0x40,
            0x0C, 0x00,
            0x0B,
            0x0B,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn bails_on_br_table() {
        let body = [
            0,
            0x02, 0x40,
            0x41, 0,      // i32.const 0
            0x0E, 0, 0,   // br_table with 0 labels, default 0
            0x0B,
            0x0B,
        ];
        assert!(run(&body).is_none());
    }
}
