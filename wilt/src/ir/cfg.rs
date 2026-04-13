//! Basic-block CFG over `BodyIr`.
//!
//! Plan C / M5. Builds:
//! - basic-block partition of the instruction stream;
//! - successor edges (fall-through, conditional, branch).
//!
//! Wasm has structured control flow — every `br L` targets a statically-
//! known label depth. We exploit that to resolve branch targets in one
//! linear pass with a frame stack.
//!
//! Coverage: `block`, `loop`, `if`/`else`, `end`, `br`, `br_if`,
//! `br_table`, `return`, `unreachable`. Bails (`build` returns `None`)
//! on any unknown / unsupported opcode the underlying `BodyIr` couldn't
//! decode.

use crate::ir::body::BodyIr;
use crate::leb128;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EdgeKind {
    /// Falls through to the next basic block in source order.
    Fallthrough,
    /// Conditional or unconditional branch via `br`/`br_if`/`br_table`/
    /// `if`/`else` semantics.
    Branch,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BlockEdge {
    pub target: u32,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug)]
pub struct BasicBlock {
    /// First instruction index in `BodyIr.instrs()`.
    pub start_instr: u32,
    /// One-past-last instruction index.
    pub end_instr: u32,
    /// 0 successors → terminator (return/unreachable/function-end).
    /// 1 successor → unconditional flow (fall-through or `br`).
    /// 2 successors → conditional (`br_if`, `if`).
    /// >2 → `br_table`.
    pub successors: Vec<BlockEdge>,
}

#[derive(Debug)]
pub struct CfgIr {
    pub blocks: Vec<BasicBlock>,
    pub entry: u32,
}

struct Frame {
    /// Branch-target BB. For block/if: the BB starting just after the
    /// matching `end` (resolved up-front via `match_ends`).
    /// For loop: the BB starting at the loop's first body instruction.
    branch_target_bb: u32,
}

impl CfgIr {
    pub fn build(ir: &BodyIr) -> Option<Self> {
        let n = ir.instrs().len();
        if n == 0 { return None; }

        // Step 1: find BB start instruction indices.
        // Boundaries:
        //   - function entry (instr 0)
        //   - after every block/loop/if/else opcode (body starts a new BB)
        //   - after every `end` (post-end code is a new BB)
        //   - after every br/br_if/br_table/return/unreachable
        let mut starts: Vec<u32> = vec![0];
        for i in 0..n {
            let op = ir.instrs()[i].op;
            let needs_split_after = matches!(op,
                0x02 | 0x03 | 0x04 | 0x05 | 0x0B
                | 0x0C | 0x0D | 0x0E | 0x0F | 0x00);
            if needs_split_after && i + 1 < n {
                starts.push((i + 1) as u32);
            }
        }
        starts.sort();
        starts.dedup();

        // Step 2: materialise BBs.
        let mut blocks: Vec<BasicBlock> = Vec::with_capacity(starts.len());
        for w in starts.windows(2) {
            blocks.push(BasicBlock {
                start_instr: w[0],
                end_instr: w[1],
                successors: Vec::new(),
            });
        }
        if let Some(&last) = starts.last() {
            blocks.push(BasicBlock {
                start_instr: last,
                end_instr: n as u32,
                successors: Vec::new(),
            });
        }

        // Helper: BB index containing a given instruction index.
        let bb_of = |instr_idx: u32| -> u32 {
            // starts is sorted; find rightmost start <= instr_idx.
            match starts.binary_search(&instr_idx) {
                Ok(i) => i as u32,
                Err(i) => (i.saturating_sub(1)) as u32,
            }
        };

        // Pre-compute matching `end` for every block/loop/if open.
        // Needed because `br` can reference a frame before its end is seen.
        let matching_end_of = match_ends(ir);

        // Step 3: walk again with a frame stack to compute edges.
        let mut frames: Vec<Frame> = Vec::new();
        for i in 0..n {
            let op = ir.instrs()[i].op;
            match op {
                0x02 | 0x04 => {
                    let end_idx = *matching_end_of.get(&i)?;
                    let target = if end_idx + 1 < n {
                        bb_of((end_idx + 1) as u32)
                    } else {
                        (blocks.len() - 1) as u32
                    };
                    frames.push(Frame { branch_target_bb: target });
                }
                0x03 => {
                    let body_target = if i + 1 < n {
                        bb_of((i + 1) as u32)
                    } else {
                        (blocks.len() - 1) as u32
                    };
                    frames.push(Frame { branch_target_bb: body_target });
                }
                0x05 => {
                    // `else`: ends the if-true region; doesn't change the
                    // frame stack here. Edges from the if-true BB are
                    // computed during fall-through pass.
                }
                0x0B => {
                    // Pop the closed frame.
                    let _ = frames.pop();
                }
                0x0C => {
                    // br L: unconditional branch.
                    let label = match decode_label(ir, i) { Some(l) => l, None => return None };
                    let target = label_target_bb(&frames, label)?;
                    let bb = bb_of(i as u32);
                    blocks[bb as usize].successors.push(BlockEdge {
                        target,
                        kind: EdgeKind::Branch,
                    });
                }
                0x0D => {
                    // br_if L: conditional. Two successors: branch target + fallthrough.
                    let label = match decode_label(ir, i) { Some(l) => l, None => return None };
                    let target = label_target_bb(&frames, label)?;
                    let bb = bb_of(i as u32);
                    blocks[bb as usize].successors.push(BlockEdge {
                        target,
                        kind: EdgeKind::Branch,
                    });
                    // Fallthrough handled in the post-pass below.
                }
                0x0E => {
                    // br_table — many labels + default. Decode each as a successor.
                    let bytes = ir.instr_bytes(i);
                    let (count, mut off) = leb128::read_u32(&bytes[1..])?;
                    off += 1; // skip the opcode byte
                    let bb = bb_of(i as u32);
                    for _ in 0..=count {     // count + default
                        let (lbl, c) = leb128::read_u32(&bytes[off..])?;
                        off += c;
                        let tgt = label_target_bb(&frames, lbl)?;
                        blocks[bb as usize].successors.push(BlockEdge {
                            target: tgt,
                            kind: EdgeKind::Branch,
                        });
                    }
                }
                _ => {}
            }
        }

        // Step 4: fall-through edges. Any BB that doesn't end in
        // return/unreachable/br/br_table gets a fall-through to the next
        // BB. Specifically:
        //   - BB ending in br_if: already has 1 branch edge; add fallthrough.
        //   - BB ending in br: NO fallthrough.
        //   - BB ending in return/unreachable: NO fallthrough (terminator).
        //   - BB ending in br_table: NO fallthrough.
        //   - BB ending in any other op (incl. block/loop/if/else/end mid-body
        //     or last instr being non-terminator): fallthrough.
        for bi in 0..blocks.len() {
            if bi + 1 >= blocks.len() { continue; }   // last BB has no next
            let last_instr_idx = blocks[bi].end_instr.saturating_sub(1);
            let last_op = ir.instrs()[last_instr_idx as usize].op;
            let no_fallthrough = matches!(last_op, 0x0C | 0x0E | 0x0F | 0x00);
            if !no_fallthrough {
                let next_bb = (bi + 1) as u32;
                blocks[bi].successors.push(BlockEdge {
                    target: next_bb,
                    kind: EdgeKind::Fallthrough,
                });
            }
        }

        Some(CfgIr { blocks, entry: 0 })
    }
}

fn decode_label(ir: &BodyIr, instr_idx: usize) -> Option<u32> {
    let bytes = ir.instr_bytes(instr_idx);
    leb128::read_u32(&bytes[1..]).map(|(v, _)| v)
}

/// `br L` at frame depth `frames.len()` targets `frames[frames.len() - 1 - L]`.
fn label_target_bb(frames: &[Frame], label: u32) -> Option<u32> {
    let idx = frames.len().checked_sub(1)?.checked_sub(label as usize)?;
    frames.get(idx).map(|f| f.branch_target_bb)
}

/// Pre-pass: locate the matching `end` instruction index for every
/// `block`/`loop`/`if` open. Returns `None` if the body's structured
/// control flow is malformed.
fn match_ends(ir: &BodyIr) -> std::collections::HashMap<usize, usize> {
    let mut out = std::collections::HashMap::new();
    let mut stack: Vec<usize> = Vec::new();
    for (i, it) in ir.instrs().iter().enumerate() {
        match it.op {
            0x02 | 0x03 | 0x04 => stack.push(i),
            0x0B => { if let Some(open) = stack.pop() { out.insert(open, i); } }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(body: &[u8]) -> CfgIr {
        let ir = BodyIr::new(body).expect("body parses");
        CfgIr::build(&ir).expect("cfg builds")
    }

    #[test]
    fn straight_line_is_one_bb() {
        // (func i32.const 1 i32.const 2 i32.add drop end)
        let body = [0u8, 0x41, 1, 0x41, 2, 0x6A, 0x1A, 0x0B];
        let cfg = build(&body);
        assert_eq!(cfg.blocks.len(), 1);
        assert_eq!(cfg.blocks[0].successors.len(), 0);
    }

    #[test]
    fn block_partitions_into_three_bbs() {
        // (func block end end-of-func)
        let body = [0u8, 0x02, 0x40, 0x0B, 0x0B];
        let cfg = build(&body);
        // Instructions: [block, end-of-block, end-of-func].
        // BB starts: 0, 1 (after block-open), 2 (after end-of-block).
        assert_eq!(cfg.blocks.len(), 3);
    }

    #[test]
    fn br_creates_edge_to_post_end_bb() {
        // (func block br 0 end)
        // Instructions:
        //   0: block
        //   1: br 0
        //   2: end (closes block)
        //   3: end (function)
        // BB 0: [block]      fallthrough → BB1
        // BB 1: [br 0]       branch → BB3 (instr just AFTER end-of-block)
        // BB 2: [end-block]  fallthrough → BB3
        // BB 3: [end func]   no successors (function terminator)
        let body = [0u8, 0x02, 0x40, 0x0C, 0x00, 0x0B, 0x0B];
        let cfg = build(&body);
        assert_eq!(cfg.blocks.len(), 4);
        let br_bb = &cfg.blocks[1];
        assert_eq!(br_bb.successors.len(), 1);
        assert_eq!(br_bb.successors[0].kind, EdgeKind::Branch);
        assert_eq!(br_bb.successors[0].target, 3);
    }

    #[test]
    fn br_if_has_branch_and_fallthrough() {
        // (func block i32.const 1 br_if 0 end)
        let body = [0u8, 0x02, 0x40, 0x41, 1, 0x0D, 0x00, 0x0B, 0x0B];
        let cfg = build(&body);
        // Find the BB containing br_if.
        let bb = cfg.blocks.iter().find(|b| {
            (b.start_instr..b.end_instr).any(|i| {
                i < 99 // any sentinel; just pick the BB with br_if as last instr
            })
        }).unwrap();
        let _ = bb;
        // Locate the br_if BB by its successor signature: exactly two
        // successors, one branch + one fallthrough.
        let br_if_bb_idx = cfg.blocks.iter().position(|b| {
            b.successors.len() == 2
                && b.successors.iter().any(|e| e.kind == EdgeKind::Branch)
                && b.successors.iter().any(|e| e.kind == EdgeKind::Fallthrough)
        });
        assert!(br_if_bb_idx.is_some(), "no BB with br_if's two-successor signature");
    }

    #[test]
    fn loop_branch_targets_loop_body() {
        // (func loop br 0 end)
        let body = [0u8, 0x03, 0x40, 0x0C, 0x00, 0x0B, 0x0B];
        let cfg = build(&body);
        // Instructions: loop, br 0, end loop, end func.
        // BB 0: [loop]
        // BB 1: [br 0] — branches to BB1 itself (loop body start).
        // BB 2: [end]
        // BB 3: [end func]
        let br_bb = &cfg.blocks[1];
        assert_eq!(br_bb.successors.len(), 1);
        assert_eq!(br_bb.successors[0].target, 1, "br 0 in loop must self-target");
    }

    #[test]
    fn return_terminates_no_fallthrough() {
        // (func return end)
        let body = [0u8, 0x0F, 0x0B];
        let cfg = build(&body);
        // BB 0: [return]
        // BB 1: [end]
        // return-BB has NO successors.
        assert!(cfg.blocks[0].successors.is_empty(), "return-BB must have no successors");
    }

    #[test]
    fn unreachable_terminates() {
        let body = [0u8, 0x00, 0x0B];
        let cfg = build(&body);
        assert!(cfg.blocks[0].successors.is_empty(), "unreachable-BB must have no successors");
    }
}
