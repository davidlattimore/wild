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
        if n == 0 {
            return None;
        }

        // Step 1: find BB start instruction indices.
        // Boundaries:
        //   - function entry (instr 0)
        //   - after every block/loop/if/else opcode (body starts a new BB)
        //   - BEFORE every else/end (so structural closers always sit in their own BB — lets
        //     dead-code elimination remove the non-structural tail of an unreachable region without
        //     touching the closer)
        //   - after every `end` (post-end code is a new BB)
        //   - after every br/br_if/br_table/return/unreachable
        let mut starts: Vec<u32> = vec![0];
        for i in 0..n {
            let op = ir.instrs()[i].op;
            let needs_split_after = matches!(
                op,
                0x02 | 0x03 | 0x04 | 0x05 | 0x0B | 0x0C | 0x0D | 0x0E | 0x0F | 0x00
            );
            let needs_split_before = matches!(op, 0x05 | 0x0B);
            if needs_split_before && i > 0 {
                starts.push(i as u32);
            }
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

        // Pre-compute matching `end` and `else` for every structural open.
        let (matching_end_of, matching_else_of) = match_structural(ir);

        // Step 3: walk again with a frame stack to compute edges.
        let mut frames: Vec<Frame> = Vec::new();
        // Then-branch tail BBs that should NOT fall through to their
        // sibling (the `else` BB) — instead they branch past the else
        // body to the post-end of the matching `if`.
        let mut suppress_fallthrough: std::collections::HashSet<u32> =
            std::collections::HashSet::new();
        let mut extra_branches: Vec<(u32, u32)> = Vec::new();
        for i in 0..n {
            let op = ir.instrs()[i].op;
            match op {
                0x02 | 0x04 => {
                    let end_idx = *matching_end_of.get(&i)?;
                    let post_end = if end_idx + 1 < n {
                        bb_of((end_idx + 1) as u32)
                    } else {
                        (blocks.len() - 1) as u32
                    };
                    frames.push(Frame {
                        branch_target_bb: post_end,
                    });

                    // For `if`, add a Branch edge for the cond=false path.
                    if op == 0x04 {
                        let if_bb = bb_of(i as u32);
                        let else_target = if let Some(&e) = matching_else_of.get(&i) {
                            // cond=false jumps to the else body, which
                            // is the BB *after* the else opcode.
                            if e + 1 < n {
                                bb_of((e + 1) as u32)
                            } else {
                                post_end
                            }
                        } else {
                            // No else: cond=false jumps to post-end.
                            post_end
                        };
                        // Skip degenerate (else_target == fallthrough).
                        let then_bb = if i + 1 < n {
                            bb_of((i + 1) as u32)
                        } else {
                            post_end
                        };
                        if else_target != then_bb {
                            blocks[if_bb as usize].successors.push(BlockEdge {
                                target: else_target,
                                kind: EdgeKind::Branch,
                            });
                        }
                    }
                }
                0x03 => {
                    let body_target = if i + 1 < n {
                        bb_of((i + 1) as u32)
                    } else {
                        (blocks.len() - 1) as u32
                    };
                    frames.push(Frame {
                        branch_target_bb: body_target,
                    });
                }
                0x05 => {
                    // `else`: the BB just before the else-BB is the
                    // then-branch tail. Its fall-through to the else-BB
                    // is wrong — execution jumps past the else body to
                    // the matching if's post-end.
                    let else_bb = bb_of(i as u32);
                    if let Some(prev) = else_bb.checked_sub(1) {
                        if let Some(frame) = frames.last() {
                            suppress_fallthrough.insert(prev);
                            extra_branches.push((prev, frame.branch_target_bb));
                        }
                    }
                }
                0x0B => {
                    let _ = frames.pop();
                }
                0x0C => {
                    // br L: unconditional branch.
                    let label = match decode_label(ir, i) {
                        Some(l) => l,
                        None => return None,
                    };
                    let target = label_target_bb(&frames, label)?;
                    let bb = bb_of(i as u32);
                    blocks[bb as usize].successors.push(BlockEdge {
                        target,
                        kind: EdgeKind::Branch,
                    });
                }
                0x0D => {
                    // br_if L: conditional. Two successors: branch target + fallthrough.
                    let label = match decode_label(ir, i) {
                        Some(l) => l,
                        None => return None,
                    };
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
                    for _ in 0..=count {
                        // count + default
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
        //   - BB ending in any other op (incl. block/loop/if/else/end mid-body or last instr being
        //     non-terminator): fallthrough.
        for bi in 0..blocks.len() {
            if bi + 1 >= blocks.len() {
                continue;
            }
            let last_instr_idx = blocks[bi].end_instr.saturating_sub(1);
            let last_op = ir.instrs()[last_instr_idx as usize].op;
            let no_fallthrough = matches!(last_op, 0x0C | 0x0E | 0x0F | 0x00)
                || suppress_fallthrough.contains(&(bi as u32));
            if !no_fallthrough {
                let next_bb = (bi + 1) as u32;
                blocks[bi].successors.push(BlockEdge {
                    target: next_bb,
                    kind: EdgeKind::Fallthrough,
                });
            }
        }

        // Apply the explicit "skip past else body" edges queued by the
        // else handling above.
        for (bb, target) in extra_branches {
            blocks[bb as usize].successors.push(BlockEdge {
                target,
                kind: EdgeKind::Branch,
            });
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

/// Pre-pass: for every `block`/`loop`/`if`, locate its matching
/// `end`; for every `if`, also locate its matching `else` (if any).
fn match_structural(
    ir: &BodyIr,
) -> (
    std::collections::HashMap<usize, usize>,
    std::collections::HashMap<usize, usize>,
) {
    let mut ends = std::collections::HashMap::new();
    let mut elses = std::collections::HashMap::new();
    let mut stack: Vec<usize> = Vec::new();
    for (i, it) in ir.instrs().iter().enumerate() {
        match it.op {
            0x02 | 0x03 | 0x04 => stack.push(i),
            0x05 => {
                if let Some(&top) = stack.last() {
                    if ir.instrs()[top].op == 0x04 {
                        elses.insert(top, i);
                    }
                }
            }
            0x0B => {
                if let Some(open) = stack.pop() {
                    ends.insert(open, i);
                }
            }
            _ => {}
        }
    }
    (ends, elses)
}

#[allow(dead_code)]
fn match_ends(ir: &BodyIr) -> std::collections::HashMap<usize, usize> {
    match_structural(ir).0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(body: &[u8]) -> CfgIr {
        let ir = BodyIr::new(body).expect("body parses");
        CfgIr::build(&ir).expect("cfg builds")
    }

    #[test]
    fn straight_line_is_two_bbs() {
        // (func i32.const 1 i32.const 2 i32.add drop end)
        // Two BBs: the linear code, and the function-end opcode in its
        // own BB (split-before-end keeps closers structurally isolated).
        let body = [0u8, 0x41, 1, 0x41, 2, 0x6A, 0x1A, 0x0B];
        let cfg = build(&body);
        assert_eq!(cfg.blocks.len(), 2);
        // BB 0 fall-through to BB 1; BB 1 (end) is terminator.
        assert_eq!(cfg.blocks[0].successors.len(), 1);
        assert!(cfg.blocks[1].successors.is_empty());
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
        let bb = cfg
            .blocks
            .iter()
            .find(|b| {
                (b.start_instr..b.end_instr).any(|i| {
                    i < 99 // any sentinel; just pick the BB with br_if as last instr
                })
            })
            .unwrap();
        let _ = bb;
        // Locate the br_if BB by its successor signature: exactly two
        // successors, one branch + one fallthrough.
        let br_if_bb_idx = cfg.blocks.iter().position(|b| {
            b.successors.len() == 2
                && b.successors.iter().any(|e| e.kind == EdgeKind::Branch)
                && b.successors.iter().any(|e| e.kind == EdgeKind::Fallthrough)
        });
        assert!(
            br_if_bb_idx.is_some(),
            "no BB with br_if's two-successor signature"
        );
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
        assert_eq!(
            br_bb.successors[0].target, 1,
            "br 0 in loop must self-target"
        );
    }

    #[test]
    fn return_terminates_no_fallthrough() {
        // (func return end)
        let body = [0u8, 0x0F, 0x0B];
        let cfg = build(&body);
        // BB 0: [return]
        // BB 1: [end]
        // return-BB has NO successors.
        assert!(
            cfg.blocks[0].successors.is_empty(),
            "return-BB must have no successors"
        );
    }

    #[test]
    fn unreachable_terminates() {
        let body = [0u8, 0x00, 0x0B];
        let cfg = build(&body);
        assert!(
            cfg.blocks[0].successors.is_empty(),
            "unreachable-BB must have no successors"
        );
    }

    #[test]
    fn if_no_else_has_two_successors() {
        // (func i32.const 1 if end end)
        let body = [0u8, 0x41, 1, 0x04, 0x40, 0x0B, 0x0B];
        let cfg = build(&body);
        // Find the BB containing the `if` (last instr 0x04). It should
        // have 2 successors: fall-through to then-body (the immediately
        // following BB) AND Branch to post-end (cond=false case).
        let if_bb = cfg.blocks.iter().position(|b| {
            let last = (b.end_instr - 1) as usize;
            // Locate by checking last opcode of BB.
            // We don't have direct access to ir here; rely on edges.
            b.successors.iter().any(|e| e.kind == EdgeKind::Branch)
                && b.successors.iter().any(|e| e.kind == EdgeKind::Fallthrough)
                && last < 99 // sentinel
        });
        assert!(
            if_bb.is_some(),
            "the if's BB should have both Fallthrough and Branch successors"
        );
    }

    #[test]
    fn if_else_then_tail_skips_else_body() {
        // (func i32.const 1 if nop else nop end end)
        // Then-tail BB (containing the first nop) should NOT fall
        // through into the else-BB; it should Branch to post-end.
        let body = [
            0u8, 0x41, 1, // i32.const 1
            0x04, 0x40, // if
            0x01, // then: nop
            0x05, // else
            0x01, // else body: nop
            0x0B, // end if
            0x0B, // end func
        ];
        let cfg = build(&body);
        // Find the then-tail BB: the one whose only successor is a
        // Branch (no Fallthrough), and that's not the end.
        let then_tail = cfg.blocks.iter().find(|b| {
            b.successors.len() == 1
                && b.successors[0].kind == EdgeKind::Branch
                // Exclude the else-BB which also has just one successor.
                // Then-tail is the one whose start_instr is BEFORE the
                // else opcode; identify by a heuristic: index 1 should
                // be the then-tail in our partition.
                && b.start_instr < 6
        });
        assert!(
            then_tail.is_some(),
            "then-tail BB should branch past else body, not fall through"
        );
    }
}
