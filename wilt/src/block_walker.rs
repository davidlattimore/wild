//! Control-flow + stack-depth walker.
//!
//! Wraps `InstrIter` with (a) a stack of block frames so passes can ask
//! "what construct encloses me?" and "what's the result arity of the
//! label `br L` targets?", and (b) a running stack-depth tracker so
//! passes can prove stack-neutrality for transforms that depend on it
//! (e.g. remove-unused-brs, simplify-locals).
//!
//! Zero-copy: walks `&[u8]`, reuses a caller-owned frame buffer. The
//! optional `SigResolver` is borrowed, not owned.
//!
//! Supported opcode families for stack-effect tracking: MVP core
//! (control flow, locals/globals, memory, numerics, reference types)
//! plus bulk-memory/table `0xFC` prefix. Calls (`call`, `call_indirect`)
//! require a `SigResolver`. SIMD (`0xFD`), atomics (`0xFE`) and EH
//! (`try`/`try_table`) fail the walker — callers that hit those must
//! bail via `failed()`.
//!
//! Blocktype encoding: `0x40` (empty), single-byte numeric/simple-ref
//! valtypes, and non-negative s33 type indices (the last only when a
//! `SigResolver` is supplied). Parametric reftypes (`0x6B`/`0x6C` +
//! heap-type) cause walker failure — we don't decode them.

use crate::leb128;
use crate::module::WasmModule;
use crate::module::{self as wmod};
use crate::opcode::InstrIter;
use crate::opcode::{self};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlockKind {
    Block,
    Loop,
    If,
    Else,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BlockFrame {
    pub kind: BlockKind,
    /// Values a `br` targeting this label transfers.
    pub branch_arity: u32,
    /// Values on the stack (above `entry_depth`) at fall-through `end`.
    pub fallthrough_arity: u32,
    /// Values consumed at block entry (block/if/loop param arity).
    pub in_arity: u32,
    /// Stack depth just BEFORE this block's opcode executed. Inside
    /// the block, `stack_depth` must not drop below this.
    pub entry_depth: i32,
    /// Whether control flow could reach this block's opening opcode.
    /// Propagates to `reachable` when the block ends.
    pub reachable_at_entry: bool,
}

/// One step of the walk.
#[derive(Debug)]
pub struct Step {
    pub pos: usize,
    pub len: usize,
    pub op: u8,
    /// Stack depth BEFORE this instruction executed. Meaningful only
    /// when `reachable_before` is true.
    pub stack_depth_before: i32,
    /// True if this instruction was reached by forward control flow.
    /// False inside unreachable (post-`br`/`return`/`unreachable`) regions.
    pub reachable_before: bool,
    /// Set for `end` — the frame just popped.
    pub closed_frame: Option<BlockFrame>,
}

/// Resolve function-signature arities. Supplied by callers that need
/// stack tracking across `call` / `call_indirect` / multi-value blocktypes.
pub trait SigResolver {
    /// `(param_count, result_count)` for the function at `func_idx` —
    /// both imported and defined functions share one index space.
    fn func_sig(&self, func_idx: u32) -> Option<(u32, u32)>;
    /// `(param_count, result_count)` for the function type at `type_idx`.
    fn type_sig(&self, type_idx: u32) -> Option<(u32, u32)>;
}

pub struct BlockWalker<'a, 'f, 'r> {
    body: &'a [u8],
    iter: InstrIter<'a>,
    frames: &'f mut Vec<BlockFrame>,
    resolver: Option<&'r dyn SigResolver>,
    stack_depth: i32,
    reachable: bool,
    failed: bool,
}

impl<'a, 'f, 'r> BlockWalker<'a, 'f, 'r> {
    pub fn new(body: &'a [u8], start: usize, frames: &'f mut Vec<BlockFrame>) -> Self {
        Self::with_resolver(body, start, frames, None)
    }

    pub fn with_resolver(
        body: &'a [u8],
        start: usize,
        frames: &'f mut Vec<BlockFrame>,
        resolver: Option<&'r dyn SigResolver>,
    ) -> Self {
        frames.clear();
        Self {
            body,
            iter: InstrIter::new(body, start),
            frames,
            resolver,
            stack_depth: 0,
            reachable: true,
            failed: false,
        }
    }

    #[inline]
    pub fn frames(&self) -> &[BlockFrame] {
        self.frames
    }
    #[inline]
    pub fn stack_depth(&self) -> i32 {
        self.stack_depth
    }
    #[inline]
    pub fn reachable(&self) -> bool {
        self.reachable
    }
    #[inline]
    pub fn failed(&self) -> bool {
        self.failed || self.iter.failed()
    }

    fn mark_unreachable(&mut self) {
        self.reachable = false;
    }

    fn apply_effect(&mut self, pops: u32, pushes: u32) {
        if !self.reachable {
            return;
        }
        self.stack_depth -= pops as i32;
        self.stack_depth += pushes as i32;
    }
}

impl<'a, 'f, 'r> Iterator for BlockWalker<'a, 'f, 'r> {
    type Item = Step;

    fn next(&mut self) -> Option<Self::Item> {
        let (pos, len) = self.iter.next()?;
        let op = self.body[pos];
        let stack_depth_before = self.stack_depth;
        let reachable_before = self.reachable;
        let mut closed_frame = None;

        match op {
            // Control flow — block open.
            0x02 | 0x03 | 0x04 => {
                let kind = match op {
                    0x02 => BlockKind::Block,
                    0x03 => BlockKind::Loop,
                    _ => BlockKind::If,
                };
                let (in_arity, out_arity) =
                    match read_blocktype_arity(self.body, pos + 1, self.resolver) {
                        Some(x) => x,
                        None => {
                            self.failed = true;
                            return Some(stub_step(pos, len, op));
                        }
                    };
                // `if` pops its condition before the scoping semantics
                // apply. The in_arity values are already on the stack
                // (block doesn't pop them — they stay visible inside).
                if op == 0x04 {
                    self.apply_effect(1, 0);
                }
                let (branch, fallthrough) = match kind {
                    BlockKind::Loop => (in_arity, out_arity),
                    _ => (out_arity, out_arity),
                };
                self.frames.push(BlockFrame {
                    kind,
                    branch_arity: branch,
                    fallthrough_arity: fallthrough,
                    in_arity,
                    entry_depth: self.stack_depth - in_arity as i32,
                    reachable_at_entry: self.reachable,
                });
            }
            // else: reset stack to if-entry + in_arity; reachable resets.
            0x05 => {
                if let Some(top) = self.frames.last_mut() {
                    if matches!(top.kind, BlockKind::If) {
                        top.kind = BlockKind::Else;
                        self.stack_depth = top.entry_depth + top.in_arity as i32;
                        self.reachable = top.reachable_at_entry;
                    }
                }
            }
            // end: close current block.
            0x0B => {
                if let Some(frame) = self.frames.pop() {
                    self.stack_depth = frame.entry_depth + frame.fallthrough_arity as i32;
                    self.reachable = frame.reachable_at_entry;
                    closed_frame = Some(frame);
                }
                // Top-level end (function body) — leave state as-is.
            }
            // unreachable.
            0x00 => self.mark_unreachable(),
            // nop.
            0x01 => {}
            // br L: polymorphic after.
            0x0C => self.mark_unreachable(),
            // br_if L: pops cond; stack otherwise unchanged.
            0x0D => self.apply_effect(1, 0),
            // br_table: pops cond, polymorphic after.
            0x0E => {
                self.apply_effect(1, 0);
                self.mark_unreachable();
            }
            // return: polymorphic.
            0x0F => self.mark_unreachable(),
            // call f — needs resolver.
            0x10 => {
                let Some((idx, _)) = leb128::read_u32(self.body.get(pos + 1..).unwrap_or(&[]))
                else {
                    self.failed = true;
                    return Some(stub_step(pos, len, op));
                };
                let Some(r) = self.resolver else {
                    self.failed = true;
                    return Some(stub_step(pos, len, op));
                };
                let Some((p, q)) = r.func_sig(idx) else {
                    self.failed = true;
                    return Some(stub_step(pos, len, op));
                };
                self.apply_effect(p, q);
            }
            // call_indirect (typeidx, tableidx) — pops index + type params.
            0x11 => {
                let Some((tidx, _)) = leb128::read_u32(self.body.get(pos + 1..).unwrap_or(&[]))
                else {
                    self.failed = true;
                    return Some(stub_step(pos, len, op));
                };
                let Some(r) = self.resolver else {
                    self.failed = true;
                    return Some(stub_step(pos, len, op));
                };
                let Some((p, q)) = r.type_sig(tidx) else {
                    self.failed = true;
                    return Some(stub_step(pos, len, op));
                };
                self.apply_effect(p + 1, q);
            }
            // drop.
            0x1A => self.apply_effect(1, 0),
            // select (typed + untyped).
            0x1B | 0x1C => self.apply_effect(3, 1),
            // local.get, global.get.
            0x20 | 0x23 => self.apply_effect(0, 1),
            // local.set, global.set.
            0x21 | 0x24 => self.apply_effect(1, 0),
            // local.tee.
            0x22 => self.apply_effect(1, 1),
            // table.get: (i) -> (ref).
            0x25 => self.apply_effect(1, 1),
            // table.set: (i, ref) -> ().
            0x26 => self.apply_effect(2, 0),
            // loads: addr -> value.
            0x28..=0x35 => self.apply_effect(1, 1),
            // stores: addr, value -> ().
            0x36..=0x3E => self.apply_effect(2, 0),
            // memory.size -> i32.
            0x3F => self.apply_effect(0, 1),
            // memory.grow: i32 -> i32.
            0x40 => self.apply_effect(1, 1),
            // consts: i32, i64, f32, f64.
            0x41..=0x44 => self.apply_effect(0, 1),
            // i32.eqz, i64.eqz, i32/i64 unary (clz/ctz/popcnt), f unary,
            // conversions — all one-in-one-out.
            0x45
            | 0x50
            | 0x67
            | 0x68
            | 0x69
            | 0x79
            | 0x7A
            | 0x7B
            | 0x8B..=0x91
            | 0x99..=0x9F
            | 0xA7..=0xC4 => self.apply_effect(1, 1),
            // Comparison + arithmetic binary ops: two-in-one-out.
            0x46..=0x4F
            | 0x51..=0x5A
            | 0x5B..=0x66
            | 0x6A..=0x78
            | 0x7C..=0x8A
            | 0x92..=0x98
            | 0xA0..=0xA6 => self.apply_effect(2, 1),
            // ref.null ht -> ref.
            0xD0 => self.apply_effect(0, 1),
            // ref.is_null: ref -> i32.
            0xD1 => self.apply_effect(1, 1),
            // ref.func f -> ref.
            0xD2 => self.apply_effect(0, 1),
            // ref.eq.
            0xD3 => self.apply_effect(2, 1),
            // ref.as_non_null.
            0xD4 => self.apply_effect(1, 1),
            // Prefix 0xFC: bulk memory + table ops.
            0xFC => {
                let Some((sub, _)) = leb128::read_u32(self.body.get(pos + 1..).unwrap_or(&[]))
                else {
                    self.failed = true;
                    return Some(stub_step(pos, len, op));
                };
                match sub {
                    0x00..=0x07 => self.apply_effect(1, 1), // saturating trunc
                    0x08 | 0x0A | 0x0B | 0x0C | 0x0E | 0x11 => self.apply_effect(3, 0),
                    // memory.init/copy/fill, table.init/copy/fill
                    0x09 | 0x0D => {}                // data.drop / elem.drop
                    0x0F => self.apply_effect(2, 1), // table.grow
                    0x10 => self.apply_effect(0, 1), // table.size
                    _ => {
                        self.failed = true;
                        return Some(stub_step(pos, len, op));
                    }
                }
            }
            // Anything we don't model — fail the walker.
            _ => {
                self.failed = true;
                return Some(stub_step(pos, len, op));
            }
        }

        Some(Step {
            pos,
            len,
            op,
            stack_depth_before,
            reachable_before,
            closed_frame,
        })
    }
}

/// Default `SigResolver` that reads function + type signatures from a
/// parsed `WasmModule`. Bails (returns `None` from `from_module`) on
/// any type/import encoding it can't decode — caller then walks
/// without a resolver, and the walker fails on any `call`.
pub struct ModuleSigs {
    /// `(param_count, result_count)` for each type index.
    types: Vec<(u32, u32)>,
    /// Type index for each function index (imports first, then defined).
    func_types: Vec<u32>,
}

impl ModuleSigs {
    pub fn from_module(module: &WasmModule<'_>) -> Option<Self> {
        let data = module.data();
        let types = read_type_arities(module, data)?;
        let mut func_types = Vec::new();
        // Imported function types first.
        if let Some(sec) = module.section(wmod::SECTION_IMPORT) {
            let p = sec.payload.slice(data);
            let (count, mut off) = leb128::read_u32(p)?;
            for _ in 0..count {
                let (mlen, c) = leb128::read_u32(p.get(off..)?)?;
                off = off.checked_add(c)?.checked_add(mlen as usize)?;
                let (flen, c) = leb128::read_u32(p.get(off..)?)?;
                off = off.checked_add(c)?.checked_add(flen as usize)?;
                let kind = *p.get(off)?;
                off = off.checked_add(1)?;
                match kind {
                    0x00 => {
                        let (tidx, c) = leb128::read_u32(p.get(off..)?)?;
                        off += c;
                        func_types.push(tidx);
                    }
                    0x01 => {
                        // table: elemtype + limits
                        off += 1;
                        let flags = *p.get(off)?;
                        off += 1;
                        let (_, c) = leb128::read_u32(p.get(off..)?)?;
                        off += c;
                        if flags & 1 != 0 {
                            let (_, c) = leb128::read_u32(p.get(off..)?)?;
                            off += c;
                        }
                    }
                    0x02 => {
                        // memory: limits
                        let flags = *p.get(off)?;
                        off += 1;
                        let (_, c) = leb128::read_u32(p.get(off..)?)?;
                        off += c;
                        if flags & 1 != 0 {
                            let (_, c) = leb128::read_u32(p.get(off..)?)?;
                            off += c;
                        }
                    }
                    0x03 => off = off.checked_add(2)?, // global: valtype + mut
                    _ => return None,
                }
            }
        }
        // Defined function types.
        if let Some(sec) = module.section(wmod::SECTION_FUNCTION) {
            let p = sec.payload.slice(data);
            let (count, mut off) = leb128::read_u32(p)?;
            for _ in 0..count {
                let (tidx, c) = leb128::read_u32(p.get(off..)?)?;
                off += c;
                func_types.push(tidx);
            }
        }
        Some(Self { types, func_types })
    }
}

impl SigResolver for ModuleSigs {
    fn func_sig(&self, func_idx: u32) -> Option<(u32, u32)> {
        let tidx = *self.func_types.get(func_idx as usize)?;
        self.type_sig(tidx)
    }
    fn type_sig(&self, type_idx: u32) -> Option<(u32, u32)> {
        self.types.get(type_idx as usize).copied()
    }
}

fn read_type_arities(module: &WasmModule<'_>, data: &[u8]) -> Option<Vec<(u32, u32)>> {
    let Some(sec) = module.section(wmod::SECTION_TYPE) else {
        return Some(Vec::new());
    };
    let p = sec.payload.slice(data);
    let (count, mut off) = leb128::read_u32(p)?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if *p.get(off)? != 0x60 {
            return None;
        }
        off += 1;
        let (params, c) = leb128::read_u32(p.get(off..)?)?;
        off += c;
        for _ in 0..params {
            let vt = *p.get(off)?;
            if !matches!(vt, 0x7B..=0x7F | 0x6F | 0x70) {
                return None;
            }
            off += 1;
        }
        let (results, c) = leb128::read_u32(p.get(off..)?)?;
        off += c;
        for _ in 0..results {
            let vt = *p.get(off)?;
            if !matches!(vt, 0x7B..=0x7F | 0x6F | 0x70) {
                return None;
            }
            off += 1;
        }
        out.push((params, results));
    }
    Some(out)
}

fn stub_step(pos: usize, len: usize, op: u8) -> Step {
    Step {
        pos,
        len,
        op,
        stack_depth_before: 0,
        reachable_before: false,
        closed_frame: None,
    }
}

/// Decode a blocktype. Returns `(in_arity, out_arity)`.
fn read_blocktype_arity(
    body: &[u8],
    off: usize,
    resolver: Option<&dyn SigResolver>,
) -> Option<(u32, u32)> {
    let b = *body.get(off)?;
    if b == 0x40 {
        return Some((0, 0));
    }
    if opcode::valtype_len(body, off).is_some() {
        return Some((0, 1));
    }
    // Try as positive s33 (non-negative single-byte LEB covers 0..=63;
    // multi-byte LEBs cover larger indices). Read as u32 — for
    // non-negative s33 the bit pattern is identical.
    let (val, _) = leb128::read_u32(body.get(off..)?)?;
    let r = resolver?;
    r.type_sig(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trivial resolver for tests: function and type tables given as slices.
    struct FixedSigs<'a> {
        funcs: &'a [(u32, u32)],
        types: &'a [(u32, u32)],
    }
    impl SigResolver for FixedSigs<'_> {
        fn func_sig(&self, i: u32) -> Option<(u32, u32)> {
            self.funcs.get(i as usize).copied()
        }
        fn type_sig(&self, i: u32) -> Option<(u32, u32)> {
            self.types.get(i as usize).copied()
        }
    }

    #[test]
    fn tracks_depth_through_const_and_arith() {
        // (func  i32.const 1  i32.const 2  i32.add  drop  end)
        let body = [0, 0x41, 1, 0x41, 2, 0x6A, 0x1A, 0x0B];
        let start = opcode::skip_locals(&body).unwrap();
        let mut frames = Vec::new();
        let mut w = BlockWalker::new(&body, start, &mut frames);

        let s = w.next().unwrap(); // i32.const 1
        assert_eq!(s.stack_depth_before, 0);
        let s = w.next().unwrap(); // i32.const 2
        assert_eq!(s.stack_depth_before, 1);
        let s = w.next().unwrap(); // i32.add
        assert_eq!(s.stack_depth_before, 2);
        let s = w.next().unwrap(); // drop
        assert_eq!(s.stack_depth_before, 1);
        let s = w.next().unwrap(); // end
        assert_eq!(s.stack_depth_before, 0);
        assert!(!w.failed());
        assert_eq!(w.stack_depth(), 0);
    }

    #[test]
    fn block_entry_depth_and_fallthrough() {
        // (func
        //   i32.const 7         ;; depth 1
        //   block (result i32)  ;; entry_depth = 1 (= 1 - in_arity 0)
        //     i32.const 9       ;; depth 2
        //   end                 ;; depth restored = 1 + 1 = 2
        //   drop
        //   drop
        // )
        let body = [0, 0x41, 7, 0x02, 0x7F, 0x41, 9, 0x0B, 0x1A, 0x1A, 0x0B];
        let start = opcode::skip_locals(&body).unwrap();
        let mut frames = Vec::new();
        let mut w = BlockWalker::new(&body, start, &mut frames);

        let _ = w.next(); // i32.const 7
        let s = w.next().unwrap(); // block
        assert_eq!(s.stack_depth_before, 1);
        assert_eq!(w.frames().last().unwrap().entry_depth, 1);
        assert_eq!(w.frames().last().unwrap().fallthrough_arity, 1);

        let _ = w.next(); // i32.const 9
        assert_eq!(w.stack_depth(), 2);

        let s = w.next().unwrap(); // end (of block)
        assert_eq!(s.op, 0x0B);
        assert!(s.closed_frame.is_some());
        assert_eq!(w.stack_depth(), 2); // 1 (entry) + 1 (fallthrough)

        let _ = w.next(); // drop -> 1
        let _ = w.next(); // drop -> 0
        let _ = w.next(); // end (func)
        assert!(!w.failed());
    }

    #[test]
    fn br_marks_unreachable_until_end() {
        // (func
        //   block
        //     br 0         ;; unreachable after
        //     i32.const 9  ;; unreachable — not tracked
        //   end            ;; back to reachable
        // )
        let body = [0, 0x02, 0x40, 0x0C, 0, 0x41, 9, 0x0B, 0x0B];
        let start = opcode::skip_locals(&body).unwrap();
        let mut frames = Vec::new();
        let mut w = BlockWalker::new(&body, start, &mut frames);

        let _ = w.next(); // block
        assert!(w.reachable());
        let _ = w.next(); // br 0
        assert!(!w.reachable());
        let s = w.next().unwrap(); // i32.const (dead)
        assert!(!s.reachable_before);
        let s = w.next().unwrap(); // end of block — back to reachable
        assert_eq!(s.op, 0x0B);
        assert!(w.reachable());
        let _ = w.next(); // end of func
        assert!(!w.failed());
    }

    #[test]
    fn call_uses_resolver() {
        // (func  (call 0)  end)  where func 0 : () -> i32
        let body = [0, 0x10, 0, 0x1A, 0x0B];
        let sigs = FixedSigs {
            funcs: &[(0, 1)],
            types: &[],
        };
        let start = opcode::skip_locals(&body).unwrap();
        let mut frames = Vec::new();
        let mut w = BlockWalker::with_resolver(&body, start, &mut frames, Some(&sigs));

        let _ = w.next(); // call 0
        assert_eq!(w.stack_depth(), 1);
        let _ = w.next(); // drop
        assert_eq!(w.stack_depth(), 0);
        assert!(!w.failed());
    }

    #[test]
    fn call_without_resolver_fails() {
        let body = [0, 0x10, 0, 0x0B];
        let start = opcode::skip_locals(&body).unwrap();
        let mut frames = Vec::new();
        let mut w = BlockWalker::new(&body, start, &mut frames);
        while w.next().is_some() {}
        assert!(w.failed());
    }

    #[test]
    fn simd_opcode_fails() {
        // 0xFD is SIMD prefix — not supported.
        let body = [0, 0xFD, 0x0C, 0x0B];
        let start = opcode::skip_locals(&body).unwrap();
        let mut frames = Vec::new();
        let mut w = BlockWalker::new(&body, start, &mut frames);
        while w.next().is_some() {}
        assert!(w.failed());
    }

    #[test]
    fn reuses_caller_frames_buffer() {
        let body1 = [0, 0x02, 0x40, 0x0B, 0x0B];
        let body2 = [0, 0x03, 0x40, 0x0B, 0x0B];
        let mut frames = Vec::with_capacity(8);
        {
            let start = opcode::skip_locals(&body1).unwrap();
            let w = BlockWalker::new(&body1, start, &mut frames);
            let _: Vec<_> = w.collect();
        }
        let cap = frames.capacity();
        {
            let start = opcode::skip_locals(&body2).unwrap();
            let w = BlockWalker::new(&body2, start, &mut frames);
            let steps: Vec<_> = w.collect();
            assert_eq!(steps[0].op, 0x03);
        }
        assert_eq!(frames.capacity(), cap);
    }
}
