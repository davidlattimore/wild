//! Reorder defined function bodies so that adjacent functions share
//! more bytes — making the output more compressible (gzip/brotli).
//!
//! Wasm-opt does call-frequency-based reordering for cache locality
//! but doesn't aim at compression. This pass IS for the wire bytes.
//!
//! Strategy (first cut): sort defined functions by body bytes
//! lexicographically. Functions with the same opcode prefix (common
//! in toolchain-emitted helpers — `local.get 0; local.get 1; ...`)
//! cluster naturally. The compressor's sliding window catches the
//! shared bytes as back-references.
//!
//! Sound — re-uses `passes::reorder::apply_with_order` which already
//! renumbers `call`/`ref.func`/element/export/start/global-init
//! references when the function index space permutes.
//!
//! Skipped when a smarter heuristic might lose: only fires when the
//! resulting order isn't already alphabetical (== fixed-point).
//!
//! Future work: shingle-set Jaccard / SimHash for smarter clustering;
//! data-segment reordering; type-section reordering. This MVP just
//! tests whether the technique pays at all on the binaryen corpus.

use crate::module::WasmModule;
use crate::opcode::InstrIter;
use crate::opcode::{self};

/// Conservative: any function type whose params or results include a
/// non-pure-numeric valtype (anything outside i32/i64/f32/f64/v128).
fn any_func_type_uses_non_numeric_valtypes(module: &WasmModule<'_>) -> bool {
    use crate::leb128;
    let Some(sec) = module.section(crate::module::SECTION_TYPE) else {
        return false;
    };
    let p = sec.payload.slice(module.data());
    let Some((count, mut off)) = leb128::read_u32(p) else {
        return true;
    };
    for _ in 0..count {
        let Some(&form) = p.get(off) else { return true };
        if form != 0x60 {
            return true;
        } // non-func type: bail
        off += 1;
        for _section in 0..2 {
            // params, then results
            let Some((n, c)) = leb128::read_u32(p.get(off..).unwrap_or(&[])) else {
                return true;
            };
            off += c;
            for _ in 0..n {
                let Some(&vt) = p.get(off) else { return true };
                off += 1;
                if !matches!(vt, 0x7B..=0x7F) {
                    return true;
                }
            }
        }
    }
    false
}

fn any_body_has_advanced_features(module: &WasmModule<'_>) -> bool {
    let data = module.data();
    for body in module.function_bodies() {
        let b = body.body.slice(data);
        let Some(start) = opcode::skip_locals(b) else {
            return true;
        };
        let mut iter = InstrIter::new(b, start);
        while let Some((p, _)) = iter.next() {
            match b[p] {
                0xFB | 0xFD | 0xFE | 0x06 | 0x07 | 0x08 | 0x09 | 0x18 | 0x1F => return true,
                _ => {}
            }
        }
    }
    false
}

pub fn apply(module: &mut WasmModule<'_>) -> Vec<u8> {
    apply_with_remap(module).0
}

pub fn apply_with_remap(module: &mut WasmModule<'_>) -> (Vec<u8>, crate::remap::FuncRemap) {
    module.ensure_function_bodies_parsed();
    let num_defined = module.num_function_bodies() as u32;
    let num_imports = super::dce::count_func_imports_pub(module);
    let total = num_imports + num_defined;
    if num_defined < 2 {
        return (
            module.data().to_vec(),
            crate::remap::FuncRemap::identity(total),
        );
    }

    // Bail on bodies we can't fully decode (GC opcodes etc.) — the
    // emit path's call-rewriter would silently miss references it
    // can't see, leaving stale function indices. apply_with_order
    // also has this guard but bailing here is clearer.
    if !super::dce::all_bodies_walkable(module) {
        return (
            module.data().to_vec(),
            crate::remap::FuncRemap::identity(total),
        );
    }
    // Conservative: bail if any body uses GC/SIMD/atomics/EH prefix
    // opcodes. Our function-index renumbering doesn't account for
    // edge-case references those families might have.
    if any_body_has_advanced_features(module) {
        return (
            module.data().to_vec(),
            crate::remap::FuncRemap::identity(total),
        );
    }
    // Extra-conservative: bail if any function type uses non-numeric
    // valtypes. Modules with externref / typed function refs / GC types
    // hit edge cases in the renumbering that we don't fully model.
    if any_func_type_uses_non_numeric_valtypes(module) {
        return (
            module.data().to_vec(),
            crate::remap::FuncRemap::identity(total),
        );
    }

    let data = module.data();

    // Collect (orig_abs_idx, body_bytes) pairs.
    let mut entries: Vec<(u32, &[u8])> = (0..num_defined as usize)
        .map(|i| {
            let abs = num_imports + i as u32;
            let body = module.function_bodies()[i].body.slice(data);
            (abs, body)
        })
        .collect();
    // Sort lexicographically by body bytes. Stable on equal bodies
    // (preserves the relative order — fn_merge handles dedup).
    entries.sort_by(|a, b| a.1.cmp(b.1));
    let order: Vec<u32> = entries.into_iter().map(|(abs, _)| abs).collect();

    // The top-level `optimise` never-grow guard catches the
    // uncommon case where layout's LEB-shift grows raw bytes. Keep
    // the reordering here unconditional so compressed wins stay.
    super::reorder::apply_with_order_remap(module, order)
}
