//! # wilt — WebAssembly In Link Time
//!
//! A zero-copy WASM optimizer. Parses WASM binary format directly
//! using memory-mapped input, only allocating for modified function bodies.
//!
//! ## Usage
//!
//! ```
//! let input = b"\0asm\x01\x00\x00\x00";
//! let optimised = wilt::optimise(input);
//! assert_eq!(optimised, input);
//! ```
//!
//! ## Architecture
//!
//! `WasmModule` borrows from the input buffer and records section
//! boundaries without copying data. Optimization passes scan the
//! raw bytes (e.g. for call opcodes) and produce patches. The emitter
//! copies unchanged sections verbatim and splices in modifications.

pub mod block_walker;
pub mod debug_level;
pub mod emit;
pub mod ir;
pub mod leb128;
pub mod linker_hints;
pub mod module;
pub mod mut_module;
pub mod opcode;
pub mod passes;
pub mod provenance;
pub mod remap;
pub mod scan;

pub use module::WasmModule;

/// Run the pipeline to fixpoint: each iteration can enable later passes
/// (e.g. dedup frees funcs → DCE removes them → type_gc frees types).
/// Capped at a handful of iterations so a pathological no-convergence case
/// still terminates.
const MAX_FIXPOINT_ITERATIONS: usize = 40;

/// Optimise a WASM module with linker-supplied metadata. Lets passes that
/// can use closed-world / call-graph / reachability information do so;
/// passes that ignore hints behave identically to `optimise`.
///
/// As of M2: `dae` consults hints; other passes ignore them.
pub fn optimise_with_hints<H: linker_hints::LinkerHints>(input: &[u8], hints: &H) -> Vec<u8> {
    if WasmModule::parse(input).is_err() {
        return input.to_vec();
    }
    let mut current = input.to_vec();
    let mut best = current.clone();
    for _ in 0..MAX_FIXPOINT_ITERATIONS {
        let (next, _remap) = optimise_once_with_hints(&current, Some(hints));
        if next == current {
            break;
        }
        if next.len() < best.len() {
            best = next.clone();
        }
        current = next;
    }
    best
}

/// Optimise a WASM module. Returns the optimised bytes.
///
/// Auto-derives closed-world hints (`DerivedHints::from_bytes`) so the
/// hint-aware passes fire even without explicit linker input. This is
/// sound on any self-contained `.wasm` — derivation scans exports,
/// ref.func, elements, start, etc., to identify internal functions the
/// same way a linker would. Callers with richer info (e.g. host-import
/// visibility) can still go through `optimise_with_hints` to override.
pub fn optimise(input: &[u8]) -> Vec<u8> {
    let result = optimise_inner(input);
    // Never-grow guard. Some pass combinations (DAE adding drops at
    // many call sites, LEB shifts after reorder, etc.) can produce
    // output slightly larger than the input. The contract is "wilt
    // never grows a module"; if we'd grow, return the input verbatim.
    if result.len() > input.len() {
        input.to_vec()
    } else {
        result
    }
}

/// Optimise + strip debug / source-map / name custom sections.
///
/// Matches what `wasm-opt -O` emits: drops `.debug_*`, source maps,
/// `name`, and `target_features`. Keeps `producers` (tiny). For
/// shipping builds. Use `optimise()` if name-map debugging must survive.
pub fn optimise_stripped(input: &[u8]) -> Vec<u8> {
    optimise_with_debug_level(input, debug_level::DebugLevel::None)
}

/// Optimise at a specified debug-info tier. See `debug_level::DebugLevel`.
///
/// - `None`: strip DWARF / source maps / names / target_features.
/// - `Names`: rewrite the `name` section to stay consistent with the output's index space. Drop
///   DWARF + source maps (they'd be stale).
/// - `Lines` / `Full`: fall back to `Names` in this build; Phase 2/3 of `wilt-debug-info-plan.md`
///   will wire them up. Callers pick the tier they want; the library silently delivers the highest
///   it honestly can.
pub fn optimise_with_debug_level(input: &[u8], level: debug_level::DebugLevel) -> Vec<u8> {
    use debug_level::DebugLevel;
    // Run the full pipeline, composing func-index remaps across iterations.
    let (optimised, cumulative_remap) = optimise_collecting_remap(input);

    // Safety guard: never grow.
    let core = if optimised.len() > input.len() {
        input.to_vec()
    } else {
        optimised
    };

    let effective = level.implemented_floor();
    match effective {
        DebugLevel::None => {
            let Ok(m) = WasmModule::parse(&core) else {
                return core;
            };
            let stripped = passes::strip::apply(&m, passes::strip::StripConfig::shipping());
            if stripped.len() > core.len() {
                core
            } else {
                stripped
            }
        }
        DebugLevel::Names => apply_names_tier(&core, input, &cumulative_remap),
        DebugLevel::Lines => apply_lines_tier(&core, input, &cumulative_remap),
        DebugLevel::Full => {
            // Lines + preserve the rest of the DWARF sections when
            // provably accurate (step 1); broader handling in future
            // steps.
            apply_full_tier(&core, input, &cumulative_remap)
        }
    }
}

fn apply_full_tier(optimised: &[u8], input: &[u8], remap: &remap::FuncRemap) -> Vec<u8> {
    // Build on the Lines-tier output (names rewritten, .debug_line
    // preserved-if-accurate-or-stripped). Then layer preserved .debug_*
    // sections on top when conditions permit.
    let mut out = apply_lines_tier(optimised, input, remap);

    if let Some(preserved) = passes::dwarf_full::preserve_full_debug(input, optimised, remap) {
        for (name, payload) in &preserved.sections {
            let mut custom_payload = Vec::new();
            leb128::write_u32(&mut custom_payload, name.len() as u32);
            custom_payload.extend_from_slice(name.as_bytes());
            custom_payload.extend_from_slice(payload);

            let mut sec = Vec::new();
            sec.push(module::SECTION_CUSTOM);
            leb128::write_u32(&mut sec, custom_payload.len() as u32);
            sec.extend_from_slice(&custom_payload);
            out.extend_from_slice(&sec);
        }
    }
    out
}

fn apply_lines_tier(optimised: &[u8], input: &[u8], remap: &remap::FuncRemap) -> Vec<u8> {
    // Names first (stripping DWARF in the process).
    let mut out = apply_names_tier(optimised, input, remap);

    // Then, if we can salvage an accurate .debug_line from the input,
    // splice it in. Today's criterion is strict: identity remap + byte-
    // identical code section. Follow-up commits of Phase 2b broaden
    // this to per-function preservation via gimli-backed rewriting.
    if let Some(line_bytes) = passes::dwarf_line::rewrite(input, optimised, remap) {
        let mut custom_payload = Vec::new();
        leb128::write_u32(&mut custom_payload, b".debug_line".len() as u32);
        custom_payload.extend_from_slice(b".debug_line");
        custom_payload.extend_from_slice(&line_bytes);

        let mut sec = Vec::new();
        sec.push(module::SECTION_CUSTOM);
        leb128::write_u32(&mut sec, custom_payload.len() as u32);
        sec.extend_from_slice(&custom_payload);

        out.extend_from_slice(&sec);
    }
    out
}

fn apply_names_tier(optimised: &[u8], input: &[u8], remap: &remap::FuncRemap) -> Vec<u8> {
    // Parse both modules so we can pull the input's name section and
    // emit an optimised module with the rewritten one in its place.
    let Ok(_out_m) = WasmModule::parse(optimised) else {
        return optimised.to_vec();
    };
    let Ok(in_m) = WasmModule::parse(input) else {
        return optimised.to_vec();
    };

    // Find the input's `name` custom section.
    let in_data = in_m.data();
    let name_payload = in_m.sections().iter().find_map(|s| {
        if s.id != module::SECTION_CUSTOM {
            return None;
        }
        let name = s.custom_name?.slice(in_data);
        if name != b"name" {
            return None;
        }
        // Payload starts after the name vec (name-length LEB + name bytes).
        let p = s.payload.slice(in_data);
        let (nlen, c) = leb128::read_u32(p)?;
        let start = c + nlen as usize;
        Some(&p[start..])
    });

    let Some(in_name) = name_payload else {
        // No name section in input → names-tier output has none either,
        // and we drop DWARF + source-maps. Same as strip.apply with a
        // names-preserving config minus names (since there are none).
        let cfg = passes::strip::StripConfig {
            dwarf: true,
            source_maps: true,
            producers: false,
            names: true,
            target_features: true,
        };
        return passes::strip::apply(&_out_m, cfg);
    };

    let rewritten = passes::name_section::rewrite(in_name, remap).unwrap_or_default();

    // Strip the optimised module's stale customs, then splice in the
    // rewritten `name` section.
    let strip_cfg = passes::strip::StripConfig {
        dwarf: true,
        source_maps: true,
        producers: false,
        names: true,
        target_features: true,
    };
    let stripped = passes::strip::apply(&_out_m, strip_cfg);
    if rewritten.is_empty() {
        return stripped;
    }

    // Build a new name custom section: id 0, size, name-vec "name", payload.
    let mut sec = Vec::new();
    sec.push(module::SECTION_CUSTOM);
    let mut payload = Vec::new();
    leb128::write_u32(&mut payload, 4);
    payload.extend_from_slice(b"name");
    payload.extend_from_slice(&rewritten);
    leb128::write_u32(&mut sec, payload.len() as u32);
    sec.extend_from_slice(&payload);

    // Append the new `name` section at the end. Spec allows custom
    // sections anywhere.
    let mut out = Vec::with_capacity(stripped.len() + sec.len());
    out.extend_from_slice(&stripped);
    out.extend_from_slice(&sec);
    if out.len() > input.len() {
        stripped
    } else {
        out
    }
}

/// Optimise + transform an external V3 source map.
///
/// Public entry point for workflows that carry a sibling `.wasm.map`
/// file. The input map describes the input wasm's code positions;
/// wilt's code-modifying passes invalidate those positions. This
/// function runs the full optimise pipeline and — when the
/// transformation is expressible as per-function byte-offset shifts
/// — rewrites the map so its `mappings` field stays consistent with
/// the output.
///
/// Returns `(optimised_wasm, maybe_rewritten_map)`. If map rewriting
/// would produce stale data (bodies modified beyond what our shifter
/// can express today), returns `None` for the map — callers should
/// strip the reference rather than embed a lie.
pub fn optimise_with_source_map(
    input: &[u8],
    input_map_json: Option<&str>,
) -> (Vec<u8>, Option<String>) {
    let (optimised, cumulative_remap) = optimise_collecting_remap(input);
    let core = if optimised.len() > input.len() {
        input.to_vec()
    } else {
        optimised
    };

    let Some(map_json) = input_map_json else {
        return (core, None);
    };

    // Compute per-function offsets in input and output.
    let Ok(mut in_m) = WasmModule::parse(input) else {
        return (core, Some(map_json.to_string()));
    };
    let Ok(mut out_m) = WasmModule::parse(&core) else {
        return (core, Some(map_json.to_string()));
    };
    in_m.ensure_function_bodies_parsed();
    out_m.ensure_function_bodies_parsed();

    let in_offsets = passes::dwarf_line::function_file_offsets(&in_m).unwrap_or_default();
    let out_offsets = passes::dwarf_line::function_file_offsets(&out_m).unwrap_or_default();
    let code_unchanged = code_section_bytes_from(&in_m) == code_section_bytes_from(&out_m);

    let rewritten = passes::source_map::rewrite_v3_with_shifts(
        map_json,
        &cumulative_remap,
        code_unchanged,
        &in_offsets,
        &out_offsets,
    );
    (core, rewritten)
}

fn code_section_bytes_from<'a>(m: &'a WasmModule<'a>) -> &'a [u8] {
    let data = m.data();
    m.sections()
        .iter()
        .find(|s| s.id == module::SECTION_CODE)
        .map(|s| s.full.slice(data))
        .unwrap_or(&[])
}

/// Runs the fixpoint and returns `(optimised_bytes, input→output FuncRemap)`.
fn optimise_collecting_remap(input: &[u8]) -> (Vec<u8>, remap::FuncRemap) {
    use linker_hints::DerivedHints;
    use linker_hints::LinkerHints;
    let Ok(_) = WasmModule::parse(input) else {
        return (input.to_vec(), identity_remap_for(input));
    };
    let hints = DerivedHints::from_bytes(input);
    let hints_ref: Option<&dyn LinkerHints> = hints.as_ref().map(|h| h as &dyn LinkerHints);

    let mut current = input.to_vec();
    let mut best = current.clone();
    let mut cumulative = identity_remap_for(input);
    let mut best_remap = cumulative.clone();

    for _ in 0..MAX_FIXPOINT_ITERATIONS {
        let (next, iter_remap) = optimise_once_with_hints(&current, hints_ref);
        if next == current {
            break;
        }
        cumulative = cumulative.compose(&iter_remap);
        if next.len() < best.len() {
            best = next.clone();
            best_remap = cumulative.clone();
        }
        current = next;
    }
    (best, best_remap)
}

fn optimise_inner(input: &[u8]) -> Vec<u8> {
    if WasmModule::parse(input).is_err() {
        return input.to_vec();
    }
    if let Some(hints) = linker_hints::DerivedHints::from_bytes(input) {
        return optimise_with_hints(input, &hints);
    }
    let mut current = input.to_vec();
    let mut best = current.clone();
    for _ in 0..MAX_FIXPOINT_ITERATIONS {
        let next = optimise_once(&current);
        if next == current {
            break;
        }
        if next.len() < best.len() {
            best = next.clone();
        }
        current = next;
    }
    best
}

fn identity_remap_for(bytes: &[u8]) -> remap::FuncRemap {
    use remap::FuncRemap;
    let Ok(mut m) = WasmModule::parse(bytes) else {
        return FuncRemap::identity(0);
    };
    m.ensure_function_bodies_parsed();
    let num_imports = passes::dce::count_func_imports_pub(&m);
    let num_defined = m.num_function_bodies() as u32;
    FuncRemap::identity(num_imports + num_defined)
}

fn optimise_once(input: &[u8]) -> Vec<u8> {
    optimise_once_with_hints(input, None).0
}

/// Returns `(bytes, this_iteration_remap)`. The iteration remap is
/// the composition of every index-changing pass's remap within this
/// iteration. The caller composes across iterations.
fn optimise_once_with_hints(
    input: &[u8],
    hints: Option<&dyn linker_hints::LinkerHints>,
) -> (Vec<u8>, remap::FuncRemap) {
    use remap::FuncRemap;
    let Ok(mut module_in) = WasmModule::parse(input) else {
        return (input.to_vec(), FuncRemap::identity(0));
    };
    let (after_didup, r_didup) = passes::dedup_imports::apply_with_remap(&mut module_in);
    let Ok(mut module) = WasmModule::parse(&after_didup) else {
        return (input.to_vec(), FuncRemap::identity(0));
    };
    let after_dedup = passes::dedup::apply(&mut module);
    let Ok(mut module0) = WasmModule::parse(&after_dedup) else {
        return (input.to_vec(), FuncRemap::identity(0));
    };
    let (after_dce, r_dce) = passes::dce::apply_with_remap(&mut module0);
    let Ok(module2) = WasmModule::parse(&after_dce) else {
        return (input.to_vec(), FuncRemap::identity(0));
    };
    let after_type_gc = passes::type_gc::apply(&module2);
    // MutModule block: body-only passes + memory_packing all share one
    // COW view over the input. No intermediate parse/emit; unchanged bytes
    // never allocated.
    let after_mut_block: Vec<u8> = match crate::mut_module::MutModule::new(&after_type_gc) {
        Ok(mut m) => {
            passes::const_fold::apply_mut(&mut m);
            passes::const_global::apply_mut_with_hints(&mut m, hints);
            passes::const_prop::apply_mut(&mut m);
            passes::copy_prop::apply_mut(&mut m);
            passes::branch_threading::apply_mut(&mut m);
            passes::if_fold::apply_mut(&mut m);
            passes::vacuum::apply_mut(&mut m);
            passes::cfg_dce::apply_mut(&mut m);
            passes::remove_unused_brs::apply_mut(&mut m);
            passes::merge_blocks::apply_mut(&mut m);
            passes::simplify_locals::apply_mut(&mut m);
            passes::devirt::apply_mut_with_hints(&mut m, hints);
            passes::fn_merge::apply_mut(&mut m);
            passes::inline_trivial::apply_mut_with_hints(&mut m, hints);
            passes::dead_globals::apply_mut_with_hints(&mut m, hints);
            passes::dae::apply_mut_with_hints(&mut m, hints);
            passes::pure_call_elim::apply_mut_with_hints(&mut m, hints);
            passes::reorder_locals::apply_mut(&mut m);
            passes::memory_packing::apply_mut(&mut m);
            m.serialize()
        }
        Err(_) => return (input.to_vec(), FuncRemap::identity(0)),
    };
    let Ok(mut module5b) = WasmModule::parse(&after_mut_block) else {
        return (input.to_vec(), FuncRemap::identity(0));
    };
    let after_unused_data = passes::unused_data::apply(&mut module5b);
    let Ok(mut module5c) = WasmModule::parse(&after_unused_data) else {
        return (input.to_vec(), FuncRemap::identity(0));
    };
    let after_unused_elem = passes::unused_elem::apply(&mut module5c);
    let Ok(mut module6) = WasmModule::parse(&after_unused_elem) else {
        return (input.to_vec(), FuncRemap::identity(0));
    };
    let (after_reorder, r_reorder) = passes::reorder::apply_with_remap(&mut module6);
    let Ok(mut module7) = WasmModule::parse(&after_reorder) else {
        return (after_reorder, r_didup.compose(&r_dce).compose(&r_reorder));
    };
    let (after_layout, r_layout) = passes::layout_for_compression::apply_with_remap(&mut module7);

    // Compose this iteration's remap: didup → dce → reorder → layout.
    // dedup/fn_merge/type_gc/body-mod passes are identity for func indices.
    let iter_remap = r_didup
        .compose(&r_dce)
        .compose(&r_reorder)
        .compose(&r_layout);
    (after_layout, iter_remap)
}

/// Configuration for the optimizer.
pub struct Config {
    /// Which passes to run.
    pub passes: Vec<PassKind>,
}

/// Available optimization passes.
pub enum PassKind {
    /// Remove functions not reachable from exports.
    DeadCodeElimination,
    /// Remove types not referenced by any function.
    TypeGC,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            passes: vec![PassKind::DeadCodeElimination, PassKind::TypeGC],
        }
    }
}

/// Optimise with specific configuration.
pub fn optimise_with(input: &[u8], _config: &Config) -> Vec<u8> {
    // TODO: apply configured passes
    optimise(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_minimal() {
        let input = b"\0asm\x01\x00\x00\x00";
        let output = optimise(input);
        assert_eq!(output, input);
    }

    #[test]
    fn roundtrip_with_exported_code() {
        // Build a minimal module with an exported function.
        let mut data = b"\0asm\x01\x00\x00\x00".to_vec();
        // Type section: 1 type, () -> ()
        data.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        // Function section: 1 function, type 0
        data.extend_from_slice(&[3, 2, 1, 0]);
        // Export section: 1 export, "f", function 0
        data.extend_from_slice(&[7, 5, 1, 1, b'f', 0x00, 0]);
        // Code section: 1 body, 2 bytes (0 locals, end)
        data.extend_from_slice(&[10, 4, 1, 2, 0, 0x0B]);

        let output = optimise(&data);
        assert_eq!(output, data, "exported function should survive DCE");
    }
}
