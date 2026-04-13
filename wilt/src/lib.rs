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
pub mod emit;
pub mod ir;
pub mod leb128;
pub mod linker_hints;
pub mod module;
pub mod mut_module;
pub mod opcode;
pub mod passes;
pub mod scan;

pub use module::WasmModule;

/// Run the pipeline to fixpoint: each iteration can enable later passes
/// (e.g. dedup frees funcs → DCE removes them → type_gc frees types).
/// Capped at a handful of iterations so a pathological no-convergence case
/// still terminates.
const MAX_FIXPOINT_ITERATIONS: usize = 6;

/// Optimise a WASM module with linker-supplied metadata. Lets passes that
/// can use closed-world / call-graph / reachability information do so;
/// passes that ignore hints behave identically to `optimise`.
///
/// As of M2: `dae` consults hints; other passes ignore them.
pub fn optimise_with_hints<H: linker_hints::LinkerHints>(input: &[u8], hints: &H) -> Vec<u8> {
    if WasmModule::parse(input).is_err() { return input.to_vec(); }
    let mut current = input.to_vec();
    for _ in 0..MAX_FIXPOINT_ITERATIONS {
        let next = optimise_once_with_hints(&current, Some(hints));
        if next == current { break; }
        current = next;
    }
    current
}

/// Optimise a WASM module. Returns the optimised bytes.
pub fn optimise(input: &[u8]) -> Vec<u8> {
    if WasmModule::parse(input).is_err() {
        return input.to_vec();
    }
    let mut current = input.to_vec();
    for _ in 0..MAX_FIXPOINT_ITERATIONS {
        let next = optimise_once(&current);
        if next == current { break; }
        current = next;
    }
    current
}

fn optimise_once(input: &[u8]) -> Vec<u8> {
    optimise_once_with_hints(input, None)
}

fn optimise_once_with_hints(input: &[u8], hints: Option<&dyn linker_hints::LinkerHints>) -> Vec<u8> {
    let Ok(mut module_in) = WasmModule::parse(input) else {
        return input.to_vec();
    };
    let after_didup = passes::dedup_imports::apply(&mut module_in);
    let Ok(mut module) = WasmModule::parse(&after_didup) else {
        return input.to_vec();
    };
    let after_dedup = passes::dedup::apply(&mut module);
    let Ok(mut module0) = WasmModule::parse(&after_dedup) else { return input.to_vec() };
    let after_dce = passes::dce::apply(&mut module0);
    let Ok(module2) = WasmModule::parse(&after_dce) else { return input.to_vec() };
    let after_type_gc = passes::type_gc::apply(&module2);
    // MutModule block: body-only passes + memory_packing all share one
    // COW view over the input. No intermediate parse/emit; unchanged bytes
    // never allocated.
    let after_mut_block: Vec<u8> = match crate::mut_module::MutModule::new(&after_type_gc) {
        Ok(mut m) => {
            passes::const_fold::apply_mut(&mut m);
            passes::vacuum::apply_mut(&mut m);
            passes::remove_unused_brs::apply_mut(&mut m);
            passes::merge_blocks::apply_mut(&mut m);
            passes::simplify_locals::apply_mut(&mut m);
            passes::devirt::apply_mut_with_hints(&mut m, hints);
            passes::inline_trivial::apply_mut_with_hints(&mut m, hints);
            passes::dead_globals::apply_mut_with_hints(&mut m, hints);
            passes::dae::apply_mut_with_hints(&mut m, hints);
            passes::reorder_locals::apply_mut(&mut m);
            passes::memory_packing::apply_mut(&mut m);
            m.serialize()
        }
        Err(_) => return input.to_vec(),
    };
    let Ok(mut module5b) = WasmModule::parse(&after_mut_block) else { return input.to_vec() };
    let after_unused_data = passes::unused_data::apply(&mut module5b);
    let Ok(mut module5c) = WasmModule::parse(&after_unused_data) else { return input.to_vec() };
    let after_unused_elem = passes::unused_elem::apply(&mut module5c);
    let Ok(mut module6) = WasmModule::parse(&after_unused_elem) else { return input.to_vec() };
    passes::reorder::apply(&mut module6)
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
