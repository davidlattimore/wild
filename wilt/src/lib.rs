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

pub mod emit;
pub mod leb128;
pub mod module;
pub mod passes;
pub mod scan;

pub use module::WasmModule;

/// Optimise a WASM module. Returns the optimised bytes.
///
/// Applies dead code elimination and type GC.
pub fn optimise(input: &[u8]) -> Vec<u8> {
    let mut module = WasmModule::parse(input).expect("invalid WASM module");
    // Pass 1: remove unreachable functions.
    let after_dce = passes::dce::apply(&mut module);
    // Pass 2: remove unused types (may be freed by DCE).
    let module2 = WasmModule::parse(&after_dce).expect("DCE produced invalid WASM");
    let after_type_gc = passes::type_gc::apply(&module2);
    // Pass 3: fold constant arithmetic.
    let module3 = WasmModule::parse(&after_type_gc).expect("type GC produced invalid WASM");
    passes::const_fold::apply(&module3)
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
