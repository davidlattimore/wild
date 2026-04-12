/// Optimization passes.
///
/// Each pass takes a `WasmModule` and returns modifications to apply.
/// Passes don't modify the module directly — they produce patches
/// that the emitter applies.

pub mod compress;
pub mod const_fold;
pub mod dce;
pub mod type_gc;
