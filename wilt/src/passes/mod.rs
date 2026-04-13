/// Optimization passes.
///
/// Each pass takes a `WasmModule` and returns modifications to apply.
/// Passes don't modify the module directly — they produce patches
/// that the emitter applies.

pub mod branch_threading;
pub mod cfg_dce;
pub mod compress;
pub mod const_fold;
pub mod const_prop;
pub mod dae;
pub mod dce;
pub mod dead_globals;
pub mod devirt;
pub mod dedup;
pub mod dedup_imports;
pub mod inline_trivial;
pub mod memory_packing;
pub mod merge_blocks;
pub mod remove_unused_brs;
pub mod reorder;
pub mod reorder_locals;
pub mod simplify_locals;
pub mod strip;
pub mod type_gc;
pub mod unused_data;
pub mod unused_elem;

pub mod vacuum;
