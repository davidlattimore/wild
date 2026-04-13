//! IR layers shared across passes.
//!
//! - [`body`] — per-body decoded instruction index. Compact, lazy
//!   immediate decode. Sufficient for passes that need O(1)
//!   instruction addressing but no control-flow understanding.
//! - [`cfg`] — basic-block graph layered on `BodyIr`. Needed by
//!   reaching-defs, copy-prop, devirt, and any pass that wants to
//!   reason across control-flow boundaries.

pub mod body;
pub mod cfg;

pub use body::{BodyIr, Instr};
pub use cfg::{BasicBlock, BlockEdge, CfgIr};
