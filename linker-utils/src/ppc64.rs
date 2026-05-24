//! Relocation utilities for the ppc64 (PowerPC64 LE, ELFv2) target.
//!
//! Relocation decoding is not yet implemented; `relocation_type_from_raw` returns `None` for every
//! relocation type, which causes the linker to emit a clean "unsupported relocation" error rather
//! than producing incorrect output.

use crate::elf::RelocationKindInfo;
use crate::relaxation::RelocationModifier;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaxationKind {
    /// Leave the instruction alone. Used when we only want to change the kind of relocation used.
    NoOp,
}

impl RelaxationKind {
    pub fn apply(self, _section_bytes: &mut [u8], _offset_in_section: &mut u64, _addend: &mut i64) {
        match self {
            RelaxationKind::NoOp => {}
        }
    }

    #[must_use]
    pub fn next_modifier(&self) -> RelocationModifier {
        RelocationModifier::Normal
    }
}

#[must_use]
pub const fn relocation_type_from_raw(_r_type: u32) -> Option<RelocationKindInfo> {
    None
}
