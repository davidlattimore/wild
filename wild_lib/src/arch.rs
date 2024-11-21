//! Abstraction over different CPU architectures.

use crate::args::OutputKind;
use crate::relaxation::RelocationModifier;
use crate::resolution::ValueFlags;
use linker_utils::elf::SectionFlags;

pub(crate) trait Arch {
    type Relaxation: Relaxation;
}

pub(crate) trait Relaxation {
    /// Tries to create a relaxation for the relocation of the specified kind, to be applied at the
    /// specified offset in the supplied section.
    fn new(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        value_flags: ValueFlags,
        output_kind: OutputKind,
        section_flags: SectionFlags,
    ) -> Option<Self>
    where
        Self: std::marker::Sized;

    fn apply(
        &self,
        section_bytes: &mut [u8],
        offset_in_section: &mut u64,
        addend: &mut u64,
        next_modifier: &mut RelocationModifier,
    );

    fn rel_info(&self) -> crate::elf::RelocationKindInfo;

    fn debug_kind(&self) -> impl std::fmt::Debug;
}
