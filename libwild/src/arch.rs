//! Abstraction over different CPU architectures.

use crate::args::OutputKind;
use crate::elf::DynamicRelocationKind;
use crate::elf::RelocationKindInfo;
use crate::error::Result;
use crate::resolution::ValueFlags;
use anyhow::bail;
use linker_utils::elf::SectionFlags;
use linker_utils::relaxation::RelocationModifier;
use std::borrow::Cow;
use std::str::FromStr;

pub(crate) trait Arch {
    type Relaxation: Relaxation;

    // Get ELF header magic for the architecture.
    fn elf_header_arch_magic() -> u16;

    // Get dynamic relocation value specific for the architecture.
    fn get_dynamic_relocation_type(relocation: DynamicRelocationKind) -> u32;

    // Write PLT entry for the architecture.
    fn write_plt_entry(plt_entry: &mut [u8], got_address: u64, plt_address: u64) -> Result;

    // Make architecture-specific parsing of the relocation types.
    fn relocation_from_raw(r_type: u32) -> Result<RelocationKindInfo>;

    // Get string representation of a relocation specific for the architecture.
    fn rel_type_to_string(r_type: u32) -> Cow<'static, str>;
}

pub(crate) enum Architecture {
    X86_64,
    AArch64,
}

impl FromStr for Architecture {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "elf_x86_64" => Ok(Architecture::X86_64),
            "aarch64elf" | "aarch64linux" => Ok(Architecture::AArch64),
            _ => bail!("-m {s} is not yet supported"),
        }
    }
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

    fn apply(&self, section_bytes: &mut [u8], offset_in_section: &mut u64, addend: &mut u64);

    fn rel_info(&self) -> crate::elf::RelocationKindInfo;

    fn debug_kind(&self) -> impl std::fmt::Debug;

    fn next_modifier(&self) -> RelocationModifier;
}
