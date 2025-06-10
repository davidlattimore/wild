//! Abstraction over different CPU architectures.

use crate::args::OutputKind;
use crate::bail;
use crate::error::Result;
use crate::resolution::ValueFlags;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::SectionFlags;
use linker_utils::relaxation::RelocationModifier;
use object::elf::EM_AARCH64;
use object::elf::EM_RISCV;
use object::elf::EM_X86_64;
use std::borrow::Cow;
use std::str::FromStr;

// Based on the following article: https://maskray.me/blog/2021-02-14-all-about-thread-local-storage#tls-variants
// There are 2 variants where are TCB (thread control block) placed relative to the thread pointer ($tp).
pub(crate) enum TcbPlacement {
    // TP is placed at the end of TCB.
    BeforeTp,
    // TP is placed at the beginning of TCB.
    AfterTp,
}

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

    // Get DTV OFFSET.
    fn get_dtv_offset() -> u64 {
        0
    }

    // Some architectures use debug info relocation that depend on local symbols.
    fn local_symbols_in_debug_info() -> bool;

    // Get TCB placement variant.
    fn tcb_placement() -> TcbPlacement;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Architecture {
    X86_64,
    AArch64,
    RISCV64,
}

impl FromStr for Architecture {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "elf_x86_64" => Ok(Architecture::X86_64),
            "aarch64elf" | "aarch64linux" => Ok(Architecture::AArch64),
            "elf64lriscv" => Ok(Architecture::RISCV64),
            _ => bail!("-m {s} is not yet supported"),
        }
    }
}

impl TryFrom<u16> for Architecture {
    type Error = crate::error::Error;

    fn try_from(arch: u16) -> Result<Self, Self::Error> {
        match arch {
            EM_X86_64 => Ok(Self::X86_64),
            EM_AARCH64 => Ok(Self::AArch64),
            EM_RISCV => Ok(Self::RISCV64),
            _ => bail!("Unsupported architecture: 0x{:x}", arch),
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
        non_zero_address: bool,
    ) -> Option<Self>
    where
        Self: std::marker::Sized;

    fn apply(&self, section_bytes: &mut [u8], offset_in_section: &mut u64, addend: &mut i64);

    fn rel_info(&self) -> RelocationKindInfo;

    fn debug_kind(&self) -> impl std::fmt::Debug;

    fn next_modifier(&self) -> RelocationModifier;
}
