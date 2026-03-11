use crate::bail;
use crate::error::Result;
use object::elf::EM_AARCH64;
use object::elf::EM_LOONGARCH;
use object::elf::EM_RISCV;
use object::elf::EM_X86_64;
use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Architecture {
    X86_64,
    AArch64,
    RISCV64,
    LoongArch64,
}

impl Architecture {
    /// Convert a `target_lexicon::Architecture` to an `Architecture`.
    /// Panics if the architecture is not supported.
    pub const fn from_target_lexicon(arch: target_lexicon::Architecture) -> Self {
        match arch {
            target_lexicon::Architecture::X86_64 => Self::X86_64,
            target_lexicon::Architecture::Aarch64(_) => Self::AArch64,
            target_lexicon::Architecture::Riscv64(_) => Self::RISCV64,
            target_lexicon::Architecture::LoongArch64 => Self::LoongArch64,
            _ => panic!("Unsupported architecture"),
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
            EM_LOONGARCH => Ok(Self::LoongArch64),
            _ => bail!("Unsupported architecture: 0x{:x}", arch),
        }
    }
}

impl Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let arch = match self {
            Architecture::X86_64 => "x86_64",
            Architecture::AArch64 => "aarch64",
            Architecture::RISCV64 => "riscv64",
            Architecture::LoongArch64 => "loongarch64",
        };
        write!(f, "{arch}")
    }
}
