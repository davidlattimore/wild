use crate::bail;
use crate::error::Result;
use object::elf::EM_AARCH64;
use object::elf::EM_LOONGARCH;
use object::elf::EM_PPC64;
use object::elf::EM_RISCV;
use object::elf::EM_X86_64;
use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Architecture {
    X86_64,
    AArch64,
    RiscV64,
    LoongArch64,
    Ppc64,
    Unsupported,
}

impl TryFrom<object::elf::Machine> for Architecture {
    type Error = crate::error::Error;

    fn try_from(arch: object::elf::Machine) -> Result<Self, Self::Error> {
        match arch {
            EM_X86_64 => Ok(Self::X86_64),
            EM_AARCH64 => Ok(Self::AArch64),
            EM_RISCV => Ok(Self::RiscV64),
            EM_LOONGARCH => Ok(Self::LoongArch64),
            EM_PPC64 => Ok(Self::Ppc64),
            _ => bail!("Unsupported architecture: 0x{:x}", arch),
        }
    }
}

impl Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let arch = match self {
            Architecture::X86_64 => "x86_64",
            Architecture::AArch64 => "aarch64",
            Architecture::RiscV64 => "riscv64",
            Architecture::LoongArch64 => "loongarch64",
            Architecture::Ppc64 => "ppc64",
            Architecture::Unsupported => "unsupported",
        };
        write!(f, "{arch}")
    }
}

impl Architecture {
    pub(crate) fn parse_output_format(format: &[u8]) -> Self {
        let Some(format) = format.strip_prefix(b"elf64-") else {
            return Self::Unsupported;
        };

        match format {
            b"x86-64" => Self::X86_64,
            b"aarch64" | b"littleaarch64" => Self::AArch64,
            b"littleriscv" => Self::RiscV64,
            b"loongarch" => Self::LoongArch64,
            b"powerpcle" => Self::Ppc64,
            _ => Self::Unsupported,
        }
    }
}

pub(crate) const SUPPORTED_TARGETS: &str =
    "elf64-x86-64 elf64-littleaarch64 elf64-littleriscv elf64-loongarch elf64-powerpcle";
