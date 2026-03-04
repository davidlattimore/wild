use crate::bail;
use crate::error::Result;
use object::elf::EM_AARCH64;
use object::elf::EM_LOONGARCH;
use object::elf::EM_RISCV;
use object::elf::EM_X86_64;
use object::pe::IMAGE_FILE_MACHINE_AMD64;
use object::pe::IMAGE_FILE_MACHINE_ARM64;
use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Architecture {
    X86_64,
    AArch64,
    RISCV64,
    LoongArch64,
}

impl Default for Architecture {
    fn default() -> Self {
        Architecture::DEFAULT
    }
}

impl Architecture {
    pub const DEFAULT: Self = const {
        #[cfg(target_arch = "x86_64")]
        {
            Architecture::X86_64
        }
        #[cfg(target_arch = "aarch64")]
        {
            Architecture::AArch64
        }
        #[cfg(target_arch = "riscv64")]
        {
            Architecture::RISCV64
        }
    };
}

impl TryFrom<u16> for Architecture {
    type Error = crate::error::Error;

    fn try_from(arch: u16) -> Result<Self, Self::Error> {
        match arch {
            EM_X86_64 | IMAGE_FILE_MACHINE_AMD64 => Ok(Self::X86_64),
            EM_AARCH64 | IMAGE_FILE_MACHINE_ARM64 => Ok(Self::AArch64),
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
