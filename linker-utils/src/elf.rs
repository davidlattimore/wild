use object::read::elf::SectionHeader;
use object::LittleEndian;
use std::borrow::Cow;

macro_rules! const_name_by_value {
    ($needle: expr, $( $const:ident ),*) => {
        match $needle {
            $(object::elf::$const => Some(stringify!($const)),)*
            _ => None
        }
    };
}

#[must_use]
pub fn rel_type_to_string(r_type: u32) -> Cow<'static, str> {
    if let Some(name) = const_name_by_value![
        r_type,
        R_X86_64_NONE,
        R_X86_64_64,
        R_X86_64_PC32,
        R_X86_64_GOT32,
        R_X86_64_PLT32,
        R_X86_64_COPY,
        R_X86_64_GLOB_DAT,
        R_X86_64_JUMP_SLOT,
        R_X86_64_RELATIVE,
        R_X86_64_GOTPCREL,
        R_X86_64_32,
        R_X86_64_32S,
        R_X86_64_16,
        R_X86_64_PC16,
        R_X86_64_8,
        R_X86_64_PC8,
        R_X86_64_DTPMOD64,
        R_X86_64_DTPOFF64,
        R_X86_64_TPOFF64,
        R_X86_64_TLSGD,
        R_X86_64_TLSLD,
        R_X86_64_DTPOFF32,
        R_X86_64_GOTTPOFF,
        R_X86_64_TPOFF32,
        R_X86_64_PC64,
        R_X86_64_GOTOFF64,
        R_X86_64_GOTPC32,
        R_X86_64_GOT64,
        R_X86_64_GOTPCREL64,
        R_X86_64_GOTPC64,
        R_X86_64_GOTPLT64,
        R_X86_64_PLTOFF64,
        R_X86_64_SIZE32,
        R_X86_64_SIZE64,
        R_X86_64_GOTPC32_TLSDESC,
        R_X86_64_TLSDESC_CALL,
        R_X86_64_TLSDESC,
        R_X86_64_IRELATIVE,
        R_X86_64_RELATIVE64,
        R_X86_64_GOTPCRELX,
        R_X86_64_REX_GOTPCRELX
    ] {
        Cow::Borrowed(name)
    } else {
        Cow::Owned(format!("Unknown relocation type 0x{r_type:x}"))
    }
}

/// Section flag bit values.
pub mod shf {
    use super::SectionFlags;

    pub const WRITE: SectionFlags = SectionFlags::from_u32(object::elf::SHF_WRITE);
    pub const ALLOC: SectionFlags = SectionFlags::from_u32(object::elf::SHF_ALLOC);
    pub const EXECINSTR: SectionFlags = SectionFlags::from_u32(object::elf::SHF_EXECINSTR);
    pub const MERGE: SectionFlags = SectionFlags::from_u32(object::elf::SHF_MERGE);
    pub const STRINGS: SectionFlags = SectionFlags::from_u32(object::elf::SHF_STRINGS);
    pub const INFO_LINK: SectionFlags = SectionFlags::from_u32(object::elf::SHF_INFO_LINK);
    pub const LINK_ORDER: SectionFlags = SectionFlags::from_u32(object::elf::SHF_LINK_ORDER);
    pub const OS_NONCONFORMING: SectionFlags =
        SectionFlags::from_u32(object::elf::SHF_OS_NONCONFORMING);
    pub const GROUP: SectionFlags = SectionFlags::from_u32(object::elf::SHF_GROUP);
    pub const TLS: SectionFlags = SectionFlags::from_u32(object::elf::SHF_TLS);
    pub const COMPRESSED: SectionFlags = SectionFlags::from_u32(object::elf::SHF_COMPRESSED);
    pub const GNU_RETAIN: SectionFlags = SectionFlags::from_u32(object::elf::SHF_GNU_RETAIN);
}

pub mod sht {
    use super::SectionType;

    pub const NULL: SectionType = SectionType(object::elf::SHT_NULL);
    pub const PROGBITS: SectionType = SectionType(object::elf::SHT_PROGBITS);
    pub const SYMTAB: SectionType = SectionType(object::elf::SHT_SYMTAB);
    pub const STRTAB: SectionType = SectionType(object::elf::SHT_STRTAB);
    pub const RELA: SectionType = SectionType(object::elf::SHT_RELA);
    pub const HASH: SectionType = SectionType(object::elf::SHT_HASH);
    pub const DYNAMIC: SectionType = SectionType(object::elf::SHT_DYNAMIC);
    pub const NOTE: SectionType = SectionType(object::elf::SHT_NOTE);
    pub const NOBITS: SectionType = SectionType(object::elf::SHT_NOBITS);
    pub const REL: SectionType = SectionType(object::elf::SHT_REL);
    pub const SHLIB: SectionType = SectionType(object::elf::SHT_SHLIB);
    pub const DYNSYM: SectionType = SectionType(object::elf::SHT_DYNSYM);
    pub const INIT_ARRAY: SectionType = SectionType(object::elf::SHT_INIT_ARRAY);
    pub const FINI_ARRAY: SectionType = SectionType(object::elf::SHT_FINI_ARRAY);
    pub const PREINIT_ARRAY: SectionType = SectionType(object::elf::SHT_PREINIT_ARRAY);
    pub const GROUP: SectionType = SectionType(object::elf::SHT_GROUP);
    pub const SYMTAB_SHNDX: SectionType = SectionType(object::elf::SHT_SYMTAB_SHNDX);
    pub const LOOS: SectionType = SectionType(object::elf::SHT_LOOS);
    pub const GNU_ATTRIBUTES: SectionType = SectionType(object::elf::SHT_GNU_ATTRIBUTES);
    pub const GNU_HASH: SectionType = SectionType(object::elf::SHT_GNU_HASH);
    pub const GNU_LIBLIST: SectionType = SectionType(object::elf::SHT_GNU_LIBLIST);
    pub const CHECKSUM: SectionType = SectionType(object::elf::SHT_CHECKSUM);
    pub const LOSUNW: SectionType = SectionType(object::elf::SHT_LOSUNW);
    pub const SUNW_COMDAT: SectionType = SectionType(object::elf::SHT_SUNW_COMDAT);
    pub const SUNW_SYMINFO: SectionType = SectionType(object::elf::SHT_SUNW_syminfo);
    pub const GNU_VERDEF: SectionType = SectionType(object::elf::SHT_GNU_VERDEF);
    pub const GNU_VERNEED: SectionType = SectionType(object::elf::SHT_GNU_VERNEED);
    pub const GNU_VERSYM: SectionType = SectionType(object::elf::SHT_GNU_VERSYM);
    pub const HISUNW: SectionType = SectionType(object::elf::SHT_HISUNW);
    pub const HIOS: SectionType = SectionType(object::elf::SHT_HIOS);
    pub const LOPROC: SectionType = SectionType(object::elf::SHT_LOPROC);
    pub const HIPROC: SectionType = SectionType(object::elf::SHT_HIPROC);
    pub const LOUSER: SectionType = SectionType(object::elf::SHT_LOUSER);
    pub const HIUSER: SectionType = SectionType(object::elf::SHT_HIUSER);
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SectionFlags(u32);

impl SectionFlags {
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[must_use]
    pub fn from_header(header: &object::elf::SectionHeader64<LittleEndian>) -> Self {
        Self(header.sh_flags(LittleEndian) as u32)
    }

    #[must_use]
    pub fn contains(self, flag: SectionFlags) -> bool {
        self.0 & flag.0 != 0
    }

    #[must_use]
    pub const fn from_u32(raw: u32) -> SectionFlags {
        SectionFlags(raw)
    }

    /// Returns self with the specified flags set.
    #[must_use]
    pub const fn with(self, flags: SectionFlags) -> SectionFlags {
        SectionFlags(self.0 | flags.0)
    }

    /// Returns self with the specified flags cleared.
    #[must_use]
    pub const fn without(self, flags: SectionFlags) -> SectionFlags {
        SectionFlags(self.0 & !flags.0)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0 as u64
    }

    #[must_use]
    pub fn should_retain(&self) -> bool {
        self.contains(shf::GNU_RETAIN)
    }
}

impl From<u64> for SectionFlags {
    fn from(value: u64) -> Self {
        Self(value as u32)
    }
}

impl std::fmt::Display for SectionFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.contains(shf::WRITE) {
            f.write_str("W")?;
        }
        if self.contains(shf::ALLOC) {
            f.write_str("A")?;
        }
        if self.contains(shf::EXECINSTR) {
            f.write_str("X")?;
        }
        if self.contains(shf::MERGE) {
            f.write_str("M")?;
        }
        if self.contains(shf::STRINGS) {
            f.write_str("S")?;
        }
        if self.contains(shf::INFO_LINK) {
            f.write_str("I")?;
        }
        if self.contains(shf::LINK_ORDER) {
            f.write_str("L")?;
        }
        if self.contains(shf::OS_NONCONFORMING) {
            f.write_str("O")?;
        }
        if self.contains(shf::GROUP) {
            f.write_str("G")?;
        }
        if self.contains(shf::TLS) {
            f.write_str("T")?;
        }
        if self.contains(shf::COMPRESSED) {
            f.write_str("C")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for SectionFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self, f)
    }
}

impl std::ops::BitOrAssign for SectionFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionType(u32);

impl SectionType {
    #[must_use]
    pub fn raw(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn from_header(header: &object::elf::SectionHeader64<LittleEndian>) -> Self {
        Self(header.sh_type(LittleEndian))
    }

    #[must_use]
    pub fn from_u32(raw: u32) -> Self {
        Self(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::elf::*;

    #[test]
    fn test_rel_type_to_string() {
        assert_eq!(&rel_type_to_string(R_X86_64_32), stringify!(R_X86_64_32));
        assert_eq!(
            &rel_type_to_string(R_X86_64_GOTPC32_TLSDESC),
            stringify!(R_X86_64_GOTPC32_TLSDESC)
        );
        assert_eq!(&rel_type_to_string(64), "Unknown relocation type 0x40");
    }
}
