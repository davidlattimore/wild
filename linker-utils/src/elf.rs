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
pub fn x86_64_rel_type_to_string(r_type: u32) -> Cow<'static, str> {
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
        Cow::Owned(format!("Unknown x86_64 relocation type 0x{r_type:x}"))
    }
}

#[must_use]
pub fn aarch64_rel_type_to_string(r_type: u32) -> Cow<'static, str> {
    if let Some(name) = const_name_by_value![
        r_type,
        R_AARCH64_NONE,
        R_AARCH64_P32_ABS32,
        R_AARCH64_P32_COPY,
        R_AARCH64_P32_GLOB_DAT,
        R_AARCH64_P32_JUMP_SLOT,
        R_AARCH64_P32_RELATIVE,
        R_AARCH64_P32_TLS_DTPMOD,
        R_AARCH64_P32_TLS_DTPREL,
        R_AARCH64_P32_TLS_TPREL,
        R_AARCH64_P32_TLSDESC,
        R_AARCH64_P32_IRELATIVE,
        R_AARCH64_ABS64,
        R_AARCH64_ABS32,
        R_AARCH64_ABS16,
        R_AARCH64_PREL64,
        R_AARCH64_PREL32,
        R_AARCH64_PREL16,
        R_AARCH64_MOVW_UABS_G0,
        R_AARCH64_MOVW_UABS_G0_NC,
        R_AARCH64_MOVW_UABS_G1,
        R_AARCH64_MOVW_UABS_G1_NC,
        R_AARCH64_MOVW_UABS_G2,
        R_AARCH64_MOVW_UABS_G2_NC,
        R_AARCH64_MOVW_UABS_G3,
        R_AARCH64_MOVW_SABS_G0,
        R_AARCH64_MOVW_SABS_G1,
        R_AARCH64_MOVW_SABS_G2,
        R_AARCH64_LD_PREL_LO19,
        R_AARCH64_ADR_PREL_LO21,
        R_AARCH64_ADR_PREL_PG_HI21,
        R_AARCH64_ADR_PREL_PG_HI21_NC,
        R_AARCH64_ADD_ABS_LO12_NC,
        R_AARCH64_LDST8_ABS_LO12_NC,
        R_AARCH64_TSTBR14,
        R_AARCH64_CONDBR19,
        R_AARCH64_JUMP26,
        R_AARCH64_CALL26,
        R_AARCH64_LDST16_ABS_LO12_NC,
        R_AARCH64_LDST32_ABS_LO12_NC,
        R_AARCH64_LDST64_ABS_LO12_NC,
        R_AARCH64_MOVW_PREL_G0,
        R_AARCH64_MOVW_PREL_G0_NC,
        R_AARCH64_MOVW_PREL_G1,
        R_AARCH64_MOVW_PREL_G1_NC,
        R_AARCH64_MOVW_PREL_G2,
        R_AARCH64_MOVW_PREL_G2_NC,
        R_AARCH64_MOVW_PREL_G3,
        R_AARCH64_LDST128_ABS_LO12_NC,
        R_AARCH64_MOVW_GOTOFF_G0,
        R_AARCH64_MOVW_GOTOFF_G0_NC,
        R_AARCH64_MOVW_GOTOFF_G1,
        R_AARCH64_MOVW_GOTOFF_G1_NC,
        R_AARCH64_MOVW_GOTOFF_G2,
        R_AARCH64_MOVW_GOTOFF_G2_NC,
        R_AARCH64_MOVW_GOTOFF_G3,
        R_AARCH64_GOTREL64,
        R_AARCH64_GOTREL32,
        R_AARCH64_GOT_LD_PREL19,
        R_AARCH64_LD64_GOTOFF_LO15,
        R_AARCH64_ADR_GOT_PAGE,
        R_AARCH64_LD64_GOT_LO12_NC,
        R_AARCH64_LD64_GOTPAGE_LO15,
        R_AARCH64_TLSGD_ADR_PREL21,
        R_AARCH64_TLSGD_ADR_PAGE21,
        R_AARCH64_TLSGD_ADD_LO12_NC,
        R_AARCH64_TLSGD_MOVW_G1,
        R_AARCH64_TLSGD_MOVW_G0_NC,
        R_AARCH64_TLSLD_ADR_PREL21,
        R_AARCH64_TLSLD_ADR_PAGE21,
        R_AARCH64_TLSLD_ADD_LO12_NC,
        R_AARCH64_TLSLD_MOVW_G1,
        R_AARCH64_TLSLD_MOVW_G0_NC,
        R_AARCH64_TLSLD_LD_PREL19,
        R_AARCH64_TLSLD_MOVW_DTPREL_G2,
        R_AARCH64_TLSLD_MOVW_DTPREL_G1,
        R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC,
        R_AARCH64_TLSLD_MOVW_DTPREL_G0,
        R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC,
        R_AARCH64_TLSLD_ADD_DTPREL_HI12,
        R_AARCH64_TLSLD_ADD_DTPREL_LO12,
        R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC,
        R_AARCH64_TLSLD_LDST8_DTPREL_LO12,
        R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC,
        R_AARCH64_TLSLD_LDST16_DTPREL_LO12,
        R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC,
        R_AARCH64_TLSLD_LDST32_DTPREL_LO12,
        R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC,
        R_AARCH64_TLSLD_LDST64_DTPREL_LO12,
        R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC,
        R_AARCH64_TLSIE_MOVW_GOTTPREL_G1,
        R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC,
        R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21,
        R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC,
        R_AARCH64_TLSIE_LD_GOTTPREL_PREL19,
        R_AARCH64_TLSLE_MOVW_TPREL_G2,
        R_AARCH64_TLSLE_MOVW_TPREL_G1,
        R_AARCH64_TLSLE_MOVW_TPREL_G1_NC,
        R_AARCH64_TLSLE_MOVW_TPREL_G0,
        R_AARCH64_TLSLE_MOVW_TPREL_G0_NC,
        R_AARCH64_TLSLE_ADD_TPREL_HI12,
        R_AARCH64_TLSLE_ADD_TPREL_LO12,
        R_AARCH64_TLSLE_ADD_TPREL_LO12_NC,
        R_AARCH64_TLSLE_LDST8_TPREL_LO12,
        R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC,
        R_AARCH64_TLSLE_LDST16_TPREL_LO12,
        R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC,
        R_AARCH64_TLSLE_LDST32_TPREL_LO12,
        R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC,
        R_AARCH64_TLSLE_LDST64_TPREL_LO12,
        R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC,
        R_AARCH64_TLSDESC_LD_PREL19,
        R_AARCH64_TLSDESC_ADR_PREL21,
        R_AARCH64_TLSDESC_ADR_PAGE21,
        R_AARCH64_TLSDESC_LD64_LO12,
        R_AARCH64_TLSDESC_ADD_LO12,
        R_AARCH64_TLSDESC_OFF_G1,
        R_AARCH64_TLSDESC_OFF_G0_NC,
        R_AARCH64_TLSDESC_LDR,
        R_AARCH64_TLSDESC_ADD,
        R_AARCH64_TLSDESC_CALL,
        R_AARCH64_TLSLE_LDST128_TPREL_LO12,
        R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC,
        R_AARCH64_TLSLD_LDST128_DTPREL_LO12,
        R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC,
        R_AARCH64_COPY,
        R_AARCH64_GLOB_DAT,
        R_AARCH64_JUMP_SLOT,
        R_AARCH64_RELATIVE,
        R_AARCH64_TLS_DTPMOD,
        R_AARCH64_TLS_DTPREL,
        R_AARCH64_TLS_TPREL,
        R_AARCH64_TLSDESC,
        R_AARCH64_IRELATIVE
    ] {
        Cow::Borrowed(name)
    } else {
        Cow::Owned(format!("Unknown aarch64 relocation type 0x{r_type:x}"))
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

pub mod secnames {
    pub const FILEHEADER_SECTION_NAME_STR: &str = "";
    pub const FILEHEADER_SECTION_NAME: &[u8] = FILEHEADER_SECTION_NAME_STR.as_bytes();
    pub const RODATA_SECTION_NAME_STR: &str = ".rodata";
    pub const RODATA_SECTION_NAME: &[u8] = RODATA_SECTION_NAME_STR.as_bytes();
    pub const TEXT_SECTION_NAME_STR: &str = ".text";
    pub const TEXT_SECTION_NAME: &[u8] = TEXT_SECTION_NAME_STR.as_bytes();
    pub const INIT_ARRAY_SECTION_NAME_STR: &str = ".init_array";
    pub const INIT_ARRAY_SECTION_NAME: &[u8] = INIT_ARRAY_SECTION_NAME_STR.as_bytes();
    pub const FINI_ARRAY_SECTION_NAME_STR: &str = ".fini_array";
    pub const FINI_ARRAY_SECTION_NAME: &[u8] = FINI_ARRAY_SECTION_NAME_STR.as_bytes();
    pub const PREINIT_ARRAY_SECTION_NAME_STR: &str = ".preinit_array";
    pub const PREINIT_ARRAY_SECTION_NAME: &[u8] = PREINIT_ARRAY_SECTION_NAME_STR.as_bytes();
    pub const DATA_SECTION_NAME_STR: &str = ".data";
    pub const DATA_SECTION_NAME: &[u8] = DATA_SECTION_NAME_STR.as_bytes();
    pub const EH_FRAME_SECTION_NAME_STR: &str = ".eh_frame";
    pub const EH_FRAME_SECTION_NAME: &[u8] = EH_FRAME_SECTION_NAME_STR.as_bytes();
    pub const EH_FRAME_HDR_SECTION_NAME_STR: &str = ".eh_frame_hdr";
    pub const EH_FRAME_HDR_SECTION_NAME: &[u8] = EH_FRAME_HDR_SECTION_NAME_STR.as_bytes();
    pub const SHSTRTAB_SECTION_NAME_STR: &str = ".shstrtab";
    pub const SHSTRTAB_SECTION_NAME: &[u8] = SHSTRTAB_SECTION_NAME_STR.as_bytes();
    pub const SYMTAB_SECTION_NAME_STR: &str = ".symtab";
    pub const SYMTAB_SECTION_NAME: &[u8] = SYMTAB_SECTION_NAME_STR.as_bytes();
    pub const STRTAB_SECTION_NAME_STR: &str = ".strtab";
    pub const STRTAB_SECTION_NAME: &[u8] = STRTAB_SECTION_NAME_STR.as_bytes();
    pub const TDATA_SECTION_NAME_STR: &str = ".tdata";
    pub const TDATA_SECTION_NAME: &[u8] = TDATA_SECTION_NAME_STR.as_bytes();
    pub const TBSS_SECTION_NAME_STR: &str = ".tbss";
    pub const TBSS_SECTION_NAME: &[u8] = TBSS_SECTION_NAME_STR.as_bytes();
    pub const BSS_SECTION_NAME_STR: &str = ".bss";
    pub const BSS_SECTION_NAME: &[u8] = BSS_SECTION_NAME_STR.as_bytes();
    pub const GOT_SECTION_NAME_STR: &str = ".got";
    pub const GOT_SECTION_NAME: &[u8] = GOT_SECTION_NAME_STR.as_bytes();
    pub const INIT_SECTION_NAME_STR: &str = ".init";
    pub const INIT_SECTION_NAME: &[u8] = INIT_SECTION_NAME_STR.as_bytes();
    pub const FINI_SECTION_NAME_STR: &str = ".fini";
    pub const FINI_SECTION_NAME: &[u8] = FINI_SECTION_NAME_STR.as_bytes();
    pub const RELA_PLT_SECTION_NAME_STR: &str = ".rela.plt";
    pub const RELA_PLT_SECTION_NAME: &[u8] = RELA_PLT_SECTION_NAME_STR.as_bytes();
    pub const COMMENT_SECTION_NAME_STR: &str = ".comment";
    pub const COMMENT_SECTION_NAME: &[u8] = COMMENT_SECTION_NAME_STR.as_bytes();
    pub const DYNAMIC_SECTION_NAME_STR: &str = ".dynamic";
    pub const DYNAMIC_SECTION_NAME: &[u8] = DYNAMIC_SECTION_NAME_STR.as_bytes();
    pub const DYNSYM_SECTION_NAME_STR: &str = ".dynsym";
    pub const DYNSYM_SECTION_NAME: &[u8] = DYNSYM_SECTION_NAME_STR.as_bytes();
    pub const DYNSTR_SECTION_NAME_STR: &str = ".dynstr";
    pub const DYNSTR_SECTION_NAME: &[u8] = DYNSTR_SECTION_NAME_STR.as_bytes();
    pub const RELA_DYN_SECTION_NAME_STR: &str = ".rela.dyn";
    pub const RELA_DYN_SECTION_NAME: &[u8] = RELA_DYN_SECTION_NAME_STR.as_bytes();
    pub const GCC_EXCEPT_TABLE_SECTION_NAME_STR: &str = ".gcc_except_table";
    pub const GCC_EXCEPT_TABLE_SECTION_NAME: &[u8] = GCC_EXCEPT_TABLE_SECTION_NAME_STR.as_bytes();
    pub const INTERP_SECTION_NAME_STR: &str = ".interp";
    pub const INTERP_SECTION_NAME: &[u8] = INTERP_SECTION_NAME_STR.as_bytes();
    pub const GNU_VERSION_SECTION_NAME_STR: &str = ".gnu.version";
    pub const GNU_VERSION_SECTION_NAME: &[u8] = GNU_VERSION_SECTION_NAME_STR.as_bytes();
    pub const GNU_VERSION_R_SECTION_NAME_STR: &str = ".gnu.version_r";
    pub const GNU_VERSION_R_SECTION_NAME: &[u8] = GNU_VERSION_R_SECTION_NAME_STR.as_bytes();
    pub const PROGRAM_HEADERS_SECTION_NAME_STR: &str = ".phdr";
    pub const PROGRAM_HEADERS_SECTION_NAME: &[u8] = PROGRAM_HEADERS_SECTION_NAME_STR.as_bytes();
    pub const SECTION_HEADERS_SECTION_NAME_STR: &str = ".shdr";
    pub const SECTION_HEADERS_SECTION_NAME: &[u8] = SECTION_HEADERS_SECTION_NAME_STR.as_bytes();
    pub const GNU_HASH_SECTION_NAME_STR: &str = ".gnu.hash";
    pub const GNU_HASH_SECTION_NAME: &[u8] = GNU_HASH_SECTION_NAME_STR.as_bytes();
    pub const PLT_SECTION_NAME_STR: &str = ".plt";
    pub const PLT_SECTION_NAME: &[u8] = PLT_SECTION_NAME_STR.as_bytes();
    pub const PLT_GOT_SECTION_NAME_STR: &str = ".plt.got";
    pub const PLT_GOT_SECTION_NAME: &[u8] = PLT_GOT_SECTION_NAME_STR.as_bytes();
    pub const GOT_PLT_SECTION_NAME_STR: &str = ".got.plt";
    pub const GOT_PLT_SECTION_NAME: &[u8] = GOT_PLT_SECTION_NAME_STR.as_bytes();
    pub const PLT_SEC_SECTION_NAME_STR: &str = ".plt.sec";
    pub const PLT_SEC_SECTION_NAME: &[u8] = PLT_SEC_SECTION_NAME_STR.as_bytes();
    pub const NOTE_ABI_TAG_SECTION_NAME_STR: &str = ".note.ABI-tag";
    pub const NOTE_ABI_TAG_SECTION_NAME: &[u8] = NOTE_ABI_TAG_SECTION_NAME_STR.as_bytes();
    pub const NOTE_GNU_PROPERTY_SECTION_NAME_STR: &str = ".note.gnu.property";
    pub const NOTE_GNU_PROPERTY_SECTION_NAME: &[u8] = NOTE_GNU_PROPERTY_SECTION_NAME_STR.as_bytes();
    pub const NOTE_GNU_BUILD_ID_SECTION_NAME_STR: &str = ".note.gnu.build-id";
    pub const NOTE_GNU_BUILD_ID_SECTION_NAME: &[u8] = NOTE_GNU_BUILD_ID_SECTION_NAME_STR.as_bytes();
    pub const DEBUG_LOC_SECTION_NAME_STR: &str = ".debug.loc";
    pub const DEBUG_LOC_SECTION_NAME: &[u8] = DEBUG_LOC_SECTION_NAME_STR.as_bytes();
    pub const DEBUG_RANGES_SECTION_NAME_STR: &str = ".debug.ranges";
    pub const DEBUG_RANGES_SECTION_NAME: &[u8] = DEBUG_RANGES_SECTION_NAME_STR.as_bytes();
    pub const GROUP_SECTION_NAME_STR: &str = ".group";
    pub const GROUP_SECTION_NAME: &[u8] = GROUP_SECTION_NAME_STR.as_bytes();
}

/// For additional information on ELF relocation types, see "ELF-64 Object File Format" -
/// https://uclibc.org/docs/elf-64-gen.pdf. For information on the TLS related relocations, see "ELF
/// Handling For Thread-Local Storage" - https://www.uclibc.org/docs/tls.pdf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocationKind {
    /// The absolute address of a symbol or section.
    Absolute,

    /// The absolute address of a symbol or section. We are going to extract only the offset
    /// within a page, so dynamic relocation creation must be skipped.
    AbsoluteAArch64,

    /// The address of the symbol, relative to the place of the relocation.
    Relative,

    /// The address of the symbol, relative to the base address of the GOT.
    SymRelGotBase,

    /// The offset of the symbol's GOT entry, relative to the start of the GOT.
    GotRelGotBase,

    /// The address of the symbol's GOT entry.
    Got,

    /// The address of the symbol's PLT entry, relative to the base address of the GOT.
    PltRelGotBase,

    /// The address of the symbol's PLT entry, relative to the place of relocation.
    PltRelative,

    /// The address of the symbol's GOT entry, relative to the place of the relocation.
    GotRelative,

    /// The address of a TLSGD structure, relative to the place of the relocation. A TLSGD
    /// (thread-local storage general dynamic) structure is a pair of values containing a module ID
    /// and the offset within that modules TLS storage.
    TlsGd,

    /// The address of the symbol's TLSGD GOT entry.
    TlsGdGot,

    /// The address of the symbol's TLSGD GOT entry, relative to the start of the GOT.
    TlsGdGotBase,

    /// The address of the TLS module ID for the shared object that we're writing, relative to the
    /// place of the relocation. This is used when a TLS variable is defined and used within the
    /// same shared object.
    TlsLd,

    /// The address of the TLS module ID for the shared object that we're writing.
    TlsLdGot,

    /// The address of the TLS module ID for the shared object that we're writing,
    /// relative to the start of the GOT.
    TlsLdGotBase,

    /// The offset of a thread-local within the TLS storage of DSO that defines that thread-local.
    DtpOff,

    /// The address of a GOT entry containing the offset of a TLS variable within the executable's
    /// TLS storage, relative to the place of the relocation.
    GotTpOff,

    /// The address of a GOT entry containing the offset of a TLS variable within the executable's
    /// TLS storage.
    GotTpOffGot,

    /// The address of a GOT entry containing the offset of a TLS variable within the executable's
    /// TLS storage, relative to the start of the GOT.
    GotTpOffGotBase,

    /// The offset of a TLS variable within the executable's TLS storage.
    TpOff,

    /// The offset of a TLS variable within the executable's TLS storage, AArch64 TLS block layout.
    TpOffAArch64,

    /// The address of a TLS descriptor structure, relative to the place of the relocation.
    TlsDesc,

    /// The address of a TLS descriptor structure.
    TlsDescGot,

    /// The address of a TLS descriptor structure, relative to the start of the GOT.
    TlsDescGotBase,

    /// Call to the TLS descriptor trampoline. Used only as a placeholder for a linker relaxation opportunity.
    TlsDescCall,

    /// No relocation needs to be applied. Produced when we eliminate a relocation due to an
    /// optimisation.
    None,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DynamicRelocationKind {
    Copy,
    Irelative,
    DtpMod,
    DtpOff,
    TlsDesc,
    TpOff,
    Relative,
    DynamicSymbol,
    JumpSlot,
}

impl DynamicRelocationKind {
    #[must_use]
    pub fn from_x86_64_r_type(r_type: u32) -> Option<Self> {
        let kind = match r_type {
            object::elf::R_X86_64_COPY => DynamicRelocationKind::Copy,
            object::elf::R_X86_64_IRELATIVE => DynamicRelocationKind::Irelative,
            object::elf::R_X86_64_DTPMOD64 => DynamicRelocationKind::DtpMod,
            object::elf::R_X86_64_DTPOFF64 => DynamicRelocationKind::DtpOff,
            object::elf::R_X86_64_TPOFF64 => DynamicRelocationKind::TpOff,
            object::elf::R_X86_64_RELATIVE => DynamicRelocationKind::Relative,
            object::elf::R_X86_64_GLOB_DAT => DynamicRelocationKind::DynamicSymbol,
            object::elf::R_X86_64_TLSDESC => DynamicRelocationKind::TlsDesc,
            object::elf::R_X86_64_JUMP_SLOT => DynamicRelocationKind::JumpSlot,
            _ => return None,
        };

        Some(kind)
    }

    #[must_use]
    pub fn x86_64_r_type(self) -> u32 {
        match self {
            DynamicRelocationKind::Copy => object::elf::R_X86_64_COPY,
            DynamicRelocationKind::Irelative => object::elf::R_X86_64_IRELATIVE,
            DynamicRelocationKind::DtpMod => object::elf::R_X86_64_DTPMOD64,
            DynamicRelocationKind::DtpOff => object::elf::R_X86_64_DTPOFF64,
            DynamicRelocationKind::TpOff => object::elf::R_X86_64_TPOFF64,
            DynamicRelocationKind::Relative => object::elf::R_X86_64_RELATIVE,
            DynamicRelocationKind::DynamicSymbol => object::elf::R_X86_64_GLOB_DAT,
            DynamicRelocationKind::TlsDesc => object::elf::R_X86_64_TLSDESC,
            DynamicRelocationKind::JumpSlot => object::elf::R_X86_64_JUMP_SLOT,
        }
    }

    #[must_use]
    pub fn aarch64_r_type(&self) -> u32 {
        match self {
            DynamicRelocationKind::Copy => object::elf::R_AARCH64_COPY,
            DynamicRelocationKind::Irelative => object::elf::R_AARCH64_IRELATIVE,
            DynamicRelocationKind::DtpMod => object::elf::R_AARCH64_TLS_DTPMOD,
            DynamicRelocationKind::DtpOff => object::elf::R_AARCH64_TLS_DTPREL,
            DynamicRelocationKind::TpOff => object::elf::R_AARCH64_TLS_TPREL,
            DynamicRelocationKind::Relative => object::elf::R_AARCH64_RELATIVE,
            DynamicRelocationKind::DynamicSymbol => object::elf::R_AARCH64_GLOB_DAT,
            DynamicRelocationKind::TlsDesc => object::elf::R_AARCH64_TLSDESC,
            DynamicRelocationKind::JumpSlot => object::elf::R_AARCH64_JUMP_SLOT,
        }
    }
}

// Half-opened range bounded inclusively below and exclusively above: [`start``, `end`)
#[derive(Clone, Debug, Copy)]
pub struct BitRange {
    pub start: u32,
    pub end: u32,
}

#[derive(Clone, Debug, Copy)]
pub enum RelocationInstruction {
    Adr,
    Movkz,
    Movnz,
    Ldr,
    LdrRegister,
    Add,
    LdSt,
    TstBr,
    Bcond,
    JumpCall,
}

impl RelocationInstruction {
    #[must_use]
    pub fn bit_mask(&self, range: BitRange) -> [u8; 4] {
        let mut mask = [0; 4];

        // To figure out which bits are part of the relocation, we write a value with
        // all ones into a buffer that initially contains zeros.
        let all_ones = (1 << (range.end - range.start)) - 1;
        self.write_to_value(all_ones, false, &mut mask);

        // Wherever we get a 1 is part of the relocation, so invert all bits.
        for b in &mut mask {
            *b = !*b;
        }

        mask
    }
}

#[derive(Clone, Debug, Copy)]
pub enum RelocationSize {
    ByteSize(usize),
    BitMasking(BitMask),
}

impl RelocationSize {
    pub(crate) const fn bit_mask(
        bit_start: u32,
        bit_end: u32,
        instruction: RelocationInstruction,
    ) -> RelocationSize {
        Self::BitMasking(BitMask::new(instruction, bit_start, bit_end))
    }
}

#[derive(Clone, Debug, Copy)]
pub struct BitMask {
    pub instruction: RelocationInstruction,
    pub range: BitRange,
}

#[derive(Debug, Clone, Copy)]
pub enum PageMask {
    SymbolPlusAddendAndPosition,
    GotEntryAndPosition,
    GotBase,
}

#[derive(Clone, Debug, Copy)]
pub struct RelocationKindInfo {
    pub kind: RelocationKind,
    pub size: RelocationSize,
    pub mask: Option<PageMask>,
}

impl BitMask {
    #[must_use]
    pub const fn new(instruction: RelocationInstruction, bit_start: u32, bit_end: u32) -> Self {
        Self {
            instruction,
            range: BitRange {
                start: bit_start,
                end: bit_end,
            },
        }
    }
}

/// Extract range-specified ([`start`..`end`]) bits from the provided `value`.
#[must_use]
pub fn extract_bits(value: u64, start: u32, end: u32) -> u64 {
    debug_assert!(start < end);
    (value >> (start)) & ((1 << (end - start)) - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::elf::*;

    #[test]
    fn test_rel_type_to_string() {
        assert_eq!(
            &x86_64_rel_type_to_string(R_X86_64_32),
            stringify!(R_X86_64_32)
        );
        assert_eq!(
            &x86_64_rel_type_to_string(R_X86_64_GOTPC32_TLSDESC),
            stringify!(R_X86_64_GOTPC32_TLSDESC)
        );
        assert_eq!(
            &x86_64_rel_type_to_string(64),
            "Unknown x86_64 relocation type 0x40"
        );

        assert_eq!(
            &aarch64_rel_type_to_string(64),
            "Unknown aarch64 relocation type 0x40"
        );
    }

    #[test]
    fn test_bit_operations() {
        assert_eq!(0b11000, extract_bits(0b1100_0000, 3, 8));
        assert_eq!(0b1010_1010_0000, extract_bits(0b10101010_00001111, 4, 16));
        assert_eq!(u32::MAX, extract_bits(u64::MAX, 0, 32) as u32);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn test_extract_bits_wrong_range() {
        let _ = extract_bits(0, 2, 1);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn test_extract_bits_too_large() {
        let _ = extract_bits(0, 0, 100);
    }
}
