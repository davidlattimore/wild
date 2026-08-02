//! The object crate provides traits that allow us to abstract over 32/64 bit classes when reading
//! from ELF structs. It doesn't currently provide any equivalent for writing. The write support in
//! object is much higher level and not suitable for our uses. In this module, we define our own
//! traits to abstract over writing to these structs.

use crate::Result;
use crate::error;
use object::LittleEndian;
use object::elf::SectionFlags;

pub(crate) trait WritableFileHeader {
    const CLASS: object::elf::FileClass;
    fn ident_mut(&mut self) -> &mut object::elf::Ident;
    fn set_type(&mut self, value: object::elf::FileType);
    fn set_machine(&mut self, value: object::elf::Machine);
    fn set_version(&mut self, value: u32);
    fn set_entry(&mut self, value: u64) -> Result;
    fn set_program_header_offset(&mut self, value: u64) -> Result;
    fn set_section_header_offset(&mut self, value: u64) -> Result;
    fn set_flags(&mut self, value: object::elf::FileFlags);
    fn set_header_size(&mut self, value: u16);
    fn set_program_header_entry_size(&mut self, value: u16);
    fn set_program_header_count(&mut self, value: u16);
    fn set_section_header_entry_size(&mut self, value: u16);
    fn set_section_header_count(&mut self, value: u16);
    fn set_section_name_table_index(&mut self, value: object::elf::SymbolSection);
}

pub(crate) trait WritableProgramHeader {
    fn set_type(&mut self, value: object::elf::ProgramType);
    fn set_flags(&mut self, value: object::elf::ProgramFlags);
    fn set_offset(&mut self, value: u64) -> Result;
    fn set_virtual_address(&mut self, value: u64) -> Result;
    fn set_physical_address(&mut self, value: u64) -> Result;
    fn set_file_size(&mut self, value: u64) -> Result;
    fn set_memory_size(&mut self, value: u64) -> Result;
    fn set_alignment(&mut self, value: u64) -> Result;
}

pub(crate) trait WritableSectionHeader {
    fn set_name(&mut self, value: u32);
    fn set_type(&mut self, value: object::elf::SectionType);
    fn set_flags(&mut self, value: SectionFlags) -> Result;
    fn set_address(&mut self, value: u64) -> Result;
    fn set_offset(&mut self, value: u64) -> Result;
    fn set_size(&mut self, value: u64) -> Result;
    fn set_link(&mut self, value: u32);
    fn set_info(&mut self, value: u32);
    fn set_alignment(&mut self, value: u64) -> Result;
    fn set_entry_size(&mut self, value: u64) -> Result;
}

pub(crate) trait WritableCompressionHeader {
    fn set_type(&mut self, value: object::elf::CompressionType);
    fn set_size(&mut self, value: u64) -> Result;
    fn set_alignment(&mut self, value: u64) -> Result;
}

pub(crate) trait WritableSymbol {
    fn set_name(&mut self, value: u32);
    fn set_info(&mut self, value: object::elf::SymbolInfo);
    fn set_binding_and_type(
        &mut self,
        binding: object::elf::SymbolBind,
        symbol_type: object::elf::SymbolType,
    );
    fn set_other(&mut self, value: object::elf::SymbolOther);
    fn set_visibility(&mut self, value: object::elf::SymbolVisibility);
    fn set_section(&mut self, value: object::elf::SymbolSection);
    fn set_value(&mut self, value: u64) -> Result;
    fn set_size(&mut self, value: u64) -> Result;
}

pub(crate) trait WritableDynamicEntry {
    fn set_tag(&mut self, value: object::elf::DynamicTag) -> Result;
    fn set_value(&mut self, value: u64) -> Result;
}

pub(crate) trait WritableRela {
    fn set_offset(&mut self, value: u64) -> Result;
    fn set_addend(&mut self, value: i64) -> Result;
    fn set_info(&mut self, symbol: u32, r_type: object::elf::RelocationType) -> Result;
}

pub(crate) trait WritableRelr: Send + Sync {
    fn set_value(&mut self, value: u64) -> Result;
}

pub(crate) trait WritableNoteHeader {
    fn set_name_size(&mut self, value: u32);
    fn set_descriptor_size(&mut self, value: u32);
    fn set_type(&mut self, value: object::elf::NoteType);
}

fn narrow_u32(value: u64, field: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| error!("{field} value 0x{value:x} does not fit in ELF32"))
}

fn narrow_i32(value: i64, field: &str) -> Result<i32> {
    i32::try_from(value).map_err(|_| error!("{field} value {value} does not fit in ELF32"))
}

#[allow(clippy::unnecessary_wraps)]
fn identity_u64(value: u64, _field: &str) -> Result<u64> {
    Ok(value)
}

macro_rules! impl_file_header {
    ($ty:ty, $class:expr, $narrow:expr) => {
        impl WritableFileHeader for $ty {
            const CLASS: object::elf::FileClass = $class;
            fn ident_mut(&mut self) -> &mut object::elf::Ident {
                &mut self.e_ident
            }
            fn set_type(&mut self, value: object::elf::FileType) {
                self.e_type.set(LittleEndian, value);
            }
            fn set_machine(&mut self, value: object::elf::Machine) {
                self.e_machine.set(LittleEndian, value);
            }
            fn set_version(&mut self, value: u32) {
                self.e_version.set(LittleEndian, value);
            }
            fn set_entry(&mut self, value: u64) -> Result {
                self.e_entry.set(LittleEndian, $narrow(value, "e_entry")?);
                Ok(())
            }
            fn set_program_header_offset(&mut self, value: u64) -> Result {
                self.e_phoff.set(LittleEndian, $narrow(value, "e_phoff")?);
                Ok(())
            }
            fn set_section_header_offset(&mut self, value: u64) -> Result {
                self.e_shoff.set(LittleEndian, $narrow(value, "e_shoff")?);
                Ok(())
            }
            fn set_flags(&mut self, value: object::elf::FileFlags) {
                self.e_flags.set(LittleEndian, value);
            }
            fn set_header_size(&mut self, value: u16) {
                self.e_ehsize.set(LittleEndian, value);
            }
            fn set_program_header_entry_size(&mut self, value: u16) {
                self.e_phentsize.set(LittleEndian, value);
            }
            fn set_program_header_count(&mut self, value: u16) {
                self.e_phnum.set(LittleEndian, value);
            }
            fn set_section_header_entry_size(&mut self, value: u16) {
                self.e_shentsize.set(LittleEndian, value);
            }
            fn set_section_header_count(&mut self, value: u16) {
                self.e_shnum.set(LittleEndian, value);
            }
            fn set_section_name_table_index(&mut self, value: object::elf::SymbolSection) {
                self.e_shstrndx.set(LittleEndian, value);
            }
        }
    };
}

impl_file_header!(
    object::elf::FileHeader32<LittleEndian>,
    object::elf::ELFCLASS32,
    narrow_u32
);
impl_file_header!(
    object::elf::FileHeader64<LittleEndian>,
    object::elf::ELFCLASS64,
    identity_u64
);

macro_rules! impl_program_header {
    ($ty:ty, $narrow:expr) => {
        impl WritableProgramHeader for $ty {
            fn set_type(&mut self, value: object::elf::ProgramType) {
                self.p_type.set(LittleEndian, value);
            }
            fn set_flags(&mut self, value: object::elf::ProgramFlags) {
                self.p_flags.set(LittleEndian, value);
            }
            fn set_offset(&mut self, value: u64) -> Result {
                self.p_offset.set(LittleEndian, $narrow(value, "p_offset")?);
                Ok(())
            }
            fn set_virtual_address(&mut self, value: u64) -> Result {
                self.p_vaddr.set(LittleEndian, $narrow(value, "p_vaddr")?);
                Ok(())
            }
            fn set_physical_address(&mut self, value: u64) -> Result {
                self.p_paddr.set(LittleEndian, $narrow(value, "p_paddr")?);
                Ok(())
            }
            fn set_file_size(&mut self, value: u64) -> Result {
                self.p_filesz.set(LittleEndian, $narrow(value, "p_filesz")?);
                Ok(())
            }
            fn set_memory_size(&mut self, value: u64) -> Result {
                self.p_memsz.set(LittleEndian, $narrow(value, "p_memsz")?);
                Ok(())
            }
            fn set_alignment(&mut self, value: u64) -> Result {
                self.p_align.set(LittleEndian, $narrow(value, "p_align")?);
                Ok(())
            }
        }
    };
}

impl_program_header!(object::elf::ProgramHeader32<LittleEndian>, narrow_u32);
impl_program_header!(object::elf::ProgramHeader64<LittleEndian>, identity_u64);

fn set_section_flags32(
    out: &mut object::U32<LittleEndian, object::elf::SectionFlags>,
    value: SectionFlags,
) -> Result {
    out.set_u64(LittleEndian, object::elf::SectionFlags(value.0))
        .map_err(|_| error!("sh_flags value 0x{:x} does not fit in ELF32", value.0))?;
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn set_section_flags64(
    out: &mut object::U64<LittleEndian, object::elf::SectionFlags>,
    value: SectionFlags,
) -> Result {
    out.set(LittleEndian, object::elf::SectionFlags(value.0));
    Ok(())
}

macro_rules! impl_section_header {
    ($ty:ty, $narrow:expr, $set_flags:expr) => {
        impl WritableSectionHeader for $ty {
            fn set_name(&mut self, value: u32) {
                self.sh_name.set(LittleEndian, value);
            }
            fn set_type(&mut self, value: object::elf::SectionType) {
                self.sh_type.set(LittleEndian, value);
            }
            fn set_flags(&mut self, value: SectionFlags) -> Result {
                $set_flags(&mut self.sh_flags, value)
            }
            fn set_address(&mut self, value: u64) -> Result {
                self.sh_addr.set(LittleEndian, $narrow(value, "sh_addr")?);
                Ok(())
            }
            fn set_offset(&mut self, value: u64) -> Result {
                self.sh_offset
                    .set(LittleEndian, $narrow(value, "sh_offset")?);
                Ok(())
            }
            fn set_size(&mut self, value: u64) -> Result {
                self.sh_size.set(LittleEndian, $narrow(value, "sh_size")?);
                Ok(())
            }
            fn set_link(&mut self, value: u32) {
                self.sh_link.set(LittleEndian, value);
            }
            fn set_info(&mut self, value: u32) {
                self.sh_info.set(LittleEndian, value);
            }
            fn set_alignment(&mut self, value: u64) -> Result {
                self.sh_addralign
                    .set(LittleEndian, $narrow(value, "sh_addralign")?);
                Ok(())
            }
            fn set_entry_size(&mut self, value: u64) -> Result {
                self.sh_entsize
                    .set(LittleEndian, $narrow(value, "sh_entsize")?);
                Ok(())
            }
        }
    };
}

impl_section_header!(
    object::elf::SectionHeader32<LittleEndian>,
    narrow_u32,
    set_section_flags32
);

macro_rules! impl_compression_header {
    ($ty:ty, $narrow:expr) => {
        impl WritableCompressionHeader for $ty {
            fn set_type(&mut self, value: object::elf::CompressionType) {
                self.ch_type.set(LittleEndian, value);
            }
            fn set_size(&mut self, value: u64) -> Result {
                self.ch_size.set(LittleEndian, $narrow(value, "ch_size")?);
                Ok(())
            }
            fn set_alignment(&mut self, value: u64) -> Result {
                self.ch_addralign
                    .set(LittleEndian, $narrow(value, "ch_addralign")?);
                Ok(())
            }
        }
    };
}

impl_compression_header!(object::elf::CompressionHeader32<LittleEndian>, narrow_u32);
impl_compression_header!(object::elf::CompressionHeader64<LittleEndian>, identity_u64);
impl_section_header!(
    object::elf::SectionHeader64<LittleEndian>,
    identity_u64,
    set_section_flags64
);

macro_rules! impl_symbol {
    ($ty:ty, $narrow:expr) => {
        impl WritableSymbol for $ty {
            fn set_name(&mut self, value: u32) {
                self.st_name.set(LittleEndian, value);
            }
            fn set_info(&mut self, value: object::elf::SymbolInfo) {
                self.st_info = value;
            }
            fn set_binding_and_type(
                &mut self,
                binding: object::elf::SymbolBind,
                symbol_type: object::elf::SymbolType,
            ) {
                self.set_st_info(binding, symbol_type);
            }
            fn set_other(&mut self, value: object::elf::SymbolOther) {
                self.st_other = value;
            }
            fn set_visibility(&mut self, value: object::elf::SymbolVisibility) {
                self.st_other = self.st_other.with_visibility(value);
            }
            fn set_section(&mut self, value: object::elf::SymbolSection) {
                self.st_shndx.set(LittleEndian, value);
            }
            fn set_value(&mut self, value: u64) -> Result {
                self.st_value.set(LittleEndian, $narrow(value, "st_value")?);
                Ok(())
            }
            fn set_size(&mut self, value: u64) -> Result {
                self.st_size.set(LittleEndian, $narrow(value, "st_size")?);
                Ok(())
            }
        }
    };
}

impl_symbol!(object::elf::Sym32<LittleEndian>, narrow_u32);
impl_symbol!(object::elf::Sym64<LittleEndian>, identity_u64);

fn set_dynamic_tag32(
    out: &mut object::I32<LittleEndian, object::elf::DynamicTag>,
    value: object::elf::DynamicTag,
) -> Result {
    out.set_i64(LittleEndian, value)
        .map_err(|_| error!("dynamic tag {} does not fit in ELF32", value.0))?;
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn set_dynamic_tag64(
    out: &mut object::I64<LittleEndian, object::elf::DynamicTag>,
    value: object::elf::DynamicTag,
) -> Result {
    out.set(LittleEndian, value);
    Ok(())
}

macro_rules! impl_dynamic_entry {
    ($ty:ty, $narrow:expr, $set_tag:expr) => {
        impl WritableDynamicEntry for $ty {
            fn set_tag(&mut self, value: object::elf::DynamicTag) -> Result {
                $set_tag(&mut self.d_tag, value)
            }
            fn set_value(&mut self, value: u64) -> Result {
                self.d_val.set(LittleEndian, $narrow(value, "d_val")?);
                Ok(())
            }
        }
    };
}

impl_dynamic_entry!(
    object::elf::Dyn32<LittleEndian>,
    narrow_u32,
    set_dynamic_tag32
);
impl_dynamic_entry!(
    object::elf::Dyn64<LittleEndian>,
    identity_u64,
    set_dynamic_tag64
);

impl WritableRela for object::elf::Rela32<LittleEndian> {
    fn set_offset(&mut self, value: u64) -> Result {
        self.r_offset
            .set(LittleEndian, narrow_u32(value, "r_offset")?);
        Ok(())
    }
    fn set_addend(&mut self, value: i64) -> Result {
        self.r_addend
            .set(LittleEndian, narrow_i32(value, "r_addend")?);
        Ok(())
    }
    fn set_info(&mut self, symbol: u32, r_type: object::elf::RelocationType) -> Result {
        if symbol > 0x00ff_ffff {
            return Err(error!(
                "relocation symbol index {symbol} does not fit in ELF32"
            ));
        }
        u8::try_from(r_type.0)
            .map_err(|_| error!("relocation type {r_type} does not fit in ELF32"))?;
        self.set_r_info(LittleEndian, symbol, r_type);
        Ok(())
    }
}

impl WritableRela for object::elf::Rela64<LittleEndian> {
    fn set_offset(&mut self, value: u64) -> Result {
        self.r_offset.set(LittleEndian, value);
        Ok(())
    }
    fn set_addend(&mut self, value: i64) -> Result {
        self.r_addend.set(LittleEndian, value);
        Ok(())
    }
    fn set_info(&mut self, symbol: u32, r_type: object::elf::RelocationType) -> Result {
        self.set_r_info(LittleEndian, false, symbol, r_type);
        Ok(())
    }
}

impl WritableRelr for object::elf::Relr32<LittleEndian> {
    fn set_value(&mut self, value: u64) -> Result {
        self.0.set(LittleEndian, narrow_u32(value, "relr")?);
        Ok(())
    }
}

impl WritableRelr for object::elf::Relr64<LittleEndian> {
    fn set_value(&mut self, value: u64) -> Result {
        self.0.set(LittleEndian, value);
        Ok(())
    }
}

macro_rules! impl_note_header {
    ($ty:ty) => {
        impl WritableNoteHeader for $ty {
            fn set_name_size(&mut self, value: u32) {
                self.n_namesz.set(LittleEndian, value);
            }
            fn set_descriptor_size(&mut self, value: u32) {
                self.n_descsz.set(LittleEndian, value);
            }
            fn set_type(&mut self, value: object::elf::NoteType) {
                self.n_type.set(LittleEndian, value);
            }
        }
    };
}

impl_note_header!(object::elf::NoteHeader32<LittleEndian>);
impl_note_header!(object::elf::NoteHeader64<LittleEndian>);
