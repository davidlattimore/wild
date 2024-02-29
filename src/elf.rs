use crate::error::Result;
use anyhow::bail;
use bytemuck::Pod;
use bytemuck::Zeroable;
use object::LittleEndian;

/// Our starting address in memory when linking non-relocatable executables. We can start memory
/// addresses wherever we like, even from 0. We pick 400k because it's the same as what ld does and
/// because picking a distinctive non-zero values makes it more obvious what's happening if we mix
/// up file and memory offsets.
pub const NON_PIE_START_MEM_ADDRESS: u64 = 0x400_000;

pub(crate) type File<'data> = object::read::elf::ElfFile64<'data, LittleEndian, &'data [u8]>;
pub(crate) type Section<'data, 'file> =
    object::read::elf::ElfSection64<'data, 'file, LittleEndian, &'data [u8]>;
pub(crate) type Symbol<'data, 'file> =
    object::read::elf::ElfSymbol64<'data, 'file, LittleEndian, &'data [u8]>;

/// The module number for TLS variables in the current executable.
pub(crate) const CURRENT_EXE_TLS_MOD: u64 = 1;

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
pub(crate) struct ProgramHeader {
    pub(crate) segment_type: u32,
    pub(crate) flags: u32,
    pub(crate) offset: u64,
    pub(crate) virtual_addr: u64,
    pub(crate) physical_addr: u64,
    pub(crate) file_size: u64,
    pub(crate) mem_size: u64,
    pub(crate) alignment: u64,
}

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
pub(crate) struct FileHeader {
    pub(crate) magic: [u8; 4],
    pub(crate) class: u8,
    pub(crate) data: u8,
    pub(crate) ei_version: u8,
    pub(crate) os_abi: u8,
    pub(crate) abi_version: u8,
    pub(crate) padding: [u8; 7],
    pub(crate) ty: u16,
    pub(crate) machine: u16,
    pub(crate) e_version: u32,
    pub(crate) entry_point: u64,
    pub(crate) program_header_offset: u64,
    pub(crate) section_header_offset: u64,
    pub(crate) flags: u32,
    pub(crate) ehsize: u16,
    pub(crate) program_header_entry_size: u16,
    pub(crate) program_header_num: u16,
    pub(crate) section_header_entry_size: u16,
    pub(crate) section_header_num: u16,
    pub(crate) section_names_index: u16,
}

/// Section flag bit values.
#[allow(unused)]
pub(crate) mod shf {
    pub(crate) const WRITE: u64 = 0x1;
    pub(crate) const ALLOC: u64 = 0x2;
    pub(crate) const EXECINSTR: u64 = 0x4;
    pub(crate) const MERGE: u64 = 0x10;
    pub(crate) const STRINGS: u64 = 0x20;
    pub(crate) const INFO_LINK: u64 = 0x40;
    pub(crate) const LINK_ORDER: u64 = 0x80;
    pub(crate) const OS_NONCONFORMING: u64 = 0x100;
    pub(crate) const GROUP: u64 = 0x200;
    pub(crate) const TLS: u64 = 0x400;
    pub(crate) const GNU_RETAIN: u64 = 0x200_000;
}

#[allow(unused)]
#[repr(u16)]
pub(crate) enum FileType {
    Unknown = 0,
    Relocatable = 0x1,
    Executable = 0x2,
    SharedObject = 0x3,
    CoreFile = 0x4,
}

/// Section types
#[allow(unused)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
#[repr(u32)]
pub(crate) enum Sht {
    #[default]
    Null = 0x0,
    Progbits = 0x1,
    Symtab = 0x2,
    Strtab = 0x3,
    Rela = 0x4,
    Hash = 0x5,
    Dynamic = 0x6,
    Note = 0x7,
    Nobits = 0x8,
    Rel = 0x9,
    Shlib = 0xa,
    DynSym = 0xb,
    InitArray = 0xe,
    FiniArray = 0xf,
    PreinitArray = 0x10,
    Group = 0x11,
    SymtabShndx = 0x12,
    Num = 0x13,
}

#[allow(unused)]
#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum Binding {
    Local = 0,
    Global = 1,
    Weak = 2,
}

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
pub(crate) struct SectionHeader {
    pub(crate) name: u32,
    pub(crate) ty: u32,
    pub(crate) flags: u64,
    pub(crate) address: u64,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) link: u32,
    pub(crate) info: u32,
    pub(crate) alignment: u64,
    pub(crate) entsize: u64,
}

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
pub(crate) struct SymtabEntry {
    pub(crate) name: u32,
    pub(crate) info: u8,
    pub(crate) other: u8,
    pub(crate) shndx: u16,
    pub(crate) value: u64,
    pub(crate) size: u64,
}

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
pub(crate) struct DynamicEntry {
    pub(crate) tag: u64,
    pub(crate) value: u64,
}

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
pub(crate) struct Rela {
    pub(crate) address: u64,
    pub(crate) info: u64,
    pub(crate) addend: u64,
}

#[allow(unused)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
#[repr(u32)]
pub(crate) enum SegmentType {
    #[default]
    Null = 0,
    Load = 1,
    Dynamic = 2,
    Interp = 3,
    Note = 4,
    Shlib = 5,
    Phdr = 6,
    Tls = 7,
    EhFrame = 0x6474e550,
}

#[allow(unused)]
#[derive(Clone, Copy)]
#[repr(u64)]
pub(crate) enum DynamicTag {
    Null = 0,
    Needed = 1,
    PltRelSize = 2,
    PltGot = 3,
    Hash = 4,
    StrTab = 5,
    SymTab = 6,
    Rela = 7,
    RelaSize = 8,
    RelaEnt = 9,
    StrSize = 10,
    SymEnt = 11,
    Init = 12,
    Fini = 13,
    SoName = 14,
    Rpath = 15,
    Symbolic = 16,
    Rel = 17,
    RelSize = 18,
    RelEnt = 19,
    PltRel = 20,
    Debug = 21,
    TextRel = 22,
    JmpRel = 23,
    BindNow = 24,
    InitArray = 25,
    FiniArray = 26,
    InitArraySize = 27,
    FiniArraySize = 28,
    Flags = 30,
    Flags1 = 0x6ffffffb,
    RelaCount = 0x6ffffff9,
}

pub(crate) mod flags_1 {
    pub(crate) const NOW: u64 = 0x1;
    pub(crate) const PIE: u64 = 0x08000000;
}

pub(crate) mod flags {
    pub(crate) const BIND_NOW: u64 = 0x8;
}

/// See https://refspecs.linuxfoundation.org/LSB_1.3.0/gLSB/gLSB/ehframehdr.html
#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
pub(crate) struct EhFrameHdr {
    pub(crate) version: u8,
    pub(crate) frame_pointer_encoding: u8,
    pub(crate) count_encoding: u8,
    pub(crate) table_encoding: u8,
    // For now we just use 32 bit pointer and count because it means that they're aligned. If we
    // need to upgrade these to u64, then we'd have to write these as unaligned fields.
    pub(crate) frame_pointer: i32,
    pub(crate) entry_count: u32,
}

// TODO: Use offset-of once it's stable.
pub(crate) const FRAME_POINTER_FIELD_OFFSET: usize = 4;

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
pub(crate) struct EhFrameHdrEntry {
    pub(crate) frame_ptr: i32,
    pub(crate) frame_info_ptr: i32,
}

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
pub(crate) struct EhFrameEntryPrefix {
    pub(crate) length: u32,
    pub(crate) cie_id: u32,
}

#[allow(unused)]
#[repr(u8)]
pub(crate) enum ExceptionHeaderFormat {
    Uleb128 = 1,
    U16 = 2,
    U32 = 3,
    U64 = 4,
    Sleb128 = 9,
    I16 = 0xa,
    I32 = 0xb,
    I64 = 0xc,
}

#[allow(unused)]
#[repr(u8)]
pub(crate) enum ExceptionHeaderApplication {
    Absolute = 0,

    /// Value is relative to the location of the pointer.
    Relative = 0x10,

    /// Value is relative to start of the .eh_frame_hdr section.
    EhFrameHdrRelative = 0x30,
}

#[allow(unused)]
#[derive(Clone, Copy)]
#[repr(u32)]
pub(crate) enum RelocationType {
    IRelative = 37,
}

/// The offset of the pc_begin field in an FDE.
pub(crate) const FDE_PC_BEGIN_OFFSET: usize = 8;

/// Offset in the file where we store the program headers. We always store these straight after the
/// file header.
pub(crate) const PHEADER_OFFSET: u64 = FILE_HEADER_SIZE as u64;

/// These sizes are from the spec (for 64 bit ELF).
pub(crate) const FILE_HEADER_SIZE: u16 = 0x40;
pub(crate) const PROGRAM_HEADER_SIZE: u16 = 0x38;
pub(crate) const SECTION_HEADER_SIZE: u16 = 0x40;

pub(crate) const GOT_ENTRY_SIZE: u64 = 0x8;
pub(crate) const PLT_ENTRY_SIZE: u64 = PLT_ENTRY_TEMPLATE.len() as u64;
pub(crate) const RELA_ENTRY_SIZE: u64 = 0x18;

pub(crate) const PLT_ENTRY_TEMPLATE: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0xf2, 0xff, 0x25, 0x0, 0x0, 0x0, 0x0, // bnd jmp *{relative GOT address}(%rip)
    0x0f, 0x1f, 0x44, 0x0, 0x0, // nopl   0x0(%rax,%rax,1)
];

const _ASSERTS: () = {
    assert!(FILE_HEADER_SIZE as usize == std::mem::size_of::<FileHeader>());
    assert!(PROGRAM_HEADER_SIZE as usize == std::mem::size_of::<ProgramHeader>());
    assert!(SECTION_HEADER_SIZE as usize == std::mem::size_of::<SectionHeader>());
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum RelocationKind {
    Absolute,
    Relative,
    Got,
    PltRelative,
    GotRelative,
    TlsGd,
    TlsLd,
    DtpOff,
    GotTpOff,
    TpOff,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RelocationKindInfo {
    pub(crate) kind: RelocationKind,
    pub(crate) byte_size: usize,
}

impl RelocationKindInfo {
    pub(crate) fn from_rel(rel: &object::Relocation) -> Result<Self> {
        let object::RelocationFlags::Elf { r_type } = rel.flags() else {
            unreachable!();
        };
        Self::from_raw(r_type)
    }

    pub(crate) fn from_raw(r_type: u32) -> Result<Self> {
        let (kind, size) = match r_type {
            rel::R_X86_64_64 => (RelocationKind::Absolute, 8),
            rel::R_X86_64_PC32 => (RelocationKind::Relative, 4),
            rel::R_X86_64_GOT32 => (RelocationKind::Got, 4),
            rel::R_X86_64_PLT32 => (RelocationKind::PltRelative, 4),
            rel::R_X86_64_GOTPCREL => (RelocationKind::GotRelative, 4),
            rel::R_X86_64_32 | rel::R_X86_64_32S => (RelocationKind::Absolute, 4),
            rel::R_X86_64_16 => (RelocationKind::Absolute, 2),
            rel::R_X86_64_PC16 => (RelocationKind::Relative, 2),
            rel::R_X86_64_8 => (RelocationKind::Absolute, 1),
            rel::R_X86_64_PC8 => (RelocationKind::Relative, 1),
            rel::R_X86_64_TLSGD => (RelocationKind::TlsGd, 4),
            rel::R_X86_64_TLSLD => (RelocationKind::TlsLd, 4),
            rel::R_X86_64_DTPOFF32 => (RelocationKind::DtpOff, 4),
            rel::R_X86_64_GOTTPOFF => (RelocationKind::GotTpOff, 4),
            rel::R_X86_64_GOTPCRELX | rel::R_X86_64_REX_GOTPCRELX => {
                (RelocationKind::GotRelative, 4)
            }
            rel::R_X86_64_TPOFF32 => (RelocationKind::TpOff, 4),
            _ => bail!("Unsupported relocation type {r_type}"),
        };
        Ok(Self {
            kind,
            byte_size: size,
        })
    }
}

#[allow(dead_code)]
pub(crate) mod rel {
    pub(crate) const R_X86_64_64: u32 = 1;
    pub(crate) const R_X86_64_PC32: u32 = 2;
    pub(crate) const R_X86_64_GOT32: u32 = 3;
    pub(crate) const R_X86_64_PLT32: u32 = 4;
    pub(crate) const R_X86_64_COPY: u32 = 5;
    pub(crate) const R_X86_64_GLOB_DAT: u32 = 6;
    pub(crate) const R_X86_64_JUMP_SLOT: u32 = 7;
    pub(crate) const R_X86_64_RELATIVE: u32 = 8;
    pub(crate) const R_X86_64_GOTPCREL: u32 = 9;
    pub(crate) const R_X86_64_32: u32 = 10;
    pub(crate) const R_X86_64_32S: u32 = 11;
    pub(crate) const R_X86_64_16: u32 = 12;
    pub(crate) const R_X86_64_PC16: u32 = 13;
    pub(crate) const R_X86_64_8: u32 = 14;
    pub(crate) const R_X86_64_PC8: u32 = 15;
    pub(crate) const R_X86_64_DTPMOD64: u32 = 16;
    pub(crate) const R_X86_64_DTPOFF64: u32 = 17;
    pub(crate) const R_X86_64_TPOFF64: u32 = 18;
    pub(crate) const R_X86_64_TLSGD: u32 = 19;
    pub(crate) const R_X86_64_TLSLD: u32 = 20;
    pub(crate) const R_X86_64_DTPOFF32: u32 = 21;
    pub(crate) const R_X86_64_GOTTPOFF: u32 = 22;
    pub(crate) const R_X86_64_TPOFF32: u32 = 23;
    pub(crate) const R_X86_64_PC64: u32 = 24;
    pub(crate) const R_X86_64_GOTOFF64: u32 = 25;
    pub(crate) const R_X86_64_GOTPC32: u32 = 26;
    pub(crate) const R_X86_64_GOT64: u32 = 27;
    pub(crate) const R_X86_64_GOTPCREL64: u32 = 28;
    pub(crate) const R_X86_64_GOTPC64: u32 = 29;
    pub(crate) const R_X86_64_GOTPLT64: u32 = 30;
    pub(crate) const R_X86_64_PLTOFF64: u32 = 31;
    pub(crate) const R_X86_64_SIZE32: u32 = 32;
    pub(crate) const R_X86_64_SIZE64: u32 = 33;
    pub(crate) const R_X86_64_GOTPC32_TLSDESC: u32 = 34;
    pub(crate) const R_X86_64_TLSDESC_CALL: u32 = 35;
    pub(crate) const R_X86_64_TLSDESC: u32 = 36;
    pub(crate) const R_X86_64_IRELATIVE: u32 = 37;
    pub(crate) const R_X86_64_RELATIVE64: u32 = 38;
    pub(crate) const R_X86_64_GOTPCRELX: u32 = 41;
    pub(crate) const R_X86_64_REX_GOTPCRELX: u32 = 42;
}
