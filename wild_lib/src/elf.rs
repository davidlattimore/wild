use crate::error::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use bytemuck::Pod;
use bytemuck::Zeroable;
use linker_utils::elf::rel_type_to_string;
use linker_utils::elf::sht;
use linker_utils::elf::SectionType;
use object::read::elf::CompressionHeader;
use object::read::elf::FileHeader as _;
use object::read::elf::ProgramHeader as _;
use object::read::elf::RelocationSections;
use object::read::elf::SectionHeader as _;
use object::LittleEndian;
use std::borrow::Cow;
use std::io::Read as _;

/// Our starting address in memory when linking non-relocatable executables. We can start memory
/// addresses wherever we like, even from 0. We pick 400k because it's the same as what ld does and
/// because picking a distinctive non-zero values makes it more obvious what's happening if we mix
/// up file and memory offsets.
pub const NON_PIE_START_MEM_ADDRESS: u64 = 0x400_000;

pub(crate) type FileHeader = object::elf::FileHeader64<LittleEndian>;
pub(crate) type ProgramHeader = object::elf::ProgramHeader64<LittleEndian>;
pub(crate) type SectionHeader = object::elf::SectionHeader64<LittleEndian>;
pub(crate) type Symbol = object::elf::Sym64<LittleEndian>;
pub(crate) type SymtabEntry = object::elf::Sym64<LittleEndian>;
pub(crate) type DynamicEntry = object::elf::Dyn64<LittleEndian>;
pub(crate) type Rela = object::elf::Rela64<LittleEndian>;
pub(crate) type GnuHashHeader = object::elf::GnuHashHeader<LittleEndian>;
pub(crate) type Verneed = object::elf::Verneed<LittleEndian>;
pub(crate) type Vernaux = object::elf::Vernaux<LittleEndian>;
pub(crate) type Versym = object::elf::Versym<LittleEndian>;
pub(crate) type VerdefIterator<'data> = object::read::elf::VerdefIterator<'data, FileHeader>;

type SectionTable<'data> = object::read::elf::SectionTable<'data, FileHeader>;
type SymbolTable<'data> = object::read::elf::SymbolTable<'data, FileHeader>;

pub(crate) struct File<'data> {
    pub(crate) data: &'data [u8],
    pub(crate) sections: SectionTable<'data>,
    /// This may be symtab or dynsym depending on the file type.
    pub(crate) symbols: SymbolTable<'data>,
    pub(crate) relocations: RelocationSections,
    pub(crate) program_headers: &'data [ProgramHeader],
    pub(crate) versym: &'data [Versym],

    /// An iterator over the version definitions and the corresponding linked string table index.
    pub(crate) verdef: Option<(VerdefIterator<'data>, object::SectionIndex)>,
}

impl<'data> File<'data> {
    pub(crate) fn parse(data: &'data [u8], is_dynamic: bool) -> Result<Self> {
        let header = FileHeader::parse(data)?;
        let endian = header.endian()?;
        let sections = header.sections(endian, data)?;

        let mut symbols = SymbolTable::default();
        let mut versym: &[Versym] = &[];
        let mut verdef = None;

        // Find all the sections that we're interested in in a single scan of the section table so
        // as to avoid multiple scans.
        for (section_index, section) in sections.enumerate() {
            match SectionType::from_header(section) {
                sht::DYNSYM if is_dynamic => {
                    symbols = SymbolTable::parse(endian, data, &sections, section_index, section)?;
                }
                sht::SYMTAB if !is_dynamic => {
                    symbols = SymbolTable::parse(endian, data, &sections, section_index, section)?;
                }
                sht::GNU_VERSYM => {
                    versym = section.data_as_array(endian, data)?;
                }
                sht::GNU_VERDEF => {
                    verdef = section.gnu_verdef(endian, data)?;
                }
                _ => {}
            }
        }
        let relocations = if is_dynamic {
            RelocationSections::default()
        } else {
            sections.relocation_sections(endian, symbols.section())?
        };
        let program_headers = get_entries(
            data,
            header.e_phoff(endian) as usize,
            header.e_phnum(endian) as usize,
        )
        .context("Failed to read program headers")?;
        Ok(Self {
            data,
            sections,
            symbols,
            relocations,
            program_headers,
            versym,
            verdef,
        })
    }

    pub(crate) fn section(&self, index: object::SectionIndex) -> Result<&'data SectionHeader> {
        Ok(self.sections.section(index)?)
    }

    pub(crate) fn section_by_name(
        &self,
        name: &str,
    ) -> Option<(object::SectionIndex, &'data SectionHeader)> {
        self.sections.section_by_name(LittleEndian, name.as_bytes())
    }

    pub(crate) fn section_name(&self, section: &SectionHeader) -> Result<&'data [u8]> {
        Ok(self.sections.section_name(LittleEndian, section)?)
    }

    pub(crate) fn section_display_name(&self, index: object::SectionIndex) -> Cow<'data, str> {
        self.section(index)
            .and_then(|section| self.section_name(section))
            .map(String::from_utf8_lossy)
            .unwrap_or_else(|_| format!("<index {}>", index.0).into())
    }

    /// Returns the raw section data. Doesn't handle decompression.
    pub(crate) fn raw_section_data(&self, section: &SectionHeader) -> Result<&'data [u8]> {
        Ok(section.data(LittleEndian, self.data)?)
    }

    pub(crate) fn section_data(
        &self,
        section: &SectionHeader,
        member: &bumpalo_herd::Member<'data>,
    ) -> Result<&'data [u8]> {
        let data = section.data(LittleEndian, self.data)?;

        if let Some((compression, _, _)) = section.compression(LittleEndian, self.data)? {
            let len = self.section_size(section)?;
            let decompressed = member.alloc_slice_fill_default(len as usize);
            decompress_into(compression, &data[COMPRESSION_HEADER_SIZE..], decompressed)?;
            Ok(decompressed)
        } else {
            Ok(data)
        }
    }

    /// Copies the data for the specified section into `out`, which must be the correct size.
    /// Decompresses the data if necessary.
    pub(crate) fn copy_section_data(&self, section: &SectionHeader, out: &mut [u8]) -> Result {
        let data = section.data(LittleEndian, self.data)?;

        if let Some((compression, _, _)) = section.compression(LittleEndian, self.data)? {
            decompress_into(compression, &data[COMPRESSION_HEADER_SIZE..], out)?;
        } else {
            out.copy_from_slice(data);
        }
        Ok(())
    }

    pub(crate) fn section_size(&self, section: &SectionHeader) -> Result<u64> {
        Ok(section.compression(LittleEndian, self.data)?.map_or_else(
            || section.sh_size.get(LittleEndian),
            |compression| compression.0.ch_size(LittleEndian),
        ))
    }

    pub(crate) fn section_alignment(&self, section: &SectionHeader) -> Result<u64> {
        Ok(section.compression(LittleEndian, self.data)?.map_or_else(
            || section.sh_addralign(LittleEndian),
            |compression| compression.0.ch_addralign(LittleEndian),
        ))
    }

    pub(crate) fn relocations(&self, index: object::SectionIndex) -> Result<&'data [Rela]> {
        let Some(rela_index) = self.relocations.get(index) else {
            return Ok(&[]);
        };
        let rela_section = self.sections.section(rela_index)?;
        let Some((rela, _)) = rela_section.rela(LittleEndian, self.data)? else {
            return Ok(&[]);
        };
        Ok(rela)
    }

    pub(crate) fn symbol(&self, index: object::SymbolIndex) -> Result<&'data Symbol> {
        Ok(self.symbols.symbol(index)?)
    }

    pub(crate) fn symbol_name(&self, symbol: &Symbol) -> Result<&'data [u8]> {
        Ok(self.symbols.symbol_name(LittleEndian, symbol)?)
    }

    pub(crate) fn symbol_section(
        &self,
        symbol: &Symbol,
        index: object::SymbolIndex,
    ) -> Result<Option<object::SectionIndex>> {
        Ok(self.symbols.symbol_section(LittleEndian, symbol, index)?)
    }

    pub(crate) fn dynamic_tags(&self) -> Result<&'data [DynamicEntry]> {
        let e = LittleEndian;
        for header in self.program_headers {
            if header.p_type(e) == object::elf::PT_DYNAMIC {
                return get_entries(
                    self.data,
                    header.p_offset(e) as usize,
                    header.p_filesz(e) as usize / core::mem::size_of::<DynamicEntry>(),
                )
                .context("Failed to read dynamic table");
            }
        }
        Ok(&[])
    }
}

fn decompress_into(
    compression: &object::elf::CompressionHeader64<LittleEndian>,
    input: &[u8],
    out: &mut [u8],
) -> Result {
    match compression.ch_type.get(LittleEndian) {
        object::elf::ELFCOMPRESS_ZLIB => {
            flate2::Decompress::new(true).decompress(
                input,
                out,
                flate2::FlushDecompress::Finish,
            )?;
        }
        object::elf::ELFCOMPRESS_ZSTD => {
            ruzstd::StreamingDecoder::new(input)?.read_exact(out)?;
        }
        c => bail!("Unsupported compression format: {}", c),
    };
    Ok(())
}

/// Get some entries from `data` as a slice of some Pod type. Alignment of `T` must be 1.
pub(crate) fn get_entries<T: object::Pod>(
    data: &[u8],
    offset: usize,
    entry_count: usize,
) -> Result<&[T]> {
    debug_assert_eq!(core::mem::align_of::<T>(), 1);
    if offset >= data.len() {
        bail!("Invalid offset 0x{offset}");
    }
    Ok(object::slice_from_bytes(&data[offset..], entry_count)
        .map_err(|()| {
            anyhow!(
                "Tried to extract 0x{:x} entries of size 0x{:x} from 0x{:x}",
                entry_count,
                core::mem::size_of::<T>(),
                data.len(),
            )
        })?
        .0)
}

/// The module number for TLS variables in the current executable.
pub(crate) const CURRENT_EXE_TLS_MOD: u64 = 1;

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

/// The offset of the offset within the structure passed to __tls_get_addr.
pub(crate) const TLS_OFFSET_OFFSET: u64 = 8;

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

/// The offset of the pc_begin field in an FDE.
pub(crate) const FDE_PC_BEGIN_OFFSET: usize = 8;

/// Offset in the file where we store the program headers. We always store these straight after the
/// file header.
pub(crate) const PHEADER_OFFSET: u64 = FILE_HEADER_SIZE as u64;

/// These sizes are from the spec (for 64 bit ELF).
pub(crate) const FILE_HEADER_SIZE: u16 = 0x40;
pub(crate) const PROGRAM_HEADER_SIZE: u16 = 0x38;
pub(crate) const SECTION_HEADER_SIZE: u16 = 0x40;
pub(crate) const COMPRESSION_HEADER_SIZE: usize =
    core::mem::size_of::<object::elf::CompressionHeader64<LittleEndian>>();

pub(crate) const GOT_ENTRY_SIZE: u64 = 0x8;
pub(crate) const PLT_ENTRY_SIZE: u64 = PLT_ENTRY_TEMPLATE.len() as u64;
pub(crate) const RELA_ENTRY_SIZE: u64 = 0x18;

pub(crate) const SYMTAB_ENTRY_SIZE: u64 = core::mem::size_of::<SymtabEntry>() as u64;
pub(crate) const GNU_VERSION_ENTRY_SIZE: u64 = core::mem::size_of::<Versym>() as u64;

pub(crate) const PLT_ENTRY_TEMPLATE: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0xf2, 0xff, 0x25, 0x0, 0x0, 0x0, 0x0, // bnd jmp *{relative GOT address}(%rip)
    0x0f, 0x1f, 0x44, 0x0, 0x0, // nopl   0x0(%rax,%rax,1)
];

/// The first entry in the PLT when we're using lazy loading. All the other entries jump to this
/// one, which then jumps to the loader function that the runtime put into
/// _GLOBAL_OFFSET_TABLE_+0x10.
pub(crate) const PLT_LAZY_HEADER_TEMPLATE: &[u8] = &[
    0xff, 0x35, 0, 0, 0, 0, // push {_GLOBAL_OFFSET_TABLE_+0x8}(%rip)
    0xf2, 0xff, 0x25, 0, 0, 0, 0, // bnd jmp *{_GLOBAL_OFFSET_TABLE_+0x10}(%rip)
    0x0f, 0x1f, 0, // nopl (%rax)
];

pub(crate) const JUMP_SLOT_TEMPLATE: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0x68, 0, 0, 0, 0, // push ${index}
    0xf2, 0xe9, 0, 0, 0, 0,    // bnd jmp {PLT base address}(%rip)
    0x90, // nop
];

const _ASSERTS: () = {
    assert!(FILE_HEADER_SIZE as usize == std::mem::size_of::<FileHeader>());
    assert!(PROGRAM_HEADER_SIZE as usize == std::mem::size_of::<ProgramHeader>());
    assert!(SECTION_HEADER_SIZE as usize == std::mem::size_of::<SectionHeader>());
    assert!(PLT_LAZY_HEADER_TEMPLATE.len() == PLT_ENTRY_TEMPLATE.len());
    assert!(JUMP_SLOT_TEMPLATE.len() == PLT_ENTRY_TEMPLATE.len());
};

/// For additional information on ELF relocation types, see "ELF-64 Object File Format" -
/// https://uclibc.org/docs/elf-64-gen.pdf. For information on the TLS related relocations, see "ELF
/// Handling For Thread-Local Storage" - https://www.uclibc.org/docs/tls.pdf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelocationKind {
    /// The absolute address of a symbol or section.
    Absolute,

    /// The address of the symbol, relative to the place of the relocation.
    Relative,

    /// The address of the symbol, relative to the base address of the GOT.
    SymRelGotBase,

    /// The offset of the symbol's GOT entry, relative to the start of the GOT.
    GotRelGotBase,

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

    /// The address of the TLS module ID for the shared object that we're writing, relative to the
    /// place of the relocation. This is used when a TLS variable is defined and used within the
    /// same shared object.
    TlsLd,

    /// The offset of a thread-local within the TLS storage of DSO that defines that thread-local.
    DtpOff,

    /// The address of a GOT entry containing the offset of a TLS variable within the executable's
    /// TLS storage, relative to the place of the relocation.
    GotTpOff,

    /// The offset of a TLS variable within the executable's TLS storage.
    TpOff,

    /// No relocation needs to be applied. Produced when we eliminate a relocation due to an
    /// optimisation.
    None,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RelocationKindInfo {
    pub(crate) kind: RelocationKind,
    pub(crate) byte_size: usize,
}

impl RelocationKindInfo {
    pub(crate) fn from_raw(r_type: u32) -> Result<Self> {
        let (kind, size) = match r_type {
            object::elf::R_X86_64_64 => (RelocationKind::Absolute, 8),
            object::elf::R_X86_64_PC32 => (RelocationKind::Relative, 4),
            object::elf::R_X86_64_PC64 => (RelocationKind::Relative, 8),
            object::elf::R_X86_64_GOT32 => (RelocationKind::GotRelGotBase, 4),
            object::elf::R_X86_64_GOT64 => (RelocationKind::GotRelGotBase, 8),
            object::elf::R_X86_64_GOTOFF64 => (RelocationKind::SymRelGotBase, 8),
            object::elf::R_X86_64_PLT32 => (RelocationKind::PltRelative, 4),
            object::elf::R_X86_64_PLTOFF64 => (RelocationKind::PltRelGotBase, 8),
            object::elf::R_X86_64_GOTPCREL => (RelocationKind::GotRelative, 4),

            // For now, we rely on GOTPC64 and GOTPC32 always referencing the symbol
            // _GLOBAL_OFFSET_TABLE_, which means that we can just treat these a normal relative
            // relocations and avoid any special processing when writing.
            object::elf::R_X86_64_GOTPC64 => (RelocationKind::Relative, 8),
            object::elf::R_X86_64_GOTPC32 => (RelocationKind::Relative, 4),

            object::elf::R_X86_64_32 | object::elf::R_X86_64_32S => (RelocationKind::Absolute, 4),
            object::elf::R_X86_64_16 => (RelocationKind::Absolute, 2),
            object::elf::R_X86_64_PC16 => (RelocationKind::Relative, 2),
            object::elf::R_X86_64_8 => (RelocationKind::Absolute, 1),
            object::elf::R_X86_64_PC8 => (RelocationKind::Relative, 1),
            object::elf::R_X86_64_TLSGD => (RelocationKind::TlsGd, 4),
            object::elf::R_X86_64_TLSLD => (RelocationKind::TlsLd, 4),
            object::elf::R_X86_64_DTPOFF32 => (RelocationKind::DtpOff, 4),
            object::elf::R_X86_64_GOTTPOFF => (RelocationKind::GotTpOff, 4),
            object::elf::R_X86_64_GOTPCRELX | object::elf::R_X86_64_REX_GOTPCRELX => {
                (RelocationKind::GotRelative, 4)
            }
            object::elf::R_X86_64_TPOFF32 => (RelocationKind::TpOff, 4),
            object::elf::R_X86_64_NONE => (RelocationKind::None, 0),
            _ => bail!("Unsupported relocation type {}", rel_type_to_string(r_type)),
        };
        Ok(Self {
            kind,
            byte_size: size,
        })
    }
}

pub(crate) fn slice_from_all_bytes_mut<T: object::Pod>(data: &mut [u8]) -> &mut [T] {
    object::slice_from_bytes_mut(data, data.len() / core::mem::size_of::<T>())
        .unwrap()
        .0
}
