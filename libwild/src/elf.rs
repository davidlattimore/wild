use crate::arch::Architecture;
use crate::bail;
use crate::ensure;
use crate::error::Context as _;
use crate::error::Result;
use crate::resolution::LoadedMetrics;
use bytemuck::Pod;
use bytemuck::Zeroable;
use linker_utils::aarch64::DEFAULT_AARCH64_PAGE_IGNORED_MASK;
use linker_utils::elf::BitMask;
use linker_utils::elf::PageMask;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RelocationSize;
use linker_utils::elf::SectionType;
use linker_utils::elf::extract_bits;
use linker_utils::elf::sht;
use object::LittleEndian;
use object::read::elf::CompressionHeader;
use object::read::elf::Dyn;
use object::read::elf::FileHeader as _;
use object::read::elf::RelocationSections;
use object::read::elf::SectionHeader as _;
use std::borrow::Cow;
use std::io::Read as _;
use std::mem::offset_of;
use std::sync::atomic::Ordering;

/// Our starting address in memory when linking non-relocatable executables. We can start memory
/// addresses wherever we like, even from 0. We pick 400k because it's the same as what ld does and
/// because picking a distinctive non-zero values makes it more obvious what's happening if we mix
/// up file and memory offsets.
pub const NON_PIE_START_MEM_ADDRESS: u64 = 0x400_000;

pub(crate) const TLS_MODULE_BASE_SYMBOL_NAME: &str = "_TLS_MODULE_BASE_";

pub(crate) type FileHeader = object::elf::FileHeader64<LittleEndian>;
pub(crate) type ProgramHeader = object::elf::ProgramHeader64<LittleEndian>;
pub(crate) type SectionHeader = object::elf::SectionHeader64<LittleEndian>;
pub(crate) type Symbol = object::elf::Sym64<LittleEndian>;
pub(crate) type SymtabEntry = object::elf::Sym64<LittleEndian>;
pub(crate) type DynamicEntry = object::elf::Dyn64<LittleEndian>;
pub(crate) type Rela = object::elf::Rela64<LittleEndian>;
pub(crate) type GnuHashHeader = object::elf::GnuHashHeader<LittleEndian>;
pub(crate) type Verdef = object::elf::Verdef<LittleEndian>;
pub(crate) type Verdaux = object::elf::Verdaux<LittleEndian>;
pub(crate) type Verneed = object::elf::Verneed<LittleEndian>;
pub(crate) type Vernaux = object::elf::Vernaux<LittleEndian>;
pub(crate) type Versym = object::elf::Versym<LittleEndian>;
pub(crate) type VerdefIterator<'data> = object::read::elf::VerdefIterator<'data, FileHeader>;
pub(crate) type NoteHeader = object::elf::NoteHeader64<LittleEndian>;

type SectionTable<'data> = object::read::elf::SectionTable<'data, FileHeader>;
type SymbolTable<'data> = object::read::elf::SymbolTable<'data, FileHeader>;

pub(crate) struct File<'data> {
    pub(crate) arch: Architecture,
    pub(crate) data: &'data [u8],
    pub(crate) sections: SectionTable<'data>,
    /// This may be symtab or dynsym depending on the file type.
    pub(crate) symbols: SymbolTable<'data>,
    pub(crate) versym: &'data [Versym],

    /// An iterator over the version definitions and the corresponding linked string table index.
    pub(crate) verdef: Option<(VerdefIterator<'data>, object::SectionIndex)>,

    /// Number of verdef versions according to the dynamic table.
    pub(crate) verdefnum: u64,
}

// Not needing Drop opens the option of storing this type in an arena that doesn't support dropping
// its contents.
const _: () = assert!(!core::mem::needs_drop::<File>());

impl<'data> File<'data> {
    pub(crate) fn parse(data: &'data [u8], is_dynamic: bool) -> Result<Self> {
        let header = FileHeader::parse(data)?;
        let endian = header.endian()?;
        let architecture = header.e_machine(endian).try_into()?;
        let sections = header.sections(endian, data)?;

        let mut symbols = SymbolTable::default();
        let mut versym: &[Versym] = &[];
        let mut verdef = None;
        let mut dynamic = None;
        let mut verdefnum = 0;

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
                sht::DYNAMIC => {
                    dynamic = section.dynamic(endian, data)?;
                }
                _ => {}
            }
        }

        if let Some((dynamic, _)) = dynamic {
            for dy in dynamic {
                if dy.d_tag(endian) == u64::from(object::elf::DT_VERDEFNUM) {
                    verdefnum = dy.d_val(endian);
                }
            }
        }

        Ok(Self {
            arch: architecture,
            data,
            sections,
            symbols,
            versym,
            verdef,
            verdefnum,
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
            .map_or_else(
                |_| format!("<index {}>", index.0).into(),
                String::from_utf8_lossy,
            )
    }

    /// Returns the raw section data. Doesn't handle decompression.
    pub(crate) fn raw_section_data(&self, section: &SectionHeader) -> Result<&'data [u8]> {
        Ok(section.data(LittleEndian, self.data)?)
    }

    pub(crate) fn section_data(
        &self,
        section: &SectionHeader,
        member: &bumpalo_herd::Member<'data>,
        loaded_metrics: &LoadedMetrics,
    ) -> Result<&'data [u8]> {
        let data = section.data(LittleEndian, self.data)?;
        loaded_metrics
            .loaded_bytes
            .fetch_add(data.len(), Ordering::Relaxed);

        if let Some((compression, _, _)) = section.compression(LittleEndian, self.data)? {
            loaded_metrics
                .loaded_compressed_bytes
                .fetch_add(data.len(), Ordering::Relaxed);
            let len = self.section_size(section)?;
            let decompressed = member.alloc_slice_fill_default(len as usize);
            decompress_into(compression, &data[COMPRESSION_HEADER_SIZE..], decompressed)?;
            loaded_metrics
                .decompressed_bytes
                .fetch_add(decompressed.len(), Ordering::Relaxed);
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
        } else if section.sh_type(LittleEndian) == object::elf::SHT_NOBITS {
            out.fill(0);
        } else {
            out.copy_from_slice(data);
        }
        Ok(())
    }

    /// Returns the contents of a section as a Cow. Will heap-allocate if the section is compressed.
    pub(crate) fn section_data_cow(&self, section: &SectionHeader) -> Result<Cow<'data, [u8]>> {
        let data = section.data(LittleEndian, self.data)?;

        if let Some((compression, _, _)) = section.compression(LittleEndian, self.data)? {
            let len = self.section_size(section)?;
            let mut decompressed = vec![0; len as usize];
            decompress_into(
                compression,
                &data[COMPRESSION_HEADER_SIZE..],
                &mut decompressed,
            )?;
            Ok(Cow::Owned(decompressed))
        } else {
            Ok(Cow::Borrowed(data))
        }
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

    pub(crate) fn relocations(
        &self,
        index: object::SectionIndex,
        relocations: &RelocationSections,
    ) -> Result<&'data [Rela]> {
        let Some(rela_index) = relocations.get(index) else {
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
        if let Some(dynamic) = self.sections.dynamic(e, self.data).transpose() {
            return dynamic
                .map(|(dynamic, _)| dynamic)
                .context("Failed to read dynamic table");
        }
        Ok(&[])
    }

    pub(crate) fn parse_relocations(&self) -> Result<RelocationSections> {
        Ok(self
            .sections
            .relocation_sections(LittleEndian, self.symbols.section())?)
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
        // We might use pure Rust implementation for the decompression (ruzstd), however the decompression
        // speed is not on par with the official C library.
        // With the official library, the linking time of Clang binary (contains 1GB of debug info sections)
        // shrinks by 30%!
        object::elf::ELFCOMPRESS_ZSTD => {
            zstd::stream::Decoder::new(input)?.read_exact(out)?;
        }
        c => bail!("Unsupported compression format: {}", c),
    };
    Ok(())
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

pub(crate) const FRAME_POINTER_FIELD_OFFSET: usize = offset_of!(EhFrameHdr, frame_pointer);

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

    /// Value is relative to the start of the .eh_frame_hdr section.
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
    size_of::<object::elf::CompressionHeader64<LittleEndian>>();

pub(crate) const GOT_ENTRY_SIZE: u64 = 0x8;
// TODO: Right now, both x86_64 and AArch64 have 16 byte long entries, but
// the size should be generic over A: Arch.
pub(crate) const PLT_ENTRY_SIZE: u64 = 0x10;
pub(crate) const RELA_ENTRY_SIZE: u64 = 0x18;

pub(crate) const SYMTAB_ENTRY_SIZE: u64 = size_of::<SymtabEntry>() as u64;
pub(crate) const GNU_VERSION_ENTRY_SIZE: u64 = size_of::<Versym>() as u64;

const _ASSERTS: () = {
    assert!(FILE_HEADER_SIZE as usize == size_of::<FileHeader>());
    assert!(PROGRAM_HEADER_SIZE as usize == size_of::<ProgramHeader>());
    assert!(SECTION_HEADER_SIZE as usize == size_of::<SectionHeader>());
};

pub(crate) const GNU_NOTE_NAME: &[u8] = b"GNU\0";
pub(crate) const GNU_NOTE_PROPERTY_ENTRY_SIZE: usize = 16;

/// For additional information on Elf_Prop, see
/// Linux Extensions to gABI at https://gitlab.com/x86-psABIs/Linux-ABI.
///
/// Right now, all properties that pr_datasz equal to 4 and so the pr_padding is always
/// 4 bytes!
///
/// typedef struct {
/// Elf_Word pr_type;
/// Elf_Word pr_datasz;
/// unsigned char pr_data[PR_DATASZ];
/// unsigned char pr_padding[PR_PADDING];
/// } Elf_Prop;

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
pub(crate) struct NoteProperty {
    pub(crate) pr_type: u32,
    pub(crate) pr_datasz: u32,
    pub(crate) pr_data: u32,
    pub(crate) pr_padding: u32,
}

pub(crate) struct PageMaskValue {
    pub(crate) symbol_plus_addend: u64,
    pub(crate) got_entry: u64,
    pub(crate) place: u64,
    pub(crate) got: u64,
}

impl Default for PageMaskValue {
    fn default() -> Self {
        Self {
            symbol_plus_addend: u64::MAX,
            got_entry: u64::MAX,
            place: u64::MAX,
            got: u64::MAX,
        }
    }
}

pub(crate) fn get_page_mask(mask: Option<PageMask>) -> PageMaskValue {
    let Some(mask) = mask else {
        return PageMaskValue::default();
    };

    match mask {
        PageMask::SymbolPlusAddendAndPosition => PageMaskValue {
            symbol_plus_addend: DEFAULT_AARCH64_PAGE_IGNORED_MASK,
            place: DEFAULT_AARCH64_PAGE_IGNORED_MASK,
            ..Default::default()
        },
        PageMask::GotEntryAndPosition => PageMaskValue {
            got_entry: DEFAULT_AARCH64_PAGE_IGNORED_MASK,
            place: DEFAULT_AARCH64_PAGE_IGNORED_MASK,
            ..Default::default()
        },
        PageMask::GotBase => PageMaskValue {
            got: DEFAULT_AARCH64_PAGE_IGNORED_MASK,
            ..Default::default()
        },
    }
}

#[inline(always)]
pub(crate) fn write_relocation_to_buffer(
    rel_info: RelocationKindInfo,
    value: u64,
    output: &mut [u8],
) -> Result<()> {
    rel_info.verify(value as i64)?;

    match rel_info.size {
        RelocationSize::ByteSize(byte_size) => {
            ensure!(
                byte_size <= output.len(),
                "Relocation outside of bounds of section"
            );
            let value_bytes = value.to_le_bytes();
            output[..byte_size].copy_from_slice(&value_bytes[..byte_size]);
        }
        RelocationSize::BitMasking(BitMask {
            range,
            instruction: insn,
        }) => {
            let extracted_value = extract_bits(value, range.start, range.end);
            let negative = (value as i64).is_negative();
            insn.write_to_value(extracted_value, negative, &mut output[..4]);
        }
    }

    Ok(())
}

pub(crate) fn slice_from_all_bytes_mut<T: object::Pod>(data: &mut [u8]) -> &mut [T] {
    object::slice_from_bytes_mut(data, data.len() / size_of::<T>())
        .unwrap()
        .0
}

pub(crate) fn is_hidden_symbol(symbol: &crate::elf::Symbol) -> bool {
    symbol.st_visibility() == object::elf::STV_HIDDEN
}
