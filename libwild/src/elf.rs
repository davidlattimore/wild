use crate::error::Result;
use crate::resolution::LoadedMetrics;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use anyhow::Context;
use bytemuck::Pod;
use bytemuck::Zeroable;
use linker_utils::elf::sht;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::SectionType;
use object::read::elf::CompressionHeader;
use object::read::elf::FileHeader as _;
use object::read::elf::ProgramHeader as _;
use object::read::elf::RelocationSections;
use object::read::elf::SectionHeader as _;
use object::LittleEndian;
use std::borrow::Cow;
use std::io::Read as _;
use std::mem::offset_of;
use std::sync::atomic::Ordering;

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
pub(crate) type NoteHeader = object::elf::NoteHeader64<LittleEndian>;

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
                    header.p_filesz(e) as usize / size_of::<DynamicEntry>(),
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

/// Get some entries from `data` as a slice of some Pod type. Alignment of `T` must be 1.
pub(crate) fn get_entries<T: object::Pod>(
    data: &[u8],
    offset: usize,
    entry_count: usize,
) -> Result<&[T]> {
    debug_assert_eq!(align_of::<T>(), 1);
    if offset >= data.len() {
        bail!("Invalid offset 0x{offset}");
    }
    Ok(object::slice_from_bytes(&data[offset..], entry_count)
        .map_err(|()| {
            anyhow!(
                "Tried to extract 0x{:x} entries of size 0x{:x} from 0x{:x}",
                entry_count,
                size_of::<T>(),
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

#[derive(Debug, Clone, Copy)]
pub(crate) enum PageMask {
    SymbolPlusAddendAndPosition,
    GotEntryAndPosition,
    GotBase,
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

pub(crate) const DEFAULT_AARCH64_PAGE_SIZE: u64 = 0x1000; // 4096
pub(crate) const DEFAULT_AARCH64_PAGE_MASK: u64 = DEFAULT_AARCH64_PAGE_SIZE - 1;
pub(crate) const DEFAULT_AARCH64_PAGE_IGNORED_MASK: u64 = !DEFAULT_AARCH64_PAGE_MASK;

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

/// Extract range-specified ([`start`..`end`]) bits from the provided `value`.
pub fn extract_bits(value: u64, start: u32, end: u32) -> u64 {
    debug_assert!(start < end);
    (value >> (start)) & ((1 << (end - start)) - 1)
}

#[cfg(test)]
mod tests {
    use super::extract_bits;

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
        extract_bits(0, 2, 1);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn test_extract_bits_too_large() {
        extract_bits(0, 0, 100);
    }
}

// Half-opened range bounded inclusively below and exclusively above: [`start``, `end`)
#[derive(Clone, Debug, Copy)]
pub(crate) struct BitRange {
    pub(crate) start: u32,
    pub(crate) end: u32,
}

#[derive(Clone, Debug, Copy)]
pub(crate) enum RelocationInstruction {
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

#[derive(Clone, Debug, Copy)]
pub(crate) enum RelocationSize {
    ByteSize(usize),
    BitMasking {
        range: BitRange,
        insn: RelocationInstruction,
    },
}

impl RelocationSize {
    pub(crate) fn write_to_buffer(self, value: u64, output: &mut [u8]) -> Result<()> {
        match self {
            RelocationSize::ByteSize(byte_size) => {
                ensure!(
                    byte_size <= output.len(),
                    "Relocation outside of bounds of section"
                );
                let value_bytes = value.to_le_bytes();
                output[..byte_size].copy_from_slice(&value_bytes[..byte_size]);
            }
            RelocationSize::BitMasking { range, insn } => {
                let extracted_value = extract_bits(value, range.start, range.end);
                let negative = (value as i64) < 0;
                insn.write_to_value(extracted_value, negative, &mut output[..4]);
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Copy)]
pub(crate) struct RelocationKindInfo {
    pub(crate) kind: RelocationKind,
    pub(crate) size: RelocationSize,
    pub(crate) mask: Option<PageMask>,
}

pub(crate) fn slice_from_all_bytes_mut<T: object::Pod>(data: &mut [u8]) -> &mut [T] {
    object::slice_from_bytes_mut(data, data.len() / size_of::<T>())
        .unwrap()
        .0
}

pub(crate) enum DynamicRelocationKind {
    Copy,
    Irelative,
    DtpMod,
    DtpOff,
    TpOff,
    Relative,
    DynamicSymbol,
}
