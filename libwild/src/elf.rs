use crate::Args;
use crate::alignment::Alignment;
use crate::arch::Architecture;
use crate::bail;
use crate::ensure;
use crate::error::Context as _;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::input_data::InputBytes;
use crate::input_data::InputRef;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::platform;
use crate::platform::CommonSymbol;
use crate::platform::ObjectFile as _;
use crate::platform::Platform;
use crate::platform::Relocation;
use crate::platform::RelocationSequence;
use crate::platform::Symbol as _;
use crate::resolution::LoadedMetrics;
use crate::symbol_db::Visibility;
use crate::timing_phase;
use hashbrown::HashMap;
use indexmap::IndexMap;
use itertools::Itertools as _;
use linker_utils::bit_misc::BitExtraction;
use linker_utils::elf::BitMask;
use linker_utils::elf::PageMask;
use linker_utils::elf::RISCV_ATTRIBUTE_VENDOR_NAME;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RelocationSize;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::SectionType;
use linker_utils::elf::riscvattr::TAG_RISCV_ARCH;
use linker_utils::elf::riscvattr::TAG_RISCV_ATOMIC_ABI;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC_MINOR;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC_REVISION;
use linker_utils::elf::riscvattr::TAG_RISCV_STACK_ALIGN;
use linker_utils::elf::riscvattr::TAG_RISCV_UNALIGNED_ACCESS;
use linker_utils::elf::riscvattr::TAG_RISCV_WHOLE_FILE;
use linker_utils::elf::riscvattr::TAG_RISCV_X3_REG_USAGE;
use linker_utils::elf::shf;
use linker_utils::elf::sht;
use object::LittleEndian;
use object::read::elf::CompressionHeader;
use object::read::elf::Crel;
use object::read::elf::CrelIterator;
use object::read::elf::Dyn as _;
use object::read::elf::FileHeader as _;
use object::read::elf::RelocationSections;
use object::read::elf::SectionHeader as _;
use rayon::prelude::*;
use std::borrow::Cow;
use std::ffi::CStr;
use std::io::Cursor;
use std::io::Read as _;
use std::mem::offset_of;
use std::num::NonZeroU32;
use std::ops::Range;
use std::sync::atomic::Ordering;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

/// Our starting address in memory when linking non-relocatable executables. We can start memory
/// addresses wherever we like, even from 0. We pick 400k because it's the same as what ld does and
/// because picking a distinctive non-zero values makes it more obvious what's happening if we mix
/// up file and memory offsets.
pub const NON_PIE_START_MEM_ADDRESS: u64 = 0x400_000;

pub(crate) const GLOBAL_POINTER_SYMBOL_NAME: &str = "__global_pointer$";

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
pub(crate) type VerneedIterator<'data> = object::read::elf::VerneedIterator<'data, FileHeader>;
pub(crate) type NoteHeader = object::elf::NoteHeader64<LittleEndian>;

type SectionTable<'data> = object::read::elf::SectionTable<'data, FileHeader>;
type SymbolTable<'data> = object::read::elf::SymbolTable<'data, FileHeader>;

#[derive(derive_more::Debug)]
pub(crate) struct File<'data> {
    pub(crate) arch: Architecture,
    #[debug(skip)]
    pub(crate) data: &'data [u8],
    #[debug(skip)]
    pub(crate) sections: SectionTable<'data>,
    /// This may be symtab or dynsym depending on the file type.
    #[debug(skip)]
    pub(crate) symbols: SymbolTable<'data>,
    #[debug(skip)]
    pub(crate) versym: &'data [Versym],

    /// An iterator over the version definitions and the corresponding linked string table index.
    pub(crate) verdef: Option<(VerdefIterator<'data>, object::SectionIndex)>,

    /// Number of verdef versions according to `sh_info` of `.gnu._version_d` section.
    pub(crate) verdefnum: u32,

    /// An iterator over the version references and the corresponding linked string table index.
    pub(crate) verneed: Option<(VerneedIterator<'data>, object::SectionIndex)>,

    /// e_flags from the header.
    pub(crate) eflags: u32,

    pub(crate) dynamic_tag_values: Option<DynamicTagValues<'data>>,
}

impl Relocation for Rela {
    type Sequence<'data> = &'data [Rela];

    fn symbol(&self) -> Option<object::SymbolIndex> {
        object::read::elf::Rela::symbol(self, LittleEndian, false)
    }

    fn raw_type(&self) -> u32 {
        object::read::elf::Rela::r_type(self, LittleEndian, false)
    }

    fn offset(&self) -> u64 {
        object::read::elf::Rela::r_offset(self, LittleEndian)
    }

    fn addend(&self) -> i64 {
        object::read::elf::Rela::r_addend(self, LittleEndian)
    }
}

impl Relocation for Crel {
    type Sequence<'data> = Vec<Crel>;

    fn symbol(&self) -> Option<object::SymbolIndex> {
        object::read::elf::Crel::symbol(self)
    }

    fn raw_type(&self) -> u32 {
        self.r_type
    }

    fn offset(&self) -> u64 {
        self.r_offset
    }

    fn addend(&self) -> i64 {
        self.r_addend
    }
}

/// A list of relocations that supports iteration.
#[derive(Clone)]
pub(crate) enum RelocationList<'data> {
    Rela(&'data [Rela]),
    Crel(CrelIterator<'data>),
}

impl<'data> RelocationSequence<'data> for &'data [Rela] {
    type Rel = Rela;

    fn rel_iter(&self) -> impl Iterator<Item = Rela> {
        self.iter().copied()
    }

    fn subsequence(&self, range: Range<usize>) -> Self {
        &self[range]
    }

    fn num_relocations(&self) -> usize {
        self.len()
    }
}

impl<'data> RelocationSequence<'data> for Vec<Crel> {
    type Rel = Crel;

    fn rel_iter(&self) -> impl Iterator<Item = Crel> {
        self.clone().into_iter()
    }

    fn subsequence(&self, range: Range<usize>) -> Self {
        self[range].to_vec()
    }

    fn num_relocations(&self) -> usize {
        self.len()
    }
}

// Not needing Drop opens the option of storing this type in an arena that doesn't support dropping
// its contents.
const _: () = assert!(!core::mem::needs_drop::<File>());

/// Threshold size for using parallel copy for section data copying.
const SECTION_PAR_COPY_SIZE_THRESHOLD: usize = 1_000_000;

impl<'data> platform::ObjectFile<'data> for File<'data> {
    type Symbol = Symbol;
    type SectionHeader = SectionHeader;
    type SectionIterator = core::slice::Iter<'data, Self::SectionHeader>;
    type DynamicTagValues = crate::elf::DynamicTagValues<'data>;
    type DynamicEntry = DynamicEntry;
    type RelocationList = RelocationList<'data>;
    type RelocationSections = RelocationSections;
    type VersionNames = VersionNames<'data>;
    type RawSymbolName = RawSymbolName<'data>;

    fn parse(input: &InputBytes<'data>, args: &Args) -> Result<Self> {
        let is_dynamic = input.kind == FileKind::ElfDynamic;

        let file = Self::parse_bytes(input.data, is_dynamic)?;

        if file.arch != args.arch {
            bail!(
                "`{}` has incompatible architecture: {}, expecting {}",
                input,
                file.arch,
                args.arch,
            )
        }

        Ok(file)
    }

    fn parse_bytes(data: &'data [u8], is_dynamic: bool) -> Result<Self> {
        let header = FileHeader::parse(data)?;
        let endian = header.endian()?;
        let architecture = header.e_machine(endian).try_into()?;
        let sections = header.sections(endian, data)?;
        let eflags = header.e_flags(endian);

        let mut symbols = SymbolTable::default();
        let mut versym: &[Versym] = &[];
        let mut verdef = None;
        let mut verdefnum = 0;
        let mut verneed = None;

        // Find all the sections that we're interested in a single scan of the section table so
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
                    verdefnum = section.sh_info(endian);
                }
                sht::GNU_VERNEED => {
                    verneed = section.gnu_verneed(endian, data)?;
                }
                _ => {}
            }
        }

        let dynamic_tag_values =
            is_dynamic.then(|| DynamicTagValues::read(&sections, data, &symbols));

        Ok(Self {
            arch: architecture,
            data,
            sections,
            symbols,
            versym,
            verdef,
            verdefnum,
            verneed,
            eflags,
            dynamic_tag_values,
        })
    }

    fn section(&self, index: object::SectionIndex) -> Result<&'data Self::SectionHeader> {
        Ok(self.sections.section(index)?)
    }

    fn section_by_name(&self, name: &str) -> Option<(object::SectionIndex, &'data SectionHeader)> {
        self.sections.section_by_name(LittleEndian, name.as_bytes())
    }

    fn section_name(&self, section: &SectionHeader) -> Result<&'data [u8]> {
        Ok(self.sections.section_name(LittleEndian, section)?)
    }

    fn section_display_name(&self, index: object::SectionIndex) -> Cow<'data, str> {
        self.section(index)
            .and_then(|section| self.section_name(section))
            .map_or_else(
                |_| format!("<index {}>", index.0).into(),
                String::from_utf8_lossy,
            )
    }

    fn raw_section_data(&self, section: &Self::SectionHeader) -> Result<&'data [u8]> {
        Ok(section.data(LittleEndian, self.data)?)
    }

    fn section_data(
        &self,
        section: &Self::SectionHeader,
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

    fn copy_section_data(&self, section: &SectionHeader, out: &mut [u8]) -> Result {
        let data = section.data(LittleEndian, self.data)?;

        if let Some((compression, _, _)) = section.compression(LittleEndian, self.data)? {
            decompress_into(compression, &data[COMPRESSION_HEADER_SIZE..], out)?;
        } else if section.sh_type(LittleEndian) == object::elf::SHT_NOBITS {
            out.fill(0);
        } else if data.len() >= SECTION_PAR_COPY_SIZE_THRESHOLD {
            let threads = rayon::current_num_threads();
            let chunk_size = (data.len() / threads).max(1);

            data.par_chunks(chunk_size)
                .zip(out.par_chunks_mut(chunk_size))
                .for_each(|(src, dst)| dst.copy_from_slice(src));
        } else {
            out.copy_from_slice(data);
        }
        Ok(())
    }

    fn section_data_cow(&self, section: &SectionHeader) -> Result<Cow<'data, [u8]>> {
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

    fn section_size(&self, section: &SectionHeader) -> Result<u64> {
        Ok(section.compression(LittleEndian, self.data)?.map_or_else(
            || section.sh_size.get(LittleEndian),
            |compression| compression.0.ch_size(LittleEndian),
        ))
    }

    fn section_alignment(&self, section: &SectionHeader) -> Result<u64> {
        Ok(section.compression(LittleEndian, self.data)?.map_or_else(
            || section.sh_addralign(LittleEndian),
            |compression| compression.0.ch_addralign(LittleEndian),
        ))
    }

    fn relocations(
        &self,
        index: object::SectionIndex,
        relocations: &Self::RelocationSections,
    ) -> Result<RelocationList<'data>> {
        let Some(section_index) = relocations.get(index) else {
            return Ok(RelocationList::Rela(&[]));
        };
        let section = self.sections.section(section_index)?;
        Ok(
            if let Some((rela, _)) = section.rela(LittleEndian, self.data)? {
                RelocationList::Rela(rela)
            } else if let Some((crel, _)) = section.crel(LittleEndian, self.data)? {
                RelocationList::Crel(crel)
            } else {
                RelocationList::Rela(&[])
            },
        )
    }

    fn symbol(&self, index: object::SymbolIndex) -> Result<&'data Symbol> {
        Ok(self.symbols.symbol(index)?)
    }

    fn symbol_name(&self, symbol: &Self::Symbol) -> Result<&'data [u8]> {
        Ok(self.symbols.symbol_name(LittleEndian, symbol)?)
    }

    fn symbol_section(
        &self,
        symbol: &Self::Symbol,
        index: object::SymbolIndex,
    ) -> Result<Option<object::SectionIndex>> {
        Ok(self.symbols.symbol_section(LittleEndian, symbol, index)?)
    }

    fn dynamic_tags(&self) -> Result<&'data [Self::DynamicEntry]> {
        dynamic_tags(&self.sections, self.data)
    }

    fn parse_relocations(&self) -> Result<Self::RelocationSections> {
        Ok(self
            .sections
            .relocation_sections(LittleEndian, self.symbols.section())?)
    }

    fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    fn is_dynamic(&self) -> bool {
        self.dynamic_tag_values.is_some()
    }

    fn dynamic_tag_values(&self) -> Option<Self::DynamicTagValues> {
        self.dynamic_tag_values
    }

    fn symbol_version_debug(&self, symbol_index: object::SymbolIndex) -> Option<String> {
        let endian = LittleEndian;
        let versym = self.versym.get(symbol_index.0)?;
        let versym = versym.0.get(endian);
        let is_default = versym & object::elf::VERSYM_HIDDEN == 0;
        let symbol_version_index = versym & object::elf::VERSYM_VERSION;
        if let Some((verdefs, string_table_index)) = self.verdef.clone() {
            let strings = self
                .sections
                .strings(endian, self.data, string_table_index)
                .ok()?;
            for r in verdefs {
                let (verdef, aux_iterator) = r.ok()?;
                for aux in aux_iterator {
                    let aux = aux.ok()?;
                    let version_index = verdef.vd_ndx.get(endian);
                    if version_index == symbol_version_index {
                        return Some(format!(
                            "{}{}",
                            if is_default { "@@" } else { "@" },
                            String::from_utf8_lossy(aux.name(endian, strings).ok()?)
                        ));
                    }
                }
            }
        }
        if let Some((verneeds, string_table_index)) = self.verneed.clone() {
            let strings = self
                .sections
                .strings(endian, self.data, string_table_index)
                .ok()?;
            for r in verneeds {
                let (_verneed, aux_iterator) = r.ok()?;
                for aux in aux_iterator {
                    let aux = aux.ok()?;
                    let version_index = aux.vna_other.get(endian);
                    if version_index == symbol_version_index {
                        return Some(format!(
                            "{}{}",
                            if is_default { "@@" } else { "@" },
                            String::from_utf8_lossy(aux.name(endian, strings).ok()?)
                        ));
                    }
                }
            }
        }
        None
    }

    fn section_iter(&self) -> Self::SectionIterator {
        self.sections.iter()
    }

    fn get_version_names(&self) -> Result<Self::VersionNames> {
        let endian = LittleEndian;

        let mut version_names = vec![None; self.verdefnum as usize + 1];

        // See https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/symversion.html
        // for information about symbol versioning.

        if let Some((verdefs, string_table_index)) = &self.verdef {
            let strings = self
                .sections
                .strings(endian, self.data, *string_table_index)?;

            for r in verdefs.clone() {
                let (verdef, mut aux_iterator) = r?;
                // Every VERDEF entry should have at least one AUX entry. We currently only care
                // about the first one.
                let aux = aux_iterator.next()?.context("VERDEF with no AUX entry")?;
                let version_index = verdef.vd_ndx.get(endian);
                let name = aux.name(endian, strings)?;

                *version_names
                    .get_mut(usize::from(version_index))
                    .with_context(|| format!("Invalid version index {version_index}"))? =
                    Some(name);
            }
        }

        Ok(VersionNames {
            names: version_names,
        })
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &crate::elf::Symbol,
        local_index: usize,
        version_names: &VersionNames<'data>,
    ) -> Result<Self::RawSymbolName> {
        let name_bytes = self.symbol_name(symbol)?;

        let is_default;
        let version_name;

        if let Some(versym) = self.versym.get(local_index) {
            let versym = versym.0.get(LittleEndian);
            is_default = versym & object::elf::VERSYM_HIDDEN == 0;
            let version_index = versym & object::elf::VERSYM_VERSION;
            version_name = version_names
                .names
                .get(usize::from(version_index))
                .copied()
                .flatten();
        } else {
            is_default = true;
            version_name = None;
        };

        Ok(RawSymbolName {
            name: name_bytes,
            version_name,
            is_default,
        })
    }

    fn symbols_iter(&self) -> impl Iterator<Item = &'data Self::Symbol> {
        self.symbols.iter()
    }
}

impl platform::SectionHeader for SectionHeader {
    type SectionFlags = SectionFlags;
    type Attributes = SectionAttributes;

    fn flags(&self) -> Self::SectionFlags {
        SectionFlags::from_header(self)
    }

    fn attributes(&self) -> Self::Attributes {
        Self::Attributes {
            flags: SectionFlags::from_header(self),
            ty: SectionType::from_header(self),
            entsize: self.sh_entsize.get(LittleEndian),
        }
    }
}

impl platform::SectionFlags for SectionFlags {
    fn is_alloc(self) -> bool {
        self.contains(shf::ALLOC)
    }

    fn is_writable(self) -> bool {
        self.contains(shf::WRITE)
    }
}

impl platform::Symbol for Symbol {
    fn as_common(&self) -> Option<CommonSymbol> {
        let e = LittleEndian;
        if !object::read::elf::Sym::is_common(self, e) {
            return None;
        }

        // Common symbols misuse the value field (which we access via `address()`) to store the
        // alignment.
        let Ok(alignment) = Alignment::new(object::read::elf::Sym::st_value(self, e)) else {
            return None;
        };
        let size = alignment.align_up(object::read::elf::Sym::st_size(self, e));

        let output_section_id = if self.st_type() == object::elf::STT_TLS {
            output_section_id::TBSS
        } else {
            output_section_id::BSS
        };

        let part_id = output_section_id.part_id_with_alignment(alignment);

        Some(CommonSymbol { size, part_id })
    }

    fn is_undefined(&self) -> bool {
        object::read::elf::Sym::is_undefined(self, LittleEndian)
    }

    fn is_local(&self) -> bool {
        object::read::elf::Sym::is_local(self)
    }

    fn visibility(&self) -> Visibility {
        Visibility::from_elf_st_visibility(self.st_visibility())
    }

    fn is_absolute(&self) -> bool {
        object::read::elf::Sym::is_absolute(self, LittleEndian)
    }

    fn is_weak(&self) -> bool {
        object::read::elf::Sym::is_weak(self)
    }

    fn value(&self) -> u64 {
        object::read::elf::Sym::st_value(self, LittleEndian)
    }

    fn size(&self) -> u64 {
        object::read::elf::Sym::st_size(self, LittleEndian)
    }

    fn section_index(&self) -> object::SectionIndex {
        object::SectionIndex(usize::from(object::read::elf::Sym::st_shndx(
            self,
            LittleEndian,
        )))
    }

    fn has_name(&self) -> bool {
        object::read::elf::Sym::st_name(self, LittleEndian) != 0
    }

    fn debug_string(&self) -> String {
        SymDebug(self).to_string()
    }

    fn is_tls(&self) -> bool {
        self.st_type() == object::elf::STT_TLS
    }

    fn is_interposable(&self) -> bool {
        self.st_visibility() == object::elf::STV_DEFAULT
    }

    fn is_func(&self) -> bool {
        self.st_type() == object::elf::STT_FUNC
    }

    fn is_ifunc(&self) -> bool {
        self.st_type() == object::elf::STT_GNU_IFUNC
    }

    fn is_hidden(&self) -> bool {
        self.st_visibility() == object::elf::STV_HIDDEN
    }
}

fn dynamic_tags<'data>(
    sections: &object::read::elf::SectionTable<'data, object::elf::FileHeader64<LittleEndian>>,
    data: &'data [u8],
) -> Result<&'data [object::elf::Dyn64<LittleEndian>]> {
    let e = LittleEndian;
    if let Some(dynamic) = sections.dynamic(e, data).transpose() {
        return dynamic
            .map(|(dynamic, _)| dynamic)
            .context("Failed to read dynamic table");
    }
    Ok(&[])
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
        // We might use pure Rust implementation for the decompression (ruzstd), however the
        // decompression speed is not on par with the official C library.
        // With the official library, the linking time of Clang binary (contains 1GB of debug info
        // sections) shrinks by 30%!
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
#[derive(FromBytes, IntoBytes, KnownLayout, Clone, Copy)]
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

#[derive(FromBytes, IntoBytes, KnownLayout, Clone, Copy)]
#[repr(C)]
pub(crate) struct EhFrameHdrEntry {
    pub(crate) frame_ptr: i32,
    pub(crate) frame_info_ptr: i32,
}

#[derive(FromBytes, Clone, Copy)]
#[repr(C)]
pub(crate) struct EhFrameEntryPrefix {
    pub(crate) length: u32,
    pub(crate) cie_id: u32,
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

#[derive(FromBytes, IntoBytes, KnownLayout, Clone, Copy)]
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
        PageMask::SymbolPlusAddendAndPosition(mask) => PageMaskValue {
            symbol_plus_addend: !mask,
            place: !mask,
            ..Default::default()
        },
        PageMask::GotEntryAndPosition(mask) => PageMaskValue {
            got_entry: !mask,
            place: !mask,
            ..Default::default()
        },
        PageMask::GotBase(mask) => PageMaskValue {
            got: !mask,
            ..Default::default()
        },
        PageMask::Position(mask) => PageMaskValue {
            place: !mask,
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

    if matches!(rel_info.kind, RelocationKind::PairSubtractionULEB128(..)) {
        // u64 always fits in 10 bytes in the ULEB format: 64 / 7 = 9.14
        let mut writer = Cursor::new(vec![0u8; 10]);
        let n = leb128::write::unsigned(&mut writer, value).expect("Must fit into the buffer");
        ensure!(
            output.len() >= n,
            "cannot write encoded ULEB128 value of {n} bytes"
        );
        output[..n].copy_from_slice(&writer.into_inner()[..n]);
    } else {
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
                let extracted_value = value.extract_bit_range(range.start..range.end);
                let negative = (value as i64).is_negative();
                let output_len = output.len();
                insn.write_to_value(extracted_value, negative, &mut output[..output_len]);
            }
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
    symbol.is_hidden()
}

#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct DynamicTagValues<'data> {
    pub(crate) verdefnum: u64,
    pub(crate) soname: Option<&'data [u8]>,
}

impl<'data> DynamicTagValues<'data> {
    fn read(
        sections: &object::read::elf::SectionTable<'data, object::elf::FileHeader64<LittleEndian>>,
        data: &'data [u8],
        symbols: &SymbolTable<'data>,
    ) -> Self {
        let mut values = DynamicTagValues::default();
        let Ok(dynamic_tags) = dynamic_tags(sections, data) else {
            return values;
        };
        let e = LittleEndian;
        for entry in dynamic_tags {
            let value = entry.d_val(e);
            match entry.d_tag(e) as u32 {
                object::elf::DT_VERDEFNUM => {
                    values.verdefnum = value;
                }
                object::elf::DT_SONAME => {
                    values.soname = symbols.strings().get(value as u32).ok();
                }
                _ => {}
            }
        }
        values
    }

    pub(crate) fn lib_name(&self, input: &InputRef<'data>) -> &'data [u8] {
        self.soname.unwrap_or_else(|| input.lib_name())
    }
}

struct SymDebug<'data>(pub(crate) &'data crate::elf::SymtabEntry);

impl std::fmt::Display for SymDebug<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let e = LittleEndian;
        let sym = self.0;

        let vis = if object::read::elf::Sym::is_local(sym) {
            "Local"
        } else if object::read::elf::Sym::is_weak(sym) {
            "Weak"
        } else {
            "Global"
        };

        let kind = if object::read::elf::Sym::is_undefined(sym, e) {
            "Undefined"
        } else {
            match sym.st_type() {
                object::elf::STT_FUNC => "Func",
                object::elf::STT_GNU_IFUNC => "IFunc",
                object::elf::STT_OBJECT => "Data",
                object::elf::STT_COMMON => "Common",
                object::elf::STT_SECTION => "Section",
                object::elf::STT_FILE => "File",
                object::elf::STT_NOTYPE => "NoType",
                object::elf::STT_TLS => "Tls",
                _ => "Unknown",
            }
        };

        write!(f, "{vis} {kind}")
    }
}

pub(crate) enum PropertyClass {
    // A bit in the output pr_data is set if it is set in any relocatable input.
    // If all bits in the output pr_data field are zero, this property should be removed from
    // output.
    Or,
    // A bit in the output pr_data field is set only if it is set in all relocatable input pr_data
    // fields. If all bits in the output pr_data field are zero, this property should be
    // removed from output.
    And,
    // A bit in the output pr_data field is set if it is set in any relocatable input pr_data
    // fields and this property is present in all relocatable input files. When all bits in
    // the output pr_data field are zero, this property should not be removed from output to
    // indicate it has zero in all bits.
    AndOr,
}

#[derive(Debug)]
pub(crate) struct GnuProperty {
    pub(crate) ptype: u32,
    pub(crate) data: u32,
}

#[derive(Debug)]
pub(crate) struct RiscVArch {
    map: IndexMap<String, (u64, u64)>,
}

impl RiscVArch {
    pub(crate) fn to_attribute_string(&self) -> String {
        self.map
            .iter()
            .map(|(arch, (major, minor))| format!("{arch}{major}p{minor}"))
            .join("_")
            .clone()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Eflags(pub(crate) u32);

#[derive(Debug)]
pub(crate) struct RiscVAttributes {
    pub(crate) attributes: Vec<RiscVAttribute>,
    pub(crate) section_size: u64,
}

#[derive(Debug)]
pub(crate) enum RiscVAttribute {
    /// Indicates the stack alignment requirement in bytes.
    StackAlign(u64),
    /// Indicates the target architecture of this object.
    Arch(RiscVArch),
    /// Indicates whether to impose unaligned memory accesses in code generation.
    UnalignedAccess(bool),
    /// Indicates the major version of the privileged specification.
    PrivilegedSpecMajor(u64),
    /// Indicates the major version of the privileged specification.
    PrivilegedSpecMinor(u64),
    /// Indicates the revision version of the privileged specification.
    PrivilegedSpecRevision(u64),
}

#[derive(Default)]
pub(crate) struct ElfObjectLayoutState {
    pub(crate) gnu_property_notes: Vec<GnuProperty>,
    pub(crate) riscv_attributes: Vec<RiscVAttribute>,
}

#[derive(Debug)]
pub(crate) struct ElfLayoutProperties {
    pub(crate) gnu_property_notes: Vec<GnuProperty>,
    pub(crate) riscv_attributes: RiscVAttributes,
    pub(crate) eflags: Eflags,
}

impl ElfLayoutProperties {
    pub(crate) fn new<'files, 'states, 'data: 'files, P: Platform<'data>>(
        objects: impl Iterator<Item = &'files File<'data>>,
        states: impl Iterator<Item = &'states ElfObjectLayoutState> + Clone,
        args: &Args,
    ) -> Result<Self> {
        let gnu_property_notes = merge_gnu_property_notes::<P>(states.clone(), args.z_isa)?;
        let riscv_attributes = merge_riscv_attributes::<P>(states)?;
        let eflags = merge_eflags::<P>(objects)?;

        Ok(Self {
            gnu_property_notes,
            riscv_attributes,
            eflags,
        })
    }
}

fn merge_gnu_property_notes<'states, 'data, P: Platform<'data>>(
    states: impl Iterator<Item = &'states ElfObjectLayoutState>,
    isa_needed: Option<NonZeroU32>,
) -> Result<Vec<GnuProperty>> {
    timing_phase!("Merge GNU property notes");

    let properties_per_file = states.map(|state| &state.gnu_property_notes).collect_vec();

    // Merge bits of each property type based on type: OR or AND operation.
    let mut property_map = HashMap::new();

    for file_props in &properties_per_file {
        for prop in *file_props {
            let property_class = P::get_property_class(prop.ptype)
                .ok_or_else(|| crate::error!("unclassified property type {}", prop.ptype))?;
            property_map
                .entry(prop.ptype)
                .and_modify(|entry: &mut (u32, PropertyClass)| {
                    if matches!(property_class, PropertyClass::And) {
                        entry.0 &= prop.data;
                    } else {
                        entry.0 |= prop.data;
                    }
                })
                .or_insert_with(|| (prop.data, property_class));
        }
    }

    // Merge needed ISA from CLI if set.
    if let Some(isa_needed) = isa_needed {
        property_map
            .entry(object::elf::GNU_PROPERTY_X86_ISA_1_NEEDED)
            .or_insert((0, PropertyClass::Or))
            .0 |= isa_needed.get();
    }

    // Iterate the properties sorted by property_type so that we have a stable output!
    let output_properties = property_map
        .into_iter()
        .sorted_by_key(|x| x.0)
        .filter_map(|(property_type, (property_value, property_class))| {
            let type_present_in_all = properties_per_file.iter().all(|props_per_file| {
                props_per_file
                    .iter()
                    .any(|prop| prop.ptype == property_type)
            });
            if match property_class {
                PropertyClass::Or => property_value != 0,
                PropertyClass::And => type_present_in_all && property_value != 0,
                PropertyClass::AndOr => type_present_in_all,
            } {
                Some(GnuProperty {
                    ptype: property_type,
                    data: property_value,
                })
            } else {
                None
            }
        })
        .collect_vec();

    Ok(output_properties)
}

fn merge_eflags<'files, 'data: 'files, P: Platform<'data>>(
    objects: impl Iterator<Item = &'files File<'data>>,
) -> Result<Eflags> {
    timing_phase!("Merge e_flags");

    Ok(Eflags(P::merge_eflags(
        objects.map(|object| object.eflags),
    )?))
}

fn merge_riscv_attributes<'groups, 'data, P: Platform<'data>>(
    states: impl Iterator<Item = &'groups ElfObjectLayoutState>,
) -> Result<RiscVAttributes> {
    timing_phase!("Merge .riscv.attributes sections");

    let attributes = states
        .map(|state| &state.riscv_attributes)
        // Sort by the number of ISAs: better output ordering
        .sorted_by_key(|x| x.len())
        .rev()
        .flatten()
        .collect_vec();

    let mut merged = Vec::new();

    let mut arch_components = IndexMap::new();
    for (name, version) in attributes
        .iter()
        .filter_map(|a| {
            if let RiscVAttribute::Arch(arch) = a {
                Some(&arch.map)
            } else {
                None
            }
        })
        .flatten()
    {
        arch_components
            .entry(name.clone())
            .and_modify(|v: &mut (u64, u64)| *v = (*v).max(*version))
            .or_insert(*version);
    }

    verify_riscv_ext_conflicts(&arch_components)?;

    if !arch_components.is_empty() {
        merged.push(RiscVAttribute::Arch(RiscVArch {
            map: arch_components,
        }));
    }

    if let Some(align) = attributes
        .iter()
        .filter_map(|a| {
            if let RiscVAttribute::StackAlign(align) = a {
                Some(align)
            } else {
                None
            }
        })
        .max()
    {
        merged.push(RiscVAttribute::StackAlign(*align));
    }
    if let Some(access) = attributes
        .iter()
        .filter_map(|a| {
            if let RiscVAttribute::UnalignedAccess(access) = a {
                Some(access)
            } else {
                None
            }
        })
        .max()
    {
        merged.push(RiscVAttribute::UnalignedAccess(*access));
    }
    if let Some(version) = attributes
        .iter()
        .filter_map(|a| {
            if let RiscVAttribute::PrivilegedSpecMajor(version) = a {
                Some(version)
            } else {
                None
            }
        })
        .max()
    {
        merged.push(RiscVAttribute::PrivilegedSpecMajor(*version));
    }
    if let Some(version) = attributes
        .iter()
        .filter_map(|a| {
            if let RiscVAttribute::PrivilegedSpecMinor(version) = a {
                Some(version)
            } else {
                None
            }
        })
        .max()
    {
        merged.push(RiscVAttribute::PrivilegedSpecMinor(*version));
    }
    if let Some(version) = attributes
        .iter()
        .filter_map(|a| {
            if let RiscVAttribute::PrivilegedSpecRevision(version) = a {
                Some(version)
            } else {
                None
            }
        })
        .max()
    {
        merged.push(RiscVAttribute::PrivilegedSpecRevision(*version));
    }

    let section_size = riscv_attributes_section_size(&merged);

    Ok(RiscVAttributes {
        attributes: merged,
        section_size,
    })
}

/// Conflicting pairs of RISC-V ISA extensions.
const RISCV_CONFLICTING_EXT_PAIRS: &[(&str, &str)] = &[
    ("f", "zfinx"),
    ("d", "zdinx"),
    ("q", "zqinx"),
    ("zfh", "zhinx"),
    ("zfhmin", "zhinxmin"),
];

fn verify_riscv_ext_conflicts(arch_components: &IndexMap<String, (u64, u64)>) -> Result {
    if arch_components.is_empty() {
        return Ok(());
    }

    let mut conflicts = Vec::new();
    for &(std_ext, inx_ext) in RISCV_CONFLICTING_EXT_PAIRS {
        if arch_components.contains_key(std_ext) && arch_components.contains_key(inx_ext) {
            conflicts.push(format!("'{std_ext}' is incompatible with '{inx_ext}'"));
        }
    }

    if conflicts.is_empty() {
        Ok(())
    } else {
        bail!(
            "Conflicting RISC-V ISA extensions in merged .riscv.attributes:\n  - {}",
            conflicts.join("\n  - ")
        );
    }
}

pub(crate) fn gnu_property_notes_section_size(gnu_property_notes: &[GnuProperty]) -> u64 {
    if gnu_property_notes.is_empty() {
        0
    } else {
        (size_of::<NoteHeader>()
            + GNU_NOTE_NAME.len()
            + gnu_property_notes.len() * GNU_NOTE_PROPERTY_ENTRY_SIZE) as u64
    }
}

fn riscv_attributes_section_size(riscv_attributes: &[RiscVAttribute]) -> u64 {
    let size_of_uleb_encoded = |value| {
        let mut cursor = Cursor::new([0u8; 10]);
        leb128::write::unsigned(&mut cursor, value).unwrap()
    };

    (if riscv_attributes.is_empty() {
        0
    } else {
        1 // 'A'
            + 4 // sizeof(u32)
            + size_of_uleb_encoded(TAG_RISCV_WHOLE_FILE)
            + 4 // sizeof(u32)
            + RISCV_ATTRIBUTE_VENDOR_NAME.len() + 1
            + riscv_attributes.iter().map(|attr| {
                match attr {
                    RiscVAttribute::StackAlign(align) => {
                                        size_of_uleb_encoded(TAG_RISCV_STACK_ALIGN) +
                                        size_of_uleb_encoded(*align)
                                    }
                    RiscVAttribute::Arch(arch) => {
                                        size_of_uleb_encoded(TAG_RISCV_ARCH)
                                        +arch.to_attribute_string().len() + 1
                                    }
                    RiscVAttribute::UnalignedAccess(_) => {
                                        size_of_uleb_encoded(TAG_RISCV_UNALIGNED_ACCESS) + 1
                                    }
                    RiscVAttribute::PrivilegedSpecMajor(version) => {
                                        size_of_uleb_encoded(TAG_RISCV_PRIV_SPEC) +
                                        size_of_uleb_encoded(*version)
                    },
                    RiscVAttribute::PrivilegedSpecMinor(version) => {
                                        size_of_uleb_encoded(TAG_RISCV_PRIV_SPEC_MINOR) +
                                        size_of_uleb_encoded(*version)
                    }
                    RiscVAttribute::PrivilegedSpecRevision(version) => {
                                        size_of_uleb_encoded(TAG_RISCV_PRIV_SPEC_REVISION) +
                                        size_of_uleb_encoded(*version)
                    }
                                    }
            }).sum::<usize>()
    }) as u64
}

pub(crate) fn process_riscv_attributes(
    object: &File,
    riscv_attributes_section_index: object::SectionIndex,
) -> Result<Vec<RiscVAttribute>> {
    let section = object.section(riscv_attributes_section_index)?;
    let e = LittleEndian;

    let content = section.data(e, object.data)?;
    ensure!(content.starts_with(b"A"), "Header must start with 'A'");
    let mut content = &content[1..];

    let read_uleb128 = |content: &mut &[u8]| leb128::read::unsigned(content);
    let read_string = |content: &mut &[u8]| -> Result<String> {
        let string = CStr::from_bytes_until_nul(content)?;
        *content = &content[string.count_bytes() + 1..];
        Ok(string.to_string_lossy().to_string())
    };
    let read_u32 = |content: &mut &[u8]| -> Result<u32> {
        let value = u32::from_le_bytes(content[..4].try_into()?);
        *content = &content[4..];
        Ok(value)
    };

    // Expect only one subsection
    let _size = read_u32(&mut content)?;
    let vendor = read_string(&mut content).context("Cannot read vendor string")?;
    ensure!(
        vendor == RISCV_ATTRIBUTE_VENDOR_NAME,
        "Unsupported vendor ('{vendor:?}') subsection"
    );

    // Assume only one sub-sub-section
    let tag = read_uleb128(&mut content).context("Cannot read tag of subsection")?;
    ensure!(tag == TAG_RISCV_WHOLE_FILE, "Whole file tag expected");
    let _size = read_u32(&mut content)?;
    let mut attributes = Vec::new();

    while !content.is_empty() {
        let tag = read_uleb128(&mut content).context("Cannot read tag of sub-subsection")?;
        let attribute = match tag {
            TAG_RISCV_STACK_ALIGN => {
                let align = read_uleb128(&mut content).context("Cannot read stack alignment")?;
                RiscVAttribute::StackAlign(align)
            }
            TAG_RISCV_ARCH => {
                let arch = read_string(&mut content).context("Cannot read arch attributes")?;
                let components = arch
                    .split('_')
                    .map(|part| {
                        let mut it = part.chars().rev();
                        let minor = it
                            .next()
                            .ok_or_else(|| crate::error!("Cannot parse minor"))?
                            .to_string();
                        let p = it
                            .next()
                            .ok_or_else(|| crate::error!("Cannot parse 'p' separator"))?;
                        ensure!(p == 'p', "Separator expected");
                        let major = it
                            .next()
                            .ok_or_else(|| crate::error!("Cannot parse major"))?
                            .to_string();
                        let name = String::from_iter(it.rev());
                        Ok((name, (major.parse()?, minor.parse()?)))
                    })
                    .collect::<Result<IndexMap<_, _>>>()?;

                RiscVAttribute::Arch(RiscVArch { map: components })
            }
            TAG_RISCV_UNALIGNED_ACCESS => {
                let access = read_uleb128(&mut content).context("Cannot read unaligned access")?;
                RiscVAttribute::UnalignedAccess(access > 0)
            }
            TAG_RISCV_PRIV_SPEC => {
                let version =
                    read_uleb128(&mut content).context("Cannot read privileged major version")?;
                RiscVAttribute::PrivilegedSpecMajor(version)
            }
            TAG_RISCV_PRIV_SPEC_MINOR => {
                let version =
                    read_uleb128(&mut content).context("Cannot read privileged minor version")?;
                RiscVAttribute::PrivilegedSpecMinor(version)
            }
            TAG_RISCV_PRIV_SPEC_REVISION => {
                let version = read_uleb128(&mut content)
                    .context("Cannot read privileged revision version")?;
                RiscVAttribute::PrivilegedSpecRevision(version)
            }
            TAG_RISCV_ATOMIC_ABI => {
                let _abi = read_uleb128(&mut content).context("Cannot read atomic ABI")?;
                bail!("TAG_RISCV_ATOMIC_ABI is not supported yet");
            }
            TAG_RISCV_X3_REG_USAGE => {
                let _x3 = read_uleb128(&mut content).context("Cannot read x3 register usage")?;
                bail!("TAG_RISCV_X3_REG_USAGE is not supported yet");
            }
            _ => {
                bail!("Unsupported tag: {tag}");
            }
        };
        attributes.push(attribute);
    }

    ensure!(content.is_empty(), "Unexpected multiple sub-sections");

    Ok(attributes)
}

/// Attributes that we'll take from an input section and apply to the output section into which it's
/// placed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SectionAttributes {
    flags: SectionFlags,
    ty: SectionType,
    entsize: u64,
}

/// Section flags that should be propagated from input sections to the output section in which they
/// are placed. Note, the inversion, so we keep all flags other than the one listed here.
const SECTION_FLAGS_PROPAGATION_MASK: SectionFlags =
    SectionFlags::from_u32(!object::elf::SHF_GROUP);

impl SectionAttributes {
    pub(crate) fn merge(&mut self, rhs: Self) {
        self.flags |= rhs.flags;

        // We somewhat arbitrarily tie-break by selecting the maximum type. This means for example
        // that types like SHT_INIT_ARRAY win out over more generic types like SHT_PROGBITS.
        self.ty = self.ty.max(rhs.ty);

        // If all input sections specify the same entsize, then we use that. If there's any
        // inconsistency, then we set entsize to 0.
        if self.entsize != rhs.entsize {
            self.entsize = 0;
        }
    }

    pub(crate) fn apply(&self, output_sections: &mut OutputSections, section_id: OutputSectionId) {
        let info = output_sections.section_infos.get_mut(section_id);

        info.section_flags |= self.flags & SECTION_FLAGS_PROPAGATION_MASK;

        info.entsize = self.entsize;

        info.ty = info.ty.max(self.ty);
    }
}

pub(crate) struct VersionNames<'data> {
    pub(crate) names: Vec<Option<&'data [u8]>>,
}

#[derive(Debug)]
pub(crate) struct RawSymbolName<'data> {
    pub(crate) name: &'data [u8],

    pub(crate) version_name: Option<&'data [u8]>,

    /// Whether the symbol can be referred to without a version.
    pub(crate) is_default: bool,
}

impl<'data> platform::RawSymbolName<'data> for RawSymbolName<'data> {
    fn parse(mut name_bytes: &'data [u8]) -> Self {
        let mut version_name = None;
        let mut is_default = true;

        // Symbols can contain version specifiers, e.g. `foo@1.1` or `foo@@2.0`. The latter,
        // with double-at specifies that it's the default version.
        if let Some(at_offset) = memchr::memchr(b'@', name_bytes) {
            if name_bytes[at_offset..].starts_with(b"@@") {
                version_name = Some(&name_bytes[at_offset + 2..]);
            } else {
                version_name = Some(&name_bytes[at_offset + 1..]);
                is_default = false;
            }

            name_bytes = &name_bytes[..at_offset];
        }

        RawSymbolName {
            name: name_bytes,
            version_name,
            is_default,
        }
    }

    fn name(&self) -> &'data [u8] {
        self.name
    }

    fn version_name(&self) -> Option<&'data [u8]> {
        self.version_name
    }

    fn is_default(&self) -> bool {
        self.is_default
    }
}
