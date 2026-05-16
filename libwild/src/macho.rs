// TODO
#![allow(unused)]

use crate::OutputKind;
use crate::alignment;
use crate::alignment::Alignment;
use crate::args::macho::MachOArgs;
use crate::ensure;
use crate::error;
use crate::error::Result;
use crate::file_writer::copy_section_data;
use crate::layout;
use crate::layout::Layout;
use crate::layout::OutputRecordLayout;
use crate::layout::Resolution;
use crate::layout::SymbolCopyInfo;
use crate::layout_rules::SectionKind;
use crate::layout_rules::SectionRule;
use crate::macho_writer;
use crate::output_section_id;
use crate::output_section_id::NUM_BUILT_IN_SECTIONS;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputOrderBuilder;
use crate::output_section_id::SectionName;
use crate::output_section_id::SectionOutputInfo;
use crate::part_id;
use crate::platform;
use crate::platform::ObjectFile;
use crate::symbol_db::Visibility;
use object::Endianness;
use object::SymbolIndex;
use object::macho;
use object::macho::N_ABS;
use object::macho::N_EXT;
use object::macho::N_PEXT;
use object::macho::N_SECT;
use object::macho::N_TYPE;
use object::macho::N_WEAK_DEF;
use object::macho::SEG_DATA;
use object::macho::SEG_LINKEDIT;
use object::macho::SEG_PAGEZERO;
use object::macho::SEG_TEXT;
use object::macho::Section64;
use object::read::macho::MachHeader;
use object::read::macho::Nlist;
use object::read::macho::Section;
use object::read::macho::Segment;
use std::borrow::Cow;
use zerocopy::BigEndian;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::U32;
use zerocopy::U64;

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct MachO;

const LE: Endianness = Endianness::Little;

/// Mach-O uses a zero page for all 32bit addresses and thus we begin the memory
/// offsets right after that (1GiB).
pub(crate) const MACHO_START_MEM_ADDRESS: u64 = 0x1_0000_0000;

/// The command alignment is 8B for 64-bit platforms.
pub(crate) const MACHO_COMMAND_ALIGNMENT: usize = 8;

/// A path to the default dynamic linker.
pub(crate) const DYLINKER_PATH: &[u8] = b"/usr/lib/dyld";
// TODO: optionality of __DATA and __CONST_DATA segments not respected
pub(crate) const DEFAULT_SEGMENT_COUNT: usize = 4;
pub(crate) const CHAINED_FIXUP_TABLE_SIZE: u64 =
    (size_of::<ChainedFixupsHeader>() + size_of::<u32>() * (DEFAULT_SEGMENT_COUNT + 1 + 1)) as u64;

type SectionHeader = Section64<crate::macho::Endianness>;
type SectionTable<'data> = &'data [Section64<crate::macho::Endianness>];
type SymbolTable<'data> = object::read::macho::SymbolTable<'data, macho::MachHeader64<Endianness>>;
type SymtabEntry = object::macho::Nlist64<Endianness>;
type Relocation = object::macho::Relocation<Endianness>;

pub(crate) type FileHeader = object::macho::MachHeader64<Endianness>;
pub(crate) type SegmentCommand = object::macho::SegmentCommand64<Endianness>;
pub(crate) type SectionEntry = object::macho::Section64<Endianness>;
pub(crate) type EntryPointCommand = object::macho::EntryPointCommand<Endianness>;
pub(crate) type DylinkerCommand = object::macho::DylinkerCommand<Endianness>;
pub(crate) type CodeSignatureCommand = object::macho::LinkeditDataCommand<Endianness>;
pub(crate) type DyldChainedFixupsCommand = object::macho::LinkeditDataCommand<Endianness>;
pub(crate) type ChainedFixupsHeader = DyldChainedFixupsHeader;
pub(crate) type SymtabCommand = object::macho::SymtabCommand<Endianness>;

// TODO: move the following data types to object crate

// values for dyld_chained_fixups_header.imports_format
#[allow(non_camel_case_types)]
#[repr(u32)]
pub(crate) enum DyldChainedFixupsImporstFormat {
    DYLD_CHAINED_IMPORT = 1,
    DYLD_CHAINED_IMPORT_ADDEND = 2,
    DYLD_CHAINED_IMPORT_ADDEND64 = 3,
}

// header of the LC_DYLD_CHAINED_FIXUPS payload
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub(crate) struct DyldChainedFixupsHeader {
    // 0
    pub(crate) fixups_version: U32<zerocopy::LittleEndian>,
    // offset of dyld_chained_starts_in_image in chain_data
    pub(crate) starts_offset: U32<zerocopy::LittleEndian>,
    // offset of imports table in chain_data
    pub(crate) imports_offset: U32<zerocopy::LittleEndian>,
    // offset of symbol strings in chain_data
    pub(crate) symbols_offset: U32<zerocopy::LittleEndian>,
    // number of imported symbol names
    pub(crate) imports_count: U32<zerocopy::LittleEndian>,
    // DYLD_CHAINED_IMPORT*
    pub(crate) imports_format: U32<zerocopy::LittleEndian>,
    // 0 => uncompressed, 1 => zlib compressed
    pub(crate) symbols_format: U32<zerocopy::LittleEndian>,
}

// This struct is embedded in LC_DYLD_CHAINED_FIXUPS payload
// struct dyld_chained_starts_in_image
// {
//     uint32_t    seg_count;
//     uint32_t    seg_info_offset[1];  // each entry is offset into this struct for that segment
//     // followed by pool of dyld_chain_starts_in_segment data
// };

// Code signature data structures are always stored big-endian, regardless of
// the target architecture's byte order.
//
// Data structures mirroring the following URL:
// https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h.

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub(crate) struct CodeSignatureSuperBlob {
    // magic number
    pub(crate) magic: U32<BigEndian>,
    // total length of SuperBlob
    pub(crate) length: U32<BigEndian>,
    // number of index entries following
    pub(crate) count: U32<BigEndian>,
    // (count) entries
    // CodeSignatureBlobIndex index[];
    // followed by Blobs in no particular order as indicated by offsets in index
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub(crate) struct CodeSignatureBlobIndex {
    // type of entry
    pub(crate) type_: U32<BigEndian>,
    // offset of entry
    pub(crate) offset: U32<BigEndian>,
    // an extra padding so that we have CodeSignatureSuperBlob + CodeSignatureBlobIndex aligned to
    // 8 bytes!
    pub(crate) padding: U32<BigEndian>,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub(crate) struct CodeSignatureCodeDirectory {
    // magic number (CSMAGIC_CODEDIRECTORY)
    pub(crate) magic: U32<BigEndian>,
    // total length of CodeDirectory blob
    pub(crate) length: U32<BigEndian>,
    // compatibility version
    pub(crate) version: U32<BigEndian>,
    // setup and mode flags
    pub(crate) flags: U32<BigEndian>,
    // offset of hash slot element at index zero
    pub(crate) hash_offset: U32<BigEndian>,
    // offset of identifier string
    pub(crate) ident_offset: U32<BigEndian>,
    // number of special hash slots
    pub(crate) n_special_slots: U32<BigEndian>,
    // number of ordinary (code) hash slots
    pub(crate) n_code_slots: U32<BigEndian>,
    // limit to main image signature range
    pub(crate) code_limit: U32<BigEndian>,
    // size of each hash in bytes
    pub(crate) hash_size: u8,
    // type of hash (cdHashType* constants)
    pub(crate) hash_type: u8,
    // platform identifier; zero if not platform binary
    pub(crate) platform: u8,
    // log2(page size in bytes); 0 => infinite
    pub(crate) page_size: u8,
    // unused (must be zero)
    pub(crate) spare2: U32<BigEndian>,

    // Version 0x20100
    //
    // offset of optional scatter vector
    pub(crate) scatter_offset: U32<BigEndian>,

    // Version 0x20200
    //
    // offset of optional team identifier
    pub(crate) team_offset: U32<BigEndian>,

    // Version 0x20300
    //
    // unused (must be zero)
    pub(crate) spare3: U32<BigEndian>,
    // limit to main image signature range, 64 bits
    pub(crate) code_limit64: U64<BigEndian>,

    // Version 0x20400
    //
    // offset of executable segment
    pub(crate) exec_seg_base: U64<BigEndian>,
    // limit of executable segment
    pub(crate) exec_seg_limit: U64<BigEndian>,
    // executable segment flags
    pub(crate) exec_seg_flags: U64<BigEndian>,
    // Version 0x20500 and 0x20600 are unused!
    // followed by dynamic content as located by offset fields above
}

pub(crate) const CS_SECTION_ALIGNMENT_EXP: u8 = 4;
pub(crate) const CS_SECTION_ALIGNMENT: u64 = 2u64.pow(CS_SECTION_ALIGNMENT_EXP as u32);
// TODO: properly implement
pub(crate) const CS_IDENTIFIER_STRING: &[u8] = b"a.out";

pub(crate) const CS_BLOB_HEADERS_SIZE: u64 =
    (size_of::<CodeSignatureSuperBlob>() + size_of::<CodeSignatureBlobIndex>()) as u64;
const _: () = assert!(CS_BLOB_HEADERS_SIZE.is_multiple_of(8));
pub(crate) const CS_HEADERS_SIZE: u64 =
    CS_BLOB_HEADERS_SIZE + size_of::<CodeSignatureCodeDirectory>() as u64;
pub(crate) const CS_PADDED_FILENAME_SIZE: u64 =
    (CS_IDENTIFIER_STRING.len() as u64 + 1).next_multiple_of(CS_SECTION_ALIGNMENT);
pub(crate) const CS_HEADERS_WITH_FILENAME_SIZE: u64 = CS_HEADERS_SIZE + CS_PADDED_FILENAME_SIZE;
pub(crate) const CS_BLOCK_SIZE_EXP: u8 = 12;
pub(crate) const CS_BLOCK_SIZE: usize = 2usize.pow(CS_BLOCK_SIZE_EXP as u32);
// SHA-256 is being used
pub(crate) const CS_HASH_SIZE: u8 = 32;

pub(crate) const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
pub(crate) const CSSLOT_CODEDIRECTORY: u32 = 0;
pub(crate) const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
pub(crate) const CS_SUPPORTSEXECSEG: u32 = 0x20400;
// Ad hoc signed
pub(crate) const CS_ADHOC: u32 = 0x00000002;
// Automatically signed by the linker
pub(crate) const CS_LINKER_SIGNED: u32 = 0x00020000;
pub(crate) const CS_HASHTYPE_SHA256: u8 = 2;
pub(crate) const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;

#[derive(derive_more::Debug)]
pub(crate) struct File<'data> {
    #[debug(skip)]
    pub(crate) data: &'data [u8],
    #[debug(skip)]
    pub(crate) sections: SectionTable<'data>,
    #[debug(skip)]
    pub(crate) symbols: SymbolTable<'data>,
    pub(crate) flags: u32,
}

impl<'data> platform::ObjectFile<'data> for File<'data> {
    type Platform = MachO;

    fn parse_bytes(input: &'data [u8], is_dynamic: bool) -> crate::error::Result<Self> {
        let header = macho::MachHeader64::<object::Endianness>::parse(input, 0)?;
        let mut commands = header.load_commands(LE, input, 0)?;

        let mut symbols = None;
        let mut sections = None;

        while let Some(command) = commands.next()? {
            if let Some(symtab_command) = command.symtab()? {
                ensure!(symbols.is_none(), "At most one symtab command expected");
                symbols = Some(symtab_command.symbols::<macho::MachHeader64<_>, _>(LE, input)?);
            } else if let Some((segment_command, segment_data)) = command.segment_64()? {
                ensure!(sections.is_none(), "At most one segment command expected");
                let section_list = segment_command.sections(LE, segment_data)?;
                sections = Some(section_list);
            }
        }

        Ok(File {
            data: input,
            symbols: symbols.ok_or("Missing symbol table")?,
            sections: sections.ok_or("Missing segment command")?,
            flags: header.flags(LE),
        })
    }

    fn parse(
        input: &crate::input_data::InputBytes<'data>,
        args: &<Self::Platform as platform::Platform>::Args,
    ) -> crate::error::Result<Self> {
        // TODO
        Self::parse_bytes(input.data, false)
    }

    fn is_dynamic(&self) -> bool {
        // TODO
        false
    }

    fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    fn symbols_iter(&self) -> impl Iterator<Item = &SymtabEntry> {
        self.symbols.iter()
    }

    fn symbol(
        &self,
        index: object::SymbolIndex,
    ) -> crate::error::Result<&<Self::Platform as platform::Platform>::SymtabEntry> {
        Ok(self.symbols.symbol(index)?)
    }

    fn section_size(
        &self,
        header: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<u64> {
        Ok(header.size.get(LE))
    }

    fn symbol_name(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
    ) -> crate::error::Result<&'data [u8]> {
        Ok(symbol.name(LE, self.symbols.strings())?)
    }

    fn symbol_offset_in_section(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        section_index: object::SectionIndex,
    ) -> crate::error::Result<u64> {
        let section = self.section(section_index)?;
        // On Mach-O the symbol value is the global offset, not a relative to the start of a
        // section.
        symbol
            .n_value
            .get(LE)
            .checked_sub(section.addr.get(LE))
            .ok_or_else(|| error!("Mach-O symbol value is before its section address"))
    }

    fn num_sections(&self) -> usize {
        self.sections.len()
    }

    fn section_iter<'a>(&'a self) -> <Self::Platform as platform::Platform>::SectionIterator<'a> {
        self.sections.iter()
    }

    fn enumerate_sections(
        &self,
    ) -> impl Iterator<
        Item = (
            object::SectionIndex,
            &<Self::Platform as platform::Platform>::SectionHeader,
        ),
    > {
        self.sections
            .iter()
            .enumerate()
            .map(|(i, section)| (object::SectionIndex(i), section))
    }

    fn section(
        &self,
        index: object::SectionIndex,
    ) -> crate::error::Result<&<Self::Platform as platform::Platform>::SectionHeader> {
        self.sections
            .get(index.0)
            .ok_or(error!("section index out of range"))
    }

    fn section_by_name(
        &self,
        name: &str,
    ) -> Option<(
        object::SectionIndex,
        &<Self::Platform as platform::Platform>::SectionHeader,
    )> {
        todo!()
    }

    fn symbol_section(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        _index: object::SymbolIndex,
    ) -> crate::error::Result<Option<object::SectionIndex>> {
        if symbol.n_type & N_TYPE == N_SECT && symbol.n_sect != 0 {
            // The index is one-based, NO_SECT == 0, marks a missing section for the symbol.
            Ok(Some(object::SectionIndex(usize::from(symbol.n_sect - 1))))
        } else {
            Ok(None)
        }
    }

    fn symbol_versions(&self) -> &[<Self::Platform as platform::Platform>::SymbolVersionIndex] {
        todo!()
    }

    fn dynamic_symbol_used(
        &self,
        symbol_index: object::SymbolIndex,
        state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
    ) -> crate::error::Result {
        todo!()
    }

    fn finalise_sizes_dynamic(
        &self,
        lib_name: &[u8],
        state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> crate::error::Result {
        todo!()
    }

    fn apply_non_addressable_indexes_dynamic(
        &self,
        indexes: &mut <Self::Platform as platform::Platform>::NonAddressableIndexes,
        counts: &mut <Self::Platform as platform::Platform>::NonAddressableCounts,
        state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
    ) -> crate::error::Result {
        todo!()
    }

    fn section_name(&self, index: object::SectionIndex) -> crate::error::Result<&'data [u8]> {
        let section = self
            .sections
            .get(index.0)
            .ok_or(error!("section index out of range"))?;
        Ok(section.name())
    }

    fn raw_section_data(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<&'data [u8]> {
        todo!()
    }

    fn section_data(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
        member: &bumpalo_herd::Member<'data>,
        loaded_metrics: &crate::resolution::LoadedMetrics,
    ) -> crate::error::Result<&'data [u8]> {
        todo!()
    }

    fn copy_section_data(&self, section: &SectionHeader, out: &mut [u8]) -> Result {
        let data = section
            .data(LE, self.data)
            .map_err(|_e| error!("cannot get section data"))?;
        copy_section_data(data, out);

        Ok(())
    }

    fn section_data_cow(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<std::borrow::Cow<'data, [u8]>> {
        todo!()
    }

    fn section_alignment(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<u64> {
        Ok(2u64.pow(section.align(LE)))
    }

    fn relocations(
        &self,
        index: object::SectionIndex,
        relocations: &<Self::Platform as platform::Platform>::RelocationSections,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RelocationList<'data>> {
        Ok(RelocationList {
            relocations: self
                .sections
                .get(index.0)
                .ok_or(error!("section index out of range"))?
                .relocations(LE, self.data)?,
        })
    }

    fn parse_relocations(
        &self,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RelocationSections> {
        Ok(())
    }

    fn symbol_version_debug(&self, symbol_index: object::SymbolIndex) -> Option<String> {
        todo!()
    }

    fn section_display_name(&self, index: object::SectionIndex) -> Cow<'data, str> {
        self.section_name(index).map_or_else(
            |_| format!("<index {}>", index.0).into(),
            String::from_utf8_lossy,
        )
    }

    fn dynamic_tag_values(
        &self,
    ) -> Option<<Self::Platform as platform::Platform>::DynamicTagValues<'data>> {
        None
    }

    fn get_version_names(
        &self,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::VersionNames<'data>> {
        todo!()
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        local_index: usize,
        version_names: &<Self::Platform as platform::Platform>::VersionNames<'data>,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RawSymbolName<'data>> {
        todo!()
    }

    fn should_enforce_undefined(
        &self,
        resources: &crate::layout::GraphResources<'data, '_, Self::Platform>,
    ) -> bool {
        todo!()
    }

    fn verneed_table(
        &self,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::VerneedTable<'data>> {
        Ok(VerneedTable { _phantom: &[] })
    }

    fn process_gnu_note_section(
        &self,
        state: &mut <Self::Platform as platform::Platform>::ObjectLayoutStateExt<'data>,
        section_index: object::SectionIndex,
    ) -> crate::error::Result {
        todo!()
    }

    fn dynamic_tags(
        &self,
    ) -> crate::error::Result<&'data [<Self::Platform as platform::Platform>::DynamicEntry]> {
        todo!()
    }
}

impl platform::SectionHeader for SectionHeader {
    fn is_alloc(&self) -> bool {
        todo!()
    }

    fn is_writable(&self) -> bool {
        todo!()
    }

    fn is_executable(&self) -> bool {
        self.sectname.starts_with(b"__text")
    }

    fn is_tls(&self) -> bool {
        todo!()
    }

    fn is_merge_section(&self) -> bool {
        // TODO
        false
    }

    fn is_strings(&self) -> bool {
        todo!()
    }

    fn should_retain(&self) -> bool {
        // TODO
        false
    }

    fn should_exclude(&self) -> bool {
        // TODO
        false
    }

    fn is_group(&self) -> bool {
        todo!()
    }

    fn is_note(&self) -> bool {
        false
    }

    fn is_prog_bits(&self) -> bool {
        todo!()
    }

    fn is_no_bits(&self) -> bool {
        todo!()
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionType {}

impl platform::SectionType for SectionType {
    fn is_rela(&self) -> bool {
        todo!()
    }

    fn is_rel(&self) -> bool {
        todo!()
    }

    fn is_symtab(&self) -> bool {
        todo!()
    }

    fn is_strtab(&self) -> bool {
        todo!()
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionFlags(u32);

impl SectionFlags {
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn from_u32(raw: u32) -> SectionFlags {
        SectionFlags(raw)
    }

    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl platform::SectionFlags for SectionFlags {
    fn is_alloc(self) -> bool {
        true
    }
}

// Documentation link for Nlist64 type: https://leopard-adc.pepas.com/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html
impl platform::Symbol for SymtabEntry {
    fn as_common(&self) -> Option<platform::CommonSymbol> {
        // TODO
        None
    }

    fn is_undefined(&self) -> bool {
        Nlist::is_undefined(self)
    }

    fn is_local(&self) -> bool {
        self.n_type & N_EXT == 0
    }

    fn is_absolute(&self) -> bool {
        self.n_type & N_TYPE == N_ABS
    }

    fn is_weak(&self) -> bool {
        self.n_desc.get(LE) & N_WEAK_DEF != 0
    }

    fn visibility(&self) -> crate::symbol_db::Visibility {
        if self.n_type & N_PEXT != 0 {
            Visibility::Hidden
        } else {
            Visibility::Default
        }
    }

    fn value(&self) -> u64 {
        self.n_value.get(LE)
    }

    fn size(&self) -> u64 {
        // TODO
        0
    }

    fn has_name(&self) -> bool {
        self.n_strx.get(LE) != 0
    }

    fn is_default_strippable(&self, name: &[u8]) -> bool {
        self.is_local() && name.starts_with(b"ltmp")
    }

    fn debug_string(&self) -> String {
        // TODO
        String::new()
    }

    fn is_tls(&self) -> bool {
        // TODO: derive from section name
        false
    }

    fn is_interposable(&self) -> bool {
        false
    }

    fn is_func(&self) -> bool {
        // TODO: derive from section name
        false
    }

    fn is_ifunc(&self) -> bool {
        false
    }

    fn is_hidden(&self) -> bool {
        self.visibility() == Visibility::Hidden
    }

    fn is_gnu_unique(&self) -> bool {
        false
    }

    fn with_hidden(mut self, hidden: bool) -> Self {
        if hidden {
            self.n_type |= N_PEXT;
        } else {
            self.n_type &= !N_PEXT;
        }
        self
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionAttributes {
    pub(crate) flags: SectionFlags,
}

impl platform::SectionAttributes for SectionAttributes {
    type Platform = MachO;

    fn merge(&mut self, rhs: Self) {
        self.flags = SectionFlags::from_u32(self.flags.raw() | rhs.flags.raw());
    }

    fn apply(
        &self,
        output_sections: &mut crate::output_section_id::OutputSections<Self::Platform>,
        section_id: crate::output_section_id::OutputSectionId,
    ) {
    }

    fn is_null(&self) -> bool {
        false
    }

    fn is_alloc(&self) -> bool {
        false
    }

    fn is_executable(&self) -> bool {
        false
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn is_writable(&self) -> bool {
        false
    }

    fn is_no_bits(&self) -> bool {
        false
    }

    fn flags(&self) -> <Self::Platform as platform::Platform>::SectionFlags {
        self.flags
    }

    fn ty(&self) -> <Self::Platform as platform::Platform>::SectionType {
        SectionType {}
    }

    fn set_to_default_type(&mut self) {}
}

pub(crate) struct NonAddressableIndexes {}

impl platform::NonAddressableIndexes for NonAddressableIndexes {
    fn new<P: platform::Platform>(symbol_db: &crate::symbol_db::SymbolDb<P>) -> Self {
        NonAddressableIndexes {}
    }
}

// TODO: update comment

#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub(crate) enum SegmentType {
    Text,
    LoadCommands,
    TextSections,
    DataSections,
    DataConstSections,
    LinkeditSections,
    // The other ELF-specific (or unused) parts/sections will be collected here.
    #[default]
    Unused,
}

impl platform::SegmentType for SegmentType {}

#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub(crate) struct ProgramSegmentDef {
    pub(crate) segment_type: SegmentType,
}

impl std::fmt::Display for ProgramSegmentDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.segment_type)
    }
}

impl platform::ProgramSegmentDef for ProgramSegmentDef {
    type Platform = MachO;

    fn is_writable(self) -> bool {
        false
    }

    fn is_executable(self) -> bool {
        false
    }

    fn always_keep(self) -> bool {
        matches!(
            self.segment_type,
            SegmentType::Text
                | SegmentType::LoadCommands
                | SegmentType::TextSections
                | SegmentType::LinkeditSections
        )
    }

    fn is_loadable(self) -> bool {
        true
    }

    fn is_stack(self) -> bool {
        false
    }

    fn is_tls(self) -> bool {
        false
    }

    fn order_key(self) -> usize {
        self.segment_type as usize
    }

    fn should_include_section(
        self,
        section_info: &crate::output_section_id::SectionOutputInfo<Self::Platform>,
        section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        let mapped_segment = match section_id {
            output_section_id::FILE_HEADER => SegmentType::Text,
            output_section_id::PAGEZERO_SEGMENT
            | output_section_id::TEXT_SEGMENT
            | output_section_id::DATA_SEGMENT
            | output_section_id::LINK_EDIT_SEGMENT
            | output_section_id::ENTRY_POINT
            | output_section_id::INTERP
            | output_section_id::DYLD_CHAINED_FIXUPS
            | output_section_id::SYMTAB_COMMAND
            | output_section_id::CODE_SIGNATURE_COMMAND => SegmentType::LoadCommands,
            output_section_id::TEXT | output_section_id::CSTRING => SegmentType::TextSections,
            output_section_id::DATA => SegmentType::DataSections,
            output_section_id::CHAINED_FIXUP_TABLE
            | output_section_id::SYMTAB_GLOBAL
            | output_section_id::STRTAB
            | output_section_id::CODE_SIGNATURE => SegmentType::LinkeditSections,
            _ => SegmentType::Unused,
        };

        match (self.segment_type, mapped_segment) {
            (SegmentType::Text, SegmentType::LoadCommands | SegmentType::TextSections) => true,
            _ => self.segment_type == mapped_segment,
        }
    }
}

pub(crate) struct BuiltInSectionDetails {
    pub(crate) kind: SectionKind<'static>,
    pub(crate) section_flags: SectionFlags,
    pub(crate) min_alignment: Alignment,
    pub(crate) target_segment_type: Option<SegmentType>,
}

impl platform::BuiltInSectionDetails for BuiltInSectionDetails {}

const DEFAULT_DEFS: BuiltInSectionDetails = BuiltInSectionDetails {
    kind: SectionKind::Primary(SectionName(&[])),
    section_flags: SectionFlags::empty(),
    min_alignment: alignment::MIN,
    target_segment_type: None,
};

#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct DynamicTagValues<'data> {
    phantom: &'data [u8],
}

#[derive(Debug)]
pub(crate) struct RelocationList<'data> {
    pub(crate) relocations: &'data [Relocation],
}

impl<'data> platform::RelocationList<'data> for RelocationList<'data> {
    fn num_relocations(&self) -> usize {
        self.relocations.len()
    }
}

impl<'data> platform::DynamicTagValues<'data> for DynamicTagValues<'data> {
    fn lib_name(&self, input: &crate::input_data::InputRef<'data>) -> &'data [u8] {
        todo!()
    }
}

#[derive(Debug)]
pub(crate) struct RawSymbolName<'data> {
    pub(crate) name: &'data [u8],
}

impl<'data> platform::RawSymbolName<'data> for RawSymbolName<'data> {
    fn parse(bytes: &'data [u8]) -> Self {
        Self { name: bytes }
    }

    fn name(&self) -> &'data [u8] {
        self.name
    }

    fn version_name(&self) -> Option<&'data [u8]> {
        None
    }

    fn is_default(&self) -> bool {
        // This port does not use symbol versioning, so every symbol is treated as
        // the default version.
        true
    }
}

impl std::fmt::Display for RawSymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

pub(crate) struct VerneedTable<'data> {
    // TODO
    _phantom: &'data [u8],
}

impl<'data> platform::VerneedTable<'data> for VerneedTable<'data> {
    fn version_name(&self, local_symbol_index: object::SymbolIndex) -> Option<&'data [u8]> {
        todo!()
    }
}

impl platform::Platform for MachO {
    type File<'data> = File<'data>;
    type SymtabEntry = SymtabEntry;
    type SectionHeader = SectionHeader;
    type SectionFlags = SectionFlags;
    type SectionAttributes = SectionAttributes;
    type SectionType = SectionType;
    type SegmentType = SegmentType;
    type ProgramSegmentDef = ProgramSegmentDef;
    type BuiltInSectionDetails = BuiltInSectionDetails;
    type RelocationSections = ();
    type DynamicEntry = ();
    type DynamicSymbolDefinitionExt = ();
    type RelocationInfo = object::macho::RelocationInfo;
    type NonAddressableIndexes = NonAddressableIndexes;
    type NonAddressableCounts = ();
    type EpilogueLayoutExt = ();
    type GroupLayoutExt = ();
    type CommonGroupStateExt = ();
    type ArchIdentifier = ();
    type Args = MachOArgs;
    type ResolutionExt = ();
    type SymtabShndxEntry = ();
    type SymbolVersionIndex = ();
    type LayoutExt = ();
    type SectionIterator<'a> = core::slice::Iter<'a, SectionHeader>;
    type DynamicTagValues<'data> = DynamicTagValues<'data>;
    type RelocationList<'data> = RelocationList<'data>;
    type DynamicLayoutStateExt<'data> = ();
    type DynamicLayoutExt<'data> = ();
    type LayoutResourcesExt<'data> = ();
    type PreludeLayoutStateExt = ();
    type PreludeLayoutExt = ();
    type ObjectLayoutStateExt<'data> = ();
    type RawSymbolName<'data> = RawSymbolName<'data>;
    type VersionNames<'data> = ();
    type VerneedTable<'data> = VerneedTable<'data>;

    fn link_for_arch<'data>(
        linker: &'data crate::Linker,
        args: &'data Self::Args,
    ) -> crate::error::Result<crate::LinkerOutput<'data>> {
        if !cfg!(feature = "macho") {
            crate::bail!(
                "Mach-O support is still experimental. Rebuild with `--features macho` to enable it."
            );
        }

        linker.link_for_arch::<MachO, crate::macho_aarch64::MachOAArch64>(args)
    }

    fn write_output_file<'data, A: platform::Arch<Platform = Self>>(
        output: &crate::file_writer::Output,
        layout: &crate::layout::Layout<'data, Self>,
    ) -> crate::error::Result {
        output.write(layout, macho_writer::write::<A>)
    }

    fn section_attributes(header: &Self::SectionHeader) -> Self::SectionAttributes {
        Self::SectionAttributes {
            ..Default::default()
        }
    }

    fn apply_force_keep_sections(
        keep_sections: &mut crate::output_section_map::OutputSectionMap<bool>,
        args: &Self::Args,
    ) {
    }

    fn is_zero_sized_section_content(
        section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        todo!()
    }

    fn built_in_section_details() -> &'static [Self::BuiltInSectionDetails] {
        &SECTION_DEFINITIONS
    }

    fn finalise_group_layout(
        memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> Self::GroupLayoutExt {
    }

    fn frame_data_base_address(
        memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> u64 {
        todo!()
    }

    fn activate_dynamic<'data>(
        state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
        todo!()
    }

    fn pre_finalise_sizes_prelude<'scope, 'data>(
        prelude: &mut crate::layout::PreludeLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        resources: &crate::layout::GraphResources<'data, 'scope, Self>,
    ) {
    }

    fn finalise_sizes_dynamic<'data>(
        object: &mut crate::layout::DynamicLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) -> crate::error::Result {
        todo!()
    }

    fn finalise_object_sizes<'data>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
    }

    fn finalise_object_layout<'data>(
        object: &crate::layout::ObjectLayoutState<'data, Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
    }

    fn finalise_layout_dynamic<'data>(
        state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
        resolutions_out: &mut crate::layout::ResolutionWriter<Self>,
    ) -> crate::error::Result<Self::DynamicLayoutExt<'data>> {
        todo!()
    }

    fn take_dynsym_index(
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        section_layouts: &crate::output_section_map::OutputSectionMap<
            crate::layout::OutputRecordLayout,
        >,
    ) -> crate::error::Result<u32> {
        todo!()
    }

    fn compute_object_addresses<'data>(
        object: &crate::layout::ObjectLayoutState<'data, Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
        todo!()
    }

    fn layout_resources_ext<'data>(
        groups: &[crate::grouping::Group<'data, Self>],
    ) -> Self::LayoutResourcesExt<'data> {
    }

    fn load_object_section_relocations<'data, 'scope, A: platform::Arch<Platform = Self>>(
        state: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        queue: &mut crate::layout::LocalWorkQueue,
        resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        section: crate::layout::Section,
        section_index: object::SectionIndex,
        scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        // TODO
        for rel in state.relocations(section_index)?.relocations {
            process_relocation::<A>(state, common, rel, section, resources, queue, false, scope)?;
        }
        Ok(())
    }

    fn create_dynamic_symbol_definition<'data>(
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> crate::error::Result<crate::layout::DynamicSymbolDefinition<'data, Self>> {
        todo!()
    }

    fn update_segment_keep_list(
        program_segments: &crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
        keep_segments: &mut [bool],
        args: &Self::Args,
    ) {
    }

    fn program_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        PROGRAM_SEGMENT_DEFS
    }

    fn unconditional_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }

    fn create_linker_defined_symbols(
        symbols: &mut crate::parsing::InternalSymbolsBuilder<Self>,
        output_kind: crate::output_kind::OutputKind,
        args: &Self::Args,
    ) {
    }

    fn built_in_section_infos<'data>()
    -> Vec<crate::output_section_id::SectionOutputInfo<'data, Self>> {
        SECTION_DEFINITIONS
            .iter()
            .map(|d| SectionOutputInfo {
                section_attributes: SectionAttributes {
                    flags: d.section_flags,
                },
                kind: d.kind,
                min_alignment: d.min_alignment,
                location: None,
                secondary_order: None,
            })
            .collect()
    }

    fn create_layout_properties<'data, 'states, 'files, A: platform::Arch<Platform = Self>>(
        args: &Self::Args,
        objects: impl Iterator<Item = &'files Self::File<'data>>,
        states: impl Iterator<Item = &'states Self::ObjectLayoutStateExt<'data>> + Clone,
    ) -> crate::error::Result<Self::LayoutExt>
    where
        'data: 'files,
        'data: 'states,
    {
        Ok(())
    }

    fn load_exception_frame_data<'data, 'scope, A: platform::Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        eh_frame_section_index: object::SectionIndex,
        resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        queue: &mut crate::layout::LocalWorkQueue,
        scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        todo!()
    }

    fn non_empty_section_loaded<'data, 'scope, A: platform::Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        queue: &mut crate::layout::LocalWorkQueue,
        unloaded: crate::resolution::UnloadedSection,
        resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn new_epilogue_layout(
        args: &Self::Args,
        output_kind: crate::output_kind::OutputKind,
        dynamic_symbol_definitions: &mut [crate::layout::DynamicSymbolDefinition<'_, Self>],
    ) -> Self::EpilogueLayoutExt {
    }

    fn apply_non_addressable_indexes_epilogue(
        counts: &mut Self::NonAddressableCounts,
        state: &mut Self::EpilogueLayoutExt,
    ) {
    }

    fn apply_non_addressable_indexes<'data, 'groups>(
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        counts: &Self::NonAddressableCounts,
        mem_sizes_iter: impl Iterator<
            Item = &'groups mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        >,
    ) {
    }

    fn finalise_sizes_epilogue<'data>(
        state: &mut Self::EpilogueLayoutExt,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        dynamic_symbol_definitions: &[crate::layout::DynamicSymbolDefinition<'data, Self>],
        properties: &Self::LayoutExt,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
    }

    fn finalise_sizes_all<'data>(
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
    }

    fn apply_late_size_adjustments_epilogue(
        state: &mut Self::EpilogueLayoutExt,
        current_sizes: &crate::output_section_part_map::OutputSectionPartMap<u64>,
        extra_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
        args: &Self::Args,
    ) -> crate::error::Result {
        Ok(())
    }

    fn finalise_layout_epilogue<'data>(
        epilogue_state: &mut Self::EpilogueLayoutExt,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        common_state: &Self::LayoutExt,
        dynsym_start_index: u32,
        dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
    ) -> crate::error::Result {
        Ok(())
    }

    fn is_symbol_non_interposable<'data>(
        object: &Self::File<'data>,
        args: &Self::Args,
        sym: &Self::SymtabEntry,
        output_kind: crate::output_kind::OutputKind,
        export_list: Option<&crate::export_list::ExportList>,
        lib_name: &[u8],
        archive_semantics: bool,
        is_undefined: bool,
    ) -> bool {
        // TODO
        true
    }

    fn allocate_header_sizes(
        prelude: &mut crate::layout::PreludeLayoutState<Self>,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        header_info: &crate::layout::HeaderInfo,
        output_sections: &crate::output_section_id::OutputSections<Self>,
    ) {
        sizes.increment(part_id::FILE_HEADER, size_of::<FileHeader>() as u64);
        sizes.increment(
            part_id::PAGEZERO_SEGMENT,
            size_of::<SegmentCommand>() as u64,
        );
        sizes.increment(
            part_id::TEXT_SEGMENT,
            (size_of::<SegmentCommand>()
                + size_of::<SectionEntry>()
                    * count_sections_for_segment_type(output_sections, SegmentType::TextSections))
                as u64,
        );
        if has_active_segment(header_info, SegmentType::DataSections) {
            sizes.increment(
                part_id::DATA_SEGMENT,
                (size_of::<SegmentCommand>()
                    + size_of::<SectionEntry>()
                        * count_sections_for_segment_type(
                            output_sections,
                            SegmentType::DataSections,
                        )) as u64,
            );
        }
        sizes.increment(
            part_id::LINK_EDIT_SEGMENT,
            size_of::<SegmentCommand>() as u64,
        );
        sizes.increment(part_id::ENTRY_POINT, size_of::<EntryPointCommand>() as u64);
        sizes.increment(
            part_id::INTERP,
            ((size_of::<DylinkerCommand>() + DYLINKER_PATH.len())
                .next_multiple_of(MACHO_COMMAND_ALIGNMENT)) as u64,
        );
        sizes.increment(
            part_id::DYLD_CHAINED_FIXUPS,
            size_of::<DyldChainedFixupsCommand>() as u64,
        );
        sizes.increment(part_id::SYMTAB_COMMAND, size_of::<SymtabCommand>() as u64);
        sizes.increment(
            part_id::CODE_SIGNATURE_COMMAND,
            size_of::<CodeSignatureCommand>() as u64,
        );
    }

    fn finalise_sizes_for_symbol<'data>(
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        symbol_id: crate::symbol_db::SymbolId,
        flags: crate::value_flags::ValueFlags,
    ) -> crate::error::Result {
        Ok(())
    }

    fn allocate_resolution(
        flags: crate::value_flags::ValueFlags,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        output_kind: crate::output_kind::OutputKind,
        _args: &Self::Args,
    ) {
    }

    fn allocate_object_symtab_space<'data>(
        state: &crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        per_symbol_flags: &crate::value_flags::AtomicPerSymbolFlags,
    ) -> Result {
        let mut num_globals = 0;
        let mut strings_size = 0;
        for ((sym_index, sym), flags) in state
            .object
            .enumerate_symbols()
            .zip(per_symbol_flags.range(state.symbol_id_range))
        {
            let symbol_id = state.symbol_id_range.input_to_id(sym_index);
            if let Some(info) = SymbolCopyInfo::new(
                state.object,
                sym_index,
                sym,
                symbol_id,
                symbol_db,
                flags.get(),
                &state.sections,
            ) {
                num_globals += 1;
                strings_size += info.name.len() + 1;
            }
        }
        let entry_size = size_of::<SymtabEntry>() as u64;
        common.allocate(part_id::SYMTAB_GLOBAL, num_globals * entry_size);
        common.allocate(part_id::STRTAB, strings_size as u64);

        Ok(())
    }

    fn allocate_internal_symbol(
        symbol_id: crate::symbol_db::SymbolId,
        def_info: &crate::parsing::InternalSymDefInfo<Self>,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) -> crate::error::Result {
        todo!()
    }

    fn allocate_prelude(
        common: &mut crate::layout::CommonGroupState<Self>,
        symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) {
        // Allocate one extra character as n_strx == 0 is treated as unnamed.
        common.allocate(part_id::STRTAB, 1);
        common.allocate(part_id::CHAINED_FIXUP_TABLE, CHAINED_FIXUP_TABLE_SIZE);
        common.allocate(part_id::CODE_SIGNATURE, CS_HEADERS_WITH_FILENAME_SIZE);
    }

    fn finalise_prelude_layout<'data>(
        prelude: &crate::layout::PreludeLayoutState<Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
    ) -> crate::error::Result<Self::PreludeLayoutExt> {
        Ok(())
    }

    fn create_resolution(
        flags: crate::value_flags::ValueFlags,
        raw_value: u64,
        dynamic_symbol_index: Option<std::num::NonZeroU32>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> crate::layout::Resolution<Self> {
        Resolution {
            raw_value,
            dynamic_symbol_index,
            format_specific: (),
            flags,
        }
    }

    fn raw_symbol_name<'data>(
        name_bytes: &'data [u8],
        _verneed_table: &Self::VerneedTable<'data>,
        _symbol_index: object::SymbolIndex,
    ) -> Self::RawSymbolName<'data> {
        RawSymbolName { name: name_bytes }
    }

    fn default_layout_rules(args: &Self::Args) -> Vec<crate::layout_rules::SectionRule<'static>> {
        DEFAULT_SECTION_RULES.to_vec()
    }

    fn build_output_order_and_program_segments<'data>(
        custom: &crate::output_section_id::CustomSectionIds,
        output_kind: OutputKind,
        output_sections: &crate::output_section_id::OutputSections<'data, Self>,
        secondary: &crate::output_section_map::OutputSectionMap<
            Vec<crate::output_section_id::OutputSectionId>,
        >,
    ) -> (
        crate::output_section_id::OutputOrder,
        crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
    ) {
        let mut builder = OutputOrderBuilder::<Self>::new(output_kind, output_sections, secondary);

        // File header and all load commands.
        builder.add_section(output_section_id::FILE_HEADER);
        builder.add_section(output_section_id::PAGEZERO_SEGMENT);
        builder.add_section(output_section_id::TEXT_SEGMENT);
        builder.add_section(output_section_id::DATA_SEGMENT);
        builder.add_section(output_section_id::LINK_EDIT_SEGMENT);
        builder.add_section(output_section_id::ENTRY_POINT);
        builder.add_section(output_section_id::INTERP); // DYLINKER
        builder.add_section(output_section_id::DYLD_CHAINED_FIXUPS);
        builder.add_section(output_section_id::SYMTAB_COMMAND);
        builder.add_section(output_section_id::CODE_SIGNATURE_COMMAND);
        // Content of the sections (e.g. __text, __data).
        builder.add_section(output_section_id::TEXT);
        builder.add_section(output_section_id::CSTRING);
        builder.add_section(output_section_id::DATA);
        // The rest (e.g. symbol table, string table).
        builder.add_section(output_section_id::CHAINED_FIXUP_TABLE);
        builder.add_section(output_section_id::SYMTAB_GLOBAL);
        builder.add_section(output_section_id::STRTAB);
        builder.add_section(output_section_id::CODE_SIGNATURE);

        builder.build()
    }

    fn start_memory_address(output_kind: OutputKind) -> u64 {
        MACHO_START_MEM_ADDRESS
    }

    fn align_load_segment_start(
        segment_def: ProgramSegmentDef,
        segment_alignment: Alignment,
        file_offset: &mut usize,
        mem_offset: &mut u64,
    ) {
        match segment_def.segment_type {
            SegmentType::Text
            | SegmentType::DataSections
            | SegmentType::DataConstSections
            | SegmentType::LinkeditSections => {
                *file_offset = segment_alignment.align_up(*file_offset as u64) as usize;
                *mem_offset = segment_alignment.align_up(*mem_offset);
            }
            _ => {}
        }
    }

    fn default_symtab_entry() -> Self::SymtabEntry {
        Self::SymtabEntry {
            n_strx: Default::default(),
            n_type: Default::default(),
            n_sect: Default::default(),
            n_desc: Default::default(),
            n_value: Default::default(),
        }
    }

    fn last_part_size_to_extend(
        record: &OutputRecordLayout,
        last_part_id: part_id::PartId,
    ) -> Result<usize> {
        ensure!(
            last_part_id == part_id::CODE_SIGNATURE,
            "code signature must be last part_id"
        );
        // The CODE_SIGNATURE size depends on the final file size, excluding the
        // signature itself. Compute it after layout because there is one SHA hash
        // per file block (4 KiB) covered by the signature.
        Ok(record.file_offset.div_ceil(CS_BLOCK_SIZE) * CS_HASH_SIZE as usize)
    }
}

const SECTION_DEFINITIONS: [BuiltInSectionDetails; NUM_BUILT_IN_SECTIONS] = {
    let mut defs: [BuiltInSectionDetails; NUM_BUILT_IN_SECTIONS] =
        [DEFAULT_DEFS; NUM_BUILT_IN_SECTIONS];

    defs[output_section_id::FILE_HEADER.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"FILE_HEADER")),
        target_segment_type: Some(SegmentType::Text),
        ..DEFAULT_DEFS
    };
    // Load commands
    defs[output_section_id::PAGEZERO_SEGMENT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(SEG_PAGEZERO.as_bytes())),
        target_segment_type: Some(SegmentType::LoadCommands),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::TEXT_SEGMENT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(SEG_TEXT.as_bytes())),
        target_segment_type: Some(SegmentType::LoadCommands),
        section_flags: SectionFlags::from_u32(macho::VM_PROT_READ | macho::VM_PROT_EXECUTE),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::DATA_SEGMENT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(SEG_DATA.as_bytes())),
        target_segment_type: Some(SegmentType::LoadCommands),
        section_flags: SectionFlags::from_u32(macho::VM_PROT_READ | macho::VM_PROT_WRITE),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::LINK_EDIT_SEGMENT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(SEG_LINKEDIT.as_bytes())),
        target_segment_type: Some(SegmentType::LoadCommands),
        section_flags: SectionFlags::from_u32(macho::VM_PROT_READ),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::ENTRY_POINT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"LC_MAIN")),
        target_segment_type: Some(SegmentType::LoadCommands),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::INTERP.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"LC_LOAD_DYLINKER")),
        target_segment_type: Some(SegmentType::LoadCommands),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::DYLD_CHAINED_FIXUPS.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"LC_DYLD_CHAINED_FIXUPS")),
        target_segment_type: Some(SegmentType::LoadCommands),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::SYMTAB_COMMAND.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"LC_SYMTAB")),
        target_segment_type: Some(SegmentType::LoadCommands),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::CODE_SIGNATURE_COMMAND.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"LC_CODE_SIGNATURE")),
        target_segment_type: Some(SegmentType::LoadCommands),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::CHAINED_FIXUP_TABLE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"DYLD_CHAINED_FIXUPS_TABLE")),
        target_segment_type: Some(SegmentType::LinkeditSections),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::SYMTAB_GLOBAL.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"SYMTAB")),
        target_segment_type: Some(SegmentType::LinkeditSections),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::STRTAB.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"STRTAB")),
        target_segment_type: Some(SegmentType::LinkeditSections),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::CODE_SIGNATURE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"CODE_SIGNATURE")),
        target_segment_type: Some(SegmentType::LinkeditSections),
        min_alignment: Alignment {
            exponent: CS_SECTION_ALIGNMENT_EXP,
        },
        ..DEFAULT_DEFS
    };
    // Multi-part generated sections
    // Start of regular sections
    defs[output_section_id::TEXT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__text")),
        section_flags: SectionFlags::from_u32(
            macho::S_REGULAR | macho::S_ATTR_PURE_INSTRUCTIONS | macho::S_ATTR_SOME_INSTRUCTIONS,
        ),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::CSTRING.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__cstring")),
        section_flags: SectionFlags::from_u32(macho::S_CSTRING_LITERALS),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::DATA.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__data")),
        section_flags: SectionFlags::from_u32(macho::S_REGULAR),
        ..DEFAULT_DEFS
    };

    defs
};

// TODO: sort properly
const DEFAULT_SECTION_RULES: &[SectionRule<'static>] = &[
    SectionRule::exact_section_keep(b"__text", crate::output_section_id::TEXT),
    SectionRule::exact_section_keep(b"__cstring", crate::output_section_id::CSTRING),
    SectionRule::exact_section_keep(b"__data", crate::output_section_id::DATA),
    // SectionRule::exact_section_keep(b"__compact_unwind", crate::output_section_id::EH_FRAME),
];

const PROGRAM_SEGMENT_DEFS: &[ProgramSegmentDef] = &[
    ProgramSegmentDef {
        segment_type: SegmentType::Text,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::LoadCommands,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::TextSections,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::DataSections,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::DataConstSections,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::LinkeditSections,
    },
];

fn has_active_segment(header_info: &crate::layout::HeaderInfo, segment_type: SegmentType) -> bool {
    header_info.active_segment_ids.iter().any(|id| {
        PROGRAM_SEGMENT_DEFS
            .get(id.as_usize())
            .is_some_and(|def| def.segment_type == segment_type)
    })
}

fn count_sections_for_segment_type(
    output_sections: &crate::output_section_id::OutputSections<MachO>,
    segment_type: SegmentType,
) -> usize {
    let segment_def = ProgramSegmentDef { segment_type };
    output_sections
        .ids_with_info()
        .filter(|(section_id, _)| {
            output_sections.should_include_in_segment(*section_id, segment_def)
        })
        .count()
}

pub(crate) struct SegmentSectionsInfo<'data> {
    pub(crate) segment_size: OutputRecordLayout,
    pub(crate) segment_sections:
        Vec<(OutputRecordLayout, Option<SectionName<'data>>, SectionFlags)>,
}

pub(crate) fn get_segment_sections<'data>(
    layout: &Layout<'data, MachO>,
    segment_type: SegmentType,
) -> Option<SegmentSectionsInfo<'data>> {
    let mut in_matching_segment = false;
    let mut sections = Vec::new();
    let mut segment_id = None;

    for event in &layout.output_order {
        match event {
            OrderEvent::SegmentStart(seg_id)
                if layout.program_segments.segment_def(seg_id).segment_type == segment_type =>
            {
                segment_id = Some(seg_id);
                in_matching_segment = true;
            }
            OrderEvent::SegmentEnd(seg_id)
                if layout.program_segments.segment_def(seg_id).segment_type == segment_type
                    && in_matching_segment =>
            {
                break;
            }
            OrderEvent::Section(section_id) if in_matching_segment => {
                let sizes = *layout.section_layouts.get(section_id);
                sections.push((
                    sizes,
                    layout.output_sections.name(section_id),
                    layout.output_sections.section_flags(section_id),
                ));
            }
            _ => {}
        }
    }

    let segment_id = segment_id.expect("must be visited in the output order");
    let segment_size = layout
        .segment_layouts
        .segments
        .iter()
        .find(|seg| seg.id == segment_id)
        .map(|seg| seg.sizes);

    segment_size.map(|segment_size| SegmentSectionsInfo {
        segment_sections: sections,
        segment_size,
    })
}

#[inline(always)]
fn process_relocation<'data, 'scope, A: platform::Arch<Platform = MachO>>(
    object: &layout::ObjectLayoutState<'data, MachO>,
    common: &layout::CommonGroupState<'data, MachO>,
    rel: &Relocation,
    section: layout::Section,
    resources: &'scope layout::GraphResources<'data, '_, MachO>,
    queue: &mut layout::LocalWorkQueue,
    is_debug_section: bool,
    scope: &rayon::Scope<'scope>,
) -> Result {
    let rel_info = rel.info(LE);
    // r_extern == true if the reference points to a symbol
    if rel_info.r_extern {
        let local_sym_index = SymbolIndex(rel_info.r_symbolnum as usize);
        let symbol_db = resources.symbol_db;
        let local_symbol_id = object.symbol_id_range.input_to_id(local_sym_index);
        let symbol_id = symbol_db.definition(local_symbol_id);
        let mut flags = resources.local_flags_for_symbol(symbol_id);
        flags.merge(resources.local_flags_for_symbol(local_symbol_id));
        let rel_offset = rel_info.r_address;

        let rel_info = A::relocation_from_raw(rel_info)?;
        let mut flags_to_add = layout::resolution_flags(rel_info.kind);

        let atomic_flags = &resources.per_symbol_flags.get_atomic(symbol_id);
        let previous_flags = atomic_flags.fetch_or(flags_to_add);

        if !previous_flags.has_resolution() {
            queue.send_symbol_request::<A>(symbol_id, resources, scope);
        }
    }

    Ok(())
}
