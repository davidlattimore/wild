use crate::FileSystem;
use crate::OutputKind;
use crate::alignment;
use crate::alignment::Alignment;
use crate::alignment::MACHO_PAGE_ALIGNMENT;
use crate::args::macho::MachOArgs;
use crate::ensure;
use crate::error;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::file_writer::copy_section_data;
use crate::grouping::SequencedInput;
use crate::input_data::FileId;
use crate::layout;
use crate::layout::HandlerData as _;
use crate::layout::Layout;
use crate::layout::OutputRecordLayout;
use crate::layout::Resolution;
use crate::layout::SectionGcUnit;
use crate::layout::StubLibraryLayoutState;
use crate::layout::SymbolCopyInfo;
use crate::layout::SymbolResolutions;
use crate::layout_rules::SectionKind;
use crate::layout_rules::SectionRule;
use crate::layout_rules::SectionRuleOutcome;
use crate::macho::output_section_id::CHAINED_FIXUP_TABLE;
use crate::macho::output_section_id::CODE_SIGNATURE;
use crate::macho::output_section_id::EXPORTS_TRIE;
use crate::macho::output_section_id::LOAD_COMMANDS;
use crate::macho::output_section_id::STRTAB;
use crate::macho::output_section_id::SYMTAB_GLOBAL;
use crate::macho_writer;
use crate::output_section_id::FILE_HEADER;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputOrderBuilder;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::SectionIdentity;
use crate::output_section_id::SectionName;
use crate::output_section_id::SectionOutputInfo;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::part_id::PartId;
use crate::platform;
use crate::platform::Args;
use crate::platform::ObjectFile;
use crate::platform::SectionAttributes as _;
use crate::program_segments::ProgramSegmentId;
use crate::program_segments::ProgramSegments;
use crate::resolution;
use crate::symbol_db::SymbolId;
use crate::symbol_db::Visibility;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use anyhow::Context;
use itertools::Itertools;
use object::Endianness;
use object::SymbolIndex;
use object::macho;
use object::macho::N_ABS;
use object::macho::N_EXT;
use object::macho::N_PEXT;
use object::macho::N_SECT;
use object::macho::N_WEAK_DEF;
use object::macho::S_ATTR_EXT_RELOC;
use object::macho::S_ATTR_LOC_RELOC;
use object::macho::S_ATTR_PURE_INSTRUCTIONS;
use object::macho::S_ATTR_SOME_INSTRUCTIONS;
use object::macho::S_GB_ZEROFILL;
use object::macho::S_THREAD_LOCAL_REGULAR;
use object::macho::S_THREAD_LOCAL_VARIABLES;
use object::macho::S_THREAD_LOCAL_ZEROFILL;
use object::macho::S_ZEROFILL;
use object::macho::SECTION_ATTRIBUTES;
use object::macho::SEG_LINKEDIT;
use object::macho::Section64;
pub use object::macho::SectionFlags;
use object::read::macho::MachHeader;
use object::read::macho::Nlist;
use object::read::macho::Section;
use object::read::macho::Segment;
use std::borrow::Cow;
use std::num::NonZeroU8;
use std::num::NonZeroU64;
use std::slice::Iter;

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct MachO;

pub(crate) fn link_for_arch<'data, F: FileSystem>(
    linker: &'data crate::Linker<F>,
    args: &'data MachOArgs,
) -> Result<crate::LinkerOutput<'data>> {
    if !(cfg!(feature = "macho") || args.common().experimental_platforms) {
        crate::bail!(
            "Mach-O support is still experimental. Rebuild with `--features macho` to enable it."
        );
    }

    linker.link_for_arch::<MachO, crate::macho_aarch64::MachOAArch64>(args)
}

#[repr(u32)]
#[derive(Clone, Copy)]
enum SinglePartSectionId {
    Strtab = crate::output_section_id::NUM_COMMON_SINGLE_PART_SECTIONS,
    Got,
    PltGot,
    SymtabGlobal,
    LinkEditSegment,
    LoadCommands,
    CodeSignature,
    ChainedFixupTable,
    ExportsTrie,
    InitOffsets,

    // Must be last.
    Count,
}

pub(crate) mod part_id {
    use super::SinglePartSectionId;
    use crate::part_id::PartId;

    pub(crate) const STRTAB: PartId = SinglePartSectionId::Strtab.part_id();
    pub(crate) const GOT: PartId = SinglePartSectionId::Got.part_id();
    pub(crate) const PLT_GOT: PartId = SinglePartSectionId::PltGot.part_id();
    pub(crate) const SYMTAB_GLOBAL: PartId = SinglePartSectionId::SymtabGlobal.part_id();
    pub(crate) const LOAD_COMMANDS: PartId = SinglePartSectionId::LoadCommands.part_id();
    pub(crate) const CODE_SIGNATURE: PartId = SinglePartSectionId::CodeSignature.part_id();
    pub(crate) const CHAINED_FIXUP_TABLE: PartId = SinglePartSectionId::ChainedFixupTable.part_id();
    pub(crate) const EXPORTS_TRIE: PartId = SinglePartSectionId::ExportsTrie.part_id();
    pub(crate) const INIT_OFFSETS: PartId = SinglePartSectionId::InitOffsets.part_id();
}

pub(crate) mod output_section_id {
    use super::SinglePartSectionId;
    use crate::output_section_id::OutputSectionId;

    pub(crate) const STRTAB: OutputSectionId = SinglePartSectionId::Strtab.output_section_id();
    pub(crate) const GOT: OutputSectionId = SinglePartSectionId::Got.output_section_id();
    pub(crate) const PLT_GOT: OutputSectionId = SinglePartSectionId::PltGot.output_section_id();
    pub(crate) const SYMTAB_GLOBAL: OutputSectionId =
        SinglePartSectionId::SymtabGlobal.output_section_id();
    pub(crate) const LINK_EDIT_SEGMENT: OutputSectionId =
        SinglePartSectionId::LinkEditSegment.output_section_id();
    pub(crate) const LOAD_COMMANDS: OutputSectionId =
        SinglePartSectionId::LoadCommands.output_section_id();
    pub(crate) const CODE_SIGNATURE: OutputSectionId =
        SinglePartSectionId::CodeSignature.output_section_id();
    pub(crate) const CHAINED_FIXUP_TABLE: OutputSectionId =
        SinglePartSectionId::ChainedFixupTable.output_section_id();
    pub(crate) const EXPORTS_TRIE: OutputSectionId =
        SinglePartSectionId::ExportsTrie.output_section_id();
    pub(crate) const INIT_OFFSETS: OutputSectionId =
        SinglePartSectionId::InitOffsets.output_section_id();
}

const LE: Endianness = Endianness::Little;

/// Mach-O uses a zero page for all 32bit addresses and thus we begin the memory
/// offsets right after that (1GiB).
pub(crate) const MACHO_START_MEM_ADDRESS: u64 = 0x1_0000_0000;

/// The command alignment is 8B for 64-bit platforms.
pub(crate) const MACHO_COMMAND_ALIGNMENT: usize = 8;

/// A path to the default dynamic linker.
pub(crate) const DYLINKER_PATH: &[u8] = b"/usr/lib/dyld";

// TODO: Getting the number of active segments in epilogue depends on determine_header_size
// which is called later for the prologue. We potentially over-allocate a couple of bytes.
pub(crate) const MAX_SEGMENT_COUNT: usize = 6;
pub(crate) const CHAINED_FIXUP_TABLE_BASE_SIZE: u64 = (size_of::<ChainedFixupsHeader>()
    + size_of::<u32>() * (MAX_SEGMENT_COUNT + /* leading segment count */ 1)
    + size_of::<ChainedStartsInSegment>())
    as u64;
pub(crate) const CHAINED_FIXUP_IMPORT_SIZE: u64 = size_of::<u32>() as u64;
pub(crate) const CHAINED_FIXUP_PAGE_START_SIZE: u64 = size_of::<u16>() as u64;
pub(crate) const GOT_ENTRY_SIZE: u64 = 8;
pub(crate) const PLT_ENTRY_SIZE: u64 = 12;
pub(crate) const INIT_OFFSET_ENTRY_SIZE: u64 = size_of::<u32>() as u64;

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
pub(crate) type DylibCommand = object::macho::DylibCommand<Endianness>;
pub(crate) type CodeSignatureCommand = object::macho::LinkeditDataCommand<Endianness>;
pub(crate) type DyldChainedFixupsCommand = object::macho::LinkeditDataCommand<Endianness>;
pub(crate) type ChainedFixupsHeader = object::macho::DyldChainedFixupsHeader<Endianness>;
pub(crate) type ChainedStartsInSegment = object::macho::DyldChainedStartsInSegment<Endianness>;
pub(crate) type SymtabCommand = object::macho::SymtabCommand<Endianness>;
pub(crate) type BuildVersionCommand = object::macho::BuildVersionCommand<Endianness>;
pub(crate) type UuidCommand = object::macho::UuidCommand<Endianness>;

pub(crate) const CS_SECTION_ALIGNMENT_EXP: u8 = 4;
pub(crate) const CS_SECTION_ALIGNMENT: u64 = 2u64.pow(CS_SECTION_ALIGNMENT_EXP as u32);

pub(crate) const CS_BLOB_HEADERS_SIZE: u64 =
    (size_of::<macho::CsSuperBlob>() + size_of::<macho::CsBlobIndex>()) as u64;
pub(crate) const CS_CODE_DIRECTORY_SIZE: u64 = (size_of::<macho::CsCodeDirectoryV0>()
    + size_of::<macho::CsCodeDirectoryV1>()
    + size_of::<macho::CsCodeDirectoryV2>()
    + size_of::<macho::CsCodeDirectoryV3>()
    + size_of::<macho::CsCodeDirectoryV4>()) as u64;
pub(crate) const CS_HEADERS_SIZE: u64 = CS_BLOB_HEADERS_SIZE + CS_CODE_DIRECTORY_SIZE;
pub(crate) const CS_BLOCK_SIZE_EXP: u8 = 12;
pub(crate) const CS_BLOCK_SIZE: usize = 2usize.pow(CS_BLOCK_SIZE_EXP as u32);
// SHA-256 is being used
pub(crate) const CS_HASH_SIZE: u8 = 32;

pub(crate) fn code_signature_identifier(args: &MachOArgs) -> &[u8] {
    args.output()
        .file_name()
        .expect("File name should be present at this point")
        .as_encoded_bytes()
}

pub(crate) fn code_signature_padded_identifier_size(args: &MachOArgs) -> u64 {
    (code_signature_identifier(args).len() as u64 + 1).next_multiple_of(CS_SECTION_ALIGNMENT)
}

pub(crate) fn load_dylib_command_size(path: &[u8]) -> usize {
    (size_of::<DylibCommand>() + path.len() + 1).next_multiple_of(MACHO_COMMAND_ALIGNMENT)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct SegmentName([u8; 16]);

impl SegmentName {
    pub(crate) const PAGEZERO: Self = Self::from_bytes(b"__PAGEZERO");
    pub(crate) const TEXT: Self = Self::from_bytes(b"__TEXT");
    pub(crate) const DATA: Self = Self::from_bytes(b"__DATA");
    pub(crate) const DATA_CONST: Self = Self::from_bytes(b"__DATA_CONST");
    pub(crate) const LINKEDIT: Self = Self::from_bytes(b"__LINKEDIT");
    pub(crate) const LLVM: Self = Self::from_bytes(b"__LLVM");

    pub(crate) const fn into_bytes(self) -> [u8; 16] {
        self.0
    }

    const fn from_bytes(name: &[u8]) -> Self {
        assert!(name.len() <= 16);
        let mut bytes = [0; 16];
        bytes.split_at_mut(name.len()).0.copy_from_slice(name);
        Self(bytes)
    }

    fn is_writable(self) -> bool {
        !matches!(self, Self::PAGEZERO | Self::TEXT | Self::LINKEDIT)
    }
}

impl std::fmt::Display for SegmentName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = String::from_utf8_lossy(&self.0);
        write!(f, "{}", name.trim_end_matches('\0'))
    }
}

#[derive(Debug, Default)]
pub(crate) struct LayoutExt {
    /// Imported STUB library symbols, sorted by GOT.
    pub(crate) imported_symbols: Vec<ImportedSymbolWithResolution>,
    /// Final addresses of initializer functions, in input relocation order.
    pub(crate) init_function_addresses: Vec<u64>,
}

#[derive(Debug, Default)]
pub(crate) struct FinaliseSizesExt {
    imported_libraries: Vec<FileId>,
    imported_symbols: Vec<SymbolId>,
    init_functions: Vec<SymbolId>,
}

#[derive(Debug, Default)]
pub(crate) struct ObjectLayoutStateExt {
    init_functions: Vec<SymbolId>,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct PreludeLayoutExt {
    pub(crate) imported_library_file_ids: Vec<FileId>,
    pub(crate) load_dylib_command_sizes: Vec<usize>,
    pub(crate) load_command_count: usize,
}

#[derive(derive_more::Debug, Clone, Copy)]
pub(crate) struct ImportedSymbolWithResolution {
    pub(crate) symbol_id: SymbolId,
    pub(crate) got_address: NonZeroU64,
    pub(crate) plt_address: Option<NonZeroU64>,
}

#[derive(derive_more::Debug)]
pub(crate) struct File<'data> {
    #[debug(skip)]
    pub(crate) data: &'data [u8],
    #[debug(skip)]
    pub(crate) symbols: SymbolTable<'data>,
    #[allow(unused)]
    pub(crate) flags: object::macho::FileFlags,
    kind: ObjectKind<'data>,
}

#[derive(Debug)]
enum ObjectKind<'data> {
    Regular(RegularObject<'data>),
    Dylib,
}

#[derive(derive_more::Debug)]
struct RegularObject<'data> {
    #[debug(skip)]
    pub(crate) sections: SectionTable<'data>,
}

impl<'data> platform::ObjectFile<'data> for File<'data> {
    type Platform = MachO;

    fn parse_bytes(input: &'data [u8], is_dynamic: bool) -> Result<Self> {
        let header = macho::MachHeader64::<object::Endianness>::parse(input, 0)?;
        let mut commands = header.load_commands(LE, input, 0)?;

        let mut symbols = None;
        let mut sections = None;

        while let Some(command) = commands.next()? {
            if let Some(symtab_command) = command.symtab()? {
                ensure!(symbols.is_none(), "At most one symtab command expected");
                symbols = Some(symtab_command.symbols::<macho::MachHeader64<_>, _>(LE, input)?);
            } else if !is_dynamic
                && let Some((segment_command, segment_data)) = command.segment_64()?
            {
                ensure!(sections.is_none(), "At most one segment command expected");
                let section_list = segment_command.sections(LE, segment_data)?;
                sections = Some(section_list);
            }
        }

        let kind = if is_dynamic {
            ObjectKind::Dylib
        } else {
            ObjectKind::Regular(RegularObject {
                sections: sections.ok_or("Missing segment command")?,
            })
        };

        Ok(File {
            data: input,
            symbols: symbols.ok_or("Missing symbol table")?,
            flags: header.flags(LE),
            kind,
        })
    }

    fn parse(input: &crate::input_data::InputBytes<'data>, _args: &MachOArgs) -> Result<Self> {
        // TODO
        Self::parse_bytes(input.data, input.kind == FileKind::MachODylib)
    }

    fn is_dynamic(&self) -> bool {
        matches!(self.kind, ObjectKind::Dylib)
    }

    fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    fn symbols_iter(&self) -> impl Iterator<Item = &SymtabEntry> {
        self.symbols.iter()
    }

    fn symbol(&self, index: object::SymbolIndex) -> Result<&SymtabEntry> {
        Ok(self.symbols.symbol(index)?)
    }

    fn section_size(&self, header: &SectionHeader) -> Result<u64> {
        Ok(header.size.get(LE))
    }

    fn symbol_name(&self, symbol: &SymtabEntry) -> Result<&'data [u8]> {
        Ok(symbol.name(LE, self.symbols.strings())?)
    }

    fn symbol_offset_in_section(
        &self,
        symbol: &SymtabEntry,
        section_index: object::SectionIndex,
    ) -> Result<u64> {
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
        self.sections().len()
    }

    fn section_iter<'a>(&'a self) -> Iter<'a, SectionHeader> {
        self.sections().iter()
    }

    fn enumerate_sections(&self) -> impl Iterator<Item = (object::SectionIndex, &SectionHeader)> {
        self.sections()
            .iter()
            .enumerate()
            .map(|(i, section)| (object::SectionIndex(i), section))
    }

    fn section(&self, index: object::SectionIndex) -> Result<&SectionHeader> {
        self.sections()
            .get(index.0)
            .ok_or(error!("section index out of range"))
    }

    fn section_by_name(&self, _name: &str) -> Option<(object::SectionIndex, &SectionHeader)> {
        todo!()
    }

    fn symbol_section(
        &self,
        symbol: &SymtabEntry,
        _index: object::SymbolIndex,
    ) -> Result<Option<object::SectionIndex>> {
        if symbol.n_type.typ() == N_SECT && symbol.n_sect != 0 {
            // The index is one-based, NO_SECT == 0, marks a missing section for the symbol.
            Ok(Some(object::SectionIndex(usize::from(symbol.n_sect - 1))))
        } else {
            Ok(None)
        }
    }

    fn symbol_versions(&self) -> &[()] {
        todo!()
    }

    fn dynamic_symbol_used(
        &self,
        symbol_index: object::SymbolIndex,
        file: &mut layout::DynamicLayoutState<'data, MachO>,
    ) -> Result {
        file.format_specific
            .imported_symbols
            .push(file.symbol_id_range.input_to_id(symbol_index));
        Ok(())
    }

    fn finalise_sizes_dynamic(
        &self,
        _lib_name: &[u8],
        _state: &mut DynamicLayoutStateExt,
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> Result {
        Ok(())
    }

    fn apply_non_addressable_indexes_dynamic(
        &self,
        _indexes: &mut NonAddressableIndexes,
        _counts: &mut (),
        _state: &mut DynamicLayoutStateExt,
    ) -> Result {
        Ok(())
    }

    fn section_name(&self, index: object::SectionIndex) -> Result<&'data [u8]> {
        let section = self
            .sections()
            .get(index.0)
            .ok_or(error!("section index out of range"))?;
        Ok(section.name())
    }

    fn raw_section_data(&self, _section: &SectionHeader) -> Result<&'data [u8]> {
        todo!()
    }

    fn section_data(
        &self,
        _section: &SectionHeader,
        _member: &bumpalo_herd::Member<'data>,
        _loaded_metrics: &crate::resolution::LoadedMetrics,
    ) -> Result<&'data [u8]> {
        todo!()
    }

    fn copy_section_data(&self, section: &SectionHeader, out: &mut [u8]) -> Result {
        let data = section
            .data(LE, self.data, section.offset(LE).into())
            .map_err(|_e| error!("cannot get section data"))?;
        copy_section_data(data, out);

        Ok(())
    }

    fn section_data_cow(&self, _section: &SectionHeader) -> Result<std::borrow::Cow<'data, [u8]>> {
        todo!()
    }

    fn section_alignment(&self, section: &SectionHeader) -> Result<u64> {
        Ok(2u64.pow(section.align(LE)))
    }

    fn relocations(
        &self,
        index: object::SectionIndex,
        _relocations: &(),
    ) -> Result<RelocationList<'data>> {
        Ok(RelocationList {
            relocations: self
                .sections()
                .get(index.0)
                .ok_or(error!("section index out of range"))?
                .relocations(LE, self.data)?,
        })
    }

    fn parse_relocations(&self) -> Result<()> {
        Ok(())
    }

    fn symbol_version_debug(&self, _symbol_index: object::SymbolIndex) -> Option<String> {
        None
    }

    fn section_display_name(&self, index: object::SectionIndex) -> Cow<'data, str> {
        self.section_name(index).map_or_else(
            |_| format!("<index {}>", index.0).into(),
            String::from_utf8_lossy,
        )
    }

    fn dynamic_tag_values(&self) -> Option<DynamicTagValues<'data>> {
        match self.kind {
            ObjectKind::Regular(_) => None,
            ObjectKind::Dylib => Some(DynamicTagValues::default()),
        }
    }

    fn get_version_names(&self) -> Result<()> {
        Ok(())
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &SymtabEntry,
        _local_index: usize,
        _version_names: &(),
    ) -> Result<RawSymbolName<'data>> {
        Ok(RawSymbolName {
            name: self.symbol_name(symbol)?,
        })
    }

    fn should_enforce_undefined(
        &self,
        _resources: &crate::layout::GraphResources<'data, '_, Self::Platform>,
    ) -> bool {
        todo!()
    }

    fn verneed_table(&self) -> Result<VerneedTable<'data>> {
        Ok(VerneedTable { _phantom: &[] })
    }

    fn process_gnu_note_section(
        &self,
        _state: &mut ObjectLayoutStateExt,
        _section_index: object::SectionIndex,
    ) -> Result {
        todo!()
    }

    fn dynamic_tags(&self) -> Result<&'data [()]> {
        todo!()
    }
}

impl platform::SectionHeader for SectionHeader {
    fn is_alloc(&self) -> bool {
        // TODO: Surely not everything is alloc. But this is for now consistent with
        // SectionFlags::is_alloc.
        true
    }

    fn is_writable(&self) -> bool {
        SegmentName::from_bytes(self.segment_name()).is_writable()
    }

    fn is_executable(&self) -> bool {
        self.flags
            .get(LE)
            .intersects(S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)
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
        // TODO: We need support for sections backed by the Mach-O indirect symbol table for dynamic
        // linking.
        self.flags.get(LE).intersects(macho::S_ATTR_DEBUG)
            || matches!(
                SegmentName::from_bytes(self.segment_name()),
                SegmentName::PAGEZERO | SegmentName::LINKEDIT | SegmentName::LLVM
            )
            || matches!(
                self.flags.get(LE).typ(),
                macho::S_NON_LAZY_SYMBOL_POINTERS
                    | macho::S_LAZY_SYMBOL_POINTERS
                    | macho::S_SYMBOL_STUBS
                    | macho::S_LAZY_DYLIB_SYMBOL_POINTERS
                    | macho::S_THREAD_LOCAL_VARIABLE_POINTERS
            )
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
        matches!(
            self.flags.get(LE).typ(),
            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        )
    }
}

impl platform::SectionType for macho::SectionType {
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
        !self.n_type.contains(N_EXT)
    }

    fn is_absolute(&self) -> bool {
        self.n_type.typ() == N_ABS
    }

    fn is_weak(&self) -> bool {
        self.n_desc.get(LE).contains(N_WEAK_DEF)
    }

    fn visibility(&self) -> crate::symbol_db::Visibility {
        if self.n_type.contains(N_PEXT) {
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
        self.visibility() == Visibility::Default
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
            self.n_type.insert(N_PEXT);
        } else {
            self.n_type.remove(N_PEXT);
        }
        self
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionAttributes {
    ty: macho::SectionType,
    attr: SectionFlags,
    writable: bool,
}

const SECTION_FLAGS_PROPAGATION_MASK: SectionFlags = S_ATTR_EXT_RELOC.with(S_ATTR_LOC_RELOC);

impl SectionAttributes {
    fn new(flags: SectionFlags, segment: Option<SegmentName>) -> Self {
        Self {
            ty: flags.typ(),
            attr: SectionFlags(flags.0 & SECTION_ATTRIBUTES),
            writable: segment.is_some_and(SegmentName::is_writable),
        }
    }
}

impl platform::SectionAttributes for SectionAttributes {
    type Platform = MachO;

    fn merge(&mut self, rhs: Self) {
        self.ty = self.ty.max(rhs.ty);
        self.attr |= rhs.attr;
        self.writable |= rhs.writable;
    }

    fn apply(
        &self,
        output_sections: &mut crate::output_section_id::OutputSections<Self::Platform>,
        section_id: crate::output_section_id::OutputSectionId,
    ) {
        let info = output_sections.section_infos.get_mut(section_id);
        // TODO: For now, we copy what ELF does to break ties in types. This acts as a workaround
        // since S_REGULAR = 0 and more specialized types should win this tiebreak.
        info.section_attributes.ty = info.section_attributes.ty.max(self.ty);
        info.section_attributes.attr |= self.attr.without(SECTION_FLAGS_PROPAGATION_MASK);
        info.section_attributes.writable |= self.writable;
    }

    fn is_null(&self) -> bool {
        false
    }

    fn is_alloc(&self) -> bool {
        true
    }

    fn is_executable(&self) -> bool {
        self.flags()
            .intersects(S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)
    }

    fn is_tls(&self) -> bool {
        matches!(self.ty, S_THREAD_LOCAL_REGULAR | S_THREAD_LOCAL_ZEROFILL)
    }

    fn occupies_only_tls_address_space(&self) -> bool {
        false
    }

    fn is_writable(&self) -> bool {
        self.writable
    }

    fn is_no_bits(&self) -> bool {
        matches!(
            self.ty,
            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        )
    }

    fn flags(&self) -> SectionFlags {
        self.attr.with_type(self.ty)
    }

    fn ty(&self) -> macho::SectionType {
        self.ty
    }

    fn set_to_default_type(&mut self) {}
}

pub(crate) struct NonAddressableIndexes {}

impl platform::NonAddressableIndexes for NonAddressableIndexes {
    fn new<P: platform::Platform>(_symbol_db: &crate::symbol_db::SymbolDb<P>) -> Self {
        NonAddressableIndexes {}
    }
}

impl platform::SegmentType for () {}

/// Represents an actual segment.
#[derive(Debug, Copy, Clone)]
pub(crate) struct ProgramSegmentDef {
    // TODO: When we implement -segprot, we should support both initprot and maxprot here.
    pub(crate) name: SegmentName,
    pub(crate) prot: macho::VmProt,
    pub(crate) flags: macho::SegmentFlags,
}

impl ProgramSegmentDef {
    fn new(name: SegmentName) -> Self {
        let (prot, flags) = match name {
            SegmentName::TEXT => (
                macho::VM_PROT_READ | macho::VM_PROT_EXECUTE,
                macho::SegmentFlags::default(),
            ),
            SegmentName::DATA_CONST => (
                macho::VM_PROT_READ | macho::VM_PROT_WRITE,
                macho::SG_READ_ONLY,
            ),
            SegmentName::LINKEDIT => (macho::VM_PROT_READ, macho::SegmentFlags::default()),
            _ => (
                macho::VM_PROT_READ | macho::VM_PROT_WRITE,
                macho::SegmentFlags::default(),
            ),
        };

        Self { name, prot, flags }
    }
}

impl std::fmt::Display for ProgramSegmentDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.name, f)
    }
}

impl platform::ProgramSegmentDef for ProgramSegmentDef {
    fn is_writable(self) -> bool {
        self.prot.contains(macho::VM_PROT_WRITE)
    }

    fn is_executable(self) -> bool {
        self.prot.contains(macho::VM_PROT_EXECUTE)
    }

    fn always_keep(self) -> bool {
        matches!(self.name, SegmentName::TEXT | SegmentName::LINKEDIT)
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
        match self.name {
            SegmentName::TEXT => 0,
            SegmentName::DATA_CONST => 1,
            SegmentName::DATA => 2,
            SegmentName::LINKEDIT => 4,
            _ => 3,
        }
    }
}

pub(crate) struct BuiltInSectionDetails {
    pub(crate) kind: SectionKind<'static, MachO>,
    pub(crate) section_flags: SectionFlags,
    pub(crate) min_alignment: Alignment,
}

impl platform::BuiltInSectionDetails for BuiltInSectionDetails {}

const DEFAULT_DEFS: BuiltInSectionDetails = BuiltInSectionDetails {
    kind: SectionKind::Primary(SectionIdentity::new(SectionName(&[]), None)),
    section_flags: SectionFlags(0),
    min_alignment: alignment::MIN,
};

#[allow(unused)]
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
    fn lib_name(&self, _input: &crate::input_data::InputRef<'data>) -> &'data [u8] {
        &[]
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
        std::fmt::Display::fmt(&String::from_utf8_lossy(self.name), f)
    }
}

pub(crate) struct VerneedTable<'data> {
    // TODO
    _phantom: &'data [u8],
}

impl<'data> platform::VerneedTable<'data> for VerneedTable<'data> {
    fn version_name(&self, _local_symbol_index: object::SymbolIndex) -> Option<&'data [u8]> {
        todo!()
    }
}

impl platform::Platform for MachO {
    const NUM_SINGLE_PART_SECTIONS: u32 = SinglePartSectionId::Count as u32;
    const NUM_BUILT_IN_REGULAR_SECTIONS: usize = 0;

    // The macOS kernel caches code signature state by vnode. Reusing a previously executed output's
    // inode after changing its contents can therefore cause the new executable to SIGKILL, even
    // though its new signature verifies successfully.
    const DEFAULT_FILE_REPLACEMENT_MODE: crate::FileReplacementMode = if cfg!(target_os = "macos") {
        crate::FileReplacementMode::UnlinkAndReplace
    } else {
        crate::FileReplacementMode::UpdateInPlaceWithFallback
    };

    const STRTAB_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::STRTAB);
    const SYMTAB_GLOBAL_SECTION_ID: Option<OutputSectionId> =
        Some(output_section_id::SYMTAB_GLOBAL);
    const GOT_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::GOT);
    const PLT_GOT_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::PLT_GOT);

    const VERIFY_IGNORE_ALIGNMENT_SECTION_IDS: &'static [OutputSectionId] =
        &[output_section_id::CODE_SIGNATURE, output_section_id::STRTAB];

    const VERIFY_IGNORE_SECTION_IDS: &'static [OutputSectionId] = &[
        crate::output_section_id::FILE_HEADER,
        output_section_id::LINK_EDIT_SEGMENT,
        output_section_id::LOAD_COMMANDS,
        output_section_id::CHAINED_FIXUP_TABLE,
        output_section_id::EXPORTS_TRIE,
        output_section_id::CODE_SIGNATURE,
    ];

    type File<'data> = File<'data>;
    type FileFlags = u32;
    type SymtabEntry = SymtabEntry;
    type PlatformSpecificSymbol = core::convert::Infallible;
    type SectionHeader = SectionHeader;
    type SectionFlags = SectionFlags;
    type SectionAttributes = SectionAttributes;
    type SectionType = macho::SectionType;
    type SegmentType = ();
    type ProgramSegmentDef = ProgramSegmentDef;
    type BuiltInSectionDetails = BuiltInSectionDetails;
    type RelocationSections = ();
    type DynamicEntry = ();
    type DynamicSymbolDefinitionExt = ();
    type RelocationInfo = object::macho::RelocationInfo;
    type NonAddressableIndexes = NonAddressableIndexes;
    type NonAddressableCounts = ();
    type EpilogueLayoutExt = EpilogueLayoutExt;
    type GroupLayoutExt = ();
    type CommonGroupStateExt = ();
    type StubLibraryLayoutStateExt = DynamicLayoutStateExt;
    type StubLibraryLayoutExt = DynamicLayoutExt;
    type ArchIdentifier = ();
    type Args = MachOArgs;
    type ResolutionExt = ResolutionExt;
    type SymtabShndxEntry = ();
    type SymbolVersionIndex = ();
    type FinaliseSizesExt<'data> = FinaliseSizesExt;
    type LayoutExt<'data> = LayoutExt;
    type GdbIndexScanResult<'data> = ();
    type SectionIterator<'a> = Iter<'a, SectionHeader>;
    type DynamicTagValues<'data> = DynamicTagValues<'data>;
    type RelocationList<'data> = RelocationList<'data>;
    type DynamicLayoutStateExt<'data> = DynamicLayoutStateExt;
    type DynamicLayoutExt<'data> = DynamicLayoutExt;
    type LayoutResourcesExt<'data> = ();
    type PreludeLayoutStateExt = PreludeLayoutExt;
    type PreludeLayoutExt = PreludeLayoutExt;
    type ObjectLayoutStateExt<'data> = ObjectLayoutStateExt;
    type RawSymbolName<'data> = RawSymbolName<'data>;
    type VersionNames<'data> = ();
    type VerneedTable<'data> = VerneedTable<'data>;
    type ResolvedObjectExt<'data> = ();
    type GcUnit = crate::layout::SectionGcUnit;

    /// Mach-O sections are associated with a SegmentName, while synthetic regions (FILE_HEADER,
    /// LOAD_COMMANDS, etc.) are not.
    type SectionIdentityExt = Option<SegmentName>;

    const HAS_NULL_SYMBOL_ENTRY: bool = true;

    fn write_output_file<'data, A: platform::Arch<Platform = Self>, F: FileSystem>(
        output: &crate::file_writer::Output<F>,
        layout: &crate::layout::Layout<'data, Self>,
    ) -> Result {
        output.write(layout, macho_writer::write::<A>)
    }

    fn section_attributes(header: &Self::SectionHeader) -> Self::SectionAttributes {
        SectionAttributes::new(
            header.flags.get(LE),
            Some(SegmentName::from_bytes(header.segment_name())),
        )
    }

    fn apply_force_keep_sections(
        _keep_sections: &mut crate::output_section_map::OutputSectionMap<bool>,
        _args: &Self::Args,
    ) {
    }

    fn is_zero_sized_section_content(
        _section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        todo!()
    }

    fn built_in_section_details() -> &'static [Self::BuiltInSectionDetails] {
        &SECTION_DEFINITIONS
    }

    fn finalise_group_layout(
        _memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> Self::GroupLayoutExt {
    }

    fn frame_data_base_address(
        _memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> u64 {
        todo!()
    }

    fn activate_dynamic<'data>(
        _state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
    }

    fn pre_finalise_sizes_prelude<'scope, 'data>(
        _prelude: &mut crate::layout::PreludeLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _resources: &crate::layout::GraphResources<'data, 'scope, Self>,
    ) {
    }

    fn finalise_sizes_dynamic<'data>(
        _object: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) -> Result {
        Ok(())
    }

    fn finalise_object_sizes<'data>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
    }

    fn finalise_object_layout<'data>(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
    }

    fn finalise_layout_dynamic<'data>(
        state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
        resolutions_out: &mut crate::layout::ResolutionWriter<Self>,
    ) -> Result<Option<Self::DynamicLayoutExt<'data>>> {
        layout::default_create_resolutions(
            memory_offsets,
            resolutions_out,
            resources,
            state.symbol_id_range,
        )?;

        create_dynamic_layout_ext(state.file_id(), resources)
    }

    fn finalise_layout_stub<'data>(
        state: layout::StubLibraryLayoutState<'data, Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
        resolutions_out: &mut crate::layout::ResolutionWriter<Self>,
    ) -> Result<Option<Self::StubLibraryLayoutExt>> {
        layout::default_create_resolutions(
            memory_offsets,
            resolutions_out,
            resources,
            state.symbol_id_range,
        )?;

        create_dynamic_layout_ext(state.file_id(), resources)
    }

    fn take_dynsym_index(
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _section_layouts: &crate::output_section_map::OutputSectionMap<
            crate::layout::OutputRecordLayout,
        >,
    ) -> Result<u32> {
        todo!()
    }

    fn compute_object_addresses<'data>(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
        todo!()
    }

    fn layout_resources_ext<'data>(
        _groups: &[crate::grouping::Group<'data, Self>],
    ) -> Self::LayoutResourcesExt<'data> {
    }

    fn gc_unit_for_symbol<'data>(
        object: &Self::File<'data>,
        symbol: &Self::SymtabEntry,
        symbol_index: object::SymbolIndex,
    ) -> Result<Option<Self::GcUnit>> {
        Ok(object
            .symbol_section(symbol, symbol_index)?
            .map(SectionGcUnit::new))
    }

    fn activate_object_gc<'data, 'scope, A: platform::Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        queue: &mut crate::layout::LocalWorkQueue<Self>,
        scope: &rayon::Scope<'scope>,
    ) -> Result {
        object.activate_section_gc::<A>(common, resources, queue, scope)
    }

    fn load_gc_unit<'data, 'scope, A: platform::Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        queue: &mut crate::layout::LocalWorkQueue<Self>,
        unit: Self::GcUnit,
        scope: &rayon::Scope<'scope>,
    ) -> Result {
        object.handle_section_load_request::<A>(
            common,
            resources,
            queue,
            unit.section_index(),
            scope,
        )
    }

    fn load_object_section_relocations<'data, 'scope, A: platform::Arch<Platform = Self>>(
        state: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        queue: &mut crate::layout::LocalWorkQueue<Self>,
        resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _section: crate::layout::Section,
        section_index: object::SectionIndex,
        scope: &rayon::Scope<'scope>,
    ) -> Result {
        // TODO
        for rel in state.relocations(section_index)?.relocations {
            process_relocation::<A>(state, rel, section_index, resources, queue, scope)?;
        }
        Ok(())
    }

    fn create_dynamic_symbol_definition<'data>(
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> Result<crate::layout::DynamicSymbolDefinition<'data, Self>> {
        Ok(crate::layout::DynamicSymbolDefinition {
            symbol_id,
            name: symbol_db.symbol_name(symbol_id)?.bytes(),
            format_specific: (),
        })
    }

    fn update_segment_keep_list(
        _program_segments: &crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
        _keep_segments: &mut [bool],
        _args: &Self::Args,
    ) {
    }

    fn program_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }

    fn unconditional_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }

    fn program_segment_should_include_section(
        segment_def: Self::ProgramSegmentDef,
        section_info: &crate::output_section_id::SectionOutputInfo<Self>,
        section_id: crate::output_section_id::OutputSectionId,
        _rosegment: bool,
    ) -> bool {
        match (section_id, section_info.kind) {
            (FILE_HEADER | LOAD_COMMANDS, _) => segment_def.name == SegmentName::TEXT,
            (STRTAB | CHAINED_FIXUP_TABLE | SYMTAB_GLOBAL | EXPORTS_TRIE | CODE_SIGNATURE, _) => {
                segment_def.name == SegmentName::LINKEDIT
            }
            (_, SectionKind::Primary(identity)) => {
                identity.format_specific() == Some(segment_def.name)
            }
            (_, SectionKind::Secondary(_)) => false,
        }
    }

    fn create_linker_defined_symbols(
        symbols: &mut crate::parsing::InternalSymbolsBuilder<Self>,
        _output_kind: crate::output_kind::OutputKind,
        _args: &Self::Args,
    ) {
        // Mach-O object symbol names include the C ABI's leading underscore.
        symbols
            .section_start(crate::output_section_id::FILE_HEADER, "___dso_handle")
            .hide();
    }

    fn built_in_section_infos<'data>()
    -> Vec<crate::output_section_id::SectionOutputInfo<'data, Self>> {
        SECTION_DEFINITIONS
            .iter()
            .map(|d| {
                let segment = match d.kind {
                    SectionKind::Primary(identity) => identity.format_specific(),
                    SectionKind::Secondary(_) => None,
                };
                SectionOutputInfo {
                    section_attributes: SectionAttributes::new(d.section_flags, segment),
                    kind: d.kind,
                    min_alignment: d.min_alignment,
                    location_info: None,
                    secondary_order: None,
                    region_name: None,
                    fill: None,
                    phdrs: Vec::new(),
                }
            })
            .collect()
    }

    fn create_finalise_sizes_ext<'data, 'states, 'files, A: platform::Arch<Platform = Self>>(
        _args: &Self::Args,
        groups: &'files mut [layout::GroupState<'data, Self>],
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) -> Result<Self::FinaliseSizesExt<'data>>
    where
        'data: 'files,
        'data: 'states,
    {
        let mut imported_libraries = Vec::new();
        let mut imported_symbols = Vec::new();
        let mut init_functions = Vec::new();

        for group in groups {
            for file in &group.files {
                match file {
                    layout::FileLayoutState::Object(state) => {
                        init_functions.extend(
                            state
                                .format_specific
                                .init_functions
                                .iter()
                                .map(|local_symbol_id| symbol_db.definition(*local_symbol_id)),
                        );
                    }
                    layout::FileLayoutState::StubLibrary(state) => {
                        if state.format_specific.loaded {
                            imported_libraries.push(state.file_id());
                        }
                        imported_symbols
                            .extend_from_slice(state.format_specific.imported_symbols.as_slice());
                    }
                    layout::FileLayoutState::Dynamic(state) => {
                        if state.format_specific.loaded {
                            imported_libraries.push(state.file_id());
                        }
                        imported_symbols
                            .extend_from_slice(state.format_specific.imported_symbols.as_slice());
                    }
                    _ => {}
                }
            }
        }

        Ok(FinaliseSizesExt {
            imported_libraries,
            imported_symbols,
            init_functions,
        })
    }

    fn create_layout_ext<'data>(
        finalise_sizes_ext: Self::FinaliseSizesExt<'data>,
        resolutions: &SymbolResolutions<Self>,
    ) -> Result<Self::LayoutExt<'data>> {
        let mut layout_ext = LayoutExt::default();

        let imported_symbols = finalise_sizes_ext
            .imported_symbols
            .iter()
            .map(|&symbol_id| {
                let resolution = resolutions
                    .get(symbol_id)
                    .with_context(|| "missing resolution for a stub library symbol".to_string())?;

                let got_address = resolution
                    .format_specific
                    .got_address
                    .ok_or_else(|| error!("missing GOT entry for a stub library symbol"))?;

                Ok(ImportedSymbolWithResolution {
                    symbol_id,
                    got_address,
                    plt_address: resolution.format_specific.plt_address,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        layout_ext.imported_symbols = imported_symbols
            .into_iter()
            .sorted_by_key(|symbol| symbol.got_address)
            .collect();
        layout_ext.init_function_addresses = finalise_sizes_ext
            .init_functions
            .iter()
            .map(|&symbol_id| {
                resolutions
                    .get(symbol_id)
                    .map(|resolution| resolution.raw_value)
                    .ok_or_else(|| {
                        error!("missing resolution for Mach-O initializer {symbol_id:?}")
                    })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(layout_ext)
    }

    fn load_exception_frame_data<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _eh_frame_section_index: object::SectionIndex,
        _resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _queue: &mut crate::layout::LocalWorkQueue<Self>,
        _scope: &rayon::Scope<'scope>,
    ) -> Result {
        todo!()
    }

    fn process_init_func_section<'data, 'scope, A: platform::Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        section_index: object::SectionIndex,
        resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        queue: &mut crate::layout::LocalWorkQueue<Self>,
        scope: &rayon::Scope<'scope>,
    ) -> Result {
        let header = object.object.section(section_index)?;
        ensure!(
            header.flags.get(LE).typ() == macho::S_MOD_INIT_FUNC_POINTERS,
            "Mach-O __mod_init_func section has an unexpected section type"
        );

        for rel in object
            .relocations(section_index)?
            .relocations
            .iter()
            .sorted_unstable_by_key(|rel| rel.info(LE).r_address)
        {
            let info = rel.info(LE);
            ensure!(
                info.r_extern
                    && !info.r_pcrel
                    && info.r_length == 3
                    && info.r_type == macho::ARM64_RELOC_UNSIGNED,
                "unsupported Mach-O initializer relocation"
            );
            object.format_specific.init_functions.push(
                object
                    .symbol_id_range
                    .input_to_id(SymbolIndex(info.r_symbolnum as usize)),
            );
            process_relocation::<A>(object, rel, section_index, resources, queue, scope)?;
        }

        Ok(())
    }

    fn non_empty_section_loaded<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue<Self>,
        _unloaded: crate::resolution::UnloadedSection,
        _resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        _scope: &rayon::Scope<'scope>,
    ) -> Result {
        Ok(())
    }

    fn new_epilogue_layout<'data>(
        _args: &Self::Args,
        _output_kind: crate::output_kind::OutputKind,
        _dynamic_symbol_definitions: &mut [crate::layout::DynamicSymbolDefinition<'data, Self>],
        group_states: &[layout::GroupState<'data, Self>],
    ) -> Self::EpilogueLayoutExt {
        verbose_timing_phase!("Gather imported symbol IDs");

        let imported_symbols = group_states
            .iter()
            .flat_map(|group| {
                group.files.iter().flat_map(|file| match file {
                    layout::FileLayoutState::StubLibrary(file) => {
                        file.format_specific.imported_symbols.as_slice()
                    }
                    layout::FileLayoutState::Dynamic(file) => {
                        file.format_specific.imported_symbols.as_slice()
                    }
                    _ => &[],
                })
            })
            .copied()
            .collect();

        EpilogueLayoutExt { imported_symbols }
    }

    fn apply_non_addressable_indexes_epilogue(
        _counts: &mut Self::NonAddressableCounts,
        _state: &mut Self::EpilogueLayoutExt,
    ) {
    }

    fn apply_non_addressable_indexes<'data, 'groups>(
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _counts: &Self::NonAddressableCounts,
        _mem_sizes_iter: impl Iterator<
            Item = &'groups mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        >,
    ) {
    }

    fn finalise_sizes_epilogue<'data>(
        state: &mut Self::EpilogueLayoutExt,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        dynamic_symbol_definitions: &[crate::layout::DynamicSymbolDefinition<'data, Self>],
        format_specific: &Self::FinaliseSizesExt<'data>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
        let mut fixup_table_size = CHAINED_FIXUP_TABLE_BASE_SIZE;

        fixup_table_size += state
            .imported_symbols
            .iter()
            .map(|&s| {
                CHAINED_FIXUP_IMPORT_SIZE
                    + symbol_db.symbol_name(s).unwrap().bytes().len() as u64
                    + 1
            })
            .sum::<u64>();

        // Chained fixups record start information per page. At this point the final GOT size is
        // known, so reserve the fixup table entries needed to describe the GOT pages.
        fixup_table_size += CHAINED_FIXUP_PAGE_START_SIZE
            * (state.imported_symbols.len() as u64).div_ceil(MACHO_PAGE_ALIGNMENT.value());

        mem_sizes.increment(
            part_id::CHAINED_FIXUP_TABLE,
            alignment::USIZE.align_up(fixup_table_size),
        );

        // Currently we determine the output file size before we assign symbol addresses. This lets
        // us do file creation in parallel with address assignment, however it means that we can't
        // take addresses into account when determining section sizes. The export trie, due to using
        // uleb128 encoding for addresses, needs addresses in order to determine an exact size. We
        // work around this for now by assuming all addresses will be u64::MAX. This gives us an
        // upper bound on how large the trie will be, but wastes some space in the file. TODO:
        // Figure out a good way to fix this.
        let mut exports = dynamic_symbol_definitions
            .iter()
            .map(|symbol| crate::trie::Symbol {
                name: symbol.name,
                address: u64::MAX,
                flags: object::macho::ExportSymbolFlags(0),
            })
            .collect_vec();

        mem_sizes.increment(
            part_id::EXPORTS_TRIE,
            crate::trie::build(&mut exports).len() as u64,
        );

        mem_sizes.increment(
            part_id::INIT_OFFSETS,
            format_specific.init_functions.len() as u64 * INIT_OFFSET_ENTRY_SIZE,
        );
    }

    fn finalise_sizes_all<'data>(
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
    }

    fn finalise_layout_epilogue<'data>(
        _epilogue_state: &mut Self::EpilogueLayoutExt,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        format_specific: &Self::FinaliseSizesExt<'data>,
        _dynsym_start_index: u32,
        _dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
    ) -> Result {
        memory_offsets.increment(
            part_id::INIT_OFFSETS,
            format_specific.init_functions.len() as u64 * INIT_OFFSET_ENTRY_SIZE,
        );
        Ok(())
    }

    fn is_symbol_non_interposable<'data>(
        _object: &Self::File<'data>,
        _args: &Self::Args,
        _sym: &Self::SymtabEntry,
        _output_kind: crate::output_kind::OutputKind,
        _export_list: Option<&crate::export_list::ExportList>,
        _lib_name: &[u8],
        _archive_semantics: bool,
        _is_undefined: bool,
    ) -> bool {
        // TODO
        true
    }

    fn allocate_header_sizes<'data>(
        prelude: &mut crate::layout::PreludeLayoutState<'data, Self>,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        header_info: &crate::layout::HeaderInfo,
        program_segments: &ProgramSegments<Self::ProgramSegmentDef>,
        output_sections: &crate::output_section_id::OutputSections<Self>,
        resources: &layout::FinaliseSizesResources<'data, '_, Self>,
        args: &Self::Args,
    ) {
        sizes.increment(crate::part_id::FILE_HEADER, size_of::<FileHeader>() as u64);

        let mut allocate_load_cmd = |command_size| {
            sizes.increment(part_id::LOAD_COMMANDS, command_size as u64);
            prelude.format_specific.load_command_count += 1;
        };

        // Separately emitted __PAGEZERO.
        allocate_load_cmd(size_of::<SegmentCommand>());

        for &segment_id in &header_info.active_segment_ids {
            let segment = program_segments.segment_def(segment_id);
            allocate_load_cmd(
                size_of::<SegmentCommand>()
                    + size_of::<SectionEntry>()
                        * count_sections_for_segment(output_sections, *segment),
            );
        }

        if resources.symbol_db.output_kind.is_executable() {
            allocate_load_cmd(size_of::<EntryPointCommand>());
        }
        allocate_load_cmd(
            (size_of::<DylinkerCommand>() + DYLINKER_PATH.len())
                .next_multiple_of(MACHO_COMMAND_ALIGNMENT),
        );

        prelude.format_specific.imported_library_file_ids =
            resources.format_specific.imported_libraries.clone();

        prelude.format_specific.load_dylib_command_sizes = prelude
            .format_specific
            .imported_library_file_ids
            .iter()
            .map(|&file_id| load_dylib_command_size(install_name(file_id, resources.symbol_db)))
            .collect();
        let load_dylib_command_sizes = prelude.format_specific.load_dylib_command_sizes.clone();
        for command_size in load_dylib_command_sizes {
            allocate_load_cmd(command_size);
        }

        allocate_load_cmd(size_of::<DyldChainedFixupsCommand>());
        if resources.symbol_db.output_kind.needs_dynsym() {
            allocate_load_cmd(size_of::<object::macho::LinkeditDataCommand<Endianness>>());
        }
        allocate_load_cmd(size_of::<SymtabCommand>());
        allocate_load_cmd(size_of::<CodeSignatureCommand>());
        allocate_load_cmd(size_of::<UuidCommand>());
        if args.platform_version.is_some() {
            allocate_load_cmd(size_of::<BuildVersionCommand>());
        }
    }

    fn new_stub_library_layout_state_ext<'data>(
        _stub: &resolution::ResolvedStubLibrary<'data>,
        args: &Self::Args,
    ) -> Self::StubLibraryLayoutStateExt {
        DynamicLayoutStateExt::new(args)
    }

    fn new_dynamic_layout_state_ext<'data>(
        _file: &resolution::ResolvedDynamic<'data, Self>,
        args: &Self::Args,
    ) -> Self::DynamicLayoutStateExt<'data> {
        DynamicLayoutStateExt::new(args)
    }

    fn load_stub_library_symbol<'data>(
        state: &mut StubLibraryLayoutState<Self>,
        symbol_id: SymbolId,
    ) -> Result {
        state.format_specific.loaded = true;
        state.format_specific.imported_symbols.push(symbol_id);

        Ok(())
    }

    fn finalise_sizes_for_symbol<'data>(
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _symbol_id: crate::symbol_db::SymbolId,
        _flags: crate::value_flags::ValueFlags,
    ) -> Result {
        Ok(())
    }

    fn allocate_resolution(
        flags: crate::value_flags::ValueFlags,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _output_kind: crate::output_kind::OutputKind,
        _args: &Self::Args,
    ) {
        if flags.is_dynamic() && flags.needs_plt() {
            mem_sizes.increment(part_id::PLT_GOT, PLT_ENTRY_SIZE);
        }
        if flags.is_dynamic() && flags.needs_got() {
            mem_sizes.increment(part_id::GOT, GOT_ENTRY_SIZE);
        }
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
        _symbol_id: crate::symbol_db::SymbolId,
        _def_info: &crate::parsing::InternalSymDefInfo<Self>,
        _sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) -> Result {
        todo!()
    }

    fn allocate_prelude(
        common: &mut crate::layout::CommonGroupState<Self>,
        symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) {
        // Allocate one extra character as n_strx == 0 is treated as unnamed.
        common.allocate(part_id::STRTAB, 1);
        common.allocate(
            part_id::CODE_SIGNATURE,
            CS_HEADERS_SIZE + code_signature_padded_identifier_size(symbol_db.args),
        );
    }

    fn finalise_prelude_layout<'data>(
        prelude: &crate::layout::PreludeLayoutState<Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
    ) -> Result<Self::PreludeLayoutExt> {
        Ok(prelude.format_specific.clone())
    }

    fn create_resolution(
        flags: crate::value_flags::ValueFlags,
        raw_value: u64,
        dynamic_symbol_index: Option<std::num::NonZeroU32>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _args: &<Self as crate::platform::Platform>::Args,
        _output_kind: crate::OutputKind,
    ) -> crate::layout::Resolution<Self> {
        let mut resolution: Resolution<MachO> = Resolution {
            raw_value,
            dynamic_symbol_index,
            format_specific: ResolutionExt {
                got_address: None,
                plt_address: None,
            },
            flags,
        };

        if flags.needs_plt() {
            let plt_address = allocate_plt(memory_offsets);
            resolution.raw_value = plt_address.get();
            resolution.format_specific.plt_address = Some(plt_address);
            resolution.format_specific.got_address = Some(allocate_got(memory_offsets));
        } else if flags.needs_got() {
            let got_address = allocate_got(memory_offsets);
            resolution.raw_value = got_address.get();
            resolution.format_specific.got_address = Some(got_address);
        }

        resolution
    }

    fn raw_symbol_name<'data>(
        name_bytes: &'data [u8],
        _verneed_table: &Self::VerneedTable<'data>,
        _symbol_index: object::SymbolIndex,
    ) -> Self::RawSymbolName<'data> {
        RawSymbolName { name: name_bytes }
    }

    fn default_layout_rules(_args: &Self::Args) -> Vec<crate::layout_rules::SectionRule<'static>> {
        DEFAULT_SECTION_RULES.to_vec()
    }

    fn build_output_order_and_program_segments<'data>(
        custom: &crate::output_section_id::CustomSectionIds,
        output_kind: OutputKind,
        output_sections: &crate::output_section_id::OutputSections<'data, Self>,
        secondary: &crate::output_section_map::OutputSectionMap<
            Vec<crate::output_section_id::OutputSectionId>,
        >,
        _location_counters: &[crate::layout_rules::LocationCounter<'data>],
    ) -> (
        crate::output_section_id::OutputOrder<'data>,
        crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
    ) {
        // TODO: Order sections within each segment according to Mach-O conventions.
        let arbitrary_segments: Vec<SegmentName> = output_sections
            .ids_with_info()
            .filter_map(|(_, info)| match info.kind {
                SectionKind::Primary(identity) => identity.format_specific(),
                SectionKind::Secondary(_) => None,
            })
            .filter(|name| {
                !matches!(
                    *name,
                    SegmentName::PAGEZERO
                        | SegmentName::TEXT
                        | SegmentName::DATA_CONST
                        | SegmentName::DATA
                        | SegmentName::LINKEDIT
                )
            })
            .unique()
            .collect();

        let segment_defs = [
            SegmentName::TEXT,
            SegmentName::DATA_CONST,
            SegmentName::DATA,
        ]
        .into_iter()
        .chain(arbitrary_segments.iter().copied())
        .chain([SegmentName::LINKEDIT])
        .map(ProgramSegmentDef::new)
        .collect();

        let mut builder = OutputOrderBuilder::<Self>::new(
            segment_defs,
            output_kind,
            output_sections,
            secondary,
            false,
            &[],
        );

        // File header and all load commands.
        builder.add_section(crate::output_section_id::FILE_HEADER);
        builder.add_section(output_section_id::LOAD_COMMANDS);

        // Content of the sections (e.g. __text, __data).
        add_sections_in_segment(
            &mut builder,
            output_sections,
            &custom.exec,
            SegmentName::TEXT,
        );
        builder.add_section(output_section_id::INIT_OFFSETS);

        builder.add_section(output_section_id::PLT_GOT);
        add_sections_in_segment(&mut builder, output_sections, &custom.ro, SegmentName::TEXT);
        builder.add_section(output_section_id::GOT);

        for segment in [SegmentName::DATA_CONST, SegmentName::DATA] {
            add_sections_in_segment(&mut builder, output_sections, &custom.exec, segment);
            add_sections_in_segment(&mut builder, output_sections, &custom.ro, segment);
            add_sections_in_segment(&mut builder, output_sections, &custom.data, segment);
            if segment == SegmentName::DATA {
                add_sections_in_segment(&mut builder, output_sections, &custom.tdata, segment);
                add_sections_in_segment(&mut builder, output_sections, &custom.tbss, segment);
            }
            add_sections_in_segment(&mut builder, output_sections, &custom.bss, segment);
        }

        // Arbitrary segment sections are added in first-seen order.
        for segment in arbitrary_segments {
            for (section_id, info) in output_sections.ids_with_info() {
                if matches!(info.kind, SectionKind::Primary(identity) if identity.format_specific() == Some(segment))
                {
                    builder.add_section(section_id);
                }
            }
        }

        // The rest (e.g. symbol table, string table).
        builder.add_section(output_section_id::STRTAB);
        builder.add_section(output_section_id::CHAINED_FIXUP_TABLE);
        builder.add_section(output_section_id::EXPORTS_TRIE);
        builder.add_section(output_section_id::SYMTAB_GLOBAL);
        builder.add_section(output_section_id::CODE_SIGNATURE);

        builder.build()
    }

    fn align_load_segment_start(
        _segment_def: ProgramSegmentDef,
        segment_alignment: Alignment,
        file_offset: &mut usize,
        mem_offset: &mut u64,
    ) {
        *file_offset = segment_alignment.align_up(*file_offset as u64) as usize;
        *mem_offset = segment_alignment.align_up(*mem_offset);
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
        last_part_id: PartId,
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

    fn is_allowed_in_archive(kind: crate::file_kind::FileKind) -> bool {
        kind == crate::file_kind::FileKind::MachOObject
    }

    fn section_identity<'data>(
        name: SectionName<'data>,
        section: &Self::SectionHeader,
    ) -> SectionIdentity<'data, Self> {
        SectionIdentity::new(name, Some(SegmentName::from_bytes(section.segment_name())))
    }

    fn fmt_section_identity(
        section_name: SectionName<'_>,
        segment_name: &Self::SectionIdentityExt,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match segment_name {
            Some(segment_name) => write!(f, "{segment_name},{section_name}"),
            None => write!(f, "{section_name}"),
        }
    }

    fn finalise_output_section_alignments(
        sizes: &OutputSectionPartMap<u64>,
        output_sections: &mut crate::output_section_id::OutputSections<'_, Self>,
    ) {
        let tlv_sections = output_sections
            .ids_with_info()
            .filter_map(|(section_id, info)| info.section_attributes.is_tls().then_some(section_id))
            .collect_vec();

        let tlv_descriptors = output_sections
            .ids_with_info()
            .filter_map(|(section_id, info)| {
                (info.section_attributes.ty() == S_THREAD_LOCAL_VARIABLES).then_some(section_id)
            })
            .collect_vec();

        let max_align = tlv_sections
            .iter()
            .map(|&section_id| {
                sizes.max_alignment(section_id.part_id_range::<MachO>(), output_sections)
            })
            .max();

        if let Some(max_align) = max_align {
            for section_id in tlv_sections {
                output_sections.bump_min_alignment(section_id, max_align);
            }
        }

        for section_id in tlv_descriptors {
            output_sections.bump_min_alignment(section_id, alignment::USIZE);
        }
    }
}

pub(crate) fn install_name<'data>(
    file_id: FileId,
    symbol_db: &crate::symbol_db::SymbolDb<'data, MachO>,
) -> &'data [u8] {
    match symbol_db.file(file_id) {
        SequencedInput::StubLibrary(stub) => stub.defined_symbols.install_name.as_bytes(),
        SequencedInput::Object(obj) => obj.parsed.input.lib_name(),
        _ => {
            panic!("Internal error: Expected StubLibrary or Dynamic");
        }
    }
}

fn create_dynamic_layout_ext<'data>(
    target_file_id: FileId,
    resources: &layout::FinaliseLayoutResources<'_, 'data, MachO>,
) -> Result<Option<DynamicLayoutExt>> {
    let Some(index) = resources
        .format_specific
        .imported_libraries
        .iter()
        .position(|file_id| *file_id == target_file_id)
    else {
        return Ok(None);
    };

    Ok(Some(DynamicLayoutExt {
        ordinal: NonZeroU8::new(u8::try_from(index + 1).context("Too many loaded stub libraries")?)
            .unwrap(),
    }))
}

const NUM_BUILT_IN_SECTIONS: usize = crate::output_section_id::num_built_in_sections::<MachO>();

const SECTION_DEFINITIONS: [BuiltInSectionDetails; NUM_BUILT_IN_SECTIONS] = {
    let mut defs = [DEFAULT_DEFS; NUM_BUILT_IN_SECTIONS];

    defs[crate::output_section_id::FILE_HEADER.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"FILE_HEADER"), None)),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::LOAD_COMMANDS.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"LOAD_COMMANDS"), None)),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::LINK_EDIT_SEGMENT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(SEG_LINKEDIT.as_bytes()),
            None,
        )),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::STRTAB.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"STRTAB"), None)),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::CHAINED_FIXUP_TABLE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"DYLD_CHAINED_FIXUPS_TABLE"),
            None,
        )),
        min_alignment: alignment::USIZE,
        ..DEFAULT_DEFS
    };
    defs[output_section_id::EXPORTS_TRIE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"EXPORTS_TRIE"), None)),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::SYMTAB_GLOBAL.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"SYMTAB"), None)),
        min_alignment: alignment::USIZE,
        ..DEFAULT_DEFS
    };
    defs[output_section_id::CODE_SIGNATURE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"CODE_SIGNATURE"), None)),
        min_alignment: Alignment {
            exponent: CS_SECTION_ALIGNMENT_EXP,
        },
        ..DEFAULT_DEFS
    };
    defs[output_section_id::GOT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"__got"),
            Some(SegmentName::DATA_CONST),
        )),
        section_flags: macho::S_NON_LAZY_SYMBOL_POINTERS.to_flags(),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::PLT_GOT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"__stubs"),
            Some(SegmentName::TEXT),
        )),
        section_flags: macho::S_SYMBOL_STUBS
            .to_flags()
            .with(macho::S_ATTR_PURE_INSTRUCTIONS)
            .with(macho::S_ATTR_SOME_INSTRUCTIONS),
        min_alignment: Alignment { exponent: 2 },
        ..DEFAULT_DEFS
    };
    defs[output_section_id::INIT_OFFSETS.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"__init_offsets"),
            Some(SegmentName::TEXT),
        )),
        section_flags: macho::S_INIT_FUNC_OFFSETS.to_flags(),
        min_alignment: Alignment { exponent: 2 },
    };

    defs
};

#[derive(Debug, Default)]
pub(crate) struct EpilogueLayoutExt {
    imported_symbols: Vec<SymbolId>,
}

#[derive(Debug)]
pub(crate) struct DynamicLayoutStateExt {
    imported_symbols: Vec<SymbolId>,
    loaded: bool,
}

#[derive(Debug)]
pub(crate) struct DynamicLayoutExt {
    pub(crate) ordinal: NonZeroU8,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ResolutionExt {
    pub(crate) got_address: Option<NonZeroU64>,
    pub(crate) plt_address: Option<NonZeroU64>,
}

fn allocate_got(memory_offsets: &mut OutputSectionPartMap<u64>) -> NonZeroU64 {
    let got_address = NonZeroU64::new(memory_offsets.get(part_id::GOT)).unwrap();
    memory_offsets.increment(part_id::GOT, GOT_ENTRY_SIZE);
    got_address
}

fn allocate_plt(memory_offsets: &mut OutputSectionPartMap<u64>) -> NonZeroU64 {
    let plt_address = NonZeroU64::new(memory_offsets.get(part_id::PLT_GOT)).unwrap();
    memory_offsets.increment(part_id::PLT_GOT, PLT_ENTRY_SIZE);
    plt_address
}

const DEFAULT_SECTION_RULES: &[SectionRule<'static>] = &[
    SectionRule::exact(b"__mod_init_func", SectionRuleOutcome::InitFunc),
    // TODO: Add a Mach-O output section ID and rule for `__compact_unwind`.
];

fn section_header_name_for_segment<'data>(
    output_sections: &crate::output_section_id::OutputSections<'data, MachO>,
    section_id: OutputSectionId,
    segment_def: ProgramSegmentDef,
) -> Option<SectionName<'data>> {
    if !output_sections.will_emit_section(section_id) {
        return None;
    }

    output_sections
        .identity(section_id)
        .filter(|identity| identity.format_specific().is_some())
        .filter(|_| output_sections.should_include_in_segment(section_id, segment_def))
        .map(|identity| identity.section_name())
}

fn count_sections_for_segment(
    output_sections: &crate::output_section_id::OutputSections<MachO>,
    segment_def: ProgramSegmentDef,
) -> usize {
    output_sections
        .ids_with_info()
        .filter(|(section_id, _)| {
            section_header_name_for_segment(output_sections, *section_id, segment_def).is_some()
        })
        .count()
}

pub(crate) fn get_segment_sections<'data>(
    layout: &Layout<'data, MachO>,
    segment_id: ProgramSegmentId,
) -> Vec<(OutputRecordLayout, SectionName<'data>, SectionFlags)> {
    let mut in_matching_segment = false;
    let mut segment_sections = Vec::new();
    let segment_def = *layout.program_segments.segment_def(segment_id);

    for event in &layout.output_order {
        match event {
            OrderEvent::SegmentStart(seg_id) if seg_id == segment_id => {
                in_matching_segment = true;
            }
            OrderEvent::SegmentEnd(seg_id) if seg_id == segment_id && in_matching_segment => {
                break;
            }
            OrderEvent::Section(section_id) if in_matching_segment => {
                let Some(section_name) = section_header_name_for_segment(
                    &layout.output_sections,
                    section_id,
                    segment_def,
                ) else {
                    continue;
                };

                segment_sections.push((
                    *layout.merged_section_layouts.get(section_id),
                    section_name,
                    layout.output_sections.section_flags(section_id),
                ));
            }
            _ => {}
        }
    }

    segment_sections
}

fn add_sections_in_segment<'data>(
    builder: &mut OutputOrderBuilder<'_, 'data, MachO>,
    output_sections: &crate::output_section_id::OutputSections<'data, MachO>,
    sections: &[OutputSectionId],
    segment: SegmentName,
) {
    for &section_id in sections {
        if output_sections
            .identity(section_id)
            .is_some_and(|identity| identity.format_specific() == Some(segment))
        {
            builder.add_section(section_id);
        }
    }
}

#[inline(always)]
fn process_relocation<'data, 'scope, A: platform::Arch<Platform = MachO>>(
    object: &layout::ObjectLayoutState<'data, MachO>,
    rel: &Relocation,
    section_index: object::SectionIndex,
    resources: &'scope layout::GraphResources<'data, '_, MachO>,
    queue: &mut layout::LocalWorkQueue<MachO>,
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

        let relocation = A::relocation_from_raw(rel_info)?;
        let mut flags_to_add = layout::resolution_flags(relocation.kind);
        if is_dynamic_library(&symbol_db.file(symbol_db.file_id_for_symbol(symbol_id))) {
            flags_to_add |= ValueFlags::GOT;
            // TODO: classify symbols more reliably, likely by checking whether their section is
            // __text.
            if rel_info.r_type == object::macho::ARM64_RELOC_BRANCH26 {
                flags_to_add |= ValueFlags::DYNAMIC_FUNCTION | ValueFlags::PLT;
            }
        }

        let atomic_flags = &resources.per_symbol_flags.get_atomic(symbol_id);
        let previous_flags = atomic_flags.fetch_or(flags_to_add);

        layout::check_for_undefined::<A>(
            object,
            object.object.section(section_index)?,
            rel_info.r_address.into(),
            local_sym_index,
            flags,
            symbol_id,
            resources,
        )?;

        if !previous_flags.has_resolution() {
            queue.send_symbol_request::<A>(symbol_id, resources, scope);
        }
    }

    Ok(())
}

fn is_dynamic_library(file: &SequencedInput<MachO>) -> bool {
    match file {
        SequencedInput::StubLibrary(_) => true,
        SequencedInput::Object(obj) => obj.is_dynamic(),
        _ => false,
    }
}

impl<'data> File<'data> {
    fn sections(&self) -> &'data [SectionHeader] {
        self.kind.sections()
    }
}

impl<'data> ObjectKind<'data> {
    fn sections(&self) -> &'data [SectionHeader] {
        match self {
            ObjectKind::Regular(regular_object) => regular_object.sections,
            ObjectKind::Dylib => &[],
        }
    }
}

impl DynamicLayoutStateExt {
    fn new(args: &MachOArgs) -> Self {
        Self {
            imported_symbols: Default::default(),
            loaded: !args.dead_strip_dylibs,
        }
    }
}

impl SinglePartSectionId {
    const fn part_id(self) -> PartId {
        PartId::from_u32(self as u32)
    }

    const fn output_section_id(self) -> OutputSectionId {
        OutputSectionId::from_u32(self as u32)
    }
}
