use crate::FileSystem;
use crate::alignment;
use crate::alignment::Alignment;
use crate::arch::Architecture;
use crate::args::BSymbolicKind;
use crate::args::RelocationModel;
use crate::args::elf::BuildIdOption;
use crate::args::elf::ElfArgs;
use crate::bail;
use crate::debug_assert_bail;
use crate::elf;
use crate::elf_writer;
use crate::ensure;
use crate::error;
use crate::error::Context as _;
use crate::error::Result;
use crate::expression_eval;
use crate::file_kind::FileKind;
use crate::file_writer::copy_section_data;
use crate::gdb_index::InputDebugIndexSection;
use crate::grouping::Group;
use crate::grouping::SequencedLinkerScript;
use crate::input_data::InputBytes;
use crate::input_data::InputRef;
use crate::layout;
use crate::layout::CommonGroupState;
use crate::layout::DynamicSymbolDefinition;
use crate::layout::HandlerData as _;
use crate::layout::ObjectLayout;
use crate::layout::ObjectLayoutState;
use crate::layout::OutputRecordLayout;
use crate::layout::Resolution;
use crate::layout::SymbolCopyInfo;
use crate::layout::objects_iter;
use crate::layout_rules::SectionKind;
use crate::layout_rules::SectionRule;
use crate::layout_rules::SectionRuleOutcome;
use crate::linker_script;
use crate::output_kind::OutputKind;
use crate::output_section_id::CustomSectionIds;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputOrder;
use crate::output_section_id::OutputOrderBuilder;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_id::SectionIdentity;
use crate::output_section_id::SectionName;
use crate::output_section_id::SectionOutputInfo;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::parsing::InternalSymDefInfo;
use crate::parsing::SymbolPlacement;
use crate::part_id::PartId;
use crate::platform;
use crate::platform::Arch;
use crate::platform::Args as _;
use crate::platform::CommonSymbol;
use crate::platform::DynamicTagValues as _;
use crate::platform::FrameIndex;
use crate::platform::ObjectFile;
use crate::platform::Platform;
use crate::platform::ProgramSegmentDef as _;
use crate::platform::RawSymbolName as _;
use crate::platform::Relaxation as _;
use crate::platform::Relocation;
use crate::platform::RelocationSequence;
use crate::platform::SectionAttributes as _;
use crate::platform::SectionFlags as _;
use crate::platform::SectionHeader as _;
use crate::platform::SectionType as _;
use crate::platform::Symbol as _;
use crate::platform::ThunkConfig;
use crate::platform::VerneedTable as _;
use crate::program_segments::ProgramSegmentId;
use crate::program_segments::ProgramSegments;
use crate::program_segments::SegmentEntry;
use crate::resolution::LoadedMetrics;
use crate::string_merging::MergedStringStartAddresses;
use crate::string_merging::MergedStringsSection;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::symbol_db::Visibility;
use crate::timing_phase;
use crate::value_flags::AtomicPerSymbolFlags;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use crate::version_script::VersionScript;
use crate::writable_elf::WritableCompressionHeader;
use crate::writable_elf::WritableDynamicEntry;
use crate::writable_elf::WritableFileHeader;
use crate::writable_elf::WritableNoteHeader;
use crate::writable_elf::WritableProgramHeader;
use crate::writable_elf::WritableRela;
use crate::writable_elf::WritableRelr;
use crate::writable_elf::WritableSectionHeader;
use crate::writable_elf::WritableSymbol;
use foldhash::HashSet;
use hashbrown::HashMap;
use indexmap::IndexMap;
use itertools::Itertools as _;
use leb128::write::unsigned_len as uleb128_size;
use linker_utils::elf::PageMask;
use linker_utils::elf::RISCV_ATTRIBUTE_VENDOR_NAME;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::SectionType;
use linker_utils::elf::SegmentFlags;
use linker_utils::elf::SegmentType;
use linker_utils::elf::pf;
use linker_utils::elf::pt;
use linker_utils::elf::riscvattr::TAG_RISCV_ARCH;
use linker_utils::elf::riscvattr::TAG_RISCV_ATOMIC_ABI;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC_MINOR;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC_REVISION;
use linker_utils::elf::riscvattr::TAG_RISCV_STACK_ALIGN;
use linker_utils::elf::riscvattr::TAG_RISCV_UNALIGNED_ACCESS;
use linker_utils::elf::riscvattr::TAG_RISCV_WHOLE_FILE;
use linker_utils::elf::riscvattr::TAG_RISCV_X3_REG_USAGE;
use linker_utils::elf::secnames;
#[allow(clippy::wildcard_imports)]
use linker_utils::elf::secnames::*;
use linker_utils::elf::shf;
use linker_utils::elf::sht;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::utils::read_string;
use linker_utils::utils::read_u32;
use linker_utils::utils::read_uleb128;
use object::LittleEndian;
use object::read::elf::CompressionHeader;
use object::read::elf::Crel;
use object::read::elf::CrelIterator;
use object::read::elf::Dyn as _;
use object::read::elf::FileHeader as _;
use object::read::elf::RelocationSections;
use object::read::elf::SectionHeader as _;
use rayon::Scope;
use rayon::prelude::*;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::mem::offset_of;
use std::num::NonZeroU32;
use std::num::NonZeroU64;
use std::ops::Range;
use std::sync::atomic;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

pub(crate) const GLOBAL_POINTER_SYMBOL_NAME: &str = "__global_pointer$";

/// The ppc64 TOC base symbol. Defined to point at the start of the GOT.
pub(crate) const TOC_SYMBOL_NAME: &str = ".TOC.";

pub(crate) const THUNK_SYMBOL_PREFIX: &str = "__thunk_";

pub(crate) fn link_for_arch<'data, F: FileSystem>(
    linker: &'data crate::Linker<F>,
    args: &'data ElfArgs,
) -> Result<crate::LinkerOutput<'data>> {
    match args.arch {
        crate::arch::Architecture::X86_64 => {
            linker.link_for_arch::<Elf64, crate::elf_x86_64::ElfX86_64>(args)
        }
        crate::arch::Architecture::AArch64 => {
            linker.link_for_arch::<Elf64, crate::elf_aarch64::ElfAArch64>(args)
        }
        crate::arch::Architecture::RiscV64 => {
            linker.link_for_arch::<Elf64, crate::elf_riscv64::ElfRiscV64>(args)
        }
        crate::arch::Architecture::LoongArch64 => {
            linker.link_for_arch::<Elf64, crate::elf_loongarch64::ElfLoongArch64>(args)
        }
        crate::arch::Architecture::Ppc64 => {
            linker.link_for_arch::<Elf64, crate::elf_ppc64::ElfPpc64>(args)
        }
        crate::arch::Architecture::Unsupported => {
            bail!(
                "No default target architecture known for host platform. \
                    Please specify an architecture with -m"
            )
        }
    }
}

pub(crate) trait ElfWord: Copy + FromBytes + IntoBytes + Into<u64> + Send + Sync {
    fn from_u64(value: u64) -> Result<Self>;
    fn from_le_bytes(bytes: &[u8]) -> Self;
}

impl ElfWord for u32 {
    fn from_u64(value: u64) -> Result<Self> {
        u32::try_from(value).map_err(|_| error!("ELF word value 0x{value:x} does not fit in ELF32"))
    }

    fn from_le_bytes(bytes: &[u8]) -> Self {
        u32::from_le_bytes(bytes.try_into().unwrap())
    }
}

impl ElfWord for u64 {
    fn from_u64(value: u64) -> Result<Self> {
        Ok(value)
    }

    fn from_le_bytes(bytes: &[u8]) -> Self {
        u64::from_le_bytes(bytes.try_into().unwrap())
    }
}

pub(crate) trait ElfClass: Copy + Default + Send + Sync + std::fmt::Debug + 'static {
    type FileHeader: object::read::elf::FileHeader<
            Endian = LittleEndian,
            Word: ElfWord,
            CompressionHeader: WritableCompressionHeader + Default,
            NoteHeader: WritableNoteHeader,
            ProgramHeader: WritableProgramHeader,
            Relr: WritableRelr,
            SectionHeader: platform::SectionHeader + WritableSectionHeader,
            Sym: ElfSymbol<Class = Self>,
            Dyn: WritableDynamicEntry + Send + Sync,
            Rela: WritableRela + Send + Sync + Copy + 'static,
        > + WritableFileHeader;

    const FILE_HEADER_SIZE: u16 = size_of::<Self::FileHeader>() as u16;
    const PROGRAM_HEADER_SIZE: u16 = size_of::<ProgramHeader<Self>>() as u16;
    const SECTION_HEADER_SIZE: u16 = size_of::<SectionHeader<Self>>() as u16;
    const ADDRESS_SIZE: u64 = size_of::<Word<Self>>() as u64;
    const ADDRESS_ALIGNMENT: Alignment = Alignment {
        exponent: Self::ADDRESS_SIZE.trailing_zeros() as u8,
    };
    const GOT_ENTRY_SIZE: u64 = Self::ADDRESS_SIZE;
    const RELA_ENTRY_SIZE: u64 = size_of::<Rela<Self>>() as u64;
    const RELR_ENTRY_SIZE: u64 = size_of::<Relr<Self>>() as u64;
    const SYMTAB_ENTRY_SIZE: u64 = size_of::<SymtabEntry<Self>>() as u64;
    const DYNAMIC_ENTRY_SIZE: u64 = size_of::<DynamicEntry<Self>>() as u64;
    const NOTE_HEADER_SIZE: u64 = size_of::<NoteHeader<Self>>() as u64;
    const GNU_HASH_BLOOM_SIZE: u64 = Self::ADDRESS_SIZE;
    const PROGRAM_HEADER_ALIGNMENT: Alignment = Self::ADDRESS_ALIGNMENT;
    const GOT_ENTRY_ALIGNMENT: Alignment = Self::ADDRESS_ALIGNMENT;
    const RELA_ENTRY_ALIGNMENT: Alignment = Self::ADDRESS_ALIGNMENT;
    const RELR_ENTRY_ALIGNMENT: Alignment = Self::ADDRESS_ALIGNMENT;
    const GNU_HASH_ALIGNMENT: Alignment = Self::ADDRESS_ALIGNMENT;
    const SYMTAB_ENTRY_ALIGNMENT: Alignment = Self::ADDRESS_ALIGNMENT;
    const VERSION_D_ALIGNMENT: Alignment = Self::ADDRESS_ALIGNMENT;
    const VERSION_R_ALIGNMENT: Alignment = Self::ADDRESS_ALIGNMENT;
    const GNU_PROPERTY_ALIGNMENT: Alignment = Self::ADDRESS_ALIGNMENT;
    const GNU_PROPERTY_ENTRY_SIZE: u64 =
        Self::GNU_PROPERTY_ALIGNMENT.align_up(size_of::<NoteProperty>() as u64);
}

pub(crate) trait ElfSymbol:
    object::read::elf::Sym<Endian = LittleEndian>
    + WritableSymbol
    + Default
    + std::fmt::Debug
    + Copy
    + Send
    + Sync
    + 'static
{
    type Class: ElfClass;
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct Class64;

impl ElfClass for Class64 {
    type FileHeader = object::elf::FileHeader64<LittleEndian>;
}

impl ElfSymbol for object::elf::Sym64<LittleEndian> {
    type Class = Class64;
}

pub(crate) type FileHeader<C> = <C as ElfClass>::FileHeader;
pub(crate) type Word<C> = <FileHeader<C> as object::read::elf::FileHeader>::Word;
pub(crate) type ProgramHeader<C> = <FileHeader<C> as object::read::elf::FileHeader>::ProgramHeader;
pub(crate) type SectionHeader<C> = <FileHeader<C> as object::read::elf::FileHeader>::SectionHeader;
pub(crate) type SymtabEntry<C> = <FileHeader<C> as object::read::elf::FileHeader>::Sym;
pub(crate) type DynamicEntry<C> = <FileHeader<C> as object::read::elf::FileHeader>::Dyn;
pub(crate) type CompressionHeaderEntry<C> =
    <FileHeader<C> as object::read::elf::FileHeader>::CompressionHeader;
pub(crate) type Rela<C> = <FileHeader<C> as object::read::elf::FileHeader>::Rela;
pub(crate) type Relr<C> = <FileHeader<C> as object::read::elf::FileHeader>::Relr;
pub(crate) type NoteHeader<C> = <FileHeader<C> as object::read::elf::FileHeader>::NoteHeader;
pub(crate) type FileHeader64 = FileHeader<Class64>;
pub(crate) type GnuHashHeader = object::elf::GnuHashHeader<LittleEndian>;
pub(crate) type Verdef = object::elf::Verdef<LittleEndian>;
pub(crate) type Verdaux = object::elf::Verdaux<LittleEndian>;
pub(crate) type Verneed = object::elf::Verneed<LittleEndian>;
pub(crate) type Vernaux = object::elf::Vernaux<LittleEndian>;
pub(crate) type Versym = object::elf::Versym<LittleEndian>;
pub(crate) type VerdefIterator<'data, C> = object::read::elf::VerdefIterator<'data, FileHeader<C>>;
type VerneedIterator<'data, C> = object::read::elf::VerneedIterator<'data, FileHeader<C>>;
type SectionTable<'data, C> = object::read::elf::SectionTable<'data, FileHeader<C>>;
type SymbolTable<'data, C> = object::read::elf::SymbolTable<'data, FileHeader<C>>;

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct Elf<C: ElfClass>(PhantomData<C>);

pub(crate) type Elf64 = Elf<Class64>;
pub(crate) type File64<'data> = File<'data, Class64>;
pub(crate) type RelocationList64<'data> = RelocationList<'data, Class64>;

#[repr(u32)]
#[derive(Clone, Copy)]
enum SinglePartSectionId {
    ProgramHeaders = crate::output_section_id::NUM_COMMON_SINGLE_PART_SECTIONS,
    SectionHeaders,
    Shstrtab,
    Strtab,
    Got,
    GotRelr,
    PltGot,
    RelaPlt,
    EhFrame,
    EhFrameHdr,
    Sframe,
    Dynamic,
    SysvHash,
    GnuHash,
    Dynsym,
    Dynstr,
    Interp,
    GnuVersion,
    GnuVersionD,
    GnuVersionR,
    NoteGnuProperty,
    NoteGnuBuildId,
    SymtabLocal,
    SymtabGlobal,
    RelaDynRelative,
    RelaDynGeneral,
    RiscvAttributes,
    RelroPadding,
    RelrDyn,
    SymtabShndxLocal,
    SymtabShndxGlobal,
    GdbIndex,

    // Must be last.
    Count,
}

#[repr(u32)]
#[derive(Clone, Copy)]
enum RegularSectionId {
    Rodata,
    InitArray,
    FiniArray,
    PreinitArray,
    Text,
    Init,
    Fini,
    Data,
    Tdata,
    Tbss,
    Bss,
    Comment,
    GccExceptTable,
    NoteAbiTag,
    DataRelRo,

    // Must be last.
    Count,
}

const ELF_NUM_SINGLE_PART_SECTIONS: u32 = SinglePartSectionId::Count as u32;
const ELF_NUM_BUILT_IN_REGULAR_SECTIONS: usize = RegularSectionId::Count as usize;
const ELF_NUM_BUILT_IN_SECTIONS: usize =
    ELF_NUM_SINGLE_PART_SECTIONS as usize + ELF_NUM_BUILT_IN_REGULAR_SECTIONS;

pub(crate) mod part_id {
    use super::SinglePartSectionId;
    use crate::part_id::PartId;

    pub(crate) const PROGRAM_HEADERS: PartId = SinglePartSectionId::ProgramHeaders.part_id();
    pub(crate) const SECTION_HEADERS: PartId = SinglePartSectionId::SectionHeaders.part_id();
    pub(crate) const SHSTRTAB: PartId = SinglePartSectionId::Shstrtab.part_id();
    pub(crate) const STRTAB: PartId = SinglePartSectionId::Strtab.part_id();
    pub(crate) const GOT: PartId = SinglePartSectionId::Got.part_id();
    pub(crate) const GOT_RELR: PartId = SinglePartSectionId::GotRelr.part_id();
    pub(crate) const PLT_GOT: PartId = SinglePartSectionId::PltGot.part_id();
    pub(crate) const RELA_PLT: PartId = SinglePartSectionId::RelaPlt.part_id();
    pub(crate) const EH_FRAME: PartId = SinglePartSectionId::EhFrame.part_id();
    pub(crate) const EH_FRAME_HDR: PartId = SinglePartSectionId::EhFrameHdr.part_id();
    pub(crate) const DYNAMIC: PartId = SinglePartSectionId::Dynamic.part_id();
    pub(crate) const SYSV_HASH: PartId = SinglePartSectionId::SysvHash.part_id();
    pub(crate) const GNU_HASH: PartId = SinglePartSectionId::GnuHash.part_id();
    pub(crate) const DYNSYM: PartId = SinglePartSectionId::Dynsym.part_id();
    pub(crate) const DYNSTR: PartId = SinglePartSectionId::Dynstr.part_id();
    pub(crate) const INTERP: PartId = SinglePartSectionId::Interp.part_id();
    pub(crate) const GNU_VERSION: PartId = SinglePartSectionId::GnuVersion.part_id();
    pub(crate) const GNU_VERSION_D: PartId = SinglePartSectionId::GnuVersionD.part_id();
    pub(crate) const GNU_VERSION_R: PartId = SinglePartSectionId::GnuVersionR.part_id();
    pub(crate) const NOTE_GNU_PROPERTY: PartId = SinglePartSectionId::NoteGnuProperty.part_id();
    pub(crate) const NOTE_GNU_BUILD_ID: PartId = SinglePartSectionId::NoteGnuBuildId.part_id();
    pub(crate) const SYMTAB_LOCAL: PartId = SinglePartSectionId::SymtabLocal.part_id();
    pub(crate) const SYMTAB_GLOBAL: PartId = SinglePartSectionId::SymtabGlobal.part_id();
    pub(crate) const RELA_DYN_RELATIVE: PartId = SinglePartSectionId::RelaDynRelative.part_id();
    pub(crate) const RELA_DYN_GENERAL: PartId = SinglePartSectionId::RelaDynGeneral.part_id();
    pub(crate) const RISCV_ATTRIBUTES: PartId = SinglePartSectionId::RiscvAttributes.part_id();
    pub(crate) const RELR_DYN: PartId = SinglePartSectionId::RelrDyn.part_id();
    pub(crate) const SYMTAB_SHNDX_LOCAL: PartId = SinglePartSectionId::SymtabShndxLocal.part_id();
    pub(crate) const SYMTAB_SHNDX_GLOBAL: PartId = SinglePartSectionId::SymtabShndxGlobal.part_id();
    pub(crate) const GDB_INDEX: PartId = SinglePartSectionId::GdbIndex.part_id();
}

pub(crate) mod output_section_id {
    use super::RegularSectionId;
    use super::SinglePartSectionId;
    use crate::output_section_id::OutputSectionId;

    pub(crate) const PROGRAM_HEADERS: OutputSectionId =
        SinglePartSectionId::ProgramHeaders.output_section_id();
    pub(crate) const SECTION_HEADERS: OutputSectionId =
        SinglePartSectionId::SectionHeaders.output_section_id();
    pub(crate) const SHSTRTAB: OutputSectionId = SinglePartSectionId::Shstrtab.output_section_id();
    pub(crate) const STRTAB: OutputSectionId = SinglePartSectionId::Strtab.output_section_id();
    pub(crate) const GOT: OutputSectionId = SinglePartSectionId::Got.output_section_id();
    pub(crate) const GOT_RELR: OutputSectionId = SinglePartSectionId::GotRelr.output_section_id();
    pub(crate) const PLT_GOT: OutputSectionId = SinglePartSectionId::PltGot.output_section_id();
    pub(crate) const RELA_PLT: OutputSectionId = SinglePartSectionId::RelaPlt.output_section_id();
    pub(crate) const EH_FRAME: OutputSectionId = SinglePartSectionId::EhFrame.output_section_id();
    pub(crate) const EH_FRAME_HDR: OutputSectionId =
        SinglePartSectionId::EhFrameHdr.output_section_id();
    pub(crate) const SFRAME: OutputSectionId = SinglePartSectionId::Sframe.output_section_id();
    pub(crate) const DYNAMIC: OutputSectionId = SinglePartSectionId::Dynamic.output_section_id();
    pub(crate) const HASH: OutputSectionId = SinglePartSectionId::SysvHash.output_section_id();
    pub(crate) const GNU_HASH: OutputSectionId = SinglePartSectionId::GnuHash.output_section_id();
    pub(crate) const DYNSYM: OutputSectionId = SinglePartSectionId::Dynsym.output_section_id();
    pub(crate) const DYNSTR: OutputSectionId = SinglePartSectionId::Dynstr.output_section_id();
    pub(crate) const INTERP: OutputSectionId = SinglePartSectionId::Interp.output_section_id();
    pub(crate) const GNU_VERSION: OutputSectionId =
        SinglePartSectionId::GnuVersion.output_section_id();
    pub(crate) const GNU_VERSION_D: OutputSectionId =
        SinglePartSectionId::GnuVersionD.output_section_id();
    pub(crate) const GNU_VERSION_R: OutputSectionId =
        SinglePartSectionId::GnuVersionR.output_section_id();
    pub(crate) const NOTE_GNU_PROPERTY: OutputSectionId =
        SinglePartSectionId::NoteGnuProperty.output_section_id();
    pub(crate) const NOTE_GNU_BUILD_ID: OutputSectionId =
        SinglePartSectionId::NoteGnuBuildId.output_section_id();
    pub(crate) const SYMTAB_LOCAL: OutputSectionId =
        SinglePartSectionId::SymtabLocal.output_section_id();
    pub(crate) const SYMTAB_GLOBAL: OutputSectionId =
        SinglePartSectionId::SymtabGlobal.output_section_id();
    pub(crate) const RELA_DYN_RELATIVE: OutputSectionId =
        SinglePartSectionId::RelaDynRelative.output_section_id();
    pub(crate) const RELA_DYN_GENERAL: OutputSectionId =
        SinglePartSectionId::RelaDynGeneral.output_section_id();
    pub(crate) const RISCV_ATTRIBUTES: OutputSectionId =
        SinglePartSectionId::RiscvAttributes.output_section_id();
    pub(crate) const RELRO_PADDING: OutputSectionId =
        SinglePartSectionId::RelroPadding.output_section_id();
    pub(crate) const RELR_DYN: OutputSectionId = SinglePartSectionId::RelrDyn.output_section_id();
    pub(crate) const SYMTAB_SHNDX_LOCAL: OutputSectionId =
        SinglePartSectionId::SymtabShndxLocal.output_section_id();
    pub(crate) const SYMTAB_SHNDX_GLOBAL: OutputSectionId =
        SinglePartSectionId::SymtabShndxGlobal.output_section_id();
    pub(crate) const GDB_INDEX: OutputSectionId = SinglePartSectionId::GdbIndex.output_section_id();

    pub(crate) const RODATA: OutputSectionId = RegularSectionId::Rodata.output_section_id();
    pub(crate) const INIT_ARRAY: OutputSectionId = RegularSectionId::InitArray.output_section_id();
    pub(crate) const FINI_ARRAY: OutputSectionId = RegularSectionId::FiniArray.output_section_id();
    pub(crate) const PREINIT_ARRAY: OutputSectionId =
        RegularSectionId::PreinitArray.output_section_id();
    pub(crate) const TEXT: OutputSectionId = RegularSectionId::Text.output_section_id();
    pub(crate) const INIT: OutputSectionId = RegularSectionId::Init.output_section_id();
    pub(crate) const FINI: OutputSectionId = RegularSectionId::Fini.output_section_id();
    pub(crate) const DATA: OutputSectionId = RegularSectionId::Data.output_section_id();
    pub(crate) const TDATA: OutputSectionId = RegularSectionId::Tdata.output_section_id();
    pub(crate) const TBSS: OutputSectionId = RegularSectionId::Tbss.output_section_id();
    pub(crate) const BSS: OutputSectionId = RegularSectionId::Bss.output_section_id();
    pub(crate) const COMMENT: OutputSectionId = RegularSectionId::Comment.output_section_id();
    pub(crate) const GCC_EXCEPT_TABLE: OutputSectionId =
        RegularSectionId::GccExceptTable.output_section_id();
    pub(crate) const NOTE_ABI_TAG: OutputSectionId =
        RegularSectionId::NoteAbiTag.output_section_id();
    pub(crate) const DATA_REL_RO: OutputSectionId = RegularSectionId::DataRelRo.output_section_id();
}

#[derive(derive_more::Debug)]
pub(crate) struct File<'data, C: ElfClass> {
    pub(crate) arch: Architecture,
    #[debug(skip)]
    pub(crate) data: &'data [u8],
    #[debug(skip)]
    pub(crate) sections: SectionTable<'data, C>,
    /// This may be symtab or dynsym depending on the file type.
    #[debug(skip)]
    pub(crate) symbols: SymbolTable<'data, C>,
    #[debug(skip)]
    pub(crate) versym: &'data [Versym],

    /// An iterator over the version definitions and the corresponding linked string table index.
    pub(crate) verdef: Option<(VerdefIterator<'data, C>, object::SectionIndex)>,

    /// Number of verdef versions according to `sh_info` of `.gnu._version_d` section.
    pub(crate) verdefnum: u32,

    /// An iterator over the version references and the corresponding linked string table index.
    pub(crate) verneed: Option<(VerneedIterator<'data, C>, object::SectionIndex)>,

    /// e_flags from the header.
    pub(crate) eflags: object::elf::FileFlags,

    pub(crate) dynamic_tag_values: Option<DynamicTagValues<'data>>,
}

#[derive(Clone, Copy)]
pub(crate) struct ElfRela<C: ElfClass> {
    raw: Rela<C>,
}

impl<C: ElfClass> ElfRela<C> {
    pub(crate) fn new(raw: Rela<C>) -> Self {
        Self { raw }
    }
}

impl<C: ElfClass> Relocation for ElfRela<C> {
    type Sequence<'data> = RelaSequence<'data, C>;
    type Platform = Elf<C>;

    fn symbol(&self) -> Option<object::SymbolIndex> {
        object::read::elf::Rela::symbol(&self.raw, LittleEndian, false)
    }

    fn raw_type(&self) -> object::elf::RelocationType {
        object::read::elf::Rela::r_type(&self.raw, LittleEndian, false)
    }

    fn offset(&self) -> u64 {
        object::read::elf::Rela::r_offset(&self.raw, LittleEndian).into()
    }

    fn addend(&self) -> i64 {
        object::read::elf::Rela::r_addend(&self.raw, LittleEndian).into()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ElfCrel<C: ElfClass> {
    raw: Crel,
    class: PhantomData<C>,
}

impl<C: ElfClass> ElfCrel<C> {
    pub(crate) fn new(raw: Crel) -> Self {
        Self {
            raw,
            class: PhantomData,
        }
    }
}

impl<C: ElfClass> Relocation for ElfCrel<C> {
    type Sequence<'data> = Vec<Self>;
    type Platform = Elf<C>;

    fn symbol(&self) -> Option<object::SymbolIndex> {
        object::read::elf::Crel::symbol(&self.raw)
    }

    fn raw_type(&self) -> object::elf::RelocationType {
        self.raw.r_type
    }

    fn offset(&self) -> u64 {
        self.raw.r_offset
    }

    fn addend(&self) -> i64 {
        self.raw.r_addend
    }
}

/// A list of relocations that supports iteration.
#[derive(Clone)]
pub(crate) enum RelocationList<'data, C: ElfClass> {
    Rela(&'data [Rela<C>]),
    Crel(CrelIterator<'data>),
}

impl<'data, C: ElfClass> platform::RelocationList<'data> for RelocationList<'data, C> {
    fn num_relocations(&self) -> usize {
        match self {
            RelocationList::Rela(rela) => rela.len(),
            RelocationList::Crel(crel) => crel.len(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RelaSequence<'data, C: ElfClass>(&'data [Rela<C>]);

impl<'data, C: ElfClass> RelocationSequence<'data> for RelaSequence<'data, C> {
    type Rel = ElfRela<C>;

    fn rel_iter(&self) -> impl Iterator<Item = ElfRela<C>> {
        self.0.iter().copied().map(|raw| ElfRela { raw })
    }

    fn subsequence(&self, range: Range<usize>) -> Self {
        Self(&self.0[range])
    }

    fn num_relocations(&self) -> usize {
        self.0.len()
    }
}

impl<'data, C: ElfClass> RelocationSequence<'data> for Vec<ElfCrel<C>> {
    type Rel = ElfCrel<C>;

    fn rel_iter(&self) -> impl Iterator<Item = ElfCrel<C>> {
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
const _: () = assert!(!core::mem::needs_drop::<File64>());

/// Returns the name to use when writing a symbol into .symtab's string table.
/// Unlike .dynsym (which encodes version info separately in .gnu.version), .symtab has no
/// .gnu.version section, so version suffixes must be embedded in the name itself
/// (e.g. `foo@VER_1.0`, `bar@@VER_1.0`, `remain_unversioned@`), matching GNU ld behaviour.
pub(crate) fn symtab_name_for_strtab(raw_name: &[u8]) -> &[u8] {
    raw_name
}

impl<C: ElfClass> platform::Platform for Elf<C> {
    const NUM_SINGLE_PART_SECTIONS: u32 = ELF_NUM_SINGLE_PART_SECTIONS;
    const NUM_BUILT_IN_REGULAR_SECTIONS: usize = ELF_NUM_BUILT_IN_REGULAR_SECTIONS;

    const TEXT_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::TEXT);
    const DATA_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::DATA);
    const BSS_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::BSS);
    const RODATA_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::RODATA);
    const TDATA_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::TDATA);
    const TBSS_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::TBSS);
    const STRTAB_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::STRTAB);
    const SYMTAB_GLOBAL_SECTION_ID: Option<OutputSectionId> =
        Some(output_section_id::SYMTAB_GLOBAL);
    const GOT_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::GOT);
    const PLT_GOT_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::PLT_GOT);
    const SYMTAB_LOCAL_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::SYMTAB_LOCAL);
    const SYMTAB_SHNDX_LOCAL_SECTION_ID: Option<OutputSectionId> =
        Some(output_section_id::SYMTAB_SHNDX_LOCAL);
    const SYMTAB_SHNDX_GLOBAL_SECTION_ID: Option<OutputSectionId> =
        Some(output_section_id::SYMTAB_SHNDX_GLOBAL);
    const GDB_INDEX_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::GDB_INDEX);
    const DYNSTR_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::DYNSTR);
    const DYNSYM_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::DYNSYM);
    const EH_FRAME_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::EH_FRAME);
    const NOTE_GNU_PROPERTY_SECTION_ID: Option<OutputSectionId> =
        Some(output_section_id::NOTE_GNU_PROPERTY);
    const RISCV_ATTRIBUTES_SECTION_ID: Option<OutputSectionId> =
        Some(output_section_id::RISCV_ATTRIBUTES);
    const GOT_RELR_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::GOT_RELR);
    const GNU_VERSION_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::GNU_VERSION);
    const COMMENT_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::COMMENT);
    const INTERP_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::INTERP);
    const SFRAME_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::SFRAME);
    const RELRO_PADDING_SECTION_ID: Option<OutputSectionId> =
        Some(output_section_id::RELRO_PADDING);

    const CUSTOM_PHDR_EXCLUDED_SECTION_IDS: &'static [OutputSectionId] = &[
        output_section_id::PROGRAM_HEADERS,
        output_section_id::SECTION_HEADERS,
    ];

    /// The `.init` section `crti.o` contains the start of a function and `crtn.o` contains the end
    /// of that function. If `.init` has say alignment = 4 and we add padding after it to bring it
    /// up to a multiple of 4 bytes, then we'll break the function, since the padding bytes won't be
    /// valid instructions. Same thing applies to `.fini`.
    const PACKED_SECTION_IDS: &'static [OutputSectionId] =
        &[output_section_id::INIT, output_section_id::FINI];

    const VERIFY_IGNORE_ALIGNMENT_SECTION_IDS: &'static [OutputSectionId] = &[
        output_section_id::GNU_HASH,
        output_section_id::EH_FRAME,
        output_section_id::GNU_VERSION_D,
        output_section_id::STRTAB,
    ];

    const VERIFY_IGNORE_SECTION_IDS: &'static [OutputSectionId] = &[
        output_section_id::RELA_PLT,
        output_section_id::EH_FRAME_HDR,
        output_section_id::RELA_DYN_GENERAL,
        output_section_id::RELA_DYN_RELATIVE,
        output_section_id::RELR_DYN,
        output_section_id::GNU_VERSION,
        output_section_id::GNU_HASH,
        output_section_id::DYNAMIC,
        output_section_id::INTERP,
        crate::output_section_id::FILE_HEADER,
        output_section_id::PROGRAM_HEADERS,
        output_section_id::SECTION_HEADERS,
        output_section_id::SHSTRTAB,
    ];

    const HAS_NULL_SYMBOL_ENTRY: bool = true;

    type File<'data> = File<'data, C>;
    type FileFlags = object::elf::FileFlags;
    type SymtabEntry = SymtabEntry<C>;
    type PlatformSpecificSymbol = core::convert::Infallible;
    type SectionHeader = SectionHeader<C>;
    type SectionFlags = SectionFlags;
    type SectionAttributes = SectionAttributes<C>;
    type SectionType = SectionType;
    type SegmentType = SegmentType;
    type ProgramSegmentDef = ProgramSegmentDef;
    type BuiltInSectionDetails = BuiltInSectionDetails<C>;
    type RelocationSections = RelocationSections;
    type DynamicEntry = DynamicEntry<C>;
    type DynamicSymbolDefinitionExt = DynamicSymbolDefinitionExt;
    type RelocationInfo = object::elf::RelocationType;
    type FinaliseSizesExt<'data> = LayoutExt;
    type LayoutExt<'data> = LayoutExt;
    type SymbolVersionIndex = Versym;
    type NonAddressableCounts = NonAddressableCounts;
    type NonAddressableIndexes = NonAddressableIndexes;
    type EpilogueLayoutExt = EpilogueLayoutExt;
    type GroupLayoutExt = GroupLayoutExt;
    type CommonGroupStateExt = CommonGroupStateExt;
    type StubLibraryLayoutStateExt = ();
    type StubLibraryLayoutExt = ();
    type PreludeLayoutStateExt = PreludeLayoutStateExt;
    type PreludeLayoutExt = PreludeLayoutExt;
    type ArchIdentifier = object::elf::Machine;
    type SectionIterator<'a> = core::slice::Iter<'a, SectionHeader<C>>;
    type DynamicTagValues<'data> = crate::elf::DynamicTagValues<'data>;
    type RelocationList<'data> = RelocationList<'data, C>;
    type VersionNames<'data> = VersionNames<'data>;
    type RawSymbolName<'data> = RawSymbolName<'data>;
    type VerneedTable<'data> = VerneedTable<'data>;
    type ObjectLayoutStateExt<'data> = ObjectLayoutStateExt<'data, C>;
    type DynamicLayoutStateExt<'data> = DynamicLayoutStateExt<'data, C>;
    type DynamicLayoutExt<'data> = DynamicLayoutExt<'data, C>;
    type LayoutResourcesExt<'data> = LayoutResourcesExt<'data>;
    type Args = ElfArgs;
    type ResolutionExt = ResolutionExt;
    type SymtabShndxEntry = SymtabShndxEntry;
    type ResolvedObjectExt<'data> = ResolvedObjectExt<'data>;
    type SectionIdentityExt = ();

    fn write_output_file<'data, A: Arch<Platform = Self>, F: FileSystem>(
        output: &crate::file_writer::Output<F>,
        layout: &layout::Layout<'data, Self>,
    ) -> Result {
        output.write(layout, elf_writer::write::<C, A>)
    }

    fn maybe_compress_debug_sections<'data, A: Arch<Platform = Self>>(
        layout: &mut layout::Layout<'data, Self>,
    ) -> Result {
        crate::compression::maybe_compress_debug_sections_elf::<C, A>(layout)
    }

    fn maybe_init_linker_plugin<'data>(
        args: &'data Self::Args,
        linker_plugin_arena: &'data colosseum::sync::Arena<crate::linker_plugins::LoadedPlugin>,
        herd: &'data bumpalo_herd::Herd,
    ) -> Result<Option<crate::linker_plugins::LinkerPlugin<'data>>> {
        crate::linker_plugins::LinkerPlugin::from_args::<C>(args, linker_plugin_arena, herd)
    }

    fn plugin_all_symbols_read<'data, F: FileSystem>(
        plugin: &mut crate::linker_plugins::LinkerPlugin<'data>,
        symbol_db: &mut SymbolDb<'data, Self>,
        resolver: &mut crate::resolution::Resolver<'data, Self>,
        file_loader: &mut crate::input_data::FileLoader<'data, F>,
        per_symbol_flags: &mut crate::value_flags::PerSymbolFlags,
        output_sections: &mut OutputSections<'data, Self>,
        layout_rules_builder: &mut crate::layout_rules::LayoutRulesBuilder<'data>,
    ) -> Result {
        plugin.all_symbols_read(
            symbol_db,
            resolver,
            file_loader,
            per_symbol_flags,
            output_sections,
            layout_rules_builder,
        )
    }

    fn resolve_lto_symbols<'data, 'scope>(
        obj: &crate::linker_plugins::LtoInput<'data>,
        resources: &'scope crate::resolution::ResolutionResources<'data, 'scope, Self>,
        definitions_out: &mut [SymbolId],
        scope: &Scope<'scope>,
    ) -> Result {
        crate::linker_plugins::resolve_lto_symbols(obj, resources, definitions_out, scope)
    }

    fn apply_force_keep_sections(keep_sections: &mut OutputSectionMap<bool>, args: &ElfArgs) {
        // Some of these sections aren't really empty, but we just haven't allocated space for them
        // yet. e.g. we don't allocate space for section headers until we know which sections we're
        // keeping, which by inherently needs to be after this method is called.
        const FORCE_KEEP_SECTIONS: &[OutputSectionId] = &[
            crate::output_section_id::FILE_HEADER,
            output_section_id::PROGRAM_HEADERS,
            output_section_id::SECTION_HEADERS,
            output_section_id::SHSTRTAB,
        ];

        for section_id in FORCE_KEEP_SECTIONS {
            *keep_sections.get_mut(*section_id) = true;
        }

        // Keep .relro_padding unless relro is disabled.
        if args.relro {
            *keep_sections.get_mut(output_section_id::RELRO_PADDING) = true;
        }
    }

    fn is_zero_sized_section_content(section_id: OutputSectionId) -> bool {
        // We always consider empty sections as content except for sframe sections.
        section_id != output_section_id::SFRAME
    }

    fn built_in_section_details() -> &'static [Self::BuiltInSectionDetails] {
        &Self::SECTION_DEFINITIONS
    }

    fn section_attributes(header: &Self::SectionHeader) -> Self::SectionAttributes {
        SectionAttributes {
            flags: header.sh_flags(LittleEndian),
            ty: header.sh_type(LittleEndian),
            entsize: header.sh_entsize(LittleEndian).into(),
            overrides: Default::default(),
            class: PhantomData,
        }
    }

    fn validate_sizes(mem_sizes: &OutputSectionPartMap<u64>) -> Result {
        if *mem_sizes.get(part_id::GNU_VERSION) > 0 {
            let num_dynamic_symbols = mem_sizes.get(part_id::DYNSYM) / C::SYMTAB_ENTRY_SIZE;
            let num_versym = mem_sizes.get(part_id::GNU_VERSION) / size_of::<Versym>() as u64;
            if num_versym != num_dynamic_symbols {
                bail!(
                    "Object has {num_dynamic_symbols} dynamic symbols, but \
                         has {num_versym} versym entries"
                );
            }
        }

        Ok(())
    }

    fn finalise_group_layout(memory_offsets: &OutputSectionPartMap<u64>) -> Self::GroupLayoutExt {
        GroupLayoutExt {
            eh_frame_start_address: *memory_offsets.get(part_id::EH_FRAME),
        }
    }

    fn frame_data_base_address(memory_offsets: &OutputSectionPartMap<u64>) -> u64 {
        // References to symbols defined in .eh_frame are a bit weird, since it's a section where
        // we're GCing stuff, but crtbegin.o and crtend.o use them in order to find the start and
        // end of the whole .eh_frame section.
        *memory_offsets.get(part_id::EH_FRAME)
    }

    fn finalise_find_required_sections<'data>(
        groups: &mut [layout::GroupState<Elf<C>>],
        symbol_db: &SymbolDb<'data, Elf<C>>,
    ) -> Result {
        tracing::debug!(target: "metrics", total = groups
            .iter()
            .map(|g| g.common.format_specific.exception_frame_count)
            .sum::<usize>(), "exception frames");

        tracing::debug!(target: "metrics", section = "`.eh_frame`", relocations = groups
            .iter()
            .map(|g| g.common.format_specific.exception_frame_relocations)
            .sum::<usize>(), "resolved relocations");

        if symbol_db.args.is_relr_enabled() {
            load_glibc_abi_dt_relr_version(groups, symbol_db)?;
        }

        Ok(())
    }

    fn activate_dynamic<'data>(
        state: &mut layout::DynamicLayoutState<'data, Self>,
        common: &mut CommonGroupState<'data, Self>,
    ) {
        common.allocate(part_id::DYNAMIC, C::DYNAMIC_ENTRY_SIZE);

        common.allocate(part_id::DYNSTR, state.lib_name.len() as u64 + 1);

        state.format_specific.symbol_versions_needed = vec![false; state.object.verdefnum as usize];
    }

    fn pre_finalise_sizes_prelude<'scope, 'data>(
        prelude: &mut layout::PreludeLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
        resources: &layout::GraphResources<'data, 'scope, Self>,
    ) {
        if resources
            .layout_resources_ext
            .uses_tlsld
            .load(atomic::Ordering::Relaxed)
        {
            // Allocate space for a TLS module number and offset for use with TLSLD relocations.
            common.allocate(part_id::GOT, C::GOT_ENTRY_SIZE * 2);
            prelude.format_specific.needs_tlsld_got_entry = true;
            // For shared objects, we'll need to use a DTPMOD relocation to fill in the TLS module
            // number.
            if !resources.symbol_db.output_kind.is_executable() {
                common.allocate(part_id::RELA_DYN_GENERAL, C::RELA_ENTRY_SIZE);
            }
        }
    }

    fn finalise_sizes_dynamic<'data>(
        object: &mut layout::DynamicLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
    ) -> Result {
        allocate_for_copy_relocations(object, common)
    }

    fn finalise_object_sizes<'data>(
        object: &mut layout::ObjectLayoutState<'data, Elf<C>>,
        common: &mut layout::CommonGroupState<'data, Elf<C>>,
    ) {
        // TODO: Deduplicate CIEs from different objects, then only allocate space for those CIEs
        // that we "won".
        for cie in &object.format_specific.cies {
            object.format_specific.eh_frame_size += cie.cie.bytes.len() as u64;
        }
        common.allocate(part_id::EH_FRAME, object.format_specific.eh_frame_size);
    }

    fn finalise_object_layout<'data>(
        object: &layout::ObjectLayoutState<'data, Elf<C>>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
    ) {
        memory_offsets.increment(part_id::EH_FRAME, object.format_specific.eh_frame_size);
    }

    fn file_thunk_config<'data>(file: &File<'data, C>) -> Option<ThunkConfig> {
        thunk_config_for_object(file)
    }

    fn finalise_layout_dynamic<'data>(
        state: &mut layout::DynamicLayoutState<'data, Self>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resources: &layout::FinaliseLayoutResources<'_, 'data, Self>,
        resolutions_out: &mut layout::ResolutionWriter<Self>,
    ) -> Result<Option<Self::DynamicLayoutExt<'data>>> {
        let mut is_last_verneed = false;

        if let Some(v) = &state.format_specific.verneed_info
            && v.version_count > 0
        {
            memory_offsets.increment(
                part_id::GNU_VERSION_R,
                size_of::<crate::elf::Verneed>() as u64
                    + u64::from(v.version_count) * size_of::<crate::elf::Vernaux>() as u64,
            );

            let version_r_layout = resources
                .section_layouts
                .get(output_section_id::GNU_VERSION_R);

            is_last_verneed = *memory_offsets.get(part_id::GNU_VERSION_R)
                == version_r_layout.mem_offset + version_r_layout.mem_size;
        }

        let version_mapping = compute_version_mapping(
            &state.format_specific.symbol_versions_needed,
            state.format_specific.non_addressable_indexes,
        );

        let copy_relocation_symbols = state
            .format_specific
            .copy_relocations
            .values()
            .map(|info| info.symbol_id)
            // We'll write the copy relocations in this order, so we need to sort it to ensure
            // deterministic output.
            .sorted()
            .collect_vec();

        let copy_relocation_addresses =
            assign_copy_relocation_addresses(state, &copy_relocation_symbols, memory_offsets)?;

        for (local_symbol, &flags) in state.object.symbols_iter().zip(
            resources
                .per_symbol_flags
                .raw_range(state.symbol_id_range()),
        ) {
            let flags = flags.get();

            if !flags.has_resolution() {
                resolutions_out.write(None)?;
                continue;
            }

            let address;
            let dynamic_symbol_index;

            if flags.needs_copy_relocation() {
                let input_address = local_symbol.value();

                address = *copy_relocation_addresses
                    .get(&input_address)
                    .context("Internal error: Missing copy relocation address")?;

                // Since this is a definition, the dynamic symbol index will be determined by the
                // epilogue and set by `update_dynamic_symbol_resolutions`.
                dynamic_symbol_index = None;
            } else {
                address = 0;
                let symbol_index =
                    Self::take_dynsym_index(memory_offsets, resources.section_layouts)?;

                dynamic_symbol_index = Some(
                    NonZeroU32::new(symbol_index)
                        .context("Tried to create dynamic symbol index 0")?,
                );
            }

            let resolution = Self::create_resolution(
                flags,
                address,
                dynamic_symbol_index,
                memory_offsets,
                resources.symbol_db.args,
                resources.symbol_db.output_kind,
            );

            resolutions_out.write(Some(resolution))?;
        }

        Ok(Some(DynamicLayoutExt {
            version_mapping,
            verneed_info: core::mem::take(&mut state.format_specific.verneed_info),
            is_last_verneed,
            copy_relocation_symbols,
        }))
    }

    fn compute_object_addresses<'data>(
        object: &layout::ObjectLayoutState<'data, Elf<C>>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
    ) {
        // Note, this is currently identical to finalise_object_layout above. The two functions are
        // however called separately and they might become different at some point.
        memory_offsets.increment(part_id::EH_FRAME, object.format_specific.eh_frame_size);
    }

    fn layout_resources_ext<'data>(
        groups: &[crate::grouping::Group<'data, Self>],
    ) -> LayoutResourcesExt<'data> {
        LayoutResourcesExt {
            sonames: Sonames::new(groups),
            uses_tlsld: AtomicBool::new(false),
        }
    }

    fn load_object_section_relocations<'data, 'scope, A: Arch<Platform = Self>>(
        state: &mut layout::ObjectLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
        queue: &mut layout::LocalWorkQueue,
        resources: &'scope layout::GraphResources<'data, '_, Self>,
        _section: layout::Section,
        section_index: object::SectionIndex,
        scope: &Scope<'scope>,
    ) -> Result {
        if resources.symbol_db.args.should_output_partial_object() {
            return Ok(());
        }
        match state.relocations(section_index)? {
            RelocationList::Rela(relocations) => {
                load_section_relocations::<C, A, ElfRela<C>>(
                    state,
                    common,
                    queue,
                    resources,
                    section_index,
                    RelaSequence(relocations).rel_iter(),
                    scope,
                )?;
            }
            RelocationList::Crel(relocations) => {
                load_section_relocations::<C, A, ElfCrel<C>>(
                    state,
                    common,
                    queue,
                    resources,
                    section_index,
                    relocations.filter_map(|r| {
                        r.ok().map(|raw| ElfCrel {
                            raw,
                            class: PhantomData,
                        })
                    }),
                    scope,
                )?;
            }
        }

        Ok(())
    }

    fn create_dynamic_symbol_definition<'data>(
        symbol_db: &SymbolDb<'data, Self>,
        symbol_id: SymbolId,
    ) -> Result<layout::DynamicSymbolDefinition<'data, Self>> {
        let symbol_name = symbol_db.symbol_name(symbol_id)?;
        let RawSymbolName {
            name,
            version_name,
            is_default,
        } = RawSymbolName::parse(symbol_name.bytes());

        let mut version = object::elf::VER_NDX_GLOBAL.into();
        if (symbol_db.version_script.version_count() > 0 || version_name.is_some())
            && let Some(v) = symbol_db
                .version_script
                .version_for_symbol(&UnversionedSymbolName::prehashed(name), version_name)?
        {
            version = v.versym(!is_default);
        }
        Ok(layout::DynamicSymbolDefinition {
            symbol_id,
            name,
            format_specific: DynamicSymbolDefinitionExt {
                hash: object::elf::gnu_hash(name),
                version,
            },
        })
    }

    fn validate_section<'data>(
        section_info: &SectionOutputInfo<Elf<C>>,
        section_flags: SectionFlags,
        section_layout: &OutputRecordLayout,
        merge_target: OutputSectionId,
        output_sections: &OutputSections<'data, Elf<C>>,
        section_id: OutputSectionId,
    ) -> Result {
        // TODO: Remove the NOTE exception. Non-alloc sections should be placed outside of program
        // segments. NOTE sections are sometimes alloc and sometimes not. Alloc NOTE sections should
        // be placed within a LOAD segment and within a NOTE segment. Non-alloc NOTE sections
        // shouldn't be in any segment.

        // The .riscv.attributes section is non-alloc but is expected to be put into a
        // RISCV_ATTRIBUTES segment.
        if [sht::NOTE, sht::RISCV_ATTRIBUTES].contains(&section_info.section_attributes.ty) {
        } else {
            // All segments should only cover sections that are allocated and have a non-zero
            // address.
            ensure!(
                section_layout.mem_offset != 0
                    || merge_target == crate::output_section_id::FILE_HEADER,
                "Missing memory offset for section {} present in a program segment.",
                output_sections.section_debug(section_id),
            );
            ensure!(
                section_flags.is_alloc(),
                "Missing SHF_ALLOC section flag for section {} present in a program \
                         segment.",
                output_sections.section_debug(section_id)
            );
        }

        Ok(())
    }

    fn verify_resolution_allocation<A: Arch<Platform = Self>>(
        output_sections: &OutputSections<Elf<C>>,
        output_order: &OutputOrder,
        output_kind: OutputKind,
        mem_sizes: &OutputSectionPartMap<u64>,
        resolution: &layout::Resolution<Elf<C>>,
        args: &ElfArgs,
    ) -> Result {
        crate::elf_writer::verify_resolution_allocation::<C, A>(
            output_sections,
            output_order,
            output_kind,
            mem_sizes,
            resolution,
            args,
        )
    }

    fn update_segment_keep_list(
        program_segments: &ProgramSegments<ProgramSegmentDef>,
        keep_segments: &mut [bool],
        args: &ElfArgs,
    ) {
        // If relro is disabled, then discard the relro segment.
        if !args.relro {
            for (segment_def, keep) in program_segments.into_iter().zip(keep_segments.iter_mut()) {
                if segment_def.segment_type == pt::GNU_RELRO {
                    *keep = false;
                }
            }
        }

        // The PHDR program header should only be present if --nmagic is not set
        for (segment_def, keep) in program_segments.into_iter().zip(keep_segments.iter_mut()) {
            if segment_def.segment_type == pt::PHDR {
                *keep = !args.nmagic;
            }
            if segment_def.segment_type == pt::RISCV_ATTRIBUTES
                && args.arch != Architecture::RiscV64
            {
                *keep = false;
            }
        }
    }

    fn program_segment_defs() -> &'static [ProgramSegmentDef] {
        PROGRAM_SEGMENT_DEFS
    }

    fn unconditional_segment_defs() -> &'static [ProgramSegmentDef] {
        &[STACK_SEGMENT_DEF]
    }

    fn program_segment_should_include_section(
        segment_def: ProgramSegmentDef,
        info: &SectionOutputInfo<Self>,
        section_id: OutputSectionId,
        rosegment: bool,
    ) -> bool {
        match segment_def.segment_type {
            pt::NOTE => info.section_attributes.ty == sht::NOTE,
            pt::TLS => info.section_attributes.flags.contains(shf::TLS),
            pt::LOAD => {
                let mut exec = info.section_attributes.flags.contains(shf::EXECINSTR);
                if !rosegment && !info.section_attributes.flags.contains(shf::WRITE) {
                    exec = true;
                }

                info.section_attributes.flags.contains(shf::ALLOC)
                    && info.section_attributes.flags.contains(shf::WRITE)
                        == segment_def.is_writable()
                    && exec == segment_def.is_executable()
            }
            pt::GNU_RELRO => {
                info.section_attributes.flags.contains(shf::TLS)
                    || section_id
                        .opt_built_in_details::<Self>()
                        .is_some_and(|details| details.is_relro)
            }
            other => section_id
                .opt_built_in_details::<Self>()
                .and_then(|details| details.target_segment_type)
                .is_some_and(|target_segment_type| target_segment_type == other),
        }
    }

    fn get_segment_flags_for_section(section_flags: &Self::SectionFlags) -> u32 {
        let mut flags = 0;
        if section_flags.contains(shf::ALLOC) {
            flags |= pf::READABLE.0;
        }
        if section_flags.contains(shf::WRITE) {
            flags |= pf::WRITABLE.0;
        }
        if section_flags.contains(shf::EXECINSTR) {
            flags |= pf::EXECUTABLE.0;
        }
        flags
    }

    fn create_linker_defined_symbols(
        symbols: &mut crate::parsing::InternalSymbolsBuilder<Elf<C>>,
        output_kind: OutputKind,
        args: &ElfArgs,
    ) {
        // The undefined symbol must always be symbol 0.
        symbols
            .add_symbol(InternalSymDefInfo::new(SymbolPlacement::Undefined, b""))
            .hide();

        symbols
            .section_start(crate::output_section_id::FILE_HEADER, "__ehdr_start")
            .hide();

        symbols.section_start(output_section_id::GOT, "_GLOBAL_OFFSET_TABLE_");

        // .rela.plt start/stop symbols are only emitted for non-relocatable executables. Emitting
        // them for relocatable binaries causes glibc to try to call the resolver functions without
        // taking into account that the binary has been relocated.
        if output_kind != OutputKind::StaticExecutable(RelocationModel::Relocatable) {
            symbols
                .section_start(output_section_id::RELA_PLT, "__rela_iplt_start")
                .hide();
            symbols
                .section_end(output_section_id::RELA_PLT, "__rela_iplt_end")
                .hide();
        }

        symbols
            .section_start(output_section_id::PREINIT_ARRAY, "__preinit_array_start")
            .hide();
        symbols
            .section_group_end(output_section_id::PREINIT_ARRAY, "__preinit_array_end")
            .hide();

        symbols
            .section_start(output_section_id::INIT_ARRAY, "__init_array_start")
            .hide();
        symbols
            .section_group_end(output_section_id::INIT_ARRAY, "__init_array_end")
            .hide();

        symbols
            .section_start(output_section_id::FINI_ARRAY, "__fini_array_start")
            .hide();
        symbols
            .section_group_end(output_section_id::FINI_ARRAY, "__fini_array_end")
            .hide();

        // GNU ld doesn't emit these symbols in shared libraries, so we hide them
        let hidden = output_kind.is_shared_object();
        symbols
            .section_end(output_section_id::TEXT, "etext")
            .set_hidden(hidden);
        symbols
            .section_end(output_section_id::TEXT, "_etext")
            .set_hidden(hidden);
        symbols
            .section_end(output_section_id::TEXT, "__etext")
            .set_hidden(hidden);

        symbols
            .section_start(output_section_id::BSS, "__bss_start")
            .set_hidden(hidden);

        symbols
            .section_end(output_section_id::BSS, "end")
            .set_hidden(hidden);
        symbols
            .section_end(output_section_id::BSS, "_end")
            .set_hidden(hidden);
        symbols.section_end(output_section_id::BSS, "__end").hide();

        if args.arch == Architecture::RiscV64 {
            symbols.section_start(
                output_section_id::DATA,
                crate::elf::GLOBAL_POINTER_SYMBOL_NAME,
            );
        }

        if args.arch == Architecture::Ppc64 {
            symbols.section_start(output_section_id::GOT, crate::elf::TOC_SYMBOL_NAME);
        }

        symbols
            .section_end(output_section_id::DATA, "edata")
            .set_hidden(hidden);
        symbols
            .section_end(output_section_id::DATA, "_edata")
            .set_hidden(hidden);

        symbols
            .section_start(output_section_id::TDATA, "__tdata_start")
            .hide();

        if output_kind != OutputKind::StaticExecutable(RelocationModel::NonRelocatable) {
            symbols.section_start(output_section_id::DYNAMIC, "_DYNAMIC");
        }

        symbols
            .add_symbol(InternalSymDefInfo::new(
                SymbolPlacement::LoadBaseAddress,
                b"__executable_start",
            ))
            .hide();

        // We define _TLS_MODULE_BASE_ either at the start or end of the TLS segment, depending on
        // whether we're building a shared object or an executable. This symbol is used for TLSDESC.
        // See https://www.fsfla.org/~lxoliva/writeups/TLS/RFC-TLSDESC-x86.txt for more details.
        let mut elf_symbol = SymtabEntry::<C>::default();
        elf_symbol.set_binding_and_type(object::elf::STB_GLOBAL, object::elf::STT_TLS);
        symbols.add_symbol(InternalSymDefInfo {
            placement: if output_kind == OutputKind::SharedObject {
                SymbolPlacement::SectionStart(output_section_id::TDATA)
            } else {
                SymbolPlacement::SectionEnd(output_section_id::TBSS)
            },
            name: b"_TLS_MODULE_BASE_",
            symbol: elf_symbol,
        });
    }

    fn built_in_section_infos<'data>()
    -> Vec<crate::output_section_id::SectionOutputInfo<'data, Elf<C>>> {
        Self::SECTION_DEFINITIONS
            .iter()
            .map(|d| SectionOutputInfo {
                section_attributes: SectionAttributes {
                    flags: d.section_flags,
                    ty: d.ty,
                    entsize: d.element_size,
                    overrides: Default::default(),
                    class: PhantomData,
                },
                kind: d.kind,
                min_alignment: d.min_alignment,
                location_info: None,
                secondary_order: None,
                region_name: None,
                fill: None,
                phdrs: Vec::new(),
            })
            .collect()
    }

    fn create_finalise_sizes_ext<'data, 'states, 'files, A: Arch<Platform = Self>>(
        args: &ElfArgs,
        groups: &'files [layout::GroupState<'data, Self>],
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) -> Result<LayoutExt>
    where
        'data: 'files,
        'data: 'states,
    {
        LayoutExt::new::<C, A>(groups, args)
    }

    fn create_layout_ext<'data>(
        finalise_sizes_ext: Self::FinaliseSizesExt<'data>,
        _resolutions: &layout::SymbolResolutions<Self>,
    ) -> Result<Self::LayoutExt<'data>> {
        Ok(finalise_sizes_ext)
    }

    fn load_exception_frame_data<'data, 'scope, A: Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Elf<C>>,
        common: &mut crate::layout::CommonGroupState<'data, Elf<C>>,
        eh_frame_section_index: object::SectionIndex,
        resources: &'scope crate::layout::GraphResources<'data, '_, Elf<C>>,
        queue: &mut crate::layout::LocalWorkQueue,
        scope: &rayon::Scope<'scope>,
    ) -> Result {
        object.format_specific.has_eh_frame_input = true;
        let eh_frame_section = object.object.section(eh_frame_section_index)?;
        let data = object.object.raw_section_data(eh_frame_section)?;
        let frame_index_offset = object.format_specific.exception_frames.len();
        let exception_frames = match object.relocations(eh_frame_section_index)? {
            RelocationList::Rela(relocations) => {
                ExceptionFrames::Rela(process_eh_frame_relocations::<C, A, ElfRela<C>>(
                    object,
                    common,
                    resources,
                    queue,
                    eh_frame_section,
                    eh_frame_section_index,
                    frame_index_offset,
                    data,
                    &RelaSequence(relocations),
                    scope,
                )?)
            }
            RelocationList::Crel(crel_iterator) => {
                ExceptionFrames::Crel(process_eh_frame_relocations::<C, A, ElfCrel<C>>(
                    object,
                    common,
                    resources,
                    queue,
                    eh_frame_section,
                    eh_frame_section_index,
                    frame_index_offset,
                    data,
                    &crel_iterator
                        .map(|raw| {
                            raw.map(|raw| ElfCrel {
                                raw,
                                class: PhantomData,
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    scope,
                )?)
            }
        };

        object
            .format_specific
            .exception_frames
            .extend(exception_frames);
        Ok(())
    }

    fn non_empty_section_loaded<'data, 'scope, A: Arch<Platform = Self>>(
        object: &mut layout::ObjectLayoutState<'data, Elf<C>>,
        common: &mut layout::CommonGroupState<'data, Elf<C>>,
        queue: &mut layout::LocalWorkQueue,
        unloaded: crate::resolution::UnloadedSection,
        resources: &'scope layout::GraphResources<'data, 'scope, Elf<C>>,
        scope: &Scope<'scope>,
    ) -> Result {
        let sizes = match &object.format_specific.exception_frames {
            ExceptionFrames::Rela(exception_frames) => {
                process_section_exception_frames::<C, A, ElfRela<C>>(
                    object,
                    unloaded.last_frame_index,
                    common,
                    resources,
                    queue,
                    scope,
                    exception_frames,
                )?
            }
            ExceptionFrames::Crel(exception_frames) => {
                process_section_exception_frames::<C, A, ElfCrel<C>>(
                    object,
                    unloaded.last_frame_index,
                    common,
                    resources,
                    queue,
                    scope,
                    exception_frames,
                )?
            }
        };

        object.format_specific.eh_frame_size += sizes.eh_frame_size;

        if resources.symbol_db.args.should_write_eh_frame_hdr {
            common.allocate(
                part_id::EH_FRAME_HDR,
                size_of::<EhFrameHdrEntry>() as u64 * sizes.num_frames,
            );
        }

        Ok(())
    }

    fn new_dynamic_layout_state_ext<'data>(
        _file: &crate::resolution::ResolvedDynamic<'data, Self>,
        _args: &Self::Args,
    ) -> Self::DynamicLayoutStateExt<'data> {
        Default::default()
    }

    fn new_epilogue_layout<'data>(
        args: &ElfArgs,
        output_kind: OutputKind,
        dynamic_symbol_definitions: &mut [DynamicSymbolDefinition<'data, Self>],
        _group_states: &[layout::GroupState<'data, Self>],
    ) -> EpilogueLayoutExt {
        let gnu_hash_layout = create_gnu_hash_layout(args, output_kind, dynamic_symbol_definitions);

        let build_id_size = match &args.build_id {
            BuildIdOption::None => None,
            BuildIdOption::Fast => Some(size_of::<blake3::Hash>()),
            BuildIdOption::Hex(hex) => Some(hex.len()),
            BuildIdOption::Uuid => Some(size_of::<uuid::Uuid>()),
        };

        EpilogueLayoutExt {
            sysv_hash_layout: Default::default(),
            gnu_hash_layout,
            verdefs: Default::default(),
            build_id_size,
            needs_eh_frame_terminator: false,
        }
    }

    fn apply_non_addressable_indexes_epilogue(
        counts: &mut NonAddressableCounts,
        state: &mut EpilogueLayoutExt,
    ) {
        counts.verdef_count += state
            .verdefs
            .as_ref()
            .map(|v| v.len() as u16)
            .unwrap_or_default();
    }

    fn apply_non_addressable_indexes<'data, 'groups>(
        symbol_db: &SymbolDb<'data, Self>,
        counts: &NonAddressableCounts,
        mem_sizes_iter: impl Iterator<Item = &'groups mut OutputSectionPartMap<u64>>,
    ) {
        // If we were going to output symbol versions, but we didn't actually use any, then we drop
        // all versym allocations. This is partly to avoid wasting unnecessary space in the output
        // file, but mostly in order match what GNU ld does.
        if (counts.verneed_count == 0 && counts.verdef_count == 0)
            && symbol_db.output_kind.should_output_symbol_versions()
        {
            for mem_sizes in mem_sizes_iter {
                *mem_sizes.get_mut(part_id::GNU_VERSION) = 0;
            }
        }
    }

    fn finalise_sizes_epilogue<'data>(
        state: &mut EpilogueLayoutExt,
        mem_sizes: &mut OutputSectionPartMap<u64>,
        dynamic_symbol_definitions: &[DynamicSymbolDefinition<'data, Self>],
        properties: &LayoutExt,
        symbol_db: &SymbolDb<'data, Self>,
    ) {
        if symbol_db.output_kind.needs_dynamic() {
            let dynamic_entry_size = C::DYNAMIC_ENTRY_SIZE as usize;
            mem_sizes.increment(
                part_id::DYNAMIC,
                (elf_writer::NUM_EPILOGUE_DYNAMIC_ENTRIES * dynamic_entry_size) as u64,
            );
            if let Some(rpath) = symbol_db.args.rpath.as_ref() {
                mem_sizes.increment(part_id::DYNAMIC, dynamic_entry_size as u64);
                mem_sizes.increment(part_id::DYNSTR, rpath.len() as u64 + 1);
            }
            if let Some(soname) = symbol_db.args.soname.as_ref() {
                mem_sizes.increment(part_id::DYNSTR, soname.len() as u64 + 1);
                mem_sizes.increment(part_id::DYNAMIC, dynamic_entry_size as u64);
            }
            for aux in &symbol_db.args.auxiliary {
                mem_sizes.increment(part_id::DYNSTR, aux.len() as u64 + 1);
                mem_sizes.increment(part_id::DYNAMIC, dynamic_entry_size as u64);
            }

            mem_sizes.increment(
                part_id::DYNSTR,
                dynamic_symbol_definitions
                    .iter()
                    .map(|n| n.name.len() + 1)
                    .sum::<usize>() as u64,
            );
            mem_sizes.increment(
                part_id::DYNSYM,
                dynamic_symbol_definitions.len() as u64 * C::SYMTAB_ENTRY_SIZE,
            );
        }

        if let Some(build_id_sec_size) = state.gnu_build_id_note_section_size::<C>() {
            mem_sizes.increment(part_id::NOTE_GNU_BUILD_ID, build_id_sec_size);
        }

        mem_sizes.increment(
            part_id::NOTE_GNU_PROPERTY,
            gnu_property_notes_section_size::<C>(&properties.gnu_property_notes),
        );

        mem_sizes.increment(
            part_id::RISCV_ATTRIBUTES,
            properties.riscv_attributes.section_size,
        );

        if let Some(gnu_hash_layout) = state.gnu_hash_layout {
            gnu_hash_layout.allocate::<C>(mem_sizes);
        }

        let version_count = symbol_db.version_script.version_count();
        if version_count > 0 {
            // If soname is not provided, allocate space for file name as the base version
            let base_version_name = if symbol_db.args.soname.is_none() {
                let file_name = symbol_db
                    .args
                    .common
                    .output
                    .file_name()
                    .expect("File name should be present at this point")
                    .to_string_lossy()
                    .to_string();
                mem_sizes.increment(part_id::DYNSTR, file_name.len() as u64 + 1);
                file_name
            } else {
                String::new()
            };

            let mut verdefs = Vec::with_capacity(version_count.into());

            // Base version
            verdefs.push(VersionDef {
                name: base_version_name.into_bytes(),
                parent_index: None,
            });

            match &symbol_db.version_script {
                VersionScript::Regular(version_script) => {
                    // Take all but the base version
                    for version in version_script.version_iter().skip(1) {
                        verdefs.push(VersionDef {
                            name: version.name.to_vec(),
                            parent_index: version.parent_index,
                        });
                        mem_sizes.increment(part_id::DYNSTR, version.name.len() as u64 + 1);
                    }
                }
                VersionScript::Rust(_) => {}
            }

            let dependencies_count = symbol_db.version_script.parent_count();
            mem_sizes.increment(
                part_id::GNU_VERSION_D,
                (size_of::<crate::elf::Verdef>() as u16 * version_count
                    + size_of::<crate::elf::Verdaux>() as u16
                        * (version_count + dependencies_count))
                    .into(),
            );
            state.verdefs.replace(verdefs);
        }
    }

    fn finalise_layout_epilogue<'data>(
        epilogue_state: &mut EpilogueLayoutExt,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<'data, Self>,
        common_state: &LayoutExt,
        dynsym_start_index: u32,
        dynamic_symbol_defs: &[DynamicSymbolDefinition<Self>],
    ) -> Result {
        memory_offsets.increment(
            part_id::DYNSYM,
            dynamic_symbol_defs.len() as u64 * C::SYMTAB_ENTRY_SIZE,
        );

        if epilogue_state.needs_eh_frame_terminator {
            memory_offsets.increment(part_id::EH_FRAME, size_of::<u32>() as u64);
        }

        if let Some(build_id_sec_size) = epilogue_state.gnu_build_id_note_section_size::<C>() {
            memory_offsets.increment(part_id::NOTE_GNU_BUILD_ID, build_id_sec_size);
        }

        if let Some(gnu_hash_layout) = epilogue_state.gnu_hash_layout.as_mut() {
            gnu_hash_layout.symbol_base = dynsym_start_index;
        }

        memory_offsets.increment(
            part_id::NOTE_GNU_PROPERTY,
            crate::elf::gnu_property_notes_section_size::<C>(&common_state.gnu_property_notes),
        );

        memory_offsets.increment(
            part_id::RISCV_ATTRIBUTES,
            common_state.riscv_attributes.section_size,
        );

        if let Some(sysv_hash_layout) = epilogue_state.sysv_hash_layout.as_mut() {
            let additional = dynamic_symbol_defs.len() as u32;
            sysv_hash_layout.chain_count = dynsym_start_index
                .checked_add(additional)
                .context("Too many dynamic symbols for .hash")?;
        }

        if let Some(sysv_hash_layout) = &epilogue_state.sysv_hash_layout {
            memory_offsets.increment(part_id::SYSV_HASH, sysv_hash_layout.byte_size()?);
        }

        if let Some(verdefs) = &epilogue_state.verdefs {
            memory_offsets.increment(
                part_id::GNU_VERSION_D,
                (size_of::<crate::elf::Verdef>() * verdefs.len()
                    + size_of::<crate::elf::Verdaux>()
                        * (verdefs.len() + symbol_db.version_script.parent_count() as usize))
                    as u64,
            );
        }

        Ok(())
    }

    fn apply_late_size_adjustments_epilogue(
        state: &mut crate::elf::EpilogueLayoutExt,
        current_sizes: &OutputSectionPartMap<u64>,
        extra_sizes: &mut OutputSectionPartMap<u64>,
        dynamic_symbol_defs: &[DynamicSymbolDefinition<Self>],
        format_specific: &Self::FinaliseSizesExt<'_>,
        args: &ElfArgs,
    ) -> Result {
        if format_specific.has_eh_frame_input || *current_sizes.get(part_id::EH_FRAME) != 0 {
            extra_sizes.increment(part_id::EH_FRAME, size_of::<u32>() as u64);
            state.needs_eh_frame_terminator = true;
        }

        if args.hash_style.includes_sysv() {
            allocate_sysv_hash(state, current_sizes, extra_sizes, dynamic_symbol_defs)?;
        }
        if args.is_relr_enabled() {
            let got_relr_size = *current_sizes.get(part_id::GOT_RELR);
            let n = got_relr_size / C::GOT_ENTRY_SIZE;
            let relr_entries = got_relr_bitmap_relr_count::<C>(n);
            if relr_entries > 0 {
                extra_sizes.increment(part_id::RELR_DYN, relr_entries * C::RELR_ENTRY_SIZE);
            }
        }
        Ok(())
    }

    fn apply_late_size_adjustments_prelude(
        current_sizes: &OutputSectionPartMap<u64>,
        extra_sizes: &mut OutputSectionPartMap<u64>,
        args: &ElfArgs,
    ) -> Result {
        if args.should_write_eh_frame_hdr && *current_sizes.get(part_id::EH_FRAME_HDR) != 0 {
            extra_sizes.increment(part_id::EH_FRAME_HDR, size_of::<EhFrameHdr>() as u64);
        }
        Ok(())
    }

    fn finalise_sizes_all<'data>(
        mem_sizes: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<'data, Self>,
    ) {
        finalise_gnu_version_size(mem_sizes, symbol_db);
    }

    fn is_symbol_non_interposable<'data>(
        object: &Self::File<'data>,
        args: &Self::Args,
        sym: &Self::SymtabEntry,
        output_kind: OutputKind,
        export_list: Option<&crate::export_list::ExportList>,
        lib_name: &[u8],
        archive_semantics: bool,
        is_undefined: bool,
    ) -> bool {
        let symbol_is_exported = || {
            if let Some(export_list) = &export_list
                && let Ok(symbol_name) = object.symbol_name(sym)
                && !&export_list.contains(&UnversionedSymbolName::prehashed(symbol_name))
            {
                return false;
            }
            true
        };

        !sym.is_interposable()
            || sym.is_local()
            || output_kind.is_static_executable()
            // Symbols defined in an executable cannot be interposed since the executable is always the
            // first place checked for a symbol by the dynamic loader.
            || (!is_undefined && (
                output_kind.is_executable()
                || (archive_semantics && !args.should_export_dynamic(lib_name))
                || (
                    args.b_symbolic == BSymbolicKind::All
                    // `-Bsymbolic-functions`
                    || (
                        args.b_symbolic == BSymbolicKind::Functions
                        && sym.is_func()
                    )
                    // `-Bsymbolic-non-weak`
                    || (
                        args.b_symbolic == BSymbolicKind::NonWeak
                        && !sym.is_weak()
                    )
                    // `-Bsymbolic-non-weak-functions`
                    || (
                        args.b_symbolic == BSymbolicKind::NonWeakFunctions
                        && (sym.is_func()
                        && !sym.is_weak())
                    )
                )
                // Bsymbolic does not affect symbols that are exported
                && !(export_list.is_some() && symbol_is_exported())
            ))
    }

    fn validate_stack_section(
        input_section: &Self::SectionHeader,
        object: &impl std::fmt::Display,
        args: &Self::Args,
    ) -> Result {
        // If the .note.GNU-stack section has SHF_EXECINSTR, the input file is requesting an
        // executable stack.
        if input_section.is_executable() && !args.execstack {
            bail!("{object}: requires executable stack, but -z execstack is not specified");
        }
        Ok(())
    }

    fn finalise_sizes_for_symbol<'data>(
        common: &mut CommonGroupState<'data, Self>,
        symbol_db: &SymbolDb<'data, Self>,
        symbol_id: SymbolId,
        flags: ValueFlags,
    ) -> Result {
        if flags.is_dynamic() && flags.has_resolution() {
            let name = symbol_db.symbol_name(symbol_id)?;
            let name = Self::RawSymbolName::parse(name.bytes()).name();

            if flags.needs_copy_relocation() {
                // The dynamic symbol is a definition, so is handled by the epilogue. We only
                // need to deal with the symtab entry here.
                common.allocate(part_id::SYMTAB_GLOBAL, C::SYMTAB_ENTRY_SIZE);
                common.allocate(part_id::STRTAB, name.len() as u64 + 1);
            } else {
                common.allocate(part_id::DYNSTR, name.len() as u64 + 1);
                common.allocate(part_id::DYNSYM, C::SYMTAB_ENTRY_SIZE);
            }
        }

        if symbol_db.args.should_emit_got_plt_syms() && flags.needs_got() {
            let name = symbol_db.symbol_name(symbol_id)?;
            let name = Self::RawSymbolName::parse(name.bytes()).name();
            let name_len = name.len() + 4; // "$got" or "$plt" suffix

            let entry_size = C::SYMTAB_ENTRY_SIZE;
            common.allocate(part_id::SYMTAB_LOCAL, entry_size);
            common.allocate(part_id::STRTAB, name_len as u64 + 1);

            if flags.needs_plt() {
                common.allocate(part_id::SYMTAB_LOCAL, entry_size);
                common.allocate(part_id::STRTAB, name_len as u64 + 1);
            }
        }

        Ok(())
    }

    fn allocate_resolution(
        flags: ValueFlags,
        mem_sizes: &mut OutputSectionPartMap<u64>,
        output_kind: OutputKind,
        args: &Self::Args,
    ) {
        let has_dynamic_symbol =
            flags.is_dynamic() || (flags.needs_export_dynamic() && flags.is_interposable());

        if flags.needs_got() && !flags.is_tls() {
            let is_got_relr = is_got_relr_eligible(flags, has_dynamic_symbol, args, output_kind);
            if is_got_relr {
                mem_sizes.increment(part_id::GOT_RELR, C::GOT_ENTRY_SIZE);
            } else {
                mem_sizes.increment(part_id::GOT, C::GOT_ENTRY_SIZE);
            }
            if flags.needs_plt() {
                mem_sizes.increment(part_id::PLT_GOT, elf::PLT_ENTRY_SIZE);
            }
            if flags.is_ifunc() {
                mem_sizes.increment(part_id::RELA_PLT, C::RELA_ENTRY_SIZE);
            } else if has_dynamic_symbol {
                mem_sizes.increment(part_id::RELA_DYN_GENERAL, C::RELA_ENTRY_SIZE);
            } else if flags.is_address() && output_kind.is_relocatable() {
                if args.is_relr_enabled() && !is_got_relr {
                    // Flat RELR for section boundary symbols (not bitmap-packed)
                    mem_sizes.increment(part_id::RELR_DYN, C::RELR_ENTRY_SIZE);
                } else if !args.is_relr_enabled() {
                    mem_sizes.increment(part_id::RELA_DYN_RELATIVE, C::RELA_ENTRY_SIZE);
                }
                // is_got_relr=true: RELR entries counted by post_compute_sizes
            }
        }

        if flags.needs_ifunc_got_for_address() {
            mem_sizes.increment(part_id::GOT, C::GOT_ENTRY_SIZE);
            if output_kind.is_relocatable() {
                if args.is_relr_enabled() {
                    mem_sizes.increment(part_id::RELR_DYN, C::RELR_ENTRY_SIZE);
                } else {
                    mem_sizes.increment(part_id::RELA_DYN_RELATIVE, C::RELA_ENTRY_SIZE);
                }
            }
        }

        if flags.needs_got_tls_offset() {
            mem_sizes.increment(part_id::GOT, C::GOT_ENTRY_SIZE);
            if flags.is_interposable() || output_kind.is_shared_object() {
                mem_sizes.increment(part_id::RELA_DYN_GENERAL, C::RELA_ENTRY_SIZE);
            }
        }

        if flags.needs_got_tls_module() {
            mem_sizes.increment(part_id::GOT, C::GOT_ENTRY_SIZE * 2);
            // For executables, the TLS module ID is known at link time. For shared objects, we need
            // a runtime relocation to fill it in.
            if !output_kind.is_executable() || flags.is_dynamic() {
                mem_sizes.increment(part_id::RELA_DYN_GENERAL, C::RELA_ENTRY_SIZE);
            }
            if has_dynamic_symbol {
                mem_sizes.increment(part_id::RELA_DYN_GENERAL, C::RELA_ENTRY_SIZE);
            }
        }

        if flags.needs_got_tls_descriptor() {
            mem_sizes.increment(part_id::GOT, C::GOT_ENTRY_SIZE * 2);
            mem_sizes.increment(part_id::RELA_DYN_GENERAL, C::RELA_ENTRY_SIZE);
        }
    }

    fn allocate_object_symtab_space<'data>(
        state: &ObjectLayoutState<'data, Elf<C>>,
        common: &mut CommonGroupState<'data, Elf<C>>,
        symbol_db: &SymbolDb<'data, Elf<C>>,
        per_symbol_flags: &AtomicPerSymbolFlags,
    ) -> Result {
        let mut num_locals = 0;
        let mut num_globals = 0;
        let mut strings_size = 0;
        for ((sym_index, sym), flags) in state
            .object
            .enumerate_symbols()
            .zip(per_symbol_flags.range(state.symbol_id_range()))
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
                // If we've decided to emit the symbol even though it's not referenced (because it's
                // in a section we're emitting), then make sure we have a resolution for it.
                flags.fetch_or(ValueFlags::DIRECT);
                if flags.get().is_symtab_local(sym) {
                    num_locals += 1;
                } else {
                    num_globals += 1;
                }
                strings_size += symtab_name_for_strtab(info.name).len() + 1;
            } else if symbol_db.args.should_output_partial_object
                && sym.is_undefined()
                && symbol_db.is_canonical(symbol_id)
                && let Ok(name) = state.object.symbol_name(sym)
                && !name.is_empty()
            {
                num_globals += 1;
                strings_size += symtab_name_for_strtab(name).len() + 1;
            }
        }
        let entry_size = C::SYMTAB_ENTRY_SIZE;
        common.allocate(part_id::SYMTAB_LOCAL, num_locals * entry_size);
        common.allocate(part_id::SYMTAB_GLOBAL, num_globals * entry_size);
        common.allocate(part_id::STRTAB, strings_size as u64);
        Ok(())
    }

    fn allocate_internal_symbol(
        symbol_id: SymbolId,
        def_info: &InternalSymDefInfo<Elf<C>>,
        sizes: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<Self>,
    ) -> Result {
        // PROVIDE_HIDDEN symbols are local, others are global
        let symtab_part = if def_info.symbol.is_hidden() {
            part_id::SYMTAB_LOCAL
        } else {
            part_id::SYMTAB_GLOBAL
        };
        sizes.increment(symtab_part, C::SYMTAB_ENTRY_SIZE);
        let symbol_name = symbol_db.symbol_name(symbol_id)?;
        let symbol_name = symtab_name_for_strtab(symbol_name.bytes());
        sizes.increment(part_id::STRTAB, symbol_name.len() as u64 + 1);

        Ok(())
    }

    fn allocate_thunk_symbol_sizes(
        sizes: &mut OutputSectionPartMap<u64>,
        symbols: &[SymbolId],
        symbol_db: &SymbolDb<Self>,
    ) {
        let total_name_bytes: usize = symbols
            .iter()
            .map(|&sym_id| {
                let name_len = symbol_db.symbol_name(sym_id).map_or(0, |n| n.bytes().len());
                elf::THUNK_SYMBOL_PREFIX.len() + name_len + 1
            })
            .sum();
        sizes.increment(
            part_id::SYMTAB_LOCAL,
            symbols.len() as u64 * C::SYMTAB_ENTRY_SIZE,
        );
        sizes.increment(part_id::STRTAB, total_name_bytes as u64);
    }

    fn allocate_prelude(common: &mut CommonGroupState<Self>, symbol_db: &SymbolDb<Self>) {
        // The first entry in the symbol table must be null. Similarly, the first string in the
        // strings table must be empty.
        if !symbol_db.args.should_strip_all() {
            common.allocate(part_id::SYMTAB_LOCAL, C::SYMTAB_ENTRY_SIZE);
            common.allocate(part_id::STRTAB, 1);
        }

        if symbol_db.output_kind.needs_dynsym() {
            // Allocate space for the null symbol.
            common.allocate(part_id::DYNSTR, 1);
            common.allocate(part_id::DYNSYM, C::SYMTAB_ENTRY_SIZE);
        }
    }

    fn finalise_prelude_layout<'data>(
        prelude: &layout::PreludeLayoutState<Self>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resources: &layout::FinaliseLayoutResources<'_, 'data, Elf<C>>,
    ) -> Result<Self::PreludeLayoutExt> {
        // Take the null symbol's index.
        if resources.symbol_db.output_kind.needs_dynsym() {
            Self::take_dynsym_index(memory_offsets, resources.section_layouts)?;
        }

        let tlsld_got_entry = prelude.format_specific.needs_tlsld_got_entry.then(|| {
            let address = NonZeroU64::new(*memory_offsets.get(part_id::GOT))
                .expect("GOT address must never be zero");
            memory_offsets.increment(part_id::GOT, C::GOT_ENTRY_SIZE * 2);
            address
        });

        Ok(PreludeLayoutExt { tlsld_got_entry })
    }

    #[inline(always)]
    fn create_resolution(
        flags: ValueFlags,
        raw_value: u64,
        dynamic_symbol_index: Option<NonZeroU32>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        args: &<Elf<C> as Platform>::Args,
        output_kind: OutputKind,
    ) -> Resolution<Elf<C>> {
        let mut resolution: Resolution<Elf<C>> = Resolution {
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
            resolution.format_specific.plt_address = Some(plt_address);
            if flags.is_dynamic() {
                resolution.raw_value = plt_address.get();
            }
            // For ifunc with address equality needs, allocate 2 GOT entries
            // - First entry: Used by PLT
            // - Second entry: Used by GOT-relative references
            let num_got_entries = if flags.needs_ifunc_got_for_address() {
                2
            } else {
                1
            };
            let has_dynamic_symbol =
                flags.is_dynamic() || (flags.needs_export_dynamic() && flags.is_interposable());
            let is_got_relr = is_got_relr_eligible(flags, has_dynamic_symbol, args, output_kind);
            resolution.format_specific.got_address = if is_got_relr && num_got_entries == 1 {
                Some(allocate_got_relr::<C>(memory_offsets))
            } else {
                Some(allocate_got::<C>(num_got_entries, memory_offsets))
            };
        } else if flags.is_tls() {
            // Handle the TLS GOT addresses where we can combine up to 3 different access methods.
            let mut num_got_slots = 0;
            if flags.needs_got_tls_offset() {
                num_got_slots += 1;
            }
            if flags.needs_got_tls_module() {
                num_got_slots += 2;
            }
            if flags.needs_got_tls_descriptor() {
                num_got_slots += 2;
            }
            debug_assert!(num_got_slots > 0);
            resolution.format_specific.got_address =
                Some(allocate_got::<C>(num_got_slots, memory_offsets));
        } else if flags.needs_got() {
            let has_dynamic_symbol =
                flags.is_dynamic() || (flags.needs_export_dynamic() && flags.is_interposable());
            let is_got_relr = is_got_relr_eligible(flags, has_dynamic_symbol, args, output_kind);
            resolution.format_specific.got_address = if is_got_relr {
                Some(allocate_got_relr::<C>(memory_offsets))
            } else {
                Some(allocate_got::<C>(1, memory_offsets))
            };
        }

        resolution
    }

    fn validate_resolution(
        name: &[u8],
        resolution: &crate::layout::Resolution<Elf<C>>,
        got: &SectionHeader<C>,
        got_data: &[u8],
    ) -> Result {
        let flags = resolution.flags;
        if flags.is_ifunc()
            || flags.needs_got_tls_module()
            || flags.needs_got_tls_offset()
            || flags.needs_got_tls_descriptor()
        {
            return Ok(());
        }
        if let Some(got_address) = resolution.format_specific.got_address {
            let start_offset =
                (got_address.get() - Into::<u64>::into(got.sh_addr(LittleEndian))) as usize;
            let end_offset = start_offset + C::GOT_ENTRY_SIZE as usize;
            if end_offset > got_data.len() {
                bail!("GOT offset beyond end of GOT 0x{end_offset}");
            }
            if resolution.flags.is_dynamic() || resolution.flags.is_ifunc() {
                return Ok(());
            }
            let expected = resolution.raw_value;
            let address = Word::<C>::from_le_bytes(&got_data[start_offset..end_offset]).into();
            if expected != address {
                let name = String::from_utf8_lossy(name);
                bail!(
                    "flags={flags:?} `{name}` has address 0x{expected:x}, but GOT \
                 (at 0x{got_address:x}) points to 0x{address:x}"
                );
            }
        }
        Ok(())
    }

    fn raw_symbol_name<'data>(
        name_bytes: &'data [u8],
        verneed_table: &Self::VerneedTable<'data>,
        symbol_index: object::SymbolIndex,
    ) -> Self::RawSymbolName<'data> {
        if let Some(version_name) = verneed_table.version_name(symbol_index) {
            RawSymbolName {
                name: name_bytes,
                version_name: Some(version_name),
                is_default: false,
            }
        } else {
            RawSymbolName::parse(name_bytes)
        }
    }

    fn default_layout_rules(args: &Self::Args) -> Vec<SectionRule<'static>> {
        let sframe_outcome = if args.discard_sframe {
            SectionRuleOutcome::Discard
        } else {
            SectionRuleOutcome::Section(crate::layout_rules::SectionOutputInfo::keep(
                output_section_id::SFRAME,
            ))
        };

        let mut rules = Vec::with_capacity(
            DEFAULT_SECTION_PLACEMENT_RULES.len() + LINKER_MANAGED_SECTION_RULES.len() + 1,
        );

        if args.gdb_index {
            rules.push(SectionRule::exact(
                secnames::DEBUG_GNU_PUBNAMES,
                SectionRuleOutcome::DebugIndex,
            ));
            rules.push(SectionRule::exact(
                secnames::DEBUG_GNU_PUBTYPES,
                SectionRuleOutcome::DebugIndex,
            ));
        }

        rules.extend(DEFAULT_SECTION_PLACEMENT_RULES.iter().cloned());
        rules.extend(LINKER_MANAGED_SECTION_RULES.iter().cloned());

        rules.push(SectionRule::exact(
            secnames::SFRAME_SECTION_NAME,
            sframe_outcome,
        ));

        rules
    }

    fn linker_script_rules_pre_build(rule_builder: &mut crate::layout_rules::LayoutRulesBuilder) {
        // Even when we have a linker script, we still need to map .comment to .comment. It's a
        // special section because both input objects and the linker write to it. At least for
        // linkers that put their version in the .comment section. GNU ld doesn't, but LLD does and
        // still does so even when a linker script supposedly suppresses built-in rules.
        rule_builder.add_section_rule(SectionRule::exact_section_keep(
            secnames::COMMENT_SECTION_NAME,
            output_section_id::COMMENT,
        ));
        for rule in LINKER_MANAGED_SECTION_RULES {
            rule_builder.add_section_rule(rule.clone());
        }
    }

    fn init_section_priority(name: &[u8]) -> Option<u16> {
        init_fini_priority(name)
    }

    fn verify_allowed_input_section_name(name: &[u8]) -> Result {
        if name.starts_with(secnames::GNU_LTO_SYMTAB_PREFIX.as_bytes()) {
            if cfg!(all(feature = "plugins", unix)) {
                bail!("Found GCC LTO input that we didn't supply to linker plugin");
            }
            return Err(crate::symbol_db::linker_plugin_disabled_error());
        }

        Ok(())
    }

    fn allocate_header_sizes<'data>(
        prelude: &mut layout::PreludeLayoutState<'data, Self>,
        sizes: &mut OutputSectionPartMap<u64>,
        header_info: &layout::HeaderInfo,
        output_sections: &OutputSections<Self>,
        _resources: &layout::FinaliseSizesResources<'data, '_, Self>,
        _args: &Self::Args,
    ) {
        sizes.increment(crate::part_id::FILE_HEADER, u64::from(C::FILE_HEADER_SIZE));
        sizes.increment(
            part_id::PROGRAM_HEADERS,
            program_headers_size::<C>(header_info),
        );
        sizes.increment(
            part_id::SECTION_HEADERS,
            section_headers_size::<C>(header_info),
        );
        prelude.format_specific.shstrtab_size = output_sections
            .ids_with_info()
            .filter(|(id, _info)| output_sections.output_index_of_section(*id).is_some())
            .map(|(_id, info)| {
                if let SectionKind::Primary(identity) = info.kind {
                    identity.section_name().len() as u64 + 1
                } else {
                    0
                }
            })
            .sum::<u64>();
        sizes.increment(part_id::SHSTRTAB, prelude.format_specific.shstrtab_size);
    }

    fn copy_relocate_symbol<'scope, 'data>(
        state: &mut layout::DynamicLayoutState<Elf<C>>,
        symbol_id: SymbolId,
        resources: &layout::GraphResources<'data, 'scope, Elf<C>>,
    ) -> Result {
        let symbol = state
            .object
            .symbol(state.symbol_id_range().id_to_input(symbol_id))?;

        // Note, we're a shared object, so this is the address relative to the load address of the
        // shared object, not an offset within a section like with regular input objects. That means
        // that we don't need to take the section into account.
        let address = symbol.value();

        let info = state
            .format_specific
            .copy_relocations
            .entry(address)
            .or_insert_with(|| CopyRelocationInfo {
                symbol_id,
                is_weak: symbol.is_weak(),
            });

        info.add_symbol(symbol_id, symbol.is_weak(), resources);

        Ok(())
    }

    fn finalise_copy_relocations<'data>(
        group_states: &mut [layout::GroupState<'data, Self>],
        symbol_db: &SymbolDb<'data, Self>,
        symbol_flags: &AtomicPerSymbolFlags,
    ) -> Result {
        finalise_copy_relocations(group_states, symbol_db, symbol_flags)
    }

    fn take_dynsym_index(
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
    ) -> Result<u32> {
        let index = u32::try_from(
            (memory_offsets.get(part_id::DYNSYM)
                - section_layouts.get(output_section_id::DYNSYM).mem_offset)
                / C::SYMTAB_ENTRY_SIZE,
        )
        .context("Too many dynamic symbols")?;
        memory_offsets.increment(part_id::DYNSYM, C::SYMTAB_ENTRY_SIZE);
        Ok(index)
    }

    fn build_output_order_and_program_segments<'data>(
        custom: &CustomSectionIds,
        output_kind: OutputKind,
        output_sections: &OutputSections<'data, Self>,
        secondary: &OutputSectionMap<Vec<OutputSectionId>>,
        location_counters: &[crate::layout_rules::LocationCounter<'data>],
    ) -> (OutputOrder<'data>, ProgramSegments<Self::ProgramSegmentDef>) {
        let mut builder = OutputOrderBuilder::<Self>::new(
            output_kind,
            output_sections,
            secondary,
            false,
            location_counters,
        );

        builder.add_section(crate::output_section_id::FILE_HEADER);
        builder.add_section(output_section_id::PROGRAM_HEADERS);
        builder.add_section(output_section_id::SECTION_HEADERS);
        builder.add_section(output_section_id::NOTE_GNU_PROPERTY);
        builder.add_section(output_section_id::NOTE_GNU_BUILD_ID);
        builder.add_section(output_section_id::INTERP);
        builder.add_section(output_section_id::NOTE_ABI_TAG);
        builder.add_section(output_section_id::HASH);
        builder.add_section(output_section_id::GNU_HASH);
        builder.add_section(output_section_id::DYNSYM);
        builder.add_section(output_section_id::DYNSTR);
        builder.add_section(output_section_id::GNU_VERSION);
        builder.add_section(output_section_id::GNU_VERSION_D);
        builder.add_section(output_section_id::GNU_VERSION_R);
        builder.add_section(output_section_id::RELA_DYN_RELATIVE);
        builder.add_section(output_section_id::RELR_DYN);
        builder.add_section(output_section_id::RELA_PLT);
        builder.add_section(output_section_id::RODATA);
        builder.add_section(output_section_id::EH_FRAME_HDR);
        builder.add_section(output_section_id::EH_FRAME);
        builder.add_section(output_section_id::SFRAME);
        builder.add_section(output_section_id::GCC_EXCEPT_TABLE);
        builder.add_sections(&custom.ro);

        builder.add_section(output_section_id::PLT_GOT);
        builder.add_section(output_section_id::INIT);
        builder.add_section(output_section_id::FINI);
        builder.add_sections(&custom.exec);
        // We want ThunkConfig::primary_function_part_id to be more or less last, since we only
        // support generating thunks before the primary_function_part, not after.
        builder.add_section(output_section_id::TEXT);

        builder.add_section(output_section_id::TDATA);
        builder.add_sections(&custom.tdata);
        builder.add_section(output_section_id::TBSS);
        builder.add_sections(&custom.tbss);
        builder.add_section(output_section_id::INIT_ARRAY);
        builder.add_section(output_section_id::FINI_ARRAY);
        builder.add_section(output_section_id::PREINIT_ARRAY);
        builder.add_section(output_section_id::DATA_REL_RO);
        builder.add_section(output_section_id::DYNAMIC);
        builder.add_section(output_section_id::GOT);
        builder.add_section(output_section_id::RELRO_PADDING);
        builder.add_section(output_section_id::DATA);
        builder.add_sections(&custom.data);
        builder.add_section(output_section_id::BSS);
        builder.add_sections(&custom.bss);

        builder.add_sections(&custom.nonalloc);
        builder.add_section(output_section_id::GDB_INDEX);
        builder.add_section(output_section_id::COMMENT);
        builder.add_section(output_section_id::RISCV_ATTRIBUTES);
        builder.add_section(output_section_id::SHSTRTAB);
        builder.add_section(output_section_id::SYMTAB_LOCAL);
        builder.add_section(output_section_id::SYMTAB_SHNDX_LOCAL);
        builder.add_section(output_section_id::STRTAB);

        builder.build()
    }

    fn build_custom_output_order_and_program_segments<'data>(
        custom: &CustomSectionIds,
        output_kind: OutputKind,
        output_sections: &OutputSections<'data, Self>,
        secondary: &OutputSectionMap<Vec<OutputSectionId>>,
        linker_scripts: &[&SequencedLinkerScript<'data, Self>],
        location_counters: &[crate::layout_rules::LocationCounter<'data>],
    ) -> Result<(OutputOrder<'data>, ProgramSegments<Self::ProgramSegmentDef>)> {
        let mut builder = OutputOrderBuilder::<Self>::new(
            output_kind,
            output_sections,
            secondary,
            true,
            location_counters,
        );

        let mut segments_map = HashMap::new();
        let mut ordered_sections = Vec::new();
        let mut segment_entries = Vec::new();

        let mut num_phdrs = 0;
        let mut has_filehdr = false;
        let mut load_without_hdrs = false;

        for script in linker_scripts {
            num_phdrs += script.parsed.program_headers.len();
            for phdr in &script.parsed.program_headers {
                let ptype = expression_eval::evaluate_const(&phdr.ptype)? as u32;
                if ptype == pt::LOAD.0 {
                    if phdr.has_filehdr || phdr.has_phdrs {
                        if load_without_hdrs {
                            bail!(
                                "PHDRS and FILEHDR are not supported when prior PT_LOAD headers lack them"
                            );
                        }
                    } else {
                        load_without_hdrs = true;
                    }
                }
                let flags = phdr
                    .flags
                    .as_ref()
                    .map(|f| expression_eval::evaluate_const(f).map(|c| c as u32))
                    .transpose()?
                    .unwrap_or({
                        if phdr.has_filehdr || phdr.has_phdrs {
                            pf::READABLE.0
                        } else {
                            0
                        }
                    });

                let id = builder.add_custom_segment(
                    <ProgramSegmentDef as platform::ProgramSegmentDef>::from_linker_script(
                        ptype, flags,
                    ),
                );
                has_filehdr = has_filehdr || phdr.has_filehdr;
                segment_entries.push(SegmentEntry {
                    id,
                    ptype,
                    flags,
                    is_emitted: phdr.has_filehdr || phdr.has_phdrs,
                    has_explicit_flags: phdr.flags.is_some(),
                    has_filehdr: phdr.has_filehdr,
                    has_phdrs: phdr.has_phdrs,
                });
                segments_map.insert(phdr.name, id);
            }

            for id in &script.parsed.ordered_sections {
                let info = output_sections.section_infos.get(*id);
                for phdr in &info.phdrs {
                    if phdr == b"NONE" {
                        continue;
                    }
                    let segment = segments_map.get(phdr).with_context(|| {
                        format!(
                            "Section {} assigned to non-existent phdr `{}`",
                            output_sections.display_name(*id),
                            String::from_utf8_lossy(phdr)
                        )
                    })?;
                    let entry = &mut segment_entries[segment.as_usize()];
                    entry.is_emitted = true;
                    if !matches!(SegmentType(entry.ptype), pt::LOAD | pt::PHDR)
                        && (entry.has_filehdr || entry.has_phdrs)
                    {
                        bail!(
                            "Non-load segment {} includes file header and/or program header",
                            segment.as_usize()
                        );
                    }
                    if entry.has_explicit_flags {
                        continue;
                    }
                    entry.flags |=
                        Self::get_segment_flags_for_section(&info.section_attributes.flags);
                    builder.get_segment_mut(*segment).segment_flags |= SegmentFlags(entry.flags);
                }
                ordered_sections.push(*id);
            }
        }

        let mut first_load = None;
        let mut starts = vec![None; num_phdrs];
        let mut ends = vec![None; num_phdrs];
        let mut first_exec: Option<ProgramSegmentId> = None;
        let mut first_rw: Option<ProgramSegmentId> = None;
        let mut first_ro: Option<ProgramSegmentId> = None;

        for (pos, id) in ordered_sections.iter().enumerate() {
            let phdrs = &output_sections.section_infos.get(*id).phdrs;
            for &phdr_name in phdrs {
                let Some(id) = segments_map.get(phdr_name) else {
                    continue;
                };
                let seg_idx = id.as_usize();
                let entry = segment_entries[seg_idx];
                if entry.ptype == pt::LOAD.0 && first_load.is_none() {
                    first_load = Some(*id);
                }
                if starts[seg_idx].is_none() {
                    starts[seg_idx] = Some(pos);
                }
                ends[seg_idx] = Some(pos);
                if entry.ptype == pt::LOAD.0 {
                    if (entry.flags & pf::EXECUTABLE.0) != 0
                        && first_exec.is_none_or(|e| {
                            segment_entries[e.as_usize()].flags & pf::WRITABLE.0 != 0
                        })
                    {
                        first_exec = Some(*id);
                    } else if (entry.flags & pf::WRITABLE.0) != 0
                        && first_rw.is_none_or(|e| {
                            segment_entries[e.as_usize()].flags & pf::EXECUTABLE.0 != 0
                        })
                    {
                        first_rw = Some(*id);
                    } else if first_ro
                        .is_none_or(|e| segment_entries[e.as_usize()].flags != pf::READABLE.0)
                    {
                        first_ro = Some(*id);
                    }
                }
            }
        }

        if first_load.is_none() {
            bail!("Missing LOAD PHDR in linker script");
        }

        let update_flags = |builder: &mut OutputOrderBuilder<Self>,
                            sections: &[OutputSectionId],
                            segment: ProgramSegmentId| {
            if segment_entries[segment.as_usize()].has_explicit_flags {
                return;
            }
            for &section_id in sections {
                let info = output_sections.section_infos.get(section_id);
                let flags = Self::get_segment_flags_for_section(&info.section_attributes.flags);
                builder.get_segment_mut(segment).segment_flags |= SegmentFlags(flags);
            }
        };

        for (pos, section_id) in ordered_sections.iter().enumerate() {
            let section_id = *section_id;

            if pos == 0 {
                let mut header_events = Vec::new();

                for (seg_idx, segment) in starts.iter().enumerate().take(num_phdrs) {
                    let entry = segment_entries[seg_idx];
                    let seg_id = ProgramSegmentId::new(seg_idx);
                    if entry.has_filehdr {
                        header_events.push((0, seg_id));
                        if ends[seg_idx].is_none() && !entry.has_phdrs {
                            header_events.push((1, seg_id));
                        }
                    } else if entry.has_phdrs {
                        header_events.push((2, seg_id));
                    } else if *segment == Some(pos) {
                        header_events.push((4, seg_id));
                    }
                    if ends[seg_idx].is_none() && entry.has_phdrs {
                        header_events.push((3, seg_id));
                    }
                }

                header_events.sort_by_key(|&(cat, _)| cat);
                let mut it = header_events.into_iter().peekable();

                while let Some((_, seg_id)) = it.next_if(|&(cat, _)| cat == 0) {
                    builder.push_event(OrderEvent::SegmentStart(seg_id));
                }
                builder.push_event(OrderEvent::Section(crate::output_section_id::FILE_HEADER));
                while let Some((_, seg_id)) = it.next_if(|&(cat, _)| cat == 1) {
                    builder.push_event(OrderEvent::SegmentEnd(seg_id));
                }
                while let Some((_, seg_id)) = it.next_if(|&(cat, _)| cat == 2) {
                    builder.push_event(OrderEvent::SegmentStart(seg_id));
                }
                builder.push_event(OrderEvent::Section(output_section_id::PROGRAM_HEADERS));
                while let Some((_, seg_id)) = it.next_if(|&(cat, _)| cat == 3) {
                    builder.push_event(OrderEvent::SegmentEnd(seg_id));
                }
                builder.push_event(OrderEvent::Section(output_section_id::SECTION_HEADERS));
                for (_, seg_id) in it {
                    builder.push_event(OrderEvent::SegmentStart(seg_id));
                }
            } else {
                for (seg_idx, segment) in starts.iter().enumerate().take(num_phdrs) {
                    let entry = segment_entries[seg_idx];
                    if *segment == Some(pos) && !entry.has_filehdr && !entry.has_phdrs {
                        builder
                            .push_event(OrderEvent::SegmentStart(ProgramSegmentId::new(seg_idx)));
                    }
                }
            }

            builder.add_section(section_id);

            for (seg_idx, segment) in ends.iter().enumerate().take(num_phdrs) {
                if *segment == Some(pos) {
                    let seg_id = ProgramSegmentId::new(seg_idx);
                    if Some(seg_id) == first_exec.or(first_load) {
                        update_flags(&mut builder, &custom.exec, seg_id);
                        builder.add_sections(&custom.exec);
                    }
                    if Some(seg_id) == first_rw.or(first_load) {
                        update_flags(&mut builder, &custom.tdata, seg_id);
                        update_flags(&mut builder, &custom.tbss, seg_id);
                        update_flags(&mut builder, &custom.data, seg_id);
                        update_flags(&mut builder, &custom.bss, seg_id);
                        builder.add_sections(&custom.tdata);
                        builder.add_sections(&custom.tbss);
                        builder.add_sections(&custom.data);
                        builder.add_sections(&custom.bss);
                    }
                    if Some(seg_id) == first_ro.or(first_load) {
                        update_flags(&mut builder, &custom.ro, seg_id);
                        builder.add_sections(&custom.ro);
                    }
                    builder.push_event(OrderEvent::SegmentEnd(seg_id));
                }
            }
        }

        for &id in &custom.nonalloc {
            if id != output_section_id::RISCV_ATTRIBUTES {
                builder.add_section(id);
            }
        }

        for segment in segment_entries {
            if !segment.is_emitted {
                builder.push_event(OrderEvent::SegmentStart(segment.id));
                builder.push_event(OrderEvent::SegmentEnd(segment.id));
            }
        }

        let riscv_segment = builder.add_custom_segment(
            <ProgramSegmentDef as platform::ProgramSegmentDef>::from_linker_script(
                pt::RISCV_ATTRIBUTES.0,
                pf::READABLE.0,
            ),
        );
        builder.push_event(OrderEvent::SegmentStart(riscv_segment));
        builder.add_section(output_section_id::RISCV_ATTRIBUTES);
        builder.push_event(OrderEvent::SegmentEnd(riscv_segment));

        Ok(builder.build())
    }

    fn will_emit_section_symbol_for_partial_objects(
        output_sections: &OutputSections<Self>,
        section_id: OutputSectionId,
    ) -> bool {
        if !output_sections.will_emit_section(section_id) {
            return false;
        }

        if matches!(
            section_id,
            crate::output_section_id::FILE_HEADER
                | output_section_id::PROGRAM_HEADERS
                | output_section_id::SECTION_HEADERS
        ) {
            return false;
        }

        let section_attr = output_sections.output_info(section_id).section_attributes;
        let segment_type = section_id
            .opt_built_in_details::<Elf<C>>()
            .and_then(|d| d.target_segment_type)
            .unwrap_or(linker_utils::elf::pt::LOAD);
        if section_attr.is_null() {
            false
        } else {
            let type_id = section_attr.ty();
            !type_id.is_rela()
                && !type_id.is_rel()
                && !type_id.is_symtab()
                && !type_id.is_strtab()
                && segment_type == linker_utils::elf::pt::LOAD
        }
    }

    fn lookup_for_partial_link(
        section_name: &[u8],
        section: &Self::SectionHeader,
        args: &Self::Args,
    ) -> SectionRuleOutcome {
        if section.should_exclude() {
            return SectionRuleOutcome::Discard;
        }

        if section_name.is_empty() {
            return crate::layout_rules::unnamed_section_output::<Elf<C>>(section);
        }

        match section_name {
            secnames::STRTAB_SECTION_NAME
            | secnames::SYMTAB_SECTION_NAME
            | secnames::SHSTRTAB_SECTION_NAME
            | secnames::SYMTAB_SHNDX_SECTION_NAME
            | secnames::GROUP_SECTION_NAME => {
                return SectionRuleOutcome::Discard;
            }
            secnames::RISCV_ATTRIBUTES_SECTION_NAME => return SectionRuleOutcome::RiscVAttribute,
            secnames::NOTE_GNU_PROPERTY_SECTION_NAME => return SectionRuleOutcome::NoteGnuProperty,
            secnames::NOTE_ABI_TAG_SECTION_NAME => {
                return SectionRuleOutcome::Section(crate::layout_rules::SectionOutputInfo::keep(
                    output_section_id::NOTE_ABI_TAG,
                ));
            }
            secnames::DEBUG_GNU_PUBNAMES | secnames::DEBUG_GNU_PUBTYPES if args.gdb_index => {
                return SectionRuleOutcome::DebugIndex;
            }
            _ => {}
        }

        SectionRuleOutcome::Custom
    }

    fn requires_symtab_shndx(num_sections: usize) -> bool {
        num_sections >= object::elf::SHN_LORESERVE as usize
    }

    fn compute_symtab_shndx_section_size(
        group_sizes: &mut OutputSectionPartMap<u64>,
        total_sizes: &mut OutputSectionPartMap<u64>,
    ) {
        let locals = group_sizes.get(part_id::SYMTAB_LOCAL) / C::SYMTAB_ENTRY_SIZE;
        let globals = group_sizes.get(part_id::SYMTAB_GLOBAL) / C::SYMTAB_ENTRY_SIZE;

        let mut extra_sizes = OutputSectionPartMap::with_size(group_sizes.num_parts());
        extra_sizes.increment(
            part_id::SYMTAB_SHNDX_LOCAL,
            locals * SYMTAB_SHNDX_ENTRY_SIZE,
        );
        extra_sizes.increment(
            part_id::SYMTAB_SHNDX_GLOBAL,
            globals * SYMTAB_SHNDX_ENTRY_SIZE,
        );

        group_sizes.merge(&extra_sizes);
        total_sizes.merge(&extra_sizes);
    }

    type GdbIndexScanResult<'data> = crate::gdb_index::GdbIndexScanResult<'data>;

    fn compute_gdb_index_size<'data>(
        groups: &[crate::layout::GroupState<'data, Self>],
    ) -> crate::error::Result<(u64, Option<Self::GdbIndexScanResult<'data>>)> {
        crate::gdb_index::compute_gdb_index_size(groups)
    }

    fn align_load_segment_start(
        _segment_def: Self::ProgramSegmentDef,
        segment_alignment: Alignment,
        file_offset: &mut usize,
        mem_offset: &mut u64,
    ) {
        *mem_offset = segment_alignment.align_modulo(*file_offset as u64, *mem_offset);
    }

    fn default_symtab_entry() -> Self::SymtabEntry {
        Default::default()
    }

    fn get_sizeof_headers(header_info: &layout::HeaderInfo) -> u64 {
        u64::from(C::FILE_HEADER_SIZE) + program_headers_size::<C>(header_info)
    }

    fn handle_debug_index_section<'data>(
        obj: &mut crate::resolution::ResolvedObject<'data, Self>,
        section_index: object::SectionIndex,
        input_section: &'data Self::SectionHeader,
        member: &bumpalo_herd::Member<'data>,
        loaded_metrics: &LoadedMetrics,
    ) -> Result {
        let data = obj
            .common
            .object
            .section_data(input_section, member, loaded_metrics)?;

        obj.format_specific
            .debug_index_sections
            .push(InputDebugIndexSection {
                contents: data,
                section_index,
            });

        Ok(())
    }

    fn new_object_layout_state_ext<'data>(
        input: Self::ResolvedObjectExt<'data>,
    ) -> Self::ObjectLayoutStateExt<'data> {
        ObjectLayoutStateExt {
            debug_index_sections: input.debug_index_sections,
            ..Default::default()
        }
    }

    fn is_allowed_in_archive(kind: crate::file_kind::FileKind) -> bool {
        kind == FileKind::ElfObject
    }

    fn section_identity<'data>(
        name: SectionName<'data>,
        _section: &Self::SectionHeader,
    ) -> SectionIdentity<'data, Self> {
        SectionIdentity::new(name, ())
    }

    fn section_identity_from_name<'data>(
        name: SectionName<'data>,
    ) -> Option<SectionIdentity<'data, Self>> {
        Some(SectionIdentity::new(name, ()))
    }

    fn apply_linker_script_attributes(
        linker_script_attributes: &linker_script::SectionAttributes,
        mut output_attributes: Self::SectionAttributes,
    ) -> Self::SectionAttributes {
        match linker_script_attributes {
            linker_script::SectionAttributes::Noload => {
                output_attributes.ty = sht::NOBITS;
                output_attributes.overrides.has_fixed_type = true;
            }
            linker_script::SectionAttributes::Readonly => {
                output_attributes.overrides.avoid_progpogation = shf::WRITE;
            }
            linker_script::SectionAttributes::Dsect
            | linker_script::SectionAttributes::Copy
            | linker_script::SectionAttributes::Info
            | linker_script::SectionAttributes::Overlay => {
                output_attributes.overrides.avoid_progpogation = shf::ALLOC;
            }
        }
        output_attributes
    }
}

/// Marks the symbol version associated with the dynamic symbol `GLIBC_ABI_DT_RELR` as needed.
/// Referencing the version will cause the binary to error if it's loaded with a glibc that doesn't
/// support relr. glibc will error at startup if we use relr and don't reference the version. If
/// we're not linking against glibc, then the symbol (and version) will be absent. This is not an
/// error and the binary will work fine provided the dynamic loader supports relr.
fn load_glibc_abi_dt_relr_version<C: ElfClass>(
    groups: &mut [layout::GroupState<'_, Elf<C>>],
    symbol_db: &SymbolDb<Elf<C>>,
) -> Result {
    if let Some(symbol_id) =
        symbol_db.get_unversioned(&UnversionedSymbolName::prehashed(b"GLIBC_ABI_DT_RELR"))
    {
        let file_id = symbol_db.file_id_for_symbol(symbol_id);
        if let layout::FileLayoutState::Dynamic(state) =
            &mut groups[file_id.group()].files[file_id.file()]
        {
            let symbol_index = state.symbol_id_range.id_to_offset(symbol_id);
            state
                .format_specific
                .mark_version_as_needed(state.object.versym[symbol_index])?;
        }
    }

    Ok(())
}

impl<'data, C: ElfClass> File<'data, C> {
    fn parse_elf_bytes(data: &'data [u8], is_dynamic: bool) -> Result<Self> {
        let header = C::FileHeader::parse(data)?;
        let endian = header.endian()?;
        let architecture = header.e_machine(endian).try_into()?;
        let sections = header.sections(endian, data)?;
        let eflags = header.e_flags(endian);

        let mut symbols = SymbolTable::<C>::default();
        let mut versym: &[Versym] = &[];
        let mut verdef = None;
        let mut verdefnum = 0;
        let mut verneed = None;

        // Find all the sections that we're interested in a single scan of the section table so
        // as to avoid multiple scans.
        for (section_index, section) in sections.enumerate() {
            match section.sh_type(endian) {
                sht::DYNSYM if is_dynamic => {
                    symbols =
                        SymbolTable::<C>::parse(endian, data, &sections, section_index, section)?;
                }
                sht::SYMTAB if !is_dynamic => {
                    symbols =
                        SymbolTable::<C>::parse(endian, data, &sections, section_index, section)?;
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
            is_dynamic.then(|| DynamicTagValues::read::<C>(&sections, data, &symbols));

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
}

impl<'data, C: ElfClass> platform::ObjectFile<'data> for File<'data, C> {
    type Platform = Elf<C>;

    fn parse(input: &InputBytes<'data>, args: &ElfArgs) -> Result<Self> {
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
        Self::parse_elf_bytes(data, is_dynamic)
    }

    fn section(&self, index: object::SectionIndex) -> Result<&SectionHeader<C>> {
        Ok(self.sections.section(index)?)
    }

    fn section_by_name(&self, name: &str) -> Option<(object::SectionIndex, &SectionHeader<C>)> {
        self.sections.section_by_name(LittleEndian, name.as_bytes())
    }

    fn section_name(&self, index: object::SectionIndex) -> Result<&'data [u8]> {
        let section = self.sections.section(index)?;
        Ok(self.sections.section_name(LittleEndian, section)?)
    }

    fn section_display_name(&self, index: object::SectionIndex) -> Cow<'data, str> {
        self.section_name(index).map_or_else(
            |_| format!("<index {}>", index.0).into(),
            String::from_utf8_lossy,
        )
    }

    fn raw_section_data(&self, section: &SectionHeader<C>) -> Result<&'data [u8]> {
        Ok(section.data(LittleEndian, self.data)?)
    }

    fn section_data(
        &self,
        section: &SectionHeader<C>,
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
            decompress_into(
                compression,
                &data[size_of::<CompressionHeaderEntry<C>>()..],
                decompressed,
            )?;
            loaded_metrics
                .decompressed_bytes
                .fetch_add(decompressed.len(), Ordering::Relaxed);
            Ok(decompressed)
        } else {
            Ok(data)
        }
    }

    fn copy_section_data(&self, section: &SectionHeader<C>, out: &mut [u8]) -> Result {
        let data = section.data(LittleEndian, self.data)?;

        if let Some((compression, _, _)) = section.compression(LittleEndian, self.data)? {
            decompress_into(
                compression,
                &data[size_of::<CompressionHeaderEntry<C>>()..],
                out,
            )?;
        } else {
            copy_section_data(data, out);
        }
        Ok(())
    }

    fn section_data_cow(&self, section: &SectionHeader<C>) -> Result<Cow<'data, [u8]>> {
        let data = section.data(LittleEndian, self.data)?;

        if let Some((compression, _, _)) = section.compression(LittleEndian, self.data)? {
            let len = self.section_size(section)?;
            let mut decompressed = vec![0; len as usize];
            decompress_into(
                compression,
                &data[size_of::<CompressionHeaderEntry<C>>()..],
                &mut decompressed,
            )?;
            Ok(Cow::Owned(decompressed))
        } else {
            Ok(Cow::Borrowed(data))
        }
    }

    fn section_size(&self, section: &SectionHeader<C>) -> Result<u64> {
        Ok(section.compression(LittleEndian, self.data)?.map_or_else(
            || section.sh_size(LittleEndian).into(),
            |compression| compression.0.ch_size(LittleEndian).into(),
        ))
    }

    fn section_alignment(&self, section: &SectionHeader<C>) -> Result<u64> {
        Ok(section.compression(LittleEndian, self.data)?.map_or_else(
            || section.sh_addralign(LittleEndian).into(),
            |compression| compression.0.ch_addralign(LittleEndian).into(),
        ))
    }

    fn relocations(
        &self,
        index: object::SectionIndex,
        relocations: &RelocationSections,
    ) -> Result<RelocationList<'data, C>> {
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

    fn symbol(&self, index: object::SymbolIndex) -> Result<&SymtabEntry<C>> {
        Ok(self.symbols.symbol(index)?)
    }

    fn symbol_name(&self, symbol: &SymtabEntry<C>) -> Result<&'data [u8]> {
        Ok(self.symbols.symbol_name(LittleEndian, symbol)?)
    }

    fn symbol_section(
        &self,
        symbol: &SymtabEntry<C>,
        index: object::SymbolIndex,
    ) -> Result<Option<object::SectionIndex>> {
        Ok(self.symbols.symbol_section(LittleEndian, symbol, index)?)
    }

    fn dynamic_tags(&self) -> Result<&'data [DynamicEntry<C>]> {
        dynamic_tags::<C>(&self.sections, self.data)
    }

    fn parse_relocations(&self) -> Result<RelocationSections> {
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

    fn dynamic_tag_values(&self) -> Option<DynamicTagValues<'data>> {
        self.dynamic_tag_values
    }

    fn symbol_version_debug(&self, symbol_index: object::SymbolIndex) -> Option<String> {
        let endian = LittleEndian;
        let versym = self.versym.get(symbol_index.0)?;
        let versym = versym.0.get(endian);
        let is_default = !versym.is_hidden();
        let symbol_version_index = versym.index();
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

    fn section_iter<'a>(&'a self) -> core::slice::Iter<'a, SectionHeader<C>> {
        self.sections.iter()
    }

    fn enumerate_sections(
        &self,
    ) -> impl Iterator<Item = (object::SectionIndex, &SectionHeader<C>)> {
        self.sections.enumerate()
    }

    fn get_version_names(&self) -> Result<VersionNames<'data>> {
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
        symbol: &SymtabEntry<C>,
        local_index: usize,
        version_names: &VersionNames<'data>,
    ) -> Result<RawSymbolName<'data>> {
        let name_bytes = self.symbol_name(symbol)?;

        let is_default;
        let version_name;

        if let Some(versym) = self.versym.get(local_index) {
            let versym = versym.0.get(LittleEndian);
            is_default = !versym.is_hidden();
            let version_index = versym.index();
            version_name = version_names
                .names
                .get(usize::from(version_index))
                .copied()
                .flatten();
        } else {
            is_default = true;
            version_name = None;
        }

        Ok(RawSymbolName {
            name: name_bytes,
            version_name,
            is_default,
        })
    }

    fn symbols_iter(&self) -> impl Iterator<Item = &SymtabEntry<C>> {
        self.symbols.iter()
    }

    fn verneed_table(&self) -> Result<VerneedTable<'data>> {
        VerneedTable::new(self)
    }

    fn num_sections(&self) -> usize {
        self.sections.len()
    }

    fn process_gnu_note_section(
        &self,
        state: &mut ObjectLayoutStateExt<'data, C>,
        section_index: object::SectionIndex,
    ) -> Result {
        let section = self.section(section_index)?;
        let e = LittleEndian;

        let Some(notes) = object::read::elf::SectionHeader::notes(section, e, self.data)? else {
            return Ok(());
        };

        for note in notes {
            for gnu_property in note?
                .gnu_properties(e)
                .ok_or(error!("Invalid type of .note.gnu.property"))?
            {
                let gnu_property = gnu_property?;

                // Right now, skip all properties other than those with size equal to 4.
                // There are existing properties, but unused right now:
                // GNU_PROPERTY_STACK_SIZE, GNU_PROPERTY_NO_COPY_ON_PROTECTED
                // TODO: support in the future
                if gnu_property.pr_data().len() != 4 {
                    continue;
                }
                state.gnu_property_notes.push(crate::elf::GnuProperty {
                    ptype: gnu_property.pr_type(),
                    data: gnu_property.data_u32(e)?,
                });
            }
        }

        Ok(())
    }

    fn symbol_versions(&self) -> &[Versym] {
        self.versym
    }

    fn dynamic_symbol_used(
        &self,
        symbol_index: object::SymbolIndex,
        file: &mut layout::DynamicLayoutState<'data, Elf<C>>,
    ) -> Result {
        if let Some(version_index) = self.versym.get(symbol_index.0) {
            file.format_specific
                .mark_version_as_needed(*version_index)?;
        }

        Ok(())
    }

    fn finalise_sizes_dynamic(
        &self,
        lib_name: &[u8],
        state: &mut DynamicLayoutStateExt<'data, C>,
        mem_sizes: &mut OutputSectionPartMap<u64>,
    ) -> Result {
        let e = LittleEndian;
        let mut version_count = 0;

        if let Some((mut verdef_iterator, link)) = self.verdef.clone() {
            let defs = verdef_iterator.clone();

            let strings = self.sections.strings(e, self.data, link)?;
            let mut base_size = 0;
            while let Some((verdef, mut aux_iterator)) = verdef_iterator.next()? {
                let version_index = verdef.vd_ndx.get(e);

                if version_index == object::elf::VER_NDX_LOCAL {
                    bail!("Invalid version index");
                }

                let flags = verdef.vd_flags.get(e);
                let is_base = flags.contains(object::elf::VER_FLG_BASE);

                // Keep the base version and any versions that are referenced.
                let needed = is_base
                    || *state
                        .symbol_versions_needed
                        .get(usize::from(version_index - object::elf::VER_NDX_GLOBAL))
                        .context("Invalid version index")?;

                if needed {
                    // For the base version, we use the lib_name rather than the version name from
                    // the input file. This matches what GNU ld appears to do. Also, if we don't do
                    // this, then the C runtime hits an assertion failure, because it expects to be
                    // able to find a DT_NEEDED entry that matches the base name of a version.
                    let name = if is_base {
                        lib_name
                    } else {
                        // Every VERDEF entry should have at least one AUX entry.
                        let aux = aux_iterator.next()?.context("VERDEF with no AUX entry")?;
                        aux.name(e, strings)?
                    };

                    let name_size = name.len() as u64 + 1;

                    if is_base {
                        // The base version doesn't count as a version, so we don't increment
                        // version_count here. We emit it as a Verneed, whereas the actual versions
                        // are emitted as Vernaux.
                        base_size = name_size;
                    } else {
                        mem_sizes.increment(part_id::DYNSTR, name_size);
                        version_count += 1;
                    }
                }
            }

            if version_count > 0 {
                mem_sizes.increment(part_id::DYNSTR, base_size);
                mem_sizes.increment(
                    part_id::GNU_VERSION_R,
                    size_of::<crate::elf::Verneed>() as u64
                        + u64::from(version_count) * size_of::<crate::elf::Vernaux>() as u64,
                );

                state.verneed_info = Some(VerneedInfo {
                    defs,
                    string_table_index: link,
                    version_count,
                });
            }
        }

        Ok(())
    }

    fn apply_non_addressable_indexes_dynamic(
        &self,
        indexes: &mut NonAddressableIndexes,
        counts: &mut NonAddressableCounts,
        state: &mut DynamicLayoutStateExt<'_, C>,
    ) -> Result {
        state.non_addressable_indexes = *indexes;
        if let Some(info) = state.verneed_info.as_ref()
            && info.version_count > 0
        {
            counts.verneed_count += 1;
            indexes.next_gnu_version_r_index = indexes
                .next_gnu_version_r_index
                .checked_offset(info.version_count)
                .context("Symbol versions overflowed 2**16")?;
        }
        Ok(())
    }

    fn should_enforce_undefined(
        &self,
        resources: &layout::GraphResources<'data, '_, Elf<C>>,
    ) -> bool {
        let is_executable = resources.symbol_db.output_kind.is_executable();

        !resources.symbol_db. args.allow_shlib_undefined
            && is_executable
            // Like lld, our behaviour for --no-allow-shlib-undefined is to only report errors for
            // shared objects that have all their dependencies in the link. This is in contrast to
            // GNU ld which recursively loads all transitive dependencies of shared objects and
            // checks our shared object against those.
            && has_complete_deps(self, resources)
    }

    fn symbol_offset_in_section(
        &self,
        symbol: &<Self::Platform as Platform>::SymtabEntry,
        _section_index: object::SectionIndex,
    ) -> Result<u64> {
        Ok(symbol.value())
    }
}

impl<C: ElfClass> DynamicLayoutStateExt<'_, C> {
    /// Marks the specified version as needed, provided it's not a local or global version.
    fn mark_version_as_needed(&mut self, version_index: Versym) -> Result {
        let version_index = version_index.0.get(LittleEndian).index();

        // Versions 0 and 1 are local and global. We care about the versions after that.
        if !version_index.is_special() {
            *self
                .symbol_versions_needed
                .get_mut(usize::from(version_index - object::elf::VER_NDX_GLOBAL))
                .with_context(|| format!("Invalid symbol version index {version_index}"))? = true;
        }
        Ok(())
    }
}

fn process_eh_frame_relocations<
    'data,
    'scope,
    C: ElfClass,
    A: Arch<Platform = Elf<C>>,
    R: Relocation<Platform = Elf<C>>,
>(
    object: &mut layout::ObjectLayoutState<'data, Elf<C>>,
    common: &mut layout::CommonGroupState<'data, Elf<C>>,
    resources: &'scope layout::GraphResources<'data, '_, Elf<C>>,
    queue: &mut layout::LocalWorkQueue,
    eh_frame_section: &'data SectionHeader<C>,
    eh_frame_section_index: object::SectionIndex,
    frame_index_offset: usize,
    data: &'data [u8],
    relocations: &R::Sequence<'data>,
    scope: &Scope<'scope>,
) -> Result<Vec<ExceptionFrame<'data, R>>> {
    const PREFIX_LEN: usize = size_of::<EhFrameEntryPrefix>();

    let mut rel_iter = relocations.rel_iter().enumerate().peekable();
    let mut offset = 0;
    let mut exception_frames = Vec::new();

    while offset + PREFIX_LEN <= data.len() {
        // Although the section data will be aligned within the object file, there's
        // no guarantee that the object is aligned within the archive to any more
        // than 2 bytes, so we can't rely on alignment here. Archives are annoying!
        // See https://www.airs.com/blog/archives/170
        let prefix =
            EhFrameEntryPrefix::read_from_bytes(&data[offset..offset + PREFIX_LEN]).unwrap();
        if prefix.length == 0 {
            offset = data.len();
            // Note, linker behaviour differs here. We match lld's behaviour, which is to stop when
            // a zero-length frame is encountered. BFD ignores the frame, but continues.
            break;
        }
        let size = size_of_val(&prefix.length) + prefix.length as usize;
        let next_offset = offset + size;

        if next_offset > data.len() {
            bail!("Invalid .eh_frame data");
        }

        if prefix.cie_id == 0 {
            // This is a CIE

            // When deduplicating CIEs, we take into consideration the bytes of the CIE and all the
            // symbols it references. If however, it references something other than a symbol, then,
            // because we're not taking that into consideration, we disallow deduplication.
            let mut eligible_for_deduplication = true;
            while let Some((_, rel)) = rel_iter.peek() {
                let rel_offset = rel.offset();
                if rel_offset >= next_offset as u64 {
                    // This relocation belongs to the next entry.
                    break;
                }

                // We currently always load all CIEs, so any relocations found in CIEs always need
                // to be processed.
                process_relocation::<C, A, <R::Sequence<'data> as RelocationSequence>::Rel>(
                    object,
                    common,
                    rel,
                    eh_frame_section,
                    output_section_id::EH_FRAME.base_part_id::<Elf<C>>(),
                    resources,
                    queue,
                    false,
                    scope,
                    &mut RelrEncoder::default(), // eh_frame relocations are never RELR-eligible
                )?;

                if rel.symbol().is_none() {
                    eligible_for_deduplication = false;
                }
                rel_iter.next();
            }

            object.format_specific.cies.push(CieAtOffset {
                offset: offset as u32,
                cie: Cie {
                    bytes: &data[offset..next_offset],
                    eligible_for_deduplication,
                },
            });
        } else {
            // This is an FDE
            let mut section_index = None;
            let rel_start_index = rel_iter.peek().map_or(0, |(i, _)| *i);
            let mut rel_end_index = 0;

            while let Some((rel_index, rel)) = rel_iter.peek() {
                let rel_offset = rel.offset();
                if rel_offset < next_offset as u64 {
                    let is_pc_begin = (rel_offset as usize - offset) == FDE_PC_BEGIN_OFFSET;

                    if is_pc_begin && let Some(index) = rel.symbol() {
                        let elf_symbol = object.object.symbol(index)?;
                        section_index = object.object.symbol_section(elf_symbol, index)?;
                    }
                    rel_end_index = rel_index + 1;
                    rel_iter.next();
                } else {
                    break;
                }
            }

            if let Some(section_index) = section_index
                && let Some(unloaded) = object.sections[section_index.0].unloaded_mut()
            {
                let frame_index =
                    FrameIndex::from_usize(frame_index_offset + exception_frames.len());

                // Update our unloaded section to point to our new frame. Our frame will then in
                // turn point to whatever the section pointed to before.
                let previous_frame_for_section = unloaded.last_frame_index.replace(frame_index);

                exception_frames.push(ExceptionFrame {
                    relocations: relocations.subsequence(rel_start_index..rel_end_index),
                    frame_size: size as u32,
                    previous_frame_for_section,
                    eh_frame_section_index,
                });
            }
        }
        offset = next_offset;
    }

    common.format_specific.exception_frame_count += exception_frames.len();

    // Allocate space for any remaining bytes in .eh_frame that aren't large enough to constitute an
    // actual entry. crtend.o has a single u32 equal to 0 as an end marker.
    let remaining = &data[offset..];
    if !is_eh_frame_terminator(remaining) {
        object.format_specific.eh_frame_size += remaining.len() as u64;
    }

    Ok(exception_frames)
}

/// Processes the exception frames for a section that we're loading.
fn process_section_exception_frames<
    'data,
    'scope,
    C: ElfClass,
    A: Arch<Platform = Elf<C>>,
    R: Relocation<Platform = Elf<C>>,
>(
    object: &layout::ObjectLayoutState<'data, Elf<C>>,
    frame_index: Option<FrameIndex>,
    common: &mut layout::CommonGroupState<'data, Elf<C>>,
    resources: &'scope layout::GraphResources<'data, '_, Elf<C>>,
    queue: &mut layout::LocalWorkQueue,
    scope: &Scope<'scope>,
    exception_frames: &[ExceptionFrame<'data, R>],
) -> Result<EhFrameSizes> {
    let mut num_frames = 0;
    let mut eh_frame_size = 0;
    let mut next_frame_index = frame_index;
    while let Some(frame_index) = next_frame_index {
        let frame_data = &exception_frames[frame_index.as_usize()];
        next_frame_index = frame_data.previous_frame_for_section;

        eh_frame_size += u64::from(frame_data.frame_size);

        num_frames += 1;

        // Request loading of any sections/symbols referenced by the FDEs for our
        // section.
        let eh_frame_section = object.object.section(frame_data.eh_frame_section_index)?;
        for rel in frame_data.relocations.rel_iter() {
            process_relocation::<C, A, <R::Sequence<'data> as RelocationSequence>::Rel>(
                object,
                common,
                &rel,
                eh_frame_section,
                output_section_id::EH_FRAME.base_part_id::<Elf<C>>(),
                resources,
                queue,
                true,
                scope,
                &mut RelrEncoder::default(), // eh_frame relocations are never RELR-eligible
            )?;
        }
        common.format_specific.exception_frame_relocations +=
            frame_data.relocations.num_relocations();
    }

    Ok(EhFrameSizes {
        num_frames,
        eh_frame_size,
    })
}

fn allocate_sysv_hash<C: ElfClass>(
    state: &mut EpilogueLayoutExt,
    current_sizes: &OutputSectionPartMap<u64>,
    extra_sizes: &mut OutputSectionPartMap<u64>,
    dynamic_symbol_defs: &[DynamicSymbolDefinition<Elf<C>>],
) -> Result {
    let num_defs = dynamic_symbol_defs.len();
    if num_defs == 0 {
        return Ok(());
    }

    let bucket_count = (num_defs / 2).max(1).next_power_of_two() as u32;
    // Whereas `num_defs` above is the number of definitions, this is the number of dynamic
    // symbols, which also includes undefined dynamic symbols.
    let num_dynsym = *current_sizes.get(part_id::DYNSYM) / C::SYMTAB_ENTRY_SIZE;
    let chain_count = num_dynsym
        .try_into()
        .context("Too many dynamic symbols for .hash")?;

    let sysv_hash_layout = SysvHashLayout {
        bucket_count,
        chain_count,
    };

    extra_sizes.increment(part_id::SYSV_HASH, sysv_hash_layout.byte_size()?);
    state.sysv_hash_layout = Some(sysv_hash_layout);

    Ok(())
}

/// Computes a mapping from input versions to output versions.
fn compute_version_mapping(
    symbol_versions_needed: &[bool],
    non_addressable_indexes: NonAddressableIndexes,
) -> Vec<object::elf::VersionIndex> {
    let mut out = vec![object::elf::VER_NDX_GLOBAL; symbol_versions_needed.len()];
    let mut next_output_version = non_addressable_indexes.next_gnu_version_r_index;
    for (input_version, needed) in symbol_versions_needed.iter().enumerate() {
        if *needed {
            out[input_version] = next_output_version;
            next_output_version += 1;
        }
    }
    out
}

impl platform::SectionHeader for object::elf::SectionHeader64<LittleEndian> {
    fn is_alloc(&self) -> bool {
        self.sh_flags(LittleEndian).is_alloc()
    }

    fn is_writable(&self) -> bool {
        self.sh_flags(LittleEndian).contains(shf::WRITE)
    }

    fn is_executable(&self) -> bool {
        self.sh_flags(LittleEndian).contains(shf::EXECINSTR)
    }

    fn is_tls(&self) -> bool {
        self.sh_flags(LittleEndian).contains(shf::TLS)
    }

    fn is_merge_section(&self) -> bool {
        self.sh_flags(LittleEndian).contains(shf::MERGE)
    }

    fn is_strings(&self) -> bool {
        self.sh_flags(LittleEndian).contains(shf::STRINGS)
    }

    fn should_retain(&self) -> bool {
        self.sh_flags(LittleEndian).contains(shf::GNU_RETAIN)
    }

    fn should_exclude(&self) -> bool {
        self.sh_flags(LittleEndian).contains(shf::EXCLUDE)
    }

    fn is_group(&self) -> bool {
        self.sh_flags(LittleEndian).contains(shf::GROUP)
    }

    fn is_note(&self) -> bool {
        self.sh_type(LittleEndian) == sht::NOTE
    }

    fn is_prog_bits(&self) -> bool {
        self.sh_type(LittleEndian) == sht::PROGBITS
    }

    fn is_no_bits(&self) -> bool {
        self.sh_type(LittleEndian) == sht::NOBITS
    }
}

impl platform::SectionType for SectionType {
    fn is_rela(&self) -> bool {
        *self == sht::RELA
    }

    fn is_rel(&self) -> bool {
        *self == sht::REL
    }

    fn is_symtab(&self) -> bool {
        *self == sht::SYMTAB
    }

    fn is_strtab(&self) -> bool {
        *self == sht::STRTAB
    }
}

impl platform::SectionFlags for SectionFlags {
    fn is_alloc(self) -> bool {
        self.contains(shf::ALLOC)
    }
}

impl<T: ElfSymbol> platform::Symbol for T {
    fn as_common(&self) -> Option<CommonSymbol> {
        let e = LittleEndian;
        if !object::read::elf::Sym::is_common(self, e) {
            return None;
        }

        // Common symbols misuse the value field (which we access via `address()`) to store
        // the alignment.
        let Ok(alignment) = Alignment::new(object::read::elf::Sym::st_value(self, e).into()) else {
            return None;
        };
        let size = alignment.align_up(object::read::elf::Sym::st_size(self, e).into());

        let output_section_id = if self.st_type() == object::elf::STT_TLS {
            output_section_id::TBSS
        } else {
            output_section_id::BSS
        };

        let part_id = output_section_id.part_id_with_alignment::<Elf<T::Class>>(alignment);

        Some(CommonSymbol { size, part_id })
    }

    fn is_undefined(&self) -> bool {
        object::read::elf::Sym::is_undefined(self, LittleEndian)
    }

    fn is_local(&self) -> bool {
        object::read::elf::Sym::is_local(self)
    }

    fn visibility(&self) -> Visibility {
        convert_elf_visibility(self.st_visibility())
    }

    fn is_absolute(&self) -> bool {
        object::read::elf::Sym::is_absolute(self, LittleEndian)
    }

    fn is_weak(&self) -> bool {
        object::read::elf::Sym::is_weak(self)
    }

    fn value(&self) -> u64 {
        object::read::elf::Sym::st_value(self, LittleEndian).into()
    }

    fn size(&self) -> u64 {
        object::read::elf::Sym::st_size(self, LittleEndian).into()
    }

    fn has_name(&self) -> bool {
        object::read::elf::Sym::st_name(self, LittleEndian) != 0
    }

    fn is_default_strippable(&self, name: &[u8]) -> bool {
        (self.is_local() && name.starts_with(b".L"))
            || crate::symbol_db::is_mapping_symbol_name(name)
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

    fn is_gnu_unique(&self) -> bool {
        self.st_bind() == object::elf::STB_GNU_UNIQUE
    }

    fn with_hidden(mut self, hidden: bool) -> Self {
        self.set_visibility(if hidden {
            object::elf::STV_HIDDEN
        } else {
            object::elf::STV_DEFAULT
        });
        self
    }
}

pub(crate) fn convert_elf_visibility(st_visibility: object::elf::SymbolVisibility) -> Visibility {
    match st_visibility {
        object::elf::STV_PROTECTED => Visibility::Protected,
        object::elf::STV_HIDDEN => Visibility::Hidden,
        _ => Visibility::Default,
    }
}

fn dynamic_tags<'data, C: ElfClass>(
    sections: &SectionTable<'data, C>,
    data: &'data [u8],
) -> Result<&'data [DynamicEntry<C>]> {
    let e = LittleEndian;
    if let Some(dynamic) = sections.dynamic(e, data).transpose() {
        return dynamic
            .map(|(dynamic, _)| dynamic)
            .context("Failed to read dynamic table");
    }
    Ok(&[])
}

fn decompress_into<C: CompressionHeader<Endian = LittleEndian>>(
    compression: &C,
    input: &[u8],
    out: &mut [u8],
) -> Result {
    match compression.ch_type(LittleEndian) {
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
            #[cfg(feature = "zstd")]
            {
                use std::io::Read as _;
                zstd::stream::Decoder::new(input)?.read_exact(out)?;
            }
            #[cfg(not(feature = "zstd"))]
            {
                bail!("wild was compiled without zstd support");
            }
        }
        c => bail!("Unsupported compression format: {}", c),
    }
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

pub(crate) fn is_eh_frame_terminator(data: &[u8]) -> bool {
    data.len() == size_of::<u32>() && data.iter().all(|&b| b == 0)
}

/// The offset of the pc_begin field in an FDE.
pub(crate) const FDE_PC_BEGIN_OFFSET: usize = 8;

// TODO: Right now, both x86_64 and AArch64 have 16 byte long entries, but
// the size should be generic over A: Arch.
pub(crate) const PLT_ENTRY_SIZE: u64 = 0x10;

pub(crate) const SYMTAB_SHNDX_ENTRY_SIZE: u64 = size_of::<SymtabShndxEntry>() as u64;
pub(crate) const GNU_VERSION_ENTRY_SIZE: u64 = size_of::<Versym>() as u64;

pub(crate) const GNU_NOTE_NAME: &[u8] = b"GNU\0";
/// For additional information on Elf_Prop, see
/// Linux Extensions to gABI at https://gitlab.com/x86-psABIs/Linux-ABI.
///
/// Right now, all properties have pr_datasz equal to 4. Any padding required for the ELF class is
/// written separately.
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

#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct DynamicTagValues<'data> {
    pub(crate) verdefnum: u64,
    pub(crate) soname: Option<&'data [u8]>,
}

impl<'data> DynamicTagValues<'data> {
    fn read<C: ElfClass>(
        sections: &SectionTable<'data, C>,
        data: &'data [u8],
        symbols: &SymbolTable<'data, C>,
    ) -> Self {
        let mut values = DynamicTagValues::default();
        let Ok(dynamic_tags) = dynamic_tags::<C>(sections, data) else {
            return values;
        };
        let e = LittleEndian;
        for entry in dynamic_tags {
            let value: u64 = entry.d_val(e).into();
            match entry.d_tag(e) {
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
}

impl<'data> platform::DynamicTagValues<'data> for DynamicTagValues<'data> {
    fn lib_name(&self, input: &InputRef<'data>) -> &'data [u8] {
        self.soname.unwrap_or_else(|| input.lib_name())
    }
}

struct SymDebug<'data, T: ElfSymbol>(pub(crate) &'data T);

impl<T: ElfSymbol> std::fmt::Display for SymDebug<'_, T> {
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
            match object::read::elf::Sym::st_type(sym) {
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
    pub(crate) ptype: object::elf::GnuPropertyType,
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
    }
}

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
pub(crate) struct ObjectLayoutStateExt<'data, C: ElfClass> {
    gnu_property_notes: Vec<GnuProperty>,
    pub(crate) riscv_attributes: Vec<RiscVAttribute>,

    has_eh_frame_input: bool,

    cies: SmallVec<[CieAtOffset<'data>; 2]>,

    eh_frame_size: u64,

    /// Indexed by `FrameIndex`.
    exception_frames: ExceptionFrames<'data, C>,

    pub(crate) debug_index_sections: Vec<InputDebugIndexSection<'data>>,
}

#[derive(Debug)]
pub(crate) struct LayoutExt {
    pub(crate) gnu_property_notes: Vec<GnuProperty>,
    pub(crate) riscv_attributes: RiscVAttributes,
    pub(crate) eflags: object::elf::FileFlags,
    has_eh_frame_input: bool,
}

impl LayoutExt {
    pub(crate) fn new<
        'files,
        'states,
        'data: 'files + 'states,
        C: ElfClass,
        A: Arch<Platform = Elf<C>>,
    >(
        groups: &'files [layout::GroupState<'data, Elf<C>>],
        args: &ElfArgs,
    ) -> Result<Self> {
        let states = objects_iter(groups).map(|o| &o.format_specific);
        let gnu_property_notes = merge_gnu_property_notes::<C, A>(states.clone(), args.z_isa)?;
        let riscv_attributes = merge_riscv_attributes::<C, A>(states)?;
        let eflags = merge_eflags::<C, A>(objects_iter(groups).map(|o| o.object))?;
        let has_eh_frame_input = objects_iter(groups).any(|o| o.format_specific.has_eh_frame_input);

        Ok(Self {
            gnu_property_notes,
            riscv_attributes,
            eflags,
            has_eh_frame_input,
        })
    }
}

fn merge_gnu_property_notes<'states, 'data: 'states, C: ElfClass, A: Arch>(
    states: impl Iterator<Item = &'states ObjectLayoutStateExt<'data, C>>,
    isa_needed: Option<NonZeroU32>,
) -> Result<Vec<GnuProperty>> {
    timing_phase!("Merge GNU property notes");

    let properties_per_file = states.map(|state| &state.gnu_property_notes).collect_vec();

    // Merge bits of each property type based on type: OR or AND operation.
    // Within a single file, OR the bits (accumulate all features the file has).
    // Across files, AND the bits (only keep features all files support).
    let mut property_map: HashMap<_, (u32, PropertyClass)> = HashMap::new();

    for file_props in &properties_per_file {
        // First OR within file to accumulate all features this file has.
        let mut file_map: HashMap<_, (u32, PropertyClass)> = HashMap::new();
        for prop in *file_props {
            let property_class = A::get_property_class(prop.ptype.0)
                .ok_or_else(|| crate::error!("unclassified property type {}", prop.ptype))?;
            file_map
                .entry(prop.ptype)
                .and_modify(|entry: &mut (u32, PropertyClass)| {
                    entry.0 |= prop.data;
                })
                .or_insert_with(|| (prop.data, property_class));
        }
        // Then AND across files to keep only features all files support.
        for (ptype, (data, class)) in file_map {
            property_map
                .entry(ptype)
                .and_modify(|entry: &mut (u32, PropertyClass)| {
                    if matches!(class, PropertyClass::And) {
                        entry.0 &= data;
                    } else {
                        entry.0 |= data;
                    }
                })
                .or_insert_with(|| (data, class));
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

fn merge_eflags<'files, 'data: 'files, C: ElfClass, A: Arch<Platform = Elf<C>>>(
    objects: impl Iterator<Item = &'files File<'data, C>>,
) -> Result<object::elf::FileFlags> {
    timing_phase!("Merge e_flags");

    A::merge_eflags(objects.map(|object| object.eflags))
}

fn merge_riscv_attributes<'groups, 'data: 'groups, C: ElfClass, A: Arch>(
    states: impl Iterator<Item = &'groups ObjectLayoutStateExt<'data, C>>,
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

pub(crate) fn gnu_property_notes_section_size<C: ElfClass>(
    gnu_property_notes: &[GnuProperty],
) -> u64 {
    if gnu_property_notes.is_empty() {
        0
    } else {
        C::NOTE_HEADER_SIZE
            + GNU_NOTE_NAME.len() as u64
            + gnu_property_notes.len() as u64 * C::GNU_PROPERTY_ENTRY_SIZE
    }
}

fn riscv_attributes_section_size(riscv_attributes: &[RiscVAttribute]) -> u64 {
    let attribute_size = |attr: &RiscVAttribute| match attr {
        RiscVAttribute::StackAlign(align) => {
            uleb128_size(TAG_RISCV_STACK_ALIGN) + uleb128_size(*align)
        }
        RiscVAttribute::Arch(arch) => {
            uleb128_size(TAG_RISCV_ARCH) + arch.to_attribute_string().len() + 1
        }
        RiscVAttribute::UnalignedAccess(_) => uleb128_size(TAG_RISCV_UNALIGNED_ACCESS) + 1,
        RiscVAttribute::PrivilegedSpecMajor(version) => {
            uleb128_size(TAG_RISCV_PRIV_SPEC) + uleb128_size(*version)
        }
        RiscVAttribute::PrivilegedSpecMinor(version) => {
            uleb128_size(TAG_RISCV_PRIV_SPEC_MINOR) + uleb128_size(*version)
        }
        RiscVAttribute::PrivilegedSpecRevision(version) => {
            uleb128_size(TAG_RISCV_PRIV_SPEC_REVISION) + uleb128_size(*version)
        }
    };

    (if riscv_attributes.is_empty() {
        0
    } else {
        1 // 'A'
            + 4 // sizeof(u32)
            + uleb128_size(TAG_RISCV_WHOLE_FILE)
            + 4 // sizeof(u32)
            + RISCV_ATTRIBUTE_VENDOR_NAME.len() + 1
            + riscv_attributes.iter().map(attribute_size).sum::<usize>()
    }) as u64
}

pub(crate) fn process_riscv_attributes(
    object: &File64,
    riscv_attributes_section_index: object::SectionIndex,
) -> Result<Vec<RiscVAttribute>> {
    let section = object.section(riscv_attributes_section_index)?;
    let e = LittleEndian;

    let content = section.data(e, object.data)?;
    ensure!(content.starts_with(b"A"), "Header must start with 'A'");
    let mut content = &content[1..];

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
                        let name = it.rev().collect();
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
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SectionAttributes<C: ElfClass> {
    pub(crate) flags: SectionFlags,
    pub(crate) ty: SectionType,
    pub(crate) entsize: u64,
    pub(crate) overrides: LinkerScriptOverrides,
    class: PhantomData<C>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LinkerScriptOverrides {
    pub(crate) avoid_progpogation: SectionFlags,
    pub(crate) has_fixed_type: bool,
}

/// Section flags that should not be propagated from input sections to the output section in which
/// they are placed. This is passed to `without`, so we keep all flags other than the one listed
/// here.
const SECTION_FLAGS_PROPAGATION_MASK: SectionFlags = object::elf::SHF_GROUP;

impl<C: ElfClass> platform::SectionAttributes for SectionAttributes<C> {
    type Platform = Elf<C>;

    fn merge(&mut self, rhs: Self) {
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

    fn apply(&self, output_sections: &mut OutputSections<Elf<C>>, section_id: OutputSectionId) {
        let info = output_sections.section_infos.get_mut(section_id);

        info.section_attributes.flags |= self.flags.without(
            SECTION_FLAGS_PROPAGATION_MASK | info.section_attributes.overrides.avoid_progpogation,
        );

        info.section_attributes.entsize = self.entsize;

        if !info.section_attributes.overrides.has_fixed_type {
            info.section_attributes.ty = info.section_attributes.ty.max(self.ty);
        }

        if let SectionKind::Secondary(primary_id) = info.kind
            && info.location_info.is_some()
        {
            self.apply(output_sections, primary_id);
        }
    }

    fn is_null(&self) -> bool {
        self.ty == sht::NULL
    }

    fn is_alloc(&self) -> bool {
        self.flags.contains(shf::ALLOC)
    }

    fn flags(&self) -> <Self::Platform as Platform>::SectionFlags {
        self.flags
    }

    fn ty(&self) -> <Self::Platform as Platform>::SectionType {
        self.ty
    }

    fn set_to_default_type(&mut self) {
        self.ty = sht::PROGBITS;
    }

    fn is_executable(&self) -> bool {
        self.flags.contains(shf::EXECINSTR)
    }

    fn is_tls(&self) -> bool {
        self.flags.contains(shf::TLS)
    }

    fn is_writable(&self) -> bool {
        self.flags.contains(shf::WRITE)
    }

    fn is_no_bits(&self) -> bool {
        self.ty == sht::NOBITS
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

impl std::fmt::Display for RawSymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.name))?;
        if let Some(version) = self.version_name {
            if self.is_default {
                write!(f, "@@")?;
            } else {
                write!(f, "@")?;
            }
            write!(f, "{}", String::from_utf8_lossy(version))?;
        }

        Ok(())
    }
}

pub(crate) struct VerneedTable<'data> {
    versym: &'data [Versym],
    version_names_by_index: Vec<Option<&'data [u8]>>,
}

impl<'data> VerneedTable<'data> {
    fn new<C: ElfClass>(file: &File<'data, C>) -> Result<Self> {
        Ok(Self {
            versym: file.versym,
            version_names_by_index: verneed_names_by_index(file)?,
        })
    }
}

impl<'data> platform::VerneedTable<'data> for VerneedTable<'data> {
    fn version_name(&self, local_symbol_index: object::SymbolIndex) -> Option<&'data [u8]> {
        let version_index = self.versym.get(local_symbol_index.0)?.0.get(LittleEndian);
        self.version_names_by_index
            .get(usize::from(version_index.index()))
            .copied()
            .flatten()
    }
}

fn verneed_names_by_index<'data, C: ElfClass>(
    file: &File<'data, C>,
) -> Result<Vec<Option<&'data [u8]>>> {
    let mut version_names = Vec::new();
    let endian = LittleEndian;

    if let Some((verneeds, string_table_index)) = &file.verneed {
        let strings = file
            .sections
            .strings(endian, file.data, *string_table_index)?;

        for r in verneeds.clone() {
            let (_verneed, aux_iterator) = r?;
            for aux in aux_iterator {
                let aux = aux?;
                let version_index = usize::from(aux.vna_other.get(endian));
                let name = aux.name(endian, strings)?;

                if version_names.len() <= version_index {
                    version_names.resize_with(version_index + 1, || None);
                }
                version_names[version_index] = Some(name);
            }
        }
    }

    Ok(version_names)
}

#[derive(Debug)]
pub(crate) struct VerneedInfo<'data, C: ElfClass> {
    pub(crate) defs: VerdefIterator<'data, C>,
    pub(crate) string_table_index: object::SectionIndex,

    /// Number of symbol versions that we're going to emit. This is the number of entries in
    /// `symbol_versions_needed` that are true. Computed after graph traversal.
    pub(crate) version_count: u16,
}

#[derive(Default)]
pub(crate) struct DynamicLayoutStateExt<'data, C: ElfClass> {
    /// Which symbol versions are needed. A symbol version is needed if a symbol with that version
    /// has been loaded. The first version has index 1, so we store it at offset 0.
    symbol_versions_needed: Vec<bool>,

    verneed_info: Option<VerneedInfo<'data, C>>,

    non_addressable_indexes: NonAddressableIndexes,

    /// Maps from addresses within the shared object to copy relocations at that address.
    copy_relocations: HashMap<u64, CopyRelocationInfo>,
}

#[derive(Debug)]
pub(crate) struct DynamicLayoutExt<'data, C: ElfClass> {
    /// Mapping from input versions to output versions. Input version 1 is at index 0.
    pub(crate) version_mapping: Vec<object::elf::VersionIndex>,

    pub(crate) verneed_info: Option<VerneedInfo<'data, C>>,

    /// Whether this is the last DynamicLayout that puts content into .gnu.version_r.
    pub(crate) is_last_verneed: bool,

    pub(crate) copy_relocation_symbols: Vec<SymbolId>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct NonAddressableIndexes {
    /// The version index that will be used for the next `.gnu.version_r` entry that we define.
    next_gnu_version_r_index: object::elf::VersionIndex,
}

impl platform::NonAddressableIndexes for NonAddressableIndexes {
    fn new<P: Platform>(symbol_db: &crate::symbol_db::SymbolDb<P>) -> Self {
        Self {
            // Allocate version indexes starting from after the local and global indexes and any
            // versions defined by a version script.
            next_gnu_version_r_index: object::elf::VER_NDX_GLOBAL
                + 1.max(symbol_db.version_script.version_count()),
        }
    }
}

struct CopyRelocationInfo {
    /// The symbol ID for which we'll actually generate the copy relocation. Initially, this is
    /// just the first symbol at a particular address for which we requested a copy relocation,
    /// then later we may update it to point to a different symbol if that first symbol was
    /// weak.
    symbol_id: SymbolId,

    is_weak: bool,
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct NonAddressableCounts {
    /// The number of shared objects that want to emit a verneed record.
    pub(crate) verneed_count: u64,
    /// The number of verdef records provided in version script.
    pub(crate) verdef_count: u16,
}

#[derive(Debug)]
pub(crate) struct EpilogueLayoutExt {
    pub(crate) sysv_hash_layout: Option<SysvHashLayout>,
    pub(crate) gnu_hash_layout: Option<GnuHashLayout>,
    pub(crate) verdefs: Option<Vec<VersionDef>>,
    build_id_size: Option<usize>,
    pub(crate) needs_eh_frame_terminator: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GnuHashLayout {
    pub(crate) num_defs: u32,
    pub(crate) bucket_count: u32,
    pub(crate) bloom_shift: u32,
    pub(crate) bloom_count: u32,
    pub(crate) symbol_base: u32,
}

fn create_gnu_hash_layout<C: ElfClass>(
    args: &ElfArgs,
    output_kind: OutputKind,
    dynamic_symbol_definitions: &mut [DynamicSymbolDefinition<'_, Elf<C>>],
) -> Option<GnuHashLayout> {
    if !args.hash_style.includes_gnu() || !output_kind.needs_dynamic() {
        return None;
    }

    // Our number of buckets is computed somewhat arbitrarily so that we have on average 2
    // symbols per bucket, but then we round up to a power of two.
    let num_defs = dynamic_symbol_definitions.len();
    let gnu_hash_layout = GnuHashLayout {
        num_defs: dynamic_symbol_definitions.len() as u32,
        bucket_count: (num_defs / 2).next_power_of_two() as u32,
        bloom_shift: 6,
        bloom_count: 1,
        // `symbol_base` is set later in `finalise_layout`.
        symbol_base: 0,
    };

    // If we're going to emit .gnu.hash, then we need to stort the dynamic symbols by bucket.
    // Tie-break by name for determinism. We can use an unstable sort because names should be
    // unique. We use a parallel sort because we're processing symbols from potentially many
    // input objects, so there can be a lot.
    dynamic_symbol_definitions.par_sort_unstable_by_key(|d| {
        (
            gnu_hash_layout.bucket_for_hash(d.format_specific.hash),
            d.name,
        )
    });

    Some(gnu_hash_layout)
}

impl GnuHashLayout {
    /// Allocates space required for .gnu.hash. Also sorts dynamic symbol definitions by their hash
    /// bucket as required by .gnu.hash.
    fn allocate<C: ElfClass>(&self, mem_sizes: &mut OutputSectionPartMap<u64>) {
        mem_sizes.increment(
            part_id::GNU_HASH,
            (size_of::<GnuHashHeader>()
                + C::GNU_HASH_BLOOM_SIZE as usize * self.bloom_count as usize
                + size_of::<u32>() * self.bucket_count as usize
                + size_of::<u32>() * self.num_defs as usize) as u64,
        );
    }

    pub(crate) fn bucket_for_hash(&self, hash: u32) -> u32 {
        hash % self.bucket_count
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct SysvHashLayout {
    pub(crate) bucket_count: u32,
    pub(crate) chain_count: u32,
}

#[derive(derive_more::Debug)]
pub(crate) struct VersionDef {
    #[debug("{}", String::from_utf8_lossy(name))]
    pub(crate) name: Vec<u8>,
    pub(crate) parent_index: Option<u16>,
}

impl SysvHashLayout {
    fn byte_size(self) -> Result<u64> {
        let words = 2u64
            .checked_add(u64::from(self.bucket_count))
            .and_then(|v| v.checked_add(u64::from(self.chain_count)))
            .context("Too many dynamic symbols for .hash")?;
        Ok(words * size_of::<u32>() as u64)
    }
}

fn finalise_gnu_version_size<'data, C: ElfClass>(
    mem_sizes: &mut OutputSectionPartMap<u64>,
    symbol_db: &SymbolDb<'data, crate::elf::Elf<C>>,
) {
    if symbol_db.output_kind.should_output_symbol_versions() {
        let num_dynamic_symbols = mem_sizes.get(part_id::DYNSYM) / C::SYMTAB_ENTRY_SIZE;
        // Note, sets the GNU_VERSION allocation rather than incrementing it. Assuming there are
        // multiple files in our group, we'll update this same value multiple times, each time
        // with a possibly revised dynamic symbol count. The important thing is that when we're
        // done finalising the group sizes, the GNU_VERSION size should be consistent with the
        // DYNSYM size.
        *mem_sizes.get_mut(part_id::GNU_VERSION) =
            num_dynamic_symbols * crate::elf::GNU_VERSION_ENTRY_SIZE;
    }
}

/// A "common information entry". This is part of the .eh_frame data in ELF.
#[derive(PartialEq, Eq, Hash)]
struct Cie<'data> {
    bytes: &'data [u8],
    eligible_for_deduplication: bool,
}

struct CieAtOffset<'data> {
    // TODO: Use or remove. I think we need this when we implement deduplication of CIEs.
    /// Offset within .eh_frame
    #[allow(dead_code)]
    offset: u32,
    cie: Cie<'data>,
}

enum ExceptionFrames<'data, C: ElfClass> {
    Rela(Vec<ExceptionFrame<'data, ElfRela<C>>>),
    Crel(Vec<ExceptionFrame<'data, ElfCrel<C>>>),
}

impl<'data, C: ElfClass> ExceptionFrames<'data, C> {
    fn extend(&mut self, other: Self) {
        match (self, other) {
            (ExceptionFrames::Rela(a), ExceptionFrames::Rela(b)) => a.extend(b),
            (ExceptionFrames::Crel(a), ExceptionFrames::Crel(b)) => a.extend(b),
            (a, b) if a.is_empty() => *a = b,
            _ => panic!("Mixed exception frame relocations"),
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            ExceptionFrames::Rela(a) => a.is_empty(),
            ExceptionFrames::Crel(a) => a.is_empty(),
        }
    }
}

impl<'data, C: ElfClass> Default for ExceptionFrames<'data, C> {
    fn default() -> Self {
        ExceptionFrames::Rela(Vec::new())
    }
}

struct ExceptionFrame<'data, R: Relocation> {
    /// The relocations that need to be processed if we load this frame.
    relocations: R::Sequence<'data>,

    /// Number of bytes required to store this frame.
    frame_size: u32,

    /// The index of the previous frame that is for the same section.
    previous_frame_for_section: Option<FrameIndex>,

    eh_frame_section_index: object::SectionIndex,
}

struct EhFrameSizes {
    num_frames: u64,
    eh_frame_size: u64,
}

impl<'data, C: ElfClass> ExceptionFrames<'data, C> {
    fn len(&self) -> usize {
        match self {
            ExceptionFrames::Rela(f) => f.len(),
            ExceptionFrames::Crel(f) => f.len(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct GroupLayoutExt {
    pub(crate) eh_frame_start_address: u64,
}

#[derive(Debug, Default)]
pub(crate) struct CommonGroupStateExt {
    pub(crate) exception_frame_relocations: usize,
    pub(crate) exception_frame_count: usize,
}

/// Return whether all DT_NEEDED entries for this shared object correspond to input files that
/// we have loaded.
fn has_complete_deps<'data, C: ElfClass>(
    file: &File<'data, C>,
    resources: &layout::GraphResources<'data, '_, Elf<C>>,
) -> bool {
    let Ok(dynamic_tags) = file.dynamic_tags() else {
        return true;
    };

    let e = LittleEndian;
    for entry in dynamic_tags {
        let value: u64 = entry.d_val(e).into();
        match entry.d_tag(e) {
            object::elf::DT_NEEDED => {
                let Ok(value) = value.try_into() else {
                    return false;
                };
                let Ok(name) = file.symbols.strings().get(value) else {
                    return false;
                };
                if !resources.layout_resources_ext.sonames.contains(name) {
                    return false;
                }
            }
            _ => {}
        }
    }

    true
}

#[derive(Debug)]
pub(crate) struct LayoutResourcesExt<'data> {
    sonames: Sonames<'data>,
    uses_tlsld: AtomicBool,
}

#[derive(Debug)]
struct Sonames<'data>(HashSet<&'data [u8]>);

impl<'data> Sonames<'data> {
    /// Builds an index of the DT_SONAMEs of the input dynamic objects. Note, that we include
    /// --as-needed shared objects that we're not actually linking against. This means that we can
    /// report --no-shlib-undefined errors for shared libraries that have all of their dependencies
    /// as inputs, even if we weren't going to add them as direct dependencies of our output file.
    fn new<C: ElfClass>(groups: &[Group<'data, Elf<C>>]) -> Self {
        timing_phase!("Build SONAME index");

        Sonames(
            groups
                .iter()
                .flat_map(|group| {
                    let objects = match group {
                        Group::Objects(objects) => *objects,
                        _ => &[],
                    };
                    objects.iter().filter_map(|input| {
                        input
                            .parsed
                            .object
                            .dynamic_tag_values()
                            .map(|tag_values| tag_values.lib_name(&input.parsed.input))
                    })
                })
                .collect(),
        )
    }

    fn contains(&self, name: &[u8]) -> bool {
        self.0.contains(name)
    }
}

impl platform::SegmentType for SegmentType {}

impl EpilogueLayoutExt {
    fn gnu_build_id_note_section_size<C: ElfClass>(&self) -> Option<u64> {
        Some(C::NOTE_HEADER_SIZE + GNU_NOTE_NAME.len() as u64 + self.build_id_size? as u64)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProgramSegmentDef {
    pub(crate) segment_type: SegmentType,
    pub(crate) segment_flags: SegmentFlags,
}

/// The different kinds of program segments that we generate based on section properties. Note, this
/// doesn't include the PT_GNU_STACK segment, since it isn't generated in response to any sections
/// because it doesn't contain any.
const PROGRAM_SEGMENT_DEFS: &[ProgramSegmentDef] = &[
    ProgramSegmentDef {
        segment_type: pt::PHDR,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::INTERP,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::NOTE,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::GNU_PROPERTY,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::LOAD,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::LOAD,
        segment_flags: pf::READABLE.with(pf::EXECUTABLE),
    },
    ProgramSegmentDef {
        segment_type: pt::LOAD,
        segment_flags: pf::READABLE.with(pf::WRITABLE),
    },
    ProgramSegmentDef {
        segment_type: pt::LOAD,
        segment_flags: pf::READABLE.with(pf::WRITABLE).with(pf::EXECUTABLE),
    },
    ProgramSegmentDef {
        segment_type: pt::TLS,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::GNU_EH_FRAME,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::GNU_SFRAME,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::DYNAMIC,
        segment_flags: pf::READABLE.with(pf::WRITABLE),
    },
    ProgramSegmentDef {
        segment_type: pt::GNU_RELRO,
        segment_flags: pf::READABLE,
    },
    ProgramSegmentDef {
        segment_type: pt::RISCV_ATTRIBUTES,
        segment_flags: pf::READABLE,
    },
];

pub(crate) const STACK_SEGMENT_DEF: ProgramSegmentDef = ProgramSegmentDef {
    segment_type: pt::GNU_STACK,
    segment_flags: pf::READABLE.with(pf::WRITABLE),
};

impl platform::ProgramSegmentDef for ProgramSegmentDef {
    fn is_writable(self) -> bool {
        self.segment_flags.contains(pf::WRITABLE)
    }

    fn is_executable(self) -> bool {
        self.segment_flags.contains(pf::EXECUTABLE)
    }

    fn always_keep(self) -> bool {
        false
    }

    fn is_loadable(self) -> bool {
        self.segment_type == pt::LOAD
    }

    fn is_stack(self) -> bool {
        self.segment_type == pt::GNU_STACK
    }

    fn is_tls(self) -> bool {
        self.segment_type == pt::TLS
    }

    fn order_key(self) -> usize {
        // Segment types that we put first. Other types
        const TYPE_ORDER: &[SegmentType] = &[pt::PHDR, pt::INTERP, pt::LOAD, pt::DYNAMIC];

        TYPE_ORDER
            .iter()
            .position(|t| *t == self.segment_type)
            .unwrap_or(TYPE_ORDER.len() + self.segment_type.0 as usize)
    }

    fn should_cut_rw_segment_when_ending(self) -> bool {
        self.segment_type == pt::GNU_RELRO
    }

    fn from_linker_script(ptype: u32, flags: u32) -> Self {
        Self {
            segment_type: SegmentType(ptype),
            segment_flags: SegmentFlags(flags),
        }
    }
}

impl std::fmt::Display for ProgramSegmentDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}, {}",
            pt::Display(self.segment_type),
            pf::Display(self.segment_flags),
        )
    }
}

#[derive(Debug)]
pub(crate) struct BuiltInSectionDetails<C: ElfClass> {
    pub(crate) kind: SectionKind<'static, Elf<C>>,
    pub(crate) section_flags: SectionFlags,
    /// Sections to try to link to. The first section that we're outputting is the one used.
    pub(crate) link: &'static [OutputSectionId],
    pub(crate) min_alignment: Alignment,
    pub(crate) element_size: u64,
    pub(crate) ty: SectionType,
    pub(crate) is_relro: bool,
    pub(crate) target_segment_type: Option<SegmentType>,
}

impl<C: ElfClass> Elf<C> {
    const DEFAULT_DEFS: BuiltInSectionDetails<C> = BuiltInSectionDetails {
        kind: Self::primary_section(&[]),
        section_flags: SectionFlags(0),
        link: &[],
        min_alignment: alignment::MIN,
        element_size: 0,
        ty: sht::NULL,
        is_relro: false,
        target_segment_type: None,
    };

    const fn primary_section(name: &'static [u8]) -> SectionKind<'static, Elf<C>> {
        SectionKind::Primary(SectionIdentity::new(SectionName(name), ()))
    }

    const SECTION_DEFINITIONS: [BuiltInSectionDetails<C>; ELF_NUM_BUILT_IN_SECTIONS] = {
        let mut defs = [Self::DEFAULT_DEFS; ELF_NUM_BUILT_IN_SECTIONS];

        // A section into which we write headers.
        defs[crate::output_section_id::FILE_HEADER.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(b""),
            section_flags: shf::ALLOC,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::PROGRAM_HEADERS.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(PROGRAM_HEADERS_SECTION_NAME),
            section_flags: shf::ALLOC,
            min_alignment: C::PROGRAM_HEADER_ALIGNMENT,
            target_segment_type: Some(pt::PHDR),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::SECTION_HEADERS.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(SECTION_HEADERS_SECTION_NAME),
            section_flags: shf::ALLOC,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::SHSTRTAB.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(SHSTRTAB_SECTION_NAME),
            ty: sht::STRTAB,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::STRTAB.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(STRTAB_SECTION_NAME),
            ty: sht::STRTAB,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::GOT.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(GOT_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::WRITE.with(shf::ALLOC),
            element_size: C::GOT_ENTRY_SIZE,
            min_alignment: C::GOT_ENTRY_ALIGNMENT,
            is_relro: true,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::GOT_RELR.as_usize()] = BuiltInSectionDetails {
            kind: SectionKind::Secondary(output_section_id::GOT),
            element_size: C::GOT_ENTRY_SIZE,
            min_alignment: C::GOT_ENTRY_ALIGNMENT,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::PLT_GOT.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(PLT_GOT_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::ALLOC.with(shf::EXECINSTR),
            element_size: crate::elf::PLT_ENTRY_SIZE,
            min_alignment: alignment::PLT,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::RELA_PLT.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(RELA_PLT_SECTION_NAME),
            ty: sht::RELA,
            section_flags: shf::ALLOC.with(shf::INFO_LINK),
            element_size: C::RELA_ENTRY_SIZE,
            link: &[output_section_id::DYNSYM, output_section_id::SYMTAB_LOCAL],
            min_alignment: C::RELA_ENTRY_ALIGNMENT,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::EH_FRAME.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(EH_FRAME_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::ALLOC,
            min_alignment: C::ADDRESS_ALIGNMENT,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::EH_FRAME_HDR.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(EH_FRAME_HDR_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::ALLOC,
            min_alignment: alignment::EH_FRAME_HDR,
            target_segment_type: Some(pt::GNU_EH_FRAME),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::SFRAME.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(SFRAME_SECTION_NAME),
            ty: sht::GNU_SFRAME,
            section_flags: shf::ALLOC,
            min_alignment: C::ADDRESS_ALIGNMENT,
            target_segment_type: Some(pt::GNU_SFRAME),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::DYNAMIC.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(DYNAMIC_SECTION_NAME),
            ty: sht::DYNAMIC,
            section_flags: shf::ALLOC.with(shf::WRITE),
            element_size: C::DYNAMIC_ENTRY_SIZE,
            link: &[output_section_id::DYNSTR],
            min_alignment: C::ADDRESS_ALIGNMENT,
            is_relro: true,
            target_segment_type: Some(pt::DYNAMIC),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::HASH.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(HASH_SECTION_NAME),
            ty: sht::HASH,
            section_flags: shf::ALLOC,
            link: &[output_section_id::DYNSYM],
            min_alignment: alignment::SYSV_HASH,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::GNU_HASH.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(GNU_HASH_SECTION_NAME),
            ty: sht::GNU_HASH,
            section_flags: shf::ALLOC,
            link: &[output_section_id::DYNSYM],
            min_alignment: C::GNU_HASH_ALIGNMENT,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::DYNSYM.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(DYNSYM_SECTION_NAME),
            ty: sht::DYNSYM,
            section_flags: shf::ALLOC,
            element_size: C::SYMTAB_ENTRY_SIZE,
            link: &[output_section_id::DYNSTR],
            min_alignment: C::SYMTAB_ENTRY_ALIGNMENT,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::DYNSTR.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(DYNSTR_SECTION_NAME),
            ty: sht::STRTAB,
            section_flags: shf::ALLOC,
            min_alignment: alignment::MIN,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::INTERP.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(INTERP_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::ALLOC,
            target_segment_type: Some(pt::INTERP),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::GNU_VERSION.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(GNU_VERSION_SECTION_NAME),
            ty: sht::GNU_VERSYM,
            section_flags: shf::ALLOC,
            element_size: size_of::<Versym>() as u64,
            min_alignment: alignment::VERSYM,
            link: &[output_section_id::DYNSYM],
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::GNU_VERSION_D.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(GNU_VERSION_D_SECTION_NAME),
            ty: sht::GNU_VERDEF,
            section_flags: shf::ALLOC,
            min_alignment: C::VERSION_D_ALIGNMENT,
            link: &[output_section_id::DYNSTR],
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::GNU_VERSION_R.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(GNU_VERSION_R_SECTION_NAME),
            ty: sht::GNU_VERNEED,
            section_flags: shf::ALLOC,
            min_alignment: C::VERSION_R_ALIGNMENT,
            link: &[output_section_id::DYNSTR],
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::NOTE_GNU_PROPERTY.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(NOTE_GNU_PROPERTY_SECTION_NAME),
            ty: sht::NOTE,
            section_flags: shf::ALLOC,
            min_alignment: C::GNU_PROPERTY_ALIGNMENT,
            target_segment_type: Some(pt::GNU_PROPERTY),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::NOTE_GNU_BUILD_ID.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(NOTE_GNU_BUILD_ID_SECTION_NAME),
            ty: sht::NOTE,
            section_flags: shf::ALLOC,
            min_alignment: alignment::NOTE_GNU_BUILD_ID,
            ..Self::DEFAULT_DEFS
        };
        // Multi-part generated sections
        defs[output_section_id::SYMTAB_LOCAL.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(SYMTAB_SECTION_NAME),
            ty: sht::SYMTAB,
            element_size: C::SYMTAB_ENTRY_SIZE,
            min_alignment: C::SYMTAB_ENTRY_ALIGNMENT,
            link: &[output_section_id::STRTAB],
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::SYMTAB_GLOBAL.as_usize()] = BuiltInSectionDetails {
            kind: SectionKind::Secondary(output_section_id::SYMTAB_LOCAL),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::RELA_DYN_RELATIVE.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(RELA_DYN_SECTION_NAME),
            ty: sht::RELA,
            section_flags: shf::ALLOC,
            element_size: C::RELA_ENTRY_SIZE,
            min_alignment: C::RELA_ENTRY_ALIGNMENT,
            link: &[output_section_id::DYNSYM],
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::RELA_DYN_GENERAL.as_usize()] = BuiltInSectionDetails {
            kind: SectionKind::Secondary(output_section_id::RELA_DYN_RELATIVE),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::RELR_DYN.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(RELR_DYN_SECTION_NAME),
            ty: sht::RELR,
            section_flags: shf::ALLOC,
            element_size: C::RELR_ENTRY_SIZE,
            min_alignment: C::RELR_ENTRY_ALIGNMENT,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::RISCV_ATTRIBUTES.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(RISCV_ATTRIBUTES_SECTION_NAME),
            ty: sht::RISCV_ATTRIBUTES,
            target_segment_type: Some(pt::RISCV_ATTRIBUTES),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::RELRO_PADDING.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(RELRO_PADDING_SECTION_NAME),
            ty: sht::NOBITS,
            section_flags: shf::ALLOC.with(shf::WRITE),
            is_relro: true,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::SYMTAB_SHNDX_LOCAL.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(SYMTAB_SHNDX_SECTION_NAME),
            ty: sht::SYMTAB_SHNDX,
            element_size: SYMTAB_SHNDX_ENTRY_SIZE,
            min_alignment: alignment::SYMTAB_SHNDX_ENTRY,
            link: &[output_section_id::SYMTAB_LOCAL],
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::SYMTAB_SHNDX_GLOBAL.as_usize()] = BuiltInSectionDetails {
            kind: SectionKind::Secondary(output_section_id::SYMTAB_SHNDX_LOCAL),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::GDB_INDEX.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(GDB_INDEX_SECTION_NAME),
            ty: sht::PROGBITS,
            ..Self::DEFAULT_DEFS
        };
        // Start of regular sections
        defs[output_section_id::RODATA.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(RODATA_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::ALLOC,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::INIT_ARRAY.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(INIT_ARRAY_SECTION_NAME),
            ty: sht::INIT_ARRAY,
            section_flags: shf::ALLOC.with(shf::WRITE),
            element_size: C::ADDRESS_SIZE,
            min_alignment: C::ADDRESS_ALIGNMENT,
            is_relro: true,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::FINI_ARRAY.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(FINI_ARRAY_SECTION_NAME),
            ty: sht::FINI_ARRAY,
            section_flags: shf::ALLOC.with(shf::WRITE),
            element_size: C::ADDRESS_SIZE,
            min_alignment: C::ADDRESS_ALIGNMENT,
            is_relro: true,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::PREINIT_ARRAY.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(PREINIT_ARRAY_SECTION_NAME),
            ty: sht::PREINIT_ARRAY,
            section_flags: shf::ALLOC.with(shf::WRITE),
            is_relro: true,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::TEXT.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(TEXT_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::ALLOC.with(shf::EXECINSTR),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::INIT.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(INIT_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::ALLOC.with(shf::EXECINSTR),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::FINI.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(FINI_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::ALLOC.with(shf::EXECINSTR),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::DATA.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(DATA_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::ALLOC.with(shf::WRITE),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::TDATA.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(TDATA_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::WRITE.with(shf::ALLOC).with(shf::TLS),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::TBSS.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(TBSS_SECTION_NAME),
            ty: sht::NOBITS,
            section_flags: shf::WRITE.with(shf::ALLOC).with(shf::TLS),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::BSS.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(BSS_SECTION_NAME),
            ty: sht::NOBITS,
            section_flags: shf::ALLOC.with(shf::WRITE),
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::COMMENT.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(COMMENT_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::STRINGS.with(shf::MERGE),
            element_size: 1,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::GCC_EXCEPT_TABLE.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(GCC_EXCEPT_TABLE_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::ALLOC,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::NOTE_ABI_TAG.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(NOTE_ABI_TAG_SECTION_NAME),
            ty: sht::NOTE,
            section_flags: shf::ALLOC,
            ..Self::DEFAULT_DEFS
        };
        defs[output_section_id::DATA_REL_RO.as_usize()] = BuiltInSectionDetails {
            kind: Self::primary_section(DATA_REL_RO_SECTION_NAME),
            ty: sht::PROGBITS,
            section_flags: shf::ALLOC.with(shf::WRITE),
            is_relro: true,
            ..Self::DEFAULT_DEFS
        };

        defs
    };
}

impl<C: ElfClass> platform::BuiltInSectionDetails for BuiltInSectionDetails<C> {}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DynamicSymbolDefinitionExt {
    pub(crate) hash: u32,
    pub(crate) version: object::elf::VersymIndex,
}

fn load_section_relocations<
    'scope,
    'data,
    C: ElfClass,
    A: Arch<Platform = Elf<C>>,
    R: Relocation<Platform = Elf<C>>,
>(
    state: &layout::ObjectLayoutState<'data, Elf<C>>,
    common: &mut CommonGroupState<'data, Elf<C>>,
    queue: &mut layout::LocalWorkQueue,
    resources: &'scope layout::GraphResources<'data, '_, Elf<C>>,
    section_index: object::SectionIndex,
    relocations: impl Iterator<Item = R>,
    scope: &Scope<'scope>,
) -> Result {
    let mut modifier = RelocationModifier::Normal;
    let mut relr_writer = RelrEncoder::default();
    for rel in relocations {
        if modifier == RelocationModifier::SkipNextRelocation {
            modifier = RelocationModifier::Normal;
            continue;
        }
        let section_header = state.object.section(section_index)?;
        let section_part_id =
            state.section_part_id(section_index, &resources.symbol_db.section_part_ids);
        modifier = process_relocation::<C, A, R>(
            state,
            common,
            &rel,
            section_header,
            section_part_id,
            resources,
            queue,
            false,
            scope,
            &mut relr_writer,
        )
        .with_context(|| {
            format!(
                "Failed to copy section {} from file {state}",
                layout::section_debug::<Elf<C>>(state.object, section_index)
            )
        })?;
    }

    Ok(())
}

pub(crate) const fn relr_bitmap_slots<C: ElfClass>() -> u64 {
    C::RELR_ENTRY_SIZE * 8 - 1
}

struct RelrBitmap<C: ElfClass> {
    range: Range<u64>,
    encoded: u64,
    class: PhantomData<C>,
}

impl<C: ElfClass> RelrBitmap<C> {
    // Return bitmap starting after the current address.
    fn after(address: u64) -> Self {
        let start = address + C::RELR_ENTRY_SIZE;
        Self {
            range: start..start + relr_bitmap_slots::<C>() * C::RELR_ENTRY_SIZE,
            encoded: 1,
            class: PhantomData,
        }
    }

    // Return bitmap that will follow after the current bitmap range.
    fn next(&self) -> Self {
        let address_range = relr_bitmap_slots::<C>() * C::RELR_ENTRY_SIZE;
        Self {
            range: self.range.start + address_range..self.range.end + address_range,
            encoded: 1,
            class: PhantomData,
        }
    }

    // Encoding address if properly aligned and fits in the current range. If fits, true is
    // returned.
    fn insert(&mut self, address: u64) -> bool {
        let offset = address.wrapping_sub(self.range.start);
        if !self.range.contains(&address) || !offset.is_multiple_of(C::RELR_ENTRY_SIZE) {
            false
        } else {
            self.encoded |= 1 << (offset / C::RELR_ENTRY_SIZE + 1);
            true
        }
    }
}

/// Tracks RELR bitmap packing within one input section. Runs deliberately don't
/// cross section boundaries because layout of separate sections is parallel.
#[derive(Default)]
enum RelrState<C: ElfClass> {
    #[default]
    NoRun,
    AddressOnly {
        next_bitmap: RelrBitmap<C>,
    },
    WithBitmap {
        bitmap: RelrBitmap<C>,
    },
}

#[derive(Clone, Copy)]
pub(crate) enum RelrEntryEncoding {
    New,
    Update,
}

#[derive(Default)]
pub(crate) struct RelrEncoder<C: ElfClass> {
    state: RelrState<C>,
}

// RELR bitmap packing state used for both allocation and the actual writing of relocations
// to the output stream.
impl<C: ElfClass> RelrEncoder<C> {
    pub(crate) fn encode(
        &mut self,
        address: u64,
        mut encode_fn: impl FnMut(u64, RelrEntryEncoding) -> Result,
    ) -> Result {
        self.state = match std::mem::take(&mut self.state) {
            RelrState::NoRun => {
                encode_fn(address, RelrEntryEncoding::New)?;
                RelrState::AddressOnly {
                    next_bitmap: RelrBitmap::after(address),
                }
            }
            RelrState::AddressOnly { mut next_bitmap } => {
                if next_bitmap.insert(address) {
                    encode_fn(next_bitmap.encoded, RelrEntryEncoding::New)?;
                    RelrState::WithBitmap {
                        bitmap: next_bitmap,
                    }
                } else {
                    encode_fn(address, RelrEntryEncoding::New)?;
                    RelrState::AddressOnly {
                        next_bitmap: RelrBitmap::after(address),
                    }
                }
            }
            RelrState::WithBitmap { mut bitmap } => {
                if bitmap.insert(address) {
                    encode_fn(bitmap.encoded, RelrEntryEncoding::Update)?;
                    RelrState::WithBitmap { bitmap }
                } else {
                    // Current window has bits — try next window.
                    // lld only advances to a new bitmap if the current one is
                    // non-empty (breaks on empty bitmap). Same rule here.
                    let mut next_bitmap = bitmap.next();
                    if next_bitmap.insert(address) {
                        encode_fn(next_bitmap.encoded, RelrEntryEncoding::New)?;
                        RelrState::WithBitmap {
                            bitmap: next_bitmap,
                        }
                    } else {
                        // Gap too large — start new address entry.
                        encode_fn(address, RelrEntryEncoding::New)?;
                        RelrState::AddressOnly {
                            next_bitmap: RelrBitmap::after(address),
                        }
                    }
                }
            }
        };
        Ok(())
    }
}

#[inline(always)]
fn process_relocation<
    'data,
    'scope,
    C: ElfClass,
    A: Arch<Platform = Elf<C>>,
    R: Relocation<Platform = Elf<C>>,
>(
    object: &ObjectLayoutState<'data, Elf<C>>,
    common: &mut CommonGroupState<'data, Elf<C>>,
    rel: &R,
    section: &<A::Platform as Platform>::SectionHeader,
    section_part_id: PartId,
    resources: &'scope layout::GraphResources<'data, '_, Elf<C>>,
    queue: &mut layout::LocalWorkQueue,
    is_debug_section: bool,
    scope: &Scope<'scope>,
    relr_writer: &mut RelrEncoder<C>,
) -> Result<RelocationModifier> {
    let Some(local_sym_index) = rel.symbol() else {
        return Ok(RelocationModifier::Normal);
    };

    let mut classified =
        classify_symbol_relocation::<C, A, R>(object, rel, section, local_sym_index, resources)?;

    materialize_relocation_requirements::<C, A, R>(
        common,
        rel,
        section,
        resources,
        is_debug_section,
        relr_writer,
        &mut classified,
    )?;

    let previous_flags =
        note_relocation_symbol_reference::<C, A>(&classified, resources, queue, scope);

    if !is_debug_section {
        crate::thunks::handle_thunk_extensions_for_relocation::<A>(
            section_part_id,
            resources,
            classified.local_symbol_id,
            classified.symbol_id,
            classified.r_type,
        );
    }

    layout::check_for_undefined::<A>(
        object,
        section,
        classified.rel_offset,
        local_sym_index,
        classified.flags,
        classified.symbol_id,
        resources,
    )?;

    if classified.flags_to_add.needs_copy_relocation() && !previous_flags.needs_copy_relocation() {
        queue.send_copy_relocation_request::<A>(classified.symbol_id, resources, scope);
    }

    Ok(classified.next_modifier)
}

/// Symbol and relocation-kind info needed for both GC edges and output accounting.
struct ClassifiedSymbolRelocation {
    local_symbol_id: SymbolId,
    symbol_id: SymbolId,
    /// Definition (and local) value flags before this relocation's contributions.
    flags: ValueFlags,
    flags_to_add: ValueFlags,
    rel_offset: u64,
    r_type: object::elf::RelocationType,
    rel_kind: linker_utils::elf::RelocationKind,
    next_modifier: RelocationModifier,
    section_is_writable: bool,
}

/// Resolve the relocated symbol and determine the effective relocation kind / initial flags.
#[inline(always)]
fn classify_symbol_relocation<
    'data,
    C: ElfClass,
    A: Arch<Platform = Elf<C>>,
    R: Relocation<Platform = Elf<C>>,
>(
    object: &ObjectLayoutState<'data, Elf<C>>,
    rel: &R,
    section: &<A::Platform as Platform>::SectionHeader,
    local_sym_index: object::SymbolIndex,
    resources: &layout::GraphResources<'data, '_, Elf<C>>,
) -> Result<ClassifiedSymbolRelocation> {
    let args = resources.symbol_db.args;
    let symbol_db = resources.symbol_db;
    let local_symbol_id = object.symbol_id_range.input_to_id(local_sym_index);
    let symbol_id = symbol_db.definition(local_symbol_id);
    let mut flags = resources.local_flags_for_symbol(symbol_id);
    flags.merge(resources.local_flags_for_symbol(local_symbol_id));
    let rel_offset = rel.offset();
    let r_type = rel.raw_type();
    let section_flags = section.sh_flags(LittleEndian);

    let mut next_modifier = RelocationModifier::Normal;
    let rel_info = if let Some(relaxation) = A::new_relaxation(
        r_type,
        object.object.raw_section_data(section)?,
        rel_offset,
        flags,
        symbol_db.output_kind,
        section_flags,
        true,
        None,
    )
    .filter(|relaxation| args.should_relax() || relaxation.is_mandatory())
    {
        next_modifier = relaxation.next_modifier();
        relaxation.rel_info()
    } else {
        A::relocation_from_raw(r_type)?
    };

    Ok(ClassifiedSymbolRelocation {
        local_symbol_id,
        symbol_id,
        flags,
        flags_to_add: layout::resolution_flags(rel_info.kind),
        rel_offset,
        r_type,
        rel_kind: rel_info.kind,
        next_modifier,
        section_is_writable: section.is_writable(),
    })
}

/// Account for GOT/PLT/dynamic-reloc/TLS sizes implied by this relocation.
#[inline(always)]
fn materialize_relocation_requirements<
    'data,
    C: ElfClass,
    A: Arch<Platform = Elf<C>>,
    R: Relocation<Platform = Elf<C>>,
>(
    common: &mut CommonGroupState<'data, Elf<C>>,
    rel: &R,
    section: &<A::Platform as Platform>::SectionHeader,
    resources: &layout::GraphResources<'data, '_, Elf<C>>,
    is_debug_section: bool,
    relr_writer: &mut RelrEncoder<C>,
    classified: &mut ClassifiedSymbolRelocation,
) -> Result {
    let args = resources.symbol_db.args;
    let symbol_db = resources.symbol_db;
    let section_flags = section.sh_flags(LittleEndian);
    let flags = classified.flags;
    let symbol_id = classified.symbol_id;
    let r_type = classified.r_type;
    let section_is_writable = classified.section_is_writable;
    let flags_to_add = &mut classified.flags_to_add;
    let rel_kind = classified.rel_kind;

    if !section_flags.is_alloc() {
        // Non-alloc sections never get dynamic relocations, so there's nothing to do here.
    } else if rel_kind.is_tls() {
        if does_relocation_require_static_tls(rel_kind) {
            resources
                .has_static_tls
                .store(true, atomic::Ordering::Relaxed);
        }

        if layout::needs_tlsld(rel_kind)
            && !resources
                .layout_resources_ext
                .uses_tlsld
                .load(atomic::Ordering::Relaxed)
        {
            resources
                .layout_resources_ext
                .uses_tlsld
                .store(true, atomic::Ordering::Relaxed);
        }
    } else if flags_to_add.needs_direct() && flags.is_interposable() {
        if symbol_db.output_kind.is_shared_object()
            && A::is_disallowed_for_interposable_symbols(r_type)
        {
            bail!(
                "relocation {} cannot be used when making a shared object; \
                recompile with -fPIC",
                A::rel_type_to_string(r_type),
            );
        }
        if section_is_writable {
            common.allocate(part_id::RELA_DYN_GENERAL, C::RELA_ENTRY_SIZE);
        } else if flags.is_function() {
            // Create a PLT entry for the function and refer to that instead.
            flags_to_add.remove(ValueFlags::DIRECT);
            *flags_to_add |= ValueFlags::PLT | ValueFlags::GOT;
        } else if !flags.is_absolute() {
            match args.copy_relocations_enabled() {
                crate::args::CopyRelocations::Allowed => {
                    *flags_to_add |= ValueFlags::COPY_RELOCATION;
                }
                crate::args::CopyRelocations::Disallowed(reason) => {
                    // We don't at present support text relocations, so if we can't apply a copy
                    // relocation, we error instead.
                    bail!(
                        "Direct relocation ({}) to dynamic symbol from non-writable section, \
                        but copy relocations are disabled because {reason}. {}",
                        A::rel_type_to_string(r_type),
                        resources.symbol_debug(symbol_id),
                    );
                }
            }
        }
    } else if flags.is_ifunc()
        && rel_kind == RelocationKind::Absolute
        && section_is_writable
        && symbol_db.output_kind.is_relocatable()
    {
        common.allocate(part_id::RELA_DYN_GENERAL, C::RELA_ENTRY_SIZE);
    } else if symbol_db.output_kind.is_relocatable()
        && rel_kind == RelocationKind::Absolute
        && flags.is_address()
    {
        if section_is_writable {
            // Odd offsets can't be encoded as RELR address entries (LSB used as
            // bitmap marker), so fall back to RELA for them.
            if resources.symbol_db.args.is_relr_enabled() && rel.offset().is_multiple_of(2) {
                relr_writer.encode(rel.offset(), |_, encoding| {
                    if matches!(encoding, RelrEntryEncoding::New) {
                        common.allocate(part_id::RELR_DYN, C::RELR_ENTRY_SIZE);
                    }
                    Ok(())
                })?;
            } else {
                common.allocate(part_id::RELA_DYN_RELATIVE, C::RELA_ENTRY_SIZE);
            }
        } else if !is_debug_section {
            bail!(
                "Cannot apply relocation {} to read-only section. \
                Please recompile with -fPIC or link with -no-pie",
                A::rel_type_to_string(r_type),
            );
        }
    }

    // For ifunc symbols with GOT-relative references (like R_X86_64_GOTPCRELX), we need a
    // separate GOT entry for address equality. The main GOT entry will be used by the PLT stub
    // with an IRELATIVE relocation, while this extra entry will contain the PLT stub address so
    // that all references to the ifunc return the same address.

    let relocation_needs_got = flags_to_add.needs_got();

    if flags.is_ifunc() && !symbol_db.output_kind.is_static_executable() {
        *flags_to_add |= ValueFlags::GOT | ValueFlags::PLT;
    }

    if flags.is_ifunc() && relocation_needs_got && !symbol_db.output_kind.is_relocatable() {
        *flags_to_add |= ValueFlags::IFUNC_GOT_FOR_ADDRESS;
    }

    Ok(())
}

/// Record that a live section references `classified.symbol_id` and enqueue graph work if needed.
#[inline(always)]
fn note_relocation_symbol_reference<'data, 'scope, C: ElfClass, A: Arch<Platform = Elf<C>>>(
    classified: &ClassifiedSymbolRelocation,
    resources: &'scope layout::GraphResources<'data, '_, Elf<C>>,
    queue: &mut layout::LocalWorkQueue,
    scope: &Scope<'scope>,
) -> ValueFlags {
    let symbol_id = classified.symbol_id;
    let flags = classified.flags;
    let flags_to_add = classified.flags_to_add;

    let atomic_flags = &resources.per_symbol_flags.get_atomic(symbol_id);
    let previous_flags = atomic_flags.fetch_or(flags_to_add);

    if !previous_flags.has_resolution() {
        if flags.is_ifunc() && resources.symbol_db.output_kind.is_static_executable() {
            atomic_flags.fetch_or(ValueFlags::GOT | ValueFlags::PLT);
        }

        queue.send_symbol_request::<A>(symbol_id, resources, scope);
    }

    previous_flags
}

/// Returns whether the supplied relocation type requires static TLS. If true and we're writing a
/// shared object, then the STATIC_TLS will be set in the shared object which is a signal to the
/// runtime loader that the shared object cannot be loaded at runtime (e.g. with dlopen).
fn does_relocation_require_static_tls(rel_kind: RelocationKind) -> bool {
    layout::resolution_flags(rel_kind) == ValueFlags::GOT_TLS_OFFSET
}

#[derive(Default, Debug)]
pub(crate) struct PreludeLayoutStateExt {
    needs_tlsld_got_entry: bool,
    shstrtab_size: u64,
}

#[derive(Default, Debug)]
pub(crate) struct PreludeLayoutExt {
    pub(crate) tlsld_got_entry: Option<NonZeroU64>,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ResolutionExt {
    /// The base GOT address for this resolution. For pointers to symbols the GOT entry will
    /// contain a single pointer. For TLS variables there can be up to 3 pointers. If
    /// ValueFlags::GOT_TLS_OFFSET is set, then that will be the first value. If
    /// ValueFlags::GOT_TLS_MODULE is set, then there will be a pair of values (module and
    /// offset within module).
    pub(crate) got_address: Option<NonZeroU64>,
    pub(crate) plt_address: Option<NonZeroU64>,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SymtabShndxEntry {
    pub(crate) _shndx: u32,
}

/// Returns true if this GOT entry should go to GOT_RELR (bitmap-packed)
/// rather than GOT (flat RELR or RELA).
pub(crate) fn is_got_relr_eligible(
    flags: ValueFlags,
    has_dynamic_symbol: bool,
    args: &ElfArgs,
    output_kind: OutputKind,
) -> bool {
    args.is_relr_enabled()
        && !flags.is_ifunc()
        && !has_dynamic_symbol
        && flags.is_address()
        && !flags.is_downgraded_to_local()
        && output_kind.is_relocatable()
}

fn got_relr_bitmap_relr_count<C: ElfClass>(n: u64) -> u64 {
    if n == 0 {
        0
    } else {
        1 + n.saturating_sub(1).div_ceil(relr_bitmap_slots::<C>())
    }
}

fn allocate_got<C: ElfClass>(
    num_entries: u64,
    memory_offsets: &mut OutputSectionPartMap<u64>,
) -> NonZeroU64 {
    let got_address = NonZeroU64::new(*memory_offsets.get(part_id::GOT)).unwrap();
    memory_offsets.increment(part_id::GOT, C::GOT_ENTRY_SIZE * num_entries);
    got_address
}

fn allocate_got_relr<C: ElfClass>(memory_offsets: &mut OutputSectionPartMap<u64>) -> NonZeroU64 {
    let got_address = NonZeroU64::new(*memory_offsets.get(part_id::GOT_RELR)).unwrap();
    memory_offsets.increment(part_id::GOT_RELR, C::GOT_ENTRY_SIZE);
    got_address
}

fn allocate_plt(memory_offsets: &mut OutputSectionPartMap<u64>) -> NonZeroU64 {
    let plt_address = NonZeroU64::new(*memory_offsets.get(part_id::PLT_GOT)).unwrap();
    memory_offsets.increment(part_id::PLT_GOT, elf::PLT_ENTRY_SIZE);
    plt_address
}

impl<C: ElfClass> Resolution<Elf<C>> {
    pub(crate) fn got_address(&self) -> Result<u64> {
        Ok(self
            .format_specific
            .got_address
            .context("Missing GOT address")?
            .get())
    }

    pub(crate) fn got_address_for_relocation(&self) -> Result<u64> {
        let mut got_address = self.got_address()?;
        if self.flags.needs_ifunc_got_for_address() {
            got_address += C::GOT_ENTRY_SIZE;
        }
        Ok(got_address)
    }

    pub(crate) fn tlsgd_got_address(&self) -> Result<u64> {
        debug_assert_bail!(
            self.flags.needs_got_tls_module(),
            "Called tlsgd_got_address without GOT_TLS_MODULE being set"
        );
        // If we've got both a GOT_TLS_OFFSET and a GOT_TLS_MODULE, then the latter comes second.
        let mut got_address = self.got_address()?;
        if self.flags.needs_got_tls_offset() {
            got_address += C::GOT_ENTRY_SIZE;
        }
        Ok(got_address)
    }

    pub(crate) fn tls_descriptor_got_address(&self) -> Result<u64> {
        debug_assert_bail!(
            self.flags.needs_got_tls_descriptor(),
            "Called tls_descriptor_got_address without GOT_TLS_DESCRIPTOR being set"
        );
        // We might have both GOT_TLS_OFFSET, GOT_TLS_MODULE and GOT_TLS_DESCRIPTOR at the same time
        // for a single symbol. Then the TLS descriptor comes as the last one.
        let mut got_address = self.got_address()?;
        if self.flags.needs_got_tls_offset() {
            got_address += C::GOT_ENTRY_SIZE;
        }
        if self.flags.needs_got_tls_module() {
            got_address += 2 * C::GOT_ENTRY_SIZE;
        }

        Ok(got_address)
    }

    pub(crate) fn plt_address(&self) -> Result<u64> {
        Ok(self
            .format_specific
            .plt_address
            .context("Missing PLT address")?
            .get())
    }

    #[inline(always)]
    pub(crate) fn value_with_addend<'data>(
        &self,
        addend: i64,
        symbol_index: object::SymbolIndex,
        object_layout: &ObjectLayout<'data, Elf<C>>,
        section_part_ids: &[PartId],
        merged_strings: &OutputSectionMap<MergedStringsSection>,
        merged_string_start_addresses: &MergedStringStartAddresses,
    ) -> Result<u64> {
        if self.flags.is_ifunc() {
            return Ok(self.plt_address()?.wrapping_add(addend as u64));
        }

        // For most symbols, `raw_value` won't be zero, so we can save ourselves from looking up the
        // section to see if it's a string-merge section. For string-merge symbols with names,
        // `raw_value` will have already been computed, so we can avoid computing it again.
        if self.raw_value == 0
            && let Some(r) = crate::string_merging::get_merged_string_output_address::<Elf<C>>(
                symbol_index,
                addend,
                object_layout.object,
                &object_layout.sections,
                section_part_ids,
                object_layout.section_id_range,
                merged_strings,
                merged_string_start_addresses,
                false,
            )?
        {
            if self.raw_value != 0 {
                bail!("Merged string resolution has value 0x{}", self.raw_value);
            }
            return Ok(r);
        }
        Ok(self.raw_value.wrapping_add(addend as u64))
    }
}

#[derive(Debug, Default)]
pub(crate) struct ResolvedObjectExt<'data> {
    debug_index_sections: Vec<InputDebugIndexSection<'data>>,
}

/// Rules that map input sections to built-in output sections when no linker script is in use.
const DEFAULT_SECTION_PLACEMENT_RULES: &[SectionRule<'static>] = &[
    SectionRule::exact_section_keep(secnames::INIT_SECTION_NAME, output_section_id::INIT),
    SectionRule::exact_section_keep(secnames::FINI_SECTION_NAME, output_section_id::FINI),
    SectionRule::exact_section_keep(
        secnames::PREINIT_ARRAY_SECTION_NAME,
        output_section_id::PREINIT_ARRAY,
    ),
    SectionRule::exact_section_keep(secnames::COMMENT_SECTION_NAME, output_section_id::COMMENT),
    SectionRule::exact_section_keep(
        secnames::NOTE_ABI_TAG_SECTION_NAME,
        output_section_id::NOTE_ABI_TAG,
    ),
    SectionRule::exact_section(
        secnames::NOTE_GNU_BUILD_ID_SECTION_NAME,
        output_section_id::NOTE_GNU_BUILD_ID,
    ),
    SectionRule::prefix_section(secnames::RODATA_SECTION_NAME, output_section_id::RODATA),
    SectionRule::prefix_section(secnames::TEXT_SECTION_NAME, output_section_id::TEXT),
    SectionRule::prefix_section(
        secnames::DATA_REL_RO_SECTION_NAME,
        output_section_id::DATA_REL_RO,
    ),
    SectionRule::prefix_section(secnames::DATA_SECTION_NAME, output_section_id::DATA),
    SectionRule::prefix_section(secnames::BSS_SECTION_NAME, output_section_id::BSS),
    SectionRule::prefix_section_sort(
        secnames::INIT_ARRAY_SECTION_NAME,
        output_section_id::INIT_ARRAY,
    ),
    SectionRule::prefix_section_sort(secnames::CTORS_SECTION_NAME, output_section_id::INIT_ARRAY),
    SectionRule::prefix_section_sort(
        secnames::FINI_ARRAY_SECTION_NAME,
        output_section_id::FINI_ARRAY,
    ),
    SectionRule::prefix_section_sort(secnames::DTORS_SECTION_NAME, output_section_id::FINI_ARRAY),
    SectionRule::prefix_section(secnames::TDATA_SECTION_NAME, output_section_id::TDATA),
    SectionRule::prefix_section(secnames::TBSS_SECTION_NAME, output_section_id::TBSS),
    SectionRule::prefix_section(
        secnames::GCC_EXCEPT_TABLE_SECTION_NAME,
        output_section_id::GCC_EXCEPT_TABLE,
    ),
];

/// Rules for input sections that the linker processes itself instead of copying them into an output
/// section.
const LINKER_MANAGED_SECTION_RULES: &[SectionRule<'static>] = &[
    SectionRule::prefix(secnames::RELA_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::prefix(secnames::CREL_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::exact(
        secnames::NOTE_GNU_STACK_SECTION_NAME,
        SectionRuleOutcome::NoteGnuStack,
    ),
    SectionRule::exact(secnames::STRTAB_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::SYMTAB_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::SHSTRTAB_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::GROUP_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::EH_FRAME_SECTION_NAME, SectionRuleOutcome::EhFrame),
    SectionRule::exact(
        secnames::NOTE_GNU_PROPERTY_SECTION_NAME,
        SectionRuleOutcome::NoteGnuProperty,
    ),
    SectionRule::exact(
        secnames::RISCV_ATTRIBUTES_SECTION_NAME,
        SectionRuleOutcome::RiscVAttribute,
    ),
    SectionRule::exact(
        secnames::SYMTAB_SHNDX_SECTION_NAME,
        SectionRuleOutcome::Discard,
    ),
    SectionRule::prefix(b".debug_", SectionRuleOutcome::Debug),
];

fn init_fini_priority(name: &[u8]) -> Option<u16> {
    if name == secnames::INIT_ARRAY_SECTION_NAME || name == secnames::FINI_ARRAY_SECTION_NAME {
        return Some(u16::MAX);
    }

    if let Some(rest) = name.strip_prefix(b".init_array.") {
        return parse_priority_suffix(rest);
    }

    if let Some(rest) = name.strip_prefix(b".fini_array.") {
        return parse_priority_suffix(rest);
    }

    // .ctors and .dtors without suffix have the same priority as .init_array/.fini_array
    if name == secnames::CTORS_SECTION_NAME || name == secnames::DTORS_SECTION_NAME {
        return Some(u16::MAX);
    }

    // .ctors uses descending order (65535 = lowest priority, 0 = highest)
    // while .init_array uses ascending order (0 = highest priority, 65535 = lowest)
    if let Some(rest) = name.strip_prefix(b".ctors.") {
        return parse_priority_suffix(rest).map(|p| u16::MAX.saturating_sub(p));
    }

    if let Some(rest) = name.strip_prefix(b".dtors.") {
        return parse_priority_suffix(rest).map(|p| u16::MAX.saturating_sub(p));
    }

    None
}

fn parse_priority_suffix(suffix: &[u8]) -> Option<u16> {
    if suffix.is_empty() || !suffix.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let value = core::str::from_utf8(suffix).ok()?.parse::<u32>().ok()?;
    Some(u16::try_from(value).unwrap_or(u16::MAX))
}

pub(crate) fn program_headers_size<C: ElfClass>(header_info: &layout::HeaderInfo) -> u64 {
    u64::from(C::PROGRAM_HEADER_SIZE) * header_info.active_segment_ids.len() as u64
}

fn section_headers_size<C: ElfClass>(header_info: &layout::HeaderInfo) -> u64 {
    u64::from(C::SECTION_HEADER_SIZE) * u64::from(header_info.num_output_sections_with_content)
}

/// Where we've decided that we need copy relocations, look for symbols with the same address as the
/// symbols with copy relocations. If the other symbol is non-weak, then we do the copy relocation
/// for that symbol instead. We also request dynamic symbol definitions for each copy relocation.
/// For that reason, this needs to be done before we merge dynamic symbol definitions.
fn finalise_copy_relocations<'data, C: ElfClass>(
    group_states: &mut [layout::GroupState<'data, Elf<C>>],
    symbol_db: &SymbolDb<'data, Elf<C>>,
    symbol_flags: &AtomicPerSymbolFlags,
) -> Result {
    timing_phase!("Finalise copy relocations");

    group_states.par_iter_mut().try_for_each(|group| {
        verbose_timing_phase!("Finalise copy relocations for group");
        for file in &mut group.files {
            if let layout::FileLayoutState::Dynamic(dynamic) = file {
                // Skip iterating over our symbol table if we don't have any copy relocations.
                if dynamic.format_specific.copy_relocations.is_empty() {
                    continue;
                }

                select_copy_relocation_alternatives(
                    dynamic,
                    symbol_flags,
                    &mut group.common,
                    symbol_db,
                )?;
            }
        }

        Ok(())
    })
}

/// Looks for any non-weak symbols at the same addresses as any of our copy relocations. If
/// found, we'll generate the copy relocation for the strong symbol instead of weak symbol at
/// the same address.
fn select_copy_relocation_alternatives<'data, C: ElfClass>(
    state: &mut layout::DynamicLayoutState<'data, Elf<C>>,
    per_symbol_flags: &AtomicPerSymbolFlags,
    common: &mut CommonGroupState<'data, Elf<C>>,
    symbol_db: &SymbolDb<'data, Elf<C>>,
) -> Result {
    for (i, symbol) in state.object.enumerate_symbols() {
        let address = symbol.value();
        let Some(info) = state.format_specific.copy_relocations.get_mut(&address) else {
            continue;
        };

        let symbol_id = state.symbol_id_range.input_to_id(i);

        if !symbol_db.is_canonical(symbol_id) {
            continue;
        }

        layout::export_dynamic(common, symbol_id, symbol_db)?;

        per_symbol_flags
            .get_atomic(symbol_id)
            .fetch_or(ValueFlags::COPY_RELOCATION);

        if symbol.is_weak() || !info.is_weak || info.symbol_id == symbol_id {
            continue;
        }

        info.symbol_id = symbol_id;
        info.is_weak = false;
    }

    Ok(())
}

fn allocate_for_copy_relocations<'data, C: ElfClass>(
    state: &layout::DynamicLayoutState<'data, Elf<C>>,
    common: &mut CommonGroupState<'data, Elf<C>>,
) -> Result {
    for value in state.format_specific.copy_relocations.values() {
        let symbol_id = value.symbol_id;

        let symbol_index = state.symbol_id_range().id_to_input(symbol_id);
        let symbol = state.object.symbol(symbol_index)?;

        let section_index = state
            .object
            .symbol_section(symbol, symbol_index)?
            .context("Copy relocation for undefined symbol")?;
        let section = state.object.section(section_index)?;

        let alignment = Alignment::new(state.object.section_alignment(section)?)?;

        // Allocate space in BSS for the copy of the symbol.
        let size = symbol.size();
        common.allocate(
            output_section_id::BSS.part_id_with_alignment::<Elf<C>>(alignment),
            alignment.align_up(size),
        );

        // Allocate space required for the copy relocation itself.
        common.allocate(part_id::RELA_DYN_GENERAL, C::RELA_ENTRY_SIZE);
    }

    Ok(())
}

fn assign_copy_relocation_addresses<'data, C: ElfClass>(
    state: &layout::DynamicLayoutState<'data, Elf<C>>,
    copy_relocation_symbols: &[SymbolId],
    memory_offsets: &mut OutputSectionPartMap<u64>,
) -> Result<HashMap<u64, u64>> {
    copy_relocation_symbols
        .iter()
        .map(|symbol_id| {
            let symbol_index = state.symbol_id_range.id_to_input(*symbol_id);
            let symbol = state.object.symbol(symbol_index)?;

            let section_index = state
                .object
                .symbol_section(symbol, symbol_index)?
                .context("Copy relocation for undefined symbol")?;
            let section = state.object.section(section_index)?;

            let alignment = Alignment::new(state.object.section_alignment(section)?)?;

            let input_address = symbol.value();
            let output_address =
                assign_copy_relocation_address::<C>(alignment, symbol.size(), memory_offsets);

            Ok((input_address, output_address))
        })
        .try_collect()
}

/// Assigns the address in BSS for the copy relocation of a symbol.
fn assign_copy_relocation_address<C: ElfClass>(
    alignment: Alignment,
    size: u64,
    memory_offsets: &mut OutputSectionPartMap<u64>,
) -> u64 {
    let bss =
        memory_offsets.get_mut(output_section_id::BSS.part_id_with_alignment::<Elf<C>>(alignment));
    let a = *bss;
    *bss += alignment.align_up(size);
    a
}

impl CopyRelocationInfo {
    fn add_symbol<'data, P: Platform>(
        &mut self,
        symbol_id: SymbolId,
        is_weak: bool,
        resources: &layout::GraphResources<'data, '_, P>,
    ) {
        if self.symbol_id == symbol_id || is_weak {
            return;
        }

        if !self.is_weak {
            resources.symbol_db.warning(format!(
                "Multiple non-weak symbols at the same address have copy relocations: {}, {}",
                resources.symbol_debug(self.symbol_id),
                resources.symbol_debug(symbol_id)
            ));
        }

        self.symbol_id = symbol_id;
        self.is_weak = false;
    }
}

/// Returns the thunk config for the architecture of the given object. This is only needed in
/// contexts that aren't currently generic over Arch.
fn thunk_config_for_object<C: ElfClass>(file: &File<'_, C>) -> Option<ThunkConfig> {
    match file.arch {
        crate::arch::Architecture::AArch64 => crate::elf_aarch64::ElfAArch64::thunk_config(),
        _ => None,
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

impl RegularSectionId {
    const fn output_section_id(self) -> OutputSectionId {
        OutputSectionId::from_u32(ELF_NUM_SINGLE_PART_SECTIONS).offset(self as usize)
    }
}
