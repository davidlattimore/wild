use crate::FileSystem;
use crate::alignment::Alignment;
use crate::args::wasm::WasmArgs;
use crate::bail;
use crate::ensure;
use crate::error::Context as _;
use crate::error::Result;
use crate::input_data::PRELUDE_FILE_ID;
use crate::layout;
use crate::layout_rules::SectionKind;
use crate::layout_rules::SectionRule;
use crate::layout_rules::SectionRuleOutcome;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::SectionIdentity;
use crate::output_section_id::SectionName;
use crate::part_id::PartId;
use crate::platform;
use crate::platform::Args as _;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::timing_phase;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use crate::wasm_writer::OutputExport;
use crate::wasm_writer::OutputGlobal;
use crate::wasm_writer::OutputImport;
use crate::wasm_writer::OutputImportEntity;
use hashbrown::HashMap;
use hashbrown::HashSet;
use leb128::write::signed_len as sleb128_size;
use leb128::write::unsigned_len as uleb128_size;
use linker_utils::utils::u32_from_slice;
use rayon::prelude::*;
use std::borrow::Cow;
use std::ops::Range;
use wasm_encoder::NameMap;
use wasm_encoder::NameSection;
use wasmparser::BinaryReader;
use wasmparser::CodeSectionReader;
use wasmparser::ConstExpr;
use wasmparser::DataKind;
use wasmparser::DataSectionReader;
use wasmparser::ExportSectionReader;
use wasmparser::FuncType;
use wasmparser::FunctionSectionReader;
use wasmparser::GlobalSectionReader;
use wasmparser::GlobalType;
use wasmparser::ImportSectionReader;
use wasmparser::KnownCustom;
use wasmparser::Linking;
use wasmparser::MemorySectionReader;
use wasmparser::MemoryType;
use wasmparser::Parser;
use wasmparser::Payload;
use wasmparser::RelocationEntry;
use wasmparser::RelocationType;
use wasmparser::SymbolFlags;
use wasmparser::SymbolInfo;
use wasmparser::TypeRef;
use wasmparser::TypeSectionReader;

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct Wasm;

pub(crate) fn link_for_arch<'data, F: FileSystem>(
    linker: &'data crate::Linker<F>,
    args: &'data WasmArgs,
) -> crate::error::Result<crate::LinkerOutput<'data>> {
    if !(cfg!(feature = "wasm") || args.common().experimental_platforms) {
        bail!("Wasm support is still experimental. Rebuild with `--features wasm` to enable it.");
    }

    linker.link_for_arch::<Wasm, crate::wasm_wasm32::WasmWasm32>(args)
}

#[repr(u32)]
#[derive(Clone, Copy)]
enum SinglePartSectionId {
    WasmType = crate::output_section_id::NUM_COMMON_SINGLE_PART_SECTIONS,
    WasmImport,
    WasmFunction,
    WasmTable,
    WasmMemory,
    WasmGlobal,
    WasmExport,
    WasmStart,
    WasmElement,
    WasmDataCount,
    WasmCode,
    WasmData,
    WasmName,
    WasmTargetFeatures,

    // Must be last.
    Count,
}

pub(crate) mod part_id {
    use super::SinglePartSectionId;
    use crate::part_id::PartId;

    pub(crate) const WASM_TYPE: PartId = SinglePartSectionId::WasmType.part_id();
    pub(crate) const WASM_IMPORT: PartId = SinglePartSectionId::WasmImport.part_id();
    pub(crate) const WASM_FUNCTION: PartId = SinglePartSectionId::WasmFunction.part_id();
    pub(crate) const WASM_TABLE: PartId = SinglePartSectionId::WasmTable.part_id();
    pub(crate) const WASM_MEMORY: PartId = SinglePartSectionId::WasmMemory.part_id();
    pub(crate) const WASM_GLOBAL: PartId = SinglePartSectionId::WasmGlobal.part_id();
    pub(crate) const WASM_EXPORT: PartId = SinglePartSectionId::WasmExport.part_id();
    // TODO(wasm): Implement start-section emission.
    #[expect(dead_code)]
    pub(crate) const WASM_START: PartId = SinglePartSectionId::WasmStart.part_id();
    pub(crate) const WASM_ELEMENT: PartId = SinglePartSectionId::WasmElement.part_id();
    // TODO(wasm): Implement data-count emission.
    #[expect(dead_code)]
    pub(crate) const WASM_DATA_COUNT: PartId = SinglePartSectionId::WasmDataCount.part_id();
    pub(crate) const WASM_CODE: PartId = SinglePartSectionId::WasmCode.part_id();
    pub(crate) const WASM_DATA: PartId = SinglePartSectionId::WasmData.part_id();
    pub(crate) const WASM_NAME: PartId = SinglePartSectionId::WasmName.part_id();
    pub(crate) const WASM_TARGET_FEATURES: PartId =
        SinglePartSectionId::WasmTargetFeatures.part_id();
}

pub(crate) mod output_section_id {
    use super::SinglePartSectionId;
    use crate::output_section_id::OutputSectionId;

    pub(crate) const WASM_TYPE: OutputSectionId = SinglePartSectionId::WasmType.output_section_id();
    pub(crate) const WASM_IMPORT: OutputSectionId =
        SinglePartSectionId::WasmImport.output_section_id();
    pub(crate) const WASM_FUNCTION: OutputSectionId =
        SinglePartSectionId::WasmFunction.output_section_id();
    pub(crate) const WASM_TABLE: OutputSectionId =
        SinglePartSectionId::WasmTable.output_section_id();
    pub(crate) const WASM_MEMORY: OutputSectionId =
        SinglePartSectionId::WasmMemory.output_section_id();
    pub(crate) const WASM_GLOBAL: OutputSectionId =
        SinglePartSectionId::WasmGlobal.output_section_id();
    pub(crate) const WASM_EXPORT: OutputSectionId =
        SinglePartSectionId::WasmExport.output_section_id();
    pub(crate) const WASM_START: OutputSectionId =
        SinglePartSectionId::WasmStart.output_section_id();
    pub(crate) const WASM_ELEMENT: OutputSectionId =
        SinglePartSectionId::WasmElement.output_section_id();
    pub(crate) const WASM_DATA_COUNT: OutputSectionId =
        SinglePartSectionId::WasmDataCount.output_section_id();
    pub(crate) const WASM_CODE: OutputSectionId = SinglePartSectionId::WasmCode.output_section_id();
    pub(crate) const WASM_DATA: OutputSectionId = SinglePartSectionId::WasmData.output_section_id();
    pub(crate) const WASM_NAME: OutputSectionId = SinglePartSectionId::WasmName.output_section_id();
    pub(crate) const WASM_TARGET_FEATURES: OutputSectionId =
        SinglePartSectionId::WasmTargetFeatures.output_section_id();
}

/// Magic bytes at the start of every Wasm module.
pub(crate) const WASM_MAGIC: [u8; 4] = [0x00, b'a', b's', b'm'];

/// Supported Wasm binary format version.
pub(crate) const WASM_VERSION: u32 = 1;

pub(crate) mod section_id {
    pub(crate) const TYPE: u8 = 1;
    pub(crate) const IMPORT: u8 = 2;
    pub(crate) const FUNCTION: u8 = 3;
    pub(crate) const TABLE: u8 = 4;
    pub(crate) const MEMORY: u8 = 5;
    pub(crate) const GLOBAL: u8 = 6;
    pub(crate) const EXPORT: u8 = 7;
    pub(crate) const START: u8 = 8;
    pub(crate) const ELEMENT: u8 = 9;
    pub(crate) const CODE: u8 = 10;
    pub(crate) const DATA: u8 = 11;
    pub(crate) const DATA_COUNT: u8 = 12;
    pub(crate) const MAX: u8 = DATA_COUNT;
}

/// Size of a `[Option<u32>; _]` lookup that can be indexed by any standard section id.
pub(crate) const STANDARD_SECTION_LOOKUP_LEN: usize = section_id::MAX as usize + 1;

/// Default `__table_base` for non-PIC executables.
const DEFAULT_TABLE_BASE: u32 = 1;

/// The custom-section name used for the linker metadata.
pub(crate) const LINKING_SECTION_NAME: &str = "linking";

/// The prefix of every `reloc.*` custom section.
pub(crate) const RELOC_SECTION_PREFIX: &str = "reloc.";

/// The custom-section name used for the WebAssembly target features.
pub(crate) const TARGET_FEATURES_SECTION_NAME: &str = "target_features";

/// Feature is used by this object (`+` in the target_features section).
const TARGET_FEATURE_PREFIX_USED: u8 = b'+';
/// Feature must not appear in the output (`-` in the target_features section).
const TARGET_FEATURE_PREFIX_DISALLOWED: u8 = b'-';

/// Default static data base for linker-produced executables.
const LINKER_MEMORY_BASE: u32 = 1024;

/// Empty function body: zero locals + `end`.
const EMPTY_FUNCTION_BODY: &[u8] = &[0x00, 0x0b];

/// Undefined weak function stubs.
const UNREACHABLE_FUNCTION_BODY: &[u8] = &[0x00, 0x00, 0x0b];

/// `i32.const` body for `LINKER_MEMORY_BASE`.
const LINKER_MEMORY_BASE_INIT_EXPR: &[u8] = &[0x41, 0x80, 0x08];

/// `i32.const 0`. Used for immutable `__tls_base` when no TLS segment is laid out.
const ZERO_I32_INIT_EXPR: &[u8] = &[0x41, 0x00];

/// `i32.const 1` for `DEFAULT_TABLE_BASE`.
const DEFAULT_TABLE_BASE_INIT_EXPR: &[u8] = &[0x41, 0x01];

/// Sentinel for a GC'd Wasm index slot.
const WASM_DEAD_INDEX: u32 = u32::MAX;

#[derive(derive_more::Debug)]
pub(crate) struct File<'data> {
    #[debug(skip)]
    pub(crate) data: &'data [u8],

    #[debug(skip)]
    pub(crate) sections: Vec<SectionHeader>,

    /// For each standard Wasm section id, the index into `sections`, if present.
    #[debug(skip)]
    pub(crate) standard_section_index: [Option<u32>; STANDARD_SECTION_LOOKUP_LEN],

    #[debug(skip)]
    pub(crate) symbols: Vec<WasmSymbol>,

    /// Per-data-segment alignments from the linking `SegmentInfo` subsection.
    #[debug(skip)]
    pub(crate) segment_alignments: Vec<Alignment>,

    /// Init functions from the linking section (`InitFuncs`), in input order.
    #[debug(skip)]
    pub(crate) init_funcs: Vec<WasmInitFunc>,

    #[debug(skip)]
    pub(crate) reloc_sections: Vec<WasmRelocSection>,

    /// Entries from the `target_features` custom section, if present.
    #[debug(skip)]
    pub(crate) target_features: Vec<WasmTargetFeature<'data>>,

    pub(crate) num_function_imports: u32,
    pub(crate) num_global_imports: u32,
    pub(crate) num_defined_functions: u32,
    pub(crate) num_defined_globals: u32,
    pub(crate) num_data_segments: u32,
}

/// One entry of the Wasm tool-conventions `target_features` custom section.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WasmTargetFeature<'data> {
    pub(crate) prefix: u8,
    pub(crate) name: &'data str,
}

/// A constructor from the linking `InitFuncs` subsection.
///
/// `symbol_index` indexes the linking symbol table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WasmInitFunc {
    pub(crate) priority: u32,
    pub(crate) symbol_index: u32,
}

/// A single section of a Wasm module.
#[derive(Debug, Default, Clone)]
pub(crate) struct SectionHeader {
    /// The wasm section id.
    pub(crate) id: u8,

    /// Byte range of the section (id + size + payload) within the original Wasm binary.
    pub(crate) payload_range: Range<u32>,

    /// For custom sections, the byte range within the input data of the section's name string.
    /// `None` for standard sections, whose canonical name is derived from `id`.
    pub(crate) name_range: Option<Range<u32>>,
}

impl SectionHeader {
    pub(crate) fn payload_range_usize(&self) -> Range<usize> {
        self.payload_range.start as usize..self.payload_range.end as usize
    }
}

fn standard_section_name(id: u8) -> Option<&'static [u8]> {
    Some(match id {
        section_id::TYPE => b"type",
        section_id::IMPORT => b"import",
        section_id::FUNCTION => b"function",
        section_id::TABLE => b"table",
        section_id::MEMORY => b"memory",
        section_id::GLOBAL => b"global",
        section_id::EXPORT => b"export",
        section_id::START => b"start",
        section_id::ELEMENT => b"element",
        section_id::CODE => b"code",
        section_id::DATA => b"data",
        section_id::DATA_COUNT => b"data_count",
        _ => return None,
    })
}

// NOTE: We deliberately don't reuse `wasmparser::SymbolInfo<'data>` here. It carries `&'data str`
// names, but `Platform::SymtabEntry` requires `Symbol: 'static + Copy`, so a wrapper around
// `SymbolInfo` would have to drop the borrowed strings anyway.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WasmSymbol {
    pub(crate) kind: WasmSymbolKind,
    pub(crate) flags: u32,
    pub(crate) index: u32,
    pub(crate) offset: u32,
    pub(crate) size: u32,
    pub(crate) name_start: u32,
    pub(crate) name_len: u32,
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub(crate) enum WasmSymbolKind {
    #[default]
    Null, // Doesn't correspond to any real wasm symbol kind.
    Func,
    Data,
    Global,
    Section,
    Event,
    Table,
}

impl WasmSymbol {
    fn raw_flags(&self) -> SymbolFlags {
        SymbolFlags::from_bits_truncate(self.flags)
    }

    pub(crate) fn is_undefined(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::UNDEFINED)
    }

    pub(crate) fn is_weak(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::BINDING_WEAK)
    }

    pub(crate) fn is_local(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::BINDING_LOCAL)
    }

    pub(crate) fn is_hidden(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::VISIBILITY_HIDDEN)
    }

    pub(crate) fn is_explicit_name(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::EXPLICIT_NAME)
    }

    fn has_name(&self) -> bool {
        self.name_len != 0
    }

    fn name_range(&self) -> Range<usize> {
        let s = self.name_start as usize;
        s..s + self.name_len as usize
    }
}

/// A `reloc.*` custom section header.
#[derive(Debug, Clone)]
pub(crate) struct WasmRelocSection {
    /// Index (into [`File::sections`]) of the section that the relocations apply to.
    pub(crate) target_section_index: u32,
    /// Byte range of the section's contents (after the section name) within the module bytes.
    pub(crate) payload_range: Range<u32>,
}

impl WasmRelocSection {
    pub(crate) fn decode_entries(&self, data: &[u8]) -> Result<Vec<WasmRelocation>> {
        let start = self.payload_range.start as usize;
        let end = self.payload_range.end as usize;
        let payload = data
            .get(start..end)
            .ok_or_else(|| crate::error!("Wasm reloc section payload range out of bounds"))?;
        let reader = wasmparser::RelocSectionReader::new(BinaryReader::new(payload, start))?;
        reader
            .entries()
            .into_iter()
            .map(|entry| Ok(WasmRelocation::from_entry(entry?)))
            .collect()
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct WasmRelocation {
    /// Wasm relocation type.
    pub(crate) ty: RelocationType,
    /// Byte offset within the target section's payload.
    pub(crate) offset: u32,
    /// Symbol or type index.
    pub(crate) index: u32,
    pub(crate) addend: i64,
}

macro_rules! define_relocation_type_to_string {
    ($($variant:ident),* $(,)?) => {
        pub(crate) const fn relocation_type_to_string(ty: RelocationType) -> &'static str {
            match ty {
                $(RelocationType::$variant => stringify!($variant),)*
            }
        }
    };
}

define_relocation_type_to_string!(
    FunctionIndexLeb,
    TableIndexSleb,
    TableIndexI32,
    MemoryAddrLeb,
    MemoryAddrSleb,
    MemoryAddrI32,
    TypeIndexLeb,
    GlobalIndexLeb,
    FunctionOffsetI32,
    SectionOffsetI32,
    EventIndexLeb,
    MemoryAddrRelSleb,
    TableIndexRelSleb,
    GlobalIndexI32,
    MemoryAddrLeb64,
    MemoryAddrSleb64,
    MemoryAddrI64,
    MemoryAddrRelSleb64,
    TableIndexSleb64,
    TableIndexI64,
    TableNumberLeb,
    MemoryAddrTlsSleb,
    FunctionOffsetI64,
    MemoryAddrLocrelI32,
    TableIndexRelSleb64,
    MemoryAddrTlsSleb64,
    FunctionIndexI32,
);

impl WasmRelocation {
    fn from_entry(entry: RelocationEntry) -> Self {
        Self {
            ty: entry.ty,
            offset: entry.offset,
            index: entry.index,
            addend: entry.addend,
        }
    }

    /// Width in bytes of the slot this relocation overwrites.
    pub(crate) fn slot_size(&self) -> usize {
        match self.ty {
            RelocationType::FunctionIndexLeb
            | RelocationType::TableIndexSleb
            | RelocationType::TableIndexRelSleb
            | RelocationType::MemoryAddrLeb
            | RelocationType::MemoryAddrSleb
            | RelocationType::MemoryAddrRelSleb
            | RelocationType::TypeIndexLeb
            | RelocationType::GlobalIndexLeb
            | RelocationType::EventIndexLeb
            | RelocationType::TableNumberLeb => 5,
            RelocationType::TableIndexI32
            | RelocationType::MemoryAddrI32
            | RelocationType::FunctionOffsetI32
            | RelocationType::SectionOffsetI32
            | RelocationType::GlobalIndexI32
            | RelocationType::FunctionIndexI32 => 4,
            _ => 0,
        }
    }
}

/// Write `value` as an unsigned LEB128 into `buf`, returning the number of bytes written.
pub(crate) fn write_uleb128(buf: &mut [u8], value: u64) -> usize {
    let mut writable = &mut *buf;
    leb128::write::unsigned(&mut writable, value).unwrap()
}

/// Write `value` as a signed LEB128 into `buf`, returning the number of bytes written.
pub(crate) fn write_sleb128(buf: &mut [u8], value: i64) -> usize {
    let mut writable = &mut *buf;
    leb128::write::signed(&mut writable, value).unwrap()
}

/// Write `value` as a 5-byte fixed-width unsigned LEB128. Used for wasm reloc slots that reserve
/// exactly 5 bytes regardless of the encoded value.
pub(crate) fn write_uleb128_5(buf: &mut [u8; 5], value: u32) {
    buf[0] = (value as u8 & 0x7f) | 0x80;
    buf[1] = ((value >> 7) as u8 & 0x7f) | 0x80;
    buf[2] = ((value >> 14) as u8 & 0x7f) | 0x80;
    buf[3] = ((value >> 21) as u8 & 0x7f) | 0x80;
    buf[4] = (value >> 28) as u8 & 0x0f;
}

/// Write `value` as a 5-byte fixed-width signed LEB128. The high three bits of the final byte are
/// sign-extended so the encoded form is canonical for any `i32`.
pub(crate) fn write_sleb128_5(buf: &mut [u8; 5], value: i32) {
    let v = value as u32;
    buf[0] = (v as u8 & 0x7f) | 0x80;
    buf[1] = ((v >> 7) as u8 & 0x7f) | 0x80;
    buf[2] = ((v >> 14) as u8 & 0x7f) | 0x80;
    buf[3] = ((v >> 21) as u8 & 0x7f) | 0x80;
    let last = (v >> 28) as u8 & 0x0f;
    let sign_ext = if value < 0 { 0x70 } else { 0x00 };
    buf[4] = last | sign_ext;
}

pub(crate) fn apply_relocation(
    bytes: &mut [u8],
    reloc: &WasmRelocation,
    value: u32,
) -> crate::error::Result<()> {
    let offset = reloc.offset as usize;
    let size = reloc.slot_size();
    let end = offset
        .checked_add(size)
        .ok_or_else(|| crate::error!("Wasm relocation offset overflow"))?;
    let slot = bytes
        .get_mut(offset..end)
        .ok_or_else(|| crate::error!("Wasm relocation slot out of range"))?;
    match reloc.ty {
        RelocationType::FunctionIndexLeb
        | RelocationType::MemoryAddrLeb
        | RelocationType::TypeIndexLeb
        | RelocationType::GlobalIndexLeb
        | RelocationType::EventIndexLeb
        | RelocationType::TableNumberLeb => {
            let buf: &mut [u8; 5] = slot.try_into().expect("slot_size returned 5");
            write_uleb128_5(buf, value);
        }
        RelocationType::TableIndexSleb
        | RelocationType::TableIndexRelSleb
        | RelocationType::MemoryAddrSleb
        | RelocationType::MemoryAddrRelSleb => {
            let buf: &mut [u8; 5] = slot.try_into().expect("slot_size returned 5");
            write_sleb128_5(buf, value as i32);
        }
        RelocationType::TableIndexI32
        | RelocationType::MemoryAddrI32
        | RelocationType::FunctionOffsetI32
        | RelocationType::SectionOffsetI32
        | RelocationType::GlobalIndexI32
        | RelocationType::FunctionIndexI32 => {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        other => bail!(
            "unsupported Wasm relocation type {}",
            relocation_type_to_string(other)
        ),
    }
    Ok(())
}

/// A single imported function. `module` / `name` borrow into the source bytes.
#[derive(Debug, Copy, Clone)]
pub(crate) struct WasmFunctionImport<'data> {
    pub(crate) module: &'data str,
    pub(crate) name: &'data str,
    /// Index into the `type` section.
    pub(crate) type_index: u32,
}

/// A single imported global.
#[derive(Debug, Copy, Clone)]
pub(crate) struct WasmGlobalImport<'data> {
    pub(crate) module: &'data str,
    pub(crate) name: &'data str,
    pub(crate) ty: GlobalType,
}

/// A global defined inside the module (not imported).
#[derive(Debug, Clone)]
pub(crate) struct WasmModuleGlobal<'data> {
    pub(crate) ty: GlobalType,
    pub(crate) init_expr: ConstExpr<'data>,
}

/// A single data segment from the `data` section.
#[derive(Debug, Clone)]
pub(crate) struct WasmDataSegment<'data> {
    pub(crate) kind: DataKind<'data>,
    pub(crate) data: &'data [u8],
    /// Byte offset of this segment's encoding within the input data section payload.
    pub(crate) section_offset: u32,
}

/// Layout for one data segment within an input object.
#[derive(Debug)]
pub(crate) struct WasmDataSegmentLayout<'data> {
    /// Index of this segment within the object's data section.
    pub(crate) segment_index: u32,
    pub(crate) data: &'data [u8],
    /// Relocations targeting this segment's payload bytes (segment-local offsets).
    pub(crate) relocations: Vec<WasmRelocation>,
    /// Output memory index after index remapping.
    pub(crate) output_memory_index: u32,
    /// Byte offset within the output module's linear memory where the payload is placed.
    pub(crate) output_memory_offset: u32,
    /// Encoded size of this segment within the output data section payload.
    pub(crate) encoded_output_size: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct WasmFunctionBody<'data> {
    /// Raw body bytes (locals + operators) without the LEB128 size prefix.
    pub(crate) bytes: Cow<'data, [u8]>,
    /// Byte offset of this body (starting at its size prefix) within the code section payload.
    pub(crate) code_offset: u32,
    /// Relocations targeting this body, with offsets relative to the body start.
    pub(crate) relocations: Vec<WasmRelocation>,
    /// Index of the object this body belongs to.
    pub(crate) object_index: usize,
}

fn is_debug_section_name(name: &[u8]) -> bool {
    name.starts_with(b".debug")
}

impl<'data> File<'data> {
    fn section_is_debug(&self, index: u32) -> bool {
        let Some(header) = self.sections.get(index as usize) else {
            return false;
        };
        let Some(name_range) = &header.name_range else {
            return false;
        };
        let name = self
            .data
            .get(name_range.start as usize..name_range.end as usize)
            .unwrap_or_default();
        is_debug_section_name(name)
    }

    /// Construct a `BinaryReader` over the payload of the standard section with the given id,
    /// or `None` if the input has no such section.
    fn standard_section_reader(&self, id: u8) -> Option<BinaryReader<'data>> {
        let section_index = self.standard_section_index.get(id as usize)?.as_ref()?;
        let header = self.sections.get(*section_index as usize)?;
        let payload = self.data.get(header.payload_range_usize())?;
        Some(BinaryReader::new(
            payload,
            header.payload_range.start as usize,
        ))
    }

    pub(crate) fn import_section_reader(&self) -> Result<Option<ImportSectionReader<'data>>> {
        self.standard_section_reader(section_id::IMPORT)
            .map(|r| ImportSectionReader::new(r).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn function_section_reader(&self) -> Result<Option<FunctionSectionReader<'data>>> {
        self.standard_section_reader(section_id::FUNCTION)
            .map(|r| FunctionSectionReader::new(r).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn global_section_reader(&self) -> Result<Option<GlobalSectionReader<'data>>> {
        self.standard_section_reader(section_id::GLOBAL)
            .map(|r| GlobalSectionReader::new(r).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn data_section_reader(&self) -> Result<Option<DataSectionReader<'data>>> {
        self.standard_section_reader(section_id::DATA)
            .map(|r| DataSectionReader::new(r).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn code_section_reader(&self) -> Result<Option<CodeSectionReader<'data>>> {
        self.standard_section_reader(section_id::CODE)
            .map(|r| CodeSectionReader::new(r).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn memory_section_reader(&self) -> Result<Option<MemorySectionReader<'data>>> {
        self.standard_section_reader(section_id::MEMORY)
            .map(|r| MemorySectionReader::new(r).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn export_section_reader(&self) -> Result<Option<ExportSectionReader<'data>>> {
        self.standard_section_reader(section_id::EXPORT)
            .map(|r| ExportSectionReader::new(r).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn type_section_reader(&self) -> Result<Option<TypeSectionReader<'data>>> {
        self.standard_section_reader(section_id::TYPE)
            .map(|r| TypeSectionReader::new(r).map_err(Into::into))
            .transpose()
    }

    /// Type indices of functions defined in this module (excluding imports), in `function`
    /// section order. The function body for each entry lives in the `code` section.
    pub(crate) fn module_functions(&self) -> Result<Vec<u32>> {
        let Some(reader) = self.function_section_reader()? else {
            return Ok(Vec::new());
        };

        reader
            .into_iter()
            .map(|res| res.map_err(Into::into))
            .collect()
    }

    /// Globals defined in this module (excluding imports), in `global` section order.
    pub(crate) fn module_globals(&self) -> Result<Vec<WasmModuleGlobal<'data>>> {
        let Some(reader) = self.global_section_reader()? else {
            return Ok(Vec::new());
        };

        reader
            .into_iter()
            .map(|res| {
                res.map(|g| WasmModuleGlobal {
                    ty: g.ty,
                    init_expr: g.init_expr,
                })
                .map_err(Into::into)
            })
            .collect()
    }

    pub(crate) fn memories(&self) -> Result<Vec<MemoryType>> {
        let Some(reader) = self.memory_section_reader()? else {
            return Ok(Vec::new());
        };
        reader
            .into_iter()
            .map(|res| res.map_err(Into::into))
            .collect()
    }

    /// Function bodies in code-section order. The returned bytes include the body size prefix.
    pub(crate) fn function_bodies(&self) -> Result<Vec<WasmFunctionBody<'data>>> {
        let Some(reader) = self.code_section_reader()? else {
            return Ok(Vec::new());
        };
        let code_payload_start = self.standard_section_index[section_id::CODE as usize]
            .and_then(|i| self.sections.get(i as usize))
            .map_or(0, |h| h.payload_range.start);
        reader
            .into_iter()
            .map(|res| {
                res.map(|body| {
                    let range = body.range();
                    WasmFunctionBody {
                        bytes: Cow::Borrowed(&self.data[range.clone()]),
                        code_offset: range.start as u32 - code_payload_start,
                        relocations: Vec::new(),
                        object_index: 0,
                    }
                })
                .map_err(Into::into)
            })
            .collect()
    }

    /// Data segments in declaration order.
    pub(crate) fn data_segments(&self) -> Result<Vec<WasmDataSegment<'data>>> {
        let Some(reader) = self.data_section_reader()? else {
            return Ok(Vec::new());
        };

        let mut segments = Vec::new();
        let mut section_offset = u32::try_from(uleb128_size(u64::from(reader.count())))
            .context("Wasm data count LEB")?;
        for res in reader {
            let d = res?;
            segments.push(WasmDataSegment {
                kind: d.kind.clone(),
                data: d.data,
                section_offset,
            });
            section_offset = section_offset
                .checked_add(wasm_data_segment_encoded_size(&d.kind, d.data.len())?)
                .ok_or_else(|| crate::error!("Wasm data section offset overflow"))?;
        }
        Ok(segments)
    }
}

impl<'data> platform::ObjectFile<'data> for File<'data> {
    type Platform = Wasm;

    fn parse_bytes(input: &'data [u8], _is_dynamic: bool) -> crate::error::Result<Self> {
        parse_wasm_module(input).context("failed to parse Wasm object file")
    }

    fn parse(
        input: &crate::input_data::InputBytes<'data>,
        _args: &<Self::Platform as platform::Platform>::Args,
    ) -> crate::error::Result<Self> {
        Self::parse_bytes(input.data, false)
    }

    fn is_dynamic(&self) -> bool {
        // Wasm has no notion of "dynamic objects" in the ELF sense yet.
        false
    }

    fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    fn symbols_iter(&self) -> impl Iterator<Item = &WasmSymbol> {
        self.symbols.iter()
    }

    fn symbol(
        &self,
        index: object::SymbolIndex,
    ) -> crate::error::Result<&<Self::Platform as platform::Platform>::SymtabEntry> {
        self.symbols
            .get(index.0)
            .ok_or_else(|| crate::error!("wasm symbol index {} out of range", index.0))
    }

    fn section_size(
        &self,
        header: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<u64> {
        Ok(header.payload_range.len() as u64)
    }

    fn symbol_name(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
    ) -> crate::error::Result<&'data [u8]> {
        if !symbol.has_name() {
            return Ok(&[]);
        }
        self.data
            .get(symbol.name_range())
            .ok_or_else(|| crate::error!("wasm symbol name range out of bounds"))
    }

    fn symbol_offset_in_section(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        _section_index: object::SectionIndex,
    ) -> crate::error::Result<u64> {
        Ok(match symbol.kind {
            WasmSymbolKind::Data => u64::from(symbol.offset),
            _ => 0,
        })
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
            .ok_or_else(|| crate::error!("wasm section index {} out of range", index.0))
    }

    fn section_by_name(
        &self,
        name: &str,
    ) -> Option<(
        object::SectionIndex,
        &<Self::Platform as platform::Platform>::SectionHeader,
    )> {
        let needle = name.as_bytes();
        self.sections
            .iter()
            .enumerate()
            .find(|(_, header)| {
                if let Some(name_range) = &header.name_range {
                    self.data
                        .get(name_range.start as usize..name_range.end as usize)
                        == Some(needle)
                } else {
                    standard_section_name(header.id) == Some(needle)
                }
            })
            .map(|(i, header)| (object::SectionIndex(i), header))
    }

    fn symbol_section(
        &self,
        _symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        _index: object::SymbolIndex,
    ) -> crate::error::Result<Option<object::SectionIndex>> {
        Ok(None)
    }

    fn symbol_versions(&self) -> &[<Self::Platform as platform::Platform>::SymbolVersionIndex] {
        // Wasm doesn't have ELF-style symbol versioning.
        &[]
    }

    fn finalise_sizes_dynamic(
        &self,
        _lib_name: &[u8],
        _state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn apply_non_addressable_indexes_dynamic(
        &self,
        _indexes: &mut <Self::Platform as platform::Platform>::NonAddressableIndexes,
        _counts: &mut <Self::Platform as platform::Platform>::NonAddressableCounts,
        _state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn section_name(&self, index: object::SectionIndex) -> crate::error::Result<&'data [u8]> {
        let header = self
            .sections
            .get(index.0)
            .ok_or_else(|| crate::error!("wasm section index {} out of range", index.0))?;
        if let Some(name_range) = &header.name_range {
            Ok(&self.data[name_range.start as usize..name_range.end as usize])
        } else {
            standard_section_name(header.id)
                .ok_or_else(|| crate::error!("unknown wasm section id {}", header.id))
        }
    }

    fn raw_section_data(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<&'data [u8]> {
        Ok(&self.data[section.payload_range_usize()])
    }

    fn section_data(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
        _member: &bumpalo_herd::Member<'data>,
        _loaded_metrics: &crate::resolution::LoadedMetrics,
    ) -> crate::error::Result<&'data [u8]> {
        // Wasm sections are never compressed.
        self.raw_section_data(section)
    }

    fn copy_section_data(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
        out: &mut [u8],
    ) -> crate::error::Result {
        let bytes = self.raw_section_data(section)?;
        ensure!(
            out.len() == bytes.len(),
            "copy_section_data: output buffer size {} does not match section size {}",
            out.len(),
            bytes.len()
        );
        out.copy_from_slice(bytes);
        Ok(())
    }

    fn section_data_cow(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<std::borrow::Cow<'data, [u8]>> {
        Ok(std::borrow::Cow::Borrowed(self.raw_section_data(section)?))
    }

    fn section_alignment(
        &self,
        _section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<u64> {
        // Wasm sections themselves don't carry an alignment requirement.
        Ok(1)
    }

    fn relocations(
        &self,
        index: object::SectionIndex,
        _relocations: &<Self::Platform as platform::Platform>::RelocationSections,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RelocationList<'data>> {
        let target = u32::try_from(index.0).unwrap_or(u32::MAX);
        let entries = self
            .reloc_sections
            .iter()
            .find(|s| s.target_section_index == target)
            .map(|s| s.decode_entries(self.data))
            .transpose()?
            .unwrap_or_default();
        Ok(RelocationList {
            entries,
            _phantom: std::marker::PhantomData,
        })
    }

    fn parse_relocations(
        &self,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RelocationSections> {
        Ok(())
    }

    fn symbol_version_debug(&self, _symbol_index: object::SymbolIndex) -> Option<String> {
        // Wasm doesn't have ELF-style symbol versioning.
        None
    }

    fn section_display_name(&self, index: object::SectionIndex) -> std::borrow::Cow<'data, str> {
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
        Ok(())
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        _local_index: usize,
        _version_names: &<Self::Platform as platform::Platform>::VersionNames<'data>,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RawSymbolName<'data>> {
        Ok(RawSymbolName {
            name: self.symbol_name(symbol)?,
        })
    }

    fn should_enforce_undefined(
        &self,
        _resources: &crate::layout::GraphResources<'data, '_, Self::Platform>,
    ) -> bool {
        // Wasm has no dynamic objects yet, so this is never reached in practice.
        false
    }

    fn verneed_table(
        &self,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::VerneedTable<'data>> {
        Ok(VerneedTable { _phantom: &[] })
    }

    fn process_gnu_note_section(
        &self,
        _state: &mut <Self::Platform as platform::Platform>::ObjectLayoutStateExt<'data>,
        _section_index: object::SectionIndex,
    ) -> crate::error::Result {
        // Wasm objects don't carry GNU property notes.
        Ok(())
    }

    fn dynamic_tags(
        &self,
    ) -> crate::error::Result<&'data [<Self::Platform as platform::Platform>::DynamicEntry]> {
        Ok(&[])
    }
}

impl platform::SectionHeader for SectionHeader {
    fn is_alloc(&self) -> bool {
        true
    }

    fn is_writable(&self) -> bool {
        // Wasm sections are not classified into RW vs RO at the section level.
        false
    }

    fn is_executable(&self) -> bool {
        // Code lives in the dedicated CODE section.
        false
    }

    fn is_tls(&self) -> bool {
        // Wasm has no TLS yet.
        false
    }

    fn is_merge_section(&self) -> bool {
        false
    }

    fn is_strings(&self) -> bool {
        false
    }

    fn should_retain(&self) -> bool {
        false
    }

    fn should_exclude(&self) -> bool {
        false
    }

    fn is_group(&self) -> bool {
        false
    }

    fn is_note(&self) -> bool {
        false
    }

    fn is_prog_bits(&self) -> bool {
        true
    }

    fn is_no_bits(&self) -> bool {
        false
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionType {}

impl platform::SectionType for SectionType {
    fn is_rela(&self) -> bool {
        false
    }

    fn is_rel(&self) -> bool {
        false
    }

    fn is_symtab(&self) -> bool {
        false
    }

    fn is_strtab(&self) -> bool {
        false
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionFlags {}

impl platform::SectionFlags for SectionFlags {
    fn is_alloc(self) -> bool {
        // All Wasm sections are conceptually loaded.
        true
    }
}

impl platform::Symbol for WasmSymbol {
    fn as_common(&self) -> Option<platform::CommonSymbol> {
        // Wasm has no COMMON symbols.
        None
    }

    fn is_undefined(&self) -> bool {
        WasmSymbol::is_undefined(self)
    }

    fn is_local(&self) -> bool {
        WasmSymbol::is_local(self)
    }

    fn is_absolute(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::ABSOLUTE)
    }

    fn is_weak(&self) -> bool {
        WasmSymbol::is_weak(self)
    }

    fn visibility(&self) -> crate::symbol_db::Visibility {
        if self.is_hidden() {
            crate::symbol_db::Visibility::Hidden
        } else {
            crate::symbol_db::Visibility::Default
        }
    }

    fn value(&self) -> u64 {
        match self.kind {
            WasmSymbolKind::Data => u64::from(self.offset),
            _ => u64::from(self.index),
        }
    }

    fn size(&self) -> u64 {
        u64::from(self.size)
    }

    fn has_name(&self) -> bool {
        WasmSymbol::has_name(self)
    }

    fn is_default_strippable(&self, _name: &[u8]) -> bool {
        // No equivalent of ELF's `.L` local symbol convention.
        false
    }

    fn debug_string(&self) -> String {
        format!("<Wasm symbol kind={:?} index={}>", self.kind, self.index)
    }

    fn is_tls(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::TLS)
    }

    fn is_interposable(&self) -> bool {
        // No dynamic linking yet; symbols can't be interposed at runtime.
        false
    }

    fn is_func(&self) -> bool {
        self.kind == WasmSymbolKind::Func
    }

    fn is_ifunc(&self) -> bool {
        false
    }

    fn is_hidden(&self) -> bool {
        WasmSymbol::is_hidden(self)
    }

    fn is_gnu_unique(&self) -> bool {
        false
    }

    fn with_hidden(mut self, hidden: bool) -> Self {
        let bit = SymbolFlags::VISIBILITY_HIDDEN.bits();
        if hidden {
            self.flags |= bit;
        } else {
            self.flags &= !bit;
        }
        self
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionAttributes {}

impl platform::SectionAttributes for SectionAttributes {
    type Platform = Wasm;

    fn merge(&mut self, _rhs: Self) {
        // No per-section attributes to merge yet.
    }

    fn apply(
        &self,
        _output_sections: &mut crate::output_section_id::OutputSections<Self::Platform>,
        _section_id: crate::output_section_id::OutputSectionId,
    ) {
        // No-op: Wasm output sections inherit their attributes from `SECTION_DEFINITIONS`.
    }

    fn is_null(&self) -> bool {
        false
    }

    fn is_alloc(&self) -> bool {
        true
    }

    fn is_executable(&self) -> bool {
        false
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn occupies_only_tls_address_space(&self) -> bool {
        false
    }

    fn is_writable(&self) -> bool {
        false
    }

    fn is_no_bits(&self) -> bool {
        false
    }

    fn flags(&self) -> <Self::Platform as platform::Platform>::SectionFlags {
        SectionFlags::default()
    }

    fn ty(&self) -> <Self::Platform as platform::Platform>::SectionType {
        SectionType::default()
    }

    fn set_to_default_type(&mut self) {
        // Wasm has no per-section type to reset.
    }
}

#[derive(Debug)]
pub(crate) struct NonAddressableIndexes {}

impl platform::NonAddressableIndexes for NonAddressableIndexes {
    fn new<P: platform::Platform>(_symbol_db: &crate::symbol_db::SymbolDb<P>) -> Self {
        Self {}
    }
}

/// Segment kinds used purely to drive output ordering. Wasm has no loadable program segments. These
/// variants are just a way to group the output sections in the canonical module layout.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub(crate) enum SegmentType {
    /// Holds the 8-byte module preamble.
    Header,
    /// Holds all standard Wasm sections in canonical order.
    Module,
    /// Anything not explicitly placed.
    #[default]
    Unused,
}

impl platform::SegmentType for SegmentType {}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProgramSegmentDef {
    pub(crate) segment_type: SegmentType,
}

impl std::fmt::Display for ProgramSegmentDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.segment_type)
    }
}

impl platform::ProgramSegmentDef for ProgramSegmentDef {
    fn is_writable(self) -> bool {
        false
    }

    fn is_executable(self) -> bool {
        false
    }

    fn always_keep(self) -> bool {
        true
    }

    fn is_loadable(self) -> bool {
        false
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
}

pub(crate) struct BuiltInSectionDetails {
    pub(crate) kind: SectionKind<'static, Wasm>,
}

impl platform::BuiltInSectionDetails for BuiltInSectionDetails {}

const DEFAULT_DEFS: BuiltInSectionDetails = BuiltInSectionDetails {
    kind: SectionKind::Primary(SectionIdentity::new(SectionName(&[]), ())),
};

const NUM_BUILT_IN_SECTIONS: usize = crate::output_section_id::num_built_in_sections::<Wasm>();

const SECTION_DEFINITIONS: [BuiltInSectionDetails; NUM_BUILT_IN_SECTIONS] = {
    use crate::layout_rules::SectionKind;
    use crate::output_section_id::SectionName;
    use crate::wasm::output_section_id as osid;

    let mut defs = [DEFAULT_DEFS; NUM_BUILT_IN_SECTIONS];

    // The module preamble.
    defs[crate::output_section_id::FILE_HEADER.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"WASM_HEADER"), ())),
    };

    // Standard Wasm sections.
    defs[osid::WASM_TYPE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"type"), ())),
    };
    defs[osid::WASM_IMPORT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"import"), ())),
    };
    defs[osid::WASM_FUNCTION.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"function"), ())),
    };
    defs[osid::WASM_TABLE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"table"), ())),
    };
    defs[osid::WASM_MEMORY.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"memory"), ())),
    };
    defs[osid::WASM_GLOBAL.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"global"), ())),
    };
    defs[osid::WASM_EXPORT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"export"), ())),
    };
    defs[osid::WASM_START.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"start"), ())),
    };
    defs[osid::WASM_ELEMENT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"element"), ())),
    };
    defs[osid::WASM_DATA_COUNT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"data_count"), ())),
    };
    defs[osid::WASM_CODE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"code"), ())),
    };
    defs[osid::WASM_DATA.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"data"), ())),
    };
    defs[osid::WASM_NAME.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"name"), ())),
    };
    defs[osid::WASM_TARGET_FEATURES.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"target_features"), ())),
    };

    defs
};

const PROGRAM_SEGMENT_DEFS: &[ProgramSegmentDef] = &[
    ProgramSegmentDef {
        segment_type: SegmentType::Header,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::Module,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::Unused,
    },
];

const DEFAULT_SECTION_RULES: &[SectionRule<'static>] = &[
    SectionRule::exact(b"type", SectionRuleOutcome::Discard),
    SectionRule::exact(b"import", SectionRuleOutcome::Discard),
    SectionRule::exact(b"function", SectionRuleOutcome::Discard),
    SectionRule::exact(b"table", SectionRuleOutcome::Discard),
    SectionRule::exact(b"memory", SectionRuleOutcome::Discard),
    SectionRule::exact(b"global", SectionRuleOutcome::Discard),
    SectionRule::exact(b"export", SectionRuleOutcome::Discard),
    SectionRule::exact(b"start", SectionRuleOutcome::Discard),
    SectionRule::exact(b"element", SectionRuleOutcome::Discard),
    SectionRule::exact(b"data_count", SectionRuleOutcome::Discard),
    SectionRule::exact(b"code", SectionRuleOutcome::Discard),
    SectionRule::exact(b"data", SectionRuleOutcome::Discard),
    SectionRule::exact(b"linking", SectionRuleOutcome::Discard),
    SectionRule::prefix(b"reloc.", SectionRuleOutcome::Discard),
    SectionRule::exact(b"name", SectionRuleOutcome::Discard),
    SectionRule::exact(b"target_features", SectionRuleOutcome::Discard),
];

#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct DynamicTagValues<'data> {
    _phantom: std::marker::PhantomData<&'data [u8]>,
}

impl<'data> platform::DynamicTagValues<'data> for DynamicTagValues<'data> {
    fn lib_name(&self, input: &crate::input_data::InputRef<'data>) -> &'data [u8] {
        input.lib_name()
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
        true
    }
}

impl std::fmt::Display for RawSymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&String::from_utf8_lossy(self.name), f)
    }
}

pub(crate) struct VerneedTable<'data> {
    _phantom: &'data [u8],
}

impl<'data> platform::VerneedTable<'data> for VerneedTable<'data> {
    fn version_name(&self, _local_symbol_index: object::SymbolIndex) -> Option<&'data [u8]> {
        None
    }
}

#[derive(Debug, Default)]
pub(crate) struct RelocationList<'data> {
    pub(crate) entries: Vec<WasmRelocation>,
    _phantom: std::marker::PhantomData<&'data ()>,
}

impl<'data> platform::RelocationList<'data> for RelocationList<'data> {
    fn num_relocations(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug, Default)]
pub(crate) struct WasmLayout<'data> {
    pub(crate) output_types: Vec<wasmparser::FuncType>,
    pub(crate) imports: Vec<OutputImport<'data>>,
    pub(crate) function_type_indices: Vec<u32>,
    pub(crate) globals: Vec<OutputGlobal<'data>>,
    pub(crate) exports: Vec<OutputExport<'data>>,
    pub(crate) function_bodies: Vec<WasmFunctionBody<'data>>,
    pub(crate) memories: Vec<MemoryType>,
    pub(crate) tables: Vec<wasmparser::TableType>,
    pub(crate) element_functions: Vec<u32>,
    pub(crate) function_table_slots: Vec<u32>,
    pub(crate) memory_base: u32,
    pub(crate) data_end: u32,
    pub(crate) unsupported_output: Vec<&'static str>,
    pub(crate) object_index_maps: Vec<WasmObjectIndexMap>,
    pub(crate) object_data_layouts: Vec<Vec<WasmDataSegmentLayout<'data>>>,
    pub(crate) per_object_symbols: Vec<&'data [WasmSymbol]>,
    pub(crate) encoded_sections: WasmEncodedSections,
    pub(crate) code_section_size: u64,
    pub(crate) data_section_size: u64,
}

#[derive(Debug, Default)]
pub(crate) struct WasmEncodedSections {
    pub(crate) ty: Option<Vec<u8>>,
    pub(crate) import: Option<Vec<u8>>,
    pub(crate) function: Option<Vec<u8>>,
    pub(crate) global: Option<Vec<u8>>,
    pub(crate) export: Option<Vec<u8>>,
    pub(crate) memory: Option<Vec<u8>>,
    pub(crate) table: Option<Vec<u8>>,
    pub(crate) element: Option<Vec<u8>>,
    // Custom `name` section.
    pub(crate) name: Option<Vec<u8>>,
    // Custom `target_features` section.
    pub(crate) target_features: Option<Vec<u8>>,
}

impl WasmEncodedSections {
    fn add_sizes_to(&self, sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>) {
        add_encoded_section_size(sizes, part_id::WASM_TYPE, self.ty.as_ref());
        add_encoded_section_size(sizes, part_id::WASM_IMPORT, self.import.as_ref());
        add_encoded_section_size(sizes, part_id::WASM_FUNCTION, self.function.as_ref());
        add_encoded_section_size(sizes, part_id::WASM_TABLE, self.table.as_ref());
        add_encoded_section_size(sizes, part_id::WASM_MEMORY, self.memory.as_ref());
        add_encoded_section_size(sizes, part_id::WASM_GLOBAL, self.global.as_ref());
        add_encoded_section_size(sizes, part_id::WASM_EXPORT, self.export.as_ref());
        add_encoded_section_size(sizes, part_id::WASM_ELEMENT, self.element.as_ref());
        add_encoded_section_size(sizes, part_id::WASM_NAME, self.name.as_ref());
        add_encoded_section_size(
            sizes,
            part_id::WASM_TARGET_FEATURES,
            self.target_features.as_ref(),
        );
    }
}

/// Per-object name entries.
#[derive(Default)]
struct ObjectNameEntries<'a> {
    functions: Vec<(u32, &'a str)>,
    globals: Vec<(u32, &'a str)>,
}

fn add_encoded_section_size(
    sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    part_id: PartId,
    section: Option<&Vec<u8>>,
) {
    if let Some(bytes) = section {
        sizes.increment(part_id, bytes.len() as u64);
    }
}

fn encode_wasm_section(section: &impl wasm_encoder::Section) -> Vec<u8> {
    let mut bytes = Vec::new();
    section.append_to(&mut bytes);
    bytes
}

fn build_name_section<'data>(
    layout: &WasmLayout<'data>,
    layout_inputs: &[WasmObjectLayoutInput<'data>],
    indices: &LinkerDefinedIndices,
    got_mem: &GotMem,
    got_func: &GotFunc,
) -> Option<wasm_encoder::NameSection> {
    let (n_func_imports, n_global_imports) = count_output_imports(layout);
    let n_funcs = n_func_imports + layout.function_type_indices.len();
    let n_globals = n_global_imports + layout.globals.len();
    let mut function_names: Vec<Option<&str>> = vec![None; n_funcs];
    let mut global_names: Vec<Option<&str>> = vec![None; n_globals];
    let mut got_mem_names: Vec<String> = Vec::new();
    let mut got_func_names: Vec<String> = Vec::new();

    // Host / remaining imports.
    let mut next_func_import = 0u32;
    let mut next_global_import = 0u32;
    for import in &layout.imports {
        match import.entity {
            crate::wasm_writer::OutputImportEntity::Function { .. } => {
                set_name_first_wins(&mut function_names, next_func_import, import.name);
                next_func_import += 1;
            }
            crate::wasm_writer::OutputImportEntity::Global(_) => {
                set_name_first_wins(&mut global_names, next_global_import, import.name);
                next_global_import += 1;
            }
        }
    }

    // Linker-synthesised functions / globals.
    if let Some(idx) = indices.memory_base_global {
        set_name_first_wins(&mut global_names, idx, "__memory_base");
    }
    if let Some(idx) = indices.table_base_global {
        set_name_first_wins(&mut global_names, idx, "__table_base");
    }
    if let Some(idx) = indices.stack_pointer_global {
        set_name_first_wins(&mut global_names, idx, "__stack_pointer");
    }
    if let Some(idx) = indices.tls_base_global {
        set_name_first_wins(&mut global_names, idx, "__tls_base");
    }
    for &(known, idx) in &indices.data_address_globals {
        set_name_first_wins(&mut global_names, idx, <&str>::from(known));
    }
    if let Some(got_base) = indices.got_mem_global_base {
        got_mem_names.reserve(got_mem.entries.len());
        for (i, entry) in got_mem.entries.iter().enumerate() {
            let name = match entry.def {
                GotMemDef::Object {
                    object_index,
                    symbol_offset,
                } => layout_inputs
                    .get(object_index)
                    .and_then(|input| {
                        input
                            .symbols
                            .get(symbol_offset)
                            .and_then(|sym| wasm_symbol_name_str(input.data, sym))
                    })
                    .map_or_else(
                        || format!("GOT.data.internal.{i}"),
                        |sym| format!("GOT.data.internal.{sym}"),
                    ),
                GotMemDef::LinkerDefined(known) => {
                    let sym = std::str::from_utf8(known.name()).unwrap_or("?");
                    format!("GOT.data.internal.{sym}")
                }
            };
            got_mem_names.push(name);
        }
        for (i, name) in got_mem_names.iter().enumerate() {
            set_name_first_wins(&mut global_names, got_base + i as u32, name.as_str());
        }
    }
    if let Some(got_base) = indices.got_func_global_base {
        got_func_names.reserve(got_func.entries.len());
        for (i, entry) in got_func.entries.iter().enumerate() {
            got_func_names.push(got_func_debug_name(layout_inputs, entry, i));
        }
        for (i, name) in got_func_names.iter().enumerate() {
            set_name_first_wins(&mut global_names, got_base + i as u32, name.as_str());
        }
    }
    if let Some(idx) = indices.call_ctors_func {
        set_name_first_wins(&mut function_names, idx, "__wasm_call_ctors");
    }

    let per_object_names: Vec<ObjectNameEntries<'_>> = layout_inputs
        .par_iter()
        .zip(layout.object_index_maps.par_iter())
        .map(|(input, index_map)| {
            verbose_timing_phase!("Collect Wasm object name entries");
            let mut entries = ObjectNameEntries::default();
            for sym in input.symbols {
                let Some(name) = wasm_symbol_name_str(input.data, sym) else {
                    continue;
                };
                match sym.kind {
                    WasmSymbolKind::Func
                        if let Some(&out_idx) =
                            index_map.function_indices.get(sym.index as usize)
                            && out_idx != WASM_DEAD_INDEX =>
                    {
                        entries.functions.push((out_idx, name));
                    }
                    WasmSymbolKind::Global
                        if let Some(&out_idx) =
                            index_map.global_indices.get(sym.index as usize)
                            && out_idx != WASM_DEAD_INDEX =>
                    {
                        entries.globals.push((out_idx, name));
                    }
                    _ => {}
                }
            }
            entries
        })
        .collect();
    for entries in per_object_names {
        for (out_idx, name) in entries.functions {
            set_name_first_wins(&mut function_names, out_idx, name);
        }
        for (out_idx, name) in entries.globals {
            set_name_first_wins(&mut global_names, out_idx, name);
        }
    }

    for export in &layout.exports {
        match export.kind {
            wasmparser::ExternalKind::Func => {
                set_name_first_wins(&mut function_names, export.index, export.name);
            }
            wasmparser::ExternalKind::Global => {
                set_name_first_wins(&mut global_names, export.index, export.name);
            }
            _ => {}
        }
    }

    let function_map = name_map_from_dense(&function_names);
    let global_map = name_map_from_dense(&global_names);
    if function_map.is_none() && global_map.is_none() {
        return None;
    }

    let mut section = NameSection::new();
    if let Some(map) = function_map {
        section.functions(&map);
    }
    if let Some(map) = global_map {
        section.globals(&map);
    }
    Some(section)
}

fn count_output_imports(layout: &WasmLayout<'_>) -> (usize, usize) {
    let mut functions = 0usize;
    let mut globals = 0usize;
    for import in &layout.imports {
        match import.entity {
            crate::wasm_writer::OutputImportEntity::Function { .. } => functions += 1,
            crate::wasm_writer::OutputImportEntity::Global(_) => globals += 1,
        }
    }
    (functions, globals)
}

fn set_name_first_wins<'a>(names: &mut Vec<Option<&'a str>>, index: u32, name: &'a str) {
    let i = index as usize;
    if i >= names.len() {
        names.resize(i + 1, None);
    }
    if names[i].is_none() {
        names[i] = Some(name);
    }
}

fn name_map_from_dense(names: &[Option<&str>]) -> Option<NameMap> {
    if names.iter().all(Option::is_none) {
        return None;
    }
    let mut map = NameMap::new();
    for (idx, name) in names.iter().enumerate() {
        if let Some(name) = name {
            map.append(idx as u32, name);
        }
    }
    Some(map)
}

fn wasm_symbol_name_str<'data>(data: &'data [u8], sym: &WasmSymbol) -> Option<&'data str> {
    if !sym.has_name() {
        return None;
    }
    let bytes = data.get(sym.name_range())?;
    core::str::from_utf8(bytes).ok()
}

/// Merge `target_features` from linked objects and encode the output custom section.
fn build_target_features_section<'data>(
    layout_inputs: &[WasmObjectLayoutInput<'data>],
) -> Result<Option<wasm_encoder::CustomSection<'static>>> {
    let mut used: HashSet<&'data str> = HashSet::new();
    // First file that disallowed each feature.
    let mut disallowed: HashMap<&'data str, crate::input_data::FileId> = HashMap::new();

    for input in layout_inputs {
        for feature in input.target_features {
            match feature.prefix {
                TARGET_FEATURE_PREFIX_USED => {
                    used.insert(feature.name);
                }
                TARGET_FEATURE_PREFIX_DISALLOWED => {
                    disallowed.entry(feature.name).or_insert(input.file_id);
                }
                other => {
                    bail!(
                        "unrecognized target_features prefix 0x{other:02x} for feature `{}`",
                        feature.name
                    );
                }
            }
        }
    }

    for name in &used {
        if let Some(&file_id) = disallowed.get(name) {
            bail!(
                "target feature `{name}` is used by linked objects but disallowed by input file \
                 {file_id}"
            );
        }
    }

    if used.is_empty() {
        return Ok(None);
    }

    let mut names: Vec<&'data str> = used.into_iter().collect();
    names.sort_unstable();

    let mut payload = Vec::new();
    leb128::write::unsigned(&mut payload, names.len() as u64).unwrap();
    for name in names {
        payload.push(TARGET_FEATURE_PREFIX_USED);
        let name_bytes = name.as_bytes();
        leb128::write::unsigned(&mut payload, name_bytes.len() as u64).unwrap();
        payload.extend_from_slice(name_bytes);
    }

    Ok(Some(wasm_encoder::CustomSection {
        name: Cow::Borrowed(TARGET_FEATURES_SECTION_NAME),
        data: Cow::Owned(payload),
    }))
}

fn parse_target_features_payload<'data>(
    data: &'data [u8],
) -> Result<Vec<WasmTargetFeature<'data>>> {
    let mut reader = BinaryReader::new(data, 0);
    let count = reader
        .read_var_u32()
        .context("invalid target_features feature count")?;
    let mut features = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let prefix = reader
            .read_u8()
            .context("truncated target_features feature prefix")?;
        let name = reader
            .read_string()
            .context("invalid target_features feature name")?;
        features.push(WasmTargetFeature { prefix, name });
    }
    ensure!(
        reader.eof(),
        "trailing bytes in target_features section after {} features",
        features.len()
    );
    Ok(features)
}

impl<'data> WasmLayout<'data> {
    fn encode_metadata_sections(
        &mut self,
        layout_inputs: &[WasmObjectLayoutInput<'data>],
        indices: &LinkerDefinedIndices,
        got_mem: &GotMem,
        got_func: &GotFunc,
    ) -> Result {
        timing_phase!("Encode Wasm metadata sections");

        {
            timing_phase!("Encode Wasm type section");
            let type_section = crate::wasm_writer::build_type_section(&self.output_types)?;
            if !type_section.is_empty() {
                self.encoded_sections.ty = Some(encode_wasm_section(&type_section));
            }
        }

        {
            timing_phase!("Encode Wasm import section");
            let import_section = crate::wasm_writer::build_import_section(&self.imports)?;
            if !import_section.is_empty() {
                self.encoded_sections.import = Some(encode_wasm_section(&import_section));
            }
        }

        {
            timing_phase!("Encode Wasm function section");
            let function_section =
                crate::wasm_writer::build_function_section(&self.function_type_indices);
            if !function_section.is_empty() {
                self.encoded_sections.function = Some(encode_wasm_section(&function_section));
            }
        }

        {
            timing_phase!("Encode Wasm global section");
            let global_section = crate::wasm_writer::build_global_section(&self.globals)?;
            if !global_section.is_empty() {
                self.encoded_sections.global = Some(encode_wasm_section(&global_section));
            }
        }

        {
            timing_phase!("Encode Wasm export section");
            let export_section = crate::wasm_writer::build_export_section(&self.exports);
            if !export_section.is_empty() {
                self.encoded_sections.export = Some(encode_wasm_section(&export_section));
            }
        }

        {
            timing_phase!("Encode Wasm memory section");
            let memory_section = crate::wasm_writer::build_memory_section(&self.memories);
            if !memory_section.is_empty() {
                self.encoded_sections.memory = Some(encode_wasm_section(&memory_section));
            }
        }

        if !self.tables.is_empty() {
            timing_phase!("Encode Wasm table section");
            let table_section = crate::wasm_writer::build_table_section(&self.tables)?;
            self.encoded_sections.table = Some(encode_wasm_section(&table_section));
        }

        if !self.element_functions.is_empty() {
            timing_phase!("Encode Wasm element section");
            let element_section =
                crate::wasm_writer::build_element_section(&self.element_functions);
            self.encoded_sections.element = Some(encode_wasm_section(&element_section));
        }

        {
            timing_phase!("Encode Wasm name section");
            if let Some(name_section) =
                build_name_section(self, layout_inputs, indices, got_mem, got_func)
            {
                self.encoded_sections.name = Some(encode_wasm_section(&name_section));
            }
        }

        {
            timing_phase!("Encode Wasm target_features section");
            if let Some(target_features) = build_target_features_section(layout_inputs)? {
                self.encoded_sections.target_features = Some(encode_wasm_section(&target_features));
            }
        }

        {
            timing_phase!("Compute Wasm code/data section sizes");
            self.code_section_size = compute_code_section_size(&self.function_bodies);
            self.data_section_size = compute_data_section_size(&self.object_data_layouts);
        }

        Ok(())
    }

    fn add_code_section_size(
        &self,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
        if self.code_section_size > 0 {
            sizes.increment(part_id::WASM_CODE, self.code_section_size);
        }
    }

    fn add_data_section_size(
        &self,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
        if self.data_section_size > 0 {
            sizes.increment(part_id::WASM_DATA, self.data_section_size);
        }
    }
}

fn const_expr_encoded_size(expr: &ConstExpr<'_>) -> Result<u32> {
    let body = crate::wasm_writer::const_expr_body(expr)
        .ok_or_else(|| crate::error!("Wasm const expression is missing end opcode"))?;
    // instruction bytes plus the trailing `end` (0x0B) opcode
    u32::try_from(body.len() + 1).context("Wasm const expression too large")
}

/// Encoded size of one segment in the data section payload. See `data` in
/// <https://webassembly.github.io/spec/core/binary/modules.html#data-section>.
fn wasm_data_segment_encoded_size(kind: &DataKind<'_>, data_len: usize) -> Result<u32> {
    let data_len = u32::try_from(data_len).context("Wasm data segment too large")?;
    let payload_len = uleb128_size(u64::from(data_len)) as u32 + data_len;
    match kind {
        DataKind::Passive => Ok(1 + payload_len),
        DataKind::Active {
            memory_index,
            offset_expr,
        } => {
            let init_len = const_expr_encoded_size(offset_expr)?;
            let header = if *memory_index == 0 {
                1
            } else {
                1 + uleb128_size(u64::from(*memory_index)) as u32
            };
            Ok(header
                .checked_add(init_len)
                .and_then(|n| n.checked_add(payload_len))
                .ok_or_else(|| crate::error!("Wasm data segment size overflow"))?)
        }
    }
}

/// Byte length of the offset `expr` we emit (`i32.const` + SLEB + `end`).
fn output_i32_const_init_expr_size(offset: u32) -> u32 {
    1 + sleb128_size(i64::from(offset)) as u32 + 1
}

fn output_data_segment_encoded_size(
    kind: &DataKind<'_>,
    data_len: usize,
    output_memory_offset: u32,
    output_memory_index: u32,
) -> Result<u32> {
    let data_len = u32::try_from(data_len).context("Wasm data segment too large")?;
    let payload_len = uleb128_size(u64::from(data_len)) as u32 + data_len;
    match kind {
        DataKind::Passive => bail!("passive data segments are not emitted"),
        DataKind::Active { .. } => {
            let init_len = output_i32_const_init_expr_size(output_memory_offset);
            let header = if output_memory_index == 0 {
                1
            } else {
                1 + uleb128_size(u64::from(output_memory_index)) as u32
            };
            Ok(header
                .checked_add(init_len)
                .and_then(|n| n.checked_add(payload_len))
                .ok_or_else(|| crate::error!("Wasm data segment size overflow"))?)
        }
    }
}

fn data_segment_payload_offset_in_section(kind: &DataKind<'_>, data_len: usize) -> Result<u32> {
    let encoded = wasm_data_segment_encoded_size(kind, data_len)?;
    let data_len = u32::try_from(data_len).context("Wasm data segment too large")?;
    encoded
        .checked_sub(data_len)
        .ok_or_else(|| crate::error!("Wasm data segment payload offset underflow"))
}

/// Precomputed span of one input data segment within the data section payload.
struct DataSegmentSpan {
    /// Inclusive start of the encoded segment in the section payload.
    start: u32,
    /// Exclusive end of the encoded segment.
    end: u32,
    /// Absolute section offset of the first payload byte (after segment header / init expr).
    payload_start: u32,
}

/// Map data-section relocations onto their owning segment with payload-local offsets.
fn classify_data_relocations(
    segments: &[WasmDataSegment<'_>],
    relocs: &[WasmRelocation],
) -> Vec<Vec<WasmRelocation>> {
    if segments.is_empty() || relocs.is_empty() {
        return vec![Vec::new(); segments.len()];
    }

    let mut spans = Vec::with_capacity(segments.len());
    for segment in segments {
        let Ok(encoded) = wasm_data_segment_encoded_size(&segment.kind, segment.data.len()) else {
            spans.push(DataSegmentSpan {
                start: 0,
                end: 0,
                payload_start: 0,
            });
            continue;
        };
        let Ok(payload_rel) =
            data_segment_payload_offset_in_section(&segment.kind, segment.data.len())
        else {
            spans.push(DataSegmentSpan {
                start: 0,
                end: 0,
                payload_start: 0,
            });
            continue;
        };
        let start = segment.section_offset;
        let end = start.saturating_add(encoded);
        let payload_start = start.saturating_add(payload_rel);
        spans.push(DataSegmentSpan {
            start,
            end,
            payload_start,
        });
    }

    debug_assert!(
        spans.windows(2).all(|w| w[0].start <= w[1].start),
        "data segments must be ordered by section_offset for binary search"
    );

    let mut per_segment = vec![Vec::new(); segments.len()];
    for &reloc in relocs {
        // Last span with start <= reloc.offset.
        let idx = spans
            .partition_point(|span| span.start <= reloc.offset)
            .saturating_sub(1);
        let Some(span) = spans.get(idx) else {
            continue;
        };
        if reloc.offset < span.start || reloc.offset >= span.end {
            continue;
        }
        if reloc.offset < span.payload_start {
            continue;
        }
        per_segment[idx].push(WasmRelocation {
            offset: reloc.offset - span.payload_start,
            ..reloc
        });
    }
    per_segment
}

/// Align `data_end` to [`STACK_ALIGNMENT`], then add the stack size.
fn stack_high_after_data(data_end: u32, stack_size: u32) -> Result<u32> {
    let stack_base = u32::try_from(crate::alignment::STACK_ALIGNMENT.align_up(u64::from(data_end)))
        .map_err(|_| crate::error!("Wasm stack base overflow"))?;
    stack_base
        .checked_add(stack_size)
        .ok_or_else(|| crate::error!("Wasm stack pointer overflow"))
}

/// Align the end of static data for `__heap_base`.
fn heap_base_after_data(data_end: u32) -> Result<u32> {
    u32::try_from(crate::alignment::STACK_ALIGNMENT.align_up(u64::from(data_end)))
        .map_err(|_| crate::error!("Wasm heap base overflow"))
}

/// Initial `__stack_pointer` value for the chosen stack layout.
fn stack_pointer_init(data_end: u32, stack_size: u32, stack_first: bool) -> Result<u32> {
    ensure_stack_size_aligned(stack_size)?;
    if stack_first {
        Ok(stack_size)
    } else {
        stack_high_after_data(data_end, stack_size)
    }
}

fn heap_base_address(data_end: u32, stack_size: u32, stack_first: bool) -> Result<u32> {
    if stack_first {
        heap_base_after_data(data_end)
    } else {
        stack_high_after_data(data_end, stack_size)
    }
}

fn ensure_stack_size_aligned(stack_size: u32) -> Result {
    let align = crate::alignment::STACK_ALIGNMENT.value();
    ensure!(
        u64::from(stack_size).is_multiple_of(align),
        "stack size must be {align}-byte aligned"
    );
    Ok(())
}

fn layout_object_data<'data>(
    input: &WasmObjectLayoutInput<'data>,
    index_map: &WasmObjectIndexMap,
    memory_cursor: &mut u32,
) -> Result<Vec<WasmDataSegmentLayout<'data>>> {
    let mut segment_relocations =
        classify_data_relocations(&input.data_segments, &input.data_relocations);
    let mut segments = Vec::with_capacity(input.data_segments.len());
    for (filtered_idx, segment) in input.data_segments.iter().enumerate() {
        let DataKind::Active { memory_index, .. } = segment.kind else {
            bail!("passive data segments are not emitted");
        };
        let output_memory_index =
            remap_wasm_index(&index_map.memory_indices, memory_index, "memory")?;
        let original_index = input
            .data_segment_original_indices
            .get(filtered_idx)
            .copied()
            .unwrap_or(filtered_idx as u32);
        // Linking `SegmentInfo.alignment` is a power-of-two exponent.
        let align = input
            .segment_alignments
            .get(original_index as usize)
            .copied()
            .unwrap_or(crate::alignment::MIN);
        *memory_cursor = u32::try_from(align.align_up(u64::from(*memory_cursor)))
            .map_err(|_| crate::error!("Wasm data segment alignment overflow"))?;
        let output_memory_offset = *memory_cursor;
        let encoded_output_size = output_data_segment_encoded_size(
            &segment.kind,
            segment.data.len(),
            output_memory_offset,
            output_memory_index,
        )?;
        *memory_cursor = memory_cursor
            .checked_add(u32::try_from(segment.data.len()).context("Wasm data segment too large")?)
            .ok_or_else(|| crate::error!("Wasm output memory offset overflow"))?;
        segments.push(WasmDataSegmentLayout {
            segment_index: original_index,
            data: segment.data,
            relocations: std::mem::take(&mut segment_relocations[filtered_idx]),
            output_memory_index,
            output_memory_offset,
            encoded_output_size,
        });
    }
    Ok(segments)
}

fn compute_data_section_size(object_data_layouts: &[Vec<WasmDataSegmentLayout<'_>>]) -> u64 {
    let segment_count: u32 = object_data_layouts
        .iter()
        .map(|obj| u32::try_from(obj.len()).unwrap_or(u32::MAX))
        .sum();
    if segment_count == 0 {
        return 0;
    }
    let count_leb_size = uleb128_size(u64::from(segment_count)) as u64;
    let segments_total: u64 = object_data_layouts
        .iter()
        .flatten()
        .map(|segment| u64::from(segment.encoded_output_size))
        .sum();
    let payload_size = count_leb_size + segments_total;
    let payload_size_leb_size = uleb128_size(payload_size) as u64;

    // `section` envelope. See <https://webassembly.github.io/spec/core/binary/modules.html#binary-section>
    1 + payload_size_leb_size + payload_size
}

fn compute_code_section_size(bodies: &[WasmFunctionBody<'_>]) -> u64 {
    if bodies.is_empty() {
        return 0;
    }
    let count = bodies.len() as u32;
    let count_leb_size = uleb128_size(u64::from(count)) as u64;
    let bodies_with_prefix_total: u64 = bodies
        .iter()
        .map(|b| {
            let body_len = b.bytes.len() as u64;
            uleb128_size(body_len) as u64 + body_len
        })
        .sum();
    let payload_size = count_leb_size + bodies_with_prefix_total;
    let payload_size_leb_size = uleb128_size(payload_size) as u64;

    // section id (1 byte) + payload size LEB + payload
    1 + payload_size_leb_size + payload_size
}

#[derive(Debug, Default)]
pub(crate) struct WasmObjectIndexMap {
    /// Maps this object's local type index to the final output type index.
    pub(crate) type_indices: Vec<u32>,
    pub(crate) function_indices: Vec<u32>,
    pub(crate) global_indices: Vec<u32>,
    pub(crate) memory_indices: Vec<u32>,
    pub(crate) table_indices: Vec<u32>,
    pub(crate) data_addresses: Vec<u32>,
    pub(crate) got_mem_globals: Vec<Option<u32>>,
    pub(crate) got_func_globals: Vec<Option<u32>>,
    pub(crate) function_symbol_redirects: Vec<Option<u32>>,
}

impl WasmObjectIndexMap {
    /// Resolve a code/data relocation to its output value using the symbol table from the same
    /// object.
    pub(crate) fn resolve_reloc(
        &self,
        reloc: &WasmRelocation,
        symbols: &[WasmSymbol],
        function_table_slots: &[u32],
        memory_base: u32,
    ) -> Result<u32> {
        if reloc.ty == RelocationType::TypeIndexLeb {
            return remap_wasm_index(&self.type_indices, reloc.index, "type");
        }

        let sym = symbols
            .get(reloc.index as usize)
            .ok_or_else(|| crate::error!("relocation symbol index {} out of range", reloc.index))?;

        match reloc.ty {
            RelocationType::FunctionIndexLeb | RelocationType::FunctionIndexI32 => {
                ensure!(
                    sym.kind == WasmSymbolKind::Func,
                    "R_WASM_FUNCTION_INDEX_* references non-function symbol"
                );
                self.output_function_index(reloc.index as usize, sym)
            }
            RelocationType::GlobalIndexLeb | RelocationType::GlobalIndexI32 => match sym.kind {
                WasmSymbolKind::Global => {
                    remap_wasm_index(&self.global_indices, sym.index, "global")
                }
                WasmSymbolKind::Data => self
                    .got_mem_globals
                    .get(reloc.index as usize)
                    .copied()
                    .flatten()
                    .ok_or_else(|| {
                        crate::error!(
                            "missing GOT.mem global for data symbol index {}",
                            reloc.index
                        )
                    }),
                WasmSymbolKind::Func => self
                    .got_func_globals
                    .get(reloc.index as usize)
                    .copied()
                    .flatten()
                    .ok_or_else(|| {
                        crate::error!(
                            "missing GOT.func global for function symbol index {}",
                            reloc.index
                        )
                    }),
                other => {
                    bail!("R_WASM_GLOBAL_INDEX_* references unsupported symbol kind {other:?}")
                }
            },
            RelocationType::TableNumberLeb => {
                ensure!(
                    sym.kind == WasmSymbolKind::Table,
                    "R_WASM_TABLE_NUMBER_LEB references non-table symbol"
                );
                remap_wasm_index(&self.table_indices, sym.index, "table")
            }
            RelocationType::MemoryAddrLeb
            | RelocationType::MemoryAddrSleb
            | RelocationType::MemoryAddrI32
            | RelocationType::MemoryAddrRelSleb => {
                ensure!(
                    sym.kind == WasmSymbolKind::Data,
                    "R_WASM_MEMORY_ADDR_* references non-data symbol"
                );
                let addr = self
                    .data_addresses
                    .get(reloc.index as usize)
                    .copied()
                    .ok_or_else(|| {
                        crate::error!("data address for symbol index {} out of range", reloc.index)
                    })?;
                if reloc.ty == RelocationType::MemoryAddrRelSleb {
                    let relative = i64::from(addr) - i64::from(memory_base) + reloc.addend;
                    let relative = i32::try_from(relative)
                        .map_err(|_| crate::error!("Wasm REL_SLEB relocation out of range"))?;
                    Ok(relative as u32)
                } else {
                    Ok(addr)
                }
            }
            RelocationType::TableIndexSleb
            | RelocationType::TableIndexI32
            | RelocationType::TableIndexRelSleb => {
                ensure!(
                    sym.kind == WasmSymbolKind::Func,
                    "R_WASM_TABLE_INDEX_* references non-function symbol"
                );
                let func_out = self.output_function_index(reloc.index as usize, sym)?;
                let slot = function_table_slots
                    .get(func_out as usize)
                    .copied()
                    .unwrap_or(u32::MAX);
                ensure!(
                    slot != u32::MAX,
                    "function {func_out} has no indirect table slot"
                );
                if reloc.ty == RelocationType::TableIndexRelSleb {
                    if slot == 0 {
                        return Ok(0);
                    }
                    let relative = slot.checked_sub(DEFAULT_TABLE_BASE).ok_or_else(|| {
                        crate::error!("Wasm TABLE_INDEX_REL_SLEB relocation out of range")
                    })?;
                    Ok(relative)
                } else {
                    Ok(slot)
                }
            }
            RelocationType::EventIndexLeb => {
                bail!("event index relocations are not supported yet");
            }
            RelocationType::FunctionOffsetI32 => {
                bail!("function offset relocations are not supported yet");
            }
            RelocationType::SectionOffsetI32 => {
                bail!("section offset relocations are not supported yet");
            }
            other => bail!(
                "unsupported Wasm relocation type {}",
                relocation_type_to_string(other)
            ),
        }
    }

    /// Output function index for a linking-section symbol.
    fn output_function_index(&self, symbol_offset: usize, sym: &WasmSymbol) -> Result<u32> {
        if let Some(out) = self
            .function_symbol_redirects
            .get(symbol_offset)
            .copied()
            .flatten()
        {
            return Ok(out);
        }
        remap_wasm_index(&self.function_indices, sym.index, "function")
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum WasmGcUnit {
    DefinedFunction(u32),
    DefinedGlobal(u32),
    DataSegment(u32),
    FunctionImport(u32),
    GlobalImport(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
enum WasmGcUnitState {
    #[default]
    Dead = 0,
    Live = 1,
}

impl WasmGcUnitState {
    fn is_live(self) -> bool {
        self == Self::Live
    }
}

#[derive(Debug, Default)]
pub(crate) struct WasmObjectLayout<'data> {
    pub(crate) symbol_id_range: crate::symbol_db::SymbolIdRange,
    pub(crate) file_id: crate::input_data::FileId,
    // Set once per-unit GC states have been allocated at object activate.
    gc_states_ready: bool,
    gc_defined_functions: Vec<WasmGcUnitState>,
    gc_defined_globals: Vec<WasmGcUnitState>,
    gc_data_segments: Vec<WasmGcUnitState>,
    gc_function_imports: Vec<WasmGcUnitState>,
    gc_global_imports: Vec<WasmGcUnitState>,
    func_import_symbol_offsets: Vec<Vec<usize>>,
    global_import_symbol_offsets: Vec<Vec<usize>>,
    relocs_ready: bool,
    code_relocations: Vec<WasmRelocation>,
    data_relocations: Vec<WasmRelocation>,
    function_body_spans: Vec<(u32, u32)>,
    data_segment_spans: Vec<(u32, u32)>,
    defined_function_live_ordinal: Vec<u32>,
    defined_global_live_ordinal: Vec<u32>,
    _phantom: std::marker::PhantomData<&'data ()>,
}

impl<'data> WasmObjectLayout<'data> {
    /// Allocate per-unit GC states from the object's unit counts.
    fn ensure_gc_states(&mut self, file: &File<'_>) {
        if self.gc_states_ready {
            return;
        }
        self.gc_defined_functions =
            vec![WasmGcUnitState::Dead; file.num_defined_functions as usize];
        self.gc_defined_globals = vec![WasmGcUnitState::Dead; file.num_defined_globals as usize];
        self.gc_data_segments = vec![WasmGcUnitState::Dead; file.num_data_segments as usize];
        self.gc_function_imports = vec![WasmGcUnitState::Dead; file.num_function_imports as usize];
        self.gc_global_imports = vec![WasmGcUnitState::Dead; file.num_global_imports as usize];

        let mut func_import_symbol_offsets = vec![Vec::new(); file.num_function_imports as usize];
        let mut global_import_symbol_offsets = vec![Vec::new(); file.num_global_imports as usize];
        for (sym_offset, sym) in file.symbols.iter().enumerate() {
            if !sym.is_undefined() {
                continue;
            }
            match sym.kind {
                WasmSymbolKind::Func => {
                    if let Some(slots) = func_import_symbol_offsets.get_mut(sym.index as usize) {
                        slots.push(sym_offset);
                    }
                }
                WasmSymbolKind::Global => {
                    if let Some(slots) = global_import_symbol_offsets.get_mut(sym.index as usize) {
                        slots.push(sym_offset);
                    }
                }
                _ => {}
            }
        }
        self.func_import_symbol_offsets = func_import_symbol_offsets;
        self.global_import_symbol_offsets = global_import_symbol_offsets;
        self.gc_states_ready = true;
    }

    fn state(&self, unit: WasmGcUnit) -> Option<WasmGcUnitState> {
        match unit {
            WasmGcUnit::DefinedFunction(i) => self.gc_defined_functions.get(i as usize).copied(),
            WasmGcUnit::DefinedGlobal(i) => self.gc_defined_globals.get(i as usize).copied(),
            WasmGcUnit::DataSegment(i) => self.gc_data_segments.get(i as usize).copied(),
            WasmGcUnit::FunctionImport(i) => self.gc_function_imports.get(i as usize).copied(),
            WasmGcUnit::GlobalImport(i) => self.gc_global_imports.get(i as usize).copied(),
        }
    }

    fn state_mut(&mut self, unit: WasmGcUnit) -> Option<&mut WasmGcUnitState> {
        match unit {
            WasmGcUnit::DefinedFunction(i) => self.gc_defined_functions.get_mut(i as usize),
            WasmGcUnit::DefinedGlobal(i) => self.gc_defined_globals.get_mut(i as usize),
            WasmGcUnit::DataSegment(i) => self.gc_data_segments.get_mut(i as usize),
            WasmGcUnit::FunctionImport(i) => self.gc_function_imports.get_mut(i as usize),
            WasmGcUnit::GlobalImport(i) => self.gc_global_imports.get_mut(i as usize),
        }
    }

    fn is_dead(&self, unit: WasmGcUnit) -> bool {
        self.state(unit) == Some(WasmGcUnitState::Dead)
    }

    fn mark_live(&mut self, unit: WasmGcUnit) -> bool {
        match self.state_mut(unit) {
            Some(state) if *state == WasmGcUnitState::Dead => {
                *state = WasmGcUnitState::Live;
                true
            }
            _ => false,
        }
    }

    /// Decode code/data reloc sections and body/segment spans once per object.
    fn ensure_relocs_decoded(&mut self, file: &File<'_>) -> Result {
        if self.relocs_ready {
            return Ok(());
        }

        let code_section_index = file.standard_section_index[section_id::CODE as usize];
        let mut code_relocations: Vec<WasmRelocation> = code_section_index
            .and_then(|code_idx| {
                file.reloc_sections
                    .iter()
                    .find(|s| s.target_section_index == code_idx)
            })
            .map(|s| s.decode_entries(file.data))
            .transpose()?
            .unwrap_or_default();
        sort_relocations_by_offset(&mut code_relocations);

        let data_section_index = file.standard_section_index[section_id::DATA as usize];
        let mut data_relocations: Vec<WasmRelocation> = data_section_index
            .and_then(|data_idx| {
                file.reloc_sections
                    .iter()
                    .find(|s| s.target_section_index == data_idx)
            })
            .map(|s| s.decode_entries(file.data))
            .transpose()?
            .unwrap_or_default();
        sort_relocations_by_offset(&mut data_relocations);

        self.function_body_spans = compute_function_body_spans(file)?;
        self.data_segment_spans = compute_data_segment_spans(file)?;
        self.code_relocations = code_relocations;
        self.data_relocations = data_relocations;
        self.relocs_ready = true;
        Ok(())
    }

    /// Pack live defined function/global ordinals into dense 0..n maps after the GC walk.
    fn compute_live_ordinals(&mut self) {
        self.defined_function_live_ordinal = pack_live_ordinals(&self.gc_defined_functions);
        self.defined_global_live_ordinal = pack_live_ordinals(&self.gc_defined_globals);
    }

    fn take_decoded_relocs(&mut self) -> (bool, Vec<WasmRelocation>, Vec<WasmRelocation>) {
        let ready = self.relocs_ready;
        self.relocs_ready = false;
        (
            ready,
            std::mem::take(&mut self.code_relocations),
            std::mem::take(&mut self.data_relocations),
        )
    }

    fn is_data_segment_live(&self, index: usize) -> bool {
        self.gc_data_segments
            .get(index)
            .is_some_and(|s| s.is_live())
    }

    fn is_defined_function_live(&self, index: usize) -> bool {
        self.gc_defined_functions
            .get(index)
            .is_some_and(|s| s.is_live())
    }

    fn is_defined_global_live(&self, index: usize) -> bool {
        self.gc_defined_globals
            .get(index)
            .is_some_and(|s| s.is_live())
    }

    fn live_function_import_bits(&self) -> Vec<bool> {
        self.gc_function_imports
            .iter()
            .map(|s| s.is_live())
            .collect()
    }

    fn live_global_import_bits(&self) -> Vec<bool> {
        self.gc_global_imports.iter().map(|s| s.is_live()).collect()
    }

    /// True when GC state was never allocated (object not activated) or every unit is live.
    fn all_units_live(&self) -> bool {
        !self.gc_states_ready
            || (self.gc_defined_functions.iter().all(|s| s.is_live())
                && self.gc_defined_globals.iter().all(|s| s.is_live())
                && self.gc_data_segments.iter().all(|s| s.is_live())
                && self.gc_function_imports.iter().all(|s| s.is_live())
                && self.gc_global_imports.iter().all(|s| s.is_live()))
    }

    fn all_defined_functions_live(&self) -> bool {
        !self.gc_states_ready || self.gc_defined_functions.iter().all(|s| s.is_live())
    }

    fn all_defined_globals_live(&self) -> bool {
        !self.gc_states_ready || self.gc_defined_globals.iter().all(|s| s.is_live())
    }

    fn all_data_segments_live(&self) -> bool {
        !self.gc_states_ready || self.gc_data_segments.iter().all(|s| s.is_live())
    }

    fn mark_all_units_live(&mut self) {
        self.gc_defined_functions.fill(WasmGcUnitState::Live);
        self.gc_defined_globals.fill(WasmGcUnitState::Live);
        self.gc_data_segments.fill(WasmGcUnitState::Live);
        self.gc_function_imports.fill(WasmGcUnitState::Live);
        self.gc_global_imports.fill(WasmGcUnitState::Live);
    }
}

fn pack_live_ordinals(states: &[WasmGcUnitState]) -> Vec<u32> {
    let mut next = 0u32;
    states
        .iter()
        .map(|state| {
            if state.is_live() {
                let ordinal = next;
                next += 1;
                ordinal
            } else {
                WASM_DEAD_INDEX
            }
        })
        .collect()
}

fn identity_ordinals(n: usize) -> Vec<u32> {
    (0..n as u32).collect()
}

fn sort_relocations_by_offset(relocs: &mut [WasmRelocation]) {
    if relocs.windows(2).any(|w| w[0].offset > w[1].offset) {
        relocs.sort_unstable_by_key(|r| r.offset);
    }
}

fn reloc_index_range(relocs: &[WasmRelocation], start: u32, end: u32) -> Range<usize> {
    let lo = relocs.partition_point(|r| r.offset < start);
    let hi = relocs.partition_point(|r| r.offset < end);
    lo..hi
}

fn relocs_in_offset_range(relocs: &[WasmRelocation], start: u32, end: u32) -> &[WasmRelocation] {
    &relocs[reloc_index_range(relocs, start, end)]
}

fn compute_function_body_spans(file: &File<'_>) -> Result<Vec<(u32, u32)>> {
    let Some(reader) = file.code_section_reader()? else {
        return Ok(Vec::new());
    };
    let code_payload_start = file.standard_section_index[section_id::CODE as usize]
        .and_then(|i| file.sections.get(i as usize))
        .map_or(0, |h| h.payload_range.start as usize);
    reader
        .into_iter()
        .map(|res| {
            let body = res?;
            let range = body.range();
            let start = u32::try_from(range.start - code_payload_start)
                .context("Wasm function body offset overflow")?;
            let end = u32::try_from(range.end - code_payload_start)
                .context("Wasm function body end overflow")?;
            Ok((start, end))
        })
        .collect()
}

fn compute_data_segment_spans(file: &File<'_>) -> Result<Vec<(u32, u32)>> {
    let segments = file.data_segments()?;
    let mut spans = Vec::with_capacity(segments.len());
    for segment in &segments {
        let encoded = wasm_data_segment_encoded_size(&segment.kind, segment.data.len())?;
        let start = segment.section_offset;
        let end = start
            .checked_add(encoded)
            .ok_or_else(|| crate::error!("Wasm data segment span overflow"))?;
        spans.push((start, end));
    }
    Ok(spans)
}

/// Map a linking symbol to its file-local GC unit, if any.
fn wasm_gc_unit_for_symbol(file: &File<'_>, symbol: &WasmSymbol) -> Option<WasmGcUnit> {
    match symbol.kind {
        WasmSymbolKind::Func if symbol.is_undefined() => {
            Some(WasmGcUnit::FunctionImport(symbol.index))
        }
        WasmSymbolKind::Func => symbol
            .index
            .checked_sub(file.num_function_imports)
            .map(WasmGcUnit::DefinedFunction),
        WasmSymbolKind::Global if symbol.is_undefined() => {
            Some(WasmGcUnit::GlobalImport(symbol.index))
        }
        WasmSymbolKind::Global => symbol
            .index
            .checked_sub(file.num_global_imports)
            .map(WasmGcUnit::DefinedGlobal),
        WasmSymbolKind::Data if !symbol.is_undefined() => {
            Some(WasmGcUnit::DataSegment(symbol.index))
        }
        _ => None,
    }
}

#[derive(Debug)]
struct WasmObjectLayoutInput<'data> {
    /// Input module bytes.
    data: &'data [u8],
    types: Vec<wasmparser::FuncType>,
    function_imports: Vec<WasmFunctionImport<'data>>,
    global_imports: Vec<WasmGlobalImport<'data>>,
    live_function_imports: Vec<bool>,
    live_global_imports: Vec<bool>,
    memory_imports: Vec<MemoryType>,
    table_imports: Vec<wasmparser::TableType>,
    module_functions: Vec<u32>,
    globals: Vec<OutputGlobal<'data>>,
    exports: Vec<OutputExport<'data>>,
    function_bodies: Vec<WasmFunctionBody<'data>>,
    memories: Vec<MemoryType>,
    unsupported_output: Vec<&'static str>,
    code_relocations: Vec<WasmRelocation>,
    data_segments: Vec<WasmDataSegment<'data>>,
    data_segment_original_indices: Vec<u32>,
    segment_alignments: &'data [Alignment],
    data_relocations: Vec<WasmRelocation>,
    symbols: &'data [WasmSymbol],
    init_funcs: &'data [WasmInitFunc],
    target_features: &'data [WasmTargetFeature<'data>],
    symbol_id_range: crate::symbol_db::SymbolIdRange,
    file_id: crate::input_data::FileId,
    defined_function_live_ordinal: Vec<u32>,
    defined_global_live_ordinal: Vec<u32>,
}

#[derive(Debug, Clone, Copy)]
struct WasmObjectIndexBases {
    type_index_base: u32,
    defined_function_base: u32,
    defined_global_base: u32,
}

#[derive(Debug)]
struct WasmObjectOutputLayout<'data> {
    types: Vec<wasmparser::FuncType>,
    function_type_indices: Vec<u32>,
    globals: Vec<OutputGlobal<'data>>,
    exports: Vec<OutputExport<'data>>,
    function_bodies: Vec<WasmFunctionBody<'data>>,
    memories: Vec<MemoryType>,
    unsupported_output: Vec<&'static str>,
    index_map: WasmObjectIndexMap,
}

impl<'data> WasmObjectLayoutInput<'data> {
    fn from_file(
        file: &'data File<'data>,
        layout: &WasmObjectLayout<'data>,
        handed_off_relocs: (bool, Vec<WasmRelocation>, Vec<WasmRelocation>),
    ) -> Result<Self> {
        let symbol_id_range = layout.symbol_id_range;
        let file_id = layout.file_id;

        let all_live = layout.all_units_live();
        let keep_all_functions = layout.all_defined_functions_live();
        let keep_all_globals = layout.all_defined_globals_live();
        let keep_all_data_segments = layout.all_data_segments_live();

        let mut types = Vec::new();
        if let Some(type_section) = file.type_section_reader()? {
            for group in type_section {
                for ty in group?.into_types() {
                    let wasmparser::CompositeInnerType::Func(func) = ty.composite_type.inner else {
                        bail!("Wasm non-function types are not emitted")
                    };
                    types.push(func);
                }
            }
        }

        let mut function_imports = Vec::new();
        let mut global_imports = Vec::new();
        let mut memory_imports = Vec::new();
        let mut table_imports = Vec::new();
        if let Some(imports) = file.import_section_reader()? {
            for import in imports.into_imports() {
                let import = import?;
                match import.ty {
                    TypeRef::Func(type_index) | TypeRef::FuncExact(type_index) => {
                        function_imports.push(WasmFunctionImport {
                            module: import.module,
                            name: import.name,
                            type_index,
                        });
                    }
                    TypeRef::Global(ty) => {
                        global_imports.push(WasmGlobalImport {
                            module: import.module,
                            name: import.name,
                            ty,
                        });
                    }
                    TypeRef::Table(ty) => {
                        table_imports.push(ty);
                    }
                    TypeRef::Memory(memory) => {
                        memory_imports.push(memory);
                    }
                    TypeRef::Tag(_) => bail!("Wasm tag imports are not emitted"),
                }
            }
        }

        let live_function_imports = if all_live {
            vec![true; function_imports.len()]
        } else {
            layout.live_function_import_bits()
        };
        let live_global_imports = if all_live {
            vec![true; global_imports.len()]
        } else {
            layout.live_global_import_bits()
        };

        let code_section_index = file.standard_section_index[section_id::CODE as usize];
        let data_section_index = file.standard_section_index[section_id::DATA as usize];

        let (relocs_were_ready, taken_code, taken_data) = handed_off_relocs;
        let (code_relocations_all, data_relocations_all) = if relocs_were_ready {
            (taken_code, taken_data)
        } else {
            let mut code_relocations: Vec<WasmRelocation> = code_section_index
                .and_then(|code_idx| {
                    file.reloc_sections
                        .iter()
                        .find(|s| s.target_section_index == code_idx)
                })
                .map(|s| s.decode_entries(file.data))
                .transpose()?
                .unwrap_or_default();
            sort_relocations_by_offset(&mut code_relocations);
            let mut data_relocations: Vec<WasmRelocation> = data_section_index
                .and_then(|data_idx| {
                    file.reloc_sections
                        .iter()
                        .find(|s| s.target_section_index == data_idx)
                })
                .map(|s| s.decode_entries(file.data))
                .transpose()?
                .unwrap_or_default();
            sort_relocations_by_offset(&mut data_relocations);
            (code_relocations, data_relocations)
        };

        // TODO(wasm): Currently relocs targeting `.debug*` are ignored (not applied, not emitted).
        let has_unsupported_non_code_relocs = file.reloc_sections.iter().any(|s| {
            let target = Some(s.target_section_index);
            if target == code_section_index || target == data_section_index {
                return false;
            }
            !file.section_is_debug(s.target_section_index)
        });

        let mut unsupported_output = Vec::new();
        if has_unsupported_non_code_relocs {
            unsupported_output.push("non-code relocation");
        }
        if !data_relocations_all.is_empty()
            && !data_relocations_are_supported(&data_relocations_all)
        {
            unsupported_output.push("data relocation");
        }
        if file.standard_section_index[section_id::TABLE as usize].is_some() {
            unsupported_output.push("table definition");
        }
        if file.standard_section_index[section_id::START as usize].is_some() {
            unsupported_output.push("start");
        }
        let all_data_segments = file.data_segments()?;
        for segment in &all_data_segments {
            if let DataKind::Passive = segment.kind {
                unsupported_output.push("passive data segment");
                break;
            }
        }

        let all_module_functions = file.module_functions()?;
        let all_function_bodies = file.function_bodies()?;
        ensure!(
            all_module_functions.len() == all_function_bodies.len(),
            "Wasm function and code section counts differ"
        );
        let memories = file.memories()?;

        let all_globals = file
            .module_globals()?
            .into_iter()
            .map(|global| {
                let init_expr_body = crate::wasm_writer::const_expr_body(&global.init_expr)
                    .ok_or_else(|| {
                        crate::error!("Wasm global initializer is missing end opcode")
                    })?;
                Ok(OutputGlobal {
                    ty: global.ty,
                    init_expr_body: Cow::Borrowed(init_expr_body),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let defined_function_live_ordinal = if keep_all_functions {
            identity_ordinals(all_module_functions.len())
        } else {
            layout.defined_function_live_ordinal.clone()
        };
        let defined_global_live_ordinal = if keep_all_globals {
            identity_ordinals(all_globals.len())
        } else {
            layout.defined_global_live_ordinal.clone()
        };

        let (module_functions, function_bodies, code_relocations) = if keep_all_functions {
            // All defined functions live.
            (
                all_module_functions,
                all_function_bodies,
                code_relocations_all,
            )
        } else {
            let mut module_functions = Vec::new();
            let mut function_bodies = Vec::new();
            let mut code_relocations = Vec::new();
            for (i, (ty, body)) in all_module_functions
                .into_iter()
                .zip(all_function_bodies)
                .enumerate()
            {
                if !layout.is_defined_function_live(i) {
                    continue;
                }
                let body_start = body.code_offset;
                let body_end = body_start + body.bytes.len() as u32;
                code_relocations.extend_from_slice(relocs_in_offset_range(
                    &code_relocations_all,
                    body_start,
                    body_end,
                ));
                module_functions.push(ty);
                function_bodies.push(body);
            }
            sort_relocations_by_offset(&mut code_relocations);
            (module_functions, function_bodies, code_relocations)
        };

        let globals = if keep_all_globals {
            all_globals
        } else {
            all_globals
                .into_iter()
                .enumerate()
                .filter_map(|(i, global)| layout.is_defined_global_live(i).then_some(global))
                .collect()
        };

        let (data_segments, data_segment_original_indices, data_relocations) =
            if keep_all_data_segments {
                let n = all_data_segments.len();
                let original_indices = (0..n as u32).collect();
                (all_data_segments, original_indices, data_relocations_all)
            } else {
                let mut data_segments = Vec::new();
                let mut data_segment_original_indices = Vec::new();
                let mut data_relocations = Vec::new();
                for (i, segment) in all_data_segments.into_iter().enumerate() {
                    if !layout.is_data_segment_live(i) {
                        continue;
                    }
                    let encoded =
                        wasm_data_segment_encoded_size(&segment.kind, segment.data.len())?;
                    let start = segment.section_offset;
                    let end = start
                        .checked_add(encoded)
                        .ok_or_else(|| crate::error!("Wasm data segment span overflow"))?;
                    data_relocations.extend_from_slice(relocs_in_offset_range(
                        &data_relocations_all,
                        start,
                        end,
                    ));
                    data_segment_original_indices
                        .push(u32::try_from(i).context("too many data segments")?);
                    data_segments.push(segment);
                }
                sort_relocations_by_offset(&mut data_relocations);
                (
                    data_segments,
                    data_segment_original_indices,
                    data_relocations,
                )
            };

        let mut exports = Vec::new();
        if let Some(export_section) = file.export_section_reader()? {
            for export in export_section {
                let export = export?;
                exports.push(OutputExport {
                    name: export.name,
                    kind: export.kind,
                    index: export.index,
                });
            }
        }

        Ok(Self {
            data: file.data,
            types,
            function_imports,
            global_imports,
            live_function_imports,
            live_global_imports,
            memory_imports,
            table_imports,
            module_functions,
            globals,
            exports,
            function_bodies,
            memories,
            unsupported_output,
            code_relocations,
            data_segments,
            data_segment_original_indices,
            segment_alignments: file.segment_alignments.as_slice(),
            data_relocations,
            symbols: file.symbols.as_slice(),
            init_funcs: file.init_funcs.as_slice(),
            target_features: file.target_features.as_slice(),
            symbol_id_range,
            file_id,
            defined_function_live_ordinal,
            defined_global_live_ordinal,
        })
    }

    fn build_object_output_layout(
        &self,
        object_index: usize,
        index_bases: WasmObjectIndexBases,
        resolutions: &ObjectImportResolutions,
        all_index_bases: &[WasmObjectIndexBases],
        indices: &LinkerDefinedIndices,
        shared_imports: &SharedUnresolvedImports<'data>,
    ) -> Result<WasmObjectOutputLayout<'data>> {
        ensure!(
            resolutions.function_resolutions.len() == self.function_imports.len(),
            "Wasm function import resolution count mismatch"
        );
        ensure!(
            resolutions.global_resolutions.len() == self.global_imports.len(),
            "Wasm global import resolution count mismatch"
        );

        let mut type_indices = Vec::with_capacity(self.types.len());
        for local_ty in 0..self.types.len() {
            let output_type_index = index_bases
                .type_index_base
                .checked_add(u32::try_from(local_ty).context("too many Wasm types")?)
                .ok_or_else(|| crate::error!("Wasm type index overflow"))?;
            type_indices.push(output_type_index);
        }

        let mut index_map = WasmObjectIndexMap {
            type_indices,
            function_indices: Vec::with_capacity(
                self.function_imports.len() + self.defined_function_live_ordinal.len(),
            ),
            global_indices: Vec::with_capacity(
                self.global_imports.len() + self.defined_global_live_ordinal.len(),
            ),
            memory_indices: Vec::with_capacity(self.memory_imports.len() + self.memories.len()),
            table_indices: vec![0; self.table_imports.len()],
            data_addresses: Vec::new(),
            got_mem_globals: Vec::new(),
            got_func_globals: Vec::new(),
            function_symbol_redirects: Vec::new(),
        };

        for (i, resolution) in resolutions.function_resolutions.iter().enumerate() {
            if !self.live_function_imports.get(i).copied().unwrap_or(false) {
                index_map.function_indices.push(WASM_DEAD_INDEX);
                continue;
            }
            match *resolution {
                ImportResolution::Unresolved => {
                    let output_function_index = shared_imports
                        .function_index(object_index, i)
                        .ok_or_else(|| {
                            crate::error!(
                                "missing shared function import index for object {object_index} \
                                 import {i}"
                            )
                        })?;
                    index_map.function_indices.push(output_function_index);
                }
                ImportResolution::LinkerDefined(known) => {
                    let index = indices.function_index(known).ok_or_else(|| {
                        crate::error!("missing reserved Wasm function for {known:?}")
                    })?;
                    index_map.function_indices.push(index);
                }
                ImportResolution::WeakUndefStub { stub_index } => {
                    let index = indices
                        .weak_undef_stubs
                        .get(stub_index as usize)
                        .map(|s| s.function_index)
                        .ok_or_else(|| {
                            crate::error!("Wasm weak-undef stub index {stub_index} out of range")
                        })?;
                    index_map.function_indices.push(index);
                }
                ImportResolution::ResolvedFunction {
                    object_index: def_object_index,
                    local_defined_index,
                } => {
                    ensure!(
                        def_object_index < all_index_bases.len(),
                        "Wasm function import resolution references object index \
                         {def_object_index} out of range"
                    );
                    ensure!(
                        local_defined_index != WASM_DEAD_INDEX,
                        "Wasm function import resolved to a GC'd definition"
                    );
                    let target_bases = &all_index_bases[def_object_index];
                    let output_function_index = target_bases
                        .defined_function_base
                        .checked_add(local_defined_index)
                        .ok_or_else(|| crate::error!("Wasm function index overflow"))?;
                    index_map.function_indices.push(output_function_index);
                }
                ImportResolution::ResolvedGlobal { .. }
                | ImportResolution::DirectGlobal { .. }
                | ImportResolution::GotMemSlot(_)
                | ImportResolution::GotFuncSlot(_) => {
                    bail!("function import resolved as global");
                }
            }
        }

        for (i, resolution) in resolutions.global_resolutions.iter().enumerate() {
            if !self.live_global_imports.get(i).copied().unwrap_or(false) {
                index_map.global_indices.push(WASM_DEAD_INDEX);
                continue;
            }
            match *resolution {
                ImportResolution::Unresolved => {
                    let output_global_index = shared_imports
                        .global_index(object_index, i)
                        .ok_or_else(|| {
                            crate::error!(
                                "missing shared global import index for object {object_index} \
                                 import {i}"
                            )
                        })?;
                    index_map.global_indices.push(output_global_index);
                }
                ImportResolution::LinkerDefined(known) => {
                    let index = indices.global_index(known).ok_or_else(|| {
                        crate::error!("missing reserved Wasm global for {known:?}")
                    })?;
                    index_map.global_indices.push(index);
                }
                ImportResolution::DirectGlobal { output_index } => {
                    index_map.global_indices.push(output_index);
                }
                ImportResolution::GotMemSlot(_) => {
                    bail!("GOT.mem slot was not converted to a module global index");
                }
                ImportResolution::GotFuncSlot(_) => {
                    bail!("GOT.func slot was not converted to a module global index");
                }
                ImportResolution::ResolvedGlobal {
                    object_index,
                    local_defined_index,
                } => {
                    ensure!(
                        object_index < all_index_bases.len(),
                        "Wasm global import resolution references object index {object_index} out \
                         of range"
                    );
                    ensure!(
                        local_defined_index != WASM_DEAD_INDEX,
                        "Wasm global import resolved to a GC'd definition"
                    );
                    let target_bases = &all_index_bases[object_index];
                    let output_global_index = target_bases
                        .defined_global_base
                        .checked_add(local_defined_index)
                        .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
                    index_map.global_indices.push(output_global_index);
                }
                ImportResolution::ResolvedFunction { .. }
                | ImportResolution::WeakUndefStub { .. } => {
                    bail!("global import resolved as function");
                }
            }
        }

        let mut function_type_indices = Vec::with_capacity(self.module_functions.len());
        for &local_type_index in &self.module_functions {
            let output_type_index = index_bases
                .type_index_base
                .checked_add(local_type_index)
                .ok_or_else(|| crate::error!("Wasm type index overflow"))?;
            function_type_indices.push(output_type_index);
        }
        // Full function index space: imports (above) + original defined ordinals.
        for &dense_or_dead in &self.defined_function_live_ordinal {
            if dense_or_dead == WASM_DEAD_INDEX {
                index_map.function_indices.push(WASM_DEAD_INDEX);
            } else {
                let output_function_index = index_bases
                    .defined_function_base
                    .checked_add(dense_or_dead)
                    .ok_or_else(|| crate::error!("Wasm function index overflow"))?;
                index_map.function_indices.push(output_function_index);
            }
        }

        for &dense_or_dead in &self.defined_global_live_ordinal {
            if dense_or_dead == WASM_DEAD_INDEX {
                index_map.global_indices.push(WASM_DEAD_INDEX);
            } else {
                let output_global_index = index_bases
                    .defined_global_base
                    .checked_add(dense_or_dead)
                    .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
                index_map.global_indices.push(output_global_index);
            }
        }

        // Imported and defined memories are merged into a single output memory.
        let memory_slot_count = self.memory_imports.len() + self.memories.len();
        index_map.memory_indices = vec![0; memory_slot_count];

        let exports = self
            .exports
            .iter()
            .map(|export| {
                let index = match export.kind {
                    wasmparser::ExternalKind::Func | wasmparser::ExternalKind::FuncExact => {
                        remap_wasm_index(&index_map.function_indices, export.index, "function")?
                    }
                    wasmparser::ExternalKind::Global => {
                        remap_wasm_index(&index_map.global_indices, export.index, "global")?
                    }
                    wasmparser::ExternalKind::Memory => {
                        remap_wasm_index(&index_map.memory_indices, export.index, "memory")?
                    }
                    wasmparser::ExternalKind::Table => 0, // single output table
                    wasmparser::ExternalKind::Tag => bail!("Wasm tag exports are not emitted"),
                };
                Ok(OutputExport { index, ..*export })
            })
            .collect::<Result<Vec<_>>>()?;

        let mut function_bodies = self.function_bodies.clone();
        classify_code_relocations(&mut function_bodies, &self.code_relocations);

        Ok(WasmObjectOutputLayout {
            types: self.types.clone(),
            function_type_indices,
            globals: self.globals.clone(),
            exports,
            function_bodies,
            memories: self.memories.clone(),
            unsupported_output: self.unsupported_output.clone(),
            index_map,
        })
    }
}

/// Describes how a single import was resolved during cross-object linking.
#[derive(Debug, Clone, Copy)]
enum ImportResolution {
    /// The import was not resolved; keep it in the output import section.
    Unresolved,
    /// The import was resolved to a defined function in `object_index` at local defined-function
    /// position `local_defined_index`.
    ResolvedFunction {
        object_index: usize,
        local_defined_index: u32,
    },
    /// The import was resolved to a defined global in `object_index` at local defined-global
    /// position `local_defined_index`.
    ResolvedGlobal {
        object_index: usize,
        local_defined_index: u32,
    },
    /// Resolved to a linker-synthesized function or global.
    LinkerDefined(WasmLinkerSymbol),
    /// Undefined weak function absorbed into a shared `unreachable` stub.
    WeakUndefStub { stub_index: u32 },
    /// Fixed module global index (GOT.mem / GOT.func entry).
    DirectGlobal { output_index: u32 },
    /// GOT.mem slot pending final module global index.
    GotMemSlot(usize),
    /// GOT.func slot pending final module global index.
    GotFuncSlot(usize),
}

#[derive(Debug, Default)]
struct ObjectImportResolutions {
    function_resolutions: Vec<ImportResolution>,
    global_resolutions: Vec<ImportResolution>,
}

#[derive(Debug, Clone)]
struct SharedFunctionImport<'data> {
    module: &'data str,
    name: &'data str,
    first_object: usize,
    local_type_index: u32,
}

#[derive(Debug, Clone)]
struct SharedGlobalImport<'data> {
    module: &'data str,
    name: &'data str,
    ty: GlobalType,
}

/// Unresolved host imports coalesced by `(module, name)` across objects.
#[derive(Debug, Default)]
struct SharedUnresolvedImports<'data> {
    functions: Vec<SharedFunctionImport<'data>>,
    globals: Vec<SharedGlobalImport<'data>>,
    function_indices: Vec<Vec<Option<u32>>>,
    global_indices: Vec<Vec<Option<u32>>>,
}

impl<'data> SharedUnresolvedImports<'data> {
    fn function_count(&self) -> u32 {
        self.functions.len() as u32
    }

    fn global_count(&self) -> u32 {
        self.globals.len() as u32
    }

    fn function_index(&self, object_index: usize, local_import: usize) -> Option<u32> {
        self.function_indices
            .get(object_index)?
            .get(local_import)
            .copied()
            .flatten()
    }

    fn global_index(&self, object_index: usize, local_import: usize) -> Option<u32> {
        self.global_indices
            .get(object_index)?
            .get(local_import)
            .copied()
            .flatten()
    }

    fn to_output_imports(
        &self,
        index_bases: &[WasmObjectIndexBases],
    ) -> Result<Vec<OutputImport<'data>>> {
        let mut imports = Vec::with_capacity(self.functions.len() + self.globals.len());
        for imp in &self.functions {
            let type_index = index_bases
                .get(imp.first_object)
                .ok_or_else(|| crate::error!("Wasm shared import object index out of range"))?
                .type_index_base
                .checked_add(imp.local_type_index)
                .ok_or_else(|| crate::error!("Wasm type index overflow"))?;
            imports.push(OutputImport {
                module: imp.module,
                name: imp.name,
                entity: OutputImportEntity::Function { type_index },
            });
        }
        for imp in &self.globals {
            imports.push(OutputImport {
                module: imp.module,
                name: imp.name,
                entity: OutputImportEntity::Global(imp.ty),
            });
        }
        Ok(imports)
    }
}

fn report_disallowed_unresolved_imports<'data>(
    inputs: &[WasmObjectLayoutInput<'data>],
    resolutions: &[ObjectImportResolutions],
    symbol_db: &SymbolDb<'data, Wasm>,
) -> Result {
    if symbol_db.args.allow_undefined {
        return Ok(());
    }

    let mut errors: Vec<String> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for (input, res) in inputs.iter().zip(resolutions.iter()) {
        let file_display = symbol_db.file(input.file_id).to_string();
        for (sym_offset, sym) in input.symbols.iter().enumerate() {
            if !sym.is_undefined() || sym.is_weak() || sym.is_explicit_name() {
                continue;
            }

            let is_unresolved = match sym.kind {
                WasmSymbolKind::Func => {
                    let idx = sym.index as usize;
                    input
                        .live_function_imports
                        .get(idx)
                        .copied()
                        .unwrap_or(false)
                        && res
                            .function_resolutions
                            .get(idx)
                            .is_some_and(|r| matches!(r, ImportResolution::Unresolved))
                }
                WasmSymbolKind::Global => {
                    let idx = sym.index as usize;
                    input.live_global_imports.get(idx).copied().unwrap_or(false)
                        && res
                            .global_resolutions
                            .get(idx)
                            .is_some_and(|r| matches!(r, ImportResolution::Unresolved))
                }
                _ => false,
            };
            if !is_unresolved {
                continue;
            }
            let Some(name) = wasm_symbol_name_str(input.data, sym) else {
                bail!(
                    "{file_display}: undefined symbol with no name (linking symbol index {sym_offset})"
                );
            };
            if !seen.insert((file_display.clone(), name.to_owned())) {
                continue;
            }
            errors.push(format!("{file_display}: undefined symbol: {name}"));
        }
    }

    if errors.is_empty() {
        return Ok(());
    }
    bail!("{}", errors.join("\n"));
}

fn collect_shared_unresolved_imports<'data>(
    inputs: &[WasmObjectLayoutInput<'data>],
    resolutions: &[ObjectImportResolutions],
) -> Result<SharedUnresolvedImports<'data>> {
    timing_phase!("Collect shared unresolved Wasm imports");

    let mut functions: Vec<SharedFunctionImport<'data>> = Vec::new();
    let mut globals: Vec<SharedGlobalImport<'data>> = Vec::new();
    let mut func_key_to_idx: HashMap<(&str, &str), u32> = HashMap::new();
    let mut global_key_to_idx: HashMap<(&str, &str), u32> = HashMap::new();
    let mut function_indices = Vec::with_capacity(inputs.len());
    let mut global_indices = Vec::with_capacity(inputs.len());

    for (obj_idx, (input, res)) in inputs.iter().zip(resolutions.iter()).enumerate() {
        let mut func_map = vec![None; input.function_imports.len()];
        for (i, import) in input.function_imports.iter().enumerate() {
            if !input.live_function_imports.get(i).copied().unwrap_or(false) {
                continue;
            }
            if !matches!(
                res.function_resolutions.get(i),
                Some(ImportResolution::Unresolved)
            ) {
                continue;
            }
            let local_type_index = import.type_index;
            ensure!(
                (local_type_index as usize) < input.types.len(),
                "Wasm type index {local_type_index} out of range for import `{}`.`{}`",
                import.module,
                import.name
            );
            let key = (import.module, import.name);
            let shared_idx = if let Some(&idx) = func_key_to_idx.get(&key) {
                let existing = &functions[idx as usize];
                let existing_ty =
                    &inputs[existing.first_object].types[existing.local_type_index as usize];
                let this_ty = &input.types[local_type_index as usize];
                ensure!(
                    existing_ty == this_ty,
                    "conflicting types for import `{}`.`{}`",
                    import.module,
                    import.name
                );
                idx
            } else {
                let idx =
                    u32::try_from(functions.len()).context("too many Wasm function imports")?;
                functions.push(SharedFunctionImport {
                    module: import.module,
                    name: import.name,
                    first_object: obj_idx,
                    local_type_index,
                });
                func_key_to_idx.insert(key, idx);
                idx
            };
            func_map[i] = Some(shared_idx);
        }
        function_indices.push(func_map);

        let mut global_map = vec![None; input.global_imports.len()];
        for (i, import) in input.global_imports.iter().enumerate() {
            if !input.live_global_imports.get(i).copied().unwrap_or(false) {
                continue;
            }
            if !matches!(
                res.global_resolutions.get(i),
                Some(ImportResolution::Unresolved)
            ) {
                continue;
            }
            let key = (import.module, import.name);
            let shared_idx = if let Some(&idx) = global_key_to_idx.get(&key) {
                let existing = &globals[idx as usize];
                ensure!(
                    existing.ty == import.ty,
                    "conflicting types for import `{}`.`{}`",
                    import.module,
                    import.name
                );
                idx
            } else {
                let idx = u32::try_from(globals.len()).context("too many Wasm global imports")?;
                globals.push(SharedGlobalImport {
                    module: import.module,
                    name: import.name,
                    ty: import.ty,
                });
                global_key_to_idx.insert(key, idx);
                idx
            };
            global_map[i] = Some(shared_idx);
        }
        global_indices.push(global_map);
    }

    Ok(SharedUnresolvedImports {
        functions,
        globals,
        function_indices,
        global_indices,
    })
}

fn local_defined_function_index(
    input: &WasmObjectLayoutInput<'_>,
    sym: &WasmSymbol,
) -> Result<u32> {
    let original = sym.index - input.function_imports.len() as u32;
    let dense = input
        .defined_function_live_ordinal
        .get(original as usize)
        .copied()
        .unwrap_or(WASM_DEAD_INDEX);
    ensure!(
        dense != WASM_DEAD_INDEX,
        "reference to GC'd Wasm defined function {original}"
    );
    Ok(dense)
}

fn local_defined_global_index(input: &WasmObjectLayoutInput<'_>, sym: &WasmSymbol) -> Result<u32> {
    let original = sym.index - input.global_imports.len() as u32;
    let dense = input
        .defined_global_live_ordinal
        .get(original as usize)
        .copied()
        .unwrap_or(WASM_DEAD_INDEX);
    ensure!(
        dense != WASM_DEAD_INDEX,
        "reference to GC'd Wasm defined global {original}"
    );
    Ok(dense)
}

/// Resolve cross-object imports. For each object's undefined function/global symbol, checks whether
/// `SymbolDb::definition()` points to a defined symbol. Resolutions are keyed by import ordinal
/// (`sym.index`), not symbol-table order.
fn resolve_cross_object_imports<'data>(
    inputs: &[WasmObjectLayoutInput<'data>],
    symbol_db: &crate::symbol_db::SymbolDb<'data, Wasm>,
    file_id_to_index: &HashMap<crate::input_data::FileId, usize>,
) -> Result<Vec<ObjectImportResolutions>> {
    timing_phase!("Resolve Wasm cross-object imports");

    inputs
        .par_iter()
        .map(|input| {
            verbose_timing_phase!("Resolve Wasm object imports");
            let function_resolutions = resolve_import_symbols(
                input.function_imports.len(),
                WasmSymbolKind::Func,
                input,
                inputs,
                symbol_db,
                file_id_to_index,
            )?;
            let global_resolutions = resolve_import_symbols(
                input.global_imports.len(),
                WasmSymbolKind::Global,
                input,
                inputs,
                symbol_db,
                file_id_to_index,
            )?;
            Ok(ObjectImportResolutions {
                function_resolutions,
                global_resolutions,
            })
        })
        .collect()
}

fn resolve_import_symbols<'data>(
    import_count: usize,
    kind: WasmSymbolKind,
    input: &WasmObjectLayoutInput<'data>,
    all_inputs: &[WasmObjectLayoutInput<'data>],
    symbol_db: &crate::symbol_db::SymbolDb<'data, Wasm>,
    file_id_to_index: &HashMap<crate::input_data::FileId, usize>,
) -> Result<Vec<ImportResolution>> {
    ensure!(u32::try_from(import_count).is_ok(), "too many Wasm imports");
    let mut resolutions = vec![ImportResolution::Unresolved; import_count];

    let live_imports = match kind {
        WasmSymbolKind::Func => input.live_function_imports.as_slice(),
        WasmSymbolKind::Global => input.live_global_imports.as_slice(),
        _ => &[],
    };

    for (sym_offset, sym) in input.symbols.iter().enumerate() {
        if !sym.is_undefined() || sym.kind != kind {
            continue;
        }
        let import_idx = sym.index as usize;
        if import_idx >= import_count {
            continue;
        }
        // Dead import slots are not emitted.
        if !live_imports.get(import_idx).copied().unwrap_or(false) {
            continue;
        }
        let resolution = resolve_one_import(
            sym_offset,
            kind,
            input,
            all_inputs,
            symbol_db,
            file_id_to_index,
        )?;
        if matches!(resolutions[import_idx], ImportResolution::Unresolved)
            && !matches!(resolution, ImportResolution::Unresolved)
        {
            resolutions[import_idx] = resolution;
        }
    }

    let import_names: Vec<&str> = match kind {
        WasmSymbolKind::Func => input.function_imports.iter().map(|i| i.name).collect(),
        WasmSymbolKind::Global => input.global_imports.iter().map(|i| i.name).collect(),
        _ => Vec::new(),
    };
    for (import_idx, name) in import_names.iter().enumerate() {
        if !live_imports.get(import_idx).copied().unwrap_or(false) {
            continue;
        }
        if !matches!(resolutions[import_idx], ImportResolution::Unresolved) {
            continue;
        }
        if let Some(resolution) = linker_defined_import_resolution(name, kind, symbol_db) {
            resolutions[import_idx] = resolution;
        }
    }

    Ok(resolutions)
}

/// Try to resolve a single undefined import symbol.
fn resolve_one_import<'data>(
    sym_offset: usize,
    expected_kind: WasmSymbolKind,
    input: &WasmObjectLayoutInput<'data>,
    all_inputs: &[WasmObjectLayoutInput<'data>],
    symbol_db: &crate::symbol_db::SymbolDb<'data, Wasm>,
    file_id_to_index: &HashMap<crate::input_data::FileId, usize>,
) -> Result<ImportResolution> {
    let symbol_id = input.symbol_id_range.offset_to_id(sym_offset);
    let def_id = symbol_db.definition(symbol_id);
    if def_id == symbol_id {
        return Ok(ImportResolution::Unresolved);
    }
    let def_file_id = symbol_db.file_id_for_symbol(def_id);

    if def_file_id == PRELUDE_FILE_ID {
        return Ok(
            linker_defined_from_prelude_def(def_id, expected_kind, symbol_db)
                .unwrap_or(ImportResolution::Unresolved),
        );
    }

    let Some(&def_obj_idx) = file_id_to_index.get(&def_file_id) else {
        return Ok(ImportResolution::Unresolved);
    };
    let def_input = &all_inputs[def_obj_idx];
    let def_sym = &def_input.symbols[def_input.symbol_id_range.id_to_offset(def_id)];
    if def_sym.is_undefined() || def_sym.kind != expected_kind {
        return Ok(ImportResolution::Unresolved);
    }
    match expected_kind {
        WasmSymbolKind::Func => {
            ensure!(
                def_sym.index >= def_input.function_imports.len() as u32,
                "defined Wasm function symbol index {} is within import range",
                def_sym.index
            );
            Ok(ImportResolution::ResolvedFunction {
                object_index: def_obj_idx,
                local_defined_index: local_defined_function_index(def_input, def_sym)?,
            })
        }
        WasmSymbolKind::Global => {
            ensure!(
                def_sym.index >= def_input.global_imports.len() as u32,
                "defined Wasm global symbol index {} is within import range",
                def_sym.index
            );
            Ok(ImportResolution::ResolvedGlobal {
                object_index: def_obj_idx,
                local_defined_index: local_defined_global_index(def_input, def_sym)?,
            })
        }
        _ => Ok(ImportResolution::Unresolved),
    }
}

fn linker_defined_from_prelude_def(
    def_id: crate::symbol_db::SymbolId,
    expected_kind: WasmSymbolKind,
    symbol_db: &SymbolDb<'_, Wasm>,
) -> Option<ImportResolution> {
    let def_info = symbol_db.prelude_symbol_def(def_id)?;
    let crate::parsing::SymbolPlacement::PlatformSpecific(known) = &def_info.placement else {
        return None;
    };
    known
        .matches_import_kind(expected_kind)
        .then_some(ImportResolution::LinkerDefined(*known))
}

/// Resolve an import name to a prelude platform-specific definition, if present in `SymbolDb`.
fn linker_defined_import_resolution(
    import_name: &str,
    expected_kind: WasmSymbolKind,
    symbol_db: &SymbolDb<'_, Wasm>,
) -> Option<ImportResolution> {
    let symbol_id =
        symbol_db.get_unversioned(&UnversionedSymbolName::prehashed(import_name.as_bytes()))?;
    let def_id = symbol_db.definition(symbol_id);
    linker_defined_from_prelude_def(def_id, expected_kind, symbol_db)
}

fn object_needs_linker_memory(input: &WasmObjectLayoutInput<'_>) -> bool {
    !input.memory_imports.is_empty() || !input.memories.is_empty()
}

fn any_object_needs_linker_memory(inputs: &[WasmObjectLayoutInput<'_>]) -> bool {
    inputs.iter().any(object_needs_linker_memory)
}

#[derive(Debug, Clone, Copy, Default)]
struct LinkerImportAbsorption {
    needs_memory_base: bool,
    needs_table_base: bool,
    needs_stack_pointer: bool,
    needs_tls_base: bool,
    needs_ctors: bool,
}

impl LinkerImportAbsorption {
    fn need(&mut self, known: WasmLinkerSymbol) {
        match known {
            WasmLinkerSymbol::CallCtors => self.needs_ctors = true,
            WasmLinkerSymbol::MemoryBase => self.needs_memory_base = true,
            WasmLinkerSymbol::TableBase => self.needs_table_base = true,
            WasmLinkerSymbol::StackPointer => self.needs_stack_pointer = true,
            // Single-threaded. Immutable base (no TLS segment yet).
            WasmLinkerSymbol::TlsBase => self.needs_tls_base = true,
            _ => {}
        }
    }

    fn from_resolutions(
        resolutions: &ObjectImportResolutions,
        live_function_imports: &[bool],
        live_global_imports: &[bool],
    ) -> Self {
        let mut absorption = Self::default();
        for (i, resolution) in resolutions.function_resolutions.iter().enumerate() {
            if !live_function_imports.get(i).copied().unwrap_or(false) {
                continue;
            }
            if let ImportResolution::LinkerDefined(known) = *resolution {
                absorption.need(known);
            }
        }
        for (i, resolution) in resolutions.global_resolutions.iter().enumerate() {
            if !live_global_imports.get(i).copied().unwrap_or(false) {
                continue;
            }
            if let ImportResolution::LinkerDefined(known) = *resolution {
                absorption.need(known);
            }
        }
        absorption
    }
}

/// Synthetic function produced for an unresolved weak function import.
#[derive(Debug, Clone)]
struct WeakUndefFunctionStub {
    ty: wasmparser::FuncType,
    function_index: u32,
}

/// Reserved Wasm index-space slots for linker-defined globals/functions.
#[derive(Debug, Clone, Default)]
struct LinkerDefinedIndices {
    memory_base_global: Option<u32>,
    table_base_global: Option<u32>,
    stack_pointer_global: Option<u32>,
    tls_base_global: Option<u32>,
    /// Index of `__stack_pointer` among the defined globals prepended by
    /// `emit_reserved_linker_definitions` (not the Wasm module global index).
    stack_pointer_defined_slot: Option<u32>,
    call_ctors_func: Option<u32>,
    entry_wrapper_func: Option<u32>,
    weak_undef_stubs: Vec<WeakUndefFunctionStub>,
    /// Linker-defined globals including GOT.mem.
    num_defined_globals: u32,
    num_defined_functions: u32,
    /// Unresolved host global imports.
    global_import_count: u32,
    /// First module global index for GOT.mem entries.
    got_mem_global_base: Option<u32>,
    got_mem_count: u32,
    /// First module global index for GOT.func entries.
    got_func_global_base: Option<u32>,
    got_func_count: u32,
    data_address_globals: Vec<(WasmLinkerSymbol, u32)>,
    // Linker symbols named by `--export` / `--export-if-defined`.
    requested_exports: Vec<WasmLinkerSymbol>,
    // `i32.const` for `__memory_base` when `memory_base_global` is set.
    memory_base_init: u32,
}

/// Where a GOT.mem slot's final linear-memory address comes from.
#[derive(Debug, Clone, Copy)]
enum GotMemDef {
    Object {
        object_index: usize,
        symbol_offset: usize,
    },
    LinkerDefined(WasmLinkerSymbol),
}

#[derive(Debug, Clone, Copy)]
struct GotMemEntry {
    def_symbol_id: SymbolId,
    def: GotMemDef,
}

#[derive(Debug, Default)]
struct GotMem {
    entries: Vec<GotMemEntry>,
    per_object_global_indices: Vec<Vec<Option<u32>>>,
}

impl GotMem {
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn len(&self) -> u32 {
        self.entries.len() as u32
    }
}

#[derive(Debug, Clone, Copy)]
struct GotFuncEntry {
    def_symbol_id: SymbolId,
    object_index: usize,
    symbol_offset: usize,
}

#[derive(Debug, Default)]
struct GotFunc {
    entries: Vec<GotFuncEntry>,
    per_object_global_indices: Vec<Vec<Option<u32>>>,
}

impl GotFunc {
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn len(&self) -> u32 {
        self.entries.len() as u32
    }
}

fn layout_file_id_to_index(
    layout_inputs: &[WasmObjectLayoutInput<'_>],
) -> HashMap<crate::input_data::FileId, usize> {
    layout_inputs
        .iter()
        .enumerate()
        .map(|(i, input)| (input.file_id, i))
        .collect()
}

/// Per-object map of linking symbol index to provisional GOT slot.
type GotSlotMap = Vec<Vec<Option<usize>>>;

struct LayoutRelocScan {
    got_mem: GotMem,
    got_func: GotFunc,
    per_object_got_mem_slots: GotSlotMap,
    per_object_got_func_slots: GotSlotMap,
    needs_memory_base: bool,
    needs_table_base: bool,
    needs_table: bool,
    table_index_symbol_indices: Vec<Vec<usize>>,
}

/// Scan relocations, absorb GOT.mem / GOT.func / weak-undef imports, and reserve indices.
fn setup_got_mem_and_indices<'data>(
    layout_inputs: &[WasmObjectLayoutInput<'data>],
    resolutions: &mut [ObjectImportResolutions],
    symbol_db: &SymbolDb<'data, Wasm>,
    file_id_to_index: &HashMap<crate::input_data::FileId, usize>,
    has_init_funcs: bool,
    wrap_entry: bool,
) -> Result<(
    LinkerDefinedIndices,
    LayoutRelocScan,
    SharedUnresolvedImports<'data>,
)> {
    timing_phase!("Setup Wasm GOT and indices");

    let mut scan = scan_layout_relocations(layout_inputs, symbol_db, file_id_to_index)?;

    let weak_undef_stubs = {
        timing_phase!("Absorb Wasm GOT and weak-undef imports");
        absorb_got_mem_imports(&scan.got_mem, layout_inputs, resolutions, symbol_db)?;
        let weak_undef_stubs = absorb_weak_undef_function_imports(layout_inputs, resolutions)?;
        absorb_got_func_imports(&scan.got_func, layout_inputs, resolutions, symbol_db)?;
        weak_undef_stubs
    };
    report_disallowed_unresolved_imports(layout_inputs, resolutions, symbol_db)?;
    let shared_imports = collect_shared_unresolved_imports(layout_inputs, resolutions)?;

    let indices = {
        timing_phase!("Reserve linker-defined Wasm indices");
        let indices = LinkerDefinedIndices::compute(
            layout_inputs,
            resolutions,
            shared_imports.function_count(),
            shared_imports.global_count(),
            weak_undef_stubs,
            &LinkerDefinedIndexRequest {
                has_init_funcs,
                export_symbols: requested_linker_export_symbols(symbol_db.args),
                has_memory: any_object_needs_linker_memory(layout_inputs),
                wrap_entry,
                got_mem_count: scan.got_mem.len(),
                got_func_count: scan.got_func.len(),
                needs_memory_base: scan.needs_memory_base,
                needs_table_base: scan.needs_table_base,
            },
        )?;

        if !scan.got_mem.is_empty() {
            let first_got = indices.got_mem_global_base.ok_or_else(|| {
                crate::error!("GOT.mem entries present but no global base reserved")
            })?;
            scan.got_mem.per_object_global_indices =
                assign_got_slot_global_indices(&scan.per_object_got_mem_slots, first_got)?;
            finalize_got_mem_import_resolutions(resolutions, first_got)?;
        }

        if !scan.got_func.is_empty() {
            let first_got = indices.got_func_global_base.ok_or_else(|| {
                crate::error!("GOT.func entries present but no global base reserved")
            })?;
            scan.got_func.per_object_global_indices =
                assign_got_slot_global_indices(&scan.per_object_got_func_slots, first_got)?;
            finalize_got_func_import_resolutions(resolutions, first_got)?;
        }

        indices
    };

    Ok((indices, scan, shared_imports))
}

/// True when every undefined Func symbol for that ordinal is weak.
fn pure_weak_function_import_flags(input: &WasmObjectLayoutInput<'_>) -> Vec<bool> {
    let n = input.function_imports.len();
    let mut saw_weak = vec![false; n];
    let mut saw_non_weak = vec![false; n];
    for sym in input.symbols {
        if sym.kind != WasmSymbolKind::Func || !sym.is_undefined() {
            continue;
        }
        let idx = sym.index as usize;
        if idx >= n {
            continue;
        }
        if sym.is_weak() {
            saw_weak[idx] = true;
        } else {
            saw_non_weak[idx] = true;
        }
    }
    saw_weak
        .into_iter()
        .zip(saw_non_weak)
        .map(|(weak, non_weak)| weak && !non_weak)
        .collect()
}

/// Absorb pure undefined-weak function imports into shared `unreachable` stubs.
fn absorb_weak_undef_function_imports<'data>(
    inputs: &[WasmObjectLayoutInput<'data>],
    resolutions: &mut [ObjectImportResolutions],
) -> Result<Vec<WeakUndefFunctionStub>> {
    let pure_weak_flags: Vec<Vec<bool>> =
        inputs.iter().map(pure_weak_function_import_flags).collect();

    let mut non_weak_names = HashSet::new();
    for (input, (res, flags)) in inputs
        .iter()
        .zip(resolutions.iter().zip(pure_weak_flags.iter()))
    {
        for (i, import) in input.function_imports.iter().enumerate() {
            if !input.live_function_imports.get(i).copied().unwrap_or(false) {
                continue;
            }
            if !matches!(
                res.function_resolutions.get(i),
                Some(ImportResolution::Unresolved)
            ) {
                continue;
            }
            if !flags.get(i).copied().unwrap_or(false) {
                non_weak_names.insert(import.name);
            }
        }
    }

    let mut stubs: Vec<WeakUndefFunctionStub> = Vec::new();
    let mut name_to_stub: HashMap<&str, u32> = HashMap::new();

    for (input, (res, flags)) in inputs
        .iter()
        .zip(resolutions.iter_mut().zip(pure_weak_flags.iter()))
    {
        for (i, import) in input.function_imports.iter().enumerate() {
            if !input.live_function_imports.get(i).copied().unwrap_or(false) {
                continue;
            }
            if !matches!(
                res.function_resolutions.get(i),
                Some(ImportResolution::Unresolved)
            ) {
                continue;
            }
            if !flags.get(i).copied().unwrap_or(false) {
                continue;
            }
            if non_weak_names.contains(import.name) {
                continue;
            }
            let ty = input
                .types
                .get(import.type_index as usize)
                .ok_or_else(|| {
                    crate::error!(
                        "Wasm type index {} out of range for weak import `{}`",
                        import.type_index,
                        import.name
                    )
                })?
                .clone();
            let stub_index = if let Some(&idx) = name_to_stub.get(import.name) {
                ensure!(
                    stubs[idx as usize].ty == ty,
                    "conflicting types for undefined weak function `{}`",
                    import.name
                );
                idx
            } else {
                let idx = u32::try_from(stubs.len()).context("too many Wasm weak-undef stubs")?;
                name_to_stub.insert(import.name, idx);
                stubs.push(WeakUndefFunctionStub {
                    ty,
                    function_index: 0,
                });
                idx
            };
            res.function_resolutions[i] = ImportResolution::WeakUndefStub { stub_index };
        }
    }

    Ok(stubs)
}

fn resolve_got_mem_def(
    def_id: SymbolId,
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    symbol_db: &SymbolDb<'_, Wasm>,
    file_id_to_index: &HashMap<crate::input_data::FileId, usize>,
) -> Result<GotMemDef> {
    let def_file_id = symbol_db.file_id_for_symbol(def_id);
    if let Some(&def_obj_idx) = file_id_to_index.get(&def_file_id) {
        let def_input = &layout_inputs[def_obj_idx];
        let def_off = def_id.to_offset(def_input.symbol_id_range);
        let def_ok = def_input
            .symbols
            .get(def_off)
            .is_some_and(|s| s.kind == WasmSymbolKind::Data);
        ensure!(
            def_ok,
            "GOT.mem for `{}` requires a data symbol in the link",
            symbol_db.symbol_name_for_display(def_id)
        );
        return Ok(GotMemDef::Object {
            object_index: def_obj_idx,
            symbol_offset: def_off,
        });
    }

    // Linker-defined data live on the prelude file, not in `layout_inputs`.
    if let Some(def_info) = symbol_db.prelude_symbol_def(def_id)
        && let crate::parsing::SymbolPlacement::PlatformSpecific(known) = def_info.placement
        && matches!(
            known,
            WasmLinkerSymbol::DataEnd
                | WasmLinkerSymbol::GlobalBase
                | WasmLinkerSymbol::HeapBase
                | WasmLinkerSymbol::HeapEnd
                | WasmLinkerSymbol::WasmFirstPageEnd
                | WasmLinkerSymbol::DsoHandle
        )
    {
        return Ok(GotMemDef::LinkerDefined(known));
    }

    bail!(
        "GOT.mem for `{}` requires a defined data symbol in the link",
        symbol_db.symbol_name_for_display(def_id)
    )
}

fn note_undefined_data_from_reloc(
    input: &WasmObjectLayoutInput<'_>,
    symbol_db: &SymbolDb<'_, Wasm>,
    reloc: &WasmRelocation,
    seen: &mut HashSet<(String, String)>,
    errors: &mut Vec<String>,
) -> Result {
    if symbol_db.args.allow_undefined || reloc.ty == RelocationType::TypeIndexLeb {
        return Ok(());
    }
    let Some(sym) = input.symbols.get(reloc.index as usize) else {
        return Ok(());
    };
    if sym.kind != WasmSymbolKind::Data
        || !sym.is_undefined()
        || sym.is_weak()
        || sym.is_explicit_name()
    {
        return Ok(());
    }
    let symbol_id = input.symbol_id_range.offset_to_id(reloc.index as usize);
    if !symbol_db.is_undefined(symbol_db.definition(symbol_id)) {
        return Ok(());
    }

    let file_display = symbol_db.file(input.file_id).to_string();
    let Some(name) = wasm_symbol_name_str(input.data, sym) else {
        bail!(
            "{file_display}: undefined symbol with no name (linking symbol index {})",
            reloc.index
        );
    };
    if seen.insert((file_display.clone(), name.to_owned())) {
        errors.push(format!("{file_display}: undefined symbol: {name}"));
    }
    Ok(())
}

fn scan_layout_relocations(
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    symbol_db: &SymbolDb<'_, Wasm>,
    file_id_to_index: &HashMap<crate::input_data::FileId, usize>,
) -> Result<LayoutRelocScan> {
    timing_phase!("Scan Wasm layout relocations");

    let mut mem_def_to_slot: HashMap<SymbolId, usize> = HashMap::new();
    let mut mem_entries = Vec::new();
    let mut per_object_got_mem_slots = vec![Vec::new(); layout_inputs.len()];
    let mut func_def_to_slot: HashMap<SymbolId, usize> = HashMap::new();
    let mut func_entries = Vec::new();
    let mut per_object_got_func_slots = vec![Vec::new(); layout_inputs.len()];
    let mut needs_memory_base = false;
    let mut needs_table_base = false;
    let mut needs_table = layout_inputs
        .iter()
        .any(|input| !input.table_imports.is_empty());
    let mut table_index_symbol_indices = vec![Vec::new(); layout_inputs.len()];
    let mut undefined_data_errors: Vec<String> = Vec::new();
    let mut seen_undefined_data: HashSet<(String, String)> = HashSet::new();

    for (obj_idx, input) in layout_inputs.iter().enumerate() {
        let mut got_mem_hits: Vec<(usize, usize)> = Vec::new();
        let mut got_func_hits: Vec<(usize, usize)> = Vec::new();
        let mut table_syms: Vec<usize> = Vec::new();
        let mut table_sym_seen = HashSet::new();

        for reloc in input
            .code_relocations
            .iter()
            .chain(input.data_relocations.iter())
        {
            note_undefined_data_from_reloc(
                input,
                symbol_db,
                reloc,
                &mut seen_undefined_data,
                &mut undefined_data_errors,
            )?;
            match reloc.ty {
                RelocationType::MemoryAddrRelSleb => {
                    needs_memory_base = true;
                }
                RelocationType::TableNumberLeb => {
                    needs_table = true;
                }
                RelocationType::TableIndexSleb
                | RelocationType::TableIndexI32
                | RelocationType::TableIndexRelSleb => {
                    if reloc.ty == RelocationType::TableIndexRelSleb {
                        needs_table_base = true;
                    }
                    needs_table = true;
                    let sym_idx = reloc.index as usize;
                    let Some(sym) = input.symbols.get(sym_idx) else {
                        bail!("table index relocation symbol {} out of range", reloc.index);
                    };
                    ensure!(
                        sym.kind == WasmSymbolKind::Func,
                        "R_WASM_TABLE_INDEX_* references non-function symbol"
                    );
                    if table_sym_seen.insert(sym_idx) {
                        table_syms.push(sym_idx);
                    }
                }
                RelocationType::GlobalIndexLeb | RelocationType::GlobalIndexI32 => {
                    let sym_idx = reloc.index as usize;
                    let Some(sym) = input.symbols.get(sym_idx) else {
                        bail!(
                            "GLOBAL_INDEX relocation symbol index {} out of range",
                            reloc.index
                        );
                    };
                    match sym.kind {
                        WasmSymbolKind::Data => {
                            let symbol_id = input.symbol_id_range.offset_to_id(sym_idx);
                            let def_id = symbol_db.definition(symbol_id);
                            let slot = if let Some(&slot) = mem_def_to_slot.get(&def_id) {
                                slot
                            } else {
                                let def = resolve_got_mem_def(
                                    def_id,
                                    layout_inputs,
                                    symbol_db,
                                    file_id_to_index,
                                )?;
                                let slot = mem_entries.len();
                                mem_def_to_slot.insert(def_id, slot);
                                mem_entries.push(GotMemEntry {
                                    def_symbol_id: def_id,
                                    def,
                                });
                                slot
                            };
                            got_mem_hits.push((sym_idx, slot));
                        }
                        WasmSymbolKind::Func => {
                            let symbol_id = input.symbol_id_range.offset_to_id(sym_idx);
                            let def_id = symbol_db.definition(symbol_id);
                            let slot = if let Some(&slot) = func_def_to_slot.get(&def_id) {
                                slot
                            } else {
                                let slot = func_entries.len();
                                func_def_to_slot.insert(def_id, slot);
                                func_entries.push(GotFuncEntry {
                                    def_symbol_id: def_id,
                                    object_index: obj_idx,
                                    symbol_offset: sym_idx,
                                });
                                slot
                            };
                            got_func_hits.push((sym_idx, slot));
                            // Ensure the function appears in the indirect table (null weak stubs
                            // are skipped later when assigning slots).
                            needs_table = true;
                            if table_sym_seen.insert(sym_idx) {
                                table_syms.push(sym_idx);
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        if !got_mem_hits.is_empty() {
            let mut obj_map = vec![None; input.symbols.len()];
            for (sym_idx, slot) in got_mem_hits {
                obj_map[sym_idx] = Some(slot);
            }
            per_object_got_mem_slots[obj_idx] = obj_map;
        }
        if !got_func_hits.is_empty() {
            let mut obj_map = vec![None; input.symbols.len()];
            for (sym_idx, slot) in got_func_hits {
                obj_map[sym_idx] = Some(slot);
            }
            per_object_got_func_slots[obj_idx] = obj_map;
        }
        table_index_symbol_indices[obj_idx] = table_syms;
    }

    if !undefined_data_errors.is_empty() {
        bail!("{}", undefined_data_errors.join("\n"));
    }

    Ok(LayoutRelocScan {
        got_mem: GotMem {
            entries: mem_entries,
            per_object_global_indices: Vec::new(),
        },
        got_func: GotFunc {
            entries: func_entries,
            per_object_global_indices: Vec::new(),
        },
        per_object_got_mem_slots,
        per_object_got_func_slots,
        needs_memory_base,
        needs_table_base,
        needs_table,
        table_index_symbol_indices,
    })
}

fn assign_got_slot_global_indices(
    per_object_slots: &GotSlotMap,
    first_global_index: u32,
) -> Result<Vec<Vec<Option<u32>>>> {
    let mut per_object = Vec::with_capacity(per_object_slots.len());
    for obj_map in per_object_slots {
        if obj_map.is_empty() {
            per_object.push(Vec::new());
            continue;
        }
        let mut out = Vec::with_capacity(obj_map.len());
        for slot in obj_map {
            out.push(match slot {
                Some(s) => Some(
                    first_global_index
                        .checked_add(*s as u32)
                        .ok_or_else(|| crate::error!("Wasm global index overflow"))?,
                ),
                None => None,
            });
        }
        per_object.push(out);
    }
    Ok(per_object)
}

fn apply_got_mem_to_index_maps(object_index_maps: &mut [WasmObjectIndexMap], got_mem: &GotMem) {
    if got_mem.is_empty() {
        return;
    }
    for (map, got) in object_index_maps
        .iter_mut()
        .zip(got_mem.per_object_global_indices.iter())
    {
        if !got.is_empty() {
            map.got_mem_globals = got.clone();
        }
    }
}

fn apply_got_func_to_index_maps(object_index_maps: &mut [WasmObjectIndexMap], got_func: &GotFunc) {
    if got_func.is_empty() {
        return;
    }
    for (map, got) in object_index_maps
        .iter_mut()
        .zip(got_func.per_object_global_indices.iter())
    {
        if !got.is_empty() {
            map.got_func_globals = got.clone();
        }
    }
}

/// Map defined weak functions to the winning definition's output index.
fn fill_function_symbol_redirects(
    object_index_maps: &mut [WasmObjectIndexMap],
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    symbol_db: &SymbolDb<'_, Wasm>,
    file_id_to_index: &HashMap<crate::input_data::FileId, usize>,
) {
    for (obj_idx, input) in layout_inputs.iter().enumerate() {
        let mut redirects = vec![None; input.symbols.len()];
        for (sym_off, sym) in input.symbols.iter().enumerate() {
            if sym.kind != WasmSymbolKind::Func || !sym.is_weak() || sym.is_undefined() {
                continue;
            }
            let local_id = input.symbol_id_range.offset_to_id(sym_off);
            let def_id = symbol_db.definition(local_id);
            if def_id == local_id {
                continue;
            }
            let Some(&def_obj_idx) = file_id_to_index.get(&symbol_db.file_id_for_symbol(def_id))
            else {
                continue;
            };
            let def_input = &layout_inputs[def_obj_idx];
            let def_sym = &def_input.symbols[def_input.symbol_id_range.id_to_offset(def_id)];
            if def_sym.kind != WasmSymbolKind::Func || def_sym.is_undefined() {
                continue;
            }
            let Some(&out) = object_index_maps[def_obj_idx]
                .function_indices
                .get(def_sym.index as usize)
            else {
                continue;
            };
            if out != WASM_DEAD_INDEX {
                redirects[sym_off] = Some(out);
            }
        }
        object_index_maps[obj_idx].function_symbol_redirects = redirects;
    }
}

fn got_func_debug_name(
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    entry: &GotFuncEntry,
    index: usize,
) -> String {
    let sym_name = layout_inputs.get(entry.object_index).and_then(|input| {
        input
            .symbols
            .get(entry.symbol_offset)
            .and_then(|sym| wasm_symbol_name_str(input.data, sym))
    });
    match sym_name {
        Some(name) => format!("GOT.func.internal.{name}"),
        None => format!("GOT.func.internal.{index}"),
    }
}

fn absorb_got_mem_imports(
    got_mem: &GotMem,
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    resolutions: &mut [ObjectImportResolutions],
    symbol_db: &SymbolDb<'_, Wasm>,
) -> Result {
    if got_mem.is_empty() {
        return Ok(());
    }

    let names: Vec<UnversionedSymbolName<'_>> = got_mem
        .entries
        .iter()
        .map(|entry| {
            symbol_db.symbol_name(entry.def_symbol_id).with_context(|| {
                format!(
                    "GOT.mem entry missing symbol name for `{}`",
                    symbol_db.symbol_name_for_display(entry.def_symbol_id)
                )
            })
        })
        .collect::<Result<_>>()?;

    let mut name_to_slot: HashMap<&[u8], usize> = HashMap::new();
    for (slot, name) in names.iter().enumerate() {
        name_to_slot.entry(name.bytes()).or_insert(slot);
    }

    for (input, res) in layout_inputs.iter().zip(resolutions.iter_mut()) {
        for (i, import) in input.global_imports.iter().enumerate() {
            if import.module != "GOT.mem" {
                continue;
            }
            if !matches!(res.global_resolutions[i], ImportResolution::Unresolved) {
                continue;
            }
            let Some(&slot) = name_to_slot.get(import.name.as_bytes()) else {
                continue;
            };
            res.global_resolutions[i] = ImportResolution::GotMemSlot(slot);
        }
    }
    Ok(())
}

fn finalize_got_mem_import_resolutions(
    resolutions: &mut [ObjectImportResolutions],
    first_got: u32,
) -> Result {
    for res in resolutions.iter_mut() {
        for resolution in &mut res.global_resolutions {
            if let ImportResolution::GotMemSlot(slot) = *resolution {
                let output_index = first_got
                    .checked_add(slot as u32)
                    .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
                *resolution = ImportResolution::DirectGlobal { output_index };
            }
        }
    }
    Ok(())
}

fn absorb_got_func_imports(
    got_func: &GotFunc,
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    resolutions: &mut [ObjectImportResolutions],
    symbol_db: &SymbolDb<'_, Wasm>,
) -> Result {
    if got_func.is_empty() {
        return Ok(());
    }

    let names: Vec<UnversionedSymbolName<'_>> = got_func
        .entries
        .iter()
        .map(|entry| {
            symbol_db.symbol_name(entry.def_symbol_id).with_context(|| {
                format!(
                    "GOT.func entry missing symbol name for `{}`",
                    symbol_db.symbol_name_for_display(entry.def_symbol_id)
                )
            })
        })
        .collect::<Result<_>>()?;

    let mut name_to_slot: HashMap<&[u8], usize> = HashMap::new();
    for (slot, name) in names.iter().enumerate() {
        name_to_slot.entry(name.bytes()).or_insert(slot);
    }

    for (input, res) in layout_inputs.iter().zip(resolutions.iter_mut()) {
        for (i, import) in input.global_imports.iter().enumerate() {
            if import.module != "GOT.func" {
                continue;
            }
            if !matches!(res.global_resolutions[i], ImportResolution::Unresolved) {
                continue;
            }
            let Some(&slot) = name_to_slot.get(import.name.as_bytes()) else {
                continue;
            };
            res.global_resolutions[i] = ImportResolution::GotFuncSlot(slot);
        }
    }
    Ok(())
}

fn finalize_got_func_import_resolutions(
    resolutions: &mut [ObjectImportResolutions],
    first_got: u32,
) -> Result {
    for res in resolutions.iter_mut() {
        for resolution in &mut res.global_resolutions {
            if let ImportResolution::GotFuncSlot(slot) = *resolution {
                let output_index = first_got
                    .checked_add(slot as u32)
                    .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
                *resolution = ImportResolution::DirectGlobal { output_index };
            }
        }
    }
    Ok(())
}

fn fill_got_mem_inits(
    layout: &mut WasmLayout<'_>,
    indices: &LinkerDefinedIndices,
    got_mem: &GotMem,
    data_start: u32,
    data_end: u32,
    stack_size: u32,
    heap_end: Option<u32>,
    stack_first: bool,
) -> Result {
    let Some(got_base) = indices.got_mem_global_base else {
        return Ok(());
    };
    let defined_slot = (got_base - indices.global_import_count) as usize;

    for (i, entry) in got_mem.entries.iter().enumerate() {
        let addr = match entry.def {
            GotMemDef::Object {
                object_index,
                symbol_offset,
            } => layout.object_index_maps[object_index]
                .data_addresses
                .get(symbol_offset)
                .copied()
                .ok_or_else(|| crate::error!("GOT.mem missing data address for definition"))?,
            GotMemDef::LinkerDefined(known) => known
                .data_address(data_start, data_end, stack_size, heap_end, stack_first)?
                .ok_or_else(|| {
                    crate::error!(
                        "GOT.mem linker-defined symbol `{}` has no data address",
                        std::str::from_utf8(known.name()).unwrap_or("?")
                    )
                })?,
        };
        let global_slot = defined_slot + i;
        let global = layout
            .globals
            .get_mut(global_slot)
            .ok_or_else(|| crate::error!("GOT.mem global slot {global_slot} out of range"))?;
        global.init_expr_body = Cow::Owned(encode_i32_const_u32(addr));
    }
    Ok(())
}

fn fill_exported_data_global_inits(
    layout: &mut WasmLayout<'_>,
    indices: &LinkerDefinedIndices,
    data_start: u32,
    data_end: u32,
    stack_size: u32,
    heap_end: Option<u32>,
    stack_first: bool,
) -> Result {
    for &(known, global_index) in &indices.data_address_globals {
        let addr = known
            .data_address(data_start, data_end, stack_size, heap_end, stack_first)?
            .ok_or_else(|| {
                crate::error!(
                    "linker-defined symbol `{}` has no address to export",
                    std::str::from_utf8(known.name()).unwrap_or("?")
                )
            })?;
        let defined_slot = (global_index - indices.global_import_count) as usize;
        let global = layout.globals.get_mut(defined_slot).ok_or_else(|| {
            crate::error!("exported data global slot {defined_slot} out of range")
        })?;
        global.init_expr_body = Cow::Owned(encode_i32_const_u32(addr));
    }
    Ok(())
}

/// Fill GOT.func globals with table indices. Requires the indirect function table first. Undefined
/// weak targets resolve through `function_indices` to unreachable stubs.
fn fill_got_func_inits(
    layout: &mut WasmLayout<'_>,
    indices: &LinkerDefinedIndices,
    got_func: &GotFunc,
    layout_inputs: &[WasmObjectLayoutInput<'_>],
) -> Result {
    let Some(got_base) = indices.got_func_global_base else {
        return Ok(());
    };
    let defined_slot = (got_base - indices.global_import_count) as usize;

    for (i, entry) in got_func.entries.iter().enumerate() {
        let input = layout_inputs.get(entry.object_index).ok_or_else(|| {
            crate::error!("GOT.func object index {} out of range", entry.object_index)
        })?;
        let sym = input.symbols.get(entry.symbol_offset).ok_or_else(|| {
            crate::error!(
                "GOT.func symbol offset {} out of range",
                entry.symbol_offset
            )
        })?;
        ensure!(
            sym.kind == WasmSymbolKind::Func,
            "GOT.func symbol is not a function"
        );
        let func_out = layout.object_index_maps[entry.object_index]
            .output_function_index(entry.symbol_offset, sym)?;
        let slot = layout
            .function_table_slots
            .get(func_out as usize)
            .copied()
            .unwrap_or(u32::MAX);
        ensure!(
            slot != u32::MAX,
            "GOT.func function {func_out} has no indirect table slot"
        );

        let global_slot = defined_slot + i;
        let global = layout
            .globals
            .get_mut(global_slot)
            .ok_or_else(|| crate::error!("GOT.func global slot {global_slot} out of range"))?;
        let table_i32 = i32::try_from(slot)
            .map_err(|_| crate::error!("GOT.func table index out of i32 range"))?;
        global.init_expr_body = Cow::Owned(encode_i32_const_body(table_i32));
    }
    Ok(())
}

/// True if inputs import or export `__wasm_call_ctors`.
fn call_ctors_used_in_objects(inputs: &[WasmObjectLayoutInput<'_>]) -> bool {
    inputs.iter().any(|input| {
        input.function_imports.iter().any(|imp| {
            matches!(
                WasmLinkerSymbol::parse(imp.name),
                Some(WasmLinkerSymbol::CallCtors)
            )
        }) || input.exports.iter().any(|exp| {
            matches!(
                WasmLinkerSymbol::parse(exp.name),
                Some(WasmLinkerSymbol::CallCtors)
            )
        })
    })
}

fn entry_is_defined_function(
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    symbol_db: &SymbolDb<'_, Wasm>,
) -> bool {
    let Some(entry_name) = symbol_db.entry_symbol_name() else {
        return false;
    };
    let Some(symbol_id) = symbol_db.get_unversioned(&UnversionedSymbolName::prehashed(entry_name))
    else {
        return false;
    };
    let def_id = symbol_db.definition(symbol_id);
    let def_file_id = symbol_db.file_id_for_symbol(def_id);
    let Some(input) = layout_inputs.iter().find(|i| i.file_id == def_file_id) else {
        return false;
    };
    let sym = &input.symbols[input.symbol_id_range.id_to_offset(def_id)];
    !sym.is_undefined() && sym.kind == WasmSymbolKind::Func
}

struct LinkerDefinedIndexRequest {
    has_init_funcs: bool,
    // Linker symbols named by `--export` / `--export-if-defined`.
    export_symbols: Vec<WasmLinkerSymbol>,
    has_memory: bool,
    wrap_entry: bool,
    got_mem_count: u32,
    got_func_count: u32,
    needs_memory_base: bool,
    needs_table_base: bool,
}

impl LinkerDefinedIndices {
    fn compute(
        layout_inputs: &[WasmObjectLayoutInput<'_>],
        import_resolutions: &[ObjectImportResolutions],
        function_import_count: u32,
        global_import_count: u32,
        mut weak_undef_stubs: Vec<WeakUndefFunctionStub>,
        request: &LinkerDefinedIndexRequest,
    ) -> Result<Self> {
        let mut needs_memory_base = request.needs_memory_base;
        let mut needs_table_base = request.needs_table_base;
        let mut needs_stack_pointer = false;
        let mut needs_tls_base = false;
        let mut needs_ctors = request.has_init_funcs;
        let mut export_data = Vec::new();
        let mut export_needs = LinkerImportAbsorption::default();
        for &sym in &request.export_symbols {
            if !sym.materialize_on_export() {
                continue;
            }
            if sym.exported_as_data_global(request.has_memory) {
                if !export_data.contains(&sym) {
                    export_data.push(sym);
                }
            } else {
                export_needs.need(sym);
            }
        }
        needs_ctors |= export_needs.needs_ctors;
        needs_table_base |= export_needs.needs_table_base;
        needs_stack_pointer |= export_needs.needs_stack_pointer;
        let export_memory_base = export_needs.needs_memory_base;

        for (input, resolutions) in layout_inputs.iter().zip(import_resolutions.iter()) {
            let absorption = LinkerImportAbsorption::from_resolutions(
                resolutions,
                &input.live_function_imports,
                &input.live_global_imports,
            );
            needs_ctors |= absorption.needs_ctors;
            needs_memory_base |= absorption.needs_memory_base;
            needs_table_base |= absorption.needs_table_base;
            needs_stack_pointer |= absorption.needs_stack_pointer;
            needs_tls_base |= absorption.needs_tls_base;
        }
        let memory_base_init = if needs_memory_base {
            LINKER_MEMORY_BASE
        } else {
            0
        };
        needs_memory_base |= export_memory_base;

        let mut next_global = global_import_count;
        // Defined-global slot before `__stack_pointer` (used for its init expression).
        let stack_pointer_defined_slot = needs_stack_pointer
            .then_some(u32::from(needs_memory_base) + u32::from(needs_table_base));
        let memory_base_global = needs_memory_base.then(|| {
            let idx = next_global;
            next_global += 1;
            idx
        });
        let table_base_global = needs_table_base.then(|| {
            let idx = next_global;
            next_global += 1;
            idx
        });
        let stack_pointer_global = needs_stack_pointer.then(|| {
            let idx = next_global;
            next_global += 1;
            idx
        });
        let tls_base_global = needs_tls_base.then(|| {
            let idx = next_global;
            next_global += 1;
            idx
        });
        let mut data_address_globals = Vec::with_capacity(export_data.len());
        for known in export_data {
            data_address_globals.push((known, next_global));
            next_global = next_global
                .checked_add(1)
                .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
        }
        let got_mem_global_base = if request.got_mem_count > 0 {
            let base = next_global;
            next_global = next_global
                .checked_add(request.got_mem_count)
                .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
            Some(base)
        } else {
            None
        };
        let got_func_global_base = if request.got_func_count > 0 {
            let base = next_global;
            next_global = next_global
                .checked_add(request.got_func_count)
                .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
            Some(base)
        } else {
            None
        };
        let num_defined_globals = next_global - global_import_count;

        let mut next_func = function_import_count;
        let call_ctors_func = needs_ctors.then(|| {
            let idx = next_func;
            next_func += 1;
            idx
        });
        let entry_wrapper_func = request.wrap_entry.then(|| {
            let idx = next_func;
            next_func += 1;
            idx
        });
        for stub in &mut weak_undef_stubs {
            stub.function_index = next_func;
            next_func = next_func
                .checked_add(1)
                .ok_or_else(|| crate::error!("Wasm function index overflow"))?;
        }
        let num_defined_functions = next_func - function_import_count;

        Ok(Self {
            memory_base_global,
            table_base_global,
            stack_pointer_global,
            tls_base_global,
            stack_pointer_defined_slot,
            call_ctors_func,
            entry_wrapper_func,
            weak_undef_stubs,
            num_defined_globals,
            num_defined_functions,
            global_import_count,
            got_mem_global_base,
            got_mem_count: request.got_mem_count,
            got_func_global_base,
            got_func_count: request.got_func_count,
            data_address_globals,
            requested_exports: request.export_symbols.clone(),
            memory_base_init,
        })
    }

    fn global_index(&self, known: WasmLinkerSymbol) -> Option<u32> {
        match known {
            WasmLinkerSymbol::MemoryBase => self.memory_base_global,
            WasmLinkerSymbol::TableBase => self.table_base_global,
            WasmLinkerSymbol::StackPointer => self.stack_pointer_global,
            WasmLinkerSymbol::TlsBase => self.tls_base_global,
            other => self
                .data_address_globals
                .iter()
                .find(|(sym, _)| *sym == other)
                .map(|(_, idx)| *idx),
        }
    }

    fn function_index(&self, known: WasmLinkerSymbol) -> Option<u32> {
        match known {
            WasmLinkerSymbol::CallCtors => self.call_ctors_func,
            _ => None,
        }
    }
}

fn encode_i32_const_body(value: i32) -> Vec<u8> {
    let mut bytes = vec![0x41];
    leb128::write::signed(&mut bytes, i64::from(value)).unwrap();
    bytes
}

/// Encode a linear-memory address as Wasm `i32.const`.
fn encode_i32_const_u32(value: u32) -> Vec<u8> {
    encode_i32_const_body(value as i32)
}

fn ensure_void_void_type(types: &mut Vec<wasmparser::FuncType>) -> u32 {
    ensure_func_type(types, &wasmparser::FuncType::new([], []))
}

fn ensure_func_type(types: &mut Vec<wasmparser::FuncType>, ty: &wasmparser::FuncType) -> u32 {
    if let Some((idx, _)) = types
        .iter()
        .enumerate()
        .find(|(_, existing)| *existing == ty)
    {
        return idx as u32;
    }
    types.push(ty.clone());
    (types.len() - 1) as u32
}

/// Collapse identical function types in the output type section and rewrite every type index that
/// refers into it.
fn deduplicate_output_types(layout: &mut WasmLayout<'_>) {
    if layout.output_types.is_empty() {
        return;
    }

    let mut unique_types = Vec::with_capacity(layout.output_types.len());
    let mut type_to_new_index: HashMap<FuncType, u32> = HashMap::new();
    let mut old_to_new = Vec::with_capacity(layout.output_types.len());

    for ty in std::mem::take(&mut layout.output_types) {
        if let Some(&new_index) = type_to_new_index.get(&ty) {
            old_to_new.push(new_index);
            continue;
        }
        let new_index = u32::try_from(unique_types.len()).expect("too many Wasm types");
        type_to_new_index.insert(ty.clone(), new_index);
        unique_types.push(ty);
        old_to_new.push(new_index);
    }

    layout.output_types = unique_types;

    if old_to_new
        .iter()
        .enumerate()
        .all(|(old, &new)| old as u32 == new)
    {
        // No remapping required.
        return;
    }

    let remap = |index: u32| -> u32 {
        old_to_new
            .get(index as usize)
            .copied()
            .expect("type index out of range during dedup")
    };

    for type_index in &mut layout.function_type_indices {
        *type_index = remap(*type_index);
    }

    for import in &mut layout.imports {
        if let OutputImportEntity::Function { type_index } = &mut import.entity {
            *type_index = remap(*type_index);
        }
    }

    for index_map in &mut layout.object_index_maps {
        for type_index in &mut index_map.type_indices {
            *type_index = remap(*type_index);
        }
    }
}

fn borrowed_linker_function_body(bytes: &'static [u8]) -> WasmFunctionBody<'static> {
    WasmFunctionBody {
        bytes: Cow::Borrowed(bytes),
        code_offset: 0,
        relocations: Vec::new(),
        object_index: 0,
    }
}

fn empty_linker_function_body() -> WasmFunctionBody<'static> {
    borrowed_linker_function_body(EMPTY_FUNCTION_BODY)
}

fn unreachable_linker_function_body() -> WasmFunctionBody<'static> {
    borrowed_linker_function_body(UNREACHABLE_FUNCTION_BODY)
}

fn owned_linker_function_body(bytes: Vec<u8>) -> WasmFunctionBody<'static> {
    WasmFunctionBody {
        bytes: Cow::Owned(bytes),
        code_offset: 0,
        relocations: Vec::new(),
        object_index: 0,
    }
}

/// Encode a body that calls each function in order.
///
/// `calls` is `(function_index, result_count)`. Result values are dropped so that
/// `__wasm_call_ctors` can stay `() -> ()` even when a constructor returns a value.
fn encode_call_sequence_body(calls: &[(u32, usize)]) -> Vec<u8> {
    let mut bytes = vec![0x00]; // 0 locals
    for &(func_index, result_count) in calls {
        bytes.push(0x10); // call
        leb128::write::unsigned(&mut bytes, u64::from(func_index))
            .expect("leb128 write to Vec cannot fail");
        bytes.extend(std::iter::repeat_n(0x1a, result_count)); // drop each result
    }
    bytes.push(0x0b); // end
    bytes
}

fn function_type_for_symbol<'a>(
    input: &'a WasmObjectLayoutInput<'_>,
    sym: &WasmSymbol,
) -> Result<&'a wasmparser::FuncType> {
    let sym_index = sym.index as usize;
    let n_imports = input.function_imports.len();
    let type_index = if sym_index < n_imports {
        input.function_imports[sym_index].type_index
    } else {
        let original = sym_index - n_imports;
        let dense = input
            .defined_function_live_ordinal
            .get(original)
            .copied()
            .unwrap_or(WASM_DEAD_INDEX);
        ensure!(
            dense != WASM_DEAD_INDEX,
            "Wasm init/reference to GC'd function index {}",
            sym.index
        );
        *input.module_functions.get(dense as usize).ok_or_else(|| {
            crate::error!(
                "Wasm function index {} out of range (dense {dense}, live len {})",
                sym.index,
                input.module_functions.len()
            )
        })?
    };
    input
        .types
        .get(type_index as usize)
        .ok_or_else(|| crate::error!("Wasm type index {type_index} out of range"))
}

/// From InitFuncs to `(output function index, result count)`, sorted by ascending priority.
fn collect_sorted_init_function_calls(
    inputs: &[WasmObjectLayoutInput<'_>],
    object_index_maps: &[WasmObjectIndexMap],
) -> Result<Vec<(u32, usize)>> {
    let mut items = Vec::new();
    for (obj_idx, input) in inputs.iter().enumerate() {
        let index_map = &object_index_maps[obj_idx];
        for init in input.init_funcs {
            let sym = &input.symbols[init.symbol_index as usize];
            ensure!(
                sym.kind == WasmSymbolKind::Func && !sym.is_undefined(),
                "Wasm init function must be a defined function symbol"
            );
            let ty = function_type_for_symbol(input, sym)?;
            ensure!(
                ty.params().is_empty(),
                "Wasm constructor must take no parameters (got {} param(s))",
                ty.params().len()
            );
            let output_index = index_map.output_function_index(init.symbol_index as usize, sym)?;
            items.push((init.priority, output_index, ty.results().len()));
        }
    }
    items.sort_by_key(|(priority, _, _)| *priority);
    Ok(items
        .into_iter()
        .map(|(_, index, n_results)| (index, n_results))
        .collect())
}

fn emit_reserved_linker_definitions(
    layout: &mut WasmLayout<'_>,
    indices: &LinkerDefinedIndices,
    call_ctors_body: Option<Vec<u8>>,
    entry_wrapper_body: Option<Vec<u8>>,
) {
    let mut linker_globals = Vec::with_capacity(indices.num_defined_globals as usize);
    if indices.memory_base_global.is_some() {
        linker_globals.push(OutputGlobal {
            ty: GlobalType {
                content_type: wasmparser::ValType::I32,
                mutable: false,
                shared: false,
            },
            init_expr_body: Cow::Owned(encode_i32_const_u32(indices.memory_base_init)),
        });
    }
    if indices.table_base_global.is_some() {
        linker_globals.push(OutputGlobal {
            ty: GlobalType {
                content_type: wasmparser::ValType::I32,
                mutable: false,
                shared: false,
            },
            init_expr_body: Cow::Borrowed(DEFAULT_TABLE_BASE_INIT_EXPR),
        });
    }
    if indices.stack_pointer_global.is_some() {
        linker_globals.push(OutputGlobal {
            ty: GlobalType {
                content_type: wasmparser::ValType::I32,
                mutable: true,
                shared: false,
            },
            init_expr_body: Cow::Borrowed(LINKER_MEMORY_BASE_INIT_EXPR),
        });
    }
    if indices.tls_base_global.is_some() {
        linker_globals.push(OutputGlobal {
            ty: GlobalType {
                content_type: wasmparser::ValType::I32,
                mutable: false,
                shared: false,
            },
            init_expr_body: Cow::Borrowed(ZERO_I32_INIT_EXPR),
        });
    }
    for _ in &indices.data_address_globals {
        linker_globals.push(OutputGlobal {
            ty: GlobalType {
                content_type: wasmparser::ValType::I32,
                mutable: false,
                shared: false,
            },
            init_expr_body: Cow::Borrowed(ZERO_I32_INIT_EXPR),
        });
    }
    // GOT.mem placeholders. wasm-ld emits static GOT.data.internal.* as immutable i32 for
    // freestanding executables.
    for _ in 0..indices.got_mem_count {
        linker_globals.push(OutputGlobal {
            ty: GlobalType {
                content_type: wasmparser::ValType::I32,
                mutable: false,
                shared: false,
            },
            init_expr_body: Cow::Borrowed(ZERO_I32_INIT_EXPR),
        });
    }
    // GOT.func placeholders. Filled with table indices after the indirect table is finalized.
    for _ in 0..indices.got_func_count {
        linker_globals.push(OutputGlobal {
            ty: GlobalType {
                content_type: wasmparser::ValType::I32,
                mutable: false,
                shared: false,
            },
            init_expr_body: Cow::Borrowed(ZERO_I32_INIT_EXPR),
        });
    }
    if !linker_globals.is_empty() {
        let mut rest = std::mem::take(&mut layout.globals);
        linker_globals.append(&mut rest);
        layout.globals = linker_globals;
    }

    if indices.num_defined_functions > 0 {
        let void_ty = ensure_void_void_type(&mut layout.output_types);
        let mut type_indices = Vec::with_capacity(indices.num_defined_functions as usize);
        let mut bodies = Vec::with_capacity(indices.num_defined_functions as usize);
        if indices.call_ctors_func.is_some() {
            type_indices.push(void_ty);
            bodies.push(match call_ctors_body {
                Some(bytes) => owned_linker_function_body(bytes),
                None => empty_linker_function_body(),
            });
        }
        if indices.entry_wrapper_func.is_some() {
            type_indices.push(void_ty);
            bodies.push(match entry_wrapper_body {
                Some(bytes) => owned_linker_function_body(bytes),
                None => empty_linker_function_body(),
            });
        }
        for stub in &indices.weak_undef_stubs {
            type_indices.push(ensure_func_type(&mut layout.output_types, &stub.ty));
            bodies.push(unreachable_linker_function_body());
        }
        type_indices.append(&mut layout.function_type_indices);

        let mut object_bodies = std::mem::take(&mut layout.function_bodies);
        bodies.append(&mut object_bodies);
        layout.function_type_indices = type_indices;
        layout.function_bodies = bodies;
    }
}

const fn wasm_page_size() -> u64 {
    crate::args::wasm::WASM_PAGE_SIZE
}

/// Size of the wasm32 linear-memory address space.
const WASM32_ADDRESS_SPACE_BYTES: u64 = 1u64 << 32;

/// Largest initial memory size.
const WASM32_MAX_INITIAL_MEMORY_BYTES: u64 = WASM32_ADDRESS_SPACE_BYTES - wasm_page_size();

fn ensure_memory_covers(
    layout: &mut WasmLayout<'_>,
    stack_size: u32,
    stack_first: bool,
    initial_memory: Option<u64>,
    max_memory: Option<u64>,
) -> Result<u64> {
    let page = wasm_page_size();
    let mut bytes_needed = u64::from(layout.data_end.max(layout.memory_base));
    if !stack_first && stack_size > 0 {
        bytes_needed = bytes_needed.max(u64::from(stack_high_after_data(
            layout.data_end,
            stack_size,
        )?));
    }

    if let Some(requested) = initial_memory {
        ensure!(
            requested.is_multiple_of(page),
            "initial memory must be aligned to the page size ({page} bytes)"
        );
        ensure!(
            requested <= WASM32_MAX_INITIAL_MEMORY_BYTES,
            "initial memory too large, cannot be greater than {WASM32_MAX_INITIAL_MEMORY_BYTES}"
        );
        ensure!(
            bytes_needed <= requested,
            "initial memory too small, {bytes_needed} bytes needed"
        );
        bytes_needed = requested;
    }

    if !layout.memories.is_empty() && bytes_needed > 0 {
        let pages_needed = bytes_needed.div_ceil(page).max(1);
        for memory in &mut layout.memories {
            memory.initial = memory.initial.max(pages_needed);
        }
    }

    let initial_pages = layout.memories.iter().map(|m| m.initial).max().unwrap_or(0);
    let initial_bytes = initial_pages.saturating_mul(page);

    if let Some(requested) = max_memory {
        ensure!(
            requested.is_multiple_of(page),
            "maximum memory must be aligned to the page size ({page} bytes)"
        );
        ensure!(
            requested <= WASM32_ADDRESS_SPACE_BYTES,
            "maximum memory too large, cannot be greater than {WASM32_ADDRESS_SPACE_BYTES}"
        );
        ensure!(
            initial_bytes <= requested,
            "maximum memory too small, {initial_bytes} bytes needed"
        );
        let max_pages = requested / page;
        for memory in &mut layout.memories {
            memory.maximum = Some(max_pages);
        }
    }

    Ok(initial_pages)
}

/// `__heap_end` = end of initial linear memory (`memory.initial * page_size`).
fn heap_end_from_initial_pages(initial_pages: u64) -> Result<u32> {
    u32::try_from(initial_pages.saturating_mul(wasm_page_size()))
        .map_err(|_| crate::error!("Wasm initial memory size overflow"))
}

/// Write stack-pointer init after static data layout.
fn fill_stack_pointer_init(
    layout: &mut WasmLayout<'_>,
    indices: &LinkerDefinedIndices,
    stack_size: u32,
    stack_first: bool,
) -> Result {
    let Some(defined_slot) = indices.stack_pointer_defined_slot else {
        return Ok(());
    };
    let sp = stack_pointer_init(layout.data_end, stack_size, stack_first)?;
    let global = layout
        .globals
        .get_mut(defined_slot as usize)
        .ok_or_else(|| crate::error!("Wasm stack pointer global missing"))?;
    ensure!(
        global.ty.mutable && global.ty.content_type == wasmparser::ValType::I32,
        "Wasm stack pointer global has unexpected type"
    );
    global.init_expr_body = Cow::Owned(encode_i32_const_u32(sp));
    Ok(())
}

fn linker_output_memory_type(inputs: &[WasmObjectLayoutInput<'_>]) -> MemoryType {
    let mut initial = 2u64;
    for input in inputs {
        for import in &input.memory_imports {
            initial = initial.max(import.initial);
        }
        for memory in &input.memories {
            initial = initial.max(memory.initial);
        }
    }
    MemoryType {
        memory64: false,
        shared: false,
        initial,
        maximum: None,
        page_size_log2: None,
    }
}

fn ensure_memory_export<'data>(exports: &mut Vec<OutputExport<'data>>, name: &'data str) {
    exports.retain(|export| !matches!(export.kind, wasmparser::ExternalKind::Memory));
    exports.push(OutputExport {
        name,
        kind: wasmparser::ExternalKind::Memory,
        index: 0,
    });
}

fn export_name_exists(exports: &[OutputExport<'_>], name: &str) -> bool {
    exports.iter().any(|export| export.name == name)
}

fn push_function_export<'data>(
    exports: &mut Vec<OutputExport<'data>>,
    name: &'data str,
    index: u32,
) {
    if export_name_exists(exports, name) {
        return;
    }
    exports.push(OutputExport {
        name,
        kind: wasmparser::ExternalKind::Func,
        index,
    });
}

fn push_global_export<'data>(exports: &mut Vec<OutputExport<'data>>, name: &'data str, index: u32) {
    if export_name_exists(exports, name) {
        return;
    }
    exports.push(OutputExport {
        name,
        kind: wasmparser::ExternalKind::Global,
        index,
    });
}

/// Resolved user entry function, if present among the linked objects.
struct ResolvedEntry<'data> {
    export_name: &'data str,
    function_index: u32,
}

/// Find the defined user entry function (default `_start`) without exporting it yet.
fn resolve_entry_function<'data>(
    layout_inputs: &[WasmObjectLayoutInput<'data>],
    object_index_maps: &[WasmObjectIndexMap],
    symbol_db: &SymbolDb<'data, Wasm>,
) -> Result<Option<ResolvedEntry<'data>>> {
    let Some(entry_name_bytes) = symbol_db.entry_symbol_name() else {
        return Ok(None);
    };
    let entry_display = String::from_utf8_lossy(entry_name_bytes);
    let not_defined =
        || crate::error!("entry symbol not defined (pass --no-entry to suppress): {entry_display}");

    let Some(symbol_id) =
        symbol_db.get_unversioned(&UnversionedSymbolName::prehashed(entry_name_bytes))
    else {
        return Err(not_defined());
    };
    let def_id = symbol_db.definition(symbol_id);
    let def_file_id = symbol_db.file_id_for_symbol(def_id);

    let Some(def_obj_idx) = layout_inputs
        .iter()
        .position(|input| input.file_id == def_file_id)
    else {
        return Err(not_defined());
    };
    let def_input = &layout_inputs[def_obj_idx];
    let def_sym = &def_input.symbols[def_input.symbol_id_range.id_to_offset(def_id)];
    if def_sym.is_undefined() || def_sym.kind != WasmSymbolKind::Func {
        return Err(not_defined());
    }

    let index_map = object_index_maps
        .get(def_obj_idx)
        .context("missing Wasm object index map for entry symbol definition")?;
    let function_index = remap_wasm_index(&index_map.function_indices, def_sym.index, "function")?;
    let export_name = core::str::from_utf8(symbol_db.symbol_name(def_id)?.bytes())
        .context("invalid UTF-8 in Wasm entry symbol name")?;
    Ok(Some(ResolvedEntry {
        export_name,
        function_index,
    }))
}

/// Export the command entry (default `_start`). With a wrapper, retarget any existing export.
fn ensure_entry_export<'data>(
    exports: &mut Vec<OutputExport<'data>>,
    entry: Option<&ResolvedEntry<'data>>,
    entry_wrapper_func: Option<u32>,
) {
    let Some(entry) = entry else {
        return;
    };
    let index = entry_wrapper_func.unwrap_or(entry.function_index);
    if let Some(existing) = exports
        .iter_mut()
        .find(|export| export.name == entry.export_name)
    {
        if entry_wrapper_func.is_some() {
            existing.kind = wasmparser::ExternalKind::Func;
            existing.index = index;
        }
        return;
    }
    exports.push(OutputExport {
        name: entry.export_name,
        kind: wasmparser::ExternalKind::Func,
        index,
    });
}

fn requested_linker_export_symbols(args: &WasmArgs) -> Vec<WasmLinkerSymbol> {
    let mut symbols = Vec::new();
    for name in args.force_export_symbol_names() {
        let Some(sym) = WasmLinkerSymbol::parse(name) else {
            continue;
        };
        if !symbols.contains(&sym) {
            symbols.push(sym);
        }
    }
    symbols
}

fn try_export_linker_defined(
    exports: &mut Vec<OutputExport<'_>>,
    known: WasmLinkerSymbol,
    indices: &LinkerDefinedIndices,
) -> bool {
    let name = <&str>::from(known);
    if let Some(index) = indices.function_index(known) {
        push_function_export(exports, name, index);
        return true;
    }
    if let Some(index) = indices.global_index(known) {
        push_global_export(exports, name, index);
        return true;
    }
    false
}

fn is_requested_linker_export(indices: &LinkerDefinedIndices, name: &str) -> bool {
    indices
        .requested_exports
        .iter()
        .any(|&sym| <&str>::from(sym) == name)
}

/// Export symbols requested via `--export` and `--export-if-defined`.
fn ensure_force_exports<'data>(
    exports: &mut Vec<OutputExport<'data>>,
    layout_inputs: &[WasmObjectLayoutInput<'data>],
    object_index_maps: &[WasmObjectIndexMap],
    symbol_db: &SymbolDb<'data, Wasm>,
    entry: Option<&ResolvedEntry<'data>>,
    indices: &LinkerDefinedIndices,
) -> Result<()> {
    for &known in &indices.requested_exports {
        if try_export_linker_defined(exports, known, indices) {
            continue;
        }
        let name = <&str>::from(known);
        if symbol_db
            .args
            .required_export_symbols
            .iter()
            .any(|required| required == name)
        {
            bail!("symbol exported via --export not found: {name}");
        }
    }

    for name in symbol_db.args.force_export_symbol_names() {
        if is_requested_linker_export(indices, name) {
            continue;
        }
        let required = symbol_db.args.required_export_symbols.contains(name);
        let Some(symbol_id) =
            symbol_db.get_unversioned(&UnversionedSymbolName::prehashed(name.as_bytes()))
        else {
            if required {
                bail!("symbol exported via --export not found: {name}");
            }
            continue;
        };
        let def_id = symbol_db.definition(symbol_id);
        let def_file_id = symbol_db.file_id_for_symbol(def_id);

        let Some(def_obj_idx) = layout_inputs
            .iter()
            .position(|input| input.file_id == def_file_id)
        else {
            if required {
                bail!("symbol exported via --export not found: {name}");
            }
            continue;
        };
        let def_input = &layout_inputs[def_obj_idx];
        let def_sym = &def_input.symbols[def_input.symbol_id_range.id_to_offset(def_id)];
        if def_sym.is_undefined() {
            if required {
                bail!("symbol exported via --export not found: {name}");
            }
            continue;
        }

        let index_map = object_index_maps
            .get(def_obj_idx)
            .context("missing Wasm object index map for --export symbol definition")?;
        let export_name = core::str::from_utf8(symbol_db.symbol_name(def_id)?.bytes())
            .context("invalid UTF-8 in Wasm --export symbol name")?;

        match def_sym.kind {
            WasmSymbolKind::Func => {
                let mut index =
                    remap_wasm_index(&index_map.function_indices, def_sym.index, "function")?;
                // If this is the entry and we wrap it, export the wrapper.
                if let (Some(entry), Some(wrapper)) = (entry, indices.entry_wrapper_func)
                    && export_name == entry.export_name
                {
                    index = wrapper;
                }
                push_function_export(exports, export_name, index);
            }
            WasmSymbolKind::Global => {
                let index = remap_wasm_index(&index_map.global_indices, def_sym.index, "global")?;
                push_global_export(exports, export_name, index);
            }
            _ => {
                bail!(
                    "Wasm --export of non-function/non-global symbols is not yet supported: {name}"
                );
            }
        }
    }
    Ok(())
}

fn build_output_module_layout<'data, 'files>(
    groups: &'files mut [layout::GroupState<'data, Wasm>],
    symbol_db: &crate::symbol_db::SymbolDb<'data, Wasm>,
) -> Result<WasmLayout<'data>>
where
    'data: 'files,
{
    timing_phase!("Build Wasm module layout");

    let layout_inputs = {
        timing_phase!("Collect Wasm object layout inputs");
        let handed_off_relocs: Vec<_> = groups
            .iter_mut()
            .flat_map(|group| group.files.iter_mut())
            .filter_map(|file| match file {
                layout::FileLayoutState::Object(object) => {
                    Some(object.format_specific.take_decoded_relocs())
                }
                _ => None,
            })
            .collect();

        let objects_and_states: Vec<_> = layout::objects_iter(groups)
            .map(|state| (&state.object, &state.format_specific))
            .collect();
        ensure!(
            objects_and_states.len() == handed_off_relocs.len(),
            "Wasm layout input count does not match taken reloc count"
        );
        objects_and_states
            .par_iter()
            .zip(handed_off_relocs.into_par_iter())
            .map(|((object, state), relocs)| {
                verbose_timing_phase!("Collect Wasm object layout input");
                WasmObjectLayoutInput::from_file(object, state, relocs)
            })
            .collect::<Result<Vec<_>>>()?
    };

    let file_id_to_index = layout_file_id_to_index(&layout_inputs);
    let mut import_resolutions =
        resolve_cross_object_imports(&layout_inputs, symbol_db, &file_id_to_index)?;
    let has_init_funcs = layout_inputs
        .iter()
        .any(|input| !input.init_funcs.is_empty());
    // Like wasm-ld, wrap only when InitFuncs exist and crt does not already call
    // `__wasm_call_ctors`.
    let wrap_entry = has_init_funcs
        && !call_ctors_used_in_objects(&layout_inputs)
        && entry_is_defined_function(&layout_inputs, symbol_db);

    let (indices, reloc_scan, shared_imports) = setup_got_mem_and_indices(
        &layout_inputs,
        &mut import_resolutions,
        symbol_db,
        &file_id_to_index,
        has_init_funcs,
        wrap_entry,
    )?;
    let got_mem = &reloc_scan.got_mem;
    let got_func = &reloc_scan.got_func;
    let index_bases = allocate_wasm_object_index_bases(&layout_inputs, &shared_imports, &indices)?;
    let mut object_layouts = {
        timing_phase!("Build per-object Wasm layouts");
        layout_inputs
            .par_iter()
            .zip(import_resolutions.par_iter())
            .enumerate()
            .map(|(obj_idx, (input, resolutions))| {
                verbose_timing_phase!("Build Wasm object output layout");
                input.build_object_output_layout(
                    obj_idx,
                    index_bases[obj_idx],
                    resolutions,
                    &index_bases,
                    &indices,
                    &shared_imports,
                )
            })
            .collect::<Result<Vec<_>>>()?
    };

    let linker_memory = any_object_needs_linker_memory(&layout_inputs);
    let stack_size = symbol_db.args.z_stack_size;
    let stack_first = symbol_db.args.stack_first;
    let initial_memory = symbol_db.args.initial_memory;
    let max_memory = symbol_db.args.max_memory;
    if stack_size > 0 {
        ensure_stack_size_aligned(stack_size)?;
    }
    let mut layout = WasmLayout {
        memory_base: if linker_memory || indices.memory_base_init == LINKER_MEMORY_BASE {
            LINKER_MEMORY_BASE
        } else {
            0
        },
        ..WasmLayout::default()
    };
    let data_start = if stack_first {
        stack_size
    } else {
        layout.memory_base
    };
    let mut memory_cursor = data_start;
    {
        timing_phase!("Merge Wasm object layouts");
        let n_objects = object_layouts.len();
        layout.object_index_maps.reserve(n_objects);
        layout.per_object_symbols.reserve(n_objects);
        layout.object_data_layouts.reserve(n_objects);

        {
            timing_phase!("Merge Wasm section lists");
            layout.imports = shared_imports.to_output_imports(&index_bases)?;
            for object_layout in &mut object_layouts {
                layout
                    .output_types
                    .extend(std::mem::take(&mut object_layout.types));
                layout
                    .function_type_indices
                    .extend(std::mem::take(&mut object_layout.function_type_indices));
                layout
                    .globals
                    .extend(std::mem::take(&mut object_layout.globals));
                layout
                    .exports
                    .extend(std::mem::take(&mut object_layout.exports));
                layout
                    .memories
                    .extend(std::mem::take(&mut object_layout.memories));
                layout
                    .unsupported_output
                    .extend(std::mem::take(&mut object_layout.unsupported_output));
            }
        }
        {
            timing_phase!("Merge Wasm function bodies");
            for (obj_idx, object_layout) in object_layouts.iter_mut().enumerate() {
                let mut bodies = std::mem::take(&mut object_layout.function_bodies);
                for body in &mut bodies {
                    body.object_index = obj_idx;
                }
                layout.function_bodies.extend(bodies);
            }
        }
        {
            timing_phase!("Merge Wasm index maps");
            for object_layout in &mut object_layouts {
                layout
                    .object_index_maps
                    .push(std::mem::take(&mut object_layout.index_map));
            }
            apply_got_mem_to_index_maps(&mut layout.object_index_maps, got_mem);
            apply_got_func_to_index_maps(&mut layout.object_index_maps, got_func);
            fill_function_symbol_redirects(
                &mut layout.object_index_maps,
                &layout_inputs,
                symbol_db,
                &file_id_to_index,
            );
        }
        {
            for input in &layout_inputs {
                layout.per_object_symbols.push(input.symbols);
            }
        }
        {
            timing_phase!("Layout Wasm data segments");
            for (obj_idx, input) in layout_inputs.iter().enumerate() {
                layout.object_data_layouts.push(layout_object_data(
                    input,
                    &layout.object_index_maps[obj_idx],
                    &mut memory_cursor,
                )?);
            }
        }
    }

    let init_function_calls =
        collect_sorted_init_function_calls(&layout_inputs, &layout.object_index_maps)?;
    let call_ctors_body = indices
        .call_ctors_func
        .map(|_| encode_call_sequence_body(&init_function_calls));

    let entry = resolve_entry_function(&layout_inputs, &layout.object_index_maps, symbol_db)?;
    let entry_wrapper_body = match (indices.entry_wrapper_func, indices.call_ctors_func, &entry) {
        (Some(_), Some(ctors), Some(entry)) => Some(encode_call_sequence_body(&[
            (ctors, 0),
            (entry.function_index, 0),
        ])),
        _ => None,
    };

    {
        timing_phase!("Wasm linker-defined symbols and data addresses");
        emit_reserved_linker_definitions(
            &mut layout,
            &indices,
            call_ctors_body,
            entry_wrapper_body,
        );
        deduplicate_output_types(&mut layout);

        if linker_memory && layout.memories.is_empty() {
            layout
                .memories
                .push(linker_output_memory_type(&layout_inputs));
        }
        if !layout.memories.is_empty() {
            ensure_memory_export(&mut layout.exports, symbol_db.args.memory_export_name());
        }
        layout.data_end = memory_cursor;
        let initial_pages = ensure_memory_covers(
            &mut layout,
            stack_size,
            stack_first,
            initial_memory,
            max_memory,
        )?;
        // wasm-ld only defines `__heap_end` when linear memory exists (end of `memory.initial`).
        let heap_end = if layout.memories.is_empty() {
            None
        } else {
            Some(heap_end_from_initial_pages(initial_pages)?)
        };
        let data_end = layout.data_end;
        compute_data_addresses(
            &mut layout.object_index_maps,
            &layout.per_object_symbols,
            &layout.object_data_layouts,
            &layout_inputs,
            symbol_db,
            &file_id_to_index,
            data_start,
            data_end,
            stack_size,
            heap_end,
            stack_first,
        )?;
        fill_got_mem_inits(
            &mut layout,
            &indices,
            got_mem,
            data_start,
            data_end,
            stack_size,
            heap_end,
            stack_first,
        )?;
        fill_exported_data_global_inits(
            &mut layout,
            &indices,
            data_start,
            data_end,
            stack_size,
            heap_end,
            stack_first,
        )?;
        fill_stack_pointer_init(&mut layout, &indices, stack_size, stack_first)?;
        ensure_entry_export(
            &mut layout.exports,
            entry.as_ref(),
            indices.entry_wrapper_func,
        );
        ensure_force_exports(
            &mut layout.exports,
            &layout_inputs,
            &layout.object_index_maps,
            symbol_db,
            entry.as_ref(),
            &indices,
        )?;
    }
    {
        timing_phase!("Finalize Wasm indirect function table");
        let weak_undef_funcs: HashSet<u32> = indices
            .weak_undef_stubs
            .iter()
            .map(|s| s.function_index)
            .collect();
        finalize_indirect_function_table(
            &mut layout,
            &layout_inputs,
            &reloc_scan.table_index_symbol_indices,
            reloc_scan.needs_table,
            &weak_undef_funcs,
        )?;
        // GOT.func inits need table slots assigned above.
        fill_got_func_inits(&mut layout, &indices, got_func, &layout_inputs)?;
    }
    layout.encode_metadata_sections(&layout_inputs, &indices, got_mem, got_func)?;
    Ok(layout)
}

/// Assign indirect-call table slots and synthesize `table` / `element` sections.
fn finalize_indirect_function_table(
    layout: &mut WasmLayout<'_>,
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    table_index_symbol_indices: &[Vec<usize>],
    needs_table: bool,
    weak_undef_funcs: &HashSet<u32>,
) -> Result {
    if !needs_table {
        return Ok(());
    }

    // Collect output function indices that must appear in the table.
    let mut needed: Vec<u32> = Vec::new();
    let mut seen = HashSet::new();

    for (obj_idx, (input, sym_indices)) in layout_inputs
        .iter()
        .zip(table_index_symbol_indices.iter())
        .enumerate()
    {
        let index_map = &layout.object_index_maps[obj_idx];
        for &sym_idx in sym_indices {
            let sym = input.symbols.get(sym_idx).ok_or_else(|| {
                crate::error!("table index relocation symbol {sym_idx} out of range")
            })?;
            ensure!(
                sym.kind == WasmSymbolKind::Func,
                "R_WASM_TABLE_INDEX_* references non-function symbol"
            );
            let func_out = index_map.output_function_index(sym_idx, sym)?;
            if weak_undef_funcs.contains(&func_out) {
                continue;
            }
            if seen.insert(func_out) {
                needed.push(func_out);
            }
        }
    }

    // Slot 0 is unused and first function at slot 1. This matches common clang/wasm-ld layout.
    let max_func = layout
        .object_index_maps
        .iter()
        .flat_map(|m| m.function_indices.iter().copied())
        .filter(|&idx| idx != WASM_DEAD_INDEX)
        .max()
        .unwrap_or(0);
    let mut slots_by_func = vec![u32::MAX; max_func as usize + 1];

    for &func_out in weak_undef_funcs {
        if (func_out as usize) < slots_by_func.len() {
            slots_by_func[func_out as usize] = 0;
        }
    }

    let mut element_functions = Vec::with_capacity(needed.len());
    for (i, &func_out) in needed.iter().enumerate() {
        let slot = i as u32 + 1;
        ensure!(
            (func_out as usize) < slots_by_func.len(),
            "output function index {func_out} out of range for table slots"
        );
        slots_by_func[func_out as usize] = slot;
        element_functions.push(func_out);
    }

    let mut initial = element_functions.len() as u64 + 1;
    for input in layout_inputs {
        for imp in &input.table_imports {
            initial = initial.max(imp.initial);
            ensure!(
                imp.element_type.is_func_ref(),
                "only funcref table imports are supported (got {:?})",
                imp.element_type
            );
        }
    }

    layout.tables = vec![wasmparser::TableType {
        element_type: wasmparser::RefType::FUNCREF,
        initial,
        maximum: Some(initial),
        shared: false,
        table64: false,
    }];
    layout.element_functions = element_functions;
    layout.function_table_slots = slots_by_func;

    Ok(())
}

fn is_memory_addr_relocation(ty: RelocationType) -> bool {
    matches!(
        ty,
        RelocationType::MemoryAddrLeb
            | RelocationType::MemoryAddrSleb
            | RelocationType::MemoryAddrI32
            | RelocationType::MemoryAddrRelSleb
    )
}

fn is_supported_data_relocation(ty: RelocationType) -> bool {
    is_memory_addr_relocation(ty)
        || matches!(
            ty,
            RelocationType::FunctionIndexI32
                | RelocationType::FunctionIndexLeb
                | RelocationType::TableIndexI32
                | RelocationType::TableIndexSleb
                | RelocationType::TableNumberLeb
                | RelocationType::GlobalIndexI32
                | RelocationType::GlobalIndexLeb
                | RelocationType::TypeIndexLeb
        )
}

fn data_relocations_are_supported(relocs: &[WasmRelocation]) -> bool {
    relocs
        .iter()
        .all(|reloc| is_supported_data_relocation(reloc.ty))
}

pub(crate) fn reloc_value_with_addend(base: u32, addend: i64) -> Result<u32> {
    let value = i64::from(base)
        .checked_add(addend)
        .ok_or_else(|| crate::error!("Wasm relocation value overflow"))?;
    u32::try_from(value).map_err(|_| crate::error!("Wasm relocation value out of range"))
}

/// Apply addend policy. Relative table/memory bases already include the addend.
pub(crate) fn finalize_reloc_value(reloc: &WasmRelocation, base: u32) -> Result<u32> {
    if matches!(
        reloc.ty,
        RelocationType::MemoryAddrRelSleb | RelocationType::TableIndexRelSleb
    ) {
        Ok(base)
    } else {
        reloc_value_with_addend(base, reloc.addend)
    }
}

fn data_segment_memory_offsets_by_original_index(
    object_data_layout: &[WasmDataSegmentLayout<'_>],
) -> Vec<Option<u32>> {
    let max_index = object_data_layout
        .iter()
        .map(|s| s.segment_index)
        .max()
        .map_or(0, |i| i as usize);
    let mut by_original = vec![None; max_index.saturating_add(1)];
    for segment in object_data_layout {
        let idx = segment.segment_index as usize;
        by_original[idx] = Some(segment.output_memory_offset);
    }
    by_original
}

/// Address of a defined data symbol, or `None` when its segment was GC'd.
fn try_data_symbol_memory_address(
    segment_memory_offsets: &[Option<u32>],
    sym: &WasmSymbol,
) -> Result<Option<u32>> {
    ensure!(
        sym.kind == WasmSymbolKind::Data,
        "memory address relocation references non-data symbol"
    );
    let Some(Some(segment_base)) = segment_memory_offsets.get(sym.index as usize) else {
        return Ok(None);
    };
    Ok(Some(segment_base.checked_add(sym.offset).ok_or_else(
        || crate::error!("Wasm data symbol address overflow"),
    )?))
}

/// Wasm symbols synthesized by the linker.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, strum::EnumIter, strum::EnumString, strum::IntoStaticStr,
)]
pub(crate) enum WasmLinkerSymbol {
    // Data
    #[strum(serialize = "__data_end")]
    DataEnd,
    #[strum(serialize = "__global_base")]
    GlobalBase,
    #[strum(serialize = "__heap_base")]
    HeapBase,
    #[strum(serialize = "__heap_end")]
    HeapEnd,
    #[strum(serialize = "__wasm_first_page_end")]
    WasmFirstPageEnd,
    #[strum(serialize = "__dso_handle")]
    DsoHandle,
    // Globals
    #[strum(serialize = "__memory_base")]
    MemoryBase,
    #[strum(serialize = "__table_base")]
    TableBase,
    #[strum(serialize = "__stack_pointer")]
    StackPointer,
    #[strum(serialize = "__tls_base")]
    TlsBase,
    // Functions
    #[strum(serialize = "__wasm_call_ctors")]
    CallCtors,
}

impl WasmLinkerSymbol {
    fn name(self) -> &'static [u8] {
        <&'static str>::from(self).as_bytes()
    }

    fn parse(name: &str) -> Option<Self> {
        name.parse().ok()
    }

    fn materialize_on_export(self) -> bool {
        // `--export` materializes every linker symbol except `__tls_base`.
        !matches!(self, Self::TlsBase)
    }

    fn exported_as_data_global(self, has_memory: bool) -> bool {
        match self {
            Self::DataEnd
            | Self::GlobalBase
            | Self::HeapBase
            | Self::WasmFirstPageEnd
            | Self::DsoHandle => true,
            Self::HeapEnd => has_memory,
            _ => false,
        }
    }

    fn matches_import_kind(self, kind: WasmSymbolKind) -> bool {
        match self {
            Self::CallCtors => kind == WasmSymbolKind::Func,
            Self::MemoryBase | Self::TableBase | Self::StackPointer | Self::TlsBase => {
                kind == WasmSymbolKind::Global
            }
            Self::DataEnd
            | Self::GlobalBase
            | Self::HeapBase
            | Self::HeapEnd
            | Self::WasmFirstPageEnd
            | Self::DsoHandle => false,
        }
    }

    /// Data-symbol address after memory layout. `None` for non-data variants or absent memory.
    fn data_address(
        self,
        data_start: u32,
        data_end: u32,
        stack_size: u32,
        heap_end: Option<u32>,
        stack_first: bool,
    ) -> Result<Option<u32>> {
        Ok(match self {
            Self::DataEnd => Some(data_end),
            Self::GlobalBase | Self::DsoHandle => Some(data_start),
            Self::HeapBase => Some(heap_base_address(data_end, stack_size, stack_first)?),
            Self::WasmFirstPageEnd => Some(u32::try_from(wasm_page_size())?),
            Self::HeapEnd => heap_end,
            Self::MemoryBase
            | Self::TableBase
            | Self::StackPointer
            | Self::TlsBase
            | Self::CallCtors => None,
        })
    }
}

fn compute_data_addresses(
    object_index_maps: &mut [WasmObjectIndexMap],
    per_object_symbols: &[&[WasmSymbol]],
    object_data_layouts: &[Vec<WasmDataSegmentLayout<'_>>],
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    symbol_db: &SymbolDb<'_, Wasm>,
    file_id_to_index: &HashMap<crate::input_data::FileId, usize>,
    data_start: u32,
    data_end: u32,
    stack_size: u32,
    heap_end: Option<u32>,
    stack_first: bool,
) -> Result {
    let segment_offsets_by_object: Vec<Vec<Option<u32>>> = object_data_layouts
        .iter()
        .map(|layout| data_segment_memory_offsets_by_original_index(layout))
        .collect();

    for (obj_idx, (index_map, symbols)) in object_index_maps
        .iter_mut()
        .zip(per_object_symbols.iter())
        .enumerate()
    {
        let mut data_addresses = vec![0u32; symbols.len()];
        for (sym_idx, sym) in symbols.iter().enumerate() {
            if sym.kind != WasmSymbolKind::Data {
                continue;
            }
            let symbol_id = layout_inputs[obj_idx].symbol_id_range.offset_to_id(sym_idx);

            if !sym.is_undefined() {
                if let Some(addr) =
                    try_data_symbol_memory_address(&segment_offsets_by_object[obj_idx], sym)?
                {
                    data_addresses[sym_idx] = addr;
                }
                continue;
            }

            let def_id = symbol_db.definition(symbol_id);
            let def_file_id = symbol_db.file_id_for_symbol(def_id);

            if let Some(&def_obj_idx) = file_id_to_index.get(&def_file_id) {
                let def_input = &layout_inputs[def_obj_idx];
                let def_sym =
                    per_object_symbols[def_obj_idx][def_id.to_offset(def_input.symbol_id_range)];
                if !def_sym.is_undefined() {
                    if let Some(addr) = try_data_symbol_memory_address(
                        &segment_offsets_by_object[def_obj_idx],
                        &def_sym,
                    )? {
                        data_addresses[sym_idx] = addr;
                    }
                    continue;
                }
            }

            if let Some(def_info) = symbol_db.prelude_symbol_def(def_id)
                && let crate::parsing::SymbolPlacement::PlatformSpecific(known) =
                    &def_info.placement
                && let Some(address) =
                    known.data_address(data_start, data_end, stack_size, heap_end, stack_first)?
            {
                data_addresses[sym_idx] = address;
            }
        }
        index_map.data_addresses = data_addresses;
    }

    Ok(())
}

fn allocate_wasm_object_index_bases(
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    shared_imports: &SharedUnresolvedImports<'_>,
    indices: &LinkerDefinedIndices,
) -> Result<Vec<WasmObjectIndexBases>> {
    timing_phase!("Allocate Wasm object index bases");

    let mut index_bases = Vec::with_capacity(layout_inputs.len());
    let mut next_type_index = 0u32;
    let function_import_count = shared_imports.function_count();
    let global_import_count = shared_imports.global_count();

    for input in layout_inputs {
        index_bases.push(WasmObjectIndexBases {
            type_index_base: next_type_index,
            defined_function_base: 0,
            defined_global_base: 0,
        });
        next_type_index = next_type_index
            .checked_add(u32::try_from(input.types.len()).context("too many Wasm types")?)
            .ok_or_else(|| crate::error!("Wasm type index overflow"))?;
    }

    let mut next_defined_function_index = function_import_count
        .checked_add(indices.num_defined_functions)
        .ok_or_else(|| crate::error!("Wasm function index overflow"))?;
    let mut next_defined_global_index = global_import_count
        .checked_add(indices.num_defined_globals)
        .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
    for (input, index_base) in layout_inputs.iter().zip(index_bases.iter_mut()) {
        index_base.defined_function_base = next_defined_function_index;
        index_base.defined_global_base = next_defined_global_index;
        next_defined_function_index = next_defined_function_index
            .checked_add(
                u32::try_from(input.module_functions.len()).context("too many Wasm functions")?,
            )
            .ok_or_else(|| crate::error!("Wasm function index overflow"))?;
        next_defined_global_index = next_defined_global_index
            .checked_add(u32::try_from(input.globals.len()).context("too many Wasm globals")?)
            .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
    }

    Ok(index_bases)
}

/// Classify code relocations into per-body groups with body-local offsets.
fn classify_code_relocations<'data>(
    bodies: &mut [WasmFunctionBody<'data>],
    relocs: &[WasmRelocation],
) {
    if relocs.is_empty() {
        return;
    }

    let mut reloc_iter = relocs.iter().peekable();
    for body in bodies.iter_mut() {
        let body_start = body.code_offset;
        let body_end = body_start + body.bytes.len() as u32;

        while let Some(reloc) = reloc_iter.peek().copied() {
            if reloc.offset >= body_end {
                break;
            }
            reloc_iter.next();
            if reloc.offset >= body_start {
                body.relocations.push(WasmRelocation {
                    offset: reloc.offset - body_start,
                    ..*reloc
                });
            }
        }
    }
}

fn remap_wasm_index(indices: &[u32], index: u32, kind: &str) -> Result<u32> {
    let mapped = indices.get(index as usize).copied().ok_or_else(|| {
        crate::error!(
            "Wasm {kind} index {index} out of range (map len {})",
            indices.len()
        )
    })?;
    ensure!(
        mapped != WASM_DEAD_INDEX,
        "Wasm {kind} index {index} was removed by GC"
    );
    Ok(mapped)
}

impl platform::Platform for Wasm {
    const NUM_SINGLE_PART_SECTIONS: u32 = SinglePartSectionId::Count as u32;
    const NUM_BUILT_IN_REGULAR_SECTIONS: usize = 0;

    const VERIFY_IGNORE_SECTION_IDS: &'static [OutputSectionId] =
        &[crate::output_section_id::FILE_HEADER];

    type File<'data> = File<'data>;
    type FileFlags = u32;
    type SymtabEntry = WasmSymbol;
    type PlatformSpecificSymbol = WasmLinkerSymbol;
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
    type RelocationInfo = RelocationType;
    type NonAddressableIndexes = NonAddressableIndexes;
    type NonAddressableCounts = ();
    type EpilogueLayoutExt = ();
    type GroupLayoutExt = ();
    type CommonGroupStateExt = ();
    type StubLibraryLayoutStateExt = ();
    type StubLibraryLayoutExt = ();
    type ArchIdentifier = ();
    type Args = WasmArgs;
    type ResolutionExt = ();
    type SymtabShndxEntry = ();
    type SymbolVersionIndex = ();
    type FinaliseSizesExt<'data> = WasmLayout<'data>;
    type LayoutExt<'data> = WasmLayout<'data>;
    type GdbIndexScanResult<'data> = ();
    type SectionIterator<'a> = core::slice::Iter<'a, SectionHeader>;
    type DynamicTagValues<'data> = DynamicTagValues<'data>;
    type RelocationList<'data> = RelocationList<'data>;
    type DynamicLayoutStateExt<'data> = ();
    type DynamicLayoutExt<'data> = ();
    type LayoutResourcesExt<'data> = ();
    type PreludeLayoutStateExt = ();
    type PreludeLayoutExt = ();
    type ObjectLayoutStateExt<'data> = WasmObjectLayout<'data>;
    type RawSymbolName<'data> = RawSymbolName<'data>;
    type VersionNames<'data> = ();
    type VerneedTable<'data> = VerneedTable<'data>;
    type ResolvedObjectExt<'data> = WasmObjectLayout<'data>;
    type SectionIdentityExt = ();
    type GcUnit = WasmGcUnit;

    fn write_output_file<'data, A: platform::Arch<Platform = Self>, F: FileSystem>(
        output: &crate::file_writer::Output<F>,
        layout: &crate::layout::Layout<'data, Self>,
    ) -> crate::error::Result {
        output.write(layout, crate::wasm_writer::write::<A>)
    }

    fn section_attributes(_header: &Self::SectionHeader) -> Self::SectionAttributes {
        SectionAttributes::default()
    }

    fn apply_force_keep_sections(
        _keep_sections: &mut crate::output_section_map::OutputSectionMap<bool>,
        _args: &Self::Args,
    ) {
        // No `-u` / `--require-defined` analogue is wired through for Wasm yet.
    }

    fn is_zero_sized_section_content(
        _section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        false
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
        0
    }

    fn post_gc<'data>(
        groups: &mut [crate::layout::GroupState<Self>],
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) -> crate::error::Result {
        for group in groups {
            for file in &mut group.files {
                if let crate::layout::FileLayoutState::Object(object) = file {
                    object.format_specific.compute_live_ordinals();
                }
            }
        }
        Ok(())
    }

    fn activate_dynamic<'data>(
        _state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
        // Dynamic Wasm objects are not emitted by this backend.
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
    ) -> crate::error::Result {
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
        _state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
        _resolutions_out: &mut crate::layout::ResolutionWriter<Self>,
    ) -> crate::error::Result<Option<Self::DynamicLayoutExt<'data>>> {
        Ok(None)
    }

    fn take_dynsym_index(
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _section_layouts: &crate::output_section_map::OutputSectionMap<
            crate::layout::OutputRecordLayout,
        >,
    ) -> crate::error::Result<u32> {
        crate::bail!("Wasm dynamic symbol table is not emitted")
    }

    fn compute_object_addresses<'data>(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
    }

    fn layout_resources_ext<'data>(
        _groups: &[crate::grouping::Group<'data, Self>],
    ) -> Self::LayoutResourcesExt<'data> {
    }

    fn gc_unit_for_symbol<'data>(
        object: &Self::File<'data>,
        symbol: &Self::SymtabEntry,
        _symbol_index: object::SymbolIndex,
    ) -> crate::error::Result<Option<Self::GcUnit>> {
        Ok(wasm_gc_unit_for_symbol(object, symbol))
    }

    fn activate_object_gc<'data, 'scope, A: platform::Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        queue: &mut crate::layout::LocalWorkQueue<Self>,
        scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        object.format_specific.ensure_gc_states(object.object);
        if resources.symbol_db.args.should_gc_sections() {
            enqueue_wasm_gc_roots::<A>(object, resources, queue, scope)?;
        } else {
            mark_all_wasm_units_live_and_scan_relocs::<A>(object, resources, queue, scope)?;
        }
        Ok(())
    }

    fn load_gc_unit<'data, 'scope, A: platform::Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        queue: &mut crate::layout::LocalWorkQueue<Self>,
        unit: Self::GcUnit,
        scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        if !object.format_specific.mark_live(unit) {
            return Ok(());
        }

        match unit {
            WasmGcUnit::DefinedFunction(_) | WasmGcUnit::DataSegment(_) => {
                object
                    .format_specific
                    .ensure_relocs_decoded(object.object)?;
                walk_wasm_gc_unit_edges::<A>(object, unit, resources, queue, scope)?;
            }
            WasmGcUnit::FunctionImport(_) | WasmGcUnit::GlobalImport(_) => {
                note_wasm_import_unit_definition::<A>(object, unit, resources, queue, scope);
            }
            WasmGcUnit::DefinedGlobal(_) => {}
        }
        Ok(())
    }

    fn load_object_section_relocations<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _state: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue<Self>,
        _resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _section: crate::layout::Section,
        _section_index: object::SectionIndex,
        _scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn create_dynamic_symbol_definition<'data>(
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _symbol_id: crate::symbol_db::SymbolId,
    ) -> crate::error::Result<crate::layout::DynamicSymbolDefinition<'data, Self>> {
        crate::bail!("Wasm dynamic symbol definitions are not emitted")
    }

    fn update_segment_keep_list(
        _program_segments: &crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
        _keep_segments: &mut [bool],
        _args: &Self::Args,
    ) {
    }

    fn program_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        PROGRAM_SEGMENT_DEFS
    }

    fn unconditional_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }

    fn program_segment_should_include_section(
        segment_def: Self::ProgramSegmentDef,
        _section_info: &crate::output_section_id::SectionOutputInfo<Self>,
        section_id: crate::output_section_id::OutputSectionId,
        _rosegment: bool,
    ) -> bool {
        use crate::wasm::output_section_id as osid;

        let section_segment_type = match section_id {
            crate::output_section_id::FILE_HEADER => SegmentType::Header,
            osid::WASM_TYPE
            | osid::WASM_IMPORT
            | osid::WASM_FUNCTION
            | osid::WASM_TABLE
            | osid::WASM_MEMORY
            | osid::WASM_GLOBAL
            | osid::WASM_EXPORT
            | osid::WASM_START
            | osid::WASM_ELEMENT
            | osid::WASM_DATA_COUNT
            | osid::WASM_CODE
            | osid::WASM_DATA
            | osid::WASM_NAME
            | osid::WASM_TARGET_FEATURES => SegmentType::Module,
            _ => SegmentType::Unused,
        };

        segment_def.segment_type == section_segment_type
    }

    fn create_linker_defined_symbols(
        symbols: &mut crate::parsing::InternalSymbolsBuilder<Self>,
        _output_kind: crate::output_kind::OutputKind,
        _args: &Self::Args,
    ) {
        // Reserve SymbolId 0 as the linker’s undefined sentinel (Wasm objects have no null symbol
        // entry).
        symbols
            .add_symbol(crate::parsing::InternalSymDefInfo::new(
                crate::parsing::SymbolPlacement::Undefined,
                b"",
            ))
            .hide();

        for sym in <WasmLinkerSymbol as strum::IntoEnumIterator>::iter() {
            symbols.platform_specific(sym.name(), sym).hide();
        }
    }

    fn built_in_section_infos<'data>()
    -> Vec<crate::output_section_id::SectionOutputInfo<'data, Self>> {
        SECTION_DEFINITIONS
            .iter()
            .map(|d| crate::output_section_id::SectionOutputInfo {
                section_attributes: SectionAttributes::default(),
                kind: d.kind,
                min_alignment: crate::alignment::MIN,
                location_info: None,
                secondary_order: None,
                region_name: None,
                fill: None,
                phdrs: Vec::new(),
            })
            .collect()
    }

    fn new_resolved_object_ext<'data>(
        symbol_id_range: crate::symbol_db::SymbolIdRange,
        file_id: crate::input_data::FileId,
    ) -> Self::ResolvedObjectExt<'data> {
        WasmObjectLayout {
            symbol_id_range,
            file_id,
            gc_states_ready: false,
            gc_defined_functions: Vec::new(),
            gc_defined_globals: Vec::new(),
            gc_data_segments: Vec::new(),
            gc_function_imports: Vec::new(),
            gc_global_imports: Vec::new(),
            func_import_symbol_offsets: Vec::new(),
            global_import_symbol_offsets: Vec::new(),
            relocs_ready: false,
            code_relocations: Vec::new(),
            data_relocations: Vec::new(),
            function_body_spans: Vec::new(),
            data_segment_spans: Vec::new(),
            defined_function_live_ordinal: Vec::new(),
            defined_global_live_ordinal: Vec::new(),
            _phantom: std::marker::PhantomData,
        }
    }

    fn new_object_layout_state_ext<'data>(
        input: Self::ResolvedObjectExt<'data>,
    ) -> Self::ObjectLayoutStateExt<'data> {
        input
    }

    fn create_finalise_sizes_ext<'data, 'states, 'files, A: platform::Arch<Platform = Self>>(
        _args: &Self::Args,
        groups: &'files mut [layout::GroupState<'data, Self>],
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) -> crate::error::Result<Self::FinaliseSizesExt<'data>>
    where
        'data: 'files,
        'data: 'states,
    {
        build_output_module_layout(groups, symbol_db)
    }

    fn create_layout_ext<'data>(
        finalise_sizes_ext: Self::FinaliseSizesExt<'data>,
        _resolutions: &layout::SymbolResolutions<Self>,
    ) -> Result<Self::LayoutExt<'data>> {
        Ok(finalise_sizes_ext)
    }

    fn load_exception_frame_data<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _eh_frame_section_index: object::SectionIndex,
        _resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _queue: &mut crate::layout::LocalWorkQueue<Self>,
        _scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        // Wasm doesn't have ELF-style `.eh_frame`.
        Ok(())
    }

    fn non_empty_section_loaded<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue<Self>,
        _unloaded: crate::resolution::UnloadedSection,
        _resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        _scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn new_epilogue_layout<'data>(
        _args: &Self::Args,
        _output_kind: crate::output_kind::OutputKind,
        _dynamic_symbol_definitions: &mut [crate::layout::DynamicSymbolDefinition<'data, Self>],
        _group_states: &[layout::GroupState<'data, Self>],
    ) -> Self::EpilogueLayoutExt {
    }

    fn apply_non_addressable_indexes_epilogue(
        _counts: &mut Self::NonAddressableCounts,
        _state: &mut Self::EpilogueLayoutExt,
    ) {
        // No-op: Wasm has no version table.
    }

    fn apply_non_addressable_indexes<'data, 'groups>(
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _counts: &Self::NonAddressableCounts,
        _mem_sizes_iter: impl Iterator<
            Item = &'groups mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        >,
    ) {
        // Wasm has no non-addressable side tables.
    }

    fn finalise_sizes_epilogue<'data>(
        _state: &mut Self::EpilogueLayoutExt,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _dynamic_symbol_definitions: &[crate::layout::DynamicSymbolDefinition<'data, Self>],
        properties: &Self::LayoutExt<'data>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
        properties.encoded_sections.add_sizes_to(mem_sizes);
        properties.add_code_section_size(mem_sizes);
        properties.add_data_section_size(mem_sizes);
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
        common_state: &Self::LayoutExt<'data>,
        _dynsym_start_index: u32,
        _dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
    ) -> crate::error::Result {
        common_state.encoded_sections.add_sizes_to(memory_offsets);
        common_state.add_code_section_size(memory_offsets);
        common_state.add_data_section_size(memory_offsets);
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
        // No dynamic linking yet, so nothing can be interposed.
        true
    }

    fn allocate_header_sizes<'data>(
        _prelude: &mut crate::layout::PreludeLayoutState<'data, Self>,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _header_info: &crate::layout::HeaderInfo,
        _program_segments: &crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
        _output_sections: &crate::output_section_id::OutputSections<Self>,
        _resources: &layout::FinaliseSizesResources<'data, '_, Self>,
        _args: &Self::Args,
    ) {
        sizes.increment(crate::part_id::FILE_HEADER, (WASM_MAGIC.len() + 4) as u64);
    }

    fn finalise_sizes_for_symbol<'data>(
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _symbol_id: crate::symbol_db::SymbolId,
        _flags: crate::value_flags::ValueFlags,
    ) -> crate::error::Result {
        Ok(())
    }

    fn allocate_resolution(
        _flags: crate::value_flags::ValueFlags,
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _output_kind: crate::output_kind::OutputKind,
        _args: &Self::Args,
    ) {
    }

    fn allocate_object_symtab_space<'data>(
        _state: &crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _per_symbol_flags: &crate::value_flags::AtomicPerSymbolFlags,
    ) -> crate::error::Result {
        Ok(())
    }

    fn allocate_internal_symbol(
        _symbol_id: crate::symbol_db::SymbolId,
        _def_info: &crate::parsing::InternalSymDefInfo<Self>,
        _sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn allocate_prelude(
        _common: &mut crate::layout::CommonGroupState<Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) {
    }

    fn finalise_prelude_layout<'data>(
        _prelude: &crate::layout::PreludeLayoutState<Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
    ) -> crate::error::Result<Self::PreludeLayoutExt> {
        Ok(())
    }

    fn create_resolution(
        flags: crate::value_flags::ValueFlags,
        raw_value: u64,
        dynamic_symbol_index: Option<std::num::NonZeroU32>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _args: &<Self as crate::platform::Platform>::Args,
        _output_kind: crate::OutputKind,
    ) -> crate::layout::Resolution<Self> {
        crate::layout::Resolution {
            raw_value,
            dynamic_symbol_index,
            flags,
            format_specific: (),
        }
    }

    fn raw_symbol_name<'data>(
        name_bytes: &'data [u8],
        _verneed_table: &Self::VerneedTable<'data>,
        _symbol_index: object::SymbolIndex,
    ) -> Self::RawSymbolName<'data> {
        RawSymbolName { name: name_bytes }
    }

    fn default_layout_rules(_args: &Self::Args) -> Vec<SectionRule<'static>> {
        DEFAULT_SECTION_RULES.to_vec()
    }

    fn align_load_segment_start(
        _segment_def: Self::ProgramSegmentDef,
        _segment_alignment: crate::alignment::Alignment,
        _file_offset: &mut usize,
        _mem_offset: &mut u64,
    ) {
        // Wasm has no load segments in the ELF sense.
    }

    fn build_output_order_and_program_segments<'data>(
        _custom: &crate::output_section_id::CustomSectionIds,
        output_kind: crate::output_kind::OutputKind,
        output_sections: &crate::output_section_id::OutputSections<'data, Self>,
        secondary: &crate::output_section_map::OutputSectionMap<
            Vec<crate::output_section_id::OutputSectionId>,
        >,
        _location_counters: &[crate::layout_rules::LocationCounter<'data>],
    ) -> (
        crate::output_section_id::OutputOrder<'data>,
        crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
    ) {
        use crate::wasm::output_section_id as osid;

        let mut builder = crate::output_section_id::OutputOrderBuilder::<Self>::new(
            Self::program_segment_defs().to_vec(),
            output_kind,
            output_sections,
            secondary,
            false,
            &[],
        );

        builder.add_section(crate::output_section_id::FILE_HEADER);
        builder.add_section(osid::WASM_TYPE);
        builder.add_section(osid::WASM_IMPORT);
        builder.add_section(osid::WASM_FUNCTION);
        builder.add_section(osid::WASM_TABLE);
        builder.add_section(osid::WASM_MEMORY);
        builder.add_section(osid::WASM_GLOBAL);
        builder.add_section(osid::WASM_EXPORT);
        builder.add_section(osid::WASM_START);
        builder.add_section(osid::WASM_ELEMENT);
        builder.add_section(osid::WASM_DATA_COUNT);
        builder.add_section(osid::WASM_CODE);
        builder.add_section(osid::WASM_DATA);
        builder.add_section(osid::WASM_NAME);
        builder.add_section(osid::WASM_TARGET_FEATURES);

        builder.build()
    }

    fn default_symtab_entry() -> Self::SymtabEntry {
        WasmSymbol::default()
    }

    fn is_allowed_in_archive(kind: crate::file_kind::FileKind) -> bool {
        kind == crate::file_kind::FileKind::WasmObject
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
}

fn parse_wasm_module<'data>(input: &'data [u8]) -> Result<File<'data>> {
    ensure!(input.len() >= 8, "Wasm module too short");
    ensure!(input[..4] == WASM_MAGIC, "missing Wasm magic header");
    let version = u32_from_slice(&input[4..8]);
    ensure!(
        version == WASM_VERSION,
        "unsupported Wasm version {version}"
    );

    let mut sections: Vec<SectionHeader> = Vec::new();
    let mut symbols: Vec<WasmSymbol> = Vec::new();
    let mut segment_alignments: Vec<Alignment> = Vec::new();
    let mut init_funcs: Vec<WasmInitFunc> = Vec::new();
    let mut reloc_sections: Vec<WasmRelocSection> = Vec::new();
    let mut target_features: Vec<WasmTargetFeature<'data>> = Vec::new();
    let mut standard_section_index = [None; STANDARD_SECTION_LOOKUP_LEN];

    for payload in Parser::new(0).parse_all(input) {
        let payload = payload?;
        let Some((id, range)) = payload.as_section() else {
            continue;
        };

        let mut name_range: Option<Range<u32>> = None;

        if let Payload::CustomSection(reader) = &payload {
            let section_name = reader.name();
            let name_end = reader.data_offset();
            let name_start = name_end - section_name.len();
            name_range = Some(name_start as u32..name_end as u32);

            if section_name == LINKING_SECTION_NAME {
                if let KnownCustom::Linking(linking) = reader.as_known() {
                    parse_linking_subsections(
                        input,
                        &linking,
                        &mut symbols,
                        &mut segment_alignments,
                        &mut init_funcs,
                    )?;
                }
            } else if section_name.starts_with(RELOC_SECTION_PREFIX) {
                if let KnownCustom::Reloc(reloc) = reader.as_known() {
                    reloc_sections.push(WasmRelocSection {
                        target_section_index: reloc.section_index(),
                        payload_range: name_end as u32..range.end as u32,
                    });
                }
            } else if section_name == TARGET_FEATURES_SECTION_NAME {
                target_features.extend(parse_target_features_payload(reader.data())?);
            }
        } else if (section_id::TYPE..=section_id::MAX).contains(&id) {
            standard_section_index[id as usize] = Some(sections.len() as u32);
        }

        sections.push(SectionHeader {
            id,
            payload_range: range.start as u32..range.end as u32,
            name_range,
        });
    }

    // Backfill names for unnamed undefined function/global symbols from the import section.
    // The Wasm linking convention allows symbol entries to omit the name when the symbol is
    // undefined; the canonical name lives in the import entry instead.
    backfill_unnamed_import_symbols(input, &standard_section_index, &sections, &mut symbols)?;

    let (num_function_imports, num_global_imports) =
        count_function_and_global_imports(input, &standard_section_index, &sections)?;
    let num_defined_functions = section_entry_count(
        input,
        &standard_section_index,
        &sections,
        section_id::FUNCTION,
    )?;
    let num_defined_globals = section_entry_count(
        input,
        &standard_section_index,
        &sections,
        section_id::GLOBAL,
    )?;
    let num_data_segments =
        section_entry_count(input, &standard_section_index, &sections, section_id::DATA)?;

    Ok(File {
        data: input,
        sections,
        standard_section_index,
        symbols,
        segment_alignments,
        init_funcs,
        reloc_sections,
        target_features,
        num_function_imports,
        num_global_imports,
        num_defined_functions,
        num_defined_globals,
        num_data_segments,
    })
}

fn count_function_and_global_imports(
    data: &[u8],
    standard_section_index: &[Option<u32>; STANDARD_SECTION_LOOKUP_LEN],
    sections: &[SectionHeader],
) -> Result<(u32, u32)> {
    let Some(section_index) = standard_section_index[section_id::IMPORT as usize] else {
        return Ok((0, 0));
    };
    let header = sections
        .get(section_index as usize)
        .ok_or_else(|| crate::error!("Wasm import section index out of range"))?;
    let payload = data
        .get(header.payload_range_usize())
        .ok_or_else(|| crate::error!("Wasm import section payload out of bounds"))?;
    let reader = ImportSectionReader::new(BinaryReader::new(
        payload,
        header.payload_range.start as usize,
    ))?;
    let mut num_function_imports = 0u32;
    let mut num_global_imports = 0u32;
    for import in reader.into_imports() {
        match import?.ty {
            TypeRef::Func(_) | TypeRef::FuncExact(_) => {
                num_function_imports = num_function_imports
                    .checked_add(1)
                    .ok_or_else(|| crate::error!("too many Wasm function imports"))?;
            }
            TypeRef::Global(_) => {
                num_global_imports = num_global_imports
                    .checked_add(1)
                    .ok_or_else(|| crate::error!("too many Wasm global imports"))?;
            }
            _ => {}
        }
    }
    Ok((num_function_imports, num_global_imports))
}

fn section_entry_count(
    data: &[u8],
    standard_section_index: &[Option<u32>; STANDARD_SECTION_LOOKUP_LEN],
    sections: &[SectionHeader],
    section_id: u8,
) -> Result<u32> {
    let Some(section_index) = standard_section_index[section_id as usize] else {
        return Ok(0);
    };
    let header = sections
        .get(section_index as usize)
        .ok_or_else(|| crate::error!("Wasm section index out of range"))?;
    let payload = data
        .get(header.payload_range_usize())
        .ok_or_else(|| crate::error!("Wasm section payload out of bounds"))?;
    let mut reader = BinaryReader::new(payload, header.payload_range.start as usize);
    Ok(reader.read_var_u32()?)
}

fn mark_all_wasm_units_live_and_scan_relocs<'data, 'scope, A: platform::Arch<Platform = Wasm>>(
    object: &mut crate::layout::ObjectLayoutState<'data, Wasm>,
    resources: &'scope crate::layout::GraphResources<'data, 'scope, Wasm>,
    queue: &mut crate::layout::LocalWorkQueue<Wasm>,
    scope: &rayon::Scope<'scope>,
) -> Result {
    object.format_specific.mark_all_units_live();
    object
        .format_specific
        .ensure_relocs_decoded(object.object)?;

    let code_len = object.format_specific.code_relocations.len();
    for i in 0..code_len {
        let reloc = object.format_specific.code_relocations[i];
        note_wasm_reloc_edge::<A>(object, &reloc, resources, queue, scope)?;
    }
    let data_len = object.format_specific.data_relocations.len();
    for i in 0..data_len {
        let reloc = object.format_specific.data_relocations[i];
        note_wasm_reloc_edge::<A>(object, &reloc, resources, queue, scope)?;
    }

    enqueue_wasm_force_export_roots::<A>(object, resources, queue, scope);
    Ok(())
}

fn enqueue_wasm_gc_unit<'data, 'scope, A: platform::Arch<Platform = Wasm>>(
    object: &crate::layout::ObjectLayoutState<'data, Wasm>,
    unit: WasmGcUnit,
    resources: &'scope crate::layout::GraphResources<'data, 'scope, Wasm>,
    queue: &mut crate::layout::LocalWorkQueue<Wasm>,
    scope: &rayon::Scope<'scope>,
) {
    if object.format_specific.is_dead(unit) {
        queue.send_gc_unit_request::<A>(object.file_id, unit, resources, scope);
    }
}

/// Roots: export section, EXPORTED / NO_STRIP linking flags, InitFuncs, `--export`.
/// Entry arrives via `LoadGlobalSymbol` from the prelude path.
fn enqueue_wasm_gc_roots<'data, 'scope, A: platform::Arch<Platform = Wasm>>(
    object: &crate::layout::ObjectLayoutState<'data, Wasm>,
    resources: &'scope crate::layout::GraphResources<'data, 'scope, Wasm>,
    queue: &mut crate::layout::LocalWorkQueue<Wasm>,
    scope: &rayon::Scope<'scope>,
) -> Result {
    let file = object.object;
    let num_function_imports = file.num_function_imports;
    let num_global_imports = file.num_global_imports;

    if let Some(export_section) = file.export_section_reader()? {
        for export in export_section {
            let export = export?;
            let unit = match export.kind {
                wasmparser::ExternalKind::Func | wasmparser::ExternalKind::FuncExact => {
                    if export.index < num_function_imports {
                        Some(WasmGcUnit::FunctionImport(export.index))
                    } else {
                        Some(WasmGcUnit::DefinedFunction(
                            export.index - num_function_imports,
                        ))
                    }
                }
                wasmparser::ExternalKind::Global => {
                    if export.index < num_global_imports {
                        Some(WasmGcUnit::GlobalImport(export.index))
                    } else {
                        Some(WasmGcUnit::DefinedGlobal(export.index - num_global_imports))
                    }
                }
                _ => None,
            };
            if let Some(unit) = unit {
                enqueue_wasm_gc_unit::<A>(object, unit, resources, queue, scope);
            }
        }
    }

    for sym_index in 0..object.object.symbols.len() {
        let sym = &object.object.symbols[sym_index];
        let flags = SymbolFlags::from_bits_truncate(sym.flags);
        if !(flags.contains(SymbolFlags::EXPORTED) || flags.contains(SymbolFlags::NO_STRIP)) {
            continue;
        }
        if let Some(unit) = wasm_gc_unit_for_symbol(object.object, sym) {
            enqueue_wasm_gc_unit::<A>(object, unit, resources, queue, scope);
        }
    }

    for init_index in 0..object.object.init_funcs.len() {
        let init = object.object.init_funcs[init_index];
        let Some(sym) = object.object.symbols.get(init.symbol_index as usize) else {
            bail!("InitFuncs symbol index {} out of range", init.symbol_index);
        };
        if let Some(unit) = wasm_gc_unit_for_symbol(object.object, sym) {
            enqueue_wasm_gc_unit::<A>(object, unit, resources, queue, scope);
        }
        if sym.is_weak() && sym.kind == WasmSymbolKind::Func && !sym.is_undefined() {
            send_wasm_definition_request::<A>(
                object,
                init.symbol_index as usize,
                resources,
                queue,
                scope,
            );
        }
    }

    enqueue_wasm_force_export_roots::<A>(object, resources, queue, scope);

    Ok(())
}

fn enqueue_wasm_force_export_roots<'data, 'scope, A: platform::Arch<Platform = Wasm>>(
    object: &crate::layout::ObjectLayoutState<'data, Wasm>,
    resources: &'scope crate::layout::GraphResources<'data, 'scope, Wasm>,
    queue: &mut crate::layout::LocalWorkQueue<Wasm>,
    scope: &rayon::Scope<'scope>,
) {
    for name in resources.symbol_db.args.force_export_symbol_names() {
        let Some(symbol_id) = resources
            .symbol_db
            .get_unversioned(&UnversionedSymbolName::prehashed(name.as_bytes()))
        else {
            continue;
        };
        let def_id = resources.symbol_db.definition(symbol_id);
        if resources.symbol_db.file_id_for_symbol(def_id) != object.file_id {
            continue;
        }
        let old_flags = resources
            .per_symbol_flags
            .get_atomic(def_id)
            .fetch_or(ValueFlags::DIRECT);
        if !old_flags.has_resolution() {
            queue.send_symbol_request::<A>(def_id, resources, scope);
        }
    }
}

fn walk_wasm_gc_unit_edges<'data, 'scope, A: platform::Arch<Platform = Wasm>>(
    object: &crate::layout::ObjectLayoutState<'data, Wasm>,
    unit: WasmGcUnit,
    resources: &'scope crate::layout::GraphResources<'data, 'scope, Wasm>,
    queue: &mut crate::layout::LocalWorkQueue<Wasm>,
    scope: &rayon::Scope<'scope>,
) -> Result {
    match unit {
        WasmGcUnit::DefinedFunction(ordinal) => {
            let Some(&(start, end)) = object
                .format_specific
                .function_body_spans
                .get(ordinal as usize)
            else {
                bail!("Wasm GC function ordinal {ordinal} out of range");
            };
            let range = reloc_index_range(&object.format_specific.code_relocations, start, end);
            for i in range {
                let reloc = object.format_specific.code_relocations[i];
                note_wasm_reloc_edge::<A>(object, &reloc, resources, queue, scope)?;
            }
        }
        WasmGcUnit::DataSegment(ordinal) => {
            let Some(&(start, end)) = object
                .format_specific
                .data_segment_spans
                .get(ordinal as usize)
            else {
                bail!("Wasm GC data segment ordinal {ordinal} out of range");
            };
            let range = reloc_index_range(&object.format_specific.data_relocations, start, end);
            for i in range {
                let reloc = object.format_specific.data_relocations[i];
                note_wasm_reloc_edge::<A>(object, &reloc, resources, queue, scope)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn note_wasm_reloc_edge<'data, 'scope, A: platform::Arch<Platform = Wasm>>(
    object: &crate::layout::ObjectLayoutState<'data, Wasm>,
    reloc: &WasmRelocation,
    resources: &'scope crate::layout::GraphResources<'data, 'scope, Wasm>,
    queue: &mut crate::layout::LocalWorkQueue<Wasm>,
    scope: &rayon::Scope<'scope>,
) -> Result {
    if reloc.ty == RelocationType::TypeIndexLeb {
        return Ok(());
    }

    let file = object.object;
    let Some(sym) = file.symbols.get(reloc.index as usize).copied() else {
        bail!("Wasm relocation symbol index {} out of range", reloc.index);
    };

    if !sym.is_undefined() {
        if let Some(unit) = wasm_gc_unit_for_symbol(file, &sym) {
            enqueue_wasm_gc_unit::<A>(object, unit, resources, queue, scope);
        }

        if sym.is_weak() && sym.kind == WasmSymbolKind::Func {
            send_wasm_definition_request::<A>(
                object,
                reloc.index as usize,
                resources,
                queue,
                scope,
            );
        }
        return Ok(());
    }

    // Undefined: keep the local import slot live (host / linker-defined / cross-object).
    if let Some(unit) = wasm_gc_unit_for_symbol(file, &sym) {
        enqueue_wasm_gc_unit::<A>(object, unit, resources, queue, scope);
    }

    send_wasm_definition_request::<A>(object, reloc.index as usize, resources, queue, scope);
    Ok(())
}

fn note_wasm_import_unit_definition<'data, 'scope, A: platform::Arch<Platform = Wasm>>(
    object: &crate::layout::ObjectLayoutState<'data, Wasm>,
    unit: WasmGcUnit,
    resources: &'scope crate::layout::GraphResources<'data, 'scope, Wasm>,
    queue: &mut crate::layout::LocalWorkQueue<Wasm>,
    scope: &rayon::Scope<'scope>,
) {
    let offsets = match unit {
        WasmGcUnit::FunctionImport(index) => object
            .format_specific
            .func_import_symbol_offsets
            .get(index as usize)
            .map_or(&[][..], Vec::as_slice),
        WasmGcUnit::GlobalImport(index) => object
            .format_specific
            .global_import_symbol_offsets
            .get(index as usize)
            .map_or(&[][..], Vec::as_slice),
        _ => return,
    };

    for &sym_offset in offsets {
        send_wasm_definition_request::<A>(object, sym_offset, resources, queue, scope);
    }
}

fn send_wasm_definition_request<'data, 'scope, A: platform::Arch<Platform = Wasm>>(
    object: &crate::layout::ObjectLayoutState<'data, Wasm>,
    local_symbol_offset: usize,
    resources: &'scope crate::layout::GraphResources<'data, 'scope, Wasm>,
    queue: &mut crate::layout::LocalWorkQueue<Wasm>,
    scope: &rayon::Scope<'scope>,
) {
    let local_symbol_id = object.symbol_id_range.offset_to_id(local_symbol_offset);
    let symbol_id = resources.symbol_db.definition(local_symbol_id);
    let previous_flags = resources
        .per_symbol_flags
        .get_atomic(symbol_id)
        .fetch_or(ValueFlags::DIRECT);
    if !previous_flags.has_resolution() {
        queue.send_symbol_request::<A>(symbol_id, resources, scope);
    }
}

/// For unnamed undefined Func/Global symbols, derive the name from the corresponding import
/// section entry. In Wasm relocatable objects, undefined symbols in the linking section may
/// omit their name; the canonical name is carried by the import entry instead.
fn backfill_unnamed_import_symbols(
    data: &[u8],
    standard_section_index: &[Option<u32>; STANDARD_SECTION_LOOKUP_LEN],
    sections: &[SectionHeader],
    symbols: &mut [WasmSymbol],
) -> Result {
    // Collect import names only if there are unnamed undefined symbols that need backfilling.
    let needs_backfill = symbols.iter().any(|s| {
        s.is_undefined()
            && !s.has_name()
            && matches!(s.kind, WasmSymbolKind::Func | WasmSymbolKind::Global)
    });
    if !needs_backfill {
        return Ok(());
    }

    let data_start = data.as_ptr() as usize;

    // Parse the import section to build name lookup tables indexed by function/global import
    // ordinal.
    let Some(import_payload) = standard_section_index
        .get(section_id::IMPORT as usize)
        .and_then(|idx| idx.as_ref())
        .and_then(|&idx| sections.get(idx as usize))
        .and_then(|header| data.get(header.payload_range_usize()))
    else {
        return Ok(());
    };
    let import_reader = ImportSectionReader::new(BinaryReader::new(import_payload, 0))?;

    let mut func_import_names: Vec<(u32, u32)> = Vec::new();
    let mut global_import_names: Vec<(u32, u32)> = Vec::new();
    for import in import_reader.into_imports() {
        let import = import?;
        let name_ptr = import.name.as_ptr() as usize - data_start;
        let name_entry = (name_ptr as u32, import.name.len() as u32);
        match import.ty {
            TypeRef::Func(_) | TypeRef::FuncExact(_) => func_import_names.push(name_entry),
            TypeRef::Global(_) => global_import_names.push(name_entry),
            _ => {}
        }
    }

    for sym in symbols.iter_mut() {
        if !sym.is_undefined() || sym.has_name() {
            continue;
        }
        let (start, len) = match sym.kind {
            WasmSymbolKind::Func => func_import_names
                .get(sym.index as usize)
                .copied()
                .unwrap_or((0, 0)),
            WasmSymbolKind::Global => global_import_names
                .get(sym.index as usize)
                .copied()
                .unwrap_or((0, 0)),
            _ => continue,
        };
        sym.name_start = start;
        sym.name_len = len;
    }

    Ok(())
}

fn parse_linking_subsections<'data>(
    data: &'data [u8],
    linking: &wasmparser::LinkingSectionReader<'data>,
    symbols: &mut Vec<WasmSymbol>,
    segment_alignments: &mut Vec<Alignment>,
    init_funcs: &mut Vec<WasmInitFunc>,
) -> Result {
    let data_start = data.as_ptr() as usize;
    let to_name_range = |s: &str| -> (u32, u32) {
        let start = s.as_ptr() as usize - data_start;
        (start as u32, s.len() as u32)
    };
    for sub in linking.subsections() {
        let sub = sub?;
        match sub {
            Linking::SymbolTable(map) => {
                for sym in map {
                    symbols.push(wasm_symbol_from_info(sym?, to_name_range));
                }
            }
            Linking::SegmentInfo(map) => {
                for seg in map {
                    let seg = seg?;
                    segment_alignments.push(Alignment::from_exponent(seg.alignment)?);
                }
            }
            Linking::InitFuncs(map) => {
                for init in map {
                    let init = init?;
                    init_funcs.push(WasmInitFunc {
                        priority: init.priority,
                        symbol_index: init.symbol_index,
                    });
                }
            }
            // `ComdatInfo` and `Unknown` subsections are not consumed.
            _ => {}
        }
    }

    Ok(())
}

fn wasm_symbol_from_info(
    info: SymbolInfo<'_>,
    to_name_range: impl Fn(&str) -> (u32, u32),
) -> WasmSymbol {
    let mut sym = WasmSymbol::default();
    let mut set_name = |name: Option<&str>| {
        if let Some(n) = name {
            let (start, len) = to_name_range(n);
            sym.name_start = start;
            sym.name_len = len;
        }
    };
    match info {
        SymbolInfo::Func { flags, index, name } => {
            sym.kind = WasmSymbolKind::Func;
            sym.flags = flags.bits();
            sym.index = index;
            set_name(name);
        }
        SymbolInfo::Data {
            flags,
            name,
            symbol,
        } => {
            sym.kind = WasmSymbolKind::Data;
            sym.flags = flags.bits();
            let (start, len) = to_name_range(name);
            sym.name_start = start;
            sym.name_len = len;
            if let Some(def) = symbol {
                sym.index = def.index;
                sym.offset = def.offset;
                sym.size = def.size;
            }
        }
        SymbolInfo::Global { flags, index, name } => {
            sym.kind = WasmSymbolKind::Global;
            sym.flags = flags.bits();
            sym.index = index;
            set_name(name);
        }
        SymbolInfo::Section { flags, section } => {
            sym.kind = WasmSymbolKind::Section;
            sym.flags = flags.bits();
            sym.index = section;
        }
        SymbolInfo::Event { flags, index, name } => {
            sym.kind = WasmSymbolKind::Event;
            sym.flags = flags.bits();
            sym.index = index;
            set_name(name);
        }
        SymbolInfo::Table { flags, index, name } => {
            sym.kind = WasmSymbolKind::Table;
            sym.flags = flags.bits();
            sym.index = index;
            set_name(name);
        }
    }

    sym
}

impl SinglePartSectionId {
    const fn part_id(self) -> PartId {
        PartId::from_u32(self as u32)
    }

    const fn output_section_id(self) -> OutputSectionId {
        OutputSectionId::from_u32(self as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::wasm::DEFAULT_STACK_SIZE;

    fn layout_input_with_features<'data>(
        file: u32,
        features: &'data [WasmTargetFeature<'data>],
    ) -> WasmObjectLayoutInput<'data> {
        WasmObjectLayoutInput {
            data: &[],
            types: Vec::new(),
            function_imports: Vec::new(),
            global_imports: Vec::new(),
            live_function_imports: Vec::new(),
            live_global_imports: Vec::new(),
            memory_imports: Vec::new(),
            table_imports: Vec::new(),
            module_functions: Vec::new(),
            globals: Vec::new(),
            exports: Vec::new(),
            function_bodies: Vec::new(),
            memories: Vec::new(),
            unsupported_output: Vec::new(),
            code_relocations: Vec::new(),
            data_segments: Vec::new(),
            data_segment_original_indices: Vec::new(),
            segment_alignments: &[],
            data_relocations: Vec::new(),
            symbols: &[],
            init_funcs: &[],
            target_features: features,
            symbol_id_range: crate::symbol_db::SymbolIdRange::empty(),
            file_id: crate::input_data::FileId::new(0, file),
            defined_function_live_ordinal: Vec::new(),
            defined_global_live_ordinal: Vec::new(),
        }
    }

    fn emitted_feature_names(section: &wasm_encoder::CustomSection<'_>) -> Vec<String> {
        let parsed = parse_target_features_payload(section.data.as_ref()).unwrap();
        assert!(
            parsed
                .iter()
                .all(|f| f.prefix == TARGET_FEATURE_PREFIX_USED),
            "output must only contain used (+) prefixes"
        );
        parsed.iter().map(|f| f.name.to_owned()).collect()
    }

    #[test]
    fn target_features_deduplicates_used_features_across_objects() {
        // Both objects use sign-ext. Only the first also uses bulk-memory.
        let features_a = [
            WasmTargetFeature {
                prefix: TARGET_FEATURE_PREFIX_USED,
                name: "sign-ext",
            },
            WasmTargetFeature {
                prefix: TARGET_FEATURE_PREFIX_USED,
                name: "bulk-memory",
            },
            WasmTargetFeature {
                prefix: TARGET_FEATURE_PREFIX_USED,
                name: "sign-ext",
            },
        ];
        let features_b = [WasmTargetFeature {
            prefix: TARGET_FEATURE_PREFIX_USED,
            name: "sign-ext",
        }];
        let inputs = [
            layout_input_with_features(1, &features_a),
            layout_input_with_features(2, &features_b),
        ];
        let section = build_target_features_section(&inputs)
            .unwrap()
            .expect("expected target_features section");
        assert_eq!(emitted_feature_names(&section), ["bulk-memory", "sign-ext"]);
    }

    #[test]
    fn target_features_errors_when_used_and_disallowed_conflict() {
        let used = [WasmTargetFeature {
            prefix: TARGET_FEATURE_PREFIX_USED,
            name: "atomics",
        }];
        let disallowed = [WasmTargetFeature {
            prefix: TARGET_FEATURE_PREFIX_DISALLOWED,
            name: "atomics",
        }];
        let inputs = [
            layout_input_with_features(1, &used),
            layout_input_with_features(2, &disallowed),
        ];
        let err = build_target_features_section(&inputs).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("atomics") && msg.contains("disallowed"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn parse_target_features_payload_used_and_disallowed() {
        // count=2, +bulk-memory, -atomics
        let payload: &[u8] = &[
            2, b'+', 11, b'b', b'u', b'l', b'k', b'-', b'm', b'e', b'm', b'o', b'r', b'y', b'-', 7,
            b'a', b't', b'o', b'm', b'i', b'c', b's',
        ];
        let features = parse_target_features_payload(payload).unwrap();
        assert_eq!(features.len(), 2);
        assert_eq!(features[0].prefix, TARGET_FEATURE_PREFIX_USED);
        assert_eq!(features[0].name, "bulk-memory");
        assert_eq!(features[1].prefix, TARGET_FEATURE_PREFIX_DISALLOWED);
        assert_eq!(features[1].name, "atomics");
    }

    #[test]
    fn linker_defined_data_symbol_addresses() {
        let data_start = 1024u32;
        let data_end = 1024u32;
        let page = wasm_page_size();
        let heap_end = heap_end_from_initial_pages(2).unwrap();
        let de = WasmLinkerSymbol::DataEnd
            .data_address(
                data_start,
                data_end,
                DEFAULT_STACK_SIZE,
                Some(heap_end),
                false,
            )
            .unwrap()
            .expect("__data_end");
        assert_eq!(de, data_end);

        let gb = WasmLinkerSymbol::GlobalBase
            .data_address(
                data_start,
                data_end,
                DEFAULT_STACK_SIZE,
                Some(heap_end),
                false,
            )
            .unwrap()
            .expect("__global_base");
        assert_eq!(gb, data_start);

        let dso = WasmLinkerSymbol::DsoHandle
            .data_address(
                data_start,
                data_end,
                DEFAULT_STACK_SIZE,
                Some(heap_end),
                false,
            )
            .unwrap()
            .expect("__dso_handle");
        assert_eq!(dso, data_start);

        let hb = WasmLinkerSymbol::HeapBase
            .data_address(
                data_start,
                data_end,
                DEFAULT_STACK_SIZE,
                Some(heap_end),
                false,
            )
            .unwrap()
            .expect("__heap_base");
        assert_eq!(
            hb,
            stack_high_after_data(data_end, DEFAULT_STACK_SIZE).unwrap()
        );

        let page_end = WasmLinkerSymbol::WasmFirstPageEnd
            .data_address(
                data_start,
                data_end,
                DEFAULT_STACK_SIZE,
                Some(heap_end),
                false,
            )
            .unwrap()
            .expect("__wasm_first_page_end");
        assert_eq!(u64::from(page_end), page);

        let he = WasmLinkerSymbol::HeapEnd
            .data_address(
                data_start,
                data_end,
                DEFAULT_STACK_SIZE,
                Some(heap_end),
                false,
            )
            .unwrap()
            .expect("__heap_end");
        assert_eq!(he, heap_end);
        assert!(he >= hb);
        assert_eq!(u64::from(he) % page, 0);

        // If there is no output memory, `__heap_end` is not synthesised.
        assert!(
            WasmLinkerSymbol::HeapEnd
                .data_address(data_start, data_end, DEFAULT_STACK_SIZE, None, false)
                .unwrap()
                .is_none()
        );
        assert!(
            WasmLinkerSymbol::WasmFirstPageEnd
                .data_address(data_start, data_end, DEFAULT_STACK_SIZE, None, false)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn stack_first_heap_base_follows_data_not_stack() {
        let data_start = 1_048_576u32;
        let data_end = 1_048_576 + 100;
        let stack_size = 1_048_576u32;
        let hb = WasmLinkerSymbol::HeapBase
            .data_address(data_start, data_end, stack_size, Some(2 * 65_536), true)
            .unwrap()
            .expect("__heap_base");
        assert_eq!(hb, heap_base_after_data(data_end).unwrap());
        assert!(hb - data_end < 16);
        let gb = WasmLinkerSymbol::GlobalBase
            .data_address(data_start, data_end, stack_size, Some(2 * 65_536), true)
            .unwrap()
            .expect("__global_base");
        assert_eq!(gb, data_start);
        let dso = WasmLinkerSymbol::DsoHandle
            .data_address(data_start, data_end, stack_size, Some(2 * 65_536), true)
            .unwrap()
            .expect("__dso_handle");
        assert_eq!(dso, data_start);
        // Without stack-first, heap would be roughly data_end + stack_size.
        let post_data = stack_high_after_data(data_end, stack_size).unwrap();
        assert!(post_data > hb + stack_size / 2);
    }

    #[test]
    fn stack_pointer_init_stack_first_is_stack_size() {
        let sp = stack_pointer_init(2_000_000, 1_048_576, true).unwrap();
        assert_eq!(sp, 1_048_576);
        let sp = stack_pointer_init(1024, DEFAULT_STACK_SIZE, false).unwrap();
        assert_eq!(sp, stack_high_after_data(1024, DEFAULT_STACK_SIZE).unwrap());
    }

    #[test]
    fn unaligned_stack_size_is_rejected() {
        assert!(ensure_stack_size_aligned(1000).is_err());
        assert!(ensure_stack_size_aligned(1024).is_ok());
        assert!(stack_pointer_init(0, 1000, true).is_err());
    }

    #[test]
    fn stack_high_is_sixteen_byte_aligned() {
        // Unaligned data_end must still yield a 16-byte-aligned stack top (wasm-ld).
        for data_end in [1u32, 2, 7, 1025, 4738] {
            let sp = stack_high_after_data(data_end, DEFAULT_STACK_SIZE).unwrap();
            assert_eq!(sp % 16, 0, "data_end={data_end} sp={sp}");
            assert!(sp >= data_end + DEFAULT_STACK_SIZE);
        }
    }

    #[test]
    fn ensure_memory_covers_stack_and_matches_heap_end() {
        let data_end = 1024u32;
        let mut layout = WasmLayout {
            data_end,
            memories: vec![MemoryType {
                memory64: false,
                shared: false,
                initial: 1,
                maximum: None,
                page_size_log2: None,
            }],
            ..Default::default()
        };

        let pages =
            ensure_memory_covers(&mut layout, DEFAULT_STACK_SIZE, true, None, None).unwrap();
        assert_eq!(pages, 1);
        assert_eq!(layout.memories[0].initial, 1);
        assert_eq!(layout.memories[0].maximum, None);

        let pages =
            ensure_memory_covers(&mut layout, DEFAULT_STACK_SIZE, false, None, None).unwrap();
        let expected_pages = (u64::from(data_end) + u64::from(DEFAULT_STACK_SIZE))
            .div_ceil(wasm_page_size())
            .max(1);
        assert_eq!(pages, expected_pages);
        assert_eq!(layout.memories[0].initial, expected_pages);
        assert!(expected_pages > 1);
        assert_eq!(
            heap_end_from_initial_pages(pages).unwrap(),
            u32::try_from(pages * wasm_page_size()).unwrap()
        );
    }
}
