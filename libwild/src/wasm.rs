// TODO
#![allow(unused)]

use crate::alignment::Alignment;
use crate::args::wasm::WasmArgs;
use crate::bail;
use crate::ensure;
use crate::error::Context as _;
use crate::error::Result;
use crate::layout;
use crate::layout_rules::SectionKind;
use crate::layout_rules::SectionRule;
use crate::layout_rules::SectionRuleOutcome;
use crate::output_section_id::SectionName;
use crate::platform;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolDb;
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
use wasmparser::SegmentFlags;
use wasmparser::SymbolFlags;
use wasmparser::SymbolInfo;
use wasmparser::TypeRef;
use wasmparser::TypeSectionReader;

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct Wasm;

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

pub(crate) mod reloc_type {
    pub(crate) const FUNCTION_INDEX_LEB: u8 = 0;
    pub(crate) const TABLE_INDEX_SLEB: u8 = 1;
    pub(crate) const TABLE_INDEX_I32: u8 = 2;
    pub(crate) const MEMORY_ADDR_LEB: u8 = 3;
    pub(crate) const MEMORY_ADDR_SLEB: u8 = 4;
    pub(crate) const MEMORY_ADDR_I32: u8 = 5;
    pub(crate) const TYPE_INDEX_LEB: u8 = 6;
    pub(crate) const GLOBAL_INDEX_LEB: u8 = 7;
    pub(crate) const FUNCTION_OFFSET_I32: u8 = 8;
    pub(crate) const SECTION_OFFSET_I32: u8 = 9;
    pub(crate) const EVENT_INDEX_LEB: u8 = 10;
    pub(crate) const MEMORY_ADDR_REL_SLEB: u8 = 11;
    pub(crate) const GLOBAL_INDEX_I32: u8 = 13;
    pub(crate) const TABLE_NUMBER_LEB: u8 = 20;
    pub(crate) const FUNCTION_INDEX_I32: u8 = 26;
}

/// `R_WASM_TYPE_INDEX_LEB` from the Wasm Tool Conventions. The only reloc whose `index` field
/// refers to a type index rather than a symbol index.
pub(crate) const R_WASM_TYPE_INDEX_LEB: u8 = reloc_type::TYPE_INDEX_LEB;

/// The custom-section name used for the linker metadata.
pub(crate) const LINKING_SECTION_NAME: &str = "linking";

/// The prefix of every `reloc.*` custom section.
pub(crate) const RELOC_SECTION_PREFIX: &str = "reloc.";

/// The custom-section name used for the WebAssembly target features.
pub(crate) const TARGET_FEATURES_SECTION_NAME: &str = "target_features";

/// Default static data base for linker-produced executables.
const LINKER_MEMORY_BASE: u32 = 1024;

/// Default stack size reserved above `__data_end` for the main stack.
const LINKER_STACK_SIZE: u32 = 64 * 1024;

/// Empty function body: zero locals + `end`.
const EMPTY_FUNCTION_BODY: &[u8] = &[0x00, 0x0b];

/// `i32.const` body for `LINKER_MEMORY_BASE`.
const LINKER_MEMORY_BASE_INIT_EXPR: &[u8] = &[0x41, 0x80, 0x08];

/// `i32.const 0`. Used for immutable `__tls_base` when no TLS segment is laid out.
const ZERO_I32_INIT_EXPR: &[u8] = &[0x41, 0x00];

#[derive(derive_more::Debug)]
pub(crate) struct File<'data> {
    #[debug(skip)]
    pub(crate) data: &'data [u8],

    pub(crate) version: u32,

    #[debug(skip)]
    pub(crate) sections: Vec<SectionHeader>,

    /// For each standard Wasm section id, the index into `sections`, if present.
    #[debug(skip)]
    pub(crate) standard_section_index: [Option<u32>; STANDARD_SECTION_LOOKUP_LEN],

    #[debug(skip)]
    pub(crate) symbols: Vec<WasmSymbol>,

    #[debug(skip)]
    pub(crate) segments: Vec<WasmSegmentInfo<'data>>,

    /// Init functions from the linking section (`InitFuncs`), in input order.
    #[debug(skip)]
    pub(crate) init_funcs: Vec<WasmInitFunc>,

    #[debug(skip)]
    pub(crate) reloc_sections: Vec<WasmRelocSection>,

    pub(crate) linking_version: Option<u32>,

    /// Raw payload of the `target_features` custom section, if present.
    #[debug(skip)]
    pub(crate) target_features_raw: Option<&'data [u8]>,
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
    pub(crate) fn is_custom(&self) -> bool {
        self.id == 0
    }

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

    pub(crate) fn is_exported(&self) -> bool {
        self.raw_flags().contains(SymbolFlags::EXPORTED)
    }

    fn has_name(&self) -> bool {
        self.name_len != 0
    }

    fn name_range(&self) -> Range<usize> {
        let s = self.name_start as usize;
        s..s + self.name_len as usize
    }
}

/// Per-data-segment metadata from the `linking` section.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WasmSegmentInfo<'data> {
    pub(crate) name: &'data str,
    pub(crate) alignment: Alignment,
    pub(crate) flags: SegmentFlags,
}

/// All relocations read from a single `reloc.*` custom section.
#[derive(Debug, Clone)]
pub(crate) struct WasmRelocSection {
    /// Index (into [`File::sections`]) of the section that the relocations apply to.
    pub(crate) target_section_index: u32,
    pub(crate) entries: Vec<WasmRelocation>,
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct WasmRelocation {
    /// Wasm relocation type code.
    pub(crate) ty: u8,
    /// Byte offset within the target section's payload.
    pub(crate) offset: u32,
    /// Symbol or type index.
    pub(crate) index: u32,
    pub(crate) addend: i64,
}

impl WasmRelocation {
    fn from_entry(entry: RelocationEntry) -> Self {
        Self {
            ty: entry.ty as u8,
            offset: entry.offset,
            index: entry.index,
            addend: entry.addend,
        }
    }

    /// Whether `index` refers to a symbol rather than a type index.
    pub(crate) fn refers_to_symbol(&self) -> bool {
        self.ty != R_WASM_TYPE_INDEX_LEB
    }

    /// Width in bytes of the slot this relocation overwrites.
    pub(crate) fn slot_size(&self) -> usize {
        match self.ty {
            reloc_type::FUNCTION_INDEX_LEB
            | reloc_type::TABLE_INDEX_SLEB
            | reloc_type::MEMORY_ADDR_LEB
            | reloc_type::MEMORY_ADDR_SLEB
            | reloc_type::MEMORY_ADDR_REL_SLEB
            | reloc_type::TYPE_INDEX_LEB
            | reloc_type::GLOBAL_INDEX_LEB
            | reloc_type::EVENT_INDEX_LEB
            | reloc_type::TABLE_NUMBER_LEB => 5,
            reloc_type::TABLE_INDEX_I32
            | reloc_type::MEMORY_ADDR_I32
            | reloc_type::FUNCTION_OFFSET_I32
            | reloc_type::SECTION_OFFSET_I32
            | reloc_type::GLOBAL_INDEX_I32
            | reloc_type::FUNCTION_INDEX_I32 => 4,
            _ => 0,
        }
    }
}

/// Write `value` as an unsigned LEB128 into `buf`, returning the number of bytes written.
pub(crate) fn write_uleb128(buf: &mut [u8], value: u64) -> usize {
    let mut writable = &mut *buf;
    leb128::write::unsigned(&mut writable, value).unwrap()
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
        reloc_type::FUNCTION_INDEX_LEB
        | reloc_type::MEMORY_ADDR_LEB
        | reloc_type::TYPE_INDEX_LEB
        | reloc_type::GLOBAL_INDEX_LEB
        | reloc_type::EVENT_INDEX_LEB
        | reloc_type::TABLE_NUMBER_LEB => {
            let buf: &mut [u8; 5] = slot.try_into().expect("slot_size returned 5");
            write_uleb128_5(buf, value);
        }
        reloc_type::TABLE_INDEX_SLEB
        | reloc_type::MEMORY_ADDR_SLEB
        | reloc_type::MEMORY_ADDR_REL_SLEB => {
            let buf: &mut [u8; 5] = slot.try_into().expect("slot_size returned 5");
            write_sleb128_5(buf, value as i32);
        }
        reloc_type::TABLE_INDEX_I32
        | reloc_type::MEMORY_ADDR_I32
        | reloc_type::FUNCTION_OFFSET_I32
        | reloc_type::SECTION_OFFSET_I32
        | reloc_type::GLOBAL_INDEX_I32
        | reloc_type::FUNCTION_INDEX_I32 => {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        other => bail!("unsupported Wasm relocation type {other}"),
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

/// A single imported memory.
#[derive(Debug, Copy, Clone)]
pub(crate) struct WasmMemoryImport<'data> {
    pub(crate) module: &'data str,
    pub(crate) name: &'data str,
    pub(crate) ty: MemoryType,
}

/// A single imported table (typically `env.__indirect_function_table`).
#[derive(Debug, Copy, Clone)]
pub(crate) struct WasmTableImport<'data> {
    pub(crate) module: &'data str,
    pub(crate) name: &'data str,
    pub(crate) ty: wasmparser::TableType,
}

/// A function defined inside the module (not imported). Stored as the index into the `type`
/// section that gives its signature; the function body lives in the `code` section.
#[derive(Debug, Copy, Clone)]
pub(crate) struct WasmModuleFunction {
    pub(crate) type_index: u32,
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
    pub(crate) kind: DataKind<'data>,
    pub(crate) data: &'data [u8],
    /// Relocations targeting this segment's payload bytes (segment-local offsets).
    pub(crate) relocations: Vec<WasmRelocation>,
    /// Output memory index after index remapping.
    pub(crate) output_memory_index: u32,
    /// Byte offset within the output module's linear memory where the payload is placed.
    pub(crate) output_memory_offset: u32,
    /// Byte offset of this segment's encoding within the output data section payload.
    pub(crate) output_section_offset: u32,
    /// Encoded size of this segment within the output data section payload.
    pub(crate) encoded_output_size: u32,
}

/// Per-object data segment layout.
#[derive(Debug, Default)]
pub(crate) struct WasmObjectDataLayout<'data> {
    pub(crate) file_id: crate::input_data::FileId,
    pub(crate) segments: Vec<WasmDataSegmentLayout<'data>>,
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

    /// Imported functions in declaration order. Imports of other kinds are skipped.
    pub(crate) fn function_imports(&self) -> Result<Vec<WasmFunctionImport<'data>>> {
        let Some(reader) = self.import_section_reader()? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for import in reader.into_imports() {
            let import = import?;
            if let TypeRef::Func(type_index) = import.ty {
                out.push(WasmFunctionImport {
                    module: import.module,
                    name: import.name,
                    type_index,
                });
            }
        }

        Ok(out)
    }

    /// Imported globals in declaration order. Imports of other kinds are skipped.
    pub(crate) fn global_imports(&self) -> Result<Vec<WasmGlobalImport<'data>>> {
        let Some(reader) = self.import_section_reader()? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for import in reader.into_imports() {
            let import = import?;
            if let TypeRef::Global(ty) = import.ty {
                out.push(WasmGlobalImport {
                    module: import.module,
                    name: import.name,
                    ty,
                });
            }
        }

        Ok(out)
    }

    /// Functions defined in this module (excluding imports), in `function` section order.
    pub(crate) fn module_functions(&self) -> Result<Vec<WasmModuleFunction>> {
        let Some(reader) = self.function_section_reader()? else {
            return Ok(Vec::new());
        };

        reader
            .into_iter()
            .map(|res| {
                res.map(|type_index| WasmModuleFunction { type_index })
                    .map_err(Into::into)
            })
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

    /// Number of imported entries in the `function` index space.
    pub(crate) fn function_import_count(&self) -> Result<u32> {
        self.count_imports_of(|ty| matches!(ty, TypeRef::Func(_)))
    }

    /// Number of imported entries in the `global` index space.
    pub(crate) fn global_import_count(&self) -> Result<u32> {
        self.count_imports_of(|ty| matches!(ty, TypeRef::Global(_)))
    }

    /// Size of the `function` index space: imports + module-defined functions.
    pub(crate) fn total_function_count(&self) -> Result<u32> {
        let module_count = self
            .function_section_reader()?
            .as_ref()
            .map_or(0, |r| r.count());

        Ok(self.function_import_count()? + module_count)
    }

    /// Size of the `global` index space: imports + module-defined globals.
    pub(crate) fn total_global_count(&self) -> Result<u32> {
        let module_count = self
            .global_section_reader()?
            .as_ref()
            .map_or(0, |r| r.count());
        Ok(self.global_import_count()? + module_count)
    }

    fn count_imports_of(&self, mut matches_kind: impl FnMut(&TypeRef) -> bool) -> Result<u32> {
        let Some(reader) = self.import_section_reader()? else {
            return Ok(0);
        };
        let mut count: u32 = 0;
        for import in reader.into_imports() {
            if matches_kind(&import?.ty) {
                count += 1;
            }
        }

        Ok(count)
    }
}

impl<'data> platform::ObjectFile<'data> for File<'data> {
    type Platform = Wasm;

    fn parse_bytes(input: &'data [u8], _is_dynamic: bool) -> crate::error::Result<Self> {
        parse_wasm_module(input).context("failed to parse Wasm object file")
    }

    fn parse(
        input: &crate::input_data::InputBytes<'data>,
        args: &<Self::Platform as platform::Platform>::Args,
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
            .map(|s| s.entries.clone())
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

    fn symbol_version_debug(&self, symbol_index: object::SymbolIndex) -> Option<String> {
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
        state: &mut <Self::Platform as platform::Platform>::ObjectLayoutStateExt<'data>,
        section_index: object::SectionIndex,
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
    fn new<P: platform::Platform>(symbol_db: &crate::symbol_db::SymbolDb<P>) -> Self {
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
    type Platform = Wasm;

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

    fn should_include_section(
        self,
        _section_info: &crate::output_section_id::SectionOutputInfo<Self::Platform>,
        section_id: crate::output_section_id::OutputSectionId,
        _rosegment: bool,
    ) -> bool {
        use crate::output_section_id as osid;

        let section_segment_type = match section_id {
            osid::FILE_HEADER => SegmentType::Header,
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
            | osid::WASM_DATA => SegmentType::Module,
            _ => SegmentType::Unused,
        };

        self.segment_type == section_segment_type
    }
}

pub(crate) struct BuiltInSectionDetails {
    pub(crate) kind: SectionKind<'static>,
    pub(crate) target_segment_type: Option<SegmentType>,
}

impl platform::BuiltInSectionDetails for BuiltInSectionDetails {}

const DEFAULT_DEFS: BuiltInSectionDetails = BuiltInSectionDetails {
    kind: SectionKind::Primary(SectionName(&[])),
    target_segment_type: None,
};

const SECTION_DEFINITIONS: [BuiltInSectionDetails;
    crate::output_section_id::NUM_BUILT_IN_SECTIONS] = {
    use crate::layout_rules::SectionKind;
    use crate::output_section_id as osid;
    use crate::output_section_id::SectionName;

    let mut defs: [BuiltInSectionDetails; osid::NUM_BUILT_IN_SECTIONS] =
        [DEFAULT_DEFS; osid::NUM_BUILT_IN_SECTIONS];

    // The module preamble.
    defs[osid::FILE_HEADER.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"WASM_HEADER")),
        target_segment_type: Some(SegmentType::Header),
    };

    // Standard Wasm sections.
    defs[osid::WASM_TYPE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"type")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_IMPORT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"import")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_FUNCTION.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"function")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_TABLE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"table")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_MEMORY.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"memory")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_GLOBAL.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"global")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_EXPORT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"export")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_START.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"start")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_ELEMENT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"element")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_DATA_COUNT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"data_count")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_CODE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"code")),
        target_segment_type: Some(SegmentType::Module),
    };
    defs[osid::WASM_DATA.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"data")),
        target_segment_type: Some(SegmentType::Module),
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
    fn version_name(&self, local_symbol_index: object::SymbolIndex) -> Option<&'data [u8]> {
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
    pub(crate) object_data_layouts: Vec<WasmObjectDataLayout<'data>>,
    pub(crate) per_object_symbols: Vec<Vec<WasmSymbol>>,
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
}

impl WasmEncodedSections {
    fn add_sizes_to(&self, sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>) {
        add_encoded_section_size(sizes, crate::part_id::WASM_TYPE, self.ty.as_ref());
        add_encoded_section_size(sizes, crate::part_id::WASM_IMPORT, self.import.as_ref());
        add_encoded_section_size(sizes, crate::part_id::WASM_FUNCTION, self.function.as_ref());
        add_encoded_section_size(sizes, crate::part_id::WASM_TABLE, self.table.as_ref());
        add_encoded_section_size(sizes, crate::part_id::WASM_MEMORY, self.memory.as_ref());
        add_encoded_section_size(sizes, crate::part_id::WASM_GLOBAL, self.global.as_ref());
        add_encoded_section_size(sizes, crate::part_id::WASM_EXPORT, self.export.as_ref());
        add_encoded_section_size(sizes, crate::part_id::WASM_ELEMENT, self.element.as_ref());
    }
}

fn add_encoded_section_size(
    sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    part_id: crate::part_id::PartId,
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

impl<'data> WasmLayout<'data> {
    fn encode_metadata_sections(&mut self) -> Result {
        let type_section = crate::wasm_writer::build_type_section(&self.output_types)?;
        if !type_section.is_empty() {
            self.encoded_sections.ty = Some(encode_wasm_section(&type_section));
        }

        let import_section = crate::wasm_writer::build_import_section(&self.imports)?;
        if !import_section.is_empty() {
            self.encoded_sections.import = Some(encode_wasm_section(&import_section));
        }

        let function_section =
            crate::wasm_writer::build_function_section(&self.function_type_indices);
        if !function_section.is_empty() {
            self.encoded_sections.function = Some(encode_wasm_section(&function_section));
        }

        let global_section = crate::wasm_writer::build_global_section(&self.globals)?;
        if !global_section.is_empty() {
            self.encoded_sections.global = Some(encode_wasm_section(&global_section));
        }

        let export_section = crate::wasm_writer::build_export_section(&self.exports);
        if !export_section.is_empty() {
            self.encoded_sections.export = Some(encode_wasm_section(&export_section));
        }

        let memory_section = crate::wasm_writer::build_memory_section(&self.memories);
        if !memory_section.is_empty() {
            self.encoded_sections.memory = Some(encode_wasm_section(&memory_section));
        }

        if !self.tables.is_empty() {
            let table_section = crate::wasm_writer::build_table_section(&self.tables)?;
            self.encoded_sections.table = Some(encode_wasm_section(&table_section));
        }

        if !self.element_functions.is_empty() {
            let element_section =
                crate::wasm_writer::build_element_section(&self.element_functions);
            self.encoded_sections.element = Some(encode_wasm_section(&element_section));
        }

        self.code_section_size = compute_code_section_size(&self.function_bodies);
        self.data_section_size = compute_data_section_size(&self.object_data_layouts);

        Ok(())
    }

    fn add_code_section_size(
        &self,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
        if self.code_section_size > 0 {
            sizes.increment(crate::part_id::WASM_CODE, self.code_section_size);
        }
    }

    fn add_data_section_size(
        &self,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
        if self.data_section_size > 0 {
            sizes.increment(crate::part_id::WASM_DATA, self.data_section_size);
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

fn classify_data_relocations(
    segments: &[WasmDataSegment<'_>],
    relocs: &[WasmRelocation],
) -> Vec<Vec<WasmRelocation>> {
    let mut per_segment = vec![Vec::new(); segments.len()];
    for &reloc in relocs {
        let Some(segment_idx) = segments.iter().position(|segment| {
            let Ok(encoded) = wasm_data_segment_encoded_size(&segment.kind, segment.data.len())
            else {
                return false;
            };
            let start = segment.section_offset;
            let end = start.saturating_add(encoded);
            reloc.offset >= start && reloc.offset < end
        }) else {
            continue;
        };
        let segment = &segments[segment_idx];
        let Ok(payload_start) =
            data_segment_payload_offset_in_section(&segment.kind, segment.data.len())
        else {
            continue;
        };
        let segment_payload_start = segment.section_offset.saturating_add(payload_start);
        if reloc.offset < segment_payload_start {
            continue;
        }
        per_segment[segment_idx].push(WasmRelocation {
            offset: reloc.offset - segment_payload_start,
            ..reloc
        });
    }
    per_segment
}

/// Align `data_end` to [`STACK_ALIGNMENT`], then add the stack size.
fn stack_high_after_data(data_end: u32) -> Result<u32> {
    let stack_base = u32::try_from(crate::alignment::STACK_ALIGNMENT.align_up(u64::from(data_end)))
        .map_err(|_| crate::error!("Wasm stack base overflow"))?;
    stack_base
        .checked_add(LINKER_STACK_SIZE)
        .ok_or_else(|| crate::error!("Wasm stack pointer overflow"))
}

fn layout_object_data<'data>(
    input: &WasmObjectLayoutInput<'data>,
    index_map: &WasmObjectIndexMap,
    memory_cursor: &mut u32,
    section_cursor: &mut u32,
) -> Result<WasmObjectDataLayout<'data>> {
    let mut segment_relocations =
        classify_data_relocations(&input.data_segments, &input.data_relocations);
    let mut segments = Vec::with_capacity(input.data_segments.len());
    for (segment_index, segment) in input.data_segments.iter().enumerate() {
        let DataKind::Active { memory_index, .. } = segment.kind else {
            bail!("passive data segments are not emitted");
        };
        let output_memory_index =
            remap_wasm_index(&index_map.memory_indices, memory_index, "memory")?;
        // Linking `SegmentInfo.alignment` is a power-of-two exponent.
        let align = input
            .segment_alignments
            .get(segment_index)
            .copied()
            .unwrap_or(crate::alignment::MIN);
        *memory_cursor = u32::try_from(align.align_up(u64::from(*memory_cursor)))
            .map_err(|_| crate::error!("Wasm data segment alignment overflow"))?;
        let output_memory_offset = *memory_cursor;
        let output_section_offset = *section_cursor;
        let encoded_output_size = output_data_segment_encoded_size(
            &segment.kind,
            segment.data.len(),
            output_memory_offset,
            output_memory_index,
        )?;
        *memory_cursor = memory_cursor
            .checked_add(u32::try_from(segment.data.len()).context("Wasm data segment too large")?)
            .ok_or_else(|| crate::error!("Wasm output memory offset overflow"))?;
        *section_cursor = section_cursor
            .checked_add(encoded_output_size)
            .ok_or_else(|| crate::error!("Wasm data section offset overflow"))?;
        segments.push(WasmDataSegmentLayout {
            segment_index: u32::try_from(segment_index).context("too many Wasm data segments")?,
            kind: segment.kind.clone(),
            data: segment.data,
            relocations: std::mem::take(&mut segment_relocations[segment_index]),
            output_memory_index,
            output_memory_offset,
            output_section_offset,
            encoded_output_size,
        });
    }
    Ok(WasmObjectDataLayout {
        file_id: input.file_id,
        segments,
    })
}

fn compute_data_section_size(object_data_layouts: &[WasmObjectDataLayout<'_>]) -> u64 {
    let segment_count: u32 = object_data_layouts
        .iter()
        .map(|obj| u32::try_from(obj.segments.len()).unwrap_or(u32::MAX))
        .sum();
    if segment_count == 0 {
        return 0;
    }
    let count_leb_size = uleb128_size(u64::from(segment_count)) as u64;
    let segments_total: u64 = object_data_layouts
        .iter()
        .flat_map(|obj| obj.segments.iter())
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
        if reloc.ty == R_WASM_TYPE_INDEX_LEB {
            return remap_wasm_index(&self.type_indices, reloc.index, "type");
        }

        let sym = symbols
            .get(reloc.index as usize)
            .ok_or_else(|| crate::error!("relocation symbol index {} out of range", reloc.index))?;

        match reloc.ty {
            reloc_type::FUNCTION_INDEX_LEB | reloc_type::FUNCTION_INDEX_I32 => {
                ensure!(
                    sym.kind == WasmSymbolKind::Func,
                    "R_WASM_FUNCTION_INDEX_* references non-function symbol"
                );
                remap_wasm_index(&self.function_indices, sym.index, "function")
            }
            reloc_type::GLOBAL_INDEX_LEB | reloc_type::GLOBAL_INDEX_I32 => {
                ensure!(
                    sym.kind == WasmSymbolKind::Global,
                    "R_WASM_GLOBAL_INDEX_* references non-global symbol"
                );
                remap_wasm_index(&self.global_indices, sym.index, "global")
            }
            reloc_type::TABLE_NUMBER_LEB => {
                ensure!(
                    sym.kind == WasmSymbolKind::Table,
                    "R_WASM_TABLE_NUMBER_LEB references non-table symbol"
                );
                remap_wasm_index(&self.table_indices, sym.index, "table")
            }
            reloc_type::MEMORY_ADDR_LEB
            | reloc_type::MEMORY_ADDR_SLEB
            | reloc_type::MEMORY_ADDR_I32
            | reloc_type::MEMORY_ADDR_REL_SLEB => {
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
                if reloc.ty == reloc_type::MEMORY_ADDR_REL_SLEB {
                    let relative = i64::from(addr) - i64::from(memory_base) + reloc.addend;
                    let relative = i32::try_from(relative)
                        .map_err(|_| crate::error!("Wasm REL_SLEB relocation out of range"))?;
                    Ok(relative as u32)
                } else {
                    Ok(addr)
                }
            }
            reloc_type::TABLE_INDEX_SLEB | reloc_type::TABLE_INDEX_I32 => {
                ensure!(
                    sym.kind == WasmSymbolKind::Func,
                    "R_WASM_TABLE_INDEX_* references non-function symbol"
                );
                let func_out = remap_wasm_index(&self.function_indices, sym.index, "function")?;
                let slot = function_table_slots
                    .get(func_out as usize)
                    .copied()
                    .unwrap_or(u32::MAX);
                ensure!(
                    slot != u32::MAX,
                    "function {func_out} has no indirect table slot"
                );
                Ok(slot)
            }
            reloc_type::EVENT_INDEX_LEB => {
                bail!("event index relocations are not supported yet");
            }
            reloc_type::FUNCTION_OFFSET_I32 => {
                bail!("function offset relocations are not supported yet");
            }
            reloc_type::SECTION_OFFSET_I32 => {
                bail!("section offset relocations are not supported yet");
            }
            other => bail!("unsupported Wasm relocation type {other}"),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct WasmObjectLayout<'data> {
    pub(crate) symbol_id_range: crate::symbol_db::SymbolIdRange,
    pub(crate) file_id: crate::input_data::FileId,
    _phantom: std::marker::PhantomData<&'data ()>,
}

#[derive(Debug)]
struct WasmObjectLayoutInput<'data> {
    types: Vec<wasmparser::FuncType>,
    function_imports: Vec<WasmFunctionImport<'data>>,
    global_imports: Vec<WasmGlobalImport<'data>>,
    memory_imports: Vec<WasmMemoryImport<'data>>,
    table_imports: Vec<WasmTableImport<'data>>,
    module_functions: Vec<WasmModuleFunction>,
    globals: Vec<OutputGlobal<'data>>,
    exports: Vec<OutputExport<'data>>,
    function_bodies: Vec<WasmFunctionBody<'data>>,
    memories: Vec<MemoryType>,
    unsupported_output: Vec<&'static str>,
    code_relocations: Vec<WasmRelocation>,
    data_segments: Vec<WasmDataSegment<'data>>,
    segment_alignments: Vec<Alignment>,
    data_relocations: Vec<WasmRelocation>,
    symbols: Vec<WasmSymbol>,
    init_funcs: Vec<WasmInitFunc>,
    symbol_id_range: crate::symbol_db::SymbolIdRange,
    file_id: crate::input_data::FileId,
}

#[derive(Debug, Clone, Copy)]
struct WasmObjectIndexBases {
    type_index_base: u32,
    function_import_base: u32,
    defined_function_base: u32,
    global_import_base: u32,
    defined_global_base: u32,
    memory_base: u32,
}

#[derive(Debug)]
struct WasmObjectOutputLayout<'data> {
    types: Vec<wasmparser::FuncType>,
    imports: Vec<OutputImport<'data>>,
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
        file: &File<'data>,
        symbol_id_range: crate::symbol_db::SymbolIdRange,
        file_id: crate::input_data::FileId,
    ) -> Result<Self> {
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
                        table_imports.push(WasmTableImport {
                            module: import.module,
                            name: import.name,
                            ty,
                        });
                    }
                    TypeRef::Memory(memory) => {
                        memory_imports.push(WasmMemoryImport {
                            module: import.module,
                            name: import.name,
                            ty: memory,
                        });
                    }
                    TypeRef::Tag(_) => bail!("Wasm tag imports are not emitted"),
                }
            }
        }

        let code_section_index = file.standard_section_index[section_id::CODE as usize];
        let code_relocations: Vec<WasmRelocation> = code_section_index
            .and_then(|code_idx| {
                file.reloc_sections
                    .iter()
                    .find(|s| s.target_section_index == code_idx)
            })
            .map(|s| s.entries.clone())
            .unwrap_or_default();

        let data_section_index = file.standard_section_index[section_id::DATA as usize];
        let data_relocations: Vec<WasmRelocation> = data_section_index
            .and_then(|data_idx| {
                file.reloc_sections
                    .iter()
                    .find(|s| s.target_section_index == data_idx)
            })
            .map(|s| s.entries.clone())
            .unwrap_or_default();

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
        if !data_relocations.is_empty() && !data_relocations_are_supported(&data_relocations) {
            unsupported_output.push("data relocation");
        }
        if file.standard_section_index[section_id::TABLE as usize].is_some() {
            unsupported_output.push("table definition");
        }
        if file.standard_section_index[section_id::START as usize].is_some() {
            unsupported_output.push("start");
        }
        let data_segments = file.data_segments()?;
        for segment in &data_segments {
            if let DataKind::Passive = segment.kind {
                unsupported_output.push("passive data segment");
                break;
            }
        }

        let module_functions = file.module_functions()?;
        let function_bodies = file.function_bodies()?;
        ensure!(
            module_functions.len() == function_bodies.len(),
            "Wasm function and code section counts differ"
        );
        let memories = file.memories()?;

        let globals = file
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
            types,
            function_imports,
            global_imports,
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
            segment_alignments: file.segments.iter().map(|s| s.alignment).collect(),
            data_relocations,
            symbols: file.symbols.clone(),
            init_funcs: file.init_funcs.clone(),
            symbol_id_range,
            file_id,
        })
    }

    fn build_object_output_layout(
        &self,
        index_bases: WasmObjectIndexBases,
        resolutions: &ObjectImportResolutions,
        all_index_bases: &[WasmObjectIndexBases],
        indices: &LinkerDefinedIndices,
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
                self.function_imports.len() + self.module_functions.len(),
            ),
            global_indices: Vec::with_capacity(self.global_imports.len() + self.globals.len()),
            memory_indices: Vec::with_capacity(self.memory_imports.len() + self.memories.len()),
            table_indices: vec![0; self.table_imports.len()],
            data_addresses: Vec::new(),
        };

        let mut imports =
            Vec::with_capacity(self.function_imports.len() + self.global_imports.len());
        let mut unresolved_func_count = 0u32;
        for (i, import) in self.function_imports.iter().enumerate() {
            match resolutions.function_resolutions[i] {
                ImportResolution::Unresolved => {
                    if let Some(index) = indices.function_index(import.name) {
                        index_map.function_indices.push(index);
                        continue;
                    }
                    let output_type_index = index_bases
                        .type_index_base
                        .checked_add(import.type_index)
                        .ok_or_else(|| crate::error!("Wasm type index overflow"))?;
                    let output_function_index = index_bases
                        .function_import_base
                        .checked_add(unresolved_func_count)
                        .ok_or_else(|| crate::error!("Wasm function index overflow"))?;
                    unresolved_func_count += 1;
                    index_map.function_indices.push(output_function_index);
                    imports.push(OutputImport {
                        module: import.module,
                        name: import.name,
                        entity: OutputImportEntity::Function {
                            type_index: output_type_index,
                        },
                    });
                }
                ImportResolution::ResolvedFunction {
                    object_index,
                    local_defined_index,
                } => {
                    ensure!(
                        object_index < all_index_bases.len(),
                        "Wasm function import resolution references object index {object_index} \
                         out of range"
                    );
                    let target_bases = &all_index_bases[object_index];
                    let output_function_index = target_bases
                        .defined_function_base
                        .checked_add(local_defined_index)
                        .ok_or_else(|| crate::error!("Wasm function index overflow"))?;
                    index_map.function_indices.push(output_function_index);
                }
                ImportResolution::ResolvedGlobal { .. } => {
                    bail!("function import resolved as global");
                }
            }
        }

        let mut unresolved_global_count = 0u32;
        for (i, import) in self.global_imports.iter().enumerate() {
            match resolutions.global_resolutions[i] {
                ImportResolution::Unresolved => {
                    if let Some(index) = indices.global_index(import.name) {
                        index_map.global_indices.push(index);
                        continue;
                    }
                    let output_global_index = index_bases
                        .global_import_base
                        .checked_add(unresolved_global_count)
                        .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
                    unresolved_global_count += 1;
                    index_map.global_indices.push(output_global_index);
                    imports.push(OutputImport {
                        module: import.module,
                        name: import.name,
                        entity: OutputImportEntity::Global(import.ty),
                    });
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
                    let target_bases = &all_index_bases[object_index];
                    let output_global_index = target_bases
                        .defined_global_base
                        .checked_add(local_defined_index)
                        .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
                    index_map.global_indices.push(output_global_index);
                }
                ImportResolution::ResolvedFunction { .. } => {
                    bail!("global import resolved as function");
                }
            }
        }

        let mut function_type_indices = Vec::with_capacity(self.module_functions.len());
        for (i, function) in self.module_functions.iter().enumerate() {
            let output_type_index = index_bases
                .type_index_base
                .checked_add(function.type_index)
                .ok_or_else(|| crate::error!("Wasm type index overflow"))?;
            let output_function_index = index_bases
                .defined_function_base
                .checked_add(u32::try_from(i).context("too many Wasm functions")?)
                .ok_or_else(|| crate::error!("Wasm function index overflow"))?;
            function_type_indices.push(output_type_index);
            index_map.function_indices.push(output_function_index);
        }

        for i in 0..self.globals.len() {
            let output_global_index = index_bases
                .defined_global_base
                .checked_add(u32::try_from(i).context("too many Wasm globals")?)
                .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
            index_map.global_indices.push(output_global_index);
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
            imports,
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
}

#[derive(Debug, Default)]
struct ObjectImportResolutions {
    function_resolutions: Vec<ImportResolution>,
    global_resolutions: Vec<ImportResolution>,
    unresolved_function_count: u32,
    unresolved_global_count: u32,
}

fn local_defined_function_index(input: &WasmObjectLayoutInput<'_>, sym: &WasmSymbol) -> u32 {
    sym.index - input.function_imports.len() as u32
}

fn local_defined_global_index(input: &WasmObjectLayoutInput<'_>, sym: &WasmSymbol) -> u32 {
    sym.index - input.global_imports.len() as u32
}

/// Resolve cross-object imports. For each object's undefined function/global symbol, checks whether
/// `SymbolDb::definition()` points to a defined symbol. Resolutions are keyed by import ordinal
/// (`sym.index`), not symbol-table order.
fn resolve_cross_object_imports<'data>(
    inputs: &[WasmObjectLayoutInput<'data>],
    symbol_db: &crate::symbol_db::SymbolDb<'data, Wasm>,
) -> Result<Vec<ObjectImportResolutions>> {
    let file_id_to_index: HashMap<crate::input_data::FileId, usize> = inputs
        .iter()
        .enumerate()
        .map(|(i, input)| (input.file_id, i))
        .collect();

    inputs
        .par_iter()
        .map(|input| {
            let (function_resolutions, unresolved_function_count) = resolve_import_symbols(
                input.function_imports.len(),
                WasmSymbolKind::Func,
                input,
                inputs,
                symbol_db,
                &file_id_to_index,
            )?;
            let (global_resolutions, unresolved_global_count) = resolve_import_symbols(
                input.global_imports.len(),
                WasmSymbolKind::Global,
                input,
                inputs,
                symbol_db,
                &file_id_to_index,
            )?;
            Ok(ObjectImportResolutions {
                function_resolutions,
                global_resolutions,
                unresolved_function_count,
                unresolved_global_count,
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
) -> Result<(Vec<ImportResolution>, u32)> {
    ensure!(u32::try_from(import_count).is_ok(), "too many Wasm imports");
    let mut resolutions = vec![ImportResolution::Unresolved; import_count];
    let mut unresolved_count = u32::try_from(import_count).expect("checked above");

    for (sym_offset, sym) in input.symbols.iter().enumerate() {
        if !sym.is_undefined() || sym.kind != kind {
            continue;
        }
        let import_idx = sym.index as usize;
        if import_idx >= import_count {
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
            unresolved_count -= 1;
            resolutions[import_idx] = resolution;
        }
    }

    Ok((resolutions, unresolved_count))
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
                local_defined_index: local_defined_function_index(def_input, def_sym),
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
                local_defined_index: local_defined_global_index(def_input, def_sym),
            })
        }
        _ => Ok(ImportResolution::Unresolved),
    }
}

fn object_needs_linker_memory(input: &WasmObjectLayoutInput<'_>) -> bool {
    !input.memory_imports.is_empty() || !input.memories.is_empty()
}

fn any_object_needs_linker_memory(inputs: &[WasmObjectLayoutInput<'_>]) -> bool {
    inputs.iter().any(object_needs_linker_memory)
}

#[derive(Debug, Clone, Copy, Default)]
struct LinkerImportAbsorption {
    absorbed_functions: u32,
    absorbed_globals: u32,
    needs_memory_base: bool,
    needs_stack_pointer: bool,
    needs_tls_base: bool,
    needs_ctors: bool,
    needs_dtors: bool,
}

impl LinkerImportAbsorption {
    fn for_object(
        input: &WasmObjectLayoutInput<'_>,
        resolutions: &ObjectImportResolutions,
    ) -> Self {
        let mut absorption = Self::default();
        for (i, import) in input.function_imports.iter().enumerate() {
            if !matches!(
                resolutions.function_resolutions.get(i),
                Some(ImportResolution::Unresolved)
            ) {
                continue;
            }
            match import.name {
                "__wasm_call_ctors" => {
                    absorption.needs_ctors = true;
                    absorption.absorbed_functions += 1;
                }
                "__wasm_call_dtors" => {
                    absorption.needs_dtors = true;
                    absorption.absorbed_functions += 1;
                }
                _ => {}
            }
        }
        for (i, import) in input.global_imports.iter().enumerate() {
            if !matches!(
                resolutions.global_resolutions.get(i),
                Some(ImportResolution::Unresolved)
            ) {
                continue;
            }
            match import.name {
                "__memory_base" => {
                    absorption.needs_memory_base = true;
                    absorption.absorbed_globals += 1;
                }
                "__stack_pointer" => {
                    absorption.needs_stack_pointer = true;
                    absorption.absorbed_globals += 1;
                }
                // Single-threaded. Immutable base (no TLS segment yet).
                "__tls_base" => {
                    absorption.needs_tls_base = true;
                    absorption.absorbed_globals += 1;
                }
                _ => {}
            }
        }
        absorption
    }
}

fn remaining_unresolved_imports(unresolved: u32, absorbed: u32) -> Result<u32> {
    unresolved.checked_sub(absorbed).ok_or_else(|| {
        crate::error!(
            "Wasm linker absorption count ({absorbed}) exceeds unresolved imports ({unresolved})"
        )
    })
}

/// Reserved Wasm index-space slots for linker-defined globals/functions.
#[derive(Debug, Clone, Copy, Default)]
struct LinkerDefinedIndices {
    memory_base_global: Option<u32>,
    stack_pointer_global: Option<u32>,
    tls_base_global: Option<u32>,
    /// Index of `__stack_pointer` among the defined globals prepended by
    /// `emit_reserved_linker_definitions` (not the Wasm module global index).
    stack_pointer_defined_slot: Option<u32>,
    call_ctors_func: Option<u32>,
    call_dtors_func: Option<u32>,
    entry_wrapper_func: Option<u32>,
    num_defined_globals: u32,
    num_defined_functions: u32,
}

/// True if inputs import or export `__wasm_call_ctors`.
fn call_ctors_used_in_objects(inputs: &[WasmObjectLayoutInput<'_>]) -> bool {
    inputs.iter().any(|input| {
        input
            .function_imports
            .iter()
            .any(|imp| imp.name == "__wasm_call_ctors")
            || input
                .exports
                .iter()
                .any(|exp| exp.name == "__wasm_call_ctors")
    })
}

fn entry_is_defined_function(
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    symbol_db: &SymbolDb<'_, Wasm>,
) -> bool {
    let entry_name = symbol_db.entry_symbol_name();
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

impl LinkerDefinedIndices {
    fn compute(
        inputs: &[WasmObjectLayoutInput<'_>],
        import_resolutions: &[ObjectImportResolutions],
        has_init_funcs: bool,
        wrap_entry: bool,
    ) -> Result<Self> {
        let mut needs_memory_base = false;
        let mut needs_stack_pointer = false;
        let mut needs_tls_base = false;
        let mut needs_ctors = has_init_funcs;
        let mut needs_dtors = false;
        let mut function_import_count = 0u32;
        let mut global_import_count = 0u32;

        for (input, resolutions) in inputs.iter().zip(import_resolutions) {
            let absorption = LinkerImportAbsorption::for_object(input, resolutions);
            needs_ctors |= absorption.needs_ctors;
            needs_dtors |= absorption.needs_dtors;
            needs_memory_base |= absorption.needs_memory_base;
            needs_stack_pointer |= absorption.needs_stack_pointer;
            needs_tls_base |= absorption.needs_tls_base;

            function_import_count = function_import_count
                .checked_add(remaining_unresolved_imports(
                    resolutions.unresolved_function_count,
                    absorption.absorbed_functions,
                )?)
                .ok_or_else(|| crate::error!("Wasm function index overflow"))?;

            global_import_count = global_import_count
                .checked_add(remaining_unresolved_imports(
                    resolutions.unresolved_global_count,
                    absorption.absorbed_globals,
                )?)
                .ok_or_else(|| crate::error!("Wasm global index overflow"))?;

            if !needs_memory_base
                && input
                    .code_relocations
                    .iter()
                    .chain(input.data_relocations.iter())
                    .any(|reloc| reloc.ty == reloc_type::MEMORY_ADDR_REL_SLEB)
            {
                needs_memory_base = true;
            }
        }

        let mut next_global = global_import_count;
        let mut next_defined_global_slot = 0u32;
        let memory_base_global = needs_memory_base.then(|| {
            let idx = next_global;
            next_global += 1;
            next_defined_global_slot += 1;
            idx
        });
        let stack_pointer_defined_slot = needs_stack_pointer.then_some(next_defined_global_slot);
        let stack_pointer_global = needs_stack_pointer.then(|| {
            let idx = next_global;
            next_global += 1;
            next_defined_global_slot += 1;
            idx
        });
        let tls_base_global = needs_tls_base.then(|| {
            let idx = next_global;
            next_global += 1;
            next_defined_global_slot += 1;
            idx
        });
        let num_defined_globals = next_global - global_import_count;

        let mut next_func = function_import_count;
        let call_ctors_func = needs_ctors.then(|| {
            let idx = next_func;
            next_func += 1;
            idx
        });
        let call_dtors_func = needs_dtors.then(|| {
            let idx = next_func;
            next_func += 1;
            idx
        });
        let entry_wrapper_func = wrap_entry.then(|| {
            let idx = next_func;
            next_func += 1;
            idx
        });
        let num_defined_functions = next_func - function_import_count;

        Ok(Self {
            memory_base_global,
            stack_pointer_global,
            tls_base_global,
            stack_pointer_defined_slot,
            call_ctors_func,
            call_dtors_func,
            entry_wrapper_func,
            num_defined_globals,
            num_defined_functions,
        })
    }

    fn global_index(&self, name: &str) -> Option<u32> {
        match name {
            "__memory_base" => self.memory_base_global,
            "__stack_pointer" => self.stack_pointer_global,
            "__tls_base" => self.tls_base_global,
            _ => None,
        }
    }

    fn function_index(&self, name: &str) -> Option<u32> {
        match name {
            "__wasm_call_ctors" => self.call_ctors_func,
            "__wasm_call_dtors" => self.call_dtors_func,
            _ => None,
        }
    }
}

fn encode_i32_const_body(value: i32) -> Vec<u8> {
    let mut bytes = vec![0x41];
    leb128::write::signed(&mut bytes, i64::from(value)).unwrap();
    bytes
}

fn ensure_void_void_type(types: &mut Vec<wasmparser::FuncType>) -> u32 {
    if let Some((idx, _)) = types
        .iter()
        .enumerate()
        .find(|(_, ty)| ty.params().is_empty() && ty.results().is_empty())
    {
        return idx as u32;
    }
    types.push(wasmparser::FuncType::new([], []));
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

fn empty_linker_function_body() -> WasmFunctionBody<'static> {
    WasmFunctionBody {
        bytes: Cow::Borrowed(EMPTY_FUNCTION_BODY),
        code_offset: 0,
        relocations: Vec::new(),
        object_index: 0,
    }
}

fn owned_linker_function_body(bytes: Vec<u8>) -> WasmFunctionBody<'static> {
    WasmFunctionBody {
        bytes: Cow::Owned(bytes),
        code_offset: 0,
        relocations: Vec::new(),
        object_index: 0,
    }
}

fn encode_call_sequence_body(func_indices: &[u32]) -> Vec<u8> {
    let mut bytes = vec![0x00]; // 0 locals
    for &func_index in func_indices {
        bytes.push(0x10); // call
        leb128::write::unsigned(&mut bytes, u64::from(func_index))
            .expect("leb128 write to Vec cannot fail");
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
        let local = (sym_index - n_imports);
        input
            .module_functions
            .get(local)
            .ok_or_else(|| crate::error!("Wasm function index {} out of range", sym.index))?
            .type_index
    };
    input
        .types
        .get(type_index as usize)
        .ok_or_else(|| crate::error!("Wasm type index {type_index} out of range"))
}

/// From InitFuncs to output function indices, sorted by ascending priority.
fn collect_sorted_init_function_indices(
    inputs: &[WasmObjectLayoutInput<'_>],
    object_index_maps: &[WasmObjectIndexMap],
) -> Result<Vec<u32>> {
    let mut items = Vec::new();
    for (obj_idx, input) in inputs.iter().enumerate() {
        let index_map = &object_index_maps[obj_idx];
        for init in &input.init_funcs {
            let sym = &input.symbols[init.symbol_index as usize];
            ensure!(
                sym.kind == WasmSymbolKind::Func && !sym.is_undefined(),
                "Wasm init function must be a defined function symbol"
            );
            let ty = function_type_for_symbol(input, sym)?;
            ensure!(
                ty.params().is_empty() && ty.results().is_empty(),
                "Wasm constructor must have type () -> ()"
            );
            let output_index =
                remap_wasm_index(&index_map.function_indices, sym.index, "function")?;
            items.push((init.priority, output_index));
        }
    }
    items.sort_by_key(|(priority, _)| *priority);
    Ok(items.into_iter().map(|(_, index)| index).collect())
}

fn emit_reserved_linker_definitions(
    layout: &mut WasmLayout<'_>,
    indices: &LinkerDefinedIndices,
    call_ctors_body: Option<Vec<u8>>,
    entry_wrapper_body: Option<Vec<u8>>,
) {
    let mut linker_globals = Vec::with_capacity(indices.num_defined_globals as usize);
    if indices.memory_base_global.is_some() {
        layout.memory_base = LINKER_MEMORY_BASE;
        linker_globals.push(OutputGlobal {
            ty: GlobalType {
                content_type: wasmparser::ValType::I32,
                mutable: false,
                shared: false,
            },
            init_expr_body: Cow::Borrowed(LINKER_MEMORY_BASE_INIT_EXPR),
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
        if indices.call_dtors_func.is_some() {
            type_indices.push(void_ty);
            bodies.push(empty_linker_function_body());
        }
        if indices.entry_wrapper_func.is_some() {
            type_indices.push(void_ty);
            bodies.push(match entry_wrapper_body {
                Some(bytes) => owned_linker_function_body(bytes),
                None => empty_linker_function_body(),
            });
        }
        type_indices.append(&mut layout.function_type_indices);

        let mut object_bodies = std::mem::take(&mut layout.function_bodies);
        bodies.append(&mut object_bodies);
        layout.function_type_indices = type_indices;
        layout.function_bodies = bodies;
    }
}

/// Write stack-pointer init and memory page sizes after static data layout.
fn fill_linker_defined_values(
    layout: &mut WasmLayout<'_>,
    indices: &LinkerDefinedIndices,
    needs_stack_gap: bool,
) -> Result {
    if let Some(defined_slot) = indices.stack_pointer_defined_slot {
        let sp = stack_high_after_data(layout.data_end)?;
        let global = layout
            .globals
            .get_mut(defined_slot as usize)
            .ok_or_else(|| crate::error!("Wasm stack pointer global missing"))?;
        ensure!(
            global.ty.mutable && global.ty.content_type == wasmparser::ValType::I32,
            "Wasm stack pointer global has unexpected type"
        );
        global.init_expr_body = Cow::Owned(encode_i32_const_body(sp as i32));
    }

    let mut bytes_needed = u64::from(layout.data_end.max(layout.memory_base));
    if indices.stack_pointer_defined_slot.is_some() || needs_stack_gap {
        bytes_needed = bytes_needed.max(u64::from(stack_high_after_data(layout.data_end)?));
    }
    if bytes_needed > 0 && !layout.memories.is_empty() {
        let pages_needed = bytes_needed.div_ceil(65536).max(1);
        for memory in &mut layout.memories {
            memory.initial = memory.initial.max(pages_needed);
        }
    }
    Ok(())
}

fn linker_output_memory_type(inputs: &[WasmObjectLayoutInput<'_>]) -> MemoryType {
    let mut initial = 2u64;
    for input in inputs {
        for import in &input.memory_imports {
            initial = initial.max(import.ty.initial);
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

fn ensure_memory_export(exports: &mut Vec<OutputExport<'_>>) {
    if exports
        .iter()
        .any(|export| matches!(export.kind, wasmparser::ExternalKind::Memory))
    {
        return;
    }
    exports.push(OutputExport {
        name: "memory",
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
    let entry_name_bytes = symbol_db.entry_symbol_name();
    let Some(symbol_id) =
        symbol_db.get_unversioned(&UnversionedSymbolName::prehashed(entry_name_bytes))
    else {
        return Ok(None);
    };
    let def_id = symbol_db.definition(symbol_id);
    let def_file_id = symbol_db.file_id_for_symbol(def_id);

    let Some(def_obj_idx) = layout_inputs
        .iter()
        .position(|input| input.file_id == def_file_id)
    else {
        return Ok(None);
    };
    let def_input = &layout_inputs[def_obj_idx];
    let def_sym = &def_input.symbols[def_input.symbol_id_range.id_to_offset(def_id)];
    if def_sym.is_undefined() || def_sym.kind != WasmSymbolKind::Func {
        return Ok(None);
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

fn build_output_module_layout<'data, 'files>(
    groups: &'files [layout::GroupState<'data, Wasm>],
    symbol_db: &crate::symbol_db::SymbolDb<'data, Wasm>,
) -> Result<WasmLayout<'data>>
where
    'data: 'files,
{
    let objects_and_states: Vec<_> = layout::objects_iter(groups)
        .map(|state| (&state.object, &state.format_specific))
        .collect();
    let layout_inputs = objects_and_states
        .par_iter()
        .map(|(object, state)| {
            WasmObjectLayoutInput::from_file(object, state.symbol_id_range, state.file_id)
        })
        .collect::<Result<Vec<_>>>()?;

    let import_resolutions = resolve_cross_object_imports(&layout_inputs, symbol_db)?;
    let has_init_funcs = layout_inputs
        .iter()
        .any(|input| !input.init_funcs.is_empty());
    // Like wasm-ld, wrap only when InitFuncs exist and crt does not already call
    // `__wasm_call_ctors`.
    let wrap_entry = has_init_funcs
        && !call_ctors_used_in_objects(&layout_inputs)
        && entry_is_defined_function(&layout_inputs, symbol_db);
    let indices = LinkerDefinedIndices::compute(
        &layout_inputs,
        &import_resolutions,
        has_init_funcs,
        wrap_entry,
    )?;
    let index_bases =
        allocate_wasm_object_index_bases(&layout_inputs, &import_resolutions, &indices)?;
    let object_layouts = layout_inputs
        .par_iter()
        .zip(import_resolutions.par_iter())
        .enumerate()
        .map(|(obj_idx, (input, resolutions))| {
            input.build_object_output_layout(
                index_bases[obj_idx],
                resolutions,
                &index_bases,
                &indices,
            )
        })
        .collect::<Result<Vec<_>>>()?;

    let linker_memory = any_object_needs_linker_memory(&layout_inputs);
    let mut layout = WasmLayout {
        memory_base: if linker_memory || indices.memory_base_global.is_some() {
            LINKER_MEMORY_BASE
        } else {
            0
        },
        ..WasmLayout::default()
    };
    let mut memory_cursor = layout.memory_base;
    let mut section_cursor = 0u32;
    for (obj_idx, (input, object_layout)) in layout_inputs.iter().zip(object_layouts).enumerate() {
        layout.output_types.extend(object_layout.types);
        layout.imports.extend(object_layout.imports);
        layout
            .function_type_indices
            .extend(object_layout.function_type_indices);
        layout.globals.extend(object_layout.globals);
        layout.exports.extend(object_layout.exports);
        let mut bodies = object_layout.function_bodies;
        for body in &mut bodies {
            body.object_index = obj_idx;
        }
        layout.function_bodies.extend(bodies);
        layout.memories.extend(object_layout.memories);
        layout
            .unsupported_output
            .extend(object_layout.unsupported_output);
        layout.object_index_maps.push(object_layout.index_map);
        layout.per_object_symbols.push(input.symbols.clone());
        layout.object_data_layouts.push(layout_object_data(
            input,
            layout.object_index_maps.last().expect("index map pushed"),
            &mut memory_cursor,
            &mut section_cursor,
        )?);
    }

    let init_function_indices =
        collect_sorted_init_function_indices(&layout_inputs, &layout.object_index_maps)?;
    let call_ctors_body = indices
        .call_ctors_func
        .map(|_| encode_call_sequence_body(&init_function_indices));

    let entry = resolve_entry_function(&layout_inputs, &layout.object_index_maps, symbol_db)?;
    let entry_wrapper_body = match (indices.entry_wrapper_func, indices.call_ctors_func, &entry) {
        (Some(_), Some(ctors), Some(entry)) => {
            Some(encode_call_sequence_body(&[ctors, entry.function_index]))
        }
        _ => None,
    };

    emit_reserved_linker_definitions(&mut layout, &indices, call_ctors_body, entry_wrapper_body);
    deduplicate_output_types(&mut layout);

    if linker_memory && layout.memories.is_empty() {
        layout
            .memories
            .push(linker_output_memory_type(&layout_inputs));
        ensure_memory_export(&mut layout.exports);
    }
    layout.data_end = memory_cursor;
    let needs_stack_gap = compute_data_addresses(
        &mut layout.object_index_maps,
        &layout.per_object_symbols,
        &layout.object_data_layouts,
        &layout_inputs,
        symbol_db,
        layout.data_end,
    )?;
    fill_linker_defined_values(&mut layout, &indices, needs_stack_gap)?;
    ensure_entry_export(
        &mut layout.exports,
        entry.as_ref(),
        indices.entry_wrapper_func,
    );
    finalize_indirect_function_table(&mut layout, &layout_inputs)?;
    layout.encode_metadata_sections()?;
    Ok(layout)
}

fn is_table_index_relocation(ty: u8) -> bool {
    matches!(
        ty,
        reloc_type::TABLE_INDEX_SLEB | reloc_type::TABLE_INDEX_I32
    )
}

fn is_table_number_relocation(ty: u8) -> bool {
    ty == reloc_type::TABLE_NUMBER_LEB
}

/// Assign indirect-call table slots and synthesize `table` / `element` sections.
fn finalize_indirect_function_table(
    layout: &mut WasmLayout<'_>,
    layout_inputs: &[WasmObjectLayoutInput<'_>],
) -> Result {
    // Collect output function indices that must appear in the table.
    let mut needed: Vec<u32> = Vec::new();
    let mut seen = HashSet::new();
    let mut needs_table = layout_inputs
        .iter()
        .any(|input| !input.table_imports.is_empty());

    for (obj_idx, input) in layout_inputs.iter().enumerate() {
        let index_map = &layout.object_index_maps[obj_idx];
        let symbols = &input.symbols;
        for reloc in input
            .code_relocations
            .iter()
            .chain(input.data_relocations.iter())
        {
            if is_table_number_relocation(reloc.ty) {
                needs_table = true;
                continue;
            }
            if !is_table_index_relocation(reloc.ty) {
                continue;
            }
            needs_table = true;
            let sym = symbols.get(reloc.index as usize).ok_or_else(|| {
                crate::error!("table index relocation symbol {} out of range", reloc.index)
            })?;
            ensure!(
                sym.kind == WasmSymbolKind::Func,
                "R_WASM_TABLE_INDEX_* references non-function symbol"
            );
            let func_out = remap_wasm_index(&index_map.function_indices, sym.index, "function")?;
            if seen.insert(func_out) {
                needed.push(func_out);
            }
        }
    }

    if !needs_table {
        return Ok(());
    }

    // Slot 0 is unused and first function at slot 1. This matches common clang/wasm-ld layout.
    let max_func = layout
        .object_index_maps
        .iter()
        .flat_map(|m| m.function_indices.iter().copied())
        .max()
        .unwrap_or(0);
    let mut slots_by_func = vec![u32::MAX; max_func as usize + 1];

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
            initial = initial.max(imp.ty.initial);
            ensure!(
                imp.ty.element_type.is_func_ref(),
                "only funcref table imports are supported (got {:?})",
                imp.ty.element_type
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

fn is_memory_addr_relocation(ty: u8) -> bool {
    matches!(
        ty,
        reloc_type::MEMORY_ADDR_LEB
            | reloc_type::MEMORY_ADDR_SLEB
            | reloc_type::MEMORY_ADDR_I32
            | reloc_type::MEMORY_ADDR_REL_SLEB
    )
}

fn is_supported_data_relocation(ty: u8) -> bool {
    is_memory_addr_relocation(ty)
        || matches!(
            ty,
            reloc_type::FUNCTION_INDEX_I32
                | reloc_type::FUNCTION_INDEX_LEB
                | reloc_type::TABLE_INDEX_I32
                | reloc_type::TABLE_INDEX_SLEB
                | reloc_type::TABLE_NUMBER_LEB
                | reloc_type::GLOBAL_INDEX_I32
                | reloc_type::GLOBAL_INDEX_LEB
                | reloc_type::TYPE_INDEX_LEB
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

/// Apply addend policy. `R_WASM_MEMORY_ADDR_REL_SLEB` bases already include the addend.
pub(crate) fn finalize_reloc_value(reloc: &WasmRelocation, base: u32) -> Result<u32> {
    if reloc.ty == reloc_type::MEMORY_ADDR_REL_SLEB {
        Ok(base)
    } else {
        reloc_value_with_addend(base, reloc.addend)
    }
}

fn data_symbol_memory_address(
    object_data_layout: &WasmObjectDataLayout<'_>,
    sym: &WasmSymbol,
) -> Result<u32> {
    ensure!(
        sym.kind == WasmSymbolKind::Data,
        "memory address relocation references non-data symbol"
    );
    let segment = object_data_layout
        .segments
        .iter()
        .find(|segment| segment.segment_index == sym.index)
        .ok_or_else(|| crate::error!("Wasm data symbol segment {} not found", sym.index))?;
    segment
        .output_memory_offset
        .checked_add(sym.offset)
        .ok_or_else(|| crate::error!("Wasm data symbol address overflow"))
}

/// Result of resolving a linker-defined data symbol name.
#[derive(Debug, Clone, Copy)]
struct LinkerDefinedDataAddress {
    address: u32,
    /// True when the address assumes a stack reservation after static data.
    needs_stack_gap: bool,
}

/// Absolute addresses for linker-defined data symbols.
fn linker_defined_data_symbol_address(
    name: &[u8],
    data_end: u32,
) -> Result<Option<LinkerDefinedDataAddress>> {
    match name {
        b"__data_end" => Ok(Some(LinkerDefinedDataAddress {
            address: data_end,
            needs_stack_gap: false,
        })),
        b"__heap_base" => Ok(Some(LinkerDefinedDataAddress {
            address: stack_high_after_data(data_end)?,
            needs_stack_gap: true,
        })),
        _ => Ok(None),
    }
}

fn compute_data_addresses(
    object_index_maps: &mut [WasmObjectIndexMap],
    per_object_symbols: &[Vec<WasmSymbol>],
    object_data_layouts: &[WasmObjectDataLayout<'_>],
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    symbol_db: &SymbolDb<'_, Wasm>,
    data_end: u32,
) -> Result<bool> {
    let file_id_to_index: HashMap<crate::input_data::FileId, usize> = layout_inputs
        .iter()
        .enumerate()
        .map(|(i, input)| (input.file_id, i))
        .collect();

    // True if any synthesised address assumes a stack gap after static data (`__heap_base`).
    let mut needs_stack_gap = false;

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

            // Resolve to the canonical definition when this is an undefined reference.
            let (def_obj_idx, def_sym, name_symbol_id) = if sym.is_undefined() {
                let def_id = symbol_db.definition(symbol_id);
                let def_file_id = symbol_db.file_id_for_symbol(def_id);
                let Some(&def_obj_idx) = file_id_to_index.get(&def_file_id) else {
                    continue;
                };
                let def_input = &layout_inputs[def_obj_idx];
                let def_sym_offset = def_id.to_offset(def_input.symbol_id_range);
                (
                    def_obj_idx,
                    per_object_symbols[def_obj_idx][def_sym_offset],
                    def_id,
                )
            } else {
                (obj_idx, *sym, symbol_id)
            };

            if def_sym.is_undefined() {
                let name = symbol_db.symbol_name(name_symbol_id)?;
                if let Some(resolved) = linker_defined_data_symbol_address(name.bytes(), data_end)?
                {
                    needs_stack_gap |= resolved.needs_stack_gap;
                    data_addresses[sym_idx] = resolved.address;
                }
                continue;
            }

            data_addresses[sym_idx] =
                data_symbol_memory_address(&object_data_layouts[def_obj_idx], &def_sym)?;
        }
        index_map.data_addresses = data_addresses;
    }

    Ok(needs_stack_gap)
}

fn allocate_wasm_object_index_bases(
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    import_resolutions: &[ObjectImportResolutions],
    indices: &LinkerDefinedIndices,
) -> Result<Vec<WasmObjectIndexBases>> {
    let mut index_bases = Vec::with_capacity(layout_inputs.len());
    let mut next_type_index = 0u32;
    let mut next_function_import_index = 0u32;
    let mut next_global_import_index = 0u32;

    for (input, resolutions) in layout_inputs.iter().zip(import_resolutions) {
        index_bases.push(WasmObjectIndexBases {
            type_index_base: next_type_index,
            function_import_base: next_function_import_index,
            defined_function_base: 0,
            global_import_base: next_global_import_index,
            defined_global_base: 0,
            // Imported and defined memories are merged into a single output memory at index 0.
            memory_base: 0,
        });
        next_type_index = next_type_index
            .checked_add(u32::try_from(input.types.len()).context("too many Wasm types")?)
            .ok_or_else(|| crate::error!("Wasm type index overflow"))?;

        let absorption = LinkerImportAbsorption::for_object(input, resolutions);
        next_function_import_index = next_function_import_index
            .checked_add(remaining_unresolved_imports(
                resolutions.unresolved_function_count,
                absorption.absorbed_functions,
            )?)
            .ok_or_else(|| crate::error!("Wasm function index overflow"))?;
        next_global_import_index = next_global_import_index
            .checked_add(remaining_unresolved_imports(
                resolutions.unresolved_global_count,
                absorption.absorbed_globals,
            )?)
            .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
    }

    // Object-defined entities start after imports and any reserved linker-defined entities.
    let mut next_defined_function_index = next_function_import_index
        .checked_add(indices.num_defined_functions)
        .ok_or_else(|| crate::error!("Wasm function index overflow"))?;
    let mut next_defined_global_index = next_global_import_index
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
    indices
        .get(index as usize)
        .copied()
        .ok_or_else(|| crate::error!("Wasm {kind} index {index} out of range"))
}

fn wasm_index_range(base: u32, len: usize, kind: &str) -> Result<Vec<u32>> {
    let len = u32::try_from(len).with_context(|| format!("too many Wasm {kind}"))?;
    let end = base
        .checked_add(len)
        .ok_or_else(|| crate::error!("too many Wasm {kind}"))?;
    Ok((base..end).collect())
}

impl platform::Platform for Wasm {
    type File<'data> = File<'data>;
    type FileFlags = u32;
    type SymtabEntry = WasmSymbol;
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
    type RelocationInfo = u32;
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

    fn link_for_arch<'data>(
        linker: &'data crate::Linker,
        args: &'data Self::Args,
    ) -> crate::error::Result<crate::LinkerOutput<'data>> {
        if !cfg!(feature = "wasm") {
            bail!(
                "Wasm support is still experimental. Rebuild with `--features wasm` to enable it."
            );
        }

        linker.link_for_arch::<Wasm, crate::wasm_wasm32::WasmWasm32>(args)
    }

    fn write_output_file<'data, A: platform::Arch<Platform = Self>>(
        output: &crate::file_writer::Output,
        layout: &crate::layout::Layout<'data, Self>,
    ) -> crate::error::Result {
        output.write(layout, crate::wasm_writer::write::<A>)
    }

    fn section_attributes(header: &Self::SectionHeader) -> Self::SectionAttributes {
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
        memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> Self::GroupLayoutExt {
    }

    fn frame_data_base_address(
        memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> u64 {
        0
    }

    fn finalise_find_required_sections<'data>(
        groups: &mut [crate::layout::GroupState<Self>],
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) -> crate::error::Result {
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
        groups: &[crate::grouping::Group<'data, Self>],
    ) -> Self::LayoutResourcesExt<'data> {
    }

    fn load_object_section_relocations<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _state: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
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
                phdr_name: None,
                region_name: None,
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
        groups: &'files [layout::GroupState<'data, Self>],
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
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        eh_frame_section_index: object::SectionIndex,
        resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        queue: &mut crate::layout::LocalWorkQueue,
        scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        // Wasm doesn't have ELF-style `.eh_frame`.
        Ok(())
    }

    fn non_empty_section_loaded<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _unloaded: crate::resolution::UnloadedSection,
        _resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        _scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn new_epilogue_layout<'data>(
        args: &Self::Args,
        output_kind: crate::output_kind::OutputKind,
        dynamic_symbol_definitions: &mut [crate::layout::DynamicSymbolDefinition<'data, Self>],
        group_states: &[layout::GroupState<'data, Self>],
    ) -> Self::EpilogueLayoutExt {
    }

    fn apply_non_addressable_indexes_epilogue(
        counts: &mut Self::NonAddressableCounts,
        state: &mut Self::EpilogueLayoutExt,
    ) {
        // No-op: Wasm has no version table.
    }

    fn apply_non_addressable_indexes<'data, 'groups>(
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        counts: &Self::NonAddressableCounts,
        mem_sizes_iter: impl Iterator<
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
        verneed_table: &Self::VerneedTable<'data>,
        symbol_index: object::SymbolIndex,
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
        use crate::output_section_id as osid;

        let mut builder = crate::output_section_id::OutputOrderBuilder::<Self>::new(
            output_kind,
            output_sections,
            secondary,
            false,
            &[],
        );

        builder.add_section(osid::FILE_HEADER);
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

        builder.build()
    }

    fn default_symtab_entry() -> Self::SymtabEntry {
        WasmSymbol::default()
    }

    fn is_allowed_in_archive(kind: crate::file_kind::FileKind) -> bool {
        kind == crate::file_kind::FileKind::WasmObject
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
    let mut segments: Vec<WasmSegmentInfo<'data>> = Vec::new();
    let mut init_funcs: Vec<WasmInitFunc> = Vec::new();
    let mut reloc_sections: Vec<WasmRelocSection> = Vec::new();
    let mut linking_version: Option<u32> = None;
    let mut target_features_raw: Option<&'data [u8]> = None;
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
                    linking_version = Some(linking.version());
                    parse_linking_subsections(
                        input,
                        &linking,
                        &mut symbols,
                        &mut segments,
                        &mut init_funcs,
                    )?;
                }
            } else if section_name.starts_with(RELOC_SECTION_PREFIX) {
                if let KnownCustom::Reloc(reloc) = reader.as_known() {
                    let target_section_index = reloc.section_index();
                    let mut entries = Vec::new();
                    for entry in reloc.entries() {
                        entries.push(WasmRelocation::from_entry(entry?));
                    }
                    reloc_sections.push(WasmRelocSection {
                        target_section_index,
                        entries,
                    });
                }
            } else if section_name == TARGET_FEATURES_SECTION_NAME {
                target_features_raw = Some(reader.data());
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

    Ok(File {
        data: input,
        version,
        sections,
        standard_section_index,
        symbols,
        segments,
        init_funcs,
        reloc_sections,
        linking_version,
        target_features_raw,
    })
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
    segments: &mut Vec<WasmSegmentInfo<'data>>,
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
                    segments.push(WasmSegmentInfo {
                        name: seg.name,
                        alignment: Alignment::from_exponent(seg.alignment)?,
                        flags: seg.flags,
                    });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linker_defined_heap_base_requires_stack_gap() {
        let data_end = 1024u32;
        let de = linker_defined_data_symbol_address(b"__data_end", data_end)
            .unwrap()
            .expect("__data_end");
        assert_eq!(de.address, data_end);
        assert!(
            !de.needs_stack_gap,
            "`__data_end` is the end of static data. It must not force a stack reservation"
        );

        let hb = linker_defined_data_symbol_address(b"__heap_base", data_end)
            .unwrap()
            .expect("__heap_base");
        assert_eq!(hb.address, stack_high_after_data(data_end).unwrap());
        assert!(
            hb.needs_stack_gap,
            "`__heap_base` sits past the stack gap, so memory must cover that range"
        );
    }

    #[test]
    fn stack_high_is_sixteen_byte_aligned() {
        // Unaligned data_end must still yield a 16-byte-aligned stack top (wasm-ld).
        for data_end in [1u32, 2, 7, 1025, 4738] {
            let sp = stack_high_after_data(data_end).unwrap();
            assert_eq!(sp % 16, 0, "data_end={data_end} sp={sp}");
            assert!(sp >= data_end + LINKER_STACK_SIZE);
        }
    }

    #[test]
    fn needs_stack_gap_grows_memory_that_would_not_cover_heap_base() {
        // Default freestanding links often already request 2 pages, which hides a missing
        // needs_stack_gap. Therefore start from a 1-page memory so the grow path is observable.
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
        let indices = LinkerDefinedIndices::default();

        fill_linker_defined_values(&mut layout, &indices, false).unwrap();
        assert_eq!(
            layout.memories[0].initial, 1,
            "without `needs_stack_gap`, a 1-page memory must stay 1 page"
        );

        fill_linker_defined_values(&mut layout, &indices, true).unwrap();
        let bytes_needed = u64::from(data_end) + u64::from(LINKER_STACK_SIZE);
        let pages_needed = bytes_needed.div_ceil(65536);
        assert_eq!(
            layout.memories[0].initial, pages_needed,
            "`needs_stack_gap` must grow memory to cover `data_end` + `LINKER_STACK_SIZE`"
        );
        assert!(pages_needed > 1);
    }
}
