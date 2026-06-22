// TODO
#![allow(unused)]

use crate::alignment::Alignment;
use crate::args::wasm::WasmArgs;
use crate::bail;
use crate::ensure;
use crate::error::Context as _;
use crate::error::Result;
use crate::layout;
use crate::layout::ImportedSymbol;
use crate::layout_rules::SectionKind;
use crate::output_section_id::SectionName;
use crate::platform;
use crate::wasm_writer::OutputExport;
use crate::wasm_writer::OutputGlobal;
use crate::wasm_writer::OutputImport;
use crate::wasm_writer::OutputImportEntity;
use hashbrown::HashMap;
use leb128::write::unsigned_len as uleb128_size;
use linker_utils::utils::u32_from_slice;
use rayon::prelude::*;
use std::ops::Range;
use wasmparser::BinaryReader;
use wasmparser::CodeSectionReader;
use wasmparser::ConstExpr;
use wasmparser::DataKind;
use wasmparser::DataSectionReader;
use wasmparser::ExportSectionReader;
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

    #[debug(skip)]
    pub(crate) reloc_sections: Vec<WasmRelocSection>,

    pub(crate) linking_version: Option<u32>,

    /// Raw payload of the `target_features` custom section, if present.
    #[debug(skip)]
    pub(crate) target_features_raw: Option<&'data [u8]>,
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
        reloc_type::TABLE_INDEX_SLEB | reloc_type::MEMORY_ADDR_SLEB => {
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
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ResolvedCodeReloc {
    /// Byte offset within the body's bytes where the relocation should be applied.
    pub(crate) offset: u32,
    /// Wasm relocation type code.
    pub(crate) ty: u8,
    /// Resolved output value to write at the relocation site.
    pub(crate) value: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct WasmFunctionBody<'data> {
    /// Raw body bytes (locals + operators) without the LEB128 size prefix.
    pub(crate) bytes: &'data [u8],
    /// Byte offset of this body (starting at its size prefix) within the code section payload.
    pub(crate) code_offset: u32,
    pub(crate) relocations: Vec<ResolvedCodeReloc>,
}

impl<'data> File<'data> {
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
                        bytes: &self.data[range.clone()],
                        code_offset: range.start as u32 - code_payload_start,
                        relocations: Vec::new(),
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

        reader
            .into_iter()
            .map(|res| {
                res.map(|d| WasmDataSegment {
                    kind: d.kind,
                    data: d.data,
                })
                .map_err(Into::into)
            })
            .collect()
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
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        _index: object::SymbolIndex,
    ) -> crate::error::Result<Option<object::SectionIndex>> {
        if symbol.is_undefined() {
            return Ok(None);
        }
        // Map each symbol kind to the wasm section that holds its definition.
        let std_id: u8 = match symbol.kind {
            WasmSymbolKind::Func => section_id::CODE,
            WasmSymbolKind::Data => section_id::DATA,
            WasmSymbolKind::Global => section_id::GLOBAL,
            WasmSymbolKind::Table => section_id::TABLE,
            WasmSymbolKind::Event | WasmSymbolKind::Null => return Ok(None),
            WasmSymbolKind::Section => {
                return Ok(self
                    .sections
                    .get(symbol.index as usize)
                    .map(|_| object::SectionIndex(symbol.index as usize)));
            }
        };
        Ok(self.standard_section_index[std_id as usize].map(|i| object::SectionIndex(i as usize)))
    }

    fn symbol_versions(&self) -> &[<Self::Platform as platform::Platform>::SymbolVersionIndex] {
        // Wasm doesn't have ELF-style symbol versioning.
        &[]
    }

    fn dynamic_symbol_used(
        &self,
        _symbol_index: object::SymbolIndex,
        _state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
    ) -> crate::error::Result {
        // Wasm has no dynamic objects yet.
        Ok(())
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
    pub(crate) unsupported_output: Vec<&'static str>,
    pub(crate) object_index_maps: Vec<WasmObjectIndexMap>,
    pub(crate) encoded_sections: WasmEncodedSections,
    pub(crate) code_section_size: u64,
}

#[derive(Debug, Default)]
pub(crate) struct WasmEncodedSections {
    pub(crate) ty: Option<Vec<u8>>,
    pub(crate) import: Option<Vec<u8>>,
    pub(crate) function: Option<Vec<u8>>,
    pub(crate) global: Option<Vec<u8>>,
    pub(crate) export: Option<Vec<u8>>,
    pub(crate) memory: Option<Vec<u8>>,
}

impl WasmEncodedSections {
    fn add_sizes_to(&self, sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>) {
        add_encoded_section_size(sizes, crate::part_id::WASM_TYPE, self.ty.as_ref());
        add_encoded_section_size(sizes, crate::part_id::WASM_IMPORT, self.import.as_ref());
        add_encoded_section_size(sizes, crate::part_id::WASM_FUNCTION, self.function.as_ref());
        add_encoded_section_size(sizes, crate::part_id::WASM_GLOBAL, self.global.as_ref());
        add_encoded_section_size(sizes, crate::part_id::WASM_EXPORT, self.export.as_ref());
        add_encoded_section_size(sizes, crate::part_id::WASM_MEMORY, self.memory.as_ref());
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

        self.code_section_size = compute_code_section_size(&self.function_bodies);

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
    pub(crate) type_index_base: u32,
    pub(crate) function_indices: Vec<u32>,
    pub(crate) global_indices: Vec<u32>,
    pub(crate) memory_indices: Vec<u32>,
}

impl WasmObjectIndexMap {
    /// Resolve a code relocation to its output value using the symbol table from the same object.
    pub(crate) fn resolve_reloc(
        &self,
        reloc: &WasmRelocation,
        symbols: &[WasmSymbol],
    ) -> Result<u32> {
        if reloc.ty == R_WASM_TYPE_INDEX_LEB {
            return self
                .type_index_base
                .checked_add(reloc.index)
                .ok_or_else(|| crate::error!("Wasm type index overflow"));
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
                bail!("table relocations are not supported yet");
            }
            reloc_type::MEMORY_ADDR_LEB
            | reloc_type::MEMORY_ADDR_SLEB
            | reloc_type::MEMORY_ADDR_I32 => {
                bail!("memory address relocations are not supported yet");
            }
            reloc_type::TABLE_INDEX_SLEB | reloc_type::TABLE_INDEX_I32 => {
                bail!("table index relocations are not supported yet");
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
    module_functions: Vec<WasmModuleFunction>,
    globals: Vec<OutputGlobal<'data>>,
    exports: Vec<OutputExport<'data>>,
    function_bodies: Vec<WasmFunctionBody<'data>>,
    memories: Vec<MemoryType>,
    unsupported_output: Vec<&'static str>,
    code_relocations: Vec<WasmRelocation>,
    symbols: Vec<WasmSymbol>,
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
                    TypeRef::Table(_) => bail!("Wasm table imports are not emitted"),
                    TypeRef::Memory(_) => bail!("Wasm memory imports are not emitted"),
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

        let has_non_code_relocs = file
            .reloc_sections
            .iter()
            .any(|s| code_section_index != Some(s.target_section_index));

        let mut unsupported_output = Vec::new();
        if has_non_code_relocs {
            unsupported_output.push("non-code relocation");
        }
        if file.standard_section_index[section_id::TABLE as usize].is_some() {
            unsupported_output.push("table");
        }
        if file.standard_section_index[section_id::ELEMENT as usize].is_some() {
            unsupported_output.push("element");
        }
        if file.standard_section_index[section_id::START as usize].is_some() {
            unsupported_output.push("start");
        }
        if file.standard_section_index[section_id::DATA_COUNT as usize].is_some() {
            unsupported_output.push("data_count");
        }
        if file.standard_section_index[section_id::DATA as usize].is_some() {
            unsupported_output.push("data");
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
                    init_expr_body,
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
            module_functions,
            globals,
            exports,
            function_bodies,
            memories,
            unsupported_output,
            code_relocations,
            symbols: file.symbols.clone(),
            symbol_id_range,
            file_id,
        })
    }

    fn into_output_layout(
        self,
        index_bases: WasmObjectIndexBases,
        resolutions: &ObjectImportResolutions,
        all_index_bases: &[WasmObjectIndexBases],
    ) -> Result<WasmObjectOutputLayout<'data>> {
        ensure!(
            resolutions.function_resolutions.len() == self.function_imports.len(),
            "Wasm function import resolution count mismatch"
        );
        ensure!(
            resolutions.global_resolutions.len() == self.global_imports.len(),
            "Wasm global import resolution count mismatch"
        );

        let mut index_map = WasmObjectIndexMap {
            type_index_base: index_bases.type_index_base,
            function_indices: Vec::with_capacity(
                self.function_imports.len() + self.module_functions.len(),
            ),
            global_indices: Vec::with_capacity(self.global_imports.len() + self.globals.len()),
            memory_indices: Vec::with_capacity(self.memories.len()),
        };

        let mut imports =
            Vec::with_capacity(self.function_imports.len() + self.global_imports.len());
        let mut unresolved_func_count = 0u32;
        for (i, import) in self.function_imports.iter().enumerate() {
            match resolutions.function_resolutions[i] {
                ImportResolution::Unresolved => {
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

        index_map.memory_indices =
            wasm_index_range(index_bases.memory_base, self.memories.len(), "memories")?;

        let exports = self
            .exports
            .into_iter()
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
                    wasmparser::ExternalKind::Table => bail!("Wasm table exports are not emitted"),
                    wasmparser::ExternalKind::Tag => bail!("Wasm tag exports are not emitted"),
                };
                Ok(OutputExport { index, ..export })
            })
            .collect::<Result<Vec<_>>>()?;

        let mut function_bodies = self.function_bodies;
        resolve_code_relocations(
            &mut function_bodies,
            &self.code_relocations,
            &self.symbols,
            &index_map,
        )?;

        Ok(WasmObjectOutputLayout {
            types: self.types,
            imports,
            function_type_indices,
            globals: self.globals,
            exports,
            function_bodies,
            memories: self.memories,
            unsupported_output: self.unsupported_output,
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
    let index_bases = allocate_wasm_object_index_bases(&layout_inputs, &import_resolutions)?;
    let object_layouts = layout_inputs
        .into_par_iter()
        .zip(import_resolutions.par_iter())
        .enumerate()
        .map(|(obj_idx, (input, resolutions))| {
            input.into_output_layout(index_bases[obj_idx], resolutions, &index_bases)
        })
        .collect::<Result<Vec<_>>>()?;

    let mut layout = WasmLayout::default();
    for object_layout in object_layouts {
        layout.output_types.extend(object_layout.types);
        layout.imports.extend(object_layout.imports);
        layout
            .function_type_indices
            .extend(object_layout.function_type_indices);
        layout.globals.extend(object_layout.globals);
        layout.exports.extend(object_layout.exports);
        layout.function_bodies.extend(object_layout.function_bodies);
        layout.memories.extend(object_layout.memories);
        layout
            .unsupported_output
            .extend(object_layout.unsupported_output);
        layout.object_index_maps.push(object_layout.index_map);
    }
    layout.encode_metadata_sections()?;
    Ok(layout)
}

fn allocate_wasm_object_index_bases(
    layout_inputs: &[WasmObjectLayoutInput<'_>],
    import_resolutions: &[ObjectImportResolutions],
) -> Result<Vec<WasmObjectIndexBases>> {
    let mut index_bases = Vec::with_capacity(layout_inputs.len());
    let mut next_type_index = 0u32;
    let mut next_function_import_index = 0u32;
    let mut next_global_import_index = 0u32;
    let mut next_memory_index = 0u32;

    for (input, resolutions) in layout_inputs.iter().zip(import_resolutions) {
        index_bases.push(WasmObjectIndexBases {
            type_index_base: next_type_index,
            function_import_base: next_function_import_index,
            defined_function_base: 0,
            global_import_base: next_global_import_index,
            defined_global_base: 0,
            memory_base: next_memory_index,
        });
        next_type_index = next_type_index
            .checked_add(u32::try_from(input.types.len()).context("too many Wasm types")?)
            .ok_or_else(|| crate::error!("Wasm type index overflow"))?;
        next_function_import_index = next_function_import_index
            .checked_add(resolutions.unresolved_function_count)
            .ok_or_else(|| crate::error!("Wasm function index overflow"))?;
        next_global_import_index = next_global_import_index
            .checked_add(resolutions.unresolved_global_count)
            .ok_or_else(|| crate::error!("Wasm global index overflow"))?;
        next_memory_index = next_memory_index
            .checked_add(u32::try_from(input.memories.len()).context("too many Wasm memories")?)
            .ok_or_else(|| crate::error!("Wasm memory index overflow"))?;
    }

    let mut next_defined_function_index = next_function_import_index;
    let mut next_defined_global_index = next_global_import_index;
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

fn resolve_code_relocations<'data>(
    bodies: &mut [WasmFunctionBody<'data>],
    relocs: &[WasmRelocation],
    symbols: &[WasmSymbol],
    index_map: &WasmObjectIndexMap,
) -> Result {
    if relocs.is_empty() {
        return Ok(());
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
                let value = index_map.resolve_reloc(reloc, symbols)?;
                body.relocations.push(ResolvedCodeReloc {
                    offset: reloc.offset - body_start,
                    ty: reloc.ty,
                    value,
                });
            }
        }
    }

    Ok(())
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
    ) -> crate::error::Result<Self::DynamicLayoutExt<'data>> {
        Ok(())
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
        output_kind: crate::output_kind::OutputKind,
        args: &Self::Args,
    ) {
        // TODO: emit `__heap_base`, `__data_end`, `__stack_pointer`, etc.
    }

    fn built_in_section_infos<'data>()
    -> Vec<crate::output_section_id::SectionOutputInfo<'data, Self>> {
        SECTION_DEFINITIONS
            .iter()
            .map(|d| crate::output_section_id::SectionOutputInfo {
                section_attributes: SectionAttributes::default(),
                kind: d.kind,
                min_alignment: crate::alignment::MIN,
                location: None,
                load_location: None,
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
    }

    fn finalise_sizes_all<'data>(
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
    }

    fn apply_late_size_adjustments_epilogue(
        state: &mut Self::EpilogueLayoutExt,
        current_sizes: &crate::output_section_part_map::OutputSectionPartMap<u64>,
        extra_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
        imported_symbols: &[ImportedSymbol],
        args: &Self::Args,
    ) -> crate::error::Result {
        Ok(())
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

    fn allocate_header_sizes(
        _prelude: &mut crate::layout::PreludeLayoutState<Self>,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _header_info: &crate::layout::HeaderInfo,
        _output_sections: &crate::output_section_id::OutputSections<Self>,
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
        raw_value: layout::ResolutionState,
        dynamic_symbol_index: Option<std::num::NonZeroU32>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
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

    fn default_layout_rules(_args: &Self::Args) -> Vec<crate::layout_rules::SectionRule<'static>> {
        Vec::new()
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
                    parse_linking_subsections(input, &linking, &mut symbols, &mut segments)?;
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
            // `InitFuncs`, `ComdatInfo`, and `Unknown` subsections are not consumed.
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
