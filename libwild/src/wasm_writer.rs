use crate::bail;
use crate::ensure;
use crate::error::Context as _;
use crate::error::Result;
use crate::file_writer::SizedOutput;
use crate::file_writer::split_output_into_sections;
use crate::layout::Layout;
use crate::platform::Arch;
use crate::timing_phase;
use crate::verbose_timing_phase;
use crate::wasm::WASM_MAGIC;
use crate::wasm::WASM_VERSION;
use crate::wasm::Wasm;
use crate::wasm::WasmLayout;
use crate::wasm::WasmObjectIndexMap;
use crate::wasm::WasmRelocation;
use crate::wasm::WasmSymbol;
use crate::wasm::apply_relocation;
use crate::wasm::finalize_reloc_value;
use crate::wasm::section_id;
use crate::wasm::write_uleb128;
use leb128::write::unsigned_len as uleb128_size;
use std::borrow::Cow;
use wasm_encoder::ConstExpr;
use wasm_encoder::DataSection;
use wasm_encoder::ElementSection;
use wasm_encoder::Elements;
use wasm_encoder::ExportSection;
use wasm_encoder::FunctionSection;
use wasm_encoder::GlobalSection;
use wasm_encoder::ImportSection;
use wasm_encoder::MemorySection;
use wasm_encoder::Section;
use wasm_encoder::TableSection;
use wasm_encoder::TypeSection;

fn apply_resolved_reloc(
    index_map: &WasmObjectIndexMap,
    reloc: &WasmRelocation,
    symbols: &[WasmSymbol],
    function_table_slots: &[u32],
    memory_base: u32,
    buf: &mut [u8],
) -> Result<()> {
    let base = index_map.resolve_reloc(reloc, symbols, function_table_slots, memory_base)?;
    apply_relocation(buf, reloc, finalize_reloc_value(reloc, base)?)
}

pub(crate) fn write<'data, A: Arch<Platform = Wasm>>(
    sized_output: &mut SizedOutput,
    layout: &Layout<'data, Wasm>,
) -> Result<()> {
    timing_phase!("Write Wasm output");
    let (mut section_buffers, mut padding) =
        split_output_into_sections(layout, &mut sized_output.out);
    padding.fill_zero();

    let preamble = section_buffers
        .get_mut(crate::output_section_id::FILE_HEADER)
        .get_mut(..8)
        .ok_or_else(|| crate::error!("Wasm output buffer is shorter than the 8-byte preamble"))?;
    preamble[..4].copy_from_slice(&WASM_MAGIC);
    preamble[4..8].copy_from_slice(&WASM_VERSION.to_le_bytes());

    if let Some(unsupported) = layout.format_specific.unsupported_output.first() {
        bail!("Wasm {unsupported} emission is not implemented yet");
    }

    {
        timing_phase!("Copy Wasm metadata sections");
        copy_metadata_sections(&layout.format_specific, &mut section_buffers)?;
    }
    {
        timing_phase!("Write Wasm code section");
        write_code_section(
            &layout.format_specific,
            section_buffers.get_mut(crate::output_section_id::WASM_CODE),
        )?;
    }
    {
        timing_phase!("Write Wasm data section");
        write_data_section(
            &layout.format_specific,
            section_buffers.get_mut(crate::output_section_id::WASM_DATA),
        )?;
    }

    Ok(())
}

fn copy_metadata_sections(
    layout: &WasmLayout<'_>,
    section_buffers: &mut crate::output_section_map::OutputSectionMap<&mut [u8]>,
) -> Result<()> {
    let encoded = &layout.encoded_sections;
    copy_encoded_section(
        encoded.ty.as_ref(),
        section_buffers.get_mut(crate::output_section_id::WASM_TYPE),
    )?;
    copy_encoded_section(
        encoded.import.as_ref(),
        section_buffers.get_mut(crate::output_section_id::WASM_IMPORT),
    )?;
    copy_encoded_section(
        encoded.function.as_ref(),
        section_buffers.get_mut(crate::output_section_id::WASM_FUNCTION),
    )?;
    copy_encoded_section(
        encoded.table.as_ref(),
        section_buffers.get_mut(crate::output_section_id::WASM_TABLE),
    )?;
    copy_encoded_section(
        encoded.memory.as_ref(),
        section_buffers.get_mut(crate::output_section_id::WASM_MEMORY),
    )?;
    copy_encoded_section(
        encoded.global.as_ref(),
        section_buffers.get_mut(crate::output_section_id::WASM_GLOBAL),
    )?;
    copy_encoded_section(
        encoded.export.as_ref(),
        section_buffers.get_mut(crate::output_section_id::WASM_EXPORT),
    )?;
    copy_encoded_section(
        encoded.element.as_ref(),
        section_buffers.get_mut(crate::output_section_id::WASM_ELEMENT),
    )?;
    Ok(())
}

fn copy_encoded_section(encoded: Option<&Vec<u8>>, out: &mut [u8]) -> Result<()> {
    match encoded {
        Some(encoded) => {
            ensure!(
                out.len() == encoded.len(),
                "Wasm metadata section size allocated {}, encoded {}",
                out.len(),
                encoded.len()
            );
            out.copy_from_slice(encoded);
        }
        None => {
            ensure!(
                out.is_empty(),
                "Wasm metadata section unexpectedly allocated {} bytes",
                out.len()
            );
        }
    }
    Ok(())
}

// Each `WasmFunctionBody.bytes` is the raw body content (locals + operators) without a size prefix.
// This function writes the LEB128 size prefix for each body, then resolves and applies relocations.
fn write_code_section(wasm_layout: &WasmLayout<'_>, out: &mut [u8]) -> Result<()> {
    verbose_timing_phase!("Apply Wasm code relocations");
    let bodies = &wasm_layout.function_bodies;
    let object_index_maps = &wasm_layout.object_index_maps;
    let per_object_symbols = &wasm_layout.per_object_symbols;
    let function_table_slots = &wasm_layout.function_table_slots;

    if bodies.is_empty() {
        ensure!(
            out.is_empty(),
            "Wasm code section buffer is {} bytes but no bodies to write",
            out.len()
        );
        return Ok(());
    }

    let mut pos = 0;

    // Section id.
    out[pos] = section_id::CODE;
    pos += 1;

    let count = bodies.len() as u64;
    // Compute payload size: count LEB + sum(body_size_leb + body_bytes) for each body.
    let count_leb_size = uleb128_size(count);
    let bodies_with_prefix_total: usize = bodies
        .iter()
        .map(|b| {
            let body_len = b.bytes.len() as u64;
            uleb128_size(body_len) + b.bytes.len()
        })
        .sum();
    let payload_size = (count_leb_size + bodies_with_prefix_total) as u64;

    pos += write_uleb128(&mut out[pos..], payload_size);

    // Body count as LEB128.
    pos += write_uleb128(&mut out[pos..], count);

    for body in bodies {
        let body_len = body.bytes.len() as u64;
        pos += write_uleb128(&mut out[pos..], body_len);
        let body_start = pos;
        let len = body.bytes.len();
        out[pos..pos + len].copy_from_slice(&body.bytes);
        let index_map = &object_index_maps[body.object_index];
        let symbols = &per_object_symbols[body.object_index];
        for reloc in &body.relocations {
            apply_resolved_reloc(
                index_map,
                reloc,
                symbols,
                function_table_slots,
                wasm_layout.memory_base,
                &mut out[body_start..body_start + len],
            )?;
        }
        pos += len;
    }

    ensure!(
        pos == out.len(),
        "Wasm code section wrote {} bytes but buffer is {} bytes",
        pos,
        out.len()
    );

    Ok(())
}

fn write_data_section(wasm_layout: &WasmLayout<'_>, out: &mut [u8]) -> Result<()> {
    verbose_timing_phase!("Encode Wasm data section");
    let object_data_layouts = &wasm_layout.object_data_layouts;
    let has_segments = object_data_layouts
        .iter()
        .any(|object| !object.segments.is_empty());
    if !has_segments {
        ensure!(
            out.is_empty(),
            "Wasm data section buffer is {} bytes but no segments to write",
            out.len()
        );
        return Ok(());
    }

    let section = build_data_section(wasm_layout)?;
    let mut encoded = Vec::new();
    section.append_to(&mut encoded);
    ensure!(
        out.len() == encoded.len(),
        "Wasm data section wrote {} bytes but buffer is {} bytes",
        encoded.len(),
        out.len()
    );
    out.copy_from_slice(&encoded);
    Ok(())
}

/// Build a `type` section from a list of function types in output order. Callers must have
/// already done dedup across input modules.
pub(crate) fn build_type_section(types: &[wasmparser::FuncType]) -> Result<TypeSection> {
    let mut section = TypeSection::new();
    for ty in types {
        let params: Vec<wasm_encoder::ValType> = ty
            .params()
            .iter()
            .copied()
            .map(convert_val_type)
            .collect::<Result<_>>()?;
        let results: Vec<wasm_encoder::ValType> = ty
            .results()
            .iter()
            .copied()
            .map(convert_val_type)
            .collect::<Result<_>>()?;
        section.ty().function(params, results);
    }
    Ok(section)
}

/// Build an `import` section. `type_index` for function imports must be the output type index.
pub(crate) fn build_import_section(imports: &[OutputImport<'_>]) -> Result<ImportSection> {
    let mut section = ImportSection::new();
    for import in imports {
        let entity = match import.entity {
            OutputImportEntity::Function { type_index } => {
                wasm_encoder::EntityType::Function(type_index)
            }
            OutputImportEntity::Global(ty) => {
                wasm_encoder::EntityType::Global(convert_global_type(ty)?)
            }
        };
        section.import(import.module, import.name, entity);
    }
    Ok(section)
}

/// Build a `function` section. Each entry is the (output) type index of a module-defined
/// function, in `code` section order.
pub(crate) fn build_function_section(type_indices: &[u32]) -> FunctionSection {
    let mut section = FunctionSection::new();
    for &type_index in type_indices {
        section.function(type_index);
    }
    section
}

/// Build a `global` section from `(type, init_expr_bytes)` pairs. The init-expr bytes are the
/// raw const-expression bytes from the input *without* the trailing `end` opcode; the encoder
/// re-appends `end` itself.
pub(crate) fn build_global_section(globals: &[OutputGlobal<'_>]) -> Result<GlobalSection> {
    let mut section = GlobalSection::new();
    for global in globals {
        let init_expr = wasm_encoder::ConstExpr::raw(global.init_expr_body.iter().copied());
        section.global(convert_global_type(global.ty)?, &init_expr);
    }
    Ok(section)
}

pub(crate) fn build_data_section(wasm_layout: &WasmLayout<'_>) -> Result<DataSection> {
    let mut section = DataSection::new();
    for (obj_idx, object_layout) in wasm_layout.object_data_layouts.iter().enumerate() {
        let index_map = &wasm_layout.object_index_maps[obj_idx];
        let symbols = &wasm_layout.per_object_symbols[obj_idx];
        for segment in &object_layout.segments {
            let mut payload = segment.data.to_vec();
            for reloc in &segment.relocations {
                apply_resolved_reloc(
                    index_map,
                    reloc,
                    symbols,
                    &wasm_layout.function_table_slots,
                    wasm_layout.memory_base,
                    &mut payload,
                )?;
            }
            let offset = ConstExpr::i32_const(
                i32::try_from(segment.output_memory_offset).with_context(|| {
                    format!(
                        "Wasm data segment memory offset {}",
                        segment.output_memory_offset
                    )
                })?,
            );
            section.active(
                segment.output_memory_index,
                &offset,
                payload.iter().copied(),
            );
        }
    }
    Ok(section)
}

pub(crate) fn build_table_section(tables: &[wasmparser::TableType]) -> Result<TableSection> {
    let mut section = TableSection::new();
    for &table in tables {
        ensure!(
            table.element_type.is_func_ref(),
            "only funcref tables are supported (got {:?})",
            table.element_type
        );
        section.table(wasm_encoder::TableType {
            element_type: wasm_encoder::RefType::FUNCREF,
            minimum: table.initial,
            maximum: table.maximum,
            table64: table.table64,
            shared: table.shared,
        });
    }
    Ok(section)
}

/// One active element segment on table 0 at offset 1 (functions occupy slots 1..).
pub(crate) fn build_element_section(element_functions: &[u32]) -> ElementSection {
    let mut section = ElementSection::new();
    if element_functions.is_empty() {
        return section;
    }
    let offset = ConstExpr::i32_const(1);
    section.active(
        Some(0),
        &offset,
        Elements::Functions(std::borrow::Cow::Borrowed(element_functions)),
    );
    section
}

pub(crate) fn build_memory_section(memories: &[wasmparser::MemoryType]) -> MemorySection {
    let mut section = MemorySection::new();
    for &memory in memories {
        section.memory(convert_memory_type(memory));
    }
    section
}

/// Build an `export` section.
pub(crate) fn build_export_section(exports: &[OutputExport<'_>]) -> ExportSection {
    let mut section = ExportSection::new();
    for export in exports {
        section.export(export.name, convert_export_kind(export.kind), export.index);
    }
    section
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct OutputImport<'a> {
    pub(crate) module: &'a str,
    pub(crate) name: &'a str,
    pub(crate) entity: OutputImportEntity,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum OutputImportEntity {
    Function { type_index: u32 },
    Global(wasmparser::GlobalType),
}

#[derive(Debug, Clone)]
pub(crate) struct OutputGlobal<'a> {
    pub(crate) ty: wasmparser::GlobalType,
    /// Const-expression body without the trailing `end` opcode.
    pub(crate) init_expr_body: Cow<'a, [u8]>,
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct OutputExport<'a> {
    pub(crate) name: &'a str,
    pub(crate) kind: wasmparser::ExternalKind,
    pub(crate) index: u32,
}

/// Strip the trailing `end` (0x0b) opcode from a wasmparser-parsed const expression so the
/// bytes are suitable for `wasm_encoder::ConstExpr::raw`. Returns `None` if the buffer doesn't
/// terminate with `end`, which would indicate a malformed input.
pub(crate) fn const_expr_body<'a>(expr: &wasmparser::ConstExpr<'a>) -> Option<&'a [u8]> {
    let mut reader = expr.get_binary_reader();
    let n = reader.bytes_remaining();
    let bytes = reader.read_bytes(n).ok()?;
    bytes.strip_suffix(&[0x0b])
}

fn convert_val_type(t: wasmparser::ValType) -> Result<wasm_encoder::ValType> {
    Ok(match t {
        wasmparser::ValType::I32 => wasm_encoder::ValType::I32,
        wasmparser::ValType::I64 => wasm_encoder::ValType::I64,
        wasmparser::ValType::F32 => wasm_encoder::ValType::F32,
        wasmparser::ValType::F64 => wasm_encoder::ValType::F64,
        wasmparser::ValType::V128 => bail!("V128 value type is not supported yet"),
        wasmparser::ValType::Ref(_) => bail!("reference value types are not supported yet"),
    })
}

fn convert_global_type(t: wasmparser::GlobalType) -> Result<wasm_encoder::GlobalType> {
    Ok(wasm_encoder::GlobalType {
        val_type: convert_val_type(t.content_type)?,
        mutable: t.mutable,
        shared: t.shared,
    })
}

fn convert_memory_type(t: wasmparser::MemoryType) -> wasm_encoder::MemoryType {
    wasm_encoder::MemoryType {
        minimum: t.initial,
        maximum: t.maximum,
        memory64: t.memory64,
        shared: t.shared,
        page_size_log2: t.page_size_log2,
    }
}

fn convert_export_kind(k: wasmparser::ExternalKind) -> wasm_encoder::ExportKind {
    match k {
        wasmparser::ExternalKind::Func | wasmparser::ExternalKind::FuncExact => {
            wasm_encoder::ExportKind::Func
        }
        wasmparser::ExternalKind::Table => wasm_encoder::ExportKind::Table,
        wasmparser::ExternalKind::Memory => wasm_encoder::ExportKind::Memory,
        wasmparser::ExternalKind::Global => wasm_encoder::ExportKind::Global,
        wasmparser::ExternalKind::Tag => wasm_encoder::ExportKind::Tag,
    }
}
