use crate::OutputFileData;
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
use crate::wasm::WasmDataSegmentLayout;
use crate::wasm::WasmFunctionBody;
use crate::wasm::WasmLayout;
use crate::wasm::WasmObjectIndexMap;
use crate::wasm::WasmRelocation;
use crate::wasm::WasmSymbol;
use crate::wasm::apply_relocation;
use crate::wasm::finalize_reloc_value;
use crate::wasm::output_section_id;
use crate::wasm::section_id;
use crate::wasm::write_sleb128;
use crate::wasm::write_uleb128;
use leb128::write::unsigned_len as uleb128_size;
use rayon::prelude::*;
use std::borrow::Cow;
use std::ops::Range;
use wasm_encoder::ConstExpr;
use wasm_encoder::ElementSection;
use wasm_encoder::Elements;
use wasm_encoder::ExportSection;
use wasm_encoder::FunctionSection;
use wasm_encoder::GlobalSection;
use wasm_encoder::ImportSection;
use wasm_encoder::MemorySection;
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

fn relocs_in_index_range(relocs: &[WasmRelocation], range: Range<u32>) -> &[WasmRelocation] {
    let start = range.start as usize;
    let end = range.end as usize;
    relocs.get(start..end).unwrap_or(&[])
}

fn apply_section_reloc(
    index_map: &WasmObjectIndexMap,
    reloc: &WasmRelocation,
    local_base: u32,
    symbols: &[WasmSymbol],
    function_table_slots: &[u32],
    memory_base: u32,
    buf: &mut [u8],
) -> Result<()> {
    let mut reloc = *reloc;
    reloc.offset = reloc.offset.checked_sub(local_base).ok_or_else(|| {
        crate::error!("Wasm relocation offset is before the body or payload start")
    })?;
    apply_resolved_reloc(
        index_map,
        &reloc,
        symbols,
        function_table_slots,
        memory_base,
        buf,
    )
}

pub(crate) fn write<'data, A: Arch<Platform = Wasm>>(
    sized_output: &mut SizedOutput<impl OutputFileData>,
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
            section_buffers.get_mut(output_section_id::WASM_CODE),
        )?;
    }
    {
        timing_phase!("Write Wasm data section");
        write_data_section(
            &layout.format_specific,
            section_buffers.get_mut(output_section_id::WASM_DATA),
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
        section_buffers.get_mut(output_section_id::WASM_TYPE),
    )?;
    copy_encoded_section(
        encoded.import.as_ref(),
        section_buffers.get_mut(output_section_id::WASM_IMPORT),
    )?;
    copy_encoded_section(
        encoded.function.as_ref(),
        section_buffers.get_mut(output_section_id::WASM_FUNCTION),
    )?;
    copy_encoded_section(
        encoded.table.as_ref(),
        section_buffers.get_mut(output_section_id::WASM_TABLE),
    )?;
    copy_encoded_section(
        encoded.memory.as_ref(),
        section_buffers.get_mut(output_section_id::WASM_MEMORY),
    )?;
    copy_encoded_section(
        encoded.global.as_ref(),
        section_buffers.get_mut(output_section_id::WASM_GLOBAL),
    )?;
    copy_encoded_section(
        encoded.export.as_ref(),
        section_buffers.get_mut(output_section_id::WASM_EXPORT),
    )?;
    copy_encoded_section(
        encoded.element.as_ref(),
        section_buffers.get_mut(output_section_id::WASM_ELEMENT),
    )?;
    copy_encoded_section(
        encoded.name.as_ref(),
        section_buffers.get_mut(output_section_id::WASM_NAME),
    )?;
    copy_encoded_section(
        encoded.target_features.as_ref(),
        section_buffers.get_mut(output_section_id::WASM_TARGET_FEATURES),
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
fn write_code_section(wasm_layout: &WasmLayout<'_>, out: &mut [u8]) -> Result<()> {
    let bodies = &wasm_layout.function_bodies;
    let object_index_maps = &wasm_layout.object_index_maps;
    let object_code_relocations = &wasm_layout.object_code_relocations;
    let per_object_symbols = &wasm_layout.per_object_symbols;
    let function_table_slots = &wasm_layout.function_table_slots;
    let memory_base = wasm_layout.memory_base;

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
    pos += write_uleb128(&mut out[pos..], count);
    let bodies_region_start = pos;

    // Split the body region into non-overlapping slots, then emit in parallel.
    let mut body_slots: Vec<(&mut [u8], &WasmFunctionBody<'_>)> = Vec::with_capacity(bodies.len());
    {
        verbose_timing_phase!("Split Wasm code body slots");
        let mut rest = &mut out[bodies_region_start..];
        for body in bodies {
            let body_len = body.bytes.len() as u64;
            let slot_len = uleb128_size(body_len) + body.bytes.len();
            ensure!(
                rest.len() >= slot_len,
                "Wasm code section body slot overflow (need {slot_len}, have {})",
                rest.len()
            );
            let (slot, next) = rest.split_at_mut(slot_len);
            body_slots.push((slot, body));
            rest = next;
        }
        ensure!(
            rest.is_empty(),
            "Wasm code section has {} trailing unused bytes after body slots",
            rest.len()
        );
    }

    {
        verbose_timing_phase!("Emit Wasm code bodies");
        body_slots
            .into_par_iter()
            .try_for_each(|(slot, body)| -> Result<()> {
                verbose_timing_phase!("Emit Wasm code body");
                let body_len = body.bytes.len() as u64;
                let pos = write_uleb128(slot, body_len);
                let len = body.bytes.len();
                slot[pos..pos + len].copy_from_slice(&body.bytes);
                let body_bytes = &mut slot[pos..pos + len];
                let index_map = &object_index_maps[body.object_index];
                let symbols = &per_object_symbols[body.object_index];
                let object_relocs = object_code_relocations
                    .get(body.object_index)
                    .map_or(&[][..], Vec::as_slice);
                for reloc in relocs_in_index_range(object_relocs, body.reloc_range.clone()) {
                    apply_section_reloc(
                        index_map,
                        reloc,
                        body.code_offset,
                        symbols,
                        function_table_slots,
                        memory_base,
                        body_bytes,
                    )?;
                }
                Ok(())
            })?;
    }

    Ok(())
}

fn write_data_section(wasm_layout: &WasmLayout<'_>, out: &mut [u8]) -> Result<()> {
    let object_data_layouts = &wasm_layout.object_data_layouts;
    let segment_count: u32 = object_data_layouts
        .iter()
        .map(|obj| u32::try_from(obj.len()).unwrap_or(u32::MAX))
        .sum();
    if segment_count == 0 {
        ensure!(
            out.is_empty(),
            "Wasm data section buffer is {} bytes but no segments to write",
            out.len()
        );
        return Ok(());
    }

    // Flatten (object_index, segment) for parallel emit. Header is serial.
    let flat: Vec<(usize, &WasmDataSegmentLayout<'_>)> = object_data_layouts
        .iter()
        .enumerate()
        .flat_map(|(obj_idx, segs)| segs.iter().map(move |seg| (obj_idx, seg)))
        .collect();
    ensure!(
        flat.len() == segment_count as usize,
        "Wasm data segment count mismatch"
    );

    let mut pos = 0;
    out[pos] = section_id::DATA;
    pos += 1;

    let segments_total: u64 = flat
        .iter()
        .map(|(_, seg)| u64::from(seg.encoded_output_size))
        .sum();
    let count_leb_size = uleb128_size(u64::from(segment_count));
    let payload_size = count_leb_size as u64 + segments_total;
    pos += write_uleb128(&mut out[pos..], payload_size);
    pos += write_uleb128(&mut out[pos..], u64::from(segment_count));
    let segments_region_start = pos;

    let object_index_maps = &wasm_layout.object_index_maps;
    let object_data_relocations = &wasm_layout.object_data_relocations;
    let per_object_symbols = &wasm_layout.per_object_symbols;
    let function_table_slots = &wasm_layout.function_table_slots;
    let memory_base = wasm_layout.memory_base;

    let mut segment_slots: Vec<(&mut [u8], usize, &WasmDataSegmentLayout<'_>)> =
        Vec::with_capacity(flat.len());
    {
        verbose_timing_phase!("Split Wasm data segment slots");
        let mut rest = &mut out[segments_region_start..];
        for (obj_idx, segment) in flat {
            let slot_len = segment.encoded_output_size as usize;
            ensure!(
                rest.len() >= slot_len,
                "Wasm data section segment slot overflow (need {slot_len}, have {})",
                rest.len()
            );
            let (slot, next) = rest.split_at_mut(slot_len);
            segment_slots.push((slot, obj_idx, segment));
            rest = next;
        }
        ensure!(
            rest.is_empty(),
            "Wasm data section has {} trailing unused bytes after segment slots",
            rest.len()
        );
    }

    {
        verbose_timing_phase!("Emit Wasm data segments");
        segment_slots
            .into_par_iter()
            .try_for_each(|(slot, obj_idx, segment)| -> Result<()> {
                verbose_timing_phase!("Emit Wasm data segment");
                write_active_data_segment(
                    slot,
                    segment,
                    &object_index_maps[obj_idx],
                    object_data_relocations
                        .get(obj_idx)
                        .map_or(&[][..], Vec::as_slice),
                    per_object_symbols[obj_idx],
                    function_table_slots,
                    memory_base,
                )
            })?;
    }

    Ok(())
}

fn write_active_data_segment(
    out: &mut [u8],
    segment: &WasmDataSegmentLayout<'_>,
    index_map: &WasmObjectIndexMap,
    object_relocs: &[WasmRelocation],
    symbols: &[WasmSymbol],
    function_table_slots: &[u32],
    memory_base: u32,
) -> Result<()> {
    ensure!(
        out.len() == segment.encoded_output_size as usize,
        "Wasm data segment buffer size {} != encoded_output_size {}",
        out.len(),
        segment.encoded_output_size
    );

    let mut pos = 0;
    if segment.output_memory_index == 0 {
        out[pos] = 0x00;
        pos += 1;
    } else {
        out[pos] = 0x02;
        pos += 1;
        pos += write_uleb128(&mut out[pos..], u64::from(segment.output_memory_index));
    }

    // Offset expr: `i32.const <offset> end`
    out[pos] = 0x41;
    pos += 1;
    let offset_i32 = i32::try_from(segment.output_memory_offset).with_context(|| {
        format!(
            "Wasm data segment memory offset {}",
            segment.output_memory_offset
        )
    })?;
    pos += write_sleb128(&mut out[pos..], i64::from(offset_i32));
    out[pos] = 0x0b;
    pos += 1;

    let data_len = segment.data.len() as u64;
    pos += write_uleb128(&mut out[pos..], data_len);
    let payload = &mut out[pos..pos + segment.data.len()];
    payload.copy_from_slice(segment.data);
    for reloc in relocs_in_index_range(object_relocs, segment.reloc_range.clone()) {
        apply_section_reloc(
            index_map,
            reloc,
            segment.payload_start,
            symbols,
            function_table_slots,
            memory_base,
            payload,
        )?;
    }
    pos += segment.data.len();

    ensure!(
        pos == out.len(),
        "Wasm data segment wrote {pos} bytes but buffer is {} bytes",
        out.len()
    );
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
