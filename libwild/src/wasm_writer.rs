#![allow(dead_code)]

use crate::bail;
use crate::error::Result;
use crate::file_writer::SizedOutput;
use crate::file_writer::split_output_into_sections;
use crate::layout::Layout;
use crate::platform::Arch;
use crate::wasm::WASM_MAGIC;
use crate::wasm::WASM_VERSION;
use crate::wasm::Wasm;
use crate::wasm::WasmLayout;
use wasm_encoder::ExportSection;
use wasm_encoder::FunctionSection;
use wasm_encoder::GlobalSection;
use wasm_encoder::ImportSection;
use wasm_encoder::TypeSection;

pub(crate) fn write<'data, A: Arch<Platform = Wasm>>(
    sized_output: &mut SizedOutput,
    layout: &Layout<'data, Wasm>,
) -> Result<()> {
    let (mut section_buffers, mut padding) =
        split_output_into_sections(layout, &mut sized_output.out);
    padding.fill_zero();

    let preamble = section_buffers
        .get_mut(crate::output_section_id::FILE_HEADER)
        .get_mut(..8)
        .ok_or_else(|| crate::error!("Wasm output buffer is shorter than the 8-byte preamble"))?;
    preamble[..4].copy_from_slice(&WASM_MAGIC);
    preamble[4..8].copy_from_slice(&WASM_VERSION.to_le_bytes());

    copy_metadata_sections(&layout.properties_and_attributes, &mut section_buffers)?;

    bail!("Wasm code and data section emission is not implemented yet");
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
        encoded.global.as_ref(),
        section_buffers.get_mut(crate::output_section_id::WASM_GLOBAL),
    )?;
    copy_encoded_section(
        encoded.export.as_ref(),
        section_buffers.get_mut(crate::output_section_id::WASM_EXPORT),
    )?;
    Ok(())
}

fn copy_encoded_section(encoded: Option<&Vec<u8>>, out: &mut [u8]) -> Result<()> {
    match encoded {
        Some(encoded) => {
            if out.len() != encoded.len() {
                bail!(
                    "Wasm metadata section size mismatch: allocated {}, encoded {}",
                    out.len(),
                    encoded.len()
                );
            }
            out.copy_from_slice(encoded);
        }
        None => {
            if !out.is_empty() {
                bail!(
                    "Wasm metadata section unexpectedly allocated {} bytes",
                    out.len()
                );
            }
        }
    }
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

#[derive(Debug, Copy, Clone)]
pub(crate) struct OutputGlobal<'a> {
    pub(crate) ty: wasmparser::GlobalType,
    /// Const-expression body without the trailing `end` opcode.
    pub(crate) init_expr_body: &'a [u8],
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
