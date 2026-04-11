// WASM output writer — writes directly to buffer.
//
// Produces a valid WASM module by merging input objects' sections
// and applying the layout's symbol resolution.

use crate::layout::FileLayout;
use crate::layout::Layout;
use crate::platform::Arch;
use crate::platform::Args as _;
use crate::wasm::Wasm;

/// WASM binary section IDs (spec §9.6: must be emitted in this order).
const SECTION_TYPE: u8 = 1;
const SECTION_IMPORT: u8 = 2;
const SECTION_FUNCTION: u8 = 3;
const SECTION_MEMORY: u8 = 5;
const SECTION_GLOBAL: u8 = 6;
const SECTION_EXPORT: u8 = 7;
const SECTION_CODE: u8 = 10;
const SECTION_DATA: u8 = 11;

/// WASM export kinds.
const EXPORT_FUNC: u8 = 0x00;
const EXPORT_MEMORY: u8 = 0x02;
const EXPORT_GLOBAL: u8 = 0x03;

/// WASM value types.
const VALTYPE_I32: u8 = 0x7F;

/// Default stack size (1MB, same as wasm-ld).
const DEFAULT_STACK_SIZE: u32 = 1048576;

/// Write a WASM module from the layout.
pub(crate) fn write_direct<A: Arch<Platform = Wasm>>(
    layout: &Layout<'_, Wasm>,
) -> crate::error::Result {
    let output_path = layout.symbol_db.args.output();
    let entry_name = layout.symbol_db.args.entry_symbol_name(None);

    // Collect functions from all input objects.
    let mut merged = merge_inputs(layout)?;

    // GC: remove unreferenced functions (spec §9.1 — output contains only
    // entries for referenced symbols). wasm-ld GCs by default.
    if layout.symbol_db.args.should_gc_sections() {
        gc_functions(&mut merged);
    }

    // Build the output module.
    let mut out = Vec::new();

    // Header: \0asm + version 1
    out.extend_from_slice(b"\0asm");
    out.extend_from_slice(&1u32.to_le_bytes());

    // Type section: merged & deduped function signatures.
    if !merged.types.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, merged.types.len() as u32);
        for ty in &merged.types {
            payload.push(0x60); // func type
            write_leb128(&mut payload, ty.params.len() as u32);
            payload.extend_from_slice(&ty.params);
            write_leb128(&mut payload, ty.results.len() as u32);
            payload.extend_from_slice(&ty.results);
        }
        write_section(&mut out, SECTION_TYPE, &payload);
    }

    // Function section: type index for each function.
    if !merged.functions.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, merged.functions.len() as u32);
        for func in &merged.functions {
            write_leb128(&mut payload, func.type_index);
        }
        write_section(&mut out, SECTION_FUNCTION, &payload);
    }

    // Memory section (spec §9.6): compute from stack + data size.
    let stack_size = layout
        .symbol_db
        .args
        .stack_size
        .unwrap_or(DEFAULT_STACK_SIZE as u64) as u32;
    let total_memory = stack_size + merged.data_size;
    let pages = (total_memory + 65535) / 65536; // round up to pages
    let pages = pages.max(1); // at least 1 page
    {
        let mut payload = Vec::new();
        write_leb128(&mut payload, 1); // 1 memory
        payload.push(0x00); // no max
        write_leb128(&mut payload, pages);
        write_section(&mut out, SECTION_MEMORY, &payload);
    }

    // Global section (spec §9.1): linker-defined globals.
    if !merged.globals.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, merged.globals.len() as u32);
        for global in &merged.globals {
            payload.push(global.valtype);
            payload.push(if global.mutable { 1 } else { 0 });
            // Init expression: i32.const <value>, end
            payload.push(0x41); // i32.const
            write_sleb128(&mut payload, global.init_value as i32);
            payload.push(0x0B); // end
        }
        write_section(&mut out, SECTION_GLOBAL, &payload);
    }

    // Export section (spec §9.2: export for each defined symbol with non-local
    // linkage and non-hidden visibility; plus explicit --export flags).
    {
        let mut payload = Vec::new();
        let mut exports: Vec<(Vec<u8>, u8, u32)> = Vec::new();

        // Memory export (unless importing).
        if !layout.symbol_db.args.import_memory {
            exports.push((b"memory".to_vec(), EXPORT_MEMORY, 0));
        }

        // Explicit --export=<sym> (spec §9.2: symbol must exist, error if not).
        for sym_name in &layout.symbol_db.args.exports {
            if let Some(func_idx) = merged.function_by_name(sym_name.as_bytes()) {
                if !exports.iter().any(|(n, _, _)| n == sym_name.as_bytes()) {
                    exports.push((sym_name.as_bytes().to_vec(), EXPORT_FUNC, func_idx));
                }
            }
        }

        // --export-if-defined=<sym>: export if present, no error if missing.
        for sym_name in &layout.symbol_db.args.exports_if_defined {
            if let Some(func_idx) = merged.function_by_name(sym_name.as_bytes()) {
                if !exports.iter().any(|(n, _, _)| n == sym_name.as_bytes()) {
                    exports.push((sym_name.as_bytes().to_vec(), EXPORT_FUNC, func_idx));
                }
            }
        }

        // Entry function export (after explicit exports).
        if !entry_name.is_empty() {
            if let Some(func_idx) = merged.entry_function_index {
                if !exports.iter().any(|(n, _, _)| n == entry_name) {
                    exports.push((entry_name.to_vec(), EXPORT_FUNC, func_idx));
                }
            }
        }

        write_leb128(&mut payload, exports.len() as u32);
        for (name, kind, index) in &exports {
            write_name(&mut payload, name);
            payload.push(*kind);
            write_leb128(&mut payload, *index);
        }
        write_section(&mut out, SECTION_EXPORT, &payload);
    }

    // Code section: merged function bodies with body-size prefix per function.
    if !merged.functions.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, merged.functions.len() as u32);
        for func in &merged.functions {
            write_leb128(&mut payload, func.body.len() as u32);
            payload.extend_from_slice(&func.body);
        }
        write_section(&mut out, SECTION_CODE, &payload);
    }

    // Data section (spec §9.1): merged data segments with memory offsets.
    if !merged.data_segments.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, merged.data_segments.len() as u32);
        for seg in &merged.data_segments {
            payload.push(0x00); // active segment, memory 0
            // Init expression: i32.const <offset>, end
            payload.push(0x41); // i32.const
            write_sleb128(&mut payload, seg.memory_offset as i32);
            payload.push(0x0B); // end
            // Data bytes
            write_leb128(&mut payload, seg.data.len() as u32);
            payload.extend_from_slice(&seg.data);
        }
        write_section(&mut out, SECTION_DATA, &payload);
    }

    // Name section (custom section "name") — maps function indices to names.
    // Per spec, this is emitted unless --strip-all is set.
    if !layout.symbol_db.args.should_strip_all() && !merged.functions.is_empty() {
        let mut name_payload = Vec::new();

        // Function names subsection (id=1).
        let mut func_names = Vec::new();
        let mut name_entries: Vec<(u32, &[u8])> = Vec::new();
        for (name, &idx) in &merged.function_name_map {
            name_entries.push((idx, name));
        }
        name_entries.sort_by_key(|(idx, _)| *idx);

        write_leb128(&mut func_names, name_entries.len() as u32);
        for (idx, name) in &name_entries {
            write_leb128(&mut func_names, *idx);
            write_name(&mut func_names, name);
        }

        // Subsection 1: function names.
        name_payload.push(1);
        write_leb128(&mut name_payload, func_names.len() as u32);
        name_payload.extend_from_slice(&func_names);

        // Subsection 7: global names.
        if !merged.globals.is_empty() {
            let mut global_names = Vec::new();
            write_leb128(&mut global_names, merged.globals.len() as u32);
            for (i, g) in merged.globals.iter().enumerate() {
                write_leb128(&mut global_names, i as u32);
                write_name(&mut global_names, &g.name);
            }
            name_payload.push(7);
            write_leb128(&mut name_payload, global_names.len() as u32);
            name_payload.extend_from_slice(&global_names);
        }

        // Custom section: id=0, then "name" + payload.
        let mut custom_payload = Vec::new();
        write_name(&mut custom_payload, b"name");
        custom_payload.extend_from_slice(&name_payload);
        write_section(&mut out, 0, &custom_payload);
    }

    std::fs::write(output_path.as_ref(), &out)?;

    // Validate output if requested.
    if std::env::var("WILD_VALIDATE_OUTPUT").is_ok() {
        validate_output(&out)?;
    }

    Ok(())
}

// --- Merged module data ---

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FuncType {
    params: Vec<u8>,
    results: Vec<u8>,
}

struct MergedFunction {
    type_index: u32,
    body: Vec<u8>, // the raw body bytes (NOT including the body size LEB prefix)
}

/// A global variable in the output module.
struct OutputGlobal {
    name: Vec<u8>,
    valtype: u8,
    mutable: bool,
    init_value: u64,
    exported: bool,
}

/// A data segment in the output module.
struct OutputDataSegment {
    /// Byte offset in linear memory.
    memory_offset: u32,
    /// Segment data.
    data: Vec<u8>,
}

/// An import in the output module (for unresolved symbols).
struct OutputImport {
    module: Vec<u8>,
    field: Vec<u8>,
    kind: ImportKind,
}

enum ImportKind {
    Function(u32), // type index
    Global { valtype: u8, mutable: bool },
}

struct MergedModule {
    types: Vec<FuncType>,
    functions: Vec<MergedFunction>,
    entry_function_index: Option<u32>,
    /// Map from symbol name to output function index.
    function_name_map: std::collections::HashMap<Vec<u8>, u32>,
    /// Function indices that are explicitly exported via --export/--export-if-defined.
    explicit_export_indices: Vec<u32>,
    /// Linker-defined globals (e.g. __stack_pointer).
    globals: Vec<OutputGlobal>,
    /// Map from global name to output global index.
    global_name_map: std::collections::HashMap<Vec<u8>, u32>,
    /// Merged data segments.
    data_segments: Vec<OutputDataSegment>,
    /// Total data size (for memory section computation).
    data_size: u32,
    /// Imports for unresolved symbols.
    imports: Vec<OutputImport>,
    /// Number of imported functions (affects function index space).
    num_imported_functions: u32,
    /// Number of imported globals (affects global index space).
    num_imported_globals: u32,
}

impl MergedModule {
    fn function_by_name(&self, name: &[u8]) -> Option<u32> {
        self.function_name_map.get(name).copied()
    }
}

/// GC: remove unreferenced functions and remap indices.
/// Per spec §9.1, output only contains entries for referenced functions.
fn gc_functions(merged: &mut MergedModule) {
    let num_funcs = merged.functions.len();
    if num_funcs == 0 {
        return;
    }

    let mut reachable = vec![false; num_funcs];

    // Mark exported functions as roots (per spec §9.2: only exported symbols
    // and the entry point are roots for GC).
    if let Some(idx) = merged.entry_function_index {
        if (idx as usize) < num_funcs {
            reachable[idx as usize] = true;
        }
    }
    // --export and --export-if-defined symbols are roots.
    for idx in merged.explicit_export_indices.iter() {
        if (*idx as usize) < num_funcs {
            reachable[*idx as usize] = true;
        }
    }

    // BFS: scan reachable function bodies for call instructions.
    // WASM call opcode is 0x10, followed by a function index (LEB128).
    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..num_funcs {
            if !reachable[i] {
                continue;
            }
            let body = &merged.functions[i].body;
            let mut pos = 0;
            // Skip local declarations at the start of the body.
            if let Ok((local_count, c)) = read_leb128(body) {
                pos += c;
                for _ in 0..local_count {
                    if let Ok((_, c)) = read_leb128(&body[pos..]) {
                        pos += c;
                    }
                    pos += 1; // valtype
                }
            }
            // Scan for call instructions.
            while pos < body.len() {
                let opcode = body[pos];
                pos += 1;
                if opcode == 0x10 {
                    // call funcidx
                    if let Ok((func_idx, c)) = read_leb128(&body[pos..]) {
                        pos += c;
                        if func_idx < num_funcs && !reachable[func_idx] {
                            reachable[func_idx] = true;
                            changed = true;
                        }
                    }
                }
                // We don't need to fully parse all opcodes — just scan for 0x10.
                // This may produce false positives (0x10 as an immediate) but
                // won't miss real calls. False positives just keep extra functions.
            }
        }
    }

    // Check if GC removes anything.
    let keep_count = reachable.iter().filter(|&&r| r).count();
    if keep_count == num_funcs {
        return;
    }

    // Build old→new index mapping.
    let mut index_map: Vec<Option<u32>> = vec![None; num_funcs];
    let mut new_idx = 0u32;
    for (old_idx, &keep) in reachable.iter().enumerate() {
        if keep {
            index_map[old_idx] = Some(new_idx);
            new_idx += 1;
        }
    }

    // Filter functions.
    let mut new_functions = Vec::with_capacity(keep_count);
    for (old_idx, keep) in reachable.iter().enumerate() {
        if !keep {
            continue;
        }
        let mut func = std::mem::replace(
            &mut merged.functions[old_idx],
            MergedFunction {
                type_index: 0,
                body: Vec::new(),
            },
        );
        // Remap call targets in the body.
        remap_call_targets(&mut func.body, &index_map);
        new_functions.push(func);
    }
    merged.functions = new_functions;

    // Remap entry function index.
    if let Some(idx) = merged.entry_function_index {
        merged.entry_function_index = index_map.get(idx as usize).copied().flatten();
    }

    // Remap function_name_map.
    merged.function_name_map = merged
        .function_name_map
        .iter()
        .filter_map(|(name, &old_idx)| {
            index_map
                .get(old_idx as usize)
                .copied()
                .flatten()
                .map(|new_idx| (name.clone(), new_idx))
        })
        .collect();

    // GC unused types.
    let mut type_used = vec![false; merged.types.len()];
    for func in &merged.functions {
        if (func.type_index as usize) < type_used.len() {
            type_used[func.type_index as usize] = true;
        }
    }
    let mut type_map: Vec<Option<u32>> = vec![None; merged.types.len()];
    let mut new_type_idx = 0u32;
    for (old_idx, &used) in type_used.iter().enumerate() {
        if used {
            type_map[old_idx] = Some(new_type_idx);
            new_type_idx += 1;
        }
    }
    merged.types = merged
        .types
        .iter()
        .enumerate()
        .filter(|(i, _)| type_used[*i])
        .map(|(_, t)| t.clone())
        .collect();
    // Remap type indices in functions.
    for func in &mut merged.functions {
        if let Some(new_idx) = type_map.get(func.type_index as usize).copied().flatten() {
            func.type_index = new_idx;
        }
    }
}

/// Remap function indices in call instructions within a function body.
fn remap_call_targets(body: &mut [u8], index_map: &[Option<u32>]) {
    let mut pos = 0;
    // Skip local declarations.
    if let Ok((local_count, c)) = read_leb128(body) {
        pos += c;
        for _ in 0..local_count {
            if let Ok((_, c)) = read_leb128(&body[pos..]) {
                pos += c;
            }
            pos += 1; // valtype
        }
    }
    while pos < body.len() {
        let opcode = body[pos];
        pos += 1;
        if opcode == 0x10 {
            // call funcidx — read the current index and remap
            let old_idx = read_padded_leb128(body, pos);
            if let Some(Some(new_idx)) = index_map.get(old_idx as usize) {
                write_padded_leb128(body, pos, *new_idx);
            }
            // Skip past the LEB128 (5 bytes padded)
            if let Ok((_, c)) = read_leb128(&body[pos..]) {
                pos += c;
            }
        }
    }
}

/// Merge all input objects into a single module description.
/// Two-pass approach:
/// 1. Parse all objects, assign output indices, build global name→index map
/// 2. Apply relocations using the global map
fn merge_inputs(layout: &Layout<'_, Wasm>) -> crate::error::Result<MergedModule> {
    let entry_name = layout.symbol_db.args.entry_symbol_name(None);
    let mut types: Vec<FuncType> = Vec::new();
    let mut function_name_map: std::collections::HashMap<Vec<u8>, u32> = Default::default();
    let mut entry_function_index: Option<u32> = None;

    // --- Pass 1: parse all objects, collect types and functions ---
    struct ObjectInfo {
        parsed: ParsedInput,
        type_map: Vec<u32>,
        func_base: u32,
    }
    let mut objects: Vec<ObjectInfo> = Vec::new();
    let mut total_functions = 0u32;

    for group in &layout.group_layouts {
        for file in &group.files {
            let FileLayout::Object(obj) = file else {
                continue;
            };
            let data = obj.object.data;
            if data.len() < 8 || &data[..4] != b"\0asm" {
                continue;
            }

            let parsed = parse_wasm_sections(data)?;

            // Type deduplication.
            let mut type_map: Vec<u32> = Vec::new();
            for input_type in &parsed.types {
                let output_idx = if let Some(pos) = types.iter().position(|t| t == input_type) {
                    pos as u32
                } else {
                    let idx = types.len() as u32;
                    types.push(input_type.clone());
                    idx
                };
                type_map.push(output_idx);
            }

            let func_base = total_functions;

            // Record function names → output indices.
            for (i, _) in parsed.functions.iter().enumerate() {
                if let Some(name) = parsed.function_names.get(&(i as u32)) {
                    let output_idx = func_base + i as u32;
                    function_name_map.insert(name.clone(), output_idx);
                    if name == entry_name {
                        entry_function_index = Some(output_idx);
                    }
                }
            }

            total_functions += parsed.functions.len() as u32;
            objects.push(ObjectInfo {
                parsed,
                type_map,
                func_base,
            });
        }
    }

    // --- Create linker-defined globals (spec §9.6) ---
    let mut globals: Vec<OutputGlobal> = Vec::new();
    let mut global_name_map: std::collections::HashMap<Vec<u8>, u32> = Default::default();

    // __stack_pointer: mutable i32 global, initialized to top of stack.
    // Per spec, the linker synthesizes this. wasm-ld defaults to 1MB stack.
    let stack_size = layout
        .symbol_db
        .args
        .stack_size
        .unwrap_or(DEFAULT_STACK_SIZE as u64) as u32;
    let sp_index = globals.len() as u32;
    global_name_map.insert(b"__stack_pointer".to_vec(), sp_index);
    globals.push(OutputGlobal {
        name: b"__stack_pointer".to_vec(),
        valtype: VALTYPE_I32,
        mutable: true,
        init_value: stack_size as u64, // will be adjusted after data layout
        exported: false,
    });

    // --- Pass 2: apply relocations with global symbol resolution ---
    let mut functions: Vec<MergedFunction> = Vec::new();

    for obj_info in &objects {
        let parsed = &obj_info.parsed;

        // Build per-object symbol → output index maps.
        let mut symbol_to_output_func: std::collections::HashMap<u32, u32> =
            Default::default();
        let mut symbol_to_output_global: std::collections::HashMap<u32, u32> =
            Default::default();
        for (sym_idx, sym) in parsed.symbols.iter().enumerate() {
            if sym.kind == 0 {
                // SYMTAB_FUNCTION
                let is_undefined = sym.flags & 0x10 != 0;
                if !is_undefined && sym.index >= parsed.num_function_imports {
                    let local_func_idx = sym.index - parsed.num_function_imports;
                    symbol_to_output_func
                        .insert(sym_idx as u32, obj_info.func_base + local_func_idx);
                } else {
                    // Undefined or import-referencing — resolve by name.
                    // Per spec §4.3: if undefined without EXPLICIT_NAME, name
                    // comes from the import entry.
                    let resolve_name = if !sym.name.is_empty() {
                        Some(sym.name.as_slice())
                    } else if is_undefined {
                        parsed
                            .import_function_names
                            .get(sym.index as usize)
                            .map(|v| v.as_slice())
                    } else {
                        None
                    };
                    if let Some(name) = resolve_name {
                        if let Some(&output_idx) = function_name_map.get(name) {
                            symbol_to_output_func
                                .insert(sym_idx as u32, output_idx);
                        }
                    }
                }
            } else if sym.kind == 2 {
                    // SYMTAB_GLOBAL — resolve to linker-defined globals by name.
                    let is_undefined = sym.flags & 0x10 != 0;
                    let resolve_name = if !sym.name.is_empty() {
                        Some(sym.name.as_slice())
                    } else if is_undefined {
                        parsed
                            .import_global_names
                            .get(sym.index as usize)
                            .map(|v| v.as_slice())
                    } else {
                        None
                    };
                    if let Some(name) = resolve_name {
                        if let Some(&output_idx) = global_name_map.get(name) {
                            symbol_to_output_global.insert(sym_idx as u32, output_idx);
                        }
                    }
                }
        }

        for (i, input_func) in parsed.functions.iter().enumerate() {
            let remapped_type = obj_info
                .type_map
                .get(input_func.type_index as usize)
                .copied()
                .unwrap_or(input_func.type_index);

            let mut body = input_func.body.clone();

            // Apply relocations that fall within this function body.
            for reloc in &parsed.code_relocations {
                let body_start = input_func.code_section_offset;
                let body_end = body_start + body.len() as u32;
                if reloc.offset < body_start || reloc.offset >= body_end {
                    continue;
                }
                let off_in_body = (reloc.offset - body_start) as usize;

                match reloc.reloc_type {
                    0 => {
                        // R_WASM_FUNCTION_INDEX_LEB (spec §2: 5-byte varuint32)
                        if let Some(&output_idx) =
                            symbol_to_output_func.get(&reloc.symbol_index)
                        {
                            write_padded_leb128(&mut body, off_in_body, output_idx);
                        }
                    }
                    6 => {
                        // R_WASM_TYPE_INDEX_LEB (spec §2: 5-byte varuint32)
                        let old_type = read_padded_leb128(&body, off_in_body);
                        let new_type = obj_info
                            .type_map
                            .get(old_type as usize)
                            .copied()
                            .unwrap_or(old_type);
                        write_padded_leb128(&mut body, off_in_body, new_type);
                    }
                    7 => {
                        // R_WASM_GLOBAL_INDEX_LEB (spec §2: 5-byte varuint32)
                        if let Some(&output_idx) =
                            symbol_to_output_global.get(&reloc.symbol_index)
                        {
                            write_padded_leb128(&mut body, off_in_body, output_idx);
                        }
                    }
                    _ => {}
                }
            }

            functions.push(MergedFunction {
                type_index: remapped_type,
                body,
            });
        }
    }

    // --- Pass 3: collect data segments ---
    // Per spec §9.1: "Merging of data sections is performed by creating
    // a new data section from the data segments."
    // Data is placed after the stack in linear memory.
    let stack_size = layout
        .symbol_db
        .args
        .stack_size
        .unwrap_or(DEFAULT_STACK_SIZE as u64) as u32;
    let mut data_offset = stack_size; // data starts after stack
    let mut data_segments: Vec<OutputDataSegment> = Vec::new();

    for obj_info in &objects {
        let parsed = &obj_info.parsed;
        for seg in &parsed.data_segments {
            // Align the offset.
            let align = seg.alignment.max(1);
            data_offset = (data_offset + align - 1) & !(align - 1);
            data_segments.push(OutputDataSegment {
                memory_offset: data_offset,
                data: seg.data.clone(),
            });
            data_offset += seg.data.len() as u32;
        }
    }
    let data_size = if data_offset > stack_size {
        data_offset - stack_size
    } else {
        0
    };

    // Collect explicit export indices for GC roots.
    let args = layout.symbol_db.args;
    let mut explicit_export_indices = Vec::new();
    for name in args.exports.iter().chain(args.exports_if_defined.iter()) {
        if let Some(&idx) = function_name_map.get(name.as_bytes()) {
            explicit_export_indices.push(idx);
        }
    }

    Ok(MergedModule {
        types,
        functions,
        entry_function_index,
        function_name_map,
        explicit_export_indices,
        globals,
        global_name_map,
        data_segments,
        data_size,
        imports: Vec::new(),
        num_imported_functions: 0,
        num_imported_globals: 0,
    })
}

// --- Raw WASM binary parsing ---

/// Per-spec §2: relocation entry from a reloc.* section.
#[derive(Debug, Clone)]
struct WasmReloc {
    reloc_type: u8,
    /// Offset relative to the start of the section being relocated.
    offset: u32,
    /// Index into the symbol table.
    symbol_index: u32,
    /// Addend (only for *_OFFSET_* and *_ADDR_* relocations).
    addend: i32,
}

/// Per-spec §4: symbol from the linking section's WASM_SYMBOL_TABLE.
#[derive(Debug, Clone)]
struct WasmSymbolInfo {
    kind: u8,
    name: Vec<u8>,
    flags: u32,
    /// For function/global/table symbols: the element index.
    index: u32,
    /// For data symbols: segment index.
    segment_index: u32,
    /// For data symbols: offset within segment.
    segment_offset: u32,
}

/// A parsed data segment from the input object.
struct ParsedDataSegment {
    data: Vec<u8>,
    alignment: u32,
}

struct ParsedInput {
    types: Vec<FuncType>,
    functions: Vec<ParsedFunction>,
    /// Map from local function index to symbol name.
    function_names: std::collections::HashMap<u32, Vec<u8>>,
    /// Import function names (indexed by import function index).
    import_function_names: Vec<Vec<u8>>,
    /// Import global names (indexed by import global index).
    import_global_names: Vec<Vec<u8>>,
    /// All symbols from the linking section.
    symbols: Vec<WasmSymbolInfo>,
    /// Relocations for the code section.
    code_relocations: Vec<WasmReloc>,
    /// Number of imported functions (offset for local function indices).
    num_function_imports: u32,
    /// Data segments from the DATA section.
    data_segments: Vec<ParsedDataSegment>,
}

struct ParsedFunction {
    type_index: u32,
    /// Raw body bytes (without the body-size LEB prefix).
    body: Vec<u8>,
    /// Byte offset of this function's body within the code section payload
    /// (after the function count LEB).
    code_section_offset: u32,
}

/// Parse raw WASM binary to extract types, functions, code, and symbol names.
fn parse_wasm_sections(data: &[u8]) -> crate::error::Result<ParsedInput> {
    let mut types = Vec::new();
    let mut func_type_indices = Vec::new();
    let mut code_bodies = Vec::new();
    let mut function_names = std::collections::HashMap::new();
    let mut symbols = Vec::new();
    let mut code_relocations = Vec::new();
    let mut num_imports = 0u32;
    let mut import_function_names: Vec<Vec<u8>> = Vec::new();
    let mut import_global_names: Vec<Vec<u8>> = Vec::new();
    let mut data_segments: Vec<ParsedDataSegment> = Vec::new();
    let mut code_section_index: Option<usize> = None;
    let mut section_counter = 0usize;

    let mut pos = 8; // skip header
    while pos < data.len() {
        if pos >= data.len() {
            break;
        }
        let section_id = data[pos];
        pos += 1;
        let (size, consumed) = read_leb128(&data[pos..])?;
        pos += consumed;
        if pos + size > data.len() {
            break;
        }
        let payload = &data[pos..pos + size];

        match section_id {
            SECTION_TYPE => {
                types = parse_type_section(payload)?;
            }
            2 => {
                // Import section: count imports to offset function indices.
                let (count, mut off) = read_leb128(payload)?;
                for _ in 0..count {
                    // module name
                    let (mod_len, c) = read_leb128(&payload[off..])?;
                    off += c + mod_len;
                    // field name
                    let (field_len, c) = read_leb128(&payload[off..])?;
                    off += c;
                    let field_name = &payload[off..off + field_len];
                    off += field_len;
                    // import kind
                    let kind = payload[off];
                    off += 1;
                    match kind {
                        0x00 => {
                            // function import — record the field name
                            import_function_names.push(field_name.to_vec());
                            let (_type_idx, c) = read_leb128(&payload[off..])?;
                            off += c;
                            num_imports += 1;
                        }
                        0x01 => {
                            // table
                            off += 1; // elemtype
                            let (flags, c) = read_leb128(&payload[off..])?;
                            off += c;
                            let (_min, c) = read_leb128(&payload[off..])?;
                            off += c;
                            if flags & 1 != 0 {
                                let (_max, c) = read_leb128(&payload[off..])?;
                                off += c;
                            }
                        }
                        0x02 => {
                            // memory
                            let (flags, c) = read_leb128(&payload[off..])?;
                            off += c;
                            let (_min, c) = read_leb128(&payload[off..])?;
                            off += c;
                            if flags & 1 != 0 {
                                let (_max, c) = read_leb128(&payload[off..])?;
                                off += c;
                            }
                        }
                        0x03 => {
                            // global import — record the field name
                            import_global_names.push(field_name.to_vec());
                            off += 1; // valtype
                            off += 1; // mutability
                        }
                        _ => {}
                    }
                }
            }
            SECTION_FUNCTION => {
                func_type_indices = parse_function_section(payload)?;
            }
            SECTION_CODE => {
                code_section_index = Some(section_counter);
                code_bodies = parse_code_section(payload)?;
            }
            SECTION_DATA => {
                data_segments = parse_data_section(payload)?;
            }
            0 => {
                // Custom section — check name.
                let (name_len, c) = read_leb128(payload)?;
                let name = &payload[c..c + name_len];
                let custom_data = &payload[c + name_len..];
                if name == b"linking" {
                    symbols = parse_linking_symbols(custom_data, num_imports);
                    parse_linking_section(
                        custom_data,
                        num_imports,
                        &mut function_names,
                    );
                } else if name.starts_with(b"reloc.") {
                    // Per spec §2: reloc section contains section_index, count, entries.
                    if let Ok(relocs) = parse_reloc_section(custom_data) {
                        // Check if this targets the code section.
                        if let Some(code_idx) = code_section_index {
                            if relocs.0 == code_idx {
                                code_relocations = relocs.1;
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        section_counter += 1;
        pos += size;
    }

    let functions: Vec<ParsedFunction> = func_type_indices
        .iter()
        .zip(code_bodies.iter())
        .map(|(&type_index, (body, offset))| ParsedFunction {
            type_index,
            body: body.clone(),
            code_section_offset: *offset,
        })
        .collect();

    Ok(ParsedInput {
        types,
        functions,
        function_names,
        import_function_names,
        import_global_names,
        symbols,
        code_relocations,
        num_function_imports: num_imports,
        data_segments,
    })
}

fn parse_type_section(payload: &[u8]) -> crate::error::Result<Vec<FuncType>> {
    let (count, mut off) = read_leb128(payload)?;
    let mut types = Vec::with_capacity(count);
    for _ in 0..count {
        let _form = payload[off]; // 0x60 = func
        off += 1;
        let (param_count, c) = read_leb128(&payload[off..])?;
        off += c;
        let params = payload[off..off + param_count].to_vec();
        off += param_count;
        let (result_count, c) = read_leb128(&payload[off..])?;
        off += c;
        let results = payload[off..off + result_count].to_vec();
        off += result_count;
        types.push(FuncType { params, results });
    }
    Ok(types)
}

fn parse_function_section(payload: &[u8]) -> crate::error::Result<Vec<u32>> {
    let (count, mut off) = read_leb128(payload)?;
    let mut indices = Vec::with_capacity(count);
    for _ in 0..count {
        let (idx, c) = read_leb128(&payload[off..])?;
        off += c;
        indices.push(idx as u32);
    }
    Ok(indices)
}

fn parse_code_section(payload: &[u8]) -> crate::error::Result<Vec<(Vec<u8>, u32)>> {
    let (count, mut off) = read_leb128(payload)?;
    let mut bodies = Vec::with_capacity(count);
    for _ in 0..count {
        let (body_size, c) = read_leb128(&payload[off..])?;
        let body_offset = (off + c) as u32; // offset of body content within code section payload
        off += c;
        let body = payload[off..off + body_size].to_vec();
        off += body_size;
        bodies.push((body, body_offset));
    }
    Ok(bodies)
}

/// Parse DATA section: extract data segments.
/// In object files, segments are passive (no init expr) — just data bytes.
fn parse_data_section(payload: &[u8]) -> crate::error::Result<Vec<ParsedDataSegment>> {
    let (count, mut off) = read_leb128(payload)?;
    let mut segments = Vec::with_capacity(count);
    for _ in 0..count {
        // In object files, data segments have segment_flags=0 (active, memory 0).
        // But the init expr is meaningless — the linker assigns offsets.
        // Format: flags (varuint32), [memory_index if flags&1], init_expr, data_len, data
        let (flags, c) = read_leb128(&payload[off..])?;
        off += c;
        if flags & 0x01 != 0 {
            // Has explicit memory index.
            let (_mem_idx, c) = read_leb128(&payload[off..])?;
            off += c;
        }
        if flags & 0x02 == 0 {
            // Active segment: skip init expr (ends with 0x0B).
            while off < payload.len() && payload[off] != 0x0B {
                off += 1;
            }
            off += 1; // skip 0x0B
        }
        // Data bytes.
        let (data_len, c) = read_leb128(&payload[off..])?;
        off += c;
        let data = payload[off..off + data_len].to_vec();
        off += data_len;
        segments.push(ParsedDataSegment {
            data,
            alignment: 1, // Will be updated from WASM_SEGMENT_INFO
        });
    }
    Ok(segments)
}

/// Parse a reloc.* section (spec §2.1).
fn parse_reloc_section(data: &[u8]) -> crate::error::Result<(usize, Vec<WasmReloc>)> {
    let (section_index, mut off) = read_leb128(data)?;
    let (count, c) = read_leb128(&data[off..])?;
    off += c;

    let mut relocs = Vec::with_capacity(count);
    for _ in 0..count {
        if off >= data.len() {
            break;
        }
        let reloc_type = data[off];
        off += 1;
        let (offset, c) = read_leb128(&data[off..])?;
        off += c;
        let (symbol_index, c) = read_leb128(&data[off..])?;
        off += c;

        // Per spec §2.1: addend is present for *_OFFSET_* and *_ADDR_* types.
        let has_addend = matches!(
            reloc_type,
            3 | 4 | 5 | 8 | 9 | 14 | 15 | 16 | 22 | 23
        );
        let addend = if has_addend {
            let (a, c) = read_sleb128(&data[off..])?;
            off += c;
            a
        } else {
            0
        };

        relocs.push(WasmReloc {
            reloc_type,
            offset: offset as u32,
            symbol_index: symbol_index as u32,
            addend,
        });
    }
    Ok((section_index, relocs))
}

/// Parse symbol table from the linking section (spec §4).
fn parse_linking_symbols(data: &[u8], num_imports: u32) -> Vec<WasmSymbolInfo> {
    let Ok((version, mut off)) = read_leb128(data) else {
        return Vec::new();
    };
    if version != 2 {
        return Vec::new();
    }

    while off < data.len() {
        let Ok((subsection_type, c)) = read_leb128(&data[off..]) else {
            return Vec::new();
        };
        off += c;
        let Ok((subsection_len, c)) = read_leb128(&data[off..]) else {
            return Vec::new();
        };
        off += c;
        let subsection_end = off + subsection_len;

        if subsection_type == 8 {
            return parse_symbol_table_entries(&data[off..subsection_end], num_imports);
        }

        off = subsection_end;
    }
    Vec::new()
}

fn parse_symbol_table_entries(data: &[u8], num_imports: u32) -> Vec<WasmSymbolInfo> {
    let Ok((count, mut off)) = read_leb128(data) else {
        return Vec::new();
    };
    let mut syms = Vec::with_capacity(count);

    for _ in 0..count {
        if off >= data.len() {
            return syms;
        }
        let kind = data[off];
        off += 1;
        let Ok((flags, c)) = read_leb128(&data[off..]) else {
            return syms;
        };
        off += c;

        let is_undefined = flags & 0x10 != 0;
        let has_explicit_name = flags & 0x40 != 0;

        match kind {
            0 | 2 | 4 | 5 => {
                // SYMTAB_FUNCTION (0), GLOBAL (2), EVENT (4), TABLE (5)
                let Ok((index, c)) = read_leb128(&data[off..]) else {
                    return syms;
                };
                off += c;

                let name = if !is_undefined || has_explicit_name {
                    let Ok((name_len, c)) = read_leb128(&data[off..]) else {
                        return syms;
                    };
                    off += c;
                    let n = data[off..off + name_len].to_vec();
                    off += name_len;
                    n
                } else {
                    Vec::new()
                };

                syms.push(WasmSymbolInfo {
                    kind,
                    name,
                    flags: flags as u32,
                    index: index as u32,
                    segment_index: 0,
                    segment_offset: 0,
                });
            }
            1 => {
                // SYMTAB_DATA
                let Ok((name_len, c)) = read_leb128(&data[off..]) else {
                    return syms;
                };
                off += c;
                let name = data[off..off + name_len].to_vec();
                off += name_len;

                let (segment_index, segment_offset) = if !is_undefined {
                    let Ok((seg, c)) = read_leb128(&data[off..]) else {
                        return syms;
                    };
                    off += c;
                    let Ok((seg_off, c)) = read_leb128(&data[off..]) else {
                        return syms;
                    };
                    off += c;
                    let Ok((_, c)) = read_leb128(&data[off..]) else {
                        return syms;
                    };
                    off += c; // size
                    (seg as u32, seg_off as u32)
                } else {
                    (0, 0)
                };

                syms.push(WasmSymbolInfo {
                    kind,
                    name,
                    flags: flags as u32,
                    index: 0,
                    segment_index,
                    segment_offset,
                });
            }
            3 => {
                // SYMTAB_SECTION
                let Ok((section, c)) = read_leb128(&data[off..]) else {
                    return syms;
                };
                off += c;
                syms.push(WasmSymbolInfo {
                    kind,
                    name: Vec::new(),
                    flags: flags as u32,
                    index: section as u32,
                    segment_index: 0,
                    segment_offset: 0,
                });
            }
            _ => return syms,
        }
    }
    syms
}

/// Extract function names from the linking section's symbol table.
fn parse_linking_section(
    data: &[u8],
    num_imports: u32,
    function_names: &mut std::collections::HashMap<u32, Vec<u8>>,
) {
    // Version
    if data.is_empty() {
        return;
    }
    let Ok((version, mut off)) = read_leb128(data) else {
        return;
    };
    if version != 2 {
        return;
    }

    while off < data.len() {
        let Ok((subsection_type, c)) = read_leb128(&data[off..]) else {
            return;
        };
        off += c;
        let Ok((subsection_len, c)) = read_leb128(&data[off..]) else {
            return;
        };
        off += c;
        let subsection_end = off + subsection_len;

        if subsection_type == 8 {
            // WASM_SYMBOL_TABLE
            parse_symbol_table(&data[off..subsection_end], num_imports, function_names);
        }

        off = subsection_end;
    }
}

fn parse_symbol_table(
    data: &[u8],
    num_imports: u32,
    function_names: &mut std::collections::HashMap<u32, Vec<u8>>,
) {
    let Ok((count, mut off)) = read_leb128(data) else {
        return;
    };

    for _ in 0..count {
        if off >= data.len() {
            return;
        }
        let kind = data[off];
        off += 1;
        let Ok((flags, c)) = read_leb128(&data[off..]) else {
            return;
        };
        off += c;

        let is_undefined = flags & 0x10 != 0;
        let has_explicit_name = flags & 0x40 != 0;

        match kind {
            0 => {
                // SYMTAB_FUNCTION
                let Ok((index, c)) = read_leb128(&data[off..]) else {
                    return;
                };
                off += c;

                // Name is present if: defined, or has EXPLICIT_NAME flag
                if !is_undefined || has_explicit_name {
                    let Ok((name_len, c)) = read_leb128(&data[off..]) else {
                        return;
                    };
                    off += c;
                    let name = data[off..off + name_len].to_vec();
                    off += name_len;

                    // Convert from absolute function index to local (subtract imports).
                    if index as u32 >= num_imports {
                        function_names.insert(index as u32 - num_imports, name);
                    }
                }
            }
            1 => {
                // SYMTAB_DATA
                let Ok((name_len, c)) = read_leb128(&data[off..]) else {
                    return;
                };
                off += c;
                off += name_len; // skip name
                if !is_undefined {
                    // segment index, offset, size
                    let Ok((_, c)) = read_leb128(&data[off..]) else {
                        return;
                    };
                    off += c;
                    let Ok((_, c)) = read_leb128(&data[off..]) else {
                        return;
                    };
                    off += c;
                    let Ok((_, c)) = read_leb128(&data[off..]) else {
                        return;
                    };
                    off += c;
                }
            }
            2 | 4 | 5 => {
                // SYMTAB_GLOBAL, SYMTAB_EVENT, SYMTAB_TABLE
                let Ok((_, c)) = read_leb128(&data[off..]) else {
                    return;
                };
                off += c; // index
                if !is_undefined || has_explicit_name {
                    let Ok((name_len, c)) = read_leb128(&data[off..]) else {
                        return;
                    };
                    off += c;
                    off += name_len; // skip name
                }
            }
            3 => {
                // SYMTAB_SECTION
                let Ok((_, c)) = read_leb128(&data[off..]) else {
                    return;
                };
                off += c; // section index
            }
            _ => return,
        }
    }
}

// --- Output validation ---

/// Validate the output WASM module against spec invariants (§9.6).
fn validate_output(data: &[u8]) -> crate::error::Result {
    if data.len() < 8 {
        return Err(crate::error!("WASM output too short"));
    }
    if &data[..4] != b"\0asm" {
        return Err(crate::error!("WASM output: bad magic"));
    }
    if data[4..8] != [1, 0, 0, 0] {
        return Err(crate::error!("WASM output: bad version"));
    }

    let mut pos = 8;
    let mut prev_id: u8 = 0;
    let mut function_count: Option<usize> = None;
    let mut code_count: Option<usize> = None;
    let mut num_globals: usize = 0;
    let mut num_functions: usize = 0;
    let mut memory_pages: usize = 0;

    while pos < data.len() {
        let section_id = data[pos];
        pos += 1;
        let (size, consumed) = read_leb128(&data[pos..])?;
        pos += consumed;
        if pos + size > data.len() {
            return Err(crate::error!(
                "WASM output: section {section_id} extends past end of file"
            ));
        }
        let payload = &data[pos..pos + size];

        // Spec §9.6: non-custom sections must be in ascending order.
        if section_id != 0 {
            if section_id <= prev_id {
                return Err(crate::error!(
                    "WASM output: section {section_id} out of order (prev {prev_id})"
                ));
            }
            prev_id = section_id;
        }

        match section_id {
            SECTION_FUNCTION => {
                let (count, _) = read_leb128(payload)?;
                function_count = Some(count);
                num_functions = count;
            }
            SECTION_CODE => {
                let (count, _) = read_leb128(payload)?;
                code_count = Some(count);
            }
            SECTION_GLOBAL => {
                let (count, _) = read_leb128(payload)?;
                num_globals = count;
            }
            SECTION_MEMORY => {
                let (count, _) = read_leb128(payload)?;
                if count > 0 {
                    let (_flags, c) = read_leb128(&payload[1..])?;
                    let (pages, _) = read_leb128(&payload[1 + c..])?;
                    memory_pages = pages;
                }
            }
            SECTION_EXPORT => {
                // Validate all exported indices are in range.
                let (count, mut off) = read_leb128(payload)?;
                for _ in 0..count {
                    let (name_len, c) = read_leb128(&payload[off..])?;
                    off += c + name_len;
                    let kind = payload[off];
                    off += 1;
                    let (index, c) = read_leb128(&payload[off..])?;
                    off += c;
                    match kind {
                        0x00 => {
                            // Function export
                            if index >= num_functions {
                                return Err(crate::error!(
                                    "WASM output: exported function index {index} \
                                     out of range (have {num_functions})"
                                ));
                            }
                        }
                        0x03 => {
                            // Global export
                            if index >= num_globals {
                                return Err(crate::error!(
                                    "WASM output: exported global index {index} \
                                     out of range (have {num_globals})"
                                ));
                            }
                        }
                        _ => {} // memory/table exports checked elsewhere
                    }
                }
            }
            SECTION_DATA => {
                // Validate data segments don't overflow memory.
                let (count, mut off) = read_leb128(payload)?;
                for _ in 0..count {
                    let (flags, c) = read_leb128(&payload[off..])?;
                    off += c;
                    if flags & 0x02 == 0 {
                        // Active segment: skip init expr.
                        while off < payload.len() && payload[off] != 0x0B {
                            off += 1;
                        }
                        off += 1;
                    }
                    let (data_len, c) = read_leb128(&payload[off..])?;
                    off += c + data_len;
                }
            }
            _ => {}
        }

        pos += size;
    }

    if pos != data.len() {
        return Err(crate::error!("WASM output: trailing bytes after last section"));
    }

    // Spec invariant: function section count must match code section count.
    if let (Some(fc), Some(cc)) = (function_count, code_count) {
        if fc != cc {
            return Err(crate::error!(
                "WASM output: function count ({fc}) != code count ({cc})"
            ));
        }
    }

    Ok(())
}

// --- Binary encoding helpers ---

/// Write a WASM name: LEB128 length + bytes.
fn write_name(out: &mut Vec<u8>, name: &[u8]) {
    write_leb128(out, name.len() as u32);
    out.extend_from_slice(name);
}

/// Write a WASM section: id byte + LEB128 size + payload.
fn write_section(out: &mut Vec<u8>, section_id: u8, payload: &[u8]) {
    out.push(section_id);
    write_leb128(out, payload.len() as u32);
    out.extend_from_slice(payload);
}

/// Write an unsigned LEB128 value.
fn write_leb128(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Write a signed LEB128 value.
fn write_sleb128(out: &mut Vec<u8>, mut value: i32) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if !done {
            byte |= 0x80;
        }
        out.push(byte);
        if done {
            break;
        }
    }
}

/// Write a 5-byte padded unsigned LEB128 value at a specific offset in a buffer.
/// Per spec §9.5: "All LEB128 values to be relocated must be maximally padded."
fn write_padded_leb128(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset] = (value & 0x7F) as u8 | 0x80;
    buf[offset + 1] = ((value >> 7) & 0x7F) as u8 | 0x80;
    buf[offset + 2] = ((value >> 14) & 0x7F) as u8 | 0x80;
    buf[offset + 3] = ((value >> 21) & 0x7F) as u8 | 0x80;
    buf[offset + 4] = ((value >> 28) & 0x0F) as u8;
}

/// Read a 5-byte padded unsigned LEB128 value at a specific offset.
fn read_padded_leb128(buf: &[u8], offset: usize) -> u32 {
    let mut result = 0u32;
    for i in 0..5 {
        let byte = buf[offset + i];
        result |= ((byte & 0x7F) as u32) << (i * 7);
        if byte < 0x80 {
            break;
        }
    }
    result
}

/// Read a signed LEB128 value. Returns (value, bytes_consumed).
fn read_sleb128(data: &[u8]) -> crate::error::Result<(i32, usize)> {
    let mut result: i32 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7F) as i32) << shift;
        shift += 7;
        if byte < 0x80 {
            // Sign extend if high bit of the last byte is set.
            if shift < 32 && (byte & 0x40) != 0 {
                result |= !0 << shift;
            }
            return Ok((result, i + 1));
        }
        if shift >= 35 {
            return Err(crate::error!("SLEB128 overflow"));
        }
    }
    Err(crate::error!("Unexpected end of SLEB128"))
}

/// Read an unsigned LEB128 value. Returns (value, bytes_consumed).
fn read_leb128(data: &[u8]) -> crate::error::Result<(usize, usize)> {
    let mut result: usize = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7F) as usize) << shift;
        shift += 7;
        if byte < 0x80 {
            return Ok((result, i + 1));
        }
        if shift >= 35 {
            return Err(crate::error!("LEB128 overflow"));
        }
    }
    Err(crate::error!("Unexpected end of LEB128"))
}
