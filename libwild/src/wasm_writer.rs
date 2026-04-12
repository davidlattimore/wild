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
const SECTION_TABLE: u8 = 4;
const SECTION_MEMORY: u8 = 5;
const SECTION_GLOBAL: u8 = 6;
const SECTION_EXPORT: u8 = 7;
const SECTION_ELEMENT: u8 = 9;
const SECTION_START: u8 = 8;
const SECTION_CODE: u8 = 10;
const SECTION_DATA: u8 = 11;
const SECTION_DATACOUNT: u8 = 12;
const SECTION_TAG: u8 = 13;

/// Linear-memory address width used by the wasm writer's layout math.
///
/// Defaults to `u32`. When the `wasm-addr64` Cargo feature is on, widens to
/// `u64` so memory64 layouts larger than 4 GiB can be planned end-to-end.
/// The memory64 relocation encoders (`R_WASM_MEMORY_ADDR_*64`) already emit
/// the full 64-bit payload; this alias controls only wild's *internal*
/// arithmetic.
#[cfg(not(feature = "wasm-addr64"))]
pub(crate) type Addr = u32;
#[cfg(feature = "wasm-addr64")]
pub(crate) type Addr = u64;

/// WASM export kinds.
const EXPORT_FUNC: u8 = 0x00;
const EXPORT_MEMORY: u8 = 0x02;
const EXPORT_GLOBAL: u8 = 0x03;
const EXPORT_TAG: u8 = 0x04;

/// WASM value types.
const VALTYPE_I32: u8 = 0x7F;

/// Default stack size (64KB, same as wasm-ld).
const DEFAULT_STACK_SIZE: u32 = 65536;

/// Write a WASM module from the layout.
pub(crate) fn write_direct<A: Arch<Platform = Wasm>>(
    layout: &Layout<'_, Wasm>,
) -> crate::error::Result {
    let output_path = layout.symbol_db.args.output();
    let entry_name = layout.symbol_db.args.entry_symbol_name(None);

    let is_shared = layout.symbol_db.args.is_shared;

    // Relocatable output (-r): emit merged .o file without linking.
    if layout.symbol_db.args.is_relocatable {
        return write_relocatable::<A>(layout);
    }

    // Collect functions from all input objects.
    let mut merged = merge_inputs(layout)?;

    // GC: remove unreferenced functions (spec §9.1).
    if layout.symbol_db.args.should_gc_sections() {
        gc_functions(&mut merged, layout.symbol_db.args.should_export_all_dynamic_symbols());
    }
    let is_pic = is_shared; // PIE also uses PIC

    // For shared/PIE: disable GC (all defined functions are potentially needed),
    // and export all by default.
    // Also: in shared mode, __stack_pointer, __memory_base, __table_base
    // are all imports, not definitions.

    // Build the output module.
    let mut out = Vec::new();

    // Header: \0asm + version 1
    out.extend_from_slice(b"\0asm");
    out.extend_from_slice(&1u32.to_le_bytes());

    // dylink.0 custom section (must be FIRST for shared libraries).
    if is_shared {
        let mut dylink_payload = Vec::new();
        write_name(&mut dylink_payload, b"dylink.0");

        // Subsection 1: WASM_DYLINK_MEM_INFO
        let mut mem_info = Vec::new();
        // MemoryAlignment is the max segment alignment as log2.
        let mem_align_log2 = if merged.max_data_alignment > 1 {
            merged.max_data_alignment.trailing_zeros()
        } else {
            0
        };
        write_leb128_addr(&mut mem_info, merged.data_size);       // MemorySize
        write_leb128(&mut mem_info, mem_align_log2);              // MemoryAlignment (log2)
        write_leb128(&mut mem_info, merged.table_entries.len() as u32); // TableSize
        write_leb128(&mut mem_info, 0);                           // TableAlignment (log2)

        dylink_payload.push(1); // subsection type: WASM_DYLINK_MEM_INFO
        write_leb128(&mut dylink_payload, mem_info.len() as u32);
        dylink_payload.extend_from_slice(&mem_info);

        // Subsection 2: WASM_DYLINK_NEEDED (empty for now)
        let needed: Vec<u8> = vec![0]; // count=0
        dylink_payload.push(2);
        write_leb128(&mut dylink_payload, needed.len() as u32);
        dylink_payload.extend_from_slice(&needed);

        write_section(&mut out, 0, &dylink_payload);
    }

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

    // Import section (spec §9.6: between type and function).
    if !merged.imports.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, merged.imports.len() as u32);
        for imp in &merged.imports {
            write_name(&mut payload, &imp.module);
            write_name(&mut payload, &imp.field);
            match &imp.kind {
                ImportKind::Function(type_idx) => {
                    payload.push(0x00);
                    write_leb128(&mut payload, *type_idx);
                }
                ImportKind::Table { min } => {
                    payload.push(0x01); // table
                    payload.push(0x70); // funcref
                    payload.push(0x00); // no max
                    write_leb128(&mut payload, *min);
                }
                ImportKind::Memory { min } => {
                    payload.push(0x02); // memory
                    payload.push(0x00); // no max
                    write_leb128(&mut payload, *min);
                }
                ImportKind::Global { valtype, mutable } => {
                    payload.push(0x03);
                    payload.push(*valtype);
                    payload.push(if *mutable { 1 } else { 0 });
                }
                ImportKind::Tag(type_idx) => {
                    payload.push(0x04); // tag
                    payload.push(0x00); // attribute: exception
                    write_leb128(&mut payload, *type_idx);
                }
            }
        }
        write_section(&mut out, SECTION_IMPORT, &payload);
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

    // Table section (spec §9.6: between function and memory).
    // --import-table: table comes from host, emit as import instead of definition.
    // --export-table: add table to exports.
    let has_table = !merged.table_entries.is_empty()
        || layout.symbol_db.args.import_table
        || layout.symbol_db.args.export_table;
    let table_size = if !merged.table_entries.is_empty() {
        merged.table_entries.len() as u32 + 1
    } else if has_table {
        1 // empty table with just the null entry
    } else {
        0
    };

    // When --import-table, table is imported (handled in merge_inputs pass 4).
    // Only emit TABLE section when defining our own table.
    if has_table && !layout.symbol_db.args.import_table {
        let mut payload = Vec::new();
        write_leb128(&mut payload, 1); // 1 table
        payload.push(0x70); // funcref
        if layout.symbol_db.args.growable_table {
            payload.push(0x00); // no max (growable)
            write_leb128(&mut payload, table_size);
        } else {
            payload.push(0x01); // has max (fixed size)
            write_leb128(&mut payload, table_size); // min
            write_leb128(&mut payload, table_size); // max = min
        }
        write_section(&mut out, SECTION_TABLE, &payload);
    }

    // Memory section (spec §9.6): compute from stack + data size.
    // In shared mode, memory is imported via dylink.
    let args = layout.symbol_db.args;
    if !is_shared {
    let total_memory_u64 = {
        let stack_size = args.stack_size.unwrap_or(DEFAULT_STACK_SIZE as u64);
        let heap_size = args.initial_heap.unwrap_or(0);
        let computed = if args.stack_first {
            stack_size + merged.data_size as u64 + heap_size
        } else {
            merged.stack_pointer_value as u64 + heap_size
        };
        if let Some(initial) = args.initial_memory {
            initial.max(computed)
        } else {
            computed
        }
    };
    let pages = ((total_memory_u64 + 65535) / 65536).max(1) as u32;
    {
        let mut payload = Vec::new();
        write_leb128(&mut payload, 1); // 1 memory
        let shared_flag: u8 = if args.shared_memory { 0x02 } else { 0x00 };
        if let Some(max) = args.max_memory {
            let max_pages = ((max + 65535) / 65536).max(pages as u64) as u32;
            payload.push(0x01 | shared_flag); // has max [+ shared]
            write_leb128(&mut payload, pages);
            write_leb128(&mut payload, max_pages);
        } else if args.no_growable_memory || args.shared_memory {
            // shared memory requires max
            payload.push(0x01 | shared_flag); // has max [+ shared]
            write_leb128(&mut payload, pages);
            write_leb128(&mut payload, pages);
        } else {
            payload.push(0x00); // no max
            write_leb128(&mut payload, pages);
        }
        write_section(&mut out, SECTION_MEMORY, &payload);
    }
    } // !is_shared

    // Tag section (EH proposal): between memory and global.
    if !merged.output_tags.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, merged.output_tags.len() as u32);
        for &type_idx in &merged.output_tags {
            payload.push(0x00); // attribute: exception
            write_leb128(&mut payload, type_idx);
        }
        write_section(&mut out, SECTION_TAG, &payload);
    }

    // Global section (spec §9.1): linker-defined globals.
    // In shared mode, skip defining globals (they're imported).
    if !merged.globals.is_empty() && !is_shared {
        let mut payload = Vec::new();
        write_leb128(&mut payload, merged.globals.len() as u32);
        for global in &merged.globals {
            payload.push(global.valtype);
            payload.push(if global.mutable { 1 } else { 0 });
            // Init expression: type-appropriate const + end
            match global.valtype {
                0x7D => {
                    // f32
                    payload.push(0x43); // f32.const
                    payload.extend_from_slice(&(global.init_value as u32).to_le_bytes());
                }
                0x7C => {
                    // f64
                    payload.push(0x44); // f64.const
                    payload.extend_from_slice(&global.init_value.to_le_bytes());
                }
                0x7E => {
                    // i64
                    payload.push(0x42); // i64.const
                    write_sleb128(&mut payload, global.init_value as i32);
                }
                _ => {
                    // i32 (0x7F) and others
                    payload.push(0x41); // i32.const
                    write_sleb128(&mut payload, global.init_value as i32);
                }
            }
            payload.push(0x0B); // end
        }
        write_section(&mut out, SECTION_GLOBAL, &payload);
    }

    // Export section (spec §9.2: export for each defined symbol with non-local
    // linkage and non-hidden visibility; plus explicit --export flags).
    // Order: memory, globals, functions, table (matching wasm-ld).
    {
        let mut payload = Vec::new();
        let mut exports: Vec<(Vec<u8>, u8, u32)> = Vec::new();

        // Memory export (unless importing or shared).
        if !layout.symbol_db.args.import_memory && !is_shared {
            exports.push((b"memory".to_vec(), EXPORT_MEMORY, 0));
        }

        // Linker-defined global exports (__stack_pointer, __data_end, __heap_base).
        // Placed early in export list (after memory) to match wasm-ld ordering.
        // With --export-dynamic, all globals are exported.
        if !is_shared {
            let export_all_globals = layout.symbol_db.args.should_export_all_dynamic_symbols();
            for (i, global) in merged.globals.iter().enumerate() {
                if global.exported || export_all_globals {
                    let global_idx = merged.num_imported_globals + i as u32;
                    if !exports.iter().any(|(n, _, _)| *n == global.name) {
                        exports.push((global.name.clone(), EXPORT_GLOBAL, global_idx));
                    }
                }
            }
        }

        // Explicit --export=<sym> (spec §9.2: symbol must exist, error if not).
        // Check both functions and globals.
        for sym_name in &layout.symbol_db.args.exports {
            if exports.iter().any(|(n, _, _)| n == sym_name.as_bytes()) {
                continue;
            }
            if let Some(func_idx) = merged.function_by_name(sym_name.as_bytes()) {
                exports.push((sym_name.as_bytes().to_vec(), EXPORT_FUNC, func_idx));
            } else if let Some((i, _)) = merged.globals.iter().enumerate()
                .find(|(_, g)| g.name == sym_name.as_bytes())
            {
                let global_idx = merged.num_imported_globals + i as u32;
                exports.push((sym_name.as_bytes().to_vec(), EXPORT_GLOBAL, global_idx));
            }
        }

        // --export-if-defined=<sym>: export if present, no error if missing.
        for sym_name in &layout.symbol_db.args.exports_if_defined {
            if exports.iter().any(|(n, _, _)| n == sym_name.as_bytes()) {
                continue;
            }
            if let Some(func_idx) = merged.function_by_name(sym_name.as_bytes()) {
                exports.push((sym_name.as_bytes().to_vec(), EXPORT_FUNC, func_idx));
            } else if let Some((i, _)) = merged.globals.iter().enumerate()
                .find(|(_, g)| g.name == sym_name.as_bytes())
            {
                let global_idx = merged.num_imported_globals + i as u32;
                exports.push((sym_name.as_bytes().to_vec(), EXPORT_GLOBAL, global_idx));
            }
        }

        // WASM_SYM_EXPORTED functions (spec §4.2, flag 0x20).
        for &func_idx in &merged.exported_indices {
            // Find the name for this function index.
            if let Some((name, _)) = merged
                .function_name_map
                .iter()
                .find(|(_, idx)| **idx == func_idx)
            {
                if !exports.iter().any(|(n, _, _)| n == name) {
                    exports.push((name.clone(), EXPORT_FUNC, func_idx));
                }
            }
        }

        // --export-dynamic / --export-all: export all non-hidden defined functions.
        // Per spec §9.2: "export for each defined symbol with non-local linkage
        // and non-hidden visibility."
        // --export-all overrides visibility and exports hidden symbols too.
        if layout.symbol_db.args.should_export_all_dynamic_symbols() {
            let skip_hidden = !layout.symbol_db.args.export_all;
            let mut names: Vec<(Vec<u8>, u32)> = merged
                .function_name_map
                .iter()
                .filter(|(name, _)| !skip_hidden || !merged.hidden_functions.contains(name.as_slice()))
                .map(|(name, &idx)| (name.clone(), idx))
                .collect();
            names.sort_by_key(|(_, idx)| *idx);
            for (name, idx) in names {
                if !exports.iter().any(|(n, _, _)| *n == name) {
                    exports.push((name, EXPORT_FUNC, idx));
                }
            }
        }

        // Tag exports: a tag with WASM_SYM_EXPORTED flag gets kind-0x04.
        // Under --export-dynamic we also emit non-hidden tags.
        {
            let export_all_dyn = layout.symbol_db.args.should_export_all_dynamic_symbols();
            let skip_hidden = !layout.symbol_db.args.export_all;
            for (name, &out_idx) in &merged.tag_name_map {
                let explicit = merged.exported_tag_names.contains(name);
                let dyn_eligible = export_all_dyn
                    && (!skip_hidden || !merged.hidden_tags.contains(name));
                if (explicit || dyn_eligible)
                    && !exports.iter().any(|(n, _, _)| n == name)
                {
                    exports.push((name.clone(), EXPORT_TAG, out_idx));
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

        // --export-table: export the indirect function table.
        if layout.symbol_db.args.export_table && has_table {
            exports.push((
                b"__indirect_function_table".to_vec(),
                0x01, // table export kind
                0,    // table index 0
            ));
        }

        write_leb128(&mut payload, exports.len() as u32);
        for (name, kind, index) in &exports {
            write_name(&mut payload, name);
            payload.push(*kind);
            write_leb128(&mut payload, *index);
        }
        write_section(&mut out, SECTION_EXPORT, &payload);
    }

    // Start section (spec §9.6: auto-called function, for __wasm_init_memory).
    if let Some(func_idx) = merged.init_memory_func_idx {
        let mut payload = Vec::new();
        write_leb128(&mut payload, func_idx);
        write_section(&mut out, SECTION_START, &payload);
    }

    // Element section (spec §9.6: populates the indirect function table).
    if !merged.table_entries.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, 1); // 1 element segment
        // Active element segment for table 0.
        payload.push(0x00); // flags: active, table 0
        // Init expression: i32.const 1 (start at index 1, 0 = null)
        payload.push(0x41); // i32.const
        write_sleb128(&mut payload, 1);
        payload.push(0x0B); // end
        // Function indices.
        write_leb128(&mut payload, merged.table_entries.len() as u32);
        for &func_idx in &merged.table_entries {
            write_leb128(&mut payload, func_idx);
        }
        write_section(&mut out, SECTION_ELEMENT, &payload);
    }

    // DataCount section (required when passive segments are used).
    if merged.use_passive_segments {
        let mut payload = Vec::new();
        write_leb128(&mut payload, merged.data_segments.len() as u32);
        write_section(&mut out, SECTION_DATACOUNT, &payload);
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

    // Data section (spec §9.1): merged data segments.
    if !merged.data_segments.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, merged.data_segments.len() as u32);
        for seg in &merged.data_segments {
            if merged.use_passive_segments {
                // Passive segment: flag=0x01, no init expression.
                payload.push(0x01);
            } else if is_shared {
                if let Some(mb_idx) = merged.memory_base_global_idx {
                    // PIC: use global.get __memory_base as init expression.
                    payload.push(0x00);
                    payload.push(0x23); // global.get
                    write_leb128(&mut payload, mb_idx);
                    payload.push(0x0B);
                } else {
                    payload.push(0x00);
                    payload.push(0x41);
                    write_sleb128(&mut payload, seg.memory_offset as i32);
                    payload.push(0x0B);
                }
            } else {
                // Active segment: flag=0x00, i32.const offset.
                payload.push(0x00);
                payload.push(0x41);
                write_sleb128(&mut payload, seg.memory_offset as i32);
                payload.push(0x0B);
            }
            // Data bytes.
            write_leb128(&mut payload, seg.data.len() as u32);
            payload.extend_from_slice(&seg.data);
        }
        write_section(&mut out, SECTION_DATA, &payload);
    }

    // Custom sections: user sections first, then name, then target_features.
    // This matches wasm-ld ordering.
    if !layout.symbol_db.args.should_strip_all() {
        // User custom sections (not name, not target_features).
        for cs in &merged.custom_sections {
            if cs.name != b"target_features" {
                let mut custom_payload = Vec::new();
                write_name(&mut custom_payload, &cs.name);
                custom_payload.extend_from_slice(&cs.data);
                write_section(&mut out, 0, &custom_payload);
            }
        }
    }

    // Name section (custom section "name") — maps function indices to names.
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

        // Subsection 7: global names (only when globals are defined).
        if !merged.globals.is_empty() && !is_shared {
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

    // target_features custom section — last.
    if !layout.symbol_db.args.should_strip_all() {
        for cs in &merged.custom_sections {
            if cs.name == b"target_features" {
                let mut custom_payload = Vec::new();
                write_name(&mut custom_payload, &cs.name);
                custom_payload.extend_from_slice(&cs.data);
                write_section(&mut out, 0, &custom_payload);
            }
        }
    }

    // Compress padded LEB128 in function bodies when --compress-relocations.
    // wasm-ld only compresses on explicit request; default keeps padded form.
    #[cfg(feature = "wasm-opt")]
    let out = if layout.symbol_db.args.compress_relocations {
        let module = wilt::WasmModule::parse(&out).unwrap_or_else(|_| {
            panic!("wilt: failed to parse wild's output for LEB compression")
        });
        wilt::passes::compress::apply(&module)
    } else {
        out
    };

    // Post-link optimization via wilt (constant folding).
    #[cfg(feature = "wasm-opt")]
    let out = {
        let module = wilt::WasmModule::parse(&out).unwrap_or_else(|_| {
            panic!("wilt: failed to parse wild's output")
        });
        wilt::passes::const_fold::apply(&module)
    };

    std::fs::write(output_path.as_ref(), &out)?;

    // Validate output if requested.
    if std::env::var("WILD_VALIDATE_OUTPUT").is_ok() {
        validate_output(&out)?;
    }

    Ok(())
}

/// Write relocatable output (-r flag).
/// Merges input objects into a single .o file with linking section.
fn write_relocatable<A: Arch<Platform = Wasm>>(
    layout: &Layout<'_, Wasm>,
) -> crate::error::Result {
    let output_path = layout.symbol_db.args.output();

    // Parse all input objects and merge types/functions.
    let mut types: Vec<FuncType> = Vec::new();
    let mut functions: Vec<(u32, Vec<u8>)> = Vec::new(); // (type_index, body)
    let mut symbol_entries: Vec<(u8, Vec<u8>, u32, u32)> = Vec::new(); // (kind, name, flags, index)
    let mut imports: Vec<(Vec<u8>, Vec<u8>, u8, u32)> = Vec::new(); // (module, field, kind, type_index)
    let mut num_func_imports = 0u32;
    let mut data_segments: Vec<(Vec<u8>, u32)> = Vec::new(); // (data, alignment)
    let mut segment_names: Vec<Vec<u8>> = Vec::new();
    let mut code_relocs: Vec<WasmReloc> = Vec::new();
    let mut data_relocs: Vec<WasmReloc> = Vec::new();
    let mut custom_sections: Vec<CustomSection> = Vec::new();
    let mut custom_section_index: std::collections::HashMap<Vec<u8>, usize> = Default::default();
    let mut total_functions = 0u32;
    let mut total_data_segments = 0u32;
    let mut func_sym_count = 0u32;

    for group in &layout.group_layouts {
        for file in &group.files {
            let FileLayout::Object(obj) = file else { continue; };
            let data = obj.object.data;
            if data.len() < 8 || &data[..4] != b"\0asm" { continue; }

            let parsed = parse_wasm_sections(data)?;

            // Type dedup.
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
            let seg_base = total_data_segments;

            // Collect imports (pass through).
            for imp in &parsed.imports {
                let remapped_type = if imp.kind == 0 {
                    type_map.get(imp.type_index as usize).copied().unwrap_or(imp.type_index)
                } else {
                    imp.type_index
                };
                imports.push((imp.module.clone(), imp.field.clone(), imp.kind, remapped_type));
                if imp.kind == 0 { num_func_imports += 1; }
            }

            // Collect functions.
            for func in &parsed.functions {
                let remapped_type = type_map.get(func.type_index as usize)
                    .copied().unwrap_or(func.type_index);
                functions.push((remapped_type, func.body.clone()));
            }

            // Collect symbols for the linking section.
            for sym in &parsed.symbols {
                let mut new_index = sym.index;
                let mut new_seg = sym.segment_index;
                match sym.kind {
                    0 => {
                        // FUNCTION: adjust index
                        if (sym.flags & 0x10) == 0 && sym.index >= parsed.num_function_imports {
                            new_index = func_base + (sym.index - parsed.num_function_imports)
                                + num_func_imports;
                        }
                    }
                    1 => {
                        // DATA: adjust segment index
                        if (sym.flags & 0x10) == 0 {
                            new_seg = seg_base + sym.segment_index;
                        }
                    }
                    _ => {}
                }
                symbol_entries.push((sym.kind, sym.name.clone(), sym.flags, new_index));
                func_sym_count += 1;
                let _ = new_seg; // TODO: use for data symbol relocation
            }

            // Collect data segments.
            for seg in &parsed.data_segments {
                data_segments.push((seg.data.clone(), seg.alignment));
                segment_names.push(seg.name.clone());
            }

            // Collect code relocations.
            for reloc in &parsed.code_relocations {
                code_relocs.push(reloc.clone());
            }

            // Collect custom sections (concatenate same-name, first-wins for target_features).
            for cs in &parsed.custom_sections {
                if cs.name == b"target_features" {
                    if !custom_section_index.contains_key(&cs.name) {
                        custom_section_index.insert(cs.name.clone(), custom_sections.len());
                        custom_sections.push(CustomSection {
                            name: cs.name.clone(),
                            data: cs.data.clone(),
                        });
                    }
                } else if let Some(&idx) = custom_section_index.get(&cs.name) {
                    custom_sections[idx].data.extend_from_slice(&cs.data);
                } else {
                    custom_section_index.insert(cs.name.clone(), custom_sections.len());
                    custom_sections.push(CustomSection {
                        name: cs.name.clone(),
                        data: cs.data.clone(),
                    });
                }
            }

            total_functions += parsed.functions.len() as u32;
            total_data_segments += parsed.data_segments.len() as u32;
        }
    }

    // Build output.
    let mut out = Vec::new();
    out.extend_from_slice(b"\0asm");
    out.extend_from_slice(&1u32.to_le_bytes());

    // Type section.
    if !types.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, types.len() as u32);
        for ty in &types {
            payload.push(0x60);
            write_leb128(&mut payload, ty.params.len() as u32);
            payload.extend_from_slice(&ty.params);
            write_leb128(&mut payload, ty.results.len() as u32);
            payload.extend_from_slice(&ty.results);
        }
        write_section(&mut out, SECTION_TYPE, &payload);
    }

    // Import section.
    if !imports.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, imports.len() as u32);
        for (module, field, kind, type_idx) in &imports {
            write_name(&mut payload, module);
            write_name(&mut payload, field);
            payload.push(*kind);
            match kind {
                0 => write_leb128(&mut payload, *type_idx), // function
                3 => {
                    // global: type_index encodes valtype<<1|mutable
                    payload.push((*type_idx >> 1) as u8);
                    payload.push((*type_idx & 1) as u8);
                }
                _ => write_leb128(&mut payload, *type_idx),
            }
        }
        write_section(&mut out, 2, &payload);
    }

    // Function section.
    if !functions.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, functions.len() as u32);
        for (type_idx, _) in &functions {
            write_leb128(&mut payload, *type_idx);
        }
        write_section(&mut out, SECTION_FUNCTION, &payload);
    }

    // Memory section (minimal, one memory with min 0).
    {
        let mut payload = Vec::new();
        write_leb128(&mut payload, 1);
        payload.push(0x00); // no max
        write_leb128(&mut payload, 0); // min pages = 0
        write_section(&mut out, SECTION_MEMORY, &payload);
    }

    // Code section.
    let code_section_offset = out.len();
    if !functions.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, functions.len() as u32);
        for (_, body) in &functions {
            write_leb128(&mut payload, body.len() as u32);
            payload.extend_from_slice(body);
        }
        write_section(&mut out, SECTION_CODE, &payload);
    }

    // Data section.
    if !data_segments.is_empty() {
        let mut payload = Vec::new();
        write_leb128(&mut payload, data_segments.len() as u32);
        for (data, _align) in &data_segments {
            payload.push(0x00); // active, memory 0
            payload.push(0x41); // i32.const
            write_sleb128(&mut payload, 0); // offset 0
            payload.push(0x0B); // end
            write_leb128(&mut payload, data.len() as u32);
            payload.extend_from_slice(data);
        }
        write_section(&mut out, SECTION_DATA, &payload);
    }

    // User custom sections (before linking section, but after standard sections).
    for cs in &custom_sections {
        if cs.name != b"target_features" {
            let mut cp = Vec::new();
            write_name(&mut cp, &cs.name);
            cp.extend_from_slice(&cs.data);
            write_section(&mut out, 0, &cp);
        }
    }

    // Linking section (custom section "linking").
    {
        let mut link_data = Vec::new();
        write_leb128(&mut link_data, 2); // version

        // WASM_SYMBOL_TABLE (subsection 8).
        let mut sym_payload = Vec::new();
        write_leb128(&mut sym_payload, symbol_entries.len() as u32);
        for (kind, name, flags, index) in &symbol_entries {
            sym_payload.push(*kind);
            write_leb128(&mut sym_payload, *flags);
            match kind {
                0 | 2 => {
                    // FUNCTION / GLOBAL: index + name
                    write_leb128(&mut sym_payload, *index);
                    if (flags & 0x10) == 0 || (flags & 0x40) != 0 {
                        write_name(&mut sym_payload, name);
                    }
                }
                1 => {
                    // DATA: name + (if defined: segment, offset, size)
                    write_name(&mut sym_payload, name);
                    if (flags & 0x10) == 0 {
                        write_leb128(&mut sym_payload, 0); // segment
                        write_leb128(&mut sym_payload, 0); // offset
                        write_leb128(&mut sym_payload, 0); // size
                    }
                }
                _ => {
                    write_leb128(&mut sym_payload, *index);
                    if (flags & 0x10) == 0 || (flags & 0x40) != 0 {
                        write_name(&mut sym_payload, name);
                    }
                }
            }
        }
        link_data.push(8); // WASM_SYMBOL_TABLE
        write_leb128(&mut link_data, sym_payload.len() as u32);
        link_data.extend_from_slice(&sym_payload);

        // WASM_SEGMENT_INFO (subsection 5).
        if !segment_names.is_empty() {
            let mut seg_payload = Vec::new();
            write_leb128(&mut seg_payload, segment_names.len() as u32);
            for (i, name) in segment_names.iter().enumerate() {
                write_name(&mut seg_payload, name);
                let align = data_segments.get(i).map(|(_, a)| *a).unwrap_or(1);
                let align_log2 = if align > 1 { align.trailing_zeros() } else { 0 };
                write_leb128(&mut seg_payload, align_log2);
                write_leb128(&mut seg_payload, 0); // flags
            }
            link_data.push(5);
            write_leb128(&mut link_data, seg_payload.len() as u32);
            link_data.extend_from_slice(&seg_payload);
        }

        let mut custom_payload = Vec::new();
        write_name(&mut custom_payload, b"linking");
        custom_payload.extend_from_slice(&link_data);
        write_section(&mut out, 0, &custom_payload);
    }

    // target_features (after linking).
    for cs in &custom_sections {
        if cs.name == b"target_features" {
            let mut cp = Vec::new();
            write_name(&mut cp, &cs.name);
            cp.extend_from_slice(&cs.data);
            write_section(&mut out, 0, &cp);
        }
    }

    std::fs::write(output_path.as_ref(), &out)?;
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
    memory_offset: Addr,
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
    Table { min: u32 },
    Memory { min: u32 },
    Global { valtype: u8, mutable: bool },
    /// Exception-handling tag (EH proposal). Value is the type index.
    Tag(u32),
}

/// A custom section to pass through to the output.
struct CustomSection {
    name: Vec<u8>,
    data: Vec<u8>,
}

struct MergedModule {
    types: Vec<FuncType>,
    functions: Vec<MergedFunction>,
    entry_function_index: Option<u32>,
    /// Map from symbol name to output function index.
    function_name_map: std::collections::HashMap<Vec<u8>, u32>,
    /// Function indices that are explicitly exported via --export/--export-if-defined.
    explicit_export_indices: Vec<u32>,
    /// Function names with VISIBILITY_HIDDEN (flag 0x04) — excluded from --export-dynamic.
    hidden_functions: std::collections::HashSet<Vec<u8>>,
    /// Functions with WASM_SYM_NO_STRIP flag (spec §4.2, flag 0x80).
    no_strip_indices: Vec<u32>,
    /// Functions with WASM_SYM_EXPORTED flag (spec §4.2, flag 0x20).
    exported_indices: Vec<u32>,
    /// Linker-defined globals (e.g. __stack_pointer).
    globals: Vec<OutputGlobal>,
    /// Map from global name to output global index.
    global_name_map: std::collections::HashMap<Vec<u8>, u32>,
    /// Merged data segments.
    data_segments: Vec<OutputDataSegment>,
    /// Total data size (for memory section computation).
    data_size: Addr,
    /// __stack_pointer initial value (for --no-stack-first memory calc).
    stack_pointer_value: Addr,
    /// Max data segment alignment (for dylink.0 MemoryAlignment).
    max_data_alignment: u32,
    /// Indirect function table: maps table index → function index.
    /// Per spec §9.4: entries start at index 1 (0 = null/trap).
    table_entries: Vec<u32>,
    /// Map from function index to table index (for relocation patching).
    func_to_table_index: std::collections::HashMap<u32, u32>,
    /// Imports for unresolved symbols.
    imports: Vec<OutputImport>,
    /// Number of imported functions (affects function index space).
    num_imported_functions: u32,
    /// Number of imported globals (affects global index space).
    num_imported_globals: u32,
    /// Index of __memory_base imported global (for PIC data segments).
    memory_base_global_idx: Option<u32>,
    /// Whether to use passive data segments (--shared-memory with data).
    use_passive_segments: bool,
    /// Function index of __wasm_init_memory (for start section).
    init_memory_func_idx: Option<u32>,
    /// Custom sections to pass through (e.g. target_features).
    custom_sections: Vec<CustomSection>,
    /// EH tags defined in the output (each entry is a type index).
    /// Tag imports live in `imports`; these are the local definitions.
    output_tags: Vec<u32>,
    /// Tag symbol names → output tag index (imports and defs). Used by the
    /// export pass to emit kind-0x04 exports for `WASM_SYM_EXPORTED` tags.
    tag_name_map: std::collections::HashMap<Vec<u8>, u32>,
    /// Tag names flagged `VISIBILITY_HIDDEN` — suppressed from
    /// --export-dynamic.
    hidden_tags: std::collections::HashSet<Vec<u8>>,
    /// Tag names flagged `WASM_SYM_EXPORTED`.
    exported_tag_names: std::collections::HashSet<Vec<u8>>,
}

impl MergedModule {
    fn function_by_name(&self, name: &[u8]) -> Option<u32> {
        self.function_name_map.get(name).copied()
    }
}

/// GC: remove unreferenced functions and remap indices.
/// Per spec §9.1, output only contains entries for referenced functions.
fn gc_functions(merged: &mut MergedModule, export_all_dynamic: bool) {
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
    // When --export-dynamic (or shared mode), all named functions are roots.
    if export_all_dynamic {
        for &func_idx in merged.function_name_map.values() {
            if (func_idx as usize) < num_funcs {
                reachable[func_idx as usize] = true;
            }
        }
    }
    // WASM_SYM_EXPORTED functions are roots (spec §4.2, flag 0x20).
    for &func_idx in &merged.exported_indices {
        if (func_idx as usize) < num_funcs {
            reachable[func_idx as usize] = true;
        }
    }
    // WASM_SYM_NO_STRIP functions are roots (spec §4.2, flag 0x80).
    for &func_idx in &merged.no_strip_indices {
        if (func_idx as usize) < num_funcs {
            reachable[func_idx as usize] = true;
        }
    }
    // Functions referenced via indirect function table are roots.
    for &func_idx in &merged.table_entries {
        if (func_idx as usize) < num_funcs {
            reachable[func_idx as usize] = true;
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
            // Scan for call instructions with basic opcode awareness.
            // Skip known immediate operands to reduce false positives.
            while pos < body.len() {
                let opcode = body[pos];
                pos += 1;
                match opcode {
                    0x10 => {
                        // call funcidx
                        if let Ok((func_idx, c)) = read_leb128(&body[pos..]) {
                            pos += c;
                            if func_idx < num_funcs && !reachable[func_idx] {
                                reachable[func_idx] = true;
                                changed = true;
                            }
                        }
                    }
                    0x11 => {
                        // call_indirect: typeidx + tableidx (two LEB128s)
                        if let Ok((_, c)) = read_leb128(&body[pos..]) { pos += c; }
                        if let Ok((_, c)) = read_leb128(&body[pos..]) { pos += c; }
                    }
                    // Block/loop/if with block type
                    0x02 | 0x03 | 0x04 => {
                        if pos < body.len() {
                            if body[pos] == 0x40 {
                                pos += 1; // void block type
                            } else if body[pos] < 0x80 {
                                pos += 1; // value type
                            } else {
                                // Signed LEB128 type index
                                if let Ok((_, c)) = read_leb128(&body[pos..]) { pos += c; }
                            }
                        }
                    }
                    // br, br_if: labelidx
                    0x0C | 0x0D => {
                        if let Ok((_, c)) = read_leb128(&body[pos..]) { pos += c; }
                    }
                    // br_table: vec(labelidx) + labelidx
                    0x0E => {
                        if let Ok((count, c)) = read_leb128(&body[pos..]) {
                            pos += c;
                            for _ in 0..=count {
                                if let Ok((_, c)) = read_leb128(&body[pos..]) { pos += c; }
                            }
                        }
                    }
                    // local.get/set/tee, global.get/set
                    0x20..=0x24 => {
                        if let Ok((_, c)) = read_leb128(&body[pos..]) { pos += c; }
                    }
                    // Memory load/store: align + offset (two LEB128s)
                    0x28..=0x3E => {
                        if let Ok((_, c)) = read_leb128(&body[pos..]) { pos += c; }
                        if let Ok((_, c)) = read_leb128(&body[pos..]) { pos += c; }
                    }
                    // memory.size, memory.grow: memory index
                    0x3F | 0x40 => {
                        if let Ok((_, c)) = read_leb128(&body[pos..]) { pos += c; }
                    }
                    // i32.const
                    0x41 => {
                        // Signed LEB128
                        if let Ok((_, c)) = read_leb128(&body[pos..]) { pos += c; }
                    }
                    // i64.const
                    0x42 => {
                        if let Ok((_, c)) = read_leb128(&body[pos..]) { pos += c; }
                    }
                    // f32.const
                    0x43 => { pos += 4; }
                    // f64.const
                    0x44 => { pos += 8; }
                    // All other opcodes have no immediates
                    _ => {}
                }
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

    // Remap exported_indices.
    merged.exported_indices = merged
        .exported_indices
        .iter()
        .filter_map(|&old_idx| index_map.get(old_idx as usize).copied().flatten())
        .collect();

    // Remap table entries.
    merged.table_entries = merged
        .table_entries
        .iter()
        .filter_map(|&old_idx| index_map.get(old_idx as usize).copied().flatten())
        .collect();
    merged.func_to_table_index = merged
        .table_entries
        .iter()
        .enumerate()
        .map(|(i, &func_idx)| (func_idx, (i + 1) as u32))
        .collect();

    // GC unused types — keep types referenced by functions AND imports.
    let mut type_used = vec![false; merged.types.len()];
    for func in &merged.functions {
        if (func.type_index as usize) < type_used.len() {
            type_used[func.type_index as usize] = true;
        }
    }
    for imp in &merged.imports {
        if let ImportKind::Function(type_idx) = &imp.kind {
            if (*type_idx as usize) < type_used.len() {
                type_used[*type_idx as usize] = true;
            }
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
    // Remap type indices in functions and imports.
    for func in &mut merged.functions {
        if let Some(new_idx) = type_map.get(func.type_index as usize).copied().flatten() {
            func.type_index = new_idx;
        }
    }
    for imp in &mut merged.imports {
        if let ImportKind::Function(ref mut type_idx) = imp.kind {
            if let Some(new_idx) = type_map.get(*type_idx as usize).copied().flatten() {
                *type_idx = new_idx;
            }
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
    // Dedup set for unhandled-relocation diagnostics: warn once per type per link
    // so silent fall-throughs in the reloc match arms are at least visible.
    let mut warned_reloc_types: std::collections::HashSet<u8> =
        std::collections::HashSet::new();
    let mut types: Vec<FuncType> = Vec::new();
    let mut function_name_map: std::collections::HashMap<Vec<u8>, u32> = Default::default();
    // Track whether each function definition is weak (for strong/weak resolution per §9.2).
    let mut function_is_weak: std::collections::HashMap<Vec<u8>, bool> = Default::default();
    // Track functions with hidden visibility (flag 0x04) — excluded from --export-dynamic.
    let mut function_is_hidden: std::collections::HashSet<Vec<u8>> = Default::default();
    let mut entry_function_index: Option<u32> = None;
    let mut no_strip_indices: Vec<u32> = Vec::new();
    // Functions with WASM_SYM_EXPORTED flag (spec §4.2, flag 0x20).
    let mut exported_indices: Vec<u32> = Vec::new();

    // --- Pass 1: parse all objects, collect types and functions ---
    struct ObjectInfo {
        parsed: ParsedInput,
        type_map: Vec<u32>,
        func_base: u32,
        /// Local function indices from duplicate COMDAT groups (to skip).
        comdat_skip_functions: std::collections::HashSet<u32>,
        /// Local data segment indices from duplicate COMDAT groups (to skip).
        comdat_skip_data: std::collections::HashSet<u32>,
        /// Local tag indices from duplicate COMDAT groups (to skip).
        comdat_skip_tags: std::collections::HashSet<u32>,
    }
    let mut objects: Vec<ObjectInfo> = Vec::new();
    let mut total_functions = 0u32;
    // COMDAT groups (spec §7): first definition wins, duplicates discarded.
    let mut seen_comdat_groups: std::collections::HashSet<Vec<u8>> = Default::default();

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

            // Spec §8 / memory64: reject mem64 inputs when the link isn't
            // configured for memory64 (pass `--features=+memory64`,
            // `-mwasm64`, or `--target=wasm64-…`).
            if parsed.is_memory64 && !layout.symbol_db.args.memory64 {
                crate::bail!(
                    "input object has a memory64 memory import but the link \
                     is 32-bit; pass --features=+memory64 (or -mwasm64) to enable"
                );
            }

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

            // COMDAT dedup (spec §7): first group wins, duplicates discarded.
            // Build a set of local function indices that belong to duplicate groups.
            let mut comdat_skip_functions: std::collections::HashSet<u32> = Default::default();
            let mut comdat_skip_data: std::collections::HashSet<u32> = Default::default();
            let mut comdat_skip_tags: std::collections::HashSet<u32> = Default::default();
            for (group_name, entries) in &parsed.comdat_groups {
                if !seen_comdat_groups.insert(group_name.clone()) {
                    // Duplicate group — mark all its entries for skipping.
                    for &(kind, index) in entries {
                        match kind {
                            0 => { comdat_skip_data.insert(index); }
                            1 => { comdat_skip_functions.insert(index); }
                            3 => { comdat_skip_tags.insert(index); }
                            _ => {}
                        }
                    }
                }
            }

            let func_base = total_functions;

            // Record function names → output indices with weak/strong resolution (§9.2).
            for (i, _) in parsed.functions.iter().enumerate() {
                // Skip functions from duplicate COMDAT groups.
                if comdat_skip_functions.contains(&(i as u32)) {
                    continue;
                }
                if let Some(name) = parsed.function_names.get(&(i as u32)) {
                    let output_idx = func_base + i as u32;
                    // Check symbol flags for this function.
                    let sym_flags = parsed.symbols.iter()
                        .find(|sym| sym.kind == 0 && !sym.name.is_empty() && sym.name == *name)
                        .map(|sym| sym.flags)
                        .unwrap_or(0);
                    let is_weak = (sym_flags & 0x01) != 0;
                    let is_hidden = (sym_flags & 0x04) != 0;
                    // Per spec §9.2: strong overrides weak. If existing is weak
                    // and new is strong, override. If both strong, first wins.
                    let should_insert = match function_is_weak.get(name) {
                        None => true,                          // first definition
                        Some(true) if !is_weak => true,        // strong overrides weak
                        _ => false,                            // keep existing
                    };
                    if should_insert {
                        function_name_map.insert(name.clone(), output_idx);
                        function_is_weak.insert(name.clone(), is_weak);
                        if is_hidden {
                            function_is_hidden.insert(name.clone());
                        } else {
                            function_is_hidden.remove(name);
                        }
                        if name == entry_name {
                            entry_function_index = Some(output_idx);
                        }
                    }
                }
            }
            // Check flags on function symbols (spec §4.2).
            for sym in &parsed.symbols {
                if sym.kind == 0 && sym.index >= parsed.num_function_imports {
                    let output_idx = func_base + (sym.index - parsed.num_function_imports);
                    // NO_STRIP (0x80): include in output regardless of usage.
                    if (sym.flags & 0x80) != 0 {
                        no_strip_indices.push(output_idx);
                    }
                    // EXPORTED (0x20): exported to host environment.
                    if (sym.flags & 0x20) != 0 {
                        exported_indices.push(output_idx);
                    }
                }
            }

            total_functions += parsed.functions.len() as u32;
            objects.push(ObjectInfo {
                parsed,
                type_map,
                func_base,
                comdat_skip_functions,
                comdat_skip_data,
                comdat_skip_tags,
            });
        }
    }

    // Build set of data segments that only contain losing weak definitions.
    // These segments should be skipped in the data layout.
    let mut weak_data_names: std::collections::HashMap<Vec<u8>, usize> = Default::default(); // name → winning obj_idx
    for (obj_idx, obj_info) in objects.iter().enumerate() {
        for sym in &obj_info.parsed.symbols {
            if sym.kind == 1 && (sym.flags & 0x10) == 0 && !sym.name.is_empty() {
                let is_weak = (sym.flags & 0x01) != 0;
                match weak_data_names.entry(sym.name.clone()) {
                    std::collections::hash_map::Entry::Vacant(e) => { e.insert(obj_idx); }
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        // Strong overrides weak.
                        if !is_weak {
                            e.insert(obj_idx);
                        }
                    }
                }
            }
        }
    }
    // Mark segments to skip: segments whose ONLY defined data symbols are losing weaks.
    let mut weak_skip_segments: Vec<std::collections::HashSet<u32>> = Vec::new();
    for (obj_idx, obj_info) in objects.iter().enumerate() {
        let mut skip_set: std::collections::HashSet<u32> = Default::default();
        // Collect segments that have losing weak symbols.
        for sym in &obj_info.parsed.symbols {
            if sym.kind == 1 && (sym.flags & 0x10) == 0 && (sym.flags & 0x01) != 0
                && !sym.name.is_empty()
            {
                if let Some(&winner_idx) = weak_data_names.get(&sym.name) {
                    if winner_idx != obj_idx {
                        skip_set.insert(sym.segment_index as u32);
                    }
                }
            }
        }
        // Don't skip segments that also have non-losing symbols.
        for sym in &obj_info.parsed.symbols {
            if sym.kind == 1 && (sym.flags & 0x10) == 0 && !sym.name.is_empty() {
                let is_weak = (sym.flags & 0x01) != 0;
                if !is_weak || weak_data_names.get(&sym.name) == Some(&obj_idx) {
                    // This symbol is a winner — keep its segment.
                    skip_set.remove(&(sym.segment_index as u32));
                }
            }
        }
        weak_skip_segments.push(skip_set);
    }

    // --- Pass 1.5: layout data segments and build data symbol address map ---
    // Per spec §9.1: data placed after stack in linear memory.
    // Per spec §9.4: R_WASM_MEMORY_ADDR_* value = symbol offset in output segment + addend.
    let stack_size = layout
        .symbol_db
        .args
        .stack_size
        .unwrap_or(DEFAULT_STACK_SIZE as u64) as u32;
    let stack_first = layout.symbol_db.args.stack_first;
    // --global-base: override where data starts in linear memory.
    // --stack-first (default): data starts after stack.
    // --no-stack-first: data starts at global_base (default 1024), stack after data.
    let default_global_base = if stack_first { stack_size } else { 1024 };
    let mut data_offset = if let Some(base) = layout.symbol_db.args.global_base {
        base as u32
    } else {
        default_global_base
    };
    // Per-object: map from data segment index to output memory offset.
    let mut segment_output_offsets: Vec<Vec<u32>> = Vec::new();
    let data_start = data_offset;

    // Three-pass layout matching wasm-ld: .rodata.* first, .data.* second, .bss.* last.
    // This ensures data layout matches wasm-ld's segment merging by name prefix.
    for obj_info in &objects {
        segment_output_offsets.push(vec![0u32; obj_info.parsed.data_segments.len()]);
    }

    // Helper: determine if a segment should be skipped.
    let should_skip_seg = |obj_idx: usize, seg_i: usize| -> bool {
        objects[obj_idx].comdat_skip_data.contains(&(seg_i as u32))
            || weak_skip_segments[obj_idx].contains(&(seg_i as u32))
            || objects[obj_idx].parsed.data_segments.get(seg_i)
                .map_or(false, |s| s.name.starts_with(b".init_array"))
    };

    // Classify segments by name prefix.
    // Order: rodata (read-only) → data (read-write non-BSS) → BSS.
    let is_rodata = |seg: &ParsedDataSegment| -> bool {
        seg.name.starts_with(b".rodata")
    };
    let is_bss_name = |seg: &ParsedDataSegment| -> bool {
        // Use the segment name for BSS classification, not the data content.
        // Segments with relocation placeholders (all zeros) should NOT be
        // treated as BSS if their name is .data.*.
        if !seg.name.is_empty() {
            seg.name.starts_with(b".bss")
        } else {
            seg.data.iter().all(|&b| b == 0)
        }
    };

    // Layout helper: place segments in a group, aligning the group start to
    // the max alignment of any segment in the group.
    let layout_group = |objects: &[ObjectInfo],
                             offsets: &mut Vec<Vec<u32>>,
                             data_offset: &mut u32,
                             filter: &dyn Fn(usize, usize, &ParsedDataSegment) -> bool| {
        // Find max alignment in this group.
        let mut max_align = 1u32;
        for (obj_idx, obj_info) in objects.iter().enumerate() {
            for (seg_i, seg) in obj_info.parsed.data_segments.iter().enumerate() {
                if should_skip_seg(obj_idx, seg_i) || !filter(obj_idx, seg_i, seg) {
                    continue;
                }
                max_align = max_align.max(seg.alignment.max(1));
            }
        }
        // Align group start.
        *data_offset = (*data_offset + max_align - 1) & !(max_align - 1);
        // Place segments.
        for (obj_idx, obj_info) in objects.iter().enumerate() {
            for (seg_i, seg) in obj_info.parsed.data_segments.iter().enumerate() {
                if should_skip_seg(obj_idx, seg_i) || !filter(obj_idx, seg_i, seg) {
                    continue;
                }
                let align = seg.alignment.max(1);
                *data_offset = (*data_offset + align - 1) & !(align - 1);
                offsets[obj_idx][seg_i] = *data_offset;
                *data_offset += seg.data.len() as u32;
            }
        }
    };

    // Pass A: .rodata.* segments.
    layout_group(&objects, &mut segment_output_offsets, &mut data_offset,
        &|obj_idx, seg_i, seg| !should_skip_seg(obj_idx, seg_i) && is_rodata(seg));
    // Pass B: .data.* segments (non-BSS, non-rodata).
    layout_group(&objects, &mut segment_output_offsets, &mut data_offset,
        &|obj_idx, seg_i, seg| !should_skip_seg(obj_idx, seg_i) && !is_rodata(seg) && !is_bss_name(seg));
    // Pass C: .bss.* segments.
    layout_group(&objects, &mut segment_output_offsets, &mut data_offset,
        &|obj_idx, seg_i, seg| !should_skip_seg(obj_idx, seg_i) && is_bss_name(seg));

    // Compute group boundaries for rodata/data segments.
    let mut rodata_start: Option<u32> = None;
    let mut rodata_end: Option<u32> = None;
    let mut rw_data_start: Option<u32> = None;
    let mut rw_data_end: Option<u32> = None;
    for (obj_idx, obj_info) in objects.iter().enumerate() {
        for (seg_i, seg) in obj_info.parsed.data_segments.iter().enumerate() {
            if should_skip_seg(obj_idx, seg_i) || is_bss_name(seg) {
                continue;
            }
            let off = segment_output_offsets[obj_idx][seg_i];
            let end = off + seg.data.len() as u32;
            if is_rodata(seg) {
                rodata_start = Some(rodata_start.map_or(off, |s: u32| s.min(off)));
                rodata_end = Some(rodata_end.map_or(end, |e: u32| e.max(end)));
            } else {
                rw_data_start = Some(rw_data_start.map_or(off, |s: u32| s.min(off)));
                rw_data_end = Some(rw_data_end.map_or(end, |e: u32| e.max(end)));
            }
        }
    }

    // Merge data into per-group output segments (spec §9.1).
    // Groups: .rodata.* → one segment, .data.* → another, matching wasm-ld.
    // BSS segments are omitted (implicit in memory allocation).
    let mut data_segments = if data_offset > data_start {
        // Build merged data for the full range, then split into segments.
        let total_data_len = (data_offset - data_start) as usize;
        let mut merged_data = vec![0u8; total_data_len];
        for (obj_idx, obj_info) in objects.iter().enumerate() {
            for (seg_i, seg) in obj_info.parsed.data_segments.iter().enumerate() {
                if should_skip_seg(obj_idx, seg_i) {
                    continue;
                }
                let off = segment_output_offsets[obj_idx][seg_i] - data_start;
                merged_data[off as usize..off as usize + seg.data.len()]
                    .copy_from_slice(&seg.data);
            }
        }

        // Create separate output segments for each group.
        let mut segments = Vec::new();
        for (start, end) in [
            (rodata_start, rodata_end),
            (rw_data_start, rw_data_end),
        ] {
            if let (Some(s), Some(e)) = (start, end) {
                let rel_start = (s - data_start) as usize;
                let rel_end = (e - data_start) as usize;
                if rel_end > rel_start && rel_end <= merged_data.len() {
                    let data = merged_data[rel_start..rel_end].to_vec();
                    segments.push(OutputDataSegment {
                        memory_offset: s as Addr,
                        data,
                    });
                }
            }
        }
        segments
    } else {
        Vec::new()
    };
    // Track TLS data: find the first TLS segment's output offset and total TLS size.
    let mut tls_base_offset: Option<u32> = None;
    let mut tls_size: u32 = 0;
    let mut tls_align: u32 = 0;
    for obj_info in &objects {
        for (seg_i, seg) in obj_info.parsed.data_segments.iter().enumerate() {
            if seg.is_tls {
                let obj_idx = objects.iter().position(|o| std::ptr::eq(o, obj_info)).unwrap();
                if let Some(&off) = segment_output_offsets[obj_idx].get(seg_i) {
                    if tls_base_offset.is_none() {
                        tls_base_offset = Some(off);
                    }
                    let seg_end = off + seg.data.len() as u32;
                    let base = tls_base_offset.unwrap();
                    tls_size = tls_size.max(seg_end - base);
                    tls_align = tls_align.max(seg.alignment);
                }
            }
        }
    }

    // Build global data symbol name → output address map for cross-object resolution.
    let mut data_name_map: std::collections::HashMap<Vec<u8>, u32> = Default::default();
    for (obj_idx, obj_info) in objects.iter().enumerate() {
        let obj_seg_offsets = &segment_output_offsets[obj_idx];
        for sym in &obj_info.parsed.symbols {
            if sym.kind == 1 && (sym.flags & 0x10) == 0 && !sym.name.is_empty() {
                // Skip data symbols from COMDAT-skipped or weak-losing segments.
                if obj_info.comdat_skip_data.contains(&(sym.segment_index as u32))
                    || weak_skip_segments[obj_idx].contains(&(sym.segment_index as u32))
                {
                    continue;
                }
                // Defined data symbol with a name.
                if let Some(&seg_base) = obj_seg_offsets.get(sym.segment_index as usize) {
                    data_name_map.insert(sym.name.clone(), seg_base + sym.segment_offset);
                }
            }
        }
    }

    // Add linker-defined data symbols to the global map.
    let data_end_addr = data_offset;
    data_name_map.insert(b"__data_end".to_vec(), data_end_addr);
    data_name_map.insert(b"__heap_base".to_vec(), data_end_addr);

    let data_size = if data_offset > data_start {
        data_offset - data_start
    } else {
        0
    };

    // --- Create linker-defined globals (spec §9.6) ---
    let mut globals: Vec<OutputGlobal> = Vec::new();
    let mut global_name_map: std::collections::HashMap<Vec<u8>, u32> = Default::default();

    // __stack_pointer: mutable i32, init to top of stack.
    // --stack-first: stack at 0..stack_size, sp = stack_size.
    // --no-stack-first: stack above data, sp = align(data_end, 16) + stack_size.
    let stack_pointer_value = if stack_first {
        stack_size
    } else {
        let aligned_data_end = (data_offset + 15) & !15;
        aligned_data_end + stack_size
    };
    let sp_index = globals.len() as u32;
    global_name_map.insert(b"__stack_pointer".to_vec(), sp_index);
    globals.push(OutputGlobal {
        name: b"__stack_pointer".to_vec(),
        valtype: VALTYPE_I32,
        mutable: true,
        init_value: stack_pointer_value as u64,
        exported: false,
    });

    // TLS globals: created when TLS data exists OR --shared-memory is used.
    let has_tls = tls_base_offset.is_some() || tls_size > 0
        || layout.symbol_db.args.shared_memory;
    // __tls_base: mutable i32 — points to TLS data start in non-shared mode.
    if has_tls {
        let tls_idx = globals.len() as u32;
        global_name_map.insert(b"__tls_base".to_vec(), tls_idx);
        globals.push(OutputGlobal {
            name: b"__tls_base".to_vec(),
            valtype: VALTYPE_I32,
            mutable: true,
            init_value: tls_base_offset.unwrap_or(0) as u64,
            exported: false,
        });
    }

    // __tls_size: immutable i32 — total TLS data size.
    if has_tls {
        let idx = globals.len() as u32;
        global_name_map.insert(b"__tls_size".to_vec(), idx);
        globals.push(OutputGlobal {
            name: b"__tls_size".to_vec(),
            valtype: VALTYPE_I32,
            mutable: false,
            init_value: tls_size as u64,
            exported: false,
        });
    }

    // __tls_align: immutable i32 — max TLS alignment.
    if has_tls {
        let idx = globals.len() as u32;
        global_name_map.insert(b"__tls_align".to_vec(), idx);
        globals.push(OutputGlobal {
            name: b"__tls_align".to_vec(),
            valtype: VALTYPE_I32,
            mutable: false,
            init_value: tls_align as u64,
            exported: false,
        });
    }

    // __data_end / __heap_base: only emitted when there are actual data segments
    // in the output (not BSS-only) or when explicitly exported.
    let data_end = data_start + data_size;
    let has_data_segments = !data_segments.is_empty();
    let exports_data_end = layout
        .symbol_db
        .args
        .exports
        .iter()
        .any(|s| s == "__data_end");
    let exports_heap_base = layout
        .symbol_db
        .args
        .exports
        .iter()
        .any(|s| s == "__heap_base");

    if has_data_segments || exports_data_end {
        let de_index = globals.len() as u32;
        global_name_map.insert(b"__data_end".to_vec(), de_index);
        globals.push(OutputGlobal {
            name: b"__data_end".to_vec(),
            valtype: VALTYPE_I32,
            mutable: false,
            init_value: data_end as u64,
            exported: has_data_segments || exports_data_end,
        });
    }

    // Linker-defined globals ordered to match wasm-ld:
    // __data_end (above), __rodata_start, __rodata_end, __heap_base, __global_base.
    let all_exports = &layout.symbol_db.args.exports;

    if all_exports.iter().any(|s| s == "__rodata_start") {
        let idx = globals.len() as u32;
        global_name_map.insert(b"__rodata_start".to_vec(), idx);
        globals.push(OutputGlobal {
            name: b"__rodata_start".to_vec(),
            valtype: VALTYPE_I32,
            mutable: false,
            init_value: rodata_start.unwrap_or(data_start) as u64,
            exported: true,
        });
    }
    if all_exports.iter().any(|s| s == "__rodata_end") {
        let idx = globals.len() as u32;
        global_name_map.insert(b"__rodata_end".to_vec(), idx);
        globals.push(OutputGlobal {
            name: b"__rodata_end".to_vec(),
            valtype: VALTYPE_I32,
            mutable: false,
            init_value: rodata_end.unwrap_or(data_start) as u64,
            exported: true,
        });
    }

    if has_data_segments || exports_heap_base {
        let mut max_data_align = 1u32;
        for obj_info in &objects {
            for seg in &obj_info.parsed.data_segments {
                max_data_align = max_data_align.max(seg.alignment.max(1));
            }
        }
        let heap_base = (data_end + max_data_align - 1) & !(max_data_align - 1);
        let hb_index = globals.len() as u32;
        global_name_map.insert(b"__heap_base".to_vec(), hb_index);
        globals.push(OutputGlobal {
            name: b"__heap_base".to_vec(),
            valtype: VALTYPE_I32,
            mutable: false,
            init_value: heap_base as u64,
            exported: has_data_segments || exports_heap_base,
        });
    }

    if all_exports.iter().any(|s| s == "__global_base") {
        let gb_index = globals.len() as u32;
        global_name_map.insert(b"__global_base".to_vec(), gb_index);
        globals.push(OutputGlobal {
            name: b"__global_base".to_vec(),
            valtype: VALTYPE_I32,
            mutable: false,
            init_value: data_start as u64,
            exported: true,
        });
    }

    // Add user-defined globals from input objects.
    // Order: immutable globals first, then mutable (matching wasm-ld).
    for obj_info in &objects {
        for (local_idx, ig) in obj_info.parsed.input_globals.iter().enumerate() {
            // Find the symbol name for this global via the linking section.
            let global_index_in_obj = obj_info.parsed.num_global_imports + local_idx as u32;
            let sym_name = obj_info.parsed.symbols.iter()
                .find(|s| s.kind == 2 && s.index == global_index_in_obj)
                .map(|s| s.name.clone())
                .unwrap_or_default();
            if sym_name.is_empty() || global_name_map.contains_key(&sym_name) {
                continue; // Skip unnamed or already-defined globals
            }
            if !ig.mutable {
                let idx = globals.len() as u32;
                global_name_map.insert(sym_name.clone(), idx);
                globals.push(OutputGlobal {
                    name: sym_name,
                    valtype: ig.valtype,
                    mutable: false,
                    init_value: ig.init_value,
                    exported: false,
                });
            }
        }
    }
    for obj_info in &objects {
        for (local_idx, ig) in obj_info.parsed.input_globals.iter().enumerate() {
            let global_index_in_obj = obj_info.parsed.num_global_imports + local_idx as u32;
            let sym_name = obj_info.parsed.symbols.iter()
                .find(|s| s.kind == 2 && s.index == global_index_in_obj)
                .map(|s| s.name.clone())
                .unwrap_or_default();
            if sym_name.is_empty() || global_name_map.contains_key(&sym_name) {
                continue;
            }
            if ig.mutable {
                let idx = globals.len() as u32;
                global_name_map.insert(sym_name.clone(), idx);
                globals.push(OutputGlobal {
                    name: sym_name,
                    valtype: ig.valtype,
                    mutable: true,
                    init_value: ig.init_value,
                    exported: false,
                });
            }
        }
    }

    // --- Pass 1.8: collect init functions and synthesize __wasm_call_ctors ---
    // This must happen BEFORE Pass 2 so relocs can resolve __wasm_call_ctors refs.
    let mut all_init_funcs: Vec<(u32, u32)> = Vec::new(); // (priority, output_func_idx)
    for obj_info in &objects {
        // From WASM_INIT_FUNCS (linking section §6).
        for init in &obj_info.parsed.init_functions {
            if let Some(sym) = obj_info.parsed.symbols.get(init.symbol_index as usize) {
                if sym.kind == 0 && sym.index >= obj_info.parsed.num_function_imports {
                    let local_idx = sym.index - obj_info.parsed.num_function_imports;
                    let output_idx = obj_info.func_base + local_idx;
                    all_init_funcs.push((init.priority, output_idx));
                }
            }
        }
        // From .init_array data segments.
        for (_seg_i, seg) in obj_info.parsed.data_segments.iter().enumerate() {
            if !seg.name.starts_with(b".init_array") {
                continue;
            }
            let priority = if seg.name.len() > 12 && seg.name[11] == b'.' {
                std::str::from_utf8(&seg.name[12..])
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(65535)
            } else {
                65535
            };
            let seg_data_start = seg.data_offset_in_section;
            let seg_data_end = seg_data_start + seg.data.len() as u32;
            for reloc in &obj_info.parsed.data_relocations {
                if reloc.offset < seg_data_start || reloc.offset >= seg_data_end {
                    continue;
                }
                if let Some(sym) = obj_info.parsed.symbols.get(reloc.symbol_index as usize) {
                    if sym.kind == 0 {
                        let output_idx = if !sym.name.is_empty() {
                            function_name_map.get(sym.name.as_slice()).copied()
                        } else if sym.index >= obj_info.parsed.num_function_imports {
                            Some(obj_info.func_base + (sym.index - obj_info.parsed.num_function_imports))
                        } else {
                            None
                        };
                        if let Some(idx) = output_idx {
                            all_init_funcs.push((priority, idx));
                        }
                    }
                }
            }
        }
    }

    let ctors_name = b"__wasm_call_ctors";
    let ctors_referenced = objects.iter().any(|obj| {
        obj.parsed.import_function_names.iter().any(|n| n == ctors_name)
    }) || entry_name == ctors_name;
    let needs_ctors = !all_init_funcs.is_empty() || ctors_referenced;

    if needs_ctors {
        all_init_funcs.sort_by_key(|(prio, _)| *prio);

        // Adjust all existing function indices by +1 for the ctors insertion.
        for idx in function_name_map.values_mut() {
            *idx += 1;
        }
        if let Some(ref mut idx) = entry_function_index {
            *idx += 1;
        }
        for idx in exported_indices.iter_mut() {
            *idx += 1;
        }
        for idx in no_strip_indices.iter_mut() {
            *idx += 1;
        }

        // Register __wasm_call_ctors at index 0.
        function_name_map.insert(b"__wasm_call_ctors".to_vec(), 0);
        if entry_name == ctors_name {
            entry_function_index = Some(0);
        }
    }

    // --- Pass 1.9: collect EH tags across all objects via symbol-name
    // resolution, mirroring the function-merge rules in Pass 1 (§9.2 and §7).
    //
    // Pipeline:
    //   1. Walk every kind-4 (SYMTAB_EVENT) symbol from every object.
    //   2. Strong overrides weak, first strong wins (same as functions).
    //   3. COMDAT-duplicate tags are dropped via `comdat_skip_tags`.
    //   4. A tag's "name" is the symbol name (if present) else the import
    //      field name per spec §4.3.
    //   5. Imported tags are emitted first in the output index space, then
    //      local definitions. Symbols that lose resolution still get a
    //      `symbol_to_output_tag` entry pointing at the winner so relocs
    //      still patch correctly.
    let mut output_tag_imports: Vec<(Vec<u8>, Vec<u8>, u32)> = Vec::new(); // (module, field, type_idx)
    let mut output_tag_defs: Vec<u32> = Vec::new();
    let mut tag_name_map: std::collections::HashMap<Vec<u8>, u32> = Default::default();
    let mut tag_is_weak: std::collections::HashMap<Vec<u8>, bool> = Default::default();
    let mut tag_is_hidden: std::collections::HashSet<Vec<u8>> = Default::default();
    let mut exported_tag_name_set: std::collections::HashSet<Vec<u8>> = Default::default();
    let mut per_obj_tag_map: Vec<std::collections::HashMap<u32, u32>> =
        vec![Default::default(); objects.len()];

    // First sub-pass: collect imports (name → output import index).
    // An imported tag "defines" nothing, so strong/weak doesn't apply — but
    // if multiple objects import the same name, they share one output slot.
    let mut tag_import_index_by_name: std::collections::HashMap<Vec<u8>, u32> =
        Default::default();
    for (obj_idx, obj) in objects.iter().enumerate() {
        let p = &obj.parsed;
        for sym in &p.symbols {
            if sym.kind != 4 || (sym.flags & 0x10) == 0 {
                // Not a tag symbol or not an import.
                continue;
            }
            // Determine the key: symbol name if present, else the import field.
            let name = if !sym.name.is_empty() {
                sym.name.clone()
            } else if let Some(field) = p.import_tag_names.get(sym.index as usize) {
                field.clone()
            } else {
                continue;
            };
            if tag_import_index_by_name.contains_key(&name) {
                continue;
            }
            // Find the matching ParsedImport for module / type_idx.
            let (module, type_idx) = p
                .imports
                .iter()
                .find(|imp| imp.kind == 4 && imp.field == name)
                .map(|imp| (imp.module.clone(), imp.type_index))
                .unwrap_or_else(|| (b"env".to_vec(), 0));
            let out_idx = output_tag_imports.len() as u32;
            output_tag_imports.push((module, name.clone(), type_idx));
            tag_import_index_by_name.insert(name.clone(), out_idx);
            tag_name_map.insert(name, out_idx);
            let _ = obj_idx; // silence unused
        }
    }

    // Second sub-pass: collect local definitions with §9.2 resolution.
    // Defined tags can promote over imports with the same name (a definition
    // in one object wins over an import of the same name elsewhere).
    for obj in &objects {
        let p = &obj.parsed;
        for sym in &p.symbols {
            if sym.kind != 4 || (sym.flags & 0x10) != 0 {
                continue;
            }
            // Defined tag. Local tag index = sym.index (beyond imports).
            let local_def_idx = if sym.index >= p.num_tag_imports {
                sym.index - p.num_tag_imports
            } else {
                continue;
            };
            if obj.comdat_skip_tags.contains(&local_def_idx) {
                continue;
            }
            let Some(&type_idx) = p.tags.get(local_def_idx as usize) else {
                continue;
            };
            let name = sym.name.clone();
            if name.is_empty() {
                // Unnamed defined tags are kept verbatim (rare; pass through).
                let out_idx =
                    (output_tag_imports.len() + output_tag_defs.len()) as u32;
                output_tag_defs.push(type_idx);
                let _ = out_idx;
                continue;
            }
            let is_weak = (sym.flags & 0x01) != 0;
            let is_hidden = (sym.flags & 0x04) != 0;
            let existing = tag_name_map.get(&name).copied();
            let existing_weak = tag_is_weak.get(&name).copied();
            let existing_is_import =
                existing.is_some() && tag_import_index_by_name.contains_key(&name);

            let should_claim = match (existing, existing_weak) {
                (None, _) => true, // brand new
                (Some(_), _) if existing_is_import => true, // def wins over import
                (Some(_), Some(true)) if !is_weak => true, // strong over weak
                _ => false,
            };
            if should_claim {
                let out_idx =
                    (output_tag_imports.len() + output_tag_defs.len()) as u32;
                output_tag_defs.push(type_idx);
                tag_name_map.insert(name.clone(), out_idx);
                tag_is_weak.insert(name.clone(), is_weak);
                if is_hidden {
                    tag_is_hidden.insert(name.clone());
                } else {
                    tag_is_hidden.remove(&name);
                }
                if (sym.flags & 0x20) != 0 {
                    exported_tag_name_set.insert(name);
                }
            }
        }
    }

    // Third sub-pass: build per-object `local_tag_idx → output_tag_idx` maps.
    for (obj_idx, obj) in objects.iter().enumerate() {
        let p = &obj.parsed;
        let m = &mut per_obj_tag_map[obj_idx];
        for sym in &p.symbols {
            if sym.kind != 4 {
                continue;
            }
            // Resolve the symbol's "key name" — same rule as in sub-pass 1.
            let name = if !sym.name.is_empty() {
                sym.name.clone()
            } else if (sym.flags & 0x10) != 0
                && let Some(field) = p.import_tag_names.get(sym.index as usize)
            {
                field.clone()
            } else {
                continue;
            };
            if let Some(&out_idx) = tag_name_map.get(&name) {
                m.insert(sym.index, out_idx);
            }
        }
    }

    // --- Pass 2: apply relocations with global symbol resolution ---
    let mut functions: Vec<MergedFunction> = Vec::new();
    let mut table_needed_funcs: std::collections::HashSet<u32> = Default::default();
    // Store deferred table relocs: (function_output_idx, offset_in_body, reloc_type, sym→func_idx)
    let mut deferred_table_relocs: Vec<(usize, usize, u8, u32)> = Vec::new();

    for (obj_idx, obj_info) in objects.iter().enumerate() {
        let parsed = &obj_info.parsed;

        // Build per-object symbol → output index/address maps.
        let mut symbol_to_output_func: std::collections::HashMap<u32, u32> =
            Default::default();
        let mut symbol_to_output_global: std::collections::HashMap<u32, u32> =
            Default::default();
        // Symbol index → output tag index (for R_WASM_TAG_INDEX_LEB).
        let mut symbol_to_output_tag: std::collections::HashMap<u32, u32> =
            Default::default();
        let obj_tag_map = &per_obj_tag_map[obj_idx];
        for (sym_idx, sym) in parsed.symbols.iter().enumerate() {
            if sym.kind == 4
                && let Some(&out_idx) = obj_tag_map.get(&sym.index)
            {
                symbol_to_output_tag.insert(sym_idx as u32, out_idx);
            }
        }
        // Data symbol → output memory address (spec §9.4: value = seg_offset + sym_offset + addend).
        let mut symbol_to_data_addr: std::collections::HashMap<u32, u32> = Default::default();
        let obj_seg_offsets = &segment_output_offsets[obj_idx];
        for (sym_idx, sym) in parsed.symbols.iter().enumerate() {
            if sym.kind == 0 {
                // SYMTAB_FUNCTION
                let is_undefined = sym.flags & 0x10 != 0;
                if !is_undefined && sym.index >= parsed.num_function_imports {
                    let local_func_idx = sym.index - parsed.num_function_imports;
                    let local_output_idx = obj_info.func_base + local_func_idx;
                    // For weak/COMDAT symbols, use the winning definition if different.
                    let output_idx = if !sym.name.is_empty() {
                        function_name_map.get(sym.name.as_slice())
                            .copied()
                            .unwrap_or(local_output_idx)
                    } else {
                        local_output_idx
                    };
                    symbol_to_output_func
                        .insert(sym_idx as u32, output_idx);
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
            } else if sym.kind == 1 {
                    // SYMTAB_DATA — compute output memory address.
                    let is_undefined = sym.flags & 0x10 != 0;
                    if !is_undefined {
                        if let Some(&seg_base) =
                            obj_seg_offsets.get(sym.segment_index as usize)
                        {
                            let addr = seg_base + sym.segment_offset;
                            symbol_to_data_addr.insert(sym_idx as u32, addr);
                        }
                    } else if !sym.name.is_empty() {
                        // Undefined data symbol — resolve by name from global map.
                        if let Some(&addr) = data_name_map.get(&sym.name) {
                            symbol_to_data_addr.insert(sym_idx as u32, addr);
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
            // Skip functions from duplicate COMDAT groups.
            if obj_info.comdat_skip_functions.contains(&(i as u32)) {
                // Still push a placeholder to maintain index alignment.
                // This will be GC'd since nothing references it.
                functions.push(MergedFunction {
                    type_index: 0,
                    body: vec![0x00, 0x0B], // empty: 0 locals, end
                });
                continue;
            }
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
                    3 => {
                        // R_WASM_MEMORY_ADDR_LEB (spec §9.4: 5-byte varuint32)
                        // value = data symbol address + addend
                        let addr = symbol_to_data_addr
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0); // undefined → 0 per spec
                        let value = (addr as i64 + reloc.addend as i64) as u32;
                        write_padded_leb128(&mut body, off_in_body, value);
                    }
                    4 => {
                        // R_WASM_MEMORY_ADDR_SLEB (spec §9.4: 5-byte varint32)
                        let addr = symbol_to_data_addr
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        let value = (addr as i64 + reloc.addend as i64) as i32;
                        write_padded_sleb128(&mut body, off_in_body, value);
                    }
                    5 => {
                        // R_WASM_MEMORY_ADDR_I32 (spec §9.4: uint32 LE)
                        let addr = symbol_to_data_addr
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        let value = (addr as i64 + reloc.addend as i64) as u32;
                        body[off_in_body..off_in_body + 4]
                            .copy_from_slice(&value.to_le_bytes());
                    }
                    7 => {
                        // R_WASM_GLOBAL_INDEX_LEB (spec §2: 5-byte varuint32)
                        if let Some(&output_idx) =
                            symbol_to_output_global.get(&reloc.symbol_index)
                        {
                            write_padded_leb128(&mut body, off_in_body, output_idx);
                        }
                    }
                    1 | 2 => {
                        // R_WASM_TABLE_INDEX_SLEB (1) / _I32 (2)
                        // Collect for table. Patching deferred to pass 2.5.
                        let func_idx = symbol_to_output_func
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        table_needed_funcs.insert(func_idx);
                        let out_func_idx = functions.len() + i;
                        deferred_table_relocs.push((
                            out_func_idx,
                            off_in_body,
                            reloc.reloc_type,
                            func_idx,
                        ));
                    }
                    21 => {
                        // R_WASM_MEMORY_ADDR_TLS_SLEB (spec §9.4, §10)
                        // value = symbol offset within TLS block (relative to __tls_base)
                        let addr = symbol_to_data_addr
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        let tls_base = tls_base_offset.unwrap_or(0);
                        let tls_rel = if addr >= tls_base {
                            (addr - tls_base) as i32
                        } else {
                            0
                        };
                        let value = tls_rel + reloc.addend;
                        write_padded_sleb128(&mut body, off_in_body, value);
                    }
                    8 => {
                        // R_WASM_FUNCTION_OFFSET_I32 (spec §9.4)
                        // "Values adjusted for new code section offsets."
                        // Currently we don't reorder, so no adjustment needed.
                    }
                    9 => {
                        // R_WASM_SECTION_OFFSET_I32 (spec §9.4)
                        // Used in debug/custom sections — no adjustment yet.
                    }
                    13 => {
                        // R_WASM_GLOBAL_INDEX_I32 (spec §2: uint32 LE)
                        if let Some(&output_idx) =
                            symbol_to_output_global.get(&reloc.symbol_index)
                            && off_in_body + 4 <= body.len()
                        {
                            body[off_in_body..off_in_body + 4]
                                .copy_from_slice(&output_idx.to_le_bytes());
                        }
                    }
                    20 => {
                        // R_WASM_TABLE_NUMBER_LEB (spec §2: 5-byte varuint32)
                        // Wild emits a single indirect function table (index 0);
                        // multi-table is unimplemented, so always patch to 0.
                        write_padded_leb128(&mut body, off_in_body, 0);
                    }
                    26 => {
                        // R_WASM_FUNCTION_INDEX_I32 (spec §2: uint32 LE)
                        // Used in custom-section annotations.
                        if let Some(&output_idx) =
                            symbol_to_output_func.get(&reloc.symbol_index)
                            && off_in_body + 4 <= body.len()
                        {
                            body[off_in_body..off_in_body + 4]
                                .copy_from_slice(&output_idx.to_le_bytes());
                        }
                    }
                    14 => {
                        // R_WASM_MEMORY_ADDR_LEB64 (spec §2: 10-byte varuint64)
                        let addr = symbol_to_data_addr
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        let v = (addr as i64 + reloc.addend as i64) as u64;
                        write_padded_leb128_u64(&mut body, off_in_body, v);
                    }
                    15 => {
                        // R_WASM_MEMORY_ADDR_SLEB64 (spec §2: 10-byte varint64)
                        let addr = symbol_to_data_addr
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        let v = addr as i64 + reloc.addend as i64;
                        write_padded_sleb128_i64(&mut body, off_in_body, v);
                    }
                    16 => {
                        // R_WASM_MEMORY_ADDR_I64 (spec §2: uint64 LE)
                        let addr = symbol_to_data_addr
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        let v = (addr as i64 + reloc.addend as i64) as u64;
                        if off_in_body + 8 <= body.len() {
                            body[off_in_body..off_in_body + 8]
                                .copy_from_slice(&v.to_le_bytes());
                        }
                    }
                    18 => {
                        // R_WASM_TABLE_INDEX_SLEB64 (spec §2: 10-byte varint64)
                        // Defer to Pass 2.6 same as 1/2.
                        let func_idx = symbol_to_output_func
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        table_needed_funcs.insert(func_idx);
                        let out_func_idx = functions.len() + i;
                        deferred_table_relocs.push((
                            out_func_idx,
                            off_in_body,
                            reloc.reloc_type,
                            func_idx,
                        ));
                    }
                    19 => {
                        // R_WASM_TABLE_INDEX_I64 (spec §2: uint64 LE)
                        let func_idx = symbol_to_output_func
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        table_needed_funcs.insert(func_idx);
                        let out_func_idx = functions.len() + i;
                        deferred_table_relocs.push((
                            out_func_idx,
                            off_in_body,
                            reloc.reloc_type,
                            func_idx,
                        ));
                    }
                    22 => {
                        // R_WASM_FUNCTION_OFFSET_I64 (spec §2: uint64 LE)
                        // Like type 8 (I32): no adjustment — wild does not reorder.
                    }
                    11 => {
                        // R_WASM_MEMORY_ADDR_REL_SLEB (PIC, 5-byte varint32)
                        // value = S + A - __memory_base. In non-PIC builds
                        // __memory_base = 0, so this degrades to SLEB.
                        let addr = symbol_to_data_addr
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        let v = (addr as i64 + reloc.addend as i64) as i32;
                        write_padded_sleb128(&mut body, off_in_body, v);
                    }
                    17 => {
                        // R_WASM_MEMORY_ADDR_REL_SLEB64 (PIC + memory64,
                        // 10-byte varint64). Degrades to SLEB64 under
                        // __memory_base = 0.
                        let addr = symbol_to_data_addr
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        let v = addr as i64 + reloc.addend as i64;
                        write_padded_sleb128_i64(&mut body, off_in_body, v);
                    }
                    25 => {
                        // R_WASM_MEMORY_ADDR_TLS_SLEB64 (spec §9.4, §10;
                        // 10-byte varint64). memory64 TLS — mirrors type 21.
                        let addr = symbol_to_data_addr
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        let tls_base = tls_base_offset.unwrap_or(0);
                        let tls_rel = if addr >= tls_base {
                            (addr - tls_base) as i64
                        } else {
                            0
                        };
                        let v = tls_rel + reloc.addend as i64;
                        write_padded_sleb128_i64(&mut body, off_in_body, v);
                    }
                    12 => {
                        // R_WASM_TABLE_INDEX_REL_SLEB (PIC, 5-byte varint32)
                        // value = table_idx - __table_base; __table_base = 0
                        // in non-PIC, so defer like type 1.
                        let func_idx = symbol_to_output_func
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        table_needed_funcs.insert(func_idx);
                        let out_func_idx = functions.len() + i;
                        deferred_table_relocs.push((
                            out_func_idx,
                            off_in_body,
                            reloc.reloc_type,
                            func_idx,
                        ));
                    }
                    24 => {
                        // R_WASM_TABLE_INDEX_REL_SLEB64 (PIC + memory64,
                        // 10-byte varint64). Defer like 18.
                        let func_idx = symbol_to_output_func
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        table_needed_funcs.insert(func_idx);
                        let out_func_idx = functions.len() + i;
                        deferred_table_relocs.push((
                            out_func_idx,
                            off_in_body,
                            reloc.reloc_type,
                            func_idx,
                        ));
                    }
                    10 => {
                        // R_WASM_TAG_INDEX_LEB (spec §2: 5-byte varuint32)
                        // Resolved through the pre-Pass-1.9 output tag map.
                        if let Some(&output_idx) =
                            symbol_to_output_tag.get(&reloc.symbol_index)
                        {
                            write_padded_leb128(&mut body, off_in_body, output_idx);
                        }
                    }
                    other => {
                        if warned_reloc_types.insert(other) {
                            tracing::warn!(
                                "wasm: unhandled code-section relocation type {other} \
                                 (spec §2) — output will be silently incorrect for this reloc"
                            );
                        }
                    }
                }
            }

            functions.push(MergedFunction {
                type_index: remapped_type,
                body,
            });
        }
    }

    // --- Pass 2.5: apply data section relocations ---
    // Per spec §9.4: R_WASM_MEMORY_ADDR_I32 in data sections.
    // Relocations target offsets within the input's DATA section payload.
    // Use precise data_offset_in_section from parsing for correct mapping.
    if !data_segments.is_empty() {
        for (obj_idx, obj_info) in objects.iter().enumerate() {
            let parsed = &obj_info.parsed;
            if parsed.data_relocations.is_empty() {
                continue;
            }

            let obj_seg_offsets = &segment_output_offsets[obj_idx];

            // Build symbol address map (function + data + global names).
            let mut sym_to_addr: std::collections::HashMap<u32, u32> = Default::default();
            for (sym_idx, sym) in parsed.symbols.iter().enumerate() {
                if sym.kind == 0 {
                    // Function symbol → resolve to output address via name.
                    if let Some(&func_idx) = function_name_map.get(sym.name.as_slice()) {
                        sym_to_addr.insert(sym_idx as u32, func_idx);
                    }
                } else if sym.kind == 1 && (sym.flags & 0x10) == 0 {
                    // Defined data symbol.
                    if let Some(&seg_base) = obj_seg_offsets.get(sym.segment_index as usize) {
                        sym_to_addr.insert(sym_idx as u32, seg_base + sym.segment_offset);
                    }
                } else if sym.kind == 2 {
                    // Global symbol → output global index (for R_WASM_GLOBAL_INDEX_I32).
                    if let Some(&g) = global_name_map.get(sym.name.as_slice()) {
                        sym_to_addr.insert(sym_idx as u32, g);
                    }
                }
            }
            // Also resolve data symbols by name (cross-object).
            for (sym_idx, sym) in parsed.symbols.iter().enumerate() {
                if sym.kind == 1 && !sym.name.is_empty() && !sym_to_addr.contains_key(&(sym_idx as u32)) {
                    if let Some(&addr) = data_name_map.get(sym.name.as_slice()) {
                        sym_to_addr.insert(sym_idx as u32, addr);
                    }
                }
            }

            for reloc in &parsed.data_relocations {
                let addr = sym_to_addr.get(&reloc.symbol_index).copied().unwrap_or(0);
                let value = (addr as i64 + reloc.addend as i64) as u32;

                // Find which input segment this reloc targets using precise offsets.
                for (seg_i, seg) in parsed.data_segments.iter().enumerate() {
                    let seg_start = seg.data_offset_in_section;
                    let seg_end = seg_start + seg.data.len() as u32;
                    if reloc.offset >= seg_start && reloc.offset < seg_end {
                        if should_skip_seg(obj_idx, seg_i) {
                            break;
                        }
                        let off_in_seg = reloc.offset - seg_start;
                        let mem_off = obj_seg_offsets[seg_i];
                        // Find the output segment that contains this memory offset.
                        for out_seg in data_segments.iter_mut() {
                            let seg_mem_start = out_seg.memory_offset;
                            let seg_mem_end = seg_mem_start + out_seg.data.len() as Addr;
                            let mem_off_a = mem_off as Addr;
                            let off_in_seg_a = off_in_seg as Addr;
                            if mem_off_a >= seg_mem_start && mem_off_a < seg_mem_end {
                                let buf_off = (mem_off_a - seg_mem_start + off_in_seg_a) as usize;
                                match reloc.reloc_type {
                                    // 32-bit LE; sym_to_addr holds:
                                    //   kind 0 → output func index
                                    //   kind 1 → output memory address
                                    //   kind 2 → output global index
                                    // The right payload per reloc type drops
                                    // out automatically from the symbol kind.
                                    5 |  // R_WASM_MEMORY_ADDR_I32
                                    13 | // R_WASM_GLOBAL_INDEX_I32
                                    26   // R_WASM_FUNCTION_INDEX_I32
                                        if buf_off + 4 <= out_seg.data.len() => {
                                        out_seg.data[buf_off..buf_off + 4]
                                            .copy_from_slice(&value.to_le_bytes());
                                    }
                                    16 if buf_off + 8 <= out_seg.data.len() => {
                                        // R_WASM_MEMORY_ADDR_I64
                                        let v64 = value as u64;
                                        out_seg.data[buf_off..buf_off + 8]
                                            .copy_from_slice(&v64.to_le_bytes());
                                    }
                                    23 if buf_off + 4 <= out_seg.data.len() => {
                                        // R_WASM_MEMORY_ADDR_LOCREL_I32:
                                        // value = S + A - P, where P is the
                                        // absolute memory address of the reloc
                                        // site (out_seg.memory_offset + buf_off).
                                        let site = (out_seg.memory_offset as u32)
                                            .wrapping_add(buf_off as u32);
                                        let rel = value.wrapping_sub(site);
                                        out_seg.data[buf_off..buf_off + 4]
                                            .copy_from_slice(&rel.to_le_bytes());
                                    }
                                    19 if buf_off + 8 <= out_seg.data.len() => {
                                        // R_WASM_TABLE_INDEX_I64 — function index
                                        // in a data initializer. No table-index
                                        // mapping here (Pass 2.6 hasn't run), so
                                        // emit the raw function index; callers
                                        // either tolerate this or the value is
                                        // patched via the deferred list above.
                                        let v64 = value as u64;
                                        out_seg.data[buf_off..buf_off + 8]
                                            .copy_from_slice(&v64.to_le_bytes());
                                    }
                                    other => {
                                        if warned_reloc_types.insert(other) {
                                            tracing::warn!(
                                                "wasm: unhandled data-section \
                                                 relocation type {other} (spec §9.4)"
                                            );
                                        }
                                    }
                                }
                                break;
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    // --- Pass 2.6: build indirect function table and patch TABLE_INDEX relocs ---
    // Per spec §9.4: "Output contains synthesized table with entries for all
    // referenced symbols. Table elements begin at non-zero offset."
    let mut table_entries: Vec<u32> = Vec::new();
    let mut func_to_table_index: std::collections::HashMap<u32, u32> = Default::default();

    if !table_needed_funcs.is_empty() {
        let mut sorted_funcs: Vec<u32> = table_needed_funcs.into_iter().collect();
        sorted_funcs.sort();
        for (i, &func_idx) in sorted_funcs.iter().enumerate() {
            let table_idx = (i + 1) as u32; // start at 1, 0 = null/trap
            func_to_table_index.insert(func_idx, table_idx);
            table_entries.push(func_idx);
        }

        // Patch deferred TABLE_INDEX relocations.
        for (func_out_idx, off_in_body, reloc_type, target_func_idx) in &deferred_table_relocs {
            let table_idx = func_to_table_index.get(target_func_idx).copied().unwrap_or(0);
            if let Some(func) = functions.get_mut(*func_out_idx) {
                match reloc_type {
                    1 => {
                        // R_WASM_TABLE_INDEX_SLEB: 5-byte signed padded LEB128
                        write_padded_sleb128(&mut func.body, *off_in_body, table_idx as i32);
                    }
                    2 => {
                        // R_WASM_TABLE_INDEX_I32: uint32 LE
                        func.body[*off_in_body..*off_in_body + 4]
                            .copy_from_slice(&table_idx.to_le_bytes());
                    }
                    18 => {
                        // R_WASM_TABLE_INDEX_SLEB64: 10-byte signed padded LEB128
                        write_padded_sleb128_i64(
                            &mut func.body,
                            *off_in_body,
                            table_idx as i64,
                        );
                    }
                    19 => {
                        // R_WASM_TABLE_INDEX_I64: uint64 LE
                        if *off_in_body + 8 <= func.body.len() {
                            func.body[*off_in_body..*off_in_body + 8]
                                .copy_from_slice(&(table_idx as u64).to_le_bytes());
                        }
                    }
                    12 => {
                        // R_WASM_TABLE_INDEX_REL_SLEB: degrades to SLEB under
                        // __table_base = 0 (non-PIC).
                        write_padded_sleb128(&mut func.body, *off_in_body, table_idx as i32);
                    }
                    24 => {
                        // R_WASM_TABLE_INDEX_REL_SLEB64: degrades to SLEB64.
                        write_padded_sleb128_i64(
                            &mut func.body,
                            *off_in_body,
                            table_idx as i64,
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    // --- Pass 3: insert __wasm_call_ctors body ---
    // Init funcs collected and indices shifted in Pass 1.8.
    // Now create the body and insert the function.
    if needs_ctors {
        let mut body = Vec::new();
        body.push(0x00); // 0 locals
        for &(_, func_idx) in &all_init_funcs {
            body.push(0x10); // call
            // func_idx is pre-shift; +1 for ctors insertion at index 0
            write_leb128(&mut body, func_idx + 1);
            body.push(0x1A); // drop
        }
        body.push(0x0B); // end

        let void_type = FuncType { params: Vec::new(), results: Vec::new() };
        let type_idx = if let Some(pos) = types.iter().position(|t| *t == void_type) {
            pos as u32
        } else {
            let idx = types.len() as u32;
            types.push(void_type);
            idx
        };

        functions.insert(0, MergedFunction { type_index: type_idx, body });
        // Shift table entries (not done in Pass 1.8 since tables built in Pass 2.6).
        for idx in table_entries.iter_mut() {
            *idx += 1;
        }
        func_to_table_index = table_entries
            .iter()
            .enumerate()
            .map(|(i, &func_idx)| (func_idx, (i + 1) as u32))
            .collect();
        // Note: call targets in function bodies are NOT shifted here because
        // Pass 2 already resolved them using post-shift function_name_map.
    }

    // --- Pass 3.5: synthesize __wasm_init_memory for --shared-memory ---
    // Per spec §10: when shared memory, data segments are passive.
    // __wasm_init_memory uses memory.init to populate them.
    let use_passive = layout.symbol_db.args.shared_memory && !data_segments.is_empty();
    let mut init_memory_func_idx: Option<u32> = None;

    if use_passive {
        let void_type = FuncType {
            params: Vec::new(),
            results: Vec::new(),
        };
        let type_idx = if let Some(pos) = types.iter().position(|t| *t == void_type) {
            pos as u32
        } else {
            let idx = types.len() as u32;
            types.push(void_type);
            idx
        };

        let mut body = Vec::new();
        body.push(0x00); // 0 locals

        for (seg_idx, seg) in data_segments.iter().enumerate() {
            // i32.const <memory_offset>
            body.push(0x41);
            write_sleb128(&mut body, seg.memory_offset as i32);
            // i32.const 0 (source offset)
            body.push(0x41);
            write_sleb128(&mut body, 0);
            // i32.const <size>
            body.push(0x41);
            write_sleb128(&mut body, seg.data.len() as i32);
            // memory.init <seg_idx> 0
            body.push(0xFC);
            write_leb128(&mut body, 0x08); // memory.init opcode
            write_leb128(&mut body, seg_idx as u32);
            write_leb128(&mut body, 0); // memory index
            // data.drop <seg_idx>
            body.push(0xFC);
            write_leb128(&mut body, 0x09); // data.drop opcode
            write_leb128(&mut body, seg_idx as u32);
        }
        body.push(0x0B); // end

        let func_idx = functions.len() as u32;
        init_memory_func_idx = Some(func_idx);
        function_name_map.insert(b"__wasm_init_memory".to_vec(), func_idx);
        functions.push(MergedFunction {
            type_index: type_idx,
            body,
        });
    }

    // (Data segment layout done in pass 1.5 above.)

    // --- Pass 4: collect unresolved imports (spec §9.2) ---
    // Per spec: "an import for each undefined strong symbol."
    // Skip imports for memory (we define our own) and globals we define
    // (like __stack_pointer). Dedup by (module, field, kind, type).
    let mut output_imports: Vec<OutputImport> = Vec::new();
    let mut num_imported_functions = 0u32;
    let mut num_imported_globals = 0u32;
    let mut seen_imports: std::collections::HashSet<(Vec<u8>, Vec<u8>, u8, u32)> =
        Default::default();

    for obj_info in &objects {
        for imp in &obj_info.parsed.imports {
            // Skip memory imports (we define our own memory).
            if imp.kind == 2 {
                continue;
            }
            // Skip function imports that are resolved by a definition.
            if imp.kind == 0 && function_name_map.contains_key(imp.field.as_slice()) {
                continue;
            }
            // Skip global imports that are resolved by linker-defined globals.
            if imp.kind == 3 && global_name_map.contains_key(imp.field.as_slice()) {
                continue;
            }
            // Dedup: same module+field+kind+type are merged, different types kept.
            let key = (imp.module.clone(), imp.field.clone(), imp.kind, imp.type_index);
            if !seen_imports.insert(key) {
                continue;
            }
            match imp.kind {
                0 => {
                    // Remap type index through the object's type map.
                    let remapped_type = obj_info
                        .type_map
                        .get(imp.type_index as usize)
                        .copied()
                        .unwrap_or(imp.type_index);
                    output_imports.push(OutputImport {
                        module: imp.module.clone(),
                        field: imp.field.clone(),
                        kind: ImportKind::Function(remapped_type),
                    });
                    num_imported_functions += 1;
                }
                3 => {
                    let valtype = (imp.type_index >> 1) as u8;
                    let mutable = (imp.type_index & 1) != 0;
                    output_imports.push(OutputImport {
                        module: imp.module.clone(),
                        field: imp.field.clone(),
                        kind: ImportKind::Global { valtype, mutable },
                    });
                    num_imported_globals += 1;
                }
                _ => {
                    // Table imports etc — skip for now.
                }
            }
        }
    }

    // Shared/PIC mode: import __memory_base and __stack_pointer.
    let mut memory_base_global_idx: Option<u32> = None;
    if layout.symbol_db.args.is_shared {
        // Import memory.
        output_imports.push(OutputImport {
            module: b"env".to_vec(),
            field: b"memory".to_vec(),
            kind: ImportKind::Memory { min: 1 },
        });
        // Import __memory_base (immutable i32).
        let idx = num_imported_globals;
        memory_base_global_idx = Some(idx);
        output_imports.push(OutputImport {
            module: b"env".to_vec(),
            field: b"__memory_base".to_vec(),
            kind: ImportKind::Global {
                valtype: VALTYPE_I32,
                mutable: false,
            },
        });
        num_imported_globals += 1;
        // Import __stack_pointer (mutable i32).
        output_imports.push(OutputImport {
            module: b"env".to_vec(),
            field: b"__stack_pointer".to_vec(),
            kind: ImportKind::Global {
                valtype: VALTYPE_I32,
                mutable: true,
            },
        });
        num_imported_globals += 1;
        // Import __indirect_function_table.
        output_imports.push(OutputImport {
            module: b"env".to_vec(),
            field: b"__indirect_function_table".to_vec(),
            kind: ImportKind::Table { min: 0 },
        });
        // Import __table_base (immutable i32).
        output_imports.push(OutputImport {
            module: b"env".to_vec(),
            field: b"__table_base".to_vec(),
            kind: ImportKind::Global {
                valtype: VALTYPE_I32,
                mutable: false,
            },
        });
        num_imported_globals += 1;

        // Pass through GOT imports (GOT.func.* and GOT.mem.*).
        // These are mutable i32 globals filled by the runtime.
        let mut seen_got: std::collections::HashSet<(Vec<u8>, Vec<u8>)> = Default::default();
        for obj_info in &objects {
            for imp in &obj_info.parsed.imports {
                if imp.kind != 3 {
                    continue; // only global imports
                }
                let is_got = imp.module.starts_with(b"GOT.");
                if !is_got {
                    continue;
                }
                let key = (imp.module.clone(), imp.field.clone());
                if !seen_got.insert(key) {
                    continue; // dedup
                }
                output_imports.push(OutputImport {
                    module: imp.module.clone(),
                    field: imp.field.clone(),
                    kind: ImportKind::Global {
                        valtype: VALTYPE_I32,
                        mutable: true,
                    },
                });
                num_imported_globals += 1;
            }
        }
    }

    // In shared mode: build global name → index for imported globals.
    if layout.symbol_db.args.is_shared {
        let mut import_global_idx = 0u32;
        for imp in &output_imports {
            if let ImportKind::Global { .. } = &imp.kind {
                global_name_map.insert(imp.field.clone(), import_global_idx);
                import_global_idx += 1;
            }
        }
    }

    // EH tag imports (collected in Pass 1.9).
    for (module, field, type_idx) in &output_tag_imports {
        output_imports.push(OutputImport {
            module: module.clone(),
            field: field.clone(),
            kind: ImportKind::Tag(*type_idx),
        });
    }

    // --import-table: add table import (spec §9.6).
    if layout.symbol_db.args.import_table && !table_entries.is_empty() {
        let table_size = table_entries.len() as u32 + 1;
        output_imports.push(OutputImport {
            module: b"env".to_vec(),
            field: b"__indirect_function_table".to_vec(),
            kind: ImportKind::Table { min: table_size },
        });
    }

    // If there are imported functions, all defined function indices shift
    // by num_imported_functions. Update all maps.
    if num_imported_functions > 0 {
        for idx in function_name_map.values_mut() {
            *idx += num_imported_functions;
        }
        if let Some(ref mut idx) = entry_function_index {
            *idx += num_imported_functions;
        }
    }

    // Similarly for imported globals.
    if num_imported_globals > 0 {
        for idx in global_name_map.values_mut() {
            *idx += num_imported_globals;
        }
    }

    // Collect explicit export indices for GC roots.
    let args = layout.symbol_db.args;
    let mut explicit_export_indices = Vec::new();
    for name in args.exports.iter().chain(args.exports_if_defined.iter()) {
        if let Some(&idx) = function_name_map.get(name.as_bytes()) {
            explicit_export_indices.push(idx);
        }
    }

    // Collect custom sections from all objects.
    // Per spec: same-name custom sections are concatenated.
    // Exception: target_features is merged per §8 across all inputs — the
    // output is the union of USED features with DISALLOWED features
    // surviving only when no input uses them. A feature that one input
    // uses ('+' 0x2b) and another disallows ('-' 0x2d) is a conflict.
    let mut merged_custom_sections: Vec<CustomSection> = Vec::new();
    let mut custom_section_index: std::collections::HashMap<Vec<u8>, usize> = Default::default();
    let merged_tf_payload = merge_target_features(
        objects.iter().map(|o| o.parsed.custom_sections.as_slice()),
        layout.symbol_db.args.shared_memory,
    )?;
    if !merged_tf_payload.is_empty() {
        custom_section_index.insert(b"target_features".to_vec(), merged_custom_sections.len());
        merged_custom_sections.push(CustomSection {
            name: b"target_features".to_vec(),
            data: merged_tf_payload,
        });
    }
    for obj_info in &objects {
        for cs in &obj_info.parsed.custom_sections {
            if cs.name == b"target_features" {
                // Handled above via merge_target_features.
                continue;
            }
            if let Some(&idx) = custom_section_index.get(&cs.name) {
                merged_custom_sections[idx].data.extend_from_slice(&cs.data);
            } else {
                custom_section_index.insert(cs.name.clone(), merged_custom_sections.len());
                merged_custom_sections.push(CustomSection {
                    name: cs.name.clone(),
                    data: cs.data.clone(),
                });
            }
        }
    }

    Ok(MergedModule {
        types,
        functions,
        entry_function_index,
        function_name_map,
        explicit_export_indices,
        hidden_functions: function_is_hidden,
        no_strip_indices,
        exported_indices,
        table_entries,
        func_to_table_index,
        globals,
        global_name_map,
        data_segments,
        data_size: data_size as Addr,
        stack_pointer_value: stack_pointer_value as Addr,
        max_data_alignment: {
            let mut max = 1u32;
            for obj in &objects {
                for seg in &obj.parsed.data_segments {
                    max = max.max(seg.alignment);
                }
            }
            max
        },
        imports: output_imports,
        num_imported_functions,
        num_imported_globals,
        memory_base_global_idx,
        use_passive_segments: use_passive,
        init_memory_func_idx,
        custom_sections: merged_custom_sections,
        output_tags: output_tag_defs,
        tag_name_map,
        hidden_tags: tag_is_hidden,
        exported_tag_names: exported_tag_name_set,
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

/// A user-defined global from the input object's GLOBAL section.
struct ParsedInputGlobal {
    valtype: u8,
    mutable: bool,
    /// Init value (from i32.const/f32.const/f64.const init expr).
    init_value: u64,
}

/// A parsed import from the input object.
#[derive(Debug, Clone)]
struct ParsedImport {
    module: Vec<u8>,
    field: Vec<u8>,
    kind: u8,       // 0=func, 1=table, 2=memory, 3=global
    type_index: u32, // for functions: type index; for globals: encoded as valtype<<1|mutable
}

/// A parsed data segment from the input object.
struct ParsedDataSegment {
    data: Vec<u8>,
    alignment: u32,
    is_tls: bool,
    /// Segment name from WASM_SEGMENT_INFO (e.g. ".data.foo", ".rodata.bar").
    name: Vec<u8>,
    /// Byte offset of this segment's data within the DATA section payload.
    /// Used for precise reloc.DATA offset mapping.
    data_offset_in_section: u32,
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
    /// True if any memory import in this object has the 0x04 (memory64)
    /// limits flag. Used to detect mem64 inputs that require
    /// `--features=+memory64` at link time.
    is_memory64: bool,
    /// Local tag definitions: one entry per tag, value = type index.
    tags: Vec<u32>,
    /// Number of imported tags (offset for local tag indices).
    num_tag_imports: u32,
    /// Import tag names (indexed by import tag index).
    import_tag_names: Vec<Vec<u8>>,
    /// User-defined globals from the GLOBAL section.
    input_globals: Vec<ParsedInputGlobal>,
    /// Number of imported globals (offset for local global indices).
    num_global_imports: u32,
    /// All symbols from the linking section.
    symbols: Vec<WasmSymbolInfo>,
    /// Relocations for the code section.
    code_relocations: Vec<WasmReloc>,
    /// Relocations for the data section.
    data_relocations: Vec<WasmReloc>,
    /// Number of imported functions (offset for local function indices).
    num_function_imports: u32,
    /// All imports from the import section.
    imports: Vec<ParsedImport>,
    /// Init functions from WASM_INIT_FUNCS (spec §6).
    init_functions: Vec<InitFunc>,
    /// Custom sections to pass through (e.g. target_features).
    custom_sections: Vec<CustomSection>,
    /// Data segments from the DATA section.
    data_segments: Vec<ParsedDataSegment>,
    /// COMDAT groups (spec §7): (group_name, [(kind, index)]).
    comdat_groups: Vec<(Vec<u8>, Vec<(u8, u32)>)>,
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
    let mut import_tag_names: Vec<Vec<u8>> = Vec::new();
    let mut num_tag_imports = 0u32;
    let mut tags: Vec<u32> = Vec::new();
    let mut parsed_imports: Vec<ParsedImport> = Vec::new();
    let mut data_segments: Vec<ParsedDataSegment> = Vec::new();
    let mut data_relocations: Vec<WasmReloc> = Vec::new();
    let mut init_funcs: Vec<InitFunc> = Vec::new();
    let mut comdat_groups: Vec<(Vec<u8>, Vec<(u8, u32)>)> = Vec::new();
    let mut input_globals: Vec<ParsedInputGlobal> = Vec::new();
    let mut num_global_imports = 0u32;
    let mut custom_sections: Vec<CustomSection> = Vec::new();
    let mut code_section_index: Option<usize> = None;
    let mut data_section_index: Option<usize> = None;
    let mut section_counter = 0usize;
    // True if this input declares a 64-bit memory (import or local) via the
    // limits 0x04 flag. Forwarded to layout so it can reject a mix of mem64
    // inputs with `--features=+memory64` absent.
    let mut is_memory64 = false;

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
                    off += c;
                    let module_name = &payload[off..off + mod_len];
                    off += mod_len;
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
                            // function import
                            import_function_names.push(field_name.to_vec());
                            let (type_idx, c) = read_leb128(&payload[off..])?;
                            off += c;
                            parsed_imports.push(ParsedImport {
                                module: module_name.to_vec(),
                                field: field_name.to_vec(),
                                kind: 0,
                                type_index: type_idx as u32,
                            });
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
                            if flags & 0x04 != 0 {
                                is_memory64 = true;
                            }
                            let (_min, c) = read_leb128(&payload[off..])?;
                            off += c;
                            if flags & 1 != 0 {
                                let (_max, c) = read_leb128(&payload[off..])?;
                                off += c;
                            }
                        }
                        0x03 => {
                            // global import
                            num_global_imports += 1;
                            import_global_names.push(field_name.to_vec());
                            let valtype = payload[off];
                            off += 1;
                            let mutable = payload[off];
                            off += 1;
                            parsed_imports.push(ParsedImport {
                                module: module_name.to_vec(),
                                field: field_name.to_vec(),
                                kind: 3,
                                type_index: ((valtype as u32) << 1) | (mutable as u32),
                            });
                        }
                        0x04 => {
                            // tag import (EH proposal): attribute byte (must be
                            // 0 = exception) + type index (varuint32).
                            off += 1; // attribute
                            let (type_idx, c) = read_leb128(&payload[off..])?;
                            off += c;
                            import_tag_names.push(field_name.to_vec());
                            num_tag_imports += 1;
                            parsed_imports.push(ParsedImport {
                                module: module_name.to_vec(),
                                field: field_name.to_vec(),
                                kind: 4,
                                type_index: type_idx as u32,
                            });
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
            SECTION_GLOBAL => {
                // Parse user-defined globals.
                let (count, mut goff) = read_leb128(payload)?;
                for _ in 0..count {
                    let valtype = payload[goff];
                    goff += 1;
                    let mutable = payload[goff] != 0;
                    goff += 1;
                    // Parse init expression to get the value.
                    let init_value = match payload[goff] {
                        0x41 => {
                            // i32.const
                            goff += 1;
                            let (val, c) = read_leb128(&payload[goff..])?;
                            goff += c;
                            val as u64
                        }
                        0x42 => {
                            // i64.const
                            goff += 1;
                            // Read as unsigned LEB128 for simplicity
                            let (val, c) = read_leb128(&payload[goff..])?;
                            goff += c;
                            val as u64
                        }
                        0x43 => {
                            // f32.const
                            goff += 1;
                            let val = u32::from_le_bytes(
                                payload[goff..goff + 4].try_into().unwrap_or([0; 4]),
                            );
                            goff += 4;
                            val as u64
                        }
                        0x44 => {
                            // f64.const
                            goff += 1;
                            let val = u64::from_le_bytes(
                                payload[goff..goff + 8].try_into().unwrap_or([0; 8]),
                            );
                            goff += 8;
                            val
                        }
                        _ => {
                            // Skip unknown init expr
                            while goff < payload.len() && payload[goff] != 0x0B {
                                goff += 1;
                            }
                            0
                        }
                    };
                    // Skip 0x0B (end of init expr)
                    if goff < payload.len() && payload[goff] == 0x0B {
                        goff += 1;
                    }
                    input_globals.push(ParsedInputGlobal {
                        valtype,
                        mutable,
                        init_value,
                    });
                }
            }
            SECTION_DATA => {
                data_section_index = Some(section_counter);
                data_segments = parse_data_section(payload)?;
            }
            0 => {
                // Custom section — check name.
                let (name_len, c) = read_leb128(payload)?;
                let name = &payload[c..c + name_len];
                let custom_data = &payload[c + name_len..];
                if name == b"linking" {
                    let linking = parse_linking_data(custom_data, num_imports);
                    symbols = linking.symbols;
                    init_funcs = linking.init_functions;
                    comdat_groups = linking.comdat_groups;
                    // Apply segment names, alignments and TLS flags.
                    for (i, name) in linking.segment_names.iter().enumerate() {
                        if let Some(seg) = data_segments.get_mut(i) {
                            seg.name = name.clone();
                        }
                    }
                    for (i, align) in linking.segment_alignments.iter().enumerate() {
                        if let Some(seg) = data_segments.get_mut(i) {
                            seg.alignment = *align;
                        }
                    }
                    for (i, &flags) in linking.segment_flags.iter().enumerate() {
                        if let Some(seg) = data_segments.get_mut(i) {
                            seg.is_tls = (flags & 0x02) != 0; // WASM_SEGMENT_FLAG_TLS
                        }
                    }
                    parse_linking_section(
                        custom_data,
                        num_imports,
                        &mut function_names,
                    );
                } else if name.starts_with(b"reloc.") {
                    // Per spec §2: reloc section contains section_index, count, entries.
                    if let Ok((target_idx, relocs)) = parse_reloc_section(custom_data) {
                        if code_section_index == Some(target_idx) {
                            code_relocations = relocs;
                        } else if data_section_index == Some(target_idx) {
                            data_relocations = relocs;
                        }
                    }
                } else {
                    // Pass through other custom sections (e.g. target_features).
                    custom_sections.push(CustomSection {
                        name: name.to_vec(),
                        data: custom_data.to_vec(),
                    });
                }
            }
            SECTION_TAG => {
                // EH tag section: count × { attribute (u8), type_index (leb) }.
                let (count, mut toff) = read_leb128(payload)?;
                for _ in 0..count {
                    if toff >= payload.len() {
                        break;
                    }
                    toff += 1; // attribute byte
                    let (type_idx, c) = read_leb128(&payload[toff..])?;
                    toff += c;
                    tags.push(type_idx as u32);
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
        data_relocations,
        init_functions: init_funcs,
        custom_sections,
        imports: parsed_imports,
        data_segments,
        comdat_groups,
        input_globals,
        num_global_imports,
        tags,
        num_tag_imports,
        import_tag_names,
        is_memory64,
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
        let data_start_offset = off as u32; // precise offset within DATA section payload
        let end = off + data_len;
        if end > payload.len() {
            return Err(crate::error!("data segment exceeds section bounds"));
        }
        let data = payload[off..end].to_vec();
        off = end;
        segments.push(ParsedDataSegment {
            data,
            alignment: 1, // Updated from WASM_SEGMENT_INFO
            is_tls: false, // Updated from WASM_SEGMENT_INFO flags
            name: Vec::new(), // Updated from WASM_SEGMENT_INFO
            data_offset_in_section: data_start_offset,
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

/// An init function entry from WASM_INIT_FUNCS (spec §6).
struct InitFunc {
    priority: u32,
    symbol_index: u32,
}

/// Parsed linking section data.
struct LinkingData {
    symbols: Vec<WasmSymbolInfo>,
    /// Segment alignment (power of 2) for each data segment.
    segment_alignments: Vec<u32>,
    /// Segment names from WASM_SEGMENT_INFO (e.g. ".data.foo").
    segment_names: Vec<Vec<u8>>,
    /// Segment flags for each data segment (WASM_SEGMENT_FLAG_TLS = 0x2).
    segment_flags: Vec<u32>,
    /// Constructor functions with priorities.
    init_functions: Vec<InitFunc>,
    /// COMDAT groups: (name, [(kind, index)])
    /// kind: 0=data, 1=function
    comdat_groups: Vec<(Vec<u8>, Vec<(u8, u32)>)>,
}

/// Parse the linking section: symbols (§4) and segment info (§5).
fn parse_linking_data(data: &[u8], num_imports: u32) -> LinkingData {
    let Ok((version, mut off)) = read_leb128(data) else {
        return LinkingData { symbols: Vec::new(), segment_alignments: Vec::new(), segment_names: Vec::new(), segment_flags: Vec::new(), init_functions: Vec::new(), comdat_groups: Vec::new() };
    };
    if version != 2 {
        return LinkingData { symbols: Vec::new(), segment_alignments: Vec::new(), segment_names: Vec::new(), segment_flags: Vec::new(), init_functions: Vec::new(), comdat_groups: Vec::new() };
    }

    let mut symbols = Vec::new();
    let mut segment_alignments = Vec::new();
    let mut segment_names: Vec<Vec<u8>> = Vec::new();
    let mut segment_flags_vec = Vec::new();
    let mut init_functions = Vec::new();
    let mut comdat_groups = Vec::new();

    while off < data.len() {
        let Ok((subsection_type, c)) = read_leb128(&data[off..]) else {
            break;
        };
        off += c;
        let Ok((subsection_len, c)) = read_leb128(&data[off..]) else {
            break;
        };
        off += c;
        let subsection_end = off + subsection_len;

        match subsection_type {
            5 => {
                // WASM_SEGMENT_INFO (spec §5)
                let Ok((count, mut soff)) = read_leb128(&data[off..subsection_end]) else {
                    off = subsection_end;
                    continue;
                };
                soff += off;
                for _ in 0..count {
                    // name_len + name
                    let Ok((name_len, c)) = read_leb128(&data[soff..]) else { break; };
                    soff += c;
                    let name = data[soff..soff + name_len].to_vec();
                    soff += name_len;
                    // alignment (power of 2)
                    let Ok((alignment, c)) = read_leb128(&data[soff..]) else { break; };
                    soff += c;
                    // flags (WASM_SEGMENT_FLAG_TLS = 0x2)
                    let Ok((flags, c)) = read_leb128(&data[soff..]) else { break; };
                    soff += c;
                    // alignment is stored as log2, convert to bytes
                    segment_alignments.push(1u32 << alignment);
                    segment_names.push(name);
                    segment_flags_vec.push(flags as u32);
                }
            }
            6 => {
                // WASM_INIT_FUNCS (spec §6)
                let Ok((count, mut ioff)) = read_leb128(&data[off..subsection_end]) else {
                    off = subsection_end;
                    continue;
                };
                ioff += off;
                for _ in 0..count {
                    let Ok((priority, c)) = read_leb128(&data[ioff..]) else { break; };
                    ioff += c;
                    let Ok((symbol_index, c)) = read_leb128(&data[ioff..]) else { break; };
                    ioff += c;
                    init_functions.push(InitFunc {
                        priority: priority as u32,
                        symbol_index: symbol_index as u32,
                    });
                }
            }
            7 => {
                // WASM_COMDAT_INFO (spec §7)
                let Ok((count, mut coff)) = read_leb128(&data[off..subsection_end]) else {
                    off = subsection_end;
                    continue;
                };
                coff += off;
                for _ in 0..count {
                    let Ok((name_len, c)) = read_leb128(&data[coff..]) else { break; };
                    coff += c;
                    if coff + name_len > data.len() { break; }
                    let name = data[coff..coff + name_len].to_vec();
                    coff += name_len;
                    let Ok((_flags, c)) = read_leb128(&data[coff..]) else { break; };
                    coff += c;
                    let Ok((sym_count, c)) = read_leb128(&data[coff..]) else { break; };
                    coff += c;
                    let mut entries = Vec::new();
                    for _ in 0..sym_count {
                        let Ok((kind, c)) = read_leb128(&data[coff..]) else { break; };
                        coff += c;
                        let Ok((index, c)) = read_leb128(&data[coff..]) else { break; };
                        coff += c;
                        entries.push((kind as u8, index as u32));
                    }
                    comdat_groups.push((name, entries));
                }
            }
            8 => {
                // WASM_SYMBOL_TABLE (spec §4)
                symbols = parse_symbol_table_entries(&data[off..subsection_end], num_imports);
            }
            _ => {}
        }

        off = subsection_end;
    }

    LinkingData { symbols, segment_alignments, segment_names, segment_flags: segment_flags_vec, init_functions, comdat_groups }
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
    let mut num_imported_functions: usize = 0;
    let mut num_imported_globals: usize = 0;
    let mut _memory_pages: usize = 0;

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

        // Non-custom sections must follow their logical order.
        // Modern wasm deviates from pure ID-ascending: datacount (12)
        // sits between element (9) and code (10), and tag (13) sits
        // between memory (5) and global (6) per the EH proposal.
        fn logical_order(id: u8) -> u8 {
            match id {
                1..=5 => id,       // type..memory
                13 => 6,           // tag (EH) after memory
                6 => 7,            // global
                7 => 8,            // export
                8 => 9,            // start
                9 => 10,           // element
                12 => 11,          // datacount
                10 => 12,          // code
                11 => 13,          // data
                other => other,    // unknown
            }
        }
        if section_id != 0 {
            let cur = logical_order(section_id);
            let prev = logical_order(prev_id);
            if prev_id != 0 && cur <= prev {
                return Err(crate::error!(
                    "WASM output: section {section_id} out of logical order (prev {prev_id})"
                ));
            }
            prev_id = section_id;
        }

        match section_id {
            2 => {
                // IMPORT section: count imported functions and globals.
                let (count, mut off) = read_leb128(payload)?;
                for _ in 0..count {
                    // module name
                    let (len, c) = read_leb128(&payload[off..])?;
                    off += c + len;
                    // field name
                    let (len, c) = read_leb128(&payload[off..])?;
                    off += c + len;
                    let kind = payload[off];
                    off += 1;
                    match kind {
                        0x00 => {
                            // function import
                            let (_, c) = read_leb128(&payload[off..])?;
                            off += c;
                            num_imported_functions += 1;
                        }
                        0x01 => {
                            // table import
                            off += 1; // elemtype
                            let (flags, c) = read_leb128(&payload[off..])?;
                            off += c;
                            let (_, c) = read_leb128(&payload[off..])?;
                            off += c;
                            if flags & 0x01 != 0 {
                                let (_, c) = read_leb128(&payload[off..])?;
                                off += c;
                            }
                        }
                        0x02 => {
                            // memory import
                            let (flags, c) = read_leb128(&payload[off..])?;
                            off += c;
                            let (_, c) = read_leb128(&payload[off..])?;
                            off += c;
                            if flags & 0x01 != 0 {
                                let (_, c) = read_leb128(&payload[off..])?;
                                off += c;
                            }
                        }
                        0x03 => {
                            // global import
                            off += 1; // valtype
                            off += 1; // mutability
                            num_imported_globals += 1;
                        }
                        _ => {}
                    }
                }
            }
            SECTION_FUNCTION => {
                let (count, _) = read_leb128(payload)?;
                function_count = Some(count);
                num_functions = num_imported_functions + count;
            }
            SECTION_CODE => {
                let (count, _) = read_leb128(payload)?;
                code_count = Some(count);
            }
            SECTION_GLOBAL => {
                let (count, _) = read_leb128(payload)?;
                num_globals = num_imported_globals + count;
            }
            SECTION_MEMORY => {
                let (count, _) = read_leb128(payload)?;
                if count > 0 {
                    let (_flags, c) = read_leb128(&payload[1..])?;
                    let (pages, _) = read_leb128(&payload[1 + c..])?;
                    _memory_pages = pages;
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

    // If there's a function section there must be a code section and vice versa.
    if function_count.is_some() != code_count.is_some() {
        return Err(crate::error!(
            "WASM output: function section present ({}) but code section present ({})",
            function_count.is_some(),
            code_count.is_some()
        ));
    }

    // Exported function indices must account for imported functions too.
    // (Already checked above via num_functions which includes imports.)

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
    if offset + 5 > buf.len() {
        return;
    }
    buf[offset] = (value & 0x7F) as u8 | 0x80;
    buf[offset + 1] = ((value >> 7) & 0x7F) as u8 | 0x80;
    buf[offset + 2] = ((value >> 14) & 0x7F) as u8 | 0x80;
    buf[offset + 3] = ((value >> 21) & 0x7F) as u8 | 0x80;
    buf[offset + 4] = ((value >> 28) & 0x0F) as u8;
}

/// Write an unsigned LEB128 value up to 64 bits wide. Emits 1–10 bytes.
fn write_leb128_u64(out: &mut Vec<u8>, mut value: u64) {
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

/// Write an unsigned LEB128 for an `Addr`. Picks the right width depending
/// on the Cargo feature.
fn write_leb128_addr(out: &mut Vec<u8>, value: Addr) {
    #[cfg(not(feature = "wasm-addr64"))]
    write_leb128(out, value);
    #[cfg(feature = "wasm-addr64")]
    write_leb128_u64(out, value);
}

/// Write a 10-byte padded unsigned LEB128 value (64-bit) at a specific offset.
fn write_padded_leb128_u64(buf: &mut [u8], offset: usize, value: u64) {
    if offset + 10 > buf.len() {
        return;
    }
    for i in 0..9 {
        buf[offset + i] = ((value >> (7 * i)) & 0x7F) as u8 | 0x80;
    }
    buf[offset + 9] = ((value >> 63) & 0x01) as u8;
}

/// Write a 10-byte padded signed LEB128 value (64-bit) at a specific offset.
/// The final byte carries the sign-extension pattern in bit 0x40 so that a
/// reader correctly recovers the signed value.
fn write_padded_sleb128_i64(buf: &mut [u8], offset: usize, value: i64) {
    if offset + 10 > buf.len() {
        return;
    }
    let uvalue = value as u64;
    for i in 0..9 {
        buf[offset + i] = ((uvalue >> (7 * i)) & 0x7F) as u8 | 0x80;
    }
    // Arithmetic right shift preserves the sign: for value >= 0 the top bits
    // are 0, for value < 0 they are 1, giving the SLEB128 terminator its
    // correct sign bit (0x40).
    buf[offset + 9] = ((value >> 63) as u8) & 0x7F;
}

/// Write a 5-byte padded signed LEB128 value at a specific offset.
fn write_padded_sleb128(buf: &mut [u8], offset: usize, value: i32) {
    if offset + 5 > buf.len() {
        return; // Not enough space — skip this relocation.
    }
    // Encode as unsigned but with sign extension in the high bits.
    let uvalue = value as u32;
    buf[offset] = (uvalue & 0x7F) as u8 | 0x80;
    buf[offset + 1] = ((uvalue >> 7) & 0x7F) as u8 | 0x80;
    buf[offset + 2] = ((uvalue >> 14) & 0x7F) as u8 | 0x80;
    buf[offset + 3] = ((uvalue >> 21) & 0x7F) as u8 | 0x80;
    buf[offset + 4] = ((uvalue >> 28) & 0x0F) as u8;
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

/// Merge the `target_features` custom sections from every input object
/// per spec §8. Returns the encoded payload (count + {prefix, name_len,
/// name} entries) for the merged section, or an empty vec when no input
/// carried a target_features section.
///
/// Rules:
/// - `+` (0x2b): this object USES the feature.
/// - `-` (0x2d): this object DISALLOWS the feature.
/// - `=` (0x3d): deprecated REQUIRED; wild treats it the same as USED.
/// - A feature USED by one input and DISALLOWED by another is a conflict.
/// - Output carries `+` for every USED feature and `-` for every feature
///   DISALLOWED by at least one input that no input uses.
fn merge_target_features<'a>(
    per_object_custom: impl IntoIterator<Item = &'a [CustomSection]>,
    shared_memory: bool,
) -> crate::error::Result<Vec<u8>> {
    use std::collections::BTreeSet;
    let mut used: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut disallowed: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut saw_any = false;

    for obj in per_object_custom {
        for cs in obj {
            if cs.name != b"target_features" {
                continue;
            }
            saw_any = true;
            let (count, mut off) = read_leb128(&cs.data)?;
            for _ in 0..count {
                if off >= cs.data.len() {
                    break;
                }
                let prefix = cs.data[off];
                off += 1;
                let (nlen, c) = read_leb128(&cs.data[off..])?;
                off += c;
                if off + nlen > cs.data.len() {
                    break;
                }
                let name = cs.data[off..off + nlen].to_vec();
                off += nlen;
                match prefix {
                    b'+' | b'=' => {
                        used.insert(name);
                    }
                    b'-' => {
                        disallowed.insert(name);
                    }
                    _ => {
                        tracing::warn!(
                            "wasm: target_features: unknown prefix byte {prefix:#04x}"
                        );
                    }
                }
            }
        }
    }

    if !saw_any {
        return Ok(Vec::new());
    }

    // Conflict: a feature used by some input and disallowed by another.
    for name in used.intersection(&disallowed) {
        crate::bail!(
            "target_features: feature {:?} is USED by one input and DISALLOWED by another",
            String::from_utf8_lossy(name)
        );
    }

    // Spec §8: "The linker will error out if a shared memory is requested
    // but the atomics target feature is disallowed in the target features
    // section of any input objects."
    if shared_memory && disallowed.contains(b"atomics".as_slice()) {
        crate::bail!(
            "--shared-memory requires the atomics feature, \
             but an input object's target_features lists '-atomics'"
        );
    }

    // Drop disallowed entries that anything uses (they can't both be true;
    // the conflict check above rules this out, but defensively compute the
    // set difference so the output is always consistent).
    let disallowed_only: Vec<Vec<u8>> =
        disallowed.difference(&used).cloned().collect();

    let mut payload = Vec::new();
    write_leb128(
        &mut payload,
        (used.len() + disallowed_only.len()) as u32,
    );
    for name in &used {
        payload.push(b'+');
        write_leb128(&mut payload, name.len() as u32);
        payload.extend_from_slice(name);
    }
    for name in &disallowed_only {
        payload.push(b'-');
        write_leb128(&mut payload, name.len() as u32);
        payload.extend_from_slice(name);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a 5-byte padded unsigned LEB128.
    fn decode_padded_u32(buf: &[u8; 5]) -> u32 {
        let mut v = 0u32;
        for i in 0..5 {
            v |= ((buf[i] & 0x7F) as u32) << (i * 7);
        }
        v
    }

    /// Decode a 5-byte padded signed LEB128.
    fn decode_padded_i32(buf: &[u8; 5]) -> i32 {
        let mut v = 0i64;
        for i in 0..5 {
            v |= ((buf[i] & 0x7F) as i64) << (i * 7);
        }
        // Sign extend from bit 34 (the highest bit carried by the last byte).
        let sign_bit = 1i64 << 34;
        if v & sign_bit != 0 {
            v |= !((sign_bit << 1) - 1);
        }
        v as i32
    }

    /// Decode a 10-byte padded unsigned LEB128 (64-bit).
    fn decode_padded_u64(buf: &[u8; 10]) -> u64 {
        let mut v = 0u64;
        for i in 0..9 {
            v |= ((buf[i] & 0x7F) as u64) << (i * 7);
        }
        v |= ((buf[9] & 0x01) as u64) << 63;
        v
    }

    /// Decode a 10-byte padded signed LEB128 (64-bit).
    fn decode_padded_i64(buf: &[u8; 10]) -> i64 {
        let mut v = 0u64;
        for i in 0..9 {
            v |= ((buf[i] & 0x7F) as u64) << (i * 7);
        }
        // Final byte carries sign-extension: bit 0x40 is the SLEB terminator
        // sign bit. For negative values byte 9 is 0x7F; for non-negative, 0.
        if buf[9] & 0x40 != 0 {
            v |= !((1u64 << 63) - 1);
        }
        v as i64
    }

    fn roundtrip_u32(v: u32) {
        let mut buf = [0u8; 5];
        write_padded_leb128(&mut buf, 0, v);
        assert_eq!(decode_padded_u32(&buf), v, "u32 roundtrip failed for {v}");
        assert_eq!(read_padded_leb128(&buf, 0), v);
    }

    fn roundtrip_i32(v: i32) {
        let mut buf = [0u8; 5];
        write_padded_sleb128(&mut buf, 0, v);
        assert_eq!(decode_padded_i32(&buf), v, "i32 roundtrip failed for {v}");
    }

    fn roundtrip_u64(v: u64) {
        let mut buf = [0u8; 10];
        write_padded_leb128_u64(&mut buf, 0, v);
        assert_eq!(decode_padded_u64(&buf), v, "u64 roundtrip failed for {v}");
    }

    fn roundtrip_i64(v: i64) {
        let mut buf = [0u8; 10];
        write_padded_sleb128_i64(&mut buf, 0, v);
        assert_eq!(decode_padded_i64(&buf), v, "i64 roundtrip failed for {v}");
    }

    #[test]
    fn padded_leb128_u32_roundtrip() {
        for &v in &[0u32, 1, 127, 128, 0x3FFF, 0x4000, 0x80000000, u32::MAX] {
            roundtrip_u32(v);
        }
    }

    #[test]
    fn padded_sleb128_i32_roundtrip() {
        for &v in &[0i32, 1, -1, 63, 64, -64, -65, i32::MAX, i32::MIN, 0x3FFFFFFF, -0x40000000] {
            roundtrip_i32(v);
        }
    }

    #[test]
    fn padded_leb128_u64_roundtrip() {
        for &v in &[0u64, 1, 127, 128, 1 << 32, (1u64 << 63) - 1, 1u64 << 63, u64::MAX] {
            roundtrip_u64(v);
        }
    }

    #[test]
    fn padded_sleb128_i64_roundtrip() {
        let cases: &[i64] = &[
            0, 1, -1, 63, 64, -64, -65,
            i32::MAX as i64, i32::MIN as i64,
            i64::MAX, i64::MIN,
            (1i64 << 40), -(1i64 << 40),
        ];
        for &v in cases {
            roundtrip_i64(v);
        }
    }

    /// Build a minimal wasm module containing:
    ///   - a type section with one type (func () -> ())
    ///   - an import of a tag named "extag" using that type
    ///   - a tag section defining one local tag of the same type
    ///   - a linking custom section with one SYMTAB_EVENT symbol for the def
    /// Then round-trip it through parse_wasm_sections and assert the shape.
    fn tf(entries: &[(u8, &[u8])]) -> Vec<CustomSection> {
        let mut data = Vec::new();
        write_leb128(&mut data, entries.len() as u32);
        for (prefix, name) in entries {
            data.push(*prefix);
            write_leb128(&mut data, name.len() as u32);
            data.extend_from_slice(name);
        }
        vec![CustomSection {
            name: b"target_features".to_vec(),
            data,
        }]
    }

    fn parse_tf(payload: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let (count, mut off) = read_leb128(payload).unwrap();
        let mut out = Vec::new();
        for _ in 0..count {
            let prefix = payload[off];
            off += 1;
            let (nlen, c) = read_leb128(&payload[off..]).unwrap();
            off += c;
            let name = payload[off..off + nlen].to_vec();
            off += nlen;
            out.push((prefix, name));
        }
        out
    }

    #[test]
    fn target_features_union_of_used() {
        let a = tf(&[(b'+', b"atomics"), (b'+', b"simd128")]);
        let b = tf(&[(b'+', b"atomics"), (b'+', b"bulk-memory")]);
        let merged = merge_target_features([a.as_slice(), b.as_slice()], false).unwrap();
        let mut got = parse_tf(&merged);
        got.sort();
        assert_eq!(
            got,
            vec![
                (b'+', b"atomics".to_vec()),
                (b'+', b"bulk-memory".to_vec()),
                (b'+', b"simd128".to_vec()),
            ]
        );
    }

    #[test]
    fn target_features_disallowed_without_use_survives() {
        let a = tf(&[(b'+', b"simd128")]);
        let b = tf(&[(b'-', b"atomics")]);
        let merged = merge_target_features([a.as_slice(), b.as_slice()], false).unwrap();
        let mut got = parse_tf(&merged);
        got.sort_by(|(_, n1), (_, n2)| n1.cmp(n2));
        assert_eq!(
            got,
            vec![
                (b'-', b"atomics".to_vec()),
                (b'+', b"simd128".to_vec()),
            ]
        );
    }

    #[test]
    fn target_features_conflict_errors() {
        let a = tf(&[(b'+', b"atomics")]);
        let b = tf(&[(b'-', b"atomics")]);
        let err = merge_target_features([a.as_slice(), b.as_slice()], false)
            .expect_err("expected conflict error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("atomics") && msg.contains("USED") && msg.contains("DISALLOWED"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn target_features_legacy_equals_is_treated_as_used() {
        // '=' (0x3d) is the deprecated REQUIRED prefix; wild folds it into '+'.
        let a = tf(&[(b'=', b"multivalue")]);
        let b = tf(&[(b'-', b"multivalue")]);
        merge_target_features([a.as_slice(), b.as_slice()], false)
            .expect_err("'=' in one input and '-' in another must conflict");
    }

    #[test]
    fn target_features_empty_when_no_inputs_carry_section() {
        let empty: Vec<CustomSection> = Vec::new();
        let payload = merge_target_features([empty.as_slice()], false).unwrap();
        assert!(payload.is_empty());
    }

    #[test]
    fn target_features_shared_memory_requires_atomics() {
        // An input that disallows atomics combined with --shared-memory
        // must error per spec §8.
        let a = tf(&[(b'-', b"atomics")]);
        let err = merge_target_features([a.as_slice()], true)
            .expect_err("shared_memory + '-atomics' must error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("shared-memory") && msg.contains("atomics"),
            "unexpected error: {msg}"
        );
        // Same input without shared_memory is fine.
        merge_target_features([a.as_slice()], false).unwrap();
    }

    #[test]
    fn memory64_import_flag_detected() {
        fn section(id: u8, payload: &[u8]) -> Vec<u8> {
            let mut v = Vec::new();
            v.push(id);
            let mut len = Vec::new();
            write_leb128(&mut len, payload.len() as u32);
            v.extend_from_slice(&len);
            v.extend_from_slice(payload);
            v
        }

        fn build(flags: u8) -> Vec<u8> {
            let mut wasm = Vec::new();
            wasm.extend_from_slice(b"\0asm");
            wasm.extend_from_slice(&[1, 0, 0, 0]);
            let mut imp = Vec::new();
            write_leb128(&mut imp, 1);
            write_name(&mut imp, b"env");
            write_name(&mut imp, b"memory");
            imp.push(0x02); // kind: memory
            imp.push(flags);
            write_leb128(&mut imp, 1); // min pages
            wasm.extend_from_slice(&section(SECTION_IMPORT, &imp));
            wasm
        }

        // 32-bit memory import: is_memory64 should remain false.
        let p32 = parse_wasm_sections(&build(0x00)).unwrap();
        assert!(!p32.is_memory64);

        // memory64 memory import (limits flag 0x04): is_memory64 true.
        let p64 = parse_wasm_sections(&build(0x04)).unwrap();
        assert!(p64.is_memory64);

        // shared memory64 (0x02 shared + 0x04 mem64 + 0x01 has-max).
        let mut shared = Vec::new();
        shared.extend_from_slice(b"\0asm");
        shared.extend_from_slice(&[1, 0, 0, 0]);
        let mut imp = Vec::new();
        write_leb128(&mut imp, 1);
        write_name(&mut imp, b"env");
        write_name(&mut imp, b"memory");
        imp.push(0x02);
        imp.push(0x07); // max | shared | mem64
        write_leb128(&mut imp, 1);
        write_leb128(&mut imp, 10);
        shared.extend_from_slice(&section(SECTION_IMPORT, &imp));
        let ps = parse_wasm_sections(&shared).unwrap();
        assert!(ps.is_memory64);
    }

    #[test]
    fn tag_section_parse_roundtrip() {
        // Helper to wrap a section payload with id + LEB length prefix.
        fn section(id: u8, payload: &[u8]) -> Vec<u8> {
            let mut v = Vec::new();
            v.push(id);
            let mut len = Vec::new();
            write_leb128(&mut len, payload.len() as u32);
            v.extend_from_slice(&len);
            v.extend_from_slice(payload);
            v
        }

        let mut wasm = Vec::new();
        wasm.extend_from_slice(b"\0asm");
        wasm.extend_from_slice(&[1, 0, 0, 0]);

        // Type section: one type (0x60 params:0 results:0).
        wasm.extend_from_slice(&section(SECTION_TYPE, &[0x01, 0x60, 0x00, 0x00]));

        // Import section: one tag import.
        let mut imp = Vec::new();
        write_leb128(&mut imp, 1); // count
        write_name(&mut imp, b"env");
        write_name(&mut imp, b"extag");
        imp.push(0x04); // kind: tag
        imp.push(0x00); // attribute
        write_leb128(&mut imp, 0); // type idx
        wasm.extend_from_slice(&section(SECTION_IMPORT, &imp));

        // Tag section: one local tag of type 0.
        let mut tagp = Vec::new();
        write_leb128(&mut tagp, 1); // count
        tagp.push(0x00); // attribute
        write_leb128(&mut tagp, 0); // type idx
        wasm.extend_from_slice(&section(SECTION_TAG, &tagp));

        let parsed = parse_wasm_sections(&wasm).expect("parse ok");
        assert_eq!(parsed.num_tag_imports, 1, "tag import count");
        assert_eq!(parsed.import_tag_names, vec![b"extag".to_vec()]);
        assert_eq!(parsed.tags, vec![0u32], "local tag type indices");
        let tag_imp = parsed
            .imports
            .iter()
            .find(|i| i.kind == 4)
            .expect("tag import present");
        assert_eq!(tag_imp.field, b"extag");
        assert_eq!(tag_imp.type_index, 0);
    }
}
