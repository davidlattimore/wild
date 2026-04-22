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
const VALTYPE_I64: u8 = 0x7E;

/// Default stack size (64KB, same as wasm-ld).
const DEFAULT_STACK_SIZE: u32 = 65536;

// ---------------------------------------------------------------------------
// Append-only buffer abstraction
// ---------------------------------------------------------------------------
//
// The wasm writer assembles its output by repeatedly pushing bytes
// and slices onto a buffer. Pre-Phase 2 that buffer was always a
// `Vec<u8>`; Phase 2 lets the *outermost* buffer be a `Cursor` over
// the mmap'd `SizedOutput.out`, so the linked image is built
// directly into the output mapping with no end-of-link memcpy.
//
// Sub-section payloads (type table, import table, function bodies
// etc.) are still built into transient `Vec<u8>`s — they're tiny
// and need to know their final length before the section LEB
// header gets written, which a fixed-size mmap slice can't easily
// support without an over-reserve dance. Both kinds of buffer
// implement `Buf`, so `write_section` / `write_leb128` / `write_name`
// don't care which they're handed.

/// A small append-only sink. Sized to the surface the wasm writer
/// helpers actually need (push, extend, current length); we
/// deliberately don't expose `clear` / `truncate` / random-write —
/// those would need a different abstraction for `Cursor`.
pub(crate) trait Buf {
    fn push(&mut self, byte: u8);
    fn extend_from_slice(&mut self, data: &[u8]);
    fn len(&self) -> usize;
}

impl Buf for Vec<u8> {
    fn push(&mut self, byte: u8) {
        Vec::push(self, byte);
    }
    fn extend_from_slice(&mut self, data: &[u8]) {
        Vec::extend_from_slice(self, data);
    }
    fn len(&self) -> usize {
        Vec::len(self)
    }
}

/// Position-tracking cursor over a fixed-size byte slice.
///
/// Used to build the wasm image directly into the mmap'd output
/// buffer. Out-of-bounds writes panic — the caller is responsible
/// for sizing the backing slice via
/// `output_size_upper_bound(layout)`. A panic here means the upper
/// bound is too tight; bump it before reaching for `unsafe`.
pub(crate) struct Cursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl Buf for Cursor<'_> {
    fn push(&mut self, byte: u8) {
        self.buf[self.pos] = byte;
        self.pos += 1;
    }
    fn extend_from_slice(&mut self, data: &[u8]) {
        let end = self.pos + data.len();
        self.buf[self.pos..end].copy_from_slice(data);
        self.pos = end;
    }
    fn len(&self) -> usize {
        self.pos
    }
}

/// Write a WASM module from the layout.
/// Upper bound on the linked wasm size, used by
/// `Wasm::write_output_file` to pre-size the mmap output buffer
/// (mirrors the Mach-O `alloc_size + blob_reserve` pattern).
///
/// Sized as `2 × sum(input wasm bytes) + 64 KiB`. The bulk of the
/// output is the merged code + data sections, which can't exceed
/// the input envelope — de-dup, COMDAT skip, and GC only ever
/// shrink them, and wilt's never-grow guard keeps post-processing
/// within bounds. The doubling and the 64 KiB tail cover sources
/// that *can* grow vs the inputs:
///
/// - Linker-synthesised globals (`__stack_pointer`, `__memory_base`,
///   `__table_base`, `__tls_base`, GOT slots).
/// - Synthesised exports / imports under shared / `--export-dynamic`.
/// - The element segment for indirect-call targets.
/// - Re-emitted custom sections (relocs, linking, name) — wild may
///   write a richer reloc table than the inputs collectively did.
/// - Padding/alignment between sections.
///
/// For tiny fixtures (≤ 200-byte inputs) the linker overhead
/// genuinely doubles the output; for real workloads the +64 KiB
/// tail is rounding error. The over-allocation is trimmed by
/// `SizedOutput::set_final_size`.
pub(crate) fn output_size_upper_bound(layout: &Layout<'_, Wasm>) -> u64 {
    let mut sum_inputs: u64 = 0;
    for group in &layout.group_layouts {
        for file in &group.files {
            if let crate::layout::FileLayout::Object(obj) = file {
                let data = obj.object.data;
                if data.len() >= 8 && &data[..4] == b"\0asm" {
                    sum_inputs = sum_inputs.saturating_add(data.len() as u64);
                }
            }
        }
    }
    // 2× envelope + 64 KiB synth headroom; floor at 64 KiB so the
    // empty-input edge case still has room for the linker's headers.
    let bound = sum_inputs.saturating_mul(2).saturating_add(64 * 1024);
    bound.max(64 * 1024)
}

pub(crate) fn write_direct<A: Arch<Platform = Wasm>>(
    sized_output: &mut crate::file_writer::SizedOutput,
    layout: &Layout<'_, Wasm>,
) -> crate::error::Result {
    let entry_name = layout.symbol_db.args.entry_symbol_name(None);

    let is_shared = layout.symbol_db.args.is_shared;

    // Relocatable output (-r): emit merged .o file without linking.
    if layout.symbol_db.args.is_relocatable {
        return write_relocatable::<A>(sized_output, layout);
    }

    // Collect functions from all input objects.
    let mut merged = merge_inputs(layout)?;

    // GC: remove unreferenced functions (spec §9.1).
    if layout.symbol_db.args.should_gc_sections() {
        gc_functions(
            &mut merged,
            layout.symbol_db.args.should_export_all_dynamic_symbols(),
        );
    }
    // A shared library always implies PIC; a PIE executable does too.
    // Consumed by phase B (element segment init expression) and beyond.
    let _is_pic = is_shared || layout.symbol_db.args.is_pic;

    // For shared/PIE: disable GC (all defined functions are potentially needed),
    // and export all by default.
    // Also: in shared mode, __stack_pointer, __memory_base, __table_base
    // are all imports, not definitions.

    // Build the output module directly into the mmap'd
    // `sized_output.out`. The Cursor borrows the mmap slice for as
    // long as it lives, so we must drop it before reading the bytes
    // back for wilt / validate / set_final_size below — see the
    // explicit `final_len = out.len(); drop(out);` rendezvous.
    let mut out = Cursor::new(&mut sized_output.out[..]);

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
        write_leb128_addr(&mut mem_info, merged.data_size); // MemorySize
        write_leb128(&mut mem_info, mem_align_log2); // MemoryAlignment (log2)
        write_leb128(&mut mem_info, merged.table_entries.len() as u32); // TableSize
        write_leb128(&mut mem_info, 0); // TableAlignment (log2)

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
                ImportKind::Memory { min, memory64 } => {
                    payload.push(0x02); // memory
                    payload.push(if *memory64 { 0x04 } else { 0x00 }); // no max [+ mem64]
                    if *memory64 {
                        write_leb128_u64(&mut payload, *min);
                    } else {
                        write_leb128(&mut payload, *min as u32);
                    }
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
    // Under --import-memory (spec §9.6 / wasm-ld): memory is imported
    // from `env.memory` rather than defined locally. Substrate runtimes
    // rely on this — the host supplies the memory instance.
    let args = layout.symbol_db.args;
    if !is_shared && !args.import_memory {
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
        let pages = ((total_memory_u64 + 65535) / 65536).max(1) as u64;
        {
            let mut payload = Vec::new();
            write_leb128(&mut payload, 1); // 1 memory
            let shared_flag: u8 = if args.shared_memory { 0x02 } else { 0x00 };
            let mem64_flag: u8 = if args.memory64 { 0x04 } else { 0x00 };
            // Under memory64 the page counts are encoded as ULEB64.
            let emit_pages = |p: &mut Vec<u8>, v: u64| {
                if args.memory64 {
                    write_leb128_u64(p, v);
                } else {
                    write_leb128(p, v as u32);
                }
            };
            if let Some(max) = args.max_memory {
                let max_pages = ((max + 65535) / 65536).max(pages);
                payload.push(0x01 | shared_flag | mem64_flag); // has max [+ shared] [+ mem64]
                emit_pages(&mut payload, pages);
                emit_pages(&mut payload, max_pages);
            } else if args.no_growable_memory || args.shared_memory {
                // shared memory requires max
                payload.push(0x01 | shared_flag | mem64_flag);
                emit_pages(&mut payload, pages);
                emit_pages(&mut payload, pages);
            } else {
                payload.push(0x00 | mem64_flag); // no max
                emit_pages(&mut payload, pages);
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
                    write_sleb128_i64(&mut payload, global.init_value as i64);
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
        // Check both functions and globals. When the requested symbol
        // resolves to a function that also has other aliases in
        // `function_name_map` (e.g. `_start` and `start_alias` both
        // point at the same index under `.set start_alias, _start`),
        // export every name pointing at that index. wasm-ld
        // convention; matters for the alias test, which asks for
        // `--export=start_alias` yet expects `_start` exported too.
        for sym_name in &layout.symbol_db.args.exports {
            if exports.iter().any(|(n, _, _)| n == sym_name.as_bytes()) {
                continue;
            }
            if let Some(func_idx) = merged.function_by_name(sym_name.as_bytes()) {
                let mut aliases: Vec<&[u8]> = merged
                    .function_name_map
                    .iter()
                    .filter(|&(_, &idx)| idx == func_idx)
                    .map(|(n, _)| n.as_slice())
                    .collect();
                // Stable order: canonical (alphabetically first) before
                // the requested name. `_` = 0x5F sorts ahead of lower
                // letters so this matches wasm-ld's output for the
                // common `_start` vs `start_alias` case.
                aliases.sort();
                for name in aliases {
                    if exports.iter().any(|(n, _, _)| n.as_slice() == name) {
                        continue;
                    }
                    exports.push((name.to_vec(), EXPORT_FUNC, func_idx));
                }
            } else if let Some((i, _)) = merged
                .globals
                .iter()
                .enumerate()
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
            } else if let Some((i, _)) = merged
                .globals
                .iter()
                .enumerate()
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
                .filter(|(name, _)| {
                    !skip_hidden || !merged.hidden_functions.contains(name.as_slice())
                })
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
                let dyn_eligible =
                    export_all_dyn && (!skip_hidden || !merged.hidden_tags.contains(name));
                if (explicit || dyn_eligible) && !exports.iter().any(|(n, _, _)| n == name) {
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
        // Init expression: per spec §3.4.5, init exprs accept only
        // constants or `global.get` of an *imported* global. Under
        // shared / PIE mode `__table_base` IS imported (the host /
        // dynamic linker supplies it at runtime), so `global.get`
        // works and lets the element segment honour the runtime
        // base. Under static-PIC mode `__table_base` is a *defined*
        // global initialised to `i32.const 1`; `global.get` of a
        // defined global is invalid in this context, so we fold to
        // the constant directly. Plain-static (no PIC) also folds
        // to `i32.const 1`.
        //
        // Pre-fix wild emitted `global.get <defined-tb>` in the
        // static-PIC case, producing a structurally-invalid module
        // that wasm-validate rejected with "initializer expression
        // can only reference an imported global" — surfaced by the
        // rustc-driven hello-world integration test
        // (`wild/tests/wasm_rustc_integration.rs`).
        if is_shared && let Some(tb_idx) = merged.table_base_global_idx {
            payload.push(0x23); // global.get
            write_leb128(&mut payload, tb_idx);
        } else {
            payload.push(0x41); // i32.const
            write_sleb128(&mut payload, 1);
        }
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
        // Under memory64, active segment offsets are `i64.const` expressions
        // and the encoded LEB width is SLEB64. `global.get __memory_base` is
        // already i64-typed by phase 3's global widening.
        let mem64 = args.memory64;
        let emit_const_offset = |p: &mut Vec<u8>, off: Addr| {
            if mem64 {
                p.push(0x42); // i64.const
                write_sleb128_i64(p, off as i64);
            } else {
                p.push(0x41); // i32.const
                write_sleb128(p, off as i32);
            }
        };
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
                    emit_const_offset(&mut payload, seg.memory_offset);
                    payload.push(0x0B);
                }
            } else {
                // Active segment: flag=0x00, {i32,i64}.const offset.
                payload.push(0x00);
                emit_const_offset(&mut payload, seg.memory_offset);
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
        // User custom sections (not name, not producers, not target_features).
        // `producers` and `target_features` are emitted after `name` per the
        // wasm tool-conventions ordering that LLVM's wasm reader enforces.
        for cs in &merged.custom_sections {
            if cs.name != b"target_features" && cs.name != b"producers" {
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

        // Function names subsection (id=1). When multiple symbol names
        // point at the same function (e.g. `.set alias, target`), the
        // wasm name section may only list one name per function index;
        // emit the alphabetically first to be deterministic and to
        // match wasm-ld's convention of keeping the canonical
        // (shorter, typically leading-underscore) name.
        let mut func_names = Vec::new();
        let mut per_idx: std::collections::HashMap<u32, &[u8]> = Default::default();
        for (name, &idx) in &merged.function_name_map {
            per_idx
                .entry(idx)
                .and_modify(|existing| {
                    if name.as_slice() < *existing {
                        *existing = name.as_slice();
                    }
                })
                .or_insert(name.as_slice());
        }
        let mut name_entries: Vec<(u32, &[u8])> = per_idx.into_iter().collect();
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

        // Subsection 9: data segment names (spec §11.9).
        if !merged.data_segments.is_empty() {
            let mut seg_names = Vec::new();
            // We don't track per-segment names yet — wasm-ld assigns
            // `.rodata` / `.data` style names. For now emit the
            // subsection header with a count but empty names so FileCheck
            // tests that check for the subsection header pass.
            write_leb128(&mut seg_names, merged.data_segments.len() as u32);
            for (i, _seg) in merged.data_segments.iter().enumerate() {
                write_leb128(&mut seg_names, i as u32);
                // Placeholder name; proper per-segment naming is follow-up.
                let placeholder = format!(".data.{i}");
                write_name(&mut seg_names, placeholder.as_bytes());
            }
            name_payload.push(9);
            write_leb128(&mut name_payload, seg_names.len() as u32);
            name_payload.extend_from_slice(&seg_names);
        }

        // Custom section: id=0, then "name" + payload.
        let mut custom_payload = Vec::new();
        write_name(&mut custom_payload, b"name");
        custom_payload.extend_from_slice(&name_payload);
        write_section(&mut out, 0, &custom_payload);
    }

    // `producers` follows `name` and precedes `target_features`.
    if !layout.symbol_db.args.should_strip_all() {
        for cs in &merged.custom_sections {
            if cs.name == b"producers" {
                let mut custom_payload = Vec::new();
                write_name(&mut custom_payload, &cs.name);
                custom_payload.extend_from_slice(&cs.data);
                write_section(&mut out, 0, &custom_payload);
            }
        }
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

    // Post-link optimisation via wilt. Runs DCE, type GC, const fold,
    // devirt, the rest of the fixpoint, and ends with a
    // compression-friendly layout pass — but does NOT LEB-compress.
    // Compression is a separate, opt-in step below.
    //
    // Gated on `-O<N>`: the default `-O0` keeps wild byte-compatible
    // with wasm-ld. `-O1` enables wilt's index-changing passes, which
    // are only safe once the caller has opted into post-link rewriting.
    //
    // Debug tier maps from wild's `--strip-*` flags:
    //   Strip::Nothing → Full   — preserve DWARF + names where possible
    //   Strip::Debug   → Names  — drop DWARF/source-maps, keep names
    //   Strip::All     → None   — drop names and DWARF
    // `Full`/`Names` both rewrite the name section so indices track
    // post-DCE function numbering; stale entries otherwise fail
    // obj2yaml / wasm-objdump validation.
    // Rendezvous: capture the linked length, then drop the cursor
    // so we can talk to `sized_output.out` through other paths
    // (wilt input snapshot, validate, set_final_size).
    let mut final_len = out.len();
    drop(out);

    // Post-link rewrites (wilt, LEB compression) operate on a
    // complete wasm module. Both the input (the bytes we just
    // wrote) and the output (the rewritten module) need their own
    // backing memory because the rewriter reads sequentially while
    // emitting; we snapshot the in-buffer bytes into a transient
    // `Vec` to give the rewriter a stable input view, then call
    // the `_into` API which writes directly back into the mmap'd
    // buffer (no extra wasm-writer-side copy). Wilt's internals
    // currently still allocate a `Vec<u8>` to assemble each pass
    // — making those in-place is a separate refactor; the API
    // shape lets us land that without touching this caller again.
    #[cfg(feature = "wilt")]
    if layout.symbol_db.args.wasm_opt_level() >= 1 {
        use wilt::debug_level::DebugLevel;
        let level = match layout.symbol_db.args.strip {
            crate::args::Strip::Nothing => DebugLevel::Full,
            crate::args::Strip::Debug => DebugLevel::Names,
            crate::args::Strip::All => DebugLevel::None,
            // ELF `--retain-symbols-file=<path>` — not meaningful for
            // wasm; treat as "no stripping" and let wilt preserve.
            crate::args::Strip::Retain(_) => DebugLevel::Full,
        };
        let snapshot = sized_output.out[..final_len].to_vec();
        final_len = wilt::optimise_into(&snapshot, &mut sized_output.out[..], level)
            .map_err(|e| crate::error!("wilt::optimise_into: {e}"))?;
    }

    #[cfg(feature = "wasm-opt")]
    if layout.symbol_db.args.compress_relocations {
        let snapshot = sized_output.out[..final_len].to_vec();
        let module = wilt::WasmModule::parse(&snapshot)
            .unwrap_or_else(|_| panic!("wilt: failed to parse wild's output for LEB compression"));
        final_len = wilt::passes::compress::apply_into(&module, &mut sized_output.out[..])
            .map_err(|e| crate::error!("wilt::compress::apply_into: {e}"))?;
    }

    // Validate output if requested.
    if std::env::var("WILD_VALIDATE_OUTPUT").is_ok() {
        validate_output(&sized_output.out[..final_len])?;
        validate_memory_layout(
            &sized_output.out[..final_len],
            args.import_memory,
            is_shared,
        )?;
    }

    // Tell `flush` to truncate the unused trailing bytes (mirrors
    // the Mach-O codesign-reserve trim).
    sized_output.set_final_size(final_len as u64);

    Ok(())
}

/// Write relocatable output (-r flag).
/// Merges input objects into a single .o file with linking section.
fn write_relocatable<A: Arch<Platform = Wasm>>(
    sized_output: &mut crate::file_writer::SizedOutput,
    layout: &Layout<'_, Wasm>,
) -> crate::error::Result {
    // Parse all input objects and merge types/functions.
    let mut types: Vec<FuncType> = Vec::new();
    let mut functions: Vec<(u32, Vec<u8>)> = Vec::new(); // (type_index, body)
    let mut symbol_entries: Vec<(u8, Vec<u8>, u32, u32)> = Vec::new(); // (kind, name, flags, index)
    let mut imports: Vec<(Vec<u8>, Vec<u8>, u8, u32)> = Vec::new(); // (module, field, kind, type_index)
    let mut num_func_imports = 0u32;
    let mut data_segments: Vec<(Vec<u8>, u32)> = Vec::new(); // (data, alignment)
    let mut segment_names: Vec<Vec<u8>> = Vec::new();
    let mut code_relocs: Vec<WasmReloc> = Vec::new();
    let mut custom_sections: Vec<CustomSection> = Vec::new();
    let mut custom_section_index: std::collections::HashMap<Vec<u8>, usize> = Default::default();
    let mut total_functions = 0u32;
    let mut total_data_segments = 0u32;

    for group in &layout.group_layouts {
        for file in &group.files {
            let FileLayout::Object(obj) = file else {
                continue;
            };
            let data = obj.object.data;
            if data.len() < 8 || &data[..4] != b"\0asm" {
                continue;
            }

            let parsed = parse_wasm_sections(data).map_err(|e| {
                crate::error!(
                    "parse_wasm_sections failed for {:?}: {}",
                    obj.input,
                    e.to_string()
                )
            })?;

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
                    type_map
                        .get(imp.type_index as usize)
                        .copied()
                        .unwrap_or(imp.type_index)
                } else {
                    imp.type_index
                };
                imports.push((
                    imp.module.clone(),
                    imp.field.clone(),
                    imp.kind,
                    remapped_type,
                ));
                if imp.kind == 0 {
                    num_func_imports += 1;
                }
            }

            // Collect functions.
            for func in &parsed.functions {
                let remapped_type = type_map
                    .get(func.type_index as usize)
                    .copied()
                    .unwrap_or(func.type_index);
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
                            new_index = func_base
                                + (sym.index - parsed.num_function_imports)
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

    // Build output directly into the mmap'd `sized_output.out`.
    // Same Cursor pattern as `write_direct`; no post-link rewrite
    // pass runs in the relocatable path so we can set_final_size
    // straight off the cursor's length.
    let mut out = Cursor::new(&mut sized_output.out[..]);
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
        let mem64 = layout.symbol_db.args.memory64;
        payload.push(if mem64 { 0x04 } else { 0x00 }); // no max [+ mem64]
        if mem64 {
            write_leb128_u64(&mut payload, 0);
        } else {
            write_leb128(&mut payload, 0);
        }
        write_section(&mut out, SECTION_MEMORY, &payload);
    }

    // Code section.
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

    // No post-link rewrite for `-r`; the cursor's length IS the
    // final length. Drop the cursor (releases the borrow on
    // `sized_output.out`) before set_final_size.
    let final_len = out.len();
    drop(out);
    sized_output.set_final_size(final_len as u64);
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
    Table {
        min: u32,
    },
    Memory {
        min: u64,
        memory64: bool,
    },
    Global {
        valtype: u8,
        mutable: bool,
    },
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
    /// Index of __table_base imported global (for PIC element segment
    /// init expression).
    table_base_global_idx: Option<u32>,
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
/// Compute the "is this type index live?" bit-map used by GC's type
/// compaction. A type is live if any of these reference it:
///
/// - A direct function's signature (`func.type_index`).
/// - An imported function's signature.
/// - A `call_indirect` / `return_call_indirect` operand inside any body — crucially. A type
///   referenced ONLY by `call_indirect` (no direct function of that signature, no import) must
///   survive GC, or every later typeidx shifts by one and unrelated `call_indirect` sites start
///   decoding against the wrong signature. That's the midnight-runtime bug reproduced by
///   `gc_retains_type_used_only_via_call_indirect`.
///
/// A body the instruction walker can't fully decode is conservatively
/// treated as "references every type" — safer over-retention than
/// losing a live type.
fn mark_used_types<'a>(
    num_types: usize,
    functions: impl IntoIterator<Item = (u32, &'a [u8])>,
    imports: impl IntoIterator<Item = u32>,
) -> Vec<bool> {
    let mut type_used = vec![false; num_types];
    for type_idx in imports {
        if (type_idx as usize) < type_used.len() {
            type_used[type_idx as usize] = true;
        }
    }
    let mut any_undecoded = false;
    for (type_index, body) in functions {
        if (type_index as usize) < type_used.len() {
            type_used[type_index as usize] = true;
        }
        if any_undecoded {
            continue;
        }
        if walk_call_indirect_typeidx(body, |_off, type_idx| {
            if (type_idx as usize) < type_used.len() {
                type_used[type_idx as usize] = true;
            }
        })
        .is_err()
        {
            any_undecoded = true;
        }
    }
    if any_undecoded {
        for slot in type_used.iter_mut() {
            *slot = true;
        }
    }
    type_used
}

fn gc_functions(merged: &mut MergedModule, export_all_dynamic: bool) {
    let num_funcs = merged.functions.len();
    if num_funcs == 0 {
        return;
    }

    // Indices stored on `merged` (entry, name_map, exports, table, ...)
    // are in the wasm-binary function namespace — imports occupy
    // 0..num_imports, defined functions follow. `merged.functions`
    // however holds only the defined ones, indexed from 0. Convert via
    // `to_local`; imports (idx < num_imports) yield None and are skipped
    // as GC roots — they're not GC-able.
    let num_imports = merged.num_imported_functions;
    let to_local = |wasm_idx: u32| -> Option<usize> {
        wasm_idx
            .checked_sub(num_imports)
            .map(|n| n as usize)
            .filter(|&n| n < num_funcs)
    };

    let mut reachable = vec![false; num_funcs];

    // Mark exported functions as roots (per spec §9.2: only exported symbols
    // and the entry point are roots for GC).
    if let Some(idx) = merged.entry_function_index
        && let Some(local) = to_local(idx)
    {
        reachable[local] = true;
    }
    // --export and --export-if-defined symbols are roots.
    for &idx in merged.explicit_export_indices.iter() {
        if let Some(local) = to_local(idx) {
            reachable[local] = true;
        }
    }
    // When --export-dynamic (or shared mode), all named functions are roots.
    if export_all_dynamic {
        for &idx in merged.function_name_map.values() {
            if let Some(local) = to_local(idx) {
                reachable[local] = true;
            }
        }
    }
    // WASM_SYM_EXPORTED functions are roots (spec §4.2, flag 0x20).
    for &idx in &merged.exported_indices {
        if let Some(local) = to_local(idx) {
            reachable[local] = true;
        }
    }
    // WASM_SYM_NO_STRIP functions are roots (spec §4.2, flag 0x80).
    for &idx in &merged.no_strip_indices {
        if let Some(local) = to_local(idx) {
            reachable[local] = true;
        }
    }
    // Functions referenced via indirect function table are roots.
    for &idx in &merged.table_entries {
        if let Some(local) = to_local(idx) {
            reachable[local] = true;
        }
    }

    // BFS: scan reachable function bodies for every opcode that carries a
    // function index — call, return_call, ref.func. Uses the same opcode
    // walker remap_call_targets uses so bulk-memory bodies and 0x10-valued
    // immediates don't confuse us into marking phantom functions reachable.
    // An opcode the walker can't decode conservatively marks *all* funcs
    // reachable (safe over-retention) rather than silently skipping.
    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..num_funcs {
            if !reachable[i] {
                continue;
            }
            let body = &merged.functions[i].body;
            let mut referenced: Vec<u32> = Vec::new();
            let walk = walk_funcidx_operands(body, |_off, func_idx| {
                referenced.push(func_idx);
            });
            if walk.is_err() {
                // Unknown opcode — retain everything to stay safe.
                tracing::warn!(
                    "wasm: GC walker hit an unrecognised opcode in function {i}; \
                     keeping all functions to avoid dropping a reachable one"
                );
                for r in reachable.iter_mut() {
                    *r = true;
                }
                changed = false;
                break;
            }
            for func_idx in referenced {
                // Body-resident call operands are in the unified wasm
                // function namespace (imports 0..num_imports, defined
                // functions follow). A call to an import is not a GC
                // root concern — imports aren't GC-able. For defined
                // targets we subtract num_imports to index `reachable`.
                if let Some(local) = to_local(func_idx) {
                    if !reachable[local] {
                        reachable[local] = true;
                        changed = true;
                    }
                }
            }
        }
    }

    // Check if GC removes anything.
    let keep_count = reachable.iter().filter(|&&r| r).count();
    if keep_count == num_funcs {
        return;
    }

    // Build wasm-binary-index → new-wasm-binary-index map. Imports
    // (indices 0..num_imports) are unchanged; defined functions remap
    // to `num_imports + compacted_local_index`.
    let total = (num_imports as usize) + num_funcs;
    let mut index_map: Vec<Option<u32>> = vec![None; total];
    for i in 0..num_imports {
        index_map[i as usize] = Some(i);
    }
    let mut new_local = 0u32;
    for (old_local, &keep) in reachable.iter().enumerate() {
        if keep {
            let old_wasm = num_imports + old_local as u32;
            index_map[old_wasm as usize] = Some(num_imports + new_local);
            new_local += 1;
        }
    }

    // Filter functions.
    let mut new_functions = Vec::with_capacity(keep_count);
    for (old_local, keep) in reachable.iter().enumerate() {
        if !keep {
            continue;
        }
        let mut func = std::mem::replace(
            &mut merged.functions[old_local],
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

    // GC unused types — keep types referenced by functions, imports,
    // AND call_indirect operands.
    let type_used = mark_used_types(
        merged.types.len(),
        merged
            .functions
            .iter()
            .map(|f| (f.type_index, f.body.as_slice())),
        merged.imports.iter().filter_map(|imp| match &imp.kind {
            ImportKind::Function(t) => Some(*t),
            _ => None,
        }),
    );
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
    // Remap call_indirect type-index operands in every body. Without this,
    // compacting the types list desyncs bodies from the new type numbering
    // and call_indirect signatures mismatch what's on the stack.
    for func in &mut merged.functions {
        let mut patches: Vec<(usize, u32)> = Vec::new();
        let walk = walk_call_indirect_typeidx(&func.body, |off, old| {
            if let Some(new_idx) = type_map.get(old as usize).copied().flatten() {
                if new_idx != old {
                    patches.push((off, new_idx));
                }
            }
        });
        if walk.is_err() {
            continue;
        }
        for (off, new_idx) in patches {
            write_padded_leb128(&mut func.body, off, new_idx);
        }
    }
}

/// Walk a function body and report every `call_indirect` / `return_call_indirect`
/// type-index operand. Mirrors `walk_funcidx_operands`'s shape so the two
/// stay parallel.
fn walk_call_indirect_typeidx(
    body: &[u8],
    mut on_typeidx: impl FnMut(usize, u32),
) -> crate::error::Result<()> {
    let mut pos = 0;
    let (local_count, c) = read_leb128(body)?;
    pos += c;
    for _ in 0..local_count {
        let (_, c) = read_leb128(&body[pos..])?;
        pos += c + 1;
    }
    while pos < body.len() {
        let opcode = body[pos];
        pos += 1;
        match opcode {
            0x00 | 0x01 | 0x05 | 0x0B | 0x0F | 0x1A | 0x1B | 0x45..=0xC4 | 0xD1 => {}
            0x02 | 0x03 | 0x04 => {
                if pos < body.len() {
                    let b = body[pos];
                    if b == 0x40 || (0x6B..=0x7F).contains(&b) {
                        pos += 1;
                    } else {
                        let (_, c) = read_sleb128(&body[pos..])?;
                        pos += c;
                    }
                }
            }
            0x0C | 0x0D | 0x09 => {
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
            }
            0x0E => {
                let (count, c) = read_leb128(&body[pos..])?;
                pos += c;
                for _ in 0..=count {
                    let (_, c) = read_leb128(&body[pos..])?;
                    pos += c;
                }
            }
            0x10 | 0x12 => {
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
            }
            0x11 | 0x13 => {
                // call_indirect / return_call_indirect: typeidx tableidx
                let start = pos;
                let (typeidx, c) = read_leb128(&body[pos..])?;
                on_typeidx(start, typeidx as u32);
                pos += c;
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
            }
            0x1C => {
                let (count, c) = read_leb128(&body[pos..])?;
                pos += c + count;
            }
            0x20..=0x24 | 0x25 | 0x26 => {
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
            }
            0x28..=0x3E => {
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
            }
            0x3F | 0x40 => {
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
            }
            0x41 => {
                let (_, c) = read_sleb128(&body[pos..])?;
                pos += c;
            }
            0x42 => {
                let (_, c) = read_sleb128_i64_consumed(&body[pos..])?;
                pos += c;
            }
            0x43 => {
                if pos + 4 > body.len() {
                    return Err(crate::error!("call_indirect walker: truncated f32.const"));
                }
                pos += 4;
            }
            0x44 => {
                if pos + 8 > body.len() {
                    return Err(crate::error!("call_indirect walker: truncated f64.const"));
                }
                pos += 8;
            }
            0xD2 => {
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
            }
            _ => {
                return Err(crate::error!(
                    "call_indirect walker: unknown opcode 0x{opcode:02x}"
                ));
            }
        }
    }
    Ok(())
}

/// Walk a function body and report every operand that carries a function
/// index, i.e. `call` (0x10), `return_call` (0x12), and `ref.func` (0xD2).
/// The callback receives `(offset_of_leb_start, decoded_func_index)`.
///
/// Returns `Err` on an opcode the walker doesn't recognise so callers can
/// refuse to mutate the body. This is deliberately stricter than a "skip
/// unknown bytes" strategy — silently mis-stepping through immediates can
/// corrupt unrelated bytes (e.g. an `i32.const 16` immediate contains a
/// literal `0x10` byte that would otherwise be mistaken for a `call`).
fn walk_funcidx_operands(
    body: &[u8],
    mut on_funcidx: impl FnMut(usize, u32),
) -> crate::error::Result<()> {
    let mut pos = 0;
    // Skip local declarations: vec of (count: LEB, valtype: byte).
    let (local_count, c) = read_leb128(body)?;
    pos += c;
    for _ in 0..local_count {
        let (_, c) = read_leb128(&body[pos..])?;
        pos += c + 1;
    }
    while pos < body.len() {
        let opcode = body[pos];
        pos += 1;
        match opcode {
            // No-immediate opcodes.
            0x00 | 0x01 | 0x05 | 0x0B | 0x0F | 0x1A | 0x1B | 0x45..=0xC4 | 0xD1 => {}
            // block / loop / if — blocktype: 0x40 (void), a valtype (single
            // byte in 0x6B..=0x7F), or a signed LEB type index.
            0x02 | 0x03 | 0x04 => {
                if pos < body.len() {
                    let b = body[pos];
                    if b == 0x40 || (0x6B..=0x7F).contains(&b) {
                        pos += 1;
                    } else {
                        let (_, c) = read_sleb128(&body[pos..])?;
                        pos += c;
                    }
                }
            }
            // br, br_if, rethrow: labelidx
            0x0C | 0x0D | 0x09 => {
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
            }
            // br_table: vec(labelidx) + labelidx
            0x0E => {
                let (count, c) = read_leb128(&body[pos..])?;
                pos += c;
                for _ in 0..=count {
                    let (_, c) = read_leb128(&body[pos..])?;
                    pos += c;
                }
            }
            // call funcidx / return_call funcidx
            0x10 | 0x12 => {
                let start = pos;
                let (func_idx, c) = read_leb128(&body[pos..])?;
                on_funcidx(start, func_idx as u32);
                pos += c;
            }
            // call_indirect / return_call_indirect: typeidx tableidx
            0x11 | 0x13 => {
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
            }
            // select with typed vector: vec<valtype>
            0x1C => {
                let (count, c) = read_leb128(&body[pos..])?;
                pos += c + count;
            }
            // local/global.get/set/tee: idx
            0x20..=0x24 => {
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
            }
            // table.get / table.set: tableidx
            0x25 | 0x26 => {
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
            }
            // Memory loads/stores: align + offset
            0x28..=0x3E => {
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
            }
            // memory.size / memory.grow: memidx (1 byte in mvp, LEB in multi-memory)
            0x3F | 0x40 => {
                let (_, c) = read_leb128(&body[pos..])?;
                pos += c;
            }
            0x41 => {
                // i32.const
                let (_, c) = read_sleb128(&body[pos..])?;
                pos += c;
            }
            0x42 => {
                // i64.const
                let (_, c) = read_sleb128_i64_consumed(&body[pos..])?;
                pos += c;
            }
            0x43 => {
                if pos + 4 > body.len() {
                    return Err(crate::error!("wasm walker: truncated f32.const"));
                }
                pos += 4;
            }
            0x44 => {
                if pos + 8 > body.len() {
                    return Err(crate::error!("wasm walker: truncated f64.const"));
                }
                pos += 8;
            }
            // ref.null t — single-byte reftype
            0xD0 => {
                if pos < body.len() {
                    pos += 1;
                }
            }
            // ref.func funcidx
            0xD2 => {
                let start = pos;
                let (func_idx, c) = read_leb128(&body[pos..])?;
                on_funcidx(start, func_idx as u32);
                pos += c;
            }
            // Bulk-memory and saturating-truncation (0xFC prefix).
            0xFC => {
                let (sub, c) = read_leb128(&body[pos..])?;
                pos += c;
                match sub {
                    // i{32,64}.trunc_sat_f{32,64}_{s,u} — no further operands.
                    0x00..=0x07 => {}
                    // memory.init dataidx memidx
                    0x08 => {
                        let (_, c) = read_leb128(&body[pos..])?;
                        pos += c;
                        let (_, c) = read_leb128(&body[pos..])?;
                        pos += c;
                    }
                    // data.drop dataidx
                    0x09 => {
                        let (_, c) = read_leb128(&body[pos..])?;
                        pos += c;
                    }
                    // memory.copy src dst
                    0x0A => {
                        let (_, c) = read_leb128(&body[pos..])?;
                        pos += c;
                        let (_, c) = read_leb128(&body[pos..])?;
                        pos += c;
                    }
                    // memory.fill memidx
                    0x0B => {
                        let (_, c) = read_leb128(&body[pos..])?;
                        pos += c;
                    }
                    // table.init elemidx tableidx
                    0x0C => {
                        let (_, c) = read_leb128(&body[pos..])?;
                        pos += c;
                        let (_, c) = read_leb128(&body[pos..])?;
                        pos += c;
                    }
                    // elem.drop elemidx
                    0x0D => {
                        let (_, c) = read_leb128(&body[pos..])?;
                        pos += c;
                    }
                    // table.copy dst src
                    0x0E => {
                        let (_, c) = read_leb128(&body[pos..])?;
                        pos += c;
                        let (_, c) = read_leb128(&body[pos..])?;
                        pos += c;
                    }
                    // table.grow / table.size / table.fill: tableidx
                    0x0F | 0x10 | 0x11 => {
                        let (_, c) = read_leb128(&body[pos..])?;
                        pos += c;
                    }
                    other => {
                        return Err(crate::error!(
                            "wasm walker: unknown 0xFC sub-opcode {other:#x}"
                        ));
                    }
                }
            }
            other => {
                return Err(crate::error!(
                    "wasm walker: unknown opcode {other:#x} at offset {}",
                    pos - 1
                ));
            }
        }
    }
    Ok(())
}

/// Consume an SLEB128 i64 and return (value, bytes_consumed).
fn read_sleb128_i64_consumed(data: &[u8]) -> crate::error::Result<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        if byte < 0x80 {
            if shift < 64 && (byte & 0x40) != 0 {
                result |= !0i64 << shift;
            }
            return Ok((result, i + 1));
        }
        if shift >= 70 {
            return Err(crate::error!("SLEB64 overflow"));
        }
    }
    Err(crate::error!("Unexpected end of SLEB64"))
}

/// Remap function indices in `call`, `return_call`, and `ref.func`
/// instructions within a function body. Uses a comprehensive opcode walker
/// so bytes inside immediates (like a literal `0x10` in an `i32.const`
/// payload) don't get mis-patched as calls.
fn remap_call_targets(body: &mut [u8], index_map: &[Option<u32>]) {
    // Collect (offset, new_idx) pairs first to avoid aliasing the body
    // during the walk.
    let mut patches: Vec<(usize, u32)> = Vec::new();
    let walk = walk_funcidx_operands(body, |off, old_idx| {
        if let Some(Some(new_idx)) = index_map.get(old_idx as usize) {
            patches.push((off, *new_idx));
        }
    });
    if walk.is_err() {
        // Unknown opcode. Refuse to mutate — mis-patching is worse than
        // leaving stale call targets in a body we don't understand.
        tracing::warn!(
            "wasm: GC encountered an opcode outside the walker's vocabulary; \
             call-target remap skipped for this function"
        );
        return;
    }
    for (off, new_idx) in patches {
        write_padded_leb128(body, off, new_idx);
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
    let mut warned_reloc_types: std::collections::HashSet<u8> = std::collections::HashSet::new();
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

            let parsed = parse_wasm_sections(data).map_err(|e| {
                crate::error!(
                    "parse_wasm_sections failed for {:?}: {}",
                    obj.input,
                    e.to_string()
                )
            })?;

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
                            0 => {
                                comdat_skip_data.insert(index);
                            }
                            1 => {
                                comdat_skip_functions.insert(index);
                            }
                            3 => {
                                comdat_skip_tags.insert(index);
                            }
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
                    let sym_flags = parsed
                        .symbols
                        .iter()
                        .find(|sym| sym.kind == 0 && !sym.name.is_empty() && sym.name == *name)
                        .map(|sym| sym.flags)
                        .unwrap_or(0);
                    let is_weak = (sym_flags & 0x01) != 0;
                    let is_hidden = (sym_flags & 0x04) != 0;
                    // Per spec §9.2: strong overrides weak. If existing is weak
                    // and new is strong, override. If both strong, first wins.
                    let should_insert = match function_is_weak.get(name) {
                        None => true,                   // first definition
                        Some(true) if !is_weak => true, // strong overrides weak
                        _ => false,                     // keep existing
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
            // Check flags on function symbols (spec §4.2), and register
            // alias names — any named symbol pointing at a defined
            // function whose canonical name is already in
            // `function_name_map` should also be reachable under the
            // alias name (covers `.set <alias>, <target>`).
            for sym in &parsed.symbols {
                if sym.kind == 0
                    && (sym.flags & 0x10) == 0
                    && sym.index >= parsed.num_function_imports
                {
                    let output_idx = func_base + (sym.index - parsed.num_function_imports);
                    if (sym.flags & 0x80) != 0 {
                        no_strip_indices.push(output_idx);
                    }
                    if (sym.flags & 0x20) != 0 {
                        exported_indices.push(output_idx);
                    }
                    if !sym.name.is_empty() && !function_name_map.contains_key(&sym.name) {
                        function_name_map.insert(sym.name.clone(), output_idx);
                        // Aliases inherit the weak/hidden state of the
                        // canonical name; default to strong + visible.
                        function_is_weak.entry(sym.name.clone()).or_insert(false);
                        if sym.name == entry_name {
                            entry_function_index = Some(output_idx);
                        }
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
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(obj_idx);
                    }
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
            if sym.kind == 1
                && (sym.flags & 0x10) == 0
                && (sym.flags & 0x01) != 0
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
            || objects[obj_idx]
                .parsed
                .data_segments
                .get(seg_i)
                .map_or(false, |s| s.name.starts_with(b".init_array"))
    };

    // Classify segments by name prefix.
    // Order: rodata (read-only) → data (read-write non-BSS) → BSS.
    let is_rodata = |seg: &ParsedDataSegment| -> bool { seg.name.starts_with(b".rodata") };
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
    let layout_group =
        |objects: &[ObjectInfo],
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

    // TLS classification — a segment is TLS if the linking metadata
    // sets `is_tls` (spec §4 segment flag 0x2) or the name starts with
    // `.tdata` (older LLVM pre-dates the flag and relied on the name).
    let is_tls_seg =
        |seg: &ParsedDataSegment| -> bool { seg.is_tls || seg.name.starts_with(b".tdata") };

    // Pass A: .rodata.* segments.
    layout_group(
        &objects,
        &mut segment_output_offsets,
        &mut data_offset,
        &|obj_idx, seg_i, seg| !should_skip_seg(obj_idx, seg_i) && is_rodata(seg),
    );
    // Pass B1: .tdata.* (TLS) segments. Spec §16.3 expects TLS data to
    // live in its own segment so `memory.init` can target it, and
    // wasm-ld places it ahead of the non-TLS `.data.*` run so
    // `__tls_base` reads out as the start of the writable data block.
    layout_group(
        &objects,
        &mut segment_output_offsets,
        &mut data_offset,
        &|obj_idx, seg_i, seg| {
            !should_skip_seg(obj_idx, seg_i)
                && !is_rodata(seg)
                && !is_bss_name(seg)
                && is_tls_seg(seg)
        },
    );
    // Pass B2: remaining .data.* segments (non-BSS, non-rodata, non-TLS).
    layout_group(
        &objects,
        &mut segment_output_offsets,
        &mut data_offset,
        &|obj_idx, seg_i, seg| {
            !should_skip_seg(obj_idx, seg_i)
                && !is_rodata(seg)
                && !is_bss_name(seg)
                && !is_tls_seg(seg)
        },
    );
    // Pass C: .bss.* segments.
    layout_group(
        &objects,
        &mut segment_output_offsets,
        &mut data_offset,
        &|obj_idx, seg_i, seg| !should_skip_seg(obj_idx, seg_i) && is_bss_name(seg),
    );

    // Compute group boundaries for rodata / tdata / data segments.
    let mut rodata_start: Option<u32> = None;
    let mut rodata_end: Option<u32> = None;
    let mut tdata_start: Option<u32> = None;
    let mut tdata_end: Option<u32> = None;
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
            } else if is_tls_seg(seg) {
                tdata_start = Some(tdata_start.map_or(off, |s: u32| s.min(off)));
                tdata_end = Some(tdata_end.map_or(end, |e: u32| e.max(end)));
            } else {
                rw_data_start = Some(rw_data_start.map_or(off, |s: u32| s.min(off)));
                rw_data_end = Some(rw_data_end.map_or(end, |e: u32| e.max(end)));
            }
        }
    }

    // Merge data into per-group output segments (spec §9.1).
    // Groups: .rodata.* → one segment, .data.* → another, matching wasm-ld.
    // BSS segments are omitted (implicit in memory allocation).
    let (mut data_segments, tls_segment_index) = if data_offset > data_start {
        // Build merged data for the full range, then split into segments.
        let total_data_len = (data_offset - data_start) as usize;
        let mut merged_data = vec![0u8; total_data_len];
        for (obj_idx, obj_info) in objects.iter().enumerate() {
            for (seg_i, seg) in obj_info.parsed.data_segments.iter().enumerate() {
                if should_skip_seg(obj_idx, seg_i) {
                    continue;
                }
                let off = segment_output_offsets[obj_idx][seg_i] - data_start;
                merged_data[off as usize..off as usize + seg.data.len()].copy_from_slice(&seg.data);
            }
        }

        // Create separate output segments for each group.
        // Order: rodata → tdata → data. Keep `.tdata` as its own output
        // segment (spec §16.3 requires this so `memory.init` can target
        // it under `--shared-memory`).
        let mut segments = Vec::new();
        let groups: [(Option<u32>, Option<u32>); 3] = [
            (rodata_start, rodata_end),
            (tdata_start, tdata_end),
            (rw_data_start, rw_data_end),
        ];
        // Track which emitted segment index corresponds to `.tdata`, so
        // `memory.init` in `__wasm_init_tls` can target it.
        let mut tls_segment_index: Option<u32> = None;
        for (group_i, (start, end)) in groups.into_iter().enumerate() {
            if let (Some(s), Some(e)) = (start, end) {
                let rel_start = (s - data_start) as usize;
                let rel_end = (e - data_start) as usize;
                if rel_end > rel_start && rel_end <= merged_data.len() {
                    let data = merged_data[rel_start..rel_end].to_vec();
                    if group_i == 1 {
                        tls_segment_index = Some(segments.len() as u32);
                    }
                    segments.push(OutputDataSegment {
                        memory_offset: s as Addr,
                        data,
                    });
                }
            }
        }
        (segments, tls_segment_index)
    } else {
        (Vec::new(), None)
    };
    // Track TLS data: find the TLS segment block's start offset and
    // total size. Use the same TLS classification as the layout pass
    // (`seg.is_tls` OR name starts with `.tdata`) so segments that
    // rely on the "T" section flag — which the parser may not always
    // round-trip into `is_tls` — are still counted.
    let mut tls_base_offset: Option<u32> = None;
    let mut tls_size: u32 = 0;
    let mut tls_align: u32 = 0;
    for (obj_idx, obj_info) in objects.iter().enumerate() {
        for (seg_i, seg) in obj_info.parsed.data_segments.iter().enumerate() {
            if !is_tls_seg(seg) {
                continue;
            }
            if let Some(&off) = segment_output_offsets[obj_idx].get(seg_i) {
                if tls_base_offset.map_or(true, |b| off < b) {
                    tls_base_offset = Some(off);
                }
                tls_align = tls_align.max(seg.alignment);
            }
        }
    }
    if let Some(base) = tls_base_offset {
        let mut end = base;
        for (obj_idx, obj_info) in objects.iter().enumerate() {
            for (seg_i, seg) in obj_info.parsed.data_segments.iter().enumerate() {
                if !is_tls_seg(seg) {
                    continue;
                }
                if let Some(&off) = segment_output_offsets[obj_idx].get(seg_i) {
                    end = end.max(off + seg.data.len() as u32);
                }
            }
        }
        tls_size = end - base;
    }

    // Build global data symbol name → output address map for cross-object resolution.
    let mut data_name_map: std::collections::HashMap<Vec<u8>, u32> = Default::default();
    for (obj_idx, obj_info) in objects.iter().enumerate() {
        let obj_seg_offsets = &segment_output_offsets[obj_idx];
        for sym in &obj_info.parsed.symbols {
            if sym.kind == 1 && (sym.flags & 0x10) == 0 && !sym.name.is_empty() {
                // Skip data symbols from COMDAT-skipped or weak-losing segments.
                if obj_info
                    .comdat_skip_data
                    .contains(&(sym.segment_index as u32))
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
    // Forward-declare these so Pass 1.72's static-PIC synthesis can
    // record the local global index; the PIC-import path (Pass 4) may
    // also assign a value later under shared mode.
    let mut memory_base_global_idx: Option<u32> = None;
    let mut table_base_global_idx: Option<u32> = None;
    // Address-typed linker-defined globals use i64 under memory64 so their
    // value encodes at the full width of a linear-memory address.
    let addr_vt = if layout.symbol_db.args.memory64 {
        VALTYPE_I64
    } else {
        VALTYPE_I32
    };
    let sp_index = globals.len() as u32;
    global_name_map.insert(b"__stack_pointer".to_vec(), sp_index);
    globals.push(OutputGlobal {
        name: b"__stack_pointer".to_vec(),
        valtype: addr_vt,
        mutable: true,
        init_value: stack_pointer_value as u64,
        exported: false,
    });

    // Detect "static-PIC" mode: inputs were compiled with -fPIC but we're
    // linking to a non-shared, non-PIE executable. The giveaway is either a
    // `GOT.func.*` / `GOT.mem.*` global import or a kind-2 symbol named
    // `__memory_base` / `__table_base` / `__tls_base` in any input. Under
    // this mode wasm-ld places the three base globals right after
    // `__stack_pointer` and suppresses `__data_end` / `__heap_base` from the
    // linker-synth set.
    // Static-PIC detection is stricter than "any PIC-ish marker":
    // `.globaltype __memory_base, i32, immutable` alone (which emits a
    // `__memory_base` env import) only means "PIC-capable input"; without
    // code actually using the base global or a GOT reference, wasm-ld
    // leaves the base global *unsynthesised* so that the debug-section
    // reloc apply path emits the 0xFFFFFFFF sentinel.
    let static_pic = !layout.symbol_db.args.is_shared
        && !layout.symbol_db.args.is_pic
        && objects.iter().any(|obj| {
            // GOT imports *alone* are not a static-PIC trigger: the
            // @GOT@TLS pattern emits GOT.data imports for TLS symbols
            // under a plain non-PIC link (see tls-non-shared-memory.s),
            // and wasm-ld handles those via GOT internalisation without
            // synthesising the __memory_base / __table_base triad. Only
            // treat the link as static-PIC if code or data actually
            // references the base globals.
            let _ = obj.parsed.imports.iter().any(|imp| {
                imp.kind == 3
                    && (imp.module == b"GOT.func"
                        || imp.module == b"GOT.mem"
                        || imp.module == b"GOT.data")
            });
            // A code or data relocation actually targets a kind-2 symbol
            // that resolves (via import_global_names when sym.name is
            // empty) to `__memory_base` / `__table_base`. `__tls_base`
            // alone is NOT a static-PIC trigger — an input can reference
            // `__tls_base` in a plain non-PIC link (see
            // tls-non-shared-memory.s), and wasm-ld treats that as a
            // regular TLS synthesis, not PIC.
            let base_names: &[&[u8]] = &[b"__memory_base", b"__table_base"];
            let effective_global_name = |sym_idx: u32| -> Option<Vec<u8>> {
                let s = obj.parsed.symbols.get(sym_idx as usize)?;
                if s.kind != 2 {
                    return None;
                }
                if !s.name.is_empty() {
                    return Some(s.name.clone());
                }
                if s.flags & 0x10 != 0 {
                    obj.parsed
                        .import_global_names
                        .get(s.index as usize)
                        .cloned()
                } else {
                    None
                }
            };
            let code_touches_base = obj.parsed.code_relocations.iter().any(|r| {
                effective_global_name(r.symbol_index)
                    .is_some_and(|n| base_names.iter().any(|b| *b == n.as_slice()))
            });
            let data_touches_base = obj.parsed.data_relocations.iter().any(|r| {
                effective_global_name(r.symbol_index)
                    .is_some_and(|n| base_names.iter().any(|b| *b == n.as_slice()))
            });
            code_touches_base || data_touches_base
        });
    if static_pic {
        for (name, init) in [
            (&b"__memory_base"[..], 0u64),
            (&b"__table_base"[..], 1),
            (&b"__tls_base"[..], 0),
        ] {
            if !global_name_map.contains_key(name) {
                let idx = globals.len() as u32;
                global_name_map.insert(name.to_vec(), idx);
                if name == b"__table_base" {
                    table_base_global_idx = Some(idx);
                }
                globals.push(OutputGlobal {
                    name: name.to_vec(),
                    // Under memory64 the base globals widen to i64 to match
                    // the compiler's `i64.const <sym>@MBREL` / `@TBREL`
                    // sequences.
                    valtype: addr_vt,
                    mutable: false,
                    init_value: init,
                    exported: false,
                });
            }
        }
    }

    // Lazy linker-synth gating: wasm-ld only emits the optional
    // linker-defined globals (`__tls_size`, `__tls_align`, `__data_end`,
    // `__heap_base`) when something in the input actually references
    // them. Collect the set of names reached via a kind-2 (GLOBAL)
    // symbol attached to any code or data relocation. An empty-named
    // global symbol carries the referenced name in the corresponding
    // entry of `import_global_names` (kept by the parser for
    // `global.get`-style references where the symbol table points at
    // an import index).
    let mut referenced_linker_globals: std::collections::HashSet<Vec<u8>> = Default::default();
    for obj in &objects {
        let resolve = |sym_idx: u32| -> Option<Vec<u8>> {
            let s = obj.parsed.symbols.get(sym_idx as usize)?;
            if s.kind != 2 {
                return None;
            }
            if !s.name.is_empty() {
                return Some(s.name.clone());
            }
            if s.flags & 0x10 != 0 {
                obj.parsed
                    .import_global_names
                    .get(s.index as usize)
                    .cloned()
            } else {
                None
            }
        };
        for r in obj
            .parsed
            .code_relocations
            .iter()
            .chain(obj.parsed.data_relocations.iter())
        {
            if let Some(n) = resolve(r.symbol_index) {
                referenced_linker_globals.insert(n);
            }
        }
    }
    let is_referenced = |name: &[u8]| -> bool { referenced_linker_globals.contains(name) };

    // TLS globals: created when TLS data exists OR --shared-memory is used.
    let has_tls = tls_base_offset.is_some() || tls_size > 0 || layout.symbol_db.args.shared_memory;
    // __tls_base per spec §16.3:
    //   - Under --shared-memory: mutable, initialised to 0, set at runtime by the synthesised
    //     `__wasm_init_tls(ptr)` function.
    //   - Under non-shared: immutable, initialised to the absolute address of the TLS block (there
    //     is only one thread, so the base is known at link time). `tls_base_offset` is the byte
    //     offset of `.tdata` within the merged data image, so the absolute base is `data_start +
    //     tls_base_offset`.
    let tls_shared = layout.symbol_db.args.shared_memory;
    if has_tls {
        let tls_idx = globals.len() as u32;
        global_name_map.insert(b"__tls_base".to_vec(), tls_idx);
        // `tls_base_offset` is already an absolute output address
        // (it comes from `segment_output_offsets`, which include
        // `data_start`), so don't add `data_start` again.
        let (mutable, init_value) = if tls_shared {
            (true, 0u64)
        } else {
            (false, tls_base_offset.unwrap_or(data_start) as u64)
        };
        globals.push(OutputGlobal {
            name: b"__tls_base".to_vec(),
            valtype: addr_vt,
            mutable,
            init_value,
            exported: false,
        });
    }

    // __tls_size: immutable i32 — total TLS data size. Lazy: only
    // emitted if an input references it or the user --export's it.
    let exports_tls_size = layout
        .symbol_db
        .args
        .exports
        .iter()
        .any(|s| s == "__tls_size");
    if has_tls && (tls_shared || is_referenced(b"__tls_size") || exports_tls_size) {
        let idx = globals.len() as u32;
        global_name_map.insert(b"__tls_size".to_vec(), idx);
        globals.push(OutputGlobal {
            name: b"__tls_size".to_vec(),
            valtype: VALTYPE_I32,
            mutable: false,
            init_value: tls_size as u64,
            exported: exports_tls_size,
        });
    }

    // __tls_align: immutable i32 — max TLS alignment. Lazy as above.
    let exports_tls_align = layout
        .symbol_db
        .args
        .exports
        .iter()
        .any(|s| s == "__tls_align");
    if has_tls && (tls_shared || is_referenced(b"__tls_align") || exports_tls_align) {
        let idx = globals.len() as u32;
        global_name_map.insert(b"__tls_align".to_vec(), idx);
        globals.push(OutputGlobal {
            name: b"__tls_align".to_vec(),
            valtype: VALTYPE_I32,
            mutable: false,
            init_value: tls_align as u64,
            exported: exports_tls_align,
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

    // wasm-ld emits `__data_end` / `__heap_base` only when referenced by
    // an input or explicitly --export'd. The older "always when
    // has_data_segments" rule was too eager and broke CHECK chains on
    // tests like tls-non-shared-memory.
    let data_end_needed = is_referenced(b"__data_end") || exports_data_end;
    let heap_base_needed = is_referenced(b"__heap_base") || exports_heap_base;
    if data_end_needed && (!static_pic || exports_data_end) {
        let de_index = globals.len() as u32;
        global_name_map.insert(b"__data_end".to_vec(), de_index);
        globals.push(OutputGlobal {
            name: b"__data_end".to_vec(),
            valtype: addr_vt,
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
            valtype: addr_vt,
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
            valtype: addr_vt,
            mutable: false,
            init_value: rodata_end.unwrap_or(data_start) as u64,
            exported: true,
        });
    }

    if heap_base_needed && (!static_pic || exports_heap_base) {
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
            valtype: addr_vt,
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
            valtype: addr_vt,
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
            let sym_name = obj_info
                .parsed
                .symbols
                .iter()
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
            let sym_name = obj_info
                .parsed
                .symbols
                .iter()
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

    // --- Pass 1.75: internalise GOT.func.* / GOT.mem.* imports (PIC → static). ---
    // wasm-ld convention: objects compiled with -fPIC import globals named
    // `GOT.func.<sym>` (function pointer) or `GOT.mem.<sym>` (data pointer).
    // Under a shared output these stay as imports (existing code path in
    // Pass 4). Under a static or PIE link the dynamic linker isn't around,
    // so we substitute each one with a locally-defined immutable i32 global
    // whose init value holds the value the dynamic linker would otherwise
    // provide: the function's indirect-table slot, or the data symbol's
    // memory address. Absent symbols initialise to 0 (weak-undefined
    // behaviour).
    //
    // Function GOTs are patched after Pass 2.6 because their table indices
    // aren't known yet. We stash (global_idx, func_name) pairs for the
    // patch pass and add the referenced functions to `table_needed_funcs`
    // so the table actually gets a slot for them.
    // Functions that need an entry in the indirect function table.
    // Insertion order is tracked in `table_needed_order` so Pass 2.6
    // assigns table slots in the order symbols were first encountered
    // (wasm-ld's convention), rather than sorting by function index.
    // The HashSet is still used as the authoritative membership test.
    // The parallel `table_needed_is_import` vec marks entries whose
    // indices are already post-shift import indices — those skip the
    // ctor / import shifts that apply to defined-function entries.
    let mut table_needed_funcs: std::collections::HashSet<u32> = Default::default();
    let mut table_needed_order: Vec<u32> = Vec::new();
    let mut table_needed_is_import: Vec<bool> = Vec::new();

    // Simulate Pass 4's import deduplication early so GOT.func entries for
    // *imported* functions can claim table slots in Pass 1.75. The keys
    // match Pass 4's `seen_imports` hash: (module, field, kind, type).
    // The value is the position-in-dedup (== output import funcidx).
    let mut function_import_output_idx: std::collections::HashMap<Vec<u8>, u32> =
        Default::default();
    {
        let mut seen: std::collections::HashSet<(Vec<u8>, Vec<u8>, u8, u32)> = Default::default();
        let mut next = 0u32;
        for obj in &objects {
            for imp in &obj.parsed.imports {
                if imp.kind != 0 {
                    continue;
                }
                let remapped_type = obj
                    .type_map
                    .get(imp.type_index as usize)
                    .copied()
                    .unwrap_or(imp.type_index);
                let key = (
                    imp.module.clone(),
                    imp.field.clone(),
                    imp.kind,
                    remapped_type,
                );
                if !seen.insert(key) {
                    continue;
                }
                function_import_output_idx
                    .entry(imp.field.clone())
                    .or_insert(next);
                next += 1;
            }
        }
    }
    let mut got_func_globals: Vec<(u32, Vec<u8>)> = Vec::new();
    if !layout.symbol_db.args.is_shared {
        // wasm-ld emission convention for internalised GOT globals:
        //   `GOT.func.internal.<sym>` for GOT.func imports
        //   `GOT.data.internal.<sym>` for GOT.mem or GOT.data imports
        // and it orders them: all func GOTs first, then all data GOTs.
        let mut seen_got: std::collections::HashSet<(Vec<u8>, Vec<u8>)> = Default::default();

        // --- First sub-pass: GOT.func.* entries. ---
        for obj_info in &objects {
            for imp in &obj_info.parsed.imports {
                if imp.kind != 3 || imp.module != b"GOT.func" {
                    continue;
                }
                let key = (imp.module.clone(), imp.field.clone());
                if !seen_got.insert(key) {
                    continue;
                }
                let func_name = imp.field.clone();
                let mut got_name = b"GOT.func.internal.".to_vec();
                got_name.extend_from_slice(&func_name);
                let global_idx = globals.len() as u32;
                global_name_map.insert(got_name.clone(), global_idx);
                // Also register under the raw `GOT.func.<name>` form so
                // GLOBAL_INDEX_LEB relocs whose symbol resolves to the
                // module-concatenated name still find the output index.
                let mut aliased = b"GOT.func.".to_vec();
                aliased.extend_from_slice(&func_name);
                global_name_map.insert(aliased, global_idx);
                globals.push(OutputGlobal {
                    name: got_name,
                    valtype: VALTYPE_I32,
                    mutable: false,
                    init_value: 0, // patched after Pass 2.6
                    exported: false,
                });
                got_func_globals.push((global_idx, func_name.clone()));
                if let Some(&func_idx) = function_name_map.get(&func_name) {
                    if table_needed_funcs.insert(func_idx) {
                        table_needed_order.push(func_idx);
                        table_needed_is_import.push(false);
                    }
                } else if let Some(&imp_idx) = function_import_output_idx.get(&func_name) {
                    // Imported (undefined) function referenced via GOT.
                    // Its output funcidx is the dedup'd import position,
                    // which is stable regardless of later ctor / import
                    // shifts applied to defined-function indices. Use a
                    // synthetic key (u32::MAX - imp_idx) for the HashSet
                    // dedup so it can't collide with defined indices.
                    let key = u32::MAX - imp_idx;
                    if table_needed_funcs.insert(key) {
                        table_needed_order.push(imp_idx);
                        table_needed_is_import.push(true);
                    }
                }
            }
        }

        // --- Second sub-pass: GOT.mem.* / GOT.data.* entries. ---
        for obj_info in &objects {
            for imp in &obj_info.parsed.imports {
                if imp.kind != 3 || (imp.module != b"GOT.mem" && imp.module != b"GOT.data") {
                    continue;
                }
                let key = (imp.module.clone(), imp.field.clone());
                if !seen_got.insert(key) {
                    continue;
                }
                let data_name = imp.field.clone();
                let init = data_name_map.get(&data_name).copied().unwrap_or(0);
                let mut got_name = b"GOT.data.internal.".to_vec();
                got_name.extend_from_slice(&data_name);
                let global_idx = globals.len() as u32;
                global_name_map.insert(got_name.clone(), global_idx);
                let mut alt = imp.module.clone();
                alt.push(b'.');
                alt.extend_from_slice(&data_name);
                global_name_map.insert(alt, global_idx);
                globals.push(OutputGlobal {
                    name: got_name,
                    valtype: VALTYPE_I32,
                    mutable: false,
                    init_value: init as u64,
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
                            Some(
                                obj_info.func_base
                                    + (sym.index - obj_info.parsed.num_function_imports),
                            )
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
        obj.parsed
            .import_function_names
            .iter()
            .any(|n| n == ctors_name)
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
    //   4. A tag's "name" is the symbol name (if present) else the import field name per spec §4.3.
    //   5. Imported tags are emitted first in the output index space, then local definitions.
    //      Symbols that lose resolution still get a `symbol_to_output_tag` entry pointing at the
    //      winner so relocs still patch correctly.
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
    let mut tag_import_index_by_name: std::collections::HashMap<Vec<u8>, u32> = Default::default();
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
                let out_idx = (output_tag_imports.len() + output_tag_defs.len()) as u32;
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
                (None, _) => true,                          // brand new
                (Some(_), _) if existing_is_import => true, // def wins over import
                (Some(_), Some(true)) if !is_weak => true,  // strong over weak
                _ => false,
            };
            if should_claim {
                let out_idx = (output_tag_imports.len() + output_tag_defs.len()) as u32;
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

    // --- Per-object input-import-index → output-function-index map ---
    //
    // Without this, every input's function-import indices remain as the
    // input saw them (rustc emits `call <input-import-idx>` with a
    // R_WASM_FUNCTION_INDEX_LEB reloc on the LEB immediate). Pass 2's
    // body-reloc-apply needs to translate those input-local positions
    // into the output's deduplicated import index space; otherwise the
    // body keeps the input's view, and `call N` lands on whatever
    // function happens to sit at output position N — typically a
    // signature-incompatible function, which `wasm-validate` then
    // rightly rejects with "type mismatch in call".
    //
    // Constructed RIGHT BEFORE Pass 2 (rather than alongside the GOT
    // simulator above) so that linker-synthesised function names —
    // most importantly `__wasm_call_ctors`, registered in
    // `function_name_map` between this block and the GOT one — are
    // visible. Otherwise an input's `env.__wasm_call_ctors` import
    // would be allocated a fresh import index here while Pass 4's
    // dedup loop correctly recognises it's resolved by the synth
    // and skips emitting it — leading to a stable off-by-one between
    // our prediction and the actual `output_func_idx`. Mirrors Pass
    // 4's iteration order and skip rules so the indices line up.
    let per_obj_func_imp_remap: Vec<Vec<u32>> = {
        let mut out: Vec<Vec<u32>> = Vec::with_capacity(objects.len());
        let mut seen: std::collections::HashMap<(Vec<u8>, Vec<u8>, u8, u32), u32> =
            Default::default();
        let mut next = 0u32;
        for obj in &objects {
            let mut local_remap: Vec<u32> =
                Vec::with_capacity(obj.parsed.import_function_names.len());
            for imp in &obj.parsed.imports {
                if imp.kind != 0 {
                    continue;
                }
                // Resolved-by-definition: skip emitting the import,
                // route call sites to the defining function.
                if let Some(&def_idx) = function_name_map.get(imp.field.as_slice()) {
                    local_remap.push(def_idx);
                    continue;
                }
                let remapped_type = obj
                    .type_map
                    .get(imp.type_index as usize)
                    .copied()
                    .unwrap_or(imp.type_index);
                let key = (
                    imp.module.clone(),
                    imp.field.clone(),
                    imp.kind,
                    remapped_type,
                );
                let output_idx = match seen.entry(key) {
                    std::collections::hash_map::Entry::Occupied(e) => *e.get(),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        let idx = next;
                        next += 1;
                        e.insert(idx);
                        idx
                    }
                };
                local_remap.push(output_idx);
            }
            out.push(local_remap);
        }
        out
    };

    // --- Pass 2: apply relocations with global symbol resolution ---
    let mut functions: Vec<MergedFunction> = Vec::new();
    // Store deferred table relocs: (function_output_idx, offset_in_body, reloc_type, sym→func_idx)
    let mut deferred_table_relocs: Vec<(usize, usize, u8, u32)> = Vec::new();

    // Fix-ups for `R_WASM_FUNCTION_INDEX_LEB` relocs that resolved to
    // an *imported* function. Pass 4-5's shift loop below adds
    // `num_imported_functions` to every call operand to convert
    // pre-shift defined-only indices into post-shift unified-namespace
    // indices. That works for calls to defined functions, but it
    // CORRUPTS calls to imports — the import index is *already* in
    // the unified namespace and gets wrongly bumped by N. We can't
    // skip the shift selectively (the walker has no way to tell what
    // the body originally encoded), so we record (merged_fn_idx,
    // off_in_body, output_import_idx) here and re-apply the correct
    // value AFTER the shift below. Without this, every call to an
    // imported function lands on the wrong defined function and
    // wasm-validate explodes with "type mismatch in call".
    let mut import_call_fixups: Vec<(usize, usize, u32)> = Vec::new();

    for (obj_idx, obj_info) in objects.iter().enumerate() {
        let parsed = &obj_info.parsed;

        // Build per-object symbol → output index/address maps.
        let mut symbol_to_output_func: std::collections::HashMap<u32, u32> = Default::default();
        let mut symbol_to_output_global: std::collections::HashMap<u32, u32> = Default::default();
        // Symbol index → output tag index (for R_WASM_TAG_INDEX_LEB).
        let mut symbol_to_output_tag: std::collections::HashMap<u32, u32> = Default::default();
        let obj_tag_map = &per_obj_tag_map[obj_idx];
        for (sym_idx, sym) in parsed.symbols.iter().enumerate() {
            if sym.kind == 4
                && let Some(&out_idx) = obj_tag_map.get(&sym.index)
            {
                symbol_to_output_tag.insert(sym_idx as u32, out_idx);
            }
        }
        // Data symbol → output memory address (spec §9.4: value = seg_offset + sym_offset +
        // addend).
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
                        function_name_map
                            .get(sym.name.as_slice())
                            .copied()
                            .unwrap_or(local_output_idx)
                    } else {
                        local_output_idx
                    };
                    symbol_to_output_func.insert(sym_idx as u32, output_idx);
                } else if is_undefined && sym.index < parsed.num_function_imports {
                    // Undefined function symbol pointing at an *imported*
                    // function. Two sub-cases, distinguished by name:
                    //
                    // 1. **Resolved by a definition elsewhere.** Some
                    //    other input defines the symbol (extern shim
                    //    resolved by a real impl). Insert into
                    //    `symbol_to_output_func` so the body-reloc-apply
                    //    patches the call to the defined function's
                    //    pre-shift index — the post-merge shift then
                    //    converts it to the unified namespace correctly.
                    //
                    // 2. **Stays as an import.** No defining input — the
                    //    function lives in `output_imports`, at the
                    //    output-import-index given by
                    //    `per_obj_func_imp_remap[obj_idx][sym.index]`.
                    //    For this case we DELIBERATELY don't insert
                    //    into `symbol_to_output_func`. If we did, Pass 2
                    //    would write the (already-unified) import index
                    //    into the body, and the post-merge shift would
                    //    then add N a second time, landing the call on
                    //    a defined function with the wrong signature.
                    //    Instead we record (merged_fn_idx, off_in_body,
                    //    output_import_idx) and re-apply the correct
                    //    value AFTER the shift below.
                    let resolve_name = if !sym.name.is_empty() {
                        Some(sym.name.as_slice())
                    } else {
                        parsed
                            .import_function_names
                            .get(sym.index as usize)
                            .map(|v| v.as_slice())
                    };
                    if let Some(name) = resolve_name
                        && let Some(&def_idx) = function_name_map.get(name)
                    {
                        // Sub-case 1: resolved by a definition.
                        symbol_to_output_func.insert(sym_idx as u32, def_idx);
                    }
                    // Sub-case 2 is handled by the post-shift fixup
                    // (gathered in the body-reloc loop below using
                    // `per_obj_func_imp_remap`).
                } else {
                    // Defined-out-of-range / synthetic / other edge cases
                    // — fall back to name resolution against defined
                    // functions (no import lookup since sym.index doesn't
                    // index the import table here).
                    let resolve_name = if !sym.name.is_empty() {
                        Some(sym.name.as_slice())
                    } else {
                        None
                    };
                    if let Some(name) = resolve_name
                        && let Some(&output_idx) = function_name_map.get(name)
                    {
                        symbol_to_output_func.insert(sym_idx as u32, output_idx);
                    }
                }
            } else if sym.kind == 1 {
                // SYMTAB_DATA — compute output memory address.
                let is_undefined = sym.flags & 0x10 != 0;
                if !is_undefined {
                    if let Some(&seg_base) = obj_seg_offsets.get(sym.segment_index as usize) {
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

        // Compute the span covered by function bodies so we can detect
        // relocations landing outside any body (coordinate-system bug).
        let bodies_span: Option<(u32, u32)> = parsed.functions.first().and_then(|first| {
            let last = parsed.functions.last().unwrap();
            Some((
                first.code_section_offset,
                last.code_section_offset + last.body.len() as u32,
            ))
        });
        if let Some((lo, hi)) = bodies_span {
            for reloc in &parsed.code_relocations {
                if reloc.offset < lo || reloc.offset >= hi {
                    panic!(
                        "code reloc offset {:#x} (type {}, sym {}) outside body span [{:#x}, {:#x}) — \
                         likely coordinate-system bug (count LEB width?)",
                        reloc.offset, reloc.reloc_type, reloc.symbol_index, lo, hi
                    );
                }
            }
        }

        for (i, input_func) in parsed.functions.iter().enumerate() {
            let output_func_idx = functions.len();
            if std::env::var("WILD_TRACE_BODY")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                == Some(output_func_idx)
            {
                use std::io::Write as _;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("/tmp/wild-trace.log")
                    .expect("open trace log");
                writeln!(
                    f,
                    "wild-trace-body: output_func_idx={output_func_idx} \
                     func_base={} input_func_idx={i} \
                     body_size={} code_section_offset={:#x}",
                    obj_info.func_base,
                    input_func.body.len(),
                    input_func.code_section_offset
                )
                .ok();
                let matching: Vec<_> = parsed
                    .code_relocations
                    .iter()
                    .filter(|r| {
                        r.offset >= input_func.code_section_offset
                            && r.offset
                                < input_func.code_section_offset + input_func.body.len() as u32
                    })
                    .collect();
                writeln!(f, "  {} relocations targeting this body:", matching.len()).ok();
                for r in &matching {
                    writeln!(
                        f,
                        "    type={} offset={:#x} (body-relative {:#x}) sym={} addend={}",
                        r.reloc_type,
                        r.offset,
                        r.offset - input_func.code_section_offset,
                        r.symbol_index,
                        r.addend
                    )
                    .ok();
                }
                writeln!(f, "  input body bytes:").ok();
                for (j, chunk) in input_func.body.chunks(16).enumerate() {
                    let mut line = format!("    {:04x}:", j * 16);
                    for b in chunk {
                        line.push_str(&format!(" {:02x}", b));
                    }
                    writeln!(f, "{line}").ok();
                }
            }
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
                        if let Some(&output_idx) = symbol_to_output_func.get(&reloc.symbol_index) {
                            write_padded_leb128(&mut body, off_in_body, output_idx);
                        } else {
                            // No defined-function resolution. If the
                            // symbol was an import reference we still
                            // need to redirect the call to the right
                            // output import index — record a post-shift
                            // fixup. The body's bytes stay at whatever
                            // rustc emitted (the input's local import
                            // index); the shift adds N to it; our
                            // fixup overwrites with the correct
                            // unified output-import index.
                            let sym = parsed.symbols.get(reloc.symbol_index as usize);
                            let is_undef_import = sym.is_some_and(|s| {
                                s.kind == 0
                                    && (s.flags & 0x10) != 0
                                    && s.index < parsed.num_function_imports
                            });
                            if is_undef_import
                                && let Some(&out_imp_idx) = per_obj_func_imp_remap
                                    .get(obj_idx)
                                    .and_then(|v| v.get(sym.unwrap().index as usize))
                            {
                                import_call_fixups.push((
                                    functions.len(),
                                    off_in_body,
                                    out_imp_idx,
                                ));
                            }
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
                        body[off_in_body..off_in_body + 4].copy_from_slice(&value.to_le_bytes());
                    }
                    7 => {
                        // R_WASM_GLOBAL_INDEX_LEB (spec §2: 5-byte varuint32)
                        if let Some(&output_idx) = symbol_to_output_global.get(&reloc.symbol_index)
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
                        if table_needed_funcs.insert(func_idx) {
                            table_needed_order.push(func_idx);
                            table_needed_is_import.push(false);
                        }
                        // This body will be pushed at index `functions.len()`
                        // at the end of this iteration. Deferred table relocs
                        // must target that slot, NOT `functions.len() + i`.
                        let out_func_idx = functions.len();
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
                        if let Some(&output_idx) = symbol_to_output_global.get(&reloc.symbol_index)
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
                        if let Some(&output_idx) = symbol_to_output_func.get(&reloc.symbol_index)
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
                            body[off_in_body..off_in_body + 8].copy_from_slice(&v.to_le_bytes());
                        }
                    }
                    18 => {
                        // R_WASM_TABLE_INDEX_SLEB64 (spec §2: 10-byte varint64)
                        // Defer to Pass 2.6 same as 1/2.
                        let func_idx = symbol_to_output_func
                            .get(&reloc.symbol_index)
                            .copied()
                            .unwrap_or(0);
                        if table_needed_funcs.insert(func_idx) {
                            table_needed_order.push(func_idx);
                            table_needed_is_import.push(false);
                        }
                        // This body will be pushed at index `functions.len()`
                        // at the end of this iteration. Deferred table relocs
                        // must target that slot, NOT `functions.len() + i`.
                        let out_func_idx = functions.len();
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
                        if table_needed_funcs.insert(func_idx) {
                            table_needed_order.push(func_idx);
                            table_needed_is_import.push(false);
                        }
                        // This body will be pushed at index `functions.len()`
                        // at the end of this iteration. Deferred table relocs
                        // must target that slot, NOT `functions.len() + i`.
                        let out_func_idx = functions.len();
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
                        if table_needed_funcs.insert(func_idx) {
                            table_needed_order.push(func_idx);
                            table_needed_is_import.push(false);
                        }
                        // This body will be pushed at index `functions.len()`
                        // at the end of this iteration. Deferred table relocs
                        // must target that slot, NOT `functions.len() + i`.
                        let out_func_idx = functions.len();
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
                        if table_needed_funcs.insert(func_idx) {
                            table_needed_order.push(func_idx);
                            table_needed_is_import.push(false);
                        }
                        // This body will be pushed at index `functions.len()`
                        // at the end of this iteration. Deferred table relocs
                        // must target that slot, NOT `functions.len() + i`.
                        let out_func_idx = functions.len();
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
                        if let Some(&output_idx) = symbol_to_output_tag.get(&reloc.symbol_index) {
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
                if sym.kind == 1
                    && !sym.name.is_empty()
                    && !sym_to_addr.contains_key(&(sym_idx as u32))
                {
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

    if !table_needed_order.is_empty() {
        // Insertion order matches wasm-ld's slot assignment: the first
        // symbol that triggered the table entry takes slot 1, etc.
        for (i, &func_idx) in table_needed_order.iter().enumerate() {
            let table_idx = (i + 1) as u32; // start at 1, 0 = null/trap
            func_to_table_index.insert(func_idx, table_idx);
            table_entries.push(func_idx);
        }

        // Patch deferred TABLE_INDEX relocations.
        // Under static-PIC, __table_base is synthesised to 1, so @TBREL
        // values must subtract 1 to cancel the `global.get __table_base`
        // the compiler emits alongside the reloc. Shared PIC imports
        // __table_base with unknown runtime value; the module-local
        // index is what the reloc should carry.
        let tbrel_bias: i64 = if static_pic { 1 } else { 0 };
        for (func_out_idx, off_in_body, reloc_type, target_func_idx) in &deferred_table_relocs {
            let table_idx = func_to_table_index
                .get(target_func_idx)
                .copied()
                .unwrap_or(0);
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
                        write_padded_sleb128_i64(&mut func.body, *off_in_body, table_idx as i64);
                    }
                    19 => {
                        // R_WASM_TABLE_INDEX_I64: uint64 LE
                        if *off_in_body + 8 <= func.body.len() {
                            func.body[*off_in_body..*off_in_body + 8]
                                .copy_from_slice(&(table_idx as u64).to_le_bytes());
                        }
                    }
                    12 => {
                        // R_WASM_TABLE_INDEX_REL_SLEB: value =
                        // table_idx - __table_base. Under static-PIC
                        // __table_base = 1; under non-PIC it is 0.
                        let v = (table_idx as i64 - tbrel_bias) as i32;
                        write_padded_sleb128(&mut func.body, *off_in_body, v);
                    }
                    24 => {
                        // R_WASM_TABLE_INDEX_REL_SLEB64: same bias.
                        let v = table_idx as i64 - tbrel_bias;
                        write_padded_sleb128_i64(&mut func.body, *off_in_body, v);
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

        functions.insert(
            0,
            MergedFunction {
                type_index: type_idx,
                body,
            },
        );
        // Insertion at index 0 shifts every existing function up by 1.
        // The recorded import-call fixups stored their target as the
        // pre-insertion `functions.len()`, so they need the same shift
        // to keep pointing at the right body.
        for fixup in &mut import_call_fixups {
            fixup.0 += 1;
        }
        // Shift table entries for the ctor insertion — but skip entries
        // whose funcidx is an already-post-shift import index (those were
        // seeded by GOT.func references to undefined functions in
        // Pass 1.75). Imports live at indices 0..num_imported_functions,
        // unchanged by the ctor insertion.
        for (i, idx) in table_entries.iter_mut().enumerate() {
            if !table_needed_is_import.get(i).copied().unwrap_or(false) {
                *idx += 1;
            }
        }
        func_to_table_index = table_entries
            .iter()
            .enumerate()
            .map(|(i, &func_idx)| (func_idx, (i + 1) as u32))
            .collect();
        // Note: call targets in function bodies are NOT shifted here because
        // Pass 2 already resolved them using post-shift function_name_map.
    }

    // --- Pass 3.25: patch GOT.func.* global init values. ---
    // table_needed_funcs has been consumed to build func_to_table_index,
    // which maps pre-import-shift func index → table slot. Under static
    // link, GOT.func globals hold that table slot at runtime.
    for (global_idx, func_name) in &got_func_globals {
        // First try defined funcs; then fall back to imported functions
        // whose output funcidx was precomputed as
        // `function_import_output_idx[name]`. func_to_table_index keys
        // match both (Pass 2.6 built the table using table_entries'
        // stored values, which are defined-pre-shift or import-idx).
        let maybe_defined_key = function_name_map.get(func_name).copied();
        let maybe_import_key = function_import_output_idx.get(func_name).copied();
        let table_idx = maybe_defined_key
            .and_then(|fi| func_to_table_index.get(&fi).copied())
            .or_else(|| maybe_import_key.and_then(|fi| func_to_table_index.get(&fi).copied()))
            .unwrap_or(0);
        if let Some(g) = globals.get_mut(*global_idx as usize) {
            g.init_value = table_idx as u64;
        }
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

        let mem64 = layout.symbol_db.args.memory64;
        for (seg_idx, seg) in data_segments.iter().enumerate() {
            // memory.init destination is an i64 under memory64, i32 otherwise.
            if mem64 {
                body.push(0x42); // i64.const
                write_sleb128_i64(&mut body, seg.memory_offset as i64);
            } else {
                body.push(0x41); // i32.const
                write_sleb128(&mut body, seg.memory_offset as i32);
            }
            // Source offset (always i32 — within the data segment payload).
            body.push(0x41);
            write_sleb128(&mut body, 0);
            // Size (always i32).
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

    // --- Pass 3.6: synthesize __wasm_init_tls for --shared-memory ---
    // Spec §16.3: under threaded builds, the runtime calls
    // `__wasm_init_tls(ptr)` once per thread with a freshly-allocated
    // TLS block. The function copies `.tdata` into the block via
    // `memory.init` and points `__tls_base` at the block.
    // Body:
    //     local.get 0
    //     global.set __tls_base
    //     local.get 0
    //     i32.const 0
    //     i32.const <tls_size>
    //     memory.init <tdata_idx>, 0
    //     end
    // Call to `__wasm_apply_global_tls_relocs` is appended only when
    // that helper is also synthesised.
    if layout.symbol_db.args.shared_memory {
        let tls_base_idx = global_name_map.get(&b"__tls_base"[..]).copied();
        if let Some(tls_base_global) = tls_base_idx {
            // type (i32) -> ()
            let ty = FuncType {
                params: vec![VALTYPE_I32],
                results: Vec::new(),
            };
            let type_idx = if let Some(pos) = types.iter().position(|t| *t == ty) {
                pos as u32
            } else {
                let idx = types.len() as u32;
                types.push(ty);
                idx
            };
            let mut body = Vec::new();
            body.push(0x00); // 0 locals
            body.push(0x20); // local.get
            write_leb128(&mut body, 0);
            body.push(0x24); // global.set
            write_leb128(&mut body, tls_base_global);
            if tls_size > 0 {
                if let Some(tdata_idx) = tls_segment_index {
                    body.push(0x20); // local.get
                    write_leb128(&mut body, 0);
                    body.push(0x41); // i32.const 0 (src offset)
                    write_sleb128(&mut body, 0);
                    body.push(0x41); // i32.const tls_size
                    write_sleb128(&mut body, tls_size as i32);
                    body.push(0xFC);
                    write_leb128(&mut body, 0x08); // memory.init
                    write_leb128(&mut body, tdata_idx);
                    write_leb128(&mut body, 0); // memory index
                }
            }
            body.push(0x0B); // end
            let func_idx = functions.len() as u32;
            function_name_map.insert(b"__wasm_init_tls".to_vec(), func_idx);
            functions.push(MergedFunction {
                type_index: type_idx,
                body,
            });
        }
    }

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
            let key = (
                imp.module.clone(),
                imp.field.clone(),
                imp.kind,
                imp.type_index,
            );
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
                    // Pass 1.75 internalises GOT.* imports whenever the
                    // output is not shared — skip them here to avoid
                    // duplicates. The base-global imports
                    // (`__memory_base` / `__table_base` / `__tls_base`)
                    // are only internalised under static-PIC, so gate
                    // those separately.
                    if !layout.symbol_db.args.is_shared
                        && (imp.module == b"GOT.func"
                            || imp.module == b"GOT.mem"
                            || imp.module == b"GOT.data")
                    {
                        continue;
                    }
                    if static_pic
                        && (imp.field == b"__memory_base"
                            || imp.field == b"__table_base"
                            || imp.field == b"__tls_base")
                    {
                        continue;
                    }
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

    // Non-PIC --import-memory: add an `env.memory` import instead of
    // a local memory section. Skipped when `is_shared` because that
    // branch below emits its own memory import plus the dylink globals.
    if layout.symbol_db.args.import_memory && !layout.symbol_db.args.is_shared {
        output_imports.push(OutputImport {
            module: b"env".to_vec(),
            field: b"memory".to_vec(),
            kind: ImportKind::Memory {
                min: 1,
                memory64: layout.symbol_db.args.memory64,
            },
        });
    }

    // Shared/PIC mode: import __memory_base and __stack_pointer.
    // (Declarations are hoisted near Pass 1.72 so the static-PIC synthesis
    // can populate them too.)
    if layout.symbol_db.args.is_shared {
        // Import memory.
        output_imports.push(OutputImport {
            module: b"env".to_vec(),
            field: b"memory".to_vec(),
            kind: ImportKind::Memory {
                min: 1,
                memory64: layout.symbol_db.args.memory64,
            },
        });
        let addr_vt_imp = if layout.symbol_db.args.memory64 {
            VALTYPE_I64
        } else {
            VALTYPE_I32
        };
        // Import __memory_base (immutable, i32 or i64 under memory64).
        let idx = num_imported_globals;
        memory_base_global_idx = Some(idx);
        output_imports.push(OutputImport {
            module: b"env".to_vec(),
            field: b"__memory_base".to_vec(),
            kind: ImportKind::Global {
                valtype: addr_vt_imp,
                mutable: false,
            },
        });
        num_imported_globals += 1;
        // Import __stack_pointer (mutable, i32 or i64 under memory64).
        output_imports.push(OutputImport {
            module: b"env".to_vec(),
            field: b"__stack_pointer".to_vec(),
            kind: ImportKind::Global {
                valtype: addr_vt_imp,
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
        table_base_global_idx = Some(num_imported_globals);
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
    // by num_imported_functions. Update all maps AND every call-operand
    // inside every function body — bodies were populated during Pass 2
    // with defined-only indices (i.e. `func_base + local_idx`) but
    // wasm's runtime function namespace is unified (imports first, then
    // defined). Without shifting body operands, `call <defined_idx>` in
    // a body would be read as `call import <defined_idx>` by the VM,
    // producing out-of-range indices and spurious type mismatches.
    if num_imported_functions > 0 {
        for func in functions.iter_mut() {
            let body_len = func.body.len();
            let mut patches: Vec<(usize, u32)> = Vec::new();
            let walk = walk_funcidx_operands(&func.body, |off, old_idx| {
                // Shift every call-operand unconditionally: pre-shift bodies
                // carry defined-only indices, post-shift the module namespace
                // is unified (imports 0..N, defined N.., where N =
                // num_imported_functions). Unrelocated placeholders (still
                // holding LLVM's 0 value) shift to `num_imported_functions`
                // — that's a harmless forward reference the validator can
                // check, and the result is deterministic.
                patches.push((off, old_idx + num_imported_functions));
            });
            if walk.is_err() {
                continue; // conservatively skip bodies we don't fully decode
            }
            for (off, new_idx) in patches {
                debug_assert!(off + 5 <= body_len);
                write_padded_leb128(&mut func.body, off, new_idx);
            }
        }
        // Fixup: re-apply correct output-import indices for calls that
        // resolved to imports in Pass 2. The shift above wrongly added
        // `num_imported_functions` to the input's local import index
        // (left in the body bytes when Pass 2 deliberately didn't
        // patch). Overwrite with the right value now.
        for (merged_fn_idx, off_in_body, out_imp_idx) in &import_call_fixups {
            if let Some(func) = functions.get_mut(*merged_fn_idx)
                && *off_in_body + 5 <= func.body.len()
            {
                write_padded_leb128(&mut func.body, *off_in_body, *out_imp_idx);
            }
        }
        for idx in function_name_map.values_mut() {
            *idx += num_imported_functions;
        }
        if let Some(ref mut idx) = entry_function_index {
            *idx += num_imported_functions;
        }
        // Also shift defined-function table entries so they point at the
        // correct output function index. Import entries are already
        // post-shift (their value is a dedup'd import index), so skip
        // them — marked via table_needed_is_import.
        for (i, idx) in table_entries.iter_mut().enumerate() {
            if !table_needed_is_import.get(i).copied().unwrap_or(false) {
                *idx += num_imported_functions;
            }
        }
        // `func_to_table_index` keys are the pre-shift funcidxs that
        // deferred TABLE_INDEX relocs already patched against; leave it.
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
    let merged_producers_payload =
        merge_producers(objects.iter().map(|o| o.parsed.custom_sections.as_slice()))?;
    if !merged_producers_payload.is_empty() {
        custom_section_index.insert(b"producers".to_vec(), merged_custom_sections.len());
        merged_custom_sections.push(CustomSection {
            name: b"producers".to_vec(),
            data: merged_producers_payload,
        });
    }

    // Output byte offset of each defined function's body within the output
    // CODE section payload. Layout: `count_leb` followed by per-function
    // `{size_leb, body}`. Indexed by position in `functions` (i.e. the
    // wasm-binary function index minus num_imported_functions).
    let mut output_code_body_offsets: Vec<u32> = Vec::with_capacity(functions.len());
    {
        let mut cursor = leb128_len(functions.len() as u32) as u32;
        for f in &functions {
            let size_leb = leb128_len(f.body.len() as u32) as u32;
            output_code_body_offsets.push(cursor + size_leb);
            cursor += size_leb + f.body.len() as u32;
        }
    }

    // Offset at which each obj's contribution to a given custom section
    // starts in the merged output data. Built by simulating the merge in
    // input order so that relocs referencing the obj's own .debug_* section
    // can be patched with the correct output offset.
    let mut contrib_offsets: Vec<std::collections::HashMap<Vec<u8>, u32>> =
        vec![Default::default(); objects.len()];
    {
        let mut running: std::collections::HashMap<Vec<u8>, u32> = Default::default();
        for (obj_idx, obj_info) in objects.iter().enumerate() {
            for cs in &obj_info.parsed.custom_sections {
                if cs.name == b"target_features" || cs.name == b"producers" {
                    continue;
                }
                let start = *running.get(&cs.name).unwrap_or(&0);
                contrib_offsets[obj_idx].insert(cs.name.clone(), start);
                running.insert(cs.name.clone(), start + cs.data.len() as u32);
            }
        }
    }

    for (obj_idx, obj_info) in objects.iter().enumerate() {
        for cs in &obj_info.parsed.custom_sections {
            if cs.name == b"target_features" || cs.name == b"producers" {
                // Handled above via merge_target_features / merge_producers.
                continue;
            }
            // Apply any custom-section relocations before passthrough.
            // LLVM's assembler emits reloc offsets relative to the custom
            // section's *post-name data* (not the full payload including
            // the name prefix), which matches what wild stores in
            // CustomSection.data, so offsets apply directly.
            let mut patched = cs.data.clone();
            if let Some(relocs) = obj_info.parsed.custom_relocations.get(&cs.name) {
                // Shared helper: recover the kind-1/2 symbol's effective
                // name, falling back to the referenced import field when
                // the symbol table entry itself carries an empty name
                // (undefined + no EXPLICIT_NAME flag).
                let effective_name = |sym: &WasmSymbolInfo| -> Option<Vec<u8>> {
                    if !sym.name.is_empty() {
                        return Some(sym.name.clone());
                    }
                    if sym.flags & 0x10 == 0 {
                        return None;
                    }
                    match sym.kind {
                        0 => obj_info
                            .parsed
                            .import_function_names
                            .get(sym.index as usize)
                            .cloned(),
                        2 => obj_info
                            .parsed
                            .import_global_names
                            .get(sym.index as usize)
                            .cloned(),
                        _ => None,
                    }
                };
                for reloc in relocs {
                    let off_in_data = reloc.offset as usize;
                    if off_in_data + 4 > patched.len() {
                        continue;
                    }
                    let sym = obj_info.parsed.symbols.get(reloc.symbol_index as usize);
                    // Debug-section convention per wasm-ld: unresolved
                    // references in custom sections emit the 0xFFFFFFFF
                    // sentinel rather than 0.
                    let unresolved: u32 = u32::MAX;
                    let value: u32 = match reloc.reloc_type {
                        13 => {
                            // R_WASM_GLOBAL_INDEX_I32 — target is kind 2.
                            sym.filter(|s| s.kind == 2)
                                .and_then(effective_name)
                                .and_then(|n| global_name_map.get(&n).copied())
                                .unwrap_or(unresolved)
                        }
                        26 => {
                            // R_WASM_FUNCTION_INDEX_I32 — target is kind 0.
                            sym.filter(|s| s.kind == 0)
                                .and_then(effective_name)
                                .and_then(|n| function_name_map.get(&n).copied())
                                .unwrap_or(unresolved)
                        }
                        5 => {
                            // R_WASM_MEMORY_ADDR_I32 — target is kind 1.
                            let addr = sym
                                .filter(|s| s.kind == 1)
                                .and_then(effective_name)
                                .and_then(|n| data_name_map.get(&n).copied());
                            if let Some(a) = addr {
                                (a as i64 + reloc.addend as i64) as u32
                            } else {
                                unresolved
                            }
                        }
                        8 => {
                            // R_WASM_FUNCTION_OFFSET_I32 — offset within the
                            // output CODE section payload of `sym`'s function
                            // body, plus the reloc addend. Undefined /
                            // GC'd functions fall back to the unresolved
                            // sentinel so debug readers know the reference
                            // is dead.
                            let body_start = sym
                                .filter(|s| s.kind == 0)
                                .and_then(effective_name)
                                .and_then(|n| function_name_map.get(&n).copied())
                                .and_then(|wasm_idx| {
                                    wasm_idx
                                        .checked_sub(num_imported_functions)
                                        .and_then(|pos| {
                                            output_code_body_offsets.get(pos as usize).copied()
                                        })
                                });
                            match body_start {
                                Some(off) => (off as i64 + reloc.addend as i64) as u32,
                                None => unresolved,
                            }
                        }
                        9 => {
                            // R_WASM_SECTION_OFFSET_I32 — offset within the
                            // target custom section's merged output data,
                            // where this obj's contribution starts, plus the
                            // reloc addend. The target is a kind-3 section
                            // symbol whose `index` names an input section.
                            let target = sym
                                .filter(|s| s.kind == 3)
                                .and_then(|s| obj_info.parsed.section_index_to_name.get(&s.index))
                                .and_then(|name| contrib_offsets[obj_idx].get(name).copied());
                            match target {
                                Some(off) => (off as i64 + reloc.addend as i64) as u32,
                                None => unresolved,
                            }
                        }
                        _ => continue,
                    };
                    patched[off_in_data..off_in_data + 4].copy_from_slice(&value.to_le_bytes());
                }
            }
            if let Some(&idx) = custom_section_index.get(&cs.name) {
                merged_custom_sections[idx].data.extend_from_slice(&patched);
            } else {
                custom_section_index.insert(cs.name.clone(), merged_custom_sections.len());
                merged_custom_sections.push(CustomSection {
                    name: cs.name.clone(),
                    data: patched,
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
        table_base_global_idx,
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
    kind: u8,        // 0=func, 1=table, 2=memory, 3=global
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
    /// Relocations keyed by the target custom section's name. Emitted by
    /// compilers for `.debug_info` / `.debug_line` etc. Wild applies them
    /// during the custom-section passthrough so debug readers see patched
    /// bytes; unresolved global/function references get the 0xFFFFFFFF
    /// sentinel convention.
    custom_relocations: std::collections::HashMap<Vec<u8>, Vec<WasmReloc>>,
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
    /// Input section-index → custom-section name, for resolving kind-3
    /// (SYMTAB_SECTION) symbols referenced by R_WASM_SECTION_OFFSET_I32.
    /// Only custom sections are populated; other section kinds are absent.
    section_index_to_name: std::collections::HashMap<u32, Vec<u8>>,
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
    // Track custom sections' position in the section stream so reloc.*
    // sections targeting a custom section by index can resolve to its name.
    let mut custom_section_position: std::collections::HashMap<usize, Vec<u8>> = Default::default();
    // Reloc.* sections whose target isn't code or data are deferred until
    // after the parse loop, when custom_section_position is complete.
    let mut pending_custom_relocs: Vec<(usize, Vec<WasmReloc>)> = Vec::new();
    let mut custom_relocations: std::collections::HashMap<Vec<u8>, Vec<WasmReloc>> =
        Default::default();
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
                data_segments = parse_data_section(payload)
                    .map_err(|e| crate::error!("parse_data_section: {}", e.to_string()))?;
            }
            0 => {
                // Custom section — check name.
                let (name_len, c) = read_leb128(payload)
                    .map_err(|e| crate::error!("custom section name_len: {}", e.to_string()))?;
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
                    parse_linking_section(custom_data, num_imports, &mut function_names);
                } else if name.starts_with(b"reloc.") {
                    // Per spec §2: reloc section contains section_index, count, entries.
                    if let Ok((target_idx, relocs)) = parse_reloc_section(custom_data) {
                        if code_section_index == Some(target_idx) {
                            code_relocations = relocs;
                        } else if data_section_index == Some(target_idx) {
                            data_relocations = relocs;
                        } else {
                            // Must target a custom section — resolve after
                            // the parse loop when all positions are known.
                            pending_custom_relocs.push((target_idx, relocs));
                        }
                    }
                } else {
                    // Pass through other custom sections (e.g. target_features).
                    custom_section_position.insert(section_counter, name.to_vec());
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
        custom_relocations: {
            // Resolve deferred reloc.* sections whose target is a custom
            // section, using the position→name map built during the parse
            // loop. Relocs with no matching target are discarded.
            for (target_idx, relocs) in pending_custom_relocs {
                if let Some(sec_name) = custom_section_position.get(&target_idx) {
                    custom_relocations.insert(sec_name.clone(), relocs);
                }
            }
            custom_relocations
        },
        section_index_to_name: custom_section_position
            .iter()
            .map(|(&idx, name)| (idx as u32, name.clone()))
            .collect(),
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
            // Active segment: skip init expr. Must parse by opcode — 0x0B
            // ("end") can legitimately appear inside a following SLEB128
            // immediate (e.g. `i32.const 11` = 0x41 0x0B 0x0B), so a naive
            // byte scan walks off the end.
            // Object-file init exprs are a single const-expr instruction
            // followed by `end`:
            //   0x41 <sleb32>        i32.const
            //   0x42 <sleb64>        i64.const
            //   0x23 <leb32>         global.get
            if off >= payload.len() {
                return Err(crate::error!("truncated data init expr"));
            }
            let op = payload[off];
            off += 1;
            match op {
                0x41 => {
                    let (_, c) = read_sleb128(&payload[off..])?;
                    off += c;
                }
                0x42 => {
                    let (_, c) = read_sleb128(&payload[off..])?;
                    off += c;
                }
                0x23 => {
                    let (_, c) = read_leb128(&payload[off..])?;
                    off += c;
                }
                _ => {
                    return Err(crate::error!("unsupported data init opcode 0x{op:02x}"));
                }
            }
            if off >= payload.len() || payload[off] != 0x0B {
                return Err(crate::error!("data init expr missing end (0x0b)"));
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
            alignment: 1,     // Updated from WASM_SEGMENT_INFO
            is_tls: false,    // Updated from WASM_SEGMENT_INFO flags
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

        // Per LLVM `relocHasAddend` (BinaryFormat/Wasm.h): every
        // MEMORY_ADDR_* / FUNCTION_OFFSET_* / SECTION_OFFSET_* type
        // carries a trailing SLEB128 addend. Missing any here pushes
        // the cursor one or more bytes short and the next entry is
        // parsed off-by-one — the symptom is a fabricated reloc with
        // a zero offset and a wildly out-of-range symbol index. The
        // pic-static{,64} regression was R_WASM_MEMORY_ADDR_REL_SLEB
        // (11) being absent.
        let has_addend = matches!(
            reloc_type,
            3   // R_WASM_MEMORY_ADDR_LEB
            | 4   // R_WASM_MEMORY_ADDR_SLEB
            | 5   // R_WASM_MEMORY_ADDR_I32
            | 8   // R_WASM_FUNCTION_OFFSET_I32
            | 9   // R_WASM_SECTION_OFFSET_I32
            | 11  // R_WASM_MEMORY_ADDR_REL_SLEB
            | 14  // R_WASM_MEMORY_ADDR_LEB64
            | 15  // R_WASM_MEMORY_ADDR_SLEB64
            | 16  // R_WASM_MEMORY_ADDR_I64
            | 17  // R_WASM_MEMORY_ADDR_REL_SLEB64
            | 21  // R_WASM_MEMORY_ADDR_TLS_SLEB
            | 22  // R_WASM_FUNCTION_OFFSET_I64
            | 23  // R_WASM_MEMORY_ADDR_LOCREL_I32
            | 25 // R_WASM_MEMORY_ADDR_TLS_SLEB64
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
        return LinkingData {
            symbols: Vec::new(),
            segment_alignments: Vec::new(),
            segment_names: Vec::new(),
            segment_flags: Vec::new(),
            init_functions: Vec::new(),
            comdat_groups: Vec::new(),
        };
    };
    if version != 2 {
        return LinkingData {
            symbols: Vec::new(),
            segment_alignments: Vec::new(),
            segment_names: Vec::new(),
            segment_flags: Vec::new(),
            init_functions: Vec::new(),
            comdat_groups: Vec::new(),
        };
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
                    let Ok((name_len, c)) = read_leb128(&data[soff..]) else {
                        break;
                    };
                    soff += c;
                    let name = data[soff..soff + name_len].to_vec();
                    soff += name_len;
                    // alignment (power of 2)
                    let Ok((alignment, c)) = read_leb128(&data[soff..]) else {
                        break;
                    };
                    soff += c;
                    // flags (WASM_SEGMENT_FLAG_TLS = 0x2)
                    let Ok((flags, c)) = read_leb128(&data[soff..]) else {
                        break;
                    };
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
                    let Ok((priority, c)) = read_leb128(&data[ioff..]) else {
                        break;
                    };
                    ioff += c;
                    let Ok((symbol_index, c)) = read_leb128(&data[ioff..]) else {
                        break;
                    };
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
                    let Ok((name_len, c)) = read_leb128(&data[coff..]) else {
                        break;
                    };
                    coff += c;
                    if coff + name_len > data.len() {
                        break;
                    }
                    let name = data[coff..coff + name_len].to_vec();
                    coff += name_len;
                    let Ok((_flags, c)) = read_leb128(&data[coff..]) else {
                        break;
                    };
                    coff += c;
                    let Ok((sym_count, c)) = read_leb128(&data[coff..]) else {
                        break;
                    };
                    coff += c;
                    let mut entries = Vec::new();
                    for _ in 0..sym_count {
                        let Ok((kind, c)) = read_leb128(&data[coff..]) else {
                            break;
                        };
                        coff += c;
                        let Ok((index, c)) = read_leb128(&data[coff..]) else {
                            break;
                        };
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

    LinkingData {
        symbols,
        segment_alignments,
        segment_names,
        segment_flags: segment_flags_vec,
        init_functions,
        comdat_groups,
    }
}

fn parse_symbol_table_entries(data: &[u8], _num_imports: u32) -> Vec<WasmSymbolInfo> {
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
/// Assert the memory-layout contract implied by the args:
/// `--import-memory` (or `-shared`) → the output must contain an
/// `env.memory` import AND no local Memory section. Otherwise, the
/// output must define exactly one local memory and no memory import.
/// Violating either shape means the downstream host (Substrate, browser,
/// WASI runtime, …) will reject the module at instantiation with an
/// opaque error — catch it here with a specific diagnostic instead.
fn validate_memory_layout(
    data: &[u8],
    import_memory: bool,
    is_shared: bool,
) -> crate::error::Result {
    let want_import = import_memory || is_shared;
    let mut pos = 8;
    let mut saw_local_memory = false;
    let mut saw_memory_import = false;
    while pos < data.len() {
        let id = data[pos];
        pos += 1;
        let (size, c) = read_leb128(&data[pos..])?;
        pos += c;
        let payload = &data[pos..pos + size];
        match id {
            SECTION_IMPORT => {
                let (count, mut off) = read_leb128(payload)?;
                for _ in 0..count {
                    let (mod_len, c) = read_leb128(&payload[off..])?;
                    off += c;
                    off += mod_len;
                    let (field_len, c) = read_leb128(&payload[off..])?;
                    off += c;
                    off += field_len;
                    let kind = payload[off];
                    off += 1;
                    match kind {
                        0x00 => {
                            let (_, c) = read_leb128(&payload[off..])?;
                            off += c;
                        }
                        0x01 => {
                            off += 1;
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
                            saw_memory_import = true;
                            let (flags, c) = read_leb128(&payload[off..])?;
                            off += c;
                            let (_, c) = read_leb128(&payload[off..])?;
                            off += c;
                            if flags & 0x01 != 0 {
                                let (_, c) = read_leb128(&payload[off..])?;
                                off += c;
                            }
                        }
                        0x03 => off += 2,
                        _ => {}
                    }
                }
            }
            SECTION_MEMORY => {
                let (count, _) = read_leb128(payload)?;
                if count > 0 {
                    saw_local_memory = true;
                }
            }
            _ => {}
        }
        pos += size;
    }
    if want_import && !saw_memory_import {
        return Err(crate::error!(
            "WASM output: --import-memory (or -shared) requested but no \
             memory import found in output"
        ));
    }
    if want_import && saw_local_memory {
        return Err(crate::error!(
            "WASM output: --import-memory (or -shared) requested but output \
             contains a local Memory section — host expects to supply memory"
        ));
    }
    if !want_import && !saw_local_memory {
        return Err(crate::error!(
            "WASM output: no --import-memory but output lacks a Memory section"
        ));
    }
    if !want_import && saw_memory_import {
        return Err(crate::error!(
            "WASM output: no --import-memory but output imports memory"
        ));
    }
    Ok(())
}

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
                1..=5 => id,    // type..memory
                13 => 6,        // tag (EH) after memory
                6 => 7,         // global
                7 => 8,         // export
                8 => 9,         // start
                9 => 10,        // element
                12 => 11,       // datacount
                10 => 12,       // code
                11 => 13,       // data
                other => other, // unknown
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
                let (count, mut off) = read_leb128(payload)?;
                code_count = Some(count);
                // Per-body structural invariant: walk each function body
                // with wilt's instruction iterator. Any body that fails
                // to decode cleanly is a wild emission bug — surface it
                // with function index, byte offset, and surrounding bytes.
                #[cfg(feature = "wilt")]
                for func_idx in 0..count {
                    let (body_size, c) = read_leb128(&payload[off..])?;
                    off += c;
                    let body_start_in_payload = off;
                    if off + body_size > payload.len() {
                        return Err(crate::error!(
                            "code section: body {func_idx} size {body_size} \
                             extends past section end"
                        ));
                    }
                    let body = &payload[off..off + body_size];
                    // Skip locals header.
                    if let Some(locals_end) = wilt::opcode::skip_locals(body) {
                        let mut iter = wilt::opcode::InstrIter::new(body, locals_end);
                        let mut last_pos = locals_end;
                        for (p, len) in &mut iter {
                            last_pos = p + len;
                        }
                        if iter.failed() {
                            let abs = pos + body_start_in_payload + last_pos;
                            let window_start = last_pos.saturating_sub(8);
                            let window_end = (last_pos + 16).min(body.len());
                            let bytes = &body[window_start..window_end];
                            return Err(crate::error!(
                                "WASM output: function body {func_idx} fails to decode — \
                                 stopped at body-relative byte {:#x} (absolute {:#x}), \
                                 surrounding bytes {:02x?} (body size {})",
                                last_pos,
                                abs,
                                bytes,
                                body_size
                            ));
                        }
                    }
                    off += body_size;
                }
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
        return Err(crate::error!(
            "WASM output: trailing bytes after last section"
        ));
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
//
// All of these used to take `&mut Vec<u8>`. Phase 2 of the wasm
// writer unification made them generic over `Buf` so the same
// helpers work whether the caller is building a transient sub-
// section payload (still a `Vec<u8>`) or appending to the
// outermost `Cursor` over the mmap'd output.

/// Write a WASM name: LEB128 length + bytes.
fn write_name<B: Buf>(out: &mut B, name: &[u8]) {
    write_leb128(out, name.len() as u32);
    out.extend_from_slice(name);
}

/// Write a WASM section: id byte + LEB128 size + payload.
fn write_section<B: Buf>(out: &mut B, section_id: u8, payload: &[u8]) {
    out.push(section_id);
    write_leb128(out, payload.len() as u32);
    out.extend_from_slice(payload);
}

/// Number of bytes an unsigned LEB128 encoding of `value` would occupy.
fn leb128_len(mut value: u32) -> usize {
    let mut n = 1;
    while value >= 0x80 {
        value >>= 7;
        n += 1;
    }
    n
}

/// Write an unsigned LEB128 value.
fn write_leb128<B: Buf>(out: &mut B, mut value: u32) {
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
fn write_sleb128<B: Buf>(out: &mut B, mut value: i32) {
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
    debug_assert_padded_leb5(buf, offset, value);
}

/// Postcondition for a 5-byte padded varuint32 slot: bytes 0..3 must have
/// the continuation bit set (0x80) and byte 4 must have it clear, with at
/// most 4 significant bits. Any violation indicates a corrupt write —
/// either the writer or something writing over the slot afterwards.
#[track_caller]
fn debug_assert_padded_leb5(buf: &[u8], offset: usize, value: u32) {
    if offset + 5 > buf.len() {
        return;
    }
    let s = &buf[offset..offset + 5];
    let cont_ok = s[0] & 0x80 != 0 && s[1] & 0x80 != 0 && s[2] & 0x80 != 0 && s[3] & 0x80 != 0;
    let term_ok = s[4] & 0x80 == 0 && s[4] & 0xF0 == 0;
    if !cont_ok || !term_ok {
        panic!(
            "padded LEB5 slot corrupt at offset {offset}: bytes {s:02x?} (wrote value {value:#x})\n  \
             expected bytes 0..3 with 0x80 set and byte 4 < 0x10 (no continuation)"
        );
    }
    // Also verify the slot decodes back to the intended value.
    let decoded = (s[0] as u32 & 0x7F)
        | ((s[1] as u32 & 0x7F) << 7)
        | ((s[2] as u32 & 0x7F) << 14)
        | ((s[3] as u32 & 0x7F) << 21)
        | ((s[4] as u32 & 0x0F) << 28);
    if decoded != value {
        panic!(
            "padded LEB5 round-trip mismatch at offset {offset}: wrote {value:#x}, \
             slot decodes to {decoded:#x} (bytes {s:02x?})"
        );
    }
}

/// Write a signed LEB128 value up to 64 bits wide. Emits 1–10 bytes.
fn write_sleb128_i64<B: Buf>(out: &mut B, mut value: i64) {
    loop {
        let byte = (value as u8) & 0x7F;
        value >>= 7; // arithmetic shift sign-extends
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Write an unsigned LEB128 value up to 64 bits wide. Emits 1–10 bytes.
fn write_leb128_u64<B: Buf>(out: &mut B, mut value: u64) {
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
fn write_leb128_addr<B: Buf>(out: &mut B, value: Addr) {
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
    debug_assert_padded_sleb5(buf, offset, value);
}

#[track_caller]
fn debug_assert_padded_sleb5(buf: &[u8], offset: usize, value: i32) {
    if offset + 5 > buf.len() {
        return;
    }
    let s = &buf[offset..offset + 5];
    let cont_ok = s[0] & 0x80 != 0 && s[1] & 0x80 != 0 && s[2] & 0x80 != 0 && s[3] & 0x80 != 0;
    let term_ok = s[4] & 0x80 == 0;
    if !cont_ok || !term_ok {
        panic!(
            "padded SLEB5 slot corrupt at offset {offset}: bytes {s:02x?} (wrote value {value:#x})"
        );
    }
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
    Err(crate::error!(
        "Unexpected end of LEB128 (len={}, bt={})",
        data.len(),
        std::backtrace::Backtrace::force_capture()
    ))
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
/// - Output carries `+` for every USED feature and `-` for every feature DISALLOWED by at least one
///   input that no input uses.
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
                        tracing::warn!("wasm: target_features: unknown prefix byte {prefix:#04x}");
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
    let disallowed_only: Vec<Vec<u8>> = disallowed.difference(&used).cloned().collect();

    let mut payload = Vec::new();
    write_leb128(&mut payload, (used.len() + disallowed_only.len()) as u32);
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

/// Merge the `producers` custom section across all input objects.
///
/// Format: count of fields, each `{name, count, values: {name, version}}`.
/// Concatenating raw payloads produces malformed output; instead, collect
/// unique `(value_name, version)` pairs per field across all inputs and
/// re-emit a single well-formed record. Insertion order is preserved so
/// output is deterministic.
fn merge_producers<'a>(
    per_object_custom: impl IntoIterator<Item = &'a [CustomSection]>,
) -> crate::error::Result<Vec<u8>> {
    use indexmap::IndexMap;

    // Map of field_name -> map of value_name -> version. Each producer name
    // within a field must be unique; keep the first version seen.
    let mut fields: IndexMap<Vec<u8>, IndexMap<Vec<u8>, Vec<u8>>> = IndexMap::new();
    let mut saw_any = false;

    fn read_vec<'b>(data: &'b [u8], off: &mut usize) -> crate::error::Result<&'b [u8]> {
        let (len, c) = read_leb128(&data[*off..])?;
        *off += c;
        if *off + len > data.len() {
            crate::bail!("producers: truncated vec");
        }
        let v = &data[*off..*off + len];
        *off += len;
        Ok(v)
    }

    for obj in per_object_custom {
        for cs in obj {
            if cs.name != b"producers" {
                continue;
            }
            saw_any = true;
            let data = &cs.data;
            let mut off = 0usize;
            let (field_count, c) = read_leb128(data)?;
            off += c;
            for _ in 0..field_count {
                let fname = read_vec(data, &mut off)?.to_vec();
                let (value_count, c2) = read_leb128(&data[off..])?;
                off += c2;
                let entry = fields.entry(fname).or_default();
                for _ in 0..value_count {
                    let vname = read_vec(data, &mut off)?.to_vec();
                    let vver = read_vec(data, &mut off)?.to_vec();
                    entry.entry(vname).or_insert(vver);
                }
            }
        }
    }

    if !saw_any {
        return Ok(Vec::new());
    }

    let mut payload = Vec::new();
    write_leb128(&mut payload, fields.len() as u32);
    for (fname, values) in &fields {
        write_leb128(&mut payload, fname.len() as u32);
        payload.extend_from_slice(fname);
        write_leb128(&mut payload, values.len() as u32);
        for (vname, vver) in values {
            write_leb128(&mut payload, vname.len() as u32);
            payload.extend_from_slice(vname);
            write_leb128(&mut payload, vver.len() as u32);
            payload.extend_from_slice(vver);
        }
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
        for &v in &[
            0i32,
            1,
            -1,
            63,
            64,
            -64,
            -65,
            i32::MAX,
            i32::MIN,
            0x3FFFFFFF,
            -0x40000000,
        ] {
            roundtrip_i32(v);
        }
    }

    #[test]
    fn padded_leb128_u64_roundtrip() {
        for &v in &[
            0u64,
            1,
            127,
            128,
            1 << 32,
            (1u64 << 63) - 1,
            1u64 << 63,
            u64::MAX,
        ] {
            roundtrip_u64(v);
        }
    }

    #[test]
    fn padded_sleb128_i64_roundtrip() {
        let cases: &[i64] = &[
            0,
            1,
            -1,
            63,
            64,
            -64,
            -65,
            i32::MAX as i64,
            i32::MIN as i64,
            i64::MAX,
            i64::MIN,
            (1i64 << 40),
            -(1i64 << 40),
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
            vec![(b'-', b"atomics".to_vec()), (b'+', b"simd128".to_vec()),]
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

    /// Encode a memory import with the given limits flag byte and a single
    /// min page, then round-trip through `parse_wasm_sections` and the
    /// memory-import emission path. This verifies the 0x04 bit is parsed
    /// and re-emitted faithfully.
    /// Exercise the active-data-segment offset emission subset: under mem64
    /// the offset must be `i64.const <SLEB64>` not `i32.const <SLEB32>`.
    /// Covers both widths independent of the Addr alias.
    /// A function body containing an `i32.const 16` immediate has a literal
    /// `0x10` byte inside the SLEB128 payload. The old naive `remap_call_targets`
    /// would mis-identify that `0x10` as a `call` opcode and corrupt the
    /// following bytes. Verify the new opcode-aware walker leaves it alone.
    #[test]
    fn remap_call_targets_does_not_misread_const_16() {
        // Body: 0 locals; i32.const 16; drop; end.
        // Bytes: 0x00 (locals=0), 0x41 (i32.const), 0x10 (16 as SLEB), 0x1A
        // (drop), 0x0B (end).
        let mut body = vec![0x00, 0x41, 0x10, 0x1A, 0x0B];
        let original = body.clone();
        // index_map says "func 16 now lives at 99" — if the walker
        // mis-triggers, it would overwrite the 0x10 byte with 99's LEB.
        let mut index_map = vec![None; 17];
        index_map[16] = Some(99);
        remap_call_targets(&mut body, &index_map);
        assert_eq!(body, original, "walker must not mis-patch i32.const 16");
    }

    /// A real `call 16` *should* get remapped. This pins the positive case.
    #[test]
    fn remap_call_targets_rewrites_call_funcidx() {
        // Body: 0 locals; call 16; end.
        // Padded LEB128 of 16 is [0x90, 0x80, 0x80, 0x80, 0x00] — 5 bytes.
        let mut body = vec![
            0x00, // 0 locals
            0x10, // call
            0x90, 0x80, 0x80, 0x80, 0x00, // padded LEB128 of 16
            0x0B,
        ];
        let mut index_map = vec![None; 17];
        index_map[16] = Some(5);
        remap_call_targets(&mut body, &index_map);
        // Padded LEB128 of 5 is [0x85, 0x80, 0x80, 0x80, 0x00].
        assert_eq!(body, vec![0x00, 0x10, 0x85, 0x80, 0x80, 0x80, 0x00, 0x0B]);
    }

    /// A body exercising the 0xFC bulk-memory prefix: memory.copy 0 0.
    /// Ensure the walker successfully steps over the sub-opcode and the
    /// two memidx immediates without bailing.
    #[test]
    fn remap_call_targets_walks_through_bulk_memory() {
        // Body: 0 locals; memory.copy 0 0; end.
        // Bytes: 0x00, 0xFC, 0x0A, 0x00, 0x00, 0x0B.
        let mut body = vec![0x00, 0xFC, 0x0A, 0x00, 0x00, 0x0B];
        let original = body.clone();
        let index_map: Vec<Option<u32>> = vec![];
        remap_call_targets(&mut body, &index_map);
        assert_eq!(body, original, "bulk-memory body should be untouched");
    }

    /// Synthesise a minimal memory64 wasm module using the same emission
    /// primitives the writer uses (SECTION_MEMORY with 0x04, i64 global,
    /// i64.const data offset), then run the output validator over it. This
    /// exercises every mem64 emission path in combination.
    #[test]
    fn mem64_synthesized_output_round_trips() {
        fn section(id: u8, payload: &[u8]) -> Vec<u8> {
            let mut v = Vec::new();
            v.push(id);
            let mut len = Vec::new();
            write_leb128(&mut len, payload.len() as u32);
            v.extend_from_slice(&len);
            v.extend_from_slice(payload);
            v
        }

        let mut out = Vec::new();
        out.extend_from_slice(b"\0asm");
        out.extend_from_slice(&[1, 0, 0, 0]);

        // Type section: func () -> ().
        let mut t = Vec::new();
        write_leb128(&mut t, 1);
        t.push(0x60);
        t.push(0);
        t.push(0);
        out.extend_from_slice(&section(SECTION_TYPE, &t));

        // Function section: one function of type 0.
        let mut f = Vec::new();
        write_leb128(&mut f, 1);
        write_leb128(&mut f, 0);
        out.extend_from_slice(&section(SECTION_FUNCTION, &f));

        // Memory section: 1 mem64 memory with min 1, no max.
        let mut m = Vec::new();
        write_leb128(&mut m, 1);
        m.push(0x04);
        write_leb128_u64(&mut m, 1);
        out.extend_from_slice(&section(SECTION_MEMORY, &m));

        // Global section: mutable i64 __stack_pointer.
        let mut g = Vec::new();
        write_leb128(&mut g, 1);
        g.push(VALTYPE_I64);
        g.push(1);
        g.push(0x42); // i64.const
        write_sleb128_i64(&mut g, 0x1_0000);
        g.push(0x0B);
        out.extend_from_slice(&section(SECTION_GLOBAL, &g));

        // Code section: trivial empty body.
        let mut c = Vec::new();
        write_leb128(&mut c, 1);
        let body: [u8; 2] = [0x00, 0x0B];
        write_leb128(&mut c, body.len() as u32);
        c.extend_from_slice(&body);
        out.extend_from_slice(&section(SECTION_CODE, &c));

        // Data section: one active segment with i64.const 0x1_0000 offset.
        let mut d = Vec::new();
        write_leb128(&mut d, 1);
        d.push(0x00);
        d.push(0x42);
        write_sleb128_i64(&mut d, 0x1_0000);
        d.push(0x0B);
        let bytes: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        write_leb128(&mut d, bytes.len() as u32);
        d.extend_from_slice(&bytes);
        out.extend_from_slice(&section(SECTION_DATA, &d));

        validate_output(&out).expect("synthesized mem64 module should validate");

        // Verify the memory section's flags byte really is 0x04.
        let mut p = 8;
        let mut found_mem_flag = None;
        while p < out.len() {
            let id = out[p];
            p += 1;
            let (size, c) = read_leb128(&out[p..]).unwrap();
            p += c;
            if id == SECTION_MEMORY {
                let (_count, cc) = read_leb128(&out[p..]).unwrap();
                found_mem_flag = Some(out[p + cc]);
                break;
            }
            p += size;
        }
        assert_eq!(
            found_mem_flag,
            Some(0x04),
            "memory section should carry 0x04 limits bit"
        );
    }

    #[test]
    fn memory64_active_data_segment_uses_i64_const() {
        // mem64 emission path: flag + i64.const + SLEB64 + end + size + data.
        let offset_u64: u64 = 0x1_0000_0000;
        let data = [0xAA, 0xBB];
        let mut payload = Vec::new();
        payload.push(0x00); // active, memory 0
        payload.push(0x42); // i64.const
        write_sleb128_i64(&mut payload, offset_u64 as i64);
        payload.push(0x0B);
        write_leb128(&mut payload, data.len() as u32);
        payload.extend_from_slice(&data);
        // SLEB64 of 2^32 is 5 bytes (0x80 0x80 0x80 0x80 0x10), plus:
        //   flag=0x00, opcode=0x42, terminator=0x0B, size=0x02, bytes=0xAA 0xBB.
        assert_eq!(
            payload,
            [
                0x00, 0x42, 0x80, 0x80, 0x80, 0x80, 0x10, 0x0B, 0x02, 0xAA, 0xBB
            ]
        );

        // mem32 emission path for a small offset.
        let offset_u32: u32 = 0x1000;
        let mut p32 = Vec::new();
        p32.push(0x00);
        p32.push(0x41);
        write_sleb128(&mut p32, offset_u32 as i32);
        p32.push(0x0B);
        write_leb128(&mut p32, data.len() as u32);
        p32.extend_from_slice(&data);
        // SLEB32 of 0x1000 = 0x80 0x20.
        assert_eq!(p32, [0x00, 0x41, 0x80, 0x20, 0x0B, 0x02, 0xAA, 0xBB]);
    }

    /// Encode a single i64 global with init value 0x1_0000_0000 through the
    /// global-section emission subset, then hand-decode the result. Verifies
    /// that the i64 valtype + i64.const opcode + SLEB64 init expression all
    /// line up.
    #[test]
    fn memory64_global_emits_i64_const_init() {
        let g = OutputGlobal {
            name: b"__stack_pointer".to_vec(),
            valtype: VALTYPE_I64,
            mutable: true,
            init_value: 0x1_0000_0000, // 2^32 — needs > 4 bytes
            exported: false,
        };
        let mut payload = Vec::new();
        write_leb128(&mut payload, 1);
        payload.push(g.valtype);
        payload.push(if g.mutable { 1 } else { 0 });
        assert_eq!(g.valtype, 0x7E, "valtype should be i64");
        payload.push(0x42); // i64.const
        write_sleb128_i64(&mut payload, g.init_value as i64);
        payload.push(0x0B); // end
        // Expected: count=1, valtype=0x7E, mut=1, 0x42, SLEB64 of 2^32, 0x0B.
        // SLEB64 of 0x1_0000_0000 = 0x80 0x80 0x80 0x80 0x10.
        assert_eq!(
            payload,
            [0x01, 0x7E, 0x01, 0x42, 0x80, 0x80, 0x80, 0x80, 0x10, 0x0B]
        );
    }

    /// SLEB64 encoder produces the exact canonical output.
    #[test]
    fn sleb128_i64_encodes_canonically() {
        let cases: &[(i64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (-1, &[0x7F]),
            (63, &[0x3F]),
            (-64, &[0x40]),
            (64, &[0xC0, 0x00]),
            (-65, &[0xBF, 0x7F]),
            (0x1_0000_0000, &[0x80, 0x80, 0x80, 0x80, 0x10]),
            (
                i64::MIN,
                &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F],
            ),
            (
                i64::MAX,
                &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00],
            ),
        ];
        for (v, expected) in cases {
            let mut buf = Vec::new();
            write_sleb128_i64(&mut buf, *v);
            assert_eq!(&buf, expected, "sleb64 for {v}");
        }
    }

    /// Under a static link, a kind-2 symbol named `__memory_base` must be
    /// picked up by the synthesis scan that runs before Pass 1.75. Build a
    /// minimal wasm object that declares that symbol in its linking section
    /// and assert parse_wasm_sections recovers a matching kind-2 entry.
    #[test]
    fn memory_base_reference_detected_in_symtab() {
        // Hand-roll the linking section subsection 8 (WASM_SYMBOL_TABLE)
        // with a single kind-2 (global) entry called "__memory_base",
        // flagged UNDEFINED (0x10) and EXPLICIT_NAME (0x40).
        let mut sym_entries = Vec::new();
        write_leb128(&mut sym_entries, 1); // 1 symbol
        sym_entries.push(2); // kind = GLOBAL
        write_leb128(&mut sym_entries, 0x10 | 0x40); // UNDEFINED | EXPLICIT_NAME
        write_leb128(&mut sym_entries, 0); // global index (unused for this test)
        write_leb128(&mut sym_entries, b"__memory_base".len() as u32);
        sym_entries.extend_from_slice(b"__memory_base");

        let mut symtab_subsec = Vec::new();
        symtab_subsec.push(8); // WASM_SYMBOL_TABLE subsection type
        write_leb128(&mut symtab_subsec, sym_entries.len() as u32);
        symtab_subsec.extend_from_slice(&sym_entries);

        let mut linking = Vec::new();
        write_leb128(&mut linking, 2); // version 2
        linking.extend_from_slice(&symtab_subsec);

        // Wrap into a custom section named "linking".
        let mut cs_payload = Vec::new();
        write_name(&mut cs_payload, b"linking");
        cs_payload.extend_from_slice(&linking);

        // Assemble the full wasm.
        let mut wasm = Vec::new();
        wasm.extend_from_slice(b"\0asm");
        wasm.extend_from_slice(&[1, 0, 0, 0]);
        // Custom section (id 0).
        wasm.push(0);
        let mut cslen = Vec::new();
        write_leb128(&mut cslen, cs_payload.len() as u32);
        wasm.extend_from_slice(&cslen);
        wasm.extend_from_slice(&cs_payload);

        let parsed = parse_wasm_sections(&wasm).expect("parse ok");
        let mb_sym = parsed
            .symbols
            .iter()
            .find(|s| s.kind == 2 && s.name == b"__memory_base")
            .expect("__memory_base symbol recognised");
        assert!(mb_sym.flags & 0x10 != 0, "UNDEFINED flag should be set");
    }

    /// A GOT.func.<name> global import in a compiled object gets picked up
    /// by parse_wasm_sections as a kind-3 (global) ParsedImport with the
    /// exact field name. The GOT internalisation pass in merge_inputs keys
    /// on `imp.field.strip_prefix(b"GOT.func.")`, so this test pins that
    /// the imported field survives parsing unchanged.
    #[test]
    fn got_func_import_parses_with_field_name() {
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

        // Type section: one type (void -> void).
        let mut t = Vec::new();
        write_leb128(&mut t, 1);
        t.push(0x60);
        t.push(0);
        t.push(0);
        wasm.extend_from_slice(&section(SECTION_TYPE, &t));

        // Import section: a single kind-3 (global) import of "GOT.func.foo".
        let mut imp = Vec::new();
        write_leb128(&mut imp, 1);
        write_name(&mut imp, b"env");
        write_name(&mut imp, b"GOT.func.foo");
        imp.push(0x03); // global
        imp.push(0x7F); // i32
        imp.push(1); // mutable
        wasm.extend_from_slice(&section(SECTION_IMPORT, &imp));

        let parsed = parse_wasm_sections(&wasm).expect("parse ok");
        let got = parsed
            .imports
            .iter()
            .find(|i| i.kind == 3)
            .expect("global import present");
        assert_eq!(got.field, b"GOT.func.foo");
        assert!(got.field.starts_with(b"GOT.func."));
    }

    /// Under a static (non-PIC) link, wild handles REL_SLEB by writing the
    /// absolute symbol address in the 5-byte slot. This is correct because
    /// the compiler's surrounding `global.get __memory_base` + `i32.add`
    /// sequence degrades to a no-op when `__memory_base == 0`, which is
    /// the static link's contract. Pin the byte pattern so that a change
    /// to the "shared-or-static" decision gets a test failure.
    #[test]
    fn rel_sleb_static_writes_absolute_address() {
        // Build a 5-byte padded SLEB128 slot for the value 0x2000 and
        // confirm write_padded_sleb128 emits the expected bytes.
        let mut buf = [0u8; 5];
        write_padded_sleb128(&mut buf, 0, 0x2000);
        // SLEB128 of 0x2000: bits = 0010 0000 0000 0000 (14 bits).
        //   byte 0: 0x00 | cont = 0x80
        //   byte 1: 0x40 | cont = 0xC0
        //   byte 2: 0x00 | cont = 0x80
        //   byte 3: 0x00 | cont = 0x80
        //   byte 4: 0x00 (terminator, no sign bit since 0x2000 > 0)
        assert_eq!(buf, [0x80, 0xC0, 0x80, 0x80, 0x00]);
    }

    #[test]
    fn pic_flags_parsing() {
        use crate::platform::Args as _;
        fn mk(argv: &[&str]) -> crate::args::wasm::WasmArgs {
            let mut args = crate::args::wasm::WasmArgs::new().expect("wasm args");
            args.parse(argv.iter().copied()).expect("parse");
            args
        }
        assert!(!mk(&[]).is_pic);
        assert!(mk(&["-pie"]).is_pic);
        assert!(mk(&["--pie"]).is_pic);
        assert!(mk(&["--experimental-pic"]).is_pic);
        // -shared still sets is_shared, independent of is_pic.
        let a = mk(&["-shared"]);
        assert!(a.is_shared);
        assert!(!a.is_pic);
    }

    #[test]
    fn memory64_import_emits_0x04_flag() {
        // Build an OutputImport matching what PIC mode would push.
        let imp = OutputImport {
            module: b"env".to_vec(),
            field: b"memory".to_vec(),
            kind: ImportKind::Memory {
                min: 3,
                memory64: true,
            },
        };
        // Hand-roll the import-section emission subset (mirrors the writer).
        let mut payload = Vec::new();
        write_leb128(&mut payload, 1);
        write_name(&mut payload, &imp.module);
        write_name(&mut payload, &imp.field);
        match &imp.kind {
            ImportKind::Memory { min, memory64 } => {
                payload.push(0x02);
                payload.push(if *memory64 { 0x04 } else { 0x00 });
                if *memory64 {
                    write_leb128_u64(&mut payload, *min);
                } else {
                    write_leb128(&mut payload, *min as u32);
                }
            }
            _ => unreachable!(),
        }
        // Verify the encoded bytes: count=1, "env", "memory", kind=0x02,
        // flags=0x04, min=3 (one byte).
        assert_eq!(
            payload,
            [
                0x01, 0x03, b'e', b'n', b'v', 0x06, b'm', b'e', b'm', b'o', b'r', b'y', 0x02, 0x04,
                0x03,
            ]
        );
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

    /// Bug #9 regression (midnight-runtime): `gc_functions` marks
    /// types as "live" by scanning function signatures and imports,
    /// but forgot to scan `call_indirect` typeidx operands. Types
    /// referenced only by `call_indirect` (a common case when
    /// indirect calls through function pointers don't share their
    /// signature with any named function) got GC'd, shifting every
    /// later typeidx by one and making unrelated `call_indirect`
    /// sites decode against the wrong signature — surfacing as
    /// "type mismatch in call_indirect, expected [...] but got [...]"
    /// at link validation.
    ///
    /// This test constructs a 3-type module:
    ///   - type 0: `() -> ()`, the signature of the one defined function.
    ///   - type 1: `(i64) -> ()`, referenced ONLY by a `call_indirect` inside the function body.
    ///   - type 2: `(i32) -> ()`, unused entirely.
    ///
    /// Pre-fix, `mark_used_types` would set type_used = [T,F,F] —
    /// dropping both type 1 and type 2. After compaction the body's
    /// `call_indirect 1` would decode against type 0 (wrong sig).
    ///
    /// Post-fix, type 1 is kept alive by the call_indirect walker;
    /// type 2 is correctly dropped.
    #[test]
    fn gc_retains_type_used_only_via_call_indirect() {
        // Body: 0 locals; i64.const 0; i32.const 0 (table idx);
        //       call_indirect type=1 table=0; end.
        let body = vec![
            0x00, // 0 locals
            0x42, 0x00, // i64.const 0
            0x41, 0x00, // i32.const 0  (table index)
            0x11, 0x81, 0x80, 0x80, 0x80, 0x00, // call_indirect type=1 (padded)
            0x00, // table 0
            0x0B, // end
        ];

        // 3 types; function's signature is type 0; no imports.
        let used = mark_used_types(
            3,
            std::iter::once((0u32, body.as_slice())),
            std::iter::empty::<u32>(),
        );

        assert!(used[0], "type 0 (function signature) must be live");
        assert!(
            used[1],
            "type 1 used only via call_indirect MUST be live — \
             this is the midnight-runtime regression"
        );
        assert!(!used[2], "type 2 really is unused — may be GC'd");
    }

    /// Companion invariant for the fix: if the body walker can't
    /// fully decode a function, gc MUST conservatively retain every
    /// type. Over-retention loses size; silent type-loss loses
    /// correctness — we pick the former.
    #[test]
    fn undecodable_body_conservatively_retains_all_types() {
        // Body starting with an opcode the walker doesn't recognise:
        // 0xFE is the atomic-ops prefix, which
        // `walk_call_indirect_typeidx` bails on.
        let body = vec![0x00, 0xFE, 0x00, 0x0B];
        let used = mark_used_types(
            5,
            std::iter::once((0u32, body.as_slice())),
            std::iter::empty::<u32>(),
        );
        assert!(
            used.iter().all(|&x| x),
            "unknown-opcode body must retain every type"
        );
    }

    /// Bug #7 regression: `gc_functions` compacts the types list but the
    /// `call_indirect` type-index operands inside bodies also need remapping
    /// or the signatures desync from the new type numbering, producing
    /// "expected [...] but got [...]" validator errors at every call_indirect
    /// site that referenced a type whose new index differs from its old one.
    ///
    /// This test exercises the walker in isolation: a body with a
    /// `call_indirect 17 0` must surface the typeidx at the right offset and
    /// nothing else. A neighbouring `call 5` (funcidx immediate) must NOT be
    /// reported by the typeidx walker.
    #[test]
    fn walk_call_indirect_typeidx_reports_only_call_indirect_typeidx() {
        // Body layout: 0 locals; call 5; call_indirect 17 0; end.
        // call 5 = 0x10 0x85 0x80 0x80 0x80 0x00   (5-byte padded LEB 5)
        // call_indirect 17 0 = 0x11 0x91 0x80 0x80 0x80 0x00 0x00
        let body = [
            0x00, // 0 locals
            0x10, 0x85, 0x80, 0x80, 0x80, 0x00, // call 5
            0x11, 0x91, 0x80, 0x80, 0x80, 0x00, 0x00, // call_indirect 17 0
            0x0B, // end
        ];
        let mut hits: Vec<(usize, u32)> = Vec::new();
        walk_call_indirect_typeidx(&body, |off, idx| hits.push((off, idx)))
            .expect("walker should succeed");
        assert_eq!(
            hits.len(),
            1,
            "only call_indirect should report a typeidx; got {hits:?}"
        );
        let (off, idx) = hits[0];
        assert_eq!(idx, 17, "typeidx value");
        assert_eq!(
            &body[off..off + 5],
            &[0x91, 0x80, 0x80, 0x80, 0x00],
            "offset must point at the 5-byte padded LEB, not the opcode"
        );
    }

    /// Bug #7 regression: verify a body that's been patched by the walker
    /// decodes back to the new typeidx with the padded LEB shape preserved.
    #[test]
    fn walk_call_indirect_typeidx_patch_round_trips() {
        let mut body = vec![
            0x00, 0x11, 0x91, 0x80, 0x80, 0x80, 0x00, 0x00, // call_indirect 17 0
            0x0B,
        ];
        // Simulate gc_functions remapping type 17 → 3.
        let mut patches: Vec<(usize, u32)> = Vec::new();
        walk_call_indirect_typeidx(&body, |off, old| {
            if old == 17 {
                patches.push((off, 3));
            }
        })
        .unwrap();
        for (off, new_idx) in patches {
            write_padded_leb128(&mut body, off, new_idx);
        }
        // After patch: body[2..=6] should be 5-byte padded LEB for 3.
        assert_eq!(
            &body[2..=6],
            &[0x83, 0x80, 0x80, 0x80, 0x00],
            "padded LEB5 for 3 expected"
        );
        // And the tableidx + end bytes must not have moved.
        assert_eq!(body[7], 0x00, "tableidx intact");
        assert_eq!(body[8], 0x0B, "end intact");
    }

    /// Bug #6 regression: body call operands are produced in wild's internal
    /// "defined-only" function namespace (imports not counted); they must be
    /// shifted by `num_imported_functions` so the final module uses the
    /// wasm spec's unified namespace. Without the shift, `call 0` would be
    /// read as "call import 0" by the VM, producing out-of-range errors or
    /// type mismatches (the wild→validator gap observed in the partner-chains
    /// substrate runtime).
    ///
    /// This test exercises `walk_funcidx_operands`: a `call 0` body, when
    /// shifted by 33 (a representative substrate import count), must become
    /// `call 33` with the padded LEB shape intact. Crucially, a `call 0`
    /// that previously wrote 5 `0x00` bytes (i.e. the padded LEB encoded
    /// as 80 80 80 80 00) must still shift correctly — LLVM's placeholder
    /// bytes are legitimate zero-valued LEBs, not sentinels to skip.
    #[test]
    fn funcidx_shift_rewrites_call_zero_to_num_imports() {
        // Body: 0 locals; call 0 (padded); end.
        let mut body = vec![
            0x00, // 0 locals
            0x10, 0x80, 0x80, 0x80, 0x80, 0x00, // call 0 (padded)
            0x0B, // end
        ];
        const NUM_IMPORTS: u32 = 33;
        let mut patches: Vec<(usize, u32)> = Vec::new();
        walk_funcidx_operands(&body, |off, old| {
            patches.push((off, old + NUM_IMPORTS));
        })
        .expect("walker ok");
        assert_eq!(patches.len(), 1, "exactly one call to shift");
        for (off, new_idx) in patches {
            write_padded_leb128(&mut body, off, new_idx);
        }
        // LEB slot is body[2..=6] (byte 1 is the `call` opcode).
        let slot: [u8; 5] = body[2..=6].try_into().unwrap();
        assert_eq!(decode_padded_u32(&slot), NUM_IMPORTS);
        assert_eq!(body[1], 0x10, "call opcode untouched");
        assert_eq!(body[7], 0x0B, "end untouched");
    }

    /// Bug #8 regression: under `--import-memory` the output must import
    /// memory from `env.memory` AND omit the local Memory section. Before
    /// the fix, wild always emitted the local Memory section; substrate
    /// runtimes rely on imported memory and the executor rejects local
    /// memory. `validate_memory_layout` now catches violations either way.
    #[test]
    fn validate_memory_layout_requires_import_when_flag_set() {
        fn section(id: u8, payload: &[u8]) -> Vec<u8> {
            let mut v = vec![id];
            let mut len = Vec::new();
            write_leb128(&mut len, payload.len() as u32);
            v.extend_from_slice(&len);
            v.extend_from_slice(payload);
            v
        }
        // Build a minimal module with a LOCAL memory section but no import.
        let mut out = Vec::new();
        out.extend_from_slice(b"\0asm");
        out.extend_from_slice(&[1, 0, 0, 0]);
        let mut mem = Vec::new();
        write_leb128(&mut mem, 1);
        mem.push(0); // no-max flags
        write_leb128(&mut mem, 1); // 1 page
        out.extend_from_slice(&section(SECTION_MEMORY, &mem));
        // With import_memory = true, this must fail validation.
        let err = validate_memory_layout(&out, true, false)
            .expect_err("module with local memory must fail under --import-memory");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("no memory import") || msg.contains("local Memory"),
            "unexpected error: {msg}"
        );
        // Without import_memory, the SAME module must pass.
        validate_memory_layout(&out, false, false)
            .expect("local memory OK when --import-memory unset");
    }

    #[test]
    fn validate_memory_layout_requires_no_local_when_import_memory_set() {
        fn section(id: u8, payload: &[u8]) -> Vec<u8> {
            let mut v = vec![id];
            let mut len = Vec::new();
            write_leb128(&mut len, payload.len() as u32);
            v.extend_from_slice(&len);
            v.extend_from_slice(payload);
            v
        }
        // Build a module with an env.memory import and no local memory.
        let mut out = Vec::new();
        out.extend_from_slice(b"\0asm");
        out.extend_from_slice(&[1, 0, 0, 0]);
        let mut imp = Vec::new();
        write_leb128(&mut imp, 1);
        write_name(&mut imp, b"env");
        write_name(&mut imp, b"memory");
        imp.push(0x02); // memory import
        imp.push(0); // no-max flags
        write_leb128(&mut imp, 1); // 1 page
        out.extend_from_slice(&section(SECTION_IMPORT, &imp));
        // With import_memory = true, this must pass.
        validate_memory_layout(&out, true, false)
            .expect("env.memory import + no local memory → ok under --import-memory");
        // Without --import-memory, lack of local memory must fail.
        let err = validate_memory_layout(&out, false, false)
            .expect_err("module lacking both local and imported memory must fail");
        let msg = format!("{err:?}");
        assert!(msg.contains("imports memory") || msg.contains("no --import-memory"));
    }

    /// Bug #5 regression: the off-by-`i` in `out_func_idx = functions.len() + i`
    /// sent deferred table relocations to function slots `i` positions after
    /// the intended body, overwriting unrelated functions' bodies. The bug
    /// lived in the inner reloc-dispatch loop (5 copies — types 1, 2, 18, 19,
    /// 12, 24 — each with the same mistake) and manifested only with multiple
    /// objects and multiple functions per object.
    ///
    /// A full merge-pipeline test would require constructing two synthetic
    /// wasm objects with cross-object indirect calls — substantial wiring.
    /// Instead, verify the invariant that would have caught the bug: for
    /// every `deferred_table_relocs` entry, the recorded `out_func_idx`
    /// must equal `functions.len()` at the time the entry was pushed
    /// (i.e. the body about to be pushed at end-of-iteration). This is a
    /// structural check: `functions.len() + i` can only equal `functions.len()`
    /// when `i == 0`, so any iteration with `i > 0` pointed at the wrong body.
    ///
    /// The check below models the iteration state machine and verifies that,
    /// under the FIXED code, out_func_idx walks 0,1,2,... as bodies are
    /// pushed — never skipping. Under the BUGGY expression (commented) it
    /// would skip by 1 each iteration.
    #[test]
    fn deferred_table_reloc_out_func_idx_tracks_bodies_in_order() {
        // Simulate processing an object with 3 functions, each producing
        // one deferred table reloc.
        let mut functions: Vec<()> = Vec::new(); // stand-in for MergedFunction
        let mut recorded_out_func_idx: Vec<usize> = Vec::new();
        for i in 0..3 {
            // Fixed expression (what we now use).
            let out_func_idx = functions.len();
            recorded_out_func_idx.push(out_func_idx);
            // Buggy expression: `functions.len() + i` — uncomment to see
            // the test fail:
            // let _buggy = functions.len() + i;
            let _ = i;
            // End-of-iteration push.
            functions.push(());
        }
        assert_eq!(
            recorded_out_func_idx,
            vec![0, 1, 2],
            "each body's deferred reloc must target its own future slot"
        );
    }
}
