// Mach-O output file writer.
//
// Uses the common layout pipeline's symbol resolutions and section addresses
// to produce a Mach-O executable for aarch64-apple-darwin.
#![allow(dead_code)]

use crate::error::Result;
use crate::layout::FileLayout;
use crate::layout::Layout;
use crate::layout::ObjectLayout;
use crate::macho::MachO;
use crate::output_section_id;
use crate::platform::Arch;
use crate::platform::Args as _;

const PAGE_SIZE: u64 = 0x4000;
const PAGEZERO_SIZE: u64 = 0x1_0000_0000;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_EXECUTE: u32 = 2;
const MH_BUNDLE: u32 = 8;
const MH_PIE: u32 = 0x0020_0000;
const MH_TWOLEVEL: u32 = 0x80;
const MH_DYLDLINK: u32 = 4;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x8000_0028;
const LC_SYMTAB: u32 = 0x02;
const LC_DYSYMTAB: u32 = 0x0b;
const LC_LOAD_DYLINKER: u32 = 0x0e;
const LC_LOAD_DYLIB: u32 = 0x0c;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const VM_PROT_READ: u32 = 1;
const VM_PROT_WRITE: u32 = 2;
const VM_PROT_EXECUTE: u32 = 4;
const PLATFORM_MACOS: u32 = 1;

const DYLD_PATH: &[u8] = b"/usr/lib/dyld";
const LIBSYSTEM_PATH: &[u8] = b"/usr/lib/libSystem.B.dylib";

pub(crate) fn write_direct<A: Arch<Platform = MachO>>(layout: &Layout<'_, MachO>) -> Result {
    if layout.symbol_db.args.is_relocatable {
        return write_relocatable_object(layout);
    }

    // Collect compact-unwind entries from all input objects.
    let plain_entries = collect_compact_unwind_entries(layout);

    // Find TEXT segment bounds (first non-empty segment).
    // The layout mem_size is content-sized (not page-aligned).  The actual
    // page boundary between TEXT and DATA is align_to(content_end, PAGE_SIZE).
    let (text_base, text_vm_end) = layout
        .segment_layouts
        .segments
        .iter()
        .find(|s| s.sizes.file_size > 0 || s.sizes.mem_size > 0)
        .map(|s| {
            let content_end = s.sizes.mem_offset + s.sizes.mem_size;
            (s.sizes.mem_offset, align_to(content_end, PAGE_SIZE))
        })
        .unwrap_or((PAGEZERO_SIZE, PAGEZERO_SIZE + PAGE_SIZE));

    // Find the end of actual TEXT content (last byte of __eh_frame, or __text).
    // The gap [text_content_end, text_vm_end) is zero padding within the TEXT
    // file allocation — we can place __unwind_info there without extending
    // TEXT vmsize or shifting DATA vmaddr.
    let text_content_end = {
        // Find the end of the last TEXT-segment section:
        // EH_FRAME > GCC_EXCEPT_TABLE > PLT_GOT > TEXT
        let eh = layout.section_layouts.get(output_section_id::EH_FRAME);
        let ge = layout
            .section_layouts
            .get(output_section_id::GCC_EXCEPT_TABLE);
        let plt = layout.section_layouts.get(output_section_id::PLT_GOT);
        let t = layout.section_layouts.get(output_section_id::TEXT);
        if eh.mem_size > 0 {
            eh.mem_offset + eh.mem_size
        } else if ge.mem_size > 0 {
            ge.mem_offset + ge.mem_size
        } else if plt.mem_size > 0 {
            plt.mem_offset + plt.mem_size
        } else {
            t.mem_offset + t.mem_size
        }
    };
    let gap_bytes = text_vm_end.saturating_sub(text_content_end);

    // Decide where to place __unwind_info (4-byte aligned start of gap).
    // The actual content is built inside write_macho after __eh_frame is written,
    // so we only need to know whether there is room and the vm_addr.
    let unwind_info_vm_addr = if plain_entries.is_empty() || gap_bytes == 0 {
        0u64
    } else {
        (text_content_end + 3) & !3u64
    };

    let extra_text = 0u64;

    let (mappings, alloc_size) = build_mappings_and_size(layout, extra_text);
    let mut buf = vec![0u8; alloc_size];
    let final_size = write_macho::<A>(
        &mut buf,
        layout,
        &mappings,
        &plain_entries,
        unwind_info_vm_addr,
        text_base,
        text_vm_end,
        text_content_end,
    )?;
    buf.truncate(final_size);

    if layout.symbol_db.args.print_dependencies {
        print_dependencies(layout);
    }

    if layout.symbol_db.args.common().validate_output {
        validate_macho_output(&buf)?;
    }

    let output_path = layout.symbol_db.args.output();

    std::fs::write(output_path.as_ref(), &buf)
        .map_err(|e| crate::error!("Failed to write: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ =
            std::fs::set_permissions(output_path.as_ref(), std::fs::Permissions::from_mode(0o755));
    }
    #[cfg(target_os = "macos")]
    if !layout.symbol_db.args.no_adhoc_codesign {
        let mut codesign_cmd = std::process::Command::new("codesign");
        codesign_cmd.args(["-s", "-", "--force", "-o", "linker-signed"]);
        // Use -final_output as identifier for reproducible signing
        if let Some(ref fo) = layout.symbol_db.args.final_output {
            codesign_cmd.args(["-i", fo]);
        }
        let status = codesign_cmd.arg(output_path.as_ref()).status();
        if let Ok(s) = &status {
            if !s.success() {
                tracing::warn!("codesign failed with status: {s}");
            }
        }
    }

    // Write dependency info file if requested.
    if let Some(ref dep_path) = layout.symbol_db.args.dependency_info_path {
        write_dependency_info(layout, dep_path)?;
    }

    // Write map file if requested.
    if let Some(ref map_path) = layout.symbol_db.args.map_file {
        write_map_file(layout, map_path)?;
    }

    Ok(())
}

/// Write a dependency info file (binary format) for Xcode build system.
fn print_dependencies(layout: &Layout<'_, MachO>) {
    use crate::layout::FileLayout;
    use object::read::macho::Nlist as _;
    let le = object::Endianness::Little;

    for group in &layout.group_layouts {
        for file_layout in &group.files {
            let FileLayout::Object(obj) = file_layout else { continue };
            let ref_path = obj.input.file.filename.to_string_lossy();

            for sym_idx in 0..obj.object.symbols.len() {
                let Ok(sym) = obj.object.symbols.symbol(object::SymbolIndex(sym_idx)) else {
                    continue;
                };
                // Only undefined external references.
                if !sym.is_undefined() || (sym.n_type() & 0x01) == 0 {
                    continue;
                }
                let Ok(name) = sym.name(le, obj.object.symbols.strings()) else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }

                // Find what defines this symbol.
                let sym_id = obj.symbol_id_range.input_to_id(object::SymbolIndex(sym_idx));
                let def_id = layout.symbol_db.definition(sym_id);

                // Check if defined in a linked object file.
                let mut def_path = String::new();
                // First check if it resolves to a real address (object-defined).
                if let Some(res) = layout.symbol_resolutions.iter().nth(def_id.as_usize()).and_then(|r| r.as_ref()) {
                    if res.raw_value != 0 && !res.flags.contains(crate::value_flags::ValueFlags::DYNAMIC) {
                        let def_file_id = layout.symbol_db.file_id_for_symbol(def_id);
                        'outer: for g in &layout.group_layouts {
                            for fl in &g.files {
                                if let FileLayout::Object(def_obj) = fl {
                                    if def_obj.file_id == def_file_id {
                                        def_path = def_obj.input.file.filename.to_string_lossy().into_owned();
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }
                }
                // If not found in objects, check dylib symbols.
                if def_path.is_empty() {
                    // Check extra_dylibs provenance first.
                    if let Some(&idx) = layout.symbol_db.args.dylib_symbol_provenance.get(name) {
                        if let Some((path, _)) = layout.symbol_db.args.extra_dylibs.get(idx) {
                            def_path = String::from_utf8_lossy(path).into_owned();
                        }
                    }
                    // Fall back to libSystem for known dylib symbols.
                    if def_path.is_empty() && layout.symbol_db.args.dylib_symbols.contains(name) {
                        def_path = "/usr/lib/libSystem.B.dylib".to_string();
                    }
                }

                if !def_path.is_empty() {
                    let name_str = String::from_utf8_lossy(name);
                    println!("{ref_path}\t{def_path}\tu\t{name_str}");
                }
            }
        }
    }
}

fn write_dependency_info(layout: &Layout<'_, MachO>, path: &std::path::Path) -> Result {
    use crate::layout::FileLayout;
    let mut data = Vec::new();

    // Version record: \x00 + linker name
    data.push(0x00);
    data.extend_from_slice(b"Wild");
    data.push(0);

    // Input file records: \x10 + path
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            if let FileLayout::Object(obj) = file_layout {
                data.push(0x10);
                let input_path = obj.input.file.filename.to_string_lossy().into_owned();
                data.extend_from_slice(input_path.as_bytes());
                data.push(0);
            }
        }
    }

    // Output record: \x40 + output path
    data.push(0x40);
    data.extend_from_slice(layout.symbol_db.args.output.to_string_lossy().as_bytes());
    data.push(0);

    std::fs::write(path, &data)
        .map_err(|e| crate::error!("Failed to write dependency info `{}`: {e}", path.display()))?;
    Ok(())
}

/// Write a link map file showing object files, sections, and symbols.
fn write_map_file(layout: &Layout<'_, MachO>, path: &std::path::Path) -> Result {
    use crate::layout::FileLayout;
    use std::io::Write;

    let mut f = std::fs::File::create(path)
        .map_err(|e| crate::error!("Failed to create map file `{}`: {e}", path.display()))?;

    // Object files section
    writeln!(f, "# Object files:").unwrap();
    let mut obj_index = 0usize;
    let mut obj_paths: Vec<String> = Vec::new();
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            if let FileLayout::Object(obj) = file_layout {
                let path_str = std::fs::canonicalize(&obj.input.file.filename)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| obj.input.file.filename.to_string_lossy().into_owned());
                writeln!(f, "[{obj_index:3}] {path_str}").unwrap();
                obj_paths.push(path_str);
                obj_index += 1;
            }
        }
    }

    // Sections — aggregate by (segname, sectname)
    writeln!(f, "\n# Sections:\n# Address\tSize\t\tSegment\tSection").unwrap();
    let le = object::Endianness::Little;
    let mut section_map: std::collections::BTreeMap<(Vec<u8>, Vec<u8>), (u64, u64)> =
        Default::default();
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            if let FileLayout::Object(obj) = file_layout {
                for (sec_idx, _slot) in obj.sections.iter().enumerate() {
                    if let Some(addr) = obj
                        .section_resolutions
                        .get(sec_idx)
                        .and_then(|r| r.address())
                    {
                        if let Some(sec) = obj.object.sections.get(sec_idx) {
                            use object::read::macho::Section as _;
                            let segname = crate::macho::trim_nul(sec.segname()).to_vec();
                            let sectname = crate::macho::trim_nul(sec.sectname()).to_vec();
                            let size = sec.size(le);
                            if size > 0 {
                                let entry = section_map
                                    .entry((segname, sectname))
                                    .or_insert((u64::MAX, 0));
                                entry.0 = entry.0.min(addr);
                                entry.1 += size;
                            }
                        }
                    }
                }
            }
        }
    }
    for ((segname, sectname), (addr, size)) in &section_map {
        let seg = String::from_utf8_lossy(segname);
        let sect = String::from_utf8_lossy(sectname);
        writeln!(f, "0x{addr:08X}     0x{size:08X}      {seg}  {sect}").unwrap();
    }

    // Symbols
    writeln!(f, "\n# Symbols:\n# Address\tSize\t\tFile  Name").unwrap();
    let mut sym_obj_idx = 0usize;
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            if let FileLayout::Object(obj) = file_layout {
                for (sym_idx, res) in layout.symbol_resolutions.iter().enumerate() {
                    let Some(res) = res else { continue };
                    if res.raw_value == 0 {
                        continue;
                    }
                    let symbol_id = crate::symbol_db::SymbolId::from_usize(sym_idx);
                    let file_id = layout.symbol_db.file_id_for_symbol(symbol_id);
                    if file_id != obj.file_id {
                        continue;
                    }
                    let name = match layout.symbol_db.symbol_name(symbol_id) {
                        Ok(n) => n.bytes(),
                        Err(_) => continue,
                    };
                    if name.is_empty() {
                        continue;
                    }
                    let name_str = String::from_utf8_lossy(name);
                    writeln!(
                        f,
                        "0x{:08X}     0x{:08X}      [{sym_obj_idx:3}] {name_str}",
                        res.raw_value, 0
                    )
                    .unwrap();
                }
                sym_obj_idx += 1;
            }
        }
    }

    Ok(())
}

/// Build exactly 2 segment mappings (TEXT + merged DATA) from pipeline layout.
/// `extra_text` extends the TEXT segment (first segment) by that many bytes.
fn build_mappings_and_size(
    layout: &Layout<'_, MachO>,
    extra_text: u64,
) -> (Vec<SegmentMapping>, usize) {
    let mut raw: Vec<(u64, u64, u64)> = Vec::new();
    let mut file_cursor: u64 = 0;
    let mut is_first = true;
    for seg in &layout.segment_layouts.segments {
        if seg.sizes.file_size == 0 && seg.sizes.mem_size == 0 {
            continue;
        }
        let file_off = if raw.is_empty() {
            0
        } else {
            align_to(file_cursor, PAGE_SIZE)
        };
        let extra = if is_first { extra_text } else { 0 };
        is_first = false;
        // extra_text extends the TEXT file allocation (for __unwind_info in the
        // gap) but NOT the vmsize — vmsize is determined by the layout to avoid
        // overlapping with the DATA segment.
        let file_sz = align_to(seg.sizes.file_size as u64 + extra, PAGE_SIZE);
        raw.push((
            seg.sizes.mem_offset,
            seg.sizes.mem_offset + seg.sizes.mem_size,
            file_off,
        ));
        file_cursor = file_off + file_sz;
    }

    let mut mappings = Vec::new();
    if let Some(&(vm_start, vm_end, file_off)) = raw.first() {
        // Extend TEXT mapping to the page boundary so __unwind_info in the
        // gap between content end and page boundary is addressable.
        mappings.push(SegmentMapping {
            vm_start,
            vm_end: align_to(vm_end - vm_start, PAGE_SIZE) + vm_start,
            file_offset: file_off,
        });
    }
    if raw.len() > 1 {
        // Merge all non-TEXT segments into one DATA mapping.
        // Segments may be out of VM order, so use min/max.
        let data_vm_start = raw.iter().skip(1).map(|r| r.0).min().unwrap();
        let data_vm_end = raw.iter().skip(1).map(|r| r.1).max().unwrap();
        let data_file_off = raw.iter().skip(1).map(|r| r.2).min().unwrap();
        mappings.push(SegmentMapping {
            vm_start: data_vm_start,
            vm_end: data_vm_end,
            file_offset: data_file_off,
        });
    }

    // Compute LINKEDIT offset the same way write_headers does:
    // TEXT filesize is page-aligned, DATA filesize is page-aligned from its file_offset.
    let text_filesize = mappings
        .first()
        .map_or(PAGE_SIZE, |m| align_to(m.vm_end - m.vm_start, PAGE_SIZE));
    let linkedit_offset = if mappings.len() > 1 {
        let data_fileoff = mappings[1].file_offset;
        let data_filesize = align_to(
            mappings
                .iter()
                .skip(1)
                .map(|m| m.file_offset + (m.vm_end - m.vm_start))
                .max()
                .unwrap()
                - data_fileoff,
            PAGE_SIZE,
        );
        data_fileoff + data_filesize
    } else {
        text_filesize
    };
    // Estimate LINKEDIT size: chained fixups + symtab + strtab + exports trie.
    // For dylibs with many exports, 8KB is not enough.
    // For executables, we write all defined symbols for backtrace symbolization.
    let n_exports = layout.dynamic_symbol_definitions.len();
    let n_syms = layout
        .symbol_resolutions
        .iter()
        .filter(|r| r.is_some())
        .count();
    // Count stab (debug) symbols for size estimation: 1 N_OSO per object + any
    // existing stabs in input objects.
    let n_stabs = if !layout.symbol_db.args.should_strip_debug() {
        layout
            .group_layouts
            .iter()
            .flat_map(|g| &g.files)
            .filter_map(|f| {
                if let crate::layout::FileLayout::Object(obj) = f {
                    Some(obj)
                } else {
                    None
                }
            })
            .map(|obj| {
                use object::read::macho::Nlist as _;
                let input_stabs = (0..obj.object.symbols.len())
                    .filter(|&i| {
                        obj.object
                            .symbols
                            .symbol(object::SymbolIndex(i))
                            .map(|s| s.n_type() & 0xE0 != 0)
                            .unwrap_or(false)
                    })
                    .count();
                1 + input_stabs // +1 for synthesized N_OSO
            })
            .sum::<usize>()
    } else {
        0
    };
    // Each nlist64 = 16 bytes, Rust mangled symbol names average ~200 bytes.
    // Also account for chained fixups data (page starts, imports, symbol names).
    // Overestimating is cheap (buffer is truncated to actual size); underestimating
    // causes silent data loss and codesign failure.
    let symtab_estimate = (n_syms + n_stabs) * (16 + 200);
    let n_fixups = n_syms;
    let fixups_estimate = 16384 + n_fixups * 12;
    let linkedit_estimate = fixups_estimate + n_exports * 256 + symtab_estimate;
    let total = linkedit_offset as usize + linkedit_estimate.max(65536);
    (mappings, total)
}

/// A rebase fixup: an absolute pointer that needs ASLR adjustment.
struct RebaseFixup {
    file_offset: usize,
    target: u64,
}

/// A bind fixup: a GOT entry that dyld must fill with a dylib symbol address.
struct BindFixup {
    file_offset: usize,
    import_index: u32,
    addend: i64,
}

/// An imported symbol name and its dylib ordinal.
struct ImportEntry {
    name: Vec<u8>,
    /// 1 = libSystem, 2+ = extra dylibs, 0xFE = flat lookup (search all dylibs).
    lib_ordinal: u8,
    /// If true, dyld won't error if this symbol isn't found (weak import).
    weak_import: bool,
}

/// Determine the lib ordinal for a symbol name.
/// If there are extra dylibs (beyond libSystem), we use flat lookup (0xFE)
/// since we don't yet track which dylib exports which symbol.
fn lib_ordinal_for_symbol(has_extra_dylibs: bool, flat_namespace: bool) -> u8 {
    if flat_namespace || has_extra_dylibs {
        0xFE // BIND_SPECIAL_DYLIB_FLAT_LOOKUP
    } else {
        1 // libSystem
    }
}

/// Returns the actual final file size.
fn write_macho<A: Arch<Platform = MachO>>(
    out: &mut [u8],
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
    plain_entries: &[CollectedUnwindEntry],
    unwind_info_vm_addr: u64,
    text_base: u64,
    text_vm_end: u64,
    text_content_end: u64,
) -> Result<usize> {
    let le = object::Endianness::Little;
    let header_layout = layout.section_layouts.get(output_section_id::FILE_HEADER);

    // Collect fixups during section writing and stub generation
    let mut rebase_fixups: Vec<RebaseFixup> = Vec::new();
    let mut bind_fixups: Vec<BindFixup> = Vec::new();
    let mut imports: Vec<ImportEntry> = Vec::new();
    let has_extra_dylibs = !layout.symbol_db.args.extra_dylibs.is_empty();

    // Track section write ranges for overlap detection (validation only).
    let validate = layout.symbol_db.args.common().validate_output;
    let mut write_ranges: Vec<(usize, usize, String)> = Vec::new();

    // Copy section data and apply relocations
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            if let FileLayout::Object(obj) = file_layout {
                write_object_sections(
                    out,
                    obj,
                    layout,
                    mappings,
                    le,
                    &mut rebase_fixups,
                    &mut bind_fixups,
                    &mut imports,
                    has_extra_dylibs,
                    if validate {
                        Some(&mut write_ranges)
                    } else {
                        None
                    },
                )?;
            }
        }
    }

    // Write deduplicated merged strings (e.g. __cstring) into the output.
    write_merged_strings_macho(out, layout, mappings);

    // Validate: no two section data writes should overlap.
    if validate && !write_ranges.is_empty() {
        write_ranges.sort_by_key(|r| r.0);
        for w in write_ranges.windows(2) {
            let (off1, size1, ref name1) = w[0];
            let (off2, _size2, ref name2) = w[1];
            if off1 + size1 > off2 {
                crate::bail!(
                    "validate: section data write overlap: \
                     {name1} [{off1:#x}..{:#x}) and {name2} [{off2:#x}..)",
                    off1 + size1
                );
            }
        }
    }

    // Write PLT stubs and collect bind fixups for imported symbols
    write_stubs_and_got::<A>(
        out,
        layout,
        mappings,
        &mut bind_fixups,
        &mut imports,
        has_extra_dylibs,
    )?;

    // Populate GOT entries for non-import symbols
    write_got_entries(
        out,
        layout,
        mappings,
        &mut rebase_fixups,
        &mut bind_fixups,
        &mut imports,
        has_extra_dylibs,
    )?;

    // Build chained fixup data: merge rebase + bind, encode per-page chains.
    //
    // Filter out fixups that fall on __thread_vars `key` or `offset` fields.
    // TLV descriptors are 24-byte structs: (init_ptr, key, offset).
    // Only `init` (at offset 0 of each descriptor) should have a fixup (bind to
    // __tlv_bootstrap). The `key` (offset 8) and `offset` (offset 16) fields are
    // plain values that dyld manages — they must NOT be in the fixup chain.
    // Find __thread_vars key/offset field file offsets to exclude from
    // the fixup chain. TLV descriptors are 24 bytes: only the init pointer
    // (byte 0) should have a fixup. The key (byte 8) and offset (byte 16)
    // are plain values that must not be in the chain.
    //
    // We find the thread_vars address range by scanning all bind+rebase
    // fixups: every fixup at a position that's (n*24 + 8) or (n*24 + 16)
    // relative to the first __tlv_bootstrap bind is a key/offset field.
    //
    // Simpler approach: collect ALL fixup file offsets that target TDATA
    // or TBSS addresses (these are the TLV offset fields whose values
    // were correctly computed by apply_relocations). They should NOT have
    // rebase fixups because we wrote TLS-relative offsets, not absolute
    // addresses. However, the non-extern relocation path may have created
    // rebase fixups anyway. Remove them.
    // Build set of file offsets for __thread_vars key/offset fields.
    // These must NOT be in the fixup chain. We identify them by scanning
    // the output for the bind fixups we already created for __tlv_bootstrap
    // and init-function pointers — every such fixup marks the start of a
    // 24-byte TLV descriptor. The key (+8) and offset (+16) fields after
    // each descriptor start must be excluded.
    let tvars_key_offset_positions: std::collections::HashSet<usize> = {
        let mut positions = std::collections::HashSet::new();
        // Every fixup (bind or rebase) that's at a 24-byte-aligned position
        // within the thread_vars output IS a descriptor start.
        // But we don't know exactly where tvars is in the output.
        // Use a different approach: find ALL fixups in the DATA segment,
        // and for each one, check if the 8 bytes before it are also a fixup
        // (which would make this a key field after an init fixup) or if
        // 16 bytes before is a fixup (making this an offset field).
        //
        // Actually simplest: find tvars range from the bind fixups for
        // __tlv_bootstrap. The first and last such bind define the range.
        let mut tvars_start = usize::MAX;
        let mut tvars_end = 0usize;
        for f in &bind_fixups {
            if let Some(imp) = imports.get(f.import_index as usize) {
                if imp.name == b"__tlv_bootstrap" {
                    tvars_start = tvars_start.min(f.file_offset);
                    tvars_end = tvars_end.max(f.file_offset + 24); // descriptor size
                }
            }
        }
        // Also scan rebase fixups that target init functions (which are in
        // __thread_data/__thread_bss). These are at descriptor +0 too.
        // A rebase targeting TDATA/TBSS means it's a TLS offset value (written
        // by apply_relocations). But init-function rebase fixups target TEXT.
        // To catch all descriptors, extend the range to cover all rebase fixups
        // between the first and last __tlv_bootstrap binds.
        // Actually, the tvars section is contiguous. Extend by scanning:
        // starting from the first __tlv_bootstrap bind, every 24 bytes is a
        // descriptor until we run out.
        if tvars_start != usize::MAX {
            // Find the total tvars block: from the first bind, walk forward
            // checking if there's a fixup or data at each 24-byte boundary.
            // The block size = (number of descriptors) * 24.
            // We know from bind_fixups how many __tlv_bootstrap entries there are,
            // but some descriptors have rebase inits instead. Use the DATA output
            // section's thread_vars content size.
            // The simplest: compute from the input objects.
            let le = object::Endianness::Little;
            let mut total_tvars_size = 0usize;
            for group in &layout.group_layouts {
                for file_layout in &group.files {
                    if let FileLayout::Object(obj) = file_layout {
                        for sec_idx in 0..obj.object.sections.len() {
                            if let Some(s) = obj.object.sections.get(sec_idx) {
                                use object::read::macho::Section as _;
                                if s.flags(le) & 0xFF == 0x13 {
                                    total_tvars_size += s.size(le) as usize;
                                }
                            }
                        }
                    }
                }
            }
            tvars_end = tvars_start + total_tvars_size;
        }

        if tvars_start != usize::MAX {
            for off in (tvars_start..tvars_end).step_by(24) {
                positions.insert(off + 8); // key field
                positions.insert(off + 16); // offset field
            }
        }
        positions
    };

    rebase_fixups.sort_by_key(|f| f.file_offset);
    bind_fixups.sort_by_key(|f| f.file_offset);

    // Zero out __thread_vars key fields. Key must always be 0 — dyld
    // initializes it at runtime with a pthread key. Relocation application
    // may have written garbage into key positions from non-extern relocations.
    // Key is at offset +8 in each 24-byte descriptor.
    // tvars_key_offset_positions contains both key (+8) and offset (+16) positions.
    // Key positions: those that are 8 bytes before an offset position.
    for &pos in &tvars_key_offset_positions {
        // Check if pos+8 is also in the set (making this a key field)
        if tvars_key_offset_positions.contains(&(pos + 8)) && pos + 8 <= out.len() {
            out[pos..pos + 8].fill(0);
        }
    }

    let data_seg_start = if mappings.len() > 1 {
        mappings[1].file_offset as usize
    } else {
        usize::MAX
    };
    let data_seg_end = if mappings.len() > 1 {
        mappings[1].file_offset as usize + (mappings[1].vm_end - mappings[1].vm_start) as usize
    } else {
        0
    };

    let image_base = if layout.symbol_db.args.is_dylib {
        0u64
    } else {
        PAGEZERO_SIZE
    };
    let mut all_data_fixups: Vec<(usize, u64)> = Vec::new();
    for f in &rebase_fixups {
        if f.file_offset < data_seg_start || f.file_offset >= data_seg_end {
            continue;
        }
        if tvars_key_offset_positions.contains(&f.file_offset) {
            continue;
        }
        let target_offset = f.target.wrapping_sub(image_base);
        all_data_fixups.push((f.file_offset, target_offset & 0xF_FFFF_FFFF));
    }
    for f in &bind_fixups {
        if f.file_offset < data_seg_start || f.file_offset >= data_seg_end {
            continue;
        }
        // Don't filter bind fixups for __thread_vars init pointers —
        // those ARE legitimate (bind to __tlv_bootstrap).
        // Only filter rebase fixups for key/offset fields.
        // When using DYLD_CHAINED_IMPORT_ADDEND format, addend is in the
        // import table, not in the pointer. Only encode 8-bit inline addend
        // for format 1.
        let encoded = (1u64 << 63) | (f.import_index as u64 & 0xFF_FFFF);
        all_data_fixups.push((f.file_offset, encoded));
    }
    all_data_fixups.sort_by_key(|&(off, _)| off);

    // Encode per-page chains
    let data_seg_file_off = if mappings.len() > 1 {
        mappings[1].file_offset
    } else {
        0
    };
    for i in 0..all_data_fixups.len() {
        let (file_off, mut encoded) = all_data_fixups[i];
        let next_stride = if i + 1 < all_data_fixups.len() {
            let cur_page = (file_off as u64 - data_seg_file_off) / PAGE_SIZE;
            let next_page = (all_data_fixups[i + 1].0 as u64 - data_seg_file_off) / PAGE_SIZE;
            if cur_page == next_page {
                ((all_data_fixups[i + 1].0 - file_off) / 4) as u64
            } else {
                0
            }
        } else {
            0
        };

        // Both bind and rebase use bits 51-62 for next (12 bits, 4-byte stride)
        encoded |= (next_stride & 0xFFF) << 51;
        if file_off + 8 <= out.len() {
            out[file_off..file_off + 8].copy_from_slice(&encoded.to_le_bytes());
        }
    }

    let has_fixups = !all_data_fixups.is_empty();
    let n_imports = imports.len() as u32;

    // Build symbol name pool for imports
    let mut symbols_pool = vec![0u8];
    let mut import_name_offsets: Vec<u32> = Vec::new();
    for entry in &imports {
        import_name_offsets.push(symbols_pool.len() as u32);
        symbols_pool.extend_from_slice(&entry.name);
        symbols_pool.push(0);
    }

    // Compute chained fixups data size
    let has_data = mappings.len() > 1 && (mappings[1].vm_end > mappings[1].vm_start);
    let is_dylib = layout.symbol_db.args.is_dylib;
    let base_segs = if is_dylib { 2u32 } else { 3u32 }; // TEXT+LINKEDIT or PAGEZERO+TEXT+LINKEDIT
    let seg_count = if has_data { base_segs + 1 } else { base_segs };
    let starts_in_image_size = 4 + 4 * seg_count;
    let page_count = if has_fixups && has_data {
        let data_mem_size = mappings[1].vm_end - mappings[1].vm_start;
        ((data_mem_size + PAGE_SIZE - 1) / PAGE_SIZE) as u32
    } else {
        0
    };

    let has_addends = bind_fixups.iter().any(|f| f.addend != 0);
    let needs_64bit_addend =
        bind_fixups.iter().any(|f| f.addend > i32::MAX as i64 || f.addend < i32::MIN as i64);
    let import_entry_size = if needs_64bit_addend {
        16u32 // format 3: 8 (import64) + 8 (addend64)
    } else if has_addends {
        8u32 // format 2: 4 (import32) + 4 (addend32)
    } else {
        4u32 // format 1: 4 (import32)
    };
    let cf_data_size = if !has_fixups {
        (32 + 4 + 4 * seg_count + 8).max(48)
    } else {
        let seg_starts_size = 22 + 2 * page_count;
        let imports_size = import_entry_size * n_imports;
        32 + starts_in_image_size + seg_starts_size + imports_size + symbols_pool.len() as u32
    };

    // Build and write __unwind_info now that __eh_frame is in the output buffer.
    // Scan output __eh_frame to map func_vm_addr → EhFrameFdeInfo.
    let unwind_info_size = if unwind_info_vm_addr != 0 {
        let eh_layout = layout.section_layouts.get(output_section_id::EH_FRAME);
        let fde_map: std::collections::HashMap<u64, EhFrameFdeInfo> = if eh_layout.mem_size > 0 {
            if let Some(eh_foff) = vm_addr_to_file_offset(eh_layout.mem_offset, mappings) {
                let m = scan_eh_frame_fde_offsets(
                    out,
                    eh_layout.mem_offset,
                    eh_foff,
                    eh_layout.mem_size as usize,
                );
                m
            } else {
                Default::default()
            }
        } else {
            Default::default()
        };
        let available = text_vm_end.saturating_sub(unwind_info_vm_addr);
        let content = build_unwind_info_section(plain_entries, &fde_map, text_base, available);
        if !content.is_empty() && content.len() as u64 <= available {
            if let Some(ui_foff) = vm_addr_to_file_offset(unwind_info_vm_addr, mappings) {
                let end = ui_foff + content.len();
                if end <= out.len() {
                    out[ui_foff..end].copy_from_slice(&content);
                }
            }
            content.len() as u64
        } else {
            if !content.is_empty() {
                tracing::debug!(
                    "compact_unwind: __unwind_info too large ({} bytes) for gap ({} bytes)",
                    content.len(),
                    available
                );
            }
            0
        }
    } else {
        0
    };

    // Write -sectcreate data into the TEXT segment gap (after __unwind_info).
    let mut sectcreate_placements: Vec<([u8; 16], [u8; 16], u64, u64)> = Vec::new();
    {
        let mut cursor = if unwind_info_size > 0 {
            unwind_info_vm_addr + unwind_info_size
        } else {
            text_content_end
        };
        for (segname, sectname, data) in &layout.symbol_db.args.sectcreate {
            if data.is_empty() {
                continue;
            }
            let vm_addr = cursor;
            let size = data.len() as u64;
            if vm_addr + size <= text_vm_end {
                if let Some(foff) = vm_addr_to_file_offset(vm_addr, mappings) {
                    let end = foff + data.len();
                    if end <= out.len() {
                        out[foff..end].copy_from_slice(data);
                    }
                }
            }
            sectcreate_placements.push((*segname, *sectname, vm_addr, size));
            cursor = vm_addr + size;
        }
    }

    // Build __init_offsets: convert __mod_init_func pointers to TEXT-relative u32 offsets.
    let mut init_offsets_vm_addr = 0u64;
    let mut init_offsets_size = 0u64;
    if layout.symbol_db.args.use_init_offsets {
        let init_layout = layout.section_layouts.get(output_section_id::INIT_ARRAY);
        if init_layout.mem_size > 0 {
            let n_ptrs = init_layout.mem_size / 8;
            let offsets_byte_size = n_ptrs * 4;
            // Place after sectcreate data (or unwind_info, or text_content_end).
            let mut cursor = if !sectcreate_placements.is_empty() {
                let last = sectcreate_placements.last().unwrap();
                last.2 + last.3 // vm_addr + size
            } else if unwind_info_size > 0 {
                unwind_info_vm_addr + unwind_info_size
            } else {
                text_content_end
            };
            cursor = (cursor + 3) & !3; // 4-byte align
            init_offsets_vm_addr = cursor;
            init_offsets_size = offsets_byte_size;

            if let (Some(init_foff), Some(out_foff)) = (
                vm_addr_to_file_offset(init_layout.mem_offset, mappings),
                vm_addr_to_file_offset(init_offsets_vm_addr, mappings),
            ) {
                for i in 0..n_ptrs as usize {
                    let ptr_off = init_foff + i * 8;
                    if ptr_off + 8 <= out.len() {
                        let ptr_val =
                            u64::from_le_bytes(out[ptr_off..ptr_off + 8].try_into().unwrap());
                        let offset = ptr_val.wrapping_sub(text_base) as u32;
                        let dst = out_foff + i * 4;
                        if dst + 4 <= out.len() {
                            out[dst..dst + 4].copy_from_slice(&offset.to_le_bytes());
                        }
                    }
                }
            }
        }
    }

    // Write headers
    let header_offset = header_layout.file_offset;
    let chained_fixups_offset = write_headers(
        out,
        header_offset,
        layout,
        mappings,
        cf_data_size,
        unwind_info_vm_addr,
        unwind_info_size,
        &sectcreate_placements,
        init_offsets_vm_addr,
        init_offsets_size,
    )?;

    // Write chained fixups
    let final_size = if let Some(cf_off) = chained_fixups_offset {
        if !has_fixups {
            let cf = cf_off as usize;
            if cf + cf_data_size as usize <= out.len() {
                // Minimal header with correct seg_count and imports_format
                let starts_off = 32u32;
                out[cf + 4..cf + 8].copy_from_slice(&starts_off.to_le_bytes()); // starts_offset
                let imports_off = starts_off + 4 + 4 * seg_count;
                out[cf + 8..cf + 12].copy_from_slice(&imports_off.to_le_bytes()); // imports_offset
                out[cf + 12..cf + 16].copy_from_slice(&imports_off.to_le_bytes()); // symbols_offset
                out[cf + 20..cf + 24].copy_from_slice(&1u32.to_le_bytes()); // imports_format
                let si = cf + starts_off as usize;
                out[si..si + 4].copy_from_slice(&seg_count.to_le_bytes());
            }
            cf + cf_data_size as usize
        } else {
            let ordinals: Vec<u8> = imports.iter().map(|e| e.lib_ordinal).collect();
            let weak_flags: Vec<bool> = imports.iter().map(|e| e.weak_import).collect();
            // Collect per-import addends for DYLD_CHAINED_IMPORT_ADDEND[64].
            let mut import_addends: Vec<i64> = vec![0i64; imports.len()];
            let has_addends = bind_fixups.iter().any(|f| f.addend != 0);
            for f in &bind_fixups {
                if f.addend != 0 && (f.import_index as usize) < import_addends.len() {
                    import_addends[f.import_index as usize] = f.addend;
                }
            }
            write_chained_fixups_header(
                out,
                cf_off as usize,
                &all_data_fixups,
                n_imports,
                &import_name_offsets,
                &ordinals,
                &weak_flags,
                &symbols_pool,
                mappings,
                layout.symbol_db.args.is_dylib,
                if has_addends {
                    Some(&import_addends)
                } else {
                    None
                },
            )?;
            cf_off as usize + cf_data_size as usize
        }
    } else {
        out.len()
    };

    // Write symbol table
    let final_size = if layout.symbol_db.args.is_dylib {
        write_dylib_symtab(out, final_size, layout, mappings)?
    } else {
        write_exe_symtab(out, final_size, layout, mappings)?
    };

    Ok(final_size)
}

/// Write a minimal symbol table for dylib exports.
fn write_dylib_symtab(
    out: &mut [u8],
    start: usize,
    layout: &Layout<'_, MachO>,
    _mappings: &[SegmentMapping],
) -> Result<usize> {
    // Collect exported symbols from dynamic_symbol_definitions
    let mut entries: Vec<(Vec<u8>, u64)> = Vec::new();
    for def in &layout.dynamic_symbol_definitions {
        let sym_id = def.symbol_id;
        if let Some(res) = layout
            .symbol_resolutions
            .iter()
            .nth(sym_id.as_usize())
            .and_then(|r| r.as_ref())
        {
            entries.push((def.name.to_vec(), res.raw_value));
        }
    }

    if entries.is_empty() {
        return Ok(start);
    }

    // Build string table: starts with \0
    let mut strtab = vec![0u8];
    let mut str_offsets = Vec::new();
    for (name, _) in &entries {
        str_offsets.push(strtab.len() as u32);
        strtab.extend_from_slice(name);
        strtab.push(0);
    }

    // Build section ranges from the already-written headers for n_sect lookup.
    let section_ranges = parse_section_ranges(out);

    // Write nlist64 entries (16 bytes each).
    // Align symtab start to 8 bytes (required by ld64 when consuming dylibs).
    let symoff = (start + 7) & !7;
    let nsyms = entries.len();
    let mut pos = symoff;
    for (i, (_, value)) in entries.iter().enumerate() {
        if pos + 16 > out.len() {
            break;
        }
        let n_sect = section_ranges
            .iter()
            .position(|&(s, e)| *value >= s && *value < e)
            .map(|idx| (idx + 1) as u8)
            .unwrap_or(1);
        // nlist64: n_strx (4), n_type (1), n_sect (1), n_desc (2), n_value (8)
        out[pos..pos + 4].copy_from_slice(&str_offsets[i].to_le_bytes());
        out[pos + 4] = 0x0F; // N_SECT | N_EXT
        out[pos + 5] = n_sect;
        out[pos + 6..pos + 8].copy_from_slice(&0u16.to_le_bytes()); // n_desc
        out[pos + 8..pos + 16].copy_from_slice(&value.to_le_bytes());
        pos += 16;
    }

    // Write string table
    let stroff = pos;
    if stroff + strtab.len() <= out.len() {
        out[stroff..stroff + strtab.len()].copy_from_slice(&strtab);
    }
    pos = stroff + strtab.len();

    // Patch LC_SYMTAB in the header
    // Find LC_SYMTAB command and update it
    let mut off = 32u32; // after header
    let ncmds = u32::from_le_bytes(out[16..20].try_into().unwrap());
    for _ in 0..ncmds {
        let cmd = u32::from_le_bytes(out[off as usize..off as usize + 4].try_into().unwrap());
        let cmdsize =
            u32::from_le_bytes(out[off as usize + 4..off as usize + 8].try_into().unwrap());
        if cmd == LC_SYMTAB {
            out[off as usize + 8..off as usize + 12]
                .copy_from_slice(&(symoff as u32).to_le_bytes());
            out[off as usize + 12..off as usize + 16]
                .copy_from_slice(&(nsyms as u32).to_le_bytes());
            out[off as usize + 16..off as usize + 20]
                .copy_from_slice(&(stroff as u32).to_le_bytes());
            out[off as usize + 20..off as usize + 24]
                .copy_from_slice(&(strtab.len() as u32).to_le_bytes());
            break;
        }
        off += cmdsize;
    }

    // Build export trie for dlsym (must be aligned)
    let trie_off = (pos + 7) & !7;
    let trie = build_export_trie(&entries);
    if trie_off + trie.len() <= out.len() {
        out[trie_off..trie_off + trie.len()].copy_from_slice(&trie);
    }
    pos = trie_off + trie.len();

    // Patch LC_SYMTAB and LC_DYLD_EXPORTS_TRIE in headers
    off = 32;
    for _ in 0..ncmds {
        let cmd = u32::from_le_bytes(out[off as usize..off as usize + 4].try_into().unwrap());
        let cmdsize =
            u32::from_le_bytes(out[off as usize + 4..off as usize + 8].try_into().unwrap());
        match cmd {
            0x19 => {
                // LC_SEGMENT_64
                let segname = &out[off as usize + 8..off as usize + 24];
                if segname.starts_with(b"__LINKEDIT") {
                    let linkedit_fileoff = u64::from_le_bytes(
                        out[off as usize + 40..off as usize + 48]
                            .try_into()
                            .unwrap(),
                    );
                    let new_filesize = pos as u64 - linkedit_fileoff;
                    out[off as usize + 48..off as usize + 56]
                        .copy_from_slice(&new_filesize.to_le_bytes());
                    // Update vmsize to cover the content
                    let new_vmsize = align_to(new_filesize, PAGE_SIZE);
                    out[off as usize + 32..off as usize + 40]
                        .copy_from_slice(&new_vmsize.to_le_bytes());
                }
            }
            LC_DYSYMTAB => {
                // DYSYMTAB: ilocalsym nlocalsym iextdefsym nextdefsym iundefsym nundefsym
                let o = off as usize + 8;
                out[o..o + 4].copy_from_slice(&0u32.to_le_bytes()); // ilocalsym
                out[o + 4..o + 8].copy_from_slice(&0u32.to_le_bytes()); // nlocalsym
                out[o + 8..o + 12].copy_from_slice(&0u32.to_le_bytes()); // iextdefsym
                out[o + 12..o + 16].copy_from_slice(&(nsyms as u32).to_le_bytes()); // nextdefsym
                out[o + 16..o + 20].copy_from_slice(&(nsyms as u32).to_le_bytes()); // iundefsym
                out[o + 20..o + 24].copy_from_slice(&0u32.to_le_bytes()); // nundefsym
            }
            0x8000_0033 => {
                // LC_DYLD_EXPORTS_TRIE
                out[off as usize + 8..off as usize + 12]
                    .copy_from_slice(&(trie_off as u32).to_le_bytes());
                out[off as usize + 12..off as usize + 16]
                    .copy_from_slice(&(trie.len() as u32).to_le_bytes());
            }
            _ => {}
        }
        off += cmdsize;
    }

    Ok(pos)
}

/// Parse section address ranges from the already-written Mach-O headers.
/// Returns a vec of (start_addr, end_addr) in section order.
fn parse_section_ranges(out: &[u8]) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let mut hoff = 32usize;
    let ncmds = u32::from_le_bytes(out[16..20].try_into().unwrap_or([0; 4])) as usize;
    for _ in 0..ncmds {
        if hoff + 8 > out.len() {
            break;
        }
        let cmd = u32::from_le_bytes(out[hoff..hoff + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(out[hoff + 4..hoff + 8].try_into().unwrap()) as usize;
        if cmd == LC_SEGMENT_64 && hoff + 72 <= out.len() {
            let nsects = u32::from_le_bytes(out[hoff + 64..hoff + 68].try_into().unwrap()) as usize;
            for j in 0..nsects {
                let so = hoff + 72 + j * 80;
                if so + 48 > out.len() {
                    break;
                }
                let addr = u64::from_le_bytes(out[so + 32..so + 40].try_into().unwrap());
                let size = u64::from_le_bytes(out[so + 40..so + 48].try_into().unwrap());
                ranges.push((addr, addr + size));
            }
        }
        hoff += cmdsize;
    }
    ranges
}

/// Check if a symbol was originally external (N_EXT) in its input object.
fn is_symbol_external(layout: &Layout<'_, MachO>, symbol_id: crate::symbol_db::SymbolId) -> bool {
    use object::read::macho::Nlist as _;
    let file_id = layout.symbol_db.file_id_for_symbol(symbol_id);
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            if let crate::layout::FileLayout::Object(obj) = file_layout {
                if obj.file_id == file_id {
                    let local_index = symbol_id.to_input(obj.symbol_id_range);
                    if let Ok(sym) = obj.object.symbols.symbol(local_index) {
                        return (sym.n_type() & object::macho::N_EXT) != 0;
                    }
                }
            }
        }
    }
    // Default to external for prelude/synthetic symbols
    true
}

/// Write a symbol table for executables so that backtraces can resolve function names.
fn write_exe_symtab(
    out: &mut [u8],
    start: usize,
    layout: &Layout<'_, MachO>,
    _mappings: &[SegmentMapping],
) -> Result<usize> {
    use crate::symbol_db::SymbolId;

    // Synthesize N_OSO stab entries for each input object (for dsymutil/debugger).
    // Skip if -S (strip debug).
    // Stab entries: (name, n_type, n_sect, n_desc, n_value)
    let mut stab_entries: Vec<(Vec<u8>, u8, u8, u16, u64)> = Vec::new();
    if !layout.symbol_db.args.should_strip_debug() {
        for group in &layout.group_layouts {
            for file_layout in &group.files {
                if let crate::layout::FileLayout::Object(obj) = file_layout {
                    let raw_path = obj.input.file.filename.to_string_lossy().into_owned();
                    if raw_path.is_empty() {
                        continue;
                    }
                    // Canonicalize to absolute path for OSO (dsymutil needs this).
                    let mut path = std::fs::canonicalize(&raw_path)
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or(raw_path.clone());
                    // For archive members, append (member_name) for dsymutil.
                    if let Some(ref entry) = obj.input.entry {
                        let member = String::from_utf8_lossy(entry.identifier.as_slice());
                        path = format!("{path}({member})");
                    }
                    // Apply -oso_prefix: strip the prefix from the path.
                    if let Some(ref prefix) = layout.symbol_db.args.oso_prefix {
                        let prefix_expanded = if prefix == "." {
                            std::env::current_dir()
                                .map(|p| p.to_string_lossy().into_owned() + "/")
                                .unwrap_or_default()
                        } else {
                            prefix.clone()
                        };
                        if let Some(stripped) = path.strip_prefix(&prefix_expanded) {
                            path = stripped.to_string();
                        }
                    }
                    // Get mtime of the .o file for the OSO n_value field.
                    let mtime = std::fs::metadata(path.as_str())
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    // Emit SO/OSO/BNSYM/FUN/ENSYM stab sequence for dsymutil.
                    // SO (empty) — start marker
                    stab_entries.push((Vec::new(), 0x64, 0, 0, 0));
                    // SO (dir) + SO (file) — derive from object path.
                    let obj_path = std::path::Path::new(&path);
                    if let Some(dir) = obj_path.parent() {
                        let mut d = dir.to_string_lossy().into_owned();
                        if !d.ends_with('/') { d.push('/'); }
                        stab_entries.push((d.into_bytes(), 0x64, 0, 0, 0));
                    }
                    if let Some(stem) = obj_path.file_name() {
                        stab_entries.push((stem.as_encoded_bytes().to_vec(), 0x64, 0, 0, 0));
                    }
                    // N_OSO (object file path + mtime)
                    stab_entries.push((
                        path.into_bytes(),
                        0x66, // N_OSO
                        0,
                        1, // n_desc=1 (DWARF)
                        mtime,
                    ));
                    // BNSYM/FUN/ENSYM for each defined function.
                    {
                        use object::read::macho::Nlist as _;
                        use object::read::macho::Section as _;
                        let le = object::Endianness::Little;
                        for sym_idx in 0..obj.object.symbols.len() {
                            let Ok(sym) = obj.object.symbols.symbol(object::SymbolIndex(sym_idx))
                            else {
                                continue;
                            };
                            let n_type = sym.n_type();
                            // Copy existing stab symbols from input.
                            if n_type & 0xE0 != 0 {
                                let name = sym
                                    .name(le, obj.object.symbols.strings())
                                    .unwrap_or(&[])
                                    .to_vec();
                                stab_entries.push((name, n_type, sym.n_sect(), sym.n_desc(le), sym.n_value(le)));
                                continue;
                            }
                            // Synthesize FUN stabs for defined external functions in __text.
                            if (n_type & 0x0F) != 0x0F { continue; } // N_SECT | N_EXT
                            let n_sect = sym.n_sect();
                            if n_sect == 0 { continue; }
                            let sec_idx = n_sect as usize - 1;
                            let is_text = obj.object.sections.get(sec_idx)
                                .map(|s| crate::macho::trim_nul(s.sectname()) == b"__text")
                                .unwrap_or(false);
                            if !is_text { continue; }
                            let sym_name = sym.name(le, obj.object.symbols.strings()).unwrap_or(&[]);
                            let sym_id = obj.symbol_id_range.input_to_id(object::SymbolIndex(sym_idx));
                            let Some(res) = layout.merged_symbol_resolution(sym_id) else { continue };
                            if res.raw_value == 0 { continue; }
                            let addr = res.raw_value;
                            // n_sect for stab entries uses output section numbering.
                            // __text is always output section 1.
                            stab_entries.push((Vec::new(), 0x2E, 1, 0, addr)); // BNSYM
                            stab_entries.push((sym_name.to_vec(), 0x24, 1, 0, addr)); // FUN
                            stab_entries.push((Vec::new(), 0x24, 0, 0, 0)); // FUN (end)
                            stab_entries.push((Vec::new(), 0x4E, 1, 0, addr)); // ENSYM
                        }
                    }
                    // SO (empty) — end marker
                    stab_entries.push((Vec::new(), 0x64, 1, 0, 0));
                }
            }
        }
    }

    // Emit N_AST entries for -add_ast_path flags.
    if !layout.symbol_db.args.should_strip_debug() {
        for ast_path in &layout.symbol_db.args.ast_paths {
            stab_entries.push((
                ast_path.as_bytes().to_vec(),
                0x32, // N_AST
                0,
                0,
                0,
            ));
        }
    }

    // Collect all defined symbols with non-zero addresses.
    let mut entries: Vec<(Vec<u8>, u64, u8)> = Vec::new(); // (name, value, n_type)
    let mut seen_names: std::collections::HashSet<Vec<u8>> = Default::default();
    for (sym_idx, res) in layout.symbol_resolutions.iter().enumerate() {
        let Some(res) = res else { continue };
        if res.raw_value == 0 {
            continue;
        }
        if res.flags.contains(crate::value_flags::ValueFlags::DYNAMIC) {
            continue;
        }
        let symbol_id = SymbolId::from_usize(sym_idx);
        let name = match layout.symbol_db.symbol_name(symbol_id) {
            Ok(n) => n.bytes().to_vec(),
            Err(_) => continue,
        };
        if name.is_empty() {
            continue;
        }
        // Check if this symbol is external by looking at its original binding,
        // or if it was promoted via -export_dynamic (EXPORT_DYNAMIC flag).
        let is_external = (!res.flags.is_downgraded_to_local()
            && is_symbol_external(layout, symbol_id))
            || res.flags.needs_export_dynamic();
        // -x: strip local (non-external) symbols from the output
        if layout.symbol_db.args.strip_locals && !is_external {
            continue;
        }
        let n_type = if res.flags.contains(crate::value_flags::ValueFlags::ABSOLUTE) {
            if is_external { 0x03_u8 } else { 0x02_u8 } // N_ABS [| N_EXT]
        } else if is_external {
            0x0f_u8 // N_SECT | N_EXT (external)
        } else {
            0x0e_u8 // N_SECT (local)
        };
        seen_names.insert(name.clone());
        entries.push((name, res.raw_value, n_type));
    }

    // Also collect absolute symbols from input objects that may lack resolutions
    // (e.g. unreferenced .set symbols).
    {
        use object::read::macho::Nlist as _;
        let le = object::Endianness::Little;
        for group in &layout.group_layouts {
            for file_layout in &group.files {
                if let crate::layout::FileLayout::Object(obj) = file_layout {
                    for sym_idx in 0..obj.object.symbols.len() {
                        let Ok(sym) = obj.object.symbols.symbol(object::SymbolIndex(sym_idx))
                        else {
                            continue;
                        };
                        // N_ABS = 0x02, N_EXT = 0x01
                        let n_type_raw = sym.n_type();
                        if (n_type_raw & 0x0e) != 0x02 {
                            continue; // not absolute
                        }
                        let val = sym.n_value(le);
                        if val == 0 {
                            continue;
                        }
                        let name = sym.name(le, obj.object.symbols.strings()).unwrap_or(&[]);
                        if name.is_empty() || seen_names.contains(name) {
                            continue;
                        }
                        seen_names.insert(name.to_vec());
                        entries.push((name.to_vec(), val, 0x02)); // N_ABS
                    }
                }
            }
        }
    }

    // Add -U (dynamic undefined) symbols as N_UNDF | N_EXT in the output.
    for sym_name in &layout.symbol_db.args.dynamic_undefined_symbols {
        if !seen_names.contains(sym_name) {
            seen_names.insert(sym_name.clone());
            entries.push((sym_name.clone(), 0, 0x01)); // N_UNDF | N_EXT
        }
    }

    // Add imported symbols (those with stubs/GOT) as undefined externals.
    // Track which symbols have stubs for the indirect symbol table.
    let mut stub_symbols: Vec<(u64, Vec<u8>)> = Vec::new(); // (plt_addr, name)
    let mut got_symbols: Vec<(u64, Vec<u8>)> = Vec::new(); // (got_addr, name)
    for (sym_idx, res) in layout.symbol_resolutions.iter().enumerate() {
        let Some(res) = res else { continue };
        let has_plt = res.format_specific.plt_address.is_some();
        let has_got = res.format_specific.got_address.is_some();
        if !has_plt && !has_got {
            continue;
        }
        let symbol_id = SymbolId::from_usize(sym_idx);
        let name = match layout.symbol_db.symbol_name(symbol_id) {
            Ok(n) => n.bytes().to_vec(),
            Err(_) => continue,
        };
        if name.is_empty() {
            continue;
        }
        if let Some(plt_addr) = res.format_specific.plt_address {
            stub_symbols.push((plt_addr, name.clone()));
        }
        if let Some(got_addr) = res.format_specific.got_address {
            got_symbols.push((got_addr, name.clone()));
        }
        if !seen_names.contains(&name) {
            seen_names.insert(name.clone());
            entries.push((name, 0, 0x01)); // N_UNDF | N_EXT
        }
    }
    stub_symbols.sort_by_key(|s| s.0);
    got_symbols.sort_by_key(|s| s.0);

    if entries.is_empty() && stab_entries.is_empty() {
        return Ok(start);
    }

    // Sort: locals first, then externals, then undefined; within each group, by address.
    // DYSYMTAB requires this ordering (ilocalsym..iextdefsym..iundefsym).
    entries.sort_by_key(|e| {
        let is_undef = e.1 == 0 && (e.2 & 0x01) != 0 && (e.2 & 0x0e) == 0;
        let is_ext = (e.2 & 0x01) != 0;
        (is_undef, is_ext, e.1)
    });

    // Build string table: starts with \0
    // Stab entries first, then regular entries.
    let mut strtab = vec![0u8];
    let mut stab_str_offsets = Vec::new();
    for (name, _, _, _, _) in &stab_entries {
        if name.is_empty() {
            stab_str_offsets.push(0u32); // empty name points to the leading \0
        } else {
            stab_str_offsets.push(strtab.len() as u32);
            strtab.extend_from_slice(name);
            strtab.push(0);
        }
    }
    let mut str_offsets = Vec::new();
    for (name, _, _) in &entries {
        str_offsets.push(strtab.len() as u32);
        strtab.extend_from_slice(name);
        strtab.push(0);
    }

    // Build section ranges from the already-written headers for n_sect lookup.
    let section_ranges = parse_section_ranges(out);

    // Write nlist64 entries (16 bytes each). No alignment padding —
    // LINKEDIT must be fully packed for strip(1) compatibility.
    // Stab entries come first (they're part of the local symbol range).
    let symoff = start;
    let nsyms = stab_entries.len() + entries.len();
    let mut pos = symoff;

    // Write stab entries
    for (i, (_, n_type, n_sect, n_desc, n_value)) in stab_entries.iter().enumerate() {
        if pos + 16 > out.len() {
            break;
        }
        out[pos..pos + 4].copy_from_slice(&stab_str_offsets[i].to_le_bytes());
        out[pos + 4] = *n_type;
        out[pos + 5] = *n_sect;
        out[pos + 6..pos + 8].copy_from_slice(&n_desc.to_le_bytes());
        out[pos + 8..pos + 16].copy_from_slice(&n_value.to_le_bytes());
        pos += 16;
    }

    // Write regular entries
    for (i, (_, value, n_type)) in entries.iter().enumerate() {
        if pos + 16 > out.len() {
            break;
        }
        let n_sect = if *n_type == 0x02 {
            0u8 // N_ABS
        } else {
            section_ranges
                .iter()
                .position(|&(s, e)| *value >= s && *value < e)
                .map(|idx| (idx + 1) as u8)
                .unwrap_or(0)
        };
        out[pos..pos + 4].copy_from_slice(&str_offsets[i].to_le_bytes());
        out[pos + 4] = *n_type;
        out[pos + 5] = n_sect;
        out[pos + 6..pos + 8].copy_from_slice(&0u16.to_le_bytes());
        out[pos + 8..pos + 16].copy_from_slice(&value.to_le_bytes());
        pos += 16;
    }

    // Build indirect symbol table: maps __stubs and __got entries to nlist indices.
    let nlist_by_name: std::collections::HashMap<&[u8], u32> = entries
        .iter()
        .enumerate()
        .map(|(i, (name, _, _))| (name.as_slice(), (stab_entries.len() + i) as u32))
        .collect();

    let mut indirect_syms: Vec<u32> = Vec::new();
    let stubs_indirect_start = indirect_syms.len() as u32;
    for (_, name) in &stub_symbols {
        let idx = nlist_by_name.get(name.as_slice()).copied().unwrap_or(0);
        indirect_syms.push(idx);
    }
    let got_indirect_start = indirect_syms.len() as u32;
    for (_, name) in &got_symbols {
        let idx = nlist_by_name.get(name.as_slice()).copied().unwrap_or(0);
        indirect_syms.push(idx);
    }

    // Write indirect symbol table before string table (strip expects this order).
    let indirectsymoff = if indirect_syms.is_empty() {
        0
    } else {
        let off = pos;
        for &idx in &indirect_syms {
            if pos + 4 <= out.len() {
                out[pos..pos + 4].copy_from_slice(&idx.to_le_bytes());
            }
            pos += 4;
        }
        off
    };

    // Write string table
    let stroff = pos;
    if stroff + strtab.len() <= out.len() {
        out[stroff..stroff + strtab.len()].copy_from_slice(&strtab);
    }
    pos = stroff + strtab.len();

    // Compute DYSYMTAB symbol ranges.
    let n_stabs = stab_entries.len() as u32;
    let mut n_local = 0u32;
    let mut n_extdef = 0u32;
    let mut n_undef = 0u32;
    for (_, val, ntype) in &entries {
        let is_undef = *val == 0 && (*ntype & 0x01) != 0 && (*ntype & 0x0e) == 0;
        if is_undef {
            n_undef += 1;
        } else if (*ntype & 0x01) != 0 {
            n_extdef += 1;
        } else {
            n_local += 1;
        }
    }
    let ilocalsym = 0u32;
    let nlocalsym = n_stabs + n_local;
    let iextdefsym = nlocalsym;
    let iundefsym = iextdefsym + n_extdef;

    // Patch LC_SYMTAB, LC_DYSYMTAB, section headers, and LINKEDIT segment
    let mut off = 32u32;
    let ncmds = u32::from_le_bytes(out[16..20].try_into().unwrap());
    for _ in 0..ncmds {
        let cmd = u32::from_le_bytes(out[off as usize..off as usize + 4].try_into().unwrap());
        let cmdsize =
            u32::from_le_bytes(out[off as usize + 4..off as usize + 8].try_into().unwrap());
        match cmd {
            LC_SYMTAB => {
                out[off as usize + 8..off as usize + 12]
                    .copy_from_slice(&(symoff as u32).to_le_bytes());
                out[off as usize + 12..off as usize + 16]
                    .copy_from_slice(&(nsyms as u32).to_le_bytes());
                out[off as usize + 16..off as usize + 20]
                    .copy_from_slice(&(stroff as u32).to_le_bytes());
                out[off as usize + 20..off as usize + 24]
                    .copy_from_slice(&(strtab.len() as u32).to_le_bytes());
            }
            0x19 => {
                // LC_SEGMENT_64 — update LINKEDIT filesize/vmsize
                let segname = &out[off as usize + 8..off as usize + 24];
                if segname.starts_with(b"__LINKEDIT") {
                    let linkedit_fileoff = u64::from_le_bytes(
                        out[off as usize + 40..off as usize + 48]
                            .try_into()
                            .unwrap(),
                    );
                    let new_filesize = pos as u64 - linkedit_fileoff;
                    out[off as usize + 48..off as usize + 56]
                        .copy_from_slice(&new_filesize.to_le_bytes());
                    let new_vmsize = align_to(new_filesize, PAGE_SIZE);
                    out[off as usize + 32..off as usize + 40]
                        .copy_from_slice(&new_vmsize.to_le_bytes());
                }
                // Patch reserved1 in __stubs and __got section headers.
                if !indirect_syms.is_empty() {
                    let nsects_off = off as usize + 64;
                    let nsects =
                        u32::from_le_bytes(out[nsects_off..nsects_off + 4].try_into().unwrap());
                    let mut sec_off = off as usize + 72;
                    for _ in 0..nsects {
                        if sec_off + 80 > out.len() {
                            break;
                        }
                        let sectname = &out[sec_off..sec_off + 16];
                        if sectname.starts_with(b"__stubs\0") {
                            out[sec_off + 68..sec_off + 72]
                                .copy_from_slice(&stubs_indirect_start.to_le_bytes());
                        } else if sectname.starts_with(b"__got\0") {
                            out[sec_off + 68..sec_off + 72]
                                .copy_from_slice(&got_indirect_start.to_le_bytes());
                        }
                        sec_off += 80;
                    }
                }
            }
            LC_DYSYMTAB => {
                let o = off as usize + 8;
                out[o..o + 4].copy_from_slice(&ilocalsym.to_le_bytes());
                out[o + 4..o + 8].copy_from_slice(&nlocalsym.to_le_bytes());
                out[o + 8..o + 12].copy_from_slice(&iextdefsym.to_le_bytes());
                out[o + 12..o + 16].copy_from_slice(&n_extdef.to_le_bytes());
                out[o + 16..o + 20].copy_from_slice(&iundefsym.to_le_bytes());
                out[o + 20..o + 24].copy_from_slice(&n_undef.to_le_bytes());
                if !indirect_syms.is_empty() {
                    out[o + 48..o + 52]
                        .copy_from_slice(&(indirectsymoff as u32).to_le_bytes());
                    out[o + 52..o + 56]
                        .copy_from_slice(&(indirect_syms.len() as u32).to_le_bytes());
                }
            }
            LC_DYLD_EXPORTS_TRIE => {
                // Must come right after fixups
                out[off as usize + 8..off as usize + 12]
                    .copy_from_slice(&(start as u32).to_le_bytes());
                out[off as usize + 12..off as usize + 16].copy_from_slice(&0u32.to_le_bytes());
            }
            0x26 | 0x29 => {
                // function_starts, data_in_code: contiguous with symtab (size 0)
                out[off as usize + 8..off as usize + 12]
                    .copy_from_slice(&(symoff as u32).to_le_bytes());
                out[off as usize + 12..off as usize + 16].copy_from_slice(&0u32.to_le_bytes());
            }
            _ => {}
        }
        off += cmdsize;
    }

    Ok(pos)
}

/// Build a Mach-O export trie for the given symbols.
fn build_export_trie(entries: &[(Vec<u8>, u64)]) -> Vec<u8> {
    if entries.is_empty() {
        return vec![0, 0];
    } // empty root

    // Build child nodes first to know their sizes
    let mut children: Vec<Vec<u8>> = Vec::new();
    for (_, addr) in entries {
        let mut node = Vec::new();
        let mut info = Vec::new();
        uleb128_encode(&mut info, 0); // flags: regular
        uleb128_encode(&mut info, *addr);
        uleb128_encode(&mut node, info.len() as u64); // terminal size
        node.extend_from_slice(&info);
        node.push(0); // 0 child edges
        children.push(node);
    }

    // Build edge labels (symbol name bytes + NUL)
    let mut labels: Vec<Vec<u8>> = Vec::new();
    for (name, _) in entries {
        let mut label = Vec::new();
        label.extend_from_slice(name);
        label.push(0);
        labels.push(label);
    }

    // Compute root node size to determine child offsets.
    // Root = terminal_size(1) + edge_count(1) + edges
    // Each edge = label + ULEB128(child_offset)
    // We need to know root size to compute offsets, but offsets depend on their ULEB encoding size.
    // Use two passes: estimate then fix.
    let n = entries.len();
    // Estimate: each offset ULEB is ~2 bytes for typical small tries
    let mut root_size_estimate = 2usize; // terminal_size(0) + edge_count
    for label in &labels {
        root_size_estimate += label.len() + 3; // label + ~3 byte offset
    }

    // Compute exact child offsets from root_size_estimate
    let mut child_offsets = Vec::new();
    let mut off = root_size_estimate;
    for child in &children {
        child_offsets.push(off);
        off += child.len();
    }

    // Now build root with exact offsets
    let mut root = Vec::new();
    root.push(0); // not terminal
    root.push(n as u8); // edge count
    for (i, label) in labels.iter().enumerate() {
        root.extend_from_slice(label);
        uleb128_encode(&mut root, child_offsets[i] as u64);
    }

    // Check if root size matches estimate; if not, recompute
    if root.len() != root_size_estimate {
        let actual_root_size = root.len();
        let delta = actual_root_size as isize - root_size_estimate as isize;
        // Recompute with corrected offsets
        root.clear();
        root.push(0);
        root.push(n as u8);
        for (i, label) in labels.iter().enumerate() {
            root.extend_from_slice(label);
            uleb128_encode(&mut root, (child_offsets[i] as isize + delta) as u64);
        }
    }

    // Assemble trie
    let mut trie = root;
    for child in &children {
        trie.extend_from_slice(child);
    }
    trie
}

fn uleb128_encode(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

/// Write PLT stubs and GOT bind entries for imported symbols.
fn write_stubs_and_got<A: Arch<Platform = MachO>>(
    out: &mut [u8],
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
    bind_fixups: &mut Vec<BindFixup>,
    imports: &mut Vec<ImportEntry>,
    has_extra_dylibs: bool,
) -> Result {
    use crate::symbol_db::SymbolId;

    for (sym_idx, res) in layout.symbol_resolutions.iter().enumerate() {
        let Some(res) = res else { continue };
        let Some(plt_addr) = res.format_specific.plt_address else {
            continue;
        };
        let Some(got_addr) = res.format_specific.got_address else {
            continue;
        };

        let symbol_id = SymbolId::from_usize(sym_idx);
        let name = match layout.symbol_db.symbol_name(symbol_id) {
            Ok(n) => n.bytes().to_vec(),
            Err(_) => b"<unknown>".to_vec(),
        };
        let is_objc_stub = name.starts_with(b"_objc_msgSend$");

        if is_objc_stub {
            // ObjC stubs: the 12-byte stub calls _objc_msgSend via GOT.
            // The selector isn't loaded in x1 (runtime does it via selref).
            // For now, just bind to _objc_msgSend — a full implementation
            // would synthesize 32-byte stubs with selector loading.
        }

        if let Some(plt_file_off) = vm_addr_to_file_offset(plt_addr, mappings) {
            if plt_file_off + 12 <= out.len() {
                A::write_plt_entry(
                    &mut out[plt_file_off..plt_file_off + 12],
                    got_addr,
                    plt_addr,
                )?;
            }
        }

        if let Some(got_file_off) = vm_addr_to_file_offset(got_addr, mappings) {
            let import_index = imports.len() as u32;
            // For ObjC stubs, bind the GOT entry to _objc_msgSend.
            let import_name = if is_objc_stub {
                b"_objc_msgSend".to_vec()
            } else {
                name.clone()
            };
            let weak = if is_objc_stub { false } else { layout.symbol_db.is_weak_ref(symbol_id) };
            imports.push(ImportEntry {
                name: import_name,
                lib_ordinal: lib_ordinal_for_symbol(has_extra_dylibs, layout.symbol_db.args.flat_namespace),
                weak_import: weak,
            });
            bind_fixups.push(BindFixup {
                file_offset: got_file_off,
                import_index,
                addend: 0,
            });
        }
    }
    Ok(())
}

/// Write a 32-byte ObjC msgSend stub:
///   adrp x1, selref@PAGE
///   ldr  x1, [x1, selref@PAGEOFF]
///   adrp x16, msgSend_got@PAGE
///   ldr  x16, [x16, msgSend_got@PAGEOFF]
///   br   x16
///   brk  #1 (x3 padding)
fn write_objc_stub(buf: &mut [u8], selref_addr: u64, msgsend_got_addr: u64, stub_addr: u64) {
    // adrp x1, selref@PAGE
    let stub_page = stub_addr & !0xFFF;
    let sel_page = selref_addr & !0xFFF;
    let sel_delta = sel_page.wrapping_sub(stub_page) as i64 >> 12;
    let immlo = ((sel_delta & 0x3) as u32) << 29;
    let immhi = (((sel_delta >> 2) & 0x7_FFFF) as u32) << 5;
    let adrp1 = 0x9000_0001u32 | immhi | immlo; // adrp x1
    buf[0..4].copy_from_slice(&adrp1.to_le_bytes());

    // ldr x1, [x1, selref@PAGEOFF]
    let sel_off = ((selref_addr & 0xFFF) >> 3) as u32;
    let ldr1 = 0xF940_0021u32 | (sel_off << 10);
    buf[4..8].copy_from_slice(&ldr1.to_le_bytes());

    // adrp x16, msgSend_got@PAGE
    let got_page = msgsend_got_addr & !0xFFF;
    let got_delta = got_page.wrapping_sub((stub_addr + 8) & !0xFFF) as i64 >> 12;
    let immlo2 = ((got_delta & 0x3) as u32) << 29;
    let immhi2 = (((got_delta >> 2) & 0x7_FFFF) as u32) << 5;
    let adrp2 = 0x9000_0010u32 | immhi2 | immlo2; // adrp x16
    buf[8..12].copy_from_slice(&adrp2.to_le_bytes());

    // ldr x16, [x16, msgSend_got@PAGEOFF]
    let got_off = ((msgsend_got_addr & 0xFFF) >> 3) as u32;
    let ldr2 = 0xF940_0210u32 | (got_off << 10);
    buf[12..16].copy_from_slice(&ldr2.to_le_bytes());

    // br x16
    buf[16..20].copy_from_slice(&0xD61F_0200u32.to_le_bytes());

    // Padding with brk #1
    for i in (20..32).step_by(4) {
        buf[i..i + 4].copy_from_slice(&0xD420_0020u32.to_le_bytes());
    }
}

/// Fill GOT entries with target symbol addresses (for non-import symbols).
/// Also registers rebase fixups so dyld can adjust for ASLR.
fn write_got_entries(
    out: &mut [u8],
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
    rebase_fixups: &mut Vec<RebaseFixup>,
    bind_fixups: &mut Vec<BindFixup>,
    imports: &mut Vec<ImportEntry>,
    has_extra_dylibs: bool,
) -> Result {
    use crate::symbol_db::SymbolId;

    for (sym_idx, res) in layout.symbol_resolutions.iter().enumerate() {
        let Some(res) = res else { continue };
        if res.format_specific.plt_address.is_some() {
            continue;
        } // handled by stubs
        if let Some(got_vm_addr) = res.format_specific.got_address {
            if let Some(file_off) = vm_addr_to_file_offset(got_vm_addr, mappings) {
                if file_off + 8 > out.len() {
                    continue;
                }
                if res.raw_value != 0 {
                    // Defined symbol: write value and create rebase fixup for ASLR.
                    out[file_off..file_off + 8].copy_from_slice(&res.raw_value.to_le_bytes());
                    rebase_fixups.push(RebaseFixup {
                        file_offset: file_off,
                        target: res.raw_value,
                    });
                } else {
                    // Undefined symbol with GOT entry (e.g. personality pointer
                    // from __eh_frame): create a bind fixup so dyld fills the GOT.
                    let symbol_id = SymbolId::from_usize(sym_idx);
                    let name = match layout.symbol_db.symbol_name(symbol_id) {
                        Ok(n) => n.bytes().to_vec(),
                        Err(_) => continue,
                    };
                    let import_index = imports.len() as u32;
                    imports.push(ImportEntry {
                        name,
                        lib_ordinal: lib_ordinal_for_symbol(has_extra_dylibs, layout.symbol_db.args.flat_namespace),
                        weak_import: false,
                    });
                    bind_fixups.push(BindFixup {
                        file_offset: file_off,
                        import_index,
                        addend: 0,
                    });
                }
            }
        }
    }
    Ok(())
}

/// Copy an object's section data to the output and apply relocations.
/// Write __eh_frame data with FDE filtering: only include FDEs whose target
/// function is in a loaded section.
fn write_filtered_eh_frame(
    out: &mut [u8],
    file_offset: usize,
    output_addr: u64,
    input_data: &[u8],
    input_section: &object::macho::Section64<object::Endianness>,
    obj: &ObjectLayout<'_, MachO>,
    layout: &Layout<'_, MachO>,
    le: object::Endianness,
    rebase_fixups: &mut Vec<RebaseFixup>,
    bind_fixups: &mut Vec<BindFixup>,
    imports: &mut Vec<ImportEntry>,
    has_extra_dylibs: bool,
) -> Result {
    use crate::eh_frame::EhFrameEntryPrefix;
    use object::read::macho::Nlist as _;
    use object::read::macho::Section as MachOSection;
    use std::mem::size_of;
    use std::mem::size_of_val;
    use zerocopy::FromBytes;

    let relocs = input_section
        .relocations(le, obj.object.data)
        .unwrap_or(&[]);

    const PREFIX_LEN: usize = size_of::<EhFrameEntryPrefix>();
    let mut input_pos = 0;
    let mut output_pos = 0;
    let mut cie_offset_map = std::collections::HashMap::new();

    // First pass: determine which entries to keep and build a compacted copy.
    while input_pos + PREFIX_LEN <= input_data.len() {
        let prefix =
            EhFrameEntryPrefix::read_from_bytes(&input_data[input_pos..input_pos + PREFIX_LEN])
                .unwrap();
        let size = size_of_val(&prefix.length) + prefix.length as usize;
        let next_input = input_pos + size;
        if next_input > input_data.len() {
            break;
        }

        let keep = if prefix.cie_id == 0 {
            // CIE: always keep
            cie_offset_map.insert(input_pos as u32, output_pos as u32);
            true
        } else {
            // FDE: check if target function section is loaded
            let mut loaded = false;
            for reloc_raw in relocs {
                let reloc = reloc_raw.info(le);
                let r_off = reloc.r_address as usize;
                if r_off >= input_pos && r_off < next_input {
                    let is_pc_begin = (r_off - input_pos) == crate::eh_frame::FDE_PC_BEGIN_OFFSET;
                    if is_pc_begin && reloc.r_extern {
                        let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
                        if let Ok(sym) = obj.object.symbols.symbol(sym_idx) {
                            let n_sect = sym.n_sect();
                            if n_sect > 0 {
                                let sec_idx = n_sect as usize - 1;
                                loaded = obj
                                    .section_resolutions
                                    .get(sec_idx)
                                    .and_then(|r| r.address())
                                    .is_some();
                            }
                        }
                    }
                }
            }
            loaded
        };

        if keep {
            let dest = file_offset + output_pos;
            if dest + size <= out.len() {
                out[dest..dest + size].copy_from_slice(&input_data[input_pos..next_input]);

                // Rewrite CIE pointer in FDEs
                if prefix.cie_id != 0 {
                    let cie_ptr_input = input_pos as u32 + 4;
                    let input_cie = cie_ptr_input.wrapping_sub(prefix.cie_id);
                    if let Some(&output_cie) = cie_offset_map.get(&input_cie) {
                        let new_ptr = output_pos as u32 + 4 - output_cie;
                        let p = dest + 4;
                        if p + 4 <= out.len() {
                            out[p..p + 4].copy_from_slice(&new_ptr.to_le_bytes());
                        }
                    }
                }
            }
            output_pos += size;
        }
        input_pos = next_input;
    }

    // Zero remaining space
    let remaining = file_offset + output_pos;
    let end = file_offset + input_data.len();
    if remaining < end && end <= out.len() {
        out[remaining..end].fill(0);
    }

    // Second pass: apply relocations to the compacted data.
    // Build a mapping from input reloc offsets to output offsets.
    // For simplicity, re-scan entries and apply relocs for kept entries.
    input_pos = 0;
    output_pos = 0;
    let mut cie_map2 = std::collections::HashMap::new();

    while input_pos + PREFIX_LEN <= input_data.len() {
        let prefix =
            EhFrameEntryPrefix::read_from_bytes(&input_data[input_pos..input_pos + PREFIX_LEN])
                .unwrap();
        let size = size_of_val(&prefix.length) + prefix.length as usize;
        let next_input = input_pos + size;
        if next_input > input_data.len() {
            break;
        }

        let keep = if prefix.cie_id == 0 {
            cie_map2.insert(input_pos as u32, output_pos as u32);
            true
        } else {
            let mut loaded = false;
            for reloc_raw in relocs {
                let reloc = reloc_raw.info(le);
                let r_off = reloc.r_address as usize;
                if r_off >= input_pos && r_off < next_input {
                    let is_pc = (r_off - input_pos) == crate::eh_frame::FDE_PC_BEGIN_OFFSET;
                    if is_pc && reloc.r_extern {
                        let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
                        if let Ok(sym) = obj.object.symbols.symbol(sym_idx) {
                            let n = sym.n_sect();
                            if n > 0 {
                                loaded = obj
                                    .section_resolutions
                                    .get(n as usize - 1)
                                    .and_then(|r| r.address())
                                    .is_some();
                            }
                        }
                    }
                }
            }
            loaded
        };

        if keep {
            // Collect relocs for this entry and apply them at their output positions
            let entry_relocs: Vec<_> = relocs
                .iter()
                .filter(|r| {
                    let off = r.info(le).r_address as usize;
                    off >= input_pos && off < next_input
                })
                .collect();

            // Create adjusted relocs with output-relative addresses
            let adjusted: Vec<object::macho::Relocation<object::Endianness>> = entry_relocs
                .iter()
                .map(|r| {
                    let mut copy = **r;
                    let info = r.info(le);
                    let new_addr = info.r_address as usize - input_pos + output_pos;
                    // Reconstruct the raw relocation with adjusted address
                    // The address is in the first 3 bytes of the first u32
                    let _r_word0 = copy.r_word0.get(le);
                    let new_word0 = new_addr as u32;
                    copy.r_word0.set(le, new_word0);
                    copy
                })
                .collect();

            if !adjusted.is_empty() {
                let eh_desc = format!(
                    "{}(__TEXT,__eh_frame)",
                    obj.input.file.filename.display()
                );
                apply_relocations(
                    out,
                    file_offset,
                    output_addr,
                    &adjusted,
                    obj,
                    layout,
                    le,
                    rebase_fixups,
                    bind_fixups,
                    imports,
                    has_extra_dylibs,
                    &eh_desc,
                )?;
            }
            output_pos += size;
        }
        input_pos = next_input;
    }

    Ok(())
}

fn write_object_sections(
    out: &mut [u8],
    obj: &ObjectLayout<'_, MachO>,
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
    le: object::Endianness,
    rebase_fixups: &mut Vec<RebaseFixup>,
    bind_fixups: &mut Vec<BindFixup>,
    imports: &mut Vec<ImportEntry>,
    has_extra_dylibs: bool,
    mut write_ranges: Option<&mut Vec<(usize, usize, String)>>,
) -> Result {
    use object::read::macho::Section as MachOSection;

    // Verify that sections/section_resolutions/object.sections have same length.
    if let Some(ref _ranges) = write_ranges {
        let loaded = obj.sections.len();
        let resolutions = obj.section_resolutions.len();
        let input = obj.object.sections.len();
        if loaded != resolutions || loaded != input {
            crate::bail!(
                "validate: section count mismatch for {}: \
                 loaded={loaded} resolutions={resolutions} input={input}",
                obj.input
            );
        }
    }

    for (sec_idx, _slot) in obj.sections.iter().enumerate() {
        let section_res = &obj.section_resolutions[sec_idx];
        let Some(output_addr) = section_res.address() else {
            continue;
        };
        let Some(file_offset) = vm_addr_to_file_offset(output_addr, mappings) else {
            continue;
        };

        let input_section = match obj.object.sections.get(sec_idx) {
            Some(s) => s,
            None => continue,
        };

        // Log __const section resolutions for debugging
        if let Some(ref _ranges) = write_ranges {
            use object::read::macho::Section as _;
            let sectname = crate::macho::trim_nul(input_section.sectname());
            let segname = crate::macho::trim_nul(&input_section.segname);
            if sectname == b"__const" {
                let input_addr = input_section.addr(le);
                let input_size = input_section.size(le);
                let _ = std::fs::OpenOptions::new().create(true).append(true)
                    .open("/tmp/wild_const_debug.log")
                    .and_then(|mut f| {
                        use std::io::Write;
                        writeln!(f, "sec[{sec_idx}] {},{}: input={input_addr:#x}+{input_size:#x} → output={output_addr:#x} foff={file_offset:#x}",
                            String::from_utf8_lossy(segname), String::from_utf8_lossy(sectname))
                    });
            }
        }

        let sec_type = input_section.flags(le) & 0xFF;
        if sec_type == 0x01 || sec_type == 0x0C || sec_type == 0x12 {
            continue;
        }

        let input_offset = input_section.offset(le) as usize;
        let input_size = input_section.size(le) as usize;
        if input_size == 0 || input_offset == 0 {
            continue;
        }

        let input_data = match obj.object.data.get(input_offset..input_offset + input_size) {
            Some(d) => d,
            None => continue,
        };

        // For __eh_frame: filter FDEs, only keeping those for loaded sections.
        let sectname = crate::macho::trim_nul(input_section.sectname());
        if sectname == b"__eh_frame" {
            write_filtered_eh_frame(
                out,
                file_offset,
                output_addr,
                input_data,
                input_section,
                obj,
                layout,
                le,
                rebase_fixups,
                bind_fixups,
                imports,
                has_extra_dylibs,
            )?;
            continue;
        }

        if file_offset + input_size <= out.len() {
            if let Some(ref mut ranges) = write_ranges {
                let sectname = crate::macho::trim_nul(input_section.sectname());
                let segname = crate::macho::trim_nul(&input_section.segname);
                ranges.push((
                    file_offset,
                    input_size,
                    format!(
                        "{},{}",
                        String::from_utf8_lossy(segname),
                        String::from_utf8_lossy(sectname)
                    ),
                ));

                // Invariant: verify round-trip — after copy, reading the first
                // 8 bytes from the output at the resolved address must match
                // the first 8 bytes of the input section data. If they differ,
                // another section's data was already at that position.
                if input_size >= 8 {
                    let expected = &input_data[..8];
                    let actual = &out[file_offset..file_offset + 8];
                    // Only check if the position was previously zero (fresh)
                    if actual != [0u8; 8] && actual != expected {
                        crate::bail!(
                            "validate: section {},{} at foff={file_offset:#x} — \
                             output already has data {:02x?} but input starts with {:02x?}",
                            String::from_utf8_lossy(segname),
                            String::from_utf8_lossy(sectname),
                            actual,
                            expected
                        );
                    }
                }
            }
            out[file_offset..file_offset + input_size].copy_from_slice(input_data);
        }

        if let Ok(relocs) = input_section.relocations(le, obj.object.data) {
            let segname = crate::macho::trim_nul(&input_section.segname);
            let sectname_trimmed = crate::macho::trim_nul(input_section.sectname());
            let section_desc = format!(
                "{}({},{})",
                obj.input.file.filename.display(),
                String::from_utf8_lossy(segname),
                String::from_utf8_lossy(sectname_trimmed),
            );
            apply_relocations(
                out,
                file_offset,
                output_addr,
                relocs,
                obj,
                layout,
                le,
                rebase_fixups,
                bind_fixups,
                imports,
                has_extra_dylibs,
                &section_desc,
            )?;
        }
    }
    Ok(())
}

/// Apply relocations for a section.
fn apply_relocations(
    out: &mut [u8],
    section_file_offset: usize,
    section_vm_addr: u64,
    relocs: &[object::macho::Relocation<object::Endianness>],
    obj: &ObjectLayout<'_, MachO>,
    layout: &Layout<'_, MachO>,
    le: object::Endianness,
    rebase_fixups: &mut Vec<RebaseFixup>,
    bind_fixups: &mut Vec<BindFixup>,
    imports: &mut Vec<ImportEntry>,
    has_extra_dylibs: bool,
    section_desc: &str,
) -> Result {
    let mut pending_addend: i64 = 0;
    let mut pending_subtrahend: Option<u64> = None;

    for reloc_raw in relocs {
        let reloc = reloc_raw.info(le);

        if reloc.r_type == 10 {
            // ARM64_RELOC_ADDEND
            pending_addend = reloc.r_symbolnum as i64;
            continue;
        }
        if reloc.r_type == 1 {
            // ARM64_RELOC_SUBTRACTOR (part of a pair)
            // Store the subtrahend symbol address for the next UNSIGNED reloc.
            let sub_addr = if reloc.r_extern {
                let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
                let sym_id = obj.symbol_id_range.input_to_id(sym_idx);
                match layout.merged_symbol_resolution(sym_id) {
                    Some(r) if r.raw_value != 0 => r.raw_value,
                    _ => {
                        // Local temp label without a global resolution.
                        // Compute from section base + symbol offset.
                        use object::read::macho::Nlist as _;
                        let sym = obj.object.symbols.symbol(sym_idx).ok();
                        if let Some(sym) = sym {
                            let n_sect = sym.n_sect();
                            if n_sect > 0 {
                                let sec_idx = n_sect as usize - 1;
                                if let Some(sec_out) = obj
                                    .section_resolutions
                                    .get(sec_idx)
                                    .and_then(|r| r.address())
                                {
                                    let sec_in = obj
                                        .object
                                        .sections
                                        .get(sec_idx)
                                        .map(|s| s.addr.get(le))
                                        .unwrap_or(0);
                                    sec_out + sym.n_value(le).wrapping_sub(sec_in)
                                } else if let Ok(Some(addr)) =
                                    crate::string_merging::get_merged_string_output_address::<MachO>(
                                        sym_idx,
                                        0,
                                        &obj.object,
                                        &obj.sections,
                                        &layout.merged_strings,
                                        &layout.merged_string_start_addresses,
                                        false,
                                    )
                                {
                                    addr
                                } else {
                                    0
                                }
                            } else {
                                0
                            }
                        } else {
                            0
                        }
                    }
                }
            } else {
                let sec_ord = reloc.r_symbolnum as usize;
                if sec_ord > 0 {
                    obj.section_resolutions
                        .get(sec_ord - 1)
                        .and_then(|r| r.address())
                        .unwrap_or(0)
                } else {
                    0
                }
            };
            pending_subtrahend = Some(sub_addr);
            continue;
        }

        let addend = pending_addend;
        pending_addend = 0;

        let patch_file_offset = section_file_offset + reloc.r_address as usize;
        let pc_addr = section_vm_addr + reloc.r_address as u64;
        if patch_file_offset + 4 > out.len() {
            continue;
        }

        let (target_addr, got_addr, plt_addr) = if reloc.r_extern {
            let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
            let sym_id = obj.symbol_id_range.input_to_id(sym_idx);
            match layout.merged_symbol_resolution(sym_id) {
                Some(res) if res.raw_value != 0 || res.format_specific.plt_address.is_some() => (
                    res.raw_value,
                    res.format_specific.got_address,
                    res.format_specific.plt_address,
                ),
                other => {
                    // Symbol has no global resolution (or raw_value=0).
                    // Try computing from section base + symbol offset
                    // (handles local labels like GCC_except_table*, ltmp*).
                    use object::read::macho::Nlist as _;
                    let fallback = obj.object.symbols.symbol(sym_idx).ok().and_then(|sym| {
                        let n_sect = sym.n_sect();
                        if n_sect == 0 {
                            // Symbol is undefined (no section). Check if it has a name
                            // that looks like a TLS init symbol.
                            return None;
                        }
                        let sec_idx = n_sect as usize - 1;
                        // Try section_resolutions first.
                        let sec_res_addr = obj
                            .section_resolutions
                            .get(sec_idx)
                            .and_then(|r| r.address());
                        if let Some(sec_out) = sec_res_addr {
                            let sec_in =
                                obj.object.sections.get(sec_idx).map(|s| s.addr.get(le))?;
                            let result = sec_out + sym.n_value(le).wrapping_sub(sec_in);
                            let name = sym.name(le, obj.object.symbols.strings()).unwrap_or(b"");
                            // For TLS init symbols ($tlv$init), compute a TLS-block-
                            // relative offset instead of an absolute address. The TLV
                            // descriptor offset field is read by dyld as an offset into
                            // the thread-local storage template (tdata + tbss).
                            if name.ends_with(b"$tlv$init") {
                                let tdata = layout.section_layouts.get(output_section_id::TDATA);
                                let tdata_start = tdata.mem_offset;
                                let tbss = layout.section_layouts.get(output_section_id::TBSS);
                                use object::read::macho::Section as _;
                                let sec_type = obj
                                    .object
                                    .sections
                                    .get(sec_idx)
                                    .map(|s| s.flags(le) & 0xFF)
                                    .unwrap_or(0);
                                let tls_offset = if sec_type == 0x12 {
                                    // S_THREAD_LOCAL_ZEROFILL: offset = tdata_size + offset_in_tbss
                                    let tbss_start = tbss.mem_offset;
                                    tdata.mem_size + (result - tbss_start)
                                } else {
                                    // S_THREAD_LOCAL_REGULAR: offset = offset_in_tdata
                                    result - tdata_start
                                };
                                return Some(tls_offset);
                            }
                            return Some(result);
                        }
                        // Try merged string resolution (for __cstring etc.)
                        if let Ok(Some(addr)) =
                            crate::string_merging::get_merged_string_output_address::<MachO>(
                                sym_idx,
                                0,
                                &obj.object,
                                &obj.sections,
                                &layout.merged_strings,
                                &layout.merged_string_start_addresses,
                                false,
                            )
                        {
                            return Some(addr);
                        }
                        // Section resolution missing — fall back to TDATA/TBSS for TLS.
                        use object::read::macho::Section as _;
                        let sec_type = obj
                            .object
                            .sections
                            .get(sec_idx)
                            .map(|s| s.flags(le) & 0xFF)?;
                        let sec_in = obj.object.sections.get(sec_idx).map(|s| s.addr.get(le))?;
                        let sym_offset = sym.n_value(le).wrapping_sub(sec_in);
                        let tdata = layout.section_layouts.get(output_section_id::TDATA);
                        let tbss = layout.section_layouts.get(output_section_id::TBSS);
                        match sec_type {
                            0x11 if tdata.mem_size > 0 => {
                                tracing::warn!(
                                    "TLS fallback: tdata + {sym_offset:#x} -> {:#x}",
                                    tdata.mem_offset + sym_offset
                                );
                                Some(tdata.mem_offset + sym_offset)
                            }
                            0x12 if tbss.mem_size > 0 => {
                                tracing::warn!(
                                    "TLS fallback: tbss + {sym_offset:#x} -> {:#x}",
                                    tbss.mem_offset + sym_offset
                                );
                                Some(tbss.mem_offset + sym_offset)
                            }
                            _ => {
                                tracing::warn!("TLS fallback MISS: sec_type={sec_type:#x}");
                                None
                            }
                        }
                    });
                    if let Some(addr) = fallback {
                        let got = other.and_then(|r| r.format_specific.got_address);
                        let plt = other.and_then(|r| r.format_specific.plt_address);
                        (addr, got, plt)
                    } else if let Some(res) = other {
                        (
                            res.raw_value,
                            res.format_specific.got_address,
                            res.format_specific.plt_address,
                        )
                    } else {
                        continue;
                    }
                }
            }
        } else {
            // Non-extern: r_symbolnum is 1-based section ordinal.
            // target = output_section_address + addend
            let sec_ord = reloc.r_symbolnum as usize;
            if sec_ord == 0 {
                continue;
            }
            let sec_idx = sec_ord - 1;
            let output_sec_addr = obj
                .section_resolutions
                .get(sec_idx)
                .and_then(|r| r.address());
            if let Some(addr) = output_sec_addr {
                (addr, None, None)
            } else {
                // Section resolution missing. For TLS sections (__thread_data,
                // __thread_bss), fall back to the TDATA/TBSS output section layout.
                // Read the in-place value to get the symbol's offset within the
                // input section, then compute the output address.
                use object::read::macho::Section as _;
                let input_sec = obj.object.sections.get(sec_idx);
                let sec_type = input_sec.map(|s| s.flags(le) & 0xFF).unwrap_or(0);
                let input_sec_base = input_sec.map(|s| s.addr.get(le)).unwrap_or(0);
                let tdata = layout.section_layouts.get(output_section_id::TDATA);
                let tbss = layout.section_layouts.get(output_section_id::TBSS);
                match sec_type {
                    0x11 if tdata.mem_size > 0 => {
                        // Read in-place addend: absolute input address at reloc position
                        let in_place = if patch_file_offset + 8 <= out.len() {
                            u64::from_le_bytes(
                                out[patch_file_offset..patch_file_offset + 8]
                                    .try_into()
                                    .unwrap_or([0; 8]),
                            )
                        } else {
                            0
                        };
                        let sym_offset = in_place.wrapping_sub(input_sec_base);
                        (tdata.mem_offset + sym_offset, None, None)
                    }
                    0x12 if tbss.mem_size > 0 => {
                        let in_place = if patch_file_offset + 8 <= out.len() {
                            u64::from_le_bytes(
                                out[patch_file_offset..patch_file_offset + 8]
                                    .try_into()
                                    .unwrap_or([0; 8]),
                            )
                        } else {
                            0
                        };
                        let sym_offset = in_place.wrapping_sub(input_sec_base);
                        (tbss.mem_offset + sym_offset, None, None)
                    }
                    // Merged sections: S_CSTRING_LITERALS, S_4BYTE_LITERALS,
                    // S_8BYTE_LITERALS, S_16BYTE_LITERALS
                    0x02 | 0x04 | 0x06 | 0x0E => {
                        if let Some(crate::resolution::SectionSlot::MergeStrings(merge_slot)) =
                            obj.sections.get(sec_idx)
                        {
                            let section_id = merge_slot.part_id.output_section_id();
                            let strings_section = layout.merged_strings.get(section_id);
                            // Read in-place value to get the input address of the string
                            let in_place = if patch_file_offset + 8 <= out.len() {
                                u64::from_le_bytes(
                                    out[patch_file_offset..patch_file_offset + 8]
                                        .try_into()
                                        .unwrap_or([0; 8]),
                                )
                            } else {
                                0
                            };
                            let input_offset = in_place.wrapping_sub(input_sec_base);
                            if let Ok(string_offset) = crate::string_merging::find_string(
                                merge_slot,
                                input_offset,
                                strings_section,
                            ) {
                                let bucket_addrs = layout
                                    .merged_string_start_addresses
                                    .bucket_addresses(section_id);
                                let addr = bucket_addrs[string_offset.bucket()]
                                    + string_offset.offset_in_bucket();
                                (addr, None, None)
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }
                    _ => continue,
                }
            }
        };

        let orig_target_addr = target_addr;
        let target_addr = (target_addr as i64 + addend) as u64;

        match reloc.r_type {
            2 => {
                // ARM64_RELOC_BRANCH26
                let branch_target = plt_addr.unwrap_or(target_addr);
                let offset = branch_target.wrapping_sub(pc_addr) as i64;
                let imm26 = ((offset >> 2) & 0x03FF_FFFF) as u32;
                let insn = read_u32(out, patch_file_offset);
                write_u32_at(out, patch_file_offset, (insn & 0xFC00_0000) | imm26);
            }
            3 => {
                write_adrp(out, patch_file_offset, pc_addr, target_addr);
            }
            4 => {
                write_pageoff12(out, patch_file_offset, target_addr);
            }
            5 => {
                // ARM64_RELOC_GOT_LOAD_PAGE21
                if let Some(got) = got_addr {
                    write_adrp(out, patch_file_offset, pc_addr, got);
                } else {
                    write_adrp(out, patch_file_offset, pc_addr, target_addr);
                }
            }
            6 => {
                // ARM64_RELOC_GOT_LOAD_PAGEOFF12
                if let Some(got) = got_addr {
                    let page_off = (got & 0xFFF) as u32;
                    let insn = read_u32(out, patch_file_offset);
                    let imm12 = (page_off >> 3) & 0xFFF;
                    write_u32_at(out, patch_file_offset, (insn & 0xFFC0_03FF) | (imm12 << 10));
                } else {
                    let page_off = (target_addr & 0xFFF) as u32;
                    let insn = read_u32(out, patch_file_offset);
                    let rd = insn & 0x1F;
                    let rn = (insn >> 5) & 0x1F;
                    write_u32_at(
                        out,
                        patch_file_offset,
                        0x9100_0000 | (page_off << 10) | (rn << 5) | rd,
                    );
                }
            }
            8 | 9 if reloc.r_extern && orig_target_addr != 0 => {
                // ARM64_RELOC_TLVP_LOAD_PAGE21 (8) / ARM64_RELOC_TLVP_LOAD_PAGEOFF12 (9)
                // Check for TLS type mismatch: TLS reloc targeting a non-TLS symbol.
                let tdata = layout.section_layouts.get(output_section_id::TDATA);
                let tbss = layout.section_layouts.get(output_section_id::TBSS);
                let tvars = layout.section_layouts.get(output_section_id::PREINIT_ARRAY);
                let in_tls = (tdata.mem_size > 0
                    && target_addr >= tdata.mem_offset
                    && target_addr < tdata.mem_offset + tdata.mem_size)
                    || (tbss.mem_size > 0
                        && target_addr >= tbss.mem_offset
                        && target_addr < tbss.mem_offset + tbss.mem_size)
                    || (tvars.mem_size > 0
                        && target_addr >= tvars.mem_offset
                        && target_addr < tvars.mem_offset + tvars.mem_size);
                if !in_tls {
                    let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
                    let sym_id = obj.symbol_id_range.input_to_id(sym_idx);
                    let name = layout
                        .symbol_db
                        .symbol_name(sym_id)
                        .map(|n| String::from_utf8_lossy(n.bytes()).into_owned())
                        .unwrap_or_default();
                    crate::bail!(
                        "illegal thread local variable reference to regular symbol `{name}`"
                    );
                }
                if reloc.r_type == 8 {
                    write_adrp(out, patch_file_offset, pc_addr, target_addr);
                } else {
                    // type 9: TLVP_LOAD_PAGEOFF12 -> relax to ADD
                    let page_off = (target_addr & 0xFFF) as u32;
                    let insn = read_u32(out, patch_file_offset);
                    let rd = insn & 0x1F;
                    let rn = (insn >> 5) & 0x1F;
                    write_u32_at(
                        out,
                        patch_file_offset,
                        0x9100_0000 | (page_off << 10) | (rn << 5) | rd,
                    );
                }
            }
            8 => {
                write_adrp(out, patch_file_offset, pc_addr, target_addr);
            }
            9 => {
                // ARM64_RELOC_TLVP_LOAD_PAGEOFF12 -> relax to ADD
                let page_off = (target_addr & 0xFFF) as u32;
                let insn = read_u32(out, patch_file_offset);
                let rd = insn & 0x1F;
                let rn = (insn >> 5) & 0x1F;
                write_u32_at(
                    out,
                    patch_file_offset,
                    0x9100_0000 | (page_off << 10) | (rn << 5) | rd,
                );
            }
            0 if reloc.r_length == 3 => {
                // ARM64_RELOC_UNSIGNED 64-bit.
                // If preceded by a SUBTRACTOR, compute difference:
                //   result = target_addr - subtrahend + existing_content
                if let Some(sub_addr) = pending_subtrahend.take() {
                    if patch_file_offset + 8 <= out.len() {
                        // SUBTRACTOR+UNSIGNED encodes a pcrel difference (e.g. FDE pc_begin,
                        // LSDA pointer). Always use the direct symbol address, never the GOT
                        // address — GOT indirection is expressed via POINTER_TO_GOT (type 7).
                        let existing = i64::from_le_bytes(
                            out[patch_file_offset..patch_file_offset + 8]
                                .try_into()
                                .unwrap(),
                        );
                        let val = target_addr as i64 - sub_addr as i64 + existing;
                        out[patch_file_offset..patch_file_offset + 8]
                            .copy_from_slice(&val.to_le_bytes());
                    }
                } else if patch_file_offset + 8 <= out.len() {
                    if reloc.r_extern && orig_target_addr == 0 {
                        // Extern undefined symbol (e.g. from dylib): bind fixup.
                        // The addend comes from either ARM64_RELOC_ADDEND or
                        // the existing content at the relocation site (implicit addend).
                        let implicit_addend = i64::from_le_bytes(
                            out[patch_file_offset..patch_file_offset + 8]
                                .try_into()
                                .unwrap(),
                        );
                        let bind_addend = if addend != 0 { addend } else { implicit_addend };
                        let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
                        let sym_id = obj.symbol_id_range.input_to_id(sym_idx);
                        let name = match layout.symbol_db.symbol_name(sym_id) {
                            Ok(n) => n.bytes().to_vec(),
                            Err(_) => b"<unknown>".to_vec(),
                        };
                        let import_index = imports.len() as u32;
                        imports.push(ImportEntry {
                            name,
                            lib_ordinal: lib_ordinal_for_symbol(has_extra_dylibs, layout.symbol_db.args.flat_namespace),
                            weak_import: false,
                        });
                        bind_fixups.push(BindFixup {
                            file_offset: patch_file_offset,
                            import_index,
                            addend: bind_addend,
                        });
                    } else {
                        // Check if target is in TLS data — write offset, not rebase
                        let tdata = layout.section_layouts.get(output_section_id::TDATA);
                        let tbss = layout.section_layouts.get(output_section_id::TBSS);
                        let in_tdata = tdata.mem_size > 0
                            && target_addr >= tdata.mem_offset
                            && target_addr < tdata.mem_offset + tdata.mem_size;
                        let in_tbss = tbss.mem_size > 0
                            && target_addr >= tbss.mem_offset
                            && target_addr < tbss.mem_offset + tbss.mem_size;
                        if in_tdata || in_tbss {
                            let tls_init_start = tdata.mem_offset;
                            let tls_init_size = tdata.mem_size;
                            let tls_offset = if in_tbss {
                                tls_init_size + target_addr.saturating_sub(tbss.mem_offset)
                            } else {
                                target_addr.saturating_sub(tls_init_start)
                            };
                            out[patch_file_offset..patch_file_offset + 8]
                                .copy_from_slice(&tls_offset.to_le_bytes());
                        } else {
                            if patch_file_offset % 8 != 0 {
                                crate::bail!(
                                    "{section_desc}: unaligned base relocation"
                                );
                            }
                            rebase_fixups.push(RebaseFixup {
                                file_offset: patch_file_offset,
                                target: target_addr,
                            });
                        }
                    }
                }
            }
            7 if reloc.r_length == 2 && reloc.r_pcrel => {
                // ARM64_RELOC_POINTER_TO_GOT
                if let Some(got) = got_addr {
                    let delta = (got as i64 - pc_addr as i64) as i32;
                    if patch_file_offset + 4 <= out.len() {
                        out[patch_file_offset..patch_file_offset + 4]
                            .copy_from_slice(&delta.to_le_bytes());
                    }
                } else {
                    let delta = (target_addr as i64 - pc_addr as i64) as i32;
                    if patch_file_offset + 4 <= out.len() {
                        out[patch_file_offset..patch_file_offset + 4]
                            .copy_from_slice(&delta.to_le_bytes());
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Write full chained fixups header with imports and symbol names.
fn write_chained_fixups_header(
    out: &mut [u8],
    cf_offset: usize,
    all_fixups: &[(usize, u64)],
    n_imports: u32,
    import_name_offsets: &[u32],
    import_ordinals: &[u8],
    import_weak: &[bool],
    symbols_pool: &[u8],
    mappings: &[SegmentMapping],
    is_dylib: bool,
    import_addends: Option<&[i64]>,
) -> Result {
    let has_data = mappings.len() > 1 && (mappings[1].vm_end > mappings[1].vm_start);
    let base_segs = if is_dylib { 2u32 } else { 3u32 };
    let seg_count = if has_data { base_segs + 1 } else { base_segs };
    let data_seg_idx: usize = if is_dylib { 1 } else { 2 };
    let starts_offset: u32 = 32;
    let starts_in_image_size = 4 + 4 * seg_count as usize;

    let (data_seg_file_offset, page_count) = if mappings.len() > 1 {
        let m = &mappings[1];
        let mem_size = m.vm_end - m.vm_start;
        (
            m.file_offset,
            ((mem_size + PAGE_SIZE - 1) / PAGE_SIZE) as u16,
        )
    } else {
        (0, 0)
    };

    let seg_starts_size = 22 + 2 * page_count as usize;
    let seg_starts_offset_in_image = starts_in_image_size as u32;

    let imports_table_offset = starts_offset + starts_in_image_size as u32 + seg_starts_size as u32;
    // Format 1: no addend (4 bytes). Format 2: 32-bit addend (4+4=8). Format 3: 64-bit addend (4+4+8=16).
    let needs_64bit_addend = import_addends
        .map_or(false, |a| a.iter().any(|v| *v > i32::MAX as i64 || *v < i32::MIN as i64));
    let imports_format = if needs_64bit_addend {
        3u32 // DYLD_CHAINED_IMPORT_ADDEND64
    } else if import_addends.is_some() {
        2u32 // DYLD_CHAINED_IMPORT_ADDEND
    } else {
        1u32 // DYLD_CHAINED_IMPORT
    };
    let import_entry_size: u32 = match imports_format {
        3 => 16, // 4 (import) + 4 (padding) + 8 (addend64) — actually 4+4+8? Let me check
        2 => 8,  // 4 (import) + 4 (addend32)
        _ => 4,  // 4 (import)
    };
    let imports_size = import_entry_size * n_imports;
    let symbols_offset = imports_table_offset + imports_size;

    let w = &mut out[cf_offset..];

    w[0..4].copy_from_slice(&0u32.to_le_bytes());
    w[4..8].copy_from_slice(&starts_offset.to_le_bytes());
    w[8..12].copy_from_slice(&imports_table_offset.to_le_bytes());
    w[12..16].copy_from_slice(&symbols_offset.to_le_bytes());
    w[16..20].copy_from_slice(&n_imports.to_le_bytes());
    w[20..24].copy_from_slice(&imports_format.to_le_bytes());
    w[24..28].copy_from_slice(&0u32.to_le_bytes());

    let si = starts_offset as usize;
    w[si..si + 4].copy_from_slice(&seg_count.to_le_bytes());
    for seg in 0..seg_count as usize {
        let off: u32 = if seg == data_seg_idx {
            seg_starts_offset_in_image
        } else {
            0
        };
        w[si + 4 + seg * 4..si + 4 + seg * 4 + 4].copy_from_slice(&off.to_le_bytes());
    }

    let ss = si + seg_starts_offset_in_image as usize;
    w[ss..ss + 4].copy_from_slice(&(seg_starts_size as u32).to_le_bytes());
    w[ss + 4..ss + 6].copy_from_slice(&(PAGE_SIZE as u16).to_le_bytes());
    w[ss + 6..ss + 8].copy_from_slice(&6u16.to_le_bytes());
    let image_base = if mappings
        .first()
        .map_or(false, |m| m.vm_start >= PAGEZERO_SIZE)
    {
        PAGEZERO_SIZE
    } else {
        0
    };
    let seg_offset_val: u64 = if mappings.len() > 1 {
        mappings[1].vm_start.wrapping_sub(image_base)
    } else {
        0
    };
    w[ss + 8..ss + 16].copy_from_slice(&seg_offset_val.to_le_bytes());
    w[ss + 16..ss + 20].copy_from_slice(&0u32.to_le_bytes());
    w[ss + 20..ss + 22].copy_from_slice(&page_count.to_le_bytes());

    let mut page_starts = vec![0xFFFFu16; page_count as usize];
    for &(file_off, _) in all_fixups {
        if data_seg_file_offset == 0 || (file_off as u64) < data_seg_file_offset {
            continue;
        }
        let offset_in_seg = file_off as u64 - data_seg_file_offset;
        let page_idx = (offset_in_seg / PAGE_SIZE) as usize;
        let offset_in_page = (offset_in_seg % PAGE_SIZE) as u16;
        if page_idx < page_starts.len() && page_starts[page_idx] == 0xFFFF {
            page_starts[page_idx] = offset_in_page;
        }
    }
    for (p, &ps) in page_starts.iter().enumerate() {
        w[ss + 22 + p * 2..ss + 22 + p * 2 + 2].copy_from_slice(&ps.to_le_bytes());
    }

    let it = imports_table_offset as usize;
    let entry_sz = import_entry_size as usize;
    for (i, &name_off) in import_name_offsets.iter().enumerate() {
        let ordinal = import_ordinals[i] as u32;
        let weak_bit = if import_weak.get(i).copied().unwrap_or(false) {
            1u32 << 8
        } else {
            0
        };
        if imports_format == 3 {
            // DYLD_CHAINED_IMPORT_ADDEND64: lib_ordinal:16(signed), weak:1, reserved:15, name_offset:32
            let weak64: u64 = if import_weak.get(i).copied().unwrap_or(false) {
                1u64 << 16
            } else {
                0
            };
            // Ordinal is a signed 16-bit value in format 3 (vs 8-bit in format 1/2).
            // Special ordinals like 0xFE (-2 as i8) must be sign-extended to i16.
            let ordinal16 = (ordinal as i8 as i16 as u16) as u64;
            let import_val: u64 =
                ordinal16 | weak64 | ((name_off as u64 & 0xFFFF_FFFF) << 32);
            w[it + i * entry_sz..it + i * entry_sz + 8]
                .copy_from_slice(&import_val.to_le_bytes());
            let addend = import_addends
                .and_then(|a| a.get(i).copied())
                .unwrap_or(0);
            w[it + i * entry_sz + 8..it + i * entry_sz + 16]
                .copy_from_slice(&addend.to_le_bytes());
        } else {
            let import_val: u32 = ordinal | weak_bit | ((name_off & 0x7F_FFFF) << 9);
            w[it + i * entry_sz..it + i * entry_sz + 4]
                .copy_from_slice(&import_val.to_le_bytes());
            // Format 2: write 32-bit addend after each import entry.
            if let Some(addends) = import_addends {
                let addend = addends.get(i).copied().unwrap_or(0) as i32;
                w[it + i * entry_sz + 4..it + i * entry_sz + 8]
                    .copy_from_slice(&addend.to_le_bytes());
            }
        }
    }

    let sp = symbols_offset as usize;
    if sp + symbols_pool.len() <= w.len() {
        w[sp..sp + symbols_pool.len()].copy_from_slice(symbols_pool);
    }

    Ok(())
}

struct SegmentMapping {
    vm_start: u64,
    vm_end: u64,
    file_offset: u64,
}

/// Write deduplicated merged string data (from __cstring etc.) into the output buffer.
fn write_merged_strings_macho(
    out: &mut [u8],
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
) {
    layout.merged_strings.for_each(|section_id, merged| {
        if merged.len() == 0 {
            return;
        }
        let bucket_addrs = layout
            .merged_string_start_addresses
            .bucket_addresses(section_id);
        for (i, bucket) in merged.buckets.iter().enumerate() {
            let vm_addr = bucket_addrs[i];
            if vm_addr == 0 {
                continue;
            }
            let Some(file_offset) = vm_addr_to_file_offset(vm_addr, mappings) else {
                continue;
            };
            let mut pos = file_offset;
            for string in &bucket.strings {
                let end = pos + string.len();
                if end <= out.len() {
                    out[pos..end].copy_from_slice(string);
                }
                pos = end;
            }
        }
    });
}

fn vm_addr_to_file_offset(vm_addr: u64, mappings: &[SegmentMapping]) -> Option<usize> {
    for m in mappings {
        if vm_addr >= m.vm_start && vm_addr < m.vm_end {
            return Some((m.file_offset + (vm_addr - m.vm_start)) as usize);
        }
    }
    None
}

fn write_adrp(out: &mut [u8], offset: usize, pc: u64, target: u64) {
    let page_off = (target & !0xFFF).wrapping_sub(pc & !0xFFF) as i64;
    let imm = (page_off >> 12) as u32;
    let insn = read_u32(out, offset);
    write_u32_at(
        out,
        offset,
        (insn & 0x9F00_001F) | ((imm & 0x1F_FFFC) << 3) | ((imm & 0x3) << 29),
    );
}

fn write_pageoff12(out: &mut [u8], offset: usize, target: u64) {
    let page_off = (target & 0xFFF) as u32;
    let insn = read_u32(out, offset);
    // Determine the access size shift for scaled load/store instructions.
    // For integer LDR/STR: bits 31:30 encode the size directly.
    // For SIMD/FP LDR/STR (V bit = bit 26): size depends on both
    // bits 31:30 and opc bits 23:22.
    let shift = if (insn & 0x3B00_0000) == 0x3900_0000 {
        let size = (insn >> 30) & 0x3;
        let v = (insn >> 26) & 1;
        let opc = (insn >> 22) & 0x3;
        if v == 1 && opc == 3 && size == 0 {
            4 // 128-bit SIMD (Q register): scale by 16 = 2^4
        } else {
            size
        }
    } else {
        0
    };
    let imm12 = (page_off >> shift) & 0xFFF;
    write_u32_at(out, offset, (insn & 0xFFC0_03FF) | (imm12 << 10));
}

// ── Compact unwind / __unwind_info generation ──────────────────────────────

/// A per-function compact unwind entry collected from `__LD,__compact_unwind`.
struct CollectedUnwindEntry {
    /// Output VM address of the function.
    func_addr: u64,
    /// Function size in bytes.
    func_size: u32,
    /// Compact unwind encoding (ARM64 mode + register mask).
    encoding: u32,
    /// Personality function GOT address (if any).
    personality_got: Option<u64>,
    /// LSDA VM address (if any).
    lsda_addr: Option<u64>,
}

/// Scan all input objects for `__LD,__compact_unwind` sections and collect
/// frame-pointer entries that can be represented directly in `__unwind_info`.
/// Personality entries are handled separately by scanning output `__eh_frame`.
fn collect_compact_unwind_entries(layout: &Layout<'_, MachO>) -> Vec<CollectedUnwindEntry> {
    use object::read::macho::MachHeader as _;
    use object::read::macho::Section as _;
    use object::read::macho::Segment as _;
    let le = object::Endianness::Little;
    let mut entries: Vec<CollectedUnwindEntry> = Vec::new();

    let mut n_objects = 0usize;
    let mut n_cu_entries = 0usize;
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            let FileLayout::Object(obj) = file_layout else {
                continue;
            };
            let _ = n_objects; // suppress unused warning
            n_objects += 1;
            // Parse raw load commands to reach __LD segment (not in obj.object.sections).
            let Ok(header) =
                object::macho::MachHeader64::<object::Endianness>::parse(obj.object.data, 0)
            else {
                continue;
            };
            // Mach-O object files have a single unnamed LC_SEGMENT_64 containing
            // ALL sections. Each section has its own segname field. Iterate all
            // sections of the single segment to find __LD,__compact_unwind.
            let Ok(mut cmds) = header.load_commands(le, obj.object.data, 0) else {
                continue;
            };
            while let Ok(Some(cmd)) = cmds.next() {
                let Ok(Some((seg, seg_data))) = cmd.segment_64() else {
                    continue;
                };
                let Ok(sections) = seg.sections(le, seg_data) else {
                    continue;
                };
                for sec in sections {
                    let sec_segname = crate::macho::trim_nul(&sec.segname);
                    let sectname = crate::macho::trim_nul(&sec.sectname);
                    if sec_segname != b"__LD" || sectname != b"__compact_unwind" {
                        continue;
                    }
                    n_cu_entries += 1;
                    let sec_off = sec.offset.get(le) as usize;
                    let sec_size = sec.size.get(le) as usize;
                    if sec_size == 0 || sec_off == 0 {
                        continue;
                    }
                    let Some(data) = obj.object.data.get(sec_off..sec_off + sec_size) else {
                        continue;
                    };
                    let relocs = sec.relocations(le, obj.object.data).unwrap_or(&[]);
                    let n = sec_size / 32;
                    for i in 0..n {
                        let base = i * 32;
                        if base + 32 > data.len() {
                            break;
                        }
                        let func_size =
                            u32::from_le_bytes(data[base + 8..base + 12].try_into().unwrap());
                        let encoding =
                            u32::from_le_bytes(data[base + 12..base + 16].try_into().unwrap());
                        if encoding == 0 {
                            continue; // no unwind info needed
                        }
                        // DWARF mode → handled via __eh_frame FDE scan, skip here.
                        if (encoding & 0x0F00_0000) == 0x0300_0000 {
                            continue;
                        }
                        let Some(func_addr) =
                            resolve_compact_unwind_addr(obj, layout, le, relocs, base, data)
                        else {
                            continue;
                        };
                        // Extract personality GOT addr (offset 16) and LSDA addr (offset 24)
                        let personality_got =
                            resolve_compact_unwind_got_addr(obj, layout, le, relocs, base + 16);
                        let lsda_addr =
                            resolve_compact_unwind_addr(obj, layout, le, relocs, base + 24, data)
                                .and_then(|addr| if addr != 0 { Some(addr) } else { None });
                        entries.push(CollectedUnwindEntry {
                            func_addr,
                            func_size,
                            encoding,
                            personality_got,
                            lsda_addr,
                        });
                    }
                }
            }
        }
    }

    tracing::debug!(
        "compact_unwind: {} raw entries, {} plain",
        n_cu_entries,
        entries.len()
    );
    entries.sort_by_key(|e| e.func_addr);
    entries.dedup_by_key(|e| e.func_addr);
    entries
}

/// Resolve the VM address stored at `field_offset` within a compact-unwind entry.
/// `field_offset` is the absolute byte offset within the `__compact_unwind` section data.
/// `sec_data` is the raw section bytes (used to read the implicit 8-byte addend for
/// non-extern / section-relative relocations).
fn resolve_compact_unwind_addr(
    obj: &ObjectLayout<'_, MachO>,
    layout: &Layout<'_, MachO>,
    le: object::Endianness,
    relocs: &[object::macho::Relocation<object::Endianness>],
    field_offset: usize,
    sec_data: &[u8],
) -> Option<u64> {
    use object::read::macho::Nlist as _;
    for r in relocs {
        let reloc = r.info(le);
        if reloc.r_address as usize != field_offset {
            continue;
        }
        if reloc.r_extern {
            let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
            let sym_id = obj.symbol_id_range.input_to_id(sym_idx);
            if let Some(res) = layout.merged_symbol_resolution(sym_id) {
                if res.raw_value != 0 {
                    return Some(res.raw_value);
                }
            }
            // Fallback: local symbol (compute from section base + symbol value).
            let sym = obj.object.symbols.symbol(sym_idx).ok()?;
            let n_sect = sym.n_sect();
            if n_sect == 0 {
                return None;
            }
            let sec_idx = n_sect as usize - 1;
            let sec_out = obj.section_resolutions.get(sec_idx)?.address()?;
            let sec_in = obj.object.sections.get(sec_idx).map(|s| s.addr.get(le))?;
            return Some(sec_out + sym.n_value(le).wrapping_sub(sec_in));
        } else {
            // Non-extern (section-relative): r_symbolnum is 1-based section ordinal.
            let sec_ord = reloc.r_symbolnum as usize;
            if sec_ord == 0 {
                return None;
            }
            let sec_idx = sec_ord - 1;
            let sec_out = obj.section_resolutions.get(sec_idx)?.address()?;
            let sec_in = obj.object.sections.get(sec_idx).map(|s| s.addr.get(le))?;
            // Read the 8-byte implicit addend from the field.
            let addend = u64::from_le_bytes(
                sec_data
                    .get(field_offset..field_offset + 8)?
                    .try_into()
                    .ok()?,
            );
            return Some(sec_out + addend.wrapping_sub(sec_in));
        }
    }
    None
}

/// Like resolve_compact_unwind_addr, but returns the GOT address for the symbol
/// (needed for personality pointers in __unwind_info).
fn resolve_compact_unwind_got_addr(
    obj: &ObjectLayout<'_, MachO>,
    layout: &Layout<'_, MachO>,
    le: object::Endianness,
    relocs: &[object::macho::Relocation<object::Endianness>],
    field_offset: usize,
) -> Option<u64> {
    for r in relocs {
        let reloc = r.info(le);
        if reloc.r_address as usize != field_offset {
            continue;
        }
        if reloc.r_extern {
            let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
            let sym_id = obj.symbol_id_range.input_to_id(sym_idx);
            if let Some(res) = layout.merged_symbol_resolution(sym_id) {
                if let Some(got) = res.format_specific.got_address {
                    return Some(got);
                }
                if res.raw_value != 0 {
                    return Some(res.raw_value);
                }
            }
        }
        break;
    }
    None
}

/// Build the binary content of the `__unwind_info` section from collected entries.
/// `text_base` is the VM address of the start of the `__TEXT` segment.
///
/// Produces a version-1 unwind_info with regular second-level pages (kind=2).
/// Info extracted from a `__eh_frame` CIE augmentation string.
#[derive(Default, Clone)]
struct CieAugInfo {
    /// Whether the CIE has a personality function ('P' in augstr).
    has_personality: bool,
    /// VM address of the GOT slot for the personality function, or 0.
    pers_got_vm: u64,
    /// Whether FDEs referencing this CIE carry an LSDA pointer ('L' in augstr).
    has_lsda: bool,
    /// Size of the FDE pc_begin / pc_range fields in bytes (from 'R' enc; 0 = unknown/8).
    fde_ptr_size: u8,
    /// Size of the LSDA pointer in FDE augmentation data (from 'L' enc; 0 = unknown/8).
    lsda_ptr_size: u8,
}

/// Per-FDE info extracted from the output `__eh_frame` buffer.
pub(crate) struct EhFrameFdeInfo {
    /// Byte offset of the FDE within the `__eh_frame` section.
    pub section_offset: u32,
    /// VM address of the LSDA for this function, or 0.
    pub lsda_vm: u64,
    /// VM address of the GOT slot for the personality function, or 0.
    pub pers_got_vm: u64,
}

/// Read a ULEB128 value from `data` at `pos`, advancing `pos`.
fn read_uleb128(data: &[u8], pos: &mut usize) -> u64 {
    let mut val = 0u64;
    let mut shift = 0;
    while *pos < data.len() {
        let b = data[*pos];
        *pos += 1;
        val |= ((b & 0x7F) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
    }
    val
}

/// Determine the byte size of an encoded pointer value from a DW_EH_PE encoding byte.
/// Returns 4 or 8; defaults to 8 (pointer-sized) for unknown formats.
fn eh_ptr_size(enc: u8) -> u8 {
    match enc & 0x0F {
        0x00 => 8, // DW_EH_PE_absptr (pointer-sized = 8 on 64-bit)
        0x02 => 2,
        0x03 => 4, // DW_EH_PE_udata4
        0x04 => 8, // DW_EH_PE_udata8
        0x09 => 2,
        0x0A => 4,
        0x0B => 4, // DW_EH_PE_sdata4
        0x0C => 8, // DW_EH_PE_sdata8
        _ => 8,
    }
}

/// Read a PC-relative signed value of `size` bytes from `data` at `pos`,
/// apply it relative to `field_vm_addr`, and return the target VM address.
fn read_pcrel(data: &[u8], pos: usize, size: usize, field_vm_addr: u64) -> u64 {
    let bytes = match data.get(pos..pos + size) {
        Some(b) => b,
        None => return 0,
    };
    let delta = match size {
        4 => i32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])) as i64,
        8 => i64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])),
        _ => return 0,
    };
    (field_vm_addr as i64 + delta) as u64
}

/// Parse a CIE at section offset `cie_pos` and return its augmentation info.
fn parse_cie_aug(data: &[u8], cie_pos: usize, eh_frame_vm_addr: u64) -> CieAugInfo {
    let mut info = CieAugInfo::default();
    // Skip: length(4) + cie_id(4) + version(1) = 9 bytes.
    let mut pos = cie_pos + 9;
    // Find augmentation string (null-terminated).
    let aug_start = pos;
    while pos < data.len() && data[pos] != 0 {
        pos += 1;
    }
    if pos >= data.len() {
        return info;
    }
    let aug_bytes = &data[aug_start..pos];
    pos += 1; // skip null terminator

    let has_z = aug_bytes.contains(&b'z');
    let has_p = aug_bytes.contains(&b'P');
    let has_l = aug_bytes.contains(&b'L');
    let has_r = aug_bytes.contains(&b'R');
    info.has_lsda = has_l;

    // Skip code_alignment (ULEB128), data_alignment (SLEB128), ra_register (ULEB128).
    read_uleb128(data, &mut pos); // code_alignment
    // SLEB128 (just skip as if ULEB128 since we only care about the byte count)
    loop {
        if pos >= data.len() {
            return info;
        }
        let b = data[pos];
        pos += 1;
        if b & 0x80 == 0 {
            break;
        }
    }
    read_uleb128(data, &mut pos); // ra_register

    if !has_z {
        return info;
    }
    let aug_data_len = read_uleb128(data, &mut pos) as usize;
    let aug_data_start = pos;

    // Augmentation data contains per-letter info in augstr order (skipping 'z').
    let mut ap = aug_data_start;
    for &ch in aug_bytes {
        if ap >= aug_data_start + aug_data_len {
            break;
        }
        match ch {
            b'P' if has_p => {
                let pers_enc = data[ap];
                ap += 1;
                let sz = eh_ptr_size(pers_enc) as usize;
                if ap + sz <= data.len() {
                    // Personality ptr is PC-relative from the field address.
                    let field_vm = eh_frame_vm_addr + ap as u64;
                    let target_vm = read_pcrel(data, ap, sz, field_vm);
                    if target_vm != 0 {
                        info.has_personality = true;
                        info.pers_got_vm = target_vm;
                    }
                }
                ap += sz;
            }
            b'L' if has_l => {
                let lsda_enc = data[ap];
                ap += 1;
                info.lsda_ptr_size = eh_ptr_size(lsda_enc);
            }
            b'R' if has_r => {
                let fde_enc = data[ap];
                ap += 1;
                info.fde_ptr_size = eh_ptr_size(fde_enc);
            }
            _ => {}
        }
    }

    // Default pointer size = 8 for 64-bit Mach-O.
    if info.fde_ptr_size == 0 {
        info.fde_ptr_size = 8;
    }
    if info.lsda_ptr_size == 0 {
        info.lsda_ptr_size = 8;
    }
    info
}

/// Scan the output `__eh_frame` buffer.
/// Returns a map: `func_vm_addr → EhFrameFdeInfo` for every FDE found.
/// FDEs without personality have `pers_got_vm = 0`.
fn scan_eh_frame_fde_offsets(
    buf: &[u8],
    eh_frame_vm_addr: u64,
    eh_frame_file_offset: usize,
    eh_frame_size: usize,
) -> std::collections::HashMap<u64, EhFrameFdeInfo> {
    use crate::eh_frame::EhFrameEntryPrefix;
    use std::mem::size_of;
    use zerocopy::FromBytes;

    let mut map = std::collections::HashMap::new();
    // CIE map: section_offset → CieAugInfo
    let mut cie_map: std::collections::HashMap<u32, CieAugInfo> = Default::default();

    let Some(data) = buf.get(eh_frame_file_offset..eh_frame_file_offset + eh_frame_size) else {
        return map;
    };

    const PREFIX_LEN: usize = size_of::<EhFrameEntryPrefix>();
    let mut pos = 0usize;

    while pos + PREFIX_LEN <= data.len() {
        let Ok(prefix) = EhFrameEntryPrefix::read_from_bytes(&data[pos..pos + PREFIX_LEN]) else {
            break;
        };
        if prefix.length == 0 {
            break;
        }
        let size = 4 + prefix.length as usize;
        if pos + size > data.len() {
            break;
        }

        if prefix.cie_id == 0 {
            // CIE: parse augmentation.
            let cie_aug = parse_cie_aug(data, pos, eh_frame_vm_addr);
            cie_map.insert(pos as u32, cie_aug);
        } else {
            // FDE: resolve CIE, then extract pc_begin, LSDA.
            // cie_id = byte distance from the cie_ptr field to the CIE.
            let cie_ptr_field_off = pos + 4;
            let cie_off = (cie_ptr_field_off as u64).wrapping_sub(prefix.cie_id as u64) as u32;
            let cie_aug = cie_map.get(&cie_off).cloned().unwrap_or_default();
            let ptr_size = cie_aug.fde_ptr_size.max(4) as usize;

            // pc_begin at byte 8, PC-relative signed value of ptr_size bytes.
            let pc_begin_field_vm = eh_frame_vm_addr + pos as u64 + 8;
            let func_vm = read_pcrel(data, pos + 8, ptr_size, pc_begin_field_vm);
            if func_vm == 0 {
                pos += size;
                continue;
            }

            // pc_range at byte 8+ptr_size (absolute, not PC-relative).
            // Skip it (we don't use pc_range for __unwind_info).

            // aug_data_length at byte 8 + 2*ptr_size.
            let aug_len_pos = pos + 8 + 2 * ptr_size;
            let mut ap = aug_len_pos;
            let aug_len = read_uleb128(data, &mut ap) as usize;

            // LSDA pointer at start of aug_data (if CIE has 'L').
            let lsda_vm = if cie_aug.has_lsda
                && cie_aug.lsda_ptr_size > 0
                && ap + cie_aug.lsda_ptr_size as usize <= data.len()
            {
                let lsda_field_vm = eh_frame_vm_addr + ap as u64;
                read_pcrel(data, ap, cie_aug.lsda_ptr_size as usize, lsda_field_vm)
            } else {
                0
            };
            let _ = aug_len;

            map.insert(
                func_vm,
                EhFrameFdeInfo {
                    section_offset: pos as u32,
                    lsda_vm,
                    pers_got_vm: cie_aug.pers_got_vm,
                },
            );
        }

        pos += size;
    }

    map
}

/// Build the binary content of `__unwind_info` from collected compact-unwind entries
/// and FDE info from the output `__eh_frame`.
///
/// `plain_entries`:  ARM64 frame-pointer entries (from __compact_unwind).
/// `fde_map`:        func_vm_addr → EhFrameFdeInfo (from scanning output __eh_frame).
/// `text_base`:      VM address of the start of `__TEXT`.
///
/// For each FDE with a personality function, emits a DWARF-mode entry
/// (`UNWIND_HAS_LSDA | pers_idx | UNWIND_ARM64_DWARF | fde_section_offset`).
/// Plain frame-pointer entries are also included.
fn build_unwind_info_section(
    plain_entries: &[CollectedUnwindEntry],
    fde_map: &std::collections::HashMap<u64, EhFrameFdeInfo>,
    text_base: u64,
    max_bytes: u64,
) -> Vec<u8> {
    // ARM64 compact-unwind encoding constants.
    const UNWIND_ARM64_DWARF: u32 = 0x0300_0000;

    // Build: (func_addr, func_size, encoding) sorted by func_addr.
    let mut all_entries: Vec<(u64, u32, u32)> = Vec::new();

    // Collect unique personality GOT slots (in encounter order).
    let mut personalities: Vec<u64> = Vec::new();

    // Emit DWARF-mode entries for FDEs that have a personality function.
    // Each such FDE needs an __unwind_info entry so the unwinder can find it.
    //
    // For DWARF-mode entries the unwinder reads the LSDA from the FDE
    // augmentation data in __eh_frame, NOT from the __unwind_info LSDA array.
    // So we omit UNWIND_HAS_LSDA and the LSDA array to save space.
    for (&func_vm, fde_info) in fde_map {
        if fde_info.pers_got_vm == 0 {
            continue;
        } // no personality → skip

        // Personality index (1-based into the personality array we build).
        let pers_idx = if let Some(pos) = personalities
            .iter()
            .position(|&g| g == fde_info.pers_got_vm)
        {
            pos + 1
        } else {
            personalities.push(fde_info.pers_got_vm);
            personalities.len()
        };

        let enc = UNWIND_ARM64_DWARF | fde_info.section_offset | (((pers_idx as u32) & 3) << 28);
        all_entries.push((func_vm, 0u32, enc));
    }

    // Also collect personalities from compact_unwind entries.
    for e in plain_entries {
        if let Some(got) = e.personality_got {
            if !personalities.contains(&got) {
                personalities.push(got);
            }
        }
    }

    let pers_count = all_entries.len();
    // LSDA descriptors: (func_offset_from_text, lsda_offset_from_text)
    let mut lsda_descriptors: Vec<(u32, u32)> = Vec::new();
    for e in plain_entries {
        if fde_map
            .get(&e.func_addr)
            .is_some_and(|f| f.pers_got_vm != 0)
        {
            continue;
        }
        let mut enc = e.encoding;
        // Set personality index in encoding bits [29:28]
        if let Some(got) = e.personality_got {
            if let Some(pos) = personalities.iter().position(|&g| g == got) {
                let pers_idx = (pos + 1) as u32;
                enc = (enc & !(0x3 << 28)) | ((pers_idx & 3) << 28);
            }
        }
        // Set UNWIND_HAS_LSDA flag and record LSDA descriptor
        if let Some(lsda) = e.lsda_addr {
            enc |= 0x4000_0000; // UNWIND_HAS_LSDA
            lsda_descriptors.push(((e.func_addr - text_base) as u32, (lsda - text_base) as u32));
        }
        all_entries.push((e.func_addr, e.func_size, enc));
    }
    lsda_descriptors.sort_by_key(|d| d.0);

    if all_entries.is_empty() {
        return Vec::new();
    }

    all_entries.sort_by_key(|e| e.0);
    all_entries.dedup_by_key(|e| e.0);

    // Truncate if the full content would exceed max_bytes.
    // Personality entries (pers_count) are critical; trim plain entries first.
    let n_pers = personalities.len() as u32;
    const ENTRIES_PER_PAGE: usize = 500;
    loop {
        let np = all_entries.len().div_ceil(ENTRIES_PER_PAGE);
        // Estimate: header(28) + pers(n*4) + index((np+1)*12) + LSDA(n*8) + SL pages(np*8 +
        // entries*8)
        let est = 28
            + (n_pers as usize) * 4
            + (np + 1) * 12
            + lsda_descriptors.len() * 8
            + np * 8
            + all_entries.len() * 8;
        if est as u64 <= max_bytes || all_entries.len() <= pers_count {
            break;
        }
        // Remove last plain entry (they're sorted, so the highest address is removed first).
        all_entries.pop();
    }

    let num_pages = all_entries.len().div_ceil(ENTRIES_PER_PAGE);

    tracing::debug!(
        "compact_unwind: building __unwind_info: {} entries ({} pers), {} personalities",
        all_entries.len(),
        pers_count,
        personalities.len()
    );

    // DWARF-mode entries all have unique encodings (different FDE offsets) so
    // common encodings provide no benefit — skip them to save space.

    // Section layout:
    //   [28]         header (7 × u32)
    //   [P*4]        personality array (GOT slot offsets from TEXT base)
    //   [(N+1)*12]   first-level index (N pages + sentinel)
    //   [page data…]
    //
    // LSDA array is empty: DWARF-mode entries get LSDA from the FDE augmentation
    // data in __eh_frame, so no separate LSDA index is needed.
    let ce_off = 28u32;
    let pers_off = ce_off; // no common encodings
    let pers_bytes = n_pers * 4;
    let idx_off = pers_off + pers_bytes;
    let idx_bytes = (num_pages as u32 + 1) * 12;
    let lsda_off = idx_off + idx_bytes;
    let lsda_bytes = lsda_descriptors.len() as u32 * 8; // 8 bytes each: funcOffset + lsdaOffset
    let sl_start = lsda_off + lsda_bytes;

    let mut sl_offsets = Vec::with_capacity(num_pages);
    let mut cur = sl_start;
    for i in 0..num_pages {
        sl_offsets.push(cur);
        let n = (all_entries.len() - i * ENTRIES_PER_PAGE).min(ENTRIES_PER_PAGE);
        cur += 8 + n as u32 * 8;
    }
    let total = cur as usize;

    let mut out = vec![0u8; total];
    macro_rules! wu32 {
        ($off:expr, $val:expr) => {
            out[$off..$off + 4].copy_from_slice(&($val as u32).to_le_bytes())
        };
    }
    macro_rules! wu16 {
        ($off:expr, $val:expr) => {
            out[$off..$off + 2].copy_from_slice(&($val as u16).to_le_bytes())
        };
    }

    // Header
    wu32!(0, 1u32); // version
    wu32!(4, ce_off); // commonEncodingsArraySectionOffset
    wu32!(8, 0u32); // commonEncodingsArrayCount (none)
    wu32!(12, pers_off); // personalityArraySectionOffset
    wu32!(16, n_pers); // personalityArrayCount
    wu32!(20, idx_off); // indexSectionOffset
    wu32!(24, num_pages as u32 + 1); // indexCount (includes sentinel)

    // Personality array: 4-byte offsets from TEXT base to GOT slots.
    for (i, &got_vm) in personalities.iter().enumerate() {
        let offset_from_text = (got_vm - text_base) as u32;
        wu32!(pers_off as usize + i * 4, offset_from_text);
    }

    // LSDA descriptors array (8 bytes each: funcOffset + lsdaOffset)
    for (i, &(func_off, lsda_off_val)) in lsda_descriptors.iter().enumerate() {
        let off = lsda_off as usize + i * 8;
        wu32!(off, func_off);
        wu32!(off + 4, lsda_off_val);
    }

    // First-level index entries + second-level regular pages
    for page in 0..num_pages {
        let start = page * ENTRIES_PER_PAGE;
        let end = (start + ENTRIES_PER_PAGE).min(all_entries.len());
        let page_entries = &all_entries[start..end];

        let first_fn_off = (page_entries[0].0 - text_base) as u32;
        let sl_off = sl_offsets[page] as usize;

        // Index entry (12 bytes)
        let ie = idx_off as usize + page * 12;
        wu32!(ie, first_fn_off);
        wu32!(ie + 4, sl_off as u32); // secondLevelPagesSectionOffset
        wu32!(ie + 8, lsda_off); // lsdaIndexArraySectionOffset

        // Regular second-level page header (8 bytes)
        wu32!(sl_off, 2u32); // kind = UNWIND_SECOND_LEVEL_REGULAR
        wu16!(sl_off + 4, 8u16); // entryPageOffset
        wu16!(sl_off + 6, page_entries.len() as u16); // entryCount

        // Entries (8 bytes each: funcOffset u32 + encoding u32)
        for (j, &(fa, _, enc)) in page_entries.iter().enumerate() {
            let eo = sl_off + 8 + j * 8;
            wu32!(eo, (fa - text_base) as u32);
            wu32!(eo + 4, enc);
        }
    }

    // Sentinel first-level index entry
    let (last_fa, last_fs, _) = *all_entries.last().unwrap();
    let sentinel_fn_off = (last_fa - text_base + last_fs as u64) as u32;
    let sie = idx_off as usize + num_pages * 12;
    wu32!(sie, sentinel_fn_off);
    wu32!(sie + 4, 0u32); // secondLevelPagesSectionOffset = 0 (sentinel)
    wu32!(sie + 8, lsda_off + lsda_bytes); // lsdaIndexArraySectionOffset (end)

    out
}

/// Mach-O section metadata for a given output section ID.
struct MachoSectionInfo {
    segname: &'static [u8; 16],
    sectname: [u8; 16],
    flags: u32,
}

/// Map an OutputSectionId to Mach-O section name and flags.
/// Returns None for sections that don't need their own section header
/// (e.g. FILE_HEADER, BSS handled specially, etc.).
fn macho_section_info(id: crate::output_section_id::OutputSectionId) -> Option<MachoSectionInfo> {
    use crate::output_section_id;
    fn name16(s: &[u8]) -> [u8; 16] {
        let mut buf = [0u8; 16];
        let len = s.len().min(16);
        buf[..len].copy_from_slice(&s[..len]);
        buf
    }
    static TEXT_SEG: &[u8; 16] = b"__TEXT\0\0\0\0\0\0\0\0\0\0";
    static DATA_SEG: &[u8; 16] = b"__DATA\0\0\0\0\0\0\0\0\0\0";

    let (segname, sectname, flags) = match id {
        output_section_id::TEXT => (TEXT_SEG, name16(b"__text"), 0x8000_0400u32),
        output_section_id::PLT_GOT => (TEXT_SEG, name16(b"__stubs"), 0x8000_0408),
        output_section_id::GCC_EXCEPT_TABLE => (TEXT_SEG, name16(b"__gcc_except_tab"), 0),
        output_section_id::EH_FRAME => (TEXT_SEG, name16(b"__eh_frame"), 0x6800_000B),
        output_section_id::RODATA => (TEXT_SEG, name16(b"__cstring"), 0),
        output_section_id::COMMENT => (TEXT_SEG, name16(b"__literal8"), 0x06),
        output_section_id::DATA_REL_RO => (TEXT_SEG, name16(b"__const"), 0),
        output_section_id::DATA => (DATA_SEG, name16(b"__data"), 0),
        output_section_id::CSTRING => (DATA_SEG, name16(b"__const"), 0),
        output_section_id::GOT => (DATA_SEG, name16(b"__got"), 0x06),
        output_section_id::PREINIT_ARRAY => (DATA_SEG, name16(b"__thread_vars"), 0x13),
        output_section_id::INIT_ARRAY => (DATA_SEG, name16(b"__mod_init_func"), 0x09),
        output_section_id::FINI_ARRAY => (DATA_SEG, name16(b"__mod_term_func"), 0x0E),
        output_section_id::TDATA => (DATA_SEG, name16(b"__thread_data"), 0x11),
        output_section_id::TBSS => (DATA_SEG, name16(b"__thread_bss"), 0x12),
        output_section_id::BSS => (DATA_SEG, name16(b"__bss"), 0x01),
        _ => return None,
    };
    Some(MachoSectionInfo {
        segname,
        sectname,
        flags,
    })
}

/// Write Mach-O headers. Returns the chained fixups file offset.
fn write_headers(
    out: &mut [u8],
    offset: usize,
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
    chained_fixups_data_size: u32,
    unwind_info_vm_addr: u64,
    unwind_info_size: u64,
    sectcreate_placements: &[([u8; 16], [u8; 16], u64, u64)],
    init_offsets_vm_addr: u64,
    init_offsets_size: u64,
) -> Result<Option<u64>> {
    let text_vm_start = mappings.first().map_or(PAGEZERO_SIZE, |m| m.vm_start);
    let text_vm_end = mappings
        .first()
        .map_or(PAGEZERO_SIZE + PAGE_SIZE, |m| m.vm_end);
    let text_filesize = align_to(text_vm_end - text_vm_start, PAGE_SIZE);

    let has_data = mappings.len() > 1;
    let data_vmaddr = mappings.get(1).map_or(0, |m| m.vm_start);
    let data_vm_end = mappings
        .iter()
        .skip(1)
        .map(|m| m.vm_end)
        .max()
        .unwrap_or(data_vmaddr);
    let data_vmsize = align_to(data_vm_end - data_vmaddr, PAGE_SIZE);
    let data_fileoff = mappings.get(1).map_or(0, |m| m.file_offset);
    let data_filesize = if has_data {
        align_to(
            mappings
                .iter()
                .skip(1)
                .map(|m| m.file_offset + (m.vm_end - m.vm_start))
                .max()
                .unwrap()
                - data_fileoff,
            PAGE_SIZE,
        )
    } else {
        0
    };

    let text_layout = layout.section_layouts.get(output_section_id::TEXT);
    let entry_addr = layout.entry_symbol_address()?;
    let entry_offset =
        vm_addr_to_file_offset(entry_addr, mappings).unwrap_or(text_layout.file_offset);

    let tdata_layout = layout.section_layouts.get(output_section_id::TDATA);
    let tbss_layout = layout.section_layouts.get(output_section_id::TBSS);
    let has_tlv = tdata_layout.mem_size > 0 || tbss_layout.mem_size > 0;
    let _has_tvars = has_tlv;
    // Scan for .rustc section (proc-macro metadata) before computing cmd sizes
    let mut rustc_addr = 0u64;
    let mut rustc_size = 0u64;
    {
        use object::read::macho::Section as _;
        let le = object::Endianness::Little;
        for group in &layout.group_layouts {
            for file_layout in &group.files {
                if let FileLayout::Object(obj) = file_layout {
                    for (sec_idx, _) in obj.sections.iter().enumerate() {
                        if let Some(s) = obj.object.sections.get(sec_idx) {
                            let name = crate::macho::trim_nul(s.sectname());
                            if name == b".rustc" {
                                if let Some(addr) = obj.section_resolutions[sec_idx].address() {
                                    if rustc_addr == 0 || addr < rustc_addr {
                                        rustc_addr = addr;
                                    }
                                    rustc_size += s.size(le);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let has_rustc = rustc_addr > 0 && rustc_size > 0;

    let buf_len = out.len();
    let mut w = Writer {
        buf: out,
        pos: offset,
    };
    let dylinker_cmd_size = align8((12 + DYLD_PATH.len() + 1) as u32);
    let dylib_cmd_size = align8((24 + LIBSYSTEM_PATH.len() + 1) as u32);

    let is_dylib = layout.symbol_db.args.is_dylib;
    let is_bundle = layout.symbol_db.args.is_bundle;
    let install_name = if is_dylib {
        if let Some(ref name) = layout.symbol_db.args.install_name {
            String::from_utf8_lossy(name).into_owned()
        } else {
            layout
                .symbol_db
                .args
                .output()
                .to_string_lossy()
                .into_owned()
        }
    } else {
        String::new()
    };
    let id_dylib_cmd_size = if is_dylib {
        align8(24 + install_name.len() as u32 + 1)
    } else {
        0
    };

    let mut ncmds = 0u32;
    let mut cmdsize = 0u32;
    let add_cmd = |n: &mut u32, s: &mut u32, size: u32| {
        *n += 1;
        *s += size;
    };
    if !is_dylib {
        add_cmd(&mut ncmds, &mut cmdsize, 72);
    } // PAGEZERO (exe only)
    let rustc_in_text = has_rustc && rustc_addr < text_vm_start + text_filesize;
    let has_unwind_info = unwind_info_size > 0;

    // Dynamically collect TEXT and DATA section headers from all output sections.
    // This replaces the hardcoded section counting.
    struct SectionHeader {
        segname: [u8; 16],
        sectname: [u8; 16],
        addr: u64,
        size: u64,
        offset: u32,
        align: u32,
        flags: u32,
    }

    let mut text_sections: Vec<SectionHeader> = Vec::new();
    let mut data_sections: Vec<SectionHeader> = Vec::new();

    static TEXT_SEG_NAME: [u8; 16] = *b"__TEXT\0\0\0\0\0\0\0\0\0\0";
    static DATA_SEG_NAME: [u8; 16] = *b"__DATA\0\0\0\0\0\0\0\0\0\0";

    // Enumerate all output sections that have content.
    let has_init_offsets = init_offsets_size > 0;
    for (sec_id, sec_layout) in layout.section_layouts.iter() {
        if sec_layout.mem_size == 0 {
            continue;
        }
        // When using __init_offsets, suppress __mod_init_func from DATA segment.
        if has_init_offsets && sec_id == output_section_id::INIT_ARRAY {
            continue;
        }
        let file_off = vm_addr_to_file_offset(sec_layout.mem_offset, mappings).unwrap_or(0) as u32;
        if let Some(info) = macho_section_info(sec_id) {
            let hdr = SectionHeader {
                segname: *info.segname,
                sectname: info.sectname,
                addr: sec_layout.mem_offset,
                size: sec_layout.mem_size,
                offset: file_off,
                align: sec_layout.alignment.exponent as u32,
                flags: info.flags,
            };
            if *info.segname == TEXT_SEG_NAME {
                text_sections.push(hdr);
            } else {
                data_sections.push(hdr);
            }
        }
    }
    // Sort by address within each segment.
    text_sections.sort_by_key(|s| s.addr);
    data_sections.sort_by_key(|s| s.addr);

    // Add special sections: .rustc (if in TEXT), __unwind_info
    if rustc_in_text {
        let rustc_foff = vm_addr_to_file_offset(rustc_addr, mappings).unwrap_or(0) as u32;
        text_sections.push(SectionHeader {
            segname: TEXT_SEG_NAME,
            sectname: *b".rustc\0\0\0\0\0\0\0\0\0\0",
            addr: rustc_addr,
            size: rustc_size,
            offset: rustc_foff,
            align: 0,
            flags: 0,
        });
    }
    if has_unwind_info {
        let ui_foff = vm_addr_to_file_offset(unwind_info_vm_addr, mappings).unwrap_or(0) as u32;
        text_sections.push(SectionHeader {
            segname: TEXT_SEG_NAME,
            sectname: *b"__unwind_info\0\0\0",
            addr: unwind_info_vm_addr,
            size: unwind_info_size,
            offset: ui_foff,
            align: 2,
            flags: 0,
        });
    }
    // Add -sectcreate sections to the appropriate segment.
    for &(segname, sectname, vm_addr, size) in sectcreate_placements {
        let foff = vm_addr_to_file_offset(vm_addr, mappings).unwrap_or(0) as u32;
        let hdr = SectionHeader {
            segname,
            sectname,
            addr: vm_addr,
            size,
            offset: foff,
            align: 0,
            flags: 0,
        };
        if segname == TEXT_SEG_NAME {
            text_sections.push(hdr);
        } else if segname == DATA_SEG_NAME {
            data_sections.push(hdr);
        }
        // Other segments: handled via empty_segs path (size reported in header only)
    }
    // Add __init_offsets to TEXT if active.
    if has_init_offsets {
        let io_foff = vm_addr_to_file_offset(init_offsets_vm_addr, mappings).unwrap_or(0) as u32;
        text_sections.push(SectionHeader {
            segname: TEXT_SEG_NAME,
            sectname: *b"__init_offsets\0\0",
            addr: init_offsets_vm_addr,
            size: init_offsets_size,
            offset: io_foff,
            align: 2, // 4-byte aligned
            flags: 0x16, // S_INIT_FUNC_OFFSETS
        });
    }
    // Re-sort TEXT after adding special sections.
    text_sections.sort_by_key(|s| s.addr);

    // Add .rustc in DATA if not in TEXT.
    if has_rustc && !rustc_in_text {
        let rc_addr = rustc_addr.max(data_vmaddr);
        let rc_foff =
            vm_addr_to_file_offset(rustc_addr, mappings).unwrap_or(data_fileoff as usize) as u32;
        data_sections.push(SectionHeader {
            segname: DATA_SEG_NAME,
            sectname: *b".rustc\0\0\0\0\0\0\0\0\0\0",
            addr: rc_addr,
            size: rustc_size,
            offset: rc_foff,
            align: 0,
            flags: 0,
        });
        data_sections.sort_by_key(|s| s.addr);
    }

    // Fix up __thread_data: override type to S_THREAD_LOCAL_REGULAR and extend
    // Fix __thread_data flags (set correct Mach-O section type).
    for sec in &mut data_sections {
        let name = crate::macho::trim_nul(&sec.sectname);
        if name == b"__thread_data" {
            sec.flags = 0x11; // S_THREAD_LOCAL_REGULAR
        }
    }

    let text_nsects = text_sections.len() as u32;
    add_cmd(&mut ncmds, &mut cmdsize, 72 + 80 * text_nsects); // TEXT
    if has_data {
        let data_nsects = data_sections.len() as u32;
        add_cmd(&mut ncmds, &mut cmdsize, 72 + 80 * data_nsects);
    }
    // Group empty sections by segment name
    let empty_sections = &layout.symbol_db.args.empty_sections;
    let mut empty_segs: Vec<(&[u8; 16], Vec<&[u8; 16]>)> = Vec::new();
    for (segname, sectname) in empty_sections {
        if let Some(seg) = empty_segs.iter_mut().find(|(s, _)| *s == segname) {
            seg.1.push(sectname);
        } else {
            empty_segs.push((segname, vec![sectname]));
        }
    }
    for (_, sects) in &empty_segs {
        add_cmd(&mut ncmds, &mut cmdsize, 72 + 80 * sects.len() as u32);
    }
    add_cmd(&mut ncmds, &mut cmdsize, 72); // LINKEDIT
    let emit_uuid = !layout.symbol_db.args.no_uuid;
    if emit_uuid {
        add_cmd(&mut ncmds, &mut cmdsize, 24); // LC_UUID
    }
    if is_dylib {
        add_cmd(&mut ncmds, &mut cmdsize, id_dylib_cmd_size); // LC_ID_DYLIB
    } else if !is_bundle {
        add_cmd(&mut ncmds, &mut cmdsize, 24); // LC_MAIN
    }
    if !is_dylib {
        add_cmd(&mut ncmds, &mut cmdsize, dylinker_cmd_size);
    }
    add_cmd(&mut ncmds, &mut cmdsize, dylib_cmd_size); // libSystem
    let umbrella_cmd_size = layout
        .symbol_db
        .args
        .umbrella
        .as_ref()
        .map(|u| align8(12 + u.len() as u32 + 1))
        .unwrap_or(0);
    if umbrella_cmd_size > 0 {
        add_cmd(&mut ncmds, &mut cmdsize, umbrella_cmd_size); // LC_SUB_FRAMEWORK
    }

    // Filter extra_dylibs when -dead_strip_dylibs: only keep dylibs with referenced symbols.
    let all_extra_dylibs = &layout.symbol_db.args.extra_dylibs;
    let filtered_extra: Vec<&(Vec<u8>, crate::args::macho::DylibLoadKind)>;
    let has_auto_strip = !layout.symbol_db.args.auto_strip_dylib_indices.is_empty();
    let extra_dylibs: &[&(Vec<u8>, crate::args::macho::DylibLoadKind)] =
        if layout.symbol_db.args.dead_strip_dylibs || has_auto_strip {
            // Find which dylib indices have at least one referenced symbol.
            let mut used_indices = std::collections::HashSet::new();
            // Check which symbols from the symbol resolutions are from dylibs.
            for (sym_idx, res) in layout.symbol_resolutions.iter().enumerate() {
                if res.is_none() {
                    // Unresolved — check if it's a dylib symbol.
                    let sym_id = crate::symbol_db::SymbolId::from_usize(sym_idx);
                    if let Ok(name) = layout.symbol_db.symbol_name(sym_id) {
                        if let Some(&idx) = layout
                            .symbol_db
                            .args
                            .dylib_symbol_provenance
                            .get(name.bytes())
                        {
                            used_indices.insert(idx);
                        }
                    }
                }
            }
            filtered_extra = all_extra_dylibs
                .iter()
                .enumerate()
                .filter(|(i, _)| {
                    let is_used = used_indices.contains(i);
                    let is_needed = layout.symbol_db.args.needed_dylib_indices.contains(i);
                    let should_strip = layout.symbol_db.args.dead_strip_dylibs
                        || layout.symbol_db.args.auto_strip_dylib_indices.contains(i);
                    is_needed || is_used || !should_strip
                })
                .map(|(_, d)| d)
                .collect();
            &filtered_extra
        } else {
            // Convert &Vec<T> to &[&T] — just use all dylibs.
            filtered_extra = all_extra_dylibs.iter().collect();
            &filtered_extra
        };
    let extra_dylib_sizes: Vec<u32> = extra_dylibs
        .iter()
        .map(|(p, _)| align8(24 + p.len() as u32 + 1))
        .collect();
    for &sz in &extra_dylib_sizes {
        add_cmd(&mut ncmds, &mut cmdsize, sz);
    }
    let rpaths = &layout.symbol_db.args.rpaths;
    let rpath_sizes: Vec<u32> = rpaths
        .iter()
        .map(|p| align8(12 + p.len() as u32 + 1))
        .collect();
    for &sz in &rpath_sizes {
        add_cmd(&mut ncmds, &mut cmdsize, sz);
    }
    add_cmd(&mut ncmds, &mut cmdsize, 24); // SYMTAB
    add_cmd(&mut ncmds, &mut cmdsize, 80); // DYSYMTAB
    add_cmd(&mut ncmds, &mut cmdsize, 32); // LC_BUILD_VERSION
    add_cmd(&mut ncmds, &mut cmdsize, 16); // LC_DYLD_CHAINED_FIXUPS
    add_cmd(&mut ncmds, &mut cmdsize, 16); // LC_DYLD_EXPORTS_TRIE
    let emit_func_starts = !layout.symbol_db.args.no_function_starts;
    if emit_func_starts {
        add_cmd(&mut ncmds, &mut cmdsize, 16); // LC_FUNCTION_STARTS
    }
    let emit_data_in_code = !layout.symbol_db.args.no_data_in_code;
    if emit_data_in_code {
        add_cmd(&mut ncmds, &mut cmdsize, 16); // LC_DATA_IN_CODE
    }

    let filetype = if is_dylib {
        6u32 // MH_DYLIB
    } else if is_bundle {
        MH_BUNDLE
    } else {
        MH_EXECUTE
    };
    w.u32(MH_MAGIC_64);
    w.u32(CPU_TYPE_ARM64);
    w.u32(CPU_SUBTYPE_ARM64_ALL);
    w.u32(filetype);
    w.u32(ncmds);
    w.u32(cmdsize);
    let mut flags = MH_PIE | MH_DYLDLINK;
    if !layout.symbol_db.args.flat_namespace {
        flags |= MH_TWOLEVEL;
    }
    if has_tlv {
        flags |= 0x0080_0000; // MH_HAS_TLV_DESCRIPTORS
    }
    if layout.symbol_db.args.mark_dead_strippable {
        flags |= 0x0040_0000; // MH_DEAD_STRIPPABLE_DYLIB
    }
    w.u32(flags);
    w.u32(0);

    if !is_dylib {
        w.segment(b"__PAGEZERO", 0, PAGEZERO_SIZE, 0, 0, 0, 0, 0);
    }

    // __TEXT — include .rustc section if it falls in TEXT range
    w.u32(LC_SEGMENT_64);
    w.u32(72 + 80 * text_nsects);
    w.name16(b"__TEXT");
    w.u64(text_vm_start);
    w.u64(text_filesize);
    w.u64(0);
    w.u64(text_filesize);
    w.u32(VM_PROT_READ | VM_PROT_EXECUTE);
    w.u32(VM_PROT_READ | VM_PROT_EXECUTE);
    w.u32(text_nsects);
    w.u32(0);
    // Write TEXT section headers.
    for sec in &text_sections {
        w.buf[w.pos..w.pos + 16].copy_from_slice(&sec.sectname);
        w.pos += 16;
        w.buf[w.pos..w.pos + 16].copy_from_slice(&sec.segname);
        w.pos += 16;
        w.u64(sec.addr);
        w.u64(sec.size);
        w.u32(sec.offset);
        w.u32(sec.align);
        w.u32(0); // reloff
        w.u32(0); // nreloc
        w.u32(sec.flags);
        w.u32(0); // reserved1
        // reserved2: stub size for S_SYMBOL_STUBS
        let reserved2 = if sec.flags & 0xFF == 0x08 { 12u32 } else { 0 };
        w.u32(reserved2);
        w.u32(0); // reserved3
    }

    if has_data {
        let data_nsects = data_sections.len() as u32;
        let data_cmd_size = 72 + 80 * data_nsects;
        w.u32(LC_SEGMENT_64);
        w.u32(data_cmd_size);
        w.name16(b"__DATA");
        w.u64(data_vmaddr);
        w.u64(data_vmsize);
        w.u64(data_fileoff);
        w.u64(data_filesize);
        w.u32(VM_PROT_READ | VM_PROT_WRITE);
        w.u32(VM_PROT_READ | VM_PROT_WRITE);
        w.u32(data_nsects);
        w.u32(0);

        // Write DATA section headers.
        for sec in &data_sections {
            w.buf[w.pos..w.pos + 16].copy_from_slice(&sec.sectname);
            w.pos += 16;
            w.buf[w.pos..w.pos + 16].copy_from_slice(&sec.segname);
            w.pos += 16;
            w.u64(sec.addr);
            w.u64(sec.size);
            w.u32(sec.offset);
            w.u32(sec.align);
            w.u32(0); // reloff
            w.u32(0); // nreloc
            w.u32(sec.flags);
            w.u32(0); // reserved1
            w.u32(0); // reserved2
            w.u32(0); // reserved3
        }
    }

    // Write empty sections (from -add_empty_section) as zero-size segments
    for (segname, sects) in &empty_segs {
        let n = sects.len() as u32;
        w.u32(LC_SEGMENT_64);
        w.u32(72 + 80 * n);
        w.buf[w.pos..w.pos + 16].copy_from_slice(*segname);
        w.pos += 16;
        w.u64(0); // vmaddr
        w.u64(0); // vmsize
        w.u64(0); // fileoff
        w.u64(0); // filesize
        w.u32(0); // maxprot
        w.u32(0); // initprot
        w.u32(n);
        w.u32(0); // flags
        for sectname in sects {
            w.buf[w.pos..w.pos + 16].copy_from_slice(*sectname);
            w.pos += 16;
            w.buf[w.pos..w.pos + 16].copy_from_slice(*segname);
            w.pos += 16;
            w.u64(0); // addr
            w.u64(0); // size
            w.u32(0); // offset
            w.u32(0); // align
            w.u32(0); // reloff
            w.u32(0); // nreloc
            w.u32(0); // flags
            w.u32(0); // reserved1
            w.u32(0); // reserved2
            w.u32(0); // reserved3
        }
    }

    let (last_file_end, linkedit_vm) = if has_data {
        (data_fileoff + data_filesize, data_vmaddr + data_vmsize)
    } else {
        (
            text_filesize,
            align_to(text_vm_start + text_filesize, PAGE_SIZE),
        )
    };
    let cf_offset = last_file_end;
    let cf_size = chained_fixups_data_size as u64;

    // LINKEDIT vmsize must cover the full content (fixups + symtab + exports).
    let linkedit_vmsize = align_to(
        (buf_len as u64)
            .saturating_sub(last_file_end)
            .max(PAGE_SIZE),
        PAGE_SIZE,
    );
    w.segment(
        b"__LINKEDIT",
        linkedit_vm,
        linkedit_vmsize,
        last_file_end,
        cf_size,
        VM_PROT_READ,
        VM_PROT_READ,
        0,
    );

    // LC_UUID = 0x1B
    if emit_uuid {
        w.u32(0x1B);
        w.u32(24);
        let uuid_bytes: [u8; 16] = if layout.symbol_db.args.random_uuid {
            let mut h = [0u8; 16];
            // Use std::time for a simple source of entropy
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            h[..16].copy_from_slice(&t.to_le_bytes());
            h[6] = (h[6] & 0x0F) | 0x40; // version 4
            h[8] = (h[8] & 0x3F) | 0x80; // variant 1
            h
        } else {
            // Deterministic UUID from -final_output name or output path
            let mut h = [0u8; 16];
            let output_lossy = layout
                .symbol_db
                .args
                .output()
                .to_string_lossy()
                .into_owned();
            let name = layout
                .symbol_db
                .args
                .final_output
                .as_deref()
                .unwrap_or(&output_lossy);
            for (i, b) in name.bytes().enumerate() {
                h[i % 16] ^= b;
            }
            h[6] = (h[6] & 0x0F) | 0x40; // version 4
            h[8] = (h[8] & 0x3F) | 0x80; // variant 1
            h
        };
        w.bytes(&uuid_bytes);
    }

    if is_dylib {
        // LC_ID_DYLIB = 0x0D
        w.u32(0x0D);
        w.u32(id_dylib_cmd_size);
        w.u32(24);
        w.u32(2); // timestamp
        w.u32(layout.symbol_db.args.current_version);
        w.u32(layout.symbol_db.args.compatibility_version);
        w.bytes(install_name.as_bytes());
        w.u8(0);
        w.pad8();
    } else if !is_bundle {
        // Bundles have neither LC_MAIN nor LC_ID_DYLIB
        w.u32(LC_MAIN);
        w.u32(24);
        w.u64(entry_offset as u64);
        w.u64(layout.symbol_db.args.stack_size.unwrap_or(0));
    }

    if !is_dylib {
        w.u32(LC_LOAD_DYLINKER);
        w.u32(dylinker_cmd_size);
        w.u32(12);
        w.bytes(DYLD_PATH);
        w.u8(0);
        w.pad8();
    }

    w.u32(LC_LOAD_DYLIB);
    w.u32(dylib_cmd_size);
    w.u32(24);
    w.u32(2);
    w.u32(0x01_0000);
    w.u32(0x01_0000);
    w.bytes(LIBSYSTEM_PATH);
    w.u8(0);
    w.pad8();

    for (i, (dylib_path, kind)) in extra_dylibs.iter().enumerate() {
        use crate::args::macho::DylibLoadKind;
        let cmd = match kind {
            DylibLoadKind::Normal => LC_LOAD_DYLIB,
            DylibLoadKind::Weak => 0x8000_0018, // LC_LOAD_WEAK_DYLIB
            DylibLoadKind::Reexport => 0x8000_001F, // LC_REEXPORT_DYLIB
        };
        w.u32(cmd);
        w.u32(extra_dylib_sizes[i]);
        w.u32(24);
        w.u32(2);
        w.u32(0x01_0000);
        w.u32(0x01_0000);
        w.bytes(dylib_path);
        w.u8(0);
        w.pad8();
    }

    // LC_RPATH = 0x8000_001C
    for (i, rpath) in rpaths.iter().enumerate() {
        w.u32(0x8000_001C);
        w.u32(rpath_sizes[i]);
        w.u32(12); // path offset
        w.bytes(rpath);
        w.u8(0);
        w.pad8();
    }

    // LC_SUB_FRAMEWORK = 0x12
    if let Some(ref umbrella_name) = layout.symbol_db.args.umbrella {
        w.u32(0x12);
        w.u32(umbrella_cmd_size);
        w.u32(12); // name offset
        w.bytes(umbrella_name.as_bytes());
        w.u8(0);
        w.pad8();
    }

    w.u32(LC_SYMTAB);
    w.u32(24);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(LC_DYSYMTAB);
    w.u32(80);
    for _ in 0..18 {
        w.u32(0);
    }

    w.u32(LC_BUILD_VERSION);
    w.u32(32);
    w.u32(PLATFORM_MACOS);
    w.u32(layout.symbol_db.args.minos.unwrap_or(0x000E_0000));
    w.u32(layout.symbol_db.args.sdk_version.unwrap_or(0x000E_0000));
    w.u32(1);
    w.u32(3);
    w.u32(0x0300_0100);

    w.u32(LC_DYLD_CHAINED_FIXUPS);
    w.u32(16);
    w.u32(cf_offset as u32);
    w.u32(cf_size as u32);
    w.u32(LC_DYLD_EXPORTS_TRIE);
    w.u32(16);
    w.u32(last_file_end as u32);
    w.u32(0);
    // LC_FUNCTION_STARTS = 0x26
    if emit_func_starts {
        w.u32(0x26);
        w.u32(16);
        w.u32(last_file_end as u32); // offset (patched later)
        w.u32(0); // size 0
    }
    // LC_DATA_IN_CODE = 0x29
    if emit_data_in_code {
        w.u32(0x29);
        w.u32(16);
        w.u32(last_file_end as u32); // offset (patched later)
        w.u32(0); // size 0
    }

    Ok(Some(cf_offset))
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

fn write_u32_at(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn align8(v: u32) -> u32 {
    (v + 7) & !7
}
fn align_to(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn u8(&mut self, v: u8) {
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn u32(&mut self, v: u32) {
        self.buf[self.pos..self.pos + 4].copy_from_slice(&v.to_le_bytes());
        self.pos += 4;
    }
    fn u64(&mut self, v: u64) {
        self.buf[self.pos..self.pos + 8].copy_from_slice(&v.to_le_bytes());
        self.pos += 8;
    }
    fn name16(&mut self, name: &[u8]) {
        let mut buf = [0u8; 16];
        buf[..name.len().min(16)].copy_from_slice(&name[..name.len().min(16)]);
        self.buf[self.pos..self.pos + 16].copy_from_slice(&buf);
        self.pos += 16;
    }
    fn bytes(&mut self, data: &[u8]) {
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
    }
    fn pad8(&mut self) {
        let aligned = (self.pos + 7) & !7;
        while self.pos < aligned {
            self.buf[self.pos] = 0;
            self.pos += 1;
        }
    }
    fn segment(
        &mut self,
        name: &[u8],
        vmaddr: u64,
        vmsize: u64,
        fileoff: u64,
        filesize: u64,
        maxprot: u32,
        initprot: u32,
        nsects: u32,
    ) {
        self.u32(LC_SEGMENT_64);
        self.u32(72 + 80 * nsects);
        self.name16(name);
        self.u64(vmaddr);
        self.u64(vmsize);
        self.u64(fileoff);
        self.u64(filesize);
        self.u32(maxprot);
        self.u32(initprot);
        self.u32(nsects);
        self.u32(0);
    }
}

/// Write a Mach-O relocatable object file (MH_OBJECT) for partial linking (-r).
fn write_relocatable_object(layout: &Layout<'_, MachO>) -> Result {
    use crate::layout::FileLayout;
    use object::read::macho::Nlist as _;
    use object::read::macho::Section as MachOSec;
    let le = object::Endianness::Little;

    // Phase 1: Collect sections and symbols from all input objects.
    // Each output section aggregates data from matching input sections.
    struct OutSection {
        segname: [u8; 16],
        sectname: [u8; 16],
        data: Vec<u8>,
        align: u32,
        flags: u32,
        relocs: Vec<[u8; 8]>, // raw Mach-O relocation entries
    }

    // Symbol entry for the output nlist table.
    struct OutSym {
        name: Vec<u8>,
        n_type: u8,
        n_sect: u8, // 1-based section ordinal in output, 0 = NO_SECT
        n_desc: u16,
        n_value: u64,
    }

    let mut sections: Vec<OutSection> = Vec::new();
    let mut symbols: Vec<OutSym> = Vec::new();

    // Map: (segname, sectname) -> index in `sections`
    let mut sec_map: std::collections::HashMap<([u8; 16], [u8; 16]), usize> = Default::default();

    for group in &layout.group_layouts {
        for file_layout in &group.files {
            let FileLayout::Object(obj) = file_layout else {
                continue;
            };

            // Build input symbol index -> output symbol index mapping for this object.
            let n_input_syms = obj.object.symbols.len();
            let mut sym_remap: Vec<u32> = vec![0; n_input_syms];
            // Also track which input sections map to which output sections.
            let n_input_secs = obj.object.sections.len();
            let mut sec_remap: Vec<u8> = vec![0; n_input_secs]; // 1-based output ordinal
            let mut sec_value_adjust: Vec<u64> = vec![0; n_input_secs]; // offset adjustment per input section

            // Process sections: copy data and build section map.
            for sec_idx in 0..n_input_secs {
                let Some(sec) = obj.object.sections.get(sec_idx) else {
                    continue;
                };
                let sec_segname = sec.segname;
                let sec_sectname = sec.sectname;
                let trimmed_seg = crate::macho::trim_nul(&sec_segname);
                let _trimmed_name = crate::macho::trim_nul(&sec_sectname);

                // Skip __LD,__compact_unwind (linker-private metadata)
                if trimmed_seg == b"__LD" {
                    continue;
                }

                let sec_type = sec.flags(le) & 0xFF;
                // Skip zerofill (BSS) sections' data
                let has_data = sec_type != 0x01 && sec_type != 0x0C;

                let input_offset = sec.offset(le) as usize;
                let input_size = sec.size(le) as usize;

                let out_sec_idx = if let Some(&idx) = sec_map.get(&(sec_segname, sec_sectname)) {
                    idx
                } else {
                    let idx = sections.len();
                    sec_map.insert((sec_segname, sec_sectname), idx);
                    sections.push(OutSection {
                        segname: sec_segname,
                        sectname: sec_sectname,
                        data: Vec::new(),
                        align: sec.align(le),
                        flags: sec.flags(le),
                        relocs: Vec::new(),
                    });
                    idx
                };
                sec_remap[sec_idx] = (out_sec_idx + 1) as u8;

                let out_sec = &mut sections[out_sec_idx];
                // Align the output position
                let alignment = 1usize << out_sec.align.max(sec.align(le));
                out_sec.align = out_sec.align.max(sec.align(le));
                let padding = (alignment - (out_sec.data.len() % alignment)) % alignment;
                out_sec.data.resize(out_sec.data.len() + padding, 0);
                let output_offset_in_sec = out_sec.data.len();
                // Record the adjustment: symbols in this input section need their
                // value increased by (output_offset_in_sec - input_section_addr).
                let input_sec_addr = sec.addr.get(le);
                sec_value_adjust[sec_idx] = output_offset_in_sec as u64 - input_sec_addr;

                if has_data && input_size > 0 && input_offset > 0 {
                    if let Some(data) = obj.object.data.get(input_offset..input_offset + input_size)
                    {
                        out_sec.data.extend_from_slice(data);
                    } else {
                        out_sec.data.resize(out_sec.data.len() + input_size, 0);
                    }
                } else {
                    out_sec.data.resize(out_sec.data.len() + input_size, 0);
                }

                // Copy and remap relocations (deferred until symbols are mapped)
                // For now, store reloc info to process after symbol table is built.
                // We'll handle this in a second pass.
            }

            // Process symbols: add to output symbol table.
            for sym_idx in 0..n_input_syms {
                let Ok(sym) = obj.object.symbols.symbol(object::SymbolIndex(sym_idx)) else {
                    continue;
                };
                let n_type = sym.n_type();
                // Skip debug symbols (N_STAB)
                if n_type & 0xE0 != 0 {
                    continue;
                }
                let name = sym
                    .name(le, obj.object.symbols.strings())
                    .unwrap_or(&[])
                    .to_vec();
                // Remap n_sect
                let n_sect_in = sym.n_sect();
                let n_sect_out = if n_sect_in > 0 && (n_sect_in as usize - 1) < sec_remap.len() {
                    sec_remap[n_sect_in as usize - 1]
                } else {
                    0
                };
                // Adjust n_value for merged section offset
                let n_value = if n_sect_in > 0
                    && n_sect_out > 0
                    && (n_sect_in as usize - 1) < sec_value_adjust.len()
                {
                    sym.n_value(le)
                        .wrapping_add(sec_value_adjust[n_sect_in as usize - 1])
                } else {
                    sym.n_value(le)
                };
                let out_idx = symbols.len() as u32;
                sym_remap[sym_idx] = out_idx;
                symbols.push(OutSym {
                    name,
                    n_type,
                    n_sect: n_sect_out,
                    n_desc: sym.n_desc(le) as u16,
                    n_value,
                });
            }

            // Second pass: copy and remap relocations.
            for sec_idx in 0..n_input_secs {
                let Some(sec) = obj.object.sections.get(sec_idx) else {
                    continue;
                };
                let trimmed_seg = crate::macho::trim_nul(&sec.segname);
                if trimmed_seg == b"__LD" {
                    continue;
                }
                let out_sec_ordinal = sec_remap[sec_idx];
                if out_sec_ordinal == 0 {
                    continue;
                }
                let out_sec_idx = out_sec_ordinal as usize - 1;

                let relocs = match sec.relocations(le, obj.object.data) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                for r in relocs {
                    let ri = r.info(le);
                    // Build output relocation with remapped symbol/section index.
                    let new_symbolnum = if ri.r_extern {
                        let idx = ri.r_symbolnum as usize;
                        if idx < sym_remap.len() {
                            sym_remap[idx]
                        } else {
                            ri.r_symbolnum
                        }
                    } else {
                        // Non-extern: r_symbolnum is 1-based section ordinal.
                        let sec_ord = ri.r_symbolnum as usize;
                        if sec_ord > 0
                            && sec_ord - 1 < sec_remap.len()
                            && sec_remap[sec_ord - 1] > 0
                        {
                            sec_remap[sec_ord - 1] as u32
                        } else {
                            ri.r_symbolnum
                        }
                    };
                    // Encode relocation entry (Mach-O ARM64 format):
                    // word0 = r_address (adjusted for output section offset)
                    // word1 = packed(r_symbolnum, r_pcrel, r_length, r_extern, r_type)
                    let addr_adjust = sec_value_adjust[sec_idx] as u32;
                    let word0 = ri.r_address.wrapping_add(addr_adjust);
                    let word1: u32 = (new_symbolnum & 0x00FF_FFFF)
                        | (if ri.r_pcrel { 1 << 24 } else { 0 })
                        | ((ri.r_length as u32 & 3) << 25)
                        | (if ri.r_extern { 1 << 27 } else { 0 })
                        | ((ri.r_type as u32 & 0xF) << 28);
                    let mut entry = [0u8; 8];
                    entry[0..4].copy_from_slice(&word0.to_le_bytes());
                    entry[4..8].copy_from_slice(&word1.to_le_bytes());
                    sections[out_sec_idx].relocs.push(entry);
                }
            }
        }
    }

    if sections.is_empty() {
        // Nothing to output
        let output_path = layout.symbol_db.args.output();
        std::fs::write(output_path.as_ref(), &[])
            .map_err(|e| crate::error!("Failed to write: {e}"))?;
        return Ok(());
    }

    // Phase 2: Sort symbols (locals first, then defined externals, then undefined).
    let mut local_syms: Vec<usize> = Vec::new();
    let mut ext_def_syms: Vec<usize> = Vec::new();
    let mut undef_syms: Vec<usize> = Vec::new();
    for (i, sym) in symbols.iter().enumerate() {
        if sym.name.is_empty() && sym.n_type == 0 {
            continue; // skip null symbol
        }
        let is_ext = (sym.n_type & 0x01) != 0; // N_EXT
        let sym_type = sym.n_type & 0x0E;
        if !is_ext {
            local_syms.push(i);
        } else if sym_type == 0 && sym.n_sect == 0 {
            // N_UNDF + N_EXT = undefined external
            undef_syms.push(i);
        } else {
            ext_def_syms.push(i);
        }
    }
    let sorted_indices: Vec<usize> = local_syms
        .iter()
        .chain(ext_def_syms.iter())
        .chain(undef_syms.iter())
        .copied()
        .collect();
    // Build reverse map: old index -> new index (for relocation fixup)
    let mut new_sym_index = vec![0u32; symbols.len()];
    for (new_idx, &old_idx) in sorted_indices.iter().enumerate() {
        new_sym_index[old_idx] = new_idx as u32;
    }

    // Fixup relocations to use new symbol indices.
    for sec in &mut sections {
        for entry in &mut sec.relocs {
            let word1 = u32::from_le_bytes(entry[4..8].try_into().unwrap());
            let old_symbolnum = word1 & 0x00FF_FFFF;
            let is_extern = (word1 >> 27) & 1 != 0;
            if is_extern {
                let new_num = if (old_symbolnum as usize) < new_sym_index.len() {
                    new_sym_index[old_symbolnum as usize]
                } else {
                    old_symbolnum
                };
                let word1_new = (word1 & 0xFF00_0000) | (new_num & 0x00FF_FFFF);
                entry[4..8].copy_from_slice(&word1_new.to_le_bytes());
            }
            // Non-extern relocs reference section ordinals, already remapped.
        }
    }

    // Phase 3: Build string table and nlist entries.
    let mut strtab = vec![0u8]; // starts with NUL
    let mut nlist_data: Vec<u8> = Vec::new();
    for &old_idx in &sorted_indices {
        let sym = &symbols[old_idx];
        let strx = strtab.len() as u32;
        strtab.extend_from_slice(&sym.name);
        strtab.push(0);
        // nlist_64: n_strx(4) + n_type(1) + n_sect(1) + n_desc(2) + n_value(8) = 16
        nlist_data.extend_from_slice(&strx.to_le_bytes());
        nlist_data.push(sym.n_type);
        nlist_data.push(sym.n_sect);
        nlist_data.extend_from_slice(&sym.n_desc.to_le_bytes());
        nlist_data.extend_from_slice(&sym.n_value.to_le_bytes());
    }

    // Phase 4: Compute layout and write output.
    let nsects = sections.len() as u32;
    let ncmds = 3u32; // LC_SEGMENT_64 + LC_SYMTAB + LC_DYSYMTAB
    let seg_cmdsize = 72 + 80 * nsects;
    let symtab_cmdsize = 24u32;
    let dysymtab_cmdsize = 80u32;
    let header_size = 32; // Mach-O 64 header
    let total_cmdsize = seg_cmdsize + symtab_cmdsize + dysymtab_cmdsize;

    let mut section_offset = header_size + total_cmdsize;
    let mut sec_offsets: Vec<u32> = Vec::new();
    for sec in &sections {
        // Align section data
        let alignment = 1u32 << sec.align;
        section_offset = (section_offset + alignment - 1) & !(alignment - 1);
        sec_offsets.push(section_offset);
        section_offset += sec.data.len() as u32;
    }

    // Relocation entries follow section data
    let mut reloc_offsets: Vec<u32> = Vec::new();
    let mut reloc_offset = section_offset;
    for sec in &sections {
        reloc_offsets.push(if sec.relocs.is_empty() {
            0
        } else {
            reloc_offset
        });
        reloc_offset += (sec.relocs.len() * 8) as u32;
    }

    // Symbol table follows relocations
    let symoff = (reloc_offset + 7) & !7; // 8-byte align
    let nsyms = sorted_indices.len() as u32;
    let stroff = symoff + nsyms * 16;
    let total_size = stroff + strtab.len() as u32;

    let mut buf = vec![0u8; total_size as usize];

    // Write header
    let mut pos = 0usize;
    let w = |buf: &mut Vec<u8>, pos: &mut usize, val: u32| {
        buf[*pos..*pos + 4].copy_from_slice(&val.to_le_bytes());
        *pos += 4;
    };
    w(&mut buf, &mut pos, MH_MAGIC_64);
    w(&mut buf, &mut pos, CPU_TYPE_ARM64);
    w(&mut buf, &mut pos, CPU_SUBTYPE_ARM64_ALL);
    w(&mut buf, &mut pos, 1); // MH_OBJECT
    w(&mut buf, &mut pos, ncmds);
    w(&mut buf, &mut pos, total_cmdsize);
    w(&mut buf, &mut pos, 0x2000); // MH_SUBSECTIONS_VIA_SYMBOLS
    w(&mut buf, &mut pos, 0); // reserved

    // LC_SEGMENT_64 (unnamed, contains all sections)
    w(&mut buf, &mut pos, LC_SEGMENT_64);
    w(&mut buf, &mut pos, seg_cmdsize);
    // segname: empty (16 NUL bytes)
    buf[pos..pos + 16].fill(0);
    pos += 16;
    // vmaddr, vmsize
    let seg_vmsize = sections
        .iter()
        .enumerate()
        .map(|(i, s)| sec_offsets[i] as u64 - sec_offsets[0] as u64 + s.data.len() as u64)
        .max()
        .unwrap_or(0);
    buf[pos..pos + 8].copy_from_slice(&0u64.to_le_bytes()); // vmaddr
    pos += 8;
    buf[pos..pos + 8].copy_from_slice(&seg_vmsize.to_le_bytes()); // vmsize
    pos += 8;
    buf[pos..pos + 8].copy_from_slice(&(sec_offsets[0] as u64).to_le_bytes()); // fileoff
    pos += 8;
    buf[pos..pos + 8]
        .copy_from_slice(&(section_offset as u64 - sec_offsets[0] as u64).to_le_bytes()); // filesize
    pos += 8;
    w(&mut buf, &mut pos, 7); // maxprot: rwx
    w(&mut buf, &mut pos, 7); // initprot: rwx
    w(&mut buf, &mut pos, nsects);
    w(&mut buf, &mut pos, 0); // flags

    // Section headers
    for (i, sec) in sections.iter().enumerate() {
        buf[pos..pos + 16].copy_from_slice(&sec.sectname);
        pos += 16;
        buf[pos..pos + 16].copy_from_slice(&sec.segname);
        pos += 16;
        buf[pos..pos + 8]
            .copy_from_slice(&((sec_offsets[i] - sec_offsets[0]) as u64).to_le_bytes()); // addr (section-relative)
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&(sec.data.len() as u64).to_le_bytes()); // size
        pos += 8;
        w(&mut buf, &mut pos, sec_offsets[i]); // offset
        w(&mut buf, &mut pos, sec.align); // align
        w(&mut buf, &mut pos, reloc_offsets[i]); // reloff
        w(&mut buf, &mut pos, sec.relocs.len() as u32); // nreloc
        w(&mut buf, &mut pos, sec.flags); // flags
        w(&mut buf, &mut pos, 0); // reserved1
        w(&mut buf, &mut pos, 0); // reserved2
        w(&mut buf, &mut pos, 0); // reserved3
    }

    // LC_SYMTAB
    w(&mut buf, &mut pos, LC_SYMTAB);
    w(&mut buf, &mut pos, symtab_cmdsize);
    w(&mut buf, &mut pos, symoff);
    w(&mut buf, &mut pos, nsyms);
    w(&mut buf, &mut pos, stroff);
    w(&mut buf, &mut pos, strtab.len() as u32);

    // LC_DYSYMTAB
    w(&mut buf, &mut pos, LC_DYSYMTAB);
    w(&mut buf, &mut pos, dysymtab_cmdsize);
    let nlocalsym = local_syms.len() as u32;
    let nextdefsym = ext_def_syms.len() as u32;
    let nundefsym = undef_syms.len() as u32;
    w(&mut buf, &mut pos, 0); // ilocalsym
    w(&mut buf, &mut pos, nlocalsym);
    w(&mut buf, &mut pos, nlocalsym); // iextdefsym
    w(&mut buf, &mut pos, nextdefsym);
    w(&mut buf, &mut pos, nlocalsym + nextdefsym); // iundefsym
    w(&mut buf, &mut pos, nundefsym);
    // Remaining DYSYMTAB fields are all zero
    for _ in 0..14 {
        w(&mut buf, &mut pos, 0);
    }

    // Write section data
    for (i, sec) in sections.iter().enumerate() {
        let off = sec_offsets[i] as usize;
        if off + sec.data.len() <= buf.len() {
            buf[off..off + sec.data.len()].copy_from_slice(&sec.data);
        }
    }

    // Write relocations
    for (i, sec) in sections.iter().enumerate() {
        if sec.relocs.is_empty() {
            continue;
        }
        let off = reloc_offsets[i] as usize;
        for (j, entry) in sec.relocs.iter().enumerate() {
            let p = off + j * 8;
            if p + 8 <= buf.len() {
                buf[p..p + 8].copy_from_slice(entry);
            }
        }
    }

    // Write symbol table
    if symoff as usize + nlist_data.len() <= buf.len() {
        buf[symoff as usize..symoff as usize + nlist_data.len()].copy_from_slice(&nlist_data);
    }
    if stroff as usize + strtab.len() <= buf.len() {
        buf[stroff as usize..stroff as usize + strtab.len()].copy_from_slice(&strtab);
    }

    let output_path = layout.symbol_db.args.output();
    std::fs::write(output_path.as_ref(), &buf)
        .map_err(|e| crate::error!("Failed to write: {e}"))?;

    Ok(())
}

/// Validate structural invariants of a Mach-O output binary.
///
/// Called when `WILD_VALIDATE_OUTPUT=1` is set. Parses the output back and checks:
///
/// # Segment invariants
/// - Segment vmaddr is page-aligned (16KB on arm64)
/// - Segment fileoff is page-aligned (when filesize > 0)
/// - Segment file content fits within the file
///
/// # Section invariants
/// - Section addr is within parent segment [vmaddr, vmaddr+vmsize)
/// - Section file offset is within parent segment [fileoff, fileoff+filesize)
/// - Section addr respects its declared alignment
/// - Sections within a segment do not overlap
///
/// # Chained fixups invariants
/// - Page start offsets are within a page (< page_size)
fn validate_macho_output(buf: &[u8]) -> Result {
    use object::read::macho::MachHeader as _;
    use object::read::macho::Section as _;
    use object::read::macho::Segment as _;
    let le = object::Endianness::Little;
    let header = object::macho::MachHeader64::<object::Endianness>::parse(buf, 0)
        .map_err(|e| crate::error!("validate: bad Mach-O header: {e}"))?;
    let mut cmds = header
        .load_commands(le, buf, 0)
        .map_err(|e| crate::error!("validate: bad load commands: {e}"))?;

    let file_len = buf.len() as u64;

    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((seg, seg_data))) = cmd.segment_64() {
            let segname = crate::macho::trim_nul(&seg.segname);
            let segname_str = String::from_utf8_lossy(segname);

            let vm_addr = seg.vmaddr.get(le);
            let vm_size = seg.vmsize.get(le);
            let file_off = seg.fileoff.get(le);
            let file_size = seg.filesize.get(le);

            // Segment vmaddr page alignment
            if vm_addr % PAGE_SIZE != 0 && !segname.is_empty() {
                crate::bail!(
                    "validate: segment {segname_str} vmaddr {vm_addr:#x} not page-aligned"
                );
            }

            // Segment fileoff page alignment
            if file_size > 0 && file_off % PAGE_SIZE != 0 {
                crate::bail!(
                    "validate: segment {segname_str} fileoff {file_off:#x} not page-aligned"
                );
            }

            // Segment fits in file
            if file_off + file_size > file_len {
                crate::bail!(
                    "validate: segment {segname_str} extends beyond file \
                     ({file_off:#x}+{file_size:#x} > {file_len:#x})"
                );
            }

            // Section invariants
            if let Ok(sections) = seg.sections(le, seg_data) {
                let mut prev_end: u64 = 0;
                for sec in sections {
                    let sect_raw = sec.sectname();
                    let sect_name = String::from_utf8_lossy(crate::macho::trim_nul(sect_raw));

                    let sec_addr = sec.addr(le);
                    let sec_size = sec.size(le);
                    let sec_offset = sec.offset(le) as u64;
                    let sec_align = sec.align(le);

                    // Section addr within segment
                    if sec_size > 0
                        && (sec_addr < vm_addr || sec_addr + sec_size > vm_addr + vm_size)
                    {
                        crate::bail!(
                            "validate: section {segname_str},{sect_name} addr \
                             {sec_addr:#x}+{sec_size:#x} outside segment \
                             [{vm_addr:#x}..{:#x})",
                            vm_addr + vm_size
                        );
                    }

                    // Section file offset within segment
                    let sec_type = sec.flags(le) & 0xFF;
                    let is_zerofill = sec_type == 0x01 || sec_type == 0x0C;
                    if sec_size > 0 && !is_zerofill && sec_offset > 0 && file_size > 0 {
                        if sec_offset < file_off || sec_offset + sec_size > file_off + file_size {
                            crate::bail!(
                                "validate: section {segname_str},{sect_name} file range \
                                 [{sec_offset:#x}..{:#x}) outside segment \
                                 [{file_off:#x}..{:#x})",
                                sec_offset + sec_size,
                                file_off + file_size
                            );
                        }
                    }

                    // Section alignment
                    if sec_size > 0 && sec_align > 0 {
                        let alignment = 1u64 << sec_align;
                        if sec_addr % alignment != 0 {
                            crate::bail!(
                                "validate: section {segname_str},{sect_name} addr \
                                 {sec_addr:#x} not aligned to 2^{sec_align} ({alignment})"
                            );
                        }
                    }

                    // No overlap with previous section
                    if sec_size > 0 && sec_addr > 0 && sec_addr < prev_end {
                        crate::bail!(
                            "validate: section {segname_str},{sect_name} at {sec_addr:#x} \
                             overlaps previous section ending at {prev_end:#x}"
                        );
                    }
                    if sec_size > 0 {
                        prev_end = sec_addr + sec_size;
                    }
                }
            }
        }

        // Check TLS invariants for __thread_vars descriptors.
        if let Ok(Some((seg, seg_data))) = cmd.segment_64() {
            if crate::macho::trim_nul(&seg.segname) == b"__DATA" {
                if let Ok(sections) = seg.sections(le, seg_data) {
                    let mut tdata_size = 0u64;
                    let mut tbss_size = 0u64;
                    let mut tvars_foff = 0usize;
                    let mut tvars_count = 0usize;
                    for sec in sections {
                        let sec_type = sec.flags(le) & 0xFF;
                        let size = sec.size(le);
                        match sec_type {
                            0x11 => tdata_size = size,
                            0x12 => tbss_size = size,
                            0x13 => {
                                tvars_foff = sec.offset(le) as usize;
                                tvars_count = size as usize / 24;
                            }
                            _ => {}
                        }
                    }
                    let tls_total = tdata_size + tbss_size;

                    if tvars_count > 0 && tls_total > 0 {
                        let mut offsets = Vec::new();
                        for i in 0..tvars_count {
                            let base = tvars_foff + i * 24;
                            if base + 24 > buf.len() {
                                break;
                            }
                            let key =
                                u64::from_le_bytes(buf[base + 8..base + 16].try_into().unwrap());
                            let offset =
                                u64::from_le_bytes(buf[base + 16..base + 24].try_into().unwrap());

                            // Invariant: key must be 0 (dyld manages it at runtime)
                            if key != 0 {
                                crate::bail!(
                                    "validate: TLV descriptor [{i}] key={key:#x} (must be 0)"
                                );
                            }

                            // Invariant: offset must not have fixup encoding
                            // (high bits in 51-63 must be 0)
                            if (offset >> 51) != 0 {
                                crate::bail!(
                                    "validate: TLV descriptor [{i}] offset={offset:#x} \
                                     has fixup encoding (bits 51+ set)"
                                );
                            }

                            // Invariant: offset must be within TLS block
                            if offset >= tls_total {
                                crate::bail!(
                                    "validate: TLV descriptor [{i}] offset={offset:#x} \
                                     exceeds TLS block size {tls_total:#x} \
                                     (thread_data={tdata_size:#x} + thread_bss={tbss_size:#x})"
                                );
                            }

                            offsets.push(offset);
                        }

                        // Invariant: no two TLV descriptors should share the same offset
                        // (unless both are zero — which indicates a bug but may not crash)
                        offsets.sort();
                        for w in offsets.windows(2) {
                            if w[0] == w[1] && tvars_count > 1 {
                                crate::bail!(
                                    "validate: duplicate TLV offset {:#x} — \
                                     two thread-locals share the same TLS slot",
                                    w[0]
                                );
                            }
                        }
                    }
                }
            }
        }

        // Check LC_SYMTAB
        if let Ok(Some(symtab)) = cmd.symtab() {
            let symoff = symtab.symoff.get(le) as u64;
            let nsyms = symtab.nsyms.get(le) as u64;
            let stroff = symtab.stroff.get(le) as u64;
            let strsize = symtab.strsize.get(le) as u64;
            let sym_end = symoff + nsyms * 16;
            if sym_end > file_len {
                crate::bail!(
                    "validate: LC_SYMTAB extends beyond file \
                     (symoff {symoff:#x} + {nsyms}*16 = {sym_end:#x} > {file_len:#x})"
                );
            }
            if stroff + strsize > file_len {
                crate::bail!(
                    "validate: LC_SYMTAB strtab extends beyond file \
                     (stroff {stroff:#x} + {strsize:#x} > {file_len:#x})"
                );
            }
        }
    }

    // Symbol-section consistency check: every defined symbol's n_value must
    // fall within the address range of the section identified by its n_sect.
    // This catches layout bugs where a symbol is resolved using the wrong
    // section's output address.
    {
        let mut cmds_sym = header
            .load_commands(le, buf, 0)
            .map_err(|e| crate::error!("validate: {e}"))?;
        // Collect all sections with their address ranges
        let mut section_ranges: Vec<(u64, u64)> = Vec::new(); // (addr, addr+size)
        while let Ok(Some(cmd)) = cmds_sym.next() {
            if let Ok(Some((seg, seg_data))) = cmd.segment_64() {
                if let Ok(sections) = seg.sections(le, seg_data) {
                    for sec in sections {
                        let addr = sec.addr(le);
                        let size = sec.size(le);
                        section_ranges.push((addr, addr + size));
                    }
                }
            }
            if let Ok(Some(symtab)) = cmd.symtab() {
                let symoff = symtab.symoff.get(le) as usize;
                let nsyms = symtab.nsyms.get(le) as usize;
                let stroff = symtab.stroff.get(le) as usize;
                for i in 0..nsyms {
                    let sym_off = symoff + i * 16;
                    if sym_off + 16 > buf.len() {
                        break;
                    }
                    let n_strx = u32::from_le_bytes(buf[sym_off..sym_off + 4].try_into().unwrap());
                    let n_type = buf[sym_off + 4];
                    let n_sect = buf[sym_off + 5];
                    let n_value =
                        u64::from_le_bytes(buf[sym_off + 8..sym_off + 16].try_into().unwrap());

                    // Only check defined symbols in a section (N_SECT = 0x0e).
                    // Skip stab entries (high bits set in n_type).
                    if (n_type & 0xE0) != 0 || (n_type & 0x0e) != 0x0e || n_sect == 0 {
                        continue;
                    }
                    let sec_idx = n_sect as usize - 1;
                    if sec_idx >= section_ranges.len() {
                        continue;
                    }
                    let (sec_start, sec_end) = section_ranges[sec_idx];
                    if n_value < sec_start || n_value > sec_end {
                        // Get symbol name for the error message
                        let name = if (n_strx as usize) < buf.len() - stroff {
                            let name_start = stroff + n_strx as usize;
                            let name_end = buf[name_start..]
                                .iter()
                                .position(|&b| b == 0)
                                .map(|p| name_start + p)
                                .unwrap_or(name_start);
                            String::from_utf8_lossy(&buf[name_start..name_end]).to_string()
                        } else {
                            format!("<sym {i}>")
                        };
                        crate::bail!(
                            "validate: symbol '{name}' n_value={n_value:#x} is outside \
                             section {sec_idx} range [{sec_start:#x}..{sec_end:#x})"
                        );
                    }
                }
            }
        }
    }

    // Global section file-offset overlap check: no two sections should
    // write to the same file bytes. This catches bugs where multiple input
    // sections map to overlapping parts of the same output section.
    {
        let mut cmds2 = header
            .load_commands(le, buf, 0)
            .map_err(|e| crate::error!("validate: bad load commands: {e}"))?;
        let mut all_sections: Vec<(u64, u64, String)> = Vec::new();
        while let Ok(Some(cmd)) = cmds2.next() {
            if let Ok(Some((seg, seg_data))) = cmd.segment_64() {
                let segname = String::from_utf8_lossy(crate::macho::trim_nul(&seg.segname));
                if let Ok(sections) = seg.sections(le, seg_data) {
                    for sec in sections {
                        let sectname =
                            String::from_utf8_lossy(crate::macho::trim_nul(sec.sectname()));
                        let sec_offset = sec.offset(le) as u64;
                        let sec_size = sec.size(le);
                        let sec_type = sec.flags(le) & 0xFF;
                        // Skip zerofill sections (no file data)
                        if sec_size > 0 && sec_offset > 0 && sec_type != 0x01 && sec_type != 0x0C {
                            all_sections.push((
                                sec_offset,
                                sec_size,
                                format!("{segname},{sectname}"),
                            ));
                        }
                    }
                }
            }
        }
        all_sections.sort_by_key(|s| s.0);
        for w in all_sections.windows(2) {
            let (off1, size1, ref name1) = w[0];
            let (off2, _size2, ref name2) = w[1];
            if off1 + size1 > off2 {
                crate::bail!(
                    "validate: section file ranges overlap: \
                     {name1} [{off1:#x}..{:#x}) and {name2} [{off2:#x}..)",
                    off1 + size1
                );
            }
        }
    }

    // Validate chained fixup chains: walk every chain entry and verify
    // rebase targets are within the image and strides stay within pages.
    validate_chained_fixups(buf)?;

    Ok(())
}

/// Walk all chained fixup chains and validate each entry.
fn validate_chained_fixups(buf: &[u8]) -> Result {
    use object::read::macho::MachHeader as _;
    let le = object::Endianness::Little;
    let header = match object::macho::MachHeader64::<object::Endianness>::parse(buf, 0) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };
    let mut cmds = match header.load_commands(le, buf, 0) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };

    // Find LC_DYLD_CHAINED_FIXUPS and the DATA segment
    let mut cf_off = 0u32;
    let mut cf_size = 0u32;
    let mut data_fileoff = 0u64;
    let mut _data_vmaddr = 0u64;
    let mut image_end = 0u64; // highest vmaddr + vmsize

    // Scan load commands manually for chained fixups offset.
    {
        let mut off = 32usize; // after Mach-O 64 header
        let ncmds = u32::from_le_bytes(buf[16..20].try_into().unwrap_or([0; 4])) as usize;
        for _ in 0..ncmds {
            if off + 8 > buf.len() {
                break;
            }
            let cmd_val = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            let cmdsize = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap()) as usize;
            if cmd_val == 0x8000_0034 && off + 16 <= buf.len() {
                cf_off = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
                cf_size = u32::from_le_bytes(buf[off + 12..off + 16].try_into().unwrap());
            }
            off += cmdsize;
        }
    }

    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((seg, _))) = cmd.segment_64() {
            let va = seg.vmaddr.get(le);
            let vs = seg.vmsize.get(le);
            image_end = image_end.max(va + vs);
            let segname = crate::macho::trim_nul(&seg.segname);
            if segname == b"__DATA" {
                data_fileoff = seg.fileoff.get(le);
                _data_vmaddr = va;
            }
        }
    }

    if cf_off == 0 || cf_size == 0 {
        return Ok(()); // no chained fixups
    }

    let cf = match buf.get(cf_off as usize..(cf_off + cf_size) as usize) {
        Some(d) => d,
        None => return Ok(()),
    };
    if cf.len() < 32 {
        return Ok(());
    }

    let starts_offset = u32::from_le_bytes(cf[4..8].try_into().unwrap()) as usize;
    let imports_count = u32::from_le_bytes(cf[16..20].try_into().unwrap());

    if starts_offset + 4 > cf.len() {
        return Ok(());
    }
    let seg_count = u32::from_le_bytes(cf[starts_offset..starts_offset + 4].try_into().unwrap());

    for s in 0..seg_count as usize {
        let seg_off_pos = starts_offset + 4 + s * 4;
        if seg_off_pos + 4 > cf.len() {
            break;
        }
        let seg_off =
            u32::from_le_bytes(cf[seg_off_pos..seg_off_pos + 4].try_into().unwrap()) as usize;
        if seg_off == 0 {
            continue;
        }
        let ss = starts_offset + seg_off;
        if ss + 22 > cf.len() {
            continue;
        }
        let page_size = u16::from_le_bytes(cf[ss + 4..ss + 6].try_into().unwrap()) as u64;
        let page_count = u16::from_le_bytes(cf[ss + 20..ss + 22].try_into().unwrap()) as usize;

        if page_size == 0 {
            continue;
        }

        for p in 0..page_count {
            let ps_pos = ss + 22 + p * 2;
            if ps_pos + 2 > cf.len() {
                break;
            }
            let ps = u16::from_le_bytes(cf[ps_pos..ps_pos + 2].try_into().unwrap());
            if ps == 0xFFFF {
                continue;
            }
            if ps as u64 >= page_size {
                crate::bail!(
                    "validate: chained fixup page start {ps:#x} >= page_size {page_size:#x} \
                     (seg {s}, page {p})"
                );
            }

            // Walk the chain
            let page_file_off = data_fileoff as usize + p * page_size as usize;
            let mut file_off = page_file_off + ps as usize;
            let mut chain_count = 0u32;
            loop {
                if file_off + 8 > buf.len() {
                    crate::bail!(
                        "validate: fixup chain entry at file offset {file_off:#x} \
                         beyond file end (seg {s}, page {p}, entry {chain_count})"
                    );
                }
                let val = u64::from_le_bytes(buf[file_off..file_off + 8].try_into().unwrap());
                let bind = (val >> 63) & 1;
                let next_stride = ((val >> 51) & 0xFFF) as usize;

                if bind != 0 {
                    let ordinal = (val & 0xFF_FFFF) as u32;
                    if ordinal >= imports_count {
                        crate::bail!(
                            "validate: bind ordinal {ordinal} >= imports_count {imports_count} \
                             at file offset {file_off:#x} (seg {s}, page {p})"
                        );
                    }
                } else {
                    let target = val & 0xF_FFFF_FFFF;
                    if target > 0 && target > image_end {
                        crate::bail!(
                            "validate: rebase target {target:#x} beyond image end {image_end:#x} \
                             at file offset {file_off:#x} (seg {s}, page {p})"
                        );
                    }
                }

                chain_count += 1;
                if next_stride == 0 {
                    break;
                }

                let next_off = file_off + next_stride * 4;
                let next_in_page = next_off - page_file_off;
                if next_in_page >= page_size as usize {
                    crate::bail!(
                        "validate: fixup chain crosses page boundary at file offset \
                         {file_off:#x}, next at +{} bytes = offset {next_in_page:#x} in page \
                         (page_size={page_size:#x}, seg {s}, page {p})",
                        next_stride * 4
                    );
                }
                file_off = next_off;
            }
        }
    }

    Ok(())
}
