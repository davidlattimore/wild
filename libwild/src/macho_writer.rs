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

pub(crate) fn write_direct<A: Arch<Platform = MachO>>(
    layout: &Layout<'_, MachO>,
) -> Result {
    let (mappings, alloc_size) = build_mappings_and_size(layout);
    let mut buf = vec![0u8; alloc_size];
    let final_size = write_macho::<A>(&mut buf, layout, &mappings)?;
    buf.truncate(final_size);

    let output_path = layout.symbol_db.args.output();
    std::fs::write(output_path.as_ref(), &buf)
        .map_err(|e| crate::error!("Failed to write: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(output_path.as_ref(),
            std::fs::Permissions::from_mode(0o755));
    }
    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("codesign")
            .args(["-s", "-", "--force"])
            .arg(output_path.as_ref())
            .status();
        if let Ok(s) = &status {
            if !s.success() {
                tracing::warn!("codesign failed with status: {s}");
            }
        }
    }
    Ok(())
}

/// Build exactly 2 segment mappings (TEXT + merged DATA) from pipeline layout.
fn build_mappings_and_size(layout: &Layout<'_, MachO>) -> (Vec<SegmentMapping>, usize) {
    let mut raw: Vec<(u64, u64, u64)> = Vec::new();
    let mut file_cursor: u64 = 0;
    for seg in &layout.segment_layouts.segments {
        if seg.sizes.file_size == 0 && seg.sizes.mem_size == 0 { continue; }
        let file_off = if raw.is_empty() { 0 } else { align_to(file_cursor, PAGE_SIZE) };
        let file_sz = align_to(seg.sizes.file_size as u64, PAGE_SIZE);
        raw.push((seg.sizes.mem_offset, seg.sizes.mem_offset + seg.sizes.mem_size, file_off));
        file_cursor = file_off + file_sz;
    }

    let mut mappings = Vec::new();
    if let Some(&(vm_start, vm_end, file_off)) = raw.first() {
        mappings.push(SegmentMapping { vm_start, vm_end, file_offset: file_off });
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
    let text_filesize = mappings.first().map_or(PAGE_SIZE, |m|
        align_to(m.vm_end - m.vm_start, PAGE_SIZE));
    let linkedit_offset = if mappings.len() > 1 {
        let data_fileoff = mappings[1].file_offset;
        let data_filesize = align_to(
            mappings.iter().skip(1).map(|m| m.file_offset + (m.vm_end - m.vm_start))
                .max().unwrap() - data_fileoff, PAGE_SIZE);
        data_fileoff + data_filesize
    } else {
        text_filesize
    };
    // Estimate LINKEDIT size: chained fixups + symtab + strtab + exports trie.
    // For dylibs with many exports, 8KB is not enough.
    let n_exports = layout.dynamic_symbol_definitions.len();
    let linkedit_estimate = 8192 + n_exports * 256;
    let total = linkedit_offset as usize + linkedit_estimate.max(8192);
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
}

/// An imported symbol name and its dylib ordinal.
struct ImportEntry {
    name: Vec<u8>,
    /// 1 = libSystem, 2+ = extra dylibs, 0xFE = flat lookup (search all dylibs).
    lib_ordinal: u8,
}

/// Determine the lib ordinal for a symbol name.
/// If there are extra dylibs (beyond libSystem), we use flat lookup (0xFE)
/// since we don't yet track which dylib exports which symbol.
fn lib_ordinal_for_symbol(has_extra_dylibs: bool) -> u8 {
    if has_extra_dylibs { 0xFE } else { 1 }
}

/// Returns the actual final file size.
fn write_macho<A: Arch<Platform = MachO>>(
    out: &mut [u8],
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
) -> Result<usize> {
    let le = object::Endianness::Little;
    let header_layout = layout.section_layouts.get(output_section_id::FILE_HEADER);

    // Collect fixups during section writing and stub generation
    let mut rebase_fixups: Vec<RebaseFixup> = Vec::new();
    let mut bind_fixups: Vec<BindFixup> = Vec::new();
    let mut imports: Vec<ImportEntry> = Vec::new();
    let has_extra_dylibs = !layout.symbol_db.args.extra_dylibs.is_empty();

    // Copy section data and apply relocations
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            if let FileLayout::Object(obj) = file_layout {
                write_object_sections(out, obj, layout, mappings, le,
                    &mut rebase_fixups, &mut bind_fixups, &mut imports, has_extra_dylibs)?;
            }
        }
    }

    // Write PLT stubs and collect bind fixups for imported symbols
    write_stubs_and_got::<A>(out, layout, mappings, &mut bind_fixups, &mut imports, has_extra_dylibs)?;

    // Populate GOT entries for non-import symbols
    write_got_entries(out, layout, mappings, &mut rebase_fixups)?;

    // Build chained fixup data: merge rebase + bind, encode per-page chains
    rebase_fixups.sort_by_key(|f| f.file_offset);
    bind_fixups.sort_by_key(|f| f.file_offset);

    let data_seg_start = if mappings.len() > 1 { mappings[1].file_offset as usize } else { usize::MAX };
    let data_seg_end = if mappings.len() > 1 {
        mappings[1].file_offset as usize + (mappings[1].vm_end - mappings[1].vm_start) as usize
    } else { 0 };

    let image_base = if layout.symbol_db.args.is_dylib { 0u64 } else { PAGEZERO_SIZE };
    let mut all_data_fixups: Vec<(usize, u64)> = Vec::new();
    for f in &rebase_fixups {
        if f.file_offset < data_seg_start || f.file_offset >= data_seg_end { continue; }
        let target_offset = f.target.wrapping_sub(image_base);
        all_data_fixups.push((f.file_offset, target_offset & 0xF_FFFF_FFFF));
    }
    for f in &bind_fixups {
        if f.file_offset < data_seg_start || f.file_offset >= data_seg_end { continue; }
        let encoded = (1u64 << 63) | (f.import_index as u64 & 0xFF_FFFF);
        all_data_fixups.push((f.file_offset, encoded));
    }
    all_data_fixups.sort_by_key(|&(off, _)| off);

    // Encode per-page chains
    let data_seg_file_off = if mappings.len() > 1 { mappings[1].file_offset } else { 0 };
    for i in 0..all_data_fixups.len() {
        let (file_off, mut encoded) = all_data_fixups[i];
        let next_stride = if i + 1 < all_data_fixups.len() {
            let cur_page = (file_off as u64 - data_seg_file_off) / PAGE_SIZE;
            let next_page = (all_data_fixups[i + 1].0 as u64 - data_seg_file_off) / PAGE_SIZE;
            if cur_page == next_page {
                ((all_data_fixups[i + 1].0 - file_off) / 4) as u64
            } else { 0 }
        } else { 0 };

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
    } else { 0 };

    let cf_data_size = if !has_fixups {
        (32 + 4 + 4 * seg_count + 8).max(48)
    } else {
        let seg_starts_size = 22 + 2 * page_count;
        let imports_size = 4 * n_imports;
        32 + starts_in_image_size + seg_starts_size + imports_size + symbols_pool.len() as u32
    };

    // Write headers
    let header_offset = header_layout.file_offset;
    let chained_fixups_offset = write_headers(out, header_offset, layout, mappings, cf_data_size)?;

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
            write_chained_fixups_header(
                out, cf_off as usize, &all_data_fixups, n_imports,
                &import_name_offsets, &ordinals, &symbols_pool, mappings,
                layout.symbol_db.args.is_dylib,
            )?;
            cf_off as usize + cf_data_size as usize
        }
    } else {
        out.len()
    };

    // For dylibs: write symbol table with exported symbols
    let final_size = if layout.symbol_db.args.is_dylib {
        write_dylib_symtab(out, final_size, layout, mappings)?
    } else {
        final_size
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
        if let Some(res) = layout.symbol_resolutions.iter().nth(sym_id.as_usize()).and_then(|r| r.as_ref()) {
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

    // Write nlist64 entries (16 bytes each, must be 8-byte aligned)
    let symoff = (start + 7) & !7; // align to 8
    let nsyms = entries.len();
    let mut pos = symoff;
    for (i, (_, value)) in entries.iter().enumerate() {
        if pos + 16 > out.len() { break; }
        // nlist64: n_strx (4), n_type (1), n_sect (1), n_desc (2), n_value (8)
        out[pos..pos+4].copy_from_slice(&str_offsets[i].to_le_bytes());
        out[pos+4] = 0x0F; // N_SECT | N_EXT
        out[pos+5] = 1; // n_sect: section 1 (__text)
        out[pos+6..pos+8].copy_from_slice(&0u16.to_le_bytes()); // n_desc
        out[pos+8..pos+16].copy_from_slice(&value.to_le_bytes());
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
        let cmd = u32::from_le_bytes(out[off as usize..off as usize+4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(out[off as usize+4..off as usize+8].try_into().unwrap());
        if cmd == LC_SYMTAB {
            out[off as usize+8..off as usize+12].copy_from_slice(&(symoff as u32).to_le_bytes());
            out[off as usize+12..off as usize+16].copy_from_slice(&(nsyms as u32).to_le_bytes());
            out[off as usize+16..off as usize+20].copy_from_slice(&(stroff as u32).to_le_bytes());
            out[off as usize+20..off as usize+24].copy_from_slice(&(strtab.len() as u32).to_le_bytes());
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
        let cmd = u32::from_le_bytes(out[off as usize..off as usize+4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(out[off as usize+4..off as usize+8].try_into().unwrap());
        match cmd {
            0x19 => { // LC_SEGMENT_64
                let segname = &out[off as usize+8..off as usize+24];
                if segname.starts_with(b"__LINKEDIT") {
                    let linkedit_fileoff = u64::from_le_bytes(
                        out[off as usize+40..off as usize+48].try_into().unwrap());
                    let new_filesize = pos as u64 - linkedit_fileoff;
                    out[off as usize+48..off as usize+56].copy_from_slice(&new_filesize.to_le_bytes());
                    // Update vmsize to cover the content
                    let new_vmsize = align_to(new_filesize, PAGE_SIZE);
                    out[off as usize+32..off as usize+40].copy_from_slice(&new_vmsize.to_le_bytes());
                }
            }
            LC_DYSYMTAB => {
                // DYSYMTAB: ilocalsym nlocalsym iextdefsym nextdefsym iundefsym nundefsym
                let o = off as usize + 8;
                out[o..o+4].copy_from_slice(&0u32.to_le_bytes()); // ilocalsym
                out[o+4..o+8].copy_from_slice(&0u32.to_le_bytes()); // nlocalsym
                out[o+8..o+12].copy_from_slice(&0u32.to_le_bytes()); // iextdefsym
                out[o+12..o+16].copy_from_slice(&(nsyms as u32).to_le_bytes()); // nextdefsym
                out[o+16..o+20].copy_from_slice(&(nsyms as u32).to_le_bytes()); // iundefsym
                out[o+20..o+24].copy_from_slice(&0u32.to_le_bytes()); // nundefsym
            }
            0x8000_0033 => { // LC_DYLD_EXPORTS_TRIE
                out[off as usize+8..off as usize+12].copy_from_slice(&(trie_off as u32).to_le_bytes());
                out[off as usize+12..off as usize+16].copy_from_slice(&(trie.len() as u32).to_le_bytes());
            }
            _ => {}
        }
        off += cmdsize;
    }

    Ok(pos)
}

/// Build a Mach-O export trie for the given symbols.
fn build_export_trie(entries: &[(Vec<u8>, u64)]) -> Vec<u8> {
    if entries.is_empty() { return vec![0, 0]; } // empty root

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
        if val != 0 { byte |= 0x80; }
        buf.push(byte);
        if val == 0 { break; }
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
        let Some(plt_addr) = res.format_specific.plt_address else { continue };
        let Some(got_addr) = res.format_specific.got_address else { continue };

        if let Some(plt_file_off) = vm_addr_to_file_offset(plt_addr, mappings) {
            if plt_file_off + 12 <= out.len() {
                A::write_plt_entry(&mut out[plt_file_off..plt_file_off + 12], got_addr, plt_addr)?;
            }
        }

        if let Some(got_file_off) = vm_addr_to_file_offset(got_addr, mappings) {
            let import_index = imports.len() as u32;
            let symbol_id = SymbolId::from_usize(sym_idx);
            let name = match layout.symbol_db.symbol_name(symbol_id) {
                Ok(n) => n.bytes().to_vec(),
                Err(_) => b"<unknown>".to_vec(),
            };
            imports.push(ImportEntry {
                name,
                lib_ordinal: lib_ordinal_for_symbol(has_extra_dylibs),
            });
            bind_fixups.push(BindFixup { file_offset: got_file_off, import_index });
        }
    }
    Ok(())
}

/// Fill GOT entries with target symbol addresses (for non-import symbols).
/// Also registers rebase fixups so dyld can adjust for ASLR.
fn write_got_entries(
    out: &mut [u8],
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
    rebase_fixups: &mut Vec<RebaseFixup>,
) -> Result {
    for res in layout.symbol_resolutions.iter().flatten() {
        if res.format_specific.plt_address.is_some() { continue; } // handled by stubs
        if let Some(got_vm_addr) = res.format_specific.got_address {
            if let Some(file_off) = vm_addr_to_file_offset(got_vm_addr, mappings) {
                if file_off + 8 <= out.len() {
                    out[file_off..file_off + 8].copy_from_slice(&res.raw_value.to_le_bytes());
                    // Register a rebase fixup so dyld adjusts for ASLR
                    if res.raw_value != 0 {
                        rebase_fixups.push(RebaseFixup {
                            file_offset: file_off,
                            target: res.raw_value,
                        });
                    }
                }
                if res.raw_value != 0 {
                    rebase_fixups.push(RebaseFixup { file_offset: file_off, target: res.raw_value });
                }
            }
        }
    }
    Ok(())
}

/// Copy an object's section data to the output and apply relocations.
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
) -> Result {
    use object::read::macho::Section as MachOSection;

    for (sec_idx, _slot) in obj.sections.iter().enumerate() {
        let section_res = &obj.section_resolutions[sec_idx];
        let Some(output_addr) = section_res.address() else { continue };
        let Some(file_offset) = vm_addr_to_file_offset(output_addr, mappings) else { continue };

        let input_section = match obj.object.sections.get(sec_idx) {
            Some(s) => s,
            None => continue,
        };

        let sec_type = input_section.flags(le) & 0xFF;
        if sec_type == 0x01 || sec_type == 0x0C || sec_type == 0x12 { continue; }

        let input_offset = input_section.offset(le) as usize;
        let input_size = input_section.size(le) as usize;
        if input_size == 0 || input_offset == 0 { continue; }

        let input_data = match obj.object.data.get(input_offset..input_offset + input_size) {
            Some(d) => d,
            None => continue,
        };

        if file_offset + input_size <= out.len() {
            out[file_offset..file_offset + input_size].copy_from_slice(input_data);
        }

        if let Ok(relocs) = input_section.relocations(le, obj.object.data) {
            apply_relocations(out, file_offset, output_addr, relocs, obj, layout, le,
                rebase_fixups, bind_fixups, imports, has_extra_dylibs)?;
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
) -> Result {
    let mut pending_addend: i64 = 0;

    for reloc_raw in relocs {
        let reloc = reloc_raw.info(le);

        if reloc.r_type == 10 { pending_addend = reloc.r_symbolnum as i64; continue; }
        if reloc.r_type == 1 { continue; }

        let addend = pending_addend;
        pending_addend = 0;

        let patch_file_offset = section_file_offset + reloc.r_address as usize;
        let pc_addr = section_vm_addr + reloc.r_address as u64;
        if patch_file_offset + 4 > out.len() { continue; }

        let (target_addr, got_addr, plt_addr) = if reloc.r_extern {
            let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
            let sym_id = obj.symbol_id_range.input_to_id(sym_idx);
            match layout.merged_symbol_resolution(sym_id) {
                Some(res) => (res.raw_value, res.format_specific.got_address, res.format_specific.plt_address),
                None => continue,
            }
        } else {
            // Non-extern: r_symbolnum is 1-based section ordinal.
            // target = output_section_address + addend
            let sec_ord = reloc.r_symbolnum as usize;
            if sec_ord == 0 { continue; }
            let sec_idx = sec_ord - 1;
            let Some(output_sec_addr) = obj.section_resolutions.get(sec_idx).and_then(|r| r.address()) else {
                continue;
            };
            // Return section base; addend is added below along with extern path.
            (output_sec_addr, None, None)
        };

        let target_addr = (target_addr as i64 + addend) as u64;

        match reloc.r_type {
            2 => { // ARM64_RELOC_BRANCH26
                let branch_target = plt_addr.unwrap_or(target_addr);
                let offset = branch_target.wrapping_sub(pc_addr) as i64;
                let imm26 = ((offset >> 2) & 0x03FF_FFFF) as u32;
                let insn = read_u32(out, patch_file_offset);
                write_u32_at(out, patch_file_offset, (insn & 0xFC00_0000) | imm26);
            }
            3 => { write_adrp(out, patch_file_offset, pc_addr, target_addr); }
            4 => { write_pageoff12(out, patch_file_offset, target_addr); }
            5 => { // ARM64_RELOC_GOT_LOAD_PAGE21
                if let Some(got) = got_addr {
                    write_adrp(out, patch_file_offset, pc_addr, got);
                } else {
                    write_adrp(out, patch_file_offset, pc_addr, target_addr);
                }
            }
            6 => { // ARM64_RELOC_GOT_LOAD_PAGEOFF12
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
                    write_u32_at(out, patch_file_offset, 0x9100_0000 | (page_off << 10) | (rn << 5) | rd);
                }
            }
            8 => { write_adrp(out, patch_file_offset, pc_addr, target_addr); }
            9 => { // ARM64_RELOC_TLVP_LOAD_PAGEOFF12 -> relax to ADD
                let page_off = (target_addr & 0xFFF) as u32;
                let insn = read_u32(out, patch_file_offset);
                let rd = insn & 0x1F;
                let rn = (insn >> 5) & 0x1F;
                write_u32_at(out, patch_file_offset, 0x9100_0000 | (page_off << 10) | (rn << 5) | rd);
            }
            0 if reloc.r_length == 3 => { // ARM64_RELOC_UNSIGNED 64-bit
                if patch_file_offset + 8 <= out.len() {
                    if reloc.r_extern && target_addr == 0 {
                        // Extern undefined symbol (e.g. _tlv_bootstrap): bind fixup
                        let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
                        let sym_id = obj.symbol_id_range.input_to_id(sym_idx);
                        let name = match layout.symbol_db.symbol_name(sym_id) {
                            Ok(n) => n.bytes().to_vec(),
                            Err(_) => b"<unknown>".to_vec(),
                        };
                        let import_index = imports.len() as u32;
                        imports.push(ImportEntry {
                            name,
                            lib_ordinal: lib_ordinal_for_symbol(has_extra_dylibs),
                        });
                        bind_fixups.push(BindFixup { file_offset: patch_file_offset, import_index });
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
                            // TLS offset relative to the GLOBAL TLS template start.
                            // The template is the TDATA section content (init data for
                            // all TLS variables across all objects) followed by TBSS.
                            let tls_init_start = tdata.mem_offset;
                            let tls_init_size = tdata.mem_size;
                            let tls_offset = if in_tbss {
                                let aligned_init = (tls_init_size + 7) & !7;
                                aligned_init + target_addr.saturating_sub(tbss.mem_offset)
                            } else {
                                target_addr.saturating_sub(tls_init_start)
                            };
                            out[patch_file_offset..patch_file_offset + 8]
                                .copy_from_slice(&tls_offset.to_le_bytes());
                        } else {
                            rebase_fixups.push(RebaseFixup {
                                file_offset: patch_file_offset, target: target_addr,
                            });
                        }
                    }
                }
            }
            7 if reloc.r_length == 2 && reloc.r_pcrel => { // ARM64_RELOC_POINTER_TO_GOT
                if let Some(got) = got_addr {
                    let delta = (got as i64 - pc_addr as i64) as i32;
                    if patch_file_offset + 4 <= out.len() {
                        out[patch_file_offset..patch_file_offset + 4].copy_from_slice(&delta.to_le_bytes());
                    }
                } else {
                    let delta = (target_addr as i64 - pc_addr as i64) as i32;
                    if patch_file_offset + 4 <= out.len() {
                        out[patch_file_offset..patch_file_offset + 4].copy_from_slice(&delta.to_le_bytes());
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
    symbols_pool: &[u8],
    mappings: &[SegmentMapping],
    is_dylib: bool,
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
        (m.file_offset, ((mem_size + PAGE_SIZE - 1) / PAGE_SIZE) as u16)
    } else {
        (0, 0)
    };

    let seg_starts_size = 22 + 2 * page_count as usize;
    let seg_starts_offset_in_image = starts_in_image_size as u32;

    let imports_table_offset = starts_offset + starts_in_image_size as u32 + seg_starts_size as u32;
    let imports_size = 4 * n_imports;
    let symbols_offset = imports_table_offset + imports_size;

    let w = &mut out[cf_offset..];

    w[0..4].copy_from_slice(&0u32.to_le_bytes());
    w[4..8].copy_from_slice(&starts_offset.to_le_bytes());
    w[8..12].copy_from_slice(&imports_table_offset.to_le_bytes());
    w[12..16].copy_from_slice(&symbols_offset.to_le_bytes());
    w[16..20].copy_from_slice(&n_imports.to_le_bytes());
    w[20..24].copy_from_slice(&1u32.to_le_bytes());
    w[24..28].copy_from_slice(&0u32.to_le_bytes());

    let si = starts_offset as usize;
    w[si..si+4].copy_from_slice(&seg_count.to_le_bytes());
    for seg in 0..seg_count as usize {
        let off: u32 = if seg == data_seg_idx { seg_starts_offset_in_image } else { 0 };
        w[si + 4 + seg * 4..si + 4 + seg * 4 + 4].copy_from_slice(&off.to_le_bytes());
    }

    let ss = si + seg_starts_offset_in_image as usize;
    w[ss..ss+4].copy_from_slice(&(seg_starts_size as u32).to_le_bytes());
    w[ss+4..ss+6].copy_from_slice(&(PAGE_SIZE as u16).to_le_bytes());
    w[ss+6..ss+8].copy_from_slice(&6u16.to_le_bytes());
    let image_base = if mappings.first().map_or(false, |m| m.vm_start >= PAGEZERO_SIZE) { PAGEZERO_SIZE } else { 0 };
    let seg_offset_val: u64 = if mappings.len() > 1 { mappings[1].vm_start.wrapping_sub(image_base) } else { 0 };
    w[ss+8..ss+16].copy_from_slice(&seg_offset_val.to_le_bytes());
    w[ss+16..ss+20].copy_from_slice(&0u32.to_le_bytes());
    w[ss+20..ss+22].copy_from_slice(&page_count.to_le_bytes());

    let mut page_starts = vec![0xFFFFu16; page_count as usize];
    for &(file_off, _) in all_fixups {
        if data_seg_file_offset == 0 || (file_off as u64) < data_seg_file_offset { continue; }
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
    for (i, &name_off) in import_name_offsets.iter().enumerate() {
        let ordinal = import_ordinals[i] as u32;
        let import_val: u32 = ordinal | ((name_off & 0x7F_FFFF) << 9);
        w[it + i * 4..it + i * 4 + 4].copy_from_slice(&import_val.to_le_bytes());
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
    write_u32_at(out, offset, (insn & 0x9F00_001F) | ((imm & 0x1F_FFFC) << 3) | ((imm & 0x3) << 29));
}

fn write_pageoff12(out: &mut [u8], offset: usize, target: u64) {
    let page_off = (target & 0xFFF) as u32;
    let insn = read_u32(out, offset);
    let shift = if (insn & 0x3B00_0000) == 0x3900_0000 { (insn >> 30) & 0x3 } else { 0 };
    let imm12 = (page_off >> shift) & 0xFFF;
    write_u32_at(out, offset, (insn & 0xFFC0_03FF) | (imm12 << 10));
}

/// Write Mach-O headers. Returns the chained fixups file offset.
fn write_headers(
    out: &mut [u8],
    offset: usize,
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
    chained_fixups_data_size: u32,
) -> Result<Option<u64>> {
    let text_vm_start = mappings.first().map_or(PAGEZERO_SIZE, |m| m.vm_start);
    let text_vm_end = mappings.first().map_or(PAGEZERO_SIZE + PAGE_SIZE, |m| m.vm_end);
    let text_filesize = align_to(text_vm_end - text_vm_start, PAGE_SIZE);

    let has_data = mappings.len() > 1;
    let data_vmaddr = mappings.get(1).map_or(0, |m| m.vm_start);
    let data_vm_end = mappings.iter().skip(1).map(|m| m.vm_end).max().unwrap_or(data_vmaddr);
    let data_vmsize = align_to(data_vm_end - data_vmaddr, PAGE_SIZE);
    let data_fileoff = mappings.get(1).map_or(0, |m| m.file_offset);
    let data_filesize = if has_data {
        align_to(mappings.iter().skip(1).map(|m| m.file_offset + (m.vm_end - m.vm_start)).max().unwrap() - data_fileoff, PAGE_SIZE)
    } else { 0 };

    let text_layout = layout.section_layouts.get(output_section_id::TEXT);
    let entry_addr = layout.entry_symbol_address().unwrap_or(0);
    let entry_offset = vm_addr_to_file_offset(entry_addr, mappings).unwrap_or(text_layout.file_offset);

    let tdata_layout = layout.section_layouts.get(output_section_id::TDATA);
    let tbss_layout = layout.section_layouts.get(output_section_id::TBSS);
    let has_tlv = tdata_layout.mem_size > 0 || tbss_layout.mem_size > 0;
    let has_tvars = has_tlv;

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
                                    if rustc_addr == 0 || addr < rustc_addr { rustc_addr = addr; }
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
    let mut w = Writer { buf: out, pos: offset };
    let dylinker_cmd_size = align8((12 + DYLD_PATH.len() + 1) as u32);
    let dylib_cmd_size = align8((24 + LIBSYSTEM_PATH.len() + 1) as u32);

    let is_dylib = layout.symbol_db.args.is_dylib;
    let install_name = if is_dylib {
        layout.symbol_db.args.output().to_string_lossy().into_owned()
    } else { String::new() };
    let id_dylib_cmd_size = if is_dylib { align8(24 + install_name.len() as u32 + 1) } else { 0 };

    let mut ncmds = 0u32;
    let mut cmdsize = 0u32;
    let add_cmd = |n: &mut u32, s: &mut u32, size: u32| { *n += 1; *s += size; };
    if !is_dylib { add_cmd(&mut ncmds, &mut cmdsize, 72); } // PAGEZERO (exe only)
    let rustc_in_text = has_rustc && rustc_addr < text_vm_start + text_filesize;
    let text_nsects = 1 + if rustc_in_text { 1u32 } else { 0 };
    add_cmd(&mut ncmds, &mut cmdsize, 72 + 80 * text_nsects); // TEXT
    let init_array_layout = layout.section_layouts.get(output_section_id::INIT_ARRAY);
    let has_init_array = init_array_layout.mem_size > 0;
    if has_data {
        let mut data_nsects = if has_tvars { 2u32 } else { 0 };
        if has_rustc { data_nsects += 1; }
        if has_init_array { data_nsects += 1; }
        add_cmd(&mut ncmds, &mut cmdsize, 72 + 80 * data_nsects);
    }
    add_cmd(&mut ncmds, &mut cmdsize, 72); // LINKEDIT
    if is_dylib {
        add_cmd(&mut ncmds, &mut cmdsize, id_dylib_cmd_size); // LC_ID_DYLIB
        add_cmd(&mut ncmds, &mut cmdsize, 24); // LC_UUID
    } else {
        add_cmd(&mut ncmds, &mut cmdsize, 24); // LC_MAIN
    }
    if !is_dylib { add_cmd(&mut ncmds, &mut cmdsize, dylinker_cmd_size); }
    add_cmd(&mut ncmds, &mut cmdsize, dylib_cmd_size); // libSystem
    let extra_dylibs = &layout.symbol_db.args.extra_dylibs;
    let extra_dylib_sizes: Vec<u32> = extra_dylibs
        .iter()
        .map(|p| align8(24 + p.len() as u32 + 1))
        .collect();
    for &sz in &extra_dylib_sizes {
        add_cmd(&mut ncmds, &mut cmdsize, sz);
    }
    add_cmd(&mut ncmds, &mut cmdsize, 24); // SYMTAB
    add_cmd(&mut ncmds, &mut cmdsize, 80); // DYSYMTAB
    add_cmd(&mut ncmds, &mut cmdsize, 32);
    add_cmd(&mut ncmds, &mut cmdsize, 16);
    add_cmd(&mut ncmds, &mut cmdsize, 16);

    let filetype = if is_dylib { 6u32 } else { MH_EXECUTE }; // MH_DYLIB = 6
    w.u32(MH_MAGIC_64); w.u32(CPU_TYPE_ARM64); w.u32(CPU_SUBTYPE_ARM64_ALL);
    w.u32(filetype); w.u32(ncmds); w.u32(cmdsize);
    let mut flags = MH_PIE | MH_TWOLEVEL | MH_DYLDLINK;
    if has_tlv { flags |= 0x0080_0000; } // MH_HAS_TLV_DESCRIPTORS
    w.u32(flags); w.u32(0);

    if !is_dylib {
        w.segment(b"__PAGEZERO", 0, PAGEZERO_SIZE, 0, 0, 0, 0, 0);
    }

    // __TEXT — include .rustc section if it falls in TEXT range
    w.u32(LC_SEGMENT_64); w.u32(72 + 80 * text_nsects); w.name16(b"__TEXT");
    w.u64(text_vm_start); w.u64(text_filesize); w.u64(0); w.u64(text_filesize);
    w.u32(VM_PROT_READ | VM_PROT_EXECUTE); w.u32(VM_PROT_READ | VM_PROT_EXECUTE);
    w.u32(text_nsects); w.u32(0);
    w.name16(b"__text"); w.name16(b"__TEXT");
    w.u64(text_layout.mem_offset); w.u64(text_layout.mem_size);
    w.u32(text_layout.file_offset as u32); w.u32(2);
    w.u32(0); w.u32(0); w.u32(0x80000400); w.u32(0); w.u32(0); w.u32(0);
    if rustc_in_text {
        let rustc_foff = vm_addr_to_file_offset(rustc_addr, mappings)
            .unwrap_or(0) as u32;
        w.name16(b".rustc"); w.name16(b"__TEXT");
        w.u64(rustc_addr); w.u64(rustc_size);
        w.u32(rustc_foff); w.u32(0);
        w.u32(0); w.u32(0); w.u32(0); w.u32(0); w.u32(0); w.u32(0);
    }

    if has_data {
        let mut nsects = if has_tvars { 2u32 } else { 0 };
        if has_rustc { nsects += 1; }
        if has_init_array { nsects += 1; }
        let data_cmd_size = 72 + 80 * nsects;
        w.u32(LC_SEGMENT_64); w.u32(data_cmd_size); w.name16(b"__DATA");
        w.u64(data_vmaddr); w.u64(data_vmsize); w.u64(data_fileoff); w.u64(data_filesize);
        w.u32(VM_PROT_READ | VM_PROT_WRITE); w.u32(VM_PROT_READ | VM_PROT_WRITE);
        w.u32(nsects); w.u32(0);
        if has_tvars {
            // Section addresses must be within [data_vmaddr, data_vmaddr+data_vmsize).
            // Clamp to segment range.
            // Find actual __thread_vars address by scanning object sections
            let le = object::Endianness::Little;
            let mut tvars_addr = u64::MAX;
            let mut tvars_size = 0u64;
            let mut tdata_addr = u64::MAX;
            let mut tdata_size = 0u64;
            for group in &layout.group_layouts {
                for file_layout in &group.files {
                    if let FileLayout::Object(obj) = file_layout {
                        for (sec_idx, _) in obj.sections.iter().enumerate() {
                            if let Some(s) = obj.object.sections.get(sec_idx) {
                                use object::read::macho::Section as _;
                                let sec_type = s.flags(le) & 0xFF;
                                if let Some(addr) = obj.section_resolutions[sec_idx].address() {
                                    if sec_type == 0x13 { // S_THREAD_LOCAL_VARIABLES
                                        tvars_addr = tvars_addr.min(addr);
                                        tvars_size += s.size(le);
                                    } else if sec_type == 0x11 { // S_THREAD_LOCAL_REGULAR
                                        tdata_addr = tdata_addr.min(addr);
                                        tdata_size += s.size(le);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            tvars_size = (tvars_size / 24) * 24;
            if tvars_addr == u64::MAX { tvars_addr = 0; }
            // If no type-0x11 sections, use TDATA layout (may be empty but correctly positioned)
            if tdata_addr == u64::MAX {
                tdata_addr = tdata_layout.mem_offset;
            }
            let tvars_foff = vm_addr_to_file_offset(tvars_addr, mappings)
                .unwrap_or(data_fileoff as usize) as u32;
            w.name16(b"__thread_vars"); w.name16(b"__DATA");
            w.u64(tvars_addr); w.u64(tvars_size);
            w.u32(tvars_foff); w.u32(3);
            w.u32(0); w.u32(0);
            w.u32(0x13); // S_THREAD_LOCAL_VARIABLES
            w.u32(0); w.u32(0); w.u32(0);

            // __thread_data: init template. Size includes TBSS for dyld.
            let tdata_init_addr = tdata_addr;
            let tdata_init_size = ((tdata_size + 7) & !7) + tbss_layout.mem_size;
            let tdata_init_foff = vm_addr_to_file_offset(tdata_init_addr, mappings)
                .unwrap_or(data_fileoff as usize) as u32;
            w.name16(b"__thread_data"); w.name16(b"__DATA");
            w.u64(tdata_init_addr); w.u64(tdata_init_size);
            w.u32(tdata_init_foff); w.u32(2);
            w.u32(0); w.u32(0);
            w.u32(0x11); // S_THREAD_LOCAL_REGULAR
            w.u32(0); w.u32(0); w.u32(0);
        }
        if has_rustc {
            // Always emit .rustc in __DATA for rustc to find metadata.
            let rc_addr = if rustc_in_text { data_vmaddr } else { rustc_addr.max(data_vmaddr) };
            let rc_foff = if rustc_in_text { data_fileoff as u32 } else {
                vm_addr_to_file_offset(rustc_addr, mappings).unwrap_or(data_fileoff as usize) as u32
            };
            w.name16(b".rustc"); w.name16(b"__DATA");
            w.u64(rc_addr); w.u64(rustc_size);
            w.u32(rc_foff); w.u32(0);
            w.u32(0); w.u32(0);
            w.u32(0); w.u32(0); w.u32(0); w.u32(0);
        }
        if has_init_array {
            let ia_foff = vm_addr_to_file_offset(init_array_layout.mem_offset, mappings)
                .unwrap_or(data_fileoff as usize) as u32;
            w.name16(b"__mod_init_func"); w.name16(b"__DATA");
            w.u64(init_array_layout.mem_offset); w.u64(init_array_layout.mem_size);
            w.u32(ia_foff); w.u32(3); // align 2^3 = 8
            w.u32(0); w.u32(0);
            w.u32(0x09); // S_MOD_INIT_FUNC_POINTERS
            w.u32(0); w.u32(0); w.u32(0);
        }
    }

    let (last_file_end, linkedit_vm) = if has_data {
        (data_fileoff + data_filesize, data_vmaddr + data_vmsize)
    } else {
        (text_filesize, align_to(text_vm_start + text_filesize, PAGE_SIZE))
    };
    let cf_offset = last_file_end;
    let cf_size = chained_fixups_data_size as u64;

    // LINKEDIT vmsize must cover the full content (fixups + symtab + exports).
    let linkedit_vmsize = align_to((buf_len as u64).saturating_sub(last_file_end).max(PAGE_SIZE), PAGE_SIZE);
    w.segment(b"__LINKEDIT", linkedit_vm, linkedit_vmsize, last_file_end, cf_size, VM_PROT_READ, VM_PROT_READ, 0);

    if is_dylib {
        // LC_ID_DYLIB = 0x0D
        w.u32(0x0D); w.u32(id_dylib_cmd_size); w.u32(24); w.u32(2);
        w.u32(0x01_0000); w.u32(0x01_0000);
        w.bytes(install_name.as_bytes()); w.u8(0); w.pad8();
        // LC_UUID = 0x1B (required for dlopen)
        w.u32(0x1B); w.u32(24);
        // Generate a deterministic UUID from the output path
        let uuid_bytes: [u8; 16] = {
            let mut h = [0u8; 16];
            for (i, b) in install_name.bytes().enumerate() {
                h[i % 16] ^= b;
            }
            h[6] = (h[6] & 0x0F) | 0x40; // version 4
            h[8] = (h[8] & 0x3F) | 0x80; // variant 1
            h
        };
        w.bytes(&uuid_bytes);
    } else {
        w.u32(LC_MAIN); w.u32(24); w.u64(entry_offset as u64); w.u64(0);
    }

    if !is_dylib {
        w.u32(LC_LOAD_DYLINKER); w.u32(dylinker_cmd_size); w.u32(12);
        w.bytes(DYLD_PATH); w.u8(0); w.pad8();
    }

    w.u32(LC_LOAD_DYLIB); w.u32(dylib_cmd_size); w.u32(24); w.u32(2);
    w.u32(0x01_0000); w.u32(0x01_0000); w.bytes(LIBSYSTEM_PATH); w.u8(0); w.pad8();

    for (i, dylib_path) in extra_dylibs.iter().enumerate() {
        w.u32(LC_LOAD_DYLIB); w.u32(extra_dylib_sizes[i]); w.u32(24); w.u32(2);
        w.u32(0x01_0000); w.u32(0x01_0000); w.bytes(dylib_path); w.u8(0); w.pad8();
    }

    w.u32(LC_SYMTAB); w.u32(24); w.u32(0); w.u32(0); w.u32(0); w.u32(0);
    w.u32(LC_DYSYMTAB); w.u32(80); for _ in 0..18 { w.u32(0); }

    w.u32(LC_BUILD_VERSION); w.u32(32); w.u32(PLATFORM_MACOS);
    w.u32(0x000E_0000); w.u32(0x000E_0000); w.u32(1); w.u32(3); w.u32(0x0300_0100);

    w.u32(LC_DYLD_CHAINED_FIXUPS); w.u32(16); w.u32(cf_offset as u32); w.u32(cf_size as u32);
    w.u32(LC_DYLD_EXPORTS_TRIE); w.u32(16); w.u32(last_file_end as u32); w.u32(0);

    Ok(Some(cf_offset))
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

fn write_u32_at(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn align8(v: u32) -> u32 { (v + 7) & !7 }
fn align_to(value: u64, alignment: u64) -> u64 { (value + alignment - 1) & !(alignment - 1) }

struct Writer<'a> { buf: &'a mut [u8], pos: usize }

impl Writer<'_> {
    fn u8(&mut self, v: u8) { self.buf[self.pos] = v; self.pos += 1; }
    fn u32(&mut self, v: u32) {
        self.buf[self.pos..self.pos + 4].copy_from_slice(&v.to_le_bytes()); self.pos += 4;
    }
    fn u64(&mut self, v: u64) {
        self.buf[self.pos..self.pos + 8].copy_from_slice(&v.to_le_bytes()); self.pos += 8;
    }
    fn name16(&mut self, name: &[u8]) {
        let mut buf = [0u8; 16];
        buf[..name.len().min(16)].copy_from_slice(&name[..name.len().min(16)]);
        self.buf[self.pos..self.pos + 16].copy_from_slice(&buf); self.pos += 16;
    }
    fn bytes(&mut self, data: &[u8]) {
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data); self.pos += data.len();
    }
    fn pad8(&mut self) {
        let aligned = (self.pos + 7) & !7;
        while self.pos < aligned { self.buf[self.pos] = 0; self.pos += 1; }
    }
    fn segment(&mut self, name: &[u8], vmaddr: u64, vmsize: u64,
               fileoff: u64, filesize: u64, maxprot: u32, initprot: u32, nsects: u32) {
        self.u32(LC_SEGMENT_64); self.u32(72 + 80 * nsects); self.name16(name);
        self.u64(vmaddr); self.u64(vmsize); self.u64(fileoff); self.u64(filesize);
        self.u32(maxprot); self.u32(initprot); self.u32(nsects); self.u32(0);
    }
}
