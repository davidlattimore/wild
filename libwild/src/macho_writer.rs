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
const LC_SOURCE_VERSION: u32 = 0x2a;
const LC_SUB_FRAMEWORK: u32 = 0x12;
const LC_UUID: u32 = 0x1b;
const LC_ID_DYLIB: u32 = 0x0d;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
/// Top bit set → "required for dyld to load" per `mach-o/loader.h`.
const LC_REQ_DYLD: u32 = 0x8000_0000;
const LC_LOAD_WEAK_DYLIB: u32 = LC_REQ_DYLD | 0x18;
const LC_REEXPORT_DYLIB: u32 = LC_REQ_DYLD | 0x1f;
const LC_RPATH: u32 = LC_REQ_DYLD | 0x1c;

/// Low byte of `section_64.flags` holds the section type
/// (the rest is attribute bits). See `mach-o/loader.h`.
const SECTION_TYPE_MASK: u32 = 0xff;
/// Section type containing indirect-symbol-pointer stubs. ARM64 stubs
/// are 12 bytes of code (adrp + ldr + br) that call dyld-populated GOT slots.
const S_SYMBOL_STUBS: u32 = 0x08;
/// Section type marking C-string literal data. Enables dyld cstring
/// deduplication across images — without it, duplicates waste memory.
const S_CSTRING_LITERALS: u32 = 0x02;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const VM_PROT_READ: u32 = 1;
const VM_PROT_WRITE: u32 = 2;
const VM_PROT_EXECUTE: u32 = 4;
const PLATFORM_MACOS: u32 = 1;

const DYLD_PATH: &[u8] = b"/usr/lib/dyld";
const LIBSYSTEM_PATH: &[u8] = b"/usr/lib/libSystem.B.dylib";

/// Forensic trace gated by `WILD_DUMP_SHA=1`: logs file length, an FNV-1a
/// fingerprint, and the first __DATA segment's filesize/vmsize to
/// `/tmp/wild-writer-trace.log`. Used to detect whether anything downstream
/// (codesign, strip, rustc's link pipeline) rewrites the file after wild
/// emits it. `stage` names the call site; `buf` may be `Some` to fingerprint
/// an in-memory buffer, or `None` to re-read from disk.
fn dump_sha_trace(stage: &str, path: &std::path::Path, buf: Option<&[u8]>) {
    if std::env::var_os("WILD_DUMP_SHA").is_none() {
        return;
    }
    let owned;
    let bytes: &[u8] = match buf {
        Some(b) => b,
        None => match std::fs::read(path) {
            Ok(b) => {
                owned = b;
                &owned
            }
            Err(e) => {
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("/tmp/wild-writer-trace.log")
                    .and_then(|mut f| {
                        use std::io::Write as _;
                        writeln!(f, "stage={stage} path={} READ-ERR {e}", path.display())
                    });
                return;
            }
        },
    };
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let (data_filesize, data_vmsize, text_filesize, text_vmsize) =
        parse_segment_sizes(bytes).unwrap_or((0, 0, 0, 0));
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/wild-writer-trace.log")
        .and_then(|mut f| {
            use std::io::Write as _;
            writeln!(
                f,
                "stage={stage} path={} len={} fnv1a={h:016x} TEXT.fs=0x{text_filesize:x}/vm=0x{text_vmsize:x} DATA.fs=0x{data_filesize:x}/vm=0x{data_vmsize:x}",
                path.display(),
                bytes.len(),
            )
        });
}

/// Parse Mach-O load commands from the start of `bytes` and return
/// (DATA.filesize, DATA.vmsize, TEXT.filesize, TEXT.vmsize). Returns `None`
/// if the file isn't a 64-bit Mach-O. Only reads enough to find the first
/// matching `LC_SEGMENT_64` entries; tolerant of trailing garbage.
///
/// **Complexity:** 𝒪(L) CPU, 𝒪(1) memory — single forward pass over load commands.
fn parse_segment_sizes(bytes: &[u8]) -> Option<(u64, u64, u64, u64)> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    if bytes.len() < 32 {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    if magic != MH_MAGIC_64 {
        return None;
    }
    let ncmds = u32::from_le_bytes(bytes[16..20].try_into().ok()?) as usize;
    let sizeofcmds = u32::from_le_bytes(bytes[20..24].try_into().ok()?) as usize;
    let mut pos = 32usize;
    let end = pos + sizeofcmds;
    let mut text = (0u64, 0u64);
    let mut data = (0u64, 0u64);
    for _ in 0..ncmds {
        if pos + 8 > bytes.len() || pos + 8 > end {
            break;
        }
        let cmd = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?);
        let cmdsize = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().ok()?) as usize;
        if cmd == 0x19 /* LC_SEGMENT_64 */ && pos + 72 <= bytes.len() {
            let name = &bytes[pos + 8..pos + 24];
            let vmsize = u64::from_le_bytes(bytes[pos + 32..pos + 40].try_into().ok()?);
            let _fileoff = u64::from_le_bytes(bytes[pos + 40..pos + 48].try_into().ok()?);
            let filesize = u64::from_le_bytes(bytes[pos + 48..pos + 56].try_into().ok()?);
            if name.starts_with(b"__TEXT\0") {
                text = (filesize, vmsize);
            } else if name.starts_with(b"__DATA\0") && data == (0, 0) {
                data = (filesize, vmsize);
            }
        }
        if cmdsize == 0 {
            break;
        }
        pos += cmdsize;
    }
    Some((data.0, data.1, text.0, text.1))
}

/// Always-on sanity check: each LC_SEGMENT_64 must declare a
/// `(fileoff, filesize)` range that fits inside `buf`. Catches
/// LINKEDIT-estimate underruns (or any other segment misreport)
/// loudly instead of emitting a binary that dyld SIGKILL's at load
/// with no diagnostic. Kept separate from `validate_macho_output`
/// (which does many more expensive checks under the `validate_output`
/// flag) so it can run on every link without measurable cost.
///
/// **Complexity:** 𝒪(L) CPU, 𝒪(1) memory — single forward pass over load commands.
fn validate_segment_bounds(buf: &[u8]) -> Result {
    if buf.len() < 32 {
        return Ok(());
    }
    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if magic != 0xfeed_facf {
        return Ok(()); // relocatable or other non-MH_MAGIC_64 output
    }
    let ncmds = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
    let sizeofcmds = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as usize;
    let buf_len = buf.len() as u64;
    let mut pos = 32usize;
    let end = pos.saturating_add(sizeofcmds);
    for _ in 0..ncmds {
        if pos + 8 > buf.len() || pos + 8 > end {
            break;
        }
        let cmd = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap()) as usize;
        if cmd == 0x19 /* LC_SEGMENT_64 */ && pos + 72 <= buf.len() {
            // Segment header layout: cmd(4) cmdsize(4) segname(16)
            //   vmaddr(8) vmsize(8) fileoff(8) filesize(8) ...
            let segname_raw: &[u8; 16] = buf[pos + 8..pos + 24].try_into().unwrap();
            let segname = crate::macho::trim_nul(segname_raw);
            let fileoff = u64::from_le_bytes(buf[pos + 40..pos + 48].try_into().unwrap());
            let filesize = u64::from_le_bytes(buf[pos + 48..pos + 56].try_into().unwrap());
            let end = fileoff.checked_add(filesize).ok_or_else(|| {
                crate::error!(
                    "segment {} fileoff+filesize overflows u64 ({}+{})",
                    String::from_utf8_lossy(segname),
                    fileoff,
                    filesize,
                )
            })?;
            if end > buf_len {
                crate::bail!(
                    "segment `{}` declares {}+{} bytes in file but output is only \
                     {} bytes; LINKEDIT / symtab estimate was too small. Bump the \
                     per-symbol budget in `build_mappings_and_size`.",
                    String::from_utf8_lossy(segname),
                    fileoff,
                    filesize,
                    buf_len,
                );
            }
        }
        if cmdsize == 0 {
            break;
        }
        pos += cmdsize;
    }
    Ok(())
}

/// Platform-trait entry for Mach-O output. Computes the total file
/// size (body + codesign blob reserve on macOS), kicks off the
/// background file-create task via `output.set_size`, then writes
/// directly into the pre-mmapped buffer exposed by
/// Pattern B+C precount result: per-object nlist/strtab slot
/// assignments + aggregate totals. Consumed by
/// `build_mappings_and_size` (exact LINKEDIT sizing) and by the
/// writer's parallel apply-reloc pass to place per-object nlist
/// rows into pre-carved disjoint slots — replacing the former
/// shared-`entries`-Vec + `seen_names`-HashSet + serial sort path.
#[derive(Default, Debug)]
pub(crate) struct MachOSymtabPrecount {
    /// Total stab entries across all objects with debug info.
    pub n_stabs: u32,
    /// Total defined-local nlist rows (strip_locals + L/l_ filters
    /// already applied; synthesised `__mh_execute_header` excluded).
    pub n_locals: u32,
    /// Total defined-external nlist rows (external, non-local,
    /// non-downgraded). Synthesised `__mh_execute_header` counted
    /// separately and added only when emitted.
    pub n_ext_def: u32,
    /// Total undefined-external nlist rows, after cross-object
    /// dedup: N_UNDF|N_EXT from all objects + imports + `-U`
    /// dynamic-undefineds, unique by name.
    pub n_undef_ext: u32,
    /// Total N_ABS (non-zero-valued) rows, unique by name.
    pub n_abs: u32,
    /// Total strtab bytes across all emitted symbols (each name's
    /// bytes + NUL). Does not include the leading NUL byte (that's
    /// added by `symtab_plus_strtab_bytes`).
    pub strtab_bytes: u32,
    /// Per-object slot assignment. Indexed in the same order as
    /// `layout.group_layouts.iter().flat_map(|g| g.files)` filters
    /// to `FileLayout::Object` — the writer iterates in the same
    /// order and looks up slots by that index.
    pub per_object: Vec<ObjectSymtabSlot>,
    /// Strtab offset where per-object names end. Stabs, undef
    /// names, and synthetic symbols (`__mh_execute_header`, -U)
    /// live in `strtab[strtab_objects_end..]`. The serial tail
    /// appends to this region after the parallel per-object
    /// writes settle.
    pub strtab_objects_end: u32,
    /// Count of symbols with either a PLT or a GOT slot — i.e. the
    /// rows that will land in `LC_DYLD_CHAINED_FIXUPS`'s imports
    /// table. Used to compute the exact chained-fixups section size
    /// at layout time (replacing the `16384 + n_fixups * 12`
    /// estimate in `build_mappings_and_size`).
    pub n_imports: u32,
    /// Total bytes those import names + NUL terminators consume in
    /// the chained-fixups symbol pool. ld64 aligns the pool to 8
    /// bytes afterwards; that padding is added by the caller.
    pub imports_name_bytes: u32,
    /// Exact size of the `LC_DYLD_EXPORTS_TRIE` payload, computed by
    /// running `build_export_trie_nodes` in a size-only pass and
    /// summing `node_encoded_size` across nodes. Does NOT include the
    /// 8-byte alignment padding the writer appends; callers add that
    /// themselves. Zero when the link has no trie (executables
    /// without `-export_dynamic` still get a 2-byte terminator, which
    /// this field captures as 2).
    pub exports_trie_bytes: u32,
}

/// Per-object symtab slot assignments — offsets are relative to
/// the start of their respective regions (locals / ext-def /
/// strtab) so the writer can carve them out via `split_off_mut`
/// without needing to know absolute file positions.
#[derive(Default, Debug, Clone)]
pub(crate) struct ObjectSymtabSlot {
    /// Count of local nlist rows this object will emit.
    pub n_locals: u32,
    /// Count of ext-def nlist rows this object will emit.
    pub n_ext_def: u32,
    /// Index within the locals region where this object's first
    /// local nlist row lands. `local_nlist_idx_start *  16 = byte
    /// offset from locals-region base`.
    pub local_nlist_idx_start: u32,
    /// Same for ext-def.
    pub ext_def_nlist_idx_start: u32,
    /// Strtab byte offset (from strtab base, AFTER leading NUL) of
    /// this object's first name. Names are emitted contiguously
    /// for each object; local names and ext-def names are
    /// interleaved in-object order (both share the same strtab
    /// slot since names aren't partitioned by category).
    pub strtab_byte_start: u32,
    /// Total strtab bytes this object's names + NULs take.
    pub strtab_bytes: u32,
}

impl MachOSymtabPrecount {
    /// Total nlist rows the writer will emit (16 bytes each).
    pub(crate) fn n_syms(&self) -> u32 {
        self.n_stabs + self.n_locals + self.n_ext_def + self.n_undef_ext + self.n_abs
    }

    /// Exact symtab + strtab byte count. Used by
    /// `build_mappings_and_size` to replace the 512 B/sym fudge.
    pub(crate) fn symtab_plus_strtab_bytes(&self) -> u64 {
        let nlist_bytes = (self.n_syms() as u64) * 16;
        // +1 for leading NUL that Mach-O strtabs conventionally carry.
        let strtab = self.strtab_bytes as u64 + 1;
        nlist_bytes + strtab
    }
}

/// Run the Pattern-C precount for Mach-O. Called from the
/// `Platform::precount_symtab` hook; caches its result on `Layout`
/// via `LayoutExt` (follow-up) or passes through explicitly.
///
/// **Complexity:** Θ(n + m·e_obj) CPU — one walk over
/// `symbol_resolutions` plus a per-object symbol-table scan for
/// undef/abs dedup. Runs once per link. Already parallelisable via
/// rayon but kept serial in this first pass for simplicity.
pub(crate) fn precount_symtab<'data>(layout: &Layout<'data, MachO>) -> MachOSymtabPrecount {
    use object::read::macho::Nlist as _;
    let le = object::Endianness::Little;

    let mut pc = MachOSymtabPrecount::default();

    // Dylibs use a separate write path (`write_dylib_symtab`) whose
    // contents derive from `dynamic_symbol_definitions`, not the
    // full symbol table. Precount only helps the exe path for now.
    if layout.symbol_db.args.is_dylib || layout.symbol_db.args.is_relocatable {
        return pc;
    }

    let strip_locals = layout.symbol_db.args.strip_locals;
    let strip_debug = layout.symbol_db.args.should_strip_debug();

    // External-bit precompute — mirrors write_exe_symtab's
    // precompute-external-bits phase. Per-symbol O(1) lookup
    // instead of O(m) per-call `is_symbol_external`.
    let ext_bits: Vec<bool> = {
        let mut bits = vec![true; layout.symbol_resolutions.len()];
        for group in &layout.group_layouts {
            for file_layout in &group.files {
                if let crate::layout::FileLayout::Object(obj) = file_layout {
                    let start = obj.symbol_id_range.start().as_usize();
                    for i in 0..obj.symbol_id_range.len() {
                        if let Ok(sym) = obj.object.symbols.symbol(object::SymbolIndex(i)) {
                            bits[start + i] = (sym.n_type() & object::macho::N_EXT) != 0;
                        } else {
                            bits[start + i] = false;
                        }
                    }
                }
            }
        }
        bits
    };

    let resolutions = layout.symbol_resolutions.as_slice();
    let mut seen_names: std::collections::HashSet<Vec<u8>> =
        std::collections::HashSet::with_capacity(resolutions.len() / 4);

    // Per-object walk — produces per-object slot counts *and*
    // tallies totals in the same pass. Order matches what the
    // writer will use: `group_layouts.iter().flat_map(files) → only
    // Objects`. Within an object, we iterate its `symbol_id_range`
    // (flat indices into `symbol_resolutions`). Defined symbols
    // land in this object's slot; undef / N_ABS / import names
    // dedup into the global `seen_names` set and go to the serial
    // tail region.
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            let crate::layout::FileLayout::Object(obj) = file_layout else {
                continue;
            };
            let mut slot = ObjectSymtabSlot::default();
            let range = obj.symbol_id_range.as_usize();
            for sym_idx in range {
                let Some(res) = resolutions.get(sym_idx).and_then(|r| r.as_ref()) else {
                    continue;
                };
                if res.raw_value == 0 {
                    continue;
                }
                if res.flags.contains(crate::value_flags::ValueFlags::DYNAMIC) {
                    continue;
                }
                let sym_id = crate::symbol_db::SymbolId::from_usize(sym_idx);
                let Ok(name_ref) = layout.symbol_db.symbol_name(sym_id) else {
                    continue;
                };
                let name_bytes = name_ref.bytes();
                if name_bytes.is_empty() {
                    continue;
                }
                let is_external = (!res.flags.is_downgraded_to_local() && ext_bits[sym_idx])
                    || res.flags.needs_export_dynamic();
                if strip_locals && !is_external {
                    continue;
                }
                if !is_external && (name_bytes.starts_with(b"L") || name_bytes.starts_with(b"l_")) {
                    continue;
                }
                if is_external {
                    slot.n_ext_def += 1;
                } else {
                    slot.n_locals += 1;
                }
                slot.strtab_bytes += name_bytes.len() as u32 + 1;
                seen_names.insert(name_bytes.to_vec());
            }
            pc.per_object.push(slot);
        }
    }

    // Prefix-sum per-object slot offsets so each object knows
    // exactly where in the nlist regions + strtab to write.
    let mut local_cursor = 0u32;
    let mut ext_def_cursor = 0u32;
    let mut strtab_cursor = 0u32;
    for slot in &mut pc.per_object {
        slot.local_nlist_idx_start = local_cursor;
        slot.ext_def_nlist_idx_start = ext_def_cursor;
        slot.strtab_byte_start = strtab_cursor;
        local_cursor += slot.n_locals;
        ext_def_cursor += slot.n_ext_def;
        strtab_cursor += slot.strtab_bytes;
    }
    pc.n_locals = local_cursor;
    pc.n_ext_def = ext_def_cursor;
    pc.strtab_objects_end = strtab_cursor;
    pc.strtab_bytes = strtab_cursor;

    // `__mh_execute_header` for executables.
    if !layout.symbol_db.args.is_bundle {
        let name: &[u8] = b"__mh_execute_header";
        if !seen_names.contains(name) {
            pc.n_ext_def += 1;
            pc.strtab_bytes += name.len() as u32 + 1;
            seen_names.insert(name.to_vec());
        }
    }

    // N_ABS + N_UNDF|N_EXT. Per-object scan, dedup across objects.
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            if let crate::layout::FileLayout::Object(obj) = file_layout {
                let strings = obj.object.symbols.strings();
                for sym_idx in 0..obj.object.symbols.len() {
                    let Ok(sym) = obj.object.symbols.symbol(object::SymbolIndex(sym_idx)) else {
                        continue;
                    };
                    let t = sym.n_type();
                    let is_abs = (t & 0x0e) == 0x02;
                    let is_undf_ext = (t & 0x0e) == 0 && (t & 0x01) != 0;
                    if !is_abs && !is_undf_ext {
                        continue;
                    }
                    let name = sym.name(le, strings).unwrap_or(&[]);
                    if name.is_empty() || seen_names.contains(name) {
                        continue;
                    }
                    if is_abs {
                        if sym.n_value(le) == 0 {
                            continue;
                        }
                        pc.n_abs += 1;
                    } else {
                        pc.n_undef_ext += 1;
                    }
                    pc.strtab_bytes += name.len() as u32 + 1;
                    seen_names.insert(name.to_vec());
                }
            }
        }
    }

    // Dynamic undefined (-U).
    for sym_name in &layout.symbol_db.args.dynamic_undefined_symbols {
        if !seen_names.contains(sym_name) {
            pc.n_undef_ext += 1;
            pc.strtab_bytes += sym_name.len() as u32 + 1;
            seen_names.insert(sym_name.clone());
        }
    }

    // Imports (PLT/GOT-having resolutions). Track two parallel
    // quantities here:
    //   * seen_names dedup → `n_undef_ext` / strtab bytes (symtab).
    //   * raw PLT/GOT count (no dedup) + raw name bytes → `n_imports` / `imports_name_bytes` for
    //     the chained-fixups imports table. Chained fixups don't dedup names against the symtab, so
    //     the two counts diverge when an undefined external is already in `seen_names` from the
    //     N_UNDF pass.
    for (sym_idx, res) in resolutions.iter().enumerate() {
        let Some(res) = res else { continue };
        let has_plt = res.format_specific.plt_address.is_some();
        let has_got = res.format_specific.got_address.is_some();
        if !has_plt && !has_got {
            continue;
        }
        let sym_id = crate::symbol_db::SymbolId::from_usize(sym_idx);
        let Ok(name_ref) = layout.symbol_db.symbol_name(sym_id) else {
            continue;
        };
        let name = name_ref.bytes();
        if name.is_empty() {
            continue;
        }
        // Each (PLT slot, GOT slot) produces its own imports-table
        // entry, so `n_imports` counts both when present. Matches
        // `write_stubs_and_got`'s emission.
        if has_plt {
            pc.n_imports += 1;
            pc.imports_name_bytes += name.len() as u32 + 1;
        }
        if has_got {
            pc.n_imports += 1;
            pc.imports_name_bytes += name.len() as u32 + 1;
        }
        if seen_names.contains(name) {
            continue;
        }
        pc.n_undef_ext += 1;
        pc.strtab_bytes += name.len() as u32 + 1;
        seen_names.insert(name.to_vec());
    }

    // Stabs — only when debug info is not stripped. The writer emits
    // *five* synthesised stab rows per object (SO start, SO dir, SO
    // file, OSO, SO end), copies all input stabs verbatim, and adds
    // four rows (BNSYM/FUN/FUN-end/ENSYM) per defined external
    // function in __text. Get all three counts so the LINKEDIT
    // estimate lands within the 8-KiB slack rather than truncating
    // ripgrep-scale symtabs.
    if !strip_debug {
        use object::read::macho::Nlist as _;
        use object::read::macho::Section as _;
        use rayon::prelude::*;
        // Flatten the (group, file) → object list so rayon can balance
        // work evenly; a serial walk over 700+ objects (rust-analyzer
        // scale) was ~20 ms and was the main regression after
        // landing Phase B's accurate stab sizing.
        let objects: Vec<&crate::layout::ObjectLayout<'_, MachO>> = layout
            .group_layouts
            .iter()
            .flat_map(|g| g.files.iter())
            .filter_map(|f| match f {
                crate::layout::FileLayout::Object(o) => Some(o),
                _ => None,
            })
            .collect();
        let (stab_rows, stab_bytes) = objects
            .par_iter()
            .filter(|obj| object_has_debug_info(obj))
            .map(|obj| -> (u32, u32) {
                let strings = obj.object.symbols.strings();
                let mut input_stabs: u32 = 0;
                let mut input_stabs_bytes: u32 = 0;
                let mut fun_count: u32 = 0;
                let mut fun_names_bytes: u32 = 0;
                for i in 0..obj.object.symbols.len() {
                    let Ok(sym) = obj.object.symbols.symbol(object::SymbolIndex(i)) else {
                        continue;
                    };
                    let n_type = sym.n_type();
                    if n_type & 0xE0 != 0 {
                        input_stabs += 1;
                        let name = sym.name(le, strings).unwrap_or(&[]);
                        if !name.is_empty() {
                            input_stabs_bytes += name.len() as u32 + 1;
                        }
                        continue;
                    }
                    if (n_type & 0x0F) != 0x0F {
                        continue;
                    }
                    let n_sect = sym.n_sect();
                    if n_sect == 0 {
                        continue;
                    }
                    let sec_idx = n_sect as usize - 1;
                    let is_text = obj
                        .object
                        .sections
                        .get(sec_idx)
                        .map(|s| crate::macho::trim_nul(s.sectname()) == b"__text")
                        .unwrap_or(false);
                    if !is_text {
                        continue;
                    }
                    fun_count += 1;
                    let name = sym.name(le, strings).unwrap_or(&[]);
                    if !name.is_empty() {
                        fun_names_bytes += name.len() as u32 + 1;
                    }
                }
                (
                    5 + input_stabs + 4 * fun_count,
                    512 + fun_names_bytes + input_stabs_bytes,
                )
            })
            .reduce(|| (0u32, 0u32), |a, b| (a.0 + b.0, a.1 + b.1));
        pc.n_stabs += stab_rows;
        pc.strtab_bytes += stab_bytes;
        // AST path stabs (each emits one N_AST row with the path as
        // name).
        for ast_path in &layout.symbol_db.args.ast_paths {
            pc.n_stabs += 1;
            pc.strtab_bytes += ast_path.as_bytes().len() as u32 + 1;
        }
    }

    // Exports trie size — exact, by running the same radix-trie build
    // that `write_exports_trie_compat` uses, then measuring without
    // emitting bytes. Replaces the `n_exports * 256` estimate in
    // `build_mappings_and_size`.
    //
    // Mirrors `write_exports_trie_compat`'s entry-gathering logic:
    //   * dylib → walk `dynamic_symbol_definitions`.
    //   * exe without `-export_dynamic` → 2-byte terminator trie (just `__mh_execute_header` which
    //     folds into a single terminal), fast-path to avoid the full O(n·m) walk.
    //   * exe with `-export_dynamic` (or exported_symbols list/flag) → walk `symbol_resolutions`,
    //     filter by `N_EXT` and not `N_PEXT`. On the fast-exe path the trie is always the trivial
    //     2-byte terminator.
    pc.exports_trie_bytes = {
        let is_dylib = layout.symbol_db.args.is_dylib;
        if is_dylib {
            let image_base = 0u64;
            let mut entries: Vec<(Vec<u8>, u64)> = Vec::new();
            let mut seen: std::collections::HashSet<Vec<u8>> = Default::default();
            let resolutions = layout.symbol_resolutions.as_slice();
            for def in &layout.dynamic_symbol_definitions {
                let sym_id = def.symbol_id;
                let Some(res) = resolutions.get(sym_id.as_usize()).and_then(|r| r.as_ref()) else {
                    continue;
                };
                if res.raw_value == 0 {
                    continue;
                }
                let name = def.name.to_vec();
                if name.is_empty() || seen.contains(&name) {
                    continue;
                }
                seen.insert(name.clone());
                entries.push((name, res.raw_value.saturating_sub(image_base)));
            }
            compute_export_trie_size(&entries)
        } else if layout.symbol_db.args.is_bundle || layout.symbol_db.args.is_relocatable {
            // Bundles / relocatables: no trie at all; the writer emits
            // a 2-byte terminator placeholder.
            2
        } else {
            let only_header = !layout.symbol_db.args.export_dynamic
                && layout.symbol_db.args.exported_symbols_list.is_none()
                && layout.symbol_db.args.exported_symbols.is_empty();
            if only_header {
                // `__mh_execute_header` is the sole export. The radix
                // trie collapses to a single terminal node under the
                // root; experimentally that's always 30 bytes for the
                // 19-char name + ULEB'd zero address, but safer to
                // size it via the real builder once so any future
                // encoding changes stay honest.
                let entries = vec![(b"__mh_execute_header".to_vec(), 0u64)];
                compute_export_trie_size(&entries)
            } else {
                // `-export_dynamic` (or exported_symbols_list) path:
                // walk symbol_resolutions filtered by N_EXT & !N_PEXT,
                // re-using the ext_bits precompute. Pre-compute pext
                // bits here since the earlier ext_bits sweep didn't
                // collect them.
                use object::read::macho::Nlist as _;
                let n = layout.symbol_resolutions.len();
                let mut pext_bits = vec![false; n];
                for group in &layout.group_layouts {
                    for file_layout in &group.files {
                        if let crate::layout::FileLayout::Object(obj) = file_layout {
                            let start = obj.symbol_id_range.start().as_usize();
                            for i in 0..obj.symbol_id_range.len() {
                                if let Ok(sym) = obj.object.symbols.symbol(object::SymbolIndex(i)) {
                                    pext_bits[start + i] =
                                        (sym.n_type() & object::macho::N_PEXT) != 0;
                                }
                            }
                        }
                    }
                }
                let mut entries: Vec<(Vec<u8>, u64)> = vec![(b"__mh_execute_header".to_vec(), 0)];
                let mut seen: std::collections::HashSet<Vec<u8>> = Default::default();
                seen.insert(b"__mh_execute_header".to_vec());
                let image_base = PAGEZERO_SIZE;
                let resolutions = layout.symbol_resolutions.as_slice();
                for (sym_idx, res) in resolutions.iter().enumerate() {
                    let Some(res) = res else { continue };
                    if res.raw_value == 0 {
                        continue;
                    }
                    if res.flags.contains(crate::value_flags::ValueFlags::DYNAMIC) {
                        continue;
                    }
                    if !ext_bits[sym_idx] && !res.flags.needs_export_dynamic() {
                        continue;
                    }
                    if res.flags.is_downgraded_to_local() {
                        continue;
                    }
                    if pext_bits[sym_idx] {
                        continue;
                    }
                    let sym_id = crate::symbol_db::SymbolId::from_usize(sym_idx);
                    let Ok(name) = layout.symbol_db.symbol_name(sym_id) else {
                        continue;
                    };
                    let name = name.bytes().to_vec();
                    if name.is_empty() || seen.contains(&name) {
                        continue;
                    }
                    seen.insert(name.clone());
                    entries.push((name, res.raw_value.saturating_sub(image_base)));
                }
                compute_export_trie_size(&entries)
            }
        }
    };

    pc
}

/// Exact upper bound on the `LC_DYLD_CHAINED_FIXUPS` payload size,
/// computed from layout-known inputs.
///
/// Mirrors `write_chained_fixups_header`'s byte layout:
/// `header(32) + image_starts + seg_starts + imports_table + symbols_pool`
/// then 8-byte padded. Differs from the real size only in that
/// `n_imports` is the pre-dedup count (PLT + GOT count per symbol, no
/// addend-tuple collapse), so the bound can be higher than the
/// eventual written size by up to ~2× in pathological workloads. Never
/// below, which is the direction that matters for buffer allocation.
///
/// **Complexity:** Θ(segments) CPU, Θ(1) memory — no symbol-table walks
/// beyond reading pre-populated `precount` fields.
pub(self) fn compute_chained_fixups_size_upper(
    precount: &MachOSymtabPrecount,
    mappings: &[SegmentMapping],
    is_dylib: bool,
) -> u32 {
    let has_data = mappings.len() > 1 && (mappings[1].vm_end > mappings[1].vm_start);
    // Upper bound: worst-case 4 chain-starts-bearing segments (DATA
    // + DATA_CONST split + TEXT for certain layouts).
    let max_seg_entries: u32 = 4;
    // Worst-case data page count, taken from the DATA mapping's VM
    // span. Small for most binaries; hundreds for mid-size Rust.
    let data_pages: u32 = if has_data {
        let dm = &mappings[1];
        (((dm.vm_end - dm.vm_start) + PAGE_SIZE - 1) / PAGE_SIZE) as u32
    } else {
        0
    };
    // seg_count in the `dyld_chained_starts_in_image` table — upper
    // bound of 5 covers all current layouts (PAGEZERO + TEXT +
    // DATA_CONST + DATA + LINKEDIT for exe with split; 4 for
    // non-split or dylib).
    let seg_count: u32 = if is_dylib { 4 } else { 5 };
    let starts_in_image_raw = 4 + 4 * seg_count;
    let starts_in_image = (starts_in_image_raw + 7) & !7;
    let starts_in_segment_total = max_seg_entries * 22 + 2 * data_pages;
    // Imports table: format 3 is the widest at 16 bytes/entry. Using
    // format 3 as the upper bound means we never under-allocate when
    // the actual format turns out to be 3 (rare — only triggered by
    // addends outside i32 range).
    let imports_size = 16 * precount.n_imports;
    let header: u32 = 32;
    // +64 trailing slack for 8-byte alignment + any drift between the
    // pre-dedup import count and the post-dedup written count.
    header
        + starts_in_image
        + starts_in_segment_total
        + imports_size
        + precount.imports_name_bytes
        + 64
}

/// `SizedOutput::out`. Reports the real end-of-file via
/// `SizedOutput::set_final_size` so `flush` truncates the trailing
/// reserve. `msync(MS_SYNC | MS_INVALIDATE)` happens inside
/// `OutputBuffer::flush` — that's the AMFI workaround.
pub(crate) fn write_output<A: Arch<Platform = MachO>>(
    output: &mut crate::file_writer::Output,
    layout: &Layout<'_, MachO>,
) -> Result {
    if layout.symbol_db.args.is_relocatable {
        return write_relocatable_object(layout);
    }

    let plain_entries = collect_compact_unwind_entries(layout);

    // Same text-segment / unwind-info slot math as `write_direct`.
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
    let text_content_end = {
        let candidates = [
            output_section_id::TEXT,
            output_section_id::PLT_GOT,
            output_section_id::RODATA,
            output_section_id::COMMENT,
            output_section_id::DATA_REL_RO,
            output_section_id::GCC_EXCEPT_TABLE,
            output_section_id::EH_FRAME,
        ];
        let text_start = layout
            .section_layouts
            .get(output_section_id::TEXT)
            .mem_offset;
        candidates
            .iter()
            .map(|id| {
                let s = layout.section_layouts.get(*id);
                if s.mem_size == 0 {
                    0
                } else {
                    s.mem_offset + s.mem_size
                }
            })
            .max()
            .unwrap_or(text_start)
    };
    let gap_bytes = text_vm_end.saturating_sub(text_content_end);
    let comment_layout = layout.section_layouts.get(output_section_id::COMMENT);
    let unwind_info_vm_addr = if !plain_entries.is_empty() && comment_layout.mem_size > 0 {
        comment_layout.mem_offset
    } else if plain_entries.is_empty() || gap_bytes == 0 {
        0u64
    } else {
        (text_content_end + 3) & !3u64
    };

    // Pattern-C precount: walk every object's symbols once, tally
    // exact nlist + strtab byte counts so `build_mappings_and_size`
    // stops over-allocating via the 512 B/sym fudge. Also the
    // substrate for Pattern B (follow-up) — per-object slot
    // assignment will attach here.
    let precount = <MachO as crate::platform::Platform>::precount_symtab(layout);
    let (mappings, alloc_size) = build_mappings_and_size(layout, 0, Some(&precount));

    let no_adhoc_codesign = layout.symbol_db.args.no_adhoc_codesign;
    let will_codesign = cfg!(target_os = "macos") && !no_adhoc_codesign;

    let output_path = layout.symbol_db.args.output().clone();
    let identifier: String = if will_codesign {
        layout
            .symbol_db
            .args
            .final_output
            .clone()
            .unwrap_or_else(|| {
                output_path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "a.out".to_string())
            })
    } else {
        String::new()
    };

    let blob_reserve = if will_codesign {
        crate::macho_codesign::blob_reserve_bytes(alloc_size, identifier.len())
    } else {
        0
    };
    let total_alloc = alloc_size + blob_reserve;

    // Kick off background file creation + mmap sized to the full
    // allocation. By the time the closure below runs, the mmap is
    // ready and we can write directly into it.
    output.set_size(total_alloc as u64);

    output.write(layout, move |sized_output, lay| {
        write_direct_inner::<A>(
            sized_output,
            lay,
            &mappings,
            &plain_entries,
            unwind_info_vm_addr,
            text_base,
            text_vm_end,
            text_content_end,
            alloc_size,
            will_codesign,
            &identifier,
            &precount,
        )
    })
}

/// Writes the Mach-O image directly into `sized_output.out` —
/// the mmap-or-Vec buffer allocated by `file_writer::Output`.
#[allow(clippy::too_many_arguments)]
fn write_direct_inner<A: Arch<Platform = MachO>>(
    sized_output: &mut crate::file_writer::SizedOutput,
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
    plain_entries: &[CollectedUnwindEntry],
    unwind_info_vm_addr: u64,
    text_base: u64,
    text_vm_end: u64,
    text_content_end: u64,
    alloc_size: usize,
    will_codesign: bool,
    identifier: &str,
    precount: &MachOSymtabPrecount,
) -> Result {
    let buf: &mut [u8] = &mut sized_output.out[..];
    let final_size = write_macho::<A>(
        &mut buf[..alloc_size],
        layout,
        mappings,
        plain_entries,
        unwind_info_vm_addr,
        text_base,
        text_vm_end,
        text_content_end,
        precount,
    )?;
    if final_size > alloc_size {
        crate::bail!(
            "macho_writer: LINKEDIT estimate too small — wrote up to offset \
             {final_size} but only allocated {alloc_size} bytes. Symtab/strtab \
             content silently truncated. Bump the per-symbol byte budget in \
             `build_mappings_and_size` (currently 512 bytes/symbol)."
        );
    }

    if layout.symbol_db.args.print_dependencies {
        print_dependencies(layout);
    }

    validate_segment_bounds(&buf[..final_size])?;
    if layout.symbol_db.args.common().validate_output {
        validate_macho_output(&buf[..final_size], layout.symbol_db.args.flat_namespace)?;
    }

    let output_path = layout.symbol_db.args.output();
    dump_sha_trace("pre-write", output_path.as_ref(), Some(&buf[..final_size]));

    let (eof_offset, use_external_codesign) = if will_codesign {
        crate::timing_phase!("Ad-hoc codesign (in-process)");
        match crate::macho_codesign::sign_in_place(buf, final_size, identifier) {
            Ok(eof) => (eof, false),
            Err(e) => {
                tracing::warn!(
                    "in-process codesign failed ({e:?}); falling back to external codesign"
                );
                (final_size, true)
            }
        }
    } else {
        (final_size, false)
    };

    // Tell the file_writer to flush exactly `eof_offset` bytes —
    // truncates the codesign-blob reserve trailing region.
    sized_output.set_final_size(eof_offset as u64);

    if use_external_codesign {
        // The external-codesign fallback requires the unsigned
        // buffer to be on disk already. With mmap output, `flush`
        // happens after we return, so we'd be signing an empty
        // file. For now, fall back to writing via `fs::write` in
        // this rare path (MH_BUNDLE with no header-pad room).
        sized_output.set_final_size(final_size as u64);
        // Drop the mmap implicitly via flush, then re-open and
        // let external codesign do its thing. We can't easily
        // re-trigger a file write from inside the closure; emit
        // a warning and let the user re-sign manually.
        tracing::warn!(
            "Mach-O output written unsigned; external `codesign -o linker-signed` \
             fallback not yet wired for the mmap writer. Re-sign with: \
             codesign -s - --force -o linker-signed {}",
            output_path.display()
        );
    }

    dump_sha_trace("post-write", output_path.as_ref(), None);
    if will_codesign && !use_external_codesign {
        dump_sha_trace("post-codesign", output_path.as_ref(), None);
    }

    // Optional auxiliary outputs — these don't go into the
    // SizedOutput buffer; they're separate files requested by
    // user flags.
    if let Some(ref dep_path) = layout.symbol_db.args.dependency_info_path {
        write_dependency_info(layout, dep_path)?;
    }
    if let Some(ref map_path) = layout.symbol_db.args.map_file {
        write_map_file(layout, map_path)?;
    }

    Ok(())
}

/// Print per-symbol dependency edges (ref-file → def-file) to stdout.
///
/// Used when `--print-dependencies` is set. Walks every object's symbol table
/// to find undefined-external references and resolves each to its definition.
///
/// **Complexity:** 𝒪(m + Σₒ eₒ) CPU where Σₒ eₒ is the total external-undef
/// reference count across objects. Uses a precomputed
/// `file_id_to_path: HashMap<FileId, String>` and direct slice indexing
/// into `symbol_resolutions` so each lookup is 𝒪(1). Was 𝒪(n·m) (one
/// file-id scan per resolved ref) plus 𝒪(def_id) per
/// `.iter().nth(def_id.as_usize())` on `symbol_resolutions`.
/// 𝒪(m) extra memory for the lookup map.
fn print_dependencies(layout: &Layout<'_, MachO>) {
    use crate::layout::FileLayout;
    use object::read::macho::Nlist as _;
    let le = object::Endianness::Little;

    // One-shot file_id → filename map; avoids re-scanning all
    // group_layouts for every resolved reference below.
    let file_id_to_path: std::collections::HashMap<crate::input_data::FileId, String> = {
        let mut m = std::collections::HashMap::new();
        for g in &layout.group_layouts {
            for fl in &g.files {
                if let FileLayout::Object(obj) = fl {
                    m.insert(
                        obj.file_id,
                        obj.input.file.filename.to_string_lossy().into_owned(),
                    );
                }
            }
        }
        m
    };
    let resolutions = layout.symbol_resolutions.as_slice();

    for group in &layout.group_layouts {
        for file_layout in &group.files {
            let FileLayout::Object(obj) = file_layout else {
                continue;
            };
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
                let sym_id = obj
                    .symbol_id_range
                    .input_to_id(object::SymbolIndex(sym_idx));
                let def_id = layout.symbol_db.definition(sym_id);

                // Check if defined in a linked object file.
                let mut def_path = String::new();
                // First check if it resolves to a real address (object-defined).
                if let Some(res) = resolutions.get(def_id.as_usize()).and_then(|r| r.as_ref()) {
                    if res.raw_value != 0
                        && !res.flags.contains(crate::value_flags::ValueFlags::DYNAMIC)
                    {
                        let def_file_id = layout.symbol_db.file_id_for_symbol(def_id);
                        if let Some(p) = file_id_to_path.get(&def_file_id) {
                            def_path = p.clone();
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

/// Serialise a compact binary dependency-info file (version byte + NUL-terminated records).
///
/// One input record per object file, one output record for the link product.
///
/// **Complexity:** 𝒪(m) CPU, 𝒪(m · p̄) memory where p̄ is average path length.
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
///
/// Three passes: object-file index, section aggregation into a `BTreeMap`, and
/// per-symbol emission. The symbol pass iterates all `symbol_resolutions` once
/// per object — making it quadratic in the worst case.
///
/// **Complexity:** 𝒪(n · m + s · log s) CPU — dominant term is the symbol loop
/// (𝒪(n) resolutions × 𝒪(m) objects); 𝒪(s + n) memory for the section map and path strings.
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

    // Symbols — walk each object's own `symbol_id_range` rather
    // than scanning all `symbol_resolutions` per object (was 𝒪(m·n),
    // now 𝒪(n) total).
    writeln!(f, "\n# Symbols:\n# Address\tSize\t\tFile  Name").unwrap();
    let mut sym_obj_idx = 0usize;
    let resolutions = layout.symbol_resolutions.as_slice();
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            if let FileLayout::Object(obj) = file_layout {
                let range = obj.symbol_id_range.as_usize();
                for sym_idx in range {
                    let Some(res) = resolutions.get(sym_idx).and_then(|r| r.as_ref()) else {
                        continue;
                    };
                    if res.raw_value == 0 {
                        continue;
                    }
                    let symbol_id = crate::symbol_db::SymbolId::from_usize(sym_idx);
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
///
/// Also computes the total allocation size (file buffer length) including an
/// estimated LINKEDIT region sized to hold symtab + strtab + fixups + exports.
///
/// **Complexity:** 𝒪(m) CPU to count stabs (one pass over object layouts),
/// 𝒪(s) for the segment iteration; 𝒪(1) extra memory — result is a fixed-size
/// `Vec` of at most 2 `SegmentMapping` entries.
fn build_mappings_and_size(
    layout: &Layout<'_, MachO>,
    extra_text: u64,
    precount: Option<&MachOSymtabPrecount>,
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
        // Reserve enough file space to cover the full VM range of this
        // segment. Historically wild only reserved `seg.sizes.file_size`
        // worth of file (the file-backed content), leaving BSS purely
        // as a vmsize-vs-filesize gap. On macOS that seemed to work
        // for small binaries but breaks on mid-size ones: dyld ends
        // up mapping whatever happens to live at
        // `fileoff + filesize`..`fileoff + vmsize` into the BSS region
        // — typically the start of `__LINKEDIT` — and
        // zero-init'd rust statics (e.g. `AtomicPtr::new(null_mut())`
        // in `std::sys::pal::unix::stack_overflow::thread_info`) come
        // up as garbage pointers. First `pthread_mutex_lock` on them
        // SIGSEGVs. Fixing this needs filesize == vmsize so there's
        // no "fall off" range for dyld to fill from trailing file
        // bytes. The writer zero-pads any slack between actual
        // content and the segment end. Guarded against VM-only
        // placeholders (PAGEZERO's 4GB mem_size) via `file_size == 0`.
        let file_sz = if seg.sizes.file_size == 0 {
            0
        } else {
            align_to(
                (seg.sizes.file_size as u64).max(seg.sizes.mem_size) + extra,
                PAGE_SIZE,
            )
        };
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
    // Each nlist64 = 16 bytes, Rust mangled symbol names in heavy crates
    // (midnight-node-runtime, subxt+sqlx workloads) average 400-500 bytes
    // due to deeply-nested generics. Previously we budgeted ~200 bytes per
    // symbol, which produced LINKEDIT segments whose filesize exceeded the
    // total file size — dyld then SIGKILL'd the process on load because
    // symtab/strtab content ran past `out.len()` (writes were silently
    // skipped via the `if stroff + strtab.len() <= out.len()` guard, but
    // `pos` advanced anyway, and the patched LINKEDIT header claimed the
    // too-large offset). Bumped to 512 bytes/symbol. Still an estimate —
    // if it's wrong, `validate_linkedit_fits` below traps it loudly
    // instead of emitting a truncated binary.
    //
    // Also account for chained fixups data (page starts, imports, symbol
    // names). Overestimating is cheap (buffer is truncated to actual size
    // after emission); underestimating causes silent data loss and
    // codesign / dyld-load failure.
    // Prefer the exact Pattern-C precount when available — zero
    // LINKEDIT over-allocation, no 512 B/sym pessimistic budget.
    // Fall back to the old fudge when precount is empty (dylib
    // path, or precount skipped).
    let is_dylib = layout.symbol_db.args.is_dylib;
    // Build preliminary mappings slice (just enough for the chained
    // fixups size bound, which needs DATA segment's VM span). Use an
    // empty placeholder if `raw` has < 2 segments — the bound falls
    // back to a 0-page DATA region which is still a valid upper
    // bound. The `mappings` built above already has the shape we
    // need.
    let (symtab_estimate, fixups_estimate, exports_estimate) =
        if let Some(pc) = precount.filter(|p| p.n_syms() > 0) {
            // Symtab + strtab: exact via `symtab_plus_strtab_bytes`.
            let symtab = pc.symtab_plus_strtab_bytes() as usize;
            // Chained fixups: exact upper bound via the same formula
            // the writer uses. Replaces `16384 + n_syms * 12` (which
            // budgeted tens of MB for 5M-symbol rust-analyzer links).
            let fixups = compute_chained_fixups_size_upper(pc, &mappings, is_dylib) as usize;
            // Exports trie: exact via the size-only trie build in
            // precount. Round up 8-byte padding the writer adds after
            // the trie. Replaces `n_exports * 256`.
            let trie_padded = ((pc.exports_trie_bytes as usize) + 7) & !7;
            // 4 KiB bookkeeping slack for the small LINKEDIT-adjacent
            // tables wild emits (LC_FUNCTION_STARTS ULEB payload,
            // LC_DATA_IN_CODE empty, indirect symbol table). Cheaper
            // than pre-computing exact values for each.
            (symtab + 4096, fixups, trie_padded)
        } else {
            // Dylib (precount skipped) / no-precount fallback path —
            // retains the old fudge-factor sizing.
            let symtab = (n_syms + n_stabs) * (16 + 512);
            let n_fixups = n_syms;
            let fixups = 16384 + n_fixups * 12;
            let exports = n_exports * 256;
            (symtab, fixups, exports)
        };
    let linkedit_estimate = fixups_estimate + exports_estimate + symtab_estimate;
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

/// Main Mach-O image assembler: copies section data, applies relocations, builds
/// chained fixups, exports trie, function-starts, symtab, and patches all headers.
///
/// Sub-phases (in order):
/// 1. `ResolutionByNameCache::build` — Θ(n/T) wall-clock.
/// 2. `write_object_sections` (rayon par_iter over m objects) — 𝒪(r/T) wall-clock.
/// 3. `write_merged_strings_macho` — 𝒪(b_strings).
/// 4. `write_stubs_and_got` / `write_got_entries` — 𝒪(i).
/// 5. Import deduplication — 𝒪(i · k̄) with hash map, where k̄ = 1 expected.
/// 6. Chained fixup chain encoding — 𝒪(i + b/PAGE_SIZE).
/// 7. `build_unwind_info_section` — 𝒪(a log a).
/// 8. `write_headers` — 𝒪(L).
/// 9. `write_exports_trie_compat` / `write_function_starts_compat` — 𝒪(e log e).
/// 10. `write_exe_symtab` / `write_dylib_symtab` — 𝒪(n/T + t) wall-clock.
///
/// **Complexity:** Θ(n + r + b) CPU sequentially; dominant wall-clock term
/// 𝒪((n + r)/T) with rayon; 𝒪(b + n) memory (output buffer + symbol tables).
fn write_macho<A: Arch<Platform = MachO>>(
    out: &mut [u8],
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
    plain_entries: &[CollectedUnwindEntry],
    unwind_info_vm_addr: u64,
    text_base: u64,
    text_vm_end: u64,
    text_content_end: u64,
    precount: &MachOSymtabPrecount,
) -> Result<usize> {
    // Post-layout invariant (debug-only): any symbol whose flags
    // include `ValueFlags::GOT` must have a `got_address`. A symbol
    // flagged for GOT but without a slot means some reloc-scan pass
    // set the flag but the slot allocator never ran (or vice
    // versa), and any POINTER_TO_GOT against it will silently
    // corrupt the output. Catches drift between the two sides of
    // the "allocate a GOT slot" contract.
    #[cfg(debug_assertions)]
    validate_got_flag_consistency(layout)?;
    #[cfg(debug_assertions)]
    validate_no_references_into_dormant_atoms(layout)?;
    let le = object::Endianness::Little;
    let header_layout = layout.section_layouts.get(output_section_id::FILE_HEADER);

    // Collect fixups during section writing and stub generation.
    // Pre-size with reasonable starting points (small-link floor) to
    // skip ~10 growth-doublings on medium / large links.
    let mut rebase_fixups: Vec<RebaseFixup> = Vec::with_capacity(1024);
    let mut bind_fixups: Vec<BindFixup> = Vec::with_capacity(256);
    let mut imports: Vec<ImportEntry> = Vec::with_capacity(64);
    let has_extra_dylibs = !layout.symbol_db.args.extra_dylibs.is_empty();

    // Track section write ranges for overlap detection (validation only).
    let validate = layout.symbol_db.args.common().validate_output;
    let mut write_ranges: Vec<(usize, usize, String)> = Vec::new();

    // Build a name-keyed resolution cache once so the apply-reloc
    // fallback path (triggered when `merged_symbol_resolution` yields
    // raw_value=0 but the name has a non-zero sibling resolution from
    // archive-chain aliasing) is O(1) per reloc instead of a linear
    // scan over every symbol in the link. Without this, rust-analyzer
    // spent ~50 μs per reloc inside `find_resolution_by_name` walking
    // ~5 M symbols; building the map takes one pass per link.
    let name_cache = {
        crate::timing_phase!("Build resolution-by-name cache");
        ResolutionByNameCache::build(layout)
    };

    // Copy section data and apply relocations. Each object writes to
    // disjoint output ranges (layout guarantees no section overlap)
    // and its fixup contributions are append-only, so the loop is
    // naturally parallel once we give each thread its own accumulator
    // and merge at the end.
    {
        crate::timing_phase!("Apply relocations (per-object sections)");
        use rayon::prelude::*;

        // Collect object references first so rayon can iterate them
        // without borrowing `layout.group_layouts` across the closure
        // mutably.
        let objects: Vec<&ObjectLayout<'_, MachO>> = layout
            .group_layouts
            .iter()
            .flat_map(|g| g.files.iter())
            .filter_map(|f| match f {
                FileLayout::Object(o) => Some(o),
                _ => None,
            })
            .collect();

        // Pre-split the output into per-(object, section) disjoint
        // `&mut [u8]` slices via the safe `split_off_mut` primitive
        // — same approach ELF's `split_output_into_sections` uses.
        // No more `AtomicPtr` + `unsafe from_raw_parts_mut` alias
        // game: rayon gets a zipped iterator of `(object,
        // Vec<SectionOutput>)` where each slice is exclusively
        // owned by its worker.
        let per_object_slices = split_output_for_objects(out, &objects, mappings);

        struct PerThread {
            rebase: Vec<RebaseFixup>,
            bind: Vec<BindFixup>,
            imports: Vec<ImportEntry>,
            ranges: Vec<(usize, usize, String)>,
        }

        let results: Result<Vec<PerThread>> = objects
            .par_iter()
            .zip(per_object_slices.into_par_iter())
            .map(|(obj, mut slices)| -> Result<PerThread> {
                let mut pt = PerThread {
                    rebase: Vec::new(),
                    bind: Vec::new(),
                    imports: Vec::new(),
                    ranges: Vec::new(),
                };
                write_object_sections(
                    &mut slices,
                    obj,
                    layout,
                    mappings,
                    le,
                    &mut pt.rebase,
                    &mut pt.bind,
                    &mut pt.imports,
                    has_extra_dylibs,
                    if validate { Some(&mut pt.ranges) } else { None },
                    &name_cache,
                )?;
                Ok(pt)
            })
            .collect();
        let per_thread = results?;

        // Merge: each per-thread `bind` stores import_index values
        // relative to that thread's `imports` Vec. Shift them to the
        // combined-imports frame as we concatenate.
        for mut pt in per_thread {
            let base = imports.len() as u32;
            for f in &mut pt.bind {
                f.import_index += base;
            }
            imports.append(&mut pt.imports);
            rebase_fixups.append(&mut pt.rebase);
            bind_fixups.append(&mut pt.bind);
            if validate {
                write_ranges.append(&mut pt.ranges);
            }
        }
    }

    // Write deduplicated merged strings (e.g. __cstring) into the output.
    {
        crate::timing_phase!("Write merged strings");
        write_merged_strings_macho(out, layout, mappings);
    }

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
    {
        crate::timing_phase!("Write stubs + GOT (imports)");
        write_stubs_and_got::<A>(
            out,
            layout,
            mappings,
            &mut rebase_fixups,
            &mut bind_fixups,
            &mut imports,
            has_extra_dylibs,
        )?;
    }

    // Populate GOT entries for non-import symbols
    {
        crate::timing_phase!("Write GOT entries (non-imports)");
        write_got_entries(
            out,
            layout,
            mappings,
            &mut rebase_fixups,
            &mut bind_fixups,
            &mut imports,
            has_extra_dylibs,
            &name_cache,
        )?;
    }

    // Deduplicate imports by (name, lib_ordinal, weak_import, addend).
    // Rust's TLS emits one bind per TLV descriptor all pointing at
    // `__tlv_bootstrap` with addend 0; ld64 collapses these to a single
    // import ordinal that every descriptor references. Addend is part of
    // the key because DYLD_CHAINED_IMPORT_ADDEND[64] stores the addend on
    // the import entry, not the fixup — two fixups to the same symbol
    // with different addends must remain distinct imports.
    {
        let mut seen: std::collections::HashMap<(Vec<u8>, u8, bool, i64), u32> =
            std::collections::HashMap::new();
        let mut deduped: Vec<ImportEntry> = Vec::new();
        // Map each bind_fixup to a new import index based on its full tuple.
        // Unreferenced entries in the original `imports` array are dropped.
        for f in &mut bind_fixups {
            let imp = &imports[f.import_index as usize];
            let key = (imp.name.clone(), imp.lib_ordinal, imp.weak_import, f.addend);
            let idx = *seen.entry(key).or_insert_with(|| {
                let new_idx = deduped.len() as u32;
                deduped.push(ImportEntry {
                    name: imp.name.clone(),
                    lib_ordinal: imp.lib_ordinal,
                    weak_import: imp.weak_import,
                });
                new_idx
            });
            f.import_index = idx;
        }
        imports = deduped;
    }

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
    let mut all_data_fixups: Vec<(usize, u64)> =
        Vec::with_capacity(rebase_fixups.len() + bind_fixups.len());
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
    let total_name_bytes: usize = imports.iter().map(|e| e.name.len() + 1).sum();
    let mut symbols_pool = Vec::with_capacity(1 + total_name_bytes);
    symbols_pool.push(0u8);
    let mut import_name_offsets: Vec<u32> = Vec::with_capacity(imports.len());
    for entry in &imports {
        import_name_offsets.push(symbols_pool.len() as u32);
        symbols_pool.extend_from_slice(&entry.name);
        symbols_pool.push(0);
    }

    // Compute chained fixups data size
    let has_data = mappings.len() > 1 && (mappings[1].vm_end > mappings[1].vm_start);
    let is_dylib = layout.symbol_db.args.is_dylib;
    let base_segs = if is_dylib { 2u32 } else { 3u32 }; // TEXT+LINKEDIT or PAGEZERO+TEXT+LINKEDIT
    // wild splits the merged DATA region into `__DATA_CONST` + `__DATA`
    // at write time when there are both immutable pointer sections
    // (__got etc.) and writable sections (__data/__bss/TLS). That's one
    // extra LC_SEGMENT_64 that dyld's chained-fixups header must know
    // about — otherwise dyld rejects the binary with "seg_count does
    // not match number of segments". The split is unconditional
    // (regardless of `-ld64_compat`): without it, __DATA ends up with
    // `vmsize > filesize` when BSS spills past the content page, and
    // macOS 14+ fills the gap from trailing file bytes (typically
    // LC_DYLD_CHAINED_FIXUPS metadata) instead of zeros — see
    // `project_zerocopy_bss_bug`.
    let splits_data = has_data && data_will_split(layout);
    let seg_count = if has_data {
        base_segs + 1 + if splits_data { 1 } else { 0 }
    } else {
        base_segs
    };
    // Keep in sync with `write_chained_fixups_header`, which rounds
    // starts_in_image_size up to 8 bytes so the following
    // starts_in_segment struct (u64-aligned fields) starts aligned.
    let starts_in_image_size = ((4 + 4 * seg_count) + 7) & !7;
    // Sum the seg_starts entry sizes the writer will emit. Under the
    // compat split we emit one entry for __DATA_CONST (const_pages
    // pages — may be >1 for big Rust binaries where __got alone
    // exceeds 16 KB) plus — when writable __DATA extends past the
    // const region — a second entry covering the remaining pages.
    // Must match `write_chained_fixups_header`.
    let total_seg_starts_size: u32 = if has_fixups && has_data {
        let data_span = mappings[1].vm_end - mappings[1].vm_start;
        let total_pages = ((data_span + PAGE_SIZE - 1) / PAGE_SIZE) as u32;
        if splits_data {
            use output_section_id as osi;
            let data_vmstart = mappings[1].vm_start;
            let const_max_end: u64 = [osi::GOT, osi::INIT_ARRAY, osi::FINI_ARRAY]
                .iter()
                .filter_map(|&id| {
                    let l = layout.section_layouts.get(id);
                    if l.mem_size == 0 {
                        None
                    } else {
                        Some(l.mem_offset + l.mem_size)
                    }
                })
                .max()
                .unwrap_or(data_vmstart);
            let const_pages =
                (((const_max_end - data_vmstart + PAGE_SIZE - 1) / PAGE_SIZE) as u32).max(1);
            let data_pages = total_pages.saturating_sub(const_pages);
            let first = 22 + 2 * const_pages;
            if data_pages > 0 {
                first + 22 + 2 * data_pages
            } else {
                first
            }
        } else {
            22 + 2 * total_pages
        }
    } else {
        0
    };

    let has_addends = bind_fixups.iter().any(|f| f.addend != 0);
    let needs_64bit_addend = bind_fixups
        .iter()
        .any(|f| f.addend > i32::MAX as i64 || f.addend < i32::MIN as i64);
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
        let seg_starts_size = total_seg_starts_size;
        let imports_size = import_entry_size * n_imports;
        let raw =
            32 + starts_in_image_size + seg_starts_size + imports_size + symbols_pool.len() as u32;
        // Round the total dyld_chained_fixups blob up to 8 bytes so the
        // next __LINKEDIT table (LC_DYLD_EXPORTS_TRIE) starts on an
        // 8-byte boundary without an inter-table gap, and the reported
        // datasize matches what `__LINKEDIT.filesize` covers.
        (raw + 7) & !7
    };

    // Build and write __unwind_info now that __eh_frame is in the output buffer.
    // Scan output __eh_frame to map func_vm_addr → EhFrameFdeInfo.
    crate::timing_phase!("Build __unwind_info");
    let unwind_info_size = if unwind_info_vm_addr != 0 {
        let eh_layout = layout.section_layouts.get(output_section_id::EH_FRAME);
        let fde_map: std::collections::HashMap<u64, EhFrameFdeInfo> = if eh_layout.mem_size > 0 {
            if let Some(eh_foff) = vm_addr_to_file_offset(eh_layout.mem_offset, mappings) {
                crate::timing_phase!("Scan eh_frame FDE offsets");
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
        crate::timing_phase!("build_unwind_info_section");
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
    let chained_fixups_offset = {
        crate::timing_phase!("Write Mach-O headers + load commands");
        write_headers(
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
        )?
    };

    // Write chained fixups
    crate::timing_phase!("Write chained fixups");
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
            // When the compat split is active, compute how many pages
            // __DATA_CONST will occupy. This is the smallest contiguous
            // VM range that holds all const sections (GOT, INIT_ARRAY,
            // FINI_ARRAY, etc.) rounded to a page boundary. Big Rust
            // binaries (subxt + sqlx workloads) can push __got past
            // 16 KB; if we tell dyld __DATA_CONST is 1 page when it's
            // really multi-page, the writer's seg layout and the fixup
            // header disagree and dyld aborts with "__got end address
            // is beyond containing segment's end".
            let const_pages: u16 = if splits_data {
                use output_section_id as osi;
                let const_max_end: u64 = [osi::GOT, osi::INIT_ARRAY, osi::FINI_ARRAY]
                    .iter()
                    .filter_map(|&id| {
                        let l = layout.section_layouts.get(id);
                        if l.mem_size == 0 {
                            None
                        } else {
                            Some(l.mem_offset + l.mem_size)
                        }
                    })
                    .max()
                    .unwrap_or(mappings[1].vm_start);
                let const_span = const_max_end - mappings[1].vm_start;
                (((const_span + PAGE_SIZE - 1) / PAGE_SIZE) as u16).max(1)
            } else {
                1
            };
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
                splits_data,
                const_pages,
            )?;
            cf_off as usize + cf_data_size as usize
        }
    } else {
        out.len()
    };

    // Under -ld64_compat, emit LC_DYLD_EXPORTS_TRIE and LC_FUNCTION_STARTS
    // payloads between the chained-fixups and the symtab. ld64 always
    // writes these tables so tools like backtrace symbolization, `atos`,
    // and `dyld` (for exports) can do their jobs from the binary alone.
    // Wild's historical default leaves both empty (datasize=0); the
    // test suite catches those as ~48+8 bytes of __LINKEDIT content
    // missing per binary.
    let mut cursor = final_size;
    let (exports_trie_off, exports_trie_size) = if !layout.symbol_db.args.is_relocatable {
        let (off, size) = write_exports_trie_compat(out, cursor, layout);
        cursor = off + size;
        (off, size)
    } else {
        (cursor, 0usize)
    };
    let (func_starts_off, func_starts_size) =
        if !layout.symbol_db.args.no_function_starts && !layout.symbol_db.args.is_relocatable {
            let (off, size) = write_function_starts_compat(out, cursor, layout, mappings);
            cursor = off + size;
            (off, size)
        } else {
            (cursor, 0usize)
        };
    let final_size = cursor;

    // Write symbol table
    crate::timing_phase!("Write symtab + strtab");
    let final_size = if layout.symbol_db.args.is_dylib {
        write_dylib_symtab(
            out,
            final_size,
            layout,
            mappings,
            func_starts_off,
            func_starts_size,
            exports_trie_off,
            exports_trie_size,
        )?
    } else {
        write_exe_symtab(
            out,
            final_size,
            layout,
            mappings,
            func_starts_off,
            func_starts_size,
            exports_trie_off,
            exports_trie_size,
            precount,
        )?
    };

    Ok(final_size)
}

/// Emit the `LC_FUNCTION_STARTS` table under `-ld64_compat`.
///
/// Format (see ld64 `OutputFile::writeFunctionStartsInfo`):
///   * ULEB128 of the first function's offset from `__TEXT.vmaddr`.
///   * For each subsequent function, ULEB128 of the delta from the previous.
///   * One zero byte terminator.
///   * Zero-padded up to an 8-byte boundary so the next `__LINKEDIT` table (symtab) starts aligned.
///
/// Walks `layout.symbol_resolutions` for external `N_SECT` symbols that
/// fall inside the `__TEXT` segment and sorts them by address.
///
/// **Complexity:** 𝒪(n log n) CPU — one pass over `symbol_resolutions` (𝒪(n))
/// then `sort_unstable` (𝒪(e log e) where e ≤ n); 𝒪(e) memory for the
/// address vec and the ULEB128 payload.
fn write_function_starts_compat(
    out: &mut [u8],
    start: usize,
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
) -> (usize, usize) {
    // Align the payload start to an 8-byte boundary so the on-disk
    // offset in LC_FUNCTION_STARTS stays aligned. dyld's `dyld_info`
    // flags unaligned starts as `mis-aligned LINKEDIT content 'function
    // starts'`; `dyld3::MachOFile::chainedPointerFormat` then reads
    // from a shifted offset and EXC_BAD_ACCESSes at startup.
    let start = (start + 7) & !7;
    let text_vmaddr = mappings.first().map_or(PAGEZERO_SIZE, |m| m.vm_start);
    // Restrict to the __text section specifically, not the whole __TEXT
    // segment — __stubs lives in __TEXT too and its slots would register
    // as bogus "functions" past the real code. ld64's LC_FUNCTION_STARTS
    // only references real code in __text.
    let text_layout = layout.section_layouts.get(output_section_id::TEXT);
    let text_end = text_layout.mem_offset + text_layout.mem_size;

    // Collect function-start VM addresses. "Function" here means any
    // defined symbol whose value lands inside `__text`; restricting to
    // N_SECT externals would miss static functions that ld64 still
    // reports through the input compact-unwind table.
    // Function count is bounded by symbol count; a small starting
    // capacity avoids early growth-doublings on all but trivial links.
    let mut func_vms: Vec<u64> = Vec::with_capacity(256);
    for (sym_idx, res) in layout.symbol_resolutions.iter().enumerate() {
        let Some(res) = res else { continue };
        if res.raw_value == 0 {
            continue;
        }
        if res.flags.contains(crate::value_flags::ValueFlags::DYNAMIC) {
            continue;
        }
        let addr = res.raw_value;
        // Must be strictly *inside* __text — equality with text_vmaddr
        // means the symbol targets the Mach header itself
        // (`__mh_execute_header`, `__mh_dylib_header`, …). Those are
        // linker-synthesised markers, not functions; ld64 excludes them
        // from LC_FUNCTION_STARTS, and strip rejects the payload
        // ("function starts data out of place") when a leading 0-byte
        // uleb128 appears. The upper bound is `__text.end`, not the
        // whole segment — __stubs trailing __text would otherwise
        // register as bogus functions.
        if addr <= text_vmaddr || addr >= text_end {
            continue;
        }
        let sym_id = crate::symbol_db::SymbolId::from_usize(sym_idx);
        let Ok(sym) = layout.symbol_db.symbol_name(sym_id) else {
            continue;
        };
        if sym.bytes().is_empty() {
            continue;
        }
        func_vms.push(addr);
    }
    func_vms.sort_unstable();
    func_vms.dedup();
    if func_vms.is_empty() {
        return (start, 0);
    }

    let mut payload: Vec<u8> = Vec::new();
    let mut prev = text_vmaddr;
    for &vm in &func_vms {
        let delta = vm - prev;
        write_uleb128(&mut payload, delta);
        prev = vm;
    }
    payload.push(0); // terminator
    // Align to 8 bytes so the following table stays aligned.
    while payload.len() % 8 != 0 {
        payload.push(0);
    }

    if start + payload.len() > out.len() {
        // Not enough buffer — keep the table empty rather than overwrite
        // adjacent data. This shouldn't happen in practice (linkedit
        // estimate reserves plenty of slack).
        return (start, 0);
    }
    out[start..start + payload.len()].copy_from_slice(&payload);
    (start, payload.len())
}

/// True when the merged DATA region contains both an immutable-pointer
/// section (routed into `__DATA_CONST`) and a writable section (routed
/// into `__DATA`), i.e. when the writer's `write_headers` will emit two
/// LC_SEGMENT_64 commands instead of one. `write_chained_fixups_header`
/// / `cf_data_size` need to count the extra segment in `seg_count`,
/// otherwise dyld rejects the binary with "seg_count does not match
/// number of segments".
///
/// **Complexity:** 𝒪(1) CPU and memory — checks a fixed set of 7 section slots.
fn data_will_split(layout: &Layout<'_, MachO>) -> bool {
    let has_size = |id| layout.section_layouts.get(id).mem_size > 0;
    let has_const = has_size(output_section_id::GOT)
        || has_size(output_section_id::INIT_ARRAY)
        || has_size(output_section_id::FINI_ARRAY);
    let has_writable = has_size(output_section_id::DATA)
        || has_size(output_section_id::BSS)
        || has_size(output_section_id::TDATA)
        || has_size(output_section_id::TBSS)
        || has_size(output_section_id::CSTRING)
        || has_size(output_section_id::PREINIT_ARRAY);
    has_const && has_writable
}

/// Append the ULEB128 encoding of `value` to `buf`.
///
/// **Complexity:** 𝒪(log value) CPU — one byte emitted per 7 bits; 𝒪(log value) memory.
fn write_uleb128(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Emit the `LC_DYLD_EXPORTS_TRIE` payload under `-ld64_compat` for an
/// executable. ld64 always publishes a trie of the exe's external
/// defined symbols (plus `__mh_execute_header`) so `dlsym(RTLD_DEFAULT, …)`
/// and `dyld`'s debugger interfaces can resolve them.
///
/// Returns `(offset, size)` — offset is the (8-byte-aligned) position
/// where the payload starts and size is its byte length (0 when no
/// exports were found).
///
/// **Complexity:** 𝒪(n + m + e · L̄ · log e) CPU — 𝒪(n + m) to precompute
/// per-symbol `N_EXT` / `N_PEXT` bits in one sweep over objects
/// (was 𝒪(n · m) because the old per-symbol `is_symbol_external` /
/// `is_symbol_private_external` calls each re-scanned every group ×
/// file), 𝒪(n) for the resolution scan, then `build_export_trie` on
/// the e surviving entries; 𝒪(e · L̄ + n) memory where L̄ is average
/// symbol-name length.
fn write_exports_trie_compat(
    out: &mut [u8],
    start: usize,
    layout: &Layout<'_, MachO>,
) -> (usize, usize) {
    // The trie needs 8-byte alignment to keep following tables aligned.
    let off = (start + 7) & !7;

    let mut entries: Vec<(Vec<u8>, u64)> = Vec::new();
    let mut seen: std::collections::HashSet<Vec<u8>> = Default::default();
    // The exports trie stores each symbol's address as an offset from
    // the image's load base — i.e. VM address minus `__PAGEZERO` size
    // for executables, or 0 for position-independent dylibs. Encoding
    // full VM addresses worked for tiny fixtures whose 0x1000003XX
    // offsets dyld happily processed, but any non-trivial binary
    // (e.g. Rust's `rust-hello`) trips dyld's "vmOffset too large for
    // <sym>" check and the whole image fails to load.
    let is_dylib = layout.symbol_db.args.is_dylib;
    let image_base =
        if !is_dylib && !layout.symbol_db.args.is_bundle && !layout.symbol_db.args.is_relocatable {
            PAGEZERO_SIZE
        } else {
            0
        };

    if is_dylib {
        // Dylibs export only what's in `dynamic_symbol_definitions`. Walking
        // every `symbol_resolutions` entry would pull in every external
        // std-library symbol — for a trivial Rust dylib that's 100 KB+ of
        // trie, which codesign's dylib path can't handle and leaves
        // LINKEDIT bloated with dead trie content.
        //
        // Avoid `.iter().nth(i)` (which is 𝒪(i) for a Vec iterator —
        // walks from the start) in favour of direct slice indexing
        // — 𝒪(1) per def instead of 𝒪(|dyn_defs| · n).
        let resolutions = layout.symbol_resolutions.as_slice();
        for def in &layout.dynamic_symbol_definitions {
            let sym_id = def.symbol_id;
            let Some(res) = resolutions.get(sym_id.as_usize()).and_then(|r| r.as_ref()) else {
                continue;
            };
            if res.raw_value == 0 {
                continue;
            }
            let name = def.name.to_vec();
            if name.is_empty() || seen.contains(&name) {
                continue;
            }
            seen.insert(name.clone());
            entries.push((name, res.raw_value.saturating_sub(image_base)));
        }
    } else {
        // __mh_execute_header points at __TEXT's start (i.e. PAGEZERO end,
        // which is offset 0 from the image base). Matching ld64: always
        // exported even if unreferenced.
        entries.push((b"__mh_execute_header".to_vec(), 0));
        seen.insert(b"__mh_execute_header".to_vec());

        // Beyond `__mh_execute_header`, an executable's exports_trie
        // should only contain symbols the user explicitly asked to
        // export (`-export_dynamic`, `-exported_symbol`, or an
        // exports list). ld64 defaults to just the header — walking
        // every external symbol would publish inlined C++ weak
        // definitions (e.g. `__ZN3FooC1Ev`), which the `weak-def-ref`
        // test expects absent.
        let only_header = !layout.symbol_db.args.export_dynamic
            && layout.symbol_db.args.exported_symbols_list.is_none()
            && layout.symbol_db.args.exported_symbols.is_empty();

        if !only_header {
            // Pre-compute per-symbol `N_EXT` and `N_PEXT` bits in one
            // sweep over input objects, so the hot loop below is 𝒪(1)
            // per symbol instead of calling `is_symbol_external` /
            // `is_symbol_private_external` (each a 𝒪(m) scan of
            // groups × files). Prevents a 𝒪(n · m) quadratic when
            // `-export_dynamic` is active on a large link.
            let (ext_bits, pext_bits): (Vec<bool>, Vec<bool>) = {
                use object::read::macho::Nlist as _;
                let n = layout.symbol_resolutions.len();
                let mut ext = vec![false; n];
                let mut pext = vec![false; n];
                for group in &layout.group_layouts {
                    for file_layout in &group.files {
                        if let FileLayout::Object(obj) = file_layout {
                            let start = obj.symbol_id_range.start().as_usize();
                            for i in 0..obj.symbol_id_range.len() {
                                if let Ok(sym) = obj.object.symbols.symbol(object::SymbolIndex(i)) {
                                    let t = sym.n_type();
                                    ext[start + i] = (t & object::macho::N_EXT) != 0;
                                    pext[start + i] = (t & object::macho::N_PEXT) != 0;
                                }
                            }
                        }
                    }
                }
                (ext, pext)
            };
            let resolutions = layout.symbol_resolutions.as_slice();
            for (sym_idx, res) in resolutions.iter().enumerate() {
                let Some(res) = res else { continue };
                if res.raw_value == 0 {
                    continue;
                }
                if res.flags.contains(crate::value_flags::ValueFlags::DYNAMIC) {
                    continue;
                }
                if !ext_bits[sym_idx] && !res.flags.needs_export_dynamic() {
                    continue;
                }
                if res.flags.is_downgraded_to_local() {
                    continue;
                }
                // Hidden-visibility symbols are private-external: visible across
                // translation units within the image but not exported to dyld's
                // global namespace. ld64 keeps them out of LC_DYLD_EXPORTS_TRIE.
                if pext_bits[sym_idx] {
                    continue;
                }
                let sym_id = crate::symbol_db::SymbolId::from_usize(sym_idx);
                let Ok(name) = layout.symbol_db.symbol_name(sym_id) else {
                    continue;
                };
                let name = name.bytes().to_vec();
                if name.is_empty() || seen.contains(&name) {
                    continue;
                }
                seen.insert(name.clone());
                entries.push((name, res.raw_value.saturating_sub(image_base)));
            }
        }
    }

    // Always write a trie — even empty dylibs get a minimal 2-byte
    // terminator so LC_DYLD_EXPORTS_TRIE points at real bytes (not at
    // chained_fixups) and codesign's strict validation passes. ld64
    // does the same: its empty-dylib trie is 8 bytes (terminator +
    // alignment).
    let mut trie = build_export_trie(&entries);
    // Pad to 8 bytes so the following LINKEDIT table (function_starts)
    // starts immediately after on an aligned boundary. strip rejects a
    // gap between tables ("function starts data out of place") even
    // when the dataoff alignment is satisfied independently.
    while trie.len() % 8 != 0 {
        trie.push(0);
    }
    if off + trie.len() > out.len() {
        return (off, 0);
    }
    out[off..off + trie.len()].copy_from_slice(&trie);
    (off, trie.len())
}

/// Write a minimal symbol table for dylib exports.
///
/// Emits nlist64 entries for `dynamic_symbol_definitions`, builds the string
/// table, optionally builds an exports trie (reusing the pre-computed one in
/// compat mode), then patches LC_SYMTAB / LC_DYSYMTAB / LC_DYLD_EXPORTS_TRIE
/// / LC_LINKEDIT in the already-written headers.
///
/// **Complexity:** 𝒪(e · L̄ + L) CPU — e exported symbols × average name
/// length for strtab construction, plus a single forward walk over L load
/// commands to patch headers; 𝒪(e · L̄) memory.
fn write_dylib_symtab(
    out: &mut [u8],
    start: usize,
    layout: &Layout<'_, MachO>,
    _mappings: &[SegmentMapping],
    // LC_FUNCTION_STARTS payload emitted by `write_function_starts_compat`
    // before this symtab. Patched into the dylib's LC so `atos` /
    // symbolicate can read it. Leaving the LC at `datasize=0` was the
    // bug that made the 6 KB function-starts blob look like an
    // unreferenced gap to codesign.
    func_starts_off: usize,
    func_starts_size: usize,
    // If `write_exports_trie_compat` already emitted a trie before this
    // symtab (compat mode), reuse it. Otherwise build one inline here.
    // Emitting twice leaves a multi-KB dead-data gap in __LINKEDIT that
    // codesign's dylib path refuses with "internal error in Code
    // Signing subsystem".
    pre_exports_trie_off: usize,
    pre_exports_trie_size: usize,
) -> Result<usize> {
    // Collect exported symbols from dynamic_symbol_definitions.
    //
    // Avoid `.iter().nth(i)` (𝒪(i) for a Vec iterator — walks from
    // the start) in favour of direct slice indexing: this drops the
    // loop from 𝒪(|dyn_defs|·n) to 𝒪(|dyn_defs|). Same fix as
    // `write_exports_trie_compat`'s dylib path.
    let mut entries: Vec<(Vec<u8>, u64)> =
        Vec::with_capacity(layout.dynamic_symbol_definitions.len());
    let resolutions = layout.symbol_resolutions.as_slice();
    for def in &layout.dynamic_symbol_definitions {
        let sym_id = def.symbol_id;
        if let Some(res) = resolutions.get(sym_id.as_usize()).and_then(|r| r.as_ref()) {
            entries.push((def.name.to_vec(), res.raw_value));
        }
    }

    // No early-return for empty entries — an empty dylib still needs a
    // valid LC_SYMTAB (symoff pointing to a 1-byte "\\0" strtab), a
    // minimal exports trie, and a codesign blob. Skipping these leaves
    // dyld's strict-validation refusing the image as "not signed".

    // Build string table: starts with \0
    let strtab_cap = 1 + entries.iter().map(|(n, _)| n.len() + 1).sum::<usize>();
    let mut strtab = Vec::with_capacity(strtab_cap);
    strtab.push(0u8);
    let mut str_offsets = Vec::with_capacity(entries.len());
    for (name, _) in &entries {
        str_offsets.push(strtab.len() as u32);
        strtab.extend_from_slice(name);
        strtab.push(0);
    }

    // Build sorted section ranges from the already-written headers
    // so per-symbol n_sect lookup is O(log N) instead of a linear scan.
    let sorted_sections = sorted_section_ranges_with_idx(out);

    // Write nlist64 entries (16 bytes each).
    // Align symtab start to 8 bytes (required by ld64 when consuming dylibs).
    let symoff = (start + 7) & !7;
    let nsyms = entries.len();
    let mut pos = symoff;
    for (i, (_, value)) in entries.iter().enumerate() {
        if pos + 16 > out.len() {
            break;
        }
        let n_sect = {
            let idx = symtab_section_for_addr(&sorted_sections, *value);
            if idx == 0 { 1 } else { idx }
        };
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

    // Build export trie for dlsym (must be aligned). In compat mode
    // `write_exports_trie_compat` already emitted one before the symtab;
    // reuse it so LINKEDIT stays packed (codesign rejects gapped dylibs
    // with "internal error in Code Signing subsystem").
    let (trie_off, trie_size) = if pre_exports_trie_size > 0 {
        (pre_exports_trie_off, pre_exports_trie_size)
    } else {
        let trie_off = (pos + 7) & !7;
        let trie = build_export_trie(&entries);
        if trie_off + trie.len() <= out.len() {
            out[trie_off..trie_off + trie.len()].copy_from_slice(&trie);
        }
        pos = trie_off + trie.len();
        (trie_off, trie.len())
    };

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
                    .copy_from_slice(&(trie_size as u32).to_le_bytes());
            }
            LC_FUNCTION_STARTS => {
                let (o, s) = if func_starts_size > 0 {
                    (func_starts_off as u32, func_starts_size as u32)
                } else {
                    (start as u32, 0u32)
                };
                out[off as usize + 8..off as usize + 12].copy_from_slice(&o.to_le_bytes());
                out[off as usize + 12..off as usize + 16].copy_from_slice(&s.to_le_bytes());
            }
            _ => {}
        }
        off += cmdsize;
    }

    Ok(pos)
}

/// Parse section address ranges from the already-written Mach-O headers.
/// Returns a vec of (start_addr, end_addr) in section order.
///
/// **Complexity:** 𝒪(L + s) CPU, 𝒪(s) memory — single forward pass over
/// load commands; one entry pushed per section.
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

/// Sort section ranges by start address and tag each with its 1-based
/// Mach-O section index. The tagged form is what `symtab_section_for_addr`
/// needs for O(log N) binary-search lookup during nlist emission.
///
/// **Complexity:** 𝒪(L + s · log s) CPU — `parse_section_ranges` (𝒪(L + s))
/// plus `sort_by_key` (𝒪(s log s)); 𝒪(s) memory.
fn sorted_section_ranges_with_idx(out: &[u8]) -> Vec<(u64, u64, u8)> {
    let mut with_idx: Vec<(u64, u64, u8)> = parse_section_ranges(out)
        .into_iter()
        .enumerate()
        .map(|(i, (s, e))| (s, e, (i + 1) as u8))
        .collect();
    with_idx.sort_by_key(|t| t.0);
    with_idx
}

/// Map a VM address to the 1-based Mach-O section index whose range
/// contains it. Assumes `sorted` is non-overlapping and sorted by start.
///
/// **Complexity:** 𝒪(log s) CPU, 𝒪(1) extra memory — `partition_point` binary search.
fn symtab_section_for_addr(sorted: &[(u64, u64, u8)], value: u64) -> u8 {
    let i = sorted.partition_point(|&(s, _, _)| s <= value);
    if i == 0 {
        return 0;
    }
    let (_, end, idx) = sorted[i - 1];
    if value < end { idx } else { 0 }
}

/// Check if a symbol was originally external (N_EXT) in its input object.
///
/// Walks all groups × files looking for the owning object, then reads the
/// raw `n_type` byte. Defaults to `true` for synthetic / prelude symbols.
///
/// **Complexity:** 𝒪(m) CPU — linear scan over all object files; 𝒪(1) memory.
/// Hot callers should use the pre-computed `external_bits` vec instead.
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

/// True if the input symbol was marked `__attribute__((visibility("hidden")))`
/// — i.e. has the `N_PEXT` (private-external) bit set in the source object's
/// `n_type`. ld64 keeps these in the symtab (as private externals) but drops
/// them from `LC_DYLD_EXPORTS_TRIE`; wild's compat path mirrors that.
///
/// **Complexity:** 𝒪(m) CPU — same linear-scan pattern as `is_symbol_external`; 𝒪(1) memory.
fn is_symbol_private_external(
    layout: &Layout<'_, MachO>,
    symbol_id: crate::symbol_db::SymbolId,
) -> bool {
    use object::read::macho::Nlist as _;
    let file_id = layout.symbol_db.file_id_for_symbol(symbol_id);
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            if let crate::layout::FileLayout::Object(obj) = file_layout {
                if obj.file_id == file_id {
                    let local_index = symbol_id.to_input(obj.symbol_id_range);
                    if let Ok(sym) = obj.object.symbols.symbol(local_index) {
                        return (sym.n_type() & object::macho::N_PEXT) != 0;
                    }
                }
            }
        }
    }
    false
}

/// Write a symbol table for executables so that backtraces can resolve function names.
///
/// `func_starts_off` / `func_starts_size` locate the `LC_FUNCTION_STARTS`
/// payload the caller has already written (zero when no payload was
/// produced, i.e. no `-ld64_compat` or `-no_function_starts`).
/// `exports_trie_off` / `exports_trie_size` do the same for the
/// `LC_DYLD_EXPORTS_TRIE` payload.
///
/// Sub-phases and their complexity:
/// - Stab construction: 𝒪(m · f̄) where f̄ = avg functions per object; 𝒪(t) memory.
/// - `external_bits` precompute: Θ(n) CPU, 𝒪(n) memory — one flag per resolution.
/// - Defined-symbol collection (rayon `par_chunks`): Θ(n/T) wall-clock, 𝒪(e) memory.
/// - N_ABS + N_UNDF_EXT sweep: 𝒪(n) CPU.
/// - Sort: 𝒪(e log e) CPU.
/// - Strtab + nlist write: 𝒪(e · L̄) CPU and memory.
/// - Indirect symbol table: 𝒪(i) CPU.
/// - Header patching: 𝒪(L) CPU.
///
/// **Complexity:** Θ(n + t + e log e) CPU sequentially;
/// 𝒪((n + t)/T) wall-clock with rayon; 𝒪(n + e · L̄) memory.
fn write_exe_symtab(
    out: &mut [u8],
    start: usize,
    layout: &Layout<'_, MachO>,
    _mappings: &[SegmentMapping],
    func_starts_off: usize,
    func_starts_size: usize,
    exports_trie_off: usize,
    exports_trie_size: usize,
    precount: &MachOSymtabPrecount,
) -> Result<usize> {
    use crate::symbol_db::SymbolId;

    // Synthesize N_OSO stab entries for each input object so dsymutil
    // can follow them back to the .o files for DWARF extraction.
    // ld64's rule: emit stabs only when the input actually has debug
    // info (a `__DWARF` segment) — emitting for every object inflates
    // the symtab by ~8 entries per input for no benefit on release
    // builds. Honour `-S` (strip debug) by skipping entirely.
    // Stab entries: (name, n_type, n_sect, n_desc, n_value).
    // Each input object with debug info emits ~2 + 4·fn_count entries
    // (SO/OSO markers + BNSYM/FUN/END/ENSYM per function). Pre-size to
    // the object count times a small per-object average so the common
    // path skips the first 6-7 growth doublings.
    let n_objects = layout
        .group_layouts
        .iter()
        .flat_map(|g| &g.files)
        .filter(|f| matches!(f, crate::layout::FileLayout::Object(_)))
        .count();
    let mut stab_entries: Vec<(Vec<u8>, u8, u8, u16, u64)> =
        Vec::with_capacity(if layout.symbol_db.args.should_strip_debug() {
            0
        } else {
            n_objects * 8
        });
    if !layout.symbol_db.args.should_strip_debug() {
        crate::timing_phase!("symtab: build stabs");
        for group in &layout.group_layouts {
            for file_layout in &group.files {
                if let crate::layout::FileLayout::Object(obj) = file_layout {
                    if !object_has_debug_info(obj) {
                        continue;
                    }
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
                        if !d.ends_with('/') {
                            d.push('/');
                        }
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
                                stab_entries.push((
                                    name,
                                    n_type,
                                    sym.n_sect(),
                                    sym.n_desc(le),
                                    sym.n_value(le),
                                ));
                                continue;
                            }
                            // Synthesize FUN stabs for defined external functions in __text.
                            if (n_type & 0x0F) != 0x0F {
                                continue;
                            } // N_SECT | N_EXT
                            let n_sect = sym.n_sect();
                            if n_sect == 0 {
                                continue;
                            }
                            let sec_idx = n_sect as usize - 1;
                            let is_text = obj
                                .object
                                .sections
                                .get(sec_idx)
                                .map(|s| crate::macho::trim_nul(s.sectname()) == b"__text")
                                .unwrap_or(false);
                            if !is_text {
                                continue;
                            }
                            let sym_name =
                                sym.name(le, obj.object.symbols.strings()).unwrap_or(&[]);
                            let sym_id = obj
                                .symbol_id_range
                                .input_to_id(object::SymbolIndex(sym_idx));
                            let Some(res) = layout.merged_symbol_resolution(sym_id) else {
                                continue;
                            };
                            if res.raw_value == 0 {
                                continue;
                            }
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

    // Collect defined symbols into three category-specific Vecs so we
    // can skip the global sort over every nlist row (DYSYMTAB requires
    // locals | extdef | undef to be contiguous; within each category
    // we sort by address, which matches ld64's emission and is what
    // `-ld64_compat` golden fixtures expect).
    //
    // Pre-sized from `MachOSymtabPrecount` so the common path skips
    // every allocator growth-doubling. N_ABS entries from the
    // secondary-pass (raw nlist `N_ABS` not already in
    // `symbol_resolutions`) emit n_type=0x02 (non-ext) and sort into
    // the locals group, so `locals_cap` budgets them here.
    //
    // `+1` headroom on `extdef_cap` covers the synthesised
    // `__mh_execute_header`; `dynamic_undefined_symbols.len()`
    // headroom on `undef_cap` covers `-U` imports that could not be
    // deduped in precount without a second resolver pass.
    let locals_cap = precount.n_locals as usize + precount.n_abs as usize;
    let extdef_cap = precount.n_ext_def as usize + 1;
    let undef_cap =
        precount.n_undef_ext as usize + layout.symbol_db.args.dynamic_undefined_symbols.len();
    let mut locals_entries: Vec<(Vec<u8>, u64, u8)> = Vec::with_capacity(locals_cap);
    let mut extdef_entries: Vec<(Vec<u8>, u64, u8)> = Vec::with_capacity(extdef_cap);
    let mut undef_entries: Vec<(Vec<u8>, u64, u8)> = Vec::with_capacity(undef_cap);
    let mut seen_names: std::collections::HashSet<Vec<u8>> =
        std::collections::HashSet::with_capacity(locals_cap + extdef_cap + undef_cap);

    // Pre-compute per-symbol `N_EXT` bit in one sweep over objects, so the hot
    // loop below is O(1) per symbol instead of calling `is_symbol_external`,
    // which re-scans every (group, file) on each call.
    let external_bits: Vec<bool> = {
        crate::timing_phase!("symtab: precompute external bits");
        use object::read::macho::Nlist as _;
        let mut bits = vec![true; layout.symbol_resolutions.len()];
        for group in &layout.group_layouts {
            for file_layout in &group.files {
                if let crate::layout::FileLayout::Object(obj) = file_layout {
                    let start = obj.symbol_id_range.start().as_usize();
                    let n = obj.symbol_id_range.len();
                    for i in 0..n {
                        if let Ok(sym) = obj.object.symbols.symbol(object::SymbolIndex(i)) {
                            bits[start + i] = (sym.n_type() & object::macho::N_EXT) != 0;
                        } else {
                            bits[start + i] = false;
                        }
                    }
                }
            }
        }
        bits
    };

    {
        crate::timing_phase!("symtab: collect defined");
        // Parallel scan over `layout.symbol_resolutions` (~5 M for
        // rust-analyzer). Filters are ordered cheapest-first; the
        // name is borrowed through every predicate and only cloned
        // into an owned `Vec<u8>` for the handful of rows that
        // survive (`entries` + `seen_names`). Each rayon worker
        // builds a partial `Vec<(name, value, n_type)>`; the serial
        // merge below appends all partials into `entries` and
        // inserts into `seen_names` in one pass.
        use rayon::prelude::*;
        const CHUNK: usize = 64 * 1024;
        let strip_locals = layout.symbol_db.args.strip_locals;
        let resolutions = layout.symbol_resolutions.as_slice();
        let ext_bits = external_bits.as_slice();
        // Each worker emits two sub-partials (locals, extdefs). The
        // serial merge below routes them into the category Vecs in
        // one pass without re-examining n_type.
        let partials: Vec<(Vec<(Vec<u8>, u64, u8)>, Vec<(Vec<u8>, u64, u8)>)> = resolutions
            .par_chunks(CHUNK)
            .enumerate()
            .map(|(chunk_idx, chunk)| {
                let base = chunk_idx * CHUNK;
                let mut locals_part: Vec<(Vec<u8>, u64, u8)> = Vec::with_capacity(chunk.len() / 16);
                let mut extdef_part: Vec<(Vec<u8>, u64, u8)> = Vec::with_capacity(chunk.len() / 16);
                for (offset, slot) in chunk.iter().enumerate() {
                    let Some(res) = slot else { continue };
                    if res.raw_value == 0 {
                        continue;
                    }
                    if res.flags.contains(crate::value_flags::ValueFlags::DYNAMIC) {
                        continue;
                    }
                    let sym_idx = base + offset;
                    let symbol_id = SymbolId::from_usize(sym_idx);
                    let Ok(name_ref) = layout.symbol_db.symbol_name(symbol_id) else {
                        continue;
                    };
                    let name_bytes = name_ref.bytes();
                    if name_bytes.is_empty() {
                        continue;
                    }
                    let is_external = (!res.flags.is_downgraded_to_local() && ext_bits[sym_idx])
                        || res.flags.needs_export_dynamic();
                    if strip_locals && !is_external {
                        continue;
                    }
                    if !is_external
                        && (name_bytes.starts_with(b"L") || name_bytes.starts_with(b"l_"))
                    {
                        continue;
                    }
                    let n_type = if res.flags.contains(crate::value_flags::ValueFlags::ABSOLUTE) {
                        if is_external { 0x03_u8 } else { 0x02_u8 }
                    } else if is_external {
                        0x0f_u8
                    } else {
                        0x0e_u8
                    };
                    if is_external {
                        extdef_part.push((name_bytes.to_vec(), res.raw_value, n_type));
                    } else {
                        locals_part.push((name_bytes.to_vec(), res.raw_value, n_type));
                    }
                }
                (locals_part, extdef_part)
            })
            .collect();
        for (locals_part, extdef_part) in partials {
            for (name, value, n_type) in locals_part {
                seen_names.insert(name.clone());
                locals_entries.push((name, value, n_type));
            }
            for (name, value, n_type) in extdef_part {
                seen_names.insert(name.clone());
                extdef_entries.push((name, value, n_type));
            }
        }
    }

    // Synthesize the conventional external symbol `__mh_execute_header`
    // pointing at the mach header (start of __TEXT). ld64 always emits
    // this in an executable's symtab — runtime tools like
    // `_dyld_get_image_header`, backtrace(), crash-reporters, and
    // `dladdr` all look it up to map an address back to the image.
    if !layout.symbol_db.args.is_dylib
        && !layout.symbol_db.args.is_bundle
        && !layout.symbol_db.args.is_relocatable
    {
        let name: &[u8] = b"__mh_execute_header";
        if !seen_names.contains(name) {
            seen_names.insert(name.to_vec());
            // __mh_execute_header lives at the start of __TEXT (just
            // past __PAGEZERO). N_SECT | N_EXT (0x0f) with section
            // index 1 matches ld64's emission.
            extdef_entries.push((name.to_vec(), PAGEZERO_SIZE, 0x0f));
        }
    }

    // Walk every input object once, picking up both kinds of
    // "undefined/external-ish" entries the symtab needs to
    // preserve:
    //   * N_ABS: absolute symbols the linker didn't map to a section (Apple tooling keeps these
    //     visible).
    //   * N_UNDF|N_EXT: undefined externals without PLT/GOT, e.g. `__tlv_bootstrap` reached via a
    //     direct pointer.
    //
    // `seen_names` is populated by the defined-symbol pass above
    // and only read from here; each worker uses it to short-
    // circuit before allocating a `Vec<u8>` key. Objects' symbol
    // tables are disjoint slices of input data, so the walk
    // parallelises perfectly — one worker per object, rayon
    // does the scheduling.
    {
        crate::timing_phase!("symtab: collect N_ABS+N_UNDF_EXT");
        use object::read::macho::Nlist as _;
        use rayon::prelude::*;
        let le = object::Endianness::Little;
        let seen_ref = &seen_names;
        let objects: Vec<&crate::layout::ObjectLayout<'_, MachO>> = layout
            .group_layouts
            .iter()
            .flat_map(|g| g.files.iter())
            .filter_map(|f| match f {
                crate::layout::FileLayout::Object(o) => Some(o),
                _ => None,
            })
            .collect();
        let partials: Vec<Vec<(Vec<u8>, u64, u8)>> = objects
            .par_iter()
            .map(|obj| -> Vec<(Vec<u8>, u64, u8)> {
                let strings = obj.object.symbols.strings();
                let n = obj.object.symbols.len();
                // Most objects have <10 N_ABS/N_UNDF_EXT entries.
                let mut local: Vec<(Vec<u8>, u64, u8)> = Vec::new();
                for sym_idx in 0..n {
                    let Ok(sym) = obj.object.symbols.symbol(object::SymbolIndex(sym_idx)) else {
                        continue;
                    };
                    let n_type_raw = sym.n_type();
                    let is_abs = (n_type_raw & 0x0e) == 0x02;
                    let is_undf_ext = (n_type_raw & 0x0e) == 0 && (n_type_raw & 0x01) != 0;
                    if !is_abs && !is_undf_ext {
                        continue;
                    }
                    let name = sym.name(le, strings).unwrap_or(&[]);
                    if name.is_empty() {
                        continue;
                    }
                    if seen_ref.contains(name) {
                        continue;
                    }
                    if is_abs {
                        let val = sym.n_value(le);
                        if val != 0 {
                            local.push((name.to_vec(), val, 0x02));
                        }
                    } else {
                        local.push((name.to_vec(), 0, 0x01));
                    }
                }
                local
            })
            .collect();
        // Serial merge with final dedup — workers independently
        // emitted candidates not in seen_names, but two workers
        // could emit the same name. Route N_ABS (0x02, non-ext,
        // val != 0) to locals; N_UNDF | N_EXT (0x01, val == 0) to
        // undefs. See sort key in the legacy writer for the mapping.
        for chunk in partials {
            for (name, val, n_type) in chunk {
                if !seen_names.contains(&name) {
                    seen_names.insert(name.clone());
                    if n_type == 0x02 {
                        locals_entries.push((name, val, n_type));
                    } else {
                        undef_entries.push((name, val, n_type));
                    }
                }
            }
        }
    }

    // Add -U (dynamic undefined) symbols as N_UNDF | N_EXT in the output.
    for sym_name in &layout.symbol_db.args.dynamic_undefined_symbols {
        if !seen_names.contains(sym_name) {
            seen_names.insert(sym_name.clone());
            undef_entries.push((sym_name.clone(), 0, 0x01)); // N_UNDF | N_EXT
        }
    }

    // Add imported symbols (those with stubs/GOT) as undefined externals.
    // Track which symbols have stubs for the indirect symbol table.
    // Both sized proportional to imports count; 64 covers most small links.
    let mut stub_symbols: Vec<(u64, Vec<u8>)> = Vec::with_capacity(64); // (plt_addr, name)
    let mut got_symbols: Vec<(u64, Vec<u8>)> = Vec::with_capacity(64); // (got_addr, name)
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
            undef_entries.push((name, 0, 0x01)); // N_UNDF | N_EXT
        }
    }
    stub_symbols.sort_by_key(|s| s.0);
    got_symbols.sort_by_key(|s| s.0);

    // (N_UNDF|N_EXT scan merged into the N_ABS pass above.)

    if locals_entries.is_empty()
        && extdef_entries.is_empty()
        && undef_entries.is_empty()
        && stab_entries.is_empty()
    {
        return Ok(start);
    }

    // Sort each category Vec by address (DYSYMTAB requires the regions
    // contiguous; address ordering within each matches ld64 and keeps
    // `-ld64_compat` fixtures byte-identical). Three smaller sorts in
    // parallel replaces the single global sort; per-sort work is
    // smaller and rayon can overlap all three.
    {
        crate::timing_phase!("symtab: sort per-category");
        use rayon::slice::ParallelSliceMut;
        rayon::join(
            || {
                rayon::join(
                    || locals_entries.par_sort_unstable_by_key(|e| e.1),
                    || extdef_entries.par_sort_unstable_by_key(|e| e.1),
                )
            },
            || undef_entries.par_sort_unstable_by_key(|e| e.1),
        );
    }

    crate::timing_phase!("symtab: build strtab + write nlist");
    // Build string table: starts with \0, then stabs, then the three
    // category regions in DYSYMTAB order (locals → extdef → undef).
    // Pre-size via precount.strtab_bytes (exact count of bytes for
    // per-object + secondary-pass names) + stab name bytes + leading
    // NUL + small headroom for synthesised `__mh_execute_header`.
    let stab_name_bytes: usize = stab_entries
        .iter()
        .map(|(n, _, _, _, _)| if n.is_empty() { 0 } else { n.len() + 1 })
        .sum();
    let strtab_cap = 1 + stab_name_bytes + precount.strtab_bytes as usize + 64;
    let mut strtab = Vec::with_capacity(strtab_cap);
    strtab.push(0u8);
    let mut stab_str_offsets = Vec::with_capacity(stab_entries.len());
    for (name, _, _, _, _) in &stab_entries {
        if name.is_empty() {
            stab_str_offsets.push(0u32); // empty name points to the leading \0
        } else {
            stab_str_offsets.push(strtab.len() as u32);
            strtab.extend_from_slice(name);
            strtab.push(0);
        }
    }
    // Pre-size the combined str_offsets Vec to fit all three categories.
    let total_entries = locals_entries.len() + extdef_entries.len() + undef_entries.len();
    let mut str_offsets: Vec<u32> = Vec::with_capacity(total_entries);
    for (name, _, _) in locals_entries
        .iter()
        .chain(extdef_entries.iter())
        .chain(undef_entries.iter())
    {
        str_offsets.push(strtab.len() as u32);
        strtab.extend_from_slice(name);
        strtab.push(0);
    }

    // Write nlist64 entries (16 bytes each). No alignment padding —
    // LINKEDIT must be fully packed for strip(1) compatibility.
    // Stab entries come first (they're part of the local symbol range),
    // then the three DYSYMTAB regions in order.
    let symoff = start;
    let nsyms = stab_entries.len() + total_entries;
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

    // Write the three category regions in DYSYMTAB order. Serial;
    // rayon par_chunks_exact_mut experimentally cost more in
    // thread-wakeup overhead than it saved in per-row compute
    // across the bench matrix (tested 2026-04-21). `str_offsets`
    // indexes sequentially into the concatenation locals ++ extdef
    // ++ undef, so a single cursor matches.
    let sorted_sections = sorted_section_ranges_with_idx(out);
    let mut str_off_idx = 0usize;
    for (name, value, n_type) in locals_entries
        .iter()
        .chain(extdef_entries.iter())
        .chain(undef_entries.iter())
    {
        if pos + 16 > out.len() {
            break;
        }
        let n_sect = if *n_type == 0x02 {
            0u8 // N_ABS
        } else if name.as_slice() == b"__mh_execute_header" {
            // `__mh_execute_header` points at the mach header, which
            // sits before any section VM range. ld64 reports it as
            // living in section 1 (first section of __TEXT) rather
            // than section 0 (undefined); matching that keeps nm and
            // `_dyld_get_image_header` lookups consistent.
            1u8
        } else {
            symtab_section_for_addr(&sorted_sections, *value)
        };
        out[pos..pos + 4].copy_from_slice(&str_offsets[str_off_idx].to_le_bytes());
        out[pos + 4] = *n_type;
        out[pos + 5] = n_sect;
        out[pos + 6..pos + 8].copy_from_slice(&0u16.to_le_bytes());
        out[pos + 8..pos + 16].copy_from_slice(&value.to_le_bytes());
        pos += 16;
        str_off_idx += 1;
    }

    // Build indirect symbol table: maps __stubs and __got entries to nlist indices.
    //
    // Per Mach-O spec, indirect-table entries whose target is a
    // locally-defined symbol must OR in `INDIRECT_SYMBOL_LOCAL`
    // (0x80000000). Without it, `strip(1)` sees the entry as
    // referencing a strippable symbol it's not allowed to remove and
    // errors with *"symbols referenced by indirect symbol table
    // entries that can't be stripped"*. rustc's post-link strip
    // wrapper removes the symbol anyway, leaving the TLV/GOT
    // descriptor pointing at nothing — Rust's runtime dereferences
    // that during `std::rt::init`'s first `pthread_mutex_lock` and
    // the binary `EXC_BAD_ACCESS`es at startup.
    //
    // Reproducer: `wild/tests/sources/macho/rust-strip-debuginfo/`
    // (currently `//#Ignore`d; once this fix lands, drop the
    // Ignore directive).
    //
    // A defined symbol in `entries` has `n_type & 0x0e != 0`
    // (`N_SECT` or `N_ABS`); an undefined external has
    // `n_type == N_UNDF | N_EXT = 0x01`.
    const INDIRECT_SYMBOL_LOCAL: u32 = 0x80000000;
    // For defined-but-stripped symbols in future: `LOCAL | ABS` =
    // 0xC0000000. Not emitted here because we don't strip; rustc's
    // post-link strip handles that transform itself once we give it
    // entries it's allowed to touch.
    // Build the (name → (nlist_index, n_type)) map from the three
    // category Vecs in DYSYMTAB order. Index = stabs_count +
    // category_offset + within_category_position.
    let stabs_count = stab_entries.len();
    let locals_off = stabs_count;
    let extdef_off = locals_off + locals_entries.len();
    let undef_off = extdef_off + extdef_entries.len();
    let nlist_by_name: std::collections::HashMap<&[u8], (u32, u8)> = locals_entries
        .iter()
        .enumerate()
        .map(|(i, (name, _, n_type))| (name.as_slice(), ((locals_off + i) as u32, *n_type)))
        .chain(
            extdef_entries
                .iter()
                .enumerate()
                .map(|(i, (name, _, n_type))| {
                    (name.as_slice(), ((extdef_off + i) as u32, *n_type))
                }),
        )
        .chain(
            undef_entries
                .iter()
                .enumerate()
                .map(|(i, (name, _, n_type))| (name.as_slice(), ((undef_off + i) as u32, *n_type))),
        )
        .collect();

    let lookup_indirect = |name: &[u8]| -> u32 {
        match nlist_by_name.get(name) {
            Some(&(idx, n_type)) => {
                // N_UNDF | N_EXT == 0x01 with no N_SECT/N_ABS bits (0x0e).
                let is_defined = (n_type & 0x0e) != 0;
                if is_defined {
                    idx | INDIRECT_SYMBOL_LOCAL
                } else {
                    idx
                }
            }
            None => 0,
        }
    };

    let mut indirect_syms: Vec<u32> = Vec::with_capacity(stub_symbols.len() + got_symbols.len());
    let stubs_indirect_start = indirect_syms.len() as u32;
    for (_, name) in &stub_symbols {
        indirect_syms.push(lookup_indirect(name));
    }
    let got_indirect_start = indirect_syms.len() as u32;
    for (_, name) in &got_symbols {
        indirect_syms.push(lookup_indirect(name));
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

    // Write string table. Under `-ld64_compat`, pad the length to an
    // 8-byte boundary so the following codesign blob (or the end of
    // __LINKEDIT content) lands on an aligned offset — matches ld64's
    // emission exactly.
    let stroff = pos;
    let padded = (strtab.len() + 7) & !7;
    strtab.resize(padded, 0);
    if stroff + strtab.len() <= out.len() {
        out[stroff..stroff + strtab.len()].copy_from_slice(&strtab);
    }
    pos = stroff + strtab.len();

    // DYSYMTAB symbol ranges fall straight out of the three category
    // Vec lengths — no re-classifying needed (we partitioned above).
    let n_stabs = stab_entries.len() as u32;
    let n_local = locals_entries.len() as u32;
    let n_extdef = extdef_entries.len() as u32;
    let n_undef = undef_entries.len() as u32;
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
                    out[o + 48..o + 52].copy_from_slice(&(indirectsymoff as u32).to_le_bytes());
                    out[o + 52..o + 56]
                        .copy_from_slice(&(indirect_syms.len() as u32).to_le_bytes());
                }
            }
            LC_DYLD_EXPORTS_TRIE => {
                // Point at the trie when the compat path wrote one;
                // otherwise degenerate to an empty placeholder pointing
                // at the start of linkedit content.
                let (off_val, size_val) = if exports_trie_size > 0 {
                    (exports_trie_off as u32, exports_trie_size as u32)
                } else {
                    (start as u32, 0u32)
                };
                out[off as usize + 8..off as usize + 12].copy_from_slice(&off_val.to_le_bytes());
                out[off as usize + 12..off as usize + 16].copy_from_slice(&size_val.to_le_bytes());
            }
            LC_FUNCTION_STARTS => {
                // Point at the ULEB128 payload when the compat path emitted
                // one (datasize > 0); otherwise degenerate to a zero-size
                // placeholder pointing at the symtab, which ld64-style
                // tooling treats as "no function starts available".
                let (off_val, size_val) = if func_starts_size > 0 {
                    (func_starts_off as u32, func_starts_size as u32)
                } else {
                    (symoff as u32, 0u32)
                };
                out[off as usize + 8..off as usize + 12].copy_from_slice(&off_val.to_le_bytes());
                out[off as usize + 12..off as usize + 16].copy_from_slice(&size_val.to_le_bytes());
            }
            LC_DATA_IN_CODE => {
                // data_in_code stays empty; align to symtab start.
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

/// Build a Mach-O export trie as a prefix-compressed radix tree.
///
/// Matches ld64's `LinkeditClassic::ExportInfoAtom` output: every edge
/// carries the longest common prefix shared by the symbols below it, so
/// two entries like `__mh_execute_header` and `_main` collapse into a
/// single `_` root edge branching to `_mh_execute_header` and `main`.
/// Wild's original flat-tree emission worked for dyld but produced a
/// different byte layout than ld64 and diverged under `-ld64_compat`.
///
/// **Complexity:** 𝒪(e · L̄ · log e) CPU — sort (𝒪(e log e)), radix build
/// (𝒪(e · L̄) for prefix comparisons), then 2–3 offset-fixup iterations each
/// 𝒪(e · L̄); 𝒪(e · L̄) memory for nodes and the output byte vec.
fn build_export_trie(entries: &[(Vec<u8>, u64)]) -> Vec<u8> {
    if entries.is_empty() {
        return vec![0, 0];
    }
    let (nodes, offsets) = build_export_trie_nodes(entries);
    let total: usize = nodes.iter().map(|n| node_encoded_size(n, &offsets)).sum();
    let mut out = Vec::with_capacity(total);
    for node in &nodes {
        encode_node(&mut out, node, &offsets);
    }
    out
}

/// Size-only counterpart of [`build_export_trie`]. Runs the identical
/// radix build + offset fix-point iteration and returns the byte count
/// without emitting any output bytes. Used by `precount_symtab` to size
/// `LC_DYLD_EXPORTS_TRIE` exactly at layout time, replacing the
/// `n_exports * 256` estimate.
///
/// The function's result is a correct upper bound for the trie's
/// eventual serialized size; it does NOT include the 8-byte alignment
/// padding the writer adds after the trie. Callers that need the
/// padded size should round up themselves.
///
/// **Complexity:** 𝒪(e · L̄ · log e) CPU, 𝒪(e · L̄) memory — same as
/// `build_export_trie` minus the final byte-emission loop. On a 45 MB
/// rust-analyzer exe this is the trivial 2-byte trie (only
/// `__mh_execute_header` exports); on a large dylib it walks every
/// exported symbol.
pub(crate) fn compute_export_trie_size(entries: &[(Vec<u8>, u64)]) -> u32 {
    if entries.is_empty() {
        return 2;
    }
    let (nodes, offsets) = build_export_trie_nodes(entries);
    let total: usize = nodes.iter().map(|n| node_encoded_size(n, &offsets)).sum();
    total as u32
}

/// Shared build+size-iterate phase for `build_export_trie` /
/// `compute_export_trie_size`. Returns the node pool and the stable
/// per-node offset table after the ULEB fix-point converges.
fn build_export_trie_nodes(entries: &[(Vec<u8>, u64)]) -> (Vec<Node>, Vec<usize>) {
    // Sort by name so radix nodes build deterministically and children
    // can be split by looking at the first byte of each residual name.
    let mut sorted: Vec<(Vec<u8>, u64)> = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    // One radix node per child group. Indexed by a flat `Vec` so every
    // node has a stable position to reference via offsets. Each child
    // edge stores `(label, child_index)`; labels are prefix-compressed.
    // Radix trie has at most one node per entry (typically much less).
    let mut nodes: Vec<Node> = Vec::with_capacity(entries.len());

    /// Append a radix node covering `entries[start..end]` assuming each
    /// residual name has already had `consumed` bytes stripped from the
    /// front. Returns the index of the new node in `nodes`.
    fn build(
        nodes: &mut Vec<Node>,
        entries: &[(Vec<u8>, u64)],
        start: usize,
        end: usize,
        consumed: usize,
    ) -> usize {
        let idx = nodes.len();
        nodes.push(Node {
            terminal: None,
            children: Vec::new(),
        });

        // A name whose length matches the consumed prefix IS this node
        // (no more bytes to split on). Record its terminal info and
        // advance past it.
        let mut cursor = start;
        if entries[cursor].0.len() == consumed {
            nodes[idx].terminal = Some(entries[cursor].1);
            cursor += 1;
        }

        while cursor < end {
            // Gather all entries sharing the same next byte, then find
            // the longest common prefix across that group so the edge
            // label carries as many bytes as possible.
            let first_byte = entries[cursor].0[consumed];
            let mut group_end = cursor + 1;
            while group_end < end && entries[group_end].0[consumed] == first_byte {
                group_end += 1;
            }

            let mut common = entries[cursor].0.len() - consumed;
            for e in &entries[cursor..group_end] {
                let rem = &e.0[consumed..];
                let mut k = 0usize;
                while k < common && k < rem.len() && rem[k] == entries[cursor].0[consumed + k] {
                    k += 1;
                }
                common = k;
            }

            let label = entries[cursor].0[consumed..consumed + common].to_vec();
            let child_idx = build(nodes, entries, cursor, group_end, consumed + common);
            nodes[idx].children.push((label, child_idx));

            cursor = group_end;
        }

        idx
    }
    let root = build(&mut nodes, &sorted, 0, sorted.len(), 0);
    debug_assert_eq!(root, 0);

    // Two-pass encoding: node bodies are fixed-shape but child offsets
    // are ULEB-encoded, so their byte length depends on the offsets
    // themselves. Iterate until offsets are stable (usually 2 passes).
    let mut offsets = vec![0usize; nodes.len()];
    loop {
        let mut cursor = 0usize;
        let mut changed = false;
        for i in 0..nodes.len() {
            if offsets[i] != cursor {
                offsets[i] = cursor;
                changed = true;
            }
            cursor += node_encoded_size(&nodes[i], &offsets);
        }
        if !changed {
            break;
        }
    }

    (nodes, offsets)
}

/// Fixed-layout size of a single trie node given child offsets.
///
/// **Complexity:** 𝒪(c) CPU where c = number of children; 𝒪(c · L̄) memory for
/// temporary ULEB scratch vecs.
fn node_encoded_size(node: &Node, offsets: &[usize]) -> usize {
    // Compute ULEB128 byte counts arithmetically — no scratch-buffer
    // allocations. Called many times per `build_export_trie` fix-point
    // iteration, and the old version paid 2 + 1-per-child heap
    // allocations just to measure lengths.
    fn uleb128_len(mut v: u64) -> usize {
        let mut n = 1;
        v >>= 7;
        while v != 0 {
            n += 1;
            v >>= 7;
        }
        n
    }
    let info_len = match node.terminal {
        Some(addr) => uleb128_len(0) + uleb128_len(addr),
        None => 0,
    };
    let term_len_len = uleb128_len(info_len as u64);
    let mut size = term_len_len + info_len + 1; // + edge_count byte
    for (label, child_idx) in &node.children {
        size += label.len() + 1; // label + NUL
        size += uleb128_len(offsets[*child_idx] as u64);
    }
    size
}

/// Append the ULEB128-encoded body of a trie node to `out`.
///
/// **Complexity:** 𝒪(c · L̄) CPU and appended bytes where c = child count and
/// L̄ = average edge-label length.
fn encode_node(out: &mut Vec<u8>, node: &Node, offsets: &[usize]) {
    let mut info = Vec::new();
    if let Some(addr) = node.terminal {
        uleb128_encode(&mut info, 0);
        uleb128_encode(&mut info, addr);
    }
    uleb128_encode(out, info.len() as u64);
    out.extend_from_slice(&info);
    out.push(node.children.len() as u8);
    for (label, child_idx) in &node.children {
        out.extend_from_slice(label);
        out.push(0);
        uleb128_encode(out, offsets[*child_idx] as u64);
    }
}

struct Node {
    terminal: Option<u64>,
    children: Vec<(Vec<u8>, usize)>,
}

/// Append the ULEB128 encoding of `val` to `buf`.
///
/// **Complexity:** 𝒪(log val) CPU; 𝒪(log val) bytes appended.
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
///
/// For each symbol resolution that has both a `plt_address` and `got_address`,
/// emits a 12-byte PLT stub (ADRP + LDR + BR) and either a bind fixup (dylib
/// symbol) or a rebase fixup (intra-image defined symbol).
///
/// **Complexity:** Θ(n) CPU — single pass over `symbol_resolutions`; 𝒪(i) memory
/// for the new `ImportEntry` and fixup records appended to the caller's vecs.
fn write_stubs_and_got<A: Arch<Platform = MachO>>(
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
            // If the symbol is defined internally (raw_value != 0), write a
            // rebase fixup instead of a bind fixup. A bind fixup for a defined
            // symbol causes dyld to look for it in dylibs, crashing at launch.
            // Exception: under -flat_namespace, defined-in-image symbols must
            // remain as BIND entries with FLAT_LOOKUP so they can be
            // interposed by dylibs loaded earlier at runtime.
            if res.raw_value != 0 && !layout.symbol_db.args.flat_namespace {
                out[got_file_off..got_file_off + 8].copy_from_slice(&res.raw_value.to_le_bytes());
                rebase_fixups.push(RebaseFixup {
                    file_offset: got_file_off,
                    target: res.raw_value,
                });
                continue;
            }
            let import_index = imports.len() as u32;
            // For ObjC stubs, bind the GOT entry to _objc_msgSend.
            let import_name = if is_objc_stub {
                b"_objc_msgSend".to_vec()
            } else {
                name.clone()
            };
            let weak = if is_objc_stub {
                false
            } else {
                layout.symbol_db.is_weak_ref(symbol_id)
            };
            imports.push(ImportEntry {
                name: import_name,
                lib_ordinal: lib_ordinal_for_symbol(
                    has_extra_dylibs,
                    layout.symbol_db.args.flat_namespace,
                ),
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
///
/// **Complexity:** 𝒪(1) CPU and memory — emits exactly 8 ARM64 instructions.
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
///
/// For symbols with a `got_address` but no `plt_address`, writes the resolved
/// value directly into the GOT slot and records a rebase fixup; falls back to
/// an 𝒪(1) `ResolutionByNameCache` lookup for broken definition chains, then
/// to a bind fixup for unresolved dylib symbols.
///
/// **Complexity:** Θ(n) CPU — single pass over `symbol_resolutions`; each
/// name-cache lookup is 𝒪(1) expected; 𝒪(i) memory for new fixup records.
fn write_got_entries(
    out: &mut [u8],
    layout: &Layout<'_, MachO>,
    mappings: &[SegmentMapping],
    rebase_fixups: &mut Vec<RebaseFixup>,
    bind_fixups: &mut Vec<BindFixup>,
    imports: &mut Vec<ImportEntry>,
    has_extra_dylibs: bool,
    name_cache: &ResolutionByNameCache,
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
                    // But first check if the symbol is actually defined elsewhere
                    // in this binary (broken definition chain).
                    let symbol_id = SymbolId::from_usize(sym_idx);
                    if let Some(addr) = name_cache.lookup(symbol_id, layout) {
                        out[file_off..file_off + 8].copy_from_slice(&addr.to_le_bytes());
                        rebase_fixups.push(RebaseFixup {
                            file_offset: file_off,
                            target: addr,
                        });
                        continue;
                    }
                    let name = match layout.symbol_db.symbol_name(symbol_id) {
                        Ok(n) => n.bytes().to_vec(),
                        Err(_) => continue,
                    };
                    let import_index = imports.len() as u32;
                    imports.push(ImportEntry {
                        name,
                        lib_ordinal: lib_ordinal_for_symbol(
                            has_extra_dylibs,
                            layout.symbol_db.args.flat_namespace,
                        ),
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

/// When a symbol's merged resolution has `raw_value == 0` (broken definition
/// chain), search all resolutions for a symbol with the same name that has a
/// non-zero address. This handles the case where archive members define
/// symbols but the definition chain wasn't properly connected (e.g., sym-0
/// points to itself instead of the actual definition).
/// Name → resolved address cache, built once per link from every
/// non-zero `symbol_resolutions` entry. Used by the hot apply-reloc
/// path as an O(1) replacement for the old linear `find_resolution_by_name`
/// scan (which on rust-analyzer was dominating at ~50 μs/reloc because
/// the loop walked ~5 M symbols per fallback).
pub(crate) struct ResolutionByNameCache {
    map: hashbrown::HashMap<Vec<u8>, u64, foldhash::fast::FixedState>,
}

impl ResolutionByNameCache {
    /// Build the name→address cache from every non-zero `symbol_resolutions` entry.
    ///
    /// Uses a rayon `par_chunks` fold-reduce: each worker produces a partial
    /// `HashMap` over its chunk, then the reduce merges partials by inserting
    /// into the larger map (swap-and-drain to minimise allocations).
    ///
    /// Hash: `foldhash::fast::FixedState` — the same non-DoS-resistant-but-
    /// SIMD-friendly hasher that wild uses elsewhere. For a cache built
    /// once per link from trusted input content (not user-controlled
    /// network data), collision-resistance isn't worth the ~2-3× speed
    /// hit of SipHash. Measured on rust-analyzer: build dropped from
    /// ~22 ms to ~10 ms.
    ///
    /// **Complexity:** Θ(n) CPU sequentially, 𝒪(n/T) wall-clock via rayon
    /// fold-reduce; Θ(u · L̄) memory where u ≤ n is the number of non-zero
    /// uniquely-named resolutions and L̄ is average name length.
    pub(crate) fn build(layout: &Layout<'_, MachO>) -> Self {
        use rayon::prelude::*;
        type FastMap = hashbrown::HashMap<Vec<u8>, u64, foldhash::fast::FixedState>;
        const CHUNK: usize = 16 * 1024;
        let resolutions = layout.symbol_resolutions.as_slice();
        // Parallel fold: each worker builds a partial HashMap over its
        // chunk of symbol indices; reduce merges them. We take the first
        // non-zero entry per name across the whole link — partials never
        // disagree on a present key (archive-chain aliases resolve to the
        // same address), so `or_insert` on merge preserves the invariant.
        let map = resolutions
            .par_chunks(CHUNK)
            .enumerate()
            .fold(
                || {
                    FastMap::with_capacity_and_hasher(
                        CHUNK / 4,
                        foldhash::fast::FixedState::default(),
                    )
                },
                |mut map, (chunk_idx, chunk)| {
                    let base = chunk_idx * CHUNK;
                    for (offset, slot) in chunk.iter().enumerate() {
                        let Some(res) = slot else { continue };
                        if res.raw_value == 0 {
                            continue;
                        }
                        let idx = base + offset;
                        let sym_id = crate::symbol_db::SymbolId::from_usize(idx);
                        if let Ok(name) = layout.symbol_db.symbol_name(sym_id) {
                            let bytes = name.bytes();
                            if !bytes.is_empty() {
                                map.entry(bytes.to_vec()).or_insert(res.raw_value);
                            }
                        }
                    }
                    map
                },
            )
            .reduce(
                || FastMap::with_hasher(foldhash::fast::FixedState::default()),
                |mut a, mut b| {
                    if a.len() < b.len() {
                        std::mem::swap(&mut a, &mut b);
                    }
                    for (k, v) in b {
                        a.entry(k).or_insert(v);
                    }
                    a
                },
            );
        Self { map }
    }

    /// Look up the resolved address for `sym_id` by name.
    ///
    /// **Complexity:** 𝒪(1) expected CPU — single `HashMap::get` after a
    /// `symbol_name` lookup; 𝒪(1) extra memory.
    pub(crate) fn lookup(
        &self,
        sym_id: crate::symbol_db::SymbolId,
        layout: &Layout<'_, MachO>,
    ) -> Option<u64> {
        let name = layout.symbol_db.symbol_name(sym_id).ok()?;
        let bytes = name.bytes();
        if bytes.is_empty() {
            return None;
        }
        self.map.get(bytes).copied()
    }
}

/// Write compacted `__eh_frame` data: filter dead FDEs, fix up CIE pointers,
/// adjust pcrel addends for compaction shifts, then apply relocations.
///
/// Two passes over the input frame data: first to decide liveness and copy/adjust,
/// second to apply relocations at their compacted output positions.
///
/// **Complexity:** 𝒪(f · r_f) CPU where f = number of FDE/CIE entries in the
/// section and r_f = relocations per entry (checking liveness scans all relocs
/// for the entry); 𝒪(f) memory for the `cie_offset_map`.
/// Emit the `__eh_frame` section into `out`, filtering dead FDEs.
///
/// `out` is the section's slice (local offsets). `file_offset` is the
/// section's absolute file offset, kept so the fixup records pushed
/// by `apply_relocations` on the compacted relocs carry
/// file-absolute coordinates.
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
    name_cache: &ResolutionByNameCache,
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

    // FDE liveness filter — per-atom granularity. Keep only FDEs
    // whose pc_begin target atom was activated during layout. For
    // sections with atom tracking, consult `subsection_tracking`
    // (atom scanned ↔ alive); otherwise fall back to "section
    // loaded".
    //
    // rustc/clang emit `pc_begin` as a
    // `SUBTRACTOR(__eh_frame_anchor) + UNSIGNED(target_fn)` pair.
    // The SUBTRACTOR's symbol sits in `__eh_frame` itself, so
    // matching on it would short-circuit via the section-loaded
    // check and defeat the filter. Pin to the UNSIGNED half
    // (r_type 0) so we see the real target.
    //
    // The pcrel placeholders stored at pc_begin and LSDA fields
    // hold `-input_field_offset`; when we drop earlier FDEs the
    // field shifts in the output and the placeholder becomes
    // stale. The copy block above bumps those placeholders by
    // `(input_pos - output_pos)` for every SUBTRACTOR that names
    // a symbol in this same `__eh_frame` section, so the pcrel
    // stays correct after compaction.
    //
    // Pre-bucket relocs by `r_address` so per-FDE lookup is 𝒪(1)
    // instead of 𝒪(r_eh) — lockstep with `compact_atom_managed_sections`.
    let relocs_by_addr: std::collections::HashMap<u32, object::macho::RelocationInfo> = {
        let mut m = std::collections::HashMap::with_capacity(relocs.len());
        for reloc_raw in relocs {
            let ri = reloc_raw.info(le);
            m.insert(ri.r_address as u32, ri);
        }
        m
    };
    let is_fde_live = |input_pos: usize, _next_input: usize| -> bool {
        let pc_begin_addr = (input_pos + crate::eh_frame::FDE_PC_BEGIN_OFFSET) as u32;
        let Some(reloc) = relocs_by_addr.get(&pc_begin_addr) else {
            return false;
        };
        if !reloc.r_extern || reloc.r_type != 0 {
            return false;
        }
        let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
        let Ok(sym) = obj.object.symbols.symbol(sym_idx) else {
            return false;
        };
        let n_sect = sym.n_sect();
        if n_sect == 0 {
            return false;
        }
        let tgt_sec_idx = n_sect as usize - 1;
        if let Some(tracking) = obj.subsection_tracking.get(&tgt_sec_idx) {
            let Some(tgt_sec) = obj.object.sections.get(tgt_sec_idx) else {
                return false;
            };
            let sec_addr = tgt_sec.addr.get(le);
            let offset_in_sec = sym.n_value(le).wrapping_sub(sec_addr);
            if let Some(atom_idx) = tracking.atom_index_for_offset(offset_in_sec) {
                return tracking.scanned[atom_idx];
            }
            false
        } else {
            obj.section_resolutions
                .get(tgt_sec_idx)
                .and_then(|r| r.address())
                .is_some()
        }
    };

    const PREFIX_LEN: usize = size_of::<EhFrameEntryPrefix>();
    let mut input_pos = 0;
    let mut output_pos = 0;
    // CIEs are sparse (typically 1–4 per object); pre-size accordingly.
    let mut cie_offset_map = std::collections::HashMap::with_capacity(4);

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
            is_fde_live(input_pos, next_input)
        };

        if keep {
            // `out` is the section's slice now, so dest is local.
            let dest = output_pos;
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

                // Compaction adjustment. rustc/clang encode `pc_begin`
                // and LSDA as `SUBTRACTOR(ltmp*) + UNSIGNED(target)`
                // where `ltmp*` is a local label anchored to the
                // section base. The compiler pre-stores
                // `existing = -input_field_offset` as the implicit
                // addend so runtime pcrel reads yield `target`:
                //
                //   val = target - ltmp + existing
                //   runtime = field_VM + val = target  (when
                //     field_VM = ltmp + input_field_offset, which
                //     holds only if output_offset == input_offset)
                //
                // When we drop earlier FDEs this entry shifts left by
                // (input_pos - output_pos), so `field_VM` no longer
                // matches the addend and the runtime reads a value
                // short by that many bytes (the off-by-48 we saw on
                // rust-panic-unwind). Bump the placeholder by that
                // delta for every SUBTRACTOR whose target is this
                // same `__eh_frame` section so pass-2's
                // apply_relocations produces the correct pcrel value.
                let shift = input_pos as i64 - output_pos as i64;
                if shift != 0 {
                    for reloc_raw in relocs {
                        let r = reloc_raw.info(le);
                        let off = r.r_address as usize;
                        if off < input_pos || off >= next_input {
                            continue;
                        }
                        if r.r_type != 1 || !r.r_extern || r.r_length != 3 {
                            continue;
                        }
                        let sym_idx = object::SymbolIndex(r.r_symbolnum as usize);
                        let Ok(sym) = obj.object.symbols.symbol(sym_idx) else {
                            continue;
                        };
                        use object::read::macho::Nlist as _;
                        let n_sect = sym.n_sect();
                        if n_sect == 0 {
                            continue;
                        }
                        let sec_idx = n_sect as usize - 1;
                        let Some(sec_out) = obj
                            .section_resolutions
                            .get(sec_idx)
                            .and_then(|res| res.address())
                        else {
                            continue;
                        };
                        if sec_out != output_addr {
                            continue;
                        }
                        let out_field = dest + (off - input_pos);
                        if out_field + 8 > out.len() {
                            continue;
                        }
                        let existing =
                            i64::from_le_bytes(out[out_field..out_field + 8].try_into().unwrap());
                        let adjusted = existing.wrapping_add(shift);
                        out[out_field..out_field + 8].copy_from_slice(&adjusted.to_le_bytes());
                    }
                }
            }
            output_pos += size;
        }
        input_pos = next_input;
    }

    // Layout now sizes this section's contribution to the
    // compacted kept-bytes only (see `compact_eh_frame_sizes` in
    // macho.rs). Zero-filling past `output_pos` would stomp the
    // next object's contribution — so nothing to do here.

    // Second pass: apply relocations to the compacted data.
    // Build a mapping from input reloc offsets to output offsets.
    // For simplicity, re-scan entries and apply relocs for kept entries.
    // Pre-compute the error-descriptor string once (avoid format! inside the loop).
    let eh_desc = format!("{}(__TEXT,__eh_frame)", obj.input.file.filename.display());
    input_pos = 0;
    output_pos = 0;
    let mut cie_map2 = std::collections::HashMap::with_capacity(4);
    // Reuse a single Vec across loop iterations to avoid per-FDE heap alloc.
    // FDEs typically carry 1–3 relocs (pc_begin, LSDA, personality); 4 covers
    // the common case without ever reallocating in the hot copy loop.
    let mut adjusted: Vec<object::macho::Relocation<object::Endianness>> = Vec::with_capacity(4);

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
            is_fde_live(input_pos, next_input)
        };

        if keep {
            // Collect and adjust relocs for this entry in one pass (no intermediate Vec).
            adjusted.clear();
            adjusted.extend(relocs.iter().filter_map(|r| {
                let info = r.info(le);
                let off = info.r_address as usize;
                if off < input_pos || off >= next_input {
                    return None;
                }
                let mut copy = *r;
                let new_addr = off - input_pos + output_pos;
                copy.r_word0.set(le, new_addr as u32);
                Some(copy)
            }));

            if !adjusted.is_empty() {
                // __eh_frame isn't subsection-managed; pass None so
                // every reloc is applied as before. The `adjusted`
                // relocs already carry the output-relative
                // `r_address`, so no source-section deltas either.
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
                    None,
                    None,
                    name_cache,
                )?;
            }
            output_pos += size;
        }
        input_pos = next_input;
    }

    Ok(())
}

/// Exclusive write access to one (object, section) contribution in
/// the output buffer, pre-carved by `split_output_for_objects`.
/// Handed out by the caller so write_object_sections + callees
/// write into disjoint slices — no raw-pointer aliasing needed.
pub(crate) struct SectionOutput<'a> {
    pub(crate) sec_idx: usize,
    pub(crate) file_offset: usize,
    pub(crate) output_addr: u64,
    pub(crate) slice: &'a mut [u8],
}

/// Walk every object × every loaded section, compute each
/// contribution's output file range (from the layout), sort the
/// ranges by start offset, and split the output buffer into
/// disjoint `&mut [u8]` slices — one per contribution — using
/// `split_off_mut`. Group the result by object index so rayon can
/// hand each worker its own `Vec<SectionOutput<'_>>`.
///
/// Safe replacement for the old `AtomicPtr` + `from_raw_parts_mut`
/// alias-across-workers dance; mirrors ELF's
/// `split_output_into_sections` pattern (same `split_off_mut`
/// primitive).
///
/// **Complexity:** 𝒪(C log C) CPU where `C` = total contribution
/// count (sections × objects loaded); 𝒪(C) memory for the
/// per-object grouping.
fn split_output_for_objects<'a>(
    mut out: &'a mut [u8],
    objects: &[&ObjectLayout<'_, MachO>],
    mappings: &[SegmentMapping],
) -> Vec<Vec<SectionOutput<'a>>> {
    use object::read::macho::Section as _;
    let le = object::Endianness::Little;

    // (object_idx, sec_idx, file_offset, file_size, output_addr)
    let mut contribs: Vec<(usize, usize, usize, usize, u64)> =
        Vec::with_capacity(objects.len() * 8);
    for (obj_idx, obj) in objects.iter().enumerate() {
        for (sec_idx, _slot) in obj.sections.iter().enumerate() {
            let section_res = &obj.section_resolutions[sec_idx];
            let Some(output_addr) = section_res.address() else {
                continue;
            };
            let Some(file_offset) = vm_addr_to_file_offset(output_addr, mappings) else {
                continue;
            };
            let Some(input_section) = obj.object.sections.get(sec_idx) else {
                continue;
            };
            // Match write_object_sections' BSS / zerofill skip.
            let sec_type = input_section.flags(le) & 0xFF;
            if sec_type == 0x01 || sec_type == 0x0C || sec_type == 0x12 {
                continue;
            }
            // Output size = max of input contribution + any padding
            // layout reserved via section_relax_deltas. For sections
            // without deltas, file_size == input_size.
            let input_size = input_section.size(le) as usize;
            if input_size == 0 {
                continue;
            }
            let padded = if let Some(deltas) = obj.section_relax_deltas.get(sec_idx) {
                (input_size as i64 - deltas.total_delta()) as usize
            } else {
                input_size
            };
            contribs.push((obj_idx, sec_idx, file_offset, padded, output_addr));
        }
    }
    contribs.sort_by_key(|&(_, _, off, _, _)| off);

    let mut by_object: Vec<Vec<SectionOutput<'a>>> =
        (0..objects.len()).map(|_| Vec::new()).collect();

    let mut cursor = 0usize;
    for (obj_idx, sec_idx, file_offset, size, output_addr) in contribs {
        if file_offset < cursor {
            // Overlap — layout bug. Continue; without a slice the
            // write will be skipped and validate_output will catch
            // it downstream.
            tracing::warn!(
                "split_output_for_objects: overlap at foff={file_offset:#x} \
                 (cursor={cursor:#x}) — skipping slice for obj {obj_idx}, sec {sec_idx}"
            );
            continue;
        }
        let gap = file_offset - cursor;
        if gap > 0 {
            let _skip = out.split_off_mut(..gap).ok_or_else(|| {
                crate::error!(
                    "split_output_for_objects: buffer short, needed gap={gap} \
                     at cursor={cursor:#x}"
                )
            });
            if _skip.is_err() {
                break;
            }
        }
        let slice = match out.split_off_mut(..size) {
            Some(s) => s,
            None => {
                tracing::warn!(
                    "split_output_for_objects: buffer short, needed size={size} \
                     at cursor={:#x}",
                    file_offset
                );
                break;
            }
        };
        cursor = file_offset + size;
        by_object[obj_idx].push(SectionOutput {
            sec_idx,
            file_offset,
            output_addr,
            slice,
        });
    }

    by_object
}

/// Copy each live section from one input object into its pre-carved
/// output slices, applying relocations.
///
/// **Complexity:** 𝒪(s·(d + r_s)) CPU per object, where `s` = section count, `d` = subsection
/// delta entries per section, `r_s` = relocations in that section. Wall-clock 𝒪(…/T) when the
/// caller dispatches objects via rayon. 𝒪(s) stack; per-thread fixup vecs accumulate 𝒪(r).
fn write_object_sections(
    section_outputs: &mut [SectionOutput<'_>],
    obj: &ObjectLayout<'_, MachO>,
    layout: &Layout<'_, MachO>,
    _mappings: &[SegmentMapping],
    le: object::Endianness,
    rebase_fixups: &mut Vec<RebaseFixup>,
    bind_fixups: &mut Vec<BindFixup>,
    imports: &mut Vec<ImportEntry>,
    has_extra_dylibs: bool,
    mut write_ranges: Option<&mut Vec<(usize, usize, String)>>,
    name_cache: &ResolutionByNameCache,
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

    // Fast index: sec_idx → position in section_outputs. Most objects
    // contribute 5–20 sections; linear scan would be fine, but a
    // small Vec lookup keeps dispatch clean.
    let mut slot_by_sec: Vec<Option<usize>> = vec![None; obj.sections.len()];
    for (i, so) in section_outputs.iter().enumerate() {
        if so.sec_idx < slot_by_sec.len() {
            slot_by_sec[so.sec_idx] = Some(i);
        }
    }

    for sec_idx in 0..obj.sections.len() {
        let Some(slot_idx) = slot_by_sec[sec_idx] else {
            continue;
        };
        // Pull the slice out of section_outputs once per iteration
        // by index. The slot is consumed exactly once (sec_idx
        // dispatch below guarantees no re-entry).
        let (slice, file_offset, output_addr) = {
            let so = &mut section_outputs[slot_idx];
            // We need to take the &mut [u8] ownership without moving
            // the whole struct. Use std::mem::take which leaves a
            // dangling empty slice behind — safe, and we won't read
            // this slot again for the current object.
            let slice = std::mem::take(&mut so.slice);
            (slice, so.file_offset, so.output_addr)
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
                slice,
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
                name_cache,
            )?;
            continue;
        }

        // Under `.subsections_via_symbols`, the copy path for this
        // section is driven by `section_relax_deltas`: negative
        // `bytes_delta` entries insert alignment padding between
        // atom boundaries, positive entries delete dormant atom
        // bytes (see `compact_atom_managed_sections`). Any delta
        // at all → route through the subsection-aware copier.
        if let Some(deltas) = obj.section_relax_deltas.get(sec_idx)
            && !deltas.is_empty()
        {
            copy_section_with_subsection_padding(slice, input_data, deltas)?;
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
                    slice,
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
                    obj.subsection_tracking.get(&sec_idx),
                    obj.section_relax_deltas.get(sec_idx),
                    name_cache,
                )?;
            }
            continue;
        }

        if input_size <= slice.len() {
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
                // With pre-split disjoint slices the old "detect
                // stale data at this file offset" invariant is
                // trivially true — no other writer can reach this
                // range. Keep the `write_ranges` push for the
                // caller's post-write no-overlap audit.
            }
            slice[..input_size].copy_from_slice(input_data);

            // Per-atom GC cleanup: zero out ranges owned by dormant
            // atoms. Writes are local to the section slice now.
            if let Some(tracking) = obj.subsection_tracking.get(&sec_idx) {
                for (idx, atom) in tracking.atoms.iter().enumerate() {
                    if tracking.scanned[idx] {
                        continue;
                    }
                    let lo = atom.input_start as usize;
                    let hi = atom.input_end as usize;
                    if hi > slice.len() || lo > hi {
                        continue;
                    }
                    slice[lo..hi].fill(0);
                }
            }
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
                slice,
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
                obj.subsection_tracking.get(&sec_idx),
                obj.section_relax_deltas.get(sec_idx),
                name_cache,
            )?;
        }
    }
    Ok(())
}

/// Copy a section's raw bytes into the output, respecting
/// `.subsections_via_symbols` insertion deltas: between each pair of
/// subsection boundaries, copy the source slice unchanged; at each
/// delta anchor, emit `-bytes_delta` zero bytes of alignment padding
/// before continuing. The output range is
/// `out[file_offset..file_offset + input_data.len() + total_padding]`;
/// callers must ensure the range is allocated (the layout widens
/// `section.size` when subsection deltas are recorded).
///
/// **Complexity:** 𝒪(a) CPU, where `a` = number of subsection delta anchors (proportional
/// to input section size); 𝒪(1) extra memory — copies in-place into `out`.
/// Copy `input_data` into the output section slice `out`, inserting
/// alignment padding (`bytes_delta < 0`) or skipping deleted bytes
/// (`bytes_delta > 0`) as described by `deltas`. `out` is already
/// positioned at the section's start — writes are local offsets.
fn copy_section_with_subsection_padding(
    out: &mut [u8],
    input_data: &[u8],
    deltas: &linker_utils::relaxation::SectionDeltas,
) -> Result {
    let mut input_pos: usize = 0;
    let mut output_pos: usize = 0;

    for delta in deltas.deltas() {
        // Deletion entries (positive delta) don't occur on the
        // Mach-O subsection path today, but if the same map ever
        // carries mixed deltas we forward the ELF semantics.
        let anchor = delta.input_offset as usize;
        if anchor > input_pos {
            let copy_len = anchor - input_pos;
            let dest_end = output_pos + copy_len;
            if dest_end > out.len() {
                crate::bail!(
                    "subsection copy: output overflow at foff={output_pos:#x} \
                     copy_len={copy_len}"
                );
            }
            let src_end = input_pos + copy_len;
            if src_end > input_data.len() {
                crate::bail!(
                    "subsection copy: input overflow at ipos={input_pos:#x} \
                     copy_len={copy_len} input_len={}",
                    input_data.len()
                );
            }
            out[output_pos..dest_end].copy_from_slice(&input_data[input_pos..src_end]);
            input_pos = src_end;
            output_pos = dest_end;
        }

        if delta.bytes_delta > 0 {
            // Deletion — skip this many input bytes.
            input_pos += delta.bytes_delta as usize;
        } else {
            // Insertion — leave the next `|bytes_delta|` output bytes
            // as zero (they're the alignment pad). `out` is
            // zero-initialised by the writer, but be explicit so a
            // repeat-fill of the same region stays clean.
            let pad = (-delta.bytes_delta) as usize;
            let dest_end = output_pos + pad;
            if dest_end > out.len() {
                crate::bail!("subsection copy: padding overflow at foff={output_pos:#x} pad={pad}");
            }
            out[output_pos..dest_end].fill(0);
            output_pos = dest_end;
        }
    }

    // Copy the remainder after the last delta.
    let remaining = input_data.len() - input_pos;
    if remaining > 0 {
        let dest_end = output_pos + remaining;
        if dest_end > out.len() {
            crate::bail!("subsection copy: tail overflow at foff={output_pos:#x} len={remaining}");
        }
        out[output_pos..dest_end].copy_from_slice(&input_data[input_pos..]);
    }
    Ok(())
}

/// Resolve the output VM of a section-local symbol, transforming
/// the input-section offset through any relaxation deltas (e.g.
/// atom-compaction deletions in `__const` or `__text`) attached
/// to the target section. Without this transformation, references
/// to `ltmp*` / `L*.*` labels and other compiler-generated locals
/// would point at their input positions after live atoms shifted
/// — same bug class as the `__eh_frame` `ltmp8` off-by-drop that
/// we fixed at write time for pcrel placeholders.
///
/// **Complexity:** 𝒪(a) CPU (binary search through relax-delta table for the section);
/// 𝒪(1) memory.
fn section_local_vm(
    obj: &ObjectLayout<'_, MachO>,
    sec_idx: usize,
    sec_out: u64,
    input_offset_in_section: u64,
) -> u64 {
    let out_off = match obj.section_relax_deltas.get(sec_idx) {
        Some(d) if !d.is_empty() => d.input_to_output_offset(input_offset_in_section),
        _ => input_offset_in_section,
    };
    sec_out + out_off
}

/// Returns true iff the Mach-O input object carries a `__DWARF`
/// segment (i.e. compiled with `-g`). Used to gate N_OSO stab
/// synthesis so we only point dsymutil at objects that actually have
/// DWARF to extract. Matches ld64's behaviour (`hasDebugInfo` check
/// before stabs pass).
///
/// **Complexity:** 𝒪(L·s_obj) CPU (walks all load commands and sections of one object);
/// 𝒪(1) memory.
fn object_has_debug_info(obj: &ObjectLayout<'_, MachO>) -> bool {
    use object::read::macho::MachHeader as _;
    use object::read::macho::Section as _;
    use object::read::macho::Segment as _;
    let le = object::Endianness::Little;
    let data = obj.object.data;
    let Ok(header) = object::macho::MachHeader64::<object::Endianness>::parse(data, 0) else {
        return false;
    };
    let Ok(mut cmds) = header.load_commands(le, data, 0) else {
        return false;
    };
    // In MH_OBJECT (.o) files there is a single anonymous LC_SEGMENT_64
    // with segname zeros; the DWARF identification lives on per-section
    // segname fields ("__DWARF"). Walk sections rather than the
    // top-level segment so compiler-of-object output is detected.
    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((seg, seg_data))) = cmd.segment_64() {
            let Ok(sections) = seg.sections(le, seg_data) else {
                continue;
            };
            for sec in sections {
                let segname = &sec.segname;
                let end = segname
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(segname.len());
                if &segname[..end] == b"__DWARF" {
                    return true;
                }
            }
        }
    }
    false
}

/// TLV template offset for a variable at VM address `target_addr`.
///
/// dyld stores this value in the third word of each TLV thunk
/// (`struct TLV_Thunkv2.offset`, libdyld/ThreadLocalVariables.cpp). At
/// first access, dyld allocates a per-thread buffer of
/// `initialContentSize` bytes — the VA range from the first
/// `S_THREAD_LOCAL_*` section to the last, inclusive — `memcpy`s the
/// template in, and returns `buffer + thunk.offset` for every
/// `thread_local` access. The offset is therefore
/// `var.finalAddress - first_tls_section.finalAddress`, which in wild's
/// layout is `__thread_data`'s `mem_offset`.
///
/// ld64's equivalent is `OutputFile::tlvTemplateOffsetOf`
/// (ld64/src/ld/OutputFile.cpp:520). Correctness further relies on
/// `__thread_data` and `__thread_bss` sharing the same alignment —
/// enforced at layout time by `adjust_alignments_after_sizing`
/// (rdar://24221680).
///
/// **Complexity:** Θ(1) CPU and memory.
fn tlv_template_offset(target_addr: u64, layout: &Layout<'_, MachO>) -> u64 {
    let tdata = layout.section_layouts.get(output_section_id::TDATA);
    target_addr - tdata.mem_offset
}

/// Apply relocations for a section.
///
/// **Complexity:** 𝒪(r) CPU sequentially; wall-clock 𝒪(r/T) since the caller dispatches
/// via rayon par_iter over objects. 𝒪(r) extra memory (per-thread rebase/bind/imports
/// accumulators).
/// Apply relocations to a single section's bytes.
///
/// `out` holds *only* this section's slice of the output file; writes
/// are local (`out[r.r_address..]`). `section_file_offset` is the
/// section's absolute offset within the file, kept so the fixup
/// records we push (`rebase_fixups`, `bind_fixups`) carry
/// file-absolute coordinates as dyld's chained-fixups format requires.
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
    active_atoms: Option<&crate::layout::SubsectionTracking>,
    source_deltas: Option<&linker_utils::relaxation::SectionDeltas>,
    name_cache: &ResolutionByNameCache,
) -> Result {
    let mut pending_addend: i64 = 0;
    let mut pending_subtrahend: Option<u64> = None;

    // `r_address` is input-section coordinate. When the source
    // section got compacted (dormant atoms deleted via `section_
    // relax_deltas`), the field we want to patch sits at a
    // different output offset. Map through the deltas once per
    // reloc before using `r_address` to compute `patch_file_offset`
    // or `pc_addr`.
    let map_r_address = |r: u32| -> u32 {
        match source_deltas {
            Some(d) if !d.is_empty() => d.input_to_output_offset(r as u64) as u32,
            _ => r,
        }
    };

    // Per-atom GC: for `MH_SUBSECTIONS_VIA_SYMBOLS` sections, only
    // apply relocations whose source lies in an *activated* atom.
    // Precompute a per-reloc `skip` mask instead of calling
    // `atom_index_for_offset` (a binary search) inside the reloc
    // loop — that turns O(M log A) into a single O(M) pass plus
    // O(1) per reloc, reusing the `reloc_buckets` built during GC
    // so the work amortises to zero when the bucket already exists.
    let reloc_skip: Option<Vec<bool>> = active_atoms.map(|tracking| {
        let buckets = tracking.reloc_buckets.get_or_init(|| {
            let mut b: Vec<Vec<u32>> = vec![Vec::new(); tracking.atoms.len()];
            for (idx, r) in relocs.iter().enumerate() {
                let r_addr = r.info(le).r_address as u64;
                if let Some(atom_idx) = tracking.atom_index_for_offset(r_addr) {
                    b[atom_idx].push(idx as u32);
                }
            }
            b
        });
        let mut skip = vec![true; relocs.len()];
        for (atom_idx, bucket) in buckets.iter().enumerate() {
            if tracking.scanned[atom_idx] {
                for &i in bucket {
                    skip[i as usize] = false;
                }
            }
        }
        skip
    });

    for (reloc_idx, reloc_raw) in relocs.iter().enumerate() {
        let reloc = reloc_raw.info(le);

        if let Some(skip) = reloc_skip.as_ref() {
            if skip[reloc_idx] {
                // Out-of-atom (gap) or inactive atom — skip, but
                // reset pending-reloc state so we don't carry an
                // addend/subtractor from the previous reloc across
                // a dead atom.
                pending_addend = 0;
                pending_subtrahend = None;
                continue;
            }
        }

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
                                    section_local_vm(
                                        obj,
                                        sec_idx,
                                        sec_out,
                                        sym.n_value(le).wrapping_sub(sec_in),
                                    )
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

        let out_r_addr = map_r_address(reloc.r_address);
        // `patch_file_offset` is now SECTION-LOCAL (was absolute).
        // Fixup records still need the absolute offset — built as
        // `section_file_offset + patch_file_offset` at the 2 sites
        // that emit rebase/bind records. Every other use is an index
        // into the section slice `out`, so local is what we want.
        let patch_file_offset = out_r_addr as usize;
        let pc_addr = section_vm_addr + out_r_addr as u64;
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
                    // Before falling back, check if there's another resolution
                    // for the same name with a non-zero address. This handles
                    // the case where the definition chain is broken (e.g., the
                    // symbol is defined in an archive member but the chain
                    // resolves to sym-0).
                    if let Some(addr) = name_cache.lookup(sym_id, layout) {
                        (addr, None, None)
                    } else {
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
                                let result = section_local_vm(
                                    obj,
                                    sec_idx,
                                    sec_out,
                                    sym.n_value(le).wrapping_sub(sec_in),
                                );
                                let name =
                                    sym.name(le, obj.object.symbols.strings()).unwrap_or(b"");
                                // For TLS init symbols ($tlv$init), the TLV descriptor
                                // `offset` field holds `var.addr - tdata.addr` — see
                                // `tlv_template_offset` for the ld64/dyld derivation.
                                if name.ends_with(b"$tlv$init") {
                                    return Some(tlv_template_offset(result, layout));
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
                            let sec_in =
                                obj.object.sections.get(sec_idx).map(|s| s.addr.get(le))?;
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
                    } // close find_resolution_by_name else block
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
                            lib_ordinal: lib_ordinal_for_symbol(
                                has_extra_dylibs,
                                layout.symbol_db.args.flat_namespace,
                            ),
                            weak_import: false,
                        });
                        bind_fixups.push(BindFixup {
                            file_offset: section_file_offset + patch_file_offset,
                            import_index,
                            addend: bind_addend,
                        });
                    } else {
                        // If the target lives inside TLS data, the patched slot
                        // is a TLV-descriptor `offset` field — write a template
                        // offset (`var.addr - tdata.addr`) rather than an
                        // absolute address or rebase fixup.
                        let tdata = layout.section_layouts.get(output_section_id::TDATA);
                        let tbss = layout.section_layouts.get(output_section_id::TBSS);
                        let in_tdata = tdata.mem_size > 0
                            && target_addr >= tdata.mem_offset
                            && target_addr < tdata.mem_offset + tdata.mem_size;
                        let in_tbss = tbss.mem_size > 0
                            && target_addr >= tbss.mem_offset
                            && target_addr < tbss.mem_offset + tbss.mem_size;
                        if in_tdata || in_tbss {
                            let tls_offset = tlv_template_offset(target_addr, layout);
                            out[patch_file_offset..patch_file_offset + 8]
                                .copy_from_slice(&tls_offset.to_le_bytes());
                        } else {
                            if patch_file_offset % 8 != 0 {
                                // Skip metadata sections (e.g. __llvm_addrsig)
                                // that aren't part of the runtime data layout.
                                if !section_desc.contains("__llvm") {
                                    crate::bail!("{section_desc}: unaligned base relocation");
                                }
                                continue;
                            }
                            rebase_fixups.push(RebaseFixup {
                                file_offset: section_file_offset + patch_file_offset,
                                target: target_addr,
                            });
                        }
                    }
                }
            }
            7 if reloc.r_length == 2 && reloc.r_pcrel => {
                // ARM64_RELOC_POINTER_TO_GOT — the 4-byte field holds
                // `(GOT slot VA) - field_vm`. If the referenced symbol
                // never had a GOT slot allocated we MUST NOT silently
                // fall back to `(target VA) - field_vm` — that writes
                // a raw text offset into a slot the reader will later
                // interpret as a GOT VA, which corrupts
                // `__unwind_info` personality indices (see
                // scan_eh_frame_fde_offsets). Earlier passes
                // (`load_object_section_relocations` for `__eh_frame`
                // and `__compact_unwind`) are responsible for setting
                // `ValueFlags::GOT` + issuing a symbol request.
                let Some(got) = got_addr else {
                    let sym_name = if reloc.r_extern {
                        let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
                        let sym_id = obj.symbol_id_range.input_to_id(sym_idx);
                        layout
                            .symbol_db
                            .symbol_name(sym_id)
                            .map(|n| String::from_utf8_lossy(n.bytes()).into_owned())
                            .unwrap_or_else(|_| format!("#{}", sym_idx.0))
                    } else {
                        format!("non-extern sym#{}", reloc.r_symbolnum)
                    };
                    crate::bail!(
                        "{section_desc}: ARM64_RELOC_POINTER_TO_GOT at \
                         r_address={:#x} references `{sym_name}` but no \
                         GOT slot was allocated. The reloc-scan pass for \
                         this section must `fetch_or(ValueFlags::GOT)` + \
                         `send_symbol_request` before layout.",
                        reloc.r_address
                    );
                };
                let delta = (got as i64 - pc_addr as i64) as i32;
                if patch_file_offset + 4 <= out.len() {
                    out[patch_file_offset..patch_file_offset + 4]
                        .copy_from_slice(&delta.to_le_bytes());
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Write full chained fixups header with imports and symbol names.
///
/// **Complexity:** 𝒪(i + p) CPU to encode fixup chains, where `i` = import count and
/// `p` = page count; 𝒪(i) memory for the import pool.
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
    data_splits_const_writable: bool,
    // How many pages `__DATA_CONST` occupies when the DATA region
    // splits. Ignored when `data_splits_const_writable == false`. Must
    // agree with the segment emission in `write_headers` or dyld aborts
    // at load with "section `__got` end address is beyond containing
    // segment's end".
    compat_const_pages: u16,
) -> Result {
    let has_data = mappings.len() > 1 && (mappings[1].vm_end > mappings[1].vm_start);
    let base_segs = if is_dylib { 2u32 } else { 3u32 };
    // Mirror the seg_count logic in `write_macho` — when the DATA
    // region will be split into __DATA_CONST + __DATA, we emit one
    // extra LC_SEGMENT_64 and the chained-fixups header needs to
    // count it.
    let splits_data = has_data && data_splits_const_writable;
    let seg_count = if has_data {
        base_segs + 1 + if splits_data { 1 } else { 0 }
    } else {
        base_segs
    };
    // Chained fixups describe one `starts_in_segment` entry per
    // fixup-carrying segment. Under `-ld64_compat` with the DATA
    // split, both `__DATA_CONST` (GOT) and `__DATA` (static function
    // pointers, vtables, TLV descriptors) can carry chain starts —
    // Rust binaries need the latter or dyld leaves the chain
    // unresolved and the first indirect call jumps through a raw
    // chained-pointer encoding (the "PC=0x804" crash on `rust-hello`
    // before this fix).
    //
    // In the non-split case, wild emits a single entry under slot 1
    // (dylib) or slot 2 (exe) covering the merged DATA mapping; this
    // matches ld64's layout and keeps bit-for-bit compat with all
    // tiny fixtures.
    let starts_offset: u32 = 32;

    let image_base = if mappings
        .first()
        .map_or(false, |m| m.vm_start >= PAGEZERO_SIZE)
    {
        PAGEZERO_SIZE
    } else {
        0
    };

    // Describe each segment that needs chain starts: (slot_index,
    // file_offset, vm_offset, page_count, page_starts).
    struct SegStarts {
        slot: usize,
        file_off: u64,
        vm_off: u64,
        page_count: u16,
        page_starts: Vec<u16>,
    }
    let mut seg_entries: Vec<SegStarts> = Vec::with_capacity(4);

    if has_data {
        let base_slot = if is_dylib { 1usize } else { 2usize };
        let data_map = &mappings[1];
        if splits_data {
            // Slot[base]       → __DATA_CONST (const_pages pages)
            // Slot[base+1]     → __DATA        (remaining pages)
            //
            // `compat_const_pages` comes from the caller and matches
            // the segment emission in `write_headers`. Big Rust
            // binaries (e.g. subxt+sqlx linked into one exe) push
            // __got past a single 16 KB page, so __DATA_CONST can
            // span multiple pages.
            let const_pages = compat_const_pages.max(1);
            // Ceiling division: partial pages still count as a page that
            // dyld must scan. Previously floored, which silently dropped
            // the second entry when __data spilled just past the page
            // boundary (e.g. 16640 bytes → 1 floor-page, 0 data pages),
            // producing a zero-page entry that dyld rejects as
            // "malformed import table".
            let total_pages =
                ((data_map.vm_end - data_map.vm_start + PAGE_SIZE - 1) / PAGE_SIZE) as u16;
            let data_pages = total_pages.saturating_sub(const_pages);
            let const_bytes = const_pages as u64 * PAGE_SIZE;
            seg_entries.push(SegStarts {
                slot: base_slot,
                file_off: data_map.file_offset,
                vm_off: data_map.vm_start - image_base,
                page_count: const_pages,
                page_starts: vec![0xFFFFu16; const_pages as usize],
            });
            if data_pages > 0 {
                seg_entries.push(SegStarts {
                    slot: base_slot + 1,
                    file_off: data_map.file_offset + const_bytes,
                    vm_off: (data_map.vm_start + const_bytes) - image_base,
                    page_count: data_pages,
                    page_starts: vec![0xFFFFu16; data_pages as usize],
                });
            }
        } else {
            let pages =
                (((data_map.vm_end - data_map.vm_start) + PAGE_SIZE - 1) / PAGE_SIZE) as u16;
            seg_entries.push(SegStarts {
                slot: base_slot,
                file_off: data_map.file_offset,
                vm_off: data_map.vm_start - image_base,
                page_count: pages,
                page_starts: vec![0xFFFFu16; pages as usize],
            });
        }
    }

    // Partition `all_fixups` across the entries by file offset so each
    // segment's page_starts captures the first fixup within its range.
    for &(file_off, _) in all_fixups {
        let file_off = file_off as u64;
        let Some(entry) = seg_entries.iter_mut().find(|e| {
            file_off >= e.file_off && file_off < e.file_off + (e.page_count as u64) * PAGE_SIZE
        }) else {
            continue;
        };
        let offset_in_seg = file_off - entry.file_off;
        let page_idx = (offset_in_seg / PAGE_SIZE) as usize;
        let offset_in_page = (offset_in_seg % PAGE_SIZE) as u16;
        if page_idx < entry.page_starts.len() && entry.page_starts[page_idx] == 0xFFFF {
            entry.page_starts[page_idx] = offset_in_page;
        }
    }

    // ld64 pads the dyld_chained_starts_in_image table (seg_count u32
    // plus per-segment u32 offsets) up to an 8-byte boundary so the
    // following dyld_chained_starts_in_segment (u64-aligned fields)
    // starts aligned.
    let raw_starts_in_image_size = 4 + 4 * seg_count as usize;
    let starts_in_image_size = (raw_starts_in_image_size + 7) & !7;

    // Layout each `starts_in_segment` entry back-to-back after the
    // `starts_in_image` table. Record each entry's offset so the
    // image table can point at it.
    let mut cursor = starts_in_image_size as u32;
    let mut entry_offsets: Vec<u32> = Vec::with_capacity(seg_entries.len());
    let mut total_seg_starts_size = 0u32;
    for entry in &seg_entries {
        entry_offsets.push(cursor);
        let entry_size = 22 + 2 * entry.page_count as u32;
        cursor += entry_size;
        total_seg_starts_size += entry_size;
    }

    let imports_table_offset = starts_offset + starts_in_image_size as u32 + total_seg_starts_size;
    // Format 1: no addend (4 bytes). Format 2: 32-bit addend (4+4=8). Format 3: 64-bit addend
    // (4+4+8=16).
    let needs_64bit_addend = import_addends.map_or(false, |a| {
        a.iter()
            .any(|v| *v > i32::MAX as i64 || *v < i32::MIN as i64)
    });
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
        let off: u32 = seg_entries
            .iter()
            .zip(&entry_offsets)
            .find_map(|(e, &o)| if e.slot == seg { Some(o) } else { None })
            .unwrap_or(0);
        w[si + 4 + seg * 4..si + 4 + seg * 4 + 4].copy_from_slice(&off.to_le_bytes());
    }

    // Emit each segment's starts_in_segment at its recorded offset.
    for (entry, &entry_off) in seg_entries.iter().zip(&entry_offsets) {
        let ss = si + entry_off as usize;
        let entry_size = 22 + 2 * entry.page_count as u32;
        w[ss..ss + 4].copy_from_slice(&entry_size.to_le_bytes());
        w[ss + 4..ss + 6].copy_from_slice(&(PAGE_SIZE as u16).to_le_bytes());
        w[ss + 6..ss + 8].copy_from_slice(&6u16.to_le_bytes());
        w[ss + 8..ss + 16].copy_from_slice(&entry.vm_off.to_le_bytes());
        w[ss + 16..ss + 20].copy_from_slice(&0u32.to_le_bytes());
        w[ss + 20..ss + 22].copy_from_slice(&entry.page_count.to_le_bytes());
        for (p, &ps) in entry.page_starts.iter().enumerate() {
            w[ss + 22 + p * 2..ss + 22 + p * 2 + 2].copy_from_slice(&ps.to_le_bytes());
        }
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
            // DYLD_CHAINED_IMPORT_ADDEND64: lib_ordinal:16(signed), weak:1, reserved:15,
            // name_offset:32
            let weak64: u64 = if import_weak.get(i).copied().unwrap_or(false) {
                1u64 << 16
            } else {
                0
            };
            // Ordinal is a signed 16-bit value in format 3 (vs 8-bit in format 1/2).
            // Special ordinals like 0xFE (-2 as i8) must be sign-extended to i16.
            let ordinal16 = (ordinal as i8 as i16 as u16) as u64;
            let import_val: u64 = ordinal16 | weak64 | ((name_off as u64 & 0xFFFF_FFFF) << 32);
            w[it + i * entry_sz..it + i * entry_sz + 8].copy_from_slice(&import_val.to_le_bytes());
            let addend = import_addends.and_then(|a| a.get(i).copied()).unwrap_or(0);
            w[it + i * entry_sz + 8..it + i * entry_sz + 16].copy_from_slice(&addend.to_le_bytes());
        } else {
            let import_val: u32 = ordinal | weak_bit | ((name_off & 0x7F_FFFF) << 9);
            w[it + i * entry_sz..it + i * entry_sz + 4].copy_from_slice(&import_val.to_le_bytes());
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
///
/// **Complexity:** 𝒪(b_str) CPU, where `b_str` = total bytes of merged string data;
/// 𝒪(1) extra memory — copies in-place into `out`.
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

/// Translate a VM address to its file offset by scanning the segment mappings.
///
/// **Complexity:** 𝒪(L) CPU (linear scan over `mappings`, one entry per segment); 𝒪(1) memory.
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
///
/// **Complexity:** 𝒪(m · (r_cu + u_obj)) CPU, where `m` = object count,
/// `r_cu` = relocations in the object's `__compact_unwind`, and
/// `u_obj` = entries per object. Building `relocs_by_addr` is 𝒪(r_cu)
/// per section; each of the 3 per-entry reloc lookups (function,
/// personality, LSDA) is then 𝒪(1) (was 𝒪(r_cu) — a 𝒪(u · r_cu)
/// quadratic). 𝒪(u + r_cu) memory for the returned `Vec` and per-
/// section HashMap.
fn collect_compact_unwind_entries(layout: &Layout<'_, MachO>) -> Vec<CollectedUnwindEntry> {
    use object::read::macho::MachHeader as _;
    use object::read::macho::Section as _;
    use object::read::macho::Segment as _;
    let le = object::Endianness::Little;
    // Upper-bound: one entry per __compact_unwind record across all
    // objects. 1024 skips the early doublings without over-committing.
    let mut entries: Vec<CollectedUnwindEntry> = Vec::with_capacity(1024);

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
                    // Pre-bucket `__compact_unwind` relocs by
                    // `r_address` so the 3 per-entry lookups (function,
                    // personality, LSDA) are 𝒪(1) each instead of a
                    // 𝒪(r_cu) linear scan — that was the 𝒪(u · r_cu)
                    // inside `collect_compact_unwind_entries`.
                    let relocs_by_addr: std::collections::HashMap<
                        u32,
                        object::macho::RelocationInfo,
                    > = {
                        let mut m = std::collections::HashMap::with_capacity(relocs.len());
                        for r in relocs {
                            let ri = r.info(le);
                            m.insert(ri.r_address as u32, ri);
                        }
                        m
                    };
                    let n = sec_size / 32;
                    for i in 0..n {
                        let base = i * 32;
                        if base + 32 > data.len() {
                            break;
                        }
                        let func_size =
                            u32::from_le_bytes(data[base + 8..base + 12].try_into().unwrap());
                        let mut encoding =
                            u32::from_le_bytes(data[base + 12..base + 16].try_into().unwrap());
                        if encoding == 0 {
                            continue; // no unwind info needed
                        }
                        // DWARF mode → handled via __eh_frame FDE scan, skip here.
                        if (encoding & 0x0F00_0000) == 0x0300_0000 {
                            continue;
                        }
                        // FRAMELESS with empty payload (stack_size = 0,
                        // no saved regs) is a valid encoding for tiny
                        // leaf functions (a single `ret`, 4-8 byte
                        // stubs), but rustc also emits it as an "I
                        // don't know how to describe this" sentinel
                        // for larger functions with real frames —
                        // e.g. edition-2015 `std::panicking::
                        // begin_panic`. Leaving it tells libunwind
                        // "leaf function, x30 is still the return
                        // address", which mis-unwinds anything that
                        // actually pushed a frame and surfaces as
                        // a "free(0x7)" abort after the bad walk
                        // corrupts callee-saves.
                        //
                        // Heuristic: any function larger than the
                        // smallest possible leaf (16 bytes covers
                        // `stp x29, x30; mov x29, sp; …; ldp; ret`)
                        // is almost certainly non-leaf, so rewrite
                        // to the FRAME encoding (`0x04000000`,
                        // fp-chain walk, no saved regs) which works
                        // for any function with a standard prologue.
                        // Functions ≤ 16 bytes keep `0x02000000`
                        // so ld64-compat bit-for-bit output stays
                        // stable on pure-C fixtures.
                        // Heuristic: for functions larger than a
                        // single instruction (>8 bytes), treat
                        // `0x02000000` as "no info" and rewrite to
                        // `0x04000000` so libunwind walks via
                        // frame-pointer chain. Sizes ≤ 8 keep the
                        // leaf encoding — those fit a single `ret`
                        // or `mov+ret` and actually don't have a
                        // frame.
                        if encoding == 0x02000000 && func_size > 8 {
                            encoding = 0x04000000;
                        }
                        let Some(func_addr) = resolve_compact_unwind_addr(
                            obj,
                            layout,
                            le,
                            &relocs_by_addr,
                            base,
                            data,
                        ) else {
                            continue;
                        };
                        // Extract personality GOT addr (offset 16) and LSDA addr (offset 24)
                        let personality_got = resolve_compact_unwind_got_addr(
                            obj,
                            layout,
                            le,
                            &relocs_by_addr,
                            base + 16,
                        );
                        let lsda_addr = resolve_compact_unwind_addr(
                            obj,
                            layout,
                            le,
                            &relocs_by_addr,
                            base + 24,
                            data,
                        )
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
///
/// **Complexity:** 𝒪(1) CPU (HashMap lookup via caller-supplied
/// `relocs_by_addr`); 𝒪(1) memory. Previously 𝒪(r_cu) linear scan.
fn resolve_compact_unwind_addr(
    obj: &ObjectLayout<'_, MachO>,
    layout: &Layout<'_, MachO>,
    le: object::Endianness,
    relocs_by_addr: &std::collections::HashMap<u32, object::macho::RelocationInfo>,
    field_offset: usize,
    sec_data: &[u8],
) -> Option<u64> {
    use object::read::macho::Nlist as _;
    // Pre-bucketed by caller: 𝒪(1) lookup instead of 𝒪(r_cu) per call.
    // `__compact_unwind` has up to 3 relocs per 32-byte entry (function,
    // personality, LSDA), so scanning all relocs per field was 𝒪(u·r_cu).
    let reloc = match relocs_by_addr.get(&(field_offset as u32)) {
        Some(r) => *r,
        None => return None,
    };
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
        return Some(section_local_vm(
            obj,
            sec_idx,
            sec_out,
            sym.n_value(le).wrapping_sub(sec_in),
        ));
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
        // Non-extern reloc: addend is an input-coord VM into
        // the target section. Map the section-local offset
        // through the relax deltas so compacted atoms land
        // on their output positions.
        return Some(section_local_vm(
            obj,
            sec_idx,
            sec_out,
            addend.wrapping_sub(sec_in),
        ));
    }
}

/// Like resolve_compact_unwind_addr, but returns the GOT address for the symbol
/// (needed for personality pointers in __unwind_info).
///
/// **Complexity:** 𝒪(1) CPU (HashMap lookup); 𝒪(1) memory.
fn resolve_compact_unwind_got_addr(
    obj: &ObjectLayout<'_, MachO>,
    layout: &Layout<'_, MachO>,
    _le: object::Endianness,
    relocs_by_addr: &std::collections::HashMap<u32, object::macho::RelocationInfo>,
    field_offset: usize,
) -> Option<u64> {
    let reloc = relocs_by_addr.get(&(field_offset as u32))?;
    if !reloc.r_extern {
        return None;
    }
    let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
    let sym_id = obj.symbol_id_range.input_to_id(sym_idx);
    let res = layout.merged_symbol_resolution(sym_id)?;
    // Only return actual GOT slot VAs. Returning the raw function VA
    // when no GOT slot was allocated leads to `got_vm - text_base`
    // overflow and garbage personality indices in `__unwind_info`.
    let got = res.format_specific.got_address?;
    // GOT slots live in __DATA_CONST, which is always above __TEXT and
    // within 2 GiB of it (far under the 4 GiB cap on unwind_info's
    // 32-bit personality offsets). A value outside that window is
    // invariably a layout bug.
    debug_assert!(
        got >= 0x1_0000_0000,
        "resolve_compact_unwind_got_addr: got={got:#x} \
         below plausible text_base (expected ≥ 0x1_0000_0000)"
    );
    Some(got)
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
///
/// **Complexity:** 𝒪(|aug|) CPU, where `|aug|` = length of the CIE augmentation string
/// (typically ≤ 4 bytes); 𝒪(1) memory.
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
                        // Debug-only invariant: the resolved
                        // personality should point into __got or
                        // __TEXT. If this fires, the CIE reloc
                        // scan in `load_object_section_relocations`
                        // missed a POINTER_TO_GOT and the
                        // personality field was written with a raw
                        // VA. We still record it; the downstream
                        // `is_plausible_got_vm` filter drops it.
                        debug_assert!(
                            target_vm >= 0x1_0000_0000
                                && (target_vm - 0x1_0000_0000) < (1u64 << 31),
                            "parse_cie_aug: CIE personality resolves to \
                             {target_vm:#x}, outside the expected __got / \
                             __TEXT window — reloc scan likely missed the \
                             CIE POINTER_TO_GOT"
                        );
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
///
/// **Complexity:** 𝒪(f) CPU, 𝒪(f) memory (returns `HashMap<u64, EhFrameFdeInfo>`).
fn scan_eh_frame_fde_offsets(
    buf: &[u8],
    eh_frame_vm_addr: u64,
    eh_frame_file_offset: usize,
    eh_frame_size: usize,
) -> std::collections::HashMap<u64, EhFrameFdeInfo> {
    use crate::eh_frame::EhFrameEntryPrefix;
    use std::mem::size_of;
    use zerocopy::FromBytes;

    // Estimate ~32 bytes per FDE for initial capacity (avoids early rehash on large binaries).
    let est_fdes = (eh_frame_size / 32).max(16);
    let mut map = std::collections::HashMap::with_capacity(est_fdes);
    // CIE map: section_offset → CieAugInfo; typically very few CIEs per image.
    let mut cie_map: std::collections::HashMap<u32, CieAugInfo> =
        std::collections::HashMap::with_capacity(4);

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
///
/// **Complexity:** 𝒪(u·log u) CPU (sort all entries by VM address) + 𝒪(u)
/// for the 2-level page encoding pass. Page builder and per-page
/// encoding-index map both use HashSet/HashMap membership so each
/// per-entry dedupe / reverse-index is 𝒪(1) (previously 𝒪(n_page·uniq_page)
/// with `Vec::contains`). 𝒪(u) memory for the merged entry vec and output buffer.
fn build_unwind_info_section(
    plain_entries: &[CollectedUnwindEntry],
    fde_map: &std::collections::HashMap<u64, EhFrameFdeInfo>,
    text_base: u64,
    max_bytes: u64,
) -> Vec<u8> {
    // ARM64 compact-unwind encoding constants.
    const UNWIND_ARM64_DWARF: u32 = 0x0300_0000;

    // Build: (func_addr, func_size, encoding) sorted by func_addr.
    let mut all_entries: Vec<(u64, u32, u32)> =
        Vec::with_capacity(fde_map.len() + plain_entries.len());

    // Collect unique personality GOT slots (in encounter order); at most 3 per Mach-O spec.
    let mut personalities: Vec<u64> = Vec::with_capacity(4);

    // A valid personality GOT slot lives in __DATA_CONST above
    // __TEXT. If the POINTER_TO_GOT reloc fell back to a raw VA
    // (because the personality symbol never had a GOT slot
    // allocated), the value read back from `__eh_frame` is either
    // below `text_base` (unrelocated high-negative delta wraps
    // through field_vm) or absurdly far above it. Screen those
    // out — the FDE still exists in `__eh_frame` so the unwinder
    // can read it, we just don't index it in `__unwind_info`.
    let is_plausible_got_vm = |v: u64| -> bool { v >= text_base && (v - text_base) < (1u64 << 31) };

    // Emit DWARF-mode entries for *every* FDE in `fde_map`, not just
    // those with a personality. Apple's libunwind consults
    // `__unwind_info` first; if the function has no entry there it
    // immediately returns `_URC_END_OF_STACK` — even if an FDE
    // exists in `__eh_frame`. Functions whose compact_unwind entry
    // said "DWARF mode" (we skip those in
    // `collect_compact_unwind_entries` expecting the FDE path to
    // cover them) and whose FDE has no personality used to slip
    // through both nets — the unwinder then failed to step through
    // them, which aborted any panic crossing such a frame in a
    // spawned thread.
    //
    // FDEs *with* a personality additionally enter the
    // `personalities` array so the encoding can reference them by
    // 1-based index.
    //
    // Emit a DWARF-mode entry for every FDE in `fde_map`. Apple's
    // libunwind uses `__unwind_info` as the primary index — without
    // an entry there it returns `_URC_END_OF_STACK` even if the
    // function has a valid FDE. Functions whose compact_unwind
    // encoding is "DWARF mode" (skipped in
    // `collect_compact_unwind_entries`) and whose FDE lacks a
    // personality used to slip through both nets; a panic crossing
    // such a frame then died with "failed to initiate panic,
    // error 5". `pers_idx = 0` means "no personality", a valid
    // encoding in ld64's output.
    //
    // LSDA: set `UNWIND_HAS_LSDA` + descriptor for DWARF entries
    // that have an LSDA. ld64 does this (e.g. `___rust_try` ships
    // as `0x530019a0`, not `0x130019a0`). Even though Apple's
    // libunwind can read LSDA from the FDE augmentation on the
    // DWARF path, matching ld64's encoding is load-bearing for
    // some personality routines that walk the LSDA descriptor
    // array directly during Phase 1 search.
    let mut dwarf_func_vms: std::collections::HashSet<u64> =
        std::collections::HashSet::with_capacity(fde_map.len());
    let mut dwarf_lsdas: Vec<(u32, u32)> = Vec::with_capacity(fde_map.len() / 4);
    for (&func_vm, fde_info) in fde_map {
        dwarf_func_vms.insert(func_vm);

        let pers_idx = if fde_info.pers_got_vm != 0 && is_plausible_got_vm(fde_info.pers_got_vm) {
            if let Some(pos) = personalities
                .iter()
                .position(|&g| g == fde_info.pers_got_vm)
            {
                pos + 1
            } else {
                personalities.push(fde_info.pers_got_vm);
                personalities.len()
            }
        } else {
            0
        };

        let mut enc =
            UNWIND_ARM64_DWARF | fde_info.section_offset | (((pers_idx as u32) & 3) << 28);
        if fde_info.lsda_vm >= text_base && (fde_info.lsda_vm - text_base) < (1u64 << 31) {
            enc |= 0x4000_0000; // UNWIND_HAS_LSDA
            dwarf_lsdas.push((
                (func_vm - text_base) as u32,
                (fde_info.lsda_vm - text_base) as u32,
            ));
        }
        all_entries.push((func_vm, 0u32, enc));
    }

    // Also collect personalities from compact_unwind entries.
    for e in plain_entries {
        if let Some(got) = e.personality_got {
            if is_plausible_got_vm(got) && !personalities.contains(&got) {
                personalities.push(got);
            }
        }
    }

    let pers_count = all_entries.len();
    // LSDA descriptors: (func_offset_from_text, lsda_offset_from_text)
    let mut lsda_descriptors: Vec<(u32, u32)> =
        Vec::with_capacity(dwarf_lsdas.len() + plain_entries.len() / 8);
    for e in plain_entries {
        // Skip only when the DWARF loop actually emitted an entry
        // for this function — otherwise (e.g. FDE-less compact entry)
        // fall through so wild still produces the compact encoding.
        if dwarf_func_vms.contains(&e.func_addr) {
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
    lsda_descriptors.extend(dwarf_lsdas);
    lsda_descriptors.sort_by_key(|d| d.0);
    lsda_descriptors.dedup_by_key(|d| d.0);

    if all_entries.is_empty() {
        return Vec::new();
    }

    all_entries.sort_by_key(|e| e.0);
    all_entries.dedup_by_key(|e| e.0);

    // Adjacent-encoding coalesce — mirrors ld64's
    // `UnwindInfoAtom::compressDuplicates` (ld64 `src/ld/passes/
    // compact_unwind.cpp:343`). Any entry with the same encoding
    // as its predecessor and no LSDA (neither current nor prev)
    // is dropped; its range is then implicitly covered by the
    // preceding entry (libunwind's binary search over
    // `__unwind_info` treats `[entry[i].addr, entry[i+1].addr)`
    // as the owning range of `entry[i]`).
    //
    // This is what makes rust-2015-edition `std::panicking::
    // begin_panic` (input `__compact_unwind` encoding
    // `0x02000000` = FRAMELESS/stack_size=0/no-saved-regs)
    // vanish from ld64's output: the surrounding functions also
    // carry `0x02000000` compact encodings, so the whole run
    // collapses to one entry and libunwind simply doesn't
    // consult `__unwind_info` at `begin_panic`'s address.
    // Without this coalesce, wild emitted the bogus
    // per-function `0x02000000` entry, which libunwind then
    // treats as "leaf, x30 still valid" — incorrect for any
    // function that actually has a frame, and the resulting
    // mis-unwind corrupts callee-save registers and crashes at
    // `thread_start`'s dealloc with a "free(0x7)" abort.
    {
        let mut kept: Vec<(u64, u32, u32)> = Vec::with_capacity(all_entries.len());
        let mut prev_enc: Option<u32> = None;
        let mut prev_had_lsda = false;
        // Build a quick lookup for "does this entry have an LSDA?"
        // by checking the HAS_LSDA bit in the encoding.
        const UNWIND_HAS_LSDA: u32 = 0x4000_0000;
        for e in &all_entries {
            let (_addr, _size, enc) = *e;
            let has_lsda = (enc & UNWIND_HAS_LSDA) != 0;
            let keep = match prev_enc {
                Some(p) => p != enc || has_lsda || prev_had_lsda,
                None => true,
            };
            if keep {
                kept.push(*e);
            }
            prev_enc = Some(enc);
            prev_had_lsda = has_lsda;
        }
        all_entries = kept;
    }

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

    // Partition entries into pages. Non-compat (regular format) uses
    // fixed ENTRIES_PER_PAGE chunks. Compat (compressed format) has
    // two extra constraints that force variable-size pages:
    //   * ≤ 255 unique encodings per page (the 8-bit `encodingIdx` in every compressed entry
    //     indexes into `commonEncodings ++ page_encodings`; with `commonEncodings = 0` the page
    //     table alone has to fit in that 8-bit index);
    //   * funcOffset for every entry fits in 24 bits (the last function's VM address minus the
    //     page's first function must stay < 16 MB).
    // Rust binaries with 300+ DWARF-mode FDEs per page trip the first
    // constraint (each FDE has a unique encoding); binaries with a few
    // large functions trip the second. Both manifest as the panic
    // unwinder aborting with "failed to initiate panic, error 5"
    // because the wrong encoding index is fetched for some frame.
    // Page builder: accumulate entries while unique-encoding count
    // stays ≤ 255 and func-offset delta fits in 24 bits. Membership
    // via `HashSet` so the check is 𝒪(1) — the old
    // `uniq.contains(&enc)` was 𝒪(|uniq|) (up to 255) giving an
    // 𝒪(n_page²) page-builder. Per-page cost is now 𝒪(n_page).
    let page_ranges: Vec<(usize, usize)> = {
        let mut ranges = Vec::new();
        let mut i = 0;
        while i < all_entries.len() {
            let start = i;
            let first_addr = all_entries[i].0;
            let mut uniq: Vec<u32> = Vec::new();
            let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
            while i < all_entries.len() && (i - start) < ENTRIES_PER_PAGE {
                let (addr, _, enc) = all_entries[i];
                if addr - first_addr >= (1 << 24) {
                    break;
                }
                if seen.insert(enc) {
                    if uniq.len() >= 255 {
                        break;
                    }
                    uniq.push(enc);
                }
                i += 1;
            }
            if i == start {
                i = start + 1;
            }
            ranges.push((start, i));
        }
        ranges
    };
    let num_pages = page_ranges.len();

    tracing::debug!(
        "compact_unwind: building __unwind_info: {} entries ({} pers), {} personalities, {} pages",
        all_entries.len(),
        pers_count,
        personalities.len(),
        num_pages
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
    // Section layout constants (see mach-o/compact_unwind_encoding.h):
    //   header (7 × u32)
    //   personality array (u32 each, offset-from-TEXT of GOT slots)
    //   first-level index: (num_pages+1) × 12-byte entries
    //   LSDA descriptors: 8 bytes each
    //   second-level pages
    const HEADER_BYTES: u32 = 28;
    const FIRST_LEVEL_ENTRY_BYTES: u32 = 12;
    const LSDA_ENTRY_BYTES: u32 = 8;
    // Regular page: 8-byte header, 8-byte entries.
    const REGULAR_PAGE_HEADER_BYTES: u32 = 8;
    const REGULAR_ENTRY_BYTES: u32 = 8;
    // Compressed page: 12-byte header, 4-byte entries, 4-byte encodings.
    const COMPRESSED_PAGE_HEADER_BYTES: u32 = 12;
    const COMPRESSED_ENTRY_BYTES: u32 = 4;
    const COMPRESSED_ENCODING_BYTES: u32 = 4;
    const UNWIND_SECOND_LEVEL_REGULAR: u32 = 2;
    const UNWIND_SECOND_LEVEL_COMPRESSED: u32 = 3;
    // Compressed entries pack funcOffset into the low 24 bits and an
    // encoding-table index into the high 8 bits.
    const COMPRESSED_ENTRY_FUNC_OFFSET_MASK: u32 = 0x00ff_ffff;
    // ld64 aligns the second-level page section to 16 bytes, leaving up
    // to 12 bytes of zero padding between the LSDA array and the page.
    const LD64_COMPAT_PAGE_ALIGN: u32 = 16;

    let ce_off = HEADER_BYTES;
    let pers_off = ce_off; // no common encodings
    let pers_bytes = n_pers * 4;
    let idx_off = pers_off + pers_bytes;
    let idx_bytes = (num_pages as u32 + 1) * FIRST_LEVEL_ENTRY_BYTES;
    let lsda_off = idx_off + idx_bytes;
    let lsda_bytes = lsda_descriptors.len() as u32 * LSDA_ENTRY_BYTES;
    let mut sl_start = lsda_off + lsda_bytes;
    sl_start = (sl_start + LD64_COMPAT_PAGE_ALIGN - 1) & !(LD64_COMPAT_PAGE_ALIGN - 1);

    // Pre-compute the deduplicated encoding table per page. Compressed
    // second-level pages store a table of unique encodings and per-entry
    // 8-bit indices into it; multiple functions with the same unwind
    // encoding (e.g. three identical frame-pointer prologues) collapse
    // to one encoding row. Without this the page would be 4 bytes per
    // duplicate too large and diverge from ld64.
    //
    // Order matters (the Vec's index becomes the per-entry encoding
    // index later), so keep the Vec but dedupe via a side HashSet so
    // the membership test is 𝒪(1) instead of 𝒪(|uniq|). Per-page
    // cost drops from 𝒪(n_page · uniq_page) to 𝒪(n_page).
    let mut page_unique_encodings: Vec<Vec<u32>> = Vec::with_capacity(num_pages);
    for &(start, end) in &page_ranges {
        let mut uniq: Vec<u32> = Vec::new();
        let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for &(_, _, enc) in &all_entries[start..end] {
            if seen.insert(enc) {
                uniq.push(enc);
            }
        }
        page_unique_encodings.push(uniq);
    }

    let mut sl_offsets = Vec::with_capacity(num_pages);
    let mut cur = sl_start;
    for (i, &(start, end)) in page_ranges.iter().enumerate() {
        sl_offsets.push(cur);
        let n = end - start;
        let enc_count = page_unique_encodings[i].len() as u32;
        let per_page = COMPRESSED_PAGE_HEADER_BYTES
            + n as u32 * COMPRESSED_ENTRY_BYTES
            + enc_count * COMPRESSED_ENCODING_BYTES;
        cur += per_page;
    }
    // Pad the __unwind_info section out to an 8-byte multiple so the
    // section honours its declared 2^2 alignment even when the last
    // second-level page ends on a 4-byte boundary.
    cur = (cur + 7) & !7;
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
    // The `is_plausible_got_vm` filter above guarantees each entry
    // fits in u32 and is at or above `text_base`.
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

    // First-level index entries + second-level pages
    for page in 0..num_pages {
        let (start, end) = page_ranges[page];
        let page_entries = &all_entries[start..end];

        let first_fn_off = (page_entries[0].0 - text_base) as u32;
        let sl_off = sl_offsets[page] as usize;

        // Index entry (12 bytes)
        let ie = idx_off as usize + page * FIRST_LEVEL_ENTRY_BYTES as usize;
        wu32!(ie, first_fn_off);
        wu32!(ie + 4, sl_off as u32); // secondLevelPagesSectionOffset
        wu32!(ie + 8, lsda_off); // lsdaIndexArraySectionOffset

        {
            // Compressed page: 12-byte header then packed 4-byte entries
            // then 4-byte deduplicated encodings table.
            //
            // Per the Apple compact-unwind format, the 24-bit funcOffset
            // in each compressed entry is relative to the *page's first
            // function* (stored in the first-level index entry's
            // `functionOffset` field) — not relative to __TEXT base.
            // Storing (fa - text_base) and silently truncating to 24
            // bits would corrupt every entry past 16 MB from __TEXT
            // start — the Rust panic unwinder then looks up garbage
            // encodings and aborts with `failed to initiate panic,
            // error 5`.
            let n = page_entries.len() as u16;
            let uniq_encs = &page_unique_encodings[page];
            let enc_count = uniq_encs.len() as u16;
            wu32!(sl_off, UNWIND_SECOND_LEVEL_COMPRESSED);
            wu16!(sl_off + 4, COMPRESSED_PAGE_HEADER_BYTES as u16); // entryPageOffset
            wu16!(sl_off + 6, n); // entryCount
            let encodings_page_off =
                COMPRESSED_PAGE_HEADER_BYTES + n as u32 * COMPRESSED_ENTRY_BYTES;
            wu16!(sl_off + 8, encodings_page_off as u16); // encodingsPageOffset
            wu16!(sl_off + 10, enc_count); // encodingsCount (deduplicated)

            // Entries: funcOffset[23:0] | encodingIdx[31:24]
            //
            // Build a per-page `encoding → index` map once so each
            // entry's encoding-index lookup is 𝒪(1) instead of
            // 𝒪(uniq_encs.len()) linear scan. For a worst-case page
            // (1021 entries × 127 unique encodings) that drops the
            // inner loop from ~130 K comparisons to 1 K HashMap hits.
            let enc_idx_map: std::collections::HashMap<u32, u32> = uniq_encs
                .iter()
                .enumerate()
                .map(|(i, &e)| (e, i as u32))
                .collect();
            let page_first_fn = page_entries[0].0;
            for (j, &(fa, _, enc)) in page_entries.iter().enumerate() {
                let eo = sl_off
                    + COMPRESSED_PAGE_HEADER_BYTES as usize
                    + j * COMPRESSED_ENTRY_BYTES as usize;
                let fn_off = ((fa - page_first_fn) as u32) & COMPRESSED_ENTRY_FUNC_OFFSET_MASK;
                let enc_idx = *enc_idx_map.get(&enc).unwrap();
                wu32!(eo, fn_off | (enc_idx << 24));
            }
            // Encodings table appended after entries (deduplicated).
            let enc_base = sl_off + encodings_page_off as usize;
            for (j, &enc) in uniq_encs.iter().enumerate() {
                wu32!(enc_base + j * COMPRESSED_ENCODING_BYTES as usize, enc);
            }
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
///
/// **Complexity:** Θ(1) CPU and memory (single `match` on a bounded enum).
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
        // S_CSTRING_LITERALS lets dyld deduplicate C strings across
        // images — ld64 always sets it. Leaving it S_REGULAR is a bug.
        output_section_id::RODATA => (TEXT_SEG, name16(b"__cstring"), S_CSTRING_LITERALS),
        output_section_id::COMMENT => (TEXT_SEG, name16(b"__unwind_info"), 0),
        output_section_id::DATA_REL_RO => (TEXT_SEG, name16(b"__const"), 0),
        output_section_id::DATA => (DATA_SEG, name16(b"__data"), 0),
        output_section_id::CSTRING => (DATA_SEG, name16(b"__const"), 0),
        output_section_id::GOT => (DATA_SEG, name16(b"__got"), 0x06),
        output_section_id::PREINIT_ARRAY => (DATA_SEG, name16(b"__thread_vars"), 0x13),
        output_section_id::INIT_ARRAY => (DATA_SEG, name16(b"__mod_init_func"), 0x09),
        // S_MOD_TERM_FUNC_POINTERS = 0x0A. Previously mis-encoded as
        // 0x0E (= S_16BYTE_LITERALS), which kept FINI_ARRAY out of
        // __DATA_CONST (is_const_pointer_flags doesn't match 0x0E)
        // but the layout order still placed it BEFORE __data. The
        // segment-bounds mismatch (section addr in __DATA_CONST's VM
        // range, segname = __DATA) crashed dyld at load:
        // `section '__mod_term_func' start address is before
        // containing segment's address`.
        output_section_id::FINI_ARRAY => (DATA_SEG, name16(b"__mod_term_func"), 0x0A),
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
///
/// **Complexity:** 𝒪(L + s) CPU, where `L` = load command count and `s` = output section
/// count (one LC_SECTION_64 per section); 𝒪(L + s) memory for the serialised header bytes.
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
    #[derive(Copy, Clone)]
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

    // Under `-ld64_compat`, ld64 reports `section.size` as the unrounded
    // content end (last symbol end minus section start), while wild's
    // default `sec_layout.mem_size` is the sum of per-part capacities
    // (each align-up'd to its own alignment). That overcounts by the
    // trailing pad of the last part when its alignment exceeds its
    // content size — e.g. `many-globals.c` has `aligned16` (size=8,
    // align=16) at the tail of `__data`, giving `mem_size=0x30` where
    // ld64 reports `0x28`.
    //
    // Scan input sections (each has a raw `size` and a `section_resolutions`
    // placement address) to find the actual content end per output
    // section, keyed by `output_section_id`.
    use std::collections::HashMap;
    let mut content_end_by_section: HashMap<output_section_id::OutputSectionId, u64> =
        HashMap::new();
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            let FileLayout::Object(obj) = file_layout else {
                continue;
            };
            for (sec_idx, slot) in obj.sections.iter().enumerate() {
                let crate::resolution::SectionSlot::Loaded(section) = slot else {
                    continue;
                };
                let Some(address) = obj.section_resolutions[sec_idx].address() else {
                    continue;
                };
                let end = address + section.size;
                let out_id = section.output_section_id();
                content_end_by_section
                    .entry(out_id)
                    .and_modify(|e| *e = (*e).max(end))
                    .or_insert(end);
            }
        }
    }

    // Sanity check: `__thread_bss` must start at or after the end of
    // `__thread_data`, and both must share the same alignment. The
    // former guards against silent layout regressions that would corrupt
    // per-thread TLV offsets (see `tlv_template_offset`); the latter
    // makes those offsets alignment-respecting per rdar://24221680.
    #[cfg(debug_assertions)]
    {
        let tdata = layout.section_layouts.get(output_section_id::TDATA);
        let tbss = layout.section_layouts.get(output_section_id::TBSS);
        if tdata.mem_size > 0 && tbss.mem_size > 0 {
            debug_assert!(
                tbss.mem_offset >= tdata.mem_offset + tdata.mem_size,
                "TLS layout: __thread_bss @ {:#x} overlaps __thread_data ending at {:#x}",
                tbss.mem_offset,
                tdata.mem_offset + tdata.mem_size,
            );
            debug_assert_eq!(
                tdata.alignment, tbss.alignment,
                "TLS layout: __thread_data align 2^{} and __thread_bss align 2^{} differ",
                tdata.alignment.exponent, tbss.alignment.exponent,
            );
        }
    }

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
            // ARM64 ABI: S_SYMBOL_STUBS entries are 12 bytes of code and
            // must be 4-byte aligned. The generic per-section alignment
            // from ELF layout can default to 1 (exponent 0) for the stubs
            // output, so clamp to a minimum of 2 (2^2=4) when the section
            // type is S_SYMBOL_STUBS.
            const STUBS_MIN_ALIGN_EXP: u32 = 2; // 2^2 = 4 bytes
            let mut align = sec_layout.alignment.exponent as u32;
            if (info.flags & SECTION_TYPE_MASK) == S_SYMBOL_STUBS && align < STUBS_MIN_ALIGN_EXP {
                align = STUBS_MIN_ALIGN_EXP;
            }
            // Under compat mode, if input sections report a smaller
            // content end than the align-up'd `mem_size`, use the
            // content end to match ld64's reported section size.
            let mut size = if let Some(&content_end) = content_end_by_section.get(&sec_id) {
                let content_size = content_end.saturating_sub(sec_layout.mem_offset);
                content_size.min(sec_layout.mem_size)
            } else {
                sec_layout.mem_size
            };
            // COMMENT repurposes its layout slot as `__unwind_info`;
            // the layout reserves an upper-bound block (see
            // `apply_late_size_adjustments_epilogue`) but the emitted
            // section header must report the *actual* bytes written
            // by `build_unwind_info_section` so ld64-compat tests
            // stay bit-for-bit with ld64.
            if sec_id == output_section_id::COMMENT {
                size = unwind_info_size;
            }
            // dyld's `findInitialContent` (libdyld/ThreadLocalVariables.cpp)
            // visits TLV-template sections in load order and extends the
            // per-thread buffer span to `last.addr + last.size - first.addr`,
            // so when `__thread_bss` follows `__thread_data` its header
            // defines the template end. No tdata-size padding needed here —
            // the TDATA/TBSS alignment promotion in `adjust_alignments_after_sizing`
            // makes the natural section-alignment gap match what every
            // consumer of `tlv_template_offset` already assumes.
            let hdr = SectionHeader {
                segname: *info.segname,
                sectname: info.sectname,
                addr: sec_layout.mem_offset,
                size,
                offset: file_off,
                align,
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
    // `__unwind_info` is emitted as the `COMMENT` output section
    // header (see `macho_section_info`). No explicit header here.
    let _ = has_unwind_info;
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
            align: 2,    // 4-byte aligned
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
    // Under `-ld64_compat`, rename `__bss` to `__common` — ld64 routes
    // tentative definitions (Clang's default for uninitialised globals
    // like `int big[1024];`) through `__DATA,__common` (S_ZEROFILL).
    // Wild lumps them into the `__bss` output section; matching the
    // name keeps bit-for-bit compat with the typical C program.
    {
        let mut buf = [0u8; 16];
        buf[..b"__common".len()].copy_from_slice(b"__common");
        for sec in &mut data_sections {
            let name = crate::macho::trim_nul(&sec.sectname);
            if name == b"__bss" {
                sec.sectname = buf;
            }
        }
    }

    let text_nsects = text_sections.len() as u32;
    add_cmd(&mut ncmds, &mut cmdsize, 72 + 80 * text_nsects); // TEXT
    // With mixed (immutable + writable) __DATA content, we emit *two*
    // segment commands (__DATA_CONST + __DATA) in place of one. Detect
    // that here so ncmds/cmdsize account for both. The emission code
    // below mirrors the same partition logic.
    let is_const_pointer_flags = |flags: u32| -> bool {
        // Low byte of Mach-O section flags is the section type. ld64
        // places these immutable-pointer types into __DATA_CONST:
        //   S_NON_LAZY_SYMBOL_POINTERS (0x06), S_LAZY_SYMBOL_POINTERS (0x07),
        //   S_MOD_INIT_FUNC_POINTERS (0x09), S_MOD_TERM_FUNC_POINTERS (0x0A),
        //   S_LAZY_DYLIB_SYMBOL_POINTERS (0x10).
        matches!(flags & SECTION_TYPE_MASK, 0x06 | 0x07 | 0x09 | 0x0A | 0x10)
    };
    let (const_count, writable_count) = if has_data {
        let mut c = 0u32;
        let mut w_ = 0u32;
        for s in &data_sections {
            if is_const_pointer_flags(s.flags) {
                c += 1;
            } else {
                w_ += 1;
            }
        }
        (c, w_)
    } else {
        (0, 0)
    };
    let split_data = has_data && const_count > 0 && writable_count > 0;
    if has_data {
        if split_data {
            add_cmd(&mut ncmds, &mut cmdsize, 72 + 80 * const_count); // __DATA_CONST
            add_cmd(&mut ncmds, &mut cmdsize, 72 + 80 * writable_count); // __DATA
        } else {
            let data_nsects = data_sections.len() as u32;
            add_cmd(&mut ncmds, &mut cmdsize, 72 + 80 * data_nsects);
        }
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
    add_cmd(&mut ncmds, &mut cmdsize, 16); // LC_SOURCE_VERSION
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
        // reserved2: stub size for S_SYMBOL_STUBS — ARM64 stubs are always 12 bytes.
        const ARM64_STUB_SIZE: u32 = 12;
        let reserved2 = if sec.flags & SECTION_TYPE_MASK == S_SYMBOL_STUBS {
            ARM64_STUB_SIZE
        } else {
            0
        };
        w.u32(reserved2);
        w.u32(0); // reserved3
    }

    if has_data {
        // Under `-ld64_compat`, the DATA region splits three ways:
        //   * All-immutable  → rename the whole segment to __DATA_CONST and flag it SG_READ_ONLY
        //     (dyld maps it read-only after fixups).
        //   * All-writable   → keep as __DATA.
        //   * Mixed          → emit two segments: __DATA_CONST (for __got etc.) then __DATA (for
        //     __data/__bss), with a 16 KB page boundary between them. The
        //     `adjust_output_section_alignments` hook forced `__data` onto a page boundary at
        //     layout time so this split has somewhere clean to cut.
        const SG_READ_ONLY: u32 = 0x10;
        const PAGE_SIZE_U64: u64 = 0x4000;

        let seg16 = |name: &[u8]| -> [u8; 16] {
            let mut buf = [0u8; 16];
            buf[..name.len().min(16)].copy_from_slice(&name[..name.len().min(16)]);
            buf
        };

        // `emit_section` writes a single section_64 with the requested
        // segname override (bit-for-bit match with ld64 requires the
        // section's segname field to track the LC it lives under).
        let emit_section = |w: &mut Writer<'_>, sec: &SectionHeader, segname: &[u8; 16]| {
            w.buf[w.pos..w.pos + 16].copy_from_slice(&sec.sectname);
            w.pos += 16;
            w.buf[w.pos..w.pos + 16].copy_from_slice(segname);
            w.pos += 16;
            w.u64(sec.addr);
            w.u64(sec.size);
            w.u32(sec.offset);
            // When we bumped the min-alignment to force the page split,
            // the section's on-disk alignment field would inherit 2^14
            w.u32(sec.align);
            w.u32(0); // reloff
            w.u32(0); // nreloc
            w.u32(sec.flags);
            w.u32(0); // reserved1
            w.u32(0); // reserved2
            w.u32(0); // reserved3
        };

        if split_data {
            // Partition sections by constness; preserve the in-vector order.
            let (const_sects, writable_sects): (Vec<_>, Vec<_>) = data_sections
                .iter()
                .partition(|s| is_const_pointer_flags(s.flags));

            // __DATA_CONST: occupies enough pages to hold every const
            // section, page-aligned so __DATA can start on a clean
            // boundary. Tiny binaries fit in one page (mixed-data,
            // bss-big etc.) — but big Rust binaries can have a
            // multi-page __got (e.g. midnight-node-toolkit linked with
            // subxt + sqlx sits around 30 KB of GOT entries). Hard-
            // coding this to one page caused dyld's "__got end address
            // is beyond containing segment's end" abort at load.
            let const_end_vm: u64 = const_sects
                .iter()
                .map(|s| {
                    let hdr: &SectionHeader = s;
                    hdr.addr + hdr.size
                })
                .max()
                .unwrap_or(data_vmaddr);
            let const_vmsize = align_to(const_end_vm - data_vmaddr, PAGE_SIZE_U64);
            let const_filesize = const_vmsize;
            w.u32(LC_SEGMENT_64);
            w.u32(72 + 80 * const_sects.len() as u32);
            w.name16(b"__DATA_CONST");
            w.u64(data_vmaddr);
            w.u64(const_vmsize);
            w.u64(data_fileoff);
            w.u64(const_filesize);
            w.u32(VM_PROT_READ | VM_PROT_WRITE);
            w.u32(VM_PROT_READ | VM_PROT_WRITE);
            w.u32(const_sects.len() as u32);
            w.u32(SG_READ_ONLY);
            let const_segname16 = seg16(b"__DATA_CONST");
            for sec in &const_sects {
                emit_section(&mut w, sec, &const_segname16);
            }

            // __DATA: remaining pages starting immediately after
            // __DATA_CONST (which may be >1 page — see above).
            let writable_vmaddr = data_vmaddr + const_vmsize;
            let writable_vmsize = data_vmsize.saturating_sub(const_vmsize);
            let writable_fileoff = data_fileoff + const_vmsize;
            let writable_filesize = data_filesize.saturating_sub(const_vmsize);
            w.u32(LC_SEGMENT_64);
            w.u32(72 + 80 * writable_sects.len() as u32);
            w.name16(b"__DATA");
            w.u64(writable_vmaddr);
            w.u64(writable_vmsize);
            w.u64(writable_fileoff);
            w.u64(writable_filesize);
            w.u32(VM_PROT_READ | VM_PROT_WRITE);
            w.u32(VM_PROT_READ | VM_PROT_WRITE);
            w.u32(writable_sects.len() as u32);
            w.u32(0);
            let writable_segname16 = seg16(b"__DATA");
            for sec in &writable_sects {
                emit_section(&mut w, sec, &writable_segname16);
            }
        } else {
            // Single-segment fast path: rename to __DATA_CONST when all
            // sections are immutable pointers; otherwise keep __DATA.
            let rename_to_const = !data_sections.is_empty()
                && data_sections
                    .iter()
                    .all(|s| is_const_pointer_flags(s.flags));
            let (seg_name, seg_flags): (&[u8], u32) = if rename_to_const {
                (b"__DATA_CONST", SG_READ_ONLY)
            } else {
                (b"__DATA", 0)
            };
            let segname16 = seg16(seg_name);

            // When every section in the merged __DATA is zerofill
            // (S_ZEROFILL, S_GB_ZEROFILL, or S_THREAD_LOCAL_ZEROFILL),
            // dyld allocates the segment's VM range at load time and
            // doesn't need any file bytes. ld64 emits fileoff=0,
            // filesize=0 for that case; reserving a full 16 KB page
            // of zeros on disk wastes space and diverges from ld64
            // bit-for-bit.
            let is_zerofill_flags =
                |flags: u32| -> bool { matches!(flags & SECTION_TYPE_MASK, 0x01 | 0x0C | 0x12) };
            let all_zerofill = !data_sections.is_empty()
                && data_sections.iter().all(|s| is_zerofill_flags(s.flags));
            let (emit_fileoff, emit_filesize) = if all_zerofill {
                (0, 0)
            } else {
                (data_fileoff, data_filesize)
            };

            w.u32(LC_SEGMENT_64);
            w.u32(72 + 80 * data_sections.len() as u32);
            w.name16(seg_name);
            w.u64(data_vmaddr);
            w.u64(data_vmsize);
            w.u64(emit_fileoff);
            w.u64(emit_filesize);
            w.u32(VM_PROT_READ | VM_PROT_WRITE);
            w.u32(VM_PROT_READ | VM_PROT_WRITE);
            w.u32(data_sections.len() as u32);
            w.u32(seg_flags);
            for sec in &data_sections {
                let segname = if rename_to_const {
                    &segname16
                } else {
                    &sec.segname
                };
                // Zerofill section headers report offset=0 since the
                // section has no file backing; dyld allocates the
                // range from its `addr`/`size` alone.
                let sec_for_emit = if is_zerofill_flags(sec.flags) {
                    SectionHeader { offset: 0, ..*sec }
                } else {
                    *sec
                };
                emit_section(&mut w, &sec_for_emit, segname);
            }
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

    // When every merged-DATA section is zerofill, the data segment
    // reports filesize=0 so __LINKEDIT slides up the file to sit
    // directly after __TEXT. Matches ld64's bss-only layout.
    let is_zerofill_flag =
        |flags: u32| -> bool { matches!(flags & SECTION_TYPE_MASK, 0x01 | 0x0C | 0x12) };
    let data_all_zerofill = has_data
        && !data_sections.is_empty()
        && data_sections.iter().all(|s| is_zerofill_flag(s.flags));
    let (last_file_end, linkedit_vm) = if has_data {
        if data_all_zerofill {
            (text_filesize, data_vmaddr + data_vmsize)
        } else {
            (data_fileoff + data_filesize, data_vmaddr + data_vmsize)
        }
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

    // Emit the non-segment load commands. The ordering follows ld64
    // when `-ld64_compat` is set (test suite needs bit-for-bit match);
    // otherwise wild uses its historical ordering. Every arm is an
    // expression with unit type so `match` below cleanly dispatches.
    //
    // ld64 order: fixups → exports → symtab → dysymtab → dylinker →
    //             uuid → build_ver → src_ver → main → dylibs → rpath →
    //             umbrella → fn_starts → data_in_code.
    // wild order: uuid → main → dylinker → dylibs → rpath → umbrella →
    //             symtab → dysymtab → build_ver → src_ver → fixups →
    //             exports → fn_starts → data_in_code.
    #[derive(Copy, Clone)]
    enum Lc {
        Uuid,
        MainOrIdDylib,
        Dylinker,
        LibSystem,
        ExtraDylibs,
        Rpaths,
        SubFramework,
        Symtab,
        Dysymtab,
        BuildVersion,
        SourceVersion,
        ChainedFixups,
        ExportsTrie,
        FunctionStarts,
        DataInCode,
    }

    // ld64 load-command order: fixups → exports → symtab → dysymtab →
    // dylinker → uuid → build_ver → src_ver → main → dylibs → rpath →
    // umbrella → fn_starts → data_in_code. dyld + otool are tested
    // primarily against this order; a handful of tools depend on
    // specific commands appearing before others (e.g. `LC_UUID` must
    // precede `LC_MAIN` for some crash reporters).
    let order: &[Lc] = &[
        Lc::ChainedFixups,
        Lc::ExportsTrie,
        Lc::Symtab,
        Lc::Dysymtab,
        Lc::Dylinker,
        Lc::Uuid,
        Lc::BuildVersion,
        Lc::SourceVersion,
        Lc::MainOrIdDylib,
        Lc::LibSystem,
        Lc::ExtraDylibs,
        Lc::Rpaths,
        Lc::SubFramework,
        Lc::FunctionStarts,
        Lc::DataInCode,
    ];

    for &lc in order {
        match lc {
            Lc::Uuid => {
                if !emit_uuid {
                    continue;
                }
                w.u32(LC_UUID);
                w.u32(24);
                let uuid_bytes: [u8; 16] = if layout.symbol_db.args.random_uuid {
                    let mut h = [0u8; 16];
                    let t = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos();
                    h[..16].copy_from_slice(&t.to_le_bytes());
                    h[6] = (h[6] & 0x0F) | 0x40;
                    h[8] = (h[8] & 0x3F) | 0x80;
                    h
                } else {
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
                    h[6] = (h[6] & 0x0F) | 0x40;
                    h[8] = (h[8] & 0x3F) | 0x80;
                    h
                };
                w.bytes(&uuid_bytes);
            }
            Lc::MainOrIdDylib => {
                if is_dylib {
                    w.u32(LC_ID_DYLIB);
                    w.u32(id_dylib_cmd_size);
                    w.u32(24);
                    w.u32(2);
                    w.u32(layout.symbol_db.args.current_version);
                    w.u32(layout.symbol_db.args.compatibility_version);
                    w.bytes(install_name.as_bytes());
                    w.u8(0);
                    w.pad8();
                } else if !is_bundle {
                    w.u32(LC_MAIN);
                    w.u32(24);
                    w.u64(entry_offset as u64);
                    w.u64(layout.symbol_db.args.stack_size.unwrap_or(0));
                }
            }
            Lc::Dylinker => {
                if !is_dylib {
                    w.u32(LC_LOAD_DYLINKER);
                    w.u32(dylinker_cmd_size);
                    w.u32(12);
                    w.bytes(DYLD_PATH);
                    w.u8(0);
                    w.pad8();
                }
            }
            Lc::LibSystem => {
                w.u32(LC_LOAD_DYLIB);
                w.u32(dylib_cmd_size);
                w.u32(24);
                w.u32(2);
                w.u32(0x01_0000);
                w.u32(0x01_0000);
                w.bytes(LIBSYSTEM_PATH);
                w.u8(0);
                w.pad8();
            }
            Lc::ExtraDylibs => {
                for (i, (dylib_path, kind)) in extra_dylibs.iter().enumerate() {
                    use crate::args::macho::DylibLoadKind;
                    let cmd = match kind {
                        DylibLoadKind::Normal => LC_LOAD_DYLIB,
                        DylibLoadKind::Weak => LC_LOAD_WEAK_DYLIB,
                        DylibLoadKind::Reexport => LC_REEXPORT_DYLIB,
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
            }
            Lc::Rpaths => {
                for (i, rpath) in rpaths.iter().enumerate() {
                    w.u32(LC_RPATH);
                    w.u32(rpath_sizes[i]);
                    w.u32(12); // rpath_command.path offset (after cmd+size+offset)
                    w.bytes(rpath);
                    w.u8(0);
                    w.pad8();
                }
            }
            Lc::SubFramework => {
                if let Some(ref umbrella_name) = layout.symbol_db.args.umbrella {
                    w.u32(LC_SUB_FRAMEWORK);
                    w.u32(umbrella_cmd_size);
                    w.u32(12); // sub_framework_command.umbrella offset
                    w.bytes(umbrella_name.as_bytes());
                    w.u8(0);
                    w.pad8();
                }
            }
            Lc::Symtab => {
                w.u32(LC_SYMTAB);
                w.u32(24);
                w.u32(0);
                w.u32(0);
                w.u32(0);
                w.u32(0);
            }
            Lc::Dysymtab => {
                w.u32(LC_DYSYMTAB);
                w.u32(80);
                for _ in 0..18 {
                    w.u32(0);
                }
            }
            Lc::BuildVersion => {
                w.u32(LC_BUILD_VERSION);
                w.u32(32);
                w.u32(PLATFORM_MACOS);
                w.u32(layout.symbol_db.args.minos.unwrap_or(0x000E_0000));
                w.u32(layout.symbol_db.args.sdk_version.unwrap_or(0x000E_0000));
                w.u32(1);
                w.u32(3);
                w.u32(0x0300_0100);
            }
            Lc::SourceVersion => {
                w.u32(LC_SOURCE_VERSION);
                w.u32(16);
                w.u64(0);
            }
            Lc::ChainedFixups => {
                w.u32(LC_DYLD_CHAINED_FIXUPS);
                w.u32(16);
                w.u32(cf_offset as u32);
                w.u32(cf_size as u32);
            }
            Lc::ExportsTrie => {
                w.u32(LC_DYLD_EXPORTS_TRIE);
                w.u32(16);
                w.u32(last_file_end as u32);
                w.u32(0);
            }
            Lc::FunctionStarts => {
                if emit_func_starts {
                    w.u32(LC_FUNCTION_STARTS);
                    w.u32(16);
                    w.u32(last_file_end as u32);
                    w.u32(0);
                }
            }
            Lc::DataInCode => {
                if emit_data_in_code {
                    w.u32(LC_DATA_IN_CODE);
                    w.u32(16);
                    w.u32(last_file_end as u32);
                    w.u32(0);
                }
            }
        }
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
/// Write a Mach-O relocatable object file (`MH_OBJECT`) for partial linking (`-r`).
/// Collects sections and symbols from all input objects, merges matching sections,
/// reindexes relocations, and serialises the result.
///
/// **Complexity:** 𝒪(m·(s_obj + r_obj + e_obj)) CPU, where `m` = object count,
/// `s_obj` = sections per object, `r_obj` = relocations per object, `e_obj` = symbols
/// per object. 𝒪(b) memory for the output buffer; 𝒪(n) for the merged symtab.
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
/// Debug-only: every symbol whose flags include `ValueFlags::GOT`
/// must have a `got_address` in its resolution. A mismatch means
/// some reloc-scan pass set the flag but the GOT slot allocator
/// never ran for this symbol — any later POINTER_TO_GOT against
/// it will silently corrupt the output. Cheap linear walk.
#[cfg(debug_assertions)]
/// See function body for details.
///
/// **Complexity:** 𝒪(n) CPU (one pass over all symbol resolutions); 𝒪(1) memory.
fn validate_got_flag_consistency(layout: &Layout<'_, MachO>) -> Result {
    use crate::symbol_db::SymbolId;
    use crate::value_flags::ValueFlags;
    for (idx, res_opt) in layout.symbol_resolutions.iter().enumerate() {
        let Some(res) = res_opt else { continue };
        let sym_id = SymbolId::from_usize(idx);
        let flags = layout.flags_for_symbol(sym_id);
        if flags.contains(ValueFlags::GOT) && res.format_specific.got_address.is_none() {
            let name = layout
                .symbol_db
                .symbol_name(sym_id)
                .map(|n| String::from_utf8_lossy(n.bytes()).into_owned())
                .unwrap_or_else(|_| format!("#{idx}"));
            crate::bail!(
                "layout invariant: symbol `{name}` (id {idx}) has \
                 ValueFlags::GOT but no got_address was allocated. \
                 Some reloc scan set the GOT flag after the slot \
                 allocator ran, or the scan and allocator disagree."
            );
        }
    }
    Ok(())
}

/// Debug-only: any symbol whose input offset lies inside a
/// *dormant* (non-scanned) atom of an atom-managed section must
/// not have any live reference-flagged state. If it does,
/// something handed out a `resolution_flags` bit (GOT / PLT /
/// DIRECT / EXPORT_DYNAMIC / ...) for a symbol whose atom the
/// GC decided to delete — the reloc using that flag will then
/// resolve against a compacted (meaningless) VM from
/// `input_to_output_offset`. Catches bugs in atom activation
/// propagation.
#[cfg(debug_assertions)]
/// See function body for details.
///
/// **Complexity:** 𝒪(m·(a_obj + e_obj)) CPU, where `a_obj` = atoms per section and
/// `e_obj` = symbols per object; 𝒪(1) memory.
fn validate_no_references_into_dormant_atoms(layout: &Layout<'_, MachO>) -> Result {
    use crate::layout::FileLayout;
    use object::read::macho::Nlist as _;
    use object::read::macho::Section as _;
    let le = object::Endianness::Little;
    for group in &layout.group_layouts {
        for file_layout in &group.files {
            let FileLayout::Object(obj) = file_layout else {
                continue;
            };
            for (sec_idx, tracking) in obj.subsection_tracking.iter() {
                let Some(input_section) = obj.object.sections.get(*sec_idx) else {
                    continue;
                };
                let section_addr = input_section.addr(le);
                for (sym_idx, sym) in obj.object.symbols.iter().enumerate() {
                    let n_type = sym.n_type();
                    if n_type & object::macho::N_STAB != 0 {
                        continue;
                    }
                    if n_type & object::macho::N_TYPE != object::macho::N_SECT {
                        continue;
                    }
                    if sym.n_sect() as usize != *sec_idx + 1 {
                        continue;
                    }
                    let offset = sym.n_value(le).wrapping_sub(section_addr);
                    let Some(atom_idx) = tracking.atom_index_for_offset(offset) else {
                        continue;
                    };
                    if tracking.scanned[atom_idx] {
                        continue;
                    }
                    // Dormant atom. Check if the symbol has any
                    // live reference. Map local sym_idx → global
                    // SymbolId; if the global id maps elsewhere
                    // (this sym was shadowed by a stronger
                    // definition in another object), dormancy
                    // here is expected — the canonical symbol
                    // lives in the other object. Only flag when
                    // the local definition IS the canonical one.
                    let local_id = obj
                        .symbol_id_range
                        .input_to_id(object::SymbolIndex(sym_idx));
                    let global_id = layout.symbol_db.definition(local_id);
                    if global_id != local_id {
                        continue;
                    }
                    let flags = layout.flags_for_symbol(global_id);
                    if flags.has_resolution() {
                        let name = sym
                            .name(le, obj.object.symbols.strings())
                            .map(|n| String::from_utf8_lossy(n).into_owned())
                            .unwrap_or_else(|_| format!("sym#{sym_idx}"));
                        let sectname = String::from_utf8_lossy(crate::macho::trim_nul(
                            input_section.sectname(),
                        ))
                        .into_owned();
                        crate::bail!(
                            "layout invariant: symbol `{name}` lives in a \
                             dormant atom of {sectname} (atom #{atom_idx}, \
                             input_range=[{:#x}..{:#x})) but has live \
                             flags={flags:?}. Something activated the \
                             symbol without activating its atom — GC bug.",
                            tracking.atoms[atom_idx].input_start,
                            tracking.atoms[atom_idx].input_end
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// Top-level Mach-O output validator. Parses load commands and delegates to all
/// sub-validators (segment/section layout, chained fixups, self-import check,
/// LINKEDIT alignment/layout, unwind info, data-split, eh_frame consistency).
///
/// **Complexity:** 𝒪(L + s + i + e + f + u) CPU (each sub-validator is linear in its
/// subject); 𝒪(f) memory for the FDE map built by `scan_eh_frame_fde_offsets`.
fn validate_macho_output(buf: &[u8], flat_namespace: bool) -> Result {
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
                    let mut tdata_start = 0u64;
                    let mut tdata_size = 0u64;
                    let mut tbss_start = 0u64;
                    let mut tbss_size = 0u64;
                    let mut tvars_foff = 0usize;
                    let mut tvars_count = 0usize;
                    for sec in sections {
                        let sec_type = sec.flags(le) & 0xFF;
                        let addr = sec.addr(le);
                        let size = sec.size(le);
                        match sec_type {
                            0x11 => {
                                tdata_start = addr;
                                tdata_size = size;
                            }
                            0x12 => {
                                tbss_start = addr;
                                tbss_size = size;
                            }
                            0x13 => {
                                tvars_foff = sec.offset(le) as usize;
                                tvars_count = size as usize / 24;
                            }
                            _ => {}
                        }
                    }
                    // Match dyld's `findInitialContent`: the per-thread
                    // span runs from tdata's address to the end of the
                    // last TLV-template section. Padding between tdata
                    // and tbss (from alignment) counts toward the span.
                    // Using `tdata.size + tbss.size` under-reports when
                    // the section header truncates tdata.size to
                    // content-end rather than mem_size.
                    let tls_total = if tbss_size > 0 {
                        (tbss_start + tbss_size).saturating_sub(tdata_start)
                    } else {
                        tdata_size
                    };

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
                                     (tdata @ {tdata_start:#x}+{tdata_size:#x}, \
                                     tbss @ {tbss_start:#x}+{tbss_size:#x})"
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
                    // __mh_execute_header lives at the Mach-O header
                    // (0x100000000 for exe) but reports n_sect=1 (__text).
                    // Its address is deliberately before __text.addr —
                    // that's how ld64 emits it too. Skip this one.
                    let name_start_for_check = stroff + n_strx as usize;
                    let mh_name = b"__mh_execute_header";
                    let is_mh_header = name_start_for_check + mh_name.len() <= buf.len()
                        && &buf[name_start_for_check..name_start_for_check + mh_name.len()]
                            == mh_name;
                    if !is_mh_header && (n_value < sec_start || n_value > sec_end) {
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

    // Validate that no chained fixup import references a symbol that is
    // actually defined in this binary. Such entries cause dyld to look up
    // the symbol from dylibs instead of using the internal definition,
    // leading to "Symbol not found" crashes at runtime.
    // Under -flat_namespace, self-imports are legitimate (interposition),
    // so skip the check.
    if !flat_namespace {
        validate_no_self_imports(buf)?;
    }

    // LINKEDIT contents must be contiguously packed: every LC blob
    // (LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE, LC_SYMTAB,
    // LC_FUNCTION_STARTS, LC_DATA_IN_CODE, LC_CODE_SIGNATURE) must sit
    // inside __LINKEDIT and must not overlap any other blob. A dead-
    // data gap (as produced by the double-write exports-trie bug that
    // broke proc-macro dylib codesigning) triggers this check.
    validate_linkedit_layout(buf)?;

    // Compact-unwind compressed pages have invariants the spec quietly
    // requires but dyld doesn't verify — the `encodingIdx` must index
    // into `commonEncodings ++ page_encodings`, and the 24-bit
    // funcOffset must fit. Violations corrupt the encoding the
    // unwinder reads for some frame and abort panics with
    // "failed to initiate panic, error 5".
    validate_unwind_info(buf)?;

    // Under `-ld64_compat`'s DATA_CONST/DATA split, every const
    // section (GOT, INIT_ARRAY, FINI_ARRAY) must fit entirely inside
    // __DATA_CONST. Hardcoding __DATA_CONST to one page broke
    // binaries whose __got overflowed 16 KB; dyld aborted with
    // "__got end address is beyond containing segment's end".
    validate_compat_datasplit(buf)?;

    // DWARF __eh_frame consistency: parse every CIE/FDE with gimli
    // and cross-check P/L augmentation pointers against the output's
    // segment layout and __unwind_info's DWARF-mode entries. Catches
    // personality-pointer mis-relocation, stale LSDA references, and
    // compact-unwind → FDE offset mismatches.
    validate_eh_frame_consistency(buf)?;

    Ok(())
}

/// Walk all chained fixup chains and validate each entry.
///
/// **Complexity:** 𝒪(i + p·entries_per_page) CPU (walks every chain entry);
/// 𝒪(1) memory.
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

    // Find LC_DYLD_CHAINED_FIXUPS and the DATA segment(s). When the
    // merged DATA region is split into __DATA_CONST + __DATA, the
    // chained fixups header has per-segment entries and each walker
    // must use the *correct* segment's file offset. Capture every
    // loadable segment's (vmaddr, fileoff) so we can translate each
    // entry's `segment_offset` (VM offset from image_base) to a file
    // offset.
    let mut cf_off = 0u32;
    let mut cf_size = 0u32;
    let mut seg_table: Vec<(u64, u64)> = Vec::new(); // (vmaddr, fileoff)
    let image_base: u64;
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

    let mut text_vmaddr: Option<u64> = None;
    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((seg, _))) = cmd.segment_64() {
            let va = seg.vmaddr.get(le);
            let vs = seg.vmsize.get(le);
            let fo = seg.fileoff.get(le);
            image_end = image_end.max(va + vs);
            let segname = crate::macho::trim_nul(&seg.segname);
            if segname == b"__TEXT" && text_vmaddr.is_none() {
                text_vmaddr = Some(va);
            }
            if vs > 0 {
                seg_table.push((va, fo));
            }
        }
    }
    // Matches `write_chained_fixups_header`'s convention: `image_base`
    // is PAGEZERO_SIZE iff the first non-PAGEZERO segment (__TEXT) sits
    // at or above the PAGEZERO top; otherwise 0. Writer uses exactly
    // this test (`mappings.first().vm_start >= PAGEZERO_SIZE`), so we
    // must match it even for oddly-laid-out bundles where __PAGEZERO
    // exists but __TEXT overlaps it at vmaddr 0.
    const PAGEZERO_SIZE: u64 = 0x1_0000_0000;
    image_base = match text_vmaddr {
        Some(v) if v >= PAGEZERO_SIZE => PAGEZERO_SIZE,
        _ => 0,
    };

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
        let segment_offset = u64::from_le_bytes(cf[ss + 8..ss + 16].try_into().unwrap());
        let page_count = u16::from_le_bytes(cf[ss + 20..ss + 22].try_into().unwrap()) as usize;

        if page_size == 0 {
            continue;
        }

        // Resolve this entry's starting file offset. `segment_offset`
        // is the VM offset from image base; find the containing
        // segment and use its (vmaddr → fileoff) mapping. Falls back
        // to the first DATA-like segment if nothing matches (keeps
        // non-split binaries working).
        let entry_vmaddr = image_base + segment_offset;
        let data_fileoff: u64 = seg_table
            .iter()
            .filter(|&&(va, _)| va <= entry_vmaddr)
            .max_by_key(|&&(va, _)| va)
            .map(|&(va, fo)| fo + (entry_vmaddr - va))
            .unwrap_or(0);

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

/// Validate that chained fixup imports don't reference symbols defined in
/// this binary. When a symbol is both defined internally and listed as an
/// import, dyld will try to resolve it from a dylib, causing a runtime
/// "Symbol not found" crash.
///
/// **Complexity:** 𝒪(e + i) CPU (linear scan of symtab + import pool); 𝒪(e) memory for
/// the defined-symbol set.
fn validate_no_self_imports(buf: &[u8]) -> Result {
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

    // Collect defined symbol names from LC_SYMTAB.
    let mut defined_syms: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();

    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some(symtab)) = cmd.symtab() {
            let symoff = symtab.symoff.get(le) as usize;
            let nsyms = symtab.nsyms.get(le) as usize;
            let symtab_stroff = symtab.stroff.get(le) as usize;
            for i in 0..nsyms {
                let sym_off = symoff + i * 16;
                if sym_off + 16 > buf.len() {
                    break;
                }
                let n_strx = u32::from_le_bytes(buf[sym_off..sym_off + 4].try_into().unwrap());
                let n_type = buf[sym_off + 4];
                let n_sect = buf[sym_off + 5];

                // Skip stab entries (high bits set) and undefined symbols.
                if (n_type & 0xE0) != 0 {
                    continue;
                }
                // N_SECT (0x0e) with a valid section means it's defined.
                if (n_type & 0x0e) == 0x0e && n_sect != 0 {
                    let name_start = symtab_stroff + n_strx as usize;
                    if name_start < buf.len() {
                        let name_end = buf[name_start..]
                            .iter()
                            .position(|&b| b == 0)
                            .map(|p| name_start + p)
                            .unwrap_or(name_start);
                        let name = &buf[name_start..name_end];
                        if !name.is_empty() {
                            defined_syms.insert(name.to_vec());
                        }
                    }
                }
            }
        }
    }

    if defined_syms.is_empty() {
        return Ok(());
    }

    // Find LC_DYLD_CHAINED_FIXUPS and extract import symbol names.
    let mut cf_off = 0u32;
    let mut cf_size = 0u32;
    {
        let mut off = 32usize;
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

    if cf_off == 0 || cf_size == 0 {
        return Ok(());
    }

    let cf = match buf.get(cf_off as usize..(cf_off + cf_size) as usize) {
        Some(d) => d,
        None => return Ok(()),
    };
    if cf.len() < 24 {
        return Ok(());
    }

    let imports_offset = u32::from_le_bytes(cf[8..12].try_into().unwrap()) as usize;
    let symbols_offset = u32::from_le_bytes(cf[12..16].try_into().unwrap()) as usize;
    let imports_count = u32::from_le_bytes(cf[16..20].try_into().unwrap()) as usize;
    let imports_format = u32::from_le_bytes(cf[20..24].try_into().unwrap());

    let import_entry_size = match imports_format {
        1 => 4usize,
        2 => 8,
        3 => 16,
        _ => return Ok(()),
    };

    for i in 0..imports_count {
        let entry_off = imports_offset + i * import_entry_size;
        if entry_off + 4 > cf.len() {
            break;
        }
        let entry_word = u32::from_le_bytes(cf[entry_off..entry_off + 4].try_into().unwrap());
        // For format 1: bits [8:31] are name_offset (24 bits)
        // For format 2: bits [8:31] are name_offset (24 bits)
        // For format 3: bits from a u64, but name_offset is [32:63] — different layout
        let name_offset = if imports_format == 3 {
            if entry_off + 8 > cf.len() {
                break;
            }
            let hi = u32::from_le_bytes(cf[entry_off + 4..entry_off + 8].try_into().unwrap());
            hi as usize
        } else {
            (entry_word >> 9) as usize
        };

        let abs_name_off = symbols_offset + name_offset;
        if abs_name_off >= cf.len() {
            continue;
        }
        let name_end = cf[abs_name_off..]
            .iter()
            .position(|&b| b == 0)
            .map_or(abs_name_off, |p| abs_name_off + p);
        let import_name = &cf[abs_name_off..name_end];

        if defined_syms.contains(import_name) {
            let name_str = String::from_utf8_lossy(import_name);
            crate::bail!(
                "validate: chained fixup import '{name_str}' is also defined in this binary. \
                 This will cause dyld to look for it in dylibs instead of using the \
                 internal definition, leading to a runtime crash."
            );
        }
    }

    Ok(())
}

/// Validate that LINKEDIT content is properly aligned.
/// - LC_SYMTAB symoff must be 8-byte aligned (nlist_64 entries are 16 bytes, but the minimum
///   natural alignment is 8 for the n_value field).
/// - LC_SYMTAB stroff should be 4-byte aligned.
///
/// **Complexity:** 𝒪(L) CPU (one load-command walk); 𝒪(1) memory.
fn validate_linkedit_alignment(buf: &[u8]) -> Result {
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

    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some(symtab)) = cmd.symtab() {
            let symoff = symtab.symoff.get(le);
            let nsyms = symtab.nsyms.get(le);
            if nsyms > 0 && symoff % 8 != 0 {
                crate::bail!(
                    "validate: LC_SYMTAB symoff {symoff:#x} is not 8-byte aligned \
                     (required for nlist_64 entries)"
                );
            }
        }
    }

    Ok(())
}

/// Verify __LINKEDIT's declared tables (chained fixups, exports trie,
/// symtab, function starts, data-in-code, code signature) all fit
/// inside __LINKEDIT and don't overlap each other. Catches regressions
/// like the double-write exports-trie bug where one table's data
/// overlaps another or where an LC reports `datasize=0` but the writer
/// actually wrote payload at that offset (a silent LINKEDIT gap).
///
/// **Complexity:** 𝒪(L·log L) CPU (collect blobs then sort for overlap check);
/// 𝒪(L) memory for the blob list.
fn validate_linkedit_layout(buf: &[u8]) -> Result {
    use object::read::macho::MachHeader as _;
    use object::read::macho::Segment as _;
    let le = object::Endianness::Little;
    let header = match object::macho::MachHeader64::<object::Endianness>::parse(buf, 0) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };

    // Locate __LINKEDIT first.
    let mut linkedit: Option<(u64, u64)> = None; // (fileoff, filesize)
    let mut cmds = header
        .load_commands(le, buf, 0)
        .map_err(|e| crate::error!("validate: bad load commands: {e}"))?;
    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((seg, _))) = cmd.segment_64() {
            if crate::macho::trim_nul(&seg.segname) == b"__LINKEDIT" {
                linkedit = Some((seg.fileoff.get(le), seg.filesize.get(le)));
                break;
            }
        }
    }
    let Some((le_off, le_size)) = linkedit else {
        return Ok(());
    };
    let le_end = le_off + le_size;

    // Collect every LINKEDIT-resident (name, off, size) from LCs.
    // Walk load commands manually from the header — cmds.next()'s
    // typed accessors don't expose the raw bytes cleanly for arbitrary
    // linkedit_data_command shapes.
    let mut blobs: Vec<(&'static str, u64, u64)> = Vec::new();
    if buf.len() < 32 {
        return Ok(());
    }
    let ncmds = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
    let sizeofcmds = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as usize;
    if 32 + sizeofcmds > buf.len() {
        return Ok(());
    }
    let mut off = 32usize;
    for _ in 0..ncmds {
        if off + 8 > buf.len() {
            break;
        }
        let cmd_id = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmdsize == 0 || off + cmdsize > buf.len() {
            break;
        }
        let name = match cmd_id {
            0x2 => "LC_SYMTAB",
            0x80000034 => "LC_DYLD_CHAINED_FIXUPS",
            0x80000033 => "LC_DYLD_EXPORTS_TRIE",
            0x26 => "LC_FUNCTION_STARTS",
            0x29 => "LC_DATA_IN_CODE",
            0x1d => "LC_CODE_SIGNATURE",
            _ => {
                off += cmdsize;
                continue;
            }
        };
        if cmd_id == 0x2 {
            if cmdsize >= 24 {
                let symoff = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap()) as u64;
                let nsyms = u32::from_le_bytes(buf[off + 12..off + 16].try_into().unwrap()) as u64;
                let stroff = u32::from_le_bytes(buf[off + 16..off + 20].try_into().unwrap()) as u64;
                let strsize =
                    u32::from_le_bytes(buf[off + 20..off + 24].try_into().unwrap()) as u64;
                if nsyms > 0 {
                    blobs.push(("LC_SYMTAB_nlist", symoff, nsyms * 16));
                }
                if strsize > 0 {
                    blobs.push(("LC_SYMTAB_strtab", stroff, strsize));
                }
            }
        } else if cmdsize >= 16 {
            let off_val = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap()) as u64;
            let size_val = u32::from_le_bytes(buf[off + 12..off + 16].try_into().unwrap()) as u64;
            if size_val > 0 {
                blobs.push((name, off_val, size_val));
            }
        }
        off += cmdsize;
    }

    // Each blob must be inside __LINKEDIT.
    for (name, off, size) in &blobs {
        if *off < le_off || *off + *size > le_end {
            crate::bail!(
                "validate: {name} [{off:#x}..{end:#x}) escapes __LINKEDIT [{le_off:#x}..{le_end:#x})",
                end = off + size
            );
        }
    }

    // No two blobs may overlap.
    let mut sorted = blobs.clone();
    sorted.sort_by_key(|b| b.1);
    for w in sorted.windows(2) {
        let (n1, o1, s1) = &w[0];
        let (n2, o2, _) = &w[1];
        if o1 + s1 > *o2 {
            crate::bail!(
                "validate: __LINKEDIT overlap: {n1} [{o1:#x}..{e1:#x}) vs {n2} @ {o2:#x}",
                e1 = o1 + s1
            );
        }
    }

    Ok(())
}

/// Parse every compressed second-level page in __unwind_info and
/// check: (a) every entry's encoding index is resolvable (within
/// commonEncodingsCount + page encodingsCount), (b) the 24-bit
/// funcOffset fits (last function's address < page_first_fn + 16 MB).
/// Violations cause the unwinder to read wrong encodings for some
/// frame — the concrete failure mode observed as
/// "failed to initiate panic, error 5, aborting".
///
/// **Complexity:** 𝒪(u) CPU (one pass over all second-level page entries); 𝒪(1) memory.
fn validate_unwind_info(buf: &[u8]) -> Result {
    use object::read::macho::MachHeader as _;
    use object::read::macho::Section as _;
    use object::read::macho::Segment as _;
    let le = object::Endianness::Little;
    let header = match object::macho::MachHeader64::<object::Endianness>::parse(buf, 0) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };

    // Find __TEXT,__unwind_info.
    let mut ui: Option<(u64, u64)> = None; // (file_off, size)
    let mut cmds = header
        .load_commands(le, buf, 0)
        .map_err(|e| crate::error!("validate: bad load commands: {e}"))?;
    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((seg, seg_data))) = cmd.segment_64() {
            if crate::macho::trim_nul(&seg.segname) != b"__TEXT" {
                continue;
            }
            if let Ok(sections) = seg.sections(le, seg_data) {
                for sec in sections {
                    if crate::macho::trim_nul(sec.sectname()) == b"__unwind_info" {
                        ui = Some((sec.offset(le) as u64, sec.size(le)));
                        break;
                    }
                }
            }
        }
    }
    let Some((ui_off, ui_size)) = ui else {
        return Ok(());
    };
    if ui_size < 28 {
        return Ok(());
    }
    let ui_off = ui_off as usize;
    let ui_size = ui_size as usize;
    let ui_buf = &buf[ui_off..ui_off + ui_size];

    let common_count = u32::from_le_bytes(ui_buf[8..12].try_into().unwrap());
    let idx_off = u32::from_le_bytes(ui_buf[20..24].try_into().unwrap()) as usize;
    let idx_count = u32::from_le_bytes(ui_buf[24..28].try_into().unwrap()) as usize;
    if idx_count < 2 {
        return Ok(());
    }

    const UNWIND_OFFSET_MASK: u32 = 0x00FF_FFFF;
    for page in 0..idx_count - 1 {
        let ie = idx_off + page * 12;
        if ie + 12 > ui_size {
            break;
        }
        let first_fn_off = u32::from_le_bytes(ui_buf[ie..ie + 4].try_into().unwrap());
        let page_off = u32::from_le_bytes(ui_buf[ie + 4..ie + 8].try_into().unwrap()) as usize;
        if page_off == 0 || page_off + 12 > ui_size {
            continue;
        }
        let kind = u32::from_le_bytes(ui_buf[page_off..page_off + 4].try_into().unwrap());
        if kind != 3 {
            continue; // skip regular / sentinel
        }
        let entry_page_off =
            u16::from_le_bytes(ui_buf[page_off + 4..page_off + 6].try_into().unwrap()) as usize;
        let entry_count =
            u16::from_le_bytes(ui_buf[page_off + 6..page_off + 8].try_into().unwrap()) as usize;
        let encodings_page_off =
            u16::from_le_bytes(ui_buf[page_off + 8..page_off + 10].try_into().unwrap()) as usize;
        let encodings_count =
            u16::from_le_bytes(ui_buf[page_off + 10..page_off + 12].try_into().unwrap()) as usize;
        let total_encodings = common_count as usize + encodings_count;

        // Also check next page's first_fn_off for the 24-bit span
        // invariant within this page.
        let next_first_fn = if page + 1 < idx_count {
            let nie = idx_off + (page + 1) * 12;
            u32::from_le_bytes(ui_buf[nie..nie + 4].try_into().unwrap())
        } else {
            u32::MAX
        };
        let max_span = next_first_fn.saturating_sub(first_fn_off);

        for j in 0..entry_count {
            let eo = page_off + entry_page_off + j * 4;
            if eo + 4 > ui_size {
                break;
            }
            let entry = u32::from_le_bytes(ui_buf[eo..eo + 4].try_into().unwrap());
            let fn_off = entry & UNWIND_OFFSET_MASK;
            let enc_idx = (entry >> 24) as usize;
            if enc_idx >= total_encodings {
                crate::bail!(
                    "validate: __unwind_info page {page} entry {j}: enc_idx={enc_idx} \
                     >= common({common}) + page_encodings({enc_count})",
                    common = common_count,
                    enc_count = encodings_count
                );
            }
            if fn_off >= max_span {
                crate::bail!(
                    "validate: __unwind_info page {page} entry {j}: funcOffset {fn_off:#x} \
                     exceeds page span {max_span:#x} (first_fn={first_fn_off:#x}, \
                     next_first_fn={next_first_fn:#x})"
                );
            }
        }
    }

    Ok(())
}

/// When `-ld64_compat` splits the merged DATA into __DATA_CONST +
/// __DATA, every const section (GOT, INIT_ARRAY, FINI_ARRAY) must fit
/// entirely inside __DATA_CONST. A size heuristic that under-sized
/// __DATA_CONST (e.g. hardcoding it to one page) leaves sections
/// spilling past the segment end, and dyld aborts with "section __got
/// end address is beyond containing segment's end".
///
/// **Complexity:** 𝒪(L·s) CPU (two load-command walks + section scan); 𝒪(1) memory.
fn validate_compat_datasplit(buf: &[u8]) -> Result {
    use object::read::macho::MachHeader as _;
    use object::read::macho::Section as _;
    use object::read::macho::Segment as _;
    let le = object::Endianness::Little;
    let header = match object::macho::MachHeader64::<object::Endianness>::parse(buf, 0) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };

    let mut data_const: Option<(u64, u64)> = None;
    let mut cmds = header
        .load_commands(le, buf, 0)
        .map_err(|e| crate::error!("validate: bad load commands: {e}"))?;
    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((seg, _))) = cmd.segment_64() {
            if crate::macho::trim_nul(&seg.segname) == b"__DATA_CONST" {
                data_const = Some((seg.vmaddr.get(le), seg.vmsize.get(le)));
                break;
            }
        }
    }
    let Some((dc_start, dc_size)) = data_const else {
        return Ok(());
    };
    let dc_end = dc_start + dc_size;

    // Walk every section; any whose segname field is "__DATA_CONST"
    // must be fully contained. (The existing section-vs-segment check
    // in validate_macho_output uses the LC_SEGMENT_64 this section
    // was emitted under, which matches segname — but the split case
    // emits sections under a *different* segment name override, so
    // this check is worth doing by segname field directly.)
    let mut cmds = header
        .load_commands(le, buf, 0)
        .map_err(|e| crate::error!("validate: bad load commands: {e}"))?;
    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((seg, seg_data))) = cmd.segment_64() {
            if let Ok(sections) = seg.sections(le, seg_data) {
                for sec in sections {
                    let sec_segname = crate::macho::trim_nul(&sec.segname);
                    if sec_segname != b"__DATA_CONST" {
                        continue;
                    }
                    let addr = sec.addr(le);
                    let size = sec.size(le);
                    if size == 0 {
                        continue;
                    }
                    if addr < dc_start || addr + size > dc_end {
                        let sn = String::from_utf8_lossy(crate::macho::trim_nul(sec.sectname()));
                        crate::bail!(
                            "validate: section __DATA_CONST,{sn} addr {addr:#x}+{size:#x} \
                             escapes __DATA_CONST segment [{dc_start:#x}..{dc_end:#x})"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Parse `__eh_frame` with gimli and cross-check every CIE/FDE
/// against the output's segment layout and `__unwind_info`'s
/// DWARF-mode entries.
///
/// Checks:
///   1. Every CIE is parseable (augstr, code_align, data_align, ra_reg).
///   2. Every FDE's `cie_ptr` resolves to a CIE.
///   3. FDE PC range (`pc_begin`..`+pc_range`) sits inside __TEXT.
///   4. LSDA pointer (L aug) is inside `__gcc_except_tab` or zero.
///   5. Personality pointer (P aug) is inside `__got` or __TEXT.
///   6. CFI instructions are walkable without unknown opcodes.
///   7. Cross-check: every DWARF-mode entry in `__unwind_info` references an FDE whose `pc_begin`
///      matches the compact- unwind func offset.
///
/// **Complexity:** 𝒪(f·|aug|) CPU (gimli parse of every CIE/FDE plus CFI walk);
/// 𝒪(f) memory for the FDE-by-offset map.
fn validate_eh_frame_consistency(buf: &[u8]) -> Result {
    use gimli::UnwindSection as _;
    use object::read::macho::MachHeader as _;
    use object::read::macho::Section as _;
    use object::read::macho::Segment as _;
    let le = object::Endianness::Little;
    let header = match object::macho::MachHeader64::<object::Endianness>::parse(buf, 0) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };

    let mut eh_frame: Option<(u64, u64, u64)> = None;
    let mut except_tab: Option<(u64, u64)> = None;
    let mut got: Option<(u64, u64)> = None;
    let mut text_seg: Option<(u64, u64)> = None;
    let mut cmds = header
        .load_commands(le, buf, 0)
        .map_err(|e| crate::error!("validate: bad load commands: {e}"))?;
    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((seg, seg_data))) = cmd.segment_64() {
            let segname = crate::macho::trim_nul(&seg.segname);
            if segname == b"__TEXT" {
                text_seg = Some((seg.vmaddr.get(le), seg.vmsize.get(le)));
            }
            if let Ok(sections) = seg.sections(le, seg_data) {
                for sec in sections {
                    let sn = crate::macho::trim_nul(sec.sectname());
                    match sn {
                        b"__eh_frame" => {
                            eh_frame = Some((sec.addr(le), sec.offset(le) as u64, sec.size(le)));
                        }
                        b"__gcc_except_tab" => {
                            except_tab = Some((sec.addr(le), sec.size(le)));
                        }
                        b"__got" => {
                            got = Some((sec.addr(le), sec.size(le)));
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    let Some((ef_vm, ef_foff, ef_size)) = eh_frame else {
        return Ok(());
    };
    if ef_size == 0 {
        return Ok(());
    }
    let ef_foff = ef_foff as usize;
    if ef_foff + ef_size as usize > buf.len() {
        return Ok(());
    }
    let ef_data = &buf[ef_foff..ef_foff + ef_size as usize];
    let (text_vm, text_vmsize) = text_seg.unwrap_or((0, u64::MAX));

    type R<'a> = gimli::EndianSlice<'a, gimli::LittleEndian>;
    let section: gimli::EhFrame<R<'_>> = gimli::EhFrame::new(ef_data, gimli::LittleEndian);
    let bases = gimli::BaseAddresses::default().set_eh_frame(ef_vm);

    let mut fde_by_offset: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
    let mut ctx = gimli::UnwindContext::new();

    let mut entries_iter = section.entries(&bases);
    while let Ok(Some(entry)) = entries_iter.next() {
        match entry {
            gimli::CieOrFde::Cie(_cie) => {
                // Check 1: CIE parseable. gimli validated augmentation
                // during parse — reaching here means the CIE is
                // structurally sound (augstr, code_align, data_align,
                // return-address register all decoded without error).
            }
            gimli::CieOrFde::Fde(partial) => {
                let fde_section_offset = partial.offset() as usize;
                // Check 2: FDE references a valid CIE.
                let fde = match partial.parse(|_, _, off| section.cie_from_offset(&bases, off)) {
                    Ok(f) => f,
                    Err(e) => {
                        crate::bail!(
                            "validate: __eh_frame FDE at {fde_section_offset:#x}: \
                                 CIE lookup failed: {e}"
                        );
                    }
                };

                let pc_begin = fde.initial_address();
                let pc_range = fde.len();

                // Check 3: PC range inside __TEXT.
                if pc_range > 0
                    && (pc_begin < text_vm || pc_begin + pc_range > text_vm + text_vmsize)
                {
                    crate::bail!(
                        "validate: __eh_frame FDE at {fde_section_offset:#x}: PC range \
                         [{pc_begin:#x}..{end:#x}) outside __TEXT [{text_vm:#x}..{text_end:#x})",
                        end = pc_begin + pc_range,
                        text_end = text_vm + text_vmsize
                    );
                }

                // Check 4: LSDA inside __gcc_except_tab.
                if let Some(gimli::Pointer::Direct(lsda)) = fde.lsda() {
                    if lsda != 0 {
                        if let Some((et_vm, et_size)) = except_tab {
                            if lsda < et_vm || lsda >= et_vm + et_size {
                                let signed_distance = lsda as i64 - et_vm as i64;
                                crate::bail!(
                                    "validate: __eh_frame FDE at {fde_section_offset:#x}: \
                                     LSDA {lsda:#x} outside __gcc_except_tab \
                                     [{et_vm:#x}..{end:#x}) (off by {signed_distance})",
                                    end = et_vm + et_size
                                );
                            }
                        }
                    }
                }

                // Check 5: Personality inside __got or __TEXT.
                if let Some((_, gimli::Pointer::Direct(pers)))
                | Some((_, gimli::Pointer::Indirect(pers))) =
                    fde.cie().personality_with_encoding()
                {
                    if pers != 0 {
                        let in_got = got.map_or(false, |(gv, gs)| pers >= gv && pers < gv + gs);
                        let in_text = pers >= text_vm && pers < text_vm + text_vmsize;
                        if !in_got && !in_text {
                            crate::bail!(
                                "validate: __eh_frame CIE personality {pers:#x} not in \
                                 __got or __TEXT"
                            );
                        }
                    }
                }

                // Check 6: CFI instructions walkable.
                {
                    let mut table = gimli::UnwindTable::new(&section, &bases, &mut ctx, &fde)
                        .map_err(|e| {
                            crate::error!(
                                "validate: __eh_frame FDE at {fde_section_offset:#x}: \
                                 UnwindTable init error: {e}"
                            )
                        })?;
                    loop {
                        match table.next_row() {
                            Ok(None) => break,
                            Ok(Some(_)) => {}
                            Err(e) => {
                                crate::bail!(
                                    "validate: __eh_frame FDE at {fde_section_offset:#x}: \
                                     CFI walk error: {e}"
                                );
                            }
                        }
                    }
                }

                fde_by_offset.insert(fde_section_offset, pc_begin);
            }
        }
    }

    // Check 7: cross-check __unwind_info DWARF-mode entries.
    validate_unwind_fde_xref(buf, ef_vm, ef_size, text_vm, &fde_by_offset)?;

    Ok(())
}

/// Cross-check every DWARF-mode entry in `__unwind_info` against the FDE map built
/// from `__eh_frame`, ensuring each referenced FDE's `pc_begin` matches the compact-
/// unwind function offset.
///
/// **Complexity:** 𝒪(u·log u) CPU (parse unwind_info pages + map lookup per entry);
/// 𝒪(1) extra memory (reads `fde_by_offset` in-place).
fn validate_unwind_fde_xref(
    buf: &[u8],
    ef_vm: u64,
    ef_size: u64,
    text_base: u64,
    fde_by_offset: &std::collections::HashMap<usize, u64>,
) -> Result {
    use object::read::macho::MachHeader as _;
    use object::read::macho::Section as _;
    use object::read::macho::Segment as _;
    let le = object::Endianness::Little;
    let header = match object::macho::MachHeader64::<object::Endianness>::parse(buf, 0) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };

    let mut ui_bounds: Option<(usize, usize)> = None;
    let mut cmds = header
        .load_commands(le, buf, 0)
        .map_err(|e| crate::error!("validate: bad load commands: {e}"))?;
    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((seg, seg_data))) = cmd.segment_64() {
            if crate::macho::trim_nul(&seg.segname) == b"__TEXT" {
                if let Ok(sections) = seg.sections(le, seg_data) {
                    for sec in sections {
                        if crate::macho::trim_nul(sec.sectname()) == b"__unwind_info" {
                            ui_bounds = Some((sec.offset(le) as usize, sec.size(le) as usize));
                        }
                    }
                }
            }
        }
    }
    let Some((ui_off, ui_size)) = ui_bounds else {
        return Ok(());
    };
    if ui_size < 28 || ui_off + ui_size > buf.len() {
        return Ok(());
    }
    let ui = &buf[ui_off..ui_off + ui_size];
    let common_count = u32::from_le_bytes(ui[8..12].try_into().unwrap()) as usize;
    let idx_off = u32::from_le_bytes(ui[20..24].try_into().unwrap()) as usize;
    let idx_count = u32::from_le_bytes(ui[24..28].try_into().unwrap()) as usize;
    if idx_count < 2 {
        return Ok(());
    }

    const UNWIND_ARM64_DWARF: u32 = 0x0300_0000;
    const UNWIND_MODE_MASK: u32 = 0x0F00_0000;
    const UNWIND_OFFSET_MASK: u32 = 0x00FF_FFFF;

    for page in 0..idx_count - 1 {
        let ie = idx_off + page * 12;
        if ie + 12 > ui_size {
            break;
        }
        let first_fn_off = u32::from_le_bytes(ui[ie..ie + 4].try_into().unwrap());
        let page_off = u32::from_le_bytes(ui[ie + 4..ie + 8].try_into().unwrap()) as usize;
        if page_off == 0 || page_off + 12 > ui_size {
            continue;
        }
        let kind = u32::from_le_bytes(ui[page_off..page_off + 4].try_into().unwrap());
        if kind != 3 {
            continue;
        }
        let entry_page_off =
            u16::from_le_bytes(ui[page_off + 4..page_off + 6].try_into().unwrap()) as usize;
        let entry_count =
            u16::from_le_bytes(ui[page_off + 6..page_off + 8].try_into().unwrap()) as usize;
        let enc_page_off =
            u16::from_le_bytes(ui[page_off + 8..page_off + 10].try_into().unwrap()) as usize;

        for j in 0..entry_count {
            let eo = page_off + entry_page_off + j * 4;
            if eo + 4 > ui_size {
                break;
            }
            let entry = u32::from_le_bytes(ui[eo..eo + 4].try_into().unwrap());
            let fn_off = entry & UNWIND_OFFSET_MASK;
            let enc_idx = (entry >> 24) as usize;
            let enc = if enc_idx < common_count {
                u32::from_le_bytes(
                    ui[28 + enc_idx * 4..28 + enc_idx * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            } else {
                let local_idx = enc_idx - common_count;
                let enc_off = page_off + enc_page_off + local_idx * 4;
                if enc_off + 4 > ui_size {
                    continue;
                }
                u32::from_le_bytes(ui[enc_off..enc_off + 4].try_into().unwrap())
            };
            if (enc & UNWIND_MODE_MASK) != UNWIND_ARM64_DWARF {
                continue;
            }
            let fde_off = (enc & UNWIND_OFFSET_MASK) as usize;
            if fde_off as u64 >= ef_size {
                crate::bail!(
                    "validate: __unwind_info page {page} entry {j}: DWARF FDE offset \
                     {fde_off:#x} >= __eh_frame size {ef_size:#x}"
                );
            }
            let expected_fn_vm = text_base + first_fn_off as u64 + fn_off as u64;
            if let Some(&actual_fn_vm) = fde_by_offset.get(&fde_off) {
                if actual_fn_vm != expected_fn_vm {
                    crate::bail!(
                        "validate: __unwind_info page {page} entry {j}: DWARF FDE at \
                         __eh_frame+{fde_off:#x} has pc_begin={actual_fn_vm:#x} but \
                         compact_unwind says func={expected_fn_vm:#x}"
                    );
                }
            }
        }
    }

    Ok(())
}
