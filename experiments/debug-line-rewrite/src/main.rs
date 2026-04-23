//! `.debug_line` v4 → v5 in-place rewriter (phase 2a).
//!
//! Reads an input ELF, re-emits every CU's `.debug_line` as DWARF 5
//! using `DW_FORM_string` (inline NUL-terminated paths) — no
//! cross-CU pooling yet. Patches every `DW_AT_stmt_list` attribute
//! in `.debug_info` to point at the new offset, replaces the
//! `.debug_line` section, shifts subsequent sections, and writes
//! the result.
//!
//! Goal of phase 2a: prove the rewrite is debugger-correct (verified
//! by `debugger-roundtrip compare`). Size delta is approximately
//! zero — v5 header costs a few bytes more (format descriptors,
//! address_size, segment_selector_size) but saves a few bytes per
//! file (no mtime / length fields).
//!
//! Phase 2b will switch the path encoding to `DW_FORM_line_strp`
//! and emit a `.debug_line_str` section with cross-CU dedup. Recon
//! showed ~21 MB savings on midnight-node from that step.
//!
//! Phase 3: lift into `libwild` and gate behind `-O1`.
//!
//! Usage:
//!   debug-line-rewrite <input.elf> <output.elf>

use gimli::EndianSlice;
use gimli::LittleEndian;
use object::Object;
use object::ObjectSection;
use object::elf::FileHeader64;
use object::elf::SectionHeader64;
use object::read::elf::FileHeader;
use object::read::elf::SectionHeader;
use std::env;
use std::fs;
use std::process::ExitCode;

type Slice<'a> = EndianSlice<'a, LittleEndian>;

const ENDIAN: object::Endianness = object::Endianness::Little;

/// Per-CU info captured during the read pass; consumed by the emit
/// pass.
struct CuLineInfo {
    /// Absolute byte offset of the `DW_AT_stmt_list` attribute's
    /// 4-byte value in `.debug_info`. We patch this at the end with
    /// the new line-program offset.
    stmt_list_byte_pos_in_debug_info: u64,
    /// Old `.debug_line` offset where this CU's line program lived.
    /// Used to find the v4 program bytes and to print before/after.
    old_line_offset: u32,
    /// New `.debug_line` offset assigned during emit.
    new_line_offset: u32,
    /// v4 fixed header fields (preserved verbatim into v5).
    min_inst_length: u8,
    max_ops_per_inst: u8,
    default_is_stmt: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
    std_opcode_lengths: Vec<u8>,
    /// Include directories from the v4 header (NUL-stripped).
    include_directories: Vec<Vec<u8>>,
    /// File entries from the v4 header. Tuple is (path, dir_index).
    /// mtime and length are dropped — rustc emits them as 0 and the
    /// v5 format we're targeting doesn't include them.
    file_entries: Vec<(Vec<u8>, u64)>,
    /// Path of the CU's primary source file (from `DW_AT_name`).
    /// Becomes file index 0 in the v5 table.
    primary_file_name: Vec<u8>,
    /// Comp-dir of the CU (from `DW_AT_comp_dir`). Becomes
    /// directory index 0 in the v5 table.
    comp_dir: Vec<u8>,
    /// Raw bytes of the line-program opcodes (everything after the
    /// v4 prologue). Copied verbatim into v5 — opcode encoding is
    /// identical between v4 and v5.
    program_bytes: Vec<u8>,
}

fn read_cus(elf: &[u8]) -> Result<Vec<CuLineInfo>, String> {
    let obj = object::File::parse(elf).map_err(|e| format!("parse: {e}"))?;

    let load = |id: gimli::SectionId| -> Result<Slice<'_>, String> {
        let data = obj
            .section_by_name(id.name())
            .map(|s| s.data().unwrap_or(&[]))
            .unwrap_or(&[]);
        Ok(EndianSlice::new(data, LittleEndian))
    };
    let dwarf = gimli::Dwarf::load(load).map_err(|e| format!("dwarf load: {e}"))?;

    // Find .debug_info file offset so we can convert in-CU offsets to
    // absolute byte positions for the patch step.
    let debug_info_section_offset = obj
        .section_by_name(".debug_info")
        .ok_or("no .debug_info")?
        .file_range()
        .ok_or("no .debug_info file range")?
        .0;
    let debug_line_bytes = obj
        .section_by_name(".debug_line")
        .map(|s| s.data().unwrap_or(&[]))
        .unwrap_or(&[]);

    let mut cus = Vec::new();
    let mut units = dwarf.units();
    while let Some(unit_header) = units.next().map_err(|e| format!("units: {e}"))? {
        let cu_offset_in_debug_info = match unit_header.offset() {
            gimli::UnitSectionOffset::DebugInfoOffset(o) => o.0 as u64,
            _ => continue,
        };
        let unit = dwarf
            .unit(unit_header)
            .map_err(|e| format!("unit @ {cu_offset_in_debug_info}: {e}"))?;
        let Some(line_program) = unit.line_program.clone() else {
            continue;
        };
        let lp_header = line_program.header();
        let line_offset = match lp_header.offset() {
            gimli::DebugLineOffset(o) => o as u32,
        };

        // Locate the byte position of DW_AT_stmt_list in .debug_info.
        // We use entries_raw to get byte-precise positions.
        let mut entries = unit
            .entries_raw(None)
            .map_err(|e| format!("entries_raw: {e}"))?;
        let abbrev = entries
            .read_abbreviation()
            .map_err(|e| format!("read_abbreviation: {e}"))?
            .ok_or("first DIE has no abbrev")?;
        let mut stmt_list_byte_pos: Option<u64> = None;
        for spec in abbrev.attributes() {
            // Position before reading this attribute's bytes is the
            // attribute value's start. Convert to absolute offset.
            let pos_in_unit: gimli::UnitOffset = entries.next_offset();
            let pos_in_debug_info = pos_in_unit.0 as u64 + cu_offset_in_debug_info;
            let attr = entries
                .read_attribute(*spec)
                .map_err(|e| format!("read_attribute: {e}"))?;
            if attr.name() == gimli::constants::DW_AT_stmt_list {
                stmt_list_byte_pos = Some(pos_in_debug_info);
            }
        }
        let stmt_list_byte_pos =
            stmt_list_byte_pos.ok_or("compile_unit DIE has no DW_AT_stmt_list")?;

        // Pull primary source file + comp_dir from the unit.
        let primary_file_name = unit
            .name
            .as_ref()
            .map(|s| s.slice().to_vec())
            .unwrap_or_default();
        let comp_dir = unit
            .comp_dir
            .as_ref()
            .map(|s| s.slice().to_vec())
            .unwrap_or_default();

        // Read v4 line-program header fields.
        let opcode_base = lp_header.opcode_base();
        let std_opcode_lengths = lp_header.standard_opcode_lengths().slice().to_vec();
        let min_inst_length = lp_header.minimum_instruction_length();
        let max_ops_per_inst = lp_header.maximum_operations_per_instruction();
        let default_is_stmt: u8 = if lp_header.default_is_stmt() { 1 } else { 0 };
        let line_base = lp_header.line_base();
        let line_range = lp_header.line_range();

        let mut include_directories = Vec::new();
        for dir in lp_header.include_directories() {
            let bytes = dir
                .string_value(&dwarf.debug_str)
                .ok_or("dir string_value")?
                .slice()
                .to_vec();
            include_directories.push(bytes);
        }
        let mut file_entries = Vec::new();
        for file in lp_header.file_names() {
            let path = file
                .path_name()
                .string_value(&dwarf.debug_str)
                .ok_or("file string_value")?
                .slice()
                .to_vec();
            let dir_index = file.directory_index();
            file_entries.push((path, dir_index));
        }

        // Extract program bytes by computing prologue length and
        // copying everything after.
        let unit_length_field_bytes = 4u32;
        let prologue_len: u32 = unit_length_field_bytes
            + 2 // version
            + 4 // header_length field itself
            + lp_header.header_length() as u32;
        let unit_total_bytes = (lp_header.unit_length() as u32) + unit_length_field_bytes;
        let program_start = (line_offset + prologue_len) as usize;
        let program_end = (line_offset + unit_total_bytes) as usize;
        if program_end > debug_line_bytes.len() {
            return Err(format!(
                "CU @ {cu_offset_in_debug_info}: program_end {program_end} exceeds .debug_line {}",
                debug_line_bytes.len()
            ));
        }
        let program_bytes = debug_line_bytes[program_start..program_end].to_vec();

        cus.push(CuLineInfo {
            stmt_list_byte_pos_in_debug_info: stmt_list_byte_pos,
            old_line_offset: line_offset,
            new_line_offset: 0, // filled in pass 2
            min_inst_length,
            max_ops_per_inst,
            default_is_stmt,
            line_base,
            line_range,
            opcode_base,
            std_opcode_lengths,
            include_directories,
            file_entries,
            primary_file_name,
            comp_dir,
            program_bytes,
        });
    }
    let _ = debug_info_section_offset;
    Ok(cus)
}

/// LEB128 unsigned write.
fn write_uleb(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Cross-CU pool of unique path strings, emitted as the
/// `.debug_line_str` section. Each path becomes a 4-byte offset
/// referenced from CUs via `DW_FORM_line_strp`.
#[derive(Default)]
struct LineStrPool {
    bytes: Vec<u8>,
    offsets: std::collections::HashMap<Vec<u8>, u32>,
}

impl LineStrPool {
    fn intern(&mut self, s: &[u8]) -> u32 {
        if let Some(&off) = self.offsets.get(s) {
            return off;
        }
        let off = self.bytes.len() as u32;
        self.bytes.extend_from_slice(s);
        self.bytes.push(0);
        self.offsets.insert(s.to_vec(), off);
        off
    }
}

/// Emit one CU's v5 line program using `DW_FORM_line_strp` for paths
/// — phase 2b shape. Each path is a 4-byte offset into the shared
/// `.debug_line_str` pool. Phase 2a's `DW_FORM_string` variant
/// remains via [`emit_v5_line_program_inline`] for reference but is
/// no longer the primary path.
fn emit_v5_line_program_pooled(out: &mut Vec<u8>, cu: &CuLineInfo, pool: &mut LineStrPool) {
    let start = out.len();
    out.extend_from_slice(&[0u8; 4]); // unit_length placeholder (32-bit)
    out.extend_from_slice(&5u16.to_le_bytes()); // version
    out.push(8); // address_size (x86_64 / aarch64)
    out.push(0); // segment_selector_size
    out.extend_from_slice(&[0u8; 4]); // header_length placeholder
    let header_len_pos = start + 4 + 2 + 1 + 1;

    let after_header_length = out.len();

    out.push(cu.min_inst_length);
    out.push(cu.max_ops_per_inst);
    out.push(cu.default_is_stmt);
    out.push(cu.line_base as u8);
    out.push(cu.line_range);
    out.push(cu.opcode_base);
    out.extend_from_slice(&cu.std_opcode_lengths);

    // directory_entries: format = (DW_LNCT_path, DW_FORM_line_strp).
    out.push(1);
    write_uleb(out, gimli::constants::DW_LNCT_path.0 as u64);
    write_uleb(out, gimli::constants::DW_FORM_line_strp.0 as u64);
    write_uleb(out, 1 + cu.include_directories.len() as u64);
    let comp_dir_off = pool.intern(&cu.comp_dir);
    out.extend_from_slice(&comp_dir_off.to_le_bytes());
    for d in &cu.include_directories {
        let off = pool.intern(d);
        out.extend_from_slice(&off.to_le_bytes());
    }

    // file_entries: format = (DW_LNCT_path DW_FORM_line_strp,
    //                         DW_LNCT_directory_index DW_FORM_udata).
    out.push(2);
    write_uleb(out, gimli::constants::DW_LNCT_path.0 as u64);
    write_uleb(out, gimli::constants::DW_FORM_line_strp.0 as u64);
    write_uleb(out, gimli::constants::DW_LNCT_directory_index.0 as u64);
    write_uleb(out, gimli::constants::DW_FORM_udata.0 as u64);
    write_uleb(out, 1 + cu.file_entries.len() as u64);
    let primary_off = pool.intern(&cu.primary_file_name);
    out.extend_from_slice(&primary_off.to_le_bytes());
    write_uleb(out, 0); // primary's dir_index = 0 (= comp_dir)
    for (path, dir_idx) in &cu.file_entries {
        let off = pool.intern(path);
        out.extend_from_slice(&off.to_le_bytes());
        write_uleb(out, *dir_idx);
    }

    let header_length = (out.len() - after_header_length) as u32;
    out[header_len_pos..header_len_pos + 4].copy_from_slice(&header_length.to_le_bytes());

    out.extend_from_slice(&cu.program_bytes);

    let unit_length = (out.len() - start - 4) as u32;
    out[start..start + 4].copy_from_slice(&unit_length.to_le_bytes());
}

/// Phase-2a variant: same shape but uses `DW_FORM_string` (inline
/// NUL-terminated paths) so no `.debug_line_str` section is needed.
/// Kept for reference / debugging.
#[allow(dead_code)]
fn emit_v5_line_program(out: &mut Vec<u8>, cu: &CuLineInfo) {
    let start = out.len();
    out.extend_from_slice(&[0u8; 4]); // unit_length placeholder (32-bit)
    out.extend_from_slice(&5u16.to_le_bytes()); // version
    out.push(8); // address_size (x86_64 / aarch64)
    out.push(0); // segment_selector_size
    out.extend_from_slice(&[0u8; 4]); // header_length placeholder
    let header_len_pos = start + 4 + 2 + 1 + 1; // start of header_length field

    let after_header_length = out.len();

    out.push(cu.min_inst_length);
    out.push(cu.max_ops_per_inst);
    out.push(cu.default_is_stmt);
    out.push(cu.line_base as u8);
    out.push(cu.line_range);
    out.push(cu.opcode_base);
    // standard_opcode_lengths is `opcode_base - 1` bytes.
    out.extend_from_slice(&cu.std_opcode_lengths);

    // directory_entries: format = (DW_LNCT_path, DW_FORM_string).
    out.push(1); // directory_entry_format_count
    write_uleb(out, gimli::constants::DW_LNCT_path.0 as u64);
    write_uleb(out, gimli::constants::DW_FORM_string.0 as u64);
    // directories_count: comp_dir at index 0 + the v4 include_dirs.
    write_uleb(out, 1 + cu.include_directories.len() as u64);
    // Index 0 = comp_dir.
    out.extend_from_slice(&cu.comp_dir);
    out.push(0);
    // Indexes 1..N = original include_directories.
    for d in &cu.include_directories {
        out.extend_from_slice(d);
        out.push(0);
    }

    // file_entries: format = (DW_LNCT_path DW_FORM_string,
    //                         DW_LNCT_directory_index DW_FORM_udata).
    out.push(2); // file_name_entry_format_count
    write_uleb(out, gimli::constants::DW_LNCT_path.0 as u64);
    write_uleb(out, gimli::constants::DW_FORM_string.0 as u64);
    write_uleb(out, gimli::constants::DW_LNCT_directory_index.0 as u64);
    write_uleb(out, gimli::constants::DW_FORM_udata.0 as u64);
    // file_names_count: primary at index 0 + v4 file_entries.
    write_uleb(out, 1 + cu.file_entries.len() as u64);
    // Index 0 = primary source.
    out.extend_from_slice(&cu.primary_file_name);
    out.push(0);
    write_uleb(out, 0); // dir_index 0 (= comp_dir)
    // Indexes 1..N = v4 entries (preserve numbering so DW_LNS_set_file
    // operands in the program don't need rewriting).
    for (path, dir_idx) in &cu.file_entries {
        out.extend_from_slice(path);
        out.push(0);
        write_uleb(out, *dir_idx);
    }

    // Patch header_length: distance from end-of-header_length field
    // (= after_header_length) to current position (start of program).
    let header_length = (out.len() - after_header_length) as u32;
    out[header_len_pos..header_len_pos + 4].copy_from_slice(&header_length.to_le_bytes());

    // Append the line opcodes verbatim.
    out.extend_from_slice(&cu.program_bytes);

    // Patch unit_length: total_bytes - 4 (the length field itself).
    let unit_length = (out.len() - start - 4) as u32;
    out[start..start + 4].copy_from_slice(&unit_length.to_le_bytes());
}

fn rewrite_elf(elf: &[u8]) -> Result<Vec<u8>, String> {
    let cus = read_cus(elf)?;
    if cus.is_empty() {
        return Err("no CUs with line programs".into());
    }

    // Pass 2: emit new .debug_line bytes + populate .debug_line_str pool.
    let mut new_debug_line = Vec::new();
    let mut pool = LineStrPool::default();
    let mut cu_offsets: Vec<(u64, u32, u32)> = Vec::with_capacity(cus.len());
    let mut owned_cus = cus;
    for cu in owned_cus.iter_mut() {
        let new_off = new_debug_line.len() as u32;
        cu.new_line_offset = new_off;
        emit_v5_line_program_pooled(&mut new_debug_line, cu, &mut pool);
        cu_offsets.push((cu.stmt_list_byte_pos_in_debug_info, cu.old_line_offset, new_off));
    }
    let new_debug_line_str = pool.bytes;
    eprintln!(
        ".debug_line_str pool: {} bytes ({} unique paths)",
        new_debug_line_str.len(),
        pool.offsets.len()
    );

    let new_debug_line_size = new_debug_line.len();
    let new_debug_line_str_size = new_debug_line_str.len();
    let old_debug_line_size = {
        let obj = object::File::parse(elf).map_err(|e| format!("parse: {e}"))?;
        obj.section_by_name(".debug_line")
            .ok_or("no .debug_line")?
            .size() as usize
    };
    eprintln!(
        ".debug_line:     {old_debug_line_size} → {new_debug_line_size} bytes \
         ({:+.2}%)",
        100.0 * (new_debug_line_size as f64 - old_debug_line_size as f64)
            / old_debug_line_size as f64
    );
    eprintln!(".debug_line_str: 0 → {new_debug_line_str_size} bytes (new section)");
    eprintln!(
        "combined:        {old_debug_line_size} → {} bytes ({:+.2}%)",
        new_debug_line_size + new_debug_line_str_size,
        100.0
            * ((new_debug_line_size + new_debug_line_str_size) as f64
                - old_debug_line_size as f64)
            / old_debug_line_size as f64
    );

    // Build new ELF. Changes vs input:
    //   (a) .debug_info — patch each CU's DW_AT_stmt_list value to
    //       its new offset.
    //   (b) .debug_line — replace contents with new_debug_line.
    //   (c) NEW .debug_line_str section — placed in the file
    //       immediately after .debug_line. SHDR table grows by 1
    //       entry; .shstrtab grows by ".debug_line_str\0" (16 bytes).
    //   (d) Sections originally after .debug_line shift forward by
    //       (new_debug_line_size - old_debug_line_size + new_debug_line_str_size).
    //   (e) Sections after .shstrtab shift further by 16 bytes.
    //   (f) SHDR table moves to the end (with one extra entry for
    //       the new section); ehdr.e_shoff + e_shnum updated.
    let data = elf.to_vec();
    let endian = ENDIAN;

    let (
        debug_info_offset,
        debug_line_idx,
        debug_line_offset,
        shstrtab_idx,
        shstrtab_offset,
        shstrtab_old_size,
        e_shoff,
        e_shentsize,
        e_shnum,
    ) = {
        let header = FileHeader64::<object::Endianness>::parse(&*data)
            .map_err(|e| format!("ehdr parse: {e:?}"))?;
        let sections = header
            .sections(endian, &*data)
            .map_err(|e| format!("sections parse: {e:?}"))?;
        let mut debug_info_offset = 0u64;
        let mut debug_line_idx = 0usize;
        let mut debug_line_offset = 0u64;
        let mut shstrtab_idx = 0usize;
        let mut shstrtab_offset = 0u64;
        let mut shstrtab_old_size = 0u64;
        let e_shstrndx = header.e_shstrndx(endian) as usize;
        for (idx, sect) in sections.iter().enumerate() {
            let name = sections
                .section_name(endian, sect)
                .map_err(|e| format!("section_name {idx}: {e:?}"))?;
            if name == b".debug_info" {
                debug_info_offset = sect.sh_offset(endian);
            } else if name == b".debug_line" {
                debug_line_idx = idx;
                debug_line_offset = sect.sh_offset(endian);
            }
            if idx == e_shstrndx {
                shstrtab_idx = idx;
                shstrtab_offset = sect.sh_offset(endian);
                shstrtab_old_size = sect.sh_size(endian);
            }
        }
        if debug_info_offset == 0 {
            return Err(".debug_info not found".into());
        }
        if debug_line_offset == 0 {
            return Err(".debug_line not found".into());
        }
        (
            debug_info_offset,
            debug_line_idx,
            debug_line_offset,
            shstrtab_idx,
            shstrtab_offset,
            shstrtab_old_size,
            header.e_shoff(endian) as usize,
            header.e_shentsize(endian) as usize,
            header.e_shnum(endian) as usize,
        )
    };

    // (a) Patch .debug_info DW_AT_stmt_list values in place — all
    //     edits are within a single byte range, no offset shift yet.
    let mut data = data;
    for &(stmt_list_pos_in_di, _old, new_off) in &cu_offsets {
        let abs = (debug_info_offset + stmt_list_pos_in_di) as usize;
        if abs + 4 > data.len() {
            return Err(format!("stmt_list patch out of bounds @ {abs}"));
        }
        data[abs..abs + 4].copy_from_slice(&new_off.to_le_bytes());
    }

    // Compute deltas:
    //   debug_line_delta: change in .debug_line size.
    //   line_str_size:    bytes added immediately after .debug_line.
    //   total_section_delta: combined growth of the body region from
    //     start of .debug_line to start of .shstrtab.
    //   shstrtab_growth: 16 bytes for ".debug_line_str\0".
    let debug_line_delta: isize =
        new_debug_line_size as isize - old_debug_line_size as isize;
    let line_str_size = new_debug_line_str_size as isize;
    let body_delta_at_debug_line = debug_line_delta + line_str_size;
    let new_section_name = b".debug_line_str\0";
    let shstrtab_growth = new_section_name.len() as isize;

    let debug_line_end = debug_line_offset as usize + old_debug_line_size;

    // Compose new file. We rebuild from scratch by section ordering:
    //
    //   [0 .. debug_line_offset)                  — bytes before .debug_line
    //   [new_debug_line]                          — replaced section
    //   [new_debug_line_str]                      — NEW section
    //   [middle: debug_line_end .. shstrtab_off)  — sections after debug_line, before shstrtab
    //   [new shstrtab = old shstrtab + name]      — extended shstrtab
    //   [tail after shstrtab .. e_shoff)          — non-shdr stuff (rare)
    //   [new SHDR table with N+1 entries]         — relocated to the end
    //
    // Anything originally in the file after the SHDR table is dropped
    // (e_shoff is normally near end of file, nothing else after).
    let shstrtab_end = shstrtab_offset as usize + shstrtab_old_size as usize;
    if shstrtab_end > e_shoff {
        return Err(format!(
            "unexpected layout: shstrtab_end {shstrtab_end} > e_shoff {e_shoff}"
        ));
    }

    let mut new_data = Vec::with_capacity(
        data.len()
            + body_delta_at_debug_line.max(0) as usize
            + shstrtab_growth.max(0) as usize
            + e_shentsize,
    );
    new_data.extend_from_slice(&data[..debug_line_offset as usize]);
    let new_debug_line_offset = new_data.len();
    new_data.extend_from_slice(&new_debug_line);
    let new_line_str_offset = new_data.len();
    new_data.extend_from_slice(&new_debug_line_str);
    // Middle bytes (between old debug_line_end and shstrtab_offset).
    new_data.extend_from_slice(&data[debug_line_end..shstrtab_offset as usize]);
    let new_shstrtab_offset = new_data.len();
    // Extended shstrtab.
    let new_section_name_offset_in_shstrtab = shstrtab_old_size as u32;
    new_data.extend_from_slice(&data[shstrtab_offset as usize..shstrtab_end]);
    new_data.extend_from_slice(new_section_name);
    let new_shstrtab_size = new_data.len() - new_shstrtab_offset;
    // Anything between shstrtab and SHDR table (usually nothing).
    new_data.extend_from_slice(&data[shstrtab_end..e_shoff]);
    let new_e_shoff = new_data.len();

    // SHDR table: N+1 entries. Build from scratch by reading each
    // existing entry, optionally adjusting, then appending a new one.
    let new_e_shnum = e_shnum + 1;
    new_data.resize(new_e_shoff + new_e_shnum * e_shentsize, 0);
    for i in 0..e_shnum {
        let src = e_shoff + i * e_shentsize;
        let dst = new_e_shoff + i * e_shentsize;
        new_data[dst..dst + e_shentsize].copy_from_slice(&data[src..src + e_shentsize]);
    }
    // Walk + adjust each SHDR.
    for i in 0..e_shnum {
        let entry_off = new_e_shoff + i * e_shentsize;
        let entry_bytes = &mut new_data[entry_off..entry_off + e_shentsize];
        let entry =
            unsafe { &mut *(entry_bytes.as_mut_ptr() as *mut SectionHeader64<object::Endianness>) };
        let sh_offset = entry.sh_offset.get(endian) as usize;

        if i == debug_line_idx {
            entry.sh_size.set(endian, new_debug_line_size as u64);
            // sh_offset unchanged — it's where the new bytes also start.
        } else if i == shstrtab_idx {
            // Will be patched below to its new offset and size.
        } else if sh_offset >= debug_line_end && sh_offset < shstrtab_offset as usize {
            // Sections between .debug_line and .shstrtab shift by
            // body_delta_at_debug_line.
            let shifted = ((sh_offset as isize) + body_delta_at_debug_line) as usize;
            entry.sh_offset.set(endian, shifted as u64);
        } else if sh_offset >= shstrtab_end {
            // Any section past the shstrtab end (rare) shifts by the
            // full delta including shstrtab growth.
            let shifted = ((sh_offset as isize)
                + body_delta_at_debug_line
                + shstrtab_growth) as usize;
            entry.sh_offset.set(endian, shifted as u64);
        }
    }
    // Patch the shstrtab entry: new offset + new size.
    {
        let entry_off = new_e_shoff + shstrtab_idx * e_shentsize;
        let entry_bytes = &mut new_data[entry_off..entry_off + e_shentsize];
        let entry =
            unsafe { &mut *(entry_bytes.as_mut_ptr() as *mut SectionHeader64<object::Endianness>) };
        entry.sh_offset.set(endian, new_shstrtab_offset as u64);
        entry.sh_size.set(endian, new_shstrtab_size as u64);
    }

    // Append the new .debug_line_str SHDR entry.
    {
        let new_entry_off = new_e_shoff + e_shnum * e_shentsize;
        let entry_bytes = &mut new_data[new_entry_off..new_entry_off + e_shentsize];
        let entry =
            unsafe { &mut *(entry_bytes.as_mut_ptr() as *mut SectionHeader64<object::Endianness>) };
        // Zero by default (Vec init).
        entry
            .sh_name
            .set(endian, new_section_name_offset_in_shstrtab);
        // sh_type = SHT_PROGBITS (1).
        entry.sh_type.set(endian, 1);
        // sh_flags = SHF_MERGE (0x10) | SHF_STRINGS (0x20).
        entry.sh_flags.set(endian, 0x30);
        entry.sh_addr.set(endian, 0);
        entry.sh_offset.set(endian, new_line_str_offset as u64);
        entry.sh_size.set(endian, new_debug_line_str_size as u64);
        entry.sh_link.set(endian, 0);
        entry.sh_info.set(endian, 0);
        entry.sh_addralign.set(endian, 1);
        entry.sh_entsize.set(endian, 1);
    }

    // Patch ehdr.e_shoff (byte 40) and e_shnum (byte 60).
    new_data[40..48].copy_from_slice(&(new_e_shoff as u64).to_le_bytes());
    new_data[60..62].copy_from_slice(&(new_e_shnum as u16).to_le_bytes());

    let _ = new_debug_line_offset;
    Ok(new_data)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <input.elf> <output.elf>", args[0]);
        return ExitCode::from(1);
    }
    let bytes = match fs::read(&args[1]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {}: {e}", args[1]);
            return ExitCode::from(1);
        }
    };
    let new_elf = match rewrite_elf(&bytes) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("rewrite failed: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = fs::write(&args[2], &new_elf) {
        eprintln!("write {}: {e}", args[2]);
        return ExitCode::from(1);
    }
    println!(
        "rewrote {} → {} ({} bytes → {} bytes)",
        args[1],
        args[2],
        bytes.len(),
        new_elf.len()
    );
    ExitCode::SUCCESS
}
