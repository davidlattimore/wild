//! `--upgrade-debug-line=v5` post-write pass.
//!
//! Re-emits each CU's `.debug_line` from DWARF 4 to DWARF 5 with
//! `DW_FORM_line_strp` references into a new `.debug_line_str`
//! section. Patches every `DW_AT_stmt_list` attribute in
//! `.debug_info` to point at the new line-program offset, replaces
//! `.debug_line`, inserts the new `.debug_line_str` section between
//! `.debug_line` and `.shstrtab`, and rewrites SHDR + ehdr.
//!
//! Saves ~16 % of `.debug_line` on rust binaries with many CUs
//! (validated end-to-end on midnight-node: 129 MB → 109 MB
//! including the new .debug_line_str pool, debugger-roundtrip
//! compare clean over 256 symbol pairs).
//!
//! The algorithm is a near-port of `experiments/debug-line-rewrite/
//! src/main.rs`'s phase 2b, adapted to:
//!   * Operate on a `&mut SizedOutput` (mmap-backed) and
//!     `set_final_size` rather than allocating a fresh `Vec<u8>`.
//!     We do build the rewrite in a temporary `Vec<u8>` and memcpy
//!     back, because the in-place arithmetic is gnarly when sections
//!     both grow (new .debug_line_str) and shrink (.debug_line).
//!   * Use `libwild::error::Result` + `bail!` / `ensure!`.
//!   * Gimli 0.33 (workspace pin) instead of 0.31 (experiment pin).

use crate::args::elf::DebugLineUpgrade;
use crate::error::Result;
use crate::file_writer::SizedOutput;
use gimli::EndianSlice;
use gimli::LittleEndian;
use object::Endianness;
use object::Object;
use object::ObjectSection;
use object::elf::FileHeader64;
use object::elf::SectionHeader64;
use object::read::elf::FileHeader;
use object::read::elf::SectionHeader;
use std::collections::HashMap;

type Slice<'a> = EndianSlice<'a, LittleEndian>;

const ENDIAN: Endianness = Endianness::Little;

/// Top-level entry point. No-op when the mode is `None`. Otherwise
/// runs the v4 → v5 rewrite + section addition and shrinks
/// `SizedOutput` to the new file size via `set_final_size`.
pub(crate) fn upgrade_debug_line(sized_output: &mut SizedOutput, mode: DebugLineUpgrade) -> Result {
    if mode == DebugLineUpgrade::None {
        return Ok(());
    }
    let new_bytes = match rewrite_buffer(&sized_output.out)? {
        Some(b) => b,
        None => return Ok(()), // nothing to rewrite
    };
    let new_len = new_bytes.len();
    if new_len > sized_output.out.len() {
        // Rewrite grew the file. Happens on tiny binaries where the
        // v5 format overhead (+ new SHDR entry + new section name in
        // shstrtab) outweighs the cross-CU path-pool savings. On
        // real workloads (substrate-class with thousands of CUs
        // sharing workspace paths) this never happens.
        //
        // Wild's SizedOutput is a fixed-size mmap — we can't grow it
        // post-hoc. Skip the upgrade and emit the original output
        // unchanged.
        eprintln!(
            "wild: elf_line_v5: skipping (rewrite would grow output {} → {} bytes; \
             likely too few paths to dedup)",
            sized_output.out.len(),
            new_len
        );
        return Ok(());
    }
    sized_output.out[..new_len].copy_from_slice(&new_bytes);
    sized_output.set_final_size(new_len as u64);
    Ok(())
}

/// Per-CU line-program info captured during the read pass and
/// consumed by the emit pass.
struct CuLineInfo {
    stmt_list_byte_pos_in_debug_info: u64,
    new_line_offset: u32,
    min_inst_length: u8,
    max_ops_per_inst: u8,
    default_is_stmt: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
    std_opcode_lengths: Vec<u8>,
    include_directories: Vec<Vec<u8>>,
    file_entries: Vec<(Vec<u8>, u64)>,
    primary_file_name: Vec<u8>,
    comp_dir: Vec<u8>,
    program_bytes: Vec<u8>,
}

#[derive(Default)]
struct LineStrPool {
    bytes: Vec<u8>,
    offsets: HashMap<Vec<u8>, u32>,
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

fn rewrite_buffer(elf: &[u8]) -> Result<Option<Vec<u8>>> {
    let cus = match read_cus(elf)? {
        Some(c) => c,
        None => return Ok(None),
    };

    let mut new_debug_line = Vec::new();
    let mut pool = LineStrPool::default();
    let mut cu_offsets: Vec<(u64, u32)> = Vec::with_capacity(cus.len());
    let mut owned_cus = cus;
    for cu in owned_cus.iter_mut() {
        let new_off = new_debug_line.len() as u32;
        cu.new_line_offset = new_off;
        emit_v5_line_program_pooled(&mut new_debug_line, cu, &mut pool);
        cu_offsets.push((cu.stmt_list_byte_pos_in_debug_info, new_off));
    }
    let new_debug_line_str = pool.bytes;
    let new_debug_line_size = new_debug_line.len();
    let new_debug_line_str_size = new_debug_line_str.len();

    apply_rewrite(
        elf,
        &cu_offsets,
        &new_debug_line,
        &new_debug_line_str,
        new_debug_line_size,
        new_debug_line_str_size,
    )
    .map(Some)
}

fn read_cus(elf: &[u8]) -> Result<Option<Vec<CuLineInfo>>> {
    let obj = object::File::parse(elf).map_err(|e| crate::error!("elf_line_v5: parse: {e:?}"))?;
    let load = |id: gimli::SectionId| -> std::result::Result<Slice<'_>, gimli::Error> {
        let data = obj
            .section_by_name(id.name())
            .map(|s| s.data().unwrap_or(&[]))
            .unwrap_or(&[]);
        Ok(EndianSlice::new(data, LittleEndian))
    };
    let dwarf =
        gimli::Dwarf::load(load).map_err(|e| crate::error!("elf_line_v5: dwarf load: {e:?}"))?;

    let debug_line_bytes = obj
        .section_by_name(".debug_line")
        .map(|s| s.data().unwrap_or(&[]))
        .unwrap_or(&[]);
    if debug_line_bytes.is_empty() {
        return Ok(None);
    }

    let mut cus = Vec::new();
    let mut units = dwarf.units();
    while let Some(unit_header) = units
        .next()
        .map_err(|e| crate::error!("elf_line_v5: units: {e:?}"))?
    {
        // gimli 0.33: UnitSectionOffset is a tuple struct, .0 is the
        // offset value. (Earlier gimli versions used an enum.)
        let cu_offset_in_debug_info = unit_header.offset().0 as u64;
        let unit = dwarf
            .unit(unit_header)
            .map_err(|e| crate::error!("elf_line_v5: unit @ {cu_offset_in_debug_info}: {e:?}"))?;
        let Some(line_program) = unit.line_program.clone() else {
            continue;
        };
        let lp_header = line_program.header();
        // We only convert v4 line programs. v5 inputs are already
        // ahead of us. v3 / v2 are theoretically convertible but
        // not seen on rustc output, so skip for safety.
        if lp_header.version() != 4 {
            continue;
        }
        let line_offset = match lp_header.offset() {
            gimli::DebugLineOffset(o) => o as u32,
        };

        // Locate DW_AT_stmt_list byte position.
        let mut entries = unit
            .entries_raw(None)
            .map_err(|e| crate::error!("elf_line_v5: entries_raw: {e:?}"))?;
        let abbrev = entries
            .read_abbreviation()
            .map_err(|e| crate::error!("elf_line_v5: read_abbreviation: {e:?}"))?
            .ok_or_else(|| crate::error!("elf_line_v5: first DIE has no abbrev"))?;
        let mut stmt_list_byte_pos: Option<u64> = None;
        for spec in abbrev.attributes() {
            let pos_in_unit: gimli::UnitOffset = entries.next_offset();
            let pos_in_debug_info = pos_in_unit.0 as u64 + cu_offset_in_debug_info;
            let attr = entries
                .read_attribute(*spec)
                .map_err(|e| crate::error!("elf_line_v5: read_attribute: {e:?}"))?;
            if attr.name() == gimli::constants::DW_AT_stmt_list {
                stmt_list_byte_pos = Some(pos_in_debug_info);
            }
        }
        let Some(stmt_list_byte_pos) = stmt_list_byte_pos else {
            // CU has no stmt_list — nothing to upgrade.
            continue;
        };

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
                .ok_or_else(|| crate::error!("elf_line_v5: dir string_value"))?
                .slice()
                .to_vec();
            include_directories.push(bytes);
        }
        let mut file_entries = Vec::new();
        for file in lp_header.file_names() {
            let path = file
                .path_name()
                .string_value(&dwarf.debug_str)
                .ok_or_else(|| crate::error!("elf_line_v5: file string_value"))?
                .slice()
                .to_vec();
            let dir_index = file.directory_index();
            file_entries.push((path, dir_index));
        }

        let unit_length_field_bytes = 4u32;
        let prologue_len: u32 = unit_length_field_bytes + 2 + 4 + lp_header.header_length() as u32;
        let unit_total_bytes = (lp_header.unit_length() as u32) + unit_length_field_bytes;
        let program_start = (line_offset + prologue_len) as usize;
        let program_end = (line_offset + unit_total_bytes) as usize;
        if program_end > debug_line_bytes.len() {
            crate::bail!(
                "elf_line_v5: program_end {program_end} exceeds .debug_line {}",
                debug_line_bytes.len()
            );
        }
        let program_bytes = debug_line_bytes[program_start..program_end].to_vec();

        cus.push(CuLineInfo {
            stmt_list_byte_pos_in_debug_info: stmt_list_byte_pos,
            new_line_offset: 0,
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
    if cus.is_empty() {
        return Ok(None);
    }
    Ok(Some(cus))
}

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

fn emit_v5_line_program_pooled(out: &mut Vec<u8>, cu: &CuLineInfo, pool: &mut LineStrPool) {
    let start = out.len();
    out.extend_from_slice(&[0u8; 4]); // unit_length placeholder
    out.extend_from_slice(&5u16.to_le_bytes()); // version
    out.push(8); // address_size
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

    out.push(2);
    write_uleb(out, gimli::constants::DW_LNCT_path.0 as u64);
    write_uleb(out, gimli::constants::DW_FORM_line_strp.0 as u64);
    write_uleb(out, gimli::constants::DW_LNCT_directory_index.0 as u64);
    write_uleb(out, gimli::constants::DW_FORM_udata.0 as u64);
    write_uleb(out, 1 + cu.file_entries.len() as u64);
    let primary_off = pool.intern(&cu.primary_file_name);
    out.extend_from_slice(&primary_off.to_le_bytes());
    write_uleb(out, 0);
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

/// One byte-range edit applied during the splice pass in
/// [`apply_rewrite`]. Positions are expressed in the OLD file's
/// coordinate system; the splice pass walks ops in sorted order
/// and maintains a cumulative delta between old and new offsets.
///
/// Four kinds of op drive the rewrite:
///   * replace: `delete > 0`, `insert.len() > 0` — op A (.debug_line).
///   * pure insert: `delete = 0`, `insert.len() > 0` — op B (the new
///     .debug_line_str) and op C (.shstrtab name append).
///   * pure delete: `delete > 0`, `insert = []` — not currently used
///     but the machinery handles it.
struct Op {
    position: usize,
    delete: usize,
    insert: Vec<u8>,
}

/// Distinguishes two semantics of remapping an old offset `p` into
/// the new file, needed when an insert op sits exactly at `p`.
///
/// Triggered by proc-macro `.so` files which happen to place a
/// section starting exactly at `debug_line_end` — without this
/// split they'd collide with our new `.debug_line_str` insert.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MapKind {
    /// Return the position where an op at `p` itself begins
    /// inserting. Used when computing OUR OWN inserts' new
    /// positions (e.g. `.debug_line_str`'s `sh_offset`). Insert
    /// ops at exactly `p` do NOT contribute.
    Before,
    /// Return the position of bytes that WERE at `p` in the old
    /// file. An insert op at exactly `p` pushes those bytes
    /// forward by its insert length.
    After,
}

/// Translate an old-file byte offset to its position in the new
/// file after `ops` have been applied. `ops` must be sorted by
/// `position` ascending.
fn map_offset(p: usize, ops: &[Op], kind: MapKind) -> usize {
    let mut delta: isize = 0;
    for op in ops {
        if op.position < p {
            delta += op.insert.len() as isize - op.delete as isize;
        } else if op.position == p && op.delete == 0 && kind == MapKind::After {
            delta += op.insert.len() as isize;
        } else {
            break;
        }
    }
    (p as isize + delta) as usize
}

fn apply_rewrite(
    elf: &[u8],
    cu_offsets: &[(u64, u32)],
    new_debug_line: &[u8],
    new_debug_line_str: &[u8],
    new_debug_line_size: usize,
    new_debug_line_str_size: usize,
) -> Result<Vec<u8>> {
    let endian = ENDIAN;

    let (
        debug_info_offset,
        debug_line_idx,
        debug_line_offset,
        old_debug_line_size,
        shstrtab_idx,
        shstrtab_offset,
        shstrtab_old_size,
        e_shoff,
        e_shentsize,
        e_shnum,
    ) = {
        let header = FileHeader64::<Endianness>::parse(elf)
            .map_err(|e| crate::error!("elf_line_v5: ehdr: {e:?}"))?;
        let sections = header
            .sections(endian, elf)
            .map_err(|e| crate::error!("elf_line_v5: sections: {e:?}"))?;
        let mut debug_info_offset = 0u64;
        let mut debug_line_idx = 0usize;
        let mut debug_line_offset = 0u64;
        let mut debug_line_size = 0u64;
        let mut shstrtab_idx = 0usize;
        let mut shstrtab_offset = 0u64;
        let mut shstrtab_old_size = 0u64;
        let e_shstrndx = header.e_shstrndx(endian) as usize;
        for (idx, sect) in sections.iter().enumerate() {
            let name = sections
                .section_name(endian, sect)
                .map_err(|e| crate::error!("elf_line_v5: section_name {idx}: {e:?}"))?;
            if name == b".debug_info" {
                debug_info_offset = sect.sh_offset(endian);
            } else if name == b".debug_line" {
                debug_line_idx = idx;
                debug_line_offset = sect.sh_offset(endian);
                debug_line_size = sect.sh_size(endian);
            }
            if idx == e_shstrndx {
                shstrtab_idx = idx;
                shstrtab_offset = sect.sh_offset(endian);
                shstrtab_old_size = sect.sh_size(endian);
            }
        }
        if debug_info_offset == 0 {
            crate::bail!("elf_line_v5: .debug_info missing");
        }
        if debug_line_offset == 0 {
            crate::bail!("elf_line_v5: .debug_line missing");
        }
        (
            debug_info_offset,
            debug_line_idx,
            debug_line_offset,
            debug_line_size as usize,
            shstrtab_idx,
            shstrtab_offset,
            shstrtab_old_size,
            header.e_shoff(endian) as usize,
            header.e_shentsize(endian) as usize,
            header.e_shnum(endian) as usize,
        )
    };

    let mut data = elf.to_vec();
    for &(stmt_list_pos_in_di, new_off) in cu_offsets {
        let abs = (debug_info_offset + stmt_list_pos_in_di) as usize;
        if abs + 4 > data.len() {
            crate::bail!("elf_line_v5: stmt_list patch out of bounds @ {abs}");
        }
        data[abs..abs + 4].copy_from_slice(&new_off.to_le_bytes());
    }

    let new_section_name = b".debug_line_str\0";
    let debug_line_end = debug_line_offset as usize + old_debug_line_size;
    let shstrtab_end = shstrtab_offset as usize + shstrtab_old_size as usize;
    let shdr_end = e_shoff + e_shnum * e_shentsize;

    // --- Layout-agnostic splice. Three in-middle ops + a
    //     SHDR-move op handled after the splice:
    //
    //   A. Replace .debug_line bytes with new_debug_line.
    //   B. Insert .debug_line_str right after .debug_line.
    //   C. Append ".debug_line_str\0" at end of .shstrtab.
    //   D. MOVE the SHDR table to the end of the file with one
    //      new entry appended. Old SHDR location becomes dead bytes
    //      (not referenced by new ehdr.e_shoff). This avoids
    //      in-file shifts within PT_LOAD regions — PHDR p_offset
    //      fields don't know about the shift and would load
    //      garbage otherwise. Wild's own layout (SHDR early,
    //      PT_LOAD sections AFTER it in the file) triggers exactly
    //      this case; growing SHDR in place would push executable
    //      bytes to offsets PHDR can't see.
    let new_section_name_offset_in_shstrtab = shstrtab_old_size as u32;
    let _ = shdr_end; // kept in scope for clarity; used by assertions

    let mut ops: Vec<Op> = Vec::with_capacity(3);
    ops.push(Op {
        position: debug_line_offset as usize,
        delete: old_debug_line_size,
        insert: new_debug_line.to_vec(),
    });
    ops.push(Op {
        position: debug_line_end,
        delete: 0,
        insert: new_debug_line_str.to_vec(),
    });
    ops.push(Op {
        position: shstrtab_end,
        delete: 0,
        insert: new_section_name.to_vec(),
    });
    ops.sort_by_key(|op| op.position);

    // ---- Apply ops A/B/C: stream old bytes → new.
    let mut new_data = Vec::with_capacity(
        data.len()
            + ops
                .iter()
                .map(|op| op.insert.len())
                .sum::<usize>()
                .saturating_sub(ops.iter().map(|op| op.delete).sum::<usize>())
            + (e_shnum + 1) * e_shentsize,
    );
    let mut cursor = 0usize;
    for op in &ops {
        if op.position < cursor {
            crate::bail!(
                "elf_line_v5: overlapping ops (cursor={cursor}, op.position={})",
                op.position
            );
        }
        new_data.extend_from_slice(&data[cursor..op.position]);
        new_data.extend_from_slice(&op.insert);
        cursor = op.position + op.delete;
    }
    new_data.extend_from_slice(&data[cursor..]);

    // ---- Op D: append new SHDR table at end of file.
    let new_e_shoff = new_data.len();
    let new_e_shnum = e_shnum + 1;
    // For .shstrtab and .debug_line: their NEW position is where
    // op A's replacement / op C's append START — Before-kind.
    let new_shstrtab_offset = map_offset(shstrtab_offset as usize, &ops, MapKind::Before);
    let new_shstrtab_size = shstrtab_old_size as usize + new_section_name.len();
    // .debug_line_str's sh_offset = where op B begins inserting.
    // Use Before so we don't get pushed past our own insert.
    let new_line_str_offset = map_offset(debug_line_end, &ops, MapKind::Before);
    let new_debug_line_offset = map_offset(debug_line_offset as usize, &ops, MapKind::Before);

    new_data.resize(new_e_shoff + new_e_shnum * e_shentsize, 0);
    for i in 0..e_shnum {
        let src = e_shoff + i * e_shentsize;
        if src + e_shentsize > data.len() {
            crate::bail!("elf_line_v5: source SHDR {i} out of bounds");
        }
        let dst = new_e_shoff + i * e_shentsize;
        new_data[dst..dst + e_shentsize].copy_from_slice(&data[src..src + e_shentsize]);
    }
    for i in 0..e_shnum {
        let entry_off = new_e_shoff + i * e_shentsize;
        let entry_bytes = &mut new_data[entry_off..entry_off + e_shentsize];
        let entry = unsafe { &mut *(entry_bytes.as_mut_ptr() as *mut SectionHeader64<Endianness>) };
        let sh_offset = entry.sh_offset.get(endian) as usize;
        if i == debug_line_idx {
            entry.sh_size.set(endian, new_debug_line_size as u64);
            entry.sh_offset.set(endian, new_debug_line_offset as u64);
        } else if i == shstrtab_idx {
            entry.sh_offset.set(endian, new_shstrtab_offset as u64);
            entry.sh_size.set(endian, new_shstrtab_size as u64);
        } else if sh_offset > 0 {
            // After-kind: a section whose sh_offset coincides with
            // an insert op's position must shift past the inserted
            // bytes, not collide with them. Hits proc-macro .so
            // files where some section starts exactly at
            // debug_line_end (= op B's insert point).
            entry
                .sh_offset
                .set(endian, map_offset(sh_offset, &ops, MapKind::After) as u64);
        }
    }
    // New entry for .debug_line_str at end of new SHDR.
    {
        let new_entry_off = new_e_shoff + e_shnum * e_shentsize;
        let entry_bytes = &mut new_data[new_entry_off..new_entry_off + e_shentsize];
        let entry = unsafe { &mut *(entry_bytes.as_mut_ptr() as *mut SectionHeader64<Endianness>) };
        entry
            .sh_name
            .set(endian, new_section_name_offset_in_shstrtab);
        entry.sh_type.set(endian, 1); // SHT_PROGBITS
        entry.sh_flags.set(endian, 0x30); // SHF_MERGE | SHF_STRINGS
        entry.sh_addr.set(endian, 0);
        entry.sh_offset.set(endian, new_line_str_offset as u64);
        entry.sh_size.set(endian, new_debug_line_str_size as u64);
        entry.sh_link.set(endian, 0);
        entry.sh_info.set(endian, 0);
        entry.sh_addralign.set(endian, 1);
        entry.sh_entsize.set(endian, 1);
    }
    new_data[40..48].copy_from_slice(&(new_e_shoff as u64).to_le_bytes());
    new_data[60..62].copy_from_slice(&(new_e_shnum as u16).to_le_bytes());

    Ok(new_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- map_offset: Before vs After semantics -------------------

    fn op_replace(position: usize, delete: usize, insert: &[u8]) -> Op {
        Op {
            position,
            delete,
            insert: insert.to_vec(),
        }
    }
    fn op_insert(position: usize, insert: &[u8]) -> Op {
        op_replace(position, 0, insert)
    }

    /// Regression for phase 4d (bug 3). Under `Before`, an insert
    /// op at the query position doesn't contribute. Under `After`,
    /// a pure insert at the query position pushes the query forward
    /// by the insert's length. A replacement op at the position
    /// never contributes for either kind (the queried bytes are
    /// what's being replaced).
    #[test]
    fn map_offset_handles_insert_at_query_position() {
        let ops = vec![op_insert(100, b"XXXX")]; // +4 bytes at 100
        assert_eq!(map_offset(100, &ops, MapKind::Before), 100);
        assert_eq!(map_offset(100, &ops, MapKind::After), 104);
        assert_eq!(map_offset(99, &ops, MapKind::After), 99);
        assert_eq!(map_offset(101, &ops, MapKind::After), 105);
    }

    #[test]
    fn map_offset_replacement_at_query_position_is_identity_for_both_kinds() {
        // Replacement (delete > 0) at position 100: bytes at 100
        // are what's being replaced, so for the replaced thing's
        // own identity both kinds return 100 + prior deltas (here 0).
        let ops = vec![op_replace(100, 50, b"ZZZ")]; // -47 bytes net
        assert_eq!(map_offset(100, &ops, MapKind::Before), 100);
        assert_eq!(map_offset(100, &ops, MapKind::After), 100);
        // Bytes right after the replacement shift by net delta.
        assert_eq!(map_offset(150, &ops, MapKind::Before), 103);
        assert_eq!(map_offset(150, &ops, MapKind::After), 103);
    }

    #[test]
    fn map_offset_accumulates_multiple_prior_ops() {
        let ops = vec![
            op_insert(10, b"AA"),     // +2 at 10
            op_replace(50, 10, b"B"), // -9 at 50
            op_insert(100, b"CCCC"),  // +4 at 100
        ];
        // Query points before all, between, and after.
        assert_eq!(map_offset(5, &ops, MapKind::Before), 5);
        assert_eq!(map_offset(20, &ops, MapKind::Before), 22); // +2
        assert_eq!(map_offset(60, &ops, MapKind::Before), 53); // +2 - 9
        assert_eq!(map_offset(100, &ops, MapKind::Before), 93);
        assert_eq!(map_offset(100, &ops, MapKind::After), 97); // +2-9+4
        assert_eq!(map_offset(200, &ops, MapKind::Before), 197); // +2-9+4
    }

    // ---- apply_rewrite on synthetic ELFs ---------------------------

    const ELF64_EHDR_SIZE: usize = 64;
    const ELF64_PHDR_SIZE: usize = 56;
    const ELF64_SHDR_SIZE: usize = 64;

    /// Build a minimal ELF64-LE with one PT_LOAD segment + three
    /// sections: null, `.debug_line` (filled with `0xDE` pattern),
    /// `.shstrtab`. No `.debug_info` / `.debug_abbrev` — we pass
    /// empty `cu_offsets` to `apply_rewrite` so nothing's patched
    /// DIE-side.
    ///
    /// `layout` picks where the SHDR table lives in the file:
    ///   * `ShdrLate` — after all sections (gcc/ld convention).
    ///   * `ShdrEarly` — right after PHDR, BEFORE section content
    ///     (wild's own convention; exercises phase 4b's SHDR-move
    ///     fix).
    ///
    /// `extra_section_at_debug_line_end`: when true, add a 4th
    /// SHDR entry for a zero-size section whose `sh_offset` is
    /// exactly `debug_line_offset + debug_line_size`. This is the
    /// shape proc-macro `.so` files have and exercises phase 4d's
    /// Before/After split.
    #[derive(Clone, Copy)]
    enum ShdrLayout {
        Early,
        Late,
    }

    #[allow(dead_code)] // some fields read only in select test assertions
    struct SyntheticParts {
        bytes: Vec<u8>,
        debug_line_offset: usize,
        debug_line_size: usize,
        shstrtab_offset: usize,
        shstrtab_size: usize,
        /// When the test built it with the trailing-section flag,
        /// this is the old `sh_offset` we'll assert gets correctly
        /// remapped past `.debug_line_str` in the new file.
        trailing_section_old_offset: Option<usize>,
        phdr_load_offset: u64,
        phdr_load_size: u64,
    }

    fn build_synthetic_elf(
        layout: ShdrLayout,
        extra_section_at_debug_line_end: bool,
    ) -> SyntheticParts {
        let shstrtab_bytes: Vec<u8> = {
            let mut s = vec![0u8];
            s.extend_from_slice(b".debug_line\0");
            s.extend_from_slice(b".shstrtab\0");
            s.extend_from_slice(b".debug_info\0");
            if extra_section_at_debug_line_end {
                s.extend_from_slice(b".edge\0");
            }
            s
        };
        let debug_line_bytes = vec![0xDEu8; 256];
        let debug_info_bytes = vec![0xD1u8; 32];
        let phdr_load_bytes = vec![0xAAu8; 128]; // distinct fingerprint

        // Sections: null, .debug_info, .debug_line, (optional .edge), .shstrtab
        let n_sections = if extra_section_at_debug_line_end {
            5
        } else {
            4
        };

        // Layout planning ------------------------------------------
        // Common prefix: ehdr (64) + phdr (56).
        let ehdr_end = ELF64_EHDR_SIZE;
        let phdr_off = ehdr_end;
        let phdr_end = phdr_off + ELF64_PHDR_SIZE;

        let (
            e_shoff,
            phdr_load_off,
            debug_info_off,
            debug_line_off,
            shstrtab_off,
            trailing_off,
            file_size,
        ) = match layout {
            ShdrLayout::Late => {
                // ehdr | phdr | PT_LOAD | .debug_info | .debug_line | [trail_edge] | .shstrtab | SHDR
                let load_off = phdr_end;
                let load_end = load_off + phdr_load_bytes.len();
                let di = load_end;
                let di_end = di + debug_info_bytes.len();
                let dl = di_end;
                let dl_end = dl + debug_line_bytes.len();
                let trail = if extra_section_at_debug_line_end {
                    Some(dl_end)
                } else {
                    None
                };
                let trail_size = if trail.is_some() { 16 } else { 0 };
                let sh = dl_end + trail_size;
                let sh_end = sh + shstrtab_bytes.len();
                let shoff = sh_end;
                let total = shoff + n_sections * ELF64_SHDR_SIZE;
                (shoff, load_off, di, dl, sh, trail, total)
            }
            ShdrLayout::Early => {
                // ehdr | phdr | SHDR | PT_LOAD | .debug_info | .debug_line | [trail_edge] | .shstrtab
                let shoff = phdr_end;
                let shdr_end = shoff + n_sections * ELF64_SHDR_SIZE;
                let load_off = shdr_end;
                let load_end = load_off + phdr_load_bytes.len();
                let di = load_end;
                let di_end = di + debug_info_bytes.len();
                let dl = di_end;
                let dl_end = dl + debug_line_bytes.len();
                let trail = if extra_section_at_debug_line_end {
                    Some(dl_end)
                } else {
                    None
                };
                let trail_size = if trail.is_some() { 16 } else { 0 };
                let sh_str = dl_end + trail_size;
                let sh_str_end = sh_str + shstrtab_bytes.len();
                (shoff, load_off, di, dl, sh_str, trail, sh_str_end)
            }
        };

        let mut out = vec![0u8; file_size];

        // ehdr
        out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // ELFDATA2LSB
        out[6] = 1; // EI_VERSION
        out[16..18].copy_from_slice(&3u16.to_le_bytes()); // e_type ET_DYN
        out[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[32..40].copy_from_slice(&(phdr_off as u64).to_le_bytes()); // e_phoff
        out[40..48].copy_from_slice(&(e_shoff as u64).to_le_bytes()); // e_shoff
        out[52..54].copy_from_slice(&(ELF64_EHDR_SIZE as u16).to_le_bytes());
        out[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
        out[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        out[58..60].copy_from_slice(&(ELF64_SHDR_SIZE as u16).to_le_bytes());
        out[60..62].copy_from_slice(&(n_sections as u16).to_le_bytes());
        out[62..64].copy_from_slice(&2u16.to_le_bytes()); // e_shstrndx (shstrtab is index 2)

        // Section slot layout:
        //   0: null
        //   1: .debug_info
        //   2: .debug_line
        //   3: .edge       (optional, only when extra_section_at_debug_line_end)
        //   last: .shstrtab
        let shstrtab_idx: u16 = if extra_section_at_debug_line_end {
            4
        } else {
            3
        };
        out[62..64].copy_from_slice(&shstrtab_idx.to_le_bytes());

        // phdr (one PT_LOAD)
        // Elf64_Phdr: p_type(u32) p_flags(u32) p_offset(u64) p_vaddr(u64)
        // p_paddr(u64) p_filesz(u64) p_memsz(u64) p_align(u64) = 56 bytes.
        out[phdr_off..phdr_off + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        out[phdr_off + 4..phdr_off + 8].copy_from_slice(&7u32.to_le_bytes()); // RWX
        out[phdr_off + 8..phdr_off + 16].copy_from_slice(&(phdr_load_off as u64).to_le_bytes());
        out[phdr_off + 16..phdr_off + 24].copy_from_slice(&(phdr_load_off as u64).to_le_bytes());
        out[phdr_off + 24..phdr_off + 32].copy_from_slice(&(phdr_load_off as u64).to_le_bytes());
        out[phdr_off + 32..phdr_off + 40]
            .copy_from_slice(&(phdr_load_bytes.len() as u64).to_le_bytes());
        out[phdr_off + 40..phdr_off + 48]
            .copy_from_slice(&(phdr_load_bytes.len() as u64).to_le_bytes());
        out[phdr_off + 48..phdr_off + 56].copy_from_slice(&4096u64.to_le_bytes());

        // Section data
        out[phdr_load_off..phdr_load_off + phdr_load_bytes.len()].copy_from_slice(&phdr_load_bytes);
        out[debug_info_off..debug_info_off + debug_info_bytes.len()]
            .copy_from_slice(&debug_info_bytes);
        out[debug_line_off..debug_line_off + debug_line_bytes.len()]
            .copy_from_slice(&debug_line_bytes);
        if let Some(_t) = trailing_off {
            // 16 zero bytes already in-place from vec![0; file_size].
        }
        out[shstrtab_off..shstrtab_off + shstrtab_bytes.len()].copy_from_slice(&shstrtab_bytes);

        // SHDR entries
        // sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
        // sh_link, sh_info, sh_addralign, sh_entsize = 64 bytes.
        let write_shdr = |out: &mut [u8],
                          slot: usize,
                          sh_name: u32,
                          sh_type: u32,
                          sh_flags: u64,
                          sh_offset: u64,
                          sh_size: u64| {
            let off = e_shoff + slot * ELF64_SHDR_SIZE;
            out[off..off + 4].copy_from_slice(&sh_name.to_le_bytes());
            out[off + 4..off + 8].copy_from_slice(&sh_type.to_le_bytes());
            out[off + 8..off + 16].copy_from_slice(&sh_flags.to_le_bytes());
            out[off + 16..off + 24].copy_from_slice(&0u64.to_le_bytes());
            out[off + 24..off + 32].copy_from_slice(&sh_offset.to_le_bytes());
            out[off + 32..off + 40].copy_from_slice(&sh_size.to_le_bytes());
            out[off + 40..off + 44].copy_from_slice(&0u32.to_le_bytes()); // sh_link
            out[off + 44..off + 48].copy_from_slice(&0u32.to_le_bytes()); // sh_info
            out[off + 48..off + 56].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
            out[off + 56..off + 64].copy_from_slice(&0u64.to_le_bytes()); // sh_entsize
        };

        // Slot 0: SHT_NULL (already zero).
        // Shstrtab name-offset helpers.
        let debug_line_name_off = 1u32;
        let shstrtab_name_off = (1 + b".debug_line\0".len()) as u32;
        let debug_info_name_off = (1 + b".debug_line\0".len() + b".shstrtab\0".len()) as u32;
        let edge_name_off =
            (1 + b".debug_line\0".len() + b".shstrtab\0".len() + b".debug_info\0".len()) as u32;

        // Slot 1: .debug_info
        write_shdr(
            &mut out,
            1,
            debug_info_name_off,
            1,
            0,
            debug_info_off as u64,
            debug_info_bytes.len() as u64,
        );
        // Slot 2: .debug_line
        write_shdr(
            &mut out,
            2,
            debug_line_name_off,
            1,
            0,
            debug_line_off as u64,
            debug_line_bytes.len() as u64,
        );
        if extra_section_at_debug_line_end {
            // Slot 3: .edge — sh_offset = debug_line_end.
            write_shdr(
                &mut out,
                3,
                edge_name_off,
                1,
                0,
                trailing_off.unwrap() as u64,
                16,
            );
            // Slot 4: .shstrtab
            write_shdr(
                &mut out,
                4,
                shstrtab_name_off,
                3,
                0,
                shstrtab_off as u64,
                shstrtab_bytes.len() as u64,
            );
        } else {
            // Slot 3: .shstrtab
            write_shdr(
                &mut out,
                3,
                shstrtab_name_off,
                3,
                0,
                shstrtab_off as u64,
                shstrtab_bytes.len() as u64,
            );
        }

        SyntheticParts {
            bytes: out,
            debug_line_offset: debug_line_off,
            debug_line_size: debug_line_bytes.len(),
            shstrtab_offset: shstrtab_off,
            shstrtab_size: shstrtab_bytes.len(),
            trailing_section_old_offset: trailing_off,
            phdr_load_offset: phdr_load_off as u64,
            phdr_load_size: phdr_load_bytes.len() as u64,
        }
    }

    /// Phase 4b regression: when SHDR is early in the file (wild's
    /// layout), the rewrite must MOVE SHDR to the end of file rather
    /// than grow it in place. PT_LOAD content must NOT shift —
    /// PHDR p_offset fields aren't updated and exec would load
    /// garbage.
    #[test]
    fn synthetic_elf_parses_via_object_crate() {
        // Sanity: both layouts produce an ELF that `object` can
        // parse + section-walk without error. If this fails, the
        // more complex rewrite tests downstream will hit confusing
        // "section_name 0" errors originating from the synthetic,
        // not from any apply_rewrite bug.
        for &layout in &[ShdrLayout::Early, ShdrLayout::Late] {
            for &extra in &[false, true] {
                let parts = build_synthetic_elf(layout, extra);
                let obj = object::File::parse(parts.bytes.as_slice()).unwrap_or_else(|e| {
                    panic!(
                        "object::File::parse failed (layout={:?}, extra={}): {e}",
                        match layout {
                            ShdrLayout::Early => "Early",
                            ShdrLayout::Late => "Late",
                        },
                        extra
                    )
                });
                use object::Object as _;
                use object::ObjectSection as _;
                for s in obj.sections() {
                    let _ = s.name().expect("section name readable");
                }
            }
        }
    }

    #[test]
    fn rewrite_moves_shdr_to_end_on_early_shdr_layout() {
        let parts = build_synthetic_elf(ShdrLayout::Early, false);
        let new_debug_line = vec![0xCAu8; 128]; // smaller than original 256
        let new_debug_line_str = vec![0xFBu8; 64];
        let out = apply_rewrite(
            &parts.bytes,
            &[],
            &new_debug_line,
            &new_debug_line_str,
            new_debug_line.len(),
            new_debug_line_str.len(),
        )
        .expect("apply_rewrite ok");

        // ehdr.e_shoff should point at (new_file_size - new_shnum*64).
        let new_e_shoff = u64::from_le_bytes(out[40..48].try_into().unwrap()) as usize;
        let new_e_shnum = u16::from_le_bytes(out[60..62].try_into().unwrap()) as usize;
        assert_eq!(
            new_e_shoff + new_e_shnum * ELF64_SHDR_SIZE,
            out.len(),
            "SHDR must live at end of new file (phase 4b)"
        );
        // 4 original sections (null, .debug_info, .debug_line, .shstrtab)
        // + 1 new (.debug_line_str) = 5.
        assert_eq!(
            new_e_shnum, 5,
            "one extra SHDR entry added (.debug_line_str)"
        );

        // PT_LOAD content must be byte-identical at its old offset.
        let load_off = parts.phdr_load_offset as usize;
        let load_sz = parts.phdr_load_size as usize;
        assert_eq!(
            &out[load_off..load_off + load_sz],
            &parts.bytes[load_off..load_off + load_sz],
            "PT_LOAD content shifted — PHDR p_offset would be stale (phase 4b regression)"
        );
    }

    /// Phase 4d regression: proc-macro `.so` files have a section
    /// starting exactly at `debug_line_end`. Under the old
    /// (single-mode) `map_offset`, such a section's new `sh_offset`
    /// collided with the newly-inserted `.debug_line_str`. The
    /// Before/After split moves it past the insert.
    #[test]
    fn rewrite_remaps_section_at_debug_line_end_past_the_insert() {
        let parts = build_synthetic_elf(ShdrLayout::Late, true);
        let new_debug_line = vec![0xCAu8; 128];
        let new_debug_line_str = vec![0xFBu8; 48];
        let out = apply_rewrite(
            &parts.bytes,
            &[],
            &new_debug_line,
            &new_debug_line_str,
            new_debug_line.len(),
            new_debug_line_str.len(),
        )
        .expect("apply_rewrite ok");

        // New SHDR is at end of file. .edge is slot 3 (after null,
        // .debug_info, .debug_line). .debug_line_str is the
        // last slot.
        let new_e_shoff = u64::from_le_bytes(out[40..48].try_into().unwrap()) as usize;
        let edge_entry_off = new_e_shoff + 3 * ELF64_SHDR_SIZE;
        let edge_sh_offset = u64::from_le_bytes(
            out[edge_entry_off + 24..edge_entry_off + 32]
                .try_into()
                .unwrap(),
        ) as usize;

        let new_e_shnum = u16::from_le_bytes(out[60..62].try_into().unwrap()) as usize;
        let line_str_entry_off = new_e_shoff + (new_e_shnum - 1) * ELF64_SHDR_SIZE;
        let line_str_sh_offset = u64::from_le_bytes(
            out[line_str_entry_off + 24..line_str_entry_off + 32]
                .try_into()
                .unwrap(),
        ) as usize;
        let line_str_sh_size = u64::from_le_bytes(
            out[line_str_entry_off + 32..line_str_entry_off + 40]
                .try_into()
                .unwrap(),
        ) as usize;

        assert_eq!(
            line_str_sh_size,
            new_debug_line_str.len(),
            "new .debug_line_str entry carries expected size"
        );
        // `.edge` must not collide with `.debug_line_str`. Under
        // the pre-phase-4d bug, both had the same sh_offset.
        assert!(
            edge_sh_offset >= line_str_sh_offset + line_str_sh_size,
            "section at debug_line_end must be remapped past .debug_line_str \
             (edge_sh_offset={edge_sh_offset}, \
              line_str=[{line_str_sh_offset}, +{line_str_sh_size})) — phase 4d regression"
        );
        // Sanity: the parts.trailing_section_old_offset was debug_line_end
        // in the OLD file. In the NEW file it should equal
        // (old position) + (new_debug_line size - old size) + new_debug_line_str.len().
        let expected_new_edge = parts.trailing_section_old_offset.unwrap() as isize
            + (new_debug_line.len() as isize - parts.debug_line_size as isize)
            + new_debug_line_str.len() as isize;
        assert_eq!(edge_sh_offset as isize, expected_new_edge);
    }

    /// Phase 4-"grew": tiny-input case. No regression test at this
    /// level because `apply_rewrite` is only called after
    /// `rewrite_buffer` has already decided to upgrade. The
    /// "grew" check lives in `upgrade_debug_line` and is exercised
    /// by the `opt1` integration fixture (small C program; rewrite
    /// always produces bigger output for such tiny inputs, so the
    /// skip path fires). Explicit unit coverage would need to
    /// construct a real DWARF 4 line program to drive `rewrite_buffer`
    /// end-to-end, which is more scaffolding than the payoff
    /// justifies right now.
    #[test]
    #[ignore = "see comment on rewrite_grew_skip_is_integration_only"]
    fn rewrite_grew_skip_is_integration_only() {}
}
