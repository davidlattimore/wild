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
    struct Op {
        position: usize,
        delete: usize,
        insert: Vec<u8>,
    }
    let new_section_name_offset_in_shstrtab = shstrtab_old_size as u32;
    let _ = shdr_end; // D no longer needs it; kept in scope for clarity

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
    // map_offset(p) = p + Σ (insert.len - delete) for ops with
    // position < p. Used to translate old file offsets to new.
    let map_offset = |p: usize, ops: &[Op]| -> usize {
        let mut delta: isize = 0;
        for op in ops {
            if op.position < p {
                delta += op.insert.len() as isize - op.delete as isize;
            } else {
                break;
            }
        }
        (p as isize + delta) as usize
    };
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
    let new_shstrtab_offset = map_offset(shstrtab_offset as usize, &ops);
    let new_shstrtab_size = shstrtab_old_size as usize + new_section_name.len();
    let new_line_str_offset = map_offset(debug_line_end, &ops);
    let new_debug_line_offset = map_offset(debug_line_offset as usize, &ops);

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
            entry
                .sh_offset
                .set(endian, map_offset(sh_offset, &ops) as u64);
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
