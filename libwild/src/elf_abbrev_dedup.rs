//! `.debug_abbrev` cross-CU hash-and-collapse post-write pass.
//!
//! Each `.debug_info` CU header carries a `debug_abbrev_offset`
//! pointing at its own table in `.debug_abbrev`. Rustc tends to emit
//! a fresh table per CU even when their contents are byte-identical,
//! so the merged `.debug_abbrev` accumulates duplicates. This pass
//! scans the CU headers, hashes each referenced table, keeps one
//! copy of each distinct byte string, and rewrites every CU's
//! `debug_abbrev_offset` to the deduped location.
//!
//! Self-contained per-table work — no DIE attributes are rewritten,
//! abbrev codes are preserved verbatim.
//!
//! Savings are modest in absolute terms (midnight-node's raw
//! `.debug_abbrev` is ~1 % of `.debug_*`, and zstd already captures
//! the within-section redundancy), but still measurable post-
//! compression and the pass is cheap.
//!
//! Layout constraint (bail-on-violation): PT_LOAD segments must end
//! before `.debug_abbrev`. Otherwise shrinking the section would
//! shift PT_LOAD bytes relative to the PHDR `p_offset` values, which
//! the kernel uses for mmap. This matches the typical linker output
//! where all loaded content precedes the `.debug_*` sections.

use crate::error::Result;
use crate::file_writer::SizedOutput;
use object::Endianness;
use object::elf::FileHeader64;
use object::elf::PT_LOAD;
use object::elf::SectionHeader64;
use object::read::elf::FileHeader;
use object::read::elf::ProgramHeader;
use object::read::elf::SectionHeader;
use std::collections::HashMap;

const ENDIAN: Endianness = Endianness::Little;

/// Top-level entry. No-op when `enabled` is false. Otherwise dedups
/// `.debug_abbrev` in-place on `sized_output`.
pub(crate) fn dedup_debug_abbrev(sized_output: &mut SizedOutput, enabled: bool) -> Result {
    if !enabled {
        return Ok(());
    }
    let effective = sized_output.effective_len();
    let new_bytes = match rewrite_buffer(&sized_output.out[..effective])? {
        Some(b) => b,
        None => return Ok(()),
    };
    let new_len = new_bytes.len();
    if new_len > effective {
        eprintln!(
            "wild: elf_abbrev_dedup: skipping (rewrite would grow {effective} → {new_len} bytes)"
        );
        return Ok(());
    }
    sized_output.out[..new_len].copy_from_slice(&new_bytes);
    sized_output.set_final_size(new_len as u64);
    Ok(())
}

struct CuAbbrevRef {
    /// File-absolute offset of the 4-byte `debug_abbrev_offset` field
    /// in this CU's header — the patch site.
    abbrev_off_field_pos: usize,
    /// Value currently at that position.
    old_abbrev_offset: u32,
}

fn rewrite_buffer(elf: &[u8]) -> Result<Option<Vec<u8>>> {
    let header = FileHeader64::<Endianness>::parse(elf)
        .map_err(|e| crate::error!("elf_abbrev_dedup: ehdr: {e:?}"))?;
    let endian = ENDIAN;

    // --- Find .debug_info + .debug_abbrev extents and the abbrev idx.
    let sections = header
        .sections(endian, elf)
        .map_err(|e| crate::error!("elf_abbrev_dedup: sections: {e:?}"))?;
    let mut di_off = 0u64;
    let mut di_size = 0u64;
    let mut da_off = 0u64;
    let mut da_size = 0u64;
    let mut da_idx = usize::MAX;
    for (idx, s) in sections.iter().enumerate() {
        let name = sections
            .section_name(endian, s)
            .map_err(|e| crate::error!("elf_abbrev_dedup: section_name {idx}: {e:?}"))?;
        if name == b".debug_info" {
            di_off = s.sh_offset(endian);
            di_size = s.sh_size(endian);
        } else if name == b".debug_abbrev" {
            da_idx = idx;
            da_off = s.sh_offset(endian);
            da_size = s.sh_size(endian);
        }
    }
    if di_off == 0 || da_off == 0 || da_idx == usize::MAX {
        return Ok(None);
    }
    let di_start = di_off as usize;
    let di_end = di_start + di_size as usize;
    let da_start = da_off as usize;
    let da_end = da_start + da_size as usize;
    if di_end > elf.len() || da_end > elf.len() {
        crate::bail!("elf_abbrev_dedup: section extent out of buffer");
    }

    // --- Safety: PT_LOAD must not extend past da_start. Otherwise
    //     shifting bytes after da_start would desync PHDR p_offset.
    let phdrs = header
        .program_headers(endian, elf)
        .map_err(|e| crate::error!("elf_abbrev_dedup: phdrs: {e:?}"))?;
    for ph in phdrs {
        if ph.p_type(endian) != PT_LOAD {
            continue;
        }
        let ph_end = ph.p_offset(endian) + ph.p_filesz(endian);
        if ph_end as usize > da_start {
            // Loaded content extends into or past .debug_abbrev.
            // Skipping is safer than a silently-corrupted exec.
            return Ok(None);
        }
    }

    // --- Walk .debug_info CU headers.
    let mut cu_refs: Vec<CuAbbrevRef> = Vec::new();
    let mut pos = di_start;
    while pos + 11 <= di_end {
        let unit_length = u32::from_le_bytes(elf[pos..pos + 4].try_into().unwrap());
        if unit_length == 0xffffffff {
            // DWARF 64 — we don't patch this layout yet.
            return Ok(None);
        }
        if unit_length == 0 {
            // Null terminator / padding — stop.
            break;
        }
        let unit_end = pos + 4 + unit_length as usize;
        if unit_end > di_end {
            crate::bail!("elf_abbrev_dedup: unit_length overflows .debug_info");
        }
        let version = u16::from_le_bytes(elf[pos + 4..pos + 6].try_into().unwrap());
        let abbrev_field_pos = match version {
            2 | 3 | 4 => pos + 6,
            5 => pos + 8,
            _ => return Ok(None), // unknown DWARF version → bail out of the pass
        };
        if abbrev_field_pos + 4 > di_end {
            crate::bail!("elf_abbrev_dedup: abbrev_field_pos OOB");
        }
        let old = u32::from_le_bytes(
            elf[abbrev_field_pos..abbrev_field_pos + 4]
                .try_into()
                .unwrap(),
        );
        cu_refs.push(CuAbbrevRef {
            abbrev_off_field_pos: abbrev_field_pos,
            old_abbrev_offset: old,
        });
        pos = unit_end;
    }
    if cu_refs.is_empty() {
        return Ok(None);
    }

    // --- Slice each referenced abbrev table.
    let abbrev_data = &elf[da_start..da_end];
    let mut distinct_offsets: Vec<u32> = cu_refs.iter().map(|c| c.old_abbrev_offset).collect();
    distinct_offsets.sort_unstable();
    distinct_offsets.dedup();
    let mut table_bytes: HashMap<u32, &[u8]> = HashMap::new();
    for &off in &distinct_offsets {
        let off_usize = off as usize;
        if off_usize >= abbrev_data.len() {
            return Ok(None);
        }
        let Some(length) = scan_abbrev_table(abbrev_data, off_usize) else {
            return Ok(None);
        };
        table_bytes.insert(off, &abbrev_data[off_usize..off_usize + length]);
    }

    // --- Dedup by content. Deterministic output ordering: process
    //     `distinct_offsets` (sorted) and emit unique tables in
    //     first-seen order.
    let mut content_to_new_off: HashMap<&[u8], u32> = HashMap::new();
    let mut old_to_new: HashMap<u32, u32> = HashMap::new();
    let mut new_abbrev: Vec<u8> = Vec::with_capacity(abbrev_data.len());
    for &old_off in &distinct_offsets {
        let bytes = table_bytes[&old_off];
        let new_off = *content_to_new_off.entry(bytes).or_insert_with(|| {
            let v = new_abbrev.len() as u32;
            new_abbrev.extend_from_slice(bytes);
            v
        });
        old_to_new.insert(old_off, new_off);
    }
    if new_abbrev.len() >= da_size as usize {
        // No reduction — skip (avoids a pointless splice).
        return Ok(None);
    }

    // --- Build output: patch CU headers, splice new .debug_abbrev,
    //     shift tail up, update SHDR + ehdr.
    let delta = da_size as usize - new_abbrev.len();
    let mut out = elf.to_vec();

    for c in &cu_refs {
        let new_off = old_to_new[&c.old_abbrev_offset];
        out[c.abbrev_off_field_pos..c.abbrev_off_field_pos + 4]
            .copy_from_slice(&new_off.to_le_bytes());
    }

    let tail_len = out.len() - da_end;
    let new_tail_start = da_start + new_abbrev.len();
    out.copy_within(da_end..da_end + tail_len, new_tail_start);
    out[da_start..da_start + new_abbrev.len()].copy_from_slice(&new_abbrev);
    out.truncate(new_tail_start + tail_len);

    // --- SHDR: .debug_abbrev sh_size shrinks; every section with
    //     sh_offset > da_start shifts up by delta. ehdr.e_shoff too.
    let e_shoff = header.e_shoff(endian) as usize;
    let e_shentsize = header.e_shentsize(endian) as usize;
    let e_shnum = header.e_shnum(endian) as usize;
    let shdr_moved = e_shoff > da_start;
    let shdr_pos_in_out = if shdr_moved { e_shoff - delta } else { e_shoff };
    for i in 0..e_shnum {
        let entry_off = shdr_pos_in_out + i * e_shentsize;
        if entry_off + e_shentsize > out.len() {
            crate::bail!("elf_abbrev_dedup: SHDR entry {i} OOB after splice");
        }
        let entry_bytes = &mut out[entry_off..entry_off + e_shentsize];
        let entry = unsafe { &mut *(entry_bytes.as_mut_ptr() as *mut SectionHeader64<Endianness>) };
        if i == da_idx {
            entry.sh_size.set(endian, new_abbrev.len() as u64);
            continue;
        }
        let sh_offset = entry.sh_offset.get(endian) as usize;
        if sh_offset > da_start {
            entry.sh_offset.set(endian, (sh_offset - delta) as u64);
        }
    }
    if shdr_moved {
        out[40..48].copy_from_slice(&(shdr_pos_in_out as u64).to_le_bytes());
    }

    Ok(Some(out))
}

/// Walk one abbrev table starting at `start` in `data`; return the
/// length (including the null-code terminator). `None` on malformed
/// input — callers treat that as "skip this pass".
fn scan_abbrev_table(data: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    loop {
        let (code, n) = read_uleb(data, pos)?;
        pos += n;
        if code == 0 {
            return Some(pos - start);
        }
        let (_tag, n) = read_uleb(data, pos)?;
        pos += n;
        if pos >= data.len() {
            return None;
        }
        pos += 1; // has_children byte
        loop {
            let (name, n) = read_uleb(data, pos)?;
            pos += n;
            let (form, n) = read_uleb(data, pos)?;
            pos += n;
            // DW_FORM_implicit_const carries an SLEB128 payload.
            if form == 0x21 {
                let n = skip_leb(data, pos)?;
                pos += n;
            }
            if name == 0 && form == 0 {
                break;
            }
        }
    }
}

fn read_uleb(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut i = 0usize;
    loop {
        let b = *data.get(pos + i)?;
        i += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, i));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

fn skip_leb(data: &[u8], pos: usize) -> Option<usize> {
    let mut i = 0usize;
    loop {
        let b = *data.get(pos + i)?;
        i += 1;
        if b & 0x80 == 0 {
            return Some(i);
        }
        if i > 10 {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uleb(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut x = v;
        loop {
            let mut b = (x & 0x7f) as u8;
            x >>= 7;
            if x != 0 {
                b |= 0x80;
            }
            out.push(b);
            if x == 0 {
                return out;
            }
        }
    }

    /// Build one abbrev declaration: code, tag, has_children, (attr,form)*, (0,0).
    fn abbrev(code: u64, tag: u64, children: u8, attrs: &[(u64, u64)]) -> Vec<u8> {
        let mut out = uleb(code);
        out.extend(uleb(tag));
        out.push(children);
        for &(n, f) in attrs {
            out.extend(uleb(n));
            out.extend(uleb(f));
        }
        out.extend(uleb(0));
        out.extend(uleb(0));
        out
    }

    fn table(decls: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for d in decls {
            out.extend_from_slice(d);
        }
        out.push(0); // null abbrev code terminator
        out
    }

    #[test]
    fn scan_abbrev_table_finds_terminator() {
        let t = table(&[abbrev(1, 0x11, 1, &[(0x03, 0x08)])]);
        assert_eq!(scan_abbrev_table(&t, 0), Some(t.len()));
    }

    #[test]
    fn scan_abbrev_table_handles_implicit_const() {
        // DW_FORM_implicit_const = 0x21 followed by SLEB128 payload
        let mut decl = uleb(1); // code
        decl.extend(uleb(0x11)); // tag
        decl.push(0); // no children
        decl.extend(uleb(0x03)); // name
        decl.extend(uleb(0x21)); // form = implicit_const
        decl.extend(uleb(0x40)); // SLEB128 const (0x40 encodes as one byte)
        decl.extend(uleb(0));
        decl.extend(uleb(0));
        let t = {
            let mut out = decl;
            out.push(0);
            out
        };
        assert_eq!(scan_abbrev_table(&t, 0), Some(t.len()));
    }

    #[test]
    fn scan_abbrev_table_rejects_truncated() {
        // Starts an abbrev but never terminates.
        let mut bad = uleb(1);
        bad.extend(uleb(0x11));
        // missing has_children
        assert_eq!(scan_abbrev_table(&bad, 0), None);
    }

    #[test]
    fn dedup_collapses_identical_tables() {
        let t = table(&[abbrev(1, 0x11, 0, &[(0x03, 0x08)])]);
        // Simulated .debug_abbrev: two back-to-back copies.
        let da = {
            let mut out = t.clone();
            out.extend_from_slice(&t);
            out
        };
        // Two CUs referencing offsets 0 and t.len() respectively.
        let off0 = 0u32;
        let off1 = t.len() as u32;
        let distinct = [off0, off1];

        let mut table_bytes: HashMap<u32, &[u8]> = HashMap::new();
        for &off in &distinct {
            let length = scan_abbrev_table(&da, off as usize).unwrap();
            table_bytes.insert(off, &da[off as usize..off as usize + length]);
        }
        let mut content_to_new_off: HashMap<&[u8], u32> = HashMap::new();
        let mut old_to_new: HashMap<u32, u32> = HashMap::new();
        let mut new_abbrev: Vec<u8> = Vec::new();
        for &old in &distinct {
            let bytes = table_bytes[&old];
            let new_off = *content_to_new_off.entry(bytes).or_insert_with(|| {
                let v = new_abbrev.len() as u32;
                new_abbrev.extend_from_slice(bytes);
                v
            });
            old_to_new.insert(old, new_off);
        }
        assert_eq!(new_abbrev.len(), t.len());
        assert_eq!(old_to_new[&off0], 0);
        assert_eq!(old_to_new[&off1], 0); // collapsed
    }
}
