//! Post-processor: read an ELF, suffix-pack its `.strtab`, rewrite
//! every `.symtab` `st_name` to point at the new packed offsets,
//! shift any sections that lived after `.strtab` forward to close
//! the gap, and emit a smaller ELF.
//!
//! `.strtab` is non-`SHF_ALLOC` — never loaded by `ld.so` at
//! runtime. Shrinking it never affects PT_LOAD segments or VM
//! addresses, so we only have to update file offsets in the
//! section header table + ELF header. That keeps the surgery
//! mechanical.
//!
//! What this tool does NOT touch (yet):
//!   - `.dynstr` (dynamic string table — referenced by ld.so at
//!     load time; involves DT_NEEDED, DT_RPATH, DT_RUNPATH,
//!     verdef/verneed, dynsym).
//!   - Mach-O LC_SYMTAB string tables.
//!   - Anything inside PT_LOAD segments.
//!
//! Usage:
//!   strtab-compact <input.elf> <output.elf>
//!
//! Prints before/after sizes + savings to stdout.

use object::Endianness;
use object::elf::FileHeader64;
use object::elf::SectionHeader64;
use object::elf::Sym64;
use object::read::elf::FileHeader;
use object::read::elf::SectionHeader;
use rayon::slice::ParallelSliceMut;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::process::ExitCode;

/// Suffix-pack a set of NUL-terminated strings.
///
/// Returns:
///   * `bytes`: packed buffer with leading NUL + each emitted owner
///     followed by its NUL.
///   * `offsets`: name → offset map, including absorbed entries.
fn pack(names: Vec<Vec<u8>>) -> (Vec<u8>, HashMap<Vec<u8>, u32>) {
    let set: BTreeSet<Vec<u8>> = names.into_iter().collect();
    let mut unique: Vec<Vec<u8>> = set.into_iter().collect();
    unique.retain(|s| !s.is_empty());
    unique.par_sort_by(|a, b| a.iter().rev().cmp(b.iter().rev()));

    let n = unique.len();
    let mut ownership: Vec<Option<usize>> = vec![None; n];
    for i in 0..n.saturating_sub(1) {
        if unique[i + 1].ends_with(&unique[i]) {
            ownership[i] = Some(i + 1);
        }
    }

    let mut bytes: Vec<u8> = Vec::with_capacity(1 + unique.iter().map(|s| s.len() + 1).sum::<usize>());
    bytes.push(0);

    let mut emitted_offsets = vec![u32::MAX; n];
    for i in 0..n {
        if ownership[i].is_none() {
            emitted_offsets[i] = bytes.len() as u32;
            bytes.extend_from_slice(&unique[i]);
            bytes.push(0);
        }
    }

    let mut offsets: HashMap<Vec<u8>, u32> = HashMap::with_capacity(n + 1);
    offsets.insert(Vec::new(), 0);
    for i in 0..n {
        let mut owner = i;
        while let Some(next) = ownership[owner] {
            owner = next;
        }
        let owner_offset = emitted_offsets[owner];
        let owner_len = unique[owner].len() as u32;
        let self_len = unique[i].len() as u32;
        let my_offset = owner_offset + (owner_len - self_len);
        offsets.insert(unique[i].clone(), my_offset);
    }

    (bytes, offsets)
}

#[derive(Debug)]
struct Compacted {
    bytes: Vec<u8>,
    old_size: usize,
    new_size: usize,
    strtab_old_size: usize,
    strtab_new_size: usize,
}

fn compact_elf64(input: &[u8]) -> Result<Compacted, String> {
    let mut data = input.to_vec();
    let endian = Endianness::Little;

    // ---- Parse ELF header + section table -------------------------
    //
    // Extract everything we need into owned values so the immutable
    // borrow of `data` used to parse doesn't block the mutation
    // pass that comes later.
    let (
        strtab_idx,
        _symtab_idx,
        strtab_offset,
        strtab_old_size,
        symtab_offset,
        symtab_size,
        e_shoff,
        e_shentsize,
        e_shnum,
    ) = {
        let header = FileHeader64::<Endianness>::parse(&*data)
            .map_err(|e| format!("parse ehdr: {e:?}"))?;
        let _ = header.endian().map_err(|e| format!("endian: {e:?}"))?;
        let sections = header
            .sections(endian, &*data)
            .map_err(|e| format!("parse sections: {e:?}"))?;

        let mut strtab_idx: Option<usize> = None;
        let mut symtab_idx: Option<usize> = None;
        for (idx, sect) in sections.iter().enumerate() {
            let name = sections
                .section_name(endian, sect)
                .map_err(|e| format!("section_name {idx}: {e:?}"))?;
            if name == b".strtab" {
                strtab_idx = Some(idx);
            } else if name == b".symtab" {
                symtab_idx = Some(idx);
            }
        }
        let strtab_idx = strtab_idx.ok_or("no .strtab section")?;
        let symtab_idx = symtab_idx.ok_or("no .symtab section")?;

        let strtab_sect = sections.section(object::SectionIndex(strtab_idx)).unwrap();
        let symtab_sect = sections.section(object::SectionIndex(symtab_idx)).unwrap();
        (
            strtab_idx,
            symtab_idx,
            strtab_sect.sh_offset(endian) as usize,
            strtab_sect.sh_size(endian) as usize,
            symtab_sect.sh_offset(endian) as usize,
            symtab_sect.sh_size(endian) as usize,
            header.e_shoff(endian) as usize,
            header.e_shentsize(endian) as usize,
            header.e_shnum(endian) as usize,
        )
    };

    // ---- Extract strings from current strtab ----------------------
    let strtab_bytes = &data[strtab_offset..strtab_offset + strtab_old_size];
    // Map from old byte-offset in strtab → name bytes (excluding NUL)
    // for all strings currently referenced. We only need the strings
    // that symtab actually points at; gathering those + suffix-packing
    // them keeps the packed result tight.
    let mut referenced_names: Vec<Vec<u8>> = Vec::new();
    let mut old_offset_to_name: HashMap<u32, Vec<u8>> = HashMap::new();

    let symtab_entries = symtab_size / std::mem::size_of::<Sym64<Endianness>>();
    let symtab_buf = &data[symtab_offset..symtab_offset + symtab_size];
    let symtab_slice = unsafe {
        std::slice::from_raw_parts(symtab_buf.as_ptr() as *const Sym64<Endianness>, symtab_entries)
    };
    for sym in symtab_slice {
        let off = sym.st_name.get(endian);
        if off == 0 {
            continue;
        }
        if old_offset_to_name.contains_key(&off) {
            continue;
        }
        let start = off as usize;
        if start >= strtab_bytes.len() {
            return Err(format!("st_name {off} out of strtab range"));
        }
        let nul = strtab_bytes[start..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| format!("no NUL after st_name {off}"))?;
        let name = strtab_bytes[start..start + nul].to_vec();
        if name.is_empty() {
            continue;
        }
        old_offset_to_name.insert(off, name.clone());
        referenced_names.push(name);
    }

    // ---- Pack ----------------------------------------------------
    let (packed_bytes, new_offsets) = pack(referenced_names);
    let strtab_new_size = packed_bytes.len();

    if strtab_new_size >= strtab_old_size {
        return Err(format!(
            "no win: packed = {} >= original = {}",
            strtab_new_size, strtab_old_size
        ));
    }
    let delta = strtab_old_size - strtab_new_size;

    // Map old offset → new offset by walking the names we collected.
    let mut old_to_new: HashMap<u32, u32> = HashMap::with_capacity(old_offset_to_name.len() + 1);
    old_to_new.insert(0, 0);
    for (old_off, name) in &old_offset_to_name {
        let new_off = *new_offsets
            .get(name)
            .ok_or_else(|| format!("packer dropped {:?}", String::from_utf8_lossy(name)))?;
        old_to_new.insert(*old_off, new_off);
    }

    // ---- Rewrite symtab st_name fields ---------------------------
    // Operate on a mutable view of the symtab inside `data`.
    let symtab_mut = &mut data[symtab_offset..symtab_offset + symtab_size];
    let symtab_slice_mut = unsafe {
        std::slice::from_raw_parts_mut(
            symtab_mut.as_mut_ptr() as *mut Sym64<Endianness>,
            symtab_entries,
        )
    };
    for sym in symtab_slice_mut.iter_mut() {
        let old_off = sym.st_name.get(endian);
        if let Some(&new_off) = old_to_new.get(&old_off) {
            sym.st_name.set(endian, new_off);
        } else if old_off != 0 {
            return Err(format!(
                "symtab references st_name {old_off} but no mapping"
            ));
        }
    }

    // ---- Plan the file shift -------------------------------------
    // Anything with file offset > strtab_offset + strtab_old_size shifts
    // backwards by `delta`. The SHDR table's offset (e_shoff) likewise.
    let strtab_end = strtab_offset + strtab_old_size;
    let file_size = data.len();

    // Step 1: physically move bytes from [strtab_end .. file_size] to
    // [strtab_end - delta .. file_size - delta]. `copy_within` handles
    // overlap correctly (memmove semantics).
    if file_size > strtab_end {
        data.copy_within(strtab_end..file_size, strtab_end - delta);
    }

    // Step 2: write packed strtab into [strtab_offset .. strtab_offset + strtab_new_size].
    data[strtab_offset..strtab_offset + strtab_new_size].copy_from_slice(&packed_bytes);

    // Step 3: truncate to the new file size.
    let new_file_size = file_size - delta;
    data.truncate(new_file_size);

    // ---- Update SHDR table fields --------------------------------
    // Re-locate the SHDR table at its new (potentially shifted) position.
    let shoff_new = if e_shoff > strtab_end {
        e_shoff - delta
    } else {
        e_shoff
    };

    // Walk SHDR entries directly in `data`.
    for i in 0..e_shnum {
        let entry_off = shoff_new + i * e_shentsize;
        if entry_off + e_shentsize > data.len() {
            return Err(format!("SHDR {i} entry out of file"));
        }
        let entry_bytes = &mut data[entry_off..entry_off + e_shentsize];
        let entry = unsafe { &mut *(entry_bytes.as_mut_ptr() as *mut SectionHeader64<Endianness>) };
        let sh_offset = entry.sh_offset.get(endian) as usize;
        let sh_size = entry.sh_size.get(endian) as usize;

        if i == strtab_idx {
            entry.sh_size.set(endian, strtab_new_size as u64);
        } else if sh_offset > strtab_end {
            entry
                .sh_offset
                .set(endian, (sh_offset - delta) as u64);
        } else if sh_offset == strtab_end {
            // Section starts exactly where strtab ends → also shifts.
            entry
                .sh_offset
                .set(endian, (sh_offset - delta) as u64);
        }
        let _ = sh_size;
    }

    // ---- Update e_shoff in ehdr ----------------------------------
    // ehdr.e_shoff lives at offset 40 in Elf64_Ehdr. Write a u64 LE.
    let e_shoff_field_off = 40usize;
    data[e_shoff_field_off..e_shoff_field_off + 8]
        .copy_from_slice(&(shoff_new as u64).to_le_bytes());

    Ok(Compacted {
        bytes: data,
        old_size: input.len(),
        new_size: new_file_size,
        strtab_old_size,
        strtab_new_size,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <input.elf> <output.elf>", args[0]);
        return ExitCode::from(1);
    }
    let in_path = &args[1];
    let out_path = &args[2];

    let bytes = match fs::read(in_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {in_path}: {e}");
            return ExitCode::from(1);
        }
    };

    let result = match compact_elf64(&bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("compact failed: {e}");
            return ExitCode::from(2);
        }
    };

    if let Err(e) = fs::write(out_path, &result.bytes) {
        eprintln!("write {out_path}: {e}");
        return ExitCode::from(1);
    }

    println!(
        "strtab: {} -> {} bytes ({:.2}% smaller)",
        result.strtab_old_size,
        result.strtab_new_size,
        100.0
            * (result.strtab_old_size - result.strtab_new_size) as f64
            / result.strtab_old_size as f64
    );
    println!(
        "file:   {} -> {} bytes ({:.2}% smaller)",
        result.old_size,
        result.new_size,
        100.0 * (result.old_size - result.new_size) as f64 / result.old_size as f64
    );
    ExitCode::SUCCESS
}
