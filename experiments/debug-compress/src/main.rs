//! Post-processor: take an ELF, zstd-compress every non-`SHF_ALLOC`
//! `.debug_*` section in place with `SHF_COMPRESSED` semantics,
//! shift subsequent sections forward, truncate the file.
//!
//! Downstream tools (gdb, lldb, objdump, addr2line, dsymutil)
//! recognise `SHF_COMPRESSED` transparently via the `Elf64_Chdr`
//! header we prepend to each compressed section. Runtime
//! execution is unaffected — `ld.so` never reads `.debug_*`.
//!
//! Usage:
//!   debug-compress <input.elf> <output.elf> [--level=<N>]
//!
//! Default zstd level is 3 (balance of speed + ratio). Higher
//! levels compress slower but tighter.
//!
//! What this tool does NOT touch:
//!   - SHF_ALLOC sections (PT_LOAD contents).
//!   - Mach-O binaries.
//!   - Already-compressed sections (we detect SHF_COMPRESSED and skip).
//!
//! Safety:
//!   - Section bytes written before the SHDR table is rewritten, so a
//!     truncation mid-op leaves either a valid old ELF or a valid new
//!     one.
//!   - `shdr_idx` / `shstrtab_idx` used to find section names stay
//!     valid because we don't re-index sections, only resize + shift
//!     them.

use object::Endianness;
use object::elf::FileHeader64;
use object::elf::SectionHeader64;
use object::read::elf::FileHeader;
use object::read::elf::SectionHeader;
use rayon::prelude::*;
use std::env;
use std::fs;
use std::process::ExitCode;

/// ELF compression header (Elf64_Chdr). Precedes compressed bytes
/// inside an `SHF_COMPRESSED` section. 24 bytes, little-endian on
/// ELFCLASS64.
const CHDR_SIZE: usize = 24;

/// `ch_type = ELFCOMPRESS_ZSTD`. Standardised in gABI spec.
const ELFCOMPRESS_ZSTD: u32 = 2;

/// `SHF_COMPRESSED` — section content carries an `Elf_Chdr` + zstd
/// stream instead of raw payload. Readers honour this flag.
const SHF_COMPRESSED: u64 = 1 << 11;

/// `SHF_ALLOC` — section occupies memory during execution. We don't
/// touch these; compressing alloc sections would need runtime
/// decompression which `ld.so` doesn't do.
const SHF_ALLOC: u64 = 1 << 1;

fn write_chdr_zstd(dst: &mut [u8], decompressed_size: u64, addralign: u64) {
    // Elf64_Chdr layout:
    //   uint32_t ch_type
    //   uint32_t ch_reserved  // padding on ELFCLASS64
    //   uint64_t ch_size      // size of decompressed section
    //   uint64_t ch_addralign // alignment of decompressed section
    assert!(dst.len() >= CHDR_SIZE);
    dst[0..4].copy_from_slice(&ELFCOMPRESS_ZSTD.to_le_bytes());
    dst[4..8].copy_from_slice(&0u32.to_le_bytes()); // reserved
    dst[8..16].copy_from_slice(&decompressed_size.to_le_bytes());
    dst[16..24].copy_from_slice(&addralign.to_le_bytes());
}

#[derive(Debug, Clone)]
struct SectionPlan {
    /// Original section header index.
    shdr_idx: usize,
    /// Original file offset.
    old_offset: usize,
    /// Original section size on disk.
    old_size: usize,
    /// Original `sh_flags` (we add `SHF_COMPRESSED` on emit).
    old_flags: u64,
    /// Alignment carried into `ch_addralign` so decompressors can
    /// restore expected alignment. Pulled from `sh_addralign`.
    addralign: u64,
    /// Compressed content: chdr + zstd stream. Filled in after the
    /// parallel compression pass.
    compressed: Vec<u8>,
}

fn plan_debug_sections(
    data: &[u8],
    endian: Endianness,
) -> Result<Vec<SectionPlan>, String> {
    let header = FileHeader64::<Endianness>::parse(data)
        .map_err(|e| format!("parse ehdr: {e:?}"))?;
    let sections = header
        .sections(endian, data)
        .map_err(|e| format!("parse sections: {e:?}"))?;

    let mut plans = Vec::new();
    for (idx, sect) in sections.iter().enumerate() {
        let name = sections
            .section_name(endian, sect)
            .map_err(|e| format!("section_name {idx}: {e:?}"))?;
        if !name.starts_with(b".debug_") {
            continue;
        }
        let flags = sect.sh_flags(endian);
        if flags & SHF_ALLOC != 0 {
            // Loaded at runtime; can't compress without runtime support.
            continue;
        }
        if flags & SHF_COMPRESSED != 0 {
            // Already compressed; skip (idempotent).
            continue;
        }
        let size = sect.sh_size(endian) as usize;
        if size < CHDR_SIZE + 64 {
            // Trivially small — compressed form with chdr overhead
            // would be bigger than original.
            continue;
        }
        plans.push(SectionPlan {
            shdr_idx: idx,
            old_offset: sect.sh_offset(endian) as usize,
            old_size: size,
            old_flags: flags,
            addralign: sect.sh_addralign(endian),
            compressed: Vec::new(),
        });
    }
    Ok(plans)
}

fn compress_section(
    data: &[u8],
    plan: &SectionPlan,
    level: i32,
) -> Result<Vec<u8>, String> {
    let decompressed = &data[plan.old_offset..plan.old_offset + plan.old_size];
    let z = zstd::encode_all(decompressed, level)
        .map_err(|e| format!("zstd compress idx {}: {}", plan.shdr_idx, e))?;
    let mut out = Vec::with_capacity(CHDR_SIZE + z.len());
    out.resize(CHDR_SIZE, 0);
    write_chdr_zstd(&mut out, plan.old_size as u64, plan.addralign);
    out.extend_from_slice(&z);
    Ok(out)
}

#[derive(Debug)]
struct Compacted {
    bytes: Vec<u8>,
    old_size: usize,
    new_size: usize,
    sections_compressed: usize,
    debug_bytes_before: usize,
    debug_bytes_after: usize,
}

fn compact_elf64(input: &[u8], level: i32) -> Result<Compacted, String> {
    let endian = Endianness::Little;

    // ---- Parse header + find debug sections + read shdr layout ----
    let (e_shoff, e_shentsize, e_shnum, mut plans) = {
        let header = FileHeader64::<Endianness>::parse(input)
            .map_err(|e| format!("parse ehdr: {e:?}"))?;
        let plans = plan_debug_sections(input, endian)?;
        (
            header.e_shoff(endian) as usize,
            header.e_shentsize(endian) as usize,
            header.e_shnum(endian) as usize,
            plans,
        )
    };
    if plans.is_empty() {
        return Err("no compressible .debug_* sections".into());
    }

    // ---- Compress in parallel -------------------------------------
    let compressed: Result<Vec<Vec<u8>>, String> = plans
        .par_iter()
        .map(|plan| compress_section(input, plan, level))
        .collect();
    let compressed = compressed?;
    for (plan, comp) in plans.iter_mut().zip(compressed.into_iter()) {
        plan.compressed = comp;
    }

    // ---- Drop plans whose compressed form isn't smaller ----------
    // Keep the original section intact for those (no win, would hurt).
    plans.retain(|p| p.compressed.len() < p.old_size);
    if plans.is_empty() {
        return Err("no compressible .debug_* sections after zstd".into());
    }

    // Sort plans by old_offset so we emit in file order.
    plans.sort_by_key(|p| p.old_offset);

    // ---- Build the new file buffer ------------------------------
    // Walk the input file; for each section in `plans`, replace its
    // bytes with `compressed`; for non-compressed regions, copy
    // through. We build the new file as a single Vec<u8>, which lets
    // the rest of the surgery (shdr rewrite, ehdr.e_shoff) just index
    // into the new buffer.
    let mut new_file = Vec::with_capacity(input.len());
    let mut cursor = 0usize;
    // Track how much each plan's new_offset is in new_file.
    let mut new_offsets = Vec::with_capacity(plans.len());
    for plan in &plans {
        if plan.old_offset > cursor {
            new_file.extend_from_slice(&input[cursor..plan.old_offset]);
        }
        let new_off = new_file.len();
        new_file.extend_from_slice(&plan.compressed);
        new_offsets.push(new_off);
        cursor = plan.old_offset + plan.old_size;
    }
    if cursor < input.len() {
        new_file.extend_from_slice(&input[cursor..]);
    }

    // Running shift for each section past a compressed one. A byte at
    // old_offset `O` in the input is at `O - shift_at(O)` in new_file.
    // shift_at(O) = Σ (plan.old_size - plan.compressed.len()) for plans
    // where plan.old_offset + plan.old_size <= O.
    let shift_at = |old_off: usize| -> usize {
        let mut shift = 0usize;
        for plan in &plans {
            if plan.old_offset + plan.old_size <= old_off {
                shift += plan.old_size - plan.compressed.len();
            }
        }
        shift
    };

    let debug_bytes_before: usize = plans.iter().map(|p| p.old_size).sum();
    let debug_bytes_after: usize = plans.iter().map(|p| p.compressed.len()).sum();

    // ---- Update each compressed section's shdr entry + every later
    //      shdr's sh_offset. e_shoff likewise shifts by the total
    //      savings if it was after at least one compressed section.
    // ---------------------------------------------------------------
    let new_shoff = if e_shoff > 0 {
        e_shoff.saturating_sub(shift_at(e_shoff))
    } else {
        0
    };

    let compressed_by_idx: std::collections::HashMap<usize, (usize, u64, u64)> = plans
        .iter()
        .map(|p| (p.shdr_idx, (p.compressed.len(), p.old_flags | SHF_COMPRESSED, p.addralign.max(1))))
        .collect();

    for i in 0..e_shnum {
        let entry_off = new_shoff + i * e_shentsize;
        if entry_off + e_shentsize > new_file.len() {
            return Err(format!("SHDR {i} out of file"));
        }
        let entry_bytes = &mut new_file[entry_off..entry_off + e_shentsize];
        // SAFETY: we just bounded the slice to one SHDR entry's size;
        // `SectionHeader64<Endianness>` is `#[repr(C)]` plain data.
        let entry =
            unsafe { &mut *(entry_bytes.as_mut_ptr() as *mut SectionHeader64<Endianness>) };
        let sh_offset = entry.sh_offset.get(endian) as usize;
        // Shift sh_offset for any section other than NOBITS / offset==0.
        if sh_offset > 0 {
            let shifted = sh_offset.saturating_sub(shift_at(sh_offset));
            entry.sh_offset.set(endian, shifted as u64);
        }
        if let Some(&(new_size, new_flags, _)) = compressed_by_idx.get(&i) {
            entry.sh_size.set(endian, new_size as u64);
            entry.sh_flags.set(endian, new_flags);
            // ch_addralign inside Chdr carries the original; sh_addralign
            // gets set to 1 so tools don't pad the compressed payload.
            entry.sh_addralign.set(endian, 1);
        }
    }

    // ---- Update e_shoff in ehdr --------------------------------------
    // ELF64 Ehdr: e_shoff lives at byte offset 40.
    new_file[40..48].copy_from_slice(&(new_shoff as u64).to_le_bytes());

    Ok(Compacted {
        new_size: new_file.len(),
        old_size: input.len(),
        sections_compressed: plans.len(),
        debug_bytes_before,
        debug_bytes_after,
        bytes: new_file,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if !(3..=4).contains(&args.len()) {
        eprintln!("usage: {} <input.elf> <output.elf> [--level=<N>]", args[0]);
        return ExitCode::from(1);
    }
    let in_path = &args[1];
    let out_path = &args[2];
    let level: i32 = args
        .get(3)
        .and_then(|a| a.strip_prefix("--level="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);

    let bytes = match fs::read(in_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {in_path}: {e}");
            return ExitCode::from(1);
        }
    };

    let result = match compact_elf64(&bytes, level) {
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
        "compressed {} .debug_* sections at zstd level {}",
        result.sections_compressed, level
    );
    println!(
        "debug total: {} -> {} bytes ({:.2}x ratio, {:.2}% of original)",
        result.debug_bytes_before,
        result.debug_bytes_after,
        result.debug_bytes_before as f64 / result.debug_bytes_after as f64,
        100.0 * result.debug_bytes_after as f64 / result.debug_bytes_before as f64,
    );
    println!(
        "file:        {} -> {} bytes ({:.2}% smaller)",
        result.old_size,
        result.new_size,
        100.0 * (result.old_size - result.new_size) as f64 / result.old_size as f64,
    );
    ExitCode::SUCCESS
}
