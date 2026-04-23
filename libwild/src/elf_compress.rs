//! `--compress-debug-sections=zstd` post-write pass.
//!
//! Runs after [`elf_writer::write`] has populated the output buffer
//! but before the file is finalised. Operates directly on the
//! `SizedOutput`'s mutable mmap-backed (or in-memory) buffer:
//!
//!   1. Walk the SHDR table; pick out every non-`SHF_ALLOC`
//!      `.debug_*` section that isn't already `SHF_COMPRESSED`
//!      and whose payload is large enough to compress profitably.
//!   2. For each picked section, in parallel: zstd-compress the
//!      payload and prepend an `Elf64_Chdr` header.
//!   3. Discard any plan whose compressed size isn't strictly
//!      smaller than the original — leaves the original section
//!      untouched.
//!   4. Build the new file as one rewrite: copy through unchanged
//!      regions, splice in compressed payloads in section order.
//!   5. Walk SHDR a second time to rewrite every `sh_offset`
//!      (shifted forward by the running savings up to that section)
//!      and to update each compressed section's `sh_size` /
//!      `sh_flags` / `sh_addralign`.
//!   6. Update `e_shoff` in the ELF header.
//!   7. Tell `SizedOutput` the new final file size via
//!      [`SizedOutput::set_final_size`] — the same mechanism
//!      Mach-O uses post-codesign.
//!
//! `SHF_ALLOC` sections are deliberately untouched: their bytes are
//! mapped at runtime by `ld.so`, and there is no in-kernel zstd
//! decompressor.
//!
//! Downstream tools (gdb 10+, lldb 12+, addr2line, objdump from
//! binutils 2.40+) honour the `SHF_COMPRESSED` flag and decompress
//! transparently.
//!
//! Determinism: zstd level 3 with no dictionary is deterministic
//! given the same input bytes; the parallel compression doesn't
//! affect output bytes (each section is independent). The only
//! non-determinism source — running shift arithmetic order — uses
//! a sort by file offset before reduction.

use crate::args::elf::DebugCompression;
use crate::error::Result;
use crate::file_writer::SizedOutput;
use object::Endianness;
use object::elf::FileHeader64;
use object::elf::SectionHeader64;
use object::read::elf::FileHeader;
use object::read::elf::SectionHeader;
use rayon::prelude::*;

/// `Elf64_Chdr` size on disk. Layout: ch_type(u32) + reserved(u32)
/// + ch_size(u64) + ch_addralign(u64) = 24 bytes.
const CHDR_SIZE: usize = 24;

/// `ch_type = ELFCOMPRESS_ZSTD`. Standardised in the gABI.
const ELFCOMPRESS_ZSTD: u32 = 2;

/// `SHF_COMPRESSED` — the section content is an `Elf_Chdr` + a
/// compressed stream rather than raw payload. Readers honour this
/// flag.
const SHF_COMPRESSED: u64 = 1 << 11;

/// `SHF_ALLOC` — section is loaded into memory at runtime. We never
/// touch these.
const SHF_ALLOC: u64 = 1 << 1;

/// Threshold below which compression isn't worth attempting. The
/// 24-byte chdr alone exceeds tiny payloads.
const MIN_COMPRESSIBLE: usize = 256;

/// Default zstd level. Trades compress time for ratio. Level 3 is
/// the zstd library default.
const ZSTD_LEVEL: i32 = 3;

/// Top-level entry point. No-op when the compression mode is
/// `DebugCompression::None`. Returns `Ok(())` on success or when
/// no `.debug_*` sections were eligible.
pub(crate) fn compress_debug_sections(
    sized_output: &mut SizedOutput,
    mode: DebugCompression,
) -> Result {
    match mode {
        DebugCompression::None => Ok(()),
        DebugCompression::Zstd => compress_zstd(sized_output),
    }
}

#[derive(Debug, Clone)]
struct Plan {
    shdr_idx: usize,
    old_offset: usize,
    old_size: usize,
    old_flags: u64,
    addralign: u64,
    /// Filled in after the compress pass. `None` means the
    /// compressed form wasn't smaller, so this section is left
    /// alone.
    compressed: Option<Vec<u8>>,
}

fn compress_zstd(sized_output: &mut SizedOutput) -> Result {
    let endian = Endianness::Little;

    // ---- Phase 1: discover candidate sections + capture SHDR layout
    let (e_shoff, e_shentsize, e_shnum, mut plans) = {
        let bytes: &[u8] = &sized_output.out;
        let header = FileHeader64::<Endianness>::parse(bytes)
            .map_err(|e| crate::error!("compress: parse ehdr: {e:?}"))?;
        let sections = header
            .sections(endian, bytes)
            .map_err(|e| crate::error!("compress: parse sections: {e:?}"))?;

        let mut plans = Vec::new();
        for (idx, sect) in sections.iter().enumerate() {
            let name = sections
                .section_name(endian, sect)
                .map_err(|e| crate::error!("compress: section_name {idx}: {e:?}"))?;
            if !name.starts_with(b".debug_") {
                continue;
            }
            let flags = sect.sh_flags(endian);
            if flags & SHF_ALLOC != 0 || flags & SHF_COMPRESSED != 0 {
                continue;
            }
            let size = sect.sh_size(endian) as usize;
            if size < MIN_COMPRESSIBLE {
                continue;
            }
            plans.push(Plan {
                shdr_idx: idx,
                old_offset: sect.sh_offset(endian) as usize,
                old_size: size,
                old_flags: flags,
                addralign: sect.sh_addralign(endian),
                compressed: None,
            });
        }
        (
            header.e_shoff(endian) as usize,
            header.e_shentsize(endian) as usize,
            header.e_shnum(endian) as usize,
            plans,
        )
    };

    if plans.is_empty() {
        return Ok(());
    }

    // ---- Phase 2: compress each plan in parallel ----
    let input_buf: &[u8] = &sized_output.out;
    let compressed: Vec<Result<Vec<u8>>> = plans
        .par_iter()
        .map(|plan| {
            let payload = &input_buf[plan.old_offset..plan.old_offset + plan.old_size];
            let z = zstd::encode_all(payload, ZSTD_LEVEL).map_err(|e| {
                crate::error!("compress: zstd .debug_* @ shdr idx {}: {e}", plan.shdr_idx)
            })?;
            // Plan accepted only if the chdr+stream is strictly
            // smaller than the original.
            if CHDR_SIZE + z.len() >= plan.old_size {
                return Ok(Vec::new());
            }
            let mut out = Vec::with_capacity(CHDR_SIZE + z.len());
            out.resize(CHDR_SIZE, 0);
            write_chdr_zstd(&mut out, plan.old_size as u64, plan.addralign);
            out.extend_from_slice(&z);
            Ok(out)
        })
        .collect();

    for (plan, c) in plans.iter_mut().zip(compressed.into_iter()) {
        let bytes = c?;
        if !bytes.is_empty() {
            plan.compressed = Some(bytes);
        }
    }

    // Drop plans where compression didn't help.
    plans.retain(|p| p.compressed.is_some());
    if plans.is_empty() {
        return Ok(());
    }

    // Sort plans by file offset — the rewrite pass walks them in
    // file order and the shift arithmetic depends on it.
    plans.sort_by_key(|p| p.old_offset);

    // ---- Phase 3: rewrite the buffer ----
    let old_file_size = sized_output.out.len();
    let mut new_file = Vec::with_capacity(old_file_size);
    let mut cursor = 0usize;
    for plan in &plans {
        if plan.old_offset > cursor {
            new_file.extend_from_slice(&sized_output.out[cursor..plan.old_offset]);
        }
        new_file.extend_from_slice(plan.compressed.as_ref().unwrap());
        cursor = plan.old_offset + plan.old_size;
    }
    if cursor < old_file_size {
        new_file.extend_from_slice(&sized_output.out[cursor..]);
    }

    // For a file offset `O` in the old layout, the new offset is
    // `O - shift_at(O)` where shift_at sums savings of every plan
    // whose original byte range ends at-or-before `O`.
    let shift_at = |old_off: usize| -> usize {
        let mut shift = 0usize;
        for plan in &plans {
            let plan_end = plan.old_offset + plan.old_size;
            if plan_end <= old_off {
                shift += plan.old_size - plan.compressed.as_ref().unwrap().len();
            }
        }
        shift
    };

    let new_shoff = if e_shoff > 0 {
        e_shoff - shift_at(e_shoff)
    } else {
        0
    };

    // Map shdr idx -> (new_size, new_flags) for compressed sections.
    let mut compressed_meta: std::collections::HashMap<usize, (usize, u64)> =
        std::collections::HashMap::with_capacity(plans.len());
    for plan in &plans {
        compressed_meta.insert(
            plan.shdr_idx,
            (
                plan.compressed.as_ref().unwrap().len(),
                plan.old_flags | SHF_COMPRESSED,
            ),
        );
    }

    // Walk + rewrite SHDR entries in `new_file`.
    for i in 0..e_shnum {
        let entry_off = new_shoff + i * e_shentsize;
        if entry_off + e_shentsize > new_file.len() {
            crate::bail!(
                "compress: SHDR {i} out of file (off {entry_off}, file {})",
                new_file.len()
            );
        }
        let entry_bytes = &mut new_file[entry_off..entry_off + e_shentsize];
        // SAFETY: `SectionHeader64<Endianness>` is `#[repr(C)]` POD;
        // the slice we cast is exactly one entry's bounds.
        let entry = unsafe { &mut *(entry_bytes.as_mut_ptr() as *mut SectionHeader64<Endianness>) };
        let sh_offset = entry.sh_offset.get(endian) as usize;
        if sh_offset > 0 {
            let shifted = sh_offset - shift_at(sh_offset);
            entry.sh_offset.set(endian, shifted as u64);
        }
        if let Some(&(new_size, new_flags)) = compressed_meta.get(&i) {
            entry.sh_size.set(endian, new_size as u64);
            entry.sh_flags.set(endian, new_flags);
            // Compressed payload stores the original alignment in
            // ch_addralign inside the chdr; the section itself has
            // alignment 1 so tools don't pad the compressed stream.
            entry.sh_addralign.set(endian, 1);
        }
    }

    // Rewrite e_shoff in the ELF header (Elf64_Ehdr.e_shoff @ 40).
    new_file[40..48].copy_from_slice(&(new_shoff as u64).to_le_bytes());

    // Copy the rewritten buffer back into the live SizedOutput and
    // tell it the new on-disk size.
    let new_len = new_file.len();
    sized_output.out[..new_len].copy_from_slice(&new_file);
    sized_output.set_final_size(new_len as u64);

    Ok(())
}

fn write_chdr_zstd(dst: &mut [u8], decompressed_size: u64, addralign: u64) {
    debug_assert!(dst.len() >= CHDR_SIZE);
    dst[0..4].copy_from_slice(&ELFCOMPRESS_ZSTD.to_le_bytes());
    dst[4..8].copy_from_slice(&0u32.to_le_bytes());
    dst[8..16].copy_from_slice(&decompressed_size.to_le_bytes());
    dst[16..24].copy_from_slice(&addralign.to_le_bytes());
}
