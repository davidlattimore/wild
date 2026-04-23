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
    let new_len = compress_zstd_in_buffer(&mut sized_output.out)?;
    if let Some(len) = new_len {
        sized_output.set_final_size(len as u64);
    }
    Ok(())
}

/// Buffer-level core of [`compress_zstd`]. Returns `Some(new_len)`
/// when at least one section was compressed and the file shrank,
/// or `None` when there was nothing eligible to compress.
///
/// Exposed so unit tests can drive the compression on a synthetic
/// ELF without needing a real `SizedOutput` (file + mmap).
pub(crate) fn compress_zstd_in_buffer<B>(buf: &mut B) -> Result<Option<usize>>
where
    B: std::ops::DerefMut<Target = [u8]>,
{
    let endian = Endianness::Little;

    // ---- Phase 1: discover candidate sections + capture SHDR layout
    let (e_shoff, e_shentsize, e_shnum, mut plans) = {
        let bytes: &[u8] = &**buf;
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
        return Ok(None);
    }

    // ---- Phase 2: compress each plan in parallel ----
    let input_buf: &[u8] = &**buf;
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
        return Ok(None);
    }

    // Sort plans by file offset — the rewrite pass walks them in
    // file order and the shift arithmetic depends on it.
    plans.sort_by_key(|p| p.old_offset);

    // ---- Phase 3: rewrite the buffer ----
    let old_file_size = buf.len();
    let mut new_file = Vec::with_capacity(old_file_size);
    let mut cursor = 0usize;
    for plan in &plans {
        if plan.old_offset > cursor {
            new_file.extend_from_slice(&buf[cursor..plan.old_offset]);
        }
        new_file.extend_from_slice(plan.compressed.as_ref().unwrap());
        cursor = plan.old_offset + plan.old_size;
    }
    if cursor < old_file_size {
        new_file.extend_from_slice(&buf[cursor..]);
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
    // return the new on-disk size.
    let new_len = new_file.len();
    buf[..new_len].copy_from_slice(&new_file);
    Ok(Some(new_len))
}

fn write_chdr_zstd(dst: &mut [u8], decompressed_size: u64, addralign: u64) {
    debug_assert!(dst.len() >= CHDR_SIZE);
    dst[0..4].copy_from_slice(&ELFCOMPRESS_ZSTD.to_le_bytes());
    dst[4..8].copy_from_slice(&0u32.to_le_bytes());
    dst[8..16].copy_from_slice(&decompressed_size.to_le_bytes());
    dst[16..24].copy_from_slice(&addralign.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-roll a minimal ELF64-LE with:
    ///   * ELF header (64 bytes).
    ///   * `payload` bytes of `.debug_foo` content.
    ///   * `.shstrtab` (NUL + ".debug_foo\0.shstrtab\0").
    ///   * SHDR table: null entry, .debug_foo entry, .shstrtab entry.
    ///
    /// Not a loadable binary — just enough for the compress pass to
    /// walk the SHDR table and find the debug section. Using
    /// `object::write` would need the `write` feature which isn't
    /// in wild's workspace deps; raw bytes keep the test standalone.
    fn build_tiny_elf(payload: &[u8]) -> Vec<u8> {
        const EHDR_SIZE: usize = 64;
        const SHDR_SIZE: usize = 64;
        // Layout on disk:
        //   [ehdr]          0..64
        //   [.debug_foo]    64..64+N
        //   [.shstrtab]     after
        //   [SHDR[3]]       last
        let shstrtab_bytes: &[u8] = b"\0.debug_foo\0.shstrtab\0";
        let debug_offset = EHDR_SIZE;
        let shstrtab_offset = debug_offset + payload.len();
        let shdr_offset = shstrtab_offset + shstrtab_bytes.len();
        let total_size = shdr_offset + SHDR_SIZE * 3;

        let mut out = vec![0u8; total_size];

        // --- ELF header ---
        out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        out[4] = 2; // EI_CLASS = ELFCLASS64
        out[5] = 1; // EI_DATA  = ELFDATA2LSB
        out[6] = 1; // EI_VERSION
        // e_type (ET_REL = 1)
        out[16..18].copy_from_slice(&1u16.to_le_bytes());
        // e_machine (EM_X86_64 = 62)
        out[18..20].copy_from_slice(&62u16.to_le_bytes());
        // e_version = 1
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_shoff
        out[40..48].copy_from_slice(&(shdr_offset as u64).to_le_bytes());
        // e_ehsize
        out[52..54].copy_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
        // e_shentsize
        out[58..60].copy_from_slice(&(SHDR_SIZE as u16).to_le_bytes());
        // e_shnum = 3
        out[60..62].copy_from_slice(&3u16.to_le_bytes());
        // e_shstrndx = 2 (index of .shstrtab)
        out[62..64].copy_from_slice(&2u16.to_le_bytes());

        // --- Section bodies ---
        out[debug_offset..debug_offset + payload.len()].copy_from_slice(payload);
        out[shstrtab_offset..shstrtab_offset + shstrtab_bytes.len()]
            .copy_from_slice(shstrtab_bytes);

        // --- SHDR[0] = null (zeros, already) ---
        // --- SHDR[1] = .debug_foo ---
        let s1 = shdr_offset + SHDR_SIZE;
        // sh_name = offset of ".debug_foo" in shstrtab (after leading NUL = 1)
        out[s1..s1 + 4].copy_from_slice(&1u32.to_le_bytes());
        // sh_type = SHT_PROGBITS (1)
        out[s1 + 4..s1 + 8].copy_from_slice(&1u32.to_le_bytes());
        // sh_flags = 0
        out[s1 + 8..s1 + 16].copy_from_slice(&0u64.to_le_bytes());
        // sh_offset
        out[s1 + 24..s1 + 32].copy_from_slice(&(debug_offset as u64).to_le_bytes());
        // sh_size
        out[s1 + 32..s1 + 40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        // sh_addralign = 1
        out[s1 + 48..s1 + 56].copy_from_slice(&1u64.to_le_bytes());

        // --- SHDR[2] = .shstrtab ---
        let s2 = shdr_offset + 2 * SHDR_SIZE;
        // sh_name = offset of ".shstrtab" in shstrtab (12)
        out[s2..s2 + 4].copy_from_slice(&12u32.to_le_bytes());
        // sh_type = SHT_STRTAB (3)
        out[s2 + 4..s2 + 8].copy_from_slice(&3u32.to_le_bytes());
        // sh_offset
        out[s2 + 24..s2 + 32].copy_from_slice(&(shstrtab_offset as u64).to_le_bytes());
        // sh_size
        out[s2 + 32..s2 + 40].copy_from_slice(&(shstrtab_bytes.len() as u64).to_le_bytes());
        // sh_addralign = 1
        out[s2 + 48..s2 + 56].copy_from_slice(&1u64.to_le_bytes());

        out
    }

    #[test]
    fn compresses_debug_section_and_shrinks_file() {
        // Highly-compressible payload: repeat the same 64 bytes many times.
        // zstd should knock this down dramatically.
        let payload: Vec<u8> = b"hello from a wild linker debug section, repeated padding data!\0"
            .iter()
            .cycle()
            .take(32 * 1024)
            .copied()
            .collect();
        let original = build_tiny_elf(&payload);
        let original_len = original.len();
        let mut buf = original.clone();
        let new_len = compress_zstd_in_buffer(&mut buf)
            .expect("compress ok")
            .expect("something was compressed");
        assert!(
            new_len < original_len,
            "expected shrink; original={original_len}, new={new_len}"
        );
        buf.truncate(new_len);

        // Re-parse the shrunk ELF; assert .debug_foo now carries
        // SHF_COMPRESSED and holds a valid Elf64_Chdr + zstd stream.
        let endian = Endianness::Little;
        let header = FileHeader64::<Endianness>::parse(&*buf).expect("parse shrunk");
        let sections = header.sections(endian, &*buf).expect("sections");
        let mut found_compressed = false;
        for (_, sect) in sections.iter().enumerate() {
            let name = sections.section_name(endian, sect).unwrap();
            if name == b".debug_foo" {
                let flags = sect.sh_flags(endian);
                assert!(
                    flags & SHF_COMPRESSED != 0,
                    ".debug_foo missing SHF_COMPRESSED"
                );
                let off = sect.sh_offset(endian) as usize;
                let size = sect.sh_size(endian) as usize;
                let body = &buf[off..off + size];
                // First 4 bytes = ch_type (LE u32) = ELFCOMPRESS_ZSTD.
                let ch_type = u32::from_le_bytes(body[0..4].try_into().unwrap());
                assert_eq!(ch_type, ELFCOMPRESS_ZSTD, "ch_type wrong");
                let ch_size = u64::from_le_bytes(body[8..16].try_into().unwrap());
                assert_eq!(
                    ch_size as usize,
                    payload.len(),
                    "ch_size != original payload"
                );
                // Decompress and compare.
                let zstd_stream = &body[CHDR_SIZE..];
                let decoded = zstd::decode_all(zstd_stream).expect("zstd decode");
                assert_eq!(decoded, payload, "round-trip content mismatch");
                found_compressed = true;
            }
        }
        assert!(found_compressed, ".debug_foo section not found in output");
    }

    #[test]
    fn skips_when_no_debug_sections() {
        // Build a tiny ELF whose single section is `.foo` (not a
        // `.debug_*` name) — the compress pass must leave the
        // buffer unchanged and return Ok(None).
        let mut buf = build_tiny_elf(b"no-debug-content-here");
        // Rewrite the section name from `.debug_foo` → `.foo_xxxxx`
        // by flipping the sh_name and shstrtab content. Simpler:
        // overwrite the first byte of `.debug_foo` in shstrtab to
        // a non-matching character so the name prefix-check fails.
        // Find `.debug_foo` byte in shstrtab and corrupt it.
        let pos = buf
            .windows(b".debug_foo".len())
            .position(|w| w == b".debug_foo")
            .expect(".debug_foo string present");
        buf[pos] = b'X'; // now ".debuX_foo" — not starts_with ".debug_"
        // Adjust: actually change the leading "." to "X" so the name
        // no longer matches ".debug_" prefix.
        buf[pos] = b'X';
        let original = buf.clone();
        let result = compress_zstd_in_buffer(&mut buf).expect("compress ok");
        assert!(result.is_none(), "expected no-op on non-debug section");
        assert_eq!(buf, original, "buffer should be unchanged on no-op");
    }

    #[test]
    fn skips_incompressible_tiny_debug_section() {
        // MIN_COMPRESSIBLE = 256. A 100-byte .debug_foo must be left
        // alone (chdr alone would be 24 bytes, and random payload may
        // not compress below the threshold anyway).
        let payload = vec![0x42u8; 100];
        let original = build_tiny_elf(&payload);
        let mut buf = original.clone();
        let result = compress_zstd_in_buffer(&mut buf).expect("compress ok");
        assert!(result.is_none(), "expected skip on tiny section");
        assert_eq!(buf, original, "buffer should be unchanged");
    }
}
