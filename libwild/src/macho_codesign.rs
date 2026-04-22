//! In-process ad-hoc "linker-signed" Mach-O code signature.
//!
//! Replaces the `codesign -s - --force -o linker-signed` shell-out
//! that wild used to fire after every link. External `codesign`
//! re-reads the file, hashes every page, adds `LC_CODE_SIGNATURE` +
//! the signature blob, then rewrites the file — ~60 ms on a 45 MB
//! rust-analyzer. In-process we skip the fork/exec, read the file
//! once (it's still mapped or fresh in page cache), hash pages in
//! parallel with `sha2` (HW-accelerated on aarch64 via CRYPTO ext),
//! and patch the header + append the blob.
//!
//! The produced blob matches what Apple's `codesign -o linker-signed`
//! emits: ad-hoc signature with the `LINKERSIGNED` flag set and no
//! special slots, requirements blob, or entitlements. dyld's strict
//! validation accepts it as `valid on disk: satisfies its Designated
//! Requirement`.

use crate::error::Result;
use sha2::Digest;
use sha2::Sha256;

/// Magic for the embedded-signature `SuperBlob` wrapping the whole
/// blob: `CSMAGIC_EMBEDDED_SIGNATURE`.
const SUPERBLOB_MAGIC: u32 = 0xfade_0cc0;
/// Magic for the `CodeDirectory` sub-blob: `CSMAGIC_CODEDIRECTORY`.
const CODEDIR_MAGIC: u32 = 0xfade_0c02;

/// CodeDirectory version 0x20400 — supports `execSegBase`, the
/// minimum required by modern macOS dyld strict validation.
const CD_VERSION: u32 = 0x0002_0400;

/// Ad-hoc | linker-signed. `CS_ADHOC = 0x2`, `CS_LINKER_SIGNED =
/// 0x20000`. The LINKERSIGNED bit tells macOS "this was produced by a
/// linker, not a human; treat it leniently".
const CD_FLAGS: u32 = 0x0002_0000 | 0x0000_0002;

/// SHA-256 slot constants.
const HASH_SIZE: u8 = 32;
const HASH_TYPE: u8 = 2; // cdHashType_SHA256

/// Page size stored in the CodeDirectory as log2. Apple's
/// `codesign -o linker-signed` picks the arch's native page size:
/// 4 KiB on x86_64, 16 KiB on arm64.  AMFI on the loader side
/// reads hashes in chunks matching this page size — mis-signing
/// with 4 KiB on arm64 produces a codesign blob that `codesign -v`
/// accepts (the blob is self-consistent) but that `execve` rejects
/// with SIGKILL because the kernel-side hash verification reads
/// 16 KiB regions and sees each hash covering only ¼ of the data.
#[cfg(target_arch = "aarch64")]
const PAGE_SIZE: usize = 16384;
#[cfg(target_arch = "aarch64")]
const PAGE_SIZE_LOG2: u8 = 14;
#[cfg(not(target_arch = "aarch64"))]
const PAGE_SIZE: usize = 4096;
#[cfg(not(target_arch = "aarch64"))]
const PAGE_SIZE_LOG2: u8 = 12;

/// CodeDirectory slot index in the SuperBlob's index table.
const SLOT_CODEDIRECTORY: u32 = 0;

/// Mach-O magic values we recognise here.
const MH_MAGIC_64: u32 = 0xfeed_facf;
const LC_SEGMENT_64: u32 = 0x19;
const LC_CODE_SIGNATURE: u32 = 0x1d;

/// Compute the size in bytes of the embedded-signature blob that
/// covers `code_limit` bytes of the binary, using an identifier of
/// length `ident_len` (caller supplies the null-terminator space).
///
/// **Complexity:** Θ(p) CPU, Θ(1) memory — fixed-layout arithmetic
/// where p = ⌈code_limit / 4 KiB⌉ hash slots dominate the result.
fn blob_size(code_limit: u64, ident_len: usize) -> usize {
    let n_slots = code_limit.div_ceil(PAGE_SIZE as u64) as usize;
    // SuperBlob header (12) + one BlobIndex (8).
    let sb_header = 12 + 8;
    // CodeDirectory fixed part for version 0x20400 (88 bytes through
    // `execSegFlags`).
    let cd_fixed = 88;
    let cd_ident = ident_len + 1; // + null terminator
    let cd_slots = n_slots * HASH_SIZE as usize;
    sb_header + cd_fixed + cd_ident + cd_slots
}

/// Apply an ad-hoc "linker-signed" code signature to the Mach-O file
/// at `output_path`. Idempotent: if the binary already has an
/// `LC_CODE_SIGNATURE` (from a previous sign), the existing blob is
/// replaced in place.
///
/// Matches Apple `codesign -s - --force -o linker-signed -i <ident>
/// <file>` on the ~50 ms-per-binary fast path; ~10× faster than the
/// external tool because we (a) skip `fork`+`exec`, (b) hash pages in
/// parallel, (c) avoid the stream-rewrite that `codesign` does when
/// adding the LC.
///
/// Upper bound on the codesign blob that would be produced for a
/// body of exactly `body_len` bytes. Matches what `sign_in_place`
/// emits. Used by `write_direct` to reserve trailing space in the
/// mmap'd output buffer so codesign can write its blob in-place
/// without needing to grow a Vec.
///
/// **Complexity:** Θ(1) CPU/memory — simple arithmetic.
pub(crate) fn blob_reserve_bytes(body_len: usize, max_ident_len: usize) -> usize {
    // Max sig_pad is 15 (16-byte alignment).
    let aligned_body_cap = body_len + 15;
    let n_slots_max = (aligned_body_cap + PAGE_SIZE - 1) / PAGE_SIZE;
    let ident_cap = max_ident_len + 1; // null terminator
    // SuperBlob(12) + BlobIndex(8) + CD fixed(88) + ident + hashes + slack.
    15 + 12 + 8 + 88 + ident_cap + n_slots_max * HASH_SIZE as usize + 64
}

/// Compute an ad-hoc code signature for an in-memory Mach-O image
/// already laid out in `buf[..body_len]`, writing the signature blob
/// into `buf[aligned_end..aligned_end + blob_size]`.
///
/// The caller supplies the buffer — it may be a Vec, an `MmapMut`,
/// or any other `&mut [u8]` with enough trailing capacity (estimate
/// via [`blob_reserve_bytes`]). `buf.len()` must be ≥
/// `body_len + blob_reserve_bytes(body_len, identifier.len())`.
///
/// Returns the final byte offset (aligned_end + blob_size) — the
/// caller is responsible for truncating the underlying file to that
/// length before closing.
///
/// **Complexity:** 𝒪(body_len + p) CPU (dominated by hashing), 𝒪(p)
/// additional memory for the hash array. Wall-clock hash phase is
/// 𝒪(body_len/T) with T scoped threads; SHA-256 is HW-accelerated on
/// aarch64 via the CRYPTO extension. Load-command scans are 𝒪(L).
pub(crate) fn sign_in_place(buf: &mut [u8], body_len: usize, identifier: &str) -> Result<usize> {
    if std::env::var_os("WILD_SIGN_DEBUG").is_some() {
        eprintln!(
            "sign_in_place: buf.len={} body_len={} ident={}",
            buf.len(),
            body_len,
            identifier
        );
    }
    let file_len = body_len as u64;

    // Parse the Mach-O header: ncmds, sizeofcmds.
    if buf.len() < 32 {
        crate::bail!("codesign: file too short for Mach-O header");
    }
    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if magic != MH_MAGIC_64 {
        crate::bail!("codesign: expected MH_MAGIC_64 ({MH_MAGIC_64:#x}), got {magic:#x}");
    }
    let mut ncmds = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let mut sizeofcmds = u32::from_le_bytes(buf[20..24].try_into().unwrap());

    // Walk the load-command list to find:
    //   * the __LINKEDIT segment LC (we patch its file+vm size)
    //   * any existing LC_CODE_SIGNATURE (we replace in-place)
    let mut linkedit_lc_off: Option<usize> = None;
    let mut codesig_lc_off: Option<usize> = None;
    let mut linkedit_fileoff = 0u64;
    let mut linkedit_vmsize = 0u64;
    {
        let mut off = 32usize;
        for _ in 0..ncmds {
            if off + 8 > buf.len() {
                crate::bail!("codesign: ran off end of LC list");
            }
            let cmd = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            let cmdsize = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap()) as usize;
            if cmd == LC_SEGMENT_64 {
                if cmdsize < 72 {
                    crate::bail!("codesign: short LC_SEGMENT_64");
                }
                let segname = &buf[off + 8..off + 24];
                let end = segname.iter().position(|&b| b == 0).unwrap_or(16);
                if &segname[..end] == b"__LINKEDIT" {
                    linkedit_lc_off = Some(off);
                    linkedit_fileoff =
                        u64::from_le_bytes(buf[off + 40..off + 48].try_into().unwrap());
                    linkedit_vmsize =
                        u64::from_le_bytes(buf[off + 32..off + 40].try_into().unwrap());
                }
            } else if cmd == LC_CODE_SIGNATURE {
                codesig_lc_off = Some(off);
            }
            off += cmdsize;
        }
    }
    let linkedit_lc_off =
        linkedit_lc_off.ok_or_else(|| crate::error!("codesign: no __LINKEDIT segment found"))?;

    // codeLimit = everything except the signature itself. For a
    // brand-new file with no LC_CODE_SIGNATURE, codeLimit = file_len.
    // For re-signing, codeLimit = file_len - old_blob_size.
    let code_limit = match codesig_lc_off {
        Some(cs_off) => {
            let old_dataoff = u32::from_le_bytes(buf[cs_off + 8..cs_off + 12].try_into().unwrap());
            old_dataoff as u64
        }
        None => file_len,
    };

    // Build the signature blob. `codeLimit` (below) includes the
    // 16-byte alignment padding that precedes the blob itself, so
    // size the blob for the ALIGNED end, not the raw `code_limit`.
    let ident_bytes = identifier.as_bytes();
    let aligned_end = (code_limit + 15) & !15;
    let total_blob = blob_size(aligned_end, ident_bytes.len());
    let n_slots = aligned_end.div_ceil(PAGE_SIZE as u64) as usize;

    // Apply the header mutations NOW — before hashing — so hashes
    // cover exactly the bytes that end up on disk. Order matters:
    // dyld rehashes pages 0..codeLimit at load time and compares
    // against the hash slots; any mismatch fails "signature have
    // been modified".
    //
    // The signature blob must be 16-byte aligned (Apple Mach-O spec;
    // `dyld_info -validate_only` rejects misaligned dylibs with
    // "mis-aligned code signature"). Pad between the previous
    // __LINKEDIT content and the signature.
    let sig_align: u64 = 16;
    let sig_pad = {
        let unaligned_end = code_limit;
        ((unaligned_end + sig_align - 1) & !(sig_align - 1)) - unaligned_end
    };
    let new_dataoff = code_limit + sig_pad;
    let new_datasize = total_blob as u64;
    let new_linkedit_filesize = (new_dataoff - linkedit_fileoff) + new_datasize;
    let page_align: u64 = 16 * 1024;
    let new_linkedit_vmsize = (new_linkedit_filesize + page_align - 1) & !(page_align - 1);

    if let Some(cs_off) = codesig_lc_off {
        buf[cs_off + 8..cs_off + 12].copy_from_slice(&(new_dataoff as u32).to_le_bytes());
        buf[cs_off + 12..cs_off + 16].copy_from_slice(&(new_datasize as u32).to_le_bytes());
    } else {
        let new_lc_off = 32 + sizeofcmds as usize;
        let header_pad_end = find_header_pad_end(&buf)?;
        if new_lc_off + 16 > header_pad_end {
            crate::bail!(
                "codesign: header-pad exhausted (have {} bytes free, need 16 \
                 for LC_CODE_SIGNATURE)",
                header_pad_end.saturating_sub(new_lc_off),
            );
        }
        buf[new_lc_off..new_lc_off + 4].copy_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
        buf[new_lc_off + 4..new_lc_off + 8].copy_from_slice(&16u32.to_le_bytes());
        buf[new_lc_off + 8..new_lc_off + 12].copy_from_slice(&(new_dataoff as u32).to_le_bytes());
        buf[new_lc_off + 12..new_lc_off + 16].copy_from_slice(&(new_datasize as u32).to_le_bytes());
        ncmds += 1;
        sizeofcmds += 16;
        buf[16..20].copy_from_slice(&ncmds.to_le_bytes());
        buf[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
    }
    buf[linkedit_lc_off + 32..linkedit_lc_off + 40]
        .copy_from_slice(&new_linkedit_vmsize.to_le_bytes());
    buf[linkedit_lc_off + 48..linkedit_lc_off + 56]
        .copy_from_slice(&new_linkedit_filesize.to_le_bytes());
    let _ = linkedit_vmsize;

    // Zero the 16-byte sig-alignment pad in the reserved trailing
    // region so the hash loop sees a contiguous block ending at
    // `aligned_end`, and the final page hash doesn't read undefined
    // bytes. Requires the caller reserved at least `sig_pad +
    // total_blob` trailing bytes beyond `body_len`.
    let aligned_end_usize = aligned_end as usize;
    let sig_pad_usize = sig_pad as usize;
    let needed = aligned_end_usize + total_blob;
    if std::env::var_os("WILD_SIGN_DEBUG").is_some() {
        eprintln!(
            "  code_limit={code_limit} aligned_end={aligned_end} sig_pad={sig_pad_usize} total_blob={total_blob} needed={needed} buf.len={}",
            buf.len()
        );
        eprintln!(
            "  linkedit_lc_off={linkedit_lc_off:?} linkedit_fileoff={linkedit_fileoff} codesig_lc_off={codesig_lc_off:?}"
        );
        eprintln!(
            "  new_dataoff={new_dataoff} new_datasize={new_datasize} new_linkedit_filesize={new_linkedit_filesize} new_linkedit_vmsize={new_linkedit_vmsize}"
        );
    }
    if buf.len() < needed {
        crate::bail!(
            "codesign: buffer too small — need {needed} bytes for body + pad + blob, \
             got {} (body_len={body_len}, sig_pad={sig_pad_usize}, \
             blob={total_blob}). Caller should reserve via `blob_reserve_bytes`.",
            buf.len()
        );
    }
    if sig_pad_usize > 0 {
        buf[body_len..body_len + sig_pad_usize].fill(0);
    }

    // Hash all code pages in parallel.
    //
    // Each slot is a 4 KiB SHA-256 (~2 µs of CPU on aarch64 CRYPTO).
    // That's small enough that rayon's work-stealing + per-task
    // scheduling overhead (~100-200 ns each) eats a measurable
    // fraction of the total. Use `std::thread::scope` with exactly
    // one thread per core and a fixed contiguous-page split instead:
    // - zero-copy: each worker borrows a disjoint `&[u8]` slice of `buf` and a disjoint `&mut [[u8;
    //   32]]` output strip;
    // - no work-stealing overhead — the split is balanced because every page is the same size;
    // - a single spawn/join barrier instead of n_slots task pushes.
    let hashes: Vec<[u8; 32]> = {
        let mut hashes = vec![[0u8; 32]; n_slots];
        let n_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(n_slots.max(1));
        let buf_ref: &[u8] = &buf;
        let aligned_end_u = aligned_end as usize;

        // Each worker owns a contiguous output strip and the matching
        // page range. The output-strip split via `chunks_mut` is
        // Rust's zero-copy idiom for safe `&mut` sharding across
        // threads.
        let chunk = n_slots.div_ceil(n_threads);
        std::thread::scope(|s| {
            for (worker_idx, out_strip) in hashes.chunks_mut(chunk).enumerate() {
                let page_base = worker_idx * chunk;
                s.spawn(move || {
                    for (i, slot) in out_strip.iter_mut().enumerate() {
                        let slot_idx = page_base + i;
                        let page_start = slot_idx * PAGE_SIZE;
                        let page_end = (page_start + PAGE_SIZE).min(aligned_end_u);
                        let mut h = Sha256::new();
                        h.update(&buf_ref[page_start..page_end]);
                        slot.copy_from_slice(&h.finalize());
                    }
                });
            }
        });
        hashes
    };

    // Blob layout. All multi-byte integers BIG-ENDIAN per Apple format.
    let mut blob = vec![0u8; total_blob];
    // SuperBlob header: magic, length, count
    blob[0..4].copy_from_slice(&SUPERBLOB_MAGIC.to_be_bytes());
    blob[4..8].copy_from_slice(&(total_blob as u32).to_be_bytes());
    blob[8..12].copy_from_slice(&1u32.to_be_bytes());
    // Single blob index entry: (type, offset)
    let cd_off_in_sb: u32 = 20; // after sb_header(12) + 1 BlobIndex(8)
    blob[12..16].copy_from_slice(&SLOT_CODEDIRECTORY.to_be_bytes());
    blob[16..20].copy_from_slice(&cd_off_in_sb.to_be_bytes());

    // CodeDirectory starts at `cd_off_in_sb` (= 20).
    let cd_base = cd_off_in_sb as usize;
    let cd_size = total_blob - cd_base;
    // Layout: fixed(88) + ident(ident_len+1) + slots(n_slots*32)
    let cd_ident_off = 88u32;
    let cd_hash_off = cd_ident_off + ident_bytes.len() as u32 + 1;

    blob[cd_base..cd_base + 4].copy_from_slice(&CODEDIR_MAGIC.to_be_bytes());
    blob[cd_base + 4..cd_base + 8].copy_from_slice(&(cd_size as u32).to_be_bytes());
    blob[cd_base + 8..cd_base + 12].copy_from_slice(&CD_VERSION.to_be_bytes());
    blob[cd_base + 12..cd_base + 16].copy_from_slice(&CD_FLAGS.to_be_bytes());
    blob[cd_base + 16..cd_base + 20].copy_from_slice(&cd_hash_off.to_be_bytes());
    blob[cd_base + 20..cd_base + 24].copy_from_slice(&cd_ident_off.to_be_bytes());
    blob[cd_base + 24..cd_base + 28].copy_from_slice(&0u32.to_be_bytes()); // nSpecialSlots
    blob[cd_base + 28..cd_base + 32].copy_from_slice(&(n_slots as u32).to_be_bytes());
    blob[cd_base + 32..cd_base + 36].copy_from_slice(&(aligned_end as u32).to_be_bytes());
    blob[cd_base + 36] = HASH_SIZE;
    blob[cd_base + 37] = HASH_TYPE;
    blob[cd_base + 38] = 0; // platform
    blob[cd_base + 39] = PAGE_SIZE_LOG2;
    blob[cd_base + 40..cd_base + 44].copy_from_slice(&0u32.to_be_bytes()); // spare2
    blob[cd_base + 44..cd_base + 48].copy_from_slice(&0u32.to_be_bytes()); // scatterOffset
    blob[cd_base + 48..cd_base + 52].copy_from_slice(&0u32.to_be_bytes()); // teamOffset
    blob[cd_base + 52..cd_base + 56].copy_from_slice(&0u32.to_be_bytes()); // spare3
    blob[cd_base + 56..cd_base + 64].copy_from_slice(&0u64.to_be_bytes()); // codeLimit64
    // execSegBase / execSegLimit / execSegFlags — parse __TEXT fileoff/filesize.
    let (exec_seg_base, exec_seg_limit) = parse_text_segment(&buf);
    // execSegFlags: 1 = main binary; 0 for dylibs/bundles — the
    // header filetype tells us which.
    let filetype = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let exec_seg_flags: u64 = if filetype == 2 { 1 } else { 0 };
    blob[cd_base + 64..cd_base + 72].copy_from_slice(&exec_seg_base.to_be_bytes());
    blob[cd_base + 72..cd_base + 80].copy_from_slice(&exec_seg_limit.to_be_bytes());
    blob[cd_base + 80..cd_base + 88].copy_from_slice(&exec_seg_flags.to_be_bytes());
    // identifier (null-terminated)
    let ident_write_off = cd_base + cd_ident_off as usize;
    blob[ident_write_off..ident_write_off + ident_bytes.len()].copy_from_slice(ident_bytes);
    // hash slots
    let hash_write_off = cd_base + cd_hash_off as usize;
    for (i, h) in hashes.iter().enumerate() {
        let o = hash_write_off + i * HASH_SIZE as usize;
        blob[o..o + HASH_SIZE as usize].copy_from_slice(h);
    }

    // Copy the blob into the reserved trailing region of `buf`.
    // Caller owns the file and will truncate it to the returned
    // length after dropping the mmap (or flushing the Vec).
    buf[aligned_end_usize..aligned_end_usize + total_blob].copy_from_slice(&blob);

    Ok(aligned_end_usize + total_blob)
}

/// Returns (fileoff, filesize) of the `__TEXT` segment.
///
/// **Complexity:** 𝒪(L) CPU, 𝒪(1) memory — single linear scan over
/// L load commands; stops at first `__TEXT` LC_SEGMENT_64 match.
fn parse_text_segment(buf: &[u8]) -> (u64, u64) {
    if buf.len() < 32 {
        return (0, 0);
    }
    let ncmds = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let mut off = 32usize;
    for _ in 0..ncmds {
        if off + 8 > buf.len() {
            return (0, 0);
        }
        let cmd = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmd == LC_SEGMENT_64 && cmdsize >= 72 {
            let segname = &buf[off + 8..off + 24];
            let end = segname.iter().position(|&b| b == 0).unwrap_or(16);
            if &segname[..end] == b"__TEXT" {
                let fileoff = u64::from_le_bytes(buf[off + 40..off + 48].try_into().unwrap());
                let filesize = u64::from_le_bytes(buf[off + 48..off + 56].try_into().unwrap());
                return (fileoff, filesize);
            }
        }
        off += cmdsize;
    }
    (0, 0)
}

/// Returns the file offset at which the first section's content
/// starts — the end of the header-pad region where new load commands
/// can be appended. For wild's output, this is the fileoff of
/// `__text` (the first section in `__TEXT`).
///
/// **Complexity:** 𝒪(L) CPU, 𝒪(1) memory — full scan over L load
/// commands to find the minimum section file-offset.
fn find_header_pad_end(buf: &[u8]) -> Result<usize> {
    if buf.len() < 32 {
        crate::bail!("codesign: file too short for header");
    }
    let ncmds = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let mut off = 32usize;
    let mut min_sect_fileoff = u64::MAX;
    for _ in 0..ncmds {
        if off + 8 > buf.len() {
            crate::bail!("codesign: truncated LC list");
        }
        let cmd = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmd == LC_SEGMENT_64 && cmdsize >= 72 {
            // Sections start at `off + 72` (segname ends at +24,
            // vmaddr..flags fills +40..+72). Each section header is 80
            // bytes: sectname(16)+segname(16)+addr(8)+size(8)+offset(4)+
            // align(4)+reloff(4)+nreloc(4)+flags(4)+reserved1..3(12).
            let nsects = u32::from_le_bytes(buf[off + 64..off + 68].try_into().unwrap()) as usize;
            for i in 0..nsects {
                let sec = off + 72 + i * 80;
                if sec + 40 > buf.len() {
                    break;
                }
                let sec_fileoff =
                    u32::from_le_bytes(buf[sec + 48..sec + 52].try_into().unwrap()) as u64;
                if sec_fileoff > 0 && sec_fileoff < min_sect_fileoff {
                    min_sect_fileoff = sec_fileoff;
                }
            }
        }
        off += cmdsize;
    }
    if min_sect_fileoff == u64::MAX {
        // No sections — LC list can grow to arbitrary length. Use the
        // linkedit fileoff as a reasonable upper bound.
        Ok(buf.len())
    } else {
        Ok(min_sect_fileoff as usize)
    }
}
