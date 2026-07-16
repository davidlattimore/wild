// Code related to output compression, in particular compression of debug sections. Input
// compression is handled elsewhere.

use crate::alignment::Alignment;
use crate::bail;
use crate::elf;
use crate::elf::Elf;
use crate::elf::Rela;
use crate::elf_writer;
use crate::elf_writer::apply_debug_relocations;
use crate::error::Result;
use crate::layout::FileLayout;
use crate::layout::Layout;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputSectionId;
use crate::platform::Arch;
use crate::platform::ObjectFile as _;
use crate::platform::Platform;
use crate::platform::SectionFlags as _;
use crate::resolution::SectionSlot;
use crate::timing_phase;
use crate::verbose_timing_phase;
use object::LittleEndian;
use object::bytes_of;
use object::elf::CompressionHeader64;
use object::elf::CompressionType;
use object::read::elf::Crel;
use rayon::iter::IntoParallelIterator as _;
use rayon::iter::IntoParallelRefIterator as _;
use rayon::iter::ParallelIterator as _;
use zlib_rs::Deflate;
use zlib_rs::DeflateError;
use zlib_rs::DeflateFlush;
use zlib_rs::Status;
use zlib_rs::adler32::adler32;
use zlib_rs::adler32::adler32_combine;

#[derive(Debug)]
pub(crate) struct CompressedSection {
    pub(crate) compressed_chunks: Vec<Vec<u8>>,
    total_compressed_size: usize,
}

/// Size in bytes below which we won't try to further split the input.
const MIN_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum number of input chunks. This limits parallelism. Note that we don't use the number of
/// threads because we want the output to not depend on the number of threads.
const MAX_CHUNKS: usize = 128;

const ZLIB_COMPRESSION_LEVEL: i32 = 1;
#[cfg(feature = "zstd")]
const ZSTD_COMPRESSION_LEVEL: i32 = 3;

/// zlib `windowBits`.
const ZLIB_WINDOW_BITS: u8 = 15;

/// Initial Adler-32 value (RFC 1950).
const ADLER32_INITIAL: u32 = 1;

/// zlib CMF+FLG header for deflate with a 32 KiB window and default FCHECK.
const ZLIB_CMF_FLG: [u8; 2] = [0x78, 0x9c];

/// Empty final deflate block (`BFINAL=1`, empty stored/fixed block) written after
/// SyncFlush'd shards so the stream can be closed before the Adler-32 trailer.
const ZLIB_EMPTY_FINAL_BLOCK: [u8; 2] = [0x03, 0x00];

/// Size of multi-shard zlib trailer. Empty final block + Adler-32 (big-endian u32).
const ZLIB_MULTI_SHARD_TRAILER_LEN: usize =
    ZLIB_EMPTY_FINAL_BLOCK.len() + std::mem::size_of::<u32>();

/// Extra bytes reserved beyond `compress_bound` so SyncFlush markers fit without an immediate
/// realloc on the first flush attempt.
const ZLIB_SYNC_FLUSH_SLACK: usize = 16;

/// How much to grow the output buffer when a Finish/SyncFlush needs more space.
const ZLIB_OUTPUT_GROW_BYTES: usize = 64;

pub(crate) fn maybe_compress_debug_sections_elf<A: Arch<Platform = Elf>>(
    layout: &mut crate::layout::Layout<Elf>,
) -> Result {
    let Some(compression_kind) = layout.args().debug_compression_kind else {
        return Ok(());
    };

    timing_phase!("Compress debug sections");

    // Figure out which sections were going to compress.
    let mut debug_sections = Vec::new();
    for (section_id, _section_info) in layout.output_sections.ids_with_info() {
        if let Some(name) = layout.output_sections.name(section_id)
            && name.bytes().starts_with(b".debug_")
            && layout.section_layouts.get(section_id).file_size > 0
            && !layout.output_sections.section_flags(section_id).is_alloc()
        {
            debug_sections.push(section_id);
        }
    }

    if debug_sections.is_empty() {
        return Ok(());
    }

    match compression_kind {
        crate::args::elf::CompressionKind::Zlib => {
            compress_sections::<A, ZlibCompressor>(layout, &debug_sections)?;
        }
        crate::args::elf::CompressionKind::Zstd => {
            compress_sections::<A, ZstdCompressor>(layout, &debug_sections)?;
        }
    }

    update_allocation_sizes(layout);
    update_file_offset(layout)?;

    Ok(())
}

trait SectionCompressor {
    fn compress_section(uncompressed: &[u8]) -> Result<Vec<Vec<u8>>>;

    fn kind() -> CompressionType;
}

struct ZlibCompressor;

impl SectionCompressor for ZlibCompressor {
    fn compress_section(uncompressed: &[u8]) -> Result<Vec<Vec<u8>>> {
        verbose_timing_phase!("Compress zlib section");

        let shard_size = shard_size(uncompressed.len());

        if uncompressed.len() <= shard_size {
            return Ok(vec![zlib_compress_whole(uncompressed)?]);
        }

        let shards: Vec<&[u8]> = uncompressed.chunks(shard_size).collect();

        let shard_results: Vec<(Vec<u8>, u32)> = shards
            .par_iter()
            .map(|shard| -> Result<(Vec<u8>, u32)> {
                verbose_timing_phase!("Compress zlib shard");
                zlib_compress_shard(shard)
            })
            .collect::<Result<_>>()?;

        let mut checksum = shard_results[0].1;
        for ((_, shard_adler), shard) in shard_results.iter().skip(1).zip(shards.iter().skip(1)) {
            checksum = adler32_combine(checksum, *shard_adler, shard.len() as u64);
        }

        // Header chunk + one chunk per shard + trailer chunk.
        let mut chunks = Vec::with_capacity(shard_results.len() + 2);
        chunks.push(ZLIB_CMF_FLG.to_vec());
        for (compressed, _) in shard_results {
            chunks.push(compressed);
        }
        let mut trailer = Vec::with_capacity(ZLIB_MULTI_SHARD_TRAILER_LEN);
        trailer.extend_from_slice(&ZLIB_EMPTY_FINAL_BLOCK);
        trailer.extend_from_slice(&checksum.to_be_bytes());
        chunks.push(trailer);
        Ok(chunks)
    }

    fn kind() -> CompressionType {
        object::elf::ELFCOMPRESS_ZLIB
    }
}

struct ZstdCompressor;

impl SectionCompressor for ZstdCompressor {
    fn compress_section(uncompressed: &[u8]) -> Result<Vec<Vec<u8>>> {
        #[cfg(not(feature = "zstd"))]
        {
            let _ = uncompressed;
            bail!("wild was compiled without zstd support");
        }

        #[cfg(feature = "zstd")]
        {
            let shard_size = shard_size(uncompressed.len());
            let shards: Vec<&[u8]> = uncompressed.chunks(shard_size).collect();

            shards
                .par_iter()
                .map(|shard| -> Result<Vec<u8>> {
                    verbose_timing_phase!("Compress zstd shard");
                    zstd::encode_all(*shard, ZSTD_COMPRESSION_LEVEL).map_err(Into::into)
                })
                .collect()
        }
    }

    fn kind() -> CompressionType {
        object::elf::ELFCOMPRESS_ZSTD
    }
}

fn zlib_deflate_error(error: DeflateError) -> crate::error::Error {
    crate::error::Error::with_message(format!("zlib compression failed: {error:?}"))
}

fn shard_size(uncompressed_len: usize) -> usize {
    std::cmp::max(MIN_CHUNK_SIZE, uncompressed_len / MAX_CHUNKS)
}

/// Full zlib stream for a single input that doesn't need sharding.
fn zlib_compress_whole(input: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = Deflate::new(ZLIB_COMPRESSION_LEVEL, true, ZLIB_WINDOW_BITS);
    let mut output = vec![0u8; zlib_rs::compress_bound(input.len())];

    match encoder
        .compress(input, &mut output, DeflateFlush::Finish)
        .map_err(zlib_deflate_error)?
    {
        Status::StreamEnd => {
            output.truncate(encoder.total_out() as usize);
            return Ok(output);
        }
        Status::Ok | Status::BufError => {}
    }

    loop {
        let bytes_written = encoder.total_out() as usize;
        if bytes_written + ZLIB_SYNC_FLUSH_SLACK > output.len() {
            output.resize(output.len() + ZLIB_OUTPUT_GROW_BYTES, 0);
        }
        match encoder
            .compress(&[], &mut output[bytes_written..], DeflateFlush::Finish)
            .map_err(zlib_deflate_error)?
        {
            Status::StreamEnd => {
                output.truncate(encoder.total_out() as usize);
                return Ok(output);
            }
            Status::Ok | Status::BufError => {}
        }
    }
}

/// Compresses one shard as raw deflate terminated with `SyncFlush`. Also returns Adler-32 of the
/// uncompressed shard.
fn zlib_compress_shard(input: &[u8]) -> Result<(Vec<u8>, u32)> {
    // Compute while `input` is hot for the following deflate pass.
    let checksum = adler32(ADLER32_INITIAL, input);

    let mut encoder = Deflate::new(ZLIB_COMPRESSION_LEVEL, false, ZLIB_WINDOW_BITS);
    let mut output = vec![0u8; zlib_rs::compress_bound(input.len()) + ZLIB_SYNC_FLUSH_SLACK];

    match encoder
        .compress(input, &mut output, DeflateFlush::Block)
        .map_err(zlib_deflate_error)?
    {
        Status::Ok | Status::BufError => {}
        Status::StreamEnd => bail!("zlib block compression failed"),
    }

    loop {
        let bytes_written = encoder.total_out() as usize;
        encoder
            .compress(&[], &mut output[bytes_written..], DeflateFlush::SyncFlush)
            .map_err(zlib_deflate_error)?;
        let new_bytes_written = encoder.total_out() as usize;
        if new_bytes_written == bytes_written {
            output.truncate(new_bytes_written);
            return Ok((output, checksum));
        }
        if new_bytes_written + ZLIB_SYNC_FLUSH_SLACK > output.len() {
            output.resize(output.len() + ZLIB_OUTPUT_GROW_BYTES, 0);
        }
    }
}

fn compress_sections<A: Arch<Platform = Elf>, C: SectionCompressor>(
    layout: &mut Layout<Elf>,
    debug_sections: &[OutputSectionId],
) -> Result {
    let compression_results = debug_sections
        .par_iter()
        .map(
            |&section_id| -> Result<(
                crate::output_section_id::OutputSectionId,
                Option<CompressedSection>,
            )> {
                verbose_timing_phase!("Process debug section");

                let section_layout = layout.section_layouts.get(section_id);
                let mut buffer = vec![0u8; section_layout.file_size];

                build_debug_section_in_memory::<A>(section_id, &mut buffer, layout)?;

                let compressed = compress_section::<C>(&buffer, section_layout.alignment)?;

                Ok((section_id, compressed))
            },
        )
        .collect::<Result<Vec<_>>>()?;

    for (section_id, compressed_data) in compression_results {
        *layout.compressed_debug_sections.get_mut(section_id) = compressed_data;
    }

    Ok(())
}

fn compress_section<C: SectionCompressor>(
    uncompressed: &[u8],
    alignment: Alignment,
) -> Result<Option<CompressedSection>> {
    verbose_timing_phase!("Compress section");

    let mut compressed_chunks = C::compress_section(uncompressed)?;

    let mut header: CompressionHeader64<LittleEndian> = Default::default();
    header.ch_type.set(LittleEndian, C::kind());
    header.ch_size.set(LittleEndian, uncompressed.len() as u64);
    header.ch_addralign.set(LittleEndian, alignment.value());

    let header_bytes = bytes_of(&header).to_vec();
    let body_size: usize = compressed_chunks.iter().map(Vec::len).sum();
    let total_compressed_size = header_bytes.len() + body_size;

    // Return None if compression made things larger.
    if total_compressed_size >= uncompressed.len() {
        return Ok(None);
    }

    compressed_chunks.insert(0, header_bytes);

    Ok(Some(CompressedSection {
        compressed_chunks,
        total_compressed_size,
    }))
}

fn build_debug_section_in_memory<A: Arch<Platform = Elf>>(
    section_id: crate::output_section_id::OutputSectionId,
    mut buffer: &mut [u8],
    layout: &crate::layout::Layout<Elf>,
) -> Result {
    let merged = layout.merged_strings.get(section_id);
    if merged.len() > 0 {
        elf_writer::write_merged_strings_to_buffer(merged, &mut buffer);
        return Ok(());
    }

    build_regular_debug_section::<A>(section_id, buffer, layout)?;

    Ok(())
}

fn build_regular_debug_section<A: Arch<Platform = Elf>>(
    section_id: OutputSectionId,
    buffer: &mut [u8],
    layout: &Layout<Elf>,
) -> Result {
    verbose_timing_phase!("Build debug section");

    let part_range = section_id.part_id_range();
    let mut remaining = buffer;
    let groups_and_buffers: Vec<(_, &mut [u8])> = layout
        .group_layouts
        .iter()
        .map(|group| {
            let size: usize = group.file_sizes[part_range.clone()].iter().sum();
            let group_buf = remaining.split_off_mut(..size).unwrap();
            (group, group_buf)
        })
        .collect();

    groups_and_buffers
        .into_par_iter()
        .try_for_each(|(group_layout, group_buf)| -> Result {
            verbose_timing_phase!("Write group debug to buffer");

            let mut offset = 0;
            for file_layout in &group_layout.files {
                if let FileLayout::Object(object_layout) = file_layout {
                    for (idx, section_slot) in object_layout.sections.iter().enumerate() {
                        if let SectionSlot::LoadedDebugInfo(_) = section_slot {
                            let section_index = object::read::SectionIndex(idx);
                            let part_id = object_layout
                                .section_part_id(section_index, &layout.symbol_db.section_part_ids);
                            if part_id.output_section_id() == section_id {
                                let object_section = object_layout.object.section(section_index)?;
                                let section_size =
                                    object_layout.object.section_size(object_section)? as usize;
                                let end = offset + section_size;

                                if end > group_buf.len() {
                                    bail!(
                                        "Buffer overflow writing debug section: {} > {}",
                                        end,
                                        group_buf.len()
                                    );
                                }

                                object_layout.object.copy_section_data(
                                    object_section,
                                    &mut group_buf[offset..end],
                                )?;

                                let relocations = object_layout.relocations(section_index)?;
                                match relocations {
                                    elf::RelocationList::Rela(rela) => {
                                        apply_debug_relocations::<A, Rela, _>(
                                            object_layout,
                                            &mut group_buf[offset..end],
                                            section_index,
                                            rela.iter().map(|r| Ok(*r)),
                                            layout,
                                        )?;
                                    }
                                    elf::RelocationList::Crel(crel_iter) => {
                                        apply_debug_relocations::<A, Crel, _>(
                                            object_layout,
                                            &mut group_buf[offset..end],
                                            section_index,
                                            crel_iter,
                                            layout,
                                        )?;
                                    }
                                }

                                offset = end;
                            }
                        }
                    }
                }
            }
            Ok(())
        })
}

fn update_allocation_sizes<P: Platform>(layout: &mut Layout<P>) {
    timing_phase!("Update sizes post-compression");

    for (section_id, compressed_data_opt) in layout.compressed_debug_sections.iter() {
        let Some(compressed_data) = compressed_data_opt else {
            continue;
        };

        let compressed_size: usize = compressed_data.total_compressed_size;
        let compressed_part_id = section_id.part_id_with_alignment(crate::alignment::MIN);

        for part_id in section_id.parts() {
            let part_layout = layout.section_part_layouts.get_mut(part_id);
            part_layout.file_size = 0;
        }

        let compressed_part_layout = layout.section_part_layouts.get_mut(compressed_part_id);
        compressed_part_layout.file_size = compressed_size;
        layout.merged_section_layouts.get_mut(section_id).mem_size = compressed_size as u64;
        layout.section_layouts.get_mut(section_id).mem_size = compressed_size as u64;

        for group_layout in &mut layout.group_layouts {
            for part_id in section_id.parts() {
                *group_layout.file_sizes.get_mut(part_id) = 0;
            }

            if group_layout
                .files
                .iter()
                .any(|file| matches!(file, FileLayout::Epilogue(_)))
            {
                *group_layout.file_sizes.get_mut(compressed_part_id) = compressed_size;
            }
        }

        // Free only `buckets`; the offset maps are still needed to resolve relocations from other
        // debug sections (e.g. `.debug_str_offsets`) that are written later.
        // https://github.com/wild-linker/wild/issues/2113
        layout.merged_strings.get_mut(section_id).buckets = Vec::new();
    }
}

fn update_file_offset<P: Platform>(layout: &mut Layout<P>) -> Result {
    timing_phase!("Update file offsets post-compression");

    // Recalculate file offsets since we changed file_sizes
    let mut segments = layout.segment_layouts.segments.iter().peekable();
    let mut file_offset = 0;
    for event in &layout.output_order {
        match event {
            OrderEvent::SegmentStart(program_segment_id)
                if segments.peek().is_some_and(|s| s.id == program_segment_id) =>
            {
                let segment_layout = segments.next().unwrap();
                if segment_layout.sizes.file_offset != file_offset {
                    bail!(
                        "Segment moved due to debug info compression 0x{:x} -> 0x{:x}",
                        segment_layout.sizes.file_offset,
                        file_offset,
                    );
                }
            }
            OrderEvent::Section(section_id) => {
                let section_layout = layout.section_layouts.get_mut(section_id);
                file_offset = section_layout.alignment.align_up_usize(file_offset);

                section_layout.file_offset = file_offset;

                let merge_target = layout
                    .output_sections
                    .merge_target(section_id)
                    .unwrap_or(section_id);
                let merged_section_layout = layout.merged_section_layouts.get_mut(merge_target);
                if merge_target == section_id {
                    merged_section_layout.file_offset = file_offset;
                }

                for part_id in section_id.parts() {
                    let part_layout = layout.section_part_layouts.get_mut(part_id);
                    part_layout.file_offset = file_offset;
                    file_offset += part_layout.file_size;
                }

                section_layout.file_size = file_offset - section_layout.file_offset;

                merged_section_layout.file_size = file_offset - merged_section_layout.file_offset;
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::ZlibDecoder;
    use std::io::Read as _;

    fn pattern_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn decompress_zlib(stream: &[u8]) -> Vec<u8> {
        let mut decoder = ZlibDecoder::new(stream);
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .expect("zlib decompression failed");
        out
    }

    #[test]
    fn zlib_multi_shard_round_trip() {
        let input = pattern_bytes(MIN_CHUNK_SIZE * 3 + 123);
        assert!(
            input.len() > shard_size(input.len()),
            "test data must span multiple shards"
        );

        let chunks = ZlibCompressor::compress_section(&input).unwrap();
        // Header + at least two raw-deflate shards + trailer.
        assert!(
            chunks.len() >= 4,
            "expected multi-shard layout, got {} chunks",
            chunks.len()
        );

        let stream: Vec<u8> = chunks.into_iter().flatten().collect();
        let recovered = decompress_zlib(&stream);
        assert_eq!(recovered, input);
    }

    #[test]
    fn zlib_single_shard_round_trip() {
        let input = pattern_bytes(1024);
        assert!(input.len() <= shard_size(input.len()));

        let chunks = ZlibCompressor::compress_section(&input).unwrap();
        assert_eq!(chunks.len(), 1, "single-shard path emits one zlib stream");

        let recovered = decompress_zlib(&chunks[0]);
        assert_eq!(recovered, input);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn zstd_multi_shard_round_trip() {
        let input = pattern_bytes(MIN_CHUNK_SIZE * 3 + 123);
        let chunks = ZstdCompressor::compress_section(&input).unwrap();
        assert!(chunks.len() > 1);

        // Multi-frame zstd. Frames written sequentially form one valid stream.
        let stream: Vec<u8> = chunks.into_iter().flatten().collect();
        let recovered = zstd::decode_all(stream.as_slice()).unwrap();
        assert_eq!(recovered, input);
    }
}
