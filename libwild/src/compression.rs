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
use crate::resolution::SectionSlot;
use crate::timing_phase;
use crate::verbose_timing_phase;
use itertools::Itertools;
use object::LittleEndian;
use object::bytes_of;
use object::elf::CompressionHeader64;
use object::read::elf::Crel;
use rayon::iter::IntoParallelIterator as _;
use rayon::iter::IntoParallelRefIterator as _;
use rayon::iter::ParallelIterator as _;
use std::io::Write as _;

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

const ZLIB_COMPRESSION_LEVEL: u32 = 1;
const ZSTD_COMPRESSION_LEVEL: i32 = 3;

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

trait Compressor {
    fn compress(chunk: &[u8]) -> Result<Vec<u8>>;

    fn kind() -> u32;
}

struct ZlibCompressor;

impl Compressor for ZlibCompressor {
    fn compress(chunk: &[u8]) -> Result<Vec<u8>> {
        let compression = flate2::Compression::new(ZLIB_COMPRESSION_LEVEL);
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), compression);
        encoder.write_all(chunk)?;
        Ok(encoder.finish()?)
    }

    fn kind() -> u32 {
        object::elf::ELFCOMPRESS_ZLIB
    }
}

struct ZstdCompressor;

impl Compressor for ZstdCompressor {
    fn compress(chunk: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        zstd::stream::copy_encode(chunk, &mut output, ZSTD_COMPRESSION_LEVEL)?;
        Ok(output)
    }

    fn kind() -> u32 {
        object::elf::ELFCOMPRESS_ZSTD
    }
}

fn compress_sections<A: Arch<Platform = Elf>, C: Compressor>(
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
                timing_phase!("Process debug section");

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

fn compress_section<C: Compressor>(
    uncompressed: &[u8],
    alignment: Alignment,
) -> Result<Option<CompressedSection>> {
    verbose_timing_phase!("Compress section");

    let chunk_size = std::cmp::max(MIN_CHUNK_SIZE, uncompressed.len() / MAX_CHUNKS);
    let chunks = uncompressed.chunks(chunk_size).collect_vec();

    let mut compressed_chunks = chunks
        .par_iter()
        .map(|chunk| -> Result<Vec<u8>> {
            verbose_timing_phase!("Compress chunk");
            C::compress(chunk)
        })
        .collect::<Result<Vec<_>>>()?;

    let mut header: CompressionHeader64<LittleEndian> = Default::default();
    header.ch_type.set(LittleEndian, C::kind());
    header.ch_size.set(LittleEndian, uncompressed.len() as u64);
    header.ch_addralign.set(LittleEndian, alignment.value());

    let header_bytes = bytes_of(&header).to_vec();

    let total_compressed_size: usize =
        header_bytes.len() + compressed_chunks.iter().map(|v| v.len()).sum::<usize>();

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

        *layout.merged_strings.get_mut(section_id) = Default::default();
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
