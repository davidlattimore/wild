use crate::alignment;
use crate::args::Args;
use crate::args::OutputKind;
use crate::debug_assert_bail;
use crate::elf;
use crate::elf::slice_from_all_bytes_mut;
use crate::elf::DynamicEntry;
use crate::elf::EhFrameHdr;
use crate::elf::EhFrameHdrEntry;
use crate::elf::FileHeader;
use crate::elf::GnuHashHeader;
use crate::elf::ProgramHeader;
use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
use crate::elf::SectionHeader;
use crate::elf::SymtabEntry;
use crate::elf::Vernaux;
use crate::elf::Verneed;
use crate::elf::Versym;
use crate::error::Result;
use crate::layout::compute_allocations;
use crate::layout::get_merged_string_output_address;
use crate::layout::DynamicLayout;
use crate::layout::EpilogueLayout;
use crate::layout::FileLayout;
use crate::layout::GroupLayout;
use crate::layout::HeaderInfo;
use crate::layout::InternalSymbols;
use crate::layout::Layout;
use crate::layout::ObjectLayout;
use crate::layout::PreludeLayout;
use crate::layout::Resolution;
use crate::layout::ResolutionFlags;
use crate::layout::Section;
use crate::layout::SymbolCopyInfo;
use crate::output_section_id;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::part_id;
use crate::relaxation::Relaxation;
use crate::relaxation::RelocationModifier;
use crate::resolution::SectionSlot;
use crate::resolution::ValueFlags;
use crate::sharding::ShardKey;
use crate::slice::slice_take_prefix_mut;
use crate::slice::take_first_mut;
use crate::symbol_db::SymbolDb;
use crate::threading::prelude::*;
use ahash::AHashMap;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use linker_utils::elf::rel_type_to_string;
use linker_utils::elf::shf;
use linker_utils::elf::sht;
use linker_utils::elf::SectionFlags;
use memmap2::MmapOptions;
use object::from_bytes_mut;
use object::read::elf::Rela;
use object::read::elf::Sym as _;
use object::LittleEndian;
use std::fmt::Display;
use std::io::Write;
use std::ops::Deref;
use std::ops::DerefMut;
use std::ops::Range;
use std::ops::Sub;
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use tracing::debug_span;

pub struct Output {
    path: Arc<Path>,
    creator: FileCreator,
}

enum FileCreator {
    Background {
        sized_output_sender: Option<Sender<Result<SizedOutput>>>,
        sized_output_recv: Receiver<Result<SizedOutput>>,
        deletion_complete_recv: Receiver<()>,
    },
    Regular {
        file_size: Option<u64>,
    },
}

pub(crate) struct SizedOutput {
    file: std::fs::File,
    out: OutputBuffer,
    path: Arc<Path>,
}

enum OutputBuffer {
    Mmap(memmap2::MmapMut),
    InMemory(Vec<u8>),
}

impl OutputBuffer {
    fn new(file: &std::fs::File, file_size: u64) -> Self {
        Self::new_mmapped(file, file_size)
            .unwrap_or_else(|| Self::InMemory(vec![0; file_size as usize]))
    }

    fn new_mmapped(file: &std::fs::File, file_size: u64) -> Option<Self> {
        file.set_len(file_size).ok()?;
        let mmap = unsafe { MmapOptions::new().map_mut(file) }.ok()?;
        Some(Self::Mmap(mmap))
    }
}

impl Deref for OutputBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            OutputBuffer::Mmap(mmap) => mmap.deref(),
            OutputBuffer::InMemory(vec) => vec.deref(),
        }
    }
}

impl DerefMut for OutputBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            OutputBuffer::Mmap(mmap) => mmap.deref_mut(),
            OutputBuffer::InMemory(vec) => vec.deref_mut(),
        }
    }
}

#[derive(Debug)]
struct SectionAllocation {
    id: OutputSectionId,
    offset: usize,
    size: usize,
}

impl Output {
    pub(crate) fn new(args: &Args) -> Output {
        if args.num_threads.get() > 1 {
            // Deletion of the old output file can take a while, so we start that in the background.
            // When we get to the stage where we're going to create the new output file, we'll wait
            // for deletion to complete if it hasn't already.
            let (deletion_complete_sender, deletion_complete_recv) = std::sync::mpsc::channel();
            let path = args.output.clone();
            crate::threading::spawn(move || {
                let _ = std::fs::remove_file(&path);
                let _ = deletion_complete_sender.send(());
            });

            let (sized_output_sender, sized_output_recv) = std::sync::mpsc::channel();
            Output {
                path: args.output.clone(),
                creator: FileCreator::Background {
                    deletion_complete_recv,
                    sized_output_sender: Some(sized_output_sender),
                    sized_output_recv,
                },
            }
        } else {
            delete_old_output(args);
            Output {
                path: args.output.clone(),
                creator: FileCreator::Regular { file_size: None },
            }
        }
    }

    pub(crate) fn set_size(&mut self, size: u64) {
        match &mut self.creator {
            FileCreator::Background {
                sized_output_sender,
                sized_output_recv: _,
                deletion_complete_recv,
            } => {
                // Wait for deletion of any existing output file to complete.
                let _ = deletion_complete_recv.recv();

                let sender = sized_output_sender
                    .take()
                    .expect("set_size must only be called once");
                let path = self.path.clone();
                crate::threading::spawn(move || {
                    let _ = sender.send(SizedOutput::new(path, size));
                });
            }
            FileCreator::Regular { file_size } => *file_size = Some(size),
        }
    }

    #[tracing::instrument(skip_all, name = "Write output file")]
    pub fn write(&mut self, layout: &Layout) -> Result<SizedOutput> {
        if layout.args().write_layout {
            write_layout(layout)?;
        }
        let mut sized_output = match &self.creator {
            FileCreator::Background {
                sized_output_sender,
                sized_output_recv,
                deletion_complete_recv: _,
            } => {
                assert!(sized_output_sender.is_none(), "set_size was never called");
                wait_for_sized_output(sized_output_recv)?
            }
            FileCreator::Regular { file_size } => {
                let file_size = file_size.context("set_size was never called")?;
                self.create_file_non_lazily(file_size)?
            }
        };
        sized_output.write(layout)?;
        sized_output.flush()?;
        // This triggers writing our .trace file if any. See output_trace module.
        tracing::trace!(output_write_complete = true);
        Ok(sized_output)
    }

    #[tracing::instrument(skip_all, name = "Create output file")]
    fn create_file_non_lazily(&mut self, file_size: u64) -> Result<SizedOutput> {
        SizedOutput::new(self.path.clone(), file_size)
    }
}

/// Delete the old output file. Note, this is only used when running from a single thread.
#[tracing::instrument(skip_all, name = "Delete old output")]
fn delete_old_output(args: &Args) {
    let _ = std::fs::remove_file(&args.output);
}

#[tracing::instrument(skip_all, name = "Wait for output file creation")]
fn wait_for_sized_output(sized_output_recv: &Receiver<Result<SizedOutput>>) -> Result<SizedOutput> {
    sized_output_recv.recv()?
}

impl SizedOutput {
    fn new(path: Arc<Path>, file_size: u64) -> Result<SizedOutput> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .with_context(|| format!("Failed to open `{}`", path.display()))?;
        let out = OutputBuffer::new(&file, file_size);
        Ok(SizedOutput { file, out, path })
    }

    pub(crate) fn write(&mut self, layout: &Layout) -> Result {
        self.write_file_contents(layout)?;
        if layout.args().validate_output {
            crate::validation::validate_bytes(layout, &self.out)?;
        }

        if layout.args().should_write_eh_frame_hdr {
            let mut section_buffers = split_output_into_sections(layout, &mut self.out);
            sort_eh_frame_hdr_entries(section_buffers.get_mut(output_section_id::EH_FRAME_HDR));
        }
        Ok(())
    }

    fn flush(&mut self) -> Result {
        match &self.out {
            OutputBuffer::Mmap(_) => {}
            OutputBuffer::InMemory(bytes) => self
                .file
                .write_all(bytes)
                .with_context(|| format!("Failed to write to {}", self.path.display()))?,
        }

        // Making the file executable is best-effort only. For example if we're writing to a pipe or
        // something, it isn't going to work and that's OK.
        let _ = crate::fs::make_executable(&self.file);

        Ok(())
    }

    #[tracing::instrument(skip_all, name = "Write data to file")]
    pub(crate) fn write_file_contents(&mut self, layout: &Layout) -> Result {
        let mut section_buffers = split_output_into_sections(layout, &mut self.out);

        let mut writable_buckets = split_buffers_by_alignment(&mut section_buffers, layout);
        let groups_and_buffers = split_output_by_group(layout, &mut writable_buckets);
        groups_and_buffers
            .into_par_iter()
            .try_for_each(|(group, mut buffers)| -> Result {
                let mut table_writer = TableWriter::from_layout(
                    layout,
                    group.dynstr_start_offset,
                    group.strtab_start_offset,
                    &mut buffers,
                    group.eh_frame_start_address,
                );

                for file in &group.files {
                    file.write(&mut buffers, &mut table_writer, layout)
                        .with_context(|| format!("Failed copying from {file} to output file"))?
                }
                table_writer
                    .validate_empty(&group.mem_sizes)
                    .with_context(|| format!("validate_empty failed for {group}"))?;
                Ok(())
            })?;

        for (output_section_id, section) in layout.output_sections.ids_with_info() {
            let relocations = layout
                .relocation_statistics
                .get(output_section_id)
                .load(Relaxed);
            if relocations > 0 {
                tracing::debug!(target: "metrics", section = %section.name, relocations, "resolved relocations");
            }
        }
        Ok(())
    }
}

#[tracing::instrument(skip_all, name = "Split output buffers by group")]
fn split_output_by_group<'data, 'out>(
    layout: &'data Layout<'data>,
    writable_buckets: &'out mut OutputSectionPartMap<&mut [u8]>,
) -> Vec<(
    &'data GroupLayout<'data>,
    OutputSectionPartMap<&'out mut [u8]>,
)> {
    layout
        .group_layouts
        .iter()
        .map(|group| (group, writable_buckets.take_mut(&group.file_sizes)))
        .collect()
}

fn split_output_into_sections<'out>(
    layout: &Layout<'_>,
    mut data: &'out mut [u8],
) -> OutputSectionMap<&'out mut [u8]> {
    let mut section_allocations = Vec::with_capacity(layout.section_layouts.len());
    layout.section_layouts.for_each(|id, s| {
        section_allocations.push(SectionAllocation {
            id,
            offset: s.file_offset,
            size: s.file_size,
        })
    });
    section_allocations.sort_by_key(|s| (s.offset, s.offset + s.size));

    // OutputSectionMap is ordered by section ID, which is not the same as output order. We
    // split the output file by output order, putting the relevant parts of the buffer into the
    // map.
    let mut section_data = OutputSectionMap::with_size(section_allocations.len());
    let mut offset = 0;
    for a in section_allocations {
        let Some(padding) = a.offset.checked_sub(offset) else {
            panic!(
                "Offsets went backward when splitting output file {offset} to {}",
                a.offset
            );
        };
        slice_take_prefix_mut(&mut data, padding);
        *section_data.get_mut(a.id) = slice_take_prefix_mut(&mut data, a.size);
        offset = a.offset + a.size;
    }
    section_data
}

#[tracing::instrument(skip_all, name = "Sort .eh_frame_hdr")]
fn sort_eh_frame_hdr_entries(eh_frame_hdr: &mut [u8]) {
    let entry_bytes = &mut eh_frame_hdr[core::mem::size_of::<elf::EhFrameHdr>()..];
    let entries: &mut [elf::EhFrameHdrEntry] = bytemuck::cast_slice_mut(entry_bytes);
    entries.sort_by_key(|e| e.frame_ptr);
}

/// Splits the writable buffers for each segment further into separate buffers for each alignment.
fn split_buffers_by_alignment<'out>(
    section_buffers: &'out mut OutputSectionMap<&mut [u8]>,
    layout: &Layout,
) -> OutputSectionPartMap<&'out mut [u8]> {
    layout.section_part_layouts.output_order_map(
        &layout.output_sections,
        |part_id, _alignment, rec| {
            crate::slice::slice_take_prefix_mut(
                section_buffers.get_mut(part_id.output_section_id()),
                rec.file_size,
            )
        },
    )
}

fn write_program_headers(program_headers_out: &mut ProgramHeaderWriter, layout: &Layout) -> Result {
    for segment_layout in layout.segment_layouts.segments.iter() {
        let segment_sizes = &segment_layout.sizes;
        let segment_id = segment_layout.id;
        let segment_header = program_headers_out.take_header()?;
        let mut alignment = segment_sizes.alignment;
        if segment_id.segment_type() == object::elf::PT_LOAD {
            alignment = alignment.max(crate::alignment::PAGE);
        }
        let e = LittleEndian;
        segment_header.p_type.set(e, segment_id.segment_type());
        segment_header.p_flags.set(e, segment_id.segment_flags());
        segment_header
            .p_offset
            .set(e, segment_sizes.file_offset as u64);
        segment_header.p_vaddr.set(e, segment_sizes.mem_offset);
        segment_header.p_paddr.set(e, segment_sizes.mem_offset);
        segment_header
            .p_filesz
            .set(e, segment_sizes.file_size as u64);
        segment_header.p_memsz.set(e, segment_sizes.mem_size);
        segment_header.p_align.set(e, alignment.value());
    }
    Ok(())
}

fn populate_file_header(
    layout: &Layout,
    header_info: &HeaderInfo,
    header: &mut FileHeader,
) -> Result {
    let args = layout.args();
    let ty = if args.output_kind.is_relocatable() {
        object::elf::ET_DYN
    } else {
        object::elf::ET_EXEC
    };
    let e = LittleEndian;
    header.e_ident.magic = object::elf::ELFMAG;
    header.e_ident.class = object::elf::ELFCLASS64;
    header.e_ident.data = object::elf::ELFDATA2LSB; // Little endian
    header.e_ident.version = 1;
    header.e_ident.os_abi = object::elf::ELFOSABI_NONE;
    header.e_ident.abi_version = 0;
    header.e_ident.padding = Default::default();
    header.e_type.set(e, ty);
    header.e_machine.set(e, object::elf::EM_X86_64);
    header.e_version.set(e, object::elf::EV_CURRENT as u32);
    header.e_entry.set(e, layout.entry_symbol_address()?);
    header.e_phoff.set(e, elf::PHEADER_OFFSET);
    header.e_shoff.set(
        e,
        u64::from(elf::FILE_HEADER_SIZE) + header_info.program_headers_size(),
    );
    header.e_flags.set(e, 0);
    header.e_ehsize.set(e, elf::FILE_HEADER_SIZE);
    header.e_phentsize.set(e, elf::PROGRAM_HEADER_SIZE);
    header
        .e_phnum
        .set(e, header_info.active_segment_ids.len() as u16);
    header.e_shentsize.set(e, elf::SECTION_HEADER_SIZE);
    header
        .e_shnum
        .set(e, header_info.num_output_sections_with_content);
    header.e_shstrndx.set(
        e,
        layout
            .output_sections
            .output_index_of_section(output_section_id::SHSTRTAB)
            .expect("we always write .shstrtab"),
    );
    Ok(())
}

impl<'data> FileLayout<'data> {
    fn write(
        &self,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
        table_writer: &mut TableWriter,
        layout: &Layout,
    ) -> Result {
        match self {
            FileLayout::Object(s) => s.write_file(buffers, table_writer, layout)?,
            FileLayout::Prelude(s) => s.write_file(buffers, table_writer, layout)?,
            FileLayout::Epilogue(s) => s.write_file(buffers, table_writer, layout)?,
            FileLayout::NotLoaded => {}
            FileLayout::Dynamic(s) => s.write_file(table_writer, layout)?,
        }
        Ok(())
    }
}

#[derive(Default)]
struct VersionWriter<'out> {
    version_r: &'out mut [u8],
    versym: &'out mut [Versym],
}

impl<'out> VersionWriter<'out> {
    fn new(version_r: &'out mut [u8], versym: &'out mut [Versym]) -> Self {
        Self { version_r, versym }
    }

    fn set_next_symbol_version(&mut self, index: u16) -> Result {
        let versym = crate::slice::take_first_mut(&mut self.versym)
            .context("Insufficient .gnu.version allocation")?;
        versym.0.set(LittleEndian, index);
        Ok(())
    }

    fn take_bytes(&mut self, size: usize) -> Result<&'out mut [u8]> {
        crate::slice::try_slice_take_prefix_mut(&mut self.version_r, size)
            .context("Insufficient .gnu.version_r allocation")
    }

    fn take_verneed(&mut self) -> Result<&'out mut Verneed> {
        let bytes = self.take_bytes(core::mem::size_of::<Verneed>())?;
        Ok(object::from_bytes_mut(bytes)
            .map_err(|_| anyhow!("Incorrect .gnu.version_r alignment"))?
            .0)
    }

    fn take_auxes(&mut self, version_count: u16) -> Result<&'out mut [Vernaux]> {
        let bytes =
            self.take_bytes(core::mem::size_of::<Vernaux>() * usize::from(version_count))?;
        object::slice_from_all_bytes_mut::<Vernaux>(bytes)
            .map_err(|_| anyhow!("Invalid .gnu.version_r allocation"))
    }

    fn check_exhausted(&self, mem_sizes: &OutputSectionPartMap<u64>) -> Result {
        if !self.versym.is_empty() {
            bail!(
                "Allocated too much space in .gnu.version. {} of {} entries remain",
                self.versym.len(),
                mem_sizes.get(part_id::GNU_VERSION) / elf::GNU_VERSION_ENTRY_SIZE
            );
        }
        if !self.version_r.is_empty() {
            bail!(
                "Allocated too much space in .gnu.version_r. {} of {} bytes remain",
                self.version_r.len(),
                mem_sizes.get(part_id::GNU_VERSION_R)
            );
        }
        Ok(())
    }
}

struct TableWriter<'data, 'out> {
    output_kind: OutputKind,
    got: &'out mut [u64],
    got_plt: &'out mut [u64],
    plt: &'out mut [u8],
    plt_got: &'out mut [u8],
    rela_plt: &'out mut [elf::Rela],
    tls: Range<u64>,
    rela_dyn_relative: &'out mut [crate::elf::Rela],
    rela_dyn_general: &'out mut [crate::elf::Rela],
    dynsym_writer: SymbolTableWriter<'data, 'out>,
    debug_symbol_writer: SymbolTableWriter<'data, 'out>,
    eh_frame_start_address: u64,
    eh_frame: &'out mut [u8],
    plt_base: u64,

    /// Note, this is stored as raw bytes because it starts with an EhFrameHdr, but is then followed
    /// by multiple EhFrameHdrEntry.
    eh_frame_hdr: &'out mut [u8],

    dynamic: DynamicEntriesWriter<'out>,
    version_writer: VersionWriter<'out>,
}

impl<'data, 'out> TableWriter<'data, 'out> {
    fn from_layout(
        layout: &'data Layout<'data>,
        dynstr_start_offset: u32,
        strtab_start_offset: u32,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
        eh_frame_start_address: u64,
    ) -> TableWriter<'data, 'out> {
        let dynsym_writer =
            SymbolTableWriter::new_dynamic(dynstr_start_offset, buffers, &layout.output_sections);
        let debug_symbol_writer =
            SymbolTableWriter::new(strtab_start_offset, buffers, &layout.output_sections);

        Self::new(
            layout.args().output_kind,
            layout.tls_start_address()..layout.tls_end_address(),
            buffers,
            dynsym_writer,
            debug_symbol_writer,
            eh_frame_start_address,
            layout.mem_address_of_built_in(output_section_id::PLT),
        )
    }

    fn new(
        output_kind: OutputKind,
        tls: Range<u64>,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
        dynsym_writer: SymbolTableWriter<'data, 'out>,
        debug_symbol_writer: SymbolTableWriter<'data, 'out>,
        eh_frame_start_address: u64,
        plt_base: u64,
    ) -> TableWriter<'data, 'out> {
        let eh_frame = buffers.take(part_id::EH_FRAME);
        let eh_frame_hdr = buffers.take(part_id::EH_FRAME_HDR);
        let dynamic = DynamicEntriesWriter::new(buffers.take(part_id::DYNAMIC));
        let version_writer = VersionWriter::new(
            buffers.take(part_id::GNU_VERSION_R),
            slice_from_all_bytes_mut(buffers.take(part_id::GNU_VERSION)),
        );

        TableWriter {
            output_kind,
            got: bytemuck::cast_slice_mut(buffers.take(part_id::GOT)),
            got_plt: bytemuck::cast_slice_mut(buffers.take(part_id::GOT_PLT)),
            plt: buffers.take(part_id::PLT),
            plt_got: buffers.take(part_id::PLT_GOT),
            rela_plt: slice_from_all_bytes_mut(buffers.take(part_id::RELA_PLT)),
            tls,
            rela_dyn_relative: slice_from_all_bytes_mut(buffers.take(part_id::RELA_DYN_RELATIVE)),
            rela_dyn_general: slice_from_all_bytes_mut(buffers.take(part_id::RELA_DYN_GENERAL)),
            dynsym_writer,
            debug_symbol_writer,
            eh_frame_start_address,
            eh_frame,
            eh_frame_hdr,
            dynamic,
            version_writer,
            plt_base,
        }
    }

    fn process_resolution(&mut self, res: &Resolution) -> Result {
        let is_copy_relocation = res
            .resolution_flags
            .contains(ResolutionFlags::COPY_RELOCATION);
        if is_copy_relocation {
            self.write_rela_dyn_general(
                res.raw_value,
                res.dynamic_symbol_index()?,
                object::elf::R_X86_64_COPY,
                0,
            )?;
        }
        let Some(got_address) = res.got_address else {
            return Ok(());
        };
        let mut got_address = got_address.get();
        let resolution_flags = res.resolution_flags;

        // For TLS variables, we'll generally only have one of these, but we might have both.
        if resolution_flags.contains(ResolutionFlags::GOT_TLS_OFFSET) {
            self.process_got_tls_offset(res, got_address)?;
            got_address += crate::elf::GOT_ENTRY_SIZE;
        }
        if resolution_flags.contains(ResolutionFlags::GOT_TLS_MODULE) {
            return self.process_got_tls_mod(res, got_address);
        }
        if resolution_flags.contains(ResolutionFlags::GOT_TLS_OFFSET) {
            return Ok(());
        }

        let got_entry = if resolution_flags.contains(ResolutionFlags::GOT) {
            // Non-lazy
            self.take_next_got_entry()?
        } else {
            // Lazy
            self.take_next_got_plt_entry()?
        };
        if (res.value_flags.contains(ValueFlags::DYNAMIC) && !is_copy_relocation)
            || (resolution_flags.contains(ResolutionFlags::EXPORT_DYNAMIC)
                && !res.value_flags.contains(ValueFlags::CAN_BYPASS_GOT))
                && !res.value_flags.contains(ValueFlags::IFUNC)
        {
            if res.resolution_flags.contains(ResolutionFlags::GOT) {
                debug_assert_bail!(
                    *compute_allocations(res, self.output_kind).get(part_id::RELA_DYN_GENERAL) > 0,
                    "Tried to write glob-dat with no allocation. {}",
                    ResFlagsDisplay(res)
                );
                self.write_dynamic_symbol_relocation(got_address, 0, res.dynamic_symbol_index()?)?;
            } else {
                self.write_jump_slot_relocation(res)?;
            }
        } else if res.value_flags.contains(ValueFlags::IFUNC) {
            self.write_ifunc_relocation(res)?;
        } else {
            *got_entry = res.raw_value;
            if (res.value_flags.contains(ValueFlags::ADDRESS) || is_copy_relocation)
                && self.output_kind.is_relocatable()
            {
                self.write_address_relocation(got_address, res.raw_value as i64)?;
            }
        }
        if let Some(plt_address) = res.plt_address {
            if res.resolution_flags.contains(ResolutionFlags::GOT) {
                self.write_plt_entry(got_address, plt_address.get())?;
            } else {
                self.write_jump_slot(plt_address.get())?;
            }
        }
        Ok(())
    }

    fn process_got_tls_offset(&mut self, res: &Resolution, got_address: u64) -> Result {
        let got_entry = self.take_next_got_entry()?;
        if res.value_flags.contains(ValueFlags::DYNAMIC)
            || (res
                .resolution_flags
                .contains(ResolutionFlags::EXPORT_DYNAMIC)
                && !res.value_flags.contains(ValueFlags::CAN_BYPASS_GOT))
        {
            return self.write_tpoff_relocation(got_address, res.dynamic_symbol_index()?, 0);
        }
        let address = res.raw_value;
        if !self.tls.contains(&address) {
            bail!(
                "GotTlsOffset resolves to address not in TLS segment 0x{:x}",
                address
            );
        }
        if self.output_kind.is_executable() {
            // Convert the address to an offset relative to the TCB which is the end of the
            // TLS segment.
            *got_entry = address.wrapping_sub(self.tls.end);
        } else {
            debug_assert_bail!(
                *compute_allocations(res, self.output_kind).get(part_id::RELA_DYN_GENERAL) > 0,
                "Tried to write tpoff with no allocation. {}",
                ResFlagsDisplay(res)
            );
            self.write_tpoff_relocation(got_address, 0, address.sub(self.tls.start) as i64)?;
        }
        Ok(())
    }

    fn process_got_tls_mod(&mut self, res: &Resolution, got_address: u64) -> Result {
        let got_entry = self.take_next_got_entry()?;
        if self.output_kind.is_executable() {
            *got_entry = elf::CURRENT_EXE_TLS_MOD;
        } else {
            let dynamic_symbol_index = res.dynamic_symbol_index.map(|i| i.get()).unwrap_or(0);
            debug_assert_bail!(
                *compute_allocations(res, self.output_kind).get(part_id::RELA_DYN_GENERAL) > 0,
                "Tried to write dtpmod with no allocation. {}",
                ResFlagsDisplay(res)
            );
            self.write_dtpmod_relocation(got_address, dynamic_symbol_index)?;
        }
        let offset_entry = self.take_next_got_entry()?;
        if let Some(dynamic_symbol_index) = res.dynamic_symbol_index {
            if !res.value_flags.contains(ValueFlags::CAN_BYPASS_GOT) {
                self.write_dtpoff_relocation(
                    got_address + crate::elf::TLS_OFFSET_OFFSET,
                    dynamic_symbol_index.get(),
                )?;
            }
            return Ok(());
        }
        // Convert the address to an offset within the TLS segment
        let address = res.address()?;
        *offset_entry = address - self.tls.start;
        Ok(())
    }

    fn write_jump_slot(&mut self, plt_address: u64) -> Result {
        let plt_entry = self.take_plt_entry()?;
        plt_entry.copy_from_slice(elf::JUMP_SLOT_TEMPLATE);
        let index = ((plt_address - self.plt_base) / elf::PLT_ENTRY_SIZE - 1) as u32;
        plt_entry[5..9].copy_from_slice(&index.to_le_bytes());
        // Update the jmp instruction to jump to the PLT base address.
        let pc_after_jmp = plt_address + 15;
        let relative_offset = self.plt_base.wrapping_sub(pc_after_jmp) as u32;
        plt_entry[11..15].copy_from_slice(&relative_offset.to_le_bytes());
        Ok(())
    }

    fn write_plt_entry(&mut self, got_address: u64, plt_address: u64) -> Result {
        let plt_entry = self.take_plt_got_entry()?;

        plt_entry.copy_from_slice(elf::PLT_ENTRY_TEMPLATE);
        let offset: i32 = ((got_address.wrapping_sub(plt_address + 0xb)) as i64)
            .try_into()
            .map_err(|_| anyhow!("PLT is more than 2GB away from GOT"))?;
        plt_entry[7..11].copy_from_slice(&offset.to_le_bytes());
        Ok(())
    }

    fn write_plt_lazy_header(&mut self, got_plt_base: u64) -> Result {
        let plt_entry = self.take_plt_entry()?;
        plt_entry.copy_from_slice(elf::PLT_LAZY_HEADER_TEMPLATE);

        let offset: i32 = ((got_plt_base
            .wrapping_sub(self.plt_base + 0x6)
            .wrapping_add(0x8)) as i64)
            .try_into()
            .map_err(|_| anyhow!("PLT is more than 2GB away from GOT"))?;
        plt_entry[2..6].copy_from_slice(&offset.to_le_bytes());

        let offset: i32 = ((got_plt_base
            .wrapping_sub(self.plt_base + 0xd)
            .wrapping_add(0x10)) as i64)
            .try_into()
            .map_err(|_| anyhow!("PLT is more than 2GB away from GOT"))?;
        plt_entry[9..13].copy_from_slice(&offset.to_le_bytes());

        Ok(())
    }

    fn take_plt_entry(&mut self) -> Result<&'out mut [u8]> {
        if self.plt.len() < elf::PLT_ENTRY_SIZE as usize {
            bail!("Didn't allocate enough space in .plt");
        }
        Ok(slice_take_prefix_mut(
            &mut self.plt,
            elf::PLT_ENTRY_SIZE as usize,
        ))
    }

    fn take_plt_got_entry(&mut self) -> Result<&'out mut [u8]> {
        if self.plt_got.len() < elf::PLT_ENTRY_SIZE as usize {
            bail!("Didn't allocate enough space in .plt.got");
        }
        Ok(slice_take_prefix_mut(
            &mut self.plt_got,
            elf::PLT_ENTRY_SIZE as usize,
        ))
    }

    fn take_next_got_entry(&mut self) -> Result<&'out mut u64> {
        crate::slice::take_first_mut(&mut self.got).context("Insufficient GOT allocation")
    }

    fn take_next_got_plt_entry(&mut self) -> Result<&'out mut u64> {
        crate::slice::take_first_mut(&mut self.got_plt).context("Insufficient .got.plt allocation")
    }

    /// Checks that we used all of the entries that we requested during layout.
    fn validate_empty(&self, mem_sizes: &OutputSectionPartMap<u64>) -> Result {
        if !self.got.is_empty() || !self.plt.is_empty() {
            bail!(
                "Unused PLT/GOT entries remain: GOT={}, PLT={}",
                self.got.len() as u64,
                self.plt.len() as u64 / elf::PLT_ENTRY_SIZE
            );
        }
        if !self.rela_dyn_relative.is_empty() {
            bail!(
                "Allocated too much relative space in .rela.dyn. {} of {} entries remain unused.",
                self.rela_dyn_relative.len(),
                mem_sizes.get(part_id::RELA_DYN_RELATIVE) / elf::RELA_ENTRY_SIZE,
            );
        }
        if !self.rela_dyn_general.is_empty() {
            bail!(
                "Allocated too much general space in .rela.dyn. {} of {} entries remain unused.",
                self.rela_dyn_general.len(),
                mem_sizes.get(part_id::RELA_DYN_GENERAL) / elf::RELA_ENTRY_SIZE,
            );
        }
        self.dynsym_writer.check_exhausted()?;
        self.debug_symbol_writer.check_exhausted()?;
        self.version_writer.check_exhausted(mem_sizes)?;
        if !self.eh_frame.is_empty() {
            bail!(
                "Allocated too much space in .eh_frame. {} of {} bytes remain",
                self.eh_frame.len(),
                mem_sizes.get(part_id::EH_FRAME)
            );
        }
        if !self.eh_frame_hdr.is_empty() {
            bail!(
                "Allocated too much space in .eh_frame_hdr. {} of {} bytes remain",
                self.eh_frame_hdr.len(),
                mem_sizes.get(part_id::EH_FRAME_HDR)
            );
        }
        Ok(())
    }

    fn write_jump_slot_relocation(&mut self, res: &Resolution) -> Result {
        let out = slice_take_prefix_mut(&mut self.rela_plt, 1);
        let out = &mut out[0];
        let e = LittleEndian;
        let got_address = res
            .got_address
            .context("Missing GOT entry for jump slot")?
            .get();
        out.r_offset.set(e, got_address);
        out.set_r_info(
            LittleEndian,
            false,
            res.dynamic_symbol_index()?,
            object::elf::R_X86_64_JUMP_SLOT,
        );
        Ok(())
    }

    fn write_ifunc_relocation(&mut self, res: &Resolution) -> Result {
        let out = slice_take_prefix_mut(&mut self.rela_plt, 1);
        let out = &mut out[0];
        let e = LittleEndian;
        out.r_addend.set(e, res.raw_value as i64);
        let got_address = res
            .got_address
            .context("Missing GOT entry for ifunc")?
            .get();
        out.r_offset.set(e, got_address);
        out.r_info.set(e, object::elf::R_X86_64_IRELATIVE as u64);
        Ok(())
    }

    fn write_dtpmod_relocation(&mut self, place: u64, dynamic_symbol_index: u32) -> Result {
        self.write_rela_dyn_general(
            place,
            dynamic_symbol_index,
            object::elf::R_X86_64_DTPMOD64,
            0,
        )
    }

    fn write_dtpoff_relocation(&mut self, place: u64, dynamic_symbol_index: u32) -> Result {
        self.write_rela_dyn_general(
            place,
            dynamic_symbol_index,
            object::elf::R_X86_64_DTPOFF64,
            0,
        )
    }

    fn write_tpoff_relocation(
        &mut self,
        place: u64,
        dynamic_symbol_index: u32,
        addend: i64,
    ) -> Result {
        self.write_rela_dyn_general(
            place,
            dynamic_symbol_index,
            object::elf::R_X86_64_TPOFF64,
            addend,
        )
    }

    fn write_address_relocation(&mut self, place: u64, relative_address: i64) -> Result {
        debug_assert_bail!(
            self.output_kind.is_relocatable(),
            "write_address_relocation called when output is not relocatable"
        );
        let e = LittleEndian;
        let rela = crate::slice::take_first_mut(&mut self.rela_dyn_relative)
            .context("insufficient allocation to .rela.dyn (relative)")?;
        rela.r_offset.set(e, place);
        rela.r_addend.set(e, relative_address);
        rela.r_info.set(e, object::elf::R_X86_64_RELATIVE.into());
        Ok(())
    }

    fn write_dynamic_symbol_relocation(
        &mut self,
        place: u64,
        addend: u64,
        symbol_index: u32,
    ) -> Result {
        let _span = tracing::trace_span!("write_dynamic_symbol_relocation").entered();
        debug_assert_bail!(
            self.output_kind.needs_dynsym(),
            "Tried to write dynamic relocation with non-relocatable output"
        );
        let e = LittleEndian;
        let rela = self.take_rela_dyn()?;
        rela.r_offset.set(e, place);
        rela.r_addend.set(e, addend as i64);
        rela.set_r_info(
            LittleEndian,
            false,
            symbol_index,
            object::elf::R_X86_64_GLOB_DAT,
        );
        Ok(())
    }

    fn write_rela_dyn_general(
        &mut self,
        place: u64,
        dynamic_symbol_index: u32,
        r_type: u32,
        addend: i64,
    ) -> Result {
        debug_assert_bail!(
            self.output_kind.needs_dynsym(),
            "write_glob_dat called when output is not dynamic"
        );
        let rela = self.take_rela_dyn()?;
        rela.r_offset.set(LittleEndian, place);
        rela.r_addend.set(LittleEndian, addend);
        rela.set_r_info(LittleEndian, false, dynamic_symbol_index, r_type);
        Ok(())
    }

    fn take_rela_dyn(&mut self) -> Result<&mut object::elf::Rela64<LittleEndian>> {
        tracing::trace!("Consume .rela.dyn general");
        crate::slice::take_first_mut(&mut self.rela_dyn_general)
            .context("insufficient allocation to .rela.dyn (non-relative)")
    }

    fn take_eh_frame_hdr(&mut self) -> &'out mut EhFrameHdr {
        let entry_bytes = crate::slice::slice_take_prefix_mut(
            &mut self.eh_frame_hdr,
            core::mem::size_of::<EhFrameHdr>(),
        );
        bytemuck::from_bytes_mut(entry_bytes)
    }

    fn take_eh_frame_hdr_entry(&mut self) -> Option<&mut EhFrameHdrEntry> {
        if self.eh_frame_hdr.is_empty() {
            return None;
        }
        let entry_bytes = crate::slice::slice_take_prefix_mut(
            &mut self.eh_frame_hdr,
            core::mem::size_of::<EhFrameHdrEntry>(),
        );
        Some(bytemuck::from_bytes_mut(entry_bytes))
    }

    fn take_eh_frame_data(&mut self, size: usize) -> Result<&'out mut [u8]> {
        if size > self.eh_frame.len() {
            bail!("Insufficient allocation to .eh_frame section");
        }
        Ok(crate::slice::slice_take_prefix_mut(
            &mut self.eh_frame,
            size,
        ))
    }
}

struct SymbolTableWriter<'data, 'out> {
    local_entries: &'out mut [SymtabEntry],
    global_entries: &'out mut [SymtabEntry],
    output_sections: &'data OutputSections<'data>,
    strtab_writer: StrTabWriter<'out>,
    is_dynamic: bool,
}

impl<'data, 'out> SymbolTableWriter<'data, 'out> {
    fn new(
        start_string_offset: u32,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
        output_sections: &'data OutputSections<'data>,
    ) -> Self {
        let local_entries = slice_from_all_bytes_mut(buffers.take(part_id::SYMTAB_LOCAL));
        let global_entries = slice_from_all_bytes_mut(buffers.take(part_id::SYMTAB_GLOBAL));
        let strings = buffers.take(part_id::STRTAB);
        Self {
            local_entries,
            global_entries,
            output_sections,
            strtab_writer: StrTabWriter {
                next_offset: start_string_offset,
                out: strings,
            },
            is_dynamic: false,
        }
    }

    fn new_dynamic(
        string_offset: u32,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
        output_sections: &'data OutputSections<'data>,
    ) -> Self {
        let global_entries = slice_from_all_bytes_mut(buffers.take(part_id::DYNSYM));
        let strings = slice_from_all_bytes_mut(buffers.take(part_id::DYNSTR));
        Self {
            local_entries: Default::default(),
            global_entries,
            output_sections,
            strtab_writer: StrTabWriter {
                next_offset: string_offset,
                out: strings,
            },
            is_dynamic: true,
        }
    }

    fn copy_symbol(
        &mut self,
        sym: &crate::elf::Symbol,
        name: &[u8],
        output_section_id: OutputSectionId,
        value: u64,
    ) -> Result {
        let shndx = self
            .output_sections
            .output_index_of_section(output_section_id)
            .with_context(|| {
                format!(
                    "internal error: tried to copy symbol `{}` that's in section {} \
                     which is not being output",
                    String::from_utf8_lossy(name),
                    output_section_id,
                )
            })?;
        self.copy_symbol_shndx(sym, name, shndx, value)
    }

    fn copy_symbol_shndx(
        &mut self,
        sym: &crate::elf::Symbol,
        name: &[u8],
        shndx: u16,
        value: u64,
    ) -> Result {
        let e = LittleEndian;
        let is_local = sym.is_local();
        let size = sym.st_size(e);
        let entry = self.define_symbol(is_local, shndx, value, size, name)?;
        entry.st_info = sym.st_info();
        entry.st_other = sym.st_other();
        Ok(())
    }

    fn copy_absolute_symbol(&mut self, sym: &crate::elf::Symbol, name: &[u8]) -> Result {
        let e = LittleEndian;
        let is_local = sym.is_local();
        let value = sym.st_value(e);
        let size = sym.st_size(e);
        let entry = self.define_symbol(is_local, object::elf::SHN_ABS, value, size, name)?;
        entry.st_info = sym.st_info();
        entry.st_other = sym.st_other();
        Ok(())
    }

    fn define_symbol(
        &mut self,
        is_local: bool,
        shndx: u16,
        value: u64,
        size: u64,
        name: &[u8],
    ) -> Result<&mut SymtabEntry> {
        let entry = if is_local {
            take_first_mut(&mut self.local_entries).with_context(|| {
                format!(
                    "Insufficient .symtab local entries allocated for symbol `{}`",
                    String::from_utf8_lossy(name),
                )
            })?
        } else {
            if self.is_dynamic {
                tracing::trace!("Write .dynsym {}", String::from_utf8_lossy(name));
            }
            take_first_mut(&mut self.global_entries).with_context(|| {
                format!(
                    "Insufficient {} entries allocated for symbol `{}`",
                    if self.is_dynamic {
                        ".dynsym"
                    } else {
                        ".symtab global"
                    },
                    String::from_utf8_lossy(name),
                )
            })?
        };
        let e = LittleEndian;
        let string_offset = self.strtab_writer.write_str(name);
        entry.st_name.set(e, string_offset);
        entry.st_info = 0;
        entry.st_other = 0;
        entry.st_shndx.set(e, shndx);
        entry.st_value.set(e, value);
        entry.st_size.set(e, size);
        Ok(entry)
    }

    /// Verifies that we've used up all the space allocated to this writer. i.e. checks that we
    /// didn't allocate too much or missed writing something that we were supposed to write.
    fn check_exhausted(&self) -> Result {
        if !self.local_entries.is_empty()
            || !self.global_entries.is_empty()
            || !self.strtab_writer.out.is_empty()
        {
            let table_names = if self.is_dynamic {
                "dynsym/dynstr"
            } else {
                "symtab/strtab"
            };
            bail!(
                "Didn't use up all allocated {table_names} space. local={} global={} strings={}",
                self.local_entries.len(),
                self.global_entries.len(),
                self.strtab_writer.out.len()
            );
        }
        Ok(())
    }
}

impl<'out> ObjectLayout<'out> {
    fn write_file(
        &self,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
        table_writer: &mut TableWriter,
        layout: &Layout,
    ) -> Result {
        let _span = debug_span!("write_file", filename = ?self.input.file.filename).entered();
        let _file_span = layout.args().trace_span_for_file(self.file_id);
        for sec in &self.sections {
            match sec {
                SectionSlot::Loaded(sec) => {
                    self.write_section(layout, sec, buffers, table_writer)?
                }
                SectionSlot::LoadedDebugInfo(sec) => {
                    self.write_debug_section(layout, sec, buffers)?;
                }
                SectionSlot::EhFrameData(section_index) => {
                    self.write_eh_frame_data(*section_index, layout, table_writer)?;
                }
                _ => (),
            }
        }
        for (symbol_id, resolution) in layout.resolutions_in_range(self.symbol_id_range) {
            let _span = tracing::trace_span!("Symbol", %symbol_id).entered();
            if let Some(res) = resolution {
                table_writer.process_resolution(res).with_context(|| {
                    format!(
                        "Failed to process `{}` with resolution {res:?}",
                        layout.symbol_debug(symbol_id)
                    )
                })?;

                // Dynamic symbols that we define are handled by the epilogue so that they can be
                // written in the correct order. Here, we only need to handle weak symbols that we
                // reference that aren't defined by any shared objects we're linking against.
                if res.value_flags.contains(ValueFlags::DYNAMIC) {
                    let symbol = self
                        .object
                        .symbol(self.symbol_id_range.id_to_input(symbol_id))?;
                    let name = self.object.symbol_name(symbol)?;
                    table_writer
                        .dynsym_writer
                        .copy_symbol_shndx(symbol, name, 0, 0)?;
                    if layout.gnu_version_enabled() {
                        table_writer
                            .version_writer
                            .set_next_symbol_version(object::elf::VER_NDX_GLOBAL)?;
                    }
                }
            }
        }

        if !layout.args().strip_all {
            self.write_symbols(&mut table_writer.debug_symbol_writer, layout)?;
        }
        Ok(())
    }

    fn write_section(
        &self,
        layout: &Layout,
        sec: &Section,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
        table_writer: &mut TableWriter,
    ) -> Result {
        let out = self.write_section_raw(layout, sec, buffers)?;
        self.apply_relocations(out, sec, layout, table_writer)
            .with_context(|| {
                format!(
                    "Failed to apply relocations in section `{}` of {}",
                    self.object.section_display_name(sec.index),
                    self.input
                )
            })?;
        if sec.resolution_kind.contains(ResolutionFlags::GOT)
            || sec.resolution_kind.contains(ResolutionFlags::PLT)
        {
            let res = self.section_resolutions[sec.index.0]
                .as_ref()
                .ok_or_else(|| anyhow!("Section requires GOT, but hasn't been resolved"))?;
            table_writer.process_resolution(res)?;
        };
        Ok(())
    }

    fn write_debug_section(
        &self,
        layout: &Layout,
        sec: &Section,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
    ) -> Result {
        let out = self.write_section_raw(layout, sec, buffers)?;
        self.apply_debug_relocations(out, sec, layout)
            .with_context(|| {
                format!(
                    "Failed to apply relocations in section `{}` of {}",
                    self.object.section_display_name(sec.index),
                    self.input
                )
            })?;
        Ok(())
    }

    fn write_section_raw(
        &self,
        layout: &Layout,
        sec: &Section,
        buffers: &'out mut OutputSectionPartMap<&mut [u8]>,
    ) -> Result<&'out mut [u8]> {
        if layout
            .output_sections
            .has_data_in_file(sec.output_section_id())
        {
            let section_buffer = buffers.get_mut(sec.output_part_id());
            let allocation_size = sec.capacity() as usize;
            if section_buffer.len() < allocation_size {
                bail!(
                    "Insufficient space allocated to section `{}`. Tried to take {} bytes, but only {} remain",
                    self.object.section_display_name(sec.index),
                    allocation_size, section_buffer.len()
                );
            }
            let out = slice_take_prefix_mut(section_buffer, allocation_size);
            // Cut off any padding so that our output buffer is the size of our input buffer.
            let object_section = self.object.section(sec.index)?;
            let section_size = self.object.section_size(object_section)?;
            let out: &'out mut [u8] = &mut out[..section_size as usize];
            self.object.copy_section_data(object_section, out)?;
            Ok(out)
        } else {
            Ok(&mut [])
        }
    }

    /// Writes debug symbols.
    fn write_symbols(&self, symbol_writer: &mut SymbolTableWriter, layout: &Layout) -> Result {
        for ((sym_index, sym), sym_state) in self
            .object
            .symbols
            .enumerate()
            .zip(&layout.symbol_resolution_flags[self.symbol_id_range.as_usize()])
        {
            let symbol_id = self.symbol_id_range.input_to_id(sym_index);
            if let Some(info) = SymbolCopyInfo::new(
                self.object,
                sym_index,
                sym,
                symbol_id,
                layout.symbol_db,
                *sym_state,
                &self.sections,
            ) {
                let e = LittleEndian;
                let section_id = if let Some(section_index) =
                    self.object.symbol_section(sym, sym_index)?
                {
                    match &self.sections[section_index.0] {
                        SectionSlot::Loaded(section) => section.output_section_id(),
                        SectionSlot::MergeStrings(section) => section.part_id.output_section_id(),
                        SectionSlot::EhFrameData(..) => output_section_id::EH_FRAME,
                        _ => bail!("Tried to copy a symbol in a section we didn't load"),
                    }
                } else if sym.is_common(e) {
                    output_section_id::BSS
                } else if sym.is_absolute(e) {
                    symbol_writer
                        .copy_absolute_symbol(sym, info.name)
                        .with_context(|| {
                            format!(
                                "Failed to absolute {}",
                                layout.symbol_db.symbol_debug(symbol_id)
                            )
                        })?;
                    continue;
                } else {
                    bail!("Attempted to output a symtab entry with an unexpected section type")
                };
                let Some(res) = layout.local_symbol_resolution(symbol_id) else {
                    bail!("Missing resolution for {}", layout.symbol_debug(symbol_id));
                };
                let mut symbol_value = res.value_for_symbol_table();
                if sym.st_type() == object::elf::STT_TLS {
                    let tls_start_address = layout.segment_layouts.tls_start_address.context(
                        "Writing TLS variable to symtab, but we don't have a TLS segment",
                    )?;
                    symbol_value -= tls_start_address;
                }
                symbol_writer
                    .copy_symbol(sym, info.name, section_id, symbol_value)
                    .with_context(|| {
                        format!("Failed to copy {}", layout.symbol_debug(symbol_id))
                    })?;
            }
        }
        Ok(())
    }

    fn apply_relocations(
        &self,
        out: &mut [u8],
        section: &Section,
        layout: &Layout,
        table_writer: &mut TableWriter,
    ) -> Result {
        let section_address = self.section_resolutions[section.index.0]
            .as_ref()
            .unwrap()
            .address()?;

        let object_section = self.object.section(section.index)?;
        let section_flags = SectionFlags::from_header(object_section);
        let mut modifier = RelocationModifier::Normal;
        let relocations = self.object.relocations(section.index)?;
        layout
            .relocation_statistics
            .get(section.part_id.output_section_id())
            .fetch_add(relocations.len() as u64, Relaxed);
        for rel in relocations {
            if modifier == RelocationModifier::SkipNextRelocation {
                modifier = RelocationModifier::Normal;
                continue;
            }
            let offset_in_section = rel.r_offset.get(LittleEndian);
            modifier = apply_relocation(
                self,
                offset_in_section,
                rel,
                SectionInfo {
                    section_address,
                    is_writable: section.is_writable,
                    section_flags,
                },
                layout,
                out,
                table_writer,
            )
            .with_context(|| {
                format!(
                    "Failed to apply {} at offset 0x{offset_in_section:x}",
                    self.display_relocation(rel, layout)
                )
            })?;
        }
        Ok(())
    }

    fn apply_debug_relocations(
        &self,
        out: &mut [u8],
        section: &Section,
        layout: &Layout,
    ) -> Result {
        let object_section = self.object.section(section.index)?;
        let section_name = self.object.section_name(object_section)?;
        let tombstone_value: u64 =
            // TODO: Starting with DWARF 6, the tombstone value will be defined as -1 and -2.
            // However, the change is premature as consumers of the DWARF format don't fully support
            // the new tombstone values.
            //
            // Link: https://dwarfstd.org/issues/200609.1.html
            if section_name == b".debug_loc" || section_name == b".debug_ranges" {
                // These sections use zero as a list terminator.
                1
            } else {
                0
            };

        let relocations = self.object.relocations(section.index)?;
        layout
            .relocation_statistics
            .get(section.part_id.output_section_id())
            .fetch_add(relocations.len() as u64, Relaxed);
        for rel in relocations {
            let offset_in_section = rel.r_offset.get(LittleEndian);
            apply_debug_relocation(self, offset_in_section, rel, layout, tombstone_value, out)
                .with_context(|| {
                    format!(
                        "Failed to apply {} at offset 0x{offset_in_section:x}",
                        self.display_relocation(rel, layout)
                    )
                })?;
        }
        Ok(())
    }

    fn write_eh_frame_data(
        &self,
        eh_frame_section_index: object::SectionIndex,
        layout: &Layout,
        table_writer: &mut TableWriter,
    ) -> Result {
        let eh_frame_section = self.object.section(eh_frame_section_index)?;
        let data = self.object.raw_section_data(eh_frame_section)?;
        const PREFIX_LEN: usize = core::mem::size_of::<elf::EhFrameEntryPrefix>();
        let e = LittleEndian;
        let section_flags = SectionFlags::from_header(eh_frame_section);
        let mut relocations = self
            .object
            .relocations(eh_frame_section_index)?
            .iter()
            .peekable();
        let mut input_pos = 0;
        let mut output_pos = 0;
        let frame_info_ptr_base = table_writer.eh_frame_start_address;
        let eh_frame_hdr_address = layout.mem_address_of_built_in(output_section_id::EH_FRAME_HDR);

        // Map from input offset to output offset of each CIE.
        let mut cies_offset_conversion: AHashMap<u32, u32> = AHashMap::new();

        while input_pos + PREFIX_LEN <= data.len() {
            let prefix: elf::EhFrameEntryPrefix =
                bytemuck::pod_read_unaligned(&data[input_pos..input_pos + PREFIX_LEN]);
            let size = core::mem::size_of_val(&prefix.length) + prefix.length as usize;
            let next_input_pos = input_pos + size;
            let next_output_pos = output_pos + size;
            if next_input_pos > data.len() {
                bail!("Invalid .eh_frame data");
            }
            let mut should_keep = false;
            let mut output_cie_offset = None;
            if prefix.cie_id == 0 {
                // This is a CIE
                cies_offset_conversion.insert(input_pos as u32, output_pos as u32);
                should_keep = true;
            } else {
                // This is an FDE
                if let Some(rel) = relocations.peek() {
                    let rel_offset = rel.r_offset.get(e);
                    if rel_offset < next_input_pos as u64 {
                        let is_pc_begin =
                            (rel_offset as usize - input_pos) == elf::FDE_PC_BEGIN_OFFSET;

                        if is_pc_begin {
                            let Some(index) = rel.symbol(e, false) else {
                                bail!("Unexpected absolute relocation in .eh_frame pc-begin");
                            };
                            let elf_symbol = &self.object.symbol(index)?;
                            let Some(section_index) =
                                self.object.symbol_section(elf_symbol, index)?
                            else {
                                bail!(".eh_frame pc-begin refers to symbol that's not defined in file");
                            };
                            let offset_in_section =
                                (elf_symbol.st_value(e) as i64 + rel.r_addend.get(e)) as u64;
                            if let Some(section_resolution) =
                                &self.section_resolutions[section_index.0]
                            {
                                should_keep = true;
                                let cie_pointer_pos = input_pos as u32 + 4;
                                let input_cie_pos = cie_pointer_pos
                                    .checked_sub(prefix.cie_id)
                                    .with_context(|| {
                                        format!(
                                            "CIE pointer is {}, but we're at offset {}",
                                            prefix.cie_id, cie_pointer_pos
                                        )
                                    })?;
                                if let Some(hdr_out) = table_writer.take_eh_frame_hdr_entry() {
                                    let frame_ptr =
                                        (section_resolution.address()? + offset_in_section) as i64
                                            - eh_frame_hdr_address as i64;
                                    let frame_info_ptr = (frame_info_ptr_base + output_pos as u64)
                                        as i64
                                        - eh_frame_hdr_address as i64;
                                    *hdr_out = EhFrameHdrEntry {
                                        frame_ptr: i32::try_from(frame_ptr)
                                            .context("32 bit overflow in frame_ptr")?,
                                        frame_info_ptr: i32::try_from(frame_info_ptr).context(
                                            "32 bit overflow when computing frame_info_ptr",
                                        )?,
                                    };
                                }
                                // TODO: Experiment with skipping this lookup if the `input_cie_pos`
                                // is the same as the previous entry.
                                let output_cie_pos = cies_offset_conversion.get(&input_cie_pos).with_context(|| format!("FDE referenced CIE at {input_cie_pos}, but no CIE at that position"))?;
                                output_cie_offset = Some(output_pos as u32 + 4 - *output_cie_pos);
                            }
                        }
                    }
                }
            }
            if should_keep {
                let entry_out = table_writer.take_eh_frame_data(next_output_pos - output_pos)?;
                entry_out.copy_from_slice(&data[input_pos..next_input_pos]);
                if let Some(output_cie_offset) = output_cie_offset {
                    entry_out[4..8].copy_from_slice(&output_cie_offset.to_le_bytes());
                }
                while let Some(rel) = relocations.peek() {
                    let rel_offset = rel.r_offset.get(e);
                    if rel_offset >= next_input_pos as u64 {
                        // This relocation belongs to the next entry.
                        break;
                    }
                    apply_relocation(
                        self,
                        rel_offset - input_pos as u64,
                        rel,
                        SectionInfo {
                            section_address: output_pos as u64
                                + table_writer.eh_frame_start_address,
                            is_writable: false,
                            section_flags,
                        },
                        layout,
                        entry_out,
                        table_writer,
                    )
                    .with_context(|| {
                        format!(
                            "Failed to apply eh_frame {}",
                            self.display_relocation(rel, layout)
                        )
                    })?;
                    relocations.next();
                }
                output_pos = next_output_pos;
            } else {
                // We're ignoring this entry, skip any relocations for it.
                while let Some(rel) = relocations.peek() {
                    let rel_offset = rel.r_offset.get(e);
                    if rel_offset < next_input_pos as u64 {
                        relocations.next();
                    } else {
                        break;
                    }
                }
            }
            input_pos = next_input_pos;
        }

        // Copy any remaining bytes in .eh_frame that aren't large enough to constitute an actual
        // entry. crtend.o has a single u32 equal to 0 as an end marker.
        let remaining = data.len() - input_pos;
        if remaining > 0 {
            table_writer
                .take_eh_frame_data(remaining)?
                .copy_from_slice(&data[input_pos..input_pos + remaining]);
            output_pos += remaining;
        }

        table_writer.eh_frame_start_address += output_pos as u64;

        Ok(())
    }

    fn display_relocation<'a>(
        &'a self,
        rel: &'a elf::Rela,
        layout: &'a Layout,
    ) -> DisplayRelocation<'a> {
        DisplayRelocation {
            rel,
            symbol_db: layout.symbol_db,
            object: self,
        }
    }
}

struct DisplayRelocation<'a> {
    rel: &'a elf::Rela,
    symbol_db: &'a SymbolDb<'a>,
    object: &'a ObjectLayout<'a>,
}

impl<'a> Display for DisplayRelocation<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let e = LittleEndian;
        write!(
            f,
            "relocation of type {} to ",
            rel_type_to_string(self.rel.r_type(e, false))
        )?;
        match self.rel.symbol(e, false) {
            None => write!(f, "absolute")?,
            Some(local_symbol_index) => {
                let symbol_id = self.object.symbol_id_range.input_to_id(local_symbol_index);
                write!(f, "{}", self.symbol_db.symbol_debug(symbol_id))?;
            }
        }
        Ok(())
    }
}

struct SectionInfo {
    section_address: u64,
    is_writable: bool,
    section_flags: SectionFlags,
}

/// Applies the relocation `rel` at `offset_in_section`, where the section bytes are `out`. See "ELF
/// Handling For Thread-Local Storage" for details about some of the TLS-related relocations and
/// transformations that are applied.
fn apply_relocation(
    object_layout: &ObjectLayout,
    mut offset_in_section: u64,
    rel: &elf::Rela,
    section_info: SectionInfo,
    layout: &Layout,
    out: &mut [u8],
    table_writer: &mut TableWriter,
) -> Result<RelocationModifier> {
    let section_address = section_info.section_address;
    let place = section_address + offset_in_section;
    let _span = tracing::trace_span!("relocation", address = place).entered();

    let e = LittleEndian;
    let symbol_index = rel
        .symbol(e, false)
        .context("Unsupported absolute relocation")?;
    let local_symbol_id = object_layout.symbol_id_range.input_to_id(symbol_index);
    let Some(resolution) = layout.merged_symbol_resolution(local_symbol_id) else {
        return Ok(RelocationModifier::Normal);
    };

    let value_flags = resolution.value_flags;
    let resolution_flags = resolution.resolution_flags;
    let mut addend = rel.r_addend.get(e) as u64;
    let mut next_modifier = RelocationModifier::Normal;
    let r_type = rel.r_type(e, false);
    let rel_info;
    let output_kind = layout.args().output_kind;
    if let Some(relaxation) = Relaxation::new(
        r_type,
        out,
        offset_in_section,
        value_flags,
        output_kind,
        section_info.section_flags,
    ) {
        tracing::trace!(?relaxation.kind, %value_flags, %resolution_flags);
        rel_info = relaxation.rel_info;
        relaxation.apply(out, &mut offset_in_section, &mut addend, &mut next_modifier);
    } else {
        tracing::trace!(%value_flags, %resolution_flags);
        rel_info = RelocationKindInfo::from_raw(r_type)?;
    }
    let value = match rel_info.kind {
        RelocationKind::Absolute => write_absolute_relocation(
            table_writer,
            resolution,
            place,
            addend,
            section_info,
            symbol_index,
            object_layout,
            layout,
        )?,
        RelocationKind::Relative => resolution
            .value_with_addend(
                addend.wrapping_add(rel_info.byte_size as u64),
                symbol_index,
                object_layout,
                &layout.merged_strings,
                &layout.merged_string_start_addresses,
            )?
            .wrapping_sub(place)
            .wrapping_sub(rel_info.byte_size as u64),
        RelocationKind::GotRelative => resolution
            .got_address()?
            .wrapping_add(addend)
            .wrapping_sub(place),
        RelocationKind::GotRelGotBase => resolution
            .got_address()?
            .wrapping_sub(layout.got_base())
            .wrapping_add(addend),
        RelocationKind::SymRelGotBase => resolution.value().wrapping_sub(layout.got_base()),
        RelocationKind::PltRelGotBase => resolution.plt_address()?.wrapping_sub(layout.got_base()),
        RelocationKind::PltRelative => resolution
            .plt_address()?
            .wrapping_add(addend)
            .wrapping_sub(place),
        RelocationKind::TlsGd => resolution
            .tlsgd_got_address()?
            .wrapping_add(addend)
            .wrapping_sub(place),
        RelocationKind::TlsLd => layout
            .prelude()
            .tlsld_got_entry
            .unwrap()
            .get()
            .wrapping_add(addend)
            .wrapping_sub(place),
        RelocationKind::DtpOff if output_kind == OutputKind::SharedObject => resolution
            .value()
            .sub(layout.tls_start_address())
            .wrapping_add(addend),
        RelocationKind::DtpOff => resolution
            .value()
            .wrapping_sub(layout.tls_end_address())
            .wrapping_add(addend),
        RelocationKind::GotTpOff => resolution
            .got_address()?
            .wrapping_add(addend)
            .wrapping_sub(place),
        RelocationKind::TpOff => resolution
            .value()
            .wrapping_sub(layout.tls_end_address())
            .wrapping_add(addend),
        RelocationKind::None => 0,
    };
    let value_bytes = value.to_le_bytes();
    let end = offset_in_section as usize + rel_info.byte_size;
    if out.len() < end {
        bail!("Relocation outside of bounds of section");
    }
    out[offset_in_section as usize..end].copy_from_slice(&value_bytes[..rel_info.byte_size]);
    Ok(next_modifier)
}

fn apply_debug_relocation(
    object_layout: &ObjectLayout,
    offset_in_section: u64,
    rel: &elf::Rela,
    layout: &Layout,
    section_tombstone_value: u64,
    out: &mut [u8],
) -> Result<()> {
    let e = LittleEndian;
    let symbol_index = rel
        .symbol(e, false)
        .context("Unsupported absolute relocation")?;
    let sym = object_layout.object.symbol(symbol_index)?;
    let section_index = object_layout.object.symbol_section(sym, symbol_index)?;

    let addend = rel.r_addend.get(e) as u64;
    let r_type = rel.r_type(e, false);
    let rel_info = RelocationKindInfo::from_raw(r_type)?;

    let resolution = layout
        .merged_symbol_resolution(object_layout.symbol_id_range.input_to_id(symbol_index))
        .or_else(|| {
            section_index
                .and_then(|section_index| object_layout.section_resolutions[section_index.0])
        });

    let value = if let Some(resolution) = resolution {
        match rel_info.kind {
            RelocationKind::Absolute => resolution.value_with_addend(
                addend,
                symbol_index,
                object_layout,
                &layout.merged_strings,
                &layout.merged_string_start_addresses,
            )?,
            RelocationKind::DtpOff => resolution
                .value()
                .wrapping_sub(layout.tls_end_address())
                .wrapping_add(addend),
            kind => bail!("Unsupported debug relocation kind {kind:?}"),
        }
    } else if let Some(section_index) = section_index {
        match object_layout.sections[section_index.0] {
            SectionSlot::MergeStrings(..) => get_merged_string_output_address(
                symbol_index,
                addend,
                object_layout.object,
                &object_layout.sections,
                &layout.merged_strings,
                &layout.merged_string_start_addresses,
                false,
            )?
            .context("Cannot get merged string offset for a debug info section")?,
            SectionSlot::Discard | SectionSlot::Unloaded(..) => section_tombstone_value,
            _ => bail!("Could not find a relocation resolution for a debug info section"),
        }
    } else {
        bail!("Could not find a relocation resolution for a debug info section");
    };

    let value_bytes = value.to_le_bytes();
    let end = offset_in_section as usize + rel_info.byte_size;
    if out.len() < end {
        bail!("Relocation outside of bounds of section");
    }
    out[offset_in_section as usize..end].copy_from_slice(&value_bytes[..rel_info.byte_size]);
    Ok(())
}

fn write_absolute_relocation(
    table_writer: &mut TableWriter,
    resolution: Resolution,
    place: u64,
    addend: u64,
    section_info: SectionInfo,
    symbol_index: object::SymbolIndex,
    object_layout: &ObjectLayout,
    layout: &Layout,
) -> Result<u64> {
    if resolution.value_flags.contains(ValueFlags::DYNAMIC) && section_info.is_writable {
        table_writer.write_dynamic_symbol_relocation(
            place,
            addend,
            resolution.dynamic_symbol_index()?,
        )?;
        Ok(0)
    } else if table_writer.output_kind.is_relocatable() && !resolution.is_absolute() {
        table_writer
            .write_address_relocation(place, resolution.raw_value.wrapping_add(addend) as i64)?;
        Ok(0)
    } else if resolution.value_flags.contains(ValueFlags::IFUNC) {
        Ok(resolution.plt_address()?.wrapping_add(addend))
    } else {
        resolution.value_with_addend(
            addend,
            symbol_index,
            object_layout,
            &layout.merged_strings,
            &layout.merged_string_start_addresses,
        )
    }
}

impl PreludeLayout {
    fn write_file(
        &self,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
        table_writer: &mut TableWriter,
        layout: &Layout,
    ) -> Result {
        let header: &mut FileHeader = from_bytes_mut(buffers.get_mut(part_id::FILE_HEADER))
            .map_err(|_| anyhow!("Invalid file header allocation"))?
            .0;
        populate_file_header(layout, &self.header_info, header)?;

        let mut program_headers =
            ProgramHeaderWriter::new(buffers.get_mut(part_id::PROGRAM_HEADERS));
        write_program_headers(&mut program_headers, layout)?;

        write_section_headers(buffers.get_mut(part_id::SECTION_HEADERS), layout);

        write_section_header_strings(buffers.get_mut(part_id::SHSTRTAB), &layout.output_sections);

        self.write_plt_got_entries(layout, table_writer)?;

        if !layout.args().strip_all {
            self.write_symbol_table_entries(&mut table_writer.debug_symbol_writer, layout)?;
        }

        if layout.args().should_write_eh_frame_hdr {
            write_eh_frame_hdr(table_writer, layout)?;
        }

        self.write_merged_strings(buffers, layout);

        self.write_interp(buffers);

        // If we're emitting symbol versions, we should have only one - symbol 0 - the undefined
        // symbol. It needs to be set as local.
        if layout.gnu_version_enabled() {
            table_writer
                .version_writer
                .set_next_symbol_version(object::elf::VER_NDX_GLOBAL)?;
        }

        // Define the null dynamic symbol.
        if layout.args().needs_dynsym() {
            table_writer
                .dynsym_writer
                .define_symbol(false, 0, 0, 0, &[])?;
        }

        Ok(())
    }

    fn write_interp(&self, buffers: &mut OutputSectionPartMap<&mut [u8]>) {
        if let Some(dynamic_linker) = self.dynamic_linker.as_ref() {
            buffers
                .get_mut(part_id::INTERP)
                .copy_from_slice(dynamic_linker.as_bytes_with_nul());
        }
    }

    fn write_merged_strings(&self, buffers: &mut OutputSectionPartMap<&mut [u8]>, layout: &Layout) {
        layout.merged_strings.for_each(|section_id, merged| {
            if merged.len() > 0 {
                let buffer =
                    buffers.get_mut(section_id.part_id_with_alignment(crate::alignment::MIN));
                for bucket in &merged.buckets {
                    for string in &bucket.strings {
                        let dest = crate::slice::slice_take_prefix_mut(buffer, string.len());
                        dest.copy_from_slice(string)
                    }
                }
            }
        });

        // Write linker identity into .comment section.
        let comment_buffer =
            buffers.get_mut(output_section_id::COMMENT.part_id_with_alignment(alignment::MIN));
        crate::slice::slice_take_prefix_mut(comment_buffer, self.identity.len())
            .copy_from_slice(self.identity.as_bytes());
    }

    fn write_plt_got_entries(&self, layout: &Layout, table_writer: &mut TableWriter) -> Result {
        if self.needs_lazy_plt {
            table_writer.write_plt_lazy_header(
                layout.mem_address_of_built_in(output_section_id::GOT_PLT),
            )?;
        }

        if layout.has_got_plt() {
            *table_writer.take_next_got_plt_entry()? =
                layout.mem_address_of_built_in(output_section_id::DYNAMIC);
            // These two entries are filled in at runtime.
            *table_writer.take_next_got_plt_entry()? = 0;
            *table_writer.take_next_got_plt_entry()? = 0;
        }

        // Write a pair of GOT entries for use by any TLSLD or TLSGD relocations.
        if let Some(got_address) = self.tlsld_got_entry {
            if layout.args().output_kind.is_executable() {
                table_writer.process_resolution(&Resolution {
                    raw_value: crate::elf::CURRENT_EXE_TLS_MOD,
                    dynamic_symbol_index: None,
                    got_address: Some(got_address),
                    plt_address: None,
                    resolution_flags: ResolutionFlags::GOT,
                    value_flags: ValueFlags::ABSOLUTE,
                })?;
            } else {
                table_writer.take_next_got_entry()?;
                table_writer.write_dtpmod_relocation(got_address.get(), 0)?;
            }
            table_writer.process_resolution(&Resolution {
                raw_value: 0,
                dynamic_symbol_index: None,
                got_address: Some(got_address.saturating_add(elf::GOT_ENTRY_SIZE)),
                plt_address: None,
                resolution_flags: ResolutionFlags::GOT,
                value_flags: ValueFlags::ABSOLUTE,
            })?;
        }

        write_internal_symbols_plt_got_entries(&self.internal_symbols, table_writer, layout)?;
        Ok(())
    }

    fn write_symbol_table_entries(
        &self,
        symbol_writer: &mut SymbolTableWriter,
        layout: &Layout,
    ) -> Result {
        // Define symbol 0. This needs to be a null placeholder.
        symbol_writer.define_symbol(true, 0, 0, 0, &[])?;

        let internal_symbols = &self.internal_symbols;

        write_internal_symbols(internal_symbols, layout, symbol_writer)?;
        Ok(())
    }
}

fn write_epilogue_dynamic_entries(layout: &Layout, table_writer: &mut TableWriter) -> Result {
    for rpath in &layout.args().rpaths {
        let offset = table_writer
            .dynsym_writer
            .strtab_writer
            .write_str(rpath.as_bytes());
        table_writer
            .dynamic
            .write(object::elf::DT_RUNPATH, offset.into())?;
    }
    if let Some(soname) = layout.args().soname.as_ref() {
        let offset = table_writer
            .dynsym_writer
            .strtab_writer
            .write_str(soname.as_bytes());
        table_writer
            .dynamic
            .write(object::elf::DT_SONAME, offset.into())?;
    }
    for writer in EPILOGUE_DYNAMIC_ENTRY_WRITERS {
        writer.write(&mut table_writer.dynamic, layout)?;
    }

    Ok(())
}

impl<'data> EpilogueLayout<'data> {
    fn write_file(
        &self,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
        table_writer: &mut TableWriter,
        layout: &Layout,
    ) -> Result {
        write_internal_symbols_plt_got_entries(&self.internal_symbols, table_writer, layout)?;

        if !layout.args().strip_all {
            write_internal_symbols(
                &self.internal_symbols,
                layout,
                &mut table_writer.debug_symbol_writer,
            )?;
        }
        if layout.args().needs_dynamic() {
            write_epilogue_dynamic_entries(layout, table_writer)?;
        }
        write_gnu_hash_tables(self, buffers)?;

        write_dynamic_symbol_definitions(self, table_writer, layout)?;

        Ok(())
    }
}

fn write_gnu_hash_tables(
    epilogue: &EpilogueLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let Some(gnu_hash_layout) = epilogue.gnu_hash_layout.as_ref() else {
        return Ok(());
    };

    let (header, rest) =
        object::from_bytes_mut::<GnuHashHeader>(buffers.get_mut(part_id::GNU_HASH))
            .map_err(|_| anyhow!("Insufficient .gnu.hash allocation"))?;
    let e = LittleEndian;
    header.bucket_count.set(e, gnu_hash_layout.bucket_count);
    header.bloom_shift.set(e, gnu_hash_layout.bloom_shift);
    header.bloom_count.set(e, gnu_hash_layout.bloom_count);
    header.symbol_base.set(e, gnu_hash_layout.symbol_base);

    let (bloom, rest) =
        object::slice_from_bytes_mut::<u64>(rest, gnu_hash_layout.bloom_count as usize)
            .map_err(|_| anyhow!("Insufficient bytes for .gnu.hash bloom filter"))?;
    let (buckets, rest) =
        object::slice_from_bytes_mut::<u32>(rest, gnu_hash_layout.bucket_count as usize)
            .map_err(|_| anyhow!("Insufficient bytes for .gnu.hash buckets"))?;
    let (chains, _) =
        object::slice_from_bytes_mut::<u32>(rest, epilogue.dynamic_symbol_definitions.len())
            .map_err(|_| anyhow!("Insufficient bytes for .gnu.hash chains"))?;

    bloom.fill(0);

    let mut sym_defs = epilogue.dynamic_symbol_definitions.iter().peekable();

    let elf_class_bits = core::mem::size_of::<u64>() as u32 * 8;

    let mut start_of_chain = true;
    for (i, chain_out) in chains.iter_mut().enumerate() {
        let sym_def = sym_defs.next().unwrap();

        // For each symbol, we set two bits in the bloom filter. This speeds up dynamic loading,
        // since most symbols not defined by the shared object can be rejected just by the bloom
        // filter.
        let bloom_index = ((sym_def.hash / elf_class_bits) % gnu_hash_layout.bloom_count) as usize;
        let bit1 = 1 << (sym_def.hash % elf_class_bits);
        let bit2 = 1 << ((sym_def.hash >> gnu_hash_layout.bloom_shift) % elf_class_bits);
        bloom[bloom_index] |= bit1 | bit2;

        // Chain values are the hashes for the corresponding symbols (shifted by symbol_base). Bit 0
        // is cleared and then later set to 1 to indicate the end of the chain.
        *chain_out = sym_def.hash & !1;
        let bucket = gnu_hash_layout.bucket_for_hash(sym_def.hash);
        if start_of_chain {
            buckets[bucket as usize] = (i as u32) + gnu_hash_layout.symbol_base;
            start_of_chain = false;
        }
        let last_in_chain = sym_defs
            .peek()
            .map(|next| gnu_hash_layout.bucket_for_hash(next.hash) != bucket)
            .unwrap_or(true);
        if last_in_chain {
            *chain_out |= 1;
            start_of_chain = true;
        }
    }
    Ok(())
}

fn write_dynamic_symbol_definitions(
    epilogue: &EpilogueLayout,
    table_writer: &mut TableWriter,
    layout: &Layout,
) -> Result {
    for sym_def in &epilogue.dynamic_symbol_definitions {
        let file_id = layout.symbol_db.file_id_for_symbol(sym_def.symbol_id);
        let file_layout = &layout.file_layout(file_id);
        match file_layout {
            FileLayout::Object(object) => {
                write_regular_object_dynamic_symbol_definition(
                    sym_def,
                    object,
                    layout,
                    &mut table_writer.dynsym_writer,
                )?;

                // We don't yet support setting symbol versions for symbols that we export, so right
                // now we just set them all to the global version.
                if let Some(version_out) =
                    crate::slice::take_first_mut(&mut table_writer.version_writer.versym)
                {
                    version_out.0.set(LittleEndian, object::elf::VER_NDX_GLOBAL);
                }
            }
            FileLayout::Dynamic(object) => {
                write_copy_relocation_dynamic_symbol_definition(
                    sym_def,
                    object,
                    layout,
                    &mut table_writer.dynsym_writer,
                )?;

                write_symbol_version(
                    object.input_symbol_versions,
                    object.symbol_id_range.id_to_offset(sym_def.symbol_id),
                    &object.version_mapping,
                    &mut table_writer.version_writer.versym,
                )?;
            }
            _ => bail!(
                "Internal error: Unexpected dynamic symbol definition from {:?}. {}",
                file_layout,
                layout.symbol_debug(sym_def.symbol_id)
            ),
        }
    }

    Ok(())
}

fn write_copy_relocation_dynamic_symbol_definition(
    sym_def: &crate::layout::DynamicSymbolDefinition,
    object: &DynamicLayout,
    layout: &Layout,
    dynamic_symbol_writer: &mut SymbolTableWriter,
) -> Result {
    debug_assert_bail!(
        layout
            .resolution_flags_for_symbol(sym_def.symbol_id)
            .contains(ResolutionFlags::COPY_RELOCATION),
        "Tried to write copy relocation for symbol without COPY_RELOCATION flag"
    );
    let sym_index = sym_def.symbol_id.to_input(object.symbol_id_range);
    let sym = object.object.symbol(sym_index)?;
    let name = sym_def.name;
    let shndx = layout
        .output_sections
        .output_index_of_section(output_section_id::BSS)
        .context("Copy relocation with no BSS section")?;
    let res = layout
        .local_symbol_resolution(sym_def.symbol_id)
        .context("Copy relocation for unresolved symbol")?;
    dynamic_symbol_writer
        .copy_symbol_shndx(sym, name, shndx, res.raw_value)
        .with_context(|| {
            format!(
                "Failed to copy dynamic {}",
                layout.symbol_debug(sym_def.symbol_id)
            )
        })?;
    Ok(())
}

fn write_regular_object_dynamic_symbol_definition(
    sym_def: &crate::layout::DynamicSymbolDefinition,
    object: &ObjectLayout,
    layout: &Layout,
    dynamic_symbol_writer: &mut SymbolTableWriter,
) -> Result {
    let sym_index = sym_def.symbol_id.to_input(object.symbol_id_range);
    let sym = object.object.symbol(sym_index)?;
    let name = sym_def.name;
    if let Some(section_index) = object.object.symbol_section(sym, sym_index)? {
        let SectionSlot::Loaded(section) = &object.sections[section_index.0] else {
            bail!("Internal error: Defined symbols should always be for a loaded section");
        };
        let output_section_id = section.output_section_id();
        let symbol_id = sym_def.symbol_id;
        let resolution = layout.local_symbol_resolution(symbol_id).with_context(|| {
            format!(
                "Tried to write dynamic symbol definition without a resolution: {}",
                layout.symbol_debug(symbol_id)
            )
        })?;
        let mut symbol_value = resolution.raw_value;
        if sym.st_type() == object::elf::STT_TLS {
            let tls_start_address = layout
                .segment_layouts
                .tls_start_address
                .context("Writing TLS variable to symtab, but we don't have a TLS segment")?;
            symbol_value -= tls_start_address;
        }
        dynamic_symbol_writer
            .copy_symbol(sym, name, output_section_id, symbol_value)
            .with_context(|| {
                format!("Failed to copy dynamic {}", layout.symbol_debug(symbol_id))
            })?;
    } else {
        dynamic_symbol_writer
            .copy_symbol_shndx(sym, name, 0, 0)
            .with_context(|| {
                format!(
                    "Failed to copy dynamic {}",
                    layout.symbol_debug(sym_def.symbol_id)
                )
            })?;
    };
    Ok(())
}

fn write_internal_symbols(
    internal_symbols: &InternalSymbols,
    layout: &Layout<'_>,
    symbol_writer: &mut SymbolTableWriter<'_, '_>,
) -> Result {
    for (local_index, def_info) in internal_symbols.symbol_definitions.iter().enumerate() {
        let symbol_id = internal_symbols.start_symbol_id.add_usize(local_index);
        if !layout.symbol_db.is_canonical(symbol_id) {
            continue;
        }
        let Some(resolution) = layout.local_symbol_resolution(symbol_id) else {
            continue;
        };
        let Some(section_id) = def_info.section_id() else {
            // The null symbol is currently handled elsewhere. TODO: See if the code would be
            // simpler if we just handled it here.
            continue;
        };

        let symbol_name = layout.symbol_db.symbol_name(symbol_id)?;
        let mut shndx = layout
            .output_sections
            .output_index_of_section(section_id)
            .with_context(|| {
                format!(
                    "symbol `{}` in section `{}` that we're not going to output {resolution:?}",
                    symbol_name,
                    layout.output_sections.display_name(section_id)
                )
            })?;

        // Move symbols that are in our header (section 0) into the first section, otherwise they'll
        // show up as undefined.
        if shndx == 0 {
            shndx = 1;
        }

        let address = resolution.address()?;
        let entry = symbol_writer
            .define_symbol(false, shndx, address, 0, symbol_name.bytes())
            .with_context(|| format!("Failed to write {}", layout.symbol_debug(symbol_id)))?;
        entry.st_info = object::elf::STB_GLOBAL << 4;
    }
    Ok(())
}

fn write_eh_frame_hdr(table_writer: &mut TableWriter, layout: &Layout<'_>) -> Result {
    let header = table_writer.take_eh_frame_hdr();
    header.version = 1;

    header.table_encoding = elf::ExceptionHeaderFormat::I32 as u8
        | elf::ExceptionHeaderApplication::EhFrameHdrRelative as u8;

    header.frame_pointer_encoding =
        elf::ExceptionHeaderFormat::I32 as u8 | elf::ExceptionHeaderApplication::Relative as u8;
    header.frame_pointer = eh_frame_ptr(layout)?;

    header.count_encoding =
        elf::ExceptionHeaderFormat::U32 as u8 | elf::ExceptionHeaderApplication::Absolute as u8;
    header.entry_count = eh_frame_hdr_entry_count(layout)?;

    Ok(())
}

fn eh_frame_hdr_entry_count(layout: &Layout<'_>) -> Result<u32> {
    let hdr_sec = layout.section_layouts.get(output_section_id::EH_FRAME_HDR);
    u32::try_from(
        (hdr_sec.mem_size - core::mem::size_of::<elf::EhFrameHdr>() as u64)
            / core::mem::size_of::<elf::EhFrameHdrEntry>() as u64,
    )
    .context(".eh_frame_hdr entries overflowed 32 bits")
}

/// Returns the address of .eh_frame relative to the location in .eh_frame_hdr where the frame
/// pointer is stored.
fn eh_frame_ptr(layout: &Layout<'_>) -> Result<i32> {
    let eh_frame_address = layout.mem_address_of_built_in(output_section_id::EH_FRAME);
    let eh_frame_hdr_address = layout.mem_address_of_built_in(output_section_id::EH_FRAME_HDR);
    i32::try_from(
        eh_frame_address - (eh_frame_hdr_address + elf::FRAME_POINTER_FIELD_OFFSET as u64),
    )
    .context(".eh_frame more than 2GB away from .eh_frame_hdr")
}

/// An upper-bound on how many dynamic entries we'll write in the epilogue. Some entries are
/// optional, so might not get written. For now, we still allocate space for these optional entries.
pub(crate) const NUM_EPILOGUE_DYNAMIC_ENTRIES: usize = EPILOGUE_DYNAMIC_ENTRY_WRITERS.len();

const EPILOGUE_DYNAMIC_ENTRY_WRITERS: &[DynamicEntryWriter] = &[
    DynamicEntryWriter::optional(
        object::elf::DT_INIT,
        |layout| layout.has_data_in_section(output_section_id::INIT),
        |layout| layout.vma_of_section(output_section_id::INIT),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_FINI,
        |layout| layout.has_data_in_section(output_section_id::FINI),
        |layout| layout.vma_of_section(output_section_id::FINI),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_INIT_ARRAY,
        |layout| layout.has_data_in_section(output_section_id::INIT_ARRAY),
        |layout| layout.vma_of_section(output_section_id::INIT_ARRAY),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_INIT_ARRAYSZ,
        |layout| layout.has_data_in_section(output_section_id::INIT_ARRAY),
        |layout| layout.size_of_section(output_section_id::INIT_ARRAY),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_FINI_ARRAY,
        |layout| layout.has_data_in_section(output_section_id::FINI_ARRAY),
        |layout| layout.vma_of_section(output_section_id::FINI_ARRAY),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_FINI_ARRAYSZ,
        |layout| layout.has_data_in_section(output_section_id::FINI_ARRAY),
        |layout| layout.size_of_section(output_section_id::FINI_ARRAY),
    ),
    DynamicEntryWriter::new(object::elf::DT_STRTAB, |layout| {
        layout.vma_of_section(output_section_id::DYNSTR)
    }),
    DynamicEntryWriter::new(object::elf::DT_STRSZ, |layout| {
        layout.size_of_section(output_section_id::DYNSTR)
    }),
    DynamicEntryWriter::new(object::elf::DT_SYMTAB, |layout| {
        layout.vma_of_section(output_section_id::DYNSYM)
    }),
    DynamicEntryWriter::new(object::elf::DT_SYMENT, |_layout| {
        core::mem::size_of::<elf::SymtabEntry>() as u64
    }),
    DynamicEntryWriter::optional(
        object::elf::DT_VERNEED,
        |layout| {
            layout
                .section_part_layouts
                .get(part_id::GNU_VERSION_R)
                .mem_size
                > 0
        },
        |layout| layout.vma_of_section(output_section_id::GNU_VERSION_R),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_VERNEEDNUM,
        |layout| {
            layout
                .section_part_layouts
                .get(part_id::GNU_VERSION_R)
                .mem_size
                > 0
        },
        |layout| layout.non_addressable_counts.verneed_count,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_VERSYM,
        |layout| {
            layout
                .section_part_layouts
                .get(part_id::GNU_VERSION)
                .mem_size
                > 0
        },
        |layout| layout.vma_of_section(output_section_id::GNU_VERSION),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_DEBUG,
        |layout| {
            // Not sure why, but GNU ld seems to emit this for executables but not for shared
            // objects.
            layout.args().output_kind != OutputKind::SharedObject
        },
        |_layout| 0,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_JMPREL,
        |layout| layout.section_part_layouts.get(part_id::RELA_PLT).mem_size > 0,
        |layout| layout.vma_of_section(output_section_id::RELA_PLT),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_PLTGOT,
        |layout| layout.args().needs_dynamic(),
        |layout| {
            layout.vma_of_section(if layout.size_of_section(output_section_id::GOT_PLT) > 0 {
                output_section_id::GOT_PLT
            } else {
                output_section_id::GOT
            })
        },
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_PLTREL,
        |layout| layout.section_part_layouts.get(part_id::RELA_PLT).mem_size > 0,
        |_| object::elf::DT_RELA.into(),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_PLTRELSZ,
        |layout| layout.section_part_layouts.get(part_id::RELA_PLT).mem_size > 0,
        |layout| layout.section_part_layouts.get(part_id::RELA_PLT).mem_size,
    ),
    DynamicEntryWriter::new(object::elf::DT_RELA, |layout| {
        layout.vma_of_section(output_section_id::RELA_DYN)
    }),
    DynamicEntryWriter::new(object::elf::DT_RELASZ, |layout| {
        layout.size_of_section(output_section_id::RELA_DYN)
    }),
    DynamicEntryWriter::new(object::elf::DT_RELAENT, |_layout| elf::RELA_ENTRY_SIZE),
    // Note, rela-count is just the count of the relative relocations and doesn't include any
    // glob-dat relocations. This is as opposed to rela-size, which includes both.
    DynamicEntryWriter::new(object::elf::DT_RELACOUNT, |layout| {
        layout
            .section_part_layouts
            .get(part_id::RELA_DYN_RELATIVE)
            .mem_size
            / core::mem::size_of::<elf::Rela>() as u64
    }),
    DynamicEntryWriter::new(object::elf::DT_GNU_HASH, |layout| {
        layout.vma_of_section(output_section_id::GNU_HASH)
    }),
    DynamicEntryWriter::optional(
        object::elf::DT_FLAGS,
        |layout| layout.dt_flags() != 0,
        |layout| layout.dt_flags(),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_FLAGS_1,
        |layout| layout.dt_flags_1() != 0,
        |layout| layout.dt_flags_1(),
    ),
    DynamicEntryWriter::new(object::elf::DT_NULL, |_layout| 0),
];

struct DynamicEntryWriter {
    tag: u32,
    is_present_cb: fn(&Layout) -> bool,
    cb: fn(&Layout) -> u64,
}

impl DynamicEntryWriter {
    const fn new(tag: u32, cb: fn(&Layout) -> u64) -> DynamicEntryWriter {
        DynamicEntryWriter {
            tag,
            is_present_cb: |_| true,
            cb,
        }
    }

    const fn optional(
        tag: u32,
        is_present_cb: fn(&Layout) -> bool,
        cb: fn(&Layout) -> u64,
    ) -> DynamicEntryWriter {
        DynamicEntryWriter {
            tag,
            is_present_cb,
            cb,
        }
    }

    fn is_present(&self, layout: &Layout) -> bool {
        (self.is_present_cb)(layout)
    }

    fn write(&self, out: &mut DynamicEntriesWriter, layout: &Layout) -> Result {
        if !self.is_present(layout) {
            return Ok(());
        }
        let value = (self.cb)(layout);
        out.write(self.tag, value)
    }
}

struct DynamicEntriesWriter<'out> {
    out: &'out mut [DynamicEntry],
}

impl<'out> DynamicEntriesWriter<'out> {
    fn new(buffer: &mut [u8]) -> DynamicEntriesWriter {
        DynamicEntriesWriter {
            out: slice_from_all_bytes_mut(buffer),
        }
    }

    fn write(&mut self, tag: u32, value: u64) -> Result {
        let entry = crate::slice::take_first_mut(&mut self.out)
            .ok_or_else(|| anyhow!("Insufficient dynamic table entries"))?;
        let e = LittleEndian;
        entry.d_tag.set(e, tag as u64);
        entry.d_val.set(e, value);
        Ok(())
    }
}

fn write_section_headers(out: &mut [u8], layout: &Layout) {
    let entries: &mut [SectionHeader] = slice_from_all_bytes_mut(out);
    let output_sections = &layout.output_sections;
    let mut entries = entries.iter_mut();
    let mut name_offset = 0;

    for event in output_sections.sections_and_segments_events() {
        let OrderEvent::Section(section_id) = event else {
            continue;
        };
        let section_type = output_sections.section_type(section_id);
        let section_layout = layout.section_layouts.get(section_id);
        if output_sections
            .output_index_of_section(section_id)
            .is_none()
        {
            continue;
        }
        let entsize = section_id.element_size();
        let size;
        let alignment;
        if section_type == sht::NULL {
            size = 0;
            alignment = 0;
        } else {
            size = section_layout.mem_size;
            alignment = section_layout.alignment.value();
        };
        let link = layout
            .output_sections
            .link_ids(section_id)
            .iter()
            .find_map(|link_id| output_sections.output_index_of_section(*link_id))
            .unwrap_or(0);
        let entry = entries.next().unwrap();
        let e = LittleEndian;
        entry.sh_name.set(e, name_offset);
        entry.sh_type.set(e, section_type.raw());
        // TODO: Section are always uncompressed and the output compression is not supported yet.
        entry.sh_flags.set(
            e,
            output_sections
                .section_flags(section_id)
                .without(shf::COMPRESSED)
                .raw(),
        );
        entry.sh_addr.set(e, section_layout.mem_offset);
        entry.sh_offset.set(e, section_layout.file_offset as u64);
        entry.sh_size.set(e, size);
        entry.sh_link.set(e, link.into());
        entry.sh_info.set(e, section_id.info(layout));
        entry.sh_addralign.set(e, alignment);
        entry.sh_entsize.set(e, entsize);
        name_offset += layout.output_sections.name(section_id).len() as u32 + 1;
    }
    assert!(
        entries.next().is_none(),
        "Allocated section entries that weren't used"
    );
}

fn write_section_header_strings(mut out: &mut [u8], sections: &OutputSections) {
    for event in sections.sections_and_segments_events() {
        if let OrderEvent::Section(id) = event {
            if sections.output_index_of_section(id).is_some() {
                let name = sections.name(id);
                let name_out = crate::slice::slice_take_prefix_mut(&mut out, name.len() + 1);
                name_out[..name.len()].copy_from_slice(name.bytes());
                name_out[name.len()] = 0;
            }
        }
    }
}

struct ProgramHeaderWriter<'out> {
    headers: &'out mut [ProgramHeader],
}

impl<'out> ProgramHeaderWriter<'out> {
    fn new(bytes: &'out mut [u8]) -> Self {
        Self {
            headers: slice_from_all_bytes_mut(bytes),
        }
    }

    fn take_header(&mut self) -> Result<&mut ProgramHeader> {
        crate::slice::take_first_mut(&mut self.headers)
            .ok_or_else(|| anyhow!("Insufficient header slots"))
    }
}

fn write_internal_symbols_plt_got_entries(
    internal_symbols: &InternalSymbols,
    table_writer: &mut TableWriter,
    layout: &Layout,
) -> Result {
    for i in 0..internal_symbols.symbol_definitions.len() {
        let symbol_id = internal_symbols.start_symbol_id.add_usize(i);
        if !layout.symbol_db.is_canonical(symbol_id) {
            continue;
        }
        if let Some(res) = layout.local_symbol_resolution(symbol_id) {
            table_writer.process_resolution(res).with_context(|| {
                format!("Failed to process `{}`", layout.symbol_debug(symbol_id))
            })?;
        }
    }
    Ok(())
}

impl<'data> DynamicLayout<'data> {
    fn write_file(&self, table_writer: &mut TableWriter, layout: &Layout) -> Result {
        self.write_so_name(table_writer)?;

        for ((symbol_id, resolution), symbol) in layout
            .resolutions_in_range(self.symbol_id_range)
            .zip(self.object.symbols.iter())
        {
            if let Some(res) = resolution {
                if res
                    .resolution_flags
                    .contains(ResolutionFlags::COPY_RELOCATION)
                {
                    // Symbol needs a copy relocation, which means that the symbol will be written
                    // by the epilogue not by us.
                } else {
                    let name = self.object.symbol_name(symbol)?;
                    table_writer
                        .dynsym_writer
                        .copy_symbol_shndx(symbol, name, 0, 0)?;

                    write_symbol_version(
                        self.input_symbol_versions,
                        self.symbol_id_range.id_to_offset(symbol_id),
                        &self.version_mapping,
                        &mut table_writer.version_writer.versym,
                    )?;
                }

                table_writer.process_resolution(res).with_context(|| {
                    format!(
                        "Failed to write {}",
                        layout.symbol_db.symbol_debug(symbol_id)
                    )
                })?;
            }
        }

        if let Some(verdef_info) = &self.verdef_info {
            let mut verdefs = verdef_info.defs.clone();
            let e = LittleEndian;
            let strings = self.object.sections.strings(
                e,
                self.object.data,
                verdef_info.string_table_index,
            )?;
            let ver_need = table_writer.version_writer.take_verneed()?;
            let next_verneed_offset = if self.is_last_verneed {
                0
            } else {
                (core::mem::size_of::<Verneed>()
                    + core::mem::size_of::<Vernaux>() * verdef_info.version_count as usize)
                    as u32
            };
            ver_need.vn_version.set(e, 1);
            ver_need.vn_cnt.set(e, verdef_info.version_count);
            ver_need
                .vn_aux
                .set(e, core::mem::size_of::<Verneed>() as u32);
            ver_need.vn_next.set(e, next_verneed_offset);

            let auxes = table_writer
                .version_writer
                .take_auxes(verdef_info.version_count)?;
            let mut aux_index = 0;
            while let Some((verdef, mut aux_iterator)) = verdefs.next()? {
                let input_version = verdef.vd_ndx.get(e);
                let flags = verdef.vd_flags.get(e);
                let is_base = (flags & object::elf::VER_FLG_BASE) != 0;
                if is_base {
                    let aux_in = aux_iterator.next()?.context("VERDEF with no AUX entry")?;
                    let name = aux_in.name(e, strings)?;
                    let name_offset = table_writer.dynsym_writer.strtab_writer.write_str(name);
                    ver_need.vn_file.set(e, name_offset);
                    continue;
                }
                if input_version == 0 {
                    bail!("Invalid version index");
                }
                let output_version = self
                    .version_mapping
                    .get(usize::from(input_version - 1))
                    .copied()
                    .unwrap_or_default();
                if output_version != object::elf::VER_NDX_GLOBAL {
                    // Every VERDEF entry should have at least one AUX entry.
                    let aux_in = aux_iterator.next()?.context("VERDEF with no AUX entry")?;
                    let name = aux_in.name(e, strings)?;
                    let name_offset = table_writer.dynsym_writer.strtab_writer.write_str(name);
                    let sysv_name_hash = object::elf::hash(name);
                    let is_last_aux = aux_index + 1 == auxes.len();
                    let aux_out = auxes
                        .get_mut(aux_index)
                        .context("Insufficient vernaux allocation")?;
                    let vna_next = if is_last_aux {
                        0
                    } else {
                        core::mem::size_of::<Vernaux>() as u32
                    };
                    aux_out.vna_next.set(e, vna_next);
                    aux_out.vna_other.set(e, output_version);
                    aux_out.vna_name.set(e, name_offset);
                    aux_out.vna_hash.set(e, sysv_name_hash);
                    aux_index += 1;
                }
            }
        }

        Ok(())
    }

    /// Write dynamic entry to indicate name of shared object to load.
    fn write_so_name(&self, table_writer: &mut TableWriter) -> Result {
        let needed_offset = table_writer
            .dynsym_writer
            .strtab_writer
            .write_str(self.lib_name);
        table_writer
            .dynamic
            .write(object::elf::DT_NEEDED, needed_offset.into())?;
        Ok(())
    }
}

fn write_symbol_version(
    versym_in: &[Versym],
    local_symbol_index: usize,
    version_mapping: &[u16],
    versym_out: &mut &mut [Versym],
) -> Result {
    let version_out =
        crate::slice::take_first_mut(versym_out).context("Insufficient .gnu.version allocation")?;
    let output_version = versym_in
        .get(local_symbol_index)
        .map(|versym| {
            let input_version = versym.0.get(LittleEndian) & object::elf::VERSYM_VERSION;
            if input_version <= object::elf::VER_NDX_GLOBAL {
                input_version
            } else {
                version_mapping[usize::from(input_version) - 1]
            }
        })
        .unwrap_or(object::elf::VER_NDX_GLOBAL);
    version_out.0.set(LittleEndian, output_version);
    Ok(())
}

struct StrTabWriter<'out> {
    next_offset: u32,
    out: &'out mut [u8],
}

impl<'out> StrTabWriter<'out> {
    /// Writes a string to the string table. Returns the offset within the string table at which the
    /// string was written.
    fn write_str(&mut self, str: &[u8]) -> u32 {
        let len_with_terminator = str.len() + 1;
        let lib_name_out = slice_take_prefix_mut(&mut self.out, len_with_terminator);
        lib_name_out[..str.len()].copy_from_slice(str);
        lib_name_out[str.len()] = 0;
        let offset = self.next_offset;
        self.next_offset += len_with_terminator as u32;
        offset
    }
}

fn write_layout(layout: &Layout) -> Result {
    let layout_path = linker_layout::layout_path(&layout.args().output);
    write_layout_to(layout, &layout_path)
        .with_context(|| format!("Failed to write layout to `{}`", layout_path.display()))
}

fn write_layout_to(layout: &Layout, path: &Path) -> Result {
    let mut file = std::io::BufWriter::new(std::fs::File::create(path)?);
    layout.layout_data().write(&mut file)?;
    Ok(())
}

struct ResFlagsDisplay<'a>(&'a Resolution);

impl Display for ResFlagsDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "value_flags = {} resolution_flags = {}",
            self.0.value_flags, self.0.resolution_flags
        )
    }
}

#[cfg(test)]
pub(crate) fn verify_resolution_allocation(
    output_sections: &OutputSections,
    output_kind: OutputKind,
    mem_sizes: OutputSectionPartMap<u64>,
    resolution: &Resolution,
) -> Result {
    // Allocate however much space was requested.
    let mut total_bytes_allocated = 0;
    mem_sizes.output_order_map(output_sections, |_part_id, alignment, &size| {
        total_bytes_allocated = alignment.align_up(total_bytes_allocated) + size;
    });
    total_bytes_allocated = crate::alignment::USIZE.align_up(total_bytes_allocated);
    let mut all_mem = vec![0_u64; total_bytes_allocated as usize / core::mem::size_of::<u64>()];
    let mut all_mem: &mut [u8] = bytemuck::cast_slice_mut(all_mem.as_mut_slice());
    let mut offset = 0;
    let mut buffers = mem_sizes.output_order_map(output_sections, |_part_id, alignment, &size| {
        let aligned_offset = alignment.align_up(offset);
        crate::slice::slice_take_prefix_mut(&mut all_mem, (aligned_offset - offset) as usize);
        offset = aligned_offset + size;
        crate::slice::slice_take_prefix_mut(&mut all_mem, size as usize)
    });

    let dynsym_writer = SymbolTableWriter::new_dynamic(0, &mut buffers, output_sections);
    let debug_symbol_writer = SymbolTableWriter::new(0, &mut buffers, output_sections);
    let mut table_writer = TableWriter::new(
        output_kind,
        0..100,
        &mut buffers,
        dynsym_writer,
        debug_symbol_writer,
        0,
        0,
    );
    table_writer.process_resolution(resolution)?;
    table_writer.validate_empty(&mem_sizes)
}
