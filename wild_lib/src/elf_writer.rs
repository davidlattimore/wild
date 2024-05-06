use crate::args::Args;
use crate::args::OutputKind;
use crate::elf;
use crate::elf::slice_from_all_bytes_mut;
use crate::elf::DynamicEntry;
use crate::elf::DynamicTag;
use crate::elf::EhFrameHdr;
use crate::elf::EhFrameHdrEntry;
use crate::elf::FileHeader;
use crate::elf::GnuHashHeader;
use crate::elf::ProgramHeader;
use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
use crate::elf::SectionHeader;
use crate::elf::SegmentType;
use crate::elf::SymtabEntry;
use crate::elf::PLT_ENTRY_TEMPLATE;
use crate::error::Result;
use crate::layout::DynamicLayout;
use crate::layout::EpilogueLayout;
use crate::layout::FileLayout;
use crate::layout::HeaderInfo;
use crate::layout::InternalLayout;
use crate::layout::InternalSymbols;
use crate::layout::Layout;
use crate::layout::ObjectLayout;
use crate::layout::Resolution;
use crate::layout::ResolutionValue;
use crate::layout::Section;
use crate::layout::SymbolCopyInfo;
use crate::layout::TargetResolutionKind;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::relaxation::Relaxation;
use crate::relaxation::RelocationModifier;
use crate::resolution::SectionSlot;
use crate::resolution::ValueKind;
use crate::sharding::ShardKey;
use crate::slice::slice_take_prefix_mut;
use crate::slice::take_first_mut;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use ahash::AHashMap;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use memmap2::MmapOptions;
use object::from_bytes_mut;
use object::LittleEndian;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use object::SymbolKind;
use rayon::prelude::*;
use std::fmt::Display;
use std::ops::Range;
use std::path::Path;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Arc;

pub struct Output {
    path: Arc<Path>,
    creator: FileCreator,
}

enum FileCreator {
    Background {
        sized_output_sender: Option<Sender<Result<SizedOutput>>>,
        sized_output_recv: Receiver<Result<SizedOutput>>,
    },
    Regular {
        file_size: Option<u64>,
    },
}

struct SizedOutput {
    file: std::fs::File,
    mmap: memmap2::MmapMut,
    path: Arc<Path>,
}

#[derive(Debug)]
struct SectionAllocation {
    id: OutputSectionId,
    offset: usize,
    size: usize,
}

impl Output {
    pub fn new(args: &Args) -> Output {
        if args.num_threads.get() > 1 {
            let (sized_output_sender, sized_output_recv) = std::sync::mpsc::channel();
            Output {
                path: args.output.clone(),
                creator: FileCreator::Background {
                    sized_output_sender: Some(sized_output_sender),
                    sized_output_recv,
                },
            }
        } else {
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
            } => {
                let sender = sized_output_sender
                    .take()
                    .expect("set_size must only be called once");
                let path = self.path.clone();
                rayon::spawn(move || {
                    let _ = sender.send(SizedOutput::new(path, size));
                });
            }
            FileCreator::Regular { file_size } => *file_size = Some(size),
        }
    }

    #[tracing::instrument(skip_all, name = "Write output file")]
    pub fn write(&mut self, layout: &Layout) -> Result {
        let mut sized_output = match &self.creator {
            FileCreator::Background {
                sized_output_sender,
                sized_output_recv,
            } => {
                assert!(sized_output_sender.is_none(), "set_size was never called");
                wait_for_sized_output(sized_output_recv)?
            }
            FileCreator::Regular { file_size } => {
                let file_size = file_size.context("set_size was never called")?;
                self.create_file_non_lazily(file_size)?
            }
        };
        sized_output.write(layout)
    }

    #[tracing::instrument(skip_all, name = "Create output file")]
    fn create_file_non_lazily(&mut self, file_size: u64) -> Result<SizedOutput> {
        SizedOutput::new(self.path.clone(), file_size)
    }
}

#[tracing::instrument(skip_all, name = "Wait for output file creation")]
fn wait_for_sized_output(sized_output_recv: &Receiver<Result<SizedOutput>>) -> Result<SizedOutput> {
    sized_output_recv.recv()?
}

impl SizedOutput {
    fn new(path: Arc<Path>, file_size: u64) -> Result<SizedOutput> {
        let _ = std::fs::remove_file(&path);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .with_context(|| format!("Failed to open `{}`", path.display()))?;
        file.set_len(file_size)?;
        let mmap = unsafe { MmapOptions::new().map_mut(&file) }
            .with_context(|| format!("Failed to mmap output file `{}`", path.display()))?;
        Ok(SizedOutput { file, mmap, path })
    }

    pub(crate) fn write(&mut self, layout: &Layout) -> Result {
        self.write_file_contents(layout)?;
        if layout.args().validate_output {
            crate::validation::validate_bytes(layout, &self.mmap)?;
        }

        let mut section_buffers = split_output_into_sections(layout, &mut self.mmap);
        sort_eh_frame_hdr_entries(section_buffers.get_mut(output_section_id::EH_FRAME_HDR));
        crate::fs::make_executable(&self.file)
            .with_context(|| format!("Failed to make `{}` executable", self.path.display()))?;
        Ok(())
    }

    #[tracing::instrument(skip_all, name = "Write data to file")]
    pub(crate) fn write_file_contents(&mut self, layout: &Layout) -> Result {
        let mut section_buffers = split_output_into_sections(layout, &mut self.mmap);

        let mut writable_buckets = split_buffers_by_alignment(&mut section_buffers, layout);
        let files_and_buffers = split_output_by_file(layout, &mut writable_buckets);
        files_and_buffers
            .into_par_iter()
            .try_for_each(|(file, buffer)| {
                file.write(buffer, layout)
                    .with_context(|| format!("Failed copying from {file} to output file"))
            })?;
        Ok(())
    }
}

#[tracing::instrument(skip_all, name = "Split output buffers by file")]
fn split_output_by_file<'data, 'out>(
    layout: &'data Layout<'data>,
    writable_buckets: &'out mut OutputSectionPartMap<&mut [u8]>,
) -> Vec<(
    &'data FileLayout<'data>,
    OutputSectionPartMap<&'out mut [u8]>,
)> {
    layout
        .file_layouts
        .iter()
        .filter_map(|file| {
            file.file_sizes()
                .map(|file_sizes| (file, writable_buckets.take_mut(file_sizes)))
        })
        .collect()
}

fn split_output_into_sections<'out>(
    layout: &Layout<'_>,
    mmap: &'out mut memmap2::MmapMut,
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

    let mut data = mmap.as_mut();
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
    layout
        .section_part_layouts
        .output_order_map(&layout.output_sections, |section_id, _, rec| {
            crate::slice::slice_take_prefix_mut(section_buffers.get_mut(section_id), rec.file_size)
        })
}

fn write_program_headers(program_headers_out: &mut ProgramHeaderWriter, layout: &Layout) -> Result {
    for segment_layout in layout.segment_layouts.segments.iter() {
        let segment_sizes = &segment_layout.sizes;
        let segment_id = segment_layout.id;
        let segment_header = program_headers_out.take_header()?;
        let mut alignment = segment_sizes.alignment;
        if segment_id.segment_type() == SegmentType::Load {
            alignment = alignment.max(crate::alignment::PAGE);
        }
        let e = LittleEndian;
        segment_header
            .p_type
            .set(e, segment_id.segment_type() as u32);
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
    let ty = match args.output_kind {
        OutputKind::NonRelocatableStaticExecutable => elf::FileType::Executable,
        _ => elf::FileType::SharedObject,
    };
    let e = LittleEndian;
    header.e_ident.magic = object::elf::ELFMAG;
    header.e_ident.class = 2; // 64 bit
    header.e_ident.data = 1; // Little endian
    header.e_ident.version = 1;
    header.e_ident.os_abi = 0;
    header.e_ident.abi_version = 0;
    header.e_ident.padding = Default::default();
    header.e_type.set(e, ty as u16);
    header.e_machine.set(e, 0x3e); // x86-64
    header.e_version.set(e, 1);
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
            .output_index_of_section(crate::output_section_id::SHSTRTAB)
            .expect("we always write .shstrtab"),
    );
    Ok(())
}

impl<'data> FileLayout<'data> {
    fn write(&self, buffers: OutputSectionPartMap<&mut [u8]>, layout: &Layout) -> Result {
        match self {
            FileLayout::Object(s) => s.write(buffers, layout)?,
            FileLayout::Internal(s) => s.write(buffers, layout)?,
            FileLayout::Epilogue(s) => s.write(buffers, layout)?,
            FileLayout::NotLoaded => {}
            FileLayout::Dynamic(s) => s.write(buffers, layout)?,
        }
        Ok(())
    }
}

struct PltGotWriter<'data, 'out> {
    layout: &'data Layout<'data>,
    got: &'out mut [u64],
    plt: &'out mut [u8],
    rela_plt: &'out mut [elf::Rela],
    tls: Range<u64>,
}

impl<'data, 'out> PltGotWriter<'data, 'out> {
    fn new(
        layout: &'data Layout,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
    ) -> PltGotWriter<'data, 'out> {
        PltGotWriter {
            layout,
            got: bytemuck::cast_slice_mut(core::mem::take(&mut buffers.got)),
            plt: core::mem::take(&mut buffers.plt),
            rela_plt: slice_from_all_bytes_mut(core::mem::take(&mut buffers.rela_plt)),
            tls: layout.tls_start_address()..layout.tls_end_address(),
        }
    }

    fn process_symbol(
        &mut self,
        symbol_id: SymbolId,
        relocation_writer: &mut DynamicRelocationWriter,
    ) -> Result {
        if let Some(res) = self.layout.symbol_resolution(symbol_id) {
            self.process_resolution(res, relocation_writer)?;
        }
        Ok(())
    }

    fn process_resolution(
        &mut self,
        res: &Resolution,
        relocation_writer: &mut DynamicRelocationWriter,
    ) -> Result {
        if let Some(got_address) = res.got_address {
            let res_value = match res.kind {
                TargetResolutionKind::GotTlsDouble => {
                    let mod_got_entry = slice_take_prefix_mut(&mut self.got, 1);
                    mod_got_entry.copy_from_slice(&[elf::CURRENT_EXE_TLS_MOD]);
                    let offset_entry = slice_take_prefix_mut(&mut self.got, 1);
                    // Convert the address to an offset relative to the TCB which is the end of the TLS
                    // segment.
                    match res.value {
                        ResolutionValue::Address(address) => {
                            offset_entry[0] = address.wrapping_sub(self.tls.end);
                        }
                        other => bail!("Unexpected resolution value {other:?}"),
                    }
                    return Ok(());
                }
                TargetResolutionKind::GotTlsOffset => {
                    // Convert the address to an offset relative to the TCB which is the end of the TLS
                    // segment.
                    match res.value {
                        ResolutionValue::Address(address) => {
                            if !self.tls.contains(&address) {
                                bail!(
                                    "GotTlsOffset resolves to address not in TLS segment 0x{:x}",
                                    address
                                );
                            }
                            ResolutionValue::Absolute(address.wrapping_sub(self.tls.end))
                        }
                        other => bail!("Unexpected resolution value {other:?}"),
                    }
                }
                TargetResolutionKind::IFunc => ResolutionValue::Absolute(0),
                TargetResolutionKind::Value => res.value,
                _ => res.value,
            };
            let got_entry = self.take_next_got_entry()?;
            relocation_writer.write_relocation(got_address.get(), res_value, 0)?;
            match res_value {
                ResolutionValue::Absolute(v) => *got_entry = v,
                ResolutionValue::Address(v) => *got_entry = v,
                ResolutionValue::Iplt(_) => {}
                ResolutionValue::Dynamic(_) => {}
            }
            if let Some(plt_address) = res.plt_address {
                self.write_plt_entry(got_address.get(), plt_address.get())?;
            }
        }
        Ok(())
    }

    fn write_plt_entry(&mut self, got_address: u64, plt_address: u64) -> Result {
        if self.plt.len() < elf::PLT_ENTRY_SIZE as usize {
            bail!("Didn't allocate enough space in PLT");
        }
        let plt_entry = slice_take_prefix_mut(&mut self.plt, elf::PLT_ENTRY_SIZE as usize);
        plt_entry.copy_from_slice(PLT_ENTRY_TEMPLATE);
        let offset: i32 = ((got_address.wrapping_sub(plt_address + 0xb)) as i64)
            .try_into()
            .map_err(|_| anyhow!("PLT is more than 2GB away from GOT"))?;
        plt_entry[7..11].copy_from_slice(&offset.to_le_bytes());
        Ok(())
    }

    fn take_next_got_entry(&mut self) -> Result<&mut u64> {
        crate::slice::take_first_mut(&mut self.got).context("Insufficient GOT allocation")
    }

    /// Checks that we used all of the GOT/PLT entries that we requested during layout.
    fn validate_empty(&self) -> Result {
        if !self.got.is_empty() || !self.plt.is_empty() {
            bail!(
                "Unused PLT/GOT entries remain: GOT={}, PLT={}",
                self.got.len() as u64 / elf::GOT_ENTRY_SIZE,
                self.plt.len() as u64 / elf::PLT_ENTRY_SIZE
            );
        }
        Ok(())
    }

    fn write_ifunc_relocation(
        &mut self,
        rel: &crate::layout::IfuncRelocation,
        relocation_writer: &mut DynamicRelocationWriter,
    ) -> Result {
        let out = slice_take_prefix_mut(&mut self.rela_plt, 1);
        let out = &mut out[0];
        let e = LittleEndian;
        if relocation_writer.is_active {
            relocation_writer.write_relocation(
                rel.relocation_address + elf::RELA_ADDEND_OFFSET as u64,
                ResolutionValue::Address(rel.resolver),
                0,
            )?;
            relocation_writer.write_relocation(
                rel.relocation_address + elf::RELA_ADDRESS_OFFSET as u64,
                ResolutionValue::Address(rel.got_address),
                0,
            )?;
        } else {
            out.r_addend.set(e, rel.resolver as i64);
            out.r_offset.set(e, rel.got_address);
        }
        out.r_info
            .set(e, elf::RelocationType::IRelative as u32 as u64);
        Ok(())
    }
}

struct SymbolTableWriter<'data, 'out> {
    string_offset: u32,
    local_entries: &'out mut [SymtabEntry],
    global_entries: &'out mut [SymtabEntry],
    strings: &'out mut [u8],
    output_sections: &'data OutputSections<'data>,
}

impl<'data, 'out> SymbolTableWriter<'data, 'out> {
    fn new(
        start_string_offset: u32,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
        sizes: &OutputSectionPartMap<u64>,
        output_sections: &'data OutputSections<'data>,
    ) -> Self {
        let local_entries = slice_from_all_bytes_mut(core::mem::take(&mut buffers.symtab_locals));
        let global_entries = slice_from_all_bytes_mut(core::mem::take(&mut buffers.symtab_globals));
        let strings = bytemuck::cast_slice_mut(slice_take_prefix_mut(
            &mut buffers.symtab_strings,
            sizes.symtab_strings as usize,
        ));
        Self {
            string_offset: start_string_offset,
            local_entries,
            global_entries,
            strings,
            output_sections,
        }
    }

    fn new_dynamic(
        string_offset: u32,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
        output_sections: &'data OutputSections<'data>,
    ) -> Self {
        let global_entries = slice_from_all_bytes_mut(core::mem::take(&mut buffers.dynsym));
        let strings = slice_from_all_bytes_mut(core::mem::take(&mut buffers.dynstr));
        Self {
            string_offset,
            local_entries: Default::default(),
            global_entries,
            strings,
            output_sections,
        }
    }

    fn copy_symbol(
        &mut self,
        sym: &crate::elf::Symbol,
        name: &[u8],
        output_section_id: OutputSectionId,
        value: u64,
    ) -> Result {
        let is_local = sym.is_local();
        let object::SymbolFlags::Elf { st_info, st_other } = sym.flags() else {
            unreachable!()
        };
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
        let size = sym.size();
        let entry = self.define_symbol(is_local, shndx, value, size, name)?;
        entry.st_info = st_info;
        entry.st_other = st_other;
        Ok(())
    }

    fn copy_absolute_symbol(&mut self, sym: &crate::elf::Symbol, name: &[u8]) -> Result {
        let is_local = sym.is_local();
        let object::SymbolFlags::Elf { st_info, st_other } = sym.flags() else {
            unreachable!()
        };
        let value = sym.address();
        let size = sym.size();
        let entry = self.define_symbol(is_local, object::elf::SHN_ABS, value, size, name)?;
        entry.st_info = st_info;
        entry.st_other = st_other;
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
                    "Insufficient local symbol entries allocated for symbol `{}`",
                    String::from_utf8_lossy(name),
                )
            })?
        } else {
            take_first_mut(&mut self.global_entries).with_context(|| {
                format!(
                    "Insufficient global symbol entries allocated for symbol `{}`",
                    String::from_utf8_lossy(name),
                )
            })?
        };
        let e = LittleEndian;
        entry.st_name.set(e, self.string_offset);
        entry.st_info = 0;
        entry.st_other = 0;
        entry.st_shndx.set(e, shndx);
        entry.st_value.set(e, value);
        entry.st_size.set(e, size);
        let len = name.len();
        let str_out = slice_take_prefix_mut(&mut self.strings, len + 1);
        str_out[..len].copy_from_slice(name);
        str_out[len] = 0;
        self.string_offset += len as u32 + 1;
        Ok(entry)
    }

    /// Verifies that we've used up all the space allocated to this writer. i.e. checks that we
    /// didn't allocate too much or missed writing something that we were supposed to write.
    fn check_exhausted(&self) -> Result {
        if !self.local_entries.is_empty()
            || !self.global_entries.is_empty()
            || !self.strings.is_empty()
        {
            bail!(
                "Didn't use up all allocated symtab/strtab space. local={} global={} strings={}",
                self.local_entries.len(),
                self.global_entries.len(),
                self.strings.len()
            );
        }
        Ok(())
    }
}

impl<'data> ObjectLayout<'data> {
    fn write(&self, mut buffers: OutputSectionPartMap<&mut [u8]>, layout: &Layout) -> Result {
        let start_str_offset = self.strtab_offset_start;
        let mut plt_got_writer = PltGotWriter::new(layout, &mut buffers);
        let mut relocation_writer =
            DynamicRelocationWriter::new(layout.args().is_relocatable(), &mut buffers);
        for sec in &self.sections {
            match sec {
                SectionSlot::Loaded(sec) => self.write_section(
                    layout,
                    sec,
                    &mut buffers,
                    &mut plt_got_writer,
                    &mut relocation_writer,
                )?,
                SectionSlot::EhFrameData(section_index) => {
                    self.write_eh_frame_data(
                        *section_index,
                        &mut buffers,
                        layout,
                        &mut relocation_writer,
                    )?;
                }
                _ => (),
            }
        }
        for rel in &self.plt_relocations {
            plt_got_writer.write_ifunc_relocation(rel, &mut relocation_writer)?;
        }
        for (symbol_id, resolution) in
            layout.resolutions_in_range(self.start_symbol_id, self.num_symbols)
        {
            if let Some(res) = resolution {
                plt_got_writer
                    .process_resolution(res, &mut relocation_writer)
                    .with_context(|| {
                        format!("Failed to process `{}`", layout.symbol_debug(symbol_id))
                    })?;
            }
        }
        if !layout.args().strip_all {
            self.write_symbols(start_str_offset, buffers, &layout.output_sections, layout)?;
        }
        plt_got_writer.validate_empty()?;
        relocation_writer.validate_empty(&self.mem_sizes)?;
        Ok(())
    }

    fn write_section(
        &self,
        layout: &Layout<'_>,
        sec: &Section<'_>,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
        plt_got_writer: &mut PltGotWriter<'_, '_>,
        relocation_writer: &mut DynamicRelocationWriter,
    ) -> Result {
        if layout
            .output_sections
            .has_data_in_file(sec.output_section_id.unwrap())
        {
            let section_buffer = buffers.regular_mut(sec.output_section_id.unwrap(), sec.alignment);
            let allocation_size = sec.capacity() as usize;
            if section_buffer.len() < allocation_size {
                bail!(
                    "Insufficient space allocated to section {}. Tried to take {} bytes, but only {} remain",
                    self.display_section_name(sec.index),
                    allocation_size, section_buffer.len()
                );
            }
            let out = slice_take_prefix_mut(section_buffer, allocation_size);
            // Cut off any padding so that our output buffer is the size of our input buffer.
            let out = &mut out[..sec.data.len()];
            out.copy_from_slice(sec.data);
            self.apply_relocations(out, sec, layout, relocation_writer)
                .with_context(|| {
                    format!(
                        "Failed to apply relocations in section {} of {}",
                        self.display_section_name(sec.index),
                        self.input
                    )
                })?;
        }
        if sec.resolution_kind.needs_got_entry() {
            let res = self.section_resolutions[sec.index.0]
                .as_ref()
                .ok_or_else(|| anyhow!("Section requires GOT, but hasn't been resolved"))?;
            plt_got_writer.process_resolution(res, relocation_writer)?;
        };
        Ok(())
    }

    fn write_symbols(
        &self,
        start_str_offset: u32,
        mut buffers: OutputSectionPartMap<&mut [u8]>,
        sections: &OutputSections,
        layout: &Layout,
    ) -> Result {
        let mut symbol_writer =
            SymbolTableWriter::new(start_str_offset, &mut buffers, &self.mem_sizes, sections);
        for (sym, sym_state) in self.object.symbols().zip(&self.symbol_states) {
            let symbol_id = self.start_symbol_id.add_usize(sym.index().0);
            if let Some(info) = SymbolCopyInfo::new(
                &sym,
                symbol_id,
                layout.symbol_db,
                *sym_state,
                &self.sections,
            ) {
                let output_section_id = match object::ObjectSymbol::section(&sym) {
                    object::SymbolSection::Section(section_index) => {
                        match &self.sections[section_index.0] {
                            SectionSlot::Loaded(section) => section.output_section_id.unwrap(),
                            SectionSlot::MergeStrings(_) => {
                                let merged_string_res = &self.merged_string_resolutions[sym.index().0].context(
                                    "Tried to write symbol for merged string without a resolution",
                                )?;
                                merged_string_res.output_section_id
                            }
                            SectionSlot::EhFrameData(..) => output_section_id::EH_FRAME,
                            _ => bail!("Tried to copy a symbol in a section we didn't load"),
                        }
                    }
                    object::SymbolSection::Common => output_section_id::BSS,
                    object::SymbolSection::Absolute | object::SymbolSection::None => {
                        symbol_writer
                            .copy_absolute_symbol(&sym, info.name)
                            .with_context(|| {
                                format!(
                                    "Failed to absolute {}",
                                    layout.symbol_db.symbol_debug(symbol_id)
                                )
                            })?;
                        continue;
                    }
                    _ => {
                        bail!("Attempted to output a symtab entry with an unexpected section type")
                    }
                };
                let Some(res) = layout.symbol_resolution(symbol_id) else {
                    bail!("Missing resolution for {}", layout.symbol_debug(symbol_id));
                };
                let mut symbol_value = res.value.address_or_value()?;
                if sym.kind() == SymbolKind::Tls {
                    let tls_start_address = layout.segment_layouts.tls_start_address.context(
                        "Writing TLS variable to symtab, but we don't have a TLS segment",
                    )?;
                    symbol_value -= tls_start_address;
                }
                symbol_writer
                    .copy_symbol(&sym, info.name, output_section_id, symbol_value)
                    .with_context(|| {
                        format!(
                            "Failed to copy {}",
                            layout.symbol_debug(self.start_symbol_id.add_usize(sym.index().0))
                        )
                    })?;
            }
        }
        symbol_writer.check_exhausted()?;
        Ok(())
    }

    fn apply_relocations(
        &self,
        out: &mut [u8],
        section: &Section,
        layout: &Layout,
        relocation_writer: &mut DynamicRelocationWriter,
    ) -> Result {
        let section_address = self.section_resolutions[section.index.0]
            .as_ref()
            .unwrap()
            .value
            .address_or_value()?;
        let elf_section = &self.object.section_by_index(section.index)?;
        let mut modifier = RelocationModifier::Normal;
        for (offset_in_section, rel) in elf_section.relocations() {
            if modifier == RelocationModifier::SkipNextRelocation {
                modifier = RelocationModifier::Normal;
                continue;
            }
            modifier = apply_relocation(
                self,
                offset_in_section,
                &rel,
                section_address,
                layout,
                out,
                relocation_writer,
            )
            .with_context(|| {
                format!(
                    "Failed to apply {} at offset 0x{offset_in_section:x}",
                    self.display_relocation(&rel, layout)
                )
            })?;
        }
        Ok(())
    }

    fn write_eh_frame_data(
        &self,
        eh_frame_section_index: object::SectionIndex,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
        layout: &Layout,
        relocation_writer: &mut DynamicRelocationWriter,
    ) -> Result {
        let output_data = &mut buffers.eh_frame[..];
        let headers_out: &mut [EhFrameHdrEntry] =
            bytemuck::cast_slice_mut(&mut buffers.eh_frame_hdr[..]);
        let mut header_offset = 0;
        let eh_frame_section = self.object.section_by_index(eh_frame_section_index)?;
        let data = eh_frame_section.data()?;
        const PREFIX_LEN: usize = core::mem::size_of::<elf::EhFrameEntryPrefix>();
        let mut relocations = eh_frame_section.relocations().peekable();
        let mut input_pos = 0;
        let mut output_pos = 0;
        let frame_info_ptr_base = self.eh_frame_start_address;
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
                if let Some((rel_offset, rel)) = relocations.peek() {
                    if *rel_offset < next_input_pos as u64 {
                        let is_pc_begin =
                            (*rel_offset as usize - input_pos) == elf::FDE_PC_BEGIN_OFFSET;

                        if is_pc_begin {
                            let section_index;
                            let offset_in_section;
                            match rel.target() {
                                object::RelocationTarget::Symbol(index) => {
                                    let elf_symbol = &self.object.symbol_by_index(index)?;
                                    if let Some(index) = elf_symbol.section_index() {
                                        section_index = index;
                                        offset_in_section = elf_symbol.address();
                                    } else {
                                        bail!(".eh_frame pc-begin refers to symbol that's not defined in file");
                                    }
                                }
                                object::RelocationTarget::Section(index) => {
                                    section_index = index;
                                    offset_in_section = 0;
                                }
                                _ => bail!("Unexpected relocation type in .eh_frame pc-begin"),
                            };
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
                                let frame_ptr = (section_resolution.value.address()?
                                    + offset_in_section)
                                    as i64
                                    - eh_frame_hdr_address as i64;
                                headers_out[header_offset] = EhFrameHdrEntry {
                                    frame_ptr: i32::try_from(frame_ptr)
                                        .context("32 bit overflow in frame_ptr")?,
                                    frame_info_ptr: i32::try_from(
                                        frame_info_ptr_base + output_pos as u64,
                                    )
                                    .context("32 bit overflow when computing frame_info_ptr")?,
                                };
                                header_offset += 1;
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
                if next_output_pos > output_data.len() {
                    bail!("Insufficient allocation to .eh_frame section. Allocated 0x{:x}, but tried to write up to 0x{:x}",
                        self.mem_sizes.eh_frame, next_output_pos);
                }
                let entry_out = &mut output_data[output_pos..next_output_pos];
                entry_out.copy_from_slice(&data[input_pos..next_input_pos]);
                if let Some(output_cie_offset) = output_cie_offset {
                    entry_out[4..8].copy_from_slice(&output_cie_offset.to_le_bytes());
                }
                while let Some((rel_offset, rel)) = relocations.peek() {
                    if *rel_offset >= next_input_pos as u64 {
                        // This relocation belongs to the next entry.
                        break;
                    }
                    apply_relocation(
                        self,
                        rel_offset - input_pos as u64,
                        rel,
                        output_pos as u64 + self.eh_frame_start_address,
                        layout,
                        entry_out,
                        relocation_writer,
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
                while let Some((rel_offset, _rel)) = relocations.peek() {
                    if *rel_offset < next_input_pos as u64 {
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
            output_data[output_pos..output_pos + remaining]
                .copy_from_slice(&data[input_pos..input_pos + remaining]);
        }

        Ok(())
    }

    fn display_relocation<'a>(
        &'a self,
        rel: &'a object::Relocation,
        layout: &'a Layout,
    ) -> DisplayRelocation<'a> {
        DisplayRelocation {
            rel,
            symbol_db: layout.symbol_db,
            object: self,
        }
    }

    fn get_resolution<'a>(
        &'a self,
        rel: &object::Relocation,
        layout: &'a Layout,
    ) -> Result<Option<Resolution>> {
        let mut new_resolution = None;
        match rel.target() {
            object::RelocationTarget::Symbol(symbol_index) => {
                let local_symbol_id = self.start_symbol_id.add_usize(symbol_index.0);
                let symbol_id = layout.symbol_db.definition(local_symbol_id);
                let file_id = layout.symbol_db.file_id_for_symbol(symbol_id);
                if symbol_id == SymbolId::undefined() || !layout.is_file_loaded(file_id) {
                    let local_symbol = &self.object.symbol_by_index(symbol_index)?;
                    if !local_symbol.is_weak() {
                        bail!(
                            "Undefined strong reference to `{}`",
                            String::from_utf8_lossy(local_symbol.name_bytes()?)
                        );
                    }
                    // TODO: Check if reference is weak.
                    new_resolution = Some(layout.internal().undefined_symbol_resolution);
                } else if let Some(res) = layout.symbol_resolution(symbol_id) {
                    new_resolution = Some(*res);
                }
            }
            object::RelocationTarget::Section(_local_index) => {
                bail!("Don't currently support relocations directly to sections");
                // self.section_resolutions[local_index.0].unwrap()
            }
            other => bail!("Unsupported relocation {other:?}"),
        };
        Ok(new_resolution)
    }

    fn display_section_name(&self, section_index: object::SectionIndex) -> String {
        if let Ok(section) = self.object.section_by_index(section_index) {
            if let Ok(name) = section.name() {
                return format!("`{name}`");
            }
        }
        "(failed to get section name)".to_owned()
    }
}

struct DisplayRelocation<'a> {
    rel: &'a object::Relocation,
    symbol_db: &'a SymbolDb<'a>,
    object: &'a ObjectLayout<'a>,
}

impl<'a> Display for DisplayRelocation<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "relocation of type ")?;
        match self.rel.kind() {
            object::RelocationKind::Unknown => write!(f, "{:?}", self.rel.flags())?,
            kind => write!(f, "{kind:?}")?,
        }
        write!(f, " to ")?;
        match self.rel.target() {
            object::RelocationTarget::Symbol(local_symbol_index) => {
                let symbol_id = self.object.start_symbol_id.add_usize(local_symbol_index.0);
                write!(f, " {}", self.symbol_db.symbol_debug(symbol_id))?;
            }
            object::RelocationTarget::Section(section_index) => write!(
                f,
                "section `{}`",
                self.object
                    .object
                    .section_by_index(section_index)
                    .and_then(|s| s.name())
                    .unwrap_or("??")
            )?,
            object::RelocationTarget::Absolute => write!(f, "absolute")?,
            _ => write!(f, "unknown")?,
        }
        Ok(())
    }
}

struct DynamicRelocationWriter<'out> {
    /// Whether we're writing relocations. This will be false if we're writing a non-relocatable
    /// output file.
    is_active: bool,
    rela_dyn_relative: &'out mut [crate::elf::Rela],
    rela_dyn_glob_dat: &'out mut [crate::elf::Rela],
}

impl<'out> DynamicRelocationWriter<'out> {
    fn new(is_active: bool, buffers: &mut OutputSectionPartMap<&'out mut [u8]>) -> Self {
        Self {
            is_active,
            rela_dyn_relative: slice_from_all_bytes_mut(core::mem::take(
                &mut buffers.rela_dyn_relative,
            )),
            rela_dyn_glob_dat: slice_from_all_bytes_mut(core::mem::take(
                &mut buffers.rela_dyn_glob_dat,
            )),
        }
    }

    fn write_relocation(&mut self, place: u64, res_value: ResolutionValue, addend: u64) -> Result {
        if !self.is_active {
            return Ok(());
        }
        let e = LittleEndian;
        match res_value {
            ResolutionValue::Absolute(_) | ResolutionValue::Iplt(_) => {}
            ResolutionValue::Address(address) => {
                let rela = crate::slice::take_first_mut(&mut self.rela_dyn_relative)
                    .context("insufficient allocation to .rela.dyn (relative)")?;
                rela.r_offset.set(e, place);
                rela.r_addend.set(e, address.wrapping_add(addend) as i64);
                rela.r_info.set(e, object::elf::R_X86_64_RELATIVE.into());
            }
            ResolutionValue::Dynamic(symbol_index) => {
                let rela = crate::slice::take_first_mut(&mut self.rela_dyn_glob_dat)
                    .context("insufficient allocation to .rela.dyn (glob-dat)")?;
                rela.r_offset.set(e, place);
                rela.r_addend.set(e, addend as i64);
                // We could plausibly use R_X86_64_JUMP_SLOT here in cases where we have only PLT
                // references to a symbol and no GOT references. If we did that, we'd need to put
                // the relocation in .rela.plt not .rela.dyn. Right now, we don't track whether a
                // symbol has only PLT references and no GOT references. Also, we currently set the
                // BIND_NOW flag, which means all the PLT relocations would be eagerly bound, making
                // use of JUMP_SLOT relocations pointless.
                rela.r_info.set(
                    e,
                    u64::from(symbol_index) << 32 | u64::from(object::elf::R_X86_64_GLOB_DAT),
                );
            }
        }
        Ok(())
    }

    fn disabled() -> Self {
        Self {
            is_active: false,
            rela_dyn_relative: Default::default(),
            rela_dyn_glob_dat: Default::default(),
        }
    }

    fn validate_empty(&self, mem_sizes: &OutputSectionPartMap<u64>) -> Result {
        if !self.rela_dyn_relative.is_empty() {
            bail!(
                "Allocated too much relative space in .rela.dyn. {} of {} entries remain unused.",
                self.rela_dyn_relative.len(),
                mem_sizes.rela_dyn_relative / elf::RELA_ENTRY_SIZE,
            );
        }
        if !self.rela_dyn_glob_dat.is_empty() {
            bail!(
                "Allocated too much glob-dat space in .rela.dyn. {} of {} entries remain unused.",
                self.rela_dyn_glob_dat.len(),
                mem_sizes.rela_dyn_glob_dat / elf::RELA_ENTRY_SIZE,
            );
        }
        Ok(())
    }
}

/// Applies the relocation `rel` at `offset_in_section`, where the section bytes are `out`. See "ELF
/// Handling For Thread-Local Storage" for details about some of the TLS-related relocations and
/// transformations that are applied.
fn apply_relocation(
    object_layout: &ObjectLayout,
    mut offset_in_section: u64,
    rel: &object::Relocation,
    section_address: u64,
    layout: &Layout,
    out: &mut [u8],
    relocation_writer: &mut DynamicRelocationWriter,
) -> Result<RelocationModifier> {
    let Some(resolution) = object_layout.get_resolution(rel, layout)? else {
        return Ok(RelocationModifier::Normal);
    };
    let (value, value_kind) = match resolution.value {
        ResolutionValue::Absolute(v) => (v, ValueKind::Absolute),
        ResolutionValue::Address(v) => (v, ValueKind::Address),
        ResolutionValue::Dynamic(_) => (0, ValueKind::Dynamic),
        ResolutionValue::Iplt(v) => (v, ValueKind::IFunc),
    };
    let place = section_address + offset_in_section;
    let mut addend = rel.addend() as u64;
    let mut next_modifier = RelocationModifier::Normal;
    let object::RelocationFlags::Elf { r_type } = rel.flags() else {
        unreachable!();
    };
    let rel_info;
    if let Some((relaxation, r_type)) = Relaxation::new(
        r_type,
        out,
        offset_in_section,
        value_kind,
        layout.args().output_kind,
    ) {
        rel_info = RelocationKindInfo::from_raw(r_type)?;
        relaxation.apply(out, &mut offset_in_section, &mut addend, &mut next_modifier);
    } else {
        rel_info = RelocationKindInfo::from_raw(r_type)?;
    }
    debug_assert!(rel.size() == 0 || rel.size() as usize / 8 == rel_info.byte_size);
    let value = match rel_info.kind {
        RelocationKind::Absolute => {
            if relocation_writer.is_active && !resolution.value.is_absolute() {
                relocation_writer.write_relocation(place, resolution.value, addend)?;
                0
            } else {
                value.wrapping_add(addend)
            }
        }
        RelocationKind::Relative => value.wrapping_add(addend).wrapping_sub(place),
        RelocationKind::GotRelative => resolution
            .got_address()?
            .wrapping_add(addend)
            .wrapping_sub(place),
        RelocationKind::PltRelative => resolution
            .plt_address()?
            .wrapping_add(addend)
            .wrapping_sub(place),
        RelocationKind::TlsGd => resolution
            .got_address()?
            .wrapping_add(addend)
            .wrapping_sub(place),
        RelocationKind::TlsLd => layout
            .internal()
            .tlsld_got_entry
            .unwrap()
            .get()
            .wrapping_add(addend)
            .wrapping_sub(place),
        RelocationKind::DtpOff => value
            .wrapping_sub(layout.tls_end_address())
            .wrapping_add(addend),
        RelocationKind::GotTpOff => resolution
            .got_address()?
            .wrapping_add(addend)
            .wrapping_sub(place),
        RelocationKind::TpOff => value.wrapping_sub(layout.tls_end_address()),
        RelocationKind::None => 0,
        other => bail!("Unsupported relocation kind {other:?}"),
    };
    let value_bytes = value.to_le_bytes();
    let end = offset_in_section as usize + rel_info.byte_size;
    if out.len() < end {
        bail!("Relocation outside of bounds of section");
    }
    out[offset_in_section as usize..end].copy_from_slice(&value_bytes[..rel_info.byte_size]);
    Ok(next_modifier)
}

impl<'data> InternalLayout<'data> {
    fn write(&self, mut buffers: OutputSectionPartMap<&mut [u8]>, layout: &Layout) -> Result {
        let header: &mut FileHeader = from_bytes_mut(buffers.file_header)
            .map_err(|_| anyhow!("Invalid file header allocation"))?
            .0;
        populate_file_header(layout, &self.header_info, header)?;

        let mut program_headers = ProgramHeaderWriter::new(buffers.program_headers);
        write_program_headers(&mut program_headers, layout)?;

        write_section_headers(buffers.section_headers, layout);

        write_section_header_strings(buffers.shstrtab, &layout.output_sections);

        let mut relocation_writer =
            DynamicRelocationWriter::new(layout.args().is_relocatable(), &mut buffers);

        self.write_plt_got_entries(&mut buffers, layout, &mut relocation_writer)?;

        if !layout.args().strip_all {
            self.write_symbol_table_entries(&mut buffers, layout)?;
        }

        write_eh_frame_hdr(&mut buffers, layout)?;

        self.write_merged_strings(&mut buffers);

        self.write_interp(&mut buffers);

        relocation_writer.validate_empty(&self.mem_sizes)?;

        Ok(())
    }

    fn write_interp(&self, buffers: &mut OutputSectionPartMap<&mut [u8]>) {
        if let Some(dynamic_linker) = self.dynamic_linker.as_ref() {
            buffers
                .interp
                .copy_from_slice(dynamic_linker.as_bytes_with_nul());
        }
    }

    fn write_merged_strings(&self, buffers: &mut OutputSectionPartMap<&mut [u8]>) {
        self.merged_strings.for_each(|section_id, merged| {
            if merged.len > 0 {
                let buffer = buffers.regular_mut(section_id, crate::alignment::MIN);
                for string in &merged.strings {
                    let dest = crate::slice::slice_take_prefix_mut(buffer, string.len());
                    dest.copy_from_slice(string)
                }
            }
        });

        // Write linker identity into .comment section.
        let comment_buffer = buffers.regular_mut(output_section_id::COMMENT, crate::alignment::MIN);
        crate::slice::slice_take_prefix_mut(comment_buffer, self.identity.len())
            .copy_from_slice(self.identity.as_bytes());
    }

    fn write_plt_got_entries(
        &self,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
        layout: &Layout,
        relocation_writer: &mut DynamicRelocationWriter,
    ) -> Result {
        let mut plt_got_writer = PltGotWriter::new(layout, buffers);

        // Our PLT entry for an undefined symbol doesn't really exist, so don't try to write an
        // actual PLT entry for it.
        let undefined_symbol_resolution = Resolution {
            plt_address: None,
            ..self.undefined_symbol_resolution
        };
        plt_got_writer
            .process_resolution(
                &undefined_symbol_resolution,
                &mut DynamicRelocationWriter::disabled(),
            )
            .context("undefined symbol resolution")?;

        // Write a pair of GOT entries for use by any TLSLD or TLSGD relocations.
        if let Some(got_address) = self.tlsld_got_entry {
            plt_got_writer.process_resolution(
                &Resolution {
                    value: ResolutionValue::Absolute(1),
                    got_address: Some(got_address),
                    plt_address: None,
                    kind: TargetResolutionKind::Got,
                },
                &mut DynamicRelocationWriter::disabled(),
            )?;
            plt_got_writer.process_resolution(
                &Resolution {
                    value: ResolutionValue::Absolute(0),
                    got_address: Some(got_address.saturating_add(elf::GOT_ENTRY_SIZE)),
                    plt_address: None,
                    kind: TargetResolutionKind::Got,
                },
                &mut DynamicRelocationWriter::disabled(),
            )?;
        }

        write_internal_symbols_plt_got_entries(
            &self.internal_symbols,
            &mut plt_got_writer,
            relocation_writer,
            layout,
        )?;
        plt_got_writer.validate_empty()?;
        Ok(())
    }

    fn write_symbol_table_entries(
        &self,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
        layout: &Layout,
    ) -> Result {
        let mut symbol_writer = SymbolTableWriter::new(
            self.strings_offset_start,
            buffers,
            &self.mem_sizes,
            &layout.output_sections,
        );

        // Define symbol 0. This needs to be a null placeholder.
        symbol_writer.define_symbol(true, 0, 0, 0, &[])?;

        let internal_symbols = &self.internal_symbols;

        write_internal_symbols(internal_symbols, layout, &mut symbol_writer)?;
        symbol_writer.check_exhausted()?;
        Ok(())
    }
}

fn write_epilogue_dynamic_entries(out: &mut [u8], layout: &Layout) -> Result {
    let mut out = DynamicEntriesWriter::new(out);
    for writer in EPILOGUE_DYNAMIC_ENTRY_WRITERS {
        writer.write(&mut out, layout)?;
    }

    Ok(())
}

impl<'data> EpilogueLayout<'data> {
    fn write(&self, mut buffers: OutputSectionPartMap<&mut [u8]>, layout: &Layout) -> Result {
        let mut relocation_writer =
            DynamicRelocationWriter::new(layout.args().is_relocatable(), &mut buffers);

        let mut plt_got_writer = PltGotWriter::new(layout, &mut buffers);
        write_internal_symbols_plt_got_entries(
            &self.internal_symbols,
            &mut plt_got_writer,
            &mut relocation_writer,
            layout,
        )?;
        plt_got_writer.validate_empty()?;

        if !layout.args().strip_all {
            let mut symbol_writer = SymbolTableWriter::new(
                self.strings_offset_start,
                &mut buffers,
                &self.mem_sizes,
                &layout.output_sections,
            );
            write_internal_symbols(&self.internal_symbols, layout, &mut symbol_writer)?;
        }
        if layout.args().needs_dynamic() {
            write_epilogue_dynamic_entries(buffers.dynamic, layout)?;
        }
        write_dynamic_symbol_definitions(self, &mut buffers, layout)?;

        Ok(())
    }
}

fn write_dynamic_symbol_definitions(
    epilogue: &EpilogueLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &Layout,
) -> Result {
    let mut dynamic_symbol_writer = SymbolTableWriter::new_dynamic(
        epilogue.dynstr_offset_start,
        buffers,
        &layout.output_sections,
    );

    let (header, rest) = object::from_bytes_mut::<GnuHashHeader>(buffers.gnu_hash)
        .map_err(|_| anyhow!("Insufficient .gnu.hash allocation"))?;
    let e = LittleEndian;
    let gnu_hash_layout = &epilogue.gnu_hash_layout;
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

        let file_id = layout.symbol_db.file_id_for_symbol(sym_def.symbol_id);
        let file_layout = &layout.file_layouts[file_id.as_usize()];
        let FileLayout::Object(object) = file_layout else {
            bail!("Internal error: only objects should define dynamic symbols");
        };
        let sym = object.object.symbol_by_index(object::SymbolIndex(
            sym_def.symbol_id.offset_from(object.start_symbol_id),
        ))?;
        let section_index = sym
            .section_index()
            .context("Internal error: Symbols should only be defined if they have a section")?;
        let SectionSlot::Loaded(section) = &object.sections[section_index.0] else {
            bail!("Internal error: Defined symbols should always be for a loaded section");
        };
        let output_section_id = section.output_section_id.unwrap();
        let section_address = object.section_resolutions[section_index.0]
            .as_ref()
            .unwrap()
            .value
            .address_or_value()?;
        let name = sym.name_bytes()?;
        dynamic_symbol_writer
            .copy_symbol(&sym, name, output_section_id, section_address)
            .with_context(|| {
                format!(
                    "Failed to copy dynamic {}",
                    layout.symbol_debug(sym_def.symbol_id)
                )
            })?;
    }

    Ok(())
}

fn write_internal_symbols(
    internal_symbols: &InternalSymbols,
    layout: &Layout<'_>,
    symbol_writer: &mut SymbolTableWriter<'_, '_>,
) -> Result {
    for (local_index, def_info) in internal_symbols.symbol_definitions.iter().enumerate() {
        let symbol_id = internal_symbols.start_symbol_id.add_usize(local_index);
        if !layout.symbol_db.is_definition(symbol_id) {
            continue;
        }
        let Some(resolution) = layout.symbol_resolution(symbol_id) else {
            continue;
        };
        let Some(section_id) = def_info.section_id() else {
            // The null symbol is currently handled elsewhere. TODO: See if the code would be
            // simpler if we just handled it here.
            continue;
        };

        // We don't emit a section header for our headers section, so don't emit symbols that
        // are in that section, otherwise they'll show up as undefined.
        if section_id == output_section_id::FILE_HEADER {
            continue;
        }

        let symbol_name = layout.symbol_db.symbol_name(symbol_id)?;
        let shndx = layout
            .output_sections
            .output_index_of_section(section_id)
            .with_context(|| {
                format!(
                    "symbol `{}` in section `{}` that we're not going to output {resolution:?}",
                    symbol_name,
                    layout.output_sections.display_name(section_id)
                )
            })?;
        let address = resolution.value.address()?;
        let entry = symbol_writer
            .define_symbol(false, shndx, address, 0, symbol_name.bytes())
            .with_context(|| format!("Failed to write {}", layout.symbol_debug(symbol_id)))?;
        entry.st_info = (elf::Binding::Global as u8) << 4;
    }
    Ok(())
}

fn write_eh_frame_hdr(
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &Layout<'_>,
) -> Result {
    let header: &mut EhFrameHdr = bytemuck::from_bytes_mut(buffers.eh_frame_hdr);
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
    let hdr_sec = layout
        .section_layouts
        .built_in(output_section_id::EH_FRAME_HDR);
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
        DynamicTag::Init,
        |layout| layout.has_data_in_section(output_section_id::INIT),
        |layout| layout.vma_of_section(output_section_id::INIT),
    ),
    DynamicEntryWriter::optional(
        DynamicTag::Fini,
        |layout| layout.has_data_in_section(output_section_id::FINI),
        |layout| layout.vma_of_section(output_section_id::FINI),
    ),
    DynamicEntryWriter::optional(
        DynamicTag::InitArray,
        |layout| layout.has_data_in_section(output_section_id::INIT_ARRAY),
        |layout| layout.vma_of_section(output_section_id::INIT_ARRAY),
    ),
    DynamicEntryWriter::optional(
        DynamicTag::InitArraySize,
        |layout| layout.has_data_in_section(output_section_id::INIT_ARRAY),
        |layout| layout.size_of_section(output_section_id::INIT_ARRAY),
    ),
    DynamicEntryWriter::optional(
        DynamicTag::FiniArray,
        |layout| layout.has_data_in_section(output_section_id::FINI_ARRAY),
        |layout| layout.vma_of_section(output_section_id::FINI_ARRAY),
    ),
    DynamicEntryWriter::optional(
        DynamicTag::FiniArraySize,
        |layout| layout.has_data_in_section(output_section_id::FINI_ARRAY),
        |layout| layout.size_of_section(output_section_id::FINI_ARRAY),
    ),
    DynamicEntryWriter::new(DynamicTag::StrTab, |layout| {
        layout.vma_of_section(output_section_id::DYNSTR)
    }),
    DynamicEntryWriter::new(DynamicTag::StrSize, |layout| {
        layout.size_of_section(output_section_id::DYNSTR)
    }),
    DynamicEntryWriter::new(DynamicTag::SymTab, |layout| {
        layout.vma_of_section(output_section_id::DYNSYM)
    }),
    DynamicEntryWriter::new(DynamicTag::SymEnt, |_layout| {
        core::mem::size_of::<elf::SymtabEntry>() as u64
    }),
    // TODO: The debug tag is sometimes not present. Figure out the rules for it.
    DynamicEntryWriter::new(DynamicTag::Debug, |_layout| 0),
    DynamicEntryWriter::optional(
        DynamicTag::JmpRel,
        |layout| layout.section_part_layouts.rela_plt.mem_size > 0,
        |layout| layout.vma_of_section(output_section_id::RELA_PLT),
    ),
    DynamicEntryWriter::optional(
        DynamicTag::PltRelSize,
        |layout| layout.section_part_layouts.rela_plt.mem_size > 0,
        |layout| layout.section_part_layouts.rela_plt.mem_size,
    ),
    // TODO: For some reason setting this causes libc init code to segfault (libc-integration test
    // fails).
    // DynamicEntryWriter::optional(
    //     DynamicTag::PltRel,
    //     |layout| layout.section_part_layouts.rela_plt.mem_size > 0,
    //     |_| object::elf::DT_RELA.into(),
    // ),
    DynamicEntryWriter::new(DynamicTag::Rela, |layout| {
        layout.vma_of_section(output_section_id::RELA_DYN)
    }),
    DynamicEntryWriter::new(DynamicTag::RelaSize, |layout| {
        layout.size_of_section(output_section_id::RELA_DYN)
    }),
    DynamicEntryWriter::new(DynamicTag::RelaEnt, |_layout| elf::RELA_ENTRY_SIZE),
    // Note, rela-count is just the count of the relative relocations and doesn't include any
    // glob-dat relocations. This is as opposed to rela-size, which includes both.
    DynamicEntryWriter::new(DynamicTag::RelaCount, |layout| {
        layout.section_part_layouts.rela_dyn_relative.mem_size
            / core::mem::size_of::<elf::Rela>() as u64
    }),
    DynamicEntryWriter::new(DynamicTag::GnuHash, |layout| {
        layout.vma_of_section(output_section_id::GNU_HASH)
    }),
    DynamicEntryWriter::optional(
        DynamicTag::Flags,
        |layout| layout.args().bind_now,
        |layout| {
            let mut flags = 0;
            if layout.args().bind_now {
                flags |= elf::flags::BIND_NOW;
            }
            flags
        },
    ),
    DynamicEntryWriter::new(DynamicTag::Flags1, |layout| {
        let mut flags = 0;
        if layout.args().bind_now {
            flags |= elf::flags_1::NOW;
        }
        if layout.args().output_kind.is_executable() && layout.args().pie {
            flags |= elf::flags_1::PIE;
        }
        flags
    }),
    DynamicEntryWriter::new(DynamicTag::Null, |_layout| 0),
];

struct DynamicEntryWriter {
    tag: DynamicTag,
    is_present_cb: fn(&Layout) -> bool,
    cb: fn(&Layout) -> u64,
}

impl DynamicEntryWriter {
    const fn new(tag: DynamicTag, cb: fn(&Layout) -> u64) -> DynamicEntryWriter {
        DynamicEntryWriter {
            tag,
            is_present_cb: |_| true,
            cb,
        }
    }

    const fn optional(
        tag: DynamicTag,
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

    fn write(&mut self, tag: DynamicTag, value: u64) -> Result {
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
    output_sections.sections_do(|section_id, section_details| {
        let section_layout = layout.section_layouts.get(section_id);
        if output_sections
            .output_index_of_section(section_id)
            .is_none()
        {
            return;
        }
        let entsize = section_details.element_size;
        let size;
        let alignment;
        if section_details.ty == elf::Sht::Null {
            size = 0;
            alignment = 0;
        } else {
            size = section_layout.mem_size;
            alignment = section_layout.alignment.value();
        };
        let mut link = 0;
        if let Some(link_id) = layout.output_sections.link_id(section_id) {
            link = output_sections
                .output_index_of_section(link_id)
                .unwrap_or(0);
        }
        let entry = entries.next().unwrap();
        let e = LittleEndian;
        entry.sh_name.set(e, name_offset);
        entry.sh_type.set(e, section_details.ty as u32);
        entry.sh_flags.set(e, section_details.section_flags);
        entry.sh_addr.set(e, section_layout.mem_offset);
        entry.sh_offset.set(e, section_layout.file_offset as u64);
        entry.sh_size.set(e, size);
        entry.sh_link.set(e, link.into());
        entry.sh_info.set(e, section_id.info(layout));
        entry.sh_addralign.set(e, alignment);
        entry.sh_entsize.set(e, entsize);
        name_offset += layout.output_sections.name(section_id).len() as u32 + 1;
    });
    assert!(
        entries.next().is_none(),
        "Allocated section entries that weren't used"
    );
}

fn write_section_header_strings(mut out: &mut [u8], sections: &OutputSections) {
    sections.sections_do(|id, _details| {
        if sections.output_index_of_section(id).is_some() {
            let name = sections.name(id);
            let name_out = crate::slice::slice_take_prefix_mut(&mut out, name.len() + 1);
            name_out[..name.len()].copy_from_slice(name);
            name_out[name.len()] = 0;
        }
    });
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
    plt_got_writer: &mut PltGotWriter,
    relocation_writer: &mut DynamicRelocationWriter,
    layout: &Layout,
) -> Result {
    for i in 0..internal_symbols.symbol_definitions.len() {
        let symbol_id = internal_symbols.start_symbol_id.add_usize(i);
        if !layout.symbol_db.is_definition(symbol_id) {
            continue;
        }
        plt_got_writer
            .process_symbol(symbol_id, relocation_writer)
            .with_context(|| format!("Failed to process `{}`", layout.symbol_debug(symbol_id)))?;
    }
    Ok(())
}

impl<'data> DynamicLayout<'data> {
    fn write(&self, mut buffers: OutputSectionPartMap<&mut [u8]>, layout: &Layout) -> Result {
        let mut plt_got_writer = PltGotWriter::new(layout, &mut buffers);
        let mut relocation_writer = DynamicRelocationWriter::new(true, &mut buffers);
        let mut strtab = StrTabWriter {
            next_offset: self.dynstr_start_offset,
            out: buffers.dynstr,
        };

        self.write_so_name(buffers.dynamic, &mut strtab)?;

        let mut dynsym: &mut [SymtabEntry] = slice_from_all_bytes_mut(buffers.dynsym);
        for ((symbol_id, resolution), symbol) in layout
            .resolutions_in_range(self.start_symbol_id, self.num_symbols)
            .zip(self.object.dynamic_symbols())
        {
            if let Some(res) = resolution {
                write_dynamic_symtab_entry(&symbol, &mut dynsym, &mut strtab)?;

                plt_got_writer
                    .process_resolution(res, &mut relocation_writer)
                    .with_context(|| {
                        format!(
                            "Failed to write {}",
                            layout.symbol_db.symbol_debug(symbol_id)
                        )
                    })?;
            }
        }

        Ok(())
    }

    /// Write dynamic entry to indicate name of shared object to load.
    fn write_so_name(&self, dynamic: &mut [u8], strtab: &mut StrTabWriter) -> Result {
        let mut dynamic_out = DynamicEntriesWriter::new(dynamic);
        let needed_offset = strtab.write_str(self.lib_name);
        dynamic_out.write(DynamicTag::Needed, needed_offset)?;
        Ok(())
    }
}

fn write_dynamic_symtab_entry(
    symbol: &crate::elf::Symbol,
    dynsym: &mut &mut [SymtabEntry],
    strtab: &mut StrTabWriter,
) -> Result {
    let sym_out =
        crate::slice::take_first_mut(dynsym).context("Insufficient .dynsym allocation")?;
    let e = LittleEndian;
    sym_out.st_name.set(
        e,
        strtab
            .write_str(symbol.name_bytes()?)
            .try_into()
            .context(".dynstr is too big")?,
    );
    let object::SymbolFlags::Elf {
        mut st_info,
        st_other,
    } = symbol.flags()
    else {
        unreachable!()
    };
    // If the symbol is an ifunc, change it to a regular func. The symbol is undefined (all the
    // symbols we write here are) and the distinction between a regular function and an ifunc only
    // makes sense in the file that defines the symbol.
    if st_info & elf::SYMBOL_TYPE_MASK == elf::SYMBOL_TYPE_IFUNC {
        st_info = (st_info & elf::SYMBOL_VISIBILITY_MASK) | elf::SYMBOL_TYPE_FUNC;
    }
    // TODO: If this shared object weakly defines a symbol, but there are strong references to the
    // symbol, then we should upgrade the symbol strength to global. Right now, we don't pass
    // whether the symbol is weak or not when requesting symbols.
    sym_out.st_info = st_info;
    sym_out.st_other = st_other;
    sym_out.st_size.set(e, 0);
    Ok(())
}

struct StrTabWriter<'out> {
    next_offset: u64,
    out: &'out mut [u8],
}

impl<'out> StrTabWriter<'out> {
    fn write_str(&mut self, str: &[u8]) -> u64 {
        let len_with_terminator = str.len() + 1;
        let lib_name_out = slice_take_prefix_mut(&mut self.out, len_with_terminator);
        lib_name_out[..str.len()].copy_from_slice(str);
        lib_name_out[str.len()] = 0;
        let offset = self.next_offset;
        self.next_offset += len_with_terminator as u64;
        offset
    }
}
