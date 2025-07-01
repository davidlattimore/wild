use self::elf::GNU_NOTE_PROPERTY_ENTRY_SIZE;
use self::elf::NoteHeader;
use self::elf::NoteProperty;
use self::elf::get_page_mask;
use crate::alignment;
use crate::arch::Arch;
use crate::arch::Relaxation as _;
use crate::args::Args;
use crate::args::BuildIdOption;
use crate::args::OutputKind;
use crate::bail;
use crate::debug_assert_bail;
use crate::elf;
use crate::elf::DynamicEntry;
use crate::elf::EhFrameHdr;
use crate::elf::EhFrameHdrEntry;
use crate::elf::FileHeader;
use crate::elf::GLOBAL_POINTER_SYMBOL_NAME;
use crate::elf::GNU_NOTE_NAME;
use crate::elf::GnuHashHeader;
use crate::elf::ProgramHeader;
use crate::elf::SectionHeader;
use crate::elf::SymtabEntry;
use crate::elf::Verdaux;
use crate::elf::Verdef;
use crate::elf::Vernaux;
use crate::elf::Verneed;
use crate::elf::Versym;
use crate::elf::slice_from_all_bytes_mut;
use crate::elf::write_relocation_to_buffer;
use crate::ensure;
use crate::error;
use crate::error::Context as _;
use crate::error::Result;
use crate::file_writer::SizedOutput;
use crate::file_writer::excessive_allocation;
use crate::file_writer::insufficient_allocation;
use crate::file_writer::split_buffers_by_alignment;
use crate::file_writer::split_output_by_group;
use crate::file_writer::split_output_into_sections;
use crate::layout::DynamicLayout;
use crate::layout::EpilogueLayout;
use crate::layout::FileLayout;
use crate::layout::HeaderInfo;
use crate::layout::InternalSymbols;
use crate::layout::Layout;
use crate::layout::LinkerScriptLayoutState;
use crate::layout::NonAddressableCounts;
use crate::layout::ObjectLayout;
use crate::layout::OutputRecordLayout;
use crate::layout::PreludeLayout;
use crate::layout::ResFlagsDisplay;
use crate::layout::Resolution;
use crate::layout::ResolutionFlags;
use crate::layout::RiscVAttribute;
use crate::layout::Section;
use crate::layout::SymbolCopyInfo;
use crate::layout::VersionDef;
use crate::layout::compute_allocations;
use crate::output_section_id;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputOrder;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::output_trace::HexU64;
use crate::output_trace::TraceOutput;
use crate::part_id;
use crate::resolution::SectionSlot;
use crate::resolution::ValueFlags;
use crate::sharding::ShardKey;
use crate::slice::slice_take_prefix_mut;
use crate::slice::take_first_mut;
use crate::string_merging::get_merged_string_output_address;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use foldhash::HashMap as FoldHashMap;
use foldhash::HashMapExt as _;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RISCV_ATTRIBUTE_VENDOR_NAME;
use linker_utils::elf::RISCV_TLS_DTV_OFFSET;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RelocationSize;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::pf;
use linker_utils::elf::riscvattr::TAG_RISCV_ARCH;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC_MINOR;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC_REVISION;
use linker_utils::elf::riscvattr::TAG_RISCV_STACK_ALIGN;
use linker_utils::elf::riscvattr::TAG_RISCV_UNALIGNED_ACCESS;
use linker_utils::elf::riscvattr::TAG_RISCV_WHOLE_FILE;
use linker_utils::elf::secnames::DEBUG_LOC_SECTION_NAME;
use linker_utils::elf::secnames::DEBUG_RANGES_SECTION_NAME;
use linker_utils::elf::secnames::DYNSYM_SECTION_NAME_STR;
use linker_utils::elf::shf;
use linker_utils::elf::sht;
use linker_utils::relaxation::RelocationModifier;
use object::LittleEndian;
use object::SymbolIndex;
use object::elf::NT_GNU_BUILD_ID;
use object::elf::NT_GNU_PROPERTY_TYPE_0;
use object::from_bytes_mut;
use object::read::elf::Rela;
use object::read::elf::Sym as _;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelBridge;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSliceMut;
use std::fmt::Display;
use std::io::Cursor;
use std::io::Write;
use std::iter;
use std::marker::PhantomData;
use std::ops::BitAnd;
use std::ops::Not as _;
use std::ops::Range;
use std::ops::Sub;
use std::sync::atomic::Ordering::Relaxed;
use tracing::debug_span;
use tracing::instrument;
use uuid::Uuid;

pub(crate) fn write<A: Arch>(sized_output: &mut SizedOutput, layout: &Layout) -> Result {
    write_file_contents::<A>(sized_output, layout)?;
    if layout.args().validate_output {
        crate::validation::validate_bytes(layout, &sized_output.out)?;
    }

    if layout.args().should_write_eh_frame_hdr {
        let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out);
        sort_eh_frame_hdr_entries(section_buffers.get_mut(output_section_id::EH_FRAME_HDR));
    }

    write_gnu_build_id_note(sized_output, &layout.args().build_id, layout)?;
    Ok(())
}

fn write_gnu_build_id_note(
    sized_output: &mut SizedOutput,
    build_id_option: &BuildIdOption,
    layout: &Layout,
) -> Result {
    let hash_placeholder;
    let uuid_placeholder;
    let build_id = match build_id_option {
        BuildIdOption::Fast => {
            hash_placeholder = compute_hash(sized_output);
            hash_placeholder.as_bytes()
        }
        BuildIdOption::Hex(hex) => hex.as_slice(),
        BuildIdOption::Uuid => {
            uuid_placeholder = Uuid::new_v4();
            uuid_placeholder.as_bytes()
        }
        BuildIdOption::None => return Ok(()),
    };

    let mut buffers = split_output_into_sections(layout, &mut sized_output.out);
    let e = LittleEndian;
    let (note_header, mut rest) =
        from_bytes_mut::<NoteHeader>(buffers.get_mut(output_section_id::NOTE_GNU_BUILD_ID))
            .map_err(|_| insufficient_allocation(".note.gnu.build-id"))?;
    note_header.n_namesz.set(e, GNU_NOTE_NAME.len() as u32);
    note_header.n_descsz.set(e, build_id.len() as u32);
    note_header.n_type.set(e, NT_GNU_BUILD_ID);

    let name_out = crate::slice::slice_take_prefix_mut(&mut rest, GNU_NOTE_NAME.len());
    name_out.copy_from_slice(GNU_NOTE_NAME);

    rest.copy_from_slice(build_id);

    Ok(())
}

#[instrument(skip_all, name = "Compute build ID")]
fn compute_hash(sized_output: &SizedOutput) -> blake3::Hash {
    blake3::Hasher::new()
        .update_rayon(&sized_output.out)
        .finalize()
}

#[tracing::instrument(skip_all, name = "Write data to file")]
fn write_file_contents<A: Arch>(sized_output: &mut SizedOutput, layout: &Layout) -> Result {
    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out);

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
                write_file::<A>(
                    file,
                    &mut buffers,
                    &mut table_writer,
                    layout,
                    &sized_output.trace,
                )
                .with_context(|| format!("Failed copying from {file} to output file"))?;
            }
            table_writer
                .validate_empty(&group.mem_sizes)
                .with_context(|| format!("validate_empty failed for {group}"))?;
            Ok(())
        })?;

    for (output_section_id, _) in layout.output_sections.ids_with_info() {
        let relocations = layout
            .relocation_statistics
            .get(output_section_id)
            .load(Relaxed);

        if relocations > 0 {
            tracing::debug!(
                    target: "metrics",
                    section = layout.output_sections.display_name(output_section_id),
                    relocations, "resolved relocations");
        }
    }
    Ok(())
}

#[tracing::instrument(skip_all, name = "Sort .eh_frame_hdr")]
fn sort_eh_frame_hdr_entries(eh_frame_hdr: &mut [u8]) {
    let entry_bytes = &mut eh_frame_hdr[size_of::<elf::EhFrameHdr>()..];
    let entries: &mut [elf::EhFrameHdrEntry] = bytemuck::cast_slice_mut(entry_bytes);
    entries.par_sort_by_key(|e| e.frame_ptr);
}

fn write_program_headers(program_headers_out: &mut ProgramHeaderWriter, layout: &Layout) -> Result {
    for segment_layout in &layout.segment_layouts.segments {
        let segment_sizes = &segment_layout.sizes;
        let segment_id = segment_layout.id;
        let segment_header = program_headers_out.take_header()?;
        let mut alignment = segment_sizes.alignment;

        if layout.program_segments.is_load_segment(segment_id) {
            alignment = alignment.max(layout.args().loadable_segment_alignment());
        } else if layout.program_segments.is_stack_segment(segment_id) {
            alignment = alignment::STACK_ALIGNMENT;
        }

        let e = LittleEndian;
        let segment_details = layout.program_segments.segment_def(segment_id);

        segment_header
            .p_type
            .set(e, segment_details.segment_type.raw());

        // Support executable stack (Wild defaults to non-executable stack)
        let mut segment_flags = segment_details.segment_flags;
        if layout.program_segments.is_stack_segment(segment_id) && layout.args().execstack {
            segment_flags |= pf::EXECUTABLE;
        }

        segment_header.p_flags.set(e, segment_flags.raw());
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

fn populate_file_header<A: Arch>(
    layout: &Layout,
    header_info: &HeaderInfo,
    header: &mut FileHeader,
) -> Result {
    let args = layout.args();
    let ty = if args.output_kind().is_relocatable() {
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
    header.e_machine.set(e, A::elf_header_arch_magic());
    header.e_version.set(e, u32::from(object::elf::EV_CURRENT));
    header.e_entry.set(e, layout.entry_symbol_address()?);
    header.e_phoff.set(e, elf::PHEADER_OFFSET);
    header.e_shoff.set(
        e,
        u64::from(elf::FILE_HEADER_SIZE) + header_info.program_headers_size(),
    );
    header.e_flags.set(e, header_info.eflags);
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

fn write_file<A: Arch>(
    file: &FileLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter,
    layout: &Layout,
    trace: &TraceOutput,
) -> Result {
    match file {
        FileLayout::Object(s) => write_object::<A>(s, buffers, table_writer, layout, trace)?,
        FileLayout::Prelude(s) => write_prelude::<A>(s, buffers, table_writer, layout)?,
        FileLayout::Epilogue(s) => write_epilogue::<A>(s, buffers, table_writer, layout)?,
        FileLayout::LinkerScript(s) => write_linker_script_state::<A>(s, table_writer, layout)?,
        FileLayout::NotLoaded => {}
        FileLayout::Dynamic(s) => write_dynamic_file::<A>(s, table_writer, layout)?,
    }
    Ok(())
}

#[derive(Default)]
struct VersionWriter<'out> {
    version_d: &'out mut [u8],
    version_r: &'out mut [u8],

    /// None if versioning is disabled, which we do if no symbols have versions.
    versym: Option<&'out mut [Versym]>,
}

impl<'out> VersionWriter<'out> {
    fn new(
        version_d: &'out mut [u8],
        version_r: &'out mut [u8],
        versym: Option<&'out mut [Versym]>,
    ) -> Self {
        Self {
            version_d,
            version_r,
            versym,
        }
    }

    fn set_next_symbol_version(&mut self, index: u16) -> Result {
        if let Some(versym_table) = self.versym.as_mut() {
            let versym = crate::slice::take_first_mut(versym_table)
                .ok_or_else(|| insufficient_allocation(".gnu.version"))?;
            versym.0.set(LittleEndian, index);
        }
        Ok(())
    }

    fn take_bytes(&mut self, size: usize) -> Result<&'out mut [u8]> {
        crate::slice::try_slice_take_prefix_mut(&mut self.version_r, size)
            .ok_or_else(|| insufficient_allocation(".gnu.version_r"))
    }

    fn take_verneed(&mut self) -> Result<&'out mut Verneed> {
        let bytes = self.take_bytes(size_of::<Verneed>())?;
        Ok(object::from_bytes_mut(bytes)
            .map_err(|_| error!("Incorrect .gnu.version_r alignment"))?
            .0)
    }

    fn take_auxes(&mut self, version_count: u16) -> Result<&'out mut [Vernaux]> {
        let bytes = self.take_bytes(size_of::<Vernaux>() * usize::from(version_count))?;
        object::slice_from_all_bytes_mut::<Vernaux>(bytes)
            .map_err(|_| error!("Invalid .gnu.version_r allocation"))
    }

    fn take_bytes_d(&mut self, size: usize) -> Result<&'out mut [u8]> {
        crate::slice::try_slice_take_prefix_mut(&mut self.version_d, size)
            .ok_or_else(|| insufficient_allocation(".gnu.version_d"))
    }

    fn take_verdef(&mut self) -> Result<&'out mut Verdef> {
        let bytes = self.take_bytes_d(size_of::<Verdef>())?;
        Ok(object::from_bytes_mut::<Verdef>(bytes)
            .map_err(|_| error!("Incorrect .gnu.version_d alignment"))?
            .0)
    }

    fn take_verdaux(&mut self) -> Result<&'out mut Verdaux> {
        let bytes = self.take_bytes_d(size_of::<Verdaux>())?;
        Ok(object::from_bytes_mut::<Verdaux>(bytes)
            .map_err(|_| error!("Incorrect .gnu.version_d aux alignment"))?
            .0)
    }

    fn check_exhausted(&self, mem_sizes: &OutputSectionPartMap<u64>) -> Result {
        if let Some(versym) = self.versym.as_ref() {
            if !versym.is_empty() {
                return Err(excessive_allocation(
                    ".gnu.version",
                    versym.len() as u64 * elf::GNU_VERSION_ENTRY_SIZE,
                    *mem_sizes.get(part_id::GNU_VERSION),
                ));
            }
        }
        if !self.version_r.is_empty() {
            bail!(
                "Allocated too much space in .gnu.version_r. {} of {} bytes remain",
                self.version_r.len(),
                mem_sizes.get(part_id::GNU_VERSION_R)
            );
        }
        if !self.version_d.is_empty() {
            bail!(
                "Allocated too much space in .gnu.version_d. {} of {} bytes remain",
                self.version_d.len(),
                mem_sizes.get(part_id::GNU_VERSION_D)
            );
        }
        Ok(())
    }
}

struct TableWriter<'layout, 'out> {
    output_kind: OutputKind,
    got: &'out mut [u64],
    plt_got: &'out mut [u8],
    rela_plt: &'out mut [elf::Rela],
    tls: Range<u64>,
    rela_dyn_relative: &'out mut [crate::elf::Rela],
    rela_dyn_general: &'out mut [crate::elf::Rela],
    dynsym_writer: SymbolTableWriter<'layout, 'out>,
    debug_symbol_writer: SymbolTableWriter<'layout, 'out>,
    eh_frame_start_address: u64,
    eh_frame: &'out mut [u8],

    /// Note, this is stored as raw bytes because it starts with an EhFrameHdr, but is then followed
    /// by multiple EhFrameHdrEntry.
    eh_frame_hdr: &'out mut [u8],

    dynamic: DynamicEntriesWriter<'out>,
    version_writer: VersionWriter<'out>,
}

impl<'layout, 'out> TableWriter<'layout, 'out> {
    fn from_layout(
        layout: &'layout Layout,
        dynstr_start_offset: u32,
        strtab_start_offset: u32,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
        eh_frame_start_address: u64,
    ) -> TableWriter<'layout, 'out> {
        let dynsym_writer =
            SymbolTableWriter::new_dynamic(dynstr_start_offset, buffers, &layout.output_sections);
        let debug_symbol_writer =
            SymbolTableWriter::new(strtab_start_offset, buffers, &layout.output_sections);

        Self::new(
            layout.args().output_kind(),
            layout.tls_start_address()..layout.tls_end_address(),
            buffers,
            dynsym_writer,
            debug_symbol_writer,
            eh_frame_start_address,
        )
    }

    fn new(
        output_kind: OutputKind,
        tls: Range<u64>,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
        dynsym_writer: SymbolTableWriter<'layout, 'out>,
        debug_symbol_writer: SymbolTableWriter<'layout, 'out>,
        eh_frame_start_address: u64,
    ) -> TableWriter<'layout, 'out> {
        let eh_frame = buffers.take(part_id::EH_FRAME);
        let eh_frame_hdr = buffers.take(part_id::EH_FRAME_HDR);
        let dynamic = DynamicEntriesWriter::new(buffers.take(part_id::DYNAMIC));
        let versym = slice_from_all_bytes_mut(buffers.take(part_id::GNU_VERSION));
        let version_writer = VersionWriter::new(
            buffers.take(part_id::GNU_VERSION_D),
            buffers.take(part_id::GNU_VERSION_R),
            versym.is_empty().not().then_some(versym),
        );

        TableWriter {
            output_kind,
            got: bytemuck::cast_slice_mut(buffers.take(part_id::GOT)),
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
        }
    }

    fn process_resolution<A: Arch>(&mut self, layout: Option<&Layout>, res: &Resolution) -> Result {
        let Some(got_address) = res.got_address else {
            return Ok(());
        };

        let mut got_address = got_address.get();
        let resolution_flags = res.resolution_flags;

        // For TLS variables, we'll generally only have one of these, but we might have all 3 combinations.
        if resolution_flags.needs_got_tls_offset()
            || resolution_flags.needs_got_tls_module()
            || resolution_flags.needs_got_tls_descriptor()
        {
            if resolution_flags.needs_got_tls_offset() {
                self.process_got_tls_offset::<A>(
                    res,
                    layout.context("Layout must be present")?,
                    got_address,
                )?;
                got_address += crate::elf::GOT_ENTRY_SIZE;
            }
            if resolution_flags.needs_got_tls_module() {
                self.process_got_tls_mod_and_offset::<A>(res, got_address)?;
                got_address += 2 * crate::elf::GOT_ENTRY_SIZE;
            }
            if resolution_flags.needs_got_tls_descriptor() {
                self.process_got_tls_descriptor::<A>(res, got_address)?;
            }
            return Ok(());
        }

        let got_entry = self.take_next_got_entry()?;

        if res.value_flags.is_dynamic()
            || (resolution_flags.needs_export_dynamic() && res.value_flags.is_interposable())
                && !res.value_flags.is_ifunc()
        {
            debug_assert_bail!(
                *compute_allocations(res, self.output_kind).get(part_id::RELA_DYN_GENERAL) > 0,
                "Tried to write glob-dat with no allocation. {}",
                ResFlagsDisplay(res)
            );
            self.write_dynamic_symbol_relocation::<A>(
                got_address,
                0,
                res.dynamic_symbol_index()?,
                DynamicRelocationKind::GotEntry,
            )?;
        } else if res.value_flags.is_ifunc() {
            self.write_ifunc_relocation::<A>(res)?;
        } else {
            *got_entry = res.raw_value;
            if res.value_flags.is_address() && self.output_kind.is_relocatable() {
                self.write_address_relocation::<A>(got_address, res.raw_value as i64)?;
            }
        }
        if let Some(plt_address) = res.plt_address {
            self.write_plt_entry::<A>(got_address, plt_address.get())?;
        }
        Ok(())
    }

    fn process_got_tls_offset<A: Arch>(
        &mut self,
        res: &Resolution,
        layout: &Layout,
        got_address: u64,
    ) -> Result {
        let got_entry = self.take_next_got_entry()?;
        if res.value_flags.is_dynamic()
            || (res.resolution_flags.needs_export_dynamic() && res.value_flags.is_interposable())
        {
            return self.write_tpoff_relocation::<A>(got_address, res.dynamic_symbol_index()?, 0);
        }
        let address = res.raw_value;
        if address == 0 {
            // Resolution is undefined.
            *got_entry = 0;
            return Ok(());
        }
        // TLS_MODULE_BASE points at the end of the .tbss in some cases, thus relax the verification.
        if !(self.tls.start..=self.tls.end).contains(&address) {
            bail!(
                "GotTlsOffset resolves to address not in TLS segment 0x{:x}",
                address
            );
        }
        if self.output_kind.is_executable() {
            // Convert the address to an offset relative to the TCB.

            *got_entry = address.wrapping_sub(A::tp_offset_start(layout));
        } else {
            debug_assert_bail!(
                *compute_allocations(res, self.output_kind).get(part_id::RELA_DYN_GENERAL) > 0,
                "Tried to write tpoff with no allocation. {}",
                ResFlagsDisplay(res)
            );
            self.write_tpoff_relocation::<A>(got_address, 0, address.sub(self.tls.start) as i64)?;
        }
        Ok(())
    }

    fn process_got_tls_mod_and_offset<A: Arch>(
        &mut self,
        res: &Resolution,
        got_address: u64,
    ) -> Result {
        let got_entry = self.take_next_got_entry()?;
        if self.output_kind.is_executable() && !res.value_flags.is_dynamic() {
            *got_entry = elf::CURRENT_EXE_TLS_MOD;
        } else {
            let dynamic_symbol_index = res.dynamic_symbol_index.map_or(0, std::num::NonZero::get);
            debug_assert_bail!(
                *compute_allocations(res, self.output_kind).get(part_id::RELA_DYN_GENERAL) > 0,
                "Tried to write dtpmod with no allocation. {}",
                ResFlagsDisplay(res)
            );
            self.write_dtpmod_relocation::<A>(got_address, dynamic_symbol_index)?;
        }
        let offset_entry = self.take_next_got_entry()?;
        if let Some(dynamic_symbol_index) = res.dynamic_symbol_index {
            if res.value_flags.is_interposable() {
                self.write_dtpoff_relocation::<A>(
                    got_address + crate::elf::TLS_OFFSET_OFFSET,
                    dynamic_symbol_index.get(),
                )?;
            }
            return Ok(());
        }
        // Convert the address to an offset within the TLS segment
        let address = res.address()?;
        *offset_entry = address
            .wrapping_sub(self.tls.start)
            .wrapping_sub(A::get_dtv_offset());
        Ok(())
    }

    fn process_got_tls_descriptor<A: Arch>(
        &mut self,
        res: &Resolution,
        got_address: u64,
    ) -> Result {
        // TLS descriptor occupies 2 entries
        self.take_next_got_entry()?;
        self.take_next_got_entry()?;

        ensure!(
            !self.output_kind.is_static_executable(),
            "Cannot create dynamic TLSDESC relocation (function trampoline will be missed) for a static executable"
        );

        let dynamic_symbol_index = res.dynamic_symbol_index.map_or(0, std::num::NonZero::get);
        debug_assert_bail!(
            *compute_allocations(res, self.output_kind).get(part_id::RELA_DYN_GENERAL) > 0,
            "Tried to write TLS descriptor with no allocation. {}",
            ResFlagsDisplay(res)
        );
        let addend = if res.dynamic_symbol_index.is_none() {
            res.raw_value.sub(self.tls.start) as i64
        } else {
            0
        };
        self.write_tls_descriptor_relocation::<A>(got_address, dynamic_symbol_index, addend)?;

        Ok(())
    }

    fn write_plt_entry<A: Arch>(&mut self, got_address: u64, plt_address: u64) -> Result {
        let plt_entry = self.take_plt_got_entry()?;
        A::write_plt_entry(plt_entry, got_address, plt_address)
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
        crate::slice::take_first_mut(&mut self.got).ok_or_else(|| insufficient_allocation(".got"))
    }

    /// Checks that we used all of the entries that we requested during layout.
    fn validate_empty(&self, mem_sizes: &OutputSectionPartMap<u64>) -> Result {
        if !self.rela_dyn_relative.is_empty() {
            return Err(excessive_allocation(
                ".rela.dyn (relative)",
                self.rela_dyn_relative.len() as u64 * elf::RELA_ENTRY_SIZE,
                *mem_sizes.get(part_id::RELA_DYN_RELATIVE),
            ));
        }
        if !self.rela_dyn_general.is_empty() {
            return Err(excessive_allocation(
                ".rela.dyn (general)",
                self.rela_dyn_general.len() as u64 * elf::RELA_ENTRY_SIZE,
                *mem_sizes.get(part_id::RELA_DYN_GENERAL),
            ));
        }
        self.dynsym_writer.check_exhausted()?;
        self.debug_symbol_writer.check_exhausted()?;
        self.version_writer.check_exhausted(mem_sizes)?;
        if !self.eh_frame.is_empty() {
            return Err(excessive_allocation(
                ".eh_frame",
                self.eh_frame.len() as u64,
                *mem_sizes.get(part_id::EH_FRAME),
            ));
        }
        if !self.eh_frame_hdr.is_empty() {
            return Err(excessive_allocation(
                ".eh_frame_hdr",
                self.eh_frame_hdr.len() as u64,
                *mem_sizes.get(part_id::EH_FRAME_HDR),
            ));
        }
        Ok(())
    }

    fn write_ifunc_relocation<A: Arch>(&mut self, res: &Resolution) -> Result {
        let out = slice_take_prefix_mut(&mut self.rela_plt, 1);
        let out = &mut out[0];
        let e = LittleEndian;
        out.r_addend.set(e, res.raw_value as i64);
        let got_address = res
            .got_address
            .context("Missing GOT entry for ifunc")?
            .get();
        out.r_offset.set(e, got_address);
        out.r_info.set(
            e,
            u64::from(A::get_dynamic_relocation_type(
                DynamicRelocationKind::Irelative,
            )),
        );
        Ok(())
    }

    fn write_dtpmod_relocation<A: Arch>(
        &mut self,
        place: u64,
        dynamic_symbol_index: u32,
    ) -> Result {
        self.write_rela_dyn_general(
            place,
            dynamic_symbol_index,
            A::get_dynamic_relocation_type(DynamicRelocationKind::DtpMod),
            0,
        )
    }

    fn write_tls_descriptor_relocation<A: Arch>(
        &mut self,
        place: u64,
        dynamic_symbol_index: u32,
        addend: i64,
    ) -> Result {
        self.write_rela_dyn_general(
            place,
            dynamic_symbol_index,
            A::get_dynamic_relocation_type(DynamicRelocationKind::TlsDesc),
            addend,
        )
    }

    fn write_dtpoff_relocation<A: Arch>(
        &mut self,
        place: u64,
        dynamic_symbol_index: u32,
    ) -> Result {
        self.write_rela_dyn_general(
            place,
            dynamic_symbol_index,
            A::get_dynamic_relocation_type(DynamicRelocationKind::DtpOff),
            0,
        )
    }

    fn write_tpoff_relocation<A: Arch>(
        &mut self,
        place: u64,
        dynamic_symbol_index: u32,
        addend: i64,
    ) -> Result {
        self.write_rela_dyn_general(
            place,
            dynamic_symbol_index,
            A::get_dynamic_relocation_type(DynamicRelocationKind::TpOff),
            addend,
        )
    }

    #[inline(always)]
    fn write_address_relocation<A: Arch>(&mut self, place: u64, relative_address: i64) -> Result {
        debug_assert_bail!(
            self.output_kind.is_relocatable(),
            "write_address_relocation called when output is not relocatable"
        );
        let e = LittleEndian;
        let rela = crate::slice::take_first_mut(&mut self.rela_dyn_relative)
            .ok_or_else(|| insufficient_allocation(".rela.dyn (relative)"))?;
        rela.r_offset.set(e, place);
        rela.r_addend.set(e, relative_address);
        rela.r_info.set(
            e,
            A::get_dynamic_relocation_type(DynamicRelocationKind::Relative).into(),
        );
        Ok(())
    }

    fn write_dynamic_symbol_relocation<A: Arch>(
        &mut self,
        place: u64,
        addend: i64,
        symbol_index: u32,
        kind: DynamicRelocationKind,
    ) -> Result {
        let _span = tracing::trace_span!("write_dynamic_symbol_relocation").entered();
        debug_assert_bail!(
            self.output_kind.needs_dynsym(),
            "Tried to write dynamic relocation with non-relocatable output"
        );
        let e = LittleEndian;
        let rela = self.take_rela_dyn()?;
        rela.r_offset.set(e, place);
        rela.r_addend.set(e, addend);
        rela.set_r_info(
            LittleEndian,
            false,
            symbol_index,
            A::get_dynamic_relocation_type(kind),
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
            "write_rela_dyn_general called when output is not dynamic"
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
            .ok_or_else(|| insufficient_allocation(".rela.dyn (non-relative)"))
    }

    fn take_eh_frame_hdr(&mut self) -> &'out mut EhFrameHdr {
        let entry_bytes =
            crate::slice::slice_take_prefix_mut(&mut self.eh_frame_hdr, size_of::<EhFrameHdr>());
        bytemuck::from_bytes_mut(entry_bytes)
    }

    fn take_eh_frame_hdr_entry(&mut self) -> Option<&mut EhFrameHdrEntry> {
        if self.eh_frame_hdr.is_empty() {
            return None;
        }
        let entry_bytes = crate::slice::slice_take_prefix_mut(
            &mut self.eh_frame_hdr,
            size_of::<EhFrameHdrEntry>(),
        );
        Some(bytemuck::from_bytes_mut(entry_bytes))
    }

    fn take_eh_frame_data(&mut self, size: usize) -> Result<&'out mut [u8]> {
        if size > self.eh_frame.len() {
            return Err(insufficient_allocation(".eh_frame"));
        }
        Ok(crate::slice::slice_take_prefix_mut(
            &mut self.eh_frame,
            size,
        ))
    }
}

struct SymbolTableWriter<'layout, 'out> {
    local_entries: &'out mut [SymtabEntry],
    global_entries: &'out mut [SymtabEntry],
    output_sections: &'layout OutputSections<'layout>,
    strtab_writer: StrTabWriter<'out>,
    is_dynamic: bool,
}

impl<'layout, 'out> SymbolTableWriter<'layout, 'out> {
    fn new(
        start_string_offset: u32,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
        output_sections: &'layout OutputSections<'layout>,
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
        output_sections: &'layout OutputSections,
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

    #[inline(always)]
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

    #[inline(always)]
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

    #[inline(always)]
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
                tracing::trace!(name = %String::from_utf8_lossy(name), "Write .dynsym");
            }
            take_first_mut(&mut self.global_entries).with_context(|| {
                format!(
                    "Insufficient {} entries allocated for symbol `{}`",
                    if self.is_dynamic {
                        DYNSYM_SECTION_NAME_STR
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

fn write_object<A: Arch>(
    object: &ObjectLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter,
    layout: &Layout,
    trace: &TraceOutput,
) -> Result {
    let _span = debug_span!("write_file", filename = %object.input).entered();
    let _file_span = layout.args().trace_span_for_file(object.file_id);
    for sec in &object.sections {
        match sec {
            SectionSlot::Loaded(sec) => {
                write_object_section::<A>(object, layout, sec, buffers, table_writer, trace)?;
            }
            SectionSlot::LoadedDebugInfo(sec) => {
                write_debug_section::<A>(object, layout, sec, buffers)?;
            }
            SectionSlot::EhFrameData(section_index) => {
                write_eh_frame_data::<A>(object, *section_index, layout, table_writer, trace)?;
            }
            _ => (),
        }
    }
    for (symbol_id, resolution) in layout.resolutions_in_range(object.symbol_id_range) {
        let _span = tracing::trace_span!("Symbol", %symbol_id).entered();
        if let Some(res) = resolution {
            table_writer
                .process_resolution::<A>(Some(layout), res)
                .with_context(|| {
                    format!(
                        "Failed to process `{}` with resolution {res:?}",
                        layout.symbol_debug(symbol_id)
                    )
                })?;

            // Dynamic symbols that we define are handled by the epilogue so that they can be
            // written in the correct order. Here, we only need to handle weak symbols that we
            // reference that aren't defined by any shared objects we're linking against.
            if res.value_flags.is_dynamic() {
                let symbol = object
                    .object
                    .symbol(object.symbol_id_range.id_to_input(symbol_id))?;
                let name = object.object.symbol_name(symbol)?;
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
        write_symbols(object, &mut table_writer.debug_symbol_writer, layout)?;
    }
    Ok(())
}

fn write_object_section<A: Arch>(
    object: &ObjectLayout,
    layout: &Layout,
    sec: &Section,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter,
    trace: &TraceOutput,
) -> Result {
    let out = write_section_raw(object, layout, sec, buffers)?;

    apply_relocations::<A>(object, out, sec, layout, table_writer, trace).with_context(|| {
        format!(
            "Failed to apply relocations in section `{}` of {}",
            object.object.section_display_name(sec.index),
            object.input
        )
    })?;
    if sec.resolution_flags.needs_got() || sec.resolution_flags.needs_plt() {
        bail!("Section has GOT or PLT");
    };
    Ok(())
}

fn write_debug_section<A: Arch>(
    object: &ObjectLayout,
    layout: &Layout,
    sec: &Section,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let out = write_section_raw(object, layout, sec, buffers)?;

    apply_debug_relocations::<A>(object, out, sec, layout).with_context(|| {
        format!(
            "Failed to apply relocations in section `{}` of {}",
            object.object.section_display_name(sec.index),
            object.input
        )
    })?;
    Ok(())
}

fn write_section_raw<'out>(
    object: &ObjectLayout,
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
                object.object.section_display_name(sec.index),
                allocation_size,
                section_buffer.len()
            );
        }
        let out = slice_take_prefix_mut(section_buffer, allocation_size);
        // Cut off any padding so that our output buffer is the size of our input buffer.
        let object_section = object.object.section(sec.index)?;
        let section_size = object.object.section_size(object_section)?;
        let out: &'out mut [u8] = &mut out[..section_size as usize];
        object.object.copy_section_data(object_section, out)?;
        Ok(out)
    } else {
        Ok(&mut [])
    }
}

/// Writes debug symbols.
fn write_symbols(
    object: &ObjectLayout,
    symbol_writer: &mut SymbolTableWriter,
    layout: &Layout,
) -> Result {
    for ((sym_index, sym), sym_state) in object
        .object
        .symbols
        .enumerate()
        .zip(&layout.symbol_resolution_flags[object.symbol_id_range.as_usize()])
    {
        let symbol_id = object.symbol_id_range.input_to_id(sym_index);

        if layout.symbol_db.args.got_plt_syms {
            write_got_plt_syms(layout, symbol_writer, symbol_id)?;
        }
        if let Some(info) = SymbolCopyInfo::new(
            object.object,
            sym_index,
            sym,
            symbol_id,
            &layout.symbol_db,
            *sym_state,
            &object.sections,
        ) {
            let e = LittleEndian;

            let section_id =
                if let Some(section_index) = object.object.symbol_section(sym, sym_index)? {
                    match &object.sections[section_index.0] {
                        SectionSlot::Loaded(section) => section.output_section_id(),
                        SectionSlot::MergeStrings(section) => section.part_id.output_section_id(),
                        SectionSlot::EhFrameData(..) => output_section_id::EH_FRAME,
                        _ => bail!(
                            "Tried to copy a symbol in a section we didn't load. {}",
                            layout.symbol_db.symbol_debug(symbol_id)
                        ),
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

            let section_id = layout.output_sections.primary_output_section(section_id);

            let Some(res) = layout.local_symbol_resolution(symbol_id) else {
                bail!("Missing resolution for {}", layout.symbol_debug(symbol_id));
            };

            let mut symbol_value = res.value_for_symbol_table();

            if sym.st_type() == object::elf::STT_TLS {
                symbol_value -= layout.tls_start_address();
            }

            symbol_writer
                .copy_symbol(sym, info.name, section_id, symbol_value)
                .with_context(|| format!("Failed to copy {}", layout.symbol_debug(symbol_id)))?;
        }
    }
    Ok(())
}

fn apply_relocations<A: Arch>(
    object: &ObjectLayout,
    out: &mut [u8],
    section: &Section,
    layout: &Layout,
    table_writer: &mut TableWriter,
    trace: &TraceOutput,
) -> Result {
    let section_address = object.section_resolutions[section.index.0]
        .address()
        .context("Attempted to apply relocations to a section that we didn't load")?;

    let object_section = object.object.section(section.index)?;
    let section_flags = SectionFlags::from_header(object_section);
    let mut modifier = RelocationModifier::Normal;
    let relocations = object.relocations(section.index)?;
    layout
        .relocation_statistics
        .get(section.part_id.output_section_id())
        .fetch_add(relocations.len() as u64, Relaxed);
    for (i, rel) in relocations.iter().enumerate() {
        if modifier == RelocationModifier::SkipNextRelocation {
            modifier = RelocationModifier::Normal;
            continue;
        }
        let offset_in_section = rel.r_offset.get(LittleEndian);
        modifier = apply_relocation::<A>(
            object,
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
            trace,
            relocations,
            i,
        )
        .with_context(|| {
            format!(
                "Failed to apply {} at offset 0x{offset_in_section:x}",
                display_relocation::<A>(object, rel, layout)
            )
        })?;
    }
    Ok(())
}

fn apply_debug_relocations<A: Arch>(
    object: &ObjectLayout,
    out: &mut [u8],
    section: &Section,
    layout: &Layout,
) -> Result {
    let object_section = object.object.section(section.index)?;
    let section_name = object.object.section_name(object_section)?;

    // TODO: Starting with DWARF 6, the tombstone value will be defined as -1 and -2.
    // However, the change is premature as consumers of the DWARF format don't fully support
    // the new tombstone values.
    //
    // Link: https://dwarfstd.org/issues/200609.1.html
    let tombstone_value: u64 =
        if section_name == DEBUG_LOC_SECTION_NAME || section_name == DEBUG_RANGES_SECTION_NAME {
            // These sections use zero as a list terminator.
            1
        } else {
            0
        };

    let relocations = object.relocations(section.index)?;
    layout
        .relocation_statistics
        .get(section.part_id.output_section_id())
        .fetch_add(relocations.len() as u64, Relaxed);
    for (i, rel) in relocations.iter().enumerate() {
        let offset_in_section = rel.r_offset.get(LittleEndian);
        apply_debug_relocation::<A>(
            object,
            offset_in_section,
            rel,
            layout,
            tombstone_value,
            out,
            relocations,
            i,
        )
        .with_context(|| {
            format!(
                "Failed to apply {} at offset 0x{offset_in_section:x}",
                display_relocation::<A>(object, rel, layout)
            )
        })?;
    }
    Ok(())
}

fn write_eh_frame_data<A: Arch>(
    object: &ObjectLayout,
    eh_frame_section_index: object::SectionIndex,
    layout: &Layout,
    table_writer: &mut TableWriter,
    trace: &TraceOutput,
) -> Result {
    let eh_frame_section = object.object.section(eh_frame_section_index)?;
    let data = object.object.raw_section_data(eh_frame_section)?;
    const PREFIX_LEN: usize = size_of::<elf::EhFrameEntryPrefix>();
    let e = LittleEndian;
    let section_flags = SectionFlags::from_header(eh_frame_section);
    let mut relocations = object
        .relocations(eh_frame_section_index)?
        .iter()
        .peekable();
    let mut input_pos = 0;
    let mut output_pos = 0;
    let frame_info_ptr_base = table_writer.eh_frame_start_address;
    let eh_frame_hdr_address = layout.mem_address_of_built_in(output_section_id::EH_FRAME_HDR);

    // Map from input offset to output offset of each CIE.
    let mut cies_offset_conversion: FoldHashMap<u32, u32> = FoldHashMap::new();

    while input_pos + PREFIX_LEN <= data.len() {
        let prefix: elf::EhFrameEntryPrefix =
            bytemuck::pod_read_unaligned(&data[input_pos..input_pos + PREFIX_LEN]);
        let size = size_of_val(&prefix.length) + prefix.length as usize;
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
                    let is_pc_begin = (rel_offset as usize - input_pos) == elf::FDE_PC_BEGIN_OFFSET;

                    if is_pc_begin {
                        let Some(index) = rel.symbol(e, false) else {
                            bail!("Unexpected absolute relocation in .eh_frame pc-begin");
                        };
                        let elf_symbol = &object.object.symbol(index)?;
                        let Some(section_index) =
                            object.object.symbol_section(elf_symbol, index)?
                        else {
                            bail!(".eh_frame pc-begin refers to symbol that's not defined in file");
                        };
                        let offset_in_section =
                            (elf_symbol.st_value(e) as i64 + rel.r_addend.get(e)) as u64;
                        if let Some(section_address) =
                            object.section_resolutions[section_index.0].address()
                        {
                            if object
                                .object
                                .section(section_index)?
                                .sh_size
                                .get(LittleEndian)
                                != 0
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
                                    let frame_ptr = (section_address + offset_in_section) as i64
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
                apply_relocation::<A>(
                    object,
                    rel_offset - input_pos as u64,
                    rel,
                    SectionInfo {
                        section_address: output_pos as u64 + table_writer.eh_frame_start_address,
                        is_writable: false,
                        section_flags,
                    },
                    layout,
                    entry_out,
                    table_writer,
                    trace,
                    &[],
                    0,
                )
                .with_context(|| {
                    format!(
                        "Failed to apply eh_frame {}",
                        display_relocation::<A>(object, rel, layout)
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

fn display_relocation<'a, A: Arch>(
    object: &'a ObjectLayout,
    rel: &'a elf::Rela,
    layout: &'a Layout,
) -> DisplayRelocation<'a, A> {
    DisplayRelocation::<'a, A> {
        rel,
        symbol_db: &layout.symbol_db,
        object,
        phantom: PhantomData,
    }
}

struct DisplayRelocation<'a, A: Arch> {
    rel: &'a elf::Rela,
    symbol_db: &'a SymbolDb<'a>,
    object: &'a ObjectLayout<'a>,
    phantom: PhantomData<A>,
}

impl<A: Arch> Display for DisplayRelocation<'_, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let e = LittleEndian;
        write!(
            f,
            "relocation of type {} to ",
            A::rel_type_to_string(self.rel.r_type(e, false))
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

#[derive(Clone, Copy)]
struct SectionInfo {
    section_address: u64,
    is_writable: bool,
    section_flags: SectionFlags,
}

fn get_resolution(
    rel: &elf::Rela,
    object_layout: &ObjectLayout,
    layout: &Layout,
) -> Result<(Resolution, SymbolIndex, SymbolId)> {
    let symbol_index = rel
        .symbol(LittleEndian, false)
        .context("Unsupported absolute relocation")?;
    let local_symbol_id = object_layout.symbol_id_range.input_to_id(symbol_index);
    let sym = object_layout.object.symbol(symbol_index)?;
    let section_index = object_layout.object.symbol_section(sym, symbol_index)?;
    let resolution = layout
        .merged_symbol_resolution(local_symbol_id)
        // TODO: the fallback should be likely only used for the debug relocations
        .or_else(|| {
            section_index.and_then(|section_index| {
                object_layout.section_resolutions[section_index.0].full_resolution()
            })
        })
        .with_context(|| {
            format!(
                "Missing resolution for: {}",
                layout.symbol_db.symbol_debug(local_symbol_id)
            )
        })?;
    Ok((resolution, symbol_index, local_symbol_id))
}

fn write_got_plt_syms(
    layout: &Layout,
    symbol_writer: &mut SymbolTableWriter<'_, '_>,
    symbol_id: SymbolId,
) -> Result {
    if !layout.symbol_db.is_canonical(symbol_id) {
        return Ok(());
    }

    let Some(resolution) = layout.local_symbol_resolution(symbol_id) else {
        return Ok(());
    };

    if !resolution.resolution_flags.needs_got() {
        return Ok(());
    }

    let current_res_flags = resolution.resolution_flags;

    let mut write_sym = |suffix: &[u8],
                         section_id: OutputSectionId,
                         get_value: fn(&Resolution) -> Result<u64>|
     -> Result {
        let mut symbol_name = layout.symbol_db.symbol_name(symbol_id)?.to_string();
        symbol_name.push_str(std::str::from_utf8(suffix).unwrap_or("unknown"));

        let shndx = layout
            .output_sections
            .output_index_of_section(section_id)
            .context(format!(
                "Tried to write dynamic symbol in {section_id} section that's not being output"
            ))?;

        let value = get_value(resolution)?;

        symbol_writer
            .define_symbol(true, shndx, value, 0, symbol_name.as_bytes())
            .with_context(|| {
                format!(
                    "Failed to copy {} symbol for {}",
                    std::str::from_utf8(suffix).unwrap_or("unknown"),
                    layout.symbol_debug(symbol_id)
                )
            })?;

        Ok(())
    };

    write_sym(b"$got", output_section_id::GOT, Resolution::got_address)?;
    if current_res_flags.needs_plt() {
        write_sym(b"$plt", output_section_id::PLT_GOT, Resolution::plt_address)?;
    }

    Ok(())
}

/// Adjust relocation value based on the actual value at the place of a relocation.
fn adjust_relocation_based_on_value(
    value: u64,
    rel_info: &RelocationKindInfo,
    out: &[u8],
    offset_in_section: usize,
) -> Result<u64> {
    const LOW6_MASK: u64 = 0b0011_1111;

    let mut read_data = [0u8; 8];
    let RelocationSize::ByteSize(rel_size) = rel_info.size else {
        bail!("Unexpected size for the addition/subtraction relocation");
    };
    // Read only N bytes from the current value based on the size of the relocation.
    read_data[..rel_size].copy_from_slice(&out[offset_in_section..offset_in_section + rel_size]);
    let current_value = u64::from_le_bytes(read_data);

    // Handle addition and subtraction relocation kinds.
    match rel_info.kind {
        RelocationKind::AbsoluteSetWord6 => {
            // Preserve the 2 most significant bits of u8.
            let value = value & LOW6_MASK;
            Ok(value | (current_value & !LOW6_MASK))
        }
        RelocationKind::AbsoluteAddition => Ok(current_value.wrapping_add(value)),
        RelocationKind::AbsoluteSubtraction => Ok(current_value.wrapping_sub(value)),
        RelocationKind::AbsoluteSubtractionWord6 => {
            // Preserve the 2 most significant bits of u8.
            let value = (current_value & LOW6_MASK).wrapping_sub(value & LOW6_MASK) & LOW6_MASK;
            Ok(value | (current_value & !LOW6_MASK))
        }
        _ => Err(error!("Unexpected relocation: {:?}", rel_info)),
    }
}

#[inline(always)]
fn get_pair_subtraction_relocation_value<'a, A: Arch>(
    object_layout: &ObjectLayout,
    rel: &elf::Rela,
    layout: &Layout,
    resolution: Resolution,
    symbol_index: SymbolIndex,
    addend: i64,
    mut relocations_to_search: impl Iterator<Item = &'a elf::Rela>,
) -> Result<u64> {
    let e = LittleEndian;
    let set_rel = relocations_to_search
        .next()
        .with_context(|| "Missing previous relocation".to_string())?;
    ensure!(
        set_rel.r_offset(e) == rel.r_offset(e),
        "R_RISCV_SET_ULEB128 relocation must have equal offset"
    );
    ensure!(
        set_rel.r_type(LittleEndian, false) == object::elf::R_RISCV_SET_ULEB128,
        "R_RISCV_SET_ULEB128 must be the previous relocation"
    );
    let (set_resolution, set_symbol_index, _) = get_resolution(set_rel, object_layout, layout)?;

    let set_resolution_val = set_resolution.value_with_addend(
        set_rel.r_addend.get(e),
        set_symbol_index,
        object_layout,
        &layout.merged_strings,
        &layout.merged_string_start_addresses,
    )?;
    let sub_resolution_val = resolution.value_with_addend(
        addend,
        symbol_index,
        object_layout,
        &layout.merged_strings,
        &layout.merged_string_start_addresses,
    )?;
    Ok(set_resolution_val.wrapping_sub(sub_resolution_val))
}

/// Applies the relocation `rel` at `offset_in_section`, where the section bytes are `out`. See "ELF
/// Handling For Thread-Local Storage" for details about some of the TLS-related relocations and
/// transformations that are applied.
#[inline(always)]
fn apply_relocation<A: Arch>(
    object_layout: &ObjectLayout,
    mut offset_in_section: u64,
    rel: &elf::Rela,
    section_info: SectionInfo,
    layout: &Layout,
    out: &mut [u8],
    table_writer: &mut TableWriter,
    trace: &TraceOutput,
    relocations: &[elf::Rela],
    relocation_index: usize,
) -> Result<RelocationModifier> {
    let section_address = section_info.section_address;
    let original_place = section_address + offset_in_section;
    let _span = tracing::trace_span!(
        "relocation",
        address = original_place,
        address_hex = %HexU64::new(original_place)
    )
    .entered();

    let e = LittleEndian;
    let r_type = rel.r_type(e, false);
    let mut addend = rel.r_addend.get(e);

    match A::relocation_from_raw(r_type)?.kind {
        RelocationKind::None => return Ok(RelocationModifier::Normal),
        RelocationKind::Alignment => {
            let addend = addend as u64;
            let address = section_address + rel.r_offset(e);
            ensure!(
                addend.is_power_of_two(),
                "A power of 2 expected for Alignment relocation: {}",
                addend
            );
            // Must be aligned to N-bytes, where N is the smallest power of two
            // that is greater than the value of the addend field.
            let expected_alignment = addend.next_power_of_two();
            ensure!(
                addend.is_multiple_of(expected_alignment),
                "Unsatisfied alignment ({expected_alignment} bytes) at address: {}",
                HexU64::new(address)
            );
            return Ok(RelocationModifier::Normal);
        }
        _ => {}
    }

    let (resolution, symbol_index, local_symbol_id) = get_resolution(rel, object_layout, layout)?;
    let value_flags = resolution.value_flags;
    let resolution_flags = resolution.resolution_flags;
    let mut next_modifier = RelocationModifier::Normal;
    let rel_info;
    let output_kind = layout.args().output_kind();

    let relaxation = A::Relaxation::new(
        r_type,
        out,
        offset_in_section,
        value_flags,
        output_kind,
        section_info.section_flags,
        resolution.raw_value != 0,
    )
    .filter(|relaxation| layout.args().relax || relaxation.is_mandatory());

    if let Some(relaxation) = &relaxation {
        rel_info = relaxation.rel_info();
        relaxation.apply(out, &mut offset_in_section, &mut addend);
        next_modifier = relaxation.next_modifier();
    } else {
        rel_info = A::relocation_from_raw(r_type)?;
    }

    // Compute place to which IP-relative relocations will be relative. This is different to
    // `original_place` in that our `offset_in_section` may have been adjusted by a relaxation.
    let place = section_address + offset_in_section;

    let mask = get_page_mask(rel_info.mask);
    let mut value = match rel_info.kind {
        RelocationKind::Absolute => {
            assert!(rel_info.mask.is_none());
            write_absolute_relocation::<A>(
                table_writer,
                resolution,
                place,
                addend,
                section_info,
                symbol_index,
                object_layout,
                layout,
            )?
        }
        RelocationKind::AbsoluteSet
        | RelocationKind::AbsoluteSetWord6
        | RelocationKind::AbsoluteAddition
        | RelocationKind::AbsoluteSubtraction
        | RelocationKind::AbsoluteSubtractionWord6 => resolution.value_with_addend(
            addend,
            symbol_index,
            object_layout,
            &layout.merged_strings,
            &layout.merged_string_start_addresses,
        )?,
        RelocationKind::AbsoluteAArch64 => resolution
            .value_with_addend(
                addend,
                symbol_index,
                object_layout,
                &layout.merged_strings,
                &layout.merged_string_start_addresses,
            )?
            .bitand(mask.symbol_plus_addend),
        RelocationKind::Relative => resolution
            .value_with_addend(
                addend,
                symbol_index,
                object_layout,
                &layout.merged_strings,
                &layout.merged_string_start_addresses,
            )?
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::RelativeRiscVLow12 => {
            // The iterator is used for e.g. R_RISCV_PCREL_HI20 & R_RISCV_PCREL_LO12_I pair of relocations where the later
            // one actually points to a label of the HI20 relocations and thus we need to find it. The relocation is typically
            // right before the LO12_* relocation.
            ensure!(
                addend == 0,
                "Unexpected added for R_RISCV_PCREL_LO12 relocation"
            );
            let mut relocations_to_search = relocations[..relocation_index]
                .iter()
                .rev()
                .chain(relocations[relocation_index + 1..].iter());
            let hi_offset_in_section = resolution
                .value_with_addend(
                    addend,
                    symbol_index,
                    object_layout,
                    &layout.merged_strings,
                    &layout.merged_string_start_addresses,
                )?
                .wrapping_sub(section_address);
            // The High-part relocation is typically just before us.
            let hi_rel = relocations_to_search
                .find(|r| {
                    r.r_offset(e) == hi_offset_in_section
                        // RELAX relocations have the same offset as the HIGH part relocation!
                        && r.r_type(e, false) != object::elf::R_RISCV_RELAX
                })
                .with_context(|| {
                    "Missing High relocation connected with R_RISCV_PCREL_LO12".to_string()
                })?;
            let hi_rel_info = A::relocation_from_raw(hi_rel.r_type(LittleEndian, false))?;
            let addend = hi_rel.r_addend.get(e);
            let (resolution, symbol_index, _) = get_resolution(hi_rel, object_layout, layout)
                .with_context(|| {
                    "Missing High resolution connected to R_RISCV_PCREL_LO12".to_string()
                })?;
            let place = section_address + hi_offset_in_section;

            // Only a subset of relocations is referenced by R_RISCV_PCREL_LO12 relocations.
            match hi_rel_info.kind {
                RelocationKind::Relative => resolution
                    .value_with_addend(
                        addend,
                        symbol_index,
                        object_layout,
                        &layout.merged_strings,
                        &layout.merged_string_start_addresses,
                    )?
                    .wrapping_sub(place),
                RelocationKind::GotRelative => resolution
                    .got_address()?
                    .wrapping_add(addend as u64)
                    .wrapping_sub(place),
                RelocationKind::TlsGd => resolution
                    .tlsgd_got_address()?
                    .wrapping_add(addend as u64)
                    .wrapping_sub(place),
                RelocationKind::TlsLd => layout
                    .prelude()
                    .tlsld_got_entry
                    .unwrap()
                    .get()
                    .wrapping_add(addend as u64)
                    .wrapping_sub(place),
                RelocationKind::GotTpOff => resolution
                    .got_address()?
                    .wrapping_add(addend as u64)
                    .wrapping_sub(place),
                _ => bail!(
                    "Unsupported high part relocation {:?} connected with R_RISCV_PCREL_LO12",
                    hi_rel_info.kind
                ),
            }
        }
        RelocationKind::PairSubtraction => get_pair_subtraction_relocation_value::<A>(
            object_layout,
            rel,
            layout,
            resolution,
            symbol_index,
            addend,
            // It must be the previous relocation
            iter::once(&relocations[relocation_index - 1]),
        )?,
        RelocationKind::GotRelative => resolution
            .got_address()?
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::GotRelGotBase => resolution
            .got_address()?
            .bitand(mask.got_entry)
            .wrapping_sub(layout.got_base().bitand(mask.got))
            .wrapping_add(addend as u64),
        RelocationKind::Got => resolution
            .got_address()?
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64),
        RelocationKind::SymRelGotBase => resolution
            .value_with_addend(
                addend,
                symbol_index,
                object_layout,
                &layout.merged_strings,
                &layout.merged_string_start_addresses,
            )?
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(layout.got_base().bitand(mask.got)),
        RelocationKind::PltRelGotBase => resolution
            .plt_address()?
            .wrapping_sub(layout.got_base().bitand(mask.got)),
        RelocationKind::PltRelative => resolution
            .plt_address()?
            .wrapping_add(addend as u64)
            .wrapping_sub(place.bitand(mask.place)),
        // TLS-related relocations
        RelocationKind::TlsGd => resolution
            .tlsgd_got_address()?
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::TlsGdGot => resolution
            .tlsgd_got_address()?
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64),
        RelocationKind::TlsGdGotBase => resolution
            .tlsgd_got_address()?
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64)
            .wrapping_sub(layout.got_base().bitand(mask.got)),
        RelocationKind::TlsLd => layout
            .prelude()
            .tlsld_got_entry
            .unwrap()
            .get()
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::TlsLdGot => layout
            .prelude()
            .tlsld_got_entry
            .unwrap()
            .get()
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64),
        RelocationKind::TlsLdGotBase => layout
            .prelude()
            .tlsld_got_entry
            .unwrap()
            .get()
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64)
            .wrapping_sub(layout.got_base().bitand(mask.got)),
        RelocationKind::DtpOff if output_kind == OutputKind::SharedObject => resolution
            .value()
            .sub(layout.tls_start_address())
            .wrapping_add(addend as u64),
        RelocationKind::DtpOff => resolution
            .value()
            .wrapping_sub(layout.tls_end_address())
            .wrapping_add(addend as u64),
        RelocationKind::GotTpOff => resolution
            .got_address()?
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::GotTpOffGot => resolution
            .got_address()?
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64),
        RelocationKind::GotTpOffGotBase => resolution
            .got_address()?
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64)
            .wrapping_sub(layout.got_base().bitand(mask.got)),
        RelocationKind::TpOff => resolution
            .value()
            .wrapping_sub(A::tp_offset_start(layout))
            .wrapping_add(addend as u64),
        RelocationKind::TlsDesc => resolution
            .tls_descriptor_got_address()?
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::TlsDescGot => resolution
            .tls_descriptor_got_address()?
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64),
        RelocationKind::TlsDescGotBase => resolution
            .tls_descriptor_got_address()?
            .bitand(mask.got_entry)
            .wrapping_add(addend as u64)
            .wrapping_sub(layout.got_base().bitand(mask.got)),
        RelocationKind::None | RelocationKind::TlsDescCall => 0,
        RelocationKind::Alignment => unreachable!(),
    };

    let offset_in_section = offset_in_section as usize;

    // Handle addition and subtraction relocation kinds.
    if matches!(
        rel_info.kind,
        RelocationKind::AbsoluteAddition
            | RelocationKind::AbsoluteSubtraction
            | RelocationKind::AbsoluteSetWord6
            | RelocationKind::AbsoluteSubtractionWord6
    ) {
        value = adjust_relocation_based_on_value(value, &rel_info, out, offset_in_section)?;
    }

    if let Some(relaxation) = relaxation {
        trace.emit(original_place, || {
            format!(
                "relaxation applied relaxation={kind:?}, value_flags={value_flags},\n\
                resolution_flags={resolution_flags}, rel_kind={rel_kind:?},\n\
                value=0x{value:x}, symbol_name={symbol_name}",
                kind = relaxation.debug_kind(),
                rel_kind = rel_info.kind,
                symbol_name = layout.symbol_db.symbol_name_for_display(local_symbol_id),
            )
        });
        tracing::trace!(
            %value_flags,
            %resolution_flags,
            relaxation_kind = ?relaxation.debug_kind(),
            ?rel_info.kind,
            %rel_info.size,
            value,
            value_hex = %HexU64::new(value),
            symbol_name = %layout.symbol_db.symbol_name_for_display(local_symbol_id),
            "relaxation applied");
    } else {
        trace.emit(original_place, || {
            format!(
                "relocation applied value_flags={value_flags},\n\
                resolution_flags={resolution_flags}, rel_kind={rel_kind:?},\n\
                value=0x{value:x}, symbol_name={symbol_name}",
                rel_kind = rel_info.kind,
                symbol_name = layout.symbol_db.symbol_name_for_display(local_symbol_id),
            )
        });
        tracing::trace!(
            %value_flags,
            %resolution_flags,
            ?rel_info.kind,
            %rel_info.size,
            value,
            value_hex = %HexU64::new(value),
            symbol_name = %layout.symbol_db.symbol_name_for_display(local_symbol_id),
            "relocation applied");
    }

    write_relocation_to_buffer(rel_info, value, &mut out[offset_in_section..])?;

    Ok(next_modifier)
}

fn apply_debug_relocation<A: Arch>(
    object_layout: &ObjectLayout,
    offset_in_section: u64,
    rel: &elf::Rela,
    layout: &Layout,
    section_tombstone_value: u64,
    out: &mut [u8],
    relocations: &[elf::Rela],
    relocation_index: usize,
) -> Result<()> {
    let e = LittleEndian;
    let symbol_index = rel
        .symbol(e, false)
        .context("Unsupported absolute relocation")?;
    let sym = object_layout.object.symbol(symbol_index)?;
    let section_index = object_layout.object.symbol_section(sym, symbol_index)?;

    let addend = rel.r_addend.get(e);
    let r_type = rel.r_type(e, false);
    let rel_info = A::relocation_from_raw(r_type)?;

    let resolution = layout
        .merged_symbol_resolution(object_layout.symbol_id_range.input_to_id(symbol_index))
        .or_else(|| {
            section_index.and_then(|section_index| {
                object_layout.section_resolutions[section_index.0].full_resolution()
            })
        });

    let value = if let Some(resolution) = resolution {
        match rel_info.kind {
            RelocationKind::Absolute
            | RelocationKind::AbsoluteSet
            | RelocationKind::AbsoluteSetWord6
            | RelocationKind::AbsoluteAddition
            | RelocationKind::AbsoluteSubtraction
            | RelocationKind::AbsoluteSubtractionWord6 => {
                let mut value = resolution.value_with_addend(
                    addend,
                    symbol_index,
                    object_layout,
                    &layout.merged_strings,
                    &layout.merged_string_start_addresses,
                )?;
                // Adjust the relocation value based on the value at the place.
                if matches!(
                    rel_info.kind,
                    RelocationKind::AbsoluteAddition
                        | RelocationKind::AbsoluteSubtraction
                        | RelocationKind::AbsoluteSetWord6
                        | RelocationKind::AbsoluteSubtractionWord6
                ) {
                    value = adjust_relocation_based_on_value(
                        value,
                        &rel_info,
                        out,
                        offset_in_section as usize,
                    )?;
                }
                value
            }
            RelocationKind::DtpOff => resolution
                .value()
                .wrapping_sub(layout.tls_end_address())
                .wrapping_add(addend as u64),
            RelocationKind::PairSubtraction => get_pair_subtraction_relocation_value::<A>(
                object_layout,
                rel,
                layout,
                resolution,
                symbol_index,
                addend,
                // Must be the previous relocation.
                iter::once(&relocations[relocation_index - 1]),
            )?,
            // Skip R_RISCV_SET_ULEB128
            RelocationKind::Relative if rel_info.size == RelocationSize::ByteSize(0) => 0,
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
        // Debug info can sometimes contain relocations for symbols from other objects. If we didn't
        // load those symbols, then we need to use the tombstone value. Careful, we don't have any
        // tests for this, but building chromium does trigger this branch.
        section_tombstone_value
    };

    write_relocation_to_buffer(rel_info, value, &mut out[offset_in_section as usize..])?;

    Ok(())
}

#[inline(always)]
fn write_absolute_relocation<A: Arch>(
    table_writer: &mut TableWriter,
    resolution: Resolution,
    place: u64,
    addend: i64,
    section_info: SectionInfo,
    symbol_index: object::SymbolIndex,
    object_layout: &ObjectLayout,
    layout: &Layout,
) -> Result<u64> {
    if resolution.value_flags.is_interposable() && section_info.is_writable {
        table_writer.write_dynamic_symbol_relocation::<A>(
            place,
            addend,
            resolution.dynamic_symbol_index()?,
            DynamicRelocationKind::Absolute,
        )?;

        Ok(0)
    } else if table_writer.output_kind.is_relocatable() && !resolution.is_absolute() {
        let address = resolution.value_with_addend(
            addend,
            symbol_index,
            object_layout,
            &layout.merged_strings,
            &layout.merged_string_start_addresses,
        )?;

        table_writer.write_address_relocation::<A>(place, address as i64)?;

        Ok(0)
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

fn write_prelude<A: Arch>(
    prelude: &PreludeLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter,
    layout: &Layout,
) -> Result {
    let header: &mut FileHeader = from_bytes_mut(buffers.get_mut(part_id::FILE_HEADER))
        .map_err(|_| error!("Invalid file header allocation"))?
        .0;
    populate_file_header::<A>(layout, &prelude.header_info, header)?;

    let mut program_headers = ProgramHeaderWriter::new(buffers.get_mut(part_id::PROGRAM_HEADERS));
    write_program_headers(&mut program_headers, layout)?;

    write_section_headers(buffers.get_mut(part_id::SECTION_HEADERS), layout)?;

    write_section_header_strings(
        buffers.get_mut(part_id::SHSTRTAB),
        &layout.output_sections,
        &layout.output_order,
    );

    write_plt_got_entries::<A>(prelude, layout, table_writer)?;

    if !layout.args().strip_all {
        write_symbol_table_entries(prelude, &mut table_writer.debug_symbol_writer, layout)?;
    }

    if layout.args().should_write_eh_frame_hdr {
        write_eh_frame_hdr(table_writer, layout)?;
    }

    write_merged_strings(prelude, buffers, layout);

    write_interp(prelude, buffers);

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

fn write_interp(prelude: &PreludeLayout, buffers: &mut OutputSectionPartMap<&mut [u8]>) {
    if let Some(dynamic_linker) = prelude.dynamic_linker.as_ref() {
        buffers
            .get_mut(part_id::INTERP)
            .copy_from_slice(dynamic_linker.as_bytes_with_nul());
    }
}

fn write_merged_strings(
    prelude: &PreludeLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &Layout,
) {
    layout.merged_strings.for_each(|section_id, merged| {
        if merged.len() > 0 {
            let buffer = buffers.get_mut(section_id.part_id_with_alignment(crate::alignment::MIN));

            merged
                .buckets
                .iter()
                .map(|b| (b, slice_take_prefix_mut(buffer, b.len())))
                .par_bridge()
                .for_each(|(bucket, mut buffer)| {
                    for string in &bucket.strings {
                        let dest = crate::slice::slice_take_prefix_mut(&mut buffer, string.len());
                        dest.copy_from_slice(string);
                    }
                });
        }
    });

    // Write linker identity into .comment section.
    let comment_buffer =
        buffers.get_mut(output_section_id::COMMENT.part_id_with_alignment(alignment::MIN));
    crate::slice::slice_take_prefix_mut(comment_buffer, prelude.identity.len())
        .copy_from_slice(prelude.identity.as_bytes());
}

fn write_plt_got_entries<A: Arch>(
    prelude: &PreludeLayout,
    layout: &Layout,
    table_writer: &mut TableWriter,
) -> Result {
    // Write a pair of GOT entries for use by any TLSLD or TLSGD relocations.
    if let Some(got_address) = prelude.tlsld_got_entry {
        let mut raw_value = 0;

        if layout.args().output_kind().is_executable() {
            table_writer.process_resolution::<A>(
                Some(layout),
                &Resolution {
                    raw_value: crate::elf::CURRENT_EXE_TLS_MOD,
                    dynamic_symbol_index: None,
                    got_address: Some(got_address),
                    plt_address: None,
                    resolution_flags: ResolutionFlags::GOT,
                    value_flags: ValueFlags::ABSOLUTE,
                },
            )?;

            // For executables, DTPOFF values are negative values relative to the thread pointer,
            // which is at the end of the TLS segment.
            raw_value = A::tp_offset_start(layout) - layout.tls_start_address();
        } else {
            table_writer.take_next_got_entry()?;
            table_writer.write_dtpmod_relocation::<A>(got_address.get(), 0)?;
        }

        table_writer.process_resolution::<A>(
            Some(layout),
            &Resolution {
                raw_value,
                dynamic_symbol_index: None,
                got_address: Some(got_address.saturating_add(elf::GOT_ENTRY_SIZE)),
                plt_address: None,
                resolution_flags: ResolutionFlags::GOT,
                value_flags: ValueFlags::ABSOLUTE,
            },
        )?;
    }

    write_internal_symbols_plt_got_entries::<A>(&prelude.internal_symbols, table_writer, layout)?;
    Ok(())
}

fn write_symbol_table_entries(
    prelude: &PreludeLayout,
    symbol_writer: &mut SymbolTableWriter,
    layout: &Layout,
) -> Result {
    // Define symbol 0. This needs to be a null placeholder.
    symbol_writer.define_symbol(true, 0, 0, 0, &[])?;

    let internal_symbols = &prelude.internal_symbols;

    write_internal_symbols(internal_symbols, layout, symbol_writer)?;
    Ok(())
}

fn write_verdef(
    verdefs: &[VersionDef],
    table_writer: &mut TableWriter,
    soname: Option<&[u8]>,
    epilogue_offsets: &EpilogueOffsets,
) -> Result {
    let e = LittleEndian;

    // Offsets of version strings, except the base version
    let mut version_string_offsets = Vec::with_capacity(verdefs.len() - 1);

    for (i, verdef) in verdefs.iter().enumerate() {
        let verdef_out = table_writer.version_writer.take_verdef()?;

        // Base version may use (already allocated) soname
        let (name, name_offset) = if i == 0 {
            if let Some(soname) = soname {
                (
                    soname,
                    epilogue_offsets
                        .soname
                        .expect("Soname offset must be present at this point"),
                )
            } else {
                let offset = table_writer
                    .dynsym_writer
                    .strtab_writer
                    .write_str(&verdef.name);
                (verdef.name.as_slice(), offset)
            }
        } else {
            let offset = table_writer
                .dynsym_writer
                .strtab_writer
                .write_str(&verdef.name);
            version_string_offsets.push(offset);
            (verdef.name.as_slice(), offset)
        };

        verdef_out.vd_version.set(e, object::elf::VER_DEF_CURRENT);
        // Mark first entry as base version
        verdef_out
            .vd_flags
            .set(e, if i == 0 { object::elf::VER_FLG_BASE } else { 0 });
        verdef_out
            .vd_ndx
            .set(e, i as u16 + object::elf::VER_NDX_GLOBAL);
        let aux_count = if verdef.parent_index.is_some() { 2 } else { 1 };
        verdef_out.vd_cnt.set(e, aux_count);
        verdef_out.vd_hash.set(e, object::elf::hash(name));
        verdef_out
            .vd_aux
            .set(e, size_of::<crate::elf::Verdef>() as u32);
        // Offset to the next entry, unless it's the last one
        if i < verdefs.len() - 1 {
            let offset = (size_of::<crate::elf::Verdef>()
                + size_of::<crate::elf::Verdaux>() * aux_count as usize)
                as u32;
            verdef_out.vd_next.set(e, offset);
        };

        let verdaux = table_writer.version_writer.take_verdaux()?;
        verdaux.vda_name.set(e, name_offset);
        let next_vda = if verdef.parent_index.is_some() {
            size_of::<crate::elf::Verdaux>() as u32
        } else {
            0
        };
        verdaux.vda_next.set(e, next_vda);

        if let Some(parent_index) = &verdef.parent_index {
            let name_offset = *version_string_offsets
                .get(*parent_index as usize - 1)
                .unwrap();
            let verdaux = table_writer.version_writer.take_verdaux()?;
            verdaux.vda_name.set(e, name_offset);
            verdaux.vda_next.set(e, 0);
        }
    }

    Ok(())
}

fn write_epilogue_dynamic_entries(
    layout: &Layout,
    table_writer: &mut TableWriter,
    epilogue_offsets: &mut EpilogueOffsets,
) -> Result {
    if let Some(rpath) = &layout.args().rpath {
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
        epilogue_offsets.soname.replace(offset);
    }

    let inputs = DynamicEntryInputs {
        args: layout.args(),
        has_static_tls: layout.has_static_tls,
        section_layouts: &layout.section_layouts,
        section_part_layouts: &layout.section_part_layouts,
        non_addressable_counts: layout.non_addressable_counts,
    };

    for writer in EPILOGUE_DYNAMIC_ENTRY_WRITERS {
        writer.write(&mut table_writer.dynamic, &inputs)?;
    }

    Ok(())
}

#[derive(Default)]
pub(crate) struct EpilogueOffsets {
    /// The offset of the shared object name in .dynsym.
    pub(crate) soname: Option<u32>,
}

fn write_linker_script_state<A: Arch>(
    script: &LinkerScriptLayoutState,
    table_writer: &mut TableWriter,
    layout: &Layout,
) -> Result {
    write_internal_symbols(
        &script.internal_symbols,
        layout,
        &mut table_writer.debug_symbol_writer,
    )?;

    write_internal_symbols_plt_got_entries::<A>(&script.internal_symbols, table_writer, layout)?;

    Ok(())
}

fn write_epilogue<A: Arch>(
    epilogue: &EpilogueLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter,
    layout: &Layout,
) -> Result {
    let mut epilogue_offsets = EpilogueOffsets::default();

    write_internal_symbols_plt_got_entries::<A>(&epilogue.internal_symbols, table_writer, layout)?;

    if !layout.args().strip_all {
        write_internal_symbols(
            &epilogue.internal_symbols,
            layout,
            &mut table_writer.debug_symbol_writer,
        )?;
    }
    if layout.args().needs_dynamic() {
        write_epilogue_dynamic_entries(layout, table_writer, &mut epilogue_offsets)?;
    }
    write_gnu_hash_tables(epilogue, buffers)?;

    write_dynamic_symbol_definitions(epilogue, table_writer, layout)?;

    if !&epilogue.gnu_property_notes.is_empty() {
        write_gnu_property_notes(epilogue, buffers)?;
    }
    if !&epilogue.riscv_attributes.is_empty() {
        write_riscv_attributes(epilogue, buffers)?;
    }

    if let Some(verdefs) = &epilogue.verdefs {
        write_verdef(
            verdefs,
            table_writer,
            layout.args().soname.as_ref().map(|s| s.as_bytes()),
            &epilogue_offsets,
        )?;
    }

    Ok(())
}

fn write_gnu_property_notes(
    epilogue: &EpilogueLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let e = LittleEndian;
    let (note_header, mut rest) =
        from_bytes_mut::<NoteHeader>(buffers.get_mut(part_id::NOTE_GNU_PROPERTY))
            .map_err(|_| error!("Insufficient .note.gnu.property allocation"))?;
    note_header.n_namesz.set(e, GNU_NOTE_NAME.len() as u32);
    note_header.n_descsz.set(
        e,
        (epilogue.gnu_property_notes.len() * GNU_NOTE_PROPERTY_ENTRY_SIZE) as u32,
    );
    note_header.n_type.set(e, NT_GNU_PROPERTY_TYPE_0);

    let name_out = crate::slice::slice_take_prefix_mut(&mut rest, GNU_NOTE_NAME.len());
    name_out.copy_from_slice(GNU_NOTE_NAME);

    for note in &epilogue.gnu_property_notes {
        let entry_bytes = crate::slice::slice_take_prefix_mut(&mut rest, size_of::<NoteProperty>());
        let property: &mut NoteProperty = bytemuck::from_bytes_mut(entry_bytes);
        property.pr_type = note.ptype;
        property.pr_datasz = size_of_val(&property.pr_data) as u32;
        property.pr_data = note.data;
        property.pr_padding = 0;
    }

    Ok(())
}

fn write_riscv_attributes(
    epilogue: &EpilogueLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let mut writer = Cursor::new(&mut **buffers.get_mut(part_id::RISCV_ATTRIBUTES));
    writer.write_all(b"A")?;
    writer.write_all(
        (epilogue.riscv_attributes_length - 1)
            .to_le_bytes()
            .as_slice(),
    )?;
    writer.write_all(RISCV_ATTRIBUTE_VENDOR_NAME.as_bytes())?;
    writer.write_all(b"\0")?;
    leb128::write::unsigned(&mut writer, TAG_RISCV_WHOLE_FILE)?;
    writer.write_all(
        (epilogue.riscv_attributes_length - 1 - 4 - RISCV_ATTRIBUTE_VENDOR_NAME.len() as u32 - 1)
            .to_le_bytes()
            .as_slice(),
    )?;
    for tag in &epilogue.riscv_attributes {
        match tag {
            &RiscVAttribute::StackAlign(align) => {
                leb128::write::unsigned(&mut writer, TAG_RISCV_STACK_ALIGN)?;
                leb128::write::unsigned(&mut writer, align)?;
            }
            RiscVAttribute::Arch(arch) => {
                leb128::write::unsigned(&mut writer, TAG_RISCV_ARCH)?;
                writer.write_all(arch.to_attribute_string().as_bytes())?;
                writer.write_all(b"\0")?;
            }
            &RiscVAttribute::UnalignedAccess(access) => {
                leb128::write::unsigned(&mut writer, TAG_RISCV_UNALIGNED_ACCESS)?;
                leb128::write::unsigned(&mut writer, u64::from(access))?;
            }
            &RiscVAttribute::PrivilegedSpecMajor(version) => {
                leb128::write::unsigned(&mut writer, TAG_RISCV_PRIV_SPEC)?;
                leb128::write::unsigned(&mut writer, version)?;
            }
            &RiscVAttribute::PrivilegedSpecMinor(version) => {
                leb128::write::unsigned(&mut writer, TAG_RISCV_PRIV_SPEC_MINOR)?;
                leb128::write::unsigned(&mut writer, version)?;
            }
            &RiscVAttribute::PrivilegedSpecRevision(version) => {
                leb128::write::unsigned(&mut writer, TAG_RISCV_PRIV_SPEC_REVISION)?;
                leb128::write::unsigned(&mut writer, version)?;
            }
        }
    }

    Ok(())
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
            .map_err(|_| error!("Insufficient .gnu.hash allocation"))?;
    let e = LittleEndian;
    header.bucket_count.set(e, gnu_hash_layout.bucket_count);
    header.bloom_shift.set(e, gnu_hash_layout.bloom_shift);
    header.bloom_count.set(e, gnu_hash_layout.bloom_count);
    header.symbol_base.set(e, gnu_hash_layout.symbol_base);

    let (bloom, rest) =
        object::slice_from_bytes_mut::<u64>(rest, gnu_hash_layout.bloom_count as usize)
            .map_err(|_| error!("Insufficient bytes for .gnu.hash bloom filter"))?;
    let (buckets, rest) =
        object::slice_from_bytes_mut::<u32>(rest, gnu_hash_layout.bucket_count as usize)
            .map_err(|_| error!("Insufficient bytes for .gnu.hash buckets"))?;
    let (chains, _) =
        object::slice_from_bytes_mut::<u32>(rest, epilogue.dynamic_symbol_definitions.len())
            .map_err(|_| error!("Insufficient bytes for .gnu.hash chains"))?;

    bloom.fill(0);

    let mut sym_defs = epilogue.dynamic_symbol_definitions.iter().peekable();

    let elf_class_bits = size_of::<u64>() as u32 * 8;

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
            .is_none_or(|next| gnu_hash_layout.bucket_for_hash(next.hash) != bucket);
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

                if let Some(versym) = table_writer.version_writer.versym.as_mut() {
                    if let Some(version_out) = crate::slice::take_first_mut(versym) {
                        // TODO: avoid rehashing
                        let version = layout
                            .symbol_db
                            .version_script
                            .version_for_symbol(&UnversionedSymbolName::prehashed(sym_def.name))
                            .unwrap_or(object::elf::VER_NDX_GLOBAL);
                        version_out.0.set(LittleEndian, version);
                    }
                }
            }
            FileLayout::Dynamic(object) => {
                write_copy_relocation_dynamic_symbol_definition(
                    sym_def,
                    object,
                    layout,
                    &mut table_writer.dynsym_writer,
                )?;

                if let Some(versym) = table_writer.version_writer.versym.as_mut() {
                    write_symbol_version(
                        object.input_symbol_versions,
                        object.symbol_id_range.id_to_offset(sym_def.symbol_id),
                        &object.version_mapping,
                        versym,
                    )?;
                }
            }
            FileLayout::LinkerScript(script) => {
                write_linker_script_dynsym(table_writer, layout, sym_def.symbol_id, script)?;
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

/// Writes a symbol that was produced by a linker script.
fn write_linker_script_dynsym(
    table_writer: &mut TableWriter,
    layout: &Layout,
    symbol_id: SymbolId,
    script: &LinkerScriptLayoutState,
) -> Result {
    let local_index = script
        .internal_symbols
        .symbol_id_range()
        .id_to_offset(symbol_id);

    let info = &script.internal_symbols.symbol_definitions[local_index];

    let section_id = info
        .section_id()
        .context("Tried to export dynamic symbol not associated with a section")?;

    let section_id = layout.output_sections.primary_output_section(section_id);

    let shndx = layout
        .output_sections
        .output_index_of_section(section_id)
        .context("Tried to write dynamic symbol in section that's not being output")?;

    let resolution = layout.local_symbol_resolution(symbol_id).with_context(|| {
        format!(
            "Missing resolution for {}",
            layout.symbol_db.symbol_debug(symbol_id)
        )
    })?;

    let address = resolution.address()?;
    let name = layout.symbol_db.symbol_name(symbol_id)?;

    let entry = table_writer
        .dynsym_writer
        .define_symbol(false, shndx, address, 0, name.bytes())?;

    entry.set_st_info(object::elf::STB_GLOBAL, object::elf::STT_NOTYPE);

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
            .needs_copy_relocation(),
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
            symbol_value -= layout.tls_start_address();
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
    layout: &Layout,
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

        let symbol_name = layout.symbol_db.symbol_name(symbol_id)?;
        let mut shndx = def_info
            .section_id()
            .map(|section_id| {
                let section_id = layout.output_sections.primary_output_section(section_id);

                layout
                    .output_sections
                    .output_index_of_section(section_id)
                    .with_context(|| {
                        format!(
                            "symbol `{}` in section `{}` that we're not going to output {resolution:?}",
                            layout.symbol_db.symbol_name_for_display(symbol_id),
                            layout.output_sections.display_name(section_id)
                        )
                    })
            })
            .transpose()?
            .unwrap_or(0);

        // Move symbols that are in our header (section 0) into the first section, otherwise they'll
        // show up as undefined.
        if shndx == 0 {
            shndx = 1;
        }

        let mut address = resolution.value();

        if def_info.elf_symbol_type == object::elf::STT_TLS {
            address -= layout.tls_start_address();
        }

        // Mandatory RISC-V symbol defined by the default linker script as:
        // __global_pointer$ = MIN(__SDATA_BEGIN__ + 0x800, MAX(__DATA_BEGIN__ + 0x800, __BSS_END__ - 0x800));
        if symbol_name.bytes() == GLOBAL_POINTER_SYMBOL_NAME.as_bytes() {
            address += RISCV_TLS_DTV_OFFSET;
        }

        let entry = symbol_writer
            .define_symbol(false, shndx, address, 0, symbol_name.bytes())
            .with_context(|| format!("Failed to write {}", layout.symbol_debug(symbol_id)))?;

        entry.set_st_info(object::elf::STB_GLOBAL, def_info.elf_symbol_type);
    }
    Ok(())
}

fn write_eh_frame_hdr(table_writer: &mut TableWriter, layout: &Layout) -> Result {
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

fn eh_frame_hdr_entry_count(layout: &Layout) -> Result<u32> {
    let hdr_sec = layout.section_layouts.get(output_section_id::EH_FRAME_HDR);
    u32::try_from(
        (hdr_sec.mem_size - size_of::<elf::EhFrameHdr>() as u64)
            / size_of::<elf::EhFrameHdrEntry>() as u64,
    )
    .context(".eh_frame_hdr entries overflowed 32 bits")
}

/// Returns the address of .eh_frame relative to the location in .eh_frame_hdr where the frame
/// pointer is stored.
fn eh_frame_ptr(layout: &Layout) -> Result<i32> {
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
        |inputs| inputs.has_data_in_section(output_section_id::INIT),
        |inputs| inputs.vma_of_section(output_section_id::INIT),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_FINI,
        |inputs| inputs.has_data_in_section(output_section_id::FINI),
        |inputs| inputs.vma_of_section(output_section_id::FINI),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_INIT_ARRAY,
        |inputs| inputs.has_data_in_section(output_section_id::INIT_ARRAY),
        |inputs| inputs.vma_of_section(output_section_id::INIT_ARRAY),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_INIT_ARRAYSZ,
        |inputs| inputs.has_data_in_section(output_section_id::INIT_ARRAY),
        |inputs| inputs.size_of_section(output_section_id::INIT_ARRAY),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_FINI_ARRAY,
        |inputs| inputs.has_data_in_section(output_section_id::FINI_ARRAY),
        |inputs| inputs.vma_of_section(output_section_id::FINI_ARRAY),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_FINI_ARRAYSZ,
        |inputs| inputs.has_data_in_section(output_section_id::FINI_ARRAY),
        |inputs| inputs.size_of_section(output_section_id::FINI_ARRAY),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_PREINIT_ARRAY,
        |inputs| inputs.has_data_in_section(output_section_id::PREINIT_ARRAY),
        |inputs| inputs.vma_of_section(output_section_id::PREINIT_ARRAY),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_PREINIT_ARRAYSZ,
        |inputs| inputs.has_data_in_section(output_section_id::PREINIT_ARRAY),
        |inputs| inputs.size_of_section(output_section_id::PREINIT_ARRAY),
    ),
    DynamicEntryWriter::new(object::elf::DT_STRTAB, |inputs| {
        inputs.vma_of_section(output_section_id::DYNSTR)
    }),
    DynamicEntryWriter::new(object::elf::DT_STRSZ, |inputs| {
        inputs.size_of_section(output_section_id::DYNSTR)
    }),
    DynamicEntryWriter::new(object::elf::DT_SYMTAB, |inputs| {
        inputs.vma_of_section(output_section_id::DYNSYM)
    }),
    DynamicEntryWriter::new(object::elf::DT_SYMENT, |_inputs| {
        size_of::<elf::SymtabEntry>() as u64
    }),
    DynamicEntryWriter::optional(
        object::elf::DT_VERDEF,
        |inputs| {
            inputs
                .section_part_layouts
                .get(part_id::GNU_VERSION_D)
                .mem_size
                > 0
        },
        |inputs| inputs.vma_of_section(output_section_id::GNU_VERSION_D),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_VERDEFNUM,
        |inputs| {
            inputs
                .section_part_layouts
                .get(part_id::GNU_VERSION_D)
                .mem_size
                > 0
        },
        |inputs| inputs.non_addressable_counts.verdef_count.into(),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_VERNEED,
        |inputs| {
            inputs
                .section_part_layouts
                .get(part_id::GNU_VERSION_R)
                .mem_size
                > 0
        },
        |inputs| inputs.vma_of_section(output_section_id::GNU_VERSION_R),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_VERNEEDNUM,
        |inputs| {
            inputs
                .section_part_layouts
                .get(part_id::GNU_VERSION_R)
                .mem_size
                > 0
        },
        |inputs| inputs.non_addressable_counts.verneed_count,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_VERSYM,
        |inputs| {
            inputs
                .section_part_layouts
                .get(part_id::GNU_VERSION)
                .mem_size
                > 0
        },
        |inputs| inputs.vma_of_section(output_section_id::GNU_VERSION),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_DEBUG,
        |inputs| {
            // Not sure why, but GNU ld seems to emit this for executables but not for shared
            // objects.
            inputs.args.output_kind() != OutputKind::SharedObject
        },
        |_inputs| 0,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_JMPREL,
        |inputs| inputs.section_part_layouts.get(part_id::RELA_PLT).mem_size > 0,
        |inputs| inputs.vma_of_section(output_section_id::RELA_PLT),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_PLTGOT,
        |inputs| inputs.args.needs_dynamic(),
        |inputs| inputs.vma_of_section(output_section_id::GOT),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_PLTREL,
        |inputs| inputs.section_part_layouts.get(part_id::RELA_PLT).mem_size > 0,
        |_| object::elf::DT_RELA.into(),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_PLTRELSZ,
        |inputs| inputs.section_part_layouts.get(part_id::RELA_PLT).mem_size > 0,
        |inputs| inputs.section_part_layouts.get(part_id::RELA_PLT).mem_size,
    ),
    DynamicEntryWriter::optional(object::elf::DT_RELA, has_rela_dyn, |inputs| {
        inputs.vma_of_section(output_section_id::RELA_DYN_RELATIVE)
    }),
    DynamicEntryWriter::optional(object::elf::DT_RELASZ, has_rela_dyn, |inputs| {
        inputs.size_of_section(output_section_id::RELA_DYN_RELATIVE)
            + inputs.size_of_section(output_section_id::RELA_DYN_GENERAL)
    }),
    DynamicEntryWriter::optional(object::elf::DT_RELAENT, has_rela_dyn, |_inputs| {
        elf::RELA_ENTRY_SIZE
    }),
    // Note, rela-count is just the count of the relative relocations and doesn't include any
    // glob-dat relocations. This is as opposed to rela-size, which includes both.
    DynamicEntryWriter::new(object::elf::DT_RELACOUNT, |inputs| {
        inputs
            .section_part_layouts
            .get(part_id::RELA_DYN_RELATIVE)
            .mem_size
            / size_of::<elf::Rela>() as u64
    }),
    DynamicEntryWriter::new(object::elf::DT_GNU_HASH, |inputs| {
        inputs.vma_of_section(output_section_id::GNU_HASH)
    }),
    DynamicEntryWriter::optional(
        object::elf::DT_FLAGS,
        |inputs| inputs.dt_flags() != 0,
        |inputs| inputs.dt_flags(),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_FLAGS_1,
        |inputs| inputs.dt_flags_1() != 0,
        |inputs| inputs.dt_flags_1(),
    ),
    DynamicEntryWriter::new(object::elf::DT_NULL, |_inputs| 0),
];

struct DynamicEntryWriter {
    tag: u32,
    is_present_cb: fn(&DynamicEntryInputs) -> bool,
    cb: fn(&DynamicEntryInputs) -> u64,
}

struct DynamicEntryInputs<'layout> {
    args: &'layout Args,
    has_static_tls: bool,
    section_layouts: &'layout OutputSectionMap<OutputRecordLayout>,
    section_part_layouts: &'layout OutputSectionPartMap<OutputRecordLayout>,
    non_addressable_counts: NonAddressableCounts,
}

impl DynamicEntryInputs<'_> {
    fn dt_flags(&self) -> u64 {
        let mut flags = 0;
        flags |= object::elf::DF_BIND_NOW;

        if !self.args.output_kind().is_executable() && self.has_static_tls {
            flags |= object::elf::DF_STATIC_TLS;
        }

        if self.args.needs_origin_handling {
            flags |= object::elf::DF_ORIGIN;
        }

        u64::from(flags)
    }

    fn dt_flags_1(&self) -> u64 {
        let mut flags = 0;
        flags |= object::elf::DF_1_NOW;

        if self.args.output_kind().is_executable() && self.args.is_relocatable() {
            flags |= object::elf::DF_1_PIE;
        }

        if self.args.needs_origin_handling {
            flags |= object::elf::DF_1_ORIGIN;
        }

        if self.args.output_kind().is_shared_object() && self.args.needs_nodelete_handling {
            flags |= object::elf::DF_1_NODELETE;
        }

        u64::from(flags)
    }

    fn vma_of_section(&self, section_id: OutputSectionId) -> u64 {
        self.section_layouts.get(section_id).mem_offset
    }

    fn size_of_section(&self, section_id: OutputSectionId) -> u64 {
        self.section_layouts.get(section_id).file_size as u64
    }

    fn has_data_in_section(&self, id: OutputSectionId) -> bool {
        self.size_of_section(id) > 0
    }
}

impl DynamicEntryWriter {
    const fn new(tag: u32, cb: fn(&DynamicEntryInputs) -> u64) -> DynamicEntryWriter {
        DynamicEntryWriter {
            tag,
            is_present_cb: |_| true,
            cb,
        }
    }

    const fn optional(
        tag: u32,
        is_present_cb: fn(&DynamicEntryInputs) -> bool,
        cb: fn(&DynamicEntryInputs) -> u64,
    ) -> DynamicEntryWriter {
        DynamicEntryWriter {
            tag,
            is_present_cb,
            cb,
        }
    }

    fn is_present(&self, inputs: &DynamicEntryInputs) -> bool {
        (self.is_present_cb)(inputs)
    }

    fn write(&self, out: &mut DynamicEntriesWriter, inputs: &DynamicEntryInputs) -> Result {
        if !self.is_present(inputs) {
            return Ok(());
        }
        let value = (self.cb)(inputs);
        out.write(self.tag, value)
    }
}

struct DynamicEntriesWriter<'out> {
    out: &'out mut [DynamicEntry],
}

impl<'out> DynamicEntriesWriter<'out> {
    fn new(buffer: &'out mut [u8]) -> DynamicEntriesWriter<'out> {
        DynamicEntriesWriter {
            out: slice_from_all_bytes_mut(buffer),
        }
    }

    fn write(&mut self, tag: u32, value: u64) -> Result {
        let entry = crate::slice::take_first_mut(&mut self.out)
            .ok_or_else(|| insufficient_allocation(".dynamic"))?;
        let e = LittleEndian;
        entry.d_tag.set(e, u64::from(tag));
        entry.d_val.set(e, value);
        Ok(())
    }
}

fn write_section_headers(out: &mut [u8], layout: &Layout) -> Result {
    let entries: &mut [SectionHeader] = slice_from_all_bytes_mut(out);
    let output_sections = &layout.output_sections;
    let mut entries = entries.iter_mut();
    let mut name_offset = 0;
    let info_inputs = layout.info_inputs();

    let mut order = layout.output_order.into_iter().peekable();

    while let Some(event) = order.next() {
        let OrderEvent::Section(section_id) = event else {
            continue;
        };

        let output_info = output_sections.output_info(section_id);
        let section_type = output_info.ty;
        let section_layout = layout.section_layouts.get(section_id);

        if output_sections
            .output_index_of_section(section_id)
            .is_none()
        {
            continue;
        }

        let entsize = output_info.entsize.max(section_id.element_size());
        let mut size;
        let alignment;

        if section_type == sht::NULL {
            size = 0;
            alignment = 0;
        } else {
            size = section_layout.mem_size;
            alignment = section_layout.alignment.value();

            while let Some(OrderEvent::Section(next_section_id)) = order.peek() {
                if let Some(primary_id) = output_sections.merge_target(*next_section_id) {
                    debug_assert_eq!(primary_id, section_id);
                    size += layout.section_layouts.get(*next_section_id).mem_size;
                    order.next();
                } else {
                    break;
                }
            }
        };

        let link = output_section_id::link_ids(section_id)
            .iter()
            .find_map(|link_id| output_sections.output_index_of_section(*link_id))
            .unwrap_or(0);

        let entry = entries.next().unwrap();
        let e = LittleEndian;
        entry.sh_name.set(e, name_offset);
        entry.sh_type.set(e, section_type.raw());

        // TODO: Sections are always uncompressed and the output compression is not supported yet.
        entry.sh_flags.set(
            e,
            output_sections
                .section_flags(section_id)
                .without(shf::COMPRESSED)
                .raw(),
        );

        let name = layout.output_sections.name(section_id).with_context(|| {
            format!(
                "Missing name for section {}",
                layout.output_sections.section_debug(section_id)
            )
        })?;

        entry.sh_addr.set(e, section_layout.mem_offset);
        entry.sh_offset.set(e, section_layout.file_offset as u64);
        entry.sh_size.set(e, size);
        entry.sh_link.set(e, link.into());
        entry.sh_info.set(e, section_id.info(&info_inputs));
        entry.sh_addralign.set(e, alignment);
        entry.sh_entsize.set(e, entsize);

        name_offset += name.len() as u32 + 1;
    }
    ensure!(
        entries.next().is_none(),
        "Allocated section entries that weren't used"
    );

    Ok(())
}

fn write_section_header_strings(
    mut out: &mut [u8],
    sections: &OutputSections,
    output_order: &OutputOrder,
) {
    for event in output_order {
        if let OrderEvent::Section(id) = event {
            if sections.output_index_of_section(id).is_some() {
                if let Some(name) = sections.name(id) {
                    let name_out = crate::slice::slice_take_prefix_mut(&mut out, name.len() + 1);
                    name_out[..name.len()].copy_from_slice(name.bytes());
                    name_out[name.len()] = 0;
                }
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
            .ok_or_else(|| error!("Insufficient header slots"))
    }
}

fn write_internal_symbols_plt_got_entries<A: Arch>(
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
            table_writer
                .process_resolution::<A>(Some(layout), res)
                .with_context(|| {
                    format!("Failed to process `{}`", layout.symbol_debug(symbol_id))
                })?;
        }

        if layout.symbol_db.args.got_plt_syms {
            write_got_plt_syms(layout, &mut table_writer.debug_symbol_writer, symbol_id)?;
        }
    }
    Ok(())
}

fn write_dynamic_file<A: Arch>(
    object: &DynamicLayout,
    table_writer: &mut TableWriter,
    layout: &Layout,
) -> Result {
    write_so_name(object, table_writer)?;

    write_copy_relocations::<A>(object, table_writer, layout)?;

    for ((symbol_id, resolution), symbol) in layout
        .resolutions_in_range(object.symbol_id_range)
        .zip(object.object.symbols.iter())
    {
        if layout.symbol_db.args.got_plt_syms {
            write_got_plt_syms(layout, &mut table_writer.debug_symbol_writer, symbol_id)?;
        }
        if let Some(res) = resolution {
            let name = object.object.symbol_name(symbol)?;

            if res.resolution_flags.needs_copy_relocation() {
                // Symbol needs a copy relocation, which means that the dynamic symbol will be
                // written by the epilogue not by us. However, we do need to write a regular
                // symtab entry.
                table_writer.debug_symbol_writer.copy_symbol(
                    symbol,
                    name,
                    output_section_id::BSS,
                    res.value(),
                )?;
            } else {
                let entry = table_writer
                    .dynsym_writer
                    .define_symbol(false, 0, 0, 0, name)?;

                // Note, we copy st_info, but not st_other since we don't want to copy the
                // visibility. We want to emit the symbol with default visibility, otherwise the
                // runtime loader may ignore dynamic relocations that reference the symbol.
                entry.st_info = symbol.st_info();

                if let Some(versym) = table_writer.version_writer.versym.as_mut() {
                    write_symbol_version(
                        object.input_symbol_versions,
                        object.symbol_id_range.id_to_offset(symbol_id),
                        &object.version_mapping,
                        versym,
                    )?;
                }
            }

            table_writer
                .process_resolution::<A>(Some(layout), res)
                .with_context(|| {
                    format!(
                        "Failed to write {}",
                        layout.symbol_db.symbol_debug(symbol_id)
                    )
                })?;
        }
    }

    if let Some(verneed_info) = &object.verneed_info {
        let mut verdefs = verneed_info.defs.clone();
        let e = LittleEndian;

        let strings = object.object.sections.strings(
            e,
            object.object.data,
            verneed_info.string_table_index,
        )?;

        let ver_need = table_writer.version_writer.take_verneed()?;

        let next_verneed_offset = if object.is_last_verneed {
            0
        } else {
            (size_of::<Verneed>() + size_of::<Vernaux>() * verneed_info.version_count as usize)
                as u32
        };

        ver_need.vn_version.set(e, 1);
        ver_need.vn_cnt.set(e, verneed_info.version_count);
        ver_need.vn_aux.set(e, size_of::<Verneed>() as u32);
        ver_need.vn_next.set(e, next_verneed_offset);

        let auxes = table_writer
            .version_writer
            .take_auxes(verneed_info.version_count)?;
        let mut aux_index = 0;

        while let Some((verdef, mut aux_iterator)) = verdefs.next()? {
            let input_version = verdef.vd_ndx.get(e);
            let flags = verdef.vd_flags.get(e);
            let is_base = (flags & object::elf::VER_FLG_BASE) != 0;

            if is_base {
                let name_offset = table_writer
                    .dynsym_writer
                    .strtab_writer
                    .write_str(object.lib_name);

                ver_need.vn_file.set(e, name_offset);
                continue;
            }

            if input_version == 0 {
                bail!("Invalid version index");
            }

            let output_version = object
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
                    size_of::<Vernaux>() as u32
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
fn write_so_name(object: &DynamicLayout, table_writer: &mut TableWriter) -> Result {
    let needed_offset = table_writer
        .dynsym_writer
        .strtab_writer
        .write_str(object.lib_name);
    table_writer
        .dynamic
        .write(object::elf::DT_NEEDED, needed_offset.into())?;
    Ok(())
}

fn write_copy_relocations<A: Arch>(
    object: &DynamicLayout,
    table_writer: &mut TableWriter,
    layout: &Layout,
) -> Result {
    for &symbol_id in &object.copy_relocation_symbols {
        write_copy_relocation_for_symbol::<A>(symbol_id, table_writer, layout).with_context(
            || {
                format!(
                    "Failed to write copy relocation for {}",
                    layout.symbol_debug(symbol_id)
                )
            },
        )?;
    }

    Ok(())
}

fn write_copy_relocation_for_symbol<A: Arch>(
    symbol_id: SymbolId,
    table_writer: &mut TableWriter,
    layout: &Layout,
) -> Result {
    let res = layout
        .local_symbol_resolution(symbol_id)
        .context("Internal error: Missing resolution for copy-relocated symbol")?;

    table_writer.write_rela_dyn_general(
        res.raw_value,
        res.dynamic_symbol_index()?,
        A::get_dynamic_relocation_type(DynamicRelocationKind::Copy),
        0,
    )
}

fn write_symbol_version(
    versym_in: &[Versym],
    local_symbol_index: usize,
    version_mapping: &[u16],
    versym_out: &mut &mut [Versym],
) -> Result {
    let version_out =
        crate::slice::take_first_mut(versym_out).context("Insufficient .gnu.version allocation")?;
    let output_version =
        versym_in
            .get(local_symbol_index)
            .map_or(object::elf::VER_NDX_GLOBAL, |versym| {
                let input_version = versym.0.get(LittleEndian) & object::elf::VERSYM_VERSION;
                if input_version <= object::elf::VER_NDX_GLOBAL {
                    input_version
                } else {
                    version_mapping[usize::from(input_version) - 1]
                }
            });
    version_out.0.set(LittleEndian, output_version);
    Ok(())
}

struct StrTabWriter<'out> {
    next_offset: u32,
    out: &'out mut [u8],
}

impl StrTabWriter<'_> {
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

fn has_rela_dyn(inputs: &DynamicEntryInputs) -> bool {
    let relative = inputs.section_part_layouts.get(part_id::RELA_DYN_RELATIVE);
    let general = inputs.section_part_layouts.get(part_id::RELA_DYN_GENERAL);
    relative.mem_size > 0 || general.mem_size > 0
}

pub(crate) fn verify_resolution_allocation(
    output_sections: &OutputSections,
    output_order: &OutputOrder,
    output_kind: OutputKind,
    mem_sizes: &OutputSectionPartMap<u64>,
    resolution: &Resolution,
) -> Result {
    // Allocate however much space was requested.

    let mut total_bytes_allocated = 0;
    mem_sizes.output_order_map(output_order, |_part_id, alignment, &size| {
        total_bytes_allocated = alignment.align_up(total_bytes_allocated) + size;
    });
    total_bytes_allocated = crate::alignment::USIZE.align_up(total_bytes_allocated);
    let mut all_mem = vec![0_u64; total_bytes_allocated as usize / size_of::<u64>()];
    let mut all_mem: &mut [u8] = bytemuck::cast_slice_mut(all_mem.as_mut_slice());
    let mut offset = 0;
    let mut buffers = mem_sizes.output_order_map(output_order, |_part_id, alignment, &size| {
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
    );
    table_writer.process_resolution::<crate::x86_64::X86_64>(None, resolution)?;
    table_writer.validate_empty(mem_sizes)
}
