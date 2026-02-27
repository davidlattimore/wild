use self::elf::GNU_NOTE_PROPERTY_ENTRY_SIZE;
use self::elf::NoteHeader;
use self::elf::NoteProperty;
use self::elf::get_page_mask;
use crate::OutputKind;
use crate::alignment;
use crate::args::Args;
use crate::args::BuildIdOption;
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
use crate::elf::NonAddressableCounts;
use crate::elf::ProgramHeader;
use crate::elf::RawSymbolName;
use crate::elf::Rela;
use crate::elf::RiscVAttribute;
use crate::elf::SectionHeader;
use crate::elf::SymtabEntry;
use crate::elf::Verdaux;
use crate::elf::Verdef;
use crate::elf::Vernaux;
use crate::elf::Verneed;
use crate::elf::VersionDef;
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
use crate::layout::ObjectLayout;
use crate::layout::OutputRecordLayout;
use crate::layout::PreludeLayout;
use crate::layout::Resolution;
use crate::layout::Section;
use crate::layout::SymbolCopyInfo;
use crate::layout::SyntheticSymbolsLayout;
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
use crate::platform::ObjectFile as _;
use crate::platform::Platform;
use crate::platform::RawSymbolName as _;
use crate::platform::Relaxation as _;
use crate::platform::Relocation;
use crate::platform::RelocationSequence;
use crate::platform::SectionFlags as _;
use crate::resolution::SectionSlot;
use crate::sframe;
use crate::sharding::ShardKey;
use crate::string_merging::get_merged_string_output_address;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::timing_phase;
use crate::value_flags::PerSymbolFlags;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use hashbrown::HashMap;
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
use linker_utils::elf::stt;
use linker_utils::loongarch64::highest_relocation_with_bias;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::relaxation::SectionRelaxDeltas;
use linker_utils::relaxation::opt_input_to_output;
use object::LittleEndian;
use object::SymbolIndex;
use object::elf::NT_GNU_BUILD_ID;
use object::elf::NT_GNU_PROPERTY_TYPE_0;
use object::elf::STT_TLS;
use object::from_bytes_mut;
use object::read::elf::Crel;
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
use uuid::Uuid;
use zerocopy::FromBytes;
use zerocopy::transmute_mut;

/// A cache for managing ELF relocations and optimization of relocation entries.
#[derive(Debug)]
struct RelocationCache<R> {
    /// The last relocation entry processed, used to optimize consecutive relocations.
    previous: Option<R>,
    /// A cache mapping symbol addresses to their relocation entries, optimizing
    /// lookups for relocations involving the high parts of address.
    high_part_symbols: HashMap<u64, R>,
}

pub(crate) fn write<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    sized_output: &mut SizedOutput,
    layout: &Layout<'data>,
) -> Result {
    write_file_contents::<P>(sized_output, layout)?;
    if layout.args().validate_output {
        crate::validation::validate_bytes(layout, &sized_output.out)?;
    }

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out);

    if layout.args().should_write_eh_frame_hdr {
        sort_eh_frame_hdr_entries(section_buffers.get_mut(output_section_id::EH_FRAME_HDR));
    }

    write_sframe_section(section_buffers.get_mut(output_section_id::SFRAME), layout)?;

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

    let name_out = rest.split_off_mut(..GNU_NOTE_NAME.len()).unwrap();
    name_out.copy_from_slice(GNU_NOTE_NAME);

    rest.copy_from_slice(build_id);

    Ok(())
}

fn compute_hash(sized_output: &SizedOutput) -> blake3::Hash {
    timing_phase!("Compute build ID");
    blake3::Hasher::new()
        .update_rayon(&sized_output.out)
        .finalize()
}

fn write_file_contents<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    sized_output: &mut SizedOutput,
    layout: &Layout<'data>,
) -> Result {
    timing_phase!("Write data to file");
    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out);

    let mut writable_buckets = split_buffers_by_alignment(&mut section_buffers, layout);
    let groups_and_buffers = split_output_by_group(layout, &mut writable_buckets);
    groups_and_buffers
        .into_par_iter()
        .try_for_each(|(group, mut buffers)| -> Result {
            verbose_timing_phase!("Write group");

            let mut table_writer = TableWriter::from_layout(
                layout,
                group.dynstr_start_offset,
                group.strtab_start_offset,
                &mut buffers,
                group.format_specific.eh_frame_start_address,
            );

            for file in &group.files {
                write_file::<P>(
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

    fill_padding(section_buffers);

    Ok(())
}

fn fill_padding(mut section_buffers: OutputSectionMap<&mut [u8]>) {
    section_buffers.for_each_mut(|_, out| {
        out.fill(0);
    });
}

fn write_sframe_section(sframe_buffer: &mut [u8], layout: &Layout) -> Result {
    if sframe_buffer.is_empty() {
        return Ok(());
    }

    timing_phase!("Write .sframe");

    let sframe_start_address = layout.mem_address_of_built_in(output_section_id::SFRAME);
    let sframe_ranges: Vec<_> = layout
        .group_layouts
        .iter()
        .flat_map(|group| group.files.iter())
        .filter_map(|file| {
            if let FileLayout::Object(object) = file {
                Some(object.sframe_ranges.iter().cloned())
            } else {
                None
            }
        })
        .flatten()
        .collect();

    sframe::sort_sframe_section(sframe_buffer, sframe_start_address, &sframe_ranges)
}

fn sort_eh_frame_hdr_entries(eh_frame_hdr: &mut [u8]) {
    timing_phase!("Sort .eh_frame_hdr");
    let entry_bytes = &mut eh_frame_hdr[size_of::<elf::EhFrameHdr>()..];
    let entries = <[elf::EhFrameHdrEntry]>::mut_from_bytes(entry_bytes).unwrap();
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

fn populate_file_header<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    layout: &Layout,
    header_info: &HeaderInfo,
    header: &mut FileHeader,
) -> Result {
    let output_kind = layout.symbol_db.output_kind;
    let ty = if output_kind.is_relocatable() {
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
    header.e_machine.set(e, P::elf_header_arch_magic());
    header.e_version.set(e, u32::from(object::elf::EV_CURRENT));
    header.e_entry.set(e, layout.entry_symbol_address()?);
    header.e_phoff.set(e, elf::PHEADER_OFFSET);
    header.e_shoff.set(
        e,
        u64::from(elf::FILE_HEADER_SIZE) + header_info.program_headers_size(),
    );
    header
        .e_flags
        .set(e, layout.properties_and_attributes.eflags.0);
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

fn write_file<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    file: &FileLayout<'data>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter,
    layout: &Layout<'data>,
    trace: &TraceOutput,
) -> Result {
    match file {
        FileLayout::Object(s) => write_object::<P>(s, buffers, table_writer, layout, trace)?,
        FileLayout::Prelude(s) => write_prelude::<P>(s, buffers, table_writer, layout)?,
        FileLayout::Epilogue(s) => write_epilogue::<P>(s, buffers, table_writer, layout)?,
        FileLayout::SyntheticSymbols(s) => write_synthetic_symbols::<P>(s, table_writer, layout)?,
        FileLayout::LinkerScript(s) => write_linker_script_state::<P>(s, table_writer, layout)?,
        FileLayout::NotLoaded => {}
        FileLayout::Dynamic(s) => write_dynamic_file::<P>(s, table_writer, layout)?,
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
            let versym = versym_table
                .split_off_first_mut()
                .ok_or_else(|| insufficient_allocation(".gnu.version"))?;
            versym.0.set(LittleEndian, index);
        }
        Ok(())
    }

    fn take_bytes(&mut self, size: usize) -> Result<&'out mut [u8]> {
        self.version_r
            .split_off_mut(..size)
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
        self.version_d
            .split_off_mut(..size)
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
        if let Some(versym) = self.versym.as_ref()
            && !versym.is_empty()
        {
            return Err(excessive_allocation(
                ".gnu.version",
                versym.len() as u64 * elf::GNU_VERSION_ENTRY_SIZE,
                *mem_sizes.get(part_id::GNU_VERSION),
            ));
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

    fn take_prefix(&mut self, num_symbols: usize) -> Option<&'out mut [Versym]> {
        Some(self.versym.as_mut()?.split_off_mut(..num_symbols).unwrap())
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

    /// Note, this is stored as raw bytes because it starts with an EhFrameHdr, but is then
    /// followed by multiple EhFrameHdrEntry.
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
            layout.symbol_db.output_kind,
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
            got: <[u64]>::mut_from_bytes(buffers.take(part_id::GOT)).unwrap(),
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

    fn process_resolution<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
        &mut self,
        layout: Option<&Layout<'data>>,
        res: &Resolution,
    ) -> Result {
        let Some(got_address) = res.got_address else {
            return Ok(());
        };

        let mut got_address = got_address.get();
        let flags = res.flags;

        // For TLS variables, we'll generally only have one of these, but we might have all 3
        // combinations.
        if flags.needs_got_tls_offset()
            || flags.needs_got_tls_module()
            || flags.needs_got_tls_descriptor()
        {
            if flags.needs_got_tls_offset() {
                self.process_got_tls_offset::<P>(
                    res,
                    layout.context("Layout must be present")?,
                    got_address,
                )?;
                got_address += crate::elf::GOT_ENTRY_SIZE;
            }
            if flags.needs_got_tls_module() {
                self.process_got_tls_mod_and_offset::<P>(res, got_address)?;
                got_address += 2 * crate::elf::GOT_ENTRY_SIZE;
            }
            if flags.needs_got_tls_descriptor() {
                self.process_got_tls_descriptor::<P>(res, got_address)?;
            }
            return Ok(());
        }

        let got_entry = self.take_next_got_entry()?;

        if res.flags.is_dynamic()
            || (flags.needs_export_dynamic() && res.flags.is_interposable())
                && !res.flags.is_ifunc()
        {
            *got_entry = 0;
            debug_assert_bail!(
                *compute_allocations(res, self.output_kind).get(part_id::RELA_DYN_GENERAL) > 0,
                "Tried to write glob-dat with no allocation. {}",
                res.flags
            );
            self.write_dynamic_symbol_relocation::<P>(
                got_address,
                0,
                res.dynamic_symbol_index()?,
                DynamicRelocationKind::GotEntry,
            )?;
        } else if res.flags.is_ifunc() {
            *got_entry = 0;
            self.write_ifunc_relocation::<P>(res)?;
        } else {
            *got_entry = res.raw_value;
            if res.flags.is_address() && self.output_kind.is_relocatable() {
                self.write_address_relocation::<P>(got_address, res.raw_value as i64)?;
            }
        }
        if let Some(plt_address) = res.plt_address {
            self.write_plt_entry::<P>(got_address, plt_address.get())?;
        }

        // For ifunc symbols with GOT-relative references, write the PLT stub
        // address to the separate GOT entry. This ensures that all references to the IFUNC
        // return the same address (the PLT stub), regardless of whether they go through the
        // PLT or directly through GOT.
        if res.flags.needs_ifunc_got_for_address() {
            let ifunc_got_address = got_address + elf::GOT_ENTRY_SIZE;
            let got_entry = self.take_next_got_entry()?;
            *got_entry = res.plt_address()?;
            if self.output_kind.is_relocatable() {
                self.write_address_relocation::<P>(ifunc_got_address, *got_entry as i64)?;
            }
        }

        Ok(())
    }

    fn process_got_tls_offset<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
        &mut self,
        res: &Resolution,
        layout: &Layout<'data>,
        got_address: u64,
    ) -> Result {
        let got_entry = self.take_next_got_entry()?;
        if res.flags.is_dynamic()
            || (res.flags.needs_export_dynamic() && res.flags.is_interposable())
        {
            *got_entry = 0;
            return self.write_tpoff_relocation::<P>(got_address, res.dynamic_symbol_index()?, 0);
        }
        let address = res.raw_value;
        if address == 0 {
            // Resolution is undefined.
            *got_entry = 0;
            return Ok(());
        }
        // TLS_MODULE_BASE points at the end of the .tbss in some cases, thus relax the
        // verification.
        if !(self.tls.start..=self.tls.end).contains(&address) {
            bail!(
                "GotTlsOffset resolves to address not in TLS segment 0x{:x}",
                address
            );
        }
        if self.output_kind.is_executable() {
            // Convert the address to an offset relative to the TCB.

            *got_entry = address.wrapping_sub(P::tp_offset_start(layout));
        } else {
            debug_assert_bail!(
                *compute_allocations(res, self.output_kind).get(part_id::RELA_DYN_GENERAL) > 0,
                "Tried to write tpoff with no allocation. {}",
                res.flags
            );
            self.write_tpoff_relocation::<P>(got_address, 0, address.sub(self.tls.start) as i64)?;
        }
        Ok(())
    }

    fn process_got_tls_mod_and_offset<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
        &mut self,
        res: &Resolution,
        got_address: u64,
    ) -> Result {
        let got_entry = self.take_next_got_entry()?;
        if self.output_kind.is_executable() && !res.flags.is_dynamic() {
            *got_entry = elf::CURRENT_EXE_TLS_MOD;
        } else {
            *got_entry = 0;
            let dynamic_symbol_index = res.dynamic_symbol_index.map_or(0, std::num::NonZero::get);
            debug_assert_bail!(
                *compute_allocations(res, self.output_kind).get(part_id::RELA_DYN_GENERAL) > 0,
                "Tried to write dtpmod with no allocation. {}",
                res.flags
            );
            self.write_dtpmod_relocation::<P>(got_address, dynamic_symbol_index)?;
        }
        let offset_entry = self.take_next_got_entry()?;
        if let Some(dynamic_symbol_index) = res.dynamic_symbol_index {
            if res.flags.is_interposable() {
                self.write_dtpoff_relocation::<P>(
                    got_address + crate::elf::TLS_OFFSET_OFFSET,
                    dynamic_symbol_index.get(),
                )?;
            }
            *offset_entry = 0;
            return Ok(());
        }
        // Convert the address to an offset within the TLS segment
        let address = res.address()?;
        *offset_entry = address
            .wrapping_sub(self.tls.start)
            .wrapping_sub(P::get_dtv_offset());
        Ok(())
    }

    fn process_got_tls_descriptor<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
        &mut self,
        res: &Resolution,
        got_address: u64,
    ) -> Result {
        // TLS descriptor occupies 2 entries
        *self.take_next_got_entry()? = 0;
        *self.take_next_got_entry()? = 0;

        ensure!(
            !self.output_kind.is_static_executable(),
            "Cannot create dynamic TLSDESC relocation (function trampoline will be missed) for a static executable"
        );

        let dynamic_symbol_index = res.dynamic_symbol_index.map_or(0, std::num::NonZero::get);
        debug_assert_bail!(
            *compute_allocations(res, self.output_kind).get(part_id::RELA_DYN_GENERAL) > 0,
            "Tried to write TLS descriptor with no allocation. {}",
            res.flags
        );
        let addend = if res.dynamic_symbol_index.is_none() {
            res.raw_value.sub(self.tls.start) as i64
        } else {
            0
        };
        self.write_tls_descriptor_relocation::<P>(got_address, dynamic_symbol_index, addend)?;

        Ok(())
    }

    fn write_plt_entry<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
        &mut self,
        got_address: u64,
        plt_address: u64,
    ) -> Result {
        let plt_entry = self.take_plt_got_entry()?;
        P::write_plt_entry(plt_entry, got_address, plt_address)
    }

    fn take_plt_got_entry(&mut self) -> Result<&'out mut [u8]> {
        if self.plt_got.len() < elf::PLT_ENTRY_SIZE as usize {
            bail!("Didn't allocate enough space in .plt.got");
        }
        Ok(self
            .plt_got
            .split_off_mut(..elf::PLT_ENTRY_SIZE as usize)
            .unwrap())
    }

    fn take_next_got_entry(&mut self) -> Result<&'out mut u64> {
        self.got
            .split_off_first_mut()
            .ok_or_else(|| insufficient_allocation(".got"))
    }

    /// Checks that we used all of the entries that we requested during layout.
    fn validate_empty(&self, mem_sizes: &OutputSectionPartMap<u64>) -> Result {
        if !self.got.is_empty() {
            return Err(excessive_allocation(
                ".got",
                self.got.len() as u64 * elf::GOT_ENTRY_SIZE,
                *mem_sizes.get(part_id::GOT),
            ));
        }
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
        if !self.dynamic.out.is_empty() {
            return Err(excessive_allocation(
                ".dynamic",
                std::mem::size_of_val(self.dynamic.out) as u64,
                *mem_sizes.get(part_id::DYNAMIC),
            ));
        }
        Ok(())
    }

    fn write_ifunc_relocation<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
        &mut self,
        res: &Resolution,
    ) -> Result {
        let out = self.rela_plt.split_off_first_mut().unwrap();
        let e = LittleEndian;
        out.r_addend.set(e, res.raw_value as i64);
        let got_address = res
            .got_address
            .context("Missing GOT entry for ifunc")?
            .get();
        out.r_offset.set(e, got_address);
        out.r_info.set(
            e,
            u64::from(P::get_dynamic_relocation_type(
                DynamicRelocationKind::Irelative,
            )),
        );
        Ok(())
    }

    fn write_dtpmod_relocation<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
        &mut self,
        place: u64,
        dynamic_symbol_index: u32,
    ) -> Result {
        self.write_rela_dyn_general(
            place,
            dynamic_symbol_index,
            P::get_dynamic_relocation_type(DynamicRelocationKind::DtpMod),
            0,
        )
    }

    fn write_tls_descriptor_relocation<
        'data,
        P: Platform<'data, File = crate::elf::File<'data>>,
    >(
        &mut self,
        place: u64,
        dynamic_symbol_index: u32,
        addend: i64,
    ) -> Result {
        self.write_rela_dyn_general(
            place,
            dynamic_symbol_index,
            P::get_dynamic_relocation_type(DynamicRelocationKind::TlsDesc),
            addend,
        )
    }

    fn write_dtpoff_relocation<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
        &mut self,
        place: u64,
        dynamic_symbol_index: u32,
    ) -> Result {
        self.write_rela_dyn_general(
            place,
            dynamic_symbol_index,
            P::get_dynamic_relocation_type(DynamicRelocationKind::DtpOff),
            0,
        )
    }

    fn write_tpoff_relocation<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
        &mut self,
        place: u64,
        dynamic_symbol_index: u32,
        addend: i64,
    ) -> Result {
        self.write_rela_dyn_general(
            place,
            dynamic_symbol_index,
            P::get_dynamic_relocation_type(DynamicRelocationKind::TpOff),
            addend,
        )
    }

    #[inline(always)]
    fn write_address_relocation<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
        &mut self,
        place: u64,
        relative_address: i64,
    ) -> Result {
        debug_assert_bail!(
            self.output_kind.is_relocatable(),
            "write_address_relocation called when output is not relocatable"
        );
        let e = LittleEndian;
        let rela = self
            .rela_dyn_relative
            .split_off_first_mut()
            .ok_or_else(|| insufficient_allocation(".rela.dyn (relative)"))?;
        rela.r_offset.set(e, place);
        rela.r_addend.set(e, relative_address);
        rela.r_info.set(
            e,
            P::get_dynamic_relocation_type(DynamicRelocationKind::Relative).into(),
        );
        Ok(())
    }

    fn write_ifunc_relocation_for_data<
        'data,
        P: Platform<'data, File = crate::elf::File<'data>>,
    >(
        &mut self,
        place: u64,
        resolver_address: i64,
    ) -> Result {
        // IRELATIVE relocations go in .rela.dyn general section, not the relative section,
        // because the dynamic linker expects only R_X86_64_RELATIVE in the relative section.
        self.write_rela_dyn_general(
            place,
            0, // No dynamic symbol for IRELATIVE
            P::get_dynamic_relocation_type(DynamicRelocationKind::Irelative),
            resolver_address,
        )
    }

    fn write_dynamic_symbol_relocation<
        'data,
        P: Platform<'data, File = crate::elf::File<'data>>,
    >(
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
            P::get_dynamic_relocation_type(kind),
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
        self.rela_dyn_general
            .split_off_first_mut()
            .ok_or_else(|| insufficient_allocation(".rela.dyn (non-relative)"))
    }

    fn take_eh_frame_hdr(&mut self) -> &'out mut EhFrameHdr {
        let entry_bytes = self
            .eh_frame_hdr
            .split_off_mut(..size_of::<EhFrameHdr>())
            .unwrap();
        EhFrameHdr::mut_from_bytes(entry_bytes).unwrap()
    }

    fn take_eh_frame_hdr_entry(&mut self) -> Option<&mut EhFrameHdrEntry> {
        if self.eh_frame_hdr.is_empty() {
            return None;
        }
        let entry_bytes = self
            .eh_frame_hdr
            .split_off_mut(..size_of::<EhFrameHdrEntry>())
            .unwrap();
        Some(EhFrameHdrEntry::mut_from_bytes(entry_bytes).unwrap())
    }

    fn take_eh_frame_data(&mut self, size: usize) -> Result<&'out mut [u8]> {
        if size > self.eh_frame.len() {
            return Err(insufficient_allocation(".eh_frame"));
        }
        Ok(self.eh_frame.split_off_mut(..size).unwrap())
    }

    /// Takes a prefix of dynsym, dynstr and versym suitable for writing the supplied definitions.
    fn take_dynsym_prefix(
        &mut self,
        defs: &[crate::layout::DynamicSymbolDefinition],
    ) -> VersionedDynsymWriter<'layout, 'out> {
        let num_symbols = defs.len();
        let strtab_size = defs.iter().map(|d| d.name.len() + 1).sum();

        VersionedDynsymWriter {
            dynsym_writer: self
                .dynsym_writer
                .take_prefix_global(num_symbols, strtab_size),
            versym: self.version_writer.take_prefix(num_symbols),
        }
    }
}

struct VersionedDynsymWriter<'layout, 'out> {
    dynsym_writer: SymbolTableWriter<'layout, 'out>,
    versym: Option<&'out mut [Versym]>,
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
        flags: ValueFlags,
    ) -> Result<&mut SymtabEntry> {
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
        self.copy_symbol_shndx(sym, name, shndx, value, flags)
    }

    #[inline(always)]
    fn copy_symbol_shndx(
        &mut self,
        sym: &crate::elf::Symbol,
        name: &[u8],
        shndx: u16,
        value: u64,
        flags: ValueFlags,
    ) -> Result<&mut SymtabEntry> {
        let e = LittleEndian;
        let is_local = flags.is_symtab_local(sym);
        let size = sym.st_size(e);
        let entry = self.define_symbol(is_local, shndx, value, size, name)?;
        entry.st_info = sym.st_info();
        entry.st_other = sym.st_other();
        // Fix binding if symbol was downgraded to local by version script
        if flags.is_downgraded_to_local() {
            entry.set_st_info(object::elf::STB_LOCAL, sym.st_type());
        }
        Ok(entry)
    }

    fn copy_absolute_symbol(
        &mut self,
        sym: &crate::elf::Symbol,
        name: &[u8],
        flags: ValueFlags,
    ) -> Result<&mut SymtabEntry> {
        let e = LittleEndian;
        let is_local = flags.is_symtab_local(sym);
        let value = sym.st_value(e);
        let size = sym.st_size(e);
        let entry = self.define_symbol(is_local, object::elf::SHN_ABS, value, size, name)?;
        entry.st_info = sym.st_info();
        entry.st_other = sym.st_other();
        // Fix binding if symbol was downgraded to local by version script
        if flags.is_downgraded_to_local() {
            entry.set_st_info(object::elf::STB_LOCAL, sym.st_type());
        }
        Ok(entry)
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
            self.local_entries.split_off_first_mut().with_context(|| {
                format!(
                    "Insufficient .symtab local entries allocated for symbol `{}`",
                    String::from_utf8_lossy(name),
                )
            })?
        } else {
            if self.is_dynamic {
                tracing::trace!(name = %String::from_utf8_lossy(name), "Write .dynsym");
            }
            self.global_entries.split_off_first_mut().with_context(|| {
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

        // Always save the name without the symbol version (e.g. foo@@VER_1).
        let name = RawSymbolName::parse(name).name;
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

    /// Returns a new writer that will take responsibility for the first `num_symbols`.
    fn take_prefix_global(&mut self, num_symbols: usize, strtab_size: usize) -> Self {
        SymbolTableWriter {
            local_entries: &mut [],
            global_entries: self.global_entries.split_off_mut(..num_symbols).unwrap(),
            output_sections: self.output_sections,
            strtab_writer: self.strtab_writer.take_prefix(strtab_size),
            is_dynamic: self.is_dynamic,
        }
    }
}

fn write_object<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    object: &ObjectLayout<'data>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter,
    layout: &Layout<'data>,
    trace: &TraceOutput,
) -> Result {
    verbose_timing_phase!("Write object", file_id = object.file_id.as_u32());

    let _span = debug_span!("write_file", filename = %object.input).entered();
    let _file_span = layout.args().trace_span_for_file(object.file_id);
    for sec in &object.sections {
        match sec {
            SectionSlot::Loaded(sec) => {
                write_object_section::<P>(object, layout, sec, buffers, table_writer, trace)?;
            }
            SectionSlot::LoadedDebugInfo(sec) => {
                write_debug_section::<P>(object, layout, sec, buffers)?;
            }
            SectionSlot::FrameData(section_index) => {
                write_eh_frame_data::<P>(object, *section_index, layout, table_writer, trace)?;
            }
            _ => (),
        }
    }
    for (symbol_id, resolution) in layout.resolutions_in_range(object.symbol_id_range) {
        let _span = tracing::trace_span!("Symbol", %symbol_id).entered();
        if let Some(res) = resolution {
            table_writer
                .process_resolution::<P>(Some(layout), res)
                .with_context(|| {
                    format!(
                        "Failed to process `{}` with resolution {res:?}",
                        layout.symbol_debug(symbol_id)
                    )
                })?;

            // Dynamic symbols that we define are handled by the epilogue so that they can be
            // written in the correct order. Here, we only need to handle weak symbols that we
            // reference that aren't defined by any shared objects we're linking against.
            if res.flags.is_dynamic() {
                let symbol = object
                    .object
                    .symbol(object.symbol_id_range.id_to_input(symbol_id))?;
                let name = object.object.symbol_name(symbol)?;
                table_writer.dynsym_writer.copy_symbol_shndx(
                    symbol,
                    name,
                    0,
                    0,
                    ValueFlags::empty(),
                )?;
                if layout.gnu_version_enabled() {
                    table_writer
                        .version_writer
                        .set_next_symbol_version(object::elf::VER_NDX_GLOBAL)?;
                }
            }
        }
    }

    if !layout.args().strip_all() {
        write_symbols(object, &mut table_writer.debug_symbol_writer, layout)?;
    }
    Ok(())
}

fn write_object_section<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    object: &ObjectLayout<'data>,
    layout: &Layout<'data>,
    section: &Section,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter,
    trace: &TraceOutput,
) -> Result {
    let out = write_section_raw(object, layout, section, buffers)?;

    // We need to reverse the contents and adjust relocations because .ctors/.dtors are executed in
    // reverse order while .init_array/.fini_array are executed in forward order.
    if section.should_reverse_contents(object.object, &layout.output_sections) {
        return write_section_reversed::<P>(object, layout, section, table_writer, trace, out);
    }

    let relocations = object.relocations(section.index)?;

    let result = match relocations {
        elf::RelocationList::Rela(rela) => apply_relocations::<P, Rela, _>(
            object,
            out,
            section,
            rela.iter().map(|rela| Ok(*rela)),
            layout,
            table_writer,
            trace,
        ),
        elf::RelocationList::Crel(crel_iter) => apply_relocations::<P, Crel, _>(
            object,
            out,
            section,
            crel_iter,
            layout,
            table_writer,
            trace,
        ),
    };
    result.with_context(|| {
        format!(
            "Failed to apply relocations in section `{}` of {}",
            object.object.section_display_name(section.index),
            object.input
        )
    })?;
    if section.flags.needs_got() || section.flags.needs_plt() {
        bail!("Section has GOT or PLT");
    };
    Ok(())
}

fn write_section_reversed<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    object: &ObjectLayout<'data>,
    layout: &Layout<'data>,
    section: &Section,
    table_writer: &mut TableWriter<'_, '_>,
    trace: &TraceOutput,
    out: &mut [u8],
) -> Result {
    const WORD_SIZE: usize = core::mem::size_of::<u64>();

    if !out.is_empty() {
        ensure!(
            out.len().is_multiple_of(WORD_SIZE),
            "Section size is not a multiple of word size"
        );

        let pointers: &mut [u64] = <[u64]>::mut_from_bytes(out).unwrap();
        pointers.reverse();
    }

    // For reversed sections, we need to adjust relocation offsets.
    // The offset transformation is: new_offset = section_size - old_offset - word_size
    let section_size = out.len() as u64;

    let relocations = object.relocations(section.index)?;

    let result = match relocations {
        elf::RelocationList::Rela(rela) => apply_relocations::<P, Crel, _>(
            object,
            out,
            section,
            rela.iter().map(|r| {
                let mut crel = Crel::from_rela(r, LittleEndian, false);
                crel.r_offset = section_size.saturating_sub(crel.r_offset + WORD_SIZE as u64);
                Ok(crel)
            }),
            layout,
            table_writer,
            trace,
        ),
        elf::RelocationList::Crel(crel_iter) => apply_relocations::<P, Crel, _>(
            object,
            out,
            section,
            crel_iter.map(|r| {
                r.map(|mut crel| {
                    crel.r_offset = section_size.saturating_sub(crel.r_offset + WORD_SIZE as u64);
                    crel
                })
            }),
            layout,
            table_writer,
            trace,
        ),
    };

    result.with_context(|| {
        format!(
            "Failed to apply relocations in section `{}` of {}",
            object.object.section_display_name(section.index),
            object.input
        )
    })?;

    if section.flags.needs_got() || section.flags.needs_plt() {
        bail!("Section has GOT or PLT");
    };

    Ok(())
}

fn write_debug_section<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    object: &ObjectLayout<'data>,
    layout: &Layout<'data>,
    section: &Section,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let out = write_section_raw(object, layout, section, buffers)?;
    let relocations = object.relocations(section.index)?;
    let result = match relocations {
        elf::RelocationList::Rela(rela) => apply_debug_relocations::<P, Rela, _>(
            object,
            out,
            section,
            rela.iter().map(|rela| Ok(*rela)),
            layout,
        ),
        elf::RelocationList::Crel(crel_iter) => {
            apply_debug_relocations::<P, Crel, _>(object, out, section, crel_iter, layout)
        }
    };
    result.with_context(|| {
        format!(
            "Failed to apply relocations in section `{}` of {}",
            object.object.section_display_name(section.index),
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
        let out = section_buffer.split_off_mut(..allocation_size).unwrap();
        let object_section = object.object.section(sec.index)?;
        let relax_deltas = object.section_relax_deltas.get(sec.index.0);

        match relax_deltas {
            None => {
                let section_size = object.object.section_size(object_section)?;
                let (out, padding) = out.split_at_mut(section_size as usize);
                object.object.copy_section_data(object_section, out)?;
                padding.fill(0);
                Ok(out)
            }
            Some(deltas) => {
                let input_data = object.object.raw_section_data(object_section)?;
                let effective_size = sec.size as usize;

                let mut input_pos: usize = 0;
                let mut output_pos: usize = 0;

                for delta in deltas.deltas() {
                    let skip_start = delta.input_offset as usize;
                    // Copy everything from input_pos up to the deletion point.
                    let copy_len = skip_start - input_pos;
                    if copy_len > 0 {
                        out[output_pos..output_pos + copy_len]
                            .copy_from_slice(&input_data[input_pos..skip_start]);
                        output_pos += copy_len;
                    }
                    // Skip over the deleted bytes in the input.
                    input_pos = skip_start + delta.bytes_deleted as usize;
                }

                // Copy the remainder after the last deletion.
                let remaining = input_data.len() - input_pos;
                if remaining > 0 {
                    out[output_pos..output_pos + remaining]
                        .copy_from_slice(&input_data[input_pos..]);
                    output_pos += remaining;
                }
                out[output_pos..].fill(0);

                Ok(&mut out[..effective_size])
            }
        }
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
    for ((sym_index, sym), flags) in object
        .object
        .symbols
        .enumerate()
        .zip(layout.per_symbol_flags.raw_range(object.symbol_id_range))
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
            flags.get(),
            &object.sections,
        ) {
            let e = LittleEndian;

            let section_id =
                if let Some(section_index) = object.object.symbol_section(sym, sym_index)? {
                    match &object.sections[section_index.0] {
                        SectionSlot::Loaded(section) => section.output_section_id(),
                        SectionSlot::MergeStrings(section) => section.part_id.output_section_id(),
                        SectionSlot::FrameData(..) => output_section_id::EH_FRAME,
                        _ => bail!(
                            "Tried to copy a symbol in a section we didn't load. {}",
                            layout.symbol_debug(symbol_id)
                        ),
                    }
                } else if sym.is_common(e) {
                    if sym.st_type() == STT_TLS {
                        output_section_id::TBSS
                    } else {
                        output_section_id::BSS
                    }
                } else if sym.is_absolute(e) {
                    symbol_writer
                        .copy_absolute_symbol(sym, info.name, flags.get())
                        .with_context(|| {
                            format!("Failed to absolute {}", layout.symbol_debug(symbol_id))
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

            let entry = symbol_writer
                .copy_symbol(sym, info.name, section_id, symbol_value, flags.get())
                .with_context(|| format!("Failed to copy {}", layout.symbol_debug(symbol_id)))?;

            // Adjust symbol size for relaxation-induced byte deletions.
            if let Some(section_index) = object.object.symbol_section(sym, sym_index)?
                && let Some(deltas) = object.section_relax_deltas.get(section_index.0)
            {
                let st_value = sym.st_value(e);
                let st_size = sym.st_size(e);
                if st_size > 0 {
                    let start_output = deltas.input_to_output_offset(st_value);
                    let end_output = deltas.input_to_output_offset(st_value + st_size);
                    entry.st_size.set(e, end_output - start_output);
                }
            }
        }
    }
    Ok(())
}

fn apply_relocations<
    'data,
    P: Platform<'data, File = crate::elf::File<'data>>,
    R: Relocation,
    I: Iterator<Item = object::Result<R>> + Clone,
>(
    object: &ObjectLayout<'data>,
    out: &mut [u8],
    section: &Section,
    mut relocations: I,
    layout: &Layout<'data>,
    table_writer: &mut TableWriter,
    trace: &TraceOutput,
) -> Result {
    let section_address = object.section_resolutions[section.index.0]
        .address()
        .context("Attempted to apply relocations to a section that we didn't load")?;
    let object_section = object.object.section(section.index)?;
    let section_flags = SectionFlags::from_header(object_section);
    let mut modifier = RelocationModifier::Normal;

    let mut relocation_count = 0;
    let mut relocation_cache = RelocationCache::<R>::default();
    let relax_deltas = object.section_relax_deltas.get(section.index.0);
    let mut relax_cursor = relax_deltas.map(|deltas| deltas.cursor());

    while let Some(rel) = relocations.next() {
        let rel = rel?;
        relocation_count += 1;
        if P::high_part_relocations().contains(&rel.raw_type()) {
            let cache_offset = opt_input_to_output(relax_deltas, rel.offset());
            relocation_cache.high_part_symbols.insert(cache_offset, rel);
        }

        if modifier == RelocationModifier::SkipNextRelocation {
            modifier = RelocationModifier::Normal;
            relocation_cache.previous = Some(rel);
            continue;
        }

        // When relaxation deltas are present, translate the relocation's input
        // offset to the corresponding output offset so that it points to the
        // correct position in the (compacted) output buffer.
        let offset_in_section = match relax_cursor.as_mut() {
            Some(cursor) => cursor.translate(rel.offset()),
            None => rel.offset(),
        };

        modifier = apply_relocation::<P, R, _>(
            object,
            offset_in_section,
            &rel,
            SectionInfo {
                section_address,
                is_writable: section.is_writable,
                section_flags,
            },
            layout,
            out,
            table_writer,
            trace,
            &relocation_cache,
            &relocations,
            relax_deltas,
        )
        .with_context(|| {
            format!(
                "Failed to apply {} at offset 0x{offset_in_section:x}",
                display_relocation::<P, R>(object, &rel, layout)
            )
        })?;
        relocation_cache.previous = Some(rel);
    }

    layout
        .relocation_statistics
        .get(section.part_id.output_section_id())
        .fetch_add(relocation_count, Relaxed);
    Ok(())
}

fn apply_debug_relocations<
    'data,
    P: Platform<'data, File = crate::elf::File<'data>>,
    R: Relocation,
    I: Iterator<Item = object::Result<R>> + Clone,
>(
    object: &ObjectLayout<'data>,
    out: &mut [u8],
    section: &Section,
    relocations: I,
    layout: &Layout<'data>,
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

    let mut relocation_count = 0;
    let mut relocation_cache = RelocationCache::default();

    for rel in relocations {
        relocation_count += 1;
        let rel = rel?;
        let offset_in_section = rel.offset();
        apply_debug_relocation::<P, R>(
            object,
            offset_in_section,
            &rel,
            layout,
            tombstone_value,
            out,
            &relocation_cache,
        )
        .with_context(|| {
            format!(
                "Failed to apply {} at offset 0x{offset_in_section:x}",
                display_relocation::<P, R>(object, &rel, layout)
            )
        })?;
        relocation_cache.previous = Some(rel);
    }
    layout
        .relocation_statistics
        .get(section.part_id.output_section_id())
        .fetch_add(relocation_count, Relaxed);
    Ok(())
}

fn write_eh_frame_data<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    object: &ObjectLayout<'data>,
    eh_frame_section_index: object::SectionIndex,
    layout: &Layout<'data>,
    table_writer: &mut TableWriter,
    trace: &TraceOutput,
) -> Result {
    let eh_frame_section = object.object.section(eh_frame_section_index)?;
    match object.relocations(eh_frame_section_index)? {
        elf::RelocationList::Rela(relocations) => write_eh_frame_relocations::<P, Rela>(
            object,
            layout,
            table_writer,
            trace,
            eh_frame_section,
            relocations.rel_iter(),
        ),
        elf::RelocationList::Crel(relocations) => write_eh_frame_relocations::<P, Crel>(
            object,
            layout,
            table_writer,
            trace,
            eh_frame_section,
            relocations.flat_map(|r| r.ok()),
        ),
    }
}

fn write_eh_frame_relocations<
    'data,
    P: Platform<'data, File = crate::elf::File<'data>>,
    R: Relocation,
>(
    object: &ObjectLayout<'data>,
    layout: &Layout<'data>,
    table_writer: &mut TableWriter<'_, '_>,
    trace: &TraceOutput,
    eh_frame_section: &object::elf::SectionHeader64<LittleEndian>,
    relocations: impl Iterator<Item = R>,
) -> std::result::Result<(), error::Error> {
    let data = object.object.raw_section_data(eh_frame_section)?;
    const PREFIX_LEN: usize = size_of::<elf::EhFrameEntryPrefix>();
    let e = LittleEndian;
    let section_flags = SectionFlags::from_header(eh_frame_section);
    let mut relocations = relocations.peekable();
    let mut input_pos = 0;
    let mut output_pos = 0;
    let frame_info_ptr_base = table_writer.eh_frame_start_address;
    let eh_frame_hdr_address = layout.mem_address_of_built_in(output_section_id::EH_FRAME_HDR);

    // Map from input offset to output offset of each CIE.
    let mut cies_offset_conversion: HashMap<u32, u32> = HashMap::new();

    while input_pos + PREFIX_LEN <= data.len() {
        let prefix =
            elf::EhFrameEntryPrefix::read_from_bytes(&data[input_pos..input_pos + PREFIX_LEN])
                .unwrap();
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
                let rel_offset = rel.offset();
                if rel_offset < next_input_pos as u64 {
                    let is_pc_begin = (rel_offset as usize - input_pos) == elf::FDE_PC_BEGIN_OFFSET;

                    if is_pc_begin {
                        let Some(index) = rel.symbol() else {
                            bail!("Unexpected absolute relocation in .eh_frame pc-begin");
                        };
                        let elf_symbol = &object.object.symbol(index)?;
                        let Some(section_index) =
                            object.object.symbol_section(elf_symbol, index)?
                        else {
                            bail!(".eh_frame pc-begin refers to symbol that's not defined in file");
                        };
                        let offset_in_section =
                            (elf_symbol.st_value(e) as i64 + rel.addend()) as u64;
                        if let Some(section_address) =
                            object.section_resolutions[section_index.0].address()
                            && object
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
                                // When relaxation has deleted bytes from the target section, the
                                // symbol's input offset no longer matches the output position.
                                let output_offset_in_section = opt_input_to_output(
                                    object.section_relax_deltas.get(section_index.0),
                                    offset_in_section,
                                );
                                let frame_ptr = (section_address + output_offset_in_section) as i64
                                    - eh_frame_hdr_address as i64;
                                let frame_info_ptr = (frame_info_ptr_base + output_pos as u64)
                                    as i64
                                    - eh_frame_hdr_address as i64;
                                *hdr_out = EhFrameHdrEntry {
                                    frame_ptr: i32::try_from(frame_ptr)
                                        .context("32 bit overflow in frame_ptr")?,
                                    frame_info_ptr: i32::try_from(frame_info_ptr)
                                        .context("32 bit overflow when computing frame_info_ptr")?,
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
                let rel_offset = rel.offset();
                if rel_offset >= next_input_pos as u64 {
                    // This relocation belongs to the next entry.
                    break;
                }
                apply_relocation::<P, R, _>(
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
                    &RelocationCache::default(),
                    &iter::empty(),
                    None,
                )
                .with_context(|| {
                    format!(
                        "Failed to apply eh_frame {}",
                        display_relocation::<P, R>(object, rel, layout)
                    )
                })?;
                relocations.next();
            }
            output_pos = next_output_pos;
        } else {
            // We're ignoring this entry, skip any relocations for it.
            while let Some(rel) = relocations.peek() {
                if rel.offset() < next_input_pos as u64 {
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

fn display_relocation<
    'a,
    'data,
    P: Platform<'data, File = crate::elf::File<'data>>,
    R: Relocation,
>(
    object: &'a ObjectLayout<'data>,
    rel: &'a R,
    layout: &'a Layout<'data>,
) -> DisplayRelocation<'a, 'data, P, R> {
    DisplayRelocation::<'a, 'data, P, R> {
        rel,
        symbol_db: &layout.symbol_db,
        per_symbol_flags: &layout.per_symbol_flags,
        object,
        phantom: PhantomData,
    }
}

struct DisplayRelocation<
    'a,
    'data,
    P: Platform<'data, File = crate::elf::File<'data>>,
    R: Relocation,
> {
    rel: &'a R,
    symbol_db: &'a SymbolDb<'data, crate::elf::File<'data>>,
    per_symbol_flags: &'a PerSymbolFlags,
    object: &'a ObjectLayout<'data>,
    phantom: PhantomData<P>,
}

impl<'a, 'data, P: Platform<'data, File = crate::elf::File<'data>>, R: Relocation> Display
    for DisplayRelocation<'a, 'data, P, R>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "relocation of type {} to ",
            P::rel_type_to_string(self.rel.raw_type())
        )?;
        match self.rel.symbol() {
            None => write!(f, "absolute")?,
            Some(local_symbol_index) => {
                let symbol_id = self.object.symbol_id_range.input_to_id(local_symbol_index);
                write!(
                    f,
                    "{}",
                    self.symbol_db
                        .symbol_debug(self.per_symbol_flags, symbol_id)
                )?;
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

fn get_resolution<R: Relocation>(
    rel: &R,
    object_layout: &ObjectLayout,
    layout: &Layout,
) -> Result<(Resolution, SymbolIndex, SymbolId)> {
    let symbol_index = rel.symbol().context("Unsupported absolute relocation")?;
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
                layout.symbol_debug(local_symbol_id)
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

    if !resolution.flags.needs_got() {
        return Ok(());
    }

    let current_res_flags = resolution.flags;

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
        RelocationKind::AbsoluteAdditionWord6 => {
            // Preserve the 2 most significant bits of u8.
            let value = (current_value & LOW6_MASK).wrapping_add(value & LOW6_MASK) & LOW6_MASK;
            Ok(value | (current_value & !LOW6_MASK))
        }
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
fn get_pair_subtraction_relocation_value<
    'data,
    P: Platform<'data, File = crate::elf::File<'data>>,
    R: Relocation,
>(
    object_layout: &ObjectLayout,
    rel: &R,
    layout: &Layout,
    resolution: Resolution,
    symbol_index: SymbolIndex,
    addend: i64,
    set_rel: &R,
    expected_r_type: u32,
) -> Result<u64> {
    ensure!(
        set_rel.offset() == rel.offset(),
        "PairSubtractionULEB128 relocation must have equal offset"
    );
    ensure!(
        set_rel.raw_type() == expected_r_type,
        "unexpected previous relocation: expected: {}, was: {}",
        P::rel_type_to_string(expected_r_type),
        P::rel_type_to_string(set_rel.raw_type())
    );
    let (set_resolution, set_symbol_index, _) = get_resolution(set_rel, object_layout, layout)?;

    let set_resolution_val = set_resolution.value_with_addend(
        set_rel.addend(),
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
fn apply_relocation<
    'data,
    P: Platform<'data, File = crate::elf::File<'data>>,
    R: Relocation,
    I: Iterator<Item = object::Result<R>> + Clone,
>(
    object_layout: &ObjectLayout,
    mut offset_in_section: u64,
    rel: &R,
    section_info: SectionInfo,
    layout: &Layout<'data>,
    out: &mut [u8],
    table_writer: &mut TableWriter,
    trace: &TraceOutput,
    relocation_cache: &RelocationCache<R>,
    relocation_iterator: &I,
    relax_deltas: Option<&SectionRelaxDeltas>,
) -> Result<RelocationModifier> {
    let section_address = section_info.section_address;
    let original_place = section_address + offset_in_section;
    let _span = tracing::trace_span!(
        "relocation",
        address = original_place,
        address_hex = %HexU64::new(original_place)
    )
    .entered();

    let r_type = rel.raw_type();
    let mut addend = rel.addend();

    match P::relocation_from_raw(r_type)?.kind {
        RelocationKind::None => return Ok(RelocationModifier::Normal),
        RelocationKind::Alignment => {
            let addend = addend as u64;
            let address = section_address + rel.offset();
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
    let flags = layout.flags_for_symbol(local_symbol_id);
    let mut next_modifier = RelocationModifier::Normal;
    let rel_info;
    let output_kind = layout.symbol_db.output_kind;

    let relaxation = P::new_relaxation(
        r_type,
        out,
        offset_in_section,
        flags,
        output_kind,
        section_info.section_flags,
        resolution.raw_value != 0,
        relax_deltas,
    )
    .filter(|relaxation| layout.args().relax || relaxation.is_mandatory());

    if let Some(relaxation) = &relaxation {
        rel_info = relaxation.rel_info();
        relaxation.apply(out, &mut offset_in_section, &mut addend);
        next_modifier = relaxation.next_modifier();
    } else {
        rel_info = P::relocation_from_raw(r_type)?;
    }

    // Compute place to which IP-relative relocations will be relative. This is different to
    // `original_place` in that our `offset_in_section` may have been adjusted by a relaxation.
    let place = section_address + offset_in_section;

    let mask = get_page_mask(rel_info.mask);
    let bias = rel_info.bias;
    let mut value = match rel_info.kind {
        RelocationKind::Absolute => write_absolute_relocation::<P>(
            table_writer,
            resolution,
            place,
            addend,
            section_info,
            symbol_index,
            object_layout,
            layout,
        )?,
        RelocationKind::AbsoluteSet
        | RelocationKind::AbsoluteSetWord6
        | RelocationKind::AbsoluteAddition
        | RelocationKind::AbsoluteAdditionWord6
        | RelocationKind::AbsoluteSubtraction
        | RelocationKind::AbsoluteSubtractionWord6 => resolution.value_with_addend(
            addend,
            symbol_index,
            object_layout,
            &layout.merged_strings,
            &layout.merged_string_start_addresses,
        )?,
        RelocationKind::AbsoluteLowPart => resolution
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
            .wrapping_add(bias)
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::RelativeLoongArchHigh => highest_relocation_with_bias(
            resolution.value_with_addend(
                addend,
                symbol_index,
                object_layout,
                &layout.merged_strings,
                &layout.merged_string_start_addresses,
            )?,
            place,
        ),
        RelocationKind::RelativeRiscVLow12 => {
            // The iterator is used for e.g. R_RISCV_PCREL_HI20 & R_RISCV_PCREL_LO12_I pair of
            // relocations where the later one actually points to a label of the HI20
            // relocations and thus we need to find it. The relocation is typically
            // right before the LO12_* relocation.
            ensure!(
                addend == 0,
                "Unexpected addend for R_RISCV_PCREL_LO12 relocation"
            );
            let hi_offset_in_section = resolution
                .value_with_addend(
                    addend,
                    symbol_index,
                    object_layout,
                    &layout.merged_strings,
                    &layout.merged_string_start_addresses,
                )?
                .wrapping_sub(section_address);
            let hi_rel = relocation_cache
                .high_part_symbols
                .get(&hi_offset_in_section)
                .copied()
                .or_else(|| {
                    // It's very unlikely that a high part follows the low part:
                    relocation_iterator.clone().find_map(|r| {
                        if let Ok(r) = r
                            && P::high_part_relocations().contains(&r.raw_type())
                        {
                            let r_output_offset = opt_input_to_output(relax_deltas, r.offset());
                            if r_output_offset == hi_offset_in_section {
                                return Some(r);
                            }
                        }
                        None
                    })
                })
                .context("Missing High relocation connected with R_RISCV_PCREL_LO12")?;

            let hi_rel_info = P::relocation_from_raw(hi_rel.raw_type())?;
            let addend = hi_rel.addend();
            let (resolution, symbol_index, _) = get_resolution(&hi_rel, object_layout, layout)
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
                    .wrapping_add(bias)
                    .wrapping_sub(place),
                RelocationKind::GotRelative => resolution
                    .got_address_for_relocation()?
                    .wrapping_add(addend as u64)
                    .wrapping_add(bias)
                    .wrapping_sub(place),
                RelocationKind::TlsGd => resolution
                    .tlsgd_got_address()?
                    .wrapping_add(addend as u64)
                    .wrapping_add(bias)
                    .wrapping_sub(place),
                RelocationKind::TlsLd => layout
                    .prelude()
                    .tlsld_got_entry
                    .unwrap()
                    .get()
                    .wrapping_add(addend as u64)
                    .wrapping_add(bias)
                    .wrapping_sub(place),
                RelocationKind::GotTpOff => resolution
                    .got_address()?
                    .wrapping_add(addend as u64)
                    .wrapping_add(bias)
                    .wrapping_sub(place),
                _ => bail!(
                    "Unsupported high part relocation {:?} connected with R_RISCV_PCREL_LO12",
                    hi_rel_info.kind
                ),
            }
        }
        RelocationKind::PairSubtractionULEB128(expected_r_type) => {
            get_pair_subtraction_relocation_value::<P, R>(
                object_layout,
                rel,
                layout,
                resolution,
                symbol_index,
                addend,
                // It must be the previous relocation
                &relocation_cache.previous.with_context(|| {
                    "Missing previous relocation for PairSubtractionULEB128".to_owned()
                })?,
                expected_r_type,
            )?
        }
        RelocationKind::GotRelative => resolution
            .got_address_for_relocation()?
            .wrapping_add(bias)
            .wrapping_add(addend as u64)
            .bitand(mask.got_entry)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::GotRelativeLoongArch64 => highest_relocation_with_bias(
            resolution
                .got_address_for_relocation()?
                .wrapping_add(addend as u64),
            place,
        ),
        RelocationKind::GotRelGotBase => resolution
            .got_address_for_relocation()?
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry)
            .wrapping_sub(layout.got_base().bitand(mask.got)),
        RelocationKind::Got => {
            // The LoongArch64 psABI does not provide a separate GOT Low part relocation for the
            // TLSGD relocation. So we need to distinguish between a classical GOT
            // slot and one corresponding to TLSGD.
            //
            // Note: TLSLD is unsupported by the target (https://github.com/loongson/la-abi-specs/issues/19).
            if resolution.flags.needs_got_tls_module() {
                resolution.tlsgd_got_address()?
            } else {
                resolution.got_address_for_relocation()?
            }
            .wrapping_add(bias)
            .bitand(mask.got_entry)
        }
        RelocationKind::SymRelGotBase => resolution
            .value_with_addend(
                addend,
                symbol_index,
                object_layout,
                &layout.merged_strings,
                &layout.merged_string_start_addresses,
            )?
            .wrapping_add(bias)
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(layout.got_base().bitand(mask.got)),
        RelocationKind::PltRelGotBase => resolution
            .plt_address()?
            .wrapping_add(bias)
            .wrapping_sub(layout.got_base().bitand(mask.got)),
        RelocationKind::PltRelative => resolution
            .plt_address()?
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .wrapping_sub(place.bitand(mask.place)),
        // TLS-related relocations
        RelocationKind::TlsGd => resolution
            .tlsgd_got_address()?
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::TlsGdGot => resolution
            .tlsgd_got_address()?
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry),
        RelocationKind::TlsGdGotBase => resolution
            .tlsgd_got_address()?
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry)
            .wrapping_sub(layout.got_base().bitand(mask.got)),
        RelocationKind::TlsLd => layout
            .prelude()
            .tlsld_got_entry
            .unwrap()
            .get()
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::TlsLdGot => layout
            .prelude()
            .tlsld_got_entry
            .unwrap()
            .get()
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry),
        RelocationKind::TlsLdGotBase => layout
            .prelude()
            .tlsld_got_entry
            .unwrap()
            .get()
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry)
            .wrapping_sub(layout.got_base().bitand(mask.got)),
        RelocationKind::DtpOff if output_kind == OutputKind::SharedObject => resolution
            .value()
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .sub(layout.tls_start_address()),
        RelocationKind::DtpOff => resolution
            .value()
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .wrapping_sub(layout.tls_end_address()),
        RelocationKind::GotTpOff => resolution
            .got_address()?
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::GotTpOffLoongArch64 => highest_relocation_with_bias(
            resolution.got_address()?.wrapping_add(addend as u64),
            place,
        ),
        RelocationKind::GotTpOffGot => resolution
            .got_address()?
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry),
        RelocationKind::GotTpOffGotBase => resolution
            .got_address()?
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry)
            .wrapping_sub(layout.got_base().bitand(mask.got)),
        RelocationKind::TpOff => resolution
            .value()
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .wrapping_sub(P::tp_offset_start(layout)),
        RelocationKind::TlsDesc => resolution
            .tls_descriptor_got_address()?
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::TlsDescLoongArch64 => highest_relocation_with_bias(
            resolution
                .tls_descriptor_got_address()?
                .wrapping_add(addend as u64),
            place,
        ),
        RelocationKind::TlsDescGot => resolution
            .tls_descriptor_got_address()?
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry),
        RelocationKind::TlsDescGotBase => resolution
            .tls_descriptor_got_address()?
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry)
            .wrapping_sub(layout.got_base().bitand(mask.got)),
        RelocationKind::None | RelocationKind::TlsDescCall => 0,
        RelocationKind::Alignment => unreachable!(),
    };

    let offset_in_section = offset_in_section as usize;

    // Handle addition and subtraction relocation kinds.
    if matches!(
        rel_info.kind,
        RelocationKind::AbsoluteAddition
            | RelocationKind::AbsoluteAdditionWord6
            | RelocationKind::AbsoluteSubtraction
            | RelocationKind::AbsoluteSetWord6
            | RelocationKind::AbsoluteSubtractionWord6
    ) {
        value = adjust_relocation_based_on_value(value, &rel_info, out, offset_in_section)?;
    }

    if let Some(relaxation) = relaxation {
        trace.emit(original_place, || {
            format!(
                "relaxation applied relaxation={kind:?}, flags={flags},\n\
                rel_kind={rel_kind:?},\n\
                value=0x{value:x}, symbol_name={symbol_name}",
                kind = relaxation.debug_kind(),
                rel_kind = rel_info.kind,
                symbol_name = layout.symbol_db.symbol_name_for_display(local_symbol_id),
            )
        });
        tracing::trace!(
            %flags,
            %flags,
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
                "relocation applied flags={flags},\n\
                rel_kind={rel_kind:?},\n\
                value=0x{value:x}, symbol_name={symbol_name}",
                rel_kind = rel_info.kind,
                symbol_name = layout.symbol_db.symbol_name_for_display(local_symbol_id),
            )
        });
        tracing::trace!(
            %flags,
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

fn apply_debug_relocation<
    'data,
    P: Platform<'data, File = crate::elf::File<'data>>,
    R: Relocation,
>(
    object_layout: &ObjectLayout,
    offset_in_section: u64,
    rel: &R,
    layout: &Layout,
    section_tombstone_value: u64,
    out: &mut [u8],
    relocation_cache: &RelocationCache<R>,
) -> Result<()> {
    let symbol_index = rel.symbol().context("Unsupported absolute relocation")?;
    let sym = object_layout.object.symbol(symbol_index)?;
    let section_index = object_layout.object.symbol_section(sym, symbol_index)?;

    let addend = rel.addend();
    let r_type = rel.raw_type();
    let rel_info = P::relocation_from_raw(r_type)?;

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
            | RelocationKind::AbsoluteAdditionWord6
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
            RelocationKind::PairSubtractionULEB128(expected_r_type) => {
                get_pair_subtraction_relocation_value::<P, R>(
                    object_layout,
                    rel,
                    layout,
                    resolution,
                    symbol_index,
                    addend,
                    // Must be the previous relocation.
                    &relocation_cache.previous.with_context(|| {
                        "Missing previous relocation for PairSubtractionULEB128".to_owned()
                    })?,
                    expected_r_type,
                )?
            }
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
fn write_absolute_relocation<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    table_writer: &mut TableWriter,
    resolution: Resolution,
    place: u64,
    addend: i64,
    section_info: SectionInfo,
    symbol_index: object::SymbolIndex,
    object_layout: &ObjectLayout,
    layout: &Layout,
) -> Result<u64> {
    if !section_info.section_flags.is_alloc() {
        resolution.value_with_addend(
            addend,
            symbol_index,
            object_layout,
            &layout.merged_strings,
            &layout.merged_string_start_addresses,
        )
    } else if resolution.flags.is_dynamic()
        && resolution.flags.is_absolute()
        && !section_info.is_writable
    {
        // Weak undefined symbol referenced from a read-only section. Fill in as zero.
        Ok(0)
    } else if resolution.flags.is_interposable() && section_info.is_writable {
        table_writer.write_dynamic_symbol_relocation::<P>(
            place,
            addend,
            resolution.dynamic_symbol_index()?,
            DynamicRelocationKind::Absolute,
        )?;

        Ok(0)
    } else if resolution.flags.is_ifunc()
        && section_info.is_writable
        && table_writer.output_kind.is_relocatable()
    {
        table_writer
            .write_ifunc_relocation_for_data::<P>(place, resolution.raw_value as i64 + addend)?;
        Ok(0)
    } else if table_writer.output_kind.is_relocatable() && !resolution.is_absolute() {
        let address = resolution.value_with_addend(
            addend,
            symbol_index,
            object_layout,
            &layout.merged_strings,
            &layout.merged_string_start_addresses,
        )?;

        table_writer.write_address_relocation::<P>(place, address as i64)?;

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

fn write_prelude<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    prelude: &PreludeLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter,
    layout: &Layout<'data>,
) -> Result {
    verbose_timing_phase!("Write prelude");

    let header: &mut FileHeader = from_bytes_mut(buffers.get_mut(part_id::FILE_HEADER))
        .map_err(|_| error!("Invalid file header allocation"))?
        .0;
    populate_file_header::<P>(layout, &prelude.header_info, header)?;

    let mut program_headers = ProgramHeaderWriter::new(buffers.get_mut(part_id::PROGRAM_HEADERS));
    write_program_headers(&mut program_headers, layout)?;

    write_section_headers(buffers.get_mut(part_id::SECTION_HEADERS), layout)?;

    write_section_header_strings(
        buffers.get_mut(part_id::SHSTRTAB),
        &layout.output_sections,
        &layout.output_order,
    );

    write_plt_got_entries::<P>(prelude, layout, table_writer)?;

    if !layout.args().strip_all() {
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
    if layout.symbol_db.output_kind.needs_dynsym() {
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
                .map(|b| (b, buffer.split_off_mut(..b.len()).unwrap()))
                .par_bridge()
                .for_each(|(bucket, mut buffer)| {
                    for string in &bucket.strings {
                        let dest = buffer.split_off_mut(..string.len()).unwrap();
                        dest.copy_from_slice(string);
                    }
                });
        }
    });

    if layout.args().should_write_linker_identity {
        // Write linker identity into .comment section.
        let comment_buffer =
            buffers.get_mut(output_section_id::COMMENT.part_id_with_alignment(alignment::MIN));
        comment_buffer
            .split_off_mut(..prelude.identity.len())
            .unwrap()
            .copy_from_slice(prelude.identity.as_bytes());
    }
}

fn write_plt_got_entries<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    prelude: &PreludeLayout,
    layout: &Layout<'data>,
    table_writer: &mut TableWriter,
) -> Result {
    // Write a pair of GOT entries for use by any TLSLD or TLSGD relocations.
    if let Some(got_address) = prelude.tlsld_got_entry {
        let mut raw_value = 0;

        if layout.symbol_db.output_kind.is_executable() {
            table_writer.process_resolution::<P>(
                Some(layout),
                &Resolution {
                    raw_value: crate::elf::CURRENT_EXE_TLS_MOD,
                    dynamic_symbol_index: None,
                    got_address: Some(got_address),
                    plt_address: None,
                    flags: ValueFlags::GOT | ValueFlags::ABSOLUTE,
                },
            )?;

            // For executables, DTPOFF values are negative values relative to the thread pointer,
            // which is at the end of the TLS segment.
            raw_value = P::tp_offset_start(layout) - layout.tls_start_address();
        } else {
            *table_writer.take_next_got_entry()? = 0;
            table_writer.write_dtpmod_relocation::<P>(got_address.get(), 0)?;
        }

        table_writer.process_resolution::<P>(
            Some(layout),
            &Resolution {
                raw_value,
                dynamic_symbol_index: None,
                got_address: Some(got_address.saturating_add(elf::GOT_ENTRY_SIZE)),
                plt_address: None,
                flags: ValueFlags::GOT | ValueFlags::ABSOLUTE,
            },
        )?;
    }

    write_internal_symbols_plt_got_entries::<P>(&prelude.internal_symbols, table_writer, layout)?;
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
        let offset = if i < verdefs.len() - 1 {
            (size_of::<crate::elf::Verdef>()
                + size_of::<crate::elf::Verdaux>() * aux_count as usize) as u32
        } else {
            0
        };
        verdef_out.vd_next.set(e, offset);

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
        let rpath_tag = if layout.args().enable_new_dtags {
            object::elf::DT_RUNPATH
        } else {
            object::elf::DT_RPATH
        };
        table_writer.dynamic.write(rpath_tag, offset.into())?;
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
    for aux in &layout.args().auxiliary {
        let offset = table_writer
            .dynsym_writer
            .strtab_writer
            .write_str(aux.as_bytes());
        table_writer
            .dynamic
            .write(object::elf::DT_AUXILIARY, offset.into())?;
    }

    let inputs = DynamicEntryInputs {
        args: layout.args(),
        has_static_tls: layout.has_static_tls,
        has_variant_pcs: layout.has_variant_pcs,
        section_layouts: &layout.merged_section_layouts,
        section_part_layouts: &layout.section_part_layouts,
        non_addressable_counts: layout.non_addressable_counts,
        output_kind: layout.symbol_db.output_kind,
    };

    for writer in EPILOGUE_DYNAMIC_ENTRY_WRITERS {
        writer.write(&mut table_writer.dynamic, &inputs)?;
    }

    table_writer.dynamic.write_unused();

    Ok(())
}

#[derive(Default)]
pub(crate) struct EpilogueOffsets {
    /// The offset of the shared object name in .dynsym.
    pub(crate) soname: Option<u32>,
}

fn write_linker_script_state<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    script: &LinkerScriptLayoutState,
    table_writer: &mut TableWriter,
    layout: &Layout<'data>,
) -> Result {
    verbose_timing_phase!("Write linker script state");

    write_internal_symbols(
        &script.internal_symbols,
        layout,
        &mut table_writer.debug_symbol_writer,
    )?;

    write_internal_symbols_plt_got_entries::<P>(&script.internal_symbols, table_writer, layout)?;

    Ok(())
}

fn write_synthetic_symbols<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    syn: &SyntheticSymbolsLayout,
    table_writer: &mut TableWriter,
    layout: &Layout<'data>,
) -> Result {
    verbose_timing_phase!("Write epilogue");

    write_internal_symbols_plt_got_entries::<P>(&syn.internal_symbols, table_writer, layout)?;

    if !layout.args().strip_all() {
        write_internal_symbols(
            &syn.internal_symbols,
            layout,
            &mut table_writer.debug_symbol_writer,
        )?;
    }

    Ok(())
}

fn write_epilogue<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    epilogue: &EpilogueLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter,
    layout: &Layout,
) -> Result {
    verbose_timing_phase!("Write epilogue");

    let mut epilogue_offsets = EpilogueOffsets::default();

    if layout.symbol_db.output_kind.needs_dynamic() {
        write_epilogue_dynamic_entries(layout, table_writer, &mut epilogue_offsets)?;
    }
    write_sysv_hash_table(layout, epilogue, buffers)?;
    write_gnu_hash_tables(layout, epilogue, buffers)?;

    write_dynamic_symbol_definitions(table_writer, layout)?;

    if !layout
        .properties_and_attributes
        .gnu_property_notes
        .is_empty()
    {
        write_gnu_property_notes(layout, buffers)?;
    }
    if layout
        .properties_and_attributes
        .riscv_attributes
        .section_size
        != 0
    {
        write_riscv_attributes(layout, buffers)?;
    }

    if let Some(verdefs) = &epilogue.format_specific.verdefs {
        write_verdef(
            verdefs,
            table_writer,
            layout.args().soname.as_ref().map(|s| s.as_bytes()),
            &epilogue_offsets,
        )?;
    }

    // The actual build-id will be filled in later once all writing has completed. It's important
    // that we fill it with zeros now however, since if we're overwriting an existing file, there
    // might be other data there and it we don't zero it, then the build ID will be hashing that
    // data.
    let build_id_buffer = buffers.get_mut(part_id::NOTE_GNU_BUILD_ID);
    build_id_buffer.fill(0);

    Ok(())
}

fn write_gnu_property_notes(
    layout: &Layout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let e = LittleEndian;
    let (note_header, mut rest) =
        from_bytes_mut::<NoteHeader>(buffers.get_mut(part_id::NOTE_GNU_PROPERTY))
            .map_err(|_| error!("Insufficient .note.gnu.property allocation"))?;
    note_header.n_namesz.set(e, GNU_NOTE_NAME.len() as u32);
    note_header.n_descsz.set(
        e,
        (layout.properties_and_attributes.gnu_property_notes.len() * GNU_NOTE_PROPERTY_ENTRY_SIZE)
            as u32,
    );
    note_header.n_type.set(e, NT_GNU_PROPERTY_TYPE_0);

    let name_out = rest.split_off_mut(..GNU_NOTE_NAME.len()).unwrap();
    name_out.copy_from_slice(GNU_NOTE_NAME);

    for note in &layout.properties_and_attributes.gnu_property_notes {
        let entry_bytes = rest.split_off_mut(..size_of::<NoteProperty>()).unwrap();
        let property = NoteProperty::mut_from_bytes(entry_bytes).unwrap();
        property.pr_type = note.ptype;
        property.pr_datasz = size_of_val(&property.pr_data) as u32;
        property.pr_data = note.data;
        property.pr_padding = 0;
    }

    Ok(())
}

fn write_riscv_attributes(
    layout: &Layout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let mut writer = Cursor::new(&mut **buffers.get_mut(part_id::RISCV_ATTRIBUTES));
    writer.write_all(b"A")?;

    let riscv_attributes_length = layout
        .properties_and_attributes
        .riscv_attributes
        .section_size as u32;

    writer.write_all((riscv_attributes_length - 1).to_le_bytes().as_slice())?;
    writer.write_all(RISCV_ATTRIBUTE_VENDOR_NAME.as_bytes())?;
    writer.write_all(b"\0")?;
    leb128::write::unsigned(&mut writer, TAG_RISCV_WHOLE_FILE)?;
    writer.write_all(
        (riscv_attributes_length - 1 - 4 - RISCV_ATTRIBUTE_VENDOR_NAME.len() as u32 - 1)
            .to_le_bytes()
            .as_slice(),
    )?;
    for tag in &layout.properties_and_attributes.riscv_attributes.attributes {
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

fn write_sysv_hash_table(
    layout: &Layout,
    epilogue: &EpilogueLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let Some(sysv_hash_layout) = epilogue.format_specific.sysv_hash_layout.as_ref() else {
        return Ok(());
    };

    let bucket_count =
        usize::try_from(sysv_hash_layout.bucket_count).context("Too many buckets for .hash")?;
    let chain_count =
        usize::try_from(sysv_hash_layout.chain_count).context("Too many chains for .hash")?;

    if bucket_count == 0 || chain_count == 0 {
        return Ok(());
    }

    let total_words = 2usize
        .checked_add(bucket_count)
        .and_then(|v| v.checked_add(chain_count))
        .context("Insufficient .hash allocation")?;
    let required_bytes = total_words
        .checked_mul(std::mem::size_of::<u32>())
        .context("Insufficient .hash allocation")?;

    let buffer = buffers.get_mut(part_id::SYSV_HASH);
    if buffer.len() < required_bytes {
        return Err(error!("Insufficient .hash allocation"));
    }
    let buffer = &mut buffer[..required_bytes];
    buffer.fill(0);

    let (header_bytes, rest) = buffer.split_at_mut(2 * std::mem::size_of::<u32>());
    header_bytes[..4].copy_from_slice(&sysv_hash_layout.bucket_count.to_le_bytes());
    header_bytes[4..8].copy_from_slice(&sysv_hash_layout.chain_count.to_le_bytes());

    let (buckets, rest) = object::slice_from_bytes_mut::<u32>(rest, bucket_count)
        .map_err(|_| error!("Insufficient bytes for .hash buckets"))?;
    let (chains, rest) = object::slice_from_bytes_mut::<u32>(rest, chain_count)
        .map_err(|_| error!("Insufficient bytes for .hash chains"))?;

    debug_assert!(rest.is_empty());

    buckets.fill(0);
    chains.fill(0);
    let mut last_in_bucket: Vec<Option<usize>> = vec![None; bucket_count];

    for (i, sym_def) in layout.dynamic_symbol_definitions.iter().enumerate() {
        let additional = u32::try_from(i).context("Too many dynamic symbols for .hash")?;
        let sym_index = epilogue
            .dynsym_start_index
            .checked_add(additional)
            .context("Too many dynamic symbols for .hash")?;
        let sym_index_usize =
            usize::try_from(sym_index).context("Too many dynamic symbols for .hash")?;
        let hash = object::elf::hash(sym_def.name);
        let bucket = (hash % sysv_hash_layout.bucket_count) as usize;

        if buckets[bucket] == 0 {
            buckets[bucket] = sym_index;
        } else {
            let last = last_in_bucket[bucket].context("Invalid .hash bucket chain construction")?;
            chains[last] = sym_index;
        }
        last_in_bucket[bucket] = Some(sym_index_usize);
    }

    Ok(())
}

fn write_gnu_hash_tables(
    layout: &Layout,
    epilogue: &EpilogueLayout,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let Some(gnu_hash_layout) = epilogue.format_specific.gnu_hash_layout.as_ref() else {
        return Ok(());
    };

    let buffer = buffers.get_mut(part_id::GNU_HASH);
    let (header, rest) = object::from_bytes_mut::<GnuHashHeader>(buffer)
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
    let (chains, rest) =
        object::slice_from_bytes_mut::<u32>(rest, layout.dynamic_symbol_definitions.len())
            .map_err(|_| error!("Insufficient bytes for .gnu.hash chains"))?;

    debug_assert_eq!(rest.len(), 0);

    // Some buckets and bloom entries might not get written below, so fill with zeros to ensure
    // deterministic output if we're editing in-place.
    buckets.fill(0);
    bloom.fill(0);

    let mut sym_defs = layout.dynamic_symbol_definitions.iter().peekable();

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

fn write_dynamic_symbol_definitions(table_writer: &mut TableWriter, layout: &Layout) -> Result {
    let chunk_size =
        10.max(layout.dynamic_symbol_definitions.len() / 10 / rayon::current_num_threads());

    layout
        .dynamic_symbol_definitions
        .chunks(chunk_size)
        .map(|defs| (defs, table_writer.take_dynsym_prefix(defs)))
        .par_bridge()
        .try_for_each(|(defs, mut table_writer)| {
            for sym_def in defs {
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

                        if let Some(versym) = table_writer.versym.as_mut() {
                            write_symbol_version(versym, sym_def.version)?;
                        }
                    }
                    FileLayout::Dynamic(object) => {
                        write_copy_relocation_dynamic_symbol_definition(
                            sym_def,
                            object,
                            layout,
                            &mut table_writer.dynsym_writer,
                        )?;

                        if let Some(versym) = table_writer.versym.as_mut() {
                            copy_symbol_version(
                                object.object.symbol_versions(),
                                object.symbol_id_range.id_to_offset(sym_def.symbol_id),
                                &object.format_specific_layout.version_mapping,
                                versym,
                            )?;
                        }
                    }
                    FileLayout::LinkerScript(script) => {
                        write_linker_script_dynsym(
                            &mut table_writer.dynsym_writer,
                            layout,
                            sym_def.symbol_id,
                            script,
                        )
                        .with_context(|| {
                            format!(
                                "Failed to write linker script dynsym: {}",
                                layout.symbol_debug(sym_def.symbol_id)
                            )
                        })?;
                    }
                    FileLayout::Prelude(prelude) => {
                        write_prelude_dynsym(
                            &mut table_writer.dynsym_writer,
                            layout,
                            sym_def.symbol_id,
                            prelude,
                        )?;
                        if let Some(versym) = table_writer.versym.as_mut() {
                            write_symbol_version(versym, sym_def.version)?;
                        }
                    }
                    _ => bail!(
                        "Internal error: Unexpected dynamic symbol definition from {:?}. {}",
                        file_layout,
                        layout.symbol_debug(sym_def.symbol_id)
                    ),
                }
            }

            Ok(())
        })
}

/// Writes a symbol that was produced by a linker script.
fn write_linker_script_dynsym(
    dynsym_writer: &mut SymbolTableWriter,
    layout: &Layout,
    symbol_id: SymbolId,
    script: &LinkerScriptLayoutState,
) -> Result {
    let local_index = script
        .internal_symbols
        .symbol_id_range()
        .id_to_offset(symbol_id);

    let info = &script.internal_symbols.symbol_definitions[local_index];

    if matches!(
        info.placement,
        crate::parsing::SymbolPlacement::DefsymSymbol(_, _)
            | crate::parsing::SymbolPlacement::DefsymAbsolute(_)
    ) {
        return write_defsym_dynsym(dynsym_writer, layout, symbol_id, info);
    }

    let section_id = info
        .section_id()
        .context("Tried to export dynamic symbol not associated with a section")?;

    let section_id = layout.output_sections.primary_output_section(section_id);

    let shndx = layout
        .output_sections
        .output_index_of_section(section_id)
        .context("Tried to write dynamic symbol in section that's not being output")?;

    let resolution = layout
        .local_symbol_resolution(symbol_id)
        .with_context(|| format!("Missing resolution for {}", layout.symbol_debug(symbol_id)))?;

    let address = resolution.address()?;
    let name = layout.symbol_db.symbol_name(symbol_id)?;

    let entry = dynsym_writer.define_symbol(false, shndx, address, 0, name.bytes())?;

    entry.set_st_info(object::elf::STB_GLOBAL, object::elf::STT_NOTYPE);

    Ok(())
}

/// Get the section index and type for a symbol.
/// This is used to copy attributes from a target symbol to a defsym alias.
fn get_symbol_attributes(layout: &Layout, symbol_id: SymbolId) -> Result<(u16, u8)> {
    let file_id = layout.symbol_db.file_id_for_symbol(symbol_id);
    let file = layout.symbol_db.file(file_id);

    match file {
        crate::grouping::SequencedInput::Object(obj) => {
            let local_index = symbol_id.to_input(obj.symbol_id_range);
            let sym = obj.parsed.object.symbol(local_index)?;

            let shndx = obj
                .parsed
                .object
                .symbol_section(sym, local_index)?
                .and_then(|section_index| match layout.file_layout(file_id) {
                    FileLayout::Object(obj_layout) => obj_layout
                        .sections
                        .get(section_index.0)
                        .and_then(|slot| match slot {
                            SectionSlot::Loaded(section) => Some(section.output_section_id()),
                            SectionSlot::MergeStrings(section) => {
                                Some(section.part_id.output_section_id())
                            }
                            _ => None,
                        })
                        .and_then(|output_section_id| {
                            layout
                                .output_sections
                                .output_index_of_section(output_section_id)
                        }),
                    _ => None,
                })
                .unwrap_or(object::elf::SHN_ABS);

            let st_type = sym.st_type();

            Ok((shndx, st_type))
        }
        crate::grouping::SequencedInput::LinkerScript(script) => {
            let local_index = symbol_id.to_input(script.symbol_id_range);
            let shndx = script
                .parsed
                .symbol_defs
                .get(local_index.0)
                .and_then(|def_info| def_info.section_id())
                .map_or(object::elf::SHN_ABS, |section_id| {
                    let section_id = layout.output_sections.primary_output_section(section_id);
                    layout
                        .output_sections
                        .output_index_of_section(section_id)
                        .unwrap_or(object::elf::SHN_ABS)
                });

            Ok((shndx, object::elf::STT_NOTYPE))
        }
        _ => {
            // For non-object files (e.g., prelude, epilogue), default to ABS
            Ok((object::elf::SHN_ABS, object::elf::STT_NOTYPE))
        }
    }
}

fn write_prelude_dynsym(
    dynsym_writer: &mut SymbolTableWriter,
    layout: &Layout,
    symbol_id: SymbolId,
    prelude: &PreludeLayout,
) -> Result {
    let offset = symbol_id.offset_from(prelude.internal_symbols.start_symbol_id);
    let def_info = prelude
        .internal_symbols
        .symbol_definitions
        .get(offset)
        .with_context(|| format!("Invalid prelude symbol {}", layout.symbol_debug(symbol_id)))?;

    write_defsym_dynsym(dynsym_writer, layout, symbol_id, def_info)
}

/// Writes a dynsym entry for a symbol defined via --defsym or linker script symbol assignment.
fn write_defsym_dynsym(
    dynsym_writer: &mut SymbolTableWriter,
    layout: &Layout,
    symbol_id: SymbolId,
    def_info: &crate::parsing::InternalSymDefInfo,
) -> Result {
    debug_assert!(matches!(
        def_info.placement,
        crate::parsing::SymbolPlacement::DefsymSymbol(_, _)
            | crate::parsing::SymbolPlacement::DefsymAbsolute(_)
    ));

    let resolution = layout
        .local_symbol_resolution(symbol_id)
        .with_context(|| format!("Missing resolution for {}", layout.symbol_debug(symbol_id)))?;
    let address = resolution.raw_value;
    let name = layout.symbol_db.symbol_name(symbol_id)?;

    // For DefsymSymbol, try to get the attributes (section, type) from the target symbol
    let (shndx, st_type) =
        if let crate::parsing::SymbolPlacement::DefsymSymbol(target_name, _offset) =
            def_info.placement
        {
            let target_symbol_id =
                layout
                    .symbol_db
                    .get_unversioned(&crate::symbol::UnversionedSymbolName::prehashed(
                        target_name.as_bytes(),
                    ));

            if let Some(target_id) = target_symbol_id {
                get_symbol_attributes(layout, target_id)?
            } else {
                return Err(layout
                    .symbol_db
                    .missing_defsym_target_error(def_info.name, target_name));
            }
        } else {
            (object::elf::SHN_ABS, object::elf::STT_NOTYPE)
        };

    let entry = dynsym_writer
        .define_symbol(false, shndx, address, 0, name.bytes())
        .with_context(|| {
            format!(
                "Failed to define dynamic {}",
                layout.symbol_debug(symbol_id)
            )
        })?;
    entry.set_st_info(object::elf::STB_GLOBAL, st_type);

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
            .flags_for_symbol(sym_def.symbol_id)
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
        .copy_symbol_shndx(sym, name, shndx, res.raw_value, ValueFlags::empty())
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
        let output_section_id = match &object.sections[section_index.0] {
            SectionSlot::Loaded(section) => section.output_section_id(),
            SectionSlot::MergeStrings(merge_section) => merge_section.part_id.output_section_id(),
            _ => bail!(
                "Internal error: Defined symbols should always be for a loaded or merge-strings section"
            ),
        };
        let output_section_id = layout
            .output_sections
            .primary_output_section(output_section_id);
        let symbol_id = sym_def.symbol_id;
        let resolution = layout.local_symbol_resolution(symbol_id).with_context(|| {
            format!(
                "Tried to write dynamic symbol definition without a resolution: {}",
                layout.symbol_debug(symbol_id)
            )
        })?;

        // For non-PIE executables, export IFUNC symbols as STT_FUNC pointing to PLT stub.
        // For PIE executables, keep IFUNC as-is.
        if resolution.flags.is_ifunc()
            && layout.symbol_db.output_kind.is_executable()
            && !layout.symbol_db.output_kind.is_relocatable()
            && let Some(plt_address) = resolution.plt_address
        {
            let plt_output_section_id = layout
                .output_sections
                .primary_output_section(output_section_id::PLT_GOT);
            let shndx = dynamic_symbol_writer
                .output_sections
                .output_index_of_section(plt_output_section_id)
                .with_context(|| {
                    format!(
                        "PLT section not found for ifunc symbol `{}`",
                        String::from_utf8_lossy(name),
                    )
                })?;
            let e = LittleEndian;
            let size = sym.st_size(e);
            let entry = dynamic_symbol_writer.define_symbol(
                false,
                shndx,
                plt_address.into(),
                size,
                name,
            )?;
            entry.set_st_info(sym.st_bind(), object::elf::STT_FUNC);
            entry.st_other = sym.st_other();
        } else {
            let mut symbol_value = resolution.raw_value;
            if sym.st_type() == object::elf::STT_TLS {
                symbol_value -= layout.tls_start_address();
            }
            dynamic_symbol_writer
                .copy_symbol(
                    sym,
                    name,
                    output_section_id,
                    symbol_value,
                    ValueFlags::empty(),
                )
                .with_context(|| {
                    format!("Failed to copy dynamic {}", layout.symbol_debug(symbol_id))
                })?;
        }
    } else {
        dynamic_symbol_writer
            .copy_symbol_shndx(sym, name, 0, 0, ValueFlags::empty())
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

        // For DefsymSymbol, get attributes from the target symbol
        let (mut shndx, st_type) = if let crate::parsing::SymbolPlacement::DefsymSymbol(
            target_name,
            _offset,
        ) = def_info.placement
        {
            let target_symbol_id =
                layout
                    .symbol_db
                    .get_unversioned(&crate::symbol::UnversionedSymbolName::prehashed(
                        target_name.as_bytes(),
                    ));

            if let Some(target_id) = target_symbol_id {
                get_symbol_attributes(layout, target_id)?
            } else {
                return Err(layout
                    .symbol_db
                    .missing_defsym_target_error(def_info.name, target_name));
            }
        } else {
            let shndx = def_info
                .section_id()
                .map(|section_id| {
                    let section_id = layout.output_sections.primary_output_section(section_id);

                    layout
                        .output_sections
                        .output_index_of_section(section_id)
                        .with_context(|| {
                            format!(
                                "symbol '{}' in section '{}' that we're not going to output {resolution:?}",
                                layout.symbol_db.symbol_name_for_display(symbol_id),
                                layout.output_sections.display_name(section_id)
                            )
                        })
                })
                .transpose()?
                .unwrap_or(object::elf::SHN_ABS);

            (shndx, def_info.elf_symbol_type.raw())
        };

        // Move symbols that are in our header (section 0) into the first section, otherwise they'll
        // show up as undefined.
        if shndx == 0 {
            shndx = 1;
        }

        let mut address = resolution.value();

        if def_info.elf_symbol_type == stt::TLS {
            address -= layout.tls_start_address();
        }

        // Mandatory RISC-V symbol defined by the default linker script as:
        // __global_pointer$ = MIN(__SDATA_BEGIN__ + 0x800, MAX(__DATA_BEGIN__ + 0x800, __BSS_END__
        // - 0x800));
        if symbol_name.bytes() == GLOBAL_POINTER_SYMBOL_NAME.as_bytes() {
            address += RISCV_TLS_DTV_OFFSET;
        }

        // PROVIDE_HIDDEN symbols should be local, not global
        let st_bind = if def_info.is_hidden {
            object::elf::STB_LOCAL
        } else {
            object::elf::STB_GLOBAL
        };

        let entry = symbol_writer
            .define_symbol(
                st_bind == object::elf::STB_LOCAL,
                shndx,
                address,
                0,
                symbol_name.bytes(),
            )
            .with_context(|| format!("Failed to write {}", layout.symbol_debug(symbol_id)))?;

        entry.set_st_info(st_bind, st_type);
    }
    Ok(())
}

fn write_eh_frame_hdr(table_writer: &mut TableWriter, layout: &Layout) -> Result {
    let header = table_writer.take_eh_frame_hdr();
    header.version = 1;

    header.table_encoding = (gimli::DW_EH_PE_sdata4 | gimli::DW_EH_PE_datarel).0;
    header.frame_pointer_encoding = (gimli::DW_EH_PE_sdata4 | gimli::DW_EH_PE_pcrel).0;
    header.frame_pointer = eh_frame_ptr(layout)?;

    header.count_encoding = (gimli::DW_EH_PE_udata4 | gimli::DW_EH_PE_absptr).0;
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
            inputs.output_kind.is_executable()
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
        |inputs| inputs.output_kind.needs_dynamic(),
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
    DynamicEntryWriter::optional(
        object::elf::DT_HASH,
        |inputs| inputs.has_data_in_section(output_section_id::HASH),
        |inputs| inputs.vma_of_section(output_section_id::HASH),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_GNU_HASH,
        |inputs| inputs.has_data_in_section(output_section_id::GNU_HASH),
        |inputs| inputs.vma_of_section(output_section_id::GNU_HASH),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_FLAGS,
        |inputs| inputs.args.enable_new_dtags && inputs.dt_flags() != 0,
        |inputs| inputs.dt_flags(),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_FLAGS_1,
        |inputs| inputs.dt_flags_1() != 0,
        |inputs| inputs.dt_flags_1(),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_BIND_NOW,
        |inputs| {
            !inputs.args.enable_new_dtags
                && (inputs.dt_flags() & u64::from(object::elf::DF_BIND_NOW)) != 0
        },
        |_inputs| 0,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_SYMBOLIC,
        |inputs| {
            !inputs.args.enable_new_dtags
                && (inputs.dt_flags() & u64::from(object::elf::DF_SYMBOLIC)) != 0
        },
        |_inputs| 0,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_TEXTREL,
        |inputs| {
            !inputs.args.enable_new_dtags
                && (inputs.dt_flags() & u64::from(object::elf::DF_TEXTREL)) != 0
        },
        |_inputs| 0,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_AARCH64_VARIANT_PCS,
        |inputs| inputs.has_variant_pcs && inputs.args.arch == crate::arch::Architecture::AArch64,
        |_inputs| 0,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_RISCV_VARIANT_CC,
        |inputs| inputs.has_variant_pcs && inputs.args.arch == crate::arch::Architecture::RISCV64,
        |_inputs| 0,
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
    has_variant_pcs: bool,
    section_layouts: &'layout OutputSectionMap<OutputRecordLayout>,
    section_part_layouts: &'layout OutputSectionPartMap<OutputRecordLayout>,
    non_addressable_counts: NonAddressableCounts,
    output_kind: OutputKind,
}

impl DynamicEntryInputs<'_> {
    fn dt_flags(&self) -> u64 {
        let mut flags = 0;
        flags |= object::elf::DF_BIND_NOW;

        if !self.output_kind.is_executable() && self.has_static_tls {
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

        if self.output_kind.is_executable() && self.output_kind.is_relocatable() {
            flags |= object::elf::DF_1_PIE;
        }

        if self.args.needs_origin_handling {
            flags |= object::elf::DF_1_ORIGIN;
        }

        if self.output_kind.is_shared_object() {
            if self.args.needs_nodelete_handling {
                flags |= object::elf::DF_1_NODELETE;
            }

            if self.args.z_interpose {
                flags |= object::elf::DF_1_INTERPOSE;
            }
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
        let entry = self
            .out
            .split_off_first_mut()
            .ok_or_else(|| insufficient_allocation(".dynamic"))?;
        let e = LittleEndian;
        entry.d_tag.set(e, u64::from(tag));
        entry.d_val.set(e, value);
        Ok(())
    }

    /// Some dynamic entries aren't used, but we currently allocate space for them anyway. This
    /// makes sure that they're written with zeros.
    fn write_unused(&mut self) {
        loop {
            let Some(entry) = self.out.split_off_first_mut() else {
                return;
            };
            let e = LittleEndian;
            entry.d_tag.set(e, 0);
            entry.d_val.set(e, 0);
        }
    }
}

fn write_section_headers(out: &mut [u8], layout: &Layout) -> Result {
    let entries: &mut [SectionHeader] = slice_from_all_bytes_mut(out);
    let output_sections = &layout.output_sections;
    let mut entries = entries.iter_mut();
    let mut name_offset = 0;
    let info_values = compute_info_values(layout);

    let mut order = layout.output_order.into_iter().peekable();

    while let Some(event) = order.next() {
        let OrderEvent::Section(section_id) = event else {
            continue;
        };

        let output_info = output_sections.output_info(section_id);
        let section_type = output_info.ty;
        let section_layout = layout.merged_section_layouts.get(section_id);

        if output_sections
            .output_index_of_section(section_id)
            .is_none()
        {
            continue;
        }

        let entsize = output_info.entsize.max(section_id.element_size());
        let size;
        let alignment;

        if section_type == sht::NULL {
            size = 0;
            alignment = 0;
        } else {
            size = section_layout.mem_size;
            alignment = section_layout.alignment.value();

            while let Some(OrderEvent::Section(next_section_id)) = order.peek()
                && let Some(primary_id) = output_sections.merge_target(*next_section_id)
            {
                debug_assert_bail!(
                    primary_id == section_id,
                    "Section order mismatch {} != {}",
                    output_sections.section_debug(primary_id),
                    output_sections.section_debug(section_id),
                );
                order.next();
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
        entry.sh_info.set(e, *info_values.get(section_id));
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

/// Computes the value of the info field for all the section headers.
fn compute_info_values(layout: &Layout) -> OutputSectionMap<u32> {
    let mut infos = layout.output_sections.new_section_map();

    // .rela.plt contains relocations for .got, so should link to it.
    *infos.get_mut(output_section_id::RELA_PLT) = u32::from(
        layout
            .output_sections
            .output_index_of_section(output_section_id::GOT)
            .unwrap_or(0),
    );

    // The only local we ever write to .dynsym is the null symbol, so this is unconditionally 1.
    *infos.get_mut(output_section_id::DYNSYM) = 1;

    *infos.get_mut(output_section_id::GNU_VERSION_D) =
        layout.non_addressable_counts.verdef_count.into();

    *infos.get_mut(output_section_id::GNU_VERSION_R) =
        layout.non_addressable_counts.verneed_count as u32;

    // For SYMTAB, the info field holds the index of the first non-local symbol.
    *infos.get_mut(output_section_id::SYMTAB_LOCAL) = (layout
        .section_part_layouts
        .get(part_id::SYMTAB_LOCAL)
        .file_size
        / size_of::<elf::SymtabEntry>())
        as u32;

    infos
}

fn write_section_header_strings(
    mut out: &mut [u8],
    sections: &OutputSections,
    output_order: &OutputOrder,
) {
    for event in output_order {
        if let OrderEvent::Section(id) = event
            && sections.output_index_of_section(id).is_some()
            && let Some(name) = sections.name(id)
        {
            let name_out = out.split_off_mut(..=name.len()).unwrap();
            name_out[..name.len()].copy_from_slice(name.bytes());
            name_out[name.len()] = 0;
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
        self.headers
            .split_off_first_mut()
            .ok_or_else(|| error!("Insufficient header slots"))
    }
}

fn write_internal_symbols_plt_got_entries<
    'data,
    P: Platform<'data, File = crate::elf::File<'data>>,
>(
    internal_symbols: &InternalSymbols,
    table_writer: &mut TableWriter,
    layout: &Layout<'data>,
) -> Result {
    for i in 0..internal_symbols.symbol_definitions.len() {
        let symbol_id = internal_symbols.start_symbol_id.add_usize(i);
        if !layout.symbol_db.is_canonical(symbol_id) {
            continue;
        }
        if let Some(res) = layout.local_symbol_resolution(symbol_id) {
            table_writer
                .process_resolution::<P>(Some(layout), res)
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

fn write_dynamic_file<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    object: &DynamicLayout,
    table_writer: &mut TableWriter,
    layout: &Layout<'data>,
) -> Result {
    verbose_timing_phase!("Write dynamic");

    write_so_name(object, table_writer)?;

    write_copy_relocations::<P>(object, table_writer, layout)?;

    for ((symbol_id, resolution), symbol) in layout
        .resolutions_in_range(object.symbol_id_range)
        .zip(object.object.symbols.iter())
    {
        if layout.symbol_db.args.got_plt_syms {
            write_got_plt_syms(layout, &mut table_writer.debug_symbol_writer, symbol_id)?;
        }
        if let Some(res) = resolution {
            let name = object.object.symbol_name(symbol)?;

            if res.flags.needs_copy_relocation() {
                // Symbol needs a copy relocation, which means that the dynamic symbol will be
                // written by the epilogue not by us. However, we do need to write a regular
                // symtab entry.
                table_writer.debug_symbol_writer.copy_symbol(
                    symbol,
                    name,
                    output_section_id::BSS,
                    res.value(),
                    ValueFlags::empty(),
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
                    copy_symbol_version(
                        object.object.symbol_versions(),
                        object.symbol_id_range.id_to_offset(symbol_id),
                        &object.format_specific_layout.version_mapping,
                        versym,
                    )?;
                }
            }

            table_writer
                .process_resolution::<P>(Some(layout), res)
                .with_context(|| format!("Failed to write {}", layout.symbol_debug(symbol_id)))?;
        }
    }

    if let Some(verneed_info) = &object.format_specific_layout.verneed_info {
        let mut verdefs = verneed_info.defs.clone();
        let e = LittleEndian;

        let strings = object.object.sections.strings(
            e,
            object.object.data,
            verneed_info.string_table_index,
        )?;

        let ver_need = table_writer.version_writer.take_verneed()?;

        let next_verneed_offset = if object.format_specific_layout.is_last_verneed {
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
                .format_specific_layout
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
                aux_out.vna_flags.set(e, 0);
                aux_index += 1;
            }
        }
        debug_assert_eq!(aux_index, auxes.len());
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

fn write_copy_relocations<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
    object: &DynamicLayout,
    table_writer: &mut TableWriter,
    layout: &Layout,
) -> Result {
    for &symbol_id in &object.copy_relocation_symbols {
        write_copy_relocation_for_symbol::<P>(symbol_id, table_writer, layout).with_context(
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

fn write_copy_relocation_for_symbol<'data, P: Platform<'data, File = crate::elf::File<'data>>>(
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
        P::get_dynamic_relocation_type(DynamicRelocationKind::Copy),
        0,
    )
}

fn copy_symbol_version(
    versym_in: &[Versym],
    local_symbol_index: usize,
    version_mapping: &[u16],
    versym_out: &mut &mut [Versym],
) -> Result {
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

    write_symbol_version(versym_out, output_version)
}

fn write_symbol_version(versym_out: &mut &mut [Versym], version: u16) -> Result {
    versym_out
        .split_off_first_mut()
        .context("Insufficient .gnu.version allocation")?
        .0
        .set(LittleEndian, version);

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
        let lib_name_out = self.out.split_off_mut(..len_with_terminator).unwrap();
        lib_name_out[..str.len()].copy_from_slice(str);
        lib_name_out[str.len()] = 0;
        let offset = self.next_offset;
        self.next_offset += len_with_terminator as u32;
        offset
    }

    fn take_prefix(&mut self, size: usize) -> Self {
        let next_offset = self.next_offset;
        self.next_offset += size as u32;

        Self {
            next_offset,
            out: self.out.split_off_mut(..size).unwrap(),
        }
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
    let mut all_mem: &mut [u8] = transmute_mut!(all_mem.as_mut_slice());
    let mut offset = 0;
    let mut buffers = mem_sizes.output_order_map(output_order, |_part_id, alignment, &size| {
        let aligned_offset = alignment.align_up(offset);
        all_mem
            .split_off_mut(..(aligned_offset - offset) as usize)
            .unwrap();
        offset = aligned_offset + size;
        all_mem.split_off_mut(..size as usize).unwrap()
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
    table_writer.process_resolution::<crate::elf_x86_64::ElfX86_64>(None, resolution)?;
    table_writer.validate_empty(mem_sizes)
}

impl<R> Default for RelocationCache<R> {
    fn default() -> Self {
        Self {
            previous: Default::default(),
            high_part_symbols: Default::default(),
        }
    }
}
