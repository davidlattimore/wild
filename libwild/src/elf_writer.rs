use self::elf::get_page_mask;
use crate::OutputFileData;
use crate::OutputKind;
use crate::alignment;
use crate::args::elf::BuildIdOption;
use crate::args::elf::ElfArgs;
use crate::bail;
use crate::debug_assert_bail;
use crate::elf;
use crate::elf::DynamicEntry;
use crate::elf::EhFrameHdr;
use crate::elf::EhFrameHdrEntry;
use crate::elf::ElfClass;
use crate::elf::ElfWord as _;
use crate::elf::GLOBAL_POINTER_SYMBOL_NAME;
use crate::elf::GNU_NOTE_NAME;
use crate::elf::GnuHashHeader;
use crate::elf::NonAddressableCounts;
use crate::elf::NoteProperty;
use crate::elf::RawSymbolName;
use crate::elf::RiscVAttribute;
use crate::elf::Verdaux;
use crate::elf::Verdef;
use crate::elf::Vernaux;
use crate::elf::Verneed;
use crate::elf::VersionDef;
use crate::elf::Versym;
use crate::elf::output_section_id;
use crate::elf::part_id;
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
use crate::linker_script::Expression;
use crate::malfunction;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputOrder;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_id::SectionIdentity;
use crate::output_section_id::SectionName;
use crate::output_section_id::SectionOutputInfo;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::output_trace::HexU64;
use crate::output_trace::TraceOutput;
use crate::parsing::SymbolLoc;
use crate::part_id::PartId;
use crate::platform;
use crate::platform::Arch;
use crate::platform::Args as _;
use crate::platform::ObjectFile;
use crate::platform::Platform;
use crate::platform::PreviousRelocationInfo;
use crate::platform::RawSymbolName as _;
use crate::platform::Relaxation as _;
use crate::platform::Relocation;
use crate::platform::RelocationList;
use crate::platform::SectionAttributes as _;
use crate::platform::SectionFlags as _;
use crate::platform::SectionHeader as _;
use crate::platform::SectionType as _;
use crate::resolution::SectionSlot;
use crate::sframe;
use crate::sharding::ShardKey;
use crate::string_merging::get_merged_string_output_address;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::thunks::ThunkBlockId;
use crate::timing_phase;
use crate::value_flags::PerSymbolFlags;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use crate::writable_elf::WritableDynamicEntry as _;
use crate::writable_elf::WritableFileHeader as _;
use crate::writable_elf::WritableNoteHeader as _;
use crate::writable_elf::WritableProgramHeader as _;
use crate::writable_elf::WritableRela as _;
use crate::writable_elf::WritableRelr as _;
use crate::writable_elf::WritableSectionHeader as _;
use crate::writable_elf::WritableSymbol as _;
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
use linker_utils::elf::secnames;
use linker_utils::elf::secnames::DEBUG_LOC_SECTION_NAME;
use linker_utils::elf::secnames::DEBUG_RANGES_SECTION_NAME;
use linker_utils::elf::secnames::DYNSYM_SECTION_NAME_STR;
use linker_utils::elf::secnames::NOTE_GNU_BUILD_ID_SECTION_NAME_STR;
use linker_utils::elf::shf;
use linker_utils::elf::sht;
use linker_utils::loongarch64::highest_relocation_with_bias;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::relaxation::SectionRelaxDeltas;
use linker_utils::relaxation::opt_input_to_output;
use linker_utils::utils::slice_from_all_bytes_mut;
use object::LittleEndian;
use object::SymbolIndex;
use object::elf::NT_GNU_BUILD_ID;
use object::elf::NT_GNU_PROPERTY_TYPE_0;
use object::elf::STT_TLS;
use object::from_bytes_mut;
use object::read::elf::Crel;
use object::read::elf::SectionHeader as _;
use object::read::elf::Sym as _;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator as _;
use rayon::iter::IntoParallelRefMutIterator as _;
use rayon::iter::ParallelBridge as _;
use rayon::iter::ParallelIterator as _;
use rayon::slice::ParallelSliceMut as _;
use std::collections::BTreeMap;
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

type ElfLayout<'data, C> = Layout<'data, elf::Elf<C>>;

/// A cache for managing ELF relocations and optimization of relocation entries.
#[derive(Debug)]
struct RelocationCache<R> {
    /// The last relocation entry processed, used to optimize consecutive relocations.
    previous: Option<R>,
    /// A cache mapping symbol addresses to their relocation entries, optimizing
    /// lookups for relocations involving the high parts of address.
    high_part_symbols: HashMap<u64, R>,
}

#[derive(Clone, Copy)]
enum SymbolSection {
    /// One of the SHN values.
    Raw(object::elf::SymbolSection),
    Index(u32),
}

impl From<object::elf::SymbolSection> for SymbolSection {
    fn from(value: object::elf::SymbolSection) -> Self {
        SymbolSection::Raw(value)
    }
}

pub(crate) fn write<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    sized_output: &mut SizedOutput<impl OutputFileData>,
    layout: &ElfLayout<'data, C>,
) -> Result {
    write_file_contents::<C, A>(sized_output, layout)?;
    if layout.args().common().validate_output {
        crate::validation::validate_bytes(layout, &sized_output.out)?;
    }

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;

    if layout.args().should_write_eh_frame_hdr
        && layout
            .section_layouts
            .get(output_section_id::EH_FRAME_HDR)
            .mem_size
            > 0
    {
        sort_eh_frame_hdr_entries(section_buffers.get_mut(output_section_id::EH_FRAME_HDR));
    }

    write_sframe_section(section_buffers.get_mut(output_section_id::SFRAME), layout)?;

    write_gnu_build_id_note(sized_output, &layout.args().build_id, layout)?;
    Ok(())
}

fn write_gnu_build_id_note<C: ElfClass>(
    sized_output: &mut SizedOutput<impl OutputFileData>,
    build_id_option: &BuildIdOption,
    layout: &ElfLayout<C>,
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

    let mut buffers = split_output_into_sections(layout, &mut sized_output.out).0;
    let (note_header, mut rest) =
        from_bytes_mut::<elf::NoteHeader<C>>(buffers.get_mut(output_section_id::NOTE_GNU_BUILD_ID))
            .map_err(|_| insufficient_allocation(NOTE_GNU_BUILD_ID_SECTION_NAME_STR))?;
    note_header.set_name_size(GNU_NOTE_NAME.len() as u32);
    note_header.set_descriptor_size(build_id.len() as u32);
    note_header.set_type(NT_GNU_BUILD_ID);

    let name_out = rest.split_off_mut(..GNU_NOTE_NAME.len()).unwrap();
    name_out.copy_from_slice(GNU_NOTE_NAME);

    rest.copy_from_slice(build_id);

    Ok(())
}

fn compute_hash(sized_output: &SizedOutput<impl OutputFileData>) -> blake3::Hash {
    timing_phase!("Compute build ID");
    blake3::Hasher::new()
        .update_rayon(&sized_output.out)
        .finalize()
}

fn write_file_contents<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    sized_output: &mut SizedOutput<impl OutputFileData>,
    layout: &ElfLayout<'data, C>,
) -> Result {
    timing_phase!("Write data to file");
    let (mut section_buffers, padding) = split_output_into_sections(layout, &mut sized_output.out);

    fill_padding_for_sections::<C, A>(layout, padding);

    let sym_index_map = if layout.args().should_output_partial_object() {
        build_sym_index_map(layout)
    } else {
        Vec::new()
    };

    let mut writable_buckets = split_buffers_by_alignment(&mut section_buffers, layout);
    let groups_and_buffers = split_output_by_group(layout, &mut writable_buckets);
    groups_and_buffers
        .into_par_iter()
        .with_max_len(1)
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
                write_file::<C, A>(
                    file,
                    &mut buffers,
                    &mut table_writer,
                    layout,
                    &sized_output.trace,
                    &sym_index_map,
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

fn fill_padding_for_sections<C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    layout: &Layout<'_, elf::Elf<C>>,
    padding: crate::file_writer::PaddingSlices<'_>,
) {
    timing_phase!("Fill padding for sections");

    for pslice in padding.slices {
        if let Some(section_id) = pslice.parent_section_id {
            let section_info = layout.output_sections.output_info(section_id);
            fill_section_padding::<C, A>(pslice.slice, section_info);
        } else {
            pslice.slice.fill(0);
        }
    }
}

fn fill_padding(mut section_buffers: OutputSectionMap<&mut [u8]>) {
    section_buffers.for_each_mut(|_, out| {
        out.fill(0);
    });
}

fn write_sframe_section<C: ElfClass>(sframe_buffer: &mut [u8], layout: &ElfLayout<C>) -> Result {
    if layout.args().discard_sframe || sframe_buffer.is_empty() {
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

    sframe::sort_sframe_section(
        sframe_buffer,
        sframe_start_address,
        &sframe_ranges,
        layout.symbol_db.args,
    )
}

fn sort_eh_frame_hdr_entries(eh_frame_hdr: &mut [u8]) {
    timing_phase!("Sort .eh_frame_hdr");
    let entry_bytes = &mut eh_frame_hdr[size_of::<elf::EhFrameHdr>()..];
    let entries = <[elf::EhFrameHdrEntry]>::mut_from_bytes(entry_bytes).unwrap();
    entries.par_sort_by_key(|e| e.frame_ptr);
}

fn write_program_headers<C: ElfClass>(
    program_headers_out: &mut ProgramHeaderWriter<'_, C>,
    layout: &ElfLayout<C>,
) -> Result {
    if layout.args().should_output_partial_object() {
        return Ok(());
    }
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

        let segment_details = layout.program_segments.segment_def(segment_id);

        segment_header.set_type(segment_details.segment_type);

        // Support executable stack (Wild defaults to non-executable stack)
        let mut segment_flags = segment_details.segment_flags;
        if layout.program_segments.is_stack_segment(segment_id) && layout.args().execstack {
            segment_flags |= pf::EXECUTABLE;
        }

        segment_header.set_flags(segment_flags);
        segment_header.set_offset(segment_sizes.file_offset as u64)?;
        segment_header.set_virtual_address(segment_sizes.mem_offset)?;
        segment_header.set_physical_address(segment_sizes.lma_offset)?;
        segment_header.set_file_size(segment_sizes.file_size as u64)?;
        segment_header.set_memory_size(segment_sizes.mem_size)?;
        segment_header.set_alignment(alignment.value())?;
    }
    Ok(())
}

fn populate_file_header<C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    layout: &ElfLayout<C>,
    header_info: &HeaderInfo,
    header: &mut elf::FileHeader<C>,
) -> Result {
    let output_kind = layout.symbol_db.output_kind;
    let mut ty = if output_kind.is_partial_link() {
        object::elf::ET_REL
    } else if output_kind.is_position_independent() {
        object::elf::ET_DYN
    } else {
        object::elf::ET_EXEC
    };

    if malfunction::malfunction_point("elf-incorrect-type") {
        ty = object::elf::ET_CORE;
    }

    let ident = header.ident_mut();
    ident.magic = object::elf::ELFMAG;
    ident.class = elf::FileHeader::<C>::CLASS;
    ident.data = object::elf::ELFDATA2LSB;
    ident.version = object::elf::EV_CURRENT;
    ident.os_abi = object::elf::ELFOSABI_NONE;
    ident.abi_version = 0;
    ident.padding = Default::default();
    header.set_type(ty);
    header.set_machine(A::arch_identifier());
    header.set_version(object::elf::EV_CURRENT.0.into());
    header.set_entry(elf_entry_address(layout)?)?;
    header.set_program_header_offset(if output_kind.is_partial_link() {
        0
    } else {
        u64::from(C::FILE_HEADER_SIZE)
    })?;
    header.set_section_header_offset(
        u64::from(C::FILE_HEADER_SIZE) + crate::elf::program_headers_size::<C>(header_info),
    )?;
    header.set_flags(layout.format_specific.eflags);
    header.set_header_size(C::FILE_HEADER_SIZE);
    header.set_program_header_entry_size(if output_kind.is_partial_link() {
        0
    } else {
        C::PROGRAM_HEADER_SIZE
    });
    header.set_program_header_count(header_info.active_segment_ids.len() as u16);
    header.set_section_header_entry_size(C::SECTION_HEADER_SIZE);
    let shnum = header_info.num_output_sections_with_content;
    header.set_section_header_count(if shnum >= u32::from(object::elf::SHN_LORESERVE) {
        0
    } else {
        shnum as u16
    });
    let shstrndx = layout
        .output_sections
        .output_index_of_section(output_section_id::SHSTRTAB)
        .expect("we always write .shstrtab");
    header.set_section_name_table_index(object::elf::SymbolSection::new(shstrndx));
    Ok(())
}

fn elf_entry_address<C: ElfClass>(layout: &ElfLayout<C>) -> Result<u64> {
    if layout.args().should_output_partial_object() {
        return Ok(0);
    }

    let entry_name = match layout.symbol_db.entry_point() {
        crate::platform::EntryPoint::None => return Ok(0),
        crate::platform::EntryPoint::Address(address) => return Ok(address),
        crate::platform::EntryPoint::Symbol(name) => name,
    };

    if let Some(address) = layout.resolved_entry_symbol_address()? {
        return Ok(address);
    }
    if layout.symbol_db.output_kind == OutputKind::SharedObject {
        return Ok(0);
    }

    let entry_name = String::from_utf8_lossy(entry_name);
    let text_layout = layout.section_layouts.get(output_section_id::TEXT);
    if text_layout.mem_size == 0 {
        layout.symbol_db.warning(format!(
            "cannot find entry symbol `{entry_name}` and .text is empty, not setting entry point"
        ));
        return Ok(0);
    }

    layout.symbol_db.warning(format!(
        "cannot find entry symbol `{entry_name}`, defaulting to 0x{:x}",
        text_layout.mem_offset
    ));
    Ok(text_layout.mem_offset)
}

fn write_file<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    file: &FileLayout<'data, elf::Elf<C>>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<'data, C>,
    trace: &TraceOutput,
    sym_index_map: &[Option<u32>],
) -> Result {
    match file {
        FileLayout::Object(s) => {
            write_object::<C, A>(s, buffers, table_writer, layout, trace, sym_index_map)?;
        }
        FileLayout::Prelude(s) => write_prelude::<C, A>(s, buffers, table_writer, layout)?,
        FileLayout::Epilogue(s) => write_epilogue::<C, A>(s, buffers, table_writer, layout, trace)?,
        FileLayout::SyntheticSymbols(s) => {
            write_synthetic_symbols::<C, A>(s, table_writer, layout)?;
        }
        FileLayout::LinkerScript(s) => write_linker_script_state::<C, A>(s, table_writer, layout)?,
        FileLayout::NotLoaded | FileLayout::StubLibrary(_) => {}
        FileLayout::Dynamic(s) => write_dynamic_file::<C, A>(s, table_writer, layout)?,
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

    fn set_next_symbol_version(&mut self, index: object::elf::VersionIndex) -> Result {
        if let Some(versym_table) = self.versym.as_mut() {
            let versym = versym_table
                .split_off_first_mut()
                .ok_or_else(|| insufficient_allocation(".gnu.version"))?;
            versym.0.set(LittleEndian, index.into());
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
                mem_sizes.get(part_id::GNU_VERSION),
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

struct TableWriter<'layout, 'out, C: ElfClass> {
    output_kind: OutputKind,
    got: &'out mut [elf::Word<C>],
    got_relr: &'out mut [elf::Word<C>],
    plt_got: &'out mut [u8],
    rela_plt: &'out mut [elf::Rela<C>],
    tls: Range<u64>,
    rela_dyn_relative: &'out mut [elf::Rela<C>],
    rela_dyn_general: &'out mut [elf::Rela<C>],
    relr_dyn: Option<&'out mut [elf::Relr<C>]>,
    current_relr_dyn: Option<&'out mut elf::Relr<C>>,
    /// RELR run state for bitmap packing.
    relr_writer: elf::RelrEncoder<C>,
    dynsym_writer: SymbolTableWriter<'layout, 'out, C>,
    debug_symbol_writer: SymbolTableWriter<'layout, 'out, C>,
    eh_frame_start_address: u64,
    eh_frame: &'out mut [u8],

    /// Note, this is stored as raw bytes because it starts with an EhFrameHdr, but is then
    /// followed by multiple EhFrameHdrEntry.
    eh_frame_hdr: &'out mut [u8],

    dynamic: DynamicEntriesWriter<'out, C>,
    version_writer: VersionWriter<'out>,

    section_headers: &'out mut [elf::SectionHeader<C>],
    shstrtab: &'out mut [u8],
}

impl<'layout, 'out, C: ElfClass> TableWriter<'layout, 'out, C> {
    fn from_layout(
        layout: &'layout ElfLayout<C>,
        dynstr_start_offset: u32,
        strtab_start_offset: u32,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
        eh_frame_start_address: u64,
    ) -> TableWriter<'layout, 'out, C> {
        let dynsym_writer = SymbolTableWriter::<C>::new_dynamic(
            dynstr_start_offset,
            buffers,
            &layout.output_sections,
        );
        let debug_symbol_writer =
            SymbolTableWriter::<C>::new(strtab_start_offset, buffers, &layout.output_sections);

        Self::new(
            layout.symbol_db.output_kind,
            layout.tls_start_address()..layout.tls_end_address(),
            buffers,
            dynsym_writer,
            debug_symbol_writer,
            eh_frame_start_address,
            layout.symbol_db.args.is_relr_enabled(),
        )
    }

    fn new(
        output_kind: OutputKind,
        tls: Range<u64>,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
        dynsym_writer: SymbolTableWriter<'layout, 'out, C>,
        debug_symbol_writer: SymbolTableWriter<'layout, 'out, C>,
        eh_frame_start_address: u64,
        pack_relative_relocs: bool,
    ) -> TableWriter<'layout, 'out, C> {
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
            got: <[elf::Word<C>]>::mut_from_bytes(buffers.take(part_id::GOT)).unwrap(),
            got_relr: <[elf::Word<C>]>::mut_from_bytes(buffers.take(part_id::GOT_RELR)).unwrap(),
            plt_got: buffers.take(part_id::PLT_GOT),
            rela_plt: slice_from_all_bytes_mut(buffers.take(part_id::RELA_PLT)),
            tls,
            rela_dyn_relative: slice_from_all_bytes_mut(buffers.take(part_id::RELA_DYN_RELATIVE)),
            rela_dyn_general: slice_from_all_bytes_mut(buffers.take(part_id::RELA_DYN_GENERAL)),
            relr_dyn: pack_relative_relocs
                .then(|| slice_from_all_bytes_mut(buffers.take(part_id::RELR_DYN)))
                .filter(|b| !b.is_empty()),
            current_relr_dyn: None,
            relr_writer: elf::RelrEncoder::<C>::default(),
            dynsym_writer,
            debug_symbol_writer,
            eh_frame_start_address,
            eh_frame,
            eh_frame_hdr,
            dynamic,
            version_writer,
            section_headers: slice_from_all_bytes_mut(buffers.take(part_id::SECTION_HEADERS)),
            shstrtab: buffers.take(part_id::SHSTRTAB),
        }
    }

    fn section_header_count(&self) -> usize {
        self.section_headers.len()
    }

    fn take_section_header(&mut self) -> Result<&'out mut elf::SectionHeader<C>> {
        self.section_headers
            .split_off_first_mut()
            .ok_or_else(|| insufficient_allocation("section headers"))
    }

    fn write_section_header_string(&mut self, string: &[u8]) -> Result {
        let len_with_terminator = string.len() + 1;
        let out = self
            .shstrtab
            .split_off_mut(..len_with_terminator)
            .ok_or_else(|| insufficient_allocation(".shstrtab"))?;
        out[..string.len()].copy_from_slice(string);
        out[string.len()] = 0;
        Ok(())
    }

    fn process_resolution<'data, A: Arch<Platform = elf::Elf<C>>>(
        &mut self,
        layout: Option<&ElfLayout<'data, C>>,
        args: &ElfArgs,
        res: &Resolution<elf::Elf<C>>,
    ) -> Result {
        let Some(got_address) = res.format_specific.got_address else {
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
                self.process_got_tls_offset::<A>(
                    res,
                    layout.context("Layout must be present")?,
                    got_address,
                )?;
                got_address += C::GOT_ENTRY_SIZE;
            }
            if flags.needs_got_tls_module() {
                self.process_got_tls_mod_and_offset::<A>(res, args, got_address)?;
                got_address += 2 * C::GOT_ENTRY_SIZE;
            }
            if flags.needs_got_tls_descriptor() {
                self.process_got_tls_descriptor::<A>(res, args, got_address)?;
            }
            return Ok(());
        }

        let has_dynamic_symbol =
            res.flags.is_dynamic() || (flags.needs_export_dynamic() && res.flags.is_interposable());
        let is_got_relr =
            crate::elf::is_got_relr_eligible(res.flags, has_dynamic_symbol, args, self.output_kind);
        let got_entry = if is_got_relr {
            self.take_next_got_relr_entry()?
        } else {
            self.take_next_got_entry()?
        };
        if res.flags.needs_canonical_plt() {
            *got_entry = elf::Word::<C>::from_u64(0)?;
            self.write_jump_slot_relocation::<A>(got_address, res.dynamic_symbol_index()?)?;
        } else if res.flags.is_dynamic()
            || (flags.needs_export_dynamic() && res.flags.is_interposable())
                && !res.flags.is_ifunc()
        {
            *got_entry = elf::Word::<C>::from_u64(0)?;
            debug_assert_bail!(
                compute_allocations::<elf::Elf<C>>(res, self.output_kind, args)
                    .get(part_id::RELA_DYN_GENERAL)
                    > 0,
                "Tried to write glob-dat with no allocation. {}",
                res.flags
            );
            self.write_dynamic_symbol_relocation::<A>(
                got_address,
                0,
                res.dynamic_symbol_index()?,
                DynamicRelocationKind::GotEntry,
            )?;
        } else if res.flags.is_ifunc() {
            *got_entry = elf::Word::<C>::from_u64(0)?;
            self.write_ifunc_relocation::<A>(res)?;
        } else {
            let value = if is_got_relr {
                // GOT_RELR entries are bitmap-packed by write_got_relr_bitmap — just store value.
                res.raw_value
            } else if res.flags.has_link_time_address()
                && self.output_kind.is_position_independent()
            {
                self.write_relr_entry_flat::<A>(got_address, res.raw_value)?
            } else {
                res.raw_value
            };
            *got_entry = elf::Word::<C>::from_u64(value)?;
        }
        if let Some(plt_address) = res.format_specific.plt_address {
            self.write_plt_entry::<A>(got_address, plt_address.get())?;
        }

        // For ifunc symbols with GOT-relative references, write the PLT stub
        // address to the separate GOT entry. This ensures that all references to the IFUNC
        // return the same address (the PLT stub), regardless of whether they go through the
        // PLT or directly through GOT.
        if res.flags.needs_ifunc_got_for_address() {
            let ifunc_got_address = got_address + C::GOT_ENTRY_SIZE;
            let got_entry = self.take_next_got_entry()?;
            let plt_address = res.plt_address()?;
            let value = if self.output_kind.is_position_independent() {
                self.write_relr_entry_flat::<A>(ifunc_got_address, plt_address)?
            } else {
                plt_address
            };
            *got_entry = elf::Word::<C>::from_u64(value)?;
        }

        if res.flags.needs_canonical_plt_got_for_address() {
            let address_got_address = got_address + C::GOT_ENTRY_SIZE;
            *self.take_next_got_entry()? = elf::Word::<C>::from_u64(0)?;

            self.write_dynamic_symbol_relocation::<A>(
                address_got_address,
                0,
                res.dynamic_symbol_index()?,
                DynamicRelocationKind::GotEntry,
            )?;
        }

        Ok(())
    }

    fn process_got_tls_offset<'data, A: Arch<Platform = elf::Elf<C>>>(
        &mut self,
        res: &Resolution<elf::Elf<C>>,
        layout: &ElfLayout<'data, C>,
        got_address: u64,
    ) -> Result {
        let got_entry = self.take_next_got_entry()?;
        if res.flags.is_dynamic()
            || (res.flags.needs_export_dynamic() && res.flags.is_interposable())
        {
            *got_entry = elf::Word::<C>::from_u64(0)?;
            return self.write_tpoff_relocation::<A>(got_address, res.dynamic_symbol_index()?, 0);
        }
        let address = res.raw_value;
        if address == 0 {
            // Resolution is undefined.
            *got_entry = elf::Word::<C>::from_u64(0)?;
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

            *got_entry =
                elf::Word::<C>::from_u64(address.wrapping_sub(A::tp_offset_start(layout)))?;
        } else {
            debug_assert_bail!(
                compute_allocations::<elf::Elf<C>>(res, self.output_kind, layout.args())
                    .get(part_id::RELA_DYN_GENERAL)
                    > 0,
                "Tried to write tpoff with no allocation. {}",
                res.flags
            );
            self.write_tpoff_relocation::<A>(got_address, 0, address.sub(self.tls.start) as i64)?;
        }
        Ok(())
    }

    fn process_got_tls_mod_and_offset<A: Arch<Platform = elf::Elf<C>>>(
        &mut self,
        res: &Resolution<elf::Elf<C>>,
        args: &ElfArgs,
        got_address: u64,
    ) -> Result {
        let got_entry = self.take_next_got_entry()?;
        if self.output_kind.is_executable() && !res.flags.is_dynamic() {
            *got_entry = elf::Word::<C>::from_u64(elf::CURRENT_EXE_TLS_MOD)?;
        } else {
            *got_entry = elf::Word::<C>::from_u64(0)?;
            let dynamic_symbol_index = res.dynamic_symbol_index.map_or(0, std::num::NonZero::get);
            debug_assert_bail!(
                compute_allocations::<elf::Elf<C>>(res, self.output_kind, args)
                    .get(part_id::RELA_DYN_GENERAL)
                    > 0,
                "Tried to write dtpmod with no allocation. {}",
                res.flags
            );
            self.write_dtpmod_relocation::<A>(got_address, dynamic_symbol_index)?;
        }
        let offset_entry = self.take_next_got_entry()?;
        if let Some(dynamic_symbol_index) = res.dynamic_symbol_index {
            if res.flags.is_interposable() {
                self.write_dtpoff_relocation::<A>(
                    got_address + C::GOT_ENTRY_SIZE,
                    dynamic_symbol_index.get(),
                )?;
            }
            *offset_entry = elf::Word::<C>::from_u64(0)?;
            return Ok(());
        }
        // Convert the address to an offset within the TLS segment
        let address = res.address()?;
        *offset_entry = elf::Word::<C>::from_u64(
            address
                .wrapping_sub(self.tls.start)
                .wrapping_sub(A::get_dtv_offset()),
        )?;
        Ok(())
    }

    fn process_got_tls_descriptor<A: Arch<Platform = elf::Elf<C>>>(
        &mut self,
        res: &Resolution<elf::Elf<C>>,
        args: &ElfArgs,
        got_address: u64,
    ) -> Result {
        // TLS descriptor occupies 2 entries
        *self.take_next_got_entry()? = elf::Word::<C>::from_u64(0)?;
        *self.take_next_got_entry()? = elf::Word::<C>::from_u64(0)?;

        ensure!(
            !self.output_kind.is_static_executable(),
            "Cannot create dynamic TLSDESC relocation (function trampoline will be missed) for a static executable"
        );

        let dynamic_symbol_index = res.dynamic_symbol_index.map_or(0, std::num::NonZero::get);
        debug_assert_bail!(
            compute_allocations::<elf::Elf<C>>(res, self.output_kind, args)
                .get(part_id::RELA_DYN_GENERAL)
                > 0,
            "Tried to write TLS descriptor with no allocation. {}",
            res.flags
        );
        let addend = if res.dynamic_symbol_index.is_none() {
            res.raw_value.sub(self.tls.start) as i64
        } else {
            0
        };
        self.write_tls_descriptor_relocation::<A>(got_address, dynamic_symbol_index, addend)?;

        Ok(())
    }

    fn write_plt_entry<A: Arch<Platform = elf::Elf<C>>>(
        &mut self,
        got_address: u64,
        plt_address: u64,
    ) -> Result {
        let plt_entry = self.take_plt_got_entry()?;
        A::write_plt_entry(plt_entry, got_address, plt_address)
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

    fn take_next_got_entry(&mut self) -> Result<&'out mut elf::Word<C>> {
        self.got
            .split_off_first_mut()
            .ok_or_else(|| insufficient_allocation(".got"))
    }

    fn take_next_got_relr_entry(&mut self) -> Result<&'out mut elf::Word<C>> {
        self.got_relr
            .split_off_first_mut()
            .ok_or_else(|| insufficient_allocation(".got (relr)"))
    }

    /// Resets RELR run state between input sections.
    /// Layout tracks runs per-section; writer must do the same to stay in sync.
    fn reset_relr_run(&mut self) {
        self.relr_writer = elf::RelrEncoder::<C>::default();
        self.current_relr_dyn = None;
    }

    /// Writes bitmap-packed RELR entries for the entire GOT_RELR block.
    /// Called after all symbol resolutions are processed.
    fn write_got_relr_bitmap(&mut self, n: u64, base: u64) -> Result {
        if base == 0 || n == 0 {
            return Ok(());
        }
        let Some(relr_writer) = &mut self.relr_dyn else {
            return Ok(());
        };
        // Write address entry for base.
        let entry = relr_writer
            .split_off_first_mut()
            .ok_or_else(|| insufficient_allocation(".relr.dyn"))?;
        entry.set_value(base)?;
        // Write bitmap entries for remaining n-1 slots.
        let mut remaining = n - 1;
        while remaining > 0 {
            let slots = remaining.min(elf::relr_bitmap_slots::<C>());
            let bitmap: u64 = ((1u64 << slots) - 1) << 1 | 1;
            let entry = relr_writer
                .split_off_first_mut()
                .ok_or_else(|| insufficient_allocation(".relr.dyn"))?;
            entry.set_value(bitmap)?;
            remaining = remaining.saturating_sub(elf::relr_bitmap_slots::<C>());
        }
        Ok(())
    }

    /// Checks that we used all of the entries that we requested during layout.
    fn validate_empty(&self, mem_sizes: &OutputSectionPartMap<u64>) -> Result {
        if !self.section_headers.is_empty() {
            return Err(excessive_allocation(
                "section headers",
                std::mem::size_of_val(self.section_headers) as u64,
                mem_sizes.get(part_id::SECTION_HEADERS),
            ));
        }
        if !self.shstrtab.is_empty() {
            return Err(excessive_allocation(
                ".shstrtab",
                self.shstrtab.len() as u64,
                mem_sizes.get(part_id::SHSTRTAB),
            ));
        }
        if !self.got.is_empty() {
            return Err(excessive_allocation(
                ".got",
                self.got.len() as u64 * C::GOT_ENTRY_SIZE,
                mem_sizes.get(part_id::GOT),
            ));
        }
        if !self.got_relr.is_empty() {
            return Err(excessive_allocation(
                ".got (relr)",
                self.got_relr.len() as u64 * C::GOT_ENTRY_SIZE,
                mem_sizes.get(part_id::GOT_RELR),
            ));
        }
        if !self.rela_dyn_relative.is_empty() {
            return Err(excessive_allocation(
                ".rela.dyn (relative)",
                self.rela_dyn_relative.len() as u64 * C::RELA_ENTRY_SIZE,
                mem_sizes.get(part_id::RELA_DYN_RELATIVE),
            ));
        }
        if !self.rela_dyn_general.is_empty() {
            return Err(excessive_allocation(
                ".rela.dyn (general)",
                self.rela_dyn_general.len() as u64 * C::RELA_ENTRY_SIZE,
                mem_sizes.get(part_id::RELA_DYN_GENERAL),
            ));
        }
        if let Some(relr_dyn) = &self.relr_dyn
            && !relr_dyn.is_empty()
        {
            return Err(excessive_allocation(
                ".relr.dyn",
                relr_dyn.len() as u64 * C::RELR_ENTRY_SIZE,
                mem_sizes.get(part_id::RELR_DYN),
            ));
        }
        self.dynsym_writer.check_exhausted()?;
        self.debug_symbol_writer.check_exhausted()?;
        self.version_writer.check_exhausted(mem_sizes)?;
        if !self.eh_frame.is_empty() {
            return Err(excessive_allocation(
                ".eh_frame",
                self.eh_frame.len() as u64,
                mem_sizes.get(part_id::EH_FRAME),
            ));
        }
        if !self.eh_frame_hdr.is_empty() {
            return Err(excessive_allocation(
                ".eh_frame_hdr",
                self.eh_frame_hdr.len() as u64,
                mem_sizes.get(part_id::EH_FRAME_HDR),
            ));
        }
        if !self.dynamic.out.is_empty() {
            return Err(excessive_allocation(
                ".dynamic",
                std::mem::size_of_val(self.dynamic.out) as u64,
                mem_sizes.get(part_id::DYNAMIC),
            ));
        }
        Ok(())
    }

    fn write_ifunc_relocation<A: Arch<Platform = elf::Elf<C>>>(
        &mut self,
        res: &Resolution<elf::Elf<C>>,
    ) -> Result {
        let out = self.rela_plt.split_off_first_mut().unwrap();
        out.set_addend(res.raw_value as i64)?;
        let got_address = res
            .format_specific
            .got_address
            .context("Missing GOT entry for ifunc")?
            .get();
        out.set_offset(got_address)?;
        out.set_info(
            0,
            A::get_dynamic_relocation_type(DynamicRelocationKind::Irelative),
        )?;
        Ok(())
    }

    fn write_jump_slot_relocation<A: Arch<Platform = elf::Elf<C>>>(
        &mut self,
        got_address: u64,
        dynamic_symbol_index: u32,
    ) -> Result {
        let out = self
            .rela_plt
            .split_off_first_mut()
            .ok_or_else(|| insufficient_allocation(".rela.plt"))?;

        out.set_addend(0)?;
        out.set_offset(got_address)?;

        out.set_info(
            dynamic_symbol_index,
            A::get_dynamic_relocation_type(DynamicRelocationKind::JumpSlot),
        )?;

        Ok(())
    }

    fn write_dtpmod_relocation<A: Arch<Platform = elf::Elf<C>>>(
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

    fn write_tls_descriptor_relocation<A: Arch<Platform = elf::Elf<C>>>(
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

    fn write_dtpoff_relocation<A: Arch<Platform = elf::Elf<C>>>(
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

    fn write_tpoff_relocation<A: Arch<Platform = elf::Elf<C>>>(
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

    /// Writes a single flat RELR address entry without bitmap packing.
    /// Used for GOT-based RELR entries where layout counts flat (one entry per slot).
    /// Falls back to rela.dyn.relative when RELR is not enabled.
    // TODO: Implement bitmap packing for GOT-based RELR entries. Requires splitting
    // the GOT into two parts so relative relocations are contiguous and countable
    // during layout.
    fn write_relr_entry_flat<A: Arch<Platform = elf::Elf<C>>>(
        &mut self,
        place: u64,
        relative_address: u64,
    ) -> Result<u64> {
        if let Some(relr_writer) = &mut self.relr_dyn
            && place.is_multiple_of(2)
        {
            let entry = relr_writer
                .split_off_first_mut()
                .ok_or_else(|| insufficient_allocation(".relr.dyn"))?;
            entry.set_value(place)?;
            Ok(relative_address)
        } else {
            let rela = self
                .rela_dyn_relative
                .split_off_first_mut()
                .ok_or_else(|| insufficient_allocation(".rela.dyn (relative)"))?;
            rela.set_offset(place)?;
            rela.set_addend(relative_address as i64)?;
            rela.set_info(
                0,
                A::get_dynamic_relocation_type(DynamicRelocationKind::Relative),
            )?;
            Ok(0)
        }
    }

    #[inline(always)]
    /// Writes RELA or RELR entry and returns value that should be written at the relocation site.
    fn write_address_relocation<A: Arch<Platform = elf::Elf<C>>>(
        &mut self,
        place: u64,
        relative_address: u64,
    ) -> Result<u64> {
        debug_assert_bail!(
            self.output_kind.is_position_independent(),
            "write_address_relocation called when output is not position-independent"
        );
        // Odd offsets can't be encoded as RELR address entries (LSB used as bitmap
        // marker), so fall back to RELA for them.
        if let Some(relr_writer) = &mut self.relr_dyn
            && place.is_multiple_of(2)
        {
            self.relr_writer.encode(place, |encoded, encoding| {
                match encoding {
                    elf::RelrEntryEncoding::New => {
                        let entry = relr_writer
                            .split_off_first_mut()
                            .ok_or_else(|| insufficient_allocation(".relr.dyn"))?;
                        entry.set_value(encoded)?;
                        self.current_relr_dyn = Some(entry);
                    }
                    elf::RelrEntryEncoding::Update => {
                        let entry = self
                            .current_relr_dyn
                            .as_deref_mut()
                            .ok_or_else(|| error!("Internal error in RELR bitmap encoding"))?;
                        entry.set_value(encoded)?;
                    }
                }
                Ok(())
            })?;
            Ok(relative_address)
        } else {
            let rela = self
                .rela_dyn_relative
                .split_off_first_mut()
                .ok_or_else(|| insufficient_allocation(".rela.dyn (relative)"))?;
            rela.set_offset(place)?;
            rela.set_addend(relative_address as i64)?;
            rela.set_info(
                0,
                A::get_dynamic_relocation_type(DynamicRelocationKind::Relative),
            )?;
            Ok(0)
        }
    }

    fn write_ifunc_relocation_for_data<A: Arch<Platform = elf::Elf<C>>>(
        &mut self,
        place: u64,
        resolver_address: i64,
    ) -> Result {
        // IRELATIVE relocations go in .rela.dyn general section, not the relative section,
        // because the dynamic linker expects only R_X86_64_RELATIVE in the relative section.
        self.write_rela_dyn_general(
            place,
            0, // No dynamic symbol for IRELATIVE
            A::get_dynamic_relocation_type(DynamicRelocationKind::Irelative),
            resolver_address,
        )
    }

    fn write_dynamic_symbol_relocation<A: Arch<Platform = elf::Elf<C>>>(
        &mut self,
        place: u64,
        addend: i64,
        symbol_index: u32,
        kind: DynamicRelocationKind,
    ) -> Result {
        let _span = tracing::trace_span!("write_dynamic_symbol_relocation").entered();
        debug_assert_bail!(
            self.output_kind.needs_dynsym(),
            "Tried to write dynamic relocation without a dynamic symbol table"
        );
        let rela = self.take_rela_dyn()?;
        rela.set_offset(place)?;
        rela.set_addend(addend)?;
        rela.set_info(symbol_index, A::get_dynamic_relocation_type(kind))?;
        Ok(())
    }

    fn write_rela_dyn_general(
        &mut self,
        place: u64,
        dynamic_symbol_index: u32,
        r_type: object::elf::RelocationType,
        addend: i64,
    ) -> Result {
        debug_assert_bail!(
            self.output_kind.needs_dynsym(),
            "write_rela_dyn_general called when output is not dynamic"
        );
        let rela = self.take_rela_dyn()?;
        rela.set_offset(place)?;
        rela.set_addend(addend)?;
        rela.set_info(dynamic_symbol_index, r_type)?;
        Ok(())
    }

    fn take_rela_dyn(&mut self) -> Result<&mut elf::Rela<C>> {
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

    fn write_eh_frame_terminator(&mut self) {
        // Ignore insufficient capacity so that we don't error if .eh_frame is empty.
        if let Ok(buf) = self.take_eh_frame_data(size_of::<u32>()) {
            buf.fill(0);
        }
    }

    /// Takes a prefix of dynsym, dynstr and versym suitable for writing the supplied definitions.
    fn take_dynsym_prefix(
        &mut self,
        defs: &[crate::layout::DynamicSymbolDefinition<elf::Elf<C>>],
    ) -> VersionedDynsymWriter<'layout, 'out, C> {
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

struct VersionedDynsymWriter<'layout, 'out, C: ElfClass> {
    dynsym_writer: SymbolTableWriter<'layout, 'out, C>,
    versym: Option<&'out mut [Versym]>,
}

fn object_symbol_size<C: ElfClass>(
    sym: &elf::SymtabEntry<C>,
    sym_index: SymbolIndex,
    object: &ObjectLayout<elf::Elf<C>>,
) -> Result<u64> {
    let e = LittleEndian;
    let st_size: u64 = sym.st_size(e).into();
    if st_size == 0 {
        return Ok(0);
    }
    let Some(section_index) = object.object.symbol_section(sym, sym_index)? else {
        return Ok(st_size);
    };
    let Some(deltas) = object.section_relax_deltas.get(section_index.0) else {
        return Ok(st_size);
    };

    // Adjust symbol size for relaxation-induced byte deletions.
    let st_value: u64 = sym.st_value(e).into();
    let start_output = deltas.input_to_output_offset(st_value);
    let end_output = deltas.input_to_output_offset(st_value + st_size);
    Ok(end_output - start_output)
}

struct SymbolTableWriter<'layout, 'out, C: ElfClass> {
    local_entries: &'out mut [elf::SymtabEntry<C>],
    global_entries: &'out mut [elf::SymtabEntry<C>],
    output_sections: &'layout OutputSections<'layout, elf::Elf<C>>,
    strtab_writer: StrTabWriter<'out>,
    is_dynamic: bool,
    symtab_shndx_local_entries: Option<&'out mut [u32]>,
    symtab_shndx_global_entries: Option<&'out mut [u32]>,
}

impl<'layout, 'out, C: ElfClass> SymbolTableWriter<'layout, 'out, C> {
    fn new(
        start_string_offset: u32,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
        output_sections: &'layout OutputSections<'layout, elf::Elf<C>>,
    ) -> Self {
        let local_entries = slice_from_all_bytes_mut(buffers.take(part_id::SYMTAB_LOCAL));
        let global_entries = slice_from_all_bytes_mut(buffers.take(part_id::SYMTAB_GLOBAL));
        let symtab_shndx_local_entries = Some(buffers.take(part_id::SYMTAB_SHNDX_LOCAL))
            .and_then(|s| (!s.is_empty()).then(|| slice_from_all_bytes_mut(s)));
        let symtab_shndx_global_entries = Some(buffers.take(part_id::SYMTAB_SHNDX_GLOBAL))
            .and_then(|s| (!s.is_empty()).then(|| slice_from_all_bytes_mut(s)));

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
            symtab_shndx_local_entries,
            symtab_shndx_global_entries,
        }
    }

    fn new_dynamic(
        string_offset: u32,
        buffers: &mut OutputSectionPartMap<&'out mut [u8]>,
        output_sections: &'layout OutputSections<elf::Elf<C>>,
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
            symtab_shndx_local_entries: None,
            symtab_shndx_global_entries: None,
        }
    }

    fn copy_object_symbol(
        &mut self,
        sym: &elf::SymtabEntry<C>,
        sym_index: SymbolIndex,
        symbol_id: SymbolId,
        name: &[u8],
        object: &ObjectLayout<elf::Elf<C>>,
        layout: &ElfLayout<C>,
        value: u64,
        flags: ValueFlags,
    ) -> Result {
        let e = LittleEndian;

        let entry = if let Some(section_index) = object.object.symbol_section(sym, sym_index)? {
            self.copy_symbol_with_section(
                sym,
                symbol_id,
                name,
                object,
                layout,
                value,
                flags,
                section_index,
            )?
        } else if sym.is_common(e) {
            let section_id = if sym.st_type() == STT_TLS {
                output_section_id::TBSS
            } else {
                output_section_id::BSS
            };

            Some(self.copy_symbol(sym, name, section_id, value, flags)?)
        } else if sym.is_absolute(e) {
            self.copy_absolute_symbol(sym, name, flags)
                .with_context(|| {
                    format!("Failed to absolute {}", layout.symbol_debug(symbol_id))
                })?;
            return Ok(());
        } else {
            bail!("Attempted to output a symtab entry with an unexpected section type")
        };

        if let Some(entry) = entry {
            entry.set_size(object_symbol_size(sym, sym_index, object)?)?;
        }

        Ok(())
    }

    fn copy_symbol_with_section(
        &mut self,
        sym: &elf::SymtabEntry<C>,
        symbol_id: SymbolId,
        name: &[u8],
        object: &ObjectLayout<elf::Elf<C>>,
        layout: &Layout<elf::Elf<C>>,
        value: u64,
        flags: ValueFlags,
        section_index: object::SectionIndex,
    ) -> Result<Option<&mut elf::SymtabEntry<C>>> {
        let section_id = match &object.sections[section_index.0] {
            SectionSlot::Loaded(_)
            | SectionSlot::Sorted(_)
            | SectionSlot::LoadedDebugInfo(_)
            | SectionSlot::MergeStrings(_) => object
                .section_part_id(section_index, &layout.symbol_db.section_part_ids)
                .output_section_id::<elf::Elf<C>>(),
            SectionSlot::FrameData(..) => output_section_id::EH_FRAME,
            _ => {
                if layout.symbol_db.is_mapping_symbol(symbol_id) {
                    return Ok(None);
                }
                bail!(
                    "Tried to copy a symbol in a section we didn't load. {}",
                    layout.symbol_debug(symbol_id)
                )
            }
        };
        let section_id = layout.output_sections.primary_output_section(section_id);
        Ok(Some(self.copy_symbol(sym, name, section_id, value, flags)?))
    }

    #[inline(always)]
    fn copy_symbol(
        &mut self,
        sym: &elf::SymtabEntry<C>,
        name: &[u8],
        output_section_id: OutputSectionId,
        value: u64,
        flags: ValueFlags,
    ) -> Result<&mut elf::SymtabEntry<C>> {
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
        sym: &elf::SymtabEntry<C>,
        name: &[u8],
        shndx: u32,
        value: u64,
        flags: ValueFlags,
    ) -> Result<&mut elf::SymtabEntry<C>> {
        let e = LittleEndian;
        let is_local = flags.is_symtab_local(sym);
        let size = sym.st_size(e).into();
        let entry = self.define_symbol(
            is_local,
            SymbolSection::Index(shndx),
            value,
            size,
            Some(name),
        )?;
        entry.set_info(sym.st_info());
        entry.set_other(sym.st_other());
        // Fix binding if symbol was downgraded to local by version script
        if flags.is_downgraded_to_local() {
            entry.set_binding_and_type(object::elf::STB_LOCAL, sym.st_type());
        }
        Ok(entry)
    }

    fn copy_absolute_symbol(
        &mut self,
        sym: &elf::SymtabEntry<C>,
        name: &[u8],
        flags: ValueFlags,
    ) -> Result<&mut elf::SymtabEntry<C>> {
        let e = LittleEndian;
        let is_local = flags.is_symtab_local(sym);
        let value = sym.st_value(e).into();
        let size = sym.st_size(e).into();
        let entry = self.define_symbol(
            is_local,
            object::elf::SHN_ABS.into(),
            value,
            size,
            Some(name),
        )?;
        entry.set_info(sym.st_info());
        entry.set_other(sym.st_other());
        // Fix binding if symbol was downgraded to local by version script
        if flags.is_downgraded_to_local() {
            entry.set_binding_and_type(object::elf::STB_LOCAL, sym.st_type());
        }
        Ok(entry)
    }

    #[inline(always)]
    fn undefined_symbol(
        &mut self,
        is_local: bool,
        name: &[u8],
    ) -> Result<&mut elf::SymtabEntry<C>> {
        self.define_symbol(is_local, object::elf::SHN_UNDEF.into(), 0, 0, Some(name))
    }

    #[inline(always)]
    fn define_symbol(
        &mut self,
        is_local: bool,
        section: SymbolSection,
        value: u64,
        size: u64,
        name: Option<&[u8]>,
    ) -> Result<&mut elf::SymtabEntry<C>> {
        let (entry, symtab_shndx_entries) = if is_local {
            (
                self.local_entries.split_off_first_mut().with_context(|| {
                    format!(
                        "Insufficient .symtab local entries allocated for symbol `{}`",
                        String::from_utf8_lossy(name.unwrap_or_default()),
                    )
                })?,
                self.symtab_shndx_local_entries
                    .as_mut()
                    .and_then(|x| x.split_off_first_mut()),
            )
        } else {
            if self.is_dynamic {
                tracing::trace!(name = %String::from_utf8_lossy(name.unwrap_or_default()), "Write .dynsym");
            }
            (
                self.global_entries.split_off_first_mut().with_context(|| {
                    format!(
                        "Insufficient {} entries allocated for symbol `{}`",
                        if self.is_dynamic {
                            DYNSYM_SECTION_NAME_STR
                        } else {
                            ".symtab global"
                        },
                        String::from_utf8_lossy(name.unwrap_or_default()),
                    )
                })?,
                self.symtab_shndx_global_entries
                    .as_mut()
                    .and_then(|x| x.split_off_first_mut()),
            )
        };
        let string_offset = if let Some(name) = name {
            let name = if self.is_dynamic {
                // .dynsym encodes version info separately in .gnu.version, so strip it from the
                // name.
                crate::elf::RawSymbolName::parse(name).name
            } else {
                crate::elf::symtab_name_for_strtab(name)
            };
            self.strtab_writer.write_str(name)
        } else {
            0
        };

        let (index, shndx) = match section {
            SymbolSection::Raw(shndx) => (0, shndx),
            SymbolSection::Index(index) => {
                let shndx = object::elf::SymbolSection::new(index);
                if shndx == object::elf::SHN_XINDEX {
                    (index, shndx)
                } else {
                    (0, shndx)
                }
            }
        };
        if let Some(s) = symtab_shndx_entries {
            *s = index;
        } else if shndx == object::elf::SHN_XINDEX {
            bail!(
                "Expected .symtab_shndx section when writing symbol {} with shndx set to SHN_XINDEX.",
                String::from_utf8_lossy(name.unwrap_or_default())
            );
        }
        entry.set_name(string_offset);
        entry.set_info(object::elf::SymbolInfo(0));
        entry.set_other(object::elf::SymbolOther(0));
        entry.set_section(shndx);
        entry.set_value(value)?;
        entry.set_size(size)?;
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

        let symtab_shndx_local_len = self
            .symtab_shndx_local_entries
            .as_ref()
            .map_or(0, |s| s.len());
        let symtab_shndx_global_len = self
            .symtab_shndx_global_entries
            .as_ref()
            .map_or(0, |s| s.len());
        if symtab_shndx_local_len > 0 || symtab_shndx_global_len > 0 {
            bail!(
                "Didn't use up all allocated symtab_shndx space. local={} global={}",
                symtab_shndx_local_len,
                symtab_shndx_global_len,
            );
        }
        Ok(())
    }

    /// Returns a new writer that will take responsibility for the first `num_symbols`.
    fn take_prefix_global(&mut self, num_symbols: usize, strtab_size: usize) -> Self {
        Self {
            local_entries: &mut [],
            global_entries: self.global_entries.split_off_mut(..num_symbols).unwrap(),
            output_sections: self.output_sections,
            strtab_writer: self.strtab_writer.take_prefix(strtab_size),
            is_dynamic: self.is_dynamic,
            symtab_shndx_local_entries: None,
            symtab_shndx_global_entries: None,
        }
    }
}

fn write_object<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    object: &ObjectLayout<'data, elf::Elf<C>>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<'data, C>,
    trace: &TraceOutput,
    sym_index_map: &[Option<u32>],
) -> Result {
    verbose_timing_phase!("Write object", file_id = object.file_id.as_u32());

    let _span = debug_span!("write_file", filename = %object.input).entered();
    let _file_span = layout.args().common().trace_span_for_file(object.file_id);

    for (i, sec) in object.sections.iter().enumerate() {
        let section_index = object::SectionIndex(i);

        match sec {
            SectionSlot::Loaded(sec) => {
                table_writer.reset_relr_run();
                write_object_section::<C, A>(
                    object,
                    layout,
                    *sec,
                    section_index,
                    buffers,
                    table_writer,
                    trace,
                )?;
            }
            SectionSlot::LoadedDebugInfo(sec) => {
                write_debug_section::<C, A>(object, layout, *sec, section_index, buffers)?;
            }
            SectionSlot::FrameData(section_index) => {
                write_eh_frame_data::<C, A>(object, *section_index, layout, table_writer, trace)?;
            }
            _ => (),
        }
    }
    for (symbol_id, resolution) in layout.resolutions_in_range(object.symbol_id_range) {
        let _span = tracing::trace_span!("Symbol", %symbol_id).entered();
        if let Some(res) = resolution {
            table_writer
                .process_resolution::<A>(Some(layout), layout.args(), res)
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

    if layout.args().should_output_partial_object() {
        write_symbols(object, &mut table_writer.debug_symbol_writer, layout)?;

        write_rela_sections(object, buffers, layout, sym_index_map)?;
    } else if !layout.args().should_strip_all() {
        write_symbols(object, &mut table_writer.debug_symbol_writer, layout)?;
    }
    if object.owns_thunk_block
        && let Some(addresses) = layout
            .thunk_block_addresses
            .get(object.thunk_block_id.as_usize())
    {
        write_thunks::<C, A>(
            addresses,
            buffers,
            layout,
            &mut table_writer.debug_symbol_writer,
        )?;
    }
    Ok(())
}

/// Write thunk instructions for a set of (SymbolId -> thunk_address) mappings.
///
/// Thunks are sorted by SymbolId for determinism and written consecutively into the primary
/// function part buffer. Space must already have been reserved during `finalise_sizes`.
fn write_thunks<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    thunk_addresses: &BTreeMap<crate::symbol_db::SymbolId, u64>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &ElfLayout<'data, C>,
    symbol_writer: &mut SymbolTableWriter<'_, '_, C>,
) -> Result {
    if thunk_addresses.is_empty() {
        return Ok(());
    }

    let config = A::thunk_config().expect("write_thunks called without thunk config");
    let thunk_size = config.thunk_size as usize;
    let primary_part_id = config.primary_function_part_id;
    let emit_symbols = !layout.args().should_strip_all();

    let text_section_id = primary_part_id.output_section_id::<elf::Elf<C>>();
    let text_shndx = layout
        .output_sections
        .output_index_of_section(text_section_id)
        .unwrap_or(0);

    for (symbol_id, &thunk_address) in thunk_addresses {
        debug_assert_ne!(thunk_address, 0, "Thunk address should have been assigned");

        let res = layout
            .merged_symbol_resolution(*symbol_id)
            .with_context(|| {
                format!(
                    "No resolution for symbol {} needed by thunk",
                    layout.symbol_db.symbol_name_for_display(*symbol_id)
                )
            })?;

        let target_address = res.plt_address().unwrap_or(res.raw_value);

        let buf = buffers.get_mut(primary_part_id);
        let thunk_buf = buf
            .split_off_mut(..thunk_size)
            .ok_or_else(|| crate::file_writer::insufficient_allocation("thunk space in .text"))?;

        A::write_thunk(thunk_address, target_address, thunk_buf);

        if emit_symbols {
            let orig_name = layout
                .symbol_db
                .symbol_name(*symbol_id)
                .map(|n| n.bytes().to_vec())
                .unwrap_or_default();
            let mut thunk_name = crate::elf::THUNK_SYMBOL_PREFIX.as_bytes().to_vec();
            thunk_name.extend_from_slice(&orig_name);
            let entry = symbol_writer.define_symbol(
                true,
                SymbolSection::Index(text_shndx),
                thunk_address,
                thunk_size as u64,
                Some(&thunk_name),
            )?;
            entry.set_binding_and_type(object::elf::STB_LOCAL, object::elf::STT_FUNC);
        }
    }

    Ok(())
}

fn build_sym_index_map<C: ElfClass>(layout: &ElfLayout<'_, C>) -> Vec<Option<u32>> {
    timing_phase!("Build sym index map");

    let section_sym_indices = build_section_sym_indices(layout);

    let num_all_locals = (layout
        .section_part_layouts
        .get(part_id::SYMTAB_LOCAL)
        .file_size
        / C::SYMTAB_ENTRY_SIZE as usize) as u32;

    let total_syms = layout.symbol_db.num_symbols();
    let mut map: Vec<Option<u32>> = vec![None; total_syms];

    // TODO: Use a ShardedWriter to parallelize this loop
    for group in &layout.group_layouts {
        let mut group_global_base = num_all_locals + group.symtab_global_start_index;
        let mut group_local_base = group.symtab_local_start_index;

        for file in &group.files {
            let FileLayout::Object(object) = file else {
                continue;
            };

            for ((sym_index, sym), flags) in object
                .object
                .enumerate_symbols()
                .zip(layout.per_symbol_flags.raw_range(object.symbol_id_range))
            {
                let symbol_id = object.symbol_id_range.input_to_id(sym_index);

                if sym.st_type() == object::elf::STT_SECTION
                    && let Ok(Some(input_section_index)) =
                        object.object.symbol_section(sym, sym_index)
                    && let Some(output_section_id) = match object.sections[input_section_index.0] {
                        SectionSlot::Loaded(_) | SectionSlot::MergeStrings(_) => Some(
                            object
                                .section_part_id(
                                    input_section_index,
                                    &layout.symbol_db.section_part_ids,
                                )
                                .output_section_id::<elf::Elf<C>>(),
                        ),
                        SectionSlot::FrameData(..) => Some(output_section_id::EH_FRAME),
                        _ => None,
                    }
                {
                    let primary_id = layout
                        .output_sections
                        .primary_output_section(output_section_id);
                    let sym_idx = section_sym_indices.get(primary_id);
                    map[symbol_id.as_usize()] = Some(*sym_idx);
                }

                if SymbolCopyInfo::new(
                    object.object,
                    sym_index,
                    sym,
                    symbol_id,
                    &layout.symbol_db,
                    flags.get(),
                    &object.sections,
                )
                .is_some()
                {
                    if flags.get().is_symtab_local(sym) {
                        map[symbol_id.as_usize()] = Some(group_local_base);
                        group_local_base += 1;
                    } else {
                        let canonical = layout.symbol_db.definition(symbol_id);
                        map[canonical.as_usize()] = Some(group_global_base);
                        group_global_base += 1;
                    }
                }
            }

            let e = LittleEndian;
            for (sym_index, sym) in object.object.symbols.enumerate() {
                if !sym.is_undefined(e) {
                    continue;
                }
                let symbol_id = object.symbol_id_range.input_to_id(sym_index);
                if !layout.symbol_db.is_canonical(symbol_id) {
                    continue;
                }
                if let Ok(name) = object.object.symbol_name(sym)
                    && !name.is_empty()
                {
                    map[symbol_id.as_usize()] = Some(group_global_base);
                    group_global_base += 1;
                }
            }
        }
    }

    map
}

fn build_section_sym_indices<C: ElfClass>(layout: &ElfLayout<'_, C>) -> OutputSectionMap<u32> {
    let mut map = OutputSectionMap::with_size(layout.output_sections.num_sections());
    let mut next_sym_idx: u32 = 1;
    for event in &layout.output_order {
        let OrderEvent::Section(section_id) = event else {
            continue;
        };
        if layout
            .output_sections
            .output_index_of_section(section_id)
            .is_none()
            || !layout
                .output_sections
                .will_emit_section_symbol_for_partial_objects(section_id)
        {
            continue;
        }
        *map.get_mut(section_id) = next_sym_idx;
        next_sym_idx += 1;
    }
    map
}

fn write_rela_sections<'data, C: ElfClass>(
    object: &ObjectLayout<'data, elf::Elf<C>>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &ElfLayout<'data, C>,
    sym_index_map: &[Option<u32>],
) -> Result {
    let e = LittleEndian;

    for (sec_idx, header) in object.object.enumerate_sections() {
        let section_name = object.object.section_name(sec_idx).unwrap_or_default();
        if !section_name.starts_with(b".rela") && !section_name.starts_with(b".crel") {
            continue;
        }

        let Some(section_id) = layout
            .output_sections
            .custom_identity_to_id(SectionIdentity::new(SectionName(section_name), ()))
        else {
            continue;
        };
        let part_id = section_id.part_id_with_alignment::<elf::Elf<C>>(C::RELA_ENTRY_ALIGNMENT);

        let target_sec_idx = object::SectionIndex(header.sh_info(e) as usize);
        let section_address = object.section_resolutions[target_sec_idx.0]
            .address()
            .unwrap_or(0);

        let relocations = object.relocations(target_sec_idx).with_context(|| {
            format!(
                "Failed to get relocations from rela section {:?} in {}",
                SectionName(section_name),
                object.input
            )
        })?;

        let num_rela = relocations.num_relocations();
        if num_rela == 0 {
            continue;
        }

        let num_bytes = num_rela * C::RELA_ENTRY_SIZE as usize;
        let part_buf = buffers.get_mut(part_id);
        let out_buf = part_buf
            .split_off_mut(..num_bytes)
            .with_context(|| format!("Insufficient buffer for rela section {sec_idx:?}"))?;
        let out_relas: &mut [elf::Rela<C>] = slice_from_all_bytes_mut(out_buf);
        let mut rela_iter = out_relas.iter_mut();

        let mut write_one = |offset: u64,
                             sym: Option<SymbolIndex>,
                             r_type: object::elf::RelocationType,
                             addend: i64| {
            let Some(out) = rela_iter.next() else {
                return Ok(());
            };
            let sym_idx = sym
                .and_then(|s| {
                    let symbol_id = object.symbol_id_range.input_to_id(s);
                    if let Some(idx) = sym_index_map.get(symbol_id.as_usize()).copied().flatten() {
                        return Some(idx);
                    }
                    let canonical_id = layout.symbol_db.definition(symbol_id);
                    sym_index_map
                        .get(canonical_id.as_usize())
                        .copied()
                        .flatten()
                })
                .unwrap_or(0);
            let addend = sym
                .and_then(|s| {
                    let sym_entry = object.object.symbol(s).ok()?;
                    if sym_entry.st_type() != object::elf::STT_SECTION {
                        return None;
                    }
                    let sec_idx = object.object.symbol_section(sym_entry, s).ok()??;
                    object.section_resolutions[sec_idx.0].address()
                })
                .map_or(addend, |offset| addend + offset as i64);
            out.set_offset(section_address + offset)?;
            out.set_addend(addend)?;
            out.set_info(sym_idx, r_type)?;
            Ok::<_, error::Error>(())
        };

        match relocations {
            elf::RelocationList::Rela(relas) => {
                for raw in relas {
                    let rel: elf::ElfRela<C> = elf::ElfRela::new(*raw);
                    write_one(rel.offset(), rel.symbol(), rel.raw_type(), rel.addend())?;
                }
            }
            elf::RelocationList::Crel(crel) => {
                for raw in crel.flatten() {
                    let rel: elf::ElfCrel<C> = elf::ElfCrel::new(raw);
                    write_one(rel.offset(), rel.symbol(), rel.raw_type(), rel.addend())?;
                }
            }
        }
    }
    Ok(())
}

fn write_object_section<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    object: &ObjectLayout<'data, elf::Elf<C>>,
    layout: &ElfLayout<'data, C>,
    section: Section,
    section_index: object::SectionIndex,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter<'_, '_, C>,
    trace: &TraceOutput,
) -> Result {
    let part_id = object.section_part_id(section_index, &layout.symbol_db.section_part_ids);
    if layout.args().should_output_partial_object() {
        let section_type = layout
            .output_sections
            .output_info(part_id.output_section_id::<elf::Elf<C>>())
            .section_attributes
            .ty();
        if section_type.is_rela() || section_type.is_rel() {
            return Ok(());
        }
    }

    let out = write_section_raw::<C, A>(object, layout, section, section_index, buffers)?;

    // We need to reverse the contents and adjust relocations because .ctors/.dtors are executed in
    // reverse order while .init_array/.fini_array are executed in forward order.
    if should_reverse_contents(
        section_index,
        part_id,
        object.object,
        &layout.output_sections,
    ) {
        return write_section_reversed::<C, A>(
            object,
            layout,
            section_index,
            table_writer,
            trace,
            out,
        );
    }

    if layout.args().should_output_partial_object() {
        return Ok(());
    }

    let relocations = object.relocations(section_index)?;
    let result = match relocations {
        elf::RelocationList::Rela(rela) => apply_relocations::<C, A, elf::ElfRela<C>, _>(
            object,
            out,
            section_index,
            rela.iter().map(|rela| Ok(elf::ElfRela::new(*rela))),
            layout,
            table_writer,
            trace,
        ),
        elf::RelocationList::Crel(crel_iter) => apply_relocations::<C, A, elf::ElfCrel<C>, _>(
            object,
            out,
            section_index,
            crel_iter.map(|r| r.map(elf::ElfCrel::new)),
            layout,
            table_writer,
            trace,
        ),
    };
    result.with_context(|| {
        format!(
            "Failed to apply relocations in section `{}` of {}",
            object.object.section_display_name(section_index),
            object.input
        )
    })?;
    Ok(())
}

fn write_section_reversed<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    object: &ObjectLayout<'data, elf::Elf<C>>,
    layout: &ElfLayout<'data, C>,
    section_index: object::SectionIndex,
    table_writer: &mut TableWriter<'_, '_, C>,
    trace: &TraceOutput,
    out: &mut [u8],
) -> Result {
    let word_size = C::ADDRESS_SIZE as usize;

    if !out.is_empty() {
        ensure!(
            out.len().is_multiple_of(word_size),
            "Section size is not a multiple of word size"
        );

        let pointers: &mut [elf::Word<C>] = <[elf::Word<C>]>::mut_from_bytes(out).unwrap();
        pointers.reverse();
    }

    // For reversed sections, we need to adjust relocation offsets.
    // The offset transformation is: new_offset = section_size - old_offset - word_size
    let section_size = out.len() as u64;

    let relocations = object.relocations(section_index)?;

    let result = match relocations {
        elf::RelocationList::Rela(rela) => apply_relocations::<C, A, elf::ElfCrel<C>, _>(
            object,
            out,
            section_index,
            rela.iter().map(|r| {
                let mut crel = Crel::from_rela(r, LittleEndian, false);
                crel.r_offset = section_size.saturating_sub(crel.r_offset + word_size as u64);
                Ok(elf::ElfCrel::new(crel))
            }),
            layout,
            table_writer,
            trace,
        ),
        elf::RelocationList::Crel(crel_iter) => apply_relocations::<C, A, elf::ElfCrel<C>, _>(
            object,
            out,
            section_index,
            crel_iter.map(|r| {
                r.map(|mut crel| {
                    crel.r_offset = section_size.saturating_sub(crel.r_offset + word_size as u64);
                    elf::ElfCrel::new(crel)
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
            object.object.section_display_name(section_index),
            object.input
        )
    })?;

    Ok(())
}

fn write_debug_section<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    object: &ObjectLayout<'data, elf::Elf<C>>,
    layout: &ElfLayout<'data, C>,
    section: Section,
    section_index: object::SectionIndex,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let part_id = object.section_part_id(section_index, &layout.symbol_db.section_part_ids);
    let section_id = part_id.output_section_id::<elf::Elf<C>>();

    if layout.compressed_debug_sections.get(section_id).is_some() {
        // Compressed debug sections are written by the epilogue.
        return Ok(());
    }

    let out = write_section_raw::<C, A>(object, layout, section, section_index, buffers)?;
    let relocations = object.relocations(section_index)?;
    let result = match relocations {
        elf::RelocationList::Rela(rela) => apply_debug_relocations::<C, A, elf::ElfRela<C>, _>(
            object,
            out,
            section_index,
            rela.iter().map(|rela| Ok(elf::ElfRela::new(*rela))),
            layout,
        ),
        elf::RelocationList::Crel(crel_iter) => {
            apply_debug_relocations::<C, A, elf::ElfCrel<C>, _>(
                object,
                out,
                section_index,
                crel_iter.map(|r| r.map(elf::ElfCrel::new)),
                layout,
            )
        }
    };
    result.with_context(|| {
        format!(
            "Failed to apply relocations in section `{}` of {}",
            object.object.section_display_name(section_index),
            object.input
        )
    })?;
    Ok(())
}

fn write_section_raw<'out, 'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    object: &ObjectLayout<'data, elf::Elf<C>>,
    layout: &ElfLayout<C>,
    sec: Section,
    section_index: object::SectionIndex,
    buffers: &'out mut OutputSectionPartMap<&mut [u8]>,
) -> Result<&'out mut [u8]> {
    let part_id = object.section_part_id(section_index, &layout.symbol_db.section_part_ids);
    if layout
        .output_sections
        .has_data_in_file(part_id.output_section_id::<elf::Elf<C>>())
    {
        let section_buffer = buffers.get_mut(part_id);
        let allocation_size = sec.capacity(part_id, &layout.output_sections) as usize;
        if section_buffer.len() < allocation_size {
            bail!(
                "Insufficient space allocated to section `{}`. Tried to take {} bytes, but only {} remain",
                object.object.section_display_name(section_index),
                allocation_size,
                section_buffer.len()
            );
        }
        let out = section_buffer.split_off_mut(..allocation_size).unwrap();
        let object_section = object.object.section(section_index)?;
        let relax_deltas = object.section_relax_deltas.get(section_index.0);

        let section_info = layout
            .output_sections
            .output_info(part_id.output_section_id::<elf::Elf<C>>());
        match relax_deltas {
            None => {
                let section_size = object.object.section_size(object_section)?;
                let (out, padding) = out.split_at_mut(section_size as usize);
                object.object.copy_section_data(object_section, out)?;
                fill_section_padding::<C, A>(padding, section_info);
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
                fill_section_padding::<C, A>(&mut out[output_pos..], section_info);

                Ok(&mut out[..effective_size])
            }
        }
    } else {
        Ok(&mut [])
    }
}

/// Writes debug symbols.
fn write_symbols<'data, C: ElfClass>(
    object: &ObjectLayout<'data, elf::Elf<C>>,
    symbol_writer: &mut SymbolTableWriter<'_, '_, C>,
    layout: &ElfLayout<'data, C>,
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
            let Some(res) = layout.local_symbol_resolution(symbol_id) else {
                bail!("Missing resolution for {}", layout.symbol_debug(symbol_id));
            };

            let mut symbol_value = res.value_for_symbol_table();

            if sym.st_type() == object::elf::STT_TLS {
                symbol_value -= layout.tls_start_address();
            }

            symbol_writer
                .copy_object_symbol(
                    sym,
                    sym_index,
                    symbol_id,
                    info.name,
                    object,
                    layout,
                    symbol_value,
                    flags.get(),
                )
                .with_context(|| format!("Failed to copy {}", layout.symbol_debug(symbol_id)))?;
        }
    }

    if layout.args().should_output_partial_object() {
        for (sym_index, sym) in object.object.symbols.enumerate() {
            if !platform::Symbol::is_undefined(sym) {
                continue;
            }
            let Ok(name) = object.object.symbol_name(sym) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let symbol_id = object.symbol_id_range.input_to_id(sym_index);
            if !layout.symbol_db.is_canonical(symbol_id) {
                continue;
            }
            let name = RawSymbolName::parse(name).name;
            let entry = symbol_writer
                .undefined_symbol(false, name)
                .with_context(|| {
                    format!(
                        "Failed to write undefined symbol `{}` for partial link",
                        String::from_utf8_lossy(name)
                    )
                })?;
            entry.set_info(sym.st_info());
            entry.set_other(sym.st_other());
        }
    }

    Ok(())
}

fn apply_relocations<
    'data,
    C: ElfClass,
    A: Arch<Platform = elf::Elf<C>>,
    R: Relocation<Platform = elf::Elf<C>>,
    I: Iterator<Item = object::Result<R>> + Clone,
>(
    object: &ObjectLayout<'data, elf::Elf<C>>,
    out: &mut [u8],
    section_index: object::SectionIndex,
    mut relocations: I,
    layout: &ElfLayout<'data, C>,
    table_writer: &mut TableWriter<'_, '_, C>,
    trace: &TraceOutput,
) -> Result {
    let section_address = object.section_resolutions[section_index.0]
        .address()
        .context("Attempted to apply relocations to a section that we didn't load")?;
    let object_section = object.object.section(section_index)?;
    let section_flags = object_section.sh_flags(LittleEndian);
    let mut modifier = RelocationModifier::Normal;

    let mut relocation_count = 0;
    let mut relocation_cache = RelocationCache::<R>::default();
    let relax_deltas = object.section_relax_deltas.get(section_index.0);
    let mut relax_cursor = relax_deltas.map(|deltas| deltas.cursor());

    while let Some(rel) = relocations.next() {
        let rel = rel?;
        relocation_count += 1;
        if A::high_part_relocations().contains(&rel.raw_type()) {
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

        modifier = apply_relocation::<C, A, R, _>(
            object,
            offset_in_section,
            &rel,
            SectionInfo {
                section_address,
                is_writable: object_section.is_writable(),
                section_flags,
                part_id: object.section_part_id(section_index, &layout.symbol_db.section_part_ids),
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
                display_relocation::<C, A, R>(object, &rel, layout)
            )
        })?;
        relocation_cache.previous = Some(rel);
    }

    layout
        .relocation_statistics
        .get(
            object
                .section_part_id(section_index, &layout.symbol_db.section_part_ids)
                .output_section_id::<elf::Elf<C>>(),
        )
        .fetch_add(relocation_count, Relaxed);
    Ok(())
}

pub(crate) fn apply_debug_relocations<
    'data,
    C: ElfClass,
    A: Arch<Platform = elf::Elf<C>>,
    R: Relocation<Platform = elf::Elf<C>>,
    I: Iterator<Item = object::Result<R>> + Clone,
>(
    object: &ObjectLayout<'data, elf::Elf<C>>,
    out: &mut [u8],
    section_index: object::SectionIndex,
    relocations: I,
    layout: &ElfLayout<'data, C>,
) -> Result {
    let section_name = object.object.section_name(section_index)?;

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
        apply_debug_relocation::<C, A, R>(
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
                display_relocation::<C, A, R>(object, &rel, layout)
            )
        })?;
        relocation_cache.previous = Some(rel);
    }
    layout
        .relocation_statistics
        .get(
            object
                .section_part_id(section_index, &layout.symbol_db.section_part_ids)
                .output_section_id::<elf::Elf<C>>(),
        )
        .fetch_add(relocation_count, Relaxed);
    Ok(())
}

fn write_eh_frame_data<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    object: &ObjectLayout<'data, elf::Elf<C>>,
    eh_frame_section_index: object::SectionIndex,
    layout: &ElfLayout<'data, C>,
    table_writer: &mut TableWriter<'_, '_, C>,
    trace: &TraceOutput,
) -> Result {
    let eh_frame_section = object.object.section(eh_frame_section_index)?;
    match object.relocations(eh_frame_section_index)? {
        elf::RelocationList::Rela(relocations) => {
            write_eh_frame_relocations::<C, A, elf::ElfRela<C>>(
                object,
                layout,
                table_writer,
                trace,
                eh_frame_section,
                relocations.iter().copied().map(elf::ElfRela::new),
            )
        }
        elf::RelocationList::Crel(relocations) => {
            write_eh_frame_relocations::<C, A, elf::ElfCrel<C>>(
                object,
                layout,
                table_writer,
                trace,
                eh_frame_section,
                relocations.filter_map(|r| r.ok().map(elf::ElfCrel::new)),
            )
        }
    }
}

fn write_eh_frame_relocations<
    'data,
    C: ElfClass,
    A: Arch<Platform = elf::Elf<C>>,
    R: Relocation<Platform = elf::Elf<C>>,
>(
    object: &ObjectLayout<'data, elf::Elf<C>>,
    layout: &ElfLayout<'data, C>,
    table_writer: &mut TableWriter<'_, '_, C>,
    trace: &TraceOutput,
    eh_frame_section: &elf::SectionHeader<C>,
    relocations: impl Iterator<Item = R>,
) -> std::result::Result<(), error::Error> {
    let data = object.object.raw_section_data(eh_frame_section)?;
    const PREFIX_LEN: usize = size_of::<elf::EhFrameEntryPrefix>();
    let e = LittleEndian;
    let section_flags = eh_frame_section.sh_flags(LittleEndian);
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
        if prefix.length == 0 {
            input_pos = data.len();
            break;
        }
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
                        let offset_in_section = (Into::<u64>::into(elf_symbol.st_value(e)) as i64
                            + rel.addend()) as u64;
                        if let Some(section_address) =
                            object.section_resolutions[section_index.0].address()
                            && object
                                .object
                                .section(section_index)?
                                .sh_size(LittleEndian)
                                .into()
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
                apply_relocation::<C, A, R, _>(
                    object,
                    rel_offset - input_pos as u64,
                    rel,
                    SectionInfo {
                        section_address: output_pos as u64 + table_writer.eh_frame_start_address,
                        is_writable: false,
                        section_flags,
                        // .eh_frame relocations never need thunks; use the eh_frame section's
                        // base part as a placeholder so the thunk lookup always misses.
                        part_id: output_section_id::EH_FRAME.base_part_id::<elf::Elf<C>>(),
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
                        display_relocation::<C, A, R>(object, rel, layout)
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
    if remaining > 0 && !elf::is_eh_frame_terminator(&data[input_pos..input_pos + remaining]) {
        table_writer
            .take_eh_frame_data(remaining)?
            .copy_from_slice(&data[input_pos..input_pos + remaining]);
        output_pos += remaining;
    }

    table_writer.eh_frame_start_address += output_pos as u64;

    Ok(())
}

fn display_relocation<'a, 'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>, R: Relocation>(
    object: &'a ObjectLayout<'data, elf::Elf<C>>,
    rel: &'a R,
    layout: &'a ElfLayout<'data, C>,
) -> DisplayRelocation<'a, 'data, C, A, R> {
    DisplayRelocation::<'a, 'data, C, A, R> {
        rel,
        symbol_db: &layout.symbol_db,
        per_symbol_flags: &layout.per_symbol_flags,
        object,
        phantom: PhantomData,
    }
}

struct DisplayRelocation<'a, 'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>, R: Relocation> {
    rel: &'a R,
    symbol_db: &'a SymbolDb<'data, elf::Elf<C>>,
    per_symbol_flags: &'a PerSymbolFlags,
    object: &'a ObjectLayout<'data, elf::Elf<C>>,
    phantom: PhantomData<A>,
}

impl<'a, 'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>, R: Relocation<Platform = elf::Elf<C>>>
    Display for DisplayRelocation<'a, 'data, C, A, R>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "relocation of type {} to ",
            A::rel_type_to_string(self.rel.raw_type())
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
struct SectionInfo<S: platform::SectionFlags> {
    section_address: u64,
    is_writable: bool,
    section_flags: S,
    part_id: PartId,
}

fn get_resolution<'data, C: ElfClass, R: Relocation>(
    rel: &R,
    object_layout: &ObjectLayout<'data, elf::Elf<C>>,
    layout: &ElfLayout<C>,
) -> Result<(Resolution<elf::Elf<C>>, SymbolIndex, SymbolId)> {
    let symbol_index = rel.symbol().context("Unsupported absolute relocation")?;
    let local_symbol_id = object_layout.symbol_id_range.input_to_id(symbol_index);
    let sym = object_layout.object.symbol(symbol_index)?;
    let section_index = object_layout.object.symbol_section(sym, symbol_index)?;
    let resolution = layout
        .merged_symbol_resolution(local_symbol_id)
        .or_else(|| {
            section_index.and_then(|section_index| {
                let section_address =
                    object_layout.section_resolutions[section_index.0].address()?;
                let output_offset = opt_input_to_output(
                    object_layout.section_relax_deltas.get(section_index.0),
                    crate::platform::Symbol::value(sym),
                );

                Some(Resolution {
                    raw_value: section_address + output_offset,
                    dynamic_symbol_index: None,
                    flags: ValueFlags::empty(),
                    format_specific: Default::default(),
                })
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

/// Returns the `st_other` byte of the canonical definition of `symbol_id`, or 0 if it isn't
/// defined by a regular object. Used for ppc64 local-entry-point computation.
fn callee_st_other<C: ElfClass>(layout: &ElfLayout<C>, symbol_id: SymbolId) -> u8 {
    let canonical = layout.symbol_db.definition(symbol_id);
    let file_id = layout.symbol_db.file_id_for_symbol(canonical);
    if let FileLayout::Object(obj) = layout.file_layout(file_id)
        && let Ok(sym) = obj.object.symbol(canonical.to_input(obj.symbol_id_range))
    {
        return sym.st_other().0;
    }
    0
}

fn write_got_plt_syms<C: ElfClass>(
    layout: &ElfLayout<C>,
    symbol_writer: &mut SymbolTableWriter<'_, '_, C>,
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

    let mut write_sym =
        |suffix: &[u8],
         section_id: OutputSectionId,
         get_value: fn(&Resolution<elf::Elf<C>>) -> Result<u64>|
         -> Result {
            let mut symbol_name = layout.symbol_db.symbol_name(symbol_id)?.to_string();
            symbol_name.push_str(std::str::from_utf8(suffix).unwrap_or("unknown"));

            let shndx = layout
            .output_sections
            .output_index_of_section(section_id)
            .with_context(||format!(
                "Tried to write dynamic symbol in {section_id} section that's not being output"
            ))?;

            let value = get_value(resolution)?;

            symbol_writer
                .define_symbol(
                    true,
                    SymbolSection::Index(shndx),
                    value,
                    0,
                    Some(symbol_name.as_bytes()),
                )
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

#[inline(always)]
fn get_pair_subtraction_relocation_value<
    'data,
    C: ElfClass,
    A: Arch<Platform = elf::Elf<C>>,
    R: Relocation<Platform = elf::Elf<C>>,
>(
    object_layout: &ObjectLayout<'data, elf::Elf<C>>,
    rel: &R,
    layout: &ElfLayout<C>,
    resolution: Resolution<elf::Elf<C>>,
    symbol_index: SymbolIndex,
    addend: i64,
    set_rel: &R,
    expected_r_type: object::elf::RelocationType,
) -> Result<u64> {
    ensure!(
        set_rel.offset() == rel.offset(),
        "PairSubtractionULEB128 relocation must have equal offset"
    );
    ensure!(
        set_rel.raw_type() == expected_r_type,
        "unexpected previous relocation: expected: {}, was: {}",
        A::rel_type_to_string(expected_r_type),
        A::rel_type_to_string(set_rel.raw_type())
    );
    let (set_resolution, set_symbol_index, _) = get_resolution(set_rel, object_layout, layout)?;

    let set_resolution_val = set_resolution.value_with_addend(
        set_rel.addend(),
        set_symbol_index,
        object_layout,
        &layout.symbol_db.section_part_ids,
        &layout.merged_strings,
        &layout.merged_string_start_addresses,
    )?;
    let sub_resolution_val = resolution.value_with_addend(
        addend,
        symbol_index,
        object_layout,
        &layout.symbol_db.section_part_ids,
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
    C: ElfClass,
    A: Arch<Platform = elf::Elf<C>>,
    R: Relocation<Platform = elf::Elf<C>>,
    I: Iterator<Item = object::Result<R>> + Clone,
>(
    object_layout: &ObjectLayout<'data, elf::Elf<C>>,
    mut offset_in_section: u64,
    rel: &R,
    section_info: SectionInfo<linker_utils::elf::SectionFlags>,
    layout: &ElfLayout<'data, C>,
    out: &mut [u8],
    table_writer: &mut TableWriter<'_, '_, C>,
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

    match A::relocation_from_raw(r_type)?.kind {
        RelocationKind::None => return Ok(RelocationModifier::Normal),
        RelocationKind::Alignment => {
            let addend = addend as u64;
            let removed_bytes =
                relax_deltas.map_or(0u64, |d| u64::from(d.delta_bytes_at(rel.offset())));
            let padding_bytes = addend.saturating_sub(removed_bytes) as usize;
            let offset_in_section = offset_in_section as usize;
            A::fill_nop_padding(&mut out[offset_in_section..offset_in_section + padding_bytes]);

            return Ok(RelocationModifier::Normal);
        }
        RelocationKind::Relative if rel.symbol().is_none() => {
            if layout.symbol_db.output_kind.is_position_independent() {
                bail!(
                    "relocation of type {} to absolute address cannot be used in \
                    position-independent output; recompile with -fPIC",
                    rel.raw_type()
                );
            }
            let place = section_info.section_address + offset_in_section;
            let value = (rel.addend() as u64).wrapping_sub(place);
            A::relocation_from_raw(r_type)?
                .write_to_buffer(value, &mut out[offset_in_section as usize..])?;
            return Ok(RelocationModifier::Normal);
        }
        RelocationKind::Absolute
            if layout.symbol_db.output_kind.is_shared_object()
                && A::is_disallowed_in_shared_object(r_type) =>
        {
            bail!(
                "relocation type {} cannot be used when making a shared object; \
                 recompile with -fPIC",
                A::rel_type_to_string(r_type)
            );
        }
        _ => {}
    }
    let (resolution, symbol_index, local_symbol_id) = get_resolution(rel, object_layout, layout)?;
    let flags = layout.flags_for_symbol(local_symbol_id);
    if layout.symbol_db.output_kind.is_position_independent()
        && (flags.is_interposable() || flags.is_dynamic())
        && !flags.needs_copy_relocation()
        && !flags.needs_plt()
        && A::is_disallowed_for_interposable_symbols(r_type)
    {
        bail!(
            "relocation {} cannot be used against symbol; recompile with -fPIC",
            A::rel_type_to_string(r_type)
        );
    }
    let mut next_modifier = RelocationModifier::Normal;
    let rel_info;
    let output_kind = layout.symbol_db.output_kind;

    let relaxation = A::new_relaxation(
        r_type,
        out,
        offset_in_section,
        flags,
        output_kind,
        section_info.section_flags,
        relax_deltas,
        resolution.raw_value,
        section_address,
        rel.addend(),
        relocation_cache
            .previous
            .as_ref()
            .filter(|r| r.symbol() == rel.symbol())
            .map(|r| PreviousRelocationInfo {
                kind: r.raw_type(),
                offset: r.offset(),
                symbol: r.symbol(),
                addend: r.addend(),
            }),
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
    let bias = rel_info.bias;
    // For ppc64 calls, branch to the callee's local entry point (we share its TOC, so the global
    // entry's r2 setup is unnecessary). Zero for every other architecture and relocation.
    let branch_local_entry = if rel_info.size.is_ppc64_branch() {
        A::local_entry_offset(callee_st_other(layout, local_symbol_id))
    } else {
        0
    };
    let mut value = match rel_info.kind {
        RelocationKind::Absolute => write_absolute_relocation::<C, A>(
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
            &layout.symbol_db.section_part_ids,
            &layout.merged_strings,
            &layout.merged_string_start_addresses,
        )?,
        RelocationKind::AbsoluteLowPart => resolution
            .value_with_addend(
                addend,
                symbol_index,
                object_layout,
                &layout.symbol_db.section_part_ids,
                &layout.merged_strings,
                &layout.merged_string_start_addresses,
            )?
            .bitand(mask.symbol_plus_addend),
        RelocationKind::Relative => resolution
            .value_with_addend(
                addend,
                symbol_index,
                object_layout,
                &layout.symbol_db.section_part_ids,
                &layout.merged_strings,
                &layout.merged_string_start_addresses,
            )?
            .wrapping_add(branch_local_entry)
            .wrapping_add(bias)
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::RelativeLoongArchHigh => highest_relocation_with_bias(
            resolution.value_with_addend(
                addend,
                symbol_index,
                object_layout,
                &layout.symbol_db.section_part_ids,
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
                    &layout.symbol_db.section_part_ids,
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
                            && A::high_part_relocations().contains(&r.raw_type())
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

            let hi_rel_info = A::relocation_from_raw(hi_rel.raw_type())?;
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
                        &layout.symbol_db.section_part_ids
                            [object_layout.section_id_range.as_usize()],
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
                    .format_specific
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
            get_pair_subtraction_relocation_value::<C, A, R>(
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
                &layout.symbol_db.section_part_ids,
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
            .format_specific
            .tlsld_got_entry
            .unwrap()
            .get()
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::TlsLdGot => layout
            .prelude()
            .format_specific
            .tlsld_got_entry
            .unwrap()
            .get()
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .bitand(mask.got_entry),
        RelocationKind::TlsLdGotBase => layout
            .prelude()
            .format_specific
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
        RelocationKind::TpOff
            if layout
                .symbol_db
                .is_undefined(layout.symbol_db.definition(local_symbol_id)) =>
        {
            // An undefined weak TLS symbol has no offset within the TLS block, so we somewhat
            // arbitrarily give the 0 offset which at least some other linkers also do and most
            // importantly is a value guaranteed to fit within the range of any relocation.
            (addend as u64).wrapping_add(bias)
        }
        RelocationKind::TpOff => resolution
            .value()
            .wrapping_add(addend as u64)
            .wrapping_add(bias)
            .wrapping_sub(A::tp_offset_start(layout)),
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
        value = rel_info.adjust_value_based_on_content(value, out, offset_in_section)?;
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

    if let Some(thunked_value) = maybe_get_thunk_for_relocation::<C, A>(
        object_layout,
        section_info,
        layout,
        rel_info,
        local_symbol_id,
        place,
        value,
    )? {
        value = thunked_value;
    }

    rel_info.write_to_buffer(value, &mut out[offset_in_section..])?;

    Ok(next_modifier)
}

/// Checks if we need to use a thunk for a relocation and if we do, return the value to use for the
/// thunk.
fn maybe_get_thunk_for_relocation<C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    object_layout: &ObjectLayout<elf::Elf<C>>,
    section_info: SectionInfo<SectionFlags>,
    layout: &Layout<elf::Elf<C>>,
    rel_info: RelocationKindInfo,
    local_symbol_id: SymbolId,
    place: u64,
    value: u64,
) -> Result<Option<u64>> {
    let Some(config) = A::thunk_config() else {
        return Ok(None);
    };

    if !rel_info.thunkable {
        return Ok(None);
    }

    if rel_info.range.contains(value as i64) {
        return Ok(None);
    }

    let canonical_id = layout.symbol_db.definition(local_symbol_id);

    let thunk_id = if section_info.part_id == config.primary_function_part_id {
        object_layout.thunk_block_id
    } else {
        ThunkBlockId::FIRST
    };

    let thunk_address_opt = layout
        .thunk_block_addresses
        .get(thunk_id.as_usize())
        .and_then(|m| m.get(&canonical_id))
        .copied();

    if let Some(thunk_address) = thunk_address_opt {
        if thunk_address == 0 {
            bail!(
                "Thunk address not yet allocated for symbol {}",
                layout.symbol_db.symbol_name_for_display(local_symbol_id)
            );
        }

        let mask = get_page_mask(rel_info.mask);
        let new_value = thunk_address
            .wrapping_add(rel_info.bias)
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(place.bitand(mask.place));

        tracing::trace!(
            old_value = value,
            new_value,
            thunk_address,
            "Using thunk instead of out-of-range branch"
        );

        return Ok(Some(new_value));
    }

    bail!(
        "Branch relocation out of range by {over} for symbol {sym} \
         but no thunk allocated. Part: {part}. Offset: {offset}",
        over = rel_info.range.overrun(value as i64),
        sym = layout.symbol_db.symbol_name_for_display(local_symbol_id),
        part = layout.output_sections.part_debug(section_info.part_id),
        offset = value as i64,
    );
}

fn apply_debug_relocation<
    'data,
    C: ElfClass,
    A: Arch<Platform = elf::Elf<C>>,
    R: Relocation<Platform = elf::Elf<C>>,
>(
    object_layout: &ObjectLayout<'data, elf::Elf<C>>,
    offset_in_section: u64,
    rel: &R,
    layout: &ElfLayout<C>,
    section_tombstone_value: u64,
    out: &mut [u8],
    relocation_cache: &RelocationCache<R>,
) -> Result<()> {
    let symbol_index = rel.symbol().context("Unsupported absolute relocation")?;
    let sym = object_layout.object.symbol(symbol_index)?;
    let section_index = object_layout.object.symbol_section(sym, symbol_index)?;

    let addend = rel.addend();
    let r_type = rel.raw_type();
    let rel_info = A::relocation_from_raw(r_type)?;

    let resolution = layout
        .merged_symbol_resolution(object_layout.symbol_id_range.input_to_id(symbol_index))
        .or_else(|| {
            section_index.and_then(|section_index| {
                let section_address =
                    object_layout.section_resolutions[section_index.0].address()?;
                // Include the symbol's offset within the section (adjusted for any relaxation
                // deltas). This is necessary on architectures like RISC-V and LoongArch64 where
                // debug info references local symbols (e.g. .LFB0, .LFE0) whose value is their
                // offset within the section, rather than section symbols where the offset is
                // encoded in the relocation addend.
                let output_offset = opt_input_to_output(
                    object_layout.section_relax_deltas.get(section_index.0),
                    crate::platform::Symbol::value(sym),
                );

                Some(Resolution {
                    raw_value: section_address + output_offset,
                    dynamic_symbol_index: None,
                    flags: ValueFlags::empty(),
                    format_specific: Default::default(),
                })
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
                    &layout.symbol_db.section_part_ids,
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
                    value = rel_info.adjust_value_based_on_content(
                        value,
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
                get_pair_subtraction_relocation_value::<C, A, R>(
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
            SectionSlot::MergeStrings(..) => get_merged_string_output_address::<elf::Elf<C>>(
                symbol_index,
                addend,
                object_layout.object,
                &object_layout.sections,
                &layout.symbol_db.section_part_ids,
                object_layout.section_id_range,
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

    rel_info.write_to_buffer(value, &mut out[offset_in_section as usize..])?;

    Ok(())
}

#[inline(always)]
fn write_absolute_relocation<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    table_writer: &mut TableWriter<'_, '_, C>,
    resolution: Resolution<elf::Elf<C>>,
    place: u64,
    addend: i64,
    section_info: SectionInfo<<A::Platform as Platform>::SectionFlags>,
    symbol_index: object::SymbolIndex,
    object_layout: &ObjectLayout<'data, elf::Elf<C>>,
    layout: &ElfLayout<C>,
) -> Result<u64> {
    if !section_info.section_flags.is_alloc() {
        resolution.value_with_addend(
            addend,
            symbol_index,
            object_layout,
            &layout.symbol_db.section_part_ids,
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
        table_writer.write_dynamic_symbol_relocation::<A>(
            place,
            addend,
            resolution.dynamic_symbol_index()?,
            DynamicRelocationKind::Absolute,
        )?;

        Ok(0)
    } else if resolution.flags.is_ifunc()
        && section_info.is_writable
        && table_writer.output_kind.is_position_independent()
    {
        table_writer
            .write_ifunc_relocation_for_data::<A>(place, resolution.raw_value as i64 + addend)?;
        Ok(0)
    } else if table_writer.output_kind.is_position_independent() && !resolution.is_absolute() {
        let address = resolution.value_with_addend(
            addend,
            symbol_index,
            object_layout,
            &layout.symbol_db.section_part_ids,
            &layout.merged_strings,
            &layout.merged_string_start_addresses,
        )?;
        table_writer.write_address_relocation::<A>(place, address)
    } else {
        resolution.value_with_addend(
            addend,
            symbol_index,
            object_layout,
            &layout.symbol_db.section_part_ids,
            &layout.merged_strings,
            &layout.merged_string_start_addresses,
        )
    }
}

fn write_prelude<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    prelude: &PreludeLayout<elf::Elf<C>>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<'data, C>,
) -> Result {
    let gdb_buf = buffers.take(part_id::GDB_INDEX);
    let (a, b) = rayon::join(
        || {
            if let Some(scan) = &layout.gdb_index_data {
                timing_phase!("Write GDB index");
                crate::gdb_index::write_gdb_index(gdb_buf, layout, scan)
            } else {
                Ok(())
            }
        },
        || write_prelude_except_gdb_index::<C, A>(prelude, buffers, table_writer, layout),
    );
    a.and(b)
}

fn write_prelude_except_gdb_index<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    prelude: &PreludeLayout<elf::Elf<C>>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<'data, C>,
) -> Result {
    verbose_timing_phase!("Write prelude");

    let header: &mut elf::FileHeader<C> =
        from_bytes_mut(buffers.get_mut(crate::part_id::FILE_HEADER))
            .map_err(|_| error!("Invalid file header allocation"))?
            .0;
    populate_file_header::<C, A>(layout, &prelude.header_info, header)?;

    let mut program_headers =
        ProgramHeaderWriter::<C>::new(buffers.get_mut(part_id::PROGRAM_HEADERS));
    write_program_headers(&mut program_headers, layout)?;

    write_section_headers(table_writer, layout)?;

    write_plt_got_entries::<C, A>(prelude, layout, table_writer)?;

    if !layout.args().should_strip_all() {
        write_symbol_table_entries(prelude, &mut table_writer.debug_symbol_writer, layout)?;
    }

    if layout.args().should_write_eh_frame_hdr
        && layout
            .section_layouts
            .get(output_section_id::EH_FRAME_HDR)
            .mem_size
            > 0
    {
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
        table_writer.dynsym_writer.undefined_symbol(false, &[])?;
    }

    Ok(())
}

fn write_interp<C: ElfClass>(
    prelude: &PreludeLayout<elf::Elf<C>>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) {
    if let Some(dynamic_linker) = prelude.dynamic_linker.as_ref() {
        buffers
            .get_mut(part_id::INTERP)
            .copy_from_slice(dynamic_linker.as_bytes_with_nul());
    }
}

fn write_merged_strings<C: ElfClass>(
    prelude: &PreludeLayout<elf::Elf<C>>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &ElfLayout<C>,
) {
    layout.merged_strings.for_each(|section_id, merged| {
        if merged.len() > 0 {
            let buffer = buffers
                .get_mut(section_id.part_id_with_alignment::<elf::Elf<C>>(crate::alignment::MIN));

            write_merged_strings_to_buffer(merged, buffer);
        }
    });

    if layout.args().should_write_linker_identity {
        // Write linker identity into .comment section.
        let comment_buffer = buffers.get_mut(
            output_section_id::COMMENT.part_id_with_alignment::<elf::Elf<C>>(alignment::MIN),
        );
        comment_buffer
            .split_off_mut(..prelude.identity.len())
            .unwrap()
            .copy_from_slice(prelude.identity.as_bytes());
    }
}

pub(crate) fn write_merged_strings_to_buffer(
    merged: &crate::string_merging::MergedStringsSection,
    buffer: &mut &mut [u8],
) {
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

fn write_plt_got_entries<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    prelude: &PreludeLayout<elf::Elf<C>>,
    layout: &ElfLayout<'data, C>,
    table_writer: &mut TableWriter<'_, '_, C>,
) -> Result {
    for _ in 0..prelude.format_specific.got_plt_header_entries {
        *table_writer.take_next_got_entry()? = elf::Word::<C>::from_u64(0)?;
    }

    // Write a pair of GOT entries for use by any TLSLD or TLSGD relocations.
    if let Some(got_address) = prelude.format_specific.tlsld_got_entry {
        let mut raw_value = 0;

        if layout.symbol_db.output_kind.is_executable() {
            table_writer.process_resolution::<A>(
                Some(layout),
                layout.args(),
                &Resolution {
                    raw_value: crate::elf::CURRENT_EXE_TLS_MOD,
                    dynamic_symbol_index: None,
                    format_specific: crate::elf::ResolutionExt {
                        got_address: Some(got_address),
                        plt_address: None,
                    },
                    flags: ValueFlags::GOT | ValueFlags::ABSOLUTE,
                },
            )?;

            // For executables, DTPOFF values are negative values relative to the thread pointer,
            // which is at the end of the TLS segment.
            raw_value = A::tp_offset_start(layout) - layout.tls_start_address();
        } else {
            *table_writer.take_next_got_entry()? = elf::Word::<C>::from_u64(0)?;
            table_writer.write_dtpmod_relocation::<A>(got_address.get(), 0)?;
        }

        table_writer.process_resolution::<A>(
            Some(layout),
            layout.args(),
            &Resolution {
                raw_value,
                dynamic_symbol_index: None,
                format_specific: crate::elf::ResolutionExt {
                    got_address: Some(got_address.saturating_add(C::GOT_ENTRY_SIZE)),
                    plt_address: None,
                },
                flags: ValueFlags::GOT | ValueFlags::ABSOLUTE,
            },
        )?;
    }

    write_internal_symbols_plt_got_entries::<C, A>(
        &prelude.internal_symbols,
        table_writer,
        layout,
    )?;
    Ok(())
}

fn write_symbol_table_entries<C: ElfClass>(
    prelude: &PreludeLayout<elf::Elf<C>>,
    symbol_writer: &mut SymbolTableWriter<'_, '_, C>,
    layout: &ElfLayout<C>,
) -> Result {
    // Define symbol 0. This needs to be a null placeholder.
    symbol_writer.undefined_symbol(true, &[])?;

    if layout.args().should_output_partial_object() {
        write_section_symbols(symbol_writer, layout)?;
    }

    let internal_symbols = &prelude.internal_symbols;

    write_internal_symbols(internal_symbols, layout, symbol_writer)?;
    Ok(())
}

fn write_section_symbols<C: ElfClass>(
    symbol_writer: &mut SymbolTableWriter<'_, '_, C>,
    layout: &ElfLayout<C>,
) -> Result {
    for event in &layout.output_order {
        let OrderEvent::Section(section_id) = event else {
            continue;
        };
        let Some(shndx) = layout.output_sections.output_index_of_section(section_id) else {
            continue;
        };
        if !layout
            .output_sections
            .will_emit_section_symbol_for_partial_objects(section_id)
        {
            continue;
        }
        let entry = symbol_writer.define_symbol(true, SymbolSection::Index(shndx), 0, 0, None)?;
        entry.set_binding_and_type(object::elf::STB_LOCAL, object::elf::STT_SECTION);
    }
    Ok(())
}

fn write_verdef<C: ElfClass>(
    verdefs: &[VersionDef],
    table_writer: &mut TableWriter<'_, '_, C>,
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
        verdef_out.vd_flags.set(
            e,
            if i == 0 {
                object::elf::VER_FLG_BASE
            } else {
                object::elf::VersionFlags(0)
            },
        );
        verdef_out
            .vd_ndx
            .set(e, object::elf::VER_NDX_GLOBAL + i as u16);
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

fn write_epilogue_dynamic_entries<C: ElfClass>(
    layout: &ElfLayout<C>,
    table_writer: &mut TableWriter<'_, '_, C>,
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
        rela_entry_size: C::RELA_ENTRY_SIZE,
        relr_entry_size: C::RELR_ENTRY_SIZE,
        symtab_entry_size: C::SYMTAB_ENTRY_SIZE,
    };

    for writer in EPILOGUE_DYNAMIC_ENTRY_WRITERS {
        writer.write(&mut table_writer.dynamic, &inputs)?;
    }

    table_writer.dynamic.write_unused()?;

    Ok(())
}

#[derive(Default)]
pub(crate) struct EpilogueOffsets {
    /// The offset of the shared object name in .dynsym.
    pub(crate) soname: Option<u32>,
}

fn write_linker_script_state<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    script: &LinkerScriptLayoutState<elf::Elf<C>>,
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<'data, C>,
) -> Result {
    verbose_timing_phase!("Write linker script state");

    write_internal_symbols(
        &script.internal_symbols,
        layout,
        &mut table_writer.debug_symbol_writer,
    )?;

    write_internal_symbols_plt_got_entries::<C, A>(&script.internal_symbols, table_writer, layout)?;

    Ok(())
}

fn write_synthetic_symbols<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    syn: &SyntheticSymbolsLayout<elf::Elf<C>>,
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<'data, C>,
) -> Result {
    verbose_timing_phase!("Write synthetic symbols");

    write_internal_symbols_plt_got_entries::<C, A>(&syn.internal_symbols, table_writer, layout)?;

    if !layout.args().should_strip_all() {
        write_internal_symbols(
            &syn.internal_symbols,
            layout,
            &mut table_writer.debug_symbol_writer,
        )?;
    }

    Ok(())
}

fn write_epilogue<C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    epilogue: &EpilogueLayout<elf::Elf<C>>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<C>,
    trace: &TraceOutput,
) -> Result {
    verbose_timing_phase!("Write epilogue");

    let mut epilogue_offsets = EpilogueOffsets::default();

    if layout.symbol_db.output_kind.needs_dynamic() {
        write_epilogue_dynamic_entries(layout, table_writer, &mut epilogue_offsets)?;
    }

    let got_relr_n = layout.got_relr_n;
    if got_relr_n > 0 {
        let got_relr_base = layout
            .section_part_layouts
            .get(part_id::GOT_RELR)
            .mem_offset;
        table_writer.write_got_relr_bitmap(got_relr_n, got_relr_base)?;
    }
    write_sysv_hash_table(layout, epilogue, buffers)?;
    write_gnu_hash_tables(layout, epilogue, buffers)?;

    write_dynamic_symbol_definitions(table_writer, layout)?;

    if !layout.format_specific.gnu_property_notes.is_empty() {
        write_gnu_property_notes(layout, buffers)?;
    }
    if layout.format_specific.riscv_attributes.section_size != 0 {
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
    if epilogue.format_specific.needs_eh_frame_terminator {
        table_writer.write_eh_frame_terminator();
    }

    // The actual build-id will be filled in later once all writing has completed. It's important
    // that we fill it with zeros now however, since if we're overwriting an existing file, there
    // might be other data there and we don't zero it, then the build ID will be hashing that data.
    let build_id_buffer = buffers.get_mut(part_id::NOTE_GNU_BUILD_ID);
    build_id_buffer.fill(0);

    for sorted_section in &layout.script_sorted_sections {
        let crate::layout::FileLayout::Object(object) = layout.file_layout(sorted_section.file_id)
        else {
            unreachable!();
        };

        if let SectionSlot::Sorted(sec) = &object.sections[sorted_section.section_index.0] {
            write_object_section::<C, A>(
                object,
                layout,
                sec.section,
                sorted_section.section_index,
                buffers,
                table_writer,
                trace,
            )?;
        }
    }

    write_compressed_debug_sections(layout, buffers);
    Ok(())
}

fn write_compressed_debug_sections<C: ElfClass>(
    layout: &ElfLayout<C>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) {
    verbose_timing_phase!("Write compressed debug sections");

    let mut work = Vec::new();

    for (section_id, _section_info) in layout.output_sections.ids_with_info() {
        if let Some(compressed_section) = layout.compressed_debug_sections.get(section_id) {
            let part_id = section_id.part_id_with_alignment::<elf::Elf<C>>(alignment::MIN);
            let buffer = buffers.get_mut(part_id);
            for chunk in &compressed_section.compressed_chunks {
                let out = buffer.split_off_mut(..chunk.len()).unwrap();
                work.push((out, chunk));
            }
        }
    }

    work.par_iter_mut().for_each(|(out, chunk)| {
        verbose_timing_phase!("Copy compressed chunk");
        out.copy_from_slice(chunk);
    });
}

fn write_gnu_property_notes<C: ElfClass>(
    layout: &ElfLayout<C>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let (note_header, mut rest) =
        from_bytes_mut::<elf::NoteHeader<C>>(buffers.get_mut(part_id::NOTE_GNU_PROPERTY))
            .map_err(|_| error!("Insufficient .note.gnu.property allocation"))?;
    note_header.set_name_size(GNU_NOTE_NAME.len() as u32);
    note_header.set_descriptor_size(
        (layout.format_specific.gnu_property_notes.len() as u64 * C::GNU_PROPERTY_ENTRY_SIZE)
            .try_into()
            .context(".note.gnu.property descriptor overflowed 32 bits")?,
    );
    note_header.set_type(NT_GNU_PROPERTY_TYPE_0);

    let name_out = rest.split_off_mut(..GNU_NOTE_NAME.len()).unwrap();
    name_out.copy_from_slice(GNU_NOTE_NAME);

    for note in &layout.format_specific.gnu_property_notes {
        let entry_size = C::GNU_PROPERTY_ENTRY_SIZE as usize;
        let entry = rest.split_off_mut(..entry_size).unwrap();
        let (property_bytes, padding) = entry.split_at_mut(size_of::<NoteProperty>());
        let property = NoteProperty::mut_from_bytes(property_bytes).unwrap();
        property.pr_type = note.ptype.0;
        property.pr_datasz = size_of_val(&property.pr_data) as u32;
        property.pr_data = note.data;
        padding.fill(0);
    }

    Ok(())
}

fn write_riscv_attributes<C: ElfClass>(
    layout: &ElfLayout<C>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let mut writer = Cursor::new(&mut **buffers.get_mut(part_id::RISCV_ATTRIBUTES));
    writer.write_all(b"A")?;

    let riscv_attributes_length = layout.format_specific.riscv_attributes.section_size as u32;

    writer.write_all((riscv_attributes_length - 1).to_le_bytes().as_slice())?;
    writer.write_all(RISCV_ATTRIBUTE_VENDOR_NAME.as_bytes())?;
    writer.write_all(b"\0")?;
    leb128::write::unsigned(&mut writer, TAG_RISCV_WHOLE_FILE)?;
    writer.write_all(
        (riscv_attributes_length - 1 - 4 - RISCV_ATTRIBUTE_VENDOR_NAME.len() as u32 - 1)
            .to_le_bytes()
            .as_slice(),
    )?;
    for tag in &layout.format_specific.riscv_attributes.attributes {
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

fn write_sysv_hash_table<C: ElfClass>(
    layout: &ElfLayout<C>,
    epilogue: &EpilogueLayout<elf::Elf<C>>,
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

    debug_assert_eq!(rest, []);

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

fn write_gnu_hash_tables<C: ElfClass>(
    layout: &ElfLayout<C>,
    epilogue: &EpilogueLayout<elf::Elf<C>>,
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

    let bloom_size = (gnu_hash_layout.bloom_count as usize)
        .checked_mul(C::GNU_HASH_BLOOM_SIZE as usize)
        .context(".gnu.hash bloom filter size overflow")?;
    ensure!(
        rest.len() >= bloom_size,
        "Insufficient bytes for .gnu.hash bloom filter"
    );
    let (bloom, rest) = rest.split_at_mut(bloom_size);
    let bloom = <[elf::Word<C>]>::mut_from_bytes(bloom)
        .map_err(|_| error!("Invalid .gnu.hash bloom filter size"))?;
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
    bloom.fill(elf::Word::<C>::from_u64(0)?);

    let mut sym_defs = layout.dynamic_symbol_definitions.iter().peekable();

    let elf_class_bits = C::ADDRESS_SIZE as u32 * 8;

    let mut start_of_chain = true;
    for (i, chain_out) in chains.iter_mut().enumerate() {
        let sym_def = sym_defs.next().unwrap();

        // For each symbol, we set two bits in the bloom filter. This speeds up dynamic loading,
        // since most symbols not defined by the shared object can be rejected just by the bloom
        // filter.
        let hash = sym_def.format_specific.hash;
        let bloom_index = ((hash / elf_class_bits) % gnu_hash_layout.bloom_count) as usize;
        let bit1 = 1 << (hash % elf_class_bits);
        let bit2 = 1 << ((hash >> gnu_hash_layout.bloom_shift) % elf_class_bits);
        bloom[bloom_index] = elf::Word::<C>::from_u64(bloom[bloom_index].into() | bit1 | bit2)?;

        // Chain values are the hashes for the corresponding symbols (shifted by symbol_base). Bit 0
        // is cleared and then later set to 1 to indicate the end of the chain.
        *chain_out = hash & !1;
        let bucket = gnu_hash_layout.bucket_for_hash(hash);
        if start_of_chain {
            buckets[bucket as usize] = (i as u32) + gnu_hash_layout.symbol_base;
            start_of_chain = false;
        }
        let last_in_chain = sym_defs.peek().is_none_or(|next| {
            gnu_hash_layout.bucket_for_hash(next.format_specific.hash) != bucket
        });
        if last_in_chain {
            *chain_out |= 1;
            start_of_chain = true;
        }
    }
    Ok(())
}

fn write_dynamic_symbol_definitions<C: ElfClass>(
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<C>,
) -> Result {
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
                            write_symbol_version(versym, sym_def.format_specific.version)?;
                        }
                    }
                    FileLayout::Dynamic(object) => {
                        if layout
                            .flags_for_symbol(sym_def.symbol_id)
                            .needs_canonical_plt()
                        {
                            write_canonical_plt_dynamic_symbol_definition(
                                sym_def,
                                object,
                                layout,
                                &mut table_writer.dynsym_writer,
                            )?;
                        } else {
                            write_copy_relocation_dynamic_symbol_definition(
                                sym_def,
                                object,
                                layout,
                                &mut table_writer.dynsym_writer,
                            )?;
                        }

                        if let Some(versym) = table_writer.versym.as_mut() {
                            copy_symbol_version(
                                object.object.symbol_versions(),
                                object.symbol_id_range.id_to_offset(sym_def.symbol_id),
                                &object.format_specific.version_mapping,
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
                            write_symbol_version(versym, sym_def.format_specific.version)?;
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
fn write_linker_script_dynsym<C: ElfClass>(
    dynsym_writer: &mut SymbolTableWriter<'_, '_, C>,
    layout: &ElfLayout<C>,
    symbol_id: SymbolId,
    script: &LinkerScriptLayoutState<elf::Elf<C>>,
) -> Result {
    let local_index = script
        .internal_symbols
        .symbol_id_range()
        .id_to_offset(symbol_id);
    let info = &script.internal_symbols.symbol_definitions[local_index];
    write_internal_dynsym(dynsym_writer, layout, symbol_id, info)
}

/// Get the section index and type for a symbol.
/// This is used to copy attributes from a target symbol to a defsym alias.
fn get_symbol_attributes<C: ElfClass>(
    layout: &ElfLayout<C>,
    symbol_id: SymbolId,
) -> Result<(SymbolSection, object::elf::SymbolType)> {
    let file_id = layout.symbol_db.file_id_for_symbol(symbol_id);

    match layout.file_layout(file_id) {
        FileLayout::Object(obj) => {
            let local_index = symbol_id.to_input(obj.symbol_id_range);
            let sym = obj.object.symbol(local_index)?;

            let shndx = obj
                .object
                .symbol_section(sym, local_index)?
                .and_then(|section_index| {
                    let slot = &obj.sections[section_index.0];
                    match slot {
                        SectionSlot::Loaded(_)
                        | SectionSlot::MergeStrings(_)
                        | SectionSlot::Sorted(_) => {
                            let output_section_id = obj
                                .section_part_id(section_index, &layout.symbol_db.section_part_ids)
                                .output_section_id::<elf::Elf<C>>();
                            layout
                                .output_sections
                                .output_index_of_section(output_section_id)
                        }
                        _ => None,
                    }
                })
                .map_or(object::elf::SHN_ABS.into(), SymbolSection::Index);

            let st_type = sym.st_type();

            Ok((shndx, st_type))
        }
        FileLayout::LinkerScript(script) => {
            let local_index = symbol_id.to_input(script.symbol_id_range);
            let def_info = &script.internal_symbols.symbol_definitions[local_index.0];
            let shndx = if let crate::parsing::SymbolPlacement::Redirect(redirect) =
                &def_info.placement
                && !redirect.expression.is_absolute()
                && let SymbolLoc::SectionEnd(section_id) = redirect.loc
            {
                let section_id = layout.output_sections.primary_output_section(section_id);
                layout
                    .output_sections
                    .output_index_of_nearest_section(section_id)
            } else {
                def_info.section_id().and_then(|section_id| {
                    let section_id = layout.output_sections.primary_output_section(section_id);
                    layout.output_sections.output_index_of_section(section_id)
                })
            }
            .map_or(object::elf::SHN_ABS.into(), SymbolSection::Index);

            Ok((shndx, object::elf::STT_NOTYPE))
        }
        FileLayout::Prelude(prelude) => {
            let offset = symbol_id.offset_from(SymbolId::undefined());
            let def_info = &prelude.internal_symbols.symbol_definitions[offset];
            let shndx = def_info
                .section_id()
                .and_then(|section_id| {
                    let section_id = layout.output_sections.primary_output_section(section_id);
                    layout.output_sections.output_index_of_section(section_id)
                })
                .map_or(object::elf::SHN_ABS.into(), SymbolSection::Index);
            Ok((shndx, def_info.symbol.st_type()))
        }
        FileLayout::SyntheticSymbols(_) => {
            // For other non-object files (e.g. epilogue), default to ABS
            Ok((object::elf::SHN_ABS.into(), object::elf::STT_NOTYPE))
        }
        FileLayout::Dynamic(_) | FileLayout::Epilogue(_) | FileLayout::NotLoaded => {
            Ok((object::elf::SHN_ABS.into(), object::elf::STT_NOTYPE))
        }
        FileLayout::StubLibrary(_) => unreachable!(),
    }
}

fn get_defsym_attributes<C: ElfClass>(
    layout: &ElfLayout<C>,
    def_info: &crate::parsing::InternalSymDefInfo<elf::Elf<C>>,
) -> Result<(SymbolSection, object::elf::SymbolType), error::Error> {
    let crate::parsing::SymbolPlacement::Redirect(redirect) = &def_info.placement else {
        unreachable!()
    };
    if let Expression::Symbol(target_name) = redirect.expression {
        let target_symbol_id =
            layout
                .symbol_db
                .get_unversioned(&crate::symbol::UnversionedSymbolName::prehashed(
                    target_name,
                ));

        if let Some(target_id) = target_symbol_id {
            let canonical_id = layout.symbol_db.definition(target_id);
            get_symbol_attributes(layout, canonical_id)
        } else {
            Err(redirect.missing_target(target_name))
        }
    } else {
        if redirect.expression.is_absolute() {
            return Ok((object::elf::SHN_ABS.into(), object::elf::STT_NOTYPE));
        }
        let shndx = match redirect.loc {
            SymbolLoc::SectionEnd(os) => {
                let os = layout.output_sections.primary_output_section(os);
                layout.output_sections.output_index_of_nearest_section(os)
            }
            SymbolLoc::SectionStartRelative(os) | SymbolLoc::SectionEndRelative(os) => {
                let os = layout.output_sections.primary_output_section(os);
                layout.output_sections.output_index_of_section(os)
            }
            SymbolLoc::FirstSection => Some(1),
            SymbolLoc::LocationCounter(_, Some(os)) => {
                let os = layout.output_sections.primary_output_section(os);
                layout.output_sections.output_index_of_section(os)
            }
            SymbolLoc::LocationCounter(_, None) => Some(1),
            SymbolLoc::None => return Ok((object::elf::SHN_ABS.into(), object::elf::STT_NOTYPE)),
        };
        Ok((
            shndx.map_or(
                SymbolSection::Raw(object::elf::SHN_ABS),
                SymbolSection::Index,
            ),
            object::elf::STT_NOTYPE,
        ))
    }
}

fn write_prelude_dynsym<C: ElfClass>(
    dynsym_writer: &mut SymbolTableWriter<'_, '_, C>,
    layout: &ElfLayout<C>,
    symbol_id: SymbolId,
    prelude: &PreludeLayout<elf::Elf<C>>,
) -> Result {
    let offset = symbol_id.offset_from(prelude.internal_symbols.start_symbol_id);
    let def_info = prelude
        .internal_symbols
        .symbol_definitions
        .get(offset)
        .with_context(|| format!("Invalid prelude symbol {}", layout.symbol_debug(symbol_id)))?;
    write_internal_dynsym(dynsym_writer, layout, symbol_id, def_info)
}

fn write_internal_dynsym<C: ElfClass>(
    dynsym_writer: &mut SymbolTableWriter<'_, '_, C>,
    layout: &ElfLayout<C>,
    symbol_id: SymbolId,
    def_info: &crate::parsing::InternalSymDefInfo<elf::Elf<C>>,
) -> Result {
    if matches!(
        def_info.placement,
        crate::parsing::SymbolPlacement::Redirect(_)
    ) {
        return write_defsym_dynsym(dynsym_writer, layout, symbol_id, def_info);
    }

    let section_id = def_info
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

    let entry = dynsym_writer.define_symbol(
        false,
        SymbolSection::Index(shndx),
        address,
        0,
        Some(name.bytes()),
    )?;
    entry.set_binding_and_type(object::elf::STB_GLOBAL, object::elf::STT_NOTYPE);

    Ok(())
}

/// Writes a dynsym entry for a symbol defined via --defsym or linker script symbol assignment.
fn write_defsym_dynsym<C: ElfClass>(
    dynsym_writer: &mut SymbolTableWriter<'_, '_, C>,
    layout: &ElfLayout<C>,
    symbol_id: SymbolId,
    def_info: &crate::parsing::InternalSymDefInfo<elf::Elf<C>>,
) -> Result {
    let (shndx, st_type) = get_defsym_attributes(layout, def_info)?;

    let resolution = layout
        .local_symbol_resolution(symbol_id)
        .with_context(|| format!("Missing resolution for {}", layout.symbol_debug(symbol_id)))?;
    let address = resolution.raw_value;
    let name = layout.symbol_db.symbol_name(symbol_id)?;

    let entry = dynsym_writer
        .define_symbol(false, shndx, address, 0, Some(name.bytes()))
        .with_context(|| {
            format!(
                "Failed to define dynamic {}",
                layout.symbol_debug(symbol_id)
            )
        })?;
    entry.set_binding_and_type(object::elf::STB_GLOBAL, st_type);

    Ok(())
}

fn write_copy_relocation_dynamic_symbol_definition<'data, C: ElfClass>(
    sym_def: &crate::layout::DynamicSymbolDefinition<elf::Elf<C>>,
    object: &DynamicLayout<'data, elf::Elf<C>>,
    layout: &ElfLayout<C>,
    dynamic_symbol_writer: &mut SymbolTableWriter<'_, '_, C>,
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

fn write_canonical_plt_dynamic_symbol_definition<'data, C: ElfClass>(
    sym_def: &crate::layout::DynamicSymbolDefinition<elf::Elf<C>>,
    object: &DynamicLayout<'data, elf::Elf<C>>,
    layout: &ElfLayout<C>,
    dynamic_symbol_writer: &mut SymbolTableWriter<'_, '_, C>,
) -> Result {
    let sym_index = sym_def.symbol_id.to_input(object.symbol_id_range);
    let sym = object.object.symbol(sym_index)?;

    let resolution = layout
        .local_symbol_resolution(sym_def.symbol_id)
        .context("Canonical PLT symbol has no resolution")?;

    let entry = dynamic_symbol_writer.undefined_symbol(false, sym_def.name)?;
    entry.set_value(resolution.plt_address()?)?;
    entry.set_binding_and_type(sym.st_bind(), object::elf::STT_FUNC);

    Ok(())
}

fn write_regular_object_dynamic_symbol_definition<'data, C: ElfClass>(
    sym_def: &crate::layout::DynamicSymbolDefinition<elf::Elf<C>>,
    object: &ObjectLayout<'data, elf::Elf<C>>,
    layout: &ElfLayout<C>,
    dynamic_symbol_writer: &mut SymbolTableWriter<'_, '_, C>,
) -> Result {
    let sym_index = sym_def.symbol_id.to_input(object.symbol_id_range);
    let sym = object.object.symbol(sym_index)?;
    let name = sym_def.name;
    let section_index = object.object.symbol_section(sym, sym_index)?;
    if section_index.is_none()
        && !platform::Symbol::is_common(sym)
        && !platform::Symbol::is_absolute(sym)
    {
        dynamic_symbol_writer
            .copy_symbol_shndx(sym, name, 0, 0, ValueFlags::empty())
            .with_context(|| {
                format!(
                    "Failed to copy dynamic {}",
                    layout.symbol_debug(sym_def.symbol_id)
                )
            })?;
        return Ok(());
    }

    let symbol_id = sym_def.symbol_id;
    let resolution = layout.local_symbol_resolution(symbol_id).with_context(|| {
        format!(
            "Tried to write dynamic symbol definition without a resolution: {}",
            layout.symbol_debug(symbol_id)
        )
    })?;

    // For non-PIE executables, export IFUNC symbols as STT_FUNC pointing to PLT stub.
    // For PIE executables, keep IFUNC as-is.
    if section_index.is_some()
        && resolution.flags.is_ifunc()
        && layout.symbol_db.output_kind.is_executable()
        && !layout.symbol_db.output_kind.is_position_independent()
        && let Some(plt_address) = resolution.format_specific.plt_address
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
        let size = object_symbol_size(sym, sym_index, object)?;
        let entry = dynamic_symbol_writer.define_symbol(
            false,
            SymbolSection::Index(shndx),
            plt_address.into(),
            size,
            Some(name),
        )?;
        entry.set_binding_and_type(sym.st_bind(), object::elf::STT_FUNC);
        entry.set_other(sym.st_other());
    } else {
        let mut symbol_value = resolution.value_for_symbol_table();
        if sym.st_type() == object::elf::STT_TLS {
            symbol_value -= layout.tls_start_address();
        }

        dynamic_symbol_writer
            .copy_object_symbol(
                sym,
                sym_index,
                symbol_id,
                name,
                object,
                layout,
                symbol_value,
                ValueFlags::empty(),
            )
            .with_context(|| {
                format!("Failed to copy dynamic {}", layout.symbol_debug(symbol_id))
            })?;
    }
    Ok(())
}

fn write_internal_symbols<C: ElfClass>(
    internal_symbols: &InternalSymbols<elf::Elf<C>>,
    layout: &ElfLayout<C>,
    symbol_writer: &mut SymbolTableWriter<'_, '_, C>,
) -> Result {
    for (local_index, def_info) in internal_symbols.symbol_definitions.iter().enumerate() {
        if def_info.name.is_empty() {
            continue;
        }
        let symbol_id = internal_symbols.start_symbol_id.add_usize(local_index);
        if !layout.symbol_db.is_canonical(symbol_id) {
            continue;
        }
        let Some(resolution) = layout.local_symbol_resolution(symbol_id) else {
            continue;
        };

        let symbol_name = layout.symbol_db.symbol_name(symbol_id)?;

        // For Redirect, get attributes from the target symbol
        let (mut shndx, st_type) = if matches!(
            def_info.placement,
            crate::parsing::SymbolPlacement::Redirect(_)
        ) {
            get_defsym_attributes(layout, def_info)?
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
                .map_or(object::elf::SHN_ABS.into(), SymbolSection::Index);

            (shndx, def_info.symbol.st_type())
        };

        // Move symbols that are in our header (section 0) into the first section, otherwise they'll
        // show up as undefined.
        if matches!(shndx, SymbolSection::Index(0)) {
            shndx = SymbolSection::Index(1);
        }

        let mut address = resolution.value();

        if platform::Symbol::is_tls(&def_info.symbol) {
            address -= layout.tls_start_address();
        }

        // Mandatory RISC-V symbol defined by the default linker script as:
        // __global_pointer$ = MIN(__SDATA_BEGIN__ + 0x800, MAX(__DATA_BEGIN__ + 0x800, __BSS_END__
        // - 0x800));
        if symbol_name.bytes() == GLOBAL_POINTER_SYMBOL_NAME.as_bytes() {
            address += RISCV_TLS_DTV_OFFSET;
        }

        // PROVIDE_HIDDEN symbols should be local, not global
        let st_bind = if platform::Symbol::is_hidden(&def_info.symbol) {
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
                Some(symbol_name.bytes()),
            )
            .with_context(|| format!("Failed to write {}", layout.symbol_debug(symbol_id)))?;

        entry.set_binding_and_type(st_bind, st_type);
        if platform::Symbol::is_hidden(&def_info.symbol) {
            entry.set_other(object::elf::STV_HIDDEN.into());
        }
    }
    Ok(())
}

fn write_eh_frame_hdr<C: ElfClass>(
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<C>,
) -> Result {
    let header = table_writer.take_eh_frame_hdr();
    header.version = 1;

    header.table_encoding = (gimli::DW_EH_PE_sdata4 | gimli::DW_EH_PE_datarel).0;
    header.frame_pointer_encoding = (gimli::DW_EH_PE_sdata4 | gimli::DW_EH_PE_pcrel).0;
    header.frame_pointer = eh_frame_ptr(layout)?;

    header.count_encoding = (gimli::DW_EH_PE_udata4 | gimli::DW_EH_PE_absptr).0;
    header.entry_count = eh_frame_hdr_entry_count(layout)?;

    Ok(())
}

fn eh_frame_hdr_entry_count<C: ElfClass>(layout: &ElfLayout<C>) -> Result<u32> {
    let hdr_sec = layout.section_layouts.get(output_section_id::EH_FRAME_HDR);
    u32::try_from(
        (hdr_sec.mem_size - size_of::<elf::EhFrameHdr>() as u64)
            / size_of::<elf::EhFrameHdrEntry>() as u64,
    )
    .context(".eh_frame_hdr entries overflowed 32 bits")
}

/// Returns the address of .eh_frame relative to the location in .eh_frame_hdr where the frame
/// pointer is stored.
fn eh_frame_ptr<C: ElfClass>(layout: &ElfLayout<C>) -> Result<i32> {
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
    DynamicEntryWriter::new(object::elf::DT_SYMENT, |inputs| inputs.symtab_entry_size),
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
        |_| object::elf::DT_RELA.0 as u64,
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
    DynamicEntryWriter::optional(object::elf::DT_RELAENT, has_rela_dyn, |inputs| {
        inputs.rela_entry_size
    }),
    // Note, rela-count is just the count of the relative relocations and doesn't include any
    // glob-dat relocations. This is as opposed to rela-size, which includes both.
    DynamicEntryWriter::new(object::elf::DT_RELACOUNT, |inputs| {
        inputs
            .section_part_layouts
            .get(part_id::RELA_DYN_RELATIVE)
            .mem_size
            / inputs.rela_entry_size
    }),
    DynamicEntryWriter::optional(
        object::elf::DT_RELR,
        |inputs| {
            inputs.has_data_in_section(output_section_id::RELR_DYN)
                && !has_android_relr_tags(inputs)
        },
        |inputs| inputs.vma_of_section(output_section_id::RELR_DYN),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_RELRSZ,
        |inputs| {
            inputs.has_data_in_section(output_section_id::RELR_DYN)
                && !has_android_relr_tags(inputs)
        },
        |inputs| inputs.size_of_section(output_section_id::RELR_DYN),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_RELRENT,
        |inputs| {
            inputs.has_data_in_section(output_section_id::RELR_DYN)
                && !has_android_relr_tags(inputs)
        },
        |inputs| inputs.relr_entry_size,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_ANDROID_RELR,
        |inputs| {
            inputs.has_data_in_section(output_section_id::RELR_DYN) && has_android_relr_tags(inputs)
        },
        |inputs| inputs.vma_of_section(output_section_id::RELR_DYN),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_ANDROID_RELRSZ,
        |inputs| {
            inputs.has_data_in_section(output_section_id::RELR_DYN) && has_android_relr_tags(inputs)
        },
        |inputs| inputs.size_of_section(output_section_id::RELR_DYN),
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_ANDROID_RELRENT,
        |inputs| {
            inputs.has_data_in_section(output_section_id::RELR_DYN) && has_android_relr_tags(inputs)
        },
        |inputs| inputs.relr_entry_size,
    ),
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
        |inputs| inputs.args.enable_new_dtags && inputs.dt_flags().0 != 0,
        |inputs| inputs.dt_flags().0,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_FLAGS_1,
        |inputs| inputs.dt_flags_1().0 != 0,
        |inputs| inputs.dt_flags_1().0,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_BIND_NOW,
        |inputs| {
            !inputs.args.enable_new_dtags && inputs.dt_flags().contains(object::elf::DF_BIND_NOW)
        },
        |_inputs| 0,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_SYMBOLIC,
        |inputs| {
            !inputs.args.enable_new_dtags && inputs.dt_flags().contains(object::elf::DF_SYMBOLIC)
        },
        |_inputs| 0,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_TEXTREL,
        |inputs| {
            !inputs.args.enable_new_dtags && inputs.dt_flags().contains(object::elf::DF_TEXTREL)
        },
        |_inputs| 0,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_AARCH64_VARIANT_PCS,
        |inputs| {
            inputs.has_variant_pcs
                && inputs.args.architecture() == crate::arch::Architecture::AArch64
        },
        |_inputs| 0,
    ),
    DynamicEntryWriter::optional(
        object::elf::DT_RISCV_VARIANT_CC,
        |inputs| {
            inputs.has_variant_pcs
                && inputs.args.architecture() == crate::arch::Architecture::RiscV64
        },
        |_inputs| 0,
    ),
    DynamicEntryWriter::new(object::elf::DT_NULL, |_inputs| 0),
];

struct DynamicEntryWriter {
    tag: object::elf::DynamicTag,
    is_present_cb: fn(&DynamicEntryInputs) -> bool,
    cb: fn(&DynamicEntryInputs) -> u64,
}

struct DynamicEntryInputs<'layout> {
    args: &'layout ElfArgs,
    has_static_tls: bool,
    has_variant_pcs: bool,
    section_layouts: &'layout OutputSectionMap<OutputRecordLayout>,
    section_part_layouts: &'layout OutputSectionPartMap<OutputRecordLayout>,
    non_addressable_counts: NonAddressableCounts,
    output_kind: OutputKind,
    rela_entry_size: u64,
    relr_entry_size: u64,
    symtab_entry_size: u64,
}

impl DynamicEntryInputs<'_> {
    fn dt_flags(&self) -> object::elf::DynamicFlags {
        let mut flags = object::elf::DynamicFlags(0);
        flags |= object::elf::DF_BIND_NOW;

        if !self.output_kind.is_executable() && self.has_static_tls {
            flags |= object::elf::DF_STATIC_TLS;
        }

        if self.args.needs_origin_handling {
            flags |= object::elf::DF_ORIGIN;
        }

        flags
    }

    fn dt_flags_1(&self) -> object::elf::DynamicFlags1 {
        let mut flags = object::elf::DynamicFlags1(0);
        flags |= object::elf::DF_1_NOW;

        if self.output_kind.is_executable() && self.output_kind.is_position_independent() {
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

        flags
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
    const fn new(
        tag: object::elf::DynamicTag,
        cb: fn(&DynamicEntryInputs) -> u64,
    ) -> DynamicEntryWriter {
        DynamicEntryWriter {
            tag,
            is_present_cb: |_| true,
            cb,
        }
    }

    const fn optional(
        tag: object::elf::DynamicTag,
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

    fn write<C: ElfClass>(
        &self,
        out: &mut DynamicEntriesWriter<'_, C>,
        inputs: &DynamicEntryInputs,
    ) -> Result {
        if !self.is_present(inputs) {
            return Ok(());
        }
        let value = (self.cb)(inputs);
        out.write(self.tag, value)
    }
}

struct DynamicEntriesWriter<'out, C: ElfClass> {
    out: &'out mut [DynamicEntry<C>],
}

impl<'out, C: ElfClass> DynamicEntriesWriter<'out, C> {
    fn new(buffer: &'out mut [u8]) -> DynamicEntriesWriter<'out, C> {
        DynamicEntriesWriter {
            out: slice_from_all_bytes_mut(buffer),
        }
    }

    fn write(&mut self, tag: object::elf::DynamicTag, value: u64) -> Result {
        let entry = self
            .out
            .split_off_first_mut()
            .ok_or_else(|| insufficient_allocation(".dynamic"))?;
        entry.set_tag(tag)?;
        entry.set_value(value)?;
        Ok(())
    }

    /// Some dynamic entries aren't used, but we currently allocate space for them anyway. This
    /// makes sure that they're written with zeros.
    fn write_unused(&mut self) -> Result {
        loop {
            let Some(entry) = self.out.split_off_first_mut() else {
                return Ok(());
            };
            entry.set_tag(object::elf::DT_NULL)?;
            entry.set_value(0)?;
        }
    }
}

fn write_section_headers<C: ElfClass>(
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<C>,
) -> Result {
    let output_sections = &layout.output_sections;
    let num_entries = table_writer.section_header_count();
    let mut name_offset = 0;
    let info_values = compute_info_values(layout);

    let mut order = layout.output_order.into_iter().peekable();

    while let Some(event) = order.next() {
        let OrderEvent::Section(section_id) = event else {
            continue;
        };

        let output_info = output_sections.output_info(section_id);
        let section_type = output_info.section_attributes.ty;
        let section_layout = layout.merged_section_layouts.get(section_id);

        if output_sections
            .output_index_of_section(section_id)
            .is_none()
        {
            continue;
        }

        let entsize = output_info.section_attributes.entsize.max(
            section_id
                .opt_built_in_details::<elf::Elf<C>>()
                .map_or(0, |details| details.element_size),
        );

        let size;
        let alignment;
        let mut link = link_ids::<C>(section_id)
            .iter()
            .find_map(|link_id| output_sections.output_index_of_section(*link_id))
            .unwrap_or(0);

        if section_type == sht::NULL {
            alignment = 0;
            if num_entries >= usize::from(object::elf::SHN_LORESERVE) {
                size = num_entries as u64;
            } else {
                size = 0;
            }

            let shstrndx = layout
                .output_sections
                .output_index_of_section(output_section_id::SHSTRTAB)
                .unwrap();
            if shstrndx >= u32::from(object::elf::SHN_LORESERVE) {
                link = shstrndx;
            } else {
                link = 0;
            }
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
        }

        let name = layout.output_sections.name(section_id).with_context(|| {
            format!(
                "Missing name for section {}",
                layout.output_sections.section_debug(section_id)
            )
        })?;
        table_writer.write_section_header_string(name.bytes())?;

        let entry = table_writer.take_section_header()?;
        entry.set_name(name_offset);

        let sh_type = if layout.args().use_android_relr_tags && section_type == sht::RELR {
            object::elf::SHT_ANDROID_RELR
        } else {
            section_type
        };
        entry.set_type(sh_type);

        let mut flags = output_sections.section_flags(section_id);

        if layout.compressed_debug_sections.get(section_id).is_some() {
            flags = flags.with(shf::COMPRESSED);
        } else {
            flags = flags.without(shf::COMPRESSED);
        }

        entry.set_flags(flags)?;

        let mut info_value = *info_values.get(section_id);

        if layout.args().should_output_partial_object()
            && section_type == sht::RELA
            && section_id.is_custom::<elf::Elf<C>>()
        {
            if let Some(symtab_idx) =
                output_sections.output_index_of_section(output_section_id::SYMTAB_LOCAL)
            {
                link = symtab_idx;
            }
            if let Some(target_name) = name.bytes().strip_prefix(b".rela")
                && let Some(target_id) = output_sections
                    .custom_identity_to_id(SectionIdentity::new(SectionName(target_name), ()))
                && let Some(target_idx) = output_sections.output_index_of_section(target_id)
            {
                info_value = target_idx;
            }
        }

        entry.set_address(if layout.symbol_db.args.should_output_partial_object() {
            0
        } else {
            section_layout.mem_offset
        })?;
        entry.set_offset(section_layout.file_offset as u64)?;
        entry.set_size(size)?;
        entry.set_link(link);
        entry.set_info(info_value);
        entry.set_alignment(alignment)?;
        entry.set_entry_size(entsize)?;

        name_offset += name.len() as u32 + 1;
    }
    Ok(())
}

/// Computes the value of the info field for all the section headers.
fn compute_info_values<C: ElfClass>(layout: &ElfLayout<C>) -> OutputSectionMap<u32> {
    let mut infos = layout.output_sections.new_section_map();

    // .rela.plt contains relocations for .got, so should link to it.
    *infos.get_mut(output_section_id::RELA_PLT) = layout
        .output_sections
        .output_index_of_section(output_section_id::GOT)
        .unwrap_or(0);

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
        / C::SYMTAB_ENTRY_SIZE as usize)
        as u32;

    infos
}

struct ProgramHeaderWriter<'out, C: ElfClass> {
    headers: &'out mut [elf::ProgramHeader<C>],
}

impl<'out, C: ElfClass> ProgramHeaderWriter<'out, C> {
    fn new(bytes: &'out mut [u8]) -> Self {
        Self {
            headers: slice_from_all_bytes_mut(bytes),
        }
    }

    fn take_header(&mut self) -> Result<&mut elf::ProgramHeader<C>> {
        self.headers
            .split_off_first_mut()
            .ok_or_else(|| error!("Insufficient header slots"))
    }
}

fn write_internal_symbols_plt_got_entries<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    internal_symbols: &InternalSymbols<elf::Elf<C>>,
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<'data, C>,
) -> Result {
    for i in 0..internal_symbols.symbol_definitions.len() {
        let symbol_id = internal_symbols.start_symbol_id.add_usize(i);
        if !layout.symbol_db.is_canonical(symbol_id) {
            continue;
        }
        if let Some(res) = layout.local_symbol_resolution(symbol_id) {
            table_writer
                .process_resolution::<A>(Some(layout), layout.args(), res)
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

fn write_dynamic_file<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    object: &DynamicLayout<'data, elf::Elf<C>>,
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<'data, C>,
) -> Result {
    verbose_timing_phase!("Write dynamic");

    write_so_name(object, table_writer)?;

    write_copy_relocations::<C, A>(object, table_writer, layout)?;

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
            } else if !res.flags.needs_canonical_plt() {
                let entry = table_writer.dynsym_writer.undefined_symbol(false, name)?;

                let symbol_type = if symbol.st_type() == object::elf::STT_GNU_IFUNC {
                    // An undefined reference to an IFUNC needs to be emitted as type FUNC.
                    object::elf::STT_FUNC
                } else {
                    symbol.st_type()
                };

                // Note, for undefined symbols, we always use default visibility.
                entry.set_binding_and_type(symbol.st_bind(), symbol_type);

                if let Some(versym) = table_writer.version_writer.versym.as_mut() {
                    copy_symbol_version(
                        object.object.symbol_versions(),
                        object.symbol_id_range.id_to_offset(symbol_id),
                        &object.format_specific.version_mapping,
                        versym,
                    )?;
                }
            }

            table_writer
                .process_resolution::<A>(Some(layout), layout.args(), res)
                .with_context(|| format!("Failed to write {}", layout.symbol_debug(symbol_id)))?;
        }
    }

    if let Some(verneed_info) = &object.format_specific.verneed_info {
        let mut verdefs = verneed_info.defs.clone();
        let e = LittleEndian;

        let strings = object.object.sections.strings(
            e,
            object.object.data,
            verneed_info.string_table_index,
        )?;

        let ver_need = table_writer.version_writer.take_verneed()?;

        let next_verneed_offset = if object.format_specific.is_last_verneed {
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
            let is_base = flags.contains(object::elf::VER_FLG_BASE);

            if is_base {
                let name_offset = table_writer
                    .dynsym_writer
                    .strtab_writer
                    .write_str(object.lib_name);

                ver_need.vn_file.set(e, name_offset);
                continue;
            }

            if input_version.is_local() {
                bail!("Invalid version index");
            }

            let output_version = object
                .format_specific
                .version_mapping
                .get(usize::from(input_version - object::elf::VER_NDX_GLOBAL))
                .copied()
                .unwrap_or_default();

            if !output_version.is_global() {
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
                aux_out.vna_flags.set(e, object::elf::VersionFlags(0));
                aux_index += 1;
            }
        }
        debug_assert_eq!(aux_index, auxes.len());
    }

    Ok(())
}

/// Write dynamic entry to indicate name of shared object to load.
fn write_so_name<'data, C: ElfClass>(
    object: &DynamicLayout<'data, elf::Elf<C>>,
    table_writer: &mut TableWriter<'_, '_, C>,
) -> Result {
    let needed_offset = table_writer
        .dynsym_writer
        .strtab_writer
        .write_str(object.lib_name);
    table_writer
        .dynamic
        .write(object::elf::DT_NEEDED, needed_offset.into())?;
    Ok(())
}

fn write_copy_relocations<'data, C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    object: &DynamicLayout<'data, elf::Elf<C>>,
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<C>,
) -> Result {
    for &symbol_id in &object.format_specific.copy_relocation_symbols {
        write_copy_relocation_for_symbol::<C, A>(symbol_id, table_writer, layout).with_context(
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

fn write_copy_relocation_for_symbol<C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    symbol_id: SymbolId,
    table_writer: &mut TableWriter<'_, '_, C>,
    layout: &ElfLayout<C>,
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

fn copy_symbol_version(
    versym_in: &[Versym],
    local_symbol_index: usize,
    version_mapping: &[object::elf::VersionIndex],
    versym_out: &mut &mut [Versym],
) -> Result {
    let output_version =
        versym_in
            .get(local_symbol_index)
            .map_or(object::elf::VER_NDX_GLOBAL, |versym| {
                let input_version = versym.0.get(LittleEndian).index();
                if input_version.is_special() {
                    input_version
                } else {
                    version_mapping[usize::from(input_version - object::elf::VER_NDX_GLOBAL)]
                }
            });

    write_symbol_version(versym_out, output_version.into())
}

fn write_symbol_version(
    versym_out: &mut &mut [Versym],
    version: object::elf::VersymIndex,
) -> Result {
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

fn has_android_relr_tags(inputs: &DynamicEntryInputs) -> bool {
    inputs.args.use_android_relr_tags
}

pub(crate) fn verify_resolution_allocation<C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    output_sections: &OutputSections<elf::Elf<C>>,
    output_order: &OutputOrder,
    output_kind: OutputKind,
    mem_sizes: &OutputSectionPartMap<u64>,
    resolution: &Resolution<elf::Elf<C>>,
    args: &ElfArgs,
) -> Result {
    // Allocate however much space was requested.

    let mut total_bytes_allocated = 0;
    mem_sizes.output_order_map(
        output_order,
        output_sections,
        |_part_id, alignment, &size| {
            total_bytes_allocated = alignment.align_up(total_bytes_allocated) + size;
        },
    );
    total_bytes_allocated = crate::alignment::USIZE.align_up(total_bytes_allocated);
    let mut all_mem = vec![0_u64; total_bytes_allocated as usize / size_of::<u64>()];
    let mut all_mem: &mut [u8] = transmute_mut!(all_mem.as_mut_slice());
    let mut offset = 0;
    let mut buffers = mem_sizes.output_order_map(
        output_order,
        output_sections,
        |_part_id, alignment, &size| {
            let aligned_offset = alignment.align_up(offset);
            all_mem
                .split_off_mut(..(aligned_offset - offset) as usize)
                .unwrap();
            offset = aligned_offset + size;
            all_mem.split_off_mut(..size as usize).unwrap()
        },
    );

    let dynsym_writer = SymbolTableWriter::<C>::new_dynamic(0, &mut buffers, output_sections);
    let debug_symbol_writer = SymbolTableWriter::<C>::new(0, &mut buffers, output_sections);
    let mut table_writer = TableWriter::<C>::new(
        output_kind,
        0..100,
        &mut buffers,
        dynsym_writer,
        debug_symbol_writer,
        0,
        args.is_relr_enabled(),
    );
    table_writer.process_resolution::<A>(None, args, resolution)?;
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

/// Returns whether to reverse the contents of a section. This is true for .ctors/.dtors sections.
fn should_reverse_contents<C: ElfClass>(
    section_index: object::SectionIndex,
    part_id: PartId,
    file: &elf::File<'_, C>,
    output_sections: &OutputSections<elf::Elf<C>>,
) -> bool {
    // Getting the section name is expensive, so we only do it when the output section is
    // .init_array / .fini_array.
    let section_id =
        output_sections.primary_output_section(part_id.output_section_id::<elf::Elf<C>>());
    if section_id != output_section_id::INIT_ARRAY && section_id != output_section_id::FINI_ARRAY {
        return false;
    }

    file.section_name(section_index).is_ok_and(|section_name| {
        // .ctors and .dtors sections need their contents reversed when merged into
        // .init_array/.fini_array
        section_name.starts_with(secnames::CTORS_SECTION_NAME)
            || section_name.starts_with(secnames::DTORS_SECTION_NAME)
    })
}

fn link_ids<C: ElfClass>(section_id: OutputSectionId) -> &'static [OutputSectionId] {
    elf::Elf::<C>::built_in_section_details()
        .get(section_id.as_usize())
        .map(|def| def.link)
        .unwrap_or_default()
}

fn fill_section_padding<C: ElfClass, A: Arch<Platform = elf::Elf<C>>>(
    padding: &mut [u8],
    section_info: &SectionOutputInfo<elf::Elf<C>>,
) {
    if let Some(pattern) = section_info.fill {
        let chunks = padding.chunks_mut(4);
        for chunk in chunks {
            let len = chunk.len();
            chunk.copy_from_slice(&pattern[..len]);
        }
    } else {
        A::fill_section_padding(padding, section_info.section_attributes.flags);
    }
}
