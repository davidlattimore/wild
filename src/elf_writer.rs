use crate::elf;
use crate::elf::DynamicEntry;
use crate::elf::DynamicTag;
use crate::elf::FileHeader;
use crate::elf::ProgramHeader;
use crate::elf::SectionHeader;
use crate::elf::SegmentType;
use crate::elf::SymtabEntry;
use crate::elf::PLT_ENTRY_TEMPLATE;
use crate::error::Result;
use crate::input_data::INTERNAL_FILE_ID;
use crate::layout::FileLayout;
use crate::layout::InternalLayout;
use crate::layout::Layout;
use crate::layout::ObjectLayout;
use crate::layout::PltGotFlags;
use crate::layout::Resolution;
use crate::layout::Section;
use crate::layout::SymbolResolution;
use crate::layout::TargetResolutionKind;
use crate::layout::TlsMode;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::program_segments::ProgramSegmentId;
use crate::program_segments::NUM_SEGMENTS;
use crate::resolution::LocalSymbolResolution;
use crate::resolution::SectionSlot;
use crate::slice::slice_take_prefix_mut;
use crate::symbol_db::GlobalSymbolId;
use crate::symbol_db::SymbolDb;
use crate::timing::Timing;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use memmap2::MmapOptions;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use rayon::prelude::*;
use std::fmt::Display;
use std::ops::Range;
use std::path::Path;

pub(crate) struct Output {
    file: std::fs::File,
    mmap: memmap2::MmapMut,
}

#[derive(Debug)]
struct SectionAllocation {
    id: OutputSectionId,
    offset: usize,
    size: usize,
}

pub(crate) struct ElfWriter<'out> {
    section_data: OutputSectionMap<&'out mut [u8]>,
}

impl Output {
    pub(crate) fn create(path: &Path, layout: &Layout, timing: &mut Timing) -> Result<Output> {
        let _ = std::fs::remove_file(path)
            .with_context(|| format!("Failed to delete `{}`", path.display()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .with_context(|| format!("Failed to open `{}`", path.display()))?;
        let mut file_size = 0;
        layout
            .section_layouts
            .for_each(|_, s| file_size = file_size.max(s.file_offset + s.file_size));
        file.set_len(file_size as u64)?;
        let mmap = unsafe { MmapOptions::new().map_mut(&file) }
            .with_context(|| format!("Failed to mmap output file `{}`", path.display()))?;
        timing.complete("Create output file");
        Ok(Output { file, mmap })
    }

    pub(crate) fn make_executable(&mut self) -> Result {
        crate::fs::make_executable(&self.file)
    }
}

impl<'out> ElfWriter<'out> {
    pub(crate) fn open(output: &'out mut Output, layout: &Layout) -> ElfWriter<'out> {
        let mut section_allocations = Vec::with_capacity(layout.section_layouts.len());
        layout.section_layouts.for_each(|id, s| {
            section_allocations.push(SectionAllocation {
                id,
                offset: s.file_offset,
                size: s.file_size,
            })
        });
        section_allocations.sort_by_key(|s| (s.offset, s.offset + s.size));

        let mut data = output.mmap.as_mut();
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
        ElfWriter { section_data }
    }

    pub(crate) fn write(&mut self, layout: &Layout, timing: &mut Timing) -> Result {
        let section_buffers = &mut self.section_data;
        let mut writable_buckets = split_buffers_by_alignment(section_buffers, layout);
        let files_and_buffers: Vec<_> = layout
            .file_layouts
            .iter()
            .map(|file| {
                if let Some(file_sizes) = file.file_sizes(&layout.output_sections) {
                    (file, writable_buckets.take_mut(&file_sizes))
                } else {
                    (
                        file,
                        OutputSectionPartMap::with_size(layout.output_sections.len()),
                    )
                }
            })
            .collect();
        files_and_buffers
            .into_par_iter()
            .map(|(file, buffer)| {
                file.write(buffer, layout)
                    .with_context(|| format!("Failed copying from {file} to output file"))
            })
            .collect::<Result>()?;
        timing.complete("Writing ELF file");
        Ok(())
    }
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
    for (segment_id, segment_layout) in layout.segment_layouts.iter().enumerate() {
        let segment_sizes = &segment_layout.sizes;
        let segment_id = ProgramSegmentId::new(segment_id);
        let segment_header = program_headers_out.take_header()?;
        let mut alignment = segment_sizes.alignment;
        if segment_id.segment_type() == SegmentType::Load {
            alignment = alignment.max(crate::alignment::PAGE);
        }
        *segment_header = ProgramHeader {
            segment_type: segment_id.segment_type() as u32,
            flags: segment_id.segment_flags(),
            offset: segment_sizes.file_offset as u64,
            virtual_addr: segment_sizes.mem_offset,
            physical_addr: segment_sizes.mem_offset,
            file_size: segment_sizes.file_size as u64,
            mem_size: segment_sizes.mem_size,
            alignment: alignment.value(),
        };
    }
    Ok(())
}

impl FileHeader {
    fn build(layout: &Layout) -> Result<Self> {
        Ok(Self {
            magic: [0x7f, b'E', b'L', b'F'],
            class: 2, // 64 bit
            data: 1,  // Little endian
            ei_version: 1,
            os_abi: 3, // Linux
            abi_version: 0,
            padding: [0; 7],
            ty: 2,         // Executable
            machine: 0x3e, // x86-64
            e_version: 1,
            entry_point: layout.entry_symbol_address()?,

            program_header_offset: elf::PHEADER_OFFSET,
            section_header_offset: 0,
            flags: 0,
            ehsize: elf::FILE_HEADER_SIZE,
            program_header_entry_size: elf::PROGRAM_HEADER_SIZE,
            program_header_num: NUM_SEGMENTS.try_into().unwrap(),
            section_header_entry_size: elf::SECTION_HEADER_SIZE,
            section_header_num: layout.output_sections.len() as u16,
            section_names_index: layout
                .output_sections
                .index_of_built_in(crate::output_section_id::SHSTRTAB),
        })
    }
}

impl<'data> FileLayout<'data> {
    fn write(&self, buffers: OutputSectionPartMap<&mut [u8]>, layout: &Layout) -> Result {
        match self {
            Self::Internal(s) => s.write(buffers, layout)?,
            Self::Object(s) => s.write(buffers, layout)?,
            Self::Dynamic(_) => {}
        }
        Ok(())
    }
}

struct PltGotWriter<'data, 'out> {
    layout: &'data Layout<'data>,
    got: &'out mut [u8],
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
            got: core::mem::take(&mut buffers.got),
            plt: core::mem::take(&mut buffers.plt),
            rela_plt: bytemuck::cast_slice_mut(core::mem::take(&mut buffers.rela_plt)),
            tls: layout.tls_start_address()..layout.tls_end_address(),
        }
    }

    fn process_symbol(&mut self, symbol_id: GlobalSymbolId) -> Result {
        match self.layout.global_symbol_resolution(symbol_id) {
            Some(SymbolResolution::Resolved(res)) => {
                self.process_resolution(res)?;
            }
            Some(SymbolResolution::Dynamic) => {}
            None => {}
        }
        Ok(())
    }

    fn process_resolution(&mut self, res: &Resolution) -> Result {
        if let Some(got_address) = res.got_address {
            if self.got.is_empty() {
                bail!("Didn't allocate enough space in GOT");
            }

            if matches!(res.kind, TargetResolutionKind::TlsGot) {
                let mod_got_entry =
                    slice_take_prefix_mut(&mut self.got, elf::GOT_ENTRY_SIZE as usize);
                mod_got_entry.copy_from_slice(&elf::CURRENT_EXE_TLS_MOD.to_le_bytes());
            }
            let got_entry = slice_take_prefix_mut(&mut self.got, elf::GOT_ENTRY_SIZE as usize);
            let mut address = res.address;
            // If our address is in the TLS segment, then the address needs to be converted to an
            // offset relative to the TCB which is the end of the TLS segment.
            if self.tls.contains(&address) {
                address = address.wrapping_sub(self.tls.end);
            }

            got_entry.copy_from_slice(&address.to_le_bytes());
            if let Some(plt_address) = res.plt_address {
                if self.plt.is_empty() {
                    bail!("Didn't allocate enough space in PLT");
                }
                let plt_entry = slice_take_prefix_mut(&mut self.plt, elf::PLT_ENTRY_SIZE as usize);
                plt_entry.copy_from_slice(PLT_ENTRY_TEMPLATE);
                let offset: i32 = ((got_address.get().wrapping_sub(plt_address.get() + 0xb))
                    as i64)
                    .try_into()
                    .map_err(|_| anyhow!("PLT is more than 2GB away from GOT"))?;
                plt_entry[7..11].copy_from_slice(&offset.to_le_bytes());
            }
        }
        Ok(())
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

    fn apply_relocation(&mut self, rel: &crate::layout::PltRelocation) -> Result {
        let out = slice_take_prefix_mut(&mut self.rela_plt, 1);
        let out = &mut out[0];
        out.addend = rel.resolver;
        out.address = rel.got_address;
        out.info = elf::RelocationType::IRelative as u32 as u64;
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
        let local_entries = bytemuck::cast_slice_mut(slice_take_prefix_mut(
            &mut buffers.symtab_locals,
            sizes.symtab_locals as usize,
        ));
        let global_entries = bytemuck::cast_slice_mut(slice_take_prefix_mut(
            &mut buffers.symtab_globals,
            sizes.symtab_globals as usize,
        ));
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

    fn copy_symbol(
        &mut self,
        sym: &crate::elf::Symbol,
        section: &Section,
        section_address: u64,
    ) -> Result {
        let is_local = sym.is_local();
        let object::SymbolFlags::Elf { st_info, st_other } = sym.flags() else {
            unreachable!()
        };
        let shndx = self
            .output_sections
            .output_info(section.output_section_id.unwrap())
            .output_index;
        let value = section_address + sym.address();
        let size = sym.size();
        let name = sym.name_bytes()?;
        let entry = self.define_symbol(is_local, shndx, value, size, name)?;
        entry.info = st_info;
        entry.other = st_other;
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
            slice_take_prefix_mut(&mut self.local_entries, 1)
        } else {
            slice_take_prefix_mut(&mut self.global_entries, 1)
        };
        entry[0] = SymtabEntry {
            name: self.string_offset,
            info: 0,
            other: 0,
            shndx,
            value,
            size,
        };
        let len = name.len();
        let str_out = slice_take_prefix_mut(&mut self.strings, len + 1);
        str_out[..len].copy_from_slice(name);
        str_out[len] = 0;
        self.string_offset += len as u32 + 1;
        Ok(&mut entry[0])
    }
}

impl<'data> ObjectLayout<'data> {
    fn write(&self, mut buffers: OutputSectionPartMap<&mut [u8]>, layout: &Layout) -> Result {
        let start_str_offset = self.strings_offset_start;
        let mut plt_got_writer = PltGotWriter::new(layout, &mut buffers);
        for sec in &self.sections {
            let SectionSlot::Loaded(sec) = sec else {
                continue;
            };
            if layout
                .output_sections
                .has_data_in_file(sec.output_section_id.unwrap())
            {
                let section_buffer =
                    buffers.regular_mut(sec.output_section_id.unwrap(), sec.alignment);
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
                self.apply_relocations(out, sec, layout).with_context(|| {
                    format!(
                        "Failed to apply relocations in section {} of {}",
                        self.display_section_name(sec.index),
                        self.input
                    )
                })?;
            }
            if !matches!(sec.resolution_kind, PltGotFlags::Neither) {
                let res = self.section_resolutions[sec.index.0]
                    .as_ref()
                    .ok_or_else(|| anyhow!("Section requires GOT, but hasn't been resolved"))?;
                plt_got_writer.process_resolution(res)?;
            }
        }
        for rel in &self.plt_relocations {
            plt_got_writer.apply_relocation(rel)?;
        }
        for symbol_id in &self.loaded_symbols {
            plt_got_writer.process_symbol(*symbol_id)?;
        }
        if !layout.symbol_db.args.strip_all {
            self.write_symbols(start_str_offset, buffers, &layout.output_sections, layout)?;
        }
        plt_got_writer.validate_empty()?;
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
        for sym in self.object.symbols() {
            match object::ObjectSymbol::section(&sym) {
                object::SymbolSection::Section(section_index) => {
                    if let SectionSlot::Loaded(section) = &self.sections[section_index.0] {
                        symbol_writer.copy_symbol(
                            &sym,
                            section,
                            self.section_resolutions[section_index.0]
                                .as_ref()
                                .unwrap()
                                .address,
                        )?;
                    }
                }
                object::SymbolSection::Common => {
                    if let Some(symbol_id) = self.global_id_for_symbol(&sym) {
                        let symbol = layout.symbol_db.symbol(symbol_id);
                        if symbol.file_id == self.file_id {
                            if let Some(SymbolResolution::Resolved(res)) =
                                layout.global_symbol_resolution(symbol_id)
                            {
                                let shndx = layout
                                    .output_sections
                                    .index_of_built_in(output_section_id::BSS);
                                symbol_writer.define_symbol(
                                    sym.is_local(),
                                    shndx,
                                    res.address,
                                    sym.size(),
                                    sym.name_bytes()?,
                                )?;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_relocations(&self, out: &mut [u8], section: &Section, layout: &Layout) -> Result {
        let section_address = self.section_resolutions[section.index.0]
            .as_ref()
            .unwrap()
            .address;
        let elf_section = &self.object.section_by_index(section.index)?;
        let mut modifier = RelocationModifier::Normal;
        for (offset_in_section, rel) in elf_section.relocations() {
            if modifier == RelocationModifier::SkipNextRelocation {
                modifier = RelocationModifier::Normal;
                continue;
            }
            if let Some(resolution) = self.get_resolution(&rel, layout)? {
                modifier = apply_relocation(
                    &resolution,
                    offset_in_section,
                    &rel,
                    section_address,
                    layout,
                    out,
                )
                .with_context(|| {
                    format!("Failed to apply {}", self.display_relocation(&rel, layout))
                })?;
            }
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
        let resolution = match rel.target() {
            object::RelocationTarget::Symbol(local_symbol_id) => {
                match self.local_symbol_resolutions[local_symbol_id.0] {
                    LocalSymbolResolution::Global(symbol_id) => {
                        match layout.global_symbol_resolution(symbol_id) {
                            Some(SymbolResolution::Resolved(resolution)) => *resolution,
                            Some(SymbolResolution::Dynamic) => todo!(),
                            None => {
                                bail!(
                                    "Missing resolution for non-weak symbol {}",
                                    layout.symbol_db.symbol_name(symbol_id)
                                )
                            }
                        }
                    }
                    LocalSymbolResolution::WeakRefToGlobal(symbol_id) => {
                        match layout.global_symbol_resolution(symbol_id) {
                            Some(SymbolResolution::Resolved(resolution)) => *resolution,
                            Some(SymbolResolution::Dynamic) => todo!(),
                            None => layout.internal().undefined_symbol_resolution,
                        }
                    }
                    LocalSymbolResolution::LocalSection(local_index) => {
                        let mut r = self.section_resolutions[local_index.0].unwrap();
                        let local_sym = self.object.symbol_by_index(local_symbol_id)?;
                        r.address += local_sym.address();
                        r
                    }
                    LocalSymbolResolution::UnresolvedWeak => {
                        layout.internal().undefined_symbol_resolution
                    }
                    LocalSymbolResolution::TlsGetAddr => return Ok(None),
                    LocalSymbolResolution::UndefinedSymbol => {
                        let name = self.object.symbol_by_index(local_symbol_id)?.name_bytes()?;
                        bail!(
                            "Reference to undefined symbol `{}`",
                            String::from_utf8_lossy(name),
                        );
                    }
                    LocalSymbolResolution::Null => bail!("Reference to null symbol"),
                }
            }
            object::RelocationTarget::Section(local_index) => {
                self.section_resolutions[local_index.0].unwrap()
            }
            other => bail!("Unsupported relocation {other:?}"),
        };
        Ok(Some(resolution))
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
            object::RelocationTarget::Symbol(local_symbol_id) => {
                match &self.object.local_symbol_resolutions[local_symbol_id.0] {
                    LocalSymbolResolution::Global(symbol_id) => {
                        write!(f, "global `{}`", self.symbol_db.symbol_name(*symbol_id))?;
                    }
                    LocalSymbolResolution::UnresolvedWeak => write!(f, "unresolved weak")?,
                    LocalSymbolResolution::TlsGetAddr => write!(f, "TlsGetAddr")?,
                    LocalSymbolResolution::WeakRefToGlobal(symbol_id) => {
                        write!(
                            f,
                            "weak ref to global `{}`",
                            self.symbol_db.symbol_name(*symbol_id)
                        )?;
                    }
                    LocalSymbolResolution::LocalSection(section_index) => {
                        write!(
                            f,
                            "section `{}`",
                            self.object
                                .object
                                .section_by_index(*section_index)
                                .and_then(|sec| sec.name())
                                .unwrap_or("??")
                        )?;
                    }
                    LocalSymbolResolution::UndefinedSymbol => writeln!(f, "undefined section")?,
                    LocalSymbolResolution::Null => writeln!(f, "null symbol")?,
                }
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelocationModifier {
    Normal,
    SkipNextRelocation,
}

/// Applies the relocation `rel` at `offset_in_section`, where the section bytes are `out`. See "ELF
/// Handling For Thread-Local Storage" for details about some of the TLS-related relocations and
/// transformations that are applied.
fn apply_relocation(
    resolution: &Resolution,
    offset_in_section: u64,
    rel: &object::Relocation,
    section_address: u64,
    layout: &Layout,
    out: &mut [u8],
) -> Result<RelocationModifier> {
    let address = resolution.address;
    let mut offset = offset_in_section as usize;
    let place = section_address + offset_in_section;
    let addend = rel.addend() as u64;
    let mut byte_size: usize = usize::from(rel.size()) / 8;
    let mut next_modifier = RelocationModifier::Normal;
    let value = match (rel.kind(), rel.flags()) {
        (object::RelocationKind::Absolute, _) => address.wrapping_add(addend),
        (object::RelocationKind::Relative, _) => address.wrapping_add(addend).wrapping_sub(place),
        (object::RelocationKind::GotRelative, _) => resolution
            .got_address()?
            .wrapping_add(addend)
            .wrapping_sub(place),
        (object::RelocationKind::PltRelative, _) => resolution
            .plt_address()?
            .wrapping_add(addend)
            .wrapping_sub(place),
        (object::RelocationKind::Unknown, object::RelocationFlags::Elf { r_type: 19 }) => {
            // R_X86_64_TLSGD
            byte_size = 4;
            match layout.tls_mode {
                TlsMode::LocalExec => {
                    // Transform GD (general dynamic) into LE (local exec). We can make this
                    // transformation because we're producing a statically linked executable.
                    expect_bytes_before_offset(out, offset, &[0x66, 0x48, 0x8d, 0x3d])?;
                    // Transforms to:
                    // mov %fs:0x0,%rax // the same as a TLSLD relocation
                    // lea {var offset}(%rax),%rax
                    out[offset - 4..offset + 8].copy_from_slice(&[
                        0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x8d, 0x80,
                    ]);
                    offset += 8;
                    next_modifier = RelocationModifier::SkipNextRelocation;
                    address.wrapping_sub(layout.tls_end_address())
                }
                TlsMode::Preserve => resolution
                    .got_address()?
                    .wrapping_add(addend)
                    .wrapping_sub(place),
            }
        }
        (object::RelocationKind::Unknown, object::RelocationFlags::Elf { r_type: 20 }) => {
            // R_X86_64_TLSLD
            byte_size = 4;
            match layout.tls_mode {
                TlsMode::LocalExec => {
                    // Transform LD (local dynamic) into LE (local exec). We can make this
                    // transformation because we're producing a statically linked executable.
                    expect_bytes_before_offset(out, offset, &[0x48, 0x8d, 0x3d])?;
                    // Transforms to: mov %fs:0x0,%rax
                    out[offset - 3..offset + 5]
                        .copy_from_slice(&[0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25]);
                    offset += 5;
                    next_modifier = RelocationModifier::SkipNextRelocation;
                    0
                }
                TlsMode::Preserve => layout
                    .internal()
                    .tlsld_got_entry
                    .unwrap()
                    .get()
                    .wrapping_add(addend)
                    .wrapping_sub(place),
            }
        }
        (object::RelocationKind::Unknown, object::RelocationFlags::Elf { r_type: 21 }) => {
            // R_X86_64_DTPOFF32
            if layout.config().link_static {
                byte_size = 4;
                address
                    .wrapping_sub(layout.tls_end_address())
                    .wrapping_add(addend)
            } else {
                todo!()
            }
        }
        (object::RelocationKind::Unknown, object::RelocationFlags::Elf { r_type: 22 }) => {
            // R_X86_64_GOTTPOFF
            byte_size = 4;
            // TODO: If we're statically linking, we can adjust the instruction to be an
            // absolute move.
            resolution
                .got_address()?
                .wrapping_add(addend)
                .wrapping_sub(place)
        }
        (object::RelocationKind::Unknown, object::RelocationFlags::Elf { r_type: 23 }) => {
            // R_X86_64_TPOFF32
            byte_size = 4;
            address.wrapping_sub(layout.tls_end_address())
        }
        (object::RelocationKind::Unknown, object::RelocationFlags::Elf { r_type: 41 }) => {
            // R_X86_64_GOTPCRELX
            byte_size = 4;
            resolution
                .got_address()?
                .wrapping_add(addend)
                .wrapping_sub(place)
        }
        (object::RelocationKind::Unknown, object::RelocationFlags::Elf { r_type: 42 }) => {
            // R_X86_64_REX_GOTPCRELX
            byte_size = 4;
            if layout.config().link_static {
                if false {
                    make_rex_got_instruction_absolute(offset, place, out)?;
                    address.wrapping_add(addend).wrapping_add(byte_size as u64)
                } else {
                    resolution
                        .got_address()?
                        .wrapping_add(addend)
                        .wrapping_sub(place)
                }
            } else {
                todo!()
            }
        }
        other => bail!("Unsupported relocation kind {other:?}"),
    };
    let value_bytes = value.to_le_bytes();
    let end = offset + byte_size;
    if out.len() < end {
        bail!("Relocation outside of bounds of section");
    }
    out[offset..end].copy_from_slice(&value_bytes[..byte_size]);
    Ok(next_modifier)
}

/// Verifies that the bytes leading up to `offset` are equal to `expected`. Return an error if not.
fn expect_bytes_before_offset(bytes: &[u8], offset: usize, expected: &[u8]) -> Result {
    if offset < expected.len() {
        bail!("Expected bytes {expected:x?}, but only had {offset} bytes available");
    }
    let actual = &bytes[offset - expected.len()..offset];
    if actual != expected {
        bail!("Expected bytes {expected:x?}, got {actual:x?}");
    }
    Ok(())
}

/// Changes the REX instruction from a relative GOT reference to an absolute instruction. This is
/// incomplete and probably wrong in places.
fn make_rex_got_instruction_absolute(offset: usize, place: u64, out: &mut [u8]) -> Result {
    if offset < 3 {
        bail!("Insufficient instruction bytes for R_X86_64_REX_GOTPCRELX");
    }
    let istart = place - 3;

    let rex = match out[offset - 3] {
        0x48 | 0x49 => 0x48,
        0x4c => 0x49,
        o => {
            bail!("Unsupported REX byte for R_X86_64_REX_GOTPCRELX 0x{o:x} at {istart:x}");
        }
    };
    let ins = match out[offset - 2] {
        0x8b => 0xc7, // mov
        0x2b => 0x81, // sub
        0x3b => 0x81, // cmp
        o => {
            bail!("Unsupported instruction byte for R_X86_64_REX_GOTPCRELX 0x{o:x} at {istart:x}");
        }
    };
    // TODO: Figure out if these operand bytes need to be different depending on the
    // instruction.
    out[offset - 1] = match out[offset - 1] {
        0x05 => 0xc0,
        0x15 => 0xc2,
        0x1d => 0xc3,
        0x25 => 0xc4,
        0x2d => 0xc5,
        0x3d => 0xc7,
        0x35 => 0xee,
        0x0d => 0xe9,
        o => {
            bail!("Unsupported operand byte for R_X86_64_REX_GOTPCRELX 0x{o:x} at {istart:x}");
        }
    };
    out[offset - 3] = rex;
    out[offset - 2] = ins;
    Ok(())
}

impl InternalLayout {
    fn write(&self, mut buffers: OutputSectionPartMap<&mut [u8]>, layout: &Layout) -> Result {
        let (file_header_bytes, rest) = buffers
            .file_headers
            .split_at_mut(usize::from(elf::FILE_HEADER_SIZE));
        let header: &mut FileHeader = bytemuck::from_bytes_mut(file_header_bytes);
        *header = FileHeader::build(layout)?;
        header.section_header_offset = self.section_header_offset();

        let (program_headers_bytes, rest) =
            rest.split_at_mut(Self::program_headers_size() as usize);
        let mut program_headers = ProgramHeaderWriter::new(program_headers_bytes);
        write_program_headers(&mut program_headers, layout)?;

        let (section_headers_bytes, _rest) =
            rest.split_at_mut(Self::section_headers_size(&layout.output_sections) as usize);
        write_section_headers(section_headers_bytes, layout);

        write_section_header_strings(buffers.shstrtab, &layout.output_sections);

        self.write_plt_got_entries(&mut buffers, layout)?;

        if !layout.symbol_db.args.strip_all {
            self.write_symbol_table_entries(&mut buffers, layout)?;
        }

        Ok(())
    }

    fn write_plt_got_entries(
        &self,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
        layout: &Layout,
    ) -> Result {
        let mut plt_got_writer = PltGotWriter::new(layout, buffers);

        // Our PLT entry for an undefined symbol doesn't really exist, so don't try to write an
        // actual PLT entry for it.
        let undefined_symbol_resolution = Resolution {
            plt_address: None,
            ..self.undefined_symbol_resolution
        };
        plt_got_writer.process_resolution(&undefined_symbol_resolution)?;
        if let Some(got_address) = self.tlsld_got_entry {
            plt_got_writer.process_resolution(&Resolution {
                address: 1,
                got_address: Some(got_address),
                plt_address: None,
                kind: TargetResolutionKind::Got,
            })?;
            plt_got_writer.process_resolution(&Resolution {
                address: 0,
                got_address: Some(got_address.saturating_add(elf::GOT_ENTRY_SIZE)),
                plt_address: None,
                kind: TargetResolutionKind::Got,
            })?;
        }

        for &symbol_id in &self.defined {
            plt_got_writer.process_symbol(symbol_id)?;
        }
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

        for &symbol_id in &self.defined {
            let symbol = layout.symbol_db.symbol(symbol_id);
            let local_index = symbol.local_index_for_file(INTERNAL_FILE_ID)?;
            let def_info = &self.symbol_definitions[local_index.0];
            let shndx = layout
                .output_sections
                .index_of_built_in(def_info.section_id());
            if let Some(resolution) = layout.global_symbol_resolution(symbol_id) {
                let address = match resolution {
                    SymbolResolution::Resolved(res) => res.address,
                    SymbolResolution::Dynamic => unreachable!(),
                };
                // We don't emit a section header for our headers section, so don't emit symbols that
                // are in that section, otherwise they'll show up as undefined.
                if shndx != 0 {
                    let symbol_name = layout.symbol_db.symbol_name(symbol_id);
                    let entry = symbol_writer.define_symbol(
                        false,
                        shndx,
                        address,
                        0,
                        symbol_name.bytes(),
                    )?;
                    entry.info = (elf::Binding::Global as u8) << 4;
                }
            }
        }
        Ok(())
    }

    // TODO
    #[allow(dead_code)]
    fn write_dynamic_entries(&self, out: &mut [u8], layout: &Layout) -> Result {
        let mut entries: &mut [DynamicEntry] = bytemuck::cast_slice_mut(out);
        assert!(entries.len() == NUM_DYNAMIC_ENTRIES);
        // When adding/removing entries, don't forget to update NUM_DYNAMIC_ENTRIES
        write_dynamic_entry(
            &mut entries,
            DynamicTag::SymTab,
            layout
                .section_layouts
                .built_in(output_section_id::SYMTAB)
                .file_offset as u64,
        )?;
        write_dynamic_entry(
            &mut entries,
            DynamicTag::StrTab,
            layout
                .section_layouts
                .built_in(output_section_id::STRTAB)
                .file_offset as u64,
        )?;

        //write_dynamic_entry(&mut entries, DynamicTag::Hash, todo)?;
        //write_dynamic_entry(&mut entries, DynamicTag::StrTab, todo)?;
        // write_dynamic_entry(&mut entries, DynamicTag::Rela, todo)?;
        // write_dynamic_entry(&mut entries, DynamicTag::RelaSize, todo)?;
        // write_dynamic_entry(&mut entries, DynamicTag::RelEnt, todo)?;
        // write_dynamic_entry(&mut entries, DynamicTag::StrSize, todo)?;
        // write_dynamic_entry(&mut entries, DynamicTag::SymEnt, todo)?;
        // write_dynamic_entry(&mut entries, DynamicTag::Rel, todo)?;
        // write_dynamic_entry(&mut entries, DynamicTag::RelSize, todo)?;
        write_dynamic_entry(&mut entries, DynamicTag::Null, 0)?;
        Ok(())
    }

    fn section_header_offset(&self) -> u64 {
        u64::from(elf::FILE_HEADER_SIZE) + Self::program_headers_size()
    }
}

pub(crate) const NUM_DYNAMIC_ENTRIES: usize = 11;

fn write_dynamic_entry(out: &mut &mut [DynamicEntry], tag: DynamicTag, value: u64) -> Result {
    let entry = crate::slice::take_first_mut(out)
        .ok_or_else(|| anyhow!("Insufficient dynamic table entries"))?;
    entry.tag = tag as u64;
    entry.value = value;
    Ok(())
}

fn write_section_headers(out: &mut [u8], layout: &Layout) {
    let entries: &mut [SectionHeader] = bytemuck::cast_slice_mut(out);
    let output_sections = &layout.output_sections;
    assert_eq!(entries.len(), output_sections.len());
    let mut entries = entries.iter_mut();
    let mut name_offset = 0;
    output_sections.sections_do(|section_id, section_details| {
        let section_layout = layout.section_layouts.get(section_id);
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
            link = output_sections.index_of_built_in(link_id);
        }
        *entries.next().unwrap() = SectionHeader {
            name: name_offset,
            ty: section_details.ty as u32,
            flags: section_details.section_flags,
            address: section_layout.mem_offset,
            offset: section_layout.file_offset as u64,
            size,
            link: link.into(),
            info: section_id.info(layout),
            alignment,
            entsize,
        };
        name_offset += layout.output_sections.name(section_id).len() as u32 + 1;
    });
}

fn write_section_header_strings(mut out: &mut [u8], sections: &OutputSections) {
    sections.sections_do(|id, _details| {
        let name = sections.name(id);
        let name_out = crate::slice::slice_take_prefix_mut(&mut out, name.len() + 1);
        name_out[..name.len()].copy_from_slice(name);
        name_out[name.len()] = 0;
    });
}

struct ProgramHeaderWriter<'out> {
    headers: &'out mut [ProgramHeader],
}

impl<'out> ProgramHeaderWriter<'out> {
    fn new(bytes: &'out mut [u8]) -> Self {
        Self {
            headers: bytemuck::cast_slice_mut(bytes),
        }
    }

    fn take_header(&mut self) -> Result<&mut ProgramHeader> {
        crate::slice::take_first_mut(&mut self.headers)
            .ok_or_else(|| anyhow!("Insufficient header slots"))
    }
}
