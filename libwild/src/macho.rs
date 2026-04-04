// Mach-O platform support for wild linker.
#![allow(unused_variables, dead_code)]

use crate::OutputKind;
use crate::args::macho::MachOArgs;
use crate::ensure;
use crate::error;
use crate::platform;
use object::Endianness;
use object::macho;
use object::read::macho::MachHeader;
use object::read::macho::Nlist;
use object::read::macho::Section as MachOSectionTrait;
use object::read::macho::Segment as MachOSegmentTrait;

#[derive(Debug, Copy, Clone)]
pub(crate) struct MachO;

const LE: Endianness = Endianness::Little;

type SectionTable<'data> = &'data [macho::Section64<Endianness>];
type SymbolTable<'data> = object::read::macho::SymbolTable<'data, macho::MachHeader64<Endianness>>;
pub(crate) type SymtabEntry = macho::Nlist64<Endianness>;

/// Wraps a Mach-O Section64 so we can implement platform traits on it.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub(crate) struct SectionHeader(pub(crate) macho::Section64<Endianness>);

#[derive(derive_more::Debug)]
pub(crate) struct File<'data> {
    #[debug(skip)]
    pub(crate) data: &'data [u8],
    #[debug(skip)]
    pub(crate) sections: SectionTable<'data>,
    #[debug(skip)]
    pub(crate) symbols: SymbolTable<'data>,
    pub(crate) flags: u32,
}

impl<'data> platform::ObjectFile<'data> for File<'data> {
    type Platform = MachO;

    fn parse_bytes(input: &'data [u8], is_dynamic: bool) -> crate::error::Result<Self> {
        let header = macho::MachHeader64::<Endianness>::parse(input, 0)?;
        let mut commands = header.load_commands(LE, input, 0)?;

        let mut symbols = None;
        let mut sections = None;

        while let Some(command) = commands.next()? {
            if let Some(symtab_command) = command.symtab()? {
                ensure!(symbols.is_none(), "At most one symtab command expected");
                symbols = Some(symtab_command.symbols::<macho::MachHeader64<_>, _>(LE, input)?);
            } else if let Some((segment_command, segment_data)) = command.segment_64()? {
                // Mach-O object files have a single unnamed segment containing all sections.
                if sections.is_none() {
                    sections = Some(segment_command.sections(LE, segment_data)?);
                }
            }
        }

        Ok(File {
            data: input,
            symbols: symbols.ok_or("Missing symbol table")?,
            sections: sections.unwrap_or(&[]),
            flags: header.flags(LE),
        })
    }

    fn parse(
        input: &crate::input_data::InputBytes<'data>,
        args: &<Self::Platform as platform::Platform>::Args,
    ) -> crate::error::Result<Self> {
        Self::parse_bytes(input.data, false)
    }

    fn is_dynamic(&self) -> bool {
        false
    }

    fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    fn symbols_iter(&self) -> impl Iterator<Item = &'data SymtabEntry> {
        self.symbols.iter()
    }

    fn symbol(
        &self,
        index: object::SymbolIndex,
    ) -> crate::error::Result<&'data SymtabEntry> {
        self.symbols
            .symbol(index)
            .map_err(|e| error!("Symbol index {} out of range: {e}", index.0))
    }

    fn section_size(&self, header: &SectionHeader) -> crate::error::Result<u64> {
        Ok(header.0.size(LE))
    }

    fn symbol_name(&self, symbol: &SymtabEntry) -> crate::error::Result<&'data [u8]> {
        symbol
            .name(LE, self.symbols.strings())
            .map_err(|e| error!("Failed to read symbol name: {e}"))
    }

    fn num_sections(&self) -> usize {
        self.sections.len()
    }

    fn section_iter(&self) -> <MachO as platform::Platform>::SectionIterator<'data> {
        MachOSectionIter {
            inner: self.sections.iter(),
        }
    }

    fn enumerate_sections(
        &self,
    ) -> impl Iterator<
        Item = (
            object::SectionIndex,
            &'data SectionHeader,
        ),
    > {
        self.sections
            .iter()
            .enumerate()
            .map(|(i, section)| {
                // Safety: SectionHeader is #[repr(transparent)] over Section64<Endianness>
                let header: &'data SectionHeader =
                    unsafe { &*(section as *const macho::Section64<Endianness> as *const SectionHeader) };
                (object::SectionIndex(i), header)
            })
    }

    fn section(
        &self,
        index: object::SectionIndex,
    ) -> crate::error::Result<&'data SectionHeader> {
        let section = self.sections.get(index.0).ok_or_else(|| {
            error!("Section index {} out of range", index.0)
        })?;
        Ok(unsafe { &*(section as *const macho::Section64<Endianness> as *const SectionHeader) })
    }

    fn section_by_name(
        &self,
        name: &str,
    ) -> Option<(object::SectionIndex, &'data SectionHeader)> {
        for (i, section) in self.sections.iter().enumerate() {
            let sectname = trim_nul(section.sectname());
            if sectname == name.as_bytes() {
                let header: &'data SectionHeader =
                    unsafe { &*(section as *const macho::Section64<Endianness> as *const SectionHeader) };
                return Some((object::SectionIndex(i), header));
            }
        }
        None
    }

    fn symbol_section(
        &self,
        symbol: &SymtabEntry,
        index: object::SymbolIndex,
    ) -> crate::error::Result<Option<object::SectionIndex>> {
        let n_type = symbol.n_type() & macho::N_TYPE;
        if n_type == macho::N_SECT {
            // n_sect is 1-based in Mach-O
            let sect = symbol.n_sect();
            if sect == 0 {
                return Ok(None);
            }
            Ok(Some(object::SectionIndex(sect as usize - 1)))
        } else {
            Ok(None)
        }
    }

    fn symbol_versions(&self) -> &[()]{
        // Mach-O doesn't have symbol versioning
        &[]
    }

    fn dynamic_symbol_used(
        &self,
        _symbol_index: object::SymbolIndex,
        _state: &mut (),
    ) -> crate::error::Result {
        Ok(())
    }

    fn finalise_sizes_dynamic(
        &self,
        _lib_name: &[u8],
        _state: &mut (),
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn apply_non_addressable_indexes_dynamic(
        &self,
        _indexes: &mut NonAddressableIndexes,
        _counts: &mut (),
        _state: &mut (),
    ) -> crate::error::Result {
        Ok(())
    }

    fn section_name(&self, section_header: &SectionHeader) -> crate::error::Result<&'data [u8]> {
        // Section names in Mach-O are stored inline in the section header (16 bytes).
        // We need to find this section in self.sections to get the 'data lifetime.
        for s in self.sections {
            if std::ptr::eq(
                s as *const macho::Section64<Endianness>,
                &section_header.0 as *const macho::Section64<Endianness>,
            ) {
                return Ok(trim_nul(s.sectname()));
            }
        }
        Err(error!("Section header not found in file's section table"))
    }

    fn raw_section_data(&self, section: &SectionHeader) -> crate::error::Result<&'data [u8]> {
        let offset = section.0.offset(LE) as usize;
        let size = section.0.size(LE) as usize;
        if size == 0 {
            return Ok(&[]);
        }
        self.data
            .get(offset..offset + size)
            .ok_or_else(|| error!("Section data out of range"))
    }

    fn section_data(
        &self,
        section: &SectionHeader,
        _member: &bumpalo_herd::Member<'data>,
        _loaded_metrics: &crate::resolution::LoadedMetrics,
    ) -> crate::error::Result<&'data [u8]> {
        // Mach-O sections are never compressed
        self.raw_section_data(section)
    }

    fn copy_section_data(&self, section: &SectionHeader, out: &mut [u8]) -> crate::error::Result {
        let data = self.raw_section_data(section)?;
        out[..data.len()].copy_from_slice(data);
        Ok(())
    }

    fn section_data_cow(
        &self,
        section: &SectionHeader,
    ) -> crate::error::Result<std::borrow::Cow<'data, [u8]>> {
        Ok(std::borrow::Cow::Borrowed(self.raw_section_data(section)?))
    }

    fn section_alignment(&self, section: &SectionHeader) -> crate::error::Result<u64> {
        // Mach-O stores alignment as a power of 2
        Ok(1u64 << section.0.align(LE))
    }

    fn relocations(
        &self,
        index: object::SectionIndex,
        _relocations: &(),
    ) -> crate::error::Result<RelocationList<'data>> {
        let section = self.sections.get(index.0).ok_or_else(|| {
            error!("Section index {} out of range for relocations", index.0)
        })?;
        let relocs = section
            .relocations(LE, self.data)
            .map_err(|e| error!("Failed to read relocations: {e}"))?;
        Ok(RelocationList { relocations: relocs })
    }

    fn parse_relocations(&self) -> crate::error::Result<()> {
        // Mach-O relocations are stored per-section, accessed via `relocations` method
        Ok(())
    }

    fn symbol_version_debug(&self, _symbol_index: object::SymbolIndex) -> Option<String> {
        None
    }

    fn section_display_name(&self, index: object::SectionIndex) -> std::borrow::Cow<'data, str> {
        if let Some(section) = self.sections.get(index.0) {
            let segname = String::from_utf8_lossy(trim_nul(section.segname()));
            let sectname = String::from_utf8_lossy(trim_nul(section.sectname()));
            std::borrow::Cow::Owned(format!("{segname},{sectname}"))
        } else {
            std::borrow::Cow::Borrowed("<unknown>")
        }
    }

    fn dynamic_tag_values(&self) -> Option<DynamicTagValues<'data>> {
        None
    }

    fn get_version_names(&self) -> crate::error::Result<()> {
        Ok(())
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &SymtabEntry,
        _local_index: usize,
        _version_names: &(),
    ) -> crate::error::Result<RawSymbolName<'data>> {
        let name = symbol
            .name(LE, self.symbols.strings())
            .map_err(|e| error!("Failed to read symbol name: {e}"))?;
        Ok(RawSymbolName { name })
    }

    fn should_enforce_undefined(
        &self,
        _resources: &crate::layout::GraphResources<'data, '_, MachO>,
    ) -> bool {
        false
    }

    fn verneed_table(&self) -> crate::error::Result<VerneedTable<'data>> {
        Ok(VerneedTable {
            _phantom: &[],
        })
    }

    fn process_gnu_note_section(
        &self,
        _state: &mut (),
        _section_index: object::SectionIndex,
    ) -> crate::error::Result {
        Ok(())
    }

    fn dynamic_tags(&self) -> crate::error::Result<&'data [()]> {
        Ok(&[])
    }
}

// -- SectionHeader trait impls --

impl platform::SectionHeader for SectionHeader {
    fn is_alloc(&self) -> bool {
        // In Mach-O, all sections in loadable segments are "allocated"
        true
    }

    fn is_writable(&self) -> bool {
        // Check segment name: __DATA and __DATA_CONST segments are writable
        let segname = trim_nul(self.0.segname());
        segname.starts_with(b"__DATA")
    }

    fn is_executable(&self) -> bool {
        let flags = self.0.flags(LE);
        (flags & macho::S_ATTR_PURE_INSTRUCTIONS) != 0
            || (flags & macho::S_ATTR_SOME_INSTRUCTIONS) != 0
    }

    fn is_tls(&self) -> bool {
        let sectname = trim_nul(self.0.sectname());
        sectname == b"__thread_vars"
            || sectname == b"__thread_data"
            || sectname == b"__thread_bss"
    }

    fn is_merge_section(&self) -> bool {
        let flags = self.0.flags(LE) & macho::SECTION_TYPE;
        flags == macho::S_CSTRING_LITERALS || flags == macho::S_LITERAL_POINTERS
    }

    fn is_strings(&self) -> bool {
        let flags = self.0.flags(LE) & macho::SECTION_TYPE;
        flags == macho::S_CSTRING_LITERALS
    }

    fn should_retain(&self) -> bool {
        false
    }

    fn should_exclude(&self) -> bool {
        let sectname = trim_nul(self.0.sectname());
        // Debug sections in __DWARF segment are not loaded
        let segname = trim_nul(self.0.segname());
        segname == b"__DWARF"
    }

    fn is_group(&self) -> bool {
        false
    }

    fn is_note(&self) -> bool {
        false
    }

    fn is_prog_bits(&self) -> bool {
        let section_type = self.0.flags(LE) & macho::SECTION_TYPE;
        section_type == macho::S_REGULAR || section_type == macho::S_CSTRING_LITERALS
    }

    fn is_no_bits(&self) -> bool {
        let section_type = self.0.flags(LE) & macho::SECTION_TYPE;
        section_type == macho::S_ZEROFILL || section_type == macho::S_GB_ZEROFILL
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionType(u32);

impl platform::SectionType for SectionType {
    fn is_rela(&self) -> bool {
        false
    }

    fn is_rel(&self) -> bool {
        false
    }

    fn is_symtab(&self) -> bool {
        false
    }

    fn is_strtab(&self) -> bool {
        false
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionFlags(u32);

impl SectionFlags {
    pub(crate) fn from_header(header: &SectionHeader) -> Self {
        SectionFlags(header.0.flags(LE))
    }
}

impl platform::SectionFlags for SectionFlags {
    fn is_alloc(self) -> bool {
        // All Mach-O sections are allocated
        true
    }
}

impl platform::Symbol for SymtabEntry {
    fn as_common(&self) -> Option<platform::CommonSymbol> {
        // In Mach-O, common symbols are N_UNDF | N_EXT with n_value > 0
        let n_type = self.n_type();
        if (n_type & macho::N_TYPE) == macho::N_UNDF
            && (n_type & macho::N_EXT) != 0
            && self.n_value(LE) > 0
        {
            let alignment_val = u64::from(self.n_desc(LE));
            let alignment =
                crate::alignment::Alignment::new(if alignment_val > 0 { 1u64 << alignment_val } else { 1 })
                    .unwrap_or(crate::alignment::MIN);
            let size = alignment.align_up(self.n_value(LE));
            let output_section_id = crate::output_section_id::BSS;
            let part_id = output_section_id.part_id_with_alignment(alignment);
            Some(platform::CommonSymbol { size, part_id })
        } else {
            None
        }
    }

    fn is_undefined(&self) -> bool {
        let n_type = self.n_type();
        // Not a stab, and type is N_UNDF
        (n_type & macho::N_STAB) == 0 && (n_type & macho::N_TYPE) == macho::N_UNDF
    }

    fn is_local(&self) -> bool {
        let n_type = self.n_type();
        // Not external and not a stab entry
        (n_type & macho::N_STAB) == 0 && (n_type & macho::N_EXT) == 0
    }

    fn is_absolute(&self) -> bool {
        (self.n_type() & macho::N_TYPE) == macho::N_ABS
    }

    fn is_weak(&self) -> bool {
        (self.n_desc(LE) & (macho::N_WEAK_DEF | macho::N_WEAK_REF)) != 0
    }

    fn visibility(&self) -> crate::symbol_db::Visibility {
        let n_type = self.n_type();
        if (n_type & macho::N_PEXT) != 0 {
            crate::symbol_db::Visibility::Hidden
        } else if (n_type & macho::N_EXT) != 0 {
            crate::symbol_db::Visibility::Default
        } else {
            crate::symbol_db::Visibility::Hidden
        }
    }

    fn value(&self) -> u64 {
        self.n_value(LE)
    }

    fn size(&self) -> u64 {
        // Mach-O symbols don't have a size field
        0
    }

    fn section_index(&self) -> object::SectionIndex {
        let n_type = self.n_type() & macho::N_TYPE;
        if n_type == macho::N_SECT {
            // n_sect is 1-based in Mach-O
            let sect = self.n_sect();
            if sect > 0 {
                return object::SectionIndex(sect as usize - 1);
            }
        }
        object::SectionIndex(0)
    }

    fn has_name(&self) -> bool {
        self.n_strx(LE) != 0
    }

    fn debug_string(&self) -> String {
        format!(
            "Nlist64 {{ n_type: 0x{:02x}, n_sect: {}, n_desc: 0x{:04x}, n_value: 0x{:x} }}",
            self.n_type(),
            self.n_sect(),
            self.n_desc(LE),
            self.n_value(LE),
        )
    }

    fn is_tls(&self) -> bool {
        // In Mach-O, TLS symbols reference __thread_vars section
        false
    }

    fn is_interposable(&self) -> bool {
        // Mach-O two-level namespace means symbols are generally not interposable
        false
    }

    fn is_func(&self) -> bool {
        // Mach-O doesn't have an explicit function type in nlist.
        // We'd need to check the section type, but for now return false.
        false
    }

    fn is_ifunc(&self) -> bool {
        false
    }

    fn is_hidden(&self) -> bool {
        (self.n_type() & macho::N_PEXT) != 0
    }

    fn is_gnu_unique(&self) -> bool {
        false
    }
}

// -- SectionAttributes --

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionAttributes {
    flags: u32,
    segname: [u8; 16],
}

impl platform::SectionAttributes for SectionAttributes {
    type Platform = MachO;

    fn merge(&mut self, rhs: Self) {
        self.flags |= rhs.flags;
    }

    fn apply(
        &self,
        _output_sections: &mut crate::output_section_id::OutputSections<MachO>,
        _section_id: crate::output_section_id::OutputSectionId,
    ) {
    }

    fn is_null(&self) -> bool {
        false
    }

    fn is_alloc(&self) -> bool {
        true
    }

    fn is_executable(&self) -> bool {
        (self.flags & macho::S_ATTR_PURE_INSTRUCTIONS) != 0
            || (self.flags & macho::S_ATTR_SOME_INSTRUCTIONS) != 0
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn is_writable(&self) -> bool {
        self.segname.starts_with(b"__DATA")
    }

    fn is_no_bits(&self) -> bool {
        let section_type = self.flags & macho::SECTION_TYPE;
        section_type == macho::S_ZEROFILL || section_type == macho::S_GB_ZEROFILL
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags(self.flags)
    }

    fn ty(&self) -> SectionType {
        SectionType(self.flags & macho::SECTION_TYPE)
    }

    fn set_to_default_type(&mut self) {
        self.flags = (self.flags & !macho::SECTION_TYPE) | macho::S_REGULAR;
    }
}

// -- Other platform type stubs --

pub(crate) struct NonAddressableIndexes {}

impl platform::NonAddressableIndexes for NonAddressableIndexes {
    fn new<P: platform::Platform>(_symbol_db: &crate::symbol_db::SymbolDb<P>) -> Self {
        NonAddressableIndexes {}
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SegmentType {}

impl platform::SegmentType for SegmentType {}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct ProgramSegmentDef {}

impl std::fmt::Display for ProgramSegmentDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<macho segment>")
    }
}

impl platform::ProgramSegmentDef for ProgramSegmentDef {
    type Platform = MachO;

    fn is_writable(self) -> bool {
        false
    }

    fn is_executable(self) -> bool {
        false
    }

    fn always_keep(self) -> bool {
        false
    }

    fn is_loadable(self) -> bool {
        false
    }

    fn is_stack(self) -> bool {
        false
    }

    fn is_tls(self) -> bool {
        false
    }

    fn order_key(self) -> usize {
        0
    }

    fn should_include_section(
        self,
        _section_info: &crate::output_section_id::SectionOutputInfo<MachO>,
        _section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        false
    }
}

pub(crate) struct BuiltInSectionDetails {}

impl platform::BuiltInSectionDetails for BuiltInSectionDetails {}

#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct DynamicTagValues<'data> {
    _phantom: &'data [u8],
}

#[derive(Debug)]
pub(crate) struct RelocationList<'data> {
    pub(crate) relocations: &'data [macho::Relocation<Endianness>],
}

impl<'data> platform::RelocationList<'data> for RelocationList<'data> {
    fn num_relocations(&self) -> usize {
        self.relocations.len()
    }
}

impl<'data> platform::DynamicTagValues<'data> for DynamicTagValues<'data> {
    fn lib_name(&self, _input: &crate::input_data::InputRef<'data>) -> &'data [u8] {
        b""
    }
}

#[derive(Debug)]
pub(crate) struct RawSymbolName<'data> {
    pub(crate) name: &'data [u8],
}

impl<'data> platform::RawSymbolName<'data> for RawSymbolName<'data> {
    fn parse(bytes: &'data [u8]) -> Self {
        RawSymbolName { name: bytes }
    }

    fn name(&self) -> &'data [u8] {
        self.name
    }

    fn version_name(&self) -> Option<&'data [u8]> {
        None
    }

    fn is_default(&self) -> bool {
        true
    }
}

impl std::fmt::Display for RawSymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.name))
    }
}

pub(crate) struct VerneedTable<'data> {
    _phantom: &'data [u8],
}

impl<'data> platform::VerneedTable<'data> for VerneedTable<'data> {
    fn version_name(&self, _local_symbol_index: object::SymbolIndex) -> Option<&'data [u8]> {
        None
    }
}

/// Iterator adapter to cast Section64 refs to SectionHeader refs.
pub(crate) struct MachOSectionIter<'data> {
    inner: core::slice::Iter<'data, macho::Section64<Endianness>>,
}

impl<'data> Iterator for MachOSectionIter<'data> {
    type Item = &'data SectionHeader;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|s| {
            unsafe { &*(s as *const macho::Section64<Endianness> as *const SectionHeader) }
        })
    }
}

impl platform::Platform for MachO {
    type File<'data> = File<'data>;
    type SymtabEntry = SymtabEntry;
    type SectionHeader = SectionHeader;
    type SectionFlags = SectionFlags;
    type SectionAttributes = SectionAttributes;
    type SectionType = SectionType;
    type SegmentType = SegmentType;
    type ProgramSegmentDef = ProgramSegmentDef;
    type BuiltInSectionDetails = BuiltInSectionDetails;
    type RelocationSections = ();
    type DynamicEntry = ();
    type DynamicSymbolDefinitionExt = ();
    type NonAddressableIndexes = NonAddressableIndexes;
    type NonAddressableCounts = ();
    type EpilogueLayoutExt = ();
    type GroupLayoutExt = ();
    type CommonGroupStateExt = ();
    type ArchIdentifier = ();
    type Args = MachOArgs;
    type ResolutionExt = ();
    type SymbolVersionIndex = ();
    type LayoutExt = ();
    type SectionIterator<'data> = MachOSectionIter<'data>;
    type DynamicTagValues<'data> = DynamicTagValues<'data>;
    type RelocationList<'data> = RelocationList<'data>;
    type DynamicLayoutStateExt<'data> = ();
    type DynamicLayoutExt<'data> = ();
    type LayoutResourcesExt<'data> = ();
    type PreludeLayoutStateExt = ();
    type PreludeLayoutExt = ();
    type ObjectLayoutStateExt<'data> = ();
    type RawSymbolName<'data> = RawSymbolName<'data>;
    type VersionNames<'data> = ();
    type VerneedTable<'data> = VerneedTable<'data>;

    fn link_for_arch<'data>(
        linker: &'data crate::Linker,
        args: &'data Self::Args,
    ) -> crate::error::Result<crate::LinkerOutput<'data>> {
        linker.link_for_arch::<MachO, crate::macho_aarch64::MachOAArch64>(args)
    }

    fn write_output_file<'data, A: platform::Arch<Platform = Self>>(
        output: &crate::file_writer::Output,
        layout: &crate::layout::Layout<'data, Self>,
    ) -> crate::error::Result {
        crate::macho_writer::write::<A>(output, layout)
    }

    fn section_attributes(header: &Self::SectionHeader) -> Self::SectionAttributes {
        SectionAttributes {
            flags: header.0.flags(LE),
            segname: *header.0.segname(),
        }
    }

    fn apply_force_keep_sections(
        _keep_sections: &mut crate::output_section_map::OutputSectionMap<bool>,
        _args: &Self::Args,
    ) {
    }

    fn is_zero_sized_section_content(
        _section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        false
    }

    fn built_in_section_details() -> &'static [Self::BuiltInSectionDetails] {
        &[]
    }

    fn finalise_group_layout(
        _memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> Self::GroupLayoutExt {
    }

    fn frame_data_base_address(
        _memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> u64 {
        0
    }

    fn finalise_find_required_sections(_groups: &[crate::layout::GroupState<Self>]) {
    }

    fn activate_dynamic<'data>(
        _state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
    }

    fn pre_finalise_sizes_prelude<'scope, 'data>(
        _prelude: &mut crate::layout::PreludeLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _resources: &crate::layout::GraphResources<'data, 'scope, Self>,
    ) {
    }

    fn finalise_sizes_dynamic<'data>(
        _object: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn finalise_object_sizes<'data>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
    }

    fn finalise_object_layout<'data>(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
    }

    fn finalise_layout_dynamic<'data>(
        _state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
        _resolutions_out: &mut crate::layout::ResolutionWriter<Self>,
    ) -> crate::error::Result<Self::DynamicLayoutExt<'data>> {
        Ok(())
    }

    fn take_dynsym_index(
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _section_layouts: &crate::output_section_map::OutputSectionMap<
            crate::layout::OutputRecordLayout,
        >,
    ) -> crate::error::Result<u32> {
        Ok(0)
    }

    fn compute_object_addresses<'data>(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
    }

    fn layout_resources_ext<'data>(
        _groups: &[crate::grouping::Group<'data, Self>],
    ) -> Self::LayoutResourcesExt<'data> {
    }

    fn load_object_section_relocations<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _state: &crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _section: crate::layout::Section,
        _scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn create_dynamic_symbol_definition<'data>(
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _symbol_id: crate::symbol_db::SymbolId,
    ) -> crate::error::Result<crate::layout::DynamicSymbolDefinition<'data, Self>> {
        Err(error!("Dynamic symbols not yet supported for Mach-O"))
    }

    fn update_segment_keep_list(
        _program_segments: &crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
        _keep_segments: &mut [bool],
        _args: &Self::Args,
    ) {
    }

    fn program_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }

    fn unconditional_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }

    fn create_linker_defined_symbols(
        _symbols: &mut crate::parsing::InternalSymbolsBuilder,
        _output_kind: crate::output_kind::OutputKind,
        _args: &Self::Args,
    ) {
    }

    fn built_in_section_infos<'data>()
    -> Vec<crate::output_section_id::SectionOutputInfo<'data, Self>> {
        use crate::layout_rules::SectionKind;
        use crate::output_section_id::NUM_BUILT_IN_SECTIONS;
        use crate::output_section_id::SectionName;
        use crate::output_section_id::SectionOutputInfo;

        let mut infos: Vec<SectionOutputInfo<'data, Self>> = Vec::with_capacity(NUM_BUILT_IN_SECTIONS);
        for _ in 0..NUM_BUILT_IN_SECTIONS {
            infos.push(SectionOutputInfo {
                kind: SectionKind::Primary(SectionName(b"")),
                section_attributes: SectionAttributes::default(),
                min_alignment: crate::alignment::MIN,
                location: None,
                secondary_order: None,
            });
        }

        // Provide names/attributes for the regular sections we care about
        infos[crate::output_section_id::TEXT.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__text")),
            section_attributes: SectionAttributes {
                flags: macho::S_REGULAR | macho::S_ATTR_PURE_INSTRUCTIONS,
                segname: *b"__TEXT\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        infos[crate::output_section_id::RODATA.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__const")),
            section_attributes: SectionAttributes::default(),
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        infos[crate::output_section_id::DATA.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__data")),
            section_attributes: SectionAttributes {
                flags: macho::S_REGULAR,
                segname: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        infos[crate::output_section_id::BSS.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__bss")),
            section_attributes: SectionAttributes {
                flags: macho::S_ZEROFILL,
                segname: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        infos
    }

    fn create_layout_properties<'data, 'states, 'files, A: platform::Arch<Platform = Self>>(
        _args: &Self::Args,
        _objects: impl Iterator<Item = &'files Self::File<'data>>,
        _states: impl Iterator<Item = &'states Self::ObjectLayoutStateExt<'data>> + Clone,
    ) -> crate::error::Result<Self::LayoutExt>
    where
        'data: 'files,
        'data: 'states,
    {
        Ok(())
    }

    fn load_exception_frame_data<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _eh_frame_section_index: object::SectionIndex,
        _resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn non_empty_section_loaded<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _unloaded: crate::resolution::UnloadedSection,
        _resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        _scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn new_epilogue_layout(
        _args: &Self::Args,
        _output_kind: crate::output_kind::OutputKind,
        _dynamic_symbol_definitions: &mut [crate::layout::DynamicSymbolDefinition<'_, Self>],
    ) -> Self::EpilogueLayoutExt {
    }

    fn apply_non_addressable_indexes_epilogue(
        _counts: &mut Self::NonAddressableCounts,
        _state: &mut Self::EpilogueLayoutExt,
    ) {
    }

    fn apply_non_addressable_indexes<'data, 'groups>(
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _counts: &Self::NonAddressableCounts,
        _mem_sizes_iter: impl Iterator<
            Item = &'groups mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        >,
    ) {
    }

    fn finalise_sizes_epilogue<'data>(
        _state: &mut Self::EpilogueLayoutExt,
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _dynamic_symbol_definitions: &[crate::layout::DynamicSymbolDefinition<'data, Self>],
        _properties: &Self::LayoutExt,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
    }

    fn finalise_sizes_all<'data>(
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
    }

    fn apply_late_size_adjustments_epilogue(
        _state: &mut Self::EpilogueLayoutExt,
        _current_sizes: &crate::output_section_part_map::OutputSectionPartMap<u64>,
        _extra_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
        _args: &Self::Args,
    ) -> crate::error::Result {
        Ok(())
    }

    fn finalise_layout_epilogue<'data>(
        _epilogue_state: &mut Self::EpilogueLayoutExt,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _common_state: &Self::LayoutExt,
        _dynsym_start_index: u32,
        _dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
    ) -> crate::error::Result {
        Ok(())
    }

    fn is_symbol_non_interposable<'data>(
        _object: &Self::File<'data>,
        _args: &Self::Args,
        _sym: &Self::SymtabEntry,
        _output_kind: crate::output_kind::OutputKind,
        _export_list: Option<&crate::export_list::ExportList>,
        _lib_name: &[u8],
        _archive_semantics: bool,
        _is_undefined: bool,
    ) -> bool {
        // Mach-O two-level namespace: symbols are generally non-interposable
        true
    }

    fn allocate_header_sizes(
        _prelude: &mut crate::layout::PreludeLayoutState<Self>,
        _sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _header_info: &crate::layout::HeaderInfo,
        _output_sections: &crate::output_section_id::OutputSections<Self>,
    ) {
    }

    fn finalise_sizes_for_symbol<'data>(
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _symbol_id: crate::symbol_db::SymbolId,
        _flags: crate::value_flags::ValueFlags,
    ) -> crate::error::Result {
        Ok(())
    }

    fn allocate_resolution(
        _flags: crate::value_flags::ValueFlags,
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _output_kind: crate::output_kind::OutputKind,
    ) {
    }

    fn allocate_object_symtab_space<'data>(
        _state: &crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _per_symbol_flags: &crate::value_flags::AtomicPerSymbolFlags,
    ) {
    }

    fn allocate_internal_symbol(
        _symbol_id: crate::symbol_db::SymbolId,
        _def_info: &crate::parsing::InternalSymDefInfo,
        _sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn allocate_prelude(
        _common: &mut crate::layout::CommonGroupState<Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) {
    }

    fn finalise_prelude_layout<'data>(
        _prelude: &crate::layout::PreludeLayoutState<Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
    ) -> crate::error::Result<Self::PreludeLayoutExt> {
        Ok(())
    }

    fn create_resolution(
        flags: crate::value_flags::ValueFlags,
        raw_value: u64,
        dynamic_symbol_index: Option<std::num::NonZeroU32>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> crate::layout::Resolution<Self> {
        crate::layout::Resolution {
            raw_value,
            dynamic_symbol_index,
            flags,
            format_specific: (),
        }
    }

    fn raw_symbol_name<'data>(
        name_bytes: &'data [u8],
        _verneed_table: &Self::VerneedTable<'data>,
        _symbol_index: object::SymbolIndex,
    ) -> Self::RawSymbolName<'data> {
        RawSymbolName { name: name_bytes }
    }

    fn default_layout_rules() -> &'static [crate::layout_rules::SectionRule<'static>] {
        MACHO_SECTION_RULES
    }

    fn build_output_order_and_program_segments<'data>(
        _custom: &crate::output_section_id::CustomSectionIds,
        output_kind: OutputKind,
        output_sections: &crate::output_section_id::OutputSections<'data, Self>,
        secondary: &crate::output_section_map::OutputSectionMap<
            Vec<crate::output_section_id::OutputSectionId>,
        >,
    ) -> (
        crate::output_section_id::OutputOrder,
        crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
    ) {
        let builder = crate::output_section_id::OutputOrderBuilder::<Self>::new(
            output_kind,
            output_sections,
            secondary,
        );
        builder.build()
    }
}

const MACHO_SECTION_RULES: &[crate::layout_rules::SectionRule<'static>] = {
    use crate::layout_rules::SectionRule;
    use crate::output_section_id;
    &[
        SectionRule::exact_section(b"__text", output_section_id::TEXT),
        SectionRule::exact_section(b"__stubs", output_section_id::TEXT),
        SectionRule::exact_section(b"__stub_helper", output_section_id::TEXT),
        SectionRule::exact_section(b"__const", output_section_id::RODATA),
        SectionRule::exact_section(b"__cstring", output_section_id::RODATA),
        SectionRule::exact_section(b"__literal4", output_section_id::RODATA),
        SectionRule::exact_section(b"__literal8", output_section_id::RODATA),
        SectionRule::exact_section(b"__literal16", output_section_id::RODATA),
        SectionRule::exact_section(b"__data", output_section_id::DATA),
        SectionRule::exact_section(b"__la_symbol_ptr", output_section_id::DATA),
        SectionRule::exact_section(b"__nl_symbol_ptr", output_section_id::DATA),
        SectionRule::exact_section(b"__got", output_section_id::DATA),
        SectionRule::exact_section(b"__bss", output_section_id::BSS),
        SectionRule::exact_section(b"__common", output_section_id::BSS),
        SectionRule::exact_section(b"__unwind_info", output_section_id::RODATA),
        SectionRule::exact_section(b"__eh_frame", output_section_id::RODATA),
        SectionRule::exact_section(b"__compact_unwind", output_section_id::RODATA),
    ]
};

/// Trim trailing NUL bytes from a fixed-size Mach-O name field.
fn trim_nul(name: &[u8; 16]) -> &[u8] {
    let end = name.iter().position(|&b| b == 0).unwrap_or(16);
    // Safety: end <= 16, and the array has 16 elements
    &name.as_slice()[..end]
}
