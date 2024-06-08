use crate::all_equal;
use crate::section_map;
use crate::section_map::InputResolution;
use crate::slice_from_all_bytes;
use crate::Diff;
use crate::DiffValues;
use crate::ElfFile64;
use crate::Object;
use crate::Rela64;
use crate::Report;
use crate::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use iced_x86::Formatter as _;
use iced_x86::Mnemonic;
use iced_x86::OpKind;
use iced_x86::Register;
use object::read::elf::ElfSection64;
use object::read::elf::ProgramHeader as _;
use object::read::elf::Rela;
use object::read::elf::SectionHeader;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection;
use object::ObjectSymbol;
use object::RelocationTarget;
use object::SymbolKind;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator as _;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Range;

const BIT_CLASS: u32 = 64;

/// Whether to resolve section names when processing a pointer that we're not sure what it points
/// to. This is off by default because we sometimes put things into sections with different names
/// and we're OK with that at the moment.
const RESOLVE_SECTION_NAMES: bool = false;

/// A placeholder value that we substitute for a relative or absolute address in order to make two
/// or more instructions equivalent.
const PLACEHOLDER: u64 = 0xaaa;

pub(crate) fn report_function_diffs(report: &mut Report, objects: &[Object]) {
    let mut all_symbols = BTreeSet::new();
    for o in objects {
        for sym in o.elf_file.symbols() {
            if let Ok(name) = sym.name_bytes() {
                if sym.kind() == SymbolKind::Text {
                    // Formatting asm diff reports is kind of expensive, so only diff symbols where
                    // we're not going to ignore the result.
                    if report.should_ignore(&diff_key_for_symbol(name)) {
                        continue;
                    }
                    // Mold creates symbols for PLT and GOT. This is neat, but the other linkers
                    // don't do this, so we ignore them.
                    if name.ends_with(b"$plt") || name.ends_with(b"$pltgot") {
                        continue;
                    }
                    all_symbols.insert(name);
                }
            }
        }
    }
    // If we got an error building our index, then don't try to diff functions. We'd just get heaps
    // of diffs due to an incomplete index.
    if objects
        .iter()
        .any(|o| o.address_index.index_error.is_some())
    {
        return;
    }
    report.add_diffs(
        all_symbols
            .into_par_iter()
            .flat_map(|symbol_name| diff_symbol(symbol_name, objects))
            .collect(),
    );
}

fn diff_key_for_symbol(symbol_name: &[u8]) -> String {
    format!("asm.{}", String::from_utf8_lossy(symbol_name))
}

pub(crate) fn validate_indexes(object: &Object) -> Result {
    if let Some(error) = &object.address_index.index_error {
        bail!("{error}");
    }
    Ok(())
}

pub(crate) fn validate_got_plt(object: &Object) -> Result {
    let Some(dynamic) = object.address_index.dynamic_segment_address else {
        return Ok(());
    };
    let got_plt_sec = object
        .section_by_name(".got.plt")
        .context(".got.plt missing")?;
    let got_plt: &[u64] = object::slice_from_all_bytes(got_plt_sec.data()?)
        .map_err(|_| anyhow!("Invalid .got.plt"))?;
    if got_plt.len() < 3 {
        bail!(".got.plt is too short");
    }
    if got_plt[0] != dynamic {
        bail!("First entry of .got.plt should point to .dynamic");
    }
    if got_plt[1] != 0 || got_plt[2] != 0 {
        bail!(".got.plt[1] and .got.plt[2] are reserved and should be zero");
    }

    Ok(())
}

fn diff_symbol(symbol_name: &[u8], objects: &[Object]) -> Option<Diff> {
    let function_versions = FunctionVersions::new(symbol_name, objects);
    if function_versions.all_the_same() && !should_force_show_fn(symbol_name) {
        return None;
    }
    Some(Diff {
        key: diff_key_for_symbol(symbol_name),
        values: DiffValues::PreFormatted(function_versions.to_string()),
    })
}

/// Sometimes we don't find a difference when we think that we should. In that case, we provide a
/// mechanism to force showing of a particular symbol.
fn should_force_show_fn(symbol_name: &[u8]) -> bool {
    let Ok(show) = std::env::var("LINKER_DIFF_SHOW_SYM") else {
        return false;
    };
    show.as_bytes() == symbol_name
}

struct FunctionVersions<'data> {
    objects: &'data [Object<'data>],
    resolutions: Vec<SymbolResolution<'data>>,
}

impl<'data> FunctionVersions<'data> {
    fn all_the_same(&self) -> bool {
        if self
            .resolutions
            .iter()
            .all(|r| matches!(r, SymbolResolution::Undefined))
        {
            return true;
        }
        // For now, if we have duplicate definitions, we just accept them so long as each file has
        // the same number of duplicates.
        if let Some(SymbolResolution::Duplicate(n)) = self.resolutions.first() {
            return self.resolutions.iter().all(|r| {
                if let SymbolResolution::Duplicate(n2) = r {
                    n2 == n
                } else {
                    false
                }
            });
        };
        let mut disassemblers = self
            .resolutions
            .iter()
            .filter_map(|r| match r {
                SymbolResolution::Undefined => None,
                SymbolResolution::Duplicate(_) => None,
                SymbolResolution::Error(_) => None,
                SymbolResolution::Function(f) => Some(f.decode()),
            })
            .collect::<Vec<_>>();
        if disassemblers.len() != self.resolutions.len() {
            return false;
        }
        loop {
            let instructions = disassemblers
                .iter_mut()
                .map(|d| d.next())
                .collect::<Vec<_>>();
            if instructions.iter().all(|i| i.is_none()) {
                return true;
            }
            let instructions = instructions.into_iter().flatten().collect::<Vec<_>>();
            if instructions.len() != self.resolutions.len() {
                return false;
            }
            if UnifiedInstruction::new(&instructions, self.objects).is_none() {
                return false;
            }
        }
    }

    fn new(symbol_name: &[u8], objects: &'data [Object<'data>]) -> Self {
        let resolutions = objects
            .iter()
            .map(|obj| SymbolResolution::new(obj, symbol_name))
            .collect::<Vec<_>>();
        Self {
            objects,
            resolutions,
        }
    }

    fn determine_input_file(&self) -> Result<&section_map::InputFile> {
        let (obj, res) = self
            .objects
            .iter()
            .zip(&self.resolutions)
            .find(|(obj, _res)| obj.layout.is_some())
            .ok_or_else(|| anyhow!("No layout files present"))?;

        if let SymbolResolution::Function(function_def) = res {
            let address = function_def.address;
            let len = function_def.bytes.len() as u64;
            let addresses = address..address + len;
            obj.input_file_in_range(addresses.clone()).ok_or_else(|| {
                anyhow!(
                    "No layout information in range {addresses:x?} (has {:x?})",
                    obj.layout.as_ref().and_then(|l| l.address_range())
                )
            })
        } else {
            bail!("Non-function resolution")
        }
    }
}

const ORIG: &str = "ORIG";

impl Display for FunctionVersions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let gutter_width = self
            .objects
            .iter()
            .map(|n| n.name.len())
            .max()
            .unwrap_or(0)
            .max(ORIG.len());
        match self.determine_input_file() {
            Ok(input_file) => {
                writeln!(f, "{ORIG:gutter_width$}            {input_file}")?;
            }
            Err(e) => {
                writeln!(f, "{ORIG:gutter_width$}            {e}")?;
            }
        }
        let mut iterators = self
            .resolutions
            .iter()
            .map(|r| r.iter())
            .collect::<Vec<_>>();
        loop {
            let values = iterators.iter_mut().map(|i| i.next()).collect::<Vec<_>>();
            if values.iter().all(|v| v.is_none()) {
                // All functions ended concurrently.
                return Ok(());
            }
            let instructions = values
                .iter()
                .filter_map(|l| match l {
                    Some(Line::Instruction(i)) => Some(*i),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if instructions.len() != self.objects.len() {
                for (value, obj) in values.iter().zip(self.objects) {
                    let display_name = &obj.name;
                    write!(f, "{display_name:gutter_width$}")?;
                    write!(f, "           ")?;
                    match value {
                        Some(Line::Instruction(_)) => write!(f, " Defined")?,
                        Some(other) => write!(f, " {other}")?,
                        None => write!(f, " Empty")?,
                    }
                    writeln!(f)?;
                }
                return Ok(());
            }
            if let Some(unified) = UnifiedInstruction::new(&instructions, self.objects) {
                writeln!(f, "{:gutter_width$}            {unified}", "")?;
                continue;
            }
            let mut input_resolution = None;
            let mut trace_messages = Vec::new();
            for (value, obj) in values.iter().zip(self.objects) {
                let Some(value) = value else {
                    continue;
                };
                let display_name = &obj.name;
                write!(f, "{display_name:gutter_width$}")?;
                if let Some(instruction_address) = value.instruction_address() {
                    if let Some(res) = obj.resolve_input(instruction_address) {
                        input_resolution = Some(res);
                    }
                    write!(f, " 0x{instruction_address:08x}")?;
                } else {
                    write!(f, "           ")?;
                }
                write!(f, " {value}")?;
                if let Line::Instruction(instruction) = value {
                    write!(f, "  // {:?}", instruction.raw_instruction.code())?;
                    if let Some((_, value)) = split_value(obj, instruction) {
                        write!(f, "(0x{value:x})")?;
                    } else {
                        write!(
                            f,
                            "({})",
                            (0..instruction.raw_instruction.op_count())
                                .map(|o| format!("{:?}", instruction.raw_instruction.op_kind(o)))
                                .collect::<Vec<_>>()
                                .join(",")
                        )?;
                    }
                    for unified in UnifiedInstruction::all_resolved(instruction, obj) {
                        if let Some(resolution) = unified.resolution {
                            write!(f, " {resolution}")?;
                        }
                    }
                    let messages = obj
                        .trace
                        .messages_in(instruction.non_relocated_address_range());
                    trace_messages.extend(messages);
                }
                writeln!(f)?;
            }
            if let Some(res) = input_resolution {
                if let Err(error) = display_input_resolution(res, f, gutter_width) {
                    write!(f, "           {error}")?;
                }
            } else {
                writeln!(f, "       -- no input resolution --")?;
            }
            for msg in trace_messages {
                writeln!(f, "TRACE           {msg}")?;
            }
        }
    }
}

fn display_input_resolution(
    res: InputResolution,
    f: &mut std::fmt::Formatter,
    gutter_width: usize,
) -> Result {
    let object_bytes = res.file.read_object_bytes()?;
    let elf_file = &ElfFile64::parse(&object_bytes)?;
    let section = elf_file.section_by_index(res.section_index())?;
    let section_data = section.data()?;
    let mut decoder = AsmDecoder::new(0, &section_data[res.offset_in_section as usize..]);
    if let Some(instruction) = decoder.next() {
        write!(f, "{ORIG:gutter_width$}")?;
        write!(f, "            {instruction}")?;
        write!(f, "  //")?;
        if let Some(rel) = find_relocation(
            &section,
            res.offset_in_section..res.offset_in_section + instruction.raw_instruction.len() as u64,
        ) {
            write!(f, " {}", RelocationDisplay { rel, elf_file })?;
        }
        writeln!(f)?;
    }
    Ok(())
}

fn find_relocation(
    section: &ElfSection64<LittleEndian>,
    range: Range<u64>,
) -> Option<object::Relocation> {
    section
        .relocations()
        .find(|(offset, _rel)| range.contains(offset))
        .map(|(_offset, rel)| rel)
}

enum SymbolResolution<'data> {
    Undefined,
    Duplicate(usize),
    Error(anyhow::Error),
    Function(FunctionDef<'data>),
}

struct RelocationDisplay<'elf, 'data> {
    rel: object::Relocation,
    elf_file: &'elf ElfFile64<'data>,
}

impl Display for RelocationDisplay<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let object::RelocationFlags::Elf { r_type } = self.rel.flags() else {
            unreachable!();
        };
        rel_type_to_string(r_type).fmt(f)?;
        " -> ".fmt(f)?;
        match self.rel.target() {
            RelocationTarget::Symbol(symbol_index) => {
                if let Err(error) = self.write_symbol_or_section_name(f, symbol_index) {
                    write!(f, "<{error}>")?
                }
            }
            RelocationTarget::Absolute => write!(f, "0x{:x}", self.rel.addend())?,
            _ => "??".fmt(f)?,
        }
        Ok(())
    }
}

impl<'elf, 'data> RelocationDisplay<'elf, 'data> {
    fn write_symbol_or_section_name(
        &self,
        f: &mut std::fmt::Formatter,
        symbol_index: object::SymbolIndex,
    ) -> Result {
        let symbol = self.elf_file.symbol_by_index(symbol_index)?;
        let symbol_name = symbol.name_bytes()?;
        if !symbol_name.is_empty() {
            write!(
                f,
                "`{}`",
                symbolic_demangle::demangle(&String::from_utf8_lossy(symbol_name)),
            )?;
            return Ok(());
        }
        if let Some(section_index) = symbol.section_index() {
            let section = self.elf_file.section_by_index(section_index)?;
            write!(f, "`{}`", String::from_utf8_lossy(section.name_bytes()?))?;
        }
        Ok(())
    }
}

fn rel_type_to_string(r_type: u32) -> Cow<'static, str> {
    Cow::Borrowed(match r_type {
        0 => "R_X86_64_NONE",
        1 => "R_X86_64_64",
        2 => "R_X86_64_PC32",
        3 => "R_X86_64_GOT32",
        4 => "R_X86_64_PLT32",
        5 => "R_X86_64_COPY",
        6 => "R_X86_64_GLOB_DAT",
        7 => "R_X86_64_JUMP_SLOT",
        8 => "R_X86_64_RELATIVE",
        9 => "R_X86_64_GOTPCREL",
        10 => "R_X86_64_32",
        11 => "R_X86_64_32S",
        12 => "R_X86_64_16",
        13 => "R_X86_64_PC16",
        14 => "R_X86_64_8",
        15 => "R_X86_64_PC8",
        16 => "R_X86_64_DTPMOD64",
        17 => "R_X86_64_DTPOFF64",
        18 => "R_X86_64_TPOFF64",
        19 => "R_X86_64_TLSGD",
        20 => "R_X86_64_TLSLD",
        21 => "R_X86_64_DTPOFF32",
        22 => "R_X86_64_GOTTPOFF",
        23 => "R_X86_64_TPOFF32",
        24 => "R_X86_64_PC64",
        25 => "R_X86_64_GOTOFF64",
        26 => "R_X86_64_GOTPC32",
        27 => "R_X86_64_GOT64",
        28 => "R_X86_64_GOTPCREL64",
        29 => "R_X86_64_GOTPC64",
        30 => "R_X86_64_GOTPLT64",
        31 => "R_X86_64_PLTOFF64",
        32 => "R_X86_64_SIZE32",
        33 => "R_X86_64_SIZE64",
        34 => "R_X86_64_GOTPC32_TLSDESC",
        35 => "R_X86_64_TLSDESC_CALL",
        36 => "R_X86_64_TLSDESC",
        37 => "R_X86_64_IRELATIVE",
        38 => "R_X86_64_RELATIVE64",
        41 => "R_X86_64_GOTPCRELX",
        42 => "R_X86_64_REX_GOTPCRELX",
        other => return Cow::Owned(format!("Unknown relocation type 0x{other:x}")),
    })
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum AddressResolution<'data> {
    Basic(BasicResolution<'data>),
    Got(BasicResolution<'data>),
    Plt(BasicResolution<'data>),
    /// When we have a pointer to something and we don't know what it is, then that means we don't
    /// know how large it is, so we can only really look at the first byte. Actually, that's not
    /// true, the pointer could be an end-pointer, so we can't even look at one byte. TODO: We
    /// probably need to use layout info to determine the size of the thing we're pointing at.
    PointerTo(RawMemory<'data>),
    FileHeaderOffset(u64),
    ProgramHeaderOffset(u64),
    TlsIdentifier(SymbolName<'data>),
    Null,
    UndefinedTls,
    UnknownTls,
    TlsBlock,
    PltWithUnresolvedGot(u64),
    NullPlt,
    PltWithInvalidGot(u64),
    UnrecognisedPlt,
    IFuncWithUnknownResolver,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct RawMemory<'data> {
    segment_details: SegmentDetails,
    section_name: Option<&'data [u8]>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct SegmentDetails {
    r: bool,
    w: bool,
    x: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum BasicResolution<'data> {
    Symbol(SymbolName<'data>),
    Dynamic(SymbolName<'data>),
    IFunc(SymbolName<'data>),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SymbolName<'data> {
    bytes: &'data [u8],
    version: Option<&'data [u8]>,
}

#[derive(Clone, Copy)]
enum Data<'data> {
    Bytes(&'data [u8]),
    Bss,
}

impl<'data> std::fmt::Debug for SymbolName<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.bytes))?;
        if let Some(version) = self.version {
            write!(f, "@{}", String::from_utf8_lossy(version))?;
        }
        Ok(())
    }
}

pub(crate) struct AddressIndex<'data> {
    address_resolutions: HashMap<u64, Vec<AddressResolution<'data>>>,
    name_to_address: HashMap<&'data [u8], u64>,
    tls_by_offset: HashMap<u64, &'data [u8]>,
    index_error: Option<anyhow::Error>,
    file_header_addresses: Range<u64>,
    program_header_addresses: Range<u64>,
    jmprel_address: Option<u64>,
    jmprel_size: Option<u64>,
    got_plt_address: Option<u64>,
    versym_address: Option<u64>,
    dynamic_segment_address: Option<u64>,
    tls_segment_size: u64,
    load_offset: u64,

    /// Version names by their index.
    verneed: Vec<Option<&'data [u8]>>,

    /// Dynamic symbol names by their index.
    dynamic_symbol_names: Vec<SymbolName<'data>>,
}

struct FunctionDef<'data> {
    address: u64,
    bytes: &'data [u8],
}

pub(crate) const DEFAULT_LOAD_OFFSET: u64 = 0x3000_0000;

impl<'data> AddressIndex<'data> {
    pub(crate) fn new(object: &'data ElfFile64<'data>) -> Self {
        let mut info = Self {
            address_resolutions: Default::default(),
            name_to_address: Default::default(),
            tls_by_offset: Default::default(),
            index_error: None,
            file_header_addresses: Default::default(),
            program_header_addresses: Default::default(),
            jmprel_address: None,
            jmprel_size: None,
            got_plt_address: None,
            versym_address: None,
            dynamic_segment_address: None,
            tls_segment_size: 0,
            verneed: Default::default(),
            load_offset: DEFAULT_LOAD_OFFSET,
            dynamic_symbol_names: Default::default(),
        };

        if let Err(error) = info.build_indexes(object) {
            info.index_error = Some(error);
        }
        info
    }

    fn build_indexes(&mut self, object: &ElfFile64<'data>) -> Result {
        // Note, `index_dynamic` needs to be called first, since it sets `load_offset` to 0 for
        // non-relocatable binaries.
        self.index_dynamic(object)?;
        self.index_headers(object);
        self.address_resolutions
            .insert(0, vec![AddressResolution::Null]);
        self.index_verneed(object)?;
        self.index_symbols(object);
        self.index_dynamic_symbols(object)?;
        self.index_dynamic_relocations(object);
        self.index_got(object).unwrap();
        self.index_ifuncs(object)?;
        self.index_plt_sections(object)?;
        self.index_undefined_tls(object);
        Ok(())
    }

    fn add_resolution(&mut self, address: u64, new_resolution: AddressResolution<'data>) {
        if address == 0 {
            return;
        }
        self.address_resolutions
            .entry(address)
            .or_default()
            .push(new_resolution);
    }

    fn index_verneed(&mut self, object: &ElfFile64<'data>) -> Result {
        let e = LittleEndian;
        let mut versions = Vec::new();
        let maybe_verneed = object
            .sections()
            .find_map(|section| {
                section
                    .elf_section_header()
                    .gnu_verneed(e, object.data())
                    .transpose()
            })
            .transpose()?;
        let Some((mut verneed_iterator, strings_index)) = maybe_verneed else {
            return Ok(());
        };
        let strings = object
            .elf_section_table()
            .strings(e, object.data(), strings_index)?;
        while let Some((_verneed, mut aux_iterator)) = verneed_iterator.next()? {
            while let Some(aux) = aux_iterator.next()? {
                let name = aux.name(e, strings)?;
                let index = aux.vna_other.get(e) as usize;
                if index >= versions.len() {
                    versions.resize(index + 1, None);
                }
                versions[index] = Some(name);
            }
        }
        self.verneed = versions;
        Ok(())
    }

    fn index_dynamic_symbols(&mut self, object: &ElfFile64<'data>) -> Result {
        let symbol_version_indexes: Option<&[u16]> = self
            .versym_address
            .and_then(|address| {
                object
                    .sections()
                    .find(|section| section.address() == address)
            })
            .and_then(|section| section.data().ok())
            .and_then(|data| object::slice_from_all_bytes(data).ok());
        let mut dynamic_symbol_names = Vec::new();
        let mut max_index = 0;
        for sym in object.dynamic_symbols() {
            let sym_index = sym.index().0;
            max_index = max_index.max(sym_index);
            let version = symbol_version_indexes
                .and_then(|indexes| indexes.get(sym_index))
                .and_then(|&ver_index| self.verneed.get(ver_index as usize).copied().flatten());
            while dynamic_symbol_names.len() < sym_index {
                dynamic_symbol_names.push(SymbolName {
                    bytes: &[],
                    version: None,
                });
            }
            dynamic_symbol_names.push(SymbolName {
                bytes: sym.name_bytes()?,
                version,
            });
        }
        if let Some(versym) = symbol_version_indexes {
            let versym_len = versym.len();
            let num_symbols = max_index + 1;
            if versym_len != num_symbols {
                bail!(".gnu.version contains {versym_len}, but .dynsym contains {num_symbols}");
            }
        }
        self.dynamic_symbol_names = dynamic_symbol_names;
        Ok(())
    }

    fn index_symbols(&mut self, object: &ElfFile64<'data>) {
        let tls_segment_size = get_tls_segment_size(object);
        self.tls_segment_size = tls_segment_size;
        for symbol in object.symbols() {
            let name = symbol.name_bytes().unwrap_or_default();
            // GNU ld usually drops local symbols that start with .L. However occasionally it keeps
            // them for some reason that I haven't been able to figure out. Ignore them here to
            // avoid spurious diffs.
            if symbol.is_local() && name.starts_with(b".L") {
                continue;
            }
            // Symbols with no section are absolute. We don't index them.
            if symbol.section_index().is_none() {
                continue;
            }
            let new_resolution = AddressResolution::Basic(BasicResolution::Symbol(SymbolName {
                bytes: name,
                version: None,
            }));
            let address = symbol.address();
            if symbol.kind() == SymbolKind::Tls {
                self.tls_by_offset.insert(address, name);
                // Index both by positive and negative offsets. Positive are used in .so files.
                // Negative are used in executables.
                self.add_resolution(address, new_resolution);
                self.add_resolution(address.wrapping_sub(tls_segment_size), new_resolution);
            } else {
                self.add_resolution(address + self.load_offset, new_resolution);
                self.name_to_address
                    .insert(name, address + self.load_offset);
            }
        }
    }

    fn index_dynamic_relocations(&mut self, elf_file: &ElfFile64<'data>) {
        let Some(relocations) = elf_file.dynamic_relocations() else {
            return;
        };
        for (address, rel) in relocations {
            if let RelocationTarget::Symbol(symbol_index) = rel.target() {
                let Some(symbol_name) = self.dynamic_symbol_names.get(symbol_index.0) else {
                    continue;
                };
                self.add_resolution(
                    address + self.load_offset,
                    AddressResolution::Basic(BasicResolution::Dynamic(*symbol_name)),
                );
            }
        }

        // The relocations above don't give us enough access to identify some of the relocation
        // types that we need, so go through the relocations again using a lower level API.
        let Some(rela_dyn_bytes) = elf_file
            .section_by_name(".rela.dyn")
            .and_then(|s| s.data().ok())
        else {
            return;
        };
        let e = LittleEndian;
        let rela_dyn: &[object::elf::Rela64<LittleEndian>] = slice_from_all_bytes(rela_dyn_bytes);
        for rel in rela_dyn {
            if rel.r_type(e, false) == object::elf::R_X86_64_DTPMOD64 {
                let address = self.load_offset + rel.r_offset(e);
                let Some(tls_offset) = read_address(elf_file, self, address + 8) else {
                    continue;
                };
                if tls_offset == 0 {
                    self.add_resolution(address, AddressResolution::TlsBlock);
                }
                if let Some(tls_name) = self.tls_by_offset.get(&tls_offset) {
                    let symbol = SymbolName {
                        bytes: tls_name,
                        version: None,
                    };
                    self.add_resolution(address, AddressResolution::TlsIdentifier(symbol));
                }
            }
        }
    }

    fn index_plt_sections(&mut self, elf_file: &ElfFile64<'data>) -> Result {
        self.index_plt_named(elf_file, ".plt")?;
        self.index_plt_named(elf_file, ".plt.sec")?;
        self.index_plt_named(elf_file, ".plt.got")?;
        Ok(())
    }

    fn index_plt_named(&mut self, elf_file: &ElfFile64<'data>, section_name: &str) -> Result {
        let Some(section) = elf_file.section_by_name(section_name) else {
            return Ok(());
        };
        let Ok(bytes) = section.data() else {
            return Ok(());
        };
        let mut entry_length = section.elf_section_header().sh_entsize(LittleEndian) as usize;
        if entry_length == 0 {
            entry_length = 0x10;
        }
        if ![8, 0x10].contains(&entry_length) {
            bail!("{section_name} has unrecognised entry length {entry_length}");
        }

        let plt_base = section.address();
        let mut plt_offset = 0;
        for chunk in bytes.chunks(entry_length) {
            let mut new_resolutions = Vec::new();
            if let Some(got_address) = PltEntry::decode(chunk, plt_base, plt_offset)
                .map(|entry| self.got_address(entry))
                .transpose()?
                .map(|o| self.load_offset + o)
            {
                for res in self.resolve(got_address) {
                    if let AddressResolution::Basic(got_resolution) = res {
                        new_resolutions.push(AddressResolution::Plt(*got_resolution));
                    }
                }
                if new_resolutions.is_empty() {
                    // If we don't have a resolution for the GOT address, then try just reading the
                    // value at that address.
                    if let Some(got_value) = read_address(elf_file, self, got_address) {
                        for res in self.resolve(got_value) {
                            match res {
                                AddressResolution::Basic(got_resolution) => {
                                    new_resolutions.push(AddressResolution::Plt(*got_resolution));
                                }
                                AddressResolution::Null => {
                                    new_resolutions.push(AddressResolution::NullPlt);
                                }
                                _ => (),
                            }
                        }
                        if new_resolutions.is_empty() {
                            new_resolutions
                                .push(AddressResolution::PltWithUnresolvedGot(got_address));
                        }
                    } else {
                        new_resolutions.push(AddressResolution::PltWithInvalidGot(got_address));
                    }
                }
            } else {
                new_resolutions.push(AddressResolution::UnrecognisedPlt);
            }
            for res in new_resolutions {
                self.add_resolution(plt_base + self.load_offset + plt_offset, res);
            }
            plt_offset += entry_length as u64;
        }
        Ok(())
    }

    fn got_address(&self, plt_entry: PltEntry) -> Result<u64> {
        match plt_entry {
            PltEntry::DerefJmp(address) => Ok(address),
            PltEntry::GotIndex(got_index) => Ok(self
                .got_plt_address
                .context("Index-based PLT entry with no DT_PLTGOT")?
                + u64::from(got_index) * 8),
        }
    }

    fn resolve(&self, address: u64) -> &[AddressResolution<'data>] {
        self.address_resolutions
            .get(&address)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    fn index_ifuncs(&mut self, elf_file: &ElfFile64) -> Result {
        let Some(iplt_bytes) = self.iplt_bytes(elf_file)? else {
            return Ok(());
        };
        let iplt: &[Rela64] = slice_from_all_bytes(iplt_bytes);
        let e = LittleEndian;
        for relocation in iplt {
            let rel_type = (relocation.r_info.get(LittleEndian) & 0xffff_ffff) as u32;
            if rel_type != object::elf::R_X86_64_IRELATIVE {
                continue;
            }
            let mut new_resolutions = Vec::new();
            let resolver_address = relocation.r_addend(e) as u64 + self.load_offset;
            for res in self.resolve(resolver_address) {
                if let AddressResolution::Basic(got_resolution) = res {
                    new_resolutions.push(AddressResolution::Basic(BasicResolution::IFunc(
                        got_resolution.symbol_name(),
                    )));
                }
            }
            if new_resolutions.is_empty() {
                new_resolutions.push(AddressResolution::IFuncWithUnknownResolver);
            }
            let address = relocation.r_offset(e) + self.load_offset;
            for res in new_resolutions {
                self.add_resolution(address, res);
            }
        }
        Ok(())
    }

    fn iplt_bytes(&self, elf_file: &ElfFile64<'data>) -> Result<Option<&'data [u8]>> {
        // Non-relocatable static binaries use symbols to determine the location of the IPLT
        // relocations.
        if let (Ok(start), Ok(end)) = (
            self.symbol_address("__rela_iplt_start"),
            self.symbol_address("__rela_iplt_end"),
        ) {
            return Ok(read_bytes(elf_file, self, start, end - start));
        }
        // Everything else uses entries in the DYNAMIC segment.
        if let (Some(start), Some(len)) = (self.jmprel_address, self.jmprel_size) {
            return Ok(read_bytes(elf_file, self, start + self.load_offset, len));
        }
        Ok(None)
    }

    /// Returns memory address of the symbol with the specified name.
    fn symbol_address(&self, symbol_name: &str) -> Result<u64> {
        self.name_to_address
            .get(symbol_name.as_bytes())
            .ok_or_else(|| anyhow!("Global symbol `{symbol_name}` is not defined"))
            .copied()
    }

    fn index_headers(&mut self, elf_file: &ElfFile64) {
        let header = elf_file.elf_header();
        let e = LittleEndian;
        let phoff = header.e_phoff.get(e);
        let phnum = header.e_phnum.get(e);
        let file_header_size =
            core::mem::size_of::<object::elf::FileHeader64<LittleEndian>>() as u64;
        for raw_seg in elf_file.elf_program_headers() {
            if raw_seg.p_type(e) != object::elf::PT_LOAD {
                continue;
            }
            let file_offset = raw_seg.p_offset(e);
            let file_size = raw_seg.p_filesz(e);
            let file_range = file_offset..(file_offset + file_size);
            let seg_address = raw_seg.p_paddr(e) + self.load_offset;
            if file_offset == 0 {
                self.file_header_addresses = seg_address..seg_address + file_header_size;
            }
            if file_range.contains(&phoff) {
                let mem_start = phoff - file_offset + seg_address;
                let byte_len = phnum as u64
                    * core::mem::size_of::<object::elf::ProgramHeader64<LittleEndian>>() as u64;
                self.program_header_addresses = mem_start..(mem_start + byte_len);
            }
        }
    }

    fn index_got(&mut self, elf_file: &ElfFile64) -> Result {
        let Some(got) = elf_file.section_by_name(".got") else {
            return Ok(());
        };
        let data = got.data()?;
        let entry_size = core::mem::size_of::<u64>();
        let entries: &[u64] = object::slice_from_bytes(data, data.len() / entry_size)
            .unwrap()
            .0;
        let mut new_resolutions = Vec::new();
        let base_address = got.address() + self.load_offset;
        for (entry, address) in entries.iter().zip((base_address..).step_by(entry_size)) {
            // If there's already a resolution for our GOT entry (e.g. a dynamic relocation), then
            // we assume that will overwrite whatever value is in the GOT entry in the file, so we
            // ignore it.
            if !self.resolve(address).is_empty() {
                continue;
            }
            new_resolutions.extend(self.resolve(*entry).iter().filter_map(|res| {
                if let AddressResolution::Basic(basic) = res {
                    Some(AddressResolution::Got(*basic))
                } else {
                    None
                }
            }));
            for res in new_resolutions.drain(..) {
                self.add_resolution(address, res);
            }
        }
        Ok(())
    }

    fn index_undefined_tls(&mut self, object: &ElfFile64) {
        // Undefined weak references to TLS variables end up with an offset that is the negative of
        // address of the TCB, which is the end of the TLS segment with 8-byte alignment applied.
        let undefined_tls = 0_u64.wrapping_sub(get_tls_end_address(object));
        self.add_resolution(undefined_tls, AddressResolution::UndefinedTls);
    }

    fn index_dynamic(&mut self, object: &ElfFile64) -> Result {
        let e = LittleEndian;
        let dynamic_segment = object
            .elf_program_headers()
            .iter()
            .find(|seg| seg.p_type(LittleEndian) == object::elf::PT_DYNAMIC);
        self.dynamic_segment_address = dynamic_segment.map(|seg| seg.p_vaddr(e));
        if dynamic_segment.is_none() {
            // There's no dynamic segment, which means our binary isn't relocatable. Don't apply any
            // offset to addresses.
            self.load_offset = 0;
        }
        dynamic_segment
            .and_then(|seg| seg.data(LittleEndian, object.data()).ok())
            .and_then(|dynamic_table_data| {
                object::slice_from_all_bytes::<object::elf::Dyn64<LittleEndian>>(dynamic_table_data)
                    .ok()
            })
            .unwrap_or_default()
            .iter()
            .for_each(|entry| match entry.d_tag.get(e) as u32 {
                object::elf::DT_JMPREL => {
                    self.jmprel_address = Some(entry.d_val.get(e));
                }
                object::elf::DT_PLTRELSZ => {
                    self.jmprel_size = Some(entry.d_val.get(e));
                }
                object::elf::DT_PLTGOT => {
                    self.got_plt_address = Some(entry.d_val.get(e));
                }
                object::elf::DT_VERSYM => {
                    self.versym_address = Some(entry.d_val.get(e));
                }
                _ => {}
            });
        Ok(())
    }
}

enum PltEntry {
    /// The parameter is an address (most likely of a GOT entry) that will be dereferenced by the
    /// PLT entry then jumped to.
    DerefJmp(u64),

    /// The parameter is an index into the GOT. This is used by PLT entries that are going to be
    /// lazily evaluated.
    GotIndex(u32),
}

impl PltEntry {
    fn decode(plt_entry: &[u8], plt_base: u64, plt_offset: u64) -> Option<PltEntry> {
        match plt_entry.len() {
            8 => Self::decode_8(plt_entry, plt_base, plt_offset),
            16 => Self::decode_16(plt_entry, plt_base, plt_offset),
            _ => None,
        }
    }

    fn decode_8(plt_entry: &[u8], plt_base: u64, plt_offset: u64) -> Option<PltEntry> {
        const RIP_OFFSET: usize = 6;
        // jmp *{relative GOT}(%rip)
        // xchg %ax, %ax
        if plt_entry.starts_with(&[0xff, 0x25]) && plt_entry.ends_with(&[0x66, 0x90]) {
            let offset = u64::from(u32::from_le_bytes(
                *plt_entry[RIP_OFFSET - 4..].first_chunk::<4>().unwrap(),
            ));
            return Some(PltEntry::DerefJmp(
                (plt_base + plt_offset + RIP_OFFSET as u64).wrapping_add(offset),
            ));
        }
        None
    }

    fn decode_16(plt_entry: &[u8], plt_base: u64, plt_offset: u64) -> Option<PltEntry> {
        // TODO: We should perhaps report differences in which PLT template was used.
        const PLT_ENTRY_LENGTH: usize = 0x10;
        {
            const PLT_ENTRY_TEMPLATE: &[u8; PLT_ENTRY_LENGTH] = &[
                0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                0xf2, 0xff, 0x25, 0x0, 0x0, 0x0, 0x0, // bnd jmp *{relative GOT address}(%rip)
                0x0f, 0x1f, 0x44, 0x0, 0x0, // nopl   0x0(%rax,%rax,1)
            ];

            if plt_entry[..7] == PLT_ENTRY_TEMPLATE[..7] {
                // The offset of the instruction pointer when the jmp instruction is processed -
                // i.e. the start of the next instruction after the jmp instruction.
                const RIP_OFFSET: usize = 11;
                let offset = u64::from(u32::from_le_bytes(
                    *plt_entry[RIP_OFFSET - 4..].first_chunk::<4>().unwrap(),
                ));
                return Some(PltEntry::DerefJmp(
                    (plt_base + plt_offset + RIP_OFFSET as u64).wrapping_add(offset),
                ));
            }
        }

        {
            const PLT_ENTRY_TEMPLATE: &[u8; PLT_ENTRY_LENGTH] = &[
                0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                0x68, 0, 0, 0, 0, // push $0
                0xf2, 0xe9, 0, 0, 0, 0,    // bnd jmp {plt[0]}(%rip)
                0x90, // nop
            ];
            // Note: Some variants use jmp instead of bnd jmp, then a different padding instruction.
            // Because we use the index that gets pushed, we ignore the bytes of the later
            // instructions, so that we support these variants.
            if plt_entry[..5] == PLT_ENTRY_TEMPLATE[..5] {
                let index = u32::from_le_bytes(*plt_entry[5..].first_chunk::<4>().unwrap());
                return Some(PltEntry::GotIndex(index));
            }
        }

        {
            const PLT_ENTRY_TEMPLATE: &[u8; PLT_ENTRY_LENGTH] = &[
                0xff, 0x25, 0, 0, 0, 0, // jmp *{relative GOT address}(%rip)
                0x68, 0, 0, 0, 0, // push $0
                0xe9, 0, 0, 0, 0, // jmp {plt[0]}(%rip)
            ];
            if plt_entry[..2] == PLT_ENTRY_TEMPLATE[..2]
                && plt_entry[6] == PLT_ENTRY_TEMPLATE[6]
                && plt_entry[11] == PLT_ENTRY_TEMPLATE[11]
            {
                // The offset of the instruction pointer when the jmp instruction is processed -
                // i.e. the start of the next instruction after the jmp instruction.
                const RIP_OFFSET: usize = 6;
                let offset = u64::from(u32::from_le_bytes(
                    *plt_entry[RIP_OFFSET - 4..].first_chunk::<4>().unwrap(),
                ));
                return Some(PltEntry::DerefJmp(
                    (plt_base + plt_offset + RIP_OFFSET as u64).wrapping_add(offset),
                ));
            }
        }

        {
            const PLT_ENTRY_TEMPLATE: &[u8; PLT_ENTRY_LENGTH] = &[
                0x41, 0xbb, 0, 0, 0, 0, // mov $X, %r11d
                0xff, 0x25, 0, 0, 0, 0, // jmp indirect relative
                0xcc, 0xcc, 0xcc, 0xcc, // int3 x 4
            ];
            if plt_entry[..2] == PLT_ENTRY_TEMPLATE[..2]
                && plt_entry[6..8] == PLT_ENTRY_TEMPLATE[6..8]
                && plt_entry[12..16] == PLT_ENTRY_TEMPLATE[12..16]
            {
                const RIP_OFFSET: usize = 12;
                let offset = u64::from(u32::from_le_bytes(
                    *plt_entry[RIP_OFFSET - 4..].first_chunk::<4>().unwrap(),
                ));
                return Some(PltEntry::DerefJmp(
                    (plt_base + plt_offset + RIP_OFFSET as u64).wrapping_add(offset),
                ));
            }
        }

        // endbr, jmp indirect relative
        let prefix = &[0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25];
        if let Some(rest) = plt_entry.strip_prefix(prefix) {
            let offset = u64::from(u32::from_le_bytes(*rest.first_chunk::<4>().unwrap()));
            return Some(PltEntry::DerefJmp(
                (plt_base + plt_offset + prefix.len() as u64 + 4).wrapping_add(offset),
            ));
        }

        None
    }
}

fn get_tls_segment_size(object: &ElfFile64) -> u64 {
    let e = LittleEndian;
    for segment in object.elf_program_headers() {
        if segment.p_type(e) == object::elf::PT_TLS {
            return segment.p_memsz(e).next_multiple_of(segment.p_align(e));
        }
    }
    0
}

fn get_tls_end_address(object: &ElfFile64) -> u64 {
    let e = LittleEndian;
    for segment in object.elf_program_headers() {
        if segment.p_type(e) == object::elf::PT_TLS {
            return (segment.p_vaddr(e) + segment.p_memsz(e)).next_multiple_of(segment.p_align(e));
        }
    }
    0
}

/// Attempts to read some data from `address`.
fn read_segment<'data>(
    elf_file: &ElfFile64<'data>,
    address_index: &AddressIndex,
    address: u64,
    len: u64,
) -> Option<(Data<'data>, SegmentDetails)> {
    let address = address.checked_sub(address_index.load_offset)?;
    // This could well end up needing to be optimised if we end up caring about performance.
    for raw_seg in elf_file.elf_program_headers() {
        let e = LittleEndian;
        if raw_seg.p_type(e) != object::elf::PT_LOAD {
            continue;
        }
        let seg_address = raw_seg.p_paddr(e);
        let seg_len = raw_seg.p_memsz(e);
        let seg_end = seg_address + seg_len;

        if seg_address <= address && address.saturating_add(len) <= seg_end {
            let start = (address - seg_address) as usize;
            let flags = raw_seg.p_flags(LittleEndian);
            let end = start + len as usize;
            let file_start = raw_seg.p_offset(e) as usize;
            let file_size = raw_seg.p_filesz(e) as usize;
            let file_end = file_start + file_size;
            let file_bytes = elf_file.data();
            let bytes = if file_end <= file_bytes.len() {
                &file_bytes[file_start..file_end]
            } else {
                &[]
            };
            let data = if end > bytes.len() {
                Data::Bss
            } else {
                Data::Bytes(&bytes[start..end])
            };
            return Some((
                data,
                SegmentDetails {
                    r: flags & object::elf::PF_R != 0,
                    w: flags & object::elf::PF_W != 0,
                    x: flags & object::elf::PF_X != 0,
                },
            ));
        }
    }
    None
}

fn read<'data>(
    elf_file: &ElfFile64<'data>,
    address_index: &AddressIndex,
    address: u64,
    len: u64,
) -> Option<Data<'data>> {
    read_segment(elf_file, address_index, address, len).map(|(data, _)| data)
}

fn read_bytes<'data>(
    elf_file: &ElfFile64<'data>,
    address_index: &AddressIndex,
    address: u64,
    len: u64,
) -> Option<&'data [u8]> {
    read_segment(elf_file, address_index, address, len).and_then(|(data, _)| match data {
        Data::Bytes(bytes) => Some(bytes),
        Data::Bss => None,
    })
}

fn read_address(elf_file: &ElfFile64, address_index: &AddressIndex, address: u64) -> Option<u64> {
    read(elf_file, address_index, address, 8).map(|data| match data {
        Data::Bytes(bytes) => u64::from_le_bytes(*bytes.first_chunk::<8>().unwrap()),
        Data::Bss => 0,
    })
}

fn read_segment_byte(
    elf_file: &ElfFile64,
    address_index: &AddressIndex,
    address: u64,
) -> Option<(u8, SegmentDetails)> {
    read_segment(elf_file, address_index, address, 1).map(|(data, segment_type)| match data {
        Data::Bytes(bytes) => (bytes[0], segment_type),
        Data::Bss => (0, segment_type),
    })
}

impl<'data> SymbolResolution<'data> {
    fn new(obj: &'data Object<'data>, name: &[u8]) -> Self {
        match Self::try_new(obj, name) {
            Ok(s) => s,
            Err(e) => SymbolResolution::Error(e),
        }
    }

    fn try_new(obj: &'data Object<'data>, name: &[u8]) -> Result<Self> {
        let symbol = match obj.symbol_by_name(name) {
            crate::NameLookupResult::Undefined => return Ok(SymbolResolution::Undefined),
            crate::NameLookupResult::Duplicate(count) => {
                return Ok(SymbolResolution::Duplicate(count))
            }
            crate::NameLookupResult::Defined(sym) => sym,
        };
        if !symbol.is_definition() {
            return Ok(SymbolResolution::Undefined);
        }
        match symbol.section() {
            object::SymbolSection::Unknown => todo!(),
            object::SymbolSection::None => todo!(),
            object::SymbolSection::Undefined => todo!(),
            object::SymbolSection::Absolute => todo!(),
            object::SymbolSection::Common => todo!(),
            object::SymbolSection::Section(section_index) => {
                let section = obj.elf_file.section_by_index(section_index)?;
                let data = section.data()?;
                let address = symbol.address() - section.address();
                let bytes = &data[address as usize..(address + symbol.size()) as usize];
                return Ok(SymbolResolution::Function(FunctionDef {
                    address: symbol.address(),
                    bytes,
                }));
            }
            _ => todo!(),
        }
    }

    fn iter(&self) -> SymbolResolutionIter {
        match self {
            SymbolResolution::Undefined => SymbolResolutionIter::Undefined,
            SymbolResolution::Duplicate(count) => SymbolResolutionIter::Duplicate(*count),
            SymbolResolution::Error(e) => SymbolResolutionIter::Error(e),
            SymbolResolution::Function(f) => SymbolResolutionIter::Function(f.decode()),
        }
    }
}

enum SymbolResolutionIter<'data> {
    Done,
    Undefined,
    Duplicate(usize),
    Error(&'data anyhow::Error),
    Function(AsmDecoder<'data>),
}

impl<'data> Iterator for SymbolResolutionIter<'data> {
    type Item = Line<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            SymbolResolutionIter::Done => None,
            SymbolResolutionIter::Duplicate(count) => {
                let count = *count;
                *self = SymbolResolutionIter::Done;
                Some(Line::Duplicate(count))
            }
            SymbolResolutionIter::Undefined => {
                *self = SymbolResolutionIter::Done;
                Some(Line::Undefined)
            }
            SymbolResolutionIter::Error(e) => {
                let e = *e;
                *self = SymbolResolutionIter::Done;
                Some(Line::Error(e))
            }
            SymbolResolutionIter::Function(d) => d.next().map(Line::Instruction),
        }
    }
}

enum Line<'data> {
    Undefined,
    Duplicate(usize),
    Error(&'data anyhow::Error),
    Instruction(Instruction<'data>),
}

impl<'data> FunctionDef<'data> {
    fn decode(&self) -> AsmDecoder<'data> {
        AsmDecoder::new(self.address, self.bytes)
    }
}

struct AsmDecoder<'data> {
    base_address: u64,
    instruction_decoder: iced_x86::Decoder<'data>,
    bytes: &'data [u8],
}

impl<'data> AsmDecoder<'data> {
    fn new(base_address: u64, bytes: &'data [u8]) -> Self {
        let options = iced_x86::DecoderOptions::NONE;
        Self {
            base_address,
            instruction_decoder: iced_x86::Decoder::new(BIT_CLASS, bytes, options),
            bytes,
        }
    }
}

impl<'data> Iterator for AsmDecoder<'data> {
    type Item = Instruction<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.instruction_decoder.can_decode() {
            return None;
        }
        let offset = self.instruction_decoder.position();
        let instruction = self.instruction_decoder.decode();
        let next_offset = self.instruction_decoder.position();
        let bytes = &self.bytes[offset..next_offset];
        Some(Instruction {
            base_address: self.base_address,
            offset: offset as u64,
            raw_instruction: instruction,
            bytes,
        })
    }
}

#[derive(Clone, Copy)]
struct Instruction<'data> {
    raw_instruction: iced_x86::Instruction,
    /// The address of the start of the function that contained this instruction.
    base_address: u64,
    /// The offset of this instruction within the function.
    offset: u64,

    bytes: &'data [u8],
}

impl Instruction<'_> {
    fn non_relocated_address_range(&self) -> Range<u64> {
        let base = self.base_address + self.offset;
        base..base + self.bytes.len() as u64
    }
}

#[derive(PartialEq, Eq)]
struct UnifiedInstruction<'data> {
    instruction: iced_x86::Instruction,
    resolution: Option<AddressResolution<'data>>,
}

impl<'data> UnifiedInstruction<'data> {
    fn new(instructions: &[Instruction], objects: &'data [Object<'data>]) -> Option<Self> {
        let first = instructions.first()?;
        let first_object = objects.first()?;
        if all_equal(instructions.iter().map(|i| i.raw_instruction)) {
            return Some(UnifiedInstruction {
                instruction: first.raw_instruction,
                resolution: None,
            });
        }
        // We might have multiple resolutions. e.g. if there is more than one symbol at the address.
        // Try to find a resolution shared by all objects and use that.
        let mut common = UnifiedInstruction::all_resolved(first, first_object);
        // If the first object has an instruction that we know is undefined behaviour, then we
        // ignore the instructions from the other objects.
        if let Some(ub) = extract_undefined_behaviour(&mut common) {
            return Some(ub);
        }
        for (ins, obj) in instructions[1..].iter().zip(&objects[1..]) {
            let unified = UnifiedInstruction::all_resolved(ins, obj);
            common.retain(|u| unified.iter().any(|a| u == a));
        }

        // In case there's still multiple resolutions, select one in a deterministic way.
        common.sort_by_key(|u| u.resolution);
        common.pop()
    }

    fn all_resolved(instruction: &Instruction, object: &'data Object<'data>) -> Vec<Self> {
        if let Some((updated_instruction, value)) = split_value(object, instruction) {
            Self::resolve_address(updated_instruction, value, object)
        } else {
            vec![]
        }
    }

    fn resolve_address(
        raw_instruction: iced_x86::Instruction,
        address: u64,
        object: &'data Object<'data>,
    ) -> Vec<UnifiedInstruction<'data>> {
        let mut resolutions = object
            .address_index
            .resolve(address)
            .iter()
            .map(|resolution| Self {
                instruction: raw_instruction,
                resolution: Some(*resolution),
            })
            .collect::<Vec<_>>();

        // We need to treat points to ELF headers separately since they're expected to have
        // different file contents.
        if object
            .address_index
            .file_header_addresses
            .contains(&address)
        {
            resolutions.push(Self {
                instruction: raw_instruction,
                resolution: Some(AddressResolution::FileHeaderOffset(
                    address - object.address_index.file_header_addresses.start,
                )),
            });
        }
        if object
            .address_index
            .program_header_addresses
            .contains(&address)
        {
            resolutions.push(Self {
                instruction: raw_instruction,
                resolution: Some(AddressResolution::ProgramHeaderOffset(
                    address - object.address_index.program_header_addresses.start,
                )),
            });
        }

        // If we don't have a resolution by now, just see what byte we're pointing at.
        if resolutions.is_empty() {
            let resolution = if address < object.address_index.tls_segment_size
                || address > 0_u64.wrapping_sub(object.address_index.tls_segment_size)
            {
                Some(AddressResolution::UnknownTls)
            } else {
                read_segment_byte(object.elf_file, &object.address_index, address).map(
                    |(_byte, segment_type)| {
                        AddressResolution::PointerTo(RawMemory {
                            segment_details: segment_type,
                            section_name: RESOLVE_SECTION_NAMES
                                .then(|| section_name_for_address(object.elf_file, address))
                                .flatten(),
                        })
                    },
                )
            };
            if let Some(resolution) = resolution {
                return vec![Self {
                    instruction: raw_instruction,
                    resolution: Some(resolution),
                }];
            }
        }
        resolutions
    }

    fn is_undefined_behaviour(&self) -> bool {
        self.instruction.mnemonic() == Mnemonic::Call
            && self.resolution.is_some_and(|res| {
                matches!(res, AddressResolution::Null | AddressResolution::NullPlt)
            })
    }
}

fn extract_undefined_behaviour<'data>(
    unified: &mut Vec<UnifiedInstruction<'data>>,
) -> Option<UnifiedInstruction<'data>> {
    if unified.iter().any(|ins| ins.is_undefined_behaviour()) {
        return unified.drain(..).find(|ins| ins.is_undefined_behaviour());
    }
    None
}

fn section_name_for_address<'data>(
    elf_file: &ElfFile64<'data>,
    address: u64,
) -> Option<&'data [u8]> {
    elf_file.sections().find_map(|section| {
        let section_address = section.address();
        (section_address..section_address + section.size())
            .contains(&address)
            .then(|| section.name_bytes().ok())
            .flatten()
    })
}

/// Returns the input instruction split into an instruction and a value. Will return none if the
/// instruction doesn't contain an address/value. The returned instruction will have had the
/// address/value replaced with the placeholder.
fn split_value(object: &Object, instruction: &Instruction) -> Option<(iced_x86::Instruction, u64)> {
    fn clear_immediate(mut instruction: iced_x86::Instruction) -> iced_x86::Instruction {
        instruction.set_immediate64(0);
        instruction
    }

    fn clear_displacement(mut instruction: iced_x86::Instruction) -> iced_x86::Instruction {
        instruction.set_memory_displacement64(0);
        instruction
    }

    for op_num in 0..instruction.raw_instruction.op_count() {
        match instruction.raw_instruction.op_kind(op_num) {
            OpKind::Immediate32to64 => {
                return Some((
                    clear_immediate(instruction.raw_instruction),
                    instruction.raw_instruction.immediate32to64() as u64,
                ))
            }
            OpKind::Immediate64 => {
                return Some((
                    clear_immediate(instruction.raw_instruction),
                    instruction.raw_instruction.immediate64(),
                ))
            }
            OpKind::Immediate32 => {
                return Some((
                    clear_immediate(instruction.raw_instruction),
                    instruction.raw_instruction.immediate32() as u64,
                ))
            }
            OpKind::Memory | OpKind::NearBranch64 => {
                let displacement = sign_extended_memory_displacement(&instruction.raw_instruction);
                if instruction.raw_instruction.has_segment_prefix() {
                    return Some((
                        clear_displacement(instruction.raw_instruction),
                        displacement,
                    ));
                }
                let mut value = displacement;
                if is_ip_relative(&instruction.raw_instruction) {
                    value = instruction.base_address.wrapping_add(displacement)
                        + object.address_index.load_offset;
                }
                // Ignore displacements relative to the stack pointer. There's probably an immediate
                // value that's what we actually want.
                if instruction.raw_instruction.memory_base() == Register::RSP {
                    continue;
                }
                return Some((clear_displacement(instruction.raw_instruction), value));
            }
            _ => {}
        }
    }
    None
}

fn is_ip_relative(instruction: &iced_x86::Instruction) -> bool {
    instruction.memory_base() == Register::RIP
        || matches!(
            instruction.mnemonic(),
            Mnemonic::Call
                | Mnemonic::Ja
                | Mnemonic::Jae
                | Mnemonic::Jb
                | Mnemonic::Jbe
                | Mnemonic::Jcxz
                | Mnemonic::Je
                | Mnemonic::Jecxz
                | Mnemonic::Jg
                | Mnemonic::Jge
                | Mnemonic::Jl
                | Mnemonic::Jle
                | Mnemonic::Jmp
                | Mnemonic::Jmpe
                | Mnemonic::Jne
                | Mnemonic::Jno
                | Mnemonic::Jnp
                | Mnemonic::Jns
                | Mnemonic::Jo
                | Mnemonic::Jp
                | Mnemonic::Jrcxz
                | Mnemonic::Js
        )
}

fn sign_extended_memory_displacement(instruction: &iced_x86::Instruction) -> u64 {
    let value = instruction.memory_displacement64();
    match instruction.memory_displ_size() {
        0 | 1 => {
            // Not quite sure how to interpret this, but let's just leave it as-is for now.
            value
        }
        2 => {
            // 16 bit
            value as i16 as i64 as u64
        }
        4 => {
            // 32 bit
            value as i32 as i64 as u64
        }
        8 => {
            // 64 bit
            value
        }
        other => unimplemented!(
            "Don't yet support sign extension of for memory displacement of size {other}"
        ),
    }
}

impl<'data> BasicResolution<'data> {
    fn symbol_name(&self) -> SymbolName<'data> {
        match self {
            BasicResolution::Symbol(s) => *s,
            BasicResolution::Dynamic(s) => *s,
            BasicResolution::IFunc(s) => *s,
        }
    }
}

impl Line<'_> {
    fn instruction_address(&self) -> Option<u64> {
        match self {
            Line::Instruction(i) => Some(i.base_address + i.offset),
            _ => None,
        }
    }
}

impl Display for AddressResolution<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressResolution::Basic(res) => write!(f, "{res}"),
            AddressResolution::Got(res) => write!(f, "GOT({res})"),
            AddressResolution::Plt(res) => write!(f, "PLT({res})"),
            AddressResolution::PointerTo(raw) => write!(f, "POINTER-TO({raw})"),
            AddressResolution::FileHeaderOffset(offset) => write!(f, "FILE_HEADER[0x{offset:x}]"),
            AddressResolution::TlsIdentifier(name) => write!(f, "TLS-IDENT({name})"),
            AddressResolution::ProgramHeaderOffset(offset) => {
                write!(f, "PROGRAM-HEADER[0x{offset:x}]")
            }
            AddressResolution::Null => write!(f, "NULL"),
            AddressResolution::UndefinedTls => write!(f, "UNDEFINED-TLS"),
            AddressResolution::UnknownTls => write!(f, "UNKNOWN-TLS"),
            AddressResolution::PltWithUnresolvedGot(address) => {
                write!(f, "PLT-UNRESOLVED-GOT(0x{address:x})")
            }
            AddressResolution::NullPlt => write!(f, "NULL-PLT"),
            AddressResolution::UnrecognisedPlt => write!(f, "UNRECOGNISED-PLT"),
            AddressResolution::PltWithInvalidGot(address) => {
                write!(f, "PLT-INVALID-GOT(0x{address:x})")
            }
            AddressResolution::IFuncWithUnknownResolver => write!(f, "IFUNC-UNKNOWN"),
            AddressResolution::TlsBlock => write!(f, "TLS"),
        }
    }
}

impl Display for BasicResolution<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BasicResolution::Symbol(name) => write!(f, "{name}"),
            BasicResolution::Dynamic(name) => write!(f, "DYNAMIC({name})"),
            BasicResolution::IFunc(res) => write!(f, "IFUNC({res})"),
        }
    }
}

impl Display for SymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            symbolic_demangle::demangle(&String::from_utf8_lossy(self.bytes))
        )?;
        if let Some(version) = self.version {
            write!(f, "@{}", String::from_utf8_lossy(version))?;
        }
        Ok(())
    }
}

impl Display for Line<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Line::Undefined => write!(f, "Undefined"),
            Line::Duplicate(count) => write!(f, "{count} definitions"),
            Line::Error(e) => write!(f, "Error: {e}"),
            Line::Instruction(ins) => Display::fmt(ins, f),
        }
    }
}

impl Display for Instruction<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = String::new();
        let mut formatter = iced_x86::GasFormatter::new();
        formatter.format(&self.raw_instruction, &mut out);
        for v in self.bytes {
            write!(f, "{v:02x} ")?;
        }
        write!(f, "{out}")?;
        Ok(())
    }
}

impl Display for UnifiedInstruction<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = String::new();
        let mut formatter = iced_x86::GasFormatter::new();
        formatter.format(&self.instruction, &mut out);
        write!(f, "{out}")?;
        if self.resolution.is_some() || f.alternate() {
            write!(f, "  //")?;
        }
        if let Some(res) = &self.resolution {
            write!(f, " 0x{PLACEHOLDER:X}={res}")?;
        }
        Ok(())
    }
}

impl Display for RawMemory<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "byte in")?;
        if let Some(section_name) = self.section_name {
            write!(f, " {}", String::from_utf8_lossy(section_name))?;
        }
        write!(f, " ({})", self.segment_details)
    }
}

impl Display for SegmentDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.r {
            write!(f, "R")?;
        }
        if self.w {
            write!(f, "W")?;
        }
        if self.x {
            write!(f, "X")?;
        }
        Ok(())
    }
}
