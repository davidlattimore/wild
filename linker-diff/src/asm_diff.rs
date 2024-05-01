use crate::all_equal;
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
use iced_x86::Formatter as _;
use iced_x86::OpKind;
use object::read::elf::ProgramHeader as _;
use object::read::elf::Rel;
use object::read::elf::Rela;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection;
use object::ObjectSymbol;
use object::ObjectSymbolTable as _;
use object::RelocationTarget;
use object::SymbolKind;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator as _;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Range;

const BIT_CLASS: u32 = 64;

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
                    all_symbols.insert(name);
                }
            }
        }
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

pub(crate) fn validate_iplt(object: &Object) -> Result {
    if let Some(error) = &object.address_index.iplt_error {
        bail!("{error}");
    }
    Ok(())
}

fn diff_symbol(symbol_name: &[u8], objects: &[Object]) -> Option<Diff> {
    let function_versions = FunctionVersions::new(symbol_name, objects);
    if function_versions.all_the_same() {
        return None;
    }
    Some(Diff {
        key: diff_key_for_symbol(symbol_name),
        values: DiffValues::PreFormatted(function_versions.to_string()),
    })
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
}

impl Display for FunctionVersions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let gutter_width = self.objects.iter().map(|n| n.name.len()).max().unwrap_or(0);
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
            for (value, obj) in values.iter().zip(self.objects) {
                let Some(value) = value else {
                    continue;
                };
                let display_name = &obj.name;
                write!(f, "{display_name:gutter_width$}")?;
                if let Some(address) = value.address() {
                    write!(f, " 0x{address:08x}")?;
                } else {
                    write!(f, "           ")?;
                }
                write!(f, " {value}")?;
                if let Line::Instruction(instruction) = value {
                    write!(f, "  // {:?}", instruction.raw_instruction.code(),)?;
                    if let Some((_, value)) = split_value(instruction) {
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
                }
                writeln!(f)?;
            }
        }
    }
}

enum SymbolResolution<'data> {
    Undefined,
    Duplicate(usize),
    Error(anyhow::Error),
    Function(FunctionDef<'data>),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum AddressResolution<'data> {
    Basic(BasicResolution<'data>),
    //Offset(BasicResolution<'data>, u64),
    Plt(BasicResolution<'data>),
    /// When we have a pointer to something and we don't know what it is, then that means we don't
    /// know how large it is, so we can only really look at the first byte.
    PointerTo(RawMemory),
    FileHeaderOffset(u64),
    ProgramHeaderOffset(u64),
    TlsIdentifier(SymbolName<'data>),
    Null,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct RawMemory {
    first_byte: u8,
    segment_details: SegmentDetails,
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
}

#[derive(Clone, Copy)]
enum Data<'data> {
    Bytes(&'data [u8]),
    Bss,
}

impl<'data> std::fmt::Debug for SymbolName<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.bytes))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PltEntry {
    got_address: u64,
}

pub(crate) struct AddressIndex<'data> {
    address_resolutions: HashMap<u64, Vec<AddressResolution<'data>>>,
    name_to_address: HashMap<&'data [u8], u64>,
    tls_by_offset: HashMap<u64, &'data [u8]>,
    iplt_error: Option<anyhow::Error>,
    file_header_addresses: Range<u64>,
    program_header_addresses: Range<u64>,
}

struct FunctionDef<'data> {
    address: u64,
    bytes: &'data [u8],
}

impl<'data> AddressIndex<'data> {
    pub(crate) fn new(object: &'data ElfFile64<'data>) -> Self {
        let mut info = Self {
            address_resolutions: Default::default(),
            name_to_address: Default::default(),
            tls_by_offset: Default::default(),
            iplt_error: None,
            file_header_addresses: Default::default(),
            program_header_addresses: Default::default(),
        };

        info.index_headers(object);
        info.address_resolutions
            .insert(0, vec![AddressResolution::Null]);
        info.index_symbols(object);
        info.index_dynamic_relocations(object);
        if let Err(error) = info.index_ifuncs(object) {
            info.iplt_error = Some(error);
        }
        info.index_plt_entries(object);

        info
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

    fn index_symbols(&mut self, object: &ElfFile64<'data>) {
        let tls_segment_size = get_tls_segment_size(object);
        for symbol in object.symbols() {
            let name = symbol.name_bytes().unwrap_or_default();
            let new_resolution =
                AddressResolution::Basic(BasicResolution::Symbol(SymbolName { bytes: name }));
            let mut address = symbol.address();
            if symbol.kind() == SymbolKind::Tls {
                self.tls_by_offset.insert(address, name);
                address = address.wrapping_sub(tls_segment_size);
            }
            self.add_resolution(address, new_resolution);
            self.name_to_address.insert(name, address);
        }
    }

    fn index_dynamic_relocations(&mut self, object: &ElfFile64<'data>) {
        let (Some(dynamic_symbol_table), Some(relocations)) =
            (object.dynamic_symbol_table(), object.dynamic_relocations())
        else {
            return;
        };
        for (address, rel) in relocations {
            if let RelocationTarget::Symbol(symbol_index) = rel.target() {
                if let Ok(symbol_name) = dynamic_symbol_table
                    .symbol_by_index(symbol_index)
                    .and_then(|sym| sym.name_bytes())
                {
                    self.add_resolution(
                        address,
                        AddressResolution::Basic(BasicResolution::Dynamic(SymbolName {
                            bytes: symbol_name,
                        })),
                    );
                }
            }
        }

        // The relocations above don't give us enough access to identify some of the relocation
        // types that we need, so go through the relocations again using a lower level API.
        let Some(rela_dyn_bytes) = object
            .section_by_name(".rela.dyn")
            .and_then(|s| s.data().ok())
        else {
            return;
        };
        let e = LittleEndian;
        let rela_dyn: &[object::elf::Rel64<LittleEndian>] = slice_from_all_bytes(rela_dyn_bytes);
        for rel in rela_dyn {
            if rel.r_type(e) == object::elf::R_X86_64_DTPMOD64 {
                let address = rel.r_offset(e);
                if let Some(tls_name) = read_address(object, address + 8)
                    .and_then(|tls_offset| self.tls_by_offset.get(&tls_offset))
                {
                    let symbol = SymbolName { bytes: tls_name };
                    self.add_resolution(address, AddressResolution::TlsIdentifier(symbol));
                }
            }
        }
    }

    fn index_plt_entries(&mut self, elf_file: &ElfFile64<'data>) {
        const PLT_ENTRY_TEMPLATE: &[u8] = &[
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0xf2, 0xff, 0x25, 0x0, 0x0, 0x0, 0x0, // bnd jmp *{relative GOT address}(%rip)
            0x0f, 0x1f, 0x44, 0x0, 0x0, // nopl   0x0(%rax,%rax,1)
        ];

        // The offset of the instruction pointer when the jmp instruction is processed - i.e. the
        // start of the next instruction after the jmp instruction.
        const RIP_OFFSET: u64 = 11;

        let Some(section) = elf_file.section_by_name(".plt") else {
            return;
        };
        let Ok(bytes) = section.data() else {
            return;
        };

        let mut address = section.address();
        for chunk in bytes.chunks(PLT_ENTRY_TEMPLATE.len()) {
            if chunk[..7] == PLT_ENTRY_TEMPLATE[..7] {
                let offset = u64::from(u32::from_le_bytes(*chunk[7..].first_chunk::<4>().unwrap()));
                let got_address = address + RIP_OFFSET + offset;
                let mut new_resolutions = Vec::new();
                for res in self.resolve(got_address) {
                    if let AddressResolution::Basic(got_resolution) = res {
                        new_resolutions.push(AddressResolution::Plt(*got_resolution));
                    }
                }
                if new_resolutions.is_empty() {
                    // If we don't have a resolution for the GOT address, then try just reading the
                    // value at that address.
                    if let Some(got_value) = read_address(elf_file, got_address) {
                        for res in self.resolve(got_value) {
                            if let AddressResolution::Basic(got_resolution) = res {
                                new_resolutions.push(AddressResolution::Plt(*got_resolution));
                            }
                        }
                    }
                }
                for res in new_resolutions {
                    self.add_resolution(address, res);
                }
            }
            address += PLT_ENTRY_TEMPLATE.len() as u64;
        }
    }

    fn resolve(&self, address: u64) -> &[AddressResolution<'data>] {
        self.address_resolutions
            .get(&address)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    fn index_ifuncs(&mut self, elf_file: &ElfFile64) -> Result {
        let start = self.symbol_address("__rela_iplt_start")?;
        let end = self.symbol_address("__rela_iplt_end")?;
        let iplt_bytes = read_bytes(elf_file, start, end - start)
            .ok_or_else(|| anyhow!("IPLT start/stop refer to invalid file range"))?;
        let iplt: &[Rela64] = slice_from_all_bytes(iplt_bytes);
        let e = LittleEndian;
        for relocation in iplt {
            let mut new_resolutions = Vec::new();
            let resolver_address = relocation.r_addend(e) as u64;
            for res in self.resolve(resolver_address) {
                if let AddressResolution::Basic(got_resolution) = res {
                    new_resolutions.push(AddressResolution::Basic(BasicResolution::IFunc(
                        got_resolution.symbol_name(),
                    )));
                }
            }
            let address = relocation.r_offset(e);
            for res in new_resolutions {
                self.add_resolution(address, res);
            }
        }
        Ok(())
    }

    /// Returns memory address of the symbol with the specified name.
    fn symbol_address(&mut self, symbol_name: &str) -> Result<u64> {
        self.name_to_address
            .get(symbol_name.as_bytes())
            .ok_or_else(|| anyhow!("Global symbol `{symbol_name}` is not defined"))
            .copied()
    }

    fn index_headers(&mut self, elf_file: &ElfFile64) {
        let header = elf_file.raw_header();
        let e = LittleEndian;
        let phoff = header.e_phoff.get(e);
        let phnum = header.e_phnum.get(e);
        let file_header_size =
            core::mem::size_of::<object::elf::FileHeader64<LittleEndian>>() as u64;
        for raw_seg in elf_file.raw_segments() {
            if raw_seg.p_type(e) != object::elf::PT_LOAD {
                continue;
            }
            let file_offset = raw_seg.p_offset(e);
            let file_size = raw_seg.p_filesz(e);
            let file_range = file_offset..(file_offset + file_size);
            let seg_address = raw_seg.p_paddr(e);
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
}

fn get_tls_segment_size(object: &ElfFile64) -> u64 {
    let e = LittleEndian;
    for segment in object.raw_segments() {
        if segment.p_type(e) == object::elf::PT_TLS {
            return segment.p_memsz(e).next_multiple_of(8);
        }
    }
    0
}

/// Attempts to read some data from `address`.
fn read_segment<'data>(
    elf_file: &ElfFile64<'data>,
    address: u64,
    len: u64,
) -> Option<(Data<'data>, SegmentDetails)> {
    // This could well end up needing to be optimised if we end up caring about performance.
    for raw_seg in elf_file.raw_segments() {
        let e = LittleEndian;
        if raw_seg.p_type(e) != object::elf::PT_LOAD {
            continue;
        }
        let seg_address = raw_seg.p_paddr(e);
        let seg_len = raw_seg.p_memsz(e);
        let seg_end = seg_address + seg_len;

        if seg_address <= address && address + len <= seg_end {
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

fn read<'data>(elf_file: &ElfFile64<'data>, address: u64, len: u64) -> Option<Data<'data>> {
    read_segment(elf_file, address, len).map(|(data, _)| data)
}

fn read_bytes<'data>(elf_file: &ElfFile64<'data>, address: u64, len: u64) -> Option<&'data [u8]> {
    read_segment(elf_file, address, len).and_then(|(data, _)| match data {
        Data::Bytes(bytes) => Some(bytes),
        Data::Bss => None,
    })
}

fn read_address(elf_file: &ElfFile64, address: u64) -> Option<u64> {
    read(elf_file, address, 8).map(|data| match data {
        Data::Bytes(bytes) => u64::from_le_bytes(*bytes.first_chunk::<8>().unwrap()),
        Data::Bss => 0,
    })
}

fn read_segment_byte(elf_file: &ElfFile64, address: u64) -> Option<(u8, SegmentDetails)> {
    read_segment(elf_file, address, 1).map(|(data, segment_type)| match data {
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
    Instruction(Instruction),
}

impl<'data> FunctionDef<'data> {
    fn decode(&self) -> AsmDecoder<'data> {
        AsmDecoder::new(self.address, self.bytes)
    }
}

struct AsmDecoder<'data> {
    base_address: u64,
    instruction_decoder: iced_x86::Decoder<'data>,
}

impl<'data> AsmDecoder<'data> {
    fn new(base_address: u64, bytes: &'data [u8]) -> Self {
        let options = iced_x86::DecoderOptions::NONE;
        Self {
            base_address,
            instruction_decoder: iced_x86::Decoder::new(BIT_CLASS, bytes, options),
        }
    }
}

impl<'data> Iterator for AsmDecoder<'data> {
    type Item = Instruction;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.instruction_decoder.can_decode() {
            return None;
        }
        let offset = self.instruction_decoder.position() as u64;
        let instruction = self.instruction_decoder.decode();
        Some(Instruction {
            base_address: self.base_address,
            offset,
            raw_instruction: instruction,
        })
    }
}

#[derive(Clone, Copy)]
struct Instruction {
    raw_instruction: iced_x86::Instruction,
    /// The address of the start of the function that contained this instruction.
    base_address: u64,
    /// The offset of this instruction within the function.
    offset: u64,
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
        for (ins, obj) in instructions[1..].iter().zip(&objects[1..]) {
            if common.is_empty() {
                break;
            }
            let unified = UnifiedInstruction::all_resolved(ins, obj);
            common.retain(|u| unified.iter().any(|a| u == a));
        }

        // In case there's still multiple resolutions, select one in a deterministic way.
        common.sort_by_key(|u| u.resolution);
        common.pop()
    }

    fn all_resolved(instruction: &Instruction, object: &'data Object<'data>) -> Vec<Self> {
        if let Some((updated_instruction, value)) = split_value(instruction) {
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
            if let Some(resolution) =
                read_segment_byte(object.elf_file, address).map(|(byte, segment_type)| {
                    AddressResolution::PointerTo(RawMemory {
                        first_byte: byte,
                        segment_details: segment_type,
                    })
                })
            {
                return vec![Self {
                    instruction: raw_instruction,
                    resolution: Some(resolution),
                }];
            }
        }
        resolutions
    }
}

/// Returns the input instruction split into an instruction and a value. Will return none if the
/// instruction doesn't contain an address/value. The returned instruction will have had the
/// address/value replaced with the placeholder.
fn split_value(instruction: &Instruction) -> Option<(iced_x86::Instruction, u64)> {
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
            OpKind::Memory | OpKind::NearBranch64 => {
                let displacement = sign_extended_memory_displacement(&instruction.raw_instruction);
                if instruction.raw_instruction.has_segment_prefix() {
                    return Some((
                        clear_displacement(instruction.raw_instruction),
                        displacement,
                    ));
                }
                return Some((
                    clear_displacement(instruction.raw_instruction),
                    instruction.base_address.wrapping_add(displacement),
                ));
            }
            _ => {}
        }
    }
    None
}

fn sign_extended_memory_displacement(instruction: &iced_x86::Instruction) -> u64 {
    let value = instruction.memory_displacement64();
    match instruction.memory_displ_size() {
        0 => 0,
        1 => {
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
    fn address(&self) -> Option<u64> {
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
            AddressResolution::Plt(res) => write!(f, "PLT[{res}]"),
            AddressResolution::PointerTo(raw) => write!(f, "pointer to {raw}"),
            AddressResolution::FileHeaderOffset(offset) => write!(f, "FILE_HEADER[0x{offset:x}]"),
            AddressResolution::TlsIdentifier(name) => write!(f, "TLS_IDENT[{name}]"),
            AddressResolution::ProgramHeaderOffset(offset) => {
                write!(f, "PROGRAM_HEADER[0x{offset:x}]")
            }
            AddressResolution::Null => write!(f, "null"),
        }
    }
}

impl Display for BasicResolution<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BasicResolution::Symbol(name) => write!(f, "{name}"),
            BasicResolution::Dynamic(name) => write!(f, "Dynamic({name})"),
            BasicResolution::IFunc(res) => write!(f, "IFunc[{res}]"),
        }
    }
}

impl Display for SymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            symbolic_demangle::demangle(&String::from_utf8_lossy(self.bytes))
        )
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

impl Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = String::new();
        let mut formatter = iced_x86::GasFormatter::new();
        formatter.format(&self.raw_instruction, &mut out);
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

impl Display for RawMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "byte in {} containing 0x{:x}",
            self.segment_details, self.first_byte
        )
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