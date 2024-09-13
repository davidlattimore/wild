//! This crate finds differences between two ELF files. It's intended use is where the files were
//! produced by different linkers, or different versions of the same linker. So the input files
//! should be the same except for where the linkers make different decisions such as layout.
//!
//! Because the intended use is verifying the correct functioning of linkers, the focus is on
//! avoiding false positives rather than avoiding false negatives. i.e. we'd much rather fail to
//! report a difference than report a difference that doesn't matter. Ideally a reported difference
//! should indicate a bug or missing feature of the linker.
//!
//! Right now, performance of this library is not a priority, so there's quite a bit of heap
//! allocation going on that with a little work could be avoided. If we end up using this library as
//! part of a fuzzer this may need to be optimised.

#![allow(clippy::too_many_arguments)]

use anyhow::bail;
use anyhow::Context as _;
use asm_diff::AddressIndex;
use clap::Parser;
use itertools::Itertools;
use object::read::elf::ElfSection64;
use object::read::elf::ProgramHeader as _;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection;
use object::ObjectSymbol as _;
use object::RelocationFlags;
use section_map::IndexedLayout;
use section_map::LayoutAndFiles;
use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Range;
use std::path::PathBuf;

mod asm_diff;
mod eh_frame_diff;
mod gnu_hash;
mod header_diff;
pub(crate) mod section_map;
mod symtab;
mod trace;

type Result<T = (), E = anyhow::Error> = core::result::Result<T, E>;
type ElfFile64<'data> = object::read::elf::ElfFile64<'data, LittleEndian>;
type ElfSymbol64<'data, 'file> = object::read::elf::ElfSymbol64<'data, 'file, LittleEndian>;
type Rela64 = object::elf::Rela64<LittleEndian>;

#[non_exhaustive]
#[derive(Parser, Default, Clone)]
pub struct Config {
    /// Keys to ignore.
    #[arg(long, value_delimiter = ',')]
    pub ignore: Vec<String>,

    /// Show only the specified keys.
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,

    /// Treat the sections with the specified names as equivalent. e.g. ".got.plt=.got"
    #[arg(long, value_delimiter = ',', value_parser = parse_string_equality)]
    pub equiv: Vec<(String, String)>,

    /// Apply defaults for things that should be ignored currently for Wild. These defaults are
    /// subject to change as Wild changes.
    #[arg(long)]
    pub wild_defaults: bool,

    /// Display names for input files.
    #[arg(long, value_delimiter = ',', value_name = "NAME,NAME...")]
    pub display_names: Vec<String>,

    /// Files to compare against
    #[arg(long = "ref", value_name = "FILE")]
    pub references: Vec<PathBuf>,

    /// Primary file that we're validating against the reference file(s)
    pub file: PathBuf,
}

pub struct Object<'data> {
    name: String,
    path: PathBuf,
    elf_file: &'data ElfFile64<'data>,
    address_index: AddressIndex<'data>,
    name_index: NameIndex<'data>,
    indexed_layout: Option<IndexedLayout<'data>>,
    trace: trace::Trace,
    sections_by_name: HashMap<&'data [u8], SectionInfo>,
}

#[derive(Clone, Copy)]
struct SectionInfo {
    index: object::SectionIndex,
    size: u64,
}

struct NameIndex<'data> {
    globals_by_name: HashMap<&'data [u8], Vec<object::SymbolIndex>>,
    locals_by_name: HashMap<&'data [u8], Vec<object::SymbolIndex>>,
}

impl Config {
    pub fn from_env() -> Self {
        Self::parse()
    }

    fn apply_wild_defaults(&mut self) {
        self.ignore.extend(
            [
                // We don't currently support allocating space except in sections, so we have sections
                // to hold the section and program headers. We then need to ignore them because GNU ld
                // doesn't define such sections.
                "section.shdr",
                "section.phdr",
                // We don't yet support these sections.
                "section.data.rel.ro",
                "section.debug*",
                "section.stapsdt.base",
                "section.note.*",
                "section.hash",
                // We set this to 8. GNU ld sometimes does too, but sometimes to 0.
                "section.got.entsize",
                "section.plt.got.entsize",
                // GNU ld sometimes sets this differently that we do.
                "section.plt.alignment",
                // We currently output version info when linking against the interpreter
                // (ld-linux-x86-64.so.2). GNU ld doesn't.
                ".dynamic.DT_VERNEEDNUM",
                // We currently handle these dynamic tags differently
                ".dynamic.DT_JMPREL",
                ".dynamic.DT_PLTGOT",
                ".dynamic.DT_PLTREL",
                // We currently produce a .got.plt whenever we produce .plt, but GNU ld doesn't
                "section.got.plt",
                ".got.plt",
                // We don't currently produce a separate .plt.sec section.
                "section.plt.sec",
                // We don't yet write this.
                ".dynamic.DT_HASH",
                // We do support this. TODO: Should definitely look into why we're seeing this missing
                // in our output.
                "section.rela.plt",
                // We currently write 10 byte PLT entries in some cases where GNU ld writes 8 byte ones.
                "section.plt.got.alignment",
                // GNU ld sometimes makes this writable sometimes not. Presumably this depends on
                // whether there are relocations or some flags.
                "section.eh_frame.flags",
            ]
            .into_iter()
            .map(|s| s.to_owned()),
        );
        self.equiv.push((".got".to_owned(), ".got.plt".to_owned()));
        // We don't currently define .plt.got and .plt.sec, we just put everything into .plt.
        self.equiv.push((".plt".to_owned(), ".plt.got".to_owned()));
        self.equiv.push((".plt".to_owned(), ".plt.sec".to_owned()));
    }

    pub fn to_arg_string(&self) -> String {
        let mut out = String::new();
        if self.wild_defaults {
            out.push_str("--wild-defaults ");
        }
        if !self.ignore.is_empty() {
            out.push_str("--ignore '");
            out.push_str(&self.ignore.join(","));
            out.push_str("' ");
        }
        if !self.equiv.is_empty() {
            out.push_str("--equiv '");
            let parts = self
                .equiv
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect_vec();
            out.push_str(&parts.join(","));
            out.push_str("' ");
        }
        if !self.display_names.is_empty() {
            out.push_str("--display-names ");
            out.push_str(&self.display_names.join(","));
            out.push(' ');
        }
        for file in &self.references {
            out.push_str("--ref ");
            out.push_str(&file.to_string_lossy());
            out.push(' ');
        }
        out.push_str(&self.file.to_string_lossy());
        out
    }

    fn filenames(&self) -> impl Iterator<Item = &PathBuf> {
        // We always put our file first, since it makes it easier to treat it differently. e.g. when
        // we compare a value from our file against each of the values from the other files.
        std::iter::once(&self.file).chain(&self.references)
    }
}

impl<'data> Object<'data> {
    pub(crate) fn new(
        elf_file: &'data ElfFile64<'data>,
        name: String,
        path: PathBuf,
        layout_and_files: Option<&'data LayoutAndFiles>,
    ) -> Result<Self> {
        let address_index = AddressIndex::new(elf_file);
        let indexed_layout = layout_and_files.map(IndexedLayout::new).transpose()?;
        let trace = trace::Trace::for_path(&path)?;
        let sections_by_name = elf_file
            .sections()
            .map(|section| {
                Ok((
                    section.name_bytes()?,
                    SectionInfo {
                        index: section.index(),
                        size: section.size(),
                    },
                ))
            })
            .collect::<Result<HashMap<&[u8], SectionInfo>>>()?;
        Ok(Self {
            name: name.to_owned(),
            elf_file,
            path,
            address_index,
            name_index: NameIndex::new(elf_file),
            indexed_layout,
            trace,
            sections_by_name,
        })
    }

    /// Looks up a symbol, first trying to get a global, or failing that a local.
    fn symbol_by_name(&self, name: &[u8]) -> NameLookupResult {
        match self.global_by_name(name) {
            NameLookupResult::Undefined => self.local_by_name(name),
            other => other,
        }
    }

    fn global_by_name(&self, name: &[u8]) -> NameLookupResult {
        self.lookup_symbol(&self.name_index.globals_by_name, name)
    }

    fn local_by_name(&self, name: &[u8]) -> NameLookupResult {
        self.lookup_symbol(&self.name_index.locals_by_name, name)
    }

    fn lookup_symbol(
        &self,
        symbol_map: &HashMap<&[u8], Vec<object::SymbolIndex>>,
        name: &[u8],
    ) -> NameLookupResult {
        let indexes = symbol_map.get(name).map(Vec::as_slice).unwrap_or_default();
        if indexes.len() >= 2 {
            return NameLookupResult::Duplicate(indexes.len());
        }
        if let Some(sym) = indexes
            .first()
            .and_then(|index| self.elf_file.symbol_by_index(*index).ok())
        {
            NameLookupResult::Defined(sym)
        } else {
            NameLookupResult::Undefined
        }
    }

    fn has_symbols(&self) -> bool {
        !self.name_index.globals_by_name.is_empty()
    }

    fn resolve_input(&self, address: u64) -> Option<section_map::InputResolution> {
        self.indexed_layout.as_ref()?.resolve_address(address)
    }

    fn input_file_in_range(&self, addresses: Range<u64>) -> Option<&section_map::InputFile> {
        self.indexed_layout.as_ref()?.file_in_range(addresses)
    }

    fn section_by_name(&self, name: &str) -> Option<ElfSection64<LittleEndian>> {
        self.section_by_name_bytes(name.as_bytes())
    }

    fn section_by_name_bytes(&self, name: &[u8]) -> Option<ElfSection64<LittleEndian>> {
        let index = self.sections_by_name.get(name)?.index;
        self.elf_file.section_by_index(index).ok()
    }
}

enum NameLookupResult<'data, 'file> {
    Undefined,
    Duplicate(usize),
    Defined(ElfSymbol64<'data, 'file>),
}

fn validate_objects(
    report: &mut Report,
    objects: &[Object],
    validation_name: &str,
    validation_fn: impl Fn(&Object) -> Result,
) {
    let values = objects
        .iter()
        .map(|obj| match validation_fn(obj) {
            Ok(_) => "OK".to_owned(),
            Err(e) => e.to_string(),
        })
        .collect_vec();
    if first_equals_any(values.iter()) {
        return;
    }
    report.add_diff(Diff {
        key: validation_name.to_owned(),
        values: DiffValues::PerObject(values),
    })
}

pub struct Report {
    names: Vec<String>,
    paths: Vec<PathBuf>,
    diffs: Vec<Diff>,
    config: Config,
}

impl Report {
    pub fn from_config(mut config: Config) -> Result<Report> {
        if config.wild_defaults {
            config.apply_wild_defaults();
        }
        let display_names = short_file_display_names(&config)?;

        let file_bytes = config
            .filenames()
            .map(|filename| -> Result<Vec<u8>> {
                let mut bytes = std::fs::read(filename)
                    .with_context(|| format!("Failed to read `{}`", filename.display()))?;
                apply_relocations(&mut bytes).with_context(|| {
                    format!("Failed to apply relocations to `{}`", filename.display())
                })?;
                Ok(bytes)
            })
            .collect::<Result<Vec<Vec<u8>>>>()?;

        let elf_files = file_bytes
            .iter()
            .map(|bytes| -> Result<ElfFile64> { Ok(ElfFile64::parse(bytes.as_slice())?) })
            .collect::<Result<Vec<_>>>()?;

        let layouts = config
            .filenames()
            .map(|p| LayoutAndFiles::from_base_path(p))
            .collect::<Result<Vec<_>>>()?;

        let objects = elf_files
            .iter()
            .zip(display_names)
            .zip(config.filenames())
            .zip(&layouts)
            .map(|(((elf_file, name), path), layout)| -> Result<Object> {
                Object::new(elf_file, name, path.clone(), layout.as_ref())
            })
            .collect::<Result<Vec<_>>>()?;

        let mut report = Report {
            names: objects.iter().map(|o| o.name.clone()).collect(),
            paths: objects.iter().map(|o| o.path.clone()).collect(),
            diffs: Default::default(),
            config,
        };
        report.run_on_objects(&objects);
        Ok(report)
    }

    fn run_on_objects(&mut self, objects: &[Object]) {
        validate_objects(self, objects, ".gnu.hash", gnu_hash::check_object);
        validate_objects(self, objects, "index", asm_diff::validate_indexes);
        validate_objects(self, objects, ".got.plt", asm_diff::validate_got_plt);
        validate_objects(self, objects, ".symtab", symtab::validate_debug);
        validate_objects(self, objects, ".dynsym", symtab::validate_dynamic);
        header_diff::check_dynamic_headers(self, objects);
        header_diff::check_file_headers(self, objects);
        asm_diff::report_function_diffs(self, objects);
        header_diff::report_section_diffs(self, objects);
        eh_frame_diff::report_diffs(self, objects);
    }

    fn add_diff(&mut self, diff: Diff) {
        if self.should_ignore(&diff.key) {
            return;
        }
        self.diffs.push(diff);
    }

    fn add_diffs(&mut self, new_diffs: Vec<Diff>) {
        for diff in new_diffs {
            self.add_diff(diff)
        }
    }

    pub fn has_problems(&self) -> bool {
        !self.diffs.is_empty()
    }

    fn should_ignore(&self, key: &str) -> bool {
        if !self.config.only.is_empty() {
            return !self.config.only.iter().any(|i| {
                if let Some(prefix) = i.strip_suffix('*') {
                    key.starts_with(prefix)
                } else {
                    key == *i
                }
            });
        }
        self.config.ignore.iter().any(|i| {
            if let Some(prefix) = i.strip_suffix('*') {
                key.starts_with(prefix)
            } else {
                key == *i
            }
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct RelativeRelocation {
    file_offset: usize,
    value: u64,
}

fn apply_relocations(file_bytes: &mut [u8]) -> Result {
    let relocations = file_relative_relocations(file_bytes)?;
    for rel in relocations {
        if rel.file_offset + 8 >= file_bytes.len() {
            bail!(
                "Relocation at offset 0x{:x} outside of file bounds ..0x{:x}",
                rel.file_offset,
                file_bytes.len()
            );
        }
        file_bytes[rel.file_offset..rel.file_offset + 8].copy_from_slice(&rel.value.to_le_bytes());
    }
    Ok(())
}

fn file_relative_relocations(file_bytes: &[u8]) -> Result<Vec<RelativeRelocation>> {
    let file = ElfFile64::parse(file_bytes)?;
    let load_segments = LoadSegments::new(&file);
    let Some(relocations) = file.dynamic_relocations() else {
        return Ok(Vec::new());
    };
    Ok(relocations
        .filter_map(|(offset, rel)| {
            let RelocationFlags::Elf { r_type } = rel.flags() else {
                unreachable!()
            };
            if r_type != object::elf::R_X86_64_RELATIVE {
                return None;
            }
            load_segments
                .file_offset_from_address(offset)
                .map(|file_offset| RelativeRelocation {
                    file_offset,
                    // We unconditionally apply the default load offset because the only
                    // circumstance in which the load offset isn't the default is if the file isn't
                    // relocatable, in which case we shouldn't have any dynamic relocations.
                    value: rel.addend() as u64 + asm_diff::DEFAULT_LOAD_OFFSET,
                })
        })
        .collect())
}

struct LoadSegment {
    mem_range: Range<u64>,
    file_range: Range<usize>,
}

struct LoadSegments {
    segments: Vec<LoadSegment>,
}

impl LoadSegments {
    fn new(elf_file: &ElfFile64) -> Self {
        let segments = elf_file
            .elf_program_headers()
            .iter()
            .filter_map(|raw_seg| {
                let e = LittleEndian;
                if raw_seg.p_type(e) != object::elf::PT_LOAD {
                    return None;
                }
                let seg_address = raw_seg.p_paddr(e);
                let seg_len = raw_seg.p_memsz(e);
                let seg_end = seg_address + seg_len;
                let file_start = raw_seg.p_offset(e) as usize;
                let file_size = raw_seg.p_filesz(e) as usize;
                let file_end = file_start + file_size;
                let mem_range = seg_address..seg_end;
                let file_range = file_start..file_end;
                Some(LoadSegment {
                    mem_range,
                    file_range,
                })
            })
            .collect();
        LoadSegments { segments }
    }

    fn file_offset_from_address(&self, address: u64) -> Option<usize> {
        for seg in &self.segments {
            if seg.mem_range.contains(&address) {
                let file_offset = (address - seg.mem_range.start) as usize + seg.file_range.start;
                if seg.file_range.contains(&file_offset) {
                    return Some(file_offset);
                }
            }
        }
        None
    }
}

struct Diff {
    key: String,
    values: DiffValues,
}

enum DiffValues {
    PerObject(Vec<String>),
    PreFormatted(String),
}

impl Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (name, path) in self.names.iter().zip(&self.paths) {
            writeln!(f, "{name}: {}", path.display())?;
        }
        for diff in &self.diffs {
            writeln!(f, "{}", diff.key)?;
            match &diff.values {
                DiffValues::PerObject(values) => {
                    for (filename, result) in self.names.iter().zip(values) {
                        writeln!(f, "  {filename} {result}")?;
                    }
                }
                DiffValues::PreFormatted(values) => {
                    for line in values.lines() {
                        writeln!(f, "  {line}")?;
                    }
                }
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

impl Display for Object<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.name.fmt(f)
    }
}

fn short_file_display_names(config: &Config) -> Result<Vec<String>> {
    let paths: Vec<&PathBuf> = config.filenames().collect();
    if !config.display_names.is_empty() {
        if config.display_names.len() != paths.len() {
            bail!(
                "--display-names has {} names, but {} filenames were provided",
                config.display_names.len(),
                paths.len()
            );
        }
        return Ok(config.display_names.clone());
    }
    if paths.is_empty() {
        return Ok(vec![]);
    }
    let mut names = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect_vec();
    if names.iter().all(|name| name.ends_with(".so")) {
        names = names
            .into_iter()
            .map(|n| n.strip_suffix(".so").unwrap().to_owned())
            .collect();
    }
    // This is not quite right, since we might split in the middle of a multibyte character.
    // But this is a dev tool, so we'll punt on that for now.
    let mut iterators = names.iter().map(|n| n.bytes()).collect_vec();
    let mut n = 0;
    while first_equals_all(iterators.iter_mut().map(|i| i.next())) {
        n += 1;
    }
    names = names
        .iter()
        .map(|name| String::from_utf8_lossy(&name.bytes().skip(n).collect_vec()).into_owned())
        .collect_vec();
    Ok(names)
}

fn first_equals_all<T: PartialEq>(mut inputs: impl Iterator<Item = T>) -> bool {
    let Some(first) = inputs.next() else {
        return true;
    };
    for next in inputs {
        if next != first {
            return false;
        }
    }
    true
}

/// Returns whether the first input is equal to at least one of the remaining values.
fn first_equals_any<T: PartialEq>(mut inputs: impl Iterator<Item = T>) -> bool {
    let Some(first) = inputs.next() else {
        return true;
    };
    for next in inputs {
        if next == first {
            return true;
        }
    }
    false
}

impl<'data> NameIndex<'data> {
    fn new(elf_file: &ElfFile64<'data>) -> NameIndex<'data> {
        let mut globals_by_name: HashMap<&[u8], Vec<object::SymbolIndex>> = HashMap::new();
        let mut locals_by_name: HashMap<&[u8], Vec<object::SymbolIndex>> = HashMap::new();
        for sym in elf_file.symbols() {
            if !sym.is_definition() {
                continue;
            }
            if let Ok(name) = sym.name_bytes() {
                if sym.is_global() {
                    globals_by_name.entry(name).or_default().push(sym.index());
                } else {
                    locals_by_name.entry(name).or_default().push(sym.index());
                }
            }
        }
        NameIndex {
            globals_by_name,
            locals_by_name,
        }
    }
}

fn slice_from_all_bytes<T: object::Pod>(data: &[u8]) -> &[T] {
    object::slice_from_bytes(data, data.len() / core::mem::size_of::<T>())
        .unwrap()
        .0
}

fn parse_string_equality(
    s: &str,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let (a, b) = s
        .split_once('=')
        .ok_or_else(|| format!("invalid key-value pair. No '=' found in `{s}`"))?;
    Ok((a.to_owned(), b.to_owned()))
}
