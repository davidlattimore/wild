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
use clap::ValueEnum;
use itertools::Itertools as _;
#[allow(clippy::wildcard_imports)]
use linker_utils::elf::secnames::*;
use object::read::elf::ElfSection64;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection;
use object::ObjectSymbol as _;
use section_map::IndexedLayout;
use section_map::LayoutAndFiles;
use std::collections::HashMap;
use std::fmt::Display;
use std::path::Path;
use std::path::PathBuf;

mod arch;
mod asm_diff;
mod debug_info_diff;
mod diagnostics;
mod eh_frame_diff;
mod gnu_hash;
mod header_diff;
pub(crate) mod section_map;
mod symtab;
mod trace;
mod x86_64;

type Result<T = (), E = anyhow::Error> = core::result::Result<T, E>;
type ElfFile64<'data> = object::read::elf::ElfFile64<'data, LittleEndian>;
type ElfSymbol64<'data, 'file> = object::read::elf::ElfSymbol64<'data, 'file, LittleEndian>;

pub use diagnostics::enable_diagnostics;

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

    #[arg(long, alias = "color", default_value = "auto")]
    pub colour: Colour,

    /// Primary file that we're validating against the reference file(s)
    pub file: PathBuf,
}

#[derive(ValueEnum, Copy, Clone, Default)]
pub enum Colour {
    #[default]
    Auto,
    Never,
    Always,
}

/// An output binary such as an executable or shared object.
pub struct Binary<'data> {
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
    #[must_use]
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
                "section.note.gnu.build-id",
                "section.note.gnu.property",
                "section.note.stapsdt",
                "section.hash",
                // We set this to 8. GNU ld sometimes does too, but sometimes to 0.
                "section.got.entsize",
                "section.plt.got.entsize",
                "section.plt.entsize",
                // GNU ld sometimes sets this differently that we do.
                "section.plt",
                "section.plt.alignment",
                "section.bss.alignment",
                "section.gnu.build.attributes",
                "section.annobin.notes.entsize",
                // We currently output version info when linking against the interpreter
                // (ld-linux-x86-64.so.2). GNU ld doesn't.
                ".dynamic.DT_VERNEEDNUM",
                // We currently handle these dynamic tags differently
                ".dynamic.DT_JMPREL",
                ".dynamic.DT_PLTGOT",
                ".dynamic.DT_PLTREL",
                // We currently produce a .got.plt whenever we produce .plt, but GNU ld doesn't
                "section.got.plt",
                GOT_PLT_SECTION_NAME_STR,
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
                // A package note section used by Ubuntu: https://systemd.io/ELF_PACKAGE_METADATA/
                "section.note.package",
                // TLSDESC relaxations aren't yet implemented.
                "rel.match_failed.R_X86_64_GOTPC32_TLSDESC",
                "rel.missing-opt.R_X86_64_TLSDESC_CALL.SkipTlsDescCall.*",
                // Wild eliminates GOTPCRELX in statically linked executables even for undefined
                // symbols, whereas other linkers don't. This is a valid optimisation that other
                // linkers don't currently do.
                "rel.extra-opt.R_X86_64_GOTPCRELX.CallIndirectToRelative.static-*",
                // We don't yet support emitting warnings.
                "section.gnu.warning",
            ]
            .into_iter()
            .map(ToOwned::to_owned),
        );

        #[cfg(target_arch = "aarch64")]
        {
            self.ignore.extend(
                [
                    // Other linkers have a bigger initial PLT entry, thus the entsize is set to zero:
                    // https://sourceware.org/bugzilla/show_bug.cgi?id=26312
                    "section.plt.entsize",
                ]
                .into_iter()
                .map(ToOwned::to_owned),
            );
        }

        self.equiv.push((
            GOT_SECTION_NAME_STR.to_owned(),
            GOT_PLT_SECTION_NAME_STR.to_owned(),
        ));
        // We don't currently define .plt.got and .plt.sec, we just put everything into .plt.
        self.equiv.push((
            PLT_SECTION_NAME_STR.to_owned(),
            PLT_GOT_SECTION_NAME_STR.to_owned(),
        ));
        self.equiv.push((
            PLT_SECTION_NAME_STR.to_owned(),
            PLT_SEC_SECTION_NAME_STR.to_owned(),
        ));
    }

    #[must_use]
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

impl<'data> Binary<'data> {
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
            name,
            elf_file,
            path,
            address_index,
            name_index: NameIndex::new(elf_file),
            indexed_layout,
            trace,
            sections_by_name,
        })
    }

    /// Looks up a symbol, first trying to get a global, or failing that a local. If multiple
    /// symbols have the same name, then `hint_address` is used to select which one to return.
    pub(crate) fn symbol_by_name(&self, name: &[u8], hint_address: u64) -> NameLookupResult {
        match self.lookup_symbol(&self.name_index.globals_by_name, name, hint_address) {
            NameLookupResult::Undefined => {
                self.lookup_symbol(&self.name_index.locals_by_name, name, hint_address)
            }
            other => other,
        }
    }

    fn lookup_symbol(
        &self,
        symbol_map: &HashMap<&[u8], Vec<object::SymbolIndex>>,
        name: &[u8],
        hint_address: u64,
    ) -> NameLookupResult {
        let indexes = symbol_map.get(name).map(Vec::as_slice).unwrap_or_default();

        if indexes.len() >= 2 {
            for sym_index in indexes {
                if let Ok(sym) = self.elf_file.symbol_by_index(*sym_index) {
                    if sym.address() == hint_address {
                        return NameLookupResult::Defined(sym);
                    }
                }
            }

            // We didn't find a symbol with exactly the address hinted at.
            return NameLookupResult::Duplicate;
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

    fn section_by_name(&self, name: &str) -> Option<ElfSection64<LittleEndian>> {
        self.section_by_name_bytes(name.as_bytes())
    }

    fn section_by_name_bytes(&self, name: &[u8]) -> Option<ElfSection64<LittleEndian>> {
        let index = self.sections_by_name.get(name)?.index;
        self.elf_file.section_by_index(index).ok()
    }

    /// Returns the name of the section that contains the supplied address. Does a linear scan, so
    /// should only be used for error reporting.
    fn section_containing_address(&self, address: u64) -> Option<&str> {
        self.elf_file
            .sections()
            .find(|sec| (sec.address()..sec.address() + sec.size()).contains(&address))
            .and_then(|sec| sec.name().ok())
    }
}

#[derive(Debug)]
enum NameLookupResult<'data, 'file> {
    Undefined,
    Duplicate,
    Defined(ElfSymbol64<'data, 'file>),
}

fn validate_objects(
    report: &mut Report,
    objects: &[Binary],
    validation_name: &str,
    validation_fn: impl Fn(&Binary) -> Result,
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
    });
}

pub struct Report {
    names: Vec<String>,
    paths: Vec<PathBuf>,
    diffs: Vec<Diff>,
    config: Config,
}

impl Report {
    pub fn from_config(mut config: Config) -> Result<Report> {
        // This changes mutable global state, which isn't an ideal thing to be doing from a library.
        // It's expedient though, and we don't really expect linker-diff to get used as a library
        // anywhere except the linker-diff binary and wild's integration tests, so this probably
        // isn't a big deal.
        match config.colour {
            Colour::Auto => colored::control::unset_override(),
            Colour::Never => colored::control::set_override(false),
            Colour::Always => colored::control::set_override(true),
        }

        if config.wild_defaults {
            config.apply_wild_defaults();
        }
        let display_names = short_file_display_names(&config)?;

        let file_bytes = config
            .filenames()
            .map(|filename| -> Result<Vec<u8>> {
                let bytes = std::fs::read(filename)
                    .with_context(|| format!("Failed to read `{}`", filename.display()))?;
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
            .map(|(((elf_file, name), path), layout)| -> Result<Binary> {
                Binary::new(elf_file, name, path.clone(), layout.as_ref())
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

    fn run_on_objects(&mut self, objects: &[Binary]) {
        validate_objects(
            self,
            objects,
            GNU_HASH_SECTION_NAME_STR,
            gnu_hash::check_object,
        );
        validate_objects(self, objects, "index", asm_diff::validate_indexes);
        validate_objects(
            self,
            objects,
            GOT_PLT_SECTION_NAME_STR,
            asm_diff::validate_got_plt,
        );
        validate_objects(
            self,
            objects,
            SYMTAB_SECTION_NAME_STR,
            symtab::validate_debug,
        );
        validate_objects(
            self,
            objects,
            DYNSYM_SECTION_NAME_STR,
            symtab::validate_dynamic,
        );
        header_diff::check_dynamic_headers(self, objects);
        header_diff::check_file_headers(self, objects);
        asm_diff::report_section_diffs(self, objects);
        header_diff::report_section_diffs(self, objects);
        eh_frame_diff::report_diffs(self, objects);
        debug_info_diff::check_debug_info(self, objects);
    }

    fn add_diff(&mut self, diff: Diff) {
        if self.should_ignore(&diff.key) {
            return;
        }
        self.diffs.push(diff);
    }

    fn add_diffs(&mut self, new_diffs: Vec<Diff>) {
        for diff in new_diffs {
            self.add_diff(diff);
        }
    }

    #[must_use]
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

    fn add_error(&mut self, error: impl Into<String>) {
        self.diffs.push(Diff {
            key: "error".to_owned(),
            values: DiffValues::PreFormatted(error.into()),
        });
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

impl Display for Binary<'_> {
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
    if names.iter().all(|name| {
        Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("so"))
    }) {
        names = names
            .into_iter()
            .map(|n| n.strip_suffix(".so").unwrap().to_owned())
            .collect();
    }

    if names.len() > 1 {
        // This is not quite right, since we might split in the middle of a multibyte character.
        // But this is a dev tool, so we'll punt on that for now.
        let mut iterators = names.iter().map(|n| n.bytes()).collect_vec();
        let mut n = 0;
        while first_equals_all(iterators.iter_mut().map(Iterator::next)) {
            n += 1;
        }
        names = names
            .iter()
            .map(|name| String::from_utf8_lossy(&name.bytes().skip(n).collect_vec()).into_owned())
            .collect_vec();
    }
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
            // We only index symbols that have a section. Note this is different than the object
            // crate's `is_defined`, which imposes additional requirements that we don't want.
            if sym.section_index().is_none() {
                continue;
            }

            if let Ok(mut name) = sym.name_bytes() {
                // Wild doesn't emit local symbols that start with ".L". The other linkers mostly do
                // the same. However, GNU ld and lld, if they encounter a GOT-forming relocation to
                // such a symbol, even if they then optimise away the GOT-forming relocation, will
                // emit the symbol. This behaviour seems weird and not worth replicating, so we just
                // ignore all just symbols.
                if name.starts_with(b".L") {
                    continue;
                }

                // GNU ld sometimes emits symbols that contain the symbol version. This causes
                // problems when we go to look those symbols up, since they no longer match the name
                // of the symbol in the original input file. So for now at least, we get rid of the
                // version.
                if let Some(at_pos) = name.iter().position(|b| *b == b'@') {
                    name = &name[..at_pos];
                }

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
    object::slice_from_bytes(data, data.len() / size_of::<T>())
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
