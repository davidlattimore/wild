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

use anyhow::Context as _;
use anyhow::bail;
use asm_diff::AddressIndex;
use clap::Parser;
use clap::ValueEnum;
use hashbrown::HashMap;
use itertools::Itertools as _;
#[allow(clippy::wildcard_imports)]
use linker_utils::elf::secnames::*;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection;
use object::ObjectSymbol as _;
use object::read::elf::ElfSection64;
use section_map::IndexedLayout;
use section_map::LayoutAndFiles;
use std::fmt::Display;
use std::path::Path;
use std::path::PathBuf;

mod aarch64;
mod arch;
mod asm_diff;
mod debug_info_diff;
mod diagnostics;
mod eh_frame_diff;
mod gnu_hash;
mod header_diff;
mod init_order;
mod riscv64;
pub(crate) mod section_map;
mod segment;
mod symbol_diff;
mod symtab;
mod trace;
mod utils;
mod version_diff;
mod x86_64;

type Result<T = (), E = anyhow::Error> = core::result::Result<T, E>;
type ElfFile64<'data> = object::read::elf::ElfFile64<'data, LittleEndian>;
type ElfSymbol64<'data, 'file> = object::read::elf::ElfSymbol64<'data, 'file, LittleEndian>;

use arch::Arch;
use arch::ArchKind;
use colored::Colorize;
pub use diagnostics::enable_diagnostics;
use section_map::InputSectionId;
use section_map::OwnedFileIdentifier;

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

    /// Print information about what sections did and didn't get diffed.
    #[arg(long)]
    pub coverage: bool,

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
    dynamic_by_name: HashMap<&'data [u8], Vec<object::SymbolIndex>>,
}

impl Config {
    #[must_use]
    pub fn from_env() -> Self {
        Self::parse()
    }

    fn apply_wild_defaults(&mut self, arch: ArchKind) {
        self.ignore.extend(
            [
                // We don't currently support allocating space except in sections, so we have sections
                // to hold the section and program headers. We then need to ignore them because GNU ld
                // doesn't define such sections.
                "section.shdr",
                "section.phdr",
                // We don't yet support these sections.
                "section.data.rel.ro",
                "section.stapsdt.base",
                "section.note.gnu.build-id",
                "section.note.gnu.property",
                "section.note.stapsdt",
                "section.hash",
                "section.sframe",
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
                // We don't yet group .lrodata sections separately.
                "section.lrodata",
                // We sometimes eliminate __tls_get_addr where GNU ld doesn't. This can mean that we
                // have no versioned symbols for ld-linux-x86-64.so.2 or equivalent, which means we
                // end up with one less version record.
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
                // aarch64-linux-gnu-ld on arch linux emits DT_BIND_NOW instead of DT_FLAGS.BIND_NOW
                ".dynamic.DT_BIND_NOW",
                ".dynamic.DT_FLAGS.BIND_NOW",
                // TODO: Implement proper ordering of .init .ctors etc
                "init_array",
                "fini_array",
                // When GNU ld encounters a GOT-forming reference to an ifunc, it generates a
                // canonical PLT entry and points the GOT at that. This means that it ends up with
                // GOT->PLT->GOT. We don't as yet support doing this.
                "rel.missing-got-plt-got",
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
                // GNU ld sometimes applies relaxations that we don't yet.
                "rel.match_failed.R_AARCH64_TLSDESC_LD64_LO12",
                "rel.match_failed.R_AARCH64_TLSGD_ADD_LO12_NC",
                "rel.missing-opt.R_X86_64_TLSGD.TlsGdToInitialExec.shared-object",
                // GNU ld sometimes relaxes an adrp instruction to an adr instruction when the
                // address is known and within +/-1MB. We don't as yet.
                "rel.missing-opt.R_AARCH64_ADR_GOT_PAGE.AdrpToAdr.*",
                "rel.missing-opt.R_AARCH64_ADR_PREL_PG_HI21.AdrpToAdr.*",
                "rel.extra-opt.R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21.MovzXnLsl16.*",
                // The other linkers set properties on sections if all input sections have that
                // property. For sections like .rodata, this seems like an unimportant behaviour to
                // replicate.
                "section.rodata.entsize",
                "section.rodata.flags",
                // We emit dynamic relocations for direct references to undefined weak symbols that
                // might be provided at runtime as well as GOT entries for indirect references. GNU
                // ld and lld only emit the GOT entries and leave direct references as null. Our
                // behaviour seems more consistent with the description of
                // `-zdynamic-undefined-weak`.
                "rel.undefined-weak.dynamic.R_X86_64_64",
                "rel.undefined-weak.dynamic.R_AARCH64_ABS64",
                // On aarch64, GNU ld, at least sometimes, converts R_AARCH64_ABS64 to a PLT-forming
                // relocation. We at present, don't.
                "rel.dynamic-plt-bypass",
                // If we don't optimise a TLS access, then we'll have references to __tls_get_addr,
                // when GNU ld doesn't.
                "dynsym.__tls_get_addr.*",
                // GNU ld emits two segments, whereas wild emits only a single segment.
                "segment.LOAD.R.*",
                // We haven't provided an implementation that is compatible with existing linkers.
                "segment.PT_NOTE.*",
                "segment.PT_INTERP.*",
                "segment.PT_PHDR.*",
                "segment.PT_GNU_RELRO.*",
                "segment.PT_GNU_STACK.*",
                "segment.PT_GNU_PROPERTY.*",
                "segment.PT_GNU_SFRAME.*",
                // TODO: RISC-V
                "segment.LOAD.RW.alignment",
            ]
            .into_iter()
            .map(ToOwned::to_owned),
        );

        match arch {
            ArchKind::Aarch64 => self.ignore.extend(
                [
                    // Other linkers have a bigger initial PLT entry, thus the entsize is set to zero:
                    // https://sourceware.org/bugzilla/show_bug.cgi?id=26312
                    "section.plt.entsize",
                    // On Alpine Linux, aarch64, GNU ld seems to emit the _DYNAMIC symbol without a
                    // section index instead of pointing it at the .dynamic section.
                    "rel.extra-symbol._DYNAMIC",
                    // Also on Alpine Linux, aarch64, it seems that GNU ld is emitting an
                    // unnecessary GLOB_DAT relocation in a GOT entry.
                    "rel.missing-got-dynamic.executable",
                ]
                .into_iter()
                .map(ToOwned::to_owned),
            ),
            ArchKind::RISCV64 => self.ignore.extend(
                [
                    // TODO: for some reason, main is put into .dynsym
                    "dynsym.main.section",
                    // GOT entries may differ due to unimplemented relaxations
                    "section.got.*",
                    // Dynamic relocations may differ
                    "rel.dynamic.*",
                    "rel.undefined-weak.*",
                    // Symbol address inconsistencies due to different optimizations
                    "error.*",
                    "section-diff-failed*",
                ]
                .into_iter()
                .map(ToOwned::to_owned),
            ),
            ArchKind::X86_64 => {}
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
    pub(crate) fn symbol_by_name<'file: 'data>(
        &'file self,
        name: &[u8],
        hint_address: u64,
    ) -> NameLookupResult<'data, 'file> {
        match self.lookup_symbol(&self.name_index.globals_by_name, name, hint_address) {
            NameLookupResult::Undefined => {
                self.lookup_symbol(&self.name_index.locals_by_name, name, hint_address)
            }
            other => other,
        }
    }

    fn lookup_symbol<'file: 'data>(
        &'file self,
        symbol_map: &HashMap<&[u8], Vec<object::SymbolIndex>>,
        name: &[u8],
        hint_address: u64,
    ) -> NameLookupResult<'data, 'file> {
        let indexes = symbol_map.get(name).map(Vec::as_slice).unwrap_or_default();

        if indexes.len() >= 2 {
            for sym_index in indexes {
                if let Ok(sym) = self.elf_file.symbol_by_index(*sym_index)
                    && sym.address() == hint_address
                {
                    return NameLookupResult::Defined(sym);
                }
            }

            // We didn't find a symbol with exactly the address hinted at.
            return NameLookupResult::Duplicate;
        }

        if let Some(symbol_index) = indexes.first() {
            if let Ok(sym) = self.elf_file.symbol_by_index(*symbol_index) {
                NameLookupResult::Defined(sym)
            } else {
                NameLookupResult::Undefined
            }
        } else {
            NameLookupResult::Undefined
        }
    }

    fn section_by_name<'file: 'data>(
        &'file self,
        name: &str,
    ) -> Option<ElfSection64<'data, 'file, LittleEndian>> {
        self.section_by_name_bytes(name.as_bytes())
    }

    fn section_by_name_bytes<'file: 'data>(
        &'file self,
        name: &[u8],
    ) -> Option<ElfSection64<'data, 'file, LittleEndian>> {
        let index = self.sections_by_name.get(name)?.index;
        self.elf_file.section_by_index(index).ok()
    }

    fn section_containing_address<'file: 'data>(
        &'file self,
        address: u64,
    ) -> Option<ElfSection64<'file, 'data, LittleEndian>> {
        self.elf_file
            .sections()
            .find(|sec| (sec.address()..sec.address() + sec.size()).contains(&address))
    }

    /// Returns the name of the section that contains the supplied address. Does a linear scan, so
    /// should only be used for error reporting.
    fn section_name_containing_address(&self, address: u64) -> Option<&str> {
        self.section_containing_address(address)
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
    /// The names of each of our binaries. These should be short, not a full path, since we often
    /// prefix lines with these names.
    names: Vec<String>,

    /// The full path of each of our binaries.
    paths: Vec<PathBuf>,

    /// The differences that were detected.
    diffs: Vec<Diff>,

    /// The configuration that was used.
    config: Config,

    pub coverage: Option<Coverage>,
}

#[derive(Default)]
pub struct Coverage {
    sections: HashMap<InputSectionId, SectionCoverage>,
}

struct SectionCoverage {
    /// The original input file from which the section came.
    original_file: OwnedFileIdentifier,

    /// The name of the section.
    name: String,

    /// Whether we diffed this section at all.
    diffed: bool,

    /// The size of the section in bytes.
    num_bytes: u64,
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

        if objects.len() < 2 {
            bail!("At least two files must be provided for comparison");
        }

        let arch = ArchKind::from_objects(&objects)?;

        if config.wild_defaults {
            config.apply_wild_defaults(arch);
        }

        let mut report = Report {
            names: objects.iter().map(|o| o.name.clone()).collect(),
            paths: objects.iter().map(|o| o.path.clone()).collect(),
            diffs: Default::default(),
            coverage: config.coverage.then(Coverage::default),
            config,
        };

        report.run_on_objects(&objects, arch);

        Ok(report)
    }

    fn run_on_objects(&mut self, objects: &[Binary], arch: ArchKind) {
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
        header_diff::report_section_diffs(self, objects);
        eh_frame_diff::report_diffs(self, objects);
        version_diff::report_diffs(self, objects);
        debug_info_diff::check_debug_info(self, objects);
        symbol_diff::report_diffs(self, objects);
        segment::report_diffs(self, objects);

        match arch {
            ArchKind::X86_64 => {
                self.report_arch_specific_diffs::<crate::x86_64::X86_64>(objects);
            }
            ArchKind::Aarch64 => {
                self.report_arch_specific_diffs::<crate::aarch64::AArch64>(objects);
            }

            ArchKind::RISCV64 => {
                self.report_arch_specific_diffs::<crate::riscv64::RiscV64>(objects);
            }
        }
    }

    fn report_arch_specific_diffs<A: Arch>(&mut self, binaries: &[Binary]) {
        asm_diff::report_section_diffs::<A>(self, binaries);
        init_order::report_diffs::<A>(self, binaries);
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

    #[must_use]
    pub fn should_ignore(&self, key: &str) -> bool {
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

impl Display for Coverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Diffed sections:")?;

        let mut total_bytes = 0;
        let mut total_diffed = 0;

        for sec in self.sections.values() {
            writeln!(
                f,
                "  {} {}: {}",
                sec.original_file,
                sec.name,
                if sec.diffed {
                    "true".green()
                } else {
                    "false".red()
                }
            )?;

            if sec.diffed {
                total_diffed += sec.num_bytes;
            }

            total_bytes += sec.num_bytes;
        }

        writeln!(
            f,
            "Diffed {total_diffed} of {total_bytes} section bytes ({}%)",
            total_diffed * 100 / total_bytes
        )?;

        Ok(())
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
        let mut dynamic_by_name: HashMap<&[u8], Vec<object::SymbolIndex>> = HashMap::new();

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

        for sym in elf_file.dynamic_symbols() {
            if let Ok(name) = sym.name_bytes() {
                dynamic_by_name.entry(name).or_default().push(sym.index());
            }
        }

        NameIndex {
            globals_by_name,
            locals_by_name,
            dynamic_by_name,
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

fn get_r_type<R: arch::RType>(rel: &object::Relocation) -> R {
    let object::RelocationFlags::Elf { r_type } = rel.flags() else {
        panic!("Unsupported object type (relocation flags)");
    };
    R::from_raw(r_type)
}
