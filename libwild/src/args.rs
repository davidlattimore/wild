//! A handwritten parser for our arguments.
//!
//! We don't currently use a 3rd party library like clap for a few reasons. Firstly, we need to
//! support flags like `--push-state` and `--pop-state`. These need to push and pop a state stack
//! when they're parsed. Some of the other flags then need to manipulate the state of the top of the
//! stack. Positional arguments like input files and libraries to link, then need to have the
//! current state of the stack attached to that file.
//!
//! Secondly, long arguments need to also be accepted with a single '-' in addition to the more
//! common double-dash.
//!
//! Basically, we need to be able to parse arguments in the same way as the other linkers on the
//! platform that we're targeting.

pub(crate) mod consts;
pub(crate) mod linux;
pub(crate) mod windows;

pub(crate) use consts::*;
use target_lexicon::BinaryFormat;

use crate::alignment::Alignment;
use crate::arch::Architecture;
use crate::bail;
use crate::error::Context as _;
use crate::error::Result;
use crate::input_data::FileId;
use crate::save_dir::SaveDir;
use hashbrown::HashMap;
use hashbrown::HashSet;
use jobserver::Acquired;
use jobserver::Client;
use std::fmt::Display;
use std::num::NonZeroUsize;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use target_lexicon::Triple;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VersionMode {
    /// Don't print version
    None,
    /// Print version and continue linking (-v)
    Verbose,
    /// Print version and exit immediately (--version)
    ExitAfterPrint,
}

#[derive(Debug)]
pub(crate) enum DefsymValue {
    /// A numeric value (address)
    Value(u64),
    /// Reference to another symbol with an optional offset
    SymbolWithOffset(String, i64),
}

/// Parsed linker arguments. Common fields are directly accessible.
/// Format-specific fields are accessible via `Deref`/`DerefMut` through `target_args`.
///
/// `T` defaults to `TargetArgs` (the enum). During parsing, `T` is set to the
/// concrete format type (e.g. `ElfArgs` or `PeArgs`).
#[derive(Debug)]
pub struct Args<T = TargetArgs> {
    // ── Infrastructure ───────────────────────────────────────────────────────
    pub should_fork: bool,
    pub(crate) output: Arc<Path>,
    pub(crate) arch: Architecture,
    pub(crate) inputs: Vec<Input>,
    pub(crate) lib_search_path: Vec<Box<Path>>,
    pub num_threads: Option<NonZeroUsize>,
    pub(crate) available_threads: NonZeroUsize,
    pub(crate) save_dir: SaveDir,
    pub(crate) unrecognized_options: Vec<String>,
    pub(crate) files_per_group: Option<u32>,
    pub(crate) write_layout: bool,
    pub(crate) write_trace: bool,
    pub(crate) jobserver_client: Option<Client>,

    // ── Core linker behavior ─────────────────────────────────────────────────
    pub(crate) strip: Strip,
    pub(crate) gc_sections: bool,
    pub(crate) merge_sections: bool,
    pub(crate) relax: bool,
    pub(crate) demangle: bool,
    pub(crate) no_undefined: bool,
    pub(crate) allow_shlib_undefined: bool,
    pub(crate) error_unresolved_symbols: bool,
    pub(crate) allow_multiple_definitions: bool,
    pub(crate) unresolved_symbols: UnresolvedSymbols,
    pub(crate) undefined: Vec<String>,
    pub(crate) copy_relocations: CopyRelocations,
    pub(crate) sysroot: Option<Box<Path>>,
    pub(crate) dynamic_linker: Option<Box<Path>>,
    pub(crate) entry: Option<String>,
    pub(crate) wrap: Vec<String>,
    pub(crate) exclude_libs: ExcludeLibs,
    pub(crate) b_symbolic: BSymbolicKind,
    pub(crate) export_list: Vec<String>,
    pub(crate) defsym: Vec<(String, DefsymValue)>,
    pub(crate) section_start: HashMap<String, u64>,
    pub(crate) max_page_size: Option<Alignment>,
    pub(crate) execstack: bool,
    pub(crate) version_mode: VersionMode,
    pub(crate) relocation_model: RelocationModel,
    pub(crate) should_output_executable: bool,
    pub(crate) export_all_dynamic_symbols: bool,
    pub(crate) version_script_path: Option<PathBuf>,
    pub(crate) export_list_path: Option<PathBuf>,

    // ── Output/writing ───────────────────────────────────────────────────────
    pub(crate) mmap_output_file: bool,
    pub(crate) file_write_mode: Option<FileWriteMode>,
    pub(crate) prepopulate_maps: bool,
    pub(crate) should_write_linker_identity: bool,

    // ── Debug/diagnostic ─────────────────────────────────────────────────────
    pub(crate) debug_fuel: Option<AtomicI64>,
    pub(crate) validate_output: bool,
    pub(crate) sym_info: Option<String>,
    pub(crate) debug_address: Option<u64>,
    pub(crate) print_allocations: Option<FileId>,
    pub(crate) verify_allocation_consistency: bool,
    pub(crate) time_phase_options: Option<Vec<CounterKind>>,
    pub(crate) numeric_experiments: Vec<Option<u64>>,
    pub(crate) write_gc_stats: Option<PathBuf>,
    pub(crate) gc_stats_ignore: Vec<String>,
    pub(crate) verbose_gc_stats: bool,
    pub(crate) dependency_file: Option<PathBuf>,

    // ── Format-specific ──────────────────────────────────────────────────────
    pub target_args: T,
}

#[derive(Debug)]
pub(crate) enum Strip {
    Nothing,
    Debug,
    All,
    Retain(HashSet<Vec<u8>>),
}

#[derive(Debug, Clone, Copy)]
pub enum CounterKind {
    Cycles,
    Instructions,
    CacheMisses,
    BranchMisses,
    PageFaults,
    PageFaultsMinor,
    PageFaultsMajor,
    L1dRead,
    L1dMiss,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CopyRelocations {
    Allowed,
    Disallowed(CopyRelocationsDisabledReason),
}

/// Represents a command-line argument that specifies the number of threads to use,
/// triggering activation of the thread pool.
pub struct ActivatedArgs<T = TargetArgs> {
    pub args: Args<T>,
    _jobserver_tokens: Vec<Acquired>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExcludeLibs {
    None,
    All,
    Some(HashSet<Box<str>>),
}

impl ExcludeLibs {
    pub(crate) fn should_exclude(&self, lib_path: &[u8]) -> bool {
        match self {
            ExcludeLibs::None => false,
            ExcludeLibs::All => true,
            ExcludeLibs::Some(libs) => {
                let lib_path_str = String::from_utf8_lossy(lib_path);
                let lib_name = lib_path_str.rsplit('/').next().unwrap_or(&lib_path_str);

                libs.contains(lib_name)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelocationModel {
    NonRelocatable,
    Relocatable,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum Experiment {
    /// How much parallelism to allow when splitting string-merge sections.
    MergeStringSplitParallelism = 0,

    /// Number of bytes of string-merge sections before we'll break to a new group.
    MergeStringMinGroupBytes = 1,

    GroupsPerThread = 2,

    MinGroups = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileWriteMode {
    /// The existing output file, if any, will be unlinked (deleted) and a new file with the same
    /// name put in its place. Any hard links to the file will not be affected.
    UnlinkAndReplace,

    /// The existing output file, if any, will be edited in-place. Any hard links to the file will
    /// update accordingly. If the file is locked due to currently being executed, then our write
    /// will fail.
    UpdateInPlace,

    /// As for `UpdateInPlace`, but if we get an error opening the file for write, fallback to
    /// unlinking and replacing.
    UpdateInPlaceWithFallback,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct Modifiers {
    /// Whether shared objects should only be linked if they're referenced.
    pub(crate) as_needed: bool,

    /// Whether we're currently allowed to link against shared libraries.
    pub(crate) allow_shared: bool,

    /// Whether object files in archives should be linked even if they do not contain symbols that
    /// are referenced.
    pub(crate) whole_archive: bool,

    /// Whether archive semantics should be applied even for regular objects.
    pub(crate) archive_semantics: bool,

    /// Whether the file is known to be a temporary file that will be deleted when the linker
    /// exits, e.g. an output file from a linker plugin. This doesn't affect linking, but is
    /// stored in the layout file if written so that linker-diff knows not to error if the file
    /// is missing.
    pub(crate) temporary: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Input {
    pub(crate) spec: InputSpec,
    /// A directory to search first. Only present when the input came from a linker script, in
    /// which case this is the directory containing the linker script.
    pub(crate) search_first: Option<PathBuf>,
    pub(crate) modifiers: Modifiers,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum InputSpec {
    /// Path (possibly just a filename) to the file.
    File(Box<Path>),
    /// Name of the library, without prefix and suffix.
    Lib(Box<str>),
    /// Name of the library, including prefix and suffix.
    Search(Box<str>),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum BSymbolicKind {
    None,
    All,
    Functions,
    NonWeakFunctions,
    NonWeak,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum UnresolvedSymbols {
    /// Report all unresolved symbols.
    ReportAll,

    /// Ignore unresolved symbols in shared libraries.
    IgnoreInSharedLibs,

    /// Ignore unresolved symbols in object files.
    IgnoreInObjectFiles,

    /// Ignore all unresolved symbols.
    IgnoreAll,
}

impl<T: Default> Default for Args<T> {
    fn default() -> Self {
        Args {
            // Infrastructure
            should_fork: true,
            arch: const { Architecture::from_target_lexicon(target_lexicon::HOST.architecture) },
            unrecognized_options: Vec::new(),
            lib_search_path: Vec::new(),
            inputs: Vec::new(),
            output: Arc::from(Path::new("a.out")),
            num_threads: None,
            write_layout: std::env::var(WRITE_LAYOUT_ENV).is_ok_and(|v| v == "1"),
            write_trace: std::env::var(WRITE_TRACE_ENV).is_ok_and(|v| v == "1"),
            files_per_group: None,
            save_dir: Default::default(),
            jobserver_client: None,
            available_threads: NonZeroUsize::new(1).unwrap(),
            // Core linker behavior
            strip: Strip::Nothing,
            gc_sections: true,
            merge_sections: true,
            relax: true,
            demangle: true,
            no_undefined: false,
            allow_shlib_undefined: false,
            error_unresolved_symbols: true,
            allow_multiple_definitions: false,
            unresolved_symbols: UnresolvedSymbols::ReportAll,
            undefined: Vec::new(),
            copy_relocations: CopyRelocations::Allowed,
            sysroot: None,
            dynamic_linker: None,
            entry: None,
            wrap: Vec::new(),
            exclude_libs: ExcludeLibs::None,
            b_symbolic: BSymbolicKind::None,
            export_list: Vec::new(),
            defsym: Vec::new(),
            section_start: HashMap::new(),
            max_page_size: None,
            execstack: false,
            version_mode: VersionMode::None,
            relocation_model: RelocationModel::NonRelocatable,
            should_output_executable: true,
            export_all_dynamic_symbols: false,
            version_script_path: None,
            export_list_path: None,
            // Output/writing
            mmap_output_file: true,
            file_write_mode: None,
            prepopulate_maps: false,
            should_write_linker_identity: true,
            // Debug/diagnostic
            debug_fuel: None,
            validate_output: std::env::var(VALIDATE_ENV).is_ok_and(|v| v == "1"),
            sym_info: None,
            debug_address: None,
            print_allocations: std::env::var("WILD_PRINT_ALLOCATIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .map(FileId::from_encoded),
            verify_allocation_consistency: std::env::var(WRITE_VERIFY_ALLOCATIONS_ENV)
                .is_ok_and(|v| v == "1"),
            time_phase_options: None,
            numeric_experiments: Vec::new(),
            write_gc_stats: None,
            gc_stats_ignore: Vec::new(),
            verbose_gc_stats: false,
            dependency_file: None,
            // Format-specific
            target_args: T::default(),
        }
    }
}

impl Args {
    /// Parse CLI arguments. Detects target format from `--target=<triple>`, `-m`,
    /// or host default, then routes to the format-specific parser.
    pub fn parse<F: Fn() -> I, S: Into<String>, I: Iterator<Item = S>>(input: F) -> Result<Args> {
        let mut input = input().map(S::into);
        // TODO: This should be used as a fallback if no target can be detected from the arguments.
        let _executable_name = input
            .next()
            .ok_or_else(|| crate::error!("should always be at least the executable name"))?;
        let all_args = input.collect::<Vec<_>>();
        let detected = detect_target(&all_args)?;
        let filtered = filter_and_inject_target_flags(&all_args, detected.format, detected.arch);

        match detected.format {
            BinaryFormat::Elf => {
                let elf_args = linux::parse(|| filtered.iter().map(|s| s.as_str()))?;
                Ok(elf_args.map_target(TargetArgs::Elf))
            }
            BinaryFormat::Coff => {
                let pe_args = windows::parse(|| filtered.iter().map(|s| s.as_str()))?;
                Ok(pe_args.map_target(TargetArgs::Pe))
            }
            _ => bail!("unsupported binary format: {}", detected.format),
        }
    }
}

impl Default for Modifiers {
    fn default() -> Self {
        Self {
            as_needed: false,
            allow_shared: true,
            whole_archive: false,
            archive_semantics: false,
            temporary: false,
        }
    }
}

pub(crate) struct ArgumentParser<T> {
    options: HashMap<&'static str, OptionHandler<T>>,
    short_options: HashMap<&'static str, OptionHandler<T>>,
    prefix_options: HashMap<&'static str, PrefixOptionHandler<T>>,
    case_insensitive: bool,
    has_option_prefix: fn(&str) -> bool,
    strip_option: for<'a> fn(&'a str) -> Option<&'a str>,
    find_separator: fn(&str) -> Option<usize>,
}

struct OptionHandler<T> {
    help_text: &'static str,
    handler: OptionHandlerFn<T>,
    short_names: Vec<&'static str>,
}

impl<T> Clone for OptionHandler<T> {
    fn clone(&self) -> Self {
        Self {
            help_text: self.help_text,
            handler: self.handler,
            short_names: self.short_names.clone(),
        }
    }
}

struct PrefixOptionHandler<T> {
    help_text: &'static str,
    handler: fn(&mut Args<T>, &mut Vec<Modifiers>, &str) -> Result<()>,
    sub_options: HashMap<&'static str, SubOption<T>>,
}

#[allow(clippy::enum_variant_names)]
enum OptionHandlerFn<T> {
    NoParam(fn(&mut Args<T>, &mut Vec<Modifiers>) -> Result<()>),
    WithParam(fn(&mut Args<T>, &mut Vec<Modifiers>, &str) -> Result<()>),
    OptionalParam(fn(&mut Args<T>, &mut Vec<Modifiers>, Option<&str>) -> Result<()>),
}

impl<T> Clone for OptionHandlerFn<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OptionHandlerFn<T> {}

impl<T> OptionHandlerFn<T> {
    fn help_suffix_long(&self) -> &'static str {
        match self {
            OptionHandlerFn::NoParam(_) => "",
            OptionHandlerFn::WithParam(_) => "=<VALUE>",
            OptionHandlerFn::OptionalParam(_) => "[=<VALUE>]",
        }
    }

    fn help_suffix_short(&self) -> &'static str {
        match self {
            OptionHandlerFn::NoParam(_) => "",
            OptionHandlerFn::WithParam(_) => " <VALUE>",
            OptionHandlerFn::OptionalParam(_) => " [<VALUE>]",
        }
    }
}

pub(crate) struct OptionDeclaration<'a, T, S> {
    parser: &'a mut ArgumentParser<T>,
    long_names: Vec<&'static str>,
    short_names: Vec<&'static str>,
    prefixes: Vec<&'static str>,
    sub_options: HashMap<&'static str, SubOption<T>>,
    help_text: &'static str,
    _phantom: std::marker::PhantomData<S>,
}

pub struct NoParam;
pub struct WithParam;
pub struct WithOptionalParam;

enum SubOptionHandler<T> {
    /// Handler without value parameter (exact match)
    NoValue(fn(&mut Args<T>, &mut Vec<Modifiers>) -> Result<()>),
    /// Handler with value parameter (prefix match)
    WithValue(fn(&mut Args<T>, &mut Vec<Modifiers>, &str) -> Result<()>),
}

impl<T> Clone for SubOptionHandler<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for SubOptionHandler<T> {}

struct SubOption<T> {
    help: &'static str,
    handler: SubOptionHandler<T>,
}

impl<T> Clone for SubOption<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for SubOption<T> {}

impl<T> SubOption<T> {
    fn with_value(&self) -> bool {
        matches!(self.handler, SubOptionHandler::WithValue(_))
    }
}

impl<T> Default for ArgumentParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ArgumentParser<T> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            options: HashMap::new(),
            short_options: HashMap::new(),
            prefix_options: HashMap::new(),
            case_insensitive: false,
            has_option_prefix: |arg| arg.starts_with('-'),
            strip_option: |arg| arg.strip_prefix("--").or(arg.strip_prefix('-')),
            find_separator: |stripped| stripped.find('='),
        }
    }

    #[must_use]
    pub fn new_case_insensitive() -> Self {
        Self {
            options: HashMap::new(),
            short_options: HashMap::new(),
            prefix_options: HashMap::new(),
            case_insensitive: true,
            has_option_prefix: |arg| arg.starts_with('/') || arg.starts_with('-'),
            strip_option: |arg| arg.strip_prefix('/').or(arg.strip_prefix('-')),
            find_separator: |stripped| stripped.find(':'),
        }
    }

    pub fn declare(&mut self) -> OptionDeclaration<'_, T, NoParam> {
        OptionDeclaration {
            parser: self,
            long_names: Vec::new(),
            short_names: Vec::new(),
            prefixes: Vec::new(),
            sub_options: HashMap::new(),
            help_text: "",
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn declare_with_param(&mut self) -> OptionDeclaration<'_, T, WithParam> {
        OptionDeclaration {
            parser: self,
            long_names: Vec::new(),
            short_names: Vec::new(),
            prefixes: Vec::new(),
            sub_options: HashMap::new(),
            help_text: "",
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn declare_with_optional_param(&mut self) -> OptionDeclaration<'_, T, WithOptionalParam> {
        OptionDeclaration {
            parser: self,
            long_names: Vec::new(),
            short_names: Vec::new(),
            prefixes: Vec::new(),
            sub_options: HashMap::new(),
            help_text: "",
            _phantom: std::marker::PhantomData,
        }
    }

    fn get_option_handler(&self, option_name: &str) -> Option<&OptionHandler<T>> {
        if self.case_insensitive {
            if let Some(handler) = self.options.get(option_name) {
                return Some(handler);
            }
            for (key, handler) in &self.options {
                if key.eq_ignore_ascii_case(option_name) {
                    return Some(handler);
                }
            }
            None
        } else {
            self.options.get(option_name)
        }
    }

    pub(crate) fn handle_argument<S: AsRef<str>, I: Iterator<Item = S>>(
        &self,
        args: &mut Args<T>,
        modifier_stack: &mut Vec<Modifiers>,
        arg: &str,
        input: &mut I,
    ) -> Result<()> {
        // TODO @lapla-cogito standardize the interface. @file doesn't use a leading hyphen.
        // Handle `@file`option (recursively) - merging in the options contained in the file
        if let Some(path) = arg.strip_prefix('@') {
            let file_args = read_args_from_file(Path::new(path))?;
            let mut file_arg_iter = file_args.iter();
            while let Some(file_arg) = file_arg_iter.next() {
                self.handle_argument(args, modifier_stack, file_arg, &mut file_arg_iter)?;
            }
            return Ok(());
        }

        if let Some(stripped) = (self.strip_option)(arg) {
            // Check for option with separator syntax
            if let Some(eq_pos) = (self.find_separator)(stripped) {
                let option_name = &stripped[..eq_pos];
                let value = &stripped[eq_pos + 1..];

                if let Some(handler) = self.get_option_handler(option_name) {
                    match &handler.handler {
                        OptionHandlerFn::WithParam(f) => f(args, modifier_stack, value)?,
                        OptionHandlerFn::OptionalParam(f) => f(args, modifier_stack, Some(value))?,
                        OptionHandlerFn::NoParam(_) => return Ok(()),
                    }
                    return Ok(());
                }
            } else {
                if stripped == "build-id"
                    && let Some(handler) = self.get_option_handler(stripped)
                    && let OptionHandlerFn::WithParam(f) = &handler.handler
                {
                    f(args, modifier_stack, "fast")?;
                    return Ok(());
                }

                if let Some(handler) = self.get_option_handler(stripped) {
                    match &handler.handler {
                        OptionHandlerFn::NoParam(f) => f(args, modifier_stack)?,
                        OptionHandlerFn::WithParam(f) => {
                            let next_arg =
                                input.next().context(format!("Missing argument to {arg}"))?;
                            f(args, modifier_stack, next_arg.as_ref())?;
                        }
                        OptionHandlerFn::OptionalParam(f) => {
                            f(args, modifier_stack, None)?;
                        }
                    }
                    return Ok(());
                }
            }
        }

        if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1 {
            let option_name = &arg[1..];
            if let Some(handler) = self.short_options.get(option_name) {
                match &handler.handler {
                    OptionHandlerFn::NoParam(f) => f(args, modifier_stack)?,
                    OptionHandlerFn::WithParam(f) => {
                        let next_arg =
                            input.next().context(format!("Missing argument to {arg}"))?;
                        f(args, modifier_stack, next_arg.as_ref())?;
                    }
                    OptionHandlerFn::OptionalParam(f) => {
                        f(args, modifier_stack, None)?;
                    }
                }
                return Ok(());
            }
        }

        // Prefix options. These should be handled after processing long and short options,
        // because some options (like `-hashstyle=gnu`) can be misinterpreted as prefix options.
        for (prefix, handler) in &self.prefix_options {
            if let Some(rest) = arg.strip_prefix(&format!("-{prefix}")) {
                let value = if rest.is_empty() {
                    let next_arg = input
                        .next()
                        .context(format!("Missing argument to -{prefix}"))?;
                    next_arg.as_ref().to_owned()
                } else {
                    rest.to_owned()
                };

                if let Some((key, param_value)) = value.split_once('=') {
                    // Value has '=', look up key with trailing '='
                    if let Some(sub) = handler.sub_options.get(format!("{key}=").as_str()) {
                        match sub.handler {
                            SubOptionHandler::NoValue(_) => {
                                (handler.handler)(args, modifier_stack, &value)?;
                            }
                            SubOptionHandler::WithValue(f) => f(args, modifier_stack, param_value)?,
                        }
                    } else {
                        // Fall back to the main handler
                        (handler.handler)(args, modifier_stack, &value)?;
                    }
                } else {
                    // No '=' in value, look up exact match
                    if let Some(sub) = handler.sub_options.get(value.as_str()) {
                        match sub.handler {
                            SubOptionHandler::NoValue(f) => f(args, modifier_stack)?,
                            SubOptionHandler::WithValue(_) => {
                                bail!("Option -{prefix} {value} requires a value");
                            }
                        }
                    } else {
                        // Fall back to the main handler
                        (handler.handler)(args, modifier_stack, &value)?;
                    }
                }
                return Ok(());
            }
        }

        if (self.has_option_prefix)(arg) {
            if let Some(stripped) = (self.strip_option)(arg)
                && IGNORED_FLAGS.contains(&stripped)
            {
                warn_unsupported(arg)?;
                return Ok(());
            }

            args.unrecognized_options.push(arg.to_owned());
            return Ok(());
        }

        args.save_dir.handle_file(arg);
        args.inputs.push(Input {
            spec: InputSpec::File(Box::from(Path::new(arg))),
            search_first: None,
            modifiers: *modifier_stack.last().unwrap(),
        });

        Ok(())
    }

    #[must_use]
    fn generate_help(&self) -> String {
        let mut help = String::new();
        help.push_str("USAGE:\n    wild [OPTIONS] [FILES...]\n\nOPTIONS:\n");

        let mut prefix_options: Vec<_> = self.prefix_options.iter().collect();
        prefix_options.sort_by_key(|(prefix, _)| *prefix);

        // TODO: This is ad-hoc
        help.push_str(&format!(
            "    {:<31} Read options from a file\n",
            format!("@<VALUE>"),
        ));

        let mut help_to_options: HashMap<&str, Vec<String>> = HashMap::new();
        let mut processed_short_options: HashSet<&str> = HashSet::new();

        // Collect all long options and their associated short options
        for (long_name, handler) in &self.options {
            if !handler.help_text.is_empty() {
                let long_suffix = handler.handler.help_suffix_long();
                let mut option_names = vec![format!("--{long_name}{long_suffix}")];

                // Add associated short options
                let short_suffix = handler.handler.help_suffix_short();
                for short_char in &handler.short_names {
                    option_names.push(format!("-{short_char}{short_suffix}"));
                }

                help_to_options
                    .entry(handler.help_text)
                    .or_default()
                    .extend(option_names);
            }

            // Mark short options of help-less handlers as processed
            for short_name in &handler.short_names {
                processed_short_options.insert(short_name);
            }
        }

        for (prefix, handler) in prefix_options {
            if !processed_short_options.contains(prefix) && !handler.help_text.is_empty() {
                help.push_str(&format!(
                    "    -{:<30} {}\n",
                    format!("{prefix} <VALUE>"),
                    handler.help_text
                ));

                // Add sub-options if they exist
                let mut sub_options: Vec<_> = handler.sub_options.iter().collect();
                sub_options.sort_by_key(|(name, _)| *name);

                for (sub_name, sub) in sub_options {
                    let display_name = if sub.with_value() && sub_name.ends_with('=') {
                        // sub_name ends with '=' (e.g., "max-page-size="), so add <VALUE>
                        format!("{sub_name}<VALUE>")
                    } else {
                        sub_name.to_string()
                    };
                    help.push_str(&format!(
                        "      -{prefix} {display_name:<30} {sub_help}\n",
                        sub_help = sub.help
                    ));
                }
            }
        }

        // Add short-only options
        for (short_char, handler) in &self.short_options {
            if !processed_short_options.contains(short_char) && !handler.help_text.is_empty() {
                let short_suffix = handler.handler.help_suffix_short();
                help_to_options
                    .entry(handler.help_text)
                    .or_default()
                    .push(format!("-{short_char}{short_suffix}"));
            }
        }

        let mut sorted_help_groups: Vec<_> = help_to_options.into_iter().collect();
        sorted_help_groups.sort_by_key(|(_, option_names)| {
            option_names.iter().min().unwrap_or(&String::new()).clone()
        });

        for (help_text, mut option_names) in sorted_help_groups {
            option_names.sort_by(|a, b| {
                let a_is_short = a.len() == 2 && a.starts_with('-');
                let b_is_short = b.len() == 2 && b.starts_with('-');
                match (a_is_short, b_is_short) {
                    (true, false) => std::cmp::Ordering::Less, // short options first
                    (false, true) => std::cmp::Ordering::Greater, // long options after
                    _ => a.cmp(b),                             // same type, alphabetical
                }
            });

            let option_names_str = option_names.join(", ");
            help.push_str(&format!("    {option_names_str:<30} {help_text}\n"));
        }

        help
    }
}

impl<'a, T, S> OptionDeclaration<'a, T, S> {
    #[must_use]
    pub fn long(mut self, name: &'static str) -> Self {
        self.long_names.push(name);
        self
    }

    #[must_use]
    pub fn short(mut self, option: &'static str) -> Self {
        self.short_names.push(option);
        self
    }

    #[must_use]
    pub fn help(mut self, text: &'static str) -> Self {
        self.help_text = text;
        self
    }

    pub fn prefix(mut self, prefix: &'static str) -> Self {
        self.prefixes.push(prefix);
        self
    }

    #[must_use]
    pub fn sub_option(
        mut self,
        name: &'static str,
        help: &'static str,
        handler: fn(&mut Args<T>, &mut Vec<Modifiers>) -> Result<()>,
    ) -> Self {
        self.sub_options.insert(
            name,
            SubOption {
                help,
                handler: SubOptionHandler::NoValue(handler),
            },
        );
        self
    }

    #[must_use]
    pub fn sub_option_with_value(
        mut self,
        name: &'static str,
        help: &'static str,
        handler: fn(&mut Args<T>, &mut Vec<Modifiers>, &str) -> Result<()>,
    ) -> Self {
        self.sub_options.insert(
            name,
            SubOption {
                help,
                handler: SubOptionHandler::WithValue(handler),
            },
        );
        self
    }
}

impl<'a, T> OptionDeclaration<'a, T, NoParam> {
    pub fn execute(self, handler: fn(&mut Args<T>, &mut Vec<Modifiers>) -> Result<()>) {
        let option_handler = OptionHandler {
            help_text: self.help_text,
            handler: OptionHandlerFn::NoParam(handler),
            short_names: self.short_names.clone(),
        };

        for name in self.long_names {
            self.parser.options.insert(name, option_handler.clone());
        }

        for option in self.short_names {
            self.parser
                .short_options
                .insert(option, option_handler.clone());
        }
    }
}

impl<'a, T> OptionDeclaration<'a, T, WithParam> {
    pub fn execute(self, handler: fn(&mut Args<T>, &mut Vec<Modifiers>, &str) -> Result<()>) {
        let mut short_names = self.short_names.clone();
        short_names.extend_from_slice(&self.prefixes);

        let option_handler = OptionHandler {
            help_text: self.help_text,
            handler: OptionHandlerFn::WithParam(handler),
            short_names,
        };

        for name in self.long_names {
            self.parser.options.insert(name, option_handler.clone());
        }

        for option in self.short_names {
            self.parser
                .short_options
                .insert(option, option_handler.clone());
        }

        for prefix in self.prefixes {
            let prefix_handler = PrefixOptionHandler {
                help_text: self.help_text,
                sub_options: self.sub_options.clone(),
                handler,
            };

            self.parser.prefix_options.insert(prefix, prefix_handler);
        }
    }
}

impl<'a, T> OptionDeclaration<'a, T, WithOptionalParam> {
    pub fn execute(
        self,
        handler: fn(&mut Args<T>, &mut Vec<Modifiers>, Option<&str>) -> Result<()>,
    ) {
        let option_handler = OptionHandler {
            help_text: self.help_text,
            handler: OptionHandlerFn::OptionalParam(handler),
            short_names: self.short_names.clone(),
        };

        for name in self.long_names {
            self.parser.options.insert(name, option_handler.clone());
        }

        for option in self.short_names {
            self.parser
                .short_options
                .insert(option, option_handler.clone());
        }
    }
}

// ── End argument parser infrastructure ───────────────────────────────────────

pub(crate) fn add_silently_ignored_flags<T>(parser: &mut ArgumentParser<T>) {
    fn noop<U>(_args: &mut Args<U>, _modifier_stack: &mut Vec<Modifiers>) -> Result<()> {
        Ok(())
    }
    for flag in SILENTLY_IGNORED_FLAGS {
        parser.declare().long(flag).execute(noop);
    }
    for flag in SILENTLY_IGNORED_SHORT_FLAGS {
        parser.declare().short(flag).execute(noop);
    }
}

pub(crate) fn add_default_flags<T>(parser: &mut ArgumentParser<T>) {
    fn noop<U>(_args: &mut Args<U>, _modifier_stack: &mut Vec<Modifiers>) -> Result<()> {
        Ok(())
    }
    for flag in DEFAULT_FLAGS {
        parser.declare().long(flag).execute(noop);
    }
    for flag in DEFAULT_SHORT_FLAGS {
        parser.declare().short(flag).execute(noop);
    }
}

pub(crate) fn read_args_from_file(path: &Path) -> Result<Vec<String>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read arguments from file `{}`", path.display()))?;
    arguments_from_string(&contents)
}

/// Parses arguments from a string, handling quoting, escapes etc.
/// All arguments must be surrounded by a white space.
pub(crate) fn arguments_from_string(input: &str) -> Result<Vec<String>> {
    const QUOTES: [char; 2] = ['\'', '"'];

    let mut out = Vec::new();
    let mut chars = input.chars();
    let mut heap = None;
    let mut quote = None;
    let mut expect_whitespace = false;

    loop {
        let Some(mut ch) = chars.next() else {
            if let Some(quote) = quote.take() {
                bail!("Missing closing '{quote}'");
            }
            if let Some(arg) = heap.take() {
                out.push(arg);
            }
            break;
        };

        crate::ensure!(
            !expect_whitespace || ch.is_whitespace(),
            "Expected white space after quoted argument"
        );
        expect_whitespace = false;

        if QUOTES.contains(&ch) {
            if let Some(qchr) = quote {
                if qchr == ch {
                    // close the argument
                    if let Some(arg) = heap.take() {
                        out.push(arg);
                    }
                    quote = None;
                    expect_whitespace = true;
                } else {
                    // accept the other quoting character as normal char
                    heap.get_or_insert(String::new()).push(ch);
                }
            } else {
                // beginning of a new argument
                crate::ensure!(heap.is_none(), "Missing opening quote '{ch}'");
                quote = Some(ch);
            }
        } else if ch.is_whitespace() {
            if quote.is_none() {
                if let Some(arg) = heap.take() {
                    out.push(arg);
                }
            } else {
                heap.get_or_insert(String::new()).push(ch);
            }
        } else {
            if ch == '\\' && (quote.is_some() || !cfg!(target_os = "windows")) {
                ch = chars.next().context("Invalid escape")?;
            }
            heap.get_or_insert(String::new()).push(ch);
        }
    }

    Ok(out)
}

pub(super) fn warn_unsupported(opt: &str) -> Result {
    match std::env::var(WILD_UNSUPPORTED_ENV)
        .unwrap_or_default()
        .as_str()
    {
        "warn" | "" => crate::error::warning(&format!("{opt} is not yet supported")),
        "ignore" => {}
        "error" => bail!("{opt} is not yet supported"),
        other => bail!("Unsupported value for {WILD_UNSUPPORTED_ENV}={other}"),
    }
    Ok(())
}

/// Result of pre-scanning args for target-determining flags.
#[derive(Debug)]
pub(crate) struct DetectedTarget {
    pub format: target_lexicon::BinaryFormat,
    /// Architecture from `--target` triple. `None` if no `--target` was given.
    pub arch: Option<Architecture>,
}

/// Known `-m` emulation values that imply ELF output.
const ELF_EMULATIONS: &[&str] = &[
    "elf_x86_64",
    "elf_x86_64_sol2",
    "aarch64elf",
    "aarch64linux",
    "elf64lriscv",
    "elf64loongarch",
];

/// Map `target_lexicon::Architecture` to Wild's `Architecture`.
fn map_triple_arch(arch: target_lexicon::Architecture) -> Result<Architecture> {
    use target_lexicon::Architecture as TL;
    match arch {
        TL::X86_64 | TL::X86_64h => Ok(Architecture::X86_64),
        TL::Aarch64(_) => Ok(Architecture::AArch64),
        TL::Riscv64(_) => Ok(Architecture::RISCV64),
        TL::LoongArch64 => Ok(Architecture::LoongArch64),
        other => bail!("unsupported architecture in target triple: {other}"),
    }
}

/// Extract the target triple value from a flag, handling all prefix styles.
/// Returns `(Some(value), consumed_next)` if the arg is a target flag.
fn extract_target_value<'a>(arg: &'a str, next_arg: Option<&'a str>) -> (Option<&'a str>, bool) {
    // Combined forms: --target=VAL, -target=VAL, /TARGET:VAL
    if let Some(val) = arg
        .strip_prefix("--target=")
        .or_else(|| arg.strip_prefix("-target="))
        .or_else(|| arg.strip_prefix("/TARGET:"))
        .or_else(|| arg.strip_prefix("/target:"))
    {
        return (Some(val), false);
    }
    // Space-separated: --target VAL, -target VAL, /TARGET VAL
    if matches!(arg, "--target" | "-target" | "/TARGET" | "/target") {
        if let Some(val) = next_arg {
            return (Some(val), true);
        }
    }
    (None, false)
}

/// Pre-scan CLI arguments to determine the output format and architecture.
///
/// Recognizes:
/// - `--target=<triple>` / `-target=<triple>` / `/TARGET:<triple>` — primary (parsed by target-lexicon)
/// - `-m <emulation>` — overrides format to ELF when present
///
/// Priority: `-m` overrides format from `--target`. Architecture comes from `--target` only.
pub(crate) fn detect_target(args: &[String]) -> Result<DetectedTarget> {
    let mut from_triple: Option<(BinaryFormat, Architecture)> = None;
    let mut m_implies_elf = false;

    let mut i = 0;
    while i < args.len() {
        let next = if i + 1 < args.len() {
            Some(args[i + 1].as_str())
        } else {
            None
        };
        let (target_val, consumed_next) = extract_target_value(&args[i], next);

        if let Some(val) = target_val {
            let triple: Triple = val
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid target triple '{val}': {e}"))?;
            let arch = map_triple_arch(triple.architecture)?;
            from_triple = Some((triple.binary_format, arch));
            if consumed_next {
                i += 1;
            }
        }
        // Check for -m <emulation> (implies ELF)
        else if args[i] == "-m" || args[i] == "--m" {
            if let Some(next_val) = next {
                if ELF_EMULATIONS.contains(&next_val) {
                    m_implies_elf = true;
                }
                i += 1;
            }
        } else if let Some(emu) = args[i].strip_prefix("-m") {
            if ELF_EMULATIONS.contains(&emu) {
                m_implies_elf = true;
            }
        }

        i += 1;
    }

    match (from_triple, m_implies_elf) {
        (Some((_, arch)), true) => {
            // -m overrides format to ELF; arch from triple preserved
            Ok(DetectedTarget {
                format: BinaryFormat::Elf,
                arch: Some(arch),
            })
        }
        (Some((format, arch)), false) => Ok(DetectedTarget {
            format,
            arch: Some(arch),
        }),
        (None, true) => Ok(DetectedTarget {
            format: BinaryFormat::Elf,
            arch: None,
        }),
        (None, false) => Ok(DetectedTarget {
            format: BinaryFormat::host(),
            arch: None,
        }),
    }
}

/// Map Wild `Architecture` to the GNU ld `-m` emulation name.
fn arch_to_elf_emulation(arch: Architecture) -> &'static str {
    match arch {
        Architecture::X86_64 => "elf_x86_64",
        Architecture::AArch64 => "aarch64linux",
        Architecture::RISCV64 => "elf64lriscv",
        Architecture::LoongArch64 => "elf64loongarch",
    }
}

/// Map Wild `Architecture` to the MSVC `/MACHINE:` value.
fn arch_to_machine_value(arch: Architecture) -> &'static str {
    match arch {
        Architecture::X86_64 => "X64",
        Architecture::AArch64 => "ARM64",
        Architecture::RISCV64 => "X64",
        Architecture::LoongArch64 => "X64",
    }
}

/// Strip `--target`/`-target`/`/TARGET` flags and inject a synthetic `-m` or `/MACHINE:` flag
/// from the detected architecture so the format-specific parser picks it up.
///
/// The user's explicit `-m` or `/MACHINE:` flags are preserved and will override the injected one
/// since they appear later in the argument list.
pub(crate) fn filter_and_inject_target_flags(
    args: &[String],
    format: BinaryFormat,
    arch: Option<Architecture>,
) -> Vec<String> {
    let mut result = Vec::with_capacity(args.len() + 2);

    // Inject synthetic arch flag at the front (user's explicit flags override later)
    if let Some(arch) = arch {
        match format {
            BinaryFormat::Elf => {
                result.push("-m".to_string());
                result.push(arch_to_elf_emulation(arch).to_string());
            }
            BinaryFormat::Coff => {
                result.push(format!("/MACHINE:{}", arch_to_machine_value(arch)));
            }
            _ => { /* no additional flags needed for other formats */ }
        }
    }

    // Strip --target flags, keep everything else
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with("--target=")
            || arg.starts_with("-target=")
            || arg.starts_with("/TARGET:")
            || arg.starts_with("/target:")
        {
            // Skip this combined arg
        } else if matches!(arg.as_str(), "--target" | "-target" | "/TARGET" | "/target") {
            i += 1; // skip value too
        } else {
            result.push(arg.clone());
        }
        i += 1;
    }
    result
}

/// Format-specific parsed arguments.
pub enum TargetArgs {
    Elf(linux::ElfArgs),
    #[allow(dead_code)]
    Pe(windows::PeArgs),
}

impl std::fmt::Debug for TargetArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetArgs::Elf(e) => e.fmt(f),
            TargetArgs::Pe(p) => p.fmt(f),
        }
    }
}

impl<T> std::ops::Deref for Args<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.target_args
    }
}

impl<T> std::ops::DerefMut for Args<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.target_args
    }
}

impl<T> Args<T> {
    /// Transform the target-specific part while preserving common fields.
    pub fn map_target<U>(self, f: impl FnOnce(T) -> U) -> Args<U> {
        Args {
            // Infrastructure
            should_fork: self.should_fork,
            output: self.output,
            arch: self.arch,
            inputs: self.inputs,
            lib_search_path: self.lib_search_path,
            num_threads: self.num_threads,
            available_threads: self.available_threads,
            save_dir: self.save_dir,
            unrecognized_options: self.unrecognized_options,
            files_per_group: self.files_per_group,
            write_layout: self.write_layout,
            write_trace: self.write_trace,
            jobserver_client: self.jobserver_client,
            // Core linker behavior
            strip: self.strip,
            gc_sections: self.gc_sections,
            merge_sections: self.merge_sections,
            relax: self.relax,
            demangle: self.demangle,
            no_undefined: self.no_undefined,
            allow_shlib_undefined: self.allow_shlib_undefined,
            error_unresolved_symbols: self.error_unresolved_symbols,
            allow_multiple_definitions: self.allow_multiple_definitions,
            unresolved_symbols: self.unresolved_symbols,
            undefined: self.undefined,
            copy_relocations: self.copy_relocations,
            sysroot: self.sysroot,
            dynamic_linker: self.dynamic_linker,
            entry: self.entry,
            wrap: self.wrap,
            exclude_libs: self.exclude_libs,
            b_symbolic: self.b_symbolic,
            export_list: self.export_list,
            defsym: self.defsym,
            section_start: self.section_start,
            max_page_size: self.max_page_size,
            execstack: self.execstack,
            version_mode: self.version_mode,
            relocation_model: self.relocation_model,
            should_output_executable: self.should_output_executable,
            export_all_dynamic_symbols: self.export_all_dynamic_symbols,
            version_script_path: self.version_script_path,
            export_list_path: self.export_list_path,
            // Output/writing
            mmap_output_file: self.mmap_output_file,
            file_write_mode: self.file_write_mode,
            prepopulate_maps: self.prepopulate_maps,
            should_write_linker_identity: self.should_write_linker_identity,
            // Debug/diagnostic
            debug_fuel: self.debug_fuel,
            validate_output: self.validate_output,
            sym_info: self.sym_info,
            debug_address: self.debug_address,
            print_allocations: self.print_allocations,
            verify_allocation_consistency: self.verify_allocation_consistency,
            time_phase_options: self.time_phase_options,
            numeric_experiments: self.numeric_experiments,
            write_gc_stats: self.write_gc_stats,
            gc_stats_ignore: self.gc_stats_ignore,
            verbose_gc_stats: self.verbose_gc_stats,
            dependency_file: self.dependency_file,
            // Format-specific
            target_args: f(self.target_args),
        }
    }

    pub fn map_ref_target<U>(&self, f: impl FnOnce(&T) -> U) -> U {
        f(&self.target_args)
    }

    /// Uses 1 debug fuel, returning how much fuel remains. Debug fuel is intended to be used when
    /// debugging certain kinds of bugs, so this function isn't normally referenced. To use it, the
    /// caller should take a different branch depending on whether the value is still positive. You
    /// can then do a binary search.
    pub(crate) fn use_debug_fuel(&self) -> i64 {
        let Some(fuel) = self.debug_fuel.as_ref() else {
            return i64::MAX;
        };
        fuel.fetch_sub(1, std::sync::atomic::Ordering::AcqRel) - 1
    }

    /// Returns whether there was sufficient fuel. If the last bit of fuel was used, then calls
    /// `last_cb`.
    #[allow(unused)]
    pub(crate) fn use_debug_fuel_on_last(&self, last_cb: impl FnOnce()) -> bool {
        match self.use_debug_fuel() {
            1.. => true,
            0 => {
                last_cb();
                true
            }
            _ => false,
        }
    }

    pub(crate) fn trace_span_for_file(
        &self,
        file_id: FileId,
    ) -> Option<tracing::span::EnteredSpan> {
        let should_trace = self.print_allocations == Some(file_id);
        should_trace.then(|| tracing::trace_span!(crate::debug_trace::TRACE_SPAN_NAME).entered())
    }

    pub(crate) fn numeric_experiment(&self, exp: Experiment, default: u64) -> u64 {
        self.numeric_experiments
            .get(exp as usize)
            .copied()
            .flatten()
            .unwrap_or(default)
    }

    pub(crate) fn loadable_segment_alignment(&self) -> Alignment {
        if let Some(max_page_size) = self.max_page_size {
            return max_page_size;
        }

        match self.arch {
            Architecture::X86_64 => Alignment { exponent: 12 },
            Architecture::AArch64 => Alignment { exponent: 16 },
            Architecture::RISCV64 => Alignment { exponent: 12 },
            Architecture::LoongArch64 => Alignment { exponent: 16 },
        }
    }

    pub(crate) fn strip_all(&self) -> bool {
        matches!(self.strip, Strip::All)
    }

    pub(crate) fn strip_debug(&self) -> bool {
        matches!(self.strip, Strip::All | Strip::Debug)
    }
}

impl<T> ActivatedArgs<T> {
    pub fn map_target<U>(self, f: impl FnOnce(T) -> U) -> ActivatedArgs<U> {
        ActivatedArgs {
            args: self.args.map_target(f),
            _jobserver_tokens: self._jobserver_tokens,
        }
    }
}

impl<T> Args<T> {
    /// Sets up the thread pool, using the explicit number of threads if specified,
    /// or falling back to the jobserver protocol if available.
    ///
    /// <https://www.gnu.org/software/make/manual/html_node/POSIX-Jobserver.html>
    pub fn activate_thread_pool(mut self) -> Result<ActivatedArgs<T>> {
        crate::timing_phase!("Activate thread pool");

        let mut tokens = Vec::new();
        self.available_threads = self.num_threads.unwrap_or_else(|| {
            if let Some(client) = &self.jobserver_client {
                while let Ok(Some(acquired)) = client.try_acquire() {
                    tokens.push(acquired);
                }
                tracing::trace!(count = tokens.len(), "Acquired jobserver tokens");
                // Our parent "holds" one jobserver token, add it.
                NonZeroUsize::new((tokens.len() + 1).max(1)).unwrap()
            } else {
                std::thread::available_parallelism().unwrap_or(NonZeroUsize::new(1).unwrap())
            }
        });

        // The pool might be already initialized, suppress the error intentionally.
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(self.available_threads.get())
            .build_global();

        Ok(ActivatedArgs {
            args: self,
            _jobserver_tokens: tokens,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CopyRelocationsDisabledReason {
    Flag,
    SharedObject,
}

impl Display for CopyRelocationsDisabledReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Reason should make sense after the word "because".
        let reason = match self {
            CopyRelocationsDisabledReason::Flag => "the flag -z nocopyreloc was supplied",
            CopyRelocationsDisabledReason::SharedObject => "output is a shared object",
        };

        Display::fmt(&reason, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    // ---- detect_target tests ----

    #[test]
    fn test_detect_format_from_triple_linux_x86() {
        let args = to_strings(&["--target=x86_64-unknown-linux-gnu", "-o", "out"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, BinaryFormat::Elf);
        assert_eq!(result.arch, Some(Architecture::X86_64));
    }

    #[test]
    fn test_detect_format_from_triple_windows() {
        let args = to_strings(&["-target=x86_64-pc-windows-msvc", "/OUT:foo.exe"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, BinaryFormat::Coff);
        assert_eq!(result.arch, Some(Architecture::X86_64));
    }

    #[test]
    fn test_detect_format_from_slash_target() {
        let args = to_strings(&["/TARGET:aarch64-pc-windows-msvc", "foo.obj"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, BinaryFormat::Coff);
        assert_eq!(result.arch, Some(Architecture::AArch64));
    }

    #[test]
    fn test_detect_format_space_separated() {
        let args = to_strings(&["--target", "aarch64-unknown-linux-gnu", "-o", "out"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, BinaryFormat::Elf);
        assert_eq!(result.arch, Some(Architecture::AArch64));
    }

    #[test]
    fn test_detect_format_from_m_flag() {
        let args = to_strings(&["-m", "elf_x86_64", "-o", "out"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, BinaryFormat::Elf);
        assert_eq!(result.arch, None);
    }

    #[test]
    fn test_m_flag_overrides_target_format() {
        let args = to_strings(&["--target=x86_64-pc-windows-msvc", "-m", "elf_x86_64"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, BinaryFormat::Elf);
    }

    #[test]
    fn test_detect_format_default_no_flags() {
        let args = to_strings(&["-o", "out", "foo.o"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, BinaryFormat::host());
        assert_eq!(result.arch, None);
    }

    #[test]
    fn test_detect_format_riscv_triple() {
        let args = to_strings(&["--target=riscv64gc-unknown-linux-gnu", "-o", "out"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, BinaryFormat::Elf);
        assert_eq!(result.arch, Some(Architecture::RISCV64));
    }

    // ---- filter_and_inject_target_flags tests ----

    #[test]
    fn test_filter_strips_target_equals() {
        let args = to_strings(&["--target=x86_64-unknown-linux-gnu", "-o", "out", "foo.o"]);
        let filtered =
            filter_and_inject_target_flags(&args, BinaryFormat::Elf, Some(Architecture::X86_64));
        assert_eq!(filtered[0], "-m");
        assert_eq!(filtered[1], "elf_x86_64");
        assert_eq!(filtered[2], "-o");
        assert!(!filtered.iter().any(|a| a.contains("--target")));
    }

    #[test]
    fn test_filter_strips_target_space() {
        let args = to_strings(&["--target", "aarch64-unknown-linux-gnu", "-o", "out"]);
        let filtered =
            filter_and_inject_target_flags(&args, BinaryFormat::Elf, Some(Architecture::AArch64));
        assert_eq!(filtered[0], "-m");
        assert_eq!(filtered[1], "aarch64linux");
        assert!(
            !filtered
                .iter()
                .any(|a| a == "--target" || a.contains("linux-gnu"))
        );
    }

    #[test]
    fn test_filter_strips_slash_target() {
        let args = to_strings(&["/TARGET:x86_64-pc-windows-msvc", "/OUT:foo.exe", "bar.obj"]);
        let filtered =
            filter_and_inject_target_flags(&args, BinaryFormat::Coff, Some(Architecture::X86_64));
        assert_eq!(filtered[0], "/MACHINE:X64");
        assert_eq!(filtered[1], "/OUT:foo.exe");
    }

    #[test]
    fn test_filter_preserves_m_flag() {
        let args = to_strings(&[
            "--target=x86_64-unknown-linux-gnu",
            "-m",
            "aarch64linux",
            "-o",
            "out",
        ]);
        let filtered =
            filter_and_inject_target_flags(&args, BinaryFormat::Elf, Some(Architecture::X86_64));
        assert_eq!(filtered[0], "-m");
        assert_eq!(filtered[1], "elf_x86_64");
        assert!(filtered.contains(&"-m".to_string()));
        assert!(filtered.contains(&"aarch64linux".to_string()));
    }

    #[test]
    fn test_filter_no_target_no_inject() {
        let args = to_strings(&["-o", "out", "foo.o"]);
        let filtered = filter_and_inject_target_flags(&args, BinaryFormat::Elf, None);
        assert_eq!(filtered, args);
    }
}
