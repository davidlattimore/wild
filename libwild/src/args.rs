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

use crate::bail;
use crate::ensure;
use crate::error::Context;
use crate::error::Result;
use crate::input_data::FileId;
use crate::save_dir::SaveDir;
use elf::IGNORED_FLAGS;
use hashbrown::HashMap;
use hashbrown::HashSet;
use itertools::Itertools;
use jobserver::Acquired;
use jobserver::Client;
use rayon::ThreadPoolBuilder;
use std::fmt::Display;
use std::num::NonZeroUsize;
use std::path::Path;
use std::path::PathBuf;

pub mod elf;
pub mod macho;
pub mod pe;

use crate::error::Warning;
use crate::platform;
use crate::platform::Args as _;
use crate::timing_phase;
use std::sync::atomic::AtomicI64;

pub(crate) const FILES_PER_GROUP_ENV: &str = "WILD_FILES_PER_GROUP";
pub const REFERENCE_LINKER_ENV: &str = "WILD_REFERENCE_LINKER";
pub const VALIDATE_ENV: &str = "WILD_VALIDATE_OUTPUT";
pub const WILD_UNSUPPORTED_ENV: &str = "WILD_UNSUPPORTED";
pub const WRITE_LAYOUT_ENV: &str = "WILD_WRITE_LAYOUT";
pub const WRITE_TRACE_ENV: &str = "WILD_WRITE_TRACE";

/// Set this environment variable if you get a failure during writing due to too much or too little
/// space being allocated to some section. When set, each time we allocate during layout, we'll
/// check that what we're doing is consistent with writing and fail in a more easy to debug way. i.e
/// we'll report the particular combination of value flags, resolution flags etc that triggered the
/// inconsistency.
pub(crate) const WRITE_VERIFY_ALLOCATIONS_ENV: &str = "WILD_VERIFY_ALLOCATIONS";

#[derive(derive_more::Debug)]
pub struct CommonArgs {
    pub(crate) unrecognized_options: Vec<String>,

    /// The number of actually available threads (considering jobserver)
    pub(crate) available_threads: NonZeroUsize,
    pub num_threads: Option<NonZeroUsize>,
    pub(crate) files_per_group: Option<u32>,

    jobserver_client: Option<Client>,
    pub(crate) inputs: Vec<Input>,
    pub(crate) file_write_mode: Option<FileWriteMode>,
    pub(crate) save_dir: SaveDir,

    pub(crate) prepopulate_maps: bool,
    pub(crate) debug_fuel: Option<AtomicI64>,
    pub(crate) should_fork: bool,
    pub(crate) demangle: bool,
    pub(crate) mmap_output_file: bool,
    pub(crate) validate_output: bool,
    pub(crate) verify_allocation_consistency: bool,
    pub(crate) write_layout: bool,
    pub(crate) write_trace: bool,
    pub(crate) print_allocations: Option<FileId>,
    pub(crate) sym_info: Option<String>,
    pub(crate) numeric_experiments: Vec<Option<u64>>,
    pub(crate) version_mode: VersionMode,

    /// If `Some`, then we'll time how long each phase takes. We'll also measure the specified
    /// counters, if any.
    pub(crate) time_phase_options: Option<Vec<CounterKind>>,

    /// Warnings that we encountered either during argument parsing, or during subsequent linker
    /// execution based on those arguments.
    #[debug(skip)]
    pub(crate) warning_callback: Box<WarningCallback>,

    /// The version of the linker being used.
    pub(crate) version: std::borrow::Cow<'static, str>,
}

pub type WarningCallback = dyn Fn(Warning) + Send + Sync + 'static;

impl Args {
    /// Construct a new instance, but doesn't yet parse the arguments. The supplied arguments are
    /// only used to help decide what kind of argument parsing we'll be doing - i.e. what platform
    /// we're linking for. We split into two phases so that the caller can adjust defaults before
    /// the actual parsing occurs.
    pub fn new<F, S, I>(input: F) -> Result<Self>
    where
        F: Fn() -> I,
        S: AsRef<str>,
        I: Iterator<Item = S>,
    {
        let mut input = input();

        // TODO: Select platform based on executable name and/or the first argument.
        let _executable_name = input
            .next()
            .ok_or_else(|| crate::error!("Failed to determine executable name"))?;

        match PlatformKind::host() {
            PlatformKind::Elf => Ok(Args::Elf(elf::ElfArgs::new()?)),
            PlatformKind::MachO => Ok(Args::MachO(macho::MachOArgs::new()?)),
            PlatformKind::Pe => Ok(Args::Pe(pe::PeArgs::new()?)),
        }
    }

    /// Parse CLI arguments. Runs format-specific parser based on the host target.
    pub fn parse<F: Fn() -> I, S: AsRef<str>, I: Iterator<Item = S>>(
        &mut self,
        input: F,
    ) -> Result {
        timing_phase!("Parse args");

        self.common_mut().save_dir = SaveDir::new(input())?;

        let mut input = input();

        // Skip the program name.
        input.next();

        match self {
            Args::Elf(args) => args.parse(input),
            Args::MachO(args) => args.parse(input),
            Args::Pe(args) => args.parse(input),
        }
    }

    /// Set the version identifier of the linker.
    pub fn set_version(&mut self, version: &str) {
        self.common_mut().version = std::borrow::Cow::Owned(version.to_owned());
    }

    /// Calls the callback whenever a warning is emitted. The default, if this method is never
    /// called is to print the warning to stderr. Calling this method suppresses the default
    /// behaviour. Warnings may be emitted while parsing arguments or later, while using the
    /// arguments to link. As such, this method should be called after calling `new` and before
    /// calling `parse`.
    pub fn on_warning(&mut self, warning_callback: Box<WarningCallback>) {
        self.common_mut().warning_callback = Box::new(warning_callback);
    }

    pub(crate) fn common(&self) -> &CommonArgs {
        match self {
            Args::Elf(args) => &args.common,
            Args::MachO(args) => &args.common,
            Args::Pe(args) => &args.common,
        }
    }

    pub(crate) fn common_mut(&mut self) -> &mut CommonArgs {
        match self {
            Args::Elf(args) => &mut args.common,
            Args::MachO(args) => &mut args.common,
            Args::Pe(args) => &mut args.common,
        }
    }
}

enum PlatformKind {
    Elf,
    MachO,
    Pe,
}

impl PlatformKind {
    fn host() -> Self {
        if cfg!(target_os = "macos") {
            PlatformKind::MachO
        } else if cfg!(target_os = "windows") {
            PlatformKind::Pe
        } else {
            PlatformKind::Elf
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VersionMode {
    /// Don't print version
    None,
    /// Print version and continue linking (-v)
    Verbose,
    /// Print version and exit immediately (--version)
    ExitAfterPrint,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelocationModel {
    NonRelocatable,
    Relocatable,
}

impl Default for CommonArgs {
    fn default() -> Self {
        Self {
            available_threads: NonZeroUsize::new(1).unwrap(),
            num_threads: None,
            jobserver_client: None,
            files_per_group: None,
            inputs: Vec::new(),
            file_write_mode: None,
            unrecognized_options: Vec::new(),
            save_dir: SaveDir::default(),
            mmap_output_file: true,
            prepopulate_maps: false,
            debug_fuel: None,
            should_fork: true,
            demangle: true,
            version_mode: VersionMode::None,
            validate_output: std::env::var(VALIDATE_ENV).is_ok_and(|v| v == "1"),
            verify_allocation_consistency: std::env::var(WRITE_VERIFY_ALLOCATIONS_ENV)
                .is_ok_and(|v| v == "1"),
            write_layout: std::env::var(WRITE_LAYOUT_ENV).is_ok_and(|v| v == "1"),
            write_trace: std::env::var(WRITE_TRACE_ENV).is_ok_and(|v| v == "1"),
            print_allocations: std::env::var("WILD_PRINT_ALLOCATIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .map(FileId::from_encoded),
            numeric_experiments: Vec::new(),
            sym_info: None,
            time_phase_options: None,
            warning_callback: Box::new(default_warning_callback),
            version: std::borrow::Cow::Borrowed("unknown version"),
        }
    }
}

fn default_warning_callback(warning: Warning) {
    eprintln!("{warning}");
    // Suppress clippy warning. We need to confirm to an API that takes warning by value.
    drop(warning);
}

impl CommonArgs {
    pub(crate) fn trace_span_for_file(
        &self,
        file_id: FileId,
    ) -> Option<tracing::span::EnteredSpan> {
        let should_trace = self.print_allocations == Some(file_id);
        should_trace.then(|| tracing::trace_span!(crate::debug_trace::TRACE_SPAN_NAME).entered())
    }

    /// Sets up the thread pool, using the explicit number of threads if specified,
    /// or falling back to the jobserver protocol if available.
    ///
    /// <https://www.gnu.org/software/make/manual/html_node/POSIX-Jobserver.html>
    pub fn activate_thread_pool(&mut self) -> Result<ThreadPool> {
        timing_phase!("Activate thread pool");

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
        if self.available_threads.get() <= 1 {
            let _ = ThreadPoolBuilder::new().use_current_thread().build_global();
        } else {
            let _ = ThreadPoolBuilder::new()
                .num_threads(self.available_threads.get())
                .build_global();
        }

        Ok(ThreadPool {
            _jobserver_tokens: tokens,
        })
    }

    /// Returns a string that identifies this linker. This is written into the .comment
    /// section which usually also contains the versions of compilers that were used.
    pub(crate) fn linker_identity(&self) -> String {
        format!("Wild {} (compatible with GNU linkers)", self.version)
    }

    /// Adds a linker script to our outputs. Note, this is only called for scripts specified via
    /// flags like -T. Where a linker script is just listed as an argument, this won't be called.
    fn add_script(&mut self, path: &str) {
        self.inputs.push(Input {
            spec: InputSpec::File(Box::from(Path::new(path))),
            search_first: None,
            modifiers: Modifiers::default(),
        });
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

    pub fn should_fork(&self) -> bool {
        self.should_fork
    }

    pub(crate) fn numeric_experiment(&self, exp: Experiment, default: u64) -> u64 {
        self.numeric_experiments
            .get(exp as usize)
            .copied()
            .flatten()
            .unwrap_or(default)
    }

    fn from_env() -> Result<Self> {
        use crate::input_data::MAX_FILES_PER_GROUP;

        // SAFETY: Should be called early before other descriptors are opened and
        // so we open it before the arguments are parsed (can open a file).
        let jobserver_client = unsafe { Client::from_env() };

        let files_per_group = std::env::var(FILES_PER_GROUP_ENV)
            .ok()
            .map(|s| s.parse())
            .transpose()?;

        if let Some(x) = files_per_group {
            ensure!(
                x <= MAX_FILES_PER_GROUP,
                "{FILES_PER_GROUP_ENV}={x} but maximum is {MAX_FILES_PER_GROUP}"
            );
        }

        let mut common = Self {
            files_per_group,
            jobserver_client,
            ..Default::default()
        };

        if std::env::var(REFERENCE_LINKER_ENV).is_ok() {
            common.write_layout = true;
            common.write_trace = true;
        }

        Ok(common)
    }
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

/// A type that indicates that the global thread pool has been created. Currently, you should only
/// create one of these at a time. If a jobserver is being used, then dropping this instance will
/// release jobserver tokens.
pub struct ThreadPool {
    _jobserver_tokens: Vec<Acquired>,
}

// TODO: remove
#[allow(clippy::large_enum_variant)]
pub enum Args {
    Elf(elf::ElfArgs),
    MachO(macho::MachOArgs),
    Pe(pe::PeArgs),
}

impl std::fmt::Debug for Args {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Args::Elf(args) => args.fmt(f),
            Args::MachO(args) => args.fmt(f),
            Args::Pe(args) => args.fmt(f),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CopyRelocations {
    Allowed,
    Disallowed(CopyRelocationsDisabledReason),
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CopyRelocationsDisabledReason {
    Unsupported,
    Flag,
    SharedObject,
}

impl Display for CopyRelocationsDisabledReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Reason should make sense after the word "because".
        let reason = match self {
            CopyRelocationsDisabledReason::Unsupported => {
                "target platform doesn't support copy relocations"
            }
            CopyRelocationsDisabledReason::Flag => "the flag -z nocopyreloc was supplied",
            CopyRelocationsDisabledReason::SharedObject => "output is a shared object",
        };

        Display::fmt(&reason, f)
    }
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

#[derive(Debug)]
pub(crate) enum DefsymValue {
    /// A numeric value (address)
    Value(u64),
    /// Reference to another symbol with an optional offset
    SymbolWithOffset(String, i64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy)]
enum OptionStyle {
    /// `--flag=value`, `-flag`, case-sensitive
    Unix,
    /// `/FLAG:value`, case-insensitive
    Windows,
}

impl OptionStyle {
    fn strip_option(self, arg: &str) -> Option<&str> {
        match self {
            Self::Unix => arg.strip_prefix("--").or(arg.strip_prefix('-')),
            Self::Windows => arg.strip_prefix('/').or(arg.strip_prefix('-')),
        }
    }

    fn has_option_prefix(self, arg: &str) -> bool {
        match self {
            Self::Unix => arg.starts_with('-'),
            Self::Windows => arg.starts_with('/') || arg.starts_with('-'),
        }
    }

    fn find_separator(self, stripped: &str) -> Option<usize> {
        match self {
            Self::Unix => stripped.find('='),
            Self::Windows => stripped.find(':'),
        }
    }

    fn is_case_insensitive(self) -> bool {
        matches!(self, Self::Windows)
    }
}

struct ArgumentParser<T> {
    options: HashMap<&'static str, OptionHandler<T>>, // Long option lookup
    short_options: HashMap<&'static str, OptionHandler<T>>, // Short option lookup
    prefix_options: HashMap<&'static str, PrefixOptionHandler<T>>, // For options like -L, -l, etc.
    style: OptionStyle,
}

impl<T: platform::Args> Default for ArgumentParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: platform::Args> ArgumentParser<T> {
    #[must_use]
    fn new() -> Self {
        Self {
            options: HashMap::new(),
            short_options: HashMap::new(),
            prefix_options: HashMap::new(),
            style: OptionStyle::Unix,
        }
    }

    #[must_use]
    fn new_windows() -> Self {
        Self {
            options: HashMap::new(),
            short_options: HashMap::new(),
            prefix_options: HashMap::new(),
            style: OptionStyle::Windows,
        }
    }

    fn declare(&mut self) -> OptionDeclaration<'_, T, NoParam> {
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

    fn declare_with_param(&mut self) -> OptionDeclaration<'_, T, WithParam> {
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

    fn declare_with_optional_param(&mut self) -> OptionDeclaration<'_, T, WithOptionalParam> {
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
        if self.style.is_case_insensitive() {
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

    fn handle_argument<S: AsRef<str>, I: Iterator<Item = S>>(
        &self,
        args: &mut T,
        modifier_stack: &mut Vec<Modifiers>,
        arg: &str,
        input: &mut I,
    ) -> Result<()> {
        let common = args.common_mut();

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

        if let Some(stripped) = self.style.strip_option(arg) {
            if let Some(eq_pos) = self.style.find_separator(stripped) {
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

        if self.style.has_option_prefix(arg) {
            if let Some(stripped) = self.style.strip_option(arg)
                && IGNORED_FLAGS.contains(&stripped)
            {
                args.warn_unsupported(arg)?;
                return Ok(());
            }

            common.unrecognized_options.push(arg.to_owned());
            return Ok(());
        }

        common.save_dir.handle_file(arg);
        common.inputs.push(Input {
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

        let mut prefix_options = self.prefix_options.iter().collect_vec();
        prefix_options.sort_by_key(|(prefix, _)| *prefix);

        // TODO: This is ad-hoc
        help.push_str(&format!(
            "    {:<31} Read options from a file\n",
            "@<VALUE>",
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
                let mut sub_options = handler.sub_options.iter().collect_vec();
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

        let mut sorted_help_groups = help_to_options.into_iter().collect_vec();
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
    handler: fn(&mut T, &mut Vec<Modifiers>, &str) -> Result<()>,
    sub_options: HashMap<&'static str, SubOption<T>>,
}

type OptionalParamHandler<T> = fn(&mut T, &mut Vec<Modifiers>, Option<&str>) -> Result<()>;

#[allow(clippy::enum_variant_names)]
enum OptionHandlerFn<T> {
    NoParam(fn(&mut T, &mut Vec<Modifiers>) -> Result<()>),
    WithParam(fn(&mut T, &mut Vec<Modifiers>, &str) -> Result<()>),
    OptionalParam(OptionalParamHandler<T>),
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

struct OptionDeclaration<'a, T, S> {
    parser: &'a mut ArgumentParser<T>,
    long_names: Vec<&'static str>,
    short_names: Vec<&'static str>,
    prefixes: Vec<&'static str>,
    sub_options: HashMap<&'static str, SubOption<T>>,
    help_text: &'static str,
    _phantom: std::marker::PhantomData<S>,
}

struct NoParam;
struct WithParam;
struct WithOptionalParam;

enum SubOptionHandler<T> {
    /// Handler without value parameter (exact match)
    NoValue(fn(&mut T, &mut Vec<Modifiers>) -> Result<()>),
    /// Handler with value parameter (prefix match)
    WithValue(fn(&mut T, &mut Vec<Modifiers>, &str) -> Result<()>),
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

impl<'a, T, S> OptionDeclaration<'a, T, S> {
    #[must_use]
    fn long(mut self, name: &'static str) -> Self {
        self.long_names.push(name);
        self
    }

    #[must_use]
    fn short(mut self, option: &'static str) -> Self {
        self.short_names.push(option);
        self
    }

    #[must_use]
    fn help(mut self, text: &'static str) -> Self {
        self.help_text = text;
        self
    }

    fn prefix(mut self, prefix: &'static str) -> Self {
        self.prefixes.push(prefix);
        self
    }

    #[must_use]
    fn sub_option(
        mut self,
        name: &'static str,
        help: &'static str,
        handler: fn(&mut T, &mut Vec<Modifiers>) -> Result<()>,
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
    fn sub_option_with_value(
        mut self,
        name: &'static str,
        help: &'static str,
        handler: fn(&mut T, &mut Vec<Modifiers>, &str) -> Result<()>,
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
    fn execute(self, handler: fn(&mut T, &mut Vec<Modifiers>) -> Result<()>) {
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
    fn execute(self, handler: fn(&mut T, &mut Vec<Modifiers>, &str) -> Result<()>) {
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
    fn execute(self, handler: OptionalParamHandler<T>) {
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

pub(crate) fn read_args_from_file(path: &Path) -> Result<Vec<String>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read arguments from file `{}`", path.display()))?;
    arguments_from_string(&contents)
}

/// Parses arguments from a string, handling quoting, escapes etc.
/// All arguments must be surrounded by a white space.
fn arguments_from_string(input: &str) -> Result<Vec<String>> {
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

        ensure!(
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
                ensure!(heap.is_none(), "Missing opening quote '{ch}'");
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
            if ch == '\\' {
                ch = chars.next().context("Invalid escape")?;
            }
            heap.get_or_insert(String::new()).push(ch);
        }
    }

    Ok(out)
}

fn parse_time_phase_options(input: &str) -> Result<Vec<CounterKind>> {
    input.split(',').map(|s| s.parse()).collect()
}

impl std::str::FromStr for CounterKind {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "cycles" => CounterKind::Cycles,
            "instructions" => CounterKind::Instructions,
            "cache-misses" => CounterKind::CacheMisses,
            "branch-misses" => CounterKind::BranchMisses,
            "page-faults" => CounterKind::PageFaults,
            "page-faults-minor" => CounterKind::PageFaultsMinor,
            "page-faults-major" => CounterKind::PageFaultsMajor,
            "l1d-read" => CounterKind::L1dRead,
            "l1d-miss" => CounterKind::L1dMiss,
            other => bail!("Unsupported performance counter `{other}`"),
        })
    }
}
