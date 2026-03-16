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
use jobserver::Acquired;
use jobserver::Client;
use rayon::ThreadPoolBuilder;
use std::fmt::Display;
use std::num::NonZeroUsize;
use std::path::Path;
use std::path::PathBuf;

pub mod elf;

use crate::timing_phase;

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

#[derive(Debug)]
pub struct Args<T = TargetArgs> {
    pub(crate) unrecognized_options: Vec<String>,

    /// The number of actually available threads (considering jobserver)
    pub(crate) available_threads: NonZeroUsize,
    pub num_threads: Option<NonZeroUsize>,
    pub(crate) files_per_group: Option<u32>,

    jobserver_client: Option<Client>,
    pub(crate) inputs: Vec<Input>,
    pub(crate) save_dir: SaveDir,

    pub(crate) validate_output: bool,
    pub(crate) verify_allocation_consistency: bool,
    pub(crate) write_layout: bool,
    pub(crate) write_trace: bool,
    pub(crate) print_allocations: Option<FileId>,

    /// Format-specific arguments.
    pub target_args: T,
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

impl Args {
    /// Parse CLI arguments. Detects target format from `--target=<triple>`, `-m`,
    /// or host default, then routes to the format-specific parser.
    pub fn parse<F: Fn() -> I, S: AsRef<str>, I: Iterator<Item = S>>(input: F) -> Result<Args> {
        let mut input = input();
        // TODO: will be used when supporting multiple formats
        let _executable_name = input
            .next()
            .ok_or_else(|| crate::error!("should always be at least the executable name"))?;
        let all_args = input.collect::<Vec<_>>();

        let elf_args = elf::parse(|| all_args.iter())?;
        Ok(elf_args.map_target(TargetArgs::Elf))
    }
}

impl<T: Default> Default for Args<T> {
    fn default() -> Self {
        Self {
            target_args: T::default(),
            available_threads: NonZeroUsize::new(1).unwrap(),
            num_threads: None,
            jobserver_client: None,
            files_per_group: None,
            inputs: Vec::new(),
            unrecognized_options: Vec::new(),
            save_dir: SaveDir::default(),
            validate_output: std::env::var(VALIDATE_ENV).is_ok_and(|v| v == "1"),
            verify_allocation_consistency: std::env::var(WRITE_VERIFY_ALLOCATIONS_ENV)
                .is_ok_and(|v| v == "1"),
            write_layout: std::env::var(WRITE_LAYOUT_ENV).is_ok_and(|v| v == "1"),
            write_trace: std::env::var(WRITE_TRACE_ENV).is_ok_and(|v| v == "1"),
            print_allocations: std::env::var("WILD_PRINT_ALLOCATIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .map(FileId::from_encoded),
        }
    }
}

impl<T> Args<T> {
    /// Transform the target-specific part while preserving common fields.
    pub fn map_target<U>(self, f: impl FnOnce(T) -> U) -> Args<U> {
        Args {
            unrecognized_options: self.unrecognized_options,
            available_threads: self.available_threads,
            num_threads: self.num_threads,
            jobserver_client: self.jobserver_client,
            inputs: self.inputs,
            save_dir: self.save_dir,
            files_per_group: self.files_per_group,
            validate_output: self.validate_output,
            verify_allocation_consistency: self.verify_allocation_consistency,
            write_layout: self.write_layout,
            write_trace: self.write_trace,
            print_allocations: self.print_allocations,
            // Format-specific
            target_args: f(self.target_args),
        }
    }

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
    pub fn activate_thread_pool(mut self) -> Result<ActivatedArgs<T>> {
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
        let _ = ThreadPoolBuilder::new()
            .num_threads(self.available_threads.get())
            .build_global();

        Ok(ActivatedArgs {
            args: self,
            _jobserver_tokens: tokens,
        })
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
}

/// Represents a command-line argument that specifies the number of threads to use,
/// triggering activation of the thread pool.
pub struct ActivatedArgs<T = TargetArgs> {
    pub args: Args<T>,
    _jobserver_tokens: Vec<Acquired>,
}
pub enum TargetArgs {
    Elf(elf::ElfArgs),
}

impl std::fmt::Debug for TargetArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetArgs::Elf(e) => e.fmt(f),
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

struct ArgumentParser<T> {
    options: HashMap<&'static str, OptionHandler<T>>, // Long option lookup
    short_options: HashMap<&'static str, OptionHandler<T>>, // Short option lookup
    prefix_options: HashMap<&'static str, PrefixOptionHandler<T>>, // For options like -L, -l, etc.
}

impl<T> Default for ArgumentParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ArgumentParser<T> {
    #[must_use]
    fn new() -> Self {
        Self {
            options: HashMap::new(),
            short_options: HashMap::new(),
            prefix_options: HashMap::new(),
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

    fn handle_argument<S: AsRef<str>, I: Iterator<Item = S>>(
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

        if let Some(stripped) = strip_option(arg) {
            // Check for option with '=' syntax
            if let Some(eq_pos) = stripped.find('=') {
                let option_name = &stripped[..eq_pos];
                let value = &stripped[eq_pos + 1..];

                if let Some(handler) = self.options.get(option_name) {
                    match &handler.handler {
                        OptionHandlerFn::WithParam(f) => f(args, modifier_stack, value)?,
                        OptionHandlerFn::OptionalParam(f) => f(args, modifier_stack, Some(value))?,
                        OptionHandlerFn::NoParam(_) => return Ok(()),
                    }
                    return Ok(());
                }
            } else {
                if stripped == "build-id"
                    && let Some(handler) = self.options.get(stripped)
                    && let OptionHandlerFn::WithParam(f) = &handler.handler
                {
                    f(args, modifier_stack, "fast")?;
                    return Ok(());
                }

                if let Some(handler) = self.options.get(stripped) {
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

        if arg.starts_with('-') {
            if let Some(stripped) = strip_option(arg)
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

type OptionalParamHandler<T> = fn(&mut Args<T>, &mut Vec<Modifiers>, Option<&str>) -> Result<()>;

#[allow(clippy::enum_variant_names)]
enum OptionHandlerFn<T> {
    NoParam(fn(&mut Args<T>, &mut Vec<Modifiers>) -> Result<()>),
    WithParam(fn(&mut Args<T>, &mut Vec<Modifiers>, &str) -> Result<()>),
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
    fn sub_option_with_value(
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
    fn execute(self, handler: fn(&mut Args<T>, &mut Vec<Modifiers>) -> Result<()>) {
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
    fn execute(self, handler: fn(&mut Args<T>, &mut Vec<Modifiers>, &str) -> Result<()>) {
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

fn strip_option(arg: &str) -> Option<&str> {
    arg.strip_prefix("--").or(arg.strip_prefix('-'))
}

fn warn_unsupported(opt: &str) -> Result {
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
