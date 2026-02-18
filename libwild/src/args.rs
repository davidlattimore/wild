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

use crate::alignment::Alignment;
use crate::arch::Architecture;
use crate::bail;
use crate::ensure;
use crate::error::Context as _;
use crate::error::Result;
use crate::input_data::FileId;
use crate::linker_script::maybe_forced_sysroot;
use crate::save_dir::SaveDir;
use crate::timing_phase;
use hashbrown::HashMap;
use hashbrown::HashSet;
use indexmap::IndexSet;
use itertools::Itertools;
use jobserver::Acquired;
use jobserver::Client;
use object::elf::GNU_PROPERTY_X86_ISA_1_BASELINE;
use object::elf::GNU_PROPERTY_X86_ISA_1_V2;
use object::elf::GNU_PROPERTY_X86_ISA_1_V3;
use object::elf::GNU_PROPERTY_X86_ISA_1_V4;
use rayon::ThreadPoolBuilder;
use std::ffi::CString;
use std::fmt::Display;
use std::mem::take;
use std::num::NonZero;
use std::num::NonZeroU32;
use std::num::NonZeroU64;
use std::num::NonZeroUsize;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;

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

#[derive(Debug)]
pub struct Args {
    pub(crate) unrecognized_options: Vec<String>,

    pub(crate) arch: Architecture,
    pub(crate) lib_search_path: Vec<Box<Path>>,
    pub(crate) inputs: Vec<Input>,
    pub(crate) output: Arc<Path>,
    pub(crate) dynamic_linker: Option<Box<Path>>,
    pub num_threads: Option<NonZeroUsize>,
    pub(crate) strip: Strip,
    pub(crate) prepopulate_maps: bool,
    pub(crate) sym_info: Option<String>,
    pub(crate) merge_sections: bool,
    pub(crate) debug_fuel: Option<AtomicI64>,
    pub(crate) validate_output: bool,
    pub(crate) version_script_path: Option<PathBuf>,
    pub(crate) debug_address: Option<u64>,
    pub(crate) write_layout: bool,
    pub(crate) should_write_eh_frame_hdr: bool,
    pub(crate) write_trace: bool,
    pub(crate) wrap: Vec<String>,
    pub(crate) rpath: Option<String>,
    pub(crate) soname: Option<String>,
    pub(crate) files_per_group: Option<u32>,
    pub(crate) exclude_libs: ExcludeLibs,
    pub(crate) gc_sections: bool,
    pub(crate) should_fork: bool,
    pub(crate) mmap_output_file: bool,
    pub(crate) build_id: BuildIdOption,
    pub(crate) file_write_mode: Option<FileWriteMode>,
    pub(crate) no_undefined: bool,
    pub(crate) allow_shlib_undefined: bool,
    pub(crate) needs_origin_handling: bool,
    pub(crate) needs_nodelete_handling: bool,
    pub(crate) copy_relocations: CopyRelocations,
    pub(crate) sysroot: Option<Box<Path>>,
    pub(crate) undefined: Vec<String>,
    pub(crate) relro: bool,
    pub(crate) entry: Option<String>,
    pub(crate) export_all_dynamic_symbols: bool,
    pub(crate) export_list: Vec<String>,
    pub(crate) export_list_path: Option<PathBuf>,
    pub(crate) auxiliary: Vec<String>,
    pub(crate) enable_new_dtags: bool,
    pub(crate) plugin_path: Option<String>,
    pub(crate) plugin_args: Vec<CString>,

    /// Symbol definitions from `--defsym` options. Each entry is (symbol_name, value_or_symbol).
    pub(crate) defsym: Vec<(String, DefsymValue)>,

    /// Section start addresses from `--section-start` options. Maps section name to address.
    pub(crate) section_start: HashMap<String, u64>,

    /// If set, GC stats will be written to the specified filename.
    pub(crate) write_gc_stats: Option<PathBuf>,

    /// If set, and we're writing GC stats, then ignore any input files that contain any of the
    /// specified substrings.
    pub(crate) gc_stats_ignore: Vec<String>,

    /// If `Some`, then we'll time how long each phase takes. We'll also measure the specified
    /// counters, if any.
    pub(crate) time_phase_options: Option<Vec<CounterKind>>,

    pub(crate) verbose_gc_stats: bool,

    pub(crate) save_dir: SaveDir,
    pub(crate) dependency_file: Option<PathBuf>,
    pub(crate) print_allocations: Option<FileId>,
    pub(crate) execstack: bool,
    pub(crate) verify_allocation_consistency: bool,
    pub(crate) version_mode: VersionMode,
    pub(crate) demangle: bool,
    pub(crate) got_plt_syms: bool,
    pub(crate) b_symbolic: BSymbolicKind,
    pub(crate) relax: bool,
    pub(crate) should_write_linker_identity: bool,
    pub(crate) hash_style: HashStyle,
    pub(crate) unresolved_symbols: UnresolvedSymbols,
    pub(crate) error_unresolved_symbols: bool,
    pub(crate) allow_multiple_definitions: bool,
    pub(crate) z_interpose: bool,
    pub(crate) z_isa: Option<NonZeroU32>,
    pub(crate) z_stack_size: Option<NonZeroU64>,
    pub(crate) max_page_size: Option<Alignment>,

    pub(crate) relocation_model: RelocationModel,
    pub(crate) should_output_executable: bool,

    /// The number of actually available threads (considering jobserver)
    pub(crate) available_threads: NonZeroUsize,

    pub(crate) numeric_experiments: Vec<Option<u64>>,

    rpath_set: IndexSet<String>,

    jobserver_client: Option<Client>,
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
pub struct ActivatedArgs {
    pub args: Args,
    _jobserver_tokens: Vec<Acquired>,
}

#[derive(Debug)]
pub(crate) enum BuildIdOption {
    None,
    Fast,
    Hex(Vec<u8>),
    Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashStyle {
    Gnu,
    Sysv,
    Both,
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

impl HashStyle {
    pub(crate) const fn includes_gnu(self) -> bool {
        matches!(self, HashStyle::Gnu | HashStyle::Both)
    }

    pub(crate) const fn includes_sysv(self) -> bool {
        matches!(self, HashStyle::Sysv | HashStyle::Both)
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

pub const WILD_UNSUPPORTED_ENV: &str = "WILD_UNSUPPORTED";
pub const VALIDATE_ENV: &str = "WILD_VALIDATE_OUTPUT";
pub const WRITE_LAYOUT_ENV: &str = "WILD_WRITE_LAYOUT";
pub const WRITE_TRACE_ENV: &str = "WILD_WRITE_TRACE";
pub const REFERENCE_LINKER_ENV: &str = "WILD_REFERENCE_LINKER";
pub(crate) const FILES_PER_GROUP_ENV: &str = "WILD_FILES_PER_GROUP";

/// Set this environment variable if you get a failure during writing due to too much or too little
/// space being allocated to some section. When set, each time we allocate during layout, we'll
/// check that what we're doing is consistent with writing and fail in a more easy to debug way. i.e
/// we'll report the particular combination of value flags, resolution flags etc that triggered the
/// inconsistency.
pub(crate) const WRITE_VERIFY_ALLOCATIONS_ENV: &str = "WILD_VERIFY_ALLOCATIONS";

// These flags don't currently affect our behaviour. TODO: Assess whether we should error or warn if
// these are given. This is tricky though. On the one hand we want to be a drop-in replacement for
// other linkers. On the other, we should perhaps somehow let the user know that we don't support a
// feature.
const SILENTLY_IGNORED_FLAGS: &[&str] = &[
    // Just like other modern linkers, we don't need groups in order to resolve cycles.
    "start-group",
    "end-group",
    // TODO: This is supposed to suppress built-in search paths, but I don't think we have any
    // built-in search paths. Perhaps we should?
    "nostdlib",
    // TODO
    "no-undefined-version",
    "fatal-warnings",
    "color-diagnostics",
    "undefined-version",
    "sort-common",
    "stats",
];
const SILENTLY_IGNORED_SHORT_FLAGS: &[&str] = &[
    "(",
    ")",
    // On Illumos, the Clang driver inserts a meaningless -C flag before calling any non-GNU ld
    // linker.
    #[cfg(target_os = "illumos")]
    "C",
];

const IGNORED_FLAGS: &[&str] = &[
    "gdb-index",
    "fix-cortex-a53-835769",
    "fix-cortex-a53-843419",
    "discard-all",
    "use-android-relr-tags",
    "x", // alias for --discard-all
];

// These flags map to the default behavior of the linker.
const DEFAULT_FLAGS: &[&str] = &[
    "no-call-graph-profile-sort",
    "no-copy-dt-needed-entries",
    "no-add-needed",
    "discard-locals",
    "no-fatal-warnings",
    "no-use-android-relr-tags",
];
const DEFAULT_SHORT_FLAGS: &[&str] = &[
    "X",  // alias for --discard-locals
    "EL", // little endian
];

impl Default for Args {
    fn default() -> Self {
        Args {
            arch: default_target_arch(),
            unrecognized_options: Vec::new(),

            lib_search_path: Vec::new(),
            inputs: Vec::new(),
            output: Arc::from(Path::new("a.out")),
            should_output_executable: true,
            dynamic_linker: None,
            time_phase_options: None,
            num_threads: None,
            strip: Strip::Nothing,
            // For now, we default to --gc-sections. This is different to other linkers, but other
            // than being different, there doesn't seem to be any downside to doing
            // this. We don't currently do any less work if we're not GCing sections,
            // but do end up writing more, so --no-gc-sections will almost always be as
            // slow or slower than --gc-sections. For that reason, the latter is
            // probably a good default.
            gc_sections: true,
            prepopulate_maps: false,
            sym_info: None,
            merge_sections: true,
            copy_relocations: CopyRelocations::Allowed,
            debug_fuel: None,
            validate_output: std::env::var(VALIDATE_ENV).is_ok_and(|v| v == "1"),
            write_layout: std::env::var(WRITE_LAYOUT_ENV).is_ok_and(|v| v == "1"),
            write_trace: std::env::var(WRITE_TRACE_ENV).is_ok_and(|v| v == "1"),
            verify_allocation_consistency: std::env::var(WRITE_VERIFY_ALLOCATIONS_ENV)
                .is_ok_and(|v| v == "1"),
            print_allocations: std::env::var("WILD_PRINT_ALLOCATIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .map(FileId::from_encoded),
            relocation_model: RelocationModel::NonRelocatable,
            version_script_path: None,
            debug_address: None,
            should_write_eh_frame_hdr: false,
            write_gc_stats: None,
            wrap: Vec::new(),
            gc_stats_ignore: Vec::new(),
            verbose_gc_stats: false,
            rpath: None,
            soname: None,
            enable_new_dtags: true,
            execstack: false,
            should_fork: true,
            mmap_output_file: true,
            needs_origin_handling: false,
            needs_nodelete_handling: false,
            should_write_linker_identity: true,
            file_write_mode: None,
            build_id: BuildIdOption::None,
            files_per_group: None,
            exclude_libs: ExcludeLibs::None,
            no_undefined: false,
            allow_shlib_undefined: false,
            version_mode: VersionMode::None,
            sysroot: None,
            save_dir: Default::default(),
            dependency_file: None,
            demangle: true,
            undefined: Vec::new(),
            relro: true,
            entry: None,
            b_symbolic: BSymbolicKind::None,
            export_all_dynamic_symbols: false,
            export_list: Vec::new(),
            export_list_path: None,
            defsym: Vec::new(),
            section_start: HashMap::new(),
            got_plt_syms: false,
            relax: true,
            hash_style: HashStyle::Both,
            jobserver_client: None,
            available_threads: NonZeroUsize::new(1).unwrap(),
            unresolved_symbols: UnresolvedSymbols::ReportAll,
            error_unresolved_symbols: true,
            allow_multiple_definitions: false,
            z_interpose: false,
            z_stack_size: None,
            z_isa: None,
            max_page_size: None,
            auxiliary: Vec::new(),
            numeric_experiments: Vec::new(),
            rpath_set: Default::default(),
            plugin_path: None,
            plugin_args: Vec::new(),
        }
    }
}

// Parse the supplied input arguments, which should not include the program name.
pub(crate) fn parse<F: Fn() -> I, S: AsRef<str>, I: Iterator<Item = S>>(input: F) -> Result<Args> {
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

    let mut args = Args {
        files_per_group,
        jobserver_client,
        ..Default::default()
    };

    args.save_dir = SaveDir::new(&input)?;

    let mut input = input();

    let mut modifier_stack = vec![Modifiers::default()];

    if std::env::var(REFERENCE_LINKER_ENV).is_ok() {
        args.write_layout = true;
        args.write_trace = true;
    }

    let arg_parser = setup_argument_parser();
    while let Some(arg) = input.next() {
        let arg = arg.as_ref();

        arg_parser.handle_argument(&mut args, &mut modifier_stack, arg, &mut input)?;
    }

    // Copy relocations are only permitted when building executables.
    if !args.should_output_executable {
        args.copy_relocations =
            CopyRelocations::Disallowed(CopyRelocationsDisabledReason::SharedObject);
    }

    if !args.rpath_set.is_empty() {
        args.rpath = Some(take(&mut args.rpath_set).into_iter().join(":"));
    }

    if !args.unrecognized_options.is_empty() {
        let options_list = args.unrecognized_options.join(", ");
        bail!("unrecognized option(s): {}", options_list);
    }

    if !args.auxiliary.is_empty() && args.should_output_executable {
        bail!("-f may not be used without -shared");
    }

    Ok(args)
}

const fn default_target_arch() -> Architecture {
    // We default to targeting the architecture that we're running on. We don't support running on
    // architectures that we can't target.
    #[cfg(target_arch = "x86_64")]
    {
        Architecture::X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        Architecture::AArch64
    }
    #[cfg(target_arch = "riscv64")]
    {
        Architecture::RISCV64
    }
    #[cfg(target_arch = "loongarch64")]
    {
        Architecture::LoongArch64
    }
}

pub(crate) fn read_args_from_file(path: &Path) -> Result<Vec<String>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read arguments from file `{}`", path.display()))?;
    arguments_from_string(&contents)
}

impl Args {
    pub fn parse<F: Fn() -> I, S: AsRef<str>, I: Iterator<Item = S>>(input: F) -> Result<Args> {
        timing_phase!("Parse args");
        parse(input)
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

    pub fn should_fork(&self) -> bool {
        self.should_fork
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

    /// Adds a linker script to our outputs. Note, this is only called for scripts specified via
    /// flags like -T. Where a linker script is just listed as an argument, this won't be called.
    fn add_script(&mut self, path: &str) {
        self.inputs.push(Input {
            spec: InputSpec::File(Box::from(Path::new(path))),
            search_first: None,
            modifiers: Modifiers::default(),
        });
    }

    /// Sets up the thread pool, using the explicit number of threads if specified,
    /// or falling back to the jobserver protocol if available.
    ///
    /// <https://www.gnu.org/software/make/manual/html_node/POSIX-Jobserver.html>
    pub fn activate_thread_pool(mut self) -> Result<ActivatedArgs> {
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

    pub(crate) fn numeric_experiment(&self, exp: Experiment, default: u64) -> u64 {
        self.numeric_experiments
            .get(exp as usize)
            .copied()
            .flatten()
            .unwrap_or(default)
    }

    pub(crate) fn strip_all(&self) -> bool {
        matches!(self.strip, Strip::All)
    }

    pub(crate) fn strip_debug(&self) -> bool {
        matches!(self.strip, Strip::All | Strip::Debug)
    }
}

fn parse_number(s: &str) -> Result<u64> {
    crate::parsing::parse_number(s).map_err(|_| crate::error!("Invalid number: {}", s))
}

fn parse_defsym_expression(s: &str) -> DefsymValue {
    use crate::parsing::ParsedSymbolExpression;
    use crate::parsing::parse_symbol_expression;

    match parse_symbol_expression(s) {
        ParsedSymbolExpression::Absolute(value) => DefsymValue::Value(value),
        ParsedSymbolExpression::SymbolWithOffset(sym, offset) => {
            DefsymValue::SymbolWithOffset(sym.to_owned(), offset)
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

struct ArgumentParser {
    options: HashMap<&'static str, OptionHandler>,
    short_options: HashMap<&'static str, OptionHandler>, // Short option lookup
    prefix_options: HashMap<&'static str, PrefixOptionHandler>, // For options like -L, -l, etc.
}

#[derive(Clone)]
struct OptionHandler {
    help_text: &'static str,
    handler: OptionHandlerFn,
    short_names: Vec<&'static str>,
}

struct PrefixOptionHandler {
    help_text: &'static str,
    handler: fn(&mut Args, &mut Vec<Modifiers>, &str) -> Result<()>,
    sub_options: HashMap<&'static str, SubOption>,
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy)]
enum OptionHandlerFn {
    NoParam(fn(&mut Args, &mut Vec<Modifiers>) -> Result<()>),
    WithParam(fn(&mut Args, &mut Vec<Modifiers>, &str) -> Result<()>),
    OptionalParam(fn(&mut Args, &mut Vec<Modifiers>, Option<&str>) -> Result<()>),
}

impl OptionHandlerFn {
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

struct OptionDeclaration<'a, T> {
    parser: &'a mut ArgumentParser,
    long_names: Vec<&'static str>,
    short_names: Vec<&'static str>,
    prefixes: Vec<&'static str>,
    sub_options: HashMap<&'static str, SubOption>,
    help_text: &'static str,
    _phantom: std::marker::PhantomData<T>,
}

struct NoParam;
struct WithParam;
struct WithOptionalParam;

#[derive(Clone, Copy)]
enum SubOptionHandler {
    /// Handler without value parameter (exact match)
    NoValue(fn(&mut Args, &mut Vec<Modifiers>) -> Result<()>),
    /// Handler with value parameter (prefix match)
    WithValue(fn(&mut Args, &mut Vec<Modifiers>, &str) -> Result<()>),
}

#[derive(Clone, Copy)]
struct SubOption {
    help: &'static str,
    handler: SubOptionHandler,
}

impl SubOption {
    fn with_value(&self) -> bool {
        matches!(self.handler, SubOptionHandler::WithValue(_))
    }
}

impl Default for ArgumentParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArgumentParser {
    #[must_use]
    fn new() -> Self {
        Self {
            options: HashMap::new(),
            short_options: HashMap::new(),
            prefix_options: HashMap::new(),
        }
    }

    fn declare(&mut self) -> OptionDeclaration<'_, NoParam> {
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

    fn declare_with_param(&mut self) -> OptionDeclaration<'_, WithParam> {
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

    fn declare_with_optional_param(&mut self) -> OptionDeclaration<'_, WithOptionalParam> {
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
        args: &mut Args,
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

impl<'a, T> OptionDeclaration<'a, T> {
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
        handler: fn(&mut Args, &mut Vec<Modifiers>) -> Result<()>,
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
        handler: fn(&mut Args, &mut Vec<Modifiers>, &str) -> Result<()>,
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

impl<'a> OptionDeclaration<'a, NoParam> {
    fn execute(self, handler: fn(&mut Args, &mut Vec<Modifiers>) -> Result<()>) {
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

impl<'a> OptionDeclaration<'a, WithParam> {
    fn execute(self, handler: fn(&mut Args, &mut Vec<Modifiers>, &str) -> Result<()>) {
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

impl<'a> OptionDeclaration<'a, WithOptionalParam> {
    fn execute(self, handler: fn(&mut Args, &mut Vec<Modifiers>, Option<&str>) -> Result<()>) {
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

fn setup_argument_parser() -> ArgumentParser {
    let mut parser = ArgumentParser::new();

    parser
        .declare_with_param()
        .prefix("L")
        .help("Add directory to library search path")
        .execute(|args, _modifier_stack, value| {
            let handle_sysroot = |path| {
                args.sysroot
                    .as_ref()
                    .and_then(|sysroot| maybe_forced_sysroot(path, sysroot))
                    .unwrap_or_else(|| Box::from(path))
            };

            let dir = handle_sysroot(Path::new(value));
            args.save_dir.handle_file(value);
            args.lib_search_path.push(dir);
            Ok(())
        });

    parser
        .declare_with_param()
        .prefix("l")
        .help("Link with library")
        .sub_option_with_value(
            ":filename",
            "Link with specific file",
            |args, modifier_stack, value| {
                let stripped = value.strip_prefix(':').unwrap_or(value);
                let spec = InputSpec::File(Box::from(Path::new(stripped)));
                args.inputs.push(Input {
                    spec,
                    search_first: None,
                    modifiers: *modifier_stack.last().unwrap(),
                });
                Ok(())
            },
        )
        .sub_option_with_value(
            "libname",
            "Link with library libname.so or libname.a",
            |args, modifier_stack, value| {
                let spec = InputSpec::Lib(Box::from(value));
                args.inputs.push(Input {
                    spec,
                    search_first: None,
                    modifiers: *modifier_stack.last().unwrap(),
                });
                Ok(())
            },
        )
        .execute(|args, modifier_stack, value| {
            let spec = if let Some(stripped) = value.strip_prefix(':') {
                InputSpec::Search(Box::from(stripped))
            } else {
                InputSpec::Lib(Box::from(value))
            };
            args.inputs.push(Input {
                spec,
                search_first: None,
                modifiers: *modifier_stack.last().unwrap(),
            });
            Ok(())
        });

    parser
        .declare_with_param()
        .prefix("u")
        .help("Force resolution of the symbol")
        .execute(|args, _modifier_stack, value| {
            args.undefined.push(value.to_owned());
            Ok(())
        });

    parser
        .declare_with_param()
        .prefix("m")
        .help("Set target architecture")
        .sub_option("elf_x86_64", "x86-64 ELF target", |args, _| {
            args.arch = Architecture::X86_64;
            Ok(())
        })
        .sub_option(
            "elf_x86_64_sol2",
            "x86-64 ELF target (Solaris)",
            |args, _| {
                if args.dynamic_linker.is_none() {
                    args.dynamic_linker = Some(Path::new("/lib/amd64/ld.so.1").into());
                }
                args.arch = Architecture::X86_64;
                Ok(())
            },
        )
        .sub_option("aarch64elf", "AArch64 ELF target", |args, _| {
            args.arch = Architecture::AArch64;
            Ok(())
        })
        .sub_option("aarch64linux", "AArch64 ELF target (Linux)", |args, _| {
            args.arch = Architecture::AArch64;
            Ok(())
        })
        .sub_option("elf64lriscv", "RISC-V 64-bit ELF target", |args, _| {
            args.arch = Architecture::RISCV64;
            Ok(())
        })
        .sub_option(
            "elf64loongarch",
            "LoongArch 64-bit ELF target",
            |args, _| {
                args.arch = Architecture::LoongArch64;
                Ok(())
            },
        )
        .execute(|_args, _modifier_stack, value| {
            bail!("-m {value} is not yet supported");
        });

    parser
        .declare_with_param()
        .prefix("z")
        .help("Linker option")
        .sub_option("now", "Resolve all symbols immediately", |_, _| Ok(()))
        .sub_option(
            "origin",
            "Mark object as requiring immediate $ORIGIN",
            |args, _| {
                args.needs_origin_handling = true;
                Ok(())
            },
        )
        .sub_option("relro", "Enable RELRO program header", |args, _| {
            args.relro = true;
            Ok(())
        })
        .sub_option("norelro", "Disable RELRO program header", |args, _| {
            args.relro = false;
            Ok(())
        })
        .sub_option("notext", "Do not report DT_TEXTREL as an error", |_, _| {
            Ok(())
        })
        .sub_option("nostart-stop-gc", "Disable start/stop symbol GC", |_, _| {
            Ok(())
        })
        .sub_option(
            "execstack",
            "Mark object as requiring an executable stack",
            |args, _| {
                args.execstack = true;
                Ok(())
            },
        )
        .sub_option(
            "noexecstack",
            "Mark object as not requiring an executable stack",
            |args, _| {
                args.execstack = false;
                Ok(())
            },
        )
        .sub_option("nocopyreloc", "Disable copy relocations", |args, _| {
            args.copy_relocations =
                CopyRelocations::Disallowed(CopyRelocationsDisabledReason::Flag);
            Ok(())
        })
        .sub_option(
            "nodelete",
            "Mark shared object as non-deletable",
            |args, _| {
                args.needs_nodelete_handling = true;
                Ok(())
            },
        )
        .sub_option(
            "defs",
            "Report unresolved symbol references in object files",
            |args, _| {
                args.no_undefined = true;
                Ok(())
            },
        )
        .sub_option(
            "undefs",
            "Do not report unresolved symbol references in object files",
            |args, _| {
                args.no_undefined = false;
                Ok(())
            },
        )
        .sub_option("muldefs", "Allow multiple definitions", |args, _| {
            args.allow_multiple_definitions = true;
            Ok(())
        })
        .sub_option("lazy", "Use lazy binding (default)", |_, _| Ok(()))
        .sub_option(
            "interpose",
            "Mark object to interpose all DSOs but executable",
            |args, _| {
                args.z_interpose = true;
                Ok(())
            },
        )
        .sub_option_with_value(
            "stack-size=",
            "Set size of stack segment",
            |args, _, value| {
                let size: u64 = parse_number(value)?;
                args.z_stack_size = NonZero::new(size);

                Ok(())
            },
        )
        .sub_option(
            "x86-64-baseline",
            "Mark x86-64-baseline ISA as needed",
            |args, _| {
                args.z_isa = NonZero::new(GNU_PROPERTY_X86_ISA_1_BASELINE);
                Ok(())
            },
        )
        .sub_option("x86-64-v2", "Mark x86-64-v2 ISA as needed", |args, _| {
            args.z_isa = NonZero::new(GNU_PROPERTY_X86_ISA_1_V2);
            Ok(())
        })
        .sub_option("x86-64-v3", "Mark x86-64-v3 ISA as needed", |args, _| {
            args.z_isa = NonZero::new(GNU_PROPERTY_X86_ISA_1_V3);
            Ok(())
        })
        .sub_option("x86-64-v4", "Mark x86-64-v4 ISA as needed", |args, _| {
            args.z_isa = NonZero::new(GNU_PROPERTY_X86_ISA_1_V4);
            Ok(())
        })
        .sub_option_with_value(
            "max-page-size=",
            "Set maximum page size for load segments",
            |args, _, value| {
                let size: u64 = parse_number(value)?;
                if !size.is_power_of_two() {
                    bail!("Invalid alignment {size:#x}");
                }
                args.max_page_size = Some(Alignment {
                    exponent: size.trailing_zeros() as u8,
                });

                Ok(())
            },
        )
        .execute(|_args, _modifier_stack, value| {
            warn_unsupported(&("-z ".to_owned() + value))?;
            Ok(())
        });

    parser
        .declare_with_param()
        .prefix("R")
        .help("Add runtime library search path")
        .execute(|args, _modifier_stack, value| {
            if Path::new(value).is_file() {
                args.unrecognized_options
                    .push(format!("-R,{value}(filename)"));
            } else {
                args.rpath_set.insert(value.to_string());
            }
            Ok(())
        });

    parser
        .declare_with_param()
        .prefix("O")
        .execute(|_args, _modifier_stack, _value|
        // We don't use opt-level for now.
        Ok(()));

    parser
        .declare()
        .long("static")
        .long("Bstatic")
        .help("Disallow linking of shared libraries")
        .execute(|_args, modifier_stack| {
            modifier_stack.last_mut().unwrap().allow_shared = false;
            Ok(())
        });

    parser
        .declare()
        .long("Bdynamic")
        .help("Allow linking of shared libraries")
        .execute(|_args, modifier_stack| {
            modifier_stack.last_mut().unwrap().allow_shared = true;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("output")
        .short("o")
        .help("Set the output filename")
        .execute(|args, _modifier_stack, value| {
            args.output = Arc::from(Path::new(value));
            Ok(())
        });

    parser
        .declare()
        .long("strip-all")
        .short("s")
        .help("Strip all symbols")
        .execute(|args, _modifier_stack| {
            args.strip = Strip::All;
            Ok(())
        });

    parser
        .declare()
        .long("strip-debug")
        .short("S")
        .help("Strip debug symbols")
        .execute(|args, _modifier_stack| {
            args.strip = Strip::Debug;
            Ok(())
        });

    parser
        .declare()
        .long("gc-sections")
        .help("Enable removal of unused sections")
        .execute(|args, _modifier_stack| {
            args.gc_sections = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-gc-sections")
        .help("Disable removal of unused sections")
        .execute(|args, _modifier_stack| {
            args.gc_sections = false;
            Ok(())
        });

    parser
        .declare()
        .long("shared")
        .long("Bshareable")
        .help("Create a shared library")
        .execute(|args, _modifier_stack| {
            args.should_output_executable = false;
            Ok(())
        });

    parser
        .declare()
        .long("pie")
        .long("pic-executable")
        .help("Create a position-independent executable")
        .execute(|args, _modifier_stack| {
            args.relocation_model = RelocationModel::Relocatable;
            args.should_output_executable = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-pie")
        .help("Do not create a position-dependent executable (default)")
        .execute(|args, _modifier_stack| {
            args.relocation_model = RelocationModel::NonRelocatable;
            args.should_output_executable = true;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("pack-dyn-relocs")
        .help("Specify dynamic relocation packing format")
        .execute(|_args, _modifier_stack, value| {
            if value != "none" {
                warn_unsupported(&format!("--pack-dyn-relocs={value}"))?;
            }
            Ok(())
        });

    parser
        .declare()
        .long("help")
        .help("Show this help message")
        .execute(|_args, _modifier_stack| {
            let parser = setup_argument_parser();
            println!("{}", parser.generate_help());

            // The following listing is something autoconf detection relies on.
            println!("wild: supported targets:elf64 -x86-64 elf64-littleaarch64 elf64-littleriscv elf64-loongarch");
            println!("wild: supported emulations: elf_x86_64 aarch64elf elf64lriscv elf64loongarch");

            std::process::exit(0);
        });

    parser
        .declare()
        .long("version")
        .help("Show version information and exit")
        .execute(|args, _modifier_stack| {
            args.version_mode = VersionMode::ExitAfterPrint;
            Ok(())
        });

    parser
        .declare()
        .short("v")
        .help("Print version and continue linking")
        .execute(|args, _modifier_stack| {
            args.version_mode = VersionMode::Verbose;
            Ok(())
        });

    parser
        .declare()
        .long("demangle")
        .help("Enable symbol demangling")
        .execute(|args, _modifier_stack| {
            args.demangle = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-demangle")
        .help("Disable symbol demangling")
        .execute(|args, _modifier_stack| {
            args.demangle = false;
            Ok(())
        });

    parser
        .declare_with_optional_param()
        .long("time")
        .help("Show timing information")
        .execute(|args, _modifier_stack, value| {
            match value {
                Some(v) => args.time_phase_options = Some(parse_time_phase_options(v)?),
                None => args.time_phase_options = Some(Vec::new()),
            }
            Ok(())
        });

    parser
        .declare_with_param()
        .long("dynamic-linker")
        .help("Set dynamic linker path")
        .execute(|args, _modifier_stack, value| {
            args.dynamic_linker = Some(Box::from(Path::new(value)));
            Ok(())
        });

    parser
        .declare()
        .long("no-dynamic-linker")
        .help("Omit the load-time dynamic linker request")
        .execute(|args, _modifier_stack| {
            args.dynamic_linker = None;
            Ok(())
        });

    parser
        .declare()
        .long("mmap-output-file")
        .help("Write output file using mmap (default)")
        .execute(|args, _modifier_stack| {
            args.mmap_output_file = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-mmap-output-file")
        .help("Write output file without mmap")
        .execute(|args, _modifier_stack| {
            args.mmap_output_file = false;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("entry")
        .short("e")
        .help("Set the entry point")
        .execute(|args, _modifier_stack, value| {
            args.entry = Some(value.to_owned());
            Ok(())
        });

    parser
        .declare_with_optional_param()
        .long("threads")
        .help("Use multiple threads for linking")
        .execute(|args, _modifier_stack, value| {
            match value {
                Some(v) => {
                    args.num_threads = Some(NonZeroUsize::try_from(v.parse::<usize>()?)?);
                }
                None => {
                    args.num_threads = None; // Default behaviour
                }
            }
            Ok(())
        });

    parser
        .declare()
        .long("no-threads")
        .help("Use a single thread")
        .execute(|args, _modifier_stack| {
            args.num_threads = Some(NonZeroUsize::new(1).unwrap());
            Ok(())
        });

    parser
        .declare_with_param()
        .long("wild-experiments")
        .help("List of numbers. Used to tweak internal parameters. '_' keeps default value.")
        .execute(|args, _modifier_stack, value| {
            args.numeric_experiments = value
                .split(',')
                .map(|p| {
                    if p == "_" {
                        Ok(None)
                    } else {
                        Ok(Some(p.parse()?))
                    }
                })
                .collect::<Result<Vec<Option<u64>>>>()?;
            Ok(())
        });

    parser
        .declare()
        .long("as-needed")
        .help("Set DT_NEEDED if used")
        .execute(|_args, modifier_stack| {
            modifier_stack.last_mut().unwrap().as_needed = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-as-needed")
        .help("Always set DT_NEEDED")
        .execute(|_args, modifier_stack| {
            modifier_stack.last_mut().unwrap().as_needed = false;
            Ok(())
        });

    parser
        .declare()
        .long("whole-archive")
        .help("Include all objects from archives")
        .execute(|_args, modifier_stack| {
            modifier_stack.last_mut().unwrap().whole_archive = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-whole-archive")
        .help("Disable --whole-archive")
        .execute(|_args, modifier_stack| {
            modifier_stack.last_mut().unwrap().whole_archive = false;
            Ok(())
        });

    parser
        .declare()
        .long("push-state")
        .help("Save current linker flags")
        .execute(|_args, modifier_stack| {
            modifier_stack.push(*modifier_stack.last().unwrap());
            Ok(())
        });

    parser
        .declare()
        .long("pop-state")
        .help("Restore previous linker flags")
        .execute(|_args, modifier_stack| {
            modifier_stack.pop();
            if modifier_stack.is_empty() {
                bail!("Mismatched --pop-state");
            }
            Ok(())
        });

    parser
        .declare()
        .long("eh-frame-hdr")
        .help("Create .eh_frame_hdr section")
        .execute(|args, _modifier_stack| {
            args.should_write_eh_frame_hdr = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-eh-frame-hdr")
        .help("Don't create .eh_frame_hdr section")
        .execute(|args, _modifier_stack| {
            args.should_write_eh_frame_hdr = false;
            Ok(())
        });

    parser
        .declare()
        .long("export-dynamic")
        .short("E")
        .help("Export all dynamic symbols")
        .execute(|args, _modifier_stack| {
            args.export_all_dynamic_symbols = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-export-dynamic")
        .help("Do not export dynamic symbols")
        .execute(|args, _modifier_stack| {
            args.export_all_dynamic_symbols = false;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("soname")
        .prefix("h")
        .help("Set shared object name")
        .execute(|args, _modifier_stack, value| {
            args.soname = Some(value.to_owned());
            Ok(())
        });

    parser
        .declare_with_param()
        .long("rpath")
        .help("Add directory to runtime library search path")
        .execute(|args, _modifier_stack, value| {
            args.rpath_set.insert(value.to_string());
            Ok(())
        });

    parser
        .declare()
        .long("no-string-merge")
        .help("Disable section merging")
        .execute(|args, _modifier_stack| {
            args.merge_sections = false;
            Ok(())
        });

    parser
        .declare()
        .long("no-undefined")
        .help("Do not allow unresolved symbols in object files")
        .execute(|args, _modifier_stack| {
            args.no_undefined = true;
            Ok(())
        });

    parser
        .declare()
        .long("allow-multiple-definition")
        .help("Allow multiple definitions of symbols")
        .execute(|args, _modifier_stack| {
            args.allow_multiple_definitions = true;
            Ok(())
        });

    parser
        .declare()
        .long("relax")
        .help("Enable target-specific optimization (instruction relaxation)")
        .execute(|args, _modifier_stack| {
            args.relax = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-relax")
        .help("Disable relaxation")
        .execute(|args, _modifier_stack| {
            args.relax = false;
            Ok(())
        });

    parser
        .declare()
        .long("validate-output")
        .execute(|args, _modifier_stack| {
            args.validate_output = true;
            Ok(())
        });

    parser
        .declare()
        .long("write-layout")
        .execute(|args, _modifier_stack| {
            args.write_layout = true;
            Ok(())
        });

    parser
        .declare()
        .long("write-trace")
        .execute(|args, _modifier_stack| {
            args.write_trace = true;
            Ok(())
        });

    parser
        .declare()
        .long("got-plt-syms")
        .help("Write symbol table entries that point to the GOT/PLT entry for symbols")
        .execute(|args, _modifier_stack| {
            args.got_plt_syms = true;
            Ok(())
        });

    parser
        .declare()
        .long("Bsymbolic")
        .help("Bind global references locally")
        .execute(|args, _modifier_stack| {
            args.b_symbolic = BSymbolicKind::All;
            Ok(())
        });

    parser
        .declare()
        .long("Bsymbolic-functions")
        .help("Bind global function references locally")
        .execute(|args, _modifier_stack| {
            args.b_symbolic = BSymbolicKind::Functions;
            Ok(())
        });

    parser
        .declare()
        .long("Bsymbolic-non-weak-functions")
        .help("Bind non-weak global function references locally")
        .execute(|args, _modifier_stack| {
            args.b_symbolic = BSymbolicKind::NonWeakFunctions;
            Ok(())
        });

    parser
        .declare()
        .long("Bsymbolic-non-weak")
        .help("Bind non-weak global references locally")
        .execute(|args, _modifier_stack| {
            args.b_symbolic = BSymbolicKind::NonWeak;
            Ok(())
        });

    parser
        .declare()
        .long("Bno-symbolic")
        .help("Do not bind global symbol references locally")
        .execute(|args, _modifier_stack| {
            args.b_symbolic = BSymbolicKind::None;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("thread-count")
        .help("Set the number of threads to use")
        .execute(|args, _modifier_stack, value| {
            args.num_threads = Some(NonZeroUsize::try_from(value.parse::<usize>()?)?);
            Ok(())
        });

    parser
        .declare_with_param()
        .long("exclude-libs")
        .help("Exclude libraries")
        .execute(|args, _modifier_stack, value| {
            for lib in value.split([',', ':']) {
                if lib.is_empty() {
                    continue;
                }

                if lib == "ALL" {
                    args.exclude_libs = ExcludeLibs::All;
                    return Ok(());
                }

                match &mut args.exclude_libs {
                    ExcludeLibs::All => {}
                    ExcludeLibs::None => {
                        let mut set = HashSet::new();
                        set.insert(Box::from(lib));
                        args.exclude_libs = ExcludeLibs::Some(set);
                    }
                    ExcludeLibs::Some(set) => {
                        set.insert(Box::from(lib));
                    }
                }
            }

            Ok(())
        });

    parser
        .declare_with_param()
        .long("version-script")
        .help("Use version script")
        .execute(|args, _modifier_stack, value| {
            args.save_dir.handle_file(value);
            args.version_script_path = Some(PathBuf::from(value));
            Ok(())
        });

    parser
        .declare_with_param()
        .long("script")
        .prefix("T")
        .help("Use linker script")
        .execute(|args, _modifier_stack, value| {
            args.save_dir.handle_file(value);
            args.add_script(value);
            Ok(())
        });

    parser
        .declare_with_param()
        .long("export-dynamic-symbol")
        .help("Export dynamic symbol")
        .execute(|args, _modifier_stack, value| {
            args.export_list.push(value.to_owned());
            Ok(())
        });

    parser
        .declare_with_param()
        .long("export-dynamic-symbol-list")
        .help("Export dynamic symbol list")
        .execute(|args, _modifier_stack, value| {
            args.export_list_path = Some(PathBuf::from(value));
            Ok(())
        });

    parser
        .declare_with_param()
        .long("dynamic-list")
        .help("Read the dynamic symbol list from a file")
        .execute(|args, _modifier_stack, value| {
            args.b_symbolic = BSymbolicKind::All;
            args.export_list_path = Some(PathBuf::from(value));
            Ok(())
        });

    parser
        .declare_with_param()
        .long("write-gc-stats")
        .help("Write GC statistics")
        .execute(|args, _modifier_stack, value| {
            args.write_gc_stats = Some(PathBuf::from(value));
            Ok(())
        });

    parser
        .declare_with_param()
        .long("gc-stats-ignore")
        .help("Ignore files in GC stats")
        .execute(|args, _modifier_stack, value| {
            args.gc_stats_ignore.push(value.to_owned());
            Ok(())
        });

    parser
        .declare()
        .long("no-identity-comment")
        .help("Don't write the linker name and version in .comment")
        .execute(|args, _modifier_stack| {
            args.should_write_linker_identity = false;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("debug-address")
        .help("Set debug address")
        .execute(|args, _modifier_stack, value| {
            args.debug_address = Some(parse_number(value).context("Invalid --debug-address")?);
            Ok(())
        });

    parser
        .declare_with_param()
        .long("debug-fuel")
        .execute(|args, _modifier_stack, value| {
            args.debug_fuel = Some(AtomicI64::new(value.parse()?));
            args.num_threads = Some(NonZeroUsize::new(1).unwrap());
            Ok(())
        });

    parser
        .declare_with_param()
        .long("unresolved-symbols")
        .help("Specify how to handle unresolved symbols")
        .execute(|args, _modifier_stack, value| {
            args.unresolved_symbols = match value {
                "report-all" => UnresolvedSymbols::ReportAll,
                "ignore-in-shared-libs" => UnresolvedSymbols::IgnoreInSharedLibs,
                "ignore-in-object-files" => UnresolvedSymbols::IgnoreInObjectFiles,
                "ignore-all" => UnresolvedSymbols::IgnoreAll,
                _ => bail!("Invalid unresolved-symbols value {value}"),
            };
            Ok(())
        });

    parser
        .declare_with_param()
        .long("undefined")
        .help("Force resolution of the symbol")
        .execute(|args, _modifier_stack, value| {
            args.undefined.push(value.to_owned());
            Ok(())
        });

    parser
        .declare_with_param()
        .long("wrap")
        .help("Use a wrapper function")
        .execute(|args, _modifier_stack, value| {
            args.wrap.push(value.to_owned());
            Ok(())
        });

    parser
        .declare_with_param()
        .long("defsym")
        .help("Define a symbol alias: --defsym=symbol=value")
        .execute(|args, _modifier_stack, value| {
            let parts: Vec<&str> = value.splitn(2, '=').collect();
            if parts.len() != 2 {
                bail!("Invalid --defsym format. Expected: --defsym=symbol=value");
            }
            let symbol_name = parts[0].to_owned();
            let value_str = parts[1];

            let defsym_value = parse_defsym_expression(value_str);

            args.defsym.push((symbol_name, defsym_value));
            Ok(())
        });

    parser
        .declare_with_param()
        .long("section-start")
        .help("Set start address for a section: --section-start=.section=address")
        .execute(|args, _modifier_stack, value| {
            let parts: Vec<&str> = value.splitn(2, '=').collect();
            if parts.len() != 2 {
                bail!("Invalid --section-start format. Expected: --section-start=.section=address");
            }

            let section_name = parts[0].to_owned();
            let address = parse_number(parts[1]).with_context(|| {
                format!(
                    "Invalid address `{}` in --section-start={}",
                    parts[1], value
                )
            })?;
            args.section_start.insert(section_name, address);

            Ok(())
        });

    parser
        .declare_with_param()
        .long("hash-style")
        .help("Set hash style")
        .execute(|args, _modifier_stack, value| {
            args.hash_style = match value {
                "gnu" => HashStyle::Gnu,
                "sysv" => HashStyle::Sysv,
                "both" => HashStyle::Both,
                _ => bail!("Unknown hash-style `{value}`"),
            };
            Ok(())
        });

    parser
        .declare()
        .long("enable-new-dtags")
        .help("Use DT_RUNPATH and DT_FLAGS/DT_FLAGS_1 (default)")
        .execute(|args, _modifier_stack| {
            args.enable_new_dtags = true;
            Ok(())
        });

    parser
        .declare()
        .long("disable-new-dtags")
        .help("Use DT_RPATH and individual dynamic entries instead of DT_FLAGS")
        .execute(|args, _modifier_stack| {
            args.enable_new_dtags = false;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("retain-symbols-file")
        .help(
            "Filter symtab to contain only symbols listed in the supplied file. \
            One symbol per line.",
        )
        .execute(|args, _modifier_stack, value| {
            // The performance this flag is not especially optimised. For one, we copy each string
            // to the heap. We also do two lookups in the hashset for each symbol. This is a pretty
            // obscure flag that we don't expect to be used much, so at this stage, it doesn't seem
            // worthwhile to optimise it.
            let contents = std::fs::read_to_string(value)
                .with_context(|| format!("Failed to read `{value}`"))?;
            args.strip = Strip::Retain(
                contents
                    .lines()
                    .filter_map(|l| {
                        if l.is_empty() {
                            None
                        } else {
                            Some(l.as_bytes().to_owned())
                        }
                    })
                    .collect(),
            );
            Ok(())
        });

    parser
        .declare_with_param()
        .long("build-id")
        .help("Generate build ID")
        .execute(|args, _modifier_stack, value| {
            args.build_id = match value {
                "none" => BuildIdOption::None,
                "fast" | "md5" | "sha1" => BuildIdOption::Fast,
                "uuid" => BuildIdOption::Uuid,
                s if s.starts_with("0x") || s.starts_with("0X") => {
                    let hex_string = &s[2..];
                    let decoded_bytes = hex::decode(hex_string)
                        .with_context(|| format!("Invalid Hex Build Id `0x{hex_string}`"))?;
                    BuildIdOption::Hex(decoded_bytes)
                }
                s => bail!(
                    "Invalid build-id value `{s}` valid values are `none`, `fast`, `md5`, `sha1` and `uuid`"
                ),
            };
            Ok(())
        });

    parser
        .declare_with_param()
        .long("icf")
        .help("Enable identical code folding (merge duplicate functions)")
        .execute(|_args, _modifier_stack, value| {
            match value {
                "none" => {}
                other => warn_unsupported(&format!("--icf={other}"))?,
            }
            Ok(())
        });

    parser
        .declare_with_param()
        .long("sysroot")
        .help("Set system root")
        .execute(|args, _modifier_stack, value| {
            args.save_dir.handle_file(value);
            let sysroot = std::fs::canonicalize(value).unwrap_or_else(|_| PathBuf::from(value));
            args.sysroot = Some(Box::from(sysroot.as_path()));
            for path in &mut args.lib_search_path {
                if let Some(new_path) = maybe_forced_sysroot(path, &sysroot) {
                    *path = new_path;
                }
            }
            Ok(())
        });

    parser
        .declare_with_param()
        .long("auxiliary")
        .short("f")
        .help("Set DT_AUXILIARY to a given value")
        .execute(|args, _modifier_stack, value| {
            args.auxiliary.push(value.to_owned());
            Ok(())
        });

    parser
        .declare_with_param()
        .long("plugin-opt")
        .help("Pass options to the plugin")
        .execute(|args, _modifier_stack, value| {
            args.plugin_args
                .push(CString::new(value).context("Invalid --plugin-opt argument")?);
            Ok(())
        });

    parser
        .declare_with_param()
        .long("dependency-file")
        .help("Write dependency rules")
        .execute(|args, _modifier_stack, value| {
            args.dependency_file = Some(PathBuf::from(value));
            Ok(())
        });

    parser
        .declare_with_param()
        .long("plugin")
        .help("Load plugin")
        .execute(|args, _modifier_stack, value| {
            args.plugin_path = Some(value.to_owned());
            Ok(())
        });

    parser
        .declare_with_param()
        .long("rpath-link")
        .help("Add runtime library search path")
        .execute(|_args, _modifier_stack, _value| {
            // TODO
            Ok(())
        });

    parser
        .declare_with_param()
        .long("sym-info")
        .help("Show symbol information. Accepts symbol name or ID.")
        .execute(|args, _modifier_stack, value| {
            args.sym_info = Some(value.to_owned());
            Ok(())
        });

    parser
        .declare()
        .long("start-lib")
        .help("Start library group")
        .execute(|_args, modifier_stack| {
            modifier_stack.last_mut().unwrap().archive_semantics = true;
            Ok(())
        });

    parser
        .declare()
        .long("end-lib")
        .help("End library group")
        .execute(|_args, modifier_stack| {
            modifier_stack.last_mut().unwrap().archive_semantics = false;
            Ok(())
        });

    parser
        .declare()
        .long("no-fork")
        .help("Do not fork while linking")
        .execute(|args, _modifier_stack| {
            args.should_fork = false;
            Ok(())
        });

    parser
        .declare()
        .long("update-in-place")
        .help("Update file in place")
        .execute(|args, _modifier_stack| {
            args.file_write_mode = Some(FileWriteMode::UpdateInPlace);
            Ok(())
        });

    parser
        .declare()
        .long("no-update-in-place")
        .help("Delete and recreate the file")
        .execute(|args, _modifier_stack| {
            args.file_write_mode = Some(FileWriteMode::UnlinkAndReplace);
            Ok(())
        });

    parser
        .declare()
        .long("EB")
        .help("Big-endian (not supported)")
        .execute(|_args, _modifier_stack| {
            bail!("Big-endian target is not supported");
        });

    parser
        .declare()
        .long("prepopulate-maps")
        .help("Prepopulate maps")
        .execute(|args, _modifier_stack| {
            args.prepopulate_maps = true;
            Ok(())
        });

    parser
        .declare()
        .long("verbose-gc-stats")
        .help("Show GC statistics")
        .execute(|args, _modifier_stack| {
            args.verbose_gc_stats = true;
            Ok(())
        });

    parser
        .declare()
        .long("allow-shlib-undefined")
        .help("Allow undefined symbol references in shared libraries")
        .execute(|args, _modifier_stack| {
            args.allow_shlib_undefined = true;
            Ok(())
        });

    parser
        .declare()
        .long("no-allow-shlib-undefined")
        .help("Disallow undefined symbol references in shared libraries")
        .execute(|args, _modifier_stack| {
            args.allow_shlib_undefined = false;
            Ok(())
        });

    parser
        .declare()
        .long("error-unresolved-symbols")
        .help("Treat unresolved symbols as errors")
        .execute(|args, _modifier_stack| {
            args.error_unresolved_symbols = true;
            Ok(())
        });

    parser
        .declare()
        .long("warn-unresolved-symbols")
        .help("Treat unresolved symbols as warnings")
        .execute(|args, _modifier_stack| {
            args.error_unresolved_symbols = false;
            Ok(())
        });

    add_silently_ignored_flags(&mut parser);
    add_default_flags(&mut parser);

    parser
}

fn add_silently_ignored_flags(parser: &mut ArgumentParser) {
    for flag in SILENTLY_IGNORED_FLAGS {
        let mut declaration = parser.declare();
        declaration = declaration.long(flag);
        declaration.execute(|_args, _modifier_stack| Ok(()));
    }
    for flag in SILENTLY_IGNORED_SHORT_FLAGS {
        let mut declaration = parser.declare();
        declaration = declaration.short(flag);
        declaration.execute(|_args, _modifier_stack| Ok(()));
    }
}

fn add_default_flags(parser: &mut ArgumentParser) {
    for flag in DEFAULT_FLAGS {
        let mut declaration = parser.declare();
        declaration = declaration.long(flag);
        declaration.execute(|_args, _modifier_stack| Ok(()));
    }
    for flag in DEFAULT_SHORT_FLAGS {
        let mut declaration = parser.declare();
        declaration = declaration.short(flag);
        declaration.execute(|_args, _modifier_stack| Ok(()));
    }
}

fn parse_time_phase_options(input: &str) -> Result<Vec<CounterKind>> {
    input.split(',').map(|s| s.parse()).collect()
}

impl FromStr for CounterKind {
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
    use super::SILENTLY_IGNORED_FLAGS;
    use super::VersionMode;
    use crate::Args;
    use crate::args::InputSpec;
    use itertools::Itertools;
    use std::fs::File;
    use std::io::BufWriter;
    use std::io::Write;
    use std::num::NonZeroUsize;
    use std::path::Path;
    use std::path::PathBuf;
    use std::str::FromStr;
    use tempfile::NamedTempFile;

    const INPUT1: &[&str] = &[
        "-pie",
        "-z",
        "relro",
        "-zrelro",
        "-hash-style=gnu",
        "--hash-style=gnu",
        "-build-id",
        "--build-id",
        "--eh-frame-hdr",
        "-m",
        "elf_x86_64",
        "-dynamic-linker",
        "/lib64/ld-linux-x86-64.so.2",
        "-o",
        "/build/target/debug/deps/c1-a212b73b12b6d123",
        "/lib/x86_64-linux-gnu/Scrt1.o",
        "/lib/x86_64-linux-gnu/crti.o",
        "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/crtbeginS.o",
        "-L/build/target/debug/deps",
        "-L/tool/lib/rustlib/x86_64/lib",
        "-L/tool/lib/rustlib/x86_64/lib",
        "-L/usr/bin/../lib/gcc/x86_64-linux-gnu/12",
        "-L/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../lib64",
        "-L/lib/x86_64-linux-gnu",
        "-L/lib/../lib64",
        "-L/usr/lib/x86_64-linux-gnu",
        "-L/usr/lib/../lib64",
        "-L",
        "/lib",
        "-L/usr/lib",
        "/tmp/rustcDcR20O/symbols.o",
        "/build/target/debug/deps/c1-a212b73b12b6d123.1.rcgu.o",
        "/build/target/debug/deps/c1-a212b73b12b6d123.2.rcgu.o",
        "/build/target/debug/deps/c1-a212b73b12b6d123.3.rcgu.o",
        "/build/target/debug/deps/c1-a212b73b12b6d123.4.rcgu.o",
        "/build/target/debug/deps/c1-a212b73b12b6d123.5.rcgu.o",
        "/build/target/debug/deps/c1-a212b73b12b6d123.6.rcgu.o",
        "/build/target/debug/deps/c1-a212b73b12b6d123.7.rcgu.o",
        "--as-needed",
        "-as-needed",
        "-Bstatic",
        "/tool/lib/rustlib/x86_64/lib/libstd-6498d8891e016dca.rlib",
        "/tool/lib/rustlib/x86_64/lib/libpanic_unwind-3debdee1a9058d84.rlib",
        "/tool/lib/rustlib/x86_64/lib/libobject-8339c5bd5cbc92bf.rlib",
        "/tool/lib/rustlib/x86_64/lib/libmemchr-160ebcebb54c11ba.rlib",
        "/tool/lib/rustlib/x86_64/lib/libaddr2line-95c75789f1b65e37.rlib",
        "/tool/lib/rustlib/x86_64/lib/libgimli-7e8094f2d6258832.rlib",
        "/tool/lib/rustlib/x86_64/lib/librustc_demangle-bac9783ef1b45db0.rlib",
        "/tool/lib/rustlib/x86_64/lib/libstd_detect-a1cd87df2f2d8e76.rlib",
        "/tool/lib/rustlib/x86_64/lib/libhashbrown-7fd06d468d7dba16.rlib",
        "/tool/lib/rustlib/x86_64/lib/librustc_std_workspace_alloc-5ac19487656e05bf.rlib",
        "/tool/lib/rustlib/x86_64/lib/libminiz_oxide-c7c35d32cf825c11.rlib",
        "/tool/lib/rustlib/x86_64/lib/libadler-c523f1571362e70b.rlib",
        "/tool/lib/rustlib/x86_64/lib/libunwind-85f17c92b770a911.rlib",
        "/tool/lib/rustlib/x86_64/lib/libcfg_if-598d3ba148dadcea.rlib",
        "/tool/lib/rustlib/x86_64/lib/liblibc-a58ec2dab545caa4.rlib",
        "/tool/lib/rustlib/x86_64/lib/liballoc-f9dda8cca149f0fc.rlib",
        "/tool/lib/rustlib/x86_64/lib/librustc_std_workspace_core-7ba4c315dd7a3503.rlib",
        "/tool/lib/rustlib/x86_64/lib/libcore-5ac2993e19124966.rlib",
        "/tool/lib/rustlib/x86_64/lib/libcompiler_builtins-df2fb7f50dec519a.rlib",
        "-Bdynamic",
        "-lgcc_s",
        "-lutil",
        "-lrt",
        "-lpthread",
        "-lm",
        "-ldl",
        "-lc",
        "--eh-frame-hdr",
        "-z",
        "noexecstack",
        "-znoexecstack",
        "--gc-sections",
        "-z",
        "relro",
        "-z",
        "now",
        "-z",
        "lazy",
        "-soname=fpp",
        "-soname",
        "bar",
        "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/crtendS.o",
        "/lib/x86_64-linux-gnu/crtn.o",
        "--version-script",
        "a.ver",
        "--no-threads",
        "--no-add-needed",
        "--no-copy-dt-needed-entries",
        "--discard-locals",
        "--use-android-relr-tags",
        "--pack-dyn-relocs=relr",
        "-X",
        "-EL",
        "-O",
        "1",
        "-O3",
        "-v",
        "--sysroot=/usr/aarch64-linux-gnu",
        "--demangle",
        "--no-demangle",
        "-l:lib85caec4suo0pxg06jm2ma7b0o.so",
        "-rpath",
        "foo/",
        "-rpath=bar/",
        "-Rbaz",
        "-R",
        "somewhere",
        // Adding the same rpath multiple times should not create duplicates
        "-rpath",
        "foo/",
        "-x",
        "--discard-all",
        "--dependency-file=deps.d",
    ];

    const FILE_OPTIONS: &[&str] = &["-pie"];

    const INLINE_OPTIONS: &[&str] = &["-L", "/lib"];

    fn write_options_to_file(file: &File, options: &[&str]) {
        let mut writer = BufWriter::new(file);
        for option in options {
            writeln!(writer, "{option}").expect("Failed to write to temporary file");
        }
    }

    #[track_caller]
    fn assert_contains(c: &[Box<Path>], v: &str) {
        assert!(c.iter().any(|p| p.as_ref() == Path::new(v)));
    }

    fn input1_assertions(args: &Args) {
        assert_eq!(
            args.inputs
                .iter()
                .filter_map(|i| match &i.spec {
                    InputSpec::File(_) | InputSpec::Search(_) => None,
                    InputSpec::Lib(lib_name) => Some(lib_name.as_ref()),
                })
                .collect_vec(),
            &["gcc_s", "util", "rt", "pthread", "m", "dl", "c"]
        );
        assert_contains(&args.lib_search_path, "/lib");
        assert_contains(&args.lib_search_path, "/usr/lib");
        assert!(!args.inputs.iter().any(|i| match &i.spec {
            InputSpec::File(f) => f.as_ref() == Path::new("/usr/bin/ld"),
            InputSpec::Lib(_) | InputSpec::Search(_) => false,
        }));
        assert_eq!(
            args.version_script_path,
            Some(PathBuf::from_str("a.ver").unwrap())
        );
        assert_eq!(args.soname, Some("bar".to_owned()));
        assert_eq!(args.num_threads, Some(NonZeroUsize::new(1).unwrap()));
        assert_eq!(args.version_mode, VersionMode::Verbose);
        assert_eq!(
            args.sysroot,
            Some(Box::from(Path::new("/usr/aarch64-linux-gnu")))
        );
        assert!(args.inputs.iter().any(|i| match &i.spec {
            InputSpec::File(_) | InputSpec::Lib(_) => false,
            InputSpec::Search(lib) => lib.as_ref() == "lib85caec4suo0pxg06jm2ma7b0o.so",
        }));
        assert_eq!(args.rpath.as_deref(), Some("foo/:bar/:baz:somewhere"));
        assert_eq!(
            args.dependency_file,
            Some(PathBuf::from_str("deps.d").unwrap())
        );
    }

    fn inline_and_file_options_assertions(args: &Args) {
        assert_contains(&args.lib_search_path, "/lib");
    }

    #[test]
    fn test_parse_inline_only_options() {
        let args = super::parse(|| INPUT1.iter()).unwrap();
        input1_assertions(&args);
    }

    #[test]
    fn test_parse_file_only_options() {
        // Create a temporary file containing the same options (one per line) as INPUT1
        let file = NamedTempFile::new().expect("Could not create temp file");
        write_options_to_file(file.as_file(), INPUT1);

        // pass the name of the file where options are as the only inline option "@filename"
        let inline_options = [format!("@{}", file.path().to_str().unwrap())];
        let args = super::parse(|| inline_options.iter()).unwrap();
        input1_assertions(&args);
    }

    #[test]
    fn test_parse_mixed_file_and_inline_options() {
        // Create a temporary file containing some options
        let file = NamedTempFile::new().expect("Could not create temp file");
        write_options_to_file(file.as_file(), FILE_OPTIONS);

        // create an inline option referring to "@filename"
        let file_option = format!("@{}", file.path().to_str().unwrap());
        // start with the set of inline options
        let mut inline_options = INLINE_OPTIONS.to_vec();
        // and extend with the "@filename" option
        inline_options.push(&file_option);

        // confirm that this works and the resulting set of options is correct
        let args = super::parse(|| inline_options.iter()).unwrap();
        inline_and_file_options_assertions(&args);
    }

    #[test]
    fn test_parse_overlapping_file_and_inline_options() {
        // Create a set of file options that has a duplicate of an inline option
        let mut file_options = FILE_OPTIONS.to_vec();
        file_options.append(&mut INLINE_OPTIONS.to_vec());
        // and save them to a file
        let file = NamedTempFile::new().expect("Could not create temp file");
        write_options_to_file(file.as_file(), &file_options);

        // pass the name of the file where options are, as an inline option "@filename"
        let file_option = format!("@{}", file.path().to_str().unwrap());
        // start with the set of inline options
        let mut inline_options = INLINE_OPTIONS.to_vec();
        // and extend with the "@filename" option
        inline_options.push(&file_option);

        // confirm that this works and the resulting set of options is correct
        let args = super::parse(|| inline_options.iter()).unwrap();
        inline_and_file_options_assertions(&args);
    }

    #[test]
    fn test_parse_recursive_file_option() {
        // Create a temporary file containing a @file option
        let file1 = NamedTempFile::new().expect("Could not create temp file");
        let file2 = NamedTempFile::new().expect("Could not create temp file");
        let file_option = format!("@{}", file2.path().to_str().unwrap());
        write_options_to_file(file1.as_file(), &[&file_option]);
        write_options_to_file(file2.as_file(), INPUT1);

        // pass the name of the file where options are, as an inline option "@filename"
        let inline_options = [format!("@{}", file1.path().to_str().unwrap())];

        // confirm that this works and the resulting set of options is correct
        let args = super::parse(|| inline_options.iter())
            .expect("Recursive @file options should parse correctly but be ignored");
        input1_assertions(&args);
    }

    #[test]
    fn test_arguments_from_string() {
        use super::arguments_from_string;

        assert!(arguments_from_string("").unwrap().is_empty());
        assert!(arguments_from_string("''").unwrap().is_empty());
        assert!(arguments_from_string("\"\"").unwrap().is_empty());
        assert_eq!(
            arguments_from_string(r#""foo" "bar""#).unwrap(),
            ["foo", "bar"]
        );
        assert_eq!(
            arguments_from_string(r#""foo\"" "\"b\"ar""#).unwrap(),
            ["foo\"", "\"b\"ar"]
        );
        assert_eq!(
            arguments_from_string("   foo  bar      ").unwrap(),
            ["foo", "bar"]
        );
        assert!(arguments_from_string("'foo''bar'").is_err());
        assert_eq!(
            arguments_from_string("'foo' 'bar' baz").unwrap(),
            ["foo", "bar", "baz"]
        );
        assert_eq!(arguments_from_string("foo\nbar").unwrap(), ["foo", "bar"]);
        assert_eq!(
            arguments_from_string(r#"'foo' "bar" baz"#).unwrap(),
            ["foo", "bar", "baz"]
        );
        assert_eq!(arguments_from_string("'foo bar'").unwrap(), ["foo bar"]);
        assert_eq!(
            arguments_from_string("'foo \"  bar'").unwrap(),
            ["foo \"  bar"]
        );
        assert!(arguments_from_string("foo\\").is_err());
        assert!(arguments_from_string("'foo").is_err());
        assert!(arguments_from_string("foo\"").is_err());
    }

    #[test]
    fn test_ignored_flags() {
        for flag in SILENTLY_IGNORED_FLAGS {
            assert!(!flag.starts_with('-'));
        }
    }
}
