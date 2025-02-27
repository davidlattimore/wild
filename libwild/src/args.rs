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
use crate::error::Result;
use crate::input_data::FileId;
use crate::linker_script::maybe_forced_sysroot;
use crate::save_dir::SaveDir;
use anyhow::Context as _;
use anyhow::bail;
use anyhow::ensure;
use rayon::ThreadPoolBuilder;
use std::num::NonZeroUsize;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;

pub(crate) struct Args {
    pub(crate) arch: Architecture,
    pub(crate) lib_search_path: Vec<Box<Path>>,
    pub(crate) inputs: Vec<Input>,
    pub(crate) output: Arc<Path>,
    pub(crate) dynamic_linker: Option<Box<Path>>,
    pub(crate) num_threads: NonZeroUsize,
    pub(crate) strip_all: bool,
    pub(crate) strip_debug: bool,
    pub(crate) prepopulate_maps: bool,
    pub(crate) sym_info: Option<String>,
    pub(crate) merge_strings: bool,
    pub(crate) debug_fuel: Option<AtomicI64>,
    pub(crate) time_phases: bool,
    pub(crate) validate_output: bool,
    pub(crate) version_script_path: Option<PathBuf>,
    pub(crate) debug_address: Option<u64>,
    pub(crate) write_layout: bool,
    pub(crate) should_write_eh_frame_hdr: bool,
    pub(crate) write_trace: bool,
    pub(crate) rpaths: Vec<String>,
    pub(crate) soname: Option<String>,
    pub(crate) files_per_group: Option<u32>,
    pub(crate) gc_sections: bool,
    pub(crate) should_fork: bool,
    pub(crate) build_id: BuildIdOption,
    pub(crate) file_write_mode: FileWriteMode,
    pub(crate) no_undefined: bool,
    pub(crate) allow_copy_relocations: bool,
    pub(crate) sysroot: Option<Box<Path>>,

    /// If set, GC stats will be written to the specified filename.
    pub(crate) write_gc_stats: Option<PathBuf>,

    /// If set, and we're writing GC stats, then ignore any input files that contain any of the
    /// specified substrings.
    pub(crate) gc_stats_ignore: Vec<String>,

    pub(crate) verbose_gc_stats: bool,

    pub(crate) print_allocations: Option<FileId>,
    pub(crate) execstack: bool,
    pub(crate) verify_allocation_consistency: bool,
    pub(crate) should_print_version: bool,
    pub(crate) demangle: bool,

    output_kind: Option<OutputKind>,
    is_dynamic_executable: bool,
    relocation_model: RelocationModel,
}

#[derive(Debug)]
pub(crate) enum BuildIdOption {
    None,
    Fast,
    Hex(Vec<u8>),
    Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputKind {
    StaticExecutable(RelocationModel),
    DynamicExecutable(RelocationModel),
    SharedObject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelocationModel {
    NonRelocatable,
    Relocatable,
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
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub(crate) struct Modifiers {
    /// Whether shared objects should only be linked if they're referenced.
    pub(crate) as_needed: bool,

    /// Whether we're currently allowed to link against shared libraries.
    pub(crate) allow_shared: bool,

    /// Whether object files in archives should be linked even if they do not contain symbols that
    /// are referenced.
    pub(crate) whole_archive: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Input {
    pub(crate) spec: InputSpec,
    /// A directory to search first. Only present when the input came from a linker script, in which
    /// case this is the directory containing the linker script.
    pub(crate) search_first: Option<PathBuf>,
    pub(crate) modifiers: Modifiers,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum InputSpec {
    File(Box<Path>),
    Lib(Box<str>),
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
    // Just like other modern linkers, we don't need groups in order resolve cycles.
    "start-group",
    "end-group",
    "(",
    ")",
    // TODO: This is supposed to suppress built-in search paths, but I don't think we have any
    // built-in search paths. Perhaps we should?
    "nostdlib",
    // TODO
    "no-undefined-version",
    "export-dynamic",
    "fatal-warnings",
    "color-diagnostics",
    "undefined-version",
    "sort-common",
    "no-relax",
];

const IGNORED_FLAGS: &[&str] = &[
    "gdb-index",
    "disable-new-dtags",
    "fix-cortex-a53-835769",
    "fix-cortex-a53-843419",
    "no-export-dynamic",
];

// These flags map to the default behavior of the linker.
const DEFAULT_FLAGS: &[&str] = &[
    "no-call-graph-profile-sort",
    "relax",
    "no-copy-dt-needed-entries",
    "no-add-needed",
    "discard-locals",
    "X",  // alias for --discard-locals
    "EL", // little endian
];

pub(crate) fn available_parallelism() -> std::num::NonZeroUsize {
    std::thread::available_parallelism().unwrap_or(std::num::NonZeroUsize::new(1).unwrap())
}

impl Default for Args {
    fn default() -> Self {
        Args {
            arch: default_target_arch(),

            lib_search_path: Vec::new(),
            inputs: Vec::new(),
            output: Arc::from(Path::new("a.out")),
            is_dynamic_executable: false,
            dynamic_linker: None,
            output_kind: None,
            time_phases: false,
            num_threads: available_parallelism(),
            strip_all: false,
            strip_debug: false,
            // For now, we default to --gc-sections. This is different to other linkers, but other than
            // being different, there doesn't seem to be any downside to doing this. We don't currently do
            // any less work if we're not GCing sections, but do end up writing more, so --no-gc-sections
            // will almost always be as slow or slower than --gc-sections. For that reason, the latter is
            // probably a good default.
            gc_sections: true,
            prepopulate_maps: false,
            sym_info: None,
            merge_strings: true,
            allow_copy_relocations: true,
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
            gc_stats_ignore: Vec::new(),
            verbose_gc_stats: false,
            rpaths: Vec::new(),
            soname: None,
            execstack: false,
            should_fork: true,
            file_write_mode: FileWriteMode::UnlinkAndReplace,
            build_id: BuildIdOption::None,
            files_per_group: None,
            no_undefined: false,
            should_print_version: false,
            sysroot: None,
            demangle: true,
        }
    }
}

// Parse the supplied input arguments, which should not include the program name.
pub(crate) fn parse<S: AsRef<str>, I: Iterator<Item = S>>(mut input: I) -> Result<Args> {
    let mut args = Args {
        files_per_group: std::env::var(FILES_PER_GROUP_ENV)
            .ok()
            .map(|s| s.parse())
            .transpose()?,
        ..Default::default()
    };

    let mut unrecognised = Vec::new();

    let mut save_dir = SaveDir::new()?;

    let mut modifier_stack = vec![Modifiers::default()];

    if std::env::var(REFERENCE_LINKER_ENV).is_ok() {
        args.write_layout = true;
        args.write_trace = true;
    }
    let mut arg_num = 0;
    while let Some(arg) = input.next() {
        arg_num += 1;
        let arg = arg.as_ref();

        fn strip_option(arg: &str) -> Option<&str> {
            arg.strip_prefix("--").or(arg.strip_prefix('-'))
        }
        let long_arg_eq = |option: &str| {
            assert!(
                !option.starts_with('-'),
                "option cannot start with a dash: `{option}`"
            );
            strip_option(arg) == Some(option)
        };
        let long_arg_split_prefix = |option: &str| -> Option<&str> {
            assert!(!option.starts_with('-'));
            assert!(option.ends_with('='));
            strip_option(arg).and_then(|stripped_arg| stripped_arg.strip_prefix(option))
        };
        let mut handle_z_option = |arg: &str| -> Result {
            match arg {
                "now" => {}
                "origin" => {}
                "norelro" => {}
                "notext" => {}
                "nostart-stop-gc" => {}
                "execstack" => args.execstack = true,
                "noexecstack" => args.execstack = false,
                "nocopyreloc" => args.allow_copy_relocations = false,
                _ => {
                    warn_unsupported(&format!("-z {arg}"))?;
                    // TODO: Handle these
                }
            }
            Ok(())
        };

        if let Some(rest) = arg.strip_prefix("-L") {
            let handle_sysroot = |path| {
                args.sysroot
                    .as_ref()
                    .and_then(|sysroot| maybe_forced_sysroot(path, sysroot))
                    .unwrap_or_else(|| Box::from(path))
            };
            if rest.is_empty() {
                if let Some(next) = input.next() {
                    args.lib_search_path
                        .push(handle_sysroot(Path::new(next.as_ref())));
                }
            } else {
                args.lib_search_path.push(handle_sysroot(Path::new(rest)));
            }
        } else if let Some(rest) = arg.strip_prefix("-l") {
            args.inputs.push(Input {
                spec: InputSpec::Lib(Box::from(rest)),
                search_first: None,
                modifiers: *modifier_stack.last().unwrap(),
            });
        } else if long_arg_eq("static") || long_arg_eq("Bstatic") {
            modifier_stack.last_mut().unwrap().allow_shared = false;
        } else if long_arg_eq("Bdynamic") {
            modifier_stack.last_mut().unwrap().allow_shared = true;
        } else if arg == "-o" {
            args.output = input
                .next()
                .map(|a| Arc::from(Path::new(a.as_ref())))
                .context("Missing argument to -o")?;
        } else if long_arg_eq("dynamic-linker") {
            args.is_dynamic_executable = true;
            args.dynamic_linker = input.next().map(|a| Box::from(Path::new(a.as_ref())));
        } else if let Some(rest) = long_arg_split_prefix("dynamic-linker=") {
            args.is_dynamic_executable = true;
            args.dynamic_linker = Some(Box::from(Path::new(rest)));
        } else if long_arg_eq("no-dynamic-linker") {
            args.dynamic_linker = None;
        } else if let Some(style) = long_arg_split_prefix("hash-style=") {
            // We don't technically support both hash styles, but if requested to do both, we just
            // do GNU, which we do support.
            if style != "gnu" && style != "both" {
                bail!("Unsupported hash-style `{style}`");
            }
            // Since we currently only support GNU hash, there's no state to update.
        } else if long_arg_eq("build-id") {
            args.build_id = BuildIdOption::Fast;
        } else if let Some(build_id_value) = long_arg_split_prefix("build-id=") {
            args.build_id = match build_id_value {
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
        } else if let Some(value) = long_arg_split_prefix("icf=") {
            match value {
                "none" => {}
                other => warn_unsupported(&format!("--icf={other}"))?,
            }
        } else if long_arg_eq("time") {
            args.time_phases = true;
        } else if let Some(rest) = long_arg_split_prefix("threads=") {
            args.num_threads = NonZeroUsize::try_from(rest.parse::<usize>()?)?;
        } else if long_arg_eq("threads") {
            // Default behaviour (multiple threads)
            args.num_threads = available_parallelism();
        } else if let Some(rest) = long_arg_split_prefix("thread-count=") {
            args.num_threads = NonZeroUsize::try_from(rest.parse::<usize>()?)?;
        } else if long_arg_eq("no-threads") {
            args.num_threads = NonZeroUsize::new(1).unwrap();
        } else if long_arg_eq("strip-all") || arg == "-s" {
            args.strip_all = true;
            args.strip_debug = true;
        } else if long_arg_eq("strip-debug") || arg == "-S" {
            args.strip_debug = true;
        } else if long_arg_eq("gc-sections") {
            args.gc_sections = true;
        } else if long_arg_eq("no-gc-sections") {
            args.gc_sections = false;
        } else if long_arg_eq("no-fork") {
            args.should_fork = false;
        } else if long_arg_eq("update-in-place") {
            args.file_write_mode = FileWriteMode::UpdateInPlace;
        } else if arg == "-m" {
            let arg_value = input.next().context("Missing argument to -m")?;
            let arg_value = arg_value.as_ref();
            args.arch = Architecture::from_str(arg_value)?;
        } else if let Some(arg_value) = arg.strip_prefix("-m") {
            args.arch = Architecture::from_str(arg_value)?;
        } else if long_arg_eq("EB") {
            bail!("Big-endian target is not supported");
        } else if arg == "-z" {
            handle_z_option(input.next().context("Missing argument to -z")?.as_ref())?;
        } else if let Some(arg) = arg.strip_prefix("-z") {
            handle_z_option(arg)?;
        } else if let Some(_rest) = arg.strip_prefix("-O") {
            // We don't use opt-level for now.
        } else if long_arg_eq("prepopulate-maps") {
            args.prepopulate_maps = true;
        } else if long_arg_eq("sym-info") {
            args.sym_info = input.next().map(|a| a.as_ref().to_owned());
        } else if long_arg_eq("as-needed") {
            modifier_stack.last_mut().unwrap().as_needed = true;
        } else if long_arg_eq("no-as-needed") {
            modifier_stack.last_mut().unwrap().as_needed = false;
        } else if long_arg_eq("whole-archive") {
            modifier_stack.last_mut().unwrap().whole_archive = true;
        } else if long_arg_eq("no-whole-archive") {
            modifier_stack.last_mut().unwrap().whole_archive = false;
        } else if long_arg_eq("push-state") {
            modifier_stack.push(*modifier_stack.last().unwrap());
        } else if long_arg_eq("pop-state") {
            modifier_stack.pop();
            // We put the initial value on the stack, so if it's ever empty, then the arguments
            // are invalid.
            if modifier_stack.is_empty() {
                bail!("Mismatched --pop-state");
            }
        } else if long_arg_eq("version-script") {
            let script = input
                .next()
                .context("Missing argument to -version-script")?
                .as_ref()
                .to_owned();
            save_dir.handle_file(&script)?;
            args.version_script_path = Some(PathBuf::from(script));
        } else if let Some(script) = long_arg_split_prefix("version-script=") {
            save_dir.handle_file(script)?;
            args.version_script_path = Some(PathBuf::from(script));
        } else if long_arg_eq("rpath") {
            args.rpaths.push(
                input
                    .next()
                    .context("Missing argument to -rpath")?
                    .as_ref()
                    .to_owned(),
            );
        } else if let Some(rest) = long_arg_split_prefix("rpath=") {
            args.rpaths.push(rest.to_owned());
        } else if long_arg_eq("no-string-merge") {
            args.merge_strings = false;
        } else if long_arg_eq("pie") {
            args.relocation_model = RelocationModel::Relocatable;
        } else if long_arg_eq("no-pie") {
            args.relocation_model = RelocationModel::NonRelocatable;
        } else if long_arg_eq("eh-frame-hdr") {
            args.should_write_eh_frame_hdr = true;
        } else if long_arg_eq("shared") {
            args.output_kind = Some(OutputKind::SharedObject);
        } else if let Some(rest) = long_arg_split_prefix("soname=") {
            args.soname = Some(rest.to_owned());
        } else if long_arg_eq("soname") {
            args.soname = Some(
                input
                    .next()
                    .context("Missing argument to -soname")?
                    .as_ref()
                    .to_owned(),
            );
        } else if long_arg_split_prefix("plugin-opt=").is_some() {
            // TODO: Implement support for linker plugins.
        } else if long_arg_eq("plugin") {
            let other = input
                .next()
                .context("Missing argument to --plugin")?
                .as_ref()
                .to_owned();
            warn_unsupported(&format!("--plugin {other}"))?;
        } else if let Some(rest) = long_arg_split_prefix("dependency-file=") {
            warn_unsupported(&format!("--dependency-file={rest}"))?;
        } else if long_arg_eq("rpath-link") {
            // TODO
            input.next();
        } else if long_arg_eq("validate-output") {
            args.validate_output = true;
        } else if long_arg_eq("write-layout") {
            args.write_layout = true;
        } else if long_arg_eq("write-trace") {
            args.write_trace = true;
        } else if let Some(rest) = long_arg_split_prefix("write-gc-stats=") {
            args.write_gc_stats = Some(PathBuf::from(rest));
        } else if let Some(rest) = long_arg_split_prefix("gc-stats-ignore=") {
            args.gc_stats_ignore.push(rest.to_owned());
        } else if long_arg_eq("version") || arg == "-v" {
            args.should_print_version = true;
        } else if long_arg_eq("verbose-gc-stats") {
            args.verbose_gc_stats = true;
        } else if let Some(rest) = long_arg_split_prefix("debug-address=") {
            args.debug_address = Some(parse_number(rest).context("Invalid --debug-address")?);
        } else if let Some(rest) = long_arg_split_prefix("debug-fuel=") {
            args.debug_fuel = Some(AtomicI64::new(rest.parse()?));
            // Using debug fuel with more than one thread would likely give non-deterministic
            // results.
            args.num_threads = NonZeroUsize::new(1).unwrap();
        } else if long_arg_eq("no-undefined") {
            args.no_undefined = true;
        } else if long_arg_eq("demangle") {
            args.demangle = true;
        } else if long_arg_eq("no-demangle") {
            args.demangle = false;
        } else if let Some(path) = arg.strip_prefix('@') {
            if input.next().is_some() || arg_num > 1 {
                bail!("Mixing of @{{filename}} and regular arguments isn't supported");
            }
            return parse_from_argument_file(Path::new(path));
        } else if long_arg_eq("help") {
            bail!("Sorry, help isn't implemented yet");
        } else if strip_option(arg)
            .is_some_and(|stripped_arg| DEFAULT_FLAGS.contains(&stripped_arg))
        { // These flags are mapped to the default behaviour of the linker.
        } else if strip_option(arg)
            .is_some_and(|stripped_arg| IGNORED_FLAGS.contains(&stripped_arg))
        {
            warn_unsupported(arg)?;
        } else if strip_option(arg)
            .is_some_and(|stripped_arg| SILENTLY_IGNORED_FLAGS.contains(&stripped_arg))
        {
        } else if let Some(sysroot) = long_arg_split_prefix("sysroot=") {
            let sysroot = Path::new(sysroot);
            args.sysroot = Some(Box::from(sysroot));
            for path in &mut args.lib_search_path {
                if let Some(new_path) = maybe_forced_sysroot(path, sysroot) {
                    *path = new_path;
                }
            }
        } else if arg.starts_with('-') {
            unrecognised.push(format!("`{arg}`"));
        } else {
            save_dir.handle_file(arg)?;
            args.inputs.push(Input {
                spec: InputSpec::File(Box::from(Path::new(arg))),
                search_first: None,
                modifiers: *modifier_stack.last().unwrap(),
            });
        }
    }

    if !unrecognised.is_empty() {
        bail!("Unrecognised argument(s): {}", unrecognised.join(" "));
    }

    save_dir.finish()?;

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
}

fn parse_from_argument_file(path: &Path) -> Result<Args> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read arguments from file `{}`", path.display()))?;
    parse(arguments_from_string(&contents)?.into_iter())
}

impl Args {
    pub(crate) fn setup_thread_pool(&self) -> Result {
        ThreadPoolBuilder::new()
            .num_threads(self.num_threads.get())
            .build_global()?;
        Ok(())
    }

    pub(crate) fn base_address(&self) -> u64 {
        if self.is_relocatable() {
            0
        } else {
            crate::elf::NON_PIE_START_MEM_ADDRESS
        }
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

    pub(crate) fn needs_dynsym(&self) -> bool {
        self.output_kind().needs_dynsym()
    }

    pub(crate) fn is_relocatable(&self) -> bool {
        self.output_kind().is_relocatable()
    }

    /// Returns whether we need a dynamic section.
    pub(crate) fn needs_dynamic(&self) -> bool {
        self.output_kind().needs_dynamic()
    }

    #[allow(dead_code)]
    pub(crate) fn should_debug_address(&self, address: u64) -> bool {
        self.debug_address
            .is_some_and(|a| address >= a && address < a + 8)
    }

    pub(crate) fn should_output_symbol_versions(&self) -> bool {
        matches!(
            self.output_kind(),
            OutputKind::DynamicExecutable(_) | OutputKind::SharedObject
        )
    }

    pub(crate) fn trace_span_for_file(
        &self,
        file_id: FileId,
    ) -> Option<tracing::span::EnteredSpan> {
        let should_trace = self.print_allocations == Some(file_id);
        should_trace.then(|| tracing::trace_span!(crate::debug_trace::TRACE_SPAN_NAME).entered())
    }

    pub(crate) fn should_fork(&self) -> bool {
        self.should_fork
    }

    pub(crate) fn output_kind(&self) -> OutputKind {
        self.output_kind.unwrap_or({
            if self.is_dynamic_executable {
                OutputKind::DynamicExecutable(self.relocation_model)
            } else {
                OutputKind::StaticExecutable(self.relocation_model)
            }
        })
    }

    pub(crate) fn loadable_segment_alignment(&self) -> Alignment {
        match self.arch {
            Architecture::X86_64 => Alignment { exponent: 12 },
            Architecture::AArch64 => Alignment { exponent: 16 },
        }
    }
}

fn parse_number(s: &str) -> Result<u64> {
    if let Some(s) = s.strip_prefix("0x") {
        Ok(u64::from_str_radix(s, 16)?)
    } else {
        Ok(s.parse::<u64>()?)
    }
}

impl Default for Modifiers {
    fn default() -> Self {
        Self {
            as_needed: false,
            allow_shared: true,
            whole_archive: false,
        }
    }
}

impl OutputKind {
    pub(crate) fn is_executable(self) -> bool {
        !matches!(self, OutputKind::SharedObject)
    }

    pub(crate) fn is_static_executable(self) -> bool {
        matches!(self, OutputKind::StaticExecutable(_))
    }

    pub(crate) fn is_relocatable(self) -> bool {
        matches!(
            self,
            OutputKind::StaticExecutable(RelocationModel::Relocatable)
                | OutputKind::DynamicExecutable(RelocationModel::Relocatable)
                | OutputKind::SharedObject
        )
    }

    pub(crate) fn needs_dynsym(self) -> bool {
        matches!(
            self,
            OutputKind::DynamicExecutable(_)
                | OutputKind::SharedObject
                // It seems a bit weird to have dynsym in a static-PIE binary, but that's what GNU
                // ld does. It just doesn't have any symbols besides the undefined symbol.
                | OutputKind::StaticExecutable(RelocationModel::Relocatable)
        )
    }

    fn needs_dynamic(self) -> bool {
        self != OutputKind::StaticExecutable(RelocationModel::NonRelocatable)
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

#[cfg(test)]
mod tests {
    use super::SILENTLY_IGNORED_FLAGS;
    use crate::args::InputSpec;
    use itertools::Itertools;
    use std::num::NonZeroUsize;
    use std::path::Path;
    use std::path::PathBuf;
    use std::str::FromStr;

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
        "-X",
        "-EL",
        "-v",
        "--sysroot=/usr/aarch64-linux-gnu",
        "--demangle",
        "--no-demangle",
    ];

    #[track_caller]
    fn assert_contains(c: &[Box<Path>], v: &str) {
        assert!(c.iter().any(|p| p.as_ref() == Path::new(v)));
    }

    #[test]
    fn test_parse() {
        let args = super::parse(INPUT1.iter()).unwrap();
        assert!(args.is_relocatable());
        assert_eq!(
            args.inputs
                .iter()
                .filter_map(|i| match &i.spec {
                    InputSpec::File(_) => None,
                    InputSpec::Lib(lib_name) => Some(lib_name.as_ref()),
                })
                .collect_vec(),
            &["gcc_s", "util", "rt", "pthread", "m", "dl", "c"]
        );
        assert_contains(&args.lib_search_path, "/lib");
        assert_contains(&args.lib_search_path, "/usr/lib");
        assert!(!args.inputs.iter().any(|i| match &i.spec {
            InputSpec::File(f) => f.as_ref() == Path::new("/usr/bin/ld"),
            InputSpec::Lib(_) => false,
        }));
        assert_eq!(
            args.version_script_path,
            Some(PathBuf::from_str("a.ver").unwrap())
        );
        assert_eq!(args.soname, Some("bar".to_owned()));
        assert_eq!(args.num_threads, NonZeroUsize::new(1).unwrap());
        assert!(args.should_print_version);
        assert_eq!(
            args.sysroot,
            Some(Box::from(Path::new("/usr/aarch64-linux-gnu")))
        );
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
