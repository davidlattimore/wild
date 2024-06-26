//! A hand-written parser for our arguments. We don't currently use a 3rd party library because
//! order is important for some arguments and it's not clear how easy it would be to get that
//! correct with something like clap.

use crate::error::Result;
use crate::save_dir::SaveDir;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context as _;
use std::num::NonZeroUsize;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

pub(crate) struct Args {
    pub(crate) lib_search_path: Vec<Box<Path>>,
    pub(crate) inputs: Vec<Input>,
    pub(crate) output: Arc<Path>,
    pub(crate) dynamic_linker: Option<Box<Path>>,
    pub(crate) output_kind: OutputKind,
    pub(crate) num_threads: NonZeroUsize,
    pub(crate) strip_all: bool,
    pub(crate) strip_debug: bool,
    pub(crate) prepopulate_maps: bool,
    pub(crate) sym_info: Option<String>,
    pub(crate) merge_strings: bool,
    pub(crate) debug_fuel: Option<AtomicI64>,
    pub(crate) time_phases: bool,
    pub(crate) validate_output: bool,
    pub(crate) pie: bool,
    pub(crate) version_script_path: Option<PathBuf>,
    pub(crate) debug_address: Option<u64>,
    pub(crate) bind_now: bool,
    pub(crate) write_layout: bool,
    pub(crate) hash_style: Option<HashStyle>,
    pub(crate) should_write_eh_frame_hdr: bool,
    pub(crate) write_trace: bool,

    /// If set, GC stats will be written to the specified filename.
    pub(crate) write_gc_stats: Option<PathBuf>,

    /// If set and we're writing GC stats, then ignore any input files that contain any of the
    /// specified substrings.
    pub(crate) gc_stats_ignore: Vec<String>,

    pub(crate) verbose_gc_stats: bool,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum Action {
    /// The default. Link something.
    Link(Args),

    /// Print the linker version.
    Version,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputKind {
    NonRelocatableStaticExecutable,
    PositionIndependentStaticExecutable,
    DynamicExecutable,
    SharedObject,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub(crate) struct Modifiers {
    /// Whether shared objects should only be linked if they're referenced.
    pub(crate) as_needed: bool,

    /// Whether we're currently allowed to link against shared libraries.
    pub(crate) allow_shared: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashStyle {
    Gnu,
}

pub const VALIDATE_ENV: &str = "WILD_VALIDATE_OUTPUT";
pub const WRITE_LAYOUT_ENV: &str = "WILD_WRITE_LAYOUT";
pub const WRITE_TRACE_ENV: &str = "WILD_WRITE_TRACE";
pub const REFERENCE_LINKER_ENV: &str = "WILD_REFERENCE_LINKER";

// These flags don't currently affect our behaviour. TODO: Assess whether we should error or warn if
// these are given. This is tricky though. On the one hand we want to be a drop-in replacement for
// other linkers. On the other, we should perhaps somehow let the user know that we don't support a
// feature.
const IGNORED_FLAGS: &[&str] = &[
    // TODO: Support build-ids
    "--build-id",
    // TODO: We currently always GC sections. Support _not_ GCing them.
    "--gc-sections",
    // TODO: Think about if anything is needed here. We don't need groups in order resolve cycles,
    // so perhaps ignoring these is the right thing to do.
    "--start-group",
    "--end-group",
    // TODO: This is supposed to suppress built-in search paths, but I don't think we have any
    // built-in search paths. Perhaps we should?
    "-nostdlib",
    // TODO
    "--no-undefined-version",
];

pub(crate) fn from_env() -> Result<Action> {
    parse(std::env::args())
}

// Parse the supplied input arguments, which should not include the program name.
#[allow(clippy::if_same_then_else)]
pub(crate) fn parse<S: AsRef<str>, I: Iterator<Item = S>>(mut input: I) -> Result<Action> {
    let mut lib_search_path = Vec::new();
    let mut inputs = Vec::new();
    let mut output = None;
    let mut dynamic_linker = None;
    let mut output_kind = None;
    let mut time_phases = false;
    let mut num_threads = None;
    let mut strip_all = false;
    let mut strip_debug = false;
    let mut prepopulate_maps = false;
    let mut save_dir = SaveDir::new()?;
    let mut sym_info = None;
    let mut merge_strings = true;
    let mut debug_fuel = None;
    let mut validate_output = std::env::var(VALIDATE_ENV).is_ok_and(|v| v == "1");
    let mut write_layout = std::env::var(WRITE_LAYOUT_ENV).is_ok_and(|v| v == "1");
    let mut write_trace = std::env::var(WRITE_TRACE_ENV).is_ok_and(|v| v == "1");
    let mut pie = false;
    let mut modifier_stack = vec![Modifiers::default()];
    let mut version_script_path = None;
    let mut debug_address = None;
    let mut eh_frame_hdr = false;
    let mut write_gc_stats = None;
    let mut gc_stats_ignore = Vec::new();
    let mut verbose_gc_stats = false;
    let mut action = None;
    if std::env::var(REFERENCE_LINKER_ENV).is_ok() {
        write_layout = true;
        write_trace = true;
    }
    // Lazy binding isn't used so much these days, since it makes things less secure. It adds
    // quite a bit of complexity and we don't properly support it. We may eventually drop
    // support completely.
    let mut bind_now = true;
    let mut hash_style = None;
    // Skip program name
    input.next();
    while let Some(arg) = input.next() {
        let arg = arg.as_ref();
        if let Some(rest) = arg.strip_prefix("-L") {
            if rest.is_empty() {
                if let Some(next) = input.next() {
                    lib_search_path.push(Box::from(Path::new(next.as_ref())));
                }
            } else {
                lib_search_path.push(Box::from(Path::new(rest)));
            }
        } else if let Some(rest) = arg.strip_prefix("-l") {
            inputs.push(Input {
                spec: InputSpec::Lib(Box::from(rest)),
                search_first: None,
                modifiers: *modifier_stack.last().unwrap(),
            });
        } else if arg == "-static" || arg == "-Bstatic" {
            modifier_stack.last_mut().unwrap().allow_shared = false;
        } else if arg == "-Bdynamic" {
            modifier_stack.last_mut().unwrap().allow_shared = true;
        } else if arg == "-o" {
            output = input.next().map(|a| Arc::from(Path::new(a.as_ref())));
        } else if arg == "--dynamic-linker" || arg == "-dynamic-linker" {
            output_kind = Some(OutputKind::DynamicExecutable);
            dynamic_linker = input.next().map(|a| Box::from(Path::new(a.as_ref())));
        } else if arg == "--no-dynamic-linker" {
            dynamic_linker = None;
        } else if let Some(style) = arg.strip_prefix("--hash-style=") {
            hash_style = Some(HashStyle::Gnu);
            // We don't technically support both hash styles, but if requested to do both, we just
            // do GNU, which we do support.
            if style != "gnu" && style != "both" {
                bail!("Unsupported hash-style `{style}`");
            }
        } else if arg.starts_with("--build-id=") {
        } else if arg == "--time" {
            time_phases = true;
        } else if let Some(rest) = arg.strip_prefix("--threads=") {
            num_threads = Some(NonZeroUsize::try_from(rest.parse::<usize>()?)?);
        } else if arg == "--strip-all" {
            strip_all = true;
            strip_debug = true;
        } else if arg == "--strip-debug" {
            strip_debug = true;
        } else if arg == "-m" {
            // TODO: Handle these flags
            input.next();
        } else if arg == "-z" {
            if let Some(z) = input.next() {
                match z.as_ref() {
                    "now" => bind_now = true,
                    _ => {
                        // TODO: Handle these
                    }
                }
            }
        } else if let Some(_rest) = arg.strip_prefix("-O") {
            // We don't use opt-level for now.
        } else if arg == "--prepopulate-maps" {
            prepopulate_maps = true;
        } else if arg == "--sym-info" {
            sym_info = input.next().map(|a| a.as_ref().to_owned());
        } else if arg == "--as-needed" {
            modifier_stack.last_mut().unwrap().as_needed = true;
        } else if arg == "--no-as-needed" {
            modifier_stack.last_mut().unwrap().as_needed = false;
        } else if arg == "--push-state" {
            modifier_stack.push(*modifier_stack.last().unwrap());
        } else if arg == "--pop-state" {
            modifier_stack.pop();
            // We put the initial value on the stack, so if it's ever empty, then the arguments
            // are invalid.
            if modifier_stack.is_empty() {
                bail!("Mismatched --pop-state");
            }
        } else if let Some(script) = arg.strip_prefix("--version-script=") {
            save_dir.handle_file(script)?;
            version_script_path = Some(PathBuf::from(script));
        } else if arg == "--no-string-merge" {
            merge_strings = false;
        } else if arg == "-pie" {
            pie = true;
        } else if arg == "--eh-frame-hdr" {
            eh_frame_hdr = true;
        } else if arg == "-shared" {
            output_kind = Some(OutputKind::SharedObject);
        } else if arg.starts_with("-plugin-opt=") {
            // TODO: Implement support for linker plugins.
        } else if arg == "-plugin" {
            input.next();
        } else if arg == "--validate-output" {
            validate_output = true;
        } else if arg == "--write-layout" {
            write_layout = true;
        } else if arg == "--write-trace" {
            write_trace = true;
        } else if let Some(rest) = arg.strip_prefix("--write-gc-stats=") {
            write_gc_stats = Some(PathBuf::from(rest));
        } else if let Some(rest) = arg.strip_prefix("--gc-stats-ignore=") {
            gc_stats_ignore.push(rest.to_owned());
        } else if arg == "--version" {
            action = Some(Action::Version);
        } else if arg == "--verbose-gc-stats" {
            verbose_gc_stats = true;
        } else if let Some(rest) = arg.strip_prefix("--debug-address=") {
            debug_address = Some(parse_number(rest).context("Invalid --debug-address")?);
        } else if let Some(rest) = arg.strip_prefix("--debug-fuel=") {
            debug_fuel = Some(AtomicI64::new(rest.parse()?));
            // Using debug fuel with more than one thread would likely give non-deterministic
            // results.
            num_threads = Some(NonZeroUsize::new(1).unwrap());
        } else if arg == "--help" {
            bail!("Sorry, help isn't implemented yet");
        } else if IGNORED_FLAGS.contains(&arg) {
        } else if arg.starts_with('-') {
            bail!("Unrecognised argument `{arg}`");
        } else {
            save_dir.handle_file(arg)?;
            inputs.push(Input {
                spec: InputSpec::File(Box::from(Path::new(arg))),
                search_first: None,
                modifiers: *modifier_stack.last().unwrap(),
            });
        }
    }
    let num_threads = num_threads.unwrap_or_else(|| {
        std::thread::available_parallelism().unwrap_or(NonZeroUsize::new(1).unwrap())
    });
    let output_kind = output_kind.unwrap_or({
        if pie {
            OutputKind::PositionIndependentStaticExecutable
        } else {
            OutputKind::NonRelocatableStaticExecutable
        }
    });
    if output_kind == OutputKind::NonRelocatableStaticExecutable {
        hash_style = None;
    }
    save_dir.finish()?;
    if let Some(a) = action {
        return Ok(a);
    }
    Ok(Action::Link(Args {
        lib_search_path,
        inputs,
        output: output.ok_or_else(|| anyhow!("Missing required argument -o"))?,
        dynamic_linker,
        output_kind,
        time_phases,
        num_threads,
        strip_all,
        strip_debug,
        prepopulate_maps,
        sym_info,
        merge_strings,
        debug_fuel,
        pie,
        validate_output,
        version_script_path,
        debug_address,
        bind_now,
        write_layout,
        write_trace,
        hash_style,
        should_write_eh_frame_hdr: eh_frame_hdr,
        write_gc_stats,
        gc_stats_ignore,
        verbose_gc_stats,
    }))
}

impl Args {
    pub(crate) fn setup_thread_pool(&self) -> Result {
        rayon::ThreadPoolBuilder::new()
            .num_threads(self.num_threads.get())
            .build_global()?;
        Ok(())
    }

    pub(crate) fn base_address(&self) -> u64 {
        if self.pie {
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

    /// Returns how we should handle TLS relocations like TLSLD and TLSGD.
    pub(crate) fn tls_mode(&self) -> crate::layout::TlsMode {
        match self.output_kind {
            OutputKind::NonRelocatableStaticExecutable
            | OutputKind::PositionIndependentStaticExecutable => crate::layout::TlsMode::LocalExec,
            OutputKind::DynamicExecutable | OutputKind::SharedObject => {
                crate::layout::TlsMode::Preserve
            }
        }
    }

    pub(crate) fn is_relocatable(&self) -> bool {
        self.output_kind.is_relocatable()
    }

    /// Returns whether we need a dynamic section.
    pub(crate) fn needs_dynamic(&self) -> bool {
        self.is_relocatable()
    }

    #[allow(dead_code)]
    pub(crate) fn should_debug_address(&self, address: u64) -> bool {
        self.debug_address
            .is_some_and(|a| address >= a && address < a + 8)
    }

    pub(crate) fn should_output_symbol_versions(&self) -> bool {
        matches!(
            self.output_kind,
            OutputKind::DynamicExecutable | OutputKind::SharedObject
        )
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
        }
    }
}

impl OutputKind {
    pub(crate) fn is_executable(&self) -> bool {
        !matches!(self, OutputKind::SharedObject)
    }

    pub(crate) fn is_static_executable(&self) -> bool {
        matches!(
            self,
            OutputKind::NonRelocatableStaticExecutable
                | OutputKind::PositionIndependentStaticExecutable
        )
    }

    pub(crate) fn is_relocatable(self) -> bool {
        self != OutputKind::NonRelocatableStaticExecutable
    }
}

#[cfg(test)]
mod tests {
    use crate::args::Action;
    use crate::args::InputSpec;
    use std::path::Path;

    const INPUT1: &[&str] = &[
        "wild",
        "-pie",
        "-z",
        "relro",
        "--hash-style=gnu",
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
        "--gc-sections",
        "-z",
        "relro",
        "-z",
        "now",
        "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/crtendS.o",
        "/lib/x86_64-linux-gnu/crtn.o",
    ];

    #[track_caller]
    fn assert_contains(c: &[Box<Path>], v: &str) {
        assert!(c.iter().any(|p| p.as_ref() == Path::new(v)));
    }

    #[test]
    fn test_parse() {
        let Action::Link(args) = super::parse(INPUT1.iter()).unwrap() else {
            panic!("Unexpected action");
        };

        assert_eq!(
            args.inputs
                .iter()
                .filter_map(|i| match &i.spec {
                    InputSpec::File(_) => None,
                    InputSpec::Lib(lib_name) => Some(lib_name.as_ref()),
                })
                .collect::<Vec<&str>>(),
            &["gcc_s", "util", "rt", "pthread", "m", "dl", "c"]
        );
        assert_contains(&args.lib_search_path, "/lib");
        assert_contains(&args.lib_search_path, "/usr/lib");
        assert!(!args.inputs.iter().any(|i| match &i.spec {
            InputSpec::File(f) => f.as_ref() == Path::new("/usr/bin/ld"),
            _ => false,
        }));
    }
}
