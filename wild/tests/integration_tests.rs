//! Tests that build and run various test programs then link them and run them. Each test is linked
//! with both the system linker (ld) and with wild.
//!
//! The test files can contain directives that affect compilation and linking as well as assertions
//! that are tested by examining the resulting binaries. Directives have the format '//#Directive:
//! Args'.
//!
//! Config:{name}[:{inherits}] Starts a new configuration with the specified name. Optionally
//! inherits from configuration with name in the second argument.
//!
//! AbstractConfig:{name}[:{inherits}] Starts an abstract configuration. This is the same as
//! `Config`, however the configuration will not be run and is only used for inheritance purposes.
//!
//! Variant:{number} Can be specified multiple times. Each specified variant is a separate test
//! which is compiled with `-DVARIANT={number}`. Only works for C/C++.
//!
//! LinkerDriver:gcc|g++|clang|clang++|none Specifies how we should invoke the linker. The default,
//! `none` means that we invoke the linker directly. For the other options, we invoke it via the
//! specified compiler. This option doesn't apply to Rust code, which always uses the Rust compiler.
//!
//! LinkArgs:... Arguments to pass to the linker. If using a LinkerDriver, these arguments should be
//! whatever the linker driver expects. e.g. `-Wl,--strip-all` rather than `--strip-all`.
//! `./<filename>` will be replaced with the path to the input file.
//!
//! LinkSoArgs:... Arguments to pass when linking a shared object.
//!
//! WildExtraLinkArgs:... Extra linker arguments that should only be passed to the Wild linker.
//!
//! CompArgs:... Arguments to be passed to the compiler when building object files.
//!
//! CompSoArgs:... Arguments to be passed to the compiler when building shared objects.
//!
//! ExpectSym:symbol-name [Symbol properties...] Checks that the specified symbol is defined in the
//! output file. Can also assert some properties of that symbol. See Symbol properties below.
//!
//! ExpectDynSym:symbol-name [section] [offset-in-section] As for ExpectSym, but for dynamic
//! symbols.
//!
//! NoSym:symbol-name Checks that the specified symbol name is not defined in either .symtab or
//! .dynsym.
//!
//! NoDynSym:symbol-name Checks that the specified symbol name is not defined in .dynsym.
//!
//! ExpectDynamic:tag-name Checks that the specified dynamic entry (e.g. DT_RUNPATH, DT_FLAGS) is
//! present in the .dynamic section.
//!
//! NoDynamic:tag-name Checks that the specified dynamic entry (e.g. DT_RPATH, DT_BIND_NOW) is
//! absent from the .dynamic section.
//!
//! ExpectComment: Checks that the comment in the .comment section is equal to the supplied
//! argument. If no ExpectComment directives are given then .comment isn't checked. The argument may
//! end with '*' which matches anything.
//!
//! ExpectLoadAlignment:{alignment} Checks that the first PT_LOAD segment in the output binary has
//! the specified alignment.
//!
//! DoesNotContain:{string} Checks that the output binary doesn't contain the specified string.
//!
//! Contains:{string} Checks that the output binary does contain the specified string.
//!
//! Mode:{mode} Set linking mode to static (default), dynamic or unspecified. Cannot be used
//! together with LinkerDriver.
//!
//! DiffIgnore:{diff-key} Add an extra linker-diff ignore directive.
//!
//! DiffEnabled:{bool} Defaults to true. Set to false to disable diffing of output files with
//! linker-diff.
//!
//! RunEnabled:{bool} Defaults to true. Set to false to disable execution of the resulting binary.
//!
//! SkipLinker:{linker-name} Don't link with the specified linker. Mostly useful if testing a flag
//! that isn't supported by GNU ld.
//!
//! EnableLinker:{linker-name} Enables a linker that isn't enabled by default. e.g. lld.
//!
//! Cross:{bool} Defaults to true. Set to false to disable cross-compilation testing for this test.
//!
//! ExpectError:{error regex} Verifies that the link fails and that the error message matches the
//! specified regex. Implies `RunEnabled:false` and `DiffEnabled:false`. May be specified multiple
//! times - all must match.
//!
//! SecEquiv:{sec-name}={sec-name} Tells linker-diff that the two section names should be considered
//! as equivalent.
//!
//! Compiler:gcc|g++|clang|clang++ Specifies what compiler should be used to compile C/C++ code.
//!
//! Arch:{arch1}[,{arch2}...] Specifies which architectures this test should be run with. Defaults
//! to all supported architectures.
//!
//! RequiresGlibc:{bool} Defaults to false. Set to true to disable this test if we're running on a
//! system without glibc.
//!
//! RequiresGlibcVersion:{version} Specifies the minimum version of glibc required for this test.
//!
//! RequiresSFrameBacktrace:{bool} Defaults to false. Set to true to disable this test if we're
//! running on a system without sframe backtrace support.
//!
//! RequiresNightlyRustc:{bool} Defaults to false. Set to true to disable this test if we detect
//! that the version of rustc available to us is not nightly.
//!
//! RequiresCompilerFlags:{flag} Checks if the compiler supports the specified flag(s) and skips the
//! test if it doesn't. Set WILD_VERIFY_PLATFORM_REQUIREMENTS=1 to verify that all requirements are
//! met and no tests are skipped.
//!
//! RequiresRustMusl:{bool} Defaults to false. Set to true to clarify that this test requires the
//! musl Rust toolchain.
//!
//! RequiresLinkerPlugin:{bool} Requires the linker driver to have linker-plugin support. This
//! checks that a simple C program can be compiled with `-flto` and skips the test if that fails.
//! This can be used for both C and Rust tests. In the case of Rust tests, the clang compiler will
//! be checked. Also checks that wild was not statically linked.
//!
//! AutoAddObjects:{bool} Whether to automatically add input objects for the test to the command
//! line. Defaults to true.
//!
//! TestUpdateInPlace:{bool} Whether to perform additional testing of the --update-in-place flag.
//! This testing runs wild twice with the second run having the --update-in-place and the file
//! having been pre-filled with random data. It then compares the output of the two runs to verify
//! that they're the same.
//!
//! RemoveSection:{section-name} Remove the section with the specified name from the output binary.
//!
//! ## Inputs
//!
//! The following input types support an optional template parameter. This should look something
//! like `Shared:template(--push-state --as-needed $O --pop-state):filename.c`.
//!
//! Object:{source-filename}[:extra-compilation-args] Builds the specified filename as a regular
//! object and adds it to the link.
//!
//! Archive:{source-filename}[:extra-compilation-args] Builds the specified filename as an archive
//! and adds it to the link.
//!
//! ThinArchive:{source-filename}[:extra-compilation-args] Builds the specified filename as a thin
//! archive and adds it to the link.
//!
//! BsdArchive:{source-filename}[:extra-compilation-args] Builds the specified filename as a bsd
//! archive and adds it to the link.
//!
//! Shared:{source-filename}[:extra-compilation-args] Builds the specified filename as a shared
//! object and adds it to the link.
//!
//! ## Symbol properties
//!
//! This describes the format of symbol properties, which can be supplied to `ExpectSym` and
//! `ExpectDynSym`.
//!
//! A comma-separated list of key value pairs. Note, commas should not have spaces after them.
//!
//! Example: `//#ExpectDynSym:start_aaa section="bar",offset-in-section=8`
//!
//! section="section-name": Type: string. Asserts the name of the section in which the symbol is
//! located.
//!
//! offset-in-section=N: Type: Integer. Asserts the offset of the symbol within the section.
//! Requires that section is also specified.
//!
//! address=N: Type: Integer. Asserts the absolute address of the symbol in the binary.
//!
//! size=N: Type: Integer. Asserts the st_size of the symbol. Useful for verifying that
//! size-changing relaxations (e.g. RISC-V call relaxation) were applied.

mod external_tests;

use itertools::Itertools;
use libwild::bail;
use libwild::ensure;
use libwild::error;
use libwild::error::Context as _;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::read::elf::ProgramHeader;
use os_info::Type;
use rstest::fixture;
use rstest::rstest;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Write as _;
use std::fs::read_dir;
use std::hash::BuildHasher as _;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::BufRead;
use std::io::BufReader;
use std::io::ErrorKind;
use std::io::IsTerminal;
use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::Once;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;
use strum::Display;
use strum::EnumString;
use wait_timeout::ChildExt;

/// Set this variable to a non-empty value to check that the current platform meets the requirements
/// for running all tests.
const FULL_PLATFORM_REQUIRED_VAR: &str = "WILD_VERIFY_PLATFORM_REQUIREMENTS";

type Result<T = (), E = libwild::error::Error> = core::result::Result<T, E>;
type ElfFile64<'data> = object::read::elf::ElfFile64<'data, LittleEndian>;

const TEMPLATE_PLACEHOLDER: &str = "$O";

fn base_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn determine_build_dir(test_name: &str) -> PathBuf {
    std::env::var("WILD_TEST_BUILD_DIR")
        .map_or(base_dir().join("tests/build"), PathBuf::from)
        .join(test_name)
}

#[derive(Debug)]
struct ProgramInputs {
    source_file: &'static str,
}

#[derive(Debug)]
struct Program<'a> {
    link_output: LinkOutput,
    assertions: &'a Assertions,
    shared_objects: Vec<LinkerInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Linker {
    Wild,
    ThirdParty(ThirdPartyLinker),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ThirdPartyLinker {
    name: &'static str,
    gcc_name: &'static str,
    path: PathBuf,
    cross_paths: HashMap<Architecture, PathBuf>,
    enabled_by_default: bool,
}

impl Linker {
    fn path(&self, cross_arch: Option<Architecture>) -> &Path {
        match self {
            Linker::Wild => wild_path(),
            Linker::ThirdParty(info) => cross_arch
                .and_then(|arch| info.cross_paths.get(&arch))
                .unwrap_or(&info.path),
        }
    }

    fn link_shared(
        &self,
        objects: &[BuiltObject],
        so_path: &Path,
        config: &Config,
        cross_arch: Option<Architecture>,
    ) -> Result<LinkerInput> {
        let mut linker_args = config.linker_args.clone();

        linker_args
            .args
            .extend(config.linker_so_args.args.iter().cloned());

        linker_args.args.push("-shared".to_owned());

        let mut command = LinkCommand::new(
            self,
            &objects.iter().flat_map(|o| o.inputs()).collect_vec(),
            so_path,
            &linker_args,
            config,
            cross_arch,
        )?;

        if !command.can_skip() {
            // If we're expecting errors, those errors should only occur when we link the final
            // binary, not when we link any dependent shared objects.
            let mut config = config.clone();
            config.expect_errors = Vec::new();

            command.run(&config)?;
            command.write_input_hashes()?;
        }

        Ok(LinkerInput::with_command(so_path.to_owned(), command))
    }

    fn is_wild(&self) -> bool {
        *self == Linker::Wild
    }

    fn name(&self) -> &str {
        match self {
            Linker::Wild => "wild",
            Linker::ThirdParty(l) => l.name,
        }
    }

    fn enabled_by_default(&self) -> bool {
        match self {
            Linker::Wild => true,
            Linker::ThirdParty(l) => l.enabled_by_default,
        }
    }
}

fn wild_path() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_wild"))
}

#[derive(Debug)]
struct LinkOutput {
    binary: PathBuf,
    command: LinkCommand,
    linker_used: Linker,
}

#[derive(Debug)]
struct LinkCommand {
    command: Command,
    input_commands: Vec<LinkCommand>,
    linker: Linker,
    invocation_mode: LinkerInvocationMode,
    opt_save_dir: Option<PathBuf>,
    output_path: PathBuf,
    inputs: Vec<LinkerInput>,
    config: Config,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkerInvocationMode {
    /// We just call the linker directly. This means that we won't be linking against libc.
    Direct,

    /// We invoke the linker by calling the C compiler and getting it to call the linker. The C
    /// compiler will by default add linker arguments to cause libc to be linked.
    Cc,

    /// We invoke a shell script which invokes the linker. The shell script will have been written
    /// by previously running wild with WILD_SAVE_DIR set.
    Script,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, EnumString, Display)]
#[strum(serialize_all = "snake_case")]
enum Architecture {
    X86_64,
    #[strum(serialize = "aarch64")]
    AArch64,
    #[strum(serialize = "riscv64")]
    RISCV64,
    #[strum(serialize = "loongarch64")]
    LoongArch64,
}

const ALL_ARCHITECTURES: &[Architecture] = &[
    Architecture::X86_64,
    Architecture::AArch64,
    Architecture::RISCV64,
    Architecture::LoongArch64,
];

impl Architecture {
    fn emulation_name(&self) -> &'static str {
        match self {
            Architecture::X86_64 => "x86_64",
            Architecture::AArch64 => "aarch64elf",
            Architecture::RISCV64 => "elf64lriscv",
            Architecture::LoongArch64 => "elf64loongarch",
        }
    }

    fn default_target_triple(&self) -> String {
        format!("{self}-unknown-linux-gnu")
    }

    fn default_target_triple_rustc(&self) -> String {
        match self {
            Architecture::RISCV64 => "riscv64gc-unknown-linux-gnu".to_string(),
            other => other.default_target_triple(),
        }
    }

    fn get_cross_sysroot_path(&self) -> String {
        format!("/usr/{self}-linux-gnu")
    }
}

fn dynamic_linker_path(cross_arch: Option<Architecture>) -> &'static str {
    match cross_arch {
        None => host_dynamic_linker_cached(),
        Some(Architecture::X86_64) => "/lib64/ld-linux-x86-64.so.2",
        Some(Architecture::AArch64) => "/lib/ld-linux-aarch64.so.1",
        Some(Architecture::RISCV64) => "/lib/ld-linux-riscv64-lp64d.so.1",
        Some(Architecture::LoongArch64) => "/lib/ld-linux-loongarch-lp64d.so.1",
    }
}

/// Returns the dynamic linker shared object that appears to be used on the host platform. This is
/// determined by trying various binaries that are likely to be dynamically linked.
fn host_dynamic_linker_cached() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    let value = VALUE.get_or_init(|| {
        [
            "/bin/true",
            "/bin/ls",
            "/usr/bin/ls",
            "/proc/self/exe",
            "/bin/less",
        ]
        .into_iter()
        .find_map(get_dynamic_linker)
        .expect("Failed to find a suitable host dynamically linked binary")
    });
    value.as_str()
}

/// Returns the dynamic linker used by the specified binary or None if it doesn't exist or isn't
/// dynamically linked.
fn get_dynamic_linker(path: impl AsRef<Path>) -> Option<String> {
    let file_bytes = std::fs::read(path.as_ref()).ok()?;
    let file = ElfFile64::parse(&*file_bytes).ok()?;

    let interp_header = file
        .elf_program_headers()
        .iter()
        .find(|header| header.p_type(LittleEndian) == object::elf::PT_INTERP)?;

    let mut interp_data = interp_header
        .data(LittleEndian, file.data())
        .ok()?
        .to_owned();

    // Remove null terminator.
    interp_data.pop();

    String::from_utf8(interp_data.to_owned()).ok()
}

#[allow(unreachable_code)]
fn get_host_architecture() -> Architecture {
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

fn is_host_debian_based() -> bool {
    matches!(
        os_info::get().os_type(),
        Type::Debian | Type::Ubuntu | Type::Pop
    )
}

fn is_musl_used() -> bool {
    os_info::get().os_type() == Type::Alpine
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    /// The base build directory for the test (without config name).
    base_build_dir: PathBuf,
    /// The build directory for this config (base_build_dir + config name).
    build_dir: PathBuf,
    name: String,
    variant_num: Option<u32>,
    assertions: Assertions,
    linker_driver: LinkerDriver,
    linker_args: ArgumentSet,
    linker_so_args: ArgumentSet,
    wild_extra_linker_args: ArgumentSet,
    compiler_args: ArgumentSet,
    compiler_so_args: ArgumentSet,
    diff_ignore: Vec<String>,
    skip_linkers: HashSet<String>,
    enabled_linkers: HashSet<String>,
    cross_enabled: bool,
    section_equiv: Vec<(String, String)>,
    is_abstract: bool,
    deps: Vec<Dep>,
    compiler: String,
    should_diff: bool,
    should_run: bool,
    expect_errors: Vec<ErrorMatcher>,
    support_architectures: Vec<Architecture>,
    requires_glibc: bool,
    requires_glibc_version: Option<String>,
    requires_sframe_backtrace: bool,
    requires_compiler_flags: Vec<String>,
    requires_nightly_rustc: bool,
    auto_add_objects: bool,
    remove_sections: Vec<String>,
    rustc_channel: RustcChannel,
    requires_rust_musl: bool,
    requires_linker_plugin: bool,
    test_update_in_place: bool,
    test_config: TestConfig,
    tracked_files: Vec<PathBuf>,
}

/// These configs are used by the config file specified in `$WILD_TEST_CONFIG`
#[derive(serde::Deserialize, Debug, Default, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TestConfig {
    #[serde(default)]
    rustc_channel: RustcChannel,

    #[serde(default)]
    qemu_arch: Vec<Architecture>,

    #[serde(default)]
    allow_rust_musl_target: bool,

    /// Extra ignore directives. This can be handy if you're running on a system with say an older
    /// version of GNU ld that doesn't perform certain optimisations.
    #[serde(default)]
    diff_ignore: Vec<String>,

    /// Run the diffing component of each test. By default, diffs are skipped.
    /// Enable this to verify that wild produces output matching other linkers.
    #[serde(default)]
    run_all_diffs: bool,

    /// A list of external tests to ignore. Expected values are filenames not full paths.
    #[serde(default)]
    ignore_external_tests: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
enum RustcChannel {
    /// Use whatever rustc is on the path and don't override the toolchain. Can be used without
    /// rustup.
    #[default]
    Default,

    Stable,

    Beta,

    /// Use the nightly toolchain. This enables nightly-only tests, including those that use the
    /// cranelift backed. It thus requires that the cranelift backend is installed.
    Nightly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumString, Default)]
#[strum(serialize_all = "snake_case")]
enum Mode {
    Dynamic,
    #[default]
    Static,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct DirectConfig {
    mode: Mode,
}

#[derive(Debug, Clone)]
struct ErrorMatcher {
    regex: regex::bytes::Regex,
}

fn get_glibc_version() -> Option<Vec<u32>> {
    static VERSION: std::sync::OnceLock<Option<Vec<u32>>> = std::sync::OnceLock::new();
    VERSION
        .get_or_init(|| {
            let output = std::process::Command::new("getconf")
                .arg("GNU_LIBC_VERSION")
                .output()
                .ok()?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let version_str = stdout.split_whitespace().last()?;
                Some(
                    version_str
                        .split('.')
                        .filter_map(|s| s.parse::<u32>().ok())
                        .collect(),
                )
            } else {
                None
            }
        })
        .clone()
}

/// Checks if the system's glibc supports SFrame-based stack unwinding for a given architecture.
///
/// 1. Check environment variable overrides (WILD_SKIP_SFRAME_BACKTRACE /
///    WILD_FORCE_SFRAME_BACKTRACE)
/// 2. Check glibc version (must be 2.42+)
/// 3. Compile and run a test program that uses SFrame-only backtrace to verify it works at runtime
fn is_sframe_backtrace_supported(arch: Architecture) -> bool {
    use std::collections::HashMap;
    use std::sync::Mutex;

    static SUPPORTED: std::sync::OnceLock<Mutex<HashMap<Architecture, bool>>> =
        std::sync::OnceLock::new();

    let cache = SUPPORTED.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache_guard = cache.lock().unwrap();

    if let Some(&result) = cache_guard.get(&arch) {
        return result;
    }

    let result = check_sframe_support_for_arch(arch);
    cache_guard.insert(arch, result);
    result
}

fn check_sframe_support_for_arch(arch: Architecture) -> bool {
    if std::env::var("WILD_SKIP_SFRAME_BACKTRACE").is_ok() {
        return false;
    }
    if std::env::var("WILD_FORCE_SFRAME_BACKTRACE").is_ok() {
        return true;
    }

    // Check glibc version (must be 2.42+)
    let version = get_glibc_version();
    if version.as_ref().is_none_or(|v| v < &vec![2, 42]) {
        return false;
    }

    run_sframe_backtrace_test(arch)
}

/// Compiles and runs a minimal test program to verify SFrame-based backtrace actually works.
/// This catches cases where glibc has .sframe sections but backtrace() doesn't use them
/// correctly (e.g., some Ubuntu 25.10 configurations).
///
/// TODO: This should be unnecessary once more various distributions have updated glibc.
fn run_sframe_backtrace_test(arch: Architecture) -> bool {
    let temp_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return false,
    };

    let source_path = temp_dir.path().join("sframe_test.c");
    let obj_path = temp_dir.path().join("sframe_test.o");
    let binary_path = temp_dir.path().join("sframe_test");
    let test_code = r#"
#define _GNU_SOURCE
#include <execinfo.h>
#include <stdlib.h>

__attribute__((noinline)) int check_bt(void) {
    void *buffer[10];
    int nptrs = backtrace(buffer, 10);
    if (nptrs < 3){ return 1; }
    for (int i = 0; i < 3; ++i) {
        if (buffer[i] == 0 || (unsigned long)buffer[i] < 0x1000){ return 2; }
    }
    return 42;
}

__attribute__((noinline)) int inner(void) {
    return check_bt();
}

int main(void) {
    return inner();
}
"#;

    if std::fs::write(&source_path, test_code).is_err() {
        return false;
    }

    let host_arch = get_host_architecture();
    let is_cross = arch != host_arch;

    let (compiler, sysroot) = if is_cross {
        let cross_compiler = format!("{}-linux-gnu-gcc", arch);
        let sysroot = arch.get_cross_sysroot_path();
        (cross_compiler, Some(sysroot))
    } else {
        ("gcc".to_string(), None)
    };

    let mut compile_cmd = std::process::Command::new(&compiler);
    compile_cmd
        .arg("-c")
        .arg("-O0")
        .arg("-fomit-frame-pointer")
        .arg("-Wa,--gsframe")
        .arg(&source_path)
        .arg("-o")
        .arg(&obj_path);

    if let Some(ref sysroot) = sysroot {
        compile_cmd.arg(format!("--sysroot={}", sysroot));
    }

    if !compile_cmd
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return false;
    }

    let mut link_cmd = std::process::Command::new(&compiler);
    link_cmd.arg(&obj_path).arg("-o").arg(&binary_path);

    if let Some(ref sysroot) = sysroot {
        link_cmd.arg(format!("--sysroot={}", sysroot));
    }

    if !link_cmd
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return false;
    }

    // Remove .eh_frame and .eh_frame_hdr sections to force SFrame-only unwinding
    let objcopy = if is_cross {
        format!("{}-linux-gnu-objcopy", arch)
    } else {
        "objcopy".to_string()
    };

    let objcopy_result = std::process::Command::new(&objcopy)
        .arg("--remove-section=.eh_frame")
        .arg("--remove-section=.eh_frame_hdr")
        .arg(&binary_path)
        .output();

    if !objcopy_result.map(|o| o.status.success()).unwrap_or(false) {
        return false;
    }

    let run_result = if is_cross {
        std::process::Command::new(format!("qemu-{arch}"))
            .arg("-L")
            .arg(arch.get_cross_sysroot_path())
            .arg(&binary_path)
            .output()
    } else {
        std::process::Command::new(&binary_path).output()
    };

    match run_result {
        Ok(output) => output.status.code() == Some(42),
        Err(_) => false,
    }
}

impl Config {
    fn should_skip(&self, arch: Architecture) -> bool {
        !self.support_architectures.contains(&arch)
            || self.requires_glibc && !cfg!(target_env = "gnu")
            || (arch != get_host_architecture()
                && (self.compiler == "clang" || !self.cross_enabled))
            || (self.test_config.rustc_channel != RustcChannel::Nightly
                && self.requires_nightly_rustc)
            || self.requires_glibc_version.as_ref().is_some_and(|version| {
                let req_version: Vec<u32> = version
                    .split('.')
                    .filter_map(|s| s.parse::<u32>().ok())
                    .collect();
                get_glibc_version().is_some_and(|current_version| req_version > current_version)
            })
            || (self.requires_sframe_backtrace && !is_sframe_backtrace_supported(arch))
    }

    fn is_linker_enabled(&self, linker: &Linker) -> bool {
        if self.skip_linkers.contains(linker.name()) {
            return false;
        }
        if self.enabled_linkers.contains(linker.name()) {
            return true;
        }
        linker.enabled_by_default()
    }

    /// Returns the configuration that should be used when building our dependencies. This is a copy
    /// of the current config with anything that shouldn't be inherited cleared.
    fn config_for_deps(&self) -> Config {
        let mut out = self.clone();
        out.deps = Vec::new();
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkerDriver {
    /// Invoke the linker via a compiler.
    Compiler(Compiler),

    /// Invoke the linker directly.
    Direct(DirectConfig),
}

/// A compiler via which the linker is invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compiler {
    Gcc(CLanguage),
    Clang(CLanguage),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FilenameArgumentPair {
    /// The source file to be compiled.
    filename: String,

    /// The arguments with which to compile the source file.
    args: ArgumentSet,
}

impl FilenameArgumentPair {
    fn new(filename: &str, args: ArgumentSet) -> Self {
        Self {
            filename: filename.to_string(),
            args,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Dep {
    files: Vec<FilenameArgumentPair>,
    input_type: InputType,

    /// Overrides how the dependency will be added to the command-line with $O as a placeholder for
    /// the output file.
    template: Option<Vec<String>>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Assertions {
    expected_symtab_entries: Vec<ExpectedSymtabEntry>,
    expected_dynsym_entries: Vec<ExpectedSymtabEntry>,
    expected_comments: Vec<String>,
    no_sym: HashSet<String>,
    no_dynsym: HashSet<String>,
    does_not_contain: Vec<String>,
    contains_strings: Vec<String>,
    expect_dynamic: bool,
    expected_load_alignment: Option<u64>,
    expected_dynamic_entries: Vec<String>,
    absent_dynamic_entries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedSymtabEntry {
    name: String,
    assertions: SymtabAssertions,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SymtabAssertions {
    #[serde(rename = "section")]
    section_name: Option<String>,

    #[serde(rename = "offset-in-section")]
    section_offset: Option<u64>,

    #[serde(rename = "address")]
    absolute_address: Option<u64>,

    size: Option<u64>,
}

impl ExpectedSymtabEntry {
    fn parse(s: &str) -> Result<Self> {
        let Some((name, config_str)) = s.split_once(' ') else {
            return Ok(Self {
                name: s.to_owned(),
                assertions: Default::default(),
            });
        };

        let assertions = serde_keyvalue::from_key_values(config_str)?;
        Ok(Self {
            name: name.to_owned(),
            assertions,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, EnumString)]
enum InputType {
    Object,
    Archive,
    ThinArchive,
    BsdArchive,
    #[strum(serialize = "Shared")]
    SharedObject,
    LinkerScript,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ArgumentSet {
    args: Vec<String>,
}

impl ArgumentSet {
    fn parse(s: &str) -> Result<ArgumentSet> {
        Ok(ArgumentSet {
            args: s
                .split(' ')
                .map(str::to_owned)
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }

    fn default_for_linking() -> Self {
        Self {
            // Wild linker uses -znow by default!
            args: vec!["-z".to_owned(), "now".to_owned()],
        }
    }

    fn default_for_compiling() -> Self {
        Self { args: Vec::new() }
    }

    fn empty() -> Self {
        Self { args: Vec::new() }
    }
}

impl Config {
    fn new(test_config: &TestConfig, build_dir: PathBuf) -> Self {
        Self {
            base_build_dir: build_dir.clone(),
            build_dir,
            name: "default".to_owned(),
            variant_num: None,
            assertions: Default::default(),
            linker_driver: LinkerDriver::Direct(DirectConfig::default()),
            linker_args: ArgumentSet::default_for_linking(),
            linker_so_args: ArgumentSet::default_for_linking(),
            compiler_args: ArgumentSet::default_for_compiling(),
            compiler_so_args: ArgumentSet::default_for_compiling(),
            wild_extra_linker_args: ArgumentSet::empty(),
            diff_ignore: Default::default(),
            skip_linkers: Default::default(),
            enabled_linkers: Default::default(),
            section_equiv: Default::default(),
            is_abstract: false,
            deps: Default::default(),
            remove_sections: Vec::new(),
            compiler: "gcc".to_owned(),
            should_diff: true,
            should_run: true,
            expect_errors: Default::default(),
            cross_enabled: true,
            support_architectures: ALL_ARCHITECTURES.to_owned(),
            requires_glibc: false,
            requires_glibc_version: None,
            requires_sframe_backtrace: false,
            requires_compiler_flags: Vec::new(),
            requires_nightly_rustc: false,
            requires_linker_plugin: false,
            auto_add_objects: true,
            rustc_channel: RustcChannel::Default,
            requires_rust_musl: false,
            test_update_in_place: false,
            test_config: test_config.clone(),
            tracked_files: Default::default(),
        }
    }
}

fn parse_single_config(src_path: &Path, default_config: &Config) -> Result<Config> {
    let mut configs = parse_configs(src_path, default_config)?;
    let Some(config) = configs.pop() else {
        unreachable!();
    };

    if !configs.is_empty() {
        bail!(
            "Multiple configs is not supported in this context: `{}`",
            src_path.display()
        );
    }

    Ok(config)
}

fn parse_configs(src_filename: &Path, default_config: &Config) -> Result<Vec<Config>> {
    let source = std::fs::read_to_string(src_filename)
        .with_context(|| format!("Failed to read {}", src_filename.display()))?;
    let is_rust = src_filename.extension().is_some_and(|ext| ext == "rs");

    let mut configs = Vec::new();
    let mut config_name_to_index = HashMap::new();
    let mut config = default_config.clone();

    for line in source.lines() {
        if let Some(rest) = line.trim().strip_prefix("//#") {
            let (directive, arg) = rest.split_once(':').context("Missing arg")?;
            let arg = arg.trim();
            match directive {
                "Config" | "AbstractConfig" => {
                    if &config != default_config {
                        let index = configs.len();
                        config_name_to_index.insert(config.name.clone(), index);
                        configs.push(config);
                    }
                    let name = if let Some((name, inherit)) = arg.split_once(':') {
                        let inherit_index = config_name_to_index.get(inherit).ok_or_else(|| {
                            error!("Config `{name}` inherits from unknown config named `{inherit}`")
                        })?;

                        config = configs[*inherit_index].clone();

                        // Clear any fields that we want to not inherit.
                        config.variant_num = None;

                        name
                    } else {
                        config = default_config.clone();
                        arg
                    };
                    config.is_abstract = directive == "AbstractConfig";
                    if config_name_to_index.contains_key(name) {
                        bail!("Duplicate config `{name}`");
                    }
                    name.clone_into(&mut config.name);
                }
                "Variant" => {
                    if config.variant_num.is_some() {
                        bail!("Variant can only be specified once per config");
                    }
                    config.variant_num = Some(
                        arg.parse()
                            .with_context(|| format!("Failed to parse '{arg}'"))?,
                    )
                }
                "LinkArgs" => {
                    if is_rust {
                        bail!("LinkArgs is not used when building Rust code");
                    }
                    if let Some((_, rest)) = arg.split_once("./") {
                        let filename = rest.split_once(' ').map_or(rest, |(f, _)| f);
                        let src_path = src_path(filename);
                        config.tracked_files.push(src_path.clone());
                        let with_replaced_path =
                            arg.replace(&format!("./{filename}"), &src_path.display().to_string());
                        config.linker_args = ArgumentSet::parse(&with_replaced_path)?
                    } else {
                        config.linker_args = ArgumentSet::parse(arg)?
                    }
                }
                "LinkSoArgs" => {
                    if is_rust {
                        bail!("LinkSoArgs is not used when building Rust code");
                    }
                    config.linker_so_args = ArgumentSet::parse(arg)?
                }
                "LinkerDriver" => {
                    config.linker_driver = LinkerDriver::parse(arg)?;
                }
                "WildExtraLinkArgs" => config.wild_extra_linker_args = ArgumentSet::parse(arg)?,
                "CompArgs" => config.compiler_args = ArgumentSet::parse(arg)?,
                "CompSoArgs" => config.compiler_so_args = ArgumentSet::parse(arg)?,
                "ExpectSym" => config.assertions.expected_symtab_entries.push(
                    ExpectedSymtabEntry::parse(arg.trim())
                        .context("Failed to parse ExpectSym arguments")?,
                ),
                "ExpectDynSym" => config.assertions.expected_dynsym_entries.push(
                    ExpectedSymtabEntry::parse(arg.trim())
                        .context("Failed to parse ExpectDynSym arguments")?,
                ),
                "ExpectComment" => config
                    .assertions
                    .expected_comments
                    .push(arg.trim().to_owned()),
                "NoSym" => {
                    config.assertions.no_sym.insert(arg.trim().to_owned());
                }
                "NoDynSym" => {
                    config.assertions.no_dynsym.insert(arg.trim().to_owned());
                }
                "DoesNotContain" => config
                    .assertions
                    .does_not_contain
                    .push(arg.trim().to_owned()),
                "Contains" => config
                    .assertions
                    .contains_strings
                    .push(arg.trim().to_owned()),
                "ExpectDynamic" => config
                    .assertions
                    .expected_dynamic_entries
                    .push(arg.trim().to_owned()),
                "NoDynamic" => config
                    .assertions
                    .absent_dynamic_entries
                    .push(arg.trim().to_owned()),
                "ExpectLoadAlignment" => {
                    let alignment_str = arg.trim();
                    let alignment = if let Some(hex) = alignment_str.strip_prefix("0x") {
                        u64::from_str_radix(hex, 16)
                            .with_context(|| format!("Invalid hex alignment: {alignment_str}"))?
                    } else {
                        alignment_str
                            .parse()
                            .with_context(|| format!("Invalid alignment: {alignment_str}"))?
                    };
                    config.assertions.expected_load_alignment = Some(alignment);
                }
                "Mode" => {
                    let mode: Mode = arg
                        .parse()
                        .with_context(|| format!("Invalid Mode `{arg}`"))?;
                    if mode == Mode::Dynamic {
                        config.assertions.expect_dynamic = true;
                    }
                    config.linker_driver.direct_mut()?.mode = mode;
                }
                "DiffIgnore" => config.diff_ignore.push(arg.trim().to_owned()),
                "DiffEnabled" => {
                    config.should_diff = arg.parse().context("Invalid bool for DiffEnabled")?
                }
                "RunEnabled" => {
                    config.should_run = arg.parse().context("Invalid bool for RunEnabled")?
                }
                "SkipLinker" => {
                    config.skip_linkers.insert(arg.trim().to_owned());
                }
                "EnableLinker" => {
                    config.enabled_linkers.insert(arg.trim().to_owned());
                }
                "Cross" => config.cross_enabled = parse_bool(arg, "Cross")?,
                "ExpectError" => {
                    config.expect_errors.push(ErrorMatcher::new(arg.trim())?);
                    // If there are errors, then there's nothing to run and nothing to diff.
                    config.should_run = false;
                    config.should_diff = false;
                }
                "SecEquiv" => config.section_equiv.push(
                    arg.trim()
                        .split_once('=')
                        .ok_or_else(|| error!("DiffIgnore missing '='"))
                        .map(|(a, b)| (a.to_owned(), b.to_owned()))?,
                ),
                "AutoAddObjects" => config.auto_add_objects = parse_bool(arg, "AutoAddObjects")?,
                input_type @ ("Object" | "Archive" | "ThinArchive" | "BsdArchive" | "Shared"
                | "LinkerScript") => {
                    let input_type = InputType::from_str(input_type)?;

                    let mut arg = arg;
                    let mut template = None;
                    if let Some(rest) = arg.strip_prefix("template(") {
                        let (t, rest) = rest
                            .split_once("):")
                            .with_context(|| format!("Missing '):' in {arg}"))?;
                        let parts = t.split(' ').map(|p| p.to_owned()).collect_vec();
                        if !parts.iter().any(|a| a.contains(TEMPLATE_PLACEHOLDER)) {
                            bail!("Template `{t}` must contain {TEMPLATE_PLACEHOLDER}");
                        }
                        template = Some(parts);
                        arg = rest;
                    }

                    let files = arg
                        .split(",")
                        .map(|arg| {
                            let (filename, comp_args) = arg.split_once(":").unwrap_or((arg, ""));
                            Ok(FilenameArgumentPair::new(
                                filename,
                                ArgumentSet::parse(comp_args)?,
                            ))
                        })
                        .collect::<Result<Vec<_>>>()?;

                    config.deps.push(Dep {
                        files,
                        input_type,
                        template,
                    })
                }
                "RemoveSection" => config.remove_sections.push(arg.trim().to_owned()),
                "Compiler" => config.compiler = arg.trim().to_owned(),
                "Arch" => {
                    config.support_architectures = arg
                        .trim()
                        .split(",")
                        .map(|arch| Architecture::from_str(arch.trim()))
                        .collect::<Result<Vec<_>, _>>()?;
                }
                "SkipArch" => {
                    let skipped = arg
                        .trim()
                        .split(",")
                        .map(|arch| Architecture::from_str(arch.trim()))
                        .collect::<Result<Vec<_>, _>>()?;
                    config.support_architectures = ALL_ARCHITECTURES
                        .to_owned()
                        .into_iter()
                        .filter(|arch| !skipped.contains(arch))
                        .collect();
                }
                "RequiresGlibc" => config.requires_glibc = arg.trim().to_lowercase().parse()?,
                "RequiresGlibcVersion" => {
                    config.requires_glibc = true;
                    config.requires_glibc_version = Some(arg.trim().to_owned())
                }
                "RequiresSFrameBacktrace" => {
                    config.requires_sframe_backtrace = parse_bool(arg, "RequiresSFrameBacktrace")?;
                }
                "RequiresCompilerFlags" => {
                    config
                        .requires_compiler_flags
                        .extend(arg.trim().split(' ').map(str::to_owned));
                }
                "RequiresNightlyRustc" => {
                    config.requires_nightly_rustc = arg.to_lowercase().parse()?;
                }
                "RequiresRustMusl" => {
                    config.requires_rust_musl = arg.to_lowercase().parse()?;
                }
                "RequiresLinkerPlugin" => {
                    config.requires_linker_plugin = arg.to_lowercase().parse()?;
                }
                "TestUpdateInPlace" => {
                    config.test_update_in_place = arg.to_lowercase().parse()?;
                }
                other => bail!("{}: Unknown directive '{other}'", src_filename.display()),
            }
        }
    }

    configs.push(config);

    configs.retain(|c| !c.is_abstract);

    if configs.is_empty() {
        bail!("Missing non-abstract Config");
    }

    Ok(configs)
}

fn parse_bool(arg: &str, opt_name: &str) -> Result<bool> {
    match arg.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => bail!("Unsupported value for {opt_name} '{other}'"),
    }
}

impl ProgramInputs {
    fn new(source_file: &'static str) -> Result<Self> {
        Ok(Self { source_file })
    }

    fn build<'a>(
        &self,
        linker: &Linker,
        config: &'a Config,
        cross_arch: Option<Architecture>,
    ) -> Result<Program<'a>> {
        let primary = build_linker_input(
            &Dep {
                files: vec![FilenameArgumentPair::new(
                    self.source_file,
                    ArgumentSet::empty(),
                )],
                input_type: InputType::Object,
                template: None,
            },
            config,
            linker,
            cross_arch,
        );

        let inputs = std::iter::once(primary)
            .chain(
                config
                    .deps
                    .iter()
                    .map(|dep| build_linker_input(dep, config, linker, cross_arch)),
            )
            .collect::<Result<Vec<_>>>()?;

        let link_output = linker.link(self.name(), &inputs, config, cross_arch)?;

        if config.test_update_in_place
            && matches!(linker, Linker::Wild)
            && config.expect_errors.is_empty()
            && (config.should_diff || config.should_run)
        {
            self.run_update_in_place_test(&inputs, config, cross_arch)?;
        }

        let shared_objects = inputs
            .into_iter()
            .filter(|input| input.path.extension().is_some_and(|ext| ext == "so"))
            .collect();

        if !config.remove_sections.is_empty() {
            remove_sections(&link_output, &config.remove_sections, cross_arch)?;
        }

        Ok(Program {
            link_output,
            assertions: &config.assertions,
            shared_objects,
        })
    }

    fn name(&self) -> &str {
        self.source_file
    }

    fn run_update_in_place_test(
        &self,
        inputs: &[LinkerInput],
        config: &Config,
        cross_arch: Option<Architecture>,
    ) -> Result<()> {
        // Link normally, using unlink-and-replace
        let link_output_1 = Linker::Wild.link(self.name(), inputs, config, cross_arch)?;
        let original_content = std::fs::read(&link_output_1.binary).with_context(|| {
            format!(
                "Failed to read first build output: {}",
                link_output_1.binary.display()
            )
        })?;

        // Overwrite the file with random data with a different length
        let random_data = (0..original_content.len() + 1024)
            .map(|i| (i % 256) as u8)
            .collect::<Vec<u8>>();
        std::fs::write(&link_output_1.binary, &random_data).with_context(|| {
            format!(
                "Failed to overwrite file with random data: {}",
                link_output_1.binary.display()
            )
        })?;

        // Link again with --update-in-place
        let mut config_update_in_place = config.clone();
        let arg = match config.linker_driver {
            LinkerDriver::Compiler(_) => "-Wl,--update-in-place",
            LinkerDriver::Direct(_) => "--update-in-place",
        };
        config_update_in_place
            .wild_extra_linker_args
            .args
            .push(arg.to_string());

        let link_output_2 =
            Linker::Wild.link(self.name(), inputs, &config_update_in_place, cross_arch)?;

        // Verify the content matches the first build
        let final_content = std::fs::read(&link_output_2.binary).with_context(|| {
            format!(
                "Failed to read second build output: {}",
                link_output_2.binary.display()
            )
        })?;

        if original_content != final_content {
            let diffs = sections_with_diffs(&original_content, &final_content)?;

            let mut original = link_output_1.binary.clone();
            let mut updated = link_output_2.binary.clone();

            fn make_variant(path: &mut std::path::PathBuf, suffix: &str) {
                let stem = path.file_stem().unwrap_or_default();
                let ext = path.extension();
                let mut filename = std::ffi::OsString::from(stem);
                filename.push(suffix);
                if let Some(ext) = ext {
                    filename.push(".");
                    filename.push(ext);
                }
                path.set_file_name(filename);
            }

            make_variant(&mut original, "-original");
            make_variant(&mut updated, "-updated");

            std::fs::write(&original, &original_content).with_context(|| {
                format!("Failed to write original file: {}", original.display())
            })?;
            std::fs::rename(&link_output_2.binary, &updated).with_context(|| {
                format!(
                    "Failed to rename {} to {}",
                    link_output_2.binary.display(),
                    updated.display()
                )
            })?;

            bail!(
                "Update-in-place test failed for {file}: content of {original} differs \
                from {updated} after update-in-place linking. Original size: {original_len}, \
                Final size: {final_len}. Diffs:\n{diffs:#?}\n\
                Rerun with:\n{cmd}",
                file = self.source_file,
                original = original.display(),
                updated = updated.display(),
                original_len = original_content.len(),
                final_len = final_content.len(),
                cmd = link_output_2.command,
            );
        }

        Ok(())
    }
}

/// Removes the specified sections from the output file.
fn remove_sections(
    link_output: &LinkOutput,
    section_names: &[String],
    cross_arch: Option<Architecture>,
) -> Result {
    let objcopy = match cross_arch {
        Some(arch) => format!("{}-linux-gnu-objcopy", arch),
        None => "objcopy".to_owned(),
    };

    let mut command = Command::new(objcopy);
    for section_name in section_names {
        command.arg("--remove-section").arg(section_name);
    }
    command.arg(&link_output.binary);
    let output = command.output().context("Failed to run objcopy")?;
    if !output.status.success() {
        bail!(
            "objcopy reported error:\n{}{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
    }
    Ok(())
}

/// Returns the unique section names in which `bytes_a` differs from `bytes_b`.
fn sections_with_diffs(bytes_a: &[u8], bytes_b: &[u8]) -> Result<Vec<SectionDiff>> {
    let file =
        ElfFile64::parse(bytes_a).context("Failed to parse output with --update-in-place")?;

    let mut sections = HashMap::new();

    for (offset, (a, b)) in bytes_a.iter().zip(bytes_b).enumerate() {
        if a == b {
            continue;
        }

        let offset = offset as u64;

        for section in file.sections() {
            let Some(start_and_len) = section.file_range() else {
                continue;
            };

            if (start_and_len.0..start_and_len.0 + start_and_len.1).contains(&offset) {
                let name_bytes = section.name_bytes()?;
                let info = sections.entry(name_bytes).or_insert_with(|| SectionDiff {
                    name: String::from_utf8_lossy(name_bytes).into_owned(),
                    section_start: start_and_len.0,
                    section_size: start_and_len.1,
                    offsets_with_diff: Vec::new(),
                });
                info.offsets_with_diff.push(offset);
            }
        }
    }

    let mut sections = sections.into_values().collect_vec();
    sections.sort_by_key(|s| s.section_start);

    Ok(sections)
}

struct SectionDiff {
    name: String,
    section_start: u64,
    section_size: u64,
    offsets_with_diff: Vec<u64>,
}

impl Debug for SectionDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{name} (0x{start:x}..0x{end:x}) ",
            name = self.name,
            start = self.section_start,
            end = self.section_start + self.section_size
        )?;
        if self.offsets_with_diff.len() <= 8 {
            write!(f, "{:x?}", self.offsets_with_diff)?;
        } else {
            write!(
                f,
                "{} bytes differ between 0x{:x} and 0x{:x}",
                self.offsets_with_diff.len(),
                self.offsets_with_diff[0],
                self.offsets_with_diff[self.offsets_with_diff.len() - 1]
            )?;
        }
        Ok(())
    }
}

/// How long test binaries are allowed to run for. Generally these should only take a few
/// milliseconds, however when running lots of testing parallel there can be quite a bit of load on
/// the system, which can mean that the test binaries take longer to start, so we need to be
/// somewhat generous here to avoid flakes.
const TEST_BINARY_TIMEOUT: Duration = std::time::Duration::from_millis(2000);

impl Program<'_> {
    fn run(&self, cross_arch: Option<Architecture>) -> Result {
        let mut command = if let Some(arch) = cross_arch {
            let mut c = Command::new(format!("qemu-{arch}"));
            c.arg("-L");
            c.arg(arch.get_cross_sysroot_path());
            c.arg(&self.link_output.binary);
            c
        } else {
            Command::new(&self.link_output.binary)
        };

        // Similarly to cargo test, capture all the run-time output, since it may contain useful
        // error messages. We only show it if the exit status is a failure since otherwise messages
        // that are expected, e.g. panic messages, would be potentially confusing to see.
        let (mut recv, send) = std::io::pipe()?;
        command.stdout(send.try_clone()?).stderr(send);

        let spawn_result = spawn_with_retry(&mut command, 10);

        let mut child = spawn_result.with_context(|| {
            format!(
                "Command `{}` failed",
                command.get_program().to_string_lossy()
            )
        })?;

        // We need to drop command here since it holds a copy or two of our send pipe. While they
        // are open, our `recv_to_end` call below can't finish.
        drop(command);

        let mut output = Vec::new();

        let status = std::thread::scope(|scope| -> Result<ExitStatus> {
            scope.spawn(|| {
                let _ = recv.read_to_end(&mut output);
            });

            match child.wait_timeout(TEST_BINARY_TIMEOUT)? {
                Some(s) => Ok(s),
                None => {
                    child.kill()?;
                    bail!("Binary ran for too long");
                }
            }
        })?;

        let output = String::from_utf8_lossy(&output);

        let exit_code = status.code().ok_or_else(|| {
            let signal = status.signal().unwrap();
            let possible_core_dumped_msg = if status.core_dumped() {
                " (core dumped) "
            } else {
                ""
            };
            error!("Binary exited{possible_core_dumped_msg} with signal {signal}: {output}")
        })?;

        if exit_code != 42 {
            bail!("Binary exited with unexpected exit code {exit_code}: {output}");
        }

        Ok(())
    }
}

/// Attempts to spawn `command`. If that fails due to ETXTBSY, then retries until we've tried
/// `max_attempts` times. Other errors do not result in retries. This works around the fact that
/// writing then executing a file from a multi-threaded program on Linux is inherently racy and
/// there's not currently any way to truly fix it. The problem occurs if other threads are spawning
/// subprocesses at the same time as our thread is writing the executable. When that happens the
/// subprocess from the other thread inherits the file descriptor and potentially also the mmaps for
/// the executable that we're writing. That means that once we close the file, the other subprocess
/// still has it open, so when we attempt to execute it, we can't because it's locked due to the
/// other process still having it open. Linux 6.11 fixed this problem by removing ETXTBSY, but
/// unfortunately that got reverted. Someday, we might get O_CLOFORK, but that would only help if
/// the associated mmap isn't cloned. In the meantime, our options are (a) only write executables
/// from subprocesses - but then we don't get to test in-process use of libwild or (b) this retry
/// logic. See also https://github.com/rust-lang/rust/issues/114554
fn spawn_with_retry(command: &mut Command, max_attempts: u32) -> Result<std::process::Child> {
    let mut attempts_remaining = max_attempts;
    loop {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error) => {
                attempts_remaining -= 1;

                if attempts_remaining == 0 || error.kind() != ErrorKind::ExecutableFileBusy {
                    return Err(error.into());
                }

                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

impl Display for Program<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Binary `{}`. Relink with:\n{}",
            self.link_output.binary.display(),
            self.link_output.command
        )
    }
}

impl Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.name, f)
    }
}

#[derive(Debug, Clone)]
struct LinkerInput {
    prefix_arg: Option<&'static str>,
    path: PathBuf,
    command: Option<LinkCommand>,
    template: Option<Vec<String>>,
}

impl LinkerInput {
    fn new(path: PathBuf) -> LinkerInput {
        LinkerInput {
            prefix_arg: None,
            path,
            command: None,
            template: None,
        }
    }

    fn with_command(path: PathBuf, command: LinkCommand) -> LinkerInput {
        LinkerInput {
            prefix_arg: None,
            path,
            command: Some(command),
            template: None,
        }
    }

    fn new_prefixed(path: PathBuf, prefix: &'static str) -> LinkerInput {
        LinkerInput {
            prefix_arg: Some(prefix),
            path,
            command: None,
            template: None,
        }
    }
}

struct BuiltObject {
    path: PathBuf,
    inputs: Vec<LinkerInput>,
}
impl BuiltObject {
    fn inputs(&self) -> Vec<LinkerInput> {
        let mut inputs = vec![LinkerInput::new(self.path.clone())];
        inputs.extend(self.inputs.iter().cloned());
        inputs
    }
}

/// Creates a linker input from a source file. This will be either an object file or an archive.
fn build_linker_input(
    dep: &Dep,
    config: &Config,
    linker: &Linker,
    cross_arch: Option<Architecture>,
) -> Result<LinkerInput> {
    if let [single_file] = dep.files.as_slice()
        && single_file.filename.ends_with(".a")
    {
        return Ok(LinkerInput::new(src_path(&single_file.filename)));
    }

    let config = config.config_for_deps();

    let objects = dep
        .files
        .iter()
        .map(|file| build_obj(file, &config, linker, dep.input_type, cross_arch))
        .collect::<Result<Vec<BuiltObject>>>()?;

    // When building archives or shared objects, we use the name of the first object to determine
    // the name.
    let first_obj_path = &objects
        .first()
        .context("At least one object is required")?
        .path;

    let first_source_filename = dep
        .files
        .first()
        .context("At least one file is required")?
        .filename
        .as_str();
    let archive_basename = Path::new(first_source_filename)
        .file_stem()
        .context("Invalid source filename")?;
    let archive_path = config.build_dir.join(archive_basename).with_extension("a");

    let mut linker_input = match dep.input_type {
        InputType::Archive | InputType::ThinArchive => {
            let thin = matches!(dep.input_type, InputType::ThinArchive);
            if !is_newer(&archive_path, objects.iter().map(|o| &o.path)) {
                make_archive(&archive_path, &objects, thin, &config)?;
            }
            LinkerInput::new(archive_path)
        }
        InputType::BsdArchive => {
            if !is_newer(&archive_path, objects.iter().map(|o| &o.path)) {
                make_bsd_archive(&archive_path, &objects)?;
            }
            LinkerInput::new(archive_path)
        }
        InputType::Object => {
            if objects.len() > 1 {
                bail!(
                    "Multiple source files on a single line is only supported with Shared/Archive"
                );
            }

            LinkerInput::new(first_obj_path.clone())
        }
        InputType::SharedObject => {
            let so_path = first_obj_path.with_extension(format!("{linker}.so"));
            let out = linker.link_shared(&objects, &so_path, &config, cross_arch)?;
            let assertions = Assertions::default();
            assertions
                .check_path(&out.path, linker)
                .with_context(|| format!("Assertions failed for `{}`", out.path.display()))?;
            out
        }
        InputType::LinkerScript => LinkerInput::new_prefixed(first_obj_path.to_owned(), "-T"),
    };

    linker_input.template = dep.template.clone();

    Ok(linker_input)
}

#[derive(Debug, Eq, PartialEq)]
enum CompilerKind {
    C,
    Rust,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CLanguage {
    C,
    Cpp,
}

fn get_c_compiler(
    compiler: &str,
    c_language: CLanguage,
    cross_arch: Option<Architecture>,
) -> Result<String> {
    match (cross_arch, compiler, c_language) {
        (None, "gcc", CLanguage::C) => Ok("gcc".to_string()),
        (None, "gcc", CLanguage::Cpp) => Ok("g++".to_string()),
        (None, "clang", CLanguage::C) => Ok("clang".to_string()),
        (None, "clang", CLanguage::Cpp) => Ok("clang++".to_string()),
        (
            Some(
                arch @ (Architecture::AArch64 | Architecture::RISCV64 | Architecture::LoongArch64),
            ),
            "gcc" | "g++",
            CLanguage::C,
        ) => Ok(format!("{arch}-linux-gnu-gcc")),
        (
            Some(
                arch @ (Architecture::AArch64 | Architecture::RISCV64 | Architecture::LoongArch64),
            ),
            "gcc" | "g++",
            CLanguage::Cpp,
        ) => Ok(format!("{arch}-linux-gnu-g++")),
        _ => bail!("Unsupported compiler and or architecture `{compiler}` / {cross_arch:?}"),
    }
}

/// Builds some C source and returns the path to the object file.
fn build_obj(
    file: &FilenameArgumentPair,
    config: &Config,
    linker: &Linker,
    input_type: InputType,
    cross_arch: Option<Architecture>,
) -> Result<BuiltObject> {
    let src_path = src_path(&file.filename);

    if input_type == InputType::LinkerScript {
        return Ok(BuiltObject {
            path: src_path,
            inputs: Vec::new(),
        });
    }

    let mut config = config.clone();

    if input_type == InputType::SharedObject {
        config = parse_single_config(&src_path, &config)?;
    }

    let inputs = config
        .deps
        .iter()
        .map(|dep| build_linker_input(dep, &config, linker, cross_arch))
        .try_collect()?;

    let Some((compiler, compiler_kind)) = compiler_for_file(&src_path, cross_arch, &config)? else {
        return Ok(BuiltObject {
            path: src_path,
            inputs,
        });
    };

    // For Rust programs, we don't have an easy way to separate compilation from linking, so we
    // output Rust compilation to a directory containing copies of the object files and a script to
    // perform the link step.
    let suffix = match compiler_kind {
        CompilerKind::C => ".o",
        CompilerKind::Rust => ".d",
    };

    let mut command = Command::new(compiler);

    let mut compiler_args =
        if input_type == InputType::SharedObject && !config.compiler_so_args.args.is_empty() {
            config.compiler_so_args.args.clone()
        } else {
            config.compiler_args.args.clone()
        };
    compiler_args.extend_from_slice(&file.args.args);

    match compiler_kind {
        CompilerKind::C => {
            if let Some(v) = config.variant_num {
                command.arg(format!("-DVARIANT={v}"));
            }

            // If we're trying to run the tests with an old version of gcc, and it doesn't support
            // an attribute that we're using like `retain`, it's better to fail right then rather
            // than trying to continue and getting a harder-to-diagnose failure.
            command.arg("-Werror=attributes");

            // Ask GCC to colourise its output even though we're capturing it, but only if we think
            // our output is likely to support colours.
            if std::io::stdout().is_terminal()
                || std::env::var("CARGO_TERM_COLOR").as_deref() == Ok("always")
                || std::env::var("NEXTEST").is_ok()
            {
                command.arg("-fdiagnostics-color=always");
            }

            command.arg("-c");
        }
        CompilerKind::Rust => {
            let wild = wild_path().to_str().context("Need UTF-8 path")?.to_owned();

            command
                .env("WILD_SAVE_SKIP_LINKING", "1")
                .args(config.rustc_channel.as_arg())
                .args(["-C", "linker=clang"])
                .args(["-C", &format!("link-arg=--ld-path={wild}")]);

            if let Some(arch) = cross_arch {
                // Debian sets sysroot to `/` and uses real paths for libraries in linker scripts.
                // So using real sysroot path breaks linking.
                if !is_host_debian_based() {
                    command.args([
                        "-C",
                        &format!("link-arg=--sysroot={}", arch.get_cross_sysroot_path()),
                    ]);
                }
            }

            if let Some(arch) = cross_arch {
                let target = get_target(&compiler_args).cloned().unwrap_or_else(|_| {
                    command.arg(format!("--target={}", arch.default_target_triple_rustc()));
                    arch.default_target_triple().to_owned()
                });
                let target_underscore = target.replace('-', "_");
                let target_triple = target.replace("-unknown", "");

                command.env(
                    format!("CC_{target_underscore}"),
                    format!("{target_triple}-gcc"),
                );

                command.env(
                    format!("AR_{target_underscore}"),
                    format!("{target_triple}-ar"),
                );

                command.arg(format!("-Clink-arg=--target={target}"));
            }

            if is_musl_used() {
                command.args(["-C", "target-feature=-crt-static"]);
            }

            if input_type == InputType::SharedObject {
                command.arg("--crate-type").arg("cdylib");
            }
        }
    }

    command.arg(&src_path);

    command.args(compiler_args);

    // Files that are shared between several tests end up being compiled with various different
    // flags and the config name isn't sufficient to disambiguate them. So we hash the command then
    // include the hash in the output filename.
    let mut hasher = std::hash::DefaultHasher::new();
    command_as_str(&command).hash(&mut hasher);
    let command_hash = hasher.finish();

    let output_path = config
        .build_dir
        .join(Path::new(&file.filename).with_extension(format!("{command_hash:x}{suffix}")));

    match compiler_kind {
        CompilerKind::C => {
            command.arg("-o").arg(&output_path);
        }
        CompilerKind::Rust => {
            command.env("WILD_SAVE_DIR", &output_path);
        }
    }

    let needs_run_with = command.get_envs().any(|(key, _)| key == "WILD_SAVE_DIR");

    // If we're creating a run-with file, then check timestamp on that rather than the directory.
    // Otherwise if a previous run created the directory but failed to create the file, we won't
    // rerun.
    let output_file = if needs_run_with {
        run_with_path(&output_path)
    } else {
        output_path.clone()
    };

    if is_newer(&output_file, std::iter::once(&src_path)) {
        return Ok(BuiltObject {
            path: output_path,
            inputs,
        });
    }

    let output = command.output().with_context(|| {
        format!(
            "Failed to run `{}`",
            command.get_program().to_string_lossy()
        )
    })?;

    if !output.status.success() {
        bail!(
            "Compilation failed to run: {}\nOutput:\n{}{}",
            command_as_str(&command),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    if needs_run_with {
        post_process_rust_run_script(&output_path).with_context(|| {
            format!(
                "Failed to process run-with script after running: {}\nOutput\n{}{}",
                command_as_str(&command),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })?;
    }

    Ok(BuiltObject {
        path: output_path,
        inputs,
    })
}

impl RustcChannel {
    fn as_arg(&self) -> Option<&'static str> {
        match self {
            RustcChannel::Stable => Some("+stable"),
            RustcChannel::Beta => Some("+beta"),
            RustcChannel::Nightly => Some("+nightly"),
            RustcChannel::Default => None,
        }
    }
}

/// Determines which compiler to use to for the supplied file. Returns None if the file is an object
/// file and doesn't need compiling.
fn compiler_for_file(
    src_path: &Path,
    cross_arch: Option<Architecture>,
    config: &Config,
) -> Result<Option<(String, CompilerKind)>> {
    let extension = src_path
        .extension()
        .with_context(|| format!("Missing extension for `{}`", src_path.display()))?
        .to_str()
        .context("Extension isn't valid UTF-8")?;

    let (compiler, compiler_kind) = match extension {
        "cc" => (
            get_c_compiler(&config.compiler, CLanguage::Cpp, cross_arch)?,
            CompilerKind::C,
        ),
        "c" => (
            get_c_compiler(&config.compiler, CLanguage::C, cross_arch)?,
            CompilerKind::C,
        ),
        "s" => (
            get_c_compiler(&config.compiler, CLanguage::C, cross_arch)?,
            CompilerKind::C,
        ),
        "rs" => ("rustc".to_string(), CompilerKind::Rust),
        "o" => {
            return Ok(None);
        }
        _ => bail!("Don't know how to compile {extension} files"),
    };

    Ok(Some((compiler, compiler_kind)))
}

/// Returns the value of the --target flag.
fn get_target(compiler_args: &[String]) -> Result<&String> {
    let mut is_next = false;

    for arg in compiler_args {
        if is_next {
            return Ok(arg);
        }

        is_next = arg == "--target";
    }

    bail!("No --target flag found");
}

fn cross_name(cross_arch: Option<Architecture>) -> String {
    cross_arch
        .map(|a| a.to_string())
        .unwrap_or("host".to_string())
}

/// Newer versions of rustc pass -soname=... to the linker when writing shared objects. This sets
/// DT_SONAME. If DT_SONAME is set, then binaries that are linked against those shared objects will
/// use the value from DT_SONAME to populate DT_NEEDED entries in the executable. If the filename of
/// the .so file doesn't match the DT_SONAME and thus doesn't match the DT_NEEDED in the executable,
/// then the dynamic linker will fail to find the .so file at runtime. None of this is a problem if
/// the DT_SONAME matches the filename. However we put stuff like the name of the linker used into
/// the output filename. So it doesn't really work for us to make them match. Instead, we remove the
/// -soname flag from the run-with script. Without the DT_SONAME, the linker will fall back to using
/// the actual name of the .so file, which is what we want.
fn post_process_rust_run_script(output_path: &Path) -> Result {
    let run_with_filename = run_with_path(output_path);
    let contents =
        std::fs::read_to_string(&run_with_filename).context("Failed to write run-with script")?;

    let mut out = String::new();
    for line in contents.lines() {
        if !line.contains("-soname") {
            out.push_str(line);
            out.push('\n');
        }
    }

    std::fs::write(&run_with_filename, out)
        .with_context(|| format!("Failed to write `{}`", run_with_filename.display()))?;

    Ok(())
}

fn run_with_path(output_path: &Path) -> PathBuf {
    output_path.join("run-with")
}

fn command_as_str(command: &Command) -> String {
    format!(
        "{} {} {}",
        command
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| format!(
                "{}={}",
                key.to_string_lossy(),
                value.to_string_lossy()
            )))
            .join(" "),
        command.get_program().to_string_lossy(),
        command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect_vec()
            .join(" ")
    )
}

fn src_path(filename: &str) -> PathBuf {
    let filename = Path::new(filename);
    base_dir().join("tests").join("sources").join(filename)
}

/// Returns whether both `output_path` all `src_paths` exist and `output_path` has a modification
/// timestamp >= that of all elements of `src_paths`.
fn is_newer<P: AsRef<Path>>(output_path: &Path, mut src_paths: impl Iterator<Item = P>) -> bool {
    let Ok(out) = std::fs::metadata(output_path) else {
        return false;
    };

    let Ok(mod_out) = out.modified() else {
        return false;
    };

    src_paths.all(|src_path| {
        std::fs::metadata(src_path.as_ref())
            .and_then(|src| src.modified())
            .is_ok_and(|mod_src| mod_out >= mod_src)
    })
}

fn parse_ld_dependency_file(depfile: &Path) -> std::io::Result<Vec<PathBuf>> {
    let f = std::fs::File::open(depfile)?;
    let mut r = BufReader::new(f);

    let mut buf = String::new();
    let mut started = false;
    let mut deps = Vec::<PathBuf>::new();
    let mut seen = HashSet::<String>::new();

    loop {
        buf.clear();
        if r.read_line(&mut buf)? == 0 {
            break;
        }
        let line = buf.trim_end_matches(['\r', '\n']);

        let frag = if !started {
            if let Some(i) = line.find(':') {
                started = true;
                &line[i + 1..]
            } else {
                continue;
            }
        } else {
            line
        };

        let (frag, cont) = if frag.ends_with('\\') {
            (frag.trim_end_matches('\\').trim_end(), true)
        } else {
            (frag, false)
        };

        for t in frag.split_whitespace() {
            if !t.is_empty() && seen.insert(t.to_string()) {
                deps.push(PathBuf::from(t));
            }
        }

        if !cont {
            break;
        }
    }

    Ok(deps)
}

impl Linker {
    /// Links the supplied object files with this configuration and returns the path to the
    /// resulting binary.
    fn link(
        &self,
        basename: &str,
        inputs: &[LinkerInput],
        config: &Config,
        cross_arch: Option<Architecture>,
    ) -> Result<LinkOutput> {
        let output_path = self.output_path(basename, config);
        let mut linker_args = config.linker_args.clone();
        if self.is_wild() {
            linker_args
                .args
                .extend(config.wild_extra_linker_args.args.iter().cloned());
        }
        let mut command =
            LinkCommand::new(self, inputs, &output_path, &linker_args, config, cross_arch)?;
        if !command.can_skip() {
            command.run(config)?;
            command.write_input_hashes()?;
        }
        Ok(LinkOutput {
            binary: output_path,
            command,
            linker_used: self.clone(),
        })
    }

    fn output_path(&self, basename: &str, config: &Config) -> PathBuf {
        config.build_dir.join(format!("{basename}.{self}"))
    }
}

fn make_archive(
    archive_path: &Path,
    objects: &[BuiltObject],
    thin: bool,
    config: &Config,
) -> Result {
    let _ = std::fs::remove_file(archive_path);
    // At least on NixOS, trying to use plain "ar" to create an archive containing GCC objects
    // fails, presumably because it's trying to index the symbols.
    let ar_cmd = if config.requires_linker_plugin
        && matches!(
            config.linker_driver,
            LinkerDriver::Compiler(Compiler::Gcc(_))
        ) {
        "gcc-ar"
    } else {
        "ar"
    };
    let mut cmd = Command::new(ar_cmd);
    cmd.arg("cr");

    if thin {
        cmd.arg("--thin");

        // For thin archives, we want to test that we properly handle relative paths, so we pass
        // paths that are relative to the directory in which we're creating the archive.
        let archive_dir = archive_path.parent().unwrap();
        cmd.current_dir(archive_dir);
        cmd.arg(archive_path.strip_prefix(archive_dir).unwrap());

        for o in objects {
            cmd.arg(o.path.strip_prefix(archive_dir).unwrap_or(&o.path));
        }
    } else {
        cmd.arg(archive_path).args(objects.iter().map(|o| &o.path));
    }
    let status = cmd.status()?;
    if !status.success() {
        bail!("Failed to create archive");
    }
    Ok(())
}

fn make_bsd_archive(archive_path: &Path, objects: &[BuiltObject]) -> Result {
    let _ = std::fs::remove_file(archive_path);

    let mut out_bytes = Vec::new();
    let mut builder = ar::Builder::new(&mut out_bytes);

    for obj in objects {
        let obj_bytes = std::fs::read(&obj.path)?;
        let obj_name = obj
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .context("Invalid object file name")?;

        let header = ar::Header::new(obj_name.as_bytes().to_vec(), obj_bytes.len() as u64);

        builder.append(&header, obj_bytes.as_slice())?;
    }

    std::fs::write(archive_path, out_bytes)?;

    Ok(())
}

impl LinkCommand {
    fn new(
        linker: &Linker,
        inputs: &[LinkerInput],
        output_path: &Path,
        linker_args: &ArgumentSet,
        config: &Config,
        cross_arch: Option<Architecture>,
    ) -> Result<LinkCommand> {
        let mut command;
        let mut invocation_mode = LinkerInvocationMode::Direct;
        let mut opt_save_dir = None;
        if let Some((script, extra_inputs)) = get_script(inputs) {
            // Workaround for #104 (Text file busy) issue.
            command = Command::new("bash");
            command.env("OUT", output_path);
            command.arg(script);
            command.arg(linker.path(cross_arch));
            add_inputs_to_command(config, extra_inputs, &mut command);
            invocation_mode = LinkerInvocationMode::Script;
        } else {
            let linker_path = linker.path(cross_arch);

            let arch = cross_arch.unwrap_or_else(get_host_architecture);

            match config.linker_driver {
                LinkerDriver::Compiler(linker_driver) => {
                    invocation_mode = LinkerInvocationMode::Cc;

                    if cross_arch.is_some() {
                        let c_compiler = get_c_compiler(
                            linker_driver.name(),
                            linker_driver.c_language(),
                            cross_arch,
                        )?;
                        command = Command::new(c_compiler);
                    } else {
                        command = Command::new(linker_driver.name());
                    }

                    if linker.is_wild() {
                        let save_dir = output_path.with_extension("save");
                        command.env("WILD_SAVE_DIR", &save_dir);
                        opt_save_dir = Some(save_dir);
                    }

                    match linker_driver {
                        Compiler::Clang(_) => {
                            command.arg(format!(
                                "--ld-path={}",
                                linker_path
                                    .to_str()
                                    .expect("Linker path must be valid UTF-8")
                            ));
                        }
                        Compiler::Gcc(_) => {
                            match linker {
                                Linker::Wild => {
                                    // GCC unfortunately doesn't provide any way to use a custom
                                    // linker. Their flag for switching linkers only accepts a
                                    // hard-coded list of alternatives and the developers don't seem
                                    // to want any equivalent to clang's --ld-path. The closest we
                                    // can get is to put a file called "ld" in a directory, then
                                    // pass "-B" and that directory.
                                    let bin_dir = wild_path().parent().unwrap();
                                    command.arg("-B").arg(bin_dir);
                                }
                                Linker::ThirdParty(third_party_linker) => {
                                    command
                                        .arg(format!("-fuse-ld={}", third_party_linker.gcc_name));
                                }
                            }
                        }
                    }

                    if arch == Architecture::AArch64 {
                        // Provide a workaround for ld.lld: error: unknown argument
                        // '--fix-cortex-a53-835769' Bug link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105941
                        command.arg("-mno-fix-cortex-a53-835769");
                    }

                    command.args(&linker_args.args);
                }
                LinkerDriver::Direct(direct_config) => {
                    command = Command::new(linker_path);

                    if let Some(arch) = cross_arch {
                        command.arg("-m").arg(arch.emulation_name());
                    }

                    match direct_config.mode {
                        Mode::Dynamic => {
                            command
                                .arg("-dynamic-linker")
                                .arg(dynamic_linker_path(cross_arch));
                        }
                        Mode::Static => {
                            command.arg("-static");
                        }
                        Mode::Unspecified => {}
                    }

                    command.arg("--gc-sections").args(&linker_args.args);
                }
            }

            if !linker_args.args.iter().any(|arg| arg == "-o") {
                command.arg("-o").arg(output_path);
            }

            add_inputs_to_command(config, inputs, &mut command);
        }

        if linker.is_wild() {
            if matches!(config.linker_driver, LinkerDriver::Direct(_)) {
                command.arg("--validate-output");
                // TODO: Add a flag or do something so that unsupported flags get ignored. i.e. the
                // equivalent of the line below, but for directly calling libwild. Perhaps rather
                // than printing warnings, libwild should return them, then we as the caller can
                // just choose to not print them.
            } else {
                command.env(libwild::args::WILD_UNSUPPORTED_ENV, "ignore");
                command.env(libwild::args::VALIDATE_ENV, "1");
            }

            if config.should_diff {
                if matches!(config.linker_driver, LinkerDriver::Direct(_)) {
                    command.arg("--write-layout");
                    command.arg("--write-trace");
                } else {
                    command.env(libwild::args::WRITE_LAYOUT_ENV, "1");
                    command.env(libwild::args::WRITE_TRACE_ENV, "1");
                }
            }
        }

        let mut link_command = LinkCommand {
            command,
            inputs: inputs.to_vec(),
            input_commands: inputs
                .iter()
                .filter_map(|input| input.command.as_ref().cloned())
                .collect(),
            linker: linker.clone(),
            config: config.clone(),
            invocation_mode,
            opt_save_dir,
            output_path: output_path.to_owned(),
        };

        link_command
            .command
            .arg(invocation_mode.format_arg(&format!(
                "--dependency-file={}",
                link_command.depfile_path().display()
            )));

        Ok(link_command)
    }

    fn run(&mut self, config: &Config) -> Result {
        if !config.expect_errors.is_empty() {
            let output = self
                .command
                .output()
                .with_context(|| format!("Failed to run command: {:?}", self.command))?;

            if output.status.success() {
                bail!(
                    "Linker returned exit status of 0, when an error was expected. Command:\n{self}",
                );
            }

            for expected_error in &config.expect_errors {
                if !expected_error.matches(&output.stderr) {
                    eprintln!(
                        "-- stdout --\n{}\n-- stderr --\n{}\n-- end --",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr),
                    );
                    bail!(
                        "Linker expected to report error `{expected_error}` on stderr, but didn't. \
                         Command:\n{self}"
                    );
                }
            }

            return Ok(());
        }

        // If we're linking with wild and we're going to be invoking the linker directly, then just
        // use libwild as a library. This is marginally faster, since we avoid the process startup
        // costs. It also allows us to exercise wild as a library. We still exercise wild from the
        // command-line via the shell-script-based tests.
        if self.linker.is_wild() && self.invocation_mode == LinkerInvocationMode::Direct {
            let args = self
                .command
                .get_args()
                .map(|a| a.to_str())
                .collect::<Option<Vec<&str>>>()
                .context("Linker args must be valid utf-8")?;

            let linker = libwild::Linker::new();
            let parsed_args = libwild::Args::parse(|| args.iter())?;

            // This call is expected to error for all but the first call.
            let _ = libwild::setup_tracing(&parsed_args);
            let parsed_args = parsed_args.activate_thread_pool()?;

            linker
                .run(&parsed_args)
                .with_context(|| format!("libwild reported error. Rerun command(s):\n{self}"))?;

            return Ok(());
        }

        let output = self
            .command
            .output()
            .with_context(|| format!("Failed to run command: {:?}", self.command))?;

        let mut messages = String::from_utf8_lossy(&output.stdout).into_owned();
        messages.push_str(&String::from_utf8_lossy(&output.stderr));

        if !output.status.success() {
            bail!("Linker failed:\n{messages}\nRelink with:\n{self}");
        }

        if let Some(save_dir) = self.opt_save_dir.as_ref() {
            let run_with = run_with_path(save_dir);
            if !run_with.exists() {
                // Note, we print self.command here not self. Printing self will print the command
                // to run using the run-with script, which doesn't exist.
                bail!(
                    "run-with script didn't get written. Command:\n{:?}\nOutput:\n{messages}",
                    self.command
                );
            }
        }

        Ok(())
    }

    /// Returns whether we can skip invoking the linker.
    fn can_skip(&self) -> bool {
        // We never skip linking when the linker is wild.
        if self.linker.is_wild() {
            return false;
        }

        if !self.output_path.is_file() {
            return false;
        }

        let Ok(previous_hashes) = std::fs::read_to_string(self.hashes_path()) else {
            return false;
        };

        self.input_hashes() == previous_hashes
    }

    /// Returns a report containing the hashes of all the inputs. Also includes the linker
    /// command-line, not hashed, because that's more useful.
    fn input_hashes(&self) -> String {
        let mut hashes = self.to_string();

        hashes.push_str("\n\n");

        let mut hash_file = |path: &Path| {
            hashes.push_str(&path.to_string_lossy());
            hashes.push_str(": ");
            match std::fs::read(path) {
                Ok(contents) => {
                    let mut hasher = foldhash::fast::FixedState::default().build_hasher();
                    hasher.write(&contents);
                    write!(&mut hashes, "{:x}", hasher.finish()).unwrap();
                }
                Err(error) => hashes.push_str(&error.to_string()),
            }
            hashes.push('\n');
        };

        for dep in &self.config.tracked_files {
            hash_file(dep);
        }

        if let Ok(deps) = parse_ld_dependency_file(&self.depfile_path()) {
            for dep in deps {
                hash_file(&dep);
            }
        } else {
            for input in &self.inputs {
                hash_file(&input.path);
            }
        }

        hashes
    }

    fn write_input_hashes(&self) -> Result {
        // We always run wild, so we don't need a hash file.
        if self.linker.is_wild() {
            return Ok(());
        }

        let path = self.hashes_path();
        std::fs::write(&path, self.input_hashes())
            .with_context(|| format!("Failed to write `{}`", path.display()))?;
        Ok(())
    }

    fn depfile_path(&self) -> PathBuf {
        add_to_path(&self.output_path, ".deps")
    }

    fn hashes_path(&self) -> PathBuf {
        add_to_path(&self.output_path, ".hashes")
    }
}

/// Returns `path` + `extra`.
fn add_to_path(path: &Path, extra: &str) -> PathBuf {
    let mut path = path.as_os_str().to_owned();
    path.push(extra);
    PathBuf::from(path)
}

fn add_inputs_to_command(config: &Config, inputs: &[LinkerInput], command: &mut Command) {
    if !config.auto_add_objects {
        return;
    }

    for input in inputs {
        command.args(input.prefix_arg);
        if let Some(template) = input.template.as_ref() {
            let path_str = input.path.to_str().expect("Non-UTF-8 paths not supported");

            for a in template {
                if a.contains(TEMPLATE_PLACEHOLDER) {
                    command.arg(a.replace(TEMPLATE_PLACEHOLDER, path_str));
                } else {
                    command.arg(a);
                }
            }
        } else {
            command.arg(&input.path);
        }
    }
}

fn get_script(inputs: &[LinkerInput]) -> Option<(PathBuf, &[LinkerInput])> {
    let path = &inputs[0].path;
    if path.is_dir() {
        return Some((run_with_path(path), &inputs[1..]));
    }
    None
}

impl Assertions {
    fn check(&self, link_output: &LinkOutput) -> Result {
        self.check_path(&link_output.binary, &link_output.linker_used)
    }

    fn check_path(&self, path: &PathBuf, linker_used: &Linker) -> Result {
        let bytes = std::fs::read(path)?;
        let obj = ElfFile64::parse(bytes.as_slice())?;

        self.verify_file_kind(&obj)?;
        verify_symbol_assertions(&obj, &self.expected_symtab_entries, obj.symbols())?;
        verify_symbol_assertions(&obj, &self.expected_dynsym_entries, obj.dynamic_symbols())?;
        self.verify_symbols_absent(&self.no_sym, obj.symbols(), ".symtab")?;
        self.verify_symbols_absent(&self.no_sym, obj.dynamic_symbols(), ".dynsym")?;
        self.verify_symbols_absent(&self.no_dynsym, obj.dynamic_symbols(), ".dynsym")?;
        self.verify_comment_section(&obj, linker_used)?;
        self.verify_strings(&bytes)?;
        self.verify_load_alignment(&obj)?;
        self.verify_dynamic_entries(&obj)?;
        Ok(())
    }

    fn verify_comment_section(&self, obj: &ElfFile64, linker_used: &Linker) -> Result {
        if self.expected_comments.is_empty() {
            match linker_used {
                Linker::Wild => {
                    if !was_linked_with_wild(obj) {
                        bail!("Object was supposed to be linked with wild, but is missing comment");
                    }
                }
                Linker::ThirdParty(linker) => {
                    if was_linked_with_wild(obj) {
                        bail!(
                            "Object was supposed to be linked with {linker}, but .comment \
                             indicates it was linked with Wild"
                        );
                    }
                }
            }
            return Ok(());
        }
        let actual_comments = read_comments(obj)?;
        for expected in self.expected_comments.iter() {
            if let Some(expected) = expected.strip_suffix('*') {
                if !actual_comments
                    .iter()
                    .any(|actual| actual.starts_with(expected))
                {
                    bail!("Expected .comment starting with `{expected}`");
                }
            } else if !actual_comments.iter().any(|actual| actual == expected) {
                bail!("Expected .comment `{expected}`");
            }
        }

        Ok(())
    }

    fn verify_strings(&self, bytes: &[u8]) -> Result {
        for needle in &self.does_not_contain {
            if bytes.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                bail!("Binary contains `{needle}` when it shouldn't");
            }
        }
        for needle in &self.contains_strings {
            if !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                bail!("Binary doesn't contain `{needle}` when it should");
            }
        }
        Ok(())
    }

    fn verify_load_alignment(&self, obj: &ElfFile64) -> Result {
        let Some(expected) = self.expected_load_alignment else {
            return Ok(());
        };

        let endian = LittleEndian;
        let segments = obj.elf_program_headers();
        for segment in segments {
            if segment.p_type(endian) == object::elf::PT_LOAD {
                let alignment = segment.p_align(endian);
                if alignment != expected {
                    bail!("Expected LOAD segment alignment {expected:#x}, but got {alignment:#x}");
                }

                return Ok(());
            }
        }

        bail!("No LOAD segment found");
    }

    fn verify_symbols_absent(
        &self,
        absent_syms: &HashSet<String>,
        symbols: object::read::elf::ElfSymbolIterator<object::elf::FileHeader64<LittleEndian>>,
        table_name: &str,
    ) -> Result {
        if absent_syms.is_empty() {
            return Ok(());
        }

        for sym in symbols {
            if let Ok(name) = sym.name()
                && absent_syms.contains(name)
            {
                bail!("Symbol `{name}` was supposed to be absent, but was found in {table_name}");
            }
        }

        Ok(())
    }

    fn verify_file_kind(&self, obj: &ElfFile64) -> Result {
        // For now, our file-kind identification is limited to just whether there's a dynamic symbol
        // table.
        if self.expect_dynamic {
            ensure!(
                obj.dynamic_symbol_table().is_some(),
                "Expected a dynamic symbol table"
            );
        }

        Ok(())
    }

    fn verify_dynamic_entries(&self, obj: &ElfFile64) -> Result {
        if self.expected_dynamic_entries.is_empty() && self.absent_dynamic_entries.is_empty() {
            return Ok(());
        }

        let Some(dynamic_section) = obj.section_by_name(".dynamic") else {
            if !self.expected_dynamic_entries.is_empty() {
                bail!(
                    "Expected dynamic entries {:?} but no .dynamic section found",
                    self.expected_dynamic_entries
                );
            }
            return Ok(());
        };

        let data = dynamic_section.data()?;
        let entry_size = std::mem::size_of::<object::elf::Dyn64<LittleEndian>>();
        let mut found_tags: HashSet<String> = HashSet::new();

        for chunk in data.chunks_exact(entry_size) {
            let tag = u64::from_le_bytes(chunk[0..8].try_into().unwrap()) as u32;
            if let Some(name) = dynamic_tag_name(tag) {
                found_tags.insert(name.to_string());
            }

            if tag == object::elf::DT_NULL {
                break;
            }
        }

        for expected in &self.expected_dynamic_entries {
            if !found_tags.contains(expected.as_str()) {
                bail!(
                    "Expected dynamic entry `{expected}` not found. Found: {:?}",
                    found_tags
                );
            }
        }

        for absent in &self.absent_dynamic_entries {
            if found_tags.contains(absent.as_str()) {
                bail!("Dynamic entry `{absent}` should be absent but was found");
            }
        }

        Ok(())
    }
}

fn dynamic_tag_name(tag: u32) -> Option<&'static str> {
    use object::elf::*;
    Some(match tag {
        DT_NULL => "DT_NULL",
        DT_NEEDED => "DT_NEEDED",
        DT_PLTRELSZ => "DT_PLTRELSZ",
        DT_PLTGOT => "DT_PLTGOT",
        DT_HASH => "DT_HASH",
        DT_STRTAB => "DT_STRTAB",
        DT_SYMTAB => "DT_SYMTAB",
        DT_RELA => "DT_RELA",
        DT_RELASZ => "DT_RELASZ",
        DT_RELAENT => "DT_RELAENT",
        DT_STRSZ => "DT_STRSZ",
        DT_SYMENT => "DT_SYMENT",
        DT_INIT => "DT_INIT",
        DT_FINI => "DT_FINI",
        DT_SONAME => "DT_SONAME",
        DT_RPATH => "DT_RPATH",
        DT_SYMBOLIC => "DT_SYMBOLIC",
        DT_REL => "DT_REL",
        DT_RELSZ => "DT_RELSZ",
        DT_RELENT => "DT_RELENT",
        DT_PLTREL => "DT_PLTREL",
        DT_DEBUG => "DT_DEBUG",
        DT_TEXTREL => "DT_TEXTREL",
        DT_JMPREL => "DT_JMPREL",
        DT_BIND_NOW => "DT_BIND_NOW",
        DT_INIT_ARRAY => "DT_INIT_ARRAY",
        DT_FINI_ARRAY => "DT_FINI_ARRAY",
        DT_INIT_ARRAYSZ => "DT_INIT_ARRAYSZ",
        DT_FINI_ARRAYSZ => "DT_FINI_ARRAYSZ",
        DT_RUNPATH => "DT_RUNPATH",
        DT_FLAGS => "DT_FLAGS",
        DT_PREINIT_ARRAY => "DT_PREINIT_ARRAY",
        DT_PREINIT_ARRAYSZ => "DT_PREINIT_ARRAYSZ",
        DT_FLAGS_1 => "DT_FLAGS_1",
        DT_GNU_HASH => "DT_GNU_HASH",
        DT_RELACOUNT => "DT_RELACOUNT",
        DT_RELCOUNT => "DT_RELCOUNT",
        DT_VERSYM => "DT_VERSYM",
        DT_VERDEF => "DT_VERDEF",
        DT_VERDEFNUM => "DT_VERDEFNUM",
        DT_VERNEED => "DT_VERNEED",
        DT_VERNEEDNUM => "DT_VERNEEDNUM",
        _ => return None,
    })
}

fn verify_symbol_assertions(
    obj: &ElfFile64,
    assertions: &[ExpectedSymtabEntry],
    symbols: object::read::elf::ElfSymbolIterator<object::elf::FileHeader64<LittleEndian>>,
) -> Result {
    let mut missing = assertions
        .iter()
        .map(|exp| (exp.name.as_str(), exp))
        .collect::<HashMap<_, _>>();

    for sym in symbols {
        let Ok(name) = sym.name() else {
            continue;
        };
        let Some(exp) = missing.remove(name) else {
            continue;
        };

        if let object::SymbolSection::Section(index) = sym.section() {
            let section = obj.section_by_index(index)?;
            let section_name = section.name()?;

            if let Some(exp_name) = exp.assertions.section_name.as_ref() {
                if section_name != exp_name {
                    bail!(
                        "Expected symbol `{name}` to be in section `{exp_name}`, \
                                but it was in `{section_name}`"
                    );
                }

                if let Some(expected_offset) = exp.assertions.section_offset {
                    let actual_offset = sym.address().wrapping_sub(section.address());
                    if expected_offset != actual_offset {
                        bail!(
                            "Expected symbol `{name}` to be at offset {expected_offset} \
                                    in section `{exp_name}`, but it was actually at offset {}",
                            actual_offset as i64
                        );
                    }
                }
            }
        }

        // Check assertions not related to sections.
        if let Some(expected_address) = exp.assertions.absolute_address {
            let actual_address = sym.address();
            if expected_address != actual_address {
                bail!(
                    "Expected symbol `{name}` to have address {expected_address:#x}, \
                                but it actually had address {actual_address:#x}"
                );
            }
        }

        if let Some(expected_size) = exp.assertions.size {
            let actual_size = sym.size();
            if expected_size != actual_size {
                bail!(
                    "Expected symbol `{name}` to have size {expected_size}, \
                                but it actually had size {actual_size}"
                );
            }
        }
    }

    let missing: Vec<&str> = missing.into_keys().collect();
    if !missing.is_empty() {
        bail!("Missing expected symbol(s): {}", missing.join(", "));
    };

    Ok(())
}

/// Returns whether the supplied object indicates that it was linked with wild.
fn was_linked_with_wild(obj: &ElfFile64) -> bool {
    let Ok(actual_comments) = read_comments(obj) else {
        return false;
    };
    actual_comments
        .iter()
        .any(|comment| comment.starts_with("Linker: Wild version"))
}

fn read_comments<'data>(obj: &ElfFile64<'data>) -> Result<Vec<std::borrow::Cow<'data, str>>> {
    let comment_section = obj
        .section_by_name(".comment")
        .context("Missing .comment section")?;
    let data = comment_section.data()?;
    Ok(data
        .split(|b| *b == 0)
        .map(|c| String::from_utf8_lossy(c))
        .filter(|c| !c.is_empty())
        .collect())
}

impl LinkerDriver {
    fn parse(arg: &str) -> Result<LinkerDriver> {
        match arg.trim() {
            "gcc" => Ok(LinkerDriver::Compiler(Compiler::Gcc(CLanguage::C))),
            "g++" => Ok(LinkerDriver::Compiler(Compiler::Gcc(CLanguage::Cpp))),
            "clang" => Ok(LinkerDriver::Compiler(Compiler::Clang(CLanguage::C))),
            "clang++" => Ok(LinkerDriver::Compiler(Compiler::Clang(CLanguage::Cpp))),
            "" | "none" => Ok(LinkerDriver::Direct(Default::default())),
            other => bail!("Unsupported linker driver `{other}`"),
        }
    }

    fn direct_mut(&mut self) -> Result<&mut DirectConfig> {
        match self {
            LinkerDriver::Compiler(_) => {
                bail!("Config option is incompatible with LinkerDriver::Compiler")
            }
            LinkerDriver::Direct(direct_config) => Ok(direct_config),
        }
    }
}

impl Compiler {
    fn name(&self) -> &str {
        match self {
            Compiler::Gcc(CLanguage::C) => "gcc",
            Compiler::Gcc(CLanguage::Cpp) => "g++",
            Compiler::Clang(CLanguage::C) => "clang",
            Compiler::Clang(CLanguage::Cpp) => "clang++",
        }
    }

    fn c_language(&self) -> CLanguage {
        match self {
            Compiler::Gcc(lang) | Compiler::Clang(lang) => *lang,
        }
    }
}

impl Display for LinkCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(save_dir) = self.opt_save_dir.as_ref()
            && save_dir.exists()
            && self.linker == Linker::Wild
        {
            write!(
                f,
                "WILD_WRITE_LAYOUT=1 WILD_WRITE_TRACE=1 OUT={} {}/run-with cargo run \
                     --bin wild --",
                self.output_path.display(),
                save_dir.display()
            )?;
            return Ok(());
        }

        for sub in &self.input_commands {
            writeln!(f, "{sub}")?;
        }

        // A bit of indentation makes it easier to see the start of the command, especially when it
        // wraps over several lines and there are multiple commands.
        write!(f, "        ")?;

        let mut command_str = self.command.get_program().to_string_lossy();

        let mut args = self
            .command
            .get_args()
            .map(|a| a.to_string_lossy())
            .collect_vec();

        if command_str == "bash" {
            command_str = args.remove(0);
        }

        match (self.invocation_mode, &self.linker) {
            (LinkerInvocationMode::Cc, Linker::Wild) => {
                write!(f, "cargo build; {} {}", command_str, args.join(" "))
            }
            (LinkerInvocationMode::Direct, Linker::Wild) => {
                write!(f, "cargo run --bin wild -- {}", args.join(" "))
            }
            (LinkerInvocationMode::Script, Linker::Wild) => {
                for (k, v) in self.command.get_envs() {
                    write!(
                        f,
                        "{}={} ",
                        k.to_str().unwrap_or("??"),
                        v.and_then(|v| v.to_str()).unwrap_or_default(),
                    )?;
                }

                // The first argument is the linker, which we're replacing with `cargo run --`.
                args.remove(0);

                write!(
                    f,
                    "{} cargo run --bin wild -- {}",
                    command_str,
                    args.join(" ")
                )
            }
            _ => {
                write!(f, "{} {}", command_str, args.join(" "))
            }
        }
    }
}

impl Display for ProgramInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.name(), f)
    }
}

impl Display for Linker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Linker::Wild => Display::fmt(&"wild", f),
            Linker::ThirdParty(info) => Display::fmt(info.name, f),
        }
    }
}

impl Display for InputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputType::Object => write!(f, "object"),
            InputType::Archive => write!(f, "archive"),
            InputType::ThinArchive => write!(f, "thin archive"),
            InputType::BsdArchive => write!(f, "bsd archive"),
            InputType::SharedObject => write!(f, "shared"),
            InputType::LinkerScript => write!(f, "linker script"),
        }
    }
}

impl Display for ThirdPartyLinker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.name, f)
    }
}

fn clone_command(command: &Command) -> Command {
    let mut out = Command::new(command.get_program());
    out.args(command.get_args());
    for (k, v) in command.get_envs() {
        if let Some(v) = v {
            out.env(k, v);
        } else {
            out.env_remove(k);
        }
    }
    if let Some(dir) = command.get_current_dir() {
        out.current_dir(dir);
    }

    out
}

impl Clone for LinkCommand {
    fn clone(&self) -> Self {
        Self {
            command: clone_command(&self.command),
            input_commands: self.input_commands.to_vec(),
            linker: self.linker.clone(),
            invocation_mode: self.invocation_mode,
            opt_save_dir: self.opt_save_dir.clone(),
            output_path: self.output_path.clone(),
            inputs: self.inputs.clone(),
            config: self.config.clone(),
        }
    }
}

fn diff_shared_objects(instructions: &Config, programs: &[Program]) -> Result {
    // All our programs should have the same number of shared objects and they should be in the same
    // order. We use this to group shared objects at the corresponding index so that we can then
    // diff them.
    let mut so_groups = Vec::new();
    for program in programs {
        for (i, so) in program.shared_objects.iter().enumerate() {
            if i >= so_groups.len() {
                so_groups.push(Vec::new());
            }
            so_groups[i].push(so);
        }
    }
    for so_group in so_groups {
        let filenames = so_group.iter().map(|i| i.path.clone()).collect_vec();
        diff_files(
            instructions,
            filenames,
            // Shared objects should always have a command.
            so_group.last().unwrap().command.as_ref().unwrap(),
        )?;
    }
    Ok(())
}

fn diff_executables(config: &Config, programs: &[Program]) -> Result {
    let filenames = programs
        .iter()
        .map(|p| p.link_output.binary.clone())
        .collect_vec();
    diff_files(config, filenames, programs.last().unwrap())
}

/// Diff the supplied files. The last file should be the one that we produced.
fn diff_files(config: &Config, files: Vec<PathBuf>, display: &dyn Display) -> Result {
    if !config.should_diff {
        return Ok(());
    }

    let mut diff_config = linker_diff::Config::default();
    diff_config.colour = linker_diff::Colour::Always;
    diff_config.wild_defaults = true;
    diff_config
        .ignore
        .extend(config.diff_ignore.iter().cloned());
    diff_config
        .ignore
        .extend(config.test_config.diff_ignore.iter().cloned());
    diff_config
        .equiv
        .extend(config.section_equiv.iter().cloned());
    diff_config.references = files.clone();
    diff_config.file = diff_config
        .references
        .pop()
        .context("Tried to diff zero files")?;
    let report = linker_diff::Report::from_config(diff_config.clone()).with_context(|| {
        format!(
            "Report::from_config failed for the following files: {}",
            files.iter().map(|f| f.to_string_lossy()).join(" ")
        )
    })?;
    if report.has_problems() {
        eprintln!("{report}");
        bail!(
            "Validation failed.\n{display}\n To revalidate:\ncargo run --bin linker-diff -- \
             {}\nTo disable diff checking, set run_all_diffs=false in test config (see CONTRIBUTING.md)",
            diff_config.to_arg_string()
        );
    }
    Ok(())
}

fn setup_wild_ld_symlink() -> Result {
    let wild = wild_path();
    let wild_ld_path = wild.with_file_name("ld");
    if let Err(error) = std::os::unix::fs::symlink(wild, &wild_ld_path)
        && error.kind() != std::io::ErrorKind::AlreadyExists
    {
        Err(error).with_context(|| {
            format!(
                "Failed to symlink `{}` to `{}`",
                wild_ld_path.display(),
                wild.display()
            )
        })?
    }
    Ok(())
}

fn find_bin(names: &[&str]) -> Result<PathBuf> {
    names
        .iter()
        .find_map(|n| which::which(n).ok())
        .with_context(|| {
            format!(
                "Failed to find any of the following on the path: {}",
                names.join(", ")
            )
        })
}

fn find_cross_paths(name: &str) -> HashMap<Architecture, PathBuf> {
    [
        Architecture::AArch64,
        Architecture::RISCV64,
        Architecture::LoongArch64,
    ]
    .into_iter()
    .map(|arch| {
        let path = PathBuf::from(format!("/usr/{arch}-linux-gnu/bin/{name}"));
        if path.exists() {
            (arch, path)
        } else {
            (arch, PathBuf::from(name))
        }
    })
    .collect()
}

static INIT: Once = Once::new();

#[fixture]
fn setup_symlink() {
    INIT.call_once(|| {
        setup_wild_ld_symlink().unwrap();
    });
}

fn should_print_timing() -> bool {
    static VALUE: OnceLock<bool> = OnceLock::new();
    *VALUE.get_or_init(|| std::env::var("WILD_TEST_PRINT_TIMING").is_ok())
}

impl LinkerInvocationMode {
    fn format_arg(&self, arg: &str) -> String {
        match self {
            LinkerInvocationMode::Direct | LinkerInvocationMode::Script => arg.to_owned(),
            LinkerInvocationMode::Cc => {
                format!("-Wl,{arg}")
            }
        }
    }
}

impl ErrorMatcher {
    fn new(pattern: &str) -> Result<Self> {
        let regex = regex::bytes::Regex::new(pattern)?;
        Ok(Self { regex })
    }

    fn matches(&self, stderr: &[u8]) -> bool {
        self.regex.is_match(stderr)
    }
}

impl Display for ErrorMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.regex.as_str())
    }
}

impl PartialEq for ErrorMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.regex.as_str() == other.regex.as_str()
    }
}

impl Eq for ErrorMatcher {}

fn available_linkers() -> Result<Vec<Linker>> {
    let mut linkers = vec![
        Linker::ThirdParty(ThirdPartyLinker {
            name: "ld",
            gcc_name: "bfd",
            path: find_bin(&["ld.bfd", "ld"])?,
            cross_paths: find_cross_paths("ld"),
            enabled_by_default: true,
        }),
        Linker::ThirdParty(ThirdPartyLinker {
            name: "lld",
            gcc_name: "lld",
            path: find_bin(&["ld.lld"])?,
            cross_paths: find_cross_paths("ld.lld"),
            enabled_by_default: false,
        }),
    ];

    // We don't need gold and mold for our tests, they're just there for the odd occasion when we're
    // curious and looking for extra data points as to how other linkers handle a particular case.
    if let Ok(path) = find_bin(&["gold"]) {
        linkers.push(Linker::ThirdParty(ThirdPartyLinker {
            name: "gold",
            gcc_name: "gold",
            path,
            cross_paths: find_cross_paths("gold"),
            enabled_by_default: false,
        }));
    }
    if let Ok(path) = find_bin(&["mold"]) {
        linkers.push(Linker::ThirdParty(ThirdPartyLinker {
            name: "mold",
            gcc_name: "mold",
            path,
            cross_paths: find_cross_paths("mold"),
            enabled_by_default: false,
        }));
    }

    linkers.push(Linker::Wild);

    Ok(linkers)
}

fn run_with_config(
    program_inputs: &ProgramInputs,
    config: &Config,
    cross_arch: Option<Architecture>,
    linkers: &[Linker],
) -> Result {
    let programs = linkers
        .iter()
        .filter(|linker| config.is_linker_enabled(linker))
        .map(|linker| {
            let start = Instant::now();
            let result = program_inputs
                .build(linker, config, cross_arch)
                .with_context(|| {
                    format!(
                        "Test failed: `{program_inputs}` \
                        with linker `{linker}` config `{}`",
                        config.name
                    )
                });
            let is_cache_hit = result
                .as_ref()
                .is_ok_and(|p| p.link_output.command.can_skip());
            if !is_cache_hit && should_print_timing() {
                println!(
                    "{program_inputs}-{config} with {linker} took {} ms",
                    start.elapsed().as_millis()
                );
            }
            result
        })
        .collect::<Result<Vec<_>>>()?;

    // If we expect an error, then don't try to diff or run the output.
    if !config.expect_errors.is_empty() {
        return Ok(());
    }

    let start = Instant::now();

    if config.should_diff || config.should_run {
        for program in &programs {
            if !program.link_output.binary.exists() {
                bail!("Linker failed to write binary. {program}");
            }
        }
    }

    if config.test_config.run_all_diffs {
        diff_shared_objects(config, &programs)?;
        diff_executables(config, &programs)?;
    }

    if should_print_timing() {
        println!(
            "{program_inputs}-{config} diff took {} ms",
            start.elapsed().as_millis()
        );
    }

    for program in programs {
        if config.should_run || program.assertions != &Assertions::default() {
            program
                .assertions
                .check(&program.link_output)
                .with_context(|| format!("Output binary assertions failed. {program}"))?;
        }

        if config.should_run {
            program
                .run(cross_arch)
                .with_context(|| format!("Failed to run program. {program}"))?;
        }
    }

    Ok(())
}

#[rstest]
fn integration_test(
    #[values(
        "trivial.c",
        "trivial-main.c",
        "trivial-dynamic.c",
        "link_args.c",
        "global_definitions.c",
        "data.c",
        "data-pointers.c",
        "weak-vars.c",
        "weak-vars-archive.c",
        "weak-fns.c",
        "weak-fns-archive.c",
        "init_test.c",
        "ifunc.c",
        "init-order.c",
        "internal-syms.c",
        "tls.c",
        "tlsdesc.c",
        "tls-variant.c",
        "weak-entry.c",
        "no_start.c",
        "old_init.c",
        "custom_section.c",
        "stack_alignment.s",
        "got_ref_to_local.c",
        "local_symbol_refs.s",
        "archive_activation.c",
        "relocation-in-non-alloc-section.s",
        "exclude-libs-all.c",
        "exclude-libs-single.c",
        "exclude-libs-selective.c",
        "exclude-section.s",
        "common_section.c",
        "string_merging.c",
        "non_string_merging.c",
        "string-merge-missing-null.c",
        "comments.c",
        "custom-note.s",
        "executable_start.c",
        "backtrace.c",
        "eh_frame.c",
        "symbol-priority.c",
        "hidden-ref.c",
        "trivial_asm.s",
        "non-alloc.s",
        "gnu-unique.c",
        "symbol-versions.c",
        "simple-version-script.c",
        "mixed-verdef-verneed.c",
        "copy-relocations.c",
        "relocation-overflow.c",
        "force-undefined.c",
        "wrap.c",
        "shlib-archive-activation.c",
        "linker-script.c",
        "linker-script-executable.c",
        "linker-script-provide.c",
        "libc-ifunc.c",
        "libc-integration.c",
        "rust-integration.rs",
        "rust-integration-dynamic.rs",
        "tls-custom.c",
        "cpp-integration.cc",
        "rust-tls.rs",
        "basic-comdat.s",
        "input_does_not_exist.c",
        "ifunc2.c",
        "ctors.c",
        "visibility-merging.c",
        "tls-local-exec.c",
        "tls-local-dynamic.c",
        "undefined_symbols.c",
        "shlib-undefined.c",
        "whole_archive.c",
        "entry_arg.c",
        "dynamic-bss-only.c",
        "shared-priority.c",
        "shared.c",
        "duplicate_strong_symbols.c",
        "linker-plugin-lto.c",
        "lto-no-plugin.c",
        "lto-integration.c",
        "preinit-array.c",
        "exception.cc",
        "z-defs.c",
        "export-dynamic.c",
        "unresolved-symbols-object.c",
        "unresolved-symbols-shared.c",
        "symbol-version-symver.c",
        "symbol-version-symver-error.c",
        "symver-shared.c",
        "output-kind.c",
        "entry-in-shared.c",
        "alignment.c",
        "hash-style.c",
        "defsym.c",
        "linker-script-defsym-notfound.c",
        "tls-common.c",
        "section-start.c",
        "max-page-size.c",
        "call-via-defsym.c",
        "wrap-real-only.c",
        "ifunc-alias.c",
        "ifunc-address-equality.c",
        "ifunc-export.c",
        "stack-size.c",
        "undefined-weak-sym.c",
        "auxiliary.c",
        "new-dtags.c",
        "riscv-attr-conflict.s",
        "riscv-call-relaxation.s",
        "riscv-cross-object-call-relaxation.s",
        "segment-end-syms.c"
    )]
    program_name: &'static str,
    #[allow(unused_variables)] setup_symlink: (),
) -> Result {
    let build_dir = determine_build_dir(program_name);
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("Failed to create directory `{}`", build_dir.display()))?;

    let program_inputs = ProgramInputs::new(program_name)?;

    let linkers = available_linkers()?;

    let test_config = read_test_config()?;

    let filename = &program_inputs.source_file;
    let configs = parse_configs(&src_path(filename), &Config::new(&test_config, build_dir))
        .with_context(|| format!("Failed to parse test parameters from `{filename}`"))?;

    let host_arch = get_host_architecture();

    for &arch in ALL_ARCHITECTURES {
        if arch != host_arch && !test_config.qemu_arch.contains(&arch) {
            continue;
        }

        let cross_arch = (arch != get_host_architecture()).then_some(arch);

        let config_it = configs.iter().filter(|config| !config.should_skip(arch));

        for config in config_it {
            let mut config = config.clone();
            config.rustc_channel = test_config.rustc_channel;

            if !test_config.allow_rust_musl_target && config.requires_rust_musl {
                continue;
            }

            if let Err(error) =
                verify_platform_requirements(&config, cross_arch, Path::new(filename))
            {
                if full_test_platform_required() {
                    return Err(error);
                }
                continue;
            }

            let arch_name = cross_name(cross_arch);
            config.build_dir = config
                .base_build_dir
                .join(format!("{}-{arch_name}", config.name));
            std::fs::create_dir_all(&config.build_dir).with_context(|| {
                format!(
                    "Failed to create directory `{}`",
                    config.build_dir.display()
                )
            })?;

            run_with_config(&program_inputs, &config, cross_arch, &linkers)?
        }
    }

    Ok(())
}

/// Verifies that the platform that we're running on meets the requirements for the supplied test
/// config.
fn verify_platform_requirements(
    config: &Config,
    cross_arch: Option<Architecture>,
    src_path: &Path,
) -> Result {
    if config.requires_linker_plugin {
        verify_linker_plugin_requirements(config, cross_arch, src_path)?;
    }

    if config.requires_compiler_flags.is_empty() {
        return Ok(());
    }

    let Some((compiler, _)) = compiler_for_file(src_path, cross_arch, config)? else {
        return Ok(());
    };

    verify_command_success(
        Command::new(&compiler)
            .args(["-c", "-x", "c", "-", "-o", "/dev/null"])
            .args(&config.requires_compiler_flags),
    )
}

fn verify_linker_plugin_requirements(
    config: &Config,
    cross_arch: Option<Architecture>,
    src: &Path,
) -> Result {
    if !cfg!(feature = "plugins") {
        bail!("The `plugins` feature is disabled");
    }

    let (compiler, compiler_kind) = compiler_for_file(src, cross_arch, config)?
        .with_context(|| format!("Config in {} does not use a linker driver", src.display()))?;

    match compiler_kind {
        CompilerKind::Rust => {
            // Check that rustc can use linker-plugin-lto with the installed clang. This eliminates
            // platforms where the LLVM version used by clang doesn't match the version used by
            // rustc.
            let mut command = Command::new(&compiler);
            command.args(config.rustc_channel.as_arg());
            command.arg(src_path("lto-verifier.rs"));
            command.args([
                "-Clinker=clang",
                "-Clinker-plugin-lto",
                "-Clink-arg=-flto",
                "-o",
                "/tmp/rust.out",
            ]);
            verify_command_success(&mut command).context(
                "Can't use rust+clang with linker plugin. LLVM version mismatch? \
                Check that clang --version matches LLVM version reported by `rustc -vV`.",
            )?;
        }
        CompilerKind::C => {
            // Verify that the linker-driver can use a linker plugin with the default linker. This
            // helps us to skip for example clang on openSUSE which doesn't bundle the linker
            // plugin.
            let LinkerDriver::Compiler(linker_driver) = config.linker_driver else {
                bail!("A linker driver is required for LTO");
            };
            let linker_driver_string =
                get_c_compiler(linker_driver.name(), linker_driver.c_language(), cross_arch)?;

            let mut command = Command::new(&linker_driver_string);
            command.args([
                "-shared",
                "-nostdlib",
                "-flto",
                "-x",
                "c",
                "-fuse-ld=bfd",
                "-",
                "-o",
                "/dev/null",
            ]);

            verify_command_success(&mut command)
                .context("Can't use compiler with linker-plugin")?;
        }
    }

    // Check that we're not statically linked. Plugins can't be loaded if we're statically linked.
    ensure!(
        !cfg!(target_feature = "crt-static"),
        "Cannot run linker-plugin tests when static linking is enabled"
    );

    Ok(())
}

fn verify_command_success(command: &mut Command) -> Result {
    let output = command
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("Failed to run {command:?}"))?;

    if !output.status.success() {
        bail!(
            "Failed platform test requirements. {command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

fn full_test_platform_required() -> bool {
    std::env::var(FULL_PLATFORM_REQUIRED_VAR).is_ok_and(|v| !v.is_empty())
}

fn get_wild_test_cross() -> Result<Option<Vec<Architecture>>> {
    std::env::var("WILD_TEST_CROSS")
        .ok()
        .map(|cross_arch| {
            if cross_arch == "all" {
                let host_arch = get_host_architecture();
                Ok(ALL_ARCHITECTURES
                    .iter()
                    .copied()
                    .filter(|&arch| arch != host_arch)
                    .collect())
            } else {
                cross_arch
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        Architecture::from_str(s)
                            .with_context(|| format!("Unknown cross arch `{s}`"))
                    })
                    .collect()
            }
        })
        .transpose()
}

fn read_test_config() -> Result<TestConfig> {
    let config_default_path = base_dir().parent().unwrap().join("test-config.toml");

    let config_path = std::env::var("WILD_TEST_CONFIG")
        .map(|config_path| base_dir().parent().unwrap().join(config_path))
        .unwrap_or_else(|_| config_default_path.clone());

    let mut config = if config_path.exists() {
        let config_content = std::fs::read_to_string(&config_path).with_context(|| {
            format!(
                "Failed to read WILD_TEST_CONFIG file at `{}`",
                config_path.display()
            )
        })?;

        toml::from_str(&config_content)
            .with_context(|| format!("Unable to load config from {config_path:?}"))?
    } else if config_path == config_default_path {
        TestConfig::default()
    } else {
        bail!(
            "WILD_TEST_CONFIG file not found at `{}`",
            config_path.display()
        );
    };

    // The environment variable `WILD_TEST_CROSS` can override the config file setting.
    if let Some(qemu_arch_from_env) = get_wild_test_cross()? {
        config.qemu_arch = qemu_arch_from_env;
    }

    Ok(config)
}

#[cfg(test)]
mod tidy {
    use super::*;

    #[test]
    fn check_sources_format() {
        if std::env::var_os("WILD_TEST_IGNORE_FORMAT").is_some() {
            return;
        }

        let extensions = ["c", "cc", "h"];
        let sources_path = format!("{}/tests/sources", env!("CARGO_MANIFEST_DIR"));
        let files_iter = read_dir(&sources_path).unwrap().filter_map(|entry| {
            let path = entry.as_ref().unwrap().path();
            if path.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extensions.contains(&extension.to_str().unwrap()))
            {
                Some(path)
            } else {
                None
            }
        });

        let clang_format_out = Command::new("clang-format")
            .arg("--dry-run")
            .arg("-Werror")
            // Undocumented option that forces the colours: https://github.com/llvm/llvm-project/issues/119224
            .arg("--color")
            .args(files_iter)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("Failed to spawn `clang-format`, is it installed?");

        if !clang_format_out.status.success() {
            let stdout = String::from_utf8_lossy(&clang_format_out.stdout);
            let stderr = String::from_utf8_lossy(&clang_format_out.stderr);
            let mut out = String::with_capacity(stdout.len() + stderr.len() + 1);
            if !stdout.is_empty() {
                out.push_str(&stdout);
                if !stderr.is_empty() {
                    out.push('\n');
                }
            }
            if !stderr.is_empty() {
                out.push_str(&stderr);
            }
            let clang_out = Command::new("clang-format")
                .arg("--version")
                .output()
                .expect("Failed to spawn `clang-format --version`");
            let clang_version = String::from_utf8_lossy(&clang_out.stdout);
            let version_no_endline = clang_version.trim_end_matches('\n');
            panic!(
                "clang-format ({version_no_endline}) check failed:\n{out}\nRun `clang-format -i {sources_path}/*.{{{extensions_str}}}` to fix it.",
                extensions_str = extensions.join(",")
            )
        }
    }
}
