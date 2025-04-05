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
//!
//! LinkSoArgs:... Arguments to pass when linking a shared object.
//!
//! WildExtraLinkArgs:... Extra linker arguments that should only be passed to the Wild linker.
//!
//! CompArgs:... Arguments to be passed to the compiler when building object files.
//!
//! CompSoArgs:... Arguments to be passed to the compiler when building shared objects.
//!
//! ExpectSym:symbol-name [section] Checks that the specified symbol is defined in the output file
//! and, if specified, that it's in the specified section.
//!
//! ExpectComment: Checks that the comment in the .comment section is equal to the supplied
//! argument. If no ExpectComment directives are given then .comment isn't checked. The argument may
//! end with '*' which matches anything.
//!
//! DoesNotContain:{string} Checks that the output binary doesn't contain the specified string.
//!
//! Contains:{string} Checks that the output binary does contain the specified string.
//!
//! Static:{bool} Only applicable when LinkerDriver=none. Defaults to true. Set to false to disable
//! passing `-static` to the linker.
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
//! ExpectError:{error string} Verifies that the link fails and that the error message includes the
//! specified string. Implies `RunEnabled:false` and `DiffEnabled:false`.
//!
//! SecEquiv:{sec-name}={sec-name} Tells linker-diff that the two section names should be considered
//! as equivalent.
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
//! Shared:{source-filename}[:extra-compilation-args] Builds the specified filename as a shared
//! object and adds it to the link.
//!
//! Compiler:gcc|g++|clang|clang++ Specifies what compiler should be used to compile C/C++ code.
//!
//! Arch:{arch1}[,{arch2}...] Specifies which architectures this test should be run with. Defaults
//! to all supported architectures.
//!
//! RequiresGlibc:{bool} Defaults to false. Set to true to disable this test if we're running on a
//! system without glibc.
//!
//! RequiresNightlyRustc:{bool} Defaults to false. Set to true to disable this test if we detect that the
//! version of rustc available to us is not nightly.
//!
//! RequiresClangWithTlsDesc:{bool} Defaults to false. Set to true to disable this test if we detect
//! that the version of clang available to us doesn't support TLSDESC.
//!
//! VersionScript:{filename} Specifies a version script file that will be passed to the linker.

use anyhow::Context;
use anyhow::anyhow;
use anyhow::bail;
use itertools::Itertools;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::read::elf::ProgramHeader;
use os_info::Type;
use rstest::fixture;
use rstest::rstest;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Display;
use std::fs::File;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::ErrorKind;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::Once;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;
use strum::EnumString;
use wait_timeout::ChildExt;

type Result<T = (), E = anyhow::Error> = core::result::Result<T, E>;
type ElfFile64<'data> = object::read::elf::ElfFile64<'data, LittleEndian>;

fn base_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn build_dir() -> PathBuf {
    base_dir().join("tests/build")
}

struct ProgramInputs {
    source_file: &'static str,
}

struct Program<'a> {
    link_output: LinkOutput,
    assertions: &'a Assertions,
    shared_objects: Vec<LinkerInput>,
}

#[derive(Clone, PartialEq, Eq)]
enum Linker {
    Wild,
    ThirdParty(ThirdPartyLinker),
}

#[derive(Clone, PartialEq, Eq)]
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
        obj_paths: &[PathBuf],
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
            &obj_paths
                .iter()
                .map(|p| LinkerInput::new(p.clone()))
                .collect_vec(),
            so_path,
            &linker_args,
            config,
            cross_arch,
        )?;

        if self.is_wild() || !is_newer(so_path, obj_paths.iter()) || !command.can_skip {
            command.run(config)?;
            write_cmd_file(so_path, &command.to_string())?;
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

struct LinkOutput {
    binary: PathBuf,
    command: LinkCommand,
    linker_used: Linker,
}

struct LinkCommand {
    command: Command,
    input_commands: Vec<LinkCommand>,
    linker: Linker,
    can_skip: bool,
    invocation_mode: LinkerInvocationMode,
    opt_save_dir: Option<PathBuf>,
    output_path: PathBuf,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Architecture {
    X86_64,
    AArch64,
}

const ALL_ARCHITECTURES: &[Architecture] = &[Architecture::X86_64, Architecture::AArch64];

impl Architecture {
    fn name(&self) -> &'static str {
        match self {
            Architecture::X86_64 => "x86_64",
            Architecture::AArch64 => "aarch64",
        }
    }

    fn emulation_name(&self) -> &'static str {
        match self {
            Architecture::X86_64 => "x86_64",
            Architecture::AArch64 => "aarch64elf",
        }
    }

    fn default_target_triple(&self) -> &'static str {
        match self {
            Architecture::X86_64 => "x86_64-unknown-linux-gnu",
            Architecture::AArch64 => "aarch64-unknown-linux-gnu",
        }
    }

    fn get_cross_sysroot_path(&self) -> String {
        if is_host_opensuse() {
            format!("/usr/{self}-suse-linux/sys-root")
        } else {
            format!("/usr/{self}-linux-gnu")
        }
    }
}

fn dynamic_linker_path(cross_arch: Option<Architecture>) -> &'static str {
    match cross_arch {
        None => host_dynamic_linker_cached(),
        Some(Architecture::X86_64) => "/lib64/ld-linux-x86-64.so.2",
        Some(Architecture::AArch64) => "/lib/ld-linux-aarch64.so.1",
    }
}

/// Returns the dynamic linker shared object that appears to be used on the host platform. This is
/// determined by trying various binaries that are likely to be dynamically linked.
fn host_dynamic_linker_cached() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    let value = VALUE.get_or_init(|| {
        ["/bin/true", "/bin/ls", "/usr/bin/ls", "/proc/self/exe"]
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

impl Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.name(), f)
    }
}

#[allow(unreachable_code)]
fn get_host_architecture() -> Architecture {
    #[cfg(target_arch = "x86_64")]
    {
        return Architecture::X86_64;
    }
    #[cfg(target_arch = "aarch64")]
    {
        return Architecture::AArch64;
    }
    todo!("Unsupported architecture")
}

fn is_host_opensuse() -> bool {
    os_info::get().os_type() == Type::openSUSE
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

fn host_supports_clang_with_tls_desc() -> bool {
    static CLANG_SUPPORTS_TLS_DESC: OnceLock<bool> = OnceLock::new();

    *CLANG_SUPPORTS_TLS_DESC.get_or_init(|| {
        let mut clang = Command::new("clang")
            .args(["-mtls-dialect=gnu2", "-x", "c", "-", "-o/dev/null"])
            .stdin(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to run clang");
        let mut stdin = clang.stdin.take().expect("Failed to open stdin");
        stdin
            .write_all("int main() { return 0; }".as_bytes())
            .expect("Write of a source file failed");
        drop(stdin);
        clang.wait().expect("Wait failed").success()
    })
}

#[derive(Clone, PartialEq, Eq)]
struct Config {
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
    expect_error: Option<String>,
    support_architectures: Vec<Architecture>,
    requires_glibc: bool,
    requires_clang_with_tlsdesc: bool,
    requires_nightly_rustc: bool,
    version_script: Option<PathBuf>,
    rustc_channel: Option<RustcChannel>,
}

#[derive(serde::Deserialize)]
struct TestConfig {
    // These configs are used by the config file specified in `$WILD_TEST_CONFIG`
    rustc_channel: RustcChannel,
    use_qemu: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
enum RustcChannel {
    Stable,
    Beta,
    Nightly,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectConfig {
    is_static: bool,
}

impl Default for DirectConfig {
    fn default() -> Self {
        Self { is_static: true }
    }
}

impl Config {
    fn should_skip(&self, arch: Architecture, test_config: &TestConfig) -> bool {
        !self.support_architectures.contains(&arch)
            || self.requires_glibc && !cfg!(target_env = "gnu")
            || (self.requires_clang_with_tlsdesc && !host_supports_clang_with_tls_desc())
            || (arch != get_host_architecture()
                && (self.compiler == "clang" || !self.cross_enabled))
            || (test_config.rustc_channel != RustcChannel::Nightly && self.requires_nightly_rustc)
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
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LinkerDriver {
    /// Invoke the linker via a compiler.
    Compiler(Compiler),

    /// Invoke the linker directly.
    Direct(DirectConfig),
}

/// A compiler via which the linker is invoked.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Compiler {
    Gcc(CLanguage),
    Clang(CLanguage),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FilenameArgumentPair {
    filename: String,
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

#[derive(Clone, PartialEq, Eq)]
struct Dep {
    files: Vec<FilenameArgumentPair>,
    input_type: InputType,
}

#[derive(Default, Clone, PartialEq, Eq)]
struct Assertions {
    expected_symtab_entries: Vec<ExpectedSymtabEntry>,
    expected_comments: Vec<String>,
    does_not_contain: Vec<String>,
    contains_strings: Vec<String>,
}

#[derive(Clone, PartialEq, Eq)]
struct ExpectedSymtabEntry {
    name: String,
    section_name: Option<String>,
}

impl ExpectedSymtabEntry {
    fn parse(s: &str) -> Result<Self> {
        let mut parts = s.split(' ').map(str::to_owned);
        let (Some(name), section, None) = (parts.next(), parts.next(), parts.next()) else {
            bail!("ExpectSym requires {{symbol name}} [{{symbol section}}]");
        };
        Ok(Self {
            name,
            section_name: section,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, EnumString)]
enum InputType {
    Object,
    Archive,
    ThinArchive,
    #[strum(serialize = "Shared")]
    SharedObject,
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

impl Default for Config {
    fn default() -> Self {
        Self {
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
            compiler: "gcc".to_owned(),
            should_diff: true,
            should_run: true,
            expect_error: None,
            cross_enabled: true,
            support_architectures: ALL_ARCHITECTURES.to_owned(),
            requires_glibc: false,
            requires_clang_with_tlsdesc: false,
            requires_nightly_rustc: false,
            version_script: None,
            rustc_channel: None,
        }
    }
}

fn parse_configs(src_filename: &Path) -> Result<Vec<Config>> {
    let source = std::fs::read_to_string(src_filename)
        .with_context(|| format!("Failed to read {}", src_filename.display()))?;
    let is_rust = src_filename.extension().is_some_and(|ext| ext == "rs");

    let mut config_by_name = HashMap::new();
    let mut config = Config::default();

    for line in source.lines() {
        if let Some(rest) = line.trim().strip_prefix("//#") {
            let (directive, arg) = rest.split_once(':').context("Missing arg")?;
            let arg = arg.trim();
            match directive {
                "Config" | "AbstractConfig" => {
                    if config != Config::default() {
                        config_by_name.insert(config.name.clone(), config);
                    }
                    let name = if let Some((name, inherit)) = arg.split_once(':') {
                        config = config_by_name
                            .get(inherit)
                            .ok_or_else(|| {
                                anyhow!(
                                    "Config `{name}` inherits from unknown config named `{inherit}`"
                                )
                            })?
                            .clone();

                        // Clear any fields that we want to not inherit.
                        config.variant_num = None;

                        name
                    } else {
                        config = Config::default();
                        arg
                    };
                    config.is_abstract = directive == "AbstractConfig";
                    if config_by_name.contains_key(name) {
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
                    config.linker_args = ArgumentSet::parse(arg)?
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
                "ExpectSym" => config
                    .assertions
                    .expected_symtab_entries
                    .push(ExpectedSymtabEntry::parse(arg.trim())?),
                "ExpectComment" => config
                    .assertions
                    .expected_comments
                    .push(arg.trim().to_owned()),
                "DoesNotContain" => config
                    .assertions
                    .does_not_contain
                    .push(arg.trim().to_owned()),
                "Contains" => config
                    .assertions
                    .contains_strings
                    .push(arg.trim().to_owned()),
                "Static" => config.linker_driver.direct_mut()?.is_static = arg.parse()?,
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
                "Cross" => {
                    config.cross_enabled = match arg.trim() {
                        "true" => true,
                        "false" => false,
                        other => bail!("Unsupported value for Cross '{other}'"),
                    }
                }
                "ExpectError" => {
                    config.expect_error = Some(arg.trim().to_owned());
                    // If there are errors, then there's nothing to run and nothing to diff.
                    config.should_run = false;
                    config.should_diff = false;
                }
                "SecEquiv" => config.section_equiv.push(
                    arg.trim()
                        .split_once('=')
                        .ok_or_else(|| anyhow!("DiffIgnore missing '='"))
                        .map(|(a, b)| (a.to_owned(), b.to_owned()))?,
                ),
                input_type @ ("Object" | "Archive" | "ThinArchive" | "Shared") => {
                    let input_type = InputType::from_str(input_type)?;
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

                    config.deps.push(Dep { files, input_type })
                }
                "Compiler" => config.compiler = arg.trim().to_owned(),
                "Arch" => {
                    config.support_architectures = arg
                        .trim()
                        .split(",")
                        .map(|arch| {
                            let arch = arch.trim().to_lowercase();
                            match arch.as_str() {
                                "x86_64" => Ok(Architecture::X86_64),
                                "aarch64" => Ok(Architecture::AArch64),
                                _ => Err(anyhow!(format!("Unsupported architecture: `{}`", arch))),
                            }
                        })
                        .collect::<Result<Vec<_>>>()?;
                }
                "RequiresGlibc" => config.requires_glibc = arg.trim().to_lowercase().parse()?,
                "RequiresClangWithTlsDesc" => {
                    config.requires_clang_with_tlsdesc = arg.to_lowercase().parse()?;
                }
                "RequiresNightlyRustc" => {
                    config.requires_nightly_rustc = arg.to_lowercase().parse()?;
                }
                "VersionScript" => {
                    config.version_script = Some(src_path(&arg.trim().to_lowercase()))
                }
                other => bail!("{}: Unknown directive '{other}'", src_filename.display()),
            }
        }
    }

    let mut configs = config_by_name
        .into_values()
        .filter(|c| !c.is_abstract)
        .collect_vec();
    configs.push(config);

    if configs.iter().all(|config| config.is_abstract) {
        bail!("Missing non-abstract Config");
    }

    Ok(configs)
}

impl ProgramInputs {
    fn new(source_file: &'static str) -> Result<Self> {
        std::fs::create_dir_all(build_dir())?;
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
        let shared_objects = inputs
            .into_iter()
            .filter(|input| input.path.extension().is_some_and(|ext| ext == "so"))
            .collect();
        Ok(Program {
            link_output,
            assertions: &config.assertions,
            shared_objects,
        })
    }

    fn name(&self) -> &str {
        self.source_file
    }
}

impl Program<'_> {
    fn run(&self, cross_arch: Option<Architecture>) -> Result {
        self.assertions
            .check(&self.link_output)
            .context("Output binary assertions failed")?;

        let mut command = if let Some(arch) = cross_arch {
            let mut c = Command::new(format!("qemu-{arch}"));
            c.arg("-L");
            c.arg(arch.get_cross_sysroot_path());
            c.arg(&self.link_output.binary);
            c
        } else {
            Command::new(&self.link_output.binary)
        };

        let spawn_result = spawn_with_retry(&mut command, 10);

        let mut child = spawn_result.with_context(|| {
            format!(
                "Command `{}` failed",
                command.get_program().to_string_lossy()
            )
        })?;

        let status = match child.wait_timeout(std::time::Duration::from_millis(500))? {
            Some(s) => s,
            None => {
                child.kill()?;
                bail!("Binary ran for too long");
            }
        };

        let exit_code = status
            .code()
            .ok_or_else(|| anyhow!("Binary exited with signal"))?;

        if exit_code != 42 {
            bail!("Binary exited with unexpected exit code {exit_code}");
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
        self.name.fmt(f)
    }
}

struct LinkerInput {
    path: PathBuf,
    command: Option<LinkCommand>,
}

impl LinkerInput {
    fn new(path: PathBuf) -> LinkerInput {
        LinkerInput {
            path,
            command: None,
        }
    }

    fn with_command(path: PathBuf, command: LinkCommand) -> LinkerInput {
        LinkerInput {
            path,
            command: Some(command),
        }
    }
}

/// Creates a linker input from a source file. This will be either an object file or an archive.
fn build_linker_input(
    dep: &Dep,
    config: &Config,
    linker: &Linker,
    cross_arch: Option<Architecture>,
) -> Result<LinkerInput> {
    if let [single_file] = dep.files.as_slice() {
        if single_file.filename.ends_with(".a") {
            return Ok(LinkerInput::new(src_path(&single_file.filename)));
        }
    }

    let obj_paths = dep
        .files
        .iter()
        .map(|file| build_obj(file, config, dep.input_type, cross_arch))
        .collect::<Result<Vec<PathBuf>>>()?;

    // When building archives or shared objects, we use the name of the first object to determine
    // the name.
    let first_obj_path = obj_paths
        .first()
        .context("At least one object is required")?;

    match dep.input_type {
        InputType::Archive | InputType::ThinArchive => {
            let thin = matches!(dep.input_type, InputType::ThinArchive);
            let archive_path = first_obj_path.with_extension("a");
            if !is_newer(&archive_path, obj_paths.iter()) {
                make_archive(&archive_path, &obj_paths, thin)?;
            }
            Ok(LinkerInput::new(archive_path))
        }
        InputType::Object => {
            if obj_paths.len() > 1 {
                bail!(
                    "Multiple source files on a single line is only supported with Shared/Archive"
                );
            }

            Ok(LinkerInput::new(first_obj_path.clone()))
        }
        InputType::SharedObject => {
            let so_path = first_obj_path.with_extension(format!("{linker}.so"));
            let out = linker.link_shared(&obj_paths, &so_path, config, cross_arch)?;
            let assertions = Assertions::default();
            assertions
                .check_path(&out.path, linker)
                .with_context(|| format!("Assertions failed for `{}`", out.path.display()))?;
            Ok(out)
        }
    }
}

#[derive(Debug)]
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
) -> Result<&'static str> {
    match (cross_arch, compiler, c_language) {
        (None, "gcc", CLanguage::C) => Ok("gcc"),
        (None, "gcc", CLanguage::Cpp) => Ok("g++"),
        (None, "clang", CLanguage::C) => Ok("clang"),
        (None, "clang", CLanguage::Cpp) => Ok("clang++"),
        (Some(Architecture::AArch64), "gcc" | "g++", CLanguage::C) => Ok(if is_host_opensuse() {
            "aarch64-suse-linux-gcc"
        } else {
            "aarch64-linux-gnu-gcc"
        }),
        (Some(Architecture::AArch64), "gcc" | "g++", CLanguage::Cpp) => Ok(if is_host_opensuse() {
            "aarch64-suse-linux-g++"
        } else {
            "aarch64-linux-gnu-g++"
        }),
        _ => bail!("Unsupported compiler and or architecture `{compiler}` / {cross_arch:?}"),
    }
}

/// Builds some C source and returns the path to the object file.
fn build_obj(
    file: &FilenameArgumentPair,
    config: &Config,
    input_type: InputType,
    cross_arch: Option<Architecture>,
) -> Result<PathBuf> {
    let src_path = src_path(&file.filename);
    let extension = src_path
        .extension()
        .context("Missing extension")?
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
        "rs" => ("rustc", CompilerKind::Rust),
        "o" => return Ok(src_path),
        _ => bail!("Don't know how to compile {extension} files"),
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
            command.arg("-c");
        }
        CompilerKind::Rust => {
            let wild = wild_path().to_str().context("Need UTF-8 path")?.to_owned();
            let rustc_channel = match config.rustc_channel {
                Some(RustcChannel::Stable) => Some("+stable"),
                Some(RustcChannel::Beta) => Some("+beta"),
                Some(RustcChannel::Nightly) => Some("+nightly"),
                None => None,
            };

            command
                .env("WILD_SAVE_SKIP_LINKING", "1")
                .args(rustc_channel)
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
                    command.arg(format!("--target={}", arch.default_target_triple()));
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

    let arch_str = cross_name(cross_arch);

    let output_path = build_dir().join(Path::new(&file.filename).with_extension(format!(
        "{}-{arch_str}-{command_hash:x}{suffix}",
        config.name
    )));

    match compiler_kind {
        CompilerKind::C => {
            command.arg("-o").arg(&output_path);
        }
        CompilerKind::Rust => {
            command.env("WILD_SAVE_DIR", &output_path);
        }
    }

    // If multiple threads try to create a file at the same time, only one should do so and the
    // others should wait.
    let lock_path = output_path.with_file_name(format!(
        ".{}.lock",
        output_path
            .file_name()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default()
    ));
    let mut output_file_lock = fd_lock::RwLock::new(File::create(&lock_path)?);
    let _write_lock = output_file_lock.write().unwrap();

    if is_newer(&output_path, std::iter::once(&src_path)) {
        return Ok(output_path);
    }

    let status = command.status().with_context(|| {
        format!(
            "Failed to run `{}`",
            command.get_program().to_string_lossy()
        )
    })?;

    if output_path.is_dir() {
        post_process_run_script(&output_path)?;
    }

    if !status.success() {
        bail!("Compilation failed: {}", command_as_str(&command));
    }

    Ok(output_path)
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

fn cross_name(cross_arch: Option<Architecture>) -> &'static str {
    cross_arch.map(|a| a.name()).unwrap_or("host")
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
fn post_process_run_script(output_path: &Path) -> Result {
    let run_with_filename = output_path.join("run-with");
    if let Ok(contents) = std::fs::read_to_string(&run_with_filename) {
        let mut out = String::new();
        for line in contents.lines() {
            if !line.contains("-soname") {
                out.push_str(line);
                out.push('\n');
            }
        }
        std::fs::write(&run_with_filename, out)
            .with_context(|| format!("Failed to write `{}`", run_with_filename.display()))?;
    }
    Ok(())
}

fn write_cmd_file(output_path: &Path, command_str: &str) -> Result {
    let path = cmd_path(output_path);
    std::fs::write(&path, command_str)
        .with_context(|| format!("Failed to write `{}`", path.display()))
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

fn cmd_path(output_path: &Path) -> PathBuf {
    let mut p = output_path.as_os_str().to_owned();
    p.push(".cmd");
    PathBuf::from(p)
}

/// Returns whether the command file for `output_path` exists and contains `command`.
fn cmd_file_is_current(output_path: &Path, command: &str) -> bool {
    std::fs::read_to_string(cmd_path(output_path))
        .is_ok_and(|previous_command| previous_command == command)
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
        let output_path = self.output_path(basename, config, cross_arch);
        let mut linker_args = config.linker_args.clone();
        if self.is_wild() {
            linker_args
                .args
                .extend(config.wild_extra_linker_args.args.iter().cloned());
        }
        let mut command =
            LinkCommand::new(self, inputs, &output_path, &linker_args, config, cross_arch)?;
        if !command.can_skip {
            command.run(config)?;
            write_cmd_file(&output_path, &command.to_string())?;
        }
        Ok(LinkOutput {
            binary: output_path,
            command,
            linker_used: self.clone(),
        })
    }

    fn output_path(
        &self,
        basename: &str,
        config: &Config,
        cross_arch: Option<Architecture>,
    ) -> PathBuf {
        let cross = cross_name(cross_arch);
        build_dir().join(format!("{basename}-{}-{cross}.{self}", config.name))
    }
}

fn make_archive(archive_path: &Path, paths: &[PathBuf], thin: bool) -> Result {
    let _ = std::fs::remove_file(archive_path);
    let mut cmd = Command::new("ar");
    cmd.arg("cr");

    if thin {
        cmd.arg("--thin");

        // For thin archives, we want to test that we properly handle relative paths, so we pass
        // paths that are relative to the directory in which we're creating the archive.
        let archive_dir = archive_path.parent().unwrap();
        cmd.current_dir(archive_dir);
        cmd.arg(archive_path.strip_prefix(archive_dir).unwrap());

        for path in paths {
            cmd.arg(path.strip_prefix(archive_dir).unwrap_or(path));
        }
    } else {
        cmd.arg(archive_path).args(paths);
    }
    let status = cmd.status()?;
    if !status.success() {
        bail!("Failed to create archive");
    }
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
            command.args(extra_inputs.iter().map(|i| &i.path));
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

                    let save_dir = output_path.with_extension("save");
                    command.env("WILD_SAVE_DIR", &save_dir);
                    opt_save_dir = Some(save_dir);

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
                                    // GCC unfortunately doesn't provide any way to use a custom linker.
                                    // Their flag for switching linkers only accepts a hard-coded list
                                    // of alternatives and the developers don't seem to want any
                                    // equivalent to clang's --ld-path. The closest we can get is to put
                                    // a file called "ld" in a directory, then pass "-B" and that
                                    // directory.
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
                        // Provide a workaround for ld.lld: error: unknown argument '--fix-cortex-a53-835769'
                        // Bug link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105941
                        command.arg("-mno-fix-cortex-a53-835769");
                    }

                    if let Some(version_script) = &config.version_script {
                        command.arg(format!("-Wl,--version-script={}", version_script.display()));
                    }

                    command.args(&linker_args.args);
                }
                LinkerDriver::Direct(direct_config) => {
                    command = Command::new(linker_path);

                    if let Some(arch) = cross_arch {
                        command.arg("-m").arg(arch.emulation_name());
                    }

                    if direct_config.is_static {
                        command.arg("-static");
                    } else {
                        command
                            .arg("-dynamic-linker")
                            .arg(dynamic_linker_path(cross_arch));
                    }

                    if let Some(version_script) = &config.version_script {
                        command.arg(format!("--version-script={}", version_script.display()));
                    }

                    command.arg("--gc-sections").args(&linker_args.args);
                }
            }
            if !linker_args.args.iter().any(|arg| arg == "-o") {
                command.arg("-o").arg(output_path);
            }
            for input in inputs {
                command.arg(&input.path);
            }
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
            input_commands: inputs
                .iter()
                .filter_map(|input| input.command.as_ref().cloned())
                .collect(),
            linker: linker.clone(),
            can_skip: false,
            invocation_mode,
            opt_save_dir,
            output_path: output_path.to_owned(),
        };
        // We allow skipping linking if all the object files and the version script
        // are unchanged and are older than our output file, but not if we're linking
        // with our linker, since we're always changing that. We also require that the
        // command we're going to run hasn't changed.
        let can_skip = !matches!(linker, Linker::Wild)
            && is_newer(output_path, inputs.iter().map(|i| i.path.as_path()))
            && is_newer(output_path, config.version_script.iter())
            && cmd_file_is_current(output_path, &link_command.to_string());
        link_command.can_skip = can_skip;

        Ok(link_command)
    }

    fn run(&mut self, config: &Config) -> Result {
        if let Some(expected_error) = config.expect_error.as_ref() {
            let output = self
                .command
                .output()
                .with_context(|| format!("Failed to run command: {:?}", self.command))?;

            if output.status.success() {
                bail!("Linker returned exit status of 0, when an error was expected");
            }

            if !output
                .stderr
                .windows(expected_error.len())
                .any(|s| s == expected_error.as_bytes())
            {
                eprintln!(
                    "-- stdout --\n{}\n-- stderr --\n{}\n-- end --",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
                bail!("Linker expected to report error `{expected_error}` on stderr, but didn't");
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
            let parsed_args = libwild::Args::parse(args.iter())?;

            // This call is expected to error for all but the first call.
            let _ = libwild::setup_tracing(&parsed_args);

            linker
                .run(&parsed_args)
                .with_context(|| format!("libwild reported error. Rerun command(s):\n {self}"))?;

            return Ok(());
        }

        let status = self
            .command
            .status()
            .with_context(|| format!("Failed to run command: {:?}", self.command))?;

        if !status.success() {
            bail!("Linker failed. Relink with:\n{self}");
        }
        Ok(())
    }
}

fn get_script(inputs: &[LinkerInput]) -> Option<(PathBuf, &[LinkerInput])> {
    let path = &inputs[0].path;
    if path.is_dir() {
        return Some((path.join("run-with"), &inputs[1..]));
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

        self.verify_symbol_assertions(&obj)?;
        self.verify_comment_section(&obj, linker_used)?;
        self.verify_strings(&bytes)?;
        Ok(())
    }

    fn verify_symbol_assertions(&self, obj: &ElfFile64<'_>) -> Result {
        let mut missing = self
            .expected_symtab_entries
            .iter()
            .map(|exp| (exp.name.as_str(), exp))
            .collect::<HashMap<_, _>>();
        for sym in obj.symbols() {
            if let Ok(name) = sym.name() {
                if let Some(exp) = missing.remove(name) {
                    if let object::SymbolSection::Section(index) = sym.section() {
                        let section = obj.section_by_index(index)?;
                        let section_name = section.name()?;
                        if let Some(exp_name) = exp.section_name.as_ref() {
                            if section_name != exp_name {
                                bail!(
                                    "Expected symbol `{name}` to be in section `{exp_name}`, \
                                    but it was in `{section_name}`"
                                );
                            }
                        }
                    }
                }
            }
        }
        let missing: Vec<&str> = missing.into_keys().collect();
        if !missing.is_empty() {
            bail!("Missing expected symbol(s): {}", missing.join(", "));
        };
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
        if let Some(save_dir) = self.opt_save_dir.as_ref() {
            if save_dir.exists() && self.linker == Linker::Wild {
                write!(
                    f,
                    "WILD_WRITE_LAYOUT=1 WILD_WRITE_TRACE=1 OUT={} {}/run-with cargo run \
                     --bin wild --",
                    self.output_path.display(),
                    save_dir.display()
                )?;
                return Ok(());
            }
        }

        for sub in &self.input_commands {
            writeln!(f, "{sub}")?;
        }

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
            InputType::SharedObject => write!(f, "shared"),
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
            can_skip: self.can_skip,
            invocation_mode: self.invocation_mode,
            opt_save_dir: self.opt_save_dir.clone(),
            output_path: self.output_path.clone(),
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

fn diff_executables(instructions: &Config, programs: &[Program]) -> Result {
    let filenames = programs
        .iter()
        .map(|p| p.link_output.binary.clone())
        .collect_vec();
    diff_files(instructions, filenames, programs.last().unwrap())
}

/// Diff the supplied files. The last file should be the one that we produced.
fn diff_files(instructions: &Config, files: Vec<PathBuf>, display: &dyn Display) -> Result {
    if !instructions.should_diff {
        return Ok(());
    }

    let mut config = linker_diff::Config::default();
    config.colour = linker_diff::Colour::Always;
    config.wild_defaults = true;
    config
        .ignore
        .extend(instructions.diff_ignore.iter().cloned());
    config
        .equiv
        .extend(instructions.section_equiv.iter().cloned());
    config.references = files.clone();
    config.file = config
        .references
        .pop()
        .context("Tried to diff zero files")?;
    let report = linker_diff::Report::from_config(config.clone()).with_context(|| {
        format!(
            "Report::from_config failed for the following files: {}",
            files.iter().map(|f| f.to_string_lossy()).join(" ")
        )
    })?;
    if report.has_problems() {
        eprintln!("{report}");
        bail!(
            "Validation failed.\n{display}\n To revalidate:\ncargo run --bin linker-diff -- \
             {}",
            config.to_arg_string()
        );
    }
    Ok(())
}

fn setup_wild_ld_symlink() -> Result {
    let wild = wild_path();
    let wild_ld_path = wild.with_file_name("ld");
    if !wild_ld_path.exists() {
        std::os::unix::fs::symlink(wild, &wild_ld_path).with_context(|| {
            format!(
                "Failed to symlink `{}` to `{}`",
                wild_ld_path.display(),
                wild.display()
            )
        })?;
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
    [Architecture::AArch64]
        .into_iter()
        .filter_map(|arch| {
            let path = PathBuf::from(if is_host_opensuse() {
                format!("/usr/{arch}-suse-linux/bin/{name}")
            } else {
                format!("/usr/{arch}-linux-gnu/bin/{name}")
            });
            if path.exists() {
                Some((arch, path))
            } else {
                None
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

fn available_linkers() -> Result<Vec<Linker>> {
    let mut linkers = vec![
        Linker::ThirdParty(ThirdPartyLinker {
            name: "ld",
            gcc_name: "bfd",
            path: find_bin(&["ld"])?,
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
    arch: Architecture,
    linkers: &[Linker],
) -> Result {
    let mut config = config.clone();

    let cross_arch = (arch != get_host_architecture()).then_some(arch);

    // GCC cross compilers, when passed `-fuse-ld=lld` won't look for `ld.lld` on the path.
    // Instead it'll look for `aarch64-linux-gnu-ld.lld` on the path and look for `ld.lld`
    // only in the sysroot (e.g. `aarch64-linux-gnu`). We could hack around this by creating
    // a temporary directory containing a symlink with the appropriate name, but for now, we
    // just skip running with lld when cross compiling.
    if cross_arch.is_some() {
        config.enabled_linkers.remove("lld");
    }

    let programs = linkers
        .iter()
        .filter(|linker| config.is_linker_enabled(linker))
        .map(|linker| {
            let start = Instant::now();
            let result = program_inputs
                .build(linker, &config, cross_arch)
                .with_context(|| {
                    format!(
                        "Failed to build program `{program_inputs}` \
                        with linker `{linker}` config `{}`",
                        config.name
                    )
                });
            let is_cache_hit = result
                .as_ref()
                .is_ok_and(|p| p.link_output.command.can_skip);
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
    if config.expect_error.is_some() {
        return Ok(());
    }

    let start = Instant::now();
    diff_shared_objects(&config, &programs)?;
    diff_executables(&config, &programs)?;

    if should_print_timing() {
        println!(
            "{program_inputs}-{config} diff took {} ms",
            start.elapsed().as_millis()
        );
    }

    if config.should_run {
        for program in programs {
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
        "internal-syms.c",
        "tls.c",
        "tlsdesc.c",
        "tls-variant.c",
        "no_start.c",
        "old_init.c",
        "custom_section.c",
        "stack_alignment.s",
        "got_ref_to_local.c",
        "local_symbol_refs.s",
        "archive_activation.c",
        "common_section.c",
        "string_merging.c",
        "comments.c",
        "eh_frame.c",
        "trivial_asm.s",
        "non-alloc.s",
        "gnu-unique.c",
        "symbol-versions.c",
        "copy-relocations.c",
        "force-undefined.c",
        "libc-ifunc.c",
        "libc-integration.c",
        "rust-integration.rs",
        "rust-integration-dynamic.rs",
        "cpp-integration.cc",
        "rust-tls.rs",
        "input_does_not_exist.c",
        "ifunc2.c",
        "tls-local-exec.c",
        "undefined_symbols.c",
        "whole_archive.c",
        "dynamic-bss-only.c",
        "shared.c",
        "duplicate_strong_symbols.c"
    )]
    program_name: &'static str,
    #[allow(unused_variables)] setup_symlink: (),
) -> Result {
    let program_inputs = ProgramInputs::new(program_name)?;

    let linkers = available_linkers()?;

    let filename = &program_inputs.source_file;
    let configs = parse_configs(&src_path(filename))
        .with_context(|| format!("Failed to parse test parameters from `{filename}`"))?;

    let host_arch = get_host_architecture();

    let test_config = read_test_config()?;

    for &arch in ALL_ARCHITECTURES {
        if arch != host_arch && !test_config.use_qemu {
            continue;
        }

        let config_it = configs
            .iter()
            .filter(|config| !config.should_skip(arch, &test_config));

        for config in config_it {
            let mut config = config.clone();
            config.rustc_channel = Some(test_config.rustc_channel);
            run_with_config(&program_inputs, &config, arch, &linkers)?
        }
    }

    Ok(())
}

fn read_test_config() -> Result<TestConfig> {
    // We only currently support cross compilation from x86_64 to aarch64, so we don't need to track
    // which targets are enabled, since there's only one.
    let mut use_qemu = std::env::var("WILD_TEST_CROSS").is_ok_and(|v| v == "aarch64");
    let mut rustc_channel = RustcChannel::Nightly;

    let config_default_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-config.toml");
    let config_path = std::env::var("WILD_TEST_CONFIG")
        .map(|config_path| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join(config_path)
        })
        .unwrap_or_else(|_| config_default_path.clone());

    if config_path.exists() {
        let config_content = std::fs::read_to_string(&config_path).with_context(|| {
            format!(
                "Failed to read WILD_TEST_CONFIG file at `{}`",
                config_path.display()
            )
        })?;
        let data: TestConfig = match toml::from_str(&config_content) {
            Ok(d) => d,
            Err(_) => {
                bail!("Unable to load config from {:?}", config_path);
            }
        };

        rustc_channel = data.rustc_channel;
        use_qemu |= data.use_qemu;
    } else if config_path != config_default_path {
        bail!(
            "WILD_TEST_CONFIG file not found at `{}`",
            config_path.display()
        );
    }

    Ok(TestConfig {
        rustc_channel,
        use_qemu,
    })
}
