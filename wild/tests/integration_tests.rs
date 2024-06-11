//! Tests that build and run various test programs then link them and run them. Each test is linked
//! with both the system linker (ld) and with wild.
//!
//! The test files can contain directives that affect compilation and linking as well as assertions
//! that are tested by examining the resulting binaries. Directives have the format '//#Directive:
//! Args'.
//!
//! ExpectComment: Checks that the the next comment in the .comment section is equal to the supplied
//! argument. If no ExpectComment directives are given then .comment isn't checked. The argument may
//! end with '*' which matches anything. The last ExpectComment directive may start with '?' to
//! indicate that the comment if present should match the rest of the argument, but that it's OK for
//! it to be absent.
//!
//! TODO: Document the rest of the directives.

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use object::LittleEndian;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Display;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Linker {
    Wild,
    ThirdParty(ThirdPartyLinker),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ThirdPartyLinker {
    name: &'static str,
    gcc_name: &'static str,
    path: &'static str,
    enabled_by_default: bool,
}

impl Linker {
    fn path(&self) -> &Path {
        match self {
            Linker::Wild => wild_path(),
            Linker::ThirdParty(info) => Path::new(info.path),
        }
    }

    fn link_shared(&self, obj_path: &Path, so_path: &Path, config: &Config) -> Result<LinkerInput> {
        let mut linker_args = config.linker_args.clone();
        linker_args.args.push("-shared".to_owned());
        let mut command = LinkCommand::new(
            *self,
            &[LinkerInput::new(obj_path.to_owned())],
            so_path,
            &linker_args,
        );
        if self.is_wild() || !is_newer(so_path, obj_path) {
            command.run()?;
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

#[derive(Clone, Copy, Debug)]
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

#[derive(Clone, PartialEq, Eq)]
struct Config {
    name: String,
    variant_num: Option<u32>,
    assertions: Assertions,
    linker_args: ArgumentSet,
    compiler_args: ArgumentSet,
    diff_ignore: Vec<String>,
    skip_linkers: HashSet<String>,
    enabled_linkers: HashSet<String>,
    section_equiv: Vec<(String, String)>,
    is_abstract: bool,
    deps: Vec<Dep>,
}
impl Config {
    fn is_linker_enabled(&self, linker: Linker) -> bool {
        if self.skip_linkers.contains(linker.name()) {
            return false;
        }
        if self.enabled_linkers.contains(linker.name()) {
            return true;
        }
        linker.enabled_by_default()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Dep {
    filename: String,
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
    section_name: String,
}

impl ExpectedSymtabEntry {
    fn parse(s: &str) -> Result<Self> {
        let mut parts = s.split(' ').map(str::to_owned);
        let (Some(name), Some(section), None) = (parts.next(), parts.next(), parts.next()) else {
            bail!("ExpectSym requires {{symbol name}}, {{symbol section}}");
        };
        Ok(Self {
            name,
            section_name: section,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum InputType {
    Object,
    Archive,
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
        Self { args: Vec::new() }
    }

    fn default_for_compiling() -> Self {
        Self { args: Vec::new() }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            name: "default".to_owned(),
            variant_num: None,
            assertions: Default::default(),
            linker_args: ArgumentSet::default_for_linking(),
            compiler_args: ArgumentSet::default_for_compiling(),
            diff_ignore: Default::default(),
            skip_linkers: Default::default(),
            enabled_linkers: Default::default(),
            section_equiv: Default::default(),
            is_abstract: false,
            deps: Default::default(),
        }
    }
}

fn parse_configs(src_filename: &Path) -> Result<Vec<Config>> {
    let source = std::fs::read_to_string(src_filename)
        .with_context(|| format!("Failed to read {}", src_filename.display()))?;

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
                "LinkArgs" => config.linker_args = ArgumentSet::parse(arg)?,
                "CompArgs" => config.compiler_args = ArgumentSet::parse(arg)?,
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
                "DiffIgnore" => config.diff_ignore.push(arg.trim().to_owned()),
                "SkipLinker" => {
                    config.skip_linkers.insert(arg.trim().to_owned());
                }
                "EnableLinker" => {
                    config.enabled_linkers.insert(arg.trim().to_owned());
                }
                "SecEquiv" => config.section_equiv.push(
                    arg.trim()
                        .split_once('=')
                        .ok_or_else(|| anyhow!("DiffIgnore missing '='"))
                        .map(|(a, b)| (a.to_owned(), b.to_owned()))?,
                ),
                "Object" => config.deps.push(Dep {
                    filename: arg.to_owned(),
                    input_type: InputType::Object,
                }),
                "Archive" => config.deps.push(Dep {
                    filename: arg.to_owned(),
                    input_type: InputType::Archive,
                }),
                "Shared" => config.deps.push(Dep {
                    filename: arg.to_owned(),
                    input_type: InputType::SharedObject,
                }),
                other => bail!("{}: Unknown directive '{other}'", src_filename.display()),
            }
        }
    }
    let mut configs = config_by_name
        .into_values()
        .filter(|c| !c.is_abstract)
        .collect::<Vec<_>>();
    configs.push(config);
    Ok(configs)
}

impl ProgramInputs {
    fn new(source_file: &'static str) -> Result<Self> {
        std::fs::create_dir_all(build_dir())?;
        Ok(Self { source_file })
    }

    fn build<'a>(&self, linker: Linker, config: &'a Config) -> Result<Program<'a>> {
        let primary = build_linker_input(
            &Dep {
                filename: self.source_file.to_owned(),
                input_type: InputType::Object,
            },
            config,
            linker,
        );
        let inputs = std::iter::once(primary)
            .chain(
                config
                    .deps
                    .iter()
                    .map(|dep| build_linker_input(dep, config, linker)),
            )
            .collect::<Result<Vec<_>>>()?;

        let link_output = linker.link(self.name(), &inputs, config)?;
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

impl<'a> Program<'a> {
    fn run(&self) -> Result {
        self.assertions
            .check(&self.link_output)
            .context("Output binary assertions failed")?;
        let mut child = Command::new(&self.link_output.binary).spawn()?;
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

impl<'a> Display for Program<'a> {
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
fn build_linker_input(dep: &Dep, config: &Config, linker: Linker) -> Result<LinkerInput> {
    let src_path = src_path(&dep.filename);
    if dep.filename.ends_with(".a") {
        return Ok(LinkerInput::new(src_path));
    }
    let obj_path = build_obj(dep, config, dep.input_type)?;

    match dep.input_type {
        InputType::Archive => {
            let archive_path = obj_path.with_extension("a");
            if !is_newer(&archive_path, &obj_path) {
                make_archive(&archive_path, &obj_path)?;
            }
            Ok(LinkerInput::new(archive_path))
        }
        InputType::Object => Ok(LinkerInput::new(obj_path)),
        InputType::SharedObject => {
            let so_path = obj_path.with_extension(format!("{linker}.so"));
            let out = linker.link_shared(&obj_path, &so_path, config)?;
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

/// Builds some C source and returns the path to the object file.
fn build_obj(dep: &Dep, config: &Config, input_type: InputType) -> Result<PathBuf> {
    let src_path = src_path(&dep.filename);
    let extension = src_path
        .extension()
        .context("Missing extension")?
        .to_str()
        .context("Extension isn't valid UTF-8")?;
    let (compiler, compiler_kind) = match extension {
        "cpp" => ("g++", CompilerKind::C),
        "c" => ("gcc", CompilerKind::C),
        "s" => ("gcc", CompilerKind::C),
        "rs" => ("rustc", CompilerKind::Rust),
        _ => bail!("Don't know how to compile {extension} files"),
    };
    // For Rust programs, we don't have an easy way to separate compilation from linking, so we
    // output Rust compilation to a directory containing copies of the object files and a script to
    // perform the link step.
    let suffix = match compiler_kind {
        CompilerKind::C => ".o",
        CompilerKind::Rust => "",
    };
    let output_path = build_dir()
        .join(Path::new(&dep.filename).with_extension(format!("{}{suffix}", config.name)));
    // Skip rebuilding if our output already exists and is newer than our source.
    if is_newer(&output_path, &src_path) {
        return Ok(output_path);
    }
    let mut command = Command::new(compiler);
    match compiler_kind {
        CompilerKind::C => {
            if let Some(v) = config.variant_num {
                command.arg(format!("-DVARIANT={v}"));
            }
            command.arg("-c").arg("-o").arg(&output_path);
        }
        CompilerKind::Rust => {
            let wild = wild_path().to_str().context("Need UTF-8 path")?.to_owned();
            command
                .env("WILD_SAVE_DIR", &output_path)
                .env("WILD_SAVE_SKIP_LINKING", "1")
                .arg("+nightly")
                .args(["-C", "linker=clang"])
                .args(["-C", &format!("link-arg=--ld-path={wild}")]);
            if input_type == InputType::SharedObject {
                command.arg("--crate-type").arg("cdylib");
            }
        }
    }
    command.arg(&src_path);
    command.args(&config.compiler_args.args);
    let status = command.status()?;
    if !status.success() {
        bail!("Compilation failed");
    }
    Ok(output_path)
}

fn src_path(filename: &str) -> PathBuf {
    let filename = Path::new(filename);
    base_dir().join("tests").join("sources").join(filename)
}

/// Returns whether both `output_path` and `src_path` exist and `output_path` has a modification
/// timestamp >= that of `src_path`.
fn is_newer(output_path: &Path, src_path: &Path) -> bool {
    let Ok(out) = std::fs::metadata(output_path) else {
        return false;
    };
    let Ok(src) = std::fs::metadata(src_path) else {
        return false;
    };
    let (Ok(mod_out), Ok(mod_src)) = (out.modified(), src.modified()) else {
        return false;
    };
    mod_out >= mod_src
}

impl Linker {
    /// Links the supplied object files with this configuration and returns the path to the
    /// resulting binary.
    fn link(self, basename: &str, inputs: &[LinkerInput], config: &Config) -> Result<LinkOutput> {
        let output_path = self.output_path(basename, config);
        let mut command = LinkCommand::new(self, inputs, &output_path, &config.linker_args);
        if !command.can_skip {
            command.run()?;
        }
        Ok(LinkOutput {
            binary: output_path,
            command,
            linker_used: self,
        })
    }

    fn output_path(&self, basename: &str, config: &Config) -> PathBuf {
        build_dir().join(format!("{basename}-{}.{self}", config.name))
    }
}

fn make_archive(archive_path: &Path, path: &Path) -> Result {
    let _ = std::fs::remove_file(archive_path);
    let mut cmd = Command::new("ar");
    cmd.arg("cr").arg(archive_path).arg(path);
    let status = cmd.status()?;
    if !status.success() {
        bail!("Failed to create archive");
    }
    Ok(())
}

impl LinkCommand {
    fn new(
        linker: Linker,
        inputs: &[LinkerInput],
        output_path: &Path,
        linker_args: &ArgumentSet,
    ) -> LinkCommand {
        // We allow skipping linking if all the object files are the unchanged and are older than
        // our output file, but not if we're linking with our linker, since we're always changing
        // that.
        let can_skip = linker != Linker::Wild
            && inputs
                .iter()
                .all(|input| is_newer(output_path, &input.path));
        let mut command;
        let mut invocation_mode = LinkerInvocationMode::Direct;
        let mut opt_save_dir = None;
        if let Some((script, extra_inputs)) = get_script(inputs) {
            command = Command::new(script);
            command.env("OUT", output_path);
            command.arg(linker.path());
            command.args(extra_inputs.iter().map(|i| &i.path));
            invocation_mode = LinkerInvocationMode::Script;
        } else {
            let linker_path = linker.path();
            if let Some(cc) = linker_args
                .args
                .first()
                .and_then(|a| a.strip_prefix("--cc="))
            {
                invocation_mode = LinkerInvocationMode::Cc;
                command = Command::new(cc);

                // It's convenient when debugging to be able to run the linker via a script rather
                // than by calling the C compiler, so we get wild to write out a script. In
                // particular, this makes it easier to inspect the linker arguments, since they're
                // in the script.
                let save_dir = output_path.with_extension("save");
                command.env("WILD_SAVE_DIR", &save_dir);
                opt_save_dir = Some(save_dir);

                match cc {
                    "clang" => {
                        command.arg(format!(
                            "--ld-path={}",
                            linker_path
                                .to_str()
                                .expect("Linker path must be valid UTF-8")
                        ));
                    }
                    "gcc" => {
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
                                command.arg(format!("-fuse-ld={}", third_party_linker.gcc_name));
                            }
                        }
                    }
                    _ => panic!("Unsupported cc={cc}"),
                }
                command.args(&linker_args.args[1..]);
            } else {
                command = Command::new(linker_path);
                command
                    .arg("--gc-sections")
                    .arg("-static")
                    .args(&linker_args.args);
            }
            command.arg("-o").arg(output_path);
            for input in inputs {
                command.arg(&input.path);
            }
        }
        command.env(wild_lib::args::VALIDATE_ENV, "1");
        command.env(wild_lib::args::WRITE_LAYOUT_ENV, "1");
        command.env(wild_lib::args::WRITE_TRACE_ENV, "1");
        LinkCommand {
            command,
            input_commands: inputs
                .iter()
                .filter_map(|input| input.command.as_ref().cloned())
                .collect(),
            linker,
            can_skip,
            invocation_mode,
            opt_save_dir,
            output_path: output_path.to_owned(),
        }
    }

    fn run(&mut self) -> Result {
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
        self.check_path(&link_output.binary, link_output.linker_used)
    }

    fn check_path(&self, path: &PathBuf, linker_used: Linker) -> Result {
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
                        let exp_name = &exp.section_name;
                        if section_name != exp_name {
                            bail!(
                                "Expected symbol `{name}` to be in section `{exp_name}`, but it was in \
                                 `{section_name}`"
                            );
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

    fn verify_comment_section(&self, obj: &ElfFile64, linker_used: Linker) -> Result {
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
        let mut actual_comments_iter = actual_comments.iter();
        let mut expected_comments = self.expected_comments.iter();
        loop {
            match (expected_comments.next(), actual_comments_iter.next()) {
                (None, None) => break,
                (None, Some(a)) => bail!("Unexpected .comment `{a}`"),
                (Some(e), None) => {
                    if !e.starts_with('?') {
                        bail!("Missing expected .comment `{e}`")
                    }
                }
                (Some(e), Some(a)) => {
                    let e = e.strip_prefix('?').unwrap_or(e.as_str());
                    if let Some(prefix) = e.strip_suffix('*') {
                        if !a.starts_with(prefix) {
                            bail!("Expected .comment starting with `{prefix}`, got `{a}`");
                        }
                    } else if e != a {
                        bail!("Expected .comment `{e}`, got `{a}`");
                    }
                }
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
        let mut args: Vec<_> = self
            .command
            .get_args()
            .map(|a| a.to_string_lossy())
            .collect();
        match (self.invocation_mode, self.linker) {
            (LinkerInvocationMode::Cc, Linker::Wild) => {
                write!(
                    f,
                    "cargo build; {} {}",
                    self.command.get_program().to_string_lossy(),
                    args.join(" ")
                )
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
                    self.command.get_program().to_string_lossy(),
                    args.join(" ")
                )
            }
            _ => {
                write!(
                    f,
                    "{} {}",
                    self.command.get_program().to_string_lossy(),
                    args.join(" ")
                )
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
            linker: self.linker,
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
        let filenames = so_group.iter().map(|i| i.path.clone()).collect::<Vec<_>>();
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
        .collect::<Vec<_>>();
    diff_files(instructions, filenames, programs.last().unwrap())
}

fn diff_files(instructions: &Config, filenames: Vec<PathBuf>, display: &dyn Display) -> Result {
    let mut config = linker_diff::Config::default();
    config.ignore.clone_from(&instructions.diff_ignore);
    config.ignore.extend(
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
            "section.note.*",
            "section.gnu.version*",
            // We set this to 8. GNU ld sometimes does too, but sometimes to 0.
            "section.got.entsize",
            "section.plt.got.entsize",
            // We do support this. TODO: Should definitely look into why we're seeing this missing
            // in our output.
            "section.rela.plt",
            // We currently write 10 byte PLT entries in some cases where GNU ld writes 8 byte ones.
            "section.plt.got.alignment",
            // GNU ld sometimes makes this writable sometimes not. Presumably this depends on
            // whether there are relocations or some flags.
            "section.eh_frame.flags",
        ]
        .into_iter()
        .map(|s| s.to_owned()),
    );
    config.equiv.clone_from(&instructions.section_equiv);
    config
        .equiv
        .push((".got".to_owned(), ".got.plt".to_owned()));
    // We don't currently define .plt.got and .plt.sec, we just put everything into .plt.
    config
        .equiv
        .push((".plt".to_owned(), ".plt.got".to_owned()));
    config
        .equiv
        .push((".plt".to_owned(), ".plt.sec".to_owned()));
    config.filenames = filenames;
    let report = linker_diff::Report::from_config(config.clone())?;
    if report.has_problems() {
        eprintln!("{report}");
        bail!(
            "Validation failed.\n{display}\n To revalidate:\ncargo run --bin linker-diff -- \
             --ignore '{}' --equiv '{}' {}",
            config.ignore.join(","),
            config
                .equiv
                .iter()
                .map(|(a, b)| format!("{a}={b}"))
                .collect::<Vec<_>>()
                .join(","),
            config
                .filenames
                .iter()
                .map(|f| f.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" ")
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

#[test]
fn integration_test() -> Result {
    // We could potentially just discover the source files, but having a hand-written ordering is
    // nice, since it means we can run the more basic tests first. If we do ever implement automatic
    // discovery, then we need a way to mitigate the possibility of creating a source file and
    // having it not get run because of a typo. e.g. we should make sure that all files in the
    // source directory get used either as test roots or test dependencies.
    let programs = [
        ProgramInputs::new("trivial.c")?,
        ProgramInputs::new("link_args.c")?,
        ProgramInputs::new("global_definitions.c")?,
        ProgramInputs::new("data.c")?,
        ProgramInputs::new("weak-vars.c")?,
        ProgramInputs::new("weak-vars-archive.c")?,
        ProgramInputs::new("weak-fns.c")?,
        ProgramInputs::new("weak-fns-archive.c")?,
        ProgramInputs::new("init_test.c")?,
        ProgramInputs::new("ifunc.c")?,
        ProgramInputs::new("internal-syms.c")?,
        ProgramInputs::new("tls.c")?,
        ProgramInputs::new("old_init.c")?,
        ProgramInputs::new("custom_section.c")?,
        ProgramInputs::new("stack_alignment.s")?,
        ProgramInputs::new("got_ref_to_local.c")?,
        ProgramInputs::new("local_symbol_refs.s")?,
        ProgramInputs::new("archive_activation.c")?,
        ProgramInputs::new("common_section.c")?,
        ProgramInputs::new("string_merging.c")?,
        ProgramInputs::new("comments.c")?,
        ProgramInputs::new("eh_frame.c")?,
        ProgramInputs::new("pie.c")?,
        ProgramInputs::new("trivial_asm.s")?,
        ProgramInputs::new("libc-integration.c")?,
        ProgramInputs::new("rust-integration.rs")?,
        ProgramInputs::new("rust-integration-dynamic.rs")?,
    ];

    let linkers = [
        Linker::ThirdParty(ThirdPartyLinker {
            name: "ld",
            gcc_name: "bfd",
            path: "/usr/bin/ld",
            enabled_by_default: true,
        }),
        Linker::ThirdParty(ThirdPartyLinker {
            name: "lld",
            gcc_name: "lld",
            path: "/usr/bin/ld.lld-15",
            enabled_by_default: false,
        }),
        Linker::ThirdParty(ThirdPartyLinker {
            name: "mold",
            gcc_name: "mold",
            path: "/usr/local/bin/mold",
            enabled_by_default: false,
        }),
        Linker::Wild,
    ];

    setup_wild_ld_symlink()?;

    let print_timing = std::env::var("WILD_TEST_PRINT_TIMING").is_ok();

    for program_inputs in &programs {
        let filename = &program_inputs.source_file;
        let configs = parse_configs(&src_path(filename))
            .with_context(|| format!("Failed to parse test parameters from `{filename}`"))?;
        for config in configs {
            let programs = linkers
                .iter()
                .filter(|linker| config.is_linker_enabled(**linker))
                .map(|linker| {
                    let start = Instant::now();
                    let result = program_inputs.build(*linker, &config).with_context(|| {
                        format!(
                            "Failed to build program `{program_inputs}` \
                                    with linker `{linker}` config {}",
                            config.name
                        )
                    });
                    let is_cache_hit = result
                        .as_ref()
                        .is_ok_and(|p| p.link_output.command.can_skip);
                    if !is_cache_hit && print_timing {
                        println!(
                            "{program_inputs}-{config} with {linker} took {} ms",
                            start.elapsed().as_millis()
                        );
                    }
                    result
                })
                .collect::<Result<Vec<_>>>()?;

            let start = Instant::now();
            diff_shared_objects(&config, &programs)?;
            diff_executables(&config, &programs)?;
            if print_timing {
                println!(
                    "{program_inputs}-{config} diff took {} ms",
                    start.elapsed().as_millis()
                );
            }

            for program in programs {
                program
                    .run()
                    .with_context(|| format!("Failed to run program. {program}"))?;
            }
        }
    }

    Ok(())
}
