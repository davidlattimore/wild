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
use std::fmt::Display;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
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
    name: &'static str,
    source_files: Vec<String>,
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
}

impl Linker {
    fn path(&self) -> &Path {
        match self {
            Linker::Wild => wild_path(),
            Linker::ThirdParty(info) => Path::new(info.path),
        }
    }

    fn link_shared(&self, obj_path: &Path, so_path: &Path) -> Result<LinkerInput> {
        let mut command = LinkCommand::new(
            *self,
            &[LinkerInput::new(obj_path.to_owned())],
            so_path,
            &ArgumentSet::default_for_linking(),
        );
        if self.is_wild() || !is_newer(so_path, obj_path) {
            command.run()?;
        }
        Ok(LinkerInput::with_command(so_path.to_owned(), command))
    }

    fn is_wild(&self) -> bool {
        *self == Linker::Wild
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

struct TestParameters {
    input_type: Vec<InputType>,
    variant_nums: Vec<u32>,
    assertions: Assertions,
    linker_args: Vec<ArgumentSet>,
    compiler_args: Vec<ArgumentSet>,
    diff_ignore: Vec<String>,
}

#[derive(Default)]
struct Assertions {
    expected_symtab_entries: Vec<ExpectedSymtabEntry>,
    expected_comments: Vec<String>,
    does_not_contain: Vec<String>,
    contains_strings: Vec<String>,
}

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

#[derive(Clone, Debug)]
struct CompilationVariant {
    variant_num: u32,
    compiler_args: ArgumentSet,
}

#[derive(Clone, Debug)]
struct Variant {
    input_type: InputType,
    compilation: CompilationVariant,
    linker_args: ArgumentSet,
}

#[derive(Copy, Clone, Debug)]
enum InputType {
    Object,
    Archive,
    SharedObject,
}

impl InputType {
    fn parse(arg: &str) -> Result<Self> {
        Ok(match arg {
            "Object" => Self::Object,
            "Archive" => Self::Archive,
            "Shared" => Self::SharedObject,
            other => bail!("Unknown LinkKind `{other}`"),
        })
    }
}

#[derive(Clone, Debug)]
struct ArgumentSet {
    name: String,
    args: Vec<String>,
}

impl ArgumentSet {
    fn parse(s: &str) -> Result<ArgumentSet> {
        let (name, rest) = s
            .split_once(':')
            .with_context(|| format!("Missing ':' in LinkArg `{s}`"))?;
        Ok(ArgumentSet {
            name: name.to_owned(),
            args: rest
                .split(' ')
                .map(str::to_owned)
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }

    fn default_for_linking() -> Self {
        Self {
            name: "default".to_owned(),
            args: Vec::new(),
        }
    }

    fn default_for_compiling() -> Self {
        Self {
            name: "default".to_owned(),
            args: Vec::new(),
        }
    }
}

impl TestParameters {
    fn from_source(src_filename: &Path) -> Result<TestParameters> {
        let source = std::fs::read_to_string(src_filename)
            .with_context(|| format!("Failed to read {}", src_filename.display()))?;

        let mut input_type = Vec::new();
        let mut tls_models = Vec::new();
        let mut variants = Vec::new();
        let mut linker_args = Vec::new();
        let mut compiler_args = Vec::new();
        let mut expected_symtab_entries = Vec::new();
        let mut expected_comments = Vec::new();
        let mut does_not_contain = Vec::new();
        let mut contains_strings = Vec::new();
        let mut diff_ignore = Vec::new();
        for line in source.lines() {
            if let Some(rest) = line.trim().strip_prefix("//#") {
                let (directive, arg) = rest.split_once(':').context("Missing arg")?;
                let arg = arg.trim();
                match directive {
                    "InputType" => {
                        for p in arg.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                            input_type.push(InputType::parse(p)?);
                        }
                    }
                    "Variant" => variants.push(
                        arg.parse()
                            .with_context(|| format!("Failed to parse '{arg}'"))?,
                    ),
                    "LinkArgs" => linker_args.push(ArgumentSet::parse(arg)?),
                    "CompArgs" => compiler_args.push(ArgumentSet::parse(arg)?),
                    "ExpectSym" => {
                        expected_symtab_entries.push(ExpectedSymtabEntry::parse(arg.trim())?)
                    }
                    "ExpectComment" => expected_comments.push(arg.trim().to_owned()),
                    "DoesNotContain" => does_not_contain.push(arg.trim().to_owned()),
                    "Contains" => contains_strings.push(arg.trim().to_owned()),
                    "DiffIgnore" => diff_ignore.push(arg.trim().to_owned()),
                    other => bail!("{}: Unknown directive '{other}'", src_filename.display()),
                }
            }
        }
        if linker_args.is_empty() {
            linker_args.push(ArgumentSet::default_for_linking());
        }
        if compiler_args.is_empty() {
            compiler_args.push(ArgumentSet::default_for_compiling());
        }
        if variants.is_empty() {
            variants.push(0);
        }
        if input_type.is_empty() {
            input_type.push(InputType::Object);
        }
        if tls_models.is_empty() {
            tls_models.push(String::new());
        }
        Ok(TestParameters {
            input_type,
            variant_nums: variants,
            assertions: Assertions {
                expected_symtab_entries,
                expected_comments,
                does_not_contain,
                contains_strings,
            },
            linker_args,
            compiler_args,
            diff_ignore,
        })
    }
}

#[derive(Default)]
struct FileOverrides {
    compiler_args: Option<Vec<String>>,
}

impl FileOverrides {
    fn from_source(src_filename: &Path, placement: FilePlacement) -> Result<Self> {
        if matches!(placement, FilePlacement::Primary) {
            return Ok(Default::default());
        }
        let source = std::fs::read_to_string(src_filename)
            .with_context(|| format!("Failed to read {}", src_filename.display()))?;

        let mut compiler_args = None;
        for line in source.lines() {
            if let Some(rest) = line.trim().strip_prefix("//#") {
                let (directive, arg) = rest.split_once(':').context("Missing arg")?;
                let arg = arg.trim();
                match directive {
                    "OverrideCompArgs" => {
                        compiler_args = Some(
                            arg.split(' ')
                                .filter(|a| !a.is_empty())
                                .map(str::to_owned)
                                .collect(),
                        )
                    }
                    other => bail!("{}: Unknown directive '{other}'", src_filename.display()),
                }
            }
        }
        Ok(Self { compiler_args })
    }
}

#[derive(Clone, Copy)]
enum FilePlacement {
    Primary,
    Secondary,
}

impl ProgramInputs {
    fn new(name: &'static str, sources: &[&str]) -> Result<Self> {
        std::fs::create_dir_all(build_dir())?;
        Ok(Self {
            name,
            source_files: sources.iter().map(|s| str::to_owned(s)).collect(),
        })
    }

    fn build<'a>(
        &self,
        linker: Linker,
        variant: &Variant,
        assertions: &'a Assertions,
    ) -> Result<Program<'a>> {
        let inputs = self
            .source_files
            .iter()
            .enumerate()
            .map(|(i, source)| {
                let mut variant_for_file = variant.clone();
                let placement = if i == 0 {
                    // For the first input file, we always compile as an object, never an archive.
                    variant_for_file.input_type = InputType::Object;
                    FilePlacement::Primary
                } else {
                    FilePlacement::Secondary
                };
                build_linker_input(source, &variant_for_file, placement, linker)
            })
            .collect::<Result<Vec<LinkerInput>>>()?;
        let link_output = linker.link(self.name, &inputs, variant)?;
        let shared_objects = inputs
            .into_iter()
            .filter(|input| input.path.extension().is_some_and(|ext| ext == "so"))
            .collect();
        Ok(Program {
            link_output,
            assertions,
            shared_objects,
        })
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
    filename: &str,
    variant: &Variant,
    placement: FilePlacement,
    linker: Linker,
) -> Result<LinkerInput> {
    let src_path = src_path(filename);
    if filename.ends_with(".a") {
        return Ok(LinkerInput::new(src_path));
    }
    let obj_path = build_obj(filename, variant, placement)?;

    match variant.input_type {
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
            let out = linker.link_shared(&obj_path, &so_path)?;
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
fn build_obj(filename: &str, variant: &Variant, placement: FilePlacement) -> Result<PathBuf> {
    let variant_num = variant.compilation.variant_num;
    let src_path = src_path(filename);
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
        .join(Path::new(filename).with_extension(format!("{}{suffix}", variant.compilation)));
    // Skip rebuilding if our output already exists and is newer than our source.
    if is_newer(&output_path, &src_path) {
        return Ok(output_path);
    }
    let mut command = Command::new(compiler);
    match compiler_kind {
        CompilerKind::C => {
            command
                .arg("-c")
                .arg(format!("-DVARIANT={variant_num}"))
                .arg("-o")
                .arg(&output_path);
        }
        CompilerKind::Rust => {
            let wild = wild_path().to_str().context("Need UTF-8 path")?.to_owned();
            command
                .env("WILD_SAVE_DIR", &output_path)
                .env("WILD_SAVE_SKIP_LINKING", "1")
                .arg("+nightly")
                .args(["-C", "linker=clang"])
                .args(["-C", &format!("link-arg=--ld-path={wild}")]);
        }
    }
    command.arg(&src_path);
    let override_parameters = FileOverrides::from_source(&src_path, placement)?;
    if let Some(args) = override_parameters.compiler_args.as_ref() {
        command.args(args);
    } else {
        command.args(&variant.compilation.compiler_args.args);
    }
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
    fn link(self, basename: &str, inputs: &[LinkerInput], variant: &Variant) -> Result<LinkOutput> {
        let output_path = self.output_path(basename, variant);
        let mut command = LinkCommand::new(self, inputs, &output_path, &variant.linker_args);
        if !command.can_skip {
            command.run()?;
        }
        Ok(LinkOutput {
            binary: output_path,
            command,
            linker_used: self,
        })
    }

    fn output_path(&self, basename: &str, variant: &Variant) -> PathBuf {
        build_dir().join(format!("{basename}-{variant}.{}", self.config_name()))
    }

    fn config_name(&self) -> String {
        self.to_string()
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
                command.arg("--gc-sections").arg("-static");
                command.args(&linker_args.args);
            }
            command.env(wild_lib::args::VALIDATE_ENV, "1");
            command.env(wild_lib::args::WRITE_LAYOUT_ENV, "1");
            command.arg("-o").arg(output_path);
            for input in inputs {
                command.arg(&input.path);
            }
        }
        LinkCommand {
            command,
            input_commands: inputs
                .iter()
                .filter_map(|input| input.command.as_ref().cloned())
                .collect(),
            linker,
            can_skip,
            invocation_mode,
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
        Display::fmt(&self.name, f)
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

impl Display for Variant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.compilation, f)?;
        Display::fmt(&'-', f)?;
        Display::fmt(&self.input_type, f)?;
        Display::fmt(&'-', f)?;
        Display::fmt(&self.linker_args.name, f)?;
        Ok(())
    }
}

impl Display for CompilationVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.variant_num, f)?;
        Display::fmt(&'-', f)?;
        Display::fmt(&self.compiler_args.name, f)?;
        Ok(())
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
        }
    }
}

#[test]
fn integration_test() -> Result {
    // TODO: We should probably just discover the source files, then work out which ones are main
    // programs and get their dependencies via comments. That said, it's somewhat handy having an
    // ordering here, since we can put more basic tests earlier such that when we fail, we report
    // the most basic test that failed.
    let programs = [
        ProgramInputs::new("trivial", &["trivial.c", "exit.c"])?,
        ProgramInputs::new("link_args", &["link_args.c", "exit.c"])?,
        ProgramInputs::new(
            "global_vars",
            &["global_definitions.c", "global_references.c", "exit.c"],
        )?,
        ProgramInputs::new("data", &["data.c", "exit.c"])?,
        ProgramInputs::new("weak-vars", &["weak-vars.c", "weak-vars1.c", "exit.c"])?,
        ProgramInputs::new(
            "weak-vars-archive",
            &["weak-vars-archive.c", "weak-vars1.c", "exit.c"],
        )?,
        ProgramInputs::new("weak-fns", &["weak-fns.c", "weak-fns1.c", "exit.c"])?,
        ProgramInputs::new(
            "weak-fns-archive",
            &["weak-fns-archive.c", "weak-fns1.c", "exit.c"],
        )?,
        ProgramInputs::new("init_test", &["init_test.c", "init.c", "exit.c"])?,
        ProgramInputs::new("ifunc", &["ifunc.c", "ifunc1.c", "ifunc_init.c", "exit.c"])?,
        ProgramInputs::new("internal-syms", &["internal-syms.c", "exit.c"])?,
        ProgramInputs::new("tls", &["tls.c", "tls1.c", "init_tls.c", "exit.c"])?,
        ProgramInputs::new(
            "old_init",
            &["old_init.c", "old_init0.s", "old_init1.s", "exit.c"],
        )?,
        ProgramInputs::new(
            "custom_section",
            &["custom_section.c", "custom_section0.c", "exit.c"],
        )?,
        ProgramInputs::new("stack_alignment", &["stack_alignment.s", "exit.c"])?,
        ProgramInputs::new(
            "got_ref_to_local",
            &["got_ref_to_local.c", "got_ref_to_local-1.s", "exit.c"],
        )?,
        ProgramInputs::new("local_symbol_refs", &["local_symbol_refs.s", "exit.c"])?,
        ProgramInputs::new(
            "archive_activation",
            &[
                "archive_activation.c",
                "archive_activation0.c",
                "archive_activation1.c",
                "exit.c",
                "empty.a",
            ],
        )?,
        ProgramInputs::new(
            "common_section",
            &[
                "common_section.c",
                "common_section0.c",
                "common_section1.c",
                "exit.c",
            ],
        )?,
        ProgramInputs::new(
            "string_merging",
            &[
                "string_merging.c",
                "string_merging1.s",
                "string_merging2.s",
                "exit.c",
            ],
        )?,
        ProgramInputs::new(
            "comments",
            &["comments.c", "comments0.c", "comments1.c", "exit.c"],
        )?,
        ProgramInputs::new("eh_frame", &["eh_frame.c", "eh_frame_end.c", "exit.c"])?,
        ProgramInputs::new(
            "pie",
            &[
                "pie.c",
                "pie0.s",
                "pie1.c",
                "init.c",
                "init_tls.c",
                "exit.c",
            ],
        )?,
        ProgramInputs::new("libc-integration", &["libc-integration.c"])?,
        ProgramInputs::new("rust-integration", &["rust-integration.rs"])?,
        ProgramInputs::new(
            "rust-integration-dynamic",
            &["rust-integration-dynamic.rs", "rdyn1.rs"],
        )?,
    ];

    let linkers = [
        Linker::ThirdParty(ThirdPartyLinker {
            name: "ld",
            gcc_name: "bfd",
            path: "/usr/bin/ld",
        }),
        Linker::Wild,
    ];

    setup_wild_ld_symlink()?;

    for program_inputs in &programs {
        let filename = program_inputs.source_files.first().unwrap();
        let instructions = TestParameters::from_source(&src_path(filename))
            .with_context(|| format!("Failed to parse test parameters from `{filename}`"))?;
        for &link_kind in &instructions.input_type {
            for link_args in &instructions.linker_args {
                for compiler_args in &instructions.compiler_args {
                    for &variant_num in &instructions.variant_nums {
                        let variant = Variant {
                            input_type: link_kind,
                            linker_args: link_args.clone(),
                            compilation: CompilationVariant {
                                variant_num,
                                compiler_args: compiler_args.clone(),
                            },
                        };
                        let programs = linkers.iter().map(|linker| {
                            program_inputs.build(*linker, &variant, &instructions.assertions).with_context(|| {
                                format!("Failed to build program `{program_inputs}` with linker `{linker}` variant #{variant}")
                            })
                        }).collect::<Result<Vec<_>>>()?;

                        diff_shared_objects(&instructions, &programs)?;
                        diff_executables(&instructions, &programs)?;

                        for program in programs {
                            program
                                .run()
                                .with_context(|| format!("Failed to run program. {program}"))?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn diff_shared_objects(instructions: &TestParameters, programs: &[Program]) -> Result {
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

fn diff_executables(instructions: &TestParameters, programs: &[Program]) -> Result {
    let filenames = programs
        .iter()
        .map(|p| p.link_output.binary.clone())
        .collect::<Vec<_>>();
    diff_files(instructions, filenames, programs.last().unwrap())
}

fn diff_files(
    instructions: &TestParameters,
    filenames: Vec<PathBuf>,
    display: &dyn Display,
) -> Result {
    let mut config = linker_diff::Config::default();
    config.ignore.clone_from(&instructions.diff_ignore);
    config.filenames = filenames;
    let report = linker_diff::Report::from_config(config.clone())?;
    if report.has_problems() {
        eprintln!("{report}");
        bail!(
            "Validation failed.\n{display}\n To revalidate:\ncargo run --bin linker-diff -- \
             --ignore '{}' {}",
            config.ignore.join(","),
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
