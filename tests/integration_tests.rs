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
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use std::fmt::Display;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use wait_timeout::ChildExt;

type Result<T = (), E = anyhow::Error> = core::result::Result<T, E>;

fn base_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn build_dir() -> PathBuf {
    base_dir().join("tests/build")
}

struct Program {
    name: &'static str,
    source_files: Vec<String>,
}

#[derive(Clone)]
struct Config {
    compilation: CompilationConfig,
    linker: LinkerConfig,
}

#[derive(Clone, Copy)]
struct CompilationConfig {
    pie: bool,
    opt_level: u8,
}

#[derive(Clone, Copy)]
struct LinkerConfig {
    kind: LinkerKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LinkerKind {
    Wild,
    ThirdParty(&'static str),
}

impl LinkerKind {
    fn path(&self) -> PathBuf {
        match self {
            LinkerKind::Wild => base_dir().join("target/debug/wild"),
            LinkerKind::ThirdParty(cmd) => PathBuf::from(cmd),
        }
    }
}

struct LinkOutput {
    binary: PathBuf,
    command: LinkCommand,
}

struct LinkCommand {
    command: Command,
    linker_kind: LinkerKind,
    can_skip: bool,
}

struct TestParameters {
    link_kind: Vec<LinkKind>,
    variant_nums: Vec<u32>,
    tls_models: Vec<String>,
    assertions: Assertions,
    linker_args: Vec<ArgumentSet>,
    compiler_args: Vec<ArgumentSet>,
}

struct Assertions {
    expected_symtab_entries: Vec<String>,
    expected_comments: Vec<String>,
}

#[derive(Clone, Debug)]
struct CompilationVariant {
    variant_num: u32,
    tls_model: String,
    compiler_args: ArgumentSet,
}

#[derive(Clone, Debug)]
struct Variant {
    link_kind: LinkKind,
    compilation: CompilationVariant,
    linker_args: ArgumentSet,
}

#[derive(Copy, Clone, Debug)]
enum LinkKind {
    Object,
    Archive,
}

impl LinkKind {
    fn parse(arg: &str) -> Result<Self> {
        Ok(match arg {
            "Object" => Self::Object,
            "Archive" => Self::Archive,
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
}

impl Default for ArgumentSet {
    fn default() -> Self {
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

        let mut link_kind = Vec::new();
        let mut tls_models = Vec::new();
        let mut variants = Vec::new();
        let mut linker_args = Vec::new();
        let mut compiler_args = Vec::new();
        let mut expected_symtab_entries = Vec::new();
        let mut expected_comments = Vec::new();
        for line in source.lines() {
            if let Some(rest) = line.trim().strip_prefix("//#") {
                let (directive, arg) = rest.split_once(':').context("Missing arg")?;
                let arg = arg.trim();
                match directive {
                    "LinkKind" => {
                        for p in arg.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                            link_kind.push(LinkKind::parse(p)?);
                        }
                    }
                    "TlsModel" => {
                        for p in arg.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                            tls_models.push(p.to_owned());
                        }
                    }
                    "Variant" => variants.push(
                        arg.parse()
                            .with_context(|| format!("Failed to parse '{arg}'"))?,
                    ),
                    "LinkArgs" => linker_args.push(ArgumentSet::parse(arg)?),
                    "CompArgs" => compiler_args.push(ArgumentSet::parse(arg)?),
                    "ExpectSym" => expected_symtab_entries.push(arg.trim().to_owned()),
                    "ExpectComment" => expected_comments.push(arg.trim().to_owned()),
                    other => bail!("{}: Unknown directive '{other}'", src_filename.display()),
                }
            }
        }
        if linker_args.is_empty() {
            linker_args.push(ArgumentSet::default());
        }
        if compiler_args.is_empty() {
            compiler_args.push(ArgumentSet::default());
        }
        if variants.is_empty() {
            variants.push(0);
        }
        if link_kind.is_empty() {
            link_kind.push(LinkKind::Object);
        }
        if tls_models.is_empty() {
            tls_models.push(String::new());
        }
        Ok(TestParameters {
            tls_models,
            link_kind,
            variant_nums: variants,
            assertions: Assertions {
                expected_symtab_entries,
                expected_comments,
            },
            linker_args,
            compiler_args,
        })
    }
}

impl Program {
    fn new(name: &'static str, sources: &[&str]) -> Result<Self> {
        std::fs::create_dir_all(build_dir())?;
        Ok(Self {
            name,
            source_files: sources.iter().map(|s| str::to_owned(s)).collect(),
        })
    }

    fn run(&self, config: &Config, variant: &Variant, assertions: &Assertions) -> Result {
        let object_paths = self
            .source_files
            .iter()
            .enumerate()
            .map(|(i, source)| {
                // For the first input file, we always compile as an object, never an archive.
                let mut variant_for_file = variant.clone();
                if i == 0 {
                    variant_for_file.link_kind = LinkKind::Object
                }
                config
                    .compilation
                    .build_linker_input(source, &variant_for_file)
            })
            .collect::<Result<Vec<PathBuf>>>()?;
        let link_output = config.link(self.name, &object_paths, variant)?;
        assertions.check(&link_output).with_context(|| {
            format!(
                "Output binary assertions failed for `{}`. Relink with:\n{}",
                link_output.binary.display(),
                link_output.command
            )
        })?;
        let mut child = Command::new(&link_output.binary).spawn()?;
        let status = match child.wait_timeout(std::time::Duration::from_millis(500))? {
            Some(s) => s,
            None => {
                child.kill()?;
                bail!(
                    "Binary `{}` ran for too long. Relink with:\n{}",
                    link_output.binary.display(),
                    link_output.command,
                );
            }
        };
        let exit_code = status.code().ok_or_else(|| {
            anyhow!(
                "Binary `{}` exited with signal. Relink with:\n{}",
                link_output.binary.display(),
                link_output.command,
            )
        })?;
        if exit_code != 42 {
            bail!(
                "Binary `{}` exited with unexpected exit code {exit_code}. Relink with:\n{}",
                link_output.binary.display(),
                link_output.command
            );
        }

        Ok(())
    }
}

impl CompilationConfig {
    /// Creates a linker input from a source file. This will be either an object file or an archive.
    fn build_linker_input(&self, filename: &str, variant: &Variant) -> Result<PathBuf> {
        if filename.ends_with(".a") {
            return Ok(src_path(filename));
        }
        let obj_path = self.build_obj(filename, variant)?;

        match variant.link_kind {
            LinkKind::Archive => {
                let archive_path = obj_path.with_extension("a");
                if !is_newer(&archive_path, &obj_path) {
                    make_archive(&archive_path, &obj_path)?;
                }
                Ok(archive_path)
            }
            LinkKind::Object => Ok(obj_path),
        }
    }

    /// Builds some C source and returns the path to the object file.
    fn build_obj(&self, filename: &str, variant: &Variant) -> Result<PathBuf> {
        let variant_num = variant.compilation.variant_num;
        let tls_model = &variant.compilation.tls_model;
        let src_path = src_path(filename);
        let extension = src_path.extension().context("Missing extension")?;
        let output_path = build_dir().join(
            Path::new(filename).with_extension(format!("{}-{}.o", self, variant.compilation)),
        );
        // Skip rebuilding if our output already exists and is newer than our source.
        if is_newer(&output_path, &src_path) {
            return Ok(output_path);
        }
        let compiler = if extension == "cpp" { "g++" } else { "gcc" };
        let mut command = Command::new(compiler);
        command.arg("-fpic");
        if self.pie {
            command.arg("-pie");
        } else {
            command.arg("-no-pie");
        }
        if !tls_model.is_empty() {
            command.arg(format!("-ftls-model={tls_model}"));
        }
        command.arg("-fcommon");
        command.arg("-fno-stack-protector");
        command.arg("-fno-omit-frame-pointer");
        command.arg("-ffunction-sections");
        command.arg("-fdata-sections");
        command.arg(format!("-O{}", self.opt_level));
        command.arg("-c").arg(src_path).arg("-o").arg(&output_path);
        command.arg(format!("-DVARIANT={variant_num}"));
        command.args(&variant.compilation.compiler_args.args);
        let status = command.status()?;
        if !status.success() {
            bail!("Compilation failed");
        }
        Ok(output_path)
    }
}

fn src_path(filename: &str) -> PathBuf {
    let filename = Path::new(filename);
    base_dir().join("tests").join("c").join(filename)
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

impl Config {
    /// Links the supplied object files with this configuration and returns the path to the
    /// resulting binary.
    fn link(
        &self,
        basename: &str,
        object_paths: &[PathBuf],
        variant: &Variant,
    ) -> Result<LinkOutput> {
        let mut command = LinkCommand::new(self, basename, object_paths, variant);
        if !command.can_skip {
            let status = command.command.status()?;
            if !status.success() {
                bail!("Linker failed. Relink with:\n{command}");
            }
        }
        Ok(LinkOutput {
            binary: self.output_path(basename, variant),
            command,
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
        config: &Config,
        basename: &str,
        object_paths: &[PathBuf],
        variant: &Variant,
    ) -> LinkCommand {
        let mut command = Command::new(config.linker.kind.path());
        let output_path = config.output_path(basename, variant);
        // We allow skipping linking if all the object files are the unchanged and are older than
        // our output file, but not if we're linking with our linker, since we're always changing
        // that.
        let can_skip = config.linker.kind != LinkerKind::Wild
            && object_paths.iter().all(|obj| is_newer(&output_path, obj));
        command
            .arg("--gc-sections")
            .arg("-static")
            .args(&variant.linker_args.args)
            .arg("-o")
            .arg(&output_path);
        for obj in object_paths {
            command.arg(obj);
        }
        LinkCommand {
            command,
            linker_kind: config.linker.kind,
            can_skip,
        }
    }
}

impl Assertions {
    fn check(&self, link_output: &LinkOutput) -> Result {
        let bytes = std::fs::read(&link_output.binary)?;
        let obj = object::File::parse(bytes.as_slice())?;

        self.verify_symbol_assertions(&obj)?;

        self.verify_comment_section(obj)?;

        Ok(())
    }

    fn verify_symbol_assertions(&self, obj: &object::File<'_>) -> Result<(), anyhow::Error> {
        let symbols = obj
            .symbols()
            .filter(|sym| sym.is_definition())
            .map(|sym| sym.name().context("Non-UTF-8 name"))
            .collect::<Result<std::collections::HashSet<&str>>>()?;
        let missing = self
            .expected_symtab_entries
            .iter()
            .map(|s| s.as_str())
            .filter(|expected_symbol| !symbols.contains(expected_symbol))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            bail!("Missing expected symbol(s): {}", missing.join(", "));
        };
        Ok(())
    }

    fn verify_comment_section(&self, obj: object::File<'_>) -> Result {
        if self.expected_comments.is_empty() {
            return Ok(());
        }
        let comment_section = obj
            .section_by_name(".comment")
            .context("Missing .comment section")?;
        let data = comment_section.data()?;
        let mut actual_comments = data
            .split(|b| *b == 0)
            .map(|c| String::from_utf8_lossy(c))
            .filter(|c| !c.is_empty());
        let mut expected_comments = self.expected_comments.iter();
        loop {
            match (expected_comments.next(), actual_comments.next()) {
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
}

impl Display for LinkCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let args: Vec<_> = self
            .command
            .get_args()
            .map(|a| a.to_string_lossy())
            .collect();
        match self.linker_kind {
            LinkerKind::Wild => {
                write!(f, "cargo run -- {}", args.join(" "))
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

impl Display for CompilationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.pie {
            write!(f, "pie")?;
        } else {
            write!(f, "no-pie")?;
        }
        write!(f, "-opt{}", self.opt_level)?;
        Ok(())
    }
}

impl Display for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.name, f)
    }
}

impl Display for LinkerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.kind, f)
    }
}

impl Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.compilation, f)?;
        Display::fmt(&'-', f)?;
        Display::fmt(&self.linker, f)?;
        Ok(())
    }
}

impl Display for LinkerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkerKind::Wild => Display::fmt(&"wild", f),
            LinkerKind::ThirdParty(cmd) => Display::fmt(cmd, f),
        }
    }
}

impl Display for LinkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkKind::Object => write!(f, "object"),
            LinkKind::Archive => write!(f, "archive"),
        }
    }
}

impl Display for Variant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.compilation, f)?;
        Display::fmt(&'-', f)?;
        Display::fmt(&self.link_kind, f)?;
        Display::fmt(&'-', f)?;
        Display::fmt(&self.linker_args.name, f)?;
        Ok(())
    }
}

impl Display for CompilationVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.tls_model, f)?;
        Display::fmt(&'-', f)?;
        Display::fmt(&self.variant_num, f)?;
        Display::fmt(&'-', f)?;
        Display::fmt(&self.compiler_args.name, f)?;
        Ok(())
    }
}

#[test]
fn integration_test() -> Result {
    // TODO: We should probably just discover the source files, then work out which ones are main
    // programs and get their dependencies via comments. That said, it's somewhat handy having an
    // ordering here, since we can put more basic tests earlier such that when we fail, we report
    // the most basic test that failed.
    let programs = [
        Program::new("trivial", &["trivial.c", "exit.c"])?,
        Program::new("link_args", &["link_args.c", "exit.c"])?,
        Program::new(
            "global_vars",
            &["global_definitions.c", "global_references.c", "exit.c"],
        )?,
        Program::new("data", &["data.c", "exit.c"])?,
        Program::new("weak-vars", &["weak-vars.c", "weak-vars1.c", "exit.c"])?,
        Program::new(
            "weak-vars-archive",
            &["weak-vars-archive.c", "weak-vars1.c", "exit.c"],
        )?,
        Program::new("weak-fns", &["weak-fns.c", "weak-fns1.c", "exit.c"])?,
        Program::new(
            "weak-fns-archive",
            &["weak-fns-archive.c", "weak-fns1.c", "exit.c"],
        )?,
        Program::new("init_test", &["init_test.c", "init.c", "exit.c"])?,
        Program::new("ifunc", &["ifunc.c", "ifunc1.c", "exit.c"])?,
        Program::new("internal-syms", &["internal-syms.c", "exit.c"])?,
        Program::new("tls", &["tls.c", "tls1.c", "init_tls.c", "exit.c"])?,
        Program::new(
            "old_init",
            &["old_init.c", "old_init0.s", "old_init1.s", "exit.c"],
        )?,
        Program::new(
            "custom_section",
            &["custom_section.c", "custom_section0.c", "exit.c"],
        )?,
        Program::new("stack_alignment", &["stack_alignment.s", "exit.c"])?,
        Program::new("local_symbol_refs", &["local_symbol_refs.s", "exit.c"])?,
        Program::new(
            "archive_activation",
            &[
                "archive_activation.c",
                "archive_activation0.c",
                "archive_activation1.c",
                "exit.c",
                "empty.a",
            ],
        )?,
        Program::new(
            "common_section",
            &[
                "common_section.c",
                "common_section0.c",
                "common_section1.c",
                "exit.c",
            ],
        )?,
        Program::new(
            "string_merging",
            &[
                "string_merging.c",
                "string_merging1.s",
                "string_merging2.s",
                "exit.c",
            ],
        )?,
        Program::new(
            "comments",
            &["comments.c", "comments0.c", "comments1.c", "exit.c"],
        )?,
        Program::new("eh_frame", &["eh_frame.c", "eh_frame_end.c", "exit.c"])?,
    ];

    let compilation_configs = [
        CompilationConfig {
            pie: false,
            opt_level: 0,
        },
        CompilationConfig {
            pie: true,
            opt_level: 0,
        },
        CompilationConfig {
            pie: false,
            opt_level: 2,
        },
    ];
    let linker_configs = [
        LinkerConfig {
            kind: LinkerKind::ThirdParty("ld"),
        },
        LinkerConfig {
            kind: LinkerKind::Wild,
        },
    ];

    for program in &programs {
        let filename = program.source_files.first().unwrap();
        let instructions = TestParameters::from_source(&src_path(filename))
            .with_context(|| format!("Failed to parse test parameters from `{filename}`"))?;
        for link_cfg in linker_configs {
            for &link_kind in &instructions.link_kind {
                for tls_model in &instructions.tls_models {
                    for link_args in &instructions.linker_args {
                        for compiler_args in &instructions.compiler_args {
                            for &variant_num in &instructions.variant_nums {
                                let variant = Variant {
                                    link_kind,
                                    linker_args: link_args.clone(),
                                    compilation: CompilationVariant {
                                        variant_num,
                                        tls_model: tls_model.clone(),
                                        compiler_args: compiler_args.clone(),
                                    },
                                };
                                for comp_cfg in compilation_configs {
                                    let config = Config {
                                        compilation: comp_cfg,
                                        linker: link_cfg,
                                    };
                                    program
                        .run(&config, &variant, &instructions.assertions)
                        .with_context(|| {
                            format!("Failed to run program `{program}` with config `{config}` variant #{variant}")
                        })?;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
