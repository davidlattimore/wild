//! An over-engineered, opinionated tool for benchmarking linkers, in particular Wild.
//!
//! Things that make this specific to linkers and/or wild.
//!
//! * It assumes benchmarks are in the form of Wild-generated save-dirs. i.e. a directory (the name
//!   of which is the name of the benchmark) where that directory contains a rust-with script.
//! * It accommodates that some of the linkers fork on startup, then do shutdown work after the
//!   linker terminates. To prevent this from affecting subsequent runs, it inserts a delay based on
//!   how long the linker took to run.
//! * It handles querying the linkers for their version to include in the report.
//! * It allows per-benchmark configuration files that can specify things like the minimum supported
//!   version of wild that can run that benchmark or skipping particular linkers for particular
//!   benchmarks.
//! * Passing --no-fork to linkers that support it when measuring memory consumption.
//!
//! Basically, this is a big script, but written in Rust, because it makes it easier to maintain.
//!
//! We avoid calling out to external tools because it wouldn't really get us much. We'd need to
//! parse their output, which would probably be more complex than doing it ourselves. We'd also have
//! less control over how exactly things are done. So we just do it ourselves.
//!
//! Benchmarking and producing reports are two separate steps. This is useful since benchmarking is
//! slow, while producing reports is very fast. By being separate, we can run the slow benchmark
//! hopefully just once, then produce the report multiple times as we tweak the presentation. The
//! format of the intermediate file uses postcard because we already had a dependency on it. It's
//! very subject to change, so is only useful for short-term storage.

use crate::config::BenchConfig;
use crate::config::Config;
use anyhow::Context;
use anyhow::bail;
use clap::Parser;
use serde::Deserialize;
use serde::Serialize;
use std::fmt::Display;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

mod benchmarking;
mod config;
mod reporting;
mod system;

type Result<T = (), E = anyhow::Error> = std::result::Result<T, E>;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Subcommand,
}

#[derive(clap::Subcommand, Clone)]
enum Subcommand {
    Bench(BenchArgs),
    Report(ReportArgs),
}

#[derive(Parser, Clone)]
struct BenchArgs {
    /// Path to benchmark.toml
    #[clap(long, default_value = "benchmarks/ryzen-9955hx.toml")]
    config: PathBuf,

    /// The directory containing the savedirs.
    #[clap(long)]
    saves: PathBuf,

    /// Skip initial verification that we can run each benchmark.
    #[clap(long)]
    no_verify: bool,

    /// Skip checking that the system is suitably configured for benchmarking.
    #[clap(long)]
    no_check_system: bool,

    /// Allow benchmarking on non-tmpfs filesystem.
    #[clap(long)]
    allow_non_tmpfs: bool,

    /// Where to write output file of linker. Should generally be on tmpfs.
    #[clap(long, default_value = "/tmp/linker-benchmark-out")]
    tmp: PathBuf,

    /// Number of runs per batch.
    #[clap(long, default_value = "8")]
    batch_size: u32,

    /// Number of batches.
    #[clap(long, default_value = "10")]
    num_batches: u32,

    /// Whether to skip checking memory consumption. Unless set, then the first batch will run with
    /// --no-fork for linkers that support it.
    #[clap(long)]
    no_mem: bool,

    /// Restrict to just the specified benchmarks.
    #[clap(long, value_delimiter = ',')]
    benches: Vec<String>,

    /// Filename to write results to. If not specified, will write to
    /// `benchmarks/[benchmark-name].bench-results`.
    #[clap(long)]
    output: Option<PathBuf>,

    /// The linker binaries to benchmark.
    binaries: Vec<PathBuf>,
}

#[derive(Parser, Clone)]
struct ReportArgs {
    /// Path to benchmark.toml. Can be repeated. If not specified, runs all toml files in the
    /// benchmarks dir.
    #[clap(long)]
    config: Vec<PathBuf>,

    /// The benchmarks directory. Reports are written here. We also by default look for config
    /// here.
    #[clap(long, default_value = "benchmarks")]
    dir: PathBuf,

    /// Override the filename containing previously written results to read from. Default is the
    /// same as for `--output` on the `bench` command.
    #[clap(long)]
    input: Option<PathBuf>,

    /// Whether to print stats to stdout.
    #[clap(long)]
    print_stats: bool,
}

fn main() -> Result {
    let args = Args::parse();

    match args.command {
        Subcommand::Bench(bench_args) => {
            let config = config::Config::load(&bench_args.config)?;
            if !bench_args.no_check_system {
                system::check_system_settings()?;
            }
            benchmarking::run_bench(&bench_args, &config)
        }
        Subcommand::Report(report_args) => {
            for config_path in &report_args.configs()? {
                let config = config::Config::load(config_path)?;
                reporting::run_report(&report_args, &config)?
            }
            Ok(())
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Benchmarks {
    benchmarks: Vec<BenchmarkResult>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BenchmarkResult {
    config: Benchmark,
    batches: Vec<BatchResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BatchResult {
    bin: Bin,
    runs: Vec<Run>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Run {
    /// The pid of the process that we timed. Within a batch, we should expect to see evenly spaced
    /// pids. If we don't, that might be a sign that the system we're running in is busy doing
    /// something (e.g. applying updates). We don't actually use this at this stage, but might in
    /// future.
    pid: u32,
    extra_flags: Vec<String>,
    elapsed: std::time::Duration,
    pub(crate) max_rss: u64,
    pub(crate) stime: Duration,
    pub(crate) utime: Duration,
    /// Size in bytes of the output file produced by this link. 0 if
    /// the output file wasn't found (e.g. link failed silently, or an
    /// older run from before this field was tracked).
    #[serde(default)]
    pub(crate) output_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Bin {
    index: u32,
    path: PathBuf,
    identifier: LinkerIdentifier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LinkerIdentifier {
    kind: LinkerKind,
    version: String,
    variant: Option<String>,
    /// The commit hash of the linker. Set for Wild when the path to the linker doesn't include the
    /// version number. i.e. when we've concluded that this isn't a release version.
    hash: Option<String>,
    /// If we've got has, then this is one patch level higher than version.
    effective_version: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LinkerKind {
    Wild,
    Lld,
    Mold,
    Bfd,
    /// Apple's Mach-O linker (also published as `ld` on macOS
    /// toolchains — `/usr/bin/ld` is ld64 there). Not cross-compatible
    /// with ELF benches.
    Ld64,
    /// Wild invoked with `-ld64_compat` via the
    /// `benchmarks/runner/bin/wild-ld64-compat` wrapper. Exists so the
    /// report distinguishes plain wild's default output from the
    /// bit-for-bit-vs-ld64 mode.
    WildCompat,
    /// Wild invoked with `-O<N>` (N = 1..=3) via the matching
    /// `benchmarks/runner/bin/wild-O<N>` wrapper. Carries the opt
    /// level so the report can label each column (Wild, Wild-O1,
    /// Wild-O2, Wild-O3) and keep them visually distinct. ELF-only
    /// today — libwild's `-O` flag parser lives in `args::elf`.
    WildOpt(u8),
    /// rust-lld's `wasm-ld` symlink (or any LLD invoked under that
    /// name). Same binary as `Lld` — disambiguated by filename in the
    /// `LinkerIdentifier::parse` path. Exists as its own kind so the
    /// report keeps the wasm baseline visually separate from the ELF
    /// `lld` line, and so `supports_platform(Platform::Wasm)` returns
    /// true for it (and false for the same binary if invoked as `ld.lld`).
    WasmLd,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Benchmark {
    name: String,
    path: PathBuf,
    config: BenchConfig,
}

impl LinkerKind {
    fn as_str(self) -> &'static str {
        match self {
            LinkerKind::Wild => "Wild",
            LinkerKind::Lld => "LLD",
            LinkerKind::Mold => "Mold",
            LinkerKind::Bfd => "GNU ld",
            LinkerKind::Ld64 => "ld64",
            LinkerKind::WildCompat => "Wild-compat",
            LinkerKind::WildOpt(1) => "Wild -O1",
            LinkerKind::WildOpt(2) => "Wild -O2",
            LinkerKind::WildOpt(3) => "Wild -O3",
            LinkerKind::WildOpt(_) => "Wild -O?",
            LinkerKind::WasmLd => "wasm-ld",
        }
    }

    fn supports_arg(&self, arg: &str) -> bool {
        match arg {
            "--no-fork" => matches!(
                self,
                LinkerKind::Wild
                    | LinkerKind::WildCompat
                    | LinkerKind::WildOpt(_)
                    | LinkerKind::Mold
            ),
            _ => true,
        }
    }

    /// Which output formats this linker can produce. Wild handles all
    /// three (ELF, Mach-O, Wasm); the rest are single-format.
    /// `WildCompat` is Mach-O-only because `-ld64_compat` has no
    /// meaning for ELF / Wasm outputs. `WildOpt(_)` is ELF-only
    /// because libwild's `-O` flag parser only exists for ELF today.
    /// `WasmLd` is the same LLD binary as `Lld` but invoked under
    /// the `wasm-ld` filename, so it produces wasm32/64 output.
    fn supports_platform(&self, platform: crate::config::Platform) -> bool {
        use crate::config::Platform as P;
        match self {
            LinkerKind::Wild => true,
            LinkerKind::Lld | LinkerKind::Mold | LinkerKind::Bfd => platform == P::Elf,
            LinkerKind::Ld64 | LinkerKind::WildCompat => platform == P::Macho,
            LinkerKind::WildOpt(_) => platform == P::Elf,
            LinkerKind::WasmLd => platform == P::Wasm,
        }
    }
}

impl Bin {
    fn new(bin_path: &Path, index: u32) -> Result<Self> {
        // Try `--version` (ELF linkers + Wild), then `-v` (ld64 doesn't
        // support `--version` and prints to stderr). Each attempt yields
        // a candidate first-line to hand to the parser; the first one
        // `LinkerIdentifier::parse` recognises wins.
        let mut tried: Vec<String> = Vec::new();
        for flag in ["--version", "-v"] {
            let output = Command::new(bin_path)
                .arg(flag)
                .output()
                .with_context(|| format!("Failed to run `{}`", bin_path.display()))?;
            // ld64 prints version info to stderr; other linkers use
            // stdout. Combine both and take the first non-empty line.
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let Some(candidate) = combined
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .map(str::to_owned)
            else {
                continue;
            };
            if let Some(identifier) = LinkerIdentifier::parse(&candidate, bin_path) {
                return Ok(Self {
                    index,
                    path: bin_path.to_owned(),
                    identifier,
                });
            }
            tried.push(candidate);
        }
        bail!(
            "Failed to identify linker at `{}`. Tried version lines: {:?}",
            bin_path.display(),
            tried
        );
    }
}

impl Benchmark {
    fn new(bench_dir: PathBuf, bench_config: BenchConfig) -> Result<Benchmark> {
        let name = bench_dir
            .file_name()
            .context("Invalid filename")?
            .to_str()
            .with_context(|| format!("Filename isn't valid UTF-8: {}", bench_dir.display()))?
            .to_owned();

        let path = bench_dir.join("run-with");
        if !path.exists() {
            bail!("{} doesn't exist", path.display())
        }

        Ok(Benchmark {
            name,
            path,
            config: bench_config,
        })
    }

    fn supports_wild_version(&self, wild_version: &[u32]) -> bool {
        let Some(min_required) = self
            .config
            .min_wild_version
            .as_ref()
            .and_then(|v| crate::parse_version_number(v).ok())
        else {
            return true;
        };

        wild_version >= &min_required
    }

    fn supports_bin(&self, bin: &Bin) -> bool {
        if self.config.skip_linkers.contains(&bin.identifier.kind) {
            return false;
        }
        if bin.identifier.kind == LinkerKind::Wild {
            return self.supports_wild_version(&bin.identifier.effective_version);
        }
        true
    }
}

impl LinkerIdentifier {
    fn parse(version_line: &str, bin_path: &Path) -> Option<Self> {
        let kind;
        let version;
        let mut hash = None;
        let mut variant = None;

        if let Some(mut rest) = version_line.strip_prefix("Wild-ld64compat ") {
            // Thin wrapper at benchmarks/runner/bin/wild-ld64-compat
            // rewrites wild's `-v` output so we can tell the two modes
            // apart in reports. Format is otherwise identical to plain
            // Wild: "Wild-ld64compat <ver> <hash> ...".
            version = take_word(&mut rest)?.to_owned();
            if !bin_path.to_string_lossy().contains(&version) {
                hash = Some(take_word(&mut rest)?.replace(['(', ')'], ""));
            }
            kind = LinkerKind::WildCompat;
        } else if let Some((opt_level, mut rest)) = strip_wild_opt_prefix(version_line) {
            // Wrappers at `benchmarks/runner/bin/wild-O<N>` rewrite the
            // banner to "Wild-O<N> <ver> <hash> ..." so the report
            // labels each opt level distinctly. Format after the
            // prefix matches plain Wild.
            version = take_word(&mut rest)?.to_owned();
            if !bin_path.to_string_lossy().contains(&version) {
                hash = Some(take_word(&mut rest)?.replace(['(', ')'], ""));
            }
            kind = LinkerKind::WildOpt(opt_level);
        } else if let Some(mut rest) = version_line
            .strip_prefix("Wild version ")
            .or_else(|| version_line.strip_prefix("Wild "))
        {
            version = take_word(&mut rest)?.to_owned();
            if !bin_path.to_string_lossy().contains(&version) {
                // For wild, we only consider the version to be true if the path to the linker
                // contains the version number, otherwise we use the git hash.
                hash = Some(take_word(&mut rest)?.replace(['(', ')'], ""));
            }

            kind = LinkerKind::Wild;
        } else if let Some(mut rest) = version_line.strip_prefix("LLD ") {
            // Same `LLD <ver>` banner is shared by `ld.lld`, `wasm-ld`,
            // and `ld64.lld`. Disambiguate from the binary's filename:
            // anything matching `wasm-ld` (with or without extension)
            // is the Wasm flavour, even when invoked through a symlink
            // — rust-lld ships its wasm front-end as `wasm-ld`.
            kind = if is_wasm_ld_path(bin_path) {
                LinkerKind::WasmLd
            } else {
                LinkerKind::Lld
            };
            version = take_word(&mut rest)?.to_owned();
        } else if let Some(mut rest) = version_line.strip_prefix("Ubuntu LLD ") {
            kind = LinkerKind::Lld;
            version = take_word(&mut rest)?.to_owned();
            variant = Some("Ubuntu".to_owned());
        } else if let Some(mut rest) = version_line.strip_prefix("Debian LLD ") {
            kind = LinkerKind::Lld;
            version = take_word(&mut rest)?.to_owned();
            variant = Some("Debian".to_owned());
        } else if let Some(mut rest) = version_line.strip_prefix("mold ") {
            kind = LinkerKind::Mold;
            version = take_word(&mut rest)?.to_owned();
        } else if let Some(mut rest) =
            version_line.strip_prefix("GNU ld (GNU Binutils for Ubuntu) ")
        {
            kind = LinkerKind::Bfd;
            version = take_word(&mut rest)?.to_owned();
            variant = Some("Ubuntu".to_owned());
        } else if let Some(rest) = version_line.strip_prefix("@(#)PROGRAM:ld ")
            && let Some(rest) = rest.split_whitespace().find_map(|w| {
                w.strip_prefix("PROJECT:ld-")
                    .or_else(|| w.strip_prefix("PROJECT:ld64-"))
            })
        {
            // ld64 / ld-prime: `@(#)PROGRAM:ld PROJECT:ld-1230.1`.
            // Apple ships recent toolchains as `ld` with the legacy
            // `ld64` still rolling the version. Accept both project
            // prefixes so the parser works on older Xcodes too.
            kind = LinkerKind::Ld64;
            version = rest.trim().to_owned();
        } else {
            return None;
        }

        let mut effective_version = parse_version_number(&version).ok()?;

        if hash.is_some()
            && let Some(patch) = effective_version.last_mut()
        {
            *patch += 1;
        }

        Some(LinkerIdentifier {
            kind,
            version,
            variant,
            hash,
            effective_version,
        })
    }

    fn name_parts(&self) -> Vec<String> {
        let mut parts = Vec::new();
        parts.push(self.kind.to_string());
        if let Some(hash) = &self.hash {
            parts.push(hash.chars().take(8).collect());
        } else {
            parts.push(self.version.clone());
        }
        if let Some(variant) = &self.variant {
            parts.push(variant.clone());
        }
        parts
    }
}

/// Match a banner of the form `Wild-O<N> <rest...>` where N ∈ 1..=3.
/// Returns the opt level and the slice after the prefix + single
/// space. Any other digit (including 0) is rejected so plain
/// `Wild` is still routed through the next branch rather than
/// being mis-tagged as `WildOpt(0)`.
fn strip_wild_opt_prefix(line: &str) -> Option<(u8, &str)> {
    let rest = line.strip_prefix("Wild-O")?;
    let (digit_ch, rest) = rest.split_at(rest.chars().next()?.len_utf8());
    let level: u8 = digit_ch.parse().ok()?;
    if !(1..=3).contains(&level) {
        return None;
    }
    let rest = rest.strip_prefix(' ')?;
    Some((level, rest))
}

/// True when the binary path is `…/wasm-ld[.exe]`. Used to flag the
/// rust-lld wasm front-end vs the regular ELF lld, since both print
/// the same `LLD <ver>` banner. We check the file *name*, not the
/// whole path — rust-lld ships its symlink as `wasm-ld` regardless
/// of where it's installed.
fn is_wasm_ld_path(bin_path: &Path) -> bool {
    bin_path
        .file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(|stem| stem == "wasm-ld")
}

fn take_word<'a>(input: &mut &'a str) -> Option<&'a str> {
    *input = input.trim();
    let i = input.find(' ').unwrap_or(input.len());
    let (word, rest) = input.split_at(i);
    *input = rest;
    Some(word)
}

impl Display for Bin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.identifier)
    }
}

impl Display for LinkerIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.kind)?;

        if let Some(hash) = &self.hash {
            let prefix: String = hash.chars().take(8).collect();
            write!(f, " {prefix}")?;
        } else {
            write!(f, " {}", self.version)?;
        }

        if let Some(variant) = &self.variant {
            write!(f, " {variant}")?;
        }
        Ok(())
    }
}

impl Display for LinkerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Display for Benchmark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

fn parse_version_number(v: &str) -> Result<Vec<u32>> {
    v.split(".")
        .map(|p| {
            p.parse()
                .with_context(|| format!("Failed to parse version `{v}`"))
        })
        .collect()
}

fn default_result_path(config: &Config, path_buf: &Option<PathBuf>) -> PathBuf {
    path_buf.clone().unwrap_or_else(|| {
        PathBuf::from("benchmarks").join(format!("{}.bench-results", config.name))
    })
}

impl ReportArgs {
    fn configs(&self) -> Result<Vec<PathBuf>> {
        if !self.config.is_empty() {
            return Ok(self.config.clone());
        }

        let dir = std::fs::read_dir(&self.dir)
            .with_context(|| format!("Failed to read --dir `{}`", self.dir.display()))?;

        Ok(dir
            .filter_map(|ent| ent.ok())
            .map(|ent| ent.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version_less_than(a: &str, b: &str) -> bool {
        let (Ok(a), Ok(b)) = (parse_version_number(a), parse_version_number(b)) else {
            return false;
        };
        a < b
    }

    #[test]
    fn test_version_comparison() {
        assert!(version_less_than("0.5.0", "0.6.0"));
        assert!(!version_less_than("0.5.0", "0.5.0"));
        assert!(!version_less_than("0.6.0", "0.5.0"));
        assert!(version_less_than("0.5.0", "0.10.0"));
    }

    #[test]
    fn test_parse_ld64_identifier() {
        // Apple `ld -v` first line on modern toolchains.
        let id =
            LinkerIdentifier::parse("@(#)PROGRAM:ld PROJECT:ld-1230.1", Path::new("/usr/bin/ld"))
                .expect("ld64 version parse");
        assert_eq!(id.kind, LinkerKind::Ld64);
        assert_eq!(id.version, "1230.1");
        assert_eq!(id.effective_version, vec![1230, 1]);
    }

    #[test]
    fn test_parse_legacy_ld64_identifier() {
        // Pre-unified toolchains had `PROJECT:ld64-NNN`.
        let id = LinkerIdentifier::parse(
            "@(#)PROGRAM:ld PROJECT:ld64-951.9",
            Path::new("/usr/bin/ld"),
        )
        .expect("legacy ld64 parse");
        assert_eq!(id.kind, LinkerKind::Ld64);
        assert_eq!(id.version, "951.9");
    }

    #[test]
    fn test_host_platform_matches_cfg() {
        use crate::config::Platform;
        let host = Platform::host();
        if cfg!(target_os = "macos") {
            assert_eq!(host, Platform::Macho);
        } else {
            assert_eq!(host, Platform::Elf);
        }
    }

    #[test]
    fn test_parse_wild_opt_banner() {
        for level in 1u8..=3 {
            let line =
                format!("Wild-O{level} 0.8.0 abcdef1234567890 (compatible with GNU linkers)");
            let id =
                LinkerIdentifier::parse(&line, Path::new(&format!("/opt/wild/bin/wild-O{level}")))
                    .unwrap_or_else(|| panic!("wild-O{level} banner parse failed"));
            assert_eq!(id.kind, LinkerKind::WildOpt(level));
            assert_eq!(id.version, "0.8.0");
            assert_eq!(id.hash.as_deref(), Some("abcdef1234567890"));
        }
    }

    #[test]
    fn test_parse_wild_opt_rejects_invalid_level() {
        // Only -O1..=-O3 are recognised. -O0 collides with plain Wild
        // (we don't want to tag baseline runs as WildOpt(0)) and
        // -O4+ isn't a real wild optimisation level.
        assert!(strip_wild_opt_prefix("Wild-O0 0.8.0").is_none());
        assert!(strip_wild_opt_prefix("Wild-O4 0.8.0").is_none());
        assert!(strip_wild_opt_prefix("Wild-Ox 0.8.0").is_none());
        // Plain Wild banner doesn't match either.
        assert!(strip_wild_opt_prefix("Wild 0.8.0").is_none());
    }

    #[test]
    fn test_wild_opt_supports_elf_only() {
        use crate::config::Platform;
        for level in 1u8..=3 {
            let k = LinkerKind::WildOpt(level);
            assert!(k.supports_platform(Platform::Elf));
            assert!(!k.supports_platform(Platform::Macho));
            assert!(!k.supports_platform(Platform::Wasm));
            assert!(k.supports_arg("--no-fork"));
        }
    }

    #[test]
    fn test_parse_wild_ld64compat_banner() {
        let id = LinkerIdentifier::parse(
            "Wild-ld64compat 0.8.0 abcdef1234567890 (compatible with GNU linkers)",
            Path::new("/opt/wild/bin/wild-ld64-compat"),
        )
        .expect("wild-compat banner parse");
        assert_eq!(id.kind, LinkerKind::WildCompat);
        assert_eq!(id.version, "0.8.0");
        // Path doesn't contain the version, so hash gets set.
        assert_eq!(id.hash.as_deref(), Some("abcdef1234567890"));
    }

    #[test]
    fn test_parse_wild_current_banner() {
        // Current wild releases: "Wild 0.8.0 (compatible with GNU linkers)".
        // Historical: "Wild version 0.8.0 …". Both accepted.
        let id = LinkerIdentifier::parse(
            "Wild 0.8.0 (compatible with GNU linkers)",
            Path::new("/opt/wild-0.8.0/wild"),
        )
        .expect("wild current banner parse");
        assert_eq!(id.kind, LinkerKind::Wild);
        assert_eq!(id.version, "0.8.0");

        let id = LinkerIdentifier::parse(
            "Wild version 0.7.0 (compatible with GNU linkers)",
            Path::new("/opt/wild-0.7.0/wild"),
        )
        .expect("wild legacy banner parse");
        assert_eq!(id.kind, LinkerKind::Wild);
        assert_eq!(id.version, "0.7.0");
    }

    #[test]
    fn test_ld64_supports_only_macho() {
        use crate::config::Platform;
        assert!(LinkerKind::Ld64.supports_platform(Platform::Macho));
        assert!(!LinkerKind::Ld64.supports_platform(Platform::Elf));
        assert!(LinkerKind::Wild.supports_platform(Platform::Macho));
        assert!(LinkerKind::Wild.supports_platform(Platform::Elf));
        assert!(LinkerKind::Mold.supports_platform(Platform::Elf));
        assert!(!LinkerKind::Mold.supports_platform(Platform::Macho));
        assert!(LinkerKind::WildCompat.supports_platform(Platform::Macho));
        assert!(!LinkerKind::WildCompat.supports_platform(Platform::Elf));
    }

    #[test]
    fn test_wasm_platform_routing() {
        use crate::config::Platform;
        // Wild handles all three; WasmLd is wasm-only; ELF/Mach-O
        // linkers refuse Wasm.
        assert!(LinkerKind::Wild.supports_platform(Platform::Wasm));
        assert!(LinkerKind::WasmLd.supports_platform(Platform::Wasm));
        assert!(!LinkerKind::WasmLd.supports_platform(Platform::Elf));
        assert!(!LinkerKind::WasmLd.supports_platform(Platform::Macho));
        assert!(!LinkerKind::Lld.supports_platform(Platform::Wasm));
        assert!(!LinkerKind::Mold.supports_platform(Platform::Wasm));
        assert!(!LinkerKind::Bfd.supports_platform(Platform::Wasm));
        assert!(!LinkerKind::Ld64.supports_platform(Platform::Wasm));
        assert!(!LinkerKind::WildCompat.supports_platform(Platform::Wasm));
    }

    #[test]
    fn test_wasm_runs_on_any_host() {
        use crate::config::Platform;
        // Wasm output is target-only; both hosts can produce it.
        assert!(Platform::Wasm.runs_on_host(Platform::Macho));
        assert!(Platform::Wasm.runs_on_host(Platform::Elf));
        // ELF / Mach-O still gated to their native host.
        assert!(Platform::Elf.runs_on_host(Platform::Elf));
        assert!(!Platform::Elf.runs_on_host(Platform::Macho));
        assert!(Platform::Macho.runs_on_host(Platform::Macho));
        assert!(!Platform::Macho.runs_on_host(Platform::Elf));
    }

    #[test]
    fn test_lld_banner_disambig_by_filename() {
        // Same `LLD <ver>` first line, two different filenames.
        // ld.lld stays Lld; wasm-ld becomes WasmLd. Both with
        // path-doesn't-contain-version so version is still parsed.
        let line = "LLD 19.1.4 (https://github.com/rust-lang/llvm-project.git abc)";

        let ld_lld =
            LinkerIdentifier::parse(line, Path::new("/usr/bin/ld.lld")).expect("ld.lld parse");
        assert_eq!(ld_lld.kind, LinkerKind::Lld);
        assert_eq!(ld_lld.version, "19.1.4");

        let wasm_ld = LinkerIdentifier::parse(
            line,
            Path::new(
                "/Users/x/.rustup/toolchains/nightly/lib/rustlib/aarch64-apple-darwin/bin/gcc-ld/wasm-ld",
            ),
        )
        .expect("wasm-ld parse");
        assert_eq!(wasm_ld.kind, LinkerKind::WasmLd);
        assert_eq!(wasm_ld.version, "19.1.4");
    }

    #[test]
    fn test_is_wasm_ld_path() {
        assert!(is_wasm_ld_path(Path::new("/foo/bar/wasm-ld")));
        assert!(is_wasm_ld_path(Path::new("./wasm-ld")));
        assert!(is_wasm_ld_path(Path::new("wasm-ld")));
        assert!(is_wasm_ld_path(Path::new("/foo/wasm-ld.exe"))); // Windows-style
        // Negatives — shouldn't false-positive on similar names.
        assert!(!is_wasm_ld_path(Path::new("/usr/bin/ld.lld")));
        assert!(!is_wasm_ld_path(Path::new("/usr/bin/lld")));
        assert!(!is_wasm_ld_path(Path::new("/foo/wasm-something-else")));
    }
}
