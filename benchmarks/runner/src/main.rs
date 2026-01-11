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
        }
    }

    fn supports_arg(&self, arg: &str) -> bool {
        match arg {
            "--no-fork" => matches!(self, LinkerKind::Wild | LinkerKind::Mold),
            _ => true,
        }
    }
}

impl Bin {
    fn new(bin_path: &Path, index: u32) -> Result<Self> {
        let output = Command::new(bin_path)
            .arg("--version")
            .output()
            .with_context(|| format!("Failed to run `{}`", bin_path.display()))?;

        if !output.status.success() {
            bail!(
                "{} --version failed: {}",
                bin_path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let version_line = String::from_utf8_lossy(&output.stdout)
            .to_string()
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();

        let identifier = LinkerIdentifier::parse(&version_line, bin_path)
            .with_context(|| format!("Failed to parse linker version `{version_line}`"))?;

        Ok(Self {
            index,
            path: bin_path.to_owned(),
            identifier,
        })
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

        if let Some(mut rest) = version_line.strip_prefix("Wild version ") {
            version = take_word(&mut rest)?.to_owned();
            if !bin_path.to_string_lossy().contains(&version) {
                // For wild, we only consider the version to be true if the path to the linker
                // contains the version number, otherwise we use the git hash.
                hash = Some(take_word(&mut rest)?.replace(['(', ')'], ""));
            }

            kind = LinkerKind::Wild;
        } else if let Some(mut rest) = version_line.strip_prefix("LLD ") {
            kind = LinkerKind::Lld;
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
}
