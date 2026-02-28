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

mod consts;
pub mod linux;
pub mod windows;

pub use consts::*;

// Re-export everything from linux.rs for backward compatibility.
// The rest of the crate uses `crate::args::Args`, `crate::args::FileWriteMode`, etc.
// and this re-export ensures those paths continue to work.
pub use linux::*;

// Re-export types that sub-modules (windows.rs, parser.rs) need via `super::*`.
pub(crate) use crate::arch::Architecture;
pub(crate) use crate::output_kind::OutputKind;
pub(crate) use crate::save_dir::SaveDir;

use crate::bail;
use crate::save_dir;
use crate::error::Result;
use crate::target_os::Os;
use jobserver::Client;
use target_lexicon::Triple;

#[allow(dead_code)]
/// Trait providing mutable access to shared fields during argument parsing.
///
/// This trait is used by the generic `ArgumentParser<ArgsType>` to access fields
/// that both Linux and Windows argument structs share. It also defines platform-specific
/// parsing helpers (option prefix detection, separator detection).
pub(crate) trait PrivateArgs {
    fn new_default() -> Self;
    fn save_dir_mut(&mut self) -> &mut save_dir::SaveDir;
    fn inputs_mut(&mut self) -> &mut Vec<Input>;
    fn unrecognized_options_mut(&mut self) -> &mut Vec<String>;
    fn files_per_group_mut(&mut self) -> &mut Option<u32>;
    fn jobserver_client_mut(&mut self) -> &mut Option<Client>;
    fn write_layout_mut(&mut self) -> &mut bool;
    fn write_trace_mut(&mut self) -> &mut bool;
    fn setup_argument_parser() -> linux::ArgumentParser<Self>
    where
        Self: Sized;

    /// Check if argument has a valid option prefix for this platform.
    /// Linux: `-`, Windows: `/` or `-`.
    fn has_option_prefix(arg: &str) -> bool;

    /// Strip the option prefix(es) from an argument.
    /// Linux: `--` or `-`, Windows: `/` or `-`.
    fn strip_option<'a>(arg: &'a str) -> Option<&'a str>;

    /// Find the key=value separator position in a stripped option.
    /// Linux: `=`, Windows: `:` or `=`.
    fn find_separator(stripped: &str) -> Option<usize>;
}

pub(crate) fn add_silently_ignored_flags<ArgsType>(
    parser: &mut linux::ArgumentParser<ArgsType>,
) {
    fn noop<T>(_args: &mut T, _modifier_stack: &mut Vec<Modifiers>) -> Result<()> {
        Ok(())
    }
    for flag in SILENTLY_IGNORED_FLAGS {
        parser.declare().long(flag).execute(noop);
    }
    for flag in SILENTLY_IGNORED_SHORT_FLAGS {
        parser.declare().short(flag).execute(noop);
    }
}

pub(crate) fn add_default_flags<ArgsType>(parser: &mut linux::ArgumentParser<ArgsType>) {
    fn noop<T>(_args: &mut T, _modifier_stack: &mut Vec<Modifiers>) -> Result<()> {
        Ok(())
    }
    for flag in DEFAULT_FLAGS {
        parser.declare().long(flag).execute(noop);
    }
    for flag in DEFAULT_SHORT_FLAGS {
        parser.declare().short(flag).execute(noop);
    }
}

/// The output binary format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    Elf,
    Pe,
}

impl Default for OutputFormat {
    fn default() -> Self {
        match Os::DEFAULT {
            Os::Linux => OutputFormat::Elf,
            Os::Windows => OutputFormat::Pe,
            Os::MacOS => todo!("macOS linking not yet supported"),
        }
    }
}

/// Result of pre-scanning args for target-determining flags.
#[derive(Debug)]
pub(crate) struct DetectedTarget {
    pub format: OutputFormat,
    /// Architecture from `--target` triple. `None` if no `--target` was given.
    pub arch: Option<Architecture>,
}

/// Known `-m` emulation values that imply ELF output.
const ELF_EMULATIONS: &[&str] = &[
    "elf_x86_64",
    "elf_x86_64_sol2",
    "aarch64elf",
    "aarch64linux",
    "elf64lriscv",
    "elf64loongarch",
];

/// Map `target_lexicon::Architecture` to Wild's `Architecture`.
fn map_triple_arch(arch: target_lexicon::Architecture) -> Result<Architecture> {
    use target_lexicon::Architecture as TL;
    match arch {
        TL::X86_64 | TL::X86_64h => Ok(Architecture::X86_64),
        TL::Aarch64(_) => Ok(Architecture::AArch64),
        TL::Riscv64(_) => Ok(Architecture::RISCV64),
        TL::LoongArch64 => Ok(Architecture::LoongArch64),
        other => bail!("unsupported architecture in target triple: {other}"),
    }
}

/// Map `target_lexicon::BinaryFormat` to `OutputFormat`.
fn map_binary_format(fmt: target_lexicon::BinaryFormat) -> Result<OutputFormat> {
    match fmt {
        target_lexicon::BinaryFormat::Elf => Ok(OutputFormat::Elf),
        target_lexicon::BinaryFormat::Coff => Ok(OutputFormat::Pe),
        other => bail!("unsupported binary format: {other}"),
    }
}

/// Extract the target triple value from a flag, handling all prefix styles.
/// Returns `(Some(value), consumed_next)` if the arg is a target flag.
fn extract_target_value<'a>(arg: &'a str, next_arg: Option<&'a str>) -> (Option<&'a str>, bool) {
    // Combined forms: --target=VAL, -target=VAL, /TARGET:VAL
    if let Some(val) = arg
        .strip_prefix("--target=")
        .or_else(|| arg.strip_prefix("-target="))
        .or_else(|| arg.strip_prefix("/TARGET:"))
        .or_else(|| arg.strip_prefix("/target:"))
    {
        return (Some(val), false);
    }
    // Space-separated: --target VAL, -target VAL, /TARGET VAL
    if matches!(arg, "--target" | "-target" | "/TARGET" | "/target") {
        if let Some(val) = next_arg {
            return (Some(val), true);
        }
    }
    (None, false)
}

/// Pre-scan CLI arguments to determine the output format and architecture.
///
/// Recognizes:
/// - `--target=<triple>` / `-target=<triple>` / `/TARGET:<triple>` — primary (parsed by target-lexicon)
/// - `-m <emulation>` — overrides format to ELF when present
///
/// Priority: `-m` overrides format from `--target`. Architecture comes from `--target` only.
pub(crate) fn detect_target(args: &[String]) -> Result<DetectedTarget> {
    let mut from_triple: Option<(OutputFormat, Architecture)> = None;
    let mut m_implies_elf = false;

    let mut i = 0;
    while i < args.len() {
        let next = if i + 1 < args.len() {
            Some(args[i + 1].as_str())
        } else {
            None
        };
        let (target_val, consumed_next) = extract_target_value(&args[i], next);

        if let Some(val) = target_val {
            let triple: Triple = val
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid target triple '{val}': {e}"))?;
            let format = map_binary_format(triple.binary_format)?;
            let arch = map_triple_arch(triple.architecture)?;
            from_triple = Some((format, arch));
            if consumed_next {
                i += 1;
            }
        }
        // Check for -m <emulation> (implies ELF)
        else if args[i] == "-m" || args[i] == "--m" {
            if let Some(next_val) = next {
                if ELF_EMULATIONS.contains(&next_val) {
                    m_implies_elf = true;
                }
                i += 1;
            }
        } else if let Some(emu) = args[i].strip_prefix("-m") {
            if ELF_EMULATIONS.contains(&emu) {
                m_implies_elf = true;
            }
        }

        i += 1;
    }

    match (from_triple, m_implies_elf) {
        (Some((_, arch)), true) => {
            // -m overrides format to ELF; arch from triple preserved
            Ok(DetectedTarget {
                format: OutputFormat::Elf,
                arch: Some(arch),
            })
        }
        (Some((format, arch)), false) => Ok(DetectedTarget {
            format,
            arch: Some(arch),
        }),
        (None, true) => Ok(DetectedTarget {
            format: OutputFormat::Elf,
            arch: None,
        }),
        (None, false) => Ok(DetectedTarget {
            format: OutputFormat::default(),
            arch: None,
        }),
    }
}

/// Map Wild `Architecture` to the GNU ld `-m` emulation name.
fn arch_to_elf_emulation(arch: Architecture) -> &'static str {
    match arch {
        Architecture::X86_64 => "elf_x86_64",
        Architecture::AArch64 => "aarch64linux",
        Architecture::RISCV64 => "elf64lriscv",
        Architecture::LoongArch64 => "elf64loongarch",
    }
}

/// Map Wild `Architecture` to the MSVC `/MACHINE:` value.
fn arch_to_machine_value(arch: Architecture) -> &'static str {
    match arch {
        Architecture::X86_64 => "X64",
        Architecture::AArch64 => "ARM64",
        Architecture::RISCV64 => "X64",
        Architecture::LoongArch64 => "X64",
    }
}

/// Strip `--target`/`-target`/`/TARGET` flags and inject a synthetic `-m` or `/MACHINE:` flag
/// from the detected architecture so the format-specific parser picks it up.
///
/// The user's explicit `-m` or `/MACHINE:` flags are preserved and will override the injected one
/// since they appear later in the argument list.
pub(crate) fn filter_and_inject_target_flags(
    args: &[String],
    format: OutputFormat,
    arch: Option<Architecture>,
) -> Vec<String> {
    let mut result = Vec::with_capacity(args.len() + 2);

    // Inject synthetic arch flag at the front (user's explicit flags override later)
    if let Some(arch) = arch {
        match format {
            OutputFormat::Elf => {
                result.push("-m".to_string());
                result.push(arch_to_elf_emulation(arch).to_string());
            }
            OutputFormat::Pe => {
                result.push(format!("/MACHINE:{}", arch_to_machine_value(arch)));
            }
        }
    }

    // Strip --target flags, keep everything else
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with("--target=")
            || arg.starts_with("-target=")
            || arg.starts_with("/TARGET:")
            || arg.starts_with("/target:")
        {
            // Skip this combined arg
        } else if matches!(arg.as_str(), "--target" | "-target" | "/TARGET" | "/target") {
            i += 1; // skip value too
        } else {
            result.push(arg.clone());
        }
        i += 1;
    }
    result
}

/// Format-specific parsed arguments.
pub enum TargetArgs {
    Elf(linux::ElfArgs),
    #[allow(dead_code)]
    Pe(windows::PeArgs),
}

/// Parsed linker arguments. Shared fields are directly accessible.
/// Format-specific fields are behind the `target_args` enum.
pub struct Args {
    pub should_fork: bool,
    pub target_args: TargetArgs,
}

impl Args {
    /// Parse CLI arguments. Detects target format from `--target=<triple>`, `-m`,
    /// or host default, then routes to the format-specific parser.
    pub fn parse<F: Fn() -> I, S: AsRef<str>, I: Iterator<Item = S>>(
        input: F,
    ) -> Result<Args> {
        let all_args: Vec<String> = input().map(|s| s.as_ref().to_owned()).collect();
        let detected = detect_target(&all_args)?;
        let filtered = filter_and_inject_target_flags(&all_args, detected.format, detected.arch);

        match detected.format {
            OutputFormat::Elf => {
                let elf = linux::parse(|| filtered.iter().map(|s| s.as_str()))?;
                let should_fork = elf.should_fork();
                Ok(Args { should_fork, target_args: TargetArgs::Elf(elf) })
            }
            OutputFormat::Pe => {
                let pe = windows::parse(|| filtered.iter().map(|s| s.as_str()))?;
                let should_fork = pe.should_fork();
                Ok(Args { should_fork, target_args: TargetArgs::Pe(pe) })
            }
        }
    }
}

/// Top-level parse function.
pub fn parse<F: Fn() -> I, S: AsRef<str>, I: Iterator<Item = S>>(
    input: F,
) -> Result<Args> {
    Args::parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    // ---- detect_target tests ----

    #[test]
    fn test_detect_format_from_triple_linux_x86() {
        let args = to_strings(&["--target=x86_64-unknown-linux-gnu", "-o", "out"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, OutputFormat::Elf);
        assert_eq!(result.arch, Some(Architecture::X86_64));
    }

    #[test]
    fn test_detect_format_from_triple_windows() {
        let args = to_strings(&["-target=x86_64-pc-windows-msvc", "/OUT:foo.exe"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, OutputFormat::Pe);
        assert_eq!(result.arch, Some(Architecture::X86_64));
    }

    #[test]
    fn test_detect_format_from_slash_target() {
        let args = to_strings(&["/TARGET:aarch64-pc-windows-msvc", "foo.obj"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, OutputFormat::Pe);
        assert_eq!(result.arch, Some(Architecture::AArch64));
    }

    #[test]
    fn test_detect_format_space_separated() {
        let args = to_strings(&["--target", "aarch64-unknown-linux-gnu", "-o", "out"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, OutputFormat::Elf);
        assert_eq!(result.arch, Some(Architecture::AArch64));
    }

    #[test]
    fn test_detect_format_from_m_flag() {
        let args = to_strings(&["-m", "elf_x86_64", "-o", "out"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, OutputFormat::Elf);
        assert_eq!(result.arch, None);
    }

    #[test]
    fn test_m_flag_overrides_target_format() {
        let args = to_strings(&["--target=x86_64-pc-windows-msvc", "-m", "elf_x86_64"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, OutputFormat::Elf);
    }

    #[test]
    fn test_detect_format_default_no_flags() {
        let args = to_strings(&["-o", "out", "foo.o"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, OutputFormat::default());
        assert_eq!(result.arch, None);
    }

    #[test]
    fn test_detect_format_riscv_triple() {
        let args = to_strings(&["--target=riscv64gc-unknown-linux-gnu", "-o", "out"]);
        let result = detect_target(&args).unwrap();
        assert_eq!(result.format, OutputFormat::Elf);
        assert_eq!(result.arch, Some(Architecture::RISCV64));
    }

    // ---- filter_and_inject_target_flags tests ----

    #[test]
    fn test_filter_strips_target_equals() {
        let args = to_strings(&["--target=x86_64-unknown-linux-gnu", "-o", "out", "foo.o"]);
        let filtered = filter_and_inject_target_flags(&args, OutputFormat::Elf, Some(Architecture::X86_64));
        assert_eq!(filtered[0], "-m");
        assert_eq!(filtered[1], "elf_x86_64");
        assert_eq!(filtered[2], "-o");
        assert!(!filtered.iter().any(|a| a.contains("--target")));
    }

    #[test]
    fn test_filter_strips_target_space() {
        let args = to_strings(&["--target", "aarch64-unknown-linux-gnu", "-o", "out"]);
        let filtered = filter_and_inject_target_flags(&args, OutputFormat::Elf, Some(Architecture::AArch64));
        assert_eq!(filtered[0], "-m");
        assert_eq!(filtered[1], "aarch64linux");
        assert!(!filtered.iter().any(|a| a == "--target" || a.contains("linux-gnu")));
    }

    #[test]
    fn test_filter_strips_slash_target() {
        let args = to_strings(&["/TARGET:x86_64-pc-windows-msvc", "/OUT:foo.exe", "bar.obj"]);
        let filtered = filter_and_inject_target_flags(&args, OutputFormat::Pe, Some(Architecture::X86_64));
        assert_eq!(filtered[0], "/MACHINE:X64");
        assert_eq!(filtered[1], "/OUT:foo.exe");
    }

    #[test]
    fn test_filter_preserves_m_flag() {
        let args = to_strings(&["--target=x86_64-unknown-linux-gnu", "-m", "aarch64linux", "-o", "out"]);
        let filtered = filter_and_inject_target_flags(&args, OutputFormat::Elf, Some(Architecture::X86_64));
        assert_eq!(filtered[0], "-m");
        assert_eq!(filtered[1], "elf_x86_64");
        assert!(filtered.contains(&"-m".to_string()));
        assert!(filtered.contains(&"aarch64linux".to_string()));
    }

    #[test]
    fn test_filter_no_target_no_inject() {
        let args = to_strings(&["-o", "out", "foo.o"]);
        let filtered = filter_and_inject_target_flags(&args, OutputFormat::Elf, None);
        assert_eq!(filtered, args);
    }
}
