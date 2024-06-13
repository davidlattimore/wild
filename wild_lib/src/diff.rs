//! If the environment variable WILD_REFERENCE_LINKER is set, then once we've finished linking,
//! we'll link again using the linker specified in the environment variable. The output from the
//! reference linker will be the same, but with '.ref-linker' appended. We'll then diff the two
//! outputs and report any unexpected differences found. Setting the environment variable will also
//! enable writing of trace and layout files by the Wild linker, which allow additional information
//! to be added to the diff outputs.
//!
//! For this to work, the linker-diff binary needs to be installed in the same directory as wild.

use crate::error::Result;
use anyhow::bail;
use anyhow::Context;
use std::path::PathBuf;
use std::process::Command;

pub(crate) fn maybe_diff() -> Result {
    if let Ok(reference_linker) = std::env::var(crate::args::REFERENCE_LINKER_ENV) {
        if let Some(paths) = run_with_linker(&reference_linker)? {
            run_diff(&paths).context("Failed to run linker-diff")?;
        }
    }
    Ok(())
}

struct BinPaths {
    our_output: PathBuf,
    reference_output: PathBuf,
}

fn run_with_linker(reference_linker: &str) -> Result<Option<BinPaths>> {
    let mut command = Command::new(reference_linker);
    let mut next_is_output = false;
    let mut paths = None;
    for mut arg in std::env::args().skip(1) {
        if next_is_output {
            let our_output = PathBuf::from(&arg);
            arg.push_str(".ref-linker");
            paths = Some(BinPaths {
                our_output,
                reference_output: PathBuf::from(&arg),
            });
        }
        next_is_output = arg == "-o";
        command.arg(arg);
    }
    // If the linker was run without -o, then there's nothing to diff
    let Some(paths) = paths else {
        return Ok(None);
    };
    let status = command
        .status()
        .with_context(|| format!("Failed to run `{reference_linker}`"))?;
    if !status.success() {
        bail!("Reference linker exited with non-zero status");
    }
    Ok(Some(paths))
}

fn run_diff(paths: &BinPaths) -> Result {
    let linker_diff_path = std::env::current_exe()?.with_file_name("linker-diff");
    if !linker_diff_path.exists() {
        bail!("linker-diff binary needs to be in the same directory as wild")
    }
    let status = Command::new(linker_diff_path)
        .arg("--wild-defaults")
        .arg(&paths.reference_output)
        .arg(&paths.our_output)
        .status()?;
    if !status.success() {
        bail!("linker-diff exited with non-zero status");
    }
    Ok(())
}
