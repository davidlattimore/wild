//! If the environment variable WILD_REFERENCE_LINKER is set, then once we've finished linking,
//! we'll link again using the linker specified in the environment variable. The output from the
//! reference linker will be the same, but with '.ref-linker' appended. We'll then diff the two
//! outputs and report any unexpected differences found. Setting the environment variable will also
//! enable writing of trace and layout files by the Wild linker, which allow additional information
//! to be added to the diff outputs.

use crate::error::Result;
use anyhow::bail;
use std::path::PathBuf;

pub(crate) fn maybe_diff() -> Result {
    if let Ok(reference_linker) = std::env::var(crate::args::REFERENCE_LINKER_ENV) {
        run_with_linker(&reference_linker)?;
    }
    Ok(())
}

struct BinPaths {
    our_output: PathBuf,
    reference_output: PathBuf,
}

fn run_with_linker(reference_linker: &str) -> Result {
    let mut command = std::process::Command::new(reference_linker);
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
        return Ok(());
    };
    let status = command.status()?;
    if !status.success() {
        bail!("Reference linker exited with non-zero status");
    }

    let mut config = linker_diff::Config::current_wild_defaults();
    config.filenames.push(paths.reference_output);
    config.filenames.push(paths.our_output);
    let report = linker_diff::Report::from_config(config.clone())?;
    if report.has_problems() {
        eprintln!("{report}");
        bail!("Differences found when compared with output of {reference_linker}");
    }
    Ok(())
}
