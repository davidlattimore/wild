//! A robust, self-contained module to find Windows and MSVC library paths.
//!
//! It combines two discovery methods for maximum reliability:
//! 1. **Primary:** Uses `vswhere.exe` and `vcvarsall.bat` to get the exact library
//!    paths configured for the Visual Studio C++ environment.
//! 2. **Fallback:** Manually scans the standard `Windows Kits` directory.
//!
//! The results are cached in a `LazyLock` static for efficient, repeated lookups.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use anyhow::Context;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use walkdir::WalkDir;

/// The lazily-initialized, thread-safe cache of library paths.
/// The closure inside is executed only once, the first time this static is accessed.
static LIBRARY_CACHE: LazyLock<HashMap<String, PathBuf>> = LazyLock::new(|| {
    let mut all_search_paths = Vec::new();

    // --- Primary Method: Use vswhere and vcvarsall.bat ---
    // This is the most accurate way to get all MSVC and SDK paths.
    match get_vc_lib_paths() {
        Ok(paths) => all_search_paths.extend(paths),
        Err(e) => {
            eprintln!("Warning: Failed to get VC lib paths: {:?}", e);
        }
    };

    // --- Fallback Method: Manually scan the Windows Kits directory ---
    // This is a great backup if vswhere fails or the installation is unusual.
    match get_manual_sdk_paths() {
        Ok(paths) => all_search_paths.extend(paths),
        Err(e) => {
            eprintln!("Warning: Failed to get manual SDK paths: {:?}", e);
        }
    };

    // Remove duplicate search paths to avoid scanning the same directory twice.
    all_search_paths.sort();
    all_search_paths.dedup();

    // --- Populate the cache by scanning all discovered directories ---
    let cache = all_search_paths
        .into_par_iter()
        .fold(
            || HashMap::new(),
            |mut acc, search_dir| {
                for entry in WalkDir::new(search_dir)
                    .into_iter()
                    .filter_map(Result::ok)
                    .filter(|e| {
                        e.file_type().is_file() && {
                            if let Some(name) = e.file_name().to_str() {
                                name.ends_with(".lib") || name.ends_with(".Lib")
                            } else {
                                false
                            }
                        }
                    })
                {
                    let path = entry.into_path();
                    let file_name = path.file_name().unwrap().to_str().unwrap().to_lowercase();
                    acc.insert(file_name, path);
                }

                acc
            },
        )
        .reduce_with(|mut acc, map| {
            acc.extend(map);
            acc
        })
        .unwrap_or_default();

    cache
});

// --- Public API ---

/// Finds the absolute path for a given library filename.
///
/// The first time this function is called, it will use `vswhere` and other
/// methods to discover all relevant MSVC and Windows SDK library directories,
/// scan them, and build a static, in-memory cache. All subsequent calls are
/// fast, case-insensitive lookups.
///
/// # Returns
/// An `Option` containing a static reference to the absolute `Path`.
pub fn find_lib(lib_name: &str) -> Option<&'static Path> {
    LIBRARY_CACHE
        .get(&lib_name.to_lowercase())
        .map(|p| p.as_path())
}

// --- Private Helper Functions ---

/// Gets library search paths by running `vcvarsall.bat` from a VS installation.
fn get_vc_lib_paths() -> anyhow::Result<Vec<PathBuf>> {
    let vcvars_path = vs_path()?
        .join("VC")
        .join("Auxiliary")
        .join("Build")
        .join("vcvarsall.bat");

    if !vcvars_path.exists() {
        anyhow::bail!(
            "vcvarsall.bat not found at expected path: {}",
            vcvars_path.display()
        );
    }

    // The trick: run the batch script, and then immediately run the `set` command
    // in the same command prompt process. This prints all environment variables.
    let output = Command::new("cmd")
        .arg("/C")
        .arg(&vcvars_path)
        .arg("x64")
        .arg("&&")
        .arg("set")
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to run vcvarsall.bat {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let env_output = String::from_utf8(output.stdout)?;

    for line in env_output.lines() {
        if line.starts_with("LIB=") {
            let lib_line = &line[4..];
            return Ok(env::split_paths(lib_line).collect());
        }
    }
    anyhow::bail!("LIB environment variable not found after running vcvarsall.bat");
}

fn vs_where() -> Command {
    Command::new("C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe")
}
/// Finds the Visual Studio installation path using a hardcoded `vswhere` path.
fn vs_path() -> anyhow::Result<PathBuf> {
    let output = vs_where()
        .args(&[
            "-latest",
            "-property",
            "installationPath",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
        ])
        .output()?;

    let path = String::from_utf8_lossy(&output.stdout);
    let path = path
        .lines()
        .next()
        .context("Failed to find VS installation path")?
        .trim();
    Ok(PathBuf::from(path))
}

/// Gets SDK search paths by manually scanning the `Windows Kits` directory.
fn get_manual_sdk_paths() -> anyhow::Result<Vec<PathBuf>> {
    let prog_files =
        env::var("ProgramFiles(x86)").context("Failed to get ProgramFiles(x86) path")?;
    let sdk_lib_path = PathBuf::from(prog_files).join("Windows Kits/10/Lib");

    let latest_version = fs::read_dir(&sdk_lib_path)
        .context("Failed to read SDK lib directory")?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .max()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No SDK version directories found in {}",
                sdk_lib_path.display()
            )
        })?; // max() on PathBufs works lexicographically.

    Ok(vec![
        latest_version.join("um/x64"),   // User-Mode libraries
        latest_version.join("ucrt/x64"), // Universal C Runtime
    ])
}

#[test]
fn find_kernel32() {
    let lib = "kernel32.lib";
    match find_lib(lib) {
        Some(path) => println!("Found {} at {}", lib, path.display()),
        None => println!("{} not found", lib),
    }
}
