//! A build script that writes `version.txt`. This will then be used by wild as the version written
//! into the .comment section and reported when the --version flag is used.
//!
//! The version will be the version from `Cargo.toml`, but only if there's a git tag with the same
//! name and we're building from that commit without other changes. Otherwise, our version will be
//! the git hash at which our changes, if any, diverge from origin/main.

use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("Needs OUT_DIR to be set");
    let out = Path::new(&out_dir).join("version.txt");
    let version = version_string();

    println!("cargo:rerun-if-changed=../.git/HEAD");

    if let Ok(existing) = std::fs::read_to_string(&out)
        && existing == version
    {
        return;
    }

    std::fs::write(&out, &version).expect("Failed to write version.txt");
}

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

fn version_string() -> String {
    if let Some(version) = get_version_tag().or_else(main_hash)
        && !has_changes_relative_to(&version)
    {
        return version;
    }

    if let Some(version) = main_hash() {
        if has_changes_relative_to(&version) {
            format!("{PKG_VERSION} {version}-modified")
        } else {
            version
        }
    } else {
        // Fallback for if we can't query git.
        format!("{PKG_VERSION} non-git-build")
    }
}

fn has_changes_relative_to(version_ref: &str) -> bool {
    Command::new("git")
        .arg("diff")
        .arg("--quiet")
        .arg(version_ref)
        .output()
        .map(|output| !output.status.success())
        .unwrap_or(true)
}

/// Returns the hash of the merge-point with origin/main.
fn main_hash() -> Option<String> {
    let output = Command::new("git")
        .arg("merge-base")
        .arg("HEAD")
        .arg("origin/main")
        .output()
        .ok()?;

    String::from_utf8(output.stdout)
        .ok()?
        .lines()
        .next()
        .map(|line| line.to_owned())
}

/// Returns the current version, but only if there's a corresponding tag at the current commit.
fn get_version_tag() -> Option<String> {
    let output = Command::new("git")
        .arg("tag")
        .arg("--points-at")
        .arg("HEAD")
        .output()
        .ok()?;
    let stdout = String::from_utf8(output.stdout).ok()?;
    if stdout.lines().any(|line| line == PKG_VERSION) {
        Some(PKG_VERSION.to_owned())
    } else {
        None
    }
}
