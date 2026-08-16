//! Integration tests that run LLD's ELF test suite with Wild as the linker.
//! Tests are vendored from llvm-project/lld/test/ELF/.
//!
//! Requires system LLVM tools: llvm-mc, FileCheck, split-file.
//! These are available on distributions like Arch Linux.

use crate::Result;
use libtest_mimic::Failed;
use libtest_mimic::Trial;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

#[derive(Deserialize)]
struct Config {
    skipped_groups: HashMap<String, SkippedGroup>,
}

#[derive(Deserialize)]
struct SkippedGroup {
    tests: Vec<String>,
}

static SKIP_TESTS_NAME: OnceLock<Option<Vec<String>>> = OnceLock::new();

const PREFIX: &str = "external_test_suites/lld";

/// Architecture prefixes used by LLD's test file naming convention
/// (e.g. `x86-64-pcrel.s`, `aarch64-abs16.s`).
const SUPPORTED_ARCHS: &[&str] = &["x86-64"];

pub(crate) fn collect_tests(tests: &mut Vec<Trial>, filter: &crate::Filter) -> Result {
    if filter.excludes(PREFIX) {
        return Ok(());
    }

    let test_dir = crate::base_dir().join("../external_test_suites/lld/test/ELF");
    if !test_dir.exists() {
        return Ok(());
    }
    let dir = std::fs::read_dir(&test_dir)?;
    for ent in dir {
        let ent = ent?;
        let path = ent.path();
        if path.extension().is_some_and(|ext| ext == "s") {
            let file_name =
                String::from_utf8_lossy(path.file_name().unwrap().as_encoded_bytes()).to_string();

            // Other architectures (aarch64, riscv64, ...) are left for a
            // follow-up PR.
            if !SUPPORTED_ARCHS
                .iter()
                .any(|arch| file_name.starts_with(&format!("{arch}-")))
            {
                continue;
            }

            let name = format!("{PREFIX}/test/ELF/{file_name}");

            if !should_skip_lld_test(&path) {
                tests.push(Trial::test(name, move || {
                    run_lld_test(&path).map_err(|e| Failed::from(e.to_string()))
                }));
            } else {
                tests.push(Trial::test(format!("{name}/expect_failure"), move || {
                    verify_skipped_lld_test_still_fails(&path)
                        .map_err(|e| Failed::from(e.to_string()))
                }));
            }
        }
    }
    Ok(())
}

fn verify_skipped_lld_test_still_fails(test_file: &Path) -> Result {
    if run_lld_test(test_file).is_ok() {
        return Err(format!(
            "Test `{}` is in the skip list but now passes. Should be removed from skip list.",
            test_file.display()
        )
        .into());
    }
    Ok(())
}

fn run_lld_test(test_file: &Path) -> Result {
    let llvm_mc = find_tool("llvm-mc")?;
    let filecheck = find_tool("FileCheck")?;
    let content = std::fs::read_to_string(test_file)?;
    let tmpdir = tempfile::tempdir()?;

    for cmd in extract_run_lines(&content) {
        let cmd = substitute_vars(&cmd, test_file, tmpdir.path());
        let cmd = substitute_tools(&cmd, &llvm_mc, &filecheck);
        execute_command(&cmd)?;
    }
    Ok(())
}

/// Extracts RUN: lines from the test file, joining lines that end in a
/// trailing `\` continuation character into a single logical command, per
/// the LLVM lit RUN line syntax:
/// https://llvm.org/docs/TestingGuide.html#run-lines
fn extract_run_lines(content: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut current: Option<String> = None;

    for line in content.lines() {
        let Some(rest) = line
            .trim()
            .strip_prefix("// RUN:")
            .or_else(|| line.trim().strip_prefix("# RUN:"))
        else {
            continue;
        };
        let rest = rest.trim();

        let (piece, continues) = match rest.strip_suffix('\\') {
            Some(stripped) => (stripped.trim_end(), true),
            None => (rest, false),
        };

        current = Some(match current.take() {
            Some(mut buf) => {
                buf.push(' ');
                buf.push_str(piece);
                buf
            }
            None => piece.to_string(),
        });

        if !continues {
            commands.push(current.take().unwrap());
        }
    }

    if let Some(buf) = current {
        commands.push(buf);
    }

    commands
}

fn substitute_vars(cmd: &str, test_file: &Path, tmpdir: &Path) -> String {
    let dir = test_file.parent().unwrap().display().to_string();
    cmd.replace("%s", &test_file.display().to_string())
        .replace("%t", &tmpdir.join("test").display().to_string())
        .replace("%S", &dir)
        .replace("%p", &dir)
}

fn substitute_tools(cmd: &str, llvm_mc: &str, filecheck: &str) -> String {
    const WILD: &str = env!("CARGO_BIN_EXE_wild");
    cmd.replace("llvm-mc", llvm_mc)
        .replace("FileCheck", filecheck)
        .replace("ld.lld", &format!("{WILD} -m elf_x86_64"))
}

fn find_tool(name: &str) -> Result<String> {
    if let Ok(path) = which::which(name) {
        return Ok(path.display().to_string());
    }
    Err(format!("Required tool '{name}' not found. Install LLVM tools.").into())
}

// TODO: This harness doesn't support the `split-file` tool or `cd %t`
// used by some LLVM tests to split one source file into several named
// sub-files in a temp directory. Supporting this would mean detecting
// `split-file %s %t` in a RUN line, invoking the real `split-file` tool,
// and tracking a working directory across subsequent RUN line executions
// (currently each command runs independently via `sh -c` with no
// persisted cwd). Tracked as follow-up work; affected tests are
// skip-listed under `split_file_unsupported` in lld_skip_tests.toml.
fn execute_command(cmd: &str) -> Result {
    let output = Command::new("sh").arg("-c").arg(cmd).output()?;
    if !output.status.success() {
        return Err(format!(
            "Command failed: {cmd}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
        .into());
    }
    Ok(())
}

fn load_skip_tests_config() -> &'static Option<Vec<String>> {
    SKIP_TESTS_NAME.get_or_init(|| {
        let skip_tests_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("external_tests")
            .join("lld_skip_tests.toml");

        fs::read_to_string(&skip_tests_path)
            .map(|content| {
                let config: Config =
                    toml::from_str(&content).expect("Failed to parse lld_skip_tests.toml");

                config
                    .skipped_groups
                    .into_values()
                    .flat_map(|group| group.tests)
                    .collect()
            })
            .ok()
    })
}

fn should_skip_lld_test(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .expect("Must be a valid filename")
        .to_str()
        .expect("Expected valid string name");

    if crate::external_tests::should_not_ignore_tests("lld") {
        return false;
    }

    load_skip_tests_config()
        .as_ref()
        .is_some_and(|skip_list| skip_list.contains(&file_name.to_string()))
}
