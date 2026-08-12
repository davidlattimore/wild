//! Integration tests that run LLD's ELF test suite with Wild as the linker.
//! Tests are vendored from llvm-project/lld/test/ELF/.
//!
//! Requires system LLVM tools: llvm-mc, FileCheck, split-file.
//! These are available on distributions like Arch Linux.

use crate::Result;
use libtest_mimic::Failed;
use libtest_mimic::Trial;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

const PREFIX: &str = "external_test_suites/lld";

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
            let name = format!("{PREFIX}/test/ELF/{file_name}");
            tests.push(Trial::test(name, move || {
                run_lld_test(&path).map_err(|e| Failed::from(e.to_string()))
            }));
        }
    }
    Ok(())
}

fn run_lld_test(test_file: &Path) -> Result {
    // Check if required LLVM tools are available
    let llvm_mc = find_tool("llvm-mc")?;
    let filecheck = find_tool("FileCheck")?;

    let content = std::fs::read_to_string(test_file)?;
    let tmpdir = tempfile::tempdir()?;

    // Extract and execute RUN: lines
    for line in content.lines() {
        let Some(cmd) = line
            .trim()
            .strip_prefix("// RUN:")
            .or_else(|| line.trim().strip_prefix("# RUN:"))
        else {
            continue;
        };

        let cmd = substitute_vars(cmd.trim(), test_file, tmpdir.path());
        let cmd = substitute_tools(&cmd, &llvm_mc, &filecheck);

        execute_command(&cmd)?;
    }
    Ok(())
}

fn substitute_vars(cmd: &str, test_file: &Path, tmpdir: &Path) -> String {
    cmd.replace("%s", &test_file.display().to_string())
        .replace("%t", &tmpdir.join("test").display().to_string())
        .replace("%p", &test_file.parent().unwrap().display().to_string())
}

fn substitute_tools(cmd: &str, llvm_mc: &str, filecheck: &str) -> String {
    let wild = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("wild");

    cmd.replace("llvm-mc", llvm_mc)
        .replace("FileCheck", filecheck)
        .replace("ld.lld", &format!("{} -m elf_x86_64", wild.display()))
}

fn find_tool(name: &str) -> Result<String> {
    if let Ok(path) = which::which(name) {
        return Ok(path.display().to_string());
    }
    Err(format!("Required tool '{name}' not found. Install LLVM tools.").into())
}

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
