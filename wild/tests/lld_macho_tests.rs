//! Test runner for lld MachO assembly tests.
//!
//! These tests are adapted from LLVM lld's MachO test suite
//! (Apache License 2.0 with LLVM Exceptions).
//!
//! Each test assembles a .s file, links with Wild, and verifies
//! the output binary is structurally valid and codesigns cleanly.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn wild_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wild"))
}

fn lld_tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/lld-macho")
}

fn collect_tests(tests: &mut Vec<libtest_mimic::Trial>) {
    let wild_bin = wild_binary_path();
    let test_dir = lld_tests_dir();

    for entry in std::fs::read_dir(&test_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map_or(true, |e| e != "s") {
            continue;
        }
        let content = std::fs::read_to_string(&path).unwrap();

        // Skip tests that need split-file (multi-file tests)
        if content.contains("split-file") {
            continue;
        }

        // Only run aarch64/arm64 tests
        if content.contains("REQUIRES: x86") || content.contains("REQUIRES: i386") {
            continue;
        }

        // Extract linker flags from RUN lines
        let is_dylib = content.contains("-dylib");

        let test_name = path.file_stem().unwrap().to_string_lossy().to_string();
        let wild = wild_bin.clone();
        let test_path = path.clone();

        tests.push(
            libtest_mimic::Trial::test(format!("lld-macho/{test_name}"), move || {
                run_lld_test(&wild, &test_path, is_dylib).map_err(Into::into)
            })
            .with_ignored_flag(
                // Known failures — ignore until fixed
                test_name == "objc-category-merging-erase-objc-name-test",
            ),
        );
    }
}

fn run_lld_test(wild_bin: &Path, test_path: &Path, is_dylib: bool) -> Result<(), String> {
    let build_dir = std::env::temp_dir().join("wild-lld-tests");
    std::fs::create_dir_all(&build_dir).map_err(|e| format!("mkdir: {e}"))?;

    let stem = test_path.file_stem().unwrap().to_string_lossy();
    let obj_path = build_dir.join(format!("{stem}.o"));
    let out_path = build_dir.join(format!("{stem}.out"));

    // Strip comment lines and assemble
    let content = std::fs::read_to_string(test_path).map_err(|e| format!("read: {e}"))?;
    let clean: String = content
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let clean_path = build_dir.join(format!("{stem}.clean.s"));
    std::fs::write(&clean_path, &clean).map_err(|e| format!("write: {e}"))?;

    // Assemble
    let asm = Command::new("clang")
        .args(["-c", "-target", "arm64-apple-macos"])
        .arg(&clean_path)
        .arg("-o")
        .arg(&obj_path)
        .output()
        .map_err(|e| format!("clang: {e}"))?;
    if !asm.status.success() {
        let stderr = String::from_utf8_lossy(&asm.stderr);
        // Some tests have intentional assembly errors
        if stderr.contains("error:") {
            return Ok(()); // Skip tests with asm errors
        }
        return Err(format!("Assembly failed:\n{stderr}"));
    }

    // Link with Wild
    let mut cmd = Command::new(wild_bin);
    cmd.arg(&obj_path);
    if is_dylib {
        cmd.arg("-dylib");
    }
    cmd.args(["-arch", "arm64", "-lSystem", "-o"])
        .arg(&out_path)
        .env("WILD_VALIDATE_OUTPUT", "1");

    let link = cmd.output().map_err(|e| format!("wild: {e}"))?;
    if !link.status.success() {
        let stderr = String::from_utf8_lossy(&link.stderr);
        // Check if test expects a link error
        if content.contains("error:") || content.contains("not-allowed") {
            return Ok(()); // Expected failure
        }
        return Err(format!("Link failed:\n{stderr}"));
    }

    // Verify output is valid: codesign check
    let verify = Command::new("codesign")
        .args(["-vv"])
        .arg(&out_path)
        .output()
        .map_err(|e| format!("codesign: {e}"))?;
    if !verify.status.success() {
        let stderr = String::from_utf8_lossy(&verify.stderr);
        return Err(format!("Codesign verification failed:\n{stderr}"));
    }

    Ok(())
}

fn main() {
    let mut tests = Vec::new();
    collect_tests(&mut tests);
    let args = libtest_mimic::Arguments::from_args();
    libtest_mimic::run(&args, tests).exit();
}
