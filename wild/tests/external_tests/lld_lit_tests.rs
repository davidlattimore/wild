//! Runs LLD's ELF test suite via lit with Wild substituted for ld.lld.
//! One test per architecture for granular reporting in cargo test output.

use crate::Result;
use crate::TestConfig;
use libtest_mimic::Failed;
use libtest_mimic::Trial;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

const PREFIX: &str = "lld_lit";

pub(crate) fn collect_tests(
    tests: &mut Vec<Trial>,
    filter: &crate::Filter,
    test_config: &TestConfig,
) -> Result {
    let test_dir = crate::base_dir().join("../external_test_suites/lld/test");
    if !test_dir.exists() {
        return Ok(());
    }

    let Some(lit_binary) = find_lit_binary() else {
        return Ok(());
    };

    for (arch, _) in crate::external_tests::lld_tests::SUPPORTED_ARCHS {
        if filter.excludes(&format!("{PREFIX}/{arch}")) {
            continue;
        }
        let arch = arch.to_string();
        let test_config = test_config.clone();
        let test_dir = test_dir.clone();
        let lit_binary = lit_binary.clone();
        tests.push(Trial::test(format!("{PREFIX}/{arch}"), move || {
            run_lit_for_arch(&arch, &test_dir, &test_config, &lit_binary)
                .map_err(|e| Failed::from(e.to_string()))
        }));
    }

    Ok(())
}

fn find_lit_binary() -> Option<PathBuf> {
    // CI location
    let ci_path = PathBuf::from("/usr/lib/llvm-21/bin/lit");
    if ci_path.exists() {
        return Some(ci_path);
    }
    // Fall back to PATH
    which::which("lit").ok()
}

fn run_lit_for_arch(
    arch: &str,
    test_dir: &Path,
    test_config: &TestConfig,
    lit_binary: &PathBuf,
) -> Result {
    let repo_root = crate::base_dir().join("..");
    let cfg_src = repo_root.join("wild/tests/external_tests/wild-lit.site.cfg.py");
    let cfg_link = test_dir.join("wild-lit.site.cfg.py");

    // Create symlink so lit can find the config alongside lit.cfg.py.
    // Use a temp name + rename for atomic replacement to avoid race conditions
    // when multiple arch tests run concurrently.
    let tmp_link = test_dir.join(format!("wild-lit.site.cfg.py.tmp.{}", std::process::id()));
    std::os::unix::fs::symlink(&cfg_src, &tmp_link)?;
    std::fs::rename(&tmp_link, &cfg_link)?;

    let wild_bin = std::path::Path::new(env!("CARGO_BIN_EXE_wild"));

    let llvm_tools_dir = test_config.llvm_tools_dir.to_str().unwrap();

    let output = Command::new(lit_binary)
        .arg("--config-prefix")
        .arg("wild-lit.site")
        .arg("--ignore-fail")
        .arg(test_dir.join("ELF"))
        .arg(format!("--filter={arch}"))
        .env("WILD_BIN", wild_bin)
        .env("LLVM_TOOLS_DIR", llvm_tools_dir)
        .output()?;

    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));

    if !output.status.success() {
        return Err(format!("lit exited with status: {}", output.status).into());
    }

    Ok(())
}
