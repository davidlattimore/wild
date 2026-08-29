//! Runs LLD's ELF test suite via lit with Wild substituted for ld.lld.
//! One test per architecture for granular reporting in cargo test output.

use crate::Result;
use crate::TestConfig;
use libtest_mimic::Failed;
use libtest_mimic::Trial;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
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

static SKIP_TESTS: OnceLock<Vec<String>> = OnceLock::new();

const PREFIX: &str = "external_test_suites/lld_lit";

const SUPPORTED_ARCHS: &[(&str, crate::Architecture)] = &[
    ("x86-64", crate::Architecture::X86_64),
    ("aarch64", crate::Architecture::AArch64),
];

pub(crate) fn collect_tests(
    tests: &mut Vec<Trial>,
    filter: &crate::Filter,
    test_config: &TestConfig,
) -> Result {
    let test_dir = crate::base_dir().join("../external_test_suites/lld/test");
    if !test_dir.exists() {
        return Ok(());
    }

    let lit_binary = find_lit_binary(test_config).ok_or_else(|| {
        format!(
            "lit not found in {} or PATH. Please install llvm tools.",
            test_config.llvm_tools_dir.display()
        )
    })?;

    for (arch, architecture) in SUPPORTED_ARCHS {
        if filter.excludes(&format!("{PREFIX}/{arch}")) {
            continue;
        }
        let arch = arch.to_string();
        let emulation = architecture.emulation_name().to_string();
        let test_config = test_config.clone();
        let test_dir = test_dir.clone();
        let lit_binary = lit_binary.clone();
        tests.push(Trial::test(format!("{PREFIX}/{arch}"), move || {
            run_lit_for_arch(&arch, &emulation, &test_dir, &test_config, &lit_binary)
                .map_err(|e| Failed::from(e.to_string()))
        }));
    }

    Ok(())
}

fn load_xfail_list() -> &'static Vec<String> {
    SKIP_TESTS.get_or_init(|| {
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
            .unwrap_or_default()
    })
}

fn find_lit_binary(test_config: &TestConfig) -> Option<PathBuf> {
    let lit = test_config.llvm_tools_dir.join("lit");
    if lit.exists() {
        return Some(lit);
    }
    which::which("lit").ok()
}

fn run_lit_for_arch(
    arch: &str,
    emulation: &str,
    test_dir: &Path,
    test_config: &TestConfig,
    lit_binary: &PathBuf,
) -> Result {
    let repo_root = crate::base_dir().join("..");
    let cfg_src = repo_root.join("wild/tests/external_tests/wild-lit.site.cfg.py");
    let lit_tmp = tempfile::tempdir()?;
    std::os::unix::fs::symlink(&cfg_src, lit_tmp.path().join("wild-lit.site.cfg.py"))?;
    std::os::unix::fs::symlink(test_dir.join("ELF"), lit_tmp.path().join("ELF"))?;

    let wild_bin = std::path::Path::new(env!("CARGO_BIN_EXE_wild"));
    let llvm_tools_dir = test_config.llvm_tools_dir.to_str().unwrap();

    // Create a fakes directory with all lld variant names pointing to Wild.
    // This is more robust than text substitution in the lit config.
    let fakes_dir = tempfile::tempdir()?;
    let script_contents = format!(
        "#!/bin/bash\nexec {} -m {} \"$@\"\n",
        wild_bin.display(),
        emulation
    );
    for linker_name in &["ld.lld", "lld-link", "ld64.lld", "wasm-ld"] {
        let script_path = fakes_dir.path().join(linker_name);
        std::fs::write(&script_path, &script_contents)?;
        libwild::make_executable(&std::fs::File::open(&script_path)?)?;
    }

    let tmpdir = tempfile::tempdir()?;

    let xfail_list: Vec<String> = load_xfail_list()
        .iter()
        .filter(|t| t.contains(arch))
        .map(|t| format!("lld :: ELF/{t}"))
        .collect();

    let mut cmd = Command::new(lit_binary);
    cmd.arg("--config-prefix")
        .arg("wild-lit.site")
        .arg(lit_tmp.path().join("ELF"))
        .arg(format!("--filter={arch}"))
        .env("WILD_BIN", wild_bin)
        .env("WILD_FAKES_DIR", fakes_dir.path())
        .env("LLVM_TOOLS_DIR", llvm_tools_dir)
        .env("LLD_OBJ_ROOT", tmpdir.path())
        .env("HOST_TRIPLE", "x86_64-unknown-linux-gnu")
        .env("TARGET_TRIPLE", arch)
        .env("WILD_EMULATION", emulation)
        .env("WILD_LIT_CFG", test_dir.join("lit.cfg.py"));

    if !xfail_list.is_empty() {
        cmd.arg("--xfail").arg(xfail_list.join(";"));
    }

    let output = cmd.output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    print!("{}", stdout);
    eprint!("{}", stderr);

    if !output.status.success() {
        return Err(format!("lit exited with status: {}", output.status).into());
    }

    if stdout.contains("Unexpectedly Passed") || stderr.contains("Unexpectedly Passed") {
        return Err("One or more tests unexpectedly passed. \
            Remove them from lld_skip_tests.toml."
            .into());
    }

    Ok(())
}
