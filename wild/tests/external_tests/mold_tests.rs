use crate::Architecture;
use crate::Result;
use crate::external_tests::run_external_test;
use crate::external_tests::should_not_ignore_tests;
use crate::get_host_architecture;
use crate::get_wild_test_cross;
use rstest::rstest;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Output;
use std::str::FromStr;
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

/// Run a mold test with mold-specific environment setup.
fn run_mold_test(mold_test: &Path) -> Result<Output> {
    // Mold tests use the `arch-` prefix to indicate architecture-specific tests.
    // If the test is architecture-specific (e.g., arch-riscv64-*.sh),
    // set the TRIPLE environment variable for cross-compilation
    let triple = if let Some(file_name) = mold_test.file_name().and_then(|n| n.to_str())
        && let Some(arch_str) = file_name.strip_prefix("arch-")
        && let Some(arch_name) = arch_str.split('-').next()
        && let Ok(arch) = Architecture::from_str(arch_name)
    {
        Some(format!("{}-linux-gnu", arch))
    } else {
        None
    };

    let env_vars: Vec<(&str, &str)> = if let Some(ref triple_value) = triple {
        vec![("TRIPLE", triple_value.as_str())]
    } else {
        vec![]
    };

    run_external_test(mold_test, &env_vars)
}

#[rstest]
fn check_mold_tests_regression(
    #[files("../external_test_suites/mold/test/*.sh")] mold_test: PathBuf,
) -> Result {
    if should_skip_mold_test(&mold_test) {
        return Ok(());
    }

    let output = run_mold_test(&mold_test)?;
    if !output.status.success() {
        let error_message = format!(
            "Mold test `{}` failed with status: {}\nOutput:\n{}",
            mold_test.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout)
        );
        return Err(error_message.into());
    }

    Ok(())
}

#[rstest]
fn verify_skipped_mold_tests_still_fail(
    #[files("../external_test_suites/mold/test/*.sh")] mold_test: PathBuf,
) -> Result {
    if !should_skip_mold_test_by_toml(&mold_test) || should_skip_mold_test_by_arch(&mold_test) {
        return Ok(());
    }

    let output = run_mold_test(&mold_test)?;
    if output.status.success() {
        return Err(format!(
            "Test `{}` is in skip list but now passes. Should be removed from skip list.",
            mold_test.display()
        )
        .into());
    }

    Ok(())
}

fn load_skip_tests_config() -> &'static Option<Vec<String>> {
    SKIP_TESTS_NAME.get_or_init(|| {
        let skip_tests_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("external_tests")
            .join("mold_skip_tests.toml");

        fs::read_to_string(&skip_tests_path)
            .map(|content| {
                let config: Config =
                    toml::from_str(&content).expect("Failed to parse skip_tests.toml");

                config
                    .skipped_groups
                    .into_iter()
                    .flat_map(|(_, group)| group.tests)
                    .collect()
            })
            .ok()
    })
}

fn should_skip_mold_test(path: &Path) -> bool {
    should_skip_mold_test_by_toml(path) || should_skip_mold_test_by_arch(path)
}

fn should_skip_mold_test_by_toml(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .expect("Must be a valid filename")
        .to_str()
        .expect("Expected valid string name");

    if should_not_ignore_tests("mold") {
        return false;
    }

    if let Some(skip_list) = load_skip_tests_config()
        && skip_list.contains(&file_name.to_string())
    {
        return true;
    }

    false
}

// Some mold tests have names starting with `arch-`, indicating the target architecture they run on. Therefore, we have to implement a similar filter for the wild tests as well.
fn should_skip_mold_test_by_arch(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .expect("Must be a valid filename")
        .to_str()
        .expect("Expected valid string name");

    let Some(name) = file_name.strip_prefix("arch-") else {
        return false;
    };

    let current_arch = get_host_architecture();
    let cross_archs = get_wild_test_cross().unwrap().unwrap_or_default();

    let Some(arch) = name
        .split('-')
        .next()
        .and_then(|arch_str| Architecture::from_str(arch_str).ok())
    else {
        return true;
    };

    current_arch != arch && !cross_archs.contains(&arch)
}
