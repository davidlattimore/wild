use crate::Architecture;
use crate::Result;
use crate::external_tests::external_linker_name;
use crate::external_tests::run_external_test;
use crate::external_tests::should_not_ignore_tests;
use crate::external_tests::using_third_party_linker;
use crate::get_host_architecture;
use crate::get_wild_test_cross;
use libtest_mimic::Failed;
use libtest_mimic::Trial;
use libwild::error::Context;
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

const PREFIX: &str = "external_test_suites/mold";

/// Run a mold test with mold-specific environment setup.
fn run_mold_test(mold_test: &Path) -> Result<Output> {
    // Mold tests use the `arch-` prefix to indicate architecture-specific tests.
    // If the test is architecture-specific (e.g., arch-riscv64-*.sh),
    // set the TRIPLE environment variable for cross-compilation
    let triple = if let Some(file_name) = mold_test.file_name().and_then(|n| n.to_str())
        && let Some(arch_str) = file_name.strip_prefix("arch-")
        && let Some(arch_name) = arch_str.split('-').next()
        && let Ok(arch) = Architecture::from_str(arch_name)
        && arch != get_host_architecture()
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

pub(crate) fn collect_tests(tests: &mut Vec<Trial>, filter: &crate::Filter) -> Result {
    if filter.excludes(PREFIX) {
        return Ok(());
    }

    let third_party = using_third_party_linker();
    let linker_name = external_linker_name();
    let test_dir_path = crate::base_dir().join("../external_test_suites/mold/test");
    let dir = std::fs::read_dir(&test_dir_path)
        .with_context(|| format!("Failed to read directory {}", test_dir_path.display()))?;

    for ent in dir {
        let ent = ent?;
        let path = ent.path();

        if path.extension().is_some_and(|ext| ext == "sh") {
            let file_name =
                String::from_utf8_lossy(path.file_name().unwrap().as_encoded_bytes()).to_string();

            let name = if third_party {
                format!("{PREFIX}[{linker_name}]/test/{file_name}")
            } else {
                format!("{PREFIX}/test/{file_name}")
            };

            if !should_skip_mold_test(&path) && !should_skip_by_local_config(&path) {
                tests.push(Trial::test(name, move || {
                    check_mold_tests_regression(path).map_err(|e| Failed::from(e.to_string()))
                }));
            } else if should_skip_mold_test_by_toml(&path)
                && !should_skip_mold_test_by_arch(&path)
                && !should_skip_by_local_config(&path)
            {
                tests.push(Trial::test(format!("{name}/expect_failure"), move || {
                    verify_skipped_mold_tests_still_fail(path)
                        .map_err(|e| Failed::from(e.to_string()))
                }));
            }
        }
    }
    Ok(())
}

fn check_mold_tests_regression(mold_test: PathBuf) -> Result {
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

fn verify_skipped_mold_tests_still_fail(mold_test: PathBuf) -> Result {
    let output = run_mold_test(&mold_test)?;
    if output.status.success() {
        let linker = external_linker_name();
        let message = if using_third_party_linker() {
            format!(
                "Test `{}` is in the skip list (fails with wild) but passes with '{linker}'. This indicates the failure may be wild-specific.",
                mold_test.display()
            )
        } else {
            format!(
                "Test `{}` is in skip list but now passes. Should be removed from skip list.",
                mold_test.display()
            )
        };
        return Err(message.into());
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

/// Returns whether the user's test-config.toml says to skip a particular test. If this returns
/// true, then we skip both the positive and negative versions of the test.
fn should_skip_by_local_config(path: &Path) -> bool {
    if let Ok(config) = crate::read_test_config()
        && let Some(name) = path.file_name().and_then(|name| name.to_str())
        && config.ignore_external_tests.iter().any(|n| n == name)
    {
        true
    } else {
        false
    }
}

// Some mold tests have names starting with `arch-`, indicating the target architecture they run on.
// Therefore, we have to implement a similar filter for the wild tests as well.
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
