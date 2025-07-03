use crate::Architecture;
use crate::Result;
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
use std::process::Command;
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

#[rstest]
fn exec_mold_tests(
    #[files("../external_test_suites/mold/test/*.sh")] mold_test: PathBuf,
) -> Result {
    let path = env::var("PATH")?;
    let current_dir = env::current_dir()?;
    let wild_dir = current_dir.parent().unwrap().join("fakes-debug");

    if should_skip_mold_test(&mold_test) {
        return Ok(());
    }

    let output = Command::new("bash")
        .current_dir("../fakes-debug")
        .arg("-c")
        .arg(format!("{} 2>&1", mold_test.display()))
        .env("PATH", format!("{wild_dir:?}:{path}"))
        .output()?;

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
    let file_name = path
        .file_name()
        .expect("Must be a valid filename")
        .to_str()
        .expect("Expected valid string name");

    if should_not_ignore_tests("mold") {
        return false;
    }

    if let Some(skip_list) = load_skip_tests_config() {
        if skip_list.contains(&file_name.to_string()) {
            return true;
        }
    }

    let Some(name) = file_name.strip_prefix("arch-") else {
        return false;
    };

    let current_arch = get_host_architecture();
    let cross_archs = get_wild_test_cross().unwrap_or_default();

    let Some(arch) = name
        .split('-')
        .next()
        .and_then(|arch_str| Architecture::from_str(arch_str).ok())
    else {
        return true;
    };

    current_arch != arch && !cross_archs.contains(&arch)
}
