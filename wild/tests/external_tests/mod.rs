#[cfg(feature = "mold_tests")]
mod mold_tests;

use crate::Result;
use std::env;
use std::path::Path;
use std::process::Command;
use std::process::Output;

#[allow(unused)]
fn should_not_ignore_tests(external_test: &str) -> bool {
    let wild_ignore_skip: Option<Vec<String>> =
        std::env::var("WILD_IGNORE_SKIP").ok().map(|test_suites| {
            test_suites
                .split(',')
                .map(|suite| suite.trim().to_string())
                .filter(|suite| !suite.is_empty())
                .collect()
        });

    wild_ignore_skip.is_some_and(|tests| {
        tests.contains(&external_test.to_string()) || tests.contains(&"all".to_string())
    })
}

#[allow(unused)]
fn run_external_test(external_test: &Path, extra_env: &[(&str, &str)]) -> Result<Output> {
    let path = env::var("PATH")?;
    let current_dir = env::current_dir()?;
    let wild_dir = current_dir.parent().unwrap().join("fakes-debug");

    let mut command = Command::new("bash");
    command
        .current_dir("../fakes-debug")
        .arg("-c")
        .arg(format!("{} 2>&1", external_test.display()))
        .env("PATH", format!("{wild_dir:?}:{path}"));

    for (key, value) in extra_env {
        command.env(key, value);
    }

    command.output().map_err(Into::into)
}
