use crate::Architecture;
use crate::Result;
use crate::get_host_architecture;
use crate::get_wild_test_cross;
use rstest::rstest;
use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

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

fn should_skip_mold_test(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .expect("Must be a valid filename")
        .to_str()
        .expect("Expected valid string name");

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
