use crate::Architecture;
use crate::Result;
use crate::get_host_architecture;
use crate::get_wild_test_cross;
use rstest::rstest;
use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

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
    if !path.exists() || path.extension() != Some(std::ffi::OsStr::new("sh")) {
        return true;
    }

    let file_name = match path.file_name().and_then(|os_str| os_str.to_str()) {
        Some(name) => name,
        None => return true,
    };

    if !file_name.starts_with("arch-") {
        return false;
    }

    let test_arch = file_name["arch-".len()..]
        .split('-')
        .next()
        .unwrap_or_default();

    let current_arch = get_host_architecture();
    let cross_archs = get_wild_test_cross().unwrap_or_default();
    match test_arch {
        "x86_64" => {
            current_arch != Architecture::X86_64 && !cross_archs.contains(&Architecture::X86_64)
        }
        "aarch64" => {
            current_arch != Architecture::AArch64 && !cross_archs.contains(&Architecture::AArch64)
        }
        "riscv64" => {
            current_arch != Architecture::RISCV64 && !cross_archs.contains(&Architecture::RISCV64)
        }
        _ => true,
    }
}
