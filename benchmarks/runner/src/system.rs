use crate::Result;
use anyhow::bail;
use std::process::Command;

pub(crate) fn check_system_settings() -> Result {
    let Ok(output) = Command::new("cpupower")
        .args(["frequency-info", "-o", "proc"])
        .output()
    else {
        // If cpupower isn't installed, then don't worry about it. It's generally only installed on
        // systems where it's supported.
        return Ok(());
    };

    let output = String::from_utf8_lossy(&output.stdout);
    if !output.contains("performance") {
        bail!(
            "CPU isn't set to performance mode, please run:\n\
        sudo cpupower frequency-set --governor performance"
        );
    }

    Ok(())
}
