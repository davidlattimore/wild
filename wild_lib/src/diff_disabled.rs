use crate::error::Result;
use anyhow::bail;

pub(crate) fn maybe_diff() -> Result {
    if std::env::var(crate::args::REFERENCE_LINKER_ENV).is_ok() {
        bail!(
            "{} is set, but the linker-diff feature isn't enabled",
            crate::args::REFERENCE_LINKER_ENV
        );
    }
    Ok(())
}
