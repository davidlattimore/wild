use std::env::VarError;

/// Reads an environment variable.
///
/// zkVM currently returns an empty string instead of an error for missing environment variables.
/// See <https://github.com/succinctlabs/sp1/issues/2883>.
pub(crate) fn get_env(key: &str) -> Result<String, VarError> {
    let value = std::env::var(key)?;
    if cfg!(target_os = "zkvm") && value.is_empty() {
        Err(VarError::NotPresent)
    } else {
        Ok(value)
    }
}
