use git_version::git_version;

/// Returns a null-terminated string that identifies this linker. This is written into the .comment
/// section which usually also contains the versions of compilers that were used.
pub(crate) fn linker_identity() -> String {
    let mut git_hash = git_version!(
        args = ["--abbrev=40", "--always", "--dirty=-modified"],
        fallback = ""
    )
    .to_string();
    if !git_hash.is_empty() {
        git_hash = format!("({git_hash}) ");
    }
    format!(
        "Wild version {} {}(compatible with GNU linkers)",
        env!("CARGO_PKG_VERSION"),
        git_hash
    )
}
