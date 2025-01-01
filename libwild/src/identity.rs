/// Returns a null-terminated string that identifies this linker. This is written into the .comment
/// section which usually also contains the versions of compilers that were used.
pub(crate) fn linker_identity() -> String {
    format!("Linker: Wild version {}\0", env!("CARGO_PKG_VERSION"))
}
