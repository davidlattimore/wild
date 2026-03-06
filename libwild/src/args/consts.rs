pub const WILD_UNSUPPORTED_ENV: &str = "WILD_UNSUPPORTED";
pub const VALIDATE_ENV: &str = "WILD_VALIDATE_OUTPUT";
pub const WRITE_LAYOUT_ENV: &str = "WILD_WRITE_LAYOUT";
pub const WRITE_TRACE_ENV: &str = "WILD_WRITE_TRACE";
pub const REFERENCE_LINKER_ENV: &str = "WILD_REFERENCE_LINKER";
pub(crate) const FILES_PER_GROUP_ENV: &str = "WILD_FILES_PER_GROUP";

/// Set this environment variable if you get a failure during writing due to too much or too little
/// space being allocated to some section. When set, each time we allocate during layout, we'll
/// check that what we're doing is consistent with writing and fail in a more easy to debug way. i.e
/// we'll report the particular combination of value flags, resolution flags etc that triggered the
/// inconsistency.
pub(crate) const WRITE_VERIFY_ALLOCATIONS_ENV: &str = "WILD_VERIFY_ALLOCATIONS";

// These flags don't currently affect our behaviour. TODO: Assess whether we should error or warn if
// these are given. This is tricky though. On the one hand we want to be a drop-in replacement for
// other linkers. On the other, we should perhaps somehow let the user know that we don't support a
// feature.
pub(super) const SILENTLY_IGNORED_FLAGS: &[&str] = &[
    // Just like other modern linkers, we don't need groups in order to resolve cycles.
    "start-group",
    "end-group",
    // TODO: This is supposed to suppress built-in search paths, but I don't think we have any
    // built-in search paths. Perhaps we should?
    "nostdlib",
    // TODO
    "no-undefined-version",
    "fatal-warnings",
    "color-diagnostics",
    "undefined-version",
    "sort-common",
    "stats",
];
pub(super) const SILENTLY_IGNORED_SHORT_FLAGS: &[&str] = &[
    "(",
    ")",
    // On Illumos, the Clang driver inserts a meaningless -C flag before calling any non-GNU ld
    // linker.
    #[cfg(target_os = "illumos")]
    "C",
];

pub(super) const IGNORED_FLAGS: &[&str] = &[
    "gdb-index",
    "fix-cortex-a53-835769",
    "fix-cortex-a53-843419",
    "discard-all",
    "use-android-relr-tags",
    "x", // alias for --discard-all
];

// These flags map to the default behavior of the linker.
pub(super) const DEFAULT_FLAGS: &[&str] = &[
    "no-call-graph-profile-sort",
    "no-copy-dt-needed-entries",
    "no-add-needed",
    "discard-locals",
    "no-fatal-warnings",
    "no-use-android-relr-tags",
];
pub(super) const DEFAULT_SHORT_FLAGS: &[&str] = &[
    "X",  // alias for --discard-locals
    "EL", // little endian
];
