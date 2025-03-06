pub(crate) use anyhow::Error;
use std::fmt::Display;

pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// An error indicating that we attempted to initialise global state that can only be initialised
/// once.
#[derive(Debug, Clone, Copy)]
pub struct AlreadyInitialised;

/// Like debug_assert, but bails instead of panicking.
///
/// Returning an error often allows us to give
/// more context as to what we were trying to do, e.g. which file / symbol we were processing,
/// whereas a panic just gives us a function backtrace, which is less useful.
#[macro_export]
macro_rules! debug_assert_bail {
    ($e:expr, $($rest:tt)*) => {
        if cfg!(debug_assertions) && !$e {
            anyhow::bail!($($rest)*);
        }
    };
}

/// Prints a warning. By using our own macro for this, it'll be easier to find places that issue
/// warnings if we want to say have a flag to suppress them.
pub(crate) fn warning(message: &str) {
    println!("WARNING: wild: {message}");
}

impl Display for AlreadyInitialised {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Attempted to initialise global state more than once")
    }
}

impl core::error::Error for AlreadyInitialised {}
