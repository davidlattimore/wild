pub(crate) use anyhow::Error;

pub type Result<T = (), E = Error> = core::result::Result<T, E>;

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
#[macro_export]
macro_rules! warning {
    ($($args:tt)*) => {
        println!($($args)*);
    };
}
