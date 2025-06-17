use colored::Colorize as _;
use std::fmt::Display;

pub type Result<T = (), E = Error> = core::result::Result<T, E>;

pub struct Error(Box<ErrorPayload>);

struct ErrorPayload {
    messages: Vec<String>,
}

#[macro_export]
macro_rules! bail {
    ($msg:literal $(,)?) => {
        return Err($crate::error!($msg))
    };
    ($fmt:expr, $(,)?) => {
        return Err($crate::error!($expr))
    };
    ($fmt:expr, $($args:tt)*) => {
        return Err($crate::error!($fmt, $($args)*))
    };
}

#[macro_export]
macro_rules! error {
    ($msg:literal $(,)?) => {
        $crate::error::Error::with_message(format!($msg))
    };
    ($fmt:expr, $(,)?) => {
        $crate::error::Error::with_message(format!($fmt))
    };
    ($fmt:expr, $($args:tt)*) => {
        $crate::error::Error::with_message(format!($fmt, $($args)*))
    };
}

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return Err($crate::error!($msg));
        }
    };
    ($cond:expr, $fmt:expr, $(,)?) => {
        if !$cond {
            return Err($crate::error!($expr));
        }
    };
    ($cond:expr, $fmt:expr, $($args:tt)*) => {
        if !$cond {
            return Err($crate::error!($fmt, $($args)*));
        }
    };
}

impl Error {
    pub fn with_message(msg: impl Into<String>) -> Self {
        Error(Box::new(ErrorPayload {
            messages: vec![msg.into()],
        }))
    }

    // We can't implement Display, since we implement From for things that are Display.
    #[allow(clippy::inherent_to_string)]
    #[must_use]
    pub fn to_string(&self) -> String {
        format!("{self:?}")
    }
}

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
            $crate::bail!($($rest)*);
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

impl<E> From<E> for Error
where
    E: std::fmt::Display,
{
    fn from(value: E) -> Self {
        Error::with_message(format!("{value}"))
    }
}

pub trait Context<T> {
    fn with_context(self, callback: impl FnOnce() -> String) -> Result<T>;
    fn context(self, message: impl Into<String>) -> Result<T>;
}

impl<T, E: Into<Error>> Context<T> for Result<T, E> {
    fn with_context(self, callback: impl FnOnce() -> String) -> Result<T> {
        match self {
            Ok(v) => Ok(v),
            Err(error) => {
                let mut error: Error = error.into();
                error.0.messages.push(callback());
                Err(error)
            }
        }
    }

    fn context(self, message: impl Into<String>) -> Result<T> {
        match self {
            Ok(v) => Ok(v),
            Err(error) => {
                let mut error: Error = error.into();
                error.0.messages.push(message.into());
                Err(error)
            }
        }
    }
}

impl<T> Context<T> for Option<T> {
    fn with_context(self, callback: impl FnOnce() -> String) -> Result<T> {
        match self {
            Some(v) => Ok(v),
            None => Err(Error::with_message(callback())),
        }
    }

    fn context(self, message: impl Into<String>) -> Result<T> {
        match self {
            Some(v) => Ok(v),
            None => Err(Error::with_message(message)),
        }
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.messages.len() == 1 {
            return write!(f, "{}", self.0.messages[0]);
        }

        let mut first = true;
        for message in self.0.messages.iter().rev() {
            if first {
                writeln!(f, "{message}")?;
                first = false;
                writeln!(f, "  Caused by:")?;
            } else {
                writeln!(f, "    {message}")?;
            }
        }
        Ok(())
    }
}

pub fn report_error(error: &Error) {
    eprintln!("wild: {}: {error:?}", "error".red());
}

pub fn report_error_and_exit(error: &Error) -> ! {
    report_error(error);
    std::process::exit(-1);
}
