use std::{fmt::Display, str::FromStr};

use crate::bail;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Os {
    Linux,
    Windows,
    MacOS,
}

impl Os {
    pub const DEFAULT: Self = const {
        #[cfg(target_os = "linux")]
        {
            Os::Linux
        }
        #[cfg(target_os = "windows")]
        {
            Os::Windows
        }
        #[cfg(target_os = "macos")]
        {
            Os::MacOS
        }
    };
}

impl Default for Os {
    fn default() -> Self {
        Os::DEFAULT
    }
}

impl FromStr for Os {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "linux" => Ok(Os::Linux),
            "windows" => Ok(Os::Windows),
            "macos" => Ok(Os::MacOS),
            _ => bail!("-m {s} is not yet supported"),
        }
    }
}

impl Display for Os {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let os = match self {
            Os::Linux => "linux",
            Os::Windows => "windows",
            Os::MacOS => "macos",
        };
        write!(f, "{os}")
    }
}
