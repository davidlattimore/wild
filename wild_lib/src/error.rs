pub(crate) use anyhow::Error;

pub type Result<T = (), E = Error> = core::result::Result<T, E>;
