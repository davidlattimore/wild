pub(crate) use anyhow::Error;

pub(crate) type Result<T = (), E = Error> = core::result::Result<T, E>;
