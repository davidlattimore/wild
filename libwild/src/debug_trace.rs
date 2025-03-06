//! Sets up a tracing layer for debugging the linker.

use crate::error::AlreadyInitialised;

/// All trace messages within a span with this name will be emitted.
pub(crate) const TRACE_SPAN_NAME: &str = "trace_file";

pub(crate) fn init() -> Result<(), AlreadyInitialised> {
    use tracing_subscriber::prelude::*;

    let filter = tracing_subscriber::filter::DynFilterFn::new(|metadata, cx| {
        if metadata.is_span() && metadata.name() == TRACE_SPAN_NAME {
            return true;
        }
        let mut current = cx.lookup_current();
        while let Some(span) = current {
            if span.name() == TRACE_SPAN_NAME {
                return true;
            }
            current = span.parent();
        }
        false
    });

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(filter))
        .try_init()
        .map_err(|_| AlreadyInitialised)
}
