use anyhow::Context;
use anyhow::Result;
use linker_trace::TraceData;
use std::ops::Range;
use std::path::Path;

pub(crate) struct Trace {
    data: linker_trace::TraceData,
}

impl Trace {
    pub(crate) fn for_path(base_path: &Path) -> Result<Trace> {
        let trace_path = linker_trace::trace_path(base_path);
        if !trace_path.exists() {
            return Ok(Trace {
                data: Default::default(),
            });
        }
        let bytes = std::fs::read(&trace_path)
            .with_context(|| format!("Failed to read `{}`", trace_path.display()))?;
        let mut trace = Trace {
            data: TraceData::from_bytes(&bytes)?,
        };
        trace.data.traces.sort_by_key(|t| t.address);
        Ok(trace)
    }

    pub(crate) fn messages_in(&self, range: Range<u64>) -> Vec<&str> {
        let mut messages = Vec::new();
        let mut i = self
            .data
            .traces
            .binary_search_by_key(&range.start, |t| t.address)
            .unwrap_or_else(|v| v);
        while let Some(t) = self.data.traces.get(i) {
            if !range.contains(&t.address) {
                break;
            }
            messages.extend(t.messages.iter().map(String::as_str));
            i += 1;
        }
        messages
    }
}
