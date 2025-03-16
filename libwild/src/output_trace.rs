//! Sets up a tracing layer for recording diagnostics associated with particular addresses in the
//! output file.

use crate::error::Result;
use linker_trace::AddressTrace;
use std::mem::take;
use std::ops::DerefMut;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;

pub(crate) struct TraceOutput {
    state: Option<State>,
}

struct State {
    trace_path: PathBuf,
    data: Mutex<linker_trace::TraceData>,
}

impl TraceOutput {
    pub(crate) fn new(should_write_trace: bool, base_output: &Path) -> Self {
        if !should_write_trace {
            return TraceOutput { state: None };
        }

        let trace_path = linker_trace::trace_path(base_output);

        TraceOutput {
            state: Some(State {
                trace_path,
                data: Default::default(),
            }),
        }
    }

    #[inline(always)]
    pub(crate) fn emit(&self, address: u64, message_cb: impl Fn() -> String) {
        if let Some(state) = self.state.as_ref() {
            let message = message_cb();
            state.data.lock().unwrap().traces.push(AddressTrace {
                address,
                messages: message.split('\n').map(|s| s.to_owned()).collect(),
            });
        }
    }

    pub(crate) fn close(&self) -> Result {
        if let Some(state) = self.state.as_ref() {
            let mut file = std::io::BufWriter::new(std::fs::File::create(&state.trace_path)?);
            let data = take(state.data.lock().unwrap().deref_mut());
            data.write(&mut file)?;
        }

        Ok(())
    }
}
