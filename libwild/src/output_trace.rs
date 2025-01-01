//! Sets up a tracing layer for recording diagnostics associated with particular addresses in the
//! output file.

use crate::args::Args;
use crate::error::Result;
use linker_trace::AddressTrace;
use std::fmt::Write as _;
use std::mem::take;
use std::ops::DerefMut;
use std::path::PathBuf;
use std::sync::Mutex;

pub(crate) fn init(args: &Args) {
    use tracing_subscriber::prelude::*;

    let trace_path = linker_trace::trace_path(&args.output);
    let layer = OutputTraceLayer {
        trace_path,
        data: Default::default(),
    };
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();
}

struct OutputTraceLayer {
    trace_path: PathBuf,
    data: Mutex<linker_trace::TraceData>,
}

#[derive(Default)]
struct Data {
    address: Option<u64>,
    messages: Mutex<Vec<String>>,
}

impl tracing::field::Visit for Data {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "address" {
            self.address = Some(value);
        }
    }

    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}
}

impl<S> tracing_subscriber::Layer<S> for OutputTraceLayer
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<S>,
    ) {
        let span = ctx.span(id).expect("valid span ID");

        let mut data = Data::default();
        attributes.values().record(&mut data);

        span.extensions_mut().insert(data);
    }

    fn on_close(&self, id: tracing::span::Id, ctx: tracing_subscriber::layer::Context<S>) {
        let span = ctx.span(&id).expect("valid span ID");
        let extensions = span.extensions();
        let Some(data) = extensions.get::<Data>() else {
            return;
        };
        let Some(address) = data.address else { return };
        let trace = AddressTrace {
            address,
            messages: take(data.messages.lock().unwrap().deref_mut()),
        };
        self.data.lock().unwrap().traces.push(trace);
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        let Some(span) = ctx.event_span(event) else {
            return;
        };
        let extensions = span.extensions();
        let Some(data) = extensions.get::<Data>() else {
            return;
        };
        let mut formatter = MessageFormatter::default();
        event.record(&mut formatter);
        if formatter.output_is_complete {
            if let Err(error) = self.flush() {
                eprintln!(
                    "Failed to write trace to `{}`: {error}",
                    self.trace_path.display()
                );
            }
            return;
        }
        data.messages.lock().unwrap().push(formatter.out);
    }
}

#[derive(Default)]
struct MessageFormatter {
    out: String,
    output_is_complete: bool,
}

impl tracing::field::Visit for MessageFormatter {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if !self.out.is_empty() {
            self.out.push(' ');
        }
        let _ = write!(&mut self.out, "{field}={value:?}");
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        if field.name() == "output_write_complete" && value {
            self.output_is_complete = true;
        } else {
            self.record_debug(field, &value);
        }
    }
}

impl OutputTraceLayer {
    fn flush(&self) -> Result {
        let mut file = std::io::BufWriter::new(std::fs::File::create(&self.trace_path)?);
        let data = take(self.data.lock().unwrap().deref_mut());
        data.write(&mut file)?;
        Ok(())
    }
}
