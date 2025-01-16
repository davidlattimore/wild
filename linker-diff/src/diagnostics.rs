//! Provides mechanisms for helping diagnose problems in linker-diff. Specifically, a way to set up
//! tracing so that we can collect tracing logs within some scope and attach them to a diff report.
//!
//! To get tracing messages, make sure the code you want to trace from is called from somewhere
//! inside a call to `trace_scope`. Assuming it is, you can then call `tracing::trace!()` and see
//! the output in the diff report for whatever was being diffed.

use std::cell::RefCell;
use std::fmt::Write as _;
use tracing_subscriber::layer::SubscriberExt as _;

/// Enable diagnostics. Configures the global tracing subscriber, so cannot be used in conjunction
/// with other things that do that. For that reason, this should be called from the main binary.
pub fn enable_diagnostics() {
    let layer = TraceLayer;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    tracing::subscriber::set_global_default(subscriber)
        .expect("Only one global tracing subscriber can be setup");
}

#[derive(Default, Debug, Clone)]
pub(crate) struct TraceOutput {
    pub(crate) messages: Vec<String>,
}

thread_local! {
    pub static TRACE_STACK: RefCell<Vec<TraceOutput>> = const { RefCell::new(Vec::new()) };
}

/// Runs `f` then returns all trace output emitted while it was running.
pub(crate) fn trace_scope<T>(trace_output: &mut TraceOutput, f: impl FnOnce() -> T) -> T {
    TRACE_STACK.with_borrow_mut(|stack| stack.push(TraceOutput::default()));

    let result = f();

    *trace_output = TRACE_STACK.with_borrow_mut(|stack| stack.pop()).unwrap();

    result
}

struct TraceLayer;

impl<S> tracing_subscriber::Layer<S> for TraceLayer
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if TRACE_STACK.with_borrow(|stack| stack.is_empty()) {
            return;
        }

        let mut formatter = MessageFormatter::default();
        event.record(&mut formatter);

        TRACE_STACK.with_borrow_mut(|stack| {
            if let Some(out) = stack.last_mut() {
                out.messages.push(formatter.out);
            }
        });
    }
}

#[derive(Default)]
struct MessageFormatter {
    out: String,
}

impl tracing::field::Visit for MessageFormatter {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if !self.out.is_empty() {
            self.out.push(' ');
        }
        let _ = write!(&mut self.out, "{field}={value:?}");
    }
}
