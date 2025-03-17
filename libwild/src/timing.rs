//! Code for reporting how long each phase of linking takes when the --time argument is supplied.

use crate::error::AlreadyInitialised;
use std::fmt::Display;
use std::time::Instant;
use tracing::field::Visit;

#[derive(Default)]
struct TimingLayer {}

struct Data {
    start: Instant,
    child_count: u32,
    attributes_string: String,
}

#[derive(Default)]
pub struct ValuesFormatter {
    out: String,
}

impl ValuesFormatter {
    fn finish(mut self) -> String {
        if !self.out.is_empty() {
            self.out.push(']');
        }
        self.out
    }
}

impl Visit for ValuesFormatter {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;

        if self.out.is_empty() {
            write!(&mut self.out, " [").unwrap();
        } else {
            write!(&mut self.out, ", ").unwrap();
        }
        match field.name() {
            "message" => {
                write!(&mut self.out, "{value:?}").unwrap();
            }
            name => {
                write!(&mut self.out, "{name}={value:?}").unwrap();
            }
        }
    }
}

impl<S> tracing_subscriber::Layer<S> for TimingLayer
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::INFO)
    }

    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<S>,
    ) {
        if *attributes.metadata().level() > tracing::Level::INFO {
            return;
        }
        let span = ctx.span(id).expect("valid span ID");

        let mut formatted = ValuesFormatter::default();
        attributes.values().record(&mut formatted);

        span.extensions_mut().insert(Data {
            start: Instant::now(),
            child_count: 0,
            attributes_string: formatted.finish(),
        });
    }

    fn on_enter(&self, id: &tracing::span::Id, ctx: tracing_subscriber::layer::Context<S>) {
        let span = ctx.span(id).expect("valid span ID");
        if let Some(data) = span.extensions_mut().get_mut::<Data>() {
            data.start = Instant::now();
        }
    }

    fn on_close(&self, id: tracing::span::Id, ctx: tracing_subscriber::layer::Context<S>) {
        let span = ctx.span(&id).expect("valid span ID");
        let metadata = span.metadata();
        if *metadata.level() > tracing::Level::INFO {
            return;
        }

        let parent_child_count = span
            .parent()
            .and_then(|parent| {
                parent
                    .extensions_mut()
                    .get_mut::<Data>()
                    .map(|parent_data| {
                        parent_data.child_count += 1;
                        parent_data.child_count
                    })
            })
            .unwrap_or(0);

        if let Some(data) = span.extensions().get::<Data>() {
            let scope_depth = span.scope().count() - 1;
            let name = metadata.name();
            let ms = data.start.elapsed().as_secs_f64() * 1000.0;
            let indent = Indent {
                scope_depth,
                child_count: data.child_count,
                parent_child_count,
            };
            println!("{indent}{ms:>8.2} {name}{}", data.attributes_string);
        };
    }
}

pub(crate) fn init_tracing() -> Result<(), AlreadyInitialised> {
    use tracing_subscriber::prelude::*;
    let layer = TimingLayer::default();
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    tracing::subscriber::set_global_default(subscriber).map_err(|_| AlreadyInitialised)
}

struct Indent {
    scope_depth: usize,
    parent_child_count: u32,
    child_count: u32,
}

impl Display for Indent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.scope_depth == 0 {
            write!(f, "└─")?;
            return Ok(());
        }
        for _ in 0..self.scope_depth - 1 {
            write!(f, "│ ")?;
        }
        if self.parent_child_count >= 2 {
            write!(f, "├─")?;
        } else {
            write!(f, "┌─")?;
        }
        if self.child_count > 0 {
            write!(f, "┴─")?;
        } else {
            write!(f, "──")?;
        }
        Ok(())
    }
}
