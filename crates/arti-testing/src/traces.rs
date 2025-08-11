//! Code to count the traces at different severities.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tracing::Subscriber;
use tracing_subscriber::Layer;

/// Count of the number of tracing events of each severity.
#[derive(Default)]
pub(crate) struct TraceCount {
    /// number of trace events
    trace: AtomicUsize,
    /// number of debug events
    debug: AtomicUsize,
    /// number of info events
    info: AtomicUsize,
    /// number of warn events
    warn: AtomicUsize,
    /// number of error events
    error: AtomicUsize,
}

impl std::fmt::Display for TraceCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::sync::atomic::fence(Ordering::SeqCst);
        let trace = self.trace.load(Ordering::SeqCst);
        let debug = self.debug.load(Ordering::SeqCst);
        let info = self.info.load(Ordering::SeqCst);
        let warn = self.warn.load(Ordering::SeqCst);
        let error = self.error.load(Ordering::SeqCst);

        write!(
            f,
            "Trace: {}, Debug: {}, Info: {}, Warn: {}, Error: {}",
            trace, debug, info, warn, error
        )
    }
}

/// A log subscriber to count the number of events of each severity.
pub(crate) struct TraceCounter(pub(crate) Arc<TraceCount>);

impl<S: Subscriber> Layer<S> for TraceCounter {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        use tracing::Level;
        let var = match *event.metadata().level() {
            Level::TRACE => &self.0.trace,
            Level::DEBUG => &self.0.debug,
            Level::INFO => &self.0.info,
            Level::WARN => &self.0.warn,
            Level::ERROR => &self.0.error,
        };

        var.fetch_add(1, Ordering::Relaxed);
    }
}
