//! Configure tracing subscribers for Arti

use arti_config::LoggingConfig;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, registry, EnvFilter};

/// As [`EnvFilter::new`], but print a message if any directive in the
/// log is invalid.
fn filt_from_str_verbose(s: &str, source: &str) -> EnvFilter {
    match EnvFilter::try_new(s) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Problem in {}:", source);
            EnvFilter::new(s)
        }
    }
}

/// Set up logging
pub(crate) fn setup_logging(config: &LoggingConfig, cli: Option<&str>) {
    let env_filter =
        match cli.map(|s| filt_from_str_verbose(s, "--log-level command line parameter")) {
            Some(f) => f,
            None => filt_from_str_verbose(
                config.trace_filter.as_str(),
                "trace_filter configuration option",
            ),
        };

    let registry = registry().with(fmt::Layer::default()).with(env_filter);

    if config.journald {
        #[cfg(feature = "journald")]
        if let Ok(journald) = tracing_journald::layer() {
            registry.with(journald).init();
            return;
        }
        #[cfg(not(feature = "journald"))]
        tracing::warn!(
            "journald logging was selected, but arti was built without journald support."
        );
    }

    registry.init();
}
