//! Configure tracing subscribers for Arti

use anyhow::{anyhow, Context, Result};
use arti_config::{LogRotation, LogfileConfig, LoggingConfig};
use std::path::Path;
use std::str::FromStr;
use tracing::Subscriber;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{filter::Targets, fmt, registry, Layer};

/// As [`Targets::from_str`], but wrapped in an [`anyhow::Result`].
//
// (Note that we have to use `Targets`, not `EnvFilter`: see comment in
// `setup_logging()`.)
fn filt_from_str_verbose(s: &str, source: &str) -> Result<Targets> {
    Targets::from_str(s).with_context(|| format!("in {}", source))
}

/// As filt_from_str_verbose, but treat an absent filter (or an empty string) as
/// None.
fn filt_from_opt_str(s: Option<&str>, source: &str) -> Result<Option<Targets>> {
    s.map(|s| filt_from_str_verbose(s, source)).transpose()
}

/// Try to construct a tracing [`Layer`] for logging to stdout.
fn console_layer<S>(config: &LoggingConfig, cli: Option<&str>) -> Result<impl Layer<S>>
where
    S: Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    let filter = cli
        .map(|s| filt_from_str_verbose(s, "--log-level command line parameter"))
        .or_else(|| filt_from_opt_str(config.console_filter(), "logging.console").transpose())
        .unwrap_or_else(|| Ok(Targets::from_str("debug").expect("bad default")))?;
    Ok(fmt::Layer::default().with_filter(filter))
}

/// Try to construct a tracing [`Layer`] for logging to journald, if one is
/// configured.
#[cfg(feature = "journald")]
fn journald_layer<S>(config: &LoggingConfig) -> Result<impl Layer<S>>
where
    S: Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    if let Some(filter) = filt_from_opt_str(config.journald_filter(), "logging.journald")? {
        Ok(Some(tracing_journald::layer()?.with_filter(filter)))
    } else {
        // Fortunately, Option<Layer> implements Layer, so we can just return None here.
        Ok(None)
    }
}

/// Try to construct a non-blocking tracing [`Layer`] for writing data to an
/// optionally rotating logfile.
///
/// On success, return that layer, along with a WorkerGuard that needs to be
/// dropped when the program exits, to flush buffered messages.
fn logfile_layer<S>(
    config: &LogfileConfig,
) -> Result<(impl Layer<S> + Send + Sync + Sized, WorkerGuard)>
where
    S: Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span> + Send + Sync,
{
    use tracing_appender::{
        non_blocking,
        rolling::{RollingFileAppender, Rotation},
    };

    let filter = filt_from_str_verbose(config.filter(), "logging.files.filter")?;
    let rotation = match config.rotate() {
        LogRotation::Daily => Rotation::DAILY,
        LogRotation::Hourly => Rotation::HOURLY,
        _ => Rotation::NEVER,
    };
    let path = config.path().path()?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let fname = path
        .file_name()
        .ok_or_else(|| anyhow!("No path for log file"))
        .map(Path::new)?;

    let appender = RollingFileAppender::new(rotation, directory, fname);
    let (nonblocking, guard) = non_blocking(appender);
    let layer = fmt::layer().with_writer(nonblocking).with_filter(filter);
    Ok((layer, guard))
}

/// Try to construct a tracing [`Layer`] for all of the configured logfiles.
///
/// On success, return that layer along with a list of [`WorkerGuard`]s that
/// need to be dropped when the program exits.
fn logfile_layers<S>(config: &LoggingConfig) -> Result<(impl Layer<S>, Vec<WorkerGuard>)>
where
    S: Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span> + Send + Sync,
{
    let mut guards = Vec::new();
    if config.logfiles().is_empty() {
        // As above, we have Option<Layer> implements Layer, so we can return
        // None in this case.
        return Ok((None, guards));
    }

    let (layer, guard) = logfile_layer(&config.logfiles()[0])?;
    guards.push(guard);

    // We have to use a dyn pointer here so we can build up linked list of
    // arbitrary depth.
    let mut layer: Box<dyn Layer<S> + Send + Sync + 'static> = Box::new(layer);

    for logfile in &config.logfiles()[1..] {
        let (new_layer, guard) = logfile_layer(logfile)?;
        layer = Box::new(layer.and_then(new_layer));
        guards.push(guard);
    }

    Ok((Some(layer), guards))
}

/// Opaque structure that gets dropped when the program is shutting down,
/// after logs are no longer needed.  The `Drop` impl flushes buffered messages.
pub(crate) struct LogGuards {
    /// The actual list of guards we're returning.
    #[allow(unused)]
    guards: Vec<WorkerGuard>,
}

/// Set up logging.
///
/// Note that the returned LogGuard must be dropped precisely when the program
/// quits; they're used to ensure that all the log messges are flushed.
pub(crate) fn setup_logging(config: &LoggingConfig, cli: Option<&str>) -> Result<LogGuards> {
    // Important: We have to make sure that the individual layers we add here
    // are not filters themselves.  That means, for example, that we can't add
    // an `EnvFilter` layer unless we want it to apply globally to _all_ layers.
    //
    // For a bit of discussion on the difference between per-layer filters and filters
    // that apply to the entire registry, see
    // https://docs.rs/tracing-subscriber/0.3.5/tracing_subscriber/layer/index.html#global-filtering

    let registry = registry().with(console_layer(config, cli)?);

    #[cfg(feature = "journald")]
    let registry = registry.with(journald_layer(config)?);

    let (layer, guards) = logfile_layers(config)?;
    let registry = registry.with(layer);

    registry.init();

    Ok(LogGuards { guards })
}
