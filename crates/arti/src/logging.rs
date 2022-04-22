//! Configure tracing subscribers for Arti

use anyhow::{anyhow, Context, Result};
use derive_builder::Builder;
use serde::Deserialize;
use std::path::Path;
use std::str::FromStr;
use tor_config::{CfgPath, ConfigBuildError};
use tracing::Subscriber;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{filter::Targets, fmt, registry, Layer};

/// Structure to hold our logging configuration options
#[derive(Deserialize, Debug, Clone, Builder, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive] // TODO(nickm) remove public elements when I revise this.
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Deserialize))]
pub struct LoggingConfig {
    /// Filtering directives that determine tracing levels as described at
    /// <https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/targets/struct.Targets.html#impl-FromStr>
    ///
    /// You can override this setting with the -l, --log-level command line parameter.
    ///
    /// Example: "info,tor_proto::channel=trace"
    #[serde(default = "default_console_filter")]
    #[builder(default = "default_console_filter()", setter(into, strip_option))]
    console: Option<String>,

    /// Filtering directives for the journald logger.
    ///
    /// Only takes effect if Arti is built with the `journald` filter.
    #[serde(default)]
    #[builder(default, setter(into, strip_option))]
    journald: Option<String>,

    /// Configuration for one or more logfiles.
    #[serde(default)]
    #[builder_field_attr(serde(default))]
    #[builder(sub_builder)]
    files: LogfileListConfig,
}

/// Return a default tracing filter value for `logging.console`.
#[allow(clippy::unnecessary_wraps)]
fn default_console_filter() -> Option<String> {
    Some("debug".to_owned())
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self::builder().build().expect("Default builder failed")
    }
}

impl LoggingConfig {
    /// Return a new LoggingConfigBuilder
    pub fn builder() -> LoggingConfigBuilder {
        LoggingConfigBuilder::default()
    }
}

/// Local type alias, mostly helpful for derive_builder to DTRT
type LogfileListConfig = Vec<LogfileConfig>;

#[derive(Default, Clone, Deserialize)]
#[serde(transparent)]
/// List of logfiles to use, being built as part of the configuration
pub struct LogfileListConfigBuilder {
    /// The logfiles, as overridden
    files: Option<Vec<LogfileConfigBuilder>>,
}

impl LogfileListConfigBuilder {
    /// Add a file logger
    pub fn append(&mut self, file: LogfileConfigBuilder) -> &mut Self {
        self.files
            .get_or_insert_with(Self::default_files)
            .push(file);
        self
    }

    /// Set the list of file loggers to the supplied `files`
    pub fn set(&mut self, files: impl IntoIterator<Item = LogfileConfigBuilder>) -> &mut Self {
        self.files = Some(files.into_iter().collect());
        self
    }

    /// Default logfiles
    ///
    /// (Currently) there are no defauolt logfiles.
    pub(crate) fn default_files() -> Vec<LogfileConfigBuilder> {
        vec![]
    }

    /// Resolve `LoggingConfigBuilder.files` to a value for `LoggingConfig.files`
    pub(crate) fn build(&self) -> Result<Vec<LogfileConfig>, ConfigBuildError> {
        let default_buffer;
        let files = match &self.files {
            Some(files) => files,
            None => {
                default_buffer = Self::default_files();
                &default_buffer
            }
        };
        let files = files
            .iter()
            .map(|item| item.build())
            .collect::<Result<_, _>>()
            .map_err(|e| e.within("files"))?;
        Ok(files)
    }
}

/// Configuration information for an (optionally rotating) logfile.
#[derive(Deserialize, Debug, Builder, Clone, Eq, PartialEq)]
#[builder(derive(Deserialize))]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct LogfileConfig {
    /// How often to rotate the file?
    #[serde(default)]
    #[builder(default)]
    rotate: LogRotation,
    /// Where to write the files?
    path: CfgPath,
    /// Filter to apply before writing
    filter: String,
}

/// How often to rotate a log file
#[derive(Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
#[serde(rename_all = "lowercase")]
pub enum LogRotation {
    /// Rotate logs daily
    Daily,
    /// Rotate logs hourly
    Hourly,
    /// Never rotate the log
    Never,
}

impl Default for LogRotation {
    fn default() -> Self {
        Self::Never
    }
}

impl LogfileConfig {
    /// Return a new [`LogfileConfigBuilder`]
    pub fn builder() -> LogfileConfigBuilder {
        LogfileConfigBuilder::default()
    }
}

/// As [`Targets::from_str`], but wrapped in an [`anyhow::Result`].
//
// (Note that we have to use `Targets`, not `EnvFilter`: see comment in
// `setup_logging()`.)
fn filt_from_str_verbose(s: &str, source: &str) -> Result<Targets> {
    Targets::from_str(s).with_context(|| format!("in {}", source))
}

/// As filt_from_str_verbose, but treat an absent filter (or an empty string) as
/// None.
fn filt_from_opt_str(s: &Option<String>, source: &str) -> Result<Option<Targets>> {
    Ok(match s {
        Some(s) if !s.is_empty() => Some(filt_from_str_verbose(s, source)?),
        _ => None,
    })
}

/// Try to construct a tracing [`Layer`] for logging to stdout.
fn console_layer<S>(config: &LoggingConfig, cli: Option<&str>) -> Result<impl Layer<S>>
where
    S: Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    let filter = cli
        .map(|s| filt_from_str_verbose(s, "--log-level command line parameter"))
        .or_else(|| filt_from_opt_str(&config.console, "logging.console").transpose())
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
    if let Some(filter) = filt_from_opt_str(&config.journald, "logging.journald")? {
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

    let filter = filt_from_str_verbose(&config.filter, "logging.files.filter")?;
    let rotation = match config.rotate {
        LogRotation::Daily => Rotation::DAILY,
        LogRotation::Hourly => Rotation::HOURLY,
        _ => Rotation::NEVER,
    };
    let path = config.path.path()?;
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
    if config.files.is_empty() {
        // As above, we have Option<Layer> implements Layer, so we can return
        // None in this case.
        return Ok((None, guards));
    }

    let (layer, guard) = logfile_layer(&config.files[0])?;
    guards.push(guard);

    // We have to use a dyn pointer here so we can build up linked list of
    // arbitrary depth.
    let mut layer: Box<dyn Layer<S> + Send + Sync + 'static> = Box::new(layer);

    for logfile in &config.files[1..] {
        let (new_layer, guard) = logfile_layer(logfile)?;
        layer = Box::new(layer.and_then(new_layer));
        guards.push(guard);
    }

    Ok((Some(layer), guards))
}

/// Opaque structure that gets dropped when the program is shutting down,
/// after logs are no longer needed.  The `Drop` impl flushes buffered messages.
pub struct LogGuards {
    /// The actual list of guards we're returning.
    #[allow(unused)]
    guards: Vec<WorkerGuard>,
}

/// Set up logging.
///
/// Note that the returned LogGuard must be dropped precisely when the program
/// quits; they're used to ensure that all the log messages are flushed.
pub fn setup_logging(config: &LoggingConfig, cli: Option<&str>) -> Result<LogGuards> {
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
