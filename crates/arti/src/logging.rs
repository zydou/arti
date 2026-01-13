//! Configure tracing subscribers for Arti

use anyhow::{Context, Result, anyhow};
use derive_builder::Builder;
use fs_mistrust::Mistrust;
use serde::{Deserialize, Serialize};
use std::io::IsTerminal as _;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use tor_basic_utils::PathExt as _;
use tor_config::ConfigBuildError;
use tor_config::impl_standard_builder;
use tor_config::{define_list_builder_accessors, define_list_builder_helper};
use tor_config_path::{CfgPath, CfgPathResolver};
use tor_error::warn_report;
use tracing::{Subscriber, error};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{Layer, filter::Targets, fmt, registry};

mod fields;
#[cfg(feature = "opentelemetry")]
mod otlp_file_exporter;
mod time;

/// Structure to hold our logging configuration options
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[non_exhaustive] // TODO(nickm) remove public elements when I revise this.
#[builder(build_fn(private, name = "build_unvalidated", error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct LoggingConfig {
    /// Filtering directives that determine tracing levels as described at
    /// <https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/targets/struct.Targets.html#impl-FromStr>
    ///
    /// You can override this setting with the -l, --log-level command line parameter.
    ///
    /// Example: "info,tor_proto::channel=trace"
    #[builder(default = "default_console_filter()", setter(into, strip_option))]
    console: Option<String>,

    /// Filtering directives for the journald logger.
    ///
    /// Only takes effect if Arti is built with the `journald` filter.
    #[builder(
        setter(into),
        field(build = r#"tor_config::resolve_option(&self.journald, || None)"#)
    )]
    journald: Option<String>,

    /// Configuration for logging spans with OpenTelemetry.
    #[cfg(feature = "opentelemetry")]
    #[builder_field_attr(serde(default))]
    #[builder(default)]
    opentelemetry: OpentelemetryConfig,

    /// Configuration for opentelemetry (disabled)
    //
    // (See comments on crate::cfg::ArtiConfig::rpc for an explanation of this pattern.)
    #[cfg(not(feature = "opentelemetry"))]
    #[builder_field_attr(serde(default))]
    #[builder(field(type = "Option<toml::Value>", build = "()"), private)]
    opentelemetry: (),

    /// Configuration for passing information to tokio-console.
    #[cfg(feature = "tokio-console")]
    #[builder(sub_builder(fn_name = "build"))]
    #[builder_field_attr(serde(default))]
    tokio_console: TokioConsoleConfig,

    /// Configuration for tokio-console (disabled)
    //
    // (See comments on crate::cfg::ArtiConfig::rpc for an explanation of this pattern.)
    #[cfg(not(feature = "tokio-console"))]
    #[builder_field_attr(serde(default))]
    #[builder(field(type = "Option<toml::Value>", build = "()"), private)]
    tokio_console: (),

    /// Configuration for one or more logfiles.
    ///
    /// The default is not to log to any files.
    #[builder_field_attr(serde(default))]
    #[builder(sub_builder(fn_name = "build"), setter(custom))]
    files: LogfileListConfig,

    /// If set to true, we disable safe logging on _all logs_, and store
    /// potentially sensitive information at level `info` or higher.
    ///
    /// This can be useful for debugging, but it increases the value of your
    /// logs to an attacker.  Do not turn this on in production unless you have
    /// a good log rotation mechanism.
    //
    // TODO: Eventually we might want to make this more complex, and add a
    // per-log mechanism to turn off unsafe logging. Alternatively, we might do
    // that by extending the filter syntax implemented by `tracing` to have an
    // "unsafe" flag on particular lines.
    #[builder_field_attr(serde(default))]
    #[builder(default)]
    log_sensitive_information: bool,

    /// An approximate granularity with which log times should be displayed.
    ///
    /// This value controls every log time that arti outputs; it doesn't have any
    /// effect on times written by other logging programs like `journald`.
    ///
    /// We may round this value up for convenience: For example, if you say
    /// "2.5s", we may treat it as if you had said "3s."
    ///
    /// The default is "1s", or one second.
    #[builder(default = "std::time::Duration::new(1,0)")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    time_granularity: std::time::Duration,
}
impl_standard_builder! { LoggingConfig }

impl LoggingConfigBuilder {
    /// Build the [`LoggingConfig`].
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) fn build(&self) -> Result<LoggingConfig, ConfigBuildError> {
        let config = self.build_unvalidated()?;

        #[cfg(not(feature = "tokio-console"))]
        if self.tokio_console.is_some() {
            tracing::warn!(
                "tokio-console options were set, but Arti was built without support for tokio-console."
            );
        }

        #[cfg(not(feature = "opentelemetry"))]
        if self.opentelemetry.is_some() {
            tracing::warn!(
                "opentelemetry options were set, but Arti was built without support for opentelemetry."
            );
        }

        Ok(config)
    }
}

/// Return a default tracing filter value for `logging.console`.
#[allow(clippy::unnecessary_wraps)]
fn default_console_filter() -> Option<String> {
    Some("info".to_owned())
}

/// Local type alias, mostly helpful for derive_builder to DTRT
type LogfileListConfig = Vec<LogfileConfig>;

define_list_builder_helper! {
    struct LogfileListConfigBuilder {
        files: [LogfileConfigBuilder],
    }
    built: LogfileListConfig = files;
    default = vec![];
}

define_list_builder_accessors! {
    struct LoggingConfigBuilder {
        pub files: [LogfileConfigBuilder],
    }
}

/// Configuration information for an (optionally rotating) logfile.
#[derive(Debug, Builder, Clone, Eq, PartialEq)]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder(build_fn(error = "ConfigBuildError"))]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct LogfileConfig {
    /// How often to rotate the file?
    #[builder(default)]
    rotate: LogRotation,
    /// Where to write the files?
    path: CfgPath,
    /// Filter to apply before writing
    filter: String,
}

impl_standard_builder! { LogfileConfig: !Default }

/// How often to rotate a log file
#[derive(Debug, Default, Clone, Serialize, Deserialize, Copy, Eq, PartialEq)]
#[non_exhaustive]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) enum LogRotation {
    /// Rotate logs daily
    Daily,
    /// Rotate logs hourly
    Hourly,
    /// Never rotate the log
    #[default]
    Never,
}

/// Configuration for exporting spans with OpenTelemetry.
#[derive(Debug, Builder, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder(build_fn(error = "ConfigBuildError"))]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct OpentelemetryConfig {
    /// Write spans to a file in OTLP JSON format.
    #[builder(default)]
    file: Option<OpentelemetryFileExporterConfig>,
    /// Export spans via HTTP.
    #[builder(default)]
    http: Option<OpentelemetryHttpExporterConfig>,
}
impl_standard_builder! { OpentelemetryConfig }

/// Configuration for the OpenTelemetry HTTP exporter.
#[derive(Debug, Builder, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder(build_fn(error = "ConfigBuildError"))]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct OpentelemetryHttpExporterConfig {
    /// HTTP(S) endpoint to send spans to.
    ///
    /// For Jaeger, this should be something like: `http://localhost:4318/v1/traces`
    endpoint: String,
    /// Configuration for how to batch exports.
    // TODO: If we can figure out the right macro invocations, this shouldn't need to be a Option.
    batch: Option<OpentelemetryBatchConfig>,
    /// Timeout for sending data.
    ///
    /// If this is set to [`None`], it will be left at the OpenTelemetry default, which is
    /// currently 10 seconds unless overrided with a environment variable.
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    timeout: Option<Duration>,
    // TODO: Once opentelemetry-otlp supports more than one protocol over HTTP, add a config option
    // to choose protocol here.
}
impl_standard_builder! { OpentelemetryHttpExporterConfig: !Default }

/// Configuration for the OpenTelemetry HTTP exporter.
#[derive(Debug, Builder, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder(build_fn(error = "ConfigBuildError"))]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct OpentelemetryFileExporterConfig {
    /// The path to write the JSON file to.
    path: CfgPath,
    /// Configuration for how to batch writes.
    // TODO: If we can figure out the right macro invocations, this shouldn't need to be a Option.
    batch: Option<OpentelemetryBatchConfig>,
}
impl_standard_builder! { OpentelemetryFileExporterConfig: !Default }

/// Configuration for the Opentelemetry batch exporting.
///
/// This is a copy of [`opentelemetry_sdk::trace::BatchConfig`].
#[derive(Debug, Builder, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder(build_fn(error = "ConfigBuildError"))]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct OpentelemetryBatchConfig {
    /// Maximum queue size. See [`opentelemetry_sdk::trace::BatchConfig::max_queue_size`].
    #[builder(default)]
    max_queue_size: Option<usize>,
    /// Maximum export batch size. See [`opentelemetry_sdk::trace::BatchConfig::max_export_batch_size`].
    #[builder(default)]
    max_export_batch_size: Option<usize>,
    /// Scheduled delay. See [`opentelemetry_sdk::trace::BatchConfig::scheduled_delay`].
    #[builder(default)]
    #[serde(with = "humantime_serde")]
    scheduled_delay: Option<Duration>,
}
impl_standard_builder! { OpentelemetryBatchConfig }

#[cfg(feature = "opentelemetry")]
impl From<OpentelemetryBatchConfig> for opentelemetry_sdk::trace::BatchConfig {
    fn from(config: OpentelemetryBatchConfig) -> opentelemetry_sdk::trace::BatchConfig {
        let batch_config = opentelemetry_sdk::trace::BatchConfigBuilder::default();

        let batch_config = if let Some(max_queue_size) = config.max_queue_size {
            batch_config.with_max_queue_size(max_queue_size)
        } else {
            batch_config
        };

        let batch_config = if let Some(max_export_batch_size) = config.max_export_batch_size {
            batch_config.with_max_export_batch_size(max_export_batch_size)
        } else {
            batch_config
        };

        let batch_config = if let Some(scheduled_delay) = config.scheduled_delay {
            batch_config.with_scheduled_delay(scheduled_delay)
        } else {
            batch_config
        };

        batch_config.build()
    }
}

/// Configuration for logging to the tokio console.
#[derive(Debug, Builder, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder(build_fn(error = "ConfigBuildError"))]
#[cfg(feature = "tokio-console")]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct TokioConsoleConfig {
    /// If true, the tokio console subscriber should be enabled.
    ///
    /// This requires that tokio (and hence arti) is built with `--cfg tokio_unstable`
    /// in RUSTFLAGS.
    #[builder(default)]
    enabled: bool,
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

/// Try to construct a tracing [`Layer`] for logging to stderr.
fn console_layer<S>(config: &LoggingConfig, cli: Option<&str>) -> Result<impl Layer<S> + use<S>>
where
    S: Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    let timer = time::new_formatter(config.time_granularity);
    let filter = cli
        .map(|s| filt_from_str_verbose(s, "--log-level command line parameter"))
        .or_else(|| filt_from_opt_str(&config.console, "logging.console").transpose())
        .unwrap_or_else(|| Ok(Targets::from_str("debug").expect("bad default")))?;
    let use_color = std::io::stderr().is_terminal();
    // We used to suppress safe-logging on the console, but we removed that
    // feature: we cannot be certain that the console really is volatile. Even
    // if isatty() returns true on the console, we can't be sure that the
    // terminal isn't saving backlog to disk or something like that.
    Ok(fmt::Layer::default()
        // we apply custom field formatting so that error fields are listed last
        .fmt_fields(fields::ErrorsLastFieldFormatter)
        .with_ansi(use_color)
        .with_timer(timer)
        .with_writer(std::io::stderr) // we make this explicit, to match with use_color.
        .with_filter(filter))
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

/// Try to construct a tracing [`Layer`] for exporting spans via OpenTelemetry.
///
/// This doesn't allow for filtering, since most of our spans are exported at the trace level
/// anyways, and filtering can easily be done when viewing the data.
#[cfg(feature = "opentelemetry")]
fn otel_layer<S>(config: &LoggingConfig, path_resolver: &CfgPathResolver) -> Result<impl Layer<S>>
where
    S: Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_otlp::WithExportConfig;

    if config.opentelemetry.file.is_some() && config.opentelemetry.http.is_some() {
        return Err(ConfigBuildError::Invalid {
            field: "logging.opentelemetry".into(),
            problem: "Only one OpenTelemetry exporter can be enabled at once.".into(),
        }
        .into());
    }

    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name("arti")
        .build();

    let span_processor = if let Some(otel_file_config) = &config.opentelemetry.file {
        let file = std::fs::File::options()
            .create(true)
            .append(true)
            .open(otel_file_config.path.path(path_resolver)?)?;

        let exporter = otlp_file_exporter::FileExporter::new(file, resource.clone());

        opentelemetry_sdk::trace::BatchSpanProcessor::builder(exporter)
            .with_batch_config(otel_file_config.batch.unwrap_or_default().into())
            .build()
    } else if let Some(otel_http_config) = &config.opentelemetry.http {
        if otel_http_config.endpoint.starts_with("http://")
            && !(otel_http_config.endpoint.starts_with("http://localhost")
                || otel_http_config.endpoint.starts_with("http://127.0.0.1"))
        {
            return Err(ConfigBuildError::Invalid {
                field: "logging.opentelemetry.http.endpoint".into(),
                problem: "OpenTelemetry endpoint is set to HTTP on a non-localhost address! For security reasons, this is not supported.".into(),
            }
            .into());
        }
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(otel_http_config.endpoint.clone());

        let exporter = if let Some(timeout) = otel_http_config.timeout {
            exporter.with_timeout(timeout)
        } else {
            exporter
        };

        let exporter = exporter.build()?;

        opentelemetry_sdk::trace::BatchSpanProcessor::builder(exporter)
            .with_batch_config(otel_http_config.batch.unwrap_or_default().into())
            .build()
    } else {
        return Ok(None);
    };

    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_span_processor(span_processor)
        .build();

    let tracer = tracer_provider.tracer("otel_file_tracer");

    Ok(Some(tracing_opentelemetry::layer().with_tracer(tracer)))
}

/// Try to construct a non-blocking tracing [`Layer`] for writing data to an
/// optionally rotating logfile.
///
/// On success, return that layer, along with a WorkerGuard that needs to be
/// dropped when the program exits, to flush buffered messages.
fn logfile_layer<S>(
    config: &LogfileConfig,
    granularity: std::time::Duration,
    mistrust: &Mistrust,
    path_resolver: &CfgPathResolver,
) -> Result<(impl Layer<S> + Send + Sync + Sized + use<S>, WorkerGuard)>
where
    S: Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span> + Send + Sync,
{
    use tracing_appender::{
        non_blocking,
        rolling::{RollingFileAppender, Rotation},
    };
    let timer = time::new_formatter(granularity);

    let filter = filt_from_str_verbose(&config.filter, "logging.files.filter")?;
    let rotation = match config.rotate {
        LogRotation::Daily => Rotation::DAILY,
        LogRotation::Hourly => Rotation::HOURLY,
        _ => Rotation::NEVER,
    };
    let path = config.path.path(path_resolver)?;

    let directory = match path.parent() {
        None => {
            return Err(anyhow!(
                "Logfile path \"{}\" did not have a parent directory",
                path.display_lossy()
            ));
        }
        Some(p) if p == Path::new("") => Path::new("."),
        Some(d) => d,
    };
    mistrust.make_directory(directory).with_context(|| {
        format!(
            "Unable to create parent directory for logfile \"{}\"",
            path.display_lossy()
        )
    })?;
    let fname = path
        .file_name()
        .ok_or_else(|| anyhow!("No path for log file"))
        .map(Path::new)?;

    let appender = RollingFileAppender::new(rotation, directory, fname);
    let (nonblocking, guard) = non_blocking(appender);
    let layer = fmt::layer()
        // we apply custom field formatting so that error fields are listed last
        .fmt_fields(fields::ErrorsLastFieldFormatter)
        .with_ansi(false)
        .with_writer(nonblocking)
        .with_timer(timer)
        .with_filter(filter);
    Ok((layer, guard))
}

/// Try to construct a tracing [`Layer`] for all of the configured logfiles.
///
/// On success, return that layer along with a list of [`WorkerGuard`]s that
/// need to be dropped when the program exits.
fn logfile_layers<S>(
    config: &LoggingConfig,
    mistrust: &Mistrust,
    path_resolver: &CfgPathResolver,
) -> Result<(impl Layer<S> + use<S>, Vec<WorkerGuard>)>
where
    S: Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span> + Send + Sync,
{
    let mut guards = Vec::new();
    if config.files.is_empty() {
        // As above, we have Option<Layer> implements Layer, so we can return
        // None in this case.
        return Ok((None, guards));
    }

    let (layer, guard) = logfile_layer(
        &config.files[0],
        config.time_granularity,
        mistrust,
        path_resolver,
    )?;
    guards.push(guard);

    // We have to use a dyn pointer here so we can build up linked list of
    // arbitrary depth.
    let mut layer: Box<dyn Layer<S> + Send + Sync + 'static> = Box::new(layer);

    for logfile in &config.files[1..] {
        let (new_layer, guard) =
            logfile_layer(logfile, config.time_granularity, mistrust, path_resolver)?;
        layer = Box::new(layer.and_then(new_layer));
        guards.push(guard);
    }

    Ok((Some(layer), guards))
}

/// Configure a panic handler to send everything to tracing, in addition to our
/// default panic behavior.
fn install_panic_handler() {
    // TODO library support: There's a library called `tracing-panic` that
    // provides a hook we could use instead, but that doesn't have backtrace
    // support.  We should consider using it if it gets backtrace support in the
    // future.  We should also keep an eye on `tracing` to see if it learns how
    // to do this for us.
    let default_handler = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // Note that if we were ever to _not_ call this handler,
        // we would want to abort on nested panics and !can_unwind cases.
        default_handler(panic_info);

        // This statement is copied from stdlib.
        let msg = match panic_info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match panic_info.payload().downcast_ref::<String>() {
                Some(s) => &s[..],
                None => "Box<dyn Any>",
            },
        };

        let backtrace = std::backtrace::Backtrace::force_capture();
        match panic_info.location() {
            Some(location) => error!("Panic at {}: {}\n{}", location, msg, backtrace),
            None => error!("Panic at ???: {}\n{}", msg, backtrace),
        };
    }));
}

/// Opaque structure that gets dropped when the program is shutting down,
/// after logs are no longer needed.  The `Drop` impl flushes buffered messages.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct LogGuards {
    /// The actual list of guards we're returning.
    #[allow(unused)]
    guards: Vec<WorkerGuard>,

    /// A safelog guard, for use if we have decided to disable safe logging.
    #[allow(unused)]
    safelog_guard: Option<safelog::Guard>,
}

/// Set up logging.
///
/// Note that the returned LogGuard must be dropped precisely when the program
/// quits; they're used to ensure that all the log messages are flushed.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental-api")))]
pub(crate) fn setup_logging(
    config: &LoggingConfig,
    mistrust: &Mistrust,
    path_resolver: &CfgPathResolver,
    cli: Option<&str>,
) -> Result<LogGuards> {
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

    #[cfg(feature = "opentelemetry")]
    let registry = registry.with(otel_layer(config, path_resolver)?);

    #[cfg(feature = "tokio-console")]
    let registry = {
        // Note 1: We can't enable console_subscriber unconditionally when the `tokio-console`
        // feature is enabled, since it panics unless tokio is built with  `--cfg tokio_unstable`,
        // but we want arti to work with --all-features without any special --cfg.
        //
        // Note 2: We have to use an `Option` here, since the type of the registry changes
        // with whatever you add to it.
        let tokio_layer = if config.tokio_console.enabled {
            Some(console_subscriber::spawn())
        } else {
            None
        };
        registry.with(tokio_layer)
    };

    let (layer, guards) = logfile_layers(config, mistrust, path_resolver)?;
    let registry = registry.with(layer);

    registry.init();

    let safelog_guard = if config.log_sensitive_information {
        match safelog::disable_safe_logging() {
            Ok(guard) => Some(guard),
            Err(e) => {
                // We don't need to propagate this error; it isn't the end of
                // the world if we were unable to disable safe logging.
                warn_report!(e, "Unable to disable safe logging");
                None
            }
        }
    } else {
        None
    };

    install_panic_handler();

    Ok(LogGuards {
        guards,
        safelog_guard,
    })
}
