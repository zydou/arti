//! Handling for arti's configuration formats.

use derive_builder::Builder;
use serde::Deserialize;
use tor_config::{CfgPath, ConfigBuildError};

/// Default options to use for our configuration.
//
// TODO should this be in `arti::cfg` ?
pub const ARTI_DEFAULTS: &str = concat!(include_str!("./arti_defaults.toml"),);

/// Structure to hold our application configuration options
#[derive(Deserialize, Debug, Default, Clone, Builder, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Deserialize))]
pub struct ApplicationConfig {
    /// If true, we should watch our configuration files for changes, and reload
    /// our configuration when they change.
    ///
    /// Note that this feature may behave in unexpected ways if the path to the
    /// directory holding our configuration files changes its identity (because
    /// an intermediate symlink is changed, because the directory is removed and
    /// recreated, or for some other reason).
    #[serde(default)]
    #[builder(default)]
    watch_configuration: bool,
}

impl ApplicationConfig {
    /// Return true if we're configured to watch for configuration changes.
    pub fn watch_configuration(&self) -> bool {
        self.watch_configuration
    }
}

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
    #[builder(default)]
    file: Vec<LogfileConfig>,
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

    /// Return the configured journald filter, if one is present
    pub fn journald_filter(&self) -> Option<&str> {
        match self.journald {
            Some(ref s) if !s.is_empty() => Some(s.as_str()),
            _ => None,
        }
    }

    /// Return the configured stdout filter, if one is present
    pub fn console_filter(&self) -> Option<&str> {
        match self.console {
            Some(ref s) if !s.is_empty() => Some(s.as_str()),
            _ => None,
        }
    }

    /// Return a list of the configured log files
    pub fn logfiles(&self) -> &[LogfileConfig] {
        &self.file
    }
}

/// Configuration information for an (optionally rotating) logfile.
#[derive(Deserialize, Debug, Builder, Clone, Eq, PartialEq)]
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

    /// Return the configured rotation interval.
    pub fn rotate(&self) -> LogRotation {
        self.rotate
    }

    /// Return the configured path to the log file.
    pub fn path(&self) -> &CfgPath {
        &self.path
    }

    /// Return the configured filter.
    pub fn filter(&self) -> &str {
        &self.filter
    }
}

/// Configuration for one or more proxy listeners.
#[derive(Deserialize, Debug, Clone, Builder, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Deserialize))]
pub struct ProxyConfig {
    /// Port to listen on (at localhost) for incoming SOCKS
    /// connections.
    #[serde(default = "default_socks_port")]
    #[builder(default = "default_socks_port()")]
    socks_port: Option<u16>,
    /// Port to lisen on (at localhost) for incoming DNS connections.
    #[serde(default)]
    #[builder(default)]
    dns_port: Option<u16>,
}

/// Return the default value for `socks_port`
#[allow(clippy::unnecessary_wraps)]
fn default_socks_port() -> Option<u16> {
    Some(9150)
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self::builder().build().expect("Default builder failed")
    }
}

impl ProxyConfig {
    /// Return a new [`ProxyConfigBuilder`].
    pub fn builder() -> ProxyConfigBuilder {
        ProxyConfigBuilder::default()
    }

    /// Return the configured SOCKS port for this proxy configuration,
    /// if one is enabled.
    pub fn socks_port(&self) -> Option<u16> {
        self.socks_port
    }

    /// Return the configured DNS port for this proxy configuration,
    /// if one is enabled.
    pub fn dns_port(&self) -> Option<u16> {
        self.dns_port
    }
}
