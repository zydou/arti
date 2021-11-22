//! Handling for arti's configuration formats.

use arti_client::config::{
    dir::{DownloadScheduleConfig, NetworkConfig},
    StorageConfig, TorClientConfig, TorClientConfigBuilder,
};
use derive_builder::Builder;
use serde::Deserialize;
use std::collections::HashMap;
use tor_config::ConfigBuildError;

/// Default options to use for our configuration.
pub(crate) const ARTI_DEFAULTS: &str = concat!(include_str!("./arti_defaults.toml"),);

/// Structure to hold our logging configuration options
#[derive(Deserialize, Debug, Clone, Builder, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive] // TODO(nickm) remove public elements when I revise this.
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct LoggingConfig {
    /// Filtering directives that determine tracing levels as described at
    /// <https://docs.rs/tracing-subscriber/0.2.20/tracing_subscriber/filter/struct.EnvFilter.html>
    ///
    /// You can override this setting with the -l, --log-level command line parameter.
    ///
    /// Example: "info,tor_proto::channel=trace"
    // TODO(nickm) remove public elements when I revise this.
    #[serde(default = "default_trace_filter")]
    #[builder(default = "default_trace_filter()")]
    pub trace_filter: String,

    /// Whether to log to journald
    // TODO(nickm) remove public elements when I revise this.
    #[serde(default)]
    #[builder(default)]
    pub journald: bool,
}

/// Return a default value for `trace_filter`.
fn default_trace_filter() -> String {
    "debug".to_owned()
}

impl LoggingConfig {
    /// Return a new LoggingConfigBuilder
    pub fn builder() -> LoggingConfigBuilder {
        LoggingConfigBuilder::default()
    }
}

impl From<LoggingConfig> for LoggingConfigBuilder {
    fn from(cfg: LoggingConfig) -> LoggingConfigBuilder {
        let mut builder = LoggingConfigBuilder::default();
        builder
            .trace_filter(cfg.trace_filter)
            .journald(cfg.journald);
        builder
    }
}

/// Configuration for one or more proxy listeners.
#[derive(Deserialize, Debug, Clone, Builder, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct ProxyConfig {
    /// Port to listen on (at localhost) for incoming SOCKS
    /// connections.
    #[serde(default = "default_socks_port")]
    #[builder(default = "default_socks_port()")]
    socks_port: Option<u16>,
}

/// Return the default value for `socks_port`
#[allow(clippy::unnecessary_wraps)]
fn default_socks_port() -> Option<u16> {
    Some(9150)
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
}

impl From<ProxyConfig> for ProxyConfigBuilder {
    fn from(cfg: ProxyConfig) -> ProxyConfigBuilder {
        let mut builder = ProxyConfigBuilder::default();
        builder.socks_port(cfg.socks_port);
        builder
    }
}

/// Structure to hold Arti's configuration options, whether from a
/// configuration file or the command line.
//
/// These options are declared in a public crate outside of `arti` so
/// that other applications can parse and use them, if desired.  If
/// you're only embedding arti via `arti-client`, and you don't want
/// to use Arti's configuration format, use
/// [`arti_client::TorClientConfig`] instead.
///
/// NOTE: These are NOT the final options or their final layout.
/// Expect NO stability here.
#[derive(Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtiConfig {
    /// Configuration for proxy listeners
    proxy: ProxyConfig,

    /// Logging configuration
    logging: LoggingConfig,

    /// Information about the Tor network we want to connect to.
    #[serde(default)]
    tor_network: NetworkConfig,

    /// Directories for storing information on disk
    storage: StorageConfig,

    /// Information about when and how often to download directory information
    download_schedule: DownloadScheduleConfig,

    /// Facility to override network parameters from the values set in the
    /// consensus.
    #[serde(default)]
    override_net_params: HashMap<String, i32>,

    /// Information about how to build paths through the network.
    path_rules: arti_client::config::circ::PathConfig,

    /// Information about how to retry and expire circuits and request for circuits.
    circuit_timing: arti_client::config::circ::CircuitTiming,

    /// Rules about which addresses the client is willing to connect to.
    address_filter: arti_client::config::ClientAddrConfig,
}

impl From<ArtiConfig> for TorClientConfigBuilder {
    fn from(cfg: ArtiConfig) -> TorClientConfigBuilder {
        let mut builder = TorClientConfig::builder();
        let ArtiConfig {
            storage,
            address_filter,
            path_rules,
            circuit_timing,
            override_net_params,
            download_schedule,
            tor_network,
            ..
        } = cfg;
        *builder.storage() = storage.into();
        *builder.address_filter() = address_filter.into();
        *builder.path_rules() = path_rules.into();
        *builder.circuit_timing() = circuit_timing.into();
        *builder.override_net_params() = override_net_params;
        *builder.download_schedule() = download_schedule.into();
        *builder.tor_network() = tor_network.into();
        builder
    }
}

impl ArtiConfig {
    /// Construct a [`TorClientConfig`] based on this configuration.
    pub fn tor_client_config(&self) -> Result<TorClientConfig, ConfigBuildError> {
        let builder: TorClientConfigBuilder = self.clone().into();
        builder.build()
    }

    /// Return the [`LoggingConfig`] for this configuration.
    pub fn logging(&self) -> &LoggingConfig {
        &self.logging
    }

    /// Return the [`ProxyConfig`] for this configuration.
    pub fn proxy(&self) -> &ProxyConfig {
        &self.proxy
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn load_default_config() {
        // TODO: this is duplicate code.
        let mut cfg = config::Config::new();
        cfg.merge(config::File::from_str(
            ARTI_DEFAULTS,
            config::FileFormat::Toml,
        ))
        .unwrap();

        let _parsed: ArtiConfig = cfg.try_into().unwrap();
    }
}
