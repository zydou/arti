//! Handling for arti's configuration formats.

use crate::CfgPath;
use arti_client::config::{
    circ::{CircMgrConfig, CircMgrConfigBuilder},
    dir::{DirMgrConfig, DirMgrConfigBuilder, DownloadScheduleConfig, NetworkConfig},
    ConfigBuildError, TorClientConfig,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Default options to use for our configuration.
pub(crate) const ARTI_DEFAULTS: &str = concat!(include_str!("./arti_defaults.toml"),);

/// Structure to hold our logging configuration options
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
#[non_exhaustive] // TODO(nickm) remove public elements when I revise this.
pub struct LoggingConfig {
    /// Filtering directives that determine tracing levels as described at
    /// <https://docs.rs/tracing-subscriber/0.2.20/tracing_subscriber/filter/struct.EnvFilter.html>
    ///
    /// You can override this setting with the -l, --log-level command line parameter.
    ///
    /// Example: "info,tor_proto::channel=trace"
    // TODO(nickm) remove public elements when I revise this.
    pub trace_filter: String,

    /// Whether to log to journald
    // TODO(nickm) remove public elements when I revise this.
    pub journald: bool,
}

/// Configuration for one or more proxy listeners.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Port to listen on (at localhost) for incoming SOCKS
    /// connections.
    socks_port: Option<u16>,
}

impl ProxyConfig {
    /// Return the configured SOCKS port for this proxy configuration,
    /// if one is enabled.
    pub fn socks_port(&self) -> Option<u16> {
        self.socks_port
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
#[derive(Deserialize, Debug, Clone)]
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

/// Configuration for where information should be stored on disk.
///
/// This section is for read/write storage.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Location on disk for cached directory information
    cache_dir: CfgPath,
    /// Location on disk for less-sensitive persistent state information.
    state_dir: CfgPath,
}

impl StorageConfig {
    /// Try to expand `state_dir` to be a path buffer.
    fn expand_state_dir(&self) -> Result<PathBuf, ConfigBuildError> {
        self.state_dir
            .path()
            .map_err(|e| ConfigBuildError::Invalid("state_dir".to_owned(), e.to_string()))
    }
    /// Try to expand `cache_dir` to be a path buffer.
    fn expand_cache_dir(&self) -> Result<PathBuf, ConfigBuildError> {
        self.state_dir
            .path()
            .map_err(|e| ConfigBuildError::Invalid("cache_dir".to_owned(), e.to_string()))
    }
}

impl ArtiConfig {
    /// Return a [`DirMgrConfig`] object based on the user's selected
    /// configuration.
    fn get_dir_config(&self) -> Result<DirMgrConfig, ConfigBuildError> {
        let mut dircfg = DirMgrConfigBuilder::default();
        dircfg.network_config(self.tor_network.clone());
        dircfg.schedule_config(self.download_schedule.clone());
        dircfg.cache_path(self.storage.expand_cache_dir()?);
        for (k, v) in self.override_net_params.iter() {
            dircfg.override_net_param(k.clone(), *v);
        }
        dircfg.build()
    }

    /// Return a [`CircMgrConfig`] object based on the user's selected
    /// configuration.
    fn get_circ_config(&self) -> Result<CircMgrConfig, ConfigBuildError> {
        let mut builder = CircMgrConfigBuilder::default();
        builder
            .path_rules(self.path_rules.clone())
            .circuit_timing(self.circuit_timing.clone())
            .build()
    }

    /// Construct a [`TorClientConfig`] based on this configuration.
    pub fn tor_client_config(&self) -> Result<TorClientConfig, ConfigBuildError> {
        let statecfg = self.storage.expand_state_dir()?;
        let dircfg = self.get_dir_config()?;
        let circcfg = self.get_circ_config()?;
        let addrcfg = self.address_filter.clone();

        TorClientConfig::builder()
            .state_cfg(statecfg)
            .dir_cfg(dircfg)
            .circ_cfg(circcfg)
            .addr_cfg(addrcfg)
            .build()
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
