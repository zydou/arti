//! Handling for arti's configuration formats.

use arti_client::config::{
    circ,
    dir::{self, DownloadScheduleConfig, NetworkConfig},
    ClientAddrConfig, ClientAddrConfigBuilder, ClientTimeoutConfig, ClientTimeoutConfigBuilder,
    StorageConfig, StorageConfigBuilder, TorClientConfig, TorClientConfigBuilder,
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
/// These options are declared in a public crate outside of `arti` so that other
/// applications can parse and use them, if desired.  If you're only embedding
/// arti via `arti-client`, and you don't want to use Arti's configuration
/// format, use [`arti_client::TorClientConfig`] instead.
///
/// By default, Arti will run using the default Tor network, store state and
/// cache information to a per-user set of directories shared by all
/// that user's applications, and run a SOCKS client on a local port.
///
/// NOTE: These are NOT the final options or their final layout. Expect NO
/// stability here.
#[derive(Deserialize, Debug, Clone, Eq, PartialEq, Default)]
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
    path_rules: circ::PathConfig,

    /// Information about preemptive circuits
    preemptive_circuits: circ::PreemptiveCircuitConfig,

    /// Information about how to retry and expire circuits and request for circuits.
    circuit_timing: circ::CircuitTiming,

    /// Rules about which addresses the client is willing to connect to.
    address_filter: ClientAddrConfig,

    /// Information about when to time out client requests.
    stream_timeouts: ClientTimeoutConfig,
}

impl From<ArtiConfig> for TorClientConfigBuilder {
    fn from(cfg: ArtiConfig) -> TorClientConfigBuilder {
        let mut builder = TorClientConfig::builder();
        let ArtiConfig {
            storage,
            address_filter,
            path_rules,
            preemptive_circuits,
            circuit_timing,
            override_net_params,
            download_schedule,
            tor_network,
            ..
        } = cfg;
        *builder.storage() = storage.into();
        *builder.address_filter() = address_filter.into();
        *builder.path_rules() = path_rules.into();
        *builder.preemptive_circuits() = preemptive_circuits.into();
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

    /// Return a new ArtiConfigBuilder.
    pub fn builder() -> ArtiConfigBuilder {
        ArtiConfigBuilder::default()
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

/// Builder object used to construct an ArtiConfig.
///
/// Most code won't need this, and should use [`TorClientConfigBuilder`] instead.
///
/// Unlike other builder types in Arti, this builder works by exposing an
/// inner builder for each section in the [`TorClientConfig`].
#[derive(Default, Clone)]
pub struct ArtiConfigBuilder {
    /// Builder for the proxy section.
    proxy: ProxyConfigBuilder,
    /// Builder for the logging section.
    logging: LoggingConfigBuilder,
    /// Builder for the storage section.
    storage: StorageConfigBuilder,
    /// Builder for the tor_network section.
    tor_network: dir::NetworkConfigBuilder,
    /// Builder for the download_schedule section.
    download_schedule: dir::DownloadScheduleConfigBuilder,
    /// In-progress object for the override_net_params section.
    override_net_params: HashMap<String, i32>,
    /// Builder for the path_rules section.
    path_rules: circ::PathConfigBuilder,
    /// Builder for the preemptive_circuits section.
    preemptive_circuits: circ::PreemptiveCircuitConfigBuilder,
    /// Builder for the circuit_timing section.
    circuit_timing: circ::CircuitTimingBuilder,
    /// Builder for the address_filter section.
    address_filter: ClientAddrConfigBuilder,
    /// Builder for the stream timeout rules.
    stream_timeouts: ClientTimeoutConfigBuilder,
}

impl ArtiConfigBuilder {
    /// Try to construct a new [`ArtiConfig`] from this builder.
    pub fn build(&self) -> Result<ArtiConfig, ConfigBuildError> {
        let proxy = self.proxy.build().map_err(|e| e.within("proxy"))?;
        let logging = self.logging.build().map_err(|e| e.within("logging"))?;
        let tor_network = self
            .tor_network
            .build()
            .map_err(|e| e.within("tor_network"))?;
        let storage = self.storage.build().map_err(|e| e.within("storage"))?;
        let download_schedule = self
            .download_schedule
            .build()
            .map_err(|e| e.within("download_schedule"))?;
        let override_net_params = self.override_net_params.clone();
        let path_rules = self
            .path_rules
            .build()
            .map_err(|e| e.within("path_rules"))?;
        let preemptive_circuits = self
            .preemptive_circuits
            .build()
            .map_err(|e| e.within("preemptive_circuits"))?;
        let circuit_timing = self
            .circuit_timing
            .build()
            .map_err(|e| e.within("circuit_timing"))?;
        let address_filter = self
            .address_filter
            .build()
            .map_err(|e| e.within("address_filter"))?;
        let stream_timeouts = self
            .stream_timeouts
            .build()
            .map_err(|e| e.within("stream_timeouts"))?;
        Ok(ArtiConfig {
            proxy,
            logging,
            tor_network,
            storage,
            download_schedule,
            override_net_params,
            path_rules,
            preemptive_circuits,
            circuit_timing,
            address_filter,
            stream_timeouts,
        })
    }

    /// Return a mutable reference to a [`ProxyConfig`] to use in
    /// configuring the Arti process.
    pub fn proxy(&mut self) -> &mut ProxyConfigBuilder {
        &mut self.proxy
    }

    /// Return a mutable reference to a
    /// [`LoggingConfigBuilder`]
    /// to use in configuring the Arti process.
    pub fn logging(&mut self) -> &mut LoggingConfigBuilder {
        &mut self.logging
    }

    /// Return a mutable reference to a
    /// [`NetworkConfigBuilder`](dir::NetworkConfigBuilder)
    /// to use in configuring the underlying Tor network.
    ///
    /// Most programs shouldn't need to alter this configuration: it's only for
    /// cases when you need to use a nonstandard set of Tor directory authorities
    /// and fallback caches.
    pub fn tor_network(&mut self) -> &mut dir::NetworkConfigBuilder {
        &mut self.tor_network
    }

    /// Return a mutable reference to a [`StorageConfigBuilder`].
    ///
    /// This section is used to configure the locations where Arti should
    /// store files on disk.
    pub fn storage(&mut self) -> &mut StorageConfigBuilder {
        &mut self.storage
    }

    /// Return a mutable reference to a
    /// [`DownloadScheduleConfigBuilder`](dir::DownloadScheduleConfigBuilder).
    ///
    /// This section is used to override Arti's schedule when attempting and
    /// retrying to download directory objects.
    pub fn download_schedule(&mut self) -> &mut dir::DownloadScheduleConfigBuilder {
        &mut self.download_schedule
    }

    /// Return a mutable reference to a [`HashMap`] of network parameters
    /// that should be used to override those specified in the consensus
    /// directory.
    ///
    /// This section should not usually be used for anything but testing:
    /// if you find yourself needing to configure an override here for
    /// production use, please consider opening a feature request for it
    /// instead.
    ///
    /// For a complete list of Tor's defined network parameters (not all of
    /// which are yet supported by Arti), see
    /// [`path-spec.txt`](https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/param-spec.txt).
    pub fn override_net_params(&mut self) -> &mut HashMap<String, i32> {
        &mut self.override_net_params
    }

    /// Return a mutable reference to a [`PathConfigBuilder`](circ::PathConfigBuilder).
    ///
    /// This section is used to override Arti's rules for selecting which
    /// relays should be used in a given circuit.
    pub fn path_rules(&mut self) -> &mut circ::PathConfigBuilder {
        &mut self.path_rules
    }

    /// Return a mutable reference to a [`PreemptiveCircuitConfigBuilder`](circ::PreemptiveCircuitConfigBuilder).
    ///
    /// This section overrides Arti's rules for preemptive circuits.
    pub fn preemptive_circuits(&mut self) -> &mut circ::PreemptiveCircuitConfigBuilder {
        &mut self.preemptive_circuits
    }

    /// Return a mutable reference to a [`CircuitTimingBuilder`](circ::CircuitTimingBuilder).
    ///
    /// This section overrides Arti's rules for deciding how long to use
    /// circuits, and when to give up on attempts to launch them.
    pub fn circuit_timing(&mut self) -> &mut circ::CircuitTimingBuilder {
        &mut self.circuit_timing
    }

    /// Return a mutable reference to a [`ClientAddrConfigBuilder`].
    ///
    /// This section controls which addresses Arti is willing to launch connections
    /// to over the Tor network.  Any addresses rejected by this section cause
    /// stream attempts to fail before any traffic is sent over the network.
    pub fn address_filter(&mut self) -> &mut ClientAddrConfigBuilder {
        &mut self.address_filter
    }

    /// Return a mutable reference to a [`ClientTimeoutConfigBuilder`].
    ///
    /// This section controls how Arti should handle an exit relay's DNS
    /// resolution.
    pub fn stream_timeouts(&mut self) -> &mut ClientTimeoutConfigBuilder {
        &mut self.stream_timeouts
    }
}

impl From<ArtiConfig> for ArtiConfigBuilder {
    fn from(cfg: ArtiConfig) -> ArtiConfigBuilder {
        ArtiConfigBuilder {
            proxy: cfg.proxy.into(),
            logging: cfg.logging.into(),
            storage: cfg.storage.into(),
            tor_network: cfg.tor_network.into(),
            download_schedule: cfg.download_schedule.into(),
            override_net_params: cfg.override_net_params,
            path_rules: cfg.path_rules.into(),
            preemptive_circuits: cfg.preemptive_circuits.into(),
            circuit_timing: cfg.circuit_timing.into(),
            address_filter: cfg.address_filter.into(),
            stream_timeouts: cfg.stream_timeouts.into(),
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use std::time::Duration;

    use super::*;

    #[test]
    fn default_config() {
        // TODO: this is duplicate code.
        let mut cfg = config::Config::new();
        cfg.merge(config::File::from_str(
            ARTI_DEFAULTS,
            config::FileFormat::Toml,
        ))
        .unwrap();

        let parsed: ArtiConfig = cfg.try_into().unwrap();
        let default = ArtiConfig::default();
        assert_eq!(&parsed, &default);

        // Make sure we can round-trip through the builder.
        let bld: ArtiConfigBuilder = default.into();
        let rebuilt = bld.build().unwrap();
        assert_eq!(&rebuilt, &parsed);

        // Make sure that the client configuration this gives us is the default one.
        let client_config = parsed.tor_client_config().unwrap();
        let dflt_client_config = TorClientConfig::default();
        assert_eq!(&client_config, &dflt_client_config);
    }

    #[test]
    fn builder() {
        use arti_client::config::dir::DownloadSchedule;
        use tor_config::CfgPath;
        let sec = std::time::Duration::from_secs(1);

        let auth = dir::Authority::builder()
            .name("Fred")
            .v3ident([22; 20].into())
            .build()
            .unwrap();
        let fallback = dir::FallbackDir::builder()
            .rsa_identity([23; 20].into())
            .ed_identity([99; 32].into())
            .orports(vec!["127.0.0.7:7".parse().unwrap()])
            .build()
            .unwrap();

        let mut bld = ArtiConfig::builder();
        bld.proxy().socks_port(Some(9999));
        bld.logging().journald(true).trace_filter("warn".to_owned());
        bld.tor_network()
            .authorities(vec![auth])
            .fallback_caches(vec![fallback]);
        bld.storage()
            .cache_dir(CfgPath::new("/var/tmp/foo".to_owned()))
            .state_dir(CfgPath::new("/var/tmp/bar".to_owned()));
        bld.download_schedule()
            .retry_certs(DownloadSchedule::new(10, sec, 3))
            .retry_microdescs(DownloadSchedule::new(30, 10 * sec, 9));
        bld.override_net_params()
            .insert("wombats-per-quokka".to_owned(), 7);
        bld.path_rules()
            .ipv4_subnet_family_prefix(20)
            .ipv6_subnet_family_prefix(48);
        bld.preemptive_circuits()
            .disable_at_threshold(12)
            .initial_predicted_ports(vec![80, 443])
            .prediction_lifetime(Duration::from_secs(3600))
            .min_exit_circs_for_port(2);
        bld.circuit_timing()
            .max_dirtiness(90 * sec)
            .request_timeout(10 * sec)
            .request_max_retries(22)
            .request_loyalty(3600 * sec);
        bld.address_filter().allow_local_addrs(true);

        let val = bld.build().unwrap();

        // Reconstruct, rebuild, and validate.
        let bld2 = ArtiConfigBuilder::from(val.clone());
        let val2 = bld2.build().unwrap();
        assert_eq!(val, val2);

        assert_ne!(val, ArtiConfig::default());
    }
}
