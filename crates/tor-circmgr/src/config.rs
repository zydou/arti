//! Configuration logic for launching a circuit manager.
//!
//! # Semver note
//!
//! Most types in this module are re-exported by `arti-client`.

use tor_config::ConfigBuildError;

use derive_builder::Builder;
use serde::Deserialize;

use std::time::Duration;

/// Rules for building paths over the network.
///
/// This type is immutable once constructed.  To build one, use
/// [`PathConfigBuilder`], or deserialize it from a string.
#[derive(Debug, Clone, Builder, Deserialize, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct PathConfig {
    /// Set the length of a bit-prefix for a default IPv4 subnet-family.
    ///
    /// Any two relays will be considerd to belong to the same family if their
    /// IPv4 addresses share at least this many initial bits.
    #[builder(default = "ipv4_prefix_default()")]
    #[serde(default = "ipv4_prefix_default")]
    ipv4_subnet_family_prefix: u8,

    /// Set the length of a bit-prefix for a default IPv6 subnet-family.
    ///
    /// Any two relays will be considerd to belong to the same family if their
    /// IPv6 addresses share at least this many initial bits.
    #[builder(default = "ipv6_prefix_default()")]
    #[serde(default = "ipv6_prefix_default")]
    ipv6_subnet_family_prefix: u8,
}

/// Default value for ipv4_subnet_family_prefix.
fn ipv4_prefix_default() -> u8 {
    16
}
/// Default value for ipv6_subnet_family_prefix.
fn ipv6_prefix_default() -> u8 {
    32
}

impl PathConfig {
    /// Return a new [`PathConfigBuilder`].
    pub fn builder(&self) -> PathConfigBuilder {
        PathConfigBuilder::default()
    }
    /// Return a subnet configuration based on these rules.
    pub fn subnet_config(&self) -> tor_netdir::SubnetConfig {
        tor_netdir::SubnetConfig::new(
            self.ipv4_subnet_family_prefix,
            self.ipv6_subnet_family_prefix,
        )
    }
}

impl Default for PathConfig {
    fn default() -> PathConfig {
        PathConfigBuilder::default()
            .build()
            .expect("unusable hirdwired defaults")
    }
}

impl From<PathConfig> for PathConfigBuilder {
    fn from(cfg: PathConfig) -> PathConfigBuilder {
        let mut builder = PathConfigBuilder::default();
        builder
            .ipv4_subnet_family_prefix(cfg.ipv4_subnet_family_prefix)
            .ipv6_subnet_family_prefix(cfg.ipv6_subnet_family_prefix);
        builder
    }
}

/// Configuration for circuit timeouts, expiration, and so on.
///
/// This type is immutable once constructd. To create an object of this
/// type, use [`CircuitTimingBuilder`].
#[derive(Debug, Clone, Builder, Deserialize, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct CircuitTiming {
    /// How long after a circuit has first been used should we give
    /// it out for new requests?
    #[builder(default = "default_max_dirtiness()")]
    #[serde(with = "humantime_serde", default = "default_max_dirtiness")]
    pub(crate) max_dirtiness: Duration,

    /// When a circuit is requested, we stop retrying new circuits
    /// after this much time.
    // TODO: Impose a maximum or minimum?
    #[builder(default = "default_request_timeout()")]
    #[serde(with = "humantime_serde", default = "default_request_timeout")]
    pub(crate) request_timeout: Duration,

    /// When a circuit is requested, we stop retrying new circuits after
    /// this many attempts.
    // TODO: Impose a maximum or minimum?
    #[builder(default = "default_request_max_retries()")]
    #[serde(default = "default_request_max_retries")]
    pub(crate) request_max_retries: u32,

    /// When waiting for requested circuits, wait at least this long
    /// before using a suitable-looking circuit launched by some other
    /// request.
    #[builder(default = "default_request_loyalty()")]
    #[serde(with = "humantime_serde", default = "default_request_loyalty")]
    pub(crate) request_loyalty: Duration,
}

/// Return the default value for `max_dirtiness`.
fn default_max_dirtiness() -> Duration {
    Duration::from_secs(60 * 10)
}

/// Return the default value for `request_timeout`.
fn default_request_timeout() -> Duration {
    Duration::from_secs(60)
}

/// Return the default value for `request_max_retries`.
fn default_request_max_retries() -> u32 {
    32
}

/// Return the default request loyalty timeout.
fn default_request_loyalty() -> Duration {
    Duration::from_millis(50)
}

// NOTE: it seems that `unwrap` may be safe because of builder defaults
// check `derive_builder` documentation for details
// https://docs.rs/derive_builder/0.10.2/derive_builder/#default-values
#[allow(clippy::unwrap_used)]
impl Default for CircuitTiming {
    fn default() -> Self {
        CircuitTimingBuilder::default().build().unwrap()
    }
}

impl CircuitTiming {
    /// Return a new [`CircuitTimingBuilder`]
    pub fn builder() -> CircuitTimingBuilder {
        CircuitTimingBuilder::default()
    }
}

impl From<CircuitTiming> for CircuitTimingBuilder {
    fn from(cfg: CircuitTiming) -> CircuitTimingBuilder {
        let mut builder = CircuitTimingBuilder::default();
        builder
            .max_dirtiness(cfg.max_dirtiness)
            .request_timeout(cfg.request_timeout)
            .request_max_retries(cfg.request_max_retries)
            .request_loyalty(cfg.request_loyalty);
        builder
    }
}

/// Configuration for a circuit manager.
///
/// This configuration includes information about how to build paths
/// on the Tor network, and rules for timeouts and retries on Tor
/// circuits.
///
/// This type is immutable once constructed.  To create an object of
/// this type, use [`CircMgrConfigBuilder`], or deserialize it from a
/// string.  (Arti generally uses Toml for configuration, but you can
/// use other formats if you prefer.)
#[derive(Debug, Clone, Builder, Default, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct CircMgrConfig {
    /// Override the default required distance for two relays to share
    /// the same circuit.
    #[builder(default)]
    pub(crate) path_rules: PathConfig,

    /// Timing and retry information related to circuits themselves.
    #[builder(default)]
    pub(crate) circuit_timing: CircuitTiming,
}

impl CircMgrConfig {
    /// Return a new [`CircMgrConfigBuilder`].
    pub fn builder() -> CircMgrConfigBuilder {
        CircMgrConfigBuilder::default()
    }
}
