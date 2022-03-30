//! Configuration logic for launching a circuit manager.
//!
//! # Semver note
//!
//! Most types in this module are re-exported by `arti-client`.

use tor_basic_utils::define_accessor_trait;
use tor_config::ConfigBuildError;
use tor_guardmgr::fallback::FallbackList;

use derive_builder::Builder;
use serde::Deserialize;

use std::time::Duration;

/// Rules for building paths over the network.
///
/// This type is immutable once constructed.  To build one, use
/// [`PathConfigBuilder`], or deserialize it from a string.
///
/// You may change the PathConfig on a running Arti client.  Doing so changes
/// paths that are constructed in the future, and prevents requests from being
/// attached to existing circuits, if the configuration has become more
/// restrictive.
#[derive(Debug, Clone, Builder, Deserialize, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Deserialize))]
#[serde(deny_unknown_fields)]
pub struct PathConfig {
    /// Set the length of a bit-prefix for a default IPv4 subnet-family.
    ///
    /// Any two relays will be considered to belong to the same family if their
    /// IPv4 addresses share at least this many initial bits.
    #[builder(default = "ipv4_prefix_default()")]
    #[serde(default = "ipv4_prefix_default")]
    ipv4_subnet_family_prefix: u8,

    /// Set the length of a bit-prefix for a default IPv6 subnet-family.
    ///
    /// Any two relays will be considered to belong to the same family if their
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
    pub fn builder() -> PathConfigBuilder {
        PathConfigBuilder::default()
    }
    /// Return a subnet configuration based on these rules.
    pub fn subnet_config(&self) -> tor_netdir::SubnetConfig {
        tor_netdir::SubnetConfig::new(
            self.ipv4_subnet_family_prefix,
            self.ipv6_subnet_family_prefix,
        )
    }

    /// Return true if this configuration is at least as permissive as `other`.
    ///
    /// In other words, in other words, return true if every circuit permitted
    /// by `other` would also be permitted by this configuration.
    pub(crate) fn at_least_as_permissive_as(&self, other: &Self) -> bool {
        self.ipv4_subnet_family_prefix >= other.ipv4_subnet_family_prefix
            && self.ipv6_subnet_family_prefix >= other.ipv6_subnet_family_prefix
    }
}

impl Default for PathConfig {
    fn default() -> PathConfig {
        PathConfigBuilder::default()
            .build()
            .expect("unusable hardwired defaults")
    }
}

/// Configuration for preemptive circuits.
///
/// Preemptive circuits are built ahead of time, to anticipate client need. This
/// object configures the way in which this demand is anticipated and in which
/// these circuits are constructed.
///
/// This type is immutable once constructed. To create an object of this type,
/// use [`PreemptiveCircuitConfigBuilder`].
///
/// Except as noted, this configuration can be changed on a running Arti client.
#[derive(Debug, Clone, Builder, Deserialize, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Deserialize))]
#[serde(deny_unknown_fields)]
pub struct PreemptiveCircuitConfig {
    /// If we have at least this many available circuits, we suspend
    /// construction of preemptive circuits. whether our available circuits
    /// support our predicted exit ports or not.
    #[builder(default = "default_preemptive_threshold()")]
    #[serde(default = "default_preemptive_threshold")]
    pub(crate) disable_at_threshold: usize,

    /// At startup, which exit ports should we expect that the client will want?
    ///
    /// (Over time, new ports are added to the predicted list, in response to
    /// what the client has actually requested.)
    ///
    /// This value cannot be changed on a running Arti client, because doing so
    /// would be meaningless.
    #[builder(default = "default_preemptive_ports()")]
    #[serde(default = "default_preemptive_ports")]
    pub(crate) initial_predicted_ports: Vec<u16>,

    /// After we see the client request a connection to a new port, how long
    /// should we predict that the client will still want to have circuits
    /// available for that port?
    #[builder(default = "default_preemptive_duration()")]
    #[serde(with = "humantime_serde", default = "default_preemptive_duration")]
    #[builder_field_attr(serde(with = "humantime_serde::option"))]
    pub(crate) prediction_lifetime: Duration,

    /// How many available circuits should we try to have, at minimum, for each
    /// predicted exit port?
    #[builder(default = "default_preemptive_min_exit_circs_for_port()")]
    #[serde(default = "default_preemptive_min_exit_circs_for_port")]
    pub(crate) min_exit_circs_for_port: usize,
}

/// Configuration for circuit timeouts, expiration, and so on.
///
/// This type is immutable once constructed. To create an object of this type,
/// use [`CircuitTimingBuilder`].
///
/// You can change the CircuitTiming on a running Arti client.  Doing
/// so _should_ affect the expiration times of all circuits that are
/// not currently expired, and the request timing of all _future_
/// requests.  However, there are currently bugs: see bug
/// [#263](https://gitlab.torproject.org/tpo/core/arti/-/issues/263).
#[derive(Debug, Clone, Builder, Deserialize, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Deserialize))]
#[serde(deny_unknown_fields)]
pub struct CircuitTiming {
    /// How long after a circuit has first been used should we give
    /// it out for new requests?
    #[builder(default = "default_max_dirtiness()")]
    #[serde(with = "humantime_serde", default = "default_max_dirtiness")]
    #[builder_field_attr(serde(with = "humantime_serde::option"))]
    pub(crate) max_dirtiness: Duration,

    /// When a circuit is requested, we stop retrying new circuits
    /// after this much time.
    // TODO: Impose a maximum or minimum?
    #[builder(default = "default_request_timeout()")]
    #[serde(with = "humantime_serde", default = "default_request_timeout")]
    #[builder_field_attr(serde(with = "humantime_serde::option"))]
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
    #[builder_field_attr(serde(with = "humantime_serde::option"))]
    pub(crate) request_loyalty: Duration,
}

/// Return default threshold
fn default_preemptive_threshold() -> usize {
    12
}

/// Return default target ports
fn default_preemptive_ports() -> Vec<u16> {
    vec![80, 443]
}

/// Return default duration
fn default_preemptive_duration() -> Duration {
    Duration::from_secs(60 * 60)
}

/// Return minimum circuits for an exit port
fn default_preemptive_min_exit_circs_for_port() -> usize {
    2
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
    16
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

impl Default for PreemptiveCircuitConfig {
    fn default() -> Self {
        PreemptiveCircuitConfigBuilder::default()
            .build()
            .expect("preemptive circuit defaults")
    }
}

impl PreemptiveCircuitConfig {
    /// Return a new [`PreemptiveCircuitConfigBuilder`]
    pub fn builder() -> PreemptiveCircuitConfigBuilder {
        PreemptiveCircuitConfigBuilder::default()
    }
}

define_accessor_trait! {
    /// Configuration for a circuit manager
    ///
    /// If the circuit manager gains new configurabilities, this trait will gain additional
    /// supertraits, as an API break.
    ///
    /// Prefer to use `TorClientConfig`, which will always implement this trait.
    //
    // We do not use a builder here.  Instead, additions or changes here are API breaks.
    //
    // Rationale:
    //
    // The purpose of using a builder is to allow the code to continue to
    // compile when new fields are added to the built struct.
    //
    // However, here, the DirMgrConfig is just a subset of the fields of a
    // TorClientConfig, and it is important that all its fields are
    // initialised by arti-client.
    //
    // If it grows a field, arti-client ought not to compile any more.
    //
    // Indeed, we have already had a bug where a manually-written
    // conversion function omitted to copy a config field from
    // TorClientConfig into then-existing CircMgrConfigBuilder.
    //
    // We use this AsRef-based trait, so that we can pass a reference
    // to the configuration when we build a new CircMgr, rather than
    // cloning all the fields an extra time.
    pub trait CircMgrConfig {
        path_rules: PathConfig,
        circuit_timing: CircuitTiming,
        preemptive_circuits: PreemptiveCircuitConfig,
        fallbacks: FallbackList,
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn path_config() {
        let pc1 = PathConfig::default();
        // Because these configurations consider _fewer_ nodes to be in the same
        // families, they are _more_ permissive about what circuits we can
        // build.
        let pc2 = PathConfig::builder()
            .ipv4_subnet_family_prefix(32)
            .build()
            .unwrap();
        let pc3 = PathConfig::builder()
            .ipv6_subnet_family_prefix(128)
            .build()
            .unwrap();

        assert!(pc2.at_least_as_permissive_as(&pc1));
        assert!(pc3.at_least_as_permissive_as(&pc1));
        assert!(pc1.at_least_as_permissive_as(&pc1));
        assert!(!pc1.at_least_as_permissive_as(&pc2));
        assert!(!pc1.at_least_as_permissive_as(&pc3));
        assert!(!pc3.at_least_as_permissive_as(&pc2));
    }
}
