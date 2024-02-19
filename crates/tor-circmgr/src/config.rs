//! Configuration logic for launching a circuit manager.
//!
//! # Semver note
//!
//! Most types in this module are re-exported by `arti-client`.

use tor_basic_utils::define_accessor_trait;
use tor_config::impl_standard_builder;
use tor_config::{define_list_builder_accessors, define_list_builder_helper, ConfigBuildError};
use tor_guardmgr::{GuardFilter, GuardMgrConfig};

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use tor_netdoc::types::policy::AddrPortPattern;

use std::collections::HashSet;
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
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub struct PathConfig {
    /// Set the length of a bit-prefix for a default IPv4 subnet-family.
    ///
    /// Any two relays will be considered to belong to the same family if their
    /// IPv4 addresses share at least this many initial bits.
    #[builder(default = "ipv4_prefix_default()")]
    ipv4_subnet_family_prefix: u8,

    /// Set the length of a bit-prefix for a default IPv6 subnet-family.
    ///
    /// Any two relays will be considered to belong to the same family if their
    /// IPv6 addresses share at least this many initial bits.
    #[builder(default = "ipv6_prefix_default()")]
    ipv6_subnet_family_prefix: u8,

    /// A set of ports that need to be sent over Stable circuits.
    #[builder(sub_builder, setter(custom))]
    #[builder_field_attr(serde(default))]
    pub(crate) long_lived_ports: LongLivedPorts,

    /// The set of addresses to which we're willing to make direct connections.
    #[builder(sub_builder, setter(custom))]
    #[builder_field_attr(serde(default))]
    pub(crate) reachable_addrs: ReachableAddrs,
}
impl_standard_builder! { PathConfig }

/// Type alias for a list of reachable addresses.
type ReachableAddrs = Vec<AddrPortPattern>;

/// Return the default list of reachable addresses (namely, "*:*")
fn default_reachable_addrs() -> ReachableAddrs {
    vec![AddrPortPattern::new_all()]
}

define_list_builder_helper! {
    struct ReachableAddrsBuilder {
        pub(crate) patterns: [AddrPortPattern],
    }
    built: ReachableAddrs = patterns;
    default = default_reachable_addrs();
    item_build: |pat| Ok(pat.clone());
}

define_list_builder_accessors! {
    struct PathConfigBuilder {
        pub reachable_addrs: [AddrPortPattern],
    }
}

/// Type alias to help define long_lived_ports.
type LongLivedPorts = HashSet<u16>;

define_list_builder_helper! {
    pub struct LongLivedPortsBuilder {
        long_lived_ports:[u16],
    }
    built: LongLivedPorts = long_lived_ports;
    default = long_lived_ports_default();
    item_build: |item| Ok(*item);
}

/// Default value for ipv4_subnet_family_prefix.
fn ipv4_prefix_default() -> u8 {
    16
}
/// Default value for ipv6_subnet_family_prefix.
fn ipv6_prefix_default() -> u8 {
    32
}
/// Default value for long_lived_ports.
fn long_lived_ports_default() -> Vec<u16> {
    vec![
        21, 22, 706, 1863, 5050, 5190, 5222, 5223, 6523, 6667, 6697, 8300,
    ]
}

impl PathConfig {
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
    ///
    /// We use this function to decide when circuits must be discarded.
    /// Therefore, it is okay to return "false" inaccurately, but we should
    /// never return "true" inaccurately.
    pub(crate) fn at_least_as_permissive_as(&self, other: &Self) -> bool {
        self.ipv4_subnet_family_prefix >= other.ipv4_subnet_family_prefix
            && self.ipv6_subnet_family_prefix >= other.ipv6_subnet_family_prefix
            && self.reachable_addrs == other.reachable_addrs
    }

    /// Return a new [`GuardFilter`] reflecting the rules in this configuration.
    pub(crate) fn build_guard_filter(&self) -> GuardFilter {
        let mut filt = GuardFilter::default();
        filt.push_reachable_addresses(self.reachable_addrs.clone());
        filt
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
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub struct PreemptiveCircuitConfig {
    /// If we have at least this many available circuits, we suspend
    /// construction of preemptive circuits. whether our available circuits
    /// support our predicted exit ports or not.
    #[builder(default = "default_preemptive_threshold()")]
    pub(crate) disable_at_threshold: usize,

    /// At startup, which exit ports should we expect that the client will want?
    ///
    /// (Over time, new ports are added to the predicted list, in response to
    /// what the client has actually requested.)
    ///
    /// This value cannot be changed on a running Arti client, because doing so
    /// would be meaningless.
    ///
    /// The default is `[80, 443]`.
    #[builder(sub_builder, setter(custom))]
    pub(crate) initial_predicted_ports: PredictedPortsList,

    /// After we see the client request a connection to a new port, how long
    /// should we predict that the client will still want to have circuits
    /// available for that port?
    #[builder(default = "default_preemptive_duration()")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    pub(crate) prediction_lifetime: Duration,

    /// How many available circuits should we try to have, at minimum, for each
    /// predicted exit port?
    #[builder(default = "default_preemptive_min_exit_circs_for_port()")]
    pub(crate) min_exit_circs_for_port: usize,
}
impl_standard_builder! { PreemptiveCircuitConfig }

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
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
// TODO Use a getters derive macro which lets us only generate getters
// for fields we explicitly request, rather than having to mark the rest with `skip`.
// (amplify::Getters doesn't allow #[getter(skip)] at the type level)
#[derive(amplify::Getters)]
pub struct CircuitTiming {
    /// How long after a circuit has first been used should we give
    /// it out for new requests?
    #[builder(default = "default_max_dirtiness()")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    #[getter(skip)]
    pub(crate) max_dirtiness: Duration,

    /// When a circuit is requested, we stop retrying new circuits
    /// after this much time.
    // TODO: Impose a maximum or minimum?
    #[builder(default = "default_request_timeout()")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    #[getter(skip)]
    pub(crate) request_timeout: Duration,

    /// When a circuit is requested, we stop retrying new circuits after
    /// this many attempts.
    // TODO: Impose a maximum or minimum?
    #[builder(default = "default_request_max_retries()")]
    #[getter(skip)]
    pub(crate) request_max_retries: u32,

    /// When waiting for requested circuits, wait at least this long
    /// before using a suitable-looking circuit launched by some other
    /// request.
    #[builder(default = "default_request_loyalty()")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    #[getter(skip)]
    pub(crate) request_loyalty: Duration,

    /// When an HS connection is attempted, we stop trying more hsdirs after this many attempts
    //
    // This parameter is honoured by tor-hsclient, not here.
    // This is because the best configuration taxonomy isn't the same as the best code structure.
    // This, and `hs_intro_rend_attempts`, fit rather well amongst the other tunings here.
    #[cfg(feature = "hs-client")]
    #[builder(default = "default_hs_max_attempts()")]
    #[getter(as_copy)]
    pub(crate) hs_desc_fetch_attempts: u32,

    /// When an HS connection is attempted, we stop trying intro/rendezvous
    /// after this many attempts
    //
    // This parameter is honoured by tor-hsclient, not here.
    #[cfg(feature = "hs-client")]
    #[builder(default = "default_hs_max_attempts()")]
    #[getter(as_copy)]
    pub(crate) hs_intro_rend_attempts: u32,
}
impl_standard_builder! { CircuitTiming }

/// Return default threshold
fn default_preemptive_threshold() -> usize {
    12
}

/// Built list of configured preemptive ports
type PredictedPortsList = Vec<u16>;

define_list_builder_helper! {
    struct PredictedPortsListBuilder {
        pub(crate) ports: [u16],
    }
    built: PredictedPortsList = ports;
    default = default_preemptive_ports();
    item_build: |&port| Ok(port);
}

define_list_builder_accessors! {
    struct PreemptiveCircuitConfigBuilder {
        pub initial_predicted_ports: [u16],
    }
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

/// Return the default value for `request_max_retries`.
#[cfg(feature = "hs-client")]
fn default_hs_max_attempts() -> u32 {
    // TODO SPEC: Should HS retries be 6 even though the default request_max_retries is 16?
    // Probably, because the HS may be missing or down, and we don't want to spend ages
    // turning over every stone looking for it.
    6
}

/// Return the default request loyalty timeout.
fn default_request_loyalty() -> Duration {
    Duration::from_millis(50)
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
    pub trait CircMgrConfig: GuardMgrConfig {
        path_rules: PathConfig,
        circuit_timing: CircuitTiming,
        preemptive_circuits: PreemptiveCircuitConfig,
    }
}

/// Testing configuration, with public fields
#[cfg(feature = "testing")]
pub(crate) mod test_config {
    use super::*;
    use crate::*;
    use tor_guardmgr::bridge::BridgeConfig;

    /// Testing configuration, with public fields
    #[derive(Default, derive_more::AsRef)]
    #[allow(clippy::exhaustive_structs)]
    #[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
    pub struct TestConfig {
        ///
        pub path_rules: PathConfig,
        ///
        pub circuit_timing: CircuitTiming,
        ///
        pub preemptive_circuits: PreemptiveCircuitConfig,
        ///
        pub guardmgr: tor_guardmgr::TestConfig,
    }
    impl AsRef<[BridgeConfig]> for TestConfig {
        fn as_ref(&self) -> &[BridgeConfig] {
            &self.guardmgr.bridges
        }
    }
    impl AsRef<FallbackList> for TestConfig {
        fn as_ref(&self) -> &FallbackList {
            &self.guardmgr.fallbacks
        }
    }
    impl GuardMgrConfig for TestConfig {
        fn bridges_enabled(&self) -> bool {
            self.guardmgr.bridges_enabled()
        }
    }
    impl CircMgrConfig for TestConfig {
        fn path_rules(&self) -> &PathConfig {
            &self.path_rules
        }
        fn circuit_timing(&self) -> &CircuitTiming {
            &self.circuit_timing
        }
        fn preemptive_circuits(&self) -> &PreemptiveCircuitConfig {
            &self.preemptive_circuits
        }
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
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
