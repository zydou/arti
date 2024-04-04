//! Functionality for exposing details about a relay that most users should avoid.
//!
//! ## Design notes
//!
//! These types aren't meant to be a dumping grounds
//! for every function in `Relay` or `UncheckedRelay`:
//! instead, they are for methods that are easy to misuse or misunderstand
//! if applied out-of-context.
//!
//! For example, it's generally wrong in most contexts
//! to check for a specific relay flag.
//! Instead, we should be checking whether the relay is suitable
//! for some particular _usage_,
//! which will itself depend on a combination of flags.
//!
//! Therefore, this module should be used for checking properties only when:
//! - The property is one that is usually subsumed
//!   in a higher-level check.
//! - Using the lower-level property on its own poses a risk
//!   of accidentally forgetting to check other important properties.
//!
//! If you find that your code is using this module, you should ask yourself
//! - whether the actual thing that you're testing
//!   is something that _any other piece of code_ might want to test
//! - whether the collection of properties that you're testing
//!   creates a risk of leaving out some other properties
//!   that should also be tested,
//!   for example in the future, if new relay flags or properties are introduced
//!   that are supposed to influence relay selection or reuse.
//!
//! If you answer "yes" to either of these, it's better to define a higher-level property,
//! and have your code use that instead.

use std::sync::Arc;

use tor_linkspec::HasRelayIds;
use tor_netdoc::{doc::netstatus, types::policy::PortPolicy};

use crate::{Relay, SubnetConfig};

/// A view for lower-level details about a [`Relay`].
///
/// Most callers should avoid using this structure;
/// they should instead call higher-level functions
/// like those in the `tor-relay-selection` crate.
#[derive(Clone)]
pub struct RelayDetails<'a>(pub(crate) &'a super::Relay<'a>);

impl<'a> RelayDetails<'a> {
    /// Return true if this relay allows exiting to `port` on IPv4.
    pub fn supports_exit_port_ipv4(&self, port: u16) -> bool {
        self.ipv4_policy().allows_port(port)
    }
    /// Return true if this relay allows exiting to `port` on IPv6.
    pub fn supports_exit_port_ipv6(&self, port: u16) -> bool {
        self.ipv6_policy().allows_port(port)
    }
    /// Return true if this relay is suitable for use as a directory
    /// cache.
    pub fn is_dir_cache(&self) -> bool {
        rs_is_dir_cache(self.0.rs)
    }
    /// Return true if this relay has the "Fast" flag.
    ///
    /// Most relays have this flag.  It indicates that the relay is suitable for
    /// circuits that need more than a minimal amount of bandwidth.
    pub fn is_flagged_fast(&self) -> bool {
        self.0.rs.is_flagged_fast()
    }
    /// Return true if this relay has the "Stable" flag.
    ///
    /// Most relays have this flag. It indicates that the relay is suitable for
    /// long-lived circuits.
    pub fn is_flagged_stable(&self) -> bool {
        self.0.rs.is_flagged_stable()
    }
    /// Return true if this relay is a potential HS introduction point
    pub fn is_hs_intro_point(&self) -> bool {
        self.is_flagged_fast() && self.0.rs.is_flagged_stable()
    }
    /// Return true if this relay is suitable for use as a newly sampled guard,
    /// or for continuing to use as a guard.
    pub fn is_suitable_as_guard(&self) -> bool {
        self.0.rs.is_flagged_guard() && self.is_flagged_fast() && self.is_flagged_stable()
    }
    /// Return true if both relays are in the same subnet, as configured by
    /// `subnet_config`.
    ///
    /// Two relays are considered to be in the same subnet if they
    /// have IPv4 addresses with the same `subnets_family_v4`-bit
    /// prefix, or if they have IPv6 addresses with the same
    /// `subnets_family_v6`-bit prefix.
    pub fn in_same_subnet(&self, other: &Relay<'_>, subnet_config: &SubnetConfig) -> bool {
        subnet_config.any_addrs_in_same_subnet(self.0, other)
    }
    /// Return true if both relays are in the same family.
    ///
    /// (Every relay is considered to be in the same family as itself.)
    pub fn in_same_family(&self, other: &Relay<'_>) -> bool {
        if self.0.same_relay_ids(other) {
            return true;
        }
        self.0.md.family().contains(other.rsa_id()) && other.md.family().contains(self.0.rsa_id())
    }

    /// Return true if there are any ports for which this Relay can be
    /// used for exit traffic.
    ///
    /// (Returns false if this relay doesn't allow exit traffic, or if it
    /// has been flagged as a bad exit.)
    pub fn policies_allow_some_port(&self) -> bool {
        if self.0.rs.is_flagged_bad_exit() {
            return false;
        }

        self.0.md.ipv4_policy().allows_some_port() || self.0.md.ipv6_policy().allows_some_port()
    }

    /// Return the IPv4 exit policy for this relay. If the relay has been marked BadExit, return an
    /// empty policy
    pub fn ipv4_policy(&self) -> Arc<PortPolicy> {
        if !self.0.rs.is_flagged_bad_exit() {
            Arc::clone(self.0.md.ipv4_policy())
        } else {
            Arc::new(PortPolicy::new_reject_all())
        }
    }
    /// Return the IPv6 exit policy for this relay. If the relay has been marked BadExit, return an
    /// empty policy
    pub fn ipv6_policy(&self) -> Arc<PortPolicy> {
        if !self.0.rs.is_flagged_bad_exit() {
            Arc::clone(self.0.md.ipv6_policy())
        } else {
            Arc::new(PortPolicy::new_reject_all())
        }
    }
    /// Return the IPv4 exit policy declared by this relay.
    ///
    /// In contrast to [`RelayDetails::ipv4_policy`],
    /// this does not verify if the relay is marked BadExit.
    pub fn ipv4_declared_policy(&self) -> &Arc<PortPolicy> {
        self.0.md.ipv4_policy()
    }
    /// Return the IPv6 exit policy declared by this relay.
    ///
    /// In contrast to [`RelayDetails::ipv6_policy`],
    /// this does not verify if the relay is marked BadExit.
    pub fn ipv6_declared_policy(&self) -> &Arc<PortPolicy> {
        self.0.md.ipv6_policy()
    }
}

/// A view for lower-level details about a [`UncheckedRelay`](crate::UncheckedRelay).
///
/// Most callers should avoid using this structure;
/// they should instead call higher-level functions
/// like those in the `tor-relay-selection` crate.
#[derive(Debug, Clone)]
pub struct UncheckedRelayDetails<'a>(pub(crate) &'a super::UncheckedRelay<'a>);

impl<'a> UncheckedRelayDetails<'a> {
    /// Return true if this relay is suitable for use as a newly sampled guard,
    /// or for continuing to use as a guard.
    pub fn is_suitable_as_guard(&self) -> bool {
        self.0.rs.is_flagged_guard() && self.0.rs.is_flagged_fast() && self.0.rs.is_flagged_stable()
    }
    /// Return true if this relay is a potential directory cache.
    pub fn is_dir_cache(&self) -> bool {
        rs_is_dir_cache(self.0.rs)
    }
}

/// Return true if `rs` is usable as a directory cache.
fn rs_is_dir_cache(rs: &netstatus::MdConsensusRouterStatus) -> bool {
    use tor_protover::ProtoKind;
    rs.is_flagged_v2dir() && rs.protovers().supports_known_subver(ProtoKind::DirCache, 2)
}
