//! Define a type describing how we're going to use a relay.

use crate::{RelayPredicate, RelaySelectionConfig, TargetPort};
use tor_netdir::{Relay, WeightRole};

/// Description for how we plan to use a single relay.
#[derive(Clone, Debug)]
pub struct RelayUsage {
    /// Interior enumeration to describe the particular usage.
    inner: RelayUsageInner,
    /// Does this usage require the `Stable` flag?
    ///
    /// This is derived when we construct the RelayUsage, since it may require
    /// access to the config, and since it's cheaper to pre-compute.
    need_stable: bool,
}

/// Implementation type for RelayUsage.
///
/// This is a separate type so that we can hide its variants.
#[derive(Clone, Debug)]
enum RelayUsageInner {
    /// Allow any relay that exits to any port.
    AnyExit,
    /// Require that the relay can exit to every port in `TargetPort`.
    ExitToAllPorts(Vec<TargetPort>),
    /// Require that the relay can exit to at least one port in a given set.
    ///
    /// (We split the ports into those that require Stability and those that do
    /// not, for efficiency.)
    ExitToAnyPort {
        /// The desired ports that require the Stable flag.
        stable_ports: Vec<TargetPort>,
        /// The desired ports that do not require the Stable flag.
        unstable_ports: Vec<TargetPort>,
    },
    /// Allow any relay that's suitable as a middle-point.
    Middle,
    /// Allow any relay that's suitable as a newly selected introduction point.
    NewIntroPoint,
    /// Allow any relay that's suitable for continued use as a pre-existing
    /// introduction point.
    ContinuingIntroPoint,
    /// Allow any relay that's suitable as a newly selected guard.
    NewGuard,
    /// Allow any relay that's suitable for continued use as a pre-existing
    /// guard.
    ContinuingGuard,
    /// Allow any relay that's suitable as a one-hop directory cache.
    DirectoryCache,
}

impl RelayUsage {
    /// Require a relay that exits to at least one port.
    ///
    /// This usage is generally suitable as the final relay for a testing
    /// circuit of some kind, or for a circuit that needs to _look_ like an
    /// exit circuit without actually being useful for any exit in particular.
    pub fn any_exit(_cfg: &RelaySelectionConfig) -> Self {
        // TODO: properly, we ought to make sure that this does not select
        // relays that only exit to long_lived ports, unless they have the
        // Stable flag.
        //
        // C tor doesn't make this distinction, however, and so neither do we.
        RelayUsage {
            inner: RelayUsageInner::AnyExit,
            need_stable: false,
        }
    }

    /// Require a relay that exits to every port in a given list.
    pub fn exit_to_all_ports(cfg: &RelaySelectionConfig, ports: Vec<TargetPort>) -> Self {
        let need_stable = ports.iter().any(|p| cfg.port_requires_stable_flag(p.port));
        RelayUsage {
            inner: RelayUsageInner::ExitToAllPorts(ports),
            need_stable,
        }
    }

    /// Require a relay that exits to at least one port in a given list.
    pub fn exit_to_any_port(cfg: &RelaySelectionConfig, ports: Vec<TargetPort>) -> Self {
        let (stable_ports, unstable_ports): (Vec<_>, Vec<_>) = ports
            .into_iter()
            .partition(|p| cfg.port_requires_stable_flag(p.port));
        let need_stable = unstable_ports.is_empty() && !stable_ports.is_empty();
        RelayUsage {
            inner: RelayUsageInner::ExitToAnyPort {
                stable_ports,
                unstable_ports,
            },
            need_stable,
        }
    }

    /// Require a relay that is suitable for a middle relay.
    ///
    /// If `known_final_hop_usage` is provided, then the middle relay must support any
    /// additional properties needed in order to build a circuit for the usage
    /// of the final hop.
    ///
    /// If `known_final_hop_usage` is *not* provided, then the middle relay must
    /// support all possible such additional properties.
    ///
    /// (Note that providing a `known_final_hop_usage` can only _weaken_ the
    /// requirements of this usage.)
    pub fn middle_relay(known_final_hop_usage: Option<&RelayUsage>) -> Self {
        let need_stable = known_final_hop_usage.map(|u| u.need_stable).unwrap_or(true);
        RelayUsage {
            inner: RelayUsageInner::Middle,
            need_stable,
        }
    }

    /// Require a relay that is suitable as a newly selected introduction point.
    ///
    /// This usage is suitable for selecting _new_ introduction points for an
    /// onion service.  When deciding whether to _keep_ an introduction point,
    /// use [`RelayUsage::continuing_intro_point`].
    pub fn new_intro_point() -> Self {
        RelayUsage {
            inner: RelayUsageInner::NewIntroPoint,
            need_stable: true,
        }
    }

    /// Require a relay that is suitable to keep using as a pre-existing introduction point.
    pub fn continuing_intro_point() -> Self {
        RelayUsage {
            inner: RelayUsageInner::ContinuingIntroPoint,
            need_stable: true,
        }
    }

    /// Require a relay that is suitable as a newly selected guard.
    ///
    /// This usage is suitable for selecting _new_ guards.
    /// When deciding whether to _keep_ a guard,
    /// use [`RelayUsage::continuing_guard`].
    pub fn new_guard() -> Self {
        RelayUsage {
            inner: RelayUsageInner::NewGuard,
            need_stable: true,
        }
    }

    /// Require a relay that is suitable to keep using as a pre-existing guard.
    pub fn continuing_guard() -> Self {
        RelayUsage {
            inner: RelayUsageInner::ContinuingGuard,
            need_stable: true,
        }
    }

    /// Require a relay that is suitable to use for a directory request.
    ///
    /// Note that this usage is suitable for fetching consensuses, authority certificates,
    /// descriptors and microdescriptors.  It is _not_ suitable for use with the
    /// HsDir system.
    pub fn directory_cache() -> Self {
        RelayUsage {
            inner: RelayUsageInner::DirectoryCache,
            need_stable: false,
        }
    }

    /// Return the [`WeightRole`] to use when picking a relay for this usage.
    pub(crate) fn selection_weight_role(&self) -> WeightRole {
        use RelayUsageInner::*;

        match &self.inner {
            AnyExit | ExitToAllPorts(_) | ExitToAnyPort { .. } => WeightRole::Exit,
            Middle => WeightRole::Middle,
            NewIntroPoint | ContinuingIntroPoint => WeightRole::HsIntro,
            NewGuard | ContinuingGuard => WeightRole::Guard,
            DirectoryCache => WeightRole::BeginDir,
        }
    }

    /// Return a string describing why we rejected the relays that _don't_ match
    /// this usage.
    pub(crate) fn rejection_description(&self) -> &'static str {
        use RelayUsageInner::*;
        match &self.inner {
            AnyExit => "non-exit",
            ExitToAllPorts(_) => "not exiting to desired ports",
            ExitToAnyPort { .. } => "not exiting to any desired port",
            Middle => "useless for middle relay",
            NewIntroPoint | ContinuingIntroPoint => "not introduction point",
            NewGuard | ContinuingGuard => "not guard",
            DirectoryCache => "not directory cache",
        }
    }
}

impl RelayPredicate for RelayUsage {
    fn permits_relay(&self, relay: &Relay<'_>) -> bool {
        use RelayUsageInner::*;
        if !relay.is_flagged_fast() {
            return false;
        }
        if self.need_stable && !relay.is_flagged_stable() {
            return false;
        }
        match &self.inner {
            AnyExit => relay.policies_allow_some_port(),
            ExitToAllPorts(ports) => ports.iter().all(|p| p.is_supported_by(relay)),
            ExitToAnyPort {
                stable_ports,
                unstable_ports,
            } => {
                if relay.is_flagged_stable()
                    && stable_ports.iter().any(|p| p.is_supported_by(relay))
                {
                    return true;
                }
                unstable_ports.iter().any(|p| p.is_supported_by(relay))
            }
            Middle => true,
            // TODO: Is there a distinction we should implement?
            // TODO: Move is_hs_intro_point logic here.
            NewIntroPoint | ContinuingIntroPoint => relay.is_hs_intro_point(),
            // TODO: Is there a distinction we should implement?
            // TODO: Move is_suitable_as_guard logic here.
            NewGuard | ContinuingGuard => relay.is_suitable_as_guard() && relay.is_dir_cache(),
            DirectoryCache => relay.is_dir_cache(),
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
    use crate::testing::{cfg, split_netdir, testnet};

    #[test]
    fn any_exits() {
        let nd = testnet();

        let (yes, no) = split_netdir(&nd, &RelayUsage::any_exit(&cfg()));

        let p = |r: &Relay<'_>| r.is_flagged_fast() && r.policies_allow_some_port();
        assert!(yes.iter().all(p));
        assert!(no.iter().all(|r| !p(r)));
    }

    #[test]
    fn all_ports() {
        let nd = testnet();
        let ports_stable = vec![TargetPort::ipv4(22), TargetPort::ipv4(80)];
        let usage_stable = RelayUsage::exit_to_all_ports(&cfg(), ports_stable);
        assert!(usage_stable.need_stable);

        let p1 = |r: &Relay<'_>| {
            r.is_flagged_fast()
                && r.is_flagged_stable()
                && r.ipv4_policy().allows_port(22)
                && r.ipv4_policy().allows_port(80)
        };

        let (yes, no) = split_netdir(&nd, &usage_stable);
        assert!(yes.iter().all(p1));
        assert!(no.iter().all(|r| !p1(r)));

        let ports_not_stable = vec![TargetPort::ipv4(80)];
        let usage_not_stable = RelayUsage::exit_to_all_ports(&cfg(), ports_not_stable);

        let p2 = |r: &Relay<'_>| r.is_flagged_fast() && r.ipv4_policy().allows_port(80);
        let (yes, no) = split_netdir(&nd, &usage_not_stable);
        assert!(yes.iter().all(p2));
        assert!(no.iter().all(|r| !p2(r)));
    }

    #[test]
    fn any_port() {
        let nd = testnet();
        let ports = vec![TargetPort::ipv4(22), TargetPort::ipv4(80)];
        let usage = RelayUsage::exit_to_any_port(&cfg(), ports);
        assert!(!usage.need_stable);
        match &usage.inner {
            RelayUsageInner::ExitToAnyPort {
                stable_ports,
                unstable_ports,
            } => {
                assert_eq!(&stable_ports[..], &[TargetPort::ipv4(22)]);
                assert_eq!(&unstable_ports[..], &[TargetPort::ipv4(80)]);
            }
            _ => {
                panic!("Wrong kind of usage.");
            }
        }

        let p = |r: &Relay<'_>| {
            let port_22 = r.is_flagged_stable() && r.ipv4_policy().allows_port(22);
            let port_80 = r.ipv4_policy().allows_port(80);
            r.is_flagged_fast() && (port_22 || port_80)
        };

        let (yes, no) = split_netdir(&nd, &usage);
        assert!(yes.iter().all(p));
        assert!(no.iter().all(|r| !p(r)));
    }

    #[test]
    fn middle() {
        let nd = testnet();

        let u_unstable = RelayUsage::any_exit(&cfg());
        let u_stable = RelayUsage::new_guard();
        let mid_stable = RelayUsage::middle_relay(Some(&u_stable));
        let mid_unstable = RelayUsage::middle_relay(Some(&u_unstable));
        let mid_default = RelayUsage::middle_relay(None);
        assert!(mid_stable.need_stable);
        assert!(!mid_unstable.need_stable);
        assert!(mid_default.need_stable);

        let (yes, no) = split_netdir(&nd, &mid_unstable);
        let p1 = |r: &Relay<'_>| r.is_flagged_fast();
        assert!(yes.iter().all(p1));
        assert!(no.iter().all(|r| !p1(r)));

        let (yes, no) = split_netdir(&nd, &mid_stable);
        let p2 = |r: &Relay<'_>| r.is_flagged_fast() && r.is_flagged_stable();
        assert!(yes.iter().all(p2));
        assert!(no.iter().all(|r| !p2(r)));
    }

    #[test]
    fn intro() {
        let nd = testnet();
        let usage = RelayUsage::new_intro_point();

        let (yes, no) = split_netdir(&nd, &usage);
        let p1 = |r: &Relay<'_>| r.is_flagged_fast() && r.is_flagged_stable();
        assert!(yes.iter().all(p1));
        assert!(no.iter().all(|r| !p1(r)));
    }

    #[test]
    fn guard() {
        let nd = testnet();
        let usage = RelayUsage::new_guard();

        let (yes, no) = split_netdir(&nd, &usage);
        let p1 = |r: &Relay<'_>| {
            r.is_flagged_fast() && r.is_flagged_stable() && r.is_flagged_guard() && r.is_dir_cache()
        };
        assert!(yes.iter().all(p1));
        assert!(no.iter().all(|r| !p1(r)));
    }

    #[test]
    fn cache() {
        let nd = testnet();
        let usage = RelayUsage::directory_cache();

        let (yes, no) = split_netdir(&nd, &usage);
        let p1 = |r: &Relay<'_>| r.is_flagged_fast() && r.is_dir_cache();
        assert!(yes.iter().all(p1));
        assert!(no.iter().all(|r| !p1(r)));
    }
}
