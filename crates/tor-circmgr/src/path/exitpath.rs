//! Code for building paths to an exit relay.

use std::time::SystemTime;

use rand::Rng;

use super::{AnonymousPathBuilder, TorPath};
use crate::path::pick_path;
use crate::{DirInfo, Error, PathConfig, Result, TargetPort};

use tor_guardmgr::{GuardMgr, GuardMonitor, GuardUsable};
use tor_linkspec::OwnedChanTarget;
use tor_netdir::{NetDir, Relay};
use tor_relay_selection::{RelayExclusion, RelaySelectionConfig, RelaySelector, RelayUsage};
use tor_rtcompat::Runtime;
#[cfg(feature = "geoip")]
use {tor_geoip::CountryCode, tor_relay_selection::RelayRestriction};

/// Internal representation of PathBuilder.
enum ExitPathBuilderInner {
    /// Request a path that allows exit to the given `TargetPort`s.
    WantsPorts(Vec<TargetPort>),

    /// Request a path that allows exit with a relay in the given country.
    // TODO GEOIP: refactor this builder to allow conjunction!
    // See discussion here:
    // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1537#note_2942218
    #[cfg(feature = "geoip")]
    ExitInCountry {
        /// The country to exit in.
        country: CountryCode,
        /// Some target ports to use (works like `WantsPorts`).
        ///
        /// HACK(eta): This is a horrible hack to work around the lack of conjunction.
        ports: Vec<TargetPort>,
    },

    /// Request a path that allows exit to _any_ port.
    AnyExit {
        /// If false, then we fall back to non-exit nodes if we can't find an
        /// exit.
        strict: bool,
    },
}

/// A PathBuilder that builds a path to an exit relay supporting a given
/// set of ports.
///
/// NOTE: The name of this type is no longer completely apt: given some circuits,
/// it is happy to build a circuit ending at a non-exit.
pub(crate) struct ExitPathBuilder {
    /// The inner ExitPathBuilder state.
    inner: ExitPathBuilderInner,
    /// If present, a "target" that every chosen relay must be able to share a circuit with with.
    compatible_with: Option<OwnedChanTarget>,
    /// If true, all relays on this path must be Stable.
    require_stability: bool,
}

impl ExitPathBuilder {
    /// Create a new builder that will try to get an exit relay
    /// containing all the ports in `ports`.
    ///
    /// If the list of ports is empty, tries to get any exit relay at all.
    pub(crate) fn from_target_ports(wantports: impl IntoIterator<Item = TargetPort>) -> Self {
        let ports: Vec<TargetPort> = wantports.into_iter().collect();
        if ports.is_empty() {
            return Self::for_any_exit();
        }
        Self {
            inner: ExitPathBuilderInner::WantsPorts(ports),
            compatible_with: None,
            require_stability: true,
        }
    }

    #[cfg(feature = "geoip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "geoip")))]
    /// Create a new builder that will try to get an exit relay in `country`,
    /// containing all the ports in `ports`.
    ///
    /// If the list of ports is empty, it is disregarded.
    // TODO GEOIP: this method is hacky, and should be refactored.
    pub(crate) fn in_given_country(
        country: CountryCode,
        wantports: impl IntoIterator<Item = TargetPort>,
    ) -> Self {
        let ports: Vec<TargetPort> = wantports.into_iter().collect();
        Self {
            inner: ExitPathBuilderInner::ExitInCountry { country, ports },
            compatible_with: None,
            require_stability: true,
        }
    }

    /// Create a new builder that will try to get any exit relay at all.
    pub(crate) fn for_any_exit() -> Self {
        Self {
            inner: ExitPathBuilderInner::AnyExit { strict: true },
            compatible_with: None,
            require_stability: false,
        }
    }

    /// Try to create and return a path corresponding to the requirements of
    /// this builder.
    pub(crate) fn pick_path<'a, R: Rng, RT: Runtime>(
        &self,
        rng: &mut R,
        netdir: DirInfo<'a>,
        guards: &GuardMgr<RT>,
        config: &PathConfig,
        now: SystemTime,
    ) -> Result<(TorPath<'a>, GuardMonitor, GuardUsable)> {
        pick_path(self, rng, netdir, guards, config, now)
    }

    /// Create a new builder that will try to get an exit relay, but which
    /// will be satisfied with a non-exit relay.
    pub(crate) fn for_timeout_testing() -> Self {
        Self {
            inner: ExitPathBuilderInner::AnyExit { strict: false },
            compatible_with: None,
            require_stability: false,
        }
    }

    /// Indicate that middle and exit relays on this circuit need (or do not
    /// need) to have the Stable flag.
    pub(crate) fn require_stability(&mut self, require_stability: bool) -> &mut Self {
        self.require_stability = require_stability;
        self
    }
}

impl AnonymousPathBuilder for ExitPathBuilder {
    fn compatible_with(&self) -> Option<&OwnedChanTarget> {
        self.compatible_with.as_ref()
    }

    fn pick_exit<'a, R: Rng>(
        &self,
        rng: &mut R,
        netdir: &'a NetDir,
        guard_exclusion: RelayExclusion<'a>,
        rs_cfg: &RelaySelectionConfig<'_>,
    ) -> Result<(Relay<'a>, RelayUsage)> {
        let selector = match &self.inner {
            ExitPathBuilderInner::AnyExit { strict } => {
                let mut selector =
                    RelaySelector::new(RelayUsage::any_exit(rs_cfg), guard_exclusion);
                if !strict {
                    selector.mark_usage_flexible();
                }
                selector
            }

            #[cfg(feature = "geoip")]
            ExitPathBuilderInner::ExitInCountry { country, ports } => {
                let mut selector = RelaySelector::new(
                    RelayUsage::exit_to_all_ports(rs_cfg, ports.clone()),
                    guard_exclusion,
                );
                selector.push_restriction(RelayRestriction::require_country_code(*country));
                selector
            }

            ExitPathBuilderInner::WantsPorts(wantports) => RelaySelector::new(
                RelayUsage::exit_to_all_ports(rs_cfg, wantports.clone()),
                guard_exclusion,
            ),
        };

        let (relay, info) = selector.select_relay(rng, netdir);
        let relay = relay.ok_or_else(|| Error::NoRelay {
            path_kind: self.path_kind(),
            role: "final hop",
            problem: info.to_string(),
        })?;
        Ok((relay, RelayUsage::middle_relay(Some(selector.usage()))))
    }

    fn path_kind(&self) -> &'static str {
        use ExitPathBuilderInner::*;
        match &self.inner {
            WantsPorts(_) => "exit circuit",
            #[cfg(feature = "geoip")]
            ExitInCountry { .. } => "country-specific exit circuit",
            AnyExit { .. } => "testing circuit",
        }
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::path::{
        assert_same_path_when_owned, MaybeOwnedRelay, OwnedPath, TorPath, TorPathInner,
    };
    use std::collections::HashSet;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_guardmgr::TestConfig;
    use tor_linkspec::{HasRelayIds, RelayIds};
    use tor_netdir::{testnet, SubnetConfig};
    use tor_persist::TestingStateMgr;
    use tor_relay_selection::LowLevelRelayPredicate;
    use tor_rtcompat::SleepProvider;

    impl<'a> MaybeOwnedRelay<'a> {
        fn can_share_circuit(
            &self,
            other: &MaybeOwnedRelay<'_>,
            subnet_config: SubnetConfig,
        ) -> bool {
            use MaybeOwnedRelay as M;
            match (self, other) {
                (M::Relay(a), M::Relay(b)) => {
                    let ports = Default::default();
                    let cfg = RelaySelectionConfig {
                        long_lived_ports: &ports,
                        subnet_config,
                    };
                    // This use of "low_level_predicate_permits_relay" is okay because
                    // because we're in tests.
                    RelayExclusion::exclude_relays_in_same_family(&cfg, vec![a.clone()])
                        .low_level_predicate_permits_relay(b)
                }
                (a, b) => !subnet_config.any_addrs_in_same_subnet(a, b),
            }
        }
    }

    fn assert_exit_path_ok(relays: &[MaybeOwnedRelay<'_>]) {
        assert_eq!(relays.len(), 3);

        let r1 = &relays[0];
        let r2 = &relays[1];
        let r3 = &relays[2];

        if let MaybeOwnedRelay::Relay(r1) = r1 {
            assert!(r1.low_level_details().is_suitable_as_guard());
        }

        assert!(!r1.same_relay_ids(r2));
        assert!(!r1.same_relay_ids(r3));
        assert!(!r2.same_relay_ids(r3));

        let subnet_config = SubnetConfig::default();
        assert!(r1.can_share_circuit(r2, subnet_config));
        assert!(r2.can_share_circuit(r3, subnet_config));
        assert!(r1.can_share_circuit(r3, subnet_config));
    }

    #[test]
    fn by_ports() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let mut rng = testing_rng();
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let ports = vec![TargetPort::ipv4(443), TargetPort::ipv4(1119)];
            let dirinfo = (&netdir).into();
            let config = PathConfig::default();
            let statemgr = TestingStateMgr::new();
            let guards =
                tor_guardmgr::GuardMgr::new(rt.clone(), statemgr, &TestConfig::default()).unwrap();
            guards.install_test_netdir(&netdir);
            let now = SystemTime::now();

            for _ in 0..1000 {
                let (path, _, _) = ExitPathBuilder::from_target_ports(ports.clone())
                    .pick_path(&mut rng, dirinfo, &guards, &config, now)
                    .unwrap();

                assert_same_path_when_owned(&path);

                if let TorPathInner::Path(p) = path.inner {
                    assert_exit_path_ok(&p[..]);
                    let exit = match &p[2] {
                        MaybeOwnedRelay::Relay(r) => r,
                        MaybeOwnedRelay::Owned(_) => panic!("Didn't asked for an owned target!"),
                    };
                    assert!(exit.low_level_details().ipv4_policy().allows_port(1119));
                } else {
                    panic!("Generated the wrong kind of path");
                }
            }
        });
    }

    #[test]
    fn any_exit() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let mut rng = testing_rng();
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let dirinfo = (&netdir).into();
            let statemgr = TestingStateMgr::new();
            let guards =
                tor_guardmgr::GuardMgr::new(rt.clone(), statemgr, &TestConfig::default()).unwrap();
            guards.install_test_netdir(&netdir);
            let now = SystemTime::now();

            let config = PathConfig::default();
            for _ in 0..1000 {
                let (path, _, _) = ExitPathBuilder::for_any_exit()
                    .pick_path(&mut rng, dirinfo, &guards, &config, now)
                    .unwrap();
                assert_same_path_when_owned(&path);
                if let TorPathInner::Path(p) = path.inner {
                    assert_exit_path_ok(&p[..]);
                    let exit = match &p[2] {
                        MaybeOwnedRelay::Relay(r) => r,
                        MaybeOwnedRelay::Owned(_) => panic!("Didn't asked for an owned target!"),
                    };
                    assert!(exit.low_level_details().policies_allow_some_port());
                } else {
                    panic!("Generated the wrong kind of path");
                }
            }
        });
    }

    #[test]
    fn empty_path() {
        // This shouldn't actually be constructable IRL, but let's test to
        // make sure our code can handle it.
        let bogus_path = TorPath {
            inner: TorPathInner::Path(vec![]),
        };

        assert!(bogus_path.exit_relay().is_none());
        assert!(bogus_path.exit_policy().is_none());
        assert_eq!(bogus_path.len(), 0);

        let owned: Result<OwnedPath> = (&bogus_path).try_into();
        assert!(owned.is_err());
    }

    #[test]
    fn no_exits() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            // Construct a netdir with no exits.
            let netdir = testnet::construct_custom_netdir(|_idx, bld| {
                bld.md.parse_ipv4_policy("reject 1-65535").unwrap();
            })
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();
            let mut rng = testing_rng();
            let dirinfo = (&netdir).into();
            let statemgr = TestingStateMgr::new();
            let guards =
                tor_guardmgr::GuardMgr::new(rt.clone(), statemgr, &TestConfig::default()).unwrap();
            guards.install_test_netdir(&netdir);
            let config = PathConfig::default();
            let now = SystemTime::now();

            // With target ports
            let outcome = ExitPathBuilder::from_target_ports(vec![TargetPort::ipv4(80)])
                .pick_path(&mut rng, dirinfo, &guards, &config, now);
            assert!(outcome.is_err());
            assert!(matches!(outcome, Err(Error::NoRelay { .. })));

            // For any exit
            let outcome =
                ExitPathBuilder::for_any_exit().pick_path(&mut rng, dirinfo, &guards, &config, now);
            assert!(outcome.is_err());
            assert!(matches!(outcome, Err(Error::NoRelay { .. })));

            // For any exit (non-strict, so this will work).
            let outcome = ExitPathBuilder::for_timeout_testing()
                .pick_path(&mut rng, dirinfo, &guards, &config, now);
            assert!(outcome.is_ok());
        });
    }

    #[test]
    fn exitpath_with_guards() {
        use tor_guardmgr::GuardStatus;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let mut rng = testing_rng();
            let dirinfo = (&netdir).into();
            let statemgr = TestingStateMgr::new();
            let guards =
                tor_guardmgr::GuardMgr::new(rt.clone(), statemgr, &TestConfig::default()).unwrap();
            let config = PathConfig::default();
            guards.install_test_netdir(&netdir);
            let port443 = TargetPort::ipv4(443);

            // We're going to just have these all succeed and make sure
            // that they pick the same guard.  We won't test failing
            // cases here, since those are tested in guardmgr.
            let mut distinct_guards = HashSet::new();
            let mut distinct_mid = HashSet::new();
            let mut distinct_exit = HashSet::new();
            for _ in 0..20 {
                let (path, mon, usable) = ExitPathBuilder::from_target_ports(vec![port443])
                    .pick_path(&mut rng, dirinfo, &guards, &config, rt.wallclock())
                    .unwrap();
                assert_eq!(path.len(), 3);
                assert_same_path_when_owned(&path);
                if let TorPathInner::Path(p) = path.inner {
                    assert_exit_path_ok(&p[..]);
                    distinct_guards.insert(RelayIds::from_relay_ids(&p[0]));
                    distinct_mid.insert(RelayIds::from_relay_ids(&p[1]));
                    distinct_exit.insert(RelayIds::from_relay_ids(&p[2]));
                } else {
                    panic!("Wrong kind of path");
                }
                assert!(matches!(
                    mon.inspect_pending_status(),
                    (GuardStatus::AttemptAbandoned, false)
                ));
                mon.succeeded();
                assert!(usable.await.unwrap());
            }
            assert_eq!(distinct_guards.len(), 1);
            assert_ne!(distinct_mid.len(), 1);
            assert_ne!(distinct_exit.len(), 1);
        });
    }
}
