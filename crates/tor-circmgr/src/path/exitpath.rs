//! Code for building paths to an exit relay.

use super::{MaybeOwnedRelay, TorPath};
use crate::{DirInfo, Error, PathConfig, Result, TargetPort};
use rand::Rng;
use std::time::SystemTime;
use tor_error::{bad_api_usage, internal};
#[cfg(feature = "geoip")]
use tor_geoip::CountryCode;
use tor_guardmgr::{GuardMgr, GuardMonitor, GuardUsable};
use tor_linkspec::{HasRelayIds, OwnedChanTarget, RelayIdSet};
use tor_netdir::{NetDir, Relay};
use tor_relay_selection::{
    RelayExclusion, RelayRestriction, RelaySelectionConfig, RelaySelector, RelayUsage,
};
use tor_rtcompat::Runtime;

/// Internal representation of PathBuilder.
enum ExitPathBuilderInner<'a> {
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

    /// Request a path to any relay, even those that cannot exit.
    // TODO: #785 may make this non-conditional.
    #[cfg(feature = "hs-common")]
    AnyRelay,

    /// Request a path that uses a given relay as exit node.
    ChosenExit(Relay<'a>),
}

/// A PathBuilder that builds a path to an exit relay supporting a given
/// set of ports.
///
/// NOTE: The name of this type is no longer completely apt: given some circuits,
/// it is happy to build a circuit ending at a non-exit.
pub struct ExitPathBuilder<'a> {
    /// The inner ExitPathBuilder state.
    inner: ExitPathBuilderInner<'a>,
    /// If present, a "target" that every chosen relay must be able to share a circuit with with.
    compatible_with: Option<OwnedChanTarget>,
    /// If true, all relays on this path must be Stable.
    require_stability: bool,
}

impl<'a> ExitPathBuilder<'a> {
    /// Create a new builder that will try to get an exit relay
    /// containing all the ports in `ports`.
    ///
    /// If the list of ports is empty, tries to get any exit relay at all.
    pub fn from_target_ports(wantports: impl IntoIterator<Item = TargetPort>) -> Self {
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
    pub fn in_given_country(
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

    /// Create a new builder that will try to build a path with the given exit
    /// relay as the last hop.
    pub fn from_chosen_exit(exit_relay: Relay<'a>) -> Self {
        Self {
            inner: ExitPathBuilderInner::ChosenExit(exit_relay),
            compatible_with: None,
            require_stability: true,
        }
    }

    /// Create a new builder that will try to get any exit relay at all.
    pub fn for_any_exit() -> Self {
        Self {
            inner: ExitPathBuilderInner::AnyExit { strict: true },
            compatible_with: None,
            require_stability: false,
        }
    }

    /// Create a new builder that will try to build a three-hop non-exit path
    /// that is compatible with being extended to an optional given relay.
    ///
    /// (The provided relay is _not_ included in the built path: we only ensure
    /// that the path we build does not have any features that would stop us
    /// extending it to that relay as a fourth hop.)
    ///
    /// TODO: This doesn't seem to belong in a type called ExitPathBuilder.
    /// Perhaps we should rename ExitPathBuilder, split it into multiple types,
    /// or move this method.
    #[cfg(feature = "hs-common")]
    pub(crate) fn for_any_compatible_with(compatible_with: Option<OwnedChanTarget>) -> Self {
        Self {
            inner: ExitPathBuilderInner::AnyRelay,
            compatible_with,
            require_stability: true,
        }
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

    /// Find a suitable exit node from either the chosen exit or from the network directory.
    ///
    /// Return the exit, along with the usage for a middle node corresponding
    /// to this exit.
    fn pick_exit<R: Rng>(
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

            #[cfg(feature = "hs-common")]
            ExitPathBuilderInner::AnyRelay => {
                // XXXX This enum variant is badly named!
                RelaySelector::new(RelayUsage::any_exit(rs_cfg), guard_exclusion)
            }

            ExitPathBuilderInner::WantsPorts(wantports) => RelaySelector::new(
                RelayUsage::exit_to_all_ports(rs_cfg, wantports.clone()),
                guard_exclusion,
            ),

            ExitPathBuilderInner::ChosenExit(exit_relay) => {
                // NOTE that this doesn't check
                // relays_can_share_circuit_opt(exit_relay,guard).  we
                // already did that, sort of, in pick_path.
                return Ok((exit_relay.clone(), RelayUsage::middle_relay(None)));
            }
        };

        let (relay, info) = selector.select_relay(rng, netdir);
        let relay = relay.ok_or_else(|| Error::NoRelay {
            path_kind: self.path_kind(),
            role: "final hop",
            problem: info.to_string(),
        })?;
        Ok((relay, RelayUsage::middle_relay(Some(selector.usage()))))
    }

    /// Try to create and return a path corresponding to the requirements of
    /// this builder.
    pub fn pick_path<R: Rng, RT: Runtime>(
        &self,
        rng: &mut R,
        netdir: DirInfo<'a>,
        guards: Option<&GuardMgr<RT>>,
        config: &PathConfig,
        _now: SystemTime,
    ) -> Result<(TorPath<'a>, Option<GuardMonitor>, Option<GuardUsable>)> {
        let netdir = match netdir {
            DirInfo::Directory(d) => d,
            _ => {
                return Err(bad_api_usage!(
                    "Tried to build a multihop path without a network directory"
                )
                .into())
            }
        };
        let rs_cfg = config.relay_selection_config();

        let chosen_exit = if let ExitPathBuilderInner::ChosenExit(e) = &self.inner {
            Some(e)
        } else {
            None
        };
        let path_is_fully_random = chosen_exit.is_none();

        // TODO-SPEC: Because of limitations in guard selection, we have to
        // pick the guard before the exit, which is not what our spec says.
        let (guard, mon, usable) = match guards {
            Some(guardmgr) => {
                // TODO: Extract this section into its own function, and see
                // what it can share with tor_relay_selection.
                let mut b = tor_guardmgr::GuardUsageBuilder::default();
                b.kind(tor_guardmgr::GuardUsageKind::Data);
                if let Some(exit_relay) = chosen_exit {
                    // TODO(nickm): Our way of building a family here is
                    // somewhat questionable. We're only adding the ed25519
                    // identities of the exit relay and its family to the
                    // RelayId set.  That's fine for now, since we will only use
                    // relays at this point if they have a known Ed25519
                    // identity.  But if in the future the ed25519 identity
                    // becomes optional, this will need to change.
                    let mut family = RelayIdSet::new();
                    family.insert(*exit_relay.id());
                    // TODO(nickm): See "limitations" note on `known_family_members`.
                    family.extend(netdir.known_family_members(exit_relay).map(|r| *r.id()));
                    b.restrictions()
                        .push(tor_guardmgr::GuardRestriction::AvoidAllIds(family));
                }
                if let Some(avoid_target) = &self.compatible_with {
                    let mut family = RelayIdSet::new();
                    family.extend(avoid_target.identities().map(|id| id.to_owned()));
                    if let Some(avoid_relay) = netdir.by_ids(avoid_target) {
                        family.extend(netdir.known_family_members(&avoid_relay).map(|r| *r.id()));
                    }
                    b.restrictions()
                        .push(tor_guardmgr::GuardRestriction::AvoidAllIds(family));
                }
                let guard_usage = b.build().expect("Failed while building guard usage!");
                let (guard, mut mon, usable) = guardmgr.select_guard(guard_usage)?;
                let guard = if let Some(ct) = guard.as_circ_target() {
                    // This is a bridge; we will not look for it in the network directory.
                    MaybeOwnedRelay::from(ct.clone())
                } else {
                    // Look this up in the network directory: we expect to find a relay.
                    guard
                        .get_relay(netdir)
                        .ok_or_else(|| {
                            internal!(
                                "Somehow the guardmgr gave us an unlisted guard {:?}!",
                                guard
                            )
                        })?
                        .into()
                };
                if !path_is_fully_random {
                    // We were given a specific exit relay to use, and
                    // the choice of exit relay might be forced by
                    // something outside of our control.
                    //
                    // Therefore, we must not blame the guard for any failure
                    // to complete the circuit.
                    mon.ignore_indeterminate_status();
                }
                (guard, Some(mon), Some(usable))
            }
            None => {
                let rs_cfg = config.relay_selection_config();
                let exclusion = match chosen_exit {
                    Some(r) => {
                        RelayExclusion::exclude_relays_in_same_family(&rs_cfg, vec![r.clone()])
                    }
                    None => RelayExclusion::no_relays_excluded(),
                };
                let selector = RelaySelector::new(RelayUsage::new_guard(), exclusion);
                let (relay, info) = selector.select_relay(rng, netdir);
                let relay = relay.ok_or_else(|| Error::NoRelay {
                    path_kind: self.path_kind(),
                    role: "entry",
                    problem: info.to_string(),
                })?;

                (MaybeOwnedRelay::from(relay), None, None)
            }
        };

        let guard_exclusion = match &guard {
            MaybeOwnedRelay::Relay(r) => RelayExclusion::exclude_relays_in_same_family(
                &config.relay_selection_config(),
                vec![r.clone()],
            ),
            MaybeOwnedRelay::Owned(ct) => RelayExclusion::exclude_channel_target_family(
                &config.relay_selection_config(),
                ct.as_ref(),
                netdir,
            ),
        };

        let (exit, middle_usage) = self.pick_exit(rng, netdir, guard_exclusion.clone(), &rs_cfg)?;

        let mut family_exclusion =
            RelayExclusion::exclude_relays_in_same_family(&rs_cfg, vec![exit.clone()]);
        family_exclusion.extend(&guard_exclusion);

        let selector = RelaySelector::new(middle_usage, family_exclusion);
        let (middle, info) = selector.select_relay(rng, netdir);
        let middle = middle.ok_or_else(|| Error::NoRelay {
            path_kind: self.path_kind(),
            role: "middle relay",
            problem: info.to_string(),
        })?;

        Ok((
            TorPath::new_multihop_from_maybe_owned(vec![
                guard,
                MaybeOwnedRelay::from(middle),
                MaybeOwnedRelay::from(exit),
            ]),
            mon,
            usable,
        ))
    }

    /// Return a short description of the path we're trying to build,
    /// for error reporting purposes.
    fn path_kind(&self) -> &'static str {
        use ExitPathBuilderInner::*;
        match &self.inner {
            WantsPorts(_) => "exit circuit",
            #[cfg(feature = "geoip")]
            ExitInCountry { .. } => "country-specific exit circuit",
            AnyExit { .. } => "testing circuit",
            AnyRelay => "onion-service circuit", // XXXX badly named.
            ChosenExit(_) => "circuit to a specific exit",
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
    use crate::path::{assert_same_path_when_owned, MaybeOwnedRelay, OwnedPath, TorPathInner};
    use crate::test::OptDummyGuardMgr;
    use std::collections::HashSet;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_guardmgr::TestConfig;
    use tor_linkspec::{HasRelayIds, RelayIds};
    use tor_llcrypto::pk::ed25519::Ed25519Identity;
    use tor_netdir::{testnet, SubnetConfig};
    use tor_rtcompat::SleepProvider;

    /// Returns true if both relays can appear together in the same circuit.
    fn relays_can_share_circuit(
        a: &Relay<'_>,
        b: &MaybeOwnedRelay<'_>,
        subnet_config: SubnetConfig,
    ) -> bool {
        if let MaybeOwnedRelay::Relay(r) = b {
            if a.in_same_family(r) {
                return false;
            };
        }

        !subnet_config.any_addrs_in_same_subnet(a, b)
    }

    impl<'a> MaybeOwnedRelay<'a> {
        fn can_share_circuit(
            &self,
            other: &MaybeOwnedRelay<'_>,
            subnet_config: SubnetConfig,
        ) -> bool {
            match self {
                MaybeOwnedRelay::Relay(r) => relays_can_share_circuit(r, other, subnet_config),
                MaybeOwnedRelay::Owned(r) => {
                    !subnet_config.any_addrs_in_same_subnet(r.as_ref(), other)
                }
            }
        }
    }

    fn assert_exit_path_ok(relays: &[MaybeOwnedRelay<'_>]) {
        assert_eq!(relays.len(), 3);

        // TODO: Eventually assert that r1 has Guard, once we enforce that.

        let r1 = &relays[0];
        let r2 = &relays[1];
        let r3 = &relays[2];

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
        let mut rng = testing_rng();
        let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
        let ports = vec![TargetPort::ipv4(443), TargetPort::ipv4(1119)];
        let dirinfo = (&netdir).into();
        let config = PathConfig::default();
        let guards: OptDummyGuardMgr<'_> = None;
        let now = SystemTime::now();

        for _ in 0..1000 {
            let (path, _, _) = ExitPathBuilder::from_target_ports(ports.clone())
                .pick_path(&mut rng, dirinfo, guards, &config, now)
                .unwrap();

            assert_same_path_when_owned(&path);

            if let TorPathInner::Path(p) = path.inner {
                assert_exit_path_ok(&p[..]);
                let exit = match &p[2] {
                    MaybeOwnedRelay::Relay(r) => r,
                    MaybeOwnedRelay::Owned(_) => panic!("Didn't asked for an owned target!"),
                };
                assert!(exit.ipv4_policy().allows_port(1119));
            } else {
                panic!("Generated the wrong kind of path");
            }
        }

        let chosen = netdir.by_id(&Ed25519Identity::from([0x20; 32])).unwrap();

        let config = PathConfig::default();
        for _ in 0..1000 {
            let (path, _, _) = ExitPathBuilder::from_chosen_exit(chosen.clone())
                .pick_path(&mut rng, dirinfo, guards, &config, now)
                .unwrap();
            assert_same_path_when_owned(&path);
            if let TorPathInner::Path(p) = path.inner {
                assert_exit_path_ok(&p[..]);
                let exit = &p[2];
                assert!(exit.same_relay_ids(&chosen));
            } else {
                panic!("Generated the wrong kind of path");
            }
        }
    }

    #[test]
    fn any_exit() {
        let mut rng = testing_rng();
        let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
        let dirinfo = (&netdir).into();
        let guards: OptDummyGuardMgr<'_> = None;
        let now = SystemTime::now();

        let config = PathConfig::default();
        for _ in 0..1000 {
            let (path, _, _) = ExitPathBuilder::for_any_exit()
                .pick_path(&mut rng, dirinfo, guards, &config, now)
                .unwrap();
            assert_same_path_when_owned(&path);
            if let TorPathInner::Path(p) = path.inner {
                assert_exit_path_ok(&p[..]);
                let exit = match &p[2] {
                    MaybeOwnedRelay::Relay(r) => r,
                    MaybeOwnedRelay::Owned(_) => panic!("Didn't asked for an owned target!"),
                };
                assert!(exit.policies_allow_some_port());
            } else {
                panic!("Generated the wrong kind of path");
            }
        }
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
        // Construct a netdir with no exits.
        let netdir = testnet::construct_custom_netdir(|_idx, bld| {
            bld.md.parse_ipv4_policy("reject 1-65535").unwrap();
        })
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();
        let mut rng = testing_rng();
        let dirinfo = (&netdir).into();
        let guards: OptDummyGuardMgr<'_> = None;
        let config = PathConfig::default();
        let now = SystemTime::now();

        // With target ports
        let outcome = ExitPathBuilder::from_target_ports(vec![TargetPort::ipv4(80)])
            .pick_path(&mut rng, dirinfo, guards, &config, now);
        assert!(outcome.is_err());
        assert!(matches!(outcome, Err(Error::NoRelay { .. })));

        // For any exit
        let outcome =
            ExitPathBuilder::for_any_exit().pick_path(&mut rng, dirinfo, guards, &config, now);
        assert!(outcome.is_err());
        assert!(matches!(outcome, Err(Error::NoRelay { .. })));

        // For any exit (non-strict, so this will work).
        let outcome = ExitPathBuilder::for_timeout_testing()
            .pick_path(&mut rng, dirinfo, guards, &config, now);
        assert!(outcome.is_ok());
    }

    #[test]
    fn exitpath_with_guards() {
        use tor_guardmgr::GuardStatus;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let mut rng = testing_rng();
            let dirinfo = (&netdir).into();
            let statemgr = tor_persist::TestingStateMgr::new();
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
                    .pick_path(&mut rng, dirinfo, Some(&guards), &config, rt.wallclock())
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
                let mon = mon.unwrap();
                assert!(matches!(
                    mon.inspect_pending_status(),
                    (GuardStatus::AttemptAbandoned, false)
                ));
                mon.succeeded();
                assert!(usable.unwrap().await.unwrap());
            }
            assert_eq!(distinct_guards.len(), 1);
            assert_ne!(distinct_mid.len(), 1);
            assert_ne!(distinct_exit.len(), 1);

            let guard_relay = netdir
                .by_ids(distinct_guards.iter().next().unwrap())
                .unwrap();
            let exit_relay = netdir.by_ids(distinct_exit.iter().next().unwrap()).unwrap();

            // Now we'll try a forced exit that is not the same as our
            // actual guard.
            let (path, mon, usable) = ExitPathBuilder::from_chosen_exit(exit_relay.clone())
                .pick_path(&mut rng, dirinfo, Some(&guards), &config, rt.wallclock())
                .unwrap();
            assert_eq!(path.len(), 3);
            if let TorPathInner::Path(p) = path.inner {
                assert_exit_path_ok(&p[..]);
                // We get our regular guard and our chosen exit.
                assert_eq!(p[0].ed_identity(), guard_relay.ed_identity());
                assert_eq!(p[2].ed_identity(), exit_relay.ed_identity());
            } else {
                panic!("Wrong kind of path");
            }
            let mon = mon.unwrap();
            // This time, "ignore indeterminate status" was set to true.
            assert!(matches!(
                mon.inspect_pending_status(),
                (GuardStatus::AttemptAbandoned, true)
            ));
            mon.succeeded();
            assert!(usable.unwrap().await.unwrap());

            // Finally, try with our exit forced to be our regular guard,
            // and make sure we get a different guard.
            let (path, mon, usable) = ExitPathBuilder::from_chosen_exit(guard_relay.clone())
                .pick_path(&mut rng, dirinfo, Some(&guards), &config, rt.wallclock())
                .unwrap();
            assert_eq!(path.len(), 3);
            if let TorPathInner::Path(p) = path.inner {
                // This is no longer guaranteed; see arti#183 :(
                // assert_exit_path_ok(&p[..]);
                // We get our chosen exit, and a different guard.
                assert_ne!(p[0].ed_identity(), guard_relay.ed_identity());
                assert_eq!(p[2].ed_identity(), guard_relay.ed_identity());
            } else {
                panic!("Wrong kind of path");
            }
            let mon = mon.unwrap();
            // This time, "ignore indeterminate status" was set to true.
            assert!(matches!(
                mon.inspect_pending_status(),
                (GuardStatus::AttemptAbandoned, true)
            ));
            mon.succeeded();
            assert!(usable.unwrap().await.unwrap());
        });
    }
}
