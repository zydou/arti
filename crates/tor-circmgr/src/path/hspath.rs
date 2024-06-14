//! Code for building paths for HS circuits.
//!
//! The path builders defined here are used for creating hidden service stub circuits,
//! which are three- or four-hop circuits that have not yet been extended to a target.
//!
//! There are two types of stub circuits:
//!   * short stub circuits, used for building circuits to a final hop that an adversary
//!     cannot easily control (for example if the target is randomly chosen by us)
//!   * extended stub circuits, used for building circuits to a final hop that an adversary
//!     can easily control (for example if the target was not chosen by us)
//!
//! Stub circuits eventually become introduction, rendezvous, and HsDir circuits.
//! For all circuit types except client rendezvous, the stubs must first be
//! extended by an extra hop:
//!
//! ```text
//!  Client hsdir:  EXTENDED -> HsDir
//!  Client intro:  EXTENDED -> Ipt
//!  Client rend:   SHORT
//!  Service hsdir: SHORT    -> HsDir
//!  Service intro: SHORT    -> Ipt
//!  Service rend:  EXTENDED -> Rpt
//! ```
//!
//! If vanguards are disabled, short stub circuits (SHORT),
//! and extended stub circuits (EXTENDED) are the same,
//! and are built using
//! [`ExitPathBuilder`](crate::path::exitpath::ExitPathBuilder)'s
//! path selection rules.
//!
//! If vanguards are enabled, the path is built without applying family
//! or same-subnet restrictions at all, the guard is not prohibited
//! from appearing as either of the last two hops of the circuit,
//! and the two circuit stub kinds are built differently
//! depending on the type of vanguards that are in use:
//!
//!   * with lite vanguards enabled:
//!      ```text
//!         SHORT    = G -> L2 -> M
//!         EXTENDED = G -> L2 -> M
//!      ```
//!
//!   * with full vanguards enabled:
//!      ```text
//!         SHORT    = G -> L2 -> L3
//!         EXTENDED = G -> L2 -> L3 -> M
//!      ```

#[cfg(feature = "vanguards")]
mod vanguards;

use rand::Rng;
use tor_error::internal;
use tor_linkspec::{HasRelayIds, OwnedChanTarget};
use tor_netdir::{NetDir, Relay};
use tor_relay_selection::{
    RelayExclusion, RelaySelectionConfig, RelaySelector, RelayUsage,
};

use crate::{hspool::HsCircStubKind, Error, Result};

use super::AnonymousPathBuilder;

use {
    crate::path::{pick_path, TorPath},
    crate::{DirInfo, PathConfig},
    std::time::SystemTime,
    tor_guardmgr::{GuardMgr, GuardMonitor, GuardUsable},
    tor_rtcompat::Runtime,
};

#[cfg(feature = "vanguards")]
use {
    crate::path::{select_guard, MaybeOwnedRelay},
    tor_error::bad_api_usage,
    tor_guardmgr::vanguards::Layer,
    tor_guardmgr::vanguards::VanguardMgr,
    tor_guardmgr::VanguardMode,
    vanguards::VanguardPath,
};

#[cfg(feature = "vanguards")]
pub(crate) use vanguards::select_middle_for_vanguard_circ;

/// A path builder for hidden service circuits.
///
/// See the [hspath](crate::path::hspath) docs for more details.
pub(crate) struct HsPathBuilder {
    /// If present, a "target" that every chosen relay must be able to share a circuit with with.
    ///
    /// Ignored if vanguards are in use.
    compatible_with: Option<OwnedChanTarget>,
    /// The type of circuit to build.
    ///
    /// This is only used if `vanguards` are enabled.
    #[cfg_attr(not(feature = "vanguards"), allow(dead_code))]
    kind: HsCircStubKind,
}

impl HsPathBuilder {
    /// Create a new builder that will try to build a three-hop non-exit path
    /// for use with the onion services protocols
    /// that is compatible with being extended to an optional given relay.
    ///
    /// (The provided relay is _not_ included in the built path: we only ensure
    /// that the path we build does not have any features that would stop us
    /// extending it to that relay as a fourth hop.)
    pub(crate) fn new(compatible_with: Option<OwnedChanTarget>, kind: HsCircStubKind) -> Self {
        Self {
            compatible_with,
            kind,
        }
    }

    /// Try to create and return a path for a hidden service circuit stub.
    #[cfg_attr(feature = "vanguards", allow(unused))]
    pub(crate) fn pick_path<'a, R: Rng, RT: Runtime>(
        &self,
        rng: &mut R,
        netdir: DirInfo<'a>,
        guards: Option<&GuardMgr<RT>>,
        config: &PathConfig,
        now: SystemTime,
    ) -> Result<(TorPath<'a>, Option<GuardMonitor>, Option<GuardUsable>)> {
        pick_path(self, rng, netdir, guards, config, now)
    }

    /// Try to create and return a path for a hidden service circuit stub.
    ///
    /// If vanguards are disabled, this has the same behavior as
    /// [pick_path](HsPathBuilder::pick_path).
    #[cfg(feature = "vanguards")]
    #[cfg_attr(not(feature = "vanguards"), allow(unused))]
    pub(crate) fn pick_path_with_vanguards<'a, R: Rng, RT: Runtime>(
        &self,
        rng: &mut R,
        netdir: DirInfo<'a>,
        guards: Option<&GuardMgr<RT>>,
        vanguards: &VanguardMgr<RT>,
        config: &PathConfig,
        now: SystemTime,
    ) -> Result<(TorPath<'a>, Option<GuardMonitor>, Option<GuardUsable>)> {
        let mode = vanguards.mode();
        if mode == VanguardMode::Disabled {
            return pick_path(self, rng, netdir, guards, config, now);
        }

        let vanguard_path_builder = VanguardHsPathBuilder {
            kind: self.kind,
            compatible_with: self.compatible_with.clone(),
        };

        vanguard_path_builder.pick_path(rng, netdir, guards, vanguards, config)
    }
}

impl<'a> AnonymousPathBuilder<'a> for HsPathBuilder {
    fn chosen_exit(&self) -> Option<&Relay<'_>> {
        None
    }

    fn compatible_with(&self) -> Option<&OwnedChanTarget> {
        self.compatible_with.as_ref()
    }

    fn path_kind(&self) -> &'static str {
        "onion-service circuit"
    }

    fn pick_exit<'s, R: Rng>(
        &'s self,
        rng: &mut R,
        netdir: &'a NetDir,
        guard_exclusion: RelayExclusion<'a>,
        _rs_cfg: &RelaySelectionConfig<'_>,
    ) -> Result<(Relay<'a>, RelayUsage)> {
        // TODO: This usage is a bit convoluted, and some onion-service-
        // related circuits don't need this much stability.
        let usage = RelayUsage::middle_relay(Some(&RelayUsage::new_intro_point()));
        let selector = RelaySelector::new(usage, guard_exclusion);

        let (relay, info) = selector.select_relay(rng, netdir);
        let relay = relay.ok_or_else(|| Error::NoRelay {
            path_kind: self.path_kind(),
            role: "final hop",
            problem: info.to_string(),
        })?;
        Ok((relay, RelayUsage::middle_relay(Some(selector.usage()))))
    }
}

/// A path builder for hidden service circuits that use vanguards.
///
/// Used by [`HsPathBuilder`] when vanguards are enabled.
///
/// See the [`HsPathBuilder`] documentation for more details.
#[cfg(feature = "vanguards")]
struct VanguardHsPathBuilder {
    /// The kind of circuit stub we are building
    kind: HsCircStubKind,
    /// The target we are about to extend the circuit to.
    compatible_with: Option<OwnedChanTarget>,
}

#[cfg(feature = "vanguards")]
impl VanguardHsPathBuilder {
    /// Try to create and return a path for a hidden service circuit stub.
    fn pick_path<'a, R: Rng, RT: Runtime>(
        &self,
        rng: &mut R,
        netdir: DirInfo<'a>,
        guards: Option<&GuardMgr<RT>>,
        vanguards: &VanguardMgr<RT>,
        config: &PathConfig,
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

        // Select the guard, allowing it to appear as
        // either of the last two hops of the circuit.
        let (l1_guard, mon, usable) =
            select_guard(rng, netdir, guards, config, None, None, self.path_kind())?;

        let target_exclusion = if let Some(target) = self.compatible_with.as_ref() {
            RelayExclusion::exclude_identities(
                target.identities().map(|id| id.to_owned()).collect(),
            )
        } else {
            RelayExclusion::no_relays_excluded()
        };

        let mode = vanguards.mode();
        let path = match mode {
            VanguardMode::Lite => {
                self.pick_lite_vanguard_path(rng, netdir, vanguards, l1_guard, &target_exclusion)?
            }
            VanguardMode::Full => {
                self.pick_full_vanguard_path(rng, netdir, vanguards, l1_guard, &target_exclusion)?
            }
            VanguardMode::Disabled => {
                return Err(internal!(
                    "VanguardHsPathBuilder::pick_path called, but vanguards are disabled?!"
                )
                .into());
            }
            _ => {
                return Err(internal!("unrecognized vanguard mode {mode}").into());
            }
        };

        let actual_len = path.len();
        let expected_len = self.kind.num_hops(mode)?;
        if actual_len != expected_len {
            return Err(internal!(
                "invalid path length for {} {mode}-vanguard circuit (expected {} hops, got {})",
                self.kind,
                expected_len,
                actual_len
            )
            .into());
        }

        Ok((path, mon, usable))
    }

    /// Create a path for a hidden service circuit stub using full vanguards.
    fn pick_full_vanguard_path<'n, R: Rng, RT: Runtime>(
        &self,
        rng: &mut R,
        netdir: &'n NetDir,
        vanguards: &VanguardMgr<RT>,
        l1_guard: MaybeOwnedRelay<'n>,
        target_exclusion: &RelayExclusion<'n>,
    ) -> Result<TorPath<'n>> {
        // NOTE: if the we are using full vanguards and building an EXTENDED circuit stub,
        // we do *not* exclude the target from occurring as the second hop
        // (circuits of the form G - L2 - L3 - M - L2 are valid)
        let l2_target_exclusion = match self.kind {
            HsCircStubKind::Extended => RelayExclusion::no_relays_excluded(),
            HsCircStubKind::Short => target_exclusion.clone(),
        };

        let path = VanguardPath::new(rng, netdir, vanguards, l1_guard);

        let path = path
            .add_vanguard(&l2_target_exclusion, Layer::Layer2)?
            .add_vanguard(target_exclusion, Layer::Layer3)?;

        match self.kind {
            HsCircStubKind::Extended => {
                // If full vanguards are enabled, we need an extra hop for the EXTENDED stub:
                //     SHORT    = G -> L2 -> L3
                //     EXTENDED = G -> L2 -> L3 -> M
                path.add_middle(target_exclusion)?.build()
            }
            HsCircStubKind::Short => path.build(),
        }
    }

    /// Create a path for a hidden service circuit stub using lite vanguards.
    fn pick_lite_vanguard_path<'n, R: Rng, RT: Runtime>(
        &self,
        rng: &mut R,
        netdir: &'n NetDir,
        vanguards: &VanguardMgr<RT>,
        l1_guard: MaybeOwnedRelay<'n>,
        target_exclusion: &RelayExclusion<'n>,
    ) -> Result<TorPath<'n>> {
        VanguardPath::new(rng, netdir, vanguards, l1_guard)
            .add_vanguard(target_exclusion, Layer::Layer2)?
            .add_middle(target_exclusion)?
            .build()
    }

    /// Return a short description of the path we're trying to build,
    /// for error reporting purposes.
    fn path_kind(&self) -> &'static str {
        "onion-service vanguard circuit"
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

    use std::sync::Arc;

    use super::*;

    use tor_linkspec::{ChannelMethod, OwnedCircTarget};
    use tor_netdir::{testnet::NodeBuilders, testprovider::TestNetDirProvider, NetDirProvider};
    use tor_netdoc::doc::netstatus::{RelayFlags, RelayWeight};
    use tor_rtmock::MockRuntime;

    #[cfg(all(feature = "vanguards", feature = "hs-common"))]
    use {
        crate::path::OwnedPath, tor_basic_utils::test_rng::testing_rng,
        tor_guardmgr::VanguardMgrError,
        tor_netdir::testnet::construct_custom_netdir,
    };

    /// The maximum number of relays in a test network.
    const MAX_NET_SIZE: usize = 40;

    /// Construct a test network of the specified size.
    fn construct_test_network<F>(size: usize, mut set_family: F) -> NetDir
    where
        F: FnMut(usize, &mut NodeBuilders),
    {
        assert!(
            size <= MAX_NET_SIZE,
            "the test network supports at most {MAX_NET_SIZE} relays"
        );
        let netdir = construct_custom_netdir(|pos, nb| {
            nb.omit_rs = pos >= size;
            if !nb.omit_rs {
                let f = RelayFlags::RUNNING
                    | RelayFlags::VALID
                    | RelayFlags::V2DIR
                    | RelayFlags::FAST
                    | RelayFlags::STABLE;
                nb.rs.set_flags(f | RelayFlags::GUARD);
                nb.rs.weight(RelayWeight::Measured(10_000));

                set_family(pos, nb);
            }
        })
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();

        assert_eq!(netdir.all_relays().count(), size);

        netdir
    }

    /// Construct a test network where every relay is in the same family with everyone else.
    fn same_family_test_network(size: usize) -> NetDir {
        construct_test_network(size, |_pos, nb| {
            // Everybody is in the same family with everyone else
            let family = (0..MAX_NET_SIZE)
                .map(|i| hex::encode([i as u8; 20]))
                .collect::<Vec<_>>()
                .join(" ");

            nb.md.family(family.parse().unwrap());
        })
    }

    /// Helper for extracting the hops in a `TorPath`.
    fn path_hops(path: &TorPath) -> Vec<OwnedCircTarget> {
        let path: OwnedPath = path.try_into().unwrap();
        match path {
            OwnedPath::ChannelOnly(_) => {
                panic!("expected OwnedPath::Normal, got OwnedPath::ChannelOnly")
            }
            OwnedPath::Normal(ref v) => v.clone(),
        }
    }

    /// Check the uniqueness of the hops from the specified `TorPath`.
    ///
    /// If `expect_dupes` is `true`, asserts that the path has some duplicate hops.
    /// Otherwise, asserts that there are no duplicate hops in the path.
    fn assert_duplicate_hops(path: &TorPath, expect_dupes: bool) {
        let hops = path_hops(path);
        let has_dupes = hops.iter().enumerate().any(|(i, hop)| {
            hops.iter()
                .skip(i + 1)
                .any(|h| h.has_any_relay_id_from(hop))
        });
        let msg = if expect_dupes { "have" } else { "not have any" };

        assert_eq!(
            has_dupes, expect_dupes,
            "expected path to {msg} duplicate hops: {:?}",
            hops
        );
    }

    /// Assert that the specified `TorPath` is a valid path for a circuit using vanguards.
    #[cfg(feature = "vanguards")]
    fn assert_vanguard_path_ok(
        path: &TorPath,
        stub_kind: HsCircStubKind,
        mode: VanguardMode,
        target: Option<&OwnedChanTarget>,
    ) {
        use itertools::Itertools;

        assert_eq!(
            path.len(),
            stub_kind.num_hops(mode).unwrap(),
            "invalid path length for {stub_kind} {mode}-vanguards circuit"
        );

        let hops = path_hops(path);
        for (hop1, hop2, hop3) in hops.iter().tuple_windows() {
            if hop1.has_any_relay_id_from(hop2)
                || hop1.has_any_relay_id_from(hop3)
                || hop2.has_any_relay_id_from(hop3)
            {
                panic!(
                    "neighboring hops should be distinct: [{}], [{}], [{}]",
                    hop1.display_relay_ids(),
                    hop2.display_relay_ids(),
                    hop3.display_relay_ids(),
                );
            }
        }

        // If the circuit had a target, make sure its last 2 hops are compatible with it.
        if let Some(target) = target {
            for hop in hops.iter().rev().take(2) {
                if hop.has_any_relay_id_from(target) {
                    panic!(
                        "invalid path: circuit target {} appears as one of the last 2 hops (matches hop {})",
                        hop.display_relay_ids(),
                        target.display_relay_ids(),
                    );
                }
            }
        }
    }

    /// Assert that the specified `TorPath` is a valid HS path.
    fn assert_hs_path_ok(path: &TorPath, target: Option<&OwnedChanTarget>) {
        assert_eq!(path.len(), 3);
        assert_duplicate_hops(path, false);
        if let Some(target) = target {
            for hop in path_hops(path) {
                if hop.has_any_relay_id_from(target) {
                    panic!(
                        "invalid path: hop {} is the same relay as the circuit target {}",
                        hop.display_relay_ids(),
                        target.display_relay_ids()
                    )
                }
            }
        }
    }

    /// Helper for calling `HsPathBuilder::pick_path_with_vanguards`.
    async fn pick_vanguard_path<'a>(
        runtime: &MockRuntime,
        netdir: &'a NetDir,
        stub_kind: HsCircStubKind,
        mode: VanguardMode,
        target: Option<&OwnedChanTarget>,
    ) -> Result<TorPath<'a>> {
        let vanguardmgr = VanguardMgr::new_testing(runtime, mode).unwrap();
        let _provider = vanguardmgr.init_vanguard_sets(netdir).await.unwrap();

        let mut rng = testing_rng();
        let guards = tor_guardmgr::GuardMgr::new(
            runtime.clone(),
            tor_persist::TestingStateMgr::new(),
            &tor_guardmgr::TestConfig::default(),
        )
        .unwrap();
        let netdir_provider = Arc::new(TestNetDirProvider::new());
        netdir_provider.set_netdir(netdir.clone());
        let netdir_provider: Arc<dyn NetDirProvider> = netdir_provider;
        guards.install_netdir_provider(&netdir_provider).unwrap();
        let config = PathConfig::default();
        let now = SystemTime::now();
        let dirinfo = (netdir).into();
        HsPathBuilder::new(target.cloned(), stub_kind)
            .pick_path_with_vanguards(&mut rng, dirinfo, Some(&guards), &vanguardmgr, &config, now)
            .map(|res| res.0)
    }

    /// Helper for calling `HsPathBuilder::pick_path`.
    fn pick_hs_path_no_vanguards<'a>(
        netdir: &'a NetDir,
        target: Option<&OwnedChanTarget>,
    ) -> Result<TorPath<'a>> {
        let mut rng = testing_rng();
        let config = PathConfig::default();
        let now = SystemTime::now();
        let dirinfo = (netdir).into();
        let guards = tor_guardmgr::GuardMgr::new(
            MockRuntime::new(),
            tor_persist::TestingStateMgr::new(),
            &tor_guardmgr::TestConfig::default(),
        )
        .unwrap();
        let netdir_provider = Arc::new(TestNetDirProvider::new());
        netdir_provider.set_netdir(netdir.clone());
        let netdir_provider: Arc<dyn NetDirProvider> = netdir_provider;
        guards.install_netdir_provider(&netdir_provider).unwrap();
        HsPathBuilder::new(target.cloned(), HsCircStubKind::Short)
            .pick_path(&mut rng, dirinfo, Some(&guards), &config, now)
            .map(|res| res.0)
    }

    /// Return an `OwnedChanTarget` to use as the target of a circuit.
    ///
    /// This will correspond to the "first" relay from the test network
    /// (the one with the $0000000000000000000000000000000000000000
    /// RSA identity fingerprint).
    fn test_target() -> OwnedChanTarget {
        // We target one of the relays known to be the network.
        OwnedChanTarget::builder()
            .addrs(vec!["127.0.0.3:9001".parse().unwrap()])
            .ed_identity([0xAA; 32].into())
            .rsa_identity([0x00; 20].into())
            .method(ChannelMethod::Direct(vec!["0.0.0.3:9001".parse().unwrap()]))
            .build()
            .unwrap()
    }

    // Prevents TROVE-2024-006 (arti#1425).
    //
    // Note: this, and all the other tests that disable vanguards,
    // perhaps belong in ExitPathBuilder, as they are are effectively
    // testing the vanilla pick_path() implementation.
    #[test]
    fn hs_path_no_vanguards_incompatible_target() {
        // We target one of the relays known to be the network.
        let target = test_target();

        let netdir = construct_test_network(3, |pos, nb| {
            // The target is in a family with every other relay,
            // so any circuit we might build is going to be incompatible with it
            if pos == 0 {
                let family = (0..MAX_NET_SIZE)
                    .map(|i| hex::encode([i as u8; 20]))
                    .collect::<Vec<_>>()
                    .join(" ");

                nb.md.family(family.parse().unwrap());
            } else {
                nb.md.family(hex::encode([pos as u8; 20]).parse().unwrap());
            }
        });
        // We'll fail to select a guard, because the network doesn't have any relays compatible
        // with the target
        let err = pick_hs_path_no_vanguards(&netdir, Some(&target))
            .map(|_| ())
            .unwrap_err();

        assert!(
            matches!(
                err,
                Error::NoRelay {
                    ref problem,
                    ..
                } if problem ==  "Failed: rejected 0/3 as useless for middle relay; 3/3 as in same family as already selected"
            ),
            "{err:?}"
        );
    }

    #[test]
    fn hs_path_no_vanguards_reject_same_family() {
        // All the relays in the network are in the same family,
        // so building HS circuits should be impossible.
        let netdir = same_family_test_network(MAX_NET_SIZE);
        let err = match pick_hs_path_no_vanguards(&netdir, None) {
            Ok(path) => panic!(
                "expected error, but got valid path: {:?})",
                OwnedPath::try_from(&path).unwrap()
            ),
            Err(e) => e,
        };

        assert!(
            matches!(
                err,
                Error::NoRelay {
                    ref problem,
                    ..
                } if problem ==  "Failed: rejected 0/40 as useless for middle relay; 40/40 as in same family as already selected"
            ),
            "{err:?}"
        );
    }

    #[test]
    fn hs_path_no_vanguards() {
        let netdir = construct_test_network(20, |pos, nb| {
            nb.md.family(hex::encode([pos as u8; 20]).parse().unwrap());
        });
        // We target one of the relays known to be the network.
        let target = test_target();
        for _ in 0..100 {
            for target in [None, Some(target.clone())] {
                let path = pick_hs_path_no_vanguards(&netdir, target.as_ref()).unwrap();
                assert_hs_path_ok(&path, target.as_ref());
            }
        }
    }

    #[test]
    #[cfg(feature = "vanguards")]
    fn lite_vanguard_path_insufficient_relays() {
        MockRuntime::test_with_various(|runtime| async move {
            let netdir = same_family_test_network(2);
            for stub_kind in [HsCircStubKind::Short, HsCircStubKind::Extended] {
                let err =
                    pick_vanguard_path(&runtime, &netdir, stub_kind, VanguardMode::Lite, None)
                        .await
                        .map(|_| ())
                        .unwrap_err();

                // The test network is too small to build a 3-hop circuit.
                assert!(
                    matches!(
                        err,
                        Error::NoRelay {
                            ref problem,
                            ..
                        } if problem == "Failed: rejected 0/2 as useless for middle relay; 2/2 as already selected",
                    ),
                    "{err:?}"
                );
            }
        });
    }

    // Prevents TROVE-2024-003 (arti#1409).
    #[test]
    #[cfg(feature = "vanguards")]
    fn lite_vanguard_path() {
        MockRuntime::test_with_various(|runtime| async move {
            // We target one of the relays known to be the network.
            let target = OwnedChanTarget::builder()
                .rsa_identity([0x00; 20].into())
                .build()
                .unwrap();
            let netdir = same_family_test_network(10);
            let mode = VanguardMode::Lite;

            for target in [None, Some(target)] {
                for stub_kind in [HsCircStubKind::Short, HsCircStubKind::Extended] {
                    let path =
                        pick_vanguard_path(&runtime, &netdir, stub_kind, mode, target.as_ref())
                            .await
                            .unwrap();
                    assert_vanguard_path_ok(&path, stub_kind, mode, target.as_ref());
                }
            }
        });
    }

    #[test]
    #[cfg(feature = "vanguards")]
    fn full_vanguard_path() {
        MockRuntime::test_with_various(|runtime| async move {
            let netdir = same_family_test_network(MAX_NET_SIZE);
            let mode = VanguardMode::Full;

            // We target one of the relays known to be the network.
            let target = OwnedChanTarget::builder()
                .rsa_identity([0x00; 20].into())
                .build()
                .unwrap();

            for target in [None, Some(target)] {
                for stub_kind in [HsCircStubKind::Short, HsCircStubKind::Extended] {
                    let path =
                        pick_vanguard_path(&runtime, &netdir, stub_kind, mode, target.as_ref())
                            .await
                            .unwrap();
                    assert_vanguard_path_ok(&path, stub_kind, mode, target.as_ref());
                }
            }
        });
    }

    #[test]
    #[cfg(feature = "vanguards")]
    fn full_vanguard_path_insufficient_relays() {
        MockRuntime::test_with_various(|runtime| async move {
            let netdir = same_family_test_network(2);

            for stub_kind in [HsCircStubKind::Short, HsCircStubKind::Extended] {
                let err =
                    pick_vanguard_path(&runtime, &netdir, stub_kind, VanguardMode::Full, None)
                        .await
                        .map(|_| ())
                        .unwrap_err();
                assert!(
                    matches!(
                        err,
                        Error::VanguardMgrInit(VanguardMgrError::NoSuitableRelay(Layer::Layer3)),
                    ),
                    "{err:?}"
                );
            }

            // We *can* build stub circuits in a 3-relay network,
            // as long as they don't have a specified target
            let netdir = same_family_test_network(3);
            let mode = VanguardMode::Full;

            for stub_kind in [HsCircStubKind::Short, HsCircStubKind::Extended] {
                let path = pick_vanguard_path(&runtime, &netdir, stub_kind, mode, None)
                    .await
                    .unwrap();
                assert_vanguard_path_ok(&path, stub_kind, mode, None);
                match stub_kind {
                    HsCircStubKind::Short => {
                        // A 3-hop circuit can't contain duplicates,
                        // because that would mean it has one of the following
                        // configurations
                        //
                        //     A - A - A
                        //     A - A - B
                        //     A - B - A
                        //     A - B - B
                        //     B - A - A
                        //     B - A - B
                        //     B - B - A
                        //     B - B - B
                        //
                        // none of which are valid circuits, because a relay won't extend
                        // to itself or its predecessor.
                        assert_duplicate_hops(&path, false);
                    }
                    HsCircStubKind::Extended => {
                        // There are only 3 relats in the network,
                        // so a 4-hop circuit must contain the same hop twice.
                        assert_duplicate_hops(&path, true);
                    }
                }
            }
        });
    }
}
