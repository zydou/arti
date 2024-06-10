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

use rand::Rng;
use tor_error::internal;
use tor_linkspec::OwnedChanTarget;
use tor_netdir::{NetDir, Relay};
use tor_relay_selection::{
    RelayExclusion, RelaySelectionConfig, RelaySelector, RelayUsage, SelectionInfo,
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
};

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
    //
    //
    // TODO(#1459): refactor the way we apply restrictions in this function to be more readable.
    fn pick_path<'a, R: Rng, RT: Runtime>(
        &self,
        rng: &mut R,
        netdir: DirInfo<'a>,
        guards: Option<&GuardMgr<RT>>,
        vanguards: &VanguardMgr<RT>,
        config: &PathConfig,
    ) -> Result<(TorPath<'a>, Option<GuardMonitor>, Option<GuardUsable>)> {
        use tor_linkspec::HasRelayIds;

        // TODO: this is copied from pick_path
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

        // Select the vanguards

        // We must exclude the guard, because it cannot be selected again as an L2 vanguard
        // (a relay won't let you extend the circuit to itself).
        //
        // TODO #504: Unaccompanied RelayExclusions
        //
        // NOTE: if the we are using full vanguards and building an EXTENDED circuit stub,
        // this will *not* exclude the target (only the the L1 guard).
        let mut exclude_guard_and_target = exclude_identities(&[&l1_guard]);

        // We need to exclude the target from being selected as
        //   * the L2 or middle hop, if using lite-vanguards
        //   * the L2 or L3 hop, if building a SHORT circuit stub with full-vanguards
        //   * the L3 or "middle" (4th) hop, if building a EXTENDED circuit stub with full-vanguards
        let target_exclusion = if let Some(target) = &self.compatible_with {
            RelayExclusion::exclude_identities(
                target.identities().map(|id| id.to_owned()).collect(),
            )
        } else {
            RelayExclusion::no_relays_excluded()
        };

        let mode = vanguards.mode();
        match mode {
            VanguardMode::Lite => {
                exclude_guard_and_target.extend(&target_exclusion);
            }
            VanguardMode::Full if self.kind == HsCircStubKind::Short => {
                exclude_guard_and_target.extend(&target_exclusion);
            }
            VanguardMode::Full => {
                // The target can be the same as the L2 hop if we're building
                // an EXTENDED stub with vanguards enabled
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
        }

        let l2_guard: MaybeOwnedRelay = vanguards
            .select_vanguard(rng, netdir, Layer::Layer2, &exclude_guard_and_target)?
            .into();

        // We exclude
        //   * the L2 vanguard, because it cannot be selected again as an L3 vanguard
        //     (a relay won't let you extend the circuit to itself).
        //   * the guard, because relays won't let you extend the circuit to their previous hop
        let l1_l2_exclusion = exclude_identities(&[&l2_guard, &l1_guard]);

        // For circuits of the form
        //
        //    G - L2 - L3 - T
        //  and
        //    G - L2 - M - T
        //  and
        //    G - L2 - L3 - M - T
        //
        //  we must exclude G, L2, T from occurring as the third hop
        let mut l1_l2_target_exclusion = l1_l2_exclusion;
        l1_l2_target_exclusion.extend(&target_exclusion);

        let mut hops = vec![l1_guard, l2_guard.clone()];

        let extra_hop_err = |info: SelectionInfo| Error::NoRelay {
            path_kind: self.path_kind(),
            role: "extra hop",
            problem: info.to_string(),
        };

        // If needed, select an L3 vanguard too
        if mode == VanguardMode::Full {
            let l3_guard: MaybeOwnedRelay = vanguards
                .select_vanguard(rng, netdir, Layer::Layer3, &l1_l2_target_exclusion)?
                .into();
            hops.push(l3_guard.clone());

            // If full vanguards are enabled, we need an extra hop for the EXTENDED stub:
            //     SHORT    = G -> L2 -> L3
            //     EXTENDED = G -> L2 -> L3 -> M
            if self.kind == HsCircStubKind::Extended {
                // TODO: this usage has need_stable = true, but we probably
                // don't necessarily need a stable relay here.
                let usage = RelayUsage::middle_relay(None);
                let mut l2_l3_target_exclusion = exclude_identities(&[&l2_guard, &l3_guard]);
                l2_l3_target_exclusion.extend(&target_exclusion);
                // We exclude
                //   * the L3 vanguard, because it cannot be selected again as the following
                //     extra hop (a relay won't let you extend the circuit to itself).
                //   * the L2 vanguard, because relays won't let you extend the circuit to their previous hop
                //   * the target, because otherwise, M won't be able to extend to it
                let selector = RelaySelector::new(usage, l2_l3_target_exclusion);

                let (extra_hop, info) = selector.select_relay(rng, netdir);
                let extra_hop = extra_hop.ok_or_else(|| extra_hop_err(info))?;
                hops.push(MaybeOwnedRelay::from(extra_hop));
            }
        } else {
            // Lite vanguards

            // Extend the circuit to a third, arbitrarily chosen hop, excluding the L1 and L2
            // guards as before, as well as the circuit target.
            let usage = RelayUsage::middle_relay(None);
            let selector = RelaySelector::new(usage, l1_l2_target_exclusion);

            let (extra_hop, info) = selector.select_relay(rng, netdir);
            let extra_hop = extra_hop.ok_or_else(|| extra_hop_err(info))?;
            hops.push(MaybeOwnedRelay::from(extra_hop));
        }

        let actual_len = hops.len();
        let expected_len = self.kind.len(mode)?;

        if actual_len != expected_len {
            return Err(internal!(
                "invalid path length for {} {mode}-vanguard circuit (expected {} hops, got {})",
                self.kind,
                expected_len,
                actual_len
            )
            .into());
        }

        Ok((TorPath::new_multihop_from_maybe_owned(hops), mon, usable))
    }

    /// Return a short description of the path we're trying to build,
    /// for error reporting purposes.
    fn path_kind(&self) -> &'static str {
        "onion-service vanguard circuit"
    }
}

/// Build a [`RelayExclusion`] that excludes the specified relays.
#[cfg(feature = "vanguards")]
fn exclude_identities<'a>(exclude_ids: &[&MaybeOwnedRelay<'a>]) -> RelayExclusion<'a> {
    use tor_linkspec::HasRelayIds;

    RelayExclusion::exclude_identities(
        exclude_ids
            .iter()
            .flat_map(|relay| relay.identities())
            .map(|id| id.to_owned())
            .collect(),
    )
}
