//! Code for building paths for HS circuits.
//!
//! The path builders defined here are used for creating hidden service stub circuits,
//! which are three-hop circuits that have not yet been extended to a target.
//!
//! Stub circuits eventually become introduction, rendezvous, and HsDir circuits.
//! For all circuit types except client rendezvous, the stubs must first be
//! extended by an extra hop:
//!
//! ```text
//!  Client hsdir:  STUB+ -> HsDir
//!  Client intro:  STUB+ -> Ipt
//!  Client rend:   STUB
//!  Service hsdir: STUB  -> HsDir
//!  Service intro: STUB  -> Ipt
//!  Service rend:  STUB+ -> Rpt
//! ```
//!
//! If vanguards are disabled, regular stub circuits (STUB),
//! and extended stub circuits (STUB+) are the same,
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
//!         STUB  = G -> L2 -> M
//!         STUB+ = G -> L2 -> M
//!      ```
//!
//!   * with full vanguards enabled:
//!      ```text
//!         STUB  = G -> L2 -> L3
//!         STUB+ = G -> L2 -> L3 -> M
//!      ```

// TODO (#1339): we should be consistent with our terminology.

use rand::Rng;
use tor_linkspec::OwnedChanTarget;
use tor_netdir::{NetDir, Relay};
use tor_relay_selection::{RelayExclusion, RelaySelectionConfig, RelaySelector, RelayUsage};

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
    pub(crate) fn pick_path_with_vanguards<'a, R: Rng, RT: Runtime>(
        &self,
        rng: &mut R,
        netdir: DirInfo<'a>,
        guards: Option<&GuardMgr<RT>>,
        vanguards: &VanguardMgr,
        config: &PathConfig,
        now: SystemTime,
    ) -> Result<(TorPath<'a>, Option<GuardMonitor>, Option<GuardUsable>)> {
        let mode = vanguards.mode();
        if mode == VanguardMode::Disabled {
            return pick_path(self, rng, netdir, guards, config, now);
        }

        VanguardHsPathBuilder(self.kind).pick_path(rng, netdir, guards, vanguards, config)
    }
}

/// A path builder for hidden service circuits that use vanguards.
///
/// Used by [`HsPathBuilder`] when vanguards are enabled.
///
/// See the [`HsPathBuilder`] documentation for more details.
#[cfg(feature = "vanguards")]
struct VanguardHsPathBuilder(HsCircStubKind);

#[cfg(feature = "vanguards")]
impl VanguardHsPathBuilder {
    /// Try to create and return a path for a hidden service circuit stub.
    fn pick_path<'a, R: Rng, RT: Runtime>(
        &self,
        rng: &mut R,
        netdir: DirInfo<'a>,
        guards: Option<&GuardMgr<RT>>,
        vanguards: &VanguardMgr,
        config: &PathConfig,
    ) -> Result<(TorPath<'a>, Option<GuardMonitor>, Option<GuardUsable>)> {
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

        // TODO HS-VANGUARDS: this is probably all wrong!

        // Select the guard, allowing it to appear as
        // either of the last two hops of the circuit.
        let (l1_guard, mon, usable) =
            select_guard(rng, netdir, guards, config, None, None, self.path_kind())?;

        // Select the vanguards
        let l2_guard = vanguards.select_vanguard(netdir, Layer::Layer2)?;
        let mut hops = vec![l1_guard, MaybeOwnedRelay::from(l2_guard)];

        // If needed, select an L3 vanguard too
        if vanguards.mode() == VanguardMode::Full {
            let l3_guard = vanguards.select_vanguard(netdir, Layer::Layer3)?;
            hops.push(MaybeOwnedRelay::from(l3_guard));

            // If full vanguards are enabled, we need an extra hop for STUB+:
            //     STUB  = G -> L2 -> L3
            //     STUB+ = G -> L2 -> L3 -> M
            if self.0 == HsCircStubKind::Extended {
                // TODO: this usage has need_stable = true, but we probably
                // don't necessarily need a stable relay here.
                let usage = RelayUsage::middle_relay(None);
                let no_exclusion = RelayExclusion::no_relays_excluded();
                let selector = RelaySelector::new(usage, no_exclusion);

                let (extra_hop, info) = selector.select_relay(rng, netdir);
                let extra_hop = extra_hop.ok_or_else(|| Error::NoRelay {
                    path_kind: self.path_kind(),
                    role: "extra hop",
                    problem: info.to_string(),
                })?;

                hops.push(MaybeOwnedRelay::from(extra_hop));
            }
        }

        Ok((TorPath::new_multihop_from_maybe_owned(hops), mon, usable))
    }

    /// Return a short description of the path we're trying to build,
    /// for error reporting purposes.
    fn path_kind(&self) -> &'static str {
        "onion-service vanguard circuit"
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
