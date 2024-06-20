//! This module provides the [`PathBuilder`] helper for building vanguard [`TorPath`]s.

use std::result::Result as StdResult;

use rand::Rng;

use tor_error::{internal, Bug};
use tor_guardmgr::vanguards::{Layer, VanguardMgr};
use tor_linkspec::HasRelayIds;
use tor_netdir::{NetDir, Relay};
use tor_relay_selection::{RelayExclusion, RelaySelector, RelayUsage};
use tor_rtcompat::Runtime;

use crate::path::{MaybeOwnedRelay, TorPath};
use crate::{Error, Result};

/// A vanguard path builder.
///
/// A `PathBuilder` is a state machine whose current state is the [`HopKind`] of its last hop.
/// Not all state transitions are valid. For the permissible state transitions, see
/// [update_last_hop_kind](PathBuilder::update_last_hop_kind).
///
/// This type is an implementation detail that should remain private.
/// Used by [`VanguardHsPathBuilder`](super::VanguardHsPathBuilder).
pub(super) struct PathBuilder<'n, 'a, RT: Runtime, R: Rng> {
    /// The relays in the path.
    hops: Vec<MaybeOwnedRelay<'n>>,
    /// The network directory.
    netdir: &'n NetDir,
    /// The vanguard manager.
    vanguards: &'a VanguardMgr<RT>,
    /// An RNG for selecting vanguards and middle relays.
    rng: &'a mut R,
    /// The `HopKind` of the last hop in the path.
    last_hop_kind: HopKind,
}

/// The type of a `PathBuilder` hop.
#[derive(Copy, Clone, Debug, PartialEq, derive_more::Display)]
enum HopKind {
    /// The L1 guard.
    Guard,
    /// A vanguard from the specified [`Layer`].
    Vanguard(Layer),
    /// A middle relay.
    Middle,
}

impl<'n, 'a, RT: Runtime, R: Rng> PathBuilder<'n, 'a, RT, R> {
    /// Create a new `PathBuilder`.
    pub(super) fn new(
        rng: &'a mut R,
        netdir: &'n NetDir,
        vanguards: &'a VanguardMgr<RT>,
        l1_guard: MaybeOwnedRelay<'n>,
    ) -> Self {
        Self {
            hops: vec![l1_guard],
            netdir,
            vanguards,
            rng,
            last_hop_kind: HopKind::Guard,
        }
    }

    /// Extend the path with a vanguard.
    pub(super) fn add_vanguard(
        mut self,
        target_exclusion: &RelayExclusion<'n>,
        layer: Layer,
    ) -> Result<Self> {
        let mut neighbor_exclusion = exclude_neighbors(&self.hops);
        neighbor_exclusion.extend(target_exclusion);
        let vanguard: MaybeOwnedRelay = self
            .vanguards
            .select_vanguard(&mut self.rng, self.netdir, layer, &neighbor_exclusion)?
            .into();
        let () = self.add_hop(vanguard, HopKind::Vanguard(layer))?;
        Ok(self)
    }

    /// Extend the path with a middle relay.
    pub(super) fn add_middle(mut self, target_exclusion: &RelayExclusion<'n>) -> Result<Self> {
        let middle =
            select_middle_for_vanguard_circ(&self.hops, self.netdir, target_exclusion, self.rng)?
                .into();
        let () = self.add_hop(middle, HopKind::Middle)?;
        Ok(self)
    }

    /// Return a [`TorPath`] built using the hops from this `PathBuilder`.
    pub(super) fn build(self) -> Result<TorPath<'n>> {
        use HopKind::*;
        use Layer::*;

        match self.last_hop_kind {
            Vanguard(Layer3) | Middle => Ok(TorPath::new_multihop_from_maybe_owned(self.hops)),
            _ => Err(internal!(
                "tried to build TorPath from incomplete PathBuilder (last_hop_kind={})",
                self.last_hop_kind
            )
            .into()),
        }
    }

    /// Try to append `hop` to the end of the path.
    ///
    /// This also causes the `PathBuilder` to transition to the state represented by `hop_kind`,
    /// if the transition is valid.
    ///
    /// Returns an error if the `hop_kind` is incompatible with the `HopKind` of the last hop.
    fn add_hop(&mut self, hop: MaybeOwnedRelay<'n>, hop_kind: HopKind) -> StdResult<(), Bug> {
        self.update_last_hop_kind(hop_kind)?;
        self.hops.push(hop);
        Ok(())
    }

    /// Transition to the state specified by `kind`.
    ///
    /// The state of the `PathBuilder` is represented by the [`HopKind`] of its last hop.
    /// This function should be called whenever a new hop is added
    /// (e.g. in [`add_hop`](PathBuilder::add_hop)), to set the current state to the
    /// [`HopKind`] of the new hop.
    ///
    /// Not all transitions are valid. The permissible state transitions are:
    ///   * `G  -> L2`
    ///   * `L2 -> L3`
    ///   * `L2 -> M`
    ///   * `L3 -> M`
    fn update_last_hop_kind(&mut self, kind: HopKind) -> StdResult<(), Bug> {
        use HopKind::*;
        use Layer::*;

        match (self.last_hop_kind, kind) {
            (Guard, Vanguard(Layer2))
            | (Vanguard(Layer2), Vanguard(Layer3))
            | (Vanguard(Layer2), Middle)
            | (Vanguard(Layer3), Middle) => {
                self.last_hop_kind = kind;
            }
            (_, _) => {
                return Err(internal!(
                    "tried to build an invalid vanguard path: cannot add a {kind} hop after {}",
                    self.last_hop_kind
                ))
            }
        }

        Ok(())
    }
}

/// Build a [`RelayExclusion`] that excludes the specified relays.
fn exclude_identities<'a, T: HasRelayIds + 'a>(exclude_ids: &[&T]) -> RelayExclusion<'a> {
    RelayExclusion::exclude_identities(
        exclude_ids
            .iter()
            .flat_map(|relay| relay.identities())
            .map(|id| id.to_owned())
            .collect(),
    )
}

/// Create a `RelayExclusion` suitable for selecting the next hop to add to `hops`.
fn exclude_neighbors<'n, T: HasRelayIds + 'n>(hops: &[T]) -> RelayExclusion<'n> {
    // We must exclude the last 2 hops in the path,
    // because a relay can't extend to itself or to its predecessor.
    let skip_n = 2;
    let neighbors = hops.iter().rev().take(skip_n).collect::<Vec<&T>>();
    exclude_identities(&neighbors[..])
}

/// Select a middle relay that can be appended to a vanguard circuit.
///
/// Used by [`PathBuilder`] to build [`TorPath`]s of the form
///
///   G - L2 - M
///   G - L2 - L3 - M
///
/// If full vanguards are enabled, this is also used by [`HsCircPool`](crate::hspool::HsCircPool),
/// for extending SHORT circuits to become EXTENDED circuits.
pub(crate) fn select_middle_for_vanguard_circ<'n, R: Rng, T: HasRelayIds + 'n>(
    hops: &[T],
    netdir: &'n NetDir,
    target_exclusion: &RelayExclusion<'n>,
    rng: &mut R,
) -> Result<Relay<'n>> {
    let mut neighbor_exclusion = exclude_neighbors(hops);
    neighbor_exclusion.extend(target_exclusion);

    // TODO: this usage has need_stable = true, but we probably
    // don't necessarily need a stable relay here.
    let usage = RelayUsage::middle_relay(None);
    let selector = RelaySelector::new(usage, neighbor_exclusion);

    let (extra_hop, info) = selector.select_relay(rng, netdir);
    extra_hop.ok_or_else(|| Error::NoRelay {
        path_kind: "onion-service vanguard circuit",
        role: "extra hop",
        problem: info.to_string(),
    })
}
