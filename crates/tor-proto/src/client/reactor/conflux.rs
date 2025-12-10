//! Conflux-related functionality

// TODO: replace Itertools::exactly_one() with a stdlib equivalent when there is one.
//
// See issue #48919 <https://github.com/rust-lang/rust/issues/48919>
#![allow(unstable_name_collisions)]

#[cfg(feature = "conflux")]
pub(crate) mod msghandler;

use std::pin::Pin;
use std::sync::atomic::{self, AtomicU64};
use std::sync::{Arc, Mutex};

use futures::{FutureExt as _, StreamExt, select_biased};
use itertools::Itertools;
use itertools::structs::ExactlyOneError;
use smallvec::{SmallVec, smallvec};
use tor_rtcompat::{SleepProvider as _, SleepProviderExt as _};
use tracing::{info, instrument, trace, warn};

use tor_cell::relaycell::AnyRelayMsgOuter;
use tor_error::{Bug, bad_api_usage, internal};
use tor_linkspec::HasRelayIds as _;

use crate::circuit::UniqId;
use crate::circuit::circhop::SendRelayCell;
use crate::client::circuit::TunnelMutableState;
#[cfg(feature = "circ-padding")]
use crate::client::circuit::padding::PaddingEvent;
use crate::client::circuit::path::HopDetail;
use crate::conflux::cmd_counts_towards_seqno;
use crate::conflux::msghandler::{ConfluxStatus, RemoveLegReason};
use crate::congestion::params::CongestionWindowParams;
use crate::crypto::cell::HopNum;
use crate::streammap;
use crate::tunnel::TunnelId;
use crate::util::err::ReactorError;
use crate::util::poll_all::PollAll;
use crate::util::tunnel_activity::TunnelActivity;

use super::circuit::CircHop;
use super::{Circuit, CircuitEvent};

#[cfg(feature = "conflux")]
use {
    crate::conflux::msghandler::ConfluxMsgHandler,
    msghandler::ClientConfluxMsgHandler,
    tor_cell::relaycell::conflux::{V1DesiredUx, V1LinkPayload, V1Nonce},
    tor_cell::relaycell::msg::{ConfluxLink, ConfluxSwitch},
};

/// The maximum number of conflux legs to store in the conflux set SmallVec.
///
/// Attempting to store more legs will cause the SmallVec to spill to the heap.
///
/// Note: this value was picked arbitrarily and may not be suitable.
const MAX_CONFLUX_LEGS: usize = 16;

/// The number of futures we add to the per-circuit [`PollAll`] future in
/// [`ConfluxSet::next_circ_event`].
///
/// Used for the SmallVec size estimate;
const NUM_CIRC_FUTURES: usize = 2;

/// The expected number of circuit events to be returned from
/// [`ConfluxSet::next_circ_event`]
const CIRC_EVENT_COUNT: usize = MAX_CONFLUX_LEGS * NUM_CIRC_FUTURES;

/// A set with one or more circuits.
///
/// ### Conflux set life cycle
///
/// Conflux sets are created by the reactor using [`ConfluxSet::new`].
///
/// Every `ConfluxSet` starts out as a single-path set consisting of a single 0-length circuit.
///
/// After constructing a `ConfluxSet`, the reactor will proceed to extend its (only) circuit.
/// At this point, the `ConfluxSet` will be a single-path set with a single n-length circuit.
///
/// The reactor can then turn the `ConfluxSet` into a multi-path set
/// (a multi-path set is a conflux set that contains more than 1 circuit).
/// This is done using [`ConfluxSet::add_legs`], in response to a `CtrlMsg` sent
/// by the reactor user (also referred to as the "conflux handshake initiator").
/// After that, the conflux set is said to be a multi-path set with multiple N-length circuits.
///
/// Circuits can be removed from the set using [`ConfluxSet::remove`].
///
/// The lifetime of a `ConfluxSet` is tied to the lifetime of the reactor.
/// When the reactor is dropped, its underlying `ConfluxSet` is dropped too.
/// This can happen on an explicit shutdown request, or if a fatal error occurs.
///
/// Conversely, the `ConfluxSet` can also trigger a reactor shutdown.
/// For example, if after being instructed to remove a circuit from the set
/// using [`ConfluxSet::remove`], the set is completely depleted,
/// the `ConfluxSet` will return a [`ReactorError::Shutdown`] error,
/// which will cause the reactor to shut down.
pub(super) struct ConfluxSet {
    /// The unique identifier of the tunnel this conflux set belongs to.
    ///
    /// Used for setting the internal [`TunnelId`] of [`Circuit`]s
    /// that gets used for logging purposes.
    tunnel_id: TunnelId,
    /// The circuits in this conflux set.
    legs: SmallVec<[Circuit; MAX_CONFLUX_LEGS]>,
    /// Tunnel state, shared with `ClientCirc`.
    ///
    /// Contains the [`MutableState`](super::MutableState) of each circuit in the set.
    mutable: Arc<TunnelMutableState>,
    /// The unique identifier of the primary leg
    primary_id: UniqId,
    /// The join point of the set, if this is a multi-path set.
    ///
    /// Initially the conflux set starts out as a single-path set with no join point.
    /// When it is converted to a multipath set using [`add_legs`](Self::add_legs),
    /// the join point is initialized to the last hop in the tunnel.
    //
    // TODO(#2017): for simplicity, we currently we force all legs to have the same length,
    // to ensure the HopNum of the join point is the same for all of them.
    //
    // In the future we might want to relax this restriction.
    join_point: Option<JoinPoint>,
    /// The nonce associated with the circuits from this set.
    #[cfg(feature = "conflux")]
    nonce: V1Nonce,
    /// The desired UX
    #[cfg(feature = "conflux")]
    desired_ux: V1DesiredUx,
    /// The absolute sequence number of the last cell delivered to a stream.
    ///
    /// A clone of this is shared with each [`ConfluxMsgHandler`] created.
    ///
    /// When a message is received on a circuit leg, the `ConfluxMsgHandler`
    /// of the leg compares the (leg-local) sequence number of the message
    /// with this sequence number to determine whether the message is in-order.
    ///
    /// If the message is in-order, the `ConfluxMsgHandler` instructs the circuit
    /// to deliver it to its corresponding stream.
    ///
    /// If the message is out-of-order, the `ConfluxMsgHandler` instructs the circuit
    /// to instruct the reactor to buffer the message.
    last_seq_delivered: Arc<AtomicU64>,
    /// Whether we have selected our initial primary leg,
    /// if this is a multipath conflux set.
    selected_init_primary: bool,
}

/// The conflux join point.
#[derive(Clone, derive_more::Debug)]
struct JoinPoint {
    /// The hop number.
    hop: HopNum,
    /// The [`HopDetail`] of the hop.
    detail: HopDetail,
    /// The stream map of the joint point, shared with each circuit leg.
    #[debug(skip)]
    streams: Arc<Mutex<streammap::StreamMap>>,
}

impl ConfluxSet {
    /// Create a new conflux set, consisting of a single leg.
    ///
    /// Returns the newly created set and a reference to its [`TunnelMutableState`].
    pub(super) fn new(
        tunnel_id: TunnelId,
        circuit_leg: Circuit,
    ) -> (Self, Arc<TunnelMutableState>) {
        let primary_id = circuit_leg.unique_id();
        let circ_mutable = Arc::clone(circuit_leg.mutable());
        let legs = smallvec![circuit_leg];
        // Note: the join point is only set for multi-path tunnels
        let join_point = None;

        // TODO(#2035): read this from the consensus/config.
        #[cfg(feature = "conflux")]
        let desired_ux = V1DesiredUx::NO_OPINION;

        let mutable = Arc::new(TunnelMutableState::default());
        mutable.insert(primary_id, circ_mutable);

        let set = Self {
            tunnel_id,
            legs,
            primary_id,
            join_point,
            mutable: mutable.clone(),
            #[cfg(feature = "conflux")]
            nonce: V1Nonce::new(&mut rand::rng()),
            #[cfg(feature = "conflux")]
            desired_ux,
            last_seq_delivered: Arc::new(AtomicU64::new(0)),
            selected_init_primary: false,
        };

        (set, mutable)
    }

    /// Remove and return the only leg of this conflux set.
    ///
    /// Returns an error if there is more than one leg in the set,
    /// or if called before any circuit legs are available.
    ///
    /// Calling this function will empty the [`ConfluxSet`].
    pub(super) fn take_single_leg(&mut self) -> Result<Circuit, Bug> {
        let circ = self
            .legs
            .iter()
            .exactly_one()
            .map_err(NotSingleLegError::from)?;
        let circ_id = circ.unique_id();

        debug_assert!(circ_id == self.primary_id);

        self.remove_unchecked(circ_id)
    }

    /// Return a reference to the only leg of this conflux set,
    /// along with the leg's ID.
    ///
    /// Returns an error if there is more than one leg in the set,
    /// or if called before any circuit legs are available.
    pub(super) fn single_leg(&self) -> Result<&Circuit, NotSingleLegError> {
        Ok(self.legs.iter().exactly_one()?)
    }

    /// Return a mutable reference to the only leg of this conflux set,
    /// along with the leg's ID.
    ///
    /// Returns an error if there is more than one leg in the set,
    /// or if called before any circuit legs are available.
    pub(super) fn single_leg_mut(&mut self) -> Result<&mut Circuit, NotSingleLegError> {
        Ok(self.legs.iter_mut().exactly_one()?)
    }

    /// Return the primary leg of this conflux set.
    ///
    /// Returns an error if called before any circuit legs are available.
    pub(super) fn primary_leg_mut(&mut self) -> Result<&mut Circuit, Bug> {
        #[cfg(not(feature = "conflux"))]
        if self.legs.len() > 1 {
            return Err(internal!(
                "got multipath tunnel, but conflux feature is disabled?!"
            ));
        }

        if self.legs.is_empty() {
            Err(bad_api_usage!(
                "tried to get circuit leg before creating it?!"
            ))
        } else {
            let circ = self
                .leg_mut(self.primary_id)
                .ok_or_else(|| internal!("conflux set is empty?!"))?;

            Ok(circ)
        }
    }

    /// Return a reference to the leg of this conflux set with the given id.
    pub(super) fn leg(&self, leg_id: UniqId) -> Option<&Circuit> {
        self.legs.iter().find(|circ| circ.unique_id() == leg_id)
    }

    /// Return a mutable reference to the leg of this conflux set with the given id.
    pub(super) fn leg_mut(&mut self, leg_id: UniqId) -> Option<&mut Circuit> {
        self.legs.iter_mut().find(|circ| circ.unique_id() == leg_id)
    }

    /// Return the number of legs in this conflux set.
    pub(super) fn len(&self) -> usize {
        self.legs.len()
    }

    /// Return whether this conflux set is empty.
    pub(super) fn is_empty(&self) -> bool {
        self.legs.len() == 0
    }

    /// Remove the specified leg from this conflux set.
    ///
    /// Returns an error if the given leg doesn't exist in the set.
    ///
    /// Returns an error instructing the reactor to perform a clean shutdown
    /// ([`ReactorError::Shutdown`]), tearing down the entire [`ConfluxSet`], if
    ///
    ///   * the set is depleted (empty) after removing the specified leg
    ///   * `leg` is currently the sending (primary) leg of this set
    ///   * the closed leg had the highest non-zero last_seq_recv/sent
    ///   * the closed leg had some in-progress data (inflight > cc_sendme_inc)
    ///
    /// We do not yet support resumption. See [2.4.3. Closing circuits] in prop329.
    ///
    /// [2.4.3. Closing circuits]: https://spec.torproject.org/proposals/329-traffic-splitting.html#243-closing-circuits
    #[instrument(level = "trace", skip_all)]
    pub(super) fn remove(&mut self, leg: UniqId) -> Result<Circuit, ReactorError> {
        let circ = self.remove_unchecked(leg)?;

        tracing::trace!(
            circ_id = %circ.unique_id(),
            "Circuit removed from conflux set"
        );

        self.mutable.remove(circ.unique_id());

        if self.legs.is_empty() {
            // TODO: log the tunnel ID
            tracing::debug!("Conflux set is now empty, tunnel reactor shutting down");

            // The last circuit in the set has just died, so the reactor should exit.
            return Err(ReactorError::Shutdown);
        }

        if leg == self.primary_id {
            // We have just removed our sending leg,
            // so it's time to close the entire conflux set.
            return Err(ReactorError::Shutdown);
        }

        cfg_if::cfg_if! {
            if #[cfg(feature = "conflux")] {
                self.remove_conflux(circ)
            } else {
                // Conflux is disabled, so we can't possibly continue running if the only
                // leg in the tunnel is gone.
                //
                // Technically this should be unreachable (because of the is_empty()
                // check above)
                Err(internal!("Multiple legs in single-path tunnel?!").into())
            }
        }
    }

    /// Handle the removal of a circuit,
    /// returning an error if the reactor needs to shut down.
    #[cfg(feature = "conflux")]
    fn remove_conflux(&self, circ: Circuit) -> Result<Circuit, ReactorError> {
        let Some(status) = circ.conflux_status() else {
            return Err(internal!("Found non-conflux circuit in conflux set?!").into());
        };

        // TODO(conflux): should the circmgr be notified about the leg removal?
        //
        // "For circuits that are unlinked, the origin SHOULD immediately relaunch a new leg when it
        // is closed, subject to the limits in [SIDE_CHANNELS]."

        // If we've reached this point and the conflux set is non-empty,
        // it means it's a multi-path set.
        //
        // Time to check if we need to tear down the entire set.
        match status {
            ConfluxStatus::Unlinked => {
                // This circuit hasn't yet begun the conflux handshake,
                // so we can safely remove it from the set
                Ok(circ)
            }
            ConfluxStatus::Pending | ConfluxStatus::Linked => {
                let (circ_last_seq_recv, circ_last_seq_sent) =
                    (|| Ok::<_, ReactorError>((circ.last_seq_recv()?, circ.last_seq_sent()?)))()?;

                // If the closed leg had the highest non-zero last_seq_recv/sent, close the set
                if let Some(max_last_seq_recv) = self.max_last_seq_recv() {
                    if circ_last_seq_recv > max_last_seq_recv {
                        return Err(ReactorError::Shutdown);
                    }
                }

                if let Some(max_last_seq_sent) = self.max_last_seq_sent() {
                    if circ_last_seq_sent > max_last_seq_sent {
                        return Err(ReactorError::Shutdown);
                    }
                }

                let hop = self.join_point_hop(&circ)?;

                let (inflight, cwnd) = (|| {
                    let ccontrol = hop.ccontrol();
                    let inflight = ccontrol.inflight()?;
                    let cwnd = ccontrol.cwnd()?;

                    Some((inflight, cwnd))
                })()
                .ok_or_else(|| {
                    internal!("Congestion control algorithm doesn't track inflight cells or cwnd?!")
                })?;

                // If data is in progress on the leg (inflight > cc_sendme_inc),
                // then all legs must be closed
                if inflight >= cwnd.params().sendme_inc() {
                    return Err(ReactorError::Shutdown);
                }

                Ok(circ)
            }
        }
    }

    /// Return the maximum relative last_seq_recv across all circuits.
    #[cfg(feature = "conflux")]
    fn max_last_seq_recv(&self) -> Option<u64> {
        self.legs
            .iter()
            .filter_map(|leg| leg.last_seq_recv().ok())
            .max()
    }

    /// Return the maximum relative last_seq_sent across all circuits.
    #[cfg(feature = "conflux")]
    fn max_last_seq_sent(&self) -> Option<u64> {
        self.legs
            .iter()
            .filter_map(|leg| leg.last_seq_sent().ok())
            .max()
    }

    /// Get the [`CircHop`] of the join point on the specified `circ`,
    /// returning an error if this is a single path conflux set.
    fn join_point_hop<'c>(&self, circ: &'c Circuit) -> Result<&'c CircHop, Bug> {
        let Some(join_point) = self.join_point.as_ref().map(|p| p.hop) else {
            return Err(internal!("No join point on conflux tunnel?!"));
        };

        circ.hop(join_point)
            .ok_or_else(|| internal!("Conflux join point disappeared?!"))
    }

    /// Return an iterator of all circuits in the conflux set.
    fn circuits(&self) -> impl Iterator<Item = &Circuit> {
        self.legs.iter()
    }

    /// Return the most active [`TunnelActivity`] for any leg of this `ConfluxSet`.
    pub(super) fn tunnel_activity(&self) -> TunnelActivity {
        self.circuits()
            .map(|c| c.hops.tunnel_activity())
            .max()
            .unwrap_or_else(TunnelActivity::never_used)
    }

    /// Add legs to the this conflux set.
    ///
    /// Returns an error if any of the legs is invalid.
    ///
    /// A leg is considered valid if
    ///
    ///   * the circuit has the same length as all the other circuits in the set
    ///   * its last hop is equal to the designated join point
    ///   * the circuit has no streams attached to any of its hops
    ///   * the circuit is not already part of a conflux set
    ///
    /// Note: the circuits will not begin linking until
    /// [`link_circuits`](Self::link_circuits) is called.
    ///
    /// IMPORTANT: this function does not prevent the construction of conflux sets
    /// where the circuit legs share guard or middle relays. It is the responsibility
    /// of the caller to enforce the following invariant from prop354:
    ///
    /// "If building a conflux leg: Reject any circuits that have the same Guard as the other conflux
    /// "leg(s) in the current conflux set, EXCEPT when one of the primary Guards is also the chosen
    /// "Exit of this conflux set (in which case, re-use the non-Exit Guard)."
    ///
    /// This is because at this level we don't actually know which relays are the guards,
    /// so we can't know if the join point happens to be one of the Guard + Exit relays.
    #[cfg(feature = "conflux")]
    pub(super) fn add_legs(
        &mut self,
        legs: Vec<Circuit>,
        runtime: &tor_rtcompat::DynTimeProvider,
    ) -> Result<(), Bug> {
        if legs.is_empty() {
            return Err(bad_api_usage!("asked to add empty leg list to conflux set"));
        }

        let join_point = match self.join_point.take() {
            Some(p) => {
                // Preserve the existing join point, if there is one.
                p
            }
            None => {
                let (hop, detail, streams) = (|| {
                    let first_leg = self.circuits().next()?;
                    let first_leg_path = first_leg.path();
                    let all_hops = first_leg_path.all_hops();
                    let hop_num = first_leg.last_hop_num()?;
                    let detail = all_hops.last()?;
                    let hop = first_leg.hop(hop_num)?;
                    let streams = Arc::clone(hop.stream_map());
                    Some((hop_num, detail.clone(), streams))
                })()
                .ok_or_else(|| bad_api_usage!("asked to join circuit with no hops"))?;

                JoinPoint {
                    hop,
                    detail,
                    streams,
                }
            }
        };

        // Check two HopDetails for equality.
        //
        // Returns an error if one of the hops is virtual.
        let hops_eq = |h1: &HopDetail, h2: &HopDetail| {
            match (h1, h2) {
                (HopDetail::Relay(t1), HopDetail::Relay(t2)) => Ok(t1.same_relay_ids(t2)),
                #[cfg(feature = "hs-common")]
                (HopDetail::Virtual, HopDetail::Virtual) => {
                    // TODO(#2016): support onion service conflux
                    Err(internal!("onion service conflux not supported"))
                }
                _ => Ok(false),
            }
        };

        // A leg is considered valid if
        //
        //   * the circuit has the expected length
        //     (the length of the first circuit we added to the set)
        //   * its last hop is equal to the designated join point
        //     (the last hop of the first circuit we added)
        //   * the circuit has no streams attached to any of its hops
        //   * the circuit is not already part of a conflux tunnel
        //
        // Returns an error if any hops are virtual.
        let leg_is_valid = |leg: &Circuit| -> Result<bool, Bug> {
            use crate::ccparams::Algorithm;

            let path = leg.path();
            let Some(last_hop) = path.all_hops().last() else {
                // A circuit with no hops is invalid
                return Ok(false);
            };

            // TODO: this sort of duplicates the check above.
            // The difference is that above we read the hop detail
            // information from the circuit Path, whereas here we get
            // the actual last CircHop of the circuit.
            let Some(last_hop_num) = leg.last_hop_num() else {
                // A circuit with no hops is invalid
                return Ok(false);
            };

            let circhop = leg
                .hop(last_hop_num)
                .ok_or_else(|| internal!("hop disappeared?!"))?;

            // Ensure we negotiated a suitable cc algorithm
            let is_cc_suitable = match circhop.ccontrol().algorithm() {
                Algorithm::FixedWindow(_) => false,
                Algorithm::Vegas(_) => true,
            };

            if !is_cc_suitable {
                return Ok(false);
            }

            Ok(last_hop_num == join_point.hop
                && hops_eq(last_hop, &join_point.detail)?
                && !leg.has_streams()
                && leg.conflux_status().is_none())
        };

        for leg in &legs {
            if !leg_is_valid(leg)? {
                return Err(bad_api_usage!("one more more conflux circuits are invalid"));
            }
        }

        // Select a join point, or put the existing one back into self.
        self.join_point = Some(join_point.clone());

        // The legs are valid, so add them to the set.
        for circ in legs {
            let mutable = Arc::clone(circ.mutable());
            let unique_id = circ.unique_id();
            self.legs.push(circ);
            // Merge the mutable state of the circuit into our tunnel state.
            self.mutable.insert(unique_id, mutable);
        }

        let cwnd_params = self.cwnd_params()?;
        for circ in self.legs.iter_mut() {
            // The circuits that have a None status don't know they're part of
            // a multi-path tunnel yet. They need to be initialized with a
            // conflux message handler, and have their join point fixed up
            // to share a stream map with the join point on all the other circuits.
            if circ.conflux_status().is_none() {
                let handler = Box::new(ClientConfluxMsgHandler::new(
                    join_point.hop,
                    self.nonce,
                    Arc::clone(&self.last_seq_delivered),
                    cwnd_params,
                    runtime.clone(),
                ));
                let conflux_handler =
                    ConfluxMsgHandler::new(handler, Arc::clone(&self.last_seq_delivered));

                circ.add_to_conflux_tunnel(self.tunnel_id, conflux_handler);

                // Ensure the stream map of the last hop is shared by all the legs
                let last_hop = circ
                    .hop_mut(join_point.hop)
                    .ok_or_else(|| bad_api_usage!("asked to join circuit with no hops"))?;
                last_hop.set_stream_map(Arc::clone(&join_point.streams))?;
            }
        }

        Ok(())
    }

    /// Get the [`CongestionWindowParams`] of the join point
    /// on the first leg.
    ///
    /// Returns an error if the congestion control algorithm
    /// doesn't have a congestion control window object,
    /// or if the conflux set is empty, or the joint point hop
    /// does not exist.
    ///
    // TODO: this function is a bit of a hack. In reality, we only
    // need the cc_cwnd_init parameter (for SWITCH seqno validation).
    // The fact that we obtain it from the cc params of the join point
    // is an implementation detail (it's a workaround for the fact that
    // at this point, these params can only obtained from a CircHop)
    #[cfg(feature = "conflux")]
    fn cwnd_params(&self) -> Result<CongestionWindowParams, Bug> {
        let primary_leg = self
            .leg(self.primary_id)
            .ok_or_else(|| internal!("no primary leg?!"))?;
        let join_point = self.join_point_hop(primary_leg)?;
        let ccontrol = join_point.ccontrol();
        let cwnd = ccontrol
            .cwnd()
            .ok_or_else(|| internal!("congestion control algorithm does not track the cwnd?!"))?;

        Ok(*cwnd.params())
    }

    /// Try to update the primary leg based on the configured desired UX,
    /// if needed.
    ///
    /// Returns the SWITCH cell to send on the primary leg,
    /// if we switched primary leg.
    #[cfg(feature = "conflux")]
    pub(super) fn maybe_update_primary_leg(&mut self) -> crate::Result<Option<SendRelayCell>> {
        use tor_error::into_internal;

        let Some(join_point) = self.join_point.as_ref() else {
            // Return early if this is not a multi-path tunnel
            return Ok(None);
        };

        let join_point = join_point.hop;

        if !self.should_update_primary_leg() {
            // Nothing to do
            return Ok(None);
        }

        let Some(new_primary_id) = self.select_primary_leg()? else {
            // None of the legs satisfy our UX requirements, continue using the existing one.
            return Ok(None);
        };

        // Check that the newly selected leg is actually different from the previous
        if self.primary_id == new_primary_id {
            // The primary leg stays the same, nothing to do.
            return Ok(None);
        }

        let prev_last_seq_sent = self.primary_leg_mut()?.last_seq_sent()?;
        self.primary_id = new_primary_id;
        let new_last_seq_sent = self.primary_leg_mut()?.last_seq_sent()?;

        // If this fails, it means we haven't updated our primary leg in a very long time.
        //
        // TODO(#2036): there are currently no safeguards to prevent us from staying
        // on the same leg for "too long". Perhaps we should design should_update_primary_leg()
        // such that it forces us to switch legs periodically, to prevent the seqno delta from
        // getting too big?
        let seqno_delta = u32::try_from(prev_last_seq_sent - new_last_seq_sent).map_err(
            into_internal!("Seqno delta for switch does not fit in u32?!"),
        )?;

        // We need to carry the last_seq_sent over to the next leg
        // (the next cell sent will have seqno = prev_last_seq_sent + 1)
        self.primary_leg_mut()?
            .set_last_seq_sent(prev_last_seq_sent)?;

        let switch = ConfluxSwitch::new(seqno_delta);
        let cell = AnyRelayMsgOuter::new(None, switch.into());
        Ok(Some(SendRelayCell {
            hop: Some(join_point),
            early: false,
            cell,
        }))
    }

    /// Whether it's time to select a new primary leg.
    #[cfg(feature = "conflux")]
    fn should_update_primary_leg(&mut self) -> bool {
        if !self.selected_init_primary {
            self.maybe_select_init_primary();
            return false;
        }

        // If we don't have at least 2 legs,
        // we can't switch our primary leg.
        if self.legs.len() < 2 {
            return false;
        }

        // TODO(conflux-tuning): if it turns out we switch legs too frequently,
        // we might want to implement some sort of rate-limiting here
        // (see c-tor's conflux_can_switch).

        true
    }

    /// Return the best leg according to the configured desired UX.
    ///
    /// Returns `None` if no suitable leg was found.
    #[cfg(feature = "conflux")]
    fn select_primary_leg(&self) -> Result<Option<UniqId>, Bug> {
        match self.desired_ux {
            V1DesiredUx::NO_OPINION | V1DesiredUx::MIN_LATENCY => {
                self.select_primary_leg_min_rtt(false)
            }
            V1DesiredUx::HIGH_THROUGHPUT => self.select_primary_leg_min_rtt(true),
            V1DesiredUx::LOW_MEM_LATENCY | V1DesiredUx::LOW_MEM_THROUGHPUT => {
                // TODO(conflux-tuning): add support for low-memory algorithms
                self.select_primary_leg_min_rtt(false)
            }
            _ => {
                // Default to MIN_RTT if we don't recognize the desired UX value
                warn!(
                    tunnel_id = %self.tunnel_id,
                    "Ignoring unrecognized conflux desired UX {}, using MIN_LATENCY",
                    self.desired_ux
                );
                self.select_primary_leg_min_rtt(false)
            }
        }
    }

    /// Try to choose an initial primary leg, if we have an initial RTT measurement
    /// for at least one of the legs.
    #[cfg(feature = "conflux")]
    fn maybe_select_init_primary(&mut self) {
        let best = self
            .legs
            .iter()
            .filter_map(|leg| leg.init_rtt().map(|rtt| (leg, rtt)))
            .min_by_key(|(_leg, rtt)| *rtt)
            .map(|(leg, _rtt)| leg.unique_id());

        if let Some(best) = best {
            self.primary_id = best;
            self.selected_init_primary = true;
        }
    }

    /// Return the leg with the best (lowest) RTT.
    ///
    /// If `check_can_send` is true, selects the lowest RTT leg that is ready to send.
    ///
    /// Returns `None` if no suitable leg was found.
    #[cfg(feature = "conflux")]
    fn select_primary_leg_min_rtt(&self, check_can_send: bool) -> Result<Option<UniqId>, Bug> {
        let mut best = None;

        for circ in self.legs.iter() {
            let leg_id = circ.unique_id();
            let join_point = self.join_point_hop(circ)?;
            let ccontrol = join_point.ccontrol();

            if check_can_send && !ccontrol.can_send() {
                continue;
            }

            let rtt = ccontrol.rtt();
            let init_rtt_usec = || {
                circ.init_rtt()
                    .map(|rtt| u32::try_from(rtt.as_micros()).unwrap_or(u32::MAX))
            };

            let Some(ewma_rtt) = rtt.ewma_rtt_usec().or_else(init_rtt_usec) else {
                return Err(internal!(
                    "attempted to select primary leg before handshake completed?!"
                ));
            };

            match best.take() {
                None => {
                    best = Some((leg_id, ewma_rtt));
                }
                Some(best_so_far) => {
                    if best_so_far.1 <= ewma_rtt {
                        best = Some(best_so_far);
                    } else {
                        best = Some((leg_id, ewma_rtt));
                    }
                }
            }
        }

        Ok(best.map(|(leg_id, _)| leg_id))
    }

    /// Returns `true` if our conflux join point is blocked on congestion control
    /// on the specified `circuit`.
    ///
    /// Returns `false` if the join point is not blocked on cc,
    /// or if this is a single-path set.
    ///
    /// Returns an error if this is a multipath tunnel,
    /// but the joint point hop doesn't exist on the specified circuit.
    #[cfg(feature = "conflux")]
    fn is_join_point_blocked_on_cc(join_hop: HopNum, circuit: &Circuit) -> Result<bool, Bug> {
        let join_circhop = circuit.hop(join_hop).ok_or_else(|| {
            internal!(
                "Join point hop {} not found on circuit {}?!",
                join_hop.display(),
                circuit.unique_id(),
            )
        })?;

        Ok(!join_circhop.ccontrol().can_send())
    }

    /// Returns whether [`next_circ_event`](Self::next_circ_event)
    /// should avoid polling the join point streams entirely.
    #[cfg(feature = "conflux")]
    fn should_skip_join_point(&self) -> Result<bool, Bug> {
        let Some(primary_join_point) = self.primary_join_point() else {
            // Single-path, there is no join point
            return Ok(false);
        };

        let join_hop = primary_join_point.1;
        let primary_blocked_on_cc = {
            let primary = self
                .leg(self.primary_id)
                .ok_or_else(|| internal!("primary leg disappeared?!"))?;
            Self::is_join_point_blocked_on_cc(join_hop, primary)?
        };

        if !primary_blocked_on_cc {
            // Easy, we can just carry on
            return Ok(false);
        }

        // Now, if the primary *is* blocked on cc, we may still be able to poll
        // the join point streams (if we're using the right desired UX)
        let should_skip = if self.desired_ux != V1DesiredUx::HIGH_THROUGHPUT {
            // The primary leg is blocked on cc, and we can't switch because we're
            // not using the high throughput algorithm, so we must stop reading
            // the join point streams.
            //
            // Note: if the selected algorithm is HIGH_THROUGHPUT,
            // it's okay to continue reading from the edge connection,
            // because maybe_update_primary_leg() will select a new,
            // non-blocked primary leg, just before sending.
            trace!(
                tunnel_id = %self.tunnel_id,
                join_point = ?primary_join_point,
                reason = "sending leg blocked on congestion control",
                "Pausing join point stream reads"
            );

            true
        } else {
            // Ah-ha, the desired UX is HIGH_THROUGHPUT, which means we can switch
            // to an unblocked leg before sending any cells over the join point,
            // as long as there are some unblocked legs.

            // TODO: figure out how to rewrite this with an idiomatic iterator combinator
            let mut all_blocked_on_cc = true;
            for leg in &self.legs {
                all_blocked_on_cc = Self::is_join_point_blocked_on_cc(join_hop, leg)?;
                if !all_blocked_on_cc {
                    break;
                }
            }

            if all_blocked_on_cc {
                // All legs are blocked on cc, so we must stop reading from
                // the join point streams for now.
                trace!(
                    tunnel_id = %self.tunnel_id,
                    join_point = ?primary_join_point,
                    reason = "all legs blocked on congestion control",
                    "Pausing join point stream reads"
                );

                true
            } else {
                // At least one leg is not blocked, so we can continue reading
                // from the join point streams
                false
            }
        };

        Ok(should_skip)
    }

    /// Returns the next ready [`CircuitEvent`],
    /// obtained from processing the incoming/outgoing messages on all the circuits in this set.
    ///
    /// Will return an error if there are no circuits in this set,
    /// or other internal errors occur.
    ///
    /// This is cancellation-safe.
    #[allow(clippy::unnecessary_wraps)] // Can return Err if conflux is enabled
    #[instrument(level = "trace", skip_all)]
    pub(super) async fn next_circ_event(
        &mut self,
        runtime: &tor_rtcompat::DynTimeProvider,
    ) -> Result<SmallVec<[CircuitEvent; CIRC_EVENT_COUNT]>, crate::Error> {
        // Avoid polling the streams on the join point if our primary
        // leg is blocked on cc
        cfg_if::cfg_if! {
            if #[cfg(feature = "conflux")] {
                let mut should_poll_join_point = !self.should_skip_join_point()?;
            } else {
                let mut should_poll_join_point = true;
            }
        };
        let join_point = self.primary_join_point().map(|join_point| join_point.1);

        // Each circuit leg has a PollAll future (see poll_all_circ below)
        // that drives two futures: one that reads from input channel,
        // and another drives the application streams.
        //
        // *This* PollAll drives the PollAll futures of all circuit legs in lockstep,
        // ensuring they all get a chance to make some progress on every reactor iteration.
        //
        // IMPORTANT: if you want to push additional futures into this,
        // bear in mind that the ordering matters!
        // If multiple futures resolve at the same time, their results will be processed
        // in the order their corresponding futures were inserted into `PollAll`.
        // So if futures A and B resolve at the same time, and future A was pushed
        // into `PollAll` before future B, the result of future A will come
        // before future B's result in the result list returned by poll_all.await.
        //
        // This means that the events corresponding to the first circuit in the tunnel
        // will be executed first, followed by the events issued by the next circuit,
        // and so on.
        //
        let mut poll_all =
            PollAll::<MAX_CONFLUX_LEGS, SmallVec<[CircuitEvent; NUM_CIRC_FUTURES]>>::new();

        for leg in &mut self.legs {
            let unique_id = leg.unique_id();
            let tunnel_id = self.tunnel_id;
            let runtime = runtime.clone();

            // Garbage-collect all halfstreams that have expired.
            //
            // Note: this will iterate over the closed streams of all hops.
            // If we think this will cause perf issues, one idea would be to make
            // StreamMap::closed_streams into a min-heap, and add a branch to the
            // select_biased! below to sleep until the first expiry is due
            // (but my gut feeling is that iterating is cheaper)
            leg.remove_expired_halfstreams(runtime.now());

            // The client SHOULD abandon and close circuit if the LINKED message takes too long to
            // arrive. This timeout MUST be no larger than the normal SOCKS/stream timeout in use for
            // RELAY_BEGIN, but MAY be the Circuit Build Timeout value, instead. (The C-Tor
            // implementation currently uses Circuit Build Timeout).
            let conflux_hs_timeout = leg.conflux_hs_timeout();

            let mut poll_all_circ = PollAll::<NUM_CIRC_FUTURES, CircuitEvent>::new();

            let input = leg.input.next().map(move |res| match res {
                Some(msg) => match msg.try_into() {
                    Ok(cell) => CircuitEvent::HandleCell {
                        leg: unique_id,
                        cell,
                    },
                    // A message outside our restricted set is either a fatal internal error or
                    // a protocol violation somehow so shutdown.
                    //
                    // TODO(relay): We have this spec ticket open about this behavior:
                    // https://gitlab.torproject.org/tpo/core/torspec/-/issues/385. It is plausible
                    // that we decide to either keep this circuit close behavior or close the
                    // entire channel in this case. Resolution of the above ticket needs to fix
                    // this part.
                    Err(e) => CircuitEvent::ProtoViolation { err: e },
                },
                None => CircuitEvent::RemoveLeg {
                    leg: unique_id,
                    reason: RemoveLegReason::ChannelClosed,
                },
            });
            poll_all_circ.push(input);

            // This future resolves when the chan_sender sink (i.e. the outgoing TCP connection)
            // becomes ready. We need it inside the next_ready_stream future below,
            // to prevent reading from the application streams before we are ready to send.
            let chan_ready_fut = futures::future::poll_fn(|cx| {
                use futures::Sink as _;

                // Ensure the chan sender sink is ready before polling the ready streams.
                Pin::new(&mut leg.chan_sender).poll_ready(cx)
            });

            let exclude_hop = if should_poll_join_point {
                // Avoid polling the join point more than once per reactor loop.
                should_poll_join_point = false;
                None
            } else {
                join_point
            };

            let mut ready_streams = leg.hops.ready_streams_iterator(exclude_hop);
            let next_ready_stream = async move {
                // Avoid polling the application streams if the outgoing sink is blocked
                let _ = chan_ready_fut.await;

                match ready_streams.next().await {
                    Some(x) => x,
                    None => {
                        info!(circ_id=%unique_id, "no ready streams (maybe blocked on cc?)");
                        // There are no ready streams (for example, they may all be
                        // blocked due to congestion control), so there is nothing
                        // to do.
                        // We await an infinitely pending future so that we don't
                        // immediately return a `None` in the `select_biased!` below.
                        // We'd rather wait on `input.next()` than immediately return with
                        // no `CircuitEvent`, which could put the reactor into a spin loop.
                        let () = std::future::pending().await;
                        unreachable!();
                    }
                }
            };

            poll_all_circ.push(next_ready_stream.map(move |cmd| CircuitEvent::RunCmd {
                leg: unique_id,
                cmd,
            }));

            let mut next_padding_event_fut = leg.padding_event_stream.next();

            // This selects between 3 events that cannot be handled concurrently.
            //
            // If the conflux handshake times out, we need to remove the circuit leg
            // (any pending padding events or application stream data should be discarded;
            // in fact, there shouldn't even be any open streams on circuits that are
            // in the conflux handshake phase).
            //
            // If there's a padding event, we need to handle it immediately,
            // because it might tell us to start blocking the chan_sender sink,
            // which, in turn, means we need to stop trying to read from the application streams.
            poll_all.push(
                async move {
                    let conflux_hs_timeout = if let Some(timeout) = conflux_hs_timeout {
                        // TODO: ask Diziet if we can have a sleep_until_instant() function
                        Box::pin(runtime.sleep_until_wallclock(timeout))
                            as Pin<Box<dyn Future<Output = ()> + Send>>
                    } else {
                        Box::pin(std::future::pending())
                    };
                    select_biased! {
                        () = conflux_hs_timeout.fuse() => {
                            warn!(
                                tunnel_id = %tunnel_id,
                                circ_id = %unique_id,
                                "Conflux handshake timed out on circuit"
                            );

                            // Conflux handshake has timed out, time to remove this circuit leg,
                            // and notify the handshake initiator.
                            smallvec![CircuitEvent::RemoveLeg {
                                leg: unique_id,
                                reason: RemoveLegReason::ConfluxHandshakeTimeout,
                            }]
                        }
                        padding_event = next_padding_event_fut => {
                            smallvec![CircuitEvent::PaddingAction {
                                leg: unique_id,
                                padding_event:
                                    padding_event.expect("PaddingEventStream, surprisingly, was terminated!"),
                            }]
                        }
                        ret = poll_all_circ.fuse() => ret,
                    }
                }
            );
        }

        // Flatten the nested SmallVecs to simplify the calling code
        // (which will handle all the returned events sequentially).
        Ok(poll_all.await.into_iter().flatten().collect())
    }

    /// The join point on the current primary leg.
    pub(super) fn primary_join_point(&self) -> Option<(UniqId, HopNum)> {
        self.join_point
            .as_ref()
            .map(|join_point| (self.primary_id, join_point.hop))
    }

    /// Does congestion control use stream SENDMEs for the given hop?
    ///
    /// Returns `None` if either the `leg` or `hop` don't exist.
    pub(super) fn uses_stream_sendme(&self, leg: UniqId, hop: HopNum) -> Option<bool> {
        self.leg(leg)?.uses_stream_sendme(hop)
    }

    /// Encode `msg`, encrypt it, and send it to the 'hop'th hop.
    ///
    /// See [`Circuit::send_relay_cell`].
    #[instrument(level = "trace", skip_all)]
    pub(super) async fn send_relay_cell_on_leg(
        &mut self,
        msg: SendRelayCell,
        leg: Option<UniqId>,
    ) -> crate::Result<()> {
        let conflux_join_point = self.join_point.as_ref().map(|join_point| join_point.hop);
        let leg = if let Some(join_point) = conflux_join_point {
            let hop = msg.hop.expect("missing hop in client SendRelayCell?!");
            // Conflux circuits always send multiplexed relay commands to
            // to the last hop (the join point).
            if cmd_counts_towards_seqno(msg.cell.cmd()) {
                if hop != join_point {
                    // For leaky pipe, we must continue using the original leg
                    leg
                } else {
                    let old_primary_leg = self.primary_id;
                    // Check if it's time to switch our primary leg.
                    #[cfg(feature = "conflux")]
                    if let Some(switch_cell) = self.maybe_update_primary_leg()? {
                        trace!(
                            old = ?old_primary_leg,
                            new = ?self.primary_id,
                            "Switching primary conflux leg..."
                        );

                        self.primary_leg_mut()?.send_relay_cell(switch_cell).await?;
                    }

                    // Use the possibly updated primary leg
                    Some(self.primary_id)
                }
            } else {
                // Non-multiplexed commands go on their original
                // circuit and hop
                leg
            }
        } else {
            // If there is no join point, it means this is not
            // a multi-path tunnel, so we continue using
            // the leg_id/hop the cmd came from.
            leg
        };

        let leg = leg.unwrap_or(self.primary_id);

        let circ = self
            .leg_mut(leg)
            .ok_or_else(|| internal!("leg disappeared?!"))?;

        circ.send_relay_cell(msg).await
    }

    /// Send a LINK cell down each unlinked leg.
    #[cfg(feature = "conflux")]
    pub(super) async fn link_circuits(
        &mut self,
        runtime: &tor_rtcompat::DynTimeProvider,
    ) -> crate::Result<()> {
        let (_leg_id, join_point) = self
            .primary_join_point()
            .ok_or_else(|| internal!("no join point when trying to send LINK"))?;

        // Link all the circuits that haven't started the conflux handshake yet.
        for circ in self
            .legs
            .iter_mut()
            // TODO: it is an internal error if any of the legs don't have a conflux handler
            // (i.e. if conflux_status() returns None)
            .filter(|circ| circ.conflux_status() == Some(ConfluxStatus::Unlinked))
        {
            let v1_payload = V1LinkPayload::new(self.nonce, self.desired_ux);
            let link = ConfluxLink::new(v1_payload);
            let cell = AnyRelayMsgOuter::new(None, link.into());

            circ.begin_conflux_link(join_point, cell, runtime).await?;
        }

        // TODO(conflux): the caller should take care to not allow opening streams
        // until the conflux set is ready (i.e. until at least one of the legs completes
        // the handshake).
        //
        // We will probably need a channel for notifying the caller
        // of handshake completion/conflux set readiness

        Ok(())
    }

    /// Get the number of unlinked or non-conflux legs.
    #[cfg(feature = "conflux")]
    pub(super) fn num_unlinked(&self) -> usize {
        self.circuits()
            .filter(|circ| {
                let status = circ.conflux_status();
                status.is_none() || status == Some(ConfluxStatus::Unlinked)
            })
            .count()
    }

    /// Check if the specified sequence number is the sequence number of the
    /// next message we're expecting to handle.
    pub(super) fn is_seqno_in_order(&self, seq_recv: u64) -> bool {
        let last_seq_delivered = self.last_seq_delivered.load(atomic::Ordering::Acquire);
        seq_recv == last_seq_delivered + 1
    }

    /// Remove the circuit leg with the specified `UniqId` from this conflux set.
    ///
    /// Unlike [`ConfluxSet::remove`], this function does not check
    /// if the removal of the leg ought to trigger a reactor shutdown.
    ///
    /// Returns an error if the leg doesn't exit in the conflux set.
    fn remove_unchecked(&mut self, circ_id: UniqId) -> Result<Circuit, Bug> {
        let idx = self
            .legs
            .iter()
            .position(|circ| circ.unique_id() == circ_id)
            .ok_or_else(|| internal!("leg {circ_id:?} not found in conflux set"))?;

        Ok(self.legs.remove(idx))
    }

    /// Perform some circuit-padding-based event on the specified circuit.
    #[cfg(feature = "circ-padding")]
    pub(super) async fn run_padding_event(
        &mut self,
        circ_id: UniqId,
        padding_event: PaddingEvent,
    ) -> crate::Result<()> {
        use PaddingEvent as E;
        let Some(circ) = self.leg_mut(circ_id) else {
            // No such circuit; it must have gone away after generating this event.
            // Just ignore it.
            return Ok(());
        };

        match padding_event {
            E::SendPadding(send_padding) => {
                circ.send_padding(send_padding).await?;
            }
            E::StartBlocking(start_blocking) => {
                circ.start_blocking_for_padding(start_blocking);
            }
            E::StopBlocking => {
                circ.stop_blocking_for_padding();
            }
        }
        Ok(())
    }
}

/// An error returned when a method is expecting a single-leg conflux circuit,
/// but it is not single-leg.
#[derive(Clone, Debug, derive_more::Display, thiserror::Error)]
pub(super) struct NotSingleLegError(#[source] Bug);

impl From<NotSingleLegError> for Bug {
    fn from(e: NotSingleLegError) -> Self {
        e.0
    }
}

impl From<NotSingleLegError> for crate::Error {
    fn from(e: NotSingleLegError) -> Self {
        Self::from(e.0)
    }
}

impl From<NotSingleLegError> for ReactorError {
    fn from(e: NotSingleLegError) -> Self {
        Self::from(e.0)
    }
}

impl<I: Iterator> From<ExactlyOneError<I>> for NotSingleLegError {
    fn from(e: ExactlyOneError<I>) -> Self {
        // TODO: cannot wrap the ExactlyOneError with into_bad_api_usage
        // because it's not Send + Sync
        Self(bad_api_usage!("not a single leg conflux set ({e})"))
    }
}

#[cfg(test)]
mod test {
    // Tested in [`crate::client::circuit::test`].
}
