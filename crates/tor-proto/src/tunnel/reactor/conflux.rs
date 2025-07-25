//! Conflux-related functionality

#[cfg(feature = "conflux")]
mod msghandler;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{self, AtomicU64};
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use futures::{select_biased, stream::FuturesUnordered, FutureExt as _};
use itertools::structs::ExactlyOneError;
use itertools::Itertools;
use smallvec::{smallvec, SmallVec};
use tor_rtcompat::SleepProviderExt as _;
use tracing::{info, trace, warn};

use tor_async_utils::SinkPrepareExt as _;
use tor_basic_utils::flatten;
use tor_cell::relaycell::{AnyRelayMsgOuter, RelayCmd};
use tor_error::{bad_api_usage, internal, Bug};
use tor_linkspec::HasRelayIds as _;

use crate::circuit::path::HopDetail;
use crate::circuit::{TunnelMutableState, UniqId};
use crate::crypto::cell::HopNum;
use crate::tunnel::reactor::circuit::ConfluxStatus;
use crate::tunnel::{streammap, TunnelId};
use crate::util::err::ReactorError;

use super::circuit::CircHop;
use super::{Circuit, CircuitAction, RemoveLegReason, SendRelayCell};

#[cfg(feature = "conflux")]
use {
    tor_cell::relaycell::conflux::{V1DesiredUx, V1LinkPayload, V1Nonce},
    tor_cell::relaycell::msg::{ConfluxLink, ConfluxSwitch},
};

#[cfg(feature = "conflux")]
pub(crate) use msghandler::{ConfluxAction, ConfluxMsgHandler, OooRelayMsg};

/// The maximum number of conflux legs to store in the conflux set SmallVec.
///
/// Attempting to store more legs will cause the SmallVec to spill to the heap.
///
/// Note: this value was picked arbitrarily and may not be suitable.
const MAX_CONFLUX_LEGS: usize = 16;

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
                (HopDetail::Relay(t1), HopDetail::Relay(ref t2)) => Ok(t1.same_relay_ids(t2)),
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

        for circ in self.legs.iter_mut() {
            // The circuits that have a None status don't know they're part of
            // a multi-path tunnel yet. They need to be initialized with a
            // conflux message handler, and have their join point fixed up
            // to share a stream map with the join point on all the other circuits.
            if circ.conflux_status().is_none() {
                let conflux_handler = ConfluxMsgHandler::new_client(
                    join_point.hop,
                    self.nonce,
                    Arc::clone(&self.last_seq_delivered),
                    runtime.clone(),
                );

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
            hop: join_point,
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

    /// Returns the `HopNum` of the join point
    /// if [`next_circ_action`](Self::next_circ_action)
    /// should avoid polling the join point streams entirely.
    #[cfg(feature = "conflux")]
    fn should_skip_join_point(&self) -> Result<Option<HopNum>, Bug> {
        let Some(primary_join_point) = self.primary_join_point() else {
            // Single-path, there is no join point
            return Ok(None);
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
            return Ok(None);
        }

        // Now, if the primary *is* blocked on cc, we may still be able to poll
        // the join point streams (if we're using the right desired UX)
        let exclude = if self.desired_ux != V1DesiredUx::HIGH_THROUGHPUT {
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

            Some(join_hop)
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

                Some(join_hop)
            } else {
                // At least one leg is not blocked, so we can continue reading
                // from the join point streams
                None
            }
        };

        Ok(exclude)
    }

    /// Returns the next ready [`CircuitAction`],
    /// obtained from processing the incoming/outgoing messages on all the circuits in this set.
    ///
    /// Will return an error if there are no circuits in this set,
    /// or other internal errors occur.
    ///
    /// This is cancellation-safe.
    #[allow(clippy::unnecessary_wraps)] // Can return Err if conflux is enabled
    pub(super) fn next_circ_action<'a>(
        &'a mut self,
        runtime: &'a tor_rtcompat::DynTimeProvider,
    ) -> Result<impl Future<Output = Result<CircuitAction, crate::Error>> + 'a, Bug> {
        // Avoid polling the streams on the join point if our primary
        // leg is blocked on cc
        cfg_if::cfg_if! {
            if #[cfg(feature = "conflux")] {
                let exclude_hop = self.should_skip_join_point()?;
            } else {
                let exclude_hop: Option<HopNum> = None;
            }
        };

        Ok(self.legs
            .iter_mut()
            .map(|leg| {
                let unique_id = leg.unique_id();
                let tunnel_id = self.tunnel_id;

                // The client SHOULD abandon and close circuit if the LINKED message takes too long to
                // arrive. This timeout MUST be no larger than the normal SOCKS/stream timeout in use for
                // RELAY_BEGIN, but MAY be the Circuit Build Timeout value, instead. (The C-Tor
                // implementation currently uses Circuit Build Timeout).
                let conflux_hs_timeout = if leg.conflux_status() == Some(ConfluxStatus::Pending) {
                    if let Some(timeout) = leg.conflux_hs_timeout() {
                        // TODO: ask Diziet if we can have a sleep_until_instant() function
                        Box::pin(runtime.sleep_until_wallclock(timeout))
                            as Pin<Box<dyn Future<Output = ()> + Send>>
                    } else {
                        Box::pin(std::future::pending())
                    }
                } else {
                    Box::pin(std::future::pending())
                };

                let mut ready_streams = leg.ready_streams_iterator(exclude_hop);
                let input = &mut leg.input;
                // TODO: we don't really need prepare_send_from here
                // because the inner select_biased! is cancel-safe.
                // We should replace this with a simple sink readiness check
                let send_fut = leg.chan_sender.prepare_send_from(async move {
                    // A future to wait for the next ready stream.
                    let next_ready_stream = async {
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
                                // no `CircuitAction`, which could put the reactor into a spin loop.
                                let () = std::future::pending().await;
                                unreachable!();
                            }
                        }
                    };

                    // NOTE: the stream returned by this function is polled in the select_biased!
                    // from Reactor::run_once(), so each block from *this* select_biased! must be
                    // cancellation-safe
                    select_biased! {
                        // Check whether we've got an input message pending.
                        ret = input.next().fuse() => {
                            let Some(cell) = ret else {
                                return Ok(CircuitAction::RemoveLeg {
                                    leg: unique_id,
                                    reason: RemoveLegReason::ChannelClosed,
                                });
                            };

                            Ok(CircuitAction::HandleCell { leg: unique_id, cell })
                        },
                        ret = next_ready_stream.fuse() => {
                            let ret = ret.map(|cmd| {
                                Ok(CircuitAction::RunCmd { leg: unique_id, cmd })
                            });

                            flatten(ret)
                        },
                    }
                });

                let mut send_fut = Box::pin(send_fut);

                async move {
                    select_biased! {
                        () = conflux_hs_timeout.fuse() => {
                            warn!(
                                tunnel_id = %tunnel_id,
                                circ_id = %unique_id,
                                "Conflux handshake timed out on circuit"
                            );

                            // Conflux handshake has timed out, time to remove this circuit leg,
                            // and notify the handshake initiator.
                            Ok(Ok(CircuitAction::RemoveLeg {
                                leg: unique_id,
                                reason: RemoveLegReason::ConfluxHandshakeTimeout,
                            }))
                        }
                        ret = send_fut => {
                            // Note: We don't actually use the returned SinkSendable,
                            // and continue writing to the SometimesUboundedSink in the reactor :(
                            ret.map(|ret| ret.0)
                        }
                    }
                }
            })
            .collect::<FuturesUnordered<_>>()
            // We only return the first ready action as a Future.
            // Can't use `next()` since it borrows the stream.
            .into_future()
            .map(|(next, _)| next.ok_or(internal!("empty conflux set").into()))
            // Clean up the nested `Result`s before returning to the caller.
            .map(|res| flatten(flatten(res))))
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
    pub(super) async fn send_relay_cell_on_leg(
        &mut self,
        msg: SendRelayCell,
        leg: Option<UniqId>,
    ) -> crate::Result<()> {
        let conflux_join_point = self.join_point.as_ref().map(|join_point| join_point.hop);
        let leg = if let Some(join_point) = conflux_join_point {
            // Conflux circuits always send multiplexed relay commands to
            // to the last hop (the join point).
            if cmd_counts_towards_seqno(msg.cell.cmd()) {
                if msg.hop != join_point {
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

/// Whether the specified `cmd` counts towards the conflux sequence numbers.
fn cmd_counts_towards_seqno(cmd: RelayCmd) -> bool {
    // Note: copy-pasted from c-tor
    match cmd {
        // These are all fine to multiplex, and must be so that ordering is preserved
        RelayCmd::BEGIN | RelayCmd::DATA | RelayCmd::END | RelayCmd::CONNECTED => true,

        // We can't multiplex these because they are circuit-specific
        RelayCmd::SENDME
        | RelayCmd::EXTEND
        | RelayCmd::EXTENDED
        | RelayCmd::TRUNCATE
        | RelayCmd::TRUNCATED
        | RelayCmd::DROP => false,

        //  We must multiplex RESOLVEs because their ordering impacts begin/end.
        RelayCmd::RESOLVE | RelayCmd::RESOLVED => true,

        // These are all circuit-specific
        RelayCmd::BEGIN_DIR
        | RelayCmd::EXTEND2
        | RelayCmd::EXTENDED2
        | RelayCmd::ESTABLISH_INTRO
        | RelayCmd::ESTABLISH_RENDEZVOUS
        | RelayCmd::INTRODUCE1
        | RelayCmd::INTRODUCE2
        | RelayCmd::RENDEZVOUS1
        | RelayCmd::RENDEZVOUS2
        | RelayCmd::INTRO_ESTABLISHED
        | RelayCmd::RENDEZVOUS_ESTABLISHED
        | RelayCmd::INTRODUCE_ACK
        | RelayCmd::PADDING_NEGOTIATE
        | RelayCmd::PADDING_NEGOTIATED => false,

        // Flow control cells must be ordered (see prop 329).
        RelayCmd::XOFF | RelayCmd::XON => true,

        // These two are not multiplexed, because they must be processed immediately
        // to update sequence numbers before any other cells are processed on the circuit
        RelayCmd::CONFLUX_SWITCH
        | RelayCmd::CONFLUX_LINK
        | RelayCmd::CONFLUX_LINKED
        | RelayCmd::CONFLUX_LINKED_ACK => false,

        _ => {
            tracing::warn!("Conflux asked to multiplex unknown relay command {cmd}");
            false
        }
    }
}

#[cfg(test)]
mod test {
    // Tested in [`crate::tunnel::circuit::test`].
}
