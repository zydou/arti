//! Conflux-related functionality

#[cfg(feature = "conflux")]
mod msghandler;

use std::future::Future;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use futures::StreamExt;
use futures::{select_biased, stream::FuturesUnordered, FutureExt as _};
use itertools::Itertools as _;
use slotmap_careful::SlotMap;

use tor_async_utils::SinkPrepareExt as _;
use tor_basic_utils::flatten;
use tor_cell::relaycell::RelayCmd;
use tor_error::{bad_api_usage, internal, into_bad_api_usage, Bug};
use tor_linkspec::HasRelayIds as _;

use crate::circuit::path::HopDetail;
use crate::crypto::cell::HopNum;
use crate::tunnel::reactor::circuit::ConfluxStatus;
use crate::util::err::ReactorError;

use super::{Circuit, CircuitAction, LegId, LegIdKey, RemoveLegReason};

#[cfg(feature = "conflux")]
use {
    tor_cell::relaycell::conflux::{V1DesiredUx, V1LinkPayload, V1Nonce},
    tor_cell::relaycell::msg::ConfluxLink,
    tor_cell::relaycell::AnyRelayMsgOuter,
};

#[cfg(feature = "conflux")]
pub(crate) use msghandler::{ConfluxAction, ConfluxMsgHandler, OooRelayMsg};

/// A set of linked conflux circuits.
pub(super) struct ConfluxSet {
    /// The circuits in this conflux set.
    legs: SlotMap<LegIdKey, Circuit>,
    /// The unique identifier of the primary leg
    primary_id: LegIdKey,
    /// The join point of the set, if this is a multi-path set.
    ///
    /// The exact leg this is located on depends on which leg is currently the primary.
    ///
    /// Initially the conflux set starts out as a single-path set with no join point.
    /// When it is converted to a multipath set using [`add_legs`](Self::add_legs),
    /// the join point is initialized to the last hop in the tunnel
    /// (which should be the same for all the circuits in the set).
    //
    // TODO(conflux): for simplicity, we currently we force all legs to have the same length,
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
    last_seq_delivered: Arc<AtomicU32>,
}

/// The conflux join point.
#[derive(Debug, Clone)]
struct JoinPoint {
    /// The hop number.
    hop: HopNum,
    /// The HopDetail of the hop.
    detail: HopDetail,
}

impl ConfluxSet {
    /// Create a new conflux set, consisting of a single leg.
    pub(super) fn new(circuit_leg: Circuit) -> Self {
        let mut legs: SlotMap<LegIdKey, Circuit> = SlotMap::with_key();
        let primary_id = legs.insert(circuit_leg);
        // Note: the join point is only set for multi-path tunnels
        let join_point = None;

        // TODO(conflux): read this from the consensus/config.
        #[cfg(feature = "conflux")]
        let desired_ux = V1DesiredUx::NO_OPINION;

        Self {
            legs,
            primary_id,
            join_point,
            #[cfg(feature = "conflux")]
            nonce: V1Nonce::new(&mut rand::rng()),
            #[cfg(feature = "conflux")]
            desired_ux,
            last_seq_delivered: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Remove and return the only leg of this conflux set.
    ///
    /// Returns an error if there is more than one leg in the set,
    /// or if called before any circuit legs are available.
    ///
    /// Calling this function will empty the [`ConfluxSet`].
    pub(super) fn take_single_leg(&mut self) -> Result<Circuit, NotSingleLegError> {
        let circ = get_single(self.legs.remove(self.primary_id).into_iter())?;
        Ok(circ)
    }

    /// Return a reference to the only leg of this conflux set,
    /// along with the leg's ID.
    ///
    /// Returns an error if there is more than one leg in the set,
    /// or if called before any circuit legs are available.
    pub(super) fn single_leg(&self) -> Result<(LegId, &Circuit), NotSingleLegError> {
        let (circ_id, circ) = get_single(self.legs.iter())?;
        Ok((LegId(circ_id), circ))
    }

    /// Return a mutable reference to the only leg of this conflux set,
    /// along with the leg's ID.
    ///
    /// Returns an error if there is more than one leg in the set,
    /// or if called before any circuit legs are available.
    pub(super) fn single_leg_mut(&mut self) -> Result<(LegId, &mut Circuit), NotSingleLegError> {
        let (circ_id, circ) = get_single(self.legs.iter_mut())?;
        Ok((LegId(circ_id), circ))
    }

    /// Return the primary leg of this conflux set.
    ///
    /// Returns an error if called before any circuit legs are available.
    pub(super) fn primary_leg_mut(&mut self) -> Result<&mut Circuit, Bug> {
        // TODO(conflux): support more than one leg,
        // and remove this check
        if self.legs.len() > 1 {
            return Err(internal!("multipath not currently supported"));
        }

        if self.legs.is_empty() {
            Err(bad_api_usage!(
                "tried to get circuit leg before creating it?!"
            ))
        } else {
            // TODO(conflux): implement primary leg selection
            let circ = self
                .legs
                .get_mut(self.primary_id)
                .ok_or_else(|| internal!("slotmap is empty?!"))?;

            Ok(circ)
        }
    }

    /// Return a reference to the leg of this conflux set with the given id.
    pub(super) fn leg(&self, leg_id: LegId) -> Option<&Circuit> {
        self.legs.get(leg_id.0)
    }

    /// Return a mutable reference to the leg of this conflux set with the given id.
    pub(super) fn leg_mut(&mut self, leg_id: LegId) -> Option<&mut Circuit> {
        self.legs.get_mut(leg_id.0)
    }

    /// Return an iterator of all legs in the conflux set.
    pub(super) fn legs(&self) -> impl Iterator<Item = (LegId, &Circuit)> {
        self.legs.iter().map(|(id, leg)| (LegId(id), leg))
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
    /// Returns an error if the given leg doesn't exist in the set,
    /// or if after removing the leg the set is depleted (empty).
    pub(super) fn remove(&mut self, leg: LegIdKey) -> Result<(), ReactorError> {
        let _ = self
            .legs
            .remove(leg)
            .ok_or_else(|| bad_api_usage!("leg {leg:?} not found in conflux set"))?;

        // TODO(conflux): if leg == primary_leg, reassign the next best leg to primary_leg

        if self.legs.is_empty() {
            // The last circuit in the set has just died, so the reactor should exit.
            return Err(ReactorError::Shutdown);
        }

        Ok(())
    }

    /// Return an iterator of all circuits in the conflux set.
    fn circuits(&self) -> impl Iterator<Item = &Circuit> {
        self.legs.iter().map(|(_id, leg)| leg)
    }

    /// Add legs to the this conflux set.
    ///
    /// Returns an error if any of the legs are invalid,
    /// or if adding the legs would cause the conflux set to contain
    /// any circuits that have the same hop in the middle and guard positions
    /// (legs of the form `G1 - M1 - E` and `G2 - M1 - E`,
    /// or `G1 - M1 -E` and `G1 - M2 - E ` aren't allowed to be part
    /// of the same conflux set).
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
    #[cfg(feature = "conflux")]
    pub(super) fn add_legs(&mut self, legs: Vec<Circuit>) -> Result<(), Bug> {
        if legs.is_empty() {
            return Err(bad_api_usage!("asked to add empty leg list to conflux set"));
        }

        let join_point = match self.join_point.take() {
            Some(p) => {
                // Preserve the existing join point, if there is one.
                p
            }
            None => {
                let (hop, detail) = (|| {
                    let first_leg = legs.first()?;
                    let all_hops = first_leg.path().all_hops();
                    let hop = first_leg.last_hop_num()?;
                    let detail = all_hops.last()?;
                    Some((hop, detail.clone()))
                })()
                .ok_or_else(|| bad_api_usage!("asked to join circuit with no hops"))?;

                JoinPoint {
                    hop,
                    detail: detail.clone(),
                }
            }
        };

        // Check two HopDetails for equality.
        let hops_eq = |h1: &HopDetail, h2: &HopDetail| {
            match (h1, h2) {
                (HopDetail::Relay(t1), HopDetail::Relay(ref t2)) => t1.same_relay_ids(t2),
                (HopDetail::Virtual, HopDetail::Virtual) => {
                    // TODO(conflux): HopDetail::Virtual are always considered equal,
                    // but that's not exactly right. We should resolve the TODO
                    // from HopDetail::Virtual, and store some additional context
                    // for differentiating virtual hops
                    true
                }
                _ => false,
            }
        };

        // Check if the last hop of leg is the same as the one from the first hop.
        let cmp_hop_detail = |leg: Option<&HopDetail>| {
            leg.map(|leg| hops_eq(leg, &join_point.detail))
                .unwrap_or_default()
        };

        // A leg is considered valid if
        //
        //   * the circuit has the expected length
        //     (the length of the first circuit we added to the set)
        //   * its last hop is equal to the designated join point
        //     (the last hop of the first circuit we added)
        //   * the circuit has no streams attached to any of its hops
        //   * the circuit is not already part of a conflux tunnel
        let leg_is_valid = |leg: &Circuit| {
            leg.last_hop_num() == Some(join_point.hop)
                && cmp_hop_detail(leg.path().all_hops().last())
                && !leg.has_streams()
                && leg.conflux_status().is_none()
        };

        if !legs.iter().all(leg_is_valid) {
            return Err(bad_api_usage!(
                "one more more conflux circuits are invalid"
            ));
        }

        let check_legs_disjoint = |(leg1, leg2): (&Circuit, &Circuit)| {
            // TODO(conflux): add a new Path API for getting an iterator over HopDetail.
            let path1 = leg1.path().all_hops();
            let path1_except_last = path1.iter().dropping_back(1);
            let path2 = leg2.path().all_hops();
            let path2_except_last = path2.iter().dropping_back(1);

            // At this point we've already validated the lengths of the new legs,
            // so we know they all have the same length.
            path1_except_last
                .zip(path2_except_last)
                .all(|(h1, h2)| !hops_eq(h1, h2))
        };

        // TODO(conflux): reduce unnecessary iteration over `legs`
        // without hurting readability

        // Ensure the legs don't share guard or middle relays
        //
        // TODO(conflux): is this right?
        // It means we allow legs of the form
        //
        //  N1 --- N2 ----
        //                \
        //                 E
        //  N2 --- N1-----/
        //
        //  But I think that's alright.
        if !self
            .circuits()
            .chain(legs.iter())
            .cartesian_product(legs.iter())
            .all(check_legs_disjoint)
        {
            return Err(bad_api_usage!(
                "conflux circuits must not share hops in the same position"
            ));
        }

        // Select a join point, or put the existing one back into self.
        self.join_point = Some(join_point.clone());

        // The legs are valid, so add them to the set.
        for mut circ in legs {
            let conflux_handler = ConfluxMsgHandler::new_client(
                join_point.hop,
                self.nonce,
                Arc::clone(&self.last_seq_delivered),
            );

            circ.install_conflux_handler(conflux_handler);
            self.legs.insert(circ);
        }

        Ok(())
    }

    /// Returns the next ready [`CircuitAction`],
    /// obtained from processing the incoming/outgoing messages on all the circuits in this set.
    ///
    /// Will return an error if there are no circuits in this set,
    /// or other internal errors occur.
    ///
    /// This is cancellation-safe.
    pub(super) fn next_circ_action<'a>(
        &'a mut self,
    ) -> impl Future<Output = Result<CircuitAction, crate::Error>> + 'a {
        self.legs
            .iter_mut()
            .map(|(leg_id, leg)| {
                let mut ready_streams = leg.ready_streams_iterator();
                let input = &mut leg.input;
                // TODO: we don't really need prepare_send_from here
                // because the inner select_biased! is cancel-safe.
                // We should replace this with a simple sink readiness check
                leg.chan_sender.prepare_send_from(async move {
                    // A future to wait for the next ready stream.
                    let next_ready_stream = async {
                        match ready_streams.next().await {
                            Some(x) => x,
                            None => {
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
                                    leg: leg_id,
                                    reason: RemoveLegReason::ChannelClosed,
                                });
                            };

                            Ok(CircuitAction::HandleCell { leg: leg_id, cell })
                        },
                        ret = next_ready_stream.fuse() => {
                            ret.map(|cmd| CircuitAction::RunCmd { leg: leg_id, cmd })
                        },
                    }
                })
            })
            .collect::<FuturesUnordered<_>>()
            // Note: We don't actually use the returned SinkSendable,
            // and continue writing to the SometimesUboundedSink in the reactor :(
            .map(|res| res.map(|res| res.0))
            // We only return the first ready action as a Future.
            // Can't use `next()` since it borrows the stream.
            .into_future()
            .map(|(next, _)| next.ok_or(internal!("empty conflux set").into()))
            // Clean up the nested `Result`s before returning to the caller.
            .map(|res| flatten(flatten(res)))
    }

    /// The join point on the current primary leg.
    pub(super) fn primary_join_point(&self) -> Option<(LegId, HopNum)> {
        self.join_point
            .as_ref()
            .map(|join_point| (LegId(self.primary_id), join_point.hop))
    }

    /// Does congestion control use stream SENDMEs for the given hop?
    ///
    /// Returns `None` if either the `leg` or `hop` don't exist.
    pub(super) fn uses_stream_sendme(&self, leg: LegId, hop: HopNum) -> Option<bool> {
        self.leg(leg)?.uses_stream_sendme(hop)
    }

    /// Send a LINK cell down each unlinked leg.
    #[cfg(feature = "conflux")]
    pub(super) async fn link_circuits(&mut self) -> crate::Result<()> {
        let (_leg_id, join_point) = self
            .primary_join_point()
            .ok_or_else(|| internal!("no join point when trying to send LINK"))?;

        // Link all the circuits that haven't started the conflux handshake yet.
        for (_, circ) in self
            .legs
            .iter_mut()
            // TODO: it is an internal error if any of the legs don't have a conflux handler
            // (i.e. if conflux_status() returns None)
            .filter(|(_, circ)| circ.conflux_status() == Some(ConfluxStatus::Unlinked))
        {
            let v1_payload = V1LinkPayload::new(self.nonce, self.desired_ux);
            let link = ConfluxLink::new(v1_payload);
            let cell = AnyRelayMsgOuter::new(None, link.into());

            circ.begin_conflux_link(join_point, cell).await?;
        }

        // TODO(conflux): the caller should take care to not allow opening streams
        // until the conflux set is ready (i.e. until at least one of the legs completes
        // the handshake).
        //
        // We will probably need a channel for notifying the caller
        // of handshake completion/conflux set readiness

        Ok(())
    }
}

// TODO(conflux): replace this with Itertools::exactly_one()?
//
/// Get the only item from an iterator.
///
/// Returns an error if the iterator is empty or has more than one item.
fn get_single<T>(mut iterator: impl Iterator<Item = T>) -> Result<T, NotSingleError> {
    let Some(rv) = iterator.next() else {
        return Err(NotSingleError::None);
    };
    if iterator.next().is_some() {
        return Err(NotSingleError::Multiple);
    }
    Ok(rv)
}

/// An error returned from [`get_single`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum NotSingleError {
    /// The iterator had no items.
    #[error("the iterator had no items")]
    None,
    /// The iterator had more than one item.
    #[error("the iterator had more than one item")]
    Multiple,
}

/// An error returned when a method is expecting a single-leg conflux circuit,
/// but it is not single-leg.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum NotSingleLegError {
    /// Conflux set has no legs.
    #[error("the conflux set has no legs")]
    EmptyConfluxSet,
    /// Conflux set is multi-path.
    #[error("the conflux set is multi-path")]
    IsMultipath,
}

impl From<NotSingleLegError> for Bug {
    fn from(e: NotSingleLegError) -> Self {
        into_bad_api_usage!("not a single leg conflux set")(e)
    }
}

impl From<NotSingleLegError> for crate::Error {
    fn from(e: NotSingleLegError) -> Self {
        Self::from(Bug::from(e))
    }
}

impl From<NotSingleLegError> for ReactorError {
    fn from(e: NotSingleLegError) -> Self {
        Self::from(Bug::from(e))
    }
}

impl From<NotSingleError> for NotSingleLegError {
    fn from(e: NotSingleError) -> Self {
        match e {
            NotSingleError::None => Self::EmptyConfluxSet,
            NotSingleError::Multiple => Self::IsMultipath,
        }
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

        // TODO(cc): XOFF/XON

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
