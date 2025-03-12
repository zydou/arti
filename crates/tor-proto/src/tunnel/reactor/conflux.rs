//! Conflux-related functionality

#[cfg(feature = "conflux")]
mod msghandler;

use std::future::Future;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use futures::StreamExt;
use futures::{select_biased, stream::FuturesUnordered, FutureExt as _};
use slotmap_careful::SlotMap;

use tor_async_utils::SinkPrepareExt as _;
use tor_basic_utils::flatten;
use tor_error::{bad_api_usage, internal, into_bad_api_usage, Bug};

use crate::circuit::path::HopDetail;
use crate::crypto::cell::HopNum;
use crate::util::err::ReactorError;

use super::{Circuit, CircuitAction, LegId, LegIdKey, RemoveLegReason};

#[cfg(feature = "conflux")]
use tor_cell::relaycell::conflux::{V1DesiredUx, V1Nonce};

#[cfg(feature = "conflux")]
pub(crate) use msghandler::ConfluxMsgHandler;

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
    /// When it is converted to a multipath set, the join point is initialized
    /// to the last hop in the tunnel (which should be the same for all the circuits in the set).
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
