//! Conflux-related functionality

use std::sync::Arc;

use futures::StreamExt;
use futures::{select_biased, stream::FuturesUnordered, FutureExt as _, Stream};
use slotmap_careful::SlotMap;

use tor_async_utils::SinkPrepareExt as _;
use tor_error::{bad_api_usage, internal, Bug};

use crate::util::err::ReactorError;

use super::{Circuit, CircuitAction, LegIdKey};

/// Type alias for the result of [`ConfluxSet::circuit_action`].
type CircuitActionResult = Result<Option<CircuitAction>, crate::Error>;

/// A set of linked conflux circuits.
pub(super) struct ConfluxSet {
    /// The circuits in this conflux set.
    legs: SlotMap<LegIdKey, Circuit>,
    /// The unique identifier of the primary leg
    pub(super) primary_id: LegIdKey,
}

impl ConfluxSet {
    /// Create a new conflux set, consisting of a single leg.
    pub(super) fn new(circuit_leg: Circuit) -> Self {
        let mut legs: SlotMap<LegIdKey, Circuit> = SlotMap::with_key();
        let primary_id = legs.insert(circuit_leg);

        Self { legs, primary_id }
    }

    /// Check if this conflux set consists of a single leg.
    ///
    /// Returns an error if there is more than one leg in the set,
    /// or if called before any circuit legs are available.
    fn single_leg_check(&self) -> Result<(), Bug> {
        if self.legs.is_empty() {
            Err(bad_api_usage!("tried to get circuit leg before creating it?!"))
        } else if self.legs.len() > 1 {
            Err(bad_api_usage!(
                "tried to get single circuit leg after conflux linking?!"
            ))
        } else {
            Ok(())
        }
    }

    /// Return the only leg of this conflux set.
    ///
    /// Returns an error if there is more than one leg in the set,
    /// or if called before any circuit legs are available.
    pub(super) fn single_leg_mut(&mut self) -> Result<&mut Circuit, Bug> {
        self.single_leg_check()?;

        let (_circ_id, circ) = self
            .legs
            .iter_mut()
            .next()
            .ok_or_else(|| internal!("slotmap is empty but its length is one?!"))?;

        Ok(circ)
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
            Err(bad_api_usage!("tried to get circuit leg before creating it?!"))
        } else {
            // TODO(conflux): implement primary leg selection
            let circ = self
                .legs
                .get_mut(self.primary_id)
                .ok_or_else(|| internal!("slotmap is empty?!"))?;

            Ok(circ)
        }
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

    /// Returns a stream of [`CircuitAction`] messages,
    /// obtained from processing the incoming/outgoing messages on all the circuits in this set.
    ///
    /// IMPORTANT: this stream locks the input mutexes of each leg,
    /// and will return an error if any of the locks are held by another task.
    /// Never create more than one [`ConfluxSet::circuit_action`] stream at a time!
    ///
    /// This is cancellation-safe.
    pub(super) fn circuit_action<'a>(
        &'a mut self,
    ) -> impl Stream<Item = Result<CircuitActionResult, crate::Error>> + 'a {
        self.legs
            .iter_mut()
            .map(|(leg_id, leg)| {
                let input = Arc::clone(&leg.input);
                let mut ready_streams = leg.ready_streams_iterator();
                // TODO: we don't really need prepare_send_from here
                // because the inner select_biased! is cancel-safe.
                // We should replace this with a simple sink readiness check
                leg.chan_sender.prepare_send_from(async move {
                    // If we can't immediately acquire this lock,
                    // something has gone terribly wrong: it likely means some other
                    // task created a poll_all_circs() future and is attempting
                    // to drive it to completion.
                    let mut input = input.try_lock().ok_or_else(|| {
                        internal!("tried to poll circuits while input lock is held?!")
                    })?;

                    // NOTE: the stream returned by this function is polled in the select_biased!
                    // from Reactor::run_once(), so each block from *this* select_biased! must be
                    // cancellation-safe
                    select_biased! {
                        // Check whether we've got an input message pending.
                        ret = input.next().fuse() => {
                            let Some(cell) = ret else {
                                return Ok(Some(CircuitAction::RemoveLeg(leg_id)));
                            };

                            Ok(Some(CircuitAction::HandleCell(cell)))
                        },
                        ret = ready_streams.next().fuse() => {
                            match ret {
                                Some(cmd) => {
                                    cmd.map(|cmd| Some(CircuitAction::Single(cmd)))
                                },
                                None => {
                                    // There are no ready streams (for example, they may all be
                                    // blocked due to congestion control), so there is nothing
                                    // to do.
                                    Ok(None)
                                }
                            }
                        }
                    }
                })
            })
            .collect::<FuturesUnordered<_>>()
            // Note: We don't actually use the returned SinkSendable,
            // and continue writing to the SometimesUboundedSink in the reactor :(
            .map(|res| res.map(|res| res.0))
    }
}
