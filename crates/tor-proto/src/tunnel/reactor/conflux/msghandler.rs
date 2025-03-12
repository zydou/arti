//! A conflux-aware message handler.

mod client;

use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tor_cell::relaycell::conflux::V1Nonce;
use tor_cell::relaycell::UnparsedRelayMsg;
use tor_error::Bug;

use crate::crypto::cell::HopNum;
use crate::tunnel::reactor::circuit::ConfluxStatus;
use crate::tunnel::reactor::CircuitCmd;

use client::ClientConfluxMsgHandler;

/// Cell handler for conflux cells.
///
/// One per Circuit.
//
// Note: this is not a `MetaCellHandler` because we need a slightly different API here.
// Perhaps we should redesign `MetaCellHandler` API to make it work for this too?
pub(crate) struct ConfluxMsgHandler {
    /// Inner message handler
    ///
    /// Customizes the cell handling logic,
    /// because clients and exits behave differently.
    ///
    /// TODO(conflux): can/should we avoid dynamic dispatch here?
    handler: Box<dyn AbstractConfluxMsgHandler + Send + Sync>,
    /// The absolute sequence number of the last message delivered to a stream.
    ///
    /// This is shared by all the circuits in a conflux set.
    last_seq_delivered: Arc<AtomicU32>,
}

impl ConfluxMsgHandler {
    /// Create a new message handler for client circuits.
    pub(super) fn new_client(
        hop: HopNum,
        nonce: V1Nonce,
        last_seq_delivered: Arc<AtomicU32>,
    ) -> Self {
        Self {
            handler: Box::new(ClientConfluxMsgHandler::new(hop, nonce)),
            last_seq_delivered,
        }
    }

    /// Validate the specified source hop of a conflux cell.
    ///
    /// The client impl of this function returns an error if the hop is not the last hop.
    ///
    /// The exit impl of this function returns an error if the source hop is not the last hop,
    /// or if there are further hops after the source hop.
    fn validate_source_hop(&self, msg: &UnparsedRelayMsg, hop: HopNum) -> crate::Result<()> {
        self.handler.validate_source_hop(msg, hop)
    }

    /// Handle the specified conflux `msg`.
    pub(crate) fn handle_conflux_msg(
        &mut self,
        msg: UnparsedRelayMsg,
        hop: HopNum,
    ) -> crate::Result<Option<CircuitCmd>> {
        // Ensure the conflux cell came from the expected hop
        // (see 4.2.1. Cell Injection Side Channel Mitigations in prop329).
        let () = self.validate_source_hop(&msg, hop)?;
        self.handler.handle_msg(msg, hop)
    }

    /// Client-only: note that the LINK cell was sent.
    ///
    /// Used for the initial RTT measurement.
    pub(crate) fn note_link_sent(&mut self, ts: Instant) -> Result<(), Bug> {
        self.handler.note_link_sent(ts)
    }

    /// Returns the conflux status of this handler.
    pub(crate) fn status(&self) -> ConfluxStatus {
        self.handler.status()
    }
}

/// An object that can process conflux relay messages
/// and manage the conflux state of a circuit.
///
/// This is indirectly used by the circuit reactor (via `ConfluxSet`)
/// for conflux handling.
trait AbstractConfluxMsgHandler {
    /// Validate the specified source hop of a conflux cell.
    fn validate_source_hop(&self, msg: &UnparsedRelayMsg, hop: HopNum) -> crate::Result<()>;

    /// Handle the specified conflux `msg`.
    fn handle_msg(
        &mut self,
        msg: UnparsedRelayMsg,
        hop: HopNum,
    ) -> crate::Result<Option<CircuitCmd>>;

    /// Returns the conflux status of this handler.
    fn status(&self) -> ConfluxStatus;

    /// Client-only: note that the LINK cell was sent.
    fn note_link_sent(&mut self, ts: Instant) -> Result<(), Bug>;

    /// Returns the initial RTT measured by this handler.
    fn init_rtt(&self) -> Option<Duration>;

    /// Return the sequence number of the last message received on this leg.
    fn last_seq_recv(&self) -> u32;

    /// Return the sequence number of the last message sent on this leg.
    fn last_seq_sent(&self) -> u32;

    /// Increment the sequence number of the last message received on this leg.
    fn inc_last_seq_recv(&mut self);

    /// Increment the sequence number of the last message sent on this leg.
    fn inc_last_seq_sent(&mut self);
}
