//! A conflux-aware message handler.

use std::cmp::Ordering;
use std::sync::Arc;
use std::sync::atomic::{self, AtomicU64};
use std::time::{Duration, SystemTime};

use tor_cell::relaycell::{AnyRelayMsgOuter, RelayCmd, StreamId, UnparsedRelayMsg};
use tor_error::{Bug, internal};

use crate::Error;
use crate::crypto::cell::HopNum;

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
    /// TODO: can/should we avoid dynamic dispatch here?
    handler: Box<dyn AbstractConfluxMsgHandler + Send + Sync>,
    /// The absolute sequence number of the last message delivered to a stream.
    ///
    /// This is shared by all the circuits in a conflux set.
    last_seq_delivered: Arc<AtomicU64>,
}

impl ConfluxMsgHandler {
    /// Create a new message handler using the specified [`AbstractConfluxMsgHandler`].
    ///
    /// Clients and relays both use this function.
    ///
    // TODO(relay): exits will need to implement their own AbstractConfluxMsgHandler
    pub(crate) fn new(
        handler: Box<dyn AbstractConfluxMsgHandler + Send + Sync>,
        last_seq_delivered: Arc<AtomicU64>,
    ) -> Self {
        Self {
            handler,
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
    ) -> Option<ConfluxCmd> {
        let res = (|| {
            // Ensure the conflux cell came from the expected hop
            // (see 4.2.1. Cell Injection Side Channel Mitigations in prop329).
            let () = self.validate_source_hop(&msg, hop)?;
            self.handler.handle_msg(msg, hop)
        })();

        // Returning an error here would cause the reactor to shut down,
        // so we return a ConfluxCmd::RemoveLeg command instead.
        //
        // After removing the leg, the reactor will decide whether it needs
        // to shut down or not.
        match res {
            Ok(cmd) => cmd,
            Err(e) => {
                // Tell the reactor to remove this leg from the conflux set,
                // and to notify the handshake initiator of the error
                Some(ConfluxCmd::RemoveLeg(RemoveLegReason::ConfluxHandshakeErr(
                    e,
                )))
            }
        }
    }

    /// Client-only: note that the LINK cell was sent.
    ///
    /// Used for the initial RTT measurement.
    pub(crate) fn note_link_sent(&mut self, ts: SystemTime) -> Result<(), Bug> {
        self.handler.note_link_sent(ts)
    }

    /// Get the wallclock time when the handshake on this circuit is supposed to time out.
    ///
    /// Returns `None` if the handshake is not currently in progress.
    pub(crate) fn handshake_timeout(&self) -> Option<SystemTime> {
        self.handler.handshake_timeout()
    }

    /// Returns the conflux status of this handler.
    pub(crate) fn status(&self) -> ConfluxStatus {
        self.handler.status()
    }

    /// Check our sequence numbers to see if the current msg is in order.
    ///
    /// Returns an internal error if the relative seqno is lower than the absolute seqno.
    fn is_msg_in_order(&self) -> Result<bool, Bug> {
        let last_seq_delivered = self.last_seq_delivered.load(atomic::Ordering::Acquire);
        match self.handler.last_seq_recv().cmp(&(last_seq_delivered + 1)) {
            Ordering::Less => {
                // Our internal accounting is busted!
                Err(internal!(
                    "Got a conflux cell with a sequence number less than the last delivered"
                ))
            }
            Ordering::Equal => Ok(true),
            Ordering::Greater => Ok(false),
        }
    }

    /// Return a [`OooRelayMsg`] for the reactor to buffer.
    fn prepare_ooo_entry(
        &self,
        hopnum: HopNum,
        cell_counts_towards_windows: bool,
        streamid: StreamId,
        msg: UnparsedRelayMsg,
    ) -> OooRelayMsg {
        OooRelayMsg {
            seqno: self.handler.last_seq_recv(),
            hopnum,
            cell_counts_towards_windows,
            streamid,
            msg,
        }
    }

    /// Check the sequence number of the specified `msg`,
    /// and decide whether it should be delivered or buffered.
    #[cfg(feature = "conflux")]
    pub(crate) fn action_for_msg(
        &mut self,
        hopnum: HopNum,
        cell_counts_towards_windows: bool,
        streamid: StreamId,
        msg: UnparsedRelayMsg,
    ) -> Result<ConfluxAction, Bug> {
        if !super::cmd_counts_towards_seqno(msg.cmd()) {
            return Ok(ConfluxAction::Deliver(msg));
        }

        // Increment the relative seqno on this leg.
        self.handler.inc_last_seq_recv();

        let action = if self.is_msg_in_order()? {
            ConfluxAction::Deliver(msg)
        } else {
            ConfluxAction::Enqueue(self.prepare_ooo_entry(
                hopnum,
                cell_counts_towards_windows,
                streamid,
                msg,
            ))
        };

        Ok(action)
    }

    /// Increment the absolute "delivered" seqno for this conflux set
    /// if the specified message counts towards sequence numbers.
    pub(crate) fn inc_last_seq_delivered(&self, msg: &UnparsedRelayMsg) {
        if super::cmd_counts_towards_seqno(msg.cmd()) {
            self.last_seq_delivered
                .fetch_add(1, atomic::Ordering::AcqRel);
        }
    }

    /// Returns the initial RTT measured by this handler.
    pub(crate) fn init_rtt(&self) -> Option<Duration> {
        self.handler.init_rtt()
    }

    /// Return the sequence number of the last message sent on this leg.
    pub(crate) fn last_seq_sent(&self) -> u64 {
        self.handler.last_seq_sent()
    }

    /// Set the sequence number of the last message sent on this leg.
    pub(crate) fn set_last_seq_sent(&mut self, n: u64) {
        self.handler.set_last_seq_sent(n);
    }

    /// Return the sequence number of the last message received on this leg.
    pub(crate) fn last_seq_recv(&self) -> u64 {
        self.handler.last_seq_recv()
    }

    /// Note that a cell has been sent.
    ///
    /// Updates the internal sequence numbers.
    pub(crate) fn note_cell_sent(&mut self, cmd: RelayCmd) {
        if super::cmd_counts_towards_seqno(cmd) {
            self.handler.inc_last_seq_sent();
        }
    }
}

/// An action to take after processing a potentially out of order message.
#[derive(Debug)]
#[cfg(feature = "conflux")]
pub(crate) enum ConfluxAction {
    /// Deliver the message to its corresponding stream
    Deliver(UnparsedRelayMsg),
    /// Enqueue the specified entry in the out-of-order queue.
    Enqueue(OooRelayMsg),
}

/// An object that can process conflux relay messages
/// and manage the conflux state of a circuit.
///
/// This is indirectly used by the circuit reactor (via `ConfluxSet`)
/// for conflux handling.
pub(crate) trait AbstractConfluxMsgHandler {
    /// Validate the specified source hop of a conflux cell.
    fn validate_source_hop(&self, msg: &UnparsedRelayMsg, hop: HopNum) -> crate::Result<()>;

    /// Handle the specified conflux `msg`.
    fn handle_msg(
        &mut self,
        msg: UnparsedRelayMsg,
        hop: HopNum,
    ) -> crate::Result<Option<ConfluxCmd>>;

    /// Returns the conflux status of this handler.
    fn status(&self) -> ConfluxStatus;

    /// Client-only: note that the LINK cell was sent.
    fn note_link_sent(&mut self, ts: SystemTime) -> Result<(), Bug>;

    /// Get the wallclock time when the handshake on this circuit is supposed to time out.
    ///
    /// Returns `None` if the handshake is not currently in progress.
    fn handshake_timeout(&self) -> Option<SystemTime>;

    /// Returns the initial RTT measured by this handler.
    fn init_rtt(&self) -> Option<Duration>;

    /// Return the sequence number of the last message received on this leg.
    fn last_seq_recv(&self) -> u64;

    /// Return the sequence number of the last message sent on this leg.
    fn last_seq_sent(&self) -> u64;

    /// Set the sequence number of the last message sent on this leg.
    fn set_last_seq_sent(&mut self, n: u64);

    /// Increment the sequence number of the last message received on this leg.
    fn inc_last_seq_recv(&mut self);

    /// Increment the sequence number of the last message sent on this leg.
    fn inc_last_seq_sent(&mut self);
}

/// An out-of-order message.
#[derive(Debug)]
pub(crate) struct OooRelayMsg {
    /// The sequence number of the message.
    pub(crate) seqno: u64,
    /// The hop this message originated from.
    pub(crate) hopnum: HopNum,
    /// Whether the cell this message originated from counts towards
    /// the stream-level SENDME window.
    ///
    /// See "SENDME window accounting" in prop340.
    pub(crate) cell_counts_towards_windows: bool,
    /// The stream ID of this message.
    pub(crate) streamid: StreamId,
    /// The actual message.
    pub(crate) msg: UnparsedRelayMsg,
}

impl Ord for OooRelayMsg {
    fn cmp(&self, other: &Self) -> Ordering {
        self.seqno.cmp(&other.seqno).reverse()
    }
}

impl PartialOrd for OooRelayMsg {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for OooRelayMsg {
    fn eq(&self, other: &Self) -> bool {
        self.seqno == other.seqno
    }
}

impl Eq for OooRelayMsg {}

/// The outcome of [`AbstractConfluxMsgHandler::handle_msg`].
#[derive(Debug)]
pub(crate) enum ConfluxCmd {
    /// Remove this circuit from the conflux set.
    ///
    /// Returned by `ConfluxMsgHandler::handle_conflux_msg` for invalid messages
    /// (originating from wrong hop), and for messages that are rejected
    /// by its inner `AbstractMsgHandler`.
    RemoveLeg(RemoveLegReason),

    /// This circuit has completed the conflux handshake,
    /// and wants to send the specified cell.
    ///
    /// Returned by an `AbstractMsgHandler` to signal to the reactor that
    /// the conflux handshake is complete.
    HandshakeComplete {
        /// The hop number.
        hop: HopNum,
        /// Whether to use a RELAY_EARLY cell.
        early: bool,
        /// The cell to send.
        cell: AnyRelayMsgOuter,
    },
}

/// The reason for removing a circuit leg from the conflux set.
#[derive(Debug, derive_more::Display)]
pub(crate) enum RemoveLegReason {
    /// The conflux handshake timed out.
    ///
    /// On the client-side, this means we didn't receive
    /// the CONFLUX_LINKED response in time.
    #[display("conflux handshake timed out")]
    ConfluxHandshakeTimeout,
    /// An error occurred during conflux handshake.
    #[display("{}", _0)]
    ConfluxHandshakeErr(Error),
    /// The channel was closed.
    #[display("channel closed")]
    ChannelClosed,
}

/// The conflux status of a conflux circuit.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConfluxStatus {
    /// Circuit has not begun the conflux handshake yet.
    Unlinked,
    /// Conflux handshake is in progress.
    Pending,
    /// A linked conflux circuit.
    Linked,
}
