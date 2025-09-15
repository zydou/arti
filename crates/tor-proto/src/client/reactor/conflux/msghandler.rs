//! Client-side conflux message handling.

use std::sync::Arc;
use std::sync::atomic::{self, AtomicU64};
use std::time::{Duration, SystemTime};

use tor_cell::relaycell::conflux::V1Nonce;
use tor_cell::relaycell::msg::{ConfluxLinked, ConfluxLinkedAck, ConfluxSwitch};
use tor_cell::relaycell::{AnyRelayMsgOuter, RelayCmd, UnparsedRelayMsg};
use tor_error::{Bug, internal, warn_report};
use tor_rtcompat::{DynTimeProvider, SleepProvider as _};

use crate::Error;
use crate::client::HopNum;
use crate::client::reactor::circuit::unsupported_client_cell;
use crate::congestion::params::CongestionWindowParams;

use crate::conflux::msghandler::{AbstractConfluxMsgHandler, ConfluxCmd, ConfluxStatus};

/// Client-side implementation of a conflux message handler.
pub(crate) struct ClientConfluxMsgHandler {
    /// The current state this leg is in.
    state: ConfluxState,
    /// The nonce associated with the circuits from this set.
    nonce: V1Nonce,
    /// The expected conflux join point.
    join_point: HopNum,
    //// The initial round-trip time measurement,
    /// measured during the conflux handshake.
    ///
    /// On the client side, this is the RTT between
    /// `RELAY_CONFLUX_LINK` and `RELAY_CONFLUX_LINKED`.
    init_rtt: Option<Duration>,
    /// The time when the handshake was initiated.
    link_sent: Option<SystemTime>,
    /// A handle to the time provider.
    runtime: DynTimeProvider,
    /// The sequence number of the last message received on this leg.
    ///
    /// This is a *relative* number.
    ///
    /// Incremented by the [`ConfluxMsgHandler`](super::ConfluxMsgHandler::action_for_msg)
    /// each time a cell that counts towards sequence numbers is received on this leg.
    last_seq_recv: u64,
    /// The sequence number of the last message sent on this leg.
    ///
    /// This is a *relative* number.
    ///
    /// Incremented by the [`ConfluxMsgHandler`](super::ConfluxMsgHandler::note_cell_sent)
    /// each time a cell that counts towards sequence numbers is sent on this leg.
    last_seq_sent: u64,
    /// The absolute sequence number of the last message delivered to a stream.
    ///
    /// This is shared by all the circuits in a conflux set,
    ///
    /// Incremented by the [`ConfluxMsgHandler`](super::ConfluxMsgHandler::inc_last_seq_delivered)
    /// upon delivering the cell to its corresponding stream.
    last_seq_delivered: Arc<AtomicU64>,
    /// Whether we have processed any SWITCH cells on the leg this handler is installed on.
    have_seen_switch: bool,
    /// The number of cells that count towards the conflux seqnos
    /// received on this leg since the last SWITCH.
    cells_since_switch: usize,
    /// The congestion window parameters.
    ///
    /// Used for SWITCH cell validation.
    cwnd_params: CongestionWindowParams,
}

/// The state of a client circuit from a conflux set.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ConfluxState {
    /// The circuit is not linked.
    Unlinked,
    /// The LINK cell was sent, awaiting response.
    AwaitingLink(V1Nonce),
    /// The circuit is linked.
    Linked,
}

impl AbstractConfluxMsgHandler for ClientConfluxMsgHandler {
    fn validate_source_hop(&self, msg: &UnparsedRelayMsg, hop: HopNum) -> crate::Result<()> {
        if hop != self.join_point {
            return Err(Error::CircProto(format!(
                "Received {} cell from unexpected hop {} on client conflux circuit",
                msg.cmd(),
                hop.display(),
            )));
        }

        Ok(())
    }

    fn handle_msg(
        &mut self,
        msg: UnparsedRelayMsg,
        hop: HopNum,
    ) -> crate::Result<Option<ConfluxCmd>> {
        match msg.cmd() {
            RelayCmd::CONFLUX_LINK => self.handle_conflux_link(msg, hop),
            RelayCmd::CONFLUX_LINKED => self.handle_conflux_linked(msg, hop),
            RelayCmd::CONFLUX_LINKED_ACK => self.handle_conflux_linked_ack(msg, hop),
            RelayCmd::CONFLUX_SWITCH => self.handle_conflux_switch(msg, hop),
            _ => Err(internal!("received non-conflux cell in conflux handler?!").into()),
        }
    }

    fn status(&self) -> ConfluxStatus {
        match self.state {
            ConfluxState::Unlinked => ConfluxStatus::Unlinked,
            ConfluxState::AwaitingLink(_) => ConfluxStatus::Pending,
            ConfluxState::Linked => ConfluxStatus::Linked,
        }
    }

    fn note_link_sent(&mut self, ts: SystemTime) -> Result<(), Bug> {
        match self.state {
            ConfluxState::Unlinked => {
                self.state = ConfluxState::AwaitingLink(self.nonce);
            }
            ConfluxState::AwaitingLink(_) | ConfluxState::Linked => {
                return Err(internal!("Sent duplicate LINK cell?!"));
            }
        }

        self.link_sent = Some(ts);
        Ok(())
    }

    /// Get the wallclock time when the handshake on this circuit is supposed to time out.
    ///
    /// Returns `None` if the handshake is not currently in progress.
    fn handshake_timeout(&self) -> Option<SystemTime> {
        /// The maximum amount of time to wait for the LINKED cell to arrive.
        //
        // TODO(conflux-tuning): we should pick a less arbitrary timeout
        //
        // "This timeout MUST be no larger than the normal SOCKS/stream timeout in
        // use for RELAY_BEGIN, but MAY be the Circuit Build Timeout value, instead.
        // (The C-Tor implementation currently uses Circuit Build Timeout)".
        const LINK_TIMEOUT: Duration = Duration::from_secs(60);

        if matches!(self.state, ConfluxState::AwaitingLink(_)) {
            debug_assert!(
                self.link_sent.is_some(),
                "awaiting LINKED, but LINK not sent?!"
            );
            self.link_sent.map(|link_sent| link_sent + LINK_TIMEOUT)
        } else {
            None
        }
    }

    /// Returns the initial RTT measured by this handler.
    fn init_rtt(&self) -> Option<Duration> {
        self.init_rtt
    }

    fn last_seq_recv(&self) -> u64 {
        self.last_seq_recv
    }

    fn last_seq_sent(&self) -> u64 {
        self.last_seq_sent
    }

    fn set_last_seq_sent(&mut self, n: u64) {
        self.last_seq_sent = n;
    }

    fn inc_last_seq_recv(&mut self) {
        self.last_seq_recv += 1;
        self.cells_since_switch += 1;
    }

    fn inc_last_seq_sent(&mut self) {
        self.last_seq_sent += 1;
    }
}

impl ClientConfluxMsgHandler {
    /// Create a new client conflux message handler.
    pub(crate) fn new(
        join_point: HopNum,
        nonce: V1Nonce,
        last_seq_delivered: Arc<AtomicU64>,
        cwnd_params: CongestionWindowParams,
        runtime: DynTimeProvider,
    ) -> Self {
        Self {
            state: ConfluxState::Unlinked,
            nonce,
            last_seq_delivered,
            join_point,
            link_sent: None,
            runtime,
            init_rtt: None,
            last_seq_recv: 0,
            last_seq_sent: 0,
            have_seen_switch: false,
            cells_since_switch: 0,
            cwnd_params,
        }
    }

    /// Handle a conflux LINK request coming from the specified hop.
    #[allow(clippy::needless_pass_by_value)]
    fn handle_conflux_link(
        &mut self,
        msg: UnparsedRelayMsg,
        hop: HopNum,
    ) -> crate::Result<Option<ConfluxCmd>> {
        unsupported_client_cell!(msg, hop)
    }

    /// Handle a conflux LINKED response coming from the specified `hop`.
    ///
    /// The caller must validate the `hop` the cell originated from.
    ///
    /// To prevent [DROPMARK] attacks, this returns a protocol error
    /// if any of the following conditions are not met:
    ///
    ///   * this is an unlinked circuit that sent a LINK command
    ///   * that the nonce matches the nonce used in the LINK command
    ///
    /// [DROPMARK]: https://www.petsymposium.org/2018/files/papers/issue2/popets-2018-0011.pdf
    fn handle_conflux_linked(
        &mut self,
        msg: UnparsedRelayMsg,
        hop: HopNum,
    ) -> crate::Result<Option<ConfluxCmd>> {
        // See [SIDE_CHANNELS] for rules for when to reject unexpected handshake cells.

        let Some(link_sent) = self.link_sent else {
            return Err(Error::CircProto(
                "Received CONFLUX_LINKED cell before sending CONFLUX_LINK?!".into(),
            ));
        };

        let expected_nonce = match self.state {
            ConfluxState::Unlinked => {
                return Err(Error::CircProto(
                    "Received CONFLUX_LINKED cell before sending CONFLUX_LINK?!".into(),
                ));
            }
            ConfluxState::AwaitingLink(expected_nonce) => expected_nonce,
            ConfluxState::Linked => {
                return Err(Error::CircProto(
                    "Received CONFLUX_LINKED on already linked circuit".into(),
                ));
            }
        };

        let linked = msg
            .decode::<ConfluxLinked>()
            .map_err(|e| Error::from_bytes_err(e, "linked message"))?
            .into_msg();

        let linked_nonce = *linked.payload().nonce();

        if expected_nonce == linked_nonce {
            self.state = ConfluxState::Linked;
        } else {
            return Err(Error::CircProto(
                "Received CONFLUX_LINKED cell with mismatched nonce".into(),
            ));
        }

        let now = self.runtime.wallclock();
        // Measure the initial RTT between the time we sent the LINK and received the LINKED
        self.init_rtt = Some(now.duration_since(link_sent).unwrap_or_else(|e| {
            warn_report!(e, "failed to calculate initial RTT for conflux circuit",);

            // TODO(conflux): this is terrible, because SystemTime is not monotonic.
            // Can we somehow use Instant instead of SystemTime?
            // (DynTimeProvider doesn't have a way of sleeping until an Instant,
            // it only has sleep_until_wallclock)
            Duration::from_secs(u64::MAX)
        }));

        let linked_ack = ConfluxLinkedAck::default();
        let cell = AnyRelayMsgOuter::new(None, linked_ack.into());

        Ok(Some(ConfluxCmd::HandshakeComplete {
            hop,
            early: false,
            cell,
        }))
    }

    /// Handle a conflux LINKED acknowledgment coming from the specified hop.
    #[allow(clippy::needless_pass_by_value)]
    fn handle_conflux_linked_ack(
        &mut self,
        msg: UnparsedRelayMsg,
        hop: HopNum,
    ) -> crate::Result<Option<ConfluxCmd>> {
        unsupported_client_cell!(msg, hop)
    }

    /// Handle a conflux SWITCH coming from the specified hop.
    fn handle_conflux_switch(
        &mut self,
        msg: UnparsedRelayMsg,
        _hop: HopNum,
    ) -> crate::Result<Option<ConfluxCmd>> {
        if self.state != ConfluxState::Linked {
            return Err(Error::CircProto(
                "Received CONFLUX_SWITCH on unlinked circuit?!".into(),
            ));
        }

        if self.have_seen_switch && self.cells_since_switch == 0 {
            return Err(Error::CircProto(
                "Received consecutive SWITCH cells on circuit?!".into(),
            ));
        }

        let switch = msg
            .decode::<ConfluxSwitch>()
            .map_err(|e| Error::from_bytes_err(e, "switch message"))?
            .into_msg();

        let rel_seqno = switch.seqno();

        self.validate_switch_seqno(rel_seqno)?;

        // Update the absolute sequence number on this leg by the delta.
        // Since this cell is not multiplexed, we do not count it towards
        // absolute sequence numbers. We only increment the sequence
        // numbers for multiplexed cells. Hence there is no +1 here.
        self.last_seq_recv += u64::from(rel_seqno);
        // Note that we've received at least one SWITCH on this leg.
        self.have_seen_switch = true;
        // Reset our counter for the number of relevant (DATA, etc.) cells
        // received since the last SWITCH
        self.cells_since_switch = 0;

        Ok(None)
    }

    /// Validate the relative sequence number specified in a switch command.
    ///
    /// Returns an error if
    ///
    ///   * `rel_seqno` is 0 (i.e. the SWITCH cell does not actually increment
    ///     the `last_seq_recv` seqno on this leg)
    ///   * the tunnel has not yet received any data and `rel_seqno` is greater
    ///     than the initial congestion window,
    fn validate_switch_seqno(&self, rel_seqno: u32) -> crate::Result<()> {
        // The sequence number from the switch must be non-zero.
        if rel_seqno == 0 {
            return Err(Error::CircProto(
                "Received SWITCH cell with seqno = 0".into(),
            ));
        }

        let no_data = self.last_seq_delivered.load(atomic::Ordering::Acquire) == 0;
        let is_first_switch = !self.have_seen_switch;

        // If we haven't received any DATA cells on this tunnel,
        // the seqno delta from the first SWITCH can't possibly
        // exceed the initial congestion window.
        if no_data && is_first_switch && rel_seqno > self.cwnd_params.cwnd_init() {
            return Err(Error::CircProto(
                "SWITCH cell seqno exceeds initial cwnd".into(),
            ));
        }

        Ok(())
    }
}
