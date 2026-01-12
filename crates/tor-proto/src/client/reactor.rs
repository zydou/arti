//! Code to handle incoming cells on a circuit.
//!
//! ## On message validation
//!
//! There are three steps for validating an incoming message on a stream:
//!
//! 1. Is the message contextually appropriate? (e.g., no more than one
//!    `CONNECTED` message per stream.) This is handled by calling
//!    [`CmdChecker::check_msg`](crate::stream::cmdcheck::CmdChecker::check_msg).
//! 2. Does the message comply with flow-control rules? (e.g., no more SENDMEs
//!    than we've sent data for.) This is handled within the reactor by the
//!    `StreamFlowCtrl`. For half-closed streams which don't send stream
//!    SENDMEs, an additional receive-window check is performed in the
//!    `halfstream` module.
//! 3. Does the message have an acceptable command type, and is the message
//!    well-formed? For open streams, the streams themselves handle this check.
//!    For half-closed streams, the reactor handles it by calling
//!    `consume_checked_msg()`.

pub(crate) mod circuit;
mod conflux;
mod control;
pub(super) mod syncview;

use crate::circuit::circhop::SendRelayCell;
use crate::circuit::{CircuitRxReceiver, UniqId};
use crate::client::circuit::padding::{PaddingController, PaddingEvent, PaddingEventStream};
use crate::client::circuit::{ClientCircChanMsg, TimeoutEstimator};
use crate::client::{HopLocation, TargetHop};
use crate::crypto::cell::HopNum;
use crate::crypto::handshake::ntor_v3::NtorV3PublicKey;
use crate::memquota::CircuitAccount;
use crate::stream::CloseStreamBehavior;
use crate::streammap;
use crate::tunnel::{TunnelId, TunnelScopedCircId};
use crate::util::err::ReactorError;
use crate::util::skew::ClockSkew;
use crate::{Error, Result};
use circuit::Circuit;
use conflux::ConfluxSet;
use control::ControlHandler;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use tor_cell::relaycell::flow_ctrl::XonKbpsEwma;
use tor_cell::relaycell::msg::Sendme;
use tor_cell::relaycell::{AnyRelayMsgOuter, RelayCellFormat, StreamId, UnparsedRelayMsg};
use tor_error::{Bug, bad_api_usage, debug_report, internal, into_bad_api_usage};
use tor_rtcompat::{DynTimeProvider, SleepProvider};

use cfg_if::cfg_if;
use futures::StreamExt;
use futures::channel::mpsc;
use futures::{FutureExt as _, select_biased};
use oneshot_fused_workaround as oneshot;

use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Duration;

use crate::channel::Channel;
use crate::conflux::msghandler::RemoveLegReason;
use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
use circuit::CircuitCmd;
use derive_more::From;
use smallvec::smallvec;
use tor_cell::chancell::CircId;
use tor_llcrypto::pk;
use tracing::{debug, info, instrument, trace, warn};

use super::circuit::{MutableState, TunnelMutableState};

#[cfg(feature = "hs-service")]
use crate::stream::incoming::IncomingStreamRequestHandler;

#[cfg(feature = "conflux")]
use {
    crate::conflux::msghandler::{ConfluxCmd, OooRelayMsg},
    crate::util::err::ConfluxHandshakeError,
};

pub(super) use control::{CtrlCmd, CtrlMsg, FlowCtrlMsg};

/// The type of a oneshot channel used to inform reactor of the result of an operation.
pub(super) type ReactorResultChannel<T> = oneshot::Sender<Result<T>>;

/// Contains a list of conflux handshake results.
#[cfg(feature = "conflux")]
pub(super) type ConfluxHandshakeResult = Vec<StdResult<(), ConfluxHandshakeError>>;

/// The type of oneshot channel used to inform reactor users of the outcome
/// of a client-side conflux handshake.
///
/// Contains a list of handshake results, one for each circuit that we were asked
/// to link in the tunnel.
#[cfg(feature = "conflux")]
pub(super) type ConfluxLinkResultChannel = ReactorResultChannel<ConfluxHandshakeResult>;

/// A handshake type, to be used when creating circuit hops.
#[derive(Clone, Debug)]
pub(crate) enum CircuitHandshake {
    /// Use the CREATE_FAST handshake.
    CreateFast,
    /// Use the ntor handshake.
    Ntor {
        /// The public key of the relay.
        public_key: NtorPublicKey,
        /// The Ed25519 identity of the relay, which is verified against the
        /// identity held in the circuit's channel.
        ed_identity: pk::ed25519::Ed25519Identity,
    },
    /// Use the ntor-v3 handshake.
    NtorV3 {
        /// The public key of the relay.
        public_key: NtorV3PublicKey,
    },
}

// TODO: the RunOnceCmd/RunOnceCmdInner/CircuitCmd/CircuitEvent enum
// proliferation is a bit bothersome, but unavoidable with the current design.
//
// We should consider getting rid of some of these enums (if possible),
// and coming up with more intuitive names.

/// One or more [`RunOnceCmdInner`] to run inside [`Reactor::run_once`].
#[derive(From, Debug)]
#[allow(clippy::large_enum_variant)] // TODO #2003: resolve this
enum RunOnceCmd {
    /// Run a single `RunOnceCmdInner` command.
    Single(RunOnceCmdInner),
    /// Run multiple `RunOnceCmdInner` commands.
    //
    // Note: this whole enum *could* be replaced with Vec<RunOnceCmdInner>,
    // but most of the time we're only going to have *one* RunOnceCmdInner
    // to run per run_once() loop. The enum enables us avoid the extra heap
    // allocation for the `RunOnceCmd::Single` case.
    Multiple(Vec<RunOnceCmdInner>),
}

/// Instructions for running something in the reactor loop.
///
/// Run at the end of [`Reactor::run_once`].
//
// TODO: many of the variants of this enum have an identical CtrlMsg counterpart.
// We should consider making each variant a tuple variant and deduplicating the fields.
#[derive(educe::Educe)]
#[educe(Debug)]
enum RunOnceCmdInner {
    /// Send a RELAY cell.
    Send {
        /// The leg the cell should be sent on.
        leg: UniqId,
        /// The cell to send.
        cell: SendRelayCell,
        /// A channel for sending completion notifications.
        done: Option<ReactorResultChannel<()>>,
    },
    /// Send a given control message on this circuit, and install a control-message handler to
    /// receive responses.
    #[cfg(feature = "send-control-msg")]
    SendMsgAndInstallHandler {
        /// The message to send, if any
        msg: Option<AnyRelayMsgOuter>,
        /// A message handler to install.
        ///
        /// If this is `None`, there must already be a message handler installed
        #[educe(Debug(ignore))]
        handler: Option<Box<dyn MetaCellHandler + Send + 'static>>,
        /// A sender that we use to tell the caller that the message was sent
        /// and the handler installed.
        done: oneshot::Sender<Result<()>>,
    },
    /// Handle a SENDME message.
    HandleSendMe {
        /// The leg the SENDME was received on.
        leg: UniqId,
        /// The hop number.
        hop: HopNum,
        /// The SENDME message to handle.
        sendme: Sendme,
    },
    /// Begin a stream with the provided hop in this circuit.
    ///
    /// Uses the provided stream ID, and sends the provided message to that hop.
    BeginStream {
        /// The cell to send.
        cell: Result<(SendRelayCell, StreamId)>,
        /// The location of the hop on the tunnel. We don't use this (and `Circuit`s shouldn't need
        /// to worry about legs anyways), but need it so that we can pass it back in `done` to the
        /// caller.
        hop: HopLocation,
        /// The circuit leg to begin the stream on.
        leg: UniqId,
        /// Oneshot channel to notify on completion, with the allocated stream ID.
        done: ReactorResultChannel<(StreamId, HopLocation, RelayCellFormat)>,
    },
    /// Consider sending an XON message with the given `rate`.
    MaybeSendXon {
        /// The drain rate to advertise in the XON message.
        rate: XonKbpsEwma,
        /// The ID of the stream to send the message on.
        stream_id: StreamId,
        /// The location of the hop on the tunnel.
        hop: HopLocation,
    },
    /// Close the specified stream.
    CloseStream {
        /// The hop number.
        hop: HopLocation,
        /// The ID of the stream to close.
        sid: StreamId,
        /// The stream-closing behavior.
        behav: CloseStreamBehavior,
        /// The reason for closing the stream.
        reason: streammap::TerminateReason,
        /// A channel for sending completion notifications.
        done: Option<ReactorResultChannel<()>>,
    },
    /// Get the clock skew claimed by the first hop of the circuit.
    FirstHopClockSkew {
        /// Oneshot channel to return the clock skew.
        answer: oneshot::Sender<StdResult<ClockSkew, Bug>>,
    },
    /// Remove a circuit leg from the conflux set.
    RemoveLeg {
        /// The circuit leg to remove.
        leg: UniqId,
        /// The reason for removal.
        ///
        /// This is only used for conflux circuits that get removed
        /// before the conflux handshake is complete.
        ///
        /// The [`RemoveLegReason`] is mapped by the reactor to a
        /// [`ConfluxHandshakeError`] that is sent to the initiator of the
        /// handshake to indicate the reason the handshake failed.
        reason: RemoveLegReason,
    },
    /// A circuit has completed the conflux handshake,
    /// and wants to send the specified cell.
    ///
    /// This is similar to [`RunOnceCmdInner::Send`],
    /// but needs to remain a separate variant,
    /// because in addition to instructing the reactor to send a cell,
    /// it also notifies it that the conflux handshake is complete on the specified `leg`.
    /// This enables the reactor to save the handshake result (`Ok(())`),
    /// and, if there are no other legs still in the handshake phase,
    /// send the result to the handshake initiator.
    #[cfg(feature = "conflux")]
    ConfluxHandshakeComplete {
        /// The circuit leg that has completed the handshake,
        /// This is the leg the cell should be sent on.
        leg: UniqId,
        /// The cell to send.
        cell: SendRelayCell,
    },
    /// Send a LINK cell on each of the unlinked circuit legs in the conflux set of this reactor.
    #[cfg(feature = "conflux")]
    Link {
        /// The circuits to link into the tunnel
        #[educe(Debug(ignore))]
        circuits: Vec<Circuit>,
        /// Oneshot channel for notifying of conflux handshake completion.
        answer: ConfluxLinkResultChannel,
    },
    /// Enqueue an out-of-order cell in ooo_msg.
    #[cfg(feature = "conflux")]
    Enqueue {
        /// The leg the entry originated from.
        leg: UniqId,
        /// The out-of-order message.
        msg: OooRelayMsg,
    },
    /// Take a padding-related event on a circuit leg.
    #[cfg(feature = "circ-padding")]
    PaddingAction {
        /// The leg to event on.
        leg: UniqId,
        /// The event to take.
        padding_event: PaddingEvent,
    },
    /// Perform a clean shutdown on this circuit.
    CleanShutdown,
}

impl RunOnceCmdInner {
    /// Create a [`RunOnceCmdInner`] out of a [`CircuitCmd`] and [`UniqId`].
    fn from_circuit_cmd(leg: UniqId, cmd: CircuitCmd) -> Self {
        match cmd {
            CircuitCmd::Send(cell) => Self::Send {
                leg,
                cell,
                done: None,
            },
            CircuitCmd::HandleSendMe { hop, sendme } => Self::HandleSendMe { leg, hop, sendme },
            CircuitCmd::CloseStream {
                hop,
                sid,
                behav,
                reason,
            } => Self::CloseStream {
                hop: HopLocation::Hop((leg, hop)),
                sid,
                behav,
                reason,
                done: None,
            },
            #[cfg(feature = "conflux")]
            CircuitCmd::Conflux(ConfluxCmd::RemoveLeg(reason)) => Self::RemoveLeg { leg, reason },
            #[cfg(feature = "conflux")]
            CircuitCmd::Conflux(ConfluxCmd::HandshakeComplete { hop, early, cell }) => {
                let cell = SendRelayCell {
                    hop: Some(hop),
                    early,
                    cell,
                };
                Self::ConfluxHandshakeComplete { leg, cell }
            }
            #[cfg(feature = "conflux")]
            CircuitCmd::Enqueue(msg) => Self::Enqueue { leg, msg },
            CircuitCmd::CleanShutdown => Self::CleanShutdown,
        }
    }
}

/// A command to execute at the end of [`Reactor::run_once`].
#[derive(From, Debug)]
#[allow(clippy::large_enum_variant)] // TODO #2003: should we resolve this?
enum CircuitEvent {
    /// Run a single `CircuitCmd` command.
    RunCmd {
        /// The unique identifier of the circuit leg to run the command on
        leg: UniqId,
        /// The command to run.
        cmd: CircuitCmd,
    },
    /// Handle a control message
    HandleControl(CtrlMsg),
    /// Handle an input message.
    HandleCell {
        /// The unique identifier of the circuit leg the message was received on.
        leg: UniqId,
        /// The message to handle.
        cell: ClientCircChanMsg,
    },
    /// Remove the specified circuit leg from the conflux set.
    ///
    /// Returned whenever a single circuit leg needs to be be removed
    /// from the reactor's conflux set, without necessarily tearing down
    /// the whole set or shutting down the reactor.
    ///
    /// Note: this event *can* cause the reactor to shut down
    /// (and the conflux set to be closed).
    ///
    /// See the [`ConfluxSet::remove`] docs for more on the exact behavior of this command.
    RemoveLeg {
        /// The leg to remove.
        leg: UniqId,
        /// The reason for removal.
        ///
        /// This is only used for conflux circuits that get removed
        /// before the conflux handshake is complete.
        ///
        /// The [`RemoveLegReason`] is mapped by the reactor to a
        /// [`ConfluxHandshakeError`] that is sent to the initiator of the
        /// handshake to indicate the reason the handshake failed.
        reason: RemoveLegReason,
    },
    /// Take some event (blocking or unblocking a circuit, or sending padding)
    /// based on the circuit padding backend code.
    PaddingAction {
        /// The leg on which to take the padding event .
        leg: UniqId,
        /// The event to take.
        padding_event: PaddingEvent,
    },
    /// Protocol violation. This leads for now to the close of the circuit reactor. The
    /// error causing the violation is set in err.
    ProtoViolation {
        /// The error that causes this protocol violation.
        err: crate::Error,
    },
}

impl CircuitEvent {
    /// Return the ordering with which we should handle this event
    /// within a list of events returned by a single call to next_circ_event().
    ///
    /// NOTE: Please do not make this any more complicated:
    /// It is a consequence of a kludge that we need this sorting at all.
    /// Assuming that eventually, we switch away from the current
    /// poll-oriented `next_circ_event` design,
    /// we may be able to get rid of this entirely.
    fn order_within_batch(&self) -> u8 {
        use CircuitEvent as CA;
        use PaddingEvent as PE;
        // This immediate state MUST NOT be used for events emitting cells. At the moment, it is
        // only used by the protocol violation event which leads to a shutdown of the reactor.
        const IMMEDIATE: u8 = 0;
        const EARLY: u8 = 1;
        const NORMAL: u8 = 2;
        const LATE: u8 = 3;

        // We use this ordering to move any "StartBlocking" to the _end_ of a batch and
        // "StopBlocking" to the start.
        //
        // This way, we can be sure that we will handle any "send data" operations
        // (and tell the Padder about them) _before_  we tell the Padder
        // that we have blocked the circuit.
        //
        // This keeps things a bit more logical.
        match self {
            CA::RunCmd { .. } => NORMAL,
            CA::HandleControl(..) => NORMAL,
            CA::HandleCell { .. } => NORMAL,
            CA::RemoveLeg { .. } => NORMAL,
            #[cfg(feature = "circ-padding")]
            CA::PaddingAction { padding_event, .. } => match padding_event {
                PE::StopBlocking => EARLY,
                PE::SendPadding(..) => NORMAL,
                PE::StartBlocking(..) => LATE,
            },
            #[cfg(not(feature = "circ-padding"))]
            CA::PaddingAction { .. } => NORMAL,
            CA::ProtoViolation { .. } => IMMEDIATE,
        }
    }
}

/// An object that's waiting for a meta cell (one not associated with a stream) in order to make
/// progress.
///
/// # Background
///
/// The `Reactor` can't have async functions that send and receive cells, because its job is to
/// send and receive cells: if one of its functions tried to do that, it would just hang forever.
///
/// To get around this problem, the reactor can send some cells, and then make one of these
/// `MetaCellHandler` objects, which will be run when the reply arrives.
pub(crate) trait MetaCellHandler: Send {
    /// The hop we're expecting the message to come from. This is compared against the hop
    /// from which we actually receive messages, and an error is thrown if the two don't match.
    fn expected_hop(&self) -> HopLocation;
    /// Called when the message we were waiting for arrives.
    ///
    /// Gets a copy of the `Reactor` in order to do anything it likes there.
    ///
    /// If this function returns an error, the reactor will shut down.
    fn handle_msg(
        &mut self,
        msg: UnparsedRelayMsg,
        reactor: &mut Circuit,
    ) -> Result<MetaCellDisposition>;
}

/// A possible successful outcome of giving a message to a [`MsgHandler`](super::msghandler::MsgHandler).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "send-control-msg", visibility::make(pub))]
#[non_exhaustive]
pub(crate) enum MetaCellDisposition {
    /// The message was consumed; the handler should remain installed.
    #[cfg(feature = "send-control-msg")]
    Consumed,
    /// The message was consumed; the handler should be uninstalled.
    ConversationFinished,
    /// The message was consumed; the circuit should be closed.
    #[cfg(feature = "send-control-msg")]
    CloseCirc,
    // TODO: Eventually we might want the ability to have multiple handlers
    // installed, and to let them say "not for me, maybe for somebody else?".
    // But right now we don't need that.
}

/// Unwrap the specified [`Option`], returning a [`ReactorError::Shutdown`] if it is `None`.
///
/// This is a macro instead of a function to work around borrowck errors
/// in the select! from run_once().
macro_rules! unwrap_or_shutdown {
    ($self:expr, $res:expr, $reason:expr) => {{
        match $res {
            None => {
                trace!(
                    tunnel_id = %$self.tunnel_id,
                    reason = %$reason,
                    "reactor shutdown"
                );
                Err(ReactorError::Shutdown)
            }
            Some(v) => Ok(v),
        }
    }};
}

/// Object to handle incoming cells and background tasks on a circuit
///
/// This type is returned when you finish a circuit; you need to spawn a
/// new task that calls `run()` on it.
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub struct Reactor {
    /// Receiver for control messages for this reactor, sent by `ClientCirc` objects.
    ///
    /// This channel is polled in [`Reactor::run_once`], but only if the `chan_sender` sink
    /// is ready to accept cells.
    control: mpsc::UnboundedReceiver<CtrlMsg>,
    /// Receiver for command messages for this reactor, sent by `ClientCirc` objects.
    ///
    /// This channel is polled in [`Reactor::run_once`].
    ///
    /// NOTE: this is a separate channel from `control`, because some messages
    /// have higher priority and need to be handled even if the `chan_sender` is not
    /// ready (whereas `control` messages are not read until the `chan_sender` sink
    /// is ready to accept cells).
    command: mpsc::UnboundedReceiver<CtrlCmd>,
    /// A oneshot sender that is used to alert other tasks when this reactor is
    /// finally dropped.
    ///
    /// It is a sender for Void because we never actually want to send anything here;
    /// we only want to generate canceled events.
    #[allow(dead_code)] // the only purpose of this field is to be dropped.
    reactor_closed_tx: oneshot::Sender<void::Void>,
    /// A set of circuits that form a tunnel.
    ///
    /// Contains 1 or more circuits.
    ///
    /// Circuits may be added to this set throughout the lifetime of the reactor.
    ///
    /// Sometimes, the reactor will remove circuits from this set,
    /// for example if the `LINKED` message takes too long to arrive,
    /// or if congestion control negotiation fails.
    /// The reactor will continue running with the remaining circuits.
    /// It will shut down if *all* the circuits are removed.
    ///
    // TODO(conflux): document all the reasons why the reactor might
    // chose to tear down a circuit or tunnel (timeouts, protocol violations, etc.)
    circuits: ConfluxSet,
    /// An identifier for logging about this tunnel reactor.
    tunnel_id: TunnelId,
    /// Handlers, shared with `Circuit`.
    cell_handlers: CellHandlers,
    /// The time provider, used for conflux handshake timeouts.
    runtime: DynTimeProvider,
    /// The conflux handshake context, if there is an on-going handshake.
    ///
    /// Set to `None` if this is a single-path tunnel,
    /// or if none of the circuit legs from our conflux set
    /// are currently in the conflux handshake phase.
    #[cfg(feature = "conflux")]
    conflux_hs_ctx: Option<ConfluxHandshakeCtx>,
    /// A min-heap buffering all the out-of-order messages received so far.
    ///
    /// TODO(conflux): this becomes a DoS vector unless we impose a limit
    /// on its size. We should make this participate in the memquota memory
    /// tracking system, somehow.
    #[cfg(feature = "conflux")]
    ooo_msgs: BinaryHeap<ConfluxHeapEntry>,
}

/// The context for an on-going conflux handshake.
#[cfg(feature = "conflux")]
struct ConfluxHandshakeCtx {
    /// A channel for notifying the caller of the outcome of a CONFLUX_LINK request.
    answer: ConfluxLinkResultChannel,
    /// The number of legs that are currently doing the handshake.
    num_legs: usize,
    /// The handshake results we have collected so far.
    results: ConfluxHandshakeResult,
}

/// An out-of-order message buffered in [`Reactor::ooo_msgs`].
#[derive(Debug)]
#[cfg(feature = "conflux")]
struct ConfluxHeapEntry {
    /// The leg id this message came from.
    leg_id: UniqId,
    /// The out of order message
    msg: OooRelayMsg,
}

#[cfg(feature = "conflux")]
impl Ord for ConfluxHeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.msg.cmp(&other.msg)
    }
}

#[cfg(feature = "conflux")]
impl PartialOrd for ConfluxHeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(feature = "conflux")]
impl PartialEq for ConfluxHeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.msg == other.msg
    }
}

#[cfg(feature = "conflux")]
impl Eq for ConfluxHeapEntry {}

/// Cell handlers, shared between the Reactor and its underlying `Circuit`s.
struct CellHandlers {
    /// A handler for a meta cell, together with a result channel to notify on completion.
    ///
    /// NOTE(prop349): this is part of Arti's "Base Circuit Hop Handler".
    ///
    /// Upon sending an EXTEND cell, the [`ControlHandler`] sets this handler
    /// to [`CircuitExtender`](circuit::extender::CircuitExtender).
    /// The handler is then used in [`Circuit::handle_meta_cell`] for handling
    /// all the meta cells received on the circuit that are not SENDMEs or TRUNCATE
    /// (which are handled separately) or conflux cells
    /// (which are handled by the conflux handlers).
    ///
    /// The handler is uninstalled after the receipt of the EXTENDED cell,
    /// so any subsequent EXTENDED cells will cause the circuit to be torn down.
    meta_handler: Option<Box<dyn MetaCellHandler + Send>>,
    /// A handler for incoming stream requests.
    #[cfg(feature = "hs-service")]
    incoming_stream_req_handler: Option<IncomingStreamRequestHandler>,
}

impl Reactor {
    /// Create a new circuit reactor.
    ///
    /// The reactor will send outbound messages on `channel`, receive incoming
    /// messages on `input`, and identify this circuit by the channel-local
    /// [`CircId`] provided.
    ///
    /// The internal unique identifier for this circuit will be `unique_id`.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)] // TODO
    pub(super) fn new(
        channel: Arc<Channel>,
        channel_id: CircId,
        unique_id: UniqId,
        input: CircuitRxReceiver,
        runtime: DynTimeProvider,
        memquota: CircuitAccount,
        padding_ctrl: PaddingController,
        padding_stream: PaddingEventStream,
        timeouts: Arc<dyn TimeoutEstimator + Send>,
    ) -> (
        Self,
        mpsc::UnboundedSender<CtrlMsg>,
        mpsc::UnboundedSender<CtrlCmd>,
        oneshot::Receiver<void::Void>,
        Arc<TunnelMutableState>,
    ) {
        let tunnel_id = TunnelId::next();
        let (control_tx, control_rx) = mpsc::unbounded();
        let (command_tx, command_rx) = mpsc::unbounded();
        let mutable = Arc::new(MutableState::default());

        let (reactor_closed_tx, reactor_closed_rx) = oneshot::channel();

        let cell_handlers = CellHandlers {
            meta_handler: None,
            #[cfg(feature = "hs-service")]
            incoming_stream_req_handler: None,
        };

        let unique_id = TunnelScopedCircId::new(tunnel_id, unique_id);
        let circuit_leg = Circuit::new(
            runtime.clone(),
            channel,
            channel_id,
            unique_id,
            input,
            memquota,
            Arc::clone(&mutable),
            padding_ctrl,
            padding_stream,
            timeouts,
        );

        let (circuits, mutable) = ConfluxSet::new(tunnel_id, circuit_leg);

        let reactor = Reactor {
            circuits,
            control: control_rx,
            command: command_rx,
            reactor_closed_tx,
            tunnel_id,
            cell_handlers,
            runtime,
            #[cfg(feature = "conflux")]
            conflux_hs_ctx: None,
            #[cfg(feature = "conflux")]
            ooo_msgs: Default::default(),
        };

        (reactor, control_tx, command_tx, reactor_closed_rx, mutable)
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    ///
    /// Once this method returns, the circuit is dead and cannot be
    /// used again.
    #[instrument(level = "trace", skip_all)]
    pub async fn run(mut self) -> Result<()> {
        trace!(tunnel_id = %self.tunnel_id, "Running tunnel reactor");
        let result: Result<()> = loop {
            match self.run_once().await {
                Ok(()) => (),
                Err(ReactorError::Shutdown) => break Ok(()),
                Err(ReactorError::Err(e)) => break Err(e),
            }
        };

        // Log that the reactor stopped, possibly with the associated error as a report.
        // May log at a higher level depending on the error kind.
        const MSG: &str = "Tunnel reactor stopped";
        match &result {
            Ok(()) => trace!(tunnel_id = %self.tunnel_id, "{MSG}"),
            Err(e) => debug_report!(e, tunnel_id = %self.tunnel_id, "{MSG}"),
        }

        result
    }

    /// Helper for run: doesn't mark the circuit closed on finish.  Only
    /// processes one cell or control message.
    #[instrument(level = "trace", skip_all)]
    async fn run_once(&mut self) -> StdResult<(), ReactorError> {
        // If all the circuits are closed, shut down the reactor
        if self.circuits.is_empty() {
            trace!(
                tunnel_id = %self.tunnel_id,
                "Tunnel reactor shutting down: all circuits have closed",
            );

            return Err(ReactorError::Shutdown);
        }

        // If this is a single path circuit, we need to wait until the first hop
        // is created before doing anything else
        let single_path_with_hops = self
            .circuits
            .single_leg_mut()
            .is_ok_and(|leg| !leg.has_hops());
        if single_path_with_hops {
            self.wait_for_create().await?;

            return Ok(());
        }

        // Prioritize the buffered messages.
        //
        // Note: if any of the messages are ready to be handled,
        // this will block the reactor until we are done processing them
        //
        // TODO circpad: If this is a problem, we might want to re-order things so that we
        // prioritize padding instead.  On the other hand, this should be fixed by refactoring
        // circuit and tunnel reactors, so we might do well to just leave it alone for now.
        #[cfg(feature = "conflux")]
        self.try_dequeue_ooo_msgs().await?;

        let mut events = select_biased! {
            res = self.command.next() => {
                let cmd = unwrap_or_shutdown!(self, res, "command channel drop")?;
                return ControlHandler::new(self).handle_cmd(cmd);
            },
            // Check whether we've got a control message pending.
            //
            // Note: unfortunately, reading from control here means we might start
            // handling control messages before our chan_senders are ready.
            // With the current design, this is inevitable: we can't know which circuit leg
            // a control message is meant for without first reading the control message from
            // the channel, and at that point, we can't know for sure whether that particular
            // circuit is ready for sending.
            ret = self.control.next() => {
                let msg = unwrap_or_shutdown!(self, ret, "control drop")?;
                smallvec![CircuitEvent::HandleControl(msg)]
            },
            res = self.circuits.next_circ_event(&self.runtime).fuse() => res?,
        };

        // Put the events into the order that we need to execute them in.
        //
        // (Yes, this _does_ have to be a stable sort.  Not all events may be freely re-ordered
        // with respect to one another.)
        events.sort_by_key(|a| a.order_within_batch());

        for event in events {
            let cmd = match event {
                CircuitEvent::RunCmd { leg, cmd } => Some(RunOnceCmd::Single(
                    RunOnceCmdInner::from_circuit_cmd(leg, cmd),
                )),
                CircuitEvent::HandleControl(ctrl) => ControlHandler::new(self)
                    .handle_msg(ctrl)?
                    .map(RunOnceCmd::Single),
                CircuitEvent::HandleCell { leg, cell } => {
                    let circ = self
                        .circuits
                        .leg_mut(leg)
                        .ok_or_else(|| internal!("the circuit leg we just had disappeared?!"))?;

                    let circ_cmds = circ.handle_cell(&mut self.cell_handlers, leg, cell)?;
                    if circ_cmds.is_empty() {
                        None
                    } else {
                        // TODO: we return RunOnceCmd::Multiple even if there's a single command.
                        //
                        // See the TODO on `Circuit::handle_cell`.
                        let cmd = RunOnceCmd::Multiple(
                            circ_cmds
                                .into_iter()
                                .map(|cmd| RunOnceCmdInner::from_circuit_cmd(leg, cmd))
                                .collect(),
                        );

                        Some(cmd)
                    }
                }
                CircuitEvent::RemoveLeg { leg, reason } => {
                    Some(RunOnceCmdInner::RemoveLeg { leg, reason }.into())
                }
                CircuitEvent::PaddingAction { leg, padding_event } => {
                    cfg_if! {
                        if #[cfg(feature = "circ-padding")] {
                            Some(RunOnceCmdInner::PaddingAction { leg, padding_event }.into())
                        } else {
                            // If padding isn't enabled, we never generate a padding event,
                            // so we can be sure this case will never be called.
                            void::unreachable(padding_event.0);
                        }
                    }
                }
                CircuitEvent::ProtoViolation { err } => {
                    return Err(err.into());
                }
            };

            if let Some(cmd) = cmd {
                self.handle_run_once_cmd(cmd).await?;
            }
        }

        Ok(())
    }

    /// Try to process the previously-out-of-order messages we might have buffered.
    #[cfg(feature = "conflux")]
    #[instrument(level = "trace", skip_all)]
    async fn try_dequeue_ooo_msgs(&mut self) -> StdResult<(), ReactorError> {
        // Check if we're ready to dequeue any of the previously out-of-order cells.
        while let Some(entry) = self.ooo_msgs.peek() {
            let should_pop = self.circuits.is_seqno_in_order(entry.msg.seqno);

            if !should_pop {
                break;
            }

            let entry = self.ooo_msgs.pop().expect("item just disappeared?!");

            let circ = self
                .circuits
                .leg_mut(entry.leg_id)
                .ok_or_else(|| internal!("the circuit leg we just had disappeared?!"))?;
            let handlers = &mut self.cell_handlers;
            let cmd = circ
                .handle_in_order_relay_msg(
                    handlers,
                    entry.msg.hopnum,
                    entry.leg_id,
                    entry.msg.cell_counts_towards_windows,
                    entry.msg.streamid,
                    entry.msg.msg,
                )?
                .map(|cmd| {
                    RunOnceCmd::Single(RunOnceCmdInner::from_circuit_cmd(entry.leg_id, cmd))
                });

            if let Some(cmd) = cmd {
                self.handle_run_once_cmd(cmd).await?;
            }
        }

        Ok(())
    }

    /// Handle a [`RunOnceCmd`].
    #[instrument(level = "trace", skip_all)]
    async fn handle_run_once_cmd(&mut self, cmd: RunOnceCmd) -> StdResult<(), ReactorError> {
        match cmd {
            RunOnceCmd::Single(cmd) => return self.handle_single_run_once_cmd(cmd).await,
            RunOnceCmd::Multiple(cmds) => {
                // While we know `sendable` is ready to accept *one* cell,
                // we can't be certain it will be able to accept *all* of the cells
                // that need to be sent here. This means we *may* end up buffering
                // in its underlying SometimesUnboundedSink! That is OK, because
                // RunOnceCmd::Multiple is only used for handling packed cells.
                for cmd in cmds {
                    self.handle_single_run_once_cmd(cmd).await?;
                }
            }
        }

        Ok(())
    }

    /// Handle a [`RunOnceCmd`].
    #[instrument(level = "trace", skip_all)]
    async fn handle_single_run_once_cmd(
        &mut self,
        cmd: RunOnceCmdInner,
    ) -> StdResult<(), ReactorError> {
        match cmd {
            RunOnceCmdInner::Send { leg, cell, done } => {
                // TODO: check the cc window
                let res = self.circuits.send_relay_cell_on_leg(cell, Some(leg)).await;
                if let Some(done) = done {
                    // Don't care if the receiver goes away
                    let _ = done.send(res.clone());
                }
                res?;
            }
            #[cfg(feature = "send-control-msg")]
            RunOnceCmdInner::SendMsgAndInstallHandler { msg, handler, done } => {
                let cell: Result<Option<SendRelayCell>> =
                    self.prepare_msg_and_install_handler(msg, handler);

                match cell {
                    Ok(Some(cell)) => {
                        // TODO(conflux): let the RunOnceCmdInner specify which leg to send the cell on
                        let outcome = self.circuits.send_relay_cell_on_leg(cell, None).await;
                        // don't care if receiver goes away.
                        let _ = done.send(outcome.clone());
                        outcome?;
                    }
                    Ok(None) => {
                        // don't care if receiver goes away.
                        let _ = done.send(Ok(()));
                    }
                    Err(e) => {
                        // don't care if receiver goes away.
                        let _ = done.send(Err(e.clone()));
                        return Err(e.into());
                    }
                }
            }
            RunOnceCmdInner::BeginStream {
                leg,
                cell,
                hop,
                done,
            } => {
                match cell {
                    Ok((cell, stream_id)) => {
                        let circ = self
                            .circuits
                            .leg_mut(leg)
                            .ok_or_else(|| internal!("leg disappeared?!"))?;
                        let cell_hop = cell.hop.expect("missing hop in client SendRelayCell?!");
                        let relay_format = circ
                            .hop_mut(cell_hop)
                            // TODO: Is this the right error type here? Or should there be a "HopDisappeared"?
                            .ok_or(Error::NoSuchHop)?
                            .relay_cell_format();

                        let outcome = self.circuits.send_relay_cell_on_leg(cell, Some(leg)).await;
                        // don't care if receiver goes away.
                        let _ = done.send(outcome.clone().map(|_| (stream_id, hop, relay_format)));
                        outcome?;
                    }
                    Err(e) => {
                        // don't care if receiver goes away.
                        let _ = done.send(Err(e.clone()));
                        return Err(e.into());
                    }
                }
            }
            RunOnceCmdInner::CloseStream {
                hop,
                sid,
                behav,
                reason,
                done,
            } => {
                let result = {
                    let (leg_id, hop_num) = self
                        .resolve_hop_location(hop)
                        .map_err(into_bad_api_usage!("Could not resolve {hop:?}"))?;
                    let leg = self
                        .circuits
                        .leg_mut(leg_id)
                        .ok_or(bad_api_usage!("No leg for id {:?}", leg_id))?;
                    Ok::<_, Bug>((leg, hop_num))
                };

                let (leg, hop_num) = match result {
                    Ok(x) => x,
                    Err(e) => {
                        if let Some(done) = done {
                            // don't care if the sender goes away
                            let e = into_bad_api_usage!("Could not resolve {hop:?}")(e);
                            let _ = done.send(Err(e.into()));
                        }
                        return Ok(());
                    }
                };

                let max_rtt = {
                    let hop = leg
                        .hop(hop_num)
                        .ok_or_else(|| internal!("the hop we resolved disappeared?!"))?;
                    let ccontrol = hop.ccontrol();

                    // Note: if we have no measurements for the RTT, this will be set to 0,
                    // and the timeout will be 2 * CBT.
                    ccontrol
                        .rtt()
                        .max_rtt_usec()
                        .map(|rtt| Duration::from_millis(u64::from(rtt)))
                        .unwrap_or_default()
                };

                // The length of the circuit up until the hop that has the half-streeam.
                //
                // +1, because HopNums are zero-based.
                let circ_len = usize::from(hop_num) + 1;

                // We double the CBT to account for rend circuits,
                // which are twice as long (otherwise we risk expiring
                // the rend half-streams too soon).
                let timeout = std::cmp::max(max_rtt, 2 * leg.estimate_cbt(circ_len));
                let expire_at = self.runtime.now() + timeout;

                let res: Result<()> = leg
                    .close_stream(hop_num, sid, behav, reason, expire_at)
                    .await;

                if let Some(done) = done {
                    // don't care if the sender goes away
                    let _ = done.send(res);
                }
            }
            RunOnceCmdInner::MaybeSendXon {
                rate,
                stream_id,
                hop,
            } => {
                let (leg_id, hop_num) = match self.resolve_hop_location(hop) {
                    Ok(x) => x,
                    Err(NoJoinPointError) => {
                        // A stream tried to send an XON message message to the join point of
                        // a tunnel that has never had a join point. Currently in arti, only a
                        // `StreamTarget` asks us to send an XON message, and this tunnel
                        // originally created the `StreamTarget` to begin with. So this is a
                        // legitimate bug somewhere in the tunnel code.
                        return Err(
                            internal!(
                                "Could not send an XON message to a join point on a tunnel without a join point",
                            )
                            .into()
                        );
                    }
                };

                let Some(leg) = self.circuits.leg_mut(leg_id) else {
                    // The leg has disappeared. This is fine since the stream may have ended and
                    // been cleaned up while this `CtrlMsg::MaybeSendXon` message was queued.
                    // It is possible that is a bug and this is an incorrect leg number, but
                    // it's not currently possible to differentiate between an incorrect leg
                    // number and a tunnel leg that has been closed.
                    debug!("Could not send an XON message on a leg that does not exist. Ignoring.");
                    return Ok(());
                };

                let Some(hop) = leg.hop_mut(hop_num) else {
                    // The hop has disappeared. This is fine since the circuit may have been
                    // been truncated while the `CtrlMsg::MaybeSendXon` message was queued.
                    // It is possible that is a bug and this is an incorrect hop number, but
                    // it's not currently possible to differentiate between an incorrect hop
                    // number and a circuit hop that has been removed.
                    debug!("Could not send an XON message on a hop that does not exist. Ignoring.");
                    return Ok(());
                };

                let Some(msg) = hop.maybe_send_xon(rate, stream_id)? else {
                    // Nothing to do.
                    return Ok(());
                };

                let cell = AnyRelayMsgOuter::new(Some(stream_id), msg.into());
                let cell = SendRelayCell {
                    hop: Some(hop_num),
                    early: false,
                    cell,
                };

                leg.send_relay_cell(cell).await?;
            }
            RunOnceCmdInner::HandleSendMe { leg, hop, sendme } => {
                let leg = self
                    .circuits
                    .leg_mut(leg)
                    .ok_or_else(|| internal!("leg disappeared?!"))?;
                // NOTE: it's okay to await. We are only awaiting on the congestion_signals
                // future which *should* resolve immediately
                let signals = leg.chan_sender.congestion_signals().await;
                leg.handle_sendme(hop, sendme, signals)?;
            }
            RunOnceCmdInner::FirstHopClockSkew { answer } => {
                let res = self.circuits.single_leg_mut().map(|leg| leg.clock_skew());

                // don't care if the sender goes away
                let _ = answer.send(res.map_err(Into::into));
            }
            RunOnceCmdInner::CleanShutdown => {
                trace!(tunnel_id = %self.tunnel_id, "reactor shutdown due to handled cell");
                return Err(ReactorError::Shutdown);
            }
            RunOnceCmdInner::RemoveLeg { leg, reason } => {
                warn!(tunnel_id = %self.tunnel_id, reason = %reason, "removing circuit leg");

                let circ = self.circuits.remove(leg)?;
                let is_conflux_pending = circ.is_conflux_pending();

                // Drop the removed leg. This will cause it to close if it's not already closed.
                drop(circ);

                // If we reach this point, it means we have more than one leg
                // (otherwise the .remove() would've returned a Shutdown error),
                // so we expect there to be a ConfluxHandshakeContext installed.

                #[cfg(feature = "conflux")]
                if is_conflux_pending {
                    let (error, proto_violation): (_, Option<Error>) = match &reason {
                        RemoveLegReason::ConfluxHandshakeTimeout => {
                            (ConfluxHandshakeError::Timeout, None)
                        }
                        RemoveLegReason::ConfluxHandshakeErr(e) => {
                            (ConfluxHandshakeError::Link(e.clone()), Some(e.clone()))
                        }
                        RemoveLegReason::ChannelClosed => {
                            (ConfluxHandshakeError::ChannelClosed, None)
                        }
                    };

                    self.note_conflux_handshake_result(Err(error), proto_violation.is_some())?;

                    if let Some(e) = proto_violation {
                        tor_error::warn_report!(
                            e,
                            tunnel_id = %self.tunnel_id,
                            "Malformed conflux handshake, tearing down tunnel",
                        );

                        return Err(e.into());
                    }
                }
            }
            #[cfg(feature = "conflux")]
            RunOnceCmdInner::ConfluxHandshakeComplete { leg, cell } => {
                // Note: on the client-side, the handshake is considered complete once the
                // RELAY_CONFLUX_LINKED_ACK is sent (roughly upon receipt of the LINKED cell).
                //
                // We're optimistic here, and declare the handshake a success *before*
                // sending the LINKED_ACK response. I think this is OK though,
                // because if the send_relay_cell() below fails, the reactor will shut
                // down anyway. OTOH, marking the handshake as complete slightly early
                // means that on the happy path, the circuit is marked as usable sooner,
                // instead of blocking on the sending of the LINKED_ACK.
                self.note_conflux_handshake_result(Ok(()), false)?;

                let res = self.circuits.send_relay_cell_on_leg(cell, Some(leg)).await;

                res?;
            }
            #[cfg(feature = "conflux")]
            RunOnceCmdInner::Link { circuits, answer } => {
                // Add the specified circuits to our conflux set,
                // and send a LINK cell down each unlinked leg.
                //
                // NOTE: this will block the reactor until all the cells are sent.
                self.handle_link_circuits(circuits, answer).await?;
            }
            #[cfg(feature = "conflux")]
            RunOnceCmdInner::Enqueue { leg, msg } => {
                let entry = ConfluxHeapEntry { leg_id: leg, msg };
                self.ooo_msgs.push(entry);
            }
            #[cfg(feature = "circ-padding")]
            RunOnceCmdInner::PaddingAction { leg, padding_event } => {
                // TODO: If we someday move back to having a per-circuit reactor,
                // this event would logically belong there, not on the tunnel reactor.
                self.circuits.run_padding_event(leg, padding_event).await?;
            }
        }

        Ok(())
    }

    /// Wait for a [`CtrlMsg::Create`] to come along to set up the circuit.
    ///
    /// Returns an error if an unexpected `CtrlMsg` is received.
    #[instrument(level = "trace", skip_all)]
    async fn wait_for_create(&mut self) -> StdResult<(), ReactorError> {
        let msg = select_biased! {
            res = self.command.next() => {
                let cmd = unwrap_or_shutdown!(self, res, "shutdown channel drop")?;
                match cmd {
                    CtrlCmd::Shutdown => return self.handle_shutdown().map(|_| ()),
                    #[cfg(test)]
                    CtrlCmd::AddFakeHop {
                        relay_cell_format: format,
                        fwd_lasthop,
                        rev_lasthop,
                        peer_id,
                        params,
                        done,
                    } => {
                        let leg = self.circuits.single_leg_mut()?;
                        leg.handle_add_fake_hop(format, fwd_lasthop, rev_lasthop, peer_id, &params, done);
                        return Ok(())
                    },
                    _ => {
                        trace!("reactor shutdown due to unexpected command: {:?}", cmd);
                        return Err(Error::CircProto(format!("Unexpected control {cmd:?} on client circuit")).into());
                    }
                }
            },
            res = self.control.next() => unwrap_or_shutdown!(self, res, "control drop")?,
        };

        match msg {
            CtrlMsg::Create {
                recv_created,
                handshake,
                settings,
                done,
            } => {
                // TODO(conflux): instead of crashing the reactor, it might be better
                // to send the error via the done channel instead
                let leg = self.circuits.single_leg_mut()?;
                leg.handle_create(recv_created, handshake, settings, done)
                    .await
            }
            _ => {
                trace!("reactor shutdown due to unexpected cell: {:?}", msg);

                Err(Error::CircProto(format!("Unexpected {msg:?} cell on client circuit")).into())
            }
        }
    }

    /// Add the specified handshake result to our `ConfluxHandshakeContext`.
    ///
    /// If all the circuits we were waiting on have finished the conflux handshake,
    /// the `ConfluxHandshakeContext` is consumed, and the results we have collected
    /// are sent to the handshake initiator.
    #[cfg(feature = "conflux")]
    #[instrument(level = "trace", skip_all)]
    fn note_conflux_handshake_result(
        &mut self,
        res: StdResult<(), ConfluxHandshakeError>,
        reactor_is_closing: bool,
    ) -> StdResult<(), ReactorError> {
        let tunnel_complete = match self.conflux_hs_ctx.as_mut() {
            Some(conflux_ctx) => {
                conflux_ctx.results.push(res);
                // Whether all the legs have finished linking:
                conflux_ctx.results.len() == conflux_ctx.num_legs
            }
            None => {
                return Err(internal!("no conflux handshake context").into());
            }
        };

        if tunnel_complete || reactor_is_closing {
            // Time to remove the conflux handshake context
            // and extract the results we have collected
            let conflux_ctx = self.conflux_hs_ctx.take().expect("context disappeared?!");

            let success_count = conflux_ctx.results.iter().filter(|res| res.is_ok()).count();
            let leg_count = conflux_ctx.results.len();

            info!(
                tunnel_id = %self.tunnel_id,
                "conflux tunnel ready ({success_count}/{leg_count} circuits successfully linked)",
            );

            send_conflux_outcome(conflux_ctx.answer, Ok(conflux_ctx.results))?;

            // We don't expect to receive any more handshake results,
            // at least not until we get another LinkCircuits control message,
            // which will install a new ConfluxHandshakeCtx with a channel
            // for us to send updates on
        }

        Ok(())
    }

    /// Prepare a `SendRelayCell` request, and install the given meta-cell handler.
    fn prepare_msg_and_install_handler(
        &mut self,
        msg: Option<AnyRelayMsgOuter>,
        handler: Option<Box<dyn MetaCellHandler + Send + 'static>>,
    ) -> Result<Option<SendRelayCell>> {
        let msg = msg
            .map(|msg| {
                let handlers = &mut self.cell_handlers;
                let handler = handler
                    .as_ref()
                    .or(handlers.meta_handler.as_ref())
                    .ok_or_else(|| internal!("tried to use an ended Conversation"))?;
                // We should always have a precise HopLocation here so this should never fails but
                // in case we have a ::JointPoint, we'll notice.
                let hop = handler.expected_hop().hop_num().ok_or(bad_api_usage!(
                    "MsgHandler doesn't have a precise HopLocation"
                ))?;
                Ok::<_, crate::Error>(SendRelayCell {
                    hop: Some(hop),
                    early: false,
                    cell: msg,
                })
            })
            .transpose()?;

        if let Some(handler) = handler {
            self.cell_handlers.set_meta_handler(handler)?;
        }

        Ok(msg)
    }

    /// Handle a shutdown request.
    fn handle_shutdown(&self) -> StdResult<Option<RunOnceCmdInner>, ReactorError> {
        trace!(
            tunnel_id = %self.tunnel_id,
            "reactor shutdown due to explicit request",
        );

        Err(ReactorError::Shutdown)
    }

    /// Handle a request to shutdown the reactor and return the only [`Circuit`] in this tunnel.
    ///
    /// Returns an error over the `answer` channel if the reactor has no circuits,
    /// or more than one circuit. The reactor will shut down regardless.
    #[cfg(feature = "conflux")]
    fn handle_shutdown_and_return_circuit(
        &mut self,
        answer: oneshot::Sender<StdResult<Circuit, Bug>>,
    ) -> StdResult<(), ReactorError> {
        // Don't care if the receiver goes away
        let _ = answer.send(self.circuits.take_single_leg());
        self.handle_shutdown().map(|_| ())
    }

    /// Resolves a [`TargetHop`] to a [`HopLocation`].
    ///
    /// After resolving a `TargetHop::LastHop`,
    /// the `HopLocation` can become stale if a single-path circuit is later extended or truncated.
    /// This means that the `HopLocation` can become stale from one reactor iteration to the next.
    ///
    /// It's generally okay to hold on to a (possibly stale) `HopLocation`
    /// if you need a fixed hop position in the tunnel.
    /// For example if we open a stream to `TargetHop::LastHop`,
    /// we would want to store the stream position as a `HopLocation` and not a `TargetHop::LastHop`
    /// as we don't want the stream position to change as the tunnel is extended or truncated.
    ///
    /// Returns [`NoHopsBuiltError`] if trying to resolve `TargetHop::LastHop`
    /// and the tunnel has no hops
    /// (either has no legs, or has legs which contain no hops).
    fn resolve_target_hop(&self, hop: TargetHop) -> StdResult<HopLocation, NoHopsBuiltError> {
        match hop {
            TargetHop::Hop(hop) => Ok(hop),
            TargetHop::LastHop => {
                if let Ok(leg) = self.circuits.single_leg() {
                    let leg_id = leg.unique_id();
                    // single-path tunnel
                    let hop = leg.last_hop_num().ok_or(NoHopsBuiltError)?;
                    Ok(HopLocation::Hop((leg_id, hop)))
                } else if !self.circuits.is_empty() {
                    // multi-path tunnel
                    Ok(HopLocation::JoinPoint)
                } else {
                    // no legs
                    Err(NoHopsBuiltError)
                }
            }
        }
    }

    /// Resolves a [`HopLocation`] to a [`UniqId`] and [`HopNum`].
    ///
    /// After resolving a `HopLocation::JoinPoint`,
    /// the [`UniqId`] and [`HopNum`] can become stale if the primary leg changes.
    ///
    /// You should try to only resolve to a specific [`UniqId`] and [`HopNum`] immediately before you
    /// need them,
    /// and you should not hold on to the resolved [`UniqId`] and [`HopNum`] between reactor
    /// iterations as the primary leg may change from one iteration to the next.
    ///
    /// Returns [`NoJoinPointError`] if trying to resolve `HopLocation::JoinPoint`
    /// but it does not have a join point.
    #[instrument(level = "trace", skip_all)]
    fn resolve_hop_location(
        &self,
        hop: HopLocation,
    ) -> StdResult<(UniqId, HopNum), NoJoinPointError> {
        match hop {
            HopLocation::Hop((leg_id, hop_num)) => Ok((leg_id, hop_num)),
            HopLocation::JoinPoint => {
                if let Some((leg_id, hop_num)) = self.circuits.primary_join_point() {
                    Ok((leg_id, hop_num))
                } else {
                    // Attempted to get the join point of a non-multipath tunnel.
                    Err(NoJoinPointError)
                }
            }
        }
    }

    /// Resolve a [`TargetHop`] directly into a [`UniqId`] and [`HopNum`].
    ///
    /// This is a helper function that basically calls both resolve_target_hop and
    /// resolve_hop_location back to back.
    ///
    /// It returns None on failure to resolve meaning that if you want more detailed error on why
    /// it failed, explicitly use the resolve_hop_location() and resolve_target_hop() functions.
    pub(crate) fn target_hop_to_hopnum_id(&self, hop: TargetHop) -> Option<(UniqId, HopNum)> {
        self.resolve_target_hop(hop)
            .ok()
            .and_then(|resolved| self.resolve_hop_location(resolved).ok())
    }

    /// Install or remove a padder at a given hop.
    #[cfg(feature = "circ-padding-manual")]
    fn set_padding_at_hop(
        &self,
        hop: HopLocation,
        padder: Option<super::circuit::padding::CircuitPadder>,
    ) -> Result<()> {
        let HopLocation::Hop((leg_id, hop_num)) = hop else {
            return Err(bad_api_usage!("Padding to the join point is not supported.").into());
        };
        let circ = self.circuits.leg(leg_id).ok_or(Error::NoSuchHop)?;
        circ.set_padding_at_hop(hop_num, padder)?;
        Ok(())
    }

    /// Does congestion control use stream SENDMEs for the given hop?
    ///
    /// Returns `None` if either the `leg` or `hop` don't exist.
    fn uses_stream_sendme(&self, leg: UniqId, hop: HopNum) -> Option<bool> {
        self.circuits.uses_stream_sendme(leg, hop)
    }

    /// Handle a request to link some extra circuits in the reactor's conflux set.
    ///
    /// The circuits are validated, and if they do not have the same length,
    /// or if they do not all have the same last hop, an error is returned on
    /// the `answer` channel, and the conflux handshake is *not* initiated.
    ///
    /// If validation succeeds, the circuits are added to this reactor's conflux set,
    /// and the conflux handshake is initiated (by sending a LINK cell on each leg).
    ///
    /// NOTE: this blocks the reactor main loop until all the cells are sent.
    #[cfg(feature = "conflux")]
    #[instrument(level = "trace", skip_all)]
    async fn handle_link_circuits(
        &mut self,
        circuits: Vec<Circuit>,
        answer: ConfluxLinkResultChannel,
    ) -> StdResult<(), ReactorError> {
        use tor_error::warn_report;

        if self.conflux_hs_ctx.is_some() {
            let err = internal!("conflux linking already in progress");
            send_conflux_outcome(answer, Err(err.into()))?;

            return Ok(());
        }

        let unlinked_legs = self.circuits.num_unlinked();

        // We need to send the LINK cell on each of the new circuits
        // and on each of the existing, unlinked legs from self.circuits.
        //
        // In reality, there can only be one such circuit
        // (the "initial" one from the previously single-path tunnel),
        // because any circuits that to complete the conflux handshake
        // get removed from the set.
        let num_legs = circuits.len() + unlinked_legs;

        // Note: add_legs validates `circuits`
        let res = async {
            self.circuits.add_legs(circuits, &self.runtime)?;
            self.circuits.link_circuits(&self.runtime).await
        }
        .await;

        if let Err(e) = res {
            warn_report!(e, "Failed to link conflux circuits");

            send_conflux_outcome(answer, Err(e))?;
        } else {
            // Save the channel, to notify the user of completion.
            self.conflux_hs_ctx = Some(ConfluxHandshakeCtx {
                answer,
                num_legs,
                results: Default::default(),
            });
        }

        Ok(())
    }
}

/// Notify the conflux handshake initiator of the handshake outcome.
///
/// Returns an error if the initiator has done away.
#[cfg(feature = "conflux")]
fn send_conflux_outcome(
    tx: ConfluxLinkResultChannel,
    res: Result<ConfluxHandshakeResult>,
) -> StdResult<(), ReactorError> {
    if tx.send(res).is_err() {
        tracing::warn!("conflux initiator went away before handshake completed?");
        return Err(ReactorError::Shutdown);
    }

    Ok(())
}

/// The tunnel does not have any hops.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
#[error("no hops have been built for this tunnel")]
pub(crate) struct NoHopsBuiltError;

/// The tunnel does not have a join point.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
#[error("the tunnel does not have a join point")]
pub(crate) struct NoJoinPointError;

impl CellHandlers {
    /// Try to install a given meta-cell handler to receive any unusual cells on
    /// this circuit, along with a result channel to notify on completion.
    fn set_meta_handler(&mut self, handler: Box<dyn MetaCellHandler + Send>) -> Result<()> {
        if self.meta_handler.is_none() {
            self.meta_handler = Some(handler);
            Ok(())
        } else {
            Err(Error::from(internal!(
                "Tried to install a meta-cell handler before the old one was gone."
            )))
        }
    }

    /// Try to install a given cell handler on this circuit.
    #[cfg(feature = "hs-service")]
    fn set_incoming_stream_req_handler(
        &mut self,
        handler: IncomingStreamRequestHandler,
    ) -> Result<()> {
        if self.incoming_stream_req_handler.is_none() {
            self.incoming_stream_req_handler = Some(handler);
            Ok(())
        } else {
            Err(Error::from(internal!(
                "Tried to install a BEGIN cell handler before the old one was gone."
            )))
        }
    }
}

#[cfg(test)]
mod test {
    // Tested in [`crate::client::circuit::test`].
}
