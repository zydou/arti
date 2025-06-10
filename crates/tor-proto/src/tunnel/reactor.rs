//! Code to handle incoming cells on a circuit.
//!
//! ## On message validation
//!
//! There are three steps for validating an incoming message on a stream:
//!
//! 1. Is the message contextually appropriate? (e.g., no more than one
//!    `CONNECTED` message per stream.) This is handled by calling
//!    [`CmdChecker::check_msg`](crate::stream::CmdChecker::check_msg).
//! 2. Does the message comply with flow-control rules? (e.g., no more data than
//!    we've gotten SENDMEs for.) For open streams, the stream itself handles
//!    this; for half-closed streams, the reactor handles it using the
//!    `halfstream` module.
//! 3. Does the message have an acceptable command type, and is the message
//!    well-formed? For open streams, the streams themselves handle this check.
//!    For half-closed streams, the reactor handles it by calling
//!    `consume_checked_msg()`.

pub(super) mod circuit;
mod conflux;
mod control;
pub(super) mod syncview;

use crate::crypto::cell::HopNum;
use crate::crypto::handshake::ntor_v3::NtorV3PublicKey;
use crate::memquota::{CircuitAccount, StreamAccount};
use crate::stream::AnyCmdChecker;
#[cfg(feature = "hs-service")]
use crate::stream::{IncomingStreamRequest, IncomingStreamRequestFilter};
use crate::tunnel::circuit::celltypes::ClientCircChanMsg;
use crate::tunnel::circuit::unique_id::UniqId;
use crate::tunnel::circuit::CircuitRxReceiver;
use crate::tunnel::{streammap, HopLocation, TargetHop};
use crate::util::err::ReactorError;
use crate::util::skew::ClockSkew;
use crate::{Error, Result};
use circuit::{Circuit, CircuitCmd};
use conflux::ConfluxSet;
use control::ControlHandler;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::mem::size_of;
use tor_cell::relaycell::msg::{AnyRelayMsg, End, Sendme};
use tor_cell::relaycell::{AnyRelayMsgOuter, RelayCellFormat, StreamId, UnparsedRelayMsg};
use tor_error::{bad_api_usage, internal, into_bad_api_usage, Bug};
use tor_rtcompat::DynTimeProvider;

use futures::channel::mpsc;
use futures::StreamExt;
use futures::{select_biased, FutureExt as _};
use oneshot_fused_workaround as oneshot;

use std::result::Result as StdResult;
use std::sync::Arc;

use crate::channel::Channel;
use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
use crate::tunnel::circuit::{StreamMpscReceiver, StreamMpscSender};
use derive_deftly::Deftly;
use derive_more::From;
use tor_cell::chancell::CircId;
use tor_llcrypto::pk;
use tor_memquota::mq_queue::{self, MpscSpec};
use tor_memquota::{derive_deftly_template_HasMemoryCost, memory_cost_structural_copy};
use tracing::{info, trace, warn};

use super::circuit::{MutableState, TunnelMutableState};

#[cfg(feature = "conflux")]
use {crate::util::err::ConfluxHandshakeError, conflux::OooRelayMsg};

pub(super) use control::CtrlCmd;
pub(super) use control::CtrlMsg;

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

pub(crate) use circuit::{RECV_WINDOW_INIT, STREAM_READER_BUFFER};

/// MPSC queue containing stream requests
#[cfg(feature = "hs-service")]
type StreamReqSender = mq_queue::Sender<StreamReqInfo, MpscSpec>;

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

/// A behavior to perform when closing a stream.
///
/// We don't use `Option<End>`` here, since the behavior of `SendNothing` is so surprising
/// that we shouldn't let it pass unremarked.
#[derive(Clone, Debug)]
pub(crate) enum CloseStreamBehavior {
    /// Send nothing at all, so that the other side will not realize we have
    /// closed the stream.
    ///
    /// We should only do this for incoming onion service streams when we
    /// want to black-hole the client's requests.
    SendNothing,
    /// Send an End cell, if we haven't already sent one.
    SendEnd(End),
}
impl Default for CloseStreamBehavior {
    fn default() -> Self {
        Self::SendEnd(End::new_misc())
    }
}

// TODO: the RunOnceCmd/RunOnceCmdInner/CircuitCmd/CircuitAction enum
// proliferation is a bit bothersome, but unavoidable with the current design.
//
// We should consider getting rid of some of these enums (if possible),
// and coming up with more intuitive names.

/// One or more [`RunOnceCmdInner`] to run inside [`Reactor::run_once`].
#[derive(From, Debug)]
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
        leg: LegId,
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
        leg: LegId,
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
        leg: LegId,
        /// Oneshot channel to notify on completion, with the allocated stream ID.
        done: ReactorResultChannel<(StreamId, HopLocation, RelayCellFormat)>,
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
        leg: LegId,
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
        leg: LegId,
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
        leg: LegId,
        /// The out-of-order message.
        msg: OooRelayMsg,
    },
    /// Perform a clean shutdown on this circuit.
    CleanShutdown,
}

impl RunOnceCmdInner {
    /// Create a [`RunOnceCmdInner`] out of a [`CircuitCmd`] and [`LegIdKey`].
    fn from_circuit_cmd(leg: LegIdKey, cmd: CircuitCmd) -> Self {
        match cmd {
            CircuitCmd::Send(cell) => Self::Send {
                leg: LegId(leg),
                cell,
                done: None,
            },
            CircuitCmd::HandleSendMe { hop, sendme } => Self::HandleSendMe {
                leg: LegId(leg),
                hop,
                sendme,
            },
            CircuitCmd::CloseStream {
                hop,
                sid,
                behav,
                reason,
            } => Self::CloseStream {
                hop: HopLocation::Hop((LegId(leg), hop)),
                sid,
                behav,
                reason,
                done: None,
            },
            #[cfg(feature = "conflux")]
            CircuitCmd::ConfluxRemove(reason) => Self::RemoveLeg {
                leg: LegId(leg),
                reason,
            },
            #[cfg(feature = "conflux")]
            CircuitCmd::ConfluxHandshakeComplete(cell) => Self::ConfluxHandshakeComplete {
                leg: LegId(leg),
                cell,
            },
            #[cfg(feature = "conflux")]
            CircuitCmd::Enqueue(msg) => Self::Enqueue {
                leg: LegId(leg),
                msg,
            },
            CircuitCmd::CleanShutdown => Self::CleanShutdown,
        }
    }
}

/// Cmd for sending a relay cell.
///
/// The contents of this struct are passed to `send_relay_cell`
#[derive(educe::Educe)]
#[educe(Debug)]
pub(crate) struct SendRelayCell {
    /// The hop number.
    pub(crate) hop: HopNum,
    /// Whether to use a RELAY_EARLY cell.
    pub(crate) early: bool,
    /// The cell to send.
    pub(crate) cell: AnyRelayMsgOuter,
}

/// A command to execute at the end of [`Reactor::run_once`].
#[derive(From, Debug)]
#[allow(clippy::large_enum_variant)] // TODO #2003: should we resolve this?
enum CircuitAction {
    /// Run a single `CircuitCmd` command.
    RunCmd {
        /// The unique identifier of the circuit leg to run the command on
        leg: LegIdKey,
        /// The command to run.
        cmd: CircuitCmd,
    },
    /// Handle a control message
    HandleControl(CtrlMsg),
    /// Handle an input message.
    HandleCell {
        /// The unique identifier of the circuit leg the message was received on.
        leg: LegIdKey,
        /// The message to handle.
        cell: ClientCircChanMsg,
    },
    /// Remove the specified circuit leg from the conflux set.
    ///
    /// Returned whenever a single circuit leg needs to be be removed
    /// from the reactor's conflux set, without necessarily tearing down
    /// the whole set or shutting down the reactor.
    ///
    /// Note: this action *can* cause the reactor to shut down
    /// (and the conflux set to be closed).
    ///
    /// See the [`ConfluxSet::remove`] docs for more on the exact behavior of this command.
    RemoveLeg {
        /// The leg to remove.
        leg: LegIdKey,
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
}

/// The reason for removing a circuit leg from the conflux set.
#[derive(Debug, derive_more::Display)]
enum RemoveLegReason {
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
    fn expected_hop(&self) -> HopNum;
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

/// A unique identifier for a circuit leg.
///
/// After the circuit is torn down, its `LegId` becomes invalid.
/// The same `LegId` won't be reused for a future circuit.
//
// TODO(#1857): make this pub
#[allow(unused)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub(crate) struct LegId(pub(crate) LegIdKey);

// TODO(#1999): can we use `UniqId` as the key instead of this newtype?
//
// See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2996#note_3199069
slotmap_careful::new_key_type! {
    /// A key type for the circuit leg slotmap
    ///
    /// See [`LegId`].
    pub(crate) struct LegIdKey;
}

impl From<LegIdKey> for LegId {
    fn from(leg_id: LegIdKey) -> Self {
        LegId(leg_id)
    }
}

memory_cost_structural_copy!(LegIdKey);

/// Unwrap the specified [`Option`], returning a [`ReactorError::Shutdown`] if it is `None`.
///
/// This is a macro instead of a function to work around borrowck errors
/// in the select! from run_once().
macro_rules! unwrap_or_shutdown {
    ($self:expr, $res:expr, $reason:expr) => {{
        match $res {
            None => {
                trace!("{}: reactor shutdown due to {}", $self.unique_id, $reason);
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
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
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
    leg_id: LegId,
    /// The out of order message
    msg: OooRelayMsg,
}

#[cfg(feature = "conflux")]
impl Ord for ConfluxHeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.msg.cmp(&other.msg).reverse()
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
    meta_handler: Option<Box<dyn MetaCellHandler + Send>>,
    /// A handler for incoming stream requests.
    #[cfg(feature = "hs-service")]
    incoming_stream_req_handler: Option<IncomingStreamRequestHandler>,
}

/// Information about an incoming stream request.
#[cfg(feature = "hs-service")]
#[derive(Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub(crate) struct StreamReqInfo {
    /// The [`IncomingStreamRequest`].
    pub(crate) req: IncomingStreamRequest,
    /// The ID of the stream being requested.
    pub(crate) stream_id: StreamId,
    /// The [`HopNum`].
    //
    // TODO: When we add support for exit relays, we need to turn this into an Option<HopNum>.
    // (For outbound messages (towards relays), there is only one hop that can send them: the client.)
    //
    // TODO: For onion services, we might be able to enforce the HopNum earlier: we would never accept an
    // incoming stream request from two separate hops.  (There is only one that's valid.)
    pub(crate) hop_num: HopNum,
    /// The [`LegId`] of the circuit the request came on.
    pub(crate) leg: LegId,
    /// The format which must be used with this stream to encode messages.
    #[deftly(has_memory_cost(indirect_size = "0"))]
    pub(crate) relay_cell_format: RelayCellFormat,
    /// A channel for receiving messages from this stream.
    #[deftly(has_memory_cost(indirect_size = "0"))] // estimate
    pub(crate) receiver: StreamMpscReceiver<UnparsedRelayMsg>,
    /// A channel for sending messages to be sent on this stream.
    #[deftly(has_memory_cost(indirect_size = "size_of::<AnyRelayMsg>()"))] // estimate
    pub(crate) msg_tx: StreamMpscSender<AnyRelayMsg>,
    /// The memory quota account to be used for this stream
    #[deftly(has_memory_cost(indirect_size = "0"))] // estimate (it contains an Arc)
    pub(crate) memquota: StreamAccount,
}

/// Data required for handling an incoming stream request.
#[cfg(feature = "hs-service")]
#[derive(educe::Educe)]
#[educe(Debug)]
struct IncomingStreamRequestHandler {
    /// A sender for sharing information about an incoming stream request.
    incoming_sender: StreamReqSender,
    /// A [`AnyCmdChecker`] for validating incoming stream requests.
    cmd_checker: AnyCmdChecker,
    /// The hop to expect incoming stream requests from.
    hop_num: HopNum,
    /// An [`IncomingStreamRequestFilter`] for checking whether the user wants
    /// this request, or wants to reject it immediately.
    #[educe(Debug(ignore))]
    filter: Box<dyn IncomingStreamRequestFilter>,
}

impl Reactor {
    /// Create a new circuit reactor.
    ///
    /// The reactor will send outbound messages on `channel`, receive incoming
    /// messages on `input`, and identify this circuit by the channel-local
    /// [`CircId`] provided.
    ///
    /// The internal unique identifier for this circuit will be `unique_id`.
    #[allow(clippy::type_complexity)] // TODO
    pub(super) fn new(
        channel: Arc<Channel>,
        channel_id: CircId,
        unique_id: UniqId,
        input: CircuitRxReceiver,
        runtime: DynTimeProvider,
        memquota: CircuitAccount,
    ) -> (
        Self,
        mpsc::UnboundedSender<CtrlMsg>,
        mpsc::UnboundedSender<CtrlCmd>,
        oneshot::Receiver<void::Void>,
        Arc<TunnelMutableState>,
    ) {
        let (control_tx, control_rx) = mpsc::unbounded();
        let (command_tx, command_rx) = mpsc::unbounded();
        let mutable = Arc::new(MutableState::default());

        let (reactor_closed_tx, reactor_closed_rx) = oneshot::channel();

        let cell_handlers = CellHandlers {
            meta_handler: None,
            #[cfg(feature = "hs-service")]
            incoming_stream_req_handler: None,
        };

        let circuit_leg = Circuit::new(
            channel,
            channel_id,
            unique_id,
            input,
            memquota,
            Arc::clone(&mutable),
        );

        let (circuits, mutable) = ConfluxSet::new(circuit_leg);

        let reactor = Reactor {
            circuits,
            control: control_rx,
            command: command_rx,
            reactor_closed_tx,
            unique_id,
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
    pub async fn run(mut self) -> Result<()> {
        trace!("{}: Running circuit reactor", self.unique_id);
        let result: Result<()> = loop {
            match self.run_once().await {
                Ok(()) => (),
                Err(ReactorError::Shutdown) => break Ok(()),
                Err(ReactorError::Err(e)) => break Err(e),
            }
        };
        trace!("{}: Circuit reactor stopped: {:?}", self.unique_id, result);
        result
    }

    /// Helper for run: doesn't mark the circuit closed on finish.  Only
    /// processes one cell or control message.
    async fn run_once(&mut self) -> StdResult<(), ReactorError> {
        // If all the circuits are closed, shut down the reactor
        //
        // TODO(conflux): we might need to rethink this behavior
        if self.circuits.is_empty() {
            trace!(
                "{}: Circuit reactor shutting down: all circuits have closed",
                self.unique_id
            );

            return Err(ReactorError::Shutdown);
        }

        // If this is a single path circuit, we need to wait until the first hop
        // is created before doing anything else
        let single_path_with_hops = self
            .circuits
            .single_leg_mut()
            .is_ok_and(|(_id, leg)| !leg.has_hops());
        if single_path_with_hops {
            self.wait_for_create().await?;

            return Ok(());
        }

        // Prioritize the buffered messages.
        //
        // Note: if any of the messages are ready to be handled,
        // this will block the reactor until we are done processing them
        #[cfg(feature = "conflux")]
        self.try_dequeue_ooo_msgs().await?;

        let action = select_biased! {
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
                CircuitAction::HandleControl(msg)
            },
            res = self.circuits.next_circ_action(&self.runtime).fuse() => res?,
        };

        let cmd = match action {
            CircuitAction::RunCmd { leg, cmd } => Some(RunOnceCmd::Single(
                RunOnceCmdInner::from_circuit_cmd(leg, cmd),
            )),
            CircuitAction::HandleControl(ctrl) => ControlHandler::new(self)
                .handle_msg(ctrl)?
                .map(RunOnceCmd::Single),
            CircuitAction::HandleCell { leg, cell } => {
                let circ = self
                    .circuits
                    .leg_mut(LegId(leg))
                    .ok_or_else(|| internal!("the circuit leg we just had disappeared?!"))?;

                let circ_cmds = circ.handle_cell(&mut self.cell_handlers, leg.into(), cell)?;
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
            CircuitAction::RemoveLeg { leg, reason } => Some(
                RunOnceCmdInner::RemoveLeg {
                    leg: LegId(leg),
                    reason,
                }
                .into(),
            ),
        };

        if let Some(cmd) = cmd {
            self.handle_run_once_cmd(cmd).await?;
        }

        Ok(())
    }

    /// Try to process the previously-out-of-order messages we might have buffered.
    #[cfg(feature = "conflux")]
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
                    RunOnceCmd::Single(RunOnceCmdInner::from_circuit_cmd(entry.leg_id.0, cmd))
                });

            if let Some(cmd) = cmd {
                self.handle_run_once_cmd(cmd).await?;
            }
        }

        Ok(())
    }

    /// Handle a [`RunOnceCmd`].
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
                        let cell_hop = cell.hop;
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
                let result = (move || {
                    // this is needed to force the closure to be FnOnce rather than FnMut :(
                    let self_ = self;
                    let (leg_id, hop_num) = self_
                        .resolve_hop_location(hop)
                        .map_err(into_bad_api_usage!("Could not resolve {hop:?}"))?;
                    let leg = self_
                        .circuits
                        .leg_mut(leg_id)
                        .ok_or(bad_api_usage!("No leg for id {:?}", leg_id))?;
                    Ok::<_, Bug>((leg, hop_num))
                })();

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

                let res: Result<()> = leg.close_stream(hop_num, sid, behav, reason).await;

                if let Some(done) = done {
                    // don't care if the sender goes away
                    let _ = done.send(res);
                }
            }
            RunOnceCmdInner::HandleSendMe { leg, hop, sendme } => {
                let leg = self
                    .circuits
                    .leg_mut(leg)
                    .ok_or_else(|| internal!("leg disappeared?!"))?;
                // NOTE: it's okay to await. We are only awaiting on the congestion_signals
                // future which *should* resolve immediately
                let signals = leg.congestion_signals().await;
                leg.handle_sendme(hop, sendme, signals)?;
            }
            RunOnceCmdInner::FirstHopClockSkew { answer } => {
                let res = self
                    .circuits
                    .single_leg_mut()
                    .map(|(_id, leg)| leg.clock_skew());

                // don't care if the sender goes away
                let _ = answer.send(res.map_err(Into::into));
            }
            RunOnceCmdInner::CleanShutdown => {
                trace!("{}: reactor shutdown due to handled cell", self.unique_id);
                return Err(ReactorError::Shutdown);
            }
            RunOnceCmdInner::RemoveLeg { leg, reason } => {
                warn!("{}: removing circuit leg: {reason}", self.unique_id);

                let circ = self.circuits.remove(leg.0)?;
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
                            "{}: Malformed conflux handshake, tearing down tunnel",
                            self.unique_id
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
        }

        Ok(())
    }

    /// Wait for a [`CtrlMsg::Create`] to come along to set up the circuit.
    ///
    /// Returns an error if an unexpected `CtrlMsg` is received.
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
                        let (_id, leg) = self.circuits.single_leg_mut()?;
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
                let (_id, leg) = self.circuits.single_leg_mut()?;
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
                "{}: conflux tunnel ready ({success_count}/{leg_count} circuits successfully linked)",
                self.unique_id
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
                Ok::<_, crate::Error>(SendRelayCell {
                    hop: handler.expected_hop(),
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
            "{}: reactor shutdown due to explicit request",
            self.unique_id
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
        let _ = answer.send(self.circuits.take_single_leg().map_err(Into::into));
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
                if let Ok((leg_id, leg)) = self.circuits.single_leg() {
                    // single-path tunnel
                    let hop = leg.last_hop_num().ok_or(NoHopsBuiltError)?;
                    Ok(HopLocation::Hop((leg_id, hop)))
                } else if !self.circuits.is_empty() {
                    // multi-path tunnel
                    return Ok(HopLocation::JoinPoint);
                } else {
                    // no legs
                    Err(NoHopsBuiltError)
                }
            }
        }
    }

    /// Resolves a [`HopLocation`] to a [`LegId`] and [`HopNum`].
    ///
    /// After resolving a `HopLocation::JoinPoint`,
    /// the [`LegId`] and [`HopNum`] can become stale if the primary leg changes.
    ///
    /// You should try to only resolve to a specific [`LegId`] and [`HopNum`] immediately before you
    /// need them,
    /// and you should not hold on to the resolved [`LegId`] and [`HopNum`] between reactor
    /// iterations as the primary leg may change from one iteration to the next.
    ///
    /// Returns [`NoJoinPointError`] if trying to resolve `HopLocation::JoinPoint`
    /// but it does not have a join point.
    fn resolve_hop_location(
        &self,
        hop: HopLocation,
    ) -> StdResult<(LegId, HopNum), NoJoinPointError> {
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

    /// Does congestion control use stream SENDMEs for the given hop?
    ///
    /// Returns `None` if either the `leg` or `hop` don't exist.
    fn uses_stream_sendme(&self, leg: LegId, hop: HopNum) -> Option<bool> {
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

            // TODO(conflux): check if we negotiated prop324 cc on *all* circuits,
            // returning an error if not?

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
    // Tested in [`crate::tunnel::circuit::test`].
}
