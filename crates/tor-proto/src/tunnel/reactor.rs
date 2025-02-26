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

mod conflux;
mod control;
mod create;
mod extender;
pub(super) mod syncview;

use super::handshake::RelayCryptLayerProtocol;
use crate::congestion::sendme::{self, CircTag};
use crate::congestion::{CongestionControl, CongestionSignals};
use crate::crypto::binding::CircuitBinding;
use crate::crypto::cell::{
    HopNum, InboundClientCrypt, InboundClientLayer, OutboundClientCrypt, OutboundClientLayer,
    RelayCellBody, SENDME_TAG_LEN,
};
use crate::crypto::handshake::fast::CreateFastClient;
#[cfg(feature = "ntor_v3")]
use crate::crypto::handshake::ntor_v3::{NtorV3Client, NtorV3PublicKey};
use crate::memquota::{CircuitAccount, SpecificAccount as _, StreamAccount};
use crate::stream::{AnyCmdChecker, StreamStatus};
use crate::tunnel::circuit::celltypes::{ClientCircChanMsg, CreateResponse};
use crate::tunnel::circuit::handshake::{BoxedClientLayer, HandshakeRole};
use crate::tunnel::circuit::unique_id::UniqId;
use crate::tunnel::circuit::MutableState;
use crate::tunnel::circuit::{CircParameters, CircuitRxReceiver};
use crate::tunnel::streammap::{
    self, EndSentStreamEnt, OpenStreamEnt, ShouldSendEnd, StreamEntMut,
};
use crate::util::err::ReactorError;
use crate::util::skew::ClockSkew;
use crate::util::sometimes_unbounded_sink::SometimesUnboundedSink;
use crate::util::SinkExt as _;
use crate::{Error, Result};
use conflux::ConfluxSet;
use control::ControlHandler;
use futures::stream::FuturesUnordered;
use std::borrow::Borrow;
use std::mem::size_of;
use std::pin::Pin;
use tor_cell::chancell::msg::{AnyChanMsg, HandshakeType, Relay};
use tor_cell::relaycell::msg::{AnyRelayMsg, End, Sendme, Truncated};
use tor_cell::relaycell::{
    AnyRelayMsgOuter, RelayCellDecoder, RelayCellDecoderResult, RelayCellFormat, RelayCmd,
    StreamId, UnparsedRelayMsg,
};
use tor_error::{internal, Bug};
#[cfg(feature = "hs-service")]
use {
    crate::stream::{DataCmdChecker, IncomingStreamRequest, IncomingStreamRequestFilter},
    tor_cell::relaycell::msg::Begin,
};

use futures::channel::mpsc;
use futures::StreamExt;
use futures::{select_biased, FutureExt as _, SinkExt as _, Stream};
use oneshot_fused_workaround as oneshot;

use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use crate::channel::{Channel, ChannelSender};
use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
use crate::crypto::handshake::{ClientHandshake, KeyGenerator};
use crate::tunnel::circuit::path;
use crate::tunnel::circuit::{StreamMpscReceiver, StreamMpscSender};
use derive_deftly::Deftly;
use derive_more::From;
use safelog::sensitive as sv;
use tor_async_utils::{SinkPrepareExt as _, SinkTrySend as _, SinkTrySendError as _};
use tor_cell::chancell::{AnyChanCell, CircId};
use tor_cell::chancell::{BoxedCellBody, ChanMsg};
use tor_linkspec::RelayIds;
use tor_llcrypto::pk;
use tor_memquota::derive_deftly_template_HasMemoryCost;
use tor_memquota::mq_queue::{self, ChannelSpec as _, MpscSpec};
use tracing::{debug, trace, warn};

use create::{Create2Wrap, CreateFastWrap, CreateHandshakeWrap};
use extender::HandshakeAuxDataHandler;

pub(super) use control::CtrlCmd;
pub(super) use control::CtrlMsg;

/// Initial value for outbound flow-control window on streams.
pub(super) const SEND_WINDOW_INIT: u16 = 500;
/// Initial value for inbound flow-control window on streams.
pub(super) const RECV_WINDOW_INIT: u16 = 500;
/// Size of the buffer used between the reactor and a `StreamReader`.
///
/// FIXME(eta): We pick 2× the receive window, which is very conservative (we arguably shouldn't
///             get sent more than the receive window anyway!). We might do due to things that
///             don't count towards the window though.
pub(super) const STREAM_READER_BUFFER: usize = (2 * RECV_WINDOW_INIT) as usize;

/// The type of a oneshot channel used to inform reactor users of the result of an operation.
pub(super) type ReactorResultChannel<T> = oneshot::Sender<Result<T>>;

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
    #[cfg(feature = "ntor_v3")]
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

/// Represents the reactor's view of a single hop.
pub(super) struct CircHop {
    /// Reactor unique ID. Used for logging.
    unique_id: UniqId,
    /// Hop number in the path.
    hop_num: HopNum,
    /// Map from stream IDs to streams.
    ///
    /// We store this with the reactor instead of the circuit, since the
    /// reactor needs it for every incoming cell on a stream, whereas
    /// the circuit only needs it when allocating new streams.
    ///
    /// NOTE: this is behind a mutex because the reactor polls the `StreamMap`s
    /// of all hops concurrently, in a [`FuturesUnordered`]. Without the mutex,
    /// this wouldn't be possible, because it would mean holding multiple
    /// mutable references to `self` (the reactor). Note, however,
    /// that there should never be any contention on this mutex:
    /// we never create more than one [`Circuit::ready_streams_iterator`] stream
    /// at a time, and we never clone/lock the hop's `StreamMap` outside of
    /// [`Circuit::ready_streams_iterator`].
    ///
    // TODO: encapsulate the Vec<CircHop> into a separate CircHops structure,
    // and hide its internals from the Reactor. The CircHops implementation
    // should enforce the invariant described in the note above.
    map: Arc<Mutex<streammap::StreamMap>>,
    /// Congestion control object.
    ///
    /// This object is also in charge of handling circuit level SENDME logic for this hop.
    ccontrol: CongestionControl,
    /// Decodes relay cells received from this hop.
    inbound: RelayCellDecoder,
}

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
        /// Oneshot channel to notify on completion, with the allocated stream ID.
        done: ReactorResultChannel<StreamId>,
    },
    /// Close the specified stream.
    CloseStream {
        /// The hop number.
        hop_num: HopNum,
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
    /// Perform a clean shutdown on this circuit.
    CleanShutdown,
}

// Cmd for sending a relay cell.
//
// The contents of this struct are passed to `send_relay_cell`
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

/// A [`RunOnceCmdInner`] command to execute at the end of [`Reactor::run_once`].
#[derive(From, Debug)]
enum SelectResult {
    /// Run a single `RunOnceCmdInner` command.
    Single(RunOnceCmdInner),
    /// Handle a control message
    HandleControl(CtrlMsg),
    /// Handle an input message.
    HandleCell(ClientCircChanMsg),
}

impl CircHop {
    /// Create a new hop.
    pub(super) fn new(
        unique_id: UniqId,
        hop_num: HopNum,
        format: RelayCellFormat,
        params: &CircParameters,
    ) -> Self {
        CircHop {
            unique_id,
            hop_num,
            map: Arc::new(Mutex::new(streammap::StreamMap::new())),
            ccontrol: CongestionControl::new(&params.ccontrol),
            inbound: RelayCellDecoder::new(format),
        }
    }

    /// Start a stream. Creates an entry in the stream map with the given channels, and sends the
    /// `message` to the provided hop.
    fn begin_stream(
        &mut self,
        message: AnyRelayMsg,
        sender: StreamMpscSender<UnparsedRelayMsg>,
        rx: StreamMpscReceiver<AnyRelayMsg>,
        cmd_checker: AnyCmdChecker,
    ) -> Result<(SendRelayCell, StreamId)> {
        let send_window = sendme::StreamSendWindow::new(SEND_WINDOW_INIT);
        let r = self.map.lock().expect("lock poisoned").add_ent(
            sender,
            rx,
            send_window,
            cmd_checker,
        )?;
        let cell = AnyRelayMsgOuter::new(Some(r), message);
        Ok((
            SendRelayCell {
                hop: self.hop_num,
                early: false,
                cell,
            },
            r,
        ))
    }

    /// Close the stream associated with `id` because the stream was
    /// dropped.
    ///
    /// If we have not already received an END cell on this stream, send one.
    /// If no END cell is specified, an END cell with the reason byte set to
    /// REASON_MISC will be sent.
    fn close_stream(
        &mut self,
        id: StreamId,
        message: CloseStreamBehavior,
        why: streammap::TerminateReason,
    ) -> Result<Option<SendRelayCell>> {
        let should_send_end = self.map.lock().expect("lock poisoned").terminate(id, why)?;
        trace!(
            "{}: Ending stream {}; should_send_end={:?}",
            self.unique_id,
            id,
            should_send_end
        );
        // TODO: I am about 80% sure that we only send an END cell if
        // we didn't already get an END cell.  But I should double-check!
        if let (ShouldSendEnd::Send, CloseStreamBehavior::SendEnd(end_message)) =
            (should_send_end, message)
        {
            let end_cell = AnyRelayMsgOuter::new(Some(id), end_message.into());
            let cell = SendRelayCell {
                hop: self.hop_num,
                early: false,
                cell: end_cell,
            };

            return Ok(Some(cell));
        }
        Ok(None)
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
pub(super) enum MetaCellDisposition {
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
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegId(pub(crate) LegIdKey);

slotmap_careful::new_key_type! {
    /// A key type for the circuit leg slotmap
    ///
    /// See [`LegId`].
    pub(crate) struct LegIdKey;
}

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
    //
    // TODO(conflux): add a control command for adding a circuit leg,
    // and update these docs to explain how legs are added
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
}

/// Cell handlers, shared between the Reactor and its underlying `Circuit`s.
struct CellHandlers {
    /// A handler for a meta cell, together with a result channel to notify on completion.
    meta_handler: Option<Box<dyn MetaCellHandler + Send>>,
    /// A handler for incoming stream requests.
    #[cfg(feature = "hs-service")]
    incoming_stream_req_handler: Option<IncomingStreamRequestHandler>,
}

/// A circuit "leg" from a tunnel.
///
/// Regular (non-multipath) circuits have a single leg.
/// Conflux (multipath) circuits have `N` (usually, `N = 2`).
pub(crate) struct Circuit {
    /// The channel this circuit is attached to.
    channel: Arc<Channel>,
    /// Sender object used to actually send cells.
    ///
    /// NOTE: Control messages could potentially add unboundedly to this, although that's
    ///       not likely to happen (and isn't triggereable from the network, either).
    chan_sender: SometimesUnboundedSink<AnyChanCell, ChannelSender>,
    /// Input stream, on which we receive ChanMsg objects from this circuit's
    /// channel.
    // TODO: could use a SPSC channel here instead.
    input: CircuitRxReceiver,
    /// The cryptographic state for this circuit for inbound cells.
    /// This object is divided into multiple layers, each of which is
    /// shared with one hop of the circuit.
    crypto_in: InboundClientCrypt,
    /// The cryptographic state for this circuit for outbound cells.
    crypto_out: OutboundClientCrypt,
    /// List of hops state objects used by the reactor
    hops: Vec<CircHop>,
    /// Mutable information about this circuit, shared with
    /// [`ClientCirc`](super::ClientCirc).
    ///
    // TODO(conflux)/TODO(#1840): this belongs in the Reactor
    mutable: Arc<Mutex<MutableState>>,
    /// This circuit's identifier on the upstream channel.
    channel_id: CircId,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// Memory quota account
    #[allow(dead_code)] // Partly here to keep it alive as long as the circuit
    memquota: CircuitAccount,
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
        memquota: CircuitAccount,
    ) -> (
        Self,
        mpsc::UnboundedSender<CtrlMsg>,
        mpsc::UnboundedSender<CtrlCmd>,
        oneshot::Receiver<void::Void>,
        Arc<Mutex<MutableState>>,
    ) {
        let crypto_out = OutboundClientCrypt::new();
        let (control_tx, control_rx) = mpsc::unbounded();
        let (command_tx, command_rx) = mpsc::unbounded();
        let mutable = Arc::new(Mutex::new(MutableState::default()));

        let (reactor_closed_tx, reactor_closed_rx) = oneshot::channel();

        let chan_sender = SometimesUnboundedSink::new(channel.sender());

        let cell_handlers = CellHandlers {
            meta_handler: None,
            #[cfg(feature = "hs-service")]
            incoming_stream_req_handler: None,
        };

        let circuit_leg = Circuit {
            channel,
            chan_sender,
            input,
            crypto_in: InboundClientCrypt::new(),
            hops: vec![],
            unique_id,
            channel_id,
            crypto_out,
            mutable: mutable.clone(),
            memquota,
        };

        let reactor = Reactor {
            circuits: ConfluxSet::new(circuit_leg),
            control: control_rx,
            command: command_rx,
            reactor_closed_tx,
            unique_id,
            cell_handlers,
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
        if self.circuits.single_leg().is_ok_and(|c| c.hops.is_empty()) {
            self.wait_for_create().await?;

            return Ok(());
        }

        // TODO(conflux): support adding and linking circuits
        // TODO(conflux): support switching the primary leg

        // TODO(conflux): read from *all* the circuits, not just the primary
        //
        // Note: this is a big TODO, and will likely involve factoring out the
        // chan_sender.prepare_send_from() call into a function on Circuit.
        // Each Circuit will have its own control channel, for handling control
        // messages meant for it (I imagine some/all CtrlMsgs will have a LegId
        // field, and that the reactor will redirect the CtrlMsg to the appropriate
        // Circuit's control channel?). Putting the control channel (which will
        // probably receive a CtrlMsgInner type) inside the Circuit should enable
        // us to lift the prepare_send_from() into a Circuit function, that will
        // get called from ConfluxSet::poll_all_name_tbd() that can be used in
        // this select_biased! to select between the channel readiness of *all*
        // underlying circuits.
        let primary_leg = self.circuits.primary_leg()?;
        let mut ready_streams = primary_leg.ready_streams_iterator();

        // Note: We don't actually use the returned SinkSendable,
        // and continue writing to the SometimesUboundedSink :(
        let (cmd, _sendable) = select_biased! {
                res = self.command.next() => {
                    let cmd = unwrap_or_shutdown!(self, res, "command channel drop")?;
                    return ControlHandler::new(self).handle_cmd(cmd);
                },
                res = primary_leg.chan_sender
                    .prepare_send_from(async {
                        select_biased! {
                            // Check whether we've got a control message pending.
                            ret = self.control.next() => {
                                let msg = unwrap_or_shutdown!(self, ret, "control drop")?;
                                Ok::<_, ReactorError>(Some(SelectResult::HandleControl(msg)))
                            },
                            // Check whether we've got an input message pending.
                            ret = primary_leg.input.next().fuse() => {
                                let cell = unwrap_or_shutdown!(self, ret, "input drop")?;
                                Ok(Some(SelectResult::HandleCell(cell)))
                            },
                            ret = ready_streams.next().fuse() => {
                                match ret {
                                    Some(cmd) => {
                                        let cmd = cmd?;
                                        Ok(Some(SelectResult::Single(cmd)))
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
                    }) => res?,
        };
        let cmd = cmd?;

        let cmd = match cmd {
            None => None,
            Some(SelectResult::Single(cmd)) => Some(RunOnceCmd::Single(cmd)),
            Some(SelectResult::HandleControl(ctrl)) => ControlHandler::new(self)
                .handle_msg(ctrl)?
                .map(RunOnceCmd::Single),
            Some(SelectResult::HandleCell(cell)) => {
                // TODO(conflux): put the LegId of the circuit the cell was received on
                // inside HandleCell
                //let circ = self.circuits.leg(leg_id)?;

                let circ = self.circuits.primary_leg()?;
                circ.handle_cell(&mut self.cell_handlers, cell)?
            }
        };

        if let Some(cmd) = cmd {
            self.handle_run_once_cmd(cmd).await?;
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
            RunOnceCmdInner::Send { cell, done } => {
                // TODO: check the cc window

                // TODO(conflux): let the RunOnceCmdInner specify which leg to send the cell on
                let res = self.circuits.primary_leg()?.send_relay_cell(cell).await;
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
                        let outcome = self.circuits.primary_leg()?.send_relay_cell(cell).await;
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
            // TODO(conflux)/TODO(#1857): should this take a leg_id argument?
            // Currently, we always begin streams on the primary leg
            RunOnceCmdInner::BeginStream { cell, done } => {
                match cell {
                    Ok((cell, stream_id)) => {
                        // TODO(conflux): let the RunOnceCmdInner specify which leg to send the cell on
                        // (currently it is an error to use BeginStream on a multipath tunnel)
                        let outcome = self.circuits.single_leg()?.send_relay_cell(cell).await;
                        // don't care if receiver goes away.
                        let _ = done.send(outcome.clone().map(|_| stream_id));
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
                hop_num,
                sid,
                behav,
                reason,
                done,
            } => {
                // TODO(conflux): currently, it is an error to use CloseStream
                // with a multi-path circuit.
                let leg = self.circuits.single_leg()?;
                let res: Result<()> = leg.close_stream(hop_num, sid, behav, reason).await;

                if let Some(done) = done {
                    // don't care if the sender goes away
                    let _ = done.send(res);
                }
            }
            RunOnceCmdInner::HandleSendMe { hop, sendme } => {
                // TODO(conflux): this should specify which leg of the circuit the SENDME
                // came on
                let leg = self.circuits.single_leg()?;
                // NOTE: it's okay to await. We are only awaiting on the congestion_signals
                // future which *should* resolve immediately
                let signals = leg.congestion_signals().await;
                leg.handle_sendme(hop, sendme, signals)?;
            }
            RunOnceCmdInner::FirstHopClockSkew { answer } => {
                let res = self
                    .circuits
                    .single_leg()
                    .map(|leg| leg.channel.clock_skew());

                // don't care if the sender goes away
                let _ = answer.send(res);
            }
            RunOnceCmdInner::CleanShutdown => {
                trace!("{}: reactor shutdown due to handled cell", self.unique_id);
                return Err(ReactorError::Shutdown);
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
                        params,
                        done,
                    } => {
                        self.circuits.single_leg()?.handle_add_fake_hop(format, fwd_lasthop, rev_lasthop, &params, done);
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
                params,
                done,
            } => {
                // TODO(conflux): instead of crashing the reactor, it might be better
                // to send the error via the done channel instead
                let legs = self.circuits.single_leg()?;
                legs.handle_create(recv_created, handshake, &params, done)
                    .await
            }
            _ => {
                trace!("reactor shutdown due to unexpected cell: {:?}", msg);

                Err(Error::CircProto(format!("Unexpected {msg:?} cell on client circuit")).into())
            }
        }
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
}

impl Circuit {
    /// Handle a [`CtrlMsg::AddFakeHop`] message.
    #[cfg(test)]
    fn handle_add_fake_hop(
        &mut self,
        format: RelayCellFormat,
        fwd_lasthop: bool,
        rev_lasthop: bool,
        params: &CircParameters,
        done: ReactorResultChannel<()>,
    ) {
        use crate::tunnel::circuit::test::DummyCrypto;

        let dummy_peer_id = tor_linkspec::OwnedChanTarget::builder()
            .ed_identity([4; 32].into())
            .rsa_identity([5; 20].into())
            .build()
            .expect("Could not construct fake hop");

        let fwd = Box::new(DummyCrypto::new(fwd_lasthop));
        let rev = Box::new(DummyCrypto::new(rev_lasthop));
        let binding = None;
        self.add_hop(
            format,
            path::HopDetail::Relay(dummy_peer_id),
            fwd,
            rev,
            binding,
            params,
        );
        let _ = done.send(Ok(()));
    }

    /// Encode `msg` and encrypt it, returning the resulting cell
    /// and tag that should be expected for an authenticated SENDME sent
    /// in response to that cell.
    fn encode_relay_cell(
        crypto_out: &mut OutboundClientCrypt,
        hop: HopNum,
        early: bool,
        msg: AnyRelayMsgOuter,
    ) -> Result<(AnyChanMsg, &[u8; SENDME_TAG_LEN])> {
        let mut body: RelayCellBody = msg
            .encode(&mut rand::thread_rng())
            .map_err(|e| Error::from_cell_enc(e, "relay cell body"))?
            .into();
        let tag = crypto_out.encrypt(&mut body, hop)?;
        let msg = Relay::from(BoxedCellBody::from(body));
        let msg = if early {
            AnyChanMsg::RelayEarly(msg.into())
        } else {
            AnyChanMsg::Relay(msg)
        };

        Ok((msg, tag))
    }

    /// Encode `msg`, encrypt it, and send it to the 'hop'th hop.
    ///
    /// If there is insufficient outgoing *circuit-level* or *stream-level*
    /// SENDME window, an error is returned instead.
    ///
    /// Does not check whether the cell is well-formed or reasonable.
    async fn send_relay_cell(&mut self, msg: SendRelayCell) -> Result<()> {
        let SendRelayCell {
            hop,
            early,
            cell: msg,
        } = msg;

        let c_t_w = sendme::cmd_counts_towards_windows(msg.cmd());
        let stream_id = msg.stream_id();
        let hop_num = Into::<usize>::into(hop);
        let circhop = &mut self.hops[hop_num];

        // We need to apply stream-level flow control *before* encoding the message.
        if c_t_w {
            if let Some(stream_id) = stream_id {
                let mut hop_map = circhop.map.lock().expect("lock poisoned");
                let Some(StreamEntMut::Open(ent)) = hop_map.get_mut(stream_id) else {
                    warn!(
                        "{}: sending a relay cell for non-existent or non-open stream with ID {}!",
                        self.unique_id, stream_id
                    );
                    return Err(Error::CircProto(format!(
                        "tried to send a relay cell on non-open stream {}",
                        sv(stream_id),
                    )));
                };
                ent.take_capacity_to_send(msg.msg())?;
            }
        }
        // NOTE(eta): Now that we've encrypted the cell, we *must* either send it or abort
        //            the whole circuit (e.g. by returning an error).
        let (msg, tag) = Self::encode_relay_cell(&mut self.crypto_out, hop, early, msg)?;
        // The cell counted for congestion control, inform our algorithm of such and pass down the
        // tag for authenticated SENDMEs.
        if c_t_w {
            circhop.ccontrol.note_data_sent(tag)?;
        }

        let cell = AnyChanCell::new(Some(self.channel_id), msg);
        Pin::new(&mut self.chan_sender).send_unbounded(cell).await?;

        Ok(())
    }

    /// Helper: process a cell on a channel.  Most cells get ignored
    /// or rejected; a few get delivered to circuits.
    ///
    /// Return `CellStatus::CleanShutdown` if we should exit.
    fn handle_cell(
        &mut self,
        handlers: &mut CellHandlers,
        cell: ClientCircChanMsg,
    ) -> Result<Option<RunOnceCmd>> {
        trace!("{}: handling cell: {:?}", self.unique_id, cell);
        use ClientCircChanMsg::*;
        match cell {
            Relay(r) => self.handle_relay_cell(handlers, r),
            Destroy(d) => {
                let reason = d.reason();
                debug!(
                    "{}: Received DESTROY cell. Reason: {} [{}]",
                    self.unique_id,
                    reason.human_str(),
                    reason
                );

                self.handle_destroy_cell()
                    .map(|c| Some(RunOnceCmd::Single(c)))
            }
        }
    }

    /// Decode `cell`, returning its corresponding hop number, tag,
    /// and decoded body.
    fn decode_relay_cell(
        &mut self,
        cell: Relay,
    ) -> Result<(HopNum, CircTag, RelayCellDecoderResult)> {
        let mut body = cell.into_relay_body().into();

        // Decrypt the cell. If it's recognized, then find the
        // corresponding hop.
        let (hopnum, tag) = self.crypto_in.decrypt(&mut body)?;
        // Make a copy of the authentication tag. TODO: I'd rather not
        // copy it, but I don't see a way around it right now.
        let tag = {
            let mut tag_copy = [0_u8; SENDME_TAG_LEN];
            // TODO(nickm): This could crash if the tag length changes.  We'll
            // have to refactor it then.
            tag_copy.copy_from_slice(tag);
            tag_copy
        };

        // Decode the cell.
        let decode_res = self
            .hop_mut(hopnum)
            .ok_or_else(|| {
                Error::from(internal!(
                    "Trying to decode cell from nonexistent hop {:?}",
                    hopnum
                ))
            })?
            .inbound
            .decode(body.into())
            .map_err(|e| Error::from_bytes_err(e, "relay cell"))?;

        Ok((hopnum, tag.into(), decode_res))
    }

    /// React to a Relay or RelayEarly cell.
    fn handle_relay_cell(
        &mut self,
        handlers: &mut CellHandlers,
        cell: Relay,
    ) -> Result<Option<RunOnceCmd>> {
        let (hopnum, tag, decode_res) = self.decode_relay_cell(cell)?;

        let c_t_w = decode_res.cmds().any(sendme::cmd_counts_towards_windows);

        // Decrement the circuit sendme windows, and see if we need to
        // send a sendme cell.
        let send_circ_sendme = if c_t_w {
            self.hop_mut(hopnum)
                .ok_or_else(|| Error::CircProto("Sendme from nonexistent hop".into()))?
                .ccontrol
                .note_data_received()?
        } else {
            false
        };

        let mut run_once_cmds = vec![];
        // If we do need to send a circuit-level SENDME cell, do so.
        if send_circ_sendme {
            // This always sends a V1 (tagged) sendme cell, and thereby assumes
            // that SendmeEmitMinVersion is no more than 1.  If the authorities
            // every increase that parameter to a higher number, this will
            // become incorrect.  (Higher numbers are not currently defined.)
            let sendme = Sendme::new_tag(tag.into());
            let cell = AnyRelayMsgOuter::new(None, sendme.into());
            run_once_cmds.push(RunOnceCmdInner::Send {
                cell: SendRelayCell {
                    hop: hopnum,
                    early: false,
                    cell,
                },
                done: None,
            });

            // Inform congestion control of the SENDME we are sending. This is a circuit level one.
            self.hop_mut(hopnum)
                .ok_or_else(|| {
                    Error::from(internal!(
                        "Trying to send SENDME to nonexistent hop {:?}",
                        hopnum
                    ))
                })?
                .ccontrol
                .note_sendme_sent()?;
        }

        let (mut msgs, incomplete) = decode_res.into_parts();
        while let Some(msg) = msgs.next() {
            let msg_status = self.handle_relay_msg(handlers, hopnum, c_t_w, msg)?;

            match msg_status {
                None => continue,
                Some(msg @ RunOnceCmdInner::CleanShutdown) => {
                    for m in msgs {
                        debug!(
                            "{id}: Ignoring relay msg received after triggering shutdown: {m:?}",
                            id = self.unique_id
                        );
                    }
                    if let Some(incomplete) = incomplete {
                        debug!(
                            "{id}: Ignoring partial relay msg received after triggering shutdown: {:?}",
                            incomplete,
                            id=self.unique_id,
                        );
                    }
                    run_once_cmds.push(msg);
                    return Ok(Some(RunOnceCmd::Multiple(run_once_cmds)));
                }
                Some(msg) => {
                    run_once_cmds.push(msg);
                }
            }
        }

        Ok(Some(RunOnceCmd::Multiple(run_once_cmds)))
    }

    /// Handle a single incoming relay message.
    fn handle_relay_msg(
        &mut self,
        handlers: &mut CellHandlers,
        hopnum: HopNum,
        cell_counts_toward_windows: bool,
        msg: UnparsedRelayMsg,
    ) -> Result<Option<RunOnceCmdInner>> {
        // If this msg wants/refuses to have a Stream ID, does it
        // have/not have one?
        let streamid = msg_streamid(&msg)?;

        // If this doesn't have a StreamId, it's a meta cell,
        // not meant for a particular stream.
        let Some(streamid) = streamid else {
            return self.handle_meta_cell(handlers, hopnum, msg);
        };

        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::CircProto("Cell from nonexistent hop!".into()))?;
        let mut hop_map = hop.map.lock().expect("lock poisoned");
        match hop_map.get_mut(streamid) {
            Some(StreamEntMut::Open(ent)) => {
                let message_closes_stream =
                    Self::deliver_msg_to_stream(streamid, ent, cell_counts_toward_windows, msg)?;

                if message_closes_stream {
                    hop_map.ending_msg_received(streamid)?;
                }
            }
            #[cfg(feature = "hs-service")]
            Some(StreamEntMut::EndSent(_))
                if matches!(
                    msg.cmd(),
                    RelayCmd::BEGIN | RelayCmd::BEGIN_DIR | RelayCmd::RESOLVE
                ) =>
            {
                // If the other side is sending us a BEGIN but hasn't yet acknowledged our END
                // message, just remove the old stream from the map and stop waiting for a
                // response
                hop_map.ending_msg_received(streamid)?;
                drop(hop_map);
                return self.handle_incoming_stream_request(handlers, msg, streamid, hopnum);
            }
            Some(StreamEntMut::EndSent(EndSentStreamEnt { half_stream, .. })) => {
                // We sent an end but maybe the other side hasn't heard.

                match half_stream.handle_msg(msg)? {
                    StreamStatus::Open => {}
                    StreamStatus::Closed => {
                        hop_map.ending_msg_received(streamid)?;
                    }
                }
            }
            #[cfg(feature = "hs-service")]
            None if matches!(
                msg.cmd(),
                RelayCmd::BEGIN | RelayCmd::BEGIN_DIR | RelayCmd::RESOLVE
            ) =>
            {
                drop(hop_map);
                return self.handle_incoming_stream_request(handlers, msg, streamid, hopnum);
            }
            _ => {
                // No stream wants this message, or ever did.
                return Err(Error::CircProto(
                    "Cell received on nonexistent stream!?".into(),
                ));
            }
        }
        Ok(None)
    }

    /// Deliver `msg` to the specified open stream entry `ent`.
    fn deliver_msg_to_stream(
        streamid: StreamId,
        ent: &mut OpenStreamEnt,
        cell_counts_toward_windows: bool,
        msg: UnparsedRelayMsg,
    ) -> Result<bool> {
        // The stream for this message exists, and is open.

        if msg.cmd() == RelayCmd::SENDME {
            let _sendme = msg
                .decode::<Sendme>()
                .map_err(|e| Error::from_bytes_err(e, "Sendme message on stream"))?
                .into_msg();
            // We need to handle sendmes here, not in the stream's
            // recv() method, or else we'd never notice them if the
            // stream isn't reading.
            ent.put_for_incoming_sendme()?;
            return Ok(false);
        }

        let message_closes_stream = ent.cmd_checker.check_msg(&msg)? == StreamStatus::Closed;

        if let Err(e) = Pin::new(&mut ent.sink).try_send(msg) {
            if e.is_full() {
                // If we get here, we either have a logic bug (!), or an attacker
                // is sending us more cells than we asked for via congestion control.
                return Err(Error::CircProto(format!(
                    "Stream sink would block; received too many cells on stream ID {}",
                    sv(streamid),
                )));
            }
            if e.is_disconnected() && cell_counts_toward_windows {
                // the other side of the stream has gone away; remember
                // that we received a cell that we couldn't queue for it.
                //
                // Later this value will be recorded in a half-stream.
                ent.dropped += 1;
            }
        }

        Ok(message_closes_stream)
    }

    /// A helper for handling incoming stream requests.
    #[cfg(feature = "hs-service")]
    fn handle_incoming_stream_request(
        &mut self,
        handlers: &mut CellHandlers,
        msg: UnparsedRelayMsg,
        stream_id: StreamId,
        hop_num: HopNum,
    ) -> Result<Option<RunOnceCmdInner>> {
        use syncview::ClientCircSyncView;
        use tor_cell::relaycell::msg::EndReason;
        use tor_error::into_internal;
        use tor_log_ratelim::log_ratelim;

        // We need to construct this early so that we don't double-borrow &mut self

        let Some(handler) = handlers.incoming_stream_req_handler.as_mut() else {
            return Err(Error::CircProto(
                "Cannot handle BEGIN cells on this circuit".into(),
            ));
        };

        if hop_num != handler.hop_num {
            return Err(Error::CircProto(format!(
                "Expecting incoming streams from {}, but received {} cell from unexpected hop {}",
                handler.hop_num.display(),
                msg.cmd(),
                hop_num.display()
            )));
        }

        let message_closes_stream = handler.cmd_checker.check_msg(&msg)? == StreamStatus::Closed;

        // TODO: we've already looked up the `hop` in handle_relay_cell, so we shouldn't
        // have to look it up again! However, we can't pass the `&mut hop` reference from
        // `handle_relay_cell` to this function, because that makes Rust angry (we'd be
        // borrowing self as mutable more than once).
        //
        // TODO: we _could_ use self.hops.get_mut(..) instead self.hop_mut(..) inside
        // handle_relay_cell to work around the problem described above
        let hop = self
            .hops
            .get_mut(Into::<usize>::into(hop_num))
            .ok_or(Error::CircuitClosed)?;

        if message_closes_stream {
            hop.map
                .lock()
                .expect("lock poisoned")
                .ending_msg_received(stream_id)?;

            return Ok(None);
        }

        let begin = msg
            .decode::<Begin>()
            .map_err(|e| Error::from_bytes_err(e, "Invalid Begin message"))?
            .into_msg();

        let req = IncomingStreamRequest::Begin(begin);

        {
            use crate::stream::IncomingStreamRequestDisposition::*;

            let ctx = crate::stream::IncomingStreamRequestContext { request: &req };
            // IMPORTANT: ClientCircSyncView::n_open_streams() (called via disposition() below)
            // accesses the stream map mutexes!
            //
            // This means it's very important not to call this function while any of the hop's
            // stream map mutex is held.
            let view = ClientCircSyncView::new(&self.hops);

            match handler.filter.as_mut().disposition(&ctx, &view)? {
                Accept => {}
                CloseCircuit => return Ok(Some(RunOnceCmdInner::CleanShutdown)),
                RejectRequest(end) => {
                    let end_msg = AnyRelayMsgOuter::new(Some(stream_id), end.into());
                    let cell = SendRelayCell {
                        hop: hop_num,
                        early: false,
                        cell: end_msg,
                    };
                    return Ok(Some(RunOnceCmdInner::Send { cell, done: None }));
                }
            }
        }

        // TODO: Sadly, we need to look up `&mut hop` yet again,
        // since we needed to pass `&self.hops` by reference to our filter above. :(
        let hop = self
            .hops
            .get_mut(Into::<usize>::into(hop_num))
            .ok_or(Error::CircuitClosed)?;

        let memquota = StreamAccount::new(&self.memquota)?;

        let (sender, receiver) = MpscSpec::new(STREAM_READER_BUFFER).new_mq(
            self.chan_sender.as_inner().time_provider().clone(),
            memquota.as_raw_account(),
        )?;
        let (msg_tx, msg_rx) = MpscSpec::new(super::CIRCUIT_BUFFER_SIZE).new_mq(
            self.chan_sender.as_inner().time_provider().clone(),
            memquota.as_raw_account(),
        )?;

        let send_window = sendme::StreamSendWindow::new(SEND_WINDOW_INIT);
        let cmd_checker = DataCmdChecker::new_connected();
        hop.map.lock().expect("lock poisoned").add_ent_with_id(
            sender,
            msg_rx,
            send_window,
            stream_id,
            cmd_checker,
        )?;

        let outcome = Pin::new(&mut handler.incoming_sender).try_send(StreamReqInfo {
            req,
            stream_id,
            hop_num,
            msg_tx,
            receiver,
            memquota,
        });

        log_ratelim!("Delivering message to incoming stream handler"; outcome);

        if let Err(e) = outcome {
            if e.is_full() {
                // The IncomingStreamRequestHandler's stream is full; it isn't
                // handling requests fast enough. So instead, we reply with an
                // END cell.
                let end_msg = AnyRelayMsgOuter::new(
                    Some(stream_id),
                    End::new_with_reason(EndReason::RESOURCELIMIT).into(),
                );

                let cell = SendRelayCell {
                    hop: hop_num,
                    early: false,
                    cell: end_msg,
                };
                return Ok(Some(RunOnceCmdInner::Send { cell, done: None }));
            } else if e.is_disconnected() {
                // The IncomingStreamRequestHandler's stream has been dropped.
                // In the Tor protocol as it stands, this always means that the
                // circuit itself is out-of-use and should be closed. (See notes
                // on `allow_stream_requests.`)
                //
                // Note that we will _not_ reach this point immediately after
                // the IncomingStreamRequestHandler is dropped; we won't hit it
                // until we next get an incoming request.  Thus, if we do later
                // want to add early detection for a dropped
                // IncomingStreamRequestHandler, we need to do it elsewhere, in
                // a different way.
                debug!(
                    "{}: Incoming stream request receiver dropped",
                    self.unique_id
                );
                // This will _cause_ the circuit to get closed.
                return Err(Error::CircuitClosed);
            } else {
                // There are no errors like this with the current design of
                // futures::mpsc, but we shouldn't just ignore the possibility
                // that they'll be added later.
                return Err(Error::from((into_internal!(
                    "try_send failed unexpectedly"
                ))(e)));
            }
        }

        Ok(None)
    }

    /// Helper: process a destroy cell.
    #[allow(clippy::unnecessary_wraps)]
    fn handle_destroy_cell(&mut self) -> Result<RunOnceCmdInner> {
        // I think there is nothing more to do here.
        Ok(RunOnceCmdInner::CleanShutdown)
    }

    /// Handle a [`CtrlMsg::Create`] message.
    async fn handle_create(
        &mut self,
        recv_created: oneshot::Receiver<CreateResponse>,
        handshake: CircuitHandshake,
        params: &CircParameters,
        done: ReactorResultChannel<()>,
    ) -> StdResult<(), ReactorError> {
        let ret = match handshake {
            CircuitHandshake::CreateFast => self.create_firsthop_fast(recv_created, params).await,
            CircuitHandshake::Ntor {
                public_key,
                ed_identity,
            } => {
                self.create_firsthop_ntor(recv_created, ed_identity, public_key, params)
                    .await
            }
            #[cfg(feature = "ntor_v3")]
            CircuitHandshake::NtorV3 { public_key } => {
                self.create_firsthop_ntor_v3(recv_created, public_key, params)
                    .await
            }
        };
        let _ = done.send(ret); // don't care if sender goes away

        // TODO: maybe we don't need to flush here?
        // (we could let run_once() handle all the flushing)
        self.chan_sender.flush().await?;

        Ok(())
    }

    /// Helper: create the first hop of a circuit.
    ///
    /// This is parameterized not just on the RNG, but a wrapper object to
    /// build the right kind of create cell, and a handshake object to perform
    /// the cryptographic handshake.
    async fn create_impl<H, W, M>(
        &mut self,
        cell_protocol: RelayCryptLayerProtocol,
        recvcreated: oneshot::Receiver<CreateResponse>,
        wrap: &W,
        key: &H::KeyType,
        params: &CircParameters,
        msg: &M,
    ) -> Result<()>
    where
        H: ClientHandshake + HandshakeAuxDataHandler,
        W: CreateHandshakeWrap,
        H::KeyGen: KeyGenerator,
        M: Borrow<H::ClientAuxData>,
    {
        // We don't need to shut down the circuit on failure here, since this
        // function consumes the PendingClientCirc and only returns
        // a ClientCirc on success.

        let (state, msg) = {
            // done like this because holding the RNG across an await boundary makes the future
            // non-Send
            let mut rng = rand::thread_rng();
            H::client1(&mut rng, key, msg)?
        };
        let create_cell = wrap.to_chanmsg(msg);
        trace!(
            "{}: Extending to hop 1 with {}",
            self.unique_id,
            create_cell.cmd()
        );
        self.send_msg(create_cell).await?;

        let reply = recvcreated
            .await
            .map_err(|_| Error::CircProto("Circuit closed while waiting".into()))?;

        let relay_handshake = wrap.decode_chanmsg(reply)?;
        let (server_msg, keygen) = H::client2(state, relay_handshake)?;

        H::handle_server_aux_data(params, &server_msg)?;

        let relay_cell_format = cell_protocol.relay_cell_format();
        let BoxedClientLayer { fwd, back, binding } =
            cell_protocol.construct_layers(HandshakeRole::Initiator, keygen)?;

        trace!("{}: Handshake complete; circuit created.", self.unique_id);

        let peer_id = self.channel.target().clone();

        self.add_hop(
            relay_cell_format,
            path::HopDetail::Relay(peer_id),
            fwd,
            back,
            binding,
            params,
        );
        Ok(())
    }

    /// Use the (questionable!) CREATE_FAST handshake to connect to the
    /// first hop of this circuit.
    ///
    /// There's no authentication in CREATE_FAST,
    /// so we don't need to know whom we're connecting to: we're just
    /// connecting to whichever relay the channel is for.
    async fn create_firsthop_fast(
        &mut self,
        recvcreated: oneshot::Receiver<CreateResponse>,
        params: &CircParameters,
    ) -> Result<()> {
        // In a CREATE_FAST handshake, we can't negotiate a format other than this.
        let protocol = RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0);
        let wrap = CreateFastWrap;
        self.create_impl::<CreateFastClient, _, _>(protocol, recvcreated, &wrap, &(), params, &())
            .await
    }

    /// Use the ntor handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided keys must match the channel's target,
    /// or the handshake will fail.
    async fn create_firsthop_ntor(
        &mut self,
        recvcreated: oneshot::Receiver<CreateResponse>,
        ed_identity: pk::ed25519::Ed25519Identity,
        pubkey: NtorPublicKey,
        params: &CircParameters,
    ) -> Result<()> {
        // In an ntor handshake, we can't negotiate a format other than this.
        let relay_cell_protocol = RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0);

        // Exit now if we have an Ed25519 or RSA identity mismatch.
        let target = RelayIds::builder()
            .ed_identity(ed_identity)
            .rsa_identity(pubkey.id)
            .build()
            .expect("Unable to build RelayIds");
        self.channel.check_match(&target)?;

        let wrap = Create2Wrap {
            handshake_type: HandshakeType::NTOR,
        };
        self.create_impl::<NtorClient, _, _>(
            relay_cell_protocol,
            recvcreated,
            &wrap,
            &pubkey,
            params,
            &(),
        )
        .await
    }

    /// Use the ntor-v3 handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided key must match the channel's target,
    /// or the handshake will fail.
    #[cfg(feature = "ntor_v3")]
    async fn create_firsthop_ntor_v3(
        &mut self,
        recvcreated: oneshot::Receiver<CreateResponse>,
        pubkey: NtorV3PublicKey,
        params: &CircParameters,
    ) -> Result<()> {
        // Exit now if we have a mismatched key.
        let target = RelayIds::builder()
            .ed_identity(pubkey.id)
            .build()
            .expect("Unable to build RelayIds");
        self.channel.check_match(&target)?;

        // TODO: Add support for negotiating other formats.
        let relay_cell_protocol = RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0);

        // TODO: Set client extensions. e.g. request congestion control
        // if specified in `params`.
        let client_extensions = [];

        let wrap = Create2Wrap {
            handshake_type: HandshakeType::NTOR_V3,
        };

        self.create_impl::<NtorV3Client, _, _>(
            relay_cell_protocol,
            recvcreated,
            &wrap,
            &pubkey,
            params,
            &client_extensions,
        )
        .await
    }

    /// Add a hop to the end of this circuit.
    fn add_hop(
        &mut self,
        format: RelayCellFormat,
        peer_id: path::HopDetail,
        fwd: Box<dyn OutboundClientLayer + 'static + Send>,
        rev: Box<dyn InboundClientLayer + 'static + Send>,
        binding: Option<CircuitBinding>,
        params: &CircParameters,
    ) {
        let hop_num = (self.hops.len() as u8).into();
        let hop = CircHop::new(self.unique_id, hop_num, format, params);
        self.hops.push(hop);
        self.crypto_in.add_layer(rev);
        self.crypto_out.add_layer(fwd);
        let mut mutable = self.mutable.lock().expect("poisoned lock");
        Arc::make_mut(&mut mutable.path).push_hop(peer_id);
        mutable.binding.push(binding);
    }

    /// Handle a RELAY cell on this circuit with stream ID 0.
    fn handle_meta_cell(
        &mut self,
        handlers: &mut CellHandlers,
        hopnum: HopNum,
        msg: UnparsedRelayMsg,
    ) -> Result<Option<RunOnceCmdInner>> {
        // SENDME cells and TRUNCATED get handled internally by the circuit.

        // TODO: This pattern (Check command, try to decode, map error) occurs
        // several times, and would be good to extract simplify. Such
        // simplification is obstructed by a couple of factors: First, that
        // there is not currently a good way to get the RelayCmd from _type_ of
        // a RelayMsg.  Second, that decode() [correctly] consumes the
        // UnparsedRelayMsg.  I tried a macro-based approach, and didn't care
        // for it. -nickm
        if msg.cmd() == RelayCmd::SENDME {
            let sendme = msg
                .decode::<Sendme>()
                .map_err(|e| Error::from_bytes_err(e, "sendme message"))?
                .into_msg();

            return Ok(Some(RunOnceCmdInner::HandleSendMe {
                hop: hopnum,
                sendme,
            }));
        }
        if msg.cmd() == RelayCmd::TRUNCATED {
            let truncated = msg
                .decode::<Truncated>()
                .map_err(|e| Error::from_bytes_err(e, "truncated message"))?
                .into_msg();
            let reason = truncated.reason();
            debug!(
                "{}: Truncated from hop {}. Reason: {} [{}]",
                self.unique_id,
                hopnum.display(),
                reason.human_str(),
                reason
            );

            return Ok(Some(RunOnceCmdInner::CleanShutdown));
        }

        trace!("{}: Received meta-cell {:?}", self.unique_id, msg);

        // For all other command types, we'll only get them in response
        // to another command, which should have registered a responder.
        //
        // TODO: that means that service-introduction circuits will need
        // a different implementation, but that should be okay. We'll work
        // something out.
        if let Some(mut handler) = handlers.meta_handler.take() {
            if handler.expected_hop() == hopnum {
                // Somebody was waiting for a message -- maybe this message
                let ret = handler.handle_msg(msg, self);
                trace!(
                    "{}: meta handler completed with result: {:?}",
                    self.unique_id,
                    ret
                );
                match ret {
                    #[cfg(feature = "send-control-msg")]
                    Ok(MetaCellDisposition::Consumed) => {
                        handlers.meta_handler = Some(handler);
                        Ok(None)
                    }
                    Ok(MetaCellDisposition::ConversationFinished) => Ok(None),
                    #[cfg(feature = "send-control-msg")]
                    Ok(MetaCellDisposition::CloseCirc) => Ok(Some(RunOnceCmdInner::CleanShutdown)),
                    Err(e) => Err(e),
                }
            } else {
                // Somebody wanted a message from a different hop!  Put this
                // one back.
                handlers.meta_handler = Some(handler);
                Err(Error::CircProto(format!(
                    "Unexpected {} cell from hop {} on client circuit",
                    msg.cmd(),
                    hopnum.display(),
                )))
            }
        } else {
            // No need to call shutdown here, since this error will
            // propagate to the reactor shut it down.
            Err(Error::CircProto(format!(
                "Unexpected {} cell on client circuit",
                msg.cmd()
            )))
        }
    }

    /// Handle a RELAY_SENDME cell on this circuit with stream ID 0.
    fn handle_sendme(
        &mut self,
        hopnum: HopNum,
        msg: Sendme,
        signals: CongestionSignals,
    ) -> Result<Option<RunOnceCmdInner>> {
        // No need to call "shutdown" on errors in this function;
        // it's called from the reactor task and errors will propagate there.
        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::CircProto(format!("Couldn't find hop {}", hopnum.display())))?;

        let tag = match msg.into_tag() {
            Some(v) => CircTag::try_from(v.as_slice())
                .map_err(|_| Error::CircProto("malformed tag on circuit sendme".into()))?,
            None => {
                // Versions of Tor <=0.3.5 would omit a SENDME tag in this case;
                // but we don't support those any longer.
                return Err(Error::CircProto("missing tag on circuit sendme".into()));
            }
        };
        // Update the CC object that we received a SENDME along with possible congestion signals.
        hop.ccontrol.note_sendme_received(tag, signals)?;
        Ok(None)
    }

    /// Send a message onto the circuit's channel.
    ///
    /// If the channel is ready to accept messages, it will be sent immediately. If not, the message
    /// will be enqueued for sending at a later iteration of the reactor loop.
    ///
    /// # Note
    ///
    /// Making use of the enqueuing capabilities of this function is discouraged! You should first
    /// check whether the channel is ready to receive messages (`self.channel.poll_ready`), and
    /// ideally use this to implement backpressure (such that you do not read from other sources
    /// that would send here while you know you're unable to forward the messages on).
    async fn send_msg(&mut self, msg: AnyChanMsg) -> Result<()> {
        let cell = AnyChanCell::new(Some(self.channel_id), msg);
        // Note: this future is always `Ready`, so await won't block.
        Pin::new(&mut self.chan_sender).send_unbounded(cell).await?;
        Ok(())
    }

    /// Returns a [`Stream`] of [`RunOnceCmdInner`] to poll from the main loop.
    ///
    /// The iterator contains at most one [`RunOnceCmdInner`] for each hop,
    /// representing the instructions for handling the ready-item, if any,
    /// of its highest priority stream.
    ///
    /// IMPORTANT: this stream locks the stream map mutexes of each `CircHop`!
    /// To avoid contention, never create more than one [`Circuit::ready_streams_iterator`]
    /// stream at a time!
    fn ready_streams_iterator(&self) -> impl Stream<Item = Result<RunOnceCmdInner>> {
        self.hops
            .iter()
            .enumerate()
            .filter_map(|(i, hop)| {
                if !hop.ccontrol.can_send() {
                    // We can't send anything on this hop that counts towards SENDME windows.
                    //
                    // In theory we could send messages that don't count towards
                    // windows (like `RESOLVE`), and process end-of-stream
                    // events (to send an `END`), but it's probably not worth
                    // doing an O(N) iteration over flow-control-ready streams
                    // to see if that's the case.
                    //
                    // This *doesn't* block outgoing flow-control messages (e.g.
                    // SENDME), which are initiated via the control-message
                    // channel, handled above.
                    //
                    // TODO: Consider revisiting. OTOH some extra throttling when circuit-level
                    // congestion control has "bottomed out" might not be so bad, and the
                    // alternatives have complexity and/or performance costs.
                    return None;
                }

                let hop_num = HopNum::from(i as u8);
                let hop_map = Arc::clone(&self.hops[i].map);
                Some(async move {
                    futures::future::poll_fn(move |cx| {
                        // Process an outbound message from the first ready stream on
                        // this hop. The stream map implements round robin scheduling to
                        // ensure fairness across streams.
                        // TODO: Consider looping here to process multiple ready
                        // streams. Need to be careful though to balance that with
                        // continuing to service incoming and control messages.
                        let mut hop_map = hop_map.lock().expect("lock poisoned");
                        let Some((sid, msg)) = hop_map.poll_ready_streams_iter(cx).next() else {
                            // No ready streams for this hop.
                            return Poll::Pending;
                        };

                        if msg.is_none() {
                            return Poll::Ready(Ok(RunOnceCmdInner::CloseStream {
                                hop_num,
                                sid,
                                behav: CloseStreamBehavior::default(),
                                reason: streammap::TerminateReason::StreamTargetClosed,
                                done: None,
                            }));
                        };
                        let msg = hop_map.take_ready_msg(sid).expect("msg disappeared");

                        #[allow(unused)] // unused in non-debug builds
                        let Some(StreamEntMut::Open(s)) = hop_map.get_mut(sid) else {
                            panic!("Stream {sid} disappeared");
                        };

                        debug_assert!(
                            s.can_send(&msg),
                            "Stream {sid} produced a message it can't send: {msg:?}"
                        );

                        let cell = SendRelayCell {
                            hop: hop_num,
                            early: false,
                            cell: AnyRelayMsgOuter::new(Some(sid), msg),
                        };
                        Poll::Ready(Ok(RunOnceCmdInner::Send { cell, done: None }))
                    })
                    .await
                })
            })
            .collect::<FuturesUnordered<_>>()
    }

    /// Return the congestion signals for this reactor. This is used by congestion control module.
    ///
    /// Note: This is only async because we need a Context to check the sink for readiness.
    async fn congestion_signals(&mut self) -> CongestionSignals {
        futures::future::poll_fn(|cx| -> Poll<CongestionSignals> {
            Poll::Ready(CongestionSignals::new(
                self.chan_sender.poll_ready_unpin_bool(cx).unwrap_or(false),
                self.chan_sender.n_queued(),
            ))
        })
        .await
    }

    /// Return the hop corresponding to `hopnum`, if there is one.
    fn hop_mut(&mut self, hopnum: HopNum) -> Option<&mut CircHop> {
        self.hops.get_mut(Into::<usize>::into(hopnum))
    }

    /// Begin a stream with the provided hop in this circuit.
    fn begin_stream(
        &mut self,
        hop_num: HopNum,
        message: AnyRelayMsg,
        sender: StreamMpscSender<UnparsedRelayMsg>,
        rx: StreamMpscReceiver<AnyRelayMsg>,
        cmd_checker: AnyCmdChecker,
    ) -> StdResult<Result<(SendRelayCell, StreamId)>, Bug> {
        let Some(hop) = self.hop_mut(hop_num) else {
            return Err(internal!(
                "{}: Attempting to send a BEGIN cell to an unknown hop {hop_num:?}",
                self.unique_id,
            ));
        };

        Ok(hop.begin_stream(message, sender, rx, cmd_checker))
    }

    /// Close the specified stream
    async fn close_stream(
        &mut self,
        hop_num: HopNum,
        sid: StreamId,
        behav: CloseStreamBehavior,
        reason: streammap::TerminateReason,
    ) -> Result<()> {
        if let Some(hop) = self.hop_mut(hop_num) {
            let res = hop.close_stream(sid, behav, reason)?;
            if let Some(cell) = res {
                self.send_relay_cell(cell).await?;
            }
        }
        Ok(())
    }
}

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

/// Return the stream ID of `msg`, if it has one.
///
/// Returns `Ok(None)` if `msg` is a meta cell.
fn msg_streamid(msg: &UnparsedRelayMsg) -> Result<Option<StreamId>> {
    let cmd = msg.cmd();
    let streamid = msg.stream_id();
    if !cmd.accepts_streamid_val(streamid) {
        return Err(Error::CircProto(format!(
            "Invalid stream ID {} for relay command {}",
            sv(StreamId::get_or_zero(streamid)),
            msg.cmd()
        )));
    }

    Ok(streamid)
}

impl Drop for Circuit {
    fn drop(&mut self) {
        let _ = self.channel.close_circuit(self.channel_id);
    }
}

#[cfg(test)]
mod test {
    // Tested in [`crate::tunnel::circuit::test`].
}
