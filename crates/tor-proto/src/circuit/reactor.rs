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
use super::streammap::{ShouldSendEnd, StreamEnt};
use super::MutableState;
use crate::circuit::celltypes::{ClientCircChanMsg, CreateResponse};
use crate::circuit::unique_id::UniqId;
use crate::circuit::{
    sendme, streammap, CircParameters, Create2Wrap, CreateFastWrap, CreateHandshakeWrap,
};
use crate::crypto::cell::{
    ClientLayer, CryptInit, HopNum, InboundClientCrypt, InboundClientLayer, OutboundClientCrypt,
    OutboundClientLayer, RelayCellBody, Tor1RelayCrypto,
};
use crate::stream::{AnyCmdChecker, StreamStatus};
use crate::util::err::{ChannelClosed, ReactorError};
use crate::{Error, Result};
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::pin::Pin;
use tor_cell::chancell::msg::{AnyChanMsg, Relay};
use tor_cell::relaycell::msg::{AnyRelayMsg, End, Sendme};
use tor_cell::relaycell::{AnyRelayCell, RelayCmd, StreamId, UnparsedRelayCell};

use futures::channel::{mpsc, oneshot};
use futures::Sink;
use futures::Stream;
use tor_error::internal;

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use crate::channel::Channel;
use crate::circuit::path;
#[cfg(test)]
use crate::circuit::sendme::CircTag;
use crate::circuit::sendme::StreamSendWindow;
use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
use crate::crypto::handshake::{ClientHandshake, KeyGenerator};
use safelog::sensitive as sv;
use tor_cell::chancell::{self, BoxedCellBody, ChanMsg};
use tor_cell::chancell::{AnyChanCell, CircId};
use tor_linkspec::{EncodedLinkSpec, OwnedChanTarget, RelayIds};
use tor_llcrypto::pk;
use tracing::{debug, trace, warn};

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

/// A handshake type, to be used when creating circuit hops.
#[derive(Clone, Debug)]
pub(super) enum CircuitHandshake {
    /// Use the CREATE_FAST handshake.
    CreateFast,
    /// Use the ntor handshake.
    Ntor {
        /// The public key of the relay.
        public_key: NtorPublicKey,
        /// The first hop's Ed25519 identity, which is verified against
        /// the identity held in the circuit's channel.
        ed_identity: pk::ed25519::Ed25519Identity,
    },
}

/// A message telling the reactor to do something.
#[derive(educe::Educe)]
#[educe(Debug)]
pub(super) enum CtrlMsg {
    /// Create the first hop of this circuit.
    Create {
        /// A oneshot channel on which we'll receive the creation response.
        recv_created: oneshot::Receiver<CreateResponse>,
        /// The handshake type to use for the first hop.
        handshake: CircuitHandshake,
        /// Whether the hop supports authenticated SENDME cells.
        /// (And therefore, whether we should require them.)
        require_sendme_auth: RequireSendmeAuth,
        /// Other parameters relevant for circuit creation.
        params: CircParameters,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
    },
    /// Extend a circuit by one hop, using the ntor handshake.
    ExtendNtor {
        /// The peer that we're extending to.
        ///
        /// Used to extend our record of the circuit's path.
        peer_id: OwnedChanTarget,
        /// The handshake type to use for this hop.
        public_key: NtorPublicKey,
        /// Information about how to connect to the relay we're extending to.
        linkspecs: Vec<EncodedLinkSpec>,
        /// Whether the hop supports authenticated SENDME cells.
        /// (And therefore, whether we should require them.)
        require_sendme_auth: RequireSendmeAuth,
        /// Other parameters relevant for circuit extension.
        params: CircParameters,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
    },
    /// Extend the circuit by one hop, in response to an out-of-band handshake.
    ///
    /// (This is used for onion services, where the negotiation takes place in
    /// INTRODUCE and RENDEZVOUS messages.)
    #[cfg(feature = "hs-common")]
    ExtendVirtual {
        /// The cryptographic algorithms and keys to use when communicating with
        /// the newly added hop.
        #[educe(Debug(ignore))]
        cell_crypto: (
            Box<dyn OutboundClientLayer + Send>,
            Box<dyn InboundClientLayer + Send>,
        ),
        /// A set of parameters used to configure this hop.
        params: CircParameters,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
    },
    /// Begin a stream with the provided hop in this circuit.
    ///
    /// Allocates a stream ID, and sends the provided message to that hop.
    BeginStream {
        /// The hop number to begin the stream with.
        hop_num: HopNum,
        /// The message to send.
        message: AnyRelayMsg,
        /// A channel to send messages on this stream down.
        ///
        /// This sender shouldn't ever block, because we use congestion control and only send
        /// SENDME cells once we've read enough out of the other end. If it *does* block, we
        /// can assume someone is trying to send us more cells than they should, and abort
        /// the stream.
        sender: mpsc::Sender<UnparsedRelayCell>,
        /// A channel to receive messages to send on this stream from.
        rx: mpsc::Receiver<AnyRelayMsg>,
        /// Oneshot channel to notify on completion, with the allocated stream ID.
        done: ReactorResultChannel<StreamId>,
        /// A `CmdChecker` to keep track of which message types are acceptable.
        cmd_checker: AnyCmdChecker,
    },
    /// Send a given control message on this circuit, and install a control-message handler to
    /// receive responses.
    // TODO hs naming.
    #[cfg(feature = "send-control-msg")]
    SendMsgAndInstallHandler {
        /// The message to send
        msg: AnyRelayCell,
        /// A message handler to install.
        #[educe(Debug(ignore))]
        handler: Box<dyn MetaCellHandler + Send + 'static>,
        /// A sender that we use to tell the caller that the message was sent
        /// and the handler installed.
        sender: oneshot::Sender<Result<()>>,
    },
    /// Send a SENDME cell (used to ask for more data to be sent) on the given stream.
    SendSendme {
        /// The stream ID to send a SENDME for.
        stream_id: StreamId,
        /// The hop number the stream is on.
        hop_num: HopNum,
    },
    /// Shut down the reactor.
    Shutdown,
    /// (tests only) Add a hop to the list of hops on this circuit, with dummy cryptography.
    #[cfg(test)]
    AddFakeHop {
        supports_flowctrl_1: bool,
        fwd_lasthop: bool,
        rev_lasthop: bool,
        params: CircParameters,
        done: ReactorResultChannel<()>,
    },
    /// (tests only) Get the send window and expected tags for a given hop.
    #[cfg(test)]
    QuerySendWindow {
        hop: HopNum,
        done: ReactorResultChannel<(u16, Vec<CircTag>)>,
    },
    /// (tests only) Send a raw relay cell with send_relay_cell().
    #[cfg(test)]
    SendRelayCell {
        hop: HopNum,
        early: bool,
        cell: AnyRelayCell,
    },
}
/// Represents the reactor's view of a single hop.
pub(super) struct CircHop {
    /// Map from stream IDs to streams.
    ///
    /// We store this with the reactor instead of the circuit, since the
    /// reactor needs it for every incoming cell on a stream, whereas
    /// the circuit only needs it when allocating new streams.
    map: streammap::StreamMap,
    /// Window used to say how many cells we can receive.
    recvwindow: sendme::CircRecvWindow,
    /// If true, this hop is using an older link protocol and we
    /// shouldn't expect good authenticated SENDMEs from it.
    auth_sendme_required: RequireSendmeAuth,
    /// Window used to say how many cells we can send.
    sendwindow: sendme::CircSendWindow,
    /// Buffer for messages we can't send to this hop yet due to congestion control.
    ///
    /// Contains the cell to send, and a boolean equivalent to the `early` parameter
    /// in `Reactor::send_relay_cell` (as in, whether to send the cell using `RELAY_EARLY`).
    ///
    /// This shouldn't grow unboundedly: we try and pop things off it first before
    /// doing things that would result in it growing (and stop before growing it
    /// if popping things off it can't be done).
    ///
    /// NOTE: Control messages could potentially add unboundedly to this, although that's
    ///       not likely to happen (and isn't triggereable from the network, either).
    outbound: VecDeque<(bool, AnyRelayCell)>,
}

/// Enumeration to determine whether we require circuit-level SENDME cells to be
/// authenticated.
///
/// (This is an enumeration rather than a boolean to prevent accidental sense
/// inversion.)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum RequireSendmeAuth {
    /// Sendme authentication is expected from this hop, and therefore is
    /// required.
    Yes,
    /// Sendme authentication is not expected from this hop, and therefore not
    /// required.
    No,
}

impl RequireSendmeAuth {
    /// Create an appropriate [`RequireSendmeAuth`] for a given set of relay
    /// subprotocol versions.
    //
    // TODO(nickm): At some point in the future, once there are no 0.3.5 relays
    // on the Tor network, we can safely require authenticated SENDMEs from all
    // relays.
    //
    // At that point, if we have a relay implementation in Rust, it should look
    // at the network parameter `SendmeAcceptMinVersion` when deciding whether
    // to require authenticated SENDMEs.
    pub(super) fn from_protocols(protocols: &tor_protover::Protocols) -> Self {
        if protocols.supports_known_subver(tor_protover::ProtoKind::FlowCtrl, 1) {
            // The relay supports FlowCtrl=1, and therefore will authenticate.
            RequireSendmeAuth::Yes
        } else {
            RequireSendmeAuth::No
        }
    }
}

/// An indicator on what we should do when we receive a cell for a circuit.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum CellStatus {
    /// The circuit should stay open.
    Continue,
    /// Perform a clean shutdown on this circuit.
    CleanShutdown,
}

impl CircHop {
    /// Create a new hop.
    pub(super) fn new(auth_sendme_required: RequireSendmeAuth, initial_window: u16) -> Self {
        CircHop {
            map: streammap::StreamMap::new(),
            recvwindow: sendme::CircRecvWindow::new(1000),
            auth_sendme_required,
            sendwindow: sendme::CircSendWindow::new(initial_window),
            outbound: VecDeque::new(),
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
pub(super) trait MetaCellHandler: Send {
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
        msg: UnparsedRelayCell,
        reactor: &mut Reactor,
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
    //
    // TODO since there are no "install handler" and "uninstall handler" calls,
    // only `send_control_message` which implicitly installs on entry and uninstalls
    // on exit, this should be renamed to `ConversationFinished` or something.
    UninstallHandler,
    /// The message was consumed; the circuit should be closed.
    #[cfg(feature = "send-control-msg")]
    CloseCirc,
    // TODO: Eventually we might want the ability to have multiple handlers
    // installed, and to let them say "not for me, maybe for somebody else?".
    // But right now we don't need that.
}

/// An object that can extend a circuit by one hop, using the `MetaCellHandler` trait.
///
/// Yes, I know having trait bounds on structs is bad, but in this case it's necessary
/// since we want to be able to use `H::KeyType`.
struct CircuitExtender<H, L, FWD, REV>
where
    H: ClientHandshake,
{
    /// The peer that we're extending to.
    ///
    /// Used to extend our record of the circuit's path.
    peer_id: OwnedChanTarget,
    /// Handshake state.
    state: Option<H::StateType>,
    /// Whether the hop supports authenticated SENDME cells.
    /// (And therefore, whether we require them.)
    require_sendme_auth: RequireSendmeAuth,
    /// Parameters used for this extension.
    params: CircParameters,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// The hop we're expecting the EXTENDED2 cell to come back from.
    expected_hop: HopNum,
    /// A oneshot channel that we should inform when we are done with this extend operation.
    operation_finished: Option<oneshot::Sender<Result<()>>>,
    /// `PhantomData` used to make the other type parameters required for a circuit extension
    /// part of the `struct`, instead of having them be provided during a function call.
    ///
    /// This is done this way so we can implement `MetaCellHandler` for this type, which
    /// doesn't include any generic type parameters; we need them to be part of the type
    /// so we know what they are for that `impl` block.
    phantom: PhantomData<(L, FWD, REV)>,
}
impl<H, L, FWD, REV> CircuitExtender<H, L, FWD, REV>
where
    H: ClientHandshake,
    H::KeyGen: KeyGenerator,
    L: CryptInit + ClientLayer<FWD, REV>,
    FWD: OutboundClientLayer + 'static + Send,
    REV: InboundClientLayer + 'static + Send,
{
    /// Start extending a circuit, sending the necessary EXTEND cell and returning a
    /// new `CircuitExtender` to be called when the reply arrives.
    ///
    /// The `handshake_id` is the numeric identifier for what kind of
    /// handshake we're doing.  The `key` is the relay's onion key that
    /// goes along with the handshake, and the `linkspecs` are the
    /// link specifiers to include in the EXTEND cell to tell the
    /// current last hop which relay to connect to.
    #[allow(clippy::too_many_arguments)]
    fn begin(
        cx: &mut Context<'_>,
        peer_id: OwnedChanTarget,
        handshake_id: u16,
        key: &H::KeyType,
        linkspecs: Vec<EncodedLinkSpec>,
        require_sendme_auth: RequireSendmeAuth,
        params: CircParameters,
        reactor: &mut Reactor,
        done: ReactorResultChannel<()>,
    ) -> Result<Self> {
        match (|| {
            let mut rng = rand::thread_rng();
            let unique_id = reactor.unique_id;

            use tor_cell::relaycell::msg::Extend2;
            // Perform the first part of the cryptographic handshake
            let (state, msg) = H::client1(&mut rng, key)?;

            let n_hops = reactor.crypto_out.n_layers();
            let hop = ((n_hops - 1) as u8).into();

            debug!(
                "{}: Extending circuit to hop {} with {:?}",
                unique_id,
                n_hops + 1,
                linkspecs
            );

            let extend_msg = Extend2::new(linkspecs, handshake_id, msg);
            let cell = AnyRelayCell::new(0.into(), extend_msg.into());

            // Send the message to the last hop...
            reactor.send_relay_cell(
                cx, hop, true, // use a RELAY_EARLY cell
                cell,
            )?;
            trace!("{}: waiting for EXTENDED2 cell", unique_id);
            // ... and now we wait for a response.

            Ok::<CircuitExtender<_, _, _, _>, Error>(Self {
                peer_id,
                state: Some(state),
                require_sendme_auth,
                params,
                unique_id,
                expected_hop: hop,
                operation_finished: None,
                phantom: Default::default(),
            })
        })() {
            Ok(mut result) => {
                result.operation_finished = Some(done);
                Ok(result)
            }
            Err(e) => {
                // It's okay if the receiver went away.
                let _ = done.send(Err(e.clone()));
                Err(e)
            }
        }
    }

    /// Perform the work of extending the circuit another hop.
    ///
    /// This is a separate function to simplify the error-handling work of handle_msg().
    fn extend_circuit(
        &mut self,
        msg: UnparsedRelayCell,
        reactor: &mut Reactor,
    ) -> Result<MetaCellDisposition> {
        let msg = msg
            .decode::<tor_cell::relaycell::msg::Extended2>()
            .map_err(|e| Error::from_bytes_err(e, "extended2 message"))?
            .into_msg();

        let relay_handshake = msg.into_body();

        trace!(
            "{}: Received EXTENDED2 cell; completing handshake.",
            self.unique_id
        );
        // Now perform the second part of the handshake, and see if it
        // succeeded.
        let keygen = H::client2(
            self.state
                .take()
                .expect("CircuitExtender::finish() called twice"),
            relay_handshake,
        )?;
        let layer = L::construct(keygen)?;

        debug!("{}: Handshake complete; circuit extended.", self.unique_id);

        // If we get here, it succeeded.  Add a new hop to the circuit.
        let (layer_fwd, layer_back) = layer.split();
        reactor.add_hop(
            path::HopDetail::Relay(self.peer_id.clone()),
            self.require_sendme_auth,
            Box::new(layer_fwd),
            Box::new(layer_back),
            &self.params,
        );
        Ok(MetaCellDisposition::UninstallHandler)
    }
}

impl<H, L, FWD, REV> MetaCellHandler for CircuitExtender<H, L, FWD, REV>
where
    H: ClientHandshake,
    H::StateType: Send,
    H::KeyGen: KeyGenerator,
    L: CryptInit + ClientLayer<FWD, REV> + Send,
    FWD: OutboundClientLayer + 'static + Send,
    REV: InboundClientLayer + 'static + Send,
{
    fn expected_hop(&self) -> HopNum {
        self.expected_hop
    }
    fn handle_msg(
        &mut self,
        msg: UnparsedRelayCell,
        reactor: &mut Reactor,
    ) -> Result<MetaCellDisposition> {
        let status = self.extend_circuit(msg, reactor);

        if let Some(done) = self.operation_finished.take() {
            // ignore it if the receiving channel went away.
            let _ = done.send(status.as_ref().map(|_| ()).map_err(Clone::clone));
            status
        } else {
            Err(Error::from(internal!(
                "Passed two messages to an CircuitExtender!"
            )))
        }
    }
}

/// Object to handle incoming cells and background tasks on a circuit
///
/// This type is returned when you finish a circuit; you need to spawn a
/// new task that calls `run()` on it.
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub struct Reactor {
    /// Receiver for control messages for this reactor, sent by `ClientCirc` objects.
    control: mpsc::UnboundedReceiver<CtrlMsg>,
    /// Buffer for cells we can't send out the channel yet due to it being full.
    ///
    /// We try and dequeue off this first before doing anything else, ensuring that
    /// it cannot grow unboundedly (and if we start having to enqueue things on here after
    /// the channel shows backpressure, we stop pulling from receivers that could send here).
    ///
    /// NOTE: Control messages could potentially add unboundedly to this, although that's
    ///       not likely to happen (and isn't triggereable from the network, either).
    outbound: VecDeque<AnyChanCell>,
    /// The channel this circuit is using to send cells through.
    channel: Channel,
    /// Input stream, on which we receive ChanMsg objects from this circuit's
    /// channel.
    // TODO: could use a SPSC channel here instead.
    input: mpsc::Receiver<ClientCircChanMsg>,
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
    mutable: Arc<Mutex<MutableState>>,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// This circuit's identifier on the upstream channel.
    channel_id: CircId,
    /// A handler for a meta cell, together with a result channel to notify on completion.
    meta_handler: Option<Box<dyn MetaCellHandler>>,
}

impl Reactor {
    /// Create a new circuit reactor.
    ///
    /// The reactor will send outbound messages on `channel`, receive incoming
    /// messages on `input`, and identify this circuit by the channel-local
    /// [`CircId`] provided.
    ///
    /// The internal unique identifier for this circuit will be `unique_id`.
    pub(super) fn new(
        channel: Channel,
        channel_id: CircId,
        unique_id: UniqId,
        input: mpsc::Receiver<ClientCircChanMsg>,
    ) -> (
        Self,
        mpsc::UnboundedSender<CtrlMsg>,
        Arc<Mutex<MutableState>>,
    ) {
        let crypto_out = OutboundClientCrypt::new();
        let (control_tx, control_rx) = mpsc::unbounded();
        let path = Arc::new(path::Path::default());
        let mutable = Arc::new(Mutex::new(MutableState { path }));

        let reactor = Reactor {
            control: control_rx,
            outbound: Default::default(),
            channel,
            input,
            crypto_in: InboundClientCrypt::new(),
            hops: vec![],
            unique_id,
            channel_id,
            crypto_out,
            meta_handler: None,
            mutable: mutable.clone(),
        };

        (reactor, control_tx, mutable)
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
        debug!("{}: Circuit reactor stopped: {:?}", self.unique_id, result);
        result
    }

    /// Helper for run: doesn't mark the circuit closed on finish.  Only
    /// processes one cell or control message.
    pub(super) async fn run_once(&mut self) -> std::result::Result<(), ReactorError> {
        #[allow(clippy::cognitive_complexity)]
        let fut = futures::future::poll_fn(|cx| -> Poll<std::result::Result<_, ReactorError>> {
            let mut create_message = None;
            let mut did_things = false;

            // Check whether we've got a control message pending.
            if let Poll::Ready(ret) = Pin::new(&mut self.control).poll_next(cx) {
                match ret {
                    None => {
                        trace!("{}: reactor shutdown due to control drop", self.unique_id);
                        return Poll::Ready(Err(ReactorError::Shutdown));
                    }
                    Some(CtrlMsg::Shutdown) => {
                        trace!(
                            "{}: reactor shutdown due to explicit request",
                            self.unique_id
                        );
                        return Poll::Ready(Err(ReactorError::Shutdown));
                    }
                    // This message requires actually blocking, so we can't handle it inside
                    // this nonblocking poll_fn.
                    Some(x @ CtrlMsg::Create { .. }) => create_message = Some(x),
                    Some(msg) => {
                        self.handle_control(cx, msg)?;
                        did_things = true;
                    }
                }
            }

            // Check whether we've got an input message pending.
            if let Poll::Ready(ret) = Pin::new(&mut self.input).poll_next(cx) {
                match ret {
                    None => {
                        trace!("{}: reactor shutdown due to input drop", self.unique_id);
                        return Poll::Ready(Err(ReactorError::Shutdown));
                    }
                    Some(cell) => {
                        if self.handle_cell(cx, cell)? == CellStatus::CleanShutdown {
                            trace!("{}: reactor shutdown due to handled cell", self.unique_id);
                            return Poll::Ready(Err(ReactorError::Shutdown));
                        }
                        did_things = true;
                    }
                }
            }

            // Now for the tricky part. We want to grab some relay cells from all of our streams
            // and forward them on to the channel, but we need to pay attention to both whether
            // the channel can accept cells right now, and whether congestion control allows us
            // to send them.
            //
            // We also have to do somewhat cursed things and call start_send inside this poll_fn,
            // since we need to check whether the channel can still receive cells after each one
            // that we send.

            let mut streams_to_close = vec![];
            let mut stream_relaycells = vec![];

            // Is the channel ready to receive anything at all?
            if self.channel.poll_ready(cx)? {
                // (using this as a named block for early returns; not actually a loop)
                #[allow(clippy::never_loop)]
                'outer: loop {
                    // First, drain our queue of things we tried to send earlier, but couldn't.
                    while let Some(msg) = self.outbound.pop_front() {
                        trace!("{}: sending from enqueued: {:?}", self.unique_id, msg);
                        Pin::new(&mut self.channel).start_send(msg)?;

                        // `futures::Sink::start_send` dictates we need to call `poll_ready` before
                        // each `start_send` call.
                        if !self.channel.poll_ready(cx)? {
                            break 'outer;
                        }
                    }

                    // Let's look at our hops, and streams for each hop.
                    for i in 0..self.hops.len() {
                        let hop_num = HopNum::from(i as u8);
                        // If we can, drain our queue of things we tried to send earlier, but
                        // couldn't due to congestion control.
                        if self.hops[i].sendwindow.window() > 0 {
                            'hop: while let Some((early, cell)) = self.hops[i].outbound.pop_front()
                            {
                                trace!(
                                    "{}: sending from hop-{}-enqueued: {:?}",
                                    self.unique_id,
                                    i,
                                    cell
                                );
                                self.send_relay_cell(cx, hop_num, early, cell)?;
                                if !self.channel.poll_ready(cx)? {
                                    break 'outer;
                                }
                                if self.hops[i].sendwindow.window() == 0 {
                                    break 'hop;
                                }
                            }
                        }
                        let hop = &mut self.hops[i];
                        // Look at all of the streams on this hop.
                        for (id, stream) in hop.map.inner().iter_mut() {
                            if let StreamEnt::Open {
                                rx, send_window, ..
                            } = stream
                            {
                                // Do the stream and hop send windows allow us to obtain and
                                // send something?
                                //
                                // FIXME(eta): not everything counts toward congestion control!
                                if send_window.window() > 0 && hop.sendwindow.window() > 0 {
                                    match Pin::new(rx).poll_next(cx) {
                                        Poll::Ready(Some(m)) => {
                                            stream_relaycells
                                                .push((hop_num, AnyRelayCell::new(*id, m)));
                                        }
                                        Poll::Ready(None) => {
                                            // Stream receiver was dropped; close the stream.
                                            // We can't close it here though due to borrowck; that
                                            // will happen later.
                                            streams_to_close.push((hop_num, *id));
                                        }
                                        Poll::Pending => {}
                                    }
                                }
                            }
                        }
                    }

                    break;
                }
            }

            // Close the streams we said we'd close.
            for (hopn, id) in streams_to_close {
                self.close_stream(cx, hopn, id)?;
                did_things = true;
            }
            // Send messages we said we'd send.
            for (hopn, rc) in stream_relaycells {
                self.send_relay_cell(cx, hopn, false, rc)?;
                did_things = true;
            }

            let _ = Pin::new(&mut self.channel)
                .poll_flush(cx)
                .map_err(|_| ChannelClosed)?;
            if create_message.is_some() {
                Poll::Ready(Ok(create_message))
            } else if did_things {
                Poll::Ready(Ok(None))
            } else {
                Poll::Pending
            }
        });
        let create_message = fut.await?;
        if let Some(CtrlMsg::Create {
            recv_created,
            handshake,
            require_sendme_auth,
            params,
            done,
        }) = create_message
        {
            let ret = match handshake {
                CircuitHandshake::CreateFast => {
                    self.create_firsthop_fast(recv_created, &params).await
                }
                CircuitHandshake::Ntor {
                    public_key,
                    ed_identity,
                } => {
                    self.create_firsthop_ntor(
                        recv_created,
                        ed_identity,
                        public_key,
                        require_sendme_auth,
                        &params,
                    )
                    .await
                }
            };
            let _ = done.send(ret); // don't care if sender goes away
            futures::future::poll_fn(|cx| -> Poll<Result<()>> {
                let _ = Pin::new(&mut self.channel)
                    .poll_flush(cx)
                    .map_err(|_| ChannelClosed)?;
                Poll::Ready(Ok(()))
            })
            .await?;
        }
        Ok(())
    }

    /// Helper: create the first hop of a circuit.
    ///
    /// This is parameterized not just on the RNG, but a wrapper object to
    /// build the right kind of create cell, a handshake object to perform
    /// the cryptographic cryptographic handshake, and a layer type to
    /// handle relay crypto after this hop is built.
    async fn create_impl<L, FWD, REV, H, W>(
        &mut self,
        recvcreated: oneshot::Receiver<CreateResponse>,
        wrap: &W,
        key: &H::KeyType,
        require_sendme_auth: RequireSendmeAuth,
        params: &CircParameters,
    ) -> Result<()>
    where
        L: CryptInit + ClientLayer<FWD, REV> + 'static + Send,
        FWD: OutboundClientLayer + 'static + Send,
        REV: InboundClientLayer + 'static + Send,
        H: ClientHandshake,
        W: CreateHandshakeWrap,
        H::KeyGen: KeyGenerator,
    {
        // We don't need to shut down the circuit on failure here, since this
        // function consumes the PendingClientCirc and only returns
        // a ClientCirc on success.

        let (state, msg) = {
            // done like this because holding the RNG across an await boundary makes the future
            // non-Send
            let mut rng = rand::thread_rng();
            H::client1(&mut rng, key)?
        };
        let create_cell = wrap.to_chanmsg(msg);
        debug!(
            "{}: Extending to hop 1 with {}",
            self.unique_id,
            create_cell.cmd()
        );
        self.send_msg(create_cell).await?;

        let reply = recvcreated
            .await
            .map_err(|_| Error::CircProto("Circuit closed while waiting".into()))?;

        let relay_handshake = wrap.decode_chanmsg(reply)?;
        let keygen = H::client2(state, relay_handshake)?;

        let layer = L::construct(keygen)?;

        debug!("{}: Handshake complete; circuit created.", self.unique_id);

        let (layer_fwd, layer_back) = layer.split();
        let peer_id = self.channel.target().clone();

        self.add_hop(
            path::HopDetail::Relay(peer_id),
            require_sendme_auth,
            Box::new(layer_fwd),
            Box::new(layer_back),
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
        use crate::crypto::handshake::fast::CreateFastClient;
        let wrap = CreateFastWrap;
        self.create_impl::<Tor1RelayCrypto, _, _, CreateFastClient, _>(
            recvcreated,
            &wrap,
            &(),
            RequireSendmeAuth::No,
            params,
        )
        .await
    }

    /// Use the ntor handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided 'target' must match the channel's target,
    /// or the handshake will fail.
    async fn create_firsthop_ntor(
        &mut self,
        recvcreated: oneshot::Receiver<CreateResponse>,
        ed_identity: pk::ed25519::Ed25519Identity,
        pubkey: NtorPublicKey,
        require_sendme_auth: RequireSendmeAuth,
        params: &CircParameters,
    ) -> Result<()> {
        // Exit now if we have an Ed25519 or RSA identity mismatch.
        let target = RelayIds::builder()
            .ed_identity(ed_identity)
            .rsa_identity(pubkey.id)
            .build()
            .expect("Unable to build RelayIds");
        self.channel.check_match(&target)?;

        let wrap = Create2Wrap {
            handshake_type: 0x0002, // ntor
        };
        self.create_impl::<Tor1RelayCrypto, _, _, NtorClient, _>(
            recvcreated,
            &wrap,
            &pubkey,
            require_sendme_auth,
            params,
        )
        .await
    }

    /// Add a hop to the end of this circuit.
    fn add_hop(
        &mut self,
        peer_id: path::HopDetail,
        require_sendme_auth: RequireSendmeAuth,
        fwd: Box<dyn OutboundClientLayer + 'static + Send>,
        rev: Box<dyn InboundClientLayer + 'static + Send>,
        params: &CircParameters,
    ) {
        let hop = crate::circuit::reactor::CircHop::new(
            require_sendme_auth,
            params.initial_send_window(),
        );
        self.hops.push(hop);
        self.crypto_in.add_layer(rev);
        self.crypto_out.add_layer(fwd);
        let mut mutable = self.mutable.lock().expect("poisoned lock");
        Arc::make_mut(&mut mutable.path).push_hop(peer_id);
    }

    /// Handle a RELAY cell on this circuit with stream ID 0.
    fn handle_meta_cell(&mut self, hopnum: HopNum, msg: UnparsedRelayCell) -> Result<CellStatus> {
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

            return self.handle_sendme(hopnum, sendme);
        }
        if msg.cmd() == RelayCmd::TRUNCATED {
            let truncated = msg
                .decode::<tor_cell::relaycell::msg::Truncated>()
                .map_err(|e| Error::from_bytes_err(e, "truncated message"))?
                .into_msg();
            let reason = truncated.reason();
            debug!(
                "{}: Truncated from hop {}. Reason: {} [{}]",
                self.unique_id,
                hopnum,
                reason.human_str(),
                reason
            );

            return Ok(CellStatus::CleanShutdown);
        }

        trace!("{}: Received meta-cell {:?}", self.unique_id, msg);

        // For all other command types, we'll only get them in response
        // to another command, which should have registered a responder.
        //
        // TODO: that means that service-introduction circuits will need
        // a different implementation, but that should be okay. We'll work
        // something out.
        if let Some(mut handler) = self.meta_handler.take() {
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
                        self.meta_handler = Some(handler);
                        Ok(CellStatus::Continue)
                    }
                    Ok(MetaCellDisposition::UninstallHandler) => Ok(CellStatus::Continue),
                    #[cfg(feature = "send-control-msg")]
                    Ok(MetaCellDisposition::CloseCirc) => Ok(CellStatus::CleanShutdown),
                    Err(e) => Err(e),
                }
            } else {
                // Somebody wanted a message from a different hop!  Put this
                // one back.
                self.meta_handler = Some(handler);
                Err(Error::CircProto(format!(
                    "Unexpected {} cell from hop {} on client circuit",
                    msg.cmd(),
                    hopnum,
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
    fn handle_sendme(&mut self, hopnum: HopNum, msg: Sendme) -> Result<CellStatus> {
        // No need to call "shutdown" on errors in this function;
        // it's called from the reactor task and errors will propagate there.
        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::CircProto(format!("Couldn't find {} hop", hopnum)))?;

        let auth: Option<[u8; 20]> = match msg.into_tag() {
            Some(v) => {
                if let Ok(tag) = <[u8; 20]>::try_from(v) {
                    Some(tag)
                } else {
                    return Err(Error::CircProto("malformed tag on circuit sendme".into()));
                }
            }
            None => {
                if hop.auth_sendme_required == RequireSendmeAuth::Yes {
                    return Err(Error::CircProto("missing tag on circuit sendme".into()));
                } else {
                    None
                }
            }
        };
        hop.sendwindow.put(auth)?;
        Ok(CellStatus::Continue)
    }

    /// Send a message onto the circuit's channel (to be called with a `Context`)
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
    fn send_msg_direct(&mut self, cx: &mut Context<'_>, msg: AnyChanMsg) -> Result<()> {
        let cell = AnyChanCell::new(self.channel_id, msg);
        // NOTE(eta): We need to check whether the outbound queue is empty before trying to send:
        //            if we just checked whether the channel was ready, it'd be possible for
        //            cells to be sent out of order, since it could transition from not ready to
        //            ready during one cycle of the reactor!
        //            (This manifests as a protocol violation.)
        if self.outbound.is_empty() && self.channel.poll_ready(cx)? {
            Pin::new(&mut self.channel).start_send(cell)?;
        } else {
            // This has been observed to happen in code that doesn't have bugs in it, simply due
            // to the way `Channel`'s `poll_ready` implementation works (it can change due to
            // the actions of another thread in between callers of this function checking it,
            // and this function checking it).
            //
            // However, if it's happening a lot more than it used to, that probably indicates
            // some caller that's not checking whether the channel is full before calling
            // this function.

            debug!(
                "{}: having to enqueue cell due to backpressure: {:?}",
                self.unique_id, cell
            );
            self.outbound.push_back(cell);

            // Ensure we absolutely get scheduled again to clear `self.outbound`.
            cx.waker().wake_by_ref();
        }
        Ok(())
    }

    /// Wrapper around `send_msg_direct` that uses `futures::future::poll_fn` to get a `Context`.
    async fn send_msg(&mut self, msg: AnyChanMsg) -> Result<()> {
        // HACK(eta): technically the closure passed to `poll_fn` is a `FnMut` closure, since it
        //            can be polled multiple times.
        //            We're going to return Ready immediately since we're only using `poll_fn` to
        //            get a `Context`, but the compiler doesn't know that, so use an `Option`
        //            which we can `take()` in order to move out of it.
        //            (if we do get polled again this'll panic, but that shouldn't happen!)
        let mut msg = Some(msg);
        futures::future::poll_fn(|cx| -> Poll<Result<()>> {
            self.send_msg_direct(cx, msg.take().expect("poll_fn called twice?"))?;
            Poll::Ready(Ok(()))
        })
        .await?;
        Ok(())
    }

    /// Encode the relay cell `cell`, encrypt it, and send it to the 'hop'th hop.
    ///
    /// Does not check whether the cell is well-formed or reasonable.
    fn send_relay_cell(
        &mut self,
        cx: &mut Context<'_>,
        hop: HopNum,
        early: bool,
        cell: AnyRelayCell,
    ) -> Result<()> {
        let c_t_w = sendme::cmd_counts_towards_windows(cell.cmd());
        let stream_id = cell.stream_id();
        // Check whether the hop send window is empty, if this cell counts towards windows.
        // NOTE(eta): It is imperative this happens *before* calling encrypt() below, otherwise
        //            we'll have cells rejected due to a protocol violation! (Cells have to be
        //            sent out in the order they were passed to encrypt().)
        if c_t_w {
            let hop_num = Into::<usize>::into(hop);
            let hop = &mut self.hops[hop_num];
            if hop.sendwindow.window() == 0 {
                // Send window is empty! Push this cell onto the hop's outbound queue, and it'll
                // get sent later.
                trace!(
                    "{}: having to use onto hop {} queue for cell: {:?}",
                    self.unique_id,
                    hop_num,
                    cell
                );
                hop.outbound.push_back((early, cell));
                return Ok(());
            }
        }
        let mut body: RelayCellBody = cell
            .encode(&mut rand::thread_rng())
            .map_err(|e| Error::from_cell_enc(e, "relay cell body"))?
            .into();
        let tag = self.crypto_out.encrypt(&mut body, hop)?;
        // NOTE(eta): Now that we've encrypted the cell, we *must* either send it or abort
        //            the whole circuit (e.g. by returning an error).
        let msg = chancell::msg::Relay::from(BoxedCellBody::from(body));
        let msg = if early {
            AnyChanMsg::RelayEarly(msg.into())
        } else {
            AnyChanMsg::Relay(msg)
        };
        // If the cell counted towards our sendme window, decrement
        // that window, and maybe remember the authentication tag.
        if c_t_w {
            let hop_num = Into::<usize>::into(hop);
            let hop = &mut self.hops[hop_num];
            // checked by earlier conditional, so this shouldn't fail
            hop.sendwindow.take(tag)?;
            if !stream_id.is_zero() {
                // We need to decrement the stream-level sendme window.
                // Stream data cells should only be dequeued and fed into this function if
                // the window is above zero, so we don't need to worry about enqueuing things.
                if let Some(window) = hop.map.get_mut(stream_id).and_then(StreamEnt::send_window) {
                    window.take(&())?;
                } else {
                    warn!(
                        "{}: sending a relay cell for non-existent or non-open stream with ID {}!",
                        self.unique_id, stream_id
                    );
                    return Err(Error::CircProto(format!(
                        "tried to send a relay cell on non-open stream {}",
                        sv(stream_id),
                    )));
                }
            }
        }
        self.send_msg_direct(cx, msg)
    }

    /// Try to install a given meta-cell handler to receive any unusual cells on
    /// this circuit, along with a result channel to notify on completion.
    fn set_meta_handler(&mut self, handler: Box<dyn MetaCellHandler>) -> Result<()> {
        if self.meta_handler.is_none() {
            self.meta_handler = Some(handler);
            Ok(())
        } else {
            Err(Error::from(internal!(
                "Tried to install a meta-cell handler before the old one was gone."
            )))
        }
    }

    /// Handle a CtrlMsg other than Shutdown.
    fn handle_control(&mut self, cx: &mut Context<'_>, msg: CtrlMsg) -> Result<()> {
        trace!("{}: reactor received {:?}", self.unique_id, msg);
        match msg {
            // This is handled earlier, since it requires blocking.
            CtrlMsg::Create { .. } => panic!("got a CtrlMsg::Create in handle_control"),
            // This is handled earlier, since it requires generating a ReactorError.
            CtrlMsg::Shutdown => panic!("got a CtrlMsg::Shutdown in handle_control"),
            CtrlMsg::ExtendNtor {
                peer_id,
                public_key,
                linkspecs,
                require_sendme_auth,
                params,
                done,
            } => {
                let extender = CircuitExtender::<NtorClient, Tor1RelayCrypto, _, _>::begin(
                    cx,
                    peer_id,
                    0x02,
                    &public_key,
                    linkspecs,
                    require_sendme_auth,
                    params,
                    self,
                    done,
                )?;
                self.set_meta_handler(Box::new(extender))?;
            }
            #[cfg(feature = "hs-common")]
            #[allow(unreachable_code)]
            CtrlMsg::ExtendVirtual {
                cell_crypto,
                params,
                done,
            } => {
                let (outbound, inbound) = cell_crypto;

                // TODO HS: Perhaps this should describe the onion service, or
                // describe why the virtual hop was added, or something?
                let peer_id = path::HopDetail::Virtual;

                // TODO HS: This is not really correct! We probably should be
                // looking at the sendme_auth_accept_min_version parameter.  See
                // comments in RequireSendmeAuth::from_protocols.
                //
                // "Yes" should be safe, however, since Tor <=0.3.5 is
                // emphatically unsupported.
                let require_sendme_auth = RequireSendmeAuth::Yes;

                self.add_hop(peer_id, require_sendme_auth, outbound, inbound, &params);
                let _ = done.send(Ok(()));
            }
            CtrlMsg::BeginStream {
                hop_num,
                message,
                sender,
                rx,
                done,
                cmd_checker,
            } => {
                let ret = self.begin_stream(cx, hop_num, message, sender, rx, cmd_checker);
                let _ = done.send(ret); // don't care if sender goes away
            }
            CtrlMsg::SendSendme { stream_id, hop_num } => {
                let sendme = Sendme::new_empty();
                let cell = AnyRelayCell::new(stream_id, sendme.into());
                self.send_relay_cell(cx, hop_num, false, cell)?;
            }
            #[cfg(feature = "send-control-msg")]
            CtrlMsg::SendMsgAndInstallHandler {
                msg,
                handler,
                sender,
            } => {
                let outcome: Result<()> = (|| {
                    self.send_relay_cell(cx, handler.expected_hop(), false, msg)?;
                    self.set_meta_handler(handler)?;
                    Ok(())
                })();
                let _ = sender.send(outcome.clone()); // don't care if receiver goes away.
                outcome?;
            }
            #[cfg(test)]
            CtrlMsg::AddFakeHop {
                supports_flowctrl_1,
                fwd_lasthop,
                rev_lasthop,
                params,
                done,
            } => {
                use crate::circuit::test::DummyCrypto;

                // This kinds of conversion is okay for testing, but just for testing.
                let require_sendme_auth = if supports_flowctrl_1 {
                    RequireSendmeAuth::Yes
                } else {
                    RequireSendmeAuth::No
                };

                let dummy_peer_id = OwnedChanTarget::builder()
                    .ed_identity([4; 32].into())
                    .rsa_identity([5; 20].into())
                    .build()
                    .expect("Could not construct fake hop");

                let fwd = Box::new(DummyCrypto::new(fwd_lasthop));
                let rev = Box::new(DummyCrypto::new(rev_lasthop));
                self.add_hop(
                    path::HopDetail::Relay(dummy_peer_id),
                    require_sendme_auth,
                    fwd,
                    rev,
                    &params,
                );
                let _ = done.send(Ok(()));
            }
            #[cfg(test)]
            CtrlMsg::QuerySendWindow { hop, done } => {
                let _ = done.send(if let Some(hop) = self.hop_mut(hop) {
                    Ok(hop.sendwindow.window_and_expected_tags())
                } else {
                    Err(Error::from(internal!(
                        "received QuerySendWindow for unknown hop {:?}",
                        hop
                    )))
                });
            }
            #[cfg(test)]
            CtrlMsg::SendRelayCell { hop, early, cell } => {
                self.send_relay_cell(cx, hop, early, cell)?;
            }
        }
        Ok(())
    }

    /// Start a stream. Creates an entry in the stream map with the given channels, and sends the
    /// `message` to the provided hop.
    fn begin_stream(
        &mut self,
        cx: &mut Context<'_>,
        hopnum: HopNum,
        message: AnyRelayMsg,
        sender: mpsc::Sender<UnparsedRelayCell>,
        rx: mpsc::Receiver<AnyRelayMsg>,
        cmd_checker: AnyCmdChecker,
    ) -> Result<StreamId> {
        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::from(internal!("No such hop {:?}", hopnum)))?;
        let send_window = StreamSendWindow::new(SEND_WINDOW_INIT);
        let r = hop.map.add_ent(sender, rx, send_window, cmd_checker)?;
        let cell = AnyRelayCell::new(r, message);
        self.send_relay_cell(cx, hopnum, false, cell)?;
        Ok(r)
    }

    /// Close the stream associated with `id` because the stream was
    /// dropped.
    ///
    /// If we have not already received an END cell on this stream, send one.
    fn close_stream(&mut self, cx: &mut Context<'_>, hopnum: HopNum, id: StreamId) -> Result<()> {
        // Mark the stream as closing.
        let hop = self.hop_mut(hopnum).ok_or_else(|| {
            Error::from(internal!(
                "Tried to close a stream on a hop {:?} that wasn't there?",
                hopnum
            ))
        })?;

        let should_send_end = hop.map.terminate(id)?;
        trace!(
            "{}: Ending stream {}; should_send_end={:?}",
            self.unique_id,
            id,
            should_send_end
        );
        // TODO: I am about 80% sure that we only send an END cell if
        // we didn't already get an END cell.  But I should double-check!
        if should_send_end == ShouldSendEnd::Send {
            let end_cell = AnyRelayCell::new(id, End::new_misc().into());
            self.send_relay_cell(cx, hopnum, false, end_cell)?;
        }
        Ok(())
    }

    /// Helper: process a cell on a channel.  Most cells get ignored
    /// or rejected; a few get delivered to circuits.
    ///
    /// Return true if we should exit.
    fn handle_cell(&mut self, cx: &mut Context<'_>, cell: ClientCircChanMsg) -> Result<CellStatus> {
        trace!("{}: handling cell: {:?}", self.unique_id, cell);
        use ClientCircChanMsg::*;
        match cell {
            Relay(r) => Ok(self.handle_relay_cell(cx, r)?),
            Destroy(d) => {
                let reason = d.reason();
                debug!(
                    "{}: Received DESTROY cell. Reason: {} [{}]",
                    self.unique_id,
                    reason.human_str(),
                    reason
                );

                self.handle_destroy_cell()?;
                Ok(CellStatus::CleanShutdown)
            }
        }
    }

    /// React to a Relay or RelayEarly cell.
    fn handle_relay_cell(&mut self, cx: &mut Context<'_>, cell: Relay) -> Result<CellStatus> {
        let mut body = cell.into_relay_body().into();

        // Decrypt the cell. If it's recognized, then find the
        // corresponding hop.
        let (hopnum, tag) = self.crypto_in.decrypt(&mut body)?;
        // Make a copy of the authentication tag. TODO: I'd rather not
        // copy it, but I don't see a way around it right now.
        let tag = {
            let mut tag_copy = [0_u8; 20];
            // TODO(nickm): This could crash if the tag length changes.  We'll
            // have to refactor it then.
            tag_copy.copy_from_slice(tag);
            tag_copy
        };
        // Put the cell into a format where we can make sense of it.
        let msg = UnparsedRelayCell::from_body(body.into());

        let c_t_w = sendme::cell_counts_towards_windows(&msg);

        // Decrement the circuit sendme windows, and see if we need to
        // send a sendme cell.
        let send_circ_sendme = if c_t_w {
            let hop = self
                .hop_mut(hopnum)
                .ok_or_else(|| Error::CircProto("Sendme from nonexistent hop".into()))?;
            hop.recvwindow.take()?
        } else {
            false
        };
        // If we do need to send a circuit-level SENDME cell, do so.
        if send_circ_sendme {
            // This always sends a V1 (tagged) sendme cell, and thereby assumes
            // that SendmeEmitMinVersion is no more than 1.  If the authorities
            // every increase that parameter to a higher number, this will
            // become incorrect.  (Higher numbers are not currently defined.)
            let sendme = Sendme::new_tag(tag);
            let cell = AnyRelayCell::new(0.into(), sendme.into());
            self.send_relay_cell(cx, hopnum, false, cell)?;
            self.hop_mut(hopnum)
                .ok_or_else(|| {
                    Error::from(internal!(
                        "Trying to send SENDME to nonexistent hop {:?}",
                        hopnum
                    ))
                })?
                .recvwindow
                .put();
        }

        // If this cell wants/refuses to have a Stream ID, does it
        // have/not have one?
        let cmd = msg.cmd();
        let streamid = msg.stream_id();
        if !cmd.accepts_streamid_val(streamid) {
            return Err(Error::CircProto(format!(
                "Invalid stream ID {} for relay command {}",
                sv(streamid),
                msg.cmd()
            )));
        }

        // If this has a reasonable streamID value of 0, it's a meta cell,
        // not meant for a particular stream.
        if streamid.is_zero() {
            return self.handle_meta_cell(hopnum, msg);
        }

        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::CircProto("Cell from nonexistent hop!".into()))?;
        match hop.map.get_mut(streamid) {
            Some(StreamEnt::Open {
                sink,
                send_window,
                dropped,
                cmd_checker,
                ..
            }) => {
                // The stream for this message exists, and is open.

                if msg.cmd() == RelayCmd::SENDME {
                    let _sendme = msg
                        .decode::<Sendme>()
                        .map_err(|e| Error::from_bytes_err(e, "Sendme message on stream"))?
                        .into_msg();
                    // We need to handle sendmes here, not in the stream's
                    // recv() method, or else we'd never notice them if the
                    // stream isn't reading.
                    send_window.put(Some(()))?;
                    return Ok(CellStatus::Continue);
                }

                let message_closes_stream = cmd_checker.check_msg(&msg)? == StreamStatus::Closed;

                if let Err(e) = sink.try_send(msg) {
                    if e.is_full() {
                        // If we get here, we either have a logic bug (!), or an attacker
                        // is sending us more cells than we asked for via congestion control.
                        return Err(Error::CircProto(format!(
                            "Stream sink would block; received too many cells on stream ID {}",
                            sv(streamid),
                        )));
                    }
                    if e.is_disconnected() && c_t_w {
                        // the other side of the stream has gone away; remember
                        // that we received a cell that we couldn't queue for it.
                        //
                        // Later this value will be recorded in a half-stream.
                        *dropped += 1;
                    }
                }
                if message_closes_stream {
                    hop.map.ending_msg_received(streamid)?;
                }
            }
            Some(StreamEnt::EndSent(halfstream)) => {
                // We sent an end but maybe the other side hasn't heard.

                match halfstream.handle_msg(msg)? {
                    StreamStatus::Open => {}
                    StreamStatus::Closed => hop.map.ending_msg_received(streamid)?,
                }
            }
            _ => {
                // No stream wants this message, or ever did.
                return Err(Error::CircProto(
                    "Cell received on nonexistent stream!?".into(),
                ));
            }
        }
        Ok(CellStatus::Continue)
    }

    /// Helper: process a destroy cell.
    #[allow(clippy::unnecessary_wraps)]
    fn handle_destroy_cell(&mut self) -> Result<()> {
        // I think there is nothing more to do here.
        Ok(())
    }

    /// Return the hop corresponding to `hopnum`, if there is one.
    fn hop_mut(&mut self, hopnum: HopNum) -> Option<&mut CircHop> {
        self.hops.get_mut(Into::<usize>::into(hopnum))
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        let _ = self.channel.close_circuit(self.channel_id);
    }
}

#[cfg(test)]
mod test {}
