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

pub(super) mod syncview;

use super::handshake::RelayCryptLayerProtocol;
use super::streammap::{EndSentStreamEnt, ShouldSendEnd, StreamEntMut};
use super::MutableState;
use crate::circuit::celltypes::{ClientCircChanMsg, CreateResponse};
use crate::circuit::handshake::{BoxedClientLayer, HandshakeRole};
use crate::circuit::unique_id::UniqId;
use crate::circuit::{
    sendme, streammap, CircParameters, Create2Wrap, CreateFastWrap, CreateHandshakeWrap,
};
use crate::crypto::binding::CircuitBinding;
use crate::crypto::cell::{
    ClientLayer, CryptInit, HopNum, InboundClientCrypt, InboundClientLayer, OutboundClientCrypt,
    OutboundClientLayer, RelayCellBody, Tor1RelayCrypto,
};
use crate::crypto::handshake::fast::CreateFastClient;
#[cfg(feature = "ntor_v3")]
use crate::crypto::handshake::ntor_v3::{NtorV3Client, NtorV3PublicKey};
use crate::stream::{AnyCmdChecker, StreamStatus};
use crate::util::err::{ChannelClosed, ReactorError};
use crate::util::sometimes_unbounded_sink::SometimesUnboundedSink;
use crate::util::SinkExt as _;
use crate::{Error, Result};
use std::borrow::Borrow;
use std::marker::PhantomData;
use std::pin::Pin;
use tor_cell::chancell::msg::{AnyChanMsg, HandshakeType, Relay};
use tor_cell::relaycell::msg::{AnyRelayMsg, End, Sendme};
use tor_cell::relaycell::{
    AnyRelayMsgOuter, RelayCellDecoder, RelayCellFormat, RelayCellFormatTrait, RelayCellFormatV0,
    RelayCmd, StreamId, UnparsedRelayMsg,
};
use tor_error::internal;
#[cfg(feature = "hs-service")]
use {
    crate::stream::{DataCmdChecker, IncomingStreamRequest, IncomingStreamRequestFilter},
    tor_cell::relaycell::msg::Begin,
};

use futures::channel::mpsc;
use futures::Stream;
use futures::{Sink, StreamExt};
use oneshot_fused_workaround as oneshot;

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use crate::channel::{Channel, ChannelSender};
use crate::circuit::path;
#[cfg(test)]
use crate::circuit::sendme::CircTag;
use crate::circuit::sendme::StreamSendWindow;
use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
use crate::crypto::handshake::{ClientHandshake, KeyGenerator};
use safelog::sensitive as sv;
use tor_async_utils::{SinkTrySend as _, SinkTrySendError as _};
use tor_cell::chancell::{self, BoxedCellBody, ChanMsg};
use tor_cell::chancell::{AnyChanCell, CircId};
use tor_cell::relaycell::extend::NtorV3Extension;
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
        /// Other parameters relevant for circuit extension.
        params: CircParameters,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
    },
    /// Extend a circuit by one hop, using the ntorv3 handshake.
    #[cfg(feature = "ntor_v3")]
    ExtendNtorV3 {
        /// The peer that we're extending to.
        ///
        /// Used to extend our record of the circuit's path.
        peer_id: OwnedChanTarget,
        /// The handshake type to use for this hop.
        public_key: NtorV3PublicKey,
        /// Information about how to connect to the relay we're extending to.
        linkspecs: Vec<EncodedLinkSpec>,
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
        /// Which relay cell format to use for this hop.
        relay_cell_format: RelayCellFormat,
        /// The cryptographic algorithms and keys to use when communicating with
        /// the newly added hop.
        #[educe(Debug(ignore))]
        cell_crypto: (
            Box<dyn OutboundClientLayer + Send>,
            Box<dyn InboundClientLayer + Send>,
            Option<CircuitBinding>,
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
        sender: mpsc::Sender<UnparsedRelayMsg>,
        /// A channel to receive messages to send on this stream from.
        rx: mpsc::Receiver<AnyRelayMsg>,
        /// Oneshot channel to notify on completion, with the allocated stream ID.
        done: ReactorResultChannel<StreamId>,
        /// A `CmdChecker` to keep track of which message types are acceptable.
        cmd_checker: AnyCmdChecker,
    },
    /// Close the specified pending incoming stream, sending the provided END message.
    ///
    /// A stream is said to be pending if the message for initiating the stream was received but
    /// not has not been responded to yet.
    ///
    /// This should be used by responders for closing pending incoming streams initiated by the
    /// other party on the circuit.
    #[cfg(feature = "hs-service")]
    ClosePendingStream {
        /// The hop number the stream is on.
        hop_num: HopNum,
        /// The stream ID to send the END for.
        stream_id: StreamId,
        /// The END message to send, if any.
        message: CloseStreamBehavior,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
    },
    /// Begin accepting streams on this circuit.
    #[cfg(feature = "hs-service")]
    AwaitStreamRequest {
        /// A channel for sending information about an incoming stream request.
        incoming_sender: mpsc::Sender<StreamReqInfo>,
        /// A `CmdChecker` to keep track of which message types are acceptable.
        cmd_checker: AnyCmdChecker,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
        /// The hop that is allowed to create streams.
        hop_num: HopNum,
        /// A filter used to check requests before passing them on.
        #[educe(Debug(ignore))]
        #[cfg(feature = "hs-service")]
        filter: Box<dyn IncomingStreamRequestFilter>,
    },
    /// Send a given control message on this circuit.
    #[cfg(feature = "send-control-msg")]
    SendMsg {
        /// The hop to receive this message.
        hop_num: HopNum,
        /// The message to send.
        msg: AnyRelayMsg,
        /// A sender that we use to tell the caller that the message was sent
        /// and the handler installed.
        sender: oneshot::Sender<Result<()>>,
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
        relay_cell_format: RelayCellFormat,
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
        cell: AnyRelayMsgOuter,
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
    /// Window used to say how many cells we can send.
    sendwindow: sendme::CircSendWindow,
    /// Decodes relay cells received from this hop.
    inbound: RelayCellDecoder,
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
    pub(super) fn new(format: RelayCellFormat, initial_window: u16) -> Self {
        CircHop {
            map: streammap::StreamMap::new(),
            recvwindow: sendme::CircRecvWindow::new(1000),
            sendwindow: sendme::CircSendWindow::new(initial_window),
            inbound: RelayCellDecoder::new(format),
        }
    }
}

/// Handle to use during an ongoing protocol exchange with a circuit's last hop
///
/// This is passed to `MsgHandler::handle_msg`.
///
/// See also [`ConversationInHandler`], which is a type used for the same purpose
/// but available to the caller of `start_conversation`
//
// This is the subset of the arguments to MetaCellHandler::handle_msg
// which are needed to be able to call send_relay_cell.
#[cfg(feature = "send-control-msg")]
pub struct ConversationInHandler<'r, 'c, 'cc> {
    /// Async task waker context
    pub(super) cx: &'c mut Context<'cc>,
    /// Reactor
    pub(super) reactor: &'r mut Reactor,
    /// Hop
    pub(super) hop_num: HopNum,
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
        cx: &mut Context<'_>,
        msg: UnparsedRelayMsg,
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
    ConversationFinished,
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
    /// Parameters used for this extension.
    params: CircParameters,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// The hop we're expecting the EXTENDED2 cell to come back from.
    expected_hop: HopNum,
    /// The relay cell format we intend to use for this hop.
    relay_cell_format: RelayCellFormat,
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
    H: ClientHandshake + HandshakeAuxDataHandler,
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
    #[allow(clippy::blocks_in_conditions)]
    fn begin(
        cx: &mut Context<'_>,
        relay_cell_format: RelayCellFormat,
        peer_id: OwnedChanTarget,
        handshake_id: HandshakeType,
        key: &H::KeyType,
        linkspecs: Vec<EncodedLinkSpec>,
        params: CircParameters,
        client_aux_data: &impl Borrow<H::ClientAuxData>,
        reactor: &mut Reactor,
        done: ReactorResultChannel<()>,
    ) -> Result<Self> {
        match (|| {
            let mut rng = rand::thread_rng();
            let unique_id = reactor.unique_id;

            use tor_cell::relaycell::msg::Extend2;
            let (state, msg) = H::client1(&mut rng, key, client_aux_data)?;

            let n_hops = reactor.crypto_out.n_layers();
            let hop = ((n_hops - 1) as u8).into();

            trace!(
                "{}: Extending circuit to hop {} with {:?}",
                unique_id,
                n_hops + 1,
                linkspecs
            );

            let extend_msg = Extend2::new(linkspecs, handshake_id, msg);
            let cell = AnyRelayMsgOuter::new(None, extend_msg.into());

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
                params,
                unique_id,
                expected_hop: hop,
                operation_finished: None,
                phantom: Default::default(),
                relay_cell_format,
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
        msg: UnparsedRelayMsg,
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
        let (server_aux_data, keygen) = H::client2(
            self.state
                .take()
                .expect("CircuitExtender::finish() called twice"),
            relay_handshake,
        )?;

        // Handle auxiliary data returned from the server, e.g. validating that
        // requested extensions have been acknowledged.
        H::handle_server_aux_data(reactor, &self.params, &server_aux_data)?;

        let layer = L::construct(keygen)?;

        trace!("{}: Handshake complete; circuit extended.", self.unique_id);

        // If we get here, it succeeded.  Add a new hop to the circuit.
        let (layer_fwd, layer_back, binding) = layer.split();
        reactor.add_hop(
            self.relay_cell_format,
            path::HopDetail::Relay(self.peer_id.clone()),
            Box::new(layer_fwd),
            Box::new(layer_back),
            Some(binding),
            &self.params,
        );
        Ok(MetaCellDisposition::ConversationFinished)
    }
}

impl<H, L, FWD, REV> MetaCellHandler for CircuitExtender<H, L, FWD, REV>
where
    H: ClientHandshake + HandshakeAuxDataHandler,
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
        _cx: &mut Context<'_>,
        msg: UnparsedRelayMsg,
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

/// Specifies handling of auxiliary handshake data for a given `ClientHandshake`.
//
// For simplicity we implement this as a trait of the handshake object itself.
// This is currently sufficient because
//
// 1. We only need or want one handler implementation for a given handshake type.
// 2. We currently don't need to keep extra state; i.e. its method doesn't take
//    &self.
//
// If we end up wanting to instantiate objects for one or both of the
// `ClientHandshake` object or the `HandshakeAuxDataHandler` object, we could
// decouple them by making this something like:
//
// ```
// trait HandshakeAuxDataHandler<H> where H: ClientHandshake
// ```
trait HandshakeAuxDataHandler: ClientHandshake {
    /// Handle auxiliary handshake data returned when creating or extending a
    /// circuit.
    fn handle_server_aux_data(
        reactor: &mut Reactor,
        params: &CircParameters,
        data: &<Self as ClientHandshake>::ServerAuxData,
    ) -> Result<()>;
}

#[cfg(feature = "ntor_v3")]
impl HandshakeAuxDataHandler for NtorV3Client {
    fn handle_server_aux_data(
        _reactor: &mut Reactor,
        _params: &CircParameters,
        data: &Vec<NtorV3Extension>,
    ) -> Result<()> {
        // There are currently no accepted server extensions,
        // particularly since we don't request any extensions yet.
        if !data.is_empty() {
            return Err(Error::HandshakeProto(
                "Received unexpected ntorv3 extension".into(),
            ));
        }
        Ok(())
    }
}

impl HandshakeAuxDataHandler for NtorClient {
    fn handle_server_aux_data(
        _reactor: &mut Reactor,
        _params: &CircParameters,
        _data: &(),
    ) -> Result<()> {
        // This handshake doesn't have any auxiliary data; nothing to do.
        Ok(())
    }
}

impl HandshakeAuxDataHandler for CreateFastClient {
    fn handle_server_aux_data(
        _reactor: &mut Reactor,
        _params: &CircParameters,
        _data: &(),
    ) -> Result<()> {
        // This handshake doesn't have any auxiliary data; nothing to do.
        Ok(())
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
    /// The channel this circuit is attached to.
    channel: Arc<Channel>,
    /// Sender object used to actually send cells.
    ///
    /// NOTE: Control messages could potentially add unboundedly to this, although that's
    ///       not likely to happen (and isn't triggereable from the network, either).
    chan_sender: SometimesUnboundedSink<AnyChanCell, ChannelSender>,
    /// A oneshot sender that is used to alert other tasks when this reactor is
    /// finally dropped.
    ///
    /// It is a sender for Void because we never actually want to send anything here;
    /// we only want to generate canceled events.
    #[allow(dead_code)] // the only purpose of this field is to be dropped.
    reactor_closed_tx: oneshot::Sender<void::Void>,
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
    meta_handler: Option<Box<dyn MetaCellHandler + Send>>,
    /// A handler for incoming stream requests.
    #[cfg(feature = "hs-service")]
    incoming_stream_req_handler: Option<IncomingStreamRequestHandler>,
}

/// Information about an incoming stream request.
#[cfg(feature = "hs-service")]
#[derive(Debug)]
pub(super) struct StreamReqInfo {
    /// The [`IncomingStreamRequest`].
    pub(super) req: IncomingStreamRequest,
    /// The ID of the stream being requested.
    pub(super) stream_id: StreamId,
    /// The [`HopNum`].
    //
    // TODO: When we add support for exit relays, we need to turn this into an Option<HopNum>.
    // (For outbound messages (towards relays), there is only one hop that can send them: the client.)
    //
    // TODO: For onion services, we might be able to enforce the HopNum earlier: we would never accept an
    // incoming stream request from two separate hops.  (There is only one that's valid.)
    pub(super) hop_num: HopNum,
    /// A channel for receiving messages from this stream.
    pub(super) receiver: mpsc::Receiver<UnparsedRelayMsg>,
    /// A channel for sending messages to be sent on this stream.
    pub(super) msg_tx: mpsc::Sender<AnyRelayMsg>,
}

/// Data required for handling an incoming stream request.
#[cfg(feature = "hs-service")]
#[derive(educe::Educe)]
#[educe(Debug)]
struct IncomingStreamRequestHandler {
    /// A sender for sharing information about an incoming stream request.
    incoming_sender: mpsc::Sender<StreamReqInfo>,
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
    pub(super) fn new(
        channel: Arc<Channel>,
        channel_id: CircId,
        unique_id: UniqId,
        input: mpsc::Receiver<ClientCircChanMsg>,
    ) -> (
        Self,
        mpsc::UnboundedSender<CtrlMsg>,
        oneshot::Receiver<void::Void>,
        Arc<Mutex<MutableState>>,
    ) {
        let crypto_out = OutboundClientCrypt::new();
        let (control_tx, control_rx) = mpsc::unbounded();
        let path = Arc::new(path::Path::default());
        let binding = Vec::new();
        let mutable = Arc::new(Mutex::new(MutableState { path, binding }));

        let (reactor_closed_tx, reactor_closed_rx) = oneshot::channel();

        let chan_sender = SometimesUnboundedSink::new(channel.sender());

        let reactor = Reactor {
            control: control_rx,
            reactor_closed_tx,
            channel,
            chan_sender,
            input,
            crypto_in: InboundClientCrypt::new(),
            hops: vec![],
            unique_id,
            channel_id,
            crypto_out,
            meta_handler: None,
            #[cfg(feature = "hs-service")]
            incoming_stream_req_handler: None,
            mutable: mutable.clone(),
        };

        (reactor, control_tx, reactor_closed_rx, mutable)
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
    async fn run_once(&mut self) -> std::result::Result<(), ReactorError> {
        if self.hops.is_empty() {
            self.wait_for_create().await?;

            return Ok(());
        }

        #[allow(clippy::cognitive_complexity)]
        let fut = futures::future::poll_fn(|cx| -> Poll<std::result::Result<_, ReactorError>> {
            let mut did_things = false;

            // Check whether we've got a control message pending.
            if let Poll::Ready(ret) = Pin::new(&mut self.control).poll_next(cx) {
                match ret {
                    None => {
                        trace!("{}: reactor shutdown due to control drop", self.unique_id);
                        return Poll::Ready(Err(ReactorError::Shutdown));
                    }
                    Some(CtrlMsg::Shutdown) => return Poll::Ready(self.handle_shutdown()),
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

            // Check each hop for an outbound message pending.
            for i in 0..self.hops.len() {
                if !self.chan_sender.poll_ready_unpin_bool(cx)? {
                    // Channel isn't ready to send; we can't act on anything else.
                    // (Even processing an end-of-stream would end up having to buffer
                    // an END message in the channel).
                    break;
                }
                if self.hops[i].sendwindow.window() == 0 {
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
                    continue;
                }
                let hop_num = HopNum::from(i as u8);
                // Process an outbound message from the first ready stream on
                // this hop. The stream map implements round robin scheduling to
                // ensure fairness across streams.
                // TODO: Consider looping here to process multiple ready
                // streams. Need to be careful though to balance that with
                // continuing to service incoming and control messages.
                let Some((sid, msg)) = self.hops[i].map.poll_ready_streams_iter(cx).next() else {
                    // No ready streams for this hop.
                    continue;
                };
                if msg.is_none() {
                    // Sender was dropped, so close the stream, which
                    // also removes this entry from the streams iterator.
                    self.close_stream(
                        cx,
                        hop_num,
                        sid,
                        CloseStreamBehavior::default(),
                        streammap::TerminateReason::StreamTargetClosed,
                    )?;
                    did_things = true;
                    continue;
                };
                let msg = self.hops[i]
                    .map
                    .take_ready_msg(sid)
                    .expect("msg disappeared");
                debug_assert!(
                    {
                        let Some(StreamEntMut::Open(s)) = self.hops[i].map.get_mut(sid) else {
                            panic!("Stream {sid} disappeared");
                        };
                        s.can_send(&msg)
                    },
                    "Stream {sid} produced a message it can't send: {msg:?}"
                );
                self.send_relay_cell(cx, hop_num, false, AnyRelayMsgOuter::new(Some(sid), msg))?;
                did_things = true;
            }

            let _ = Pin::new(&mut self.chan_sender)
                .poll_flush(cx)
                .map_err(|_| ChannelClosed)?;

            if did_things {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        });

        fut.await?;
        Ok(())
    }

    /// Wait for a [`CtrlMsg::Create`] to come along to set up the circuit.
    ///
    /// Returns an error if an unexpected `CtrlMsg` is received.
    async fn wait_for_create(&mut self) -> std::result::Result<(), ReactorError> {
        let Some(msg) = self.control.next().await else {
            trace!("{}: reactor shutdown due to control drop", self.unique_id);
            return Err(ReactorError::Shutdown);
        };

        match msg {
            CtrlMsg::Create {
                recv_created,
                handshake,
                params,
                done,
            } => {
                self.handle_create(recv_created, handshake, &params, done)
                    .await
            }
            CtrlMsg::Shutdown => self.handle_shutdown(),
            #[cfg(test)]
            CtrlMsg::AddFakeHop {
                relay_cell_format: format,
                fwd_lasthop,
                rev_lasthop,
                params,
                done,
            } => {
                self.handle_add_fake_hop(format, fwd_lasthop, rev_lasthop, &params, done);
                Ok(())
            }
            _ => {
                trace!("reactor shutdown due to unexpected cell: {:?}", msg);

                Err(Error::CircProto(format!("Unexpected {msg:?} cell on client circuit")).into())
            }
        }
    }

    /// Handle a [`CtrlMsg::Create`] message.
    async fn handle_create(
        &mut self,
        recv_created: oneshot::Receiver<CreateResponse>,
        handshake: CircuitHandshake,
        params: &CircParameters,
        done: ReactorResultChannel<()>,
    ) -> std::result::Result<(), ReactorError> {
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

        futures::future::poll_fn(|cx| -> Poll<Result<()>> {
            let _ = Pin::new(&mut self.chan_sender)
                .poll_flush(cx)
                .map_err(|_| ChannelClosed)?;
            Poll::Ready(Ok(()))
        })
        .await?;

        Ok(())
    }

    /// Handle a [`CtrlMsg::Shutdown`] message.
    fn handle_shutdown(&self) -> std::result::Result<(), ReactorError> {
        trace!(
            "{}: reactor shutdown due to explicit request",
            self.unique_id
        );

        Err(ReactorError::Shutdown)
    }

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
        use crate::circuit::test::DummyCrypto;

        let dummy_peer_id = OwnedChanTarget::builder()
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

        H::handle_server_aux_data(self, params, &server_msg)?;

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
        let hop = crate::circuit::reactor::CircHop::new(format, params.initial_send_window());
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
        cx: &mut Context<'_>,
        hopnum: HopNum,
        msg: UnparsedRelayMsg,
    ) -> Result<CellStatus> {
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
                hopnum.display(),
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
                let ret = handler.handle_msg(cx, msg, self);
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
                    Ok(MetaCellDisposition::ConversationFinished) => Ok(CellStatus::Continue),
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
    fn handle_sendme(&mut self, hopnum: HopNum, msg: Sendme) -> Result<CellStatus> {
        // No need to call "shutdown" on errors in this function;
        // it's called from the reactor task and errors will propagate there.
        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::CircProto(format!("Couldn't find hop {}", hopnum.display())))?;

        let auth: Option<[u8; 20]> = match msg.into_tag() {
            Some(v) => {
                if let Ok(tag) = <[u8; 20]>::try_from(v) {
                    Some(tag)
                } else {
                    return Err(Error::CircProto("malformed tag on circuit sendme".into()));
                }
            }
            None => {
                // Versions of Tor <=0.3.5 would omit a SENDME tag in this case;
                // but we don't support those any longer.
                return Err(Error::CircProto("missing tag on circuit sendme".into()));
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
        let cell = AnyChanCell::new(Some(self.channel_id), msg);
        Pin::new(&mut self.chan_sender).pollish_send_unbounded(cx, cell)
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

    /// Encode `msg`, encrypt it, and send it to the 'hop'th hop.
    ///
    /// If there is insufficient outgoing *circuit-level* or *stream-level*
    /// SENDME window, an error is returned instead.
    ///
    /// Does not check whether the cell is well-formed or reasonable.
    fn send_relay_cell(
        &mut self,
        cx: &mut Context<'_>,
        hop: HopNum,
        early: bool,
        msg: AnyRelayMsgOuter,
    ) -> Result<()> {
        let c_t_w = sendme::cmd_counts_towards_windows(msg.cmd());
        let stream_id = msg.stream_id();
        let hop_num = Into::<usize>::into(hop);
        let circhop = &mut self.hops[hop_num];
        // We need to apply stream-level flow control *before* encoding the message.
        if c_t_w {
            if let Some(stream_id) = stream_id {
                let Some(StreamEntMut::Open(ent)) = circhop.map.get_mut(stream_id) else {
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
        let mut body: RelayCellBody = msg
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
            circhop.sendwindow.take(tag)?;
        }
        self.send_msg_direct(cx, msg)
    }

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

    /// Handle a CtrlMsg other than Create and Shutdown.
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
                params,
                done,
            } => {
                // ntor handshake only supports V0.
                /// Local type alias to ensure consistency below.
                type Rcf = RelayCellFormatV0;

                let extender = CircuitExtender::<NtorClient, Tor1RelayCrypto<Rcf>, _, _>::begin(
                    cx,
                    Rcf::FORMAT,
                    peer_id,
                    HandshakeType::NTOR,
                    &public_key,
                    linkspecs,
                    params,
                    &(),
                    self,
                    done,
                )?;
                self.set_meta_handler(Box::new(extender))?;
            }
            #[cfg(feature = "ntor_v3")]
            CtrlMsg::ExtendNtorV3 {
                peer_id,
                public_key,
                linkspecs,
                params,
                done,
            } => {
                // TODO #1067: support negotiating other formats.
                /// Local type alias to ensure consistency below.
                type Rcf = RelayCellFormatV0;

                // TODO: Set extensions, e.g. based on `params`.
                let client_extensions = [];

                let extender = CircuitExtender::<NtorV3Client, Tor1RelayCrypto<Rcf>, _, _>::begin(
                    cx,
                    Rcf::FORMAT,
                    peer_id,
                    HandshakeType::NTOR_V3,
                    &public_key,
                    linkspecs,
                    params,
                    &client_extensions,
                    self,
                    done,
                )?;
                self.set_meta_handler(Box::new(extender))?;
            }
            #[cfg(feature = "hs-common")]
            #[allow(unreachable_code)]
            CtrlMsg::ExtendVirtual {
                relay_cell_format: format,
                cell_crypto,
                params,
                done,
            } => {
                let (outbound, inbound, binding) = cell_crypto;

                // TODO HS: Perhaps this should describe the onion service, or
                // describe why the virtual hop was added, or something?
                let peer_id = path::HopDetail::Virtual;

                self.add_hop(format, peer_id, outbound, inbound, binding, &params);
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
            #[cfg(feature = "hs-service")]
            CtrlMsg::ClosePendingStream {
                hop_num,
                stream_id,
                message,
                done,
            } => {
                let ret = self.close_stream(
                    cx,
                    hop_num,
                    stream_id,
                    message,
                    streammap::TerminateReason::ExplicitEnd,
                )?;
                let _ = done.send(Ok(ret)); // don't care if sender goes away
            }
            #[cfg(feature = "hs-service")]
            CtrlMsg::AwaitStreamRequest {
                cmd_checker,
                incoming_sender,
                hop_num,
                done,
                filter,
            } => {
                // TODO: At some point we might want to add a CtrlMsg for
                // de-registering the handler.  See comments on `allow_stream_requests`.
                let handler = IncomingStreamRequestHandler {
                    incoming_sender,
                    cmd_checker,
                    hop_num,
                    filter,
                };

                let ret = self.set_incoming_stream_req_handler(handler);
                let _ = done.send(ret); // don't care if the corresponding receiver goes away.
            }
            CtrlMsg::SendSendme { stream_id, hop_num } => {
                let sendme = Sendme::new_empty();
                let cell = AnyRelayMsgOuter::new(Some(stream_id), sendme.into());
                self.send_relay_cell(cx, hop_num, false, cell)?;
            }
            #[cfg(feature = "send-control-msg")]
            CtrlMsg::SendMsg {
                hop_num,
                msg,
                sender,
            } => {
                let cell = AnyRelayMsgOuter::new(None, msg);
                let outcome = self.send_relay_cell(cx, hop_num, false, cell);
                let _ = sender.send(outcome.clone()); // don't care if receiver goes away.
                outcome?;
            }
            #[cfg(feature = "send-control-msg")]
            CtrlMsg::SendMsgAndInstallHandler {
                msg,
                handler,
                sender,
            } => {
                let outcome: Result<()> = (|| {
                    if let Some(msg) = msg {
                        let handler = handler
                            .as_ref()
                            .or(self.meta_handler.as_ref())
                            .ok_or_else(|| internal!("tried to use an ended Conversation"))?;
                        self.send_relay_cell(cx, handler.expected_hop(), false, msg)?;
                    }
                    if let Some(handler) = handler {
                        self.set_meta_handler(handler)?;
                    }
                    Ok(())
                })();
                let _ = sender.send(outcome.clone()); // don't care if receiver goes away.
                outcome?;
            }
            #[cfg(test)]
            CtrlMsg::AddFakeHop {
                relay_cell_format,
                fwd_lasthop,
                rev_lasthop,
                params,
                done,
            } => {
                self.handle_add_fake_hop(
                    relay_cell_format,
                    fwd_lasthop,
                    rev_lasthop,
                    &params,
                    done,
                );
            }
            #[cfg(test)]
            CtrlMsg::QuerySendWindow { hop, done } => {
                let _ = done.send(if let Some(hop) = self.hop_mut(hop) {
                    Ok(hop.sendwindow.window_and_expected_tags())
                } else {
                    Err(Error::from(internal!(
                        "received QuerySendWindow for unknown hop {}",
                        hop.display()
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
        sender: mpsc::Sender<UnparsedRelayMsg>,
        rx: mpsc::Receiver<AnyRelayMsg>,
        cmd_checker: AnyCmdChecker,
    ) -> Result<StreamId> {
        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::from(internal!("No such hop {}", hopnum.display())))?;
        let send_window = StreamSendWindow::new(SEND_WINDOW_INIT);
        let r = hop.map.add_ent(sender, rx, send_window, cmd_checker)?;
        let cell = AnyRelayMsgOuter::new(Some(r), message);
        self.send_relay_cell(cx, hopnum, false, cell)?;
        Ok(r)
    }

    /// Close the stream associated with `id` because the stream was
    /// dropped.
    ///
    /// If we have not already received an END cell on this stream, send one.
    /// If no END cell is specified, an END cell with the reason byte set to
    /// REASON_MISC will be sent.
    fn close_stream(
        &mut self,
        cx: &mut Context<'_>,
        hopnum: HopNum,
        id: StreamId,
        message: CloseStreamBehavior,
        why: streammap::TerminateReason,
    ) -> Result<()> {
        // Mark the stream as closing.
        let hop = self.hop_mut(hopnum).ok_or_else(|| {
            Error::from(internal!(
                "Tried to close a stream on a hop {:?} that wasn't there?",
                hopnum
            ))
        })?;

        let should_send_end = hop.map.terminate(id, why)?;
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

        let c_t_w = decode_res.cmds().any(sendme::cmd_counts_towards_windows);

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
            let cell = AnyRelayMsgOuter::new(None, sendme.into());
            self.send_relay_cell(cx, hopnum, false, cell)?;
            self.hop_mut(hopnum)
                .ok_or_else(|| {
                    Error::from(internal!(
                        "Trying to send SENDME to nonexistent hop {:?}",
                        hopnum
                    ))
                })?
                .recvwindow
                .put()?;
        }

        let (mut msgs, incomplete) = decode_res.into_parts();
        while let Some(msg) = msgs.next() {
            let msg_status = self.handle_relay_msg(cx, hopnum, c_t_w, msg)?;
            match msg_status {
                CellStatus::Continue => (),
                CellStatus::CleanShutdown => {
                    for msg in msgs {
                        debug!(
                            "{id}: Ignoring relay msg received after triggering shutdown: {msg:?}",
                            id = self.unique_id
                        );
                    }
                    if let Some(incomplete) = incomplete {
                        debug!("{id}: Ignoring partial relay msg received after triggering shutdown: {incomplete:?}", id=self.unique_id);
                    }
                    return Ok(CellStatus::CleanShutdown);
                }
            }
        }
        Ok(CellStatus::Continue)
    }

    /// Handle a single incoming relay message.
    fn handle_relay_msg(
        &mut self,
        cx: &mut Context<'_>,
        hopnum: HopNum,
        cell_counts_toward_windows: bool,
        msg: UnparsedRelayMsg,
    ) -> Result<CellStatus> {
        // If this msg wants/refuses to have a Stream ID, does it
        // have/not have one?
        let cmd = msg.cmd();
        let streamid = msg.stream_id();
        if !cmd.accepts_streamid_val(streamid) {
            return Err(Error::CircProto(format!(
                "Invalid stream ID {} for relay command {}",
                sv(StreamId::get_or_zero(streamid)),
                msg.cmd()
            )));
        }

        // If this doesn't have a StreamId, it's a meta cell,
        // not meant for a particular stream.
        let Some(streamid) = streamid else {
            return self.handle_meta_cell(cx, hopnum, msg);
        };

        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::CircProto("Cell from nonexistent hop!".into()))?;
        match hop.map.get_mut(streamid) {
            Some(StreamEntMut::Open(ent)) => {
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
                    return Ok(CellStatus::Continue);
                }

                let message_closes_stream =
                    ent.cmd_checker.check_msg(&msg)? == StreamStatus::Closed;

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
                if message_closes_stream {
                    hop.map.ending_msg_received(streamid)?;
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
                hop.map.ending_msg_received(streamid)?;
                return self.handle_incoming_stream_request(cx, msg, streamid, hopnum);
            }
            Some(StreamEntMut::EndSent(EndSentStreamEnt { half_stream, .. })) => {
                // We sent an end but maybe the other side hasn't heard.

                match half_stream.handle_msg(msg)? {
                    StreamStatus::Open => {}
                    StreamStatus::Closed => hop.map.ending_msg_received(streamid)?,
                }
            }
            #[cfg(feature = "hs-service")]
            None if matches!(
                msg.cmd(),
                RelayCmd::BEGIN | RelayCmd::BEGIN_DIR | RelayCmd::RESOLVE
            ) =>
            {
                self.handle_incoming_stream_request(cx, msg, streamid, hopnum)?;
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

    /// A helper for handling incoming stream requests.
    #[cfg(feature = "hs-service")]
    fn handle_incoming_stream_request(
        &mut self,
        cx: &mut Context<'_>,
        msg: UnparsedRelayMsg,
        stream_id: StreamId,
        hop_num: HopNum,
    ) -> Result<CellStatus> {
        use syncview::ClientCircSyncView;
        use tor_cell::relaycell::msg::EndReason;
        use tor_error::into_internal;
        use tor_log_ratelim::log_ratelim;

        // We need to construct this early so that we don't double-borrow &mut self

        let Some(handler) = self.incoming_stream_req_handler.as_mut() else {
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
            hop.map.ending_msg_received(stream_id)?;

            return Ok(CellStatus::Continue);
        }

        let begin = msg
            .decode::<Begin>()
            .map_err(|e| Error::from_bytes_err(e, "Invalid Begin message"))?
            .into_msg();

        let req = IncomingStreamRequest::Begin(begin);

        {
            use crate::stream::IncomingStreamRequestDisposition::*;

            let ctx = crate::stream::IncomingStreamRequestContext { request: &req };
            let view = ClientCircSyncView::new(&self.hops);

            match handler.filter.as_mut().disposition(&ctx, &view)? {
                Accept => {}
                CloseCircuit => return Ok(CellStatus::CleanShutdown),
                RejectRequest(end) => {
                    let end_msg = AnyRelayMsgOuter::new(Some(stream_id), end.into());
                    self.send_relay_cell(cx, hop_num, false, end_msg)?;
                    return Ok(CellStatus::Continue);
                }
            }
        }

        // TODO: Sadly, we need to look up `&mut hop` yet again,
        // since we needed to pass `&self.hops` by reference to our filter above. :(
        let hop = self
            .hops
            .get_mut(Into::<usize>::into(hop_num))
            .ok_or(Error::CircuitClosed)?;

        let (sender, receiver) = mpsc::channel(STREAM_READER_BUFFER);
        let (msg_tx, msg_rx) = mpsc::channel(super::CIRCUIT_BUFFER_SIZE);

        let send_window = StreamSendWindow::new(SEND_WINDOW_INIT);
        let cmd_checker = DataCmdChecker::new_connected();
        hop.map
            .add_ent_with_id(sender, msg_rx, send_window, stream_id, cmd_checker)?;

        let outcome = Pin::new(&mut handler
            .incoming_sender
	)
            .try_send(StreamReqInfo {
                req,
                stream_id,
                hop_num,
                msg_tx,
                receiver,
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
                self.send_relay_cell(cx, hop_num, false, end_msg)?;
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

#[cfg(feature = "send-control-msg")]
#[cfg_attr(docsrs, doc(cfg(feature = "send-control-msg")))]
impl ConversationInHandler<'_, '_, '_> {
    /// Send a protocol message as part of an ad-hoc exchange
    ///
    /// This is the within-[`MsgHandler`](super::MsgHandler)
    /// counterpart to [`Conversation`](super::Conversation).
    ///
    /// It differs only in that the `send_message` function here is sync,
    /// and takes `&mut self`.
    //
    // TODO hs: it might be nice to avoid exposing tor-cell APIs in the
    //   tor-proto interface.
    pub fn send_message(&mut self, msg: tor_cell::relaycell::msg::AnyRelayMsg) -> Result<()> {
        let msg = tor_cell::relaycell::AnyRelayMsgOuter::new(None, msg);

        self.reactor
            .send_relay_cell(self.cx, self.hop_num, false, msg)
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        let _ = self.channel.close_circuit(self.channel_id);
    }
}

#[cfg(test)]
mod test {
    // Tested in [`crate::circuit::test`].
}
