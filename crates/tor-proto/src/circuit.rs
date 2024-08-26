//! Multi-hop paths over the Tor network.
//!
//! Right now, we only implement "client circuits" -- also sometimes
//! called "origin circuits".  A client circuit is one that is
//! constructed by this Tor instance, and used in its own behalf to
//! send data over the Tor network.
//!
//! Each circuit has multiple hops over the Tor network: each hop
//! knows only the hop before and the hop after.  The client shares a
//! separate set of keys with each hop.
//!
//! To build a circuit, first create a [crate::channel::Channel], then
//! call its [crate::channel::Channel::new_circ] method.  This yields
//! a [PendingClientCirc] object that won't become live until you call
//! one of the methods that extends it to its first hop.  After you've
//! done that, you can call [ClientCirc::extend_ntor] on the circuit to
//! build it into a multi-hop circuit.  Finally, you can use
//! [ClientCirc::begin_stream] to get a Stream object that can be used
//! for anonymized data.
//!
//! # Implementation
//!
//! Each open circuit has a corresponding Reactor object that runs in
//! an asynchronous task, and manages incoming cells from the
//! circuit's upstream channel.  These cells are either RELAY cells or
//! DESTROY cells.  DESTROY cells are handled immediately.
//! RELAY cells are either for a particular stream, in which case they
//! get forwarded to a RawCellStream object, or for no particular stream,
//! in which case they are considered "meta" cells (like EXTENDED2)
//! that should only get accepted if something is waiting for them.
//!
//! # Limitations
//!
//! This is client-only.
//!
//! There is no flow-control or rate-limiting or fairness.

pub(crate) mod celltypes;
pub(crate) mod halfcirc;
mod halfstream;

#[cfg(feature = "hs-common")]
pub mod handshake;
#[cfg(not(feature = "hs-common"))]
mod handshake;

#[cfg(feature = "send-control-msg")]
mod msghandler;
mod path;
pub(crate) mod reactor;
pub(crate) mod sendme;
mod streammap;
mod unique_id;

use crate::channel::Channel;
use crate::circuit::celltypes::*;
use crate::circuit::reactor::{
    CircuitHandshake, CtrlMsg, Reactor, RECV_WINDOW_INIT, STREAM_READER_BUFFER,
};
pub use crate::circuit::unique_id::UniqId;
pub use crate::crypto::binding::CircuitBinding;
use crate::crypto::cell::HopNum;
#[cfg(feature = "ntor_v3")]
use crate::crypto::handshake::ntor_v3::NtorV3PublicKey;
use crate::stream::{
    AnyCmdChecker, DataCmdChecker, DataStream, ResolveCmdChecker, ResolveStream, StreamParameters,
    StreamReader,
};
use crate::{Error, ResolveError, Result};
use educe::Educe;
use tor_cell::chancell::msg::HandshakeType;
use tor_cell::{
    chancell::{self, msg::AnyChanMsg, CircId},
    relaycell::msg::{AnyRelayMsg, Begin, Resolve, Resolved, ResolvedVal},
};

use tor_error::{bad_api_usage, internal, into_internal};
use tor_linkspec::{CircTarget, LinkSpecType, OwnedChanTarget, RelayIdType};

#[cfg(feature = "hs-service")]
use {
    crate::circuit::reactor::StreamReqInfo,
    crate::stream::{IncomingCmdChecker, IncomingStream},
};

use futures::channel::mpsc;
use tor_async_utils::oneshot;

use crate::circuit::sendme::StreamRecvWindow;
use futures::{FutureExt as _, SinkExt as _};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tor_cell::relaycell::StreamId;
// use std::time::Duration;

use crate::crypto::handshake::ntor::NtorPublicKey;
pub use path::{Path, PathEntry};
pub use reactor::syncview::ClientCircSyncView;

/// The size of the buffer for communication between `ClientCirc` and its reactor.
pub const CIRCUIT_BUFFER_SIZE: usize = 128;

#[cfg(feature = "send-control-msg")]
use reactor::MetaCellHandler;

#[cfg(feature = "send-control-msg")]
#[cfg_attr(docsrs, doc(cfg(feature = "send-control-msg")))]
pub use {
    msghandler::MsgHandler,
    reactor::{ConversationInHandler, MetaCellDisposition},
};

#[derive(Debug)]
/// A circuit that we have constructed over the Tor network.
///
/// # Circuit life cycle
///
/// `ClientCirc`s are created in an initially unusable state using [`Channel::new_circ`],
/// which returns a [`PendingClientCirc`].  To get a real (one-hop) circuit from
/// one of these, you invoke one of its `create_firsthop` methods (currently
/// [`create_firsthop_fast()`](PendingClientCirc::create_firsthop_fast) or
/// [`create_firsthop_ntor()`](PendingClientCirc::create_firsthop_ntor)).
/// Then, to add more hops to the circuit, you can call
/// [`extend_ntor()`](ClientCirc::extend_ntor) on it.
///
/// For higher-level APIs, see the `tor-circmgr` crate: the ones here in
/// `tor-proto` are probably not what you need.
///
/// After a circuit is created, it will persist until it is closed in one of
/// five ways:
///    1. A remote error occurs.
///    2. Some hop on the circuit sends a `DESTROY` message to tear down the
///       circuit.
///    3. The circuit's channel is closed.
///    4. Someone calls [`ClientCirc::terminate`] on the circuit.
///    5. The last reference to the `ClientCirc` is dropped. (Note that every stream
///       on a `ClientCirc` keeps a reference to it, which will in turn keep the
///       circuit from closing until all those streams have gone away.)
///
/// Note that in cases 1-4 the [`ClientCirc`] object itself will still exist: it
/// will just be unusable for most purposes.  Most operations on it will fail
/// with an error.
//
// Effectively, this struct contains two Arcs: one for `path` and one for
// `control` (which surely has something Arc-like in it).  We cannot unify
// these by putting a single Arc around the whole struct, and passing
// an Arc strong reference to the `Reactor`, because then `control` would
// not be dropped when the last user of the circuit goes away.  We could
// make the reactor have a weak reference but weak references are more
// expensive to dereference.
//
// Because of the above, cloning this struct is always going to involve
// two atomic refcount changes/checks.  Wrapping it in another Arc would
// be overkill.

pub struct ClientCirc {
    /// Mutable state shared with the `Reactor`.
    mutable: Arc<Mutex<MutableState>>,
    /// A unique identifier for this circuit.
    unique_id: UniqId,
    /// Channel to send control messages to the reactor.
    control: mpsc::UnboundedSender<CtrlMsg>,
    /// The channel that this ClientCirc is connected to and using to speak with
    /// its first hop.
    ///
    /// # Warning
    ///
    /// Don't use this field to send or receive any data, or perform any network
    /// operations for this circuit!  All network operations should be done by
    /// the circuit reactor.
    ///
    /// TODO: This limitation strongly suggests that we have made a mistake somewhere, and should
    /// not be holding this field in this structure.  Or maybe the object that lets us send/receive
    /// from a channel should be separate from Channel itself, like how StreamTarget is separate
    /// from Circuit.
    channel: Arc<Channel>,
    /// A future that resolves to Cancelled once the reactor is shut down,
    /// meaning that the circuit is closed.
    #[cfg_attr(not(feature = "experimental-api"), allow(dead_code))]
    reactor_closed_rx: futures::future::Shared<oneshot::Receiver<void::Void>>,
    /// For testing purposes: the CircId, for use in peek_circid().
    #[cfg(test)]
    circid: CircId,
}

/// Mutable state shared by [`ClientCirc`] and [`Reactor`].
#[derive(Educe)]
#[educe(Debug)]
struct MutableState {
    /// Information about this circuit's path.
    ///
    /// This is stored in an Arc so that we can cheaply give a copy of it to
    /// client code; when we need to add a hop (which is less frequent) we use
    /// [`Arc::make_mut()`].
    path: Arc<path::Path>,

    /// Circuit binding keys [q.v.][`CircuitBinding`] information for each hop
    /// in the circuit's path.
    ///
    /// NOTE: Right now, there is a `CircuitBinding` for every hop.  There's a
    /// fair chance that this will change in the future, and I don't want other
    /// code to assume that a `CircuitBinding` _must_ exist, so I'm making this
    /// an `Option`.
    #[educe(Debug(ignore))]
    binding: Vec<Option<CircuitBinding>>,
}

/// A ClientCirc that needs to send a create cell and receive a created* cell.
///
/// To use one of these, call create_firsthop_fast() or create_firsthop_ntor()
/// to negotiate the cryptographic handshake with the first hop.
pub struct PendingClientCirc {
    /// A oneshot receiver on which we'll receive a CREATED* cell,
    /// or a DESTROY cell.
    recvcreated: oneshot::Receiver<CreateResponse>,
    /// The ClientCirc object that we can expose on success.
    circ: Arc<ClientCirc>,
}

/// Description of the network's current rules for building circuits.
#[derive(Clone, Debug)]
pub struct CircParameters {
    /// Initial value to use for our outbound circuit-level windows.
    initial_send_window: u16,
    /// Whether we should include ed25519 identities when we send
    /// EXTEND2 cells.
    extend_by_ed25519_id: bool,
}

impl Default for CircParameters {
    fn default() -> CircParameters {
        CircParameters {
            initial_send_window: 1000,
            extend_by_ed25519_id: true,
        }
    }
}

impl CircParameters {
    /// Override the default initial send window for these parameters.
    /// Gives an error on any value above 1000.
    ///
    /// You should probably not call this.
    pub fn set_initial_send_window(&mut self, v: u16) -> Result<()> {
        if v <= 1000 {
            self.initial_send_window = v;
            Ok(())
        } else {
            Err(Error::from(bad_api_usage!(
                "Tried to set an initial send window over 1000"
            )))
        }
    }

    /// Return the initial send window as set in this parameter set.
    pub fn initial_send_window(&self) -> u16 {
        self.initial_send_window
    }

    /// Override the default decision about whether to use ed25519
    /// identities in outgoing EXTEND2 cells.
    ///
    /// You should probably not call this.
    pub fn set_extend_by_ed25519_id(&mut self, v: bool) {
        self.extend_by_ed25519_id = v;
    }

    /// Return true if we're configured to extend by ed25519 ID; false
    /// otherwise.
    pub fn extend_by_ed25519_id(&self) -> bool {
        self.extend_by_ed25519_id
    }
}

/// Internal handle, used to implement a stream on a particular circuit.
///
/// The reader and the writer for a stream should hold a `StreamTarget` for the stream;
/// the reader should additionally hold an `mpsc::Receiver` to get
/// relay messages for the stream.
///
/// When all the `StreamTarget`s for a stream are dropped, the Reactor will
/// close the stream by sending an END message to the other side.
/// You can close a stream earlier by using [`StreamTarget::close`]
/// or [`StreamTarget::close_pending`].
#[derive(Clone, Debug)]
pub(crate) struct StreamTarget {
    /// Which hop of the circuit this stream is with.
    hop_num: HopNum,
    /// Reactor ID for this stream.
    stream_id: StreamId,
    /// Channel to send cells down.
    tx: mpsc::Sender<AnyRelayMsg>,
    /// Reference to the circuit that this stream is on.
    circ: Arc<ClientCirc>,
}

impl ClientCirc {
    /// Return a description of the first hop of this circuit.
    ///
    /// # Panics
    ///
    /// Panics if there is no first hop.  (This should be impossible outside of
    /// the tor-proto crate, but within the crate it's possible to have a
    /// circuit with no hops.)
    pub fn first_hop(&self) -> OwnedChanTarget {
        let first_hop = self
            .mutable
            .lock()
            .expect("poisoned lock")
            .path
            .first_hop()
            .expect("called first_hop on an un-constructed circuit");
        match first_hop {
            path::HopDetail::Relay(r) => r,
            #[cfg(feature = "hs-common")]
            path::HopDetail::Virtual => {
                panic!("somehow made a circuit with a virtual first hop.")
            }
        }
    }

    /// Return the [`HopNum`] of the last hop of this circuit.
    ///
    /// Returns an error if there is no last hop.  (This should be impossible outside of the
    /// tor-proto crate, but within the crate it's possible to have a circuit with no hops.)
    pub fn last_hop_num(&self) -> Result<HopNum> {
        Ok(self
            .mutable
            .lock()
            .expect("poisoned lock")
            .path
            .last_hop_num()
            .ok_or_else(|| internal!("no last hop index"))?)
    }

    /// Return a description of all the hops in this circuit.
    ///
    /// This method is **deprecated** for several reasons:
    ///   * It performs a deep copy.
    ///   * It ignores virtual hops.
    ///   * It's not so extensible.
    ///
    /// Use [`ClientCirc::path_ref()`] instead.
    #[deprecated(since = "0.11.1", note = "Use path_ref() instead.")]
    pub fn path(&self) -> Vec<OwnedChanTarget> {
        #[allow(clippy::unnecessary_filter_map)] // clippy is blind to the cfg
        self.mutable
            .lock()
            .expect("poisoned lock")
            .path
            .all_hops()
            .into_iter()
            .filter_map(|hop| match hop {
                path::HopDetail::Relay(r) => Some(r),
                #[cfg(feature = "hs-common")]
                path::HopDetail::Virtual => None,
            })
            .collect()
    }

    /// Return a [`Path`] object describing all the hops in this circuit.
    ///
    /// Note that this `Path` is not automatically updated if the circuit is
    /// extended.
    pub fn path_ref(&self) -> Arc<Path> {
        self.mutable.lock().expect("poisoned_lock").path.clone()
    }

    /// Return a reference to the channel that this circuit is connected to.
    ///
    /// A client circuit is always connected to some relay via a [`Channel`].
    /// That relay has to be the same relay as the first hop in the client's
    /// path.
    pub fn channel(&self) -> &Channel {
        &self.channel
    }

    /// Return the cryptographic material used to prove knowledge of a shared
    /// secret with with `hop`.
    ///
    /// See [`CircuitBinding`] for more information on how this is used.
    ///
    /// Return None if we have no circuit binding information for the hop, or if
    /// the hop does not exist.
    pub fn binding_key(&self, hop: HopNum) -> Option<CircuitBinding> {
        self.mutable
            .lock()
            .expect("poisoned lock")
            .binding
            .get::<usize>(hop.into())
            .cloned()
            .flatten()
        // NOTE: I'm not thrilled to have to copy this information, but we use
        // it very rarely, so it's not _that_ bad IMO.
    }

    /// Start an ad-hoc protocol exchange to the specified hop on this circuit
    ///
    /// To use this:
    ///
    ///  0. Create an inter-task channel you'll use to receive
    ///     the outcome of your conversation,
    ///     and bundle it into a [`MsgHandler`].
    ///
    ///  1. Call `start_conversation`.
    ///     This will install a your handler, for incoming messages,
    ///     and send the outgoing message (if you provided one).
    ///     After that, each message on the circuit
    ///     that isn't handled by the core machinery
    ///     is passed to your provided `reply_handler`.
    ///
    ///  2. Possibly call `send_msg` on the [`Conversation`],
    ///     from the call site of `start_conversation`,
    ///     possibly multiple times, from time to time,
    ///     to send further desired messages to the peer.
    ///
    ///  3. In your [`MsgHandler`], process the incoming messages.
    ///     You may respond by
    ///     sending additional messages
    ///     (using the [`ConversationInHandler`] provided to `MsgHandler::handle_msg`,
    ///     or, outside the handler using the `Conversation`)
    ///     When the protocol exchange is finished,
    ///     `MsgHandler::handle_msg` should return
    ///     [`ConversationFinished`](MetaCellDisposition::ConversationFinished).
    ///
    /// If you don't need the `Conversation` to send followup messages,
    /// you may simply drop it,
    /// and rely on the responses you get from your handler,
    /// on the channel from step 0 above.
    /// Your handler will remain installed and able to process incoming messages
    /// until it returns `ConversationFinished`.
    ///
    /// (If you don't want to accept any replies at all, it may be
    /// simpler to use [`ClientCirc::send_raw_msg`].)
    ///
    /// Note that it is quite possible to use this function to violate the tor
    /// protocol; most users of this API will not need to call it.  It is used
    /// to implement most of the onion service handshake.
    ///
    /// # Limitations
    ///
    /// Only one conversation may be active at any one time,
    /// for any one circuit.
    /// This generally means that this function should not be called
    /// on a circuit which might be shared with anyone else.
    ///
    /// Likewise, it is forbidden to try to extend the circuit,
    /// while the conversation is in progress.
    ///
    /// After the conversation has finished, the circuit may be extended.
    /// Or, `start_conversation` may be called again;
    /// but, in that case there will be a gap between the two conversations,
    /// during which no `MsgHandler` is installed,
    /// and unexpected incoming messages would close the circuit.
    ///
    /// If these restrictions are violated, the circuit will be closed with an error.
    ///
    /// ## Precise definition of the lifetime of a conversation
    ///
    /// A conversation is in progress from entry to `start_conversation`,
    /// until entry to the body of the [`MsgHandler::handle_msg`]
    /// call which returns [`ConversationFinished`](MetaCellDisposition::ConversationFinished).
    /// (*Entry* since `handle_msg` is synchronously embedded
    /// into the incoming message processing.)
    /// So you may start a new conversation as soon as you have the final response
    /// via your inter-task channel from (0) above.
    ///
    /// The lifetime relationship of the [`Conversation`],
    /// vs the handler returning `ConversationFinished`
    /// is not enforced by the type system.
    // Doing so without still leaving plenty of scope for runtime errors doesn't seem possible,
    // at least while allowing sending followup messages from outside the handler.
    //
    // TODO hs: it might be nice to avoid exposing tor-cell APIs in the
    //   tor-proto interface.
    #[cfg(feature = "send-control-msg")]
    pub async fn start_conversation(
        &self,
        msg: Option<tor_cell::relaycell::msg::AnyRelayMsg>,
        reply_handler: impl MsgHandler + Send + 'static,
        hop_num: HopNum,
    ) -> Result<Conversation<'_>> {
        let handler = Box::new(msghandler::UserMsgHandler::new(hop_num, reply_handler));
        let conversation = Conversation(self);
        conversation.send_internal(msg, Some(handler)).await?;
        Ok(conversation)
    }

    /// Start an ad-hoc protocol exchange to the final hop on this circuit
    ///
    /// See the [`ClientCirc::start_conversation`] docs for more information.
    #[cfg(feature = "send-control-msg")]
    #[deprecated(since = "0.13.0", note = "Use start_conversation instead.")]
    pub async fn start_conversation_last_hop(
        &self,
        msg: Option<tor_cell::relaycell::msg::AnyRelayMsg>,
        reply_handler: impl MsgHandler + Send + 'static,
    ) -> Result<Conversation<'_>> {
        let last_hop = self
            .mutable
            .lock()
            .expect("poisoned lock")
            .path
            .last_hop_num()
            .ok_or_else(|| internal!("no last hop index"))?;

        self.start_conversation(msg, reply_handler, last_hop).await
    }

    /// Send an ad-hoc message to a given hop on the circuit, without expecting
    /// a reply.
    ///
    /// (If you want to handle one or more possible replies, see
    /// [`ClientCirc::start_conversation`].)
    #[cfg(feature = "send-control-msg")]
    pub async fn send_raw_msg(
        &self,
        msg: tor_cell::relaycell::msg::AnyRelayMsg,
        hop_num: HopNum,
    ) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        let ctrl_msg = CtrlMsg::SendMsg {
            hop_num,
            msg,
            sender,
        };
        self.control
            .unbounded_send(ctrl_msg)
            .map_err(|_| Error::CircuitClosed)?;

        receiver.await.map_err(|_| Error::CircuitClosed)?
    }

    /// Tell this circuit to begin allowing the final hop of the circuit to try
    /// to create new Tor streams, and to return those pending requests in an
    /// asynchronous stream.
    ///
    /// Ordinarily, these requests are rejected.
    ///
    /// There can only be one [`Stream`](futures::Stream) of this type created on a given circuit.
    /// If a such a [`Stream`](futures::Stream) already exists, this method will return
    /// an error.
    ///
    /// After this method has been called on a circuit, the circuit is expected
    /// to receive requests of this type indefinitely, until it is finally closed.
    /// If the `Stream` is dropped, the next request on this circuit will cause it to close.
    ///
    /// Only onion services (and eventually) exit relays should call this
    /// method.
    //
    // TODO: Someday, we might want to allow a stream request handler to be
    // un-registered.  However, nothing in the Tor protocol requires it.
    #[cfg(feature = "hs-service")]
    pub async fn allow_stream_requests(
        self: &Arc<ClientCirc>,
        allow_commands: &[tor_cell::relaycell::RelayCmd],
        hop_num: HopNum,
        filter: impl crate::stream::IncomingStreamRequestFilter,
    ) -> Result<impl futures::Stream<Item = IncomingStream>> {
        use futures::stream::StreamExt;

        /// The size of the channel receiving IncomingStreamRequestContexts.
        const INCOMING_BUFFER: usize = STREAM_READER_BUFFER;

        let cmd_checker = IncomingCmdChecker::new_any(allow_commands);
        let (incoming_sender, incoming_receiver) = mpsc::channel(INCOMING_BUFFER);
        let (tx, rx) = oneshot::channel();

        self.control
            .unbounded_send(CtrlMsg::AwaitStreamRequest {
                cmd_checker,
                incoming_sender,
                hop_num,
                done: tx,
                filter: Box::new(filter),
            })
            .map_err(|_| Error::CircuitClosed)?;

        // Check whether the AwaitStreamRequest was processed successfully.
        rx.await.map_err(|_| Error::CircuitClosed)??;

        let allowed_hop_num = hop_num;

        let circ = Arc::clone(self);
        Ok(incoming_receiver.map(move |req_ctx| {
            let StreamReqInfo {
                req,
                stream_id,
                hop_num,
                receiver,
                msg_tx,
            } = req_ctx;

            // We already enforce this in handle_incoming_stream_request; this
            // assertion is just here to make sure that we don't ever
            // accidentally remove or fail to enforce that check, since it is
            // security-critical.
            assert_eq!(allowed_hop_num, hop_num);

            let target = StreamTarget {
                circ: Arc::clone(&circ),
                tx: msg_tx,
                hop_num,
                stream_id,
            };

            let reader = StreamReader {
                target: target.clone(),
                receiver,
                recv_window: StreamRecvWindow::new(RECV_WINDOW_INIT),
                ended: false,
            };

            IncomingStream::new(req, target, reader)
        }))
    }

    /// Extend the circuit via the ntor handshake to a new target last
    /// hop.
    pub async fn extend_ntor<Tg>(&self, target: &Tg, params: &CircParameters) -> Result<()>
    where
        Tg: CircTarget,
    {
        let key = NtorPublicKey {
            id: *target
                .rsa_identity()
                .ok_or(Error::MissingId(RelayIdType::Rsa))?,
            pk: *target.ntor_onion_key(),
        };
        let mut linkspecs = target
            .linkspecs()
            .map_err(into_internal!("Could not encode linkspecs for extend_ntor"))?;
        if !params.extend_by_ed25519_id() {
            linkspecs.retain(|ls| ls.lstype() != LinkSpecType::ED25519ID);
        }

        let (tx, rx) = oneshot::channel();

        let peer_id = OwnedChanTarget::from_chan_target(target);
        self.control
            .unbounded_send(CtrlMsg::ExtendNtor {
                peer_id,
                public_key: key,
                linkspecs,
                params: params.clone(),
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)??;

        Ok(())
    }

    /// Extend the circuit via the ntor handshake to a new target last
    /// hop.
    #[cfg(feature = "ntor_v3")]
    pub async fn extend_ntor_v3<Tg>(&self, target: &Tg, params: &CircParameters) -> Result<()>
    where
        Tg: CircTarget,
    {
        let key = NtorV3PublicKey {
            id: *target
                .ed_identity()
                .ok_or(Error::MissingId(RelayIdType::Ed25519))?,
            pk: *target.ntor_onion_key(),
        };
        let mut linkspecs = target
            .linkspecs()
            .map_err(into_internal!("Could not encode linkspecs for extend_ntor"))?;
        if !params.extend_by_ed25519_id() {
            linkspecs.retain(|ls| ls.lstype() != LinkSpecType::ED25519ID);
        }

        let (tx, rx) = oneshot::channel();

        let peer_id = OwnedChanTarget::from_chan_target(target);
        self.control
            .unbounded_send(CtrlMsg::ExtendNtorV3 {
                peer_id,
                public_key: key,
                linkspecs,
                params: params.clone(),
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)??;

        Ok(())
    }

    /// Extend this circuit by a single, "virtual" hop.
    ///
    /// A virtual hop is one for which we do not add an actual network connection
    /// between separate hosts (such as Relays).  We only add a layer of
    /// cryptography.
    ///
    /// This is used to implement onion services: the client and the service
    /// both build a circuit to a single rendezvous point, and tell the
    /// rendezvous point to relay traffic between their two circuits.  Having
    /// completed a [`handshake`] out of band[^1], the parties each extend their
    /// circuits by a single "virtual" encryption hop that represents their
    /// shared cryptographic context.
    ///
    /// Once a circuit has been extended in this way, it is an error to try to
    /// extend it in any other way.
    ///
    /// [^1]: Technically, the handshake is only _mostly_ out of band: the
    ///     client sends their half of the handshake in an ` message, and the
    ///     service's response is inline in its `RENDEZVOUS2` message.
    //
    // TODO hs: let's try to enforce the "you can't extend a circuit again once
    // it has been extended this way" property.  We could do that with internal
    // state, or some kind of a type state pattern.
    //
    // TODO hs: possibly we should take a set of Protovers, and not just `Params`.
    #[cfg(feature = "hs-common")]
    pub async fn extend_virtual(
        &self,
        protocol: handshake::RelayProtocol,
        role: handshake::HandshakeRole,
        seed: impl handshake::KeyGenerator,
        params: CircParameters,
    ) -> Result<()> {
        use self::handshake::BoxedClientLayer;

        let protocol = handshake::RelayCryptLayerProtocol::from(protocol);
        let relay_cell_format = protocol.relay_cell_format();

        let BoxedClientLayer { fwd, back, binding } = protocol.construct_layers(role, seed)?;

        let (tx, rx) = oneshot::channel();
        let message = CtrlMsg::ExtendVirtual {
            relay_cell_format,
            cell_crypto: (fwd, back, binding),
            params,
            done: tx,
        };

        self.control
            .unbounded_send(message)
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)?
    }

    /// Helper, used to begin a stream.
    ///
    /// This function allocates a stream ID, and sends the message
    /// (like a BEGIN or RESOLVE), but doesn't wait for a response.
    ///
    /// The caller will typically want to see the first cell in response,
    /// to see whether it is e.g. an END or a CONNECTED.
    async fn begin_stream_impl(
        self: &Arc<ClientCirc>,
        begin_msg: AnyRelayMsg,
        cmd_checker: AnyCmdChecker,
    ) -> Result<(StreamReader, StreamTarget)> {
        // TODO: Possibly this should take a hop, rather than just
        // assuming it's the last hop.

        let hop_num = self
            .mutable
            .lock()
            .expect("poisoned lock")
            .path
            .last_hop_num()
            .ok_or_else(|| Error::from(internal!("Can't begin a stream at the 0th hop")))?;

        let (sender, receiver) = mpsc::channel(STREAM_READER_BUFFER);
        let (tx, rx) = oneshot::channel();
        let (msg_tx, msg_rx) = mpsc::channel(CIRCUIT_BUFFER_SIZE);

        self.control
            .unbounded_send(CtrlMsg::BeginStream {
                hop_num,
                message: begin_msg,
                sender,
                rx: msg_rx,
                done: tx,
                cmd_checker,
            })
            .map_err(|_| Error::CircuitClosed)?;

        let stream_id = rx.await.map_err(|_| Error::CircuitClosed)??;

        let target = StreamTarget {
            circ: self.clone(),
            tx: msg_tx,
            hop_num,
            stream_id,
        };

        let reader = StreamReader {
            target: target.clone(),
            receiver,
            recv_window: StreamRecvWindow::new(RECV_WINDOW_INIT),
            ended: false,
        };

        Ok((reader, target))
    }

    /// Start a DataStream (anonymized connection) to the given
    /// address and port, using a BEGIN cell.
    async fn begin_data_stream(
        self: &Arc<ClientCirc>,
        msg: AnyRelayMsg,
        optimistic: bool,
    ) -> Result<DataStream> {
        let (reader, target) = self
            .begin_stream_impl(msg, DataCmdChecker::new_any())
            .await?;
        let mut stream = DataStream::new(reader, target);
        if !optimistic {
            stream.wait_for_connection().await?;
        }
        Ok(stream)
    }

    /// Start a stream to the given address and port, using a BEGIN
    /// cell.
    ///
    /// The use of a string for the address is intentional: you should let
    /// the remote Tor relay do the hostname lookup for you.
    pub async fn begin_stream(
        self: &Arc<ClientCirc>,
        target: &str,
        port: u16,
        parameters: Option<StreamParameters>,
    ) -> Result<DataStream> {
        let parameters = parameters.unwrap_or_default();
        let begin_flags = parameters.begin_flags();
        let optimistic = parameters.is_optimistic();
        let target = if parameters.suppressing_hostname() {
            ""
        } else {
            target
        };
        let beginmsg = Begin::new(target, port, begin_flags)
            .map_err(|e| Error::from_cell_enc(e, "begin message"))?;
        self.begin_data_stream(beginmsg.into(), optimistic).await
    }

    /// Start a new stream to the last relay in the circuit, using
    /// a BEGIN_DIR cell.
    pub async fn begin_dir_stream(self: Arc<ClientCirc>) -> Result<DataStream> {
        // Note that we always open begindir connections optimistically.
        // Since they are local to a relay that we've already authenticated
        // with and built a circuit to, there should be no additional checks
        // we need to perform to see whether the BEGINDIR will succeed.
        self.begin_data_stream(AnyRelayMsg::BeginDir(Default::default()), true)
            .await
    }

    /// Perform a DNS lookup, using a RESOLVE cell with the last relay
    /// in this circuit.
    ///
    /// Note that this function does not check for timeouts; that's
    /// the caller's responsibility.
    pub async fn resolve(self: &Arc<ClientCirc>, hostname: &str) -> Result<Vec<IpAddr>> {
        let resolve_msg = Resolve::new(hostname);

        let resolved_msg = self.try_resolve(resolve_msg).await?;

        resolved_msg
            .into_answers()
            .into_iter()
            .filter_map(|(val, _)| match resolvedval_to_result(val) {
                Ok(ResolvedVal::Ip(ip)) => Some(Ok(ip)),
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            })
            .collect()
    }

    /// Perform a reverse DNS lookup, by sending a RESOLVE cell with
    /// the last relay on this circuit.
    ///
    /// Note that this function does not check for timeouts; that's
    /// the caller's responsibility.
    pub async fn resolve_ptr(self: &Arc<ClientCirc>, addr: IpAddr) -> Result<Vec<String>> {
        let resolve_ptr_msg = Resolve::new_reverse(&addr);

        let resolved_msg = self.try_resolve(resolve_ptr_msg).await?;

        resolved_msg
            .into_answers()
            .into_iter()
            .filter_map(|(val, _)| match resolvedval_to_result(val) {
                Ok(ResolvedVal::Hostname(v)) => Some(
                    String::from_utf8(v)
                        .map_err(|_| Error::StreamProto("Resolved Hostname was not utf-8".into())),
                ),
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            })
            .collect()
    }

    /// Helper: Send the resolve message, and read resolved message from
    /// resolve stream.
    async fn try_resolve(self: &Arc<ClientCirc>, msg: Resolve) -> Result<Resolved> {
        let (reader, _) = self
            .begin_stream_impl(msg.into(), ResolveCmdChecker::new_any())
            .await?;
        let mut resolve_stream = ResolveStream::new(reader);
        resolve_stream.read_msg().await
    }

    /// Shut down this circuit, along with all streams that are using it.
    /// Happens asynchronously (i.e. the circuit won't necessarily be done shutting down
    /// immediately after this function returns!).
    ///
    /// Note that other references to this circuit may exist.  If they
    /// do, they will stop working after you call this function.
    ///
    /// It's not necessary to call this method if you're just done
    /// with a circuit: the circuit should close on its own once nothing
    /// is using it any more.
    pub fn terminate(&self) {
        let _ = self.control.unbounded_send(CtrlMsg::Shutdown);
    }

    /// Called when a circuit-level protocol error has occurred and the
    /// circuit needs to shut down.
    ///
    /// This is a separate function because we may eventually want to have
    /// it do more than just shut down.
    ///
    /// As with `terminate`, this function is asynchronous.
    pub(crate) fn protocol_error(&self) {
        self.terminate();
    }

    /// Return true if this circuit is closed and therefore unusable.
    pub fn is_closing(&self) -> bool {
        self.control.is_closed()
    }

    /// Return a process-unique identifier for this circuit.
    pub fn unique_id(&self) -> UniqId {
        self.unique_id
    }

    /// Return the number of hops in this circuit.
    ///
    /// NOTE: This function will currently return only the number of hops
    /// _currently_ in the circuit. If there is an extend operation in progress,
    /// the currently pending hop may or may not be counted, depending on whether
    /// the extend operation finishes before this call is done.
    pub fn n_hops(&self) -> usize {
        self.mutable.lock().expect("poisoned lock").path.n_hops()
    }

    /// Return a future that will resolve once this circuit has closed.
    ///
    /// Note that this method does not itself cause the circuit to shut down.
    ///
    /// TODO: Perhaps this should return some kind of status indication instead
    /// of just ()
    #[cfg(feature = "experimental-api")]
    pub fn wait_for_close(&self) -> impl futures::Future<Output = ()> + Send + Sync + 'static {
        self.reactor_closed_rx.clone().map(|_| ())
    }
}

/// Handle to use during an ongoing protocol exchange with a circuit's last hop
///
/// This is obtained from [`ClientCirc::start_conversation`],
/// and used to send messages to the last hop relay.
///
/// See also [`ConversationInHandler`], which is a type used for the same purpose
/// but available only inside [`MsgHandler::handle_msg`].
#[cfg(feature = "send-control-msg")]
#[cfg_attr(docsrs, doc(cfg(feature = "send-control-msg")))]
pub struct Conversation<'r>(&'r ClientCirc);

#[cfg(feature = "send-control-msg")]
#[cfg_attr(docsrs, doc(cfg(feature = "send-control-msg")))]
impl Conversation<'_> {
    /// Send a protocol message as part of an ad-hoc exchange
    ///
    /// Responses are handled by the `MsgHandler` set up
    /// when the `Conversation` was created.
    pub async fn send_message(&self, msg: tor_cell::relaycell::msg::AnyRelayMsg) -> Result<()> {
        self.send_internal(Some(msg), None).await
    }

    /// Send a `SendMsgAndInstallHandler` to the reactor and wait for the outcome
    ///
    /// The guts of `start_conversation` and `Conversation::send_msg`
    async fn send_internal(
        &self,
        msg: Option<tor_cell::relaycell::msg::AnyRelayMsg>,
        handler: Option<Box<dyn MetaCellHandler + Send + 'static>>,
    ) -> Result<()> {
        let msg = msg.map(|msg| tor_cell::relaycell::AnyRelayMsgOuter::new(None, msg));
        let (sender, receiver) = oneshot::channel();

        let ctrl_msg = CtrlMsg::SendMsgAndInstallHandler {
            msg,
            handler,
            sender,
        };
        self.0
            .control
            .unbounded_send(ctrl_msg)
            .map_err(|_| Error::CircuitClosed)?;

        receiver.await.map_err(|_| Error::CircuitClosed)?
    }
}

impl PendingClientCirc {
    /// Instantiate a new circuit object: used from Channel::new_circ().
    ///
    /// Does not send a CREATE* cell on its own.
    ///
    ///
    pub(crate) fn new(
        id: CircId,
        channel: Arc<Channel>,
        createdreceiver: oneshot::Receiver<CreateResponse>,
        input: mpsc::Receiver<ClientCircChanMsg>,
        unique_id: UniqId,
    ) -> (PendingClientCirc, reactor::Reactor) {
        let (reactor, control_tx, reactor_closed_rx, mutable) =
            Reactor::new(channel.clone(), id, unique_id, input);

        let circuit = ClientCirc {
            mutable,
            unique_id,
            control: control_tx,
            reactor_closed_rx: reactor_closed_rx.shared(),
            channel,
            #[cfg(test)]
            circid: id,
        };

        let pending = PendingClientCirc {
            recvcreated: createdreceiver,
            circ: Arc::new(circuit),
        };
        (pending, reactor)
    }

    /// Extract the process-unique identifier for this pending circuit.
    pub fn peek_unique_id(&self) -> UniqId {
        self.circ.unique_id
    }

    /// Use the (questionable!) CREATE_FAST handshake to connect to the
    /// first hop of this circuit.
    ///
    /// There's no authentication in CRATE_FAST,
    /// so we don't need to know whom we're connecting to: we're just
    /// connecting to whichever relay the channel is for.
    pub async fn create_firsthop_fast(self, params: &CircParameters) -> Result<Arc<ClientCirc>> {
        let (tx, rx) = oneshot::channel();
        self.circ
            .control
            .unbounded_send(CtrlMsg::Create {
                recv_created: self.recvcreated,
                handshake: CircuitHandshake::CreateFast,
                params: params.clone(),
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)??;

        Ok(self.circ)
    }

    /// Use the ntor handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided 'target' must match the channel's target,
    /// or the handshake will fail.
    pub async fn create_firsthop_ntor<Tg>(
        self,
        target: &Tg,
        params: CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        Tg: tor_linkspec::CircTarget,
    {
        let (tx, rx) = oneshot::channel();

        self.circ
            .control
            .unbounded_send(CtrlMsg::Create {
                recv_created: self.recvcreated,
                handshake: CircuitHandshake::Ntor {
                    public_key: NtorPublicKey {
                        id: *target
                            .rsa_identity()
                            .ok_or(Error::MissingId(RelayIdType::Rsa))?,
                        pk: *target.ntor_onion_key(),
                    },
                    ed_identity: *target
                        .ed_identity()
                        .ok_or(Error::MissingId(RelayIdType::Ed25519))?,
                },
                params: params.clone(),
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)??;

        Ok(self.circ)
    }

    /// Use the ntor_v3 handshake to connect to the first hop of this circuit.
    ///
    /// Assumes that the target supports ntor_v3. The caller should verify
    /// this before calling this function, e.g. by validating that the target
    /// has advertised ["Relay=4"](https://spec.torproject.org/tor-spec/subprotocol-versioning.html#relay).
    ///
    /// Note that the provided 'target' must match the channel's target,
    /// or the handshake will fail.
    #[cfg(feature = "ntor_v3")]
    pub async fn create_firsthop_ntor_v3<Tg>(
        self,
        target: &Tg,
        params: CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        Tg: tor_linkspec::CircTarget,
    {
        let (tx, rx) = oneshot::channel();

        self.circ
            .control
            .unbounded_send(CtrlMsg::Create {
                recv_created: self.recvcreated,
                handshake: CircuitHandshake::NtorV3 {
                    public_key: NtorV3PublicKey {
                        id: *target
                            .ed_identity()
                            .ok_or(Error::MissingId(RelayIdType::Ed25519))?,
                        pk: *target.ntor_onion_key(),
                    },
                },
                params: params.clone(),
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)??;

        Ok(self.circ)
    }
}

/// An object that can put a given handshake into a ChanMsg for a CREATE*
/// cell, and unwrap a CREATED* cell.
trait CreateHandshakeWrap {
    /// Construct an appropriate ChanMsg to hold this kind of handshake.
    fn to_chanmsg(&self, bytes: Vec<u8>) -> AnyChanMsg;
    /// Decode a ChanMsg to an appropriate handshake value, checking
    /// its type.
    fn decode_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>>;
}

/// A CreateHandshakeWrap that generates CREATE_FAST and handles CREATED_FAST.
struct CreateFastWrap;

impl CreateHandshakeWrap for CreateFastWrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> AnyChanMsg {
        chancell::msg::CreateFast::new(bytes).into()
    }
    fn decode_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>> {
        use CreateResponse::*;
        match msg {
            CreatedFast(m) => Ok(m.into_handshake()),
            Destroy(_) => Err(Error::CircRefused(
                "Relay replied to CREATE_FAST with DESTROY.",
            )),
            _ => Err(Error::CircProto(format!(
                "Relay replied to CREATE_FAST with unexpected cell: {}",
                msg
            ))),
        }
    }
}

/// A CreateHandshakeWrap that generates CREATE2 and handles CREATED2
struct Create2Wrap {
    /// The handshake type to put in the CREATE2 cell.
    handshake_type: HandshakeType,
}
impl CreateHandshakeWrap for Create2Wrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> AnyChanMsg {
        chancell::msg::Create2::new(self.handshake_type, bytes).into()
    }
    fn decode_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>> {
        use CreateResponse::*;
        match msg {
            Created2(m) => Ok(m.into_body()),
            Destroy(_) => Err(Error::CircRefused("Relay replied to CREATE2 with DESTROY.")),
            _ => Err(Error::CircProto(format!(
                "Relay replied to CREATE2 with unexpected cell {}",
                msg
            ))),
        }
    }
}

impl StreamTarget {
    /// Deliver a relay message for the stream that owns this StreamTarget.
    ///
    /// The StreamTarget will set the correct stream ID and pick the
    /// right hop, but will not validate that the message is well-formed
    /// or meaningful in context.
    pub(crate) async fn send(&mut self, msg: AnyRelayMsg) -> Result<()> {
        self.tx.send(msg).await.map_err(|_| Error::CircuitClosed)?;
        Ok(())
    }

    /// Close the pending stream that owns this StreamTarget, delivering the specified
    /// END message (if any)
    ///
    /// The stream is closed by sending a [`CtrlMsg::ClosePendingStream`] message to the reactor.
    ///
    /// Returns a [`oneshot::Receiver`] that can be used to await the reactor's response.
    ///
    /// The StreamTarget will set the correct stream ID and pick the
    /// right hop, but will not validate that the message is well-formed
    /// or meaningful in context.
    ///
    /// Note that in many cases, the actual contents of an END message can leak unwanted
    /// information. Please consider carefully before sending anything but an
    /// [`End::new_misc()`](tor_cell::relaycell::msg::End::new_misc) message over a `ClientCirc`.
    /// (For onion services, we send [`DONE`](tor_cell::relaycell::msg::EndReason::DONE) )
    ///
    /// In addition to sending the END message, this function also ensures
    /// the state of the stream map entry of this stream is updated
    /// accordingly.
    ///
    /// Normally, you shouldn't need to call this function, as streams are implicitly closed by the
    /// reactor when their corresponding `StreamTarget` is dropped. The only valid use of this
    /// function is for closing pending incoming streams (a stream is said to be pending if we have
    /// received the message initiating the stream but have not responded to it yet).
    ///
    /// **NOTE**: This function should be called at most once per request.
    /// Calling it twice is an error.
    #[cfg(feature = "hs-service")]
    pub(crate) fn close_pending(
        &self,
        message: reactor::CloseStreamBehavior,
    ) -> Result<oneshot::Receiver<Result<()>>> {
        let (tx, rx) = oneshot::channel();

        self.circ
            .control
            .unbounded_send(CtrlMsg::ClosePendingStream {
                stream_id: self.stream_id,
                hop_num: self.hop_num,
                message,
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        Ok(rx)
    }

    /// Queue a "close" for the stream corresponding to this StreamTarget.
    ///
    /// Unlike `close_pending`, this method does not allow the caller to provide an `END` message.
    ///
    /// Once this method has been called, no more messages may be sent with [`StreamTarget::send`],
    /// on this `StreamTarget`` or any clone of it.
    /// The reactor *will* try to flush any already-send messages before it closes the stream.
    ///
    /// You don't need to call this method if the stream is closing because all of its StreamTargets
    /// have been dropped.
    pub(crate) fn close(&mut self) {
        self.tx.close_channel();
    }

    /// Called when a circuit-level protocol error has occurred and the
    /// circuit needs to shut down.
    pub(crate) fn protocol_error(&mut self) {
        self.circ.protocol_error();
    }

    /// Send a SENDME cell for this stream.
    pub(crate) fn send_sendme(&mut self) -> Result<()> {
        self.circ
            .control
            .unbounded_send(CtrlMsg::SendSendme {
                stream_id: self.stream_id,
                hop_num: self.hop_num,
            })
            .map_err(|_| Error::CircuitClosed)?;
        Ok(())
    }

    /// Return a reference to the circuit that this `StreamTarget` is using.
    #[cfg(any(feature = "experimental-api", feature = "stream-ctrl"))]
    pub(crate) fn circuit(&self) -> &Arc<ClientCirc> {
        &self.circ
    }
}

/// Convert a [`ResolvedVal`] into a Result, based on whether or not
/// it represents an error.
fn resolvedval_to_result(val: ResolvedVal) -> Result<ResolvedVal> {
    match val {
        ResolvedVal::TransientError => Err(Error::ResolveError(ResolveError::Transient)),
        ResolvedVal::NontransientError => Err(Error::ResolveError(ResolveError::Nontransient)),
        ResolvedVal::Unrecognized(_, _) => Err(Error::ResolveError(ResolveError::Unrecognized)),
        _ => Ok(val),
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::channel::OpenChanCellS2C;
    use crate::channel::{test::new_reactor, CodecError};
    use crate::crypto::cell::RelayCellBody;
    #[cfg(feature = "ntor_v3")]
    use crate::crypto::handshake::ntor_v3::NtorV3Server;
    #[cfg(feature = "hs-service")]
    use crate::stream::IncomingStreamRequestFilter;
    use chanmsg::{AnyChanMsg, Created2, CreatedFast};
    use futures::channel::mpsc::{Receiver, Sender};
    use futures::io::{AsyncReadExt, AsyncWriteExt};
    use futures::sink::SinkExt;
    use futures::stream::StreamExt;
    use futures::task::SpawnExt;
    use hex_literal::hex;
    use std::collections::{HashMap, VecDeque};
    use std::time::Duration;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_cell::chancell::{msg as chanmsg, AnyChanCell, BoxedCellBody};
    use tor_cell::relaycell::extend::NtorV3Extension;
    use tor_cell::relaycell::{
        msg as relaymsg, AnyRelayMsgOuter, RelayCellFormat, RelayCmd, RelayMsg as _, StreamId,
    };
    use tor_linkspec::OwnedCircTarget;
    use tor_rtcompat::{Runtime, SleepProvider};
    use tracing::trace;

    impl PendingClientCirc {
        /// Testing only: Extract the circuit ID for this pending circuit.
        pub(crate) fn peek_circid(&self) -> CircId {
            self.circ.circid
        }
    }

    impl ClientCirc {
        /// Testing only: Extract the circuit ID of this circuit.
        pub(crate) fn peek_circid(&self) -> CircId {
            self.circid
        }
    }

    fn rmsg_to_ccmsg(id: Option<StreamId>, msg: relaymsg::AnyRelayMsg) -> ClientCircChanMsg {
        let body: BoxedCellBody = AnyRelayMsgOuter::new(id, msg)
            .encode(&mut testing_rng())
            .unwrap();
        let chanmsg = chanmsg::Relay::from(body);
        ClientCircChanMsg::Relay(chanmsg)
    }

    // Example relay IDs and keys
    const EXAMPLE_SK: [u8; 32] =
        hex!("7789d92a89711a7e2874c61ea495452cfd48627b3ca2ea9546aafa5bf7b55803");
    const EXAMPLE_PK: [u8; 32] =
        hex!("395cb26b83b3cd4b91dba9913e562ae87d21ecdd56843da7ca939a6a69001253");
    const EXAMPLE_ED_ID: [u8; 32] = [6; 32];
    const EXAMPLE_RSA_ID: [u8; 20] = [10; 20];

    /// return an example OwnedCircTarget that can get used for an ntor handshake.
    fn example_target() -> OwnedCircTarget {
        let mut builder = OwnedCircTarget::builder();
        builder
            .chan_target()
            .ed_identity(EXAMPLE_ED_ID.into())
            .rsa_identity(EXAMPLE_RSA_ID.into());
        builder
            .ntor_onion_key(EXAMPLE_PK.into())
            .protocols("FlowCtrl=1".parse().unwrap())
            .build()
            .unwrap()
    }
    fn example_ntor_key() -> crate::crypto::handshake::ntor::NtorSecretKey {
        crate::crypto::handshake::ntor::NtorSecretKey::new(
            EXAMPLE_SK.into(),
            EXAMPLE_PK.into(),
            EXAMPLE_RSA_ID.into(),
        )
    }
    #[cfg(feature = "ntor_v3")]
    fn example_ntor_v3_key() -> crate::crypto::handshake::ntor_v3::NtorV3SecretKey {
        crate::crypto::handshake::ntor_v3::NtorV3SecretKey::new(
            EXAMPLE_SK.into(),
            EXAMPLE_PK.into(),
            EXAMPLE_ED_ID.into(),
        )
    }

    fn working_fake_channel<R: Runtime>(
        rt: &R,
    ) -> (
        Arc<Channel>,
        Receiver<AnyChanCell>,
        Sender<std::result::Result<OpenChanCellS2C, CodecError>>,
    ) {
        let (channel, chan_reactor, rx, tx) = new_reactor(rt.clone());
        rt.spawn(async {
            let _ignore = chan_reactor.run().await;
        })
        .unwrap();
        (channel, rx, tx)
    }

    /// Which handshake type to use.
    #[derive(Copy, Clone)]
    enum HandshakeType {
        Fast,
        Ntor,
        #[cfg(feature = "ntor_v3")]
        NtorV3,
    }

    async fn test_create<R: Runtime>(rt: &R, handshake_type: HandshakeType) {
        // We want to try progressing from a pending circuit to a circuit
        // via a crate_fast handshake.

        use crate::crypto::handshake::{fast::CreateFastServer, ntor::NtorServer, ServerHandshake};

        let (chan, mut rx, _sink) = working_fake_channel(rt);
        let circid = CircId::new(128).unwrap();
        let (created_send, created_recv) = oneshot::channel();
        let (_circmsg_send, circmsg_recv) = mpsc::channel(64);
        let unique_id = UniqId::new(23, 17);

        let (pending, reactor) =
            PendingClientCirc::new(circid, chan, created_recv, circmsg_recv, unique_id);

        rt.spawn(async {
            let _ignore = reactor.run().await;
        })
        .unwrap();

        // Future to pretend to be a relay on the other end of the circuit.
        let simulate_relay_fut = async move {
            let mut rng = testing_rng();
            let create_cell = rx.next().await.unwrap();
            assert_eq!(create_cell.circid(), Some(circid));
            let reply = match handshake_type {
                HandshakeType::Fast => {
                    let cf = match create_cell.msg() {
                        AnyChanMsg::CreateFast(cf) => cf,
                        _ => panic!(),
                    };
                    let (_, rep) = CreateFastServer::server(
                        &mut rng,
                        &mut |_: &()| Some(()),
                        &[()],
                        cf.handshake(),
                    )
                    .unwrap();
                    CreateResponse::CreatedFast(CreatedFast::new(rep))
                }
                HandshakeType::Ntor => {
                    let c2 = match create_cell.msg() {
                        AnyChanMsg::Create2(c2) => c2,
                        _ => panic!(),
                    };
                    let (_, rep) = NtorServer::server(
                        &mut rng,
                        &mut |_: &()| Some(()),
                        &[example_ntor_key()],
                        c2.body(),
                    )
                    .unwrap();
                    CreateResponse::Created2(Created2::new(rep))
                }
                #[cfg(feature = "ntor_v3")]
                HandshakeType::NtorV3 => {
                    let c2 = match create_cell.msg() {
                        AnyChanMsg::Create2(c2) => c2,
                        _ => panic!(),
                    };
                    let (_, rep) = NtorV3Server::server(
                        &mut rng,
                        &mut |_: &_| Some(vec![]),
                        &[example_ntor_v3_key()],
                        c2.body(),
                    )
                    .unwrap();
                    CreateResponse::Created2(Created2::new(rep))
                }
            };
            created_send.send(reply).unwrap();
        };
        // Future to pretend to be a client.
        let client_fut = async move {
            let target = example_target();
            let params = CircParameters::default();
            let ret = match handshake_type {
                HandshakeType::Fast => {
                    trace!("doing fast create");
                    pending.create_firsthop_fast(&params).await
                }
                HandshakeType::Ntor => {
                    trace!("doing ntor create");
                    pending.create_firsthop_ntor(&target, params).await
                }
                #[cfg(feature = "ntor_v3")]
                HandshakeType::NtorV3 => {
                    trace!("doing ntor_v3 create");
                    pending.create_firsthop_ntor_v3(&target, params).await
                }
            };
            trace!("create done: result {:?}", ret);
            ret
        };

        let (circ, _) = futures::join!(client_fut, simulate_relay_fut);

        let _circ = circ.unwrap();

        // pfew!  We've build a circuit!  Let's make sure it has one hop.
        /* TODO: reinstate this.
        let inner = Arc::get_mut(&mut circuit).unwrap().c.into_inner();
        assert_eq!(inner.hops.len(), 1);
         */
    }

    #[test]
    fn test_create_fast() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_create(&rt, HandshakeType::Fast).await;
        });
    }
    #[test]
    fn test_create_ntor() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_create(&rt, HandshakeType::Ntor).await;
        });
    }
    #[cfg(feature = "ntor_v3")]
    #[test]
    fn test_create_ntor_v3() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_create(&rt, HandshakeType::NtorV3).await;
        });
    }

    // An encryption layer that doesn't do any crypto.   Can be used
    // as inbound or outbound, but not both at once.
    pub(crate) struct DummyCrypto {
        counter_tag: [u8; 20],
        counter: u32,
        lasthop: bool,
    }
    impl DummyCrypto {
        fn next_tag(&mut self) -> &[u8; 20] {
            #![allow(clippy::identity_op)]
            self.counter_tag[0] = ((self.counter >> 0) & 255) as u8;
            self.counter_tag[1] = ((self.counter >> 8) & 255) as u8;
            self.counter_tag[2] = ((self.counter >> 16) & 255) as u8;
            self.counter_tag[3] = ((self.counter >> 24) & 255) as u8;
            self.counter += 1;
            &self.counter_tag
        }
    }

    impl crate::crypto::cell::OutboundClientLayer for DummyCrypto {
        fn originate_for(&mut self, _cell: &mut RelayCellBody) -> &[u8] {
            self.next_tag()
        }
        fn encrypt_outbound(&mut self, _cell: &mut RelayCellBody) {}
    }
    impl crate::crypto::cell::InboundClientLayer for DummyCrypto {
        fn decrypt_inbound(&mut self, _cell: &mut RelayCellBody) -> Option<&[u8]> {
            if self.lasthop {
                Some(self.next_tag())
            } else {
                None
            }
        }
    }
    impl DummyCrypto {
        pub(crate) fn new(lasthop: bool) -> Self {
            DummyCrypto {
                counter_tag: [0; 20],
                counter: 0,
                lasthop,
            }
        }
    }

    // Helper: set up a 3-hop circuit with no encryption, where the
    // next inbound message seems to come from hop next_msg_from
    async fn newcirc_ext<R: Runtime>(
        rt: &R,
        chan: Arc<Channel>,
        next_msg_from: HopNum,
    ) -> (Arc<ClientCirc>, mpsc::Sender<ClientCircChanMsg>) {
        let circid = CircId::new(128).unwrap();
        let (_created_send, created_recv) = oneshot::channel();
        let (circmsg_send, circmsg_recv) = mpsc::channel(64);
        let unique_id = UniqId::new(23, 17);

        let (pending, reactor) =
            PendingClientCirc::new(circid, chan, created_recv, circmsg_recv, unique_id);

        rt.spawn(async {
            let _ignore = reactor.run().await;
        })
        .unwrap();

        let PendingClientCirc {
            circ,
            recvcreated: _,
        } = pending;

        // TODO #1067: Support other formats
        let relay_cell_format = RelayCellFormat::V0;
        for idx in 0_u8..3 {
            let params = CircParameters::default();
            let (tx, rx) = oneshot::channel();
            circ.control
                .unbounded_send(CtrlMsg::AddFakeHop {
                    relay_cell_format,
                    fwd_lasthop: idx == 2,
                    rev_lasthop: idx == u8::from(next_msg_from),
                    params,
                    done: tx,
                })
                .unwrap();
            rx.await.unwrap().unwrap();
        }

        (circ, circmsg_send)
    }

    // Helper: set up a 3-hop circuit with no encryption, where the
    // next inbound message seems to come from hop next_msg_from
    async fn newcirc<R: Runtime>(
        rt: &R,
        chan: Arc<Channel>,
    ) -> (Arc<ClientCirc>, mpsc::Sender<ClientCircChanMsg>) {
        newcirc_ext(rt, chan, 2.into()).await
    }

    // Try sending a cell via send_relay_cell
    #[test]
    fn send_simple() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, mut rx, _sink) = working_fake_channel(&rt);
            let (circ, _send) = newcirc(&rt, chan).await;
            let begindir = AnyRelayMsgOuter::new(None, AnyRelayMsg::BeginDir(Default::default()));
            circ.control
                .unbounded_send(CtrlMsg::SendRelayCell {
                    hop: 2.into(),
                    early: false,
                    cell: begindir,
                })
                .unwrap();

            // Here's what we tried to put on the TLS channel.  Note that
            // we're using dummy relay crypto for testing convenience.
            let rcvd = rx.next().await.unwrap();
            assert_eq!(rcvd.circid(), Some(circ.peek_circid()));
            let m = match rcvd.into_circid_and_msg().1 {
                AnyChanMsg::Relay(r) => {
                    AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                        .unwrap()
                }
                _ => panic!(),
            };
            assert!(matches!(m.msg(), AnyRelayMsg::BeginDir(_)));
        });
    }

    async fn test_extend<R: Runtime>(rt: &R, handshake_type: HandshakeType) {
        use crate::crypto::handshake::{ntor::NtorServer, ServerHandshake};

        let (chan, mut rx, _sink) = working_fake_channel(rt);
        let (circ, mut sink) = newcirc(rt, chan).await;
        let circid = circ.peek_circid();
        let params = CircParameters::default();

        let extend_fut = async move {
            let target = example_target();
            match handshake_type {
                HandshakeType::Fast => panic!("Can't extend with Fast handshake"),
                HandshakeType::Ntor => circ.extend_ntor(&target, &params).await.unwrap(),
                #[cfg(feature = "ntor_v3")]
                HandshakeType::NtorV3 => circ.extend_ntor_v3(&target, &params).await.unwrap(),
            };
            circ // gotta keep the circ alive, or the reactor would exit.
        };
        let reply_fut = async move {
            // We've disabled encryption on this circuit, so we can just
            // read the extend2 cell.
            let (id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
            assert_eq!(id, Some(circid));
            let rmsg = match chmsg {
                AnyChanMsg::RelayEarly(r) => {
                    AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                        .unwrap()
                }
                _ => panic!(),
            };
            let e2 = match rmsg.msg() {
                AnyRelayMsg::Extend2(e2) => e2,
                _ => panic!(),
            };
            let mut rng = testing_rng();
            let reply = match handshake_type {
                HandshakeType::Fast => panic!("Can't extend with Fast handshake"),
                HandshakeType::Ntor => {
                    let (_keygen, reply) = NtorServer::server(
                        &mut rng,
                        &mut |_: &()| Some(()),
                        &[example_ntor_key()],
                        e2.handshake(),
                    )
                    .unwrap();
                    reply
                }
                #[cfg(feature = "ntor_v3")]
                HandshakeType::NtorV3 => {
                    let (_keygen, reply) = NtorV3Server::server(
                        &mut rng,
                        &mut |_: &[NtorV3Extension]| Some(vec![]),
                        &[example_ntor_v3_key()],
                        e2.handshake(),
                    )
                    .unwrap();
                    reply
                }
            };

            let extended2 = relaymsg::Extended2::new(reply).into();
            sink.send(rmsg_to_ccmsg(None, extended2)).await.unwrap();
            sink // gotta keep the sink alive, or the reactor will exit.
        };

        let (circ, _) = futures::join!(extend_fut, reply_fut);

        // Did we really add another hop?
        assert_eq!(circ.n_hops(), 4);

        // Do the path accessors report a reasonable outcome?
        #[allow(deprecated)]
        {
            let path = circ.path();
            assert_eq!(path.len(), 4);
            use tor_linkspec::HasRelayIds;
            assert_eq!(path[3].ed_identity(), example_target().ed_identity());
            assert_ne!(path[0].ed_identity(), example_target().ed_identity());
        }
        {
            let path = circ.path_ref();
            assert_eq!(path.n_hops(), 4);
            use tor_linkspec::HasRelayIds;
            assert_eq!(
                path.hops()[3].as_chan_target().unwrap().ed_identity(),
                example_target().ed_identity()
            );
            assert_ne!(
                path.hops()[0].as_chan_target().unwrap().ed_identity(),
                example_target().ed_identity()
            );
        }
    }

    #[test]
    fn test_extend_ntor() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_extend(&rt, HandshakeType::Ntor).await;
        });
    }

    #[cfg(feature = "ntor_v3")]
    #[test]
    fn test_extend_ntor_v3() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_extend(&rt, HandshakeType::NtorV3).await;
        });
    }

    async fn bad_extend_test_impl<R: Runtime>(
        rt: &R,
        reply_hop: HopNum,
        bad_reply: ClientCircChanMsg,
    ) -> Error {
        let (chan, _rx, _sink) = working_fake_channel(rt);
        let (circ, mut sink) = newcirc_ext(rt, chan, reply_hop).await;
        let params = CircParameters::default();

        let target = example_target();
        #[allow(clippy::clone_on_copy)]
        let rtc = rt.clone();
        let sink_handle = rt
            .spawn_with_handle(async move {
                rtc.sleep(Duration::from_millis(100)).await;
                sink.send(bad_reply).await.unwrap();
                sink
            })
            .unwrap();
        let outcome = circ.extend_ntor(&target, &params).await;
        let _sink = sink_handle.await;

        assert_eq!(circ.n_hops(), 3);
        assert!(outcome.is_err());
        outcome.unwrap_err()
    }

    #[test]
    fn bad_extend_wronghop() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let extended2 = relaymsg::Extended2::new(vec![]).into();
            let cc = rmsg_to_ccmsg(None, extended2);

            let error = bad_extend_test_impl(&rt, 1.into(), cc).await;
            // This case shows up as a CircDestroy, since a message sent
            // from the wrong hop won't even be delivered to the extend
            // code's meta-handler.  Instead the unexpected message will cause
            // the circuit to get torn down.
            match error {
                Error::CircuitClosed => {}
                x => panic!("got other error: {}", x),
            }
        });
    }

    #[test]
    fn bad_extend_wrongtype() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let extended = relaymsg::Extended::new(vec![7; 200]).into();
            let cc = rmsg_to_ccmsg(None, extended);

            let error = bad_extend_test_impl(&rt, 2.into(), cc).await;
            match error {
                Error::BytesErr {
                    err: tor_bytes::Error::InvalidMessage(_),
                    object: "extended2 message",
                } => {}
                _ => panic!(),
            }
        });
    }

    #[test]
    fn bad_extend_destroy() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let cc = ClientCircChanMsg::Destroy(chanmsg::Destroy::new(4.into()));
            let error = bad_extend_test_impl(&rt, 2.into(), cc).await;
            match error {
                Error::CircuitClosed => {}
                _ => panic!(),
            }
        });
    }

    #[test]
    fn bad_extend_crypto() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let extended2 = relaymsg::Extended2::new(vec![99; 256]).into();
            let cc = rmsg_to_ccmsg(None, extended2);
            let error = bad_extend_test_impl(&rt, 2.into(), cc).await;
            assert!(matches!(error, Error::BadCircHandshakeAuth));
        });
    }

    #[test]
    fn begindir() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, mut rx, _sink) = working_fake_channel(&rt);
            let (circ, mut sink) = newcirc(&rt, chan).await;
            let circid = circ.peek_circid();

            let begin_and_send_fut = async move {
                // Here we'll say we've got a circuit, and we want to
                // make a simple BEGINDIR request with it.
                let mut stream = circ.begin_dir_stream().await.unwrap();
                stream.write_all(b"HTTP/1.0 GET /\r\n").await.unwrap();
                stream.flush().await.unwrap();
                let mut buf = [0_u8; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"HTTP/1.0 404 Not found\r\n");
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(n, 0);
                stream
            };
            let reply_fut = async move {
                // We've disabled encryption on this circuit, so we can just
                // read the begindir cell.
                let (id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
                assert_eq!(id, Some(circid));
                let rmsg = match chmsg {
                    AnyChanMsg::Relay(r) => {
                        AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                            .unwrap()
                    }
                    _ => panic!(),
                };
                let (streamid, rmsg) = rmsg.into_streamid_and_msg();
                assert!(matches!(rmsg, AnyRelayMsg::BeginDir(_)));

                // Reply with a Connected cell to indicate success.
                let connected = relaymsg::Connected::new_empty().into();
                sink.send(rmsg_to_ccmsg(streamid, connected)).await.unwrap();

                // Now read a DATA cell...
                let (id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
                assert_eq!(id, Some(circid));
                let rmsg = match chmsg {
                    AnyChanMsg::Relay(r) => {
                        AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                            .unwrap()
                    }
                    _ => panic!(),
                };
                let (streamid_2, rmsg) = rmsg.into_streamid_and_msg();
                assert_eq!(streamid_2, streamid);
                if let AnyRelayMsg::Data(d) = rmsg {
                    assert_eq!(d.as_ref(), &b"HTTP/1.0 GET /\r\n"[..]);
                } else {
                    panic!();
                }

                // Write another data cell in reply!
                let data = relaymsg::Data::new(b"HTTP/1.0 404 Not found\r\n")
                    .unwrap()
                    .into();
                sink.send(rmsg_to_ccmsg(streamid, data)).await.unwrap();

                // Send an END cell to say that the conversation is over.
                let end = relaymsg::End::new_with_reason(relaymsg::EndReason::DONE).into();
                sink.send(rmsg_to_ccmsg(streamid, end)).await.unwrap();

                (rx, sink) // gotta keep these alive, or the reactor will exit.
            };

            let (_stream, (_rx, _sink)) = futures::join!(begin_and_send_fut, reply_fut);
        });
    }

    // Test: close a stream, either by dropping it or by calling AsyncWriteExt::close.
    fn close_stream_helper(by_drop: bool) {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, mut rx, _sink) = working_fake_channel(&rt);
            let (circ, mut sink) = newcirc(&rt, chan).await;

            let stream_fut = async move {
                let stream = circ
                    .begin_stream("www.example.com", 80, None)
                    .await
                    .unwrap();

                let (r, mut w) = stream.split();
                if by_drop {
                    // Drop the writer and the reader, which should close the stream.
                    drop(r);
                    drop(w);
                    (None, circ) // make sure to keep the circuit alive
                } else {
                    // Call close on the writer, while keeping the reader alive.
                    w.close().await.unwrap();
                    (Some(r), circ)
                }
            };
            let handler_fut = async {
                // Read the BEGIN message.
                let (_, msg) = rx.next().await.unwrap().into_circid_and_msg();
                let rmsg = match msg {
                    AnyChanMsg::Relay(r) => {
                        AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                            .unwrap()
                    }
                    _ => panic!(),
                };
                let (streamid, rmsg) = rmsg.into_streamid_and_msg();
                assert_eq!(rmsg.cmd(), RelayCmd::BEGIN);

                // Reply with a CONNECTED.
                let connected =
                    relaymsg::Connected::new_with_addr("10.0.0.1".parse().unwrap(), 1234).into();
                sink.send(rmsg_to_ccmsg(streamid, connected)).await.unwrap();

                // Expect an END.
                let (_, msg) = rx.next().await.unwrap().into_circid_and_msg();
                let rmsg = match msg {
                    AnyChanMsg::Relay(r) => {
                        AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                            .unwrap()
                    }
                    _ => panic!(),
                };
                let (_, rmsg) = rmsg.into_streamid_and_msg();
                assert_eq!(rmsg.cmd(), RelayCmd::END);

                (rx, sink) // keep these alive or the reactor will exit.
            };

            let ((_opt_reader, _circ), (_rx, _sink)) = futures::join!(stream_fut, handler_fut);
        });
    }

    #[test]
    fn drop_stream() {
        close_stream_helper(true);
    }

    #[test]
    fn close_stream() {
        close_stream_helper(false);
    }

    // Set up a circuit and stream that expects some incoming SENDMEs.
    async fn setup_incoming_sendme_case<R: Runtime>(
        rt: &R,
        n_to_send: usize,
    ) -> (
        Arc<ClientCirc>,
        DataStream,
        mpsc::Sender<ClientCircChanMsg>,
        Option<StreamId>,
        usize,
        Receiver<AnyChanCell>,
        Sender<std::result::Result<OpenChanCellS2C, CodecError>>,
    ) {
        let (chan, mut rx, sink2) = working_fake_channel(rt);
        let (circ, mut sink) = newcirc(rt, chan).await;
        let circid = circ.peek_circid();

        let begin_and_send_fut = {
            let circ = circ.clone();
            async move {
                // Take our circuit and make a stream on it.
                let mut stream = circ
                    .begin_stream("www.example.com", 443, None)
                    .await
                    .unwrap();
                let junk = [0_u8; 1024];
                let mut remaining = n_to_send;
                while remaining > 0 {
                    let n = std::cmp::min(remaining, junk.len());
                    stream.write_all(&junk[..n]).await.unwrap();
                    remaining -= n;
                }
                stream.flush().await.unwrap();
                stream
            }
        };

        let receive_fut = async move {
            // Read the begin cell.
            let (_id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
            let rmsg = match chmsg {
                AnyChanMsg::Relay(r) => {
                    AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                        .unwrap()
                }
                _ => panic!(),
            };
            let (streamid, rmsg) = rmsg.into_streamid_and_msg();
            assert!(matches!(rmsg, AnyRelayMsg::Begin(_)));
            // Reply with a connected cell...
            let connected = relaymsg::Connected::new_empty().into();
            sink.send(rmsg_to_ccmsg(streamid, connected)).await.unwrap();
            // Now read bytes from the stream until we have them all.
            let mut bytes_received = 0_usize;
            let mut cells_received = 0_usize;
            while bytes_received < n_to_send {
                // Read a data cell, and remember how much we got.
                let (id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
                assert_eq!(id, Some(circid));

                let rmsg = match chmsg {
                    AnyChanMsg::Relay(r) => {
                        AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                            .unwrap()
                    }
                    _ => panic!(),
                };
                let (streamid2, rmsg) = rmsg.into_streamid_and_msg();
                assert_eq!(streamid2, streamid);
                if let AnyRelayMsg::Data(dat) = rmsg {
                    cells_received += 1;
                    bytes_received += dat.as_ref().len();
                } else {
                    panic!();
                }
            }

            (sink, streamid, cells_received, rx)
        };

        let (stream, (sink, streamid, cells_received, rx)) =
            futures::join!(begin_and_send_fut, receive_fut);

        (circ, stream, sink, streamid, cells_received, rx, sink2)
    }

    #[test]
    fn accept_valid_sendme() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (circ, _stream, mut sink, streamid, cells_received, _rx, _sink2) =
                setup_incoming_sendme_case(&rt, 300 * 498 + 3).await;

            assert_eq!(cells_received, 301);

            // Make sure that the circuit is indeed expecting the right sendmes
            {
                let (tx, rx) = oneshot::channel();
                circ.control
                    .unbounded_send(CtrlMsg::QuerySendWindow {
                        hop: 2.into(),
                        done: tx,
                    })
                    .unwrap();
                let (window, tags) = rx.await.unwrap().unwrap();
                assert_eq!(window, 1000 - 301);
                assert_eq!(tags.len(), 3);
                // 100
                assert_eq!(
                    tags[0],
                    sendme::CircTag::from(hex!("6400000000000000000000000000000000000000"))
                );
                // 200
                assert_eq!(
                    tags[1],
                    sendme::CircTag::from(hex!("c800000000000000000000000000000000000000"))
                );
                // 300
                assert_eq!(
                    tags[2],
                    sendme::CircTag::from(hex!("2c01000000000000000000000000000000000000"))
                );
            }

            let reply_with_sendme_fut = async move {
                // make and send a circuit-level sendme.
                let c_sendme =
                    relaymsg::Sendme::new_tag(hex!("6400000000000000000000000000000000000000"))
                        .into();
                sink.send(rmsg_to_ccmsg(None, c_sendme)).await.unwrap();

                // Make and send a stream-level sendme.
                let s_sendme = relaymsg::Sendme::new_empty().into();
                sink.send(rmsg_to_ccmsg(streamid, s_sendme)).await.unwrap();

                sink
            };

            let _sink = reply_with_sendme_fut.await;

            // FIXME(eta): this is a hacky way of waiting for the reactor to run before doing the below
            //             query; should find some way to properly synchronize to avoid flakiness
            rt.sleep(Duration::from_millis(100)).await;
            // Now make sure that the circuit is still happy, and its
            // window is updated.
            {
                let (tx, rx) = oneshot::channel();
                circ.control
                    .unbounded_send(CtrlMsg::QuerySendWindow {
                        hop: 2.into(),
                        done: tx,
                    })
                    .unwrap();
                let (window, _tags) = rx.await.unwrap().unwrap();
                assert_eq!(window, 1000 - 201);
            }
        });
    }

    #[test]
    fn invalid_circ_sendme() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            // Same setup as accept_valid_sendme() test above but try giving
            // a sendme with the wrong tag.

            let (circ, _stream, mut sink, _streamid, _cells_received, _rx, _sink2) =
                setup_incoming_sendme_case(&rt, 300 * 498 + 3).await;

            let reply_with_sendme_fut = async move {
                // make and send a circuit-level sendme with a bad tag.
                let c_sendme =
                    relaymsg::Sendme::new_tag(hex!("FFFF0000000000000000000000000000000000FF"))
                        .into();
                sink.send(rmsg_to_ccmsg(None, c_sendme)).await.unwrap();
                sink
            };

            let _sink = reply_with_sendme_fut.await;

            let mut tries = 0;
            // FIXME(eta): we aren't testing the error message like we used to; however, we can at least
            //             check whether the reactor dies as a result of receiving invalid data.
            while !circ.control.is_closed() {
                // TODO: Don't sleep in tests.
                rt.sleep(Duration::from_millis(100)).await;
                tries += 1;
                if tries > 10 {
                    panic!("reactor continued running after invalid sendme");
                }
            }

            // TODO: check that the circuit is shut down too
        });
    }

    #[test]
    fn test_busy_stream_fairness() {
        // Number of streams to use.
        const N_STREAMS: usize = 3;
        // Number of cells (roughly) for each stream to send.
        const N_CELLS: usize = 20;
        // Number of bytes that *each* stream will send, and that we'll read
        // from the channel.
        const N_BYTES: usize = relaymsg::Data::MAXLEN * N_CELLS;
        // Ignoring cell granularity, with perfect fairness we'd expect
        // `N_BYTES/N_STREAMS` bytes from each stream.
        //
        // We currently allow for up to a full cell less than that.  This is
        // somewhat arbitrary and can be changed as needed, since we don't
        // provide any specific fairness guarantees.
        const MIN_EXPECTED_BYTES_PER_STREAM: usize = N_BYTES / N_STREAMS - relaymsg::Data::MAXLEN;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, mut rx, _sink) = working_fake_channel(&rt);
            let (circ, mut sink) = newcirc(&rt, chan).await;

            // Run clients in a single task, doing our own round-robin
            // scheduling of writes to the reactor. Conversely, if we were to
            // put each client in its own task, we would be at the the mercy of
            // how fairly the runtime schedules the client tasks, which is outside
            // the scope of this test.
            rt.spawn({
                // Clone the circuit to keep it alive after writers have
                // finished with it.
                let circ = circ.clone();
                async move {
                    let mut clients = VecDeque::new();
                    struct Client {
                        stream: DataStream,
                        to_write: &'static [u8],
                    }
                    for _ in 0..N_STREAMS {
                        clients.push_back(Client {
                            stream: circ
                                .begin_stream("www.example.com", 80, None)
                                .await
                                .unwrap(),
                            to_write: &[0_u8; N_BYTES][..],
                        });
                    }
                    while let Some(mut client) = clients.pop_front() {
                        if client.to_write.is_empty() {
                            // Client is done. Don't put back in queue.
                            continue;
                        }
                        let written = client.stream.write(client.to_write).await.unwrap();
                        client.to_write = &client.to_write[written..];
                        clients.push_back(client);
                    }
                }
            })
            .unwrap();

            let channel_handler_fut = async {
                let mut stream_bytes_received = HashMap::<StreamId, usize>::new();
                let mut total_bytes_received = 0;

                loop {
                    let (_, msg) = rx.next().await.unwrap().into_circid_and_msg();
                    let rmsg = match msg {
                        AnyChanMsg::Relay(r) => AnyRelayMsgOuter::decode_singleton(
                            RelayCellFormat::V0,
                            r.into_relay_body(),
                        )
                        .unwrap(),
                        other => panic!("Unexpected chanmsg: {other:?}"),
                    };
                    let (streamid, rmsg) = rmsg.into_streamid_and_msg();
                    match rmsg.cmd() {
                        RelayCmd::BEGIN => {
                            // Add an entry for this stream.
                            let prev = stream_bytes_received.insert(streamid.unwrap(), 0);
                            assert_eq!(prev, None);
                            // Reply with a CONNECTED.
                            let connected = relaymsg::Connected::new_with_addr(
                                "10.0.0.1".parse().unwrap(),
                                1234,
                            )
                            .into();
                            sink.send(rmsg_to_ccmsg(streamid, connected)).await.unwrap();
                        }
                        RelayCmd::DATA => {
                            let data_msg = relaymsg::Data::try_from(rmsg).unwrap();
                            let nbytes = data_msg.as_ref().len();
                            total_bytes_received += nbytes;
                            let streamid = streamid.unwrap();
                            let stream_bytes = stream_bytes_received.get_mut(&streamid).unwrap();
                            *stream_bytes += nbytes;
                            if total_bytes_received >= N_BYTES {
                                break;
                            }
                        }
                        RelayCmd::END => {
                            // Stream is done. If fair scheduling is working as
                            // expected we *probably* shouldn't get here, but we
                            // can ignore it and save the failure until we
                            // actually have the final stats.
                            continue;
                        }
                        other => {
                            panic!("Unexpected command {other:?}");
                        }
                    }
                }

                // Return our stats, along with the `rx` and `sink` to keep the
                // reactor alive (since clients could still be writing).
                (total_bytes_received, stream_bytes_received, rx, sink)
            };

            let (total_bytes_received, stream_bytes_received, _rx, _sink) =
                channel_handler_fut.await;
            assert_eq!(stream_bytes_received.len(), N_STREAMS);
            for (sid, stream_bytes) in stream_bytes_received {
                assert!(
                    stream_bytes >= MIN_EXPECTED_BYTES_PER_STREAM,
                    "Only {stream_bytes} of {total_bytes_received} bytes received from {N_STREAMS} came from {sid:?}; expected at least {MIN_EXPECTED_BYTES_PER_STREAM}"
                );
            }
        });
    }

    #[test]
    fn basic_params() {
        use super::CircParameters;
        let mut p = CircParameters::default();
        assert_eq!(p.initial_send_window(), 1000);
        assert!(p.extend_by_ed25519_id());

        assert!(p.set_initial_send_window(500).is_ok());
        p.set_extend_by_ed25519_id(false);
        assert_eq!(p.initial_send_window(), 500);
        assert!(!p.extend_by_ed25519_id());

        assert!(p.set_initial_send_window(9000).is_err());
        assert_eq!(p.initial_send_window(), 500);
    }

    #[cfg(feature = "hs-service")]
    struct AllowAllStreamsFilter;
    #[cfg(feature = "hs-service")]
    impl IncomingStreamRequestFilter for AllowAllStreamsFilter {
        fn disposition(
            &mut self,
            _ctx: &crate::stream::IncomingStreamRequestContext<'_>,
            _circ: &ClientCircSyncView<'_>,
        ) -> Result<crate::stream::IncomingStreamRequestDisposition> {
            Ok(crate::stream::IncomingStreamRequestDisposition::Accept)
        }
    }

    #[test]
    #[cfg(feature = "hs-service")]
    fn allow_stream_requests_twice() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, _rx, _sink) = working_fake_channel(&rt);
            let (circ, _send) = newcirc(&rt, chan).await;

            let _incoming = circ
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    circ.last_hop_num().unwrap(),
                    AllowAllStreamsFilter,
                )
                .await
                .unwrap();

            let incoming = circ
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    circ.last_hop_num().unwrap(),
                    AllowAllStreamsFilter,
                )
                .await;

            // There can only be one IncomingStream at a time on any given circuit.
            assert!(incoming.is_err());
        });
    }

    #[test]
    #[cfg(feature = "hs-service")]
    fn allow_stream_requests() {
        use tor_cell::relaycell::msg::BeginFlags;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            const TEST_DATA: &[u8] = b"ping";

            let (chan, _rx, _sink) = working_fake_channel(&rt);
            let (circ, mut send) = newcirc(&rt, chan).await;

            // A helper channel for coordinating the "client"/"service" interaction
            let (tx, rx) = oneshot::channel();
            let mut incoming = circ
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    circ.last_hop_num().unwrap(),
                    AllowAllStreamsFilter,
                )
                .await
                .unwrap();

            let simulate_service = async move {
                let stream = incoming.next().await.unwrap();
                let mut data_stream = stream
                    .accept_data(relaymsg::Connected::new_empty())
                    .await
                    .unwrap();
                // Notify the client task we're ready to accept DATA cells
                tx.send(()).unwrap();

                // Read the data the client sent us
                let mut buf = [0_u8; TEST_DATA.len()];
                data_stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, TEST_DATA);

                circ
            };

            let simulate_client = async move {
                let begin = Begin::new("localhost", 80, BeginFlags::IPV6_OKAY).unwrap();
                let body: BoxedCellBody =
                    AnyRelayMsgOuter::new(StreamId::new(12), AnyRelayMsg::Begin(begin))
                        .encode(&mut testing_rng())
                        .unwrap();
                let begin_msg = chanmsg::Relay::from(body);

                // Pretend to be a client at the other end of the circuit sending a begin cell
                send.send(ClientCircChanMsg::Relay(begin_msg))
                    .await
                    .unwrap();

                // Wait until the service is ready to accept data
                // TODO: we shouldn't need to wait! This is needed because the service will reject
                // any DATA cells that aren't associated with a known stream. We need to wait until
                // the service receives our BEGIN cell (and the reactor updates hop.map with the
                // new stream).
                rx.await.unwrap();
                // Now send some data along the newly established circuit..
                let data = relaymsg::Data::new(TEST_DATA).unwrap();
                let body: BoxedCellBody =
                    AnyRelayMsgOuter::new(StreamId::new(12), AnyRelayMsg::Data(data))
                        .encode(&mut testing_rng())
                        .unwrap();
                let data_msg = chanmsg::Relay::from(body);

                send.send(ClientCircChanMsg::Relay(data_msg)).await.unwrap();
                send
            };

            let (_circ, _send) = futures::join!(simulate_service, simulate_client);
        });
    }

    #[test]
    #[cfg(feature = "hs-service")]
    fn accept_stream_after_reject() {
        use tor_cell::relaycell::msg::BeginFlags;
        use tor_cell::relaycell::msg::EndReason;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            const TEST_DATA: &[u8] = b"ping";
            const STREAM_COUNT: usize = 2;

            let (chan, _rx, _sink) = working_fake_channel(&rt);
            let (circ, mut send) = newcirc(&rt, chan).await;

            // A helper channel for coordinating the "client"/"service" interaction
            let (mut tx, mut rx) = mpsc::channel(STREAM_COUNT);

            let mut incoming = circ
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    circ.last_hop_num().unwrap(),
                    AllowAllStreamsFilter,
                )
                .await
                .unwrap();

            let simulate_service = async move {
                // Process 2 incoming streams
                for i in 0..STREAM_COUNT {
                    let stream = incoming.next().await.unwrap();

                    // Reject the first one
                    if i == 0 {
                        stream
                            .reject(relaymsg::End::new_with_reason(EndReason::INTERNAL))
                            .await
                            .unwrap();
                        // Notify the client
                        tx.send(()).await.unwrap();
                        continue;
                    }

                    let mut data_stream = stream
                        .accept_data(relaymsg::Connected::new_empty())
                        .await
                        .unwrap();
                    // Notify the client task we're ready to accept DATA cells
                    tx.send(()).await.unwrap();

                    // Read the data the client sent us
                    let mut buf = [0_u8; TEST_DATA.len()];
                    data_stream.read_exact(&mut buf).await.unwrap();
                    assert_eq!(&buf, TEST_DATA);
                }

                circ
            };

            let simulate_client = async move {
                let begin = Begin::new("localhost", 80, BeginFlags::IPV6_OKAY).unwrap();
                let body: BoxedCellBody =
                    AnyRelayMsgOuter::new(StreamId::new(12), AnyRelayMsg::Begin(begin))
                        .encode(&mut testing_rng())
                        .unwrap();
                let begin_msg = chanmsg::Relay::from(body);

                // Pretend to be a client at the other end of the circuit sending 2 identical begin
                // cells (the first one will be rejected by the test service).
                for _ in 0..STREAM_COUNT {
                    send.send(ClientCircChanMsg::Relay(begin_msg.clone()))
                        .await
                        .unwrap();

                    // Wait until the service rejects our request
                    rx.next().await.unwrap();
                }

                // Now send some data along the newly established circuit..
                let data = relaymsg::Data::new(TEST_DATA).unwrap();
                let body: BoxedCellBody =
                    AnyRelayMsgOuter::new(StreamId::new(12), AnyRelayMsg::Data(data))
                        .encode(&mut testing_rng())
                        .unwrap();
                let data_msg = chanmsg::Relay::from(body);

                send.send(ClientCircChanMsg::Relay(data_msg)).await.unwrap();
                send
            };

            let (_circ, _send) = futures::join!(simulate_service, simulate_client);
        });
    }

    #[test]
    #[cfg(feature = "hs-service")]
    fn incoming_stream_bad_hop() {
        use tor_cell::relaycell::msg::BeginFlags;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            /// Expect the originator of the BEGIN cell to be hop 1.
            const EXPECTED_HOP: u8 = 1;

            let (chan, _rx, _sink) = working_fake_channel(&rt);
            let (circ, mut send) = newcirc(&rt, chan).await;

            // Expect to receive incoming streams from hop EXPECTED_HOP
            let mut incoming = circ
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    EXPECTED_HOP.into(),
                    AllowAllStreamsFilter,
                )
                .await
                .unwrap();

            let simulate_service = async move {
                // The originator of the cell is actually the last hop on the circuit, not hop 1,
                // so we expect the reactor to shut down.
                assert!(incoming.next().await.is_none());
                circ
            };

            let simulate_client = async move {
                let begin = Begin::new("localhost", 80, BeginFlags::IPV6_OKAY).unwrap();
                let body: BoxedCellBody =
                    AnyRelayMsgOuter::new(StreamId::new(12), AnyRelayMsg::Begin(begin))
                        .encode(&mut testing_rng())
                        .unwrap();
                let begin_msg = chanmsg::Relay::from(body);

                // Pretend to be a client at the other end of the circuit sending a begin cell
                send.send(ClientCircChanMsg::Relay(begin_msg))
                    .await
                    .unwrap();

                send
            };

            let (_circ, _send) = futures::join!(simulate_service, simulate_client);
        });
    }
}
