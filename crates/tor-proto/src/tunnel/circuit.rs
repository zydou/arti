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
//! one of the methods
//! (typically [`PendingClientCirc::create_firsthop`])
//! that extends it to its first hop.  After you've
//! done that, you can call [`ClientCirc::extend`] on the circuit to
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

pub(crate) mod celltypes;
pub(crate) mod halfcirc;

#[cfg(feature = "hs-common")]
pub mod handshake;
#[cfg(not(feature = "hs-common"))]
pub(crate) mod handshake;

pub(super) mod path;
pub(crate) mod unique_id;

use crate::channel::Channel;
use crate::congestion::params::CongestionControlParams;
use crate::crypto::cell::HopNum;
use crate::crypto::handshake::ntor_v3::NtorV3PublicKey;
use crate::memquota::{CircuitAccount, SpecificAccount as _};
use crate::stream::{
    AnyCmdChecker, DataCmdChecker, DataStream, ResolveCmdChecker, ResolveStream, StreamParameters,
    StreamReceiver,
};
use crate::tunnel::circuit::celltypes::*;
use crate::tunnel::reactor::CtrlCmd;
use crate::tunnel::reactor::{
    CircuitHandshake, CtrlMsg, Reactor, RECV_WINDOW_INIT, STREAM_READER_BUFFER,
};
use crate::tunnel::{StreamTarget, TargetHop};
use crate::util::skew::ClockSkew;
use crate::{Error, ResolveError, Result};
use educe::Educe;
use path::HopDetail;
use tor_cell::{
    chancell::CircId,
    relaycell::msg::{AnyRelayMsg, Begin, Resolve, Resolved, ResolvedVal},
};

use tor_error::{bad_api_usage, internal, into_internal};
use tor_linkspec::{CircTarget, LinkSpecType, OwnedChanTarget, RelayIdType};
use tor_protover::named;

pub use crate::crypto::binding::CircuitBinding;
pub use crate::memquota::StreamAccount;
pub use crate::tunnel::circuit::unique_id::UniqId;

#[cfg(feature = "hs-service")]
use {
    crate::stream::{IncomingCmdChecker, IncomingStream},
    crate::tunnel::reactor::StreamReqInfo,
};

use futures::channel::mpsc;
use oneshot_fused_workaround as oneshot;

use crate::congestion::sendme::StreamRecvWindow;
use crate::DynTimeProvider;
use futures::FutureExt as _;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tor_memquota::mq_queue::{self, ChannelSpec as _, MpscSpec};

use crate::crypto::handshake::ntor::NtorPublicKey;

pub use path::{Path, PathEntry};

/// The size of the buffer for communication between `ClientCirc` and its reactor.
pub const CIRCUIT_BUFFER_SIZE: usize = 128;

#[cfg(feature = "send-control-msg")]
use {crate::tunnel::msghandler::UserMsgHandler, crate::tunnel::reactor::MetaCellHandler};

pub use crate::tunnel::reactor::syncview::ClientCircSyncView;
#[cfg(feature = "send-control-msg")]
#[cfg_attr(docsrs, doc(cfg(feature = "send-control-msg")))]
pub use {crate::tunnel::msghandler::MsgHandler, crate::tunnel::reactor::MetaCellDisposition};

/// MPSC queue relating to a stream (either inbound or outbound), sender
pub(crate) type StreamMpscSender<T> = mq_queue::Sender<T, MpscSpec>;
/// MPSC queue relating to a stream (either inbound or outbound), receiver
pub(crate) type StreamMpscReceiver<T> = mq_queue::Receiver<T, MpscSpec>;

/// MPSC queue for inbound data on its way from channel to circuit, sender
pub(crate) type CircuitRxSender = mq_queue::Sender<ClientCircChanMsg, MpscSpec>;
/// MPSC queue for inbound data on its way from channel to circuit, receiver
pub(crate) type CircuitRxReceiver = mq_queue::Receiver<ClientCircChanMsg, MpscSpec>;

#[derive(Debug)]
/// A circuit that we have constructed over the Tor network.
///
/// # Circuit life cycle
///
/// `ClientCirc`s are created in an initially unusable state using [`Channel::new_circ`],
/// which returns a [`PendingClientCirc`].  To get a real (one-hop) circuit from
/// one of these, you invoke one of its `create_firsthop` methods (typically
/// [`create_firsthop_fast()`](PendingClientCirc::create_firsthop_fast) or
/// [`create_firsthop()`](PendingClientCirc::create_firsthop)).
/// Then, to add more hops to the circuit, you can call
/// [`extend()`](ClientCirc::extend) on it.
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
//
pub struct ClientCirc {
    /// Mutable state shared with the `Reactor`.
    mutable: Arc<TunnelMutableState>,
    /// A unique identifier for this circuit.
    unique_id: UniqId,
    /// Channel to send control messages to the reactor.
    pub(super) control: mpsc::UnboundedSender<CtrlMsg>,
    /// Channel to send commands to the reactor.
    pub(super) command: mpsc::UnboundedSender<CtrlCmd>,
    /// A future that resolves to Cancelled once the reactor is shut down,
    /// meaning that the circuit is closed.
    #[cfg_attr(not(feature = "experimental-api"), allow(dead_code))]
    reactor_closed_rx: futures::future::Shared<oneshot::Receiver<void::Void>>,
    /// For testing purposes: the CircId, for use in peek_circid().
    #[cfg(test)]
    circid: CircId,
    /// Memory quota account
    memquota: CircuitAccount,
    /// Time provider
    time_provider: DynTimeProvider,
}

/// The mutable state of a tunnel, shared between [`ClientCirc`] and [`Reactor`].
///
/// NOTE(gabi): this mutex-inside-a-mutex might look suspicious,
/// but it is currently the best option we have for sharing
/// the circuit state with `ClientCirc` (and soon, with `ClientTunnel`).
/// In practice, these mutexes won't be accessed very often
/// (they're accessed for writing when a circuit is extended,
/// and for reading by the various `ClientCirc` APIs),
/// so they shouldn't really impact performance.
///
/// Alternatively, the circuit state information could be shared
/// outside the reactor through a channel (passed to the reactor via a `CtrlCmd`),
/// but in #1840 @opara notes that involves making the `ClientCirc` accessors
/// (`ClientCirc::path`, `ClientCirc::binding_key`, etc.)
/// asynchronous, which will significantly complicate their callsites,
/// which would in turn need to be made async too.
///
/// We should revisit this decision at some point, and decide whether an async API
/// would be preferable.
#[derive(Debug, Default)]
pub(super) struct TunnelMutableState(Mutex<HashMap<UniqId, Arc<MutableState>>>);

impl TunnelMutableState {
    /// Add the [`MutableState`] of a circuit.
    pub(super) fn insert(&self, unique_id: UniqId, mutable: Arc<MutableState>) {
        #[allow(unused)] // unused in non-debug builds
        let state = self
            .0
            .lock()
            .expect("lock poisoned")
            .insert(unique_id, mutable);

        debug_assert!(state.is_none());
    }

    /// Remove the [`MutableState`] of a circuit.
    pub(super) fn remove(&self, unique_id: UniqId) {
        #[allow(unused)] // unused in non-debug builds
        let state = self.0.lock().expect("lock poisoned").remove(&unique_id);

        debug_assert!(state.is_some());
    }

    /// Return a [`Path`] object describing all the hops in the specified circuit.
    ///
    /// See [`MutableState::path`].
    fn path_ref(&self, unique_id: UniqId) -> Result<Arc<Path>> {
        let lock = self.0.lock().expect("lock poisoned");
        let mutable = lock
            .get(&unique_id)
            .ok_or_else(|| bad_api_usage!("no circuit with unique ID {unique_id}"))?;

        Ok(mutable.path())
    }

    /// Return a description of the first hop of this circuit.
    ///
    /// Returns an error if a circuit with the specified [`UniqId`] doesn't exist.
    /// Returns `Ok(None)` if the specified circuit doesn't have any hops.
    fn first_hop(&self, unique_id: UniqId) -> Result<Option<OwnedChanTarget>> {
        let lock = self.0.lock().expect("lock poisoned");
        let mutable = lock
            .get(&unique_id)
            .ok_or_else(|| bad_api_usage!("no circuit with unique ID {unique_id}"))?;

        let first_hop = mutable.first_hop().map(|first_hop| match first_hop {
            path::HopDetail::Relay(r) => r,
            #[cfg(feature = "hs-common")]
            path::HopDetail::Virtual => {
                panic!("somehow made a circuit with a virtual first hop.")
            }
        });

        Ok(first_hop)
    }

    /// Return the [`HopNum`] of the last hop of the specified circuit.
    ///
    /// Returns an error if a circuit with the specified [`UniqId`] doesn't exist.
    ///
    /// See [`MutableState::last_hop_num`].
    fn last_hop_num(&self, unique_id: UniqId) -> Result<Option<HopNum>> {
        let lock = self.0.lock().expect("lock poisoned");
        let mutable = lock
            .get(&unique_id)
            .ok_or_else(|| bad_api_usage!("no circuit with unique ID {unique_id}"))?;

        Ok(mutable.last_hop_num())
    }

    /// Return the number of hops in the specified circuit.
    ///
    /// See [`MutableState::n_hops`].
    fn n_hops(&self, unique_id: UniqId) -> Result<usize> {
        let lock = self.0.lock().expect("lock poisoned");
        let mutable = lock
            .get(&unique_id)
            .ok_or_else(|| bad_api_usage!("no circuit with unique ID {unique_id}"))?;

        Ok(mutable.n_hops())
    }

    /// Return the number of legs in this tunnel.
    ///
    /// TODO(conflux-fork): this can be removed once we modify `path_ref`
    /// to return *all* the Paths in the tunnel.
    fn n_legs(&self) -> usize {
        let lock = self.0.lock().expect("lock poisoned");
        lock.len()
    }
}

/// The mutable state of a circuit.
#[derive(Educe, Default)]
#[educe(Debug)]
pub(super) struct MutableState(Mutex<CircuitState>);

impl MutableState {
    /// Add a hop to the path of this circuit.
    pub(super) fn add_hop(&self, peer_id: HopDetail, binding: Option<CircuitBinding>) {
        let mut mutable = self.0.lock().expect("poisoned lock");
        Arc::make_mut(&mut mutable.path).push_hop(peer_id);
        mutable.binding.push(binding);
    }

    /// Get a copy of the circuit's current [`path::Path`].
    pub(super) fn path(&self) -> Arc<path::Path> {
        let mutable = self.0.lock().expect("poisoned lock");
        Arc::clone(&mutable.path)
    }

    /// Return the cryptographic material used to prove knowledge of a shared
    /// secret with with `hop`.
    pub(super) fn binding_key(&self, hop: HopNum) -> Option<CircuitBinding> {
        let mutable = self.0.lock().expect("poisoned lock");

        mutable.binding.get::<usize>(hop.into()).cloned().flatten()
        // NOTE: I'm not thrilled to have to copy this information, but we use
        // it very rarely, so it's not _that_ bad IMO.
    }

    /// Return a description of the first hop of this circuit.
    fn first_hop(&self) -> Option<HopDetail> {
        let mutable = self.0.lock().expect("poisoned lock");
        mutable.path.first_hop()
    }

    /// Return the [`HopNum`] of the last hop of this circuit.
    ///
    /// NOTE: This function will return the [`HopNum`] of the hop
    /// that is _currently_ the last. If there is an extend operation in progress,
    /// the currently pending hop may or may not be counted, depending on whether
    /// the extend operation finishes before this call is done.
    fn last_hop_num(&self) -> Option<HopNum> {
        let mutable = self.0.lock().expect("poisoned lock");
        mutable.path.last_hop_num()
    }

    /// Return the number of hops in this circuit.
    ///
    /// NOTE: This function will currently return only the number of hops
    /// _currently_ in the circuit. If there is an extend operation in progress,
    /// the currently pending hop may or may not be counted, depending on whether
    /// the extend operation finishes before this call is done.
    fn n_hops(&self) -> usize {
        let mutable = self.0.lock().expect("poisoned lock");
        mutable.path.n_hops()
    }
}

/// The shared state of a circuit.
#[derive(Educe, Default)]
#[educe(Debug)]
pub(super) struct CircuitState {
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
/// To use one of these, call `create_firsthop_fast()` or `create_firsthop()`
/// to negotiate the cryptographic handshake with the first hop.
pub struct PendingClientCirc {
    /// A oneshot receiver on which we'll receive a CREATED* cell,
    /// or a DESTROY cell.
    recvcreated: oneshot::Receiver<CreateResponse>,
    /// The ClientCirc object that we can expose on success.
    circ: Arc<ClientCirc>,
}

/// Description of the network's current rules for building circuits.
///
/// This type describes rules derived from the consensus,
/// and possibly amended by our own configuration.
///
/// Typically, this type created once for an entire circuit,
/// and any special per-hop information is derived
/// from each hop as a CircTarget.
/// Note however that callers _may_ provide different `CircParameters`
/// for different hops within a circuit if they have some reason to do so,
/// so we do not enforce that every hop in a circuit has the same `CircParameters`.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct CircParameters {
    /// Whether we should include ed25519 identities when we send
    /// EXTEND2 cells.
    pub extend_by_ed25519_id: bool,
    /// Congestion control parameters for this circuit.
    pub ccontrol: CongestionControlParams,
}

/// The settings we use for single hop of a circuit.
///
/// Unlike [`CircParameters`], this type is crate-internal.
/// We construct it based on our settings from the circuit,
/// and from the hop's actual capabilities.
/// Then, we negotiate with the hop as part of circuit
/// creation/extension to determine the actual settings that will be in use.
/// Finally, we use those settings to construct the negotiated circuit hop.
//
// TODO: Relays should probably derive an instance of this type too, as
// part of the circuit creation handshake.
#[derive(Clone, Debug)]
pub(super) struct HopSettings {
    /// The negotiated congestion control settings for this circuit.
    pub(super) ccontrol: CongestionControlParams,
}

impl HopSettings {
    /// Construct a new `HopSettings` based on `params` (a set of circuit parameters)
    /// and `caps` (a set of protocol capabilities for a circuit target).
    ///
    /// The resulting settings will represent what the client would prefer to negotiate
    /// (determined by `params`),
    /// as modified by what the target relay is believed to support (represented by `caps`).
    ///
    /// This represents the `HopSettings` in a pre-negotiation state:
    /// the circuit negotiation process will modify it.
    #[allow(clippy::unnecessary_wraps)] // likely to become fallible in the future.
    pub(super) fn from_params_and_caps(
        params: &CircParameters,
        caps: &tor_protover::Protocols,
    ) -> Result<Self> {
        let mut settings = Self {
            ccontrol: params.ccontrol.clone(),
        };

        match settings.ccontrol.alg() {
            crate::ccparams::Algorithm::FixedWindow(_) => {}
            crate::ccparams::Algorithm::Vegas(_) => {
                // If the target doesn't support FLOWCTRL_CC, we can't use Vegas.
                if !caps.supports_named_subver(named::FLOWCTRL_CC) {
                    settings.ccontrol.use_fallback_alg();
                }
            }
        }

        Ok(settings)
    }

    /// Return a new `HopSettings` based on this one,
    /// representing the settings that we should use
    /// if circuit negotiation will be impossible.
    ///
    /// (Circuit negotiation is impossible when using the legacy ntor protocol,
    /// and when using CRATE_FAST.  It is currently unsupported with virtual hops.)
    pub(super) fn without_negotiation(mut self) -> Self {
        self.ccontrol.use_fallback_alg();
        self
    }
}

#[cfg(test)]
impl std::default::Default for CircParameters {
    fn default() -> Self {
        Self {
            extend_by_ed25519_id: true,
            ccontrol: crate::congestion::test_utils::params::build_cc_fixed_params(),
        }
    }
}

impl CircParameters {
    /// Constructor
    pub fn new(extend_by_ed25519_id: bool, ccontrol: CongestionControlParams) -> Self {
        Self {
            extend_by_ed25519_id,
            ccontrol,
        }
    }
}

impl ClientCirc {
    /// Return a description of the first hop of this circuit.
    ///
    /// # Panics
    ///
    /// Panics if there is no first hop.  (This should be impossible outside of
    /// the tor-proto crate, but within the crate it's possible to have a
    /// circuit with no hops.)
    pub fn first_hop(&self) -> Result<OwnedChanTarget> {
        Ok(self
            .mutable
            .first_hop(self.unique_id)
            .map_err(|_| Error::CircuitClosed)?
            .expect("called first_hop on an un-constructed circuit"))
    }

    /// Return the [`HopNum`] of the last hop of this circuit.
    ///
    /// Returns an error if there is no last hop.  (This should be impossible outside of the
    /// tor-proto crate, but within the crate it's possible to have a circuit with no hops.)
    ///
    /// NOTE: This function will return the [`HopNum`] of the hop
    /// that is _currently_ the last. If there is an extend operation in progress,
    /// the currently pending hop may or may not be counted, depending on whether
    /// the extend operation finishes before this call is done.
    pub fn last_hop_num(&self) -> Result<HopNum> {
        Ok(self
            .mutable
            .last_hop_num(self.unique_id)?
            .ok_or_else(|| internal!("no last hop index"))?)
    }

    /// Return a [`TargetHop`] representing precisely the last hop of the circuit as in set as a
    /// HopLocation with its id and hop number.
    ///
    /// Return an error if there is no last hop.
    pub fn last_hop(&self) -> Result<TargetHop> {
        let hop_num = self
            .mutable
            .last_hop_num(self.unique_id)?
            .ok_or_else(|| bad_api_usage!("no last hop"))?;
        Ok((self.unique_id, hop_num).into())
    }

    /// Return a [`Path`] object describing all the hops in this circuit.
    ///
    /// Note that this `Path` is not automatically updated if the circuit is
    /// extended.
    pub fn path_ref(&self) -> Result<Arc<Path>> {
        self.mutable
            .path_ref(self.unique_id)
            .map_err(|_| Error::CircuitClosed)
    }

    /// Get the clock skew claimed by the first hop of the circuit.
    ///
    /// See [`Channel::clock_skew()`].
    pub async fn first_hop_clock_skew(&self) -> Result<ClockSkew> {
        let (tx, rx) = oneshot::channel();

        self.control
            .unbounded_send(CtrlMsg::FirstHopClockSkew { answer: tx })
            .map_err(|_| Error::CircuitClosed)?;

        Ok(rx.await.map_err(|_| Error::CircuitClosed)??)
    }

    /// Return a reference to this circuit's memory quota account
    pub fn mq_account(&self) -> &CircuitAccount {
        &self.memquota
    }

    /// Return the cryptographic material used to prove knowledge of a shared
    /// secret with with `hop`.
    ///
    /// See [`CircuitBinding`] for more information on how this is used.
    ///
    /// Return None if we have no circuit binding information for the hop, or if
    /// the hop does not exist.
    #[cfg(feature = "hs-service")]
    pub async fn binding_key(&self, hop: TargetHop) -> Result<Option<CircuitBinding>> {
        let (sender, receiver) = oneshot::channel();
        let msg = CtrlCmd::GetBindingKey { hop, done: sender };
        self.command
            .unbounded_send(msg)
            .map_err(|_| Error::CircuitClosed)?;

        receiver.await.map_err(|_| Error::CircuitClosed)?
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
        hop: TargetHop,
    ) -> Result<Conversation<'_>> {
        // We need to resolve the TargetHop into a precise HopLocation so our msg handler can match
        // the right Leg/Hop with inbound cell.
        let (sender, receiver) = oneshot::channel();
        self.command
            .unbounded_send(CtrlCmd::ResolveTargetHop { hop, done: sender })
            .map_err(|_| Error::CircuitClosed)?;
        let hop_location = receiver.await.map_err(|_| Error::CircuitClosed)??;
        let handler = Box::new(UserMsgHandler::new(hop_location, reply_handler));
        let conversation = Conversation(self);
        conversation.send_internal(msg, Some(handler)).await?;
        Ok(conversation)
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
        hop: TargetHop,
    ) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        let ctrl_msg = CtrlMsg::SendMsg { hop, msg, sender };
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
        hop: TargetHop,
        filter: impl crate::stream::IncomingStreamRequestFilter,
    ) -> Result<impl futures::Stream<Item = IncomingStream>> {
        use futures::stream::StreamExt;

        /// The size of the channel receiving IncomingStreamRequestContexts.
        const INCOMING_BUFFER: usize = STREAM_READER_BUFFER;

        // TODO(#2002): support onion service conflux
        let circ_count = self.mutable.n_legs();
        if circ_count != 1 {
            return Err(
                internal!("Cannot allow stream requests on tunnel with {circ_count} legs",).into(),
            );
        }

        let time_prov = self.time_provider.clone();
        let cmd_checker = IncomingCmdChecker::new_any(allow_commands);
        let (incoming_sender, incoming_receiver) =
            MpscSpec::new(INCOMING_BUFFER).new_mq(time_prov, self.memquota.as_raw_account())?;
        let (tx, rx) = oneshot::channel();

        self.command
            .unbounded_send(CtrlCmd::AwaitStreamRequest {
                cmd_checker,
                incoming_sender,
                hop,
                done: tx,
                filter: Box::new(filter),
            })
            .map_err(|_| Error::CircuitClosed)?;

        // Check whether the AwaitStreamRequest was processed successfully.
        rx.await.map_err(|_| Error::CircuitClosed)??;

        let allowed_hop_loc = match hop {
            TargetHop::Hop(loc) => Some(loc),
            _ => None,
        }
        .ok_or_else(|| bad_api_usage!("Expected TargetHop with HopLocation"))?;

        let circ = Arc::clone(self);
        Ok(incoming_receiver.map(move |req_ctx| {
            let StreamReqInfo {
                req,
                stream_id,
                hop,
                receiver,
                msg_tx,
                memquota,
                relay_cell_format,
            } = req_ctx;

            // We already enforce this in handle_incoming_stream_request; this
            // assertion is just here to make sure that we don't ever
            // accidentally remove or fail to enforce that check, since it is
            // security-critical.
            assert_eq!(allowed_hop_loc, hop);

            // TODO(#2002): figure out what this is going to look like
            // for onion services (perhaps we should forbid this function
            // from being called on a multipath circuit?)
            //
            // See also:
            // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3002#note_3200937
            let target = StreamTarget {
                circ: Arc::clone(&circ),
                tx: msg_tx,
                hop: allowed_hop_loc,
                stream_id,
                relay_cell_format,
            };

            let reader = StreamReceiver {
                target: target.clone(),
                receiver,
                recv_window: StreamRecvWindow::new(RECV_WINDOW_INIT),
                ended: false,
            };

            IncomingStream::new(circ.time_provider.clone(), req, target, reader, memquota)
        }))
    }

    /// Extend the circuit, via the most appropriate circuit extension handshake,
    /// to the chosen `target` hop.
    pub async fn extend<Tg>(&self, target: &Tg, params: CircParameters) -> Result<()>
    where
        Tg: CircTarget,
    {
        // For now we use the simplest decision-making mechanism:
        // we use ntor_v3 whenever it is present; and otherwise we use ntor.
        //
        // This behavior is slightly different from C tor, which uses ntor v3
        // only whenever it want to send any extension in the circuit message.
        // But thanks to congestion control (named::FLOWCTRL_CC), we'll _always_
        // want to use an extension if we can, and so it doesn't make too much
        // sense to detect the case where we have no extensions.
        //
        // (As of April 2025, RELAY_NTORV3 is not yet listed as Required for relays
        // on the tor network, and so we cannot simply assume that everybody has it.)
        if target
            .protovers()
            .supports_named_subver(named::RELAY_NTORV3)
        {
            self.extend_ntor_v3(target, params).await
        } else {
            self.extend_ntor(target, params).await
        }
    }

    /// Extend the circuit via the ntor handshake to a new target last
    /// hop.
    pub async fn extend_ntor<Tg>(&self, target: &Tg, params: CircParameters) -> Result<()>
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
        if !params.extend_by_ed25519_id {
            linkspecs.retain(|ls| ls.lstype() != LinkSpecType::ED25519ID);
        }

        let (tx, rx) = oneshot::channel();

        let peer_id = OwnedChanTarget::from_chan_target(target);
        let settings =
            HopSettings::from_params_and_caps(&params, target.protovers())?.without_negotiation();
        self.control
            .unbounded_send(CtrlMsg::ExtendNtor {
                peer_id,
                public_key: key,
                linkspecs,
                settings,
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)??;

        Ok(())
    }

    /// Extend the circuit via the ntor handshake to a new target last
    /// hop.
    pub async fn extend_ntor_v3<Tg>(&self, target: &Tg, params: CircParameters) -> Result<()>
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
        if !params.extend_by_ed25519_id {
            linkspecs.retain(|ls| ls.lstype() != LinkSpecType::ED25519ID);
        }

        let (tx, rx) = oneshot::channel();

        let peer_id = OwnedChanTarget::from_chan_target(target);
        let settings = HopSettings::from_params_and_caps(&params, target.protovers())?;
        self.control
            .unbounded_send(CtrlMsg::ExtendNtorV3 {
                peer_id,
                public_key: key,
                linkspecs,
                settings,
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
    #[cfg(feature = "hs-common")]
    pub async fn extend_virtual(
        &self,
        protocol: handshake::RelayProtocol,
        role: handshake::HandshakeRole,
        seed: impl handshake::KeyGenerator,
        params: &CircParameters,
        capabilities: &tor_protover::Protocols,
    ) -> Result<()> {
        use self::handshake::BoxedClientLayer;

        let protocol = handshake::RelayCryptLayerProtocol::from(protocol);
        let relay_cell_format = protocol.relay_cell_format();

        let BoxedClientLayer { fwd, back, binding } =
            protocol.construct_client_layers(role, seed)?;

        let settings = HopSettings::from_params_and_caps(params, capabilities)?
            // TODO #2037: We _should_ support negotiation here; see #2037.
            .without_negotiation();
        let (tx, rx) = oneshot::channel();
        let message = CtrlCmd::ExtendVirtual {
            relay_cell_format,
            cell_crypto: (fwd, back, binding),
            settings,
            done: tx,
        };

        self.command
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
    ) -> Result<(StreamReceiver, StreamTarget, StreamAccount)> {
        // TODO: Possibly this should take a hop, rather than just
        // assuming it's the last hop.
        let hop = TargetHop::LastHop;

        let time_prov = self.time_provider.clone();

        let memquota = StreamAccount::new(self.mq_account())?;
        let (sender, receiver) = MpscSpec::new(STREAM_READER_BUFFER)
            .new_mq(time_prov.clone(), memquota.as_raw_account())?;
        let (tx, rx) = oneshot::channel();
        let (msg_tx, msg_rx) =
            MpscSpec::new(CIRCUIT_BUFFER_SIZE).new_mq(time_prov, memquota.as_raw_account())?;

        self.control
            .unbounded_send(CtrlMsg::BeginStream {
                hop,
                message: begin_msg,
                sender,
                rx: msg_rx,
                done: tx,
                cmd_checker,
            })
            .map_err(|_| Error::CircuitClosed)?;

        let (stream_id, hop, relay_cell_format) = rx.await.map_err(|_| Error::CircuitClosed)??;

        let target = StreamTarget {
            circ: self.clone(),
            tx: msg_tx,
            hop,
            stream_id,
            relay_cell_format,
        };

        let stream_receiver = StreamReceiver {
            target: target.clone(),
            receiver,
            recv_window: StreamRecvWindow::new(RECV_WINDOW_INIT),
            ended: false,
        };

        Ok((stream_receiver, target, memquota))
    }

    /// Start a DataStream (anonymized connection) to the given
    /// address and port, using a BEGIN cell.
    async fn begin_data_stream(
        self: &Arc<ClientCirc>,
        msg: AnyRelayMsg,
        optimistic: bool,
    ) -> Result<DataStream> {
        let (stream_receiver, target, memquota) = self
            .begin_stream_impl(msg, DataCmdChecker::new_any())
            .await?;
        let mut stream = DataStream::new(
            self.time_provider.clone(),
            stream_receiver,
            target,
            memquota,
        );
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
        let (stream_receiver, _target, memquota) = self
            .begin_stream_impl(msg.into(), ResolveCmdChecker::new_any())
            .await?;
        let mut resolve_stream = ResolveStream::new(stream_receiver, memquota);
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
        let _ = self.command.unbounded_send(CtrlCmd::Shutdown);
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
    pub fn n_hops(&self) -> Result<usize> {
        self.mutable
            .n_hops(self.unique_id)
            .map_err(|_| Error::CircuitClosed)
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
//
// TODO(conflux): this should use ClientTunnel, and it should be moved into
// the tunnel module.
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
    pub(crate) async fn send_internal(
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
        input: CircuitRxReceiver,
        unique_id: UniqId,
        runtime: DynTimeProvider,
        memquota: CircuitAccount,
    ) -> (PendingClientCirc, crate::tunnel::reactor::Reactor) {
        let time_provider = channel.time_provider().clone();
        let (reactor, control_tx, command_tx, reactor_closed_rx, mutable) =
            Reactor::new(channel, id, unique_id, input, runtime, memquota.clone());

        let circuit = ClientCirc {
            mutable,
            unique_id,
            control: control_tx,
            command: command_tx,
            reactor_closed_rx: reactor_closed_rx.shared(),
            #[cfg(test)]
            circid: id,
            memquota,
            time_provider,
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
    pub async fn create_firsthop_fast(self, params: CircParameters) -> Result<Arc<ClientCirc>> {
        // We no nothing about this relay, so we assume it supports no protocol capabilities at all.
        //
        // TODO: If we had a consensus, we could assume it supported all required-relay-protocols.
        let protocols = tor_protover::Protocols::new();
        let settings =
            HopSettings::from_params_and_caps(&params, &protocols)?.without_negotiation();

        let (tx, rx) = oneshot::channel();
        self.circ
            .control
            .unbounded_send(CtrlMsg::Create {
                recv_created: self.recvcreated,
                handshake: CircuitHandshake::CreateFast,
                settings,
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)??;

        Ok(self.circ)
    }

    /// Use the most appropriate handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided 'target' must match the channel's target,
    /// or the handshake will fail.
    pub async fn create_firsthop<Tg>(
        self,
        target: &Tg,
        params: CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        Tg: tor_linkspec::CircTarget,
    {
        // (See note in ClientCirc::extend.)
        if target
            .protovers()
            .supports_named_subver(named::RELAY_NTORV3)
        {
            self.create_firsthop_ntor_v3(target, params).await
        } else {
            self.create_firsthop_ntor(target, params).await
        }
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
        let settings =
            HopSettings::from_params_and_caps(&params, target.protovers())?.without_negotiation();

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
                settings,
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
    pub async fn create_firsthop_ntor_v3<Tg>(
        self,
        target: &Tg,
        params: CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        Tg: tor_linkspec::CircTarget,
    {
        let settings = HopSettings::from_params_and_caps(&params, target.protovers())?;
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
                settings,
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)??;

        Ok(self.circ)
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
pub(crate) mod test {
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
    use crate::congestion::test_utils::params::build_cc_vegas_params;
    use crate::crypto::cell::RelayCellBody;
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
    use std::fmt::Debug;
    use std::time::Duration;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_cell::chancell::{msg as chanmsg, AnyChanCell, BoxedCellBody, ChanCell, ChanCmd};
    use tor_cell::relaycell::extend::{self as extend_ext, CircRequestExt, CircResponseExt};
    use tor_cell::relaycell::msg::SendmeTag;
    use tor_cell::relaycell::{
        msg as relaymsg, AnyRelayMsgOuter, RelayCellFormat, RelayCmd, RelayMsg as _, StreamId,
    };
    use tor_linkspec::OwnedCircTarget;
    use tor_memquota::HasMemoryCost;
    use tor_rtcompat::Runtime;
    use tracing::trace;
    use tracing_test::traced_test;

    #[cfg(feature = "conflux")]
    use {
        crate::tunnel::reactor::ConfluxHandshakeResult,
        crate::util::err::ConfluxHandshakeError,
        futures::lock::Mutex as AsyncMutex,
        std::result::Result as StdResult,
        tor_cell::relaycell::conflux::{V1DesiredUx, V1LinkPayload, V1Nonce},
        tor_cell::relaycell::msg::ConfluxLink,
        tor_rtmock::MockRuntime,
    };

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
        // TODO #1947: test other formats.
        let rfmt = RelayCellFormat::V0;
        let body: BoxedCellBody = AnyRelayMsgOuter::new(id, msg)
            .encode(rfmt, &mut testing_rng())
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

    /// Make an MPSC queue, of the type we use in Channels, but a fake one for testing
    #[cfg(test)]
    pub(crate) fn fake_mpsc<T: HasMemoryCost + Debug + Send>(
        buffer: usize,
    ) -> (StreamMpscSender<T>, StreamMpscReceiver<T>) {
        crate::fake_mpsc(buffer)
    }

    /// return an example OwnedCircTarget that can get used for an ntor handshake.
    fn example_target() -> OwnedCircTarget {
        let mut builder = OwnedCircTarget::builder();
        builder
            .chan_target()
            .ed_identity(EXAMPLE_ED_ID.into())
            .rsa_identity(EXAMPLE_RSA_ID.into());
        builder
            .ntor_onion_key(EXAMPLE_PK.into())
            .protocols("FlowCtrl=1-2".parse().unwrap())
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
        NtorV3,
    }

    async fn test_create<R: Runtime>(rt: &R, handshake_type: HandshakeType, with_cc: bool) {
        // We want to try progressing from a pending circuit to a circuit
        // via a crate_fast handshake.

        use crate::crypto::handshake::{fast::CreateFastServer, ntor::NtorServer, ServerHandshake};

        let (chan, mut rx, _sink) = working_fake_channel(rt);
        let circid = CircId::new(128).unwrap();
        let (created_send, created_recv) = oneshot::channel();
        let (_circmsg_send, circmsg_recv) = fake_mpsc(64);
        let unique_id = UniqId::new(23, 17);

        let (pending, reactor) = PendingClientCirc::new(
            circid,
            chan,
            created_recv,
            circmsg_recv,
            unique_id,
            DynTimeProvider::new(rt.clone()),
            CircuitAccount::new_noop(),
        );

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
                        other => panic!("{:?}", other),
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
                        other => panic!("{:?}", other),
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
                HandshakeType::NtorV3 => {
                    let c2 = match create_cell.msg() {
                        AnyChanMsg::Create2(c2) => c2,
                        other => panic!("{:?}", other),
                    };
                    let mut reply_fn = if with_cc {
                        |client_exts: &[CircRequestExt]| {
                            let _ = client_exts
                                .iter()
                                .find(|e| matches!(e, CircRequestExt::CcRequest(_)))
                                .expect("Client failed to request CC");
                            // This needs to be aligned to test_utils params
                            // value due to validation that needs it in range.
                            Some(vec![CircResponseExt::CcResponse(
                                extend_ext::CcResponse::new(31),
                            )])
                        }
                    } else {
                        |_: &_| Some(vec![])
                    };
                    let (_, rep) = NtorV3Server::server(
                        &mut rng,
                        &mut reply_fn,
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
                    pending.create_firsthop_fast(params).await
                }
                HandshakeType::Ntor => {
                    trace!("doing ntor create");
                    pending.create_firsthop_ntor(&target, params).await
                }
                HandshakeType::NtorV3 => {
                    let params = if with_cc {
                        // Setup CC vegas parameters.
                        CircParameters::new(true, build_cc_vegas_params())
                    } else {
                        params
                    };
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
        assert_eq!(_circ.n_hops().unwrap(), 1);
    }

    #[traced_test]
    #[test]
    fn test_create_fast() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_create(&rt, HandshakeType::Fast, false).await;
        });
    }
    #[traced_test]
    #[test]
    fn test_create_ntor() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_create(&rt, HandshakeType::Ntor, false).await;
        });
    }
    #[traced_test]
    #[test]
    fn test_create_ntor_v3() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_create(&rt, HandshakeType::NtorV3, false).await;
        });
    }
    #[traced_test]
    #[test]
    #[cfg(feature = "flowctl-cc")]
    fn test_create_ntor_v3_with_cc() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_create(&rt, HandshakeType::NtorV3, true).await;
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
        fn next_tag(&mut self) -> SendmeTag {
            #![allow(clippy::identity_op)]
            self.counter_tag[0] = ((self.counter >> 0) & 255) as u8;
            self.counter_tag[1] = ((self.counter >> 8) & 255) as u8;
            self.counter_tag[2] = ((self.counter >> 16) & 255) as u8;
            self.counter_tag[3] = ((self.counter >> 24) & 255) as u8;
            self.counter += 1;
            self.counter_tag.into()
        }
    }

    impl crate::crypto::cell::OutboundClientLayer for DummyCrypto {
        fn originate_for(&mut self, _cmd: ChanCmd, _cell: &mut RelayCellBody) -> SendmeTag {
            self.next_tag()
        }
        fn encrypt_outbound(&mut self, _cmd: ChanCmd, _cell: &mut RelayCellBody) {}
    }
    impl crate::crypto::cell::InboundClientLayer for DummyCrypto {
        fn decrypt_inbound(
            &mut self,
            _cmd: ChanCmd,
            _cell: &mut RelayCellBody,
        ) -> Option<SendmeTag> {
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
        unique_id: UniqId,
        chan: Arc<Channel>,
        hops: Vec<path::HopDetail>,
        next_msg_from: HopNum,
        params: CircParameters,
    ) -> (Arc<ClientCirc>, CircuitRxSender) {
        let circid = CircId::new(128).unwrap();
        let (_created_send, created_recv) = oneshot::channel();
        let (circmsg_send, circmsg_recv) = fake_mpsc(64);

        let (pending, reactor) = PendingClientCirc::new(
            circid,
            chan,
            created_recv,
            circmsg_recv,
            unique_id,
            DynTimeProvider::new(rt.clone()),
            CircuitAccount::new_noop(),
        );

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

        let last_hop_num = u8::try_from(hops.len() - 1).unwrap();
        for (idx, peer_id) in hops.into_iter().enumerate() {
            let (tx, rx) = oneshot::channel();
            let idx = idx as u8;

            circ.command
                .unbounded_send(CtrlCmd::AddFakeHop {
                    relay_cell_format,
                    fwd_lasthop: idx == last_hop_num,
                    rev_lasthop: idx == u8::from(next_msg_from),
                    peer_id,
                    params: params.clone(),
                    done: tx,
                })
                .unwrap();
            rx.await.unwrap().unwrap();
        }

        (circ, circmsg_send)
    }

    // Helper: set up a 3-hop circuit with no encryption, where the
    // next inbound message seems to come from hop next_msg_from
    async fn newcirc<R: Runtime>(rt: &R, chan: Arc<Channel>) -> (Arc<ClientCirc>, CircuitRxSender) {
        let hops = std::iter::repeat_with(|| {
            let peer_id = tor_linkspec::OwnedChanTarget::builder()
                .ed_identity([4; 32].into())
                .rsa_identity([5; 20].into())
                .build()
                .expect("Could not construct fake hop");

            path::HopDetail::Relay(peer_id)
        })
        .take(3)
        .collect();

        let unique_id = UniqId::new(23, 17);
        newcirc_ext(
            rt,
            unique_id,
            chan,
            hops,
            2.into(),
            CircParameters::default(),
        )
        .await
    }

    /// Create `n` distinct [`path::HopDetail`]s,
    /// with the specified `start_idx` for the dummy identities.
    fn hop_details(n: u8, start_idx: u8) -> Vec<path::HopDetail> {
        (0..n)
            .map(|idx| {
                let peer_id = tor_linkspec::OwnedChanTarget::builder()
                    .ed_identity([idx + start_idx; 32].into())
                    .rsa_identity([idx + start_idx + 1; 20].into())
                    .build()
                    .expect("Could not construct fake hop");

                path::HopDetail::Relay(peer_id)
            })
            .collect()
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
                HandshakeType::Ntor => circ.extend_ntor(&target, params).await.unwrap(),
                HandshakeType::NtorV3 => circ.extend_ntor_v3(&target, params).await.unwrap(),
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
                other => panic!("{:?}", other),
            };
            let e2 = match rmsg.msg() {
                AnyRelayMsg::Extend2(e2) => e2,
                other => panic!("{:?}", other),
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
                HandshakeType::NtorV3 => {
                    let (_keygen, reply) = NtorV3Server::server(
                        &mut rng,
                        &mut |_: &[CircRequestExt]| Some(vec![]),
                        &[example_ntor_v3_key()],
                        e2.handshake(),
                    )
                    .unwrap();
                    reply
                }
            };

            let extended2 = relaymsg::Extended2::new(reply).into();
            sink.send(rmsg_to_ccmsg(None, extended2)).await.unwrap();
            (sink, rx) // gotta keep the sink and receiver alive, or the reactor will exit.
        };

        let (circ, (_sink, _rx)) = futures::join!(extend_fut, reply_fut);

        // Did we really add another hop?
        assert_eq!(circ.n_hops().unwrap(), 4);

        // Do the path accessors report a reasonable outcome?
        {
            let path = circ.path_ref().unwrap();
            let path = path
                .all_hops()
                .filter_map(|hop| match hop {
                    path::HopDetail::Relay(r) => Some(r),
                    #[cfg(feature = "hs-common")]
                    path::HopDetail::Virtual => None,
                })
                .collect::<Vec<_>>();

            assert_eq!(path.len(), 4);
            use tor_linkspec::HasRelayIds;
            assert_eq!(path[3].ed_identity(), example_target().ed_identity());
            assert_ne!(path[0].ed_identity(), example_target().ed_identity());
        }
        {
            let path = circ.path_ref().unwrap();
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

    #[traced_test]
    #[test]
    fn test_extend_ntor() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_extend(&rt, HandshakeType::Ntor).await;
        });
    }

    #[traced_test]
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
        let hops = std::iter::repeat_with(|| {
            let peer_id = tor_linkspec::OwnedChanTarget::builder()
                .ed_identity([4; 32].into())
                .rsa_identity([5; 20].into())
                .build()
                .expect("Could not construct fake hop");

            path::HopDetail::Relay(peer_id)
        })
        .take(3)
        .collect();

        let unique_id = UniqId::new(23, 17);
        let (circ, mut sink) = newcirc_ext(
            rt,
            unique_id,
            chan,
            hops,
            reply_hop,
            CircParameters::default(),
        )
        .await;
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
        let outcome = circ.extend_ntor(&target, params).await;
        let _sink = sink_handle.await;

        assert_eq!(circ.n_hops().unwrap(), 3);
        assert!(outcome.is_err());
        outcome.unwrap_err()
    }

    #[traced_test]
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

    #[traced_test]
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
                other => panic!("{:?}", other),
            }
        });
    }

    #[traced_test]
    #[test]
    fn bad_extend_destroy() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let cc = ClientCircChanMsg::Destroy(chanmsg::Destroy::new(4.into()));
            let error = bad_extend_test_impl(&rt, 2.into(), cc).await;
            match error {
                Error::CircuitClosed => {}
                other => panic!("{:?}", other),
            }
        });
    }

    #[traced_test]
    #[test]
    fn bad_extend_crypto() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let extended2 = relaymsg::Extended2::new(vec![99; 256]).into();
            let cc = rmsg_to_ccmsg(None, extended2);
            let error = bad_extend_test_impl(&rt, 2.into(), cc).await;
            assert!(matches!(error, Error::BadCircHandshakeAuth));
        });
    }

    #[traced_test]
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
                    other => panic!("{:?}", other),
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
                    other => panic!("{:?}", other),
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
                    other => panic!("{:?}", other),
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
                    other => panic!("{:?}", other),
                };
                let (_, rmsg) = rmsg.into_streamid_and_msg();
                assert_eq!(rmsg.cmd(), RelayCmd::END);

                (rx, sink) // keep these alive or the reactor will exit.
            };

            let ((_opt_reader, _circ), (_rx, _sink)) = futures::join!(stream_fut, handler_fut);
        });
    }

    #[traced_test]
    #[test]
    fn drop_stream() {
        close_stream_helper(true);
    }

    #[traced_test]
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
        CircuitRxSender,
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
                other => panic!("{:?}", other),
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
                    other => panic!("{:?}", other),
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

    #[traced_test]
    #[test]
    fn accept_valid_sendme() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (circ, _stream, mut sink, streamid, cells_received, _rx, _sink2) =
                setup_incoming_sendme_case(&rt, 300 * 498 + 3).await;

            assert_eq!(cells_received, 301);

            // Make sure that the circuit is indeed expecting the right sendmes
            {
                let (tx, rx) = oneshot::channel();
                circ.command
                    .unbounded_send(CtrlCmd::QuerySendWindow {
                        hop: 2.into(),
                        leg: circ.unique_id(),
                        done: tx,
                    })
                    .unwrap();
                let (window, tags) = rx.await.unwrap().unwrap();
                assert_eq!(window, 1000 - 301);
                assert_eq!(tags.len(), 3);
                // 100
                assert_eq!(
                    tags[0],
                    SendmeTag::from(hex!("6400000000000000000000000000000000000000"))
                );
                // 200
                assert_eq!(
                    tags[1],
                    SendmeTag::from(hex!("c800000000000000000000000000000000000000"))
                );
                // 300
                assert_eq!(
                    tags[2],
                    SendmeTag::from(hex!("2c01000000000000000000000000000000000000"))
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

            rt.advance_until_stalled().await;

            // Now make sure that the circuit is still happy, and its
            // window is updated.
            {
                let (tx, rx) = oneshot::channel();
                circ.command
                    .unbounded_send(CtrlCmd::QuerySendWindow {
                        hop: 2.into(),
                        leg: circ.unique_id(),
                        done: tx,
                    })
                    .unwrap();
                let (window, _tags) = rx.await.unwrap().unwrap();
                assert_eq!(window, 1000 - 201);
            }
        });
    }

    #[traced_test]
    #[test]
    fn invalid_circ_sendme() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
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

            // Check whether the reactor dies as a result of receiving invalid data.
            rt.advance_until_stalled().await;
            assert!(circ.is_closing());
        });
    }

    #[traced_test]
    #[test]
    fn test_busy_stream_fairness() {
        // Number of streams to use.
        const N_STREAMS: usize = 3;
        // Number of cells (roughly) for each stream to send.
        const N_CELLS: usize = 20;
        // Number of bytes that *each* stream will send, and that we'll read
        // from the channel.
        const N_BYTES: usize = relaymsg::Data::MAXLEN_V0 * N_CELLS;
        // Ignoring cell granularity, with perfect fairness we'd expect
        // `N_BYTES/N_STREAMS` bytes from each stream.
        //
        // We currently allow for up to a full cell less than that.  This is
        // somewhat arbitrary and can be changed as needed, since we don't
        // provide any specific fairness guarantees.
        const MIN_EXPECTED_BYTES_PER_STREAM: usize =
            N_BYTES / N_STREAMS - relaymsg::Data::MAXLEN_V0;

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
        assert!(p.extend_by_ed25519_id);

        p.extend_by_ed25519_id = false;
        assert!(!p.extend_by_ed25519_id);
    }

    #[cfg(feature = "hs-service")]
    struct AllowAllStreamsFilter;
    #[cfg(feature = "hs-service")]
    impl IncomingStreamRequestFilter for AllowAllStreamsFilter {
        fn disposition(
            &mut self,
            _ctx: &crate::stream::IncomingStreamRequestContext<'_>,
            _circ: &crate::tunnel::reactor::syncview::ClientCircSyncView<'_>,
        ) -> Result<crate::stream::IncomingStreamRequestDisposition> {
            Ok(crate::stream::IncomingStreamRequestDisposition::Accept)
        }
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "hs-service")]
    fn allow_stream_requests_twice() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, _rx, _sink) = working_fake_channel(&rt);
            let (circ, _send) = newcirc(&rt, chan).await;

            let _incoming = circ
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    circ.last_hop().unwrap(),
                    AllowAllStreamsFilter,
                )
                .await
                .unwrap();

            let incoming = circ
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    circ.last_hop().unwrap(),
                    AllowAllStreamsFilter,
                )
                .await;

            // There can only be one IncomingStream at a time on any given circuit.
            assert!(incoming.is_err());
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "hs-service")]
    fn allow_stream_requests() {
        use tor_cell::relaycell::msg::BeginFlags;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            const TEST_DATA: &[u8] = b"ping";

            let (chan, _rx, _sink) = working_fake_channel(&rt);
            let (circ, mut send) = newcirc(&rt, chan).await;

            let rfmt = RelayCellFormat::V0;

            // A helper channel for coordinating the "client"/"service" interaction
            let (tx, rx) = oneshot::channel();
            let mut incoming = circ
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    circ.last_hop().unwrap(),
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
                        .encode(rfmt, &mut testing_rng())
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
                        .encode(rfmt, &mut testing_rng())
                        .unwrap();
                let data_msg = chanmsg::Relay::from(body);

                send.send(ClientCircChanMsg::Relay(data_msg)).await.unwrap();
                send
            };

            let (_circ, _send) = futures::join!(simulate_service, simulate_client);
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "hs-service")]
    fn accept_stream_after_reject() {
        use tor_cell::relaycell::msg::BeginFlags;
        use tor_cell::relaycell::msg::EndReason;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            const TEST_DATA: &[u8] = b"ping";
            const STREAM_COUNT: usize = 2;
            let rfmt = RelayCellFormat::V0;

            let (chan, _rx, _sink) = working_fake_channel(&rt);
            let (circ, mut send) = newcirc(&rt, chan).await;

            // A helper channel for coordinating the "client"/"service" interaction
            let (mut tx, mut rx) = mpsc::channel(STREAM_COUNT);

            let mut incoming = circ
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    circ.last_hop().unwrap(),
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
                        .encode(rfmt, &mut testing_rng())
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
                        .encode(rfmt, &mut testing_rng())
                        .unwrap();
                let data_msg = chanmsg::Relay::from(body);

                send.send(ClientCircChanMsg::Relay(data_msg)).await.unwrap();
                send
            };

            let (_circ, _send) = futures::join!(simulate_service, simulate_client);
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "hs-service")]
    fn incoming_stream_bad_hop() {
        use tor_cell::relaycell::msg::BeginFlags;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            /// Expect the originator of the BEGIN cell to be hop 1.
            const EXPECTED_HOP: u8 = 1;
            let rfmt = RelayCellFormat::V0;

            let (chan, _rx, _sink) = working_fake_channel(&rt);
            let (circ, mut send) = newcirc(&rt, chan).await;

            // Expect to receive incoming streams from hop EXPECTED_HOP
            let mut incoming = circ
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    (circ.unique_id(), EXPECTED_HOP.into()).into(),
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
                        .encode(rfmt, &mut testing_rng())
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

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn multipath_circ_validation() {
        use std::error::Error as _;

        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let params = CircParameters::default();
            let invalid_tunnels = [
                setup_bad_conflux_tunnel(&rt).await,
                setup_conflux_tunnel(&rt, true, params).await,
            ];

            for tunnel in invalid_tunnels {
                let TestTunnelCtx {
                    tunnel: _tunnel,
                    circs: _circs,
                    conflux_link_rx,
                } = tunnel;

                let conflux_hs_err = conflux_link_rx.await.unwrap().unwrap_err();
                let err_src = conflux_hs_err.source().unwrap();

                // The two circuits don't end in the same hop (no join point),
                // so the reactor will refuse to link them
                assert!(err_src
                    .to_string()
                    .contains("one more more conflux circuits are invalid"));
            }
        });
    }

    // TODO: this structure could be reused for the other tests,
    // to address nickm's comment:
    // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3005#note_3202362
    #[derive(Debug)]
    #[allow(unused)]
    #[cfg(feature = "conflux")]
    struct TestCircuitCtx {
        chan_rx: Receiver<AnyChanCell>,
        chan_tx: Sender<std::result::Result<OpenChanCellS2C, CodecError>>,
        circ_tx: CircuitRxSender,
        unique_id: UniqId,
    }

    #[derive(Debug)]
    #[cfg(feature = "conflux")]
    struct TestTunnelCtx {
        tunnel: Arc<ClientCirc>,
        circs: Vec<TestCircuitCtx>,
        conflux_link_rx: oneshot::Receiver<Result<ConfluxHandshakeResult>>,
    }

    /// Wait for a LINK cell to arrive on the specified channel and return its payload.
    #[cfg(feature = "conflux")]
    async fn await_link_payload(rx: &mut Receiver<AnyChanCell>) -> ConfluxLink {
        // Wait for the LINK cell...
        let (_id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
        let rmsg = match chmsg {
            AnyChanMsg::Relay(r) => {
                AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                    .unwrap()
            }
            other => panic!("{:?}", other),
        };
        let (streamid, rmsg) = rmsg.into_streamid_and_msg();

        let link = match rmsg {
            AnyRelayMsg::ConfluxLink(link) => link,
            _ => panic!("unexpected relay message {rmsg:?}"),
        };

        assert!(streamid.is_none());

        link
    }

    #[cfg(feature = "conflux")]
    async fn setup_conflux_tunnel(
        rt: &MockRuntime,
        same_hops: bool,
        params: CircParameters,
    ) -> TestTunnelCtx {
        let hops1 = hop_details(3, 0);
        let hops2 = if same_hops {
            hops1.clone()
        } else {
            hop_details(3, 10)
        };

        let (chan1, rx1, chan_sink1) = working_fake_channel(rt);
        let (circ1, sink1) = newcirc_ext(
            rt,
            UniqId::new(1, 3),
            chan1,
            hops1,
            2.into(),
            params.clone(),
        )
        .await;

        let (chan2, rx2, chan_sink2) = working_fake_channel(rt);

        let (circ2, sink2) =
            newcirc_ext(rt, UniqId::new(2, 4), chan2, hops2, 2.into(), params).await;

        let (answer_tx, answer_rx) = oneshot::channel();
        circ2
            .command
            .unbounded_send(CtrlCmd::ShutdownAndReturnCircuit { answer: answer_tx })
            .unwrap();

        let circuit = answer_rx.await.unwrap().unwrap();
        // The circuit should be shutting down its reactor
        rt.advance_until_stalled().await;
        assert!(circ2.is_closing());

        let (conflux_link_tx, conflux_link_rx) = oneshot::channel();
        // Tell the first circuit to link with the second and form a multipath tunnel
        circ1
            .control
            .unbounded_send(CtrlMsg::LinkCircuits {
                circuits: vec![circuit],
                answer: conflux_link_tx,
            })
            .unwrap();

        let circ_ctx1 = TestCircuitCtx {
            chan_rx: rx1,
            chan_tx: chan_sink1,
            circ_tx: sink1,
            unique_id: circ1.unique_id(),
        };

        let circ_ctx2 = TestCircuitCtx {
            chan_rx: rx2,
            chan_tx: chan_sink2,
            circ_tx: sink2,
            unique_id: circ2.unique_id(),
        };

        TestTunnelCtx {
            tunnel: circ1,
            circs: vec![circ_ctx1, circ_ctx2],
            conflux_link_rx,
        }
    }

    #[cfg(feature = "conflux")]
    async fn setup_good_conflux_tunnel(rt: &MockRuntime) -> TestTunnelCtx {
        // Our 2 test circuits are identical, so they both have the same guards,
        // which technically violates the conflux set rule mentioned in prop354.
        // For testing purposes this is fine, but in production we'll need to ensure
        // the calling code prevents guard reuse (except in the case where
        // one of the guards happens to be Guard + Exit)
        let same_hops = true;
        let params = CircParameters::new(true, build_cc_vegas_params());
        setup_conflux_tunnel(rt, same_hops, params).await
    }

    #[cfg(feature = "conflux")]
    async fn setup_bad_conflux_tunnel(rt: &MockRuntime) -> TestTunnelCtx {
        // The two circuits don't share any hops,
        // so they won't end in the same hop (no join point),
        // causing the reactor to refuse to link them.
        let same_hops = false;
        let params = CircParameters::new(true, build_cc_vegas_params());
        setup_conflux_tunnel(rt, same_hops, params).await
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn reject_conflux_linked_before_hs() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (chan, mut _rx, _sink) = working_fake_channel(&rt);
            let (circ, mut sink) = newcirc(&rt, chan).await;

            let nonce = V1Nonce::new(&mut testing_rng());
            let payload = V1LinkPayload::new(nonce, V1DesiredUx::NO_OPINION);
            // Send a LINKED cell
            let linked = relaymsg::ConfluxLinked::new(payload).into();
            sink.send(rmsg_to_ccmsg(None, linked)).await.unwrap();

            rt.advance_until_stalled().await;
            assert!(circ.is_closing());
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn conflux_hs_timeout() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let TestTunnelCtx {
                tunnel: _tunnel,
                circs,
                conflux_link_rx,
            } = setup_good_conflux_tunnel(&rt).await;

            let [mut circ1, _circ2]: [TestCircuitCtx; 2] = circs.try_into().unwrap();

            // Wait for the LINK cell
            let link = await_link_payload(&mut circ1.chan_rx).await;

            // Send a LINK cell on the first leg...
            let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
            circ1
                .circ_tx
                .send(rmsg_to_ccmsg(None, linked))
                .await
                .unwrap();

            // Do nothing, and wait for the handshake to timeout on the second leg
            rt.advance_by(Duration::from_secs(60)).await;

            let conflux_hs_res = conflux_link_rx.await.unwrap().unwrap();

            // Get the handshake results of each circuit
            let [res1, res2]: [StdResult<(), ConfluxHandshakeError>; 2] =
                conflux_hs_res.try_into().unwrap();

            assert!(res1.is_ok());

            let err = res2.unwrap_err();
            assert!(matches!(err, ConfluxHandshakeError::Timeout), "{err:?}");
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn conflux_bad_hs() {
        use crate::util::err::ConfluxHandshakeError;

        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let nonce = V1Nonce::new(&mut testing_rng());
            let bad_link_payload = V1LinkPayload::new(nonce, V1DesiredUx::NO_OPINION);
            //let extended2 = relaymsg::Extended2::new(vec![]).into();
            let bad_hs_responses = [
                (
                    rmsg_to_ccmsg(
                        None,
                        relaymsg::ConfluxLinked::new(bad_link_payload.clone()).into(),
                    ),
                    "Received CONFLUX_LINKED cell with mismatched nonce",
                ),
                (
                    rmsg_to_ccmsg(None, relaymsg::ConfluxLink::new(bad_link_payload).into()),
                    "Unexpected CONFLUX_LINK cell from hop #3 on client circuit",
                ),
                (
                    rmsg_to_ccmsg(None, relaymsg::ConfluxSwitch::new(0).into()),
                    "Received CONFLUX_SWITCH on unlinked circuit?!",
                ),
                // TODO: this currently causes the reactor to shut down immediately,
                // without sending a response on the handshake channel
                /*
                (
                    rmsg_to_ccmsg(None, extended2),
                    "Received CONFLUX_LINKED cell with mismatched nonce",
                ),
                */
            ];

            for (bad_cell, expected_err) in bad_hs_responses {
                let TestTunnelCtx {
                    tunnel,
                    circs,
                    conflux_link_rx,
                } = setup_good_conflux_tunnel(&rt).await;

                let [mut _circ1, mut circ2]: [TestCircuitCtx; 2] = circs.try_into().unwrap();

                // Respond with a bogus cell on one of the legs
                circ2.circ_tx.send(bad_cell).await.unwrap();

                let conflux_hs_res = conflux_link_rx.await.unwrap().unwrap();
                // Get the handshake results (the handshake results are reported early,
                // without waiting for the second circuit leg's handshake to timeout,
                // because this is a protocol violation causing the entire tunnel to shut down)
                let [res2]: [StdResult<(), ConfluxHandshakeError>; 1] =
                    conflux_hs_res.try_into().unwrap();

                match res2.unwrap_err() {
                    ConfluxHandshakeError::Link(Error::CircProto(e)) => {
                        assert_eq!(e, expected_err);
                    }
                    e => panic!("unexpected error: {e:?}"),
                }

                assert!(tunnel.is_closing());
            }
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn unexpected_conflux_cell() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let nonce = V1Nonce::new(&mut testing_rng());
            let link_payload = V1LinkPayload::new(nonce, V1DesiredUx::NO_OPINION);
            let bad_cells = [
                rmsg_to_ccmsg(
                    None,
                    relaymsg::ConfluxLinked::new(link_payload.clone()).into(),
                ),
                rmsg_to_ccmsg(
                    None,
                    relaymsg::ConfluxLink::new(link_payload.clone()).into(),
                ),
                rmsg_to_ccmsg(None, relaymsg::ConfluxSwitch::new(0).into()),
            ];

            for bad_cell in bad_cells {
                let (chan, mut _rx, _sink) = working_fake_channel(&rt);
                let (circ, mut sink) = newcirc(&rt, chan).await;

                sink.send(bad_cell).await.unwrap();
                rt.advance_until_stalled().await;

                // Note: unfortunately we can't assert the circuit is
                // closing for the reason, because the reactor just logs
                // the error and then exits.
                assert!(circ.is_closing());
            }
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn conflux_bad_linked() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let TestTunnelCtx {
                tunnel,
                circs,
                conflux_link_rx: _,
            } = setup_good_conflux_tunnel(&rt).await;

            let [mut circ1, mut circ2]: [TestCircuitCtx; 2] = circs.try_into().unwrap();

            let link = await_link_payload(&mut circ1.chan_rx).await;

            // Send a LINK cell on the first leg...
            let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
            circ1
                .circ_tx
                .send(rmsg_to_ccmsg(None, linked))
                .await
                .unwrap();

            // ...and two LINKED cells on the second
            let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
            circ2
                .circ_tx
                .send(rmsg_to_ccmsg(None, linked))
                .await
                .unwrap();
            let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
            circ2
                .circ_tx
                .send(rmsg_to_ccmsg(None, linked))
                .await
                .unwrap();

            rt.advance_until_stalled().await;

            // Receiving a LINKED cell on an already linked leg causes
            // the tunnel to be torn down
            assert!(tunnel.is_closing());
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn conflux_bad_switch() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let bad_switch = [
                // SWITCH cells with seqno = 0 are not allowed
                relaymsg::ConfluxSwitch::new(0),
                // TODO(#2031): from c-tor:
                //
                // We have to make sure that the switch command is truely
                // incrementing the sequence number, or else it becomes
                // a side channel that can be spammed for traffic analysis.
                //
                // We should figure out what this check is supposed to look like,
                // and have a test for it
            ];

            for bad_cell in bad_switch {
                let TestTunnelCtx {
                    tunnel,
                    circs,
                    conflux_link_rx,
                } = setup_good_conflux_tunnel(&rt).await;

                let [mut circ1, mut circ2]: [TestCircuitCtx; 2] = circs.try_into().unwrap();

                let link = await_link_payload(&mut circ1.chan_rx).await;

                // Send a LINKED cell on both legs
                for circ in [&mut circ1, &mut circ2] {
                    let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
                    circ.circ_tx
                        .send(rmsg_to_ccmsg(None, linked))
                        .await
                        .unwrap();
                }

                let conflux_hs_res = conflux_link_rx.await.unwrap().unwrap();
                assert!(conflux_hs_res.iter().all(|res| res.is_ok()));

                // Now send a bad SWITCH cell on *both* legs.
                // This will cause both legs to be removed from the conflux set,
                // which causes the tunnel reactor to shut down
                for circ in [&mut circ1, &mut circ2] {
                    let msg = rmsg_to_ccmsg(None, bad_cell.clone().into());
                    circ.circ_tx.send(msg).await.unwrap();
                }

                // The tunnel should be shutting down
                rt.advance_until_stalled().await;
                assert!(tunnel.is_closing());
            }
        });
    }

    // TODO(conflux): add a test for SWITCH handling

    /// Run a conflux test endpoint.
    #[cfg(feature = "conflux")]
    #[derive(Debug)]
    enum ConfluxTestEndpoint<I: Iterator<Item = Option<Duration>>> {
        /// Pretend to be an exit relay.
        Relay(ConfluxExitState<I>),
        /// Client task.
        Client {
            /// Channel for receiving the outcome of the conflux handshakes.
            conflux_link_rx: oneshot::Receiver<Result<ConfluxHandshakeResult>>,
            /// The tunnel reactor handle
            tunnel: Arc<ClientCirc>,
            /// Data to send on a stream.
            send_data: Vec<u8>,
            /// Data we expect to receive on a stream.
            recv_data: Vec<u8>,
        },
    }

    /// Structure for returning the sinks, channels, etc. that must stay
    /// alive until the test is complete.
    #[allow(unused)]
    #[derive(Debug)]
    #[cfg(feature = "conflux")]
    enum ConfluxEndpointResult {
        Circuit {
            tunnel: Arc<ClientCirc>,
            stream: DataStream,
        },
        Relay {
            circ: TestCircuitCtx,
        },
    }

    /// Stream data, shared by all the mock exit endpoints.
    #[derive(Debug)]
    #[cfg(feature = "conflux")]
    struct ConfluxStreamState {
        /// The data received so far on this stream.
        data_recvd: Vec<u8>,
        /// The total amount of data we expect to receive on this stream.
        expected_data_len: usize,
        /// Whether we have seen a BEGIN cell yet.
        begin_recvd: bool,
        /// Whether we have seen an END cell yet.
        end_recvd: bool,
        /// Whether we have sent an END cell yet.
        end_sent: bool,
    }

    /// An object describing a SWITCH cell that we expect to receive
    /// in the mock exit
    #[derive(Debug)]
    #[cfg(feature = "conflux")]
    struct ExpectedSwitch {
        /// The number of cells we've seen on this leg so far,
        /// up to and including the SWITCH.
        cells_so_far: usize,
        /// The expected seqno in SWITCH cell,
        seqno: u32,
    }

    /// The state of a mock exit.
    #[derive(Debug)]
    #[cfg(feature = "conflux")]
    struct ConfluxExitState<I: Iterator<Item = Option<Duration>>> {
        /// The runtime.
        runtime: Arc<AsyncMutex<MockRuntime>>,
        /// The client view of the tunnel.
        tunnel: Arc<ClientCirc>,
        /// The circuit test context.
        circ: TestCircuitCtx,
        /// The RTT delay to introduce just before each SENDME.
        ///
        /// Used to trigger the client to send a SWITCH.
        rtt_delays: I,
        /// State of the (only) expected stream on this tunnel,
        /// shared by all the mock exit endpoints.
        stream_state: Arc<Mutex<ConfluxStreamState>>,
        /// The number of cells after which to expect a SWITCH
        /// cell from the client.
        expect_switch: Vec<ExpectedSwitch>,
        /// Channel for receiving completion notifications from the other leg.
        done_rx: oneshot::Receiver<()>,
        /// Channel for sending completion notifications to the other leg.
        done_tx: oneshot::Sender<()>,
        /// Whether this circuit leg should act as the primary (sending) leg.
        is_sending_leg: bool,
    }

    #[cfg(feature = "conflux")]
    async fn good_exit_handshake(
        runtime: &Arc<AsyncMutex<MockRuntime>>,
        init_rtt_delay: Option<Duration>,
        rx: &mut Receiver<ChanCell<AnyChanMsg>>,
        sink: &mut CircuitRxSender,
    ) {
        // Wait for the LINK cell
        let link = await_link_payload(rx).await;

        // Introduce an artificial delay, to make one circ have a better initial RTT
        // than the other
        if let Some(init_rtt_delay) = init_rtt_delay {
            runtime.lock().await.advance_by(init_rtt_delay).await;
        }

        // Reply with a LINKED cell...
        let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
        sink.send(rmsg_to_ccmsg(None, linked)).await.unwrap();

        // Wait for the client to respond with LINKED_ACK...
        let (_id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
        let rmsg = match chmsg {
            AnyChanMsg::Relay(r) => {
                AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                    .unwrap()
            }
            other => panic!("{other:?}"),
        };
        let (_streamid, rmsg) = rmsg.into_streamid_and_msg();

        assert!(matches!(rmsg, AnyRelayMsg::ConfluxLinkedAck(_)));
    }

    #[cfg(feature = "conflux")]
    async fn run_mock_conflux_exit<I: Iterator<Item = Option<Duration>>>(
        state: ConfluxExitState<I>,
    ) -> ConfluxEndpointResult {
        let ConfluxExitState {
            runtime,
            tunnel,
            mut circ,
            rtt_delays,
            stream_state,
            mut expect_switch,
            done_tx,
            mut done_rx,
            is_sending_leg,
        } = state;

        let mut rtt_delays = rtt_delays.into_iter();

        // Expect the client to open a stream, and de-multiplex the received stream data
        let stream_len = stream_state.lock().unwrap().expected_data_len;
        let mut data_cells_received = 0_usize;
        let mut cell_count = 0_usize;
        let mut tags = vec![];
        let mut streamid = None;

        while stream_state.lock().unwrap().data_recvd.len() < stream_len {
            use futures::select;

            // Wait for the BEGIN cell to arrive, or for the transfer to complete
            // (we need to bail if the other leg already completed);
            let res = select! {
                res = circ.chan_rx.next() => {
                    res.unwrap()
                },
                res = done_rx => {
                    res.unwrap();
                    break;
                }
            };

            let (_id, chmsg) = res.into_circid_and_msg();
            cell_count += 1;
            let rmsg = match chmsg {
                AnyChanMsg::Relay(r) => {
                    AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                        .unwrap()
                }
                other => panic!("{:?}", other),
            };
            let (new_streamid, rmsg) = rmsg.into_streamid_and_msg();
            if streamid.is_none() {
                streamid = new_streamid;
            }

            let begin_recvd = stream_state.lock().unwrap().begin_recvd;
            let end_recvd = stream_state.lock().unwrap().end_recvd;
            match rmsg {
                AnyRelayMsg::Begin(_) if begin_recvd => {
                    panic!("client tried to open two streams?!");
                }
                AnyRelayMsg::Begin(_) if !begin_recvd => {
                    stream_state.lock().unwrap().begin_recvd = true;
                    // Reply with a connected cell...
                    let connected = relaymsg::Connected::new_empty().into();
                    circ.circ_tx
                        .send(rmsg_to_ccmsg(streamid, connected))
                        .await
                        .unwrap();
                }
                AnyRelayMsg::End(_) if !end_recvd => {
                    stream_state.lock().unwrap().end_recvd = true;
                    break;
                }
                AnyRelayMsg::End(_) if end_recvd => {
                    panic!("received two END cells for the same stream?!");
                }
                AnyRelayMsg::ConfluxSwitch(cell) => {
                    // Ensure we got the SWITCH after the expected number of cells
                    let expected = expect_switch.remove(0);

                    assert_eq!(expected.cells_so_far, cell_count);
                    assert_eq!(expected.seqno, cell.seqno());

                    // To keep the tests simple, we don't handle out of order cells,
                    // and simply sort the received data at the end.
                    // This ensures all the data was actually received,
                    // but it doesn't actually test that the SWITCH cells
                    // contain the appropriate seqnos.
                    continue;
                }
                AnyRelayMsg::Data(dat) => {
                    data_cells_received += 1;
                    stream_state
                        .lock()
                        .unwrap()
                        .data_recvd
                        .extend_from_slice(dat.as_ref());

                    let is_next_cell_sendme = data_cells_received % 31 == 0;
                    if is_next_cell_sendme {
                        if tags.is_empty() {
                            // Important: we need to make sure all the SENDMEs
                            // we sent so far have been processed by the reactor
                            // (otherwise the next QuerySendWindow call
                            // might return an outdated list of tags!)
                            runtime.lock().await.advance_until_stalled().await;
                            let (tx, rx) = oneshot::channel();
                            tunnel
                                .command
                                .unbounded_send(CtrlCmd::QuerySendWindow {
                                    hop: 2.into(),
                                    leg: circ.unique_id,
                                    done: tx,
                                })
                                .unwrap();

                            // Get a fresh batch of tags.
                            let (_window, new_tags) = rx.await.unwrap().unwrap();
                            tags = new_tags;
                        }

                        let tag = tags.remove(0);

                        // Introduce an artificial delay, to make one circ have worse RTT
                        // than the other, and thus trigger a SWITCH
                        if let Some(rtt_delay) = rtt_delays.next().flatten() {
                            runtime.lock().await.advance_by(rtt_delay).await;
                        }
                        // Make and send a circuit-level SENDME
                        let sendme = relaymsg::Sendme::from(tag).into();

                        circ.circ_tx
                            .send(rmsg_to_ccmsg(None, sendme))
                            .await
                            .unwrap();
                    }
                }
                _ => panic!("unexpected message {rmsg:?} on leg {}", circ.unique_id),
            }
        }

        let end_recvd = stream_state.lock().unwrap().end_recvd;

        // Close the stream if the other endpoint hasn't already done so
        if is_sending_leg && !end_recvd {
            let end = relaymsg::End::new_with_reason(relaymsg::EndReason::DONE).into();
            circ.circ_tx
                .send(rmsg_to_ccmsg(streamid, end))
                .await
                .unwrap();
            stream_state.lock().unwrap().end_sent = true;
        }

        // This is allowed to fail, because the other leg might have exited first.
        let _ = done_tx.send(());

        // Ensure we received all the switch cells we were expecting
        assert!(
            expect_switch.is_empty(),
            "expect_switch = {expect_switch:?}"
        );

        ConfluxEndpointResult::Relay { circ }
    }

    #[cfg(feature = "conflux")]
    async fn run_conflux_client(
        tunnel: Arc<ClientCirc>,
        conflux_link_rx: oneshot::Receiver<Result<ConfluxHandshakeResult>>,
        send_data: Vec<u8>,
        recv_data: Vec<u8>,
    ) -> ConfluxEndpointResult {
        let res = conflux_link_rx.await;

        let res = res.unwrap().unwrap();
        assert_eq!(res.len(), 2);

        // All circuit legs have completed the conflux handshake,
        // so we now have a multipath tunnel

        // Now we're ready to open a stream
        let mut stream = tunnel
            .begin_stream("www.example.com", 443, None)
            .await
            .unwrap();

        stream.write_all(&send_data).await.unwrap();
        stream.flush().await.unwrap();

        let mut recv: Vec<u8> = Vec::new();
        let recv_len = stream.read_to_end(&mut recv).await.unwrap();
        assert_eq!(recv_len, recv_data.len());
        assert_eq!(recv_data, recv);

        ConfluxEndpointResult::Circuit { tunnel, stream }
    }

    #[cfg(feature = "conflux")]
    async fn run_conflux_endpoint<I: Iterator<Item = Option<Duration>>>(
        endpoint: ConfluxTestEndpoint<I>,
    ) -> ConfluxEndpointResult {
        match endpoint {
            ConfluxTestEndpoint::Relay(state) => run_mock_conflux_exit(state).await,
            ConfluxTestEndpoint::Client {
                tunnel,
                conflux_link_rx,
                send_data,
                recv_data,
            } => run_conflux_client(tunnel, conflux_link_rx, send_data, recv_data).await,
        }
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn multipath_stream() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            /// The number of data cells to send.
            const NUM_CELLS: usize = 300;
            /// 498 bytes per DATA cell.
            const CELL_SIZE: usize = 498;

            let TestTunnelCtx {
                tunnel,
                circs,
                conflux_link_rx,
            } = setup_good_conflux_tunnel(&rt).await;
            let [circ1, circ2]: [TestCircuitCtx; 2] = circs.try_into().unwrap();

            // The stream data we're going to send over the conflux tunnel
            let mut send_data = (0..255_u8)
                .cycle()
                .take(NUM_CELLS * CELL_SIZE)
                .collect::<Vec<_>>();
            let stream_state = Arc::new(Mutex::new(ConfluxStreamState {
                data_recvd: vec![],
                expected_data_len: send_data.len(),
                begin_recvd: false,
                end_recvd: false,
                end_sent: false,
            }));

            let mut tasks = vec![];

            // Channels used by the mock relays to notify each other
            // of stream transfer completion.
            let (tx1, rx1) = oneshot::channel();
            let (tx2, rx2) = oneshot::channel();

            // The 9 RTT delays to insert before each of the 9 SENDMEs
            // the exit will end up sending.
            //
            // Note: the first delay is the init_rtt delay (measured during the conflux HS).
            let circ1_rtt_delays = [
                // Initially, circ1 has better RTT, so we will start on this leg.
                Some(Duration::from_millis(100)),
                // But then its RTT takes a turn for the worse,
                // triggering a switch after the first SENDME is processed
                // (this happens after sending 123 DATA cells).
                Some(Duration::from_millis(500)),
                Some(Duration::from_millis(700)),
                Some(Duration::from_millis(900)),
                Some(Duration::from_millis(1100)),
                Some(Duration::from_millis(1300)),
                Some(Duration::from_millis(1500)),
                Some(Duration::from_millis(1700)),
                Some(Duration::from_millis(1900)),
                Some(Duration::from_millis(2100)),
            ]
            .into_iter();

            let circ2_rtt_delays = [
                Some(Duration::from_millis(200)),
                Some(Duration::from_millis(400)),
                Some(Duration::from_millis(600)),
                Some(Duration::from_millis(800)),
                Some(Duration::from_millis(1000)),
                Some(Duration::from_millis(1200)),
                Some(Duration::from_millis(1400)),
                Some(Duration::from_millis(1600)),
                Some(Duration::from_millis(1800)),
                Some(Duration::from_millis(2000)),
            ]
            .into_iter();

            // Note: we can't have two advance_by() calls running
            // at the same time (it's a limitation of MockRuntime),
            // so we need to be careful to not cause concurrent delays
            // on the two circuits.
            let relays = [
                (
                    circ1,
                    tx1,
                    rx2,
                    vec![ExpectedSwitch {
                        // We start on this leg, and receive a BEGIN cell,
                        // followed by (4 * 31 - 1) = 123 DATA cells.
                        // Then it becomes blocked on CC, then finally the reactor
                        // realizes it has some SENDMEs to process, and
                        // then as a result of the new RTT measurement, we switch to circ1,
                        // and then finally we switch back here, and get another SWITCH
                        // as the 126th cell.
                        cells_so_far: 126,
                        // Leg 2 switches back to this leg after the 249th cell
                        // (just before sending the 250th one):
                        // seqno = 125 carried over from leg 1 (see the seqno of the
                        // SWITCH expected on leg 2 below), plus 1 SWITCH, plus
                        // 4 * 31 = 124 DATA cells after which the RTT of the first leg
                        // is deemed favorable again.
                        //
                        // 249 - 125 (last_seq_sent of leg 1) = 124
                        seqno: 124,
                    }],
                    circ1_rtt_delays,
                    true,
                ),
                (
                    circ2,
                    tx2,
                    rx1,
                    vec![ExpectedSwitch {
                        // The SWITCH is the first cell we received after the conflux HS
                        // on this leg.
                        cells_so_far: 1,
                        // See explanation on the ExpectedSwitch from circ1 above.
                        seqno: 125,
                    }],
                    circ2_rtt_delays,
                    false,
                ),
            ];

            let relay_runtime = Arc::new(AsyncMutex::new(rt.clone()));
            for (mut circ, done_tx, done_rx, expect_switch, mut rtt_delays, is_sending_leg) in
                relays.into_iter()
            {
                let leg = circ.unique_id;

                // Do the conflux handshake
                //
                // We do this outside of run_conflux_endpoint,
                // toa void running both handshakes at concurrently
                // (this gives more predictable RTT delays:
                // if both handshake tasks run at once, they race
                // to advance the mock runtime's clock)
                good_exit_handshake(
                    &relay_runtime,
                    rtt_delays.next().flatten(),
                    &mut circ.chan_rx,
                    &mut circ.circ_tx,
                )
                .await;

                let relay = ConfluxTestEndpoint::Relay(ConfluxExitState {
                    runtime: Arc::clone(&relay_runtime),
                    tunnel: Arc::clone(&tunnel),
                    circ,
                    rtt_delays,
                    stream_state: Arc::clone(&stream_state),
                    expect_switch,
                    done_tx,
                    done_rx,
                    is_sending_leg,
                });

                tasks.push(rt.spawn_join(format!("relay task {leg}"), run_conflux_endpoint(relay)));
            }

            tasks.push(rt.spawn_join(
                "client task".to_string(),
                run_conflux_endpoint(ConfluxTestEndpoint::Client {
                    tunnel,
                    conflux_link_rx,
                    send_data: send_data.clone(),
                    recv_data: vec![],
                }),
            ));
            let _sinks = futures::future::join_all(tasks).await;
            let mut stream_state = stream_state.lock().unwrap();
            assert!(stream_state.begin_recvd);

            stream_state.data_recvd.sort();
            send_data.sort();
            assert_eq!(stream_state.data_recvd, send_data);
        });
    }

    #[traced_test]
    #[test]
    #[cfg(all(feature = "conflux", feature = "hs-service"))]
    fn conflux_incoming_stream() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            use std::error::Error as _;

            const EXPECTED_HOP: u8 = 1;

            let TestTunnelCtx {
                tunnel,
                circs,
                conflux_link_rx,
            } = setup_good_conflux_tunnel(&rt).await;

            let [mut circ1, mut circ2]: [TestCircuitCtx; 2] = circs.try_into().unwrap();

            let link = await_link_payload(&mut circ1.chan_rx).await;
            for circ in [&mut circ1, &mut circ2] {
                let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
                circ.circ_tx
                    .send(rmsg_to_ccmsg(None, linked))
                    .await
                    .unwrap();
            }

            let conflux_hs_res = conflux_link_rx.await.unwrap().unwrap();
            assert!(conflux_hs_res.iter().all(|res| res.is_ok()));

            // TODO(#2002): we don't currently support conflux for onion services
            let err = tunnel
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    (tunnel.unique_id(), EXPECTED_HOP.into()).into(),
                    AllowAllStreamsFilter,
                )
                .await
                // IncomingStream doesn't impl Debug, so we need to map to a different type
                .map(|_| ())
                .unwrap_err();

            let err_src = err.source().unwrap();
            assert!(err_src
                .to_string()
                .contains("Cannot allow stream requests on tunnel with 2 legs"));
        });
    }

    // TODO: add a test where the client receives data on a multipath stream,
    // and ensure it handles ooo cells correctly
}
