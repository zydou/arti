//! Code for talking directly (over a TLS connection) to a Tor client or relay.
//!
//! Channels form the basis of the rest of the Tor protocol: they are
//! the only way for two Tor instances to talk.
//!
//! Channels are not useful directly for application requests: after
//! making a channel, it needs to get used to build circuits, and the
//! circuits are used to anonymize streams.  The streams are the
//! objects corresponding to directory requests.
//!
//! In general, you shouldn't try to manage channels on your own;
//! use the `tor-chanmgr` crate instead.
//!
//! To launch a channel:
//!
//!  * Create a TLS connection as an object that implements AsyncRead +
//!    AsyncWrite + StreamOps, and pass it to a [ChannelBuilder].  This will
//!    yield an [handshake::OutboundClientHandshake] that represents
//!    the state of the handshake.
//!  * Call [handshake::OutboundClientHandshake::connect] on the result
//!    to negotiate the rest of the handshake.  This will verify
//!    syntactic correctness of the handshake, but not its cryptographic
//!    integrity.
//!  * Call [handshake::UnverifiedChannel::check] on the result.  This
//!    finishes the cryptographic checks.
//!  * Call [handshake::VerifiedChannel::finish] on the result. This
//!    completes the handshake and produces an open channel and Reactor.
//!  * Launch an asynchronous task to call the reactor's run() method.
//!
//! One you have a running channel, you can create circuits on it with
//! its [Channel::new_circ] method.  See
//! [crate::tunnel::circuit::PendingClientCirc] for information on how to
//! proceed from there.
//!
//! # Design
//!
//! For now, this code splits the channel into two pieces: a "Channel"
//! object that can be used by circuits to write cells onto the
//! channel, and a "Reactor" object that runs as a task in the
//! background, to read channel cells and pass them to circuits as
//! appropriate.
//!
//! I'm not at all sure that's the best way to do that, but it's what
//! I could think of.
//!
//! # Limitations
//!
//! This is client-only, and only supports link protocol version 4.
//!
//! TODO: There is no channel padding.
//!
//! TODO: There is no flow control, rate limiting, queueing, or
//! fairness.

/// The size of the channel buffer for communication between `Channel` and its reactor.
pub const CHANNEL_BUFFER_SIZE: usize = 128;

mod circmap;
mod codec;
mod handshake;
pub mod kist;
pub mod padding;
pub mod params;
mod reactor;
mod unique_id;

pub use crate::channel::params::*;
use crate::channel::reactor::{BoxedChannelSink, BoxedChannelStream, Reactor};
pub use crate::channel::unique_id::UniqId;
use crate::memquota::{ChannelAccount, CircuitAccount, SpecificAccount as _};
use crate::util::err::ChannelClosed;
use crate::util::oneshot_broadcast;
use crate::util::ts::AtomicOptTimestamp;
use crate::{tunnel, tunnel::circuit, ClockSkew};
use crate::{Error, Result};
use reactor::BoxedChannelStreamOps;
use safelog::sensitive as sv;
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use tor_cell::chancell::msg::AnyChanMsg;
use tor_cell::chancell::{msg, msg::PaddingNegotiate, AnyChanCell, CircId};
use tor_cell::chancell::{ChanCell, ChanMsg};
use tor_cell::restricted_msg;
use tor_error::internal;
use tor_linkspec::{HasRelayIds, OwnedChanTarget};
use tor_memquota::mq_queue::{self, ChannelSpec as _, MpscSpec};
use tor_rtcompat::{CoarseTimeProvider, DynTimeProvider, SleepProvider, StreamOps};

/// Imports that are re-exported pub if feature `testing` is enabled
///
/// Putting them together in a little module like this allows us to select the
/// visibility for all of these things together.
mod testing_exports {
    #![allow(unreachable_pub)]
    pub use super::reactor::CtrlMsg;
    pub use crate::tunnel::circuit::celltypes::CreateResponse;
}
#[cfg(feature = "testing")]
pub use testing_exports::*;
#[cfg(not(feature = "testing"))]
use testing_exports::*;

use asynchronous_codec;
use futures::channel::mpsc;
use futures::io::{AsyncRead, AsyncWrite};
use oneshot_fused_workaround as oneshot;

use educe::Educe;
use futures::{FutureExt as _, Sink};
use std::result::Result as StdResult;
use std::sync::Arc;
use std::task::{Context, Poll};

use tracing::trace;

// reexport
use crate::channel::unique_id::CircUniqIdContext;
#[cfg(test)]
pub(crate) use codec::CodecError;
pub use handshake::{OutboundClientHandshake, UnverifiedChannel, VerifiedChannel};

use kist::KistParams;

restricted_msg! {
    /// A channel message that we allow to be sent from a server to a client on
    /// an open channel.
    ///
    /// (An Open channel here is one on which we have received a NETINFO cell.)
    ///
    /// Note that an unexpected message type will _not_ be ignored: instead, it
    /// will cause the channel to shut down.
    #[derive(Clone, Debug)]
    pub(crate) enum OpenChanMsgS2C : ChanMsg {
        Padding,
        Vpadding,
        // Not Create*, since we are not a relay.
        // Not Created, since we never send CREATE.
        CreatedFast,
        Created2,
        Relay,
        // Not RelayEarly, since we are a client.
        Destroy,
        // Not PaddingNegotiate, since we are not a relay.
        // Not Versions, Certs, AuthChallenge, Authenticate: they are for handshakes.
        // Not Authorize: it is reserved, but unused.
    }
}

/// A channel cell that we allot to be sent on an open channel from
/// a server to a client.
pub(crate) type OpenChanCellS2C = ChanCell<OpenChanMsgS2C>;

/// Type alias: A Sink and Stream that transforms a TLS connection into
/// a cell-based communication mechanism.
type CellFrame<T> =
    asynchronous_codec::Framed<T, crate::channel::codec::ChannelCodec<OpenChanMsgS2C, AnyChanMsg>>;

/// An open client channel, ready to send and receive Tor cells.
///
/// A channel is a direct connection to a Tor relay, implemented using TLS.
///
/// This struct is a frontend that can be used to send cells
/// and otherwise control the channel.  The main state is
/// in the Reactor object.
///
/// (Users need a mutable reference because of the types in `Sink`, and
/// ultimately because `cell_tx: mpsc::Sender` doesn't work without mut.
///
/// # Channel life cycle
///
/// Channels can be created directly here through the [`ChannelBuilder`] API.
/// For a higher-level API (with better support for TLS, pluggable transports,
/// and channel reuse) see the `tor-chanmgr` crate.
///
/// After a channel is created, it will persist until it is closed in one of
/// four ways:
///    1. A remote error occurs.
///    2. The other side of the channel closes the channel.
///    3. Someone calls [`Channel::terminate`] on the channel.
///    4. The last reference to the `Channel` is dropped. (Note that every circuit
///       on a `Channel` keeps a reference to it, which will in turn keep the
///       channel from closing until all those circuits have gone away.)
///
/// Note that in cases 1-3, the [`Channel`] object itself will still exist: it
/// will just be unusable for most purposes.  Most operations on it will fail
/// with an error.
#[derive(Debug)]
pub struct Channel {
    /// A channel used to send control messages to the Reactor.
    control: mpsc::UnboundedSender<CtrlMsg>,
    /// A channel used to send cells to the Reactor.
    cell_tx: mq_queue::Sender<AnyChanCell, mq_queue::MpscSpec>,

    /// A receiver that indicates whether the channel is closed.
    ///
    /// Awaiting will return a `CancelledError` event when the reactor is dropped.
    /// Read to decide if operations may succeed, and is returned by `wait_for_close`.
    reactor_closed_rx: oneshot_broadcast::Receiver<Result<CloseInfo>>,

    /// A unique identifier for this channel.
    unique_id: UniqId,
    /// Validated identity and address information for this peer.
    peer_id: OwnedChanTarget,
    /// The declared clock skew on this channel, at the time when this channel was
    /// created.
    clock_skew: ClockSkew,
    /// The time when this channel was successfully completed
    opened_at: coarsetime::Instant,
    /// Mutable state used by the `Channel.
    mutable: Mutex<MutableDetails>,

    /// Information shared with the reactor
    details: Arc<ChannelDetails>,
}

/// This is information shared between the reactor and the frontend (`Channel` object).
///
/// `control` can't be here because we rely on it getting dropped when the last user goes away.
#[derive(Debug)]
pub(crate) struct ChannelDetails {
    /// Since when the channel became unused.
    ///
    /// If calling `time_since_update` returns None,
    /// this channel is still in use by at least one circuit.
    ///
    /// Set by reactor when a circuit is added or removed.
    /// Read from `Channel::duration_unused`.
    unused_since: AtomicOptTimestamp,
    /// Memory quota account
    ///
    /// This is here partly because we need to ensure it lives as long as the channel,
    /// as otherwise the memquota system will tear the account down.
    #[allow(dead_code)]
    memquota: ChannelAccount,
}

/// Mutable details (state) used by the `Channel` (frontend)
#[derive(Debug, Default)]
struct MutableDetails {
    /// State used to control padding
    padding: PaddingControlState,
}

/// State used to control padding
///
/// We store this here because:
///
///  1. It must be per-channel, because it depends on channel usage.  So it can't be in
///     (for example) `ChannelPaddingInstructionsUpdate`.
///
///  2. It could be in the channel manager's per-channel state but (for code flow reasons
///     there, really) at the point at which the channel manager concludes for a pending
///     channel that it ought to update the usage, it has relinquished the lock on its own data
///     structure.
///     And there is actually no need for this to be global: a per-channel lock is better than
///     reacquiring the global one.
///
///  3. It doesn't want to be in the channel reactor since that's super hot.
///
/// See also the overview at [`tor_proto::channel::padding`](padding)
#[derive(Debug, Educe)]
#[educe(Default)]
enum PaddingControlState {
    /// No usage of this channel, so far, implies sending or negotiating channel padding.
    ///
    /// This means we do not send (have not sent) any `ChannelPaddingInstructionsUpdates` to the reactor,
    /// with the following consequences:
    ///
    ///  * We don't enable our own padding.
    ///  * We don't do any work to change the timeout distribution in the padding timer,
    ///    (which is fine since this timer is not enabled).
    ///  * We don't send any PADDING_NEGOTIATE cells.  The peer is supposed to come to the
    ///    same conclusions as us, based on channel usage: it should also not send padding.
    #[educe(Default)]
    UsageDoesNotImplyPadding {
        /// The last padding parameters (from reparameterize)
        ///
        /// We keep this so that we can send it if and when
        /// this channel starts to be used in a way that implies (possibly) sending padding.
        padding_params: ChannelPaddingInstructionsUpdates,
    },

    /// Some usage of this channel implies possibly sending channel padding
    ///
    /// The required padding timer, negotiation cell, etc.,
    /// have been communicated to the reactor via a `CtrlMsg::ConfigUpdate`.
    ///
    /// Once we have set this variant, it remains this way forever for this channel,
    /// (the spec speaks of channels "only used for" certain purposes not getting padding).
    PaddingConfigured,
}

use PaddingControlState as PCS;

/// A handle to a [`Channel`]` that can be used, by circuits, to send channel cells.
#[derive(Debug)]
pub(crate) struct ChannelSender {
    /// MPSC sender to send cells.
    cell_tx: mq_queue::Sender<AnyChanCell, mq_queue::MpscSpec>,
    /// A receiver used to check if the channel is closed.
    reactor_closed_rx: oneshot_broadcast::Receiver<Result<CloseInfo>>,
    /// Unique ID for this channel. For logging.
    unique_id: UniqId,
}

impl ChannelSender {
    /// Check whether a cell type is permissible to be _sent_ on an
    /// open client channel.
    fn check_cell(&self, cell: &AnyChanCell) -> Result<()> {
        use msg::AnyChanMsg::*;
        let msg = cell.msg();
        match msg {
            Created(_) | Created2(_) | CreatedFast(_) => Err(Error::from(internal!(
                "Can't send {} cell on client channel",
                msg.cmd()
            ))),
            Certs(_) | Versions(_) | Authenticate(_) | Authorize(_) | AuthChallenge(_)
            | Netinfo(_) => Err(Error::from(internal!(
                "Can't send {} cell after handshake is done",
                msg.cmd()
            ))),
            _ => Ok(()),
        }
    }

    /// Obtain a reference to the `ChannelSender`'s [`DynTimeProvider`]
    ///
    /// (This can sometimes be used to avoid having to keep
    /// a separate clone of the time provider.)
    pub(crate) fn time_provider(&self) -> &DynTimeProvider {
        self.cell_tx.time_provider()
    }
}

impl Sink<AnyChanCell> for ChannelSender {
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.cell_tx)
            .poll_ready(cx)
            .map_err(|_| ChannelClosed.into())
    }

    fn start_send(self: Pin<&mut Self>, cell: AnyChanCell) -> Result<()> {
        let this = self.get_mut();
        if this.reactor_closed_rx.is_ready() {
            return Err(ChannelClosed.into());
        }
        this.check_cell(&cell)?;
        {
            use msg::AnyChanMsg::*;
            match cell.msg() {
                Relay(_) | Padding(_) | Vpadding(_) => {} // too frequent to log.
                _ => trace!(
                    channel_id = %this.unique_id,
                    "Sending {} for {}",
                    cell.msg().cmd(),
                    CircId::get_or_zero(cell.circid())
                ),
            }
        }

        Pin::new(&mut this.cell_tx)
            .start_send(cell)
            .map_err(|_| ChannelClosed.into())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.cell_tx)
            .poll_flush(cx)
            .map_err(|_| ChannelClosed.into())
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.cell_tx)
            .poll_close(cx)
            .map_err(|_| ChannelClosed.into())
    }
}

/// Structure for building and launching a Tor channel.
#[derive(Default)]
pub struct ChannelBuilder {
    /// If present, a description of the address we're trying to connect to,
    /// and the way in which we are trying to connect to it.
    ///
    /// TODO: at some point, check this against the addresses in the netinfo
    /// cell too.
    target: Option<tor_linkspec::ChannelMethod>,
}

impl ChannelBuilder {
    /// Construct a new ChannelBuilder.
    pub fn new() -> Self {
        ChannelBuilder::default()
    }

    /// Set the declared target method of this channel to correspond to a direct
    /// connection to a given socket address.
    #[deprecated(note = "use set_declared_method instead", since = "0.7.1")]
    pub fn set_declared_addr(&mut self, target: std::net::SocketAddr) {
        self.set_declared_method(tor_linkspec::ChannelMethod::Direct(vec![target]));
    }

    /// Set the declared target method of this channel.
    ///
    /// Note that nothing enforces the correctness of this method: it
    /// doesn't have to match the real method used to create the TLS
    /// stream.
    pub fn set_declared_method(&mut self, target: tor_linkspec::ChannelMethod) {
        self.target = Some(target);
    }

    /// Launch a new client handshake over a TLS stream.
    ///
    /// After calling this function, you'll need to call `connect()` on
    /// the result to start the handshake.  If that succeeds, you'll have
    /// authentication info from the relay: call `check()` on the result
    /// to check that.  Finally, to finish the handshake, call `finish()`
    /// on the result of _that_.
    pub fn launch<T, S>(
        self,
        tls: T,
        sleep_prov: S,
        memquota: ChannelAccount,
    ) -> OutboundClientHandshake<T, S>
    where
        T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
        S: CoarseTimeProvider + SleepProvider,
    {
        handshake::OutboundClientHandshake::new(tls, self.target, sleep_prov, memquota)
    }
}

impl Channel {
    /// Construct a channel and reactor.
    ///
    /// Internal method, called to finalize the channel when we've
    /// sent our netinfo cell, received the peer's netinfo cell, and
    /// we're finally ready to create circuits.
    #[allow(clippy::too_many_arguments)] // TODO consider if we want a builder
    fn new<S>(
        link_protocol: u16,
        sink: BoxedChannelSink,
        stream: BoxedChannelStream,
        streamops: BoxedChannelStreamOps,
        unique_id: UniqId,
        peer_id: OwnedChanTarget,
        clock_skew: ClockSkew,
        sleep_prov: S,
        memquota: ChannelAccount,
    ) -> Result<(Arc<Self>, reactor::Reactor<S>)>
    where
        S: CoarseTimeProvider + SleepProvider,
    {
        use circmap::{CircIdRange, CircMap};
        let circmap = CircMap::new(CircIdRange::High);
        let dyn_time = DynTimeProvider::new(sleep_prov.clone());

        let (control_tx, control_rx) = mpsc::unbounded();
        let (cell_tx, cell_rx) = mq_queue::MpscSpec::new(CHANNEL_BUFFER_SIZE)
            .new_mq(dyn_time.clone(), memquota.as_raw_account())?;
        let unused_since = AtomicOptTimestamp::new();
        unused_since.update();

        let mutable = MutableDetails::default();
        let (reactor_closed_tx, reactor_closed_rx) = oneshot_broadcast::channel();

        let details = ChannelDetails {
            unused_since,
            memquota,
        };
        let details = Arc::new(details);

        let channel = Arc::new(Channel {
            control: control_tx,
            cell_tx,
            reactor_closed_rx,
            unique_id,
            peer_id,
            clock_skew,
            opened_at: coarsetime::Instant::now(),
            mutable: Mutex::new(mutable),
            details: Arc::clone(&details),
        });

        // We start disabled; the channel manager will `reconfigure` us soon after creation.
        let padding_timer = Box::pin(padding::Timer::new_disabled(sleep_prov, None)?);

        let reactor = Reactor {
            control: control_rx,
            cells: cell_rx,
            reactor_closed_tx,
            input: futures::StreamExt::fuse(stream),
            output: sink,
            streamops,
            circs: circmap,
            circ_unique_id_ctx: CircUniqIdContext::new(),
            link_protocol,
            unique_id,
            details,
            padding_timer,
            special_outgoing: Default::default(),
        };

        Ok((channel, reactor))
    }

    /// Return a process-unique identifier for this channel.
    pub fn unique_id(&self) -> UniqId {
        self.unique_id
    }

    /// Return a reference to the memory tracking account for this Channel
    pub fn mq_account(&self) -> &ChannelAccount {
        &self.details.memquota
    }

    /// Obtain a reference to the `Channel`'s [`DynTimeProvider`]
    ///
    /// (This can sometimes be used to avoid having to keep
    /// a separate clone of the time provider.)
    pub fn time_provider(&self) -> &DynTimeProvider {
        self.cell_tx.time_provider()
    }

    /// Return an OwnedChanTarget representing the actual handshake used to
    /// create this channel.
    pub fn target(&self) -> &OwnedChanTarget {
        &self.peer_id
    }

    /// Return the amount of time that has passed since this channel became open.
    pub fn age(&self) -> Duration {
        self.opened_at.elapsed().into()
    }

    /// Return a ClockSkew declaring how much clock skew the other side of this channel
    /// claimed that we had when we negotiated the connection.
    pub fn clock_skew(&self) -> ClockSkew {
        self.clock_skew
    }

    /// Send a control message
    fn send_control(&self, msg: CtrlMsg) -> StdResult<(), ChannelClosed> {
        self.control
            .unbounded_send(msg)
            .map_err(|_| ChannelClosed)?;
        Ok(())
    }

    /// Acquire the lock on `mutable` (and handle any poison error)
    fn mutable(&self) -> MutexGuard<MutableDetails> {
        self.mutable.lock().expect("channel details poisoned")
    }

    /// Specify that this channel should do activities related to channel padding
    ///
    /// Initially, the channel does nothing related to channel padding:
    /// it neither sends any padding, nor sends any PADDING_NEGOTIATE cells.
    ///
    /// After this function has been called, it will do both,
    /// according to the parameters specified through `reparameterize`.
    /// Note that this might include *disabling* padding
    /// (for example, by sending a `PADDING_NEGOTIATE`).
    ///
    /// Idempotent.
    ///
    /// There is no way to undo the effect of this call.
    pub fn engage_padding_activities(&self) {
        let mut mutable = self.mutable();

        match &mutable.padding {
            PCS::UsageDoesNotImplyPadding {
                padding_params: params,
            } => {
                // Well, apparently the channel usage *does* imply padding now,
                // so we need to (belatedly) enable the timer,
                // send the padding negotiation cell, etc.
                let mut params = params.clone();

                // Except, maybe the padding we would be requesting is precisely default,
                // so we wouldn't actually want to send that cell.
                if params.padding_negotiate == Some(PaddingNegotiate::start_default()) {
                    params.padding_negotiate = None;
                }

                match self.send_control(CtrlMsg::ConfigUpdate(Arc::new(params))) {
                    Ok(()) => {}
                    Err(ChannelClosed) => return,
                }

                mutable.padding = PCS::PaddingConfigured;
            }

            PCS::PaddingConfigured => {
                // OK, nothing to do
            }
        }

        drop(mutable); // release the lock now: lock span covers the send, ensuring ordering
    }

    /// Reparameterise (update parameters; reconfigure)
    ///
    /// Returns `Err` if the channel was closed earlier
    pub fn reparameterize(&self, params: Arc<ChannelPaddingInstructionsUpdates>) -> Result<()> {
        let mut mutable = self
            .mutable
            .lock()
            .map_err(|_| internal!("channel details poisoned"))?;

        match &mut mutable.padding {
            PCS::PaddingConfigured => {
                self.send_control(CtrlMsg::ConfigUpdate(params))?;
            }
            PCS::UsageDoesNotImplyPadding { padding_params } => {
                padding_params.combine(&params);
            }
        }

        drop(mutable); // release the lock now: lock span covers the send, ensuring ordering
        Ok(())
    }

    /// Update the KIST parameters.
    ///
    /// Returns `Err` if the channel is closed.
    pub fn reparameterize_kist(&self, kist_params: KistParams) -> Result<()> {
        Ok(self.send_control(CtrlMsg::KistConfigUpdate(kist_params))?)
    }

    /// Return an error if this channel is somehow mismatched with the
    /// given target.
    pub fn check_match<T: HasRelayIds + ?Sized>(&self, target: &T) -> Result<()> {
        check_id_match_helper(&self.peer_id, target)
    }

    /// Return true if this channel is closed and therefore unusable.
    pub fn is_closing(&self) -> bool {
        self.reactor_closed_rx.is_ready()
    }

    /// If the channel is not in use, return the amount of time
    /// it has had with no circuits.
    ///
    /// Return `None` if the channel is currently in use.
    pub fn duration_unused(&self) -> Option<std::time::Duration> {
        self.details
            .unused_since
            .time_since_update()
            .map(Into::into)
    }

    /// Return a new [`ChannelSender`] to transmit cells on this channel.
    pub(crate) fn sender(&self) -> ChannelSender {
        ChannelSender {
            cell_tx: self.cell_tx.clone(),
            reactor_closed_rx: self.reactor_closed_rx.clone(),
            unique_id: self.unique_id,
        }
    }

    /// Return a newly allocated PendingClientCirc object with
    /// a corresponding circuit reactor. A circuit ID is allocated, but no
    /// messages are sent, and no cryptography is done.
    ///
    /// To use the results of this method, call Reactor::run() in a
    /// new task, then use the methods of
    /// [crate::tunnel::circuit::PendingClientCirc] to build the circuit.
    pub async fn new_circ(
        self: &Arc<Self>,
    ) -> Result<(circuit::PendingClientCirc, tunnel::reactor::Reactor)> {
        if self.is_closing() {
            return Err(ChannelClosed.into());
        }

        let time_prov = self.cell_tx.time_provider().clone();
        let memquota = CircuitAccount::new(&self.details.memquota)?;

        // TODO: blocking is risky, but so is unbounded.
        let (sender, receiver) =
            MpscSpec::new(128).new_mq(time_prov.clone(), memquota.as_raw_account())?;
        let (createdsender, createdreceiver) = oneshot::channel::<CreateResponse>();

        let (tx, rx) = oneshot::channel();
        self.send_control(CtrlMsg::AllocateCircuit {
            created_sender: createdsender,
            sender,
            tx,
        })?;
        let (id, circ_unique_id) = rx.await.map_err(|_| ChannelClosed)??;

        trace!("{}: Allocated CircId {}", circ_unique_id, id);

        Ok(circuit::PendingClientCirc::new(
            id,
            self.clone(),
            createdreceiver,
            receiver,
            circ_unique_id,
            time_prov,
            memquota,
        ))
    }

    /// Shut down this channel immediately, along with all circuits that
    /// are using it.
    ///
    /// Note that other references to this channel may exist.  If they
    /// do, they will stop working after you call this function.
    ///
    /// It's not necessary to call this method if you're just done
    /// with a channel: the channel should close on its own once nothing
    /// is using it any more.
    pub fn terminate(&self) {
        let _ = self.send_control(CtrlMsg::Shutdown);
    }

    /// Tell the reactor that the circuit with the given ID has gone away.
    pub fn close_circuit(&self, circid: CircId) -> Result<()> {
        self.send_control(CtrlMsg::CloseCircuit(circid))?;
        Ok(())
    }

    /// Return a future that will resolve once this channel has closed.
    ///
    /// Note that this method does not _cause_ the channel to shut down on its own.
    pub fn wait_for_close(
        &self,
    ) -> impl Future<Output = StdResult<CloseInfo, ClosedUnexpectedly>> + Send + Sync + 'static
    {
        self.reactor_closed_rx
            .clone()
            .into_future()
            .map(|recv| match recv {
                Ok(Ok(info)) => Ok(info),
                Ok(Err(e)) => Err(ClosedUnexpectedly::ReactorError(e)),
                Err(oneshot_broadcast::SenderDropped) => Err(ClosedUnexpectedly::ReactorDropped),
            })
    }

    /// Make a new fake reactor-less channel.  For testing only, obviously.
    ///
    /// Returns the receiver end of the control message mpsc.
    ///
    /// Suitable for external callers who want to test behaviour
    /// of layers including the logic in the channel frontend
    /// (`Channel` object methods).
    //
    // This differs from test::fake_channel as follows:
    //  * It returns the mpsc Receiver
    //  * It does not require explicit specification of details
    #[cfg(feature = "testing")]
    pub fn new_fake() -> (Channel, mpsc::UnboundedReceiver<CtrlMsg>) {
        let (control, control_recv) = mpsc::unbounded();
        let details = fake_channel_details();

        let unique_id = UniqId::new();
        let peer_id = OwnedChanTarget::builder()
            .ed_identity([6_u8; 32].into())
            .rsa_identity([10_u8; 20].into())
            .build()
            .expect("Couldn't construct peer id");

        // This will make rx trigger immediately.
        let (_tx, rx) = oneshot_broadcast::channel();

        let channel = Channel {
            control,
            cell_tx: fake_mpsc().0,
            reactor_closed_rx: rx,
            unique_id,
            peer_id,
            clock_skew: ClockSkew::None,
            opened_at: coarsetime::Instant::now(),
            mutable: Default::default(),
            details,
        };
        (channel, control_recv)
    }
}

/// If there is any identity in `wanted_ident` that is not present in
/// `my_ident`, return a ChanMismatch error.
///
/// This is a helper for [`Channel::check_match`] and
/// [`UnverifiedChannel::check_internal`].
fn check_id_match_helper<T, U>(my_ident: &T, wanted_ident: &U) -> Result<()>
where
    T: HasRelayIds + ?Sized,
    U: HasRelayIds + ?Sized,
{
    for desired in wanted_ident.identities() {
        let id_type = desired.id_type();
        match my_ident.identity(id_type) {
            Some(actual) if actual == desired => {}
            Some(actual) => {
                return Err(Error::ChanMismatch(format!(
                    "Identity {} does not match target {}",
                    sv(actual),
                    sv(desired)
                )));
            }
            None => {
                return Err(Error::ChanMismatch(format!(
                    "Peer does not have {} identity",
                    id_type
                )))
            }
        }
    }
    Ok(())
}

impl HasRelayIds for Channel {
    fn identity(
        &self,
        key_type: tor_linkspec::RelayIdType,
    ) -> Option<tor_linkspec::RelayIdRef<'_>> {
        self.peer_id.identity(key_type)
    }
}

/// The status of a channel which was closed successfully.
///
/// **Note:** This doesn't have any associated data,
/// but may be expanded in the future.
// I can't think of any info we'd want to return to waiters,
// but this type leaves the possibility open without requiring any backwards-incompatible changes.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CloseInfo;

/// The status of a channel which closed unexpectedly.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClosedUnexpectedly {
    /// The channel reactor was dropped or panicked before completing.
    #[error("channel reactor was dropped or panicked before completing")]
    ReactorDropped,
    /// The channel reactor had an internal error.
    #[error("channel reactor had an internal error")]
    ReactorError(Error),
}

/// Make some fake channel details (for testing only!)
#[cfg(any(test, feature = "testing"))]
fn fake_channel_details() -> Arc<ChannelDetails> {
    let unused_since = AtomicOptTimestamp::new();

    Arc::new(ChannelDetails {
        unused_since,
        memquota: crate::util::fake_mq(),
    })
}

/// Make an MPSC queue, of the type we use in Channels, but a fake one for testing
#[cfg(any(test, feature = "testing"))] // Used by Channel::new_fake which is also feature=testing
pub(crate) fn fake_mpsc() -> (
    mq_queue::Sender<AnyChanCell, mq_queue::MpscSpec>,
    mq_queue::Receiver<AnyChanCell, mq_queue::MpscSpec>,
) {
    crate::fake_mpsc(CHANNEL_BUFFER_SIZE)
}

#[cfg(test)]
pub(crate) mod test {
    // Most of this module is tested via tests that also check on the
    // reactor code; there are just a few more cases to examine here.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::channel::codec::test::MsgBuf;
    pub(crate) use crate::channel::reactor::test::new_reactor;
    use crate::util::fake_mq;
    use tor_cell::chancell::msg::HandshakeType;
    use tor_cell::chancell::{msg, AnyChanCell};
    use tor_rtcompat::PreferredRuntime;

    /// Make a new fake reactor-less channel.  For testing only, obviously.
    pub(crate) fn fake_channel(details: Arc<ChannelDetails>) -> Channel {
        let unique_id = UniqId::new();
        let peer_id = OwnedChanTarget::builder()
            .ed_identity([6_u8; 32].into())
            .rsa_identity([10_u8; 20].into())
            .build()
            .expect("Couldn't construct peer id");
        // This will make rx trigger immediately.
        let (_tx, rx) = oneshot_broadcast::channel();
        Channel {
            control: mpsc::unbounded().0,
            cell_tx: fake_mpsc().0,
            reactor_closed_rx: rx,
            unique_id,
            peer_id,
            clock_skew: ClockSkew::None,
            opened_at: coarsetime::Instant::now(),
            mutable: Default::default(),
            details,
        }
    }

    #[test]
    fn send_bad() {
        tor_rtcompat::test_with_all_runtimes!(|_rt| async move {
            use std::error::Error;
            let chan = fake_channel(fake_channel_details());

            let cell = AnyChanCell::new(CircId::new(7), msg::Created2::new(&b"hihi"[..]).into());
            let e = chan.sender().check_cell(&cell);
            assert!(e.is_err());
            assert!(format!("{}", e.unwrap_err().source().unwrap())
                .contains("Can't send CREATED2 cell on client channel"));
            let cell = AnyChanCell::new(None, msg::Certs::new_empty().into());
            let e = chan.sender().check_cell(&cell);
            assert!(e.is_err());
            assert!(format!("{}", e.unwrap_err().source().unwrap())
                .contains("Can't send CERTS cell after handshake is done"));

            let cell = AnyChanCell::new(
                CircId::new(5),
                msg::Create2::new(HandshakeType::NTOR, &b"abc"[..]).into(),
            );
            let e = chan.sender().check_cell(&cell);
            assert!(e.is_ok());
            // FIXME(eta): more difficult to test that sending works now that it has to go via reactor
            // let got = output.next().await.unwrap();
            // assert!(matches!(got.msg(), ChanMsg::Create2(_)));
        });
    }

    #[test]
    fn chanbuilder() {
        let rt = PreferredRuntime::create().unwrap();
        let mut builder = ChannelBuilder::default();
        builder.set_declared_method(tor_linkspec::ChannelMethod::Direct(vec!["127.0.0.1:9001"
            .parse()
            .unwrap()]));
        let tls = MsgBuf::new(&b""[..]);
        let _outbound = builder.launch(tls, rt, fake_mq());
    }

    #[test]
    fn check_match() {
        let chan = fake_channel(fake_channel_details());

        let t1 = OwnedChanTarget::builder()
            .ed_identity([6; 32].into())
            .rsa_identity([10; 20].into())
            .build()
            .unwrap();
        let t2 = OwnedChanTarget::builder()
            .ed_identity([1; 32].into())
            .rsa_identity([3; 20].into())
            .build()
            .unwrap();
        let t3 = OwnedChanTarget::builder()
            .ed_identity([3; 32].into())
            .rsa_identity([2; 20].into())
            .build()
            .unwrap();

        assert!(chan.check_match(&t1).is_ok());
        assert!(chan.check_match(&t2).is_err());
        assert!(chan.check_match(&t3).is_err());
    }

    #[test]
    fn unique_id() {
        let ch1 = fake_channel(fake_channel_details());
        let ch2 = fake_channel(fake_channel_details());
        assert_ne!(ch1.unique_id(), ch2.unique_id());
    }

    #[test]
    fn duration_unused_at() {
        let details = fake_channel_details();
        let ch = fake_channel(Arc::clone(&details));
        details.unused_since.update();
        assert!(ch.duration_unused().is_some());
    }
}
