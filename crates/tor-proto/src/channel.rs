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
//! however, there is no alternative in Arti today.  (A future
//! channel-manager library will probably fix that.)
//!
//! To launch a channel:
//!
//!  * Create a TLS connection as an object that implements AsyncRead
//!    + AsyncWrite, and pass it to a [ChannelBuilder].  This will
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
//! [crate::circuit::PendingClientCirc] for information on how to
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
pub mod padding;
pub mod params;
mod reactor;
mod unique_id;

pub use crate::channel::params::*;
use crate::channel::reactor::{BoxedChannelSink, BoxedChannelStream, CtrlMsg, Reactor};
pub use crate::channel::unique_id::UniqId;
use crate::circuit::celltypes::CreateResponse;
use crate::util::err::ChannelClosed;
use crate::util::ts::OptTimestamp;
use crate::{circuit, ClockSkew};
use crate::{Error, Result};
use std::pin::Pin;
use std::result::Result as StdResult;
use std::time::Duration;
use tor_cell::chancell::{msg, ChanCell, CircId};
use tor_error::internal;
use tor_linkspec::{HasRelayIds, OwnedChanTarget};
use tor_rtcompat::SleepProvider;

use asynchronous_codec as futures_codec;
use futures::channel::{mpsc, oneshot};
use futures::io::{AsyncRead, AsyncWrite};

use futures::{Sink, SinkExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tracing::trace;

// reexport
use crate::channel::unique_id::CircUniqIdContext;
#[cfg(test)]
pub(crate) use codec::CodecError;
pub use handshake::{OutboundClientHandshake, UnverifiedChannel, VerifiedChannel};

/// Type alias: A Sink and Stream that transforms a TLS connection into
/// a cell-based communication mechanism.
type CellFrame<T> = futures_codec::Framed<T, crate::channel::codec::ChannelCodec>;

/// An open client channel, ready to send and receive Tor cells.
///
/// A channel is a direct connection to a Tor relay, implemented using TLS.
///
/// This struct is a frontend that can be used to send cells (using the `Sink<ChanCell>`
/// impl and otherwise control the channel.  The main state is in the Reactor object.
/// `Channel` is cheap to clone.
///
/// (Users need a mutable reference because of the types in `Sink`, and ultimately because
/// `cell_tx: mpsc::Sender` doesn't work without mut.
#[derive(Clone, Debug)]
pub struct Channel {
    /// A channel used to send control messages to the Reactor.
    control: mpsc::UnboundedSender<CtrlMsg>,
    /// A channel used to send cells to the Reactor.
    cell_tx: mpsc::Sender<ChanCell>,
    /// Information shared with the reactor
    details: Arc<ChannelDetails>,
}

/// This is information shared between the reactor and the frontend.
///
/// This exists to make `Channel` cheap to clone, which is desirable because every circuit wants
/// an owned mutable `Channel`.
///
/// `control` can't be here because we rely on it getting dropped when the last user goes away.
#[derive(Debug)]
pub(crate) struct ChannelDetails {
    /// A unique identifier for this channel.
    unique_id: UniqId,
    /// Validated identity and address information for this peer.
    peer_id: OwnedChanTarget,
    /// If true, this channel is closing.
    closed: AtomicBool,
    /// Since when the channel became unused.
    ///
    /// If calling `time_since_update` returns None,
    /// this channel is still in use by at least one circuit.
    unused_since: OptTimestamp,
    /// The declared clock skew on this channel, at the time when this channel was
    /// created.
    clock_skew: ClockSkew,
    /// The time when this channel was successfully completed
    opened_at: coarsetime::Instant,
}

impl Sink<ChanCell> for Channel {
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.cell_tx)
            .poll_ready(cx)
            .map_err(|_| ChannelClosed.into())
    }

    fn start_send(self: Pin<&mut Self>, cell: ChanCell) -> Result<()> {
        let this = self.get_mut();
        if this.details.closed.load(Ordering::SeqCst) {
            return Err(ChannelClosed.into());
        }
        this.check_cell(&cell)?;
        {
            use msg::ChanMsg::*;
            match cell.msg() {
                Relay(_) | Padding(_) | VPadding(_) => {} // too frequent to log.
                _ => trace!(
                    "{}: Sending {} for {}",
                    this.details.unique_id,
                    cell.msg().cmd(),
                    cell.circid()
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
    /// to be used in log messages.
    ///
    /// TODO: at some point, check this against the addresses in the
    /// netinfo cell too.
    target: Option<std::net::SocketAddr>,
}

impl ChannelBuilder {
    /// Construct a new ChannelBuilder.
    pub fn new() -> Self {
        ChannelBuilder::default()
    }

    /// Set the declared target address of this channel.
    ///
    /// Note that nothing enforces the correctness of this address: it
    /// doesn't have to match the real address target of the TLS
    /// stream.  For now it is only used for logging.
    pub fn set_declared_addr(&mut self, target: std::net::SocketAddr) {
        self.target = Some(target);
    }

    /// Launch a new client handshake over a TLS stream.
    ///
    /// After calling this function, you'll need to call `connect()` on
    /// the result to start the handshake.  If that succeeds, you'll have
    /// authentication info from the relay: call `check()` on the result
    /// to check that.  Finally, to finish the handshake, call `finish()`
    /// on the result of _that_.
    pub fn launch<T, S>(self, tls: T, sleep_prov: S) -> OutboundClientHandshake<T, S>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        S: SleepProvider,
    {
        handshake::OutboundClientHandshake::new(tls, self.target, sleep_prov)
    }
}

impl Channel {
    /// Construct a channel and reactor.
    ///
    /// Internal method, called to finalize the channel when we've
    /// sent our netinfo cell, received the peer's netinfo cell, and
    /// we're finally ready to create circuits.
    fn new<S>(
        link_protocol: u16,
        sink: BoxedChannelSink,
        stream: BoxedChannelStream,
        unique_id: UniqId,
        peer_id: OwnedChanTarget,
        clock_skew: ClockSkew,
        sleep_prov: S,
    ) -> (Self, reactor::Reactor<S>)
    where
        S: SleepProvider,
    {
        use circmap::{CircIdRange, CircMap};
        let circmap = CircMap::new(CircIdRange::High);

        let (control_tx, control_rx) = mpsc::unbounded();
        let (cell_tx, cell_rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let closed = AtomicBool::new(false);
        let unused_since = OptTimestamp::new();
        unused_since.update();

        let details = ChannelDetails {
            unique_id,
            peer_id,
            closed,
            unused_since,
            clock_skew,
            opened_at: coarsetime::Instant::now(),
        };
        let details = Arc::new(details);

        let channel = Channel {
            control: control_tx,
            cell_tx,
            details: Arc::clone(&details),
        };

        // We start disabled; the channel manager will `reconfigure` us soon after creation.
        let padding_timer = Box::pin(padding::Timer::new_disabled(sleep_prov, None));

        let reactor = Reactor {
            control: control_rx,
            cells: cell_rx,
            input: futures::StreamExt::fuse(stream),
            output: sink,
            circs: circmap,
            circ_unique_id_ctx: CircUniqIdContext::new(),
            link_protocol,
            details,
            padding_timer,
        };

        (channel, reactor)
    }

    /// Return a process-unique identifier for this channel.
    pub fn unique_id(&self) -> UniqId {
        self.details.unique_id
    }

    /// Return an OwnedChanTarget representing the actual handshake used to
    /// create this channel.
    pub fn target(&self) -> &OwnedChanTarget {
        &self.details.peer_id
    }

    /// Return the amount of time that has passed since this channel became open.
    pub fn age(&self) -> Duration {
        self.details.opened_at.elapsed().into()
    }

    /// Return a ClockSkew declaring how much clock skew the other side of this channel
    /// claimed that we had when we negotiated the connection.
    pub fn clock_skew(&self) -> ClockSkew {
        self.details.clock_skew
    }

    /// Reparameterise (update parameters; reconfigure)
    ///
    /// Returns `Err` if the channel was closed earlier
    pub fn reparameterize(
        &mut self,
        updates: Arc<ChannelsParamsUpdates>,
    ) -> StdResult<(), ChannelClosed> {
        self.control
            .unbounded_send(CtrlMsg::ConfigUpdate(updates))
            .map_err(|_| ChannelClosed)
    }

    /// Return an error if this channel is somehow mismatched with the
    /// given target.
    pub fn check_match<T: HasRelayIds + ?Sized>(&self, target: &T) -> Result<()> {
        check_id_match_helper(&self.details.peer_id, target)
    }

    /// Return true if this channel is closed and therefore unusable.
    pub fn is_closing(&self) -> bool {
        self.details.closed.load(Ordering::SeqCst)
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

    /// Check whether a cell type is permissible to be _sent_ on an
    /// open client channel.
    fn check_cell(&self, cell: &ChanCell) -> Result<()> {
        use msg::ChanMsg::*;
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

    /// Like `futures::Sink::poll_ready`.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Result<bool> {
        Ok(match Pin::new(&mut self.cell_tx).poll_ready(cx) {
            Poll::Ready(Ok(_)) => true,
            Poll::Ready(Err(_)) => return Err(Error::CircuitClosed),
            Poll::Pending => false,
        })
    }

    /// Transmit a single cell on a channel.
    pub async fn send_cell(&mut self, cell: ChanCell) -> Result<()> {
        self.send(cell).await?;

        Ok(())
    }

    /// Return a newly allocated PendingClientCirc object with
    /// a corresponding circuit reactor. A circuit ID is allocated, but no
    /// messages are sent, and no cryptography is done.
    ///
    /// To use the results of this method, call Reactor::run() in a
    /// new task, then use the methods of
    /// [crate::circuit::PendingClientCirc] to build the circuit.
    pub async fn new_circ(
        &self,
    ) -> Result<(circuit::PendingClientCirc, circuit::reactor::Reactor)> {
        if self.is_closing() {
            return Err(ChannelClosed.into());
        }

        // TODO: blocking is risky, but so is unbounded.
        let (sender, receiver) = mpsc::channel(128);
        let (createdsender, createdreceiver) = oneshot::channel::<CreateResponse>();

        let (tx, rx) = oneshot::channel();
        self.control
            .unbounded_send(CtrlMsg::AllocateCircuit {
                created_sender: createdsender,
                sender,
                tx,
            })
            .map_err(|_| ChannelClosed)?;
        let (id, circ_unique_id) = rx.await.map_err(|_| ChannelClosed)??;

        trace!("{}: Allocated CircId {}", circ_unique_id, id);

        Ok(circuit::PendingClientCirc::new(
            id,
            self.clone(),
            createdreceiver,
            receiver,
            circ_unique_id,
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
        let _ = self.control.unbounded_send(CtrlMsg::Shutdown);
    }

    /// Tell the reactor that the circuit with the given ID has gone away.
    pub fn close_circuit(&self, circid: CircId) -> Result<()> {
        self.control
            .unbounded_send(CtrlMsg::CloseCircuit(circid))
            .map_err(|_| ChannelClosed)?;
        Ok(())
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
                    actual, desired
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

#[cfg(test)]
pub(crate) mod test {
    // Most of this module is tested via tests that also check on the
    // reactor code; there are just a few more cases to examine here.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::channel::codec::test::MsgBuf;
    pub(crate) use crate::channel::reactor::test::new_reactor;
    use tor_cell::chancell::{msg, ChanCell};
    use tor_rtcompat::PreferredRuntime;

    /// Make a new fake reactor-less channel.  For testing only, obviously.
    pub(crate) fn fake_channel(details: Arc<ChannelDetails>) -> Channel {
        Channel {
            control: mpsc::unbounded().0,
            cell_tx: mpsc::channel(CHANNEL_BUFFER_SIZE).0,
            details,
        }
    }

    fn fake_channel_details() -> Arc<ChannelDetails> {
        let unique_id = UniqId::new();
        let unused_since = OptTimestamp::new();
        let peer_id = OwnedChanTarget::new(vec![], [6_u8; 32].into(), [10_u8; 20].into());

        Arc::new(ChannelDetails {
            unique_id,
            peer_id,
            closed: AtomicBool::new(false),
            unused_since,
            clock_skew: ClockSkew::None,
            opened_at: coarsetime::Instant::now(),
        })
    }

    #[test]
    fn send_bad() {
        tor_rtcompat::test_with_all_runtimes!(|_rt| async move {
            use std::error::Error;
            let chan = fake_channel(fake_channel_details());

            let cell = ChanCell::new(7.into(), msg::Created2::new(&b"hihi"[..]).into());
            let e = chan.check_cell(&cell);
            assert!(e.is_err());
            assert!(format!("{}", e.unwrap_err().source().unwrap())
                .contains("Can't send CREATED2 cell on client channel"));
            let cell = ChanCell::new(0.into(), msg::Certs::new_empty().into());
            let e = chan.check_cell(&cell);
            assert!(e.is_err());
            assert!(format!("{}", e.unwrap_err().source().unwrap())
                .contains("Can't send CERTS cell after handshake is done"));

            let cell = ChanCell::new(5.into(), msg::Create2::new(2, &b"abc"[..]).into());
            let e = chan.check_cell(&cell);
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
        builder.set_declared_addr("127.0.0.1:9001".parse().unwrap());
        let tls = MsgBuf::new(&b""[..]);
        let _outbound = builder.launch(tls, rt);
    }

    #[test]
    fn check_match() {
        let chan = fake_channel(fake_channel_details());

        let t1 = OwnedChanTarget::new(vec![], [6; 32].into(), [10; 20].into());
        let t2 = OwnedChanTarget::new(vec![], [0x1; 32].into(), [0x3; 20].into());
        let t3 = OwnedChanTarget::new(vec![], [0x3; 32].into(), [0x2; 20].into());

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
