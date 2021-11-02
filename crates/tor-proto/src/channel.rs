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

mod circmap;
mod codec;
mod handshake;
mod reactor;
mod unique_id;

use crate::channel::reactor::CtrlMsg;
pub use crate::channel::unique_id::UniqId;
use crate::circuit;
use crate::circuit::celltypes::CreateResponse;
use crate::{Error, Result};
use tor_cell::chancell::{msg, ChanCell, CircId};
use tor_linkspec::ChanTarget;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;

use asynchronous_codec as futures_codec;
use futures::channel::{mpsc, oneshot};
use futures::io::{AsyncRead, AsyncWrite};
use futures::lock::Mutex;
use futures::sink::{Sink, SinkExt};
use futures::stream::Stream;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use rand::Rng;
use tracing::trace;

// reexport
pub use handshake::{OutboundClientHandshake, UnverifiedChannel, VerifiedChannel};

/// Type alias: A Sink and Stream that transforms a TLS connection into
/// a cell-based communication mechanism.
type CellFrame<T> = futures_codec::Framed<T, crate::channel::codec::ChannelCodec>;

/// An open client channel, ready to send and receive Tor cells.
///
/// A channel is a direct connection to a Tor relay, implemented using TLS.
pub struct Channel {
    /// A unique identifier for this channel.
    unique_id: UniqId,
    /// Validated Ed25519 identity for this peer.
    ed25519_id: Ed25519Identity,
    /// Validated RSA identity for this peer.
    rsa_id: RsaIdentity,
    /// If true, this channel is closing.
    closed: AtomicBool,

    /// reference-counted locked wrapper around the channel object
    inner: Mutex<ChannelImpl>,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("unique_id", &self.unique_id)
            .field("ed25519_id", &self.ed25519_id)
            .field("rsa_id", &self.rsa_id)
            .field("closed", &self.closed)
            .finish()
    }
}

/// Main implementation type for a channel.
struct ChannelImpl {
    /// What link protocol is the channel using?
    #[allow(dead_code)] // We don't support protocols where this would matter
    link_protocol: u16,
    /// The underlying channel, as a Sink of ChanCell.  Writing
    /// a ChanCell onto this sink sends it over the TLS channel.
    tls: Box<dyn Sink<ChanCell, Error = tor_cell::Error> + Send + Unpin + 'static>,
    /// A circuit map, to translate circuit IDs into circuits.
    ///
    /// The ChannelImpl side of this object only needs to use this
    /// when creating circuits; it's shared with the reactor, which uses
    /// it for dispatch.
    // This uses a separate mutex from the channel, since we only need
    // the circmap when we're making a new circuit, the reactor needs
    // it all the time.
    circmap: Weak<Mutex<circmap::CircMap>>,
    /// A stream used to send control messages to the Reactor.
    control: mpsc::UnboundedSender<CtrlMsg>,
    /// Context for allocating unique circuit log identifiers.
    circ_unique_id_ctx: unique_id::CircUniqIdContext,
}

/// Structure for building and launching a Tor channel.
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
        ChannelBuilder { target: None }
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
    pub fn launch<T>(self, tls: T) -> OutboundClientHandshake<T>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        handshake::OutboundClientHandshake::new(tls, self.target)
    }
}

impl Default for ChannelBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Channel {
    /// Construct a channel and reactor.
    ///
    /// Internal method, called to finalize the channel when we've
    /// sent our netinfo cell, received the peer's netinfo cell, and
    /// we're finally ready to create circuits.
    fn new<T>(
        link_protocol: u16,
        tls_sink: Box<dyn Sink<ChanCell, Error = tor_cell::Error> + Send + Unpin + 'static>,
        tls_stream: T,
        unique_id: UniqId,
        ed25519_id: Ed25519Identity,
        rsa_id: RsaIdentity,
    ) -> (Arc<Self>, reactor::Reactor<T>)
    where
        T: Stream<Item = std::result::Result<ChanCell, tor_cell::Error>> + Send + Unpin + 'static,
    {
        use circmap::{CircIdRange, CircMap};
        let circmap = Arc::new(Mutex::new(CircMap::new(CircIdRange::High)));

        let (control_tx, control_rx) = mpsc::unbounded();

        let inner = ChannelImpl {
            tls: tls_sink,
            link_protocol,
            circmap: Arc::downgrade(&circmap),
            control: control_tx,
            circ_unique_id_ctx: unique_id::CircUniqIdContext::new(),
        };
        let inner = Mutex::new(inner);
        let channel = Channel {
            unique_id,
            ed25519_id,
            rsa_id,
            closed: AtomicBool::new(false),
            inner,
        };
        let channel = Arc::new(channel);

        let reactor = reactor::Reactor::new(
            &Arc::clone(&channel),
            circmap,
            control_rx,
            tls_stream,
            unique_id,
        );

        (channel, reactor)
    }

    /// Return a process-unique identifier for this channel.
    pub fn unique_id(&self) -> UniqId {
        self.unique_id
    }

    /// Return the Ed25519 identity for the peer of this channel.
    pub fn peer_ed25519_id(&self) -> &Ed25519Identity {
        &self.ed25519_id
    }

    /// Return the (legacy) RSA identity for the peer of this channel.
    pub fn peer_rsa_id(&self) -> &RsaIdentity {
        &self.rsa_id
    }

    /// Return an error if this channel is somehow mismatched with the
    /// given target.
    pub fn check_match<T: ChanTarget + ?Sized>(&self, target: &T) -> Result<()> {
        if self.peer_ed25519_id() != target.ed_identity() {
            return Err(Error::ChanMismatch(format!(
                "Identity {} does not match target {}",
                self.peer_ed25519_id(),
                target.ed_identity()
            )));
        }

        if self.peer_rsa_id() != target.rsa_identity() {
            return Err(Error::ChanMismatch(format!(
                "Identity {} does not match target {}",
                self.peer_rsa_id(),
                target.rsa_identity()
            )));
        }

        Ok(())
    }

    /// Return true if this channel is closed and therefore unusable.
    pub fn is_closing(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Check whether a cell type is permissible to be _sent_ on an
    /// open client channel.
    fn check_cell(&self, cell: &ChanCell) -> Result<()> {
        use msg::ChanMsg::*;
        let msg = cell.msg();
        match msg {
            Created(_) | Created2(_) | CreatedFast(_) => Err(Error::InternalError(format!(
                "Can't send {} cell on client channel",
                msg.cmd()
            ))),
            Certs(_) | Versions(_) | Authenticate(_) | Authorize(_) | AuthChallenge(_)
            | Netinfo(_) => Err(Error::InternalError(format!(
                "Can't send {} cell after handshake is done",
                msg.cmd()
            ))),
            _ => Ok(()),
        }
    }

    /// Transmit a single cell on a channel.
    pub async fn send_cell(&self, cell: ChanCell) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::ChannelClosed);
        }
        self.check_cell(&cell)?;
        {
            use msg::ChanMsg::*;
            match cell.msg() {
                Relay(_) | Padding(_) | VPadding(_) => {} // too frequent to log.
                _ => trace!(
                    "{}: Sending {} for {}",
                    self.unique_id,
                    cell.msg().cmd(),
                    cell.circid()
                ),
            }
        }

        let inner = &mut self.inner.lock().await;
        inner.tls.send(cell).await?; // XXXX I don't like holding the lock here.

        Ok(())
    }

    /// Return a newly allocated PendingClientCirc object with
    /// a corresponding circuit reactor. A circuit ID is allocated, but no
    /// messages are sent, and no cryptography is done.
    ///
    /// To use the results of this method, call Reactor::run() in a
    /// new task, then use the methods of
    /// [crate::circuit::PendingClientCirc] to build the circuit.
    pub async fn new_circ<R: Rng>(
        self: &Arc<Self>,
        rng: &mut R,
    ) -> Result<(circuit::PendingClientCirc, circuit::reactor::Reactor)> {
        if self.is_closing() {
            return Err(Error::ChannelClosed);
        }

        // TODO: blocking is risky, but so is unbounded.
        let (sender, receiver) = mpsc::channel(128);
        let (createdsender, createdreceiver) = oneshot::channel::<CreateResponse>();

        let (circ_unique_id, id, reactor_tx) = {
            let mut inner = self.inner.lock().await;
            if let Some(circmap) = inner.circmap.upgrade() {
                let my_unique_id = self.unique_id;
                let circ_unique_id = inner.circ_unique_id_ctx.next(my_unique_id);
                let mut cmap = circmap.lock().await;
                (
                    circ_unique_id,
                    cmap.add_ent(rng, createdsender, sender)?,
                    inner.control.clone(),
                )
            } else {
                return Err(Error::ChannelClosed);
            }
        };
        trace!("{}: Allocated CircId {}", circ_unique_id, id);

        let destroy_handle = CircDestroyHandle::new(id, reactor_tx);

        Ok(circuit::PendingClientCirc::new(
            id,
            Arc::clone(self),
            createdreceiver,
            Some(destroy_handle),
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
    pub async fn terminate(&self) {
        let outcome = self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        if outcome == Ok(false) {
            // The old value was false and the new value is true.
            let mut inner = self.inner.lock().await;
            inner.shutdown_reactor();
            // ignore any failure to flush; we can't do anything about it.
            let _ignore = inner.tls.flush().await;
        }
    }
}

impl Drop for ChannelImpl {
    fn drop(&mut self) {
        self.shutdown_reactor();
    }
}

impl ChannelImpl {
    /// Shut down this channel's reactor; causes all circuits using
    /// this channel to become unusable.
    fn shutdown_reactor(&mut self) {
        // FIXME(eta): this shouldn't be required
        let _ = self.control.unbounded_send(CtrlMsg::Shutdown);
    }
}

/// Helper structure: when this is dropped, the reactor is told to kill
/// the circuit.
pub(crate) struct CircDestroyHandle {
    /// The circuit ID in question
    id: CircId,
    /// A sender to tell the reactor.
    sender: mpsc::UnboundedSender<CtrlMsg>,
}

impl CircDestroyHandle {
    /// Create a new CircDestroyHandle
    fn new(id: CircId, sender: mpsc::UnboundedSender<CtrlMsg>) -> Self {
        CircDestroyHandle { id, sender }
    }
}

impl Drop for CircDestroyHandle {
    fn drop(&mut self) {
        let _ignore_cancel = self.sender.unbounded_send(CtrlMsg::CloseCircuit(self.id));
    }
}

#[cfg(test)]
pub(crate) mod test {
    // Most of this module is tested via tests that also check on the
    // reactor code; there are just a few more cases to examine here.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::channel::codec::test::MsgBuf;
    use crate::channel::reactor::test::new_reactor;
    use futures::stream::StreamExt;
    use futures_await_test::async_test;
    use tor_cell::chancell::{msg, msg::ChanMsg, ChanCell};

    /// Type returned along with a fake channel: used to impersonate a
    /// reactor and a network.
    #[allow(unused)]
    pub(crate) struct FakeChanHandle {
        pub(crate) cells: mpsc::Receiver<ChanCell>,
        circmap: Arc<Mutex<circmap::CircMap>>,
        ignore_control_msgs: mpsc::UnboundedReceiver<CtrlMsg>,
    }

    /// Make a new fake reactor-less channel.  For testing only, obviously.
    ///
    /// This function is used for testing _circuits_, not channels.
    pub(crate) fn fake_channel() -> (Arc<Channel>, FakeChanHandle) {
        let (cell_send, cell_recv) = mpsc::channel(64);
        let (control_tx, control_rx) = mpsc::unbounded();

        let cell_send = cell_send.sink_map_err(|_| {
            tor_cell::Error::InternalError("Error from mpsc stream while testing".into())
        });

        let circmap = circmap::CircMap::new(circmap::CircIdRange::High);
        let circmap = Arc::new(Mutex::new(circmap));
        let unique_id = UniqId::new();
        let inner = ChannelImpl {
            link_protocol: 4,
            tls: Box::new(cell_send),
            circmap: Arc::downgrade(&circmap),
            control: control_tx,
            circ_unique_id_ctx: unique_id::CircUniqIdContext::new(),
        };
        let channel = Channel {
            unique_id,
            ed25519_id: [6_u8; 32].into(),
            rsa_id: [10_u8; 20].into(),
            closed: AtomicBool::new(false),
            inner: Mutex::new(inner),
        };
        let handle = FakeChanHandle {
            cells: cell_recv,
            circmap,
            ignore_control_msgs: control_rx,
        };

        (Arc::new(channel), handle)
    }

    #[async_test]
    async fn send_bad() {
        let (chan, _reactor, mut output, _input) = new_reactor();

        let cell = ChanCell::new(7.into(), msg::Created2::new(&b"hihi"[..]).into());
        let e = chan.send_cell(cell).await;
        assert!(e.is_err());
        assert_eq!(
            format!("{}", e.unwrap_err()),
            "Internal programming error: Can't send CREATED2 cell on client channel"
        );
        let cell = ChanCell::new(0.into(), msg::Certs::new_empty().into());
        let e = chan.send_cell(cell).await;
        assert!(e.is_err());
        assert_eq!(
            format!("{}", e.unwrap_err()),
            "Internal programming error: Can't send CERTS cell after handshake is done"
        );

        let cell = ChanCell::new(5.into(), msg::Create2::new(2, &b"abc"[..]).into());
        let e = chan.send_cell(cell).await;
        assert!(e.is_ok());
        let got = output.next().await.unwrap();
        assert!(matches!(got.msg(), ChanMsg::Create2(_)));
    }

    #[test]
    fn chanbuilder() {
        let mut builder = ChannelBuilder::default();
        builder.set_declared_addr("127.0.0.1:9001".parse().unwrap());
        let tls = MsgBuf::new(&b""[..]);
        let _outbound = builder.launch(tls);
    }

    #[test]
    fn check_match() {
        use std::net::SocketAddr;
        let (chan, _reactor, _output, _input) = new_reactor();

        struct ChanT {
            ed_id: Ed25519Identity,
            rsa_id: RsaIdentity,
        }
        impl ChanTarget for ChanT {
            fn ed_identity(&self) -> &Ed25519Identity {
                &self.ed_id
            }
            fn rsa_identity(&self) -> &RsaIdentity {
                &self.rsa_id
            }
            fn addrs(&self) -> &[SocketAddr] {
                &[]
            }
        }

        let t1 = ChanT {
            ed_id: [0x1; 32].into(),
            rsa_id: [0x2; 20].into(),
        };
        let t2 = ChanT {
            ed_id: [0x1; 32].into(),
            rsa_id: [0x3; 20].into(),
        };
        let t3 = ChanT {
            ed_id: [0x3; 32].into(),
            rsa_id: [0x2; 20].into(),
        };

        assert!(chan.check_match(&t1).is_ok());
        assert!(chan.check_match(&t2).is_err());
        assert!(chan.check_match(&t3).is_err());
    }

    #[test]
    fn unique_id() {
        let (ch1, _handle1) = fake_channel();
        let (ch2, _handle2) = fake_channel();
        assert!(ch1.unique_id() != ch2.unique_id());
    }
}
