//! Declarations for traits that we need our runtimes to implement.
use async_trait::async_trait;
use futures::stream;
use futures::task::Spawn;
use futures::{AsyncRead, AsyncWrite, Future};
use std::fmt::Debug;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

/// A runtime that we can use to run Tor as a client.
///
/// This trait comprises several other traits that we require all of our
/// runtimes to provide:
///
/// * [`futures::task::Spawn`] to launch new background tasks.
/// * [`SleepProvider`] to pause a task for a given amount of time.
/// * [`TcpProvider`] to launch and accept TCP connections.
/// * [`TlsProvider`] to launch TLS connections.
/// * [`BlockOn`] to block on a future and run it to completion
///   (This may become optional in the future, if/when we add WASM
///   support).
///
/// We require that every `Runtime` has an efficient [`Clone`] implementation
/// that gives a new opaque reference to the same underlying runtime.
///
/// Additionally, every `Runtime` is [`Send`] and [`Sync`], though these
/// requirements may be somewhat relaxed in the future.
///
/// At some future point,
/// Arti may require that the runtime `impl<S> TlsProvider<S>` (for suitable`S`),
/// rather than just for their own `TcpStream`s.
/// I.e., Arti may start to require that the runtime's TLS provider can wrap any streams,
/// not only the runtime's own TCP streams.
/// This might be expressed as an additional supertrait bound on `Runtime`,
/// eg when Rust supports GATs,
/// or as an additional bound on the Arti APIs that currently use `Runtime`.
/// For API future compatibility, if you `impl Runtime for MyRuntime`,
/// you should also ensure that you
/// ```ignore
/// impl<S> TlsProvider<S> for MyRuntime
/// where S: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static
/// ```
//
/// Perhaps we will need this if we make our own TLS connections *through* Tor,
/// rather than just channels to guards.
pub trait Runtime:
    Sync
    + Send
    + Spawn
    + BlockOn
    + Clone
    + SleepProvider
    + TcpProvider
    + TlsProvider<Self::TcpStream>
    + UdpProvider
    + Debug
    + 'static
{
}

impl<T> Runtime for T where
    T: Sync
        + Send
        + Spawn
        + BlockOn
        + Clone
        + SleepProvider
        + TcpProvider
        + TlsProvider<Self::TcpStream>
        + UdpProvider
        + Debug
        + 'static
{
}

/// Trait for a runtime that can wait until a timer has expired.
///
/// Every `SleepProvider` also implements
/// [`SleepProviderExt`](crate::SleepProviderExt); see that trait
/// for other useful functions.
pub trait SleepProvider: Clone + Send + Sync + 'static {
    /// A future returned by [`SleepProvider::sleep()`]
    type SleepFuture: Future<Output = ()> + Send + 'static;
    /// Return a future that will be ready after `duration` has
    /// elapsed.
    #[must_use = "sleep() returns a future, which does nothing unless used"]
    fn sleep(&self, duration: Duration) -> Self::SleepFuture;

    /// Return the SleepProvider's view of the current instant.
    ///
    /// (This is the same as `Instant::now`, if not running in test mode.)
    fn now(&self) -> Instant {
        Instant::now()
    }

    /// Return the SleepProvider's view of the current wall-clock time.
    ///
    /// (This is the same as `SystemTime::now`, if not running in test mode.)
    fn wallclock(&self) -> SystemTime {
        SystemTime::now()
    }

    /// Signify that a test running under mock time shouldn't advance time yet, with a given
    /// unique reason string. This is useful for making sure (mock) time doesn't advance while
    /// things that might require some (real-world) time to complete do so, such as spawning a task
    /// on another thread.
    ///
    /// Call `release_advance` with the same reason string in order to unblock.
    ///
    /// This method is only for testing: it should never have any
    /// effect when invoked on non-testing runtimes.
    fn block_advance<T: Into<String>>(&self, _reason: T) {}

    /// Signify that the reason to withhold time advancing provided in a call to `block_advance` no
    /// longer exists, and it's fine to move time forward if nothing else is blocking advances.
    ///
    /// This method is only for testing: it should never have any
    /// effect when invoked on non-testing runtimes.
    fn release_advance<T: Into<String>>(&self, _reason: T) {}

    /// Allow a test running under mock time to advance time by the provided duration, even if the
    /// above `block_advance` API has been used.
    ///
    /// This method is only for testing: it should never have any
    /// effect when invoked on non-testing runtimes.
    fn allow_one_advance(&self, _dur: Duration) {}
}

/// A provider of reduced-precision timestamps
///
/// This doesn't provide any facility for sleeping.
/// If you want to sleep based on reduced-precision timestamps,
/// convert the desired sleep duration to `std::time::Duration`
/// and use [`SleepProvider`].
pub trait CoarseTimeProvider: Clone + Send + Sync + 'static {
    /// Return the `CoarseTimeProvider`'s view of the current instant.
    ///
    /// This is supposed to be cheaper than `std::time::Instant::now`.
    fn now_coarse(&self) -> crate::coarsetime::CoarseInstant;
}

/// Trait for a runtime that can block on a future.
pub trait BlockOn: Clone + Send + Sync + 'static {
    /// Run `future` until it is ready, and return its output.
    fn block_on<F: Future>(&self, future: F) -> F::Output;
}

/// Trait for a runtime that can create and accept TCP connections.
///
/// (In Arti we use the [`AsyncRead`] and [`AsyncWrite`] traits from
/// [`futures::io`] as more standard, even though the ones from Tokio
/// can be a bit more efficient.  Let's hope that they converge in the
/// future.)
// TODO: Use of async_trait is not ideal, since we have to box with every
// call.  Still, async_io basically makes that necessary :/
#[async_trait]
pub trait TcpProvider: Clone + Send + Sync + 'static {
    /// The type for the TCP connections returned by [`Self::connect()`].
    type TcpStream: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static;
    /// The type for the TCP listeners returned by [`Self::listen()`].
    type TcpListener: TcpListener<TcpStream = Self::TcpStream> + Send + Sync + Unpin + 'static;

    /// Launch a TCP connection to a given socket address.
    ///
    /// Note that unlike `std::net:TcpStream::connect`, we do not accept
    /// any types other than a single [`SocketAddr`].  We do this because,
    /// as a Tor implementation, we most be absolutely sure not to perform
    /// unnecessary DNS lookups.
    async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::TcpStream>;

    /// Open a TCP listener on a given socket address.
    async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::TcpListener>;
}

/// Trait for a local socket that accepts incoming TCP streams.
///
/// These objects are returned by instances of [`TcpProvider`].  To use
/// one, either call `accept` to accept a single connection, or
/// use `incoming` to wrap this object as a [`stream::Stream`].
// TODO: Use of async_trait is not ideal here either.
#[async_trait]
pub trait TcpListener {
    /// The type of TCP connections returned by [`Self::accept()`].
    type TcpStream: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static;

    /// The type of [`stream::Stream`] returned by [`Self::incoming()`].
    type Incoming: stream::Stream<Item = IoResult<(Self::TcpStream, SocketAddr)>> + Send + Unpin;

    /// Wait for an incoming stream; return it along with its address.
    async fn accept(&self) -> IoResult<(Self::TcpStream, SocketAddr)>;

    /// Wrap this listener into a new [`stream::Stream`] that yields
    /// TCP streams and addresses.
    fn incoming(self) -> Self::Incoming;

    /// Return the local address that this listener is bound to.
    fn local_addr(&self) -> IoResult<SocketAddr>;
}

/// Trait for a runtime that can send and receive UDP datagrams.
#[async_trait]
pub trait UdpProvider: Clone + Send + Sync + 'static {
    /// The type of Udp Socket returned by [`Self::bind()`]
    type UdpSocket: UdpSocket + Send + Sync + Unpin + 'static;

    /// Bind a local port to send and receive packets from
    async fn bind(&self, addr: &SocketAddr) -> IoResult<Self::UdpSocket>;
}

/// Trait for a locally bound Udp socket that can send and receive datagrams.
///
/// These objects are returned by instances of [`UdpProvider`].
//
// NOTE that UdpSocket objects are _necessarily_ un-connected.  If you need to
// implement a connected Udp socket in the future, please make a new trait (and
// a new type.)
#[async_trait]
pub trait UdpSocket {
    /// Wait for an incoming datagram; return it along its address.
    async fn recv(&self, buf: &mut [u8]) -> IoResult<(usize, SocketAddr)>;
    /// Send a datagram to the provided address.
    async fn send(&self, buf: &[u8], target: &SocketAddr) -> IoResult<usize>;
    /// Return the local address that this socket is bound to.
    fn local_addr(&self) -> IoResult<SocketAddr>;
}

/// An object with a peer certificate: typically a TLS connection.
pub trait CertifiedConn {
    /// Try to return the (DER-encoded) peer certificate for this
    /// connection, if any.
    fn peer_certificate(&self) -> IoResult<Option<Vec<u8>>>;
}

/// An object that knows how to wrap a TCP connection (where the type of said TCP
/// connection is `S`) with TLS.
///
/// # Usage notes
///
/// Note that because of Tor's peculiarities, this is not a
/// general-purpose TLS type.  Unlike typical users, Tor does not want
/// its TLS library to check whether the certificates used in TLS are signed
/// within the web PKI hierarchy, or what their hostnames are, or even whether
/// they are valid.  It *does*, however, check that the subject public key in the
/// certificate is indeed correctly used to authenticate the TLS handshake.
///
/// If you are implementing something other than Tor, this is **not** the
/// functionality you want.
///
/// How can this behavior be remotely safe, even in Tor?  It only works for Tor
/// because the certificate that a Tor relay uses in TLS is not actually being
/// used to certify that relay's public key.  Instead, the certificate only used
/// as a container for the relay's public key.  The real certification happens
/// later, inside the TLS session, when the relay presents a CERTS cell.
///
/// Such sneakiness was especially necessary before TLS 1.3, which encrypts more
/// of the handshake, and before pluggable transports, which make
/// "innocuous-looking TLS handshakes" less important than they once were.  Once
/// TLS 1.3 is completely ubiquitous, we might be able to specify a simpler link
/// handshake than Tor uses now.
#[async_trait]
pub trait TlsConnector<S> {
    /// The type of connection returned by this connector
    type Conn: AsyncRead + AsyncWrite + CertifiedConn + Unpin + Send + 'static;

    /// Start a TLS session over the provided TCP stream `stream`.
    ///
    /// Declare `sni_hostname` as the desired hostname, but don't actually check
    /// whether the hostname in the certificate matches it.  The connector may
    /// send `sni_hostname` as part of its handshake, if it supports
    /// [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication) or one of
    /// the TLS 1.3 equivalents.
    async fn negotiate_unvalidated(&self, stream: S, sni_hostname: &str) -> IoResult<Self::Conn>;
}

/// Trait for a runtime that knows how to create TLS connections over
/// TCP streams of type `S`.
///
/// This is separate from [`TlsConnector`] because eventually we may
/// eventually want to support multiple `TlsConnector` implementations
/// that use a single [`Runtime`].
///
/// See the [`TlsConnector`] documentation for a discussion of the Tor-specific
/// limitations of this trait: If you are implementing something other than Tor,
/// this is **not** the functionality you want.
pub trait TlsProvider<S>: Clone + Send + Sync + 'static {
    /// The Connector object that this provider can return.
    type Connector: TlsConnector<S, Conn = Self::TlsStream> + Send + Sync + Unpin;

    /// The type of the stream returned by that connector.
    type TlsStream: AsyncRead + AsyncWrite + CertifiedConn + Unpin + Send + 'static;

    /// Return a TLS connector for use with this runtime.
    fn tls_connector(&self) -> Self::Connector;
}
