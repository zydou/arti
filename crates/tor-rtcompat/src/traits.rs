//! Declarations for traits that we need our runtimes to implement.
use async_trait::async_trait;
use futures::stream;
use futures::task::Spawn;
use futures::{AsyncRead, AsyncWrite, Future};
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
/// * [`SpawnBlocking`] to block on a future and run it to completion
///   (This may become optional in the future, if/when we add WASM
///   support).
///
/// We require that every `Runtime` has an efficient [`Clone`] implementation
/// that gives a new opaque reference to the same underlying runtime.
///
/// Additionally, every `Runtime` is [`Send`] and [`Sync`], though these
/// requirements may be somewhat relaxed in the future.
pub trait Runtime:
    Sync + Send + Spawn + SpawnBlocking + Clone + SleepProvider + TcpProvider + TlsProvider + 'static
{
}

impl<T> Runtime for T where
    T: Sync
        + Send
        + Spawn
        + SpawnBlocking
        + Clone
        + SleepProvider
        + TcpProvider
        + TlsProvider
        + 'static
{
}

/// Trait for a runtime that can wait until a timer has expired.
///
/// Every `SleepProvider` also implements [`crate::SleepProviderExt`];
/// see that trait for other useful functions.
pub trait SleepProvider {
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
    fn block_advance<T: Into<String>>(&self, _reason: T) {}

    /// Signify that the reason to withhold time advancing provided in a call to `block_advance` no
    /// longer exists, and it's fine to move time forward if nothing else is blocking advances.
    fn release_advance<T: Into<String>>(&self, _reason: T) {}

    /// Allow a test running under mock time to advance time by the provided duration, even if the
    /// above `block_advance` API has been used.
    fn allow_one_advance(&self, _dur: Duration) {}
}

/// Trait for a runtime that can block on a future.
pub trait SpawnBlocking {
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
pub trait TcpProvider {
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
    type Incoming: stream::Stream<Item = IoResult<(Self::TcpStream, SocketAddr)>> + Unpin;

    /// Wait for an incoming stream; return it along with its address.
    async fn accept(&self) -> IoResult<(Self::TcpStream, SocketAddr)>;

    /// Wrap this listener into a new [`stream::Stream`] that yields
    /// TCP streams and addresses.
    fn incoming(self) -> Self::Incoming;

    /// Return the local address that this listener is bound to.
    fn local_addr(&self) -> IoResult<SocketAddr>;
}

/// An object with a peer certificate: typically a TLS connection.
pub trait CertifiedConn {
    /// Try to return the (DER-encoded) peer certificate for this
    /// connection, if any.
    fn peer_certificate(&self) -> IoResult<Option<Vec<u8>>>;
}

/// An object that knows how to make a TLS-over-TCP connection we
/// can use in Tor.
///
/// (Note that because of Tor's peculiarities, this is not a
/// general-purpose TLS type.  Unlike typical users, Tor does not want
/// its TLS library to check whether the certificates are signed
/// within the web PKI hierarchy, or what their hostnames are.
#[async_trait]
pub trait TlsConnector {
    /// The type of connection returned by this connector
    type Conn: AsyncRead + AsyncWrite + CertifiedConn + Unpin + Send + 'static;

    /// Launch a TLS-over-TCP connection to a given address.
    ///
    /// Declare `sni_hostname` as the desired hostname, but don't
    /// actually check whether the hostname in the certificate matches
    /// it.
    async fn connect_unvalidated(
        &self,
        addr: &SocketAddr,
        sni_hostname: &str,
    ) -> IoResult<Self::Conn>;
}

/// Trait for a runtime that knows how to create TLS connections.
///
/// This is separate from [`TlsConnector`] because eventually we may
/// eventually want to support multiple `TlsConnector` implementations
/// that use a single [`Runtime`].
pub trait TlsProvider {
    /// The Connector object that this provider can return.
    type Connector: TlsConnector<Conn = Self::TlsStream> + Send + Sync + Unpin;

    /// The type of the stream returned by that connector.
    type TlsStream: AsyncRead + AsyncWrite + CertifiedConn + Unpin + Send + 'static;

    /// Return a TLS connector for use with this runtime.
    fn tls_connector(&self) -> Self::Connector;
}
