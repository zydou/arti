//! Declarations for traits that we need our runtimes to implement.
use async_trait::async_trait;
use asynchronous_codec::Framed;
use futures::stream;
use futures::task::Spawn;
use futures::{AsyncRead, AsyncWrite, Future};
use std::fmt::Debug;
use std::io::{self, Result as IoResult};
use std::net;
use std::time::{Duration, Instant, SystemTime};
use tor_general_addr::unix;

/// A runtime for use by Tor client library code.
///
/// This trait comprises several other traits that we require all of our
/// runtimes to provide:
///
/// * [`futures::task::Spawn`] to launch new background tasks.
/// * [`SleepProvider`] to pause a task for a given amount of time.
/// * [`CoarseTimeProvider`] for a cheaper but less accurate notion of time.
/// * [`NetStreamProvider`] to launch and accept network connections.
/// * [`TlsProvider`] to launch TLS connections.
/// * [`Blocking`] to be able to run synchronous (cpubound or IO) code,
///   and *re*-enter the async context from synchronous thread
///   (This may become optional in the future, if/when we add WASM
///   support).
///
/// A value which is only `Runtime` cannot be used as an *entry point* to the runtime.
/// For that, it must also implement [`ToplevelBlockOn`],
/// making it a [`ToplevelRuntime`].
/// Since you can only [enter a runtime](ToplevelBlockOn::block_on) once,
/// typically you use a `ToplevelRuntime` to enter the runtime,
/// and use it as only a `Runtime` afterwards.
/// This means that library code should typically
/// deal with `Runtime` rather than `ToplevelRuntime`.
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
    + Blocking
    + Clone
    + SleepProvider
    + CoarseTimeProvider
    + NetStreamProvider<net::SocketAddr>
    + NetStreamProvider<unix::SocketAddr>
    + TlsProvider<<Self as NetStreamProvider<net::SocketAddr>>::Stream>
    + UdpProvider
    + Debug
    + 'static
{
}

impl<T> Runtime for T where
    T: Sync
        + Send
        + Spawn
        + Blocking
        + Clone
        + SleepProvider
        + CoarseTimeProvider
        + NetStreamProvider<net::SocketAddr>
        + NetStreamProvider<unix::SocketAddr>
        + TlsProvider<<Self as NetStreamProvider<net::SocketAddr>>::Stream>
        + UdpProvider
        + Debug
        + 'static
{
}

/// A runtime that we can use to run Tor as a client.
/// * [`ToplevelBlockOn`] to block on a top-level future and run it to completion
///   (This may become optional in the future, if/when we add WASM
///   support).
///
pub trait ToplevelRuntime: Runtime + ToplevelBlockOn {}
impl<T: Runtime + ToplevelBlockOn> ToplevelRuntime for T {}

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
    fn now_coarse(&self) -> crate::coarse_time::CoarseInstant;
}

/// Trait for a runtime that can be entered to block on a toplevel future.
///
/// This trait is *not* implied by `Runtime`, only by `ToplevelRuntime`.
/// `ToplevelRuntime` is available at the toplevel of each program,
/// typically, where a concrete async executor is selected.
pub trait ToplevelBlockOn: Clone + Send + Sync + 'static {
    /// Run `future` until it is ready, and return its output.
    ///
    /// # Not reentrant!
    ///
    /// There should be one call to `block_on` (for each fresh `Runtime`),
    /// at the toplevel of the program (or test case).
    /// (Sequential calls to `block_on` from the same thread are allowed.)
    ///
    /// `block_on` may not function correctly if is called
    /// from multiple threads simultaneously,
    /// or if calls involving different `Runtime`s are interleaved on the same thread.
    /// (Specific runtimes may offer better guarantees.)
    ///
    /// (`tor_rtmock::MockExecutor`'s implementation will often detect violations.)
    fn block_on<F: Future>(&self, future: F) -> F::Output;
}

/// Support for interacting with blocking (non-async) code
///
/// This supports two use cases: blocking IO and CPU-intensive activities.
/// (In both of these cases, simply calling the functions within an `async` task
/// is a bad idea, because that can block the whole async runtime.)
///
/// ### Blocking IO
///
/// `Blocking` can be used to interact with libraries or OS primitives
/// that only offer a synchronous, blocking, interface.
///
/// Use [`spawn_blocking`](Blocking::spawn_blocking)
/// when it is convenient to have a long-running thread,
/// for these operations.
///
/// Use [`blocking_io`](Blocking::blocking_io)
/// when the blocking code is usually expected to complete quickly,
/// and/or you will be switching back and forth a lot
/// between sync and async contexts.
/// Note that you cannot call back to async code from within `blocking_io`.
///
/// ### CPU-intensive activities
///
/// Perform CPU-intensive work, that ought not to block the program's main loop,
/// via [`Blocking::spawn_blocking`].
///
/// `spawn_blocking` does not apply any limiting or prioritisation;
/// its threads simply compete for CPU with other threads in the program.
/// That must be done by the caller; therefore:
///
/// **Limit the number of cpu threads** spawned
/// in order to limit the total amount of CPU time consumed by any part of the program.
/// For example, consider using one CPU thread per Tor Hidden Service.
///
/// It is most performant to spawn a long-running thread,
/// rather than to repeatedly spawn short-lived threads for individual work items.
/// This also makes it easier to limit the number of concurrente cpu threads.
/// For the same reason, [`Blocking::blocking_io`] should be avoided
/// for the CPU-intensive use case.
///
/// ### Mapping to concrete functions from underlying libraries
///
/// The semantics of `Blocking` are heavily influenced by Tokio
/// and by the desire to be able to use tor-rtmock's `MockExecutor` to test Arti code.
///
/// | `tor-rtcompat`               | Tokio                 | `MockExecutor`                 |
/// |------------------------------|-----------------------|--------------------------------|
/// | `ToplevelBlockOn::block_on`  | `Runtime::block_on`   | `ToplevelBlockOn::block_on`    |
/// | `Blocking::spawn_blocking`   | `task::spawn_blocking`  | `subthread_spawn`            |
/// | `Blocking::reenter_block_on` | `Handle::block_on`    | `subthread_block_on_future`    |
/// | `Blocking::blocking_io`      | `block_in_place`      | `subthread_spawn`              |
/// | (not available)              | (not implemented)     | `progress_until_stalled` etc.  |
///
/// Re `block_on`, see also the docs for the underlying implementations in
/// [tokio][tokio-threadpool] and
/// [async-std][async-std-threadpool].
///
/// [tokio-threadpool]: https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html
/// [async-std-threadpool]: https://docs.rs/async-std/latest/async_std/task/fn.spawn_blocking.html
pub trait Blocking: Clone + Send + Sync + 'static {
    /// Spawn a thread for blocking IO or CPU-bound work.
    ///
    /// This is used in two situations:
    ///
    ///  * To perform blocking IO
    ///  * For cpu-intensive work
    ///
    /// See [`Blocking`]'s trait level docs for advice on choosing
    /// between `spawn_blocking` and [`Blocking::blocking_io`].
    ///
    /// `Blocking::spawn_blocking` is similar to `std::thread::spawn`
    /// but also makes any necessary arrangements so that `reenter_block_on`,
    /// can be called on the spawned thread.
    ///
    /// However, `Blocking::spawn_blocking` *does not guarantee*
    /// to use a completely fresh thread.
    /// The implementation may have a thread pool, allowing it reuse an existing thread.
    /// Correspondingly, if a very large number of `Blocking::spawn_blocking` calls,
    /// are in progress at once, some of them may block.
    /// (For example, the implementation for Tokio uses `tokio::task::spawn_blocking`,
    /// which has both of these properties.)
    ///
    /// ### Typical use of `spawn_blocking`
    ///
    ///  * Spawn the thread with `SpawnThread::spawn_blocking`.
    ///  * On that thread, receive work items from from the async environment
    ///    using async inter-task facilities (eg `futures::channel::mpsc::channel`),
    ///    called via [`reenter_block_on`](Blocking::reenter_block_on).
    ///  * Return answers with async inter-task facilities, calling either
    ///    a non-blocking immediate send (eg `[try_send`])
    ///    or an async send call via `reneter_block_on`.
    ///
    /// ### CPU-intensive work
    ///
    /// Limit the number of CPU-intensive concurrent threads spawned with `spawn_blocking`.
    /// See the [trait-level docs](Blocking) for more details.
    ///
    /// ### Panics
    ///
    /// `Blocking::spawn_blocking` may only be called from within either:
    ///
    ///  * A task or future being polled by this `Runtime`; or
    ///  * A thread itself spawned with `Blocking::spawn_blocking` on the this runtime.
    ///
    /// Otherwise it may malfunction or panic.
    /// (`tor_rtmock::MockExecutor`'s implementation will usually detect violations.)
    ///
    /// If `f` panics, `ThreadHandle` will also panic when polled
    /// (perhaps using `resume_unwind`).
    fn spawn_blocking<F, T>(&self, f: F) -> Self::ThreadHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static;

    /// Future from [`spawn_blocking`](Self::spawn_blocking)
    ///
    /// The function callback (`f: F` in [`spawn_blocking`](Self::spawn_blocking)
    /// will start to run regardless of whether this future is awaited.
    ///
    /// Dropping this future doesn't stop the callback; it detaches it:
    /// the function will continue to run, but its output can no longer be collected.
    type ThreadHandle<T: Send + 'static>: Future<Output = T>;

    /// Block on a future, from within `Blocking::spawn_blocking`
    ///
    /// Reenters the executor, blocking this thread until `future` is `Ready`.
    ///
    /// See [`spawn_blocking`](Blocking::spawn_blocking) and
    /// [`Blocking`]'s trait-level docs for more details.
    ///
    /// It is not guaranteed what thread the future will be polled on.
    /// In production `Runtime`s, it will usually be the thread calling `reenter_block_on`.
    // All existing runtimes other than MockExecutor accept a non-Send future, but
    // MockExecutor::subthread_block_on_future does not.
    // If this restriction turns out to be awkward, MockExecutor could be changed, with some work.
    ///
    /// ### Panics
    ///
    /// Must only be called on a thread made with `Blocking::spawn_blocking`.
    /// **Not** allowed within [`blocking_io`](Blocking::blocking_io).
    ///
    /// Otherwise it may malfunction or panic.
    /// (`tor_rtmock::MockExecutor`'s implemnetation will usually detect violations.)
    fn reenter_block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
        F::Output: Send + 'static;

    /// Perform some blocking IO from an async future
    ///
    /// Call the blocking function `f`, informing the async executor
    /// that we are going to perform blocking IO.
    ///
    /// This is a usually-faster, but simpler, alternative to [`Blocking::spawn_blocking`].
    ///
    /// Its API can be more convenient than `spawn_blocking`.
    /// `blocking_io` is intended to be more performant than `spawn_blocking`
    /// when called repeatedly (ie, when switching quickly between sync and async).
    ///
    /// See [`Blocking`]'s trait-level docs for more information about
    /// the performance properties, and on choosing between `blocking_io`
    /// and `spawn_blocking`.
    /// (Avoid using `blocking_io` for CPU-intensive work.)
    ///
    /// ### Limitations
    ///
    ///  * `f` may **not** call [`Blocking::reenter_block_on`], so:
    ///  * `f` cannot execute any futures.
    ///    If this is needed, break up `f` into smaller pieces so that the
    ///    futures can be awaited outside the call to `blocking_io`,
    ///    or use `spawn_blocking` for the whole activity.
    ///  * `f` *may* be called on the calling thread when `blocking_io` is called,
    ///    on an executor thread when the returned future is polled,
    ///    or a different thread.
    ///  * Not suitable for CPU-intensive work
    ///    (mostly because there is no practical way to ration or limit
    ///    the amount of cpu time used).
    ///    Use `spawn_blocking` for that.
    ///  * Performance better than using `spawn_blocking` each time is not guaranteed.
    ///
    /// Otherwise the semantics are the same as
    /// [`spawn_blocking`](Self::spawn_blocking).
    ///
    /// ### Panics
    ///
    /// `Blocking::block_in_place` may only be called from within
    /// a task or future being polled by this `Runtime`.
    ///
    /// Otherwise it may malfunction or panic.
    /// (`tor_rtmock::MockExecutor`'s implemnetation will usually detect violations.)
    ///
    /// ### Fallback (provided) implementation
    ///
    /// The fallback implementation is currently used with `async_std`.
    /// It spawns a thread with `spawn_blocking`, once for each `blocking_io` call.
    fn blocking_io<F, T>(&self, f: F) -> impl Future<Output = T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.spawn_blocking(f)
    }
}

/// Trait providing additional operations on network sockets.
pub trait StreamOps {
    /// Set the [`TCP_NOTSENT_LOWAT`] socket option, if this `Stream` is a TCP stream.
    ///
    /// Implementations should return an [`UnsupportedStreamOp`] IO error
    /// if the stream is not a TCP stream,
    /// and on platforms where the operation is not supported.
    ///
    /// [`TCP_NOTSENT_LOWAT`]: https://lwn.net/Articles/560082/
    fn set_tcp_notsent_lowat(&self, _notsent_lowat: u32) -> IoResult<()> {
        Err(UnsupportedStreamOp {
            op: "set_tcp_notsent_lowat",
            reason: "unsupported object type",
        }
        .into())
    }

    /// Return a new handle that implements [`StreamOps`],
    /// and that can be used independently of `self`.
    fn new_handle(&self) -> Box<dyn StreamOps + Send + Unpin> {
        Box::new(NoOpStreamOpsHandle)
    }
}

/// A [`StreamOps`] handle that always returns an error.
///
/// Returned from [`StreamOps::new_handle`] for types and platforms
/// that do not support `StreamOps`.
#[derive(Copy, Clone, Debug, Default)]
#[non_exhaustive]
pub struct NoOpStreamOpsHandle;

impl StreamOps for NoOpStreamOpsHandle {
    fn new_handle(&self) -> Box<dyn StreamOps + Send + Unpin> {
        Box::new(*self)
    }
}

impl<T: StreamOps, C> StreamOps for Framed<T, C> {
    fn set_tcp_notsent_lowat(&self, notsent_lowat: u32) -> IoResult<()> {
        let inner: &T = self;
        inner.set_tcp_notsent_lowat(notsent_lowat)
    }

    fn new_handle(&self) -> Box<dyn StreamOps + Send + Unpin> {
        let inner: &T = self;
        inner.new_handle()
    }
}

/// Error: Tried to perform a [`StreamOps`] operation on an unsupported stream type
/// or on an unsupported platform.
///
/// (For example, you can't call [`StreamOps::set_tcp_notsent_lowat`] on Windows
/// or on a stream type that is not backed by a TCP socket.)
#[derive(Clone, Debug, thiserror::Error)]
#[error("Operation {op} not supported: {reason}")]
pub struct UnsupportedStreamOp {
    /// The unsupported operation.
    op: &'static str,
    /// The reason the operation is unsupported.
    reason: &'static str,
}

impl UnsupportedStreamOp {
    /// Construct a new `UnsupportedStreamOp` error with the provided operation and reason.
    pub fn new(op: &'static str, reason: &'static str) -> Self {
        Self { op, reason }
    }
}

impl From<UnsupportedStreamOp> for io::Error {
    fn from(value: UnsupportedStreamOp) -> Self {
        io::Error::new(io::ErrorKind::Unsupported, value)
    }
}

/// Trait for a runtime that can create and accept connections
/// over network sockets.
///
/// (In Arti we use the [`AsyncRead`] and [`AsyncWrite`] traits from
/// [`futures::io`] as more standard, even though the ones from Tokio
/// can be a bit more efficient.  Let's hope that they converge in the
/// future.)
// TODO: Use of async_trait is not ideal, since we have to box with every
// call.  Still, async_io basically makes that necessary :/
#[async_trait]
pub trait NetStreamProvider<ADDR = net::SocketAddr>: Clone + Send + Sync + 'static {
    /// The type for the connections returned by [`Self::connect()`].
    type Stream: AsyncRead + AsyncWrite + StreamOps + Send + Sync + Unpin + 'static;
    /// The type for the listeners returned by [`Self::listen()`].
    type Listener: NetStreamListener<ADDR, Stream = Self::Stream> + Send + Sync + Unpin + 'static;

    /// Launch a connection connection to a given socket address.
    ///
    /// Note that unlike `std::net:TcpStream::connect`, we do not accept
    /// any types other than a single `ADDR`.  We do this because
    /// we must be absolutely sure not to perform
    /// unnecessary DNS lookups.
    async fn connect(&self, addr: &ADDR) -> IoResult<Self::Stream>;

    /// Open a listener on a given socket address.
    async fn listen(&self, addr: &ADDR) -> IoResult<Self::Listener>;
}

/// Trait for a local socket that accepts incoming streams.
///
/// These objects are returned by instances of [`NetStreamProvider`].  To use
/// one,
/// use `incoming` to convert this object into a [`stream::Stream`].
pub trait NetStreamListener<ADDR = net::SocketAddr> {
    /// The type of connections returned by [`Self::incoming()`].
    type Stream: AsyncRead + AsyncWrite + StreamOps + Send + Sync + Unpin + 'static;

    /// The type of [`stream::Stream`] returned by [`Self::incoming()`].
    type Incoming: stream::Stream<Item = IoResult<(Self::Stream, ADDR)>>
        + Send
        + Sync
        + Unpin
        + 'static;

    /// Wrap this listener into a new [`stream::Stream`] that yields
    /// streams and addresses.
    fn incoming(self) -> Self::Incoming;

    /// Return the local address that this listener is bound to.
    fn local_addr(&self) -> IoResult<ADDR>;
}

/// Trait for a runtime that can send and receive UDP datagrams.
#[async_trait]
pub trait UdpProvider: Clone + Send + Sync + 'static {
    /// The type of Udp Socket returned by [`Self::bind()`]
    type UdpSocket: UdpSocket + Send + Sync + Unpin + 'static;

    /// Bind a local port to send and receive packets from
    async fn bind(&self, addr: &net::SocketAddr) -> IoResult<Self::UdpSocket>;
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
    async fn recv(&self, buf: &mut [u8]) -> IoResult<(usize, net::SocketAddr)>;
    /// Send a datagram to the provided address.
    async fn send(&self, buf: &[u8], target: &net::SocketAddr) -> IoResult<usize>;
    /// Return the local address that this socket is bound to.
    fn local_addr(&self) -> IoResult<net::SocketAddr>;
}

/// An object with a peer certificate: typically a TLS connection.
pub trait CertifiedConn {
    /// Return the keying material (RFC 5705) given a label and an optional context.
    fn export_keying_material(
        &self,
        len: usize,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> IoResult<Vec<u8>>;
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
pub trait TlsProvider<S: StreamOps>: Clone + Send + Sync + 'static {
    /// The Connector object that this provider can return.
    type Connector: TlsConnector<S, Conn = Self::TlsStream> + Send + Sync + Unpin;

    /// The type of the stream returned by that connector.
    type TlsStream: AsyncRead + AsyncWrite + StreamOps + CertifiedConn + Unpin + Send + 'static;

    /// Return a TLS connector for use with this runtime.
    fn tls_connector(&self) -> Self::Connector;

    /// Return true iff the keying material exporters (RFC 5705) is supported.
    fn supports_keying_material_export(&self) -> bool;
}
