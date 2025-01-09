//! Implements a simple mock network for testing purposes.

// Note: There are lots of opportunities here for making the network
// more and more realistic, but please remember that this module only
// exists for writing unit tests.  Let's resist the temptation to add
// things we don't need.

#![forbid(unsafe_code)] // if you remove this, enable (or write) miri tests (git grep miri)

use super::io::{stream_pair, LocalStream};
use super::MockNetRuntime;
use crate::util::mpsc_channel;
use core::fmt;
use tor_rtcompat::tls::TlsConnector;
use tor_rtcompat::{
    CertifiedConn, NetStreamListener, NetStreamProvider, Runtime, StreamOps, TlsProvider,
};
use tor_rtcompat::{UdpProvider, UdpSocket};

use async_trait::async_trait;
use futures::channel::mpsc;
use futures::io::{AsyncRead, AsyncWrite};
use futures::lock::Mutex as AsyncMutex;
use futures::sink::SinkExt;
use futures::stream::{Stream, StreamExt};
use futures::FutureExt;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::io::{self, Error as IoError, ErrorKind, Result as IoResult};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use thiserror::Error;
use void::Void;

/// A channel sender that we use to send incoming connections to
/// listeners.
type ConnSender = mpsc::Sender<(LocalStream, SocketAddr)>;
/// A channel receiver that listeners use to receive incoming connections.
type ConnReceiver = mpsc::Receiver<(LocalStream, SocketAddr)>;

/// A simulated Internet, for testing.
///
/// We simulate TCP streams only, and skip all the details. Connection
/// are implemented using [`LocalStream`]. The MockNetwork object is
/// shared by a large set of MockNetworkProviders, each of which has
/// its own view of its address(es) on the network.
#[derive(Default)]
pub struct MockNetwork {
    /// A map from address to the entries about listeners there.
    listening: Mutex<HashMap<SocketAddr, AddrBehavior>>,
}

/// The `MockNetwork`'s view of a listener.
#[derive(Clone)]
struct ListenerEntry {
    /// A sender that need to be informed about connection attempts
    /// there.
    send: ConnSender,

    /// A notional TLS certificate for this listener.  If absent, the
    /// listener isn't a TLS listener.
    tls_cert: Option<Vec<u8>>,
}

/// A possible non-error behavior from an address
#[derive(Clone)]
enum AddrBehavior {
    /// There's a listener at this address, which would like to reply.
    Listener(ListenerEntry),
    /// All connections sent to this address will time out.
    Timeout,
}

/// A view of a single host's access to a MockNetwork.
///
/// Each simulated host has its own addresses that it's allowed to listen on,
/// and a reference to the network.
///
/// This type implements [`NetStreamProvider`] for [`SocketAddr`]
/// so that it can be used as a
/// drop-in replacement for testing code that uses the network.
///
/// # Limitations
///
/// There's no randomness here, so we can't simulate the weirdness of
/// real networks.
///
/// So far, there's no support for DNS or UDP.
///
/// We don't handle localhost specially, and we don't simulate providers
/// that can connect to some addresses but not all.
///
/// We don't do the right thing (block) if there is a listener that
/// never calls accept.
///
/// UDP is completely broken:
/// datagrams appear to be transmitted, but will never be received.
/// And local address assignment is not implemented
/// so [`.local_addr()`](UdpSocket::local_addr) can return `NONE`
// TODO MOCK UDP: Documentation does describe the brokennesses
///
/// We use a simple `u16` counter to decide what arbitrary port
/// numbers to use: Once that counter is exhausted, we will fail with
/// an assertion.  We don't do anything to prevent those arbitrary
/// ports from colliding with specified ports, other than declare that
/// you can't have two listeners on the same addr:port at the same
/// time.
///
/// We pretend to provide TLS, but there's no actual encryption or
/// authentication.
#[derive(Clone)]
pub struct MockNetProvider {
    /// Actual implementation of this host's view of the network.
    ///
    /// We have to use a separate type here and reference count it,
    /// since the `next_port` counter needs to be shared.
    inner: Arc<MockNetProviderInner>,
}

impl fmt::Debug for MockNetProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockNetProvider").finish_non_exhaustive()
    }
}

/// Shared part of a MockNetworkProvider.
///
/// This is separate because providers need to implement Clone, but
/// `next_port` can't be cloned.
struct MockNetProviderInner {
    /// List of public addresses
    addrs: Vec<IpAddr>,
    /// Shared reference to the network.
    net: Arc<MockNetwork>,
    /// Next port number to hand out when we're asked to listen on
    /// port 0.
    ///
    /// See discussion of limitations on `listen()` implementation.
    next_port: AtomicU16,
}

/// A [`NetStreamListener`] implementation returned by a [`MockNetProvider`].
///
/// Represents listening on a public address for incoming TCP connections.
pub struct MockNetListener {
    /// The address that we're listening on.
    addr: SocketAddr,
    /// The incoming channel that tells us about new connections.
    // TODO: I'm not thrilled to have to use an AsyncMutex and a
    // std Mutex in the same module.
    receiver: AsyncMutex<ConnReceiver>,
}

/// A builder object used to configure a [`MockNetProvider`]
///
/// Returned by [`MockNetwork::builder()`].
pub struct ProviderBuilder {
    /// List of public addresses.
    addrs: Vec<IpAddr>,
    /// Shared reference to the network.
    net: Arc<MockNetwork>,
}

impl Default for MockNetProvider {
    fn default() -> Self {
        Arc::new(MockNetwork::default()).builder().provider()
    }
}

impl MockNetwork {
    /// Make a new MockNetwork with no active listeners.
    pub fn new() -> Arc<Self> {
        Default::default()
    }

    /// Return a [`ProviderBuilder`] for creating a [`MockNetProvider`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use tor_rtmock::net::*;
    /// # let mock_network = MockNetwork::new();
    /// let client_net = mock_network.builder()
    ///       .add_address("198.51.100.6".parse().unwrap())
    ///       .add_address("2001:db8::7".parse().unwrap())
    ///       .provider();
    /// ```
    pub fn builder(self: &Arc<Self>) -> ProviderBuilder {
        ProviderBuilder {
            addrs: vec![],
            net: Arc::clone(self),
        }
    }

    /// Add a "black hole" at the given address, where all traffic will time out.
    pub fn add_blackhole(&self, address: SocketAddr) -> IoResult<()> {
        let mut listener_map = self.listening.lock().expect("Poisoned lock for listener");
        if listener_map.contains_key(&address) {
            return Err(err(ErrorKind::AddrInUse));
        }
        listener_map.insert(address, AddrBehavior::Timeout);
        Ok(())
    }

    /// Tell the listener at `target_addr` (if any) about an incoming
    /// connection from `source_addr` at `peer_stream`.
    ///
    /// If the listener is a TLS listener, returns its certificate.
    /// **Note:** Callers should check whether the presence or absence of a certificate
    /// matches their expectations.
    ///
    /// Returns an error if there isn't any such listener.
    async fn send_connection(
        &self,
        source_addr: SocketAddr,
        target_addr: SocketAddr,
        peer_stream: LocalStream,
    ) -> IoResult<Option<Vec<u8>>> {
        let entry = {
            let listener_map = self.listening.lock().expect("Poisoned lock for listener");
            listener_map.get(&target_addr).cloned()
        };
        match entry {
            Some(AddrBehavior::Listener(mut entry)) => {
                if entry.send.send((peer_stream, source_addr)).await.is_ok() {
                    return Ok(entry.tls_cert);
                }
                Err(err(ErrorKind::ConnectionRefused))
            }
            Some(AddrBehavior::Timeout) => futures::future::pending().await,
            None => Err(err(ErrorKind::ConnectionRefused)),
        }
    }

    /// Register a listener at `addr` and return the ConnReceiver
    /// that it should use for connections.
    ///
    /// If tls_cert is provided, then the listener is a TLS listener
    /// and any only TLS connection attempts should succeed.
    ///
    /// Returns an error if the address is already in use.
    fn add_listener(&self, addr: SocketAddr, tls_cert: Option<Vec<u8>>) -> IoResult<ConnReceiver> {
        let mut listener_map = self.listening.lock().expect("Poisoned lock for listener");
        if listener_map.contains_key(&addr) {
            // TODO: Maybe this should ignore dangling Weak references?
            return Err(err(ErrorKind::AddrInUse));
        }

        let (send, recv) = mpsc_channel(16);

        let entry = ListenerEntry { send, tls_cert };

        listener_map.insert(addr, AddrBehavior::Listener(entry));

        Ok(recv)
    }
}

impl ProviderBuilder {
    /// Add `addr` as a new address for the provider we're building.
    pub fn add_address(&mut self, addr: IpAddr) -> &mut Self {
        self.addrs.push(addr);
        self
    }
    /// Use this builder to return a new [`MockNetRuntime`] wrapping
    /// an existing `runtime`.
    pub fn runtime<R: Runtime>(&self, runtime: R) -> super::MockNetRuntime<R> {
        MockNetRuntime::new(runtime, self.provider())
    }
    /// Use this builder to return a new [`MockNetProvider`]
    pub fn provider(&self) -> MockNetProvider {
        let inner = MockNetProviderInner {
            addrs: self.addrs.clone(),
            net: Arc::clone(&self.net),
            next_port: AtomicU16::new(1),
        };
        MockNetProvider {
            inner: Arc::new(inner),
        }
    }
}

impl NetStreamListener for MockNetListener {
    type Stream = LocalStream;

    type Incoming = Self;

    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(self.addr)
    }

    fn incoming(self) -> Self {
        self
    }
}

impl Stream for MockNetListener {
    type Item = IoResult<(LocalStream, SocketAddr)>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut recv = futures::ready!(self.receiver.lock().poll_unpin(cx));
        match recv.poll_next_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(v)) => Poll::Ready(Some(Ok(v))),
        }
    }
}

/// A very poor imitation of a UDP socket
#[derive(Debug)]
#[non_exhaustive]
pub struct MockUdpSocket {
    /// This is uninhabited.
    ///
    /// To implement UDP support, implement `.bind()`, and abolish this field,
    /// replacing it with the actual implementation.
    void: Void,
}

#[async_trait]
impl UdpProvider for MockNetProvider {
    type UdpSocket = MockUdpSocket;

    async fn bind(&self, addr: &SocketAddr) -> IoResult<MockUdpSocket> {
        let _ = addr; // MockNetProvider UDP is not implemented
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[allow(clippy::diverging_sub_expression)] // void::unimplemented + async_trait
#[async_trait]
impl UdpSocket for MockUdpSocket {
    async fn recv(&self, buf: &mut [u8]) -> IoResult<(usize, SocketAddr)> {
        // This tuple idiom avoids unused variable warnings.
        // An alternative would be to write _buf, but then when this is implemented,
        // and the void::unreachable call removed, we actually *want* those warnings.
        void::unreachable((self.void, buf).0)
    }
    async fn send(&self, buf: &[u8], target: &SocketAddr) -> IoResult<usize> {
        void::unreachable((self.void, buf, target).0)
    }
    fn local_addr(&self) -> IoResult<SocketAddr> {
        void::unreachable(self.void)
    }
}

impl MockNetProvider {
    /// If we have a local addresses that is in the same family as `other`,
    /// return it.
    fn get_addr_in_family(&self, other: &IpAddr) -> Option<IpAddr> {
        self.inner
            .addrs
            .iter()
            .find(|a| a.is_ipv4() == other.is_ipv4())
            .copied()
    }

    /// Return an arbitrary port number that we haven't returned from
    /// this function before.
    ///
    /// # Panics
    ///
    /// Panics if there are no remaining ports that this function hasn't
    /// returned before.
    fn arbitrary_port(&self) -> u16 {
        let next = self.inner.next_port.fetch_add(1, Ordering::Relaxed);
        assert!(next != 0);
        next
    }

    /// Helper for connecting: Picks the socketaddr to use
    /// when told to connect to `addr`.
    ///
    /// The IP is one of our own IPs with the same family as `addr`.
    /// The port is a port that we haven't used as an arbitrary port
    /// before.
    fn get_origin_addr_for(&self, addr: &SocketAddr) -> IoResult<SocketAddr> {
        let my_addr = self
            .get_addr_in_family(&addr.ip())
            .ok_or_else(|| err(ErrorKind::AddrNotAvailable))?;
        Ok(SocketAddr::new(my_addr, self.arbitrary_port()))
    }

    /// Helper for binding a listener: Picks the socketaddr to use
    /// when told to bind to `addr`.
    ///
    /// If addr is `0.0.0.0` or `[::]`, then we pick one of our own
    /// addresses with the same family. Otherwise we fail unless `addr` is
    /// one of our own addresses.
    ///
    /// If port is 0, we pick a new arbitrary port we haven't used as
    /// an arbitrary port before.
    fn get_listener_addr(&self, spec: &SocketAddr) -> IoResult<SocketAddr> {
        let ipaddr = {
            let ip = spec.ip();
            if ip.is_unspecified() {
                self.get_addr_in_family(&ip)
                    .ok_or_else(|| err(ErrorKind::AddrNotAvailable))?
            } else if self.inner.addrs.iter().any(|a| a == &ip) {
                ip
            } else {
                return Err(err(ErrorKind::AddrNotAvailable));
            }
        };
        let port = {
            if spec.port() == 0 {
                self.arbitrary_port()
            } else {
                spec.port()
            }
        };

        Ok(SocketAddr::new(ipaddr, port))
    }

    /// Create a mock TLS listener with provided certificate.
    ///
    /// Note that no encryption or authentication is actually
    /// performed!  Other parties are simply told that their connections
    /// succeeded and were authenticated against the given certificate.
    pub fn listen_tls(&self, addr: &SocketAddr, tls_cert: Vec<u8>) -> IoResult<MockNetListener> {
        let addr = self.get_listener_addr(addr)?;

        let receiver = AsyncMutex::new(self.inner.net.add_listener(addr, Some(tls_cert))?);

        Ok(MockNetListener { addr, receiver })
    }
}

#[async_trait]
impl NetStreamProvider for MockNetProvider {
    type Stream = LocalStream;
    type Listener = MockNetListener;

    async fn connect(&self, addr: &SocketAddr) -> IoResult<LocalStream> {
        let my_addr = self.get_origin_addr_for(addr)?;
        let (mut mine, theirs) = stream_pair();

        let cert = self
            .inner
            .net
            .send_connection(my_addr, *addr, theirs)
            .await?;

        mine.tls_cert = cert;

        Ok(mine)
    }

    async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::Listener> {
        let addr = self.get_listener_addr(addr)?;

        let receiver = AsyncMutex::new(self.inner.net.add_listener(addr, None)?);

        Ok(MockNetListener { addr, receiver })
    }
}

#[async_trait]
impl TlsProvider<LocalStream> for MockNetProvider {
    type Connector = MockTlsConnector;
    type TlsStream = MockTlsStream;

    fn tls_connector(&self) -> MockTlsConnector {
        MockTlsConnector {}
    }

    fn supports_keying_material_export(&self) -> bool {
        false
    }
}

/// Mock TLS connector for use with MockNetProvider.
///
/// Note that no TLS is actually performed here: connections are simply
/// told that they succeeded with a given certificate.
#[derive(Clone)]
#[non_exhaustive]
pub struct MockTlsConnector;

/// Mock TLS connector for use with MockNetProvider.
///
/// Note that no TLS is actually performed here: connections are simply
/// told that they succeeded with a given certificate.
///
/// Note also that we only use this type for client-side connections
/// right now: Arti doesn't support being a real TLS Listener yet,
/// since we only handle Tor client operations.
pub struct MockTlsStream {
    /// The peer certificate that we are pretending our peer has.
    peer_cert: Option<Vec<u8>>,
    /// The underlying stream.
    stream: LocalStream,
}

#[async_trait]
impl TlsConnector<LocalStream> for MockTlsConnector {
    type Conn = MockTlsStream;

    async fn negotiate_unvalidated(
        &self,
        mut stream: LocalStream,
        _sni_hostname: &str,
    ) -> IoResult<MockTlsStream> {
        let peer_cert = stream.tls_cert.take();

        if peer_cert.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "attempted to wrap non-TLS stream!",
            ));
        }

        Ok(MockTlsStream { peer_cert, stream })
    }
}

impl CertifiedConn for MockTlsStream {
    fn peer_certificate(&self) -> IoResult<Option<Vec<u8>>> {
        Ok(self.peer_cert.clone())
    }
    fn export_keying_material(
        &self,
        _len: usize,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> IoResult<Vec<u8>> {
        Ok(Vec::new())
    }
}

impl AsyncRead for MockTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for MockTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.stream).poll_close(cx)
    }
}

impl StreamOps for MockTlsStream {
    fn set_tcp_notsent_lowat(&self, _notsent_lowat: u32) -> IoResult<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "not supported on non-StreamOps stream!",
        ))
    }

    fn new_handle(&self) -> Box<dyn StreamOps + Send + Unpin> {
        Box::new(tor_rtcompat::UnsupportedStreamOpsHandle::default())
    }
}

/// Inner error type returned when a `MockNetwork` operation fails.
#[derive(Clone, Error, Debug)]
#[non_exhaustive]
pub enum MockNetError {
    /// General-purpose error.  The real information is in `ErrorKind`.
    #[error("Invalid operation on mock network")]
    BadOp,
}

/// Wrap `k` in a new [`std::io::Error`].
fn err(k: ErrorKind) -> IoError {
    IoError::new(k, MockNetError::BadOp)
}

#[cfg(all(test, not(miri)))] // miri cannot simulate the networking
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
    use futures::io::{AsyncReadExt, AsyncWriteExt};
    use tor_rtcompat::test_with_all_runtimes;

    fn client_pair() -> (MockNetProvider, MockNetProvider) {
        let net = MockNetwork::new();
        let client1 = net
            .builder()
            .add_address("192.0.2.55".parse().unwrap())
            .provider();
        let client2 = net
            .builder()
            .add_address("198.51.100.7".parse().unwrap())
            .provider();

        (client1, client2)
    }

    #[test]
    fn end_to_end() {
        test_with_all_runtimes!(|_rt| async {
            let (client1, client2) = client_pair();
            let lis = client2.listen(&"0.0.0.0:99".parse().unwrap()).await?;
            let address = lis.local_addr()?;

            let (r1, r2): (IoResult<()>, IoResult<()>) = futures::join!(
                async {
                    let mut conn = client1.connect(&address).await?;
                    conn.write_all(b"This is totally a network.").await?;
                    conn.close().await?;

                    // Nobody listening here...
                    let a2 = "192.0.2.200:99".parse().unwrap();
                    let cant_connect = client1.connect(&a2).await;
                    assert!(cant_connect.is_err());
                    Ok(())
                },
                async {
                    let (mut conn, a) = lis.incoming().next().await.expect("closed?")?;
                    assert_eq!(a.ip(), "192.0.2.55".parse::<IpAddr>().unwrap());
                    let mut inp = Vec::new();
                    conn.read_to_end(&mut inp).await?;
                    assert_eq!(&inp[..], &b"This is totally a network."[..]);
                    Ok(())
                }
            );
            r1?;
            r2?;
            IoResult::Ok(())
        });
    }

    #[test]
    fn pick_listener_addr() -> IoResult<()> {
        let net = MockNetwork::new();
        let ip4 = "192.0.2.55".parse().unwrap();
        let ip6 = "2001:db8::7".parse().unwrap();
        let client = net.builder().add_address(ip4).add_address(ip6).provider();

        // Successful cases
        let a1 = client.get_listener_addr(&"0.0.0.0:99".parse().unwrap())?;
        assert_eq!(a1.ip(), ip4);
        assert_eq!(a1.port(), 99);
        let a2 = client.get_listener_addr(&"192.0.2.55:100".parse().unwrap())?;
        assert_eq!(a2.ip(), ip4);
        assert_eq!(a2.port(), 100);
        let a3 = client.get_listener_addr(&"192.0.2.55:0".parse().unwrap())?;
        assert_eq!(a3.ip(), ip4);
        assert!(a3.port() != 0);
        let a4 = client.get_listener_addr(&"0.0.0.0:0".parse().unwrap())?;
        assert_eq!(a4.ip(), ip4);
        assert!(a4.port() != 0);
        assert!(a4.port() != a3.port());
        let a5 = client.get_listener_addr(&"[::]:99".parse().unwrap())?;
        assert_eq!(a5.ip(), ip6);
        assert_eq!(a5.port(), 99);
        let a6 = client.get_listener_addr(&"[2001:db8::7]:100".parse().unwrap())?;
        assert_eq!(a6.ip(), ip6);
        assert_eq!(a6.port(), 100);

        // Failing cases
        let e1 = client.get_listener_addr(&"192.0.2.56:0".parse().unwrap());
        let e2 = client.get_listener_addr(&"[2001:db8::8]:0".parse().unwrap());
        assert!(e1.is_err());
        assert!(e2.is_err());

        IoResult::Ok(())
    }

    #[test]
    fn listener_stream() {
        test_with_all_runtimes!(|_rt| async {
            let (client1, client2) = client_pair();

            let lis = client2.listen(&"0.0.0.0:99".parse().unwrap()).await?;
            let address = lis.local_addr()?;
            let mut incoming = lis.incoming();

            let (r1, r2): (IoResult<()>, IoResult<()>) = futures::join!(
                async {
                    for _ in 0..3_u8 {
                        let mut c = client1.connect(&address).await?;
                        c.close().await?;
                    }
                    Ok(())
                },
                async {
                    for _ in 0..3_u8 {
                        let (mut c, a) = incoming.next().await.unwrap()?;
                        let mut v = Vec::new();
                        let _ = c.read_to_end(&mut v).await?;
                        assert_eq!(a.ip(), "192.0.2.55".parse::<IpAddr>().unwrap());
                    }
                    Ok(())
                }
            );
            r1?;
            r2?;
            IoResult::Ok(())
        });
    }

    #[test]
    fn tls_basics() {
        let (client1, client2) = client_pair();
        let cert = b"I am certified for something I assure you.";

        test_with_all_runtimes!(|_rt| async {
            let lis = client2
                .listen_tls(&"0.0.0.0:0".parse().unwrap(), cert[..].into())
                .unwrap();
            let address = lis.local_addr().unwrap();

            let (r1, r2): (IoResult<()>, IoResult<()>) = futures::join!(
                async {
                    let connector = client1.tls_connector();
                    let conn = client1.connect(&address).await?;
                    let mut conn = connector
                        .negotiate_unvalidated(conn, "zombo.example.com")
                        .await?;
                    assert_eq!(&conn.peer_certificate()?.unwrap()[..], &cert[..]);
                    conn.write_all(b"This is totally encrypted.").await?;
                    let mut v = Vec::new();
                    conn.read_to_end(&mut v).await?;
                    conn.close().await?;
                    assert_eq!(v[..], b"Yup, your secrets is safe"[..]);
                    Ok(())
                },
                async {
                    let (mut conn, a) = lis.incoming().next().await.expect("closed?")?;
                    assert_eq!(a.ip(), "192.0.2.55".parse::<IpAddr>().unwrap());
                    let mut inp = [0_u8; 26];
                    conn.read_exact(&mut inp[..]).await?;
                    assert_eq!(&inp[..], &b"This is totally encrypted."[..]);
                    conn.write_all(b"Yup, your secrets is safe").await?;
                    Ok(())
                }
            );
            r1?;
            r2?;
            IoResult::Ok(())
        });
    }
}
