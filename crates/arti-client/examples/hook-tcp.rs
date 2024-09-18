// @@ begin example lint list maintained by maint/add_warning @@
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
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
//! <!-- @@ end example lint list maintained by maint/add_warning @@ -->

//! This example showcases using a custom [`TcpProvider`] to do custom actions before Arti initiates
//! TCP connections, and after the connections are closed.
//!
//! This might be useful, for example, to dynamically open ports on a restrictive firewall or modify
//! routing information. It would also be possible to adapt the example to make it proxy the TCP
//! connections somehow, depending on your usecase.

use std::future::Future;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use arti_client::{TorClient, TorClientConfig};
use tokio_crate as tokio;

use futures::{AsyncRead, AsyncWrite, FutureExt, Stream};
use tor_rtcompat::{PreferredRuntime, RuntimeSubstExt as _, TcpListener, TcpProvider};

use futures::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = TorClientConfig::default();
    // Get the current preferred runtime.
    let rt = PreferredRuntime::current()?;
    // Instantiate our custom TCP provider (see implementation below).
    let tcp_rt = CustomTcpProvider { inner: rt.clone() };
    // Create a `CompoundRuntime`, swapping out the TCP part of the preferred runtime for our custom one.
    let rt = rt.with_tcp_provider(tcp_rt);

    eprintln!("connecting to Tor...");
    // Pass in our custom runtime using `with_runtime`.
    let tor_client = TorClient::with_runtime(rt)
        .config(config)
        .create_bootstrapped()
        .await?;

    eprintln!("connecting to example.com...");
    let mut stream = tor_client.connect(("example.com", 80)).await?;

    eprintln!("sending request...");

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;

    stream.flush().await?;

    eprintln!("reading response...");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    println!("{}", String::from_utf8_lossy(&buf));

    Ok(())
}

/// A custom TCP provider that relies on an existing TCP provider (`inner`), but modifies its
/// behavior.
#[derive(Clone)]
struct CustomTcpProvider<T> {
    /// The underlying TCP provider.
    inner: T,
}

/// A custom TCP stream that wraps another TCP provider's TCP stream type, letting us do things
/// when the stream is read from, written to, or closed.
struct CustomTcpStream<T> {
    /// The underlying TCP stream.
    inner: T,
    /// The address of the remote peer at the other end of this stream.
    addr: SocketAddr,
    /// The current state of the socket: whether it is open, in the process of closing, or closed.
    state: TcpState,
}

/// An enum representing states a TCP stream can be in.
#[derive(PartialEq, Eq)]
enum TcpState {
    /// Stream is open.
    Open,
    /// We've sent a close, but haven't received one.
    SendClosed,
    /// We've received a close, but haven't sent one.
    RecvClosed,
    /// Stream is fully closed.
    Closed,
}

/// A wrapper over a `TcpListener`.
struct CustomTcpListener<T> {
    inner: T,
}

/// An `Incoming` type for our `CustomTcpListener`.
struct CustomIncoming<T> {
    inner: T,
}

impl<T> TcpProvider for CustomTcpProvider<T>
where
    T: TcpProvider,
{
    type TcpStream = CustomTcpStream<T::TcpStream>;
    type TcpListener = CustomTcpListener<T::TcpListener>;

    // This is an async trait method (using the `async_trait` crate). We manually implement it
    // here so that we don't borrow `self` for too long.
    // (The lifetimes are explicit and somewhat ugly because that's how `async_trait` works.)
    fn connect<'a, 'b, 'c>(
        &'a self,
        addr: &'b SocketAddr,
    ) -> Pin<Box<dyn Future<Output = IoResult<Self::TcpStream>> + Send + 'c>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        // Use the underlying TCP provider implementation to do the connection, and
        // return our wrapper around it once done.
        println!("tcp connect to {addr}");
        self.inner
            .connect(addr)
            .map(move |r| {
                r.map(|stream| CustomTcpStream {
                    inner: stream,
                    addr: *addr,
                    state: TcpState::Open,
                })
            })
            .boxed()
    }

    // This is also an async trait method (see above).
    fn listen<'a, 'b, 'c>(
        &'a self,
        addr: &'b SocketAddr,
    ) -> Pin<Box<dyn Future<Output = IoResult<Self::TcpListener>> + Send + 'c>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        // Use the underlying TCP provider implementation to make the listener, and
        // return our wrapper around it once done.
        println!("tcp listen on {addr}");
        self.inner
            .listen(addr)
            .map(|l| l.map(|listener| CustomTcpListener { inner: listener }))
            .boxed()
    }
}

// We implement `AsyncRead` and `AsyncWrite` for our custom TCP stream object.
// This implementation mostly uses the underlying stream's methods, but we insert some
// code to check for a zero-byte read (indicating stream closure), and callers closing the
// stream, and use that to update our `TcpState`.
// When we detect that the stream is closed, we run some code (in this case, just a `println!`).
impl<T> AsyncRead for CustomTcpStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        // Call the underlying stream's method.
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);

        // Check for a zero-byte read, indicating closure.
        if let Poll::Ready(Ok(0)) = res {
            // Ignore if buf is zero-length, reading 0 bytes doesn't mean eof in that case
            if !buf.is_empty() {
                match self.state {
                    // If we're already closed, do nothing.
                    TcpState::Closed | TcpState::RecvClosed => (),
                    // We're open, and haven't tried to close the stream yet, so note that
                    // the other side closed it.
                    TcpState::Open => self.state = TcpState::RecvClosed,
                    // We've closed the stream on our end, and the other side has now closed it
                    // too, so the stream is now fully closed.
                    TcpState::SendClosed => {
                        println!("closed a connection to {}", self.addr);
                        self.state = TcpState::Closed;
                    }
                }
            }
        }
        res
    }

    // Do the same thing, but for `poll_read_vectored`.
    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        let res = Pin::new(&mut self.inner).poll_read_vectored(cx, bufs);

        if let Poll::Ready(Ok(0)) = res {
            if bufs.iter().any(|buf| !buf.is_empty()) {
                match self.state {
                    TcpState::Closed | TcpState::RecvClosed => (),
                    TcpState::Open => self.state = TcpState::RecvClosed,
                    TcpState::SendClosed => {
                        println!("closed a connection to {}", self.addr);
                        self.state = TcpState::Closed;
                    }
                }
            }
        }
        res
    }
}

// The only thing that's custom here is checking for closure. Everything else is just calling
// `self.inner`.
impl<T> AsyncWrite for CustomTcpStream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let res = Pin::new(&mut self.inner).poll_close(cx);
        if res.is_ready() {
            match self.state {
                TcpState::Closed | TcpState::SendClosed => (),
                TcpState::Open => self.state = TcpState::SendClosed,
                TcpState::RecvClosed => {
                    println!("closed a connection to {}", self.addr);
                    self.state = TcpState::Closed;
                }
            }
        }
        res
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
}

impl<T> Drop for CustomTcpStream<T> {
    fn drop(&mut self) {
        if self.state != TcpState::Closed {
            println!("closed a connection to {}", self.addr);
        }
    }
}

impl<T> TcpListener for CustomTcpListener<T>
where
    T: TcpListener,
{
    type TcpStream = CustomTcpStream<T::TcpStream>;
    type Incoming = CustomIncoming<T::Incoming>;

    fn incoming(self) -> Self::Incoming {
        CustomIncoming {
            inner: self.inner.incoming(),
        }
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.inner.local_addr()
    }
}

impl<T, S> Stream for CustomIncoming<T>
where
    T: Stream<Item = IoResult<(S, SocketAddr)>> + Unpin,
{
    type Item = IoResult<(CustomTcpStream<S>, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok((stream, addr)))) => Poll::Ready(Some(Ok((
                CustomTcpStream {
                    inner: stream,
                    addr,
                    state: TcpState::Open,
                },
                addr,
            )))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
