use std::future::Future;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use arti_client::{TorClient, TorClientConfig};
use tokio_crate as tokio;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;

use futures::{AsyncRead, AsyncWrite, FutureExt, Stream};
use tor_rtcompat::tls::NativeTlsProvider;
use tor_rtcompat::{CompoundRuntime, TcpListener, TcpProvider};

use futures::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = TorClientConfig::default();
    let rt = TokioNativeTlsRuntime::current()?;
    let tcp_rt = CustomTcpProvider { inner: rt.clone() };
    let rt = CompoundRuntime::new(rt.clone(), rt, tcp_rt, NativeTlsProvider::default());

    eprintln!("connecting to Tor...");
    let tor_client = TorClient::create_bootstrapped(rt, config).await?;

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

struct CustomTcpProvider<T> {
    inner: T,
}

struct CustomTcpStream<T> {
    inner: T,
    addr: SocketAddr,
}

struct CustomTcpListener<T> {
    inner: T,
}

struct CustomIncoming<T> {
    inner: T,
}

impl<T> TcpProvider for CustomTcpProvider<T>
where
    T: TcpProvider,
{
    type TcpStream = CustomTcpStream<T::TcpStream>;
    type TcpListener = CustomTcpListener<T::TcpListener>;

    // using a manual implementation is required to have Send+Sync when using reference to self
    fn connect<'life0, 'life1, 'async_trait>(
        &'life0 self,
        addr: &'life1 SocketAddr,
    ) -> Pin<Box<dyn Future<Output = IoResult<Self::TcpStream>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        println!("tcp connect to {}", addr);
        self.inner
            .connect(addr)
            .map(move |r| {
                r.map(|stream| CustomTcpStream {
                    inner: stream,
                    addr: *addr,
                })
            })
            .boxed()
    }

    fn listen<'life0, 'life1, 'async_trait>(
        &'life0 self,
        addr: &'life1 SocketAddr,
    ) -> Pin<Box<dyn Future<Output = IoResult<Self::TcpListener>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        println!("tcp listen on {}", addr);
        self.inner
            .listen(addr)
            .map(|l| l.map(|listener| CustomTcpListener { inner: listener }))
            .boxed()
    }
}

impl<T> AsyncRead for CustomTcpStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.inner).poll_read_vectored(cx, bufs)
    }
}

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
            println!("closed a connecion to {}", self.addr);
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

type AcceptResult<T> = IoResult<(T, SocketAddr)>;

impl<T> TcpListener for CustomTcpListener<T>
where
    T: TcpListener,
{
    type TcpStream = CustomTcpStream<T::TcpStream>;
    type Incoming = CustomIncoming<T::Incoming>;

    fn accept<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<Box<dyn Future<Output = AcceptResult<Self::TcpStream>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.inner
            .accept()
            .inspect(|r| {
                if let Ok((_, addr)) = r {
                    println!("accepted connection from {}", addr)
                }
            })
            .map(|r| {
                r.map(|(stream, addr)| {
                    (
                        CustomTcpStream {
                            inner: stream,
                            addr,
                        },
                        addr,
                    )
                })
            })
            .boxed()
    }

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
    T: Stream<Item = IoResult<(S, SocketAddr)>> + std::marker::Unpin,
{
    type Item = IoResult<(CustomTcpStream<S>, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok((stream, addr)))) => Poll::Ready(Some(Ok((
                CustomTcpStream {
                    inner: stream,
                    addr,
                },
                addr,
            )))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
