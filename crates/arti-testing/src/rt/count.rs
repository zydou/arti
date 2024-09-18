//! Support for counting various TCP stats for a Runtime.

use futures::Stream;
use tor_rtcompat::{TcpListener, TcpProvider};

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};
use pin_project::pin_project;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// Object that holds underlying counts for a Runtime.
#[derive(Debug, Clone, Default)]
pub(crate) struct TcpCount {
    /// number of TCP connections we've launched
    pub(crate) n_connect_attempt: usize,
    /// number of TCP connections we've successfully completed
    pub(crate) n_connect_ok: usize,
    /// number of incoming TCP connections we've received
    pub(crate) n_accept: usize,
    /// total number of bytes we've sent
    pub(crate) n_bytes_send: usize,
    /// total number of bytes we've received
    pub(crate) n_bytes_recv: usize,
}

/// A "Counting" wrapper around various objects, keeping running counts of TCP
/// events.
///
/// This can wrap most Tcp-related Runtime types.
#[pin_project]
pub(crate) struct Counting<R> {
    /// The inner object that we're instrumenting
    #[pin]
    inner: R,
    /// A shared mutable set of counts.
    count: Arc<Mutex<TcpCount>>,
}

impl<R> Clone for Counting<R>
where
    R: Clone,
{
    fn clone(&self) -> Self {
        // TODO: Use educe instead.
        Self {
            inner: self.inner.clone(),
            count: self.count.clone(),
        }
    }
}

impl<R> Counting<R> {
    /// Return a new wrapper around a TcpProvider with a new set of statistics
    pub(crate) fn new_zeroed(inner: R) -> Self
    where
        R: TcpProvider,
    {
        Self {
            inner,
            count: Default::default(),
        }
    }

    /// Return a copy of our current statistics
    pub(crate) fn counts(&self) -> TcpCount {
        self.count.lock().expect("lock poisoned").clone()
    }
}

#[async_trait]
impl<R: TcpProvider + Send + Sync> TcpProvider for Counting<R> {
    type TcpStream = Counting<R::TcpStream>;

    type TcpListener = Counting<R::TcpListener>;

    async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::TcpStream> {
        {
            self.count.lock().expect("lock poisoned").n_connect_attempt += 1;
        }

        let inner = self.inner.connect(addr).await?;

        {
            self.count.lock().expect("lock poisoned").n_connect_ok += 1;
        }

        Ok(Counting {
            inner,
            count: self.count.clone(),
        })
    }

    async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::TcpListener> {
        let inner = self.inner.listen(addr).await?;
        Ok(Counting {
            inner,
            count: self.count.clone(),
        })
    }
}

impl<S: AsyncRead> AsyncRead for Counting<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let this = self.project();
        let outcome = this.inner.poll_read(cx, buf);

        if let Poll::Ready(Ok(n)) = outcome {
            this.count.lock().expect("poisoned lock").n_bytes_recv += n;
        }
        outcome
    }
}

impl<S: AsyncWrite> AsyncWrite for Counting<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let this = self.project();
        let outcome = this.inner.poll_write(cx, buf);

        if let Poll::Ready(Ok(n)) = outcome {
            this.count.lock().expect("poisoned lock").n_bytes_send += n;
        }
        outcome
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().inner.poll_flush(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().inner.poll_close(cx)
    }
}

#[async_trait]
impl<S: TcpListener + Send + Sync> TcpListener for Counting<S> {
    type TcpStream = Counting<S::TcpStream>;
    type Incoming = Counting<S::Incoming>;

    fn incoming(self) -> Self::Incoming {
        Counting {
            inner: self.inner.incoming(),
            count: self.count,
        }
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.inner.local_addr()
    }
}

impl<S, T> Stream for Counting<S>
where
    S: Stream<Item = IoResult<(T, SocketAddr)>>,
{
    type Item = IoResult<(Counting<T>, SocketAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        let outcome = this.inner.poll_next(cx);

        match outcome {
            Poll::Ready(Some(Ok((inner, addr)))) => {
                {
                    this.count.lock().expect("lock poisoned").n_accept += 1;
                }
                Poll::Ready(Some(Ok((
                    Counting {
                        inner,
                        count: this.count.clone(),
                    },
                    addr,
                ))))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
