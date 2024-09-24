//! Implement a NetStreamProvider that can break things.
#![allow(clippy::missing_docs_in_private_items)] // required for pin_project(enum)

use futures::Stream;
use tor_rtcompat::{NetStreamListener, NetStreamProvider, SleepProvider};

use anyhow::anyhow;
use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};
use pin_project::pin_project;
use rand::thread_rng;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tor_basic_utils::RngExt as _;

/// An action that we can take upon trying to make a TCP connection.
#[derive(Debug, Copy, Clone)]
pub(crate) enum Action {
    /// Let the connection work as intended.
    Work,
    /// Wait for a random interval up to the given duration, then return an error.
    Fail(Duration, IoErrorKind),
    /// Time out indefinitely.
    Timeout,
    /// Succeed, then drop all data.
    Blackhole,
}

/// When should an Action apply?
#[derive(Debug, Clone)]
pub(crate) enum ActionPat {
    /// always apply
    Always,
    /// Apply to all ipv4
    V4,
    /// apply to all ipv6
    V6,
    /// apply to all ports but 443
    Non443,
}

/// An Action plus a set of conditions when it applies.
///
/// (When the action doesn't apply, connections will just `Action::Work`.
#[derive(Debug, Clone)]
pub(crate) struct ConditionalAction {
    /// The underlying action
    pub(crate) action: Action,

    /// When should the action apply?
    pub(crate) when: ActionPat,
}

impl FromStr for Action {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "none" | "work" => Action::Work,
            "error" => Action::Fail(Duration::from_millis(10), IoErrorKind::Other),
            "timeout" => Action::Timeout,
            "blackhole" => Action::Blackhole,
            _ => return Err(anyhow!("unrecognized tcp breakage action {:?}", s)),
        })
    }
}

impl FromStr for ActionPat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "all" => ActionPat::Always,
            "v4" => ActionPat::V4,
            "v6" => ActionPat::V6,
            "non443" => ActionPat::Non443,
            _ => return Err(anyhow!("unrecognized tcp breakage condition {:?}", s)),
        })
    }
}

impl ConditionalAction {
    fn applies_to(&self, addr: &SocketAddr) -> bool {
        match (addr, &self.when) {
            (_, ActionPat::Always) => true,
            (SocketAddr::V4(_), ActionPat::V4) => true,
            (SocketAddr::V6(_), ActionPat::V6) => true,
            (sa, ActionPat::Non443) if sa.port() != 443 => true,
            (_, _) => false,
        }
    }
}

impl Default for ConditionalAction {
    fn default() -> Self {
        Self {
            action: Action::Work,
            when: ActionPat::Always,
        }
    }
}

/// A NetStreamProvider that can make its connections fail.
#[pin_project]
#[derive(Debug, Clone)]
pub(crate) struct BrokenTcpProvider<R> {
    /// An underlying NetStreamProvider to use when we actually want our connections to succeed
    #[pin]
    inner: R,
    /// The action to take when we try to make an outbound connection.
    action: Arc<Mutex<ConditionalAction>>,
}

impl<R> BrokenTcpProvider<R> {
    /// Construct a new BrokenTcpProvider which responds to all outbound
    /// connections by taking the specified action.
    pub(crate) fn new(inner: R, action: ConditionalAction) -> Self {
        Self {
            inner,
            action: Arc::new(Mutex::new(action)),
        }
    }

    /// Cause the provider to respond to all outbound connection attempts
    /// with the specified action.
    pub(crate) fn set_action(&self, action: ConditionalAction) {
        *self.action.lock().expect("Lock poisoned") = action;
    }

    /// Return the action to take for a connection to `addr`.
    fn get_action(&self, addr: &SocketAddr) -> Action {
        let action = self.action.lock().expect("Lock poisoned");
        if action.applies_to(addr) {
            action.action
        } else {
            Action::Work
        }
    }
}

#[async_trait]
impl<R: NetStreamProvider + SleepProvider> NetStreamProvider for BrokenTcpProvider<R> {
    type Stream = BreakableTcpStream<R::Stream>;
    type Listener = BrokenTcpProvider<R::Listener>;

    async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::Stream> {
        match self.get_action(addr) {
            Action::Work => {
                let conn = self.inner.connect(addr).await?;
                Ok(BreakableTcpStream::Present(conn))
            }
            Action::Fail(dur, kind) => {
                let d = thread_rng().gen_range_infallible(..=dur);
                self.inner.sleep(d).await;
                Err(IoError::new(kind, anyhow::anyhow!("intentional failure")))
            }
            Action::Timeout => futures::future::pending().await,
            Action::Blackhole => Ok(BreakableTcpStream::Broken),
        }
    }

    async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::Listener> {
        let listener = self.inner.listen(addr).await?;
        Ok(BrokenTcpProvider {
            inner: listener,
            action: self.action.clone(),
        })
    }
}

/// A TCP stream that is either present, or black-holed.
#[pin_project(project = BreakableTcpStreamP)]
#[derive(Debug, Clone)]
pub(crate) enum BreakableTcpStream<S> {
    /// The stream is black-holed: there is nothing to read, and all writes
    /// succeed but are ignored.
    Broken,

    /// The stream is present and should work normally.
    Present(#[pin] S),
}

impl<S: AsyncRead> AsyncRead for BreakableTcpStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let this = self.project();
        match this {
            BreakableTcpStreamP::Present(s) => s.poll_read(cx, buf),
            BreakableTcpStreamP::Broken => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite> AsyncWrite for BreakableTcpStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        match self.project() {
            BreakableTcpStreamP::Present(s) => s.poll_write(cx, buf),
            BreakableTcpStreamP::Broken => Poll::Ready(Ok(buf.len())),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        match self.project() {
            BreakableTcpStreamP::Present(s) => s.poll_flush(cx),
            BreakableTcpStreamP::Broken => Poll::Ready(Ok(())),
        }
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        match self.project() {
            BreakableTcpStreamP::Present(s) => s.poll_close(cx),
            BreakableTcpStreamP::Broken => Poll::Ready(Ok(())),
        }
    }
}

impl<S: NetStreamListener + Send + Sync> NetStreamListener for BrokenTcpProvider<S> {
    type Stream = BreakableTcpStream<S::Stream>;
    type Incoming = BrokenTcpProvider<S::Incoming>;

    fn incoming(self) -> Self::Incoming {
        BrokenTcpProvider {
            inner: self.inner.incoming(),
            action: self.action,
        }
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.inner.local_addr()
    }
}
impl<S, T> Stream for BrokenTcpProvider<S>
where
    S: Stream<Item = IoResult<(T, SocketAddr)>>,
{
    type Item = IoResult<(BreakableTcpStream<T>, SocketAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.project().inner.poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Some(Ok((s, a)))) => {
                Poll::Ready(Some(Ok((BreakableTcpStream::Present(s), a))))
            }
        }
    }
}
