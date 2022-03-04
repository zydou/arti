//! Implement a tcpProvider that can break things.

use tor_rtcompat::{Runtime, TcpProvider};

use async_trait::async_trait;
use rand::{thread_rng, Rng};
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::net::SocketAddr;
use std::time::Duration;

/// An action that we can take upon trying to make a TCP connection.
#[derive(Debug, Clone)]
pub(crate) enum Action {
    /// Let the connection work as intended.
    Work,
    /// Wait for a random interval up to the given duration, then return an error.
    Fail(Duration, IoErrorKind),
    /// Time out indefinitely.
    Timeout,
}

/// A TcpProvider that can make its connections fail.
#[derive(Debug, Clone)]
pub(crate) struct BrokenTcpProvider<R> {
    /// An underlying TcpProvider to use when we actually want our connections to succeed
    inner: R,
    /// The action to take when we try to make an outbound connection.
    ///
    /// TODO: make this conditional, mutable, etc.
    action: Action,
}

impl<R> BrokenTcpProvider<R> {
    /// Construct a new BrokenTcpProvider which responds to all outbound
    /// connections by taking the specified action.
    pub(crate) fn new(inner: R, action: Action) -> Self {
        Self { inner, action }
    }

    /// Return the action to take for a connection to `addr`.
    fn get_action(&self, _addr: &SocketAddr) -> Action {
        self.action.clone()
    }
}

#[async_trait]
impl<R: Runtime> TcpProvider for BrokenTcpProvider<R> {
    type TcpStream = R::TcpStream;
    type TcpListener = R::TcpListener;

    async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::TcpStream> {
        match self.get_action(addr) {
            Action::Work => self.inner.connect(addr).await,
            Action::Fail(dur, kind) => {
                let d = thread_rng().gen_range(Duration::from_secs(0)..dur);
                self.inner.sleep(d).await;
                Err(IoError::new(kind, anyhow::anyhow!("intentional failure")))
            }
            Action::Timeout => futures::future::pending().await,
        }
    }

    async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::TcpListener> {
        self.inner.listen(addr).await
    }
}
