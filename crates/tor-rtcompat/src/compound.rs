//! Define a [`CompoundRuntime`] part that can be built from several component
//! pieces.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::traits::*;
use async_trait::async_trait;
use futures::{future::FutureObj, task::Spawn};
use std::io::Result as IoResult;

/// A runtime made of several parts, each of which implements one trait-group.
///
/// The `SpawnR` component should implements [`Spawn`] and [`BlockOn`];
/// the `SleepR` component should implement [`SleepProvider`]; the `TcpR`
/// component should implement [`TcpProvider`]; and the `TlsR` component should
/// implement [`TlsProvider`].
///
/// You can use this structure to create new runtimes in two ways: either by
/// overriding a single part of an existing runtime, or by building an entirely
/// new runtime from pieces.
pub struct CompoundRuntime<SpawnR, SleepR, TcpR, TlsR> {
    /// The actual collection of Runtime objects.
    ///
    /// We wrap this in an Arc rather than requiring that each item implement
    /// Clone, though we could change our minds later on.
    inner: Arc<Inner<SpawnR, SleepR, TcpR, TlsR>>,
}

// We have to provide this ourselves, since derive(Clone) wrongly infers a
// `where S: Clone` bound (from the generic argument).
impl<SpawnR, SleepR, TcpR, TlsR> Clone for CompoundRuntime<SpawnR, SleepR, TcpR, TlsR> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// A collection of objects implementing that traits that make up a [`Runtime`]
struct Inner<SpawnR, SleepR, TcpR, TlsR> {
    /// A `Spawn` and `BlockOn` implementation.
    spawn: SpawnR,
    /// A `SleepProvider` implementation.
    sleep: SleepR,
    /// A `TcpProvider` implementation
    tcp: TcpR,
    /// A `TcpProvider<TcpR::TcpStream>` implementation.
    tls: TlsR,
}

impl<SpawnR, SleepR, TcpR, TlsR> CompoundRuntime<SpawnR, SleepR, TcpR, TlsR> {
    /// Construct a new CompoundRuntime from its components.
    pub fn new(spawn: SpawnR, sleep: SleepR, tcp: TcpR, tls: TlsR) -> Self {
        CompoundRuntime {
            inner: Arc::new(Inner {
                spawn,
                sleep,
                tcp,
                tls,
            }),
        }
    }
}

impl<SpawnR, SleepR, TcpR, TlsR> Spawn for CompoundRuntime<SpawnR, SleepR, TcpR, TlsR>
where
    SpawnR: Spawn,
{
    #[inline]
    fn spawn_obj(&self, future: FutureObj<'static, ()>) -> Result<(), futures::task::SpawnError> {
        self.inner.spawn.spawn_obj(future)
    }
}

impl<SpawnR, SleepR, TcpR, TlsR> BlockOn for CompoundRuntime<SpawnR, SleepR, TcpR, TlsR>
where
    SpawnR: BlockOn,
{
    #[inline]
    fn block_on<F: futures::Future>(&self, future: F) -> F::Output {
        self.inner.spawn.block_on(future)
    }
}

impl<SpawnR, SleepR, TcpR, TlsR> SleepProvider for CompoundRuntime<SpawnR, SleepR, TcpR, TlsR>
where
    SleepR: SleepProvider,
{
    type SleepFuture = SleepR::SleepFuture;

    #[inline]
    fn sleep(&self, duration: Duration) -> Self::SleepFuture {
        self.inner.sleep.sleep(duration)
    }
}

#[async_trait]
impl<SpawnR, SleepR, TcpR, TlsR> TcpProvider for CompoundRuntime<SpawnR, SleepR, TcpR, TlsR>
where
    TcpR: TcpProvider,
    SpawnR: Send + Sync + 'static,
    SleepR: Send + Sync + 'static,
    TcpR: Send + Sync + 'static,
    TlsR: Send + Sync + 'static,
{
    type TcpStream = TcpR::TcpStream;

    type TcpListener = TcpR::TcpListener;

    #[inline]
    async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::TcpStream> {
        self.inner.tcp.connect(addr).await
    }

    #[inline]
    async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::TcpListener> {
        self.inner.tcp.listen(addr).await
    }
}

impl<SpawnR, SleepR, TcpR, TlsR, S> TlsProvider<S> for CompoundRuntime<SpawnR, SleepR, TcpR, TlsR>
where
    TcpR: TcpProvider,
    TlsR: TlsProvider<S>,
{
    type Connector = TlsR::Connector;
    type TlsStream = TlsR::TlsStream;

    #[inline]
    fn tls_connector(&self) -> Self::Connector {
        self.inner.tls.tls_connector()
    }
}

impl<SpawnR, SleepR, TcpR, TlsR> std::fmt::Debug for CompoundRuntime<SpawnR, SleepR, TcpR, TlsR> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompoundRuntime").finish_non_exhaustive()
    }
}
