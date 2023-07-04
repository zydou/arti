//! Declare MockNetRuntime.

// TODO(nickm): This is mostly copy-paste from MockSleepRuntime.  If possible,
// we should make it so that more code is more shared.

use crate::net::MockNetProvider;
use tor_rtcompat::{BlockOn, Runtime, SleepProvider, TcpProvider, TlsProvider, UdpProvider};

use async_trait::async_trait;
use futures::task::{FutureObj, Spawn, SpawnError};
use futures::Future;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

/// A wrapper Runtime that overrides the SleepProvider trait for the
/// underlying runtime.
#[derive(Clone, Debug)]
pub struct MockNetRuntime<R: Runtime> {
    /// The underlying runtime. Most calls get delegated here.
    runtime: R,
    /// A MockNetProvider.  Network-related calls get delegated here.
    net: MockNetProvider,
}

impl<R: Runtime> MockNetRuntime<R> {
    /// Create a new runtime that wraps `runtime`, but overrides
    /// its view of the network with a [`MockNetProvider`], `net`.
    pub fn new(runtime: R, net: MockNetProvider) -> Self {
        MockNetRuntime { runtime, net }
    }

    /// Return a reference to the underlying runtime.
    pub fn inner(&self) -> &R {
        &self.runtime
    }

    /// Return a reference to the [`MockNetProvider`]
    pub fn mock_net(&self) -> &MockNetProvider {
        &self.net
    }
}

impl_runtime! {
    [ <R: Runtime> ] MockNetRuntime<R>,
    spawn: runtime,
    block: runtime,
    sleep: runtime: R,
    net: net: MockNetProvider,
    udp: runtime: R, // TODO this should probably get delegated to $NetProvider instead
}
