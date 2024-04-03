//! Declare MockNetRuntime.

// TODO(nickm): This is mostly copy-paste from MockSleepRuntime.  If possible,
// we should make it so that more code is more shared.

use crate::util::impl_runtime_prelude::*;

use crate::net::MockNetProvider;

/// A wrapper Runtime that overrides the SleepProvider trait for the
/// underlying runtime.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(SomeMockRuntime)]
pub struct MockNetRuntime<R: Runtime> {
    /// The underlying runtime. Most calls get delegated here.
    #[deftly(mock(task, sleep))]
    runtime: R,
    /// A MockNetProvider.  Network-related calls get delegated here.
    #[deftly(mock(net))]
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
