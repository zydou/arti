//! Types for conveniently constructing TorClients.

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use crate::{err::ErrorDetail, BootstrapBehavior, Result, TorClient, TorClientConfig};
use tor_rtcompat::Runtime;

/// An object for constructing a [`TorClient`].
///
/// Returned by [`TorClient::builder()`].
#[derive(Debug, Clone)]
#[must_use]
pub struct TorClientBuilder<R> {
    /// The runtime for the client to use
    runtime: R,
    /// The client's configuration.
    config: TorClientConfig,
    /// How the client should behave when it is asked to do something on the Tor
    /// network before `bootstrap()` is called.
    bootstrap_behavior: BootstrapBehavior,
}

impl<R> TorClientBuilder<R> {
    /// Construct a new TorClientBuilder with the given runtime.
    pub(crate) fn new(runtime: R) -> Self {
        Self {
            runtime,
            config: TorClientConfig::default(),
            bootstrap_behavior: BootstrapBehavior::default(),
        }
    }

    /// Set the configuration for the `TorClient` under construction.
    ///
    /// If not called, then a compiled-in default configuration will be used.
    pub fn config(mut self, config: TorClientConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the bootstrap behavior for the `TorClient` under construction.
    ///
    /// If not called, then the default ([`BootstrapBehavior::OnDemand`]) will
    /// be used.
    pub fn bootstrap_behavior(mut self, bootstrap_behavior: BootstrapBehavior) -> Self {
        self.bootstrap_behavior = bootstrap_behavior;
        self
    }
}

impl<R: Runtime> TorClientBuilder<R> {
    /// Create a `TorClient` from this builder, without automatically launching
    /// the bootstrap process.
    ///
    /// If you have left the default [`BootstrapBehavior`] in place, the client
    /// will bootstrap itself as soon any attempt is made to use it.  You can
    /// also bootstrap the client yourself by running its
    /// [`bootstrap()`](TorClient::bootstrap) method.
    ///
    /// If you have replaced the default behavior with [`BootstrapBehavior::Manual`],
    /// any attempts to use the client will fail with an error of kind
    /// [`ErrorKind::BootstrapRequired`](crate::ErrorKind::BootstrapRequired),
    /// until you have called [`TorClient::bootstrap`] yourself.  
    /// This option is useful if you wish to have control over the bootstrap
    /// process (for example, you might wish to avoid initiating network
    /// connections until explicit user confirmation is given).
    pub fn create_unbootstrapped(self) -> Result<TorClient<R>> {
        TorClient::create_inner(self.runtime, self.config, self.bootstrap_behavior)
            .map_err(ErrorDetail::into)
    }

    /// Create a TorClient from this builder, and try to bootstrap it.
    pub async fn create_bootstrapped(self) -> Result<TorClient<R>> {
        let r = self.create_unbootstrapped()?;
        r.bootstrap().await?;
        Ok(r)
    }
}
