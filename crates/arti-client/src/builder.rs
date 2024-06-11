//! Types for conveniently constructing TorClients.

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use crate::{err::ErrorDetail, BootstrapBehavior, Result, TorClient, TorClientConfig};
use std::sync::Arc;
use tor_dirmgr::{DirMgrConfig, DirMgrStore};
use tor_rtcompat::Runtime;

/// An object that knows how to construct some kind of DirProvider.
///
/// Note that this type is only actually exposed when the `experimental-api`
/// feature is enabled.
#[allow(unreachable_pub)]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental-api")))]
pub trait DirProviderBuilder<R: Runtime>: Send + Sync {
    fn build(
        &self,
        runtime: R,
        store: DirMgrStore<R>,
        circmgr: Arc<tor_circmgr::CircMgr<R>>,
        config: DirMgrConfig,
    ) -> Result<Arc<dyn tor_dirmgr::DirProvider + 'static>>;
}

/// A DirProviderBuilder that constructs a regular DirMgr.
#[derive(Clone, Debug)]
struct DirMgrBuilder {}

impl<R: Runtime> DirProviderBuilder<R> for DirMgrBuilder {
    fn build(
        &self,
        runtime: R,
        store: DirMgrStore<R>,
        circmgr: Arc<tor_circmgr::CircMgr<R>>,
        config: DirMgrConfig,
    ) -> Result<Arc<dyn tor_dirmgr::DirProvider + 'static>> {
        let dirmgr = tor_dirmgr::DirMgr::create_unbootstrapped(config, runtime, store, circmgr)
            .map_err(ErrorDetail::DirMgrSetup)?;
        Ok(Arc::new(dirmgr))
    }
}

/// An object for constructing a [`TorClient`].
///
/// Returned by [`TorClient::builder()`].
#[derive(Clone)]
#[must_use]
pub struct TorClientBuilder<R: Runtime> {
    /// The runtime for the client to use
    runtime: R,
    /// The client's configuration.
    config: TorClientConfig,
    /// How the client should behave when it is asked to do something on the Tor
    /// network before `bootstrap()` is called.
    bootstrap_behavior: BootstrapBehavior,
    /// Optional object to construct a DirProvider.
    ///
    /// Wrapped in an Arc so that we don't need to force DirProviderBuilder to
    /// implement Clone.
    dirmgr_builder: Arc<dyn DirProviderBuilder<R>>,
    /// Optional directory filter to install for testing purposes.
    ///
    /// Only available when `arti-client` is built with the `dirfilter` and `experimental-api` features.
    #[cfg(feature = "dirfilter")]
    dirfilter: tor_dirmgr::filter::FilterConfig,
}

impl<R: Runtime> TorClientBuilder<R> {
    /// Construct a new TorClientBuilder with the given runtime.
    pub(crate) fn new(runtime: R) -> Self {
        Self {
            runtime,
            config: TorClientConfig::default(),
            bootstrap_behavior: BootstrapBehavior::default(),
            dirmgr_builder: Arc::new(DirMgrBuilder {}),
            #[cfg(feature = "dirfilter")]
            dirfilter: None,
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

    /// Override the default function used to construct the directory provider.
    ///
    /// Only available when compiled with the `experimental-api` feature: this
    /// code is unstable.
    #[cfg(all(feature = "experimental-api", feature = "error_detail"))]
    pub fn dirmgr_builder<B>(mut self, builder: Arc<dyn DirProviderBuilder<R>>) -> Self
    where
        B: DirProviderBuilder<R> + 'static,
    {
        self.dirmgr_builder = builder;
        self
    }

    /// Install a [`DirFilter`](tor_dirmgr::filter::DirFilter) to
    ///
    /// Only available when compiled with the `dirfilter` feature: this code
    /// is unstable and not recommended for production use.
    #[cfg(feature = "dirfilter")]
    pub fn dirfilter<F>(mut self, filter: F) -> Self
    where
        F: Into<Arc<dyn tor_dirmgr::filter::DirFilter + 'static>>,
    {
        self.dirfilter = Some(filter.into());
        self
    }

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
    pub fn create_unbootstrapped(&self) -> Result<TorClient<R>> {
        #[allow(unused_mut)]
        let mut dirmgr_extensions = tor_dirmgr::config::DirMgrExtensions::default();
        #[cfg(feature = "dirfilter")]
        {
            dirmgr_extensions.filter.clone_from(&self.dirfilter);
        }

        TorClient::create_inner(
            self.runtime.clone(),
            &self.config,
            self.bootstrap_behavior,
            self.dirmgr_builder.as_ref(),
            dirmgr_extensions,
        )
        .map_err(ErrorDetail::into)
    }

    /// Create a TorClient from this builder, and try to bootstrap it.
    pub async fn create_bootstrapped(&self) -> Result<TorClient<R>> {
        let r = self.create_unbootstrapped()?;
        r.bootstrap().await?;
        Ok(r)
    }
}

#[cfg(test)]
mod test {
    use tor_rtcompat::PreferredRuntime;

    use super::*;

    fn must_be_send_and_sync<S: Send + Sync>() {}

    #[test]
    fn builder_is_send() {
        must_be_send_and_sync::<TorClientBuilder<PreferredRuntime>>();
    }
}
