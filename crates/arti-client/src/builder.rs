//! Types for conveniently constructing TorClients.

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use crate::{
    err::ErrorDetail, BootstrapBehavior, InertTorClient, Result, TorClient, TorClientConfig,
};
use std::{
    result::Result as StdResult,
    sync::Arc,
    time::{Duration, Instant},
};
use tor_dirmgr::{DirMgrConfig, DirMgrStore};
use tor_error::{ErrorKind, HasKind as _};
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
    /// If present, an amount of time to wait when trying to acquire the filesystem locks for our
    /// storage.
    local_resource_timeout: Option<Duration>,
    /// Optional directory filter to install for testing purposes.
    ///
    /// Only available when `arti-client` is built with the `dirfilter` and `experimental-api` features.
    #[cfg(feature = "dirfilter")]
    dirfilter: tor_dirmgr::filter::FilterConfig,
}

/// Longest allowable duration to wait for local resources to be available
/// when creating a TorClient.
///
/// This value may change in future versions of Arti.
/// It is an error to configure
/// a [`local_resource_timeout`](TorClientBuilder)
/// with a larger value than this.
///
/// (Reducing this value would count as a breaking change.)
pub const MAX_LOCAL_RESOURCE_TIMEOUT: Duration = Duration::new(5, 0);

impl<R: Runtime> TorClientBuilder<R> {
    /// Construct a new TorClientBuilder with the given runtime.
    pub(crate) fn new(runtime: R) -> Self {
        Self {
            runtime,
            config: TorClientConfig::default(),
            bootstrap_behavior: BootstrapBehavior::default(),
            dirmgr_builder: Arc::new(DirMgrBuilder {}),
            local_resource_timeout: None,
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

    /// Set a timeout that we should allow when trying to acquire our local resources
    /// (including lock files.)
    ///
    /// If no timeout is set, we wait for a short while (currently 500 msec) when invoked with
    /// [`create_bootstrapped`](Self::create_bootstrapped) or
    /// [`create_unbootstrapped_async`](Self::create_unbootstrapped_async),
    /// and we do not wait at all if invoked with
    /// [`create_unbootstrapped`](Self::create_unbootstrapped).
    ///
    /// (This difference in default behavior is meant to avoid unintentional blocking.
    /// If you call this method, subsequent calls to `crate_bootstrapped` may block
    /// the current thread.)
    ///
    /// The provided timeout value may not be larger than [`MAX_LOCAL_RESOURCE_TIMEOUT`].
    pub fn local_resource_timeout(mut self, timeout: Duration) -> Self {
        self.local_resource_timeout = Some(timeout);
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
    /// [`ErrorKind::BootstrapRequired`],
    /// until you have called [`TorClient::bootstrap`] yourself.
    /// This option is useful if you wish to have control over the bootstrap
    /// process (for example, you might wish to avoid initiating network
    /// connections until explicit user confirmation is given).
    ///
    /// If a [local_resource_timeout](Self::local_resource_timeout) has been set, this function may
    /// block the current thread.
    /// Use [`create_unbootstrapped_async`](Self::create_unbootstrapped_async)
    /// if that is not what you want.
    pub fn create_unbootstrapped(&self) -> Result<TorClient<R>> {
        let timeout = self.local_resource_timeout_or(Duration::from_millis(0))?;
        let give_up_at = Instant::now() + timeout;
        let mut first_attempt = true;

        loop {
            match self.create_unbootstrapped_inner(Instant::now, give_up_at, first_attempt) {
                Err(delay) => {
                    first_attempt = false;
                    std::thread::sleep(delay);
                }
                Ok(other) => return other,
            }
        }
    }

    /// Like create_unbootstrapped, but does not block the thread while trying to acquire the lock.
    ///
    /// If no [`local_resource_timeout`](Self::local_resource_timeout) has been set, this function may
    /// delay a short while (currently 500 msec) for local resources (such as lock files) to be available.
    /// Set `local_resource_timeout` to 0 if you do not want this behavior.
    pub async fn create_unbootstrapped_async(&self) -> Result<TorClient<R>> {
        // TODO: This code is largely duplicated from create_unbootstrapped above.  It might be good
        // to have a single shared implementation to handle both the sync and async cases, but I am
        // concerned that doing so would just add a lot of complexity.
        let timeout = self.local_resource_timeout_or(Duration::from_millis(500))?;
        let give_up_at = self.runtime.now() + timeout;
        let mut first_attempt = true;

        loop {
            match self.create_unbootstrapped_inner(|| self.runtime.now(), give_up_at, first_attempt)
            {
                Err(delay) => {
                    first_attempt = false;
                    self.runtime.sleep(delay).await;
                }
                Ok(other) => return other,
            }
        }
    }

    /// Helper for create_bootstrapped and create_bootstrapped_async.
    ///
    /// Does not retry on `LocalResourceAlreadyInUse`; instead, returns a time that we should wait,
    /// and log a message if `first_attempt` is true.
    fn create_unbootstrapped_inner<F>(
        &self,
        now: F,
        give_up_at: Instant,
        first_attempt: bool,
    ) -> StdResult<Result<TorClient<R>>, Duration>
    where
        F: FnOnce() -> Instant,
    {
        #[allow(unused_mut)]
        let mut dirmgr_extensions = tor_dirmgr::config::DirMgrExtensions::default();
        #[cfg(feature = "dirfilter")]
        {
            dirmgr_extensions.filter.clone_from(&self.dirfilter);
        }

        let result: Result<TorClient<R>> = TorClient::create_inner(
            self.runtime.clone(),
            &self.config,
            self.bootstrap_behavior,
            self.dirmgr_builder.as_ref(),
            dirmgr_extensions,
        )
        .map_err(ErrorDetail::into);

        match result {
            Err(e) if e.kind() == ErrorKind::LocalResourceAlreadyInUse => {
                let now = now();
                if now >= give_up_at {
                    // no time remaining; return the error that we got.
                    Ok(Err(e))
                } else {
                    let remaining = give_up_at.saturating_duration_since(now);
                    if first_attempt {
                        tracing::info!(
                            "Looks like another TorClient may be running; retrying for up to {}",
                            humantime::Duration::from(remaining),
                        );
                    }
                    // We'll retry at least once.
                    // TODO: Maybe use a smarter backoff strategy here?
                    Err(Duration::from_millis(50).min(remaining))
                }
            }
            // We either succeeded, or failed for a reason other than LocalResourceAlreadyInUse
            other => Ok(other),
        }
    }

    /// Create a TorClient from this builder, and try to bootstrap it.
    pub async fn create_bootstrapped(&self) -> Result<TorClient<R>> {
        let r = self.create_unbootstrapped_async().await?;
        r.bootstrap().await?;
        Ok(r)
    }

    /// Return the local_resource_timeout, or `dflt` if none is defined.
    ///
    /// Give an error if the value is above MAX_LOCAL_RESOURCE_TIMEOUT
    fn local_resource_timeout_or(&self, dflt: Duration) -> Result<Duration> {
        let timeout = self.local_resource_timeout.unwrap_or(dflt);
        if timeout > MAX_LOCAL_RESOURCE_TIMEOUT {
            return Err(
                ErrorDetail::Configuration(tor_config::ConfigBuildError::Invalid {
                    field: "local_resource_timeout".into(),
                    problem: "local resource timeout too large".into(),
                })
                .into(),
            );
        }
        Ok(timeout)
    }

    /// Create an `InertTorClient` from this builder, without launching
    /// the bootstrap process, or connecting to the network.
    #[allow(clippy::unnecessary_wraps)]
    pub fn create_inert(&self) -> Result<InertTorClient> {
        Ok(InertTorClient::new(&self.config)?)
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
