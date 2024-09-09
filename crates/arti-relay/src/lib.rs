pub mod builder;
mod config;
mod err;

pub use err::Error;

use std::sync::Arc;

use builder::TorRelayBuilder;
use tor_chanmgr::Dormancy;
use tor_netdir::params::NetParameters;
use tor_rtcompat::Runtime;

use crate::config::TorRelayConfig;
use crate::err::ErrorDetail;

// Only rustls is supported.
#[cfg(all(feature = "rustls", any(feature = "async-std", feature = "tokio")))]
use tor_rtcompat::PreferredRuntime;

/// Represent an active Relay on the Tor network.
#[derive(Clone)]
pub struct TorRelay<R: Runtime> {
    /// Asynchronous runtime object.
    #[allow(unused)] // TODO RELAY remove
    runtime: R,
    /// Channel manager, used by circuits etc.,
    #[allow(unused)] // TODO RELAY remove
    chanmgr: Arc<tor_chanmgr::ChanMgr<R>>,
}

/// TorRelay can't be used with native-tls due to the lack of RFC5705 (keying material exporter).
#[cfg(all(feature = "rustls", any(feature = "async-std", feature = "tokio")))]
impl TorRelay<PreferredRuntime> {
    /// Return a new builder for creating a TorRelay object.
    ///
    /// # Panics
    ///
    /// If Tokio is being used (the default), panics if created outside the context of a currently
    /// running Tokio runtime. See the documentation for `tokio::runtime::Handle::current` for
    /// more information.
    ///
    /// If using `async-std`, either take care to ensure Arti is not compiled with Tokio support,
    /// or manually create an `async-std` runtime using [`tor_rtcompat`] and use it with
    /// [`TorRelay::with_runtime`].
    pub fn builder() -> TorRelayBuilder<PreferredRuntime> {
        let runtime = PreferredRuntime::current().expect(
            "TorRelay could not get an asynchronous runtime; are you running in the right context?",
        );
        TorRelayBuilder::new(runtime)
    }
}

impl<R: Runtime> TorRelay<R> {
    /// Return a new builder for creating TorRelay objects, with a custom provided [`Runtime`].
    ///
    /// See the [`tor_rtcompat`] crate for more information on custom runtimes.
    pub fn with_runtime(runtime: R) -> TorRelayBuilder<R> {
        TorRelayBuilder::new(runtime)
    }

    /// Return a TorRelay object.
    pub(crate) fn create_inner(runtime: R, config: &TorRelayConfig) -> Result<Self, ErrorDetail> {
        let chanmgr = Arc::new(tor_chanmgr::ChanMgr::new(
            runtime.clone(),
            &config.channel,
            Dormancy::Active,
            &NetParameters::from_map(&config.override_net_params),
        ));
        Ok(Self { runtime, chanmgr })
    }
}
