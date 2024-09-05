//! Types for conveniently constructing a TorRelay.

use tor_rtcompat::Runtime;

use crate::err::Error;
use crate::{config::TorRelayConfig, TorRelay};

/// An object for constructing a [`TorRelay`].
///
/// Returned by [`TorRelay::builder()`].
#[derive(Clone)]
#[must_use]
pub struct TorRelayBuilder<R: Runtime> {
    /// The runtime for the client to use
    runtime: R,
    /// The configuration.
    config: TorRelayConfig,
}

impl<R: Runtime> TorRelayBuilder<R> {
    /// Construct a new TorClientBuilder with the given runtime.
    pub(crate) fn new(runtime: R) -> Self {
        Self {
            runtime,
            config: TorRelayConfig::default(),
        }
    }

    /// Return a newly created TorRelay object.
    pub fn create(&self) -> Result<TorRelay<R>, Error> {
        TorRelay::create_inner(self.runtime.clone(), &self.config).map_err(Into::into)
    }
}
