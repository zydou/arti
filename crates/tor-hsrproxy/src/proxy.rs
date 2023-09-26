//! A simple reverse-proxy implementation for onion services.

use std::sync::{Arc, Mutex};

use futures::{channel::oneshot, FutureExt as _};
use tor_rtcompat::Runtime;

use crate::config::ProxyConfig;

/// A reverse proxy that handles connections from an `OnionService` by routing
/// them to local addresses.
#[derive(Debug)]
pub struct OnionServiceReverseProxy {
    /// Mutable state held by this reverse proxy.
    state: Mutex<State>,
}

/// Mutable part of an RProxy
#[derive(Debug)]
struct State {
    /// The current configuration for this reverse proxy.
    config: ProxyConfig,
    /// A sender that we'll drop when it's time to shut down this proxy.
    shutdown_tx: Option<oneshot::Sender<void::Void>>,
    /// A receiver that we'll use to monitor for shutdown signals.
    shutdown_rx: futures::future::Shared<oneshot::Receiver<void::Void>>,
}

impl OnionServiceReverseProxy {
    /// Create a new proxy with a given configuration.
    pub fn new(config: ProxyConfig) -> Arc<Self> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        Arc::new(Self {
            state: Mutex::new(State {
                config,
                shutdown_tx: Some(shutdown_tx),
                shutdown_rx: shutdown_rx.shared(),
            }),
        })
    }

    /// Try to change the configuration of this proxy.
    pub fn reconfigure(&self, config: ProxyConfig) -> Result<(), tor_config::ReconfigureError> {
        let mut state = self.state.lock().expect("poisoned lock");
        state.config = config;
        // Note: we don't need to use a postage::watch here, since we just want
        // to lock this configuration whenever we get a request.  We could use a
        // Mutex<Arc<>> instead, but the performance shouldn't matter.
        Ok(())
    }

    /// Shut down all request-handlers running using with this proxy.
    pub fn shutdown(&self) {
        let mut state = self.state.lock().expect("poisoned lock");
        let _ = state.shutdown_tx.take();
    }

    /// XXXX
    async fn handle_requests<R: Runtime>(&self, _runtime: R, _requests: ()) {}
}
