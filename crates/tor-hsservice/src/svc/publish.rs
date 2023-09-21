//! Publish and maintain onion service descriptors

#![allow(clippy::needless_pass_by_value)] // TODO HSS REMOVE.

mod backoff;
mod descriptor;
mod err;
mod reactor;

use futures::task::SpawnExt;
use postage::watch;
use std::sync::Arc;

use tor_circmgr::hspool::HsCircPool;
use tor_hscrypto::pk::HsId;
use tor_netdir::NetDirProvider;
use tor_rtcompat::Runtime;

use crate::ipt_set::IptsPublisherView;
use crate::OnionServiceConfig;

use err::PublisherError;
use reactor::{Reactor, ReactorError, ReactorState};

/// A handle for the Hsdir Publisher for an onion service.
///
/// This handle represents a set of tasks that identify the hsdirs for each
/// relevant time period, construct descriptors, publish them, and keep them
/// up-to-date.
#[must_use = "If you don't call launch() on the publisher, it won't publish any descriptors."]
pub(crate) struct Publisher<R: Runtime> {
    /// The runtime.
    runtime: R,
    /// The HsId of the service.
    //
    // TODO HSS: read this from the KeyMgr instead?
    hsid: HsId,
    /// A source for new network directories that we use to determine
    /// our HsDirs.
    dir_provider: Arc<dyn NetDirProvider>,
    /// A [`HsCircPool`] for building circuits to HSDirs.
    circpool: Arc<HsCircPool<R>>,
    /// The onion service config.
    config: Arc<OnionServiceConfig>,
    /// A channel for receiving IPT change notifications.
    ipt_watcher: IptsPublisherView,
    /// A channel for receiving onion service config change notifications.
    config_rx: watch::Receiver<Arc<OnionServiceConfig>>,
}

impl<R: Runtime> Publisher<R> {
    /// Create a new publisher.
    ///
    /// When it launches, it will know no keys or introduction points,
    /// and will therefore not upload any descriptors.
    ///
    /// The publisher won't start publishing until you call [`Publisher::launch`].
    //
    // TODO HSS: perhaps we don't need both config and config_rx (we could read the initial config
    // value from config_rx).
    pub(crate) fn new(
        runtime: R,
        hsid: HsId,
        dir_provider: Arc<dyn NetDirProvider>,
        circpool: Arc<HsCircPool<R>>,
        ipt_watcher: IptsPublisherView,
        config_rx: watch::Receiver<Arc<OnionServiceConfig>>,
    ) -> Self {
        let config = config_rx.borrow().clone();
        Self {
            runtime,
            hsid,
            dir_provider,
            circpool,
            config,
            ipt_watcher,
            config_rx,
        }
    }

    /// Launch the publisher reactor.
    pub(crate) async fn launch(self) -> Result<(), PublisherError> {
        let state = ReactorState::new(self.circpool);
        let reactor = Reactor::new(
            self.runtime.clone(),
            self.hsid,
            self.dir_provider,
            state,
            self.config,
            self.ipt_watcher,
            self.config_rx,
        )
        .await?;

        self.runtime
            .spawn(async move {
                let _result: Result<(), ReactorError> = reactor.run().await;
            })
            .map_err(|e| PublisherError::from_spawn("publisher reactor task", e))?;

        Ok(())
    }

    /// Inform this publisher that its set of keys has changed.
    ///
    /// TODO HSS: Either this needs to take new keys as an argument, or there
    /// needs to be a source of keys (including public keys) in Publisher.
    pub(crate) fn new_hs_keys(&self, keys: ()) {
        todo!()
    }

    /// Return our current status.
    //
    // TODO HSS: There should also be a postage::Watcher -based stream of status
    // change events.
    pub(crate) fn status(&self) -> PublisherStatus {
        todo!()
    }

    // TODO HSS: We may also need to update descriptors based on configuration
    // or authentication changes.
}

/// Current status of our attempts to publish an onion service descriptor.
#[derive(Debug, Clone)]
pub(crate) struct PublisherStatus {
    // TODO HSS add fields
}

//
// Our main loop has to look something like:

// Whenever time period or keys or netdir changes: Check whether our list of
// HsDirs has changed.  If it is, add and/or remove hsdirs as needed.

// "when learning about new keys, new intro points, or new configurations,
// or whenever the time period changes: Mark descriptors dirty."

// Whenever descriptors are dirty, we have enough info to generate
// descriptors, and we aren't upload-rate-limited: Generate new descriptors
// and mark descriptors clean.  Mark all hsdirs as needing new versions of
// this descriptor.

// While any hsdir does not have the latest version of its any descriptor:
// upload it.  Retry with usual timeouts on failure."

// TODO HSS: tests
