//! Publish and maintain onion service descriptors

#![allow(clippy::needless_pass_by_value)] // TODO HSS REMOVE.

mod descriptor;
mod err;
mod reactor;

use futures::channel::mpsc;
use futures::task::SpawnExt;
use std::sync::Arc;
use tracing::error;

use tor_circmgr::hspool::HsCircPool;
use tor_hscrypto::pk::HsId;
use tor_netdir::NetDirProvider;
use tor_rtcompat::Runtime;

use crate::OnionServiceConfig;

pub(crate) use descriptor::Ipt;
use err::PublisherError;
use reactor::{Event, Reactor, ReactorError, ReactorState};

/// A handle for the Hsdir Publisher for an onion service.
///
/// This handle represents a set of tasks that identify the hsdirs for each
/// relevant time period, construct descriptors, publish them, and keep them
/// up-to-date.
pub(crate) struct Publisher {
    // TODO HSS: Write the contents here.
    //
    // I'm assuming that each Publisher knows its current keys, keeps track of
    // the current relevant time periods, and knows the current
    // status for uploading to each HsDir.
    //
    // Some of these contents may actually wind up belonging to a reactor
    // task.
    /// A channel for sending `Event`s to the reactor.
    tx: mpsc::UnboundedSender<Event>,
}

/// A set of introduction points for publication
pub(crate) struct IptSet {
    /// The actual introduction points
    pub(crate) ipts: Vec<Ipt>,
}

impl Publisher {
    /// Create and launch a new publisher.
    ///
    /// When it launches, it will know no keys or introduction points,
    /// and will therefore not upload any descriptors.
    pub(crate) async fn new<R: Runtime>(
        runtime: R,
        hsid: HsId,
        dir_provider: Arc<dyn NetDirProvider>,
        circpool: Arc<HsCircPool<R>>,
        config: OnionServiceConfig,
    ) -> Result<Self, PublisherError> {
        let (tx, rx) = mpsc::unbounded();
        let state = ReactorState::new(circpool);
        let Ok(reactor) =
            Reactor::new(runtime.clone(), hsid, dir_provider, state, config, rx).await
        else {
            error!("failed to create reactor");
            panic!();
        };

        // TODO: Do we really want to launch now, or later?
        runtime
            .spawn(async move {
                let _result: Result<(), ReactorError> = reactor.run().await;
            })
            .map_err(|e| PublisherError::from_spawn("publisher reactor task", e))?;

        Ok(Self { tx })
    }

    /// Inform this publisher that its set of keys has changed.
    ///
    /// TODO HSS: Either this needs to take new keys as an argument, or there
    /// needs to be a source of keys (including public keys) in Publisher.
    pub(crate) fn new_hs_keys(&self, keys: ()) {
        // TODO HSS: handle/return the error
        let _ = self.tx.unbounded_send(Event::NewKeys(()));
    }

    /// Inform this publisher that  the set of introduction points has changed.
    ///
    /// TODO HSS: Either this needs to take new intropoints as an argument,
    /// or there needs to be a source of intro points in the Publisher.
    pub(crate) fn new_intro_points(&self, ipts: IptSet) {
        // TODO HSS: handle/return the error
        let _ = self.tx.unbounded_send(Event::NewIntroPoints(ipts));
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
