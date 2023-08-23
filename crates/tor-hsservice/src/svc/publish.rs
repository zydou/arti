//! Publish and maintain onion service descriptors

#![allow(clippy::needless_pass_by_value)] // TODO HSS REMOVE.

mod err;

use std::sync::Arc;

use tor_circmgr::hspool::HsCircPool;
use tor_hscrypto::pk::HsId;
use tor_netdir::NetDirProvider;
use tor_rtcompat::Runtime;

use crate::OnionServiceConfig;

use err::PublisherError;

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
    //
    /// A source for new network directories that we use to determine
    /// our HsDirs.
    dir_provider: Arc<dyn NetDirProvider>,
}

impl Publisher {
    /// Create and launch a new publisher.
    ///
    /// When it launches, it will know no keys or introduction points,
    /// and will therefore not upload any descriptors.
    ///
    #[allow(clippy::unnecessary_wraps)] // TODO HSS REMOVE
    pub(crate) async fn new<R: Runtime>(
        runtime: R,
        hsid: HsId,
        dir_provider: Arc<dyn NetDirProvider>,
        circpool: Arc<HsCircPool<R>>,
        config: OnionServiceConfig,
    ) -> Result<Self, PublisherError> {

        // TODO: Do we really want to launch now, or later?
        Ok(Self { dir_provider })
    }

    /// Inform this publisher that its set of keys has changed.
    ///
    /// TODO HSS: Either this needs to take new keys as an argument, or there
    /// needs to be a source of keys (including public keys) in Publisher.
    pub(crate) fn new_hs_keys(&self, keys: ()) {
        todo!()
    }

    /// Inform this publisher that  the set of introduction points has changed.
    ///
    /// TODO HSS: Either this needs to take new intropoints as an argument,
    /// or there needs to be a source of intro points in the Publisher.
    pub(crate) fn new_intro_points(&self, ipts: ()) {
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
