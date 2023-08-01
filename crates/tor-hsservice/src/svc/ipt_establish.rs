//! IPT Establisher
//!
//! Responsible for maintaining and establishing one introduction point.
//!
//! TODO HSS: move docs from `hssvc-ipt-algorithm.md`

#![allow(clippy::needless_pass_by_value)] // TODO HSS remove

use std::sync::Arc;

use futures::channel::mpsc;
use tor_circmgr::hspool::HsCircPool;
use tor_netdir::{NetDirProvider, Relay};
use tor_rtcompat::Runtime;

use crate::RendRequest;

/// Handle onto the task which is establishing and maintaining one IPT
pub(crate) struct IptEstablisher {}

/// When the `IptEstablisher` is dropped it is torn down
///
/// Synchronously
///
///  * No rendezvous requests will be accepted
///    that arrived after `Drop::drop` returns.
///
/// Asynchronously
///
///  * Circuits constructed for this IPT are torn down
///  * The `rend_reqs` sink is closed (dropped)
///  * `IptStatusStatus::Faulty` will be indicated
impl Drop for IptEstablisher {
    fn drop(&mut self) {
        todo!()
    }
}

/// An error from trying to create in introduction point establisher.
///
/// TODO HSS: This is probably too narrow a definition; do something else
/// instead.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum IptError {}

impl IptEstablisher {
    /// Try to set up, and maintain, an IPT at `Relay`
    ///
    /// Rendezvous requests will be rejected
    pub(crate) fn new<R: Runtime>(
        circ_pool: Arc<HsCircPool<R>>,
        dirprovider: Arc<dyn NetDirProvider>,
        relay: &Relay<'_>,
        // Not a postage::watch since we want to count `Good` to `Faulty`
        // transitions
        //
        // (The alternative would be to count them as part of this structure and
        // use a postage watch.)
        //
        // bounded sender with a fixed small bound; OK to stall waiting for manager to catch up
        status: mpsc::Sender<IptStatus>,
        // TODO HSS: this needs to take some configuration
    ) -> Result<Self, IptError> {
        todo!()
    }

    /// Begin accepting connections from this introduction point.
    //
    // TODO HSS: Perhaps we want to provide rend_reqs as part of the
    // new() API instead.  If we do, we must make sure there's a way to
    // turn requests on and off, so that we can say "now we have advertised this
    // so requests are okay."
    pub(crate) fn start_accepting(&self, rend_reqs: mpsc::Sender<RendRequest>) {
        todo!()
    }
}

/// The current status of an introduction point, as defined in
/// `hssvc-ipt-algorithms.md`.
///
/// TODO HSS Make that file unneeded.
#[derive(Clone, Debug)]
pub(crate) enum IptStatusStatus {
    /// We are (re)establishing our connection to the IPT
    ///
    /// But we don't think there's anything wrong with it.
    Establishing,

    /// The IPT is established and ready to accept rendezvous requests
    Good,

    /// We don't have the IPT and it looks like it was the IPT's fault
    Faulty,
}

/// `Err(IptWantsToRetire)` indicates that the IPT Establisher wants to retire this IPT
///
/// This happens when the IPT has had (too) many rendezvous requests.
#[derive(Clone, Debug)]
pub(crate) struct IptWantsToRetire;

/// The current status of an introduction point.
#[derive(Clone, Debug)]
pub(crate) struct IptStatus {
    /// The current state of this introduction point as defined by
    /// `hssvc-ipt-algorithms.md`.
    ///
    /// TODO HSS Make that file unneeded.
    pub(crate) status: IptStatusStatus,

    /// The current status of whether this introduction point circuit wants to be
    /// retired based on having processed too many requests.
    pub(crate) wants_to_retire: Result<(), IptWantsToRetire>,
}
