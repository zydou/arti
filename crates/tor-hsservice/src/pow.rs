//! Implementation of [`PowManager`], for tracking proof-of-work seeds and data
//! for adjusting difficulty.

#[cfg_attr(not(feature = "hs-pow-full"), path = "pow/v1_stub.rs")]
pub(crate) mod v1;

use std::{pin::Pin, sync::Arc};

pub(crate) use self::v1::PowManager;

use futures::{Stream, channel::mpsc};
use tor_async_utils::mpsc_channel_no_memquota;
use tor_hscrypto::time::TimePeriod;

use crate::RendRequest;

/// Struct to hold various things you get when you make a new [`PowManager`].
pub(crate) struct NewPowManager<R> {
    /// The PoW manager.
    pub(crate) pow_manager: Arc<PowManager<R>>,
    /// Sender for rendezvous requests.
    pub(crate) rend_req_tx: mpsc::Sender<RendRequest>,
    /// Receiver for rendezvous requests.
    pub(crate) rend_req_rx: Pin<Box<dyn Stream<Item = RendRequest> + Send + Sync>>,
    /// Receiver used for the publisher to hear when it needs to republish for a TP because of a
    /// seed update.
    pub(crate) publisher_update_rx: mpsc::Receiver<TimePeriod>,
}

/// Depth of the [`RendRequest`] queue.
// TODO #1779: allow clients to configure this?
const REND_QUEUE_DEPTH: usize = 32;

/// Make a MPSC channel for the rendevouz request queue.
///
/// This is the underlying object in both the stub and non-stub case, so we share the code.
fn make_rend_queue() -> (mpsc::Sender<RendRequest>, mpsc::Receiver<RendRequest>) {
    // If the HS implementation is stalled somehow, this is a local problem.
    // We shouldn't kill the HS even if this is the oldest data in the system.
    mpsc_channel_no_memquota(REND_QUEUE_DEPTH)
}
