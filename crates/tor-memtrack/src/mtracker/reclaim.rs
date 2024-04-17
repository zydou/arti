//! Reclamation algorithm

use super::*;

mod deferred_drop;

use deferred_drop::{DeferredDrop, GuardWithDeferredDrop};

/// Internal long-running task, handling reclsmation
///
/// This is the entrypoint for the rest of the `tracker`.
/// It handles logging of crashes.
pub(super) async fn task(tracker: Weak<MemoryQuotaTracker>, wakeup: mpsc::Receiver<()>) {
    todo!() // XXXX
}
