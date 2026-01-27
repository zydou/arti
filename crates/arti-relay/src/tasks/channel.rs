//! Channel tasks of the arti-relay.
//!
//! The tasks are:
//!     * [`ChannelHouseKeepingTask`] which is in charge of regurlarly going over existing channels
//!       to clean up expiring ones and prune duplicates. At the start, it will run in
//!       [`ChannelHouseKeepingTask::START_TICK_TIME`] seconds and then the channel expiry function
//!       tells it how much time to sleep.

use anyhow::Context;
use std::{
    sync::{Arc, Weak},
    time::Duration,
};
use tracing::debug;

use tor_chanmgr::ChanMgr;
use tor_rtcompat::Runtime;

/// Channel housekeeping standalone background task.
pub(crate) struct ChannelHouseKeepingTask<R: Runtime> {
    /// Weak reference to the ChanMgr. If it disappears, task stops.
    mgr: Weak<ChanMgr<R>>,
}

impl<R: Runtime> ChannelHouseKeepingTask<R> {
    /// Starting tick time is to run in 3 minutes. The ChanMgr expire channels uses a default of
    /// 180 seconds and so we simply align with that for the first run. After that, the channel
    /// subsystems will tell us how long to wait if any channels.
    const START_TICK_TIME: Duration = Duration::from_secs(180);

    /// Constructor.
    pub(crate) fn new(mgr: &Arc<ChanMgr<R>>) -> Self {
        Self {
            mgr: Arc::downgrade(mgr),
        }
    }

    /// Run the background task.
    #[allow(clippy::unused_async)] // TODO(relay)
    async fn run(&mut self) -> anyhow::Result<Duration> {
        let mgr = Weak::upgrade(&self.mgr).context("Channel manager is gone")?;
        // Expire any channels that are possibly closing.
        let next_expiry = mgr.expire_channels();

        // TODO: Another action is to prune duplicate channels like C-tor does in
        // channel_update_bad_for_new_circs().
        Ok(next_expiry)
    }

    /// Start the task.
    pub(crate) async fn start(&mut self) -> anyhow::Result<void::Void> {
        let mut next_tick_in = Self::START_TICK_TIME;
        debug!("Channel housekeeping task starting.");
        loop {
            // Sleep until next tick.
            tokio::time::sleep(next_tick_in).await;
            // Run this task. The returned value is the next tick.
            next_tick_in = self
                .run()
                .await
                .context("Shutting down channel housekeeping task")?;
        }
    }
}
