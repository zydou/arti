//! Implement background tasks used by guard managers.
//!
//! These background tasks keep a weak reference to the [`GuardMgrInner`]
//! and use that to notice when they should shut down.

use crate::pending::{GuardStatus, RequestId};
use crate::GuardMgrInner;

#[cfg(test)]
use futures::channel::oneshot;
use futures::{channel::mpsc, stream::StreamExt};

use std::sync::{Mutex, Weak};

/// A message sent by to the [`report_status_events()`] task.
#[derive(Debug)]
pub(crate) enum Msg {
    /// A message sent by a [`GuardMonitor`](crate::GuardMonitor) to
    /// report the status of an attempt to use a guard.
    Status(RequestId, GuardStatus),
    /// Tells the task to reply on the provided oneshot::Sender once
    /// it has seen this message.  Used to indicate that the message
    /// queue is flushed.
    #[cfg(test)]
    Ping(oneshot::Sender<()>),
}

/// Background task: wait for messages about guard statuses, and
/// tell a guard manager about them.  Runs indefinitely.
///
/// Takes the [`GuardMgrInner`] by weak reference; if the guard
/// manager goes away, then this task exits.
///
/// Requires a `mpsc::Receiver` that is used to tell the task about
/// new status events to wait for.
pub(crate) async fn report_status_events(
    runtime: impl tor_rtcompat::SleepProvider,
    inner: Weak<Mutex<GuardMgrInner>>,
    mut events: mpsc::UnboundedReceiver<Msg>,
) {
    loop {
        match events.next().await {
            Some(Msg::Status(id, status)) => {
                // We've got a report about a guard status.
                if let Some(inner) = inner.upgrade() {
                    let mut inner = inner.lock().expect("Poisoned lock");
                    inner.handle_msg(id, status, &runtime);
                } else {
                    // The guard manager has gone away.
                    return;
                }
            }
            #[cfg(test)]
            Some(Msg::Ping(sender)) => {
                let _ignore = sender.send(());
            }
            // The streams have all closed.  (I think this is impossible?)
            None => return,
        }
        // TODO: Is this task guaranteed to exit?
    }
}

/// Background task to run periodic events on the guard manager.
///
/// The only role of this task is to invoke
/// [`GuardMgrInner::run_periodic_events`] from time to time, so that
/// it can perform housekeeping tasks.
///
/// Takes the [`GuardMgrInner`] by weak reference; if the guard
/// manager goes away, then this task exits.
pub(crate) async fn run_periodic<R: tor_rtcompat::SleepProvider>(
    runtime: R,
    inner: Weak<Mutex<GuardMgrInner>>,
) {
    loop {
        let delay = if let Some(inner) = inner.upgrade() {
            let mut inner = inner.lock().expect("Poisoned lock");
            let wallclock = runtime.wallclock();
            let now = runtime.now();
            inner.run_periodic_events(wallclock, now)
        } else {
            // The guard manager has gone away.
            return;
        };
        runtime.sleep(delay).await;
    }
}
