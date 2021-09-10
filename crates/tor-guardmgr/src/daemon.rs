//! Implement background tasks used by guard managers.
//!
//! These background tasks keep a weak reference to the [`GuardMgrInner`]
//! and use that to notice when they should shut down.

use crate::pending::{GuardStatusMsg, RequestId};
use crate::GuardMgrInner;

use futures::{
    channel::{mpsc, oneshot},
    lock::Mutex,
    stream::{self, StreamExt},
    FutureExt,
};
use std::sync::Weak;

/// A message sent by to the [`report_status_events()`] task.
#[derive(Debug)]
pub(crate) enum Msg {
    /// Tells the task to add another [`oneshot::Receiver`] to the list
    /// of receivers it's listening to.
    ///
    /// This message is sent by guard manager whenever it hands out a
    /// guard; the receiver will be notified when the requester's circuit
    /// succeeds, fails, or is abandoned.  The receiver corresponds
    /// to the sender in some [`crate::GuardMonitor`].
    Observe(RequestId, oneshot::Receiver<GuardStatusMsg>),
    /// A message sent by a [`crate::GuardMonitor`] to report the status
    /// of an attempt to use a guard.
    Status(RequestId, GuardStatusMsg),
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
    ctrl: mpsc::Receiver<Msg>,
) {
    // Multiplexes a bunch of one-shot streams containing
    // oneshot::Receiver for guard status.
    let notifications = stream::SelectAll::new();
    // Multiplexes `notifications` with events from `ctrl`.
    let mut events = stream::select(notifications, ctrl);

    loop {
        match events.next().await {
            Some(Msg::Observe(id, rcv)) => {
                // We've been told to wait for a new event; add it to
                // `notifications`.
                events.get_mut().0.push(stream::once(rcv.map(move |st| {
                    Msg::Status(id, st.unwrap_or(GuardStatusMsg::AttemptAbandoned))
                })));
            }
            Some(Msg::Status(id, status)) => {
                // We've got a report about a guard status.
                if let Some(inner) = inner.upgrade() {
                    let mut inner = inner.lock().await;
                    inner.handle_msg(id, status, &runtime);
                } else {
                    // The guard manager has gone away.
                    return;
                }
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
            let mut inner = inner.lock().await;
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
