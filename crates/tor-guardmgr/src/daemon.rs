//! Implement background tasks used by guard managers.
//!
//! These background tasks keep a weak reference to the [`GuardMgrInner`]
//! and use that to notice when they should shut down.

use crate::pending::{GuardStatusMsg, RequestId};
use crate::GuardMgrInner;

use futures::{
    channel::{mpsc, oneshot},
    stream::{self, StreamExt},
};
use std::sync::{Mutex, Weak};

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
    Observe(oneshot::Receiver<Msg>),
    /// A message sent by a [`crate::GuardMonitor`] to report the status
    /// of an attempt to use a guard.
    Status(RequestId, GuardStatusMsg),
    /// Tells the task to reply on the provided oneshot::Sender once
    /// it has seen this message.  Used to indicate that the message
    /// queue is flushed.
    #[cfg(test)]
    Ping(oneshot::Sender<()>),
}

/// Wrapper type to unify returns from mpsc and oneshots
pub(crate) type MsgResult = Result<Msg, futures::channel::oneshot::Canceled>;

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
    ctrl: mpsc::UnboundedReceiver<MsgResult>,
) {
    // Multiplexes a bunch of one-shot receivers to tell us about guard
    // status outcomes.
    let notifications = stream::FuturesUnordered::new();
    // If I don't put this dummy receiver into notifications, then
    // notifications will be finished prematurely and not get polled any more.
    // TODO: Is there a better way to do this?
    let (_dummy_snd, rcv) = oneshot::channel();
    notifications.push(rcv);

    // Multiplexes `notifications` with events from `ctrl`.
    let mut events = stream::select(notifications, ctrl);

    loop {
        match events.next().await {
            Some(Ok(Msg::Observe(rcv))) => {
                // We've been told to wait for a new event; add it to
                // `notifications`.
                events.get_ref().0.push(rcv);
            }
            Some(Ok(Msg::Status(id, status))) => {
                // We've got a report about a guard status.
                if let Some(inner) = inner.upgrade() {
                    let mut inner = inner.lock().expect("Poisoned lock");
                    inner.handle_msg(id, status, &runtime);
                } else {
                    // The guard manager has gone away.
                    return;
                }
            }
            Some(Err(_)) => {
                // TODO: Unfortunately, we don't know which future was cancelled.
                // It shouldn't be possible for this to occur, though, since
                // GuardMonitor always sends a message, even on drop.
                tracing::warn!("bug: Somehow a guard success event was dropped.");
            }
            #[cfg(test)]
            Some(Ok(Msg::Ping(sender))) => {
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
