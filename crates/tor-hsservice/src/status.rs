//! Support for reporting the status of an onion service.

use std::{
    sync::{Arc, Mutex},
    time::SystemTime,
};

use futures::StreamExt as _;
use tor_async_utils::PostageWatchSenderExt;

/// The current reported status of an onion service.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OnionServiceStatus {
    /// The current high-level state for this onion service.
    state: State,
    // TODO HSS: Add key expiration
    // TODO HSS: Add latest-error.
    //
    // NOTE: Do _not_ add general metrics (like failure/success rates , number
    // of intro points, etc) here.
}

/// The high-level state of an onion service.
///
/// This type summarizes the most basic information about an onion service's
/// status.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum State {
    /// The service is not launched.
    ///
    /// Either [`OnionService::launch`](crate::OnionService::launch) has not
    /// been called, or the service has been shut down.
    Shutdown,

    /// The service is bootstrapping.
    ///
    /// Specifically, we have been offline, or we just initialized:
    /// We are trying to build introduction points and publish a descriptor,
    /// and haven't hit any significant problems yet.
    Bootstrapping,
    /// The service is running.
    ///
    /// Specifically, we are satisfied with our introduction points, and our
    /// descriptor is up-to-date.
    Running,
    /// The service is trying to recover from a minor interruption.
    ///
    /// Specifically:
    ///   * We have encountered a problem (like a dead intro point or an
    ///     intermittent failure to upload a descriptor)
    ///   * We are trying to recover from the problem.
    ///   * We have not yet failed.
    Recovering,
    /// The service is not working.
    ///
    /// Specifically, there is a problem with this onion service, and either it
    /// is one we cannot recover from, or we have tried for a while to recover
    /// and have failed.
    Broken,
}

impl OnionServiceStatus {
    /// Create a new OnionServiceStatus for a service that has not been bootstrapped.
    pub(crate) fn new_shutdown() -> Self {
        Self {
            state: State::Shutdown,
        }
    }

    /// Return the current high-level state of this onion service.
    pub fn state(&self) -> State {
        self.state
    }

    /// Return the most severe current problem
    //
    // TODO HSS: We need an error type that can encompass StartupError _and_
    // intermittent problems encountered after we've launched for the first
    // time.
    // Perhaps the solution is to rename StartupError?  Or to make a new Problem
    // enum?
    // Please feel free to take whatever approach works best.
    pub fn current_problem(&self) -> Option<&crate::StartupError> {
        // TODO HSS: We can't put a StartupError here until the type implements
        // Eq, since postage::Watch requires that its type is Eq.
        None
    }

    /// Return a time before which the user must re-provision this onion service
    /// with new keys.
    ///
    /// Returns `None` if the onion service is able to generate and sign new
    /// keys as needed.
    pub fn provisioned_key_expiration(&self) -> Option<SystemTime> {
        None // TODO HSS: Implement
    }
}

/// A stream of OnionServiceStatus events, returned by an onion service.
///   
/// Note that multiple status change events may be coalesced into one if the
/// receiver does not read them as fast as they are generated.  Note also
/// that it's possible for an item to arise in this stream without an underlying
/// change having occurred.
///
//
// We define this so that we aren't exposing postage in our public API.
#[derive(Clone)]
pub struct OnionServiceStatusStream(postage::watch::Receiver<OnionServiceStatus>);

impl futures::Stream for OnionServiceStatusStream {
    type Item = OnionServiceStatus;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_next_unpin(cx)
    }
}

/// A shared handle to a postage::watch::Sender that we can use to update an OnionServiceStatus.
//
// TODO HSS: Possibly, we don't need this to be Clone: as we implement the code
// that adjusts the status, we might find that only a single location needs to
// hold the Sender.  If that turns out to be the case, we should remove the
// `Arc<Mutex<.>>` here.  If not, we should remove this comment.
#[derive(Clone)]
pub(crate) struct StatusSender(Arc<Mutex<postage::watch::Sender<OnionServiceStatus>>>);

impl StatusSender {
    /// Create a new StatusSender with a given initial status.
    pub(crate) fn new(initial_status: OnionServiceStatus) -> Self {
        let (tx, _) = postage::watch::channel_with(initial_status);
        StatusSender(Arc::new(Mutex::new(tx)))
    }

    /// Run `func` on the current status, and return a new one.  If it is
    /// different, update the current status and notify all listeners.
    #[allow(dead_code)]
    pub(crate) fn maybe_send<F>(&self, func: F)
    where
        F: FnOnce(&OnionServiceStatus) -> OnionServiceStatus,
    {
        self.0.lock().expect("Poisoned lock").maybe_send(func);
    }

    /// Return a copy of the current status.
    pub(crate) fn get(&self) -> OnionServiceStatus {
        self.0.lock().expect("Poisoned lock").borrow().clone()
    }

    /// Return a new OnionServiceStatusStream to return events from this StatusSender.
    pub(crate) fn subscribe(&self) -> OnionServiceStatusStream {
        OnionServiceStatusStream(self.0.lock().expect("Poisoned lock").subscribe())
    }
}
