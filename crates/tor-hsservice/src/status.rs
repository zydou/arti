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

    /// The current high-level state for the IPT manager.
    ipt_mgr_state: State,

    /// The current high-level state for the descriptor publisher.
    publisher_state: State,
    // TODO (#1083): Add key expiration
    // TODO (#1083): Add latest-error.
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
            ipt_mgr_state: State::Shutdown,
            publisher_state: State::Shutdown,
        }
    }

    /// Return the current high-level state of this onion service.
    ///
    /// The overall state is derived from the `State`s of its underlying components
    /// (i.e. the IPT manager and descriptor publisher).
    pub fn state(&self) -> State {
        use State::*;

        match (self.ipt_mgr_state, self.publisher_state) {
            (Shutdown, _) | (_, Shutdown) => Shutdown,
            (Bootstrapping, _) | (_, Bootstrapping) => Bootstrapping,
            (Running, Running) => Running,
            (Recovering, _) | (_, Recovering) => Recovering,
            (Broken, _) | (_, Broken) => Broken,
        }
    }

    /// Return the most severe current problem
    //
    // TODO (#1083): We need an error type that can encompass StartupError _and_
    // intermittent problems encountered after we've launched for the first
    // time.
    // Perhaps the solution is to rename StartupError?  Or to make a new Problem
    // enum?
    // Please feel free to take whatever approach works best.
    pub fn current_problem(&self) -> Option<&crate::StartupError> {
        // TODO (#1083): We can't put a StartupError here until the type implements
        // Eq, since postage::Watch requires that its type is Eq.
        None
    }

    /// Return a time before which the user must re-provision this onion service
    /// with new keys.
    ///
    /// Returns `None` if the onion service is able to generate and sign new
    /// keys as needed.
    pub fn provisioned_key_expiration(&self) -> Option<SystemTime> {
        None // TODO (#1083): Implement
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

    /// Update the current IPT manager state.
    ///
    /// If the new state is different, update the current status and notify all listeners.
    //
    // TODO: should we have separate state enums for the IPT mgr and publisher states?
    #[allow(dead_code)]
    pub(crate) fn maybe_update_ipt_mgr(&self, state: State) {
        let mut tx = self.0.lock().expect("Poisoned lock");
        let mut svc_status = tx.borrow().clone();
        svc_status.ipt_mgr_state = state;
        tx.maybe_send(|_| svc_status);
    }

    /// Update the current publisher state.
    ///
    /// If the new state is different, update the current status and notify all listeners.
    #[allow(dead_code)]
    pub(crate) fn maybe_update_publisher(&self, state: State) {
        let mut tx = self.0.lock().expect("Poisoned lock");
        let mut svc_status = tx.borrow().clone();
        svc_status.publisher_state = state;
        tx.maybe_send(|_| svc_status);
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
