#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

pub mod events;

use crate::events::{TorEvent, TorEventKind};
use async_broadcast::{InactiveReceiver, Receiver, Sender, TrySendError};
use futures::channel::mpsc;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::future::Either;
use futures::StreamExt;
use once_cell::sync::OnceCell;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use thiserror::Error;
use tracing::{error, warn};

/// Pointer to an `UnboundedSender`, used to send events into the `EventReactor`.
static EVENT_SENDER: OnceCell<UnboundedSender<TorEvent>> = OnceCell::new();
/// An inactive receiver for the currently active broadcast channel, if there is one.
static CURRENT_RECEIVER: OnceCell<InactiveReceiver<TorEvent>> = OnceCell::new();
/// The number of `TorEventKind`s there are.
const EVENT_KIND_COUNT: usize = 1;
/// An array containing one `AtomicUsize` for each `TorEventKind`, used to track subscriptions.
///
/// When a `TorEventReceiver` subscribes to a `TorEventKind`, it uses its `usize` value to index
/// into this array and increment the associated `AtomicUsize` (and decrements it to unsubscribe).
/// This lets event emitters check whether there are any subscribers, and avoid emitting events
/// if there aren't.
static EVENT_SUBSCRIBERS: [AtomicUsize; EVENT_KIND_COUNT] = [AtomicUsize::new(0); EVENT_KIND_COUNT];

/// The size of the internal broadcast channel used to implement event subscription.
pub static BROADCAST_CAPACITY: usize = 512;

/// A reactor used to forward events to make the event reporting system work.
///
/// # Note
///
/// Currently, this type is a singleton; there is one event reporting system used for the entire
/// program. This is not stable, and may change in future.
pub struct EventReactor {
    /// A receiver that the reactor uses to learn about incoming events.
    ///
    /// This is unbounded so that event publication doesn't have to be async.
    receiver: UnboundedReceiver<TorEvent>,
    /// A sender that the reactor uses to publish events.
    ///
    /// Events are only sent here if at least one subscriber currently wants them.
    broadcast: Sender<TorEvent>,
}

impl EventReactor {
    /// Initialize the event reporting system, returning a reactor that must be run for it to work,
    /// and a `TorEventReceiver` that can be used to extract events from the system. If the system
    /// has already been initialized, returns `None` instead of a reactor.
    ///
    /// # Warnings
    ///
    /// The returned reactor *must* be run with `EventReactor::run`, in a background async task.
    /// If it is not, the event system might consume unbounded amounts of memory.
    pub fn new() -> Option<Self> {
        let (tx, rx) = mpsc::unbounded();
        if EVENT_SENDER.set(tx).is_ok() {
            let (btx, brx) = async_broadcast::broadcast(BROADCAST_CAPACITY);
            CURRENT_RECEIVER
                .set(brx.deactivate())
                .expect("CURRENT_RECEIVER can't be set if EVENT_SENDER is unset!");
            Some(Self {
                receiver: rx,
                broadcast: btx,
            })
        } else {
            None
        }
    }
    /// Get a `TorEventReceiver` to receive events from, assuming an `EventReactor` is already
    /// running somewhere. (If it isn't, returns `None`.)
    ///
    /// As noted in the type-level documentation, this function might not always work this way.
    pub fn receiver() -> Option<TorEventReceiver> {
        CURRENT_RECEIVER
            .get()
            .map(|rx| TorEventReceiver::wrap(rx.clone()))
    }
    /// Run the event forwarding reactor.
    ///
    /// You *must* call this function once a reactor is created.
    pub async fn run(mut self) {
        while let Some(event) = self.receiver.next().await {
            match self.broadcast.try_broadcast(event) {
                Ok(_) => {}
                Err(TrySendError::Closed(_)) => break,
                Err(TrySendError::Full(event)) => {
                    // If the channel is full, do a blocking broadcast to wait for it to be
                    // not full, and log a warning about receivers lagging behind.
                    warn!("TorEventReceivers aren't receiving events fast enough!");
                    if self.broadcast.broadcast(event).await.is_err() {
                        break;
                    }
                }
                Err(TrySendError::Inactive(_)) => {
                    // no active receivers, so just drop the event on the floor.
                }
            }
        }
        // It shouldn't be possible to get here, since we have globals keeping the channels
        // open. Still, if we somehow do, log an error about it.
        error!("event reactor shutting down; this shouldn't ever happen");
    }
}

/// An error encountered when trying to receive a `TorEvent`.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum ReceiverError {
    /// The receiver isn't subscribed to anything, so wouldn't ever return any events.
    #[error("No event subscriptions")]
    NoSubscriptions,
    /// The internal broadcast channel was closed, which shouldn't ever happen.
    #[error("Internal event broadcast channel closed")]
    ChannelClosed,
}

/// A receiver for `TorEvent`s emitted by other users of this crate.
///
/// To use this type, first subscribe to some kinds of event by calling
/// `TorEventReceiver::subscribe`. Then, consume events using the implementation of
/// `futures::stream::Stream`.
///
/// # Warning
///
/// Once interest in events has been signalled with `subscribe`, events must be continuously
/// read from the receiver in order to avoid excessive memory consumption.
#[derive(Clone, Debug)]
pub struct TorEventReceiver {
    /// If no events have been subscribed to yet, this is an `InactiveReceiver`; otherwise,
    /// it's a `Receiver`.
    inner: Either<Receiver<TorEvent>, InactiveReceiver<TorEvent>>,
    /// Whether we're subscribed to each event kind (if `subscribed[kind]` is true, we're
    /// subscribed to `kind`).
    subscribed: [bool; EVENT_KIND_COUNT],
}

impl futures::stream::Stream for TorEventReceiver {
    type Item = TorEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.inner {
            Either::Left(ref mut active) => loop {
                match Pin::new(&mut *active).poll_next(cx) {
                    Poll::Ready(Some(e)) => {
                        if this.subscribed[e.kind() as usize] {
                            return Poll::Ready(Some(e));
                        }
                        // loop, since we weren't subscribed to that event
                    }
                    x => return x,
                }
            },
            Either::Right(_) => {
                warn!("TorEventReceiver::poll_next() called without subscriptions!");
                Poll::Ready(None)
            }
        }
    }
}

impl TorEventReceiver {
    /// Create a `TorEventReceiver` from an `InactiveReceiver` handle.
    pub(crate) fn wrap(rx: InactiveReceiver<TorEvent>) -> Self {
        Self {
            inner: Either::Right(rx),
            subscribed: [false; EVENT_KIND_COUNT],
        }
    }
    /// Subscribe to a given kind of `TorEvent`.
    ///
    /// After calling this function, `TorEventReceiver::recv` will emit events of that kind.
    /// This function is idempotent (subscribing twice has the same effect as doing so once).
    pub fn subscribe(&mut self, kind: TorEventKind) {
        if !self.subscribed[kind as usize] {
            EVENT_SUBSCRIBERS[kind as usize].fetch_add(1, Ordering::SeqCst);
            self.subscribed[kind as usize] = true;
        }
        // FIXME(eta): cloning is ungood, but hard to avoid
        if let Either::Right(inactive) = self.inner.clone() {
            self.inner = Either::Left(inactive.activate());
        }
    }
    /// Unsubscribe from a given kind of `TorEvent`.
    ///
    /// After calling this function, `TorEventReceiver::recv` will no longer emit events of that
    /// kind.
    /// This function is idempotent (unsubscribing twice has the same effect as doing so once).
    pub fn unsubscribe(&mut self, kind: TorEventKind) {
        if self.subscribed[kind as usize] {
            EVENT_SUBSCRIBERS[kind as usize].fetch_sub(1, Ordering::SeqCst);
            self.subscribed[kind as usize] = false;
        }
        // If we're now not subscribed to anything, deactivate our channel.
        if self.subscribed.iter().all(|x| !*x) {
            // FIXME(eta): cloning is ungood, but hard to avoid
            if let Either::Left(active) = self.inner.clone() {
                self.inner = Either::Right(active.deactivate());
            }
        }
    }
}

impl Drop for TorEventReceiver {
    fn drop(&mut self) {
        for (i, subscribed) in self.subscribed.iter().enumerate() {
            // FIXME(eta): duplicates logic from Self::unsubscribe, because it's not possible
            //             to go from a `usize` to a `TorEventKind`
            if *subscribed {
                EVENT_SUBSCRIBERS[i].fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}

/// Returns a boolean indicating whether the event `kind` has any subscribers (as in,
/// whether `TorEventReceiver::subscribe` has been called with that event kind).
///
/// This is useful to avoid doing work to generate events that might be computationally expensive
/// to generate.
pub fn event_has_subscribers(kind: TorEventKind) -> bool {
    EVENT_SUBSCRIBERS[kind as usize].load(Ordering::SeqCst) > 0
}

/// Broadcast the given `TorEvent` to any interested subscribers.
///
/// As an optimization, does nothing if the event has no subscribers (`event_has_subscribers`
/// returns false). (also does nothing if the event subsystem hasn't been initialized yet)
///
/// This function isn't intended for use outside Arti crates (as in, library consumers of Arti
/// shouldn't broadcast events!).
pub fn broadcast(event: TorEvent) {
    if !event_has_subscribers(event.kind()) {
        return;
    }
    if let Some(sender) = EVENT_SENDER.get() {
        // If this fails, there isn't much we can really do about it!
        let _ = sender.unbounded_send(event);
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use crate::{
        broadcast, event_has_subscribers, EventReactor, StreamExt, TorEvent, TorEventKind,
    };
    use once_cell::sync::OnceCell;
    use std::sync::{Mutex, MutexGuard};
    use std::time::Duration;
    use tokio::runtime::Runtime;

    // HACK(eta): these tests need to run effectively singlethreaded, since they mutate global
    //            state. They *also* need to share the same tokio runtime, which the
    //            #[tokio::test] thing doesn't do (it makes a new runtime per test), because of
    //            the need to have a background singleton EventReactor.
    //
    //            To hack around this, we just have a global runtime protected by a mutex!
    static TEST_MUTEX: OnceCell<Mutex<Runtime>> = OnceCell::new();

    /// Locks the mutex, and makes sure the event reactor is initialized.
    fn test_setup() -> MutexGuard<'static, Runtime> {
        let mutex = TEST_MUTEX.get_or_init(|| Mutex::new(Runtime::new().unwrap()));
        let runtime = mutex
            .lock()
            .expect("mutex poisoned, probably by other failing tests");
        if let Some(reactor) = EventReactor::new() {
            runtime.handle().spawn(reactor.run());
        }
        runtime
    }

    #[test]
    fn subscriptions() {
        let rt = test_setup();

        rt.block_on(async move {
            // shouldn't have any subscribers at the start
            assert!(!event_has_subscribers(TorEventKind::Empty));

            let mut rx = EventReactor::receiver().unwrap();
            // creating a receiver shouldn't result in any subscriptions
            assert!(!event_has_subscribers(TorEventKind::Empty));

            rx.subscribe(TorEventKind::Empty);
            // subscription should work
            assert!(event_has_subscribers(TorEventKind::Empty));

            rx.unsubscribe(TorEventKind::Empty);
            // unsubscribing should work
            assert!(!event_has_subscribers(TorEventKind::Empty));

            // subscription should be idempotent
            rx.subscribe(TorEventKind::Empty);
            rx.subscribe(TorEventKind::Empty);
            rx.subscribe(TorEventKind::Empty);
            assert!(event_has_subscribers(TorEventKind::Empty));

            rx.unsubscribe(TorEventKind::Empty);
            assert!(!event_has_subscribers(TorEventKind::Empty));

            rx.subscribe(TorEventKind::Empty);
            assert!(event_has_subscribers(TorEventKind::Empty));

            std::mem::drop(rx);
            // dropping the receiver should auto-unsubscribe
            assert!(!event_has_subscribers(TorEventKind::Empty));
        });
    }

    #[test]
    fn empty_recv() {
        let rt = test_setup();

        rt.block_on(async move {
            let mut rx = EventReactor::receiver().unwrap();
            // attempting to read from a receiver with no subscriptions should return None
            let result = rx.next().await;
            assert!(result.is_none());
        });
    }

    #[test]
    fn receives_events() {
        let rt = test_setup();

        rt.block_on(async move {
            let mut rx = EventReactor::receiver().unwrap();
            rx.subscribe(TorEventKind::Empty);
            // HACK(eta): give the event reactor time to run
            tokio::time::sleep(Duration::from_millis(100)).await;
            broadcast(TorEvent::Empty);

            let result = rx.next().await;
            assert_eq!(result, Some(TorEvent::Empty));
        });
    }

    #[test]
    fn does_not_send_to_no_subscribers() {
        let rt = test_setup();

        rt.block_on(async move {
            // this event should just get dropped on the floor, because no subscribers exist
            broadcast(TorEvent::Empty);

            let mut rx = EventReactor::receiver().unwrap();
            rx.subscribe(TorEventKind::Empty);

            // this shouldn't have an event to receive now
            let result = tokio::time::timeout(Duration::from_millis(100), rx.next()).await;
            assert!(result.is_err());
        });
    }
}
