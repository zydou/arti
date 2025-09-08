//! Implements an outbound Sink type for cells being sent from a circuit onto a
//! [channel](crate::channel).

use std::{
    pin::{Pin, pin},
    task::{Context, Poll},
};

use cfg_if::cfg_if;
use futures::Sink;
use pin_project::pin_project;
use tor_rtcompat::DynTimeProvider;

use crate::{
    channel::{ChanCellQueueEntry, ChannelSender},
    util::sometimes_unbounded_sink::SometimesUnboundedSink,
};

cfg_if! {
    if #[cfg(feature="circ-padding")] {
        use crate::util::sink_blocker::{BooleanPolicy, CountingPolicy, SinkBlocker};
        /// Inner type used to implement a [`CircuitCellSender`].
        ///
        /// When `circ-padding` feature is enabled, this is a multi-level wrapper around
        /// a ChanSender:
        /// - On the outermost layer, there is a [`SinkBlocker`] that we use
        ///   to make this sink behave as if it were full
        ///   when our [circuit padding](crate::client::circuit::padding) code
        ///   tells us to block outbound traffic.
        /// - Then there is a [`SometimesUnboundedSink`] that we use to queue control messages
        ///   when the target `ChanSender` is full,
        ///   or when we traffic is blocked.
        /// - (TODO: At this point in the future, we might want to add
        ///   an additional _bounded_ [`futures::sink::Buffer`]
        ///   to queue cells before they are put onto the channel.)
        /// - Then there is a second `SinkBlocker` that permits us to trickle messages from the
        ///   queue to the ChanSender even traffic is blocked by our padding system.
        /// - Finally, there is the [`ChannelSender`] itself.
        ///
        /// TODO: Ideally, this type would participate in the memory quota system.
        ///
        ///
        type InnerSink = SinkBlocker<
            SometimesUnbounded, BooleanPolicy,
        >;
        /// The type of our `SometimesUnboundedSink`, as instantiated.
        ///
        /// We use this to queue control cells.
        type SometimesUnbounded = SometimesUnboundedSink<
            ChanCellQueueEntry,
            SinkBlocker<ChannelSender, CountingPolicy>
        >;
    } else {
        /// Inner type used to implement a [`CircuitCellSender`].
        ///
        /// When the `circ-padding` is disabled, this only adds a [`SometimesUnboundedSink`].
        ///
        /// TODO: Ideally, this type would participate in the memory quota system.
        /// TODO: At some point, we might want to add
        /// an additional _bounded_ [`futures::sink::Buffer`]
        /// to queue cells before they are put onto the channel.)
        type InnerSink = SometimesUnboundedSink<ChanCellQueueEntry, ChannelSender>;
        /// The type of our `SometimesUnboundedSink`, as instantiated.
        ///
        /// We use this to queue control cells.
        type SometimesUnbounded = InnerSink;
    }
}

/// A sink that a circuit uses to send cells onto a Channel.
///
/// (This is a separate type so we can more easily control access to its internals.)
///
/// ### You must poll this type
///
/// This type is based on [`SometimesUnboundedSink`].
/// For queued items to be delivered,
/// [`SometimesUnboundedSink`] must be polled,
/// even if you don't have an item to send.
/// The same rule applies here.
///
/// Currently [`Sink::poll_flush`], [`Sink::poll_close`], and [`Sink::poll_ready`]
/// will all work for this purpose.
#[pin_project]
pub(in crate::client::reactor) struct CircuitCellSender {
    /// The actual inner sink on which we'll be sending cells.
    ///
    /// See type alias documentation for full details.
    #[pin]
    sink: InnerSink,
}

impl CircuitCellSender {
    /// Construct a new `CircuitCellSender` to deliver cells onto `inner`.
    pub(super) fn from_channel_sender(inner: ChannelSender) -> Self {
        cfg_if! {
            if #[cfg(feature="circ-padding")] {
                let sink = SinkBlocker::new(
                    SometimesUnboundedSink::new(
                        SinkBlocker::new(inner, CountingPolicy::new_unlimited())
                    ),
                    BooleanPolicy::Unblocked
                );
            } else {
                let sink = SometimesUnboundedSink::new(inner);
            }
        }

        Self { sink }
    }

    /// Return the number of cells queued in this Sender
    /// that have not yet been flushed onto the channel.
    pub(super) fn n_queued(&self) -> usize {
        self.sometimes_unbounded().n_queued()
    }

    /// Send a cell on this sender,
    /// even if the  underlying channel queues are all full.
    ///
    /// You must `.await` this, but it will never block.
    /// (Its future is always `Ready`.)
    ///
    /// See note on [`CircuitCellSender`] type about polling:
    /// If you don't poll this sink, then queued items might never flush.
    pub(super) async fn send_unbounded(&mut self, entry: ChanCellQueueEntry) -> crate::Result<()> {
        Pin::new(self.sometimes_unbounded_mut())
            .send_unbounded(entry)
            .await
    }

    /// Return the time provider used by the underlying channel sender
    /// for memory quota purposes.
    pub(super) fn time_provider(&self) -> &DynTimeProvider {
        self.chan_sender().time_provider()
    }

    /// Circpadding only: Put this sink into a blocked state.
    ///
    /// When we are blocked, attempts to `send()` to this sink will fail.
    /// You can still queue items with `send_unbounded()`,
    /// but such items will not be flushed until this sink is unblocked,
    /// or when allowed by [`bypass_blocking_once()`](Self::bypass_blocking_once).
    #[cfg(feature = "circ-padding")]
    pub(super) fn start_blocking(&mut self) {
        self.pre_queue_blocker_mut().set_blocked();
        self.post_queue_blocker_mut().set_blocked();
    }

    /// Circpadding only: Put this sink into an unblocked state.
    #[cfg(feature = "circ-padding")]
    pub(super) fn stop_blocking(&mut self) {
        self.pre_queue_blocker_mut().set_unblocked();
        self.post_queue_blocker_mut().set_unlimited();
    }

    /// Circpadding only: If this sink is currently blocked,
    /// allow one queued item to bypass the block.
    #[cfg(feature = "circ-padding")]
    pub(super) fn bypass_blocking_once(&mut self) {
        self.post_queue_blocker_mut().allow_n_additional_items(1);
    }

    /// Helper: return a reference to the internal [`SometimesUnboundedSink`]
    /// that this `CircuitCellSender` is based on.
    fn sometimes_unbounded(&self) -> &SometimesUnbounded {
        cfg_if! {
            if #[cfg(feature="circ-padding")] {
                self.sink.as_inner()
            } else {
                &self.sink
            }
        }
    }

    /// Helper: return a mutable reference to the internal [`SometimesUnboundedSink`]
    /// that this `CircuitCellSender` is based on.
    fn sometimes_unbounded_mut(&mut self) -> &mut SometimesUnbounded {
        cfg_if! {
            if #[cfg(feature="circ-padding")] {
                self.sink.as_inner_mut()
            } else {
                &mut self.sink
            }
        }
    }

    /// Helper: Return a reference to the internal [`ChannelSender`]
    /// that this `CircuitCellSender` is based on.
    fn chan_sender(&self) -> &ChannelSender {
        cfg_if! {
            if #[cfg(feature="circ-padding")] {
                self.sink.as_inner().as_inner().as_inner()
            } else {
                self.sink.as_inner()
            }
        }
    }

    /// Helper: Return a mutable reference to our outer [`SinkBlocker`]
    #[cfg(feature = "circ-padding")]
    fn pre_queue_blocker_mut(&mut self) -> &mut InnerSink {
        &mut self.sink
    }

    /// Helper: Return a mutable reference to our inner [`SinkBlocker`].
    ///
    /// q.v. the dire warnings on [`SometimesUnboundedSink::as_inner_mut()`]:
    /// We must not use this reference to enqueue anything onto the returned sink directly.
    #[cfg(feature = "circ-padding")]
    fn post_queue_blocker_mut(&mut self) -> &mut SinkBlocker<ChannelSender, CountingPolicy> {
        self.sink.as_inner_mut().as_inner_mut()
    }
}

impl Sink<ChanCellQueueEntry> for CircuitCellSender {
    type Error = <ChannelSender as Sink<ChanCellQueueEntry>>::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        cfg_if! {
            if #[cfg(feature = "circ-padding")] {
                // In this case, our sink is _not_ the same as our SometimesUnboundedSink.
                // But we need to ensure that SometimesUnboundedMut gets polled
                // unconditionally, so that it can actually flush its members.
                //
                // We don't actually _care_ if it's ready;
                // we just need to make sure that it gets polled.
                // See the "You must poll this type" comment on SometimesUnboundedSink.
                let _ignore = pin!(self.sometimes_unbounded_mut()).poll_ready(cx);
            }
        }
        self.project().sink.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: ChanCellQueueEntry) -> Result<(), Self::Error> {
        self.project().sink.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_close(cx)
    }
}
