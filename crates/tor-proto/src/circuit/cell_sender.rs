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
use tracing::instrument;

use crate::{
    HopNum,
    channel::{ChanCellQueueEntry, ChannelSender},
    congestion::CongestionSignals,
    util::{SinkExt, sometimes_unbounded_sink::SometimesUnboundedSink},
};

cfg_if! {
    if #[cfg(feature="circ-padding")] {
        use crate::util::sink_blocker::{BooleanPolicy, SinkBlocker};
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
        /// - Finally, there is the [`ChannelSender`] itself.
        ///
        /// NOTE: We once had a second `SinkBlocker` to keep messages from the
        /// SometimesUnboundedSink from reaching the ChanSender
        /// when we were blocked on padding.
        /// We no longer use this SinkBlocker, since we decided in
        /// our [padding design] that non-data messages
        /// would never wait for a padding-based block.
        /// We can reinstate it if we change our mind.
        ///
        /// TODO: Ideally, this type would participate in the memory quota system.
        ///
        /// TODO: At some point in the future, we might want to add
        /// an additional _bounded_ [`futures::sink::Buffer`]
        /// to queue cells before they are put onto the channel,
        /// or to queue data from loud streams.
        ///
        /// [padding design]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/dev/notes/circuit-padding.md
        type InnerSink = SinkBlocker<
            SometimesUnbounded, BooleanPolicy,
        >;
        /// The type of our `SometimesUnboundedSink`, as instantiated.
        ///
        /// We use this to queue control cells.
        type SometimesUnbounded = SometimesUnboundedSink<
            ChanCellQueueEntry,
            // This is what we would reinstate
            // in order to have control messages blocked by padding frameworks:
            //      SinkBlocker<ChannelSender, CountingPolicy>
            ChannelSender
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
pub(crate) struct CircuitCellSender {
    /// The actual inner sink on which we'll be sending cells.
    ///
    /// See type alias documentation for full details.
    #[pin]
    sink: InnerSink,
}

impl CircuitCellSender {
    /// Construct a new `CircuitCellSender` to deliver cells onto `inner`.
    pub(crate) fn from_channel_sender(inner: ChannelSender) -> Self {
        cfg_if! {
            if #[cfg(feature="circ-padding")] {
                let sink = SinkBlocker::new(
                    SometimesUnboundedSink::new(
                        inner
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
    pub(crate) fn n_queued(&self) -> usize {
        self.sometimes_unbounded().n_queued()
    }

    /// Return true if we have a queued cell for the specified hop or later.
    #[cfg(feature = "circ-padding")]
    pub(crate) fn have_queued_cell_for_hop_or_later(&self, hop: HopNum) -> bool {
        if hop.is_first_hop() && self.chan_sender().approx_count() > 0 {
            // There's a cell on the outbound channel queue:
            // That will function perfectly well as padding to the first hop of this circuit,
            // whether it is actually for this circuit or not.
            return true;
        }

        // Now look at our own sometimes_unbounded queue.
        //
        // TODO circpad: in theory we could also look at the members of the per-channel queue to find this out!
        // But that's nontrivial, since the per-channel queue is implemented with an futures mpsc
        // channel, which doesn't have any functionality to let you inspect its queue.
        self.sometimes_unbounded()
            .iter_queue()
            .any(|(_, info)| info.is_some_and(|inf| inf.target_hop >= hop))
    }

    /// Send a cell on this sender,
    /// even if the  underlying channel queues are all full.
    ///
    /// You must `.await` this, but it will never block.
    /// (Its future is always `Ready`.)
    ///
    /// See note on [`CircuitCellSender`] type about polling:
    /// If you don't poll this sink, then queued items might never flush.
    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn send_unbounded(&mut self, entry: ChanCellQueueEntry) -> crate::Result<()> {
        Pin::new(self.sometimes_unbounded_mut())
            .send_unbounded(entry)
            .await?;
        self.chan_sender().note_cell_queued();
        Ok(())
    }

    /// Return the time provider used by the underlying channel sender
    /// for memory quota purposes.
    pub(crate) fn time_provider(&self) -> &DynTimeProvider {
        self.chan_sender().time_provider()
    }

    /// Circpadding only: Put this sink into a blocked state.
    ///
    /// When we are blocked, attempts to `send()` to this sink will fail.
    /// You can still queue items with `send_unbounded()`,
    /// and they will be sent immediately.
    //
    // (Previously we would block those items too,
    // and only allow them to be flushed one by one,
    // but we changed that behavior so that non-DATA cells can _always_ be sent.)
    #[cfg(feature = "circ-padding")]
    pub(crate) fn start_blocking(&mut self) {
        self.pre_queue_blocker_mut().set_blocked();
    }

    /// Circpadding only: Put this sink into an unblocked state.
    #[cfg(feature = "circ-padding")]
    pub(crate) fn stop_blocking(&mut self) {
        self.pre_queue_blocker_mut().set_unblocked();
    }

    /// Note: This is only async because we need a Context to check the underlying sink for readiness.
    /// This will register a new waker (or overwrite any existing waker).
    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn congestion_signals(&mut self) -> CongestionSignals {
        futures::future::poll_fn(|cx| -> Poll<CongestionSignals> {
            // We're looking at the ChanSender's in order to deliberately ignore the blocked/unblocked
            // status of this sink.
            //
            // See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3225#note_3252061
            // for a deeper discussion.
            let channel_ready = self
                .chan_sender_mut()
                .poll_ready_unpin_bool(cx)
                .unwrap_or(false);
            Poll::Ready(CongestionSignals::new(
                /* channel_blocked= */ !channel_ready,
                self.n_queued(),
            ))
        })
        .await
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
                self.sink.as_inner().as_inner()
            } else {
                self.sink.as_inner()
            }
        }
    }

    /// Helper: Return a mutable reference to the internal [`ChannelSender`]
    /// that this `CircuitCellSender` is based on.
    fn chan_sender_mut(&mut self) -> &mut ChannelSender {
        cfg_if! {
            if #[cfg(feature="circ-padding")] {
                self.sink.as_inner_mut().as_inner_mut()
            } else {
                self.sink.as_inner_mut()
            }
        }
    }

    /// Helper: Return a mutable reference to our outer [`SinkBlocker`]
    #[cfg(feature = "circ-padding")]
    fn pre_queue_blocker_mut(&mut self) -> &mut InnerSink {
        &mut self.sink
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

    fn start_send(mut self: Pin<&mut Self>, item: ChanCellQueueEntry) -> Result<(), Self::Error> {
        self.as_mut().project().sink.start_send(item)?;
        self.chan_sender().note_cell_queued();
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_close(cx)
    }
}
