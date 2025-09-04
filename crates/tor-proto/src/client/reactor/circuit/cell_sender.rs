//! Implements an outbound Sink type for cells being sent from a circuit onto a
//! [channel](crate::channel).

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::Sink;
use pin_project::pin_project;
use tor_rtcompat::DynTimeProvider;

use crate::{
    channel::{ChanCellQueueEntry, ChannelSender},
    util::sometimes_unbounded_sink::SometimesUnboundedSink,
};

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
    /// This is a [`SometimesUnboundedSink`] because we need the ability
    /// to queue control (non-data) cells even when the target channel is full.
    ///
    /// The `SometimesUnboundedSink` sits outside the ChannelSender,
    /// since we want each circuit to have its own overflow queue.
    #[pin]
    sink: SometimesUnboundedSink<ChanCellQueueEntry, ChannelSender>,
}

impl CircuitCellSender {
    /// Construct a new `CircuitCellSender` to deliver cells onto `inner`.
    pub(super) fn from_channel_sender(inner: ChannelSender) -> Self {
        Self {
            sink: SometimesUnboundedSink::new(inner),
        }
    }

    /// Return the number of cells queued in this Sender
    /// that have not yet been flushed onto the channel.
    pub(super) fn n_queued(&self) -> usize {
        self.sink.n_queued()
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
        Pin::new(&mut self.sink).send_unbounded(entry).await
    }

    /// Return the time provider used by the underlying channel sender
    /// for memory quota purposes.
    pub(super) fn time_provider(&self) -> &DynTimeProvider {
        self.chan_sender().time_provider()
    }

    /// Helper: Return a reference to the internal [`ChannelSender`]
    /// that this `CircuitCellSender` is based on.
    fn chan_sender(&self) -> &ChannelSender {
        self.sink.as_inner()
    }
}

impl Sink<ChanCellQueueEntry> for CircuitCellSender {
    type Error = <ChannelSender as Sink<ChanCellQueueEntry>>::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
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
