//! No-op implementation of our padding APIs.
//!
//! Used when circ-padding is not enabled, to simplify our code.

use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tor_rtcompat::{DynTimeProvider, SleepProvider};

use crate::HopNum;

/// Used to report padding events.
///
/// When the `circ-padding` feature is disabled, this type does nothing.
#[derive(Clone)]
pub(crate) struct PaddingController<S: SleepProvider = DynTimeProvider> {
    /// Marker, to pretend that we use a runtime.
    _phantom: PhantomData<S>,
}

/// Indication that padding should be sent.
///
/// When the `circ-padding` feature is disabled, this type is uninhabited and unconstructable.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SendPadding(void::Void);

/// Indication that we should begin blocking traffic to a given hop,
/// or change the hop to which we're blocking traffic.
///
/// When the `circ-padding` feature is disabled, this type is uninhabited and unconstructable.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StartBlocking(void::Void);

impl<S: SleepProvider> PaddingController<S> {
    /// Report that we've enqueued a non-padding cell for a given hop.
    pub(crate) fn queued_data(&self, _hop: HopNum) {}

    /// Report that we have enqueued a non-padding cell
    /// in place of a replaceable padding cell
    /// for a given hop.
    pub(crate) fn queued_data_as_padding(&self, _hop: HopNum, sendpadding: SendPadding) {
        void::unreachable(sendpadding.0);
    }

    /// Report that we have enqueued a padding cell to a given hop.
    pub(crate) fn queued_padding(&self, _hop: HopNum, sendpadding: SendPadding) {
        void::unreachable(sendpadding.0);
    }
    /// Report that we've flushed a cell from the queue for the given hop.
    pub(crate) fn flushed_relay_cell(&self, _hop: HopNum) {}

    /// Report that we have decrypted a non-padding cell from our queue
    /// from a given hop.
    pub(crate) fn decrypted_data(&self, _hop: HopNum) {}

    /// Report that we have decrypted a non-padding cell from our queue.
    //
    // See note above.
    pub(crate) fn decrypted_padding(&self, _hop: HopNum) {}
}

/// A stream of [`PaddingEvent`]
///
/// When the `circ-padding` feature is disabled, this stream never yields.
pub(crate) struct PaddingEventStream<S: SleepProvider = DynTimeProvider> {
    /// Marker, to pretend that we use a runtime.
    _phantom: PhantomData<S>,
}

impl futures::Stream for PaddingEventStream {
    type Item = super::PaddingEvent;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // TODO circpad: Might it be more efficient to return Ready(None)?
        Poll::Pending
    }
}
