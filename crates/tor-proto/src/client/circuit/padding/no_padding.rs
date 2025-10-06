//! No-op implementation of our padding APIs.
//!
//! Used when circ-padding is not enabled, to simplify our code.

use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tor_memquota::memory_cost_structural_copy;
use tor_rtcompat::{DynTimeProvider, SleepProvider};

use crate::Error;
use crate::HopNum;
use crate::util::err::ExcessPadding;

/// Used to report padding events.
///
/// When the `circ-padding` feature is disabled, this type does nothing.
#[derive(Clone, Debug)]
pub(crate) struct PaddingController<S: SleepProvider = DynTimeProvider> {
    /// Marker, to pretend that we use a runtime.
    _phantom: PhantomData<S>,
}

/// Indication that padding should be sent.
///
/// When the `circ-padding` feature is disabled, this type is uninhabited and unconstructable.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SendPadding(void::Void);

/// Information about a queued cell that we need to feed back into the padding
/// subsystem.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueuedCellPaddingInfo(void::Void);
memory_cost_structural_copy!(QueuedCellPaddingInfo);

/// Indication that we should begin blocking traffic to a given hop,
/// or change the hop to which we're blocking traffic.
///
/// When the `circ-padding` feature is disabled, this type is uninhabited and unconstructable.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StartBlocking(void::Void);

/// An instruction from the padding machine to the circuit.
///
/// These are returned from the [`PaddingEventStream`].
///
/// When the `circ-padding` feature is disabled, this type is uninhabited and unconstructable.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PaddingEvent(pub(crate) void::Void);

impl<S: SleepProvider> PaddingController<S> {
    /// Report that we've enqueued a non-padding cell for a given hop.
    pub(crate) fn queued_data(&self, _hop: HopNum) -> Option<QueuedCellPaddingInfo> {
        None
    }

    /// Report that we have enqueued a non-padding cell
    /// in place of a replaceable padding cell
    /// for a given hop.
    pub(crate) fn queued_data_as_padding(
        &self,
        _hop: HopNum,
        sendpadding: SendPadding,
    ) -> Option<QueuedCellPaddingInfo> {
        void::unreachable(sendpadding.0);
    }

    /// Report that we have enqueued a padding cell to a given hop.
    pub(crate) fn queued_padding(
        &self,
        _hop: HopNum,
        sendpadding: SendPadding,
    ) -> Option<QueuedCellPaddingInfo> {
        void::unreachable(sendpadding.0);
    }
    /// Report that we've flushed a cell from the queue for the given hop.
    pub(crate) fn flushed_relay_cell(&self, _info: QueuedCellPaddingInfo) {}

    /// Report that we've flushed a cell from the per-channel queue.
    pub(crate) fn flushed_channel_cell(&self) {}

    /// Report that we have decrypted a non-padding cell from our queue
    /// from a given hop.
    pub(crate) fn decrypted_data(&self, _hop: HopNum) {}

    /// Report that we have decrypted a padding cell from our queue.
    pub(crate) fn decrypted_padding(&self, hop: HopNum) -> Result<(), crate::Error> {
        Err(crate::Error::ExcessPadding(
            ExcessPadding::NoPaddingNegotiated,
            hop,
        ))
    }
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

impl futures::stream::FusedStream for PaddingEventStream {
    fn is_terminated(&self) -> bool {
        // TODO circpad: _if_ we have the above implementation return Ready(None),
        // then we must change this to return true.
        false
    }
}

/// Initialize a new PaddingController and PaddingEventStream.
///
/// When the `circ-padding` feature is disabled, these do nothing.
pub(crate) fn new_padding<S: SleepProvider>(runtime: S) -> (PaddingController, PaddingEventStream) {
    drop(runtime);
    (
        PaddingController {
            _phantom: PhantomData,
        },
        PaddingEventStream {
            _phantom: PhantomData,
        },
    )
}
