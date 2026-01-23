//! Circuit padding
//!
// TODO(DEDUP): we should eventually move client::circuit::padding here

/// A possible way to handle a request to send padding.
#[derive(Copy, Clone, Debug)]
pub(crate) enum CircPaddingDisposition {
    /// Enqueue the padding normally.
    QueuePaddingNormally,
    /// Enqueue the padding, and allow one cell of data on our outbound queue
    /// to bypass the current block.
    QueuePaddingAndBypass,
    /// Do not take any actual padding action:
    /// existing data on our outbound queue will count as padding.
    TreatQueuedCellAsPadding,
}
