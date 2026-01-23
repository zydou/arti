//! Circuit padding
//!
// TODO(DEDUP): we should eventually move client::circuit::padding here

#[cfg(feature = "circ-padding")]
use {crate::circuit::cell_sender::CircuitCellSender, crate::client::circuit::padding};

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

/// Determine how exactly to handle a request to handle padding.
///
/// This is fairly complicated; see the maybenot documentation for more information.
///
// TODO(relay): relays use the same logic as clients here. Is that okay,
// or do they need to handle SendPadding differently??
#[cfg(feature = "circ-padding")]
pub(crate) fn padding_disposition(
    send_padding: &padding::SendPadding,
    chan_sender: &CircuitCellSender,
    padding_block: Option<&padding::StartBlocking>,
) -> CircPaddingDisposition {
    use CircPaddingDisposition::*;
    use padding::Bypass::*;
    use padding::Replace::*;

    // If true, and we are trying to send Replaceable padding,
    // we should let any data in the queue count as the queued padding instead,
    // if it is queued for our target hop (or any subsequent hop).
    //
    // TODO circpad: In addition to letting currently-queued data count as padding,
    // maybenot also permits us to send currently pending data from our streams
    // (or from our next hop, if we're a relay).  We don't have that implemented yet.
    //
    // TODO circpad: This will usually be false, since we try not to queue data
    // when there isn't space to write it.  If we someday add internal per-circuit
    // Buffers to chan_sender, this test is more likely to trigger.
    let have_queued_cell_for_hop = chan_sender.have_queued_cell_for_hop_or_later(send_padding.hop);

    match padding_block {
        Some(blocking) if blocking.is_bypassable => {
            match (
                send_padding.may_replace_with_data(),
                send_padding.may_bypass_block(),
            ) {
                (NotReplaceable, DoNotBypass) => QueuePaddingNormally,
                (NotReplaceable, BypassBlocking) => QueuePaddingAndBypass,
                (Replaceable, DoNotBypass) => {
                    if have_queued_cell_for_hop {
                        TreatQueuedCellAsPadding
                    } else {
                        QueuePaddingNormally
                    }
                }
                (Replaceable, BypassBlocking) => {
                    if have_queued_cell_for_hop {
                        TreatQueuedCellAsPadding
                    } else {
                        QueuePaddingAndBypass
                    }
                }
            }
        }
        Some(_) | None => match send_padding.may_replace_with_data() {
            Replaceable => {
                if have_queued_cell_for_hop {
                    TreatQueuedCellAsPadding
                } else {
                    QueuePaddingNormally
                }
            }
            NotReplaceable => QueuePaddingNormally,
        },
    }
}
