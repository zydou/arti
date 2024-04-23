//! `TotalQtyNotifier`
//!
//! This newtype assures that we wake up the reclamation task when nceessary

use super::*;

/// Wrapper for `TotalQty`
#[derive(Deref, Debug)]
pub(super) struct TotalQtyNotifier {
    /// Total memory usage
    ///
    /// Invariant: equal to
    /// ```text
    ///    Σ        Σ         PRecord.used
    ///     ARecord  PRecord
    /// ```
    #[deref]
    total_used: TotalQty,

    /// Condvar to wake up the reclamation task
    ///
    /// The reclamation task has another clone of this
    reclamation_task_wakeup: mpsc::Sender<()>,
}

impl TotalQtyNotifier {
    /// Make a new `TotalQtyNotifier`, which will notify a specified condvar
    pub(super) fn new_zero(reclamation_task_wakeup: mpsc::Sender<()>) -> Self {
        TotalQtyNotifier {
            total_used: TotalQty::ZERO,
            reclamation_task_wakeup,
        }
    }

    /// Record that some memory has been (or will be) allocated by a participant
    ///
    /// Signals the wakeup task if we need to.
    pub(super) fn claim(
        &mut self,
        precord: &mut PRecord,
        want: Qty,
        config: &Config,
    ) -> crate::Result<ClaimedQty> {
        let got = self
            .total_used
            .claim(&mut precord.used, want)
            .ok_or_else(|| internal!("integer overflow attempting to add claim {}", want))?;
        if self.total_used > config.max {
            match self.reclamation_task_wakeup.try_send(()) {
                Ok(()) => Ok(()),
                Err(e) if e.is_full() => Ok(()),
                Err(e) => Err(into_internal!("could not notify reclamation task!")(e)),
            }?;
        }
        Ok(got)
    }

    /// Declare this poisoned, and prevent further claims
    pub(super) fn set_poisoned(&mut self) {
        self.total_used.set_poisoned();
    }

    /// Record that some memory has been (or will be) freed by a participant
    pub(super) fn release(&mut self, precord: &mut PRecord, have: ClaimedQty) // infallible
    {
        // TODO if the participant's usage underflows, tell it to reclaim
        // (and log some kind of internal error)
        self.total_used.release(&mut precord.used, have);
    }
}
