//! Helpers for reporting information about guard status to the guard manager.

use std::sync::Mutex;
use tor_guardmgr::{GuardMonitor, GuardStatus};

/// A shareable object that we can use to report guard status to the guard
/// manager.
pub(crate) struct GuardStatusHandle {
    /// An inner guard monitor.
    ///
    /// If this is None, then either we aren't using the guard
    /// manager, or we already reported a status to it.
    mon: Mutex<Option<GuardMonitor>>,
}

impl From<Option<GuardMonitor>> for GuardStatusHandle {
    fn from(mon: Option<GuardMonitor>) -> Self {
        Self {
            mon: Mutex::new(mon),
        }
    }
}

impl GuardStatusHandle {
    /// Finalize this guard status handle, and report its pending status
    /// to the guard manager.
    ///
    /// Future calls to methods on this object will do nothing.
    pub(crate) fn commit(&self) {
        let mut mon = self.mon.lock().expect("Poisoned lock");
        if let Some(mon) = mon.take() {
            mon.commit();
        }
    }

    /// Change the pending status on this guard.
    ///
    /// Note that the pending status will not be sent to the guard manager
    /// immediately: only committing this GuardStatusHandle, or dropping it,
    /// will do so.
    pub(crate) fn pending(&self, status: GuardStatus) {
        let mut mon = self.mon.lock().expect("Poisoned lock");
        if let Some(mon) = mon.as_mut() {
            mon.pending_status(status);
        }
    }

    /// Report the provided status to the guard manager.
    ///
    /// Future calls to methods on this object will do nothing.
    pub(crate) fn report(&self, status: GuardStatus) {
        let mut mon = self.mon.lock().expect("Poisoned lock");
        if let Some(mon) = mon.take() {
            mon.report(status);
        }
    }
}
