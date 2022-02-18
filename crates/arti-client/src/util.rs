//! Utility functions for the rest of the crate.

use tor_persist::StateMgr;
use tracing::error;

/// A RAII guard that calls `<T as StateMgr>::unlock` on drop.
pub(crate) struct StateMgrUnlockGuard<'a, T: StateMgr + 'a> {
    /// The inner manager.
    mgr: &'a T,
}

impl<'a, T: StateMgr + 'a> Drop for StateMgrUnlockGuard<'a, T> {
    fn drop(&mut self) {
        if let Err(e) = self.mgr.unlock() {
            error!("Failed to unlock state manager: {}", e);
        }
    }
}

impl<'a, T: StateMgr + 'a> StateMgrUnlockGuard<'a, T> {
    /// Create an unlock guard.
    pub(crate) fn new(mgr: &'a T) -> Self {
        Self { mgr }
    }
    /// Consume the unlock guard without unlocking the state manager.
    pub(crate) fn disarm(self) {
        std::mem::forget(self);
    }
}
