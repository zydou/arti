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

/// Return true if we are running with elevated privileges via setuid, setgid,
/// or a similar mechanism.
///
/// We detect this by checking whether there is any difference between our real,
/// effective, and saved user IDs; and then by doing the same check for our
/// group IDs.
///
/// On non-unix platforms, this function always returns false.
pub(crate) fn running_as_setuid() -> bool {
    #[cfg(target_family = "unix")]
    {
        // Use `libc` to find our real, effective, and saved UIDs and GIDs.
        let mut resuid = [0, 0, 0];
        let mut resgid = [0, 0, 0];
        unsafe {
            // We ignore failures from getresuid or getresgid: these syscalls
            // can only fail if we give them bad pointers, if they are disabled
            // via a maddened sandbox, or something like that.  In that case, we'll
            // just assume that the user knows what they're doing.
            let _ = libc::getresuid(&mut resuid[0], &mut resuid[1], &mut resuid[2]);
            let _ = libc::getresgid(&mut resgid[0], &mut resgid[1], &mut resgid[2]);
        }

        // The user can change any of their (real, effective, saved) IDs to any
        // of their (real, effective, saved) IDs.  Thus, privileges are elevated
        // if there is any difference between these IDs.
        let same_resuid = resuid.iter().all(|uid| uid == &resuid[0]);
        let same_resgid = resgid.iter().all(|gid| gid == &resgid[0]);
        !(same_resuid && same_resgid)
    }
    #[cfg(not(target_family = "unix"))]
    {
        false
    }
}
