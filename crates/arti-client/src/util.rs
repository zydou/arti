//! Utility functions for the rest of the crate.

use tor_error::error_report;
use tor_persist::StateMgr;

/// A RAII guard that calls `<T as StateMgr>::unlock` on drop.
pub(crate) struct StateMgrUnlockGuard<'a, T: StateMgr + 'a> {
    /// The inner manager.
    mgr: &'a T,
}

impl<'a, T: StateMgr + 'a> Drop for StateMgrUnlockGuard<'a, T> {
    fn drop(&mut self) {
        if let Err(e) = self.mgr.unlock() {
            error_report!(e, "Failed to unlock state manager");
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
    cfg_if::cfg_if! {
        // this is the exhaustive list of os where `getresuid` and `getresgid` are available
        if #[cfg(any(target_os = "fuchsia",
                     target_os = "linux",
                     target_os = "l4re",
                     target_os = "android",
                     target_os = "emscripten",
                     target_os = "freebsd",
                     target_os = "dragonfly",
                     target_os = "openbsd",
                     ))] {
            // Use `libc` to find our real, effective, and saved UIDs and GIDs.
            //
            // On systems with setresuid, a caller can (and people sometimes do)
            // arrange for ruid==euid != saveduid, and that is still set-id:
            // the process can retain privilege.
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
        } else if #[cfg(any(target_family = "unix", target_os = "vxworks"))] {
            // Some unix-like OS lacks setresuid/setresgid, while possibly still having a saved
            // set-id, which we then can't query. I *think* it is even possible to create a
            // situation where ruid==euid != saveduid.  But it is not possible to detect it
            // (other than maybe by experimentally guessing that saved set-id is zero and trying
            // to seteuid(0) - a bad move).
            //
            // So, use test for euid==ruid instead, which is about the best we can do.

            // We "sort of" ignore failures: in each case, we insist that both calls succeed,
            // giving the same answer, or both calls fail.  This ought to work well enough.
            let same_reuid = unsafe { libc::geteuid() == libc::getuid() };
            let same_regid = unsafe { libc::getegid() == libc::getgid() };
            !(same_reuid && same_regid)
        } else {
            false
        }
    }
}
