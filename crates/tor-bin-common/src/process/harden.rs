//! Hardening the current process.
//!
//! Some operating systems give processes the ability to prevent other
//! (low-privilege) processes from inspecting their state.
//! When possible, we usually want to opt in to that.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Enable process hardening, to make it harder for low-privilege users to
/// extract information from Arti.
///
/// This function only has effect the first time it is called.  If it returns an
/// error, the caller should probably exit the process.
///
/// # Limitations
///
/// See notes from the [`secmem_proc`] crate: this is a best-effort defense, and
/// only makes these attacks _harder_.  It can interfere with debugging.
pub fn enable_process_hardening() -> Result<(), Error> {
    /// Have we called this method before?
    static ENABLED: AtomicBool = AtomicBool::new(false);

    if ENABLED.swap(true, Ordering::SeqCst) {
        // Already enabled, or already tried to enable.

        // TODO: We should fail if any previous attempt failed!
        return Ok(());
    }

    secmem_proc::harden_process().map_err(|e| Error::Failed(Arc::new(e)))?;

    Ok(())
}

/// An error returned from calling enable_process_hardening.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// `secmem_proc` was unable to turn on process hardening.
    #[error("Could not enable process hardening")]
    Failed(#[source] Arc<secmem_proc::error::Error>),
}
