//! Code to adjust process-related parameters.

use crate::ArtiConfig;

/// Set our current maximum-file limit to a large value, if we can.
///
/// Since we're going to be used as a proxy, we're likely to need a
/// _lot_ of simultaneous sockets.
///
/// # Limitations
///
/// This doesn't actually do anything on windows.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) fn use_max_file_limit(config: &ArtiConfig) {
    match rlimit::increase_nofile_limit(config.system.max_files) {
        Ok(n) => tracing::debug!("Increased process file limit to {}", n),
        Err(e) => tracing::warn!("Error while increasing file limit: {}", e),
    }
}

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
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg(feature = "harden")]
pub(crate) fn enable_process_hardening() -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    /// Have we called this method before?
    static ENABLED: AtomicBool = AtomicBool::new(false);

    if ENABLED.swap(true, Ordering::SeqCst) {
        // Already enabled, or tried to enable.
        return Ok(());
    }

    #[cfg(unix)]
    rlimit::setrlimit(rlimit::Resource::CORE, 0, 0)
        .context("Problem while disabling core dumps")?;

    secmem_proc::harden_process_std_err().context("Problem while hardening process")?;

    Ok(())
}
