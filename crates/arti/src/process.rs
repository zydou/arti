//! Code to adjust process-related parameters.

use tor_error::ErrorReport;
use tracing::error;

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
        Err(e) => tracing::warn!("Error while increasing file limit: {}", e.report()),
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

    secmem_proc::harden_process_std_err().context("Problem while hardening process")?;

    Ok(())
}

/// Check that we are not running as "root".
///
/// If we are, give an error message, and exit.
pub(crate) fn exit_if_root() {
    if running_as_root() {
        error!(
            "You are running Arti as root. You don't need to, and \
             you probably shouldn't. \
             To run as root anyway, set application.allow_running_as_root."
        );
        std::process::exit(1);
    }
}

/// Return true if we seem to be running as root.
fn running_as_root() -> bool {
    #[cfg(target_family = "unix")]
    unsafe {
        libc::geteuid() == 0
    }
    #[cfg(not(target_family = "unix"))]
    false
}

/// Return an async stream that reports an event whenever we get a `SIGHUP`
/// signal.
///
/// Note that the signal-handling backend can coalesce signals; this is normal.
pub(crate) fn sighup_stream() -> crate::Result<impl futures::Stream<Item = ()>> {
    cfg_if::cfg_if! {
        if #[cfg(all(feature="tokio", target_family = "unix"))] {
            use tokio_crate::signal::unix as s;
            let mut signal = s::signal(s::SignalKind::hangup())?;
            Ok(futures::stream::poll_fn(move |ctx| signal.poll_recv(ctx)))
        } else if #[cfg(all(feature="async-std", target_family = "unix"))] {
            use signal_hook_async_std as s;
            use signal_hook::consts::signal;
            use futures::stream::StreamExt as _;
            let signal = s::Signals::new(&[signal::SIGHUP])?;
            Ok(signal.map(|_| ()))
        } else {
            // Not unix or no backend, so we won't ever get a SIGHUP.
            Ok(futures::stream::pending())
        }
    }
}
