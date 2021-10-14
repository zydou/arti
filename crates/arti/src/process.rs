//! Code to adjust process-related parameters.

/// Set our current maximum-file limit to a large value, if we can.
///
/// Since we're going to be used as a proxy, we're likely to need a
/// _lot_ of simultaneous sockets.
///
/// # Limitations
///
/// Maybe this should take a value from the configuration instead.
///
/// This doesn't actually do anything on windows.
pub(crate) fn use_max_file_limit() {
    /// Default maximum value to set for our maximum-file limit.
    ///
    /// If the system supports more than this, we won't ask for it.
    /// This should be plenty for proxy usage, though relays and onion
    /// services (once supported) may need more.
    const DFLT_MAX_N_FILES: u64 = 16384;

    match rlimit::utils::increase_nofile_limit(DFLT_MAX_N_FILES) {
        Ok(n) => tracing::debug!("Increased process file limit to {}", n),
        Err(e) => tracing::warn!("Error while increasing file limit: {}", e),
    }
}
