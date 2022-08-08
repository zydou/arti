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
