//! Errors coming from the DNS resolver

use hickory_net::NetError;
use thiserror::Error;
use tor_error::Bug;

/// An error representing a failed DNS lookup.
#[derive(Clone, Debug, Error)]
pub(crate) enum LookupError {
    /// The hostname from the RESOLVE message was not valid ASCII.
    #[error("Hostname is not ASCII")]
    NonAsciiHostname,

    /// An error coming from hickory
    #[error("failed to resolve name")]
    #[allow(dead_code)] // TODO(relay)
    Hickory(#[from] NetError),

    /// An internal error
    #[error("internal error")]
    Bug(#[from] Bug),
}

impl LookupError {
    /// Whether this is a transient error
    pub(crate) fn is_transient(&self) -> bool {
        use LookupError as LE;

        match self {
            LE::Hickory(_) => {
                // TODO(relay): not all of these are transient!
                // We should see if the hickory folks would be happy with us
                // adding NetError::is_transient() method,
                // or, alternatively, just match on the inner error here
                true
            }
            LE::NonAsciiHostname | LE::Bug(_) => false,
        }
    }
}
