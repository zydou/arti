//! Declare an error type for tor_socksproto
use thiserror::Error;

use tor_error::{ErrorKind, HasKind, InternalError};

/// An error that occurs while negotiating a SOCKS handshake.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The SOCKS client didn't implement SOCKS correctly.
    ///
    /// (Or, more likely, we didn't account for its behavior.)
    #[error("SOCKS protocol syntax violation")]
    Syntax,

    /// Failed to decode a SOCKS message.
    #[error("Error decoding message")]
    Decode(#[from] tor_bytes::Error),

    /// Called a function with an invalid argument.
    #[error("Invalid argument: {0}")]
    Invalid(&'static str),

    /// The SOCKS client declared a SOCKS version number that isn't
    /// one we support.
    ///
    /// In all likelihood, this is somebody trying to use the port for
    /// some protocol other than SOCKS.
    #[error("Unrecognized SOCKS protocol version {0}")]
    BadProtocol(u8),

    /// The SOCKS client tried to use a SOCKS feature that we don't
    /// support at all.
    #[error("SOCKS feature not implemented")]
    NotImplemented,

    /// Tried to progress the SOCKS handshake when it was already
    /// finished.  This is a programming error.
    #[error("SOCKS handshake was finished; no need to call this again")]
    AlreadyFinished(InternalError),

    /// Something went wrong with the programming of this module.
    #[error("Internal programming error while handling SOCKS handshake")]
    Internal(InternalError),
}

// Note: at present, tor-socksproto isn't used in any settings where ErrorKind
// is used.  This is provided for future-proofing, since someday we'll want to
// have SOCKS protocol support internally as well as in the `arti` proxy.
impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::Decode(tor_bytes::Error::Truncated) => {
                // This variant should always get converted before a user can
                // see it.
                EK::Internal
            }
            E::Syntax | E::Decode(_) | E::BadProtocol(_) => EK::LocalProtocolViolation,
            E::Invalid(_) => EK::BadArgument,
            E::NotImplemented => EK::NotImplemented,
            E::AlreadyFinished(_) => EK::Internal,
            E::Internal(_) => EK::Internal,
        }
    }
}
