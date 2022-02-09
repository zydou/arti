//! Declare an error type for tor_socksproto
use thiserror::Error;

use tor_error::{ErrorKind, HasKind, InternalError};

/// An error that occurs while negotiating a SOCKS handshake.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Tried to handle a message what wasn't complete: try again.
    #[error("Message truncated; need to wait for more")]
    Truncated,

    /// The SOCKS client didn't implement SOCKS correctly.
    ///
    /// (Or, more likely, we didn't account for its behavior.)
    #[error("SOCKS protocol syntax violation")]
    Syntax,

    /// The SOCKS client declared a SOCKS version number that isn't
    /// one we support.
    ///
    /// In all likelihood, this is somebody trying to use the port for
    /// some protocol other than SOCKS.
    #[error("Unrecognized SOCKS protocol version {0}")]
    BadProtocol(u8),

    /// The SOCKS client tried to use a SOCKS feature that we don't
    /// support at all.
    #[error("SOCKS feature not supported")]
    NoSupport,

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
            E::Truncated => {
                // XXXX: This is not truly an error; it just means that you need
                // to read more and try again.
                //
                // So... what do we do with ErrorKind here?
                //
                // Should we add a new "NotAnError" kind, and document that if
                // you ever see it, you treated some "normal" error as a real
                // error?  [Users hate seeing: "FATAL: not an error" so I don't
                // love that].
                //
                // Should we add a new "MessageTruncated" or "ReadMore" or
                // "WantRead" kind?  That might be our best bet; we can document
                // that it's an error something should have handled before it
                // propagated to TorError.
                //
                // Should we remove this error case from `Error`, and change the
                // return type for all the functions in handshake(), so that
                // they return an Option<Result<>> or a Result<Result<>> ?
                todo!()
            }
            E::Syntax | E::BadProtocol(_) => EK::ProtocolViolation,
            E::NoSupport => EK::NoSupport,
            E::AlreadyFinished(_) => EK::Internal,
            E::Internal(_) => EK::Internal,
        }
    }
}

impl From<tor_bytes::Error> for Error {
    fn from(e: tor_bytes::Error) -> Error {
        use tor_bytes::Error as E;
        match e {
            E::Truncated => Error::Truncated,
            _ => Error::Syntax,
        }
    }
}
