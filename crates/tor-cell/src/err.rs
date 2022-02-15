//! Define an error type for the tor-cell crate.
use thiserror::Error;
use tor_error::{ErrorKind, HasKind};

/// An error type for the tor-cell crate.
///
/// This type should probably be split into several.  There's more
/// than one kind of error that can occur while doing something with
/// tor cells.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// An error that occurred in the tor_bytes crate while decoding an
    /// object.
    #[error("parsing error: {0}")]
    BytesErr(#[from] tor_bytes::Error),
    /// There was a programming error somewhere in the code.
    #[error("Internal programming error: {0}")]
    Internal(tor_error::Bug),
    /// Protocol violation at the channel level
    #[error("channel protocol violation: {0}")]
    ChanProto(String),
    /// Tried to make or use a stream to an invalid destination address.
    #[error("invalid stream target address")]
    BadStreamAddress,
    /// Tried to construct a message that Tor can't represent.
    #[error("Message can't be represented in a Tor cell.")]
    CantEncode,
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use tor_bytes::Error as ByE;
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::BytesErr(ByE::Truncated) => EK::Internal,
            E::BytesErr(_) => EK::TorProtocolViolation,
            E::Internal(_) => EK::Internal,
            E::ChanProto(_) => EK::TorProtocolViolation,
            E::BadStreamAddress => EK::BadApiUsage,
            E::CantEncode => EK::Internal,
        }
    }
}
