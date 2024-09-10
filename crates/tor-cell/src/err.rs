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
    #[error("Error while parsing {parsed}")]
    BytesErr {
        /// The error that occurred.
        #[source]
        err: tor_bytes::Error,
        /// The thing that was being parsed.
        parsed: &'static str,
    },
    /// We encountered an error while encoding an outgoing message.
    ///
    /// This is likely to be a bug in somebody's code: either the code in this
    /// crate, or in the calling code that provided an unencodable message.
    #[error("Error while encoding message")]
    EncodeErr(#[from] tor_bytes::EncodeError),
    /// There was a programming error somewhere in the code.
    #[error("Internal programming error")]
    Internal(tor_error::Bug),
    /// Protocol violation at the channel level
    #[error("Channel protocol violation: {0}")]
    ChanProto(String),
    /// Protocol violation at the circuit level
    #[error("Circuit protocol violation: {0}")]
    CircProto(String),
    /// Tried to make or use a stream to an invalid destination address.
    #[error("Invalid stream target address")]
    BadStreamAddress,
    /// Tried to construct a message that Tor can't represent.
    #[error("Message can't be represented in a Tor cell: {0}")]
    CantEncode(&'static str),
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use tor_bytes::Error as ByE;
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::BytesErr {
                err: ByE::Truncated { .. },
                ..
            } => EK::Internal,
            E::EncodeErr(..) => EK::BadApiUsage,
            E::BytesErr { .. } => EK::TorProtocolViolation,
            E::Internal(_) => EK::Internal,
            E::ChanProto(_) => EK::TorProtocolViolation,
            E::CircProto(_) => EK::TorProtocolViolation,
            E::BadStreamAddress => EK::BadApiUsage,
            E::CantEncode(_) => EK::Internal,
        }
    }
}
